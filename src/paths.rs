//! Build-host attribution via nimble package path leaks.
//!
//! When a Nim binary retains stack-trace metadata, paths containing
//! `.nimble/pkgs` or `.nimble/pkgs2` reveal the build host's OS,
//! username, and the exact nimble package name/version/hash that was
//! compiled in. See RESEARCH.md §5.4 and WeLiveSecurity examples.

use crate::container::{Container, SectionKind};
use core::fmt;

/// Attribution data extracted from a `.nimble/pkgs` path leak.
#[derive(Debug, Clone)]
pub struct NimblePath {
    /// The raw path string as found in the binary.
    pub raw: String,
    /// Detected OS hint from path format.
    pub os_hint: PathOs,
    /// Username extracted from the home directory, if present.
    pub user_hint: Option<String>,
    /// Nimble package name (e.g. `nimSHA2`).
    pub pkg_name: Option<String>,
    /// Package version (e.g. `0.1.1`).
    pub pkg_version: Option<String>,
    /// Package hash — typically a git commit hash (pkgs2 layout only).
    pub pkg_hash: Option<String>,
}

/// OS hint from path format.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's
/// stable API. Changes are SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathOs {
    /// Path starts with a drive letter (`C:\` or `C:/`).
    Windows,
    /// Path starts with `/`.
    Unix,
    /// Relative or unrecognised prefix.
    Unknown,
}

impl fmt::Display for PathOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Windows => "Windows",
            Self::Unix => "Unix",
            Self::Unknown => "Unknown",
        })
    }
}

/// Scans read-only sections for `.nimble/pkgs` path leaks.
pub fn scan(container: &Container<'_>) -> Vec<NimblePath> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for section in container.sections() {
        if section.kind != SectionKind::RoData {
            continue;
        }
        scan_section(section.data, &mut results, &mut seen);
    }

    results
}

fn scan_section(
    data: &[u8],
    out: &mut Vec<NimblePath>,
    seen: &mut std::collections::HashSet<String>,
) {
    // Scan for the ".nimble/pkgs" substring.
    let needle = b".nimble/pkgs";
    let mut start = 0;
    while let Some(tail) = data.get(start..)
        && let Some(pos) = memchr::memmem::find(tail, needle)
    {
        let abs_pos = start.saturating_add(pos);

        // Walk backwards to find the start of the enclosing cstring.
        let str_start = walk_back_to_string_start(data, abs_pos);
        // Walk forwards to find the NUL terminator.
        let str_end = data
            .get(abs_pos..)
            .and_then(|s| s.iter().position(|&b| b == 0))
            .map(|p| abs_pos.saturating_add(p))
            .unwrap_or_else(|| data.len().min(abs_pos.saturating_add(4096)));

        if let Some(slice) = data.get(str_start..str_end)
            && let Ok(raw) = std::str::from_utf8(slice)
            && !raw.is_empty()
            && seen.insert(raw.to_owned())
        {
            out.push(parse_nimble_path(raw));
        }

        start = str_end.saturating_add(1);
    }
}

fn walk_back_to_string_start(data: &[u8], pos: usize) -> usize {
    // Walk backwards from `pos` looking for a NUL or non-printable byte.
    let mut i = pos;
    while i > 0 {
        let prev = i.saturating_sub(1);
        let Some(&b) = data.get(prev) else {
            return i;
        };
        if b == 0 || !(0x20..=0x7E).contains(&b) {
            return i;
        }
        i = prev;
    }
    0
}

fn parse_nimble_path(raw: &str) -> NimblePath {
    let os_hint = if raw.len() >= 3 && raw.as_bytes().get(1).copied() == Some(b':') {
        PathOs::Windows
    } else if raw.starts_with('/') {
        PathOs::Unix
    } else {
        PathOs::Unknown
    };

    let user_hint = extract_user_hint(raw, os_hint);
    let (pkg_name, pkg_version, pkg_hash) = extract_package_info(raw);

    NimblePath {
        raw: raw.to_owned(),
        os_hint,
        user_hint,
        pkg_name,
        pkg_version,
        pkg_hash,
    }
}

/// Extracts username from paths like `/home/<user>/.nimble/` or
/// `C:/Users/<user>/.nimble/`.
fn extract_user_hint(raw: &str, os: PathOs) -> Option<String> {
    match os {
        PathOs::Unix => {
            // `/home/<user>/.nimble/` or `/Users/<user>/.nimble/`
            let after_home = raw
                .strip_prefix("/home/")
                .or_else(|| raw.strip_prefix("/Users/"))?;
            let user = after_home.split('/').next()?;
            if !user.is_empty() {
                Some(user.to_owned())
            } else {
                None
            }
        }
        PathOs::Windows => {
            // `C:/Users/<user>/.nimble/` or `C:\Users\<user>\.nimble\`
            let norm = raw.replace('\\', "/");
            let after = norm
                .find("/Users/")
                .and_then(|i| norm.get(i.saturating_add(7)..))?;
            let user = after.split('/').next()?;
            if !user.is_empty() {
                Some(user.to_owned())
            } else {
                None
            }
        }
        PathOs::Unknown => None,
    }
}

/// Extracts package name, version, and hash from `.nimble/pkgs2/<pkg>-<ver>-<hash>/`
/// or `.nimble/pkgs/<pkg>-<ver>/` patterns.
fn extract_package_info(raw: &str) -> (Option<String>, Option<String>, Option<String>) {
    // Find the segment after ".nimble/pkgs2/" or ".nimble/pkgs/"
    let pkg_segment = if let Some(pos) = raw.find(".nimble/pkgs2/") {
        raw.get(pos.saturating_add(14)..).map(|s| (s, true)) // (segment, is_pkgs2)
    } else {
        raw.find(".nimble/pkgs/")
            .and_then(|pos| raw.get(pos.saturating_add(13)..))
            .map(|s| (s, false))
    };

    let Some((segment, is_pkgs2)) = pkg_segment else {
        return (None, None, None);
    };

    // The segment is `<pkg>-<ver>[-<hash>]/<rest>` or just `<pkg>-<ver>[-<hash>]`
    let dir_part = segment.split('/').next().unwrap_or(segment);

    // Split on `-` to find pkg name, version, and optional hash.
    // Package name can contain `-`, but version starts with a digit.
    // Strategy: find the first `-` followed by a digit → that's the ver start.
    let parts: Vec<&str> = dir_part.splitn(2, '-').collect();
    if parts.len() < 2 {
        return (Some(dir_part.to_owned()), None, None);
    }

    // Find where version starts (first segment after pkg name that starts with digit)
    let mut name_end = None;
    let bytes = dir_part.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        let here = bytes.get(i).copied();
        let next = bytes.get(i.saturating_add(1)).copied();
        if here == Some(b'-') && next.is_some_and(|b| b.is_ascii_digit()) {
            name_end = Some(i);
            break;
        }
    }

    let Some(ne) = name_end else {
        return (Some(dir_part.to_owned()), None, None);
    };

    let Some(pkg_name) = dir_part.get(..ne) else {
        return (Some(dir_part.to_owned()), None, None);
    };
    let Some(remainder) = dir_part.get(ne.saturating_add(1)..) else {
        return (Some(pkg_name.to_owned()), None, None);
    };

    if is_pkgs2 {
        // pkgs2: `<ver>-<hash>`
        if let Some(hash_sep) = remainder.rfind('-') {
            let ver = remainder.get(..hash_sep).unwrap_or("");
            let hash = remainder.get(hash_sep.saturating_add(1)..).unwrap_or("");
            (
                Some(pkg_name.to_owned()),
                Some(ver.to_owned()),
                if hash.is_empty() {
                    None
                } else {
                    Some(hash.to_owned())
                },
            )
        } else {
            (Some(pkg_name.to_owned()), Some(remainder.to_owned()), None)
        }
    } else {
        // pkgs: `<ver>` (no hash)
        (Some(pkg_name.to_owned()), Some(remainder.to_owned()), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unix_pkgs2() {
        let p = parse_nimble_path(
            "/home/alex/.nimble/pkgs2/nimSHA2-0.1.1-6765d9a04c328c64eb56b3fa90f45690294cc8fd/nimSHA2",
        );
        assert_eq!(p.os_hint, PathOs::Unix);
        assert_eq!(p.user_hint.as_deref(), Some("alex"));
        assert_eq!(p.pkg_name.as_deref(), Some("nimSHA2"));
        assert_eq!(p.pkg_version.as_deref(), Some("0.1.1"));
        assert!(p.pkg_hash.is_some());
    }

    #[test]
    fn parse_windows_pkgs2() {
        let p = parse_nimble_path("C:/Users/User.name/.nimble/pkgs2/nimSHA2-0.1.1-abc123/nimSHA2");
        assert_eq!(p.os_hint, PathOs::Windows);
        assert_eq!(p.user_hint.as_deref(), Some("User.name"));
        assert_eq!(p.pkg_name.as_deref(), Some("nimSHA2"));
    }

    #[test]
    fn parse_legacy_pkgs() {
        let p = parse_nimble_path("/home/user/.nimble/pkgs/asynctools-0.1.0/asynctools");
        assert_eq!(p.pkg_name.as_deref(), Some("asynctools"));
        assert_eq!(p.pkg_version.as_deref(), Some("0.1.0"));
        assert_eq!(p.pkg_hash, None);
    }

    #[test]
    fn parse_relative_nimble() {
        let p = parse_nimble_path(".nimble/pkgs/foo-1.0/foo");
        assert_eq!(p.os_hint, PathOs::Unknown);
        assert_eq!(p.pkg_name.as_deref(), Some("foo"));
    }
}
