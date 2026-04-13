//! Stack-trace metadata harvester.
//!
//! Every Nim proc compiled with `--stackTrace:on` (the default for debug
//! builds) embeds a `procname` and `filename` cstring pair via the
//! `nimfr_()` frame-init macro (RESEARCH.md §5.2). This module scans
//! read-only sections for those cstrings.
//!
//! **File paths** end with `.nim` and may be absolute (revealing the
//! build host) or relative (basename only).
//!
//! **Proc names** are the remaining short, printable cstrings that look
//! like Nim identifiers.

use crate::{
    container::{Container, SectionKind},
    util,
};

/// Harvested stack-trace metadata from a Nim binary.
#[derive(Debug, Clone)]
pub struct StackTraceHarvest {
    /// Nim source-file paths found in rodata (deduplicated).
    pub file_paths: Vec<FilePath>,
    /// Nim proc names found in rodata (deduplicated).
    pub proc_names: Vec<String>,
}

/// A `.nim` file path found in the binary.
#[derive(Debug, Clone)]
pub struct FilePath {
    /// The path as found in the binary.
    pub path: String,
    /// Whether the path is absolute (starts with `/` or a drive letter).
    pub is_absolute: bool,
}

/// Scans read-only sections for Nim stack-trace file paths and proc names.
pub fn harvest(container: &Container<'_>) -> StackTraceHarvest {
    let mut file_paths = Vec::new();
    let mut proc_names = Vec::new();
    let mut seen_files = std::collections::HashSet::new();
    let mut seen_procs = std::collections::HashSet::new();

    for section in container.sections() {
        if section.kind != SectionKind::RoData {
            continue;
        }
        harvest_section(
            section.data,
            &mut file_paths,
            &mut proc_names,
            &mut seen_files,
            &mut seen_procs,
        );
    }

    StackTraceHarvest {
        file_paths,
        proc_names,
    }
}

fn harvest_section(
    data: &[u8],
    file_paths: &mut Vec<FilePath>,
    proc_names: &mut Vec<String>,
    seen_files: &mut std::collections::HashSet<String>,
    seen_procs: &mut std::collections::HashSet<String>,
) {
    // Walk the section looking for NUL-terminated cstrings.
    let mut offset = 0;
    while offset < data.len() {
        // Find next NUL-terminated string.
        let Some(cstr) = util::slice_cstring(data, offset, 4096) else {
            // No NUL found within budget — skip forward.
            offset += 1;
            continue;
        };

        if cstr.is_empty() {
            offset += 1;
            continue;
        }

        let advance = cstr.len() + 1; // +1 for the NUL terminator

        if let Ok(s) = std::str::from_utf8(cstr) {
            // File path: ends with ".nim"
            if s.ends_with(".nim") && s.len() >= 5 && is_printable(s) {
                // Strip leading `@` — Nim string literals in rodata are
                // often preceded by the `@` tag byte (0x40) which ends up
                // as part of the NUL-terminated cstring.
                let path = s.strip_prefix('@').unwrap_or(s);
                if path.ends_with(".nim") && !path.is_empty() && seen_files.insert(path.to_owned())
                {
                    let is_absolute =
                        path.starts_with('/') || (path.len() >= 3 && path.as_bytes()[1] == b':');
                    file_paths.push(FilePath {
                        path: path.to_owned(),
                        is_absolute,
                    });
                }
            }
            // Proc name: short, printable, looks like a Nim identifier.
            else if s.len() <= 128
                && s.len() >= 2
                && is_nim_proc_name(s)
                && !looks_like_path(s)
                && seen_procs.insert(s.to_owned())
            {
                proc_names.push(s.to_owned());
            }
        }

        offset += advance;
    }
}

/// Returns `true` if every byte is printable ASCII (0x20..0x7E).
fn is_printable(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// Heuristic: does this string look like a Nim proc name?
///
/// Nim proc names are identifiers: start with a letter, contain letters,
/// digits, and underscores. Some operators are mangled but the stack-trace
/// `procname` field stores the original Nim name.
fn is_nim_proc_name(s: &str) -> bool {
    let first = s.as_bytes()[0];
    if !first.is_ascii_alphabetic() {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Reject strings that look like file paths or URLs rather than proc names.
fn looks_like_path(s: &str) -> bool {
    s.contains('/') || s.contains('\\') || s.contains("://") || s.ends_with(".nim")
}
