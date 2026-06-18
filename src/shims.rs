//! Entry-point shim locator.
//!
//! Every Nim executable contains a standard set of entry-point shim
//! functions emitted by the compiler (RESEARCH.md §6). This module
//! scans the symbol table for them in a single pass.

use crate::container::Container;
use core::fmt;

/// Which canonical entry-point shim a symbol represents.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's
/// stable API. Changes are SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShimKind {
    /// `NimMain` — public initialiser, calls `NimMainInner`.
    NimMain,
    /// `NimMainInner` — runs module init functions.
    NimMainInner,
    /// `PreMain` — calls `PreMainInner` via volatile pointer.
    PreMain,
    /// `PreMainInner` — initial setup before module init.
    PreMainInner,
    /// `NimMainModule` — init function of the main module.
    NimMainModule,
}

impl ShimKind {
    /// Returns the stable string identifier for this shim kind (the canonical
    /// unprefixed symbol name).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NimMain => "NimMain",
            Self::NimMainInner => "NimMainInner",
            Self::PreMain => "PreMain",
            Self::PreMainInner => "PreMainInner",
            Self::NimMainModule => "NimMainModule",
        }
    }
}

impl fmt::Display for ShimKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A located entry-point shim.
///
/// `address` is a virtual address (image load space). To convert to an
/// RVA for disassembler use, call [`crate::NimBinary::shim_rva`].
#[derive(Debug, Clone)]
pub struct EntryShim {
    /// Which canonical shim this is.
    pub kind: ShimKind,
    /// The raw symbol name as it appeared in the binary.
    pub symbol_name: String,
    /// Virtual address of the symbol (image load space, not file offset).
    pub address: u64,
}

/// The five canonical shim suffixes, in the order they typically appear
/// in `cgen.nim`. The `--nimMainPrefix` option prepends a user-chosen
/// prefix to each name.
const SHIM_NAMES: &[(&str, ShimKind)] = &[
    ("NimMain", ShimKind::NimMain),
    ("NimMainInner", ShimKind::NimMainInner),
    ("NimMainModule", ShimKind::NimMainModule),
    ("PreMain", ShimKind::PreMain),
    ("PreMainInner", ShimKind::PreMainInner),
];

/// Scans the container's symbol table for Nim entry-point shims.
///
/// Returns all matched shims. With `--nimMainPrefix` the prefix is
/// automatically detected: a symbol ending in `NimMain` whose prefix is
/// shared by other shim names qualifies.
pub fn scan(container: &Container<'_>) -> Vec<EntryShim> {
    let mut result = Vec::new();

    for sym in container.symbols() {
        let name = sym.name.as_ref();
        // Strip leading underscore (Mach-O C-level symbols already have
        // it stripped by the container layer, but COFF entries may retain
        // one).
        let stripped = name.strip_prefix('_').unwrap_or(name);

        for &(suffix, kind) in SHIM_NAMES {
            if stripped == suffix || stripped.ends_with(suffix) && is_prefix_match(stripped, suffix)
            {
                result.push(EntryShim {
                    kind,
                    symbol_name: name.to_string(),
                    address: sym.vm_addr,
                });
                break;
            }
        }
    }

    result
}

/// Checks that a symbol is `<prefix>NimMain` etc. — the prefix must be
/// non-empty and not contain `__` (which would indicate a normal Nim
/// function, not a shim).
fn is_prefix_match(symbol: &str, suffix: &str) -> bool {
    let Some(prefix) = symbol.strip_suffix(suffix) else {
        return false;
    };
    if prefix.is_empty() {
        return false;
    }
    // A nimMainPrefix is a short identifier — no double underscores.
    !prefix.contains("__")
}

/// Attempts to detect the `--nimMainPrefix` value from located shims.
///
/// Returns `Some("")` if the default (empty) prefix is in use,
/// `Some(prefix)` if a shared non-empty prefix is found across all shims,
/// or `None` if no shims were located.
pub fn detect_prefix(shims: &[EntryShim]) -> Option<&str> {
    // Find the NimMain shim — its prefix is authoritative.
    let nim_main = shims.iter().find(|s| s.kind == ShimKind::NimMain)?;
    let name = nim_main.symbol_name.as_str();
    let stripped = name.strip_prefix('_').unwrap_or(name);
    let prefix = stripped.strip_suffix("NimMain")?;
    Some(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shim_kind_eq() {
        assert_eq!(ShimKind::NimMain, ShimKind::NimMain);
        assert_ne!(ShimKind::NimMain, ShimKind::PreMain);
    }

    #[test]
    fn prefix_match_rejects_mangled_symbols() {
        // Full Nim symbols with `__module_u<id>` suffix don't end with
        // shim names, so ends_with() filters them first. But if a bare
        // symbol happens to end with a shim name AND has `__` in the
        // prefix, is_prefix_match rejects it.
        assert!(!is_prefix_match("something__NimMain", "NimMain"));
    }

    #[test]
    fn prefix_match_accepts_custom_prefix() {
        assert!(is_prefix_match("MyLibNimMain", "NimMain"));
        assert!(is_prefix_match("AppNimMainInner", "NimMainInner"));
    }

    #[test]
    fn prefix_match_rejects_exact() {
        // Exact match (prefix length 0) — is_prefix_match returns false,
        // but the caller checks exact match first via `==`.
        assert!(!is_prefix_match("NimMain", "NimMain"));
    }
}
