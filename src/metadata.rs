//! Nim binary metadata detection.
//!
//! Infers high-level properties from the container's symbol table:
//!
//! - **GC mode** — `refc` (legacy) vs `arc`/`orc` (modern), based on
//!   which RTTI global naming convention is present.
//! - **`--nimMainPrefix`** — the user-configurable prefix on entry shims.
//!
//! See RESEARCH.md §3.5 (RTTI counts by mode) and §6 (entry shims).

use crate::{container::Container, detect::DetectionMatches};

/// Nim garbage-collector / memory-management mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GcMode {
    /// `--mm:refc` — traditional reference-counting GC (Nim 1.x default).
    /// Indicated by the presence of legacy `NTI_` RTTI globals.
    Refc,
    /// `--mm:arc` or `--mm:orc` — deterministic ARC with optional cycle
    /// collector (Nim 2.x default). Indicated by `NTIv2_` globals.
    ArcOrc,
    /// Could not determine the GC mode (no RTTI symbols found, e.g.
    /// in a fully stripped binary).
    Unknown,
}

/// Infers the GC mode from the detection report's RTTI flags.
///
/// - `NTIv2_` symbols → [`GcMode::ArcOrc`]
/// - `NTI_` symbols (without `NTIv2_`) → [`GcMode::Refc`]
/// - Neither → [`GcMode::Unknown`]
pub fn gc_mode(matches: DetectionMatches) -> GcMode {
    let has_v2 = matches.contains(DetectionMatches::NTIV2_SYMBOL);
    let has_legacy = matches.contains(DetectionMatches::NTI_LEGACY_SYMBOL);

    match (has_v2, has_legacy) {
        (true, _) => GcMode::ArcOrc,
        (false, true) => GcMode::Refc,
        _ => GcMode::Unknown,
    }
}

/// Attempts to detect the `--nimMainPrefix` from the symbol table.
///
/// Scans for a symbol matching `<prefix>NimMain` (exact name, no module
/// suffix). Returns the prefix (empty string for the default, non-empty
/// for custom prefixes), or `None` if `NimMain` was not found.
pub fn nim_main_prefix<'a>(container: &'a Container<'a>) -> Option<&'a str> {
    for sym in container.symbols() {
        let name = sym.name.as_ref();
        let stripped = name.strip_prefix('_').unwrap_or(name);
        if stripped == "NimMain" {
            return Some("");
        }
        // Custom prefix: `<prefix>NimMain` — must not contain `__`
        // (which would indicate a normal mangled symbol).
        if stripped.ends_with("NimMain")
            && !stripped.contains("__")
            && stripped.len() > "NimMain".len()
        {
            let prefix = &stripped[..stripped.len() - "NimMain".len()];
            // The prefix should be a valid identifier fragment.
            if prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Some(prefix);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_mode_from_flags() {
        assert_eq!(gc_mode(DetectionMatches::NTIV2_SYMBOL), GcMode::ArcOrc);
        assert_eq!(gc_mode(DetectionMatches::NTI_LEGACY_SYMBOL), GcMode::Refc);
        assert_eq!(gc_mode(DetectionMatches::EMPTY), GcMode::Unknown);
        // Both set — V2 wins (ARC/ORC is the authoritative modern mode).
        assert_eq!(
            gc_mode(DetectionMatches::NTIV2_SYMBOL | DetectionMatches::NTI_LEGACY_SYMBOL),
            GcMode::ArcOrc
        );
    }
}
