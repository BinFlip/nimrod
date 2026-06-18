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
use core::fmt;

/// Nim garbage-collector / memory-management mode.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's
/// stable API. Changes are SemVer-major.
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

impl GcMode {
    /// Returns the stable string identifier for this mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Refc => "Refc",
            Self::ArcOrc => "ArcOrc",
            Self::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for GcMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Best-effort Nim compiler-family hint.
///
/// Derived from RTTI generation plus the cycle-collector signal — there is no
/// deterministic version stamp in a Nim binary (`RESEARCH.md` §12), so this is
/// a heuristic, not a precise point-release.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's stable
/// API. Changes are SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NimVersionHint {
    /// Legacy `--mm:refc` build (Nim 1.x default, still available in 2.x).
    /// Signalled by V1 `NTI_` RTTI globals with no V2 globals.
    Nim1xRefc,
    /// Modern `--mm:arc` build (Nim 2.x). V2 RTTI present, no cycle collector.
    Nim2xArc,
    /// Modern `--mm:orc` build (Nim 2.x default). V2 RTTI present *and*
    /// cycle-collector symbols (`collectCycles`) present.
    Nim2xOrc,
    /// Could not determine (no RTTI globals — e.g. a fully stripped binary).
    Unknown,
}

impl NimVersionHint {
    /// Returns the stable string identifier for this hint.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nim1xRefc => "Nim1xRefc",
            Self::Nim2xArc => "Nim2xArc",
            Self::Nim2xOrc => "Nim2xOrc",
            Self::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for NimVersionHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Infers a best-effort Nim compiler-family hint.
///
/// - V2 RTTI + a cycle-collector symbol (`collectCycles…`) → [`NimVersionHint::Nim2xOrc`]
/// - V2 RTTI without one → [`NimVersionHint::Nim2xArc`]
/// - V1 RTTI only → [`NimVersionHint::Nim1xRefc`]
/// - neither → [`NimVersionHint::Unknown`]
///
/// The ARC vs ORC split keys off the ORC cycle collector
/// (`collectCycles` / `collectCyclesBacon`, from `lib/system/orc.nim`). That
/// symbol is stripped by `-d:danger` / `--passL:-s`, so a stripped ORC build
/// may be reported as [`NimVersionHint::Nim2xArc`]. The refc-vs-modern split is
/// robust regardless of stripping (it keys off the RTTI naming convention,
/// `RESEARCH.md` §3.4).
pub fn detect_compiler_version(
    container: &Container<'_>,
    matches: DetectionMatches,
) -> NimVersionHint {
    match gc_mode(matches) {
        GcMode::ArcOrc => {
            if has_cycle_collector(container) {
                NimVersionHint::Nim2xOrc
            } else {
                NimVersionHint::Nim2xArc
            }
        }
        GcMode::Refc => NimVersionHint::Nim1xRefc,
        GcMode::Unknown => NimVersionHint::Unknown,
    }
}

/// Returns `true` if the symbol table contains an ORC cycle-collector routine.
fn has_cycle_collector(container: &Container<'_>) -> bool {
    container.symbols().iter().any(|s| {
        let name = s.name.as_ref();
        name.contains("collectCycles") || name.contains("collectCyclesBacon")
    })
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
        if let Some(prefix) = stripped.strip_suffix("NimMain")
            && !prefix.is_empty()
            && !stripped.contains("__")
        {
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
    fn compiler_version_splits_arc_orc_via_cycle_collector() {
        use crate::container::{self, Arch, Format, Symbol, SymbolKind};
        use std::borrow::Cow;

        let bytes = [0u8; 4];
        let orc_syms = vec![Symbol {
            name: Cow::Borrowed("collectCyclesBacon__system_u3313"),
            vm_addr: 0x1000,
            size: 0,
            kind: SymbolKind::Function,
        }];
        let orc = container::assemble(&bytes, Format::Elf, Arch::Amd64, 0, vec![], orc_syms);
        assert_eq!(
            detect_compiler_version(&orc, DetectionMatches::NTIV2_SYMBOL),
            NimVersionHint::Nim2xOrc
        );

        // Same V2 flags but no cycle collector → ARC.
        let arc = container::assemble(&bytes, Format::Elf, Arch::Amd64, 0, vec![], vec![]);
        assert_eq!(
            detect_compiler_version(&arc, DetectionMatches::NTIV2_SYMBOL),
            NimVersionHint::Nim2xArc
        );
        // V1 only → refc; nothing → unknown.
        assert_eq!(
            detect_compiler_version(&arc, DetectionMatches::NTI_LEGACY_SYMBOL),
            NimVersionHint::Nim1xRefc
        );
        assert_eq!(
            detect_compiler_version(&arc, DetectionMatches::EMPTY),
            NimVersionHint::Unknown
        );
    }

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
