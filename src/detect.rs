//! Nim-binary fingerprint detection.
//!
//! Detection runs in two single-pass phases:
//!
//! 1. **Symbol scan** — one walk of the symbol table classifies every
//!    symbol against all symbol-based probes (entry shims, init functions,
//!    RTTI globals, `.nim` file markers). This is cheap: string comparisons
//!    on a pre-parsed list.
//!
//! 2. **Rodata scan** — one walk of the read-only sections tests byte-string
//!    needles via `memchr::memmem`. This is the more expensive phase (substring
//!    search over potentially hundreds of KB), so it runs second.
//!
//! Both phases exit early once their respective flag sets are saturated.
//! Every probe sets a single bit in [`DetectionMatches`]; the overall
//! verdict is derived from whether any bit is set.
//!
//! All strings and symbol names probed here are anchored in `RESEARCH.md`
//! section 11 (fingerprint catalogue), which in turn quotes either the Nim
//! compiler source or the ESET `id_nim_binary.yar` ruleset verbatim.

use crate::container::{Container, Format, SymbolKind};

/// A bitset of which Nim-detection probes matched on a given binary.
///
/// Every flag corresponds to a single probe. The flags are intentionally
/// independent: a single flag set is sometimes enough to be confident
/// (e.g. `NIMMAIN_SYMBOL`), but the caller can also inspect individual
/// matches to understand *why* a binary was classified the way it was.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DetectionMatches(u16);

impl DetectionMatches {
    /// No probes matched.
    pub const EMPTY: Self = Self(0);

    /// At least one canonical entry-shim symbol name (`NimMain`,
    /// `NimMainInner`, `NimMainModule`, `PreMain`, `PreMainInner`) was
    /// present in the symbol table.
    pub const NIMMAIN_SYMBOL: Self = Self(1 << 0);

    /// At least one canonical entry-shim name appeared as a plain string
    /// literal in a read-only section (useful when the symbol table is
    /// stripped).
    pub const NIMMAIN_STRING: Self = Self(1 << 1);

    /// The string `"fatal.nim"` appeared in a read-only section.
    pub const FATAL_NIM: Self = Self(1 << 2);

    /// The string `"sysFatal"` appeared in a read-only section.
    pub const SYS_FATAL: Self = Self(1 << 3);

    /// Two or more of the Nim error strings (`@value out of range`,
    /// `@division by zero`, `@over- or underflow`, `@index out of bounds`)
    /// appeared in a read-only section.
    pub const NIM_ERROR_STRINGS: Self = Self(1 << 4);

    /// At least one symbol matches the Nim module init naming convention
    /// (`…Init000` or `…DatInit000`).
    pub const INIT000_SYMBOL: Self = Self(1 << 5);

    /// At least one V2 RTTI global (`NTIv2<hash>_`) was present in the
    /// symbol table.
    pub const NTIV2_SYMBOL: Self = Self(1 << 6);

    /// At least one legacy V1 RTTI global (`NTI…<hash>_`) was present in
    /// the symbol table.
    pub const NTI_LEGACY_SYMBOL: Self = Self(1 << 7);

    /// At least one ELF `STT_FILE` symbol or PE COFF file symbol ends in
    /// `.nim`.
    pub const STT_FILE_DOT_NIM: Self = Self(1 << 8);

    /// The substring `.nimble/pkgs` appeared in a read-only section.
    pub const NIMBLE_PATH_LEAK: Self = Self(1 << 9);

    /// At least one Nim signal-handler or exception-formatting string was
    /// found in a read-only section. These survive even in
    /// `-d:danger --opt:size --passL:-s` builds where all other rodata
    /// fingerprints are stripped. See RESEARCH.md §11.3.
    pub const NIM_SIGNAL_STRINGS: Self = Self(1 << 10);

    /// Returns `true` if every flag in `other` is set in `self`.
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns `true` if no probes matched.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Number of flags that are set.
    pub fn count(self) -> u32 {
        self.0.count_ones()
    }

    /// Iterates matching flags as `(name, singleton)` tuples.
    pub fn iter(self) -> impl Iterator<Item = (&'static str, Self)> {
        const ALL: &[(&str, DetectionMatches)] = &[
            ("NIMMAIN_SYMBOL", DetectionMatches::NIMMAIN_SYMBOL),
            ("NIMMAIN_STRING", DetectionMatches::NIMMAIN_STRING),
            ("FATAL_NIM", DetectionMatches::FATAL_NIM),
            ("SYS_FATAL", DetectionMatches::SYS_FATAL),
            ("NIM_ERROR_STRINGS", DetectionMatches::NIM_ERROR_STRINGS),
            ("INIT000_SYMBOL", DetectionMatches::INIT000_SYMBOL),
            ("NTIV2_SYMBOL", DetectionMatches::NTIV2_SYMBOL),
            ("NTI_LEGACY_SYMBOL", DetectionMatches::NTI_LEGACY_SYMBOL),
            ("STT_FILE_DOT_NIM", DetectionMatches::STT_FILE_DOT_NIM),
            ("NIMBLE_PATH_LEAK", DetectionMatches::NIMBLE_PATH_LEAK),
            ("NIM_SIGNAL_STRINGS", DetectionMatches::NIM_SIGNAL_STRINGS),
        ];
        ALL.iter()
            .copied()
            .filter(move |(_, flag)| self.contains(*flag))
    }
}

impl core::ops::BitOr for DetectionMatches {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for DetectionMatches {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Outcome of running the full detection probe set on a container.
#[derive(Debug, Clone)]
pub struct DetectionReport {
    /// Every probe that matched.
    pub matches: DetectionMatches,
    /// Cached verdict: `true` iff at least one probe matched.
    pub is_nim: bool,
}

impl DetectionReport {
    /// Runs every detection probe against `container` and returns the
    /// aggregated report.
    ///
    /// Two phases, each a single pass over its data source:
    ///
    /// 1. **Symbol scan** — one walk of the symbol table classifies every
    ///    symbol against all symbol-based probes simultaneously.
    /// 2. **Rodata scan** — one walk of the read-only sections tests every
    ///    byte-string needle.
    ///
    /// Both phases exit early when their respective flag sets are saturated.
    pub fn run(container: &Container<'_>) -> Self {
        let mut matches = DetectionMatches::EMPTY;

        matches |= probe_symbols(container);
        matches |= probe_rodata(container);

        let is_nim = !matches.is_empty();
        Self { matches, is_nim }
    }
}

const ENTRY_SHIM_NAMES: &[&str] = &[
    "NimMain",
    "NimMainInner",
    "NimMainModule",
    "PreMain",
    "PreMainInner",
];

/// Union of every symbol-table flag that applies regardless of format.
const SYMBOL_FLAGS_COMMON: DetectionMatches = DetectionMatches(
    DetectionMatches::NIMMAIN_SYMBOL.0
        | DetectionMatches::INIT000_SYMBOL.0
        | DetectionMatches::NTIV2_SYMBOL.0
        | DetectionMatches::NTI_LEGACY_SYMBOL.0,
);

/// Walks the symbol table once, testing every symbol against all
/// symbol-based probes. Exits early once every applicable flag is set.
fn probe_symbols(c: &Container<'_>) -> DetectionMatches {
    let mut m = DetectionMatches::EMPTY;

    // STT_FILE / COFF `.file` records only exist in ELF and PE.
    let check_file = c.format() == Format::Elf || c.format() == Format::Pe;

    // The maximum set of flags this pass can produce — used for early exit.
    let ceiling = if check_file {
        DetectionMatches(SYMBOL_FLAGS_COMMON.0 | DetectionMatches::STT_FILE_DOT_NIM.0)
    } else {
        SYMBOL_FLAGS_COMMON
    };

    for sym in c.symbols() {
        let name = sym.name.as_ref();

        if !m.contains(DetectionMatches::NIMMAIN_SYMBOL) {
            let stripped = name.strip_prefix('_').unwrap_or(name);
            for &probe in ENTRY_SHIM_NAMES {
                if stripped == probe {
                    m |= DetectionMatches::NIMMAIN_SYMBOL;
                    break;
                }
            }
        }

        if !m.contains(DetectionMatches::INIT000_SYMBOL)
            && (name.ends_with("Init000") || name.ends_with("DatInit000"))
        {
            m |= DetectionMatches::INIT000_SYMBOL;
        }

        // The trailing underscore avoids false positives on Windows SDK
        // names like `NTI_HANDLE`.
        if name.ends_with('_') {
            if !m.contains(DetectionMatches::NTIV2_SYMBOL) && name.starts_with("NTIv2") {
                m |= DetectionMatches::NTIV2_SYMBOL;
            } else if !m.contains(DetectionMatches::NTI_LEGACY_SYMBOL)
                && name.starts_with("NTI")
                && !name.starts_with("NTIv2")
            {
                m |= DetectionMatches::NTI_LEGACY_SYMBOL;
            }
        }

        if check_file
            && !m.contains(DetectionMatches::STT_FILE_DOT_NIM)
            && sym.kind == SymbolKind::File
        {
            // Nim codegens intermediate C files named `@m<module>.nim.c`
            // (or `.nim.cpp` / `.nim.m` for cpp/objc backends). The `@m`
            // prefix is itself a strong Nim fingerprint (RESEARCH.md §10).
            if name.starts_with("@m")
                || name.ends_with(".nim")
                || name.ends_with(".nim.c")
                || name.ends_with(".nim.cpp")
                || name.ends_with(".nim.m")
            {
                m |= DetectionMatches::STT_FILE_DOT_NIM;
            }
        }

        if m.contains(ceiling) {
            break;
        }
    }

    m
}

/// Needles scanned in rodata. Each needle maps to a single flag.
/// `ERROR_NEEDLES` is handled separately because two hits are required.
const RODATA_NEEDLES: &[(&[u8], DetectionMatches)] = &[
    (b"fatal.nim", DetectionMatches::FATAL_NIM),
    (b"sysFatal", DetectionMatches::SYS_FATAL),
    (b"NimMain", DetectionMatches::NIMMAIN_STRING),
    (b"PreMainInner", DetectionMatches::NIMMAIN_STRING),
    (b".nimble/pkgs", DetectionMatches::NIMBLE_PATH_LEAK),
    // Danger-mode survivors: these come from Nim's signal handler
    // (excpt.nim:546 processSignal) and exception formatting
    // (excpt.nim:254). See RESEARCH.md §11.3.
    (
        b"Attempt to read from nil?",
        DetectionMatches::NIM_SIGNAL_STRINGS,
    ),
    (b"@[[reraised from:", DetectionMatches::NIM_SIGNAL_STRINGS),
];

const ERROR_NEEDLES: &[&[u8]] = &[
    b"@value out of range",
    b"@division by zero",
    b"@over- or underflow",
    b"@index out of bounds",
];

/// Union of every flag that `probe_rodata` can set.
const ALL_RODATA_FLAGS: DetectionMatches = DetectionMatches(
    DetectionMatches::FATAL_NIM.0
        | DetectionMatches::SYS_FATAL.0
        | DetectionMatches::NIMMAIN_STRING.0
        | DetectionMatches::NIM_ERROR_STRINGS.0
        | DetectionMatches::NIMBLE_PATH_LEAK.0
        | DetectionMatches::NIM_SIGNAL_STRINGS.0,
);

/// Walks read-only sections once, testing every needle. Exits early
/// once all rodata flags are saturated.
fn probe_rodata(c: &Container<'_>) -> DetectionMatches {
    let mut m = DetectionMatches::EMPTY;
    let mut error_hits: u8 = 0;

    for section in c.rodata_sections() {
        if section.data.is_empty() {
            continue;
        }

        for &(needle, flag) in RODATA_NEEDLES {
            if !m.contains(flag) && memchr::memmem::find(section.data, needle).is_some() {
                m |= flag;
            }
        }

        if error_hits < 2 {
            for needle in ERROR_NEEDLES {
                if memchr::memmem::find(section.data, needle).is_some() {
                    error_hits += 1;
                    if error_hits >= 2 {
                        m |= DetectionMatches::NIM_ERROR_STRINGS;
                        break;
                    }
                }
            }
        }

        if m.contains(ALL_RODATA_FLAGS) {
            break;
        }
    }

    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_default_is_empty() {
        let m = DetectionMatches::default();
        assert!(m.is_empty());
        assert_eq!(m.count(), 0);
        assert!(!m.contains(DetectionMatches::NIMMAIN_SYMBOL));
    }

    #[test]
    fn matches_bitor() {
        let m = DetectionMatches::NIMMAIN_SYMBOL | DetectionMatches::FATAL_NIM;
        assert!(m.contains(DetectionMatches::NIMMAIN_SYMBOL));
        assert!(m.contains(DetectionMatches::FATAL_NIM));
        assert!(!m.contains(DetectionMatches::SYS_FATAL));
        assert_eq!(m.count(), 2);
    }

    #[test]
    fn matches_iter_names() {
        let m = DetectionMatches::NIMMAIN_SYMBOL | DetectionMatches::STT_FILE_DOT_NIM;
        let names: Vec<_> = m.iter().map(|(n, _)| n).collect();
        assert!(names.contains(&"NIMMAIN_SYMBOL"));
        assert!(names.contains(&"STT_FILE_DOT_NIM"));
        assert_eq!(names.len(), 2);
    }
}
