//! Module init-function scanner.
//!
//! Every Nim module compiles to an `Init000` function (runtime init) and
//! optionally a `DatInit000` (data-segment init) and `HcrInit000`
//! (hot-code-reload init). The function name encodes the module's
//! build-host filesystem path via the `@m`/`@s` token scheme decoded by
//! [`crate::demangle::modpath`]. See RESEARCH.md §7.

use crate::{
    container::Container,
    demangle::modpath::{self, ModulePath},
};
use core::fmt;

/// Classification of an init function.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's
/// stable API. Changes are SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InitKind {
    /// `*Init000` — runtime module initialisation.
    Init,
    /// `*DatInit000` — data-segment initialisation.
    DatInit,
    /// `*HcrInit000` — hot-code-reload initialisation.
    HcrInit,
}

impl fmt::Display for InitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Init => "Init",
            Self::DatInit => "DatInit",
            Self::HcrInit => "HcrInit",
        })
    }
}

/// A located module init function.
///
/// `address` is a virtual address (image load space). To convert to an
/// RVA for disassembler use, call [`crate::NimBinary::init_rva`].
#[derive(Debug, Clone)]
pub struct InitFunction {
    /// Classification.
    pub kind: InitKind,
    /// The raw symbol name.
    pub symbol_name: String,
    /// Virtual address (image load space, not file offset).
    pub address: u64,
    /// Decoded module path (filesystem path recovered from the mangled
    /// symbol name).
    pub module_path: ModulePath,
}

/// The init-function suffixes, ordered longest-first so that `DatInit000`
/// matches before `Init000`.
const INIT_SUFFIXES: &[(&str, InitKind)] = &[
    ("HcrInit000", InitKind::HcrInit),
    ("DatInit000", InitKind::DatInit),
    ("Init000", InitKind::Init),
];

/// Scans the container's symbol table for Nim module init functions.
///
/// Skips `NimMainModule` (which is an entry shim, not a module init
/// function) and linker-generated suffixed variants (e.g. `.cold.1`).
pub fn scan(container: &Container<'_>) -> Vec<InitFunction> {
    let mut result = Vec::new();

    for sym in container.symbols() {
        let name = sym.name.as_ref();
        // Skip linker-generated suffixed variants.
        if name.contains(".cold.") || name.contains(".TM_") || name.contains(".part.") {
            continue;
        }

        for &(suffix, kind) in INIT_SUFFIXES {
            if let Some(module_part) = name.strip_suffix(suffix) {
                // Skip the main-module shim `NimMainModule` and prefixed
                // variants (`<prefix>NimMainModule`) — those are entry
                // shims, not module init functions.
                if module_part.is_empty() || module_part.ends_with("NimMain") {
                    continue;
                }

                let module_path = modpath::decode(module_part);

                result.push(InitFunction {
                    kind,
                    symbol_name: name.to_string(),
                    address: sym.vm_addr,
                    module_path,
                });
                break;
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_kind_eq() {
        assert_eq!(InitKind::Init, InitKind::Init);
        assert_ne!(InitKind::Init, InitKind::DatInit);
    }
}
