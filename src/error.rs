//! Error types for Nim binary parsing.
//!
//! A single flat [`Error`] enum covers all failure modes across container
//! parsing, symbol table access, RTTI recovery, string scanning, and
//! demangling. Same shape as the `nsis` crate's error enum — intentionally
//! flat rather than hierarchical.

use core::fmt;
use std::error;

/// Crate-wide `Result` alias.
pub type Result<T> = core::result::Result<T, Error>;

/// All errors that can occur during Nim binary parsing.
///
/// Each variant carries enough context for a useful diagnostic message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The underlying container parser (`goblin`) failed.
    ///
    /// The inner string is the stringified goblin error. We stringify because
    /// `goblin::error::Error` does not implement `Clone` / `Eq`, which we
    /// want on our own error type.
    Goblin(String),

    /// The input bytes are not an ELF, PE, or Mach-O file — or the container
    /// format is recognised but not one we currently support.
    UnsupportedFormat,

    /// A buffer or structure is shorter than the parser expected.
    TooShort {
        /// Human-readable name of the structure being parsed.
        what: &'static str,
        /// Minimum bytes required.
        expected: usize,
        /// Actual bytes available.
        actual: usize,
    },

    /// A structure failed internal validation (bad magic, impossible field
    /// value, inconsistent size, etc.).
    Malformed {
        /// Name of the structure.
        what: &'static str,
        /// Short human-readable reason.
        reason: &'static str,
    },

    /// A virtual address did not resolve to any section/segment in the
    /// container.
    UnmappedAddress {
        /// The unresolved virtual address.
        va: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Goblin(msg) => write!(f, "container parsing error: {msg}"),
            Error::UnsupportedFormat => {
                write!(f, "unsupported container format (not ELF/PE/Mach-O)")
            }
            Error::TooShort {
                what,
                expected,
                actual,
            } => write!(
                f,
                "{what}: expected at least {expected} bytes, got {actual}"
            ),
            Error::Malformed { what, reason } => {
                write!(f, "malformed {what}: {reason}")
            }
            Error::UnmappedAddress { va } => {
                write!(f, "virtual address 0x{va:016x} is not mapped")
            }
        }
    }
}

impl error::Error for Error {}

impl From<goblin::error::Error> for Error {
    fn from(e: goblin::error::Error) -> Self {
        Error::Goblin(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_goblin() {
        let e = Error::Goblin("bad magic".into());
        assert_eq!(e.to_string(), "container parsing error: bad magic");
    }

    #[test]
    fn display_unsupported_format() {
        let e = Error::UnsupportedFormat;
        assert!(e.to_string().contains("unsupported"));
    }

    #[test]
    fn display_too_short() {
        let e = Error::TooShort {
            what: "NimStringV2",
            expected: 16,
            actual: 8,
        };
        let s = e.to_string();
        assert!(s.contains("NimStringV2"));
        assert!(s.contains("16"));
        assert!(s.contains("8"));
    }

    #[test]
    fn display_malformed() {
        let e = Error::Malformed {
            what: "TNimTypeV2",
            reason: "destructor pointer out of range",
        };
        let s = e.to_string();
        assert!(s.contains("TNimTypeV2"));
        assert!(s.contains("destructor"));
    }

    #[test]
    fn display_unmapped_address() {
        let e = Error::UnmappedAddress { va: 0xdeadbeef };
        assert!(e.to_string().contains("deadbeef"));
    }

    #[test]
    fn error_is_clone_eq() {
        let a = Error::UnsupportedFormat;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn error_trait_impl() {
        let e: Box<dyn std::error::Error> = Box::new(Error::UnsupportedFormat);
        let _ = e.to_string();
    }
}
