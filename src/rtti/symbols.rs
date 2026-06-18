//! RTTI symbol enumeration.
//!
//! Scans the symbol table for `NTIv2_` (ARC/ORC) and `NTI_` (refc)
//! globals, returning structured entries for each. See RESEARCH.md §3.4.

use crate::container::Container;
use core::fmt;

/// Which RTTI generation a symbol belongs to.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's
/// stable API. Changes are SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RttiVersion {
    /// Legacy `TNimType` (refc GC). Symbol format: `NTI<typespec><hash>_`.
    V1,
    /// Modern `TNimTypeV2` (ARC/ORC). Symbol format: `NTIv2<hash>_`.
    V2,
}

impl RttiVersion {
    /// Returns the stable string identifier for this RTTI version.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1 => "V1",
            Self::V2 => "V2",
        }
    }
}

impl fmt::Display for RttiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A located RTTI symbol.
///
/// `address` is a virtual address (image load space). To convert to an
/// RVA for disassembler use, call [`crate::NimBinary::rtti_rva`].
#[derive(Debug, Clone)]
pub struct RttiSymbol {
    /// V1 or V2.
    pub version: RttiVersion,
    /// The full symbol name (e.g. `NTIv2__abc123_`).
    pub symbol_name: String,
    /// Virtual address of the RTTI global (image load space, not file
    /// offset).
    pub address: u64,
    /// For V1 symbols, the type-name fragment between `NTI` and the hash.
    /// E.g. `NTIseqLintT<hash>_` → `Some("seqLintT")`.
    /// Always `None` for V2 symbols.
    pub type_fragment: Option<String>,
}

/// Scans the container's symbol table for all RTTI globals.
pub fn scan(container: &Container<'_>) -> Vec<RttiSymbol> {
    let mut result = Vec::new();

    for sym in container.symbols() {
        let name = sym.name.as_ref();
        if !name.ends_with('_') {
            continue;
        }

        if let Some(_inner) = name.strip_prefix("NTIv2") {
            result.push(RttiSymbol {
                version: RttiVersion::V2,
                symbol_name: name.to_string(),
                address: sym.vm_addr,
                type_fragment: None,
            });
        } else if let Some(inner) = name.strip_prefix("NTI") {
            let body = inner.strip_suffix('_').unwrap_or(inner);
            let type_fragment = extract_v1_type_fragment(body).map(|s| s.to_string());
            result.push(RttiSymbol {
                version: RttiVersion::V1,
                symbol_name: name.to_string(),
                address: sym.vm_addr,
                type_fragment,
            });
        }
    }

    result
}

/// Extracts the type-name fragment from a V1 RTTI symbol body.
///
/// V1 symbols are `NTI<typeToC(t)><hash>_` where `typeToC` produces a
/// lowercase representation with substitutions (`,→_`, `.→O`, etc.).
/// The hash is an opaque suffix. We split at the boundary where the
/// readable type name ends and the hash begins. The hash is typically
/// `__<SigHash>` but the format isn't guaranteed, so we do best-effort.
fn extract_v1_type_fragment(body: &str) -> Option<&str> {
    // The body often has the form `<typename>__<hash>`. Try splitting on `__`.
    if let Some(pos) = body.find("__") {
        let frag = &body[..pos];
        if !frag.is_empty() {
            return Some(frag);
        }
    }
    // Fallback: the entire body is the type name (no hash separator found).
    if !body.is_empty() { Some(body) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_v1_fragment_with_hash() {
        assert_eq!(
            extract_v1_type_fragment("seqLintT__abc123"),
            Some("seqLintT")
        );
    }

    #[test]
    fn extract_v1_fragment_no_hash() {
        assert_eq!(extract_v1_type_fragment("int"), Some("int"));
    }

    #[test]
    fn extract_v1_fragment_empty() {
        assert_eq!(extract_v1_type_fragment(""), None);
    }
}
