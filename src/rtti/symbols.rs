//! RTTI symbol enumeration.
//!
//! Scans the symbol table for `NTIv2_` (ARC/ORC) and `NTI_` (refc)
//! globals, returning structured entries for each. See RESEARCH.md §3.4.

use crate::container::Container;

/// Which RTTI generation a symbol belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RttiVersion {
    /// Legacy `TNimType` (refc GC). Symbol format: `NTI<typespec><hash>_`.
    V1,
    /// Modern `TNimTypeV2` (ARC/ORC). Symbol format: `NTIv2<hash>_`.
    V2,
}

/// A located RTTI symbol.
#[derive(Debug, Clone)]
pub struct RttiSymbol<'a> {
    /// V1 or V2.
    pub version: RttiVersion,
    /// The full symbol name (e.g. `NTIv2__abc123_`).
    pub symbol_name: &'a str,
    /// Virtual address of the RTTI global.
    pub address: u64,
    /// For V1 symbols, the type-name fragment between `NTI` and the hash.
    /// E.g. `NTIseqLintT<hash>_` → `Some("seqLintT")`.
    /// Always `None` for V2 symbols.
    pub type_fragment: Option<&'a str>,
}

/// Scans the container's symbol table for all RTTI globals.
pub fn scan<'a>(container: &'a Container<'a>) -> Vec<RttiSymbol<'a>> {
    let mut result = Vec::new();

    for sym in container.symbols() {
        let name = sym.name.as_ref();
        if !name.ends_with('_') {
            continue;
        }

        if let Some(inner) = name.strip_prefix("NTIv2") {
            // V2: NTIv2<hash>_
            let _ = inner; // hash is the part between "NTIv2" and trailing "_"
            result.push(RttiSymbol {
                version: RttiVersion::V2,
                symbol_name: name,
                address: sym.vm_addr,
                type_fragment: None,
            });
        } else if let Some(inner) = name.strip_prefix("NTI") {
            // V1: NTI<typespec><hash>_ — the hash is separated from the
            // type spec by `__` in the naming convention from ccgtypes.nim.
            // We extract the type fragment before the hash.
            let body = inner.strip_suffix('_').unwrap_or(inner);
            let type_fragment = extract_v1_type_fragment(body);
            result.push(RttiSymbol {
                version: RttiVersion::V1,
                symbol_name: name,
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
