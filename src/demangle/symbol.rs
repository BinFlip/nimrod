//! Nim symbol-name parser.
//!
//! Parses the canonical Nim symbol layout
//! `<mangled_identifier>__<module_unique_name>_u<item_id>` emitted by
//! `compiler/ccgtypes.nim proc fillBackendName` (RESEARCH.md §8.2).
//!
//! The identifier part is demangled via [`super::identifier::demangle`],
//! and the module name may contain Z-encoded path separators (e.g.
//! `OOZdistZchecksumsZsrcZchecksumsZmd5`).

use std::borrow::Cow;

use crate::demangle::identifier;

/// A parsed Nim symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Demangled<'a> {
    /// Demangled Nim identifier (inverse of `ccgutils.nim mangle`).
    pub identifier: Cow<'a, str>,
    /// Raw module unique name. May contain `Z`-encoded path separators
    /// (e.g. `OOZdistZchecksumsZsrcZchecksumsZmd5`).
    pub module: &'a str,
    /// The `itemId.item` disambiguator, or `None` if the `_u<N>` suffix
    /// was absent.
    pub item_id: Option<u64>,
    /// The raw mangled identifier before demangling (the part before `__`).
    pub raw_identifier: &'a str,
}

/// Attempts to parse a Nim symbol name into its components.
///
/// Returns `None` if the symbol does not match the canonical
/// `<ident>__<module>_u<id>` format.
///
/// # Examples
///
/// ```
/// use nimrod::demangle::symbol::parse;
///
/// let d = parse("genNimMainInner__cgen_u41496").unwrap();
/// assert_eq!(&*d.identifier, "genNimMainInner");
/// assert_eq!(d.module, "cgen");
/// assert_eq!(d.item_id, Some(41496));
/// ```
pub fn parse(symbol: &str) -> Option<Demangled<'_>> {
    // Find the `__` separator between identifier and module. We need the
    // *rightmost* `__` that still leaves a valid module+id suffix, because
    // the identifier itself can contain underscores.
    //
    // However, the identifier may end with `_` (the substitution marker
    // from mangle). When it does, the separator looks like `___` (three
    // underscores). We handle this by scanning for `__` from the right
    // and validating the suffix.

    let (raw_ident, module, item_id) = split_symbol(symbol)?;

    let identifier = identifier::demangle(raw_ident);

    Some(Demangled {
        identifier,
        module,
        item_id,
        raw_identifier: raw_ident,
    })
}

/// Splits `symbol` into `(raw_ident, module, item_id)` by finding the
/// `__` separator and then the `_u<N>` suffix.
fn split_symbol(symbol: &str) -> Option<(&str, &str, Option<u64>)> {
    // Scan for `__` positions from right to left. The first valid split
    // (where the right side contains a plausible module name) wins.
    let bytes = symbol.as_bytes();

    // We need at least `X__Y` (1 char ident + __ + 1 char module).
    if bytes.len() < 4 {
        return None;
    }

    // Iterate potential `__` split positions from right to left.
    let start = bytes.len().saturating_sub(2);
    for i in (1..=start).rev() {
        let b0 = bytes.get(i).copied();
        let b1 = bytes.get(i.saturating_add(1)).copied();
        if b0 == Some(b'_') && b1 == Some(b'_') {
            // Check that this isn't the middle of `___` — if bytes[i-1]
            // is also `_`, we may need to try one position further left
            // to get the real split. But first, try this position.
            let raw_ident = symbol.get(..i).unwrap_or("");
            let suffix = symbol.get(i.saturating_add(2)..).unwrap_or("");

            if !raw_ident.is_empty()
                && !suffix.is_empty()
                && let Some((module, item_id)) = parse_module_suffix(suffix)
            {
                return Some((raw_ident, module, item_id));
            }
        }
    }

    None
}

/// Parses the `<module>_u<id>` or bare `<module>` suffix after `__`.
fn parse_module_suffix(suffix: &str) -> Option<(&str, Option<u64>)> {
    // Try to find `_u<digits>` at the end.
    if let Some(pos) = suffix.rfind("_u") {
        let after_u = suffix.get(pos.saturating_add(2)..).unwrap_or("");
        // The part after `_u` may have an HCR trailing suffix like `_<hash>`.
        // Parse digits greedily from the start.
        let digit_end = after_u
            .bytes()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(after_u.len());

        if digit_end > 0 {
            let id: u64 = after_u.get(..digit_end)?.parse().ok()?;
            let module = suffix.get(..pos)?;
            if !module.is_empty() && is_valid_module_name(module) {
                return Some((module, Some(id)));
            }
        }
    }

    // No `_u<id>` suffix — the entire suffix is the module name.
    // This happens for some special symbols.
    if is_valid_module_name(suffix) {
        return Some((suffix, None));
    }

    None
}

/// Quick validity check for a module name. Module names are mangled
/// identifiers containing alphanumeric chars, underscores, and `Z`
/// (used as path separator encoding in `mangleModuleName`).
fn is_valid_module_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_symbol() {
        let d = parse("genNimMainInner__cgen_u41496").unwrap();
        assert_eq!(&*d.identifier, "genNimMainInner");
        assert_eq!(d.module, "cgen");
        assert_eq!(d.item_id, Some(41496));
    }

    #[test]
    fn operator_symbol() {
        let d = parse("amp___docgen_u11299").unwrap();
        assert_eq!(&*d.identifier, "&");
        assert_eq!(d.module, "docgen");
        assert_eq!(d.item_id, Some(11299));
    }

    #[test]
    fn compound_operator() {
        let d = parse("ampeq___sighashes_u12").unwrap();
        assert_eq!(&*d.identifier, "&=");
        assert_eq!(d.module, "sighashes");
        assert_eq!(d.item_id, Some(12));
    }

    #[test]
    fn literal_camelcase_identifier() {
        // "colonOrEquals" is a literal Nim identifier name (a token kind
        // in the parser), not an operator. No trailing `_` in the mangled
        // form means no substitutions.
        let d = parse("colonOrEquals__parser_u350").unwrap();
        assert_eq!(&*d.identifier, "colonOrEquals");
        assert_eq!(d.module, "parser");
        assert_eq!(d.item_id, Some(350));
    }

    #[test]
    fn z_encoded_module_path() {
        let d = parse("FF__OOZdistZchecksumsZsrcZchecksumsZmd5_u42").unwrap();
        assert_eq!(&*d.identifier, "FF");
        assert_eq!(d.module, "OOZdistZchecksumsZsrcZchecksumsZmd5");
        assert_eq!(d.item_id, Some(42));
    }

    #[test]
    fn underscore_in_identifier() {
        let d = parse("GC_getStatistics__system_u7819").unwrap();
        assert_eq!(&*d.identifier, "GC_getStatistics");
        assert_eq!(d.module, "system");
        assert_eq!(d.item_id, Some(7819));
    }

    #[test]
    fn z_module_with_z_prefix() {
        let d = parse("WEXITSTATUS__posixZposix_u1063").unwrap();
        assert_eq!(&*d.identifier, "WEXITSTATUS");
        assert_eq!(d.module, "posixZposix");
        assert_eq!(d.item_id, Some(1063));
    }

    #[test]
    fn pure_z_module() {
        let d = parse("DefaultLocale__pureZtimes_u2303").unwrap();
        assert_eq!(&*d.identifier, "DefaultLocale");
        assert_eq!(d.module, "pureZtimes");
        assert_eq!(d.item_id, Some(2303));
    }

    #[test]
    fn rejects_non_nim() {
        assert!(parse("main").is_none());
        assert!(parse("_start").is_none());
        assert!(parse("printf").is_none());
    }

    #[test]
    fn rejects_bare_separator() {
        assert!(parse("__").is_none());
        assert!(parse("foo__").is_none());
    }

    #[test]
    fn triple_underscore_operator() {
        // colonanonymous_ + __ + cgen_u4206
        let d = parse("colonanonymous___cgen_u4206").unwrap();
        assert_eq!(&*d.identifier, ":anonymous");
        assert_eq!(d.module, "cgen");
        assert_eq!(d.item_id, Some(4206));
    }
}
