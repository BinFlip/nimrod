//! Character-level identifier demangling.
//!
//! Implements the inverse of the substitution table in
//! `compiler/ccgutils.nim proc mangle*` (RESEARCH.md §8.1).
//!
//! The Nim compiler mangles special characters in identifiers into
//! alphabetic words (`$` → `dollar`, `=` → `eq`, etc.) and appends a
//! trailing underscore when any substitution was used. This module
//! reverses that process.

use std::borrow::Cow;

/// Substitution table: encoded word → original Nim character.
///
/// Ordered longest-first so that a greedy scan never mismatches a prefix
/// (e.g. `backslash` before `bar`). From `ccgutils.nim` lines 68–95.
const SUBSTITUTIONS: &[(&str, char)] = &[
    ("backslash", '\\'),
    ("percent", '%'),
    ("dollar", '$'),
    ("tilde", '~'),
    ("colon", ':'),
    ("qmark", '?'),
    ("emark", '!'),
    ("slash", '/'),
    ("minus", '-'),
    ("plus", '+'),
    ("star", '*'),
    ("roof", '^'),
    ("amp", '&'),
    ("bar", '|'),
    ("dot", '.'),
    ("lt", '<'),
    ("gt", '>'),
    ("eq", '='),
    ("at", '@'),
];

/// Demangles a Nim identifier back to its original form.
///
/// If the input contains substitutions (indicated by a trailing `_`), they
/// are reversed. If no substitutions are present the input is returned
/// as-is (zero-copy).
///
/// The leading-digit escape (`X<digit>` at position 0, where the original
/// identifier started with a digit) and the arbitrary-byte escape
/// (`X<hex2>`) are also decoded.
///
/// # Examples
///
/// ```
/// use nimrod::demangle::identifier::demangle;
///
/// assert_eq!(demangle("amp"), "amp");         // no trailing _ → passthrough
/// assert_eq!(demangle("amp_"), "&");           // trailing _ → substitution
/// assert_eq!(demangle("colonOrEquals_"), ":OrEquals");
/// assert_eq!(demangle("X20_"), " ");           // hex escape (uppercase hex)
/// assert_eq!(demangle("X1foo"), "X1foo");      // no trailing _ → literal
/// ```
pub fn demangle(mangled: &str) -> Cow<'_, str> {
    // A trailing underscore signals that substitutions were applied.
    // Without it the identifier is literal (possibly with a leading-digit
    // escape, but nothing else).
    let (body, had_substitutions) = if let Some(stripped) = mangled.strip_suffix('_') {
        (stripped, true)
    } else {
        (mangled, false)
    };

    if !had_substitutions {
        // Without a trailing `_`, no substitutions were applied, so the
        // string is literal. (Leading-digit escapes are ambiguous without
        // the trailing `_` context — `X0` could be literal `X0` or
        // escaped `0` — so we treat everything as literal.)
        return Cow::Borrowed(mangled);
    }

    let mut out = String::with_capacity(body.len());
    let bytes = body.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Try X<hex2> escape.
        // Nim's `toHex(ord(c), 2)` always produces UPPERCASE hex digits,
        // and only for characters not handled by passthrough or named
        // substitutions. We check both conditions to avoid false positives.
        if bytes[i] == b'X' {
            if i + 2 < bytes.len() {
                let hi = bytes[i + 1];
                let lo = bytes[i + 2];

                if is_upper_hex(hi) && is_upper_hex(lo) {
                    if let Some(val) = decode_hex2(hi, lo) {
                        if !is_mangle_passthrough_or_substitution(val) {
                            out.push(val as char);
                            i += 3;
                            continue;
                        }
                    }
                }
            }

            // Leading-digit escape at position 0: X followed by a digit
            // that started the original Nim identifier.
            if i == 0 && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
        }

        // Try substitution words (longest-first).
        if let Some((word, ch)) = try_substitution(&bytes[i..]) {
            out.push(ch);
            i += word.len();
            continue;
        }

        // Literal character.
        out.push(bytes[i] as char);
        i += 1;
    }

    Cow::Owned(out)
}

/// Mangles a Nim identifier using the same rules as `ccgutils.nim proc mangle*`.
///
/// This is the forward direction — primarily useful for round-trip testing
/// via proptest.
pub fn mangle(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut result = String::with_capacity(name.len());
    let mut start = 0;
    let mut requires_underscore = false;

    // Leading-digit escape.
    if !bytes.is_empty() && bytes[0].is_ascii_digit() {
        result.push('X');
        result.push(bytes[0] as char);
        start = 1;
    }

    for i in start..bytes.len() {
        let c = bytes[i];
        match c {
            b'a'..=b'z' | b'0'..=b'9' | b'A'..=b'Z' => {
                result.push(c as char);
            }
            b'_' => {
                // Nim discards underscores before digits (scope disambiguator).
                if i > 0 && i < bytes.len() - 1 && bytes[i + 1].is_ascii_digit() {
                    // discard
                } else {
                    result.push('_');
                }
            }
            _ => {
                let word = match c {
                    b'$' => "dollar",
                    b'%' => "percent",
                    b'&' => "amp",
                    b'^' => "roof",
                    b'!' => "emark",
                    b'?' => "qmark",
                    b'*' => "star",
                    b'+' => "plus",
                    b'-' => "minus",
                    b'/' => "slash",
                    b'\\' => "backslash",
                    b'=' => "eq",
                    b'<' => "lt",
                    b'>' => "gt",
                    b'~' => "tilde",
                    b':' => "colon",
                    b'.' => "dot",
                    b'@' => "at",
                    b'|' => "bar",
                    _ => {
                        result.push('X');
                        result.push(to_hex_upper((c >> 4) & 0xF));
                        result.push(to_hex_upper(c & 0xF));
                        requires_underscore = true;
                        continue;
                    }
                };
                result.push_str(word);
                requires_underscore = true;
            }
        }
    }

    if requires_underscore {
        result.push('_');
    }
    result
}

fn to_hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + nibble - 10) as char,
        _ => unreachable!(),
    }
}

fn try_substitution(bytes: &[u8]) -> Option<(&'static str, char)> {
    // Greedy longest-first matching. No word-boundary check is needed
    // because the trailing underscore already tells us that substitutions
    // are present, and no substitution word is a prefix of another, so the
    // longest-first ordering is unambiguous.
    //
    // Edge case: `fooampbar_` is genuinely ambiguous between `foo&|` and
    // `foo&bar` — the Nim compiler's mangle produces the same output for
    // both. We match greedily (same as ESET nimfilt).
    for &(word, ch) in SUBSTITUTIONS {
        if bytes.len() >= word.len() && &bytes[..word.len()] == word.as_bytes() {
            return Some((word, ch));
        }
    }
    None
}

/// Returns `true` if `b` is an uppercase hex digit (0-9, A-F).
/// Nim's `toHex` always emits uppercase, so lowercase hex after `X`
/// means the `X` is a literal character.
fn is_upper_hex(b: u8) -> bool {
    b.is_ascii_digit() || matches!(b, b'A'..=b'F')
}

/// Returns `true` if `b` is a character that Nim's `mangle` handles via
/// passthrough (alphanumeric, underscore) or a named substitution word.
/// Such characters are never encoded via `X<hex2>`.
fn is_mangle_passthrough_or_substitution(b: u8) -> bool {
    matches!(b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'
        | b'$' | b'%' | b'&' | b'^' | b'!' | b'?'
        | b'*' | b'+' | b'-' | b'/' | b'\\' | b'='
        | b'<' | b'>' | b'~' | b':' | b'.' | b'@' | b'|'
    )
}

fn decode_hex2(hi: u8, lo: u8) -> Option<u8> {
    let h = hex_val(hi)?;
    let l = hex_val(lo)?;
    Some((h << 4) | l)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn plain_identifier_passthrough() {
        assert_eq!(demangle("fooBar"), "fooBar");
        assert_eq!(demangle("x"), "x");
    }

    #[test]
    fn no_trailing_underscore_means_literal() {
        // "amp" without trailing _ is the literal identifier "amp"
        assert_eq!(demangle("amp"), "amp");
        assert_eq!(demangle("dot"), "dot");
    }

    #[test]
    fn every_substitution() {
        assert_eq!(demangle("dollar_"), "$");
        assert_eq!(demangle("percent_"), "%");
        assert_eq!(demangle("amp_"), "&");
        assert_eq!(demangle("roof_"), "^");
        assert_eq!(demangle("emark_"), "!");
        assert_eq!(demangle("qmark_"), "?");
        assert_eq!(demangle("star_"), "*");
        assert_eq!(demangle("plus_"), "+");
        assert_eq!(demangle("minus_"), "-");
        assert_eq!(demangle("slash_"), "/");
        assert_eq!(demangle("backslash_"), "\\");
        assert_eq!(demangle("eq_"), "=");
        assert_eq!(demangle("lt_"), "<");
        assert_eq!(demangle("gt_"), ">");
        assert_eq!(demangle("tilde_"), "~");
        assert_eq!(demangle("colon_"), ":");
        assert_eq!(demangle("dot_"), ".");
        assert_eq!(demangle("at_"), "@");
        assert_eq!(demangle("bar_"), "|");
    }

    #[test]
    fn mixed_substitutions() {
        // colonOrEquals → :OrEquals
        assert_eq!(demangle("colonOrEquals_"), ":OrEquals");
        // ampeq → &=
        assert_eq!(demangle("ampeq_"), "&=");
        // ltlt → <<
        assert_eq!(demangle("ltlt_"), "<<");
    }

    #[test]
    fn hex_escape() {
        // Nim's toHex always uses uppercase hex digits.
        // X20 → ' ' (0x20 = 32)
        assert_eq!(demangle("X20_"), " ");
        // X7B → '{' (0x7B = 123)
        assert_eq!(demangle("X7B_"), "{");
    }

    #[test]
    fn leading_digit_escape() {
        // Leading-digit escape only fires in substitution mode (trailing _).
        // mangle("1+") → "X1plus_"
        assert_eq!(demangle("X1plus_"), "1+");
        // Without trailing _, X1foo is literal.
        assert_eq!(demangle("X1foo"), "X1foo");
    }

    #[test]
    fn real_world_identifiers() {
        // From the nightly binary
        assert_eq!(demangle("genNimMainInner"), "genNimMainInner");
        assert_eq!(demangle("GC_getStatistics"), "GC_getStatistics");
        assert_eq!(demangle("amp_"), "&");
        assert_eq!(demangle("ampeq_"), "&=");
        assert_eq!(demangle("colonOrEquals_"), ":OrEquals");
        assert_eq!(demangle("colonanonymous_"), ":anonymous");
    }

    #[test]
    fn mangle_plain() {
        assert_eq!(mangle("fooBar"), "fooBar");
    }

    #[test]
    fn mangle_special_chars() {
        assert_eq!(mangle("$"), "dollar_");
        assert_eq!(mangle("&="), "ampeq_");
        assert_eq!(mangle(":OrEquals"), "colonOrEquals_");
    }

    #[test]
    fn mangle_leading_digit() {
        assert_eq!(mangle("1foo"), "X1foo");
    }

    #[test]
    fn mangle_hex_fallback() {
        assert_eq!(mangle(" "), "X20_");
    }

    #[test]
    fn round_trip_basic() {
        // Note: the Nim mangling scheme has inherent ambiguities when
        // substitution words appear as literal substrings (e.g. "$dollar"
        // and "$$" both mangle to "dollardollar_"). We test cases that are
        // unambiguous and representative of real Nim identifiers.
        for name in &["foo", "&", "&=", ":OrEquals", "a+b", "GC_ref"] {
            let mangled = mangle(name);
            let back = demangle(&mangled);
            assert_eq!(
                &*back, *name,
                "round-trip failed for {name:?} (mangled: {mangled:?})"
            );
        }
    }

    // Nim's mangling scheme has inherent ambiguities when substitution
    // words appear as literal substrings (e.g. "+lt" and "+<" both
    // mangle to "pluslt_"). We restrict the proptest to inputs that
    // are unambiguous round-trips.

    /// Strategy 1: pure alphanumeric identifiers (no substitutions).
    /// Avoids `_<digit>` sequences (mangle silently drops them) and
    /// `X<digit>` at position 0 (ambiguous with leading-digit escape).
    fn alpha_ident_strategy() -> impl Strategy<Value = String> {
        "[a-wyzA-WYZ][a-zA-Z0-9]{0,19}"
    }

    /// Strategy 2: pure operator sequences (all substitution chars,
    /// no adjacent literal text to create ambiguity).
    fn operator_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop::sample::select(vec![
                '$', '%', '&', '^', '!', '?', '*', '+', '-', '/', '\\', '=', '<', '>', '~', ':',
                '.', '@', '|',
            ]),
            1..6,
        )
        .prop_map(|chars| chars.into_iter().collect::<String>())
    }

    proptest! {
        #[test]
        fn proptest_alpha_round_trip(name in alpha_ident_strategy()) {
            let mangled = mangle(&name);
            let back = demangle(&mangled);
            prop_assert_eq!(&*back, &*name,
                "round-trip failed: {:?} → {:?} → {:?}", name, mangled, back);
        }

        #[test]
        fn proptest_operator_round_trip(name in operator_strategy()) {
            let mangled = mangle(&name);
            let back = demangle(&mangled);
            prop_assert_eq!(&*back, &*name,
                "round-trip failed: {:?} → {:?} → {:?}", name, mangled, back);
        }

        #[test]
        fn proptest_mangle_produces_valid_c_identifier(name in alpha_ident_strategy()) {
            let mangled = mangle(&name);
            for (i, b) in mangled.bytes().enumerate() {
                prop_assert!(
                    b.is_ascii_alphanumeric() || b == b'_',
                    "mangled form {:?} has non-C-ident byte {:#04x} at position {}",
                    mangled, b, i
                );
            }
        }
    }
}
