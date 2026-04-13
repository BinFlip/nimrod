//! Module-path token decoder.
//!
//! Decodes the `@m…@s…@h…` path markers (post-mangle form
//! `atm…ats…ath…`) used by Nim in init-function symbol names to encode
//! the build-host path that produced the module (RESEARCH.md §10).
//!
//! The decoding is a two-step process:
//!
//! 1. Run [`super::identifier::demangle`] on the mangled module name to
//!    recover the `@`-token form (e.g. `atpsystemdotnim_` → `@psystem.nim`).
//! 2. Interpret the `@m`, `@s`, `@p`, `@h`, `@d` tokens into a
//!    human-readable filesystem path.

use crate::demangle::identifier;

/// A decoded module path from an init-function symbol name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModulePath {
    /// The decoded filesystem-like path (e.g. `system/exceptions.nim`).
    pub path: String,
    /// The raw prefix token if present (`@m`, `@p`, `@d`, `@h`).
    /// `None` if the module name had no prefix token.
    pub prefix: Option<PathPrefix>,
}

/// The prefix token in a Nim module path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathPrefix {
    /// `@m` — module (direct source file).
    Module,
    /// `@p` — package / stdlib path.
    Package,
    /// `@d` — directory-level marker.
    Directory,
    /// `@h` — higher-level directory.
    Higher,
}

/// Decodes a mangled Nim module name into a filesystem path.
///
/// The input should be the module-name part of an init function symbol,
/// **including** the trailing `_` from the mangle substitution marker.
/// For example, from `atpsystemdotnim_Init000`, pass `atpsystemdotnim_`.
///
/// # Examples
///
/// ```
/// use nimrod::demangle::modpath::decode;
///
/// let m = decode("atpsystemdotnim_");
/// assert_eq!(m.path, "system.nim");
/// ```
pub fn decode(mangled_module: &str) -> ModulePath {
    // Step 1: reverse the character-level mangling.
    let demangled = identifier::demangle(mangled_module);

    // Step 2: parse @-tokens.
    parse_tokens(&demangled)
}

/// Parses a demangled `@`-token string into a `ModulePath`.
fn parse_tokens(s: &str) -> ModulePath {
    let (prefix, body) = strip_prefix(s);

    // Replace `@c` with `:` (drive-letter colon on Windows paths),
    // then split on `@s` (path separator) and join with `/`.
    let body = body.replace("@c", ":");
    let path = body
        .split("@s")
        .filter(|seg| !seg.is_empty())
        .collect::<Vec<_>>()
        .join("/");

    ModulePath { path, prefix }
}

/// Strips the leading `@m`, `@p`, `@d`, or `@h` prefix if present.
fn strip_prefix(s: &str) -> (Option<PathPrefix>, &str) {
    if let Some(rest) = s.strip_prefix("@m") {
        // Could be `@m` followed by `@d`, `@s`, etc.
        if let Some(rest2) = rest.strip_prefix("@d") {
            return (Some(PathPrefix::Directory), rest2);
        }
        (Some(PathPrefix::Module), rest)
    } else if let Some(rest) = s.strip_prefix("@p") {
        (Some(PathPrefix::Package), rest)
    } else if let Some(rest) = s.strip_prefix("@h") {
        (Some(PathPrefix::Higher), rest)
    } else if let Some(rest) = s.strip_prefix("@d") {
        (Some(PathPrefix::Directory), rest)
    } else {
        (None, s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdlib_system() {
        let m = decode("atpsystemdotnim_");
        assert_eq!(m.path, "system.nim");
        assert_eq!(m.prefix, Some(PathPrefix::Package));
    }

    #[test]
    fn stdlib_submodule() {
        let m = decode("atpsystematsexceptionsdotnim_");
        assert_eq!(m.path, "system/exceptions.nim");
        assert_eq!(m.prefix, Some(PathPrefix::Package));
    }

    #[test]
    fn module_direct() {
        let m = decode("atmast2nifdotnim_");
        assert_eq!(m.path, "ast2nif.nim");
        assert_eq!(m.prefix, Some(PathPrefix::Module));
    }

    #[test]
    fn deep_path() {
        let m = decode("atmatdatsdistatsnimonyatssrcatslibatsnifstreamsdotnim_");
        assert_eq!(m.path, "dist/nimony/src/lib/nifstreams.nim");
        assert_eq!(m.prefix, Some(PathPrefix::Directory));
    }

    #[test]
    fn welive_security_example() {
        // From RESEARCH.md §10:
        // atmCatcatstoolsatsNimatsnimminus2dot0dot0atslibatssystemdotnim
        // → C:/tools/Nim/nim-2.0.0/lib/system.nim
        let m = decode("atmCatcatstoolsatsNimatsnimminus2dot0dot0atslibatssystemdotnim_");
        assert_eq!(m.path, "C:/tools/Nim/nim-2.0.0/lib/system.nim");
        assert_eq!(m.prefix, Some(PathPrefix::Module));
    }

    #[test]
    fn no_prefix() {
        // A bare mangled name without @-prefix
        let m = decode("systemdotnim_");
        assert_eq!(m.path, "system.nim");
        assert_eq!(m.prefix, None);
    }

    #[test]
    fn no_trailing_underscore() {
        // If the mangled name has no trailing underscore (no substitutions
        // in the original), it's still a valid input.
        let m = decode("system");
        assert_eq!(m.path, "system");
        assert_eq!(m.prefix, None);
    }
}
