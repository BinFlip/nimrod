//! Symbol and module-path demangling.
//!
//! Three layers, matching the Nim compiler's mangling pipeline:
//!
//! - [`identifier::demangle`] — inverse of `ccgutils.nim proc mangle*`
//!   (character-level substitution reversal).
//! - [`symbol::parse`] — splits the canonical
//!   `<ident>__<module>_u<item_id>` layout from `fillBackendName`.
//! - [`modpath::decode`] — decodes the `atm…ats…` (encoded `@m…@s…`)
//!   module-path tokens used in init-function symbol names.
//!
//! See `RESEARCH.md` sections 8 and 10 for the format specification.

pub mod identifier;
pub mod modpath;
pub mod symbol;
