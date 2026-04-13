//! Run-time type information (RTTI) recovery.
//!
//! Covers both the legacy `TNimType` / `TNimNode` (refc GC) layout and
//! the modern `TNimTypeV2` (ARC/ORC) layout. See `RESEARCH.md` section 3.
//!
//! - [`symbols::scan`] enumerates `NTIv2_` and `NTI_` globals from the
//!   symbol table.
//! - [`v2::read`] parses a `TNimTypeV2` struct at a given address.
//! - [`v1::read`] does best-effort parsing of a legacy `TNimType`.

pub mod symbols;
pub mod v1;
pub mod v2;
