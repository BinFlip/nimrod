//! Nim string literal scanning.
//!
//! Covers both the V1 (`NimStringDesc` / `TGenericSeq`) and V2
//! (`NimStringV2` / `NimStrPayload`) layouts. See `RESEARCH.md` section 4.
//!
//! - [`v2::scan`] finds V2 literals via the `NIM_STRLIT_FLAG` pattern.
//! - [`v1::scan`] finds legacy V1 literals (best-effort).

pub mod v1;
pub mod v2;
