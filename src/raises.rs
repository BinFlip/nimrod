//! Exception raise-site recovery (phase 1).
//!
//! Every `raise` statement in Nim compiles to a call to
//! `raiseExceptionEx(e, "<TypeName>", "<proc>", "<file>", <line>)`.
//! All four string arguments are embedded as `.rodata` cstrings
//! (RESEARCH.md §5.5).
//!
//! **Phase 1** (this module) recovers exception type names only, by
//! scanning rodata for short cstrings matching known Nim exception
//! naming patterns (`*Error`, `*Defect`, `*Exception`). This is fast
//! and doesn't require instruction-level analysis.

use crate::{
    container::{Container, SectionKind},
    util,
};

/// A recovered exception type reference.
#[derive(Debug, Clone)]
pub struct ExceptionRef {
    /// The exception type name (e.g. `ValueError`, `MyError`).
    pub type_name: String,
}

/// Known Nim stdlib exception type names. These are always present as
/// cstrings when the exception infrastructure is compiled in.
const KNOWN_EXCEPTION_TYPES: &[&str] = &[
    "AssertionDefect",
    "ArithmeticDefect",
    "DivByZeroDefect",
    "OverflowDefect",
    "RangeDefect",
    "IndexDefect",
    "FieldDefect",
    "ObjectConversionDefect",
    "ReraiseDefect",
    "AccessViolationDefect",
    "DeadThreadDefect",
    "NilAccessDefect",
    "OutOfMemDefect",
    "StackOverflowDefect",
    "ValueError",
    "IOError",
    "EOFError",
    "OSError",
    "KeyError",
    "CatchableError",
    "Exception",
    "Defect",
    "FloatingPointDefect",
    "FloatInvalidOpDefect",
    "FloatDivByZeroDefect",
    "FloatOverflowDefect",
    "FloatUnderflowDefect",
    "FloatInexactDefect",
    "ResourceExhaustedError",
    "ObjectAssignmentDefect",
];

/// Scans read-only sections for exception type name cstrings.
///
/// Finds both known Nim stdlib exception types and user-defined types
/// matching the `*Error`, `*Defect`, or `*Exception` suffix pattern.
pub fn scan(container: &Container<'_>) -> Vec<ExceptionRef> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for section in container.sections() {
        if section.kind != SectionKind::RoData {
            continue;
        }
        scan_section(section.data, &mut results, &mut seen);
    }

    results
}

fn scan_section(
    data: &[u8],
    out: &mut Vec<ExceptionRef>,
    seen: &mut std::collections::HashSet<String>,
) {
    let mut offset = 0;
    while offset < data.len() {
        let Some(cstr) = util::slice_cstring(data, offset, 256) else {
            offset += 1;
            continue;
        };

        if cstr.is_empty() {
            offset += 1;
            continue;
        }

        let advance = cstr.len() + 1;

        if let Ok(s) = std::str::from_utf8(cstr) {
            if is_exception_type_name(s) && seen.insert(s.to_owned()) {
                out.push(ExceptionRef {
                    type_name: s.to_owned(),
                });
            }
        }

        offset += advance;
    }
}

/// Returns `true` if the string looks like a Nim exception type name.
fn is_exception_type_name(s: &str) -> bool {
    // Must be a valid identifier: starts with uppercase, alphanumeric.
    if s.len() < 3 || !s.as_bytes()[0].is_ascii_uppercase() {
        return false;
    }
    if !s.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }

    // Check known names first (exact match).
    if KNOWN_EXCEPTION_TYPES.contains(&s) {
        return true;
    }

    // Suffix pattern: *Error, *Defect, *Exception (user-defined types
    // typically follow Nim convention of naming exceptions this way).
    s.ends_with("Error") || s.ends_with("Defect") || s.ends_with("Exception")
}
