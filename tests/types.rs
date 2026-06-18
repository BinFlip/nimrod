//! Integration tests for the v0.3.0 type-graph, code-entrypoint, and
//! compiler-version surfaces.
//!
//! Fixtures live under `tests/fixtures/` (see `tests/integration.rs` for how
//! they are produced). Every test skips gracefully when its fixture is absent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};

use nimrod::{EntrypointKind, NimBinary, NimVersionHint, rtti::symbols::RttiVersion};

fn fixture_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn parse_fixture(rel: &str) -> Option<Vec<u8>> {
    std::fs::read(fixture_path(rel)).ok()
}

const NIGHTLY_ELF: &str = "nightly/linux_x64/nim-2.3.1/bin/nim";

#[test]
fn elf_v2_type_graph_is_fully_readable() {
    let Some(data) = parse_fixture(NIGHTLY_ELF) else {
        eprintln!("skip: {NIGHTLY_ELF} not present");
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();

    let types = bin.types();
    assert!(types.len() >= 80, "expected many V2 types, got {}", types.len());

    // One NimType per RTTI symbol (1:1 with the symbol scan).
    assert_eq!(types.len(), bin.rtti_symbols().len());

    // Every type is a readable V2 record with a parsed size/align.
    for t in types {
        assert_eq!(t.version, RttiVersion::V2);
        assert!(t.is_readable(), "V2 type {} should be file-backed", t.symbol_name);
        assert!(t.align > 0, "align should be populated for {}", t.symbol_name);
        assert!(t.depth.is_some(), "V2 depth should be populated");
    }

    // At least one object type has resolved members or an inheritance chain.
    assert!(
        types.iter().any(|t| !t.display_tokens.is_empty()),
        "expected V2 inheritance display tokens"
    );
    // Destructors resolve to functions for the bulk of types.
    let with_dtor = types.iter().filter(|t| t.destructor.is_some()).count();
    assert!(with_dtor > 0, "expected resolved destructors");
}

#[test]
fn elf_v2_display_tokens_track_depth() {
    let Some(data) = parse_fixture(NIGHTLY_ELF) else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    // The display array holds depth+1 class tokens (RESEARCH.md §3.2). Verify
    // for every type that produced one.
    let mut checked = 0;
    for t in bin.types() {
        if t.display_tokens.is_empty() {
            continue;
        }
        let depth = t.depth.expect("V2 type has depth");
        let expected = usize::try_from(depth).unwrap() + 1;
        assert_eq!(
            t.display_tokens.len(),
            expected,
            "{}: display token count should be depth+1",
            t.symbol_name
        );
        checked += 1;
    }
    assert!(checked > 0, "expected at least one type with display tokens");
}

#[test]
fn macho_v1_types_degrade_to_name_only() {
    // V1 globals land in Mach-O __DATA,__common (no file backing, §3.6): they
    // must surface as name-only shells, never panic, never drop.
    let Some(data) = parse_fixture("native/exceptions_refc_debug") else {
        eprintln!("skip: native/exceptions_refc_debug not present");
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let types = bin.types();
    assert!(!types.is_empty(), "expected V1 RTTI symbols");
    for t in types {
        assert_eq!(t.version, RttiVersion::V1);
        assert!(!t.is_readable(), "Mach-O V1 should be name-only");
        // The embedded type fragment is the forensic value that survives.
        assert!(t.type_fragment.is_some());
    }
    // The user-defined exception types are present by fragment.
    let frags: Vec<&str> = types
        .iter()
        .filter_map(|t| t.type_fragment.as_deref())
        .collect();
    assert!(
        frags.iter().any(|f| f.contains("myerror")),
        "expected MyError fragment, got {frags:?}"
    );
}

#[test]
fn compiler_version_distinguishes_modes() {
    let cases = [
        ("native/exceptions_arc_release", NimVersionHint::Nim2xArc),
        ("native/exceptions_orc_release", NimVersionHint::Nim2xOrc),
        ("native/exceptions_refc_debug", NimVersionHint::Nim1xRefc),
    ];
    for (rel, expected) in cases {
        let Some(data) = parse_fixture(rel) else {
            eprintln!("skip: {rel} not present");
            continue;
        };
        let bin = NimBinary::from_bytes(&data).unwrap();
        assert_eq!(bin.nim_version(), expected, "{rel}: version mismatch");
    }
}

#[test]
fn code_entrypoints_aggregate_sources() {
    let Some(data) = parse_fixture(NIGHTLY_ELF) else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let eps = bin.code_entrypoints();
    assert!(!eps.is_empty());

    // VA-sorted and unique.
    assert!(eps.windows(2).all(|w| w[0].va < w[1].va), "must be VA-sorted & deduped");

    let has = |k: EntrypointKind| eps.iter().any(|e| e.kind == k);
    assert!(has(EntrypointKind::EntryShim), "expected entry shims");
    assert!(has(EntrypointKind::ModuleInit), "expected module inits");
    assert!(has(EntrypointKind::ProcSymbol), "expected proc symbols");
}

#[test]
fn format_and_bitness_predicates() {
    if let Some(data) = parse_fixture(NIGHTLY_ELF) {
        let bin = NimBinary::from_bytes(&data).unwrap();
        assert!(bin.format().is_elf());
        assert!(!bin.format().is_pe());
        assert!(bin.is_64bit());
        assert_eq!(bin.bitness(), Some(64));
    }
}
