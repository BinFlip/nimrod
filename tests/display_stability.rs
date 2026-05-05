//! Snapshot test for the public-enum `Display` strings.
//!
//! These strings are part of nimrod's stable API: downstream consumers
//! persist them as schema discriminators. If a variant is renamed, this
//! test fails and reminds the author to bump the SemVer-major.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use nimrod::{Arch, Format, GcMode, InitKind, PathOs, RttiVersion, ShimKind};

#[test]
fn format_display_strings() {
    assert_eq!(Format::Elf.to_string(), "Elf");
    assert_eq!(Format::Pe.to_string(), "Pe");
    assert_eq!(Format::MachO.to_string(), "MachO");
}

#[test]
fn arch_display_strings() {
    assert_eq!(Arch::I386.to_string(), "I386");
    assert_eq!(Arch::Amd64.to_string(), "Amd64");
    assert_eq!(Arch::Arm.to_string(), "Arm");
    assert_eq!(Arch::Aarch64.to_string(), "Aarch64");
    assert_eq!(Arch::Riscv32.to_string(), "Riscv32");
    assert_eq!(Arch::Riscv64.to_string(), "Riscv64");
    assert_eq!(Arch::PowerPc.to_string(), "PowerPc");
    assert_eq!(Arch::PowerPc64.to_string(), "PowerPc64");
    assert_eq!(Arch::Other.to_string(), "Other");
}

#[test]
fn gc_mode_display_strings() {
    assert_eq!(GcMode::Refc.to_string(), "Refc");
    assert_eq!(GcMode::ArcOrc.to_string(), "ArcOrc");
    assert_eq!(GcMode::Unknown.to_string(), "Unknown");
}

#[test]
fn shim_kind_display_strings() {
    assert_eq!(ShimKind::NimMain.to_string(), "NimMain");
    assert_eq!(ShimKind::NimMainInner.to_string(), "NimMainInner");
    assert_eq!(ShimKind::PreMain.to_string(), "PreMain");
    assert_eq!(ShimKind::PreMainInner.to_string(), "PreMainInner");
    assert_eq!(ShimKind::NimMainModule.to_string(), "NimMainModule");
}

#[test]
fn init_kind_display_strings() {
    assert_eq!(InitKind::Init.to_string(), "Init");
    assert_eq!(InitKind::DatInit.to_string(), "DatInit");
    assert_eq!(InitKind::HcrInit.to_string(), "HcrInit");
}

#[test]
fn rtti_version_display_strings() {
    assert_eq!(RttiVersion::V1.to_string(), "V1");
    assert_eq!(RttiVersion::V2.to_string(), "V2");
}

#[test]
fn path_os_display_strings() {
    assert_eq!(PathOs::Windows.to_string(), "Windows");
    assert_eq!(PathOs::Unix.to_string(), "Unix");
    assert_eq!(PathOs::Unknown.to_string(), "Unknown");
}

/// Display must match Debug exactly so consumers' existing
/// `format!("{:?}", …)` rows stay valid after the migration to Display.
#[test]
fn display_matches_debug_for_every_variant() {
    macro_rules! check {
        ($variant:expr) => {
            assert_eq!(format!("{}", $variant), format!("{:?}", $variant));
        };
    }
    check!(Format::Elf);
    check!(Format::Pe);
    check!(Format::MachO);
    check!(Arch::I386);
    check!(Arch::Amd64);
    check!(Arch::Arm);
    check!(Arch::Aarch64);
    check!(Arch::Riscv32);
    check!(Arch::Riscv64);
    check!(Arch::PowerPc);
    check!(Arch::PowerPc64);
    check!(Arch::Other);
    check!(GcMode::Refc);
    check!(GcMode::ArcOrc);
    check!(GcMode::Unknown);
    check!(ShimKind::NimMain);
    check!(ShimKind::NimMainInner);
    check!(ShimKind::PreMain);
    check!(ShimKind::PreMainInner);
    check!(ShimKind::NimMainModule);
    check!(InitKind::Init);
    check!(InitKind::DatInit);
    check!(InitKind::HcrInit);
    check!(RttiVersion::V1);
    check!(RttiVersion::V2);
    check!(PathOs::Windows);
    check!(PathOs::Unix);
    check!(PathOs::Unknown);
}
