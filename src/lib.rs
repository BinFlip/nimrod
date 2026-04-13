//! Parse and inspect Nim-compiled native binaries.
//!
//! This crate provides a pure-Rust parser and forensic-artifact extractor for
//! binaries produced by the Nim compiler via its C, C++, or Objective-C
//! backends. A Nim-compiled program is a normal ELF, PE, or Mach-O executable
//! — there is no Nim-specific container. The crate recovers Nim **runtime
//! artifacts** left inside an otherwise-ordinary native binary.
//!
//! # What it extracts
//!
//! | Artifact | Method | Notes |
//! |----------|--------|-------|
//! | Detection verdict | [`NimBinary::is_nim`] | 11 independent probes |
//! | Format / arch / GC mode | [`NimBinary::format`], [`NimBinary::gc_mode`] | ELF, PE, Mach-O; refc vs ARC/ORC |
//! | Entry shims | [`NimBinary::entry_shims`] | `NimMain`, `PreMain`, etc. |
//! | Init functions | [`NimBinary::init_functions`] | With decoded module paths |
//! | Module map | [`NimBinary::module_map`] | Per-module: symbols, sizes, init VAs, leaked paths |
//! | RTTI globals | [`NimBinary::rtti_symbols`] | V1 (`TNimType`) and V2 (`TNimTypeV2`) with parsed fields |
//! | String literals | [`NimBinary::string_literals_v2`] | V2 `NIM_STRLIT_FLAG` scan |
//! | Stack-trace metadata | [`NimBinary::stack_trace`] | Proc names + `.nim` file paths (build-host leaks) |
//! | Nimble path leaks | [`NimBinary::nimble_paths`] | Package name, version, hash, username, OS |
//! | Exception types | [`NimBinary::exception_types`] | `*Error`, `*Defect` cstrings in rodata |
//! | Raise sites | [`NimBinary::raise_sites`] | Full (type, proc, file, line) tuples via instruction analysis |
//! | Demangled symbols | [`demangle::symbol::parse`] | Identifier, module, item ID |
//!
//! # Quick start
//!
//! ```no_run
//! use nimrod::NimBinary;
//!
//! let data = std::fs::read("sample").unwrap();
//! let bin = NimBinary::from_bytes(&data).unwrap();
//!
//! if !bin.is_nim() {
//!     eprintln!("not a Nim binary");
//!     return;
//! }
//!
//! // Detection and classification
//! println!("format: {:?}, gc: {:?}", bin.format(), bin.gc_mode());
//!
//! // Module map: which Nim modules are compiled in, with every function
//! let mmap = bin.module_map();
//! for (name, info) in &mmap.modules {
//!     println!("{name}: {} functions", info.symbol_count());
//!     for sym in &info.symbols {
//!         // sym.name    = demangled Nim identifier
//!         // sym.address = VA (start disassembling here)
//!         // sym.size    = byte count (ELF; 0 on Mach-O/PE)
//!         let _ = (sym.name.as_str(), sym.address, sym.size);
//!     }
//! }
//!
//! // Raise sites: exception type + enclosing function + source location
//! for rs in &bin.raise_sites() {
//!     let _ = (
//!         rs.exception_type.as_deref(),   // "ValueError"
//!         rs.enclosing_function.as_deref(), // "parseHexInt__strutils_u1234"
//!         rs.file.as_deref(),              // "strutils.nim"
//!         rs.line,                         // Some(1242)
//!     );
//! }
//! ```
//!
//! # Design
//!
//! - **Pure Rust**, `#![deny(unsafe_code)]`.
//! - **Cross-format**: ELF, PE, Mach-O via [`goblin`](https://docs.rs/goblin).
//! - **Zero-copy** where possible — borrows from the input byte slice.
//! - **Forensic-oriented**: prioritises attribution-grade artifacts (build-host
//!   paths, package refs, exception locations) over pretty-printing.
//!
//! The format-level research backing every probe and struct layout is
//! documented in `RESEARCH.md` at the crate root.

#![deny(missing_docs, unsafe_code)]

pub mod container;
pub mod demangle;
pub mod detect;
pub mod error;
pub mod inits;
pub mod metadata;
pub mod modules;
pub mod paths;
pub mod raises;
pub mod rtti;
pub mod shims;
pub mod sites;
pub mod stacktrace;
pub mod strings;

mod binary;
mod util;

pub use binary::NimBinary;
pub use container::{Arch, Container, Format, Section, SectionKind, Symbol, SymbolKind};
pub use detect::{DetectionMatches, DetectionReport};
pub use error::{Error, Result};
pub use inits::{InitFunction, InitKind};
pub use metadata::GcMode;
pub use modules::{ModuleInfo, ModuleMap, ModuleSymbol};
pub use paths::{NimblePath, PathOs};
pub use raises::ExceptionRef;
pub use rtti::symbols::{RttiSymbol, RttiVersion};
pub use shims::{EntryShim, ShimKind};
pub use sites::RaiseSite;
pub use stacktrace::{FilePath, StackTraceHarvest};
pub use strings::v1::StringLiteralV1;
pub use strings::v2::StringLiteral;
