# Changelog

All notable changes to `nimrod` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-06-17

Type intelligence and API maturity. The headline is a cross-linked **type
graph** that surfaces RTTI data (members, offsets, sizes, layout,
inheritance, enum values, destructors) which 0.2.0 parsed internally but
never exposed on the facade.

### Added

- **`types` module + `NimBinary::types()`** — the full Nim type graph
  recovered from V1 (`TNimType`) and V2 (`TNimTypeV2`) RTTI. Each
  `NimType` merges the RTTI symbol with parsed struct fields and resolves
  raw pointers into cross-references: member field types and parent
  (inheritance) types as `TypeRef`, and destructor / trace / finalizer /
  marker / deepcopy procs as `CodeRef` (demangled function + module). New
  public types: `NimType`, `TypeField`, `EnumValue`, `TypeRef`, `CodeRef`,
  `TypeFlags`, `TypeShape`. Accessors `type_at(va)`, `object_types()`,
  `enum_types()`, and `type_rva()`.
  - V2 **inheritance chain** decoded from the `display` class-token array
    (`depth + 1` tokens, RESEARCH.md §3.2), with V2 parents linked through it.
  - V1 **enum values** (`name`, `ordinal`) recovered from the `TNimNode`
    slots, distinct from struct fields.
  - V2 → V1 **field bridge**: a non-nil `typeInfoV1` backpointer is followed
    to import member names for ARC/ORC objects lacking `nimTypeNames`.
  - Non-file-backed RTTI globals (Mach-O `__DATA,__common`, §3.6) degrade to
    name-only entries (`is_readable() == false`) instead of being dropped.
- **`entrypoints` module + `NimBinary::code_entrypoints()`** — one
  deduplicated, VA-sorted stream of every labelled code address (entry shims,
  module inits, demangled procs, raise-enclosing functions, RTTI destructor /
  trace procs), tagged by `EntrypointKind`.
- **`NimBinary::nim_version()`** → `NimVersionHint` (`Nim1xRefc` / `Nim2xArc`
  / `Nim2xOrc` / `Unknown`), splitting ARC vs ORC by the presence of the ORC
  cycle collector (`collectCycles`). Heuristic; see rustdoc for limits
  (stripped ORC builds report as ARC).
- **Ergonomics**: `Format::is_elf()/is_pe()/is_macho()`; `Arch::bits()` and
  `Arch::is_64bit()`; `NimBinary::bitness()/is_64bit()`;
  `DetectionMatches::bits()/from_bits()/from_bits_truncate()`; `as_str()` on
  every public discriminator enum (`Format`, `Arch`, `GcMode`, `ShimKind`,
  `PathOs`, `NimKind`, `RttiVersion`, plus the new `TypeShape`,
  `EntrypointKind`, `NimVersionHint`).
- Compile-time `Send + Sync` guarantee on `NimBinary`, plus a documented
  **robustness contract** (never panics, empty on missing, skip-per-record)
  and address-space contract in the crate docs.

### Changed

- `examples/dump.rs` now prints the full type graph (members, offsets, enum
  values, inheritance, resolved destructors), the code-entrypoint kind
  histogram, and the Nim version hint.

## [0.2.0] — 2026-05-04

Public-API hardening, RVA helpers, and scan caching. **Breaking
release** under [Cargo SemVer for 0.x][cargo-0x] — every breaking
change in a `0.x.y` crate is a `0.x` minor bump, so the scan-accessor
return-type change and the dropped lifetime parameters on three
structs make this `0.2.0`.

[cargo-0x]: https://doc.rust-lang.org/cargo/reference/semver.html

### Added

- `addr` module with `nimrod::va_to_i64(u64) -> Option<i64>` for
  consumers persisting VAs into a signed 64-bit column. Returns `None`
  when the VA exceeds `i64::MAX` (TODO §11.6).
- `Display` impls on every public discriminator enum — `Format`, `Arch`,
  `GcMode`, `ShimKind`, `InitKind`, `RttiVersion`, `PathOs`. Strings
  match the existing `Debug` output exactly so consumers persisting
  `format!("{:?}", …)` don't need a schema migration. The `Display`
  output is now part of the crate's stable API; future changes are
  breaking (TODO §11.1).
- `Container::image_base()` and `Container::va_to_rva(va)` —
  per-format image-base recovery (PE `image_base`, ELF lowest `PT_LOAD`
  `p_vaddr`, Mach-O lowest segment `vmaddr`) plus checked VA→RVA
  translation (TODO §11.2).
- `NimBinary::image_base`, `shim_rva`, `init_rva`, `raise_rva`,
  `rtti_rva` — first-class RVA accessors so consumers stop paying the
  `va.saturating_sub(image_base)` tax (TODO §11.2).
- "Address space" rustdoc section on `NimBinary`, `Container`,
  `EntryShim`, `InitFunction`, `RaiseSite`, `RttiSymbol`,
  `ModuleSymbol`, `StringLiteral`, `StringLiteralV1` documenting that
  every address field is a VA, not a file offset (TODO §11.3).
- Rustdoc on `ModuleInfo::symbol_count` confirming `usize` is always
  representable in `u64` on every supported target (TODO §11.4).
- `tests/display_stability.rs` — snapshot test asserting Display output
  matches Debug for every variant of every public enum.

### Changed

- **All scan accessors on `NimBinary` are now lazily cached.** Each of
  `entry_shims`, `init_functions`, `rtti_symbols`, `string_literals_v2`,
  `string_literals_v1`, `stack_trace`, `nimble_paths`,
  `exception_types`, `raise_sites`, `module_map` runs at most once per
  `NimBinary` instance and returns a borrowed slice (`&[T]`) or
  reference (`&T`) on subsequent calls in O(1). Caching uses
  `std::sync::OnceLock` and is thread-safe (TODO §11.5).
- **Breaking.** Scan accessors that previously returned `Vec<T>` now
  return `&[T]`; `module_map` and `stack_trace` return `&T` instead
  of an owned value. Callers that bound by value should clone
  (`.to_vec()`) or take by reference.
- **Breaking.** `EntryShim<'a>`, `InitFunction<'a>`, and
  `RttiSymbol<'a>` lost their lifetime parameter. `symbol_name` and
  `RttiSymbol::type_fragment` are now `String` / `Option<String>`
  instead of `&'a str` / `Option<&'a str>`. This was required to
  make caching tractable inside `NimBinary` (otherwise the cached
  values would be self-referential through the embedded
  `Container`). Cost is a handful of short-string allocations per
  binary; the caching gain dominates.
- `shims::detect_prefix` signature loosened from
  `<'a>(&'a [EntryShim<'a>]) -> Option<&'a str>` to
  `(&[EntryShim]) -> Option<&str>` to match the new owned types.

### Fixed

- **Lint policy uniformity (TODO §11.0).** Cleared 232 `cargo clippy`
  violations introduced when the panic-prevention lint set
  (`unwrap_used`, `expect_used`, `panic`, `arithmetic_side_effects`,
  `indexing_slicing`) was added to `Cargo.toml`. Every site is now
  bounds-checked or uses `wrapping_*` / `checked_*` / `saturating_*`
  arithmetic, with the choice driven by whether overflow is genuinely
  impossible at the call site or could be triggered by adversarial
  input. No behavioral changes — the parser was already correct, just
  not provably panic-free under the new lints.

## [0.1.0] — initial release

- ELF, PE, Mach-O container abstraction.
- Detection probes covering entry shims, fatal strings, NTIv2 symbols,
  STT_FILE `.nim` suffix, danger-mode signal/exception strings.
- Demangler for Nim identifiers, mangled symbols, and `@m`/`@s`/`@h`
  module-path tokens.
- Entry shims, init functions, GC mode, `--nimMainPrefix` detection.
- V1 + V2 string literal scanners.
- V1 + V2 RTTI recovery.
- Stack-trace harvesting; `.nimble/pkgs` attribution.
- Phase 1 + phase 2 raise-site recovery (cstring exception types and
  full `(type, proc, file, line)` tuples on x86_64 / AArch64).
- Cross-referenced module map.
