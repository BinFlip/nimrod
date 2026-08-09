# nimrod

A pure-Rust parser and forensic-artifact extractor for
[Nim](https://nim-lang.org/)-compiled native binaries. Built for **malware
analysis** and **reverse engineering**.

Nim compiles to C/C++/ObjC and then to a standard **ELF, PE, or Mach-O**
binary — there is no Nim-specific container. This crate recovers the runtime
artifacts that the Nim compiler leaves behind: entry shims, module init
functions, RTTI tables, string literals, stack-trace metadata, build-host
attribution paths, and exception raise sites.

## What it extracts

| Artifact | Description |
|----------|-------------|
| **Detection** | 11 independent fingerprint probes — reliable even on stripped `-d:danger` builds |
| **GC mode / version** | `refc` vs `arc/orc`, plus a best-effort `Nim1xRefc` / `Nim2xArc` / `Nim2xOrc` hint |
| **Entry shims** | `NimMain`, `PreMain`, `NimMainModule`, etc. with addresses |
| **Init functions** | `*Init000` / `*DatInit000` with decoded build-host module paths |
| **Type graph** | Cross-linked types: members, offsets, sizes, alignment, inheritance, enum values, resolved destructors |
| **Code entrypoints** | One VA-tagged stream of shims, inits, procs, raise-enclosing fns, and RTTI procs for disassembler labelling |
| **Module map** | Every Nim module compiled into the binary, with per-function name, address, and size (ELF) |
| **Symbol demangling** | Reverses Nim's `<ident>__<module>_u<id>` mangling back to identifiers |
| **RTTI** | `TNimTypeV2` fields (size, align, depth, destructor) and `TNimType` with field-name recovery |
| **String literals** | V2 (`NIM_STRLIT_FLAG`) and V1 (`NimStringDesc`) scans |
| **Stack traces** | Proc names and `.nim` file paths — absolute paths leak the build host |
| **Nimble paths** | `.nimble/pkgs` leaks parsed into package name, version, hash, and username |
| **Exception types** | `*Error` / `*Defect` cstrings found in rodata |
| **Raise sites** | Full (type, proc, file, line) tuples recovered via x86_64/AArch64 instruction analysis |

## Quick start

```rust
use nimrod::NimBinary;

let data = std::fs::read("sample.exe")?;
let bin = NimBinary::from_bytes(&data)?;

if !bin.is_nim() {
    println!("Not a Nim binary");
    return Ok(());
}

println!("Format: {:?}, GC: {:?}", bin.format(), bin.gc_mode());
```

## Type graph

`bin.types()` recovers every Nim type from RTTI (V1 `TNimType` and V2
`TNimTypeV2`) into one cross-linked graph: size, alignment, inheritance
depth, member fields with offsets and resolved field types, enum values, and
destructor procs resolved to function symbols.

```rust
for t in bin.types() {
    let name = t.name.as_deref().or(t.type_fragment.as_deref()).unwrap_or("?");
    println!("{} {} (size={}, align={})", t.version, name, t.size, t.align);

    if let Some(parent) = &t.parent {
        println!("  inherits: {}", parent.name.as_deref().unwrap_or("?"));
    }
    for f in &t.fields {
        let fty = f.type_ref.as_ref().and_then(|r| r.name.as_deref()).unwrap_or("?");
        println!("  +{:<4} {}: {}", f.offset, f.name, fty);
    }
    for e in &t.enum_values {
        println!("  = {} ({})", e.name, e.ordinal);
    }
    if let Some(d) = &t.destructor {
        println!("  =destroy: {}", d.function.as_deref().unwrap_or("?"));
    }
}
```

V2 (ARC/ORC) object layouts also expose the inheritance chain via the
`display` class-token array. On Mach-O, legacy V1 globals are stored in
`__DATA,__common` with no file backing, so they degrade gracefully to
name-only entries (`t.is_readable() == false`) carrying the type-name
fragment — never a panic, never a dropped type.

## Code entrypoints

`bin.code_entrypoints()` collapses every confidently-labelled code address —
entry shims, module inits, demangled procs, raise-enclosing functions, and
RTTI destructor / trace procs — into one deduplicated, VA-sorted stream so a
disassembler front-end can label a whole binary from a single call:

```rust
for ep in bin.code_entrypoints() {
    println!("{:#x}  {}  {}", ep.va, ep.kind, ep.name);
}
```

## Module map

The module map cross-references init functions, demangled symbols, and
stack-trace file paths into a per-module view. Each module lists every
function with its demangled name, virtual address, and size (ELF):

```rust
let mmap = bin.module_map();
for (name, info) in &mmap.modules {
    println!("{name}: {} functions", info.symbol_count());
    if let Some(ref path) = info.init_path {
        println!("  source: {path}");
    }
    for sym in &info.symbols {
        println!("  {:#x} {} ({} bytes)", sym.address, sym.name, sym.size);
    }
}
```

```text
cgen: 650 functions
  source: cgen.nim
  0x7b6100 cProcParams (439 bytes)
  0x7b62c0 genProcPrototype (312 bytes)
  ...
system: 224 functions
  source: system.nim
  0x405e70 rawAlloc (1284 bytes)
  0x406360 collectCyclesBacon (820 bytes)
  ...
```

This gives downstream tools (Binary Ninja, Ghidra, IDA) the function
boundaries they need for disassembly and analysis.

## Raise-site recovery

Phase 2 raise-site recovery analyses x86_64 and AArch64 instructions around
calls to `raiseExceptionEx` to extract the full exception tuple:

```rust
for rs in &bin.raise_sites() {
    println!(
        "{} in {} at {}:{} [fn: {}]",
        rs.exception_type.as_deref().unwrap_or("?"),
        rs.proc_name.as_deref().unwrap_or("?"),
        rs.file.as_deref().unwrap_or("?"),
        rs.line.map(|l| l.to_string()).unwrap_or("?".into()),
        rs.enclosing_function.as_deref().unwrap_or("?"),
    );
}
```

```text
ValueError in parseHexInt at strutils.nim:1242  [fn: nsuParseHexInt]
IndexDefect in delete at system.nim:2196        [fn: delete__closureiters_u3150]
MyError in inner at exceptions.nim:7            [fn: outer__exceptions_u129]
```

## Build-host attribution

Debug and standard-release Nim builds leak build-host paths via stack-trace
metadata and nimble package paths:

```rust
// Absolute .nim file paths (build-host leak)
let harvest = bin.stack_trace();
for f in &harvest.file_paths {
    if f.is_absolute {
        println!("leaked: {}", f.path);
    }
}

// Nimble package paths (username + package intel)
for p in &bin.nimble_paths() {
    println!("pkg: {}@{}", 
        p.pkg_name.as_deref().unwrap_or("?"),
        p.pkg_version.as_deref().unwrap_or("?"));
    if let Some(ref user) = p.user_hint {
        println!("  user: {user}");
    }
}
```

```text
leaked: /opt/homebrew/Cellar/nim/2.2.8/nim/lib/system.nim
pkg: nimSHA2@0.1.1
  user: alex
```

## Dump example

The included `dump` example prints every recoverable artifact:

```sh
cargo run --example dump -- sample.exe
```

## Supported formats

- **ELF** (Linux, BSD) — full support including function sizes from `st_size`
- **PE** (Windows) — COFF symbol table + exports; MinGW and MSVC linked
- **Mach-O** (macOS) — single-arch and universal/fat binaries

## Dependencies

Deliberately minimal:

- [`goblin`](https://docs.rs/goblin) — ELF/PE/Mach-O parsing
- [`memchr`](https://docs.rs/memchr) — fast byte-level rodata scanning

## License

Copyright 2026 ATRAPS LLC. Licensed under the Apache License,
Version 2.0. See `LICENSE` and `NOTICE`.
