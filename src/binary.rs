//! High-level [`NimBinary`] facade.
//!
//! Owns a parsed [`Container`], a cached [`DetectionReport`], and a lazy
//! cache of every scan accessor. Each scan runs at most once per
//! `NimBinary` instance — repeated calls return the same `&[T]` slice.

use std::sync::OnceLock;

use crate::{
    container::{Arch, Container, Format},
    detect::{DetectionMatches, DetectionReport},
    entrypoints::{self, CodeEntrypoint},
    error::Result,
    inits::{self, InitFunction},
    metadata::{self, GcMode, NimVersionHint},
    modules::{self, ModuleMap},
    paths::{self, NimblePath},
    raises::{self, ExceptionRef},
    rtti::symbols::{self as rtti_symbols, RttiSymbol},
    shims::{self, EntryShim},
    sites::{self, RaiseSite},
    stacktrace::{self, StackTraceHarvest},
    strings::{v1 as strings_v1, v2 as strings_v2},
    types::{self, NimType, TypeShape},
};

/// Lazy result cache. Each scan runs at most once per [`NimBinary`].
#[derive(Default)]
struct Cache {
    entry_shims: OnceLock<Vec<EntryShim>>,
    init_functions: OnceLock<Vec<InitFunction>>,
    rtti_symbols: OnceLock<Vec<RttiSymbol>>,
    string_literals_v2: OnceLock<Vec<strings_v2::StringLiteral>>,
    string_literals_v1: OnceLock<Vec<strings_v1::StringLiteralV1>>,
    stack_trace: OnceLock<StackTraceHarvest>,
    nimble_paths: OnceLock<Vec<NimblePath>>,
    exception_types: OnceLock<Vec<ExceptionRef>>,
    raise_sites: OnceLock<Vec<RaiseSite>>,
    module_map: OnceLock<ModuleMap>,
    types: OnceLock<Vec<NimType>>,
    code_entrypoints: OnceLock<Vec<CodeEntrypoint>>,
}

/// Parsed view of a Nim-compiled native binary.
///
/// Construct via [`NimBinary::from_bytes`]. The type borrows from the input
/// byte slice — no copies of the original bytes are made.
///
/// # Caching
///
/// Every scan accessor (`entry_shims`, `init_functions`, `rtti_symbols`,
/// `string_literals_v2`, `string_literals_v1`, `stack_trace`,
/// `nimble_paths`, `exception_types`, `raise_sites`, `module_map`,
/// `types`, `code_entrypoints`) runs at most once. The first call performs the full scan
/// and stores the result; subsequent calls return the same borrowed
/// slice in `O(1)`. Caching is thread-safe (`OnceLock`).
///
/// # Address space
///
/// Every address-bearing field returned by `NimBinary` and its scan
/// methods is a **virtual address** in the input image's load space —
/// not a file offset. Most disassemblers (Binary Ninja, Ghidra, IDA)
/// work in image-relative space; convert with the `*_rva` helpers on
/// this type, with [`Container::va_to_rva`], or with the standalone
/// helper [`crate::va_to_i64`] if you need a signed-integer encoding
/// for persistence.
pub struct NimBinary<'a> {
    container: Container<'a>,
    detection: DetectionReport,
    cache: Cache,
}

impl<'a> NimBinary<'a> {
    /// Parses the given bytes as a Nim-compiled native binary.
    ///
    /// This unconditionally parses the container (ELF, PE, or Mach-O) and
    /// runs the full detection probe set. It does **not** early-exit for
    /// non-Nim binaries — the caller is expected to inspect
    /// [`NimBinary::is_nim`] or [`NimBinary::detection`] and act
    /// accordingly.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let container = Container::parse(bytes)?;
        let detection = DetectionReport::run(&container);
        Ok(Self {
            container,
            detection,
            cache: Cache::default(),
        })
    }

    /// Returns the underlying input byte slice.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.container.bytes()
    }

    /// Returns the detected container format.
    pub fn format(&self) -> Format {
        self.container.format()
    }

    /// Returns the detected CPU architecture.
    pub fn arch(&self) -> Arch {
        self.container.arch()
    }

    /// Returns the pointer width in bits, or `None` for an architecture nimrod
    /// does not map explicitly. See [`Arch::bits`].
    pub fn bitness(&self) -> Option<u8> {
        self.container.arch().bits()
    }

    /// Returns `true` for a known 64-bit target.
    pub fn is_64bit(&self) -> bool {
        self.container.arch().is_64bit()
    }

    /// Returns the parsed container view. Mainly useful for downstream
    /// crates that want to walk sections or symbols directly.
    pub fn container(&self) -> &Container<'a> {
        &self.container
    }

    /// Returns `true` if at least one detection probe matched.
    pub fn is_nim(&self) -> bool {
        self.detection.is_nim
    }

    /// Returns the full detection report.
    pub fn detection(&self) -> &DetectionReport {
        &self.detection
    }

    /// Returns the matched detection flags.
    pub fn detection_matches(&self) -> DetectionMatches {
        self.detection.matches
    }

    /// Scans for Nim entry-point shims (`NimMain`, `PreMain`, etc.).
    ///
    /// Cached: subsequent calls return the same slice in `O(1)`.
    pub fn entry_shims(&self) -> &[EntryShim] {
        self.cache
            .entry_shims
            .get_or_init(|| shims::scan(&self.container))
    }

    /// Scans for Nim module init functions (`*Init000`, `*DatInit000`).
    ///
    /// Cached: subsequent calls return the same slice in `O(1)`.
    pub fn init_functions(&self) -> &[InitFunction] {
        self.cache
            .init_functions
            .get_or_init(|| inits::scan(&self.container))
    }

    /// Infers the GC / memory-management mode from RTTI symbol presence.
    pub fn gc_mode(&self) -> GcMode {
        metadata::gc_mode(self.detection.matches)
    }

    /// Best-effort Nim compiler-family hint (refc / arc / orc).
    ///
    /// Heuristic; see [`metadata::detect_compiler_version`] for the signals and
    /// their limitations (notably stripped ORC builds reported as ARC).
    pub fn nim_version(&self) -> NimVersionHint {
        metadata::detect_compiler_version(&self.container, self.detection.matches)
    }

    /// Detects the `--nimMainPrefix` value, if any.
    ///
    /// Returns `Some("")` for the default (empty) prefix, `Some(prefix)`
    /// for a custom prefix, or `None` if `NimMain` was not found.
    pub fn nim_main_prefix(&self) -> Option<&str> {
        metadata::nim_main_prefix(&self.container)
    }

    /// Enumerates all RTTI globals (`NTIv2_` and `NTI_`) from the symbol
    /// table.
    ///
    /// Cached: subsequent calls return the same slice in `O(1)`.
    pub fn rtti_symbols(&self) -> &[RttiSymbol] {
        self.cache
            .rtti_symbols
            .get_or_init(|| rtti_symbols::scan(&self.container))
    }

    /// Scans rodata for V2 string literals (ARC/ORC builds).
    ///
    /// Cached: subsequent calls return the same slice in `O(1)`.
    pub fn string_literals_v2(&self) -> &[strings_v2::StringLiteral] {
        self.cache
            .string_literals_v2
            .get_or_init(|| strings_v2::scan(&self.container))
    }

    /// Scans rodata for V1 string literals (refc builds, best-effort).
    ///
    /// Cached: subsequent calls return the same slice in `O(1)`.
    pub fn string_literals_v1(&self) -> &[strings_v1::StringLiteralV1] {
        self.cache
            .string_literals_v1
            .get_or_init(|| strings_v1::scan(&self.container))
    }

    /// Harvests stack-trace file paths and proc names from rodata.
    ///
    /// Cached: subsequent calls return the same value in `O(1)`.
    pub fn stack_trace(&self) -> &StackTraceHarvest {
        self.cache
            .stack_trace
            .get_or_init(|| stacktrace::harvest(&self.container))
    }

    /// Scans for `.nimble/pkgs` path leaks revealing build-host
    /// attribution.
    ///
    /// Cached: subsequent calls return the same slice in `O(1)`.
    pub fn nimble_paths(&self) -> &[NimblePath] {
        self.cache
            .nimble_paths
            .get_or_init(|| paths::scan(&self.container))
    }

    /// Scans for exception type name cstrings (phase 1 raise-site
    /// recovery).
    ///
    /// Cached: subsequent calls return the same slice in `O(1)`.
    pub fn exception_types(&self) -> &[ExceptionRef] {
        self.cache
            .exception_types
            .get_or_init(|| raises::scan(&self.container))
    }

    /// Recovers full raise-site tuples (type, proc, file, line) by
    /// analysing call sites to `raiseExceptionEx` (phase 2).
    ///
    /// Requires x86_64 or AArch64 architecture. Returns an empty slice
    /// on unsupported architectures or if `raiseExceptionEx` is not
    /// found in the symbol table.
    ///
    /// Cached: subsequent calls return the same slice in `O(1)`.
    pub fn raise_sites(&self) -> &[RaiseSite] {
        self.cache
            .raise_sites
            .get_or_init(|| sites::scan(&self.container))
    }

    /// Builds a cross-referenced module map from init functions,
    /// demangled symbols, and stack-trace file paths.
    ///
    /// Cached: subsequent calls return the same value in `O(1)`.
    pub fn module_map(&self) -> &ModuleMap {
        self.cache
            .module_map
            .get_or_init(|| modules::build(&self.container))
    }

    /// Recovers the full Nim type graph from RTTI (V1 + V2).
    ///
    /// Each entry merges the RTTI symbol with its parsed struct fields and
    /// resolves the raw pointer fields into cross-references: member field
    /// types, parent (inheritance) types, and destructor / trace / finalizer
    /// functions. See [`crate::types`] for the extraction passes.
    ///
    /// Cached: subsequent calls return the same slice in `O(1)`.
    pub fn types(&self) -> &[NimType] {
        self.cache.types.get_or_init(|| types::build(&self.container))
    }

    /// Returns the type whose RTTI global is located at the virtual address
    /// `va`, if any.
    ///
    /// Runs over the cached [`types`](NimBinary::types) slice; the type count
    /// is small (a handful to low hundreds), so this is a linear scan.
    pub fn type_at(&self, va: u64) -> Option<&NimType> {
        self.types().iter().find(|t| t.address == va)
    }

    /// Iterates the object and tuple types in the type graph.
    pub fn object_types(&self) -> impl Iterator<Item = &NimType> {
        self.types()
            .iter()
            .filter(|t| matches!(t.shape, TypeShape::Object | TypeShape::Tuple))
    }

    /// Iterates the enum types in the type graph.
    pub fn enum_types(&self) -> impl Iterator<Item = &NimType> {
        self.types().iter().filter(|t| t.shape == TypeShape::Enum)
    }

    /// Returns every code address the crate can confidently label, as one
    /// deduplicated, VA-sorted stream tagged by
    /// [`EntrypointKind`](crate::entrypoints::EntrypointKind).
    ///
    /// Aggregates entry shims, init functions, demangled proc symbols,
    /// raise-enclosing functions, and RTTI destructor / trace procs. See
    /// [`crate::entrypoints`] for the dedup priority.
    ///
    /// Cached: subsequent calls return the same slice in `O(1)`.
    pub fn code_entrypoints(&self) -> &[CodeEntrypoint] {
        self.cache
            .code_entrypoints
            .get_or_init(|| entrypoints::build(&self.container))
    }

    /// Returns the image base address. See [`Container::image_base`].
    pub fn image_base(&self) -> u64 {
        self.container.image_base()
    }

    /// Returns an [`EntryShim`]'s address as an RVA (image-relative).
    ///
    /// `None` if the shim's VA is below the image base, which would
    /// indicate a malformed container.
    pub fn shim_rva(&self, shim: &EntryShim) -> Option<u64> {
        self.container.va_to_rva(shim.address)
    }

    /// Returns an [`InitFunction`]'s address as an RVA.
    pub fn init_rva(&self, init: &InitFunction) -> Option<u64> {
        self.container.va_to_rva(init.address)
    }

    /// Returns a [`RaiseSite`]'s call address as an RVA.
    pub fn raise_rva(&self, site: &RaiseSite) -> Option<u64> {
        self.container.va_to_rva(site.call_addr)
    }

    /// Returns an [`RttiSymbol`]'s address as an RVA.
    pub fn rtti_rva(&self, sym: &RttiSymbol) -> Option<u64> {
        self.container.va_to_rva(sym.address)
    }

    /// Returns a [`NimType`]'s RTTI-global address as an RVA.
    pub fn type_rva(&self, ty: &NimType) -> Option<u64> {
        self.container.va_to_rva(ty.address)
    }
}

// Compile-time guarantee that `NimBinary` is `Send + Sync` so consumers may
// share it across threads / hold it across `.await` points. All cached data is
// owned (or borrows the immutable input slice), so this holds; the assertion
// makes it a checked, documented contract rather than an accident.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NimBinary<'static>>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_rejects_garbage() {
        let result = NimBinary::from_bytes(b"not an elf or pe or macho");
        assert!(result.is_err());
    }
}
