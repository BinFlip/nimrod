//! High-level [`NimBinary`] facade.
//!
//! Owns a parsed [`Container`] plus a cached [`DetectionReport`]. Later
//! milestones (M2+) add lazy accessors for symbols, RTTI, strings,
//! stack-trace metadata, and attribution artifacts; M1 exposes only the
//! container view and the detection verdict.

use crate::{
    container::{Arch, Container, Format},
    detect::{DetectionMatches, DetectionReport},
    error::Result,
    inits::{self, InitFunction},
    metadata::{self, GcMode},
    modules::{self, ModuleMap},
    paths::{self, NimblePath},
    raises::{self, ExceptionRef},
    rtti::symbols::{self as rtti_symbols, RttiSymbol},
    shims::{self, EntryShim},
    sites::{self, RaiseSite},
    stacktrace::{self, StackTraceHarvest},
    strings::{v1 as strings_v1, v2 as strings_v2},
};

/// Parsed view of a Nim-compiled native binary.
///
/// Construct via [`NimBinary::from_bytes`]. The type borrows from the input
/// byte slice — no copies of the original bytes are made.
pub struct NimBinary<'a> {
    container: Container<'a>,
    detection: DetectionReport,
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
    pub fn entry_shims(&'a self) -> Vec<EntryShim<'a>> {
        shims::scan(&self.container)
    }

    /// Scans for Nim module init functions (`*Init000`, `*DatInit000`).
    pub fn init_functions(&'a self) -> Vec<InitFunction<'a>> {
        inits::scan(&self.container)
    }

    /// Infers the GC / memory-management mode from RTTI symbol presence.
    pub fn gc_mode(&self) -> GcMode {
        metadata::gc_mode(self.detection.matches)
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
    pub fn rtti_symbols(&'a self) -> Vec<RttiSymbol<'a>> {
        rtti_symbols::scan(&self.container)
    }

    /// Scans rodata for V2 string literals (ARC/ORC builds).
    pub fn string_literals_v2(&self) -> Vec<strings_v2::StringLiteral> {
        strings_v2::scan(&self.container)
    }

    /// Scans rodata for V1 string literals (refc builds, best-effort).
    pub fn string_literals_v1(&self) -> Vec<strings_v1::StringLiteralV1> {
        strings_v1::scan(&self.container)
    }

    /// Harvests stack-trace file paths and proc names from rodata.
    pub fn stack_trace(&self) -> StackTraceHarvest {
        stacktrace::harvest(&self.container)
    }

    /// Scans for `.nimble/pkgs` path leaks revealing build-host
    /// attribution.
    pub fn nimble_paths(&self) -> Vec<NimblePath> {
        paths::scan(&self.container)
    }

    /// Scans for exception type name cstrings (phase 1 raise-site
    /// recovery).
    pub fn exception_types(&self) -> Vec<ExceptionRef> {
        raises::scan(&self.container)
    }

    /// Recovers full raise-site tuples (type, proc, file, line) by
    /// analysing call sites to `raiseExceptionEx` (phase 2).
    ///
    /// Requires x86_64 or AArch64 architecture. Returns an empty vec
    /// on unsupported architectures or if `raiseExceptionEx` is not
    /// found in the symbol table.
    pub fn raise_sites(&self) -> Vec<RaiseSite> {
        sites::scan(&self.container)
    }

    /// Builds a cross-referenced module map from init functions,
    /// demangled symbols, and stack-trace file paths.
    pub fn module_map(&self) -> ModuleMap {
        modules::build(&self.container)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_rejects_garbage() {
        let result = NimBinary::from_bytes(b"not an elf or pe or macho");
        assert!(result.is_err());
    }
}
