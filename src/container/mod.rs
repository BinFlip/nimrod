//! Container-format abstraction over ELF, PE, and Mach-O.
//!
//! The rest of the crate accesses host-binary structure (sections, symbols,
//! rodata slices) through this layer so that the Nim-specific probes in
//! [`crate::detect`] and later milestones do not care which native format
//! they are running against.
//!
//! [`Container::parse`] dispatches on the magic bytes and returns a
//! container whose `sections` and `symbols` have been collected eagerly into
//! vectors borrowing from the input slice. The per-format backends (ELF,
//! PE, Mach-O) are private to this module — only the unified types below
//! are part of the crate API.

mod elf;
mod macho;
mod pe;

use crate::error::{Error, Result};
use core::fmt;

/// Native container format of the underlying binary.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's
/// stable API: downstream consumers persist it as a schema
/// discriminator. Changes to these strings are SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// Executable and Linkable Format — Linux, BSD, and other Unix hosts.
    Elf,
    /// Portable Executable — Windows.
    Pe,
    /// Mach object format — macOS, iOS, and other Apple platforms.
    MachO,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Elf => "Elf",
            Self::Pe => "Pe",
            Self::MachO => "MachO",
        })
    }
}

/// CPU architecture reported by the container header.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's
/// stable API. Changes are SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    /// 32-bit x86.
    I386,
    /// 64-bit x86.
    Amd64,
    /// 32-bit ARM.
    Arm,
    /// 64-bit ARM (AArch64 / ARM64).
    Aarch64,
    /// 32-bit RISC-V.
    Riscv32,
    /// 64-bit RISC-V.
    Riscv64,
    /// 32-bit PowerPC.
    PowerPc,
    /// 64-bit PowerPC.
    PowerPc64,
    /// Any architecture we did not map explicitly.
    Other,
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::I386 => "I386",
            Self::Amd64 => "Amd64",
            Self::Arm => "Arm",
            Self::Aarch64 => "Aarch64",
            Self::Riscv32 => "Riscv32",
            Self::Riscv64 => "Riscv64",
            Self::PowerPc => "PowerPc",
            Self::PowerPc64 => "PowerPc64",
            Self::Other => "Other",
        })
    }
}

/// Coarse classification of a section's role.
///
/// The Nim probes only need to distinguish "code" from "read-only data"
/// from "everything else" — we deliberately do not expose every
/// format-specific section type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionKind {
    /// Machine code (ELF `.text`, PE `.text`, Mach-O `__TEXT,__text`).
    Text,
    /// Read-only data (ELF `.rodata`, PE `.rdata`, Mach-O `__TEXT,__cstring`,
    /// `__TEXT,__const`, `__DATA_CONST,__const`).
    RoData,
    /// Initialised mutable data.
    Data,
    /// Uninitialised / BSS-like (no file bytes).
    Bss,
    /// Anything else — debug info, relocations, unwind tables, etc.
    Other,
}

/// One section/segment of the parsed binary.
///
/// The `data` slice borrows from the input bytes; for BSS-like sections
/// with no file backing, the slice is empty and `SectionKind::Bss` is set.
#[derive(Debug, Clone)]
pub struct Section<'a> {
    /// Section name as it appears in the container (without normalisation).
    ///
    /// ELF/PE names are a single token (`.text`, `.rdata`). Mach-O section
    /// names are qualified with their segment as `__SEGMENT,__sect`.
    pub name: String,
    /// Virtual address this section is mapped at. Zero for sections with no
    /// VA (e.g. ELF `.shstrtab`).
    pub vm_addr: u64,
    /// Section size in bytes as declared by the container header.
    pub vm_size: u64,
    /// File bytes backing this section. Empty for BSS-like sections.
    pub data: &'a [u8],
    /// Coarse classification used by higher-level scans.
    pub kind: SectionKind,
}

/// Coarse classification of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// Executable code.
    Function,
    /// Data / global variable.
    Object,
    /// Source file marker (ELF `STT_FILE`). Used for Nim `.nim` file
    /// suffix detection.
    File,
    /// Section-level symbol.
    Section,
    /// Unclassified / unknown.
    Other,
}

/// Normalised symbol extracted from the container.
///
/// Names are demangled at the container level only insofar as the format
/// demands it — specifically, Mach-O names have their leading underscore
/// stripped so that a `NimMain` probe works uniformly across ELF/PE/Mach-O.
#[derive(Debug, Clone)]
pub struct Symbol<'a> {
    /// Normalised symbol name. Borrows from the input bytes where possible,
    /// owns the string when normalisation required allocation (e.g. ELF
    /// symbols in the `.strtab`, PE long names via the COFF string table,
    /// Mach-O names with the leading underscore stripped).
    pub name: std::borrow::Cow<'a, str>,
    /// Virtual address of the symbol, when known. Zero for undefined
    /// symbols.
    pub vm_addr: u64,
    /// Size in bytes of the symbol (from ELF `st_size`). Zero when the
    /// format doesn't provide size information (Mach-O, stripped PE).
    pub size: u64,
    /// Classification of the symbol.
    pub kind: SymbolKind,
}

/// Parsed container-format view of a native binary.
///
/// # Address space
///
/// All address fields exposed by `Container` and the higher-level scans
/// (`Section::vm_addr`, `Symbol::vm_addr`, `EntryShim::address`,
/// `RaiseSite::call_addr`, …) are **virtual addresses** in the input
/// image's load space, not file offsets. To translate a VA into a
/// disassembler-style RVA, subtract [`Container::image_base`] (or use
/// the `*_rva` helpers on [`crate::NimBinary`]).
pub struct Container<'a> {
    bytes: &'a [u8],
    format: Format,
    arch: Arch,
    image_base: u64,
    sections: Vec<Section<'a>>,
    symbols: Vec<Symbol<'a>>,
}

impl<'a> Container<'a> {
    /// Parses `bytes` as an ELF, PE, or Mach-O binary.
    ///
    /// Returns [`Error::UnsupportedFormat`] if the input is neither.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let obj = goblin::Object::parse(bytes)?;
        match obj {
            goblin::Object::Elf(elf) => elf::build(bytes, elf),
            goblin::Object::PE(pe) => pe::build(bytes, pe),
            goblin::Object::Mach(mach) => macho::build(bytes, mach),
            _ => Err(Error::UnsupportedFormat),
        }
    }

    /// Returns the underlying input byte slice.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the detected container format.
    pub fn format(&self) -> Format {
        self.format
    }

    /// Returns the detected CPU architecture.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// Returns the image base address: the virtual address that the
    /// container's lowest loadable region maps to.
    ///
    /// - **PE**: `OptionalHeader.windows_fields.image_base` (the canonical
    ///   `ImageBase`).
    /// - **ELF**: lowest `PT_LOAD` `p_vaddr` (zero for typical PIE / shared
    ///   objects, non-zero for fixed-load executables).
    /// - **Mach-O**: lowest segment `vmaddr` (often the `__TEXT` segment).
    ///
    /// Subtracting this from any VA produced by nimrod yields the RVA used
    /// by Binary Ninja, Ghidra, IDA, and similar disassemblers.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Translates a virtual address into an image-relative address (RVA).
    ///
    /// Returns `None` when `va < image_base()` (e.g. a sentinel zero VA on
    /// an undefined symbol, or a VA from a different image).
    pub fn va_to_rva(&self, va: u64) -> Option<u64> {
        va.checked_sub(self.image_base)
    }

    /// Returns every parsed section.
    pub fn sections(&self) -> &[Section<'a>] {
        &self.sections
    }

    /// Returns every parsed symbol.
    pub fn symbols(&self) -> &[Symbol<'a>] {
        &self.symbols
    }

    /// Iterates only sections classified as read-only data.
    pub fn rodata_sections(&self) -> impl Iterator<Item = &Section<'a>> + '_ {
        self.sections
            .iter()
            .filter(|s| s.kind == SectionKind::RoData)
    }

    /// Finds the function symbol that contains the given virtual address.
    ///
    /// For ELF binaries (which have `st_size`), this checks
    /// `sym.vm_addr <= va < sym.vm_addr + sym.size`. For formats without
    /// size info, it finds the nearest preceding function symbol.
    pub fn function_at_va(&self, va: u64) -> Option<&Symbol<'a>> {
        // First try exact range match (ELF with sizes).
        if let Some(sym) = self.symbols.iter().find(|s| {
            s.kind == SymbolKind::Function
                && s.size > 0
                && va >= s.vm_addr
                && s.vm_addr.checked_add(s.size).is_some_and(|end| va < end)
        }) {
            return Some(sym);
        }

        // Fallback: nearest preceding function symbol.
        self.symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Function && s.vm_addr <= va && s.vm_addr > 0)
            .max_by_key(|s| s.vm_addr)
    }
}

impl std::fmt::Debug for Container<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Container")
            .field("format", &self.format)
            .field("arch", &self.arch)
            .field("sections", &self.sections.len())
            .field("symbols", &self.symbols.len())
            .finish()
    }
}

/// Internal constructor used by the per-format backends.
pub(crate) fn assemble<'a>(
    bytes: &'a [u8],
    format: Format,
    arch: Arch,
    image_base: u64,
    sections: Vec<Section<'a>>,
    symbols: Vec<Symbol<'a>>,
) -> Container<'a> {
    Container {
        bytes,
        format,
        arch,
        image_base,
        sections,
        symbols,
    }
}
