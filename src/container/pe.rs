//! PE backend for the container abstraction.
//!
//! Parses sections and the COFF symbol table (when present — MinGW-linked
//! binaries typically retain it). Modern MSVC PEs usually strip the COFF
//! symbol table in favour of PDBs, but exports still surface through
//! goblin's `PE::exports`.

use std::borrow::Cow;

use goblin::pe::{
    PE,
    header::{
        COFF_MACHINE_ARM, COFF_MACHINE_ARM64, COFF_MACHINE_RISCV32, COFF_MACHINE_RISCV64,
        COFF_MACHINE_X86, COFF_MACHINE_X86_64,
    },
    section_table::{
        IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA,
        IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, SectionTable,
    },
    symbol::{IMAGE_SYM_CLASS_FILE, IMAGE_SYM_DTYPE_FUNCTION, SymbolTable},
};

use crate::{
    container::{Arch, Container, Format, Section, SectionKind, Symbol, SymbolKind, assemble},
    error::Result,
};

pub(crate) fn build<'a>(bytes: &'a [u8], pe: PE<'a>) -> Result<Container<'a>> {
    let arch = map_arch(pe.header.coff_header.machine);
    let image_base = pe.image_base;
    let sections = collect_sections(bytes, &pe);
    let symbols = collect_symbols(bytes, &pe)?;
    Ok(assemble(
        bytes,
        Format::Pe,
        arch,
        image_base,
        sections,
        symbols,
    ))
}

fn map_arch(machine: u16) -> Arch {
    match machine {
        COFF_MACHINE_X86 => Arch::I386,
        COFF_MACHINE_X86_64 => Arch::Amd64,
        COFF_MACHINE_ARM => Arch::Arm,
        COFF_MACHINE_ARM64 => Arch::Aarch64,
        COFF_MACHINE_RISCV32 => Arch::Riscv32,
        COFF_MACHINE_RISCV64 => Arch::Riscv64,
        _ => Arch::Other,
    }
}

fn collect_sections<'a>(bytes: &'a [u8], pe: &PE<'a>) -> Vec<Section<'a>> {
    let mut out = Vec::with_capacity(pe.sections.len());
    for s in &pe.sections {
        let name = section_name(s);
        let vm_addr = pe.image_base.wrapping_add(u64::from(s.virtual_address));
        let vm_size = u64::from(s.virtual_size);

        let file_offset = s.pointer_to_raw_data as usize;
        let file_size = s.size_of_raw_data as usize;
        let data = bytes
            .get(file_offset..file_offset.saturating_add(file_size))
            .unwrap_or(&[]);

        let kind = classify(&name, s.characteristics);
        out.push(Section {
            name,
            vm_addr,
            vm_size,
            data,
            kind,
        });
    }
    out
}

fn section_name(s: &SectionTable) -> String {
    if let Some(ref real) = s.real_name {
        return real.clone();
    }
    // Inline name is 8 bytes, NUL-padded.
    let end = s.name.iter().position(|&b| b == 0).unwrap_or(s.name.len());
    let bytes = s.name.get(..end).unwrap_or(&[]);
    String::from_utf8_lossy(bytes).into_owned()
}

fn classify(name: &str, characteristics: u32) -> SectionKind {
    let exec = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
    let write = characteristics & IMAGE_SCN_MEM_WRITE != 0;
    let code = characteristics & IMAGE_SCN_CNT_CODE != 0;
    let init_data = characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0;
    let uninit_data = characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0;

    if uninit_data {
        return SectionKind::Bss;
    }
    if code || exec {
        return SectionKind::Text;
    }
    if init_data && !write {
        return SectionKind::RoData;
    }
    if init_data && write {
        return SectionKind::Data;
    }

    match name {
        ".rdata" | ".rodata" => SectionKind::RoData,
        ".data" => SectionKind::Data,
        ".text" => SectionKind::Text,
        ".bss" => SectionKind::Bss,
        _ => SectionKind::Other,
    }
}

fn collect_symbols<'a>(bytes: &'a [u8], pe: &PE<'a>) -> Result<Vec<Symbol<'a>>> {
    let mut out = Vec::new();

    // Exported symbols surface even when the COFF symbol table is stripped.
    for exp in &pe.exports {
        if let Some(name) = exp.name {
            out.push(Symbol {
                name: Cow::Borrowed(name),
                vm_addr: pe.image_base.wrapping_add(exp.rva as u64),
                size: 0, // PE exports don't carry size
                kind: SymbolKind::Function,
            });
        }
    }

    // COFF symbol table (typically present on MinGW-linked executables).
    let sym_ptr = pe.header.coff_header.pointer_to_symbol_table as usize;
    let nsyms = pe.header.coff_header.number_of_symbol_table as usize;
    if sym_ptr == 0 || nsyms == 0 {
        return Ok(out);
    }

    // Goblin's `CoffHeader::strings` handles the 4-byte length prefix
    // correctly (advancing past it and subtracting 4 from the declared
    // length). Rolling the parse by hand leaves a classic off-by-4 that
    // makes every strtab-referenced symbol name come out as the final
    // 3 characters of the previous symbol.
    let strtab = match pe.header.coff_header.strings(bytes) {
        Ok(Some(s)) => s,
        _ => goblin::strtab::Strtab::new(&[], 0),
    };

    let symtab = match SymbolTable::parse(bytes, sym_ptr, nsyms) {
        Ok(t) => t,
        Err(_) => return Ok(out),
    };

    for (index, _inline, sym) in symtab.iter() {
        // Resolve the symbol name. Long names live in the COFF string
        // table (borrow from `bytes` via strtab), short names are inline
        // in the symbol record and must be copied out.
        //
        // `.file` records are a special case: the short inline name is
        // literally ".file" and the actual source filename is stored in
        // one or more auxiliary symbol records that follow. Goblin's
        // `aux_file` reads them for us.
        let is_file_record =
            sym.storage_class == IMAGE_SYM_CLASS_FILE && sym.number_of_aux_symbols > 0;
        let name: Cow<'a, str> = if is_file_record {
            // Aux records live at `(main_index + 1) * COFF_SYMBOL_SIZE`,
            // and goblin's helper takes the aux record's own index.
            match symtab.aux_file(index.saturating_add(1), sym.number_of_aux_symbols as usize) {
                Some(s) if !s.is_empty() => Cow::Borrowed(s),
                _ => continue,
            }
        } else if let Some(offset) = sym.name_offset() {
            match strtab.get_at(offset as usize) {
                Some(s) if !s.is_empty() => Cow::Borrowed(s),
                _ => continue,
            }
        } else {
            let end = sym.name.iter().position(|&b| b == 0).unwrap_or(8);
            if end == 0 {
                continue;
            }
            Cow::Owned(String::from_utf8_lossy(sym.name.get(..end).unwrap_or(&[])).into_owned())
        };
        let kind = classify_symbol(sym.storage_class, sym.typ);
        let section_va = if sym.section_number > 0 {
            pe.sections
                .get((sym.section_number as usize).saturating_sub(1))
                .map(|s| pe.image_base.wrapping_add(u64::from(s.virtual_address)))
                .unwrap_or(0)
        } else {
            0
        };
        out.push(Symbol {
            name,
            vm_addr: section_va.wrapping_add(u64::from(sym.value)),
            size: 0, // COFF symbols don't carry size
            kind,
        });
    }

    Ok(out)
}

fn classify_symbol(storage_class: u8, typ: u16) -> SymbolKind {
    if storage_class == IMAGE_SYM_CLASS_FILE {
        return SymbolKind::File;
    }
    // High nibble of typ describes the "derived type"; DTYPE_FUNCTION marks
    // a function.
    if (typ >> 4) == IMAGE_SYM_DTYPE_FUNCTION {
        SymbolKind::Function
    } else {
        SymbolKind::Other
    }
}
