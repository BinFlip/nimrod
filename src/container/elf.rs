//! ELF backend for the container abstraction.

use std::borrow::Cow;

use goblin::elf::{
    Elf, Symtab,
    header::{EM_386, EM_AARCH64, EM_ARM, EM_PPC, EM_PPC64, EM_RISCV, EM_X86_64},
    section_header::{SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS, SHT_PROGBITS},
    sym::{STT_FILE, STT_FUNC, STT_OBJECT, STT_SECTION, st_type},
};

use crate::{
    container::{Arch, Container, Format, Section, SectionKind, Symbol, SymbolKind, assemble},
    error::Result,
};

pub(crate) fn build<'a>(bytes: &'a [u8], elf: Elf<'a>) -> Result<Container<'a>> {
    let arch = map_arch(elf.header.e_machine);
    let sections = collect_sections(bytes, &elf);
    let symbols = collect_symbols(&elf, &elf.syms, &elf.strtab)
        .into_iter()
        .chain(collect_symbols(&elf, &elf.dynsyms, &elf.dynstrtab))
        .collect();
    Ok(assemble(bytes, Format::Elf, arch, sections, symbols))
}

fn map_arch(e_machine: u16) -> Arch {
    match e_machine {
        EM_386 => Arch::I386,
        EM_X86_64 => Arch::Amd64,
        EM_ARM => Arch::Arm,
        EM_AARCH64 => Arch::Aarch64,
        EM_PPC => Arch::PowerPc,
        EM_PPC64 => Arch::PowerPc64,
        EM_RISCV => Arch::Riscv64, // distinguishing 32/64 needs class field; good enough here
        _ => Arch::Other,
    }
}

fn collect_sections<'a>(bytes: &'a [u8], elf: &Elf<'a>) -> Vec<Section<'a>> {
    let mut out = Vec::with_capacity(elf.section_headers.len());
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let vm_addr = sh.sh_addr;
        let vm_size = sh.sh_size;

        let file_offset = sh.sh_offset as usize;
        let file_size = sh.sh_size as usize;

        let data: &'a [u8] = if sh.sh_type == SHT_NOBITS {
            &[]
        } else {
            bytes
                .get(file_offset..file_offset.saturating_add(file_size))
                .unwrap_or(&[])
        };

        let kind = classify(&name, sh.sh_type, sh.sh_flags);

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

fn classify(name: &str, sh_type: u32, sh_flags: u64) -> SectionKind {
    let exec = sh_flags & u64::from(SHF_EXECINSTR) != 0;
    let write = sh_flags & u64::from(SHF_WRITE) != 0;

    if sh_type == SHT_NOBITS {
        return SectionKind::Bss;
    }
    if sh_type != SHT_PROGBITS {
        return SectionKind::Other;
    }

    if exec {
        SectionKind::Text
    } else if !write {
        // PROGBITS + allocated + not writable → read-only data.
        // Common names: .rodata, .rodata.str1.1, .rodata.cst16, .eh_frame, .data.rel.ro
        if name.starts_with(".rodata") || name == ".data.rel.ro" {
            SectionKind::RoData
        } else if name == ".eh_frame" || name == ".gcc_except_table" {
            SectionKind::Other
        } else {
            SectionKind::RoData
        }
    } else {
        SectionKind::Data
    }
}

fn collect_symbols<'a>(
    _elf: &Elf<'a>,
    syms: &Symtab<'a>,
    strtab: &goblin::strtab::Strtab<'a>,
) -> Vec<Symbol<'a>> {
    let mut out = Vec::new();
    for sym in syms.iter() {
        let name = strtab.get_at(sym.st_name).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let kind = match st_type(sym.st_info) {
            STT_FUNC => SymbolKind::Function,
            STT_OBJECT => SymbolKind::Object,
            STT_FILE => SymbolKind::File,
            STT_SECTION => SymbolKind::Section,
            _ => SymbolKind::Other,
        };
        out.push(Symbol {
            name: Cow::Borrowed(name),
            vm_addr: sym.st_value,
            size: sym.st_size,
            kind,
        });
    }
    out
}
