//! Mach-O backend for the container abstraction.
//!
//! Handles single-architecture Mach-O binaries and, for Fat (universal)
//! binaries, picks the first slice. Future milestones may expose all
//! slices as a list of containers.

use std::borrow::Cow;

use goblin::mach::{
    Mach, MachO,
    constants::cputype::{CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_I386, CPU_TYPE_X86_64},
    symbols::{N_SECT, Nlist},
};

use crate::{
    container::{Arch, Container, Format, Section, SectionKind, Symbol, SymbolKind, assemble},
    error::{Error, Result},
};

pub(crate) fn build<'a>(bytes: &'a [u8], mach: Mach<'a>) -> Result<Container<'a>> {
    let macho = match mach {
        Mach::Binary(m) => m,
        Mach::Fat(fat) => {
            let arches = fat.arches()?;
            let first = arches.first().ok_or(Error::UnsupportedFormat)?;
            MachO::parse(bytes, first.offset as usize)?
        }
    };

    let arch = map_arch(macho.header.cputype);
    let sections = collect_sections(bytes, &macho)?;
    let symbols = collect_symbols(&macho)?;
    Ok(assemble(bytes, Format::MachO, arch, sections, symbols))
}

fn map_arch(cputype: u32) -> Arch {
    match cputype {
        CPU_TYPE_X86_64 => Arch::Amd64,
        CPU_TYPE_I386 => Arch::I386,
        CPU_TYPE_ARM64 => Arch::Aarch64,
        CPU_TYPE_ARM => Arch::Arm,
        _ => Arch::Other,
    }
}

fn collect_sections<'a>(bytes: &'a [u8], macho: &MachO<'a>) -> Result<Vec<Section<'a>>> {
    let mut out = Vec::new();
    for seg in &macho.segments {
        let segname = seg.name().unwrap_or("").to_string();
        for section in seg.into_iter() {
            let (sect, _data) = match section {
                Ok(s) => s,
                Err(_) => continue,
            };
            let sectname = sect.name().unwrap_or("").to_string();
            let qualified = format!("{segname},{sectname}");

            let vm_addr = sect.addr;
            let vm_size = sect.size;

            let file_offset = sect.offset as usize;
            let file_size = sect.size as usize;
            let data: &'a [u8] = if file_offset == 0 {
                // A zero offset on Mach-O usually means the section has no
                // file backing (__bss, __common).
                &[]
            } else {
                bytes
                    .get(file_offset..file_offset.saturating_add(file_size))
                    .unwrap_or(&[])
            };

            let kind = classify(&segname, &sectname);
            out.push(Section {
                name: qualified,
                vm_addr,
                vm_size,
                data,
                kind,
            });
        }
    }
    Ok(out)
}

fn classify(segname: &str, sectname: &str) -> SectionKind {
    match segname {
        "__TEXT" => match sectname {
            "__text" => SectionKind::Text,
            "__cstring" | "__const" | "__ustring" | "__gcc_except_tab" | "__eh_frame" => {
                SectionKind::RoData
            }
            _ => SectionKind::RoData, // __TEXT is read-only by convention
        },
        "__DATA_CONST" => SectionKind::RoData,
        "__DATA" => match sectname {
            "__bss" | "__common" => SectionKind::Bss,
            _ => SectionKind::Data,
        },
        _ => SectionKind::Other,
    }
}

fn collect_symbols<'a>(macho: &MachO<'a>) -> Result<Vec<Symbol<'a>>> {
    let mut out = Vec::new();
    for result in macho.symbols() {
        let (name, nlist) = match result {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        if name.is_empty() || nlist.is_stab() {
            continue;
        }
        // Mach-O C-level symbols are prefixed with a leading underscore.
        // Strip it so that probes matching "NimMain" work uniformly across
        // all three formats.
        let normalised: Cow<'a, str> = if let Some(stripped) = name.strip_prefix('_') {
            Cow::Borrowed(stripped)
        } else {
            Cow::Borrowed(name)
        };
        let kind = classify_symbol(&nlist);
        out.push(Symbol {
            name: normalised,
            vm_addr: nlist.n_value,
            size: 0, // Mach-O nlist doesn't carry size
            kind,
        });
    }
    Ok(out)
}

fn classify_symbol(nlist: &Nlist) -> SymbolKind {
    if nlist.get_type() == N_SECT {
        // Distinguishing function vs data requires looking at the target
        // section; we report all defined symbols as functions by default
        // and rely on downstream consumers to refine.
        SymbolKind::Function
    } else {
        SymbolKind::Other
    }
}
