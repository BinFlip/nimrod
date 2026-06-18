//! Aggregated code entrypoints.
//!
//! [`build`] collapses every code virtual address the crate can confidently
//! label into one deduplicated, VA-sorted stream, each entry tagged by
//! [`EntrypointKind`]. It composes the entry-shim, init-function, module-symbol,
//! raise-site, and RTTI walkers so a disassembler front-end can label a whole
//! binary from a single call instead of reconciling the individual scans.
//!
//! Entries are keyed by virtual address; when more than one source names the
//! same address the higher-priority source wins, in this order: entry shim →
//! module init → module dat-init → proc symbol → raise-enclosing function →
//! RTTI destructor → RTTI trace proc.
//!
//! Only *addressable* code is included. Stack-trace proc **names** carry no
//! reliable address of their own — every addressable proc already surfaces as
//! [`EntrypointKind::ProcSymbol`] — so they are intentionally not a separate
//! entry kind here; consult [`crate::NimBinary::stack_trace`] for the raw name
//! list.

use std::collections::BTreeMap;

use crate::{
    container::{Container, SymbolKind},
    demangle::symbol,
    inits::{self, InitKind},
    shims, sites, types,
};

/// What a [`CodeEntrypoint`] points at.
///
/// # Stability
///
/// The string returned by [`as_str`](EntrypointKind::as_str) /
/// [`Display`](core::fmt::Display) is part of nimrod's stable API. Changes are
/// SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntrypointKind {
    /// A Nim entry shim (`NimMain`, `PreMain`, …).
    EntryShim,
    /// A module init function (`*Init000`).
    ModuleInit,
    /// A module data-init function (`*DatInit000`).
    ModuleDatInit,
    /// A demangled Nim procedure symbol.
    ProcSymbol,
    /// A function that contains a `raise` site (resolved from the raise-site
    /// walker via its enclosing function symbol).
    EnclosingFunction,
    /// A V2 RTTI `=destroy` destructor proc.
    RttiDestructor,
    /// A V2 RTTI cycle-collector trace proc.
    RttiTraceImpl,
}

impl EntrypointKind {
    /// Returns the stable string identifier for this kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EntryShim => "EntryShim",
            Self::ModuleInit => "ModuleInit",
            Self::ModuleDatInit => "ModuleDatInit",
            Self::ProcSymbol => "ProcSymbol",
            Self::EnclosingFunction => "EnclosingFunction",
            Self::RttiDestructor => "RttiDestructor",
            Self::RttiTraceImpl => "RttiTraceImpl",
        }
    }
}

impl core::fmt::Display for EntrypointKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single labelled code address.
///
/// `va` is a **virtual address** in the image's load space. Convert to an RVA
/// with [`crate::container::Container::va_to_rva`].
#[derive(Debug, Clone)]
pub struct CodeEntrypoint {
    /// Virtual address of the code.
    pub va: u64,
    /// What the address is.
    pub kind: EntrypointKind,
    /// Best-effort human-readable name (demangled where possible). May be empty
    /// if no name was recoverable.
    pub name: String,
    /// Size in bytes when the container provides it (ELF `st_size`); `None`
    /// otherwise.
    pub size: Option<u64>,
}

/// Builds the deduplicated, VA-sorted entrypoint stream for `container`.
pub fn build(container: &Container<'_>) -> Vec<CodeEntrypoint> {
    let mut map: BTreeMap<u64, CodeEntrypoint> = BTreeMap::new();

    // 1 — entry shims.
    for s in shims::scan(container) {
        insert(
            &mut map,
            s.address,
            EntrypointKind::EntryShim,
            s.symbol_name.clone(),
            container,
        );
    }

    // 2/3 — module init / dat-init functions.
    for f in inits::scan(container) {
        let kind = match f.kind {
            InitKind::Init | InitKind::HcrInit => EntrypointKind::ModuleInit,
            InitKind::DatInit => EntrypointKind::ModuleDatInit,
        };
        let name = if f.module_path.path.is_empty() {
            f.symbol_name.clone()
        } else {
            f.module_path.path.clone()
        };
        insert(&mut map, f.address, kind, name, container);
    }

    // 4 — demangled Nim proc symbols (those with a `_u<item>` id).
    for sym in container.symbols() {
        if sym.kind != SymbolKind::Function || sym.vm_addr == 0 {
            continue;
        }
        let raw = sym.name.as_ref();
        let Some(d) = symbol::parse(raw) else {
            continue;
        };
        if d.item_id.is_none() {
            continue;
        }
        let entry = CodeEntrypoint {
            va: sym.vm_addr,
            kind: EntrypointKind::ProcSymbol,
            name: d.identifier.into_owned(),
            size: if sym.size > 0 { Some(sym.size) } else { None },
        };
        map.entry(sym.vm_addr).or_insert(entry);
    }

    // 5 — functions that contain a raise site.
    for rs in sites::scan(container) {
        let Some(func) = container.function_at_va(rs.call_addr) else {
            continue;
        };
        let name = rs
            .enclosing_function
            .clone()
            .unwrap_or_else(|| func.name.as_ref().to_owned());
        let entry = CodeEntrypoint {
            va: func.vm_addr,
            kind: EntrypointKind::EnclosingFunction,
            name,
            size: if func.size > 0 { Some(func.size) } else { None },
        };
        map.entry(func.vm_addr).or_insert(entry);
    }

    // 6/7 — RTTI destructor / trace procs from the type graph.
    for t in types::build(container) {
        if let Some(d) = &t.destructor {
            let name = code_ref_name(d);
            insert(&mut map, d.address, EntrypointKind::RttiDestructor, name, container);
        }
        if let Some(tr) = &t.trace_impl {
            let name = code_ref_name(tr);
            insert(
                &mut map,
                tr.address,
                EntrypointKind::RttiTraceImpl,
                name,
                container,
            );
        }
    }

    map.into_values().collect()
}

/// Inserts an entry at `va` unless one already exists (priority: first wins).
/// Resolves the size from the function symbol covering `va` when its entry
/// matches `va` exactly.
fn insert(
    map: &mut BTreeMap<u64, CodeEntrypoint>,
    va: u64,
    kind: EntrypointKind,
    name: String,
    container: &Container<'_>,
) {
    map.entry(va).or_insert_with(|| CodeEntrypoint {
        va,
        kind,
        name,
        size: size_at(container, va),
    });
}

/// Returns the size of the function whose entry is exactly `va`, when known.
fn size_at(container: &Container<'_>, va: u64) -> Option<u64> {
    container
        .function_at_va(va)
        .filter(|s| s.vm_addr == va && s.size > 0)
        .map(|s| s.size)
}

/// Picks the most useful name out of a resolved [`types::CodeRef`].
fn code_ref_name(r: &types::CodeRef) -> String {
    r.function
        .clone()
        .or_else(|| r.symbol_name.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_as_str_is_stable() {
        assert_eq!(EntrypointKind::EntryShim.as_str(), "EntryShim");
        assert_eq!(EntrypointKind::ProcSymbol.to_string(), "ProcSymbol");
        assert_eq!(EntrypointKind::RttiDestructor.as_str(), "RttiDestructor");
    }

    #[test]
    fn code_ref_name_prefers_function_then_symbol() {
        let with_fn = types::CodeRef {
            address: 0,
            function: Some("foo".into()),
            module: None,
            symbol_name: Some("foo__m_u1".into()),
        };
        assert_eq!(code_ref_name(&with_fn), "foo");
        let sym_only = types::CodeRef {
            address: 0,
            function: None,
            module: None,
            symbol_name: Some("rawSym".into()),
        };
        assert_eq!(code_ref_name(&sym_only), "rawSym");
    }

    #[test]
    fn build_tags_shims_procs_and_skips_non_nim() {
        use crate::container::{self, Arch, Format, Symbol, SymbolKind};
        use std::borrow::Cow;

        let bytes = vec![0u8; 16];
        let symbols = vec![
            Symbol {
                name: Cow::Borrowed("NimMain"),
                vm_addr: 0x1000,
                size: 0,
                kind: SymbolKind::Function,
            },
            Symbol {
                name: Cow::Borrowed("parseInt__strutils_u42"),
                vm_addr: 0x2000,
                size: 16,
                kind: SymbolKind::Function,
            },
            // Not Nim-mangled (no `_u<id>`): must be skipped.
            Symbol {
                name: Cow::Borrowed("memcpy"),
                vm_addr: 0x3000,
                size: 0,
                kind: SymbolKind::Function,
            },
        ];
        let c = container::assemble(&bytes, Format::Elf, Arch::Amd64, 0, vec![], symbols);

        let eps = build(&c);
        let shim = eps.iter().find(|e| e.va == 0x1000).expect("shim present");
        assert_eq!(shim.kind, EntrypointKind::EntryShim);

        let proc = eps.iter().find(|e| e.va == 0x2000).expect("proc present");
        assert_eq!(proc.kind, EntrypointKind::ProcSymbol);
        assert_eq!(proc.name, "parseInt");
        assert_eq!(proc.size, Some(16));

        assert!(eps.iter().all(|e| e.va != 0x3000), "non-Nim symbol excluded");
        // VA-sorted output.
        assert!(eps.windows(2).all(|w| w[0].va <= w[1].va));
    }
}
