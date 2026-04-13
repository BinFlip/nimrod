//! Cross-referenced module map.
//!
//! Builds a comprehensive view of which Nim modules are compiled into a
//! binary by cross-referencing three independent data sources:
//!
//! 1. **Init functions** — module paths decoded from `*Init000` symbol names.
//! 2. **Demangled symbols** — module names from the `__<module>_u<id>` suffix.
//! 3. **Stack-trace file paths** — `.nim` file paths embedded in rodata.
//!
//! All three sources are reconciled into a single map keyed by module
//! name. The key is the bare module name (e.g. `vm`, `system`) when
//! available, falling back to the `.nim` filename.

use std::collections::BTreeMap;

use crate::{
    container::Container,
    demangle::{modpath::PathPrefix, symbol},
    inits, stacktrace,
};

/// A reconstructed map of Nim modules present in the binary.
#[derive(Debug, Clone)]
pub struct ModuleMap {
    /// Modules keyed by canonical name (e.g. `system`, `vm`, `strutils`).
    pub modules: BTreeMap<String, ModuleInfo>,
}

/// Information about a single Nim module.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Decoded filesystem path from init functions (e.g. `system/exceptions.nim`).
    pub init_path: Option<String>,
    /// Module path prefix (`@m`, `@p`, `@d`, etc.).
    pub prefix: Option<PathPrefix>,
    /// Virtual address of the `Init000` function, if found.
    pub init_addr: Option<u64>,
    /// Virtual address of the `DatInit000` function, if found.
    pub dat_init_addr: Option<u64>,
    /// Function symbols attributed to this module (demangled name + VA).
    pub symbols: Vec<ModuleSymbol>,
    /// Stack-trace file paths matching this module, if any.
    pub file_paths: Vec<String>,
}

/// A function symbol within a module.
#[derive(Debug, Clone)]
pub struct ModuleSymbol {
    /// Demangled Nim identifier.
    pub name: String,
    /// Virtual address.
    pub address: u64,
    /// Size in bytes (from ELF `st_size`; zero if unavailable).
    pub size: u64,
    /// The `itemId.item` disambiguator.
    pub item_id: u64,
}

impl ModuleInfo {
    /// Number of function symbols in this module.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
}

/// Builds a cross-referenced module map from the container.
pub fn build(container: &Container<'_>) -> ModuleMap {
    let mut modules: BTreeMap<String, ModuleInfo> = BTreeMap::new();

    // Source 1: init functions → module paths.
    // Key by the basename without .nim extension (e.g. "system.nim" → "system").
    let inits = inits::scan(container);
    for f in &inits {
        let key = module_key_from_path(&f.module_path.path);
        let entry = modules.entry(key).or_insert_with(default_info);
        if entry.init_path.is_none() {
            entry.init_path = Some(f.module_path.path.clone());
        }
        if entry.prefix.is_none() {
            entry.prefix = f.module_path.prefix;
        }

        match f.kind {
            inits::InitKind::Init => entry.init_addr = Some(f.address),
            inits::InitKind::DatInit => entry.dat_init_addr = Some(f.address),
            inits::InitKind::HcrInit => {}
        }
    }

    // Source 2: demangled symbols → module names.
    // Only count symbols with a valid `_u<N>` item ID.
    for sym in container.symbols() {
        if let Some(d) = symbol::parse(sym.name.as_ref()) {
            if let Some(item_id) = d.item_id {
                let key = d.module.to_owned();
                let entry = modules.entry(key).or_insert_with(default_info);
                entry.symbols.push(ModuleSymbol {
                    name: d.identifier.into_owned(),
                    address: sym.vm_addr,
                    size: sym.size,
                    item_id,
                });
            }
        }
    }

    // Source 3: stack-trace file paths → merge into existing modules.
    let harvest = stacktrace::harvest(container);
    for fp in &harvest.file_paths {
        let basename = fp.path.rsplit('/').next().unwrap_or(&fp.path);
        let stem = basename.strip_suffix(".nim").unwrap_or(basename);

        // Try to find an existing module entry that matches:
        // 1. Exact key match on the stem (e.g. "vm" from demangling)
        // 2. Init path ends with this basename (e.g. "system.nim" init
        //    matches "/opt/.../system.nim" stack trace)
        let matched_key = if modules.contains_key(stem) {
            Some(stem.to_owned())
        } else {
            modules
                .iter()
                .find(|(_, info)| {
                    info.init_path
                        .as_ref()
                        .is_some_and(|p| p.ends_with(basename))
                })
                .map(|(k, _)| k.clone())
        };

        if let Some(key) = matched_key {
            if let Some(info) = modules.get_mut(&key) {
                if !info.file_paths.contains(&fp.path) {
                    info.file_paths.push(fp.path.clone());
                }
            }
        } else {
            // No match — create a new entry keyed by stem.
            let entry = modules.entry(stem.to_owned()).or_insert_with(default_info);
            if !entry.file_paths.contains(&fp.path) {
                entry.file_paths.push(fp.path.clone());
            }
        }
    }

    ModuleMap { modules }
}

fn default_info() -> ModuleInfo {
    ModuleInfo {
        init_path: None,
        prefix: None,
        init_addr: None,
        dat_init_addr: None,
        symbols: Vec::new(),
        file_paths: Vec::new(),
    }
}

/// Derives a canonical module key from a decoded init-function path.
///
/// `"system.nim"` → `"system"`, `"system/exceptions.nim"` → `"system/exceptions"`,
/// `"dist/nimony/src/lib/nifstreams.nim"` → `"dist/nimony/src/lib/nifstreams"`.
fn module_key_from_path(path: &str) -> String {
    path.strip_suffix(".nim").unwrap_or(path).to_owned()
}
