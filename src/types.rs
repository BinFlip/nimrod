//! Cross-referenced Nim type graph recovered from RTTI.
//!
//! This module is the high-level counterpart to [`crate::rtti`]. Where
//! `rtti::symbols::scan` only enumerates the `NTIv2_` / `NTI_` globals and the
//! per-version readers ([`rtti::v1::read`], [`rtti::v2::read`]) parse one
//! struct at a time, [`build`] reconciles all of them into a single navigable
//! graph: every recovered type is parsed in full and its raw pointer fields are
//! resolved into [`TypeRef`] (type → type) and [`CodeRef`] (type → function)
//! cross-links.
//!
//! On top of the per-version readers, three extraction passes recover data the
//! readers expose only as raw addresses:
//!
//! - **V2 inheritance** — the `display` class-token array (`RESEARCH.md` §3.2)
//!   is dereferenced into [`NimType::display_tokens`], and V2 parents are
//!   linked through it.
//! - **V1 enum values** — for enum types the `TNimNode` slots are reinterpreted
//!   as [`EnumValue`]s (each slot's `offset` is the enumerator ordinal).
//! - **V2 → V1 bridge** — when a V2 type carries a non-nil `typeInfoV1`
//!   backpointer, the legacy record it points at is read and its field names
//!   are imported (the only way to recover member names for ARC/ORC objects
//!   that were not compiled with `nimTypeNames`).
//!
//! All types here are **owned** (no lifetime parameter): the graph outlives the
//! borrow of the input bytes, so [`crate::NimBinary`] can cache it in a
//! `OnceLock` exactly like the other scans.

use std::collections::BTreeMap;

use crate::{
    container::Container,
    demangle::symbol,
    rtti::{
        self,
        symbols::RttiVersion,
        v1::{NimKind, NimTypeFlag, NodeField},
    },
    util,
};

/// Coarse classification of a recovered type.
///
/// For V1 (`refc`) types this is derived directly from the `TNimType.kind`
/// field. V2 (`ARC`/`ORC`) records carry no kind field, so the shape is
/// inferred: a V2 type whose `display` (inheritance class-token array) pointer
/// is non-null is classified as [`TypeShape::Object`]; otherwise
/// [`TypeShape::Other`].
///
/// # Stability
///
/// The string returned by [`as_str`](TypeShape::as_str) /
/// [`Display`](std::fmt::Display) is part of nimrod's stable API. Changes are
/// SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeShape {
    /// An object / record type (`tyObject`, or a V2 type with a `display`
    /// inheritance array).
    Object,
    /// A tuple type (`tyTuple`).
    Tuple,
    /// An enum type (`tyEnum`); see [`NimType::enum_values`].
    Enum,
    /// A `ref T` type (`tyRef`).
    Ref,
    /// A `seq[T]` type (`tySequence`).
    Sequence,
    /// Any other kind (primitives, pointers, procs, or a V2 type with no
    /// `display` array), or a type whose struct data could not be read.
    Other,
}

impl TypeShape {
    /// Returns the stable string identifier for this shape.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Object => "Object",
            Self::Tuple => "Tuple",
            Self::Enum => "Enum",
            Self::Ref => "Ref",
            Self::Sequence => "Sequence",
            Self::Other => "Other",
        }
    }

    /// Maps a V1 [`NimKind`] to a coarse [`TypeShape`].
    fn from_kind(kind: NimKind) -> Self {
        match kind {
            NimKind::Object => Self::Object,
            NimKind::Tuple => Self::Tuple,
            NimKind::Enum => Self::Enum,
            NimKind::Ref => Self::Ref,
            NimKind::Sequence => Self::Sequence,
            _ => Self::Other,
        }
    }
}

impl core::fmt::Display for TypeShape {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Version-independent type flags.
///
/// Unifies the V1 `TNimTypeFlag` set ([`NimTypeFlag`]) with the V2 `flags`
/// integer (`RESEARCH.md` §3.3: bit 0 is set when the type cannot form a
/// reference cycle).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct TypeFlags {
    /// `ntfNoRefs` — the type contains no `ref` / `seq` / `string` members.
    /// V1 only; always `false` for V2 (the V2 flag word does not encode it).
    pub no_refs: bool,
    /// The type cannot form a reference cycle (`ntfAcyclic` for V1, `flags & 1`
    /// for V2).
    pub acyclic: bool,
    /// `ntfEnumHole` — an enum with non-contiguous ordinals; `$` needs the slow
    /// path. V1 only.
    pub enum_hole: bool,
}

/// A reference from one type to another, by virtual address.
#[derive(Debug, Clone)]
pub struct TypeRef {
    /// Virtual address of the target RTTI global.
    pub address: u64,
    /// Index of the target in the slice returned by [`crate::NimBinary::types`],
    /// when the address matched a known type. `None` when the pointer targets a
    /// type with no enumerable RTTI symbol.
    pub index: Option<usize>,
    /// Resolved name of the target type, when known.
    pub name: Option<String>,
}

/// A reference from a type to a code address (destructor, finalizer, marker,
/// deepcopy, or trace proc), resolved to a function symbol when possible.
#[derive(Debug, Clone)]
pub struct CodeRef {
    /// Virtual address of the function.
    pub address: u64,
    /// Demangled Nim identifier of the function symbol covering `address`, when
    /// one was found.
    pub function: Option<String>,
    /// Module the function belongs to, demangled from its symbol, when known.
    pub module: Option<String>,
    /// Raw (mangled) symbol name covering `address`, when one was found.
    pub symbol_name: Option<String>,
}

/// A member field of an object or tuple type.
#[derive(Debug, Clone)]
pub struct TypeField {
    /// Field name (from the `TNimNode.name` cstring).
    pub name: String,
    /// Byte offset of the field within its parent struct.
    pub offset: u64,
    /// The field's own type, when the `TNimNode.typ` pointer resolved to a
    /// known type.
    pub type_ref: Option<TypeRef>,
}

/// A single member of an enum type.
#[derive(Debug, Clone)]
pub struct EnumValue {
    /// Enumerator name.
    pub name: String,
    /// Ordinal value. Nim encodes enum ordinals in the `TNimNode.offset` slot
    /// rather than a byte offset; for enums flagged [`TypeFlags::enum_hole`]
    /// the ordinals may be non-contiguous.
    pub ordinal: u64,
}

/// A fully recovered, cross-linked Nim type.
///
/// # Address space
///
/// [`address`](NimType::address) and every nested [`TypeRef::address`] /
/// [`CodeRef::address`] is a **virtual address** in the image's load space, not
/// a file offset. Convert with [`crate::NimBinary::type_rva`] or
/// [`crate::container::Container::va_to_rva`].
///
/// # Readability
///
/// When the RTTI struct's bytes are not file-backed (notably V1 globals that
/// land in Mach-O `__DATA,__common`, `RESEARCH.md` §3.6), the struct cannot be
/// parsed from the file. The entry is still returned — `symbol_name`,
/// `address`, `version`, and the V1 `type_fragment` carry forensic value — but
/// the parsed fields default to empty and [`shape`](NimType::shape) is
/// [`TypeShape::Other`]. Use [`NimType::is_readable`] to distinguish.
#[derive(Debug, Clone)]
pub struct NimType {
    /// Which RTTI generation this type came from.
    pub version: RttiVersion,
    /// Full RTTI symbol name (`NTIv2…_` or `NTI…_`).
    pub symbol_name: String,
    /// Virtual address of the RTTI global.
    pub address: u64,
    /// Human-readable type name from the struct's `name` field. Populated only
    /// when the binary was compiled with `nimTypeNames` (typical for debug
    /// builds, absent in release).
    pub name: Option<String>,
    /// V1 readable type fragment decoded from the `NTI<typespec><hash>_` symbol
    /// name (`RESEARCH.md` §3.4). Always `None` for V2.
    pub type_fragment: Option<String>,
    /// Coarse classification.
    pub shape: TypeShape,
    /// Size of the type in bytes (`0` when the struct was unreadable).
    pub size: u64,
    /// Alignment in bytes (`0` when unreadable).
    pub align: u64,
    /// Inheritance depth. V2 only; `None` for V1.
    pub depth: Option<i16>,
    /// Unified type flags.
    pub flags: TypeFlags,
    /// V1 `TNimType.kind`; `None` for V2 (which has no kind field).
    pub kind: Option<NimKind>,
    /// Parent type: V1 `base`, or for V2 the type one level up the `display`
    /// inheritance chain.
    pub parent: Option<TypeRef>,
    /// Member fields of an object / tuple type. Recovered from the V1
    /// `TNimNode` tree, or imported via the V2 → V1 bridge.
    pub fields: Vec<TypeField>,
    /// Members of an enum type.
    pub enum_values: Vec<EnumValue>,
    /// V2 inheritance class tokens read from the `display` array
    /// (`depth + 1` entries, root first). Empty for V1 or when the array was
    /// not readable.
    pub display_tokens: Vec<u32>,
    /// Destructor proc (V2 `=destroy` hook).
    pub destructor: Option<CodeRef>,
    /// Cycle-collector trace proc (V2 `traceImpl`).
    pub trace_impl: Option<CodeRef>,
    /// Finalizer proc (V1).
    pub finalizer: Option<CodeRef>,
    /// GC marker proc (V1).
    pub marker: Option<CodeRef>,
    /// Deep-copy proc (V1).
    pub deepcopy: Option<CodeRef>,
    /// V2 → V1 backpointer (`typeInfoV1`), when non-nil. The legacy record it
    /// targets is the source of any imported [`fields`](NimType::fields).
    pub type_info_v1: Option<TypeRef>,
    /// Whether the RTTI struct bytes were file-backed and parsed. `false` for
    /// name-only shells (see the type-level "Readability" note).
    pub readable: bool,
}

impl NimType {
    /// Returns `true` if the RTTI struct bytes were file-backed and parsed.
    ///
    /// `false` indicates a name-only shell — the symbol existed but its struct
    /// data was not in the file (e.g. Mach-O `__DATA,__common`).
    pub fn is_readable(&self) -> bool {
        self.readable
    }
}

/// Builds the cross-referenced type graph for `container`.
///
/// Returns one [`NimType`] per RTTI global found by
/// [`rtti::symbols::scan`]. The result is deterministic (symbols are processed
/// in scan order; internal indices use [`BTreeMap`]).
pub fn build(container: &Container<'_>) -> Vec<NimType> {
    // Step 1 — seed one NimType per RTTI symbol. This fixes every type's
    // address, which is all that the VA index in step 2 needs.
    let rtti_syms = rtti::symbols::scan(container);
    let mut types: Vec<NimType> = rtti_syms
        .iter()
        .map(|s| NimType {
            version: s.version,
            symbol_name: s.symbol_name.clone(),
            address: s.address,
            name: None,
            type_fragment: s.type_fragment.clone(),
            shape: TypeShape::Other,
            size: 0,
            align: 0,
            depth: None,
            flags: TypeFlags::default(),
            kind: None,
            parent: None,
            fields: Vec::new(),
            enum_values: Vec::new(),
            display_tokens: Vec::new(),
            destructor: None,
            trace_impl: None,
            finalizer: None,
            marker: None,
            deepcopy: None,
            type_info_v1: None,
            readable: false,
        })
        .collect();

    // Step 2 — VA → type-index map. Built from addresses alone, so it is
    // complete before any struct is read and can resolve forward references.
    let va_index: BTreeMap<u64, usize> = types
        .iter()
        .enumerate()
        .map(|(i, t)| (t.address, i))
        .collect();

    // Step 3 — parse each struct and resolve its cross-references. The
    // `display`/`typeInfoV1` addresses are stashed for passes a and c.
    let mut display_info: Vec<Option<(u64, i16)>> = vec![None; types.len()];

    for (i, t) in types.iter_mut().enumerate() {
        match t.version {
            RttiVersion::V2 => {
                let Some(f) = rtti::v2::read(container, t.address) else {
                    continue;
                };
                t.readable = true;
                t.size = f.size;
                t.align = u64::try_from(f.align).unwrap_or(0);
                t.depth = Some(f.depth);
                t.name = f.name;
                t.flags = TypeFlags {
                    no_refs: false,
                    acyclic: f.flags & 1 != 0,
                    enum_hole: false,
                };
                t.destructor = f.destructor_addr.map(|a| resolve_code_ref(container, a));
                t.trace_impl = f.trace_impl_addr.map(|a| resolve_code_ref(container, a));
                t.type_info_v1 = f.type_info_v1_addr.map(|a| make_type_ref(a, &va_index));
                // V2 has no kind field. A non-null `display` (inheritance
                // class-token array) is emitted for object types.
                if let Some(d) = f.display_addr {
                    t.shape = TypeShape::Object;
                    if let Some(slot) = display_info.get_mut(i) {
                        *slot = Some((d, f.depth));
                    }
                }
            }
            RttiVersion::V1 => {
                let Some(f) = rtti::v1::read(container, t.address) else {
                    continue;
                };
                t.readable = true;
                t.size = f.size;
                t.align = f.align;
                t.kind = Some(f.kind);
                t.name = f.name;
                t.shape = TypeShape::from_kind(f.kind);
                t.flags = flags_from_v1(&f.flags);
                t.parent = f.base_addr.map(|a| make_type_ref(a, &va_index));
                t.finalizer = f.finalizer_addr.map(|a| resolve_code_ref(container, a));
                t.marker = f.marker_addr.map(|a| resolve_code_ref(container, a));
                t.deepcopy = f.deepcopy_addr.map(|a| resolve_code_ref(container, a));

                // Pass b — enum slots encode (name, ordinal); everything else
                // is a struct field.
                if f.kind == NimKind::Enum {
                    t.enum_values = node_fields_to_enum_values(&f.node_fields);
                } else {
                    t.fields = node_fields_to_type_fields(&f.node_fields, &va_index);
                }
            }
        }
    }

    // Pass a — dereference each V2 `display` array into class tokens, then link
    // V2 parents through them. Two sub-passes because the token→index map needs
    // every type's own token first.
    let mut token_index: BTreeMap<u32, usize> = BTreeMap::new();
    for (i, t) in types.iter_mut().enumerate() {
        let Some((display_addr, depth)) = display_info.get(i).copied().flatten() else {
            continue;
        };
        t.display_tokens = read_display_tokens(container, display_addr, depth);
        // The type's own class token is the last entry (index == depth).
        if let Some(&own) = t.display_tokens.last() {
            token_index.insert(own, i);
        }
    }
    // Link parents: the token at index depth-1 identifies the immediate parent.
    let parents: Vec<Option<u64>> = types
        .iter()
        .map(|t| {
            let len = t.display_tokens.len();
            if len < 2 {
                return None;
            }
            let parent_token = t.display_tokens.get(len.wrapping_sub(2)).copied()?;
            let parent_idx = token_index.get(&parent_token).copied()?;
            types.get(parent_idx).map(|p| p.address)
        })
        .collect();
    for (t, parent_addr) in types.iter_mut().zip(parents) {
        if t.version == RttiVersion::V2
            && t.parent.is_none()
            && let Some(addr) = parent_addr
        {
            t.parent = Some(make_type_ref(addr, &va_index));
        }
    }

    // Pass c — V2 → V1 field bridge. When a V2 object carries a non-nil
    // typeInfoV1 backpointer, import the legacy record's member names (the only
    // route to field names for ARC/ORC objects without `nimTypeNames`).
    let bridge_targets: Vec<(usize, u64)> = types
        .iter()
        .enumerate()
        .filter_map(|(i, t)| {
            if t.version == RttiVersion::V2 && t.fields.is_empty() {
                t.type_info_v1.as_ref().map(|r| (i, r.address))
            } else {
                None
            }
        })
        .collect();
    for (i, v1_addr) in bridge_targets {
        let Some(f) = rtti::v1::read(container, v1_addr) else {
            continue;
        };
        if f.node_fields.is_empty() {
            continue;
        }
        let imported = node_fields_to_type_fields(&f.node_fields, &va_index);
        if let Some(t) = types.get_mut(i) {
            t.fields = imported;
        }
    }

    // Final pass — back-fill every TypeRef's resolved name. Snapshot the names
    // first so we can read and write `types` without aliasing.
    let names: Vec<Option<String>> = types.iter().map(|t| t.name.clone()).collect();
    for t in types.iter_mut() {
        backfill_ref(&mut t.parent, &names);
        backfill_ref(&mut t.type_info_v1, &names);
        for field in t.fields.iter_mut() {
            backfill_ref(&mut field.type_ref, &names);
        }
    }

    types
}

/// Builds a [`TypeRef`] to the type at `addr`, resolving its index now and its
/// name in the final back-fill pass.
fn make_type_ref(addr: u64, va_index: &BTreeMap<u64, usize>) -> TypeRef {
    TypeRef {
        address: addr,
        index: va_index.get(&addr).copied(),
        name: None,
    }
}

/// Fills a [`TypeRef::name`] from the snapshot of resolved type names.
fn backfill_ref(slot: &mut Option<TypeRef>, names: &[Option<String>]) {
    if let Some(r) = slot.as_mut()
        && let Some(idx) = r.index
        && let Some(Some(name)) = names.get(idx)
    {
        r.name = Some(name.clone());
    }
}

/// Resolves a code address to the function symbol that covers it, demangling
/// the Nim identifier and module when the symbol matches the canonical layout.
fn resolve_code_ref(container: &Container<'_>, addr: u64) -> CodeRef {
    let Some(sym) = container.function_at_va(addr) else {
        return CodeRef {
            address: addr,
            function: None,
            module: None,
            symbol_name: None,
        };
    };
    let raw = sym.name.as_ref();
    let demangled = symbol::parse(raw);
    CodeRef {
        address: addr,
        function: demangled
            .as_ref()
            .map(|d| d.identifier.clone().into_owned()),
        module: demangled.as_ref().map(|d| d.module.to_owned()),
        symbol_name: Some(raw.to_owned()),
    }
}

/// Maps a V1 flag vector onto the unified [`TypeFlags`].
fn flags_from_v1(flags: &[NimTypeFlag]) -> TypeFlags {
    TypeFlags {
        no_refs: flags.contains(&NimTypeFlag::NoRefs),
        acyclic: flags.contains(&NimTypeFlag::Acyclic),
        enum_hole: flags.contains(&NimTypeFlag::EnumHole),
    }
}

/// Converts `TNimNode` slot entries into struct [`TypeField`]s.
fn node_fields_to_type_fields(
    node_fields: &[NodeField],
    va_index: &BTreeMap<u64, usize>,
) -> Vec<TypeField> {
    node_fields
        .iter()
        .map(|nf| TypeField {
            name: nf.name.clone(),
            offset: nf.offset,
            type_ref: nf.type_addr.map(|a| make_type_ref(a, va_index)),
        })
        .collect()
}

/// Reinterprets `TNimNode` enum slots as [`EnumValue`]s (`offset` is the
/// enumerator ordinal, not a byte offset).
fn node_fields_to_enum_values(node_fields: &[NodeField]) -> Vec<EnumValue> {
    node_fields
        .iter()
        .map(|nf| EnumValue {
            name: nf.name.clone(),
            ordinal: nf.offset,
        })
        .collect()
}

/// Reads `depth + 1` little-endian `u32` class tokens from the V2 `display`
/// array at `display_addr`. Returns an empty vector if the array is not
/// file-backed. The count is bounded defensively in case `depth` is corrupt.
fn read_display_tokens(container: &Container<'_>, display_addr: u64, depth: i16) -> Vec<u32> {
    /// Hard cap on the inheritance depth we will read, guarding against a
    /// corrupt `depth` field driving an oversized read.
    const MAX_DEPTH: usize = 256;

    let Ok(depth_usize) = usize::try_from(depth) else {
        return Vec::new();
    };
    let count = depth_usize.saturating_add(1).min(MAX_DEPTH);

    let Some(base_off) = rtti::v2::va_to_offset(container, display_addr) else {
        return Vec::new();
    };
    let bytes = container.bytes();

    let mut tokens = Vec::with_capacity(count);
    for i in 0..count {
        let Some(off) = i.checked_mul(4).and_then(|d| base_off.checked_add(d)) else {
            break;
        };
        // Stop at the first token that would read past the file end rather than
        // emitting zeros for unmapped bytes.
        if off.checked_add(4).is_none_or(|end| end > bytes.len()) {
            break;
        }
        tokens.push(util::read_u32_le(bytes, off));
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_from_kind_maps_known_kinds() {
        assert_eq!(TypeShape::from_kind(NimKind::Object), TypeShape::Object);
        assert_eq!(TypeShape::from_kind(NimKind::Tuple), TypeShape::Tuple);
        assert_eq!(TypeShape::from_kind(NimKind::Enum), TypeShape::Enum);
        assert_eq!(TypeShape::from_kind(NimKind::Ref), TypeShape::Ref);
        assert_eq!(TypeShape::from_kind(NimKind::Sequence), TypeShape::Sequence);
        assert_eq!(TypeShape::from_kind(NimKind::Int), TypeShape::Other);
    }

    #[test]
    fn shape_as_str_is_stable() {
        assert_eq!(TypeShape::Object.as_str(), "Object");
        assert_eq!(TypeShape::Enum.as_str(), "Enum");
        assert_eq!(TypeShape::Other.to_string(), "Other");
    }

    #[test]
    fn flags_from_v1_unifies_set() {
        let f = flags_from_v1(&[NimTypeFlag::NoRefs, NimTypeFlag::Acyclic]);
        assert!(f.no_refs);
        assert!(f.acyclic);
        assert!(!f.enum_hole);
    }

    #[test]
    fn node_fields_become_type_fields_with_refs() {
        let idx: BTreeMap<u64, usize> = [(0x1000, 0)].into_iter().collect();
        let nf = vec![
            NodeField {
                name: "a".to_string(),
                offset: 0,
                type_addr: Some(0x1000),
            },
            NodeField {
                name: "b".to_string(),
                offset: 8,
                type_addr: None,
            },
        ];
        let fields = node_fields_to_type_fields(&nf, &idx);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "a");
        assert_eq!(fields[0].type_ref.as_ref().unwrap().index, Some(0));
        assert_eq!(fields[1].offset, 8);
        assert!(fields[1].type_ref.is_none());
    }

    #[test]
    fn enum_slots_become_values_with_ordinals() {
        let nf = vec![
            NodeField {
                name: "ckRed".to_string(),
                offset: 0,
                type_addr: None,
            },
            NodeField {
                name: "ckBlue".to_string(),
                offset: 7,
                type_addr: None,
            },
        ];
        let values = node_fields_to_enum_values(&nf);
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].name, "ckRed");
        assert_eq!(values[1].ordinal, 7);
    }

    #[test]
    fn backfill_ref_fills_name_from_snapshot() {
        let names = vec![Some("Foo".to_string())];
        let mut slot = Some(TypeRef {
            address: 0x10,
            index: Some(0),
            name: None,
        });
        backfill_ref(&mut slot, &names);
        assert_eq!(slot.unwrap().name.as_deref(), Some("Foo"));
    }

    // ---------------------------------------------------------------------
    // End-to-end synthetic-container test for the V1 (refc) read path.
    //
    // The V1 `TNimType` + `TNimNode` field/enum recovery cannot be exercised
    // by the bundled fixtures: on Mach-O the globals land in `__DATA,__common`
    // (no file backing, RESEARCH.md §3.6) and the only ELF fixture is V2-only.
    // So we hand-build a tiny 64-bit container holding one object type with two
    // named fields and one enum type with two values, and assert `build`
    // recovers members, offsets, and ordinals through the real reader.
    // ---------------------------------------------------------------------

    use crate::container::{self, Arch, Format, Section, SectionKind, Symbol, SymbolKind};
    use std::borrow::Cow;

    fn w64(buf: &mut [u8], off: usize, val: u64) {
        buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
    }
    fn wstr(buf: &mut [u8], off: usize, s: &str) {
        buf[off..off + s.len()].copy_from_slice(s.as_bytes());
    }

    /// Lays out a synthetic 64-bit image. Virtual addresses map 1:1 to file
    /// offsets (image base 0, one section at VA 0 spanning the whole buffer).
    fn synthetic_v1_container() -> Vec<u8> {
        let mut b = vec![0u8; 0x400];

        // Object TNimType @0x40: size=24, align=8, kind=17(Object), node=0x100.
        w64(&mut b, 0x40, 24); // size
        w64(&mut b, 0x48, 8); // align
        b[0x50] = 17; // kind = tyObject
        b[0x51] = 0; // flags
        w64(&mut b, 0x60, 0x100); // node -> object field list

        // Object field list (nkList) @0x100: len=2, sons=0x140.
        b[0x100] = 2; // nkList
        w64(&mut b, 0x120, 2); // len
        w64(&mut b, 0x128, 0x140); // sons
        w64(&mut b, 0x140, 0x160); // sons[0] -> slot "x"
        w64(&mut b, 0x148, 0x1A0); // sons[1] -> slot "y"

        // Field slot "x" (nkSlot) @0x160: offset=0, name=0x300.
        b[0x160] = 1; // nkSlot
        w64(&mut b, 0x168, 0); // offset
        w64(&mut b, 0x178, 0x300); // name -> "x"

        // Field slot "y" (nkSlot) @0x1A0: offset=8, name=0x310.
        b[0x1A0] = 1; // nkSlot
        w64(&mut b, 0x1A8, 8); // offset
        w64(&mut b, 0x1B8, 0x310); // name -> "y"

        // Enum TNimType @0x200: size=1, align=1, kind=14(Enum), node=0x240.
        w64(&mut b, 0x200, 1); // size
        w64(&mut b, 0x208, 1); // align
        b[0x210] = 14; // kind = tyEnum
        w64(&mut b, 0x220, 0x240); // node -> enum value list

        // Enum value list (nkList) @0x240: len=2, sons=0x280.
        b[0x240] = 2; // nkList
        w64(&mut b, 0x260, 2); // len
        w64(&mut b, 0x268, 0x280); // sons
        w64(&mut b, 0x280, 0x2A0); // sons[0] -> "ckRed"
        w64(&mut b, 0x288, 0x2C0); // sons[1] -> "ckBlue"

        // Enum slot "ckRed" @0x2A0: ordinal(offset)=0, name=0x320.
        b[0x2A0] = 1;
        w64(&mut b, 0x2A8, 0); // ordinal
        w64(&mut b, 0x2B8, 0x320); // name -> "ckRed"

        // Enum slot "ckBlue" @0x2C0: ordinal(offset)=7, name=0x330.
        b[0x2C0] = 1;
        w64(&mut b, 0x2C8, 7); // ordinal
        w64(&mut b, 0x2D8, 0x330); // name -> "ckBlue"

        // String pool.
        wstr(&mut b, 0x300, "x");
        wstr(&mut b, 0x310, "y");
        wstr(&mut b, 0x320, "ckRed");
        wstr(&mut b, 0x330, "ckBlue");

        b
    }

    #[test]
    fn build_recovers_v1_fields_and_enum_values() {
        let bytes = synthetic_v1_container();
        let section = Section {
            name: ".data".to_string(),
            vm_addr: 0,
            vm_size: bytes.len() as u64,
            data: &bytes,
            kind: SectionKind::Data,
        };
        let symbols = vec![
            Symbol {
                name: Cow::Borrowed("NTIobjtype__deadbeef_"),
                vm_addr: 0x40,
                size: 0,
                kind: SymbolKind::Object,
            },
            Symbol {
                name: Cow::Borrowed("NTImyenum__cafef00d_"),
                vm_addr: 0x200,
                size: 0,
                kind: SymbolKind::Object,
            },
        ];
        let container =
            container::assemble(&bytes, Format::Elf, Arch::Amd64, 0, vec![section], symbols);

        let types = build(&container);
        assert_eq!(types.len(), 2);

        let obj = types
            .iter()
            .find(|t| t.symbol_name.starts_with("NTIobjtype"))
            .expect("object type present");
        assert!(obj.is_readable());
        assert_eq!(obj.shape, TypeShape::Object);
        assert_eq!(obj.size, 24);
        assert_eq!(obj.align, 8);
        assert_eq!(obj.kind, Some(NimKind::Object));
        assert_eq!(obj.fields.len(), 2);
        assert_eq!(obj.fields[0].name, "x");
        assert_eq!(obj.fields[0].offset, 0);
        assert_eq!(obj.fields[1].name, "y");
        assert_eq!(obj.fields[1].offset, 8);
        assert!(obj.enum_values.is_empty());

        let en = types
            .iter()
            .find(|t| t.symbol_name.starts_with("NTImyenum"))
            .expect("enum type present");
        assert!(en.is_readable());
        assert_eq!(en.shape, TypeShape::Enum);
        assert_eq!(en.kind, Some(NimKind::Enum));
        assert!(en.fields.is_empty());
        assert_eq!(en.enum_values.len(), 2);
        assert_eq!(en.enum_values[0].name, "ckRed");
        assert_eq!(en.enum_values[0].ordinal, 0);
        assert_eq!(en.enum_values[1].name, "ckBlue");
        assert_eq!(en.enum_values[1].ordinal, 7);
    }
}
