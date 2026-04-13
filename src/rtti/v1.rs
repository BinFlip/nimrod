//! TNimType (refc GC) reader.
//!
//! Reads all fields of a legacy `TNimType` struct from binary data
//! (RESEARCH.md §3.1). Also walks the `TNimNode` tree to recover field
//! names for object/tuple/enum types.

use crate::{
    container::{Arch, Container},
    rtti::v2::{read_cstring_at_va, read_ptr, va_to_offset},
};

/// `TNimKind` — mirrors `ast.TTypeKind` from `lib/system/hti.nim`.
///
/// Values are the ordinal positions in the enum (0-based). Only the
/// commonly encountered kinds are named; the rest are captured as
/// `Other(u8)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NimKind {
    /// `tyNone` (0)
    None,
    /// `tyBool` (1)
    Bool,
    /// `tyChar` (2)
    Char,
    /// `tyEnum` (14)
    Enum,
    /// `tyArray` (16)
    Array,
    /// `tyObject` (17)
    Object,
    /// `tyTuple` (18)
    Tuple,
    /// `tySet` (19)
    Set,
    /// `tyRange` (20)
    Range,
    /// `tyPtr` (21)
    Ptr,
    /// `tyRef` (22)
    Ref,
    /// `tySequence` (24)
    Sequence,
    /// `tyProc` (25)
    Proc,
    /// `tyPointer` (26)
    Pointer,
    /// `tyString` (28)
    String,
    /// `tyCstring` (29)
    Cstring,
    /// `tyInt` (31)
    Int,
    /// `tyInt8` (32)
    Int8,
    /// `tyInt16` (33)
    Int16,
    /// `tyInt32` (34)
    Int32,
    /// `tyInt64` (35)
    Int64,
    /// `tyFloat` (36)
    Float,
    /// `tyFloat32` (37)
    Float32,
    /// `tyFloat64` (38)
    Float64,
    /// `tyFloat128` (39)
    Float128,
    /// `tyUInt` (40)
    UInt,
    /// `tyUInt8` (41)
    UInt8,
    /// `tyUInt16` (42)
    UInt16,
    /// `tyUInt32` (43)
    UInt32,
    /// `tyUInt64` (44)
    UInt64,
    /// Any other kind not explicitly listed.
    Other(u8),
}

impl NimKind {
    /// Converts a raw ordinal to a `NimKind`.
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::None,
            1 => Self::Bool,
            2 => Self::Char,
            14 => Self::Enum,
            16 => Self::Array,
            17 => Self::Object,
            18 => Self::Tuple,
            19 => Self::Set,
            20 => Self::Range,
            21 => Self::Ptr,
            22 => Self::Ref,
            24 => Self::Sequence,
            25 => Self::Proc,
            26 => Self::Pointer,
            28 => Self::String,
            29 => Self::Cstring,
            31 => Self::Int,
            32 => Self::Int8,
            33 => Self::Int16,
            34 => Self::Int32,
            35 => Self::Int64,
            36 => Self::Float,
            37 => Self::Float32,
            38 => Self::Float64,
            39 => Self::Float128,
            40 => Self::UInt,
            41 => Self::UInt8,
            42 => Self::UInt16,
            43 => Self::UInt32,
            44 => Self::UInt64,
            n => Self::Other(n),
        }
    }
}

/// `TNimTypeFlag` — from `lib/system/hti.nim`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NimTypeFlag {
    /// `ntfNoRefs` (bit 0) — type contains no tyRef/tySequence/tyString.
    NoRefs,
    /// `ntfAcyclic` (bit 1) — type cannot form a cycle.
    Acyclic,
    /// `ntfEnumHole` (bit 2) — enum has holes; `$` needs the slow path.
    EnumHole,
}

/// Parsed fields of a legacy `TNimType` RTTI record.
#[derive(Debug, Clone)]
pub struct TNimTypeFields {
    /// Size of the described type in bytes.
    pub size: u64,
    /// Alignment.
    pub align: u64,
    /// Type kind.
    pub kind: NimKind,
    /// Raw kind byte (for round-tripping when `NimKind::Other`).
    pub kind_raw: u8,
    /// Type flags (raw byte, bits 0–2 are `TNimTypeFlag`).
    pub flags_raw: u8,
    /// Parsed type flags.
    pub flags: Vec<NimTypeFlag>,
    /// Virtual address of `base` (parent type), if non-null.
    pub base_addr: Option<u64>,
    /// Virtual address of the `node` (`TNimNode` tree root), if non-null.
    pub node_addr: Option<u64>,
    /// Virtual address of the `finalizer`, if non-null.
    pub finalizer_addr: Option<u64>,
    /// Virtual address of the `marker` proc, if non-null.
    pub marker_addr: Option<u64>,
    /// Virtual address of the `deepcopy` proc, if non-null.
    pub deepcopy_addr: Option<u64>,
    /// The `name` cstring if present (`nimTypeNames` defined).
    pub name: Option<String>,
    /// Field names recovered by walking the `TNimNode` tree (if the node
    /// pointer was valid and the tree was walkable).
    pub node_fields: Vec<NodeField>,
}

/// A field recovered from the `TNimNode` tree.
#[derive(Debug, Clone)]
pub struct NodeField {
    /// Field name (from the `name: cstring` in `TNimNode`).
    pub name: String,
    /// Byte offset of the field within the parent struct.
    pub offset: u64,
    /// Virtual address of the `TNimType` pointer for this field's type,
    /// if non-null.
    pub type_addr: Option<u64>,
}

/// `TNimNodeKind` — from `lib/system/hti.nim`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeKind {
    None, // 0
    Slot, // 1
    List, // 2
    Case, // 3
}

impl NodeKind {
    fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::None,
            1 => Self::Slot,
            2 => Self::List,
            3 => Self::Case,
            _ => Self::None,
        }
    }
}

/// Reads a `TNimType` struct and optionally walks its `TNimNode` tree.
///
/// The struct layout depends on compile-time flags. We parse the common
/// layout (no `gcHooks`):
///
/// ```text
/// size:      NI
/// align:     NI
/// kind:      u8  (TNimKind)
/// flags:     u8  (set[TNimTypeFlag])
/// <pad to ptr alignment>
/// base:      ptr TNimType
/// node:      ptr TNimNode
/// finalizer: ptr
/// marker:    ptr (proc)
/// deepcopy:  ptr (proc)
/// // conditional fields follow:
/// // typeInfoV2: ptr   (if nimSeqsV2)
/// // name:  cstring    (if nimTypeNames)
/// // nextType: ptr     (if nimTypeNames)
/// // instances: NI     (if nimTypeNames)
/// // sizes: NI         (if nimTypeNames)
/// ```
pub fn read(container: &Container<'_>, va: u64) -> Option<TNimTypeFields> {
    let is_64 = matches!(
        container.arch(),
        Arch::Amd64 | Arch::Aarch64 | Arch::PowerPc64 | Arch::Riscv64
    );
    let ptr_size: usize = if is_64 { 8 } else { 4 };

    let bytes = container.bytes();
    let offset = va_to_offset(container, va)?;

    // Need at least: size + align + kind + flags + pad + 5 pointers
    let min = ptr_size * 7 + 2;
    if offset + min > bytes.len() {
        return None;
    }

    let mut pos = offset;

    let size = read_ptr(bytes, pos, is_64);
    pos += ptr_size;

    let align = read_ptr(bytes, pos, is_64);
    pos += ptr_size;

    let kind_raw = bytes.get(pos).copied().unwrap_or(0);
    pos += 1;

    let flags_raw = bytes.get(pos).copied().unwrap_or(0);
    pos += 1;

    // Padding to pointer alignment.
    let misalign = (pos - offset) % ptr_size;
    if misalign != 0 {
        pos += ptr_size - misalign;
    }

    let base = read_ptr(bytes, pos, is_64);
    pos += ptr_size;

    let node = read_ptr(bytes, pos, is_64);
    pos += ptr_size;

    let finalizer = read_ptr(bytes, pos, is_64);
    pos += ptr_size;

    let marker = read_ptr(bytes, pos, is_64);
    pos += ptr_size;

    let deepcopy = read_ptr(bytes, pos, is_64);
    pos += ptr_size;

    // Try to find the `name` cstring. There may be a `typeInfoV2` pointer
    // first (if nimSeqsV2 is defined). We probe both positions.
    let name = try_read_name(container, bytes, pos, is_64)
        .or_else(|| try_read_name(container, bytes, pos + ptr_size, is_64));

    // Parse flags.
    let mut flags = Vec::new();
    if flags_raw & (1 << 0) != 0 {
        flags.push(NimTypeFlag::NoRefs);
    }
    if flags_raw & (1 << 1) != 0 {
        flags.push(NimTypeFlag::Acyclic);
    }
    if flags_raw & (1 << 2) != 0 {
        flags.push(NimTypeFlag::EnumHole);
    }

    // Walk the TNimNode tree for field names.
    let node_fields = if node != 0 {
        walk_node_tree(container, bytes, node, is_64, ptr_size, 0)
    } else {
        Vec::new()
    };

    Some(TNimTypeFields {
        size,
        align,
        kind: NimKind::from_raw(kind_raw),
        kind_raw,
        flags_raw,
        flags,
        base_addr: if base != 0 { Some(base) } else { None },
        node_addr: if node != 0 { Some(node) } else { None },
        finalizer_addr: if finalizer != 0 {
            Some(finalizer)
        } else {
            None
        },
        marker_addr: if marker != 0 { Some(marker) } else { None },
        deepcopy_addr: if deepcopy != 0 { Some(deepcopy) } else { None },
        name,
        node_fields,
    })
}

fn try_read_name(
    container: &Container<'_>,
    bytes: &[u8],
    pos: usize,
    is_64: bool,
) -> Option<String> {
    let name_ptr = read_ptr(bytes, pos, is_64);
    let name = read_cstring_at_va(container, bytes, name_ptr)?;
    // Basic validation: type names should be printable ASCII.
    if name.bytes().all(|b| (0x20..0x7F).contains(&b)) && !name.is_empty() {
        Some(name)
    } else {
        None
    }
}

/// Recursively walks a `TNimNode` tree, collecting field entries.
///
/// `TNimNode` layout:
/// ```text
/// kind:   u8 (TNimNodeKind: 0=nkNone, 1=nkSlot, 2=nkList, 3=nkCase)
/// <pad>
/// offset: NI
/// typ:    ptr TNimType
/// name:   cstring
/// len:    NI
/// sons:   ptr array[0x7fff, ptr TNimNode]
/// ```
fn walk_node_tree(
    container: &Container<'_>,
    bytes: &[u8],
    node_va: u64,
    is_64: bool,
    ptr_size: usize,
    depth: usize,
) -> Vec<NodeField> {
    // Guard against infinite recursion on malformed data.
    if depth > 16 {
        return Vec::new();
    }

    let Some(off) = va_to_offset(container, node_va) else {
        return Vec::new();
    };

    // Minimum node size: kind(1) + pad + offset + typ + name + len + sons
    let min = ptr_size * 5 + 1;
    if off + min > bytes.len() {
        return Vec::new();
    }

    let mut pos = off;

    let kind_raw = bytes.get(pos).copied().unwrap_or(0);
    let kind = NodeKind::from_raw(kind_raw);
    pos += 1;

    // Pad to pointer alignment.
    let misalign = (pos - off) % ptr_size;
    if misalign != 0 {
        pos += ptr_size - misalign;
    }

    let field_offset = read_ptr(bytes, pos, is_64);
    pos += ptr_size;

    let typ = read_ptr(bytes, pos, is_64);
    pos += ptr_size;

    let name_ptr = read_ptr(bytes, pos, is_64);
    pos += ptr_size;

    let len = read_ptr(bytes, pos, is_64) as usize;
    pos += ptr_size;

    let sons_ptr = read_ptr(bytes, pos, is_64);

    let mut result = Vec::new();

    match kind {
        NodeKind::Slot => {
            // A single field.
            if let Some(name) = read_cstring_at_va(container, bytes, name_ptr) {
                result.push(NodeField {
                    name,
                    offset: field_offset,
                    type_addr: if typ != 0 { Some(typ) } else { None },
                });
            }
        }
        NodeKind::List => {
            // A list of child nodes. `len` is the count, `sons` points to
            // an array of `len` pointers to TNimNode.
            if sons_ptr != 0 && len > 0 && len <= 4096 {
                if let Some(sons_off) = va_to_offset(container, sons_ptr) {
                    for i in 0..len {
                        let child_ptr_off = sons_off + i * ptr_size;
                        let child_va = read_ptr(bytes, child_ptr_off, is_64);
                        if child_va != 0 {
                            let child_fields = walk_node_tree(
                                container,
                                bytes,
                                child_va,
                                is_64,
                                ptr_size,
                                depth + 1,
                            );
                            result.extend(child_fields);
                        }
                    }
                }
            }
        }
        NodeKind::Case => {
            // A variant/case node. The `sons` array contains branches.
            // We walk all branches to collect all possible fields.
            if sons_ptr != 0 && len > 0 && len <= 4096 {
                if let Some(sons_off) = va_to_offset(container, sons_ptr) {
                    for i in 0..len {
                        let child_ptr_off = sons_off + i * ptr_size;
                        let child_va = read_ptr(bytes, child_ptr_off, is_64);
                        if child_va != 0 {
                            let child_fields = walk_node_tree(
                                container,
                                bytes,
                                child_va,
                                is_64,
                                ptr_size,
                                depth + 1,
                            );
                            result.extend(child_fields);
                        }
                    }
                }
            }
        }
        NodeKind::None => {}
    }

    result
}
