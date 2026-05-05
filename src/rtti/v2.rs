//! TNimTypeV2 (ARC/ORC) reader.
//!
//! Reads the fields of a `TNimTypeV2` struct from binary data at a given
//! virtual address. The struct layout is fixed (RESEARCH.md §3.2):
//!
//! ```text
//! struct TNimTypeV2 {
//!     void*   destructor;    // ptr
//!     int     size;          // NI (pointer-sized int)
//!     int16   align;         // NI16
//!     int16   depth;         // NI16
//!     void*   display;       // ptr to UncheckedArray[uint32]
//!     char*   name;          // cstring (conditional on nimTypeNames)
//!     void*   traceImpl;     // ptr
//!     void*   typeInfoV1;    // ptr (usually nil)
//!     int     flags;         // NI
//! };
//! ```

use crate::{
    container::{Arch, Container},
    util,
};

/// Parsed fields of a `TNimTypeV2` RTTI record.
#[derive(Debug, Clone)]
pub struct TNimTypeV2Fields {
    /// Size of the described type in bytes.
    pub size: u64,
    /// Alignment in bytes.
    pub align: i16,
    /// Depth in the type inheritance hierarchy.
    pub depth: i16,
    /// Type flags (raw integer from the binary).
    pub flags: u64,
    /// The `name` cstring if present and decodable. Only populated when
    /// the binary was compiled with `nimTypeNames` (the default for debug
    /// builds, absent in release).
    pub name: Option<String>,
    /// Virtual address of the destructor, if non-null.
    pub destructor_addr: Option<u64>,
    /// Virtual address of the `display` (class-token array), if non-null.
    pub display_addr: Option<u64>,
    /// Virtual address of `traceImpl` (cycle-collector trace proc), if
    /// non-null.
    pub trace_impl_addr: Option<u64>,
    /// Virtual address of `typeInfoV1` (backwards-compat pointer to legacy
    /// RTTI), if non-null. Usually nil.
    pub type_info_v1_addr: Option<u64>,
}

/// Reads a `TNimTypeV2` struct from the container at the given virtual
/// address.
///
/// The `name` field is conditional on `nimTypeNames` (present in debug
/// builds, absent in release). We try the with-name layout first; if
/// the name pointer doesn't resolve to a valid cstring, we fall back
/// to the without-name layout.
///
/// Returns `None` if the address cannot be mapped to file bytes or the
/// data is too short.
pub fn read(container: &Container<'_>, va: u64) -> Option<TNimTypeV2Fields> {
    let is_64 = is_64bit(container);
    let ptr_size: usize = if is_64 { 8 } else { 4 };

    let bytes = container.bytes();
    let offset = va_to_offset(container, va)?;

    let min_size = ptr_size.saturating_mul(6).saturating_add(4); // without name field
    if offset.checked_add(min_size)? > bytes.len() {
        return None;
    }

    let mut pos = offset;

    let destructor = read_ptr(bytes, pos, is_64);
    pos = pos.saturating_add(ptr_size);

    let size = read_ptr(bytes, pos, is_64);
    pos = pos.saturating_add(ptr_size);

    let align = util::read_i16_le(bytes, pos);
    pos = pos.saturating_add(2);

    let depth = util::read_i16_le(bytes, pos);
    pos = pos.saturating_add(2);

    // Padding to pointer alignment after two i16s.
    if is_64 {
        pos = pos.saturating_add(4);
    }

    let display = read_ptr(bytes, pos, is_64);
    pos = pos.saturating_add(ptr_size);

    // Try the with-name layout first. If the pointer at this position
    // resolves to a valid cstring, the name field is present.
    let candidate_name_ptr = read_ptr(bytes, pos, is_64);
    let name = read_cstring_at_va(container, bytes, candidate_name_ptr);

    let (trace_impl, type_info_v1, flags) = if name.is_some() {
        // With-name layout: name, traceImpl, typeInfoV1, flags.
        pos = pos.saturating_add(ptr_size); // skip name
        let ti = read_ptr(bytes, pos, is_64);
        pos = pos.saturating_add(ptr_size);
        let tv1 = read_ptr(bytes, pos, is_64);
        pos = pos.saturating_add(ptr_size);
        let fl = read_ptr(bytes, pos, is_64);
        (ti, tv1, fl)
    } else {
        // Without-name layout: traceImpl, typeInfoV1, flags.
        // The pointer we read as candidate_name_ptr is actually traceImpl.
        let ti = candidate_name_ptr;
        pos = pos.saturating_add(ptr_size); // skip traceImpl
        let tv1 = read_ptr(bytes, pos, is_64);
        pos = pos.saturating_add(ptr_size);
        let fl = read_ptr(bytes, pos, is_64);
        (ti, tv1, fl)
    };

    Some(TNimTypeV2Fields {
        size,
        align,
        depth,
        flags,
        name,
        destructor_addr: non_null(destructor),
        display_addr: non_null(display),
        trace_impl_addr: non_null(trace_impl),
        type_info_v1_addr: non_null(type_info_v1),
    })
}

fn non_null(addr: u64) -> Option<u64> {
    if addr != 0 { Some(addr) } else { None }
}

fn is_64bit(container: &Container<'_>) -> bool {
    matches!(
        container.arch(),
        Arch::Amd64 | Arch::Aarch64 | Arch::PowerPc64 | Arch::Riscv64
    )
}

pub(crate) fn read_ptr(data: &[u8], offset: usize, is_64: bool) -> u64 {
    if is_64 {
        util::read_u64_le(data, offset)
    } else {
        u64::from(util::read_u32_le(data, offset))
    }
}

pub(crate) fn read_cstring_at_va(
    container: &Container<'_>,
    bytes: &[u8],
    va: u64,
) -> Option<String> {
    if va == 0 {
        return None;
    }
    let off = va_to_offset(container, va)?;
    let cstr = util::slice_cstring(bytes, off, 256)?;
    std::str::from_utf8(cstr).ok().map(|s| s.to_owned())
}

/// Maps a virtual address to a file offset by searching sections.
pub(crate) fn va_to_offset(container: &Container<'_>, va: u64) -> Option<usize> {
    for section in container.sections() {
        let Some(end) = section.vm_addr.checked_add(section.vm_size) else {
            continue;
        };
        if va >= section.vm_addr && va < end {
            let section_offset = va.wrapping_sub(section.vm_addr) as usize;
            if section_offset < section.data.len() {
                // Recover the absolute offset into `container.bytes()` via
                // pointer arithmetic on the section's data sub-slice.
                let base = section.data.as_ptr() as usize;
                let container_base = container.bytes().as_ptr() as usize;
                if base >= container_base {
                    return Some(
                        base.wrapping_sub(container_base)
                            .wrapping_add(section_offset),
                    );
                }
            }
        }
    }
    None
}
