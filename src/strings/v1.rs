//! V1 string literal scanner (refc builds).
//!
//! Legacy Nim strings use an inline layout (RESEARCH.md §4.3):
//!
//! ```text
//! NimStringDesc {
//!     len:      NI,    // string length
//!     reserved: NI,    // capacity; strlitFlag in bit 62/30 for literals
//!     data:     [char] // NUL-terminated
//! }
//! ```
//!
//! We scan rodata for `(len, reserved)` pairs where `reserved` has the
//! `strlitFlag` set and `len <= reserved & ~flag`, then validate the
//! trailing data. This is less reliable than V2 scanning because the
//! two-word header is less distinctive.

use crate::{
    container::{Arch, Container, SectionKind},
    util,
};

/// `strlitFlag` on 64-bit.
const STRLIT_FLAG_64: u64 = 1 << 62;

/// `strlitFlag` on 32-bit.
const STRLIT_FLAG_32: u32 = 1 << 30;

/// A recovered V1 string literal.
///
/// `header_addr` is a virtual address (image load space). To convert
/// to an RVA, subtract [`crate::NimBinary::image_base`] or use
/// [`crate::container::Container::va_to_rva`].
#[derive(Debug, Clone)]
pub struct StringLiteralV1 {
    /// The literal content.
    pub value: String,
    /// Virtual address of the NimStringDesc header (image load space,
    /// not file offset).
    pub header_addr: u64,
}

/// Scans read-only sections for V1 `NimStringDesc` literals.
pub fn scan(container: &Container<'_>) -> Vec<StringLiteralV1> {
    let is_64 = matches!(
        container.arch(),
        Arch::Amd64 | Arch::Aarch64 | Arch::PowerPc64 | Arch::Riscv64
    );

    let mut result = Vec::new();

    for section in container.sections() {
        if section.kind != SectionKind::RoData {
            continue;
        }
        if section.data.is_empty() {
            continue;
        }

        if is_64 {
            scan_section_64(section.data, section.vm_addr, &mut result);
        } else {
            scan_section_32(section.data, section.vm_addr, &mut result);
        }
    }

    result.sort_by_key(|s| s.header_addr);
    result
}

fn scan_section_64(data: &[u8], base_va: u64, out: &mut Vec<StringLiteralV1>) {
    let word_size: usize = 8;
    let header_size = word_size.saturating_mul(2);
    if data.len() < header_size {
        return;
    }

    let mut offset: usize = 0;
    while offset.saturating_add(header_size) <= data.len() {
        let len = util::read_u64_le(data, offset) as usize;
        let reserved = util::read_u64_le(data, offset.saturating_add(word_size));

        if reserved & STRLIT_FLAG_64 != 0 {
            let cap = (reserved & !STRLIT_FLAG_64) as usize;

            if len <= cap && cap < 1_000_000 {
                let Some(data_start) = offset.checked_add(header_size) else {
                    break;
                };
                let Some(data_end) = data_start.checked_add(len) else {
                    offset = offset.saturating_add(word_size);
                    continue;
                };

                if data_end < data.len()
                    && data.get(data_end).copied() == Some(0)
                    && let Some(payload) = data.get(data_start..data_end)
                    && let Ok(s) = std::str::from_utf8(payload)
                {
                    out.push(StringLiteralV1 {
                        value: s.to_owned(),
                        header_addr: base_va.wrapping_add(offset as u64),
                    });

                    if let Some(after_nul) = cap.checked_add(1)
                        && let Some(next) = data_start.checked_add(after_nul)
                    {
                        let rem = next % word_size;
                        offset = if rem != 0 {
                            next.saturating_add(word_size.saturating_sub(rem))
                        } else {
                            next
                        };
                        continue;
                    }
                }
            }
        }

        offset = offset.saturating_add(word_size);
    }
}

fn scan_section_32(data: &[u8], base_va: u64, out: &mut Vec<StringLiteralV1>) {
    let word_size: usize = 4;
    let header_size = word_size.saturating_mul(2);
    if data.len() < header_size {
        return;
    }

    let mut offset: usize = 0;
    while offset.saturating_add(header_size) <= data.len() {
        let len = util::read_u32_le(data, offset) as usize;
        let reserved = util::read_u32_le(data, offset.saturating_add(word_size));

        if reserved & STRLIT_FLAG_32 != 0 {
            let cap = (reserved & !STRLIT_FLAG_32) as usize;

            if len <= cap && cap < 1_000_000 {
                let Some(data_start) = offset.checked_add(header_size) else {
                    break;
                };
                let Some(data_end) = data_start.checked_add(len) else {
                    offset = offset.saturating_add(word_size);
                    continue;
                };

                if data_end < data.len()
                    && data.get(data_end).copied() == Some(0)
                    && let Some(payload) = data.get(data_start..data_end)
                    && let Ok(s) = std::str::from_utf8(payload)
                {
                    out.push(StringLiteralV1 {
                        value: s.to_owned(),
                        header_addr: base_va.wrapping_add(offset as u64),
                    });

                    if let Some(after_nul) = cap.checked_add(1)
                        && let Some(next) = data_start.checked_add(after_nul)
                    {
                        let rem = next % word_size;
                        offset = if rem != 0 {
                            next.saturating_add(word_size.saturating_sub(rem))
                        } else {
                            next
                        };
                        continue;
                    }
                }
            }
        }

        offset = offset.saturating_add(word_size);
    }
}
