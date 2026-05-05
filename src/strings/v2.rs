//! V2 string literal scanner (ARC/ORC builds).
//!
//! Nim V2 string literals are stored in `.rodata` as a two-object pair
//! (RESEARCH.md §4.1, §4.4):
//!
//! 1. **Payload**: `{ cap: NI | NIM_STRLIT_FLAG, data: [cap+1 x u8] }`
//! 2. **Header** : `NimStringV2 { len: NI, payload_ptr: *NimStrPayload }`
//!
//! `NIM_STRLIT_FLAG` is bit 62 on 64-bit systems (`0x4000_0000_0000_0000`)
//! and bit 30 on 32-bit (`0x4000_0000`). We scan rodata for `cap` words
//! with the flag set, then validate the trailing data as a NUL-terminated
//! UTF-8 string whose length matches `cap & ~flag`.

use crate::{
    container::{Arch, Container, SectionKind},
    util,
};

/// `strlitFlag` on 64-bit: `1 << 62`.
const STRLIT_FLAG_64: u64 = 1 << 62;

/// `strlitFlag` on 32-bit: `1 << 30`.
const STRLIT_FLAG_32: u32 = 1 << 30;

/// A recovered V2 string literal.
///
/// `payload_addr` is a virtual address (image load space). To convert
/// to an RVA, subtract [`crate::NimBinary::image_base`] or use
/// [`crate::container::Container::va_to_rva`].
#[derive(Debug, Clone)]
pub struct StringLiteral {
    /// The literal content as a Rust string.
    pub value: String,
    /// Virtual address of the payload in the binary (image load space,
    /// not file offset).
    pub payload_addr: u64,
}

/// Scans read-only sections for V2 `NimStrPayload` literals.
///
/// Returns all string literals found, sorted by address. Empty strings
/// (cap == 0 with the flag set) are included.
pub fn scan(container: &Container<'_>) -> Vec<StringLiteral> {
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

    result.sort_by_key(|s| s.payload_addr);
    result
}

fn scan_section_64(data: &[u8], base_va: u64, out: &mut Vec<StringLiteral>) {
    let word_size = 8;
    if data.len() < word_size {
        return;
    }

    let mut offset: usize = 0;
    while offset.saturating_add(word_size) <= data.len() {
        let raw_cap = util::read_u64_le(data, offset);

        if raw_cap & STRLIT_FLAG_64 != 0 {
            let cap = (raw_cap & !STRLIT_FLAG_64) as usize;
            let Some(data_start) = offset.checked_add(word_size) else {
                break;
            };
            let Some(data_end) = data_start.checked_add(cap) else {
                offset = offset.saturating_add(word_size);
                continue;
            };

            if cap < data.len()
                && data_end < data.len()
                && data.get(data_end).copied() == Some(0)
                && let Some(payload) = data.get(data_start..data_end)
                && let Ok(s) = std::str::from_utf8(payload)
            {
                out.push(StringLiteral {
                    value: s.to_owned(),
                    payload_addr: base_va.wrapping_add(offset as u64),
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

        offset = offset.saturating_add(word_size);
    }
}

fn scan_section_32(data: &[u8], base_va: u64, out: &mut Vec<StringLiteral>) {
    let word_size = 4;
    if data.len() < word_size {
        return;
    }

    let mut offset: usize = 0;
    while offset.saturating_add(word_size) <= data.len() {
        let raw_cap = util::read_u32_le(data, offset);

        if raw_cap & STRLIT_FLAG_32 != 0 {
            let cap = (raw_cap & !STRLIT_FLAG_32) as usize;
            let Some(data_start) = offset.checked_add(word_size) else {
                break;
            };
            let Some(data_end) = data_start.checked_add(cap) else {
                offset = offset.saturating_add(word_size);
                continue;
            };

            if cap < data.len()
                && data_end < data.len()
                && data.get(data_end).copied() == Some(0)
                && let Some(payload) = data.get(data_start..data_end)
                && let Ok(s) = std::str::from_utf8(payload)
            {
                out.push(StringLiteral {
                    value: s.to_owned(),
                    payload_addr: base_va.wrapping_add(offset as u64),
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

        offset = offset.saturating_add(word_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_cap_with_flag_64() {
        let raw: u64 = 5 | STRLIT_FLAG_64;
        assert_eq!(raw & STRLIT_FLAG_64, STRLIT_FLAG_64);
        assert_eq!((raw & !STRLIT_FLAG_64) as usize, 5);
    }

    #[test]
    fn scan_synthetic_payload_64() {
        // Build a synthetic rodata section with one V2 string literal.
        // Layout: cap(8 bytes) | data | NUL
        let mut data = Vec::new();

        let cap: u64 = 5 | STRLIT_FLAG_64;
        data.extend_from_slice(&cap.to_le_bytes());
        data.extend_from_slice(b"hello\0");
        // Pad to 8-byte alignment.
        data.extend_from_slice(&[0; 2]);

        let mut result = Vec::new();
        scan_section_64(&data, 0x1000, &mut result);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "hello");
        assert_eq!(result[0].payload_addr, 0x1000);
    }

    #[test]
    fn scan_rejects_non_utf8() {
        let mut data = Vec::new();
        let cap: u64 = 2 | STRLIT_FLAG_64;
        data.extend_from_slice(&cap.to_le_bytes());
        data.extend_from_slice(&[0xFF, 0xFE, 0x00]); // invalid UTF-8
        data.extend_from_slice(&[0; 5]); // padding

        let mut result = Vec::new();
        scan_section_64(&data, 0x1000, &mut result);
        assert!(result.is_empty());
    }
}
