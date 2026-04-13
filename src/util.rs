//! Low-level byte-reading utilities.
//!
//! Checked little-endian readers and a NUL-terminated C string slicer.
//! These avoid panics and return sensible defaults (zero / empty) when the
//! offset is out of bounds — callers use them during best-effort scans of
//! binary data where out-of-range reads are expected.

#![allow(dead_code)] // wired up in M1+

#[inline(always)]
pub(crate) fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

#[inline(always)]
pub(crate) fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

#[inline(always)]
pub(crate) fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    data.get(offset..offset + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .unwrap_or(0)
}

#[inline(always)]
pub(crate) fn read_i16_le(data: &[u8], offset: usize) -> i16 {
    data.get(offset..offset + 2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

/// Returns the NUL-terminated byte slice starting at `offset`, excluding the
/// NUL byte. Returns `None` if no NUL is found within `max_len` bytes or the
/// offset is out of range.
pub(crate) fn slice_cstring(data: &[u8], offset: usize, max_len: usize) -> Option<&[u8]> {
    let end = offset.checked_add(max_len)?.min(data.len());
    let slice = data.get(offset..end)?;
    let nul = memchr::memchr(0, slice)?;
    Some(&slice[..nul])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u16_le() {
        assert_eq!(read_u16_le(&[0x34, 0x12], 0), 0x1234);
    }

    #[test]
    fn u32_le() {
        assert_eq!(read_u32_le(&[0x78, 0x56, 0x34, 0x12], 0), 0x12345678);
    }

    #[test]
    fn u64_le() {
        let b = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        assert_eq!(read_u64_le(&b, 0), 0x0102030405060708);
    }

    #[test]
    fn i16_le_negative() {
        assert_eq!(read_i16_le(&[0xFF, 0xFF], 0), -1);
    }

    #[test]
    fn out_of_bounds_reads_return_zero() {
        assert_eq!(read_u16_le(&[0x00], 0), 0);
        assert_eq!(read_u32_le(&[0x00, 0x01, 0x02], 0), 0);
        assert_eq!(read_u64_le(&[0; 4], 0), 0);
    }

    #[test]
    fn cstring_basic() {
        let data = b"hello\0world";
        assert_eq!(slice_cstring(data, 0, 32), Some(&b"hello"[..]));
    }

    #[test]
    fn cstring_offset() {
        let data = b"hello\0world\0";
        assert_eq!(slice_cstring(data, 6, 32), Some(&b"world"[..]));
    }

    #[test]
    fn cstring_no_nul_within_budget() {
        let data = b"hello";
        assert_eq!(slice_cstring(data, 0, 32), None);
    }

    #[test]
    fn cstring_max_len_limits_scan() {
        let data = b"hello\0world";
        // Budget of 3 from offset 0 never reaches the NUL.
        assert_eq!(slice_cstring(data, 0, 3), None);
    }

    #[test]
    fn cstring_offset_out_of_range() {
        let data = b"hello";
        assert_eq!(slice_cstring(data, 100, 32), None);
    }
}
