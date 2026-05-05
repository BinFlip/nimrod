//! Low-level byte-reading utilities.
//!
//! Checked little-endian readers and a NUL-terminated C string slicer.
//! These avoid panics and return sensible defaults (zero / empty) when the
//! offset is out of bounds — callers use them during best-effort scans of
//! binary data where out-of-range reads are expected.

#![allow(dead_code)] // wired up in M1+

#[inline(always)]
pub(crate) fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    read_array::<2>(data, offset)
        .map(u16::from_le_bytes)
        .unwrap_or(0)
}

#[inline(always)]
pub(crate) fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    read_array::<4>(data, offset)
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}

#[inline(always)]
pub(crate) fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    read_array::<8>(data, offset)
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

#[inline(always)]
pub(crate) fn read_i16_le(data: &[u8], offset: usize) -> i16 {
    read_array::<2>(data, offset)
        .map(i16::from_le_bytes)
        .unwrap_or(0)
}

#[inline(always)]
fn read_array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let slice = data.get(offset..end)?;
    slice.try_into().ok()
}

/// Returns the NUL-terminated byte slice starting at `offset`, excluding the
/// NUL byte. Returns `None` if no NUL is found within `max_len` bytes or the
/// offset is out of range.
pub(crate) fn slice_cstring(data: &[u8], offset: usize, max_len: usize) -> Option<&[u8]> {
    let end = offset.checked_add(max_len)?.min(data.len());
    let slice = data.get(offset..end)?;
    let nul = memchr::memchr(0, slice)?;
    slice.get(..nul)
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
