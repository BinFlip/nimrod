//! Address-space helpers.
//!
//! All address fields exposed by nimrod (`vm_addr`, `address`, `call_addr`,
//! `payload_addr`, …) are **virtual addresses** in the input image's load
//! space, not file offsets. Consumers that need an RVA (for cross-tool
//! compatibility with disassemblers that work in image-relative space) can
//! use [`crate::NimBinary::shim_rva`] et al.
//!
//! Consumers that persist VAs into a signed-integer column should use
//! [`va_to_i64`] to guard against the rare adversarial case of a VA above
//! `i64::MAX`.
//!
//! Nimrod itself does not bound VAs below `i64::MAX`; pathological PE
//! image bases or Mach-O segment vmaddrs can in principle place values in
//! the upper half of the `u64` range.

/// Returns the VA as an `i64`, or `None` if it would overflow.
///
/// Use this when persisting nimrod address fields into a signed
/// 64-bit column. Wrapping casts (`va as i64`) silently produce
/// negative values for VAs above `i64::MAX`, which is rare but
/// possible on adversarial input.
#[inline]
pub fn va_to_i64(va: u64) -> Option<i64> {
    if va > i64::MAX as u64 {
        None
    } else {
        Some(va as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_va_round_trips() {
        assert_eq!(va_to_i64(0), Some(0));
        assert_eq!(va_to_i64(0x4000_1000), Some(0x4000_1000));
    }

    #[test]
    fn i64_max_is_inclusive() {
        assert_eq!(va_to_i64(i64::MAX as u64), Some(i64::MAX));
    }

    #[test]
    fn above_i64_max_returns_none() {
        assert_eq!(va_to_i64(i64::MAX as u64 + 1), None);
        assert_eq!(va_to_i64(u64::MAX), None);
    }
}
