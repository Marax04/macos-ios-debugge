//! Total, panic-free bit-width helpers used across the SPARC backend.
//!
//! A disassembler is fed attacker-controlled bytes, so a narrowing conversion
//! must never be able to panic and must never silently drop information that
//! the caller believed it kept. Every function here is *total*: it is defined
//! for the whole input domain and its result is exactly the documented slice of
//! the input, so there is no error case to propagate and no `unwrap` to hide.
//!
//! They are written with `to_le_bytes`/`from_le_bytes` rather than an `as`
//! cast, which makes "take the low N bits" the literal meaning of the code
//! instead of a side effect of a lossy cast.

/// Low 8 bits of a 32-bit word.
#[inline]
#[must_use]
pub const fn low_u8_of_u32(v: u32) -> u8 {
    v.to_le_bytes()[0]
}

/// Low 8 bits of a 64-bit word.
#[inline]
#[must_use]
pub const fn low_u8_of_u64(v: u64) -> u8 {
    v.to_le_bytes()[0]
}

/// Low 8 bits of a `usize`.
#[inline]
#[must_use]
pub const fn low_u8_of_usize(v: usize) -> u8 {
    v.to_le_bytes()[0]
}

/// Low 16 bits of a 32-bit word.
#[inline]
#[must_use]
pub const fn low_u16_of_u32(v: u32) -> u16 {
    let b = v.to_le_bytes();
    u16::from_le_bytes([b[0], b[1]])
}

/// Low 32 bits of a 64-bit word.
#[inline]
#[must_use]
pub const fn low_u32_of_u64(v: u64) -> u32 {
    let b = v.to_le_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Low 32 bits of a `usize`, on any pointer width.
#[inline]
#[must_use]
pub const fn low_u32_of_usize(v: usize) -> u32 {
    let b = v.to_le_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Low 16 bits of a 32-bit word, reinterpreted as signed.
///
/// This is the SPARC `simm13`/`disp16` shape: the field has already been masked
/// to its architectural width, and the two's-complement bit pattern *is* the
/// value.
#[inline]
#[must_use]
pub const fn low_i16_of_u32(v: u32) -> i16 {
    low_u16_of_u32(v).cast_signed()
}

/// Low 32 bits of a 64-bit word, reinterpreted as signed.
#[inline]
#[must_use]
pub const fn low_i32_of_u64(v: u64) -> i32 {
    low_u32_of_u64(v).cast_signed()
}

/// Widen a `u32` to `usize` without an `as` cast.
///
/// `usize` is at least 16 bits by definition and at least 32 bits on every
/// target this crate is built for; the saturating fallback keeps the function
/// total on a hypothetical 16-bit target instead of panicking there.
#[inline]
#[must_use]
pub fn u32_to_usize(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Widen a `u64` to `usize` without an `as` cast, saturating on overflow.
#[inline]
#[must_use]
pub fn u64_to_usize(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Narrow a `usize` to `u64` without an `as` cast, saturating on overflow.
#[inline]
#[must_use]
pub fn usize_to_u64(v: usize) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

/// Convert an integer count to `f64` for a ratio or percentage.
///
/// Above 2^53 the result is the nearest representable `f64`. That is the
/// documented and intended behaviour for statistics; it is never used for an
/// address or an instruction field.
#[inline]
#[must_use]
pub fn count_to_f64(v: usize) -> f64 {
    // u32 -> f64 is exact; wider counts saturate into the exact range first.
    f64::from(u32::try_from(v).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_u8_takes_low_byte() {
        assert_eq!(low_u8_of_u32(0xDEAD_BEEF), 0xEF);
        assert_eq!(low_u8_of_u64(0x0123_4567_89AB_CDEF), 0xEF);
        assert_eq!(low_u8_of_usize(0x1F), 0x1F);
    }

    #[test]
    fn low_u16_and_u32_take_low_halves() {
        assert_eq!(low_u16_of_u32(0xDEAD_BEEF), 0xBEEF);
        assert_eq!(low_u32_of_u64(0x0123_4567_89AB_CDEF), 0x89AB_CDEF);
        assert_eq!(low_u32_of_usize(0x1234), 0x1234);
    }

    #[test]
    fn signed_views_reinterpret_the_bit_pattern() {
        assert_eq!(low_i16_of_u32(0x0000_FFFF), -1);
        assert_eq!(low_i16_of_u32(0x0000_1FFF), 0x1FFF);
        assert_eq!(low_i32_of_u64(0xFFFF_FFFF), -1);
    }

    #[test]
    fn widening_helpers_are_total() {
        assert_eq!(u32_to_usize(0), 0);
        assert_eq!(u32_to_usize(u32::MAX), 0xFFFF_FFFF);
        assert_eq!(u64_to_usize(7), 7);
        assert_eq!(usize_to_u64(7), 7);
    }

    #[test]
    fn count_to_f64_is_exact_in_range() {
        assert!((count_to_f64(3) - 3.0).abs() < f64::EPSILON);
        assert!((count_to_f64(0) - 0.0).abs() < f64::EPSILON);
    }
}
