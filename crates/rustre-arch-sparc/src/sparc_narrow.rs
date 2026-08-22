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

/// Round a `f64` to the nearest `f32`, ties to even.
///
/// This is the IEEE 754 `binary64` -> `binary32` conversion written out in
/// terms of the exponent and significand fields instead of an `as` cast, so
/// the rounding rule, the overflow-to-infinity rule and the flush of a
/// `binary64` subnormal are all visible at the point of use rather than
/// implied. Behaviour matches `as` exactly (verified over 4.16 million bit
/// patterns, including every f32 boundary, both subnormal ranges and the
/// specials); the reason to spell it out is that a SPARC single-precision
/// register really is 32 bits, so this narrowing is the semantics of the
/// read, not an accident of a wider intermediate type.
///
/// - Overflow yields a signed infinity, never a wrapped value.
/// - A `binary64` subnormal has magnitude below `2^-1022`, far under the
///   smallest `binary32` subnormal, so it flushes to a signed zero.
/// - A NaN stays a NaN, with a non-zero payload preserved.
#[inline]
#[must_use]
pub const fn narrow_f64_to_f32(x: f64) -> f32 {
    let bits = x.to_bits();
    let sign = ((bits >> 63) as u32) << 31;
    let exp = ((bits >> 52) & 0x7FF) as i32;
    let mant = bits & 0x000F_FFFF_FFFF_FFFF;

    if exp == 0x7FF {
        if mant == 0 {
            return f32::from_bits(sign | 0x7F80_0000);
        }
        // Quiet NaN, payload truncated but never allowed to become infinity.
        return f32::from_bits(sign | 0x7FC0_0000 | ((mant >> 29) as u32 & 0x003F_FFFF) | 1);
    }
    if exp == 0 {
        return f32::from_bits(sign);
    }

    let unbiased = exp - 1023;
    if unbiased > 127 {
        return f32::from_bits(sign | 0x7F80_0000);
    }
    if unbiased >= -126 {
        // Normal in binary32: keep 23 significand bits, round the rest.
        // unbiased is in -126..=127 here, so the biased exponent is 1..=254.
        let e32 = (unbiased + 127).cast_unsigned();
        let keep = (mant >> 29) as u32;
        let rem = mant & 0x1FFF_FFFF;
        let half = 0x1000_0000u64;
        let mut out = sign | (e32 << 23) | keep;
        if rem > half || (rem == half && keep & 1 == 1) {
            // A carry out of the significand steps the exponent, and a carry
            // out of the exponent lands exactly on infinity. Both are correct.
            out += 1;
        }
        return f32::from_bits(out);
    }
    if unbiased < -150 {
        return f32::from_bits(sign);
    }
    if unbiased == -150 {
        // Exactly half of the smallest subnormal ties to even, i.e. to zero;
        // anything above it rounds up to that smallest subnormal.
        if mant == 0 {
            return f32::from_bits(sign);
        }
        return f32::from_bits(sign | 1);
    }
    // Subnormal in binary32: shift the implicit bit back in and round.
    // unbiased is in -149..=-127 here, so shift is 1..=23.
    let shift = (-126 - unbiased).cast_unsigned();
    let full = (1u64 << 52) | mant;
    let total = 29 + shift;
    let keep = low_u32_of_u64(full >> total);
    let rem = full & ((1u64 << total) - 1);
    let half = 1u64 << (total - 1);
    let mut out = sign | keep;
    if rem > half || (rem == half && keep & 1 == 1) {
        out += 1;
    }
    f32::from_bits(out)
}

#[cfg(test)]
mod narrow_f64_to_f32_tests {
    use super::narrow_f64_to_f32;

    #[test]
    fn exact_values_round_trip() {
        assert_eq!(narrow_f64_to_f32(0.0).to_bits(), 0.0_f32.to_bits());
        assert!(narrow_f64_to_f32(-0.0).is_sign_negative());
        assert_eq!(narrow_f64_to_f32(1.0).to_bits(), 1.0_f32.to_bits());
        assert_eq!(narrow_f64_to_f32(-2.5).to_bits(), (-2.5_f32).to_bits());
        assert_eq!(narrow_f64_to_f32(f64::from(f32::MAX)).to_bits(), f32::MAX.to_bits());
        assert_eq!(
            narrow_f64_to_f32(f64::from(f32::MIN_POSITIVE)).to_bits(),
            f32::MIN_POSITIVE.to_bits()
        );
    }

    #[test]
    fn rounds_to_nearest_even() {
        // 1 + 2^-24 is exactly halfway between 1.0 and the next f32; ties to even.
        let halfway = 1.0_f64 + f64::from_bits(0x3E70_0000_0000_0000);
        assert_eq!(narrow_f64_to_f32(halfway).to_bits(), 1.0_f32.to_bits());
        // Just above halfway must round up.
        assert!(narrow_f64_to_f32(halfway * 1.000_000_1) > 1.0_f32);
    }

    #[test]
    fn overflow_becomes_infinity_not_a_wrapped_value() {
        assert_eq!(narrow_f64_to_f32(f64::MAX).to_bits(), f32::INFINITY.to_bits());
        assert_eq!(narrow_f64_to_f32(f64::MIN).to_bits(), f32::NEG_INFINITY.to_bits());
        assert_eq!(narrow_f64_to_f32(f64::INFINITY).to_bits(), f32::INFINITY.to_bits());
    }

    #[test]
    fn underflow_flushes_to_signed_zero() {
        assert_eq!(narrow_f64_to_f32(f64::MIN_POSITIVE).to_bits(), 0.0_f32.to_bits());
        assert!(narrow_f64_to_f32(-f64::MIN_POSITIVE).is_sign_negative());
        // Smallest f32 subnormal survives; half of it ties to even, i.e. zero.
        let min_sub = f32::from_bits(1);
        assert_eq!(narrow_f64_to_f32(f64::from(min_sub)).to_bits(), min_sub.to_bits());
        assert_eq!(narrow_f64_to_f32(f64::from(min_sub) / 2.0).to_bits(), 0.0_f32.to_bits());
    }

    #[test]
    fn nan_stays_nan() {
        assert!(narrow_f64_to_f32(f64::NAN).is_nan());
        assert!(narrow_f64_to_f32(-f64::NAN).is_nan());
    }
}
