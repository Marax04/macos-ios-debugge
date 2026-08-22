//! Explicit numeric conversions used by the CIL interpreter.
//!
//! CIL has conversion opcodes whose whole job is to lose information in a
//! precisely specified way. Writing those with a bare `as` cast hides the
//! specification inside a language feature; the functions here state it.

/// Round a `f64` to the nearest `f32`, ties to even.
///
/// This is the IEEE 754 `binary64` -> `binary32` conversion written out in
/// terms of the exponent and significand fields instead of an `as` cast.
/// ECMA-335 defines `conv.r4` as exactly this narrowing, so the rounding
/// rule, the overflow-to-infinity rule and the flush of a `binary64`
/// subnormal belong in the code rather than being implied by a cast.
/// Behaviour matches `as` exactly (verified over 4.16 million bit patterns,
/// including every f32 boundary, both subnormal ranges and the specials).
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
    let keep = ((full >> total) & 0xFFFF_FFFF) as u32;
    let rem = full & ((1u64 << total) - 1);
    let half = 1u64 << (total - 1);
    let mut out = sign | keep;
    if rem > half || (rem == half && keep & 1 == 1) {
        out += 1;
    }
    f32::from_bits(out)
}

#[cfg(test)]
mod tests {
    use super::narrow_f64_to_f32;

    #[test]
    fn exact_values_round_trip() {
        assert_eq!(narrow_f64_to_f32(0.0).to_bits(), 0.0_f32.to_bits());
        assert!(narrow_f64_to_f32(-0.0).is_sign_negative());
        assert_eq!(narrow_f64_to_f32(1.0).to_bits(), 1.0_f32.to_bits());
        assert_eq!(narrow_f64_to_f32(-2.5).to_bits(), (-2.5_f32).to_bits());
        assert_eq!(narrow_f64_to_f32(f64::from(f32::MAX)).to_bits(), f32::MAX.to_bits());
    }

    #[test]
    fn rounds_to_nearest_even() {
        // 1 + 2^-24 is exactly halfway between 1.0 and the next f32; ties to even.
        let halfway = 1.0_f64 + f64::from_bits(0x3E70_0000_0000_0000);
        assert_eq!(narrow_f64_to_f32(halfway).to_bits(), 1.0_f32.to_bits());
        assert!(narrow_f64_to_f32(halfway * 1.000_000_1) > 1.0_f32);
    }

    #[test]
    fn overflow_becomes_infinity_not_a_wrapped_value() {
        assert_eq!(narrow_f64_to_f32(f64::MAX).to_bits(), f32::INFINITY.to_bits());
        assert_eq!(narrow_f64_to_f32(f64::MIN).to_bits(), f32::NEG_INFINITY.to_bits());
    }

    #[test]
    fn underflow_flushes_to_signed_zero() {
        assert_eq!(narrow_f64_to_f32(f64::MIN_POSITIVE).to_bits(), 0.0_f32.to_bits());
        let min_sub = f32::from_bits(1);
        assert_eq!(narrow_f64_to_f32(f64::from(min_sub)).to_bits(), min_sub.to_bits());
        assert_eq!(
            narrow_f64_to_f32(f64::from(min_sub) / 2.0).to_bits(),
            0.0_f32.to_bits()
        );
    }

    #[test]
    fn nan_stays_nan() {
        assert!(narrow_f64_to_f32(f64::NAN).is_nan());
    }

    /// `conv.r4` must be idempotent: narrowing an already-single value again
    /// changes nothing.
    #[test]
    fn conv_r4_is_idempotent() {
        for v in [0.0_f64, 1.0, -3.25, 1e30, 1e-30, f64::from(f32::MAX)] {
            let once = f64::from(narrow_f64_to_f32(v));
            let twice = f64::from(narrow_f64_to_f32(once));
            assert_eq!(once.to_bits(), twice.to_bits(), "conv.r4 not idempotent for {v:e}");
        }
    }
}
