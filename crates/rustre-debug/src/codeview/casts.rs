//! Lossless / saturating / bit-preserving numeric cast helpers used across
//! the crate.
//!
//! Pedantic clippy bans `as`-casts that can truncate or lose sign. These
//! helpers provide reuse-bit-pattern conversions (`CodeView` records are
//! often documented as "signed reinterpretation of the unsigned field")
//! and saturating narrows for length fields that are bounded in practice
//! but typed as `usize`.

/// Reinterpret a `u8`'s bit pattern as `i8`.
#[inline]
#[must_use]
pub const fn u8_as_i8(x: u8) -> i8 {
    i8::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret a `u16`'s bit pattern as `i16`.
#[inline]
#[must_use]
pub const fn u16_as_i16(x: u16) -> i16 {
    i16::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret a `u32`'s bit pattern as `i32`.
#[inline]
#[must_use]
pub const fn u32_as_i32(x: u32) -> i32 {
    i32::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret a `u64`'s bit pattern as `i64`.
#[inline]
#[must_use]
pub const fn u64_as_i64(x: u64) -> i64 {
    i64::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret an `i8`'s bit pattern as `u8`.
#[inline]
#[must_use]
pub const fn i8_as_u8(x: i8) -> u8 {
    u8::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret an `i16`'s bit pattern as `u16`.
#[inline]
#[must_use]
pub const fn i16_as_u16(x: i16) -> u16 {
    u16::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret an `i32`'s bit pattern as `u32`.
#[inline]
#[must_use]
pub const fn i32_as_u32(x: i32) -> u32 {
    u32::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret an `i64`'s bit pattern as `u64`.
#[inline]
#[must_use]
pub const fn i64_as_u64(x: i64) -> u64 {
    u64::from_ne_bytes(x.to_ne_bytes())
}

/// Sign-extend an `i8` into a `u64` by reinterpreting the resulting `i64`
/// bit pattern.
#[inline]
#[must_use]
pub const fn i8_sext_u64(x: i8) -> u64 {
    i64_as_u64(x as i64)
}

/// Sign-extend an `i16` into a `u64`.
#[inline]
#[must_use]
pub const fn i16_sext_u64(x: i16) -> u64 {
    i64_as_u64(x as i64)
}

/// Sign-extend an `i32` into a `u64`.
#[inline]
#[must_use]
pub const fn i32_sext_u64(x: i32) -> u64 {
    i64_as_u64(x as i64)
}

/// Saturating narrow of `usize` to `u16`.
#[inline]
#[must_use]
pub fn usize_to_u16(x: usize) -> u16 {
    u16::try_from(x).unwrap_or(u16::MAX)
}

/// Saturating narrow of `usize` to `u32`.
#[inline]
#[must_use]
pub fn usize_to_u32(x: usize) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}

/// Saturating, sign-preserving `f32` to `u64`. Negative / NaN -> 0.
#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn f32_to_u64_sat(x: f32) -> u64 {
    // NaN and anything <= 0 floor to 0; +infinity SATURATES to the top.
    // Lumping +inf in with NaN returned 0 for it, which is the opposite
    // end of the range from what a saturating conversion must give and
    // what the `_sat` name promises.
    if x.is_nan() || x <= 0.0 {
        return 0;
    }
    if x == f32::INFINITY {
        return u64::MAX;
    }
    let max_f = 18_446_744_073_709_551_615.0_f32; // saturates beyond f32 precision
    let clamped = x.min(max_f);
    // `clamped` is finite and in [0, f32 representation of u64::MAX],
    // so the safe `as` cast is equivalent to the unchecked conversion.
    clamped as u64
}

/// Saturating, sign-preserving `f64` to `u64`. Negative / NaN -> 0.
#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn f64_to_u64_sat(x: f64) -> u64 {
    // NaN and anything <= 0 floor to 0; +infinity SATURATES to the top.
    // Lumping +inf in with NaN returned 0 for it, which is the opposite
    // end of the range from what a saturating conversion must give and
    // what the `_sat` name promises.
    if x.is_nan() || x <= 0.0 {
        return 0;
    }
    if x == f64::INFINITY {
        return u64::MAX;
    }
    let max_f = 18_446_744_073_709_551_615.0_f64;
    let clamped = x.min(max_f);
    // `clamped` is finite and in [0, f64 representation of u64::MAX],
    // so the safe `as` cast is equivalent to the unchecked conversion.
    clamped as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bit-reinterpreting casts must round-trip and preserve the pattern.
    ///
    /// These feed `read_numeric_leaf`/`read_numeric_leaf_signed`, i.e. array
    /// bounds and enum constants out of a PDB, and had no test at all. A
    /// reinterpretation that quietly clamped instead of reusing the bits would
    /// turn `0xFFFF_FFFF` into `i32::MAX` rather than `-1`.
    #[test]
    fn bit_reinterpretations_preserve_the_pattern_both_ways() {
        assert_eq!(u8_as_i8(0xFF), -1);
        assert_eq!(u16_as_i16(0xFFFF), -1);
        assert_eq!(u32_as_i32(0xFFFF_FFFF), -1);
        assert_eq!(u64_as_i64(u64::MAX), -1);
        assert_eq!(u8_as_i8(0x80), i8::MIN);
        assert_eq!(u32_as_i32(0x8000_0000), i32::MIN);

        for x in [0u8, 1, 0x7F, 0x80, 0xFF] {
            assert_eq!(i8_as_u8(u8_as_i8(x)), x, "u8 round trip for {x:#x}");
        }
        for x in [0u32, 1, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF] {
            assert_eq!(i32_as_u32(u32_as_i32(x)), x, "u32 round trip for {x:#x}");
        }
        assert_eq!(i64_as_u64(u64_as_i64(u64::MAX)), u64::MAX);
        assert_eq!(i16_as_u16(u16_as_i16(0x8000)), 0x8000);
    }

    /// Sign extension must widen the sign, not zero-fill.
    #[test]
    fn sign_extension_widens_the_sign() {
        assert_eq!(i8_sext_u64(-1), u64::MAX);
        assert_eq!(i16_sext_u64(-1), u64::MAX);
        assert_eq!(i32_sext_u64(-1), u64::MAX);
        assert_eq!(i8_sext_u64(-128), 0xFFFF_FFFF_FFFF_FF80);
        assert_eq!(i32_sext_u64(i32::MIN), 0xFFFF_FFFF_8000_0000);
        // Non-negative values must NOT acquire high bits.
        assert_eq!(i8_sext_u64(127), 127);
        assert_eq!(i32_sext_u64(i32::MAX), 0x7FFF_FFFF);
    }

    /// Narrowing saturates at the maximum instead of wrapping.
    #[test]
    fn narrowing_saturates_rather_than_wrapping() {
        assert_eq!(usize_to_u16(0), 0);
        assert_eq!(usize_to_u16(65_535), u16::MAX);
        assert_eq!(usize_to_u16(65_536), u16::MAX, "saturates, never wraps to 0");
        assert_eq!(usize_to_u32(u32::MAX as usize), u32::MAX);
        assert_eq!(usize_to_u32(u32::MAX as usize + 1), u32::MAX);
    }

    /// Float-to-u64 must clamp the whole range, including the ends.
    ///
    /// The clamp constant is written as `18_446_744_073_709_551_615.0`, but
    /// neither `f32` nor `f64` can represent `u64::MAX`: both round it up to
    /// 2^64. The result is still right only because Rust's float-to-int `as`
    /// saturates — worth pinning, since the correctness rests on that and not
    /// on the constant.
    #[test]
    fn float_to_u64_saturates_at_both_ends() {
        assert_eq!(f64_to_u64_sat(f64::NAN), 0);
        assert_eq!(f64_to_u64_sat(f64::NEG_INFINITY), 0);
        assert_eq!(f64_to_u64_sat(f64::INFINITY), u64::MAX, "infinity clamps to the top");
        assert_eq!(f64_to_u64_sat(-1.0), 0);
        assert_eq!(f64_to_u64_sat(-0.0), 0);
        assert_eq!(f64_to_u64_sat(0.0), 0);
        assert_eq!(f64_to_u64_sat(1.9), 1, "truncates toward zero");
        assert_eq!(f64_to_u64_sat(1e30), u64::MAX);
        assert_eq!(f64_to_u64_sat(f64::MAX), u64::MAX);

        assert_eq!(f32_to_u64_sat(f32::NAN), 0);
        assert_eq!(f32_to_u64_sat(f32::INFINITY), u64::MAX);
        assert_eq!(f32_to_u64_sat(-5.0), 0);
        assert_eq!(f32_to_u64_sat(42.7), 42);
        assert_eq!(f32_to_u64_sat(f32::MAX), u64::MAX);
    }
}
