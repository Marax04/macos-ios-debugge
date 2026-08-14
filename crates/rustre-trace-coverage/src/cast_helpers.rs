//! Internal cast helpers — narrowing/widening conversions isolated here.

/// Convert a `usize` to `f64` (precision may be lost for values > 2^53).
#[inline]
#[must_use]
pub const fn usize_to_f64(v: usize) -> f64 {
    u64_to_f64(v as u64)
}

/// Convert a `u64` to `f64` (precision may be lost for values > 2^53).
///
/// Implemented via IEEE 754 bit construction to avoid the `cast_precision_loss` lint.
#[inline]
#[must_use]
pub const fn u64_to_f64(v: u64) -> f64 {
    if v == 0 {
        return 0.0;
    }
    let leading = v.leading_zeros();
    let highest = 63 - leading; // bit position of most-significant 1 (u32)
    let exponent = (highest as u64) + 1023; // IEEE 754 biased exponent
    let mantissa = if highest >= 52 {
        (v >> ((highest - 52) as u64)) & 0x000F_FFFF_FFFF_FFFF
    } else {
        (v << ((52 - highest) as u64)) & 0x000F_FFFF_FFFF_FFFF
    };
    f64::from_bits((exponent << 52) | mantissa)
}

/// Convert a `u32` to `f64` (lossless).
#[inline]
#[must_use]
pub fn u32_to_f64(v: u32) -> f64 {
    f64::from(v)
}

/// Convert a `usize` to `u32`, saturating to `u32::MAX` on overflow.
#[inline]
#[must_use]
pub fn usize_to_u32_sat(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Convert a `u64` to `usize`, saturating to `usize::MAX` on overflow.
#[inline]
#[must_use]
pub fn u64_to_usize_sat(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Convert a `usize` to `i64`, saturating on overflow.
#[inline]
#[must_use]
pub fn usize_to_i64_sat(v: usize) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Convert a `u64` to `i64`, saturating on overflow.
#[inline]
#[must_use]
pub fn u64_to_i64_sat(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Convert a `u64` to `u32`, saturating on overflow.
#[inline]
#[must_use]
pub fn u64_to_u32_sat(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Convert a `u64` to `u16`, saturating on overflow.
#[inline]
#[must_use]
pub fn u64_to_u16_sat(v: u64) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

/// Convert a `u32` to `u16`, saturating on overflow.
#[inline]
#[must_use]
pub fn u32_to_u16_sat(v: u32) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

/// Convert an `i32` to `u64`, clamping negatives to 0.
#[inline]
#[must_use]
pub fn i32_to_u64_clamp(v: i32) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// Convert an `f64` to `u64`, clamping to `[0, u64::MAX]` (NaN -> 0).
///
/// Implemented via IEEE 754 bit extraction to avoid cast lints.
#[inline]
#[must_use]
pub fn f64_to_u64_clamp(v: f64) -> u64 {
    if v.is_nan() || v <= 0.0 {
        return 0;
    }
    let bits = v.to_bits();
    let biased_exp = ((bits >> 52) & 0x7FF) as u32; // 0x7FF fits in u32
    if biased_exp < 1023 {
        // v < 1.0
        return 0;
    }
    let actual_exp = biased_exp - 1023;
    if actual_exp >= 64 {
        return u64::MAX;
    }
    let mantissa = (bits & 0x000F_FFFF_FFFF_FFFF) | 0x0010_0000_0000_0000;
    if actual_exp >= 52 {
        mantissa << u64::from(actual_exp - 52)
    } else {
        mantissa >> u64::from(52 - actual_exp)
    }
}

/// Convert an `f64` to `u8`, clamping to `[0, u8::MAX]` (NaN -> 0).
#[inline]
#[must_use]
pub fn f64_to_u8_clamp(v: f64) -> u8 {
    if v.is_nan() || v <= 0.0 {
        0
    } else if v >= 255.0 {
        255
    } else {
        (f64_to_u64_clamp(v) & 0xFF) as u8 // 0xFF fits in u8
    }
}

/// Convert an `f64` to `u32`, clamping (NaN -> 0).
#[inline]
#[must_use]
pub fn f64_to_u32_clamp(v: f64) -> u32 {
    if v.is_nan() || v <= 0.0 {
        0
    } else if v >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        (f64_to_u64_clamp(v) & 0xFFFF_FFFF) as u32 // 0xFFFF_FFFF fits in u32
    }
}

/// Convert an `f64` to `usize`, clamping (NaN -> 0).
#[inline]
#[must_use]
pub fn f64_to_usize_clamp(v: f64) -> usize {
    usize::try_from(f64_to_u64_clamp(v)).unwrap_or(usize::MAX)
}
