//! Internal numeric cast helpers.
//!
//! These tiny boundary functions exist so the rest of the crate can perform
//! intentional lossy numeric conversions without spreading `as` casts across
//! the codebase. Each helper documents the intentional semantics (saturating,
//! truncating, or fp-conversion with precision loss).

/// Convert `u64` to `usize`. On 64-bit targets this is lossless; on 32-bit
/// targets values larger than `usize::MAX` saturate.
#[inline]
#[must_use]
pub fn u64_to_usize(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Convert `usize` to `u32`. Values above `u32::MAX` saturate.
#[inline]
#[must_use]
pub fn usize_to_u32(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Convert `usize` to `i32`. Values above `i32::MAX` saturate.
#[inline]
#[must_use]
pub fn usize_to_i32(v: usize) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

/// Convert `usize` to `i8`. Values above `i8::MAX` saturate.
#[inline]
#[must_use]
pub fn usize_to_i8(v: usize) -> i8 {
    i8::try_from(v).unwrap_or(i8::MAX)
}

/// Convert `i8` to `usize`. Negative values clamp to `0`.
#[inline]
#[must_use]
pub fn i8_to_usize(v: i8) -> usize {
    usize::try_from(v).unwrap_or(0)
}

/// Convert `u64` to `u32`. Saturates above `u32::MAX`.
#[inline]
#[must_use]
pub fn u64_to_u32(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Truncate `u64` to its low 8 bits.
#[inline]
#[must_use]
pub fn u64_to_u8(v: u64) -> u8 {
    u8::try_from(v & 0xff).unwrap_or(0)
}

/// Truncate `u64` to its low 16 bits as `i16` via two's-complement wrap.
#[inline]
#[must_use]
pub fn u64_to_i16(v: u64) -> i16 {
    let low = u16::try_from(v & 0xffff).unwrap_or(0);
    i16::from_ne_bytes(low.to_ne_bytes())
}

/// Truncate `u64` to its low 32 bits as `i32` via two's-complement wrap.
#[inline]
#[must_use]
pub fn u64_to_i32(v: u64) -> i32 {
    let low = u32::try_from(v & 0xffff_ffff).unwrap_or(0);
    i32::from_ne_bytes(low.to_ne_bytes())
}

/// Truncate an `i32` to `u8` (low 8 bits, sign discarded).
#[inline]
#[must_use]
pub const fn i32_to_u8(v: i32) -> u8 {
    let b = v.to_le_bytes();
    b[0]
}

/// Truncate an `i32` to `u16` (low 16 bits, sign discarded).
#[inline]
#[must_use]
pub const fn i32_to_u16(v: i32) -> u16 {
    let b = v.to_le_bytes();
    u16::from_le_bytes([b[0], b[1]])
}

/// 2^64 as `f64` — the nearest representable `f64` above `u64::MAX`.
/// Bit pattern: sign=0, `biased_exp=0x43F` (=64+1023), mantissa=0.
const U64_LIMIT_F64: f64 = f64::from_bits(0x43F0_0000_0000_0000);

/// Convert `usize` to `f64`. Precision is lost for values above 2^53.
///
/// Uses a split via two `u32` halves so that each half converts losslessly.
#[inline]
#[must_use]
pub fn usize_to_f64(v: usize) -> f64 {
    u64_to_f64(v as u64)
}

/// Convert `u64` to `f64`. Precision is lost for values above 2^53.
///
/// Uses a split via two `u32` halves so that each half converts losslessly
/// through `f64::from`, then recombines: `hi * 2^32 + lo`.
#[inline]
#[must_use]
pub fn u64_to_f64(v: u64) -> f64 {
    let bytes = v.to_le_bytes();
    let lo = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let hi = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    f64::from(hi).mul_add(4_294_967_296.0, f64::from(lo))
}

/// Convert `f64` to `u64`, saturating negative/NaN to 0 and large values to `u64::MAX`.
///
/// Uses IEEE 754 bit-pattern decomposition to avoid any numeric casts.
#[inline]
#[must_use]
pub fn f64_to_u64(v: f64) -> u64 {
    if !v.is_finite() || v <= 0.0 {
        return 0;
    }
    if v >= U64_LIMIT_F64 {
        return u64::MAX;
    }
    // Decompose the IEEE 754 double bit pattern to reconstruct the integer value.
    let bits = v.to_bits();
    // Biased exponent occupies bits 62..52 (11 bits).
    let biased_exp = u32::try_from((bits >> 52) & 0x7FF).unwrap_or(0);
    if biased_exp < 1023 {
        // Value is in [0, 1); truncation yields 0.
        return 0;
    }
    let exp = biased_exp - 1023; // unbiased; in [0, 63] given the guards above
    // Mantissa with the implicit leading 1 restored (53 significant bits).
    let mantissa = (bits & 0x000F_FFFF_FFFF_FFFF) | 0x0010_0000_0000_0000;
    // Align the mantissa with the integer's binary point.
    if exp >= 52 {
        mantissa << (exp - 52)
    } else {
        mantissa >> (52 - exp)
    }
}
