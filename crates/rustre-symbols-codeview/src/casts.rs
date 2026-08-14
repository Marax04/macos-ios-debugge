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
pub fn u8_as_i8(x: u8) -> i8 {
    i8::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret a `u16`'s bit pattern as `i16`.
#[inline]
#[must_use]
pub fn u16_as_i16(x: u16) -> i16 {
    i16::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret a `u32`'s bit pattern as `i32`.
#[inline]
#[must_use]
pub fn u32_as_i32(x: u32) -> i32 {
    i32::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret a `u64`'s bit pattern as `i64`.
#[inline]
#[must_use]
pub fn u64_as_i64(x: u64) -> i64 {
    i64::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret an `i8`'s bit pattern as `u8`.
#[inline]
#[must_use]
pub fn i8_as_u8(x: i8) -> u8 {
    u8::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret an `i16`'s bit pattern as `u16`.
#[inline]
#[must_use]
pub fn i16_as_u16(x: i16) -> u16 {
    u16::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret an `i32`'s bit pattern as `u32`.
#[inline]
#[must_use]
pub fn i32_as_u32(x: i32) -> u32 {
    u32::from_ne_bytes(x.to_ne_bytes())
}

/// Reinterpret an `i64`'s bit pattern as `u64`.
#[inline]
#[must_use]
pub fn i64_as_u64(x: i64) -> u64 {
    u64::from_ne_bytes(x.to_ne_bytes())
}

/// Sign-extend an `i8` into a `u64` by reinterpreting the resulting `i64`
/// bit pattern.
#[inline]
#[must_use]
pub fn i8_sext_u64(x: i8) -> u64 {
    i64_as_u64(i64::from(x))
}

/// Sign-extend an `i16` into a `u64`.
#[inline]
#[must_use]
pub fn i16_sext_u64(x: i16) -> u64 {
    i64_as_u64(i64::from(x))
}

/// Sign-extend an `i32` into a `u64`.
#[inline]
#[must_use]
pub fn i32_sext_u64(x: i32) -> u64 {
    i64_as_u64(i64::from(x))
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
pub fn f32_to_u64_sat(x: f32) -> u64 {
    if !x.is_finite() || x <= 0.0 {
        return 0;
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
pub fn f64_to_u64_sat(x: f64) -> u64 {
    if !x.is_finite() || x <= 0.0 {
        return 0;
    }
    let max_f = 18_446_744_073_709_551_615.0_f64;
    let clamped = x.min(max_f);
    // `clamped` is finite and in [0, f64 representation of u64::MAX],
    // so the safe `as` cast is equivalent to the unchecked conversion.
    clamped as u64
}
