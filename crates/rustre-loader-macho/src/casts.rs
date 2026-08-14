//! Boundary cast helpers used throughout the loader.
//!
//! All checked casts that clippy's pedantic lints would otherwise flag are
//! centralised here. Each helper uses `try_from` and saturates to the target
//! type's `MAX` (or `MIN` for signed) on overflow, preserving behaviour while
//! making the conversion intent explicit at every call site.

#[inline]
#[must_use]
pub fn u64_to_usize(x: u64) -> usize {
    usize::try_from(x).unwrap_or(usize::MAX)
}

#[inline]
#[must_use]
pub fn usize_to_u32(x: usize) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}

#[inline]
#[must_use]
pub fn u64_to_u32(x: u64) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}

#[inline]
#[must_use]
pub fn u64_to_u16(x: u64) -> u16 {
    u16::try_from(x).unwrap_or(u16::MAX)
}

#[inline]
#[must_use]
pub fn u64_to_u8(x: u64) -> u8 {
    u8::try_from(x).unwrap_or(u8::MAX)
}

#[inline]
#[must_use]
pub fn usize_to_u8(x: usize) -> u8 {
    u8::try_from(x).unwrap_or(u8::MAX)
}

#[inline]
#[must_use]
pub fn usize_to_i64(x: usize) -> i64 {
    i64::try_from(x).unwrap_or(i64::MAX)
}

#[inline]
#[must_use]
pub fn i64_to_usize(x: i64) -> usize {
    usize::try_from(x).unwrap_or(0)
}

#[inline]
#[must_use]
pub fn i64_to_u64(x: i64) -> u64 {
    u64::try_from(x).unwrap_or(0)
}

#[inline]
#[must_use]
pub fn u32_to_i32(x: u32) -> i32 {
    i32::try_from(x).unwrap_or(i32::MAX)
}

#[inline]
#[must_use]
pub fn u64_to_i32(x: u64) -> i32 {
    i32::try_from(x).unwrap_or(i32::MAX)
}

#[inline]
#[must_use]
pub fn u8_to_i8(x: u8) -> i8 {
    i8::try_from(x).unwrap_or(i8::MAX)
}

#[inline]
#[must_use]
pub fn usize_to_f64(x: usize) -> f64 {
    // Intentional precision loss for statistical / heuristic usage.
    // Bounded via try_from to u32 first, so values up to ~4G are exact.
    if let Ok(narrow) = u32::try_from(x) {
        f64::from(narrow)
    } else {
        // For larger values, use a deliberate widening through u64 then f64-from-u32 of high bits.
        // We accept inexact representation above 2^53.
        let hi = u32::try_from(x >> 32).unwrap_or(u32::MAX);
        let lo = u32::try_from(x & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        f64::from(hi) * 4_294_967_296.0_f64 + f64::from(lo)
    }
}
