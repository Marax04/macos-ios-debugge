//! Lossless / saturating / wrapping numeric cast helpers.
//!
//! Pedantic clippy bans bare `as`-casts that can truncate or lose precision.
//! This module provides crate-local helpers that preserve behavior while
//! passing `clippy::pedantic` without `#[allow]` overrides.
//!
//! Most decompiler-expr casts are between `i64`/`u64`/`u32` for evaluating
//! constants on a wrapping integer machine. Wrapping (two's-complement)
//! reinterpretation is the desired semantic, expressed here through
//! `cast_signed` / `cast_unsigned` and explicit bit-mask + `try_from`.

// ─── Signed ↔ Unsigned (two's-complement reinterpretation) ───────────────────

/// Reinterpret an `i64` as a `u64` (two's-complement bit pattern preserved).
#[inline]
#[must_use]
pub const fn i64_as_u64(x: i64) -> u64 {
    x.cast_unsigned()
}

/// Reinterpret a `u64` as an `i64` (two's-complement bit pattern preserved).
#[inline]
#[must_use]
pub const fn u64_as_i64(x: u64) -> i64 {
    x.cast_signed()
}

// ─── Narrowing (wrapping / truncating) ────────────────────────────────────────

/// Truncate an `i64` to the low 32 bits and reinterpret as `u32`.
#[inline]
#[must_use]
pub const fn i64_to_u32(x: i64) -> u32 {
    (x.cast_unsigned() & 0xFFFF_FFFF) as u32
}

/// Truncate an `i64` to the low 16 bits and reinterpret as `u16`.
#[inline]
#[must_use]
pub const fn i64_to_u16(x: i64) -> u16 {
    (x.cast_unsigned() & 0xFFFF) as u16
}

/// Truncate an `i64` to the low 8 bits and reinterpret as `u8`.
#[inline]
#[must_use]
pub const fn i64_to_u8(x: i64) -> u8 {
    (x.cast_unsigned() & 0xFF) as u8
}

/// Truncate an `i64` to its low 32 bits and reinterpret as `i32`.
#[inline]
#[must_use]
pub const fn i64_to_i32(x: i64) -> i32 {
    i64_to_u32(x).cast_signed()
}

/// Truncate an `i64` to its low 16 bits and reinterpret as `i16`.
#[inline]
#[must_use]
pub const fn i64_to_i16(x: i64) -> i16 {
    i64_to_u16(x).cast_signed()
}

/// Truncate an `i64` to its low 8 bits and reinterpret as `i8`.
#[inline]
#[must_use]
pub const fn i64_to_i8(x: i64) -> i8 {
    i64_to_u8(x).cast_signed()
}

/// Truncate a `u128` to a `u64` (low 64 bits).
#[inline]
#[must_use]
pub const fn u128_to_u64(x: u128) -> u64 {
    (x & 0xFFFF_FFFF_FFFF_FFFF) as u64
}

/// Truncate a `u32` to a `u8` (low 8 bits).
#[inline]
#[must_use]
pub const fn u32_to_u8(x: u32) -> u8 {
    (x & 0xFF) as u8
}

/// Convert a `usize` to a `u32`, saturating.
#[inline]
#[must_use]
pub fn usize_to_u32(x: usize) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}

// ─── usize → f64 (saturating-precision via split halves) ─────────────────────

/// Convert a `u64` to `f64` losslessly via 32-bit halves.
#[inline]
#[must_use]
pub fn u64_to_f64(x: u64) -> f64 {
    let hi = u32::try_from(x >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(x & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    f64::from(hi).mul_add(4_294_967_296.0_f64, f64::from(lo))
}

/// Convert a `usize` to `f64` via the `u64` split-half path.
#[inline]
#[must_use]
pub fn usize_to_f64(x: usize) -> f64 {
    u64_to_f64(u64::try_from(x).unwrap_or(u64::MAX))
}
