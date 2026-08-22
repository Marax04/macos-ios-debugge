//! Saturating / wrapping numeric cast helpers used across this crate.
//!
//! Pedantic clippy bans `as`-casts that can truncate, wrap or lose sign.
//! These helpers provide the workspace-standard conversions that preserve
//! behavior while passing `clippy::pedantic` without `#[allow]` overrides.

// ─── Truncating (saturating) integer narrowing ────────────────────────────────

/// `u64` → `u32`, saturating at `u32::MAX`.
#[inline]
#[must_use]
pub fn u64_to_u32(x: u64) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}

/// `u64` → `u16`, truncating to the low 16 bits (matches `as u16` semantics).
#[inline]
#[must_use]
pub const fn u64_to_u16(x: u64) -> u16 {
    (x & 0xFFFF) as u16
}

/// `u64` → `u8`, saturating at `u8::MAX`.
#[inline]
#[must_use]
pub fn u64_to_u8(x: u64) -> u8 {
    u8::try_from(x).unwrap_or(u8::MAX)
}

/// `u64` → `usize`, saturating on 32-bit targets.
#[inline]
#[must_use]
pub fn u64_to_usize(x: u64) -> usize {
    usize::try_from(x).unwrap_or(usize::MAX)
}

/// `usize` → `u32`, saturating on 64-bit targets.
#[inline]
#[must_use]
pub fn usize_to_u32(x: usize) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}

// ─── Sign reinterpretation (bit-exact) ────────────────────────────────────────

/// `u8` → `i8` (bit-exact reinterpret).
#[inline]
#[must_use]
pub const fn u8_to_i8(x: u8) -> i8 {
    x.cast_signed()
}

/// `u16` → `i16` (bit-exact reinterpret).
#[inline]
#[must_use]
pub const fn u16_to_i16(x: u16) -> i16 {
    x.cast_signed()
}

/// `u32` → `i32` (bit-exact reinterpret).
#[inline]
#[must_use]
pub const fn u32_to_i32(x: u32) -> i32 {
    x.cast_signed()
}

/// `u64` → `i64` (bit-exact reinterpret).
#[inline]
#[must_use]
pub const fn u64_to_i64(x: u64) -> i64 {
    x.cast_signed()
}

/// `usize` → `isize` (bit-exact reinterpret).
#[inline]
#[must_use]
pub const fn usize_to_isize(x: usize) -> isize {
    x.cast_signed()
}

/// `i64` → `u64` (bit-exact reinterpret).
#[inline]
#[must_use]
pub const fn i64_to_u64(x: i64) -> u64 {
    x.cast_unsigned()
}

// ─── Signed → smaller / unsigned (saturating both ends) ───────────────────────

/// `i64` → `u32`, saturating: negatives → 0, > `u32::MAX` → `u32::MAX`.
#[inline]
#[must_use]
pub fn i64_to_u32(x: i64) -> u32 {
    if x <= 0 {
        0
    } else {
        u32::try_from(x).unwrap_or(u32::MAX)
    }
}

/// `i64` → `u8`, saturating: negatives → 0, > 255 → 255.
#[inline]
#[must_use]
pub fn i64_to_u8(x: i64) -> u8 {
    if x <= 0 {
        0
    } else {
        u8::try_from(x).unwrap_or(u8::MAX)
    }
}

/// `i64` → `usize`, saturating: negatives → 0, large → `usize::MAX`.
#[inline]
#[must_use]
pub fn i64_to_usize(x: i64) -> usize {
    if x <= 0 {
        0
    } else {
        usize::try_from(x).unwrap_or(usize::MAX)
    }
}

/// `usize` → `i64`, saturating at `i64::MAX`.
#[inline]
#[must_use]
pub fn usize_to_i64(x: usize) -> i64 {
    i64::try_from(x).unwrap_or(i64::MAX)
}
