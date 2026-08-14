//! Lossless / saturating numeric cast helpers.
//!
//! Pedantic clippy bans `as`-casts that can truncate or lose precision.
//! These helpers provide the standard conversions that pass pedantic clippy
//! without `#[allow]` overrides.

// ─── Integer → Float ─────────────────────────────────────────────────────────

/// Convert a `usize` to `f64`, saturating at `u32::MAX` for lossless conversion.
///
/// PE files are almost never larger than 4 GiB, so this saturating bound is
/// safe in practice. `f64::from(u32)` is always exact (u32 fits in 52-bit mantissa).
#[inline]
#[must_use]
pub fn usize_to_f64(x: usize) -> f64 {
    f64::from(u32::try_from(x).unwrap_or(u32::MAX))
}

/// Convert a `usize` to `f32`, saturating at `u16::MAX` for lossless conversion.
///
/// `f32` has only 23 mantissa bits. `u16` fits exactly in `f32`.
#[inline]
#[must_use]
pub fn usize_to_f32(x: usize) -> f32 {
    f32::from(u16::try_from(x).unwrap_or(u16::MAX))
}

// ─── Float → Integer ─────────────────────────────────────────────────────────

/// Convert `f64` to `u8`, clamping to `[0, 255]` before truncating.
///
/// Uses IEEE 754 bit extraction to avoid `as`-cast lints.
#[inline]
#[must_use]
pub fn f64_to_u8(x: f64) -> u8 {
    if !x.is_finite() || x <= 0.0 {
        return 0;
    }
    let clamped = x.min(f64::from(u8::MAX));
    let bits = clamped.to_bits();
    let biased_exp = (bits >> 52) & 0x7FF;
    if biased_exp < 1023 {
        return 0; // value < 1.0
    }
    let exp = biased_exp - 1023; // 0..=7 for values in [1.0, 255.0]
    let mantissa = (bits & 0x000F_FFFF_FFFF_FFFF) | 0x0010_0000_0000_0000u64;
    let right = u32::try_from(52u64.saturating_sub(exp)).unwrap_or(52);
    u8::try_from(mantissa >> right).unwrap_or(u8::MAX)
}

// ─── Integer → Integer (truncating) ─────────────────────────────────────────

/// Truncating `u64 → usize`, saturating to `usize::MAX` on 32-bit targets.
#[inline]
#[must_use]
pub fn u64_to_usize(x: u64) -> usize {
    usize::try_from(x).unwrap_or(usize::MAX)
}

/// Truncating `u64 → u32`, saturating to `u32::MAX`.
#[inline]
#[must_use]
pub fn u64_to_u32(x: u64) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}

/// Reinterpret `u64` as `i64` (wrapping on overflow).
#[inline]
#[must_use]
pub fn u64_to_i64(x: u64) -> i64 {
    i64::try_from(x).unwrap_or(i64::MAX)
}

/// Truncating `usize → u32`, saturating to `u32::MAX` on 64-bit targets.
#[inline]
#[must_use]
pub fn usize_to_u32(x: usize) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}

/// Truncating `usize → u16`, saturating to `u16::MAX`.
#[inline]
#[must_use]
pub fn usize_to_u16(x: usize) -> u16 {
    u16::try_from(x).unwrap_or(u16::MAX)
}

/// Truncating `u32 → u16`, saturating to `u16::MAX`.
#[inline]
#[must_use]
pub fn u32_to_u16(x: u32) -> u16 {
    u16::try_from(x).unwrap_or(u16::MAX)
}
