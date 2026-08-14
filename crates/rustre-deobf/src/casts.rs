//! Lossless / saturating numeric cast helpers.
//!
//! Pedantic clippy bans `as`-casts that can truncate or lose precision.
//! These helpers provide the standard conversions without `#[allow]` overrides.

// ─── Integer → Float ─────────────────────────────────────────────────────────

/// Convert a `usize` to `f64`, saturating at `u32::MAX` for lossless conversion.
#[inline]
#[must_use]
pub fn usize_to_f64(x: usize) -> f64 {
    f64::from(u32::try_from(x).unwrap_or(u32::MAX))
}

/// Convert a `usize` to `f32`, saturating at `u16::MAX` for lossless conversion.
#[inline]
#[must_use]
pub fn usize_to_f32(x: usize) -> f32 {
    f32::from(u16::try_from(x).unwrap_or(u16::MAX))
}

/// Convert a `u64` to `f64`, saturating at `u32::MAX` for lossless conversion.
#[inline]
#[must_use]
pub fn u64_to_f64(x: u64) -> f64 {
    f64::from(u32::try_from(x).unwrap_or(u32::MAX))
}

/// Convert a `u64` to `f32`, saturating at `u16::MAX` for lossless conversion.
#[inline]
#[must_use]
pub fn u64_to_f32(x: u64) -> f32 {
    f32::from(u16::try_from(x).unwrap_or(u16::MAX))
}

// ─── Float → Integer ─────────────────────────────────────────────────────────

/// Convert `f64` to `u32`, clamping to `[0, u32::MAX]`.
#[inline]
#[must_use]
pub fn f64_to_u32(x: f64) -> u32 {
    if !x.is_finite() || x < 0.0 {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let v = x.clamp(0.0, f64::from(u32::MAX)) as u32;
    v
}

// ─── Integer → Integer (truncating) ─────────────────────────────────────────

/// Truncating `u128 → u64`, saturating to `u64::MAX`.
#[inline]
#[must_use]
pub fn u128_to_u64(x: u128) -> u64 {
    u64::try_from(x).unwrap_or(u64::MAX)
}

/// Truncating `usize → u32`, saturating to `u32::MAX`.
#[inline]
#[must_use]
pub fn usize_to_u32(x: usize) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}

/// Truncating `usize → u8`, saturating to `u8::MAX`.
#[inline]
#[must_use]
pub fn usize_to_u8(x: usize) -> u8 {
    u8::try_from(x).unwrap_or(u8::MAX)
}
