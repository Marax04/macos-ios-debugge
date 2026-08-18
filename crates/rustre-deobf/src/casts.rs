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
    // ⚠ No `#[allow]` here any more, and the clippy warning it suppressed is
    // now visible on purpose.
    //
    // The bound IS proven: `clamp` puts the value in `0.0..=u32::MAX` before the
    // conversion, and `f64 as u32` is a SATURATING cast in Rust (since 1.45),
    // so neither truncation nor sign loss can occur. But there is no checked
    // float-to-integer conversion in std — `try_from` is not implemented for
    // float sources — so `as` is the only way to express this, and clippy's
    // `cast_possible_truncation` fires on it regardless of the guard.
    //
    // Silencing it would have meant re-adding the attribute; hiding it by
    // routing through `u64` first (the previous attempt) only moved the same
    // warning one line down. So it stays visible, and this comment is the
    // record of why: the lint is a false positive at this call site, and the
    // clamp above is the proof a reader can check.
    let clamped = x.clamp(0.0, f64::from(u32::MAX));
    clamped as u32
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
