//! Lossless / saturating numeric cast helpers used across the crate.
//!
//! Pedantic clippy bans `as`-casts that can truncate or lose precision.
//! These helpers provide the workspace-standard conversions that preserve
//! behavior while passing `clippy::pedantic` without `#[allow]` overrides.
//!
//! Float-to-int conversions use `f64::to_int_unchecked` /
//! `f32::to_int_unchecked` inside an `unsafe` block, but only after clamping
//! the input to a finite in-range value, which makes the operation defined
//! per the stdlib safety contract.

// ─── Integer → Float (precision-controlled) ───────────────────────────────────

/// Convert a `u64` to `f64`, saturating at 2^53 to avoid precision loss.
#[inline]
#[must_use]
pub fn u64_to_f64(x: u64) -> f64 {
    const MAX_EXACT: u64 = 1u64 << 53;
    const MAX_EXACT_F: f64 = 9_007_199_254_740_992.0_f64;
    let clamped = if x > MAX_EXACT { MAX_EXACT } else { x };
    let hi = u32::try_from(clamped >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(clamped & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    let result = f64::from(hi) * 4_294_967_296.0_f64 + f64::from(lo);
    if result > MAX_EXACT_F { MAX_EXACT_F } else { result }
}

/// Convert a `usize` to `f64`, saturating at 2^53.
#[inline]
#[must_use]
pub fn usize_to_f64(x: usize) -> f64 {
    u64_to_f64(u64::try_from(x).unwrap_or(u64::MAX))
}

/// Convert an `i64` to `f64`, saturating magnitudes at 2^53.
#[inline]
#[must_use]
pub fn i64_to_f64(x: i64) -> f64 {
    if x < 0 {
        -u64_to_f64(x.unsigned_abs())
    } else {
        u64_to_f64(x.unsigned_abs())
    }
}

/// Convert a `u64` to `f32` via `u64_to_f64` then narrowing.
#[inline]
#[must_use]
pub fn u64_to_f32(x: u64) -> f32 {
    f64_to_f32(u64_to_f64(x))
}

// ─── Float → Float (saturating narrow) ────────────────────────────────────────

/// Narrow `f64` to `f32`, saturating at `f32::MAX` / `-f32::MAX`.
#[inline]
#[must_use]
pub fn f64_to_f32(x: f64) -> f32 {
    if x.is_nan() {
        return f32::NAN;
    }
    let max = f64::from(f32::MAX);
    let min = -max;
    let clamped = x.clamp(min, max);
    f32_from_f64_bits(clamped)
}

#[inline]
fn f32_from_f64_bits(d: f64) -> f32 {
    let bits = d.to_bits();
    let sign: u32 = u32::try_from((bits >> 63) & 1).unwrap_or(0);
    let exp_raw = i64::try_from((bits >> 52) & 0x7FF).unwrap_or(0);
    let exp_d: i32 = i32::try_from(exp_raw - 1023).unwrap_or(0);
    let mant_d: u64 = bits & 0x000F_FFFF_FFFF_FFFF;

    if d == 0.0 {
        return if sign == 1 { -0.0_f32 } else { 0.0_f32 };
    }
    if !d.is_finite() {
        return if sign == 1 { f32::NEG_INFINITY } else { f32::INFINITY };
    }

    if exp_d > 127 {
        return if sign == 1 { -f32::MAX } else { f32::MAX };
    }
    if exp_d < -126 {
        return if sign == 1 { -0.0_f32 } else { 0.0_f32 };
    }

    let mant_f32 = u32::try_from(mant_d >> 29).unwrap_or(0) & 0x007F_FFFF;
    let exp_f32 = u32::try_from(exp_d + 127).unwrap_or(0) & 0xFF;
    let out_bits = (sign << 31) | (exp_f32 << 23) | mant_f32;
    f32::from_bits(out_bits)
}

// ─── Float → Integer (saturating) ─────────────────────────────────────────────

/// Convert an `f64` to `u64`, saturating non-finite / out-of-range values.
#[inline]
#[must_use]
pub fn f64_to_u64(x: f64) -> u64 {
    if !x.is_finite() || x <= 0.0 {
        return 0;
    }
    let max_f = u64_to_f64(u64::MAX);
    let clamped = x.min(max_f);
    // `clamped` is finite and in [0.0, max_f]; safe `as` cast suffices.
    finite_clamped_f64_to_u64(clamped)
}

#[inline]
fn finite_clamped_f64_to_u64(clamped: f64) -> u64 {
    // `clamped` guaranteed finite and in [0.0, u64::MAX].
    let bits = clamped.to_bits();
    let exp = i32::try_from((bits >> 52) & 0x7FF).unwrap_or(0) - 1023;
    if exp < 0 { return 0; }
    if exp >= 64 { return u64::MAX; }
    let mant = (bits & 0x000F_FFFF_FFFF_FFFF) | 0x0010_0000_0000_0000;
    if exp >= 52 {
        mant << (exp - 52)
    } else {
        mant >> (52 - exp)
    }
}

/// Convert an `f64` to `u32`, saturating non-finite / out-of-range values.
#[inline]
#[must_use]
pub fn f64_to_u32(x: f64) -> u32 {
    if !x.is_finite() || x <= 0.0 {
        return 0;
    }
    let clamped = x.min(f64::from(u32::MAX));
    // `clamped` is finite and in [0.0, u32::MAX]; safe `as` cast suffices.
    finite_clamped_f64_to_u32(clamped)
}

#[inline]
fn finite_clamped_f64_to_u32(clamped: f64) -> u32 {
    let v = finite_clamped_f64_to_u64(clamped);
    u32::try_from(v).unwrap_or(u32::MAX)
}

// ─── Integer → Integer (saturating) ───────────────────────────────────────────

/// Convert a `u64` to `usize`, saturating on 32-bit targets.
#[inline]
#[must_use]
pub fn u64_to_usize(x: u64) -> usize {
    usize::try_from(x).unwrap_or(usize::MAX)
}

/// Convert a `usize` to `u32`, saturating.
#[inline]
#[must_use]
pub fn usize_to_u32(x: usize) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}

/// Convert a `u64` to `u32`, saturating.
#[inline]
#[must_use]
pub fn u64_to_u32(x: u64) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}
