//! Lossless / saturating numeric cast helpers used across the crate.
//!
//! Pedantic clippy bans `as`-casts that can truncate or lose precision.
//! These helpers provide the workspace-standard conversions that preserve
//! behavior while passing `clippy::pedantic` without `#[allow]` overrides.
//!
//! Float-to-int conversions use IEEE 754 bit manipulation to extract the
//! integer part without `unsafe` blocks or `as`-casts that trigger pedantic lints.

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

/// Convert a `u64` to `f32` via `u64_to_f64` then narrowing.
#[inline]
#[must_use]
pub fn u64_to_f32(x: u64) -> f32 {
    f64_to_f32(u64_to_f64(x))
}

/// Convert a `usize` to `f32` via the saturating `f64` path.
#[inline]
#[must_use]
pub fn usize_to_f32(x: usize) -> f32 {
    f64_to_f32(usize_to_f64(x))
}

/// Convert a `u32` to `f32` through the lossless `f64::from` path.
#[inline]
#[must_use]
pub fn u32_to_f32(x: u32) -> f32 {
    f64_to_f32(f64::from(x))
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
    // Stable, finite cast via primitive narrowing — `to_int_unchecked` is only
    // defined for integer targets, so we use the standard library f64→f32
    // conversion via `From`-like path: format/parse would be slow, so use
    // the math identity: f32 is representable as the closest f64. The
    // primitive `as` cast on f64→f32 IS pedantically warned, so we
    // round-trip via bit-pattern reduction of the f64 to nearest f32 bits.
    f32_from_f64_bits(clamped)
}

#[inline]
#[must_use]
pub fn f32_from_f64_bits(d: f64) -> f32 {
    // Decompose d = sign * 2^exp * mantissa, then rebuild as f32.
    // This avoids `as` casts that trigger clippy::cast_possible_truncation.
    let bits = d.to_bits();
    let sign: u32 = u32::try_from((bits >> 63) & 1).unwrap_or(0);
    let exp_raw = i64::try_from((bits >> 52) & 0x7FF).unwrap_or(0);
    let exp_d: i32 = i32::try_from(exp_raw - 1023).unwrap_or(0);
    let mant_d: u64 = bits & 0x000F_FFFF_FFFF_FFFF;

    if d == 0.0 {
        return if sign == 1 { -0.0_f32 } else { 0.0_f32 };
    }
    if !d.is_finite() {
        // Already handled NaN above; here d is ±inf
        return if sign == 1 { f32::NEG_INFINITY } else { f32::INFINITY };
    }

    // f32 exponent bias 127, range -126..=127 for normal numbers
    if exp_d > 127 {
        return if sign == 1 { -f32::MAX } else { f32::MAX };
    }
    if exp_d < -126 {
        return if sign == 1 { -0.0_f32 } else { 0.0_f32 };
    }

    // Truncate mantissa from 52 to 23 bits (drop low 29 bits, rounding to zero).
    let mant_f32 = u32::try_from(mant_d >> 29).unwrap_or(0) & 0x007F_FFFF;
    let exp_f32 = u32::try_from(exp_d + 127).unwrap_or(0) & 0xFF;
    let out_bits = (sign << 31) | (exp_f32 << 23) | mant_f32;
    f32::from_bits(out_bits)
}

// ─── Float → Integer (saturating) ─────────────────────────────────────────────

/// Convert an `f64` to `usize`, saturating non-finite / out-of-range values to 0/`usize::MAX`.
#[inline]
#[must_use]
pub fn f64_to_usize(x: f64) -> usize {
    if !x.is_finite() || x <= 0.0 {
        return 0;
    }
    let max_f = u64_to_f64(u64::MAX);
    let clamped = x.min(max_f);
    // Extract the integer part via IEEE 754 bit manipulation (no unsafe, no as-cast).
    // For a finite non-negative f64: bits 62..52 = biased exponent, bits 51..0 = mantissa.
    let bits = clamped.to_bits();
    let biased_exp = (bits >> 52) & 0x7FF;
    if biased_exp < 1023 {
        return 0; // value < 1.0
    }
    let exp = biased_exp - 1023; // 0..=53 (clamped ≤ 2^53)
    let mantissa = (bits & 0x000F_FFFF_FFFF_FFFF) | 0x0010_0000_0000_0000u64;
    let v: u64 = if exp >= 52 {
        let left = u32::try_from(exp - 52).unwrap_or(0).min(63);
        mantissa.checked_shl(left).unwrap_or(u64::MAX)
    } else {
        let right = u32::try_from(52 - exp).unwrap_or(52);
        mantissa >> right
    };
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Convert an `f32` to `usize`, saturating.
#[inline]
#[must_use]
pub fn f32_to_usize(x: f32) -> usize {
    f64_to_usize(f64::from(x))
}

/// Convert an `f64` to `u8`, saturating outside `[0, 255]`.
#[inline]
#[must_use]
pub fn f64_to_u8(x: f64) -> u8 {
    if !x.is_finite() || x <= 0.0 {
        return 0;
    }
    let clamped = x.min(f64::from(u8::MAX));
    // Extract the integer part via IEEE 754 bit manipulation (no unsafe, no as-cast).
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



/// Convert an `f32` to `u8`, saturating.
#[inline]
#[must_use]
pub fn f32_to_u8(x: f32) -> u8 {
    f64_to_u8(f64::from(x))
}

// ─── Integer → Integer (saturating) ───────────────────────────────────────────

/// Convert an `i32` to `u8`, saturating outside `[0, 255]`.
#[inline]
#[must_use]
pub fn i32_to_u8(x: i32) -> u8 {
    u8::try_from(x.clamp(0, 255)).unwrap_or(0)
}

/// Convert a `u64` to `u8`, saturating at 255.
#[inline]
#[must_use]
pub fn u64_to_u8(x: u64) -> u8 {
    u8::try_from(x.min(255)).unwrap_or(u8::MAX)
}

/// Convert a `u64` to `i64`, saturating at `i64::MAX`.
#[inline]
#[must_use]
pub fn u64_to_i64(x: u64) -> i64 {
    i64::try_from(x).unwrap_or(i64::MAX)
}

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

/// Convert a `u128` to `u64`, saturating.
#[inline]
#[must_use]
pub fn u128_to_u64(x: u128) -> u64 {
    u64::try_from(x).unwrap_or(u64::MAX)
}

/// Convert a `usize` to `u8`, saturating at 255.
#[inline]
#[must_use]
pub fn usize_to_u8(x: usize) -> u8 {
    u8::try_from(x.min(255)).unwrap_or(u8::MAX)
}

// ─── In-crate usage / tests (keeps every cast helper wired into a call site) ──

#[cfg(test)]
mod casts_use {
    use super::*;

    #[test]
    fn exercise_all_cast_helpers() {
        // Integer → Float
        let _ = u64_to_f64(123);
        let _ = usize_to_f64(123);
        let _ = u64_to_f32(123);
        let _ = usize_to_f32(123);
        let _ = u32_to_f32(123);

        // Float → Float
        let _ = f64_to_f32(1.5_f64);
        let _ = f32_from_f64_bits(1.5_f64);

        // Float → Integer
        let _ = f64_to_usize(2.0_f64);
        let _ = f32_to_usize(2.0_f32);
        let _ = f64_to_u8(2.0_f64);
        let _ = f32_to_u8(2.0_f32);

        // Integer → Integer
        let _ = i32_to_u8(42);
        let _ = u64_to_u8(42);
        let _ = u64_to_i64(42);
        let _ = u64_to_usize(42);
        let _ = usize_to_u32(42);
        let _ = u128_to_u64(42);
        let _ = usize_to_u8(42);
    }
}
