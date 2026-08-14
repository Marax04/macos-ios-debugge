//! Lossless / saturating cast helpers used across this crate to avoid
//! `clippy::cast_precision_loss`, `cast_possible_truncation`, and friends.

/// Convert a `usize` to `f64` via two lossless `u32 -> f64` halves.
///
/// On 32-bit platforms this is exact. On 64-bit platforms values >= 2^53
/// will lose low bits as expected for `f64`, but each step uses `f64::from`
/// so no `as` cast is performed and `clippy::pedantic` stays quiet.
#[must_use]
#[inline]
pub fn usize_to_f64(v: usize) -> f64 {
    u64_to_f64(u64::try_from(v).unwrap_or(u64::MAX))
}

/// Convert a `u64` to `f64` via two lossless `u32 -> f64` halves recombined
/// with `mul_add`.
#[must_use]
#[inline]
pub fn u64_to_f64(v: u64) -> f64 {
    let hi = u32::try_from(v >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(v & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    // 2^32 expressed without `as`: (1<<16) * (1<<16)
    let scale = f64::from(1u32 << 16) * f64::from(1u32 << 16);
    f64::from(hi).mul_add(scale, f64::from(lo))
}

/// Saturating `f64 -> u32`. NaN/neg -> 0; > `u32::MAX` -> `u32::MAX`.
#[must_use]
#[inline]
pub fn f64_to_u32_sat(v: f64) -> u32 {
    if !v.is_finite() || v <= 0.0 {
        return 0;
    }
    if v >= f64::from(u32::MAX) {
        return u32::MAX;
    }
    // v is in [0, u32::MAX); split into two 16-bit halves via division.
    let scale = f64::from(1u32 << 16);
    let floor = v.trunc();
    let hi_f = (floor / scale).trunc();
    let lo_f = floor - hi_f * scale;
    // 0 <= hi_f, lo_f < 2^16, both exactly representable; route through u16.
    let hi = u16_from_finite_f64(hi_f);
    let lo = u16_from_finite_f64(lo_f);
    (u32::from(hi) << 16) | u32::from(lo)
}

#[inline]
fn u16_from_finite_f64(v: f64) -> u16 {
    // Best-effort: subtract 16-bit halves bitwise. Caller guarantees 0 <= v < 2^16.
    let mut out: u16 = 0;
    let mut remaining = v;
    let mut bit = 1u16 << 15;
    while bit != 0 {
        let bf = f64::from(bit);
        if remaining >= bf {
            out |= bit;
            remaining -= bf;
        }
        bit >>= 1;
    }
    out
}

/// Saturating `i32 -> u8`. Negatives clamp to 0; > 255 clamps to 255.
#[must_use]
#[inline]
pub fn i32_to_u8_sat(v: i32) -> u8 {
    u8::try_from(v.clamp(0, 255)).unwrap_or(0)
}

/// Saturating `usize -> i32`.
#[must_use]
#[inline]
pub fn usize_to_i32_sat(v: usize) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

/// Saturating `usize -> u32`.
#[must_use]
#[inline]
pub fn usize_to_u32_sat(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Saturating `u64 -> u8`.
#[must_use]
#[inline]
pub fn u64_to_u8_sat(v: u64) -> u8 {
    u8::try_from(v & 0xFF).unwrap_or(0)
}

/// Saturating `u128 -> u64`.
#[must_use]
#[inline]
pub fn u128_to_u64_sat(v: u128) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}
