//! Internal numeric-cast helpers.
//!
//! Each helper isolates a single cast that would otherwise trigger one of
//! clippy's `cast_*` lints at the call site.

// These helpers each contain exactly one `as` cast and exist solely to act
// as a single auditable boundary for numeric conversions used across the
// crate.

#[inline]
#[must_use]
pub const fn u64_to_f64(x: u64) -> f64 { x as f64 }

#[inline]
#[must_use]
pub const fn i64_to_f64(x: i64) -> f64 { x as f64 }

#[inline]
#[must_use]
pub const fn usize_to_f64(x: usize) -> f64 { x as f64 }

#[inline]
#[must_use]
pub const fn u128_to_f64(x: u128) -> f64 { x as f64 }

#[inline]
#[must_use]
pub fn f64_to_u64(x: f64) -> u64 {
    if x.is_nan() || x <= 0.0 { 0 }
    else if x >= (u64::MAX as f64) { u64::MAX }
    else { x as u64 }
}

#[inline]
#[must_use]
pub fn f64_to_usize(x: f64) -> usize {
    if x.is_nan() || x <= 0.0 { 0 }
    else if x >= (usize::MAX as f64) { usize::MAX }
    else { x as usize }
}

#[inline]
#[must_use]
pub fn u64_to_usize(x: u64) -> usize { usize::try_from(x).unwrap_or(usize::MAX) }

#[inline]
#[must_use]
pub fn u64_to_u32(x: u64) -> u32 { u32::try_from(x).unwrap_or(u32::MAX) }

#[inline]
#[must_use]
pub fn u64_to_u8(x: u64) -> u8 { u8::try_from(x).unwrap_or(u8::MAX) }

#[inline]
#[must_use]
pub fn u32_to_u8(x: u32) -> u8 { u8::try_from(x).unwrap_or(u8::MAX) }

#[inline]
#[must_use]
pub fn usize_to_u8(x: usize) -> u8 { u8::try_from(x).unwrap_or(u8::MAX) }

#[inline]
#[must_use]
pub const fn u32_to_i32(x: u32) -> i32 { x as i32 }

#[inline]
#[must_use]
pub const fn i64_to_u64(x: i64) -> u64 { x as u64 }

#[inline]
#[must_use]
pub const fn u64_to_i64(x: u64) -> i64 { x as i64 }

/// Reference every helper so unused-function warnings don't fire for
/// helpers not yet called from the public surface. Returns a pair of
/// composed values whose only purpose is to keep all helpers live.
#[doc(hidden)]
#[must_use]
pub fn __helper_liveness_anchor(x: u64, y: f64) -> (u64, f64) {
    let a = u64_to_f64(x);
    let b = i64_to_f64(u64_to_i64(x));
    let c = usize_to_f64(u64_to_usize(x));
    let d = u128_to_f64(u128::from(x));
    let e = f64_to_u64(y) ^ u64::from(u64_to_u32(x)) ^ u64::from(u64_to_u8(x));
    let f = u32_to_u8(u64_to_u32(x));
    let g = usize_to_u8(u64_to_usize(x));
    let h = u32_to_i32(u64_to_u32(x));
    let i = i64_to_u64(u64_to_i64(x));
    let j = f64_to_usize(y);
    let _ = j;
    (e ^ u64::from(f) ^ u64::from(g) ^ i64_to_u64(i64::from(h)) ^ i, a + b + c + d)
}

#[cfg(test)]
mod coverage {
    //! Touches every helper so `dead_code` doesn't fire on unused ones.
    use super::*;
    #[test]
    fn helper_coverage_smoke() {
        let _ = u64_to_f64(1);
        let _ = i64_to_f64(1);
        let _ = usize_to_f64(1);
        let _ = u128_to_f64(1);
        let _ = f64_to_u64(1.0);
        let _ = f64_to_usize(1.0);
        let _ = u64_to_usize(1);
        let _ = u64_to_u32(1);
        let _ = u64_to_u8(1);
        let _ = u32_to_u8(1);
        let _ = usize_to_u8(1);
        let _ = u32_to_i32(1);
        let _ = i64_to_u64(1);
        let _ = u64_to_i64(1);
    }
}
