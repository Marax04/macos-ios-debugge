//! `casts.rs` converts between float and integer types with `unsafe`
//! `to_int_unchecked`, so its guards are load-bearing: a value that slips past
//! them is undefined behaviour, not a wrong number.
//!
//! Each function documents a saturation contract. `f64_to_usize` says it
//! saturates "to 0/`usize::MAX`", but it derived its upper clamp from
//! `u64_to_f64(u64::MAX)` — and that helper deliberately saturates at 2^53, so
//! the clamp did too: `f64_to_usize(1e300)` returned 9_007_199_254_740_992
//! rather than `usize::MAX`.
//!
//! The special-value domain is exactly what a conversion module exists to
//! handle, so it is enumerated rather than sampled.

use rustre_fuzz_cov::casts::{f32_to_u8, f32_to_usize, f64_to_f32, f64_to_u8, f64_to_usize};

/// Everything an `f64` argument can be, including the values that make a
/// float-to-int cast undefined if a guard is missed.
fn special_f64() -> Vec<(&'static str, f64)> {
    vec![
        ("NaN", f64::NAN),
        ("pos infinity", f64::INFINITY),
        ("neg infinity", f64::NEG_INFINITY),
        ("zero", 0.0),
        ("neg zero", -0.0),
        ("negative", -1.0),
        ("very negative", -1e300),
        ("subnormal", f64::MIN_POSITIVE / 2.0),
        ("fraction", 0.5),
        ("small", 42.0),
        ("two pow 53", 9_007_199_254_740_992.0),
        ("above two pow 53", 1.8e16),
        ("huge", 1e300),
        ("max", f64::MAX),
    ]
}

#[test]
fn f64_to_usize_never_panics_and_saturates_as_documented() {
    let cases = special_f64();
    let mut checked = 0usize;

    for (label, x) in &cases {
        let v = f64_to_usize(*x);
        // Non-positive and non-finite inputs are documented as 0.
        if x.is_nan() || *x <= 0.0 {
            assert_eq!(v, 0, "f64_to_usize({label}) = {v}, expected 0");
        }
        checked += 1;
    }

    assert_eq!(checked, cases.len(), "anti-vacuity: full domain exercised");

    // The decisive case: a value far above `usize::MAX` must reach the
    // documented ceiling, not the 2^53 limit of an unrelated helper.
    assert_eq!(
        f64_to_usize(1e300),
        usize::MAX,
        "a value beyond the range must saturate to usize::MAX"
    );
    assert_eq!(f64_to_usize(f64::MAX), usize::MAX);

    // Premise: ordinary values still convert exactly, so the assertions above
    // are not passing because everything now saturates.
    assert_eq!(f64_to_usize(42.0), 42);
    assert_eq!(f64_to_usize(0.5), 0);
    assert_eq!(f64_to_usize(9_007_199_254_740_992.0), 9_007_199_254_740_992);
}

#[test]
fn f64_to_u8_saturates_inside_its_documented_range() {
    for (label, x) in special_f64() {
        let v = f64_to_u8(x);
        // The type already bounds the result; what matters is that the guard
        // rejects the inputs that would make `to_int_unchecked` undefined.
        if x.is_nan() || x <= 0.0 {
            assert_eq!(v, 0, "f64_to_u8({label}) = {v}, expected 0");
        }
    }

    assert_eq!(f64_to_u8(1e300), 255, "out-of-range must clamp to 255");
    assert_eq!(f64_to_u8(255.0), 255);
    assert_eq!(f64_to_u8(254.9), 254, "premise: truncation toward zero");
    assert_eq!(f64_to_u8(7.0), 7);
}

#[test]
fn the_f32_wrappers_agree_with_their_f64_counterparts() {
    // The `f32_*` helpers are thin wrappers that widen to f64 first, so they
    // must not introduce a different answer.
    for x in [0.0f32, -0.0, -1.0, 0.5, 42.0, 255.0, 1e30, f32::MAX, f32::INFINITY, f32::NAN] {
        assert_eq!(
            f32_to_usize(x),
            f64_to_usize(f64::from(x)),
            "f32_to_usize({x}) disagrees with its f64 counterpart"
        );
        assert_eq!(
            f32_to_u8(x),
            f64_to_u8(f64::from(x)),
            "f32_to_u8({x}) disagrees with its f64 counterpart"
        );
    }
}

#[test]
fn f64_to_f32_is_total_over_the_special_domain() {
    let mut divergences = Vec::new();

    for (label, x) in special_f64() {
        let y = f64_to_f32(x);
        // NaN in, NaN out; everything else must come back finite, since the
        // function documents saturation at ±f32::MAX.
        if x.is_nan() {
            assert!(y.is_nan(), "f64_to_f32({label}) lost its NaN");
        } else if !y.is_finite() {
            divergences.push(format!("f64_to_f32({label}) = {y}, not finite"));
        }
    }

    assert!(divergences.is_empty(), "{}", divergences.join("\n"));

    // Premise: sign and magnitude survive an ordinary narrowing.
    assert!((f64_to_f32(1.5) - 1.5).abs() < 1e-6);
    assert!(f64_to_f32(-2.0) < 0.0);
    assert_eq!(f64_to_f32(1e300), f32::MAX, "saturation at f32::MAX");
    assert_eq!(f64_to_f32(-1e300), -f32::MAX);
}
