//! `SmcIndicator::confidence` is documented as "a confidence score in the range
//! `[0.0, 1.0]`", and the crate's own unit tests assert `<= 1.0` and `>= 0.0`.
//! `SmcIndicator::new` enforced that with `f32::clamp`, which **propagates NaN**
//! rather than bounding it — so a NaN argument produced a value that fails both
//! assertions.
//!
//! A NaN confidence is worse than an out-of-range one: every comparison with it
//! is false, so the indicator fails each `>= threshold` filter downstream and
//! disappears instead of ranking low. That is the same silent-loss shape found
//! in `SymbolConfidence` in `rustre-symbols`.

use rustre_deobf_smc::{SmcIndicator, SmcKind};

/// The special values an `f32` argument can carry.
fn specials() -> Vec<(&'static str, f32)> {
    vec![
        ("zero", 0.0),
        ("neg zero", -0.0),
        ("half", 0.5),
        ("one", 1.0),
        ("above one", 1.5),
        ("large", 1e30),
        ("negative", -1.0),
        ("pos infinity", f32::INFINITY),
        ("neg infinity", f32::NEG_INFINITY),
        ("NaN", f32::NAN),
    ]
}

#[test]
fn the_constructor_always_produces_a_confidence_in_range() {
    let cases = specials();
    let mut checked = 0usize;
    let mut divergences = Vec::new();

    for (label, v) in &cases {
        let c = SmcIndicator::new(0x10, SmcKind::UnpackLoop, *v).confidence;
        if !c.is_finite() {
            divergences.push(format!("new({label}) = {c}, not finite"));
        } else if !(0.0..=1.0).contains(&c) {
            divergences.push(format!("new({label}) = {c}, outside [0,1]"));
        }
        checked += 1;
    }

    assert_eq!(checked, 10, "anti-vacuity: every special value exercised");
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn a_nan_confidence_cannot_hide_an_indicator_from_every_threshold() {
    // The decisive consequence rather than "the value is finite": an indicator
    // whose confidence fails `>= 0.0` can never pass any filter, at any
    // setting. No value in [0,1] can do that.
    let ind = SmcIndicator::new(0x10, SmcKind::UnpackLoop, f32::NAN);

    assert!(
        ind.confidence >= 0.0,
        "a NaN-derived confidence ({}) passes no threshold at all, so the \
         indicator is dropped from every filtered result",
        ind.confidence
    );
}

#[test]
fn ordinary_values_are_untouched_and_the_bounds_saturate() {
    // Premise: the assertions above are not passing because every input now
    // collapses onto one value.
    assert!((SmcIndicator::new(0, SmcKind::UnpackLoop, 0.65).confidence - 0.65).abs() < 1e-6);
    assert!((SmcIndicator::new(0, SmcKind::UnpackLoop, 2.0).confidence - 1.0).abs() < 1e-6);
    assert!((SmcIndicator::new(0, SmcKind::UnpackLoop, -3.0).confidence - 0.0).abs() < 1e-6);
    assert!(
        SmcIndicator::new(0, SmcKind::UnpackLoop, 0.9).confidence
            > SmcIndicator::new(0, SmcKind::UnpackLoop, 0.1).confidence
    );
}
