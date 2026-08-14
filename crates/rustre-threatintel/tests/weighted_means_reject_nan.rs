//! Every weighted mean in this crate divides by a sum of caller-supplied
//! weights, and each one guarded that denominator — but in a form NaN walks
//! straight through.
//!
//! `x == 0.0`, `x <= 0.0` and `x < EPSILON` are all **false** when `x` is NaN,
//! so a NaN weight reaches the division, and `clamp` propagates NaN rather than
//! bounding it. The result is not a panic: it is a score that silently fails
//! every subsequent comparison (`>= threshold` is false for NaN), so the item
//! disappears from the output instead of being reported.
//!
//! The NaN-safe form is `!(x > 0.0)`. This test pins the property on the public
//! entry points of the class at once, over the full special-value domain — the
//! ordinary values were already covered, NaN was the one nobody fed in.

use rustre_threatintel::attribution_engine::cosine_similarity;
use rustre_threatintel::intel_enricher::MergeStrategy;
use rustre_threatintel::ioc_normalizer::SourceConfidenceScorer;

/// The special values a public `f32` field or parameter can actually hold.
fn special_f32() -> Vec<(&'static str, f32)> {
    vec![
        ("zero", 0.0),
        ("neg zero", -0.0),
        ("one", 1.0),
        ("half", 0.5),
        ("tiny", 1e-9),
        ("negative", -1.0),
        ("pos infinity", f32::INFINITY),
        ("neg infinity", f32::NEG_INFINITY),
        ("NaN", f32::NAN),
    ]
}

#[test]
fn combining_source_confidences_never_yields_a_nan_score() {
    let cases = special_f32();
    assert!(cases.len() >= 9, "anti-vacuity: expected the full domain");

    let mut saw_positive = 0usize;
    let mut saw_degenerate = 0usize;

    for (wlabel, weight) in &cases {
        for (clabel, confidence) in &cases {
            let combined = SourceConfidenceScorer::combine(&[(*confidence, *weight)]);
            assert!(
                combined.is_finite(),
                "combine(confidence={clabel}, weight={wlabel}) = {combined}, not finite"
            );
            assert!(
                (0.0..=1.0).contains(&combined),
                "combine(confidence={clabel}, weight={wlabel}) = {combined}, outside [0,1]"
            );
            if combined > 0.0 {
                saw_positive += 1;
            } else {
                saw_degenerate += 1;
            }
        }
    }

    // Both outcomes must occur, or "always finite and in range" is trivial.
    assert!(
        saw_positive >= 1,
        "anti-vacuity: no input produced a positive score, so the property is vacuous"
    );
    assert!(
        saw_degenerate >= 1,
        "anti-vacuity: no input produced the degenerate score"
    );
}

#[test]
fn a_well_formed_combination_still_averages_as_expected() {
    // Premise: the degenerate cases above are not passing because `combine` is
    // simply returning 0.0 for everything.
    let combined = SourceConfidenceScorer::combine(&[(0.8, 1.0), (0.4, 1.0)]);
    assert!(
        (combined - 0.6).abs() < 1e-6,
        "premise: two equally weighted sources must average, got {combined}"
    );
}

/// `MergeStrategy::merge` is the fifth weighted mean in this crate, and the one
/// a name-based search missed: its divisor is called `weight_total`, not
/// `total_weight`. Two of its four branches never divide at all — they fold with
/// `f32::max`/`f32::min`, which *skip* NaN and so return the ±infinity sentinel
/// they started from when every element is NaN.
#[test]
fn every_merge_strategy_is_total_over_the_special_domain() {
    let strategies = [
        ("Average", MergeStrategy::Average),
        ("Maximum", MergeStrategy::Maximum),
        ("Minimum", MergeStrategy::Minimum),
        ("WeightedFirst", MergeStrategy::WeightedFirst),
    ];
    let cases = special_f32();
    let mut checked = 0usize;

    for (slabel, strategy) in &strategies {
        for (vlabel, v) in &cases {
            for (inputs, ilabel) in [
                (vec![*v], "alone"),
                (vec![*v, 0.5], "followed by a sane value"),
                (vec![0.5, *v], "preceded by a sane value"),
                (vec![*v, *v, *v], "repeated"),
            ] {
                let merged = strategy.merge(&inputs);
                assert!(
                    merged.is_finite(),
                    "{slabel}::merge({vlabel} {ilabel}) = {merged}, not finite"
                );
                checked += 1;
            }
        }
    }

    assert_eq!(
        checked,
        strategies.len() * cases.len() * 4,
        "anti-vacuity: every strategy/value/shape combination must be exercised"
    );

    // Premise: the strategies are not all collapsing to the same fallback.
    assert!((MergeStrategy::Average.merge(&[0.2, 0.8]) - 0.5).abs() < 1e-6);
    assert!((MergeStrategy::Maximum.merge(&[0.2, 0.8]) - 0.8).abs() < 1e-6);
    assert!((MergeStrategy::Minimum.merge(&[0.2, 0.8]) - 0.2).abs() < 1e-6);
}

#[test]
fn cosine_similarity_is_bounded_for_every_special_component() {
    let cases = special_f32();
    let mut checked = 0usize;

    for (label, x) in &cases {
        // A NaN or infinite component makes the norm non-finite; the equality
        // guard used to let that through into `dot / (norm_a * norm_b)`.
        for (a, b) in [
            (vec![*x, 1.0], vec![1.0, 1.0]),
            (vec![1.0, 1.0], vec![*x, 1.0]),
            (vec![*x, *x], vec![*x, *x]),
        ] {
            let sim = cosine_similarity(&a, &b);
            assert!(
                sim.is_finite(),
                "cosine_similarity with a {label} component = {sim}, not finite"
            );
            assert!(
                (-1.0..=1.0).contains(&sim),
                "cosine_similarity with a {label} component = {sim}, outside [-1,1]"
            );
            checked += 1;
        }
    }

    assert_eq!(
        checked,
        cases.len() * 3,
        "anti-vacuity: every special component must have been exercised"
    );

    // Premise: the function is not simply returning 0.0 everywhere.
    let identical = cosine_similarity(&[1.0, 2.0, 3.0], &[1.0, 2.0, 3.0]);
    assert!(
        (identical - 1.0).abs() < 1e-6,
        "premise: identical vectors must have similarity 1, got {identical}"
    );
}
