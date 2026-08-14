//! `AggregationStrategy::BayesianUpdate` divides by `1.0 - s*w + 0.001`, which
//! is **exactly zero** when `s * w == 1.001` — not an approximation, an exact
//! binary-representable hit. The result is `inf`, then `inf / (1 + inf)` is NaN,
//! and once `p` is NaN it stays NaN for every remaining signal; the trailing
//! `clamp` propagates it.
//!
//! The setup is deterministic on purpose: `TiProvider::Misp` has `base_weight`
//! 1.0, and a `DecayConfig` with `floor: 1.0` pins the decay multiplier to 1.0
//! (the implementation ends with `decayed.max(self.floor)` and `decayed <= 1`).
//! So the effective weight is exactly `provider_confidence`, and `s * w` is
//! exactly `raw_score * provider_confidence` — the singularity is hit, not
//! approached.

use rustre_threatintel::threat_scorer::{
    AggregationStrategy, ContextBoost, DecayConfig, ScorerConfig, SourceSignal, ThreatScorer,
    TiProvider,
};

fn scorer() -> ThreatScorer {
    ThreatScorer::new(ScorerConfig {
        decay: DecayConfig {
            half_life_secs: 30 * 24 * 3600,
            // Pins the decay multiplier to exactly 1.0 for any timestamp, so
            // this test does not depend on the current clock.
            floor: 1.0,
        },
        aggregation: AggregationStrategy::BayesianUpdate,
        max_boost: 0.4,
        apply_sigmoid: true,
    })
}

fn signal(raw_score: f32, provider_confidence: f32) -> SourceSignal {
    SourceSignal {
        provider: TiProvider::Misp,
        raw_score,
        observed_at: 1_700_000_000,
        provider_confidence: Some(provider_confidence),
        tags: Vec::new(),
    }
}

fn specials() -> Vec<(&'static str, f32)> {
    vec![
        ("zero", 0.0),
        ("half", 0.5),
        ("one", 1.0),
        // `raw_score * conf == 1.001` makes the likelihood-ratio denominator
        // exactly 0.0.
        ("the singularity", 1.001),
        ("just past it", 1.002),
        ("negative", -1.0),
        ("large", 1e9),
        ("pos infinity", f32::INFINITY),
        ("neg infinity", f32::NEG_INFINITY),
        ("NaN", f32::NAN),
    ]
}

#[test]
fn the_exact_singularity_does_not_produce_a_nan_score() {
    // s * w == 1.0 * 1.001 == 1.001 → denominator `1.0 - 1.001 + 0.001` == 0.0.
    let breakdown = scorer().score(&[signal(1.0, 1.001)], &[]);

    assert!(
        breakdown.final_score.is_finite(),
        "final_score is {}, not finite",
        breakdown.final_score
    );
    assert!(
        (0.0..=1.0).contains(&breakdown.final_score),
        "final_score {} is outside [0,1]",
        breakdown.final_score
    );
}

#[test]
fn one_malformed_signal_does_not_erase_the_others() {
    // The decisive property: a poisoned `p` stays poisoned for every subsequent
    // signal, so a single bad source would wipe out all the good evidence that
    // follows it. The bad signal is placed FIRST for exactly that reason.
    let good_only = scorer().score(&[signal(0.9, 1.0), signal(0.8, 1.0)], &[]);
    let with_bad = scorer().score(
        &[signal(1.0, 1.001), signal(0.9, 1.0), signal(0.8, 1.0)],
        &[],
    );

    assert!(
        good_only.final_score > 0.0,
        "premise: two strong signals must score above zero, got {}",
        good_only.final_score
    );
    assert!(
        with_bad.final_score.is_finite(),
        "final_score is {}, not finite",
        with_bad.final_score
    );
    assert!(
        with_bad.final_score > 0.0,
        "a single malformed signal erased all subsequent evidence: {} vs {}",
        with_bad.final_score,
        good_only.final_score
    );
}

#[test]
fn the_score_is_total_over_the_special_domain() {
    let cases = specials();
    let mut checked = 0usize;

    for (slabel, s) in &cases {
        for (clabel, c) in &cases {
            let breakdown = scorer().score(&[signal(*s, *c)], &[]);
            assert!(
                breakdown.final_score.is_finite(),
                "raw_score={slabel}, confidence={clabel}: final_score is {}",
                breakdown.final_score
            );
            assert!(
                (0.0..=1.0).contains(&breakdown.final_score),
                "raw_score={slabel}, confidence={clabel}: final_score {} outside [0,1]",
                breakdown.final_score
            );
            assert!(
                breakdown.weighted_mean.is_finite(),
                "raw_score={slabel}, confidence={clabel}: weighted_mean is {}",
                breakdown.weighted_mean
            );
            checked += 1;
        }
    }

    assert_eq!(
        checked,
        cases.len() * cases.len(),
        "anti-vacuity: every raw_score/confidence pair must have been exercised"
    );
}

#[test]
fn a_context_boost_cannot_unbound_the_score() {
    let cases = specials();
    let mut checked = 0usize;

    for (label, boost) in &cases {
        let breakdown = scorer().score(
            &[signal(0.7, 1.0)],
            &[ContextBoost {
                label: (*label).to_string(),
                boost: *boost,
            }],
        );
        assert!(
            breakdown.final_score.is_finite(),
            "boost={label}: final_score is {}",
            breakdown.final_score
        );
        assert!(
            (0.0..=1.0).contains(&breakdown.final_score),
            "boost={label}: final_score {} outside [0,1]",
            breakdown.final_score
        );
        checked += 1;
    }

    assert_eq!(checked, cases.len(), "anti-vacuity: every boost exercised");
}
