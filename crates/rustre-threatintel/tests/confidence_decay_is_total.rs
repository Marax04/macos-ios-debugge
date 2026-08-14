//! `ConfidenceDecay::new` clamps `initial_score` into `[0,1]` and forces
//! `half_life_secs >= 1.0` — but both are **public fields**, so those invariants
//! hold only for values that went through the constructor.
//!
//! Built by struct literal (which is what makes the fields public useful, and
//! what `Deserialize` does too), `half_life_secs = 0.0` gives `lambda = +inf`,
//! and `inf * 0.0` — an `age_secs` of zero — is NaN. `exp` and `clamp` both
//! propagate it, so the "score in [0,1]" contract in the doc silently fails.
//!
//! `age_secs` needs no public field at all: it is a caller-supplied parameter.

use rustre_threatintel::confidence::ConfidenceDecay;

fn specials() -> Vec<(&'static str, f64)> {
    vec![
        ("zero", 0.0),
        ("neg zero", -0.0),
        ("one", 1.0),
        ("ordinary", 3600.0),
        ("huge", 1e300),
        ("negative", -1.0),
        ("pos infinity", f64::INFINITY),
        ("neg infinity", f64::NEG_INFINITY),
        ("NaN", f64::NAN),
    ]
}

#[test]
fn the_decayed_score_is_bounded_for_every_field_and_age() {
    let cases = specials();
    let mut checked = 0usize;

    for (hlabel, half_life) in &cases {
        for (ilabel, initial) in &cases {
            for (alabel, age) in &cases {
                // Struct literal on purpose: the constructor's clamping is
                // exactly what a public field lets a caller bypass.
                let decay = ConfidenceDecay {
                    initial_score: *initial,
                    half_life_secs: *half_life,
                };

                let score = decay.score_at_age(*age);
                assert!(
                    score.is_finite(),
                    "half_life={hlabel}, initial={ilabel}, age={alabel}: score is {score}"
                );
                assert!(
                    (0.0..=1.0).contains(&score),
                    "half_life={hlabel}, initial={ilabel}, age={alabel}: score {score} outside [0,1]"
                );
                assert!(
                    decay.score_pct_at_age(*age) <= 100,
                    "half_life={hlabel}, initial={ilabel}, age={alabel}: pct above 100"
                );
                checked += 1;
            }
        }
    }

    assert_eq!(
        checked,
        cases.len().pow(3),
        "anti-vacuity: every half_life/initial/age triple must have been exercised"
    );
}

#[test]
fn the_zero_half_life_and_zero_age_combination_is_the_one_that_broke() {
    // lambda = LN_2 / 0.0 = +inf, and inf * 0.0 = NaN — no NaN input required.
    let decay = ConfidenceDecay {
        initial_score: 0.9,
        half_life_secs: 0.0,
    };
    let score = decay.score_at_age(0.0);
    assert!(score.is_finite(), "score is {score}");
    assert!((0.0..=1.0).contains(&score));
}

#[test]
fn an_ordinary_decay_still_decays() {
    // Premise: the assertions above are not passing because everything now
    // collapses to the fallback.
    let decay = ConfidenceDecay::new(1.0, 100.0);

    let fresh = decay.score_at_age(0.0);
    let one_half_life = decay.score_at_age(100.0);
    let old = decay.score_at_age(1000.0);

    assert!(
        (fresh - 1.0).abs() < 1e-9,
        "premise: a fresh score must equal the initial score, got {fresh}"
    );
    assert!(
        (one_half_life - 0.5).abs() < 1e-9,
        "premise: one half-life must halve the score, got {one_half_life}"
    );
    assert!(
        old < one_half_life,
        "premise: the score must keep decreasing, got {old} after {one_half_life}"
    );
}
