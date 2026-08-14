//! `ScoreComponents::total()` is the single funnel through which all six public
//! scoring dimensions pass, and its `clamp(0.0, 100.0)` is what the rest of the
//! crate relies on for a bounded score.
//!
//! Each field's doc states an intended range (`0.0–25.0`, `-10.0–10.0`, …), but
//! they are plain `pub f64` with a `Default` derive and no validation —
//! `analyst_override` in particular is *meant* to be written directly. `clamp`
//! does not sanitise NaN, so one non-finite component (or `inf - inf` between a
//! bonus and the staleness penalty) makes the total NaN.
//!
//! The symptom is not a panic and not an out-of-range number: `exceeds(t)` is
//! `false` for NaN at *every* threshold, so the IoC silently disappears from
//! every filtered result rather than scoring high or low.

use rustre_threatintel::threat_score_calculator::{ScoreComponents, ThreatScore};

fn special_f64() -> Vec<(&'static str, f64)> {
    vec![
        ("zero", 0.0),
        ("neg zero", -0.0),
        ("in range", 12.5),
        ("above range", 1e9),
        ("negative", -50.0),
        ("pos infinity", f64::INFINITY),
        ("neg infinity", f64::NEG_INFINITY),
        ("NaN", f64::NAN),
    ]
}

/// Set one field at a time, leaving the rest at their `Default`.
fn with_field(index: usize, v: f64) -> ScoreComponents {
    let mut c = ScoreComponents::default();
    match index {
        0 => c.ioc_type_base = v,
        1 => c.corroboration = v,
        2 => c.severity_uplift = v,
        3 => c.staleness_penalty = v,
        4 => c.enrichment_bonus = v,
        _ => c.analyst_override = v,
    }
    c
}

const FIELDS: [&str; 6] = [
    "ioc_type_base",
    "corroboration",
    "severity_uplift",
    "staleness_penalty",
    "enrichment_bonus",
    "analyst_override",
];

#[test]
fn the_total_is_bounded_for_every_special_value_of_every_component() {
    let cases = special_f64();
    let mut checked = 0usize;

    for (index, field) in FIELDS.iter().enumerate() {
        for (label, v) in &cases {
            let total = with_field(index, *v).total();
            assert!(
                total.is_finite(),
                "total() with {field} = {label} is {total}, not finite"
            );
            assert!(
                (0.0..=100.0).contains(&total),
                "total() with {field} = {label} is {total}, outside [0,100]"
            );
            checked += 1;
        }
    }

    assert_eq!(
        checked,
        FIELDS.len() * cases.len(),
        "anti-vacuity: every field/value pair must have been exercised"
    );
}

#[test]
fn opposing_infinities_do_not_produce_a_nan_total() {
    // `inf - inf` is NaN, and this is the one combination reachable without any
    // NaN input at all: a bonus and the staleness penalty are on opposite sides
    // of the sum.
    let mut c = ScoreComponents::default();
    c.enrichment_bonus = f64::INFINITY;
    c.staleness_penalty = f64::INFINITY;

    let total = c.total();
    assert!(total.is_finite(), "inf - inf produced {total}");
    assert!((0.0..=100.0).contains(&total));
}

#[test]
fn a_non_finite_component_cannot_hide_the_ioc_from_every_threshold() {
    let mut c = ScoreComponents::default();
    c.ioc_type_base = 20.0;
    c.analyst_override = f64::NAN;

    let score = ThreatScore::new("evil.example.com", c);
    assert!(
        score.score.is_finite(),
        "score is {}, not finite — it would fail `exceeds` at every threshold",
        score.score
    );
    // The decisive property: a NaN score answers `false` to every threshold,
    // including 0.0, which no finite score in [0,100] can do.
    assert!(
        score.exceeds(0.0),
        "a score of {} does not exceed 0.0, so the IoC vanishes from every filter",
        score.score
    );
}

#[test]
fn ordinary_components_still_add_up() {
    // Premise: the assertions above are not passing because `total()` collapses
    // everything to the fallback.
    let mut c = ScoreComponents::default();
    c.ioc_type_base = 20.0;
    c.corroboration = 10.0;
    c.staleness_penalty = 5.0;

    let total = c.total();
    assert!(
        (total - 25.0).abs() < 1e-9,
        "premise: 20 + 10 - 5 must be 25, got {total}"
    );
}
