//! An attribution confidence must always be a finite number in `[0, 1]`.
//!
//! `aggregate_evidence` computes a weighted mean, and the weights come from
//! `AttributionConfig::evidence_weights` — a public, unvalidated field whose
//! whole purpose is to let a caller re-weight (including zero out) a kind of
//! evidence. When every item present is of a zeroed kind the denominator is 0,
//! and `0.0 / 0.0` is NaN. `clamp` does *not* sanitise NaN — it propagates it —
//! so the `[0, 1]` bound that line appears to establish would not hold.
//!
//! The observable symptom is not a panic: `confidence >= min_confidence` is
//! false for NaN, so the actor is silently dropped from the results instead of
//! being reported with no confidence.

use std::collections::{HashMap, HashSet};

use rustre_threatintel::attribution_engine::{
    ActorDatabase, ActorProfile, AttributionConfig, AttributionEngine, InfraNode, TtpCluster,
};

const IOC: &str = "evil.example.com";
const ACTOR: &str = "APT-TEST";

fn actor_profile() -> ActorProfile {
    ActorProfile {
        actor_id: ACTOR.to_string(),
        actor_name: "Test Actor".to_string(),
        mitre_group_id: None,
        known_iocs: HashSet::from([IOC.to_string()]),
        ttp_cluster: TtpCluster {
            actor_id: ACTOR.to_string(),
            techniques: HashSet::new(),
            tactics: HashSet::new(),
        },
        infrastructure: HashSet::new(),
        known_malware_families: HashSet::new(),
        operation_hours: None,
    }
}

fn engine(weights: HashMap<String, f32>) -> AttributionEngine {
    let mut db = ActorDatabase::new();
    db.add_actor(actor_profile());
    AttributionEngine::new(
        db,
        AttributionConfig {
            // Keep every result so nothing is hidden by the threshold itself.
            min_confidence: 0.0,
            max_alternatives: 3,
            evidence_weights: weights,
            ioc_match_half_life_days: None,
        },
    )
}

fn attribute(e: &AttributionEngine) -> Vec<(String, f32, (f32, f32))> {
    let observed_iocs = HashSet::from([IOC.to_string()]);
    let observed_ttps = TtpCluster {
        actor_id: "observed".to_string(),
        techniques: HashSet::new(),
        tactics: HashSet::new(),
    };
    let observed_infra: HashSet<InfraNode> = HashSet::new();
    e.attribute(&observed_iocs, &observed_ttps, &observed_infra, &[])
        .into_iter()
        .map(|r| (r.actor_id, r.confidence, r.confidence_interval))
        .collect()
}

#[test]
fn the_matching_actor_is_reported_with_default_weights() {
    // Premise for the tests below: this setup really does produce a result, so
    // a later empty list means something was dropped, not that the fixture is
    // simply not matching anything.
    let results = attribute(&engine(HashMap::new()));
    assert_eq!(
        results.len(),
        1,
        "premise: the observed IoC matches the actor and must yield one result"
    );
    assert_eq!(results[0].0, ACTOR);
    assert!(
        results[0].1 > 0.0,
        "premise: with default weights the confidence is positive, got {}",
        results[0].1
    );
}

#[test]
fn zeroing_every_weight_does_not_make_the_actor_disappear() {
    // Zeroing a weight is the documented way to disable a kind of evidence. It
    // must lower the confidence, not delete the result.
    let weights = HashMap::from([("IoCMatch".to_string(), 0.0)]);
    let results = attribute(&engine(weights));

    assert_eq!(
        results.len(),
        1,
        "an actor with zero-weighted evidence must still be reported (as no confidence), \
         not silently dropped — a NaN confidence fails `>= min_confidence` and vanishes"
    );
    assert_eq!(results[0].1, 0.0, "zero total weight means zero confidence");
}

#[test]
fn confidence_and_interval_are_always_finite_and_in_range() {
    let mut checked = 0usize;
    // `evidence_weights` is a public `HashMap<String, f32>` with no validation,
    // so the domain includes the special values, not just the ordinary ones.
    // NaN is the one that matters: every comparison with it is false, so a
    // guard written `total_weight <= 0.0` lets it through untouched.
    for weight in [
        0.0f32,
        0.5,
        1.0,
        1e-9,
        f32::NAN,
        -1.0,
        f32::INFINITY,
    ] {
        let weights = HashMap::from([("IoCMatch".to_string(), weight)]);
        for (actor, confidence, (lo, hi)) in attribute(&engine(weights.clone())) {
            assert!(
                confidence.is_finite(),
                "{actor}: confidence is not finite ({confidence}) with weight {weight}"
            );
            assert!(
                (0.0..=1.0).contains(&confidence),
                "{actor}: confidence {confidence} outside [0,1] with weight {weight}"
            );
            assert!(
                lo.is_finite() && hi.is_finite(),
                "{actor}: confidence interval ({lo}, {hi}) is not finite with weight {weight}"
            );
            assert!(
                lo <= hi,
                "{actor}: interval is inverted ({lo} > {hi}) with weight {weight}"
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked, 7,
        "anti-vacuity: every weight must have produced exactly one result to check — \
         a NaN weight that silently drops the actor shows up here as a missing result"
    );
}
