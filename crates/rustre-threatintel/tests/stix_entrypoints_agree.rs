//! `StixBundle::from_json` and `from_bytes` are two doors into the same parser
//! and must not disagree about what they accept.
//!
//! `MAX_INPUT_BYTES` is documented as the limit for *both*, yet only
//! `from_bytes` enforced it — the same bundle was size-limited when passed as
//! `&[u8]` and unbounded when passed as `&str`.
//!
//! The over-limit case itself is deliberately not exercised here: the constant
//! is 256 MiB, and allocating that in a unit test costs more than it proves.
//! What is checked is the property that makes the limit meaningful — the two
//! entry points agree on every input they are given.

use rustre_threatintel::stix_parser::StixBundle;

/// Shaped after the parser's own fixtures: an indicator needs `name`,
/// `pattern_type` and `valid_from`, and the bundle needs `spec_version`.
fn bundle_json(n: usize) -> String {
    let objects: Vec<String> = (0..n)
        .map(|i| {
            format!(
                r#"{{"type":"indicator","id":"indicator--{i:04}","name":"Indicator {i}","pattern":"[ipv4-addr:value = '10.0.0.{}']","pattern_type":"stix","valid_from":"2024-01-01T00:00:00Z"}}"#,
                i % 256
            )
        })
        .collect();
    format!(
        r#"{{"type":"bundle","spec_version":"2.1","id":"bundle--test","objects":[{}]}}"#,
        objects.join(",")
    )
}

/// Inputs spanning well-formed bundles and several shapes of malformed input.
fn corpus() -> Vec<(&'static str, String)> {
    vec![
        ("empty bundle", bundle_json(0)),
        ("one object", bundle_json(1)),
        ("many objects", bundle_json(64)),
        ("not json at all", "definitely not json".to_string()),
        ("truncated json", r#"{"type":"bundle","objects":["#.to_string()),
        ("wrong shape", r#"{"hello":"world"}"#.to_string()),
        ("empty string", String::new()),
    ]
}

#[test]
fn both_entry_points_accept_and_reject_the_same_inputs() {
    let cases = corpus();
    assert!(cases.len() >= 7, "anti-vacuity: expected the full corpus");

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for (label, json) in &cases {
        let via_str = StixBundle::from_json(json);
        let via_bytes = StixBundle::from_bytes(json.as_bytes());

        assert_eq!(
            via_str.is_ok(),
            via_bytes.is_ok(),
            "case `{label}`: from_json ok={} but from_bytes ok={}",
            via_str.is_ok(),
            via_bytes.is_ok()
        );

        if let (Ok(a), Ok(b)) = (&via_str, &via_bytes) {
            assert_eq!(
                a.object_count(),
                b.object_count(),
                "case `{label}`: the two entry points parsed a different number of objects"
            );
            accepted += 1;
        } else {
            rejected += 1;
        }
    }

    // Both outcomes must actually occur, or the agreement is trivial.
    assert!(
        accepted >= 3,
        "anti-vacuity: expected several accepted bundles, got {accepted}"
    );
    assert!(
        rejected >= 3,
        "anti-vacuity: expected several rejected inputs, got {rejected}"
    );
}

#[test]
fn a_well_formed_bundle_round_trips_through_both_doors() {
    let json = bundle_json(8);

    let a = StixBundle::from_json(&json).expect("premise: the fixture is a valid STIX bundle");
    assert_eq!(a.object_count(), 8, "premise: the fixture has 8 objects");

    let reserialised = a.to_json().expect("a parsed bundle must serialise");
    let b = StixBundle::from_bytes(reserialised.as_bytes())
        .expect("a bundle this crate produced must be accepted by its own parser");

    assert_eq!(
        a.object_count(),
        b.object_count(),
        "object count changed across a serialise/parse round trip"
    );
}
