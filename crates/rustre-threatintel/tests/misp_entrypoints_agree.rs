//! `MispFeed::from_json` and `from_bytes` are two doors into the same parser
//! and must not disagree about what they accept.
//!
//! `MAX_FEED_BYTES` was enforced by `from_bytes` only, so the same feed was
//! size-limited when passed as `&[u8]` and unbounded when passed as `&str` —
//! the same asymmetry already found and fixed in `StixBundle`.
//!
//! The over-limit case is deliberately not exercised: the constant is 256 MiB
//! and allocating that in a unit test costs more than it proves. What is
//! checked is the property that makes the limit meaningful — the two entry
//! points agree on every input they are given.

use rustre_threatintel::misp_feed_reader::MispFeed;

/// Shaped after the module's own fixtures: an event is wrapped in `"Event"`,
/// and a feed may also be a top-level array of such wrappers.
fn event_wrapper(uuid: &str, info: &str) -> String {
    format!(r#"{{"Event":{{"uuid":"{uuid}","info":"{info}"}}}}"#)
}

fn event_array(n: usize) -> String {
    let items: Vec<String> = (0..n)
        .map(|i| event_wrapper(&format!("evt-{i:04}"), &format!("Event {i}")))
        .collect();
    format!("[{}]", items.join(","))
}

/// Inputs spanning well-formed feeds and several shapes of malformed input.
fn corpus() -> Vec<(&'static str, String)> {
    vec![
        ("single event", event_wrapper("evt-1", "Test campaign")),
        ("empty array", event_array(0)),
        ("array of one", event_array(1)),
        ("array of many", event_array(64)),
        ("manifest-shaped object", r#"{"hello":"world"}"#.to_string()),
        ("not json at all", "definitely not json".to_string()),
        ("truncated json", r#"[{"Event":{"uuid":"#.to_string()),
        ("scalar at top level", "42".to_string()),
        ("empty string", String::new()),
    ]
}

#[test]
fn both_entry_points_accept_and_reject_the_same_inputs() {
    let cases = corpus();
    assert!(cases.len() >= 9, "anti-vacuity: expected the full corpus");

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for (label, json) in &cases {
        let via_str = MispFeed::from_json(json);
        let via_bytes = MispFeed::from_bytes(json.as_bytes());

        assert_eq!(
            via_str.is_ok(),
            via_bytes.is_ok(),
            "case `{label}`: from_json ok={} but from_bytes ok={}",
            via_str.is_ok(),
            via_bytes.is_ok()
        );

        if let (Ok(a), Ok(b)) = (&via_str, &via_bytes) {
            assert_eq!(
                a.len(),
                b.len(),
                "case `{label}`: the two entry points parsed a different number of events"
            );
            accepted += 1;
        } else {
            rejected += 1;
        }
    }

    // Both outcomes must actually occur, or the agreement is trivial.
    assert!(
        accepted >= 3,
        "anti-vacuity: expected several accepted feeds, got {accepted}"
    );
    assert!(
        rejected >= 2,
        "anti-vacuity: expected several rejected inputs, got {rejected}"
    );
}

#[test]
fn the_documented_limit_is_the_same_for_both_doors() {
    // The constant's doc names both entry points; this pins that it is a single
    // shared value rather than two independently drifting ones.
    assert_eq!(MispFeed::MAX_FEED_BYTES, 256 * 1024 * 1024);

    let feed = MispFeed::from_json(&event_array(4)).expect("premise: the fixture is a valid feed");
    assert_eq!(feed.len(), 4, "premise: the fixture has 4 events");
}
