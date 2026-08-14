//! Publication statistics must not be silently discarded (T2).
//!
//! # Why this one warning out of eighteen
//!
//! T2 recorded "106 clippy warnings" across the three FLIRT crates. Filtered to
//! the crates' own `src/`, there are **18**: 5 in `rustre-flirt`, 3 in
//! `rustre-flirt-gen`, 10 in `rustre-flirt-apply`. The rest belonged to other
//! crates compiled in the same run, or to test code — the same double
//! contamination measured on `typerecov` one iteration earlier, where 197 turned
//! out to be 14.
//!
//! Seventeen of the eighteen are style: `const fn`, missing backticks,
//! `sort_by_key`, a 215-line data table. One had a defect profile —
//! `casting u16 to u8` in a CRC — and turned out to be the algorithm itself,
//! already unified and pinned by an earlier iteration.
//!
//! So nothing needed fixing for correctness. What was worth taking was the
//! `#[must_use]` on `publish_resolved_matches`: its `BridgeStats` is the **only**
//! signal that anything reached the type recovery. A run where every matched
//! name lacked a prototype returns `published: 0` and is otherwise
//! indistinguishable from a successful one — which is exactly how "the bridge
//! works" stayed unquestioned across several iterations until it was measured.
//!
//! Ignoring it is now a compile-time warning, and this test pins the meaning of
//! the value being returned.

use rustre_flirt_apply::typerecov_bridge::{BridgeStats, publish_identifications};

#[test]
fn publishing_nothing_is_reported_and_not_silent() {
    // The case that matters: names nobody has a prototype for. The call
    // succeeds, and only the stats reveal that nothing was published.
    let ids: Vec<(u64, &str)> = vec![
        (0x1000, "__no_such_prototype_aaa"),
        (0x2000, "__no_such_prototype_bbb"),
    ];
    let stats: BridgeStats = publish_identifications(ids.iter().copied());

    assert_eq!(stats.considered, 2, "entrambe le identificazioni considerate");
    assert_eq!(stats.published, 0, "nessun prototipo, nessuna pubblicazione");
    assert_eq!(
        stats.skipped_unknown_prototype, 2,
        "il motivo dello scarto deve essere distinguibile da un successo"
    );
}

#[test]
fn the_counts_account_for_every_identification() {
    // An invariant worth pinning: considered = published + skipped. If they ever
    // stop adding up, an identification is being lost somewhere without any
    // category recording it.
    let ids: Vec<(u64, &str)> = vec![
        (0x1000, "__acrt_iob_func"),
        (0x2000, "__no_such_prototype_zzz"),
        (0x3000, "_matherr"),
    ];
    let stats = publish_identifications(ids.iter().copied());
    assert_eq!(
        stats.considered,
        stats.published + stats.skipped_unknown_prototype,
        "considerate {} != pubblicate {} + scartate {}",
        stats.considered,
        stats.published,
        stats.skipped_unknown_prototype
    );
}

#[test]
fn an_empty_input_publishes_nothing_without_error() {
    let stats = publish_identifications(std::iter::empty::<(u64, &str)>());
    assert_eq!(stats.considered, 0);
    assert_eq!(stats.published, 0);
}
