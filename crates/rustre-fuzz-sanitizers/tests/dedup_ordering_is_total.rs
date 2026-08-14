//! The deduplicator's bucket choices must not depend on `HashMap` order.
//!
//! Both the fuzzy-match in `add` and `buckets_by_severity` read from a
//! `HashMap`. Rust's default hasher is re-seeded every process, so any place
//! that resolves a tie by "whichever the map yielded first" produces output
//! that changes between runs of the same binary on the same input — a poor
//! property for a crash deduplicator, whose whole job is stable grouping.
//!
//! These tests pin the tie-breaks as *total* orders rather than asserting any
//! particular bucket count, so they stay valid independently of the clustering
//! policy.

use std::time::Instant;

use rustre_fuzz_sanitizers::crash_deduplicator::{CrashDeduplicator, RawCrash, StackFrame};
use rustre_fuzz_sanitizers::sanitizer_crash_deduplicator::{
    CrashSource, SanitizerCrashDeduplicator,
};

fn frame(index: u32, function: &str) -> StackFrame {
    StackFrame {
        index,
        address: 0x4000 + u64::from(index),
        function: Some(function.to_string()),
        module: Some("target".to_string()),
        offset: Some(0x10),
        file: Some("src/a.c".to_string()),
        line: Some(10 + index),
    }
}

fn crash(kind: &str, functions: &[&str]) -> RawCrash {
    RawCrash {
        id: 0,
        crash_type_str: kind.to_string(),
        is_write: false,
        fault_address: Some(0x6020_0000_0018),
        stack_frames: functions
            .iter()
            .enumerate()
            .map(|(i, f)| frame(u32::try_from(i).unwrap(), f))
            .collect(),
        input: vec![1, 2, 3],
        description: format!("{kind} in {}", functions.first().copied().unwrap_or("?")),
        discovered_at: Instant::now(),
    }
}

/// Distinct crashes that bucket separately under exact (non-fuzzy) matching.
fn distinct_crashes() -> Vec<RawCrash> {
    vec![
        crash("heap-buffer-overflow", &["parse", "main"]),
        crash("heap-buffer-overflow", &["decode", "run", "main"]),
        crash("heap-use-after-free", &["free_it", "main"]),
        crash("heap-use-after-free", &["reuse", "dispatch", "main"]),
    ]
}

fn build() -> CrashDeduplicator {
    let mut d = CrashDeduplicator::new().with_fuzzy_distance(0);
    for c in distinct_crashes() {
        d.add(c);
    }
    d
}

#[test]
fn buckets_by_severity_is_a_total_order() {
    let d = build();
    let buckets = d.buckets_by_severity();

    assert!(
        buckets.len() >= 2,
        "anti-vacuity: need at least two buckets to have an order at all, got {}",
        buckets.len()
    );

    // Count the ties actually exercised, so a future fixture that accidentally
    // gives every bucket a distinct severity cannot make this vacuous.
    let mut ties = 0usize;
    for pair in buckets.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        assert!(
            a.max_exploitability >= b.max_exploitability,
            "severity must be descending: {:?} came before {:?}",
            a.max_exploitability,
            b.max_exploitability
        );
        if a.max_exploitability == b.max_exploitability {
            ties += 1;
            assert!(
                a.bucket_id < b.bucket_id,
                "equal severity must be broken by ascending bucket_id, \
                 got {} before {}",
                a.bucket_id,
                b.bucket_id
            );
        }
    }
    assert!(
        ties >= 1,
        "anti-vacuity: the fixture must produce at least one severity tie, \
         otherwise the tie-break is never exercised"
    );
}

#[test]
fn the_same_input_always_produces_the_same_bucket_order() {
    let first: Vec<u64> = build().buckets_by_severity().iter().map(|b| b.bucket_id).collect();
    let second: Vec<u64> = build().buckets_by_severity().iter().map(|b| b.bucket_id).collect();

    assert!(!first.is_empty(), "anti-vacuity: no buckets were produced");
    assert_eq!(
        first, second,
        "identical input produced two different bucket orders"
    );
}

#[test]
fn the_same_input_always_produces_the_same_bucketing() {
    // Same crashes, fuzzy matching on: the (crash_id, bucket_id) assignment
    // must be reproducible.
    let run = || {
        let mut d = CrashDeduplicator::new().with_fuzzy_distance(2);
        distinct_crashes()
            .into_iter()
            .map(|c| {
                let (id, bucket, _is_new) = d.add(c);
                (id, bucket)
            })
            .collect::<Vec<_>>()
    };

    let a = run();
    let b = run();
    assert_eq!(a.len(), 4, "anti-vacuity: all four crashes must be added");
    assert_eq!(a, b, "identical input produced two different bucketings");
}

/// The same ordering rule applies to the crate's *other* deduplicator.
///
/// `SanitizerCrashDeduplicator::hot_clusters` sorts clusters read out of a
/// `HashMap` by hit count. Without a tie-break it is the exact twin of
/// `buckets_by_severity`, so it is held to the same property here rather than
/// left to be rediscovered later.
fn build_clusters() -> SanitizerCrashDeduplicator {
    let mut d = SanitizerCrashDeduplicator::new(3);
    // Four distinct clusters, hit once each — every pair is a tie.
    for key in ["alpha", "beta", "gamma", "delta"] {
        d.add_raw_key(
            key,
            CrashSource::ASan,
            format!("raw {key}"),
            format!("summary {key}"),
        );
    }
    d
}

#[test]
fn hot_clusters_is_a_total_order() {
    let d = build_clusters();
    let hot = d.hot_clusters(1);

    assert!(
        hot.len() >= 2,
        "anti-vacuity: need at least two clusters, got {}",
        hot.len()
    );

    let mut ties = 0usize;
    for pair in hot.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        assert!(
            a.hit_count >= b.hit_count,
            "hit count must be descending: {} came before {}",
            a.hit_count,
            b.hit_count
        );
        if a.hit_count == b.hit_count {
            ties += 1;
            assert!(
                a.hash.0 < b.hash.0,
                "equal hit counts must be broken by ascending hash, got {} before {}",
                a.hash.0,
                b.hash.0
            );
        }
    }
    assert!(
        ties >= 1,
        "anti-vacuity: the fixture must produce at least one hit-count tie"
    );
}

#[test]
fn hot_clusters_order_is_reproducible() {
    let first: Vec<u64> = build_clusters().hot_clusters(1).iter().map(|c| c.hash.0).collect();
    let second: Vec<u64> = build_clusters().hot_clusters(1).iter().map(|c| c.hash.0).collect();

    assert_eq!(first.len(), 4, "anti-vacuity: all four clusters must appear");
    assert_eq!(
        first, second,
        "identical input produced two different cluster orders"
    );
}
