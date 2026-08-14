//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact output the audit predicted.

use rustre_analysis_string::encoding_detect::estimate_xor_key_length;
use rustre_analysis_string::unicode_detector::{auto_detect_encoding, UnicodeEncoding};

// ── auto_detect_encoding: UTF-16 threshold ─────────────────────────────────

/// The UTF-16 test required 5 qualifying 2-byte units but only ever inspected
/// `chunks(2).take(8)` of an input gated at `len >= 8`. An 8- or 9-byte input
/// has only 4 units, so the threshold was UNREACHABLE and every short UTF-16
/// string — which is most of the interesting ones in a binary — was
/// misreported as ASCII.
#[test]
fn short_utf16le_strings_are_detected() {
    assert_eq!(
        auto_detect_encoding(b"t\0e\0s\0t\0"),
        UnicodeEncoding::Utf16Le,
        "8 bytes of perfectly formed UTF-16LE"
    );
    assert_eq!(
        auto_detect_encoding(b"e\0x\0i\0t\0"),
        UnicodeEncoding::Utf16Le
    );
}

#[test]
fn short_utf16be_strings_are_detected() {
    assert_eq!(
        auto_detect_encoding(b"\0t\0e\0s\0t"),
        UnicodeEncoding::Utf16Be
    );
}

/// Longer UTF-16LE was already detected and must stay detected.
#[test]
fn long_utf16le_is_still_detected() {
    assert_eq!(
        auto_detect_encoding(b"h\0e\0l\0l\0o\0w\0o\0r\0l\0d\0"),
        UnicodeEncoding::Utf16Le
    );
}

/// Plain ASCII must NOT be promoted to UTF-16 — the fix must not simply lower
/// the bar until everything matches.
#[test]
fn plain_ascii_is_not_mistaken_for_utf16() {
    assert_eq!(auto_detect_encoding(b"abcdefgh"), UnicodeEncoding::Ascii);
    assert_eq!(
        auto_detect_encoding(b"/usr/bin/env sh"),
        UnicodeEncoding::Ascii
    );
}

/// A run with only a couple of incidental zero bytes is not UTF-16 either.
#[test]
fn sparse_zero_bytes_do_not_imply_utf16() {
    // Two zeros out of eight units: well below any sane proportion.
    assert_ne!(
        auto_detect_encoding(b"ab\0defgh\0jklmno"),
        UnicodeEncoding::Utf16Le
    );
}

// ── estimate_xor_key_length: documented contract ───────────────────────────

/// The doc-comment promised an Index of Coincidence sorted DESCENDING, where
/// higher is better. The body computes a normalised Hamming distance and sorts
/// ASCENDING, where LOWER is better. The code was self-consistent — the
/// in-crate caller takes the first three — but anything written against the
/// documented contract would have taken the last entry and got the worst
/// candidate. These tests pin the real contract so the two cannot drift again.
#[test]
fn key_length_candidates_are_sorted_best_first() {
    // "attack at dawn" repeated, XORed with a 3-byte key.
    let plain = b"attackatdawnattackatdawnattackatdawnattackatdawn";
    let key = [0x13u8, 0x37, 0x5A];
    let data: Vec<u8> = plain
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    let scores = estimate_xor_key_length(&data, 12);
    assert!(!scores.is_empty());

    for w in scores.windows(2) {
        assert!(
            w[0].1 <= w[1].1,
            "candidates must come out ascending (best first), got {scores:?}"
        );
    }
}

/// Every score is a mean popcount-per-byte, so it lives in `0.0..=8.0` — it is
/// emphatically not an index of coincidence near 0.065.
#[test]
fn scores_are_hamming_distances_not_indices_of_coincidence() {
    let data: Vec<u8> = (0..200u32).map(|i| (i as u8) ^ 0x5A).collect();
    for (kl, score) in estimate_xor_key_length(&data, 16) {
        assert!(
            (0.0..=8.0).contains(&score) || score == f64::MAX,
            "key length {kl} scored {score}, outside the popcount-per-byte range"
        );
    }
}

/// The true period must rank ahead of a length that shares no factor with it.
#[test]
fn the_real_period_outranks_an_unrelated_length() {
    let plain: Vec<u8> = b"the quick brown fox jumps over the lazy dog ".repeat(6);
    let key = [0xAAu8, 0x55, 0xF0, 0x0F];
    let data: Vec<u8> = plain
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    let scores = estimate_xor_key_length(&data, 12);
    let pos = |k: usize| scores.iter().position(|&(kl, _)| kl == k);
    let (Some(p4), Some(p7)) = (pos(4), pos(7)) else {
        panic!("both candidates should be present: {scores:?}");
    };
    assert!(
        p4 < p7,
        "the real 4-byte period must rank ahead of 7: {scores:?}"
    );
}

// ── StringClusterer: similarity_scores reference point ─────────────────────

use rustre_analysis_string::string_clusterer::{
    normalized_edit_similarity, ClusterAlgorithm, StringClusterer, StringRef,
};

fn refs(vals: &[&str]) -> Vec<StringRef> {
    vals.iter()
        .enumerate()
        .map(|(i, v)| StringRef::new(i as u64 * 0x10, *v))
        .collect()
}

/// `similarity_scores` is documented as "Pairwise similarity of each member to
/// the CENTROID", but the greedy algorithms filled it while accumulating —
/// i.e. against the SEED string — and only afterwards picked a centroid, which
/// is often a different member. Every score then referred to a string that is
/// not the one the cluster reports as its centre, and `average_similarity()`
/// was computed from those wrong numbers.
///
/// `cluster_fingerprint` in the same file already computes the scores AFTER
/// choosing the centroid.
#[test]
fn edit_distance_scores_are_measured_against_the_centroid() {
    let c = StringClusterer::new(ClusterAlgorithm::EditDistance, 0.5);
    let report = c.cluster(refs(&["aaaa", "aaab", "aabb"]));

    let cluster = report
        .clusters
        .iter()
        .find(|cl| cl.members.len() == 3)
        .expect("all three cluster together");

    for (m, score) in cluster.members.iter().zip(&cluster.similarity_scores) {
        let expected = normalized_edit_similarity(&m.value, &cluster.centroid);
        assert!(
            (score - expected).abs() < 1e-9,
            "member {:?} scored {score} but its similarity to the centroid \
             {:?} is {expected}",
            m.value,
            cluster.centroid
        );
    }
}

/// The centroid must score 1.0 against itself — the clearest symptom of the
/// scores referring to a different string.
#[test]
fn the_centroid_scores_one_against_itself() {
    for algo in [ClusterAlgorithm::EditDistance, ClusterAlgorithm::Ngram] {
        let c = StringClusterer::new(algo.clone(), 0.4);
        let report = c.cluster(refs(&["aaaa", "aaab", "aabb"]));
        for cluster in &report.clusters {
            let Some(pos) = cluster
                .members
                .iter()
                .position(|m| m.value == cluster.centroid)
            else {
                continue;
            };
            assert!(
                (cluster.similarity_scores[pos] - 1.0).abs() < 1e-9,
                "{algo:?}: the centroid {:?} must score 1.0, got {}",
                cluster.centroid,
                cluster.similarity_scores[pos]
            );
        }
    }
}

/// Structural invariant: one score per member, always.
#[test]
fn there_is_exactly_one_score_per_member() {
    for algo in [
        ClusterAlgorithm::EditDistance,
        ClusterAlgorithm::Ngram,
        ClusterAlgorithm::Fingerprint,
    ] {
        let c = StringClusterer::new(algo.clone(), 0.4);
        let report = c.cluster(refs(&["error: %s", "error: %d", "warning: %s", "zzz"]));
        for cluster in &report.clusters {
            assert_eq!(
                cluster.members.len(),
                cluster.similarity_scores.len(),
                "{algo:?}: {} members but {} scores",
                cluster.members.len(),
                cluster.similarity_scores.len()
            );
        }
    }
}
