//! Arithmetic laws of Shannon entropy, and agreement between the crate's
//! several implementations of it.
//!
//! The crate computes byte entropy in three independent places — `shannon_entropy`,
//! `shannon_entropy_f32`, and `FrequencyHistogram::entropy` — and every consumer
//! (packer detection, section analysis, heatmaps) branches on the result against
//! fixed thresholds. Two implementations that disagree cannot both be right, and
//! the disagreement is invisible from inside any one of them.
//!
//! Entropy also has laws that hold by definition, not by convention: it depends
//! only on the *multiset of byte counts*, so it is unchanged by reordering the
//! data or by relabelling the byte values bijectively. Those are checkable
//! exactly, with no threshold to argue about.

use rustre_triage_entropy::entropy_heuristics::{compute_entropy, FrequencyHistogram};
use rustre_triage_entropy::shannon::byte_entropy;
use rustre_triage_entropy::{shannon_entropy, shannon_entropy_f32};

/// Deterministic noise — reproducible failures, no external crates.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut s = seed;
    (0..n)
        .map(|_| {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (s >> 24) as u8
        })
        .collect()
}

/// A spread of inputs covering the whole entropy range: constant, textual,
/// structured, and random.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("single byte", vec![0x41]),
        ("constant", vec![0xAA; 1024]),
        ("two values", [vec![0u8; 512], vec![1u8; 512]].concat()),
        ("ascii text", b"the quick brown fox jumps over the lazy dog".repeat(20)),
        ("all 256 once", (0..=255u8).collect()),
        ("all 256 x4", (0..=255u8).cycle().take(1024).collect()),
        ("random", noise(4096, 0xDEAD_BEEF)),
        ("random small", noise(37, 0x1234_5678)),
    ]
}

/// All implementations of byte entropy must agree.
#[test]
fn every_implementation_agrees() {
    for (name, data) in corpus() {
        let base = shannon_entropy(&data);

        assert!(
            (byte_entropy(&data) - base).abs() < 1e-12,
            "{name}: shannon::byte_entropy gave {}, shannon_entropy gave {base}",
            byte_entropy(&data)
        );
        assert!(
            (compute_entropy(&data) - base).abs() < 1e-9,
            "{name}: entropy_heuristics::compute_entropy gave {}, shannon_entropy gave {base}",
            compute_entropy(&data)
        );
        assert!(
            (FrequencyHistogram::from_data(&data).entropy() - base).abs() < 1e-9,
            "{name}: FrequencyHistogram::entropy gave {}, shannon_entropy gave {base}",
            FrequencyHistogram::from_data(&data).entropy()
        );
        // f32 carries ~7 decimal digits; compare at a width it can represent.
        assert!(
            (f64::from(shannon_entropy_f32(&data)) - base).abs() < 1e-4,
            "{name}: shannon_entropy_f32 gave {}, shannon_entropy gave {base}",
            shannon_entropy_f32(&data)
        );
    }
}

/// Entropy of a byte stream is bounded by 0 and 8 bits per byte, by definition.
#[test]
fn entropy_stays_within_its_definition() {
    for (name, data) in corpus() {
        let h = shannon_entropy(&data);
        assert!(
            (0.0..=8.0).contains(&h),
            "{name}: entropy {h} lies outside the range 0..=8 bits per byte"
        );
        assert!(h.is_finite(), "{name}: entropy is {h}, not a finite number");
    }
}

/// Data with one distinct value carries no information: entropy is exactly zero.
#[test]
fn constant_data_has_zero_entropy() {
    for b in [0u8, 1, 0x41, 0xFF] {
        for len in [1usize, 2, 1024] {
            let h = shannon_entropy(&vec![b; len]);
            assert!(
                h.abs() < 1e-12,
                "{len} copies of {b:#04x} gave entropy {h}, expected exactly 0"
            );
        }
    }
}

/// A uniform distribution over all 256 values attains the maximum, exactly 8.
#[test]
fn a_uniform_distribution_attains_the_maximum() {
    for reps in [1usize, 2, 7] {
        let data: Vec<u8> = (0..=255u8).cycle().take(256 * reps).collect();
        let h = shannon_entropy(&data);
        assert!(
            (h - 8.0).abs() < 1e-12,
            "each of the 256 values appearing {reps} time(s) gave entropy {h}, \
             expected exactly 8"
        );
    }
}

/// Entropy depends only on the multiset of byte counts, so reordering the data
/// cannot change it.
///
/// A failure here means the computation is sensitive to position — it is
/// measuring something other than the byte distribution.
#[test]
fn entropy_is_invariant_under_reordering() {
    for (name, data) in corpus() {
        if data.len() < 2 {
            continue;
        }
        let before = shannon_entropy(&data);

        let mut reversed = data.clone();
        reversed.reverse();
        assert!(
            (shannon_entropy(&reversed) - before).abs() < 1e-12,
            "{name}: reversing the data changed entropy from {before} to {}",
            shannon_entropy(&reversed)
        );

        let mut sorted = data.clone();
        sorted.sort_unstable();
        assert!(
            (shannon_entropy(&sorted) - before).abs() < 1e-12,
            "{name}: sorting the data changed entropy from {before} to {}",
            shannon_entropy(&sorted)
        );
    }
}

/// Relabelling byte values bijectively cannot change entropy either: XOR with a
/// constant is a permutation of `0..=255`, so it permutes the counts without
/// altering the multiset.
///
/// This is the law that catches an indexing mistake in the histogram — a bucket
/// written at the wrong offset survives every threshold-based test but not this
/// one.
#[test]
fn entropy_is_invariant_under_bijective_relabelling() {
    for (name, data) in corpus() {
        let before = shannon_entropy(&data);
        for key in [0x01u8, 0x55, 0xFF, 0x80] {
            let relabelled: Vec<u8> = data.iter().map(|b| b ^ key).collect();
            assert!(
                (shannon_entropy(&relabelled) - before).abs() < 1e-12,
                "{name}: XOR with {key:#04x} changed entropy from {before} to {}",
                shannon_entropy(&relabelled)
            );
        }
    }
}

/// Guards every test above: the corpus must actually span the entropy range.
///
/// If every input scored the same, agreement and invariance would hold without
/// the implementations ever being exercised on interesting data.
#[test]
fn the_corpus_actually_spans_the_entropy_range() {
    let values: Vec<f64> = corpus().iter().map(|(_, d)| shannon_entropy(d)).collect();
    let lo = values.iter().copied().fold(f64::INFINITY, f64::min);
    let hi = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);

    assert!(lo < 0.5, "lowest entropy in the corpus is {lo}, expected a near-zero case");
    assert!(hi > 7.5, "highest entropy in the corpus is {hi}, expected a near-maximal case");
}
