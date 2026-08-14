//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! These are "wrong but plausible" results: the code compiled and ran, it just
//! answered incorrectly. Assertions are therefore written against the defining
//! property of the operation, not against observed behaviour.

use rustre_diff_bindiff::hungarian_matcher::{CostMatrix, MatchConfidence};

// ── CostMatrix::from_similarity ────────────────────────────────────────────

/// A jagged input whose later rows are longer than row 0 used to index past
/// the end of the buffer: the width was taken from the first row alone.
#[test]
fn jagged_similarity_does_not_panic() {
    let sim = vec![vec![0.5; 1], vec![0.5; 5]];
    let m = CostMatrix::from_similarity(&sim);
    assert_eq!(m.padded_dim(), 5, "padding must cover the widest row");
    assert_eq!(m.original_rows(), 2);
    assert_eq!(m.original_cols(), 5);
}

#[test]
fn jagged_in_either_direction_is_accepted() {
    for sim in [
        vec![vec![0.1; 4], vec![0.1; 1]],
        vec![vec![0.1; 1], vec![0.1; 4]],
        vec![vec![0.1; 3]],
        vec![vec![]; 3],
        Vec::<Vec<f64>>::new(),
    ] {
        let m = CostMatrix::from_similarity(&sim);
        // Every stored cell must be addressable within the padded square.
        let n = m.padded_dim();
        for i in 0..n {
            for j in 0..n {
                assert!(m.cost_at(i, j).is_some(), "cell ({i},{j}) missing in {n}x{n}");
            }
        }
    }
}

#[test]
fn square_similarity_is_transcribed_as_cost() {
    let sim = vec![vec![1.0, 0.0], vec![0.25, 0.5]];
    let m = CostMatrix::from_similarity(&sim);
    assert_eq!(m.padded_dim(), 2);
    // cost = 1 - similarity
    assert_eq!(m.cost_at(0, 0), Some(0.0));
    assert_eq!(m.cost_at(0, 1), Some(1.0));
    assert_eq!(m.cost_at(1, 1), Some(0.5));
}

// ── MatchConfidence ordering ───────────────────────────────────────────────

/// The derived `Ord` follows declaration order, in which `Exact` is the
/// MINIMUM. Any comparison meaning "at least this good" must not use it.
#[test]
fn strength_ranks_exact_highest() {
    assert!(MatchConfidence::Exact.strength() > MatchConfidence::High.strength());
    assert!(MatchConfidence::High.strength() > MatchConfidence::Medium.strength());
    assert!(MatchConfidence::Medium.strength() > MatchConfidence::Low.strength());
}

/// Strength must agree with the numeric band each variant represents —
/// otherwise the qualitative label and the score it came from disagree.
#[test]
fn strength_agrees_with_lower_bound() {
    let bands = [
        MatchConfidence::Low,
        MatchConfidence::Medium,
        MatchConfidence::High,
        MatchConfidence::Exact,
    ];
    for w in bands.windows(2) {
        assert!(
            w[0].strength() < w[1].strength(),
            "{:?} should rank below {:?}",
            w[0],
            w[1]
        );
        assert!(
            w[0].lower_bound() < w[1].lower_bound(),
            "{:?} should have a lower score floor than {:?}",
            w[0],
            w[1]
        );
    }
}

/// The band derived from a score must rank at least as high as the band
/// derived from any lower score.
#[test]
fn higher_scores_never_yield_weaker_bands() {
    let mut prev: Option<MatchConfidence> = None;
    let mut s = 0.30_f64;
    while s <= 1.0 {
        if let Some(band) = MatchConfidence::from_score(s) {
            if let Some(p) = prev {
                assert!(
                    band.strength() >= p.strength(),
                    "score {s} gave {band:?}, weaker than {p:?} from a lower score"
                );
            }
            prev = Some(band);
        }
        s += 0.01;
    }
    assert_eq!(prev, Some(MatchConfidence::Exact));
}
