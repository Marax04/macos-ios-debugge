//! `similarity_score` — Discrete and composite similarity scoring primitives.
//!
//! Provides strongly-typed similarity values constrained to `[0.0, 1.0]`,
//! Jaccard and edit-distance similarity for instruction sets, a weighted
//! combined similarity score, and a threshold enum for human-readable
//! classification of match quality.

use std::collections::HashSet;
use std::fmt;

fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SimilarityScore — a validated f64 in [0.0, 1.0]
// ---------------------------------------------------------------------------

/// A similarity score guaranteed to be in the range `[0.0, 1.0]`.
///
/// # Examples
///
/// ```
/// use rustre_diff_semantic::similarity_score::SimilarityScore;
/// let s = SimilarityScore::new(0.75);
/// assert_eq!(s.value(), 0.75);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SimilarityScore(f64);

impl SimilarityScore {
    /// Create a new score, clamping the value to `[0.0, 1.0]`.
    #[must_use]
    pub const fn new(value: f64) -> Self {
        Self(value.clamp(0.0, 1.0))
    }

    /// Create a score representing identity (1.0).
    #[must_use]
    pub const fn identical() -> Self {
        Self(1.0)
    }

    /// Create a score representing complete dissimilarity (0.0).
    #[must_use]
    pub const fn zero() -> Self {
        Self(0.0)
    }

    /// Return the underlying `f64` value.
    #[must_use]
    pub const fn value(self) -> f64 {
        self.0
    }

    /// Return `true` if the score equals 1.0.
    #[must_use]
    pub fn is_identical(self) -> bool {
        (self.0 - 1.0).abs() < f64::EPSILON
    }

    /// Return `true` if the score is 0.0.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 < f64::EPSILON
    }

    /// Classify the score into a [`SimilarityThreshold`] band.
    #[must_use]
    pub fn classify(self) -> SimilarityThreshold {
        SimilarityThreshold::from_score(self)
    }

    /// Linearly interpolate between `self` and `other` by `t ∈ [0.0, 1.0]`.
    #[must_use]
    pub fn lerp(self, other: Self, t: f64) -> Self {
        let t = t.clamp(0.0, 1.0);
        Self::new(self.0.mul_add(1.0 - t, other.0 * t))
    }
}

impl fmt::Display for SimilarityScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.4}", self.0)
    }
}

impl From<f64> for SimilarityScore {
    fn from(v: f64) -> Self {
        Self::new(v)
    }
}

impl From<SimilarityScore> for f64 {
    fn from(s: SimilarityScore) -> Self {
        s.0
    }
}

// ---------------------------------------------------------------------------
// SimilarityThreshold — human-readable bands
// ---------------------------------------------------------------------------

/// Qualitative classification of a similarity score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SimilarityThreshold {
    /// Score in `[1.0, 1.0]` — functions are byte-for-byte identical.
    Identical,
    /// Score in `[0.85, 1.0)` — functions are very likely the same logic.
    High,
    /// Score in `[0.60, 0.85)` — functions share significant behavioural overlap.
    Medium,
    /// Score in `[0.30, 0.60)` — functions share some structure but differ meaningfully.
    Low,
    /// Score in `[0.0, 0.30)` — functions appear unrelated.
    Different,
}

impl SimilarityThreshold {
    /// Classify a [`SimilarityScore`] into the appropriate band.
    #[must_use]
    pub fn from_score(score: SimilarityScore) -> Self {
        let v = score.value();
        if (v - 1.0).abs() < f64::EPSILON {
            Self::Identical
        } else if v >= 0.85 {
            Self::High
        } else if v >= 0.60 {
            Self::Medium
        } else if v >= 0.30 {
            Self::Low
        } else {
            Self::Different
        }
    }

    /// Return the minimum score value for this band.
    #[must_use]
    pub const fn min_score(self) -> f64 {
        match self {
            Self::Identical => 1.0,
            Self::High => 0.85,
            Self::Medium => 0.60,
            Self::Low => 0.30,
            Self::Different => 0.0,
        }
    }

    /// Return a short string label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Identical => "identical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Different => "different",
        }
    }

    /// Return `true` if the threshold indicates a meaningful match.
    #[must_use]
    pub const fn is_match(self) -> bool {
        matches!(self, Self::Identical | Self::High | Self::Medium)
    }
}

impl fmt::Display for SimilarityThreshold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// JaccardSimilarity — set-based overlap for instruction sets
// ---------------------------------------------------------------------------

/// Computes Jaccard similarity between two sets of instruction mnemonics.
///
/// Jaccard(A, B) = |A ∩ B| / |A ∪ B|
///
/// Returns [`SimilarityScore::identical()`] when both sets are empty, and
/// [`SimilarityScore::zero()`] when exactly one set is empty.
#[derive(Debug, Clone, Default)]
pub struct JaccardSimilarity;

impl JaccardSimilarity {
    /// Compute Jaccard similarity between two mnemonic slices.
    ///
    /// Duplicate mnemonics within a slice are collapsed — only set membership
    /// matters, not frequency.
    #[must_use]
    pub fn compute(a: &[&str], b: &[&str]) -> SimilarityScore {
        if a.is_empty() && b.is_empty() {
            return SimilarityScore::identical();
        }
        if a.is_empty() || b.is_empty() {
            return SimilarityScore::zero();
        }
        let set_a: HashSet<&str> = a.iter().copied().collect();
        let set_b: HashSet<&str> = b.iter().copied().collect();
        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();
        SimilarityScore::new(count_as_f64(intersection) / count_as_f64(union))
    }

    /// Compute Jaccard similarity between two sets of owned mnemonic strings.
    #[must_use]
    pub fn compute_owned(a: &[String], b: &[String]) -> SimilarityScore {
        let a_refs: Vec<&str> = a.iter().map(String::as_str).collect();
        let b_refs: Vec<&str> = b.iter().map(String::as_str).collect();
        Self::compute(&a_refs, &b_refs)
    }

    /// Compute Jaccard similarity between two sorted, deduplicated `u64` sets.
    #[must_use]
    pub fn compute_u64(a: &[u64], b: &[u64]) -> SimilarityScore {
        if a.is_empty() && b.is_empty() {
            return SimilarityScore::identical();
        }
        if a.is_empty() || b.is_empty() {
            return SimilarityScore::zero();
        }
        let set_a: HashSet<u64> = a.iter().copied().collect();
        let set_b: HashSet<u64> = b.iter().copied().collect();
        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();
        SimilarityScore::new(count_as_f64(intersection) / count_as_f64(union))
    }
}

// ---------------------------------------------------------------------------
// EditDistanceSimilarity — normalised Levenshtein distance
// ---------------------------------------------------------------------------

/// Computes similarity based on the Levenshtein edit distance between two
/// sequences of instruction mnemonics.
///
/// Similarity = 1.0 − (`edit_distance` / `max_length`).
/// Returns 1.0 for two empty sequences and 0.0 when one is empty.
#[derive(Debug, Clone, Default)]
pub struct EditDistanceSimilarity;

impl EditDistanceSimilarity {
    /// Compute edit-distance similarity between two mnemonic slices.
    #[must_use]
    pub fn compute(a: &[&str], b: &[&str]) -> SimilarityScore {
        if a.is_empty() && b.is_empty() {
            return SimilarityScore::identical();
        }
        let max_len = a.len().max(b.len());
        if max_len == 0 {
            return SimilarityScore::identical();
        }
        let dist = levenshtein_str(a, b);
        SimilarityScore::new(1.0 - count_as_f64(dist) / count_as_f64(max_len))
    }

    /// Compute edit-distance similarity between two owned mnemonic slices.
    #[must_use]
    pub fn compute_owned(a: &[String], b: &[String]) -> SimilarityScore {
        let a_refs: Vec<&str> = a.iter().map(String::as_str).collect();
        let b_refs: Vec<&str> = b.iter().map(String::as_str).collect();
        Self::compute(&a_refs, &b_refs)
    }

    /// Compute edit-distance similarity between two byte sequences.
    #[must_use]
    pub fn compute_bytes(a: &[u8], b: &[u8]) -> SimilarityScore {
        if a.is_empty() && b.is_empty() {
            return SimilarityScore::identical();
        }
        let max_len = a.len().max(b.len());
        let dist = levenshtein_bytes(a, b);
        SimilarityScore::new(1.0 - count_as_f64(dist) / count_as_f64(max_len))
    }
}

/// Classic Levenshtein distance for string slices.
fn levenshtein_str(a: &[&str], b: &[&str]) -> usize {
    let (m, n) = (a.len(), b.len());
    let mut dp: Vec<usize> = (0..=n).collect();
    for i in 1..=m {
        let mut prev = dp[0];
        dp[0] = i;
        for j in 1..=n {
            let temp = dp[j];
            dp[j] = if a[i - 1] == b[j - 1] {
                prev
            } else {
                1 + prev.min(dp[j]).min(dp[j - 1])
            };
            prev = temp;
        }
    }
    dp[n]
}

/// Classic Levenshtein distance for byte slices.
fn levenshtein_bytes(a: &[u8], b: &[u8]) -> usize {
    let (m, n) = (a.len(), b.len());
    let mut dp: Vec<usize> = (0..=n).collect();
    for i in 1..=m {
        let mut prev = dp[0];
        dp[0] = i;
        for j in 1..=n {
            let temp = dp[j];
            dp[j] = if a[i - 1] == b[j - 1] {
                prev
            } else {
                1 + prev.min(dp[j]).min(dp[j - 1])
            };
            prev = temp;
        }
    }
    dp[n]
}

// ---------------------------------------------------------------------------
// WeightedComponent — a (score, weight) pair
// ---------------------------------------------------------------------------

/// A single component of a combined similarity score.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WeightedComponent {
    /// The component score.
    pub score: SimilarityScore,
    /// Non-negative weight (will be normalised when combined).
    pub weight: f64,
    /// Short human-readable label.
    pub label: &'static str,
}

impl WeightedComponent {
    /// Create a new weighted component.
    ///
    /// # Panics
    ///
    /// Panics in debug mode if `weight` is negative.
    #[must_use]
    pub fn new(label: &'static str, score: SimilarityScore, weight: f64) -> Self {
        debug_assert!(weight >= 0.0, "weight must be non-negative");
        Self {
            score,
            weight: weight.max(0.0),
            label,
        }
    }
}

// ---------------------------------------------------------------------------
// CombinedSimilarity — weighted average of multiple components
// ---------------------------------------------------------------------------

/// Combines multiple similarity components into a single weighted-average
/// [`SimilarityScore`].
///
/// If the total weight of all components is zero the result is
/// [`SimilarityScore::zero()`].
#[derive(Debug, Clone, Default)]
pub struct CombinedSimilarity {
    components: Vec<WeightedComponent>,
}

impl CombinedSimilarity {
    /// Create an empty combiner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a weighted component.
    pub fn add(&mut self, component: WeightedComponent) {
        self.components.push(component);
    }

    /// Convenience builder: add a labelled score with a weight and return `&mut self`.
    #[must_use] 
    pub fn with(mut self, label: &'static str, score: SimilarityScore, weight: f64) -> Self {
        self.add(WeightedComponent::new(label, score, weight));
        self
    }

    /// Compute the weighted-average similarity across all added components.
    #[must_use]
    pub fn compute(&self) -> SimilarityScore {
        let total_weight: f64 = self.components.iter().map(|c| c.weight).sum();
        if total_weight < f64::EPSILON {
            return SimilarityScore::zero();
        }
        let weighted_sum: f64 = self
            .components
            .iter()
            .map(|c| c.score.value() * c.weight)
            .sum();
        SimilarityScore::new(weighted_sum / total_weight)
    }

    /// Return the components contributing most strongly (weight × score ≥ mean).
    #[must_use]
    pub fn dominant_components(&self) -> Vec<&WeightedComponent> {
        let total_weight: f64 = self.components.iter().map(|c| c.weight).sum();
        if total_weight < f64::EPSILON {
            return vec![];
        }
        let n = count_as_f64(self.components.len());
        let mean = total_weight / n.max(1.0);
        self.components
            .iter()
            .filter(|c| c.weight >= mean)
            .collect()
    }

    /// Number of components registered.
    #[must_use]
    pub const fn component_count(&self) -> usize {
        self.components.len()
    }
}

impl fmt::Display for CombinedSimilarity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let score = self.compute();
        write!(
            f,
            "CombinedSimilarity({score} from {} components)",
            self.components.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── SimilarityScore ───────────────────────────────────────────────────────

    #[test]
    fn test_score_clamp_high() {
        let s = SimilarityScore::new(2.0);
        assert!((s.value() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_score_clamp_low() {
        let s = SimilarityScore::new(-1.0);
        assert!(s.is_zero());
    }

    #[test]
    fn test_score_identical_and_zero() {
        assert!(SimilarityScore::identical().is_identical());
        assert!(SimilarityScore::zero().is_zero());
    }

    #[test]
    fn test_score_lerp() {
        let a = SimilarityScore::new(0.0);
        let b = SimilarityScore::new(1.0);
        let mid = a.lerp(b, 0.5);
        assert!((mid.value() - 0.5).abs() < 1e-9);
    }

    // ── SimilarityThreshold ───────────────────────────────────────────────────

    #[test]
    fn test_threshold_identical() {
        assert_eq!(
            SimilarityThreshold::from_score(SimilarityScore::new(1.0)),
            SimilarityThreshold::Identical
        );
    }

    #[test]
    fn test_threshold_high() {
        let s = SimilarityScore::new(0.90);
        assert_eq!(s.classify(), SimilarityThreshold::High);
    }

    #[test]
    fn test_threshold_medium() {
        assert_eq!(
            SimilarityScore::new(0.70).classify(),
            SimilarityThreshold::Medium
        );
    }

    #[test]
    fn test_threshold_low() {
        assert_eq!(
            SimilarityScore::new(0.45).classify(),
            SimilarityThreshold::Low
        );
    }

    #[test]
    fn test_threshold_different() {
        assert_eq!(
            SimilarityScore::new(0.10).classify(),
            SimilarityThreshold::Different
        );
    }

    #[test]
    fn test_threshold_is_match() {
        assert!(SimilarityThreshold::Identical.is_match());
        assert!(SimilarityThreshold::High.is_match());
        assert!(SimilarityThreshold::Medium.is_match());
        assert!(!SimilarityThreshold::Low.is_match());
        assert!(!SimilarityThreshold::Different.is_match());
    }

    // ── JaccardSimilarity ─────────────────────────────────────────────────────

    #[test]
    fn test_jaccard_identical_sets() {
        let mnemonics = &["ADD", "SUB", "MOV", "JMP"];
        let score = JaccardSimilarity::compute(mnemonics, mnemonics);
        assert!(
            score.is_identical(),
            "identical sets → score 1.0, got {score}"
        );
    }

    #[test]
    fn test_jaccard_disjoint_sets() {
        let a = &["ADD", "SUB"];
        let b = &["MUL", "DIV"];
        let score = JaccardSimilarity::compute(a, b);
        assert!(score.is_zero(), "disjoint sets → score 0.0, got {score}");
    }

    #[test]
    fn test_jaccard_partial_overlap() {
        let a = &["ADD", "SUB", "MOV"];
        let b = &["ADD", "MUL", "MOV"];
        // |intersection| = 2, |union| = 4  → 0.5
        let score = JaccardSimilarity::compute(a, b);
        assert!(
            (score.value() - 0.5).abs() < 1e-9,
            "expected 0.5, got {score}"
        );
    }

    #[test]
    fn test_jaccard_both_empty() {
        let score = JaccardSimilarity::compute(&[], &[]);
        assert!(score.is_identical());
    }

    #[test]
    fn test_jaccard_one_empty() {
        let score = JaccardSimilarity::compute(&["ADD"], &[]);
        assert!(score.is_zero());
    }

    // ── EditDistanceSimilarity ────────────────────────────────────────────────

    #[test]
    fn test_edit_identical() {
        let seq = &["MOV", "ADD", "RET"];
        let score = EditDistanceSimilarity::compute(seq, seq);
        assert!(score.is_identical(), "expected 1.0, got {score}");
    }

    #[test]
    fn test_edit_single_substitution() {
        let a = &["MOV", "ADD", "RET"];
        let b = &["MOV", "SUB", "RET"];
        let score = EditDistanceSimilarity::compute(a, b);
        // dist = 1, max_len = 3 → 1 − 1/3 ≈ 0.667
        assert!(
            score.value() > 0.6 && score.value() < 0.8,
            "unexpected score {score}"
        );
    }

    #[test]
    fn test_edit_completely_different() {
        let a = &["NOP"];
        let b = &["HLT"];
        let score = EditDistanceSimilarity::compute(a, b);
        assert!(score.is_zero(), "expected 0.0, got {score}");
    }

    #[test]
    fn test_edit_both_empty() {
        let score = EditDistanceSimilarity::compute(&[], &[]);
        assert!(score.is_identical());
    }

    // ── CombinedSimilarity ────────────────────────────────────────────────────

    #[test]
    fn test_combined_equal_weights() {
        let score = CombinedSimilarity::new()
            .with("a", SimilarityScore::new(1.0), 1.0)
            .with("b", SimilarityScore::new(0.0), 1.0)
            .compute();
        assert!(
            (score.value() - 0.5).abs() < 1e-9,
            "expected 0.5, got {score}"
        );
    }

    #[test]
    fn test_combined_no_components() {
        let score = CombinedSimilarity::new().compute();
        assert!(score.is_zero());
    }

    #[test]
    fn test_combined_single_component() {
        let score = CombinedSimilarity::new()
            .with("only", SimilarityScore::new(0.75), 2.0)
            .compute();
        assert!((score.value() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn test_combined_weighted_dominance() {
        // 0.9 × 3 + 0.1 × 1 = 2.8, total_weight = 4 → 0.7
        let score = CombinedSimilarity::new()
            .with("heavy", SimilarityScore::new(0.9), 3.0)
            .with("light", SimilarityScore::new(0.1), 1.0)
            .compute();
        assert!(
            (score.value() - 0.7).abs() < 1e-9,
            "expected 0.7, got {score}"
        );
    }

    #[test]
    fn test_combined_display() {
        let c = CombinedSimilarity::new().with("x", SimilarityScore::new(0.5), 1.0);
        let s = c.to_string();
        assert!(s.contains("CombinedSimilarity"), "unexpected display: {s}");
    }
}
