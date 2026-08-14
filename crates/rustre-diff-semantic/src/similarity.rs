//! Similarity metrics and feature comparison for semantic binary diffing.
//!
//! Provides [`FeatureVector`], [`SimilarityMetric`] (Jaccard, cosine, edit
//! distance), [`FeatureExtractor`], [`SimilarityMatrix`], and a
//! [`HungarianMatcher`] for optimal 1-to-1 function matching.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}


fn usize_to_u32_saturating(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

// ─────────────────────────────────────────────────────────────────────────────
// FeatureVector
// ─────────────────────────────────────────────────────────────────────────────

/// A named feature vector used for similarity comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    pub name: String,
    pub address: u64,
    /// Normalized histogram features (`feature_name` → count).
    pub int_features: HashMap<String, u32>,
    /// Floating-point features (e.g. call density, loop nesting depth).
    pub float_features: HashMap<String, f64>,
    /// Set features (e.g. callee names, string literals).
    pub set_features: HashMap<String, HashSet<String>>,
}

impl FeatureVector {
    pub fn new(name: impl Into<String>, address: u64) -> Self {
        Self {
            name: name.into(),
            address,
            int_features: HashMap::new(),
            float_features: HashMap::new(),
            set_features: HashMap::new(),
        }
    }

    pub fn set_int(&mut self, key: &str, val: u32) {
        self.int_features.insert(key.to_string(), val);
    }

    pub fn set_float(&mut self, key: &str, val: f64) {
        self.float_features.insert(key.to_string(), val);
    }

    pub fn add_set_item(&mut self, key: &str, item: impl Into<String>) {
        self.set_features
            .entry(key.to_string())
            .or_default()
            .insert(item.into());
    }

    #[must_use] 
    pub fn get_int(&self, key: &str) -> u32 {
        self.int_features.get(key).copied().unwrap_or(0)
    }

    #[must_use] 
    pub fn get_float(&self, key: &str) -> f64 {
        self.float_features.get(key).copied().unwrap_or(0.0)
    }

    /// L2 norm of the integer feature vector.
    #[must_use] 
    pub fn l2_norm(&self) -> f64 {
        let sum: f64 = self
            .int_features
            .values()
            .map(|&v| f64::from(v).powi(2))
            .sum();
        sum.sqrt()
    }

    /// Union of all feature keys across int and float maps.
    #[must_use] 
    pub fn all_keys(&self) -> HashSet<String> {
        let mut keys: HashSet<String> = self.int_features.keys().cloned().collect();
        keys.extend(self.float_features.keys().cloned());
        keys
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SimilarityMetric
// ─────────────────────────────────────────────────────────────────────────────

/// A similarity metric that computes a score in [0.0, 1.0].
pub trait SimilarityMetric: fmt::Debug {
    fn name(&self) -> &'static str;
    fn score(&self, a: &FeatureVector, b: &FeatureVector) -> f64;
}

/// Jaccard similarity on the integer feature keys (ignoring magnitudes).
#[derive(Debug, Default)]
pub struct JaccardSimilarity;

impl SimilarityMetric for JaccardSimilarity {
    fn name(&self) -> &'static str {
        "jaccard"
    }

    fn score(&self, a: &FeatureVector, b: &FeatureVector) -> f64 {
        let ka: HashSet<&str> = a.int_features.keys().map(String::as_str).collect();
        let kb: HashSet<&str> = b.int_features.keys().map(String::as_str).collect();
        let intersection = ka.intersection(&kb).count();
        let union = ka.union(&kb).count();
        if union == 0 {
            1.0
        } else {
            count_as_f64(intersection) / count_as_f64(union)
        }
    }
}

/// Cosine similarity on integer feature vectors.
#[derive(Debug, Default)]
pub struct CosineSimilarity;

impl SimilarityMetric for CosineSimilarity {
    fn name(&self) -> &'static str {
        "cosine"
    }

    fn score(&self, a: &FeatureVector, b: &FeatureVector) -> f64 {
        let all_keys: HashSet<String> = a.all_keys().union(&b.all_keys()).cloned().collect();
        let dot: f64 = all_keys
            .iter()
            .map(|k| {
                let av = f64::from(a.int_features.get(k).copied().unwrap_or(0));
                let bv = f64::from(b.int_features.get(k).copied().unwrap_or(0));
                av * bv
            })
            .sum();
        let na = a.l2_norm();
        let nb = b.l2_norm();
        if na == 0.0 || nb == 0.0 {
            0.0
        } else {
            dot / (na * nb)
        }
    }
}

/// Normalized edit distance on mnemonic histograms (simulated as sorted key lists).
#[derive(Debug, Default)]
pub struct EditDistanceSimilarity;

impl SimilarityMetric for EditDistanceSimilarity {
    fn name(&self) -> &'static str {
        "edit_distance"
    }

    fn score(&self, a: &FeatureVector, b: &FeatureVector) -> f64 {
        // Simplified: compare sorted int feature key lists.
        let mut ka: Vec<&str> = a.int_features.keys().map(String::as_str).collect();
        let mut kb: Vec<&str> = b.int_features.keys().map(String::as_str).collect();
        ka.sort_unstable();
        kb.sort_unstable();
        let dist = levenshtein_distance_str_slices(&ka, &kb);
        let max_len = ka.len().max(kb.len());
        if max_len == 0 {
            1.0
        } else {
            1.0 - count_as_f64(dist) / count_as_f64(max_len)
        }
    }
}

fn levenshtein_distance_str_slices(a: &[&str], b: &[&str]) -> usize {
    let m = a.len();
    let n = b.len();
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for (i, row) in dp.iter_mut().enumerate().take(m + 1) {
        row[0] = i;
    }
    for (j, cell) in dp[0].iter_mut().enumerate().take(n + 1) {
        *cell = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1]
            } else {
                1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1])
            };
        }
    }
    dp[m][n]
}

/// Weighted combination of multiple metrics.
#[derive(Debug)]
pub struct WeightedSimilarity {
    pub metrics: Vec<(Box<dyn SimilarityMetric>, f64)>,
}

impl WeightedSimilarity {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            metrics: Vec::new(),
        }
    }

    #[must_use] 
    pub fn add(mut self, metric: Box<dyn SimilarityMetric>, weight: f64) -> Self {
        self.metrics.push((metric, weight));
        self
    }

    #[must_use] 
    pub fn score(&self, a: &FeatureVector, b: &FeatureVector) -> f64 {
        let total_weight: f64 = self.metrics.iter().map(|(_, w)| w).sum();
        if total_weight == 0.0 {
            return 0.0;
        }
        let weighted_sum: f64 = self.metrics.iter().map(|(m, w)| m.score(a, b) * w).sum();
        weighted_sum / total_weight
    }
}

impl Default for WeightedSimilarity {
    fn default() -> Self {
        Self::new()
            .add(Box::new(JaccardSimilarity), 1.0)
            .add(Box::new(CosineSimilarity), 2.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FeatureExtractor
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts a [`FeatureVector`] from a sequence of instruction mnemonics
/// and a list of call targets.
pub struct FeatureExtractor;

impl FeatureExtractor {
    /// Extract features from a function's instruction stream.
    #[must_use] 
    pub fn extract(
        name: &str,
        address: u64,
        mnemonics: &[&str],
        callees: &[String],
        strings: &[String],
    ) -> FeatureVector {
        let mut fv = FeatureVector::new(name, address);

        // Mnemonic histogram
        let mut hist: HashMap<String, u32> = HashMap::new();
        for &m in mnemonics {
            let base = m
                .to_lowercase()
                .trim_end_matches(|c: char| c.is_ascii_digit())
                .to_string();
            *hist.entry(base).or_default() += 1;
        }
        for (k, v) in hist {
            fv.set_int(&k, v);
        }

        // Instruction counts
        fv.set_int("total_instrs", usize_to_u32_saturating(mnemonics.len()));
        fv.set_int("call_count", usize_to_u32_saturating(callees.len()));
        fv.set_int("string_ref_count", usize_to_u32_saturating(strings.len()));

        // Callee set
        for c in callees {
            fv.add_set_item("callees", c);
        }

        // String references
        for s in strings {
            fv.add_set_item("strings", s);
        }

        // Approximate loop count (back-branch heuristic)
        // Counted over every instruction, not over `windows(3)[2]`: the old
        // form could not see a branch in the first two positions, so the same
        // instructions scored differently depending on where they sat.
        let back_branches = mnemonics.iter().filter(|m| m.starts_with('j')).count();
        fv.set_int("approx_loops", usize_to_u32_saturating(back_branches));

        // Float / vector ratio
        let float_count = mnemonics
            .iter()
            .filter(|m| m.starts_with('f') || m.starts_with("xmm"))
            .count();
        fv.set_float(
            "float_ratio",
            count_as_f64(float_count) / count_as_f64(mnemonics.len().max(1)),
        );

        fv
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SimilarityMatrix
// ─────────────────────────────────────────────────────────────────────────────

/// Dense similarity matrix for two sets of functions.
pub struct SimilarityMatrix {
    pub scores: Vec<Vec<f64>>,
    pub row_names: Vec<String>,
    pub col_names: Vec<String>,
}

impl SimilarityMatrix {
    /// Build a similarity matrix from two slices of feature vectors.
    pub fn build(
        old_funcs: &[FeatureVector],
        new_funcs: &[FeatureVector],
        metric: &dyn SimilarityMetric,
    ) -> Self {
        let rows = old_funcs.len();
        let cols = new_funcs.len();
        let mut scores = vec![vec![0.0f64; cols]; rows];
        for (i, a) in old_funcs.iter().enumerate() {
            for (j, b) in new_funcs.iter().enumerate() {
                scores[i][j] = metric.score(a, b);
            }
        }
        Self {
            scores,
            row_names: old_funcs.iter().map(|f| f.name.clone()).collect(),
            col_names: new_funcs.iter().map(|f| f.name.clone()).collect(),
        }
    }

    #[must_use] 
    pub const fn rows(&self) -> usize {
        self.scores.len()
    }
    #[must_use] 
    pub fn cols(&self) -> usize {
        self.scores.first().map_or(0, std::vec::Vec::len)
    }

    #[must_use] 
    pub fn get(&self, row: usize, col: usize) -> f64 {
        self.scores
            .get(row)
            .and_then(|r| r.get(col))
            .copied()
            .unwrap_or(0.0)
    }

    /// Best match for each row (greedy, O(n²)).
    #[must_use] 
    pub fn best_matches(&self) -> Vec<(usize, usize, f64)> {
        let mut used_cols: HashSet<usize> = HashSet::new();
        let mut matches = Vec::new();
        for row in 0..self.rows() {
            if let Some((col, score)) = (0..self.cols())
                .filter(|c| !used_cols.contains(c))
                .map(|c| (c, self.get(row, c)))
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            {
                used_cols.insert(col);
                matches.push((row, col, score));
            }
        }
        matches
    }

    /// Minimum similarity across all best matches.
    pub fn min_best_score(&self) -> f64 {
        self.best_matches()
            .iter()
            .map(|&(_, _, s)| s)
            .fold(f64::INFINITY, f64::min)
    }

    /// Average similarity across all best matches.
    #[must_use] 
    pub fn avg_best_score(&self) -> f64 {
        let bm = self.best_matches();
        if bm.is_empty() {
            return 0.0;
        }
        bm.iter().map(|&(_, _, s)| s).sum::<f64>() / count_as_f64(bm.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HungarianMatcher (simplified)
// ─────────────────────────────────────────────────────────────────────────────

/// Optimal 1-to-1 function matching using a greedy approximation of the
/// Hungarian algorithm (O(n³) true Hungarian is not needed for typical
/// binary diff sizes).
pub struct HungarianMatcher {
    pub threshold: f64,
}

impl HungarianMatcher {
    #[must_use] 
    pub const fn new(threshold: f64) -> Self {
        Self { threshold }
    }

    /// Return matched pairs `(old_idx, new_idx, score)` above threshold.
    #[must_use] 
    pub fn match_functions(&self, matrix: &SimilarityMatrix) -> Vec<(usize, usize, f64)> {
        // Greedy: repeatedly pick the highest-scoring unmatched pair.
        let mut all_pairs: Vec<(usize, usize, f64)> = Vec::new();
        for i in 0..matrix.rows() {
            for j in 0..matrix.cols() {
                let s = matrix.get(i, j);
                if s >= self.threshold {
                    all_pairs.push((i, j, s));
                }
            }
        }
        all_pairs.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

        let mut used_rows = HashSet::new();
        let mut used_cols = HashSet::new();
        let mut result = Vec::new();
        for (row, col, score) in all_pairs {
            if !used_rows.contains(&row) && !used_cols.contains(&col) {
                used_rows.insert(row);
                used_cols.insert(col);
                result.push((row, col, score));
            }
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fv(name: &str, keys: &[&str]) -> FeatureVector {
        let mut fv = FeatureVector::new(name, 0);
        for &k in keys {
            fv.set_int(k, 1);
        }
        fv
    }

    // --- FeatureVector ---

    #[test]
    fn fv_set_get_int() {
        let mut fv = FeatureVector::new("f", 0);
        fv.set_int("mov", 5);
        assert_eq!(fv.get_int("mov"), 5);
    }

    #[test]
    fn fv_missing_key_zero() {
        let fv = FeatureVector::new("f", 0);
        assert_eq!(fv.get_int("no_key"), 0);
    }

    #[test]
    fn fv_l2_norm() {
        let mut fv = FeatureVector::new("f", 0);
        fv.set_int("a", 3);
        fv.set_int("b", 4);
        assert!((fv.l2_norm() - 5.0).abs() < 1e-10);
    }

    #[test]
    fn fv_set_feature() {
        let mut fv = FeatureVector::new("f", 0);
        fv.add_set_item("callees", "malloc");
        assert!(fv.set_features["callees"].contains("malloc"));
    }

    #[test]
    fn fv_all_keys() {
        let mut fv = FeatureVector::new("f", 0);
        fv.set_int("a", 1);
        fv.set_float("b", 1.0);
        let keys = fv.all_keys();
        assert!(keys.contains("a"));
        assert!(keys.contains("b"));
    }

    // --- JaccardSimilarity ---

    #[test]
    fn jaccard_identical() {
        let a = make_fv("a", &["mov", "add", "ret"]);
        let b = make_fv("b", &["mov", "add", "ret"]);
        let s = JaccardSimilarity.score(&a, &b);
        assert!((s - 1.0).abs() < 1e-10);
    }

    #[test]
    fn jaccard_disjoint() {
        let a = make_fv("a", &["mov"]);
        let b = make_fv("b", &["xor"]);
        let s = JaccardSimilarity.score(&a, &b);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn jaccard_partial() {
        let a = make_fv("a", &["mov", "add"]);
        let b = make_fv("b", &["mov", "xor"]);
        let s = JaccardSimilarity.score(&a, &b);
        // intersection=1, union=3
        assert!((s - 1.0 / 3.0).abs() < 1e-10);
    }

    // --- CosineSimilarity ---

    #[test]
    fn cosine_identical() {
        let a = make_fv("a", &["mov", "add"]);
        let b = make_fv("b", &["mov", "add"]);
        let s = CosineSimilarity.score(&a, &b);
        assert!((s - 1.0).abs() < 1e-10);
    }

    #[test]
    fn cosine_disjoint() {
        let a = make_fv("a", &["mov"]);
        let b = make_fv("b", &["ret"]);
        let s = CosineSimilarity.score(&a, &b);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn cosine_empty_vectors() {
        let a = FeatureVector::new("a", 0);
        let b = FeatureVector::new("b", 0);
        assert_eq!(CosineSimilarity.score(&a, &b), 0.0);
    }

    // --- EditDistanceSimilarity ---

    #[test]
    fn edit_identical() {
        let a = make_fv("a", &["mov", "add"]);
        let b = make_fv("b", &["add", "mov"]);
        let s = EditDistanceSimilarity.score(&a, &b);
        // Sorted lists are same → distance = 0 → similarity = 1
        assert!((s - 1.0).abs() < 1e-10);
    }

    #[test]
    fn edit_completely_different() {
        let a = make_fv("a", &["aaa"]);
        let b = make_fv("b", &["zzz"]);
        let s = EditDistanceSimilarity.score(&a, &b);
        assert_eq!(s, 0.0);
    }

    // --- levenshtein ---

    #[test]
    fn levenshtein_empty_slices() {
        assert_eq!(levenshtein_distance_str_slices(&[], &[]), 0);
    }

    #[test]
    fn levenshtein_one_empty() {
        assert_eq!(levenshtein_distance_str_slices(&["a", "b"], &[]), 2);
    }

    // --- WeightedSimilarity ---

    #[test]
    fn weighted_no_metrics_zero() {
        let w = WeightedSimilarity::new();
        let a = make_fv("a", &["x"]);
        let b = make_fv("b", &["x"]);
        assert_eq!(w.score(&a, &b), 0.0);
    }

    #[test]
    fn weighted_single_metric() {
        let w = WeightedSimilarity::new().add(Box::new(JaccardSimilarity), 1.0);
        let a = make_fv("a", &["x"]);
        let b = make_fv("b", &["x"]);
        assert!((w.score(&a, &b) - 1.0).abs() < 1e-10);
    }

    // --- FeatureExtractor ---

    #[test]
    fn feature_extractor_basic() {
        let fv = FeatureExtractor::extract(
            "foo",
            0x1000,
            &["mov", "add", "call", "ret"],
            &["malloc".to_string()],
            &["hello".to_string()],
        );
        assert_eq!(fv.get_int("total_instrs"), 4);
        assert_eq!(fv.get_int("call_count"), 1);
        assert!(fv.set_features.get("callees").unwrap().contains("malloc"));
    }

    #[test]
    fn feature_extractor_no_strings() {
        let fv = FeatureExtractor::extract("g", 0, &["nop"], &[], &[]);
        assert_eq!(fv.get_int("string_ref_count"), 0);
    }

    // --- SimilarityMatrix ---

    #[test]
    fn matrix_build_shape() {
        let old = vec![make_fv("a", &["mov"]), make_fv("b", &["add"])];
        let new_ = vec![
            make_fv("c", &["mov"]),
            make_fv("d", &["xor"]),
            make_fv("e", &["ret"]),
        ];
        let m = SimilarityMatrix::build(&old, &new_, &JaccardSimilarity);
        assert_eq!(m.rows(), 2);
        assert_eq!(m.cols(), 3);
    }

    #[test]
    fn matrix_identical_diagonal() {
        let funcs = vec![make_fv("f", &["mov", "ret"])];
        let m = SimilarityMatrix::build(&funcs, &funcs, &JaccardSimilarity);
        assert!((m.get(0, 0) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn matrix_best_matches() {
        let old = vec![make_fv("a", &["mov"]), make_fv("b", &["add"])];
        let new_ = vec![make_fv("c", &["mov"]), make_fv("d", &["add"])];
        let m = SimilarityMatrix::build(&old, &new_, &JaccardSimilarity);
        let matches = m.best_matches();
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn matrix_avg_best_score() {
        let funcs = vec![make_fv("x", &["a", "b"])];
        let m = SimilarityMatrix::build(&funcs, &funcs, &JaccardSimilarity);
        assert!((m.avg_best_score() - 1.0).abs() < 1e-10);
    }

    // --- HungarianMatcher ---

    #[test]
    fn hungarian_threshold_filters() {
        let old = vec![make_fv("a", &["uniq1"])];
        let new_ = vec![make_fv("b", &["uniq2"])];
        let m = SimilarityMatrix::build(&old, &new_, &JaccardSimilarity);
        let matcher = HungarianMatcher::new(0.5);
        let matches = matcher.match_functions(&m);
        // Jaccard of disjoint sets = 0, below threshold → no matches
        assert!(matches.is_empty());
    }

    #[test]
    fn hungarian_matches_identical() {
        let old = vec![make_fv("a", &["mov", "add"])];
        let new_ = vec![make_fv("b", &["mov", "add"])];
        let m = SimilarityMatrix::build(&old, &new_, &JaccardSimilarity);
        let matcher = HungarianMatcher::new(0.9);
        let matches = matcher.match_functions(&m);
        assert_eq!(matches.len(), 1);
    }
}
