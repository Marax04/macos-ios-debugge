//! Function similarity matrix for `rustre-diff-bindiff`.

use crate::{FunctionInfo, similarity_score};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── SimEntry ──────────────────────────────────────────────────────────────────

/// One entry in the similarity matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimEntry {
    pub func_a: u64,
    pub func_b: u64,
    pub score: f64,
}

impl SimEntry {
    #[must_use]
    pub const fn new(func_a: u64, func_b: u64, score: f64) -> Self {
        Self {
            func_a,
            func_b,
            score,
        }
    }
    #[must_use]
    pub fn is_high_similarity(&self) -> bool {
        self.score >= 0.9
    }
}

// ── SimilarityMatrix ──────────────────────────────────────────────────────────

/// `NxM` similarity matrix between two sets of functions.
pub struct SimilarityMatrix {
    pub funcs_a: Vec<FunctionInfo>,
    pub funcs_b: Vec<FunctionInfo>,
    pub matrix: Vec<Vec<f64>>,
}

impl SimilarityMatrix {
    /// Maximum number of functions per side that this matrix will hold.
    /// Building a full `NxM` matrix beyond this limit would risk memory exhaustion.
    pub const MAX_SIDE: usize = 10_000;

    /// Build the full `NxM` matrix.
    ///
    /// # Panics
    /// Panics if either side has more than [`Self::MAX_SIDE`] entries, to prevent
    /// a dos-memory-exhaustion attack from a crafted binary with a huge function list.
    #[must_use]
    pub fn build(funcs_a: Vec<FunctionInfo>, funcs_b: Vec<FunctionInfo>) -> Self {
        assert!(
            funcs_a.len() <= Self::MAX_SIDE,
            "SimilarityMatrix: funcs_a length {} exceeds MAX_SIDE {}",
            funcs_a.len(),
            Self::MAX_SIDE
        );
        assert!(
            funcs_b.len() <= Self::MAX_SIDE,
            "SimilarityMatrix: funcs_b length {} exceeds MAX_SIDE {}",
            funcs_b.len(),
            Self::MAX_SIDE
        );
        let matrix = funcs_a
            .iter()
            .map(|a| funcs_b.iter().map(|b| similarity_score(a, b)).collect())
            .collect();
        Self {
            funcs_a,
            funcs_b,
            matrix,
        }
    }

    /// Get the similarity score for (row i, col j).
    #[must_use]
    pub fn get(&self, i: usize, j: usize) -> Option<f64> {
        self.matrix.get(i)?.get(j).copied()
    }

    /// Return all entries as a flat list sorted by score descending.
    #[must_use]
    pub fn all_entries(&self) -> Vec<SimEntry> {
        let mut entries = Vec::new();
        for (i, row) in self.matrix.iter().enumerate() {
            for (j, &score) in row.iter().enumerate() {
                if i < self.funcs_a.len() && j < self.funcs_b.len() {
                    entries.push(SimEntry::new(
                        self.funcs_a[i].address,
                        self.funcs_b[j].address,
                        score,
                    ));
                }
            }
        }
        entries.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        entries
    }

    #[must_use]
    pub const fn rows(&self) -> usize {
        self.funcs_a.len()
    }

    #[must_use]
    pub const fn cols(&self) -> usize {
        self.funcs_b.len()
    }

    /// Return the best match for each function in A.
    #[must_use]
    pub fn best_matches_a(&self) -> Vec<Option<SimEntry>> {
        (0..self.rows())
            .map(|i| {
                self.matrix[i]
                    .iter()
                    .enumerate()
                    .max_by(|x, y| x.1.partial_cmp(y.1).unwrap_or(std::cmp::Ordering::Equal))
                    .filter(|&(_, &s)| s > 0.0)
                    .map(|(j, &s)| {
                        SimEntry::new(self.funcs_a[i].address, self.funcs_b[j].address, s)
                    })
            })
            .collect()
    }
}

// ── BestMatchFinder ───────────────────────────────────────────────────────────

/// Finds the best match for each function using various strategies.
pub struct BestMatchFinder {
    pub threshold: f64,
}

impl Default for BestMatchFinder {
    fn default() -> Self {
        Self { threshold: 0.5 }
    }
}

impl BestMatchFinder {
    #[must_use]
    pub const fn new(threshold: f64) -> Self {
        Self { threshold }
    }

    /// Find the best match for `func_a` in `funcs_b`.
    #[must_use]
    pub fn find_best<'b>(
        &self,
        func_a: &FunctionInfo,
        funcs_b: &'b [FunctionInfo],
    ) -> Option<(&'b FunctionInfo, f64)> {
        funcs_b
            .iter()
            .map(|b| (b, similarity_score(func_a, b)))
            .filter(|(_, s)| *s >= self.threshold)
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Find top-N matches for `func_a`.
    #[must_use]
    pub fn find_top_n<'b>(
        &self,
        func_a: &FunctionInfo,
        funcs_b: &'b [FunctionInfo],
        n: usize,
    ) -> Vec<(&'b FunctionInfo, f64)> {
        let mut scored: Vec<(&FunctionInfo, f64)> = funcs_b
            .iter()
            .map(|b| (b, similarity_score(func_a, b)))
            .filter(|(_, s)| *s >= self.threshold)
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(n);
        scored
    }
}

// ── ThresholdFilter ───────────────────────────────────────────────────────────

/// Filters entries by a minimum similarity threshold.
pub struct ThresholdFilter {
    pub min_score: f64,
    pub max_score: f64,
}

impl Default for ThresholdFilter {
    fn default() -> Self {
        Self {
            min_score: 0.0,
            max_score: 1.0,
        }
    }
}

impl ThresholdFilter {
    #[must_use]
    pub const fn new(min_score: f64) -> Self {
        Self {
            min_score,
            max_score: 1.0,
        }
    }

    #[must_use]
    pub fn filter<'a>(&self, entries: &'a [SimEntry]) -> Vec<&'a SimEntry> {
        entries
            .iter()
            .filter(|e| e.score >= self.min_score && e.score <= self.max_score)
            .collect()
    }

    #[must_use]
    pub fn filter_owned(&self, entries: Vec<SimEntry>) -> Vec<SimEntry> {
        entries
            .into_iter()
            .filter(|e| e.score >= self.min_score && e.score <= self.max_score)
            .collect()
    }
}

// ── GreedyAssignment ──────────────────────────────────────────────────────────

/// Greedy one-to-one assignment from a similarity matrix.
pub struct GreedyAssignment;

impl GreedyAssignment {
    /// Assign functions greedily: take the highest-scoring pair, then repeat.
    #[must_use]
    pub fn assign(matrix: &SimilarityMatrix, threshold: f64) -> Vec<SimEntry> {
        let mut assigned_a = vec![false; matrix.rows()];
        let mut assigned_b = vec![false; matrix.cols()];
        let all = matrix.all_entries();
        let mut result = Vec::new();
        let idx_a: HashMap<u64, usize> = matrix
            .funcs_a
            .iter()
            .enumerate()
            .map(|(i, f)| (f.address, i))
            .collect();
        let idx_b: HashMap<u64, usize> = matrix
            .funcs_b
            .iter()
            .enumerate()
            .map(|(i, f)| (f.address, i))
            .collect();

        for entry in &all {
            if entry.score < threshold {
                break;
            }
            let Some(&ia) = idx_a.get(&entry.func_a) else {
                continue;
            };
            let Some(&ib) = idx_b.get(&entry.func_b) else {
                continue;
            };
            if assigned_a[ia] || assigned_b[ib] {
                continue;
            }
            assigned_a[ia] = true;
            assigned_b[ib] = true;
            result.push(SimEntry::new(entry.func_a, entry.func_b, entry.score));
        }
        result
    }
}

// ── SimilarityHeatmap ─────────────────────────────────────────────────────────

/// Visualization data for a similarity heatmap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityHeatmap {
    pub rows: Vec<String>,
    pub cols: Vec<String>,
    pub cells: Vec<Vec<f64>>,
}

impl SimilarityHeatmap {
    #[must_use]
    pub fn from_matrix(matrix: &SimilarityMatrix) -> Self {
        let rows = matrix
            .funcs_a
            .iter()
            .map(|f| format!("0x{:x}", f.address))
            .collect();
        let cols = matrix
            .funcs_b
            .iter()
            .map(|f| format!("0x{:x}", f.address))
            .collect();
        Self {
            rows,
            cols,
            cells: matrix.matrix.clone(),
        }
    }

    #[must_use]
    pub fn to_ascii(&self, width: usize) -> String {
        let scale = |v: f64| -> char {
            if v < 0.1 {
                ' '
            } else if v < 0.2 {
                '░'
            } else if v < 0.5 {
                '▒'
            } else if v < 0.8 {
                '▓'
            } else {
                '█'
            }
        };
        let mut s = String::new();
        for row in &self.cells {
            let take = if width == 0 {
                row.len()
            } else {
                width.min(row.len())
            };
            for &v in row.iter().take(take) {
                s.push(scale(v));
            }
            s.push('\n');
        }
        s
    }

    #[must_use]
    pub fn max_score(&self) -> f64 {
        self.cells
            .iter()
            .flat_map(|r| r.iter())
            .copied()
            .fold(0.0f64, f64::max)
    }

    #[must_use]
    pub fn avg_score(&self) -> f64 {
        let flat: Vec<f64> = self.cells.iter().flat_map(|r| r.iter().copied()).collect();
        if flat.is_empty() {
            0.0
        } else {
            flat.iter().sum::<f64>()
                / f64::from(u32::try_from(flat.len()).unwrap_or(u32::MAX))
        }
    }
}

// ── CrossBinaryCluster ────────────────────────────────────────────────────────

/// Groups highly similar functions across two binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossBinaryCluster {
    pub cluster_id: usize,
    pub functions_a: Vec<u64>,
    pub functions_b: Vec<u64>,
    pub avg_similarity: f64,
}

impl CrossBinaryCluster {
    #[must_use]
    pub const fn size(&self) -> usize {
        self.functions_a.len() + self.functions_b.len()
    }
}

/// Clusters functions with mutual similarity above `threshold`.
pub struct CrossBinaryClusterer {
    pub threshold: f64,
}

impl CrossBinaryClusterer {
    #[must_use]
    pub const fn new(threshold: f64) -> Self {
        Self { threshold }
    }

    /// Form clusters from a similarity matrix.
    #[must_use]
    pub fn cluster(&self, matrix: &SimilarityMatrix) -> Vec<CrossBinaryCluster> {
        let assignments = GreedyAssignment::assign(matrix, self.threshold);
        let mut idx_a_map: HashMap<u64, usize> = HashMap::new();
        let mut clusters: Vec<CrossBinaryCluster> = Vec::new();

        for (id, entry) in assignments.iter().enumerate() {
            let cluster_id = *idx_a_map.entry(entry.func_a).or_insert(id);
            if cluster_id == id {
                clusters.push(CrossBinaryCluster {
                    cluster_id: id,
                    functions_a: vec![entry.func_a],
                    functions_b: vec![entry.func_b],
                    avg_similarity: entry.score,
                });
            }
        }
        clusters
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(addr: u64, bb: u32) -> FunctionInfo {
        FunctionInfo {
            address: addr,
            name: None,
            bytes_crc32: 0,
            in_edges: 0,
            out_edges: 0,
            bb_count: bb,
            md_index: 0,
        }
    }

    fn make_named_func(addr: u64, name: &str, bb: u32) -> FunctionInfo {
        FunctionInfo {
            address: addr,
            name: Some(name.to_string()),
            bytes_crc32: 0,
            in_edges: 0,
            out_edges: 0,
            bb_count: bb,
            md_index: 0,
        }
    }

    // ── SimEntry ─────────────────────────────────────────────────────────────

    #[test]
    fn test_sim_entry_high_similarity() {
        assert!(SimEntry::new(0, 1, 0.95).is_high_similarity());
        assert!(!SimEntry::new(0, 1, 0.5).is_high_similarity());
    }

    // ── SimilarityMatrix ──────────────────────────────────────────────────────

    #[test]
    fn test_matrix_build() {
        let a = vec![make_func(0x1000, 5)];
        let b = vec![make_func(0x2000, 5)];
        let m = SimilarityMatrix::build(a, b);
        assert_eq!(m.rows(), 1);
        assert_eq!(m.cols(), 1);
    }

    #[test]
    fn test_matrix_get() {
        let a = vec![make_named_func(0x1000, "foo", 5)];
        let b = vec![make_named_func(0x2000, "foo", 5)]; // same name → high score
        let m = SimilarityMatrix::build(a, b);
        let score = m.get(0, 0).unwrap();
        assert!(score > 0.0);
    }

    #[test]
    fn test_matrix_all_entries_sorted() {
        let a = vec![make_func(0x1000, 5), make_func(0x1010, 10)];
        let b = vec![make_func(0x2000, 5), make_func(0x2010, 10)];
        let m = SimilarityMatrix::build(a, b);
        let entries = m.all_entries();
        for w in entries.windows(2) {
            assert!(w[0].score >= w[1].score);
        }
    }

    #[test]
    fn test_matrix_best_matches_a() {
        let a = vec![make_named_func(0x1000, "main", 10)];
        let b = vec![
            make_named_func(0x2000, "main", 10),
            make_named_func(0x2010, "other", 5),
        ];
        let m = SimilarityMatrix::build(a, b);
        let bests = m.best_matches_a();
        assert_eq!(bests.len(), 1);
        assert!(bests[0].is_some());
    }

    #[test]
    fn test_matrix_2x2() {
        let a = vec![make_func(1, 5), make_func(2, 10)];
        let b = vec![make_func(3, 5), make_func(4, 10)];
        let m = SimilarityMatrix::build(a, b);
        assert_eq!(m.rows(), 2);
        assert_eq!(m.cols(), 2);
        assert!(m.get(0, 0).is_some());
        assert!(m.get(1, 1).is_some());
    }

    // ── BestMatchFinder ───────────────────────────────────────────────────────

    #[test]
    fn test_best_match_finder() {
        let finder = BestMatchFinder::new(0.0);
        let a = make_named_func(0x1000, "foo", 5);
        let b = vec![
            make_named_func(0x2000, "foo", 5),
            make_named_func(0x2010, "bar", 10),
        ];
        let best = finder.find_best(&a, &b);
        assert!(best.is_some());
        let (_, score) = best.unwrap();
        assert!(score > 0.0);
    }

    #[test]
    fn test_best_match_finder_top_n() {
        let finder = BestMatchFinder::new(0.0);
        let a = make_func(0, 5);
        let b: Vec<FunctionInfo> = (0..10_u32).map(|i| make_func(u64::from(i) + 1, 5 + i)).collect();
        let top = finder.find_top_n(&a, &b, 3);
        assert!(top.len() <= 3);
        for w in top.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[test]
    fn test_best_match_finder_threshold() {
        let finder = BestMatchFinder::new(0.99); // very high threshold
        let a = make_func(0, 5);
        let b = vec![make_func(1, 10)]; // different bb_count → likely below 0.99
        let best = finder.find_best(&a, &b);
        let _ = best; // may or may not match
    }

    // ── ThresholdFilter ───────────────────────────────────────────────────────

    #[test]
    fn test_threshold_filter() {
        let f = ThresholdFilter::new(0.5);
        let entries = vec![SimEntry::new(0, 1, 0.9), SimEntry::new(0, 2, 0.3)];
        let filtered = f.filter(&entries);
        assert_eq!(filtered.len(), 1);
        assert!((filtered[0].score - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_threshold_filter_owned() {
        let f = ThresholdFilter::new(0.7);
        let entries = vec![SimEntry::new(0, 1, 0.8), SimEntry::new(0, 2, 0.5)];
        let filtered = f.filter_owned(entries);
        assert_eq!(filtered.len(), 1);
    }

    // ── GreedyAssignment ──────────────────────────────────────────────────────

    #[test]
    fn test_greedy_assignment_basic() {
        let a = vec![make_named_func(0x1000, "foo", 5)];
        let b = vec![make_named_func(0x2000, "foo", 5)];
        let m = SimilarityMatrix::build(a, b);
        let assigned = GreedyAssignment::assign(&m, 0.0);
        assert!(!assigned.is_empty());
    }

    #[test]
    fn test_greedy_assignment_no_duplicates() {
        let a = vec![make_named_func(1, "f1", 5), make_named_func(2, "f2", 5)];
        let b = vec![make_named_func(3, "f1", 5), make_named_func(4, "f2", 5)];
        let m = SimilarityMatrix::build(a, b);
        let assigned = GreedyAssignment::assign(&m, 0.0);
        let b_addrs: Vec<u64> = assigned.iter().map(|e| e.func_b).collect();
        let mut uniq = b_addrs.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(b_addrs.len(), uniq.len()); // no duplicate B assignments
    }

    // ── SimilarityHeatmap ─────────────────────────────────────────────────────

    #[test]
    fn test_heatmap_from_matrix() {
        let a = vec![make_func(1, 5)];
        let b = vec![make_func(2, 5), make_func(3, 10)];
        let m = SimilarityMatrix::build(a, b);
        let hm = SimilarityHeatmap::from_matrix(&m);
        assert_eq!(hm.rows.len(), 1);
        assert_eq!(hm.cols.len(), 2);
    }

    #[test]
    fn test_heatmap_ascii_nonempty() {
        let a = vec![make_func(1, 5), make_func(2, 10)];
        let b = vec![make_func(3, 5), make_func(4, 10)];
        let m = SimilarityMatrix::build(a, b);
        let hm = SimilarityHeatmap::from_matrix(&m);
        let ascii = hm.to_ascii(80);
        assert!(!ascii.is_empty());
    }

    #[test]
    fn test_heatmap_max_score() {
        let a = vec![make_named_func(1, "foo", 5)];
        let b = vec![make_named_func(2, "foo", 5)];
        let m = SimilarityMatrix::build(a, b);
        let hm = SimilarityHeatmap::from_matrix(&m);
        assert!(hm.max_score() > 0.0);
    }

    #[test]
    fn test_heatmap_avg_score() {
        let a = vec![make_func(1, 5)];
        let b = vec![make_func(2, 5)];
        let m = SimilarityMatrix::build(a, b);
        let hm = SimilarityHeatmap::from_matrix(&m);
        let avg = hm.avg_score();
        assert!((0.0..=1.0).contains(&avg));
    }

    // ── CrossBinaryClusterer ──────────────────────────────────────────────────

    #[test]
    fn test_clusterer_basic() {
        let a = vec![make_named_func(1, "foo", 5)];
        let b = vec![make_named_func(2, "foo", 5)];
        let m = SimilarityMatrix::build(a, b);
        let clusterer = CrossBinaryClusterer::new(0.0);
        let clusters = clusterer.cluster(&m);
        let _ = clusters; // may be empty or not; just no panic
    }

    #[test]
    fn test_cluster_size() {
        let c = CrossBinaryCluster {
            cluster_id: 0,
            functions_a: vec![1, 2],
            functions_b: vec![3],
            avg_similarity: 0.9,
        };
        assert_eq!(c.size(), 3);
    }
}
