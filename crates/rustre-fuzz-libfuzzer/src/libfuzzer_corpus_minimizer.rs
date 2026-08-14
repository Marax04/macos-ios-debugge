//! `LibFuzzer` corpus minimization.
//!
//! Provides [`LibFuzzerCorpusMinimizer`], [`MinimizeResult`], [`CoverageMatrix`],
//! and the top-level [`LibFuzzerCorpusMinimizer::minimize`] method that reduces a
//! corpus to a minimal set of inputs still covering all observed edges.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, Instant};

use rayon::prelude::*;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the corpus minimizer.
#[derive(Debug, Error, Clone)]
pub enum MinimizerError {
    #[error("corpus is empty")]
    EmptyCorpus,

    #[error("coverage matrix has no edges")]
    NoEdges,

    #[error("input {0} has no coverage data")]
    MissingCoverage(usize),

    #[error("time limit exceeded after {0:?}")]
    TimeLimitExceeded(Duration),

    #[error("io error: {0}")]
    Io(String),
}

// ─── CoverageMatrix ───────────────────────────────────────────────────────────

/// Maps each corpus input (by index) to the set of coverage edges it activates.
///
/// Used by [`LibFuzzerCorpusMinimizer`] to compute which inputs are necessary for
/// full coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMatrix {
    /// Number of corpus entries.
    pub input_count: usize,
    /// Total unique edges observed across the corpus.
    pub edge_count: usize,
    /// `input_index` → set of covered edge IDs.
    coverage: HashMap<usize, HashSet<u32>>,
    /// `edge_id` → set of input indices that cover it.
    reverse: HashMap<u32, HashSet<usize>>,
}

impl CoverageMatrix {
    /// Create an empty matrix for `input_count` inputs.
    #[must_use]
    pub fn new(input_count: usize) -> Self {
        Self {
            input_count,
            edge_count: 0,
            coverage: HashMap::new(),
            reverse: HashMap::new(),
        }
    }

    /// Record that `input_idx` covers `edges`.
    pub fn add_coverage(&mut self, input_idx: usize, edges: impl IntoIterator<Item = u32>) {
        let entry = self.coverage.entry(input_idx).or_default();
        for edge in edges {
            if entry.insert(edge) {
                // Only update reverse map and edge count for genuinely new edges.
                let rev = self.reverse.entry(edge).or_default();
                rev.insert(input_idx);
                if rev.len() == 1 {
                    // First time we see this edge globally.
                    self.edge_count += 1;
                }
            }
        }
    }

    /// Return the edges covered by `input_idx`.
    #[must_use]
    pub fn edges_for(&self, input_idx: usize) -> &HashSet<u32> {
        static EMPTY: std::sync::LazyLock<HashSet<u32>> =
            std::sync::LazyLock::new(HashSet::new);
        self.coverage.get(&input_idx).unwrap_or(&EMPTY)
    }

    /// Return the inputs that cover `edge_id`.
    #[must_use]
    pub fn inputs_for_edge(&self, edge_id: u32) -> Option<&HashSet<usize>> {
        self.reverse.get(&edge_id)
    }

    /// All edge IDs seen in the matrix.
    #[must_use]
    pub fn all_edges(&self) -> HashSet<u32> {
        self.reverse.keys().copied().collect()
    }

    /// Return the number of unique edges covered by `input_idx`.
    #[must_use]
    pub fn coverage_count(&self, input_idx: usize) -> usize {
        self.coverage.get(&input_idx).map_or(0, HashSet::len)
    }

    /// Build a synthetic matrix from raw coverage bytes per input.
    ///
    /// Each byte in the coverage slice represents one edge bucket; non-zero bytes
    /// are treated as active edges.
    #[must_use]
    pub fn from_coverage_bytes(coverage_bytes: &[Vec<u8>]) -> Self {
        let mut m = Self::new(coverage_bytes.len());
        for (idx, cov) in coverage_bytes.iter().enumerate() {
            let edges: Vec<u32> = cov
                .iter()
                .enumerate()
                .filter(|(_, b)| **b != 0)
                .map(|(i, _)| i as u32)
                .collect();
            m.add_coverage(idx, edges);
        }
        m
    }

    /// Compute a coverage fingerprint (FNV-1a hash of all edge IDs, sorted).
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        let mut edges: Vec<u32> = self.reverse.keys().copied().collect();
        edges.sort_unstable();
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = OFFSET;
        for e in edges {
            for b in e.to_le_bytes() {
                h ^= u64::from(b);
                h = h.wrapping_mul(PRIME);
            }
        }
        h
    }
}

// ─── MinimizeConfig ───────────────────────────────────────────────────────────

/// Configuration options for the minimization run.
#[derive(Debug, Clone)]
pub struct MinimizeConfig {
    /// Prefer smaller inputs over later-registered ones.
    pub prefer_smaller: bool,
    /// Maximum number of corpus entries to keep (0 = unlimited).
    pub max_output_size: usize,
    /// Optional wall-clock time limit for the minimization.
    pub time_limit: Option<Duration>,
    /// Whether to remove syntactically duplicate inputs (same hash).
    pub dedup_identical: bool,
}

impl Default for MinimizeConfig {
    fn default() -> Self {
        Self {
            prefer_smaller: true,
            max_output_size: 0,
            time_limit: None,
            dedup_identical: true,
        }
    }
}

// ─── MinimizeResult ───────────────────────────────────────────────────────────

/// The result of a corpus minimization run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimizeResult {
    /// Indices (into the original corpus) of the retained inputs.
    pub retained_indices: Vec<usize>,
    /// Indices of the discarded inputs.
    pub discarded_indices: Vec<usize>,
    /// Number of unique edges covered by the retained set.
    pub covered_edges: usize,
    /// Total unique edges in the original corpus.
    pub total_edges: usize,
    /// Coverage ratio in [0.0, 1.0].
    pub coverage_ratio: f64,
    /// Wall-clock time taken.
    pub elapsed: Duration,
    /// Whether any inputs were deduplicated (identical bytes).
    pub deduplication_applied: bool,
}

impl MinimizeResult {
    /// Return the reduction ratio: (original − retained) / original.
    #[must_use]
    pub fn reduction_ratio(&self, original_count: usize) -> f64 {
        if original_count == 0 {
            return 0.0;
        }
        let retained = self.retained_indices.len();
        1.0 - (retained as f64 / original_count as f64)
    }

    /// Size of the retained corpus.
    #[must_use]
    pub const fn retained_count(&self) -> usize {
        self.retained_indices.len()
    }

    /// Size of the discarded set.
    #[must_use]
    pub const fn discarded_count(&self) -> usize {
        self.discarded_indices.len()
    }
}

impl fmt::Display for MinimizeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MinimizeResult {{ retained={}, discarded={}, coverage={}/{} ({:.1}%), elapsed={:.2?} }}",
            self.retained_count(),
            self.discarded_count(),
            self.covered_edges,
            self.total_edges,
            self.coverage_ratio * 100.0,
            self.elapsed,
        )
    }
}

// ─── LibFuzzerCorpusMinimizer ─────────────────────────────────────────────────

/// Minimizes a libFuzzer-style corpus using a greedy set-cover algorithm.
///
/// The minimizer iterates until all observed edges are covered, at each step
/// picking the corpus entry that covers the most currently-uncovered edges.
/// Ties are broken by input size (prefer shorter) when `config.prefer_smaller`
/// is set.
pub struct LibFuzzerCorpusMinimizer {
    /// Configuration for this minimizer.
    pub config: MinimizeConfig,
}

impl LibFuzzerCorpusMinimizer {
    /// Create with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self { config: MinimizeConfig::default() }
    }

    /// Create with explicit configuration.
    #[must_use]
    pub const fn with_config(config: MinimizeConfig) -> Self {
        Self { config }
    }

    /// Minimize the corpus represented by `inputs` and `matrix`.
    ///
    /// `inputs[i]` is the raw byte vector for the i-th corpus entry.
    /// `matrix` holds the coverage data for each entry.
    ///
    /// Returns a [`MinimizeResult`] or [`MinimizerError`] on failure.
    ///
    /// # Errors
    /// Returns [`MinimizerError::EmptyCorpus`] if `inputs` is empty.
    /// Returns [`MinimizerError::NoEdges`] if the matrix has no edges.
    /// Returns [`MinimizerError::TimeLimitExceeded`] if the time limit is hit.
    pub fn minimize(
        &self,
        inputs: &[Vec<u8>],
        matrix: &CoverageMatrix,
    ) -> Result<MinimizeResult, MinimizerError> {
        if inputs.is_empty() {
            return Err(MinimizerError::EmptyCorpus);
        }
        if matrix.edge_count == 0 {
            return Err(MinimizerError::NoEdges);
        }

        let start = Instant::now();
        let total_edges = matrix.edge_count;

        // Step 1 — Optional deduplication by content hash.
        let dedup_applied;
        let active_indices: Vec<usize> = if self.config.dedup_identical {
            dedup_applied = true;
            let mut seen_hashes: HashSet<u64> = HashSet::new();
            inputs
                .iter()
                .enumerate()
                .filter(|(_, data)| seen_hashes.insert(fnv1a(data)))
                .map(|(i, _)| i)
                .collect()
        } else {
            dedup_applied = false;
            (0..inputs.len()).collect()
        };

        // Step 2 — Greedy set-cover.
        let all_edges = matrix.all_edges();
        let mut uncovered: HashSet<u32> = all_edges;
        let mut retained: Vec<usize> = Vec::new();

        while !uncovered.is_empty() {
            // Check time limit.
            if let Some(limit) = self.config.time_limit {
                let elapsed = start.elapsed();
                if elapsed > limit {
                    return Err(MinimizerError::TimeLimitExceeded(elapsed));
                }
            }

            // Find the best candidate among active indices not yet retained.
            // Uses rayon to evaluate candidates in parallel.
            let already: HashSet<usize> = retained.iter().copied().collect();
            let prefer_smaller = self.config.prefer_smaller;
            let best = active_indices
                .par_iter()
                .filter(|&&i| !already.contains(&i))
                .max_by_key(|&&i| {
                    let edges = matrix.edges_for(i);
                    let new_edges = edges.intersection(&uncovered).count();
                    // Tiebreak: prefer smaller inputs when configured.
                    let size_penalty = if prefer_smaller {
                        usize::MAX - inputs[i].len()
                    } else {
                        0
                    };
                    (new_edges, size_penalty)
                });

            match best {
                Some(&idx) => {
                    let edges = matrix.edges_for(idx);
                    let newly: Vec<u32> =
                        edges.intersection(&uncovered).copied().collect();
                    if newly.is_empty() {
                        // No active candidate can cover new edges — stop.
                        break;
                    }
                    for e in newly {
                        uncovered.remove(&e);
                    }
                    retained.push(idx);
                }
                None => break,
            }

            // Enforce max_output_size cap.
            if self.config.max_output_size > 0
                && retained.len() >= self.config.max_output_size
            {
                break;
            }
        }

        // Step 3 — Record discarded indices.
        let retained_set: HashSet<usize> = retained.iter().copied().collect();
        let discarded: Vec<usize> = (0..inputs.len())
            .filter(|i| !retained_set.contains(i))
            .collect();

        let covered_edges = total_edges - uncovered.len();
        let coverage_ratio = if total_edges == 0 {
            0.0
        } else {
            (covered_edges as f64) / (total_edges as f64)
        };

        Ok(MinimizeResult {
            retained_indices: retained,
            discarded_indices: discarded,
            covered_edges,
            total_edges,
            coverage_ratio,
            elapsed: start.elapsed(),
            deduplication_applied: dedup_applied,
        })
    }

    /// Build a coverage matrix from raw inputs using a synthetic edge function.
    ///
    /// Each input's coverage is derived from the FNV-1a hash of the input,
    /// mapped to 8 synthetic edge IDs.  This is a stand-in for real
    /// instrumentation-based coverage.
    #[must_use]
    pub fn synthetic_coverage(inputs: &[Vec<u8>]) -> CoverageMatrix {
        let mut m = CoverageMatrix::new(inputs.len());
        for (i, input) in inputs.iter().enumerate() {
            let h = fnv1a(input);
            // Generate 8 edge IDs from the hash.
            let edges: Vec<u32> = (0u8..8)
                .map(|shift| ((h >> (shift * 8)) & 0xFF) as u32)
                .collect();
            m.add_coverage(i, edges);
        }
        m
    }

    /// Compute coverage density: number of retained inputs per edge.
    #[must_use]
    pub fn compute_density(retained: &[usize], matrix: &CoverageMatrix) -> f64 {
        if matrix.edge_count == 0 {
            return 0.0;
        }
        let total_coverage: usize = retained
            .iter()
            .map(|&i| matrix.coverage_count(i))
            .sum();
        (total_coverage as f64) / (matrix.edge_count as f64)
    }
}

impl Default for LibFuzzerCorpusMinimizer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// FNV-1a (64-bit) hash.
#[inline]
fn fnv1a(data: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

// ─── CorpusSizeBudget ─────────────────────────────────────────────────────────

/// Tracks whether a minimized corpus stays within a configured size budget.
#[derive(Debug, Clone)]
pub struct CorpusSizeBudget {
    /// Maximum total bytes across all retained inputs.
    pub max_bytes: usize,
    /// Maximum number of retained entries.
    pub max_entries: usize,
}

impl CorpusSizeBudget {
    /// Create a budget.
    #[must_use]
    pub const fn new(max_bytes: usize, max_entries: usize) -> Self {
        Self { max_bytes, max_entries }
    }

    /// Returns `true` if the retained inputs fit within the budget.
    #[must_use]
    pub fn fits(&self, retained: &[usize], inputs: &[Vec<u8>]) -> bool {
        if retained.len() > self.max_entries {
            return false;
        }
        let total: usize = retained.iter().map(|&i| inputs[i].len()).sum();
        total <= self.max_bytes
    }

    /// Trim `retained` to fit within the budget, dropping larger entries first.
    #[must_use]
    pub fn trim(&self, mut retained: Vec<usize>, inputs: &[Vec<u8>]) -> Vec<usize> {
        // First enforce entry count.
        if retained.len() > self.max_entries {
            retained.truncate(self.max_entries);
        }
        // Then enforce byte budget by removing largest entries.
        loop {
            let total: usize = retained.iter().map(|&i| inputs[i].len()).sum();
            if total <= self.max_bytes {
                break;
            }
            if retained.is_empty() {
                break;
            }
            // Remove the largest entry.
            let max_idx = retained
                .iter()
                .enumerate()
                .max_by_key(|(_, i)| inputs[**i].len())
                .map(|(pos, _)| pos)
                .unwrap();
            retained.remove(max_idx);
        }
        retained
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inputs() -> Vec<Vec<u8>> {
        vec![
            b"hello world".to_vec(),
            b"foo bar".to_vec(),
            b"test input".to_vec(),
            b"another test".to_vec(),
            b"x".to_vec(),
        ]
    }

    fn make_matrix(inputs: &[Vec<u8>]) -> CoverageMatrix {
        LibFuzzerCorpusMinimizer::synthetic_coverage(inputs)
    }

    #[test]
    fn test_basic_minimization() {
        let inputs = make_inputs();
        let matrix = make_matrix(&inputs);
        let minimizer = LibFuzzerCorpusMinimizer::new();
        let result = minimizer.minimize(&inputs, &matrix).unwrap();
        assert!(!result.retained_indices.is_empty());
        assert!(result.coverage_ratio > 0.0);
        assert_eq!(
            result.retained_count() + result.discarded_count(),
            inputs.len()
        );
    }

    #[test]
    fn test_empty_corpus_error() {
        let minimizer = LibFuzzerCorpusMinimizer::new();
        let matrix = CoverageMatrix::new(0);
        let err = minimizer.minimize(&[], &matrix).unwrap_err();
        assert!(matches!(err, MinimizerError::EmptyCorpus));
    }

    #[test]
    fn test_no_edges_error() {
        let minimizer = LibFuzzerCorpusMinimizer::new();
        let inputs = make_inputs();
        let matrix = CoverageMatrix::new(inputs.len()); // no coverage added
        let err = minimizer.minimize(&inputs, &matrix).unwrap_err();
        assert!(matches!(err, MinimizerError::NoEdges));
    }

    #[test]
    fn test_dedup_identical() {
        let inputs = vec![
            b"dup".to_vec(),
            b"dup".to_vec(),
            b"unique".to_vec(),
        ];
        let matrix = LibFuzzerCorpusMinimizer::synthetic_coverage(&inputs);
        let minimizer = LibFuzzerCorpusMinimizer::new();
        let result = minimizer.minimize(&inputs, &matrix).unwrap();
        assert!(result.deduplication_applied);
        // The two "dup" entries should be collapsed to one.
        assert!(result.retained_count() <= 2);
    }

    #[test]
    fn test_coverage_matrix_add() {
        let mut m = CoverageMatrix::new(3);
        m.add_coverage(0, [1, 2, 3]);
        m.add_coverage(1, [3, 4]);
        m.add_coverage(2, [5]);
        assert_eq!(m.edge_count, 5);
        assert!(m.edges_for(0).contains(&1));
        assert!(m.inputs_for_edge(3).unwrap().contains(&0));
        assert!(m.inputs_for_edge(3).unwrap().contains(&1));
    }

    #[test]
    fn test_max_output_size() {
        let inputs = make_inputs();
        let matrix = make_matrix(&inputs);
        let config = MinimizeConfig {
            max_output_size: 2,
            ..Default::default()
        };
        let minimizer = LibFuzzerCorpusMinimizer::with_config(config);
        let result = minimizer.minimize(&inputs, &matrix).unwrap();
        assert!(result.retained_count() <= 2);
    }

    #[test]
    fn test_coverage_density() {
        let inputs = make_inputs();
        let matrix = make_matrix(&inputs);
        let all: Vec<usize> = (0..inputs.len()).collect();
        let density = LibFuzzerCorpusMinimizer::compute_density(&all, &matrix);
        assert!(density >= 0.0);
    }

    #[test]
    fn test_corpus_size_budget_trim() {
        let inputs = vec![
            vec![0u8; 100],
            vec![0u8; 50],
            vec![0u8; 10],
        ];
        let budget = CorpusSizeBudget::new(120, 3);
        let retained = budget.trim(vec![0, 1, 2], &inputs);
        let total: usize = retained.iter().map(|&i| inputs[i].len()).sum();
        assert!(total <= 120);
    }

    #[test]
    fn test_matrix_fingerprint_deterministic() {
        let inputs = make_inputs();
        let m1 = LibFuzzerCorpusMinimizer::synthetic_coverage(&inputs);
        let m2 = LibFuzzerCorpusMinimizer::synthetic_coverage(&inputs);
        assert_eq!(m1.fingerprint(), m2.fingerprint());
    }
}
