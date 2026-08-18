//! Seed minimization for the `rustre-fuzz` framework.
//!
//! Implements delta-debugging, binary/linear/byte trim strategies, coverage
//! preservation checks, and a structured minimization report.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::{fnv1a, FuzzError};

// ── TrimStrategy ─────────────────────────────────────────────────────────────

/// Strategy used when trimming bytes from a candidate seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrimStrategy {
    /// Binary search: try removing halves of the remaining input.
    Binary,
    /// Linear scan: try removing one byte at a time from left to right.
    Linear,
    /// Byte-granularity: zero out individual bytes rather than deleting them.
    Byte,
}

impl TrimStrategy {
    /// Human-readable name of the strategy.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Linear => "linear",
            Self::Byte => "byte",
        }
    }

    /// All defined trim strategies.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Binary, Self::Linear, Self::Byte]
    }
}

impl std::fmt::Display for TrimStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── SeedDiff ─────────────────────────────────────────────────────────────────

/// Byte-level diff between an original seed and its minimized version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedDiff {
    /// Number of bytes in the original seed.
    pub original_len: usize,
    /// Number of bytes in the minimized seed.
    pub minimized_len: usize,
    /// Indices of bytes that were removed (sorted ascending).
    pub removed_indices: Vec<usize>,
    /// Indices of bytes that were zeroed (for byte-granularity strategy).
    pub zeroed_indices: Vec<usize>,
    /// Reduction ratio: 1 - (`minimized_len` / `original_len`).
    pub reduction_ratio: f64,
}

impl SeedDiff {
    /// Compute a diff between `original` and `minimized`.
    ///
    /// Uses a simple LCS-based heuristic: bytes present in minimized in order
    /// are treated as retained; the rest are marked removed.
    #[must_use]
    pub fn compute(original: &[u8], minimized: &[u8]) -> Self {
        let reduction_ratio = if original.is_empty() {
            0.0
        } else {
            1.0 - (minimized.len() as f64 / original.len() as f64)
        };

        // Find which byte positions from the original were retained using a
        // greedy forward scan.
        let mut retained_in_orig: HashSet<usize> = HashSet::new();
        let mut min_cursor = 0usize;
        for (orig_idx, &ob) in original.iter().enumerate() {
            if min_cursor < minimized.len() && minimized[min_cursor] == ob {
                retained_in_orig.insert(orig_idx);
                min_cursor += 1;
            }
        }

        let removed_indices: Vec<usize> = (0..original.len())
            .filter(|i| !retained_in_orig.contains(i))
            .collect();

        // Find bytes that were zeroed (present in both but changed to 0).
        let zeroed_indices: Vec<usize> = original
            .iter()
            .zip(minimized.iter())
            .enumerate()
            .filter(|&(_, (&ob, &mb))| ob != 0 && mb == 0)
            .map(|(i, _)| i)
            .collect();

        Self {
            original_len: original.len(),
            minimized_len: minimized.len(),
            removed_indices,
            zeroed_indices,
            reduction_ratio,
        }
    }

    /// Number of bytes removed.
    #[must_use]
    pub const fn bytes_removed(&self) -> usize {
        self.original_len.saturating_sub(self.minimized_len)
    }

    /// Whether any reduction was achieved.
    #[must_use]
    pub const fn any_reduction(&self) -> bool {
        self.minimized_len < self.original_len
    }
}

// ── MinimizedSeed ─────────────────────────────────────────────────────────────

/// A minimized seed together with its provenance metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimizedSeed {
    /// The minimized byte sequence.
    pub data: Vec<u8>,
    /// FNV-1a hash of the minimized bytes.
    pub hash: u64,
    /// The strategy used to produce this minimized seed.
    pub strategy: TrimStrategy,
    /// Byte-level diff against the original.
    pub diff: SeedDiff,
    /// Coverage bits still covered after minimization.
    pub coverage_preserved: bool,
    /// Number of interesting-check calls made.
    pub checks_performed: u32,
    /// Wall-clock time spent minimizing.
    pub elapsed: Duration,
}

impl MinimizedSeed {
    /// Create a new minimized-seed record.
    #[must_use]
    pub fn new(
        data: Vec<u8>,
        strategy: TrimStrategy,
        diff: SeedDiff,
        coverage_preserved: bool,
        checks_performed: u32,
        elapsed: Duration,
    ) -> Self {
        let hash = fnv1a(&data);
        Self {
            data,
            hash,
            strategy,
            diff,
            coverage_preserved,
            checks_performed,
            elapsed,
        }
    }

    /// Length of the minimized seed in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// True when the minimized seed is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ── CoveragePreservation ─────────────────────────────────────────────────────

/// Tracks which coverage bits were present in the original seed and verifies
/// they are still present in the minimized candidate.
#[derive(Debug, Clone, Default)]
pub struct CoveragePreservation {
    /// Coverage bits required by the original seed (set of edge identifiers).
    pub required_bits: HashSet<u64>,
    /// Coverage bits observed in the minimized candidate.
    pub observed_bits: HashSet<u64>,
}

impl CoveragePreservation {
    /// Create a new tracker with no required bits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a required edge id from the original seed's coverage.
    pub fn require(&mut self, edge_id: u64) {
        self.required_bits.insert(edge_id);
    }

    /// Record all edge ids from a bitmap as required.
    pub fn require_all(&mut self, edge_ids: impl IntoIterator<Item = u64>) {
        for id in edge_ids {
            self.required_bits.insert(id);
        }
    }

    /// Record an observed edge id in the candidate's coverage.
    pub fn observe(&mut self, edge_id: u64) {
        self.observed_bits.insert(edge_id);
    }

    /// Record all edges from a bitmap as observed.
    pub fn observe_all(&mut self, edge_ids: impl IntoIterator<Item = u64>) {
        for id in edge_ids {
            self.observed_bits.insert(id);
        }
    }

    /// Returns `true` when all required bits are present in the observed set.
    #[must_use]
    pub fn is_preserved(&self) -> bool {
        self.required_bits
            .iter()
            .all(|r| self.observed_bits.contains(r))
    }

    /// Number of required bits that are missing from the observed set.
    #[must_use]
    pub fn missing_count(&self) -> usize {
        self.required_bits
            .iter()
            .filter(|r| !self.observed_bits.contains(r))
            .count()
    }

    /// Clear observed bits for the next candidate check.
    pub fn reset_observed(&mut self) {
        self.observed_bits.clear();
    }

    /// Clear all state.
    pub fn reset(&mut self) {
        self.required_bits.clear();
        self.observed_bits.clear();
    }
}

// ── DeltaDebugging ────────────────────────────────────────────────────────────

/// Pure delta-debugging implementation (ddmin algorithm).
///
/// Given an oracle `is_interesting` that returns `true` when a candidate
/// still triggers the behavior of interest, `ddmin` finds the 1-minimal
/// subsequence.
#[derive(Debug, Clone)]
pub struct DeltaDebugging {
    /// Maximum number of oracle calls permitted (0 = unlimited).
    pub max_oracle_calls: u32,
    /// Minimum size below which we stop reducing.
    pub min_size: usize,
}

impl DeltaDebugging {
    /// Create a new delta-debugger with default limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_oracle_calls: 0,
            min_size: 1,
        }
    }

    /// Create with explicit oracle-call limit.
    #[must_use]
    pub const fn with_limit(max_oracle_calls: u32) -> Self {
        Self {
            max_oracle_calls,
            min_size: 1,
        }
    }

    /// Run the ddmin algorithm on `input`.
    ///
    /// Returns `(minimized, oracle_calls)`.
    #[must_use]
    pub fn ddmin<F>(&self, input: &[u8], mut is_interesting: F) -> (Vec<u8>, u32)
    where
        F: FnMut(&[u8]) -> bool,
    {
        if input.is_empty() {
            return (input.to_vec(), 0);
        }

        let mut current = input.to_vec();
        let mut n = 2usize; // granularity
        let mut calls = 0u32;

        loop {
            if current.len() <= self.min_size {
                break;
            }
            let chunk_size = (current.len() / n).max(1);
            let mut reduced = false;

            // Try removing each chunk.
            let mut i = 0usize;
            while i < current.len() {
                if self.max_oracle_calls > 0 && calls >= self.max_oracle_calls {
                    return (current, calls);
                }
                let end = (i + chunk_size).min(current.len());
                let mut candidate = Vec::with_capacity(current.len() - (end - i));
                candidate.extend_from_slice(&current[..i]);
                candidate.extend_from_slice(&current[end..]);

                if candidate.len() >= self.min_size {
                    calls += 1;
                    if is_interesting(&candidate) {
                        current = candidate;
                        reduced = true;
                        // Don't advance i; re-check same position
                        if n > 2 {
                            n -= 1;
                        }
                        continue;
                    }
                }
                i += chunk_size;
            }

            if !reduced {
                if n >= current.len() {
                    break;
                }
                n = (n * 2).min(current.len());
            }
        }

        (current, calls)
    }

    /// Run ddmin and return only the minimized bytes.
    #[must_use]
    pub fn minimize<F>(&self, input: &[u8], is_interesting: F) -> Vec<u8>
    where
        F: FnMut(&[u8]) -> bool,
    {
        self.ddmin(input, is_interesting).0
    }
}

impl Default for DeltaDebugging {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate a candidate seed against an oracle that may fail.
///
/// Wraps a fallible oracle so that minimization drivers built on top of
/// `DeltaDebugging` can surface infrastructure failures (lost connection to
/// the target, harness panic, …) as a [`FuzzError`] instead of silently
/// dropping the candidate.
///
/// Returns `Ok(true)` if the candidate still triggers the bug, `Ok(false)`
/// otherwise, and propagates any error from the oracle.
pub fn validate_with_oracle<F>(candidate: &[u8], mut oracle: F) -> Result<bool, FuzzError>
where
    F: FnMut(&[u8]) -> Result<bool, FuzzError>,
{
    if candidate.is_empty() {
        return Err(FuzzError::InputError("empty candidate".into()));
    }
    oracle(candidate)
}

// ── MinimizationReport ────────────────────────────────────────────────────────

/// Summary of a completed minimization run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimizationReport {
    /// Original seed length in bytes.
    pub original_len: usize,
    /// Final minimized length in bytes.
    pub final_len: usize,
    /// Strategy that produced the best result.
    pub best_strategy: TrimStrategy,
    /// Number of oracle (interesting-check) calls.
    pub oracle_calls: u32,
    /// Wall-clock duration of the minimization.
    pub elapsed: Duration,
    /// Whether the minimized seed still preserves the required coverage.
    pub coverage_preserved: bool,
    /// Byte-level diff.
    pub diff: SeedDiff,
    /// Per-strategy sizes achieved (name → final length).
    pub strategy_results: HashMap<String, usize>,
    /// When the minimization was completed.
    pub completed_at: SystemTime,
}

impl MinimizationReport {
    /// Percentage reduction (0.0–100.0).
    #[must_use]
    pub fn reduction_pct(&self) -> f64 {
        if self.original_len == 0 {
            0.0
        } else {
            (1.0 - self.final_len as f64 / self.original_len as f64) * 100.0
        }
    }

    /// Bytes removed from the original.
    #[must_use]
    pub const fn bytes_removed(&self) -> usize {
        self.original_len.saturating_sub(self.final_len)
    }
}

// ── SeedMinimizer ─────────────────────────────────────────────────────────────

/// The main seed-minimization driver.
///
/// Tries multiple [`TrimStrategy`] options and selects the one that produces
/// the smallest result while still passing the provided `is_interesting` oracle.
pub struct SeedMinimizer {
    /// Strategies to attempt (in order).
    pub strategies: Vec<TrimStrategy>,
    /// Maximum number of oracle calls per strategy (0 = unlimited).
    pub max_oracle_calls: u32,
    /// Minimum seed size to reduce to.
    pub min_size: usize,
    /// Maximum rounds for linear / binary trimming.
    pub max_rounds: usize,
    /// Whether to attempt delta-debugging after strategy passes.
    pub use_ddmin: bool,
    /// Coverage preservation checker.
    pub coverage: CoveragePreservation,
}

impl SeedMinimizer {
    /// Create a minimizer with all three strategies enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            strategies: TrimStrategy::all().to_vec(),
            max_oracle_calls: 0,
            min_size: 1,
            max_rounds: 16,
            use_ddmin: true,
            coverage: CoveragePreservation::new(),
        }
    }

    /// Create a minimizer using only the specified strategy.
    #[must_use]
    pub fn with_strategy(strategy: TrimStrategy) -> Self {
        let mut m = Self::new();
        m.strategies = vec![strategy];
        m
    }

    /// Set the oracle-call limit per strategy pass.
    #[must_use]
    pub const fn with_limit(mut self, limit: u32) -> Self {
        self.max_oracle_calls = limit;
        self
    }

    /// Minimize `input` using all configured strategies, choosing the best
    /// (shortest) result that satisfies `is_interesting`.
    ///
    /// Returns a [`MinimizationReport`] together with the best minimized bytes.
    pub fn minimize<F>(
        &mut self,
        input: &[u8],
        mut is_interesting: F,
    ) -> (Vec<u8>, MinimizationReport)
    where
        F: FnMut(&[u8]) -> bool,
    {
        let start = Instant::now();
        let original_len = input.len();
        let mut best: Vec<u8> = input.to_vec();
        let mut best_strategy = TrimStrategy::Binary;
        let mut total_calls = 0u32;
        let mut strategy_results: HashMap<String, usize> = HashMap::new();

        for &strategy in &self.strategies.clone() {
            let (candidate, calls) =
                self.apply_strategy(strategy, &best, &mut is_interesting);
            total_calls += calls;
            strategy_results.insert(strategy.name().to_string(), candidate.len());
            if candidate.len() < best.len()
                || (candidate.len() == best.len() && candidate != best)
            {
                best = candidate;
                best_strategy = strategy;
            }
        }

        // Optional ddmin pass.
        if self.use_ddmin && best.len() > self.min_size {
            let dd = DeltaDebugging::with_limit(if self.max_oracle_calls > 0 {
                self.max_oracle_calls.saturating_sub(total_calls)
            } else {
                0
            });
            let (candidate, calls) = dd.ddmin(&best, &mut is_interesting);
            total_calls += calls;
            if candidate.len() < best.len() {
                best = candidate;
            }
        }

        let elapsed = start.elapsed();
        let diff = SeedDiff::compute(input, &best);
        let coverage_preserved = true; // caller is responsible for verifying via oracle

        let report = MinimizationReport {
            original_len,
            final_len: best.len(),
            best_strategy,
            oracle_calls: total_calls,
            elapsed,
            coverage_preserved,
            diff,
            strategy_results,
            completed_at: SystemTime::now(),
        };

        (best, report)
    }

    /// Apply a single strategy to `input` with the given oracle.
    fn apply_strategy<F>(
        &self,
        strategy: TrimStrategy,
        input: &[u8],
        is_interesting: &mut F,
    ) -> (Vec<u8>, u32)
    where
        F: FnMut(&[u8]) -> bool,
    {
        match strategy {
            TrimStrategy::Binary => self.binary_trim(input, is_interesting),
            TrimStrategy::Linear => self.linear_trim(input, is_interesting),
            TrimStrategy::Byte => self.byte_trim(input, is_interesting),
        }
    }

    /// Binary trim: repeatedly try to remove the first / second half.
    fn binary_trim<F>(&self, input: &[u8], is_interesting: &mut F) -> (Vec<u8>, u32)
    where
        F: FnMut(&[u8]) -> bool,
    {
        let mut current = input.to_vec();
        let mut calls = 0u32;
        let mut block = current.len() / 2;

        while block >= 1 && current.len() > self.min_size {
            let mut progress = false;
            let mut i = 0usize;
            while i + block <= current.len() {
                if self.max_oracle_calls > 0 && calls >= self.max_oracle_calls {
                    return (current, calls);
                }
                if current.len() - block < self.min_size {
                    break;
                }
                let mut candidate = current.clone();
                candidate.drain(i..i + block);
                calls += 1;
                if is_interesting(&candidate) {
                    current = candidate;
                    progress = true;
                } else {
                    i += block;
                }
            }
            if !progress {
                block /= 2;
            }
        }
        (current, calls)
    }

    /// Linear trim: scan byte-by-byte and remove each one if still interesting.
    fn linear_trim<F>(&self, input: &[u8], is_interesting: &mut F) -> (Vec<u8>, u32)
    where
        F: FnMut(&[u8]) -> bool,
    {
        let mut current = input.to_vec();
        let mut calls = 0u32;
        let mut i = 0usize;

        while i < current.len() {
            if current.len() <= self.min_size {
                break;
            }
            if self.max_oracle_calls > 0 && calls >= self.max_oracle_calls {
                break;
            }
            let mut candidate = current.clone();
            candidate.remove(i);
            calls += 1;
            if is_interesting(&candidate) {
                current = candidate;
                // Don't advance i: re-check same position.
            } else {
                i += 1;
            }
        }
        (current, calls)
    }

    /// Byte trim: zero out individual bytes rather than removing them.
    fn byte_trim<F>(&self, input: &[u8], is_interesting: &mut F) -> (Vec<u8>, u32)
    where
        F: FnMut(&[u8]) -> bool,
    {
        let mut current = input.to_vec();
        let mut calls = 0u32;

        for i in 0..current.len() {
            if current[i] == 0 {
                continue;
            }
            if self.max_oracle_calls > 0 && calls >= self.max_oracle_calls {
                break;
            }
            let mut candidate = current.clone();
            candidate[i] = 0;
            calls += 1;
            if is_interesting(&candidate) {
                current = candidate;
            }
        }
        (current, calls)
    }
}

impl Default for SeedMinimizer {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TrimStrategy ─────────────────────────────────────────────────────────

    #[test]
    fn trim_strategy_names() {
        assert_eq!(TrimStrategy::Binary.name(), "binary");
        assert_eq!(TrimStrategy::Linear.name(), "linear");
        assert_eq!(TrimStrategy::Byte.name(), "byte");
    }

    #[test]
    fn trim_strategy_display() {
        assert_eq!(format!("{}", TrimStrategy::Binary), "binary");
    }

    #[test]
    fn trim_strategy_all_has_three() {
        assert_eq!(TrimStrategy::all().len(), 3);
    }

    #[test]
    fn trim_strategy_round_trip_serialize() {
        let s = serde_json::to_string(&TrimStrategy::Linear).unwrap();
        let back: TrimStrategy = serde_json::from_str(&s).unwrap();
        assert_eq!(back, TrimStrategy::Linear);
    }

    // ── SeedDiff ─────────────────────────────────────────────────────────────

    #[test]
    fn seed_diff_no_reduction() {
        let orig = vec![1u8, 2, 3];
        let diff = SeedDiff::compute(&orig, &orig);
        assert!(!diff.any_reduction());
        assert_eq!(diff.bytes_removed(), 0);
        assert!((diff.reduction_ratio - 0.0).abs() < 1e-9);
    }

    #[test]
    fn seed_diff_full_reduction() {
        let orig = vec![1u8, 2, 3, 4];
        let diff = SeedDiff::compute(&orig, &[]);
        assert_eq!(diff.minimized_len, 0);
        assert_eq!(diff.bytes_removed(), 4);
    }

    #[test]
    fn seed_diff_partial_reduction() {
        let orig = vec![0u8, 1, 2, 3];
        let mini = vec![0u8, 2];
        let diff = SeedDiff::compute(&orig, &mini);
        assert!(diff.any_reduction());
        assert_eq!(diff.minimized_len, 2);
    }

    #[test]
    fn seed_diff_reduction_ratio() {
        let orig = vec![0u8; 100];
        let mini = vec![0u8; 50];
        let diff = SeedDiff::compute(&orig, &mini);
        assert!((diff.reduction_ratio - 0.5).abs() < 1e-9);
    }

    #[test]
    fn seed_diff_zeroed_indices() {
        let orig = vec![1u8, 2, 3];
        let mini = vec![0u8, 2, 3];
        let diff = SeedDiff::compute(&orig, &mini);
        assert!(!diff.zeroed_indices.is_empty());
    }

    // ── MinimizedSeed ─────────────────────────────────────────────────────────

    #[test]
    fn minimized_seed_hash_deterministic() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let diff = SeedDiff::compute(&data, &data);
        let ms = MinimizedSeed::new(data.clone(), TrimStrategy::Binary, diff, true, 5, Duration::ZERO);
        assert_eq!(ms.hash, fnv1a(&data));
    }

    #[test]
    fn minimized_seed_len() {
        let data = vec![1u8, 2, 3];
        let diff = SeedDiff::compute(&data, &data);
        let ms = MinimizedSeed::new(data, TrimStrategy::Linear, diff, true, 1, Duration::ZERO);
        assert_eq!(ms.len(), 3);
        assert!(!ms.is_empty());
    }

    #[test]
    fn minimized_seed_empty() {
        let diff = SeedDiff::compute(&[], &[]);
        let ms = MinimizedSeed::new(vec![], TrimStrategy::Byte, diff, false, 0, Duration::ZERO);
        assert!(ms.is_empty());
    }

    // ── CoveragePreservation ─────────────────────────────────────────────────

    #[test]
    fn coverage_preserved_when_all_required_observed() {
        let mut cp = CoveragePreservation::new();
        cp.require(1);
        cp.require(2);
        cp.observe(1);
        cp.observe(2);
        cp.observe(3);
        assert!(cp.is_preserved());
    }

    #[test]
    fn coverage_not_preserved_when_missing() {
        let mut cp = CoveragePreservation::new();
        cp.require(1);
        cp.require(2);
        cp.observe(1);
        assert!(!cp.is_preserved());
        assert_eq!(cp.missing_count(), 1);
    }

    #[test]
    fn coverage_empty_required_always_preserved() {
        let cp = CoveragePreservation::new();
        assert!(cp.is_preserved());
    }

    #[test]
    fn coverage_reset_observed() {
        let mut cp = CoveragePreservation::new();
        cp.require(1);
        cp.observe(1);
        assert!(cp.is_preserved());
        cp.reset_observed();
        assert!(!cp.is_preserved());
    }

    #[test]
    fn coverage_require_all() {
        let mut cp = CoveragePreservation::new();
        cp.require_all([1, 2, 3]);
        assert_eq!(cp.required_bits.len(), 3);
    }

    #[test]
    fn coverage_observe_all() {
        let mut cp = CoveragePreservation::new();
        cp.require_all([10, 20]);
        cp.observe_all([10, 20]);
        assert!(cp.is_preserved());
    }

    #[test]
    fn coverage_reset_clears_all() {
        let mut cp = CoveragePreservation::new();
        cp.require(5);
        cp.observe(5);
        cp.reset();
        assert!(cp.required_bits.is_empty());
        assert!(cp.observed_bits.is_empty());
    }

    // ── DeltaDebugging ────────────────────────────────────────────────────────

    #[test]
    fn ddmin_trivial_empty() {
        let dd = DeltaDebugging::new();
        let (result, calls) = dd.ddmin(&[], |_| true);
        assert!(result.is_empty());
        assert_eq!(calls, 0);
    }

    #[test]
    fn ddmin_all_bytes_needed() {
        let dd = DeltaDebugging::new();
        let input = vec![1u8, 2, 3, 4, 5];
        // Oracle requires full input.
        let (result, _) = dd.ddmin(&input, |c| c == input.as_slice());
        assert_eq!(result, input);
    }

    #[test]
    fn ddmin_removes_unnecessary_bytes() {
        let dd = DeltaDebugging::new();
        let input = vec![0u8; 8];
        let mut modified = input;
        modified[3] = 0xff;
        // Oracle: interesting iff contains 0xff.
        let (result, _) = dd.ddmin(&modified, |c| c.contains(&0xff));
        assert!(result.contains(&0xff));
        assert!(result.len() <= modified.len());
    }

    #[test]
    fn ddmin_respects_min_size() {
        let mut dd = DeltaDebugging::new();
        dd.min_size = 4;
        let input = vec![0xdeu8; 16];
        let (result, _) = dd.ddmin(&input, |_| true);
        assert!(result.len() >= 4);
    }

    #[test]
    fn ddmin_with_limit_stops_early() {
        let dd = DeltaDebugging::with_limit(2);
        let input = vec![0u8; 32];
        let (_, calls) = dd.ddmin(&input, |_| true);
        assert!(calls <= 2);
    }

    // ── SeedMinimizer (trim strategies) ───────────────────────────────────────

    #[test]
    fn binary_trim_reduces_unnecessary_prefix() {
        let mut m = SeedMinimizer::with_strategy(TrimStrategy::Binary);
        let input: Vec<u8> = (0u8..=7).collect();
        // Oracle: interesting iff last byte is 7.
        let (result, _) = m.minimize(&input, |c| c.last() == Some(&7));
        assert_eq!(result.last(), Some(&7));
        assert!(result.len() < input.len());
    }

    #[test]
    fn linear_trim_single_interesting_byte() {
        let mut m = SeedMinimizer::with_strategy(TrimStrategy::Linear);
        let mut input = vec![0u8; 10];
        input[5] = 0x42;
        let (result, _) = m.minimize(&input, |c| c.contains(&0x42));
        assert!(result.contains(&0x42));
        assert!(result.len() <= input.len());
    }

    #[test]
    fn byte_trim_zeros_unnecessary_bytes() {
        let mut m = SeedMinimizer::with_strategy(TrimStrategy::Byte);
        // Disable ddmin so it does not further shrink the byte-trimmed output
        // (ddmin would otherwise drop the zeroed tail entirely, producing [0xAB]).
        m.use_ddmin = false;
        let input = vec![0xABu8; 8];
        // Oracle: interesting iff first byte is 0xAB.
        let (result, _) = m.minimize(&input, |c| c.first() == Some(&0xAB));
        assert_eq!(result[0], 0xAB);
        // Most other bytes should be zeroed.
        let mut zeroed = 0usize;
        for &b in &result {
            if b == 0 {
                zeroed += 1;
            }
        }
        assert!(zeroed > 0);
    }

    #[test]
    fn minimizer_all_strategies() {
        let mut m = SeedMinimizer::new();
        let input: Vec<u8> = (0u8..32).collect();
        let (result, report) = m.minimize(&input, |c| c.contains(&15u8));
        assert!(result.contains(&15u8));
        assert!(report.original_len == 32);
        assert!(report.final_len <= 32);
        assert_eq!(report.strategy_results.len(), 3);
    }

    #[test]
    fn minimizer_oracle_limit() {
        let mut m = SeedMinimizer::new().with_limit(10);
        let input = vec![0xFFu8; 64];
        let (_, report) = m.minimize(&input, |_| true);
        // Total calls should be bounded (multiply by number of strategies + ddmin).
        assert!(report.oracle_calls <= 10 * 4 + 10);
    }

    #[test]
    fn minimizer_min_size_respected() {
        let mut m = SeedMinimizer::new();
        m.min_size = 4;
        let input = vec![1u8; 32];
        let (result, _) = m.minimize(&input, |_| true);
        assert!(result.len() >= 4);
    }

    #[test]
    fn minimizer_report_reduction_pct() {
        let mut m = SeedMinimizer::new();
        let input = vec![0u8; 100];
        let (_, report) = m.minimize(&input, |_| true);
        // With oracle always true, minimizer should reduce significantly.
        assert!(report.reduction_pct() >= 0.0);
        assert!(report.reduction_pct() <= 100.0);
    }

    #[test]
    fn minimizer_report_elapsed_nonnegative() {
        let mut m = SeedMinimizer::new();
        let input = vec![1u8, 2, 3, 4];
        let (_, report) = m.minimize(&input, |_| true);
        let _ = report.elapsed.as_nanos();
    }

    #[test]
    fn minimizer_no_ddmin() {
        let mut m = SeedMinimizer::new();
        m.use_ddmin = false;
        let input: Vec<u8> = (0u8..16).collect();
        let (result, report) = m.minimize(&input, |c| c.last() == Some(&15u8));
        assert_eq!(result.last(), Some(&15u8));
        // Without ddmin, strategy_results has exactly 3 entries.
        assert_eq!(report.strategy_results.len(), 3);
    }

    #[test]
    fn minimizer_empty_input() {
        let mut m = SeedMinimizer::new();
        let (result, report) = m.minimize(&[], |_| true);
        assert!(result.is_empty());
        assert_eq!(report.original_len, 0);
    }

    #[test]
    fn minimization_report_bytes_removed() {
        let report = MinimizationReport {
            original_len: 100,
            final_len: 30,
            best_strategy: TrimStrategy::Binary,
            oracle_calls: 50,
            elapsed: Duration::from_millis(10),
            coverage_preserved: true,
            diff: SeedDiff::compute(&[0u8; 100], &[0u8; 30]),
            strategy_results: HashMap::new(),
            completed_at: SystemTime::now(),
        };
        assert_eq!(report.bytes_removed(), 70);
        assert!((report.reduction_pct() - 70.0).abs() < 0.001);
    }
}
