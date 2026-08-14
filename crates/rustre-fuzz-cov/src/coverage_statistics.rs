//! Comprehensive coverage statistics for the `RustRE` fuzzing suite.
//!
//! Provides branch coverage, path coverage, function coverage, growth curves,
//! plateau detection, heatmaps, and JSON/CSV export.

use std::fmt::Write as _;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ── BranchCoverage ────────────────────────────────────────────────────────────

/// Taken / not-taken hit counts for a single conditional branch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BranchEntry {
    /// Number of times the branch was taken.
    pub taken: u64,
    /// Number of times the branch was not taken.
    pub not_taken: u64,
}

impl BranchEntry {
    /// Create an entry from taken / not-taken counts.
    #[must_use]
    pub const fn new(taken: u64, not_taken: u64) -> Self {
        Self { taken, not_taken }
    }

    /// Total number of times this branch was reached.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.taken.saturating_add(self.not_taken)
    }

    /// Ratio of taken executions to total (NaN if never reached).
    #[must_use]
    pub fn taken_ratio(&self) -> f64 {
        let t = self.total();
        if t == 0 {
            0.0
        } else {
            crate::casts::u64_to_f64(self.taken) / crate::casts::u64_to_f64(t)
        }
    }

    /// Return `true` if both edges (taken and not-taken) were observed.
    #[must_use]
    pub const fn is_fully_covered(&self) -> bool {
        self.taken > 0 && self.not_taken > 0
    }
}

/// Coverage statistics broken down per branch (conditional edge).
///
/// Keyed by `(source_address, destination_address)`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BranchCoverage {
    /// Map of `(from, to)` edge → entry.
    pub entries: BTreeMap<(u64, u64), BranchEntry>,
}

impl BranchCoverage {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that branch `(from, to)` was taken.
    pub fn record_taken(&mut self, from: u64, to: u64) {
        self.entries.entry((from, to)).or_default().taken += 1;
    }

    /// Record that branch `(from, to)` was not taken.
    pub fn record_not_taken(&mut self, from: u64, to: u64) {
        self.entries.entry((from, to)).or_default().not_taken += 1;
    }

    /// Number of branches where both edges have been observed.
    #[must_use]
    pub fn fully_covered_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| e.is_fully_covered())
            .count()
    }

    /// Branch coverage percentage (fully covered / total).
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        let total = self.entries.len();
        if total == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f64(self.fully_covered_count()) / crate::casts::usize_to_f64(total) * 100.0
    }

    /// Total number of tracked branches.
    #[must_use]
    pub fn total_branches(&self) -> usize {
        self.entries.len()
    }

    /// Merge another [`BranchCoverage`] into this one.
    pub fn merge(&mut self, other: &Self) {
        for (&edge, e) in &other.entries {
            let mine = self.entries.entry(edge).or_default();
            mine.taken = mine.taken.saturating_add(e.taken);
            mine.not_taken = mine.not_taken.saturating_add(e.not_taken);
        }
    }

    /// List all fully uncovered branches.
    #[must_use]
    pub fn uncovered_branches(&self) -> Vec<(u64, u64)> {
        self.entries
            .iter()
            .filter(|(_, e)| !e.is_fully_covered())
            .map(|(&edge, _)| edge)
            .collect()
    }
}

// ── PathCoverage ──────────────────────────────────────────────────────────────

/// A path signature — a compact hash of a unique execution path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathSignature(pub u64);

impl PathSignature {
    /// Compute a path signature from a sequence of basic-block addresses.
    ///
    /// Uses a FNV-1a style hash over the address sequence.
    #[must_use]
    pub fn from_trace(trace: &[u64]) -> Self {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &addr in trace {
            for byte in addr.to_le_bytes() {
                h ^= u64::from(byte);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        Self(h)
    }
}

impl fmt::Display for PathSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "path:{:016x}", self.0)
    }
}

/// Records the set of unique execution paths observed during fuzzing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathCoverage {
    /// Set of unique path signatures seen.
    pub unique_paths: HashSet<PathSignature>,
    /// Number of total executions (including duplicate paths).
    pub total_executions: u64,
    /// Most-recently added path.
    pub last_path: Option<PathSignature>,
}

impl PathCoverage {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an execution trace.
    ///
    /// Returns `true` if this was a new (unseen) path.
    pub fn record(&mut self, trace: &[u64]) -> bool {
        self.total_executions += 1;
        let sig = PathSignature::from_trace(trace);
        self.last_path = Some(sig);
        self.unique_paths.insert(sig)
    }

    /// Record a pre-computed path signature.
    ///
    /// Returns `true` if this was a new path.
    pub fn record_signature(&mut self, sig: PathSignature) -> bool {
        self.total_executions += 1;
        self.last_path = Some(sig);
        self.unique_paths.insert(sig)
    }

    /// Number of unique paths seen.
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.unique_paths.len()
    }

    /// Ratio of unique paths to total executions.
    #[must_use]
    pub fn novelty_ratio(&self) -> f64 {
        if self.total_executions == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f64(self.unique_count()) / crate::casts::u64_to_f64(self.total_executions)
    }

    /// Merge another [`PathCoverage`] into this one.
    pub fn merge(&mut self, other: &Self) {
        self.unique_paths.extend(other.unique_paths.iter().copied());
        self.total_executions = self.total_executions.saturating_add(other.total_executions);
    }
}

// ── FunctionCoverage ──────────────────────────────────────────────────────────

/// Per-function hit counts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionCoverage {
    /// Map of function address → hit count.
    pub hits: HashMap<u64, u64>,
    /// Optional function name resolution.
    pub names: HashMap<u64, String>,
}

impl FunctionCoverage {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one call to the function at `addr`.
    pub fn record_call(&mut self, addr: u64) {
        *self.hits.entry(addr).or_insert(0) += 1;
    }

    /// Record `n` calls to the function at `addr`.
    pub fn record_calls(&mut self, addr: u64, n: u64) {
        *self.hits.entry(addr).or_insert(0) += n;
    }

    /// Register a function name.
    pub fn set_name(&mut self, addr: u64, name: impl Into<String>) {
        self.names.insert(addr, name.into());
    }

    /// Return the hit count for `addr`.
    #[must_use]
    pub fn hit_count(&self, addr: u64) -> u64 {
        self.hits.get(&addr).copied().unwrap_or(0)
    }

    /// Number of functions called at least once.
    #[must_use]
    pub fn functions_hit(&self) -> usize {
        self.hits.values().filter(|&&c| c > 0).count()
    }

    /// Total number of tracked functions.
    #[must_use]
    pub fn total_functions(&self) -> usize {
        self.hits.len()
    }

    /// Coverage percentage.
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        let total = self.total_functions();
        if total == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f64(self.functions_hit()) / crate::casts::usize_to_f64(total) * 100.0
    }

    /// Hot functions (hit more than `threshold` times).
    #[must_use]
    pub fn hot_functions(&self, threshold: u64) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self
            .hits
            .iter()
            .filter(|&(_, &c)| c >= threshold)
            .map(|(&a, &c)| (a, c))
            .collect();
        // Total order: `hits` is a `HashMap`, whose iteration order Rust
        // randomises per process, and `sort_by` is stable — so ranking on the
        // hit count alone left equally-hot functions in hash order, and a
        // "hot functions" report listed them differently on each run.
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    /// Merge another [`FunctionCoverage`] into this one.
    pub fn merge(&mut self, other: &Self) {
        for (&addr, &count) in &other.hits {
            *self.hits.entry(addr).or_insert(0) += count;
        }
        self.names
            .extend(other.names.iter().map(|(&a, n)| (a, n.clone())));
    }
}

// ── CoverageGrowthCurve ───────────────────────────────────────────────────────

/// Tracks new basic-block edges discovered per fuzzing iteration.
///
/// Used to plot coverage-over-time graphs and detect plateaus.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageGrowthCurve {
    /// Each entry is `(iteration_number, new_edges_in_this_iteration, cumulative_edges)`.
    pub data_points: Vec<(u64, usize, usize)>,
    /// All edges ever seen.
    known_edges: HashSet<u64>,
    /// Current iteration counter.
    iteration: u64,
}

impl CoverageGrowthCurve {
    /// Create an empty curve.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an iteration with the given set of edges.
    ///
    /// Returns the number of new edges introduced by this iteration.
    pub fn record_iteration(&mut self, edges: &[u64]) -> usize {
        self.iteration += 1;
        let before = self.known_edges.len();
        for &e in edges {
            self.known_edges.insert(e);
        }
        let new = self.known_edges.len() - before;
        self.data_points
            .push((self.iteration, new, self.known_edges.len()));
        new
    }

    /// Total edges seen so far.
    #[must_use]
    pub fn total_edges(&self) -> usize {
        self.known_edges.len()
    }

    /// Number of iterations recorded.
    #[must_use]
    pub const fn iteration_count(&self) -> u64 {
        self.iteration
    }

    /// Average new edges per iteration.
    #[must_use]
    pub fn avg_new_edges_per_iter(&self) -> f64 {
        if self.iteration == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f64(self.total_edges()) / crate::casts::u64_to_f64(self.iteration)
    }

    /// Return the last `n` data points.
    #[must_use]
    pub fn recent(&self, n: usize) -> &[(u64, usize, usize)] {
        let len = self.data_points.len();
        if len <= n {
            &self.data_points
        } else {
            &self.data_points[len - n..]
        }
    }

    /// Export the curve as CSV text.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = "iteration,new_edges,cumulative_edges\n".to_owned();
        for &(iter, new, cum) in &self.data_points {
            let _ = writeln!(out, "{iter},{new},{cum}");
        }
        out
    }
}

// ── CoveragePlateauDetector ───────────────────────────────────────────────────

/// Detects when fuzzing coverage has stagnated (plateau condition).
///
/// Uses a sliding window: if new edges per iteration fall below a threshold
/// for `window` consecutive iterations the fuzzer is considered to have
/// plateaued.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoveragePlateauDetector {
    /// Sliding window of recent new-edge counts.
    window: VecDeque<usize>,
    /// Window size.
    pub window_size: usize,
    /// Minimum new edges per iteration to avoid plateau.
    pub threshold: usize,
}

use std::collections::VecDeque;

impl CoveragePlateauDetector {
    /// Create a detector with `window_size` and minimum `threshold` new edges.
    #[must_use]
    pub fn new(window_size: usize, threshold: usize) -> Self {
        Self {
            window: VecDeque::with_capacity(window_size),
            window_size,
            threshold,
        }
    }

    /// Feed a new observation of `new_edges` into the detector.
    ///
    /// Returns `true` if a plateau is now detected.
    pub fn observe(&mut self, new_edges: usize) -> bool {
        if self.window.len() >= self.window_size {
            self.window.pop_front();
        }
        self.window.push_back(new_edges);
        self.is_plateau()
    }

    /// Return `true` if the current window indicates a plateau.
    #[must_use]
    pub fn is_plateau(&self) -> bool {
        if self.window.len() < self.window_size {
            return false;
        }
        self.window.iter().all(|&n| n <= self.threshold)
    }

    /// Average new edges per iteration in the current window.
    #[must_use]
    pub fn window_avg(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        crate::casts::usize_to_f64(self.window.iter().sum::<usize>()) / crate::casts::usize_to_f64(self.window.len())
    }

    /// Reset the detector window.
    pub fn reset(&mut self) {
        self.window.clear();
    }
}

// ── CoverageHeatmap ───────────────────────────────────────────────────────────

/// Maps addresses to hit counts (heatmap for visualisation).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageHeatmap {
    /// Address → hit count.
    pub cells: BTreeMap<u64, u64>,
}

impl CoverageHeatmap {
    /// Create an empty heatmap.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a hit at `addr`.
    pub fn record(&mut self, addr: u64) {
        *self.cells.entry(addr).or_insert(0) += 1;
    }

    /// Record `n` hits at `addr`.
    pub fn record_n(&mut self, addr: u64, n: u64) {
        *self.cells.entry(addr).or_insert(0) += n;
    }

    /// Hit count for `addr`.
    #[must_use]
    pub fn hit_count(&self, addr: u64) -> u64 {
        self.cells.get(&addr).copied().unwrap_or(0)
    }

    /// Maximum hit count across all addresses.
    #[must_use]
    pub fn max_hits(&self) -> u64 {
        self.cells.values().copied().max().unwrap_or(0)
    }

    /// Minimum hit count (excluding zero-hit cells).
    #[must_use]
    pub fn min_hits_nonzero(&self) -> u64 {
        self.cells
            .values()
            .copied()
            .filter(|&c| c > 0)
            .min()
            .unwrap_or(0)
    }

    /// Normalise hit count for `addr` to the range `[0.0, 1.0]`.
    #[must_use]
    pub fn normalised(&self, addr: u64) -> f64 {
        let max = self.max_hits();
        if max == 0 {
            return 0.0;
        }
        crate::casts::u64_to_f64(self.hit_count(addr)) / crate::casts::u64_to_f64(max)
    }

    /// Return all addresses with hits ≥ `threshold`.
    #[must_use]
    pub fn hot_addresses(&self, threshold: u64) -> Vec<(u64, u64)> {
        self.cells
            .iter()
            .filter(|&(_, &c)| c >= threshold)
            .map(|(&a, &c)| (a, c))
            .collect()
    }

    /// Merge another heatmap into this one.
    pub fn merge(&mut self, other: &Self) {
        for (&addr, &count) in &other.cells {
            *self.cells.entry(addr).or_insert(0) += count;
        }
    }

    /// Total cells (unique addresses with at least one hit).
    #[must_use]
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// Export the heatmap as CSV text.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = "address,hits\n".to_owned();
        for (&addr, &hits) in &self.cells {
            let _ = writeln!(out, "0x{addr:x},{hits}");
        }
        out
    }

    /// Export the heatmap as a JSON string.
    ///
    /// # Errors
    /// Returns a `serde_json` error on failure (practically infallible).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ── CoverageStatistics ────────────────────────────────────────────────────────

/// Aggregated coverage statistics combining branch, path, function, growth,
/// and heatmap data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageStatistics {
    /// Branch-level coverage.
    pub branches: BranchCoverage,
    /// Unique execution path coverage.
    pub paths: PathCoverage,
    /// Per-function call counts.
    pub functions: FunctionCoverage,
    /// Coverage growth curve (edges over iterations).
    pub growth: CoverageGrowthCurve,
    /// Address-level hit heatmap.
    pub heatmap: CoverageHeatmap,
    /// Human-readable label for this statistics snapshot.
    pub label: String,
    /// Number of fuzzer executions contributing to these stats.
    pub total_executions: u64,
}

impl CoverageStatistics {
    /// Create empty statistics.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            ..Self::default()
        }
    }

    /// Record a single fuzzer execution described by a trace of basic-block
    /// addresses.
    pub fn record_execution(&mut self, trace: &[u64]) {
        self.total_executions += 1;
        // Heatmap
        for &addr in trace {
            self.heatmap.record(addr);
        }
        // Path
        self.paths.record(trace);
        // Growth
        let edges: Vec<u64> = trace
            .windows(2)
            .map(|w| w[0].wrapping_mul(0x9e37_79b9).wrapping_add(w[1]))
            .collect();
        self.growth.record_iteration(&edges);
    }

    /// Merge another [`CoverageStatistics`] snapshot into this one.
    pub fn merge(&mut self, other: &Self) {
        self.branches.merge(&other.branches);
        self.paths.merge(&other.paths);
        self.functions.merge(&other.functions);
        self.heatmap.merge(&other.heatmap);
        self.total_executions = self.total_executions.saturating_add(other.total_executions);
    }

    /// Overall coverage summary as a human-readable string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "CoverageStatistics '{}': execs={}, unique_paths={}, \
             branch_cov={:.1}%, fn_cov={:.1}%, heatmap_cells={}, \
             total_edges={}",
            self.label,
            self.total_executions,
            self.paths.unique_count(),
            self.branches.coverage_pct(),
            self.functions.coverage_pct(),
            self.heatmap.cell_count(),
            self.growth.total_edges(),
        )
    }

    /// Export all statistics to JSON.
    ///
    /// # Errors
    /// Returns a `serde_json` error on failure.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export all statistics as multiple CSV documents in a map.
    #[must_use]
    pub fn to_csv_map(&self) -> HashMap<&'static str, String> {
        let mut m = HashMap::new();
        m.insert("growth", self.growth.to_csv());
        m.insert("heatmap", self.heatmap.to_csv());
        m
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── BranchEntry ───────────────────────────────────────────────────────────

    #[test]
    fn test_branch_entry_total() {
        let e = BranchEntry::new(3, 5);
        assert_eq!(e.total(), 8);
    }

    #[test]
    fn test_branch_entry_taken_ratio() {
        let e = BranchEntry::new(2, 2);
        assert!((e.taken_ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_branch_entry_zero_total() {
        let e = BranchEntry::new(0, 0);
        assert!(e.taken_ratio().abs() < f64::EPSILON);
    }

    #[test]
    fn test_branch_entry_fully_covered() {
        let e = BranchEntry::new(1, 1);
        assert!(e.is_fully_covered());
    }

    #[test]
    fn test_branch_entry_not_fully_covered() {
        let e = BranchEntry::new(5, 0);
        assert!(!e.is_fully_covered());
    }

    // ── BranchCoverage ────────────────────────────────────────────────────────

    #[test]
    fn test_branch_coverage_record_taken() {
        let mut bc = BranchCoverage::new();
        bc.record_taken(0x100, 0x200);
        assert_eq!(bc.entries[&(0x100, 0x200)].taken, 1);
    }

    #[test]
    fn test_branch_coverage_pct_empty() {
        let bc = BranchCoverage::new();
        assert!(bc.coverage_pct().abs() < f64::EPSILON);
    }

    #[test]
    fn test_branch_coverage_fully_covered() {
        let mut bc = BranchCoverage::new();
        bc.record_taken(0x1, 0x2);
        bc.record_not_taken(0x1, 0x2);
        assert_eq!(bc.fully_covered_count(), 1);
    }

    #[test]
    fn test_branch_coverage_merge() {
        let mut a = BranchCoverage::new();
        a.record_taken(0x1, 0x2);
        let mut b = BranchCoverage::new();
        b.record_not_taken(0x1, 0x2);
        a.merge(&b);
        assert!(a.entries[&(0x1, 0x2)].is_fully_covered());
    }

    #[test]
    fn test_branch_coverage_uncovered() {
        let mut bc = BranchCoverage::new();
        bc.record_taken(0xA, 0xB);
        let uncovered = bc.uncovered_branches();
        assert_eq!(uncovered.len(), 1);
    }

    // ── PathSignature ─────────────────────────────────────────────────────────

    #[test]
    fn test_path_signature_deterministic() {
        let a = PathSignature::from_trace(&[0x100, 0x200, 0x300]);
        let b = PathSignature::from_trace(&[0x100, 0x200, 0x300]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_path_signature_different_traces() {
        let a = PathSignature::from_trace(&[0x100, 0x200]);
        let b = PathSignature::from_trace(&[0x200, 0x100]);
        assert_ne!(a, b);
    }

    // ── PathCoverage ──────────────────────────────────────────────────────────

    #[test]
    fn test_path_coverage_record_new() {
        let mut pc = PathCoverage::new();
        let is_new = pc.record(&[0x1, 0x2, 0x3]);
        assert!(is_new);
        assert_eq!(pc.unique_count(), 1);
    }

    #[test]
    fn test_path_coverage_duplicate_not_new() {
        let mut pc = PathCoverage::new();
        pc.record(&[0x1, 0x2]);
        let is_new = pc.record(&[0x1, 0x2]);
        assert!(!is_new);
        assert_eq!(pc.unique_count(), 1);
    }

    #[test]
    fn test_path_coverage_novelty_ratio() {
        let mut pc = PathCoverage::new();
        pc.record(&[0x1]);
        pc.record(&[0x1]); // duplicate
        // 1 unique / 2 total = 0.5
        assert!((pc.novelty_ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_path_coverage_merge() {
        let mut a = PathCoverage::new();
        a.record(&[0x1]);
        let mut b = PathCoverage::new();
        b.record(&[0x2]);
        a.merge(&b);
        assert_eq!(a.unique_count(), 2);
    }

    // ── FunctionCoverage ──────────────────────────────────────────────────────

    #[test]
    fn test_function_coverage_record_call() {
        let mut fc = FunctionCoverage::new();
        fc.record_call(0xDEAD);
        assert_eq!(fc.hit_count(0xDEAD), 1);
    }

    #[test]
    fn test_function_coverage_record_calls_n() {
        let mut fc = FunctionCoverage::new();
        fc.record_calls(0x1000, 5);
        assert_eq!(fc.hit_count(0x1000), 5);
    }

    #[test]
    fn test_function_coverage_pct() {
        let mut fc = FunctionCoverage::new();
        fc.hits.insert(0x1, 3);
        fc.hits.insert(0x2, 0);
        assert!((fc.coverage_pct() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_function_coverage_hot_functions() {
        let mut fc = FunctionCoverage::new();
        fc.record_calls(0x100, 10);
        fc.record_calls(0x200, 2);
        let hot = fc.hot_functions(5);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].0, 0x100);
    }

    #[test]
    fn test_function_coverage_merge() {
        let mut a = FunctionCoverage::new();
        a.record_calls(0x1, 3);
        let mut b = FunctionCoverage::new();
        b.record_calls(0x1, 2);
        a.merge(&b);
        assert_eq!(a.hit_count(0x1), 5);
    }

    // ── CoverageGrowthCurve ───────────────────────────────────────────────────

    #[test]
    fn test_growth_curve_record_iteration() {
        let mut gc = CoverageGrowthCurve::new();
        let new = gc.record_iteration(&[0x1, 0x2, 0x3]);
        assert_eq!(new, 3);
        assert_eq!(gc.total_edges(), 3);
    }

    #[test]
    fn test_growth_curve_duplicate_no_new_edges() {
        let mut gc = CoverageGrowthCurve::new();
        gc.record_iteration(&[0x1, 0x2]);
        let new = gc.record_iteration(&[0x1, 0x2]);
        assert_eq!(new, 0);
    }

    #[test]
    fn test_growth_curve_to_csv() {
        let mut gc = CoverageGrowthCurve::new();
        gc.record_iteration(&[0x1]);
        let csv = gc.to_csv();
        assert!(csv.contains("iteration"));
        assert!(csv.contains('1'));
    }

    #[test]
    fn test_growth_curve_recent() {
        let mut gc = CoverageGrowthCurve::new();
        for i in 0..10u64 {
            gc.record_iteration(&[i]);
        }
        assert_eq!(gc.recent(3).len(), 3);
    }

    // ── CoveragePlateauDetector ───────────────────────────────────────────────

    #[test]
    fn test_plateau_not_detected_initially() {
        let mut pd = CoveragePlateauDetector::new(3, 0);
        pd.observe(5);
        pd.observe(4);
        assert!(!pd.is_plateau());
    }

    #[test]
    fn test_plateau_detected_all_zero() {
        let mut pd = CoveragePlateauDetector::new(3, 0);
        pd.observe(0);
        pd.observe(0);
        let plateau = pd.observe(0);
        assert!(plateau);
    }

    #[test]
    fn test_plateau_not_detected_with_growth() {
        let mut pd = CoveragePlateauDetector::new(3, 0);
        pd.observe(0);
        pd.observe(0);
        let plateau = pd.observe(5); // new edge appears
        assert!(!plateau);
    }

    #[test]
    fn test_plateau_window_avg() {
        let mut pd = CoveragePlateauDetector::new(4, 0);
        pd.observe(4);
        pd.observe(8);
        assert!((pd.window_avg() - 6.0).abs() < 1e-9);
    }

    #[test]
    fn test_plateau_reset() {
        let mut pd = CoveragePlateauDetector::new(2, 0);
        pd.observe(0);
        pd.observe(0);
        assert!(pd.is_plateau());
        pd.reset();
        assert!(!pd.is_plateau());
    }

    // ── CoverageHeatmap ───────────────────────────────────────────────────────

    #[test]
    fn test_heatmap_record() {
        let mut h = CoverageHeatmap::new();
        h.record(0x100);
        h.record(0x100);
        assert_eq!(h.hit_count(0x100), 2);
    }

    #[test]
    fn test_heatmap_max_hits() {
        let mut h = CoverageHeatmap::new();
        h.record_n(0x1, 5);
        h.record_n(0x2, 3);
        assert_eq!(h.max_hits(), 5);
    }

    #[test]
    fn test_heatmap_normalised() {
        let mut h = CoverageHeatmap::new();
        h.record_n(0x1, 4);
        h.record_n(0x2, 2);
        assert!((h.normalised(0x1) - 1.0).abs() < 1e-9);
        assert!((h.normalised(0x2) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_heatmap_hot_addresses() {
        let mut h = CoverageHeatmap::new();
        h.record_n(0x10, 10);
        h.record_n(0x20, 2);
        let hot = h.hot_addresses(5);
        assert_eq!(hot.len(), 1);
    }

    #[test]
    fn test_heatmap_to_csv() {
        let mut h = CoverageHeatmap::new();
        h.record(0x100);
        let csv = h.to_csv();
        assert!(csv.contains("address"));
        assert!(csv.contains("0x100"));
    }

    #[test]
    fn test_heatmap_merge() {
        let mut a = CoverageHeatmap::new();
        a.record_n(0x1, 3);
        let mut b = CoverageHeatmap::new();
        b.record_n(0x1, 2);
        a.merge(&b);
        assert_eq!(a.hit_count(0x1), 5);
    }

    // ── CoverageStatistics ────────────────────────────────────────────────────

    #[test]
    fn test_statistics_record_execution() {
        let mut cs = CoverageStatistics::new("test");
        cs.record_execution(&[0x100, 0x200, 0x300]);
        assert_eq!(cs.total_executions, 1);
        assert!(cs.heatmap.hit_count(0x100) > 0);
    }

    #[test]
    fn test_statistics_paths_unique() {
        let mut cs = CoverageStatistics::new("test");
        cs.record_execution(&[0x1, 0x2]);
        cs.record_execution(&[0x3, 0x4]);
        assert_eq!(cs.paths.unique_count(), 2);
    }

    #[test]
    fn test_statistics_growth_tracks_edges() {
        let mut cs = CoverageStatistics::new("test");
        cs.record_execution(&[0x1, 0x2, 0x3]);
        assert!(cs.growth.total_edges() > 0);
    }

    #[test]
    fn test_statistics_merge() {
        let mut a = CoverageStatistics::new("a");
        a.record_execution(&[0x1, 0x2]);
        let mut b = CoverageStatistics::new("b");
        b.record_execution(&[0x3, 0x4]);
        a.merge(&b);
        assert_eq!(a.total_executions, 2);
    }

    #[test]
    fn test_statistics_summary_string() {
        let mut cs = CoverageStatistics::new("my_run");
        cs.record_execution(&[0x1, 0x2]);
        let s = cs.summary();
        assert!(s.contains("my_run"), "{s}");
    }

    #[test]
    fn test_statistics_to_csv_map() {
        let mut cs = CoverageStatistics::new("t");
        cs.record_execution(&[0x1]);
        let m = cs.to_csv_map();
        assert!(m.contains_key("growth"));
        assert!(m.contains_key("heatmap"));
    }
}
