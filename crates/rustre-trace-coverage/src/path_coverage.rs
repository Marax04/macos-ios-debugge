//! `path_coverage` — Execution-path reconstruction and path-sensitive coverage.
//!
//! Key types:
//! - [`ExecutionPath`] — an ordered sequence of basic-block addresses forming one path
//! - [`PathSet`] — a de-duplicated collection of execution paths
//! - [`PathCoverageTracker`] — builds path sets from edge hits recorded during a run
//! - [`PathProfile`] — frequency profile: how many times each distinct path was taken

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::CoverageRun;

// ─── ExecutionPath ────────────────────────────────────────────────────────────

/// An ordered sequence of basic-block addresses representing one program path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecutionPath {
    /// Sequence of basic-block start addresses.
    pub blocks: Vec<u64>,
}

impl ExecutionPath {
    /// Create an empty path.
    #[must_use]
    pub const fn new() -> Self {
        Self { blocks: Vec::new() }
    }

    /// Create a path from an existing block sequence.
    #[must_use]
    pub const fn from_blocks(blocks: Vec<u64>) -> Self {
        Self { blocks }
    }

    /// Append a block to this path.
    pub fn push(&mut self, addr: u64) {
        self.blocks.push(addr);
    }

    /// Length of this path (number of blocks).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether this path is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Entry address (first block).
    #[must_use]
    pub fn entry(&self) -> Option<u64> {
        self.blocks.first().copied()
    }

    /// Exit address (last block).
    #[must_use]
    pub fn exit(&self) -> Option<u64> {
        self.blocks.last().copied()
    }

    /// Whether this path contains the given address.
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        self.blocks.contains(&addr)
    }

    /// Number of times the path passes through `addr`.
    #[must_use]
    pub fn pass_count(&self, addr: u64) -> usize {
        self.blocks.iter().filter(|&&a| a == addr).count()
    }

    /// Whether this path has a loop (any address appears more than once).
    #[must_use]
    pub fn has_loop(&self) -> bool {
        let mut seen = std::collections::HashSet::new();
        self.blocks.iter().any(|a| !seen.insert(a))
    }

    /// Longest common prefix with another path.
    #[must_use]
    pub fn common_prefix_len(&self, other: &Self) -> usize {
        self.blocks
            .iter()
            .zip(other.blocks.iter())
            .take_while(|(a, b)| a == b)
            .count()
    }

    /// A compact hex representation of the path.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.blocks
            .iter()
            .map(|a| format!("{a:x}"))
            .collect::<Vec<_>>()
            .join("->")
    }

    /// Whether this path is a prefix of `other`.
    #[must_use]
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        if self.blocks.len() > other.blocks.len() {
            return false;
        }
        self.blocks == other.blocks[..self.blocks.len()]
    }
}

impl Default for ExecutionPath {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ExecutionPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Path[{}]", self.fingerprint())
    }
}

// ─── PathSet ──────────────────────────────────────────────────────────────────

/// A de-duplicated collection of execution paths.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathSet {
    paths: Vec<ExecutionPath>,
}

impl PathSet {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a path if it is not already present.
    ///
    /// Returns `true` if the path was newly inserted.
    pub fn insert(&mut self, path: ExecutionPath) -> bool {
        if self.paths.contains(&path) {
            return false;
        }
        self.paths.push(path);
        true
    }

    /// Number of distinct paths.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.paths.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Iterate over all paths.
    pub fn iter(&self) -> impl Iterator<Item = &ExecutionPath> {
        self.paths.iter()
    }

    /// All paths that pass through a given address.
    #[must_use]
    pub fn paths_through(&self, addr: u64) -> Vec<&ExecutionPath> {
        self.paths.iter().filter(|p| p.contains(addr)).collect()
    }

    /// All paths that start at `entry`.
    #[must_use]
    pub fn paths_from(&self, entry: u64) -> Vec<&ExecutionPath> {
        self.paths
            .iter()
            .filter(|p| p.entry() == Some(entry))
            .collect()
    }

    /// All paths that end at `exit`.
    #[must_use]
    pub fn paths_to(&self, exit: u64) -> Vec<&ExecutionPath> {
        self.paths
            .iter()
            .filter(|p| p.exit() == Some(exit))
            .collect()
    }

    /// Compute the union of two path sets.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for path in other.iter() {
            result.insert(path.clone());
        }
        result
    }

    /// Paths present in `self` but not in `other`.
    #[must_use]
    pub fn difference(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for path in &self.paths {
            if !other.paths.contains(path) {
                result.paths.push(path.clone());
            }
        }
        result
    }

    /// Longest path in the set.
    #[must_use]
    pub fn longest_path(&self) -> Option<&ExecutionPath> {
        self.paths.iter().max_by_key(|p| p.len())
    }

    /// Shortest path in the set.
    #[must_use]
    pub fn shortest_path(&self) -> Option<&ExecutionPath> {
        self.paths.iter().min_by_key(|p| p.len())
    }

    /// Average path length.
    #[must_use]
    pub fn average_length(&self) -> f64 {
        if self.paths.is_empty() {
            return 0.0;
        }
        crate::usize_to_f64(self.paths.iter().map(ExecutionPath::len).sum::<usize>()) / crate::usize_to_f64(self.paths.len())
    }
}

// ─── PathProfile ─────────────────────────────────────────────────────────────

/// Frequency profile: how many times each distinct path was observed.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathProfile {
    counts: HashMap<ExecutionPath, u64>,
}

impl PathProfile {
    /// Create an empty profile.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observation of `path`.
    pub fn record(&mut self, path: ExecutionPath) {
        *self.counts.entry(path).or_insert(0) += 1;
    }

    /// Record N observations of `path`.
    pub fn record_n(&mut self, path: ExecutionPath, n: u64) {
        *self.counts.entry(path).or_insert(0) += n;
    }

    /// Count for a specific path.
    #[must_use]
    pub fn count_for(&self, path: &ExecutionPath) -> u64 {
        self.counts.get(path).copied().unwrap_or(0)
    }

    /// Number of distinct paths recorded.
    #[must_use]
    pub fn distinct_count(&self) -> usize {
        self.counts.len()
    }

    /// Total path observations.
    #[must_use]
    pub fn total_observations(&self) -> u64 {
        self.counts.values().sum()
    }

    /// The most frequently observed path.
    #[must_use]
    pub fn hottest_path(&self) -> Option<(&ExecutionPath, u64)> {
        self.counts
            .iter()
            .max_by_key(|&(_, &c)| c)
            .map(|(p, &c)| (p, c))
    }

    /// Paths sorted by observation count (descending).
    #[must_use]
    pub fn ranked_paths(&self) -> Vec<(&ExecutionPath, u64)> {
        let mut pairs: Vec<(&ExecutionPath, u64)> =
            self.counts.iter().map(|(p, &c)| (p, c)).collect();
        pairs.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        pairs
    }

    /// Top-N most frequent paths.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(&ExecutionPath, u64)> {
        let mut ranked = self.ranked_paths();
        ranked.truncate(n);
        ranked
    }

    /// Frequency of a path as a fraction of total observations.
    #[must_use]
    pub fn frequency_of(&self, path: &ExecutionPath) -> f64 {
        let total = self.total_observations();
        if total == 0 {
            return 0.0;
        }
        crate::u64_to_f64(self.count_for(path)) / crate::u64_to_f64(total)
    }

    /// All distinct paths.
    #[must_use]
    pub fn all_paths(&self) -> Vec<&ExecutionPath> {
        self.counts.keys().collect()
    }
}

// ─── PathCoverageTracker ──────────────────────────────────────────────────────

/// Reconstructs execution paths from edge hits in a `CoverageRun`.
///
/// The reconstruction builds paths by following chains of edges. It uses a
/// DFS-like approach over the edge graph rooted at addresses that have no
/// in-edge (i.e., entry points).
pub struct PathCoverageTracker {
    /// Maximum path depth to avoid infinite loops.
    pub max_depth: usize,
    /// Maximum number of paths to reconstruct.
    pub max_paths: usize,
}

impl PathCoverageTracker {
    /// Create a tracker with default limits (depth=50, `paths=10_000`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_depth: 50,
            max_paths: 10_000,
        }
    }

    /// Create a tracker with custom limits.
    #[must_use]
    pub const fn with_limits(max_depth: usize, max_paths: usize) -> Self {
        Self {
            max_depth,
            max_paths,
        }
    }

    /// Reconstruct execution paths from the edge graph of a `CoverageRun`.
    ///
    /// Returns a `PathSet` containing all paths reconstructed within the
    /// configured limits.
    ///
    /// # Panics
    /// Panics if the internal path stack is empty when popped (should not happen given the loop guard).
    #[must_use]
    pub fn reconstruct_paths(&self, run: &CoverageRun) -> PathSet {
        // Build adjacency list: addr -> [successors]
        let mut succ: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut has_pred: std::collections::HashSet<u64> = std::collections::HashSet::new();

        for &(from, to) in run.edge_hits.keys() {
            succ.entry(from).or_default().push(to);
            has_pred.insert(to);
        }

        // Entry points: BBs covered that have no predecessor in the edge graph
        let mut entry_points: Vec<u64> = run
            .bb_hits
            .keys()
            .copied()
            .filter(|addr| !has_pred.contains(addr))
            .collect();
        entry_points.sort_unstable();

        let mut paths = PathSet::new();
        let mut path_stack: Vec<(u64, Vec<u64>)> =
            entry_points.iter().map(|&e| (e, vec![e])).collect();

        while !path_stack.is_empty() && paths.len() < self.max_paths {
            let (current, current_path) = path_stack.pop().unwrap();

            let successors = succ.get(&current).cloned().unwrap_or_default();
            if successors.is_empty() || current_path.len() >= self.max_depth {
                // Terminal node — emit the path
                paths.insert(ExecutionPath::from_blocks(current_path));
                continue;
            }

            for &next in &successors {
                // Cycle detection: don't re-visit an address in the current path
                if current_path.contains(&next) {
                    // Loop: emit the path up to the back-edge
                    paths.insert(ExecutionPath::from_blocks(current_path.clone()));
                } else {
                    let mut new_path = current_path.clone();
                    new_path.push(next);
                    path_stack.push((next, new_path));
                }
            }
        }

        paths
    }

    /// Build a path profile from a run: reconstruct paths and count observations
    /// by using edge hit counts as a proxy for execution frequency.
    #[must_use]
    pub fn build_profile(&self, run: &CoverageRun) -> PathProfile {
        let path_set = self.reconstruct_paths(run);
        let mut profile = PathProfile::new();

        for path in path_set.iter() {
            // Use the minimum edge count along the path as the path frequency.
            let freq = self.path_frequency(run, path);
            profile.record_n(path.clone(), freq);
        }

        profile
    }

    /// Estimate how many times a path was executed by taking the minimum
    /// edge hit count along consecutive blocks.
    #[must_use]
    pub fn path_frequency(&self, run: &CoverageRun, path: &ExecutionPath) -> u64 {
        if path.blocks.len() < 2 {
            return path
                .entry()
                .and_then(|a| run.bb_hits.get(&a))
                .copied()
                .unwrap_or(0);
        }
        path.blocks
            .windows(2)
            .map(|w| {
                run.edge_hits
                    .get(&(w[0], w[1]))
                    .copied()
                    .unwrap_or(0)
            })
            .min()
            .unwrap_or(0)
    }
}

impl Default for PathCoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PathCoverageStats ────────────────────────────────────────────────────────

/// Statistics derived from a `PathSet`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCoverageStats {
    /// Total distinct paths.
    pub distinct_paths: usize,
    /// Average path length.
    pub avg_length: f64,
    /// Length of the longest path.
    pub max_length: usize,
    /// Length of the shortest path.
    pub min_length: usize,
    /// Fraction of paths that contain a loop.
    pub loop_fraction: f64,
    /// Number of unique entry addresses across all paths.
    pub unique_entries: usize,
    /// Number of unique exit addresses across all paths.
    pub unique_exits: usize,
}

impl PathCoverageStats {
    /// Compute statistics from a `PathSet`.
    #[must_use]
    pub fn from_path_set(ps: &PathSet) -> Self {
        if ps.is_empty() {
            return Self {
                distinct_paths: 0,
                avg_length: 0.0,
                max_length: 0,
                min_length: 0,
                loop_fraction: 0.0,
                unique_entries: 0,
                unique_exits: 0,
            };
        }
        let distinct = ps.len();
        let avg = ps.average_length();
        let max_len = ps.longest_path().map_or(0, ExecutionPath::len);
        let min_len = ps.shortest_path().map_or(0, ExecutionPath::len);
        let loops = ps.iter().filter(|p| p.has_loop()).count();
        let loop_frac = crate::usize_to_f64(loops) / crate::usize_to_f64(distinct);

        let entries: std::collections::HashSet<u64> =
            ps.iter().filter_map(ExecutionPath::entry).collect();
        let exits: std::collections::HashSet<u64> =
            ps.iter().filter_map(ExecutionPath::exit).collect();

        Self {
            distinct_paths: distinct,
            avg_length: avg,
            max_length: max_len,
            min_length: min_len,
            loop_fraction: loop_frac,
            unique_entries: entries.len(),
            unique_exits: exits.len(),
        }
    }

    /// Render a human-readable summary.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "PathCoverageStats:\n  distinct_paths  = {}\n  avg_length      = {:.2}\n  max_length      = {}\n  min_length      = {}\n  loop_fraction   = {:.1}%%\n  unique_entries  = {}\n  unique_exits    = {}\n",
            self.distinct_paths,
            self.avg_length,
            self.max_length,
            self.min_length,
            self.loop_fraction * 100.0,
            self.unique_entries,
            self.unique_exits,
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoverageRun;

    fn make_run_with_edges(name: &str, edges: &[(u64, u64)]) -> CoverageRun {
        let mut run = CoverageRun::new(name);
        for &(f, t) in edges {
            run.record_bb(f);
            run.record_bb(t);
            run.record_edge(f, t);
        }
        run
    }

    #[test]
    fn test_execution_path_basic() {
        let mut p = ExecutionPath::new();
        p.push(0x1000);
        p.push(0x1010);
        p.push(0x1020);
        assert_eq!(p.len(), 3);
        assert_eq!(p.entry(), Some(0x1000));
        assert_eq!(p.exit(), Some(0x1020));
        assert!(p.contains(0x1010));
        assert!(!p.contains(0x9999));
    }

    #[test]
    fn test_execution_path_fingerprint() {
        let p = ExecutionPath::from_blocks(vec![0x1000, 0x1010]);
        let fp = p.fingerprint();
        assert!(fp.contains("1000"));
        assert!(fp.contains("1010"));
    }

    #[test]
    fn test_execution_path_has_loop() {
        let p_no_loop = ExecutionPath::from_blocks(vec![0x1000, 0x1010]);
        let p_loop = ExecutionPath::from_blocks(vec![0x1000, 0x1010, 0x1000]);
        assert!(!p_no_loop.has_loop());
        assert!(p_loop.has_loop());
    }

    #[test]
    fn test_execution_path_is_prefix_of() {
        let prefix = ExecutionPath::from_blocks(vec![0x1000, 0x1010]);
        let full = ExecutionPath::from_blocks(vec![0x1000, 0x1010, 0x1020]);
        assert!(prefix.is_prefix_of(&full));
        assert!(!full.is_prefix_of(&prefix));
    }

    #[test]
    fn test_path_set_insert_dedup() {
        let mut ps = PathSet::new();
        let p1 = ExecutionPath::from_blocks(vec![0x1000, 0x1010]);
        let p2 = p1.clone();
        assert!(ps.insert(p1));
        assert!(!ps.insert(p2)); // duplicate
        assert_eq!(ps.len(), 1);
    }

    #[test]
    fn test_path_set_paths_through() {
        let mut ps = PathSet::new();
        ps.insert(ExecutionPath::from_blocks(vec![0x1000, 0x1010, 0x1020]));
        ps.insert(ExecutionPath::from_blocks(vec![0x1000, 0x1030]));
        let through = ps.paths_through(0x1010);
        assert_eq!(through.len(), 1);
    }

    #[test]
    fn test_path_set_union() {
        let mut a = PathSet::new();
        let mut b = PathSet::new();
        a.insert(ExecutionPath::from_blocks(vec![0x1000]));
        b.insert(ExecutionPath::from_blocks(vec![0x1010]));
        let u = a.union(&b);
        assert_eq!(u.len(), 2);
    }

    #[test]
    fn test_path_profile_record() {
        let mut profile = PathProfile::new();
        let p = ExecutionPath::from_blocks(vec![0x1000, 0x1010]);
        profile.record(p.clone());
        profile.record(p.clone());
        assert_eq!(profile.count_for(&p), 2);
        assert_eq!(profile.total_observations(), 2);
    }

    #[test]
    fn test_path_profile_top_n() {
        let mut profile = PathProfile::new();
        let p1 = ExecutionPath::from_blocks(vec![0x1000]);
        let p2 = ExecutionPath::from_blocks(vec![0x2000]);
        profile.record_n(p1, 10);
        profile.record_n(p2, 3);
        let top = profile.top_n(1);
        assert_eq!(top[0].1, 10);
    }

    #[test]
    fn test_path_coverage_tracker_reconstruct() {
        let run = make_run_with_edges("r", &[
            (0x1000, 0x1010),
            (0x1010, 0x1020),
        ]);
        let tracker = PathCoverageTracker::new();
        let paths = tracker.reconstruct_paths(&run);
        assert!(!paths.is_empty());
        // Should find a path 0x1000 -> 0x1010 -> 0x1020
        let has_path = paths.iter().any(|p| {
            p.blocks == vec![0x1000, 0x1010, 0x1020]
        });
        assert!(has_path);
    }

    #[test]
    fn test_path_coverage_tracker_frequency() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 5);
        run.record_bb_n(0x1010, 3);
        run.record_edge_n(0x1000, 0x1010, 3);
        let tracker = PathCoverageTracker::new();
        let p = ExecutionPath::from_blocks(vec![0x1000, 0x1010]);
        let freq = tracker.path_frequency(&run, &p);
        assert_eq!(freq, 3);
    }

    #[test]
    fn test_path_coverage_stats() {
        let mut ps = PathSet::new();
        ps.insert(ExecutionPath::from_blocks(vec![0x1000, 0x1010]));
        ps.insert(ExecutionPath::from_blocks(vec![0x1000, 0x1020]));
        ps.insert(ExecutionPath::from_blocks(vec![0x2000]));
        let stats = PathCoverageStats::from_path_set(&ps);
        assert_eq!(stats.distinct_paths, 3);
        assert_eq!(stats.max_length, 2);
        assert_eq!(stats.min_length, 1);
    }

    #[test]
    fn test_path_coverage_stats_empty() {
        let ps = PathSet::new();
        let stats = PathCoverageStats::from_path_set(&ps);
        assert_eq!(stats.distinct_paths, 0);
        assert!((stats.avg_length - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_common_prefix_len() {
        let p1 = ExecutionPath::from_blocks(vec![0x1000, 0x1010, 0x1020]);
        let p2 = ExecutionPath::from_blocks(vec![0x1000, 0x1010, 0x2000]);
        assert_eq!(p1.common_prefix_len(&p2), 2);
    }
}
