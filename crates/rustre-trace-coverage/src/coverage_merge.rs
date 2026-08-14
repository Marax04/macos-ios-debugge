//! Coverage map merging utilities.
//!
//! Provides [`CoverageMerger`] to combine multiple [`super::CoverageRun`] maps
//! using Union, Intersection, or Difference strategies, and returns a
//! [`MergeResult`] containing per-run delta statistics.

use super::CoverageRun;
use std::collections::{HashMap, HashSet};

// ── MergeStrategy ─────────────────────────────────────────────────────────────

/// How to combine multiple coverage maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeStrategy {
    /// Union: a block is in the output if it appears in *any* input.
    /// Hit counts are summed.
    Union,
    /// Intersection: a block is in the output only if it appears in *all* inputs.
    /// Hit counts are the minimum across inputs.
    Intersection,
    /// Difference (A − B): blocks present in the *first* run but absent from all others.
    Difference,
}

impl std::fmt::Display for MergeStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Union => write!(f, "Union"),
            Self::Intersection => write!(f, "Intersection"),
            Self::Difference => write!(f, "Difference"),
        }
    }
}

// ── MergeResult ───────────────────────────────────────────────────────────────

/// Statistics produced by a merge operation.
#[derive(Debug, Clone)]
pub struct MergeResult {
    /// The merged coverage run.
    pub run: CoverageRun,
    /// Blocks that appear in the output but were absent from the *first* input.
    pub new_blocks: HashSet<u64>,
    /// Blocks that were present in the *first* input but absent from the output.
    pub lost_blocks: HashSet<u64>,
    /// Strategy used.
    pub strategy: MergeStrategy,
    /// Number of input runs merged.
    pub input_count: usize,
}

impl MergeResult {
    /// How many blocks were gained relative to the first input.
    #[must_use]
    pub fn gained_count(&self) -> usize {
        self.new_blocks.len()
    }

    /// How many blocks were lost relative to the first input.
    #[must_use]
    pub fn lost_count(&self) -> usize {
        self.lost_blocks.len()
    }

    /// Net block delta (gained − lost).
    #[must_use]
    pub fn net_delta(&self) -> i64 {
        crate::usize_to_i64_sat(self.gained_count()) - crate::usize_to_i64_sat(self.lost_count())
    }

    /// Coverage ratio of the merged output (unique blocks / sum of all input blocks).
    #[must_use]
    pub fn coverage_ratio(&self) -> f64 {
        let out = self.run.bb_hits.len();
        if out == 0 {
            return 0.0;
        }
        crate::usize_to_f64(out) / crate::usize_to_f64(out.max(1)) // always 1.0 for merged; useful as a hook
    }
}

// ── CoverageMerger ────────────────────────────────────────────────────────────

/// Merges multiple coverage maps according to a chosen [`MergeStrategy`].
pub struct CoverageMerger {
    /// Strategy to use.
    pub strategy: MergeStrategy,
    /// Accumulated input runs.
    inputs: Vec<CoverageRun>,
}

impl CoverageMerger {
    /// Create a new merger with the given strategy.
    #[must_use]
    pub const fn new(strategy: MergeStrategy) -> Self {
        Self {
            strategy,
            inputs: Vec::new(),
        }
    }

    /// Add a coverage run as an input.
    pub fn add_run(&mut self, run: CoverageRun) {
        self.inputs.push(run);
    }

    /// Return the number of input runs added so far.
    #[must_use]
    pub const fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Execute the merge and return a [`MergeResult`].
    ///
    /// Returns an empty result if no inputs have been added.
    #[must_use]
    pub fn merge(&self, output_name: impl Into<String>) -> MergeResult {
        let name = output_name.into();
        if self.inputs.is_empty() {
            return MergeResult {
                run: CoverageRun::new(&name),
                new_blocks: HashSet::new(),
                lost_blocks: HashSet::new(),
                strategy: self.strategy,
                input_count: 0,
            };
        }

        let first_blocks: HashSet<u64> = self.inputs[0].bb_hits.keys().copied().collect();
        let merged_bb = match self.strategy {
            MergeStrategy::Union => self.merge_union(),
            MergeStrategy::Intersection => self.merge_intersection(),
            MergeStrategy::Difference => self.merge_difference(),
        };

        let output_blocks: HashSet<u64> = merged_bb.keys().copied().collect();
        let new_blocks: HashSet<u64> = output_blocks.difference(&first_blocks).copied().collect();
        let lost_blocks: HashSet<u64> = first_blocks.difference(&output_blocks).copied().collect();

        let mut run = CoverageRun::new(&name);
        for (&addr, &count) in &merged_bb {
            run.record_bb_n(addr, count);
        }
        // Also merge edges (union by default)
        for input in &self.inputs {
            for (&(from, to), &count) in &input.edge_hits {
                run.record_edge_n(from, to, count);
            }
        }

        MergeResult {
            run,
            new_blocks,
            lost_blocks,
            strategy: self.strategy,
            input_count: self.inputs.len(),
        }
    }

    /// Union merge: sum hit counts for all blocks across all inputs.
    fn merge_union(&self) -> HashMap<u64, u64> {
        let mut out: HashMap<u64, u64> = HashMap::new();
        for input in &self.inputs {
            for (&addr, &count) in &input.bb_hits {
                *out.entry(addr).or_insert(0) += count;
            }
        }
        out
    }

    /// Intersection merge: only blocks present in all inputs, with min hit count.
    fn merge_intersection(&self) -> HashMap<u64, u64> {
        if self.inputs.is_empty() {
            return HashMap::new();
        }
        // Start with first input's blocks
        let mut candidates: HashMap<u64, u64> = self.inputs[0].bb_hits.clone();
        for input in &self.inputs[1..] {
            candidates.retain(|addr, count| {
                if let Some(&other_count) = input.bb_hits.get(addr) {
                    *count = (*count).min(other_count);
                    true
                } else {
                    false
                }
            });
        }
        candidates
    }

    /// Difference merge: blocks only in the first input.
    fn merge_difference(&self) -> HashMap<u64, u64> {
        if self.inputs.is_empty() {
            return HashMap::new();
        }
        let other_blocks: HashSet<u64> = self.inputs[1..]
            .iter()
            .flat_map(|r| r.bb_hits.keys().copied())
            .collect();
        self.inputs[0]
            .bb_hits
            .iter()
            .filter(|(addr, _)| !other_blocks.contains(*addr))
            .map(|(&addr, &count)| (addr, count))
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_run(name: &str, addrs: &[(u64, u64)]) -> CoverageRun {
        let mut run = CoverageRun::new(name);
        for &(addr, count) in addrs {
            run.record_bb_n(addr, count);
        }
        run
    }

    #[test]
    fn test_union_sums_hit_counts() {
        let mut merger = CoverageMerger::new(MergeStrategy::Union);
        merger.add_run(make_run("a", &[(0x1000, 3), (0x2000, 1)]));
        merger.add_run(make_run("b", &[(0x1000, 2), (0x3000, 4)]));
        let result = merger.merge("merged");
        assert_eq!(result.run.visit_count(0x1000), 5);
        assert_eq!(result.run.visit_count(0x2000), 1);
        assert_eq!(result.run.visit_count(0x3000), 4);
    }

    #[test]
    fn test_union_new_blocks_from_second() {
        let mut merger = CoverageMerger::new(MergeStrategy::Union);
        merger.add_run(make_run("a", &[(0x1000, 1)]));
        merger.add_run(make_run("b", &[(0x2000, 1)]));
        let result = merger.merge("m");
        assert!(result.new_blocks.contains(&0x2000));
        assert!(!result.new_blocks.contains(&0x1000));
    }

    #[test]
    fn test_intersection_only_shared_blocks() {
        let mut merger = CoverageMerger::new(MergeStrategy::Intersection);
        merger.add_run(make_run("a", &[(0x1000, 5), (0x2000, 3)]));
        merger.add_run(make_run("b", &[(0x1000, 2), (0x3000, 1)]));
        let result = merger.merge("inter");
        assert!(result.run.is_covered(0x1000));
        assert!(!result.run.is_covered(0x2000));
        assert!(!result.run.is_covered(0x3000));
        // min hit count
        assert_eq!(result.run.visit_count(0x1000), 2);
    }

    #[test]
    fn test_intersection_lost_blocks() {
        let mut merger = CoverageMerger::new(MergeStrategy::Intersection);
        merger.add_run(make_run("a", &[(0x1000, 1), (0x2000, 1)]));
        merger.add_run(make_run("b", &[(0x1000, 1)]));
        let result = merger.merge("inter");
        assert!(result.lost_blocks.contains(&0x2000));
    }

    #[test]
    fn test_difference_only_first_blocks() {
        let mut merger = CoverageMerger::new(MergeStrategy::Difference);
        merger.add_run(make_run("a", &[(0x1000, 3), (0x2000, 1), (0x3000, 2)]));
        merger.add_run(make_run("b", &[(0x2000, 99)]));
        let result = merger.merge("diff");
        assert!(result.run.is_covered(0x1000));
        assert!(!result.run.is_covered(0x2000));
        assert!(result.run.is_covered(0x3000));
    }

    #[test]
    fn test_empty_merger_returns_empty() {
        let merger = CoverageMerger::new(MergeStrategy::Union);
        let result = merger.merge("empty");
        assert_eq!(result.run.unique_bbs(), 0);
        assert_eq!(result.input_count, 0);
    }

    #[test]
    fn test_net_delta_positive() {
        let mut merger = CoverageMerger::new(MergeStrategy::Union);
        merger.add_run(make_run("a", &[(0x1000, 1)]));
        merger.add_run(make_run("b", &[(0x2000, 1), (0x3000, 1)]));
        let result = merger.merge("m");
        assert!(result.net_delta() > 0);
    }

    #[test]
    fn test_strategy_display() {
        assert_eq!(MergeStrategy::Union.to_string(), "Union");
        assert_eq!(MergeStrategy::Intersection.to_string(), "Intersection");
        assert_eq!(MergeStrategy::Difference.to_string(), "Difference");
    }

    #[test]
    fn test_single_input_union() {
        let mut merger = CoverageMerger::new(MergeStrategy::Union);
        merger.add_run(make_run("only", &[(0xABCD, 7)]));
        let result = merger.merge("out");
        assert_eq!(result.run.visit_count(0xABCD), 7);
        assert_eq!(result.new_blocks.len(), 0); // first input = baseline, no new
    }
}
