//! Basic block hit-count heatmap.
//!
//! Tracks per-block execution frequencies, sorts them by hotness, aggregates
//! at the function level, detects cold/dead blocks, and computes coverage
//! diffs between two runs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

pub use crate::CovError;

// ─── BbHeatmap ────────────────────────────────────────────────────────────────

/// Per-basic-block hit-count heatmap.
///
/// Maps each block start address to an execution count.
#[derive(Debug, Clone, Default)]
pub struct BbHeatmap {
    /// `block_addr → hit_count`.
    counts: HashMap<u64, u64>,
}

impl BbHeatmap {
    /// Create an empty heatmap.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one hit at `addr`.
    pub fn record(&mut self, addr: u64) {
        *self.counts.entry(addr).or_insert(0) += 1;
    }

    /// Record `n` hits at `addr`.
    pub fn record_n(&mut self, addr: u64, n: u64) {
        *self.counts.entry(addr).or_insert(0) += n;
    }

    /// Return the hit count for `addr` (0 if not present).
    #[must_use]
    pub fn count(&self, addr: u64) -> u64 {
        self.counts.get(&addr).copied().unwrap_or(0)
    }

    /// Total number of distinct blocks tracked.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.counts.len()
    }

    /// Total number of hits across all blocks.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Return `true` if any block was hit.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// Merge `other` into `self` by summing hit counts.
    pub fn merge(&mut self, other: &Self) {
        for (&addr, &cnt) in &other.counts {
            *self.counts.entry(addr).or_insert(0) += cnt;
        }
    }

    /// Return all addresses that were hit at least once.
    #[must_use]
    pub fn covered_blocks(&self) -> HashSet<u64> {
        self.counts.keys().copied().collect()
    }

    /// Iterator over `(addr, hit_count)` pairs in address order.
    pub fn iter_sorted_by_addr(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        let mut v: Vec<(u64, u64)> = self.counts.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_unstable_by_key(|&(a, _)| a);
        v.into_iter()
    }

    /// Create a view sorted by descending hit count.
    #[must_use]
    pub fn hotness_view(&self) -> HeatmapView {
        HeatmapView::from_heatmap(self)
    }

    /// Maximum hit count among all blocks (0 if empty).
    #[must_use]
    pub fn max_count(&self) -> u64 {
        self.counts.values().copied().max().unwrap_or(0)
    }

    /// Minimum hit count among hit blocks (0 if empty).
    #[must_use]
    pub fn min_count(&self) -> u64 {
        self.counts.values().copied().min().unwrap_or(0)
    }

    /// Normalised heat in `[0.0, 1.0]` for `addr`.
    #[must_use]
    pub fn normalised_heat(&self, addr: u64) -> f64 {
        let max = self.max_count();
        if max == 0 {
            return 0.0;
        }
        crate::cast_helpers::u64_to_f64(self.count(addr)) / crate::cast_helpers::u64_to_f64(max)
    }

    /// Build from a raw `HashMap<addr, count>`.
    #[must_use]
    pub const fn from_map(map: HashMap<u64, u64>) -> Self {
        Self { counts: map }
    }

    /// Expose internal map (immutable reference).
    #[must_use]
    pub const fn as_map(&self) -> &HashMap<u64, u64> {
        &self.counts
    }
}

// ─── HeatmapView ──────────────────────────────────────────────────────────────

/// A snapshot of a `BbHeatmap` sorted by descending hotness.
#[derive(Debug, Clone)]
pub struct HeatmapView {
    /// Entries sorted `hottest → coldest`.
    pub entries: Vec<HeatmapEntry>,
}

/// A single heatmap entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeatmapEntry {
    /// Block start address.
    pub addr: u64,
    /// Execution hit count.
    pub count: u64,
}

impl HeatmapEntry {
    /// Create a new entry.
    #[must_use]
    pub const fn new(addr: u64, count: u64) -> Self {
        Self { addr, count }
    }
}

impl fmt::Display for HeatmapEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}: {} hits", self.addr, self.count)
    }
}

impl HeatmapView {
    /// Build a view from a heatmap, sorted hottest first.
    #[must_use]
    pub fn from_heatmap(hm: &BbHeatmap) -> Self {
        let mut entries: Vec<HeatmapEntry> = hm
            .counts
            .iter()
            .map(|(&a, &c)| HeatmapEntry::new(a, c))
            .collect();
        entries.sort_unstable_by(|a, b| b.count.cmp(&a.count).then(a.addr.cmp(&b.addr)));
        Self { entries }
    }

    /// Top-N hottest blocks.
    #[must_use]
    pub fn top_n(&self, n: usize) -> &[HeatmapEntry] {
        let end = n.min(self.entries.len());
        &self.entries[..end]
    }

    /// Bottom-N coldest blocks (above zero count).
    #[must_use]
    pub fn bottom_n(&self, n: usize) -> Vec<&HeatmapEntry> {
        let end = n.min(self.entries.len());
        self.entries[self.entries.len().saturating_sub(end)..]
            .iter()
            .collect()
    }

    /// Total number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when view is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Index of the entry for `addr` in the sorted list, if present.
    #[must_use]
    pub fn rank_of(&self, addr: u64) -> Option<usize> {
        self.entries.iter().position(|e| e.addr == addr)
    }
}

// ─── HottestFunctions ─────────────────────────────────────────────────────────

/// Aggregates BB heat scores per function.
///
/// Each function is identified by its entry-point address.  BB addresses are
/// attributed to a function via a simple range-based lookup.
#[derive(Debug, Clone, Default)]
pub struct HottestFunctions {
    /// `function_entry → (total_hits, block_count)`.
    functions: BTreeMap<u64, FunctionHeat>,
}

/// Heat statistics for a single function.
#[derive(Debug, Clone, Default)]
pub struct FunctionHeat {
    /// Entry-point address of the function.
    pub entry: u64,
    /// Total execution hits across all BBs in this function.
    pub total_hits: u64,
    /// Number of BBs covered in this function.
    pub covered_blocks: usize,
    /// Total number of BBs in this function (if known, else 0).
    pub total_blocks: usize,
}

impl FunctionHeat {
    /// Coverage ratio `[0.0, 1.0]`.  Returns 0 if `total_blocks` is 0.
    #[must_use]
    pub fn coverage_ratio(&self) -> f64 {
        if self.total_blocks == 0 {
            return 0.0;
        }
        crate::cast_helpers::usize_to_f64(self.covered_blocks) / crate::cast_helpers::usize_to_f64(self.total_blocks)
    }
}

impl HottestFunctions {
    /// Create an empty aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attribute BB `(addr, hits)` to function `func_entry`.
    pub fn attribute(&mut self, func_entry: u64, bb_addr: u64, hits: u64, total_bb: usize) {
        let _ = bb_addr; // addr is used for covered_blocks tracking
        let e = self.functions.entry(func_entry).or_insert_with(|| FunctionHeat {
            entry: func_entry,
            ..Default::default()
        });
        e.total_hits += hits;
        e.covered_blocks += 1;
        if total_bb > e.total_blocks {
            e.total_blocks = total_bb;
        }
    }

    /// Build from a heatmap and an `addr → func_entry` attribution map.
    #[must_use] 
    pub fn from_heatmap(hm: &BbHeatmap, attr: &HashMap<u64, u64>) -> Self {
        let mut hf = Self::new();
        for (&addr, &cnt) in hm.as_map() {
            if let Some(&func) = attr.get(&addr) {
                hf.attribute(func, addr, cnt, 0);
            }
        }
        hf
    }

    /// Return functions sorted by `total_hits` descending.
    #[must_use]
    pub fn sorted_by_heat(&self) -> Vec<&FunctionHeat> {
        let mut v: Vec<&FunctionHeat> = self.functions.values().collect();
        v.sort_unstable_by_key(|b| std::cmp::Reverse(b.total_hits));
        v
    }

    /// Get the heat record for `entry`, if any.
    #[must_use]
    pub fn get(&self, entry: u64) -> Option<&FunctionHeat> {
        self.functions.get(&entry)
    }

    /// Number of tracked functions.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }
}

// ─── ColdBlockDetector ────────────────────────────────────────────────────────

/// Detects basic blocks that were never executed in a given run.
#[derive(Debug, Clone)]
pub struct ColdBlockDetector {
    /// Complete set of known blocks (from static analysis).
    all_blocks: HashSet<u64>,
}

impl ColdBlockDetector {
    /// Create a detector from a set of all known block addresses.
    #[must_use]
    pub const fn new(all_blocks: HashSet<u64>) -> Self {
        Self { all_blocks }
    }

    /// Return the set of blocks not present in `heatmap`.
    #[must_use]
    pub fn cold_blocks(&self, heatmap: &BbHeatmap) -> HashSet<u64> {
        let covered = heatmap.covered_blocks();
        self.all_blocks.difference(&covered).copied().collect()
    }

    /// Number of cold blocks in `heatmap`.
    #[must_use]
    pub fn cold_count(&self, heatmap: &BbHeatmap) -> usize {
        self.cold_blocks(heatmap).len()
    }

    /// Coverage percentage: `100 * (total - cold) / total`.
    #[must_use]
    pub fn coverage_pct(&self, heatmap: &BbHeatmap) -> f64 {
        let total = self.all_blocks.len();
        if total == 0 {
            return 100.0;
        }
        let cold = self.cold_count(heatmap);
        crate::cast_helpers::usize_to_f64(total - cold) / crate::cast_helpers::usize_to_f64(total) * 100.0
    }

    /// Total number of known blocks.
    #[must_use]
    pub fn total_blocks(&self) -> usize {
        self.all_blocks.len()
    }

    /// Add a block to the known set.
    pub fn add_block(&mut self, addr: u64) {
        self.all_blocks.insert(addr);
    }
}

// ─── CoverageDiff ─────────────────────────────────────────────────────────────

/// Diff between two `BbHeatmap` runs.
///
/// Identifies blocks that appear only in the first run, only in the second,
/// or in both, and tracks count deltas.
#[derive(Debug, Clone)]
pub struct CoverageDiff {
    /// Blocks present only in run A (regressed in B).
    pub only_in_a: HashSet<u64>,
    /// Blocks present only in run B (newly covered in B).
    pub only_in_b: HashSet<u64>,
    /// Blocks in both runs.  `(addr, count_a, count_b)`.
    pub in_both: Vec<(u64, u64, u64)>,
}

impl CoverageDiff {
    /// Compute the diff between heatmaps `a` and `b`.
    #[must_use]
    pub fn compute(a: &BbHeatmap, b: &BbHeatmap) -> Self {
        let set_a: HashSet<u64> = a.covered_blocks();
        let set_b: HashSet<u64> = b.covered_blocks();

        let only_in_a: HashSet<u64> = set_a.difference(&set_b).copied().collect();
        let only_in_b: HashSet<u64> = set_b.difference(&set_a).copied().collect();
        let in_both: Vec<(u64, u64, u64)> = set_a
            .intersection(&set_b)
            .map(|&addr| (addr, a.count(addr), b.count(addr)))
            .collect();

        Self {
            only_in_a,
            only_in_b,
            in_both,
        }
    }

    /// Number of newly covered blocks in B.
    #[must_use]
    pub fn new_blocks_in_b(&self) -> usize {
        self.only_in_b.len()
    }

    /// Number of regressed blocks (in A but not B).
    #[must_use]
    pub fn regressed_blocks(&self) -> usize {
        self.only_in_a.len()
    }

    /// Blocks in B with a higher count than in A (hot spots that grew).
    #[must_use]
    pub fn hotter_in_b(&self) -> Vec<(u64, u64, u64)> {
        self.in_both
            .iter()
            .filter(|&&(_, ca, cb)| cb > ca)
            .copied()
            .collect()
    }

    /// Blocks in B with a lower count than in A (cooled down).
    #[must_use]
    pub fn cooler_in_b(&self) -> Vec<(u64, u64, u64)> {
        self.in_both
            .iter()
            .filter(|&&(_, ca, cb)| cb < ca)
            .copied()
            .collect()
    }

    /// Total count delta across common blocks (`sum(cb - ca)`).
    #[must_use]
    pub fn total_count_delta(&self) -> i64 {
        self.in_both
            .iter()
            .map(|&(_, ca, cb)| crate::cast_helpers::u64_to_i64_sat(cb) - crate::cast_helpers::u64_to_i64_sat(ca))
            .sum()
    }
}

impl fmt::Display for CoverageDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CoverageDiff: +{} new, -{} regressed, {} common",
            self.only_in_b.len(),
            self.only_in_a.len(),
            self.in_both.len()
        )
    }
}

// ─── HeatBand ─────────────────────────────────────────────────────────────────

/// Classify heat into bands for gradient display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeatBand {
    /// Never hit.
    Cold,
    /// Hit 1-9 times.
    Warm,
    /// Hit 10-99 times.
    Hot,
    /// Hit 100+ times.
    Blazing,
}

impl HeatBand {
    /// Classify a raw hit count.
    #[must_use]
    pub const fn classify(count: u64) -> Self {
        match count {
            0 => Self::Cold,
            1..=9 => Self::Warm,
            10..=99 => Self::Hot,
            _ => Self::Blazing,
        }
    }

    /// ASCII-art color hint for terminal display.
    #[must_use]
    pub const fn ansi_color_hint(&self) -> &'static str {
        match self {
            Self::Cold => "\x1b[34m",    // blue
            Self::Warm => "\x1b[32m",    // green
            Self::Hot => "\x1b[33m",     // yellow
            Self::Blazing => "\x1b[31m", // red
        }
    }
}

impl fmt::Display for HeatBand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cold => write!(f, "COLD"),
            Self::Warm => write!(f, "WARM"),
            Self::Hot => write!(f, "HOT"),
            Self::Blazing => write!(f, "BLAZING"),
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_heatmap(pairs: &[(u64, u64)]) -> BbHeatmap {
        let mut hm = BbHeatmap::new();
        for &(addr, n) in pairs {
            hm.record_n(addr, n);
        }
        hm
    }

    // ── BbHeatmap ────────────────────────────────────────────────────────────

    #[test]
    fn record_and_count() {
        let mut hm = BbHeatmap::new();
        hm.record(0x1000);
        hm.record(0x1000);
        assert_eq!(hm.count(0x1000), 2);
    }

    #[test]
    fn record_n() {
        let mut hm = BbHeatmap::new();
        hm.record_n(0x2000, 50);
        assert_eq!(hm.count(0x2000), 50);
    }

    #[test]
    fn count_missing_returns_zero() {
        let hm = BbHeatmap::new();
        assert_eq!(hm.count(0xDEAD), 0);
    }

    #[test]
    fn total_hits() {
        let hm = make_heatmap(&[(0x1000, 3), (0x2000, 7)]);
        assert_eq!(hm.total_hits(), 10);
    }

    #[test]
    fn merge_sums_counts() {
        let mut a = make_heatmap(&[(0x1000, 5)]);
        let b = make_heatmap(&[(0x1000, 3), (0x2000, 4)]);
        a.merge(&b);
        assert_eq!(a.count(0x1000), 8);
        assert_eq!(a.count(0x2000), 4);
    }

    #[test]
    fn max_and_min_count() {
        let hm = make_heatmap(&[(0x1000, 10), (0x2000, 1), (0x3000, 5)]);
        assert_eq!(hm.max_count(), 10);
        assert_eq!(hm.min_count(), 1);
    }

    #[test]
    fn normalised_heat() {
        let hm = make_heatmap(&[(0x1000, 100), (0x2000, 50)]);
        assert!((hm.normalised_heat(0x1000) - 1.0).abs() < f64::EPSILON);
        assert!((hm.normalised_heat(0x2000) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn covered_blocks_set() {
        let hm = make_heatmap(&[(0x1000, 1), (0x2000, 1)]);
        let set = hm.covered_blocks();
        assert!(set.contains(&0x1000));
        assert!(set.contains(&0x2000));
    }

    #[test]
    fn iter_sorted_by_addr_order() {
        let hm = make_heatmap(&[(0x3000, 1), (0x1000, 1), (0x2000, 1)]);
        let addrs: Vec<u64> = hm.iter_sorted_by_addr().map(|(a, _)| a).collect();
        assert_eq!(addrs, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn from_map_and_as_map() {
        let mut raw = HashMap::new();
        raw.insert(0x1000u64, 7u64);
        let hm = BbHeatmap::from_map(raw);
        assert_eq!(hm.count(0x1000), 7);
        assert_eq!(hm.as_map().len(), 1);
    }

    // ── HeatmapView ──────────────────────────────────────────────────────────

    #[test]
    fn view_sorted_hottest_first() {
        let hm = make_heatmap(&[(0x1000, 5), (0x2000, 100), (0x3000, 1)]);
        let view = hm.hotness_view();
        assert_eq!(view.entries[0].addr, 0x2000);
        assert_eq!(view.entries[2].addr, 0x3000);
    }

    #[test]
    fn view_top_n() {
        let hm = make_heatmap(&[(0x1000, 1), (0x2000, 2), (0x3000, 3)]);
        let view = hm.hotness_view();
        let top = view.top_n(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].addr, 0x3000);
    }

    #[test]
    fn view_rank_of() {
        let hm = make_heatmap(&[(0x1000, 10), (0x2000, 5)]);
        let view = hm.hotness_view();
        assert_eq!(view.rank_of(0x1000), Some(0));
        assert_eq!(view.rank_of(0xDEAD), None);
    }

    // ── HottestFunctions ─────────────────────────────────────────────────────

    #[test]
    fn hottest_functions_attribution() {
        let hm = make_heatmap(&[(0x1000, 5), (0x1010, 3), (0x2000, 10)]);
        let mut attr = HashMap::new();
        attr.insert(0x1000u64, 0x1000u64);
        attr.insert(0x1010u64, 0x1000u64);
        attr.insert(0x2000u64, 0x2000u64);
        let hf = HottestFunctions::from_heatmap(&hm, &attr);
        let func_a = hf.get(0x1000).unwrap();
        assert_eq!(func_a.total_hits, 8);
        assert_eq!(func_a.covered_blocks, 2);
        let func_b = hf.get(0x2000).unwrap();
        assert_eq!(func_b.total_hits, 10);
    }

    #[test]
    fn hottest_functions_sorted() {
        let hm = make_heatmap(&[(0x1000, 1), (0x2000, 100)]);
        let mut attr = HashMap::new();
        attr.insert(0x1000u64, 0x1000u64);
        attr.insert(0x2000u64, 0x2000u64);
        let hf = HottestFunctions::from_heatmap(&hm, &attr);
        let sorted = hf.sorted_by_heat();
        assert_eq!(sorted[0].entry, 0x2000);
    }

    // ── ColdBlockDetector ────────────────────────────────────────────────────

    #[test]
    fn cold_block_detector_basic() {
        let all: HashSet<u64> = [0x1000, 0x2000, 0x3000].iter().copied().collect();
        let det = ColdBlockDetector::new(all);
        let hm = make_heatmap(&[(0x1000, 1)]);
        let cold = det.cold_blocks(&hm);
        assert!(cold.contains(&0x2000));
        assert!(cold.contains(&0x3000));
        assert!(!cold.contains(&0x1000));
    }

    #[test]
    fn cold_block_count() {
        let all: HashSet<u64> = [0x1000, 0x2000, 0x3000].iter().copied().collect();
        let det = ColdBlockDetector::new(all);
        let hm = make_heatmap(&[(0x1000, 5)]);
        assert_eq!(det.cold_count(&hm), 2);
    }

    #[test]
    fn coverage_pct() {
        let all: HashSet<u64> = [0x1000, 0x2000].iter().copied().collect();
        let det = ColdBlockDetector::new(all);
        let hm = make_heatmap(&[(0x1000, 1)]);
        assert!((det.coverage_pct(&hm) - 50.0).abs() < 1e-9);
    }

    #[test]
    fn coverage_pct_empty_all_blocks() {
        let det = ColdBlockDetector::new(HashSet::new());
        let hm = BbHeatmap::new();
        assert!((det.coverage_pct(&hm) - 100.0).abs() < 1e-9);
    }

    // ── CoverageDiff ─────────────────────────────────────────────────────────

    #[test]
    fn diff_new_blocks_in_b() {
        let a = make_heatmap(&[(0x1000, 1)]);
        let b = make_heatmap(&[(0x1000, 1), (0x2000, 1)]);
        let diff = CoverageDiff::compute(&a, &b);
        assert_eq!(diff.new_blocks_in_b(), 1);
        assert!(diff.only_in_b.contains(&0x2000));
    }

    #[test]
    fn diff_regressed_blocks() {
        let a = make_heatmap(&[(0x1000, 1), (0x3000, 1)]);
        let b = make_heatmap(&[(0x1000, 1)]);
        let diff = CoverageDiff::compute(&a, &b);
        assert_eq!(diff.regressed_blocks(), 1);
        assert!(diff.only_in_a.contains(&0x3000));
    }

    #[test]
    fn diff_hotter_in_b() {
        let a = make_heatmap(&[(0x1000, 5)]);
        let b = make_heatmap(&[(0x1000, 10)]);
        let diff = CoverageDiff::compute(&a, &b);
        assert_eq!(diff.hotter_in_b().len(), 1);
        assert_eq!(diff.cooler_in_b().len(), 0);
    }

    #[test]
    fn diff_total_count_delta() {
        let a = make_heatmap(&[(0x1000, 10)]);
        let b = make_heatmap(&[(0x1000, 15)]);
        let diff = CoverageDiff::compute(&a, &b);
        assert_eq!(diff.total_count_delta(), 5);
    }

    #[test]
    fn diff_display() {
        let a = make_heatmap(&[(0x1000, 1)]);
        let b = make_heatmap(&[(0x2000, 1)]);
        let diff = CoverageDiff::compute(&a, &b);
        let s = diff.to_string();
        assert!(s.contains("CoverageDiff"));
    }

    // ── HeatBand ─────────────────────────────────────────────────────────────

    #[test]
    fn heat_band_cold() {
        assert_eq!(HeatBand::classify(0), HeatBand::Cold);
    }

    #[test]
    fn heat_band_warm() {
        assert_eq!(HeatBand::classify(5), HeatBand::Warm);
    }

    #[test]
    fn heat_band_hot() {
        assert_eq!(HeatBand::classify(50), HeatBand::Hot);
    }

    #[test]
    fn heat_band_blazing() {
        assert_eq!(HeatBand::classify(200), HeatBand::Blazing);
    }

    #[test]
    fn heat_band_display() {
        assert_eq!(HeatBand::Cold.to_string(), "COLD");
        assert_eq!(HeatBand::Blazing.to_string(), "BLAZING");
    }
}
