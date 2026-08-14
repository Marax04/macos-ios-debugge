//! `coverage_timeline` — Track how coverage accumulates over time across
//! multiple runs, producing a coverage growth curve and novelty metrics.
//!
//! Key types:
//! - [`TimelineEntry`] — one point on the growth curve (run index, cumulative unique BBs)
//! - [`CoverageTimeline`] — ordered list of timeline entries with growth statistics
//! - [`CoverageTimelineBuilder`] — incrementally builds a timeline from a sequence of runs
//! - [`NoveltyReport`] — summarises which addresses were "newly discovered" in each run

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::{CoverageRun, CoverageDiff};

// ─── TimelineEntry ────────────────────────────────────────────────────────────

/// A single data point on the coverage growth curve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// Sequential index of this run (0-based).
    pub run_index: usize,
    /// Label / name of this run.
    pub run_name: String,
    /// Cumulative unique basic blocks seen up to and including this run.
    pub cumulative_unique_bbs: usize,
    /// New unique BBs added by this run (delta from previous entry).
    pub new_bbs_this_run: usize,
    /// Total execution count (sum of all BB hit counts) for this run.
    pub total_executions: u64,
    /// Unique edges covered in this run.
    pub unique_edges: usize,
}

impl TimelineEntry {
    /// Coverage growth rate: fraction of new BBs relative to cumulative total.
    #[must_use]
    pub fn growth_rate(&self) -> f64 {
        if self.cumulative_unique_bbs == 0 {
            return 0.0;
        }
        crate::usize_to_f64(self.new_bbs_this_run) / crate::usize_to_f64(self.cumulative_unique_bbs)
    }
}

// ─── CoverageTimeline ─────────────────────────────────────────────────────────

/// Coverage growth curve over a sequence of runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageTimeline {
    /// Ordered entries, one per run.
    pub entries: Vec<TimelineEntry>,
    /// Label for this timeline.
    pub label: String,
}

impl CoverageTimeline {
    /// Create an empty timeline.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            entries: Vec::new(),
            label: label.into(),
        }
    }

    /// Total unique BBs at the end of the timeline.
    #[must_use]
    pub fn final_unique_bbs(&self) -> usize {
        self.entries.last().map_or(0, |e| e.cumulative_unique_bbs)
    }

    /// Number of runs.
    #[must_use]
    pub const fn run_count(&self) -> usize {
        self.entries.len()
    }

    /// The run with the most new BBs (the highest-value run).
    #[must_use]
    pub fn best_run(&self) -> Option<&TimelineEntry> {
        self.entries.iter().max_by_key(|e| e.new_bbs_this_run)
    }

    /// Estimated saturation point: the index at which 90 % of final coverage was reached.
    #[must_use]
    pub fn saturation_index(&self) -> Option<usize> {
        let target = crate::f64_to_usize_clamp(crate::usize_to_f64(self.final_unique_bbs()) * 0.9);
        self.entries
            .iter()
            .position(|e| e.cumulative_unique_bbs >= target)
    }

    /// Compute average new BBs per run.
    #[must_use]
    pub fn average_new_bbs(&self) -> f64 {
        if self.entries.is_empty() {
            return 0.0;
        }
        let total: usize = self.entries.iter().map(|e| e.new_bbs_this_run).sum();
        crate::usize_to_f64(total) / crate::usize_to_f64(self.entries.len())
    }

    /// Render a plain-text growth table.
    #[must_use]
    pub fn render_table(&self) -> String {
        let mut out = format!("=== Coverage Timeline: {} ===\n", self.label);
        writeln!(out,
            "{:>5}  {:32}  {:>8}  {:>6}  {:>7}  {:>8}",
            "Run", "Name", "Cumul.BB", "+New", "Edges", "Exec"
        ).ok();
        out.push_str(&"-".repeat(80));
        out.push('\n');
        for e in &self.entries {
            writeln!(out,
                "{:>5}  {:32}  {:>8}  {:>+6}  {:>7}  {:>8}",
                e.run_index,
                truncate_32(&e.run_name),
                e.cumulative_unique_bbs,
                e.new_bbs_this_run,
                e.unique_edges,
                e.total_executions,
            ).ok();
        }
        out
    }

    /// Render as CSV.
    #[must_use]
    pub fn render_csv(&self) -> String {
        let mut out = String::from(
            "run_index,run_name,cumulative_unique_bbs,new_bbs_this_run,unique_edges,total_executions\n",
        );
        for e in &self.entries {
            writeln!(out,
                "{},{},{},{},{},{}",
                e.run_index,
                e.run_name,
                e.cumulative_unique_bbs,
                e.new_bbs_this_run,
                e.unique_edges,
                e.total_executions,
            ).ok();
        }
        out
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` on serialization failure.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ─── CoverageTimelineBuilder ──────────────────────────────────────────────────

/// Incrementally builds a [`CoverageTimeline`] by feeding runs one at a time.
///
/// Maintains a cumulative set of all addresses seen so far.
#[derive(Debug, Default)]
pub struct CoverageTimelineBuilder {
    seen: HashSet<u64>,
    entries: Vec<TimelineEntry>,
    label: String,
}

impl CoverageTimelineBuilder {
    /// Create a new builder with the given timeline label.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            seen: HashSet::new(),
            entries: Vec::new(),
            label: label.into(),
        }
    }

    /// Feed the next run into the timeline.
    ///
    /// Returns the number of new unique BBs discovered by this run.
    pub fn feed(&mut self, run: &CoverageRun) -> usize {
        let before = self.seen.len();
        for &addr in run.bb_hits.keys() {
            self.seen.insert(addr);
        }
        let after = self.seen.len();
        let new_bbs = after - before;

        self.entries.push(TimelineEntry {
            run_index: self.entries.len(),
            run_name: run.name.clone(),
            cumulative_unique_bbs: after,
            new_bbs_this_run: new_bbs,
            total_executions: run.total_bb_executions(),
            unique_edges: run.unique_edges(),
        });

        new_bbs
    }

    /// Feed multiple runs at once.
    pub fn feed_all(&mut self, runs: &[CoverageRun]) {
        for run in runs {
            self.feed(run);
        }
    }

    /// Finalize and return the completed timeline.
    #[must_use]
    pub fn build(self) -> CoverageTimeline {
        CoverageTimeline {
            entries: self.entries,
            label: self.label,
        }
    }

    /// Current cumulative unique BB count.
    #[must_use]
    pub fn current_unique_bbs(&self) -> usize {
        self.seen.len()
    }

    /// Number of runs fed so far.
    #[must_use]
    pub const fn run_count(&self) -> usize {
        self.entries.len()
    }
}

// ─── NoveltyReport ────────────────────────────────────────────────────────────

/// A per-run novelty record: which addresses were first seen in this run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunNovelty {
    /// Run index.
    pub run_index: usize,
    /// Run name.
    pub run_name: String,
    /// Addresses newly discovered in this run.
    pub new_addresses: Vec<u64>,
}

impl RunNovelty {
    /// Number of new addresses.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.new_addresses.len()
    }
}

/// Full novelty report: maps run index to the set of new addresses it discovered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoveltyReport {
    pub runs: Vec<RunNovelty>,
    /// Total unique addresses across all runs.
    pub total_unique: usize,
    /// Label for this report.
    pub label: String,
}

impl NoveltyReport {
    /// Build a novelty report from a sequence of `CoverageRun`s.
    #[must_use]
    pub fn build(runs: &[CoverageRun], label: impl Into<String>) -> Self {
        let mut seen: HashSet<u64> = HashSet::new();
        let mut novelties = Vec::with_capacity(runs.len());

        for (idx, run) in runs.iter().enumerate() {
            let mut new_addrs: Vec<u64> = run
                .bb_hits
                .keys()
                .copied()
                .filter(|addr| !seen.contains(addr))
                .collect();
            new_addrs.sort_unstable();
            for &addr in &new_addrs {
                seen.insert(addr);
            }
            novelties.push(RunNovelty {
                run_index: idx,
                run_name: run.name.clone(),
                new_addresses: new_addrs,
            });
        }

        Self {
            total_unique: seen.len(),
            runs: novelties,
            label: label.into(),
        }
    }

    /// Find the run that discovered the most new addresses.
    #[must_use]
    pub fn most_novel_run(&self) -> Option<&RunNovelty> {
        self.runs.iter().max_by_key(|r| r.count())
    }

    /// Find runs that discovered zero new addresses (redundant runs).
    #[must_use]
    pub fn redundant_runs(&self) -> Vec<&RunNovelty> {
        self.runs.iter().filter(|r| r.count() == 0).collect()
    }

    /// Render a summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut out = format!("=== Novelty Report: {} ===\n", self.label);
        writeln!(out, "Total unique addresses: {}", self.total_unique).ok();
        writeln!(out, "Runs analyzed: {}", self.runs.len()).ok();
        if let Some(best) = self.most_novel_run() {
            writeln!(out,
                "Most novel run: {} (+{} addresses)",
                best.run_name,
                best.count()
            ).ok();
        }
        let redundant = self.redundant_runs().len();
        writeln!(out, "Redundant runs (0 new): {redundant}").ok();
        out
    }
}

// ─── CoverageGrowthStats ──────────────────────────────────────────────────────

/// Statistical summary of coverage growth across a sequence of runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageGrowthStats {
    /// Total runs.
    pub run_count: usize,
    /// Final cumulative unique BB count.
    pub final_unique_bbs: usize,
    /// Average new BBs per run.
    pub avg_new_bbs_per_run: f64,
    /// Maximum new BBs in a single run.
    pub max_new_bbs_single_run: usize,
    /// Estimated run index at which 50 % coverage was reached.
    pub half_coverage_index: Option<usize>,
    /// Estimated run index at which 90 % coverage was reached.
    pub saturation_index: Option<usize>,
    /// Fraction of runs that were redundant (added 0 new BBs).
    pub redundancy_ratio: f64,
}

impl CoverageGrowthStats {
    /// Compute growth statistics from a [`CoverageTimeline`].
    #[must_use]
    pub fn from_timeline(tl: &CoverageTimeline) -> Self {
        let final_unique = tl.final_unique_bbs();
        let run_count = tl.run_count();
        let avg = tl.average_new_bbs();
        let max = tl.entries.iter().map(|e| e.new_bbs_this_run).max().unwrap_or(0);

        let half_target = crate::f64_to_usize_clamp(crate::usize_to_f64(final_unique) * 0.5);
        let half_idx = tl
            .entries
            .iter()
            .position(|e| e.cumulative_unique_bbs >= half_target);

        let sat_idx = tl.saturation_index();

        let redundant = tl.entries.iter().filter(|e| e.new_bbs_this_run == 0).count();
        let redundancy = if run_count == 0 {
            0.0
        } else {
            crate::usize_to_f64(redundant) / crate::usize_to_f64(run_count)
        };

        Self {
            run_count,
            final_unique_bbs: final_unique,
            avg_new_bbs_per_run: avg,
            max_new_bbs_single_run: max,
            half_coverage_index: half_idx,
            saturation_index: sat_idx,
            redundancy_ratio: redundancy,
        }
    }

    /// Render a human-readable summary.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from("=== Coverage Growth Statistics ===\n");
        writeln!(out, "  Runs:               {}", self.run_count).ok();
        writeln!(out, "  Final unique BBs:   {}", self.final_unique_bbs).ok();
        writeln!(out, "  Avg new BBs/run:    {:.2}", self.avg_new_bbs_per_run).ok();
        writeln!(out, "  Max new BBs/run:    {}", self.max_new_bbs_single_run).ok();
        writeln!(out,
            "  50%% coverage at:   {}",
            self.half_coverage_index
                .map_or_else(|| "N/A".to_string(), |i| i.to_string())
        ).ok();
        writeln!(out,
            "  90%% coverage at:   {}",
            self.saturation_index
                .map_or_else(|| "N/A".to_string(), |i| i.to_string())
        ).ok();
        writeln!(out,
            "  Redundancy ratio:   {:.1}%%",
            self.redundancy_ratio * 100.0
        ).ok();
        out
    }
}

// ─── RunComparison ────────────────────────────────────────────────────────────

/// Pairwise comparison between two consecutive runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunComparison {
    pub run_a_name: String,
    pub run_b_name: String,
    /// BBs only in A.
    pub only_in_a: usize,
    /// BBs only in B.
    pub only_in_b: usize,
    /// BBs in both.
    pub in_both: usize,
    /// Jaccard similarity.
    pub jaccard: f64,
}

impl RunComparison {
    /// Compare two runs.
    #[must_use]
    pub fn compare(a: &CoverageRun, b: &CoverageRun) -> Self {
        let diff = CoverageDiff::compute(a, b);
        Self {
            run_a_name: a.name.clone(),
            run_b_name: b.name.clone(),
            only_in_a: diff.new_in_a.len(),
            only_in_b: diff.new_in_b.len(),
            in_both: diff.in_both.len(),
            jaccard: diff.jaccard,
        }
    }

    /// Overall coverage overlap fraction (0.0 – 1.0).
    #[must_use]
    pub const fn overlap(&self) -> f64 {
        self.jaccard
    }
}

/// Compute pairwise comparisons for a sequence of runs.
#[must_use]
pub fn pairwise_comparisons(runs: &[CoverageRun]) -> Vec<RunComparison> {
    if runs.len() < 2 {
        return Vec::new();
    }
    runs.windows(2)
        .map(|w| RunComparison::compare(&w[0], &w[1]))
        .collect()
}

// ─── BucketedTimeline ────────────────────────────────────────────────────────

/// A timeline bucketed by time windows (e.g., every N runs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketedTimelineEntry {
    /// Start index of this bucket.
    pub bucket_start: usize,
    /// End index (exclusive).
    pub bucket_end: usize,
    /// Total new BBs discovered in this bucket.
    pub new_bbs_in_bucket: usize,
    /// Cumulative unique BBs at end of bucket.
    pub cumulative_at_end: usize,
}

/// Build a bucketed timeline from a flat timeline.
#[must_use]
pub fn bucket_timeline(tl: &CoverageTimeline, bucket_size: usize) -> Vec<BucketedTimelineEntry> {
    if tl.entries.is_empty() || bucket_size == 0 {
        return Vec::new();
    }
    let mut buckets = Vec::new();
    let mut i = 0;
    while i < tl.entries.len() {
        let end = (i + bucket_size).min(tl.entries.len());
        let bucket_new: usize = tl.entries[i..end].iter().map(|e| e.new_bbs_this_run).sum();
        let cumulative = tl.entries[end - 1].cumulative_unique_bbs;
        buckets.push(BucketedTimelineEntry {
            bucket_start: i,
            bucket_end: end,
            new_bbs_in_bucket: bucket_new,
            cumulative_at_end: cumulative,
        });
        i += bucket_size;
    }
    buckets
}

// ─── AddressFirstSeen ─────────────────────────────────────────────────────────

/// Track which run first covered each address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressFirstSeen {
    /// Map from BB address to the run index that first covered it.
    pub first_seen: BTreeMap<u64, usize>,
}

impl AddressFirstSeen {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a run at the given index.
    pub fn feed(&mut self, run_index: usize, run: &CoverageRun) {
        for &addr in run.bb_hits.keys() {
            self.first_seen.entry(addr).or_insert(run_index);
        }
    }

    /// Which run first covered `addr`?
    #[must_use]
    pub fn first_seen_in(&self, addr: u64) -> Option<usize> {
        self.first_seen.get(&addr).copied()
    }

    /// Number of distinct addresses tracked.
    #[must_use]
    pub fn address_count(&self) -> usize {
        self.first_seen.len()
    }

    /// Distribution: how many addresses were first seen in each run.
    #[must_use]
    pub fn distribution(&self) -> HashMap<usize, usize> {
        let mut dist: HashMap<usize, usize> = HashMap::new();
        for &run_idx in self.first_seen.values() {
            *dist.entry(run_idx).or_insert(0) += 1;
        }
        dist
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn truncate_32(s: &str) -> String {
    if s.chars().count() <= 32 {
        s.to_string()
    } else {
        // Collect up to 31 chars so we never split a multibyte codepoint.
        let truncated: String = s.chars().take(31).collect();
        format!("{truncated}…")
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoverageRun;

    fn make_run_with_bbs(name: &str, addrs: &[u64]) -> CoverageRun {
        let mut run = CoverageRun::new(name);
        for &addr in addrs {
            run.record_bb(addr);
        }
        run
    }

    #[test]
    fn test_timeline_builder_basic() {
        let r1 = make_run_with_bbs("r1", &[0x1000, 0x1010]);
        let r2 = make_run_with_bbs("r2", &[0x1010, 0x1020]);
        let r3 = make_run_with_bbs("r3", &[0x1000]);

        let mut builder = CoverageTimelineBuilder::new("test");
        let new1 = builder.feed(&r1);
        let new2 = builder.feed(&r2);
        let new3 = builder.feed(&r3);

        assert_eq!(new1, 2);
        assert_eq!(new2, 1); // 0x1020 is new
        assert_eq!(new3, 0); // no new addresses
        assert_eq!(builder.current_unique_bbs(), 3);
    }

    #[test]
    fn test_timeline_render_table() {
        let r1 = make_run_with_bbs("run_a", &[0x1000]);
        let r2 = make_run_with_bbs("run_b", &[0x1010]);
        let mut builder = CoverageTimelineBuilder::new("t");
        builder.feed_all(&[r1, r2]);
        let tl = builder.build();
        let table = tl.render_table();
        assert!(table.contains("run_a"));
        assert!(table.contains("run_b"));
    }

    #[test]
    fn test_novelty_report() {
        let runs = vec![
            make_run_with_bbs("r1", &[0x1000, 0x1010]),
            make_run_with_bbs("r2", &[0x1020]),
            make_run_with_bbs("r3", &[0x1000]), // redundant
        ];
        let report = NoveltyReport::build(&runs, "test");
        assert_eq!(report.total_unique, 3);
        assert_eq!(report.runs[0].count(), 2);
        assert_eq!(report.runs[1].count(), 1);
        assert_eq!(report.runs[2].count(), 0);
        let redundant = report.redundant_runs();
        assert_eq!(redundant.len(), 1);
    }

    #[test]
    fn test_coverage_growth_stats() {
        let r1 = make_run_with_bbs("r1", &[0x1000, 0x1010]);
        let r2 = make_run_with_bbs("r2", &[0x1020]);
        let r3 = make_run_with_bbs("r3", &[0x1000]);
        let mut builder = CoverageTimelineBuilder::new("s");
        builder.feed_all(&[r1, r2, r3]);
        let tl = builder.build();
        let stats = CoverageGrowthStats::from_timeline(&tl);
        assert_eq!(stats.run_count, 3);
        assert_eq!(stats.final_unique_bbs, 3);
        assert!((stats.redundancy_ratio - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_run_comparison() {
        let r1 = make_run_with_bbs("r1", &[0x1000, 0x1010]);
        let r2 = make_run_with_bbs("r2", &[0x1010, 0x1020]);
        let cmp = RunComparison::compare(&r1, &r2);
        assert_eq!(cmp.only_in_a, 1);
        assert_eq!(cmp.only_in_b, 1);
        assert_eq!(cmp.in_both, 1);
        assert!((cmp.jaccard - 1.0 / 3.0).abs() < 1e-6);
    }

    #[test]
    fn test_pairwise_comparisons() {
        let runs = vec![
            make_run_with_bbs("r0", &[0x1000]),
            make_run_with_bbs("r1", &[0x1010]),
            make_run_with_bbs("r2", &[0x1020]),
        ];
        let cmps = pairwise_comparisons(&runs);
        assert_eq!(cmps.len(), 2);
    }

    #[test]
    fn test_bucket_timeline() {
        let r1 = make_run_with_bbs("r1", &[0x1000]);
        let r2 = make_run_with_bbs("r2", &[0x1010]);
        let r3 = make_run_with_bbs("r3", &[0x1020]);
        let r4 = make_run_with_bbs("r4", &[0x1030]);
        let mut builder = CoverageTimelineBuilder::new("b");
        builder.feed_all(&[r1, r2, r3, r4]);
        let tl = builder.build();
        let buckets = bucket_timeline(&tl, 2);
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].new_bbs_in_bucket, 2);
        assert_eq!(buckets[1].new_bbs_in_bucket, 2);
    }

    #[test]
    fn test_address_first_seen() {
        let r1 = make_run_with_bbs("r1", &[0x1000, 0x1010]);
        let r2 = make_run_with_bbs("r2", &[0x1010, 0x1020]);
        let mut tracker = AddressFirstSeen::new();
        tracker.feed(0, &r1);
        tracker.feed(1, &r2);
        assert_eq!(tracker.first_seen_in(0x1000), Some(0));
        assert_eq!(tracker.first_seen_in(0x1010), Some(0));
        assert_eq!(tracker.first_seen_in(0x1020), Some(1));
        assert_eq!(tracker.first_seen_in(0x9999), None);
    }

    #[test]
    fn test_timeline_csv() {
        let mut builder = CoverageTimelineBuilder::new("csv_test");
        builder.feed(&make_run_with_bbs("r1", &[0x1000]));
        let tl = builder.build();
        let csv = tl.render_csv();
        assert!(csv.contains("run_index"));
        assert!(csv.contains("r1"));
    }

    #[test]
    fn test_timeline_saturation_index() {
        let mut builder = CoverageTimelineBuilder::new("sat");
        for i in 0..10u64 {
            builder.feed(&make_run_with_bbs(&format!("r{i}"), &[i * 0x10]));
        }
        let tl = builder.build();
        let idx = tl.saturation_index();
        assert!(idx.is_some());
        assert!(idx.unwrap() < 10);
    }

    #[test]
    fn test_run_novelty_best_run() {
        let runs = vec![
            make_run_with_bbs("big", &[0x1000, 0x1010, 0x1020]),
            make_run_with_bbs("small", &[0x1030]),
        ];
        let report = NoveltyReport::build(&runs, "best");
        let best = report.most_novel_run().unwrap();
        assert_eq!(best.run_name, "big");
    }
}
