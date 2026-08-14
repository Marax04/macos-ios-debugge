//! Coverage diff: compare two fuzzing runs and detect regressions.
//!
//! Given two [`CoverageSnapshot`] or two sets of covered edges, this module
//! computes:
//! - New edges: covered in run B but not in run A.
//! - Lost edges: covered in run A but not in run B (regression).
//! - Stable edges: covered in both.
//! - Coverage delta percentage.
//!
//! Also provides:
//! - Diff of per-function hit counts (which functions gained / lost coverage).
//! - Regression detector: flags when a diff exceeds configurable thresholds.
//! - Multi-run trend analysis: compute coverage growth over a sequence of runs.
//! - LCOV diff export (patch-style `.info` diff).

use std::fmt::Write as _;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use rayon::prelude::*;

use crate::{CoverageRun, FileCoverage};

// ─── Edge sets (type aliases) ────────────────────────────────────────────────

pub type EdgeId = u64;

/// A named snapshot of covered edges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeSnapshot {
    /// Human-readable label (e.g. run ID, commit SHA, date-time).
    pub label: String,
    /// Covered edge IDs.
    pub edges: HashSet<EdgeId>,
    /// Per-edge hit counts (0 = not hit, positive = hit count).
    pub hit_counts: HashMap<EdgeId, u64>,
    /// Timestamp of this snapshot.
    pub timestamp: Option<u64>,
    /// Optional path to the source coverage file.
    pub source_path: Option<PathBuf>,
}

impl EdgeSnapshot {
    /// Create a snapshot from a coverage run.
    pub fn from_run(run: &CoverageRun) -> Self {
        let mut edges = HashSet::new();
        let mut hit_counts = HashMap::new();
        for (&addr, &count) in &run.bb_hits {
            edges.insert(addr);
            hit_counts.insert(addr, count);
        }
        Self {
            label: run.name.clone(),
            edges,
            hit_counts,
            timestamp: run
                .timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
            source_path: run.source.as_ref().map(PathBuf::from),
        }
    }

    /// Create a snapshot from a raw edge set.
    pub fn from_edges(
        label: impl Into<String>,
        edges: HashSet<EdgeId>,
    ) -> Self {
        let hit_counts: HashMap<EdgeId, u64> =
            edges.iter().map(|&e| (e, 1u64)).collect();
        Self {
            label: label.into(),
            edges,
            hit_counts,
            timestamp: None,
            source_path: None,
        }
    }

    /// Total edge count.
    #[must_use] 
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Total hit sum across all edges.
    #[must_use] 
    pub fn total_hits(&self) -> u64 {
        self.hit_counts.values().sum()
    }
}

// ─── EdgeDiff ────────────────────────────────────────────────────────────────

/// Result of diffing two edge snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeDiff {
    /// Label of the baseline snapshot.
    pub baseline_label: String,
    /// Label of the comparison snapshot.
    pub compare_label: String,
    /// Edges gained in compare vs baseline.
    pub gained: HashSet<EdgeId>,
    /// Edges lost in compare vs baseline (regression).
    pub lost: HashSet<EdgeId>,
    /// Edges present in both snapshots.
    pub stable: HashSet<EdgeId>,
    /// Edges where the hit count changed (but edge is present in both).
    pub hit_count_changed: HashMap<EdgeId, (u64, u64)>, // (baseline_hits, compare_hits)
    /// Coverage delta in absolute edge count.
    pub delta_edges: i64,
    /// Coverage delta as a percentage of baseline coverage.
    pub delta_pct: f64,
    /// Whether this diff represents a regression (lost edges > threshold).
    pub is_regression: bool,
}

impl EdgeDiff {
    /// Compute the diff between two snapshots.
    #[must_use] 
    pub fn compute(baseline: &EdgeSnapshot, compare: &EdgeSnapshot) -> Self {
        let gained: HashSet<EdgeId> = compare
            .edges
            .difference(&baseline.edges)
            .copied()
            .collect();
        let lost: HashSet<EdgeId> = baseline
            .edges
            .difference(&compare.edges)
            .copied()
            .collect();
        let stable: HashSet<EdgeId> = baseline
            .edges
            .intersection(&compare.edges)
            .copied()
            .collect();

        let mut hit_count_changed = HashMap::new();
        for &edge in &stable {
            let b = baseline.hit_counts.get(&edge).copied().unwrap_or(0);
            let c = compare.hit_counts.get(&edge).copied().unwrap_or(0);
            if b != c {
                hit_count_changed.insert(edge, (b, c));
            }
        }

        let delta_edges = i64::try_from(compare.edge_count()).unwrap_or(i64::MAX) - i64::try_from(baseline.edge_count()).unwrap_or(i64::MAX);
        let delta_pct = if baseline.edge_count() > 0 {
            crate::casts::u64_to_f64(u64::try_from((delta_edges).max(0)).unwrap_or(0)) / crate::casts::usize_to_f64(baseline.edge_count()) * 100.0
        } else {
            0.0
        };

        Self {
            baseline_label: baseline.label.clone(),
            compare_label: compare.label.clone(),
            gained,
            lost,
            stable,
            hit_count_changed,
            delta_edges,
            delta_pct,
            is_regression: false, // filled in by RegressionDetector
        }
    }

    /// Number of edges gained.
    #[must_use] 
    pub fn gained_count(&self) -> usize {
        self.gained.len()
    }

    /// Number of edges lost.
    #[must_use] 
    pub fn lost_count(&self) -> usize {
        self.lost.len()
    }

    /// Number of stable edges.
    #[must_use] 
    pub fn stable_count(&self) -> usize {
        self.stable.len()
    }
}

impl fmt::Display for EdgeDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EdgeDiff [{} → {}]: +{} gained, -{} lost, {} stable, Δ{:+.1}%{}",
            self.baseline_label,
            self.compare_label,
            self.gained_count(),
            self.lost_count(),
            self.stable_count(),
            self.delta_pct,
            if self.is_regression { " ⚠ REGRESSION" } else { "" },
        )
    }
}

// ─── FunctionDiff ─────────────────────────────────────────────────────────────

/// Per-function coverage change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDiff {
    pub function_name: String,
    pub module: String,
    /// Lines covered in baseline.
    pub baseline_lines: usize,
    /// Lines covered in compare.
    pub compare_lines: usize,
    /// Total lines in the function (if known).
    pub total_lines: Option<usize>,
    /// Coverage percentage in baseline.
    pub baseline_pct: f64,
    /// Coverage percentage in compare.
    pub compare_pct: f64,
    /// Absolute change in covered lines.
    pub delta_lines: i64,
    /// Change in coverage percentage.
    pub delta_pct: f64,
    pub status: FunctionDiffStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionDiffStatus {
    /// Coverage improved.
    Improved,
    /// Coverage regressed.
    Regressed,
    /// No change.
    Unchanged,
    /// Function newly appeared in compare.
    New,
    /// Function was present in baseline but absent in compare.
    Dropped,
}

// ─── FileCoverageDiff ─────────────────────────────────────────────────────────

/// Diff of line-level coverage for a single source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCoverageDiff {
    pub source_file: PathBuf,
    /// Lines that became covered in compare.
    pub newly_covered: Vec<u32>,
    /// Lines that lost coverage in compare.
    pub lost_coverage: Vec<u32>,
    /// Lines with increased hit counts.
    pub increased_hits: Vec<(u32, u64, u64)>, // (line, baseline_hits, compare_hits)
    /// Lines with decreased hit counts (but still covered).
    pub decreased_hits: Vec<(u32, u64, u64)>,
    pub baseline_covered_lines: usize,
    pub compare_covered_lines: usize,
    pub delta_lines: i64,
    pub delta_pct: f64,
}

impl FileCoverageDiff {
    /// Compute the diff between two `FileCoverage` objects.
    #[must_use] 
    pub fn compute(baseline: &FileCoverage, compare: &FileCoverage) -> Self {
        let mut newly_covered = Vec::new();
        let mut lost_coverage = Vec::new();
        let mut increased_hits = Vec::new();
        let mut decreased_hits = Vec::new();

        // Union of all line numbers.
        let all_lines: HashSet<u32> = baseline
            .lines
            .keys()
            .chain(compare.lines.keys())
            .copied()
            .collect();

        for line in &all_lines {
            let b_hits = baseline.lines.get(line).copied().unwrap_or(0);
            let c_hits = compare.lines.get(line).copied().unwrap_or(0);
            match (b_hits, c_hits) {
                (0, c) if c > 0 => newly_covered.push(*line),
                (b, 0) if b > 0 => lost_coverage.push(*line),
                (b, c) if c > b => increased_hits.push((*line, u64::from(b), u64::from(c))),
                (b, c) if c < b && c > 0 => decreased_hits.push((*line, u64::from(b), u64::from(c))),
                _ => {}
            }
        }

        newly_covered.sort_unstable();
        lost_coverage.sort_unstable();
        increased_hits.sort_unstable_by_key(|x| x.0);
        decreased_hits.sort_unstable_by_key(|x| x.0);

        let baseline_covered = baseline.lines.values().filter(|&&h| h > 0).count();
        let compare_covered = compare.lines.values().filter(|&&h| h > 0).count();
        let delta_lines = i64::try_from(compare_covered).unwrap_or(i64::MAX) - i64::try_from(baseline_covered).unwrap_or(i64::MAX);
        let total = all_lines.len();
        let delta_pct = if total > 0 {
            crate::casts::u64_to_f64(u64::try_from((delta_lines).max(0)).unwrap_or(0)) / crate::casts::usize_to_f64(total) * 100.0
        } else {
            0.0
        };

        Self {
            source_file: baseline.source_file.clone(),
            newly_covered,
            lost_coverage,
            increased_hits,
            decreased_hits,
            baseline_covered_lines: baseline_covered,
            compare_covered_lines: compare_covered,
            delta_lines,
            delta_pct,
        }
    }

    /// True if there are any regressions (lost coverage lines).
    #[must_use] 
    pub const fn has_regression(&self) -> bool {
        !self.lost_coverage.is_empty()
    }
}

// ─── RegressionDetector ──────────────────────────────────────────────────────

/// Configurable thresholds for regression detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionConfig {
    /// Minimum number of lost edges to trigger a regression flag.
    pub min_lost_edges: usize,
    /// Minimum percentage of lost edges (relative to baseline) to trigger.
    pub min_lost_pct: f64,
    /// If true, any lost edge is a regression (overrides other thresholds).
    pub any_loss_is_regression: bool,
    /// Specific edge IDs that are "sentinel" edges — losing them is always a regression.
    pub sentinel_edges: HashSet<EdgeId>,
}

impl Default for RegressionConfig {
    fn default() -> Self {
        Self {
            min_lost_edges: 1,
            min_lost_pct: 0.5,
            any_loss_is_regression: false,
            sentinel_edges: HashSet::new(),
        }
    }
}

/// Evaluates a diff against configured thresholds.
pub struct RegressionDetector {
    config: RegressionConfig,
}

impl RegressionDetector {
    #[must_use] 
    pub const fn new(config: RegressionConfig) -> Self {
        Self { config }
    }

    /// Annotate an [`EdgeDiff`] with regression status.
    pub fn evaluate(&self, diff: &mut EdgeDiff) {
        if self.config.any_loss_is_regression && diff.lost_count() > 0 {
            diff.is_regression = true;
            return;
        }

        // Check sentinel edges.
        if !self.config.sentinel_edges.is_empty()
            && diff.lost.intersection(&self.config.sentinel_edges).count() > 0 {
                diff.is_regression = true;
                return;
            }

        let lost = diff.lost_count();
        let baseline_total = diff.stable_count() + lost; // approximate
        let lost_pct = if baseline_total > 0 {
            crate::casts::usize_to_f64(lost) / crate::casts::usize_to_f64(baseline_total) * 100.0
        } else {
            0.0
        };

        diff.is_regression = lost >= self.config.min_lost_edges
            && lost_pct >= self.config.min_lost_pct;
    }
}

// ─── MultiRunTrend ────────────────────────────────────────────────────────────

/// Coverage trend across an ordered sequence of runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunTrendPoint {
    pub label: String,
    pub timestamp: Option<u64>,
    pub edge_count: usize,
    pub new_edges: usize,   // new since previous run
    pub lost_edges: usize,  // lost since previous run
    pub cumulative_edges: usize,
    pub is_regression: bool,
}

/// Compute a coverage trend over an ordered slice of snapshots.
#[must_use] 
pub fn compute_trend(
    snapshots: &[EdgeSnapshot],
    regression_config: &RegressionConfig,
) -> Vec<RunTrendPoint> {
    if snapshots.is_empty() {
        return Vec::new();
    }

    let detector = RegressionDetector::new(regression_config.clone());
    let mut cumulative: HashSet<EdgeId> = HashSet::new();
    let mut prev_edges: Option<&HashSet<EdgeId>> = None;
    let mut points = Vec::with_capacity(snapshots.len());

    let empty_edges: HashSet<EdgeId> = HashSet::new();
    for snap in snapshots {
        let new_edges = snap
            .edges
            .difference(prev_edges.unwrap_or(&empty_edges))
            .count();
        let lost_edges = prev_edges
            .map_or(0, |p| p.difference(&snap.edges).count());

        cumulative.extend(snap.edges.iter().copied());

        let is_regression = prev_edges.is_some_and(|prev| {
            let baseline = EdgeSnapshot::from_edges("_baseline", prev.clone());
            let mut diff = EdgeDiff::compute(&baseline, snap);
            detector.evaluate(&mut diff);
            diff.is_regression
        });

        points.push(RunTrendPoint {
            label: snap.label.clone(),
            timestamp: snap.timestamp,
            edge_count: snap.edge_count(),
            new_edges,
            lost_edges,
            cumulative_edges: cumulative.len(),
            is_regression,
        });

        prev_edges = Some(&snap.edges);
    }
    points
}

// ─── LcovDiff export ─────────────────────────────────────────────────────────

/// LCOV diff: exports changed lines as a unified LCOV `.info` patch.
///
/// Only lines that changed are emitted, prefixed with `+` (gained) or `-` (lost).
/// This is a non-standard format but useful for CI diffs.
pub struct LcovDiffExporter {
    pub show_unchanged: bool,
}

impl LcovDiffExporter {
    #[must_use] 
    pub const fn new(show_unchanged: bool) -> Self {
        Self { show_unchanged }
    }

    /// Generate a diff string from a list of per-file diffs.
    #[must_use] 
    pub fn export(&self, diffs: &[FileCoverageDiff]) -> String {
        let mut out = String::with_capacity(diffs.len() * 256);
        for d in diffs {
            if d.newly_covered.is_empty()
                && d.lost_coverage.is_empty()
                && d.increased_hits.is_empty()
                && d.decreased_hits.is_empty()
                && !self.show_unchanged
            {
                continue;
            }
            let _ = writeln!(out, "SF:{}", d.source_file.display());
            for &line in &d.newly_covered {
                let _ = writeln!(out, "+DA:{line},1");
            }
            for &line in &d.lost_coverage {
                let _ = writeln!(out, "-DA:{line},0");
            }
            for &(line, b, c) in &d.increased_hits {
                let _ = writeln!(out, "~DA:{line},{b}→{c}");
            }
            for &(line, b, c) in &d.decreased_hits {
                let _ = writeln!(out, "~DA:{line},-{b}→{c}");
            }
            out.push_str("end_of_record\n");
        }
        out
    }
}

// ─── CoverageDiffReport ───────────────────────────────────────────────────────

/// Top-level report combining edge diff and file-level diffs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageDiffReport {
    pub edge_diff: EdgeDiff,
    pub file_diffs: Vec<FileCoverageDiff>,
    /// Summary of per-function changes.
    pub function_diffs: Vec<FunctionDiff>,
    pub generated_at: u64,
}

impl CoverageDiffReport {
    /// Compute a report from two full coverage snapshots with file-level data.
    #[must_use] 
    pub fn compute(
        baseline_snap: &EdgeSnapshot,
        compare_snap: &EdgeSnapshot,
        baseline_files: &[FileCoverage],
        compare_files: &[FileCoverage],
        regression_config: &RegressionConfig,
    ) -> Self {
        let mut edge_diff = EdgeDiff::compute(baseline_snap, compare_snap);
        let detector = RegressionDetector::new(regression_config.clone());
        detector.evaluate(&mut edge_diff);

        // Index compare files by path.
        let compare_by_path: HashMap<&Path, &FileCoverage> = compare_files
            .iter()
            .map(|f| (f.source_file.as_path(), f))
            .collect();

        // Compute file diffs in parallel.
        let file_diffs: Vec<FileCoverageDiff> = baseline_files
            .par_iter()
            .filter_map(|bf| {
                compare_by_path
                    .get(bf.source_file.as_path())
                    .map(|cf| FileCoverageDiff::compute(bf, cf))
            })
            .collect();

        let generated_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        Self {
            edge_diff,
            file_diffs,
            function_diffs: Vec::new(), // populated separately if needed
            generated_at,
        }
    }

    /// True if any file-level regression was detected.
    #[must_use] 
    pub fn has_file_regression(&self) -> bool {
        self.file_diffs.iter().any(FileCoverageDiff::has_regression)
    }

    /// Files with newly covered lines.
    #[must_use] 
    pub fn improved_files(&self) -> Vec<&FileCoverageDiff> {
        self.file_diffs
            .iter()
            .filter(|d| !d.newly_covered.is_empty())
            .collect()
    }

    /// Files with lost coverage.
    #[must_use] 
    pub fn regressed_files(&self) -> Vec<&FileCoverageDiff> {
        self.file_diffs
            .iter()
            .filter(|d| d.has_regression())
            .collect()
    }

    /// Export the full report as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export a human-readable summary.
    #[must_use] 
    pub fn summary(&self) -> String {
        let mut s = String::new();
        s.push_str("Coverage Diff Report\n");
        let _ = writeln!(s, "  {}", self.edge_diff);
        let _ = writeln!(
            s,
            "  File diffs: {} files, {} improved, {} regressed",
            self.file_diffs.len(),
            self.improved_files().len(),
            self.regressed_files().len(),
        );
        if self.edge_diff.is_regression || self.has_file_regression() {
            s.push_str("  STATUS: REGRESSION DETECTED\n");
        } else if self.edge_diff.gained_count() > 0 {
            s.push_str("  STATUS: COVERAGE IMPROVED\n");
        } else {
            s.push_str("  STATUS: NO CHANGE\n");
        }
        s
    }
}

// ─── CovError extension ───────────────────────────────────────────────────────

// (No new variants needed; uses existing crate::CovError.)

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(label: &str, edges: &[u64]) -> EdgeSnapshot {
        EdgeSnapshot::from_edges(label, edges.iter().copied().collect())
    }

    #[test]
    fn test_basic_diff() {
        let a = snap("a", &[1, 2, 3, 4]);
        let b = snap("b", &[2, 3, 5, 6]);
        let diff = EdgeDiff::compute(&a, &b);
        assert_eq!(diff.gained_count(), 2); // 5, 6
        assert_eq!(diff.lost_count(), 2);   // 1, 4
        assert_eq!(diff.stable_count(), 2); // 2, 3
        assert_eq!(diff.delta_edges, 0);    // same total
    }

    #[test]
    fn test_regression_detector_threshold() {
        let a = snap("a", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        // lose 2 edges out of 10 = 20% → above 0.5% threshold
        let b = snap("b", &[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut diff = EdgeDiff::compute(&a, &b);
        let detector = RegressionDetector::new(RegressionConfig::default());
        detector.evaluate(&mut diff);
        assert!(diff.is_regression);
    }

    #[test]
    fn test_no_regression_when_only_gained() {
        let a = snap("a", &[1, 2, 3]);
        let b = snap("b", &[1, 2, 3, 4, 5]);
        let mut diff = EdgeDiff::compute(&a, &b);
        let detector = RegressionDetector::new(RegressionConfig::default());
        detector.evaluate(&mut diff);
        assert!(!diff.is_regression);
        assert_eq!(diff.gained_count(), 2);
    }

    #[test]
    fn test_sentinel_edge() {
        let a = snap("a", &[1, 2, 3]);
        let b = snap("b", &[2, 3]); // lost edge 1 (sentinel)
        let config = RegressionConfig {
            sentinel_edges: std::iter::once(1u64).collect(),
            ..Default::default()
        };
        let mut diff = EdgeDiff::compute(&a, &b);
        let detector = RegressionDetector::new(config);
        detector.evaluate(&mut diff);
        assert!(diff.is_regression);
    }

    #[test]
    fn test_trend() {
        let snaps = vec![
            snap("r1", &[1, 2, 3]),
            snap("r2", &[1, 2, 3, 4, 5]),
            snap("r3", &[1, 2, 3, 4]),   // regression: lost 5
        ];
        let config = RegressionConfig::default();
        let trend = compute_trend(&snaps, &config);
        assert_eq!(trend.len(), 3);
        assert_eq!(trend[0].new_edges, 3); // first run
        assert_eq!(trend[1].new_edges, 2); // gained 4,5
        assert_eq!(trend[2].lost_edges, 1); // lost 5
        assert!(trend[2].is_regression);
    }

    #[test]
    fn test_file_diff() {
        let mut baseline = FileCoverage {
            source_file: PathBuf::from("src/foo.rs"),
            lines: HashMap::new(),
            functions: HashMap::new(),
        };
        baseline.lines.insert(1, 5);
        baseline.lines.insert(2, 0);
        baseline.lines.insert(3, 3);

        let mut compare = FileCoverage {
            source_file: PathBuf::from("src/foo.rs"),
            lines: HashMap::new(),
            functions: HashMap::new(),
        };
        compare.lines.insert(1, 5);
        compare.lines.insert(2, 2); // newly covered
        compare.lines.insert(3, 0); // lost coverage

        let diff = FileCoverageDiff::compute(&baseline, &compare);
        assert!(diff.newly_covered.contains(&2));
        assert!(diff.lost_coverage.contains(&3));
        assert!(diff.has_regression());
    }

    #[test]
    fn test_lcov_diff_export() {
        let diff = FileCoverageDiff {
            source_file: PathBuf::from("src/bar.rs"),
            newly_covered: vec![10, 11],
            lost_coverage: vec![5],
            increased_hits: vec![],
            decreased_hits: vec![],
            baseline_covered_lines: 8,
            compare_covered_lines: 9,
            delta_lines: 1,
            delta_pct: 5.0,
        };
        let exporter = LcovDiffExporter::new(false);
        let out = exporter.export(&[diff]);
        assert!(out.contains("+DA:10,1"));
        assert!(out.contains("-DA:5,0"));
        assert!(out.contains("SF:src/bar.rs"));
    }
}
