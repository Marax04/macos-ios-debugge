//! `pass_metrics.rs` — pass-level performance and transformation metrics.
//!
//! Provides structured, queryable metrics for every IL pass that executes
//! inside the pass manager.
//!
//! # Types
//! * [`PassMetrics`] — timing + transformation counters for a single run.
//! * [`PassProfile`] — accumulated profile over multiple runs of one pass.
//! * [`MetricsCollector`] — records and stores [`PassMetrics`] per run.
//! * [`PassComparison`] — side-by-side comparison of two profiles.
//! * [`RegressionDetector`] — flags statistically significant regressions.
//! * [`MetricsDashboard`] — human-readable summary of all collected profiles.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

// ─── PassMetrics ─────────────────────────────────────────────────────────────

/// Metrics captured during a single execution of one IL pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassMetrics {
    /// Unique name of the pass (e.g. `"mlil-constant-fold"`).
    pub pass_name: String,
    /// Wall-clock duration of the pass.
    pub duration: Duration,
    /// Peak heap allocated during the pass (bytes), if measured.
    pub peak_memory_bytes: Option<usize>,
    /// Number of IR transformations (instructions changed/removed/inserted).
    pub transforms: u32,
    /// Number of instructions that were *visited* (read) by the pass.
    pub instrs_visited: u64,
    /// Number of instructions removed.
    pub instrs_removed: u64,
    /// Number of instructions inserted.
    pub instrs_inserted: u64,
    /// Pass-specific named counters (e.g. `"folds"`, `"phi_elim"`, …).
    pub counters: HashMap<String, u64>,
}

impl PassMetrics {
    /// Create a new zero-initialised metrics record for `pass_name`.
    #[must_use]
    pub fn new(pass_name: impl Into<String>) -> Self {
        Self {
            pass_name: pass_name.into(),
            duration: Duration::ZERO,
            peak_memory_bytes: None,
            transforms: 0,
            instrs_visited: 0,
            instrs_removed: 0,
            instrs_inserted: 0,
            counters: HashMap::new(),
        }
    }

    /// Set a named counter value.
    pub fn set_counter(&mut self, key: impl Into<String>, value: u64) {
        self.counters.insert(key.into(), value);
    }

    /// Increment a named counter.
    pub fn inc_counter(&mut self, key: impl Into<String>) {
        *self.counters.entry(key.into()).or_insert(0) += 1;
    }

    /// Retrieve a named counter value (0 if not present).
    #[must_use]
    pub fn counter(&self, key: &str) -> u64 {
        self.counters.get(key).copied().unwrap_or(0)
    }

    /// True when no transformations were applied.
    #[must_use]
    pub const fn is_noop(&self) -> bool {
        self.transforms == 0 && self.instrs_removed == 0 && self.instrs_inserted == 0
    }

    /// Throughput in instructions-per-second (0.0 when duration is zero).
    #[must_use]
    pub fn throughput_ips(&self) -> f64 {
        let secs = self.duration.as_secs_f64();
        if secs == 0.0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.instrs_visited).unwrap_or(u32::MAX)) / secs
    }
}

impl fmt::Display for PassMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {:?}  transforms={}  visited={}  removed={}  inserted={}",
            self.pass_name,
            self.duration,
            self.transforms,
            self.instrs_visited,
            self.instrs_removed,
            self.instrs_inserted,
        )
    }
}

// ─── PassProfile ─────────────────────────────────────────────────────────────

/// Accumulated statistics across multiple runs of the same pass.
#[derive(Debug, Clone, Default)]
pub struct PassProfile {
    pub pass_name: String,
    pub run_count: u64,
    pub total_duration: Duration,
    pub total_transforms: u64,
    pub total_memory_bytes: u64,
    pub memory_sample_count: u64,
    pub min_duration: Option<Duration>,
    pub max_duration: Option<Duration>,
    pub total_instrs_visited: u64,
    pub total_instrs_removed: u64,
    pub total_instrs_inserted: u64,
}

impl PassProfile {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            pass_name: name.into(),
            ..Default::default()
        }
    }

    /// Ingest one [`PassMetrics`] record.
    pub fn record(&mut self, m: &PassMetrics) {
        self.run_count += 1;
        self.total_duration += m.duration;
        self.total_transforms += u64::from(m.transforms);
        self.total_instrs_visited += m.instrs_visited;
        self.total_instrs_removed += m.instrs_removed;
        self.total_instrs_inserted += m.instrs_inserted;
        if let Some(mem) = m.peak_memory_bytes {
            self.total_memory_bytes += mem as u64;
            self.memory_sample_count += 1;
        }
        self.min_duration = Some(
            self.min_duration
                .map_or(m.duration, |prev| prev.min(m.duration)),
        );
        self.max_duration = Some(
            self.max_duration
                .map_or(m.duration, |prev| prev.max(m.duration)),
        );
    }

    /// Average wall-clock duration per run.
    #[must_use]
    pub fn avg_duration(&self) -> Duration {
        if self.run_count == 0 {
            return Duration::ZERO;
        }
        self.total_duration / u32::try_from(self.run_count).unwrap_or(u32::MAX)
    }

    /// Average peak memory per run (None when no memory samples).
    #[must_use]
    pub const fn avg_memory_bytes(&self) -> Option<u64> {
        if self.memory_sample_count == 0 {
            return None;
        }
        Some(self.total_memory_bytes / self.memory_sample_count)
    }

    /// Average transforms per run.
    #[must_use]
    pub fn avg_transforms(&self) -> f64 {
        if self.run_count == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.total_transforms).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.run_count).unwrap_or(u32::MAX))
    }

    /// Average instructions visited per run.
    #[must_use]
    pub fn avg_instrs_visited(&self) -> f64 {
        if self.run_count == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.total_instrs_visited).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.run_count).unwrap_or(u32::MAX))
    }

    /// Speedup ratio relative to `baseline` (`baseline_avg` / `self_avg`).
    /// Returns 1.0 if either profile has zero average duration.
    #[must_use]
    pub fn speedup_vs(&self, baseline: &Self) -> f64 {
        let mine = self.avg_duration().as_secs_f64();
        let base = baseline.avg_duration().as_secs_f64();
        if mine == 0.0 || base == 0.0 {
            return 1.0;
        }
        base / mine
    }
}

impl fmt::Display for PassProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] runs={} avg={:?} transforms_avg={:.1}",
            self.pass_name,
            self.run_count,
            self.avg_duration(),
            self.avg_transforms(),
        )
    }
}

// ─── MetricsCollector ────────────────────────────────────────────────────────

/// Maximum number of raw run records retained by [`MetricsCollector`].
///
/// Older records beyond this cap are dropped once the tail of `runs` would
/// exceed it, preventing unbounded memory growth when the collector is driven
/// by untrusted input (dos-memory-exhaustion).
pub const MAX_RAW_RUNS: usize = 65_536;

/// Records [`PassMetrics`] for every pass run and aggregates them into profiles.
#[derive(Debug, Default)]
pub struct MetricsCollector {
    /// Raw run records, in insertion order (capped at [`MAX_RAW_RUNS`]).
    pub runs: Vec<PassMetrics>,
    /// Aggregated profiles per pass name.
    pub profiles: HashMap<String, PassProfile>,
    /// Whether to auto-update profiles on each `record` call.
    pub auto_aggregate: bool,
}

impl MetricsCollector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            auto_aggregate: true,
            ..Default::default()
        }
    }

    /// Start timing a pass; returns an in-progress timer.
    #[must_use]
    pub fn start(pass_name: impl Into<String>) -> PassTimer {
        PassTimer {
            name: pass_name.into(),
            started: Instant::now(),
        }
    }

    /// Record a completed metrics object.
    ///
    /// Raw run records are capped at [`MAX_RAW_RUNS`]; records beyond that
    /// limit are silently dropped after aggregation to avoid unbounded memory
    /// growth when driven by untrusted input (dos-memory-exhaustion).
    pub fn record(&mut self, m: PassMetrics) {
        if self.auto_aggregate {
            let profile = self
                .profiles
                .entry(m.pass_name.clone())
                .or_insert_with(|| PassProfile::new(&m.pass_name));
            profile.record(&m);
        }
        if self.runs.len() < MAX_RAW_RUNS {
            self.runs.push(m);
        }
    }

    /// Return all metrics for a named pass.
    #[must_use]
    pub fn runs_for(&self, name: &str) -> Vec<&PassMetrics> {
        self.runs.iter().filter(|m| m.pass_name == name).collect()
    }

    /// Return the profile for a named pass.
    #[must_use]
    pub fn profile_for(&self, name: &str) -> Option<&PassProfile> {
        self.profiles.get(name)
    }

    /// Total number of pass executions recorded.
    #[must_use]
    pub const fn total_runs(&self) -> usize {
        self.runs.len()
    }

    /// Names of all passes that have been recorded.
    #[must_use]
    pub fn pass_names(&self) -> Vec<&str> {
        self.profiles.keys().map(std::string::String::as_str).collect()
    }

    /// Clear all recorded data.
    pub fn clear(&mut self) {
        self.runs.clear();
        self.profiles.clear();
    }

    /// Convenience recorder for callers that only know a pass name and a change
    /// count (analogous to the old `PassProfiler::record` API).
    ///
    /// Internally constructs a [`PassMetrics`] with `transforms` set to
    /// `changes as u32` and zero timing/memory data, then delegates to
    /// [`MetricsCollector::record`].
    pub fn record_pass(&mut self, pass_id: &str, changes: usize) {
        let mut m = PassMetrics::new(pass_id);
        m.transforms = u32::try_from(changes).unwrap_or(u32::MAX);
        self.record(m);
    }

    /// Total transformations across all passes (sum of `profile.total_transforms`).
    #[must_use]
    pub fn total_transforms(&self) -> u64 {
        self.profiles.values().map(|p| p.total_transforms).sum()
    }
}

/// A running timer returned by [`MetricsCollector::start`].
pub struct PassTimer {
    pub name: String,
    started: Instant,
}

impl PassTimer {
    /// Stop the timer and return a [`PassMetrics`] with the elapsed duration.
    #[must_use]
    pub fn stop(self) -> PassMetrics {
        let mut m = PassMetrics::new(self.name);
        m.duration = self.started.elapsed();
        m
    }

    /// Stop and populate `transforms` in one call.
    #[must_use]
    pub fn stop_with(self, transforms: u32) -> PassMetrics {
        let mut m = self.stop();
        m.transforms = transforms;
        m
    }
}

// ─── PassComparison ──────────────────────────────────────────────────────────

/// Side-by-side comparison of two pass profiles.
#[derive(Debug, Clone)]
pub struct PassComparison {
    pub baseline: PassProfile,
    pub candidate: PassProfile,
}

impl PassComparison {
    #[must_use] 
    pub const fn new(baseline: PassProfile, candidate: PassProfile) -> Self {
        Self {
            baseline,
            candidate,
        }
    }

    /// Duration change (candidate − baseline) as a fraction of baseline.
    /// Positive = slower, negative = faster.
    #[must_use]
    pub fn duration_delta_pct(&self) -> f64 {
        let base = self.baseline.avg_duration().as_secs_f64();
        let cand = self.candidate.avg_duration().as_secs_f64();
        if base == 0.0 {
            return 0.0;
        }
        (cand - base) / base * 100.0
    }

    /// Transform count change as a fraction of baseline.
    #[must_use]
    pub fn transforms_delta_pct(&self) -> f64 {
        let base = self.baseline.avg_transforms();
        let cand = self.candidate.avg_transforms();
        if base == 0.0 {
            return 0.0;
        }
        (cand - base) / base * 100.0
    }

    /// True when candidate is faster (lower avg duration) than baseline.
    #[must_use]
    pub fn is_faster(&self) -> bool {
        self.candidate.avg_duration() < self.baseline.avg_duration()
    }

    /// True when candidate applies more transformations (≥1% more) per run.
    #[must_use]
    pub fn is_more_effective(&self) -> bool {
        self.transforms_delta_pct() >= 1.0
    }
}

impl fmt::Display for PassComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Compare {} vs {}: Δdur={:.1}%  Δxforms={:.1}%",
            self.candidate.pass_name,
            self.baseline.pass_name,
            self.duration_delta_pct(),
            self.transforms_delta_pct(),
        )
    }
}

// ─── RegressionDetector ──────────────────────────────────────────────────────

/// Detects performance regressions relative to a baseline.
///
/// Flags a regression when the candidate's average duration exceeds the
/// baseline by more than `threshold_pct` percent.
#[derive(Debug, Clone)]
pub struct RegressionDetector {
    /// Regression threshold as a percentage (e.g. `10.0` = 10 % slower).
    pub threshold_pct: f64,
    /// Detected regressions since the last `check` call.
    pub regressions: Vec<String>,
}

impl RegressionDetector {
    #[must_use]
    pub const fn new(threshold_pct: f64) -> Self {
        Self {
            threshold_pct,
            regressions: Vec::new(),
        }
    }

    /// Check `comparison` for a regression.  Returns `true` when one is found.
    pub fn check(&mut self, comparison: &PassComparison) -> bool {
        let delta = comparison.duration_delta_pct();
        if delta > self.threshold_pct {
            self.regressions.push(format!(
                "{}: {:.1}% slower than baseline (threshold {:.1}%)",
                comparison.candidate.pass_name, delta, self.threshold_pct,
            ));
            return true;
        }
        false
    }

    /// True when any regression was detected in the last batch of `check` calls.
    #[must_use]
    pub const fn has_regressions(&self) -> bool {
        !self.regressions.is_empty()
    }

    /// Clear all recorded regressions.
    pub fn clear(&mut self) {
        self.regressions.clear();
    }
}

// ─── MetricsDashboard ────────────────────────────────────────────────────────

/// Renders a human-readable summary of all profiles in a collector.
#[derive(Debug, Default)]
pub struct MetricsDashboard;

impl MetricsDashboard {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Render a text table summarising all profiles in `collector`.
    #[must_use]
    pub fn render(&self, collector: &MetricsCollector) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "{:<30} {:>8} {:>12} {:>12} {:>12}",
            "Pass", "Runs", "Avg Duration", "Avg Xforms", "Avg Visited"
        ));
        lines.push("-".repeat(80));

        let mut names: Vec<&str> = collector.pass_names();
        names.sort_unstable();
        for name in names {
            if let Some(p) = collector.profile_for(name) {
                lines.push(format!(
                    "{:<30} {:>8} {:>12} {:>12.1} {:>12.0}",
                    p.pass_name,
                    p.run_count,
                    format!("{:?}", p.avg_duration()),
                    p.avg_transforms(),
                    p.avg_instrs_visited(),
                ));
            }
        }
        lines.join("\n")
    }

    /// Render only the top-N slowest passes by average duration.
    #[must_use]
    pub fn render_top_n_slowest(&self, collector: &MetricsCollector, n: usize) -> String {
        let mut profiles: Vec<&PassProfile> = collector.profiles.values().collect();
        profiles.sort_by_key(|b| std::cmp::Reverse(b.avg_duration()));
        let mut lines = vec![format!("Top-{n} slowest passes:")];
        for p in profiles.iter().take(n) {
            lines.push(format!("  {:?}  {}", p.avg_duration(), p.pass_name));
        }
        lines.join("\n")
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_metrics(name: &str, dur_ms: u64, transforms: u32) -> PassMetrics {
        let mut m = PassMetrics::new(name);
        m.duration = Duration::from_millis(dur_ms);
        m.transforms = transforms;
        m
    }

    // PassMetrics tests ────────────────────────────────────────────────────

    #[test]
    fn metrics_new_zero() {
        let m = PassMetrics::new("test");
        assert_eq!(m.transforms, 0);
        assert_eq!(m.duration, Duration::ZERO);
        assert!(m.is_noop());
    }

    #[test]
    fn metrics_counter_increment() {
        let mut m = PassMetrics::new("p");
        m.inc_counter("folds");
        m.inc_counter("folds");
        assert_eq!(m.counter("folds"), 2);
    }

    #[test]
    fn metrics_counter_set() {
        let mut m = PassMetrics::new("p");
        m.set_counter("dead", 10);
        assert_eq!(m.counter("dead"), 10);
    }

    #[test]
    fn metrics_missing_counter_zero() {
        let m = PassMetrics::new("p");
        assert_eq!(m.counter("nonexistent"), 0);
    }

    #[test]
    fn metrics_is_noop_when_no_transforms() {
        let m = make_metrics("p", 10, 0);
        assert!(m.is_noop());
    }

    #[test]
    fn metrics_not_noop_when_transforms() {
        let m = make_metrics("p", 10, 5);
        assert!(!m.is_noop());
    }

    #[test]
    fn metrics_throughput_zero_duration() {
        let m = make_metrics("p", 0, 0);
        assert_eq!(m.throughput_ips(), 0.0);
    }

    #[test]
    fn metrics_throughput_positive() {
        let mut m = make_metrics("p", 1000, 0);
        m.instrs_visited = 1000;
        let tp = m.throughput_ips();
        assert!(tp > 0.0);
    }

    #[test]
    fn metrics_display() {
        let m = make_metrics("fold", 5, 3);
        let s = m.to_string();
        assert!(s.contains("fold"));
        assert!(s.contains("transforms=3"));
    }

    // PassProfile tests ────────────────────────────────────────────────────

    #[test]
    fn profile_record_run_count() {
        let mut p = PassProfile::new("fold");
        p.record(&make_metrics("fold", 10, 5));
        p.record(&make_metrics("fold", 20, 3));
        assert_eq!(p.run_count, 2);
    }

    #[test]
    fn profile_avg_duration() {
        let mut p = PassProfile::new("fold");
        p.record(&make_metrics("fold", 10, 0));
        p.record(&make_metrics("fold", 30, 0));
        assert_eq!(p.avg_duration(), Duration::from_millis(20));
    }

    #[test]
    fn profile_min_max_duration() {
        let mut p = PassProfile::new("fold");
        p.record(&make_metrics("fold", 5, 0));
        p.record(&make_metrics("fold", 50, 0));
        assert_eq!(p.min_duration, Some(Duration::from_millis(5)));
        assert_eq!(p.max_duration, Some(Duration::from_millis(50)));
    }

    #[test]
    fn profile_avg_transforms() {
        let mut p = PassProfile::new("p");
        p.record(&make_metrics("p", 10, 10));
        p.record(&make_metrics("p", 10, 20));
        assert!((p.avg_transforms() - 15.0).abs() < 0.01);
    }

    #[test]
    fn profile_no_memory_samples() {
        let mut p = PassProfile::new("p");
        p.record(&make_metrics("p", 10, 0));
        assert!(p.avg_memory_bytes().is_none());
    }

    #[test]
    fn profile_with_memory_samples() {
        let mut p = PassProfile::new("p");
        let mut m = make_metrics("p", 10, 0);
        m.peak_memory_bytes = Some(1024);
        p.record(&m);
        assert_eq!(p.avg_memory_bytes(), Some(1024));
    }

    #[test]
    fn profile_speedup_vs() {
        let mut base = PassProfile::new("base");
        base.record(&make_metrics("base", 100, 0));
        let mut cand = PassProfile::new("cand");
        cand.record(&make_metrics("cand", 50, 0));
        let speedup = cand.speedup_vs(&base);
        assert!((speedup - 2.0).abs() < 0.01);
    }

    // MetricsCollector tests ────────────────────────────────────────────────

    #[test]
    fn collector_record_and_retrieve() {
        let mut col = MetricsCollector::new();
        col.record(make_metrics("fold", 10, 5));
        assert_eq!(col.total_runs(), 1);
        assert_eq!(col.runs_for("fold").len(), 1);
    }

    #[test]
    fn collector_profile_aggregates() {
        let mut col = MetricsCollector::new();
        col.record(make_metrics("fold", 10, 5));
        col.record(make_metrics("fold", 20, 3));
        let p = col.profile_for("fold").unwrap();
        assert_eq!(p.run_count, 2);
    }

    #[test]
    fn collector_pass_names() {
        let mut col = MetricsCollector::new();
        col.record(make_metrics("a", 1, 0));
        col.record(make_metrics("b", 1, 0));
        let names = col.pass_names();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
    }

    #[test]
    fn collector_clear() {
        let mut col = MetricsCollector::new();
        col.record(make_metrics("fold", 10, 5));
        col.clear();
        assert_eq!(col.total_runs(), 0);
        assert!(col.profile_for("fold").is_none());
    }

    #[test]
    fn collector_timer_roundtrip() {
        let timer = MetricsCollector::start("test-pass");
        let m = timer.stop_with(7);
        assert_eq!(m.pass_name, "test-pass");
        assert_eq!(m.transforms, 7);
        assert!(m.duration >= Duration::ZERO);
    }

    // PassComparison tests ──────────────────────────────────────────────────

    #[test]
    fn comparison_faster() {
        let mut base = PassProfile::new("base");
        base.record(&make_metrics("base", 100, 0));
        let mut cand = PassProfile::new("cand");
        cand.record(&make_metrics("cand", 50, 0));
        let cmp = PassComparison::new(base, cand);
        assert!(cmp.is_faster());
    }

    #[test]
    fn comparison_delta_pct() {
        let mut base = PassProfile::new("b");
        base.record(&make_metrics("b", 100, 10));
        let mut cand = PassProfile::new("c");
        cand.record(&make_metrics("c", 110, 10));
        let cmp = PassComparison::new(base, cand);
        assert!((cmp.duration_delta_pct() - 10.0).abs() < 0.1);
    }

    #[test]
    fn comparison_more_effective() {
        let mut base = PassProfile::new("b");
        base.record(&make_metrics("b", 10, 10));
        let mut cand = PassProfile::new("c");
        cand.record(&make_metrics("c", 10, 11));
        let cmp = PassComparison::new(base, cand);
        assert!(cmp.is_more_effective());
    }

    // RegressionDetector tests ──────────────────────────────────────────────

    #[test]
    fn regression_none_when_same() {
        let mut det = RegressionDetector::new(10.0);
        let mut base = PassProfile::new("b");
        base.record(&make_metrics("b", 100, 0));
        let mut cand = PassProfile::new("c");
        cand.record(&make_metrics("c", 100, 0));
        let cmp = PassComparison::new(base, cand);
        assert!(!det.check(&cmp));
        assert!(!det.has_regressions());
    }

    #[test]
    fn regression_detected_when_over_threshold() {
        let mut det = RegressionDetector::new(5.0);
        let mut base = PassProfile::new("b");
        base.record(&make_metrics("b", 100, 0));
        let mut cand = PassProfile::new("c");
        cand.record(&make_metrics("c", 120, 0));
        let cmp = PassComparison::new(base, cand);
        assert!(det.check(&cmp));
        assert!(det.has_regressions());
    }

    #[test]
    fn regression_clear() {
        let mut det = RegressionDetector::new(5.0);
        let mut base = PassProfile::new("b");
        base.record(&make_metrics("b", 100, 0));
        let mut cand = PassProfile::new("c");
        cand.record(&make_metrics("c", 200, 0));
        let cmp = PassComparison::new(base, cand);
        det.check(&cmp);
        det.clear();
        assert!(!det.has_regressions());
    }

    // MetricsDashboard tests ────────────────────────────────────────────────

    #[test]
    fn dashboard_renders_non_empty() {
        let mut col = MetricsCollector::new();
        col.record(make_metrics("fold", 10, 5));
        let dash = MetricsDashboard::new();
        let output = dash.render(&col);
        assert!(output.contains("fold"));
    }

    #[test]
    fn dashboard_top_n_slowest_empty() {
        let col = MetricsCollector::new();
        let dash = MetricsDashboard::new();
        let output = dash.render_top_n_slowest(&col, 3);
        assert!(output.contains("Top-3"));
    }

    #[test]
    fn dashboard_top_n_slowest_ordering() {
        let mut col = MetricsCollector::new();
        col.record(make_metrics("fast", 1, 0));
        col.record(make_metrics("slow", 1000, 0));
        let dash = MetricsDashboard::new();
        let output = dash.render_top_n_slowest(&col, 1);
        assert!(output.contains("slow"));
    }

    #[test]
    fn metrics_instrs_removed_tracked() {
        let mut m = PassMetrics::new("p");
        m.instrs_removed = 5;
        assert!(!m.is_noop());
    }

    #[test]
    fn metrics_instrs_inserted_tracked() {
        let mut m = PassMetrics::new("p");
        m.instrs_inserted = 2;
        assert!(!m.is_noop());
    }

    #[test]
    fn profile_total_instrs_visited_accumulates() {
        let mut p = PassProfile::new("x");
        let mut m = make_metrics("x", 1, 0);
        m.instrs_visited = 100;
        p.record(&m);
        assert_eq!(p.total_instrs_visited, 100);
    }

    #[test]
    fn collector_no_auto_aggregate() {
        let mut col = MetricsCollector::new();
        col.auto_aggregate = false;
        col.record(make_metrics("p", 1, 0));
        assert!(col.profile_for("p").is_none());
        assert_eq!(col.runs.len(), 1);
    }

    #[test]
    fn comparison_not_more_effective_when_same() {
        let mut base = PassProfile::new("b");
        base.record(&make_metrics("b", 10, 10));
        let mut cand = PassProfile::new("c");
        cand.record(&make_metrics("c", 10, 10));
        let cmp = PassComparison::new(base, cand);
        assert!(!cmp.is_more_effective());
    }

    #[test]
    fn regression_not_detected_when_faster() {
        let mut det = RegressionDetector::new(10.0);
        let mut base = PassProfile::new("b");
        base.record(&make_metrics("b", 100, 0));
        let mut cand = PassProfile::new("c");
        cand.record(&make_metrics("c", 50, 0));
        let cmp = PassComparison::new(base, cand);
        assert!(!det.check(&cmp));
    }

    #[test]
    fn profile_avg_instrs_visited_zero_when_empty() {
        let p = PassProfile::new("x");
        assert_eq!(p.avg_instrs_visited(), 0.0);
    }

    #[test]
    fn dashboard_render_empty_collector() {
        let col = MetricsCollector::new();
        let dash = MetricsDashboard::new();
        let output = dash.render(&col);
        assert!(output.contains("Pass"));
    }
}
