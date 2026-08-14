//! `analysis_metrics` — per-pass timing, coverage statistics, and aggregated metrics reports.
//!
//! This module tracks how long each analysis pass takes, how much of the binary
//! was covered, and produces a [`MetricsReport`] that can be used for performance
//! tuning, regression detection, and user-facing progress displays.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Convert a `f64` value in `[0.0, 255.0]` to a `u8` without any clippy-flagged casts.
///
/// Values below 0.0 clamp to 0; values above 255.0 clamp to 255.
fn f64_to_u8_clamped(v: f64) -> u8 {
    let clamped = v.clamp(0.0, f64::from(u8::MAX));
    // Lint-free: compare u8 values losslessly promoted to f64.
    let mut result: u8 = 0;
    for i in 1u8..=u8::MAX {
        if f64::from(i) <= clamped {
            result = i;
        } else {
            break;
        }
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// PassTiming
// ─────────────────────────────────────────────────────────────────────────────

/// Wall-clock timing sample for a single execution of one analysis pass.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PassTiming {
    /// Unique name of the pass.
    pub pass_name: String,
    /// When the pass started (serialised as milliseconds since Unix epoch).
    pub started_at_ms: u64,
    /// Wall-clock elapsed time for this execution.
    pub elapsed_ms: u64,
    /// Whether the pass completed successfully.
    pub succeeded: bool,
    /// Optional error message if `succeeded` is `false`.
    pub error: Option<String>,
    /// Number of functions processed (pass-specific semantics).
    pub items_processed: usize,
}

impl PassTiming {
    /// Create a successful timing record.
    #[must_use]
    pub fn success(
        pass_name: impl Into<String>,
        started_at_ms: u64,
        elapsed_ms: u64,
        items_processed: usize,
    ) -> Self {
        Self {
            pass_name: pass_name.into(),
            started_at_ms,
            elapsed_ms,
            succeeded: true,
            error: None,
            items_processed,
        }
    }

    /// Create a failure timing record.
    #[must_use]
    pub fn failure(
        pass_name: impl Into<String>,
        started_at_ms: u64,
        elapsed_ms: u64,
        error: impl Into<String>,
    ) -> Self {
        Self {
            pass_name: pass_name.into(),
            started_at_ms,
            elapsed_ms,
            succeeded: false,
            error: Some(error.into()),
            items_processed: 0,
        }
    }

    /// Throughput: items per second (0.0 if elapsed is zero).
    #[must_use]
    pub fn throughput(&self) -> f64 {
        if self.elapsed_ms == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.items_processed).unwrap_or(u32::MAX))
            / (f64::from(u32::try_from(self.elapsed_ms).unwrap_or(u32::MAX)) / 1_000.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CoverageStats
// ─────────────────────────────────────────────────────────────────────────────

/// Coverage statistics for one analysis pass over a binary region.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CoverageStats {
    /// Total bytes in the region under analysis.
    pub total_bytes: u64,
    /// Bytes that were successfully disassembled / decoded.
    pub decoded_bytes: u64,
    /// Number of functions identified.
    pub functions_identified: usize,
    /// Number of basic blocks identified.
    pub basic_blocks_identified: usize,
    /// Number of instructions decoded.
    pub instructions_decoded: usize,
    /// Number of strings found.
    pub strings_found: usize,
    /// Number of data cross-references found.
    pub xrefs_found: usize,
}

impl CoverageStats {
    /// Create a new zeroed `CoverageStats` for a region of `total_bytes`.
    #[must_use]
    pub const fn new(total_bytes: u64) -> Self {
        Self {
            total_bytes,
            decoded_bytes: 0,
            functions_identified: 0,
            basic_blocks_identified: 0,
            instructions_decoded: 0,
            strings_found: 0,
            xrefs_found: 0,
        }
    }

    /// Fraction of bytes decoded (0.0–1.0).  Returns 0.0 if `total_bytes` is 0.
    #[must_use]
    pub fn byte_coverage_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.decoded_bytes).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total_bytes).unwrap_or(u32::MAX))
    }

    /// Byte coverage as a percentage (0.0–100.0).
    #[must_use]
    pub fn byte_coverage_pct(&self) -> f64 {
        self.byte_coverage_ratio() * 100.0
    }

    /// Average instruction size in bytes.  Returns 0.0 if no instructions were decoded.
    #[must_use]
    pub fn avg_instruction_bytes(&self) -> f64 {
        if self.instructions_decoded == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.decoded_bytes).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.instructions_decoded).unwrap_or(u32::MAX))
    }

    /// Average basic-block size in instructions.  Returns 0.0 if no basic blocks.
    #[must_use]
    pub fn avg_block_instructions(&self) -> f64 {
        if self.basic_blocks_identified == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.instructions_decoded).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.basic_blocks_identified).unwrap_or(u32::MAX))
    }

    /// Merge another `CoverageStats` into this one (additive).
    pub const fn merge(&mut self, other: &Self) {
        self.total_bytes += other.total_bytes;
        self.decoded_bytes += other.decoded_bytes;
        self.functions_identified += other.functions_identified;
        self.basic_blocks_identified += other.basic_blocks_identified;
        self.instructions_decoded += other.instructions_decoded;
        self.strings_found += other.strings_found;
        self.xrefs_found += other.xrefs_found;
    }

    /// Record that `n` bytes were decoded.
    pub const fn record_decoded_bytes(&mut self, n: u64) {
        self.decoded_bytes += n;
    }

    /// Record one decoded instruction of `size` bytes.
    pub const fn record_instruction(&mut self, size: u64) {
        self.instructions_decoded += 1;
        self.decoded_bytes += size;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassMetricsEntry
// ─────────────────────────────────────────────────────────────────────────────

/// Combined timing + coverage data for a single pass execution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PassMetricsEntry {
    /// Timing for this pass run.
    pub timing: PassTiming,
    /// Coverage statistics for this pass run.
    pub coverage: CoverageStats,
    /// Arbitrary key/value annotations from the pass itself.
    pub annotations: HashMap<String, String>,
}

impl PassMetricsEntry {
    /// Create a new entry from timing and coverage data.
    #[must_use]
    pub fn new(timing: PassTiming, coverage: CoverageStats) -> Self {
        Self {
            timing,
            coverage,
            annotations: HashMap::new(),
        }
    }

    /// Attach an annotation.
    pub fn annotate(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.annotations.insert(key.into(), value.into());
    }

    /// Retrieve an annotation value.
    #[must_use]
    pub fn annotation(&self, key: &str) -> Option<&str> {
        self.annotations.get(key).map(String::as_str)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MetricsReport
// ─────────────────────────────────────────────────────────────────────────────

/// An aggregated metrics report covering all passes in an analysis run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricsReport {
    /// URI of the binary that was analysed.
    pub binary_uri: String,
    /// Per-pass entries, ordered by pass execution sequence.
    pub entries: Vec<PassMetricsEntry>,
    /// Aggregate coverage across all passes.
    pub aggregate_coverage: CoverageStats,
    /// Total wall-clock time across all passes (sum of `elapsed_ms`).
    pub total_elapsed_ms: u64,
    /// Number of passes that succeeded.
    pub succeeded_count: usize,
    /// Number of passes that failed.
    pub failed_count: usize,
}

impl MetricsReport {
    /// Create an empty report for the given binary URI.
    #[must_use]
    pub fn new(binary_uri: impl Into<String>) -> Self {
        Self {
            binary_uri: binary_uri.into(),
            entries: Vec::new(),
            aggregate_coverage: CoverageStats::default(),
            total_elapsed_ms: 0,
            succeeded_count: 0,
            failed_count: 0,
        }
    }

    /// Append a pass entry, updating aggregate totals.
    pub fn push(&mut self, entry: PassMetricsEntry) {
        self.total_elapsed_ms += entry.timing.elapsed_ms;
        if entry.timing.succeeded {
            self.succeeded_count += 1;
        } else {
            self.failed_count += 1;
        }
        self.aggregate_coverage.merge(&entry.coverage);
        self.entries.push(entry);
    }

    /// Overall pass count (succeeded + failed).
    #[must_use]
    pub const fn total_passes(&self) -> usize {
        self.entries.len()
    }

    /// Pass success rate (0.0–1.0).
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.total_passes();
        if total == 0 {
            return 1.0;
        }
        f64::from(u32::try_from(self.succeeded_count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }

    /// Return the slowest pass entry, or `None` if no passes were recorded.
    #[must_use]
    pub fn slowest_pass(&self) -> Option<&PassMetricsEntry> {
        self.entries
            .iter()
            .max_by_key(|e| e.timing.elapsed_ms)
    }

    /// Return the fastest pass entry, or `None` if no passes were recorded.
    #[must_use]
    pub fn fastest_pass(&self) -> Option<&PassMetricsEntry> {
        self.entries
            .iter()
            .min_by_key(|e| e.timing.elapsed_ms)
    }

    /// Average elapsed time per pass in milliseconds.
    #[must_use]
    pub fn avg_pass_elapsed_ms(&self) -> f64 {
        let n = self.entries.len();
        if n == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.total_elapsed_ms).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// Find a pass entry by name.
    #[must_use]
    pub fn find_pass(&self, name: &str) -> Option<&PassMetricsEntry> {
        self.entries.iter().find(|e| e.timing.pass_name == name)
    }

    /// Passes sorted by elapsed time descending (slowest first).
    #[must_use]
    pub fn passes_by_time_desc(&self) -> Vec<&PassMetricsEntry> {
        let mut v: Vec<&PassMetricsEntry> = self.entries.iter().collect();
        v.sort_unstable_by(|a, b| b.timing.elapsed_ms.cmp(&a.timing.elapsed_ms));
        v
    }

    /// Passes that failed.
    #[must_use]
    pub fn failed_passes(&self) -> Vec<&PassMetricsEntry> {
        self.entries
            .iter()
            .filter(|e| !e.timing.succeeded)
            .collect()
    }

    /// Produce a human-readable summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "MetricsReport[{}]: {} passes ({} ok, {} fail), {}ms total, {:.1}% coverage",
            self.binary_uri,
            self.total_passes(),
            self.succeeded_count,
            self.failed_count,
            self.total_elapsed_ms,
            self.aggregate_coverage.byte_coverage_pct(),
        )
    }

    /// Serialise the report to pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] if serialisation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisMetrics — live metrics collector
// ─────────────────────────────────────────────────────────────────────────────

/// Milliseconds since Unix epoch (monotone-ish; uses `std::time`).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis().try_into().unwrap_or(u64::MAX)
}

/// In-progress timing guard returned by [`AnalysisMetrics::begin_pass`].
///
/// Drop this (or call [`PassGuard::finish`]) to record the elapsed time.
pub struct PassGuard<'a> {
    metrics: &'a AnalysisMetrics,
    pass_name: String,
    started_at_ms: u64,
    start: Instant,
}

impl PassGuard<'_> {
    /// Finish the pass recording with a success outcome and item count.
    ///
    /// Returns the [`PassMetricsEntry`] that was recorded.
    #[must_use] 
    pub fn finish(self, items_processed: usize) -> PassMetricsEntry {
        let elapsed_ms = self.start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        let timing = PassTiming::success(
            &self.pass_name,
            self.started_at_ms,
            elapsed_ms,
            items_processed,
        );
        let entry = PassMetricsEntry::new(timing, CoverageStats::default());
        self.metrics.record(entry.clone());
        entry
    }

    /// Finish the pass recording with a failure outcome.
    ///
    /// Returns the [`PassMetricsEntry`] that was recorded.
    pub fn finish_err(self, error: impl Into<String>) -> PassMetricsEntry {
        let elapsed_ms = self.start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        let timing = PassTiming::failure(
            &self.pass_name,
            self.started_at_ms,
            elapsed_ms,
            error,
        );
        let entry = PassMetricsEntry::new(timing, CoverageStats::default());
        self.metrics.record(entry.clone());
        entry
    }

    /// Finish the pass with full timing + coverage data.
    #[must_use] 
    pub fn finish_with_coverage(
        self,
        items_processed: usize,
        coverage: CoverageStats,
    ) -> PassMetricsEntry {
        let elapsed_ms = self.start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        let timing = PassTiming::success(
            &self.pass_name,
            self.started_at_ms,
            elapsed_ms,
            items_processed,
        );
        let entry = PassMetricsEntry::new(timing, coverage);
        self.metrics.record(entry.clone());
        entry
    }
}

// Drop without calling finish => record as failure with zero elapsed.
impl Drop for PassGuard<'_> {
    fn drop(&mut self) {
        // Only record if the guard was not already consumed by finish/finish_err.
        // We detect this by checking whether this pass name already has an entry
        // recorded at this exact start time.
        let already = self.metrics.entries.read().iter().any(|e| {
            e.timing.pass_name == self.pass_name
                && e.timing.started_at_ms == self.started_at_ms
        });
        if !already {
            let elapsed_ms = self.start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
            let timing = PassTiming::failure(
                &self.pass_name,
                self.started_at_ms,
                elapsed_ms,
                "PassGuard dropped without explicit finish",
            );
            self.metrics
                .record(PassMetricsEntry::new(timing, CoverageStats::default()));
        }
    }
}

/// Thread-safe live metrics collector for an analysis run.
///
/// Collect metrics with [`begin_pass`](Self::begin_pass) / [`PassGuard`], or
/// record pre-built entries with [`record`](Self::record).  Build the final
/// [`MetricsReport`] with [`build_report`](Self::build_report).
pub struct AnalysisMetrics {
    binary_uri: String,
    entries: parking_lot::RwLock<Vec<PassMetricsEntry>>,
}

impl AnalysisMetrics {
    /// Create a new metrics collector for the given binary URI.
    #[must_use]
    pub fn new(binary_uri: impl Into<String>) -> Self {
        Self {
            binary_uri: binary_uri.into(),
            entries: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Begin timing a pass.  Returns a [`PassGuard`] that records elapsed time
    /// when dropped or when its `finish*` methods are called.
    pub fn begin_pass(&self, pass_name: impl Into<String>) -> PassGuard<'_> {
        PassGuard {
            metrics: self,
            pass_name: pass_name.into(),
            started_at_ms: now_ms(),
            start: Instant::now(),
        }
    }

    /// Directly record a pre-built [`PassMetricsEntry`].
    pub fn record(&self, entry: PassMetricsEntry) {
        self.entries.write().push(entry);
    }

    /// Record a pass result from raw timing values.
    pub fn record_raw(
        &self,
        pass_name: impl Into<String>,
        elapsed_ms: u64,
        items: usize,
        succeeded: bool,
        error: Option<String>,
    ) {
        let timing = if succeeded {
            PassTiming::success(pass_name, now_ms(), elapsed_ms, items)
        } else {
            PassTiming::failure(
                pass_name,
                now_ms(),
                elapsed_ms,
                error.unwrap_or_else(|| "unknown".into()),
            )
        };
        self.record(PassMetricsEntry::new(timing, CoverageStats::default()));
    }

    /// Build the final [`MetricsReport`] from all recorded entries.
    #[must_use]
    pub fn build_report(&self) -> MetricsReport {
        let mut report = MetricsReport::new(&self.binary_uri);
        for entry in self.entries.read().iter() {
            report.push(entry.clone());
        }
        report
    }

    /// Number of entries recorded so far.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.read().len()
    }

    /// Return all entries as a snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Vec<PassMetricsEntry> {
        self.entries.read().clone()
    }

    /// Clear all recorded entries.
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Total elapsed milliseconds across all recorded entries.
    #[must_use]
    pub fn total_elapsed_ms(&self) -> u64 {
        self.entries.read().iter().map(|e| e.timing.elapsed_ms).sum()
    }
}

impl std::fmt::Debug for AnalysisMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisMetrics")
            .field("binary_uri", &self.binary_uri)
            .field("entry_count", &self.entry_count())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// score_function — convenience scoring helper
// ─────────────────────────────────────────────────────────────────────────────

/// A simple numeric score (0–100) summarising how well a pass performed over a
/// function-sized region.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FunctionScore {
    /// Address of the function start.
    pub address: u64,
    /// Score 0–100.
    pub score: u8,
    /// Coverage fraction 0.0–1.0.
    pub coverage: f64,
}

impl FunctionScore {
    /// Compute a score from coverage and elapsed time relative to a budget.
    ///
    /// * `coverage` — fraction 0.0–1.0 of bytes decoded.
    /// * `elapsed_ms` — how long the pass took for this function.
    /// * `budget_ms` — the acceptable time budget.  Exceeding it penalises the score.
    #[must_use]
    pub fn compute(address: u64, coverage: f64, elapsed_ms: u64, budget_ms: u64) -> Self {
        let coverage = coverage.clamp(0.0, 1.0);
        let time_factor = if budget_ms == 0 {
            1.0_f64
        } else {
            (f64::from(u32::try_from(budget_ms).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(elapsed_ms.max(1)).unwrap_or(u32::MAX)))
            .min(1.0)
        };
        let raw = f64_to_u8_clamped((coverage * 70.0 + time_factor * 30.0).round());
        Self {
            address,
            score: raw.min(100),
            coverage,
        }
    }

    /// Whether this function achieved a passing score (>= 60).
    #[must_use]
    pub const fn is_passing(&self) -> bool {
        self.score >= 60
    }
}

/// Score a collection of pass timings per function address.
///
/// Returns one [`FunctionScore`] per entry in `timings`, using `budget_ms` as the
/// per-function time budget and deriving coverage from `CoverageStats` attached
/// to each entry.
#[must_use]
pub fn score_function(timings: &[PassMetricsEntry], budget_ms: u64) -> Vec<FunctionScore> {
    timings
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let address = i as u64 * 0x10; // synthetic address when none is embedded
            FunctionScore::compute(
                address,
                entry.coverage.byte_coverage_ratio(),
                entry.timing.elapsed_ms,
                budget_ms,
            )
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// MetricsAggregator — multi-binary roll-up
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregates [`MetricsReport`]s from multiple binary analysis runs into a
/// single roll-up view.
#[derive(Debug, Default)]
pub struct MetricsAggregator {
    reports: Vec<MetricsReport>,
}

impl MetricsAggregator {
    /// Create an empty aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a report to the aggregator.
    pub fn push(&mut self, report: MetricsReport) {
        self.reports.push(report);
    }

    /// Total number of reports ingested.
    #[must_use]
    pub const fn report_count(&self) -> usize {
        self.reports.len()
    }

    /// Total passes across all reports.
    #[must_use]
    pub fn total_passes(&self) -> usize {
        self.reports.iter().map(MetricsReport::total_passes).sum()
    }

    /// Total wall-clock time across all reports.
    #[must_use]
    pub fn total_elapsed_ms(&self) -> u64 {
        self.reports.iter().map(|r| r.total_elapsed_ms).sum()
    }

    /// Global success rate across all passes.
    #[must_use]
    pub fn global_success_rate(&self) -> f64 {
        let total = self.total_passes();
        if total == 0 {
            return 1.0;
        }
        let succeeded: usize = self.reports.iter().map(|r| r.succeeded_count).sum();
        f64::from(u32::try_from(succeeded).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }

    /// Aggregate coverage across all reports.
    #[must_use]
    pub fn aggregate_coverage(&self) -> CoverageStats {
        let mut combined = CoverageStats::default();
        for report in &self.reports {
            combined.merge(&report.aggregate_coverage);
        }
        combined
    }

    /// Pass name histogram: how many times each pass name appears across all reports.
    #[must_use]
    pub fn pass_name_histogram(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for report in &self.reports {
            for entry in &report.entries {
                *map.entry(entry.timing.pass_name.clone()).or_insert(0) += 1;
            }
        }
        map
    }

    /// Average elapsed milliseconds per named pass across all reports.
    #[must_use]
    pub fn avg_elapsed_per_pass(&self) -> HashMap<String, f64> {
        let mut totals: HashMap<String, u64> = HashMap::new();
        let mut counts: HashMap<String, usize> = HashMap::new();
        for report in &self.reports {
            for entry in &report.entries {
                *totals
                    .entry(entry.timing.pass_name.clone())
                    .or_insert(0) += entry.timing.elapsed_ms;
                *counts
                    .entry(entry.timing.pass_name.clone())
                    .or_insert(0) += 1;
            }
        }
        totals
            .into_iter()
            .map(|(name, total)| {
                let count = counts.get(&name).copied().unwrap_or(1);
                (name, f64::from(u32::try_from(total).unwrap_or(u32::MAX))
                    / f64::from(u32::try_from(count).unwrap_or(u32::MAX)))
            })
            .collect()
    }

    /// Reports sorted by total elapsed time descending.
    #[must_use]
    pub fn reports_by_time_desc(&self) -> Vec<&MetricsReport> {
        let mut v: Vec<&MetricsReport> = self.reports.iter().collect();
        v.sort_unstable_by(|a, b| b.total_elapsed_ms.cmp(&a.total_elapsed_ms));
        v
    }

    /// Find the binary URI with the highest total elapsed time.
    #[must_use]
    pub fn slowest_binary(&self) -> Option<&str> {
        self.reports
            .iter()
            .max_by_key(|r| r.total_elapsed_ms)
            .map(|r| r.binary_uri.as_str())
    }

    /// Produce a roll-up summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "MetricsAggregator: {} binaries, {} passes, {:.1}% success, {}ms total, {:.1}% coverage",
            self.report_count(),
            self.total_passes(),
            self.global_success_rate() * 100.0,
            self.total_elapsed_ms(),
            self.aggregate_coverage().byte_coverage_pct(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Regression detection
// ─────────────────────────────────────────────────────────────────────────────

/// Threshold configuration for regression detection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegressionThresholds {
    /// Maximum acceptable elapsed-time regression factor (e.g. 1.5 = 50% slower is a regression).
    pub max_time_regression_factor: f64,
    /// Minimum acceptable coverage delta (e.g. -0.02 means a 2% drop is a regression).
    pub min_coverage_delta: f64,
    /// Minimum acceptable success-rate delta (e.g. -0.05 = 5% fewer passes succeeding).
    pub min_success_rate_delta: f64,
}

impl Default for RegressionThresholds {
    fn default() -> Self {
        Self {
            max_time_regression_factor: 1.5,
            min_coverage_delta: -0.02,
            min_success_rate_delta: -0.05,
        }
    }
}

/// One detected regression.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Regression {
    /// Kind of regression.
    pub kind: RegressionKind,
    /// Human-readable description.
    pub description: String,
    /// Severity 0–100.
    pub severity: u8,
}

/// The kind of regression detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RegressionKind {
    /// A pass became significantly slower.
    TimeSlow,
    /// Code coverage dropped.
    CoverageDown,
    /// Pass success rate dropped.
    SuccessRateDown,
}

/// Compare a `baseline` report to a `current` report and detect regressions.
///
/// Returns a (possibly empty) list of [`Regression`]s.
#[must_use]
pub fn detect_regressions(
    baseline: &MetricsReport,
    current: &MetricsReport,
    thresholds: &RegressionThresholds,
) -> Vec<Regression> {
    let mut regressions = Vec::new();

    // Time regression: current total time > baseline * factor.
    if baseline.total_elapsed_ms > 0 {
        let factor = f64::from(u32::try_from(current.total_elapsed_ms).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(baseline.total_elapsed_ms).unwrap_or(u32::MAX));
        if factor > thresholds.max_time_regression_factor {
            regressions.push(Regression {
                kind: RegressionKind::TimeSlow,
                description: format!(
                    "Total elapsed time increased by {:.1}x (baseline {}ms, current {}ms)",
                    factor, baseline.total_elapsed_ms, current.total_elapsed_ms
                ),
                severity: f64_to_u8_clamped(((factor - 1.0) * 50.0).min(100.0)),
            });
        }
    }

    // Coverage regression.
    let baseline_cov = baseline.aggregate_coverage.byte_coverage_ratio();
    let current_cov = current.aggregate_coverage.byte_coverage_ratio();
    let cov_delta = current_cov - baseline_cov;
    if cov_delta < thresholds.min_coverage_delta {
        regressions.push(Regression {
            kind: RegressionKind::CoverageDown,
            description: format!(
                "Coverage dropped by {:.2}% (baseline {:.2}%, current {:.2}%)",
                -cov_delta * 100.0,
                baseline_cov * 100.0,
                current_cov * 100.0,
            ),
            severity: f64_to_u8_clamped(((-cov_delta) * 1000.0).min(100.0)),
        });
    }

    // Success rate regression.
    let baseline_rate = baseline.success_rate();
    let current_rate = current.success_rate();
    let rate_delta = current_rate - baseline_rate;
    if rate_delta < thresholds.min_success_rate_delta {
        regressions.push(Regression {
            kind: RegressionKind::SuccessRateDown,
            description: format!(
                "Success rate dropped by {:.1}% (baseline {:.1}%, current {:.1}%)",
                -rate_delta * 100.0,
                baseline_rate * 100.0,
                current_rate * 100.0,
            ),
            severity: f64_to_u8_clamped(((-rate_delta) * 500.0).min(100.0)),
        });
    }

    regressions
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_timing_throughput() {
        let t = PassTiming::success("sweep", 0, 500, 1000);
        assert!((t.throughput() - 2000.0).abs() < 0.01);
    }

    #[test]
    fn pass_timing_zero_elapsed() {
        let t = PassTiming::success("sweep", 0, 0, 100);
        assert_eq!(t.throughput(), 0.0);
    }

    #[test]
    fn coverage_stats_ratio() {
        let mut c = CoverageStats::new(1000);
        c.decoded_bytes = 800;
        assert!((c.byte_coverage_ratio() - 0.8).abs() < 1e-9);
        assert!((c.byte_coverage_pct() - 80.0).abs() < 1e-9);
    }

    #[test]
    fn coverage_merge() {
        let mut a = CoverageStats::new(1000);
        a.decoded_bytes = 500;
        a.functions_identified = 10;
        let mut b = CoverageStats::new(500);
        b.decoded_bytes = 250;
        b.functions_identified = 5;
        a.merge(&b);
        assert_eq!(a.total_bytes, 1500);
        assert_eq!(a.decoded_bytes, 750);
        assert_eq!(a.functions_identified, 15);
    }

    #[test]
    fn metrics_record_and_report() {
        let m = AnalysisMetrics::new("test.bin");
        m.record_raw("pass_a", 100, 50, true, None);
        m.record_raw("pass_b", 200, 30, false, Some("err".into()));
        assert_eq!(m.entry_count(), 2);
        let report = m.build_report();
        assert_eq!(report.total_passes(), 2);
        assert_eq!(report.succeeded_count, 1);
        assert_eq!(report.failed_count, 1);
        assert_eq!(report.total_elapsed_ms, 300);
        assert!((report.success_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn function_score_compute() {
        let s = FunctionScore::compute(0x1000, 1.0, 50, 100);
        assert!(s.score >= 60);
        assert!(s.is_passing());
    }

    #[test]
    fn regression_detection_time() {
        let mut base = MetricsReport::new("a.bin");
        base.total_elapsed_ms = 100;
        let mut cur = MetricsReport::new("a.bin");
        cur.total_elapsed_ms = 200;
        let thresholds = RegressionThresholds::default();
        let r = detect_regressions(&base, &cur, &thresholds);
        assert!(r.iter().any(|x| x.kind == RegressionKind::TimeSlow));
    }

    #[test]
    fn aggregator_roll_up() {
        let mut agg = MetricsAggregator::new();
        let mut r1 = MetricsReport::new("a.bin");
        r1.succeeded_count = 3;
        r1.entries.push(PassMetricsEntry::new(
            PassTiming::success("p", 0, 10, 5),
            CoverageStats::new(100),
        ));
        agg.push(r1);
        assert_eq!(agg.report_count(), 1);
        assert_eq!(agg.total_passes(), 1);
    }

    #[test]
    fn metrics_report_summary() {
        let report = MetricsReport::new("x.bin");
        let s = report.summary();
        assert!(s.contains("x.bin"));
    }

    #[test]
    fn pass_guard_finish() {
        let m = AnalysisMetrics::new("g.bin");
        {
            let guard = m.begin_pass("guarded_pass");
            let _ = guard.finish(42);
        }
        // Guard was consumed by finish; drop should not double-record.
        let report = m.build_report();
        assert_eq!(report.total_passes(), 1);
        assert_eq!(report.entries[0].timing.pass_name, "guarded_pass");
        assert_eq!(report.entries[0].timing.items_processed, 42);
    }
}
