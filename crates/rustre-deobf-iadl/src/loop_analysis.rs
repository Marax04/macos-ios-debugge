//! Deobfuscation loop analysis.
//!
//! Tracks per-iteration progress metrics for IADL loops, detects stagnation,
//! and enforces resource budgets. Useful for controlling long-running
//! deobfuscation passes that iterate over binary regions.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum LoopAnalysisError {
    #[error("loop budget exceeded: {reason}")]
    BudgetExceeded { reason: String },
    #[error("stagnation detected after {iterations} iterations with no progress")]
    Stagnation { iterations: u32 },
    #[error("invalid state snapshot: {0}")]
    InvalidSnapshot(String),
    #[error("loop analysis error: {0}")]
    Other(String),
}

// ─── StateSnapshot ────────────────────────────────────────────────────────────

/// A snapshot of deobfuscation state at the start of an iteration.
///
/// Contains only the metrics relevant for progress measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Monotonic iteration index.
    pub iteration: u32,
    /// Number of unique IL/asm instructions decoded so far.
    pub instructions_decoded: u64,
    /// Number of distinct string literals recovered.
    pub strings_found: u32,
    /// Shannon entropy over the working buffer (bits per byte).
    pub entropy: f64,
    /// Number of functions identified.
    pub functions_found: u32,
    /// Number of data bytes de-obfuscated.
    pub bytes_deobfuscated: u64,
    /// Arbitrary named metrics set by the caller.
    pub custom_metrics: std::collections::BTreeMap<String, f64>,
}

impl StateSnapshot {
    /// Create a snapshot with all counters at zero.
    #[must_use] 
    pub const fn zeroed(iteration: u32) -> Self {
        Self {
            iteration,
            instructions_decoded: 0,
            strings_found: 0,
            entropy: 8.0, // Start at maximum entropy.
            functions_found: 0,
            bytes_deobfuscated: 0,
            custom_metrics: std::collections::BTreeMap::new(),
        }
    }

    /// Return `true` if entropy is below the "mostly decoded" threshold.
    #[must_use] 
    pub fn is_low_entropy(&self) -> bool {
        self.entropy < 2.0
    }

    /// Set a named custom metric.
    pub fn set_metric(&mut self, name: impl Into<String>, value: f64) {
        self.custom_metrics.insert(name.into(), value);
    }

    /// Get a named custom metric value.
    #[must_use] 
    pub fn get_metric(&self, name: &str) -> Option<f64> {
        self.custom_metrics.get(name).copied()
    }
}

// ─── ProgressDelta ────────────────────────────────────────────────────────────

/// The difference in progress metrics between two iterations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgressDelta {
    /// Change in decoded instructions (can be 0 if no new code decoded).
    pub delta_instructions: i64,
    /// Change in strings found.
    pub delta_strings: i32,
    /// Change in entropy (negative means entropy reduced, i.e., progress).
    pub delta_entropy: f64,
    /// Change in functions found.
    pub delta_functions: i32,
    /// Change in bytes de-obfuscated.
    pub delta_bytes: i64,
}

impl ProgressDelta {
    /// Compute the delta between two snapshots.
    #[must_use] 
    pub fn compute(before: &StateSnapshot, after: &StateSnapshot) -> Self {
        // Use saturating casts so counters > i64::MAX / i32::MAX don't wrap.
        let clamp_u64_i64 = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
        let clamp_u32_i32 = |v: u32| i32::try_from(v).unwrap_or(i32::MAX);
        Self {
            delta_instructions: clamp_u64_i64(after.instructions_decoded)
                .saturating_sub(clamp_u64_i64(before.instructions_decoded)),
            delta_strings: clamp_u32_i32(after.strings_found)
                .saturating_sub(clamp_u32_i32(before.strings_found)),
            delta_entropy: after.entropy - before.entropy,
            delta_functions: clamp_u32_i32(after.functions_found)
                .saturating_sub(clamp_u32_i32(before.functions_found)),
            delta_bytes: clamp_u64_i64(after.bytes_deobfuscated)
                .saturating_sub(clamp_u64_i64(before.bytes_deobfuscated)),
        }
    }

    /// Return `true` if any positive progress was made.
    ///
    /// Progress means: more instructions decoded, more strings, lower entropy,
    /// more functions, or more bytes de-obfuscated.
    #[must_use] 
    pub fn has_progress(&self) -> bool {
        self.delta_instructions > 0
            || self.delta_strings > 0
            || self.delta_entropy < -1e-6
            || self.delta_functions > 0
            || self.delta_bytes > 0
    }

    /// A scalar progress score (higher is better).
    ///
    /// Weights: instructions (×1), strings (×10), entropy reduction (×20),
    /// functions (×5), bytes (×0.001).
    #[must_use] 
    pub fn score(&self) -> f64 {
        (self.delta_bytes as f64).mul_add(0.001, f64::from(self.delta_functions).mul_add(5.0, (-self.delta_entropy).max(0.0).mul_add(20.0, f64::from(self.delta_strings).mul_add(10.0, self.delta_instructions as f64))))
    }

    /// Return `true` if all metrics are non-negative (no regressions).
    #[must_use] 
    pub fn is_monotone(&self) -> bool {
        self.delta_instructions >= 0
            && self.delta_strings >= 0
            && self.delta_entropy <= 1e-6
            && self.delta_functions >= 0
            && self.delta_bytes >= 0
    }
}

// ─── LoopIteration ────────────────────────────────────────────────────────────

/// Record of a single deobfuscation loop iteration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopIteration {
    /// Iteration number (0-based).
    pub iteration: u32,
    /// Snapshot at the start of this iteration.
    pub start_snapshot: StateSnapshot,
    /// Snapshot at the end of this iteration.
    pub end_snapshot: StateSnapshot,
    /// Progress delta computed from start → end.
    pub delta: ProgressDelta,
    /// Wall-clock time consumed by this iteration.
    #[serde(skip)]
    pub duration: Option<Duration>,
    /// Peak memory usage during this iteration (bytes), if measured.
    pub peak_memory_bytes: Option<u64>,
    /// Human-readable description of what happened in this iteration.
    pub description: String,
}

impl LoopIteration {
    /// Create a new iteration record.
    pub fn new(
        iteration: u32,
        start_snapshot: StateSnapshot,
        end_snapshot: StateSnapshot,
        duration: Option<Duration>,
        description: impl Into<String>,
    ) -> Self {
        let delta = ProgressDelta::compute(&start_snapshot, &end_snapshot);
        Self {
            iteration,
            start_snapshot,
            end_snapshot,
            delta,
            duration,
            peak_memory_bytes: None,
            description: description.into(),
        }
    }

    /// Return `true` if this iteration made any progress.
    #[must_use] 
    pub fn made_progress(&self) -> bool {
        self.delta.has_progress()
    }

    /// Progress score for this iteration.
    #[must_use] 
    pub fn progress_score(&self) -> f64 {
        self.delta.score()
    }

    /// Wall-clock duration in milliseconds.
    #[must_use] 
    pub fn duration_ms(&self) -> Option<u64> {
        self.duration.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

// ─── StagnationDetector ──────────────────────────────────────────────────────

/// Detects stagnation: no measurable progress for `window` consecutive iterations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagnationDetector {
    /// Number of consecutive no-progress iterations to consider stagnated.
    pub window: u32,
    /// Minimum scalar progress score to consider an iteration successful.
    pub min_progress_score: f64,
    /// Ring buffer of recent progress scores.
    #[serde(skip)]
    recent_scores: VecDeque<f64>,
    /// Count of consecutive non-progressing iterations.
    pub stagnant_count: u32,
}

impl StagnationDetector {
    /// Create a new detector with the given window.
    #[must_use] 
    pub const fn new(window: u32) -> Self {
        Self {
            window,
            min_progress_score: 1.0,
            recent_scores: VecDeque::new(),
            stagnant_count: 0,
        }
    }

    /// Create a detector with a custom minimum progress threshold.
    #[must_use] 
    pub fn with_threshold(window: u32, min_progress_score: f64) -> Self {
        Self {
            min_progress_score,
            ..Self::new(window)
        }
    }

    /// Record an iteration's progress score and return `true` if stagnated.
    pub fn record(&mut self, score: f64) -> bool {
        if score >= self.min_progress_score {
            self.stagnant_count = 0;
        } else {
            self.stagnant_count += 1;
        }
        self.recent_scores.push_back(score);
        if self.recent_scores.len() > self.window as usize * 2 {
            self.recent_scores.pop_front();
        }
        self.is_stagnated()
    }

    /// Return `true` if stagnation has been detected.
    #[must_use] 
    pub const fn is_stagnated(&self) -> bool {
        self.stagnant_count >= self.window
    }

    /// Reset the stagnation counter (e.g., after a strategy switch).
    pub fn reset(&mut self) {
        self.stagnant_count = 0;
        self.recent_scores.clear();
    }

    /// Return the average progress score over the recent window.
    #[must_use] 
    pub fn average_score(&self) -> f64 {
        if self.recent_scores.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.recent_scores.iter().sum();
        sum / self.recent_scores.len() as f64
    }

    /// Return the best score seen recently.
    pub fn best_recent_score(&self) -> f64 {
        self.recent_scores
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max)
    }
}

// ─── LoopBudget ───────────────────────────────────────────────────────────────

/// Resource limits for a deobfuscation loop.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LoopBudget {
    /// Maximum number of iterations (0 = unlimited).
    pub max_iterations: u32,
    /// Maximum wall-clock time (None = unlimited).
    #[serde(skip)]
    pub max_duration: Option<Duration>,
    /// Maximum memory usage in bytes (0 = unlimited).
    pub max_memory_bytes: u64,
}

impl Default for LoopBudget {
    fn default() -> Self {
        Self {
            max_iterations: 1000,
            max_duration: Some(Duration::from_mins(5)),
            max_memory_bytes: 512 * 1024 * 1024, // 512 MiB
        }
    }
}

impl LoopBudget {
    /// Create an unlimited budget (useful for testing).
    #[must_use] 
    pub const fn unlimited() -> Self {
        Self {
            max_iterations: u32::MAX,
            max_duration: None,
            max_memory_bytes: 0,
        }
    }

    /// Check whether the iteration limit has been exceeded.
    pub fn check_iterations(&self, current: u32) -> Result<(), LoopAnalysisError> {
        if self.max_iterations > 0 && current >= self.max_iterations {
            return Err(LoopAnalysisError::BudgetExceeded {
                reason: format!("iteration limit {}", self.max_iterations),
            });
        }
        Ok(())
    }

    /// Check whether the wall-clock budget has been exceeded.
    pub fn check_time(&self, start: Instant) -> Result<(), LoopAnalysisError> {
        if let Some(max_dur) = self.max_duration
            && start.elapsed() >= max_dur {
                return Err(LoopAnalysisError::BudgetExceeded {
                    reason: format!("time limit {max_dur:?}"),
                });
            }
        Ok(())
    }

    /// Check whether memory usage is within budget.
    pub fn check_memory(&self, current_bytes: u64) -> Result<(), LoopAnalysisError> {
        if self.max_memory_bytes > 0 && current_bytes > self.max_memory_bytes {
            return Err(LoopAnalysisError::BudgetExceeded {
                reason: format!(
                    "memory limit {} bytes (current: {} bytes)",
                    self.max_memory_bytes, current_bytes
                ),
            });
        }
        Ok(())
    }
}

// ─── LoopProgressAnalyzer ────────────────────────────────────────────────────

/// Tracks per-iteration progress metrics across the lifetime of a loop.
///
/// Intended as the primary entry point for monitoring loop health.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LoopProgressAnalyzer {
    /// All iteration records, in order.
    pub iterations: Vec<LoopIteration>,
    /// Total number of instructions decoded.
    pub total_instructions: u64,
    /// Total number of strings found.
    pub total_strings: u32,
    /// Total bytes de-obfuscated.
    pub total_bytes: u64,
    /// Cumulative wall-clock time.
    #[serde(skip)]
    pub total_duration: Duration,
}

impl LoopProgressAnalyzer {
    /// Create a new, empty analyzer.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a completed iteration.
    pub fn record(&mut self, iter: LoopIteration) {
        self.total_instructions += iter.delta.delta_instructions.max(0) as u64;
        self.total_strings += iter.delta.delta_strings.max(0) as u32;
        self.total_bytes += iter.delta.delta_bytes.max(0) as u64;
        if let Some(d) = iter.duration {
            self.total_duration += d;
        }
        self.iterations.push(iter);
    }

    /// Return the number of completed iterations.
    #[must_use] 
    pub const fn iteration_count(&self) -> usize {
        self.iterations.len()
    }

    /// Return `true` if the last `n` iterations all had no progress.
    #[must_use] 
    pub fn last_n_no_progress(&self, n: usize) -> bool {
        if self.iterations.len() < n {
            return false;
        }
        self.iterations
            .iter()
            .rev()
            .take(n)
            .all(|it| !it.made_progress())
    }

    /// Return the best iteration (highest progress score).
    #[must_use] 
    pub fn best_iteration(&self) -> Option<&LoopIteration> {
        self.iterations
            .iter()
            .max_by(|a, b| a.progress_score().total_cmp(&b.progress_score()))
    }

    /// Return the average progress score per iteration.
    #[must_use] 
    pub fn average_score(&self) -> f64 {
        if self.iterations.is_empty() {
            return 0.0;
        }
        let total: f64 = self.iterations.iter().map(LoopIteration::progress_score).sum();
        total / self.iterations.len() as f64
    }

    /// Return the last recorded snapshot, if any.
    #[must_use] 
    pub fn last_snapshot(&self) -> Option<&StateSnapshot> {
        self.iterations.last().map(|it| &it.end_snapshot)
    }

    /// Return a progress trend: slope of progress scores over last `window` iters.
    #[must_use] 
    pub fn trend(&self, window: usize) -> f64 {
        let n = window.min(self.iterations.len());
        if n < 2 {
            return 0.0;
        }
        let scores: Vec<f64> = self
            .iterations
            .iter()
            .rev()
            .take(n)
            .map(LoopIteration::progress_score)
            .collect();
        // Simple linear trend: last - first over n-1 steps.
        (scores[0] - scores[n - 1]) / (n as f64 - 1.0)
    }

    /// Return all iterations that made progress.
    #[must_use] 
    pub fn progressing_iterations(&self) -> Vec<&LoopIteration> {
        self.iterations
            .iter()
            .filter(|it| it.made_progress())
            .collect()
    }

    /// Return all iterations that made no progress.
    #[must_use] 
    pub fn stagnant_iterations(&self) -> Vec<&LoopIteration> {
        self.iterations
            .iter()
            .filter(|it| !it.made_progress())
            .collect()
    }

    /// Ratio of progressing iterations to total.
    #[must_use] 
    pub fn progress_ratio(&self) -> f64 {
        if self.iterations.is_empty() {
            return 0.0;
        }
        self.progressing_iterations().len() as f64 / self.iterations.len() as f64
    }
}

// ─── LoopController ──────────────────────────────────────────────────────────

/// Combines `LoopProgressAnalyzer`, `StagnationDetector`, and `LoopBudget`
/// into a single controller for driving a deobfuscation loop.
pub struct LoopController {
    pub analyzer: LoopProgressAnalyzer,
    pub stagnation: StagnationDetector,
    pub budget: LoopBudget,
    start_time: Instant,
    pub current_iteration: u32,
}

impl LoopController {
    /// Create a new controller.
    #[must_use] 
    pub fn new(budget: LoopBudget, stagnation_window: u32) -> Self {
        Self {
            analyzer: LoopProgressAnalyzer::new(),
            stagnation: StagnationDetector::new(stagnation_window),
            budget,
            start_time: Instant::now(),
            current_iteration: 0,
        }
    }

    /// Call at the start of each iteration. Returns an error if the budget is
    /// exceeded before the iteration begins.
    pub fn begin_iteration(&mut self) -> Result<u32, LoopAnalysisError> {
        self.budget.check_iterations(self.current_iteration)?;
        self.budget.check_time(self.start_time)?;
        Ok(self.current_iteration)
    }

    /// Call at the end of each iteration with the before/after snapshots.
    ///
    /// Returns `Err(Stagnation)` if the loop has stagnated.
    pub fn end_iteration(
        &mut self,
        start_snap: StateSnapshot,
        end_snap: StateSnapshot,
        duration: Option<Duration>,
        description: impl Into<String>,
    ) -> Result<bool, LoopAnalysisError> {
        let iter = LoopIteration::new(
            self.current_iteration,
            start_snap,
            end_snap,
            duration,
            description,
        );
        let score = iter.progress_score();
        let made_progress = iter.made_progress();
        self.analyzer.record(iter);
        self.current_iteration += 1;
        let stagnated = self.stagnation.record(score);
        if stagnated {
            return Err(LoopAnalysisError::Stagnation {
                iterations: self.stagnation.stagnant_count,
            });
        }
        Ok(made_progress)
    }

    /// Total elapsed wall-clock time since the controller was created.
    #[must_use] 
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Return a summary string for diagnostics.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "Iteration {}: {} total, {:.1}% progress, avg_score={:.2}, elapsed={:.1}s",
            self.current_iteration,
            self.analyzer.iteration_count(),
            self.analyzer.progress_ratio() * 100.0,
            self.analyzer.average_score(),
            self.elapsed().as_secs_f64(),
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(iter: u32, instructions: u64, strings: u32, entropy: f64, bytes: u64) -> StateSnapshot {
        let mut s = StateSnapshot::zeroed(iter);
        s.instructions_decoded = instructions;
        s.strings_found = strings;
        s.entropy = entropy;
        s.bytes_deobfuscated = bytes;
        s
    }

    // ── StateSnapshot tests ───────────────────────────────────────────────────

    #[test]
    fn state_snapshot_zeroed() {
        let s = StateSnapshot::zeroed(0);
        assert_eq!(s.instructions_decoded, 0);
        assert_eq!(s.strings_found, 0);
        assert!((s.entropy - 8.0).abs() < 1e-9);
    }

    #[test]
    fn state_snapshot_is_low_entropy() {
        let mut s = StateSnapshot::zeroed(0);
        s.entropy = 1.5;
        assert!(s.is_low_entropy());
        s.entropy = 3.0;
        assert!(!s.is_low_entropy());
    }

    #[test]
    fn state_snapshot_custom_metrics() {
        let mut s = StateSnapshot::zeroed(0);
        s.set_metric("coverage", 0.75);
        assert!((s.get_metric("coverage").unwrap() - 0.75).abs() < 1e-9);
        assert!(s.get_metric("missing").is_none());
    }

    // ── ProgressDelta tests ───────────────────────────────────────────────────

    #[test]
    fn progress_delta_has_progress_instructions() {
        let before = snap(0, 100, 0, 6.0, 0);
        let after = snap(1, 200, 0, 6.0, 0);
        let d = ProgressDelta::compute(&before, &after);
        assert_eq!(d.delta_instructions, 100);
        assert!(d.has_progress());
    }

    #[test]
    fn progress_delta_has_progress_entropy() {
        let before = snap(0, 0, 0, 7.0, 0);
        let after = snap(1, 0, 0, 5.0, 0);
        let d = ProgressDelta::compute(&before, &after);
        assert!(d.delta_entropy < 0.0);
        assert!(d.has_progress());
    }

    #[test]
    fn progress_delta_no_progress_when_all_zero() {
        let s0 = snap(0, 100, 5, 6.0, 50);
        let s1 = snap(1, 100, 5, 6.0, 50);
        let d = ProgressDelta::compute(&s0, &s1);
        assert!(!d.has_progress());
    }

    #[test]
    fn progress_delta_score_positive_on_progress() {
        let before = snap(0, 0, 0, 8.0, 0);
        let after = snap(1, 100, 3, 5.0, 1000);
        let d = ProgressDelta::compute(&before, &after);
        assert!(d.score() > 0.0);
    }

    #[test]
    fn progress_delta_score_zero_when_no_progress() {
        let s = snap(0, 100, 5, 6.0, 50);
        let d = ProgressDelta::compute(&s, &s.clone());
        assert!((d.score()).abs() < 1e-9);
    }

    #[test]
    fn progress_delta_is_monotone_on_equal() {
        let s = snap(0, 100, 5, 6.0, 50);
        let d = ProgressDelta::compute(&s, &s.clone());
        assert!(d.is_monotone());
    }

    #[test]
    fn progress_delta_not_monotone_on_regression() {
        let before = snap(0, 100, 5, 6.0, 50);
        let after = snap(1, 50, 5, 6.0, 50); // instructions went down
        let d = ProgressDelta::compute(&before, &after);
        assert!(!d.is_monotone());
    }

    // ── LoopIteration tests ───────────────────────────────────────────────────

    #[test]
    fn loop_iteration_made_progress() {
        let before = snap(0, 0, 0, 8.0, 0);
        let after = snap(1, 10, 1, 7.0, 100);
        let it = LoopIteration::new(0, before, after, None, "test");
        assert!(it.made_progress());
    }

    #[test]
    fn loop_iteration_no_progress() {
        let s = snap(0, 100, 5, 6.0, 50);
        let it = LoopIteration::new(0, s.clone(), s, None, "test");
        assert!(!it.made_progress());
    }

    #[test]
    fn loop_iteration_duration_ms() {
        let s = snap(0, 0, 0, 8.0, 0);
        let it = LoopIteration::new(0, s.clone(), s, Some(Duration::from_millis(42)), "test");
        assert_eq!(it.duration_ms(), Some(42));
    }

    // ── StagnationDetector tests ──────────────────────────────────────────────

    #[test]
    fn stagnation_detector_not_stagnated_initially() {
        let det = StagnationDetector::new(3);
        assert!(!det.is_stagnated());
    }

    #[test]
    fn stagnation_detector_stagnates_after_window() {
        let mut det = StagnationDetector::new(3);
        for _ in 0..3 {
            det.record(0.0); // below threshold
        }
        assert!(det.is_stagnated());
    }

    #[test]
    fn stagnation_detector_resets_on_progress() {
        let mut det = StagnationDetector::new(3);
        det.record(0.0);
        det.record(0.0);
        det.record(100.0); // progress! resets count
        assert!(!det.is_stagnated());
        assert_eq!(det.stagnant_count, 0);
    }

    #[test]
    fn stagnation_detector_reset_clears_state() {
        let mut det = StagnationDetector::new(3);
        det.record(0.0);
        det.record(0.0);
        det.record(0.0);
        assert!(det.is_stagnated());
        det.reset();
        assert!(!det.is_stagnated());
        assert_eq!(det.stagnant_count, 0);
    }

    #[test]
    fn stagnation_detector_average_score() {
        let mut det = StagnationDetector::new(5);
        det.record(10.0);
        det.record(20.0);
        det.record(30.0);
        let avg = det.average_score();
        assert!((avg - 20.0).abs() < 1e-6);
    }

    #[test]
    fn stagnation_detector_best_recent_score() {
        let mut det = StagnationDetector::new(5);
        det.record(5.0);
        det.record(42.0);
        det.record(1.0);
        assert!((det.best_recent_score() - 42.0).abs() < 1e-6);
    }

    #[test]
    fn stagnation_detector_custom_threshold() {
        let mut det = StagnationDetector::with_threshold(2, 50.0);
        det.record(40.0); // below 50.0 → counts as no progress
        det.record(40.0);
        assert!(det.is_stagnated());
    }

    // ── LoopBudget tests ──────────────────────────────────────────────────────

    #[test]
    fn loop_budget_default_passes_for_zero_iterations() {
        let budget = LoopBudget::default();
        assert!(budget.check_iterations(0).is_ok());
    }

    #[test]
    fn loop_budget_iteration_limit_exceeded() {
        let budget = LoopBudget {
            max_iterations: 5,
            ..LoopBudget::default()
        };
        assert!(budget.check_iterations(5).is_err());
        assert!(budget.check_iterations(4).is_ok());
    }

    #[test]
    fn loop_budget_memory_ok() {
        let budget = LoopBudget {
            max_memory_bytes: 1024,
            ..LoopBudget::default()
        };
        assert!(budget.check_memory(512).is_ok());
        assert!(budget.check_memory(2048).is_err());
    }

    #[test]
    fn loop_budget_unlimited_never_exceeds() {
        let budget = LoopBudget::unlimited();
        assert!(budget.check_iterations(u32::MAX - 1).is_ok());
        assert!(budget.check_memory(u64::MAX).is_ok());
    }

    #[test]
    fn loop_budget_time_ok_when_just_started() {
        let budget = LoopBudget {
            max_duration: Some(Duration::from_hours(1)),
            ..LoopBudget::default()
        };
        let start = Instant::now();
        assert!(budget.check_time(start).is_ok());
    }

    // ── LoopProgressAnalyzer tests ────────────────────────────────────────────

    #[test]
    fn progress_analyzer_records_iteration() {
        let mut analyzer = LoopProgressAnalyzer::new();
        let s0 = snap(0, 0, 0, 8.0, 0);
        let s1 = snap(1, 100, 2, 6.0, 500);
        let it = LoopIteration::new(0, s0, s1, None, "test");
        analyzer.record(it);
        assert_eq!(analyzer.iteration_count(), 1);
        assert_eq!(analyzer.total_instructions, 100);
        assert_eq!(analyzer.total_strings, 2);
        assert_eq!(analyzer.total_bytes, 500);
    }

    #[test]
    fn progress_analyzer_best_iteration() {
        let mut analyzer = LoopProgressAnalyzer::new();
        for i in 0..5u32 {
            let s0 = snap(i, u64::from(i) * 10, 0, 8.0, 0);
            let s1 = snap(i + 1, u64::from(i + 1) * 10, 0, 8.0, 0);
            analyzer.record(LoopIteration::new(i, s0, s1, None, "test"));
        }
        let best = analyzer.best_iteration().unwrap();
        // Last iteration has the highest delta.
        assert_eq!(best.iteration, 4);
    }

    #[test]
    fn progress_analyzer_last_n_no_progress() {
        let mut analyzer = LoopProgressAnalyzer::new();
        for i in 0..3u32 {
            let s = snap(i, 100, 5, 6.0, 50); // no change
            analyzer.record(LoopIteration::new(i, s.clone(), s, None, "test"));
        }
        assert!(analyzer.last_n_no_progress(3));
        assert!(!analyzer.last_n_no_progress(4)); // not enough iterations
    }

    #[test]
    fn progress_analyzer_progress_ratio() {
        let mut analyzer = LoopProgressAnalyzer::new();
        // 2 progressing, 1 stagnant
        let s_base = snap(0, 100, 5, 6.0, 50);
        let s_prog = snap(1, 200, 5, 6.0, 50);
        analyzer.record(LoopIteration::new(
            0,
            s_base.clone(),
            s_prog.clone(),
            None,
            "prog",
        ));
        analyzer.record(LoopIteration::new(
            1,
            s_prog,
            s_base.clone(),
            None,
            "noprog",
        ));
        analyzer.record(LoopIteration::new(
            2,
            s_base,
            snap(3, 300, 5, 6.0, 50),
            None,
            "prog",
        ));
        // 2 out of 3 have progress.
        assert!((analyzer.progress_ratio() - 2.0 / 3.0).abs() < 0.01);
    }

    // ── LoopController tests ──────────────────────────────────────────────────

    #[test]
    fn loop_controller_basic_iteration() {
        let budget = LoopBudget {
            max_iterations: 10,
            ..LoopBudget::default()
        };
        let mut ctrl = LoopController::new(budget, 3);
        let iter_num = ctrl.begin_iteration().unwrap();
        assert_eq!(iter_num, 0);
        let s0 = snap(0, 0, 0, 8.0, 0);
        let s1 = snap(1, 100, 0, 7.0, 0);
        let _ = ctrl.end_iteration(s0, s1, None, "iter 0");
        assert_eq!(ctrl.current_iteration, 1);
    }

    #[test]
    fn loop_controller_budget_exceeded_stops() {
        let budget = LoopBudget {
            max_iterations: 2,
            ..LoopBudget::default()
        };
        let mut ctrl = LoopController::new(budget, 10);
        ctrl.begin_iteration().unwrap();
        ctrl.end_iteration(snap(0, 0, 0, 8.0, 0), snap(1, 100, 0, 7.0, 0), None, "")
            .unwrap();
        ctrl.begin_iteration().unwrap();
        ctrl.end_iteration(snap(1, 100, 0, 7.0, 0), snap(2, 200, 0, 6.0, 0), None, "")
            .unwrap();
        let r = ctrl.begin_iteration();
        assert!(r.is_err());
    }

    #[test]
    fn loop_controller_stagnation_detected() {
        let budget = LoopBudget::unlimited();
        let mut ctrl = LoopController::new(budget, 2);
        for i in 0..2u32 {
            let s = snap(i, 100, 5, 6.0, 50);
            ctrl.begin_iteration().unwrap();
            let r = ctrl.end_iteration(s.clone(), s, None, "no progress");
            if i == 1 {
                assert!(r.is_err());
            }
        }
    }

    #[test]
    fn loop_controller_summary_non_empty() {
        let ctrl = LoopController::new(LoopBudget::default(), 3);
        let s = ctrl.summary();
        assert!(!s.is_empty());
        assert!(s.contains("Iteration"));
    }
}
