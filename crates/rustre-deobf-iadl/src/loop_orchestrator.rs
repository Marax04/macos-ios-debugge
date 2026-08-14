//! Loop orchestrator for the Iterative Adversarial Deobfuscation Loop (IADL).
//!
//! Provides:
//! * [`DeobfIteration`] — a single iteration record.
//! * [`IterationResult`] — outcome of one iteration.
//! * [`QualityDelta`] — quality change between two states.
//! * [`StrategySwitch`] — a recorded change of deobfuscation strategy.
//! * [`OrchestratorStats`] — aggregated statistics after a run.
//! * [`LoopReport`] — comprehensive per-run report.
//! * [`LoopOrchestrator`] — the main orchestration engine.

use std::collections::HashMap;

use tracing::{debug, info};

// ─────────────────────────────────────────────────────────────────────────────
// DeobfIteration
// ─────────────────────────────────────────────────────────────────────────────

/// A single iteration in the deobfuscation loop.
#[derive(Debug, Clone)]
pub struct DeobfIteration {
    /// Zero-based iteration index.
    pub index: usize,
    /// Strategy name used in this iteration.
    pub strategy: String,
    /// Quality score before the iteration (higher = better).
    pub score_before: f64,
    /// Quality score after the iteration.
    pub score_after: f64,
    /// Complexity metric before the iteration.
    pub complexity_before: u64,
    /// Complexity metric after the iteration.
    pub complexity_after: u64,
    /// Whether the iteration improved quality.
    pub improved: bool,
    /// Whether the iteration was accepted into the solution.
    pub accepted: bool,
    /// Elapsed time in microseconds.
    pub elapsed_us: u64,
    /// Human-readable notes from the strategy.
    pub notes: Vec<String>,
}

impl DeobfIteration {
    /// Create a new iteration record.
    #[must_use]
    pub fn new(
        index: usize,
        strategy: impl Into<String>,
        score_before: f64,
        complexity_before: u64,
    ) -> Self {
        Self {
            index,
            strategy: strategy.into(),
            score_before,
            score_after: score_before,
            complexity_before,
            complexity_after: complexity_before,
            improved: false,
            accepted: false,
            elapsed_us: 0,
            notes: Vec::new(),
        }
    }

    /// Mark as completed with the given outcome.
    pub fn complete(&mut self, score_after: f64, complexity_after: u64) {
        self.score_after = score_after;
        self.complexity_after = complexity_after;
        self.improved = score_after > self.score_before;
    }

    /// Quality delta for this iteration.
    #[must_use]
    pub fn delta(&self) -> f64 {
        self.score_after - self.score_before
    }

    /// Complexity reduction (positive = improved).
    #[must_use]
    pub const fn complexity_reduction(&self) -> i64 {
        self.complexity_before as i64 - self.complexity_after as i64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IterationResult
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a single deobfuscation iteration.
#[derive(Debug, Clone, PartialEq)]
pub enum IterationResult {
    /// Quality improved — iteration accepted.
    Improved {
        delta: f64,
        complexity_reduction: i64,
    },
    /// No change — iteration had no effect.
    NoChange,
    /// Quality decreased — iteration rejected.
    Degraded { delta: f64 },
    /// The pass detected that convergence has been reached.
    Converged,
    /// The pass encountered an error.
    Error { message: String },
}

impl IterationResult {
    /// Return `true` if the iteration was beneficial.
    #[must_use]
    pub const fn is_beneficial(&self) -> bool {
        matches!(self, Self::Improved { .. })
    }

    /// Return `true` if the loop should stop.
    #[must_use]
    pub const fn should_stop(&self) -> bool {
        matches!(self, Self::Converged | Self::Error { .. })
    }

    /// Return the delta if applicable.
    #[must_use]
    pub const fn delta(&self) -> f64 {
        match self {
            Self::Improved { delta, .. } | Self::Degraded { delta } => *delta,
            _ => 0.0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QualityDelta
// ─────────────────────────────────────────────────────────────────────────────

/// Quality change between two consecutive iterations.
#[derive(Debug, Clone)]
pub struct QualityDelta {
    /// Iteration index that produced this delta.
    pub iteration: usize,
    /// The strategy that was running.
    pub strategy: String,
    /// Absolute quality delta.
    pub absolute: f64,
    /// Relative delta (absolute / `previous_score`), or 0.0 if previous was 0.
    pub relative: f64,
    /// Complexity delta (positive = reduced complexity).
    pub complexity_delta: i64,
    /// Whether this delta crosses the acceptance threshold.
    pub is_accepted: bool,
}

impl QualityDelta {
    /// Create a new quality delta.
    #[must_use]
    pub fn new(
        iteration: usize,
        strategy: impl Into<String>,
        previous: f64,
        current: f64,
        prev_complexity: u64,
        curr_complexity: u64,
    ) -> Self {
        let absolute = current - previous;
        let relative = if previous.abs() > 1e-12 {
            absolute / previous
        } else {
            0.0
        };
        let complexity_delta = prev_complexity as i64 - curr_complexity as i64;
        Self {
            iteration,
            strategy: strategy.into(),
            absolute,
            relative,
            complexity_delta,
            is_accepted: absolute > 0.0,
        }
    }

    /// Return `true` if quality improved.
    #[must_use]
    pub fn is_improvement(&self) -> bool {
        self.absolute > 1e-12
    }

    /// Return `true` if quality was unchanged.
    #[must_use]
    pub fn is_no_change(&self) -> bool {
        self.absolute.abs() < 1e-12
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StrategySwitch
// ─────────────────────────────────────────────────────────────────────────────

/// A recorded strategy change during the loop.
#[derive(Debug, Clone)]
pub struct StrategySwitch {
    /// Iteration at which the switch occurred.
    pub at_iteration: usize,
    /// Previous strategy name.
    pub from: String,
    /// New strategy name.
    pub to: String,
    /// Reason for the switch.
    pub reason: StrategySwitchReason,
    /// Quality score at the time of the switch.
    pub score_at_switch: f64,
}

/// Why a strategy switch was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrategySwitchReason {
    /// The current strategy stagnated (no progress for N iterations).
    Stagnation,
    /// A better strategy was found via scoring.
    BetterStrategyFound,
    /// The iteration count for this strategy was exhausted.
    IterationBudgetExhausted,
    /// Manual / user-directed switch.
    Manual,
    /// Scheduled rotation (round-robin).
    Rotation,
}

impl StrategySwitchReason {
    /// Short label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Stagnation => "stagnation",
            Self::BetterStrategyFound => "better-strategy",
            Self::IterationBudgetExhausted => "budget-exhausted",
            Self::Manual => "manual",
            Self::Rotation => "rotation",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OrchestratorStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated statistics after a loop run.
#[derive(Debug, Clone, Default)]
pub struct OrchestratorStats {
    /// Total iterations executed.
    pub total_iterations: usize,
    /// Iterations that improved quality.
    pub improving_iterations: usize,
    /// Iterations that had no effect.
    pub no_change_iterations: usize,
    /// Iterations that degraded quality.
    pub degraded_iterations: usize,
    /// Total number of strategy switches.
    pub strategy_switches: usize,
    /// Total elapsed time in microseconds.
    pub total_elapsed_us: u64,
    /// Final quality score.
    pub final_score: f64,
    /// Initial quality score.
    pub initial_score: f64,
    /// Per-strategy iteration counts.
    pub per_strategy_count: HashMap<String, usize>,
}

impl OrchestratorStats {
    /// Create empty stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Overall quality improvement.
    #[must_use]
    pub fn total_improvement(&self) -> f64 {
        self.final_score - self.initial_score
    }

    /// Fraction of improving iterations.
    #[must_use]
    pub fn improvement_rate(&self) -> f64 {
        if self.total_iterations == 0 {
            return 0.0;
        }
        self.improving_iterations as f64 / self.total_iterations as f64
    }

    /// Record an iteration outcome.
    pub fn record(&mut self, result: &IterationResult, strategy: &str, elapsed_us: u64) {
        self.total_iterations += 1;
        self.total_elapsed_us += elapsed_us;
        *self
            .per_strategy_count
            .entry(strategy.to_owned())
            .or_insert(0) += 1;
        match result {
            IterationResult::Improved { .. } => self.improving_iterations += 1,
            IterationResult::NoChange => self.no_change_iterations += 1,
            IterationResult::Degraded { .. } => self.degraded_iterations += 1,
            _ => {}
        }
    }

    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "iterations={} improving={} no_change={} degraded={} switches={} Δscore={:.4}",
            self.total_iterations,
            self.improving_iterations,
            self.no_change_iterations,
            self.degraded_iterations,
            self.strategy_switches,
            self.total_improvement(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopReport
// ─────────────────────────────────────────────────────────────────────────────

/// Comprehensive per-run report from the loop orchestrator.
#[derive(Debug, Clone, Default)]
pub struct LoopReport {
    /// Aggregated statistics.
    pub stats: OrchestratorStats,
    /// All iteration records (may be truncated for large runs).
    pub iterations: Vec<DeobfIteration>,
    /// Quality deltas for each accepted iteration.
    pub deltas: Vec<QualityDelta>,
    /// All strategy switches that occurred.
    pub switches: Vec<StrategySwitch>,
    /// Whether the loop converged.
    pub converged: bool,
    /// Reason the loop terminated.
    pub termination_reason: String,
    /// Best quality score observed during the run.
    pub best_score: f64,
    /// Iteration at which the best score was achieved.
    pub best_at_iteration: usize,
}

impl LoopReport {
    /// Create an empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the strategy that produced the most improvements.
    #[must_use]
    pub fn best_strategy(&self) -> Option<&str> {
        // Count improvements per strategy.
        let mut counts: HashMap<&str, usize> = HashMap::with_capacity(self.iterations.len());
        for it in &self.iterations {
            if it.improved {
                *counts.entry(it.strategy.as_str()).or_insert(0) += 1;
            }
        }
        // `counts` is a HashMap: with no tie-break, two strategies that produced
        // the same number of improvements would win arbitrarily, so the reported
        // "best strategy" could differ between runs on identical data.
        counts
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
            .map(|(s, _)| s)
    }

    /// Append an iteration record and update the best score.
    pub fn record_iteration(&mut self, iter: DeobfIteration) {
        if iter.score_after > self.best_score {
            self.best_score = iter.score_after;
            self.best_at_iteration = iter.index;
        }
        self.iterations.push(iter);
    }

    /// Return all improvement deltas sorted by absolute improvement descending.
    #[must_use]
    pub fn top_improvements(&self, n: usize) -> Vec<&QualityDelta> {
        let mut sorted: Vec<&QualityDelta> = self.deltas.iter().collect();
        sorted.sort_by(|a, b| {
            b.absolute
                .partial_cmp(&a.absolute)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.into_iter().take(n).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfProgressTracker — tracks overall deobfuscation progress across runs
// ─────────────────────────────────────────────────────────────────────────────

/// Records the deobfuscation progress of one binary across multiple loop runs.
#[derive(Debug, Clone, Default)]
pub struct DeobfProgressTracker {
    /// Scores at each checkpoint (one per loop run).
    pub checkpoints: Vec<f64>,
    /// Complexity at each checkpoint.
    pub complexity_checkpoints: Vec<u64>,
    /// Strategies used at each checkpoint.
    pub strategy_at_checkpoint: Vec<String>,
}

impl DeobfProgressTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a checkpoint.
    pub fn record(&mut self, score: f64, complexity: u64, strategy: impl Into<String>) {
        self.checkpoints.push(score);
        self.complexity_checkpoints.push(complexity);
        self.strategy_at_checkpoint.push(strategy.into());
    }

    /// Return the overall improvement from first to last checkpoint.
    #[must_use]
    pub fn total_improvement(&self) -> f64 {
        match (self.checkpoints.first(), self.checkpoints.last()) {
            (Some(&first), Some(&last)) => last - first,
            _ => 0.0,
        }
    }

    /// Return the fraction of checkpoints that showed improvement.
    #[must_use]
    pub fn improving_fraction(&self) -> f64 {
        if self.checkpoints.len() < 2 {
            return 0.0;
        }
        let improving = self.checkpoints.windows(2).filter(|w| w[1] > w[0]).count();
        improving as f64 / (self.checkpoints.len() - 1) as f64
    }

    /// Return `true` if the tracker shows convergence (last 3 deltas < epsilon).
    #[must_use]
    pub fn is_converged(&self, epsilon: f64) -> bool {
        if self.checkpoints.len() < 4 {
            return false;
        }
        self.checkpoints
            .windows(2)
            .rev()
            .take(3)
            .all(|w| (w[1] - w[0]).abs() < epsilon)
    }

    /// Number of checkpoints.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.checkpoints.len()
    }

    /// Return `true` when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.checkpoints.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IterationHistory — typed wrapper with statistics over past iterations
// ─────────────────────────────────────────────────────────────────────────────

/// A compact, statistics-aware history of recent iteration scores.
#[derive(Debug, Clone, Default)]
pub struct IterationHistory {
    /// All recorded score values.
    pub scores: Vec<f64>,
    /// All recorded complexity values.
    pub complexities: Vec<u64>,
    /// Maximum number of entries to retain (0 = unlimited).
    pub max_entries: usize,
}

impl IterationHistory {
    /// Create an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a retention limit.
    #[must_use]
    pub const fn with_limit(mut self, n: usize) -> Self {
        self.max_entries = n;
        self
    }

    /// Record a score/complexity pair.
    pub fn record(&mut self, score: f64, complexity: u64) {
        self.scores.push(score);
        self.complexities.push(complexity);
        if self.max_entries > 0 && self.scores.len() > self.max_entries {
            self.scores.remove(0);
            self.complexities.remove(0);
        }
    }

    /// Return the mean score.
    #[must_use]
    pub fn mean_score(&self) -> f64 {
        if self.scores.is_empty() {
            return 0.0;
        }
        self.scores.iter().sum::<f64>() / self.scores.len() as f64
    }

    /// Return the maximum score observed.
    #[must_use]
    pub fn max_score(&self) -> f64 {
        self.scores
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max)
    }

    /// Return the minimum score observed.
    #[must_use]
    pub fn min_score(&self) -> f64 {
        self.scores.iter().copied().fold(f64::INFINITY, f64::min)
    }

    /// Return `true` when scores are monotonically non-decreasing over the last N.
    #[must_use]
    pub fn is_monotone(&self, n: usize) -> bool {
        let mut iter = self.scores.iter().copied().rev().take(n);
        let Some(mut prev) = iter.next() else {
            return true;
        };
        for v in iter {
            if v > prev {
                return false;
            }
            prev = v;
        }
        true
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.scores.len()
    }

    /// Return `true` when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IterationScheduler — budget allocation across strategies
// ─────────────────────────────────────────────────────────────────────────────

/// A budget entry: how many iterations a strategy is allocated per round.
#[derive(Debug, Clone)]
pub struct StrategyBudget {
    /// Strategy name.
    pub name: String,
    /// Number of iterations allocated per scheduling round.
    pub budget: usize,
    /// Total iterations consumed so far.
    pub consumed: usize,
}

impl StrategyBudget {
    /// Create a new budget entry.
    #[must_use]
    pub fn new(name: impl Into<String>, budget: usize) -> Self {
        Self {
            name: name.into(),
            budget,
            consumed: 0,
        }
    }

    /// Consume one iteration. Returns `true` if budget was available.
    pub const fn consume(&mut self) -> bool {
        if self.consumed < self.budget {
            self.consumed += 1;
            true
        } else {
            false
        }
    }

    /// Reset the consumed counter for a new round.
    pub const fn reset(&mut self) {
        self.consumed = 0;
    }

    /// Return `true` if budget is exhausted.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.consumed >= self.budget
    }
}

/// Schedules iteration budgets across a set of strategies.
#[derive(Debug, Clone, Default)]
pub struct IterationScheduler {
    /// Per-strategy budgets.
    pub budgets: Vec<StrategyBudget>,
}

impl IterationScheduler {
    /// Create an empty scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a strategy with `budget` iterations per round.
    pub fn add(&mut self, name: impl Into<String>, budget: usize) {
        self.budgets.push(StrategyBudget::new(name, budget));
    }

    /// Return the next strategy name that has budget remaining (round-robin).
    #[must_use]
    pub fn next_available(&mut self) -> Option<&str> {
        for b in &mut self.budgets {
            if !b.is_exhausted() {
                b.consume();
                return Some(b.name.as_str());
            }
        }
        None
    }

    /// Reset all budgets for a new round.
    pub fn reset_all(&mut self) {
        for b in &mut self.budgets {
            b.reset();
        }
    }

    /// Return `true` if all budgets are exhausted.
    #[must_use]
    pub fn all_exhausted(&self) -> bool {
        self.budgets.iter().all(StrategyBudget::is_exhausted)
    }

    /// Total budget across all strategies.
    #[must_use]
    pub fn total_budget(&self) -> usize {
        self.budgets.iter().map(|b| b.budget).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy trait and built-in strategies
// ─────────────────────────────────────────────────────────────────────────────

/// A deobfuscation strategy that can be invoked in one iteration.
pub trait Strategy: Send + Sync {
    /// Short identifier.
    fn name(&self) -> &str;
    /// Run one step on `state`, returning an [`IterationResult`].
    fn step(&self, state: &mut LoopState) -> IterationResult;
    /// Return `true` if this strategy is applicable to the current state.
    fn is_applicable(&self, state: &LoopState) -> bool;
}

/// Shared mutable state passed to each strategy step.
#[derive(Debug, Clone)]
pub struct LoopState {
    /// Current quality score.
    pub score: f64,
    /// Current complexity.
    pub complexity: u64,
    /// Iteration index.
    pub iteration: usize,
    /// Arbitrary key-value metadata for strategy communication.
    pub metadata: HashMap<String, f64>,
}

impl LoopState {
    /// Create an initial state.
    #[must_use]
    pub fn new(score: f64, complexity: u64) -> Self {
        Self {
            score,
            complexity,
            iteration: 0,
            metadata: HashMap::new(),
        }
    }

    /// Set a metadata value.
    pub fn set_meta(&mut self, key: impl Into<String>, value: f64) {
        self.metadata.insert(key.into(), value);
    }

    /// Get a metadata value.
    #[must_use]
    pub fn get_meta(&self, key: &str) -> Option<f64> {
        self.metadata.get(key).copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in strategies
// ─────────────────────────────────────────────────────────────────────────────

/// A strategy that always reports convergence (terminal no-op).
pub struct ConvergedStrategy;

impl Strategy for ConvergedStrategy {
    fn name(&self) -> &'static str {
        "converged"
    }
    fn step(&self, _state: &mut LoopState) -> IterationResult {
        IterationResult::Converged
    }
    fn is_applicable(&self, _state: &LoopState) -> bool {
        true
    }
}

/// A strategy that makes a fixed delta improvement per step until a cap.
pub struct FixedDeltaStrategy {
    pub name_str: String,
    pub delta: f64,
    pub complexity_reduction: u64,
    pub max_steps: usize,
    pub steps_taken: std::sync::atomic::AtomicUsize,
}

impl FixedDeltaStrategy {
    /// Create a strategy that applies `delta` per step up to `max_steps`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        delta: f64,
        complexity_reduction: u64,
        max_steps: usize,
    ) -> Self {
        Self {
            name_str: name.into(),
            delta,
            complexity_reduction,
            max_steps,
            steps_taken: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl Strategy for FixedDeltaStrategy {
    fn name(&self) -> &str {
        &self.name_str
    }

    fn step(&self, state: &mut LoopState) -> IterationResult {
        let taken = self
            .steps_taken
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if taken >= self.max_steps {
            return IterationResult::Converged;
        }
        state.score += self.delta;
        state.complexity = state.complexity.saturating_sub(self.complexity_reduction);
        if self.delta > 0.0 {
            IterationResult::Improved {
                delta: self.delta,
                complexity_reduction: self.complexity_reduction as i64,
            }
        } else if self.delta < 0.0 {
            IterationResult::Degraded { delta: self.delta }
        } else {
            IterationResult::NoChange
        }
    }

    fn is_applicable(&self, _state: &LoopState) -> bool {
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConvergenceDetector — detects fixed-point convergence
// ─────────────────────────────────────────────────────────────────────────────

/// Detects when the loop has reached a fixed point by analysing recent deltas.
#[derive(Debug, Clone)]
pub struct ConvergenceDetector {
    /// Window of recent absolute delta values.
    window: std::collections::VecDeque<f64>,
    /// Window size (default 5).
    pub window_size: usize,
    /// Maximum absolute delta to consider converged (default 1e-6).
    pub epsilon: f64,
}

impl Default for ConvergenceDetector {
    fn default() -> Self {
        Self {
            window: std::collections::VecDeque::new(),
            window_size: 5,
            epsilon: 1e-6,
        }
    }
}

impl ConvergenceDetector {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the window size.
    #[must_use]
    pub const fn with_window(mut self, n: usize) -> Self {
        self.window_size = n;
        self
    }

    /// Set the convergence epsilon.
    #[must_use]
    pub const fn with_epsilon(mut self, e: f64) -> Self {
        self.epsilon = e;
        self
    }

    /// Record a new delta and return `true` if convergence is detected.
    pub fn update(&mut self, delta: f64) -> bool {
        self.window.push_back(delta.abs());
        if self.window.len() > self.window_size {
            self.window.pop_front();
        }
        self.is_converged()
    }

    /// Return `true` if all deltas in the window are below epsilon.
    ///
    /// An empty window is never convergence. `all()` over no elements is true by
    /// definition, and `len() >= window_size` holds trivially when `window_size`
    /// is zero — which is reachable, since the field is public and
    /// [`Self::with_window`] does not validate it. Without the emptiness check a
    /// detector reported a fixed point before observing a single delta, so a
    /// loop consulting it would stop at once and report the input as fully
    /// deobfuscated having done no work.
    #[must_use]
    pub fn is_converged(&self) -> bool {
        !self.window.is_empty()
            && self.window.len() >= self.window_size
            && self.window.iter().all(|&d| d < self.epsilon)
    }

    /// Return the mean absolute delta in the current window.
    #[must_use]
    pub fn mean_delta(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        self.window.iter().sum::<f64>() / self.window.len() as f64
    }

    /// Clear the window.
    pub fn reset(&mut self) {
        self.window.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// The main loop orchestrator.
///
/// Drives a sequence of strategies over a shared [`LoopState`], building a
/// [`LoopReport`] of all iterations, quality deltas, and strategy switches.
pub struct LoopOrchestrator {
    /// Maximum number of iterations.
    pub max_iterations: usize,
    /// Minimum absolute quality delta to count as "improved".
    pub improvement_threshold: f64,
    /// Number of consecutive no-change iterations before a strategy switch.
    pub stagnation_threshold: usize,
    /// Whether to log all iterations (not just improvements).
    pub verbose: bool,
}

impl Default for LoopOrchestrator {
    fn default() -> Self {
        Self {
            max_iterations: 100,
            improvement_threshold: 1e-6,
            stagnation_threshold: 5,
            verbose: false,
        }
    }
}

impl LoopOrchestrator {
    /// Create an orchestrator with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set max iterations.
    #[must_use]
    pub const fn with_max_iterations(mut self, n: usize) -> Self {
        self.max_iterations = n;
        self
    }

    /// Set stagnation threshold.
    #[must_use]
    pub const fn with_stagnation_threshold(mut self, n: usize) -> Self {
        self.stagnation_threshold = n;
        self
    }

    /// Run the loop with the given strategies in round-robin order.
    ///
    /// Returns a [`LoopReport`] summarising the run.
    #[must_use]
    pub fn run(&self, strategies: &[Box<dyn Strategy>], initial_state: LoopState) -> LoopReport {
        let mut report = LoopReport::new();
        report.stats.initial_score = initial_state.score;
        report.best_score = initial_state.score;

        if strategies.is_empty() {
            report.termination_reason = "no strategies".into();
            return report;
        }

        let mut state = initial_state;
        let mut stagnation_count = 0usize;
        let mut strategy_idx = 0usize;
        let mut current_strategy_name = strategies[0].name().to_owned();

        info!(
            max_iterations = self.max_iterations,
            initial_score = state.score,
            "loop orchestrator starting"
        );
        for iter_idx in 0..self.max_iterations {
            state.iteration = iter_idx;

            // Pick applicable strategy (round-robin with stagnation switch).
            let strat = &strategies[strategy_idx % strategies.len()];

            if !strat.is_applicable(&state) {
                strategy_idx += 1;
                continue;
            }

            let prev_score = state.score;
            let prev_complexity = state.complexity;

            let result = strat.step(&mut state);

            // Build iteration record.
            let mut iter_rec =
                DeobfIteration::new(iter_idx, strat.name(), prev_score, prev_complexity);
            iter_rec.complete(state.score, state.complexity);
            iter_rec.accepted = result.is_beneficial();
            iter_rec.elapsed_us = 1; // placeholder

            // Update stats.
            report
                .stats
                .record(&result, strat.name(), iter_rec.elapsed_us);

            // Build quality delta.
            let delta = QualityDelta::new(
                iter_idx,
                strat.name(),
                prev_score,
                state.score,
                prev_complexity,
                state.complexity,
            );
            if delta.is_improvement() {
                // Sanitize strategy name to prevent log-injection: replace control
                // characters (newlines, carriage returns, etc.) with a placeholder so
                // that attacker-controlled strategy names cannot forge log records.
                let safe_strategy_name: String = strat
                    .name()
                    .chars()
                    .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
                    .collect();
                debug!(
                    iter = iter_idx,
                    score = state.score,
                    strategy = safe_strategy_name,
                    "iteration accepted"
                );
                report.deltas.push(delta);
                stagnation_count = 0;
            } else {
                debug!(iter = iter_idx, stagnation_count, "no improvement this iteration");
                stagnation_count += 1;
            }

            report.record_iteration(iter_rec);

            // Check convergence.
            if result.should_stop() {
                report.converged = matches!(result, IterationResult::Converged);
                report.termination_reason = if report.converged {
                    "converged".into()
                } else {
                    "error".into()
                };
                break;
            }

            // Stagnation switch.
            if stagnation_count >= self.stagnation_threshold {
                let new_strategy_idx = (strategy_idx + 1) % strategies.len();
                let new_name = strategies[new_strategy_idx].name().to_owned();
                if new_name != current_strategy_name {
                    report.switches.push(StrategySwitch {
                        at_iteration: iter_idx,
                        from: current_strategy_name.clone(),
                        to: new_name.clone(),
                        reason: StrategySwitchReason::Stagnation,
                        score_at_switch: state.score,
                    });
                    report.stats.strategy_switches += 1;
                    current_strategy_name = new_name;
                    strategy_idx = new_strategy_idx;
                    stagnation_count = 0;
                }
            }
        }

        if report.termination_reason.is_empty() {
            report.termination_reason = "max-iterations".into();
        }
        report.stats.final_score = state.score;
        report
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DeobfIteration ────────────────────────────────────────────────────────

    #[test]
    fn test_iteration_new() {
        let it = DeobfIteration::new(0, "xor-pass", 0.5, 100);
        assert_eq!(it.index, 0);
        assert_eq!(it.strategy, "xor-pass");
        assert!(!it.improved);
    }

    #[test]
    fn test_iteration_complete_improved() {
        let mut it = DeobfIteration::new(0, "s", 0.5, 100);
        it.complete(0.8, 80);
        assert!(it.improved);
        assert!((it.delta() - 0.3).abs() < 1e-10);
    }

    #[test]
    fn test_iteration_complete_no_change() {
        let mut it = DeobfIteration::new(0, "s", 0.5, 100);
        it.complete(0.5, 100);
        assert!(!it.improved);
        assert_eq!(it.delta(), 0.0);
    }

    #[test]
    fn test_iteration_complexity_reduction() {
        let mut it = DeobfIteration::new(0, "s", 0.5, 100);
        it.complete(0.6, 80);
        assert_eq!(it.complexity_reduction(), 20);
    }

    // ── IterationResult ───────────────────────────────────────────────────────

    #[test]
    fn test_result_improved_is_beneficial() {
        let r = IterationResult::Improved {
            delta: 0.1,
            complexity_reduction: 10,
        };
        assert!(r.is_beneficial());
        assert!(!r.should_stop());
        assert!((r.delta() - 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_result_no_change() {
        let r = IterationResult::NoChange;
        assert!(!r.is_beneficial());
        assert_eq!(r.delta(), 0.0);
    }

    #[test]
    fn test_result_converged_stops() {
        let r = IterationResult::Converged;
        assert!(r.should_stop());
    }

    #[test]
    fn test_result_error_stops() {
        let r = IterationResult::Error {
            message: "oops".into(),
        };
        assert!(r.should_stop());
    }

    // ── QualityDelta ──────────────────────────────────────────────────────────

    #[test]
    fn test_delta_improvement() {
        let d = QualityDelta::new(0, "s", 0.5, 0.7, 100, 80);
        assert!(d.is_improvement());
        assert!(!d.is_no_change());
        assert_eq!(d.complexity_delta, 20);
    }

    #[test]
    fn test_delta_no_change() {
        let d = QualityDelta::new(1, "s", 0.5, 0.5, 50, 50);
        assert!(d.is_no_change());
    }

    #[test]
    fn test_delta_relative() {
        let d = QualityDelta::new(0, "s", 1.0, 1.5, 100, 100);
        assert!((d.relative - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_delta_relative_zero_prev() {
        let d = QualityDelta::new(0, "s", 0.0, 0.5, 100, 100);
        assert_eq!(d.relative, 0.0); // division by zero guard
    }

    // ── StrategySwitch ────────────────────────────────────────────────────────

    #[test]
    fn test_strategy_switch_reason_labels() {
        assert_eq!(StrategySwitchReason::Stagnation.label(), "stagnation");
        assert_eq!(StrategySwitchReason::Rotation.label(), "rotation");
    }

    #[test]
    fn test_strategy_switch_fields() {
        let sw = StrategySwitch {
            at_iteration: 5,
            from: "A".into(),
            to: "B".into(),
            reason: StrategySwitchReason::BetterStrategyFound,
            score_at_switch: 0.8,
        };
        assert_eq!(sw.at_iteration, 5);
        assert_eq!(sw.reason, StrategySwitchReason::BetterStrategyFound);
    }

    // ── OrchestratorStats ─────────────────────────────────────────────────────

    #[test]
    fn test_stats_empty() {
        let s = OrchestratorStats::new();
        assert_eq!(s.total_iterations, 0);
        assert_eq!(s.improvement_rate(), 0.0);
        assert_eq!(s.total_improvement(), 0.0);
    }

    #[test]
    fn test_stats_record_improved() {
        let mut s = OrchestratorStats::new();
        let r = IterationResult::Improved {
            delta: 0.1,
            complexity_reduction: 5,
        };
        s.record(&r, "test", 100);
        assert_eq!(s.total_iterations, 1);
        assert_eq!(s.improving_iterations, 1);
        assert_eq!(s.improvement_rate(), 1.0);
    }

    #[test]
    fn test_stats_record_mixed() {
        let mut s = OrchestratorStats::new();
        s.record(
            &IterationResult::Improved {
                delta: 0.1,
                complexity_reduction: 0,
            },
            "s",
            1,
        );
        s.record(&IterationResult::NoChange, "s", 1);
        s.record(&IterationResult::Degraded { delta: -0.05 }, "s", 1);
        assert_eq!(s.improving_iterations, 1);
        assert_eq!(s.no_change_iterations, 1);
        assert_eq!(s.degraded_iterations, 1);
    }

    #[test]
    fn test_stats_summary_format() {
        let mut s = OrchestratorStats::new();
        s.final_score = 1.0;
        let sum = s.summary();
        assert!(sum.contains("iterations=0"));
    }

    // ── LoopReport ────────────────────────────────────────────────────────────

    #[test]
    fn test_report_record_iteration() {
        let mut r = LoopReport::new();
        let mut it = DeobfIteration::new(0, "s", 0.5, 100);
        it.complete(0.9, 80);
        r.record_iteration(it);
        assert_eq!(r.iterations.len(), 1);
        assert_eq!(r.best_score, 0.9);
        assert_eq!(r.best_at_iteration, 0);
    }

    #[test]
    fn test_report_best_strategy() {
        let mut r = LoopReport::new();
        let mut it1 = DeobfIteration::new(0, "A", 0.0, 0);
        it1.complete(0.5, 0);
        let mut it2 = DeobfIteration::new(1, "B", 0.5, 0);
        it2.complete(0.6, 0);
        let mut it3 = DeobfIteration::new(2, "A", 0.6, 0);
        it3.complete(0.9, 0);
        r.record_iteration(it1);
        r.record_iteration(it2);
        r.record_iteration(it3);
        assert_eq!(r.best_strategy(), Some("A")); // A improved twice
    }

    #[test]
    fn test_report_top_improvements() {
        let mut r = LoopReport::new();
        r.deltas.push(QualityDelta::new(0, "s", 0.0, 0.5, 100, 100));
        r.deltas.push(QualityDelta::new(1, "s", 0.5, 0.9, 100, 100));
        let top = r.top_improvements(1);
        assert_eq!(top.len(), 1);
        // top_improvements sorts by absolute delta descending, so the larger
        // 0.5 delta comes first, not 0.4.
        assert!((top[0].absolute - 0.5).abs() < 1e-10);
    }

    // ── LoopOrchestrator ──────────────────────────────────────────────────────

    #[test]
    fn test_orchestrator_empty_strategies() {
        let orch = LoopOrchestrator::new();
        let state = LoopState::new(0.0, 100);
        let report = orch.run(&[], state);
        assert_eq!(report.termination_reason, "no strategies");
    }

    #[test]
    fn test_orchestrator_converged_strategy() {
        let orch = LoopOrchestrator::new();
        let strategies: Vec<Box<dyn Strategy>> = vec![Box::new(ConvergedStrategy)];
        let state = LoopState::new(0.0, 100);
        let report = orch.run(&strategies, state);
        assert!(report.converged);
    }

    #[test]
    fn test_orchestrator_fixed_delta_improves() {
        let orch = LoopOrchestrator::new().with_max_iterations(5);
        let strategies: Vec<Box<dyn Strategy>> = vec![Box::new(FixedDeltaStrategy::new(
            "delta-strat",
            0.1,
            10,
            10,
        ))];
        let state = LoopState::new(0.0, 100);
        let report = orch.run(&strategies, state);
        assert!(report.stats.improving_iterations > 0);
        assert!(report.stats.final_score > 0.0);
    }

    #[test]
    fn test_orchestrator_max_iterations() {
        let orch = LoopOrchestrator::new().with_max_iterations(3);
        let strategies: Vec<Box<dyn Strategy>> =
            vec![Box::new(FixedDeltaStrategy::new("noop", 0.0, 0, 100))];
        let state = LoopState::new(0.5, 50);
        let report = orch.run(&strategies, state);
        // Should terminate at max iterations (or stagnation switch, same count).
        assert!(report.stats.total_iterations <= 3);
    }

    #[test]
    fn test_orchestrator_stagnation_switch() {
        let orch = LoopOrchestrator::new()
            .with_max_iterations(20)
            .with_stagnation_threshold(2);
        let strategies: Vec<Box<dyn Strategy>> = vec![
            Box::new(FixedDeltaStrategy::new("stagnant", 0.0, 0, 100)),
            Box::new(FixedDeltaStrategy::new("improver", 0.1, 5, 100)),
        ];
        let state = LoopState::new(0.0, 100);
        let report = orch.run(&strategies, state);
        // Should see at least one strategy switch.
        assert!(report.stats.strategy_switches >= 1 || report.stats.improving_iterations > 0);
    }

    // ── LoopState ─────────────────────────────────────────────────────────────

    #[test]
    fn test_loop_state_metadata() {
        let mut s = LoopState::new(0.5, 100);
        s.set_meta("confidence", 0.9);
        assert_eq!(s.get_meta("confidence"), Some(0.9));
        assert_eq!(s.get_meta("missing"), None);
    }

    #[test]
    fn test_loop_state_new() {
        let s = LoopState::new(1.0, 500);
        assert_eq!(s.score, 1.0);
        assert_eq!(s.complexity, 500);
        assert_eq!(s.iteration, 0);
    }

    // ── Additional coverage tests ─────────────────────────────────────────────

    #[test]
    fn test_iteration_result_degraded_is_not_beneficial() {
        let r = IterationResult::Degraded { delta: -0.1 };
        assert!(!r.is_beneficial());
        assert!(!r.should_stop());
        assert!((r.delta() + 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_quality_delta_improvement_flag_false_when_equal() {
        let d = QualityDelta::new(0, "s", 0.5, 0.5, 100, 100);
        assert!(!d.is_improvement());
        assert!(d.is_no_change());
    }

    #[test]
    fn test_orchestrator_stats_per_strategy() {
        let mut s = OrchestratorStats::new();
        s.record(
            &IterationResult::Improved {
                delta: 0.1,
                complexity_reduction: 0,
            },
            "alpha",
            50,
        );
        s.record(&IterationResult::NoChange, "beta", 30);
        assert_eq!(*s.per_strategy_count.get("alpha").unwrap(), 1);
        assert_eq!(*s.per_strategy_count.get("beta").unwrap(), 1);
    }

    #[test]
    fn test_loop_report_best_score_monotone() {
        let mut r = LoopReport::new();
        for (i, score) in [0.2, 0.8, 0.5, 0.9].iter().enumerate() {
            let mut it = DeobfIteration::new(i, "s", 0.0, 0);
            it.complete(*score, 0);
            r.record_iteration(it);
        }
        assert_eq!(r.best_score, 0.9);
        assert_eq!(r.best_at_iteration, 3);
    }

    #[test]
    fn test_strategy_switch_reason_budget() {
        let sw = StrategySwitch {
            at_iteration: 10,
            from: "a".into(),
            to: "b".into(),
            reason: StrategySwitchReason::IterationBudgetExhausted,
            score_at_switch: 0.6,
        };
        assert_eq!(sw.reason.label(), "budget-exhausted");
    }

    #[test]
    fn test_fixed_delta_strategy_converges() {
        let strat = FixedDeltaStrategy::new("test", 0.1, 0, 3);
        let mut state = LoopState::new(0.0, 100);
        // After 3 steps, should return Converged.
        let _ = strat.step(&mut state);
        let _ = strat.step(&mut state);
        let _ = strat.step(&mut state);
        let r = strat.step(&mut state);
        assert_eq!(r, IterationResult::Converged);
    }

    #[test]
    fn test_converged_strategy_always_converges() {
        let strat = ConvergedStrategy;
        let mut state = LoopState::new(0.5, 50);
        let r = strat.step(&mut state);
        assert_eq!(r, IterationResult::Converged);
        assert!(strat.is_applicable(&state));
    }

    #[test]
    fn test_orchestrator_single_improving_strategy() {
        let orch = LoopOrchestrator::new().with_max_iterations(10);
        let strategies: Vec<Box<dyn Strategy>> =
            vec![Box::new(FixedDeltaStrategy::new("up", 0.05, 5, 20))];
        let state = LoopState::new(0.0, 200);
        let report = orch.run(&strategies, state);
        assert!(report.stats.final_score > 0.0);
        assert!(report.stats.improving_iterations > 0);
    }

    #[test]
    fn test_stats_total_elapsed() {
        let mut s = OrchestratorStats::new();
        s.record(&IterationResult::NoChange, "s", 100);
        s.record(&IterationResult::NoChange, "s", 200);
        assert_eq!(s.total_elapsed_us, 300);
    }

    #[test]
    fn test_loop_report_no_best_strategy_on_empty() {
        let r = LoopReport::new();
        assert!(r.best_strategy().is_none());
    }

    #[test]
    fn test_loop_report_top_improvements_empty() {
        let r = LoopReport::new();
        assert!(r.top_improvements(5).is_empty());
    }
}
