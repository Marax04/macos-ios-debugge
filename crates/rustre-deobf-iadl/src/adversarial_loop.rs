//! `adversarial_loop` — iterative adversarial deobfuscation loop (IADL).
//!
//! [`IadlLoop`] drives a feedback-driven deobfuscation cycle:
//! 1. Apply a deobfuscation pass to the current binary.
//! 2. Measure progress via [`ProgressMetric`].
//! 3. If stuck (no improvement), apply an adversarial perturbation and retry.
//! 4. Stop when convergence is detected or the iteration budget is exceeded.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

use crate::convergence_detector::{ConvergenceDetector, ConvergenceState};
use crate::perturbation::{Perturbation, PerturbationType, apply_perturbation};

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the IADL loop.
#[derive(Debug, Error)]
pub enum IadlLoopError {
    /// The initial binary is empty.
    #[error("binary is empty")]
    EmptyBinary,
    /// No deobfuscation passes were registered.
    #[error("no passes registered")]
    NoPasses,
    /// The iteration budget was exhausted without convergence.
    #[error("iteration budget exhausted after {iterations} iterations")]
    BudgetExhausted { iterations: u32 },
    /// An internal calculation error.
    #[error("internal error: {0}")]
    Internal(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// ProgressMetric
// ─────────────────────────────────────────────────────────────────────────────

/// Multi-dimensional progress measurement after one deobfuscation iteration.
///
/// All fields are in `[0.0, 1.0]` unless otherwise noted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgressMetric {
    /// Increase in code coverage (distinct instruction bytes reached).
    pub code_coverage_increase: f64,
    /// Reduction in detected obfuscation patterns (0 = no change, 1 = all removed).
    pub pattern_reduction: f64,
    /// Fraction of string references successfully resolved.
    pub string_recovery_ratio: f64,
    /// Reduction in Shannon entropy normalised to [0,1].
    pub entropy_reduction: f64,
    /// Number of patches applied in this iteration (not normalised).
    pub patches_applied: usize,
    /// Composite progress score (weighted average).
    pub composite: f64,
}

impl ProgressMetric {
    /// Compute from before/after binary snapshots and patch count.
    #[must_use]
    pub fn compute(before: &[u8], after: &[u8], patches: usize) -> Self {
        if before.is_empty() || after.is_empty() {
            return Self::zero();
        }

        let entropy_before = shannon_entropy(before);
        let entropy_after = shannon_entropy(after);
        let entropy_reduction =
            ((entropy_before - entropy_after) / entropy_before.max(1e-12)).clamp(0.0, 1.0);

        // Code coverage increase: more distinct non-NOP bytes in `after` than `before`.
        let cov_before = coverage_score(before);
        let cov_after = coverage_score(after);
        let code_coverage_increase = (cov_after - cov_before).max(0.0).clamp(0.0, 1.0);

        // Pattern reduction: compare opaque-predicate density before and after.
        let pat_before = opaque_predicate_density(before);
        let pat_after = opaque_predicate_density(after);
        let pattern_reduction = if pat_before < 1e-12 {
            0.0
        } else {
            ((pat_before - pat_after) / pat_before).clamp(0.0, 1.0)
        };

        // String recovery: printable-run coverage after.
        let string_recovery_ratio = string_coverage(after);

        let patch_score = (patches as f64 / 50.0).min(1.0);
        let composite = (string_recovery_ratio.mul_add(0.20, code_coverage_increase * 0.25 + pattern_reduction * 0.25)
            + entropy_reduction * 0.20
            + patch_score * 0.10)
            .clamp(0.0, 1.0);

        Self {
            code_coverage_increase,
            pattern_reduction,
            string_recovery_ratio,
            entropy_reduction,
            patches_applied: patches,
            composite,
        }
    }

    /// Return a zero-progress metric.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            code_coverage_increase: 0.0,
            pattern_reduction: 0.0,
            string_recovery_ratio: 0.0,
            entropy_reduction: 0.0,
            patches_applied: 0,
            composite: 0.0,
        }
    }

    /// Returns `true` if composite score exceeds `threshold`.
    #[must_use]
    pub fn has_progress(&self, threshold: f64) -> bool {
        self.composite > threshold
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IadlPass — trait for passes usable by the loop
// ─────────────────────────────────────────────────────────────────────────────

/// A deobfuscation pass usable within the IADL loop.
pub trait IadlPass: Send + Sync {
    /// Short identifier.
    fn name(&self) -> &str;

    /// Returns `true` if this pass is applicable to `data`.
    fn is_applicable(&self, data: &[u8]) -> bool;

    /// Apply the pass to `data` and return the (potentially modified) bytes
    /// and the number of patches applied.
    fn apply(&self, data: &[u8]) -> (Vec<u8>, usize);
}

// ─────────────────────────────────────────────────────────────────────────────
// IterationRecord
// ─────────────────────────────────────────────────────────────────────────────

/// Record for one iteration of the IADL loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterationRecord {
    /// Iteration number (0-based).
    pub iteration: u32,
    /// Name of the pass applied.
    pub pass_name: String,
    /// Progress metric computed after this iteration.
    pub metric: ProgressMetric,
    /// Whether a perturbation was applied before this iteration.
    pub perturbed: bool,
    /// Perturbation type applied (if any).
    pub perturbation_type: Option<PerturbationType>,
    /// Wall-clock time for this iteration.
    pub elapsed_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// IadlLoopConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for [`IadlLoop`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IadlLoopConfig {
    /// Maximum number of iterations.
    pub max_iterations: u32,
    /// Number of consecutive no-progress iterations before applying perturbation.
    pub stuck_threshold: u32,
    /// Minimum composite progress required to be considered "not stuck".
    pub progress_threshold: f64,
    /// Maximum time budget for the entire loop.
    pub time_budget: Duration,
    /// Whether to apply adversarial perturbations when stuck.
    pub adversarial_mode: bool,
}

impl Default for IadlLoopConfig {
    fn default() -> Self {
        Self {
            max_iterations: 64,
            stuck_threshold: 3,
            progress_threshold: 1e-4,
            time_budget: Duration::from_mins(5),
            adversarial_mode: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IadlLoopReport
// ─────────────────────────────────────────────────────────────────────────────

/// Final report produced by [`IadlLoop::run`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IadlLoopReport {
    /// Best binary found by the loop.
    pub best_binary: Vec<u8>,
    /// Progress metric for the best binary (relative to the initial binary).
    pub best_metric: ProgressMetric,
    /// Ordered iteration records.
    pub records: Vec<IterationRecord>,
    /// Convergence state when the loop stopped.
    pub convergence: ConvergenceState,
    /// Total wall-clock time.
    pub elapsed_ms: u64,
    /// Number of perturbations applied.
    pub perturbation_count: u32,
}

impl IadlLoopReport {
    /// Total patches applied across all iterations.
    #[must_use]
    pub fn total_patches(&self) -> usize {
        self.records.iter().map(|r| r.metric.patches_applied).sum()
    }

    /// Iterations that made measurable progress.
    #[must_use]
    pub fn progressive_iterations(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.metric.composite > 1e-6)
            .count()
    }

    /// Human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} iterations, {} patches, best composite {:.4}, convergence: {:?}, {}ms",
            self.records.len(),
            self.total_patches(),
            self.best_metric.composite,
            self.convergence,
            self.elapsed_ms,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IadlLoop
// ─────────────────────────────────────────────────────────────────────────────

/// Iterative adversarial deobfuscation loop.
///
/// Drives a sequence of passes with adversarial perturbation fallback when
/// stuck and a convergence detector to stop early when no further progress
/// is possible.
pub struct IadlLoop {
    passes: Vec<Box<dyn IadlPass>>,
    perturbations: Vec<Perturbation>,
    config: IadlLoopConfig,
    convergence_detector: ConvergenceDetector,
}

impl IadlLoop {
    /// Create a new loop with the given configuration and passes.
    #[must_use]
    pub fn new(config: IadlLoopConfig, passes: Vec<Box<dyn IadlPass>>) -> Self {
        let perturbations = vec![
            Perturbation::new(PerturbationType::NopElimination),
            Perturbation::new(PerturbationType::ConstantSubstitution { constant: 0x42 }),
            Perturbation::new(PerturbationType::JunkCodeRemoval),
            Perturbation::new(PerturbationType::PatternMutation { seed: 0xDEAD }),
        ];
        let max_iter = config.max_iterations;
        Self {
            passes,
            perturbations,
            config,
            convergence_detector: ConvergenceDetector::new(max_iter as usize),
        }
    }

    /// Register an additional perturbation strategy.
    pub fn add_perturbation(&mut self, p: Perturbation) {
        self.perturbations.push(p);
    }

    /// Run the adversarial loop on `initial_binary`.
    ///
    /// # Errors
    /// Returns [`IadlLoopError`] on empty input or no passes.
    pub fn run(&mut self, initial_binary: &[u8]) -> Result<IadlLoopReport, IadlLoopError> {
        if initial_binary.is_empty() {
            return Err(IadlLoopError::EmptyBinary);
        }
        if self.passes.is_empty() {
            return Err(IadlLoopError::NoPasses);
        }

        let wall_start = Instant::now();
        let mut current = initial_binary.to_vec();
        let mut best = current.clone();
        let mut best_metric = ProgressMetric::zero();
        let mut records = Vec::with_capacity(self.config.max_iterations as usize);
        let mut no_progress_count = 0u32;
        let mut perturbation_count = 0u32;
        let mut score_history: VecDeque<f64> = VecDeque::new();
        let mut perturb_index = 0usize;

        info!(max_iterations = self.config.max_iterations, "adversarial loop starting");
        for iteration in 0..self.config.max_iterations {
            if wall_start.elapsed() >= self.config.time_budget {
                debug!(iteration, "time budget exhausted");
                break;
            }

            // ── Convergence check ─────────────────────────────────────────
            let conv = self.convergence_detector.check(&score_history);
            if conv != ConvergenceState::Running {
                return Ok(self.make_report(
                    best,
                    best_metric,
                    records,
                    conv,
                    wall_start,
                    perturbation_count,
                ));
            }

            // ── Apply perturbation if stuck ───────────────────────────────
            let mut perturbed = false;
            let mut perturbation_type = None;

            if self.config.adversarial_mode && no_progress_count >= self.config.stuck_threshold
                && !self.perturbations.is_empty() {
                    let p = &self.perturbations[perturb_index % self.perturbations.len()];
                    current = apply_perturbation(&current, p);
                    perturbed = true;
                    perturbation_type = Some(p.kind);
                    perturbation_count += 1;
                    perturb_index += 1;
                }

            // ── Run all applicable passes ─────────────────────────────────
            let pass_start = Instant::now();
            let snapshot = current.clone();
            let mut total_patches = 0usize;
            let mut last_pass_name = "none".to_owned();

            for pass in &self.passes {
                if pass.is_applicable(&current) {
                    let (result, patches) = pass.apply(&current);
                    current = result;
                    total_patches += patches;
                    pass.name().clone_into(&mut last_pass_name);
                }
            }

            let metric = ProgressMetric::compute(&snapshot, &current, total_patches);
            let elapsed_ms = u64::try_from(pass_start.elapsed().as_millis()).unwrap_or(u64::MAX);

            if metric.has_progress(self.config.progress_threshold) {
                no_progress_count = 0;
                if metric.composite > best_metric.composite {
                    debug!(
                        iteration,
                        composite = metric.composite,
                        "new best candidate accepted"
                    );
                    best.clone_from(&current);
                    best_metric.clone_from(&metric);
                }
            } else {
                debug!(iteration, no_progress_count, "no progress this iteration");
                no_progress_count += 1;
            }

            score_history.push_back(metric.composite);
            if score_history.len() > 16 {
                score_history.pop_front();
            }

            records.push(IterationRecord {
                iteration,
                pass_name: last_pass_name,
                metric,
                perturbed,
                perturbation_type,
                elapsed_ms,
            });
        }

        let conv = self.convergence_detector.check(&score_history);
        Ok(self.make_report(
            best,
            best_metric,
            records,
            conv,
            wall_start,
            perturbation_count,
        ))
    }

    fn make_report(
        &self,
        best_binary: Vec<u8>,
        best_metric: ProgressMetric,
        records: Vec<IterationRecord>,
        convergence: ConvergenceState,
        wall_start: Instant,
        perturbation_count: u32,
    ) -> IadlLoopReport {
        IadlLoopReport {
            best_binary,
            best_metric,
            records,
            convergence,
            elapsed_ms: u64::try_from(wall_start.elapsed().as_millis()).unwrap_or(u64::MAX),
            perturbation_count,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility functions
// ─────────────────────────────────────────────────────────────────────────────

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = f64::from(c) / n;
        p.mul_add(-p.log2(), acc)
    })
}

fn coverage_score(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let non_junk = data.iter().filter(|&&b| b != 0x90 && b != 0x00).count();
    non_junk as f64 / data.len() as f64
}

fn opaque_predicate_density(data: &[u8]) -> f64 {
    if data.len() < 5 {
        return 0.0;
    }
    let count = data
        .windows(5)
        .filter(|w| {
            w[0] == 0x31
                && w[1] == 0xC0
                && w[2] == 0x85
                && w[3] == 0xC0
                && (w[4] == 0x74 || w[4] == 0x75)
        })
        .count();
    (count as f64 / (data.len() as f64 / 5.0)).clamp(0.0, 1.0)
}

fn string_coverage(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut printable = 0usize;
    let mut run = 0usize;
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            run += 1;
            if run >= 4 {
                printable += 1;
            }
        } else {
            run = 0;
        }
    }
    (printable as f64 / data.len() as f64).clamp(0.0, 1.0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial pass that removes NOP bytes.
    struct NopPass;
    impl IadlPass for NopPass {
        fn name(&self) -> &'static str {
            "nop-pass"
        }
        fn is_applicable(&self, data: &[u8]) -> bool {
            data.contains(&0x90)
        }
        fn apply(&self, data: &[u8]) -> (Vec<u8>, usize) {
            let mut count = 0;
            let out = data
                .iter()
                .map(|&b| {
                    if b == 0x90 {
                        count += 1;
                        0x00
                    } else {
                        b
                    }
                })
                .collect();
            (out, count)
        }
    }

    /// A pass that does nothing.
    struct IdentityPass;
    impl IadlPass for IdentityPass {
        fn name(&self) -> &'static str {
            "identity"
        }
        fn is_applicable(&self, _data: &[u8]) -> bool {
            true
        }
        fn apply(&self, data: &[u8]) -> (Vec<u8>, usize) {
            (data.to_vec(), 0)
        }
    }

    #[test]
    fn test_empty_binary_error() {
        let mut lp = IadlLoop::new(IadlLoopConfig::default(), vec![Box::new(IdentityPass)]);
        let err = lp.run(&[]).unwrap_err();
        assert!(matches!(err, IadlLoopError::EmptyBinary));
    }

    #[test]
    fn test_no_passes_error() {
        let mut lp = IadlLoop::new(IadlLoopConfig::default(), vec![]);
        let err = lp.run(&[0x90u8; 8]).unwrap_err();
        assert!(matches!(err, IadlLoopError::NoPasses));
    }

    #[test]
    fn test_nop_pass_runs() {
        let config = IadlLoopConfig {
            max_iterations: 4,
            ..IadlLoopConfig::default()
        };
        let mut lp = IadlLoop::new(config, vec![Box::new(NopPass)]);
        let data = vec![0x90u8; 64];
        let report = lp.run(&data).unwrap();
        assert!(!report.records.is_empty());
    }

    #[test]
    fn test_identity_loop_converges() {
        let config = IadlLoopConfig {
            max_iterations: 32,
            stuck_threshold: 2,
            ..IadlLoopConfig::default()
        };
        let mut lp = IadlLoop::new(config, vec![Box::new(IdentityPass)]);
        let data = b"some test data for the loop.".to_vec();
        let report = lp.run(&data).unwrap();
        assert!(report.convergence != ConvergenceState::Running);
    }

    #[test]
    fn test_progress_metric_compute() {
        let before = vec![0x90u8; 128];
        let mut after = vec![0x00u8; 128]; // NOPs removed
        after.extend_from_slice(b"Hello, World! Nice string coverage here.");
        let after = after[..128].to_vec();
        let m = ProgressMetric::compute(&before, &after, 64);
        assert!(m.patches_applied == 64);
        assert!(m.composite >= 0.0);
    }

    #[test]
    fn test_report_summary_non_empty() {
        let config = IadlLoopConfig {
            max_iterations: 2,
            ..IadlLoopConfig::default()
        };
        let mut lp = IadlLoop::new(config, vec![Box::new(IdentityPass)]);
        let report = lp.run(b"test binary data").unwrap();
        let summary = report.summary();
        assert!(summary.contains("iterations"));
    }
}
