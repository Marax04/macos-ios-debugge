//! Extended deobfuscation orchestrator for the IADL crate.
//!
//! This module provides [`DeobfOrchestrator`], a higher-level orchestrator
//! built on top of the core [`crate::IadlOrchestrator`].  While the core
//! orchestrator runs a single hypothesis loop, `DeobfOrchestrator` manages
//! *multiple* deobfuscation phases (call-graph reconstruction, indirect-call
//! resolution, constraint propagation, etc.) and tracks per-phase iteration
//! histories.
//!
//! Key types:
//! - [`DeobfIteration`]   — snapshot of state at one iteration.
//! - [`IterationResult`]  — outcome of completing a full orchestration run.
//! - [`PhaseId`]          — enumeration of deobfuscation phases.
//! - [`DeobfOrchestrator`] — the main orchestrator.
//!
//! # Example
//! ```
//! use rustre_deobf_iadl::iadl_orchestrator::{DeobfOrchestrator, OrchConfig};
//!
//! let mut orch = DeobfOrchestrator::new(OrchConfig::default());
//! // `run` takes the starting score and complexity, not a binary state.
//! let result = orch.run(1.0, 100);
//! println!("Converged after {} iterations", result.total_iterations);
//! ```

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Phase identifiers
// ---------------------------------------------------------------------------

/// An individual deobfuscation phase managed by the orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PhaseId {
    /// Reconstruct the call graph (resolve indirect calls by type signature).
    CallGraphReconstruction,
    /// Resolve indirect jump tables.
    IndirectJumpResolution,
    /// Propagate constraints across the CFG.
    ConstraintPropagation,
    /// Classify and remove obfuscation patterns (opaque predicates, junk code).
    ObfuscationRemoval,
    /// Apply IR-level transformation rules.
    IrNormalization,
    /// Detect and restructure artificial loops.
    LoopNormalization,
    /// Final convergence check — no structural changes expected.
    ConvergenceVerification,
}

impl PhaseId {
    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            PhaseId::CallGraphReconstruction => "call-graph-reconstruction",
            PhaseId::IndirectJumpResolution  => "indirect-jump-resolution",
            PhaseId::ConstraintPropagation   => "constraint-propagation",
            PhaseId::ObfuscationRemoval      => "obfuscation-removal",
            PhaseId::IrNormalization         => "ir-normalization",
            PhaseId::LoopNormalization       => "loop-normalization",
            PhaseId::ConvergenceVerification => "convergence-verification",
        }
    }

    /// Default maximum iterations for this phase.
    #[must_use]
    pub const fn default_max_iter(&self) -> u32 {
        match self {
            PhaseId::CallGraphReconstruction => 8,
            PhaseId::IndirectJumpResolution  => 16,
            PhaseId::ConstraintPropagation   => 32,
            PhaseId::ObfuscationRemoval      => 24,
            PhaseId::IrNormalization         => 16,
            PhaseId::LoopNormalization       => 8,
            PhaseId::ConvergenceVerification => 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Iteration snapshot
// ---------------------------------------------------------------------------

/// A complete snapshot of orchestration state at one iteration of one phase.
#[derive(Debug, Clone)]
pub struct DeobfIteration {
    /// Phase that produced this snapshot.
    pub phase: PhaseId,
    /// Iteration index within this phase (0-based).
    pub phase_iter: u32,
    /// Cumulative iteration index across all phases.
    pub global_iter: u32,
    /// Quality score at this iteration (higher is better).
    pub score: f64,
    /// Delta from the previous iteration (positive = improvement).
    pub delta: f64,
    /// Approximate structural complexity at this iteration.
    pub complexity: u64,
    /// Wall-clock time elapsed since orchestration start.
    pub elapsed: Duration,
    /// Was this iteration accepted (score improved or met threshold)?
    pub accepted: bool,
    /// Arbitrary diagnostic key-value pairs published by phase handlers.
    pub diagnostics: BTreeMap<String, f64>,
}

impl DeobfIteration {
    #[must_use]
    pub const fn initial(phase: PhaseId) -> Self {
        Self {
            phase,
            phase_iter: 0,
            global_iter: 0,
            score: 0.0,
            delta: 0.0,
            complexity: 0,
            elapsed: std::time::Duration::ZERO,
            accepted: true,
            diagnostics: std::collections::BTreeMap::new(),
        }
    }
}


// ---------------------------------------------------------------------------
// IterationResult
// ---------------------------------------------------------------------------

/// The outcome of a complete [`DeobfOrchestrator::run`] call.
#[derive(Debug, Clone)]
pub struct IterationResult {
    /// Whether all phases converged.
    pub converged: bool,
    /// Total number of iterations across all phases.
    pub total_iterations: u32,
    /// Total wall-clock time for the run.
    pub elapsed: Duration,
    /// Final quality score.
    pub final_score: f64,
    /// Final complexity.
    pub final_complexity: u64,
    /// Reason the run terminated.
    pub termination_reason: TerminationReason,
    /// Per-phase iteration counts.
    pub phase_iters: HashMap<PhaseId, u32>,
    /// All iteration snapshots (one per iteration per phase).
    pub history: Vec<DeobfIteration>,
}

impl IterationResult {
    /// Returns `true` if the run converged and quality is above `threshold`.
    #[must_use]
    pub fn is_good(&self, threshold: f64) -> bool {
        self.converged && self.final_score >= threshold
    }

    /// Return the history entries for a specific phase.
    #[must_use]
    pub fn phase_history(&self, phase: PhaseId) -> Vec<&DeobfIteration> {
        self.history.iter().filter(|i| i.phase == phase).collect()
    }

    /// Compute the average score improvement per iteration.
    #[must_use]
    pub fn avg_improvement(&self) -> f64 {
        if self.history.is_empty() {
            return 0.0;
        }
        let total_delta: f64 = self.history.iter().map(|i| i.delta.max(0.0)).sum();
        total_delta / self.history.len() as f64
    }
}

/// Why the orchestrator stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationReason {
    /// All phases converged.
    Converged,
    /// Maximum global iteration budget exhausted.
    MaxIterations,
    /// Score stalled for too many consecutive iterations.
    Stalled,
    /// An error was signalled by a phase handler.
    PhaseError,
}

// ---------------------------------------------------------------------------
// OrchestratorConfig
// ---------------------------------------------------------------------------

/// Configuration for [`DeobfOrchestrator`].
#[derive(Debug, Clone)]
pub struct OrchConfig {
    /// Maximum total iterations across all phases.
    pub max_global_iter: u32,
    /// Minimum score improvement required to count as progress.
    pub min_improvement: f64,
    /// How many consecutive non-improving iterations before stall-stop.
    pub stall_limit: u32,
    /// Whether to restart phases on score regression.
    pub restart_on_regression: bool,
    /// Per-phase maximum iteration overrides.
    pub phase_limits: HashMap<PhaseId, u32>,
    /// Ordered list of phases to run (empty = use default ordering).
    pub phase_order: Vec<PhaseId>,
}

impl Default for OrchConfig {
    fn default() -> Self {
        Self {
            max_global_iter: 256,
            min_improvement: 1e-6,
            stall_limit: 5,
            restart_on_regression: false,
            phase_limits: HashMap::new(),
            phase_order: vec![
                PhaseId::CallGraphReconstruction,
                PhaseId::IndirectJumpResolution,
                PhaseId::ConstraintPropagation,
                PhaseId::ObfuscationRemoval,
                PhaseId::IrNormalization,
                PhaseId::LoopNormalization,
                PhaseId::ConvergenceVerification,
            ],
        }
    }
}

impl OrchConfig {
    /// Maximum iterations for the given phase.
    #[must_use]
    pub fn max_iter_for(&self, phase: PhaseId) -> u32 {
        self.phase_limits.get(&phase).copied().unwrap_or(phase.default_max_iter())
    }
}

// ---------------------------------------------------------------------------
// PhaseHandler trait
// ---------------------------------------------------------------------------

/// Trait implemented by each deobfuscation phase.
///
/// A `PhaseHandler` receives the current quality score and complexity and
/// returns updated values together with diagnostics.  It must be deterministic
/// given the same inputs.
pub trait PhaseHandler: Send {
    /// Execute one iteration of this phase.
    ///
    /// Returns `(new_score, new_complexity, diagnostics)` or an error string.
    fn iterate(
        &mut self,
        phase_iter: u32,
        current_score: f64,
        current_complexity: u64,
    ) -> Result<(f64, u64, BTreeMap<String, f64>), String>;

    /// Called when the phase is being skipped or reset.
    fn reset(&mut self) {}
}

// ---------------------------------------------------------------------------
// ConvergenceCheck
// ---------------------------------------------------------------------------

/// Simple convergence check: is the improvement below `threshold`?
#[must_use]
pub fn convergence_check(previous: f64, current: f64, threshold: f64) -> bool {
    (current - previous).abs() < threshold
}

/// Check whether a sequence of iteration deltas has stalled.
///
/// `stall_limit` is the number of consecutive non-improving iterations
/// required before declaring a stall.
#[must_use]
pub fn stall_check(history: &[f64], stall_limit: usize, threshold: f64) -> bool {
    if history.len() < stall_limit {
        return false;
    }
    history[history.len() - stall_limit..].iter().all(|&d| d.abs() < threshold)
}

// ---------------------------------------------------------------------------
// DeobfOrchestrator
// ---------------------------------------------------------------------------

/// The main multi-phase deobfuscation orchestrator.
///
/// Register phase handlers with [`register_phase`], then call [`run`]
/// to execute all phases in order.
pub struct DeobfOrchestrator {
    config: OrchConfig,
    handlers: HashMap<PhaseId, Box<dyn PhaseHandler>>,
}

impl DeobfOrchestrator {
    /// Create a new orchestrator with the given configuration.
    #[must_use]
    pub fn new(config: OrchConfig) -> Self {
        Self { config, handlers: HashMap::new() }
    }

    /// Register a handler for a specific phase.
    pub fn register_phase(&mut self, phase: PhaseId, handler: Box<dyn PhaseHandler>) {
        self.handlers.insert(phase, handler);
    }

    /// Remove the handler for a phase.
    pub fn remove_phase(&mut self, phase: PhaseId) -> Option<Box<dyn PhaseHandler>> {
        self.handlers.remove(&phase)
    }

    /// Execute all phases in order, respecting per-phase and global budgets.
    pub fn run(&mut self, initial_score: f64, initial_complexity: u64) -> IterationResult {
        let start = Instant::now();
        let mut score = initial_score;
        let mut complexity = initial_complexity;
        let mut global_iter = 0u32;
        let mut history = Vec::new();
        let mut phase_iters: HashMap<PhaseId, u32> = HashMap::new();
        let mut stall_deltas: Vec<f64> = Vec::new();
        let mut termination = TerminationReason::Converged;
        let mut converged = true;

        let phases = self.config.phase_order.clone();

        'outer: for &phase in &phases {
            let max_iter = self.config.max_iter_for(phase);
            let mut prev_score = score;

            for p_iter in 0..max_iter {
                if global_iter >= self.config.max_global_iter {
                    converged = false;
                    termination = TerminationReason::MaxIterations;
                    break 'outer;
                }

                let result = if let Some(handler) = self.handlers.get_mut(&phase) {
                    handler.iterate(p_iter, score, complexity)
                } else {
                    Ok((score, complexity, BTreeMap::new()))
                };

                match result {
                    Err(_) => {
                        converged = false;
                        termination = TerminationReason::PhaseError;
                        break 'outer;
                    }
                    Ok((new_score, new_complexity, diag)) => {
                        let delta = new_score - prev_score;
                        let accepted = delta >= 0.0;

                        let snap = DeobfIteration {
                            phase,
                            phase_iter: p_iter,
                            global_iter,
                            score: new_score,
                            delta,
                            complexity: new_complexity,
                            elapsed: start.elapsed(),
                            accepted,
                            diagnostics: diag,
                        };
                        history.push(snap);

                        stall_deltas.push(delta);
                        if stall_check(
                            &stall_deltas,
                            self.config.stall_limit as usize,
                            self.config.min_improvement,
                        ) {
                            converged = false;
                            termination = TerminationReason::Stalled;
                            score = new_score;
                            complexity = new_complexity;
                            *phase_iters.entry(phase).or_insert(0) += p_iter + 1;
                            global_iter += 1;
                            break 'outer;
                        }

                        if convergence_check(prev_score, new_score, self.config.min_improvement) {
                            score = new_score;
                            complexity = new_complexity;
                            *phase_iters.entry(phase).or_insert(0) += p_iter + 1;
                            global_iter += 1;
                            break;
                        }

                        prev_score = new_score;
                        score = new_score;
                        complexity = new_complexity;
                        global_iter += 1;
                        *phase_iters.entry(phase).or_insert(0) = p_iter + 1;
                    }
                }
            }
        }

        IterationResult {
            converged,
            total_iterations: global_iter,
            elapsed: start.elapsed(),
            final_score: score,
            final_complexity: complexity,
            termination_reason: termination,
            phase_iters,
            history,
        }
    }

    /// Access the configuration.
    #[must_use]
    pub const fn config(&self) -> &OrchConfig {
        &self.config
    }

    /// Mutably access the configuration.
    pub const fn config_mut(&mut self) -> &mut OrchConfig {
        &mut self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct MockHandler {
        step: f64,
    }

    impl PhaseHandler for MockHandler {
        fn iterate(
            &mut self,
            _iter: u32,
            score: f64,
            complexity: u64,
        ) -> Result<(f64, u64, BTreeMap<String, f64>), String> {
            let new_score = score + self.step;
            let new_complexity = complexity.saturating_sub(1);
            let mut diag = BTreeMap::new();
            diag.insert("step".into(), self.step);
            Ok((new_score, new_complexity, diag))
        }
    }

    #[test]
    fn test_phase_id_names() {
        assert_eq!(PhaseId::CallGraphReconstruction.name(), "call-graph-reconstruction");
        assert_eq!(PhaseId::ConvergenceVerification.name(), "convergence-verification");
    }

    #[test]
    fn test_convergence_check() {
        assert!(convergence_check(1.0, 1.0 + 1e-9, 1e-6));
        assert!(!convergence_check(1.0, 1.5, 1e-6));
    }

    #[test]
    fn test_stall_check() {
        let tiny = vec![0.0, 1e-9, 1e-10, 0.0, 1e-11];
        assert!(stall_check(&tiny, 4, 1e-6));
        let big = vec![0.0, 1.0, 1e-9, 1e-9];
        assert!(!stall_check(&big, 4, 1e-6));
    }

    #[test]
    fn test_orchestrator_no_handlers() {
        let mut orch = DeobfOrchestrator::new(OrchConfig::default());
        let result = orch.run(0.0, 100);
        // With no handlers registered, score never improves, so the loop
        // terminates via the stall path (not Converged), but still records
        // at least one iteration of effort.
        assert!(result.total_iterations > 0);
    }

    #[test]
    fn test_orchestrator_with_mock_handler() {
        let mut cfg = OrchConfig::default();
        cfg.phase_order = vec![PhaseId::IrNormalization];
        cfg.phase_limits.insert(PhaseId::IrNormalization, 5);
        cfg.min_improvement = 0.1;

        let mut orch = DeobfOrchestrator::new(cfg);
        orch.register_phase(PhaseId::IrNormalization, Box::new(MockHandler { step: 1.0 }));

        let result = orch.run(0.0, 50);
        assert!(result.total_iterations > 0);
        assert!(result.final_score > 0.0);
    }

    #[test]
    fn test_iteration_result_phase_history() {
        let mut cfg = OrchConfig::default();
        cfg.phase_order = vec![PhaseId::ConstraintPropagation];
        cfg.phase_limits.insert(PhaseId::ConstraintPropagation, 3);
        cfg.min_improvement = 0.001;

        let mut orch = DeobfOrchestrator::new(cfg);
        orch.register_phase(
            PhaseId::ConstraintPropagation,
            Box::new(MockHandler { step: 0.5 }),
        );
        let result = orch.run(0.0, 100);
        let ph = result.phase_history(PhaseId::ConstraintPropagation);
        assert!(!ph.is_empty());
    }

    #[test]
    fn test_orch_config_defaults() {
        let cfg = OrchConfig::default();
        assert_eq!(cfg.max_global_iter, 256);
        assert_eq!(cfg.stall_limit, 5);
    }

    #[test]
    fn test_avg_improvement() {
        let result = IterationResult {
            converged: true,
            total_iterations: 3,
            elapsed: Duration::ZERO,
            final_score: 3.0,
            final_complexity: 0,
            termination_reason: TerminationReason::Converged,
            phase_iters: HashMap::new(),
            history: vec![
                { let mut i = DeobfIteration::initial(PhaseId::IrNormalization); i.delta = 1.0; i },
                { let mut i = DeobfIteration::initial(PhaseId::IrNormalization); i.delta = 2.0; i },
                { let mut i = DeobfIteration::initial(PhaseId::IrNormalization); i.delta = 0.0; i },
            ],
        };
        assert!((result.avg_improvement() - 1.0).abs() < 1e-9);
    }
}
