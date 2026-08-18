//! `deobf_orchestrator` — Adaptive deobfuscation pass orchestrator.
//!
//! Runs deobfuscation passes in an adaptive sequence: after each pass,
//! recomputes a quality score, selects the next most-promising pass,
//! manages pass dependencies, and terminates on convergence or max iterations.

use crate::hypothesis_manager::{DeobfPassSpec, HypothesisManager, QualityScore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use ahash::AHashMap as HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// PassCategory
// ─────────────────────────────────────────────────────────────────────────────

/// High-level category of a deobfuscation pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PassCategory {
    /// String decryption (XOR, RC4, etc.).
    StringDecrypt,
    /// MBA simplification.
    Mba,
    /// Opaque predicate elimination.
    OpaquePred,
    /// Control-flow flattening removal.
    CffRemoval,
    /// Dead code elimination.
    DeadCode,
    /// Self-modifying code reconstruction.
    Smc,
    /// Anti-anti-analysis (anti-debug, anti-vm).
    AntiAnti,
    /// Import resolution / IAT fixing.
    IatFix,
    /// Constant propagation.
    ConstProp,
    /// Dataflow simplification.
    Dataflow,
}

impl PassCategory {
    /// Estimated cost of running this pass (higher = more expensive).
    #[must_use]
    pub const fn cost(self) -> u32 {
        match self {
            Self::StringDecrypt => 10,
            Self::Mba => 50,
            Self::OpaquePred => 30,
            Self::CffRemoval => 40,
            Self::DeadCode => 15,
            Self::Smc => 80,
            Self::AntiAnti => 20,
            Self::IatFix => 25,
            Self::ConstProp => 20,
            Self::Dataflow => 35,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Full descriptor for a runnable pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassDescriptor {
    pub spec: DeobfPassSpec,
    pub category: PassCategory,
    /// Which categories must have run before this pass.
    pub prerequisites: Vec<PassCategory>,
    /// Estimated quality improvement (0.0–1.0) if this pass succeeds.
    pub expected_gain: f32,
    /// Whether the pass is deterministic (same output every run).
    pub deterministic: bool,
    /// Maximum times this pass should run in one session.
    pub max_runs: u32,
}

impl PassDescriptor {
    #[must_use]
    pub const fn new(spec: DeobfPassSpec, category: PassCategory) -> Self {
        Self {
            spec,
            category,
            prerequisites: vec![],
            expected_gain: 0.5,
            deterministic: true,
            max_runs: 1,
        }
    }

    #[must_use]
    pub fn with_prereq(mut self, prereq: PassCategory) -> Self {
        self.prerequisites.push(prereq);
        self
    }

    #[must_use]
    pub const fn with_gain(mut self, gain: f32) -> Self {
        self.expected_gain = gain;
        self
    }

    #[must_use]
    pub const fn repeatable(mut self, max: u32) -> Self {
        self.max_runs = max;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of all available deobfuscation passes.
pub struct PassRegistry {
    passes: Vec<PassDescriptor>,
}

impl PassRegistry {
    /// Create the default registry with all built-in passes.
    #[must_use]
    pub fn default_registry() -> Self {
        let mut r = Self { passes: vec![] };

        r.add(
            PassDescriptor::new(
                DeobfPassSpec::new("const-prop", "const_prop"),
                PassCategory::ConstProp,
            )
            .with_gain(0.3)
            .repeatable(3),
        );

        r.add(
            PassDescriptor::new(
                DeobfPassSpec::new("dead-code-elim", "dead_code"),
                PassCategory::DeadCode,
            )
            .with_gain(0.2)
            .repeatable(3),
        );

        r.add(
            PassDescriptor::new(
                DeobfPassSpec::new("string-decrypt-xor", "string_decrypt"),
                PassCategory::StringDecrypt,
            )
            .with_gain(0.6),
        );

        r.add(
            PassDescriptor::new(
                DeobfPassSpec::new("mba-simplify", "mba"),
                PassCategory::Mba,
            )
            .with_prereq(PassCategory::ConstProp)
            .with_gain(0.55)
            .repeatable(2),
        );

        r.add(
            PassDescriptor::new(
                DeobfPassSpec::new("opaque-pred-elim", "opaque"),
                PassCategory::OpaquePred,
            )
            .with_prereq(PassCategory::ConstProp)
            .with_gain(0.50)
            .repeatable(2),
        );

        r.add(
            PassDescriptor::new(
                DeobfPassSpec::new("cff-remove", "cff"),
                PassCategory::CffRemoval,
            )
            .with_prereq(PassCategory::OpaquePred)
            .with_gain(0.65),
        );

        r.add(
            PassDescriptor::new(
                DeobfPassSpec::new("anti-anti-bypass", "anti_anti"),
                PassCategory::AntiAnti,
            )
            .with_gain(0.40),
        );

        r.add(
            PassDescriptor::new(
                DeobfPassSpec::new("iat-fix", "iat_fix"),
                PassCategory::IatFix,
            )
            .with_gain(0.35),
        );

        r.add(
            PassDescriptor::new(
                DeobfPassSpec::new("smc-reconstruct", "smc"),
                PassCategory::Smc,
            )
            .with_gain(0.70),
        );

        r.add(
            PassDescriptor::new(
                DeobfPassSpec::new("dataflow-simplify", "dataflow"),
                PassCategory::Dataflow,
            )
            .with_prereq(PassCategory::ConstProp)
            .with_gain(0.45)
            .repeatable(2),
        );

        r
    }

    pub fn add(&mut self, desc: PassDescriptor) {
        self.passes.push(desc);
    }

    /// Find a pass by spec name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&PassDescriptor> {
        self.passes.iter().find(|p| p.spec.name == name)
    }

    /// Return all passes, sorted by expected gain descending.
    #[must_use]
    pub fn sorted_by_gain(&self) -> Vec<&PassDescriptor> {
        let mut v: Vec<&PassDescriptor> = self.passes.iter().collect();
        // `unwrap()` would panic on a NaN gain; every other ranking in this
        // crate already falls back to `Equal`.
        v.sort_by(|a, b| {
            b.expected_gain
                .partial_cmp(&a.expected_gain)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OrchestratorConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorConfig {
    /// Maximum number of pass iterations before forced termination.
    pub max_iterations: u32,
    /// Convergence threshold: stop if score improves less than this per iteration.
    pub convergence_threshold: f64,
    /// Top-K hypotheses to maintain.
    pub top_k: usize,
    /// Minimum quality score to consider a hypothesis successful.
    pub success_threshold: f64,
    /// Whether to run passes in parallel (requires thread-safe data).
    pub parallel: bool,
    /// Total compute budget (sum of pass costs).
    pub compute_budget: u64,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            max_iterations: 20,
            convergence_threshold: 0.01,
            top_k: 5,
            success_threshold: 0.70,
            parallel: false,
            compute_budget: 10_000,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OrchestratorSession
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks per-session state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorSession {
    pub iteration: u32,
    pub total_cost: u64,
    pub passes_run: Vec<String>,
    pub score_history: Vec<f64>,
    /// Categories of passes already run in this session.
    pub categories_completed: HashSet<String>,
    pub converged: bool,
    pub succeeded: bool,
}

impl OrchestratorSession {
    fn new() -> Self {
        Self {
            iteration: 0,
            total_cost: 0,
            passes_run: Vec::new(),
            score_history: Vec::new(),
            categories_completed: HashSet::new(),
            converged: false,
            succeeded: false,
        }
    }

    /// Check whether convergence has been reached.
    fn check_convergence(&self, threshold: f64) -> bool {
        if self.score_history.len() < 3 {
            return false;
        }
        let n = self.score_history.len();
        let recent_gain = self.score_history[n-1] - self.score_history[n-3];
        recent_gain.abs() < threshold
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of running a single pass.
#[derive(Debug, Clone)]
pub struct PassResult {
    pub pass_name: String,
    pub output: Vec<u8>,
    pub score: QualityScore,
    pub duration_ms: u64,
    pub success: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Central orchestrator that coordinates all deobfuscation passes.
pub struct DeobfOrchestrator {
    config: OrchestratorConfig,
    registry: PassRegistry,
    _hypothesis_mgr: HypothesisManager,
}

impl DeobfOrchestrator {
    /// Create a new orchestrator with the given config and default registry.
    #[must_use]
    pub fn new(config: OrchestratorConfig) -> Self {
        let top_k = config.top_k;
        Self {
            config,
            registry: PassRegistry::default_registry(),
            _hypothesis_mgr: HypothesisManager::new(top_k, 0.05),
        }
    }

    /// Register a custom pass in the registry.
    pub fn register_pass(&mut self, desc: PassDescriptor) {
        self.registry.add(desc);
    }

    /// Select the next pass to run given the current session state.
    ///
    /// Returns `None` if no eligible pass remains.
    fn select_next_pass(
        &self,
        session: &OrchestratorSession,
        run_counts: &HashMap<String, u32>,
    ) -> Option<&PassDescriptor> {
        let completed_cats: HashSet<PassCategory> = self
            .registry
            .passes
            .iter()
            .filter(|p| {
                session
                    .categories_completed
                    .contains(&format!("{:?}", p.category))
            })
            .map(|p| p.category)
            .collect();

        self.registry
            .sorted_by_gain()
            .into_iter()
            .find(|p| {
                // Check budget
                let cost = p.category.cost() as u64;
                if session.total_cost + cost > self.config.compute_budget {
                    return false;
                }
                // Check prerequisites
                for &prereq in &p.prerequisites {
                    if !completed_cats.contains(&prereq) {
                        return false;
                    }
                }
                // Check run count
                let ran = run_counts.get(&p.spec.name).copied().unwrap_or(0);
                ran < p.max_runs
            })
    }

    /// Run a single pass over `data`, returning the result.
    ///
    /// In a real implementation this dispatches to the actual pass implementation.
    /// Here we provide a stub that just applies a simple transformation.
    fn run_pass(
        &self,
        pass: &PassDescriptor,
        data: &[u8],
    ) -> PassResult {
        let start = std::time::Instant::now();

        // Stub: for testing, just return data unchanged (real impl calls the pass).
        let output = self.stub_apply_pass(pass, data);
        let score = QualityScore::compute(&output);
        let duration_ms = start.elapsed().as_millis() as u64;

        PassResult {
            pass_name: pass.spec.name.clone(),
            output,
            score,
            duration_ms,
            success: true,
        }
    }

    /// Stub pass application (for testing / integration skeletons).
    fn stub_apply_pass(&self, pass: &PassDescriptor, data: &[u8]) -> Vec<u8> {
        match pass.category {
            PassCategory::StringDecrypt => {
                // Stub: XOR with 0x00 (identity)
                data.iter().map(|&b| b ^ 0x00).collect()
            }
            PassCategory::DeadCode | PassCategory::ConstProp => {
                data.to_vec() // no-op stub
            }
            _ => data.to_vec(),
        }
    }

    /// Run the full orchestration loop over `initial_data`.
    ///
    /// Returns a summary report.
    pub fn run(&mut self, initial_data: Vec<u8>) -> OrchestrationReport {
        let mut session = OrchestratorSession::new();
        let mut current_data = initial_data;
        let mut run_counts: HashMap<String, u32> = HashMap::new();
        let mut results: Vec<PassResult> = Vec::new();

        let initial_score = QualityScore::compute(&current_data);
        session.score_history.push(initial_score.composite);

        while session.iteration < self.config.max_iterations {
            session.iteration += 1;

            // Check convergence
            if session.check_convergence(self.config.convergence_threshold) {
                session.converged = true;
                break;
            }

            // Select next pass
            let pass = match self.select_next_pass(&session, &run_counts) {
                Some(p) => p,
                None => break, // no more eligible passes
            };

            let pass_name = pass.spec.name.clone();
            let category_str = format!("{:?}", pass.category);
            let pass_cost = pass.category.cost() as u64;

            // Run the pass
            let result = self.run_pass(pass, &current_data);

            session.total_cost += pass_cost;
            session.passes_run.push(pass_name.clone());
            session.categories_completed.insert(category_str);
            *run_counts.entry(pass_name).or_default() += 1;

            let new_score = result.score.composite;
            current_data = result.output.clone();
            session.score_history.push(new_score);

            if new_score >= self.config.success_threshold {
                session.succeeded = true;
            }

            results.push(result);
        }

        let final_score = QualityScore::compute(&current_data);

        OrchestrationReport {
            total_iterations: session.iteration,
            total_cost: session.total_cost,
            passes_applied: session.passes_run.clone(),
            score_history: session.score_history,
            final_data: current_data,
            final_score,
            converged: session.converged,
            succeeded: session.succeeded,
            pass_results: results,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OrchestrationReport
// ─────────────────────────────────────────────────────────────────────────────

/// Final report from an orchestration run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrationReport {
    pub total_iterations: u32,
    pub total_cost: u64,
    pub passes_applied: Vec<String>,
    pub score_history: Vec<f64>,
    pub final_data: Vec<u8>,
    pub final_score: QualityScore,
    pub converged: bool,
    pub succeeded: bool,
    /// Per-pass results (note: not serializable in full — score only here).
    #[serde(skip)]
    pub pass_results: Vec<PassResult>,
}

impl OrchestrationReport {
    /// Human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "OrchestrationReport: iters={} cost={} passes=[{}] \
             final_score={:.3} converged={} succeeded={}",
            self.total_iterations,
            self.total_cost,
            self.passes_applied.join(", "),
            self.final_score.composite,
            self.converged,
            self.succeeded,
        )
    }

    /// Score improvement from initial to final.
    #[must_use]
    pub fn score_delta(&self) -> f64 {
        let first = self.score_history.first().copied().unwrap_or(0.0);
        self.final_score.composite - first
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pass_registry_sorted() {
        let reg = PassRegistry::default_registry();
        let sorted = reg.sorted_by_gain();
        // SMC should be first (0.70)
        assert!(sorted[0].expected_gain >= sorted[1].expected_gain);
    }

    #[test]
    fn test_orchestrator_runs_without_panic() {
        let config = OrchestratorConfig {
            max_iterations: 5,
            compute_budget: 1000,
            ..Default::default()
        };
        let mut orch = DeobfOrchestrator::new(config);
        let data = b"Hello, World! Some deobfuscated text that is very readable.".to_vec();
        let report = orch.run(data);
        assert!(report.total_iterations > 0);
        assert!(!report.passes_applied.is_empty());
    }

    #[test]
    fn test_convergence_detection() {
        let mut session = OrchestratorSession::new();
        session.score_history = vec![0.5, 0.5001, 0.5002];
        assert!(session.check_convergence(0.01));
    }

    #[test]
    fn test_prerequisite_enforcement() {
        let config = OrchestratorConfig {
            max_iterations: 5,
            compute_budget: 100,
            ..Default::default()
        };
        let orch = DeobfOrchestrator::new(config);
        let session = OrchestratorSession::new();
        let run_counts = HashMap::new();

        // MBA requires ConstProp — should not be selected first if budget allows ConstProp
        let first = orch.select_next_pass(&session, &run_counts);
        assert!(first.is_some());
        // MBA should not be the very first because ConstProp is a prerequisite
        if let Some(p) = first {
            assert_ne!(p.category, PassCategory::Mba);
        }
    }
}
