//! Iterative Adversarial Deobfuscation Loop (IADL).
//!
//! This crate contains a deterministic, testable core loop that can orchestrate
//! hypothesis evaluation for deobfuscation tasks.

pub mod adversarial_loop;
pub mod adversarial_tester;
pub mod call_graph_builder;
pub mod deobf_strategy_selector;
pub mod iadl_orchestrator;
pub mod constraint_propagation;
pub mod convergence_detector;
pub mod indirect_target_resolver;
pub mod ir_transform;
pub mod loop_analysis;
pub mod loop_orchestrator;
pub mod obfuscation_classifier;
pub mod perturbation;
pub mod strategy_selector;

use std::collections::BTreeMap;

use rayon::prelude::*;

/// Immutable input state consumed by hypotheses.
#[derive(Debug, Clone, PartialEq)]
pub struct IadlState {
    /// Monotonic iteration index.
    pub iteration: u32,
    /// Current global quality score for the accepted state.
    pub global_score: f64,
    /// Coarse-grained complexity metric (lower is better).
    pub complexity: u64,
    /// Optional score components published by callers.
    pub score_components: BTreeMap<String, f64>,
}

impl IadlState {
    /// Create a new state with an initial score.
    #[must_use] 
    pub const fn new(global_score: f64, complexity: u64) -> Self {
        Self {
            iteration: 0,
            global_score,
            complexity,
            score_components: BTreeMap::new(),
        }
    }
}

/// Candidate result produced by applying a hypothesis.
#[derive(Debug, Clone, PartialEq)]
pub struct TentativeState {
    /// Identifier of the hypothesis that produced this state.
    pub hypothesis_id: String,
    /// Candidate quality score.
    pub score: f64,
    /// Candidate complexity metric.
    pub complexity: u64,
    /// Human-readable reasoning for diagnostics and reporting.
    pub rationale: String,
}

impl TentativeState {
    /// Construct a candidate state.
    #[must_use]
    pub fn new(
        hypothesis_id: impl Into<String>,
        score: f64,
        complexity: u64,
        rationale: impl Into<String>,
    ) -> Self {
        Self {
            hypothesis_id: hypothesis_id.into(),
            score,
            complexity,
            rationale: rationale.into(),
        }
    }
}

/// One hypothesis evaluated by the loop.
pub trait Hypothesis: Send + Sync {
    /// Stable identifier for reporting and tie-breaking.
    fn id(&self) -> &str;

    /// Relative prior confidence (0.0..=1.0).
    fn prior(&self, _state: &IadlState) -> f64 {
        0.5
    }

    /// Apply this hypothesis to produce a tentative state.
    fn apply(&self, state: &IadlState) -> TentativeState;
}

/// Scorer used to re-evaluate tentative states.
pub trait Scorer: Send + Sync {
    /// Name used in reports.
    fn name(&self) -> &str;
    /// Relative scorer weight (0.0..=1.0).
    fn weight(&self) -> f64;
    /// Score a tentative candidate.
    fn score(&self, tentative: &TentativeState, baseline: &IadlState) -> f64;
}

/// Deterministic scoring details for one hypothesis candidate.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateEvaluation {
    /// Candidate after orchestration scoring has been applied.
    pub candidate: TentativeState,
    /// Clamped hypothesis prior used by the orchestrator.
    pub prior: f64,
    /// Weighted average of external scorers before prior adjustment.
    pub scorer_score: f64,
    /// Final score used for ranking and acceptance.
    pub final_score: f64,
    /// Per-scorer contributions in input order.
    pub scorer_breakdown: Vec<ScorerContribution>,
}

/// Contribution from a single scorer.
#[derive(Debug, Clone, PartialEq)]
pub struct ScorerContribution {
    /// Scorer name.
    pub name: String,
    /// Non-negative scorer weight.
    pub weight: f64,
    /// Raw score returned by the scorer.
    pub score: f64,
}

/// Terminal reason for a loop execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// No hypothesis produced an improvement for `max_no_progress` iterations.
    NoProgress,
    /// Iteration budget exhausted.
    IterationBudget,
}

/// Per-iteration diagnostics.
#[derive(Debug, Clone, PartialEq)]
pub struct IterationResult {
    pub iteration: u32,
    pub accepted_hypothesis: Option<String>,
    pub accepted_score: f64,
    pub no_progress_count: u32,
    pub candidates: Vec<CandidateEvaluation>,
}

/// Final report emitted by [`IadlOrchestrator`].
#[derive(Debug, Clone, PartialEq)]
pub struct IadlReport {
    pub final_state: IadlState,
    pub iterations: Vec<IterationResult>,
    pub stop_reason: StopReason,
}

/// Runtime parameters for the loop.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IadlConfig {
    pub max_iterations: u32,
    pub max_no_progress: u32,
    /// Minimum delta required to accept a new state.
    pub min_improvement: f64,
    /// Complexity penalty subtracted per byte/block of candidate complexity.
    pub complexity_penalty: f64,
}

impl Default for IadlConfig {
    fn default() -> Self {
        Self {
            max_iterations: 64,
            max_no_progress: 3,
            min_improvement: 1e-6,
            complexity_penalty: 0.0,
        }
    }
}

/// Simple deterministic orchestrator for IADL.
pub struct IadlOrchestrator {
    config: IadlConfig,
}

impl IadlOrchestrator {
    /// Create an orchestrator with default loop parameters.
    #[must_use]
    pub fn default_config() -> Self {
        Self::default()
    }

    /// Create an orchestrator from explicit runtime parameters.
    #[must_use]
    pub const fn new(config: IadlConfig) -> Self {
        Self { config }
    }

    /// Return the active configuration.
    #[must_use]
    pub const fn config(&self) -> IadlConfig {
        self.config
    }

    /// Run the loop until improvement stops or the iteration budget is reached.
    #[must_use]
    pub fn run(
        &self,
        mut state: IadlState,
        hypotheses: &[Box<dyn Hypothesis>],
        scorers: &[Box<dyn Scorer>],
    ) -> IadlReport {
        let mut results = Vec::with_capacity(self.config.max_iterations as usize);
        let mut no_progress = 0u32;

        for iteration in 0..self.config.max_iterations {
            state.iteration = iteration;
            let evaluations = self.evaluate_all(&state, hypotheses, scorers);
            let best = evaluations.first();

            if let Some(candidate) = best {
                if candidate.final_score > state.global_score + self.config.min_improvement {
                    state.global_score = candidate.final_score;
                    state.complexity = candidate.candidate.complexity;
                    no_progress = 0;
                    results.push(IterationResult {
                        iteration,
                        accepted_hypothesis: Some(candidate.candidate.hypothesis_id.clone()),
                        accepted_score: state.global_score,
                        no_progress_count: no_progress,
                        candidates: evaluations,
                    });
                } else {
                    no_progress += 1;
                    results.push(IterationResult {
                        iteration,
                        accepted_hypothesis: None,
                        accepted_score: state.global_score,
                        no_progress_count: no_progress,
                        candidates: evaluations,
                    });
                }
            } else {
                no_progress += 1;
                results.push(IterationResult {
                    iteration,
                    accepted_hypothesis: None,
                    accepted_score: state.global_score,
                    no_progress_count: no_progress,
                    candidates: evaluations,
                });
            }

            if no_progress >= self.config.max_no_progress {
                return IadlReport {
                    final_state: state,
                    iterations: results,
                    stop_reason: StopReason::NoProgress,
                };
            }
        }

        IadlReport {
            final_state: state,
            iterations: results,
            stop_reason: StopReason::IterationBudget,
        }
    }

    /// Evaluate and sort all hypotheses for the current state.
    ///
    /// Ranking is deterministic: higher final score wins, then lower
    /// complexity, then lexicographically smaller hypothesis id.
    #[must_use]
    pub fn evaluate_all(
        &self,
        state: &IadlState,
        hypotheses: &[Box<dyn Hypothesis>],
        scorers: &[Box<dyn Scorer>],
    ) -> Vec<CandidateEvaluation> {
        let mut evaluations: Vec<_> = hypotheses
            .iter()
            .map(|hypothesis| {
                let mut tentative = hypothesis.apply(state);
                let prior = hypothesis.prior(state).clamp(0.0, 1.0);
                let scoring = weighted_score(&tentative, state, scorers);
                let final_score = scoring.score.mul_add(prior, -(tentative.complexity as f64 * self.config.complexity_penalty))
                    .max(0.0);
                tentative.score = final_score;
                CandidateEvaluation {
                    candidate: tentative,
                    prior,
                    scorer_score: scoring.score,
                    final_score,
                    scorer_breakdown: scoring.contributions,
                }
            })
            .collect();
        evaluations.sort_by(|a, b| {
            b.final_score
                .total_cmp(&a.final_score)
                .then_with(|| a.candidate.complexity.cmp(&b.candidate.complexity))
                .then_with(|| a.candidate.hypothesis_id.cmp(&b.candidate.hypothesis_id))
        });
        evaluations
    }
}

impl Default for IadlOrchestrator {
    fn default() -> Self {
        Self::new(IadlConfig::default())
    }
}

struct WeightedScore {
    score: f64,
    contributions: Vec<ScorerContribution>,
}

fn weighted_score(
    tentative: &TentativeState,
    baseline: &IadlState,
    scorers: &[Box<dyn Scorer>],
) -> WeightedScore {
    if scorers.is_empty() {
        return WeightedScore {
            score: tentative.score,
            contributions: Vec::new(),
        };
    }

    let mut contributions = Vec::with_capacity(scorers.len());
    let (total, weight) = scorers.iter().fold((0.0, 0.0), |(sum, wsum), scorer| {
        let w = scorer.weight().max(0.0);
        let score = scorer.score(tentative, baseline);
        contributions.push(ScorerContribution {
            name: scorer.name().to_string(),
            weight: w,
            score,
        });
        (score.mul_add(w, sum), wsum + w)
    });

    let score = if weight > 0.0 {
        total / weight
    } else {
        tentative.score
    };

    WeightedScore {
        score,
        contributions,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §37.1-37.2  IADL — Binary protection layer analysis and convergent loop
// ─────────────────────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ── ProtectionLayer ──────────────────────────────────────────────────────────

/// A coarse-grained protection technique identified in a binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionLayer {
    /// Packer (e.g. UPX, MPRESS). The inner string is the packer name.
    Packer(String),
    /// VM-based obfuscation (e.g. Themida, VMP). The string identifies the engine.
    VmObfuscation(String),
    /// Anti-debug technique. The `u32` is a bit-flag summary of detected tricks.
    AntiDebug(u32),
    /// Encrypted / obfuscated string literals.
    StringEncryption,
    /// Control-flow flattening (state-machine dispatcher).
    CflFlattening,
    /// Opaque predicates injected to hide true control flow.
    OpaquePredicates,
    /// Mixed Boolean Arithmetic expression obfuscation.
    MbaObfuscation,
}

impl ProtectionLayer {
    /// Human-readable name for the layer.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Packer(_) => "Packer",
            Self::VmObfuscation(_) => "VM Obfuscation",
            Self::AntiDebug(_) => "Anti-Debug",
            Self::StringEncryption => "String Encryption",
            Self::CflFlattening => "Control-Flow Flattening",
            Self::OpaquePredicates => "Opaque Predicates",
            Self::MbaObfuscation => "MBA Obfuscation",
        }
    }

    /// Estimated cost (in arbitrary units) to remove this layer.
    #[must_use]
    pub const fn removal_cost(&self) -> u32 {
        match self {
            Self::Packer(_) => 10,
            Self::VmObfuscation(_) => 100,
            Self::AntiDebug(_) => 20,
            Self::StringEncryption => 30,
            Self::CflFlattening => 50,
            Self::OpaquePredicates => 40,
            Self::MbaObfuscation => 60,
        }
    }
}

// ── BinaryIadlState ──────────────────────────────────────────────────────────

/// Rich analysis state populated from a static binary scan (§37.1).
///
/// This is deliberately separate from the generic [`IadlState`] used by the
/// orchestrator so that the two models can coexist without conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryIadlState {
    /// Monotonic iteration index (mirrors [`IadlState::iteration`]).
    pub iteration: u32,
    /// Current global quality score for the accepted state.
    pub global_score: f64,
    /// Protection layers identified so far.
    pub identified_layers: Vec<ProtectionLayer>,
    /// Size of the binary in bytes.
    pub binary_size: usize,
    /// Number of functions recognised at this point.
    pub function_count: u32,
    /// Section names (or synthetic labels) judged to have high entropy.
    pub high_entropy_sections: Vec<String>,
}

impl BinaryIadlState {
    /// Construct a minimal initial state from a binary's basic stats.
    #[must_use]
    pub const fn new(binary_size: usize, function_count: u32) -> Self {
        Self {
            iteration: 0,
            global_score: 0.0,
            identified_layers: Vec::new(),
            binary_size,
            function_count,
            high_entropy_sections: Vec::new(),
        }
    }

    /// Return `true` if the named section/label is in the high-entropy list.
    #[must_use]
    pub fn is_high_entropy(&self, section: &str) -> bool {
        self.high_entropy_sections.iter().any(|s| s == section)
    }

    /// Return `true` if any packer layer has been identified.
    #[must_use]
    pub fn has_packer(&self) -> bool {
        self.identified_layers
            .iter()
            .any(|l| matches!(l, ProtectionLayer::Packer(_)))
    }
}

// ── BinaryTentativeState ─────────────────────────────────────────────────────

/// Proposed deobfuscation outcome produced by a [`BinaryHypothesis`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryTentativeState {
    /// Name of the hypothesis that produced this candidate.
    pub hypothesis_name: String,
    /// Human-readable description of each proposed modification.
    pub modifications: Vec<String>,
    /// Heuristic: how "natural" the code would look after applying this pass (0.0–1.0).
    pub estimated_naturalness: f64,
    /// Heuristic: reduction in structural complexity, normalised to 0.0–1.0.
    pub estimated_complexity_reduction: f64,
}

impl BinaryTentativeState {
    /// Weighted combined score used for candidate ranking (§37.2).
    ///
    /// `combined = naturalness * 0.6 + complexity_reduction * 0.4`
    #[must_use]
    pub fn combined_score(&self) -> f64 {
        self.estimated_naturalness.mul_add(0.6, self.estimated_complexity_reduction * 0.4)
            .clamp(0.0, 1.0)
    }
}

// ── BinaryHypothesis trait ───────────────────────────────────────────────────

/// A binary-level deobfuscation hypothesis (§37.2).
///
/// Each implementation encapsulates both the *detection* logic (`prior`) and
/// the *proposed action* (`apply`).  Implementations must be `Send + Sync` so
/// that [`BinaryIadlOrchestrator`] can evaluate them in parallel via `rayon`.
pub trait BinaryHypothesis: Send + Sync {
    /// Stable numeric identifier — must be unique among registered hypotheses.
    fn id(&self) -> u64;

    /// Human-readable label used in reports.
    fn name(&self) -> &str;

    /// Bayesian prior: probability (0.0–1.0) that this technique applies given
    /// the current `state`.  May inspect `state.identified_layers`,
    /// `state.high_entropy_sections`, etc.
    fn prior(&self, state: &BinaryIadlState) -> f64;

    /// Produce a tentative deobfuscation candidate for the given state.
    fn apply(&self, state: &BinaryIadlState) -> BinaryTentativeState;

    /// Rough wall-clock cost estimate for applying this hypothesis.
    fn cost_estimate(&self) -> std::time::Duration;
}

// ── Built-in hypothesis implementations ──────────────────────────────────────

/// UPX packer detection and unpack hypothesis.
///
/// Prior is elevated when UPX section markers are present in the binary
/// (`high_entropy_sections` contains "UPX0" or "UPX1").
pub struct UPXUnpackHypothesis;

impl BinaryHypothesis for UPXUnpackHypothesis {
    fn id(&self) -> u64 {
        0x0001
    }
    fn name(&self) -> &'static str {
        "UPXUnpack"
    }

    fn prior(&self, state: &BinaryIadlState) -> f64 {
        let has_upx = state
            .high_entropy_sections
            .iter()
            .any(|s| s.contains("UPX0") || s.contains("UPX1"));
        if has_upx { 0.8 } else { 0.1 }
    }

    fn apply(&self, state: &BinaryIadlState) -> BinaryTentativeState {
        let has_upx = state
            .high_entropy_sections
            .iter()
            .any(|s| s.contains("UPX0") || s.contains("UPX1"));
        let (naturalness, reduction) = if has_upx { (0.85, 0.70) } else { (0.30, 0.10) };
        BinaryTentativeState {
            hypothesis_name: self.name().to_owned(),
            modifications: vec![
                "Decompress UPX stub".to_owned(),
                "Restore original PE section layout".to_owned(),
                "Rebuild import table from stubs".to_owned(),
            ],
            estimated_naturalness: naturalness,
            estimated_complexity_reduction: reduction,
        }
    }

    fn cost_estimate(&self) -> std::time::Duration {
        std::time::Duration::from_millis(200)
    }
}

/// Control-flow flattening removal hypothesis.
///
/// Prior is elevated when a large state-machine dispatcher function is likely
/// present.  We use a heuristic: binary has many functions and the dispatcher
/// section is flagged as high-entropy.
pub struct CflFlatteningHypothesis;

impl BinaryHypothesis for CflFlatteningHypothesis {
    fn id(&self) -> u64 {
        0x0002
    }
    fn name(&self) -> &'static str {
        "CflFlattening"
    }

    fn prior(&self, state: &BinaryIadlState) -> f64 {
        // Heuristic: large function count + no existing CFL layer identified yet
        let already = state
            .identified_layers
            .iter()
            .any(|l| matches!(l, ProtectionLayer::CflFlattening));
        if already {
            return 0.05;
        }
        if state.function_count > 50 { 0.7 } else { 0.2 }
    }

    fn apply(&self, state: &BinaryIadlState) -> BinaryTentativeState {
        let gain = if state.function_count > 100 {
            0.65
        } else {
            0.45
        };
        BinaryTentativeState {
            hypothesis_name: self.name().to_owned(),
            modifications: vec![
                "Identify state-machine dispatcher switch".to_owned(),
                "Recover original CFG edges from state variables".to_owned(),
                "Rewrite dispatcher into straight-line / conditional jumps".to_owned(),
                "Remove dead state-variable assignments".to_owned(),
            ],
            estimated_naturalness: 0.70,
            estimated_complexity_reduction: gain,
        }
    }

    fn cost_estimate(&self) -> std::time::Duration {
        std::time::Duration::from_secs(2)
    }
}

/// Opaque-predicate elimination hypothesis.
///
/// Prior is elevated when many single-target (always-taken / never-taken)
/// conditional branches are present — approximated by a high function count
/// with many small functions.
pub struct OpaquePredicateHypothesis;

impl BinaryHypothesis for OpaquePredicateHypothesis {
    fn id(&self) -> u64 {
        0x0003
    }
    fn name(&self) -> &'static str {
        "OpaquePredicates"
    }

    fn prior(&self, state: &BinaryIadlState) -> f64 {
        let already = state
            .identified_layers
            .iter()
            .any(|l| matches!(l, ProtectionLayer::OpaquePredicates));
        if already {
            return 0.05;
        }
        // High function count relative to binary size → many tiny trampolines
        let density = f64::from(state.function_count) / (state.binary_size.max(1) as f64 / 1024.0);
        if density > 2.0 { 0.6 } else { 0.25 }
    }

    fn apply(&self, _state: &BinaryIadlState) -> BinaryTentativeState {
        BinaryTentativeState {
            hypothesis_name: self.name().to_owned(),
            modifications: vec![
                "Symbolically evaluate branch conditions".to_owned(),
                "Resolve always-taken / never-taken branches".to_owned(),
                "Remove dead code blocks guarded by opaque predicates".to_owned(),
            ],
            estimated_naturalness: 0.65,
            estimated_complexity_reduction: 0.55,
        }
    }

    fn cost_estimate(&self) -> std::time::Duration {
        std::time::Duration::from_secs(3)
    }
}

/// String-encryption removal hypothesis.
///
/// Elevated prior when many small functions with loop + XOR patterns are
/// detected (approximated by high-entropy sections and a moderate function
/// count).
pub struct StringDecryptHypothesis;

impl BinaryHypothesis for StringDecryptHypothesis {
    fn id(&self) -> u64 {
        0x0004
    }
    fn name(&self) -> &'static str {
        "StringDecrypt"
    }

    fn prior(&self, state: &BinaryIadlState) -> f64 {
        let already = state
            .identified_layers
            .iter()
            .any(|l| matches!(l, ProtectionLayer::StringEncryption));
        if already {
            return 0.05;
        }
        // High-entropy sections + moderate function count → likely encrypted strings
        let has_entropy = !state.high_entropy_sections.is_empty();
        if has_entropy && state.function_count > 20 {
            0.5
        } else {
            0.15
        }
    }

    fn apply(&self, _state: &BinaryIadlState) -> BinaryTentativeState {
        BinaryTentativeState {
            hypothesis_name: self.name().to_owned(),
            modifications: vec![
                "Identify XOR/RC4 string-decryption stubs".to_owned(),
                "Emulate stubs to recover plaintext strings".to_owned(),
                "Replace encrypted byte arrays with string literals".to_owned(),
                "Remove now-dead decryption helper functions".to_owned(),
            ],
            estimated_naturalness: 0.75,
            estimated_complexity_reduction: 0.50,
        }
    }

    fn cost_estimate(&self) -> std::time::Duration {
        std::time::Duration::from_millis(800)
    }
}

/// Anti-debug bypass hypothesis.
///
/// Very high prior when well-known anti-debug API names are detected in the
/// import list (represented as high-entropy sections named after them, as a
/// static-analysis approximation).
pub struct AntiDebugHypothesis;

impl BinaryHypothesis for AntiDebugHypothesis {
    fn id(&self) -> u64 {
        0x0005
    }
    fn name(&self) -> &'static str {
        "AntiDebug"
    }

    fn prior(&self, state: &BinaryIadlState) -> f64 {
        let already = state
            .identified_layers
            .iter()
            .any(|l| matches!(l, ProtectionLayer::AntiDebug(_)));
        if already {
            return 0.05;
        }
        // Check for known anti-debug section / import markers
        let markers = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugString",
        ];
        let found = markers
            .iter()
            .any(|m| state.high_entropy_sections.iter().any(|s| s.contains(m)));
        if found { 0.9 } else { 0.2 }
    }

    fn apply(&self, state: &BinaryIadlState) -> BinaryTentativeState {
        let has_markers = state
            .high_entropy_sections
            .iter()
            .any(|s| s.contains("IsDebuggerPresent") || s.contains("CheckRemoteDebugger"));
        let naturalness = if has_markers { 0.80 } else { 0.45 };
        BinaryTentativeState {
            hypothesis_name: self.name().to_owned(),
            modifications: vec![
                "Patch IsDebuggerPresent to always return 0".to_owned(),
                "NOP CheckRemoteDebuggerPresent calls".to_owned(),
                "Neutralise timing-based anti-debug loops".to_owned(),
            ],
            estimated_naturalness: naturalness,
            estimated_complexity_reduction: 0.30,
        }
    }

    fn cost_estimate(&self) -> std::time::Duration {
        std::time::Duration::from_millis(100)
    }
}

/// VM-obfuscation lift hypothesis.
///
/// Elevated prior when a large computed-jump dispatcher is suspected (binary
/// has very few recognisable functions relative to its size, and a high
/// proportion of high-entropy sections).
pub struct VmObfuscationHypothesis;

impl BinaryHypothesis for VmObfuscationHypothesis {
    fn id(&self) -> u64 {
        0x0006
    }
    fn name(&self) -> &'static str {
        "VmObfuscation"
    }

    fn prior(&self, state: &BinaryIadlState) -> f64 {
        let already = state
            .identified_layers
            .iter()
            .any(|l| matches!(l, ProtectionLayer::VmObfuscation(_)));
        if already {
            return 0.05;
        }
        // Very few functions but large binary → likely VM bytecode
        let fn_density = f64::from(state.function_count) / (state.binary_size.max(1) as f64 / 1024.0);
        let many_entropy = state.high_entropy_sections.len() >= 2;
        if fn_density < 0.5 && many_entropy {
            0.6
        } else {
            0.15
        }
    }

    fn apply(&self, _state: &BinaryIadlState) -> BinaryTentativeState {
        BinaryTentativeState {
            hypothesis_name: self.name().to_owned(),
            modifications: vec![
                "Identify VM handler table and dispatcher loop".to_owned(),
                "Lift VM bytecode to intermediate representation".to_owned(),
                "Reconstruct native CFG from lifted IR".to_owned(),
                "Emit deobfuscated pseudo-code".to_owned(),
            ],
            estimated_naturalness: 0.55,
            estimated_complexity_reduction: 0.80,
        }
    }

    fn cost_estimate(&self) -> std::time::Duration {
        std::time::Duration::from_secs(10)
    }
}

// ── NaturalnessScorer ────────────────────────────────────────────────────────

/// Heuristic scorer that estimates how "natural" the deobfuscated code will look
/// after a hypothesis is applied.
///
/// Scoring heuristics (§37.2):
/// - Fewer modifications → higher base score (each extra step adds noise risk).
/// - Higher complexity reduction → better.
/// - Known well-defined techniques (UPX, anti-debug) → boost.
pub struct NaturalnessScorer;

impl NaturalnessScorer {
    /// Score a [`BinaryTentativeState`] on a 0.0–1.0 scale.
    #[must_use]
    pub fn score(state: &BinaryTentativeState) -> f64 {
        // Base: fewer modifications are safer
        let mod_count = state.modifications.len() as f64;
        let base = (mod_count - 1.0).max(0.0).mul_add(-0.05, 1.0).max(0.5);

        // Complexity reduction bonus
        let cr_bonus = state.estimated_complexity_reduction * 0.3;

        // Pattern-match boost: UPX / anti-debug are well-understood
        let pattern_boost =
            if state.hypothesis_name == "UPXUnpack" || state.hypothesis_name == "AntiDebug" {
                0.10
            } else {
                0.0
            };

        state.estimated_naturalness.mul_add(0.2, base + cr_bonus + pattern_boost).clamp(0.0, 1.0)
    }
}

// ── BinaryIadlReport ─────────────────────────────────────────────────────────

/// Final report emitted by [`BinaryIadlOrchestrator::run`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryIadlReport {
    /// Number of loop iterations completed.
    pub iterations_run: u32,
    /// Protection layers conclusively identified.
    pub layers_identified: Vec<ProtectionLayer>,
    /// Names of hypotheses that were accepted and applied.
    pub applied_passes: Vec<String>,
    /// Final global quality score.
    pub final_score: f64,
    /// Actionable textual recommendations for the analyst.
    pub recommendations: Vec<String>,
    /// Wall-clock time spent in milliseconds.
    pub time_elapsed_ms: u64,
}

impl BinaryIadlReport {
    /// Return `true` if at least one pass was applied.
    #[must_use]
    pub const fn has_progress(&self) -> bool {
        !self.applied_passes.is_empty()
    }

    /// Return the highest-priority recommendation, if any.
    #[must_use]
    pub fn top_recommendation(&self) -> Option<&str> {
        self.recommendations.first().map(std::string::String::as_str)
    }

    /// Serialise this report to a JSON string for tooling integration.
    ///
    /// # Errors
    /// Returns an error if serialisation fails (should not happen for
    /// well-formed report data).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialise a report from a JSON string.
    ///
    /// # Errors
    /// Returns an error if the JSON is malformed or missing required fields.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

// ── BinaryIadlOrchestrator ───────────────────────────────────────────────────

/// Convergent multi-hypothesis deobfuscation loop (§37.2).
///
/// On each iteration the orchestrator:
/// 1. Computes priors for all registered hypotheses.
/// 2. Applies the top-ranked hypotheses (optionally in parallel via `rayon`).
/// 3. Scores each tentative state with [`NaturalnessScorer`].
/// 4. Accepts the best candidate if it exceeds an improvement threshold.
/// 5. Stops when no progress has been made for `max_no_progress_iters`
///    consecutive iterations, or when the iteration budget is exhausted.
pub struct BinaryIadlOrchestrator {
    /// Registered hypotheses.
    hypotheses: Vec<Box<dyn BinaryHypothesis>>,
    /// Maximum number of iterations.
    pub max_iterations: u32,
    /// Wall-clock budget in seconds.
    pub budget_secs: u64,
    /// Stop after this many consecutive no-improvement iterations.
    max_no_progress_iters: u32,
    /// Minimum score improvement required to accept a candidate.
    min_improvement: f64,
}

impl Default for BinaryIadlOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryIadlOrchestrator {
    /// Create a new orchestrator with all built-in hypotheses registered.
    #[must_use]
    pub fn new() -> Self {
        let hypotheses: Vec<Box<dyn BinaryHypothesis>> = vec![
            Box::new(UPXUnpackHypothesis),
            Box::new(CflFlatteningHypothesis),
            Box::new(OpaquePredicateHypothesis),
            Box::new(StringDecryptHypothesis),
            Box::new(AntiDebugHypothesis),
            Box::new(VmObfuscationHypothesis),
        ];
        Self {
            hypotheses,
            max_iterations: 32,
            budget_secs: 60,
            max_no_progress_iters: 3,
            min_improvement: 1e-4,
        }
    }

    /// Register an additional hypothesis.
    pub fn register(&mut self, hypothesis: Box<dyn BinaryHypothesis>) {
        self.hypotheses.push(hypothesis);
    }

    /// Run the convergent loop on a pre-populated [`BinaryIadlState`].
    ///
    /// Returns a [`BinaryIadlReport`] summarising the outcome.
    #[must_use]
    pub fn run_state(&mut self, mut state: BinaryIadlState) -> BinaryIadlReport {
        use std::time::Instant;
        let start = Instant::now();
        let budget = std::time::Duration::from_secs(self.budget_secs);

        let mut applied_passes: Vec<String> = Vec::with_capacity(self.max_iterations as usize);
        let mut no_progress: u32 = 0;
        let mut iterations_run = 0u32;

        for iter in 0..self.max_iterations {
            if start.elapsed() >= budget {
                break;
            }
            state.iteration = iter;
            iterations_run += 1;

            // Rank hypotheses by prior descending.
            let mut ranked: Vec<(&dyn BinaryHypothesis, f64)> =
                Vec::with_capacity(self.hypotheses.len());
            ranked.extend(self.hypotheses.iter().map(|h| (h.as_ref(), h.prior(&state))));
            ranked.sort_by(|a, b| b.1.total_cmp(&a.1));

            // Apply and score candidates in parallel via rayon (BinaryHypothesis: Send + Sync).
            let acceptance_threshold = state.global_score + self.min_improvement;

            // Evaluate all sufficiently-confident hypotheses in parallel.
            let evaluated: Vec<(BinaryTentativeState, f64, f64)> = ranked
                .par_iter()
                .filter(|(_, prior)| *prior >= 0.05)
                .map(|(hypothesis, prior)| {
                    let candidate = hypothesis.apply(&state);
                    let naturalness_score = NaturalnessScorer::score(&candidate);
                    let combined = candidate.combined_score();
                    let final_rank = naturalness_score.mul_add(0.1, combined * prior);
                    (candidate, combined, final_rank)
                })
                .collect();

            // Pick the best candidate from the parallel results.
            // best_rank tracks the best combined rank for threshold comparison;
            // it must NOT be mixed with global_score which holds a normalised
            // quality metric on a different scale.
            let mut best_candidate: Option<BinaryTentativeState> = None;
            let mut best_rank = f64::NEG_INFINITY;
            for (candidate, combined, final_rank) in evaluated {
                if final_rank > best_rank {
                    best_rank = final_rank;
                    if combined > acceptance_threshold {
                        best_candidate = Some(candidate);
                    }
                }
            }

            if let Some(candidate) = best_candidate {
                // Accept this candidate: update state using the normalised
                // combined_score so global_score stays on a consistent scale.
                let pass_name = candidate.hypothesis_name.clone();
                state.global_score = candidate.combined_score();

                // Infer ProtectionLayer from hypothesis name.
                let layer = infer_protection_layer(&pass_name, &state);
                if let Some(l) = layer
                    && !state.identified_layers.contains(&l) {
                        state.identified_layers.push(l);
                    }

                applied_passes.push(pass_name);
                no_progress = 0;
            } else {
                no_progress += 1;
                if no_progress >= self.max_no_progress_iters {
                    break;
                }
            }
        }

        let elapsed_raw = start.elapsed().as_millis();
        let elapsed_ms = u64::try_from(elapsed_raw).unwrap_or(u64::MAX);
        let recommendations = build_recommendations(&state, &applied_passes);

        BinaryIadlReport {
            iterations_run,
            final_score: state.global_score,
            layers_identified: state.identified_layers,
            applied_passes,
            recommendations,
            time_elapsed_ms: elapsed_ms,
        }
    }

    /// Convenience entry-point: scan the binary, build initial state, then run
    /// the loop.
    #[must_use]
    pub fn run(&mut self, binary: &[u8]) -> BinaryIadlReport {
        let state = analyze_binary_for_protections(binary);
        self.run_state(state)
    }
}

// ── Helper: infer protection layer from hypothesis name ──────────────────────

fn infer_protection_layer(pass_name: &str, _state: &BinaryIadlState) -> Option<ProtectionLayer> {
    match pass_name {
        "UPXUnpack" => Some(ProtectionLayer::Packer("UPX".to_owned())),
        "CflFlattening" => Some(ProtectionLayer::CflFlattening),
        "OpaquePredicates" => Some(ProtectionLayer::OpaquePredicates),
        "StringDecrypt" => Some(ProtectionLayer::StringEncryption),
        "AntiDebug" => Some(ProtectionLayer::AntiDebug(0b0111)),
        "VmObfuscation" => Some(ProtectionLayer::VmObfuscation("unknown".to_owned())),
        _ => None,
    }
}

// ── Helper: generate analyst recommendations ─────────────────────────────────

fn build_recommendations(state: &BinaryIadlState, applied: &[String]) -> Vec<String> {
    let mut recs: Vec<String> = Vec::new();

    for layer in &state.identified_layers {
        match layer {
            ProtectionLayer::Packer(name) => {
                recs.push(format!(
                    "Binary is packed with {name}. Run upx -d or equivalent before deeper analysis."
                ));
            }
            ProtectionLayer::VmObfuscation(engine) => {
                recs.push(format!(
                    "VM obfuscation engine '{engine}' detected. Use a VM-lift pass before \
                     CFG reconstruction."
                ));
            }
            ProtectionLayer::AntiDebug(_flags) => {
                recs.push(
                    "Anti-debug tricks detected. Patch IsDebuggerPresent / timing checks \
                     before dynamic analysis."
                        .to_owned(),
                );
            }
            ProtectionLayer::StringEncryption => {
                recs.push(
                    "Encrypted strings detected. Emulate decryption stubs to recover \
                     plaintext before string-based analysis."
                        .to_owned(),
                );
            }
            ProtectionLayer::CflFlattening => {
                recs.push(
                    "Control-flow flattening detected. Apply a CFF removal pass to recover \
                     readable CFGs."
                        .to_owned(),
                );
            }
            ProtectionLayer::OpaquePredicates => {
                recs.push(
                    "Opaque predicates detected. Apply symbolic evaluation to resolve \
                     always-taken / never-taken branches."
                        .to_owned(),
                );
            }
            ProtectionLayer::MbaObfuscation => {
                recs.push(
                    "MBA obfuscation detected. Apply simplification pass (e.g. sspam) to \
                     recover arithmetic intent."
                        .to_owned(),
                );
            }
        }
    }

    if applied.is_empty() {
        recs.push(
            "No deobfuscation passes were applied. Binary may be clean or analysis budget \
             was exhausted."
                .to_owned(),
        );
    }

    // Generic hygiene advice
    recs.push(
        "Verify all passes on a copy of the binary before committing to any patch.".to_owned(),
    );

    recs
}

// ── analyze_binary_for_protections ──────────────────────────────────────────

/// Quick static scan of `data` to populate an initial [`BinaryIadlState`].
///
/// Heuristics applied:
/// - Shannon entropy per 256-byte window → high-entropy section labels.
/// - UPX signature bytes (`UPX0`, `UPX1`) → packer marker.
/// - Anti-debug API name strings → anti-debug marker.
/// - Very low function-count proxy (few `0x55 0x8B 0xEC` / `0x55 0x48 0x89 0xE5`
///   prologue patterns) relative to binary size → possible VM.
#[must_use]
pub fn analyze_binary_for_protections(data: &[u8]) -> BinaryIadlState {
    let binary_size = data.len();
    const WINDOW: usize = 256;
    // Reserve for windows + a handful of marker/antidebug entries.
    // Capacity hint: at most one high-entropy label per 8 windows, plus some
    // headroom for marker strings. Cap to avoid OOM on adversarial large inputs.
    let hint = (binary_size.div_ceil(WINDOW) / 8 + 16).min(4096);
    let mut high_entropy_sections: Vec<String> = Vec::with_capacity(hint);

    // ── Entropy windows ───────────────────────────────────────────────────
    for (window_idx, chunk) in data.chunks(WINDOW).enumerate() {
        let entropy = shannon_entropy(chunk);
        if entropy > 7.0 {
            high_entropy_sections.push(format!("window_{:06x}", window_idx * WINDOW));
        }
    }

    // ── UPX section markers ───────────────────────────────────────────────
    if contains_bytes(data, b"UPX0") {
        high_entropy_sections.push("UPX0".to_owned());
    }
    if contains_bytes(data, b"UPX1") {
        high_entropy_sections.push("UPX1".to_owned());
    }
    if contains_bytes(data, b"UPX!") {
        high_entropy_sections.push("UPX!".to_owned());
    }

    // ── Anti-debug API name strings ───────────────────────────────────────
    const ANTIDEBUG_NAMES: &[&[u8]] = &[
        b"IsDebuggerPresent",
        b"CheckRemoteDebuggerPresent",
        b"NtQueryInformationProcess",
        b"OutputDebugString",
        b"FindWindow",
        b"ZwSetInformationThread",
    ];
    for name in ANTIDEBUG_NAMES {
        if contains_bytes(data, name)
            && let Ok(s) = std::str::from_utf8(name) {
                high_entropy_sections.push(s.to_owned());
            }
    }

    // ── Rough function-prologue count ─────────────────────────────────────
    // x86:  55 8B EC  (PUSH EBP; MOV EBP, ESP)
    // x64:  55 48 89 E5  (PUSH RBP; MOV RBP, RSP)
    let function_count = u32::try_from(count_pattern(data, &[0x55, 0x8B, 0xEC]))
        .unwrap_or(u32::MAX)
        .saturating_add(
            u32::try_from(count_pattern(data, &[0x55, 0x48, 0x89, 0xE5]))
                .unwrap_or(u32::MAX),
        );

    BinaryIadlState {
        iteration: 0,
        global_score: 0.0,
        identified_layers: Vec::new(),
        binary_size,
        function_count,
        high_entropy_sections,
    }
}

// ── Internal static-analysis utilities ───────────────────────────────────────

/// Compute Shannon entropy of a byte slice (bits per byte, max 8.0).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter().filter(|&&f| f > 0).fold(0.0, |acc, &f| {
        let p = f64::from(f) / len;
        p.mul_add(-p.log2(), acc)
    })
}

/// Return `true` if `haystack` contains `needle` as a contiguous sub-slice.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Count non-overlapping occurrences of `pattern` in `data`.
fn count_pattern(data: &[u8], pattern: &[u8]) -> usize {
    if pattern.is_empty() || data.len() < pattern.len() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + pattern.len() <= data.len() {
        if &data[i..i + pattern.len()] == pattern {
            count += 1;
            i += pattern.len();
        } else {
            i += 1;
        }
    }
    count
}

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic API resolution detection
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from API resolution analysis.
#[derive(Debug, Error)]
pub enum IadlError {
    /// Hash algorithm is not supported for this operation.
    #[error("unsupported hash algorithm: {name}")]
    UnsupportedAlgorithm { name: String },
    /// No candidate was found.
    #[error("no resolution candidate found")]
    NotFound,
    /// Internal analysis error.
    #[error("analysis error: {0}")]
    Analysis(String),
}

/// Hash algorithm used for dynamic API resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// Djb2: `h = h * 33 + c`.
    Djb2,
    /// FNV-1a 32-bit.
    Fnv1a32,
    /// SDBM hash.
    Sdbm,
    /// CRC32 (IEEE polynomial).
    Crc32,
    /// Adler32.
    Adler32,
    /// ROR-based hash (common in shellcode).
    RorHash,
    /// Unknown / custom.
    Unknown,
}

impl HashAlgorithm {
    /// Return a human-readable name for this algorithm.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Djb2 => "djb2",
            Self::Fnv1a32 => "fnv1a32",
            Self::Sdbm => "sdbm",
            Self::Crc32 => "crc32",
            Self::Adler32 => "adler32",
            Self::RorHash => "ror_hash",
            Self::Unknown => "unknown",
        }
    }

    /// Return `true` if this is a well-known algorithm.
    #[must_use]
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// A detected API hash reference in the binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiHash {
    /// The 32/64-bit hash value found in the binary.
    pub hash: u64,
    /// Resolved API function name (if any).
    pub name: Option<String>,
    /// Resolved DLL name (if any).
    pub dll: Option<String>,
    /// Algorithm that was used.
    pub algorithm: HashAlgorithm,
    /// File offset where the hash constant was found.
    pub file_offset: u64,
}

impl ApiHash {
    /// Create a new [`ApiHash`].
    #[must_use]
    pub const fn new(hash: u64, algorithm: HashAlgorithm, file_offset: u64) -> Self {
        Self {
            hash,
            name: None,
            dll: None,
            algorithm,
            file_offset,
        }
    }

    /// Attach a resolved API name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Attach a resolved DLL name.
    #[must_use]
    pub fn with_dll(mut self, dll: impl Into<String>) -> Self {
        self.dll = Some(dll.into());
        self
    }

    /// Return `true` if both name and DLL have been resolved.
    #[must_use]
    pub const fn is_fully_resolved(&self) -> bool {
        self.name.is_some() && self.dll.is_some()
    }

    /// Return `true` if the name has been resolved.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        self.name.is_some()
    }
}

/// A resolved API import via dynamic API lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiResolution {
    /// The API hash that was resolved.
    pub api_hash: ApiHash,
    /// Virtual address of the `CALL` or `JMP` site that uses this API.
    pub call_site: u64,
    /// The resolved function pointer address (if known at analysis time).
    pub resolved_address: Option<u64>,
    /// Confidence in the resolution (0–100).
    pub confidence: u32,
}

impl ApiResolution {
    /// Create a new [`ApiResolution`].
    #[must_use]
    pub const fn new(api_hash: ApiHash, call_site: u64) -> Self {
        Self {
            api_hash,
            call_site,
            resolved_address: None,
            confidence: 50,
        }
    }

    /// Attach a resolved address.
    #[must_use]
    pub const fn with_address(mut self, addr: u64) -> Self {
        self.resolved_address = Some(addr);
        self
    }

    /// Set confidence.
    #[must_use]
    pub fn with_confidence(mut self, conf: u32) -> Self {
        self.confidence = conf.min(100);
        self
    }

    /// Return `true` if the resolution is highly confident.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IadlDetector — detects dynamic API resolution patterns
// ─────────────────────────────────────────────────────────────────────────────

/// Detector for dynamic API resolution patterns in binary data.
#[derive(Debug, Clone)]
pub struct IadlDetector {
    /// Minimum number of hash references to consider a binary as using dynamic resolution.
    pub min_hash_refs: usize,
    /// Whether to scan for hash-based patterns.
    pub scan_hashes: bool,
    /// Whether to scan for `LoadLibrary` / `GetProcAddress` patterns.
    pub scan_loadlib: bool,
}

impl Default for IadlDetector {
    fn default() -> Self {
        Self {
            min_hash_refs: 2,
            scan_hashes: true,
            scan_loadlib: true,
        }
    }
}

impl IadlDetector {
    /// Create a new [`IadlDetector`] with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `data` for suspected dynamic-API-resolution hash constants.
    ///
    /// Returns a list of suspected 32-bit hash values and their offsets.
    #[must_use]
    pub fn scan_hash_constants(&self, data: &[u8]) -> Vec<(u64, usize)> {
        if data.len() < 4 {
            return Vec::new();
        }
        // Heuristic capacity: a small fraction of 4-byte windows survive the filter.
        // Cap to avoid OOM when data is a large adversarial input (e.g. 4 GB → 67M entries).
        let capacity_hint = (data.len() / 64).min(1 << 20); // max ~1M pre-allocated entries
        let mut results = Vec::with_capacity(capacity_hint);
        let mut i = 0;
        while i + 4 <= data.len() {
            let bytes: [u8; 4] = data[i..i + 4].try_into().unwrap();
            let le_word = u32::from_le_bytes(bytes);
            let be_word = u32::from_be_bytes(bytes);
            // Heuristic: values with many set bits and not all-zeros or 0xFFFFFFFF
            // are likely hash constants. Try both endiannesses so big-endian
            // binaries are not missed.
            // Emit at most one entry per offset: prefer LE interpretation.
            // Emitting both LE and BE for the same offset would create duplicate
            // ApiResolution entries at the same call_site, inflating match counts.
            if le_word != 0 && le_word != 0xFFFF_FFFF && le_word.count_ones() >= 8 {
                results.push((u64::from(le_word), i));
            } else if be_word != le_word
                && be_word != 0
                && be_word != 0xFFFF_FFFF
                && be_word.count_ones() >= 8
            {
                results.push((u64::from(be_word), i));
            }
            i += 4;
        }
        results
    }

    /// Detect `LoadLibrary` / `GetProcAddress` pattern byte sequences in `data`.
    ///
    /// Returns file offsets where LoadLibrary-style API resolution is likely.
    #[must_use]
    pub fn detect_loadlib_pattern(&self, data: &[u8]) -> Vec<usize> {
        // Patterns commonly seen around GetProcAddress calls:
        // `FF D0` = CALL EAX  (indirect call to resolved function pointer)
        // `FF 15` = CALL [addr] (indirect call via IAT)
        // `FF D2` = CALL EDX
        let patterns: &[&[u8]] = &[&[0xFF, 0xD0], &[0xFF, 0xD2], &[0xFF, 0x15]];
        let mut offsets = Vec::with_capacity(data.len() / 256);
        for pattern in patterns {
            let mut pos = 0;
            while pos + pattern.len() <= data.len() {
                if &data[pos..pos + pattern.len()] == *pattern {
                    offsets.push(pos);
                }
                pos += 1;
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }

    /// Attempt to identify the hash algorithm used by correlating hash values
    /// against a built-in list of well-known API names.
    ///
    /// Returns the detected algorithm and number of matched hashes.
    #[must_use]
    pub fn identify_algorithm(&self, hashes: &[u64]) -> (HashAlgorithm, usize) {
        const KNOWN_APIS: &[&str] = &[
            "LoadLibraryA",
            "GetProcAddress",
            "VirtualAlloc",
            "VirtualProtect",
            "CreateThread",
            "WinExec",
            "ExitProcess",
            "GetModuleHandleA",
            "InternetOpenA",
            "WSAStartup",
        ];

        let algorithms = [
            HashAlgorithm::Djb2,
            HashAlgorithm::Fnv1a32,
            HashAlgorithm::Crc32,
            HashAlgorithm::Sdbm,
            HashAlgorithm::Adler32,
        ];

        let mut best_algo = HashAlgorithm::Unknown;
        let mut best_matches = 0usize;

        for algo in &algorithms {
            let mut matches = 0usize;
            let table = HashTable::build(KNOWN_APIS, *algo);
            for &h in hashes {
                if table.resolve(h).is_some() {
                    matches += 1;
                }
            }
            if matches > best_matches {
                best_matches = matches;
                best_algo = *algo;
            }
        }
        (best_algo, best_matches)
    }

    /// Full pipeline: scan for hash constants, identify the algorithm, and
    /// return resolved [`ApiResolution`] objects.
    #[must_use]
    pub fn analyze(&self, data: &[u8], call_base: u64) -> Vec<ApiResolution> {
        if !self.scan_hashes {
            return Vec::new();
        }
        let constants = self.scan_hash_constants(data);
        if constants.len() < self.min_hash_refs {
            return Vec::new();
        }
        let hashes: Vec<u64> = constants.iter().map(|(h, _)| *h).collect();
        let (algo, _) = self.identify_algorithm(&hashes);

        const KNOWN_APIS: &[&str] = &[
            "LoadLibraryA",
            "GetProcAddress",
            "VirtualAlloc",
            "VirtualProtect",
            "CreateThread",
            "WinExec",
            "ExitProcess",
            "GetModuleHandleA",
        ];
        let table = HashTable::build(KNOWN_APIS, algo);

        constants
            .into_iter()
            .filter_map(|(hash, offset)| {
                let api_hash = if let Some(name) = table.resolve(hash) {
                    ApiHash::new(hash, algo, offset as u64).with_name(name)
                } else {
                    ApiHash::new(hash, algo, offset as u64)
                };
                let call_site = call_base.saturating_add(offset as u64);
                Some(ApiResolution::new(api_hash, call_site).with_confidence(60))
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HashTable — lookup table for API hashes
// ─────────────────────────────────────────────────────────────────────────────

/// A lookup table mapping hash values to API names.
#[derive(Debug, Clone)]
pub struct HashTable {
    /// Map from hash value to API name.
    entries: HashMap<u64, String>,
    /// Algorithm used to compute the hashes.
    pub algorithm: HashAlgorithm,
}

impl Default for HashTable {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            algorithm: HashAlgorithm::Unknown,
        }
    }
}

impl HashTable {
    /// Create a new empty [`HashTable`].
    #[must_use]
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            entries: HashMap::new(),
            algorithm,
        }
    }

    /// Build a [`HashTable`] from a list of API names using the given algorithm.
    #[must_use]
    pub fn build(names: &[&str], algorithm: HashAlgorithm) -> Self {
        let mut table = Self::new(algorithm);
        for &name in names {
            let hash = compute_hash(name.as_bytes(), algorithm);
            table.entries.insert(hash, name.to_owned());
        }
        table
    }

    /// Insert a name→hash pair into the table.
    pub fn insert(&mut self, name: impl Into<String>) {
        let name = name.into();
        let hash = compute_hash(name.as_bytes(), self.algorithm);
        self.entries.insert(hash, name);
    }

    /// Resolve a hash to an API name.
    #[must_use]
    pub fn resolve(&self, hash: u64) -> Option<&str> {
        self.entries.get(&hash).map(std::string::String::as_str)
    }

    /// Return the number of entries in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all (hash, name) pairs.
    #[must_use]
    pub fn entries(&self) -> Vec<(u64, &str)> {
        self.entries.iter().map(|(k, v)| (*k, v.as_str())).collect()
    }
}

/// Compute the hash of `data` using the specified algorithm.
#[must_use]
pub fn compute_hash(data: &[u8], algorithm: HashAlgorithm) -> u64 {
    match algorithm {
        HashAlgorithm::Djb2 => {
            let mut h = 5381u32;
            for &b in data {
                h = h.wrapping_mul(33).wrapping_add(u32::from(b));
            }
            u64::from(h)
        }
        HashAlgorithm::Fnv1a32 => {
            const PRIME: u32 = 0x0100_0193;
            const BASIS: u32 = 0x811C_9DC5;
            let mut h = BASIS;
            for &b in data {
                h ^= u32::from(b);
                h = h.wrapping_mul(PRIME);
            }
            u64::from(h)
        }
        HashAlgorithm::Sdbm => {
            let mut h = 0u32;
            for &b in data {
                h = u32::from(b)
                    .wrapping_add(h.wrapping_shl(6))
                    .wrapping_add(h.wrapping_shl(16))
                    .wrapping_sub(h);
            }
            u64::from(h)
        }
        HashAlgorithm::Crc32 => {
            let mut crc = 0xFFFF_FFFFu32;
            for &b in data {
                crc ^= u32::from(b);
                for _ in 0..8 {
                    if crc & 1 == 1 {
                        crc = (crc >> 1) ^ 0xEDB8_8320;
                    } else {
                        crc >>= 1;
                    }
                }
            }
            u64::from(!crc)
        }
        HashAlgorithm::Adler32 => {
            const MOD: u32 = 65521;
            let mut a = 1u32;
            let mut b_val = 0u32;
            for &byte in data {
                a = (a + u32::from(byte)) % MOD;
                b_val = (b_val + a) % MOD;
            }
            u64::from((b_val << 16) | a)
        }
        HashAlgorithm::RorHash => {
            let mut h = 0u32;
            for &b in data {
                h = h.rotate_right(13).wrapping_add(u32::from(b));
            }
            u64::from(h)
        }
        HashAlgorithm::Unknown => 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoadLibraryChain — trace LoadLibrary + GetProcAddress call chains
// ─────────────────────────────────────────────────────────────────────────────

/// A single step in a `LoadLibrary` / `GetProcAddress` resolution chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStep {
    /// File offset of this step.
    pub offset: u64,
    /// Type of call: "`LoadLibrary`", "`GetProcAddress`", or "indirect".
    pub call_type: String,
    /// Argument string literal (if detected statically).
    pub argument: Option<String>,
}

impl ChainStep {
    /// Create a new [`ChainStep`].
    #[must_use]
    pub fn new(offset: u64, call_type: impl Into<String>) -> Self {
        Self {
            offset,
            call_type: call_type.into(),
            argument: None,
        }
    }

    /// Attach a static argument.
    #[must_use]
    pub fn with_argument(mut self, arg: impl Into<String>) -> Self {
        self.argument = Some(arg.into());
        self
    }
}

/// A chain of calls that dynamically resolves an API.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoadLibraryChain {
    /// Steps in the resolution chain.
    pub steps: Vec<ChainStep>,
    /// Final resolved API name (if determinable).
    pub resolved_api: Option<String>,
}

impl LoadLibraryChain {
    /// Create an empty [`LoadLibraryChain`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a step.
    pub fn push(&mut self, step: ChainStep) {
        self.steps.push(step);
    }

    /// Return the number of steps.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.steps.len()
    }

    /// Return `true` if the chain has no steps.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Return `true` if the chain has both a `LoadLibrary` and a `GetProcAddress` step.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        let has_ll = self
            .steps
            .iter()
            .any(|s| s.call_type.contains("LoadLibrary"));
        let has_gpa = self
            .steps
            .iter()
            .any(|s| s.call_type.contains("GetProcAddress"));
        has_ll && has_gpa
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoring helpers built on top of IADL primitives
// ─────────────────────────────────────────────────────────────────────────────

/// A scorer that rewards candidates with lower complexity.
#[derive(Debug, Clone, Copy)]
pub struct ComplexityScorer {
    /// Weight of this scorer (0.0..=1.0).
    pub weight: f64,
}

impl ComplexityScorer {
    /// Create a new [`ComplexityScorer`] with the given weight.
    #[must_use]
    pub const fn new(weight: f64) -> Self {
        Self {
            weight: weight.clamp(0.0, 1.0),
        }
    }
}

impl Scorer for ComplexityScorer {
    fn name(&self) -> &'static str {
        "complexity"
    }

    fn weight(&self) -> f64 {
        self.weight
    }

    fn score(&self, tentative: &TentativeState, baseline: &IadlState) -> f64 {
        if baseline.complexity == 0 {
            return 0.5;
        }
        let ratio = tentative.complexity as f64 / baseline.complexity as f64;
        // Lower complexity → higher score.
        (1.0 - ratio).clamp(0.0, 1.0)
    }
}

/// A scorer that rewards candidates whose score exceeds the baseline.
#[derive(Debug, Clone, Copy)]
pub struct ImprovementScorer {
    /// Weight of this scorer.
    pub weight: f64,
}

impl ImprovementScorer {
    /// Create a new [`ImprovementScorer`].
    #[must_use]
    pub const fn new(weight: f64) -> Self {
        Self {
            weight: weight.clamp(0.0, 1.0),
        }
    }
}

impl Scorer for ImprovementScorer {
    fn name(&self) -> &'static str {
        "improvement"
    }

    fn weight(&self) -> f64 {
        self.weight
    }

    fn score(&self, tentative: &TentativeState, baseline: &IadlState) -> f64 {
        if tentative.score > baseline.global_score {
            // Normalise improvement to [0, 1].
            (tentative.score - baseline.global_score).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hypothesis library
// ─────────────────────────────────────────────────────────────────────────────

/// A hypothesis that always proposes a fixed score and complexity.
#[derive(Debug, Clone)]
pub struct ConstantHypothesis {
    /// Identifier.
    pub id: String,
    /// Proposed score.
    pub score: f64,
    /// Proposed complexity.
    pub complexity: u64,
    /// Rationale text.
    pub rationale: String,
    /// Prior confidence.
    pub prior: f64,
}

impl ConstantHypothesis {
    /// Create a new [`ConstantHypothesis`].
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        score: f64,
        complexity: u64,
        rationale: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            score,
            complexity,
            rationale: rationale.into(),
            prior: 0.5,
        }
    }

    /// Set the prior and return `self`.
    #[must_use]
    pub const fn with_prior(mut self, prior: f64) -> Self {
        // NaN-safe clamp: `f64::clamp` propagates NaN, and `is_nan()` is not
        // available here. With NaN every comparison is false, so we fall
        // through to 0.0.
        self.prior = if prior >= 1.0 {
            1.0
        } else if prior > 0.0 {
            prior
        } else {
            0.0
        };
        self
    }
}

impl Hypothesis for ConstantHypothesis {
    fn id(&self) -> &str {
        &self.id
    }

    fn prior(&self, _state: &IadlState) -> f64 {
        self.prior
    }

    fn apply(&self, _state: &IadlState) -> TentativeState {
        TentativeState::new(
            self.id.clone(),
            self.score,
            self.complexity,
            self.rationale.clone(),
        )
    }
}

/// A hypothesis that proposes an improvement proportional to the current score.
#[derive(Debug, Clone)]
pub struct IncrementalHypothesis {
    /// Identifier.
    pub id: String,
    /// Multiplicative factor applied to the current global score.
    pub factor: f64,
    /// Prior confidence.
    pub prior: f64,
}

impl IncrementalHypothesis {
    /// Create a new [`IncrementalHypothesis`].
    #[must_use]
    pub fn new(id: impl Into<String>, factor: f64) -> Self {
        Self {
            id: id.into(),
            factor,
            prior: 0.5,
        }
    }
}

impl Hypothesis for IncrementalHypothesis {
    fn id(&self) -> &str {
        &self.id
    }

    fn prior(&self, _state: &IadlState) -> f64 {
        self.prior
    }

    fn apply(&self, state: &IadlState) -> TentativeState {
        let proposed_score = (state.global_score * self.factor).min(1.0);
        // Guard against division by zero or near-zero factor to avoid
        // producing u64::MAX via saturating cast of f64::INFINITY.
        let proposed_complexity = if self.factor.abs() < f64::EPSILON {
            return TentativeState::new(
                self.id.clone(),
                state.global_score,
                state.complexity,
                format!("incremental by factor {:.3} (no-op: factor too small)", self.factor),
            );
        } else {
            let raw = state.complexity as f64 * (1.0 / self.factor);
            // Guard against NaN / infinity / values > u64::MAX before casting.
            if raw.is_finite() && raw >= 0.0 && raw < u64::MAX as f64 {
                raw as u64
            } else {
                u64::MAX
            }
        };
        TentativeState::new(
            self.id.clone(),
            proposed_score,
            proposed_complexity,
            format!("incremental by factor {:.3}", self.factor),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolutionStats — statistics about API resolution coverage
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics summarising API resolution results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResolutionStats {
    /// Total number of API hash references found.
    pub total_hashes: usize,
    /// Number of successfully resolved API names.
    pub resolved: usize,
    /// Number of unresolved hashes.
    pub unresolved: usize,
    /// Resolution rate as a percentage.
    pub resolution_rate: f64,
    /// Most likely algorithm detected.
    pub algorithm: Option<HashAlgorithm>,
}

impl ResolutionStats {
    /// Compute stats from a list of [`ApiResolution`] objects.
    #[must_use]
    pub fn from_resolutions(resolutions: &[ApiResolution]) -> Self {
        let total = resolutions.len();
        let resolved = resolutions
            .iter()
            .filter(|r| r.api_hash.is_resolved())
            .count();
        let unresolved = total.saturating_sub(resolved);
        let resolution_rate = if total == 0 {
            0.0
        } else {
            resolved as f64 / total as f64 * 100.0
        };
        let algorithm = resolutions.first().map(|r| r.api_hash.algorithm);
        Self {
            total_hashes: total,
            resolved,
            unresolved,
            resolution_rate,
            algorithm,
        }
    }

    /// Return `true` if resolution rate is above 50%.
    #[must_use]
    pub fn is_good_coverage(&self) -> bool {
        self.resolution_rate > 50.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IADL-specific deobfuscation pass
// ─────────────────────────────────────────────────────────────────────────────

/// A deobfuscation pass that uses the IADL loop for adaptive strategy selection.
#[derive(Debug, Clone)]
pub struct IadlDeobfPass {
    /// Configuration for the IADL loop.
    pub config: IadlConfig,
    /// Name of this pass.
    pub name: String,
}

impl IadlDeobfPass {
    /// Create a new [`IadlDeobfPass`].
    #[must_use]
    pub fn new(name: impl Into<String>, config: IadlConfig) -> Self {
        Self {
            config,
            name: name.into(),
        }
    }

    /// Run the IADL loop with the provided hypotheses and scorers.
    ///
    /// Returns the final [`IadlReport`].
    #[must_use]
    pub fn run(
        &self,
        initial_score: f64,
        initial_complexity: u64,
        hypotheses: &[Box<dyn Hypothesis>],
        scorers: &[Box<dyn Scorer>],
    ) -> IadlReport {
        let state = IadlState::new(initial_score, initial_complexity);
        let orch = IadlOrchestrator::new(self.config);
        orch.run(state, hypotheses, scorers)
    }

    /// Return the pass name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// A registry of named hypotheses for the IADL loop.
///
/// Uses [`BTreeMap`] instead of [`HashMap`] so that attacker-controlled
/// hypothesis IDs cannot cause hash-collision DoS.
#[derive(Default)]
pub struct HypothesisRegistry {
    hypotheses: BTreeMap<String, Box<dyn Hypothesis>>,
}

impl HypothesisRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a hypothesis. Returns `false` if the ID was already registered.
    pub fn register(&mut self, hypothesis: Box<dyn Hypothesis>) -> bool {
        let id = hypothesis.id().to_owned();
        if self.hypotheses.contains_key(&id) {
            return false;
        }
        self.hypotheses.insert(id, hypothesis);
        true
    }

    /// Return a list of hypothesis IDs in sorted order.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        // BTreeMap iterates in sorted order already.
        self.hypotheses.keys().cloned().collect()
    }

    /// Return the number of registered hypotheses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hypotheses.len()
    }

    /// Return `true` if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hypotheses.is_empty()
    }

    /// Collect all hypotheses into a `Vec<Box<dyn Hypothesis>>`.
    #[must_use]
    pub fn all(&self) -> Vec<&dyn Hypothesis> {
        // BTreeMap already yields values in key-sorted order.
        self.hypotheses.values().map(std::convert::AsRef::as_ref).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedHypothesis {
        id: String,
        prior: f64,
        score: f64,
        complexity: u64,
    }

    impl Hypothesis for FixedHypothesis {
        fn id(&self) -> &str {
            &self.id
        }

        fn prior(&self, _state: &IadlState) -> f64 {
            self.prior
        }

        fn apply(&self, _state: &IadlState) -> TentativeState {
            TentativeState::new(self.id.clone(), self.score, self.complexity, "fixed")
        }
    }

    struct PassthroughScorer;

    impl Scorer for PassthroughScorer {
        fn name(&self) -> &'static str {
            "passthrough"
        }
        fn weight(&self) -> f64 {
            1.0
        }
        fn score(&self, tentative: &TentativeState, _baseline: &IadlState) -> f64 {
            tentative.score
        }
    }

    #[test]
    fn accepts_best_candidate_when_improving() {
        let orchestrator = IadlOrchestrator::new(IadlConfig {
            max_iterations: 1,
            max_no_progress: 1,
            min_improvement: 0.001,
            complexity_penalty: 0.0,
        });
        let state = IadlState::new(0.2, 100);
        let hypotheses: Vec<Box<dyn Hypothesis>> = vec![
            Box::new(FixedHypothesis {
                id: "a".into(),
                prior: 1.0,
                score: 0.5,
                complexity: 90,
            }),
            Box::new(FixedHypothesis {
                id: "b".into(),
                prior: 1.0,
                score: 0.8,
                complexity: 80,
            }),
        ];
        let scorers: Vec<Box<dyn Scorer>> = vec![Box::new(PassthroughScorer)];

        let report = orchestrator.run(state, &hypotheses, &scorers);
        assert_eq!(report.final_state.global_score, 0.8);
        assert_eq!(
            report.iterations[0].accepted_hypothesis.as_deref(),
            Some("b")
        );
    }

    #[test]
    fn stops_after_no_progress_threshold() {
        let orchestrator = IadlOrchestrator::new(IadlConfig {
            max_iterations: 10,
            max_no_progress: 2,
            min_improvement: 0.01,
            complexity_penalty: 0.0,
        });
        let state = IadlState::new(0.9, 40);
        let hypotheses: Vec<Box<dyn Hypothesis>> = vec![Box::new(FixedHypothesis {
            id: "stuck".into(),
            prior: 1.0,
            score: 0.9,
            complexity: 39,
        })];
        let scorers: Vec<Box<dyn Scorer>> = vec![Box::new(PassthroughScorer)];

        let report = orchestrator.run(state, &hypotheses, &scorers);
        assert_eq!(report.stop_reason, StopReason::NoProgress);
        assert_eq!(report.iterations.len(), 2);
    }

    #[test]
    fn tie_breaks_by_lower_complexity_then_id() {
        let orchestrator = IadlOrchestrator::new(IadlConfig {
            max_iterations: 1,
            max_no_progress: 1,
            min_improvement: 0.0,
            complexity_penalty: 0.0,
        });
        let state = IadlState::new(0.0, 999);
        let hypotheses: Vec<Box<dyn Hypothesis>> = vec![
            Box::new(FixedHypothesis {
                id: "z".into(),
                prior: 1.0,
                score: 0.6,
                complexity: 50,
            }),
            Box::new(FixedHypothesis {
                id: "a".into(),
                prior: 1.0,
                score: 0.6,
                complexity: 40,
            }),
        ];
        let scorers: Vec<Box<dyn Scorer>> = vec![Box::new(PassthroughScorer)];

        let report = orchestrator.run(state, &hypotheses, &scorers);
        assert_eq!(
            report.iterations[0].accepted_hypothesis.as_deref(),
            Some("a")
        );
    }

    #[test]
    fn scorer_can_veto_raw_candidate_score() {
        struct VetoScorer;

        impl Scorer for VetoScorer {
            fn name(&self) -> &'static str {
                "veto"
            }

            fn weight(&self) -> f64 {
                1.0
            }

            fn score(&self, tentative: &TentativeState, _baseline: &IadlState) -> f64 {
                if tentative.hypothesis_id == "noisy" {
                    0.1
                } else {
                    tentative.score
                }
            }
        }

        let orchestrator = IadlOrchestrator::new(IadlConfig::default());
        let state = IadlState::new(0.0, 999);
        let hypotheses: Vec<Box<dyn Hypothesis>> = vec![
            Box::new(FixedHypothesis {
                id: "noisy".into(),
                prior: 1.0,
                score: 0.9,
                complexity: 10,
            }),
            Box::new(FixedHypothesis {
                id: "steady".into(),
                prior: 1.0,
                score: 0.5,
                complexity: 10,
            }),
        ];
        let scorers: Vec<Box<dyn Scorer>> = vec![Box::new(VetoScorer)];

        let evaluations = orchestrator.evaluate_all(&state, &hypotheses, &scorers);
        assert_eq!(evaluations[0].candidate.hypothesis_id, "steady");
        assert_eq!(evaluations[0].scorer_breakdown[0].name, "veto");
    }

    #[test]
    fn complexity_penalty_changes_ranking_deterministically() {
        let orchestrator = IadlOrchestrator::new(IadlConfig {
            max_iterations: 1,
            max_no_progress: 1,
            min_improvement: 0.0,
            complexity_penalty: 0.01,
        });
        let state = IadlState::new(0.0, 999);
        let hypotheses: Vec<Box<dyn Hypothesis>> = vec![
            Box::new(FixedHypothesis {
                id: "large".into(),
                prior: 1.0,
                score: 0.8,
                complexity: 40,
            }),
            Box::new(FixedHypothesis {
                id: "small".into(),
                prior: 1.0,
                score: 0.7,
                complexity: 10,
            }),
        ];
        let scorers: Vec<Box<dyn Scorer>> = vec![Box::new(PassthroughScorer)];

        let evaluations = orchestrator.evaluate_all(&state, &hypotheses, &scorers);
        assert_eq!(evaluations[0].candidate.hypothesis_id, "small");
    }

    // ── Additional tests ─────────────────────────────────────────────────────

    #[test]
    fn iadl_state_new_initial_values() {
        let state = IadlState::new(0.5, 100);
        assert_eq!(state.iteration, 0);
        assert!((state.global_score - 0.5).abs() < 1e-9);
        assert_eq!(state.complexity, 100);
        assert!(state.score_components.is_empty());
    }

    #[test]
    fn tentative_state_new_fields() {
        let t = TentativeState::new("hyp_a", 0.7, 50, "reason");
        assert_eq!(t.hypothesis_id, "hyp_a");
        assert!((t.score - 0.7).abs() < 1e-9);
        assert_eq!(t.complexity, 50);
        assert_eq!(t.rationale, "reason");
    }

    #[test]
    fn orchestrator_default_config() {
        let o = IadlOrchestrator::default_config();
        let cfg = o.config();
        assert_eq!(cfg.max_iterations, 64);
        assert_eq!(cfg.max_no_progress, 3);
    }

    #[test]
    fn run_with_no_hypotheses_stops_immediately() {
        let orchestrator = IadlOrchestrator::new(IadlConfig {
            max_iterations: 10,
            max_no_progress: 1,
            min_improvement: 0.0,
            complexity_penalty: 0.0,
        });
        let state = IadlState::new(0.5, 50);
        let report = orchestrator.run(state, &[], &[]);
        assert_eq!(report.stop_reason, StopReason::NoProgress);
        assert_eq!(report.iterations.len(), 1);
    }

    #[test]
    fn run_exhausts_iteration_budget() {
        let orchestrator = IadlOrchestrator::new(IadlConfig {
            max_iterations: 5,
            max_no_progress: 100, // never stop early
            min_improvement: 0.0,
            complexity_penalty: 0.0,
        });
        let state = IadlState::new(0.0, 0);
        let hypotheses: Vec<Box<dyn Hypothesis>> = vec![Box::new(FixedHypothesis {
            id: "h".into(),
            prior: 1.0,
            score: 0.99,
            complexity: 0,
        })];
        let scorers: Vec<Box<dyn Scorer>> = vec![Box::new(PassthroughScorer)];
        let report = orchestrator.run(state, &hypotheses, &scorers);
        assert_eq!(report.stop_reason, StopReason::IterationBudget);
        assert_eq!(report.iterations.len(), 5);
    }

    #[test]
    fn prior_clamped_to_zero_one() {
        struct ZeroPrior;
        impl Hypothesis for ZeroPrior {
            fn id(&self) -> &'static str {
                "z"
            }
            fn prior(&self, _s: &IadlState) -> f64 {
                -99.0
            } // will be clamped
            fn apply(&self, _s: &IadlState) -> TentativeState {
                TentativeState::new("z", 1.0, 0, "")
            }
        }
        let orch = IadlOrchestrator::new(IadlConfig {
            max_iterations: 1,
            max_no_progress: 1,
            min_improvement: 0.0,
            complexity_penalty: 0.0,
        });
        let state = IadlState::new(0.0, 0);
        let evals = orch.evaluate_all(&state, &[Box::new(ZeroPrior)], &[]);
        assert_eq!(evals.len(), 1);
        // Clamped prior of 0 means final_score = 0.
        assert!((evals[0].prior).abs() < 1e-9);
    }

    #[test]
    fn no_scorers_passes_raw_candidate_score() {
        let orch = IadlOrchestrator::new(IadlConfig::default());
        let state = IadlState::new(0.0, 0);
        let hypotheses: Vec<Box<dyn Hypothesis>> = vec![Box::new(FixedHypothesis {
            id: "raw".into(),
            prior: 1.0,
            score: 0.77,
            complexity: 0,
        })];
        let evals = orch.evaluate_all(&state, &hypotheses, &[]);
        assert!((evals[0].scorer_score - 0.77).abs() < 1e-9);
    }

    #[test]
    fn evaluate_all_empty_hypotheses() {
        let orch = IadlOrchestrator::default_config();
        let state = IadlState::new(0.5, 50);
        let evals = orch.evaluate_all(&state, &[], &[]);
        assert!(evals.is_empty());
    }

    #[test]
    fn iteration_result_no_progress_count_increments() {
        let orch = IadlOrchestrator::new(IadlConfig {
            max_iterations: 5,
            max_no_progress: 10,
            min_improvement: 0.01,
            complexity_penalty: 0.0,
        });
        // Score below improvement threshold always → no progress.
        let state = IadlState::new(0.9, 0);
        let hypotheses: Vec<Box<dyn Hypothesis>> = vec![Box::new(FixedHypothesis {
            id: "stuck".into(),
            prior: 1.0,
            score: 0.9, // not > 0.9 + 0.01
            complexity: 0,
        })];
        let scorers: Vec<Box<dyn Scorer>> = vec![Box::new(PassthroughScorer)];
        let report = orch.run(state, &hypotheses, &scorers);
        // All iterations should have no accepted hypothesis.
        for iter in &report.iterations {
            assert!(iter.accepted_hypothesis.is_none());
        }
    }

    #[test]
    fn scorer_contribution_fields() {
        let sc = ScorerContribution {
            name: "test_scorer".to_string(),
            weight: 0.5,
            score: 0.8,
        };
        assert_eq!(sc.name, "test_scorer");
        assert!((sc.weight - 0.5).abs() < 1e-9);
        assert!((sc.score - 0.8).abs() < 1e-9);
    }

    #[test]
    fn iadl_config_default() {
        let cfg = IadlConfig::default();
        assert_eq!(cfg.max_iterations, 64);
        assert_eq!(cfg.max_no_progress, 3);
        assert!(cfg.min_improvement > 0.0);
    }

    #[test]
    fn iadl_state_score_components_can_be_set() {
        let mut state = IadlState::new(0.0, 0);
        state.score_components.insert("entropy".to_string(), 0.7);
        state.score_components.insert("coverage".to_string(), 0.3);
        assert_eq!(state.score_components.len(), 2);
        assert!((state.score_components["entropy"] - 0.7).abs() < 1e-9);
    }

    #[test]
    fn stop_reason_no_progress_displayed() {
        let r = StopReason::NoProgress;
        assert_eq!(r, StopReason::NoProgress);
    }

    #[test]
    fn stop_reason_iteration_budget_displayed() {
        let r = StopReason::IterationBudget;
        assert_eq!(r, StopReason::IterationBudget);
    }

    #[test]
    fn report_final_state_updated_on_acceptance() {
        let orch = IadlOrchestrator::new(IadlConfig {
            max_iterations: 3,
            max_no_progress: 10,
            min_improvement: 0.01,
            complexity_penalty: 0.0,
        });
        let state = IadlState::new(0.0, 999);
        let hypotheses: Vec<Box<dyn Hypothesis>> = vec![Box::new(FixedHypothesis {
            id: "improve".into(),
            prior: 1.0,
            score: 0.5,
            complexity: 100,
        })];
        let scorers: Vec<Box<dyn Scorer>> = vec![Box::new(PassthroughScorer)];
        let report = orch.run(state, &hypotheses, &scorers);
        // Score should have improved on the first iteration.
        assert!(report.final_state.global_score > 0.0);
    }

    #[test]
    fn candidate_evaluation_clone() {
        let eval = CandidateEvaluation {
            candidate: TentativeState::new("x", 0.5, 10, "r"),
            prior: 0.9,
            scorer_score: 0.8,
            final_score: 0.72,
            scorer_breakdown: vec![],
        };
        let cloned = eval.clone();
        assert_eq!(eval, cloned);
    }

    // ── New types: HashAlgorithm, ApiHash, IadlDetector, HashTable ─────────────

    #[test]
    fn hash_algorithm_name() {
        assert_eq!(HashAlgorithm::Djb2.name(), "djb2");
        assert_eq!(HashAlgorithm::Crc32.name(), "crc32");
        assert_eq!(HashAlgorithm::Unknown.name(), "unknown");
    }

    #[test]
    fn hash_algorithm_is_known() {
        assert!(HashAlgorithm::Fnv1a32.is_known());
        assert!(!HashAlgorithm::Unknown.is_known());
    }

    #[test]
    fn compute_hash_djb2_deterministic() {
        let h1 = compute_hash(b"LoadLibraryA", HashAlgorithm::Djb2);
        let h2 = compute_hash(b"LoadLibraryA", HashAlgorithm::Djb2);
        assert_eq!(h1, h2);
        assert_ne!(h1, 0);
    }

    #[test]
    fn compute_hash_fnv1a_empty_is_basis() {
        let h = compute_hash(b"", HashAlgorithm::Fnv1a32);
        assert_eq!(h, 0x811c_9dc5);
    }

    #[test]
    fn compute_hash_crc32_known_vector() {
        let h = compute_hash(b"123456789", HashAlgorithm::Crc32);
        assert_eq!(h, 0xCBF4_3926);
    }

    #[test]
    fn hash_table_build_and_resolve() {
        let names = ["VirtualAlloc", "GetProcAddress", "LoadLibraryA"];
        let table = HashTable::build(&names, HashAlgorithm::Djb2);
        assert_eq!(table.len(), 3);
        let h = compute_hash(b"VirtualAlloc", HashAlgorithm::Djb2);
        assert_eq!(table.resolve(h), Some("VirtualAlloc"));
        assert_eq!(table.resolve(0xDEAD_BEEF), None);
    }

    #[test]
    fn hash_table_insert() {
        let mut table = HashTable::new(HashAlgorithm::Crc32);
        table.insert("WinExec");
        assert_eq!(table.len(), 1);
        let h = compute_hash(b"WinExec", HashAlgorithm::Crc32);
        assert_eq!(table.resolve(h), Some("WinExec"));
    }

    #[test]
    fn hash_table_is_empty() {
        let table = HashTable::new(HashAlgorithm::Sdbm);
        assert!(table.is_empty());
    }

    #[test]
    fn api_hash_resolution_fields() {
        let a = ApiHash::new(0x1234, HashAlgorithm::Djb2, 0x400)
            .with_name("VirtualProtect")
            .with_dll("kernel32.dll");
        assert!(a.is_fully_resolved());
        assert!(a.is_resolved());
        assert_eq!(a.name.as_deref(), Some("VirtualProtect"));
        assert_eq!(a.dll.as_deref(), Some("kernel32.dll"));
    }

    #[test]
    fn api_resolution_confidence() {
        let h = ApiHash::new(0, HashAlgorithm::Crc32, 0);
        let r = ApiResolution::new(h, 0x401000).with_confidence(80);
        assert!(r.is_high_confidence());
        let h2 = ApiHash::new(0, HashAlgorithm::Crc32, 0);
        let r2 = ApiResolution::new(h2, 0x402000).with_confidence(50);
        assert!(!r2.is_high_confidence());
    }

    #[test]
    fn iadl_detector_scan_hash_constants() {
        let det = IadlDetector::new();
        // Insert a u32 with ≥8 set bits into a 4-byte buffer.
        let val: u32 = 0xF0F0_F0F0; // popcount = 16
        let data: Vec<u8> = val.to_le_bytes().to_vec();
        let consts = det.scan_hash_constants(&data);
        assert!(!consts.is_empty());
        assert_eq!(consts[0].0, u64::from(val));
    }

    #[test]
    fn iadl_detector_loadlib_pattern() {
        let det = IadlDetector::new();
        let data = vec![0x90, 0xFF, 0xD0, 0x90]; // CALL EAX at offset 1
        let offsets = det.detect_loadlib_pattern(&data);
        assert!(!offsets.is_empty());
        assert!(offsets.contains(&1));
    }

    #[test]
    fn iadl_detector_identify_algorithm() {
        let det = IadlDetector::new();
        let known = ["VirtualAlloc", "GetProcAddress"];
        let hashes: Vec<u64> = known
            .iter()
            .map(|n| compute_hash(n.as_bytes(), HashAlgorithm::Crc32))
            .collect();
        let (algo, matches) = det.identify_algorithm(&hashes);
        assert_eq!(algo, HashAlgorithm::Crc32);
        assert_eq!(matches, 2);
    }

    #[test]
    fn loadlib_chain_complete() {
        let mut chain = LoadLibraryChain::new();
        chain.push(ChainStep::new(0x1000, "LoadLibraryA").with_argument("kernel32.dll"));
        chain.push(ChainStep::new(0x1010, "GetProcAddress").with_argument("VirtualAlloc"));
        assert!(chain.is_complete());
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn loadlib_chain_not_complete_without_gpa() {
        let mut chain = LoadLibraryChain::new();
        chain.push(ChainStep::new(0x2000, "LoadLibraryA"));
        assert!(!chain.is_complete());
    }

    #[test]
    fn resolution_stats_from_resolutions() {
        let h1 = ApiHash::new(1, HashAlgorithm::Djb2, 0).with_name("VirtualAlloc");
        let h2 = ApiHash::new(2, HashAlgorithm::Djb2, 4); // unresolved
        let resolutions = vec![
            ApiResolution::new(h1, 0x1000),
            ApiResolution::new(h2, 0x1010),
        ];
        let stats = ResolutionStats::from_resolutions(&resolutions);
        assert_eq!(stats.total_hashes, 2);
        assert_eq!(stats.resolved, 1);
        assert_eq!(stats.unresolved, 1);
        assert!((stats.resolution_rate - 50.0).abs() < 1e-6);
    }

    #[test]
    fn resolution_stats_empty() {
        let stats = ResolutionStats::from_resolutions(&[]);
        assert_eq!(stats.total_hashes, 0);
        assert!((stats.resolution_rate).abs() < 1e-9);
    }

    #[test]
    fn constant_hypothesis_with_prior() {
        let h = ConstantHypothesis::new("ch", 0.8, 50, "test").with_prior(0.9);
        let state = IadlState::new(0.0, 100);
        assert!((h.prior(&state) - 0.9).abs() < 1e-9);
        let t = h.apply(&state);
        assert_eq!(t.hypothesis_id, "ch");
        assert!((t.score - 0.8).abs() < 1e-9);
    }

    #[test]
    fn incremental_hypothesis_applies_factor() {
        let h = IncrementalHypothesis::new("incr", 1.5);
        let state = IadlState::new(0.4, 100);
        let t = h.apply(&state);
        // Proposed score = 0.4 * 1.5 = 0.6.
        assert!((t.score - 0.6).abs() < 1e-9);
    }

    #[test]
    fn complexity_scorer_rewards_lower_complexity() {
        let scorer = ComplexityScorer::new(1.0);
        let baseline = IadlState::new(0.5, 100);
        let tentative = TentativeState::new("h", 0.7, 50, "");
        let score = scorer.score(&tentative, &baseline);
        assert!(score > 0.0, "lower complexity should score positively");
    }

    #[test]
    fn improvement_scorer_rewards_improvement() {
        let scorer = ImprovementScorer::new(1.0);
        let baseline = IadlState::new(0.3, 100);
        let tentative = TentativeState::new("h", 0.7, 100, "");
        let score = scorer.score(&tentative, &baseline);
        assert!((score - 0.4).abs() < 1e-9);
    }

    #[test]
    fn improvement_scorer_zero_for_no_improvement() {
        let scorer = ImprovementScorer::new(1.0);
        let baseline = IadlState::new(0.9, 100);
        let tentative = TentativeState::new("h", 0.5, 100, "");
        let score = scorer.score(&tentative, &baseline);
        assert!((score).abs() < 1e-9);
    }

    #[test]
    fn hypothesis_registry_register_and_list() {
        let mut reg = HypothesisRegistry::new();
        let h = Box::new(ConstantHypothesis::new("alpha", 0.5, 10, "test"));
        assert!(reg.register(h));
        let h2 = Box::new(ConstantHypothesis::new("beta", 0.6, 20, "test2"));
        assert!(reg.register(h2));
        assert_eq!(reg.len(), 2);
        let ids = reg.ids();
        assert_eq!(ids, vec!["alpha", "beta"]);
    }

    #[test]
    fn hypothesis_registry_no_duplicate_ids() {
        let mut reg = HypothesisRegistry::new();
        let h1 = Box::new(ConstantHypothesis::new("same", 0.5, 10, "first"));
        let h2 = Box::new(ConstantHypothesis::new("same", 0.8, 5, "duplicate"));
        assert!(reg.register(h1));
        assert!(!reg.register(h2)); // second registration rejected
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn iadl_deobf_pass_runs_loop() {
        let pass = IadlDeobfPass::new(
            "test_pass",
            IadlConfig {
                max_iterations: 3,
                max_no_progress: 10,
                min_improvement: 0.01,
                complexity_penalty: 0.0,
            },
        );
        assert_eq!(pass.name(), "test_pass");
        let hyps: Vec<Box<dyn Hypothesis>> =
            vec![Box::new(ConstantHypothesis::new("h", 0.7, 50, ""))];
        let scorers: Vec<Box<dyn Scorer>> = vec![];
        let report = pass.run(0.0, 100, &hyps, &scorers);
        assert!(report.final_state.global_score > 0.0);
    }

    // ── §37.1-37.2 Binary IADL tests ────────────────────────────────────────

    #[test]
    fn protection_layer_names_and_costs() {
        assert_eq!(ProtectionLayer::Packer("UPX".into()).name(), "Packer");
        assert_eq!(
            ProtectionLayer::CflFlattening.name(),
            "Control-Flow Flattening"
        );
        assert_eq!(ProtectionLayer::AntiDebug(0).removal_cost(), 20);
        assert!(ProtectionLayer::VmObfuscation("VMP".into()).removal_cost() > 50);
    }

    #[test]
    fn binary_tentative_state_combined_score() {
        let ts = BinaryTentativeState {
            hypothesis_name: "test".into(),
            modifications: vec![],
            estimated_naturalness: 1.0,
            estimated_complexity_reduction: 1.0,
        };
        let score = ts.combined_score();
        assert!((score - 1.0).abs() < 1e-9);

        let ts2 = BinaryTentativeState {
            hypothesis_name: "test2".into(),
            modifications: vec![],
            estimated_naturalness: 0.0,
            estimated_complexity_reduction: 0.0,
        };
        assert!((ts2.combined_score()).abs() < 1e-9);
    }

    #[test]
    fn binary_tentative_state_combined_score_weighted() {
        let ts = BinaryTentativeState {
            hypothesis_name: "t".into(),
            modifications: vec![],
            estimated_naturalness: 0.5,
            estimated_complexity_reduction: 0.0,
        };
        // 0.5 * 0.6 + 0.0 * 0.4 = 0.3
        assert!((ts.combined_score() - 0.3).abs() < 1e-9);
    }

    #[test]
    fn binary_iadl_state_has_packer() {
        let mut state = BinaryIadlState::new(1024, 10);
        assert!(!state.has_packer());
        state
            .identified_layers
            .push(ProtectionLayer::Packer("UPX".into()));
        assert!(state.has_packer());
    }

    #[test]
    fn binary_iadl_state_is_high_entropy() {
        let mut state = BinaryIadlState::new(512, 5);
        state.high_entropy_sections.push("UPX0".into());
        assert!(state.is_high_entropy("UPX0"));
        assert!(!state.is_high_entropy("UPX1"));
    }

    #[test]
    fn upx_unpack_hypothesis_prior_high_with_markers() {
        let h = UPXUnpackHypothesis;
        let mut state = BinaryIadlState::new(65536, 20);
        state.high_entropy_sections.push("UPX0".into());
        state.high_entropy_sections.push("UPX1".into());
        assert!(h.prior(&state) >= 0.8);
    }

    #[test]
    fn upx_unpack_hypothesis_prior_low_without_markers() {
        let h = UPXUnpackHypothesis;
        let state = BinaryIadlState::new(65536, 20);
        assert!(h.prior(&state) < 0.2);
    }

    #[test]
    fn upx_unpack_hypothesis_apply_produces_modifications() {
        let h = UPXUnpackHypothesis;
        let mut state = BinaryIadlState::new(65536, 20);
        state.high_entropy_sections.push("UPX0".into());
        let ts = h.apply(&state);
        assert!(!ts.modifications.is_empty());
        assert_eq!(ts.hypothesis_name, "UPXUnpack");
    }

    #[test]
    fn cfl_flattening_hypothesis_prior_scales_with_function_count() {
        let h = CflFlatteningHypothesis;
        let state_small = BinaryIadlState::new(65536, 10);
        let state_large = BinaryIadlState::new(65536, 200);
        assert!(h.prior(&state_large) > h.prior(&state_small));
    }

    #[test]
    fn antidebug_hypothesis_prior_high_with_markers() {
        let h = AntiDebugHypothesis;
        let mut state = BinaryIadlState::new(65536, 30);
        state.high_entropy_sections.push("IsDebuggerPresent".into());
        assert!(h.prior(&state) >= 0.9);
    }

    #[test]
    fn antidebug_hypothesis_prior_low_without_markers() {
        let h = AntiDebugHypothesis;
        let state = BinaryIadlState::new(65536, 30);
        assert!(h.prior(&state) < 0.3);
    }

    #[test]
    fn vm_obfuscation_hypothesis_prior_high_for_sparse_functions() {
        let h = VmObfuscationHypothesis;
        let mut state = BinaryIadlState::new(1_048_576, 2); // 1 MB, 2 functions
        state.high_entropy_sections.push("seg0".into());
        state.high_entropy_sections.push("seg1".into());
        assert!(h.prior(&state) >= 0.5);
    }

    #[test]
    fn naturalnessscorer_upx_boost() {
        let ts = BinaryTentativeState {
            hypothesis_name: "UPXUnpack".into(),
            modifications: vec!["step1".into()],
            estimated_naturalness: 0.8,
            estimated_complexity_reduction: 0.6,
        };
        let score = NaturalnessScorer::score(&ts);
        assert!(score > 0.5, "UPX should score high: {score}");
    }

    #[test]
    fn naturalnessscorer_many_modifications_penalised() {
        let few_mods = BinaryTentativeState {
            hypothesis_name: "X".into(),
            modifications: vec!["a".into()],
            estimated_naturalness: 0.6,
            estimated_complexity_reduction: 0.5,
        };
        let many_mods = BinaryTentativeState {
            hypothesis_name: "X".into(),
            modifications: (0..20).map(|i| format!("mod{i}")).collect(),
            estimated_naturalness: 0.6,
            estimated_complexity_reduction: 0.5,
        };
        assert!(
            NaturalnessScorer::score(&few_mods) >= NaturalnessScorer::score(&many_mods),
            "fewer modifications should not score worse"
        );
    }

    #[test]
    fn analyze_binary_for_protections_upx_markers() {
        // Construct a fake binary with UPX section names.
        let mut data = vec![0u8; 512];
        data[100..104].copy_from_slice(b"UPX0");
        data[200..204].copy_from_slice(b"UPX1");
        let state = analyze_binary_for_protections(&data);
        assert!(
            state.high_entropy_sections.iter().any(|s| s == "UPX0"),
            "UPX0 marker should be detected"
        );
    }

    #[test]
    fn analyze_binary_for_protections_antidebug_string() {
        let mut data = vec![0u8; 512];
        let marker = b"IsDebuggerPresent";
        data[50..50 + marker.len()].copy_from_slice(marker);
        let state = analyze_binary_for_protections(&data);
        assert!(
            state
                .high_entropy_sections
                .iter()
                .any(|s| s == "IsDebuggerPresent"),
            "anti-debug marker should be detected"
        );
    }

    #[test]
    fn analyze_binary_for_protections_function_count() {
        // Embed a few x86 prologues.
        let prologue: &[u8] = &[0x55, 0x8B, 0xEC];
        let mut data = vec![0x90u8; 256];
        for i in 0..5 {
            let offset = i * 40;
            data[offset..offset + 3].copy_from_slice(prologue);
        }
        let state = analyze_binary_for_protections(&data);
        assert!(
            state.function_count >= 5,
            "should detect at least 5 prologues"
        );
    }

    #[test]
    fn analyze_binary_empty_does_not_panic() {
        let state = analyze_binary_for_protections(&[]);
        assert_eq!(state.binary_size, 0);
        assert_eq!(state.function_count, 0);
    }

    #[test]
    fn binary_iadl_orchestrator_runs_clean_binary() {
        let mut orch = BinaryIadlOrchestrator::new();
        let report = orch.run(&[0u8; 256]);
        // Clean binary → few passes should be applied, loop should terminate cleanly.
        assert!(report.iterations_run > 0);
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn binary_iadl_orchestrator_upx_binary_applies_unpack() {
        // Simulate a UPX-packed binary with section markers.
        let mut data = vec![0x90u8; 4096];
        data[0..4].copy_from_slice(b"UPX0");
        data[512..516].copy_from_slice(b"UPX1");
        // Fill a window with high-entropy bytes (alternating pattern).
        for (i, b) in data[1024..1280].iter_mut().enumerate() {
            *b = ((i * 73 + 19) & 0xFF) as u8;
        }
        let mut orch = BinaryIadlOrchestrator::new();
        let report = orch.run(&data);
        assert!(
            report.applied_passes.iter().any(|p| p == "UPXUnpack"),
            "UPXUnpack should have been applied; passes: {:?}",
            report.applied_passes
        );
    }

    #[test]
    fn binary_iadl_orchestrator_antidebug_binary_applies_patch() {
        let mut data = vec![0x90u8; 1024];
        let marker = b"IsDebuggerPresent";
        data[200..200 + marker.len()].copy_from_slice(marker);
        let mut orch = BinaryIadlOrchestrator::new();
        let report = orch.run(&data);
        assert!(
            report.applied_passes.iter().any(|p| p == "AntiDebug"),
            "AntiDebug should have been applied; passes: {:?}",
            report.applied_passes
        );
    }

    #[test]
    fn binary_iadl_report_has_progress() {
        let report = BinaryIadlReport {
            iterations_run: 3,
            layers_identified: vec![],
            applied_passes: vec!["UPXUnpack".into()],
            final_score: 0.8,
            recommendations: vec!["rec".into()],
            time_elapsed_ms: 50,
        };
        assert!(report.has_progress());
        assert_eq!(report.top_recommendation(), Some("rec"));
    }

    #[test]
    fn binary_iadl_report_no_progress() {
        let report = BinaryIadlReport {
            iterations_run: 1,
            layers_identified: vec![],
            applied_passes: vec![],
            final_score: 0.0,
            recommendations: vec!["no passes applied".into()],
            time_elapsed_ms: 5,
        };
        assert!(!report.has_progress());
    }

    #[test]
    fn opaque_predicate_hypothesis_prior_scales_with_density() {
        let h = OpaquePredicateHypothesis;
        // Very high function density: 500 functions in 8 KB → density ~62 > 2.0
        let dense = BinaryIadlState::new(8192, 500);
        // Low density: 2 functions in 1 MB → density ~0.002
        let sparse = BinaryIadlState::new(1_048_576, 2);
        assert!(
            h.prior(&dense) > h.prior(&sparse),
            "dense should have higher prior than sparse"
        );
    }

    #[test]
    fn string_decrypt_hypothesis_prior_with_entropy_and_functions() {
        let h = StringDecryptHypothesis;
        let mut state = BinaryIadlState::new(65536, 50);
        state.high_entropy_sections.push("window_000000".into());
        assert!(h.prior(&state) >= 0.5);
    }

    #[test]
    fn hypothesis_cost_estimates_are_positive() {
        let hypotheses: Vec<Box<dyn BinaryHypothesis>> = vec![
            Box::new(UPXUnpackHypothesis),
            Box::new(CflFlatteningHypothesis),
            Box::new(OpaquePredicateHypothesis),
            Box::new(StringDecryptHypothesis),
            Box::new(AntiDebugHypothesis),
            Box::new(VmObfuscationHypothesis),
        ];
        for h in &hypotheses {
            assert!(
                h.cost_estimate() > std::time::Duration::ZERO,
                "{} should have positive cost",
                h.name()
            );
        }
    }

    #[test]
    fn all_builtin_hypothesis_ids_are_unique() {
        let hypotheses: Vec<Box<dyn BinaryHypothesis>> = vec![
            Box::new(UPXUnpackHypothesis),
            Box::new(CflFlatteningHypothesis),
            Box::new(OpaquePredicateHypothesis),
            Box::new(StringDecryptHypothesis),
            Box::new(AntiDebugHypothesis),
            Box::new(VmObfuscationHypothesis),
        ];
        let mut ids: Vec<u64> = hypotheses.iter().map(|h| h.id()).collect();
        let original_len = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "all hypothesis IDs must be unique");
    }

    #[test]
    fn infer_layer_from_pass_name() {
        let state = BinaryIadlState::new(0, 0);
        assert!(matches!(
            infer_protection_layer("UPXUnpack", &state),
            Some(ProtectionLayer::Packer(_))
        ));
        assert!(matches!(
            infer_protection_layer("CflFlattening", &state),
            Some(ProtectionLayer::CflFlattening)
        ));
        assert!(matches!(
            infer_protection_layer("AntiDebug", &state),
            Some(ProtectionLayer::AntiDebug(_))
        ));
        assert!(infer_protection_layer("unknown_pass", &state).is_none());
    }

    #[test]
    fn shannon_entropy_all_zeros_is_zero() {
        let data = vec![0u8; 256];
        let e = shannon_entropy(&data);
        assert!(e.abs() < 1e-9, "all-zero buffer should have entropy 0");
    }

    #[test]
    fn shannon_entropy_uniform_is_eight() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!(
            (e - 8.0).abs() < 0.01,
            "uniform distribution should have entropy ~8"
        );
    }

    #[test]
    fn contains_bytes_finds_pattern() {
        assert!(contains_bytes(b"hello world", b"world"));
        assert!(!contains_bytes(b"hello world", b"xyz"));
        assert!(contains_bytes(b"UPX0MOREDATA", b"UPX0"));
    }

    #[test]
    fn count_pattern_counts_correctly() {
        let data = &[0x55u8, 0x8B, 0xEC, 0x90, 0x55, 0x8B, 0xEC];
        assert_eq!(count_pattern(data, &[0x55, 0x8B, 0xEC]), 2);
        assert_eq!(count_pattern(data, &[0xFF]), 0);
    }
}
