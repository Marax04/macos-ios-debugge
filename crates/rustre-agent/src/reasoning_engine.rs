//! `reasoning_engine` — AI reasoning engine for reverse engineering tasks.
//!
//! Provides a structured, multi-step reasoning pipeline that collects evidence,
//! generates and tests hypotheses, detects contradictions, and exports its chain
//! of reasoning as JSON or Markdown.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors produced by the reasoning engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReasoningError {
    /// A required hypothesis was not found in the chain.
    HypothesisNotFound(String),
    /// The reasoning chain is in a state that prevents the requested operation.
    InvalidState(String),
    /// Serialization / deserialization failed.
    SerdeError(String),
    /// Cache look-up error.
    CacheError(String),
    /// Task decomposition failed.
    DecompositionError(String),
}

impl fmt::Display for ReasoningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HypothesisNotFound(id) => write!(f, "hypothesis not found: {id}"),
            Self::InvalidState(msg) => write!(f, "invalid state: {msg}"),
            Self::SerdeError(msg) => write!(f, "serde error: {msg}"),
            Self::CacheError(msg) => write!(f, "cache error: {msg}"),
            Self::DecompositionError(msg) => write!(f, "decomposition error: {msg}"),
        }
    }
}

impl std::error::Error for ReasoningError {}

// ─── Confidence ──────────────────────────────────────────────────────────────

/// A probability-like confidence score in `[0.0, 1.0]`.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Confidence(f64);

impl Confidence {
    /// Create a new confidence value, clamping to `[0.0, 1.0]`.
    #[must_use] 
    pub const fn new(v: f64) -> Self {
        Self(v.clamp(0.0, 1.0))
    }

    /// Return the raw `f64` value.
    #[must_use] 
    pub const fn value(self) -> f64 {
        self.0
    }

    /// `true` when confidence is at least `threshold`.
    #[must_use] 
    pub fn at_least(self, threshold: f64) -> bool {
        self.0 >= threshold
    }

    /// Combine two confidence scores via conjunction (product).
    #[must_use] 
    pub fn and(self, other: Self) -> Self {
        Self::new(self.0 * other.0)
    }

    /// Combine two confidence scores via disjunction (probabilistic OR).
    #[must_use] 
    pub fn or(self, other: Self) -> Self {
        Self::new(self.0.mul_add(-other.0, self.0 + other.0))
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Self(0.5)
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.1}%", self.0 * 100.0)
    }
}

// ─── Evidence ────────────────────────────────────────────────────────────────

/// The type of evidence piece.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Disassembly observation (e.g. "uses SSE4.2 intrinsics").
    Disassembly,
    /// String literal found in the binary.
    StringLiteral,
    /// Import/export symbol.
    Symbol,
    /// Control-flow pattern.
    ControlFlow,
    /// Data structure pattern.
    DataStructure,
    /// Cryptographic constant.
    CryptographicConstant,
    /// Network protocol indicator.
    NetworkProtocol,
    /// Entropy measurement.
    Entropy,
    /// External tool output.
    ToolOutput(String),
    /// User-provided annotation.
    UserAnnotation,
}

/// A single piece of evidence supporting or refuting a hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Unique identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// What kind of evidence this is.
    pub kind: EvidenceKind,
    /// How strongly this evidence supports the hypothesis (positive) or refutes
    /// it (negative). Range `[-1.0, 1.0]`.
    pub weight: f64,
    /// Address in the binary where this evidence was observed.
    pub address: Option<u64>,
    /// Raw bytes or text payload associated with the evidence.
    pub payload: Option<String>,
    /// When was this piece of evidence collected.
    #[serde(skip)]
    pub collected_at: Option<Instant>,
}

impl Evidence {
    /// Create a new evidence item.
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        kind: EvidenceKind,
        weight: f64,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            kind,
            weight: weight.clamp(-1.0, 1.0),
            address: None,
            payload: None,
            collected_at: Some(Instant::now()),
        }
    }

    /// Attach a binary address to this evidence item.
    #[must_use] 
    pub const fn at_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Attach a textual payload.
    #[must_use]
    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = Some(payload.into());
        self
    }

    /// Returns `true` when the evidence is supportive (positive weight).
    #[must_use] 
    pub fn is_supportive(&self) -> bool {
        self.weight > 0.0
    }

    /// Returns `true` when the evidence refutes (negative weight).
    #[must_use] 
    pub fn is_contradictory(&self) -> bool {
        self.weight < 0.0
    }
}

// ─── Hypothesis ──────────────────────────────────────────────────────────────

/// Current status of a hypothesis.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HypothesisStatus {
    /// Newly created, not yet evaluated.
    Pending,
    /// Currently being evaluated.
    Active,
    /// Supported by evidence.
    Confirmed,
    /// Refuted by evidence.
    Refuted,
    /// Not enough evidence to decide.
    Inconclusive,
}

/// A testable claim about the binary being analysed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    /// Unique identifier (e.g. "hyp-crypto-aes").
    pub id: String,
    /// Human-readable claim.
    pub claim: String,
    /// All evidence collected for / against this hypothesis.
    pub evidence: Vec<Evidence>,
    /// Aggregated confidence after evidence weighing.
    pub confidence: Confidence,
    /// Current evaluation status.
    pub status: HypothesisStatus,
    /// Optional parent hypothesis this is derived from.
    pub parent_id: Option<String>,
    /// Tags for categorisation.
    pub tags: Vec<String>,
    /// When this hypothesis was first created.
    #[serde(skip)]
    pub created_at: Option<Instant>,
}

impl Hypothesis {
    /// Create a new pending hypothesis.
    pub fn new(id: impl Into<String>, claim: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            claim: claim.into(),
            evidence: Vec::new(),
            confidence: Confidence::default(),
            status: HypothesisStatus::Pending,
            parent_id: None,
            tags: Vec::new(),
            created_at: Some(Instant::now()),
        }
    }

    /// Add a tag.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set the parent hypothesis identifier.
    #[must_use]
    pub fn with_parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    /// Add an evidence item and recalculate confidence.
    pub fn add_evidence(&mut self, ev: Evidence) {
        self.evidence.push(ev);
        self.recalculate_confidence();
    }

    /// Recalculate aggregate confidence from all evidence weights.
    ///
    /// Uses a simple Bayesian-style update: start at 0.5 and nudge proportionally
    /// to each evidence weight.
    pub fn recalculate_confidence(&mut self) {
        if self.evidence.is_empty() {
            self.confidence = Confidence::default();
            return;
        }
        let mut score: f64 = 0.5;
        for ev in &self.evidence {
            // Each evidence nudges the score by `weight * (1 - current_distance_from_extreme)`.
            let delta = ev.weight * 0.15;
            score = (score + delta).clamp(0.0, 1.0);
        }
        self.confidence = Confidence::new(score);
        self.status = if score >= 0.75 {
            HypothesisStatus::Confirmed
        } else if score <= 0.25 {
            HypothesisStatus::Refuted
        } else {
            HypothesisStatus::Inconclusive
        };
    }

    /// Total supporting weight.
    #[must_use] 
    pub fn support_weight(&self) -> f64 {
        self.evidence
            .iter()
            .filter(|e| e.is_supportive())
            .map(|e| e.weight)
            .sum()
    }

    /// Total contradicting weight (returned as positive number).
    #[must_use] 
    pub fn contradiction_weight(&self) -> f64 {
        self.evidence
            .iter()
            .filter(|e| e.is_contradictory())
            .map(|e| -e.weight)
            .sum()
    }
}

// ─── EvidenceCollector ───────────────────────────────────────────────────────

/// Collects evidence for one or more hypotheses from binary data.
#[derive(Debug, Default)]
pub struct EvidenceCollector {
    collected: Vec<Evidence>,
    next_id: usize,
}

impl EvidenceCollector {
    /// Create a fresh collector.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate the next evidence ID.
    fn next_id(&mut self) -> String {
        self.next_id += 1;
        format!("ev-{:04}", self.next_id)
    }

    /// Scan raw bytes for high-entropy regions (possible encrypted/compressed data).
    pub fn collect_entropy_evidence(&mut self, bytes: &[u8], window: usize) -> Vec<Evidence> {
        let mut results = Vec::new();
        if window == 0 || bytes.len() < window {
            return results;
        }
        let step = (window / 2).max(1);
        for start in (0..bytes.len() - window).step_by(step) {
            let chunk = &bytes[start..start + window];
            let entropy = shannon_entropy(chunk);
            if entropy >= 5.5 {
                let id = self.next_id();
                let ev = Evidence::new(
                    id,
                    format!("High entropy ({entropy:.2} bits) at offset 0x{start:x}"),
                    EvidenceKind::Entropy,
                    0.6,
                )
                .at_address(start as u64);
                results.push(ev.clone());
                self.collected.push(ev);
            }
        }
        results
    }

    /// Scan for well-known cryptographic constants.
    pub fn collect_crypto_constants(&mut self, bytes: &[u8]) -> Vec<Evidence> {
        const CRYPTO_CONSTANTS: &[(u32, &str)] = &[
            (0x6745_2301, "MD5/SHA-1 init constant A"),
            (0xEFCD_AB89, "MD5/SHA-1 init constant B"),
            (0x98BA_DCFE, "MD5/SHA-1 init constant C"),
            (0x1032_5476, "MD5/SHA-1 init constant D"),
            (0x6A09_E667, "SHA-256 init constant H0"),
            (0xBB67_AE85, "SHA-256 init constant H1"),
            (0x3C6E_F372, "SHA-256 init constant H2"),
            (0xA54F_F53A, "SHA-256 init constant H3"),
            (0x63, "AES S-box first byte"),
        ];
        let mut results = Vec::new();
        for i in 0..bytes.len().saturating_sub(3) {
            let word =
                u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
            for &(constant, name) in CRYPTO_CONSTANTS {
                if word == constant {
                    let id = self.next_id();
                    let ev = Evidence::new(
                        id,
                        format!("Found crypto constant: {name} at 0x{i:x}"),
                        EvidenceKind::CryptographicConstant,
                        0.85,
                    )
                    .at_address(i as u64);
                    results.push(ev.clone());
                    self.collected.push(ev);
                    break;
                }
            }
        }
        results
    }

    /// Collect all gathered evidence.
    pub fn drain(&mut self) -> Vec<Evidence> {
        std::mem::take(&mut self.collected)
    }

    /// Peek at collected evidence without consuming.
    #[must_use] 
    pub fn peek(&self) -> &[Evidence] {
        &self.collected
    }

    /// Add evidence directly.
    pub fn add(&mut self, ev: Evidence) {
        self.collected.push(ev);
    }
}

/// Compute Shannon entropy (bits per byte) of a byte slice.
#[must_use] 
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = crate::casts::usize_to_f64(data.len());
    counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = crate::casts::u64_to_f64(c) / len;
        p.mul_add(-p.log2(), acc)
    })
}

// ─── ContradictionDetector ───────────────────────────────────────────────────

/// Detects when two hypotheses are contradictory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contradiction {
    /// First hypothesis ID.
    pub hyp_a: String,
    /// Second hypothesis ID.
    pub hyp_b: String,
    /// Human-readable explanation.
    pub explanation: String,
    /// Severity: 0.0 (mild) to 1.0 (definite contradiction).
    pub severity: f64,
}

/// Detects logical contradictions between hypotheses.
#[derive(Debug, Default)]
pub struct ContradictionDetector {
    /// Rules: pairs of tag sets that are mutually exclusive.
    mutual_exclusion_rules: Vec<(String, String)>,
}

impl ContradictionDetector {
    /// Create a new detector with default rules.
    #[must_use] 
    pub fn new() -> Self {
        let mut d = Self::default();
        // Well-known mutually exclusive tag pairs.
        for pair in &[
            ("32-bit", "64-bit"),
            ("little-endian", "big-endian"),
            ("packed", "not-packed"),
            ("encrypted", "not-encrypted"),
            ("interpreted", "compiled"),
        ] {
            d.add_exclusion_rule(pair.0, pair.1);
        }
        d
    }

    /// Register a new mutual-exclusion rule.
    pub fn add_exclusion_rule(&mut self, tag_a: impl Into<String>, tag_b: impl Into<String>) {
        self.mutual_exclusion_rules
            .push((tag_a.into(), tag_b.into()));
    }

    /// Scan a list of hypotheses for contradictions.
    #[must_use] 
    pub fn detect(&self, hypotheses: &[Hypothesis]) -> Vec<Contradiction> {
        let mut contradictions = Vec::new();
        for i in 0..hypotheses.len() {
            for j in (i + 1)..hypotheses.len() {
                let ha = &hypotheses[i];
                let hb = &hypotheses[j];
                // Check only confirmed or active hypotheses.
                if !matches!(
                    ha.status,
                    HypothesisStatus::Confirmed | HypothesisStatus::Active
                ) {
                    continue;
                }
                if !matches!(
                    hb.status,
                    HypothesisStatus::Confirmed | HypothesisStatus::Active
                ) {
                    continue;
                }
                for (ta, tb) in &self.mutual_exclusion_rules {
                    let a_has = ha.tags.contains(ta);
                    let b_has = hb.tags.contains(tb);
                    let a_has_b = ha.tags.contains(tb);
                    let b_has_a = hb.tags.contains(ta);
                    if (a_has && b_has) || (a_has_b && b_has_a) {
                        let severity = ha.confidence.value() * hb.confidence.value();
                        contradictions.push(Contradiction {
                            hyp_a: ha.id.clone(),
                            hyp_b: hb.id.clone(),
                            explanation: format!(
                                "Hypotheses '{}' and '{}' are mutually exclusive (tags: {}/{}).",
                                ha.id, hb.id, ta, tb
                            ),
                            severity,
                        });
                    }
                }
            }
        }
        contradictions
    }
}

// ─── ReasoningStep ───────────────────────────────────────────────────────────

/// The kind of reasoning step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepKind {
    /// Formulate a new hypothesis.
    FormulateHypothesis,
    /// Gather evidence.
    CollectEvidence,
    /// Test a hypothesis against evidence.
    TestHypothesis,
    /// Detect contradictions.
    DetectContradictions,
    /// Revise a hypothesis based on new evidence.
    Revise,
    /// Draw a conclusion.
    Conclude,
    /// Sub-task spawned by task decomposition.
    SubTask,
}

/// A single step in a reasoning chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    /// Sequential index within the chain.
    pub index: usize,
    /// What kind of step this is.
    pub kind: StepKind,
    /// Natural-language description of what happened in this step.
    pub description: String,
    /// Which hypothesis this step acts on (if any).
    pub hypothesis_id: Option<String>,
    /// Evidence items produced or consumed.
    pub evidence_ids: Vec<String>,
    /// Confidence after this step.
    pub confidence_after: Option<Confidence>,
    /// Elapsed time for this step.
    #[serde(skip)]
    pub duration: Option<Duration>,
}

impl ReasoningStep {
    /// Create a new step.
    pub fn new(index: usize, kind: StepKind, description: impl Into<String>) -> Self {
        Self {
            index,
            kind,
            description: description.into(),
            hypothesis_id: None,
            evidence_ids: Vec::new(),
            confidence_after: None,
            duration: None,
        }
    }
}

// ─── ReasoningChain ──────────────────────────────────────────────────────────

/// An ordered sequence of reasoning steps forming a complete analysis.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ReasoningChain {
    /// The title / goal of this chain.
    pub title: String,
    /// Ordered steps.
    pub steps: Vec<ReasoningStep>,
    /// All hypotheses tracked.
    pub hypotheses: HashMap<String, Hypothesis>,
    /// Detected contradictions.
    pub contradictions: Vec<Contradiction>,
    /// Overall conclusion drawn at the end.
    pub conclusion: Option<String>,
}

impl ReasoningChain {
    /// Create a new chain with the given goal.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            ..Default::default()
        }
    }

    /// Append a step.
    pub fn push_step(&mut self, step: ReasoningStep) {
        self.steps.push(step);
    }

    /// Register a hypothesis.
    pub fn add_hypothesis(&mut self, hyp: Hypothesis) {
        let index = self.steps.len();
        let mut step = ReasoningStep::new(
            index,
            StepKind::FormulateHypothesis,
            format!("Formulate hypothesis: {}", hyp.claim),
        );
        step.hypothesis_id = Some(hyp.id.clone());
        self.steps.push(step);
        self.hypotheses.insert(hyp.id.clone(), hyp);
    }

    /// Update a hypothesis with new evidence.
    /// # Errors
    /// Returns `ReasoningError` if the hypothesis id is not registered.
    pub fn update_hypothesis(
        &mut self,
        hyp_id: &str,
        evidence: Vec<Evidence>,
    ) -> Result<(), ReasoningError> {
        let hyp = self
            .hypotheses
            .get_mut(hyp_id)
            .ok_or_else(|| ReasoningError::HypothesisNotFound(hyp_id.to_string()))?;
        let evidence_ids: Vec<_> = evidence.iter().map(|e| e.id.clone()).collect();
        for ev in evidence {
            hyp.add_evidence(ev);
        }
        let confidence_after = hyp.confidence;
        let index = self.steps.len();
        let mut step = ReasoningStep::new(
            index,
            StepKind::TestHypothesis,
            format!(
                "Test hypothesis '{hyp_id}': confidence now {confidence_after}"
            ),
        );
        step.hypothesis_id = Some(hyp_id.to_string());
        step.evidence_ids = evidence_ids;
        step.confidence_after = Some(confidence_after);
        self.steps.push(step);
        Ok(())
    }

    /// Set the final conclusion.
    pub fn conclude(&mut self, conclusion: impl Into<String>) {
        let text = conclusion.into();
        let index = self.steps.len();
        self.steps
            .push(ReasoningStep::new(index, StepKind::Conclude, text.clone()));
        self.conclusion = Some(text);
    }

    /// Return confirmed hypotheses sorted by confidence descending.
    #[must_use] 
    pub fn confirmed_hypotheses(&self) -> Vec<&Hypothesis> {
        let mut confirmed: Vec<_> = self
            .hypotheses
            .values()
            .filter(|h| h.status == HypothesisStatus::Confirmed)
            .collect();
        confirmed.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        confirmed
    }

    /// Return highest-confidence hypothesis (any status).
    #[must_use] 
    pub fn top_hypothesis(&self) -> Option<&Hypothesis> {
        self.hypotheses
            .values()
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal))
    }
}

// ─── TaskDecomposer ──────────────────────────────────────────────────────────

/// A sub-task produced by decomposing a larger RE task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubTask {
    /// Unique identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Estimated difficulty (0 = trivial, 10 = very hard).
    pub difficulty: u8,
    /// Whether this sub-task depends on another sub-task's completion.
    pub depends_on: Vec<String>,
    /// Tags for routing to the right tool / agent.
    pub tags: Vec<String>,
    /// Priority (higher = more urgent).
    pub priority: u8,
}

impl SubTask {
    /// Create a new sub-task.
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        difficulty: u8,
        priority: u8,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            difficulty: difficulty.min(10),
            depends_on: Vec::new(),
            tags: Vec::new(),
            priority: priority.min(10),
        }
    }
}

/// Decomposes complex RE tasks into a directed acyclic graph of sub-tasks.
#[derive(Debug, Default)]
pub struct TaskDecomposer {
    strategies: Vec<DecompositionStrategy>,
}

/// A decomposition strategy maps a high-level goal to sub-tasks.
#[derive(Debug, Clone)]
pub struct DecompositionStrategy {
    /// Pattern in the goal string that triggers this strategy.
    pub trigger_pattern: String,
    /// Sub-tasks to emit (their descriptions; IDs are auto-generated).
    pub sub_task_templates: Vec<(&'static str, u8, u8)>, // (description, difficulty, priority)
}

impl TaskDecomposer {
    /// Create a decomposer with built-in strategies.
    #[must_use] 
    pub fn new() -> Self {
        let mut d = Self::default();
        d.add_strategy(DecompositionStrategy {
            trigger_pattern: "malware".to_string(),
            sub_task_templates: vec![
                ("Identify packer/obfuscator", 4, 9),
                ("Unpack/deobfuscate binary", 7, 8),
                ("Identify C2 communication", 5, 7),
                ("Extract IoCs (IPs, URLs, hashes)", 3, 8),
                ("Analyse persistence mechanisms", 5, 6),
                ("Identify payload dropping", 6, 7),
            ],
        });
        d.add_strategy(DecompositionStrategy {
            trigger_pattern: "crypto".to_string(),
            sub_task_templates: vec![
                ("Detect cryptographic primitives", 3, 9),
                ("Recover encryption keys", 8, 8),
                ("Identify block cipher mode", 5, 7),
                ("Detect custom/broken crypto", 7, 8),
            ],
        });
        d.add_strategy(DecompositionStrategy {
            trigger_pattern: "protocol".to_string(),
            sub_task_templates: vec![
                ("Capture network traffic", 2, 9),
                ("Identify protocol framing", 5, 8),
                ("Reverse message types", 6, 7),
                ("Build protocol grammar", 8, 6),
            ],
        });
        d.add_strategy(DecompositionStrategy {
            trigger_pattern: "vulnerability".to_string(),
            sub_task_templates: vec![
                ("Identify attack surface", 3, 9),
                ("Find input parsing code", 4, 8),
                ("Check bounds validation", 5, 8),
                ("Trace data flow to sinks", 7, 7),
                ("Estimate exploitability", 8, 6),
            ],
        });
        d
    }

    /// Add a custom decomposition strategy.
    pub fn add_strategy(&mut self, strategy: DecompositionStrategy) {
        self.strategies.push(strategy);
    }

    /// Decompose a goal string into sub-tasks.
    /// # Errors
    /// Returns `ReasoningError` if decomposition fails.
    pub fn decompose(&self, goal: &str) -> Result<Vec<SubTask>, ReasoningError> {
        let goal_lower = goal.to_lowercase();
        let mut tasks = Vec::new();
        let mut counter = 0usize;

        for strategy in &self.strategies {
            if goal_lower.contains(&strategy.trigger_pattern) {
                for &(desc, diff, prio) in &strategy.sub_task_templates {
                    counter += 1;
                    let prefix: String = strategy.trigger_pattern.chars().take(4).collect();
                    let id = format!("task-{prefix}-{counter:03}");
                    tasks.push(SubTask::new(id, desc, diff, prio));
                }
            }
        }

        if tasks.is_empty() {
            // Generic decomposition fallback.
            tasks.push(SubTask::new("task-001", "Static analysis of binary", 3, 8));
            tasks.push(SubTask::new(
                "task-002",
                "Dynamic analysis / emulation",
                5,
                7,
            ));
            tasks.push(SubTask::new(
                "task-003",
                "Identify interesting functions",
                4,
                7,
            ));
            tasks.push(SubTask::new("task-004", "Document findings", 2, 5));
        }

        // Sort by priority descending.
        tasks.sort_by(|a, b| b.priority.cmp(&a.priority));
        Ok(tasks)
    }
}

// ─── ReasoningCache ──────────────────────────────────────────────────────────

/// A simple in-memory cache for reasoning chains keyed by binary hash or task ID.
#[derive(Debug, Default)]
pub struct ReasoningCache {
    entries: HashMap<String, CachedChain>,
    max_entries: usize,
    lru_order: VecDeque<String>,
}

#[derive(Debug, Clone)]
struct CachedChain {
    chain: Arc<ReasoningChain>,
    inserted_at: Instant,
    hits: u64,
}

impl ReasoningCache {
    /// Create a cache with the given capacity.
    #[must_use] 
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            lru_order: VecDeque::new(),
        }
    }

    /// Insert a reasoning chain.
    pub fn insert(&mut self, key: impl Into<String>, chain: ReasoningChain) {
        let key = key.into();
        if self.entries.len() >= self.max_entries
            && let Some(evict) = self.lru_order.pop_front() {
                self.entries.remove(&evict);
            }
        self.lru_order.push_back(key.clone());
        self.entries.insert(
            key,
            CachedChain {
                chain: Arc::new(chain),
                inserted_at: Instant::now(),
                hits: 0,
            },
        );
    }

    /// Look up a chain.
    pub fn get(&mut self, key: &str) -> Option<Arc<ReasoningChain>> {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.hits += 1;
            // Move to back of LRU queue.
            if let Some(pos) = self.lru_order.iter().position(|k| k == key) {
                self.lru_order.remove(pos);
                self.lru_order.push_back(key.to_string());
            }
            Some(Arc::clone(&entry.chain))
        } else {
            None
        }
    }

    /// Number of entries currently cached.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the cache is empty.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.lru_order.clear();
    }

    /// Total cache hits across all entries.
    #[must_use] 
    pub fn total_hits(&self) -> u64 {
        self.entries.values().map(|e| e.hits).sum()
    }

    /// Return the age (since insertion) of the cached entry for `key`,
    /// or `None` if the key is not present.
    #[must_use] 
    pub fn entry_age(&self, key: &str) -> Option<std::time::Duration> {
        self.entries.get(key).map(|e| e.inserted_at.elapsed())
    }

    /// Return the age of the oldest entry currently held in the cache.
    #[must_use] 
    pub fn oldest_entry_age(&self) -> Option<std::time::Duration> {
        self.entries.values().map(|e| e.inserted_at.elapsed()).max()
    }
}

// ─── ReasoningExport ─────────────────────────────────────────────────────────

/// Serialization formats for exporting a reasoning chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// JSON (pretty-printed).
    Json,
    /// Markdown document.
    Markdown,
    /// Plain text summary.
    PlainText,
}

/// Exports a [`ReasoningChain`] to various formats.
pub struct ReasoningExport;

impl ReasoningExport {
    /// Export the chain in the requested format.
    /// # Errors
    /// Returns `ReasoningError` if serialization for the requested format fails.
    pub fn export(chain: &ReasoningChain, format: ExportFormat) -> Result<String, ReasoningError> {
        match format {
            ExportFormat::Json => serde_json::to_string_pretty(chain)
                .map_err(|e| ReasoningError::SerdeError(e.to_string())),
            ExportFormat::Markdown => Ok(Self::to_markdown(chain)),
            ExportFormat::PlainText => Ok(Self::to_plain_text(chain)),
        }
    }

    fn to_markdown(chain: &ReasoningChain) -> String {
        use std::fmt::Write as _;
        let mut buf = String::new();
        let _ = write!(buf, "# Reasoning Chain: {}\n\n", chain.title);

        buf.push_str("## Steps\n\n");
        for step in &chain.steps {
            let _ = writeln!(
                buf,
                "{}. **[{:?}]** {}",
                step.index + 1,
                step.kind,
                step.description
            );
            if let Some(c) = step.confidence_after {
                let _ = writeln!(buf, "   *Confidence: {c}*");
            }
        }

        buf.push_str("\n## Hypotheses\n\n");
        for hyp in chain.hypotheses.values() {
            let _ = write!(
                buf,
                "### {} — {:?} ({})\n\n",
                hyp.id, hyp.status, hyp.confidence
            );
            let _ = write!(buf, "**Claim:** {}\n\n", hyp.claim);
            if !hyp.evidence.is_empty() {
                buf.push_str("**Evidence:**\n");
                for ev in &hyp.evidence {
                    let sign = if ev.weight >= 0.0 { "+" } else { "-" };
                    let _ = writeln!(
                        buf,
                        "- [{}] {} (weight: {:.2})",
                        sign, ev.description, ev.weight
                    );
                }
                buf.push('\n');
            }
        }

        if !chain.contradictions.is_empty() {
            buf.push_str("## Contradictions\n\n");
            for c in &chain.contradictions {
                let _ = writeln!(
                    buf,
                    "- **{} ↔ {}**: {} (severity: {:.2})",
                    c.hyp_a, c.hyp_b, c.explanation, c.severity
                );
            }
            buf.push('\n');
        }

        if let Some(conclusion) = &chain.conclusion {
            let _ = write!(buf, "## Conclusion\n\n{conclusion}\n");
        }

        buf
    }

    fn to_plain_text(chain: &ReasoningChain) -> String {
        use std::fmt::Write as _;
        let mut buf = String::new();
        let _ = writeln!(buf, "REASONING CHAIN: {}", chain.title);
        buf.push_str(&"─".repeat(60));
        buf.push('\n');
        for step in &chain.steps {
            let _ = writeln!(
                buf,
                "[Step {}] {:?}: {}",
                step.index + 1,
                step.kind,
                step.description
            );
        }
        buf.push_str(&"─".repeat(60));
        buf.push('\n');
        if let Some(c) = &chain.conclusion {
            let _ = writeln!(buf, "CONCLUSION: {c}");
        }
        buf
    }
}

// ─── ReasoningEngine ─────────────────────────────────────────────────────────

/// Configuration for the reasoning engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningEngineConfig {
    /// Confidence threshold above which a hypothesis is considered confirmed.
    pub confirmation_threshold: f64,
    /// Confidence threshold below which a hypothesis is considered refuted.
    pub refutation_threshold: f64,
    /// Maximum number of reasoning steps before forcing a conclusion.
    pub max_steps: usize,
    /// Whether to automatically detect contradictions after each update.
    pub auto_detect_contradictions: bool,
    /// Cache capacity.
    pub cache_capacity: usize,
}

impl Default for ReasoningEngineConfig {
    fn default() -> Self {
        Self {
            confirmation_threshold: 0.75,
            refutation_threshold: 0.25,
            max_steps: 200,
            auto_detect_contradictions: true,
            cache_capacity: 64,
        }
    }
}

/// Statistics emitted by the engine.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReasoningStats {
    /// Total hypotheses created.
    pub hypotheses_created: u64,
    /// Total evidence items collected.
    pub evidence_items: u64,
    /// Total contradictions detected.
    pub contradictions_detected: u64,
    /// Total reasoning chains completed.
    pub chains_completed: u64,
    /// Total sub-tasks generated.
    pub sub_tasks_generated: u64,
}

/// The main AI reasoning engine for reverse engineering tasks.
///
/// Orchestrates hypothesis generation, evidence collection, contradiction
/// detection, task decomposition, and export.
pub struct ReasoningEngine {
    config: ReasoningEngineConfig,
    cache: ReasoningCache,
    contradiction_detector: ContradictionDetector,
    task_decomposer: TaskDecomposer,
    stats: Arc<Mutex<ReasoningStats>>,
}

impl ReasoningEngine {
    /// Create a new engine with default configuration.
    #[must_use] 
    pub fn new() -> Self {
        Self::with_config(ReasoningEngineConfig::default())
    }

    /// Create a new engine with custom configuration.
    #[must_use] 
    pub fn with_config(config: ReasoningEngineConfig) -> Self {
        Self {
            cache: ReasoningCache::with_capacity(config.cache_capacity),
            contradiction_detector: ContradictionDetector::new(),
            task_decomposer: TaskDecomposer::new(),
            stats: Arc::new(Mutex::new(ReasoningStats::default())),
            config,
        }
    }

    /// Start a new reasoning chain for the given goal.
    pub fn start_chain(&self, title: impl Into<String>) -> ReasoningChain {
        ReasoningChain::new(title)
    }

    /// Add a hypothesis to a chain and return a mutable reference path.
    pub fn add_hypothesis(&self, chain: &mut ReasoningChain, hyp: Hypothesis) {
        if let Ok(mut s) = self.stats.lock() {
            s.hypotheses_created += 1;
        }
        chain.add_hypothesis(hyp);
    }

    /// Collect evidence and attach it to a hypothesis.
    /// # Errors
    /// Returns `ReasoningError` if the hypothesis is unknown or attaching fails.
    pub fn collect_and_attach(
        &self,
        chain: &mut ReasoningChain,
        hyp_id: &str,
        evidence: Vec<Evidence>,
    ) -> Result<(), ReasoningError> {
        if let Ok(mut s) = self.stats.lock() {
            s.evidence_items += evidence.len() as u64;
        }
        chain.update_hypothesis(hyp_id, evidence)?;
        if self.config.auto_detect_contradictions {
            let hyps: Vec<_> = chain.hypotheses.values().cloned().collect();
            let new_contradictions = self.contradiction_detector.detect(&hyps);
            if let Ok(mut s) = self.stats.lock() {
                s.contradictions_detected += new_contradictions.len() as u64;
            }
            chain.contradictions.extend(new_contradictions);
        }
        Ok(())
    }

    /// Decompose a goal into sub-tasks.
    /// # Errors
    /// Returns `ReasoningError` if the decomposer fails.
    pub fn decompose_goal(&self, goal: &str) -> Result<Vec<SubTask>, ReasoningError> {
        let tasks = self.task_decomposer.decompose(goal)?;
        if let Ok(mut s) = self.stats.lock() {
            s.sub_tasks_generated += tasks.len() as u64;
        }
        Ok(tasks)
    }

    /// Finalize a chain: detect all contradictions, draw conclusion, cache result.
    pub fn finalize_chain(
        &mut self,
        mut chain: ReasoningChain,
        cache_key: Option<&str>,
    ) -> ReasoningChain {
        // Final contradiction pass.
        let hyps: Vec<_> = chain.hypotheses.values().cloned().collect();
        let contradictions = self.contradiction_detector.detect(&hyps);
        chain.contradictions.extend(contradictions);

        // Auto-conclude if not already done.
        if chain.conclusion.is_none() {
            if let Some(top) = chain.top_hypothesis() {
                let conclusion = format!(
                    "Most likely: '{}' (confidence: {})",
                    top.claim, top.confidence
                );
                chain.conclude(conclusion);
            } else {
                chain.conclude("Insufficient evidence to draw a conclusion.");
            }
        }

        if let Ok(mut s) = self.stats.lock() {
            s.chains_completed += 1;
        }

        if let Some(key) = cache_key {
            self.cache.insert(key, chain.clone());
        }

        chain
    }

    /// Retrieve a cached chain.
    pub fn get_cached(&mut self, key: &str) -> Option<Arc<ReasoningChain>> {
        self.cache.get(key)
    }

    /// Export a chain to the given format.
    /// # Errors
    /// Returns `ReasoningError` if serialization fails.
    pub fn export(
        &self,
        chain: &ReasoningChain,
        format: ExportFormat,
    ) -> Result<String, ReasoningError> {
        ReasoningExport::export(chain, format)
    }

    /// Return a snapshot of current statistics.
    #[must_use] 
    pub fn stats(&self) -> ReasoningStats {
        self.stats.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Access the internal cache.
    #[must_use] 
    pub const fn cache(&self) -> &ReasoningCache {
        &self.cache
    }

    /// Access the config.
    #[must_use] 
    pub const fn config(&self) -> &ReasoningEngineConfig {
        &self.config
    }
}

impl Default for ReasoningEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Clone impl for ReasoningChain ──────────────────────────────────────────

impl Clone for ReasoningChain {
    fn clone(&self) -> Self {
        Self {
            title: self.title.clone(),
            steps: self.steps.clone(),
            hypotheses: self.hypotheses.clone(),
            contradictions: self.contradictions.clone(),
            conclusion: self.conclusion.clone(),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_evidence(id: &str, weight: f64) -> Evidence {
        Evidence::new(id, "test evidence", EvidenceKind::Disassembly, weight)
    }

    #[test]
    fn confidence_clamp() {
        assert!((Confidence::new(1.5).value() - 1.0).abs() < 1e-9);
        assert!(Confidence::new(-0.5).value().abs() < 1e-9);
    }

    #[test]
    fn confidence_and_or() {
        let a = Confidence::new(0.8);
        let b = Confidence::new(0.6);
        assert!((a.and(b).value() - 0.48).abs() < 1e-9);
        let expected_or = 0.8f64.mul_add(-0.6, 0.8 + 0.6);
        assert!((a.or(b).value() - expected_or).abs() < 1e-9);
    }

    #[test]
    fn hypothesis_status_confirmed() {
        let mut h = Hypothesis::new("h1", "Binary uses AES");
        for _ in 0..5 {
            h.add_evidence(make_evidence("e", 0.9));
        }
        assert_eq!(h.status, HypothesisStatus::Confirmed);
    }

    #[test]
    fn hypothesis_status_refuted() {
        let mut h = Hypothesis::new("h2", "Binary is 64-bit");
        for _ in 0..5 {
            h.add_evidence(make_evidence("e", -0.9));
        }
        assert_eq!(h.status, HypothesisStatus::Refuted);
    }

    #[test]
    fn hypothesis_support_weight() {
        let mut h = Hypothesis::new("h3", "claim");
        h.add_evidence(make_evidence("e1", 0.7));
        h.add_evidence(make_evidence("e2", -0.3));
        assert!((h.support_weight() - 0.7).abs() < 1e-9);
        assert!((h.contradiction_weight() - 0.3).abs() < 1e-9);
    }

    #[test]
    fn evidence_supportive_contradictory() {
        let ev_pos = make_evidence("p", 0.5);
        let ev_neg = make_evidence("n", -0.5);
        assert!(ev_pos.is_supportive());
        assert!(ev_neg.is_contradictory());
    }

    #[test]
    fn evidence_collector_entropy() {
        let mut ec = EvidenceCollector::new();
        // All same byte -> 0 entropy, no results.
        let low: Vec<u8> = vec![0u8; 256];
        let r = ec.collect_entropy_evidence(&low, 64);
        assert!(r.is_empty());
        // Random-looking bytes -> high entropy.
        let high: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let r2 = ec.collect_entropy_evidence(&high, 64);
        assert!(!r2.is_empty());
    }

    #[test]
    fn evidence_collector_crypto_constants() {
        let mut ec = EvidenceCollector::new();
        let bytes: Vec<u8> = 0x6745_2301_u32.to_le_bytes().to_vec();
        let r = ec.collect_crypto_constants(&bytes);
        assert!(!r.is_empty());
        assert!(r[0].description.contains("MD5/SHA-1"));
    }

    #[test]
    fn shannon_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn shannon_entropy_constant() {
        let data = vec![0u8; 256];
        assert!(shannon_entropy(&data).abs() < 1e-9);
    }

    #[test]
    fn contradiction_detector_tags() {
        let mut h1 = Hypothesis::new("h1", "32-bit binary");
        h1.tags.push("32-bit".into());
        h1.status = HypothesisStatus::Confirmed;
        h1.confidence = Confidence::new(0.9);

        let mut h2 = Hypothesis::new("h2", "64-bit binary");
        h2.tags.push("64-bit".into());
        h2.status = HypothesisStatus::Confirmed;
        h2.confidence = Confidence::new(0.9);

        let detector = ContradictionDetector::new();
        let contradictions = detector.detect(&[h1, h2]);
        assert!(!contradictions.is_empty());
    }

    #[test]
    fn contradiction_no_contradictions_pending() {
        let mut h1 = Hypothesis::new("h1", "32-bit binary");
        h1.tags.push("32-bit".into());
        // Pending status — should not trigger contradiction detection.

        let mut h2 = Hypothesis::new("h2", "64-bit binary");
        h2.tags.push("64-bit".into());

        let detector = ContradictionDetector::new();
        let contradictions = detector.detect(&[h1, h2]);
        assert!(contradictions.is_empty());
    }

    #[test]
    fn reasoning_chain_add_and_update() {
        let mut chain = ReasoningChain::new("test goal");
        let hyp = Hypothesis::new("h1", "packed binary");
        chain.add_hypothesis(hyp);

        let ev = make_evidence("e1", 0.8);
        chain.update_hypothesis("h1", vec![ev]).unwrap();

        let h = &chain.hypotheses["h1"];
        assert!(!h.evidence.is_empty());
    }

    #[test]
    fn reasoning_chain_confirmed_sorted() {
        let mut chain = ReasoningChain::new("goal");
        let mut h1 = Hypothesis::new("h1", "a");
        h1.confidence = Confidence::new(0.9);
        h1.status = HypothesisStatus::Confirmed;
        let mut h2 = Hypothesis::new("h2", "b");
        h2.confidence = Confidence::new(0.8);
        h2.status = HypothesisStatus::Confirmed;
        chain.hypotheses.insert("h1".into(), h1);
        chain.hypotheses.insert("h2".into(), h2);

        let confirmed = chain.confirmed_hypotheses();
        assert_eq!(confirmed.len(), 2);
        // h1 has higher confidence so should come first.
        assert!(confirmed[0].confidence.value() >= confirmed[1].confidence.value());
    }

    #[test]
    fn reasoning_chain_conclude() {
        let mut chain = ReasoningChain::new("goal");
        chain.conclude("This binary is malware");
        assert_eq!(chain.conclusion.as_deref(), Some("This binary is malware"));
    }

    #[test]
    fn task_decomposer_malware() {
        let d = TaskDecomposer::new();
        let tasks = d.decompose("analyse malware sample").unwrap();
        assert!(!tasks.is_empty());
        // Should be sorted by priority descending.
        for i in 1..tasks.len() {
            assert!(tasks[i - 1].priority >= tasks[i].priority);
        }
    }

    #[test]
    fn task_decomposer_crypto() {
        let d = TaskDecomposer::new();
        let tasks = d.decompose("identify crypto algorithm").unwrap();
        assert!(
            tasks
                .iter()
                .any(|t| t.description.to_lowercase().contains("crypto"))
        );
    }

    #[test]
    fn task_decomposer_fallback() {
        let d = TaskDecomposer::new();
        let tasks = d.decompose("unknown goal xyz").unwrap();
        assert!(!tasks.is_empty());
    }

    #[test]
    fn reasoning_cache_insert_get() {
        let mut cache = ReasoningCache::with_capacity(4);
        let chain = ReasoningChain::new("test");
        cache.insert("key1", chain);
        assert!(cache.get("key1").is_some());
        assert!(cache.get("key2").is_none());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn reasoning_cache_lru_eviction() {
        let mut cache = ReasoningCache::with_capacity(2);
        cache.insert("a", ReasoningChain::new("a"));
        cache.insert("b", ReasoningChain::new("b"));
        cache.insert("c", ReasoningChain::new("c")); // should evict "a"
        assert!(cache.get("a").is_none());
        assert!(cache.get("b").is_some());
        assert!(cache.get("c").is_some());
    }

    #[test]
    fn reasoning_cache_clear() {
        let mut cache = ReasoningCache::with_capacity(8);
        cache.insert("x", ReasoningChain::new("x"));
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn reasoning_cache_hits() {
        let mut cache = ReasoningCache::with_capacity(8);
        cache.insert("k", ReasoningChain::new("k"));
        cache.get("k");
        cache.get("k");
        assert_eq!(cache.total_hits(), 2);
    }

    #[test]
    fn export_json() {
        let chain = ReasoningChain::new("test export");
        let json = ReasoningExport::export(&chain, ExportFormat::Json).unwrap();
        assert!(json.contains("test export"));
    }

    #[test]
    fn export_markdown() {
        let mut chain = ReasoningChain::new("md test");
        chain.conclude("finished");
        let md = ReasoningExport::export(&chain, ExportFormat::Markdown).unwrap();
        assert!(md.contains("# Reasoning Chain"));
        assert!(md.contains("finished"));
    }

    #[test]
    fn export_plain_text() {
        let chain = ReasoningChain::new("plain test");
        let txt = ReasoningExport::export(&chain, ExportFormat::PlainText).unwrap();
        assert!(txt.contains("REASONING CHAIN"));
    }

    #[test]
    fn reasoning_engine_full_pipeline() {
        let mut engine = ReasoningEngine::new();
        let mut chain = engine.start_chain("analyse crypto");

        let hyp = Hypothesis::new("h-aes", "Binary uses AES-128")
            .tag("crypto")
            .tag("aes");
        engine.add_hypothesis(&mut chain, hyp);

        let ev = Evidence::new(
            "e1",
            "AES S-box found",
            EvidenceKind::CryptographicConstant,
            0.9,
        );
        engine
            .collect_and_attach(&mut chain, "h-aes", vec![ev])
            .unwrap();

        let chain = engine.finalize_chain(chain, Some("sample-hash"));
        assert!(chain.conclusion.is_some());
        assert!(engine.get_cached("sample-hash").is_some());
    }

    #[test]
    fn reasoning_engine_stats() {
        let mut engine = ReasoningEngine::new();
        let mut chain = engine.start_chain("test stats");
        let hyp = Hypothesis::new("h1", "claim");
        engine.add_hypothesis(&mut chain, hyp);
        let ev = make_evidence("e1", 0.5);
        engine
            .collect_and_attach(&mut chain, "h1", vec![ev])
            .unwrap();
        engine.finalize_chain(chain, None);
        let stats = engine.stats();
        assert_eq!(stats.hypotheses_created, 1);
        assert_eq!(stats.evidence_items, 1);
        assert_eq!(stats.chains_completed, 1);
    }

    #[test]
    fn reasoning_engine_decompose() {
        let engine = ReasoningEngine::new();
        let tasks = engine
            .decompose_goal("reverse engineer malware sample")
            .unwrap();
        assert!(!tasks.is_empty());
    }

    #[test]
    fn hypothesis_tags() {
        let h = Hypothesis::new("h", "claim").tag("crypto").tag("aes");
        assert!(h.tags.contains(&"crypto".to_string()));
        assert!(h.tags.contains(&"aes".to_string()));
    }

    #[test]
    fn hypothesis_parent() {
        let h = Hypothesis::new("child", "sub-claim").with_parent("parent");
        assert_eq!(h.parent_id.as_deref(), Some("parent"));
    }

    #[test]
    fn evidence_at_address() {
        let ev = make_evidence("e1", 0.5).at_address(0xDEAD_BEEF);
        assert_eq!(ev.address, Some(0xDEAD_BEEF));
    }

    #[test]
    fn evidence_with_payload() {
        let ev = make_evidence("e1", 0.5).with_payload("MOV EAX, 0x67452301");
        assert!(ev.payload.is_some());
    }

    #[test]
    fn sub_task_difficulty_clamp() {
        let t = SubTask::new("t", "desc", 99, 5);
        assert_eq!(t.difficulty, 10);
    }

    #[test]
    fn sub_task_priority_clamp() {
        let t = SubTask::new("t", "desc", 3, 99);
        assert_eq!(t.priority, 10);
    }

    #[test]
    fn reasoning_engine_default() {
        let engine = ReasoningEngine::default();
        assert!((engine.config().confirmation_threshold - 0.75).abs() < 1e-9);
    }

    #[test]
    fn contradiction_detector_no_false_positives_different_tags() {
        let mut h1 = Hypothesis::new("h1", "little-endian");
        h1.tags.push("little-endian".into());
        h1.status = HypothesisStatus::Confirmed;
        h1.confidence = Confidence::new(0.9);

        let mut h2 = Hypothesis::new("h2", "64-bit");
        h2.tags.push("64-bit".into());
        h2.status = HypothesisStatus::Confirmed;
        h2.confidence = Confidence::new(0.9);

        let detector = ContradictionDetector::new();
        // little-endian and 64-bit are NOT mutually exclusive.
        let cs = detector.detect(&[h1, h2]);
        assert!(cs.is_empty());
    }

    #[test]
    fn reasoning_chain_error_unknown_hyp() {
        let mut chain = ReasoningChain::new("goal");
        let result = chain.update_hypothesis("nonexistent", vec![]);
        assert!(matches!(result, Err(ReasoningError::HypothesisNotFound(_))));
    }

    #[test]
    fn evidence_collector_drain() {
        let mut ec = EvidenceCollector::new();
        ec.add(make_evidence("e1", 0.5));
        ec.add(make_evidence("e2", 0.6));
        let drained = ec.drain();
        assert_eq!(drained.len(), 2);
        assert!(ec.peek().is_empty());
    }

    #[test]
    fn export_json_contains_steps() {
        let mut chain = ReasoningChain::new("steps test");
        let hyp = Hypothesis::new("h", "claim");
        chain.add_hypothesis(hyp);
        let json = ReasoningExport::export(&chain, ExportFormat::Json).unwrap();
        assert!(json.contains("FormulateHypothesis"));
    }
}
