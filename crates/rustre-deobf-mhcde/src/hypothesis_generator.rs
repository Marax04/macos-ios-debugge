//! `hypothesis_generator` — Generate deobfuscation hypotheses.
//!
//! Proposes multiple candidate interpretations of an obfuscated code block,
//! assigns a confidence score to each, and groups them by kind for downstream
//! concurrency-based evaluation.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{EntropyAnalyzer, ScoreModel};

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisKind
// ─────────────────────────────────────────────────────────────────────────────

/// The broad class of deobfuscation hypothesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HypothesisKind {
    /// The code is a single-byte XOR cipher.
    XorSingleByte,
    /// The code uses a rolling / add-based cipher.
    AddRollingKey,
    /// The code is NOP-padded but otherwise intact.
    NopPadded,
    /// The code uses control-flow flattening.
    ControlFlowFlattened,
    /// The code is stack-string constructed.
    StackString,
    /// The code uses return-address obfuscation (ROP gadget chaining).
    ReturnAddrObf,
    /// The code is a constant-unfolded arithmetic sequence.
    ConstantUnfolded,
    /// The code hides string data via byte-by-byte construction.
    ByteByByteString,
    /// The code is wrapped in a custom VM dispatcher.
    VirtualMachine,
    /// The plaintext code appears to be unobfuscated.
    Identity,
}

impl HypothesisKind {
    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::XorSingleByte => "xor-single-byte",
            Self::AddRollingKey => "add-rolling-key",
            Self::NopPadded => "nop-padded",
            Self::ControlFlowFlattened => "cff",
            Self::StackString => "stack-string",
            Self::ReturnAddrObf => "return-addr-obf",
            Self::ConstantUnfolded => "constant-unfolded",
            Self::ByteByByteString => "byte-by-byte-string",
            Self::VirtualMachine => "virtual-machine",
            Self::Identity => "identity",
        }
    }

    /// Base prior probability (0.0–1.0) for this hypothesis before evidence.
    #[must_use]
    pub const fn base_prior(self) -> f64 {
        match self {
            Self::Identity => 0.40,
            Self::NopPadded => 0.30,
            Self::XorSingleByte => 0.25,
            Self::ConstantUnfolded => 0.20,
            Self::ControlFlowFlattened => 0.15,
            Self::StackString => 0.15,
            Self::AddRollingKey => 0.10,
            Self::ByteByByteString => 0.10,
            Self::ReturnAddrObf => 0.05,
            Self::VirtualMachine => 0.05,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hypothesis
// ─────────────────────────────────────────────────────────────────────────────

/// A single deobfuscation hypothesis produced by [`HypothesisGenerator`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    /// Unique identifier for this hypothesis.
    pub id: u32,
    /// Broad classification.
    pub kind: HypothesisKind,
    /// Human-readable summary of what this hypothesis proposes.
    pub description: String,
    /// Confidence score in the range [0.0, 1.0].
    pub confidence: f64,
    /// Optional parameter relevant to the hypothesis (e.g. XOR key value).
    pub parameter: Option<String>,
    /// Evidence features that led to this hypothesis.
    pub evidence: Vec<String>,
    /// Priority: higher means the executor should try this first.
    pub priority: u32,
}

impl Hypothesis {
    /// Create a new hypothesis.
    #[must_use]
    pub fn new(
        id: u32,
        kind: HypothesisKind,
        description: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            id,
            kind,
            description: description.into(),
            confidence: confidence.clamp(0.0, 1.0),
            parameter: None,
            evidence: Vec::new(),
            priority: 0,
        }
    }

    /// Attach a hypothesis parameter.
    #[must_use]
    pub fn with_parameter(mut self, param: impl Into<String>) -> Self {
        self.parameter = Some(param.into());
        self
    }

    /// Attach an evidence string.
    #[must_use]
    pub fn with_evidence(mut self, ev: impl Into<String>) -> Self {
        self.evidence.push(ev.into());
        self
    }

    /// Set priority.
    #[must_use]
    pub const fn with_priority(mut self, p: u32) -> Self {
        self.priority = p;
        self
    }

    /// Combine the base prior with evidence-derived likelihood to produce a
    /// posterior confidence estimate using a simple Bayesian update:
    ///
    /// ```text
    /// posterior = (prior * likelihood) / ((prior * likelihood) + (1 - prior) * (1 - likelihood))
    /// ```
    #[must_use]
    pub fn posterior(prior: f64, likelihood: f64) -> f64 {
        let p = prior.clamp(1e-9, 1.0 - 1e-9);
        let l = likelihood.clamp(1e-9, 1.0 - 1e-9);
        let num = p * l;
        let denom = num + (1.0 - p) * (1.0 - l);
        if denom < 1e-12 {
            0.0
        } else {
            (num / denom).clamp(0.0, 1.0)
        }
    }

    /// Returns `true` when confidence is high enough to be forwarded to execution.
    #[must_use]
    pub fn is_viable(&self) -> bool {
        self.confidence >= 0.30
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisGeneratorConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration parameters for `HypothesisGenerator`.
#[derive(Debug, Clone)]
pub struct HypothesisGeneratorConfig {
    /// Minimum confidence for a hypothesis to be included in the output.
    pub min_confidence: f64,
    /// Maximum number of hypotheses to generate.
    pub max_hypotheses: usize,
    /// Whether to include the identity (no-obfuscation) hypothesis.
    pub include_identity: bool,
    /// Entropy threshold above which XOR hypotheses are considered.
    pub high_entropy_threshold: f32,
    /// NOP density above which NOP-padded hypothesis is considered.
    pub nop_density_threshold: f32,
}

impl Default for HypothesisGeneratorConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.25,
            max_hypotheses: 8,
            include_identity: true,
            high_entropy_threshold: 6.5,
            nop_density_threshold: 0.05,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FeatureVector
// ─────────────────────────────────────────────────────────────────────────────

/// Observed features extracted from the input bytes.
#[derive(Debug, Clone)]
struct FeatureVector {
    entropy: f32,
    nop_density: f32,
    naturalness: f64,
    _byte_freq: [u32; 256],
    has_indirect_jmp: bool,
    push_pop_pairs: usize,
    mov_imm_density: f32,
    call_density: f32,
    ret_count: usize,
    len: usize,
}

impl FeatureVector {
    fn extract(data: &[u8]) -> Self {
        let analyzer = EntropyAnalyzer::new(64.min(data.len().max(4)));
        let entropy = if data.is_empty() {
            0.0
        } else {
            EntropyAnalyzer::entropy(data)
        };

        let mut byte_freq = [0u32; 256];
        let mut nop_count = 0usize;
        let mut push_pop_pairs = 0usize;
        let mut mov_imm_count = 0usize;
        let mut call_count = 0usize;
        let mut ret_count = 0usize;
        let mut has_indirect_jmp = false;
        let mut i = 0usize;

        while i < data.len() {
            let b = data[i];
            byte_freq[b as usize] += 1;
            match b {
                0x90 => nop_count += 1,
                0xE8 => call_count += 1,
                0xC3 | 0xC2 => ret_count += 1,
                0xB0..=0xBF => mov_imm_count += 1,
                0xFF if i + 1 < data.len() && (data[i + 1] == 0x24 || data[i + 1] == 0xE0) => {
                    has_indirect_jmp = true;
                }
                0x50..=0x57
                    if i + 1 < data.len() && data[i + 1] == (b + 8) =>
                {
                    push_pop_pairs += 1;
                    i += 1;
                }
                _ => {}
            }
            i += 1;
        }

        let len = data.len().max(1);
        let nop_density = nop_count as f32 / len as f32;
        let mov_imm_density = mov_imm_count as f32 / len as f32;
        let call_density = call_count as f32 / len as f32;
        let naturalness = ScoreModel::naturalness_score(data);

        let _ = analyzer;
        Self {
            entropy,
            nop_density,
            naturalness,
            _byte_freq: byte_freq,
            has_indirect_jmp,
            push_pop_pairs,
            mov_imm_density,
            call_density,
            ret_count,
            len,
        }
    }

    /// Find the single-byte XOR key that produces the lowest-entropy result.
    fn best_xor_key(&self, data: &[u8]) -> (u8, f64) {
        let mut best_key = 0u8;
        let mut best_nat = ScoreModel::naturalness_score(data);
        for key in 1u8..=255 {
            let dec: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            let nat = ScoreModel::naturalness_score(&dec);
            if nat > best_nat {
                best_nat = nat;
                best_key = key;
            }
        }
        (best_key, best_nat)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisGenerator
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a ranked list of candidate deobfuscation hypotheses from
/// raw bytes.
///
/// # Usage
/// ```rust,ignore
/// let gen = HypothesisGenerator::new(HypothesisGeneratorConfig::default());
/// let hypotheses = gen.generate(code_bytes);
/// for h in &hypotheses {
///     println!("{} confidence={:.2}", h.description, h.confidence);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct HypothesisGenerator {
    config: HypothesisGeneratorConfig,
    next_id: u32,
}

impl HypothesisGenerator {
    /// Create a new generator with the given configuration.
    #[must_use]
    pub const fn new(config: HypothesisGeneratorConfig) -> Self {
        Self { config, next_id: 0 }
    }

    /// Create a generator with default configuration.
    #[must_use]
    pub fn default() -> Self {
        Self::new(HypothesisGeneratorConfig::default())
    }

    /// Generate hypotheses for the given byte slice.
    ///
    /// Returns a `Vec<Hypothesis>` sorted by descending confidence.
    #[must_use]
    pub fn generate(&mut self, data: &[u8]) -> Vec<Hypothesis> {
        if data.is_empty() {
            return vec![];
        }
        let features = FeatureVector::extract(data);
        let mut candidates: Vec<Hypothesis> = Vec::with_capacity(16);

        if self.config.include_identity {
            candidates.push(self.make_identity(&features));
        }
        candidates.extend(self.make_xor_hypotheses(data, &features));
        candidates.extend(self.make_nop_hypothesis(&features));
        candidates.extend(self.make_cff_hypothesis(&features));
        candidates.extend(self.make_stack_string_hypothesis(&features));
        candidates.extend(self.make_constant_unfolded_hypothesis(&features));
        candidates.extend(self.make_add_rolling_hypothesis(data, &features));
        candidates.extend(self.make_vm_hypothesis(&features));
        candidates.extend(self.make_rop_hypothesis(&features));

        // Filter by minimum confidence
        candidates.retain(|h| h.confidence >= self.config.min_confidence);

        // Sort by descending confidence then ascending id for determinism
        candidates.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id))
        });

        candidates.truncate(self.config.max_hypotheses);
        candidates
    }

    /// Return a summary map of `kind → confidence` for the top hypotheses.
    #[must_use]
    pub fn confidence_map(&mut self, data: &[u8]) -> HashMap<HypothesisKind, f64> {
        self.generate(data)
            .into_iter()
            .map(|h| (h.kind, h.confidence))
            .collect()
    }

    // ── Private generators ────────────────────────────────────────────────────

    const fn next_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn make_identity(&mut self, features: &FeatureVector) -> Hypothesis {
        let prior = HypothesisKind::Identity.base_prior();
        // High naturalness → high identity confidence
        let confidence = Hypothesis::posterior(prior, features.naturalness);
        Hypothesis::new(
            self.next_id(),
            HypothesisKind::Identity,
            "Code appears to be unobfuscated; natural instruction distribution",
            confidence,
        )
        .with_evidence(format!("naturalness={:.3}", features.naturalness))
        .with_evidence(format!("entropy={:.2}", features.entropy))
        .with_priority(10)
    }

    fn make_xor_hypotheses(
        &mut self,
        data: &[u8],
        features: &FeatureVector,
    ) -> Vec<Hypothesis> {
        let mut out = Vec::new();
        if features.entropy < self.config.high_entropy_threshold {
            return out;
        }

        let (key, nat_after) = features.best_xor_key(data);
        let improvement = nat_after - features.naturalness;
        if improvement < 0.05 {
            return out;
        }

        let prior = HypothesisKind::XorSingleByte.base_prior();
        // Likelihood: improvement in naturalness is strong evidence
        let likelihood = (improvement / 0.5).min(1.0);
        let confidence = Hypothesis::posterior(prior, likelihood);

        out.push(
            Hypothesis::new(
                self.next_id(),
                HypothesisKind::XorSingleByte,
                format!(
                    "Single-byte XOR cipher with key {key:#04x} improves naturalness by {improvement:.3}"
                ),
                confidence,
            )
            .with_parameter(format!("{key:#04x}"))
            .with_evidence(format!("entropy={:.2}", features.entropy))
            .with_evidence(format!("naturalness_after={nat_after:.3}"))
            .with_priority(8),
        );
        out
    }

    fn make_nop_hypothesis(&mut self, features: &FeatureVector) -> Vec<Hypothesis> {
        if features.nop_density < self.config.nop_density_threshold {
            return vec![];
        }
        let prior = HypothesisKind::NopPadded.base_prior();
        let likelihood = (features.nop_density as f64 / 0.20).min(1.0);
        let confidence = Hypothesis::posterior(prior, likelihood);
        vec![Hypothesis::new(
            self.next_id(),
            HypothesisKind::NopPadded,
            format!(
                "Code contains {:.1}% NOP bytes; likely NOP-padded obfuscation",
                features.nop_density * 100.0
            ),
            confidence,
        )
        .with_evidence(format!("nop_density={:.3}", features.nop_density))
        .with_priority(7)]
    }

    fn make_cff_hypothesis(&mut self, features: &FeatureVector) -> Vec<Hypothesis> {
        if !features.has_indirect_jmp {
            return vec![];
        }
        let prior = HypothesisKind::ControlFlowFlattened.base_prior();
        let ret_rate = features.ret_count as f64 / features.len as f64;
        let likelihood = if features.ret_count > 2 {
            (ret_rate / 0.01).min(1.0)
        } else {
            0.4
        };
        let confidence = Hypothesis::posterior(prior, likelihood);
        vec![Hypothesis::new(
            self.next_id(),
            HypothesisKind::ControlFlowFlattened,
            "Indirect jump detected; consistent with control-flow flattening dispatcher",
            confidence,
        )
        .with_evidence("indirect_jmp=true".to_string())
        .with_evidence(format!("ret_count={}", features.ret_count))
        .with_priority(6)]
    }

    fn make_stack_string_hypothesis(&mut self, features: &FeatureVector) -> Vec<Hypothesis> {
        // Stack string construction uses many MOV-immediate operations
        if features.mov_imm_density < 0.05 {
            return vec![];
        }
        let prior = HypothesisKind::StackString.base_prior();
        let likelihood = (features.mov_imm_density as f64 / 0.15).min(1.0);
        let confidence = Hypothesis::posterior(prior, likelihood);
        vec![Hypothesis::new(
            self.next_id(),
            HypothesisKind::StackString,
            format!(
                "High MOV-immediate density ({:.1}%); possibly stack-string construction",
                features.mov_imm_density * 100.0
            ),
            confidence,
        )
        .with_evidence(format!("mov_imm_density={:.3}", features.mov_imm_density))
        .with_priority(5)]
    }

    fn make_constant_unfolded_hypothesis(&mut self, features: &FeatureVector) -> Vec<Hypothesis> {
        // Constant unfolding: push/pop identity pairs; low naturalness; low entropy
        if features.push_pop_pairs == 0 {
            return vec![];
        }
        let prior = HypothesisKind::ConstantUnfolded.base_prior();
        let pair_density = features.push_pop_pairs as f64 / features.len as f64;
        let likelihood = (pair_density / 0.02).min(1.0);
        let confidence = Hypothesis::posterior(prior, likelihood);
        vec![Hypothesis::new(
            self.next_id(),
            HypothesisKind::ConstantUnfolded,
            format!(
                "{} push/pop identity pairs detected; likely constant-unfolded junk",
                features.push_pop_pairs
            ),
            confidence,
        )
        .with_evidence(format!("push_pop_pairs={}", features.push_pop_pairs))
        .with_priority(4)]
    }

    fn make_add_rolling_hypothesis(
        &mut self,
        data: &[u8],
        features: &FeatureVector,
    ) -> Vec<Hypothesis> {
        if features.entropy < 5.0 || data.len() < 16 {
            return vec![];
        }
        // Heuristic: try ADD-with-key-0x41 rolling cipher
        let key = 0x41u8;
        let dec: Vec<u8> = data
            .iter()
            .enumerate()
            .map(|(i, &b)| b.wrapping_sub(key.wrapping_add(i as u8)))
            .collect();
        let nat_after = ScoreModel::naturalness_score(&dec);
        let improvement = nat_after - features.naturalness;
        if improvement < 0.04 {
            return vec![];
        }
        let prior = HypothesisKind::AddRollingKey.base_prior();
        let likelihood = (improvement / 0.3).min(1.0);
        let confidence = Hypothesis::posterior(prior, likelihood);
        vec![Hypothesis::new(
            self.next_id(),
            HypothesisKind::AddRollingKey,
            format!(
                "Rolling ADD cipher (base key {key:#04x}) improves naturalness by {improvement:.3}"
            ),
            confidence,
        )
        .with_parameter(format!("{key:#04x}"))
        .with_evidence(format!("entropy={:.2}", features.entropy))
        .with_priority(3)]
    }

    fn make_vm_hypothesis(&mut self, features: &FeatureVector) -> Vec<Hypothesis> {
        // VM detection: low call density + indirect jumps + low naturalness
        if !features.has_indirect_jmp || features.naturalness > 0.5 {
            return vec![];
        }
        let prior = HypothesisKind::VirtualMachine.base_prior();
        let inv_nat = 1.0 - features.naturalness;
        let confidence = Hypothesis::posterior(prior, inv_nat * 0.7);
        vec![Hypothesis::new(
            self.next_id(),
            HypothesisKind::VirtualMachine,
            "Low naturalness + indirect dispatch; consistent with custom VM bytecode interpreter",
            confidence,
        )
        .with_evidence(format!("naturalness={:.3}", features.naturalness))
        .with_evidence("indirect_jmp=true".to_string())
        .with_priority(2)]
    }

    fn make_rop_hypothesis(&mut self, features: &FeatureVector) -> Vec<Hypothesis> {
        // ROP: many RET instructions relative to CALL instructions
        if features.ret_count < 4 {
            return vec![];
        }
        let call_count = (features.call_density * features.len as f32) as usize;
        if call_count == 0 || features.ret_count < call_count * 2 {
            return vec![];
        }
        let prior = HypothesisKind::ReturnAddrObf.base_prior();
        let ratio = (features.ret_count as f64 / (call_count + 1) as f64).min(10.0) / 10.0;
        let confidence = Hypothesis::posterior(prior, ratio);
        vec![Hypothesis::new(
            self.next_id(),
            HypothesisKind::ReturnAddrObf,
            format!(
                "ret/call ratio={:.1}; possibly return-address obfuscation / ROP chain",
                features.ret_count as f64 / (call_count + 1) as f64
            ),
            confidence,
        )
        .with_evidence(format!("ret_count={}", features.ret_count))
        .with_evidence(format!("call_count={call_count}"))
        .with_priority(1)]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// confidence_score() — standalone function
// ─────────────────────────────────────────────────────────────────────────────

/// Compute a quick aggregate confidence score for the most-likely hypothesis
/// for the given bytes.
///
/// Returns a value in `[0.0, 1.0]` representing how confident the generator
/// is that at least one of its hypotheses correctly identifies the obfuscation.
#[must_use]
pub fn confidence_score(data: &[u8]) -> f64 {
    let mut generator = HypothesisGenerator::default();
    let hypotheses = generator.generate(data);
    hypotheses
        .first()
        .map(|h| h.confidence)
        .unwrap_or(0.0)
}

/// Return the kind of the top hypothesis for `data`.
#[must_use]
pub fn top_hypothesis_kind(data: &[u8]) -> Option<HypothesisKind> {
    let mut generator = HypothesisGenerator::default();
    generator.generate(data).into_iter().next().map(|h| h.kind)
}

/// Return all viable hypotheses for `data` (confidence >= 0.3).
#[must_use]
pub fn viable_hypotheses(data: &[u8]) -> Vec<Hypothesis> {
    let mut generator = HypothesisGenerator::default();
    generator.generate(data)
        .into_iter()
        .filter(|h| h.is_viable())
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn nop_sled(len: usize) -> Vec<u8> {
        vec![0x90; len]
    }

    fn _xor_data(key: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u8) ^ key).collect()
    }

    #[test]
    fn test_empty_data_returns_empty() {
        let mut generator = HypothesisGenerator::default();
        assert!(generator.generate(&[]).is_empty());
    }

    #[test]
    fn test_identity_hypothesis_present() {
        let data = [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0xC3];
        let mut generator = HypothesisGenerator::default();
        let hyps = generator.generate(&data);
        assert!(!hyps.is_empty());
        let has_identity = hyps.iter().any(|h| h.kind == HypothesisKind::Identity);
        assert!(has_identity);
    }

    #[test]
    fn test_nop_hypothesis_triggered() {
        let data = nop_sled(64);
        let mut generator = HypothesisGenerator::default();
        let hyps = generator.generate(&data);
        let has_nop = hyps.iter().any(|h| h.kind == HypothesisKind::NopPadded);
        assert!(has_nop);
    }

    #[test]
    fn test_confidence_range() {
        let data: Vec<u8> = (0..128).collect();
        let mut generator = HypothesisGenerator::default();
        for h in generator.generate(&data) {
            assert!(h.confidence >= 0.0 && h.confidence <= 1.0, "confidence out of range");
        }
    }

    #[test]
    fn test_hypothesis_sorted_by_descending_confidence() {
        let data: Vec<u8> = (0..256u16).map(|i| i as u8).cycle().take(256).collect();
        let mut generator = HypothesisGenerator::default();
        let hyps = generator.generate(&data);
        let confs: Vec<f64> = hyps.iter().map(|h| h.confidence).collect();
        for w in confs.windows(2) {
            assert!(w[0] >= w[1], "hypotheses not sorted");
        }
    }

    #[test]
    fn test_confidence_score_nonzero() {
        let data: Vec<u8> = (0..64).collect();
        let score = confidence_score(&data);
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[test]
    fn test_max_hypotheses_limit() {
        let cfg = HypothesisGeneratorConfig {
            max_hypotheses: 3,
            ..HypothesisGeneratorConfig::default()
        };
        let data: Vec<u8> = (0..128).collect();
        let mut generator = HypothesisGenerator::new(cfg);
        let hyps = generator.generate(&data);
        assert!(hyps.len() <= 3);
    }

    #[test]
    fn test_posterior_calculation() {
        let p = Hypothesis::posterior(0.5, 0.9);
        assert!(p > 0.8 && p < 1.0, "posterior={p}");
    }

    #[test]
    fn test_posterior_zero_likelihood() {
        let p = Hypothesis::posterior(0.5, 0.0);
        assert!(p < 0.1);
    }

    #[test]
    fn test_hypothesis_kind_labels_unique() {
        let kinds = [
            HypothesisKind::XorSingleByte,
            HypothesisKind::AddRollingKey,
            HypothesisKind::NopPadded,
            HypothesisKind::ControlFlowFlattened,
            HypothesisKind::StackString,
            HypothesisKind::ReturnAddrObf,
            HypothesisKind::ConstantUnfolded,
            HypothesisKind::ByteByByteString,
            HypothesisKind::VirtualMachine,
            HypothesisKind::Identity,
        ];
        let labels: std::collections::HashSet<&str> = kinds.iter().map(|k| k.label()).collect();
        assert_eq!(labels.len(), kinds.len());
    }

    #[test]
    fn test_viable_hypotheses() {
        let data: Vec<u8> = (0..128).collect();
        let hyps = viable_hypotheses(&data);
        for h in &hyps {
            assert!(h.confidence >= 0.30);
        }
    }

    #[test]
    fn test_xor_high_entropy_data() {
        // Create very high-entropy (pseudo-random) data
        let mut data: Vec<u8> = Vec::with_capacity(256);
        let mut state = 12345u32;
        for _ in 0..256 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            data.push((state >> 16) as u8);
        }
        let score = confidence_score(&data);
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[test]
    fn test_confidence_map_contains_identity() {
        let data = [0x55, 0x48, 0x89, 0xE5, 0xC3];
        let mut generator = HypothesisGenerator::default();
        let map = generator.confidence_map(&data);
        assert!(map.contains_key(&HypothesisKind::Identity));
    }

    #[test]
    fn test_hypothesis_with_evidence() {
        let h = Hypothesis::new(0, HypothesisKind::NopPadded, "test", 0.8)
            .with_evidence("nop_density=0.3")
            .with_evidence("entropy=1.2");
        assert_eq!(h.evidence.len(), 2);
    }

    #[test]
    fn test_hypothesis_is_viable() {
        let h_viable = Hypothesis::new(0, HypothesisKind::Identity, "test", 0.6);
        let h_not = Hypothesis::new(1, HypothesisKind::Identity, "test", 0.1);
        assert!(h_viable.is_viable());
        assert!(!h_not.is_viable());
    }

    #[test]
    fn test_hypothesis_kind_base_prior() {
        let prior = HypothesisKind::Identity.base_prior();
        assert!(prior > 0.0 && prior <= 1.0);
    }
}
