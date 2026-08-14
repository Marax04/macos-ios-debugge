//! `hypothesis_engine` — multi-hypothesis engine for combinatorial deobfuscation.
//!
//! [`HypothesisEngine`] maintains a pool of candidate deobfuscation hypotheses,
//! ranks them via a weighted scoring model, allows combination of the top-K
//! hypotheses, and drives selection through a priority queue.

use std::collections::BinaryHeap;
use ahash::AHashMap as HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the hypothesis engine.
#[derive(Debug, Error)]
pub enum HypothesisEngineError {
    /// A hypothesis with the given ID already exists in the pool.
    #[error("duplicate hypothesis id: {0}")]
    DuplicateId(u64),
    /// Attempted to select a hypothesis from an empty pool.
    #[error("hypothesis pool is empty")]
    EmptyPool,
    /// Invalid parameter supplied.
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm
// ─────────────────────────────────────────────────────────────────────────────

/// The deobfuscation algorithm a hypothesis proposes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    /// XOR decryption with a constant key.
    XorConstant { key: u8 },
    /// XOR decryption with a cyclic key.
    XorCyclic { key: Vec<u8> },
    /// Rolling XOR decryption.
    XorRolling { initial_key: u8 },
    /// RC4 decryption.
    Rc4 { key: Vec<u8> },
    /// NOP sled removal.
    NopElimination,
    /// Opaque predicate removal.
    OpaquePredicateRemoval,
    /// Control-flow flattening removal.
    CffRemoval,
    /// MBA expression simplification.
    MbaSimplification,
    /// String decryption via emulation.
    StringDecryption { method: String },
    /// Anti-debug patch (neutralise checks).
    AntiDebugPatch,
    /// UPX unpack.
    UpxUnpack,
    /// Custom algorithm identified by name.
    Custom { name: String },
}

impl Algorithm {
    /// Human-readable name for the algorithm.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::XorConstant { key } => format!("xor-constant(key=0x{key:02x})"),
            Self::XorCyclic { key } => format!("xor-cyclic(len={})", key.len()),
            Self::XorRolling { initial_key } => format!("xor-rolling(init=0x{initial_key:02x})"),
            Self::Rc4 { key } => format!("rc4(key-len={})", key.len()),
            Self::NopElimination => "nop-elimination".to_owned(),
            Self::OpaquePredicateRemoval => "opaque-predicate-removal".to_owned(),
            Self::CffRemoval => "cff-removal".to_owned(),
            Self::MbaSimplification => "mba-simplification".to_owned(),
            Self::StringDecryption { method } => format!("string-decryption({method})"),
            Self::AntiDebugPatch => "anti-debug-patch".to_owned(),
            Self::UpxUnpack => "upx-unpack".to_owned(),
            Self::Custom { name } => format!("custom({name})"),
        }
    }

    /// Estimated computational cost (0 = free, 100 = very expensive).
    #[must_use]
    pub const fn cost_estimate(&self) -> u32 {
        match self {
            Self::NopElimination | Self::AntiDebugPatch => 5,
            Self::XorConstant { .. } | Self::XorRolling { .. } => 10,
            Self::XorCyclic { key } => 10 + key.len() as u32,
            Self::OpaquePredicateRemoval => 20,
            Self::StringDecryption { .. } => 30,
            Self::Rc4 { .. } => 25,
            Self::CffRemoval | Self::MbaSimplification => 60,
            Self::UpxUnpack => 80,
            Self::Custom { .. } => 50,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisParameters
// ─────────────────────────────────────────────────────────────────────────────

/// Flexible key-value parameters for a hypothesis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HypothesisParameters {
    pub values: HashMap<String, serde_json::Value>,
}

impl HypothesisParameters {
    /// Create empty parameters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a string parameter.
    pub fn set_str(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values
            .insert(key.into(), serde_json::json!(value.into()));
    }

    /// Insert an integer parameter.
    pub fn set_int(&mut self, key: impl Into<String>, value: i64) {
        self.values.insert(key.into(), serde_json::json!(value));
    }

    /// Insert a float parameter.
    pub fn set_float(&mut self, key: impl Into<String>, value: f64) {
        self.values.insert(key.into(), serde_json::json!(value));
    }

    /// Retrieve a parameter as `f64`, or `None` if missing.
    #[must_use]
    pub fn get_float(&self, key: &str) -> Option<f64> {
        self.values.get(key)?.as_f64()
    }

    /// Retrieve a parameter as `i64`, or `None` if missing.
    #[must_use]
    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.values.get(key)?.as_i64()
    }

    /// Retrieve a parameter as `&str`, or `None` if missing.
    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.values.get(key)?.as_str()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hypothesis
// ─────────────────────────────────────────────────────────────────────────────

/// A single deobfuscation hypothesis.
///
/// Each hypothesis represents one candidate explanation for the obfuscation
/// observed in a binary region and the proposed algorithm to undo it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    /// Unique numeric ID.
    pub id: u64,
    /// Human-readable label.
    pub label: String,
    /// Algorithm proposed by this hypothesis.
    pub algorithm: Algorithm,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
    /// Algorithm-specific parameters.
    pub parameters: HypothesisParameters,
    /// Source features that generated this hypothesis (evidence tags).
    pub evidence_tags: Vec<String>,
    /// Generation index (0 = original, higher = derived/combined).
    pub generation: u32,
}

impl Hypothesis {
    /// Create a new hypothesis.
    #[must_use]
    pub fn new(id: u64, label: impl Into<String>, algorithm: Algorithm, confidence: f64) -> Self {
        Self {
            id,
            label: label.into(),
            algorithm,
            confidence: confidence.clamp(0.0, 1.0),
            parameters: HypothesisParameters::new(),
            evidence_tags: Vec::new(),
            generation: 0,
        }
    }

    /// Attach a parameter.
    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.parameters.values.insert(key.into(), value);
        self
    }

    /// Attach an evidence tag.
    #[must_use]
    pub fn with_evidence(mut self, tag: impl Into<String>) -> Self {
        self.evidence_tags.push(tag.into());
        self
    }

    /// Adjust the confidence value.
    #[must_use]
    pub const fn with_confidence(mut self, c: f64) -> Self {
        self.confidence = c.clamp(0.0, 1.0);
        self
    }

    /// Set the generation index.
    #[must_use]
    pub const fn with_generation(mut self, g: u32) -> Self {
        self.generation = g;
        self
    }

    /// Compute a combined priority score used for pool ranking.
    ///
    /// Priority = confidence × (1 − `normalised_cost`)
    #[must_use]
    pub fn priority_score(&self) -> f64 {
        let cost_norm = f64::from(self.algorithm.cost_estimate()) / 100.0;
        self.confidence * (1.0 - cost_norm.min(0.9))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PriorityItem — wrapper for BinaryHeap ordering
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct PriorityItem {
    priority: u64, // fixed-point score × 1_000_000
    id: u64,
}

impl PartialEq for PriorityItem {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}
impl Eq for PriorityItem {}
impl PartialOrd for PriorityItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for PriorityItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.id.cmp(&self.id))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisPool
// ─────────────────────────────────────────────────────────────────────────────

/// A ranked pool of [`Hypothesis`] objects.
///
/// Internally backed by a max-heap keyed on [`Hypothesis::priority_score`].
#[derive(Debug, Default)]
pub struct HypothesisPool {
    hypotheses: HashMap<u64, Hypothesis>,
    heap: BinaryHeap<PriorityItem>,
    next_id: u64,
}

impl HypothesisPool {
    /// Create an empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a hypothesis.
    ///
    /// # Errors
    /// Returns [`HypothesisEngineError::DuplicateId`] if the ID is already present.
    pub fn insert(&mut self, h: Hypothesis) -> Result<(), HypothesisEngineError> {
        if self.hypotheses.contains_key(&h.id) {
            return Err(HypothesisEngineError::DuplicateId(h.id));
        }
        let priority = (h.priority_score() * 1_000_000.0) as u64;
        self.heap.push(PriorityItem { priority, id: h.id });
        self.hypotheses.insert(h.id, h);
        Ok(())
    }

    /// Allocate a new unique ID.
    pub const fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Peek at the highest-priority hypothesis without removing it.
    #[must_use]
    pub fn peek_best(&self) -> Option<&Hypothesis> {
        let top = self.heap.peek()?;
        self.hypotheses.get(&top.id)
    }

    /// Remove and return the highest-priority hypothesis.
    pub fn pop_best(&mut self) -> Option<Hypothesis> {
        while let Some(item) = self.heap.pop() {
            if let Some(h) = self.hypotheses.remove(&item.id) {
                return Some(h);
            }
        }
        None
    }

    /// Return the top `n` hypotheses in descending priority order (non-destructive).
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<&Hypothesis> {
        let mut sorted: Vec<&Hypothesis> = self.hypotheses.values().collect();
        sorted.sort_by(|a, b| {
            b.priority_score()
                .partial_cmp(&a.priority_score())
                .unwrap()
                .then_with(|| a.id.cmp(&b.id))
        });
        sorted.truncate(n);
        sorted
    }

    /// Number of hypotheses in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hypotheses.len()
    }

    /// Returns `true` if the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hypotheses.is_empty()
    }

    /// Remove a hypothesis by ID. Returns `true` if it existed.
    pub fn remove(&mut self, id: u64) -> bool {
        self.hypotheses.remove(&id).is_some()
    }

    /// Boost the confidence of hypothesis `id` by `delta` (clamped to 1.0).
    ///
    /// # Errors
    /// Returns an error if the ID is unknown.
    pub fn boost_confidence(&mut self, id: u64, delta: f64) -> Result<(), HypothesisEngineError> {
        let h = self
            .hypotheses
            .get_mut(&id)
            .ok_or(HypothesisEngineError::EmptyPool)?;
        let old_conf = h.confidence;
        h.confidence = (h.confidence + delta).clamp(0.0, 1.0);
        // Re-insert into heap with updated priority if confidence changed.
        if (h.confidence - old_conf).abs() > 1e-9 {
            let priority = (h.priority_score() * 1_000_000.0) as u64;
            self.heap.push(PriorityItem { priority, id });
        }
        Ok(())
    }

    /// Return all hypotheses sorted by descending priority.
    #[must_use]
    pub fn all_sorted(&self) -> Vec<&Hypothesis> {
        let mut v: Vec<&Hypothesis> = self.hypotheses.values().collect();
        v.sort_by(|a, b| {
            b.priority_score()
                .partial_cmp(&a.priority_score())
                .unwrap()
                .then_with(|| a.id.cmp(&b.id))
        });
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Drives multi-hypothesis generation and ranking.
///
/// The engine generates hypotheses from a set of feature observations
/// (e.g. high entropy, XOR patterns) and stores them in a [`HypothesisPool`].
/// It also supports combining the top-K hypotheses into a composite hypothesis.
#[derive(Debug, Default)]
pub struct HypothesisEngine {
    pool: HypothesisPool,
    /// Generation counter used when creating new hypotheses.
    generation: u32,
    /// Minimum confidence required for a hypothesis to be retained.
    pub min_confidence: f64,
}

impl HypothesisEngine {
    /// Create a new engine with a minimum confidence threshold.
    #[must_use]
    pub fn new(min_confidence: f64) -> Self {
        Self {
            pool: HypothesisPool::new(),
            generation: 0,
            min_confidence: min_confidence.clamp(0.0, 1.0),
        }
    }

    /// Add a hypothesis to the pool if its confidence exceeds the threshold.
    ///
    /// Returns the ID assigned if the hypothesis was inserted, or `None` if
    /// it was rejected due to low confidence.
    ///
    /// # Errors
    /// Propagates [`HypothesisEngineError::DuplicateId`] if the ID collides.
    pub fn add_hypothesis(
        &mut self,
        mut h: Hypothesis,
    ) -> Result<Option<u64>, HypothesisEngineError> {
        if h.confidence < self.min_confidence {
            return Ok(None);
        }
        h.generation = self.generation;
        let id = h.id;
        self.pool.insert(h)?;
        Ok(Some(id))
    }

    /// Generate hypotheses from a feature observation vector.
    ///
    /// Heuristic mapping from features to algorithm proposals:
    /// - `entropy > 7.0` → XOR constant / RC4 hypotheses
    /// - `nop_ratio > 0.1` → NOP elimination
    /// - `indirect_jump_ratio > 0.3` → CFF removal
    /// - `xor_loop_count > 0` → string decryption
    /// - `upx_marker` → UPX unpack
    ///
    /// Returns the IDs of all generated hypotheses.
    pub fn generate_from_features(&mut self, features: &FeatureObservation) -> Vec<u64> {
        self.generation += 1;
        let r#gen = self.generation;
        let mut ids = Vec::new();

        // ── Entropy → XOR or RC4 ─────────────────────────────────────────
        if features.byte_entropy > 7.0 {
            for key in [0x42u8, 0xFF, 0x00, 0xAA] {
                if key == 0 {
                    continue;
                }
                let conf = ((features.byte_entropy - 7.0) * 2.5).min(0.85);
                let id = self.pool.next_id();
                let h = Hypothesis::new(
                    id,
                    format!("xor-const-0x{key:02x}"),
                    Algorithm::XorConstant { key },
                    conf,
                )
                .with_generation(r#gen)
                .with_evidence("high-entropy");
                if let Ok(Some(id)) = self.add_hypothesis(h) {
                    ids.push(id);
                }
            }
            if features.byte_entropy > 7.5 {
                let id = self.pool.next_id();
                let h = Hypothesis::new(
                    id,
                    "rc4-short-key",
                    Algorithm::Rc4 {
                        key: vec![0xDE, 0xAD],
                    },
                    0.65,
                )
                .with_generation(r#gen)
                .with_evidence("very-high-entropy");
                if let Ok(Some(hid)) = self.add_hypothesis(h) {
                    ids.push(hid);
                }
            }
        }

        // ── NOP ratio → NOP elimination ───────────────────────────────────
        if features.nop_ratio > 0.05 {
            let conf = (features.nop_ratio * 4.0).min(0.95);
            let id = self.pool.next_id();
            let h = Hypothesis::new(id, "nop-elimination", Algorithm::NopElimination, conf)
                .with_generation(r#gen)
                .with_evidence("high-nop-ratio");
            if let Ok(Some(hid)) = self.add_hypothesis(h) {
                ids.push(hid);
            }
        }

        // ── Indirect jump ratio → CFF ─────────────────────────────────────
        if features.indirect_jump_ratio > 0.2 {
            let conf = (features.indirect_jump_ratio * 2.0).min(0.9);
            let id = self.pool.next_id();
            let h = Hypothesis::new(id, "cff-removal", Algorithm::CffRemoval, conf)
                .with_generation(r#gen)
                .with_evidence("indirect-jumps");
            if let Ok(Some(hid)) = self.add_hypothesis(h) {
                ids.push(hid);
            }
        }

        // ── XOR-loop count → string decryption ───────────────────────────
        if features.xor_loop_count > 2 {
            let conf = (features.xor_loop_count as f64 * 0.08).min(0.80);
            let id = self.pool.next_id();
            let h = Hypothesis::new(
                id,
                "string-decrypt-xor",
                Algorithm::StringDecryption {
                    method: "xor".to_owned(),
                },
                conf,
            )
            .with_generation(r#gen)
            .with_evidence("xor-loop");
            if let Ok(Some(hid)) = self.add_hypothesis(h) {
                ids.push(hid);
            }
        }

        // ── UPX marker → unpack ───────────────────────────────────────────
        if features.has_upx_marker {
            let id = self.pool.next_id();
            let h = Hypothesis::new(id, "upx-unpack", Algorithm::UpxUnpack, 0.92)
                .with_generation(r#gen)
                .with_evidence("upx-marker");
            if let Ok(Some(hid)) = self.add_hypothesis(h) {
                ids.push(hid);
            }
        }

        // ── Opaque predicate count → predicate removal ────────────────────
        if features.opaque_predicate_count > 0 {
            let conf = (features.opaque_predicate_count as f64).mul_add(0.05, 0.5).min(0.90);
            let id = self.pool.next_id();
            let h = Hypothesis::new(
                id,
                "opaque-pred-removal",
                Algorithm::OpaquePredicateRemoval,
                conf,
            )
            .with_generation(r#gen)
            .with_evidence("opaque-predicates");
            if let Ok(Some(hid)) = self.add_hypothesis(h) {
                ids.push(hid);
            }
        }

        ids
    }

    /// Combine the top `k` hypotheses into a new composite hypothesis.
    ///
    /// The composite hypothesis uses the algorithm of the highest-priority
    /// component and averages confidence across components.  The generation
    /// counter is incremented.
    ///
    /// # Errors
    /// Returns [`HypothesisEngineError::EmptyPool`] if the pool has fewer than
    /// `k` hypotheses, or [`HypothesisEngineError::InvalidParameter`] if k=0.
    pub fn combine_top_k(&mut self, k: usize) -> Result<Hypothesis, HypothesisEngineError> {
        if k == 0 {
            return Err(HypothesisEngineError::InvalidParameter(
                "k must be >= 1".to_owned(),
            ));
        }
        if self.pool.len() < k {
            return Err(HypothesisEngineError::EmptyPool);
        }
        self.generation += 1;
        // Clone the top-N hypotheses up-front so the immutable borrow on
        // `self.pool` does not overlap with the mutable `next_id()` call.
        let top_owned: Vec<Hypothesis> = self.pool.top_n(k).into_iter().cloned().collect();
        let avg_confidence = top_owned.iter().map(|h| h.confidence).sum::<f64>() / k as f64;
        let best = &top_owned[0];
        let tags: Vec<String> = top_owned
            .iter()
            .flat_map(|h| h.evidence_tags.clone())
            .collect();
        let id = self.pool.next_id();

        let mut combined = Hypothesis::new(
            id,
            format!("combined-top-{k}"),
            best.algorithm.clone(),
            avg_confidence,
        )
        .with_generation(self.generation);
        combined.evidence_tags = tags;

        Ok(combined)
    }

    /// Return an immutable reference to the internal pool.
    #[must_use]
    pub const fn pool(&self) -> &HypothesisPool {
        &self.pool
    }

    /// Return a mutable reference to the internal pool.
    pub const fn pool_mut(&mut self) -> &mut HypothesisPool {
        &mut self.pool
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FeatureObservation — input to hypothesis generation
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated feature observations used to seed the hypothesis engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeatureObservation {
    /// Shannon entropy of the binary region (0.0–8.0).
    pub byte_entropy: f64,
    /// Fraction of bytes that are NOP (0x90).
    pub nop_ratio: f64,
    /// Fraction of branch instructions that are indirect.
    pub indirect_jump_ratio: f64,
    /// Number of detected XOR-loop sequences.
    pub xor_loop_count: usize,
    /// Whether a UPX marker byte sequence was found.
    pub has_upx_marker: bool,
    /// Number of detected opaque-predicate sequences.
    pub opaque_predicate_count: usize,
    /// Optional CFG edge count (used for CFF estimation).
    pub cfg_edge_count: Option<usize>,
    /// Optional basic-block count.
    pub basic_block_count: Option<usize>,
}

impl FeatureObservation {
    /// Create an observation from raw binary data using fast heuristics.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self::default();
        }

        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let len = data.len() as f64;
        let byte_entropy: f64 = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / len;
                -p * p.log2()
            })
            .sum();

        let nop_count = freq[0x90] as usize;
        let nop_ratio = nop_count as f64 / len;

        // Indirect jumps: FF E0, FF E1, FF E2, FF E3
        let mut indirect = 0usize;
        let mut total_branches = 0usize;
        let mut xor_loops = 0usize;
        for i in 0..data.len().saturating_sub(1) {
            if data[i] == 0xFF && matches!(data[i + 1], 0xE0..=0xE3 | 0x24 | 0x25) {
                indirect += 1;
                total_branches += 1;
            } else if matches!(data[i], 0xEB | 0xE9 | 0x74..=0x7F) {
                total_branches += 1;
            }
            if (data[i] == 0x30 || data[i] == 0x32) && i + 8 < data.len() {
                let nearby_loop = data[i..data.len().min(i + 16)]
                    .iter()
                    .any(|&b| matches!(b, 0xE0..=0xE2));
                if nearby_loop {
                    xor_loops += 1;
                }
            }
        }
        let indirect_jump_ratio = if total_branches == 0 {
            0.0
        } else {
            indirect as f64 / total_branches as f64
        };

        let has_upx_marker = data
            .windows(4)
            .any(|w| w == b"UPX0" || w == b"UPX1" || w == b"UPX!");

        // Opaque predicates: xor eax,eax; test eax,eax; jz (31 C0 85 C0 74)
        let opaque_predicate_count = data
            .windows(5)
            .filter(|w| {
                w[0] == 0x31
                    && w[1] == 0xC0
                    && w[2] == 0x85
                    && w[3] == 0xC0
                    && (w[4] == 0x74 || w[4] == 0x75)
            })
            .count();

        Self {
            byte_entropy,
            nop_ratio,
            indirect_jump_ratio,
            xor_loop_count: xor_loops,
            has_upx_marker,
            opaque_predicate_count,
            cfg_edge_count: None,
            basic_block_count: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> HypothesisEngine {
        HypothesisEngine::new(0.1)
    }

    #[test]
    fn test_insert_and_pop() {
        let mut engine = make_engine();
        let h = Hypothesis::new(1, "test", Algorithm::NopElimination, 0.8);
        engine.add_hypothesis(h).unwrap();
        assert_eq!(engine.pool().len(), 1);
        let best = engine.pool_mut().pop_best().unwrap();
        assert_eq!(best.id, 1);
        assert!(engine.pool().is_empty());
    }

    #[test]
    fn test_duplicate_id_rejected() {
        let mut pool = HypothesisPool::new();
        pool.insert(Hypothesis::new(1, "a", Algorithm::NopElimination, 0.5))
            .unwrap();
        let result = pool.insert(Hypothesis::new(1, "b", Algorithm::NopElimination, 0.5));
        assert!(matches!(result, Err(HypothesisEngineError::DuplicateId(1))));
    }

    #[test]
    fn test_priority_ordering() {
        let mut pool = HypothesisPool::new();
        pool.insert(Hypothesis::new(1, "low", Algorithm::NopElimination, 0.3))
            .unwrap();
        pool.insert(Hypothesis::new(2, "high", Algorithm::NopElimination, 0.9))
            .unwrap();
        let best = pool.pop_best().unwrap();
        assert_eq!(best.id, 2);
    }

    #[test]
    fn test_generate_from_high_entropy() {
        let mut engine = make_engine();
        let obs = FeatureObservation {
            byte_entropy: 7.5,
            nop_ratio: 0.0,
            indirect_jump_ratio: 0.0,
            xor_loop_count: 0,
            has_upx_marker: false,
            opaque_predicate_count: 0,
            cfg_edge_count: None,
            basic_block_count: None,
        };
        let ids = engine.generate_from_features(&obs);
        assert!(
            !ids.is_empty(),
            "high entropy should generate XOR/RC4 hypotheses"
        );
    }

    #[test]
    fn test_generate_from_upx_marker() {
        let mut engine = make_engine();
        let obs = FeatureObservation {
            has_upx_marker: true,
            ..Default::default()
        };
        let ids = engine.generate_from_features(&obs);
        assert!(!ids.is_empty());
        let pool_labels: Vec<_> = engine
            .pool()
            .all_sorted()
            .iter()
            .map(|h| h.label.clone())
            .collect();
        assert!(pool_labels.iter().any(|l| l.contains("upx")));
    }

    #[test]
    fn test_combine_top_k() {
        let mut engine = make_engine();
        for i in 0..5u64 {
            let h = Hypothesis::new(
                i,
                format!("h{i}"),
                Algorithm::NopElimination,
                (i as f64).mul_add(0.08, 0.5),
            );
            engine.pool_mut().insert(h).unwrap();
        }
        let combined = engine.combine_top_k(3).unwrap();
        assert!(combined.confidence > 0.0);
        assert!(combined.label.contains("combined"));
    }

    #[test]
    fn test_feature_observation_from_nop_sled() {
        let data = vec![0x90u8; 512];
        let obs = FeatureObservation::from_bytes(&data);
        assert!(obs.nop_ratio > 0.9);
    }

    #[test]
    fn test_low_confidence_rejected() {
        let mut engine = HypothesisEngine::new(0.5);
        let h = Hypothesis::new(99, "weak", Algorithm::NopElimination, 0.2);
        let result = engine.add_hypothesis(h).unwrap();
        assert_eq!(result, None);
        assert!(engine.pool().is_empty());
    }

    #[test]
    fn test_boost_confidence() {
        let mut pool = HypothesisPool::new();
        pool.insert(Hypothesis::new(1, "a", Algorithm::NopElimination, 0.5))
            .unwrap();
        pool.boost_confidence(1, 0.3).unwrap();
        assert!((pool.hypotheses[&1].confidence - 0.8).abs() < 1e-9);
    }
}
