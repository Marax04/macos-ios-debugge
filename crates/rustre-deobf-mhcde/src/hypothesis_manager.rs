//! `hypothesis_manager` — Concurrent deobfuscation hypothesis management.
//!
//! Each hypothesis is a separate deobfuscation "path" (e.g. XOR key=0x42 vs
//! XOR key=0x13 vs ROT13). All paths run in parallel, each is scored on output
//! quality (readability, entropy, string count), and the top-K hypotheses are
//! maintained throughout the process.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::sync::{Arc, Mutex};

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisId
// ─────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a hypothesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HypothesisId(pub u64);

impl HypothesisId {
    /// Generate the next ID (monotonically increasing).
    const fn next(counter: &mut u64) -> Self {
        *counter += 1;
        Self(*counter)
    }
}

impl std::fmt::Display for HypothesisId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "H{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfPass description
// ─────────────────────────────────────────────────────────────────────────────

/// A concrete deobfuscation pass applied in a hypothesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeobfPassSpec {
    /// Human-readable name (e.g. "XOR-single-0x42").
    pub name: String,
    /// Pass category (e.g. "xor", "mba", "opaque", "smc").
    pub category: String,
    /// Parameters as JSON-like map (key=value strings).
    pub params: Vec<(String, String)>,
}

impl DeobfPassSpec {
    #[must_use]
    pub fn new(name: impl Into<String>, category: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            category: category.into(),
            params: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.push((key.into(), value.into()));
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisState
// ─────────────────────────────────────────────────────────────────────────────

/// Lifecycle state of a hypothesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HypothesisState {
    /// Waiting to be executed.
    Pending,
    /// Currently being evaluated.
    Running,
    /// Evaluation complete (score assigned).
    Completed,
    /// Pruned because score was below threshold.
    Pruned,
    /// Evaluation failed with an error.
    Failed,
}

// ─────────────────────────────────────────────────────────────────────────────
// QualityScore
// ─────────────────────────────────────────────────────────────────────────────

/// Quality metrics computed for a hypothesis output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityScore {
    /// Shannon entropy of the output bytes (0.0–8.0; lower = more structured).
    pub entropy: f64,
    /// Fraction of printable ASCII bytes (0.0–1.0; higher = more readable).
    pub printable_ratio: f64,
    /// Number of candidate ASCII strings found (≥4 bytes).
    pub string_count: usize,
    /// Number of recognisable x86 function prologues (heuristic).
    pub function_prologue_count: usize,
    /// Weighted composite score (higher = better hypothesis).
    pub composite: f64,
}

impl QualityScore {
    /// Compute a [`QualityScore`] from raw output bytes.
    #[must_use]
    pub fn compute(output: &[u8]) -> Self {
        let entropy = compute_entropy(output);
        let printable_ratio = compute_printable(output);
        let string_count = count_strings(output, 4);
        let function_prologue_count = count_prologues(output);

        // Composite: weight readability + low entropy + string presence
        let composite = printable_ratio * 0.35
            + (1.0 - entropy / 8.0) * 0.30
            + (string_count.min(50) as f64 / 50.0) * 0.25
            + (function_prologue_count.min(10) as f64 / 10.0) * 0.10;

        Self {
            entropy,
            printable_ratio,
            string_count,
            function_prologue_count,
            composite,
        }
    }

    /// Whether this score suggests the hypothesis is likely correct.
    #[must_use]
    pub fn is_promising(&self) -> bool {
        self.composite > 0.4
    }
}

fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let n = data.len() as f64;
    freq.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

fn compute_printable(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    data.iter().filter(|&&b| b >= 0x20 && b <= 0x7E).count() as f64 / data.len() as f64
}

fn count_strings(data: &[u8], min_len: usize) -> usize {
    let mut count = 0;
    let mut run = 0;
    for &b in data {
        if b >= 0x20 && b <= 0x7E {
            run += 1;
        } else {
            if run >= min_len { count += 1; }
            run = 0;
        }
    }
    if run >= min_len { count += 1; }
    count
}

fn count_prologues(data: &[u8]) -> usize {
    let patterns: &[&[u8]] = &[
        &[0x55, 0x48, 0x89, 0xe5], // push rbp; mov rbp, rsp
        &[0x55, 0x89, 0xe5],        // push ebp; mov ebp, esp
        &[0x48, 0x83, 0xec],        // sub rsp, N
    ];
    let mut count = 0;
    for pat in patterns {
        count += data.windows(pat.len()).filter(|w| w == pat).count();
    }
    count
}

// ─────────────────────────────────────────────────────────────────────────────
// Hypothesis
// ─────────────────────────────────────────────────────────────────────────────

/// One deobfuscation hypothesis (a specific combination of pass parameters).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: HypothesisId,
    /// Description of the pass sequence.
    pub passes: Vec<DeobfPassSpec>,
    /// Current lifecycle state.
    pub state: HypothesisState,
    /// Output bytes produced by running the passes (if completed).
    pub output: Vec<u8>,
    /// Quality score (if completed).
    pub score: Option<QualityScore>,
    /// Error message if state is Failed.
    pub error: Option<String>,
    /// Parent hypothesis ID (for forked paths).
    pub parent: Option<HypothesisId>,
    /// Generation number (0 = root, increments on fork).
    pub generation: u32,
}

impl Hypothesis {
    #[must_use]
    pub const fn new(id: HypothesisId, passes: Vec<DeobfPassSpec>) -> Self {
        Self {
            id,
            passes,
            state: HypothesisState::Pending,
            output: Vec::new(),
            score: None,
            error: None,
            parent: None,
            generation: 0,
        }
    }

    /// Fork this hypothesis, prepending an additional pass.
    #[must_use]
    pub fn fork(&self, extra_pass: DeobfPassSpec, new_id: HypothesisId) -> Self {
        let mut passes = self.passes.clone();
        passes.push(extra_pass);
        Self {
            id: new_id,
            passes,
            state: HypothesisState::Pending,
            output: Vec::new(),
            score: None,
            error: None,
            parent: Some(self.id),
            generation: self.generation + 1,
        }
    }

    /// Assign output and compute score.
    pub fn complete(&mut self, output: Vec<u8>) {
        let score = QualityScore::compute(&output);
        self.output = output;
        self.score = Some(score);
        self.state = HypothesisState::Completed;
    }

    /// Mark as failed.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
        self.state = HypothesisState::Failed;
    }

    /// Composite score (0.0 if not yet scored).
    #[must_use]
    pub fn composite_score(&self) -> f64 {
        self.score.as_ref().map_or(0.0, |s| s.composite)
    }
}

/// Wrapper for ordering hypotheses in a max-heap by composite score.
struct _ScoredHypothesis(Arc<Mutex<Hypothesis>>);

impl PartialEq for _ScoredHypothesis {
    fn eq(&self, other: &Self) -> bool {
        let a = self.0.lock().unwrap().composite_score();
        let b = other.0.lock().unwrap().composite_score();
        a == b
    }
}

impl Eq for _ScoredHypothesis {}

impl PartialOrd for _ScoredHypothesis {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for _ScoredHypothesis {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = self.0.lock().unwrap().composite_score();
        let b = other.0.lock().unwrap().composite_score();
        a.partial_cmp(&b).unwrap_or(Ordering::Equal)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages all active hypotheses, pruning to top-K.
pub struct HypothesisManager {
    /// Maximum number of hypotheses to keep alive.
    pub top_k: usize,
    /// Minimum composite score for a hypothesis to survive pruning.
    pub min_score: f64,
    /// All hypotheses ever created (including pruned).
    all: Vec<Arc<Mutex<Hypothesis>>>,
    /// ID counter.
    counter: u64,
}

impl HypothesisManager {
    /// Create a new manager.
    #[must_use]
    pub const fn new(top_k: usize, min_score: f64) -> Self {
        Self {
            top_k,
            min_score,
            all: Vec::new(),
            counter: 0,
        }
    }

    /// Create and register a new hypothesis.
    pub fn create(&mut self, passes: Vec<DeobfPassSpec>) -> HypothesisId {
        let id = HypothesisId::next(&mut self.counter);
        let h = Arc::new(Mutex::new(Hypothesis::new(id, passes)));
        self.all.push(h);
        id
    }

    /// Fork an existing hypothesis with an additional pass.
    ///
    /// Returns `None` if the parent hypothesis is not found.
    pub fn fork(&mut self, parent_id: HypothesisId, extra_pass: DeobfPassSpec) -> Option<HypothesisId> {
        let parent_arc = self.find_arc(parent_id)?;
        let new_id = HypothesisId::next(&mut self.counter);
        let child = {
            let p = parent_arc.lock().unwrap();
            p.fork(extra_pass, new_id)
        };
        self.all.push(Arc::new(Mutex::new(child)));
        Some(new_id)
    }

    /// Mark hypothesis as complete with the given output bytes.
    #[must_use]
    pub fn complete(&self, id: HypothesisId, output: Vec<u8>) -> bool {
        if let Some(arc) = self.find_arc(id) {
            arc.lock().unwrap().complete(output);
            true
        } else {
            false
        }
    }

    /// Mark hypothesis as failed.
    pub fn fail(&self, id: HypothesisId, error: impl Into<String>) -> bool {
        if let Some(arc) = self.find_arc(id) {
            arc.lock().unwrap().fail(error);
            true
        } else {
            false
        }
    }

    /// Prune hypotheses below threshold or beyond top-K.
    ///
    /// Returns the IDs of pruned hypotheses.
    pub fn prune(&mut self) -> Vec<HypothesisId> {
        let mut pruned = Vec::new();

        // Mark below-threshold as Pruned
        for arc in &self.all {
            let mut h = arc.lock().unwrap();
            if h.state == HypothesisState::Completed && h.composite_score() < self.min_score {
                h.state = HypothesisState::Pruned;
                pruned.push(h.id);
            }
        }

        // Keep only top-K among completed
        let mut completed: Vec<(f64, HypothesisId)> = self
            .all
            .iter()
            .filter_map(|a| {
                let h = a.lock().unwrap();
                if h.state == HypothesisState::Completed {
                    Some((h.composite_score(), h.id))
                } else {
                    None
                }
            })
            .collect();
        // `unwrap()` would panic on a NaN score; every other ranking in this
        // crate already falls back to `Equal`.
        completed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        for (_, id) in completed.into_iter().skip(self.top_k) {
            if let Some(arc) = self.find_arc(id) {
                let mut h = arc.lock().unwrap();
                if h.state == HypothesisState::Completed {
                    h.state = HypothesisState::Pruned;
                    pruned.push(id);
                }
            }
        }

        pruned
    }

    /// Return the best completed hypothesis.
    #[must_use]
    pub fn best(&self) -> Option<Hypothesis> {
        self.all
            .iter()
            .filter_map(|a| {
                let h = a.lock().unwrap();
                if h.state == HypothesisState::Completed {
                    Some(h.clone())
                } else {
                    None
                }
            })
            .max_by(|a, b| {
                a.composite_score()
                    .partial_cmp(&b.composite_score())
                    .unwrap()
            })
    }

    /// Return all hypotheses in a given state.
    #[must_use]
    pub fn by_state(&self, state: HypothesisState) -> Vec<Hypothesis> {
        self.all
            .iter()
            .filter_map(|a| {
                let h = a.lock().unwrap();
                if h.state == state { Some(h.clone()) } else { None }
            })
            .collect()
    }

    /// Return all pending hypothesis IDs.
    #[must_use]
    pub fn pending_ids(&self) -> Vec<HypothesisId> {
        self.all
            .iter()
            .filter_map(|a| {
                let h = a.lock().unwrap();
                if h.state == HypothesisState::Pending { Some(h.id) } else { None }
            })
            .collect()
    }

    /// Number of hypotheses in each state.
    #[must_use]
    pub fn status_summary(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for arc in &self.all {
            let h = arc.lock().unwrap();
            let key = format!("{:?}", h.state);
            *map.entry(key).or_default() += 1;
        }
        map
    }

    fn find_arc(&self, id: HypothesisId) -> Option<Arc<Mutex<Hypothesis>>> {
        self.all
            .iter()
            .find(|a| a.lock().unwrap().id == id)
            .cloned()
    }
}

use ahash::AHashMap as HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisGenerator — generates initial hypothesis set
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a diverse initial set of hypotheses for a given input.
pub struct HypothesisGenerator {
    /// XOR key candidates to try.
    pub xor_keys: Vec<u8>,
    /// Whether to include MBA simplification hypotheses.
    pub include_mba: bool,
    /// Whether to include opaque predicate hypotheses.
    pub include_opaque: bool,
    /// Whether to include SMC hypotheses.
    pub include_smc: bool,
}

impl Default for HypothesisGenerator {
    fn default() -> Self {
        Self {
            xor_keys: vec![0x00, 0x13, 0x42, 0x5A, 0xAA, 0xFF],
            include_mba: true,
            include_opaque: true,
            include_smc: false,
        }
    }
}

impl HypothesisGenerator {
    /// Generate all hypotheses and register them in the manager.
    pub fn generate(&self, manager: &mut HypothesisManager) -> Vec<HypothesisId> {
        let mut ids = Vec::new();

        // XOR single-byte hypotheses
        for &key in &self.xor_keys {
            let pass = DeobfPassSpec::new(
                format!("XOR-single-0x{key:02X}"),
                "xor",
            )
            .with_param("key", format!("{key}"));
            ids.push(manager.create(vec![pass]));
        }

        // MBA simplification hypothesis
        if self.include_mba {
            let pass = DeobfPassSpec::new("MBA-simplify", "mba");
            ids.push(manager.create(vec![pass]));
        }

        // Opaque predicate elimination hypothesis
        if self.include_opaque {
            let pass = DeobfPassSpec::new("opaque-pred-elim", "opaque");
            ids.push(manager.create(vec![pass]));
        }

        // Combined: opaque + MBA
        if self.include_mba && self.include_opaque {
            let passes = vec![
                DeobfPassSpec::new("opaque-pred-elim", "opaque"),
                DeobfPassSpec::new("MBA-simplify", "mba"),
            ];
            ids.push(manager.create(passes));
        }

        // SMC hypothesis
        if self.include_smc {
            let pass = DeobfPassSpec::new("SMC-reconstruct", "smc");
            ids.push(manager.create(vec![pass]));
        }

        ids
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hypothesis_lifecycle() {
        let mut mgr = HypothesisManager::new(5, 0.1);
        let id = mgr.create(vec![DeobfPassSpec::new("test", "xor")]);
        assert!(!mgr.by_state(HypothesisState::Pending).is_empty());

        let output = b"Hello World!!!! some readable text here".to_vec();
        // `complete` returns whether the id was found; ignoring it meant an
        // unknown id silently did nothing and the failure surfaced later, on a
        // count assertion, pointing at the wrong line.
        assert!(mgr.complete(id, output), "the hypothesis id must be known");
        assert_eq!(mgr.by_state(HypothesisState::Completed).len(), 1);
    }

    #[test]
    fn test_pruning_keeps_top_k() {
        let mut mgr = HypothesisManager::new(2, 0.0);
        for i in 0..5 {
            let id = mgr.create(vec![DeobfPassSpec::new(format!("pass-{}", i), "xor")]);
            // Give each a different quality output
            let output = vec![b'A' + i as u8; 100 * (i + 1)];
            assert!(mgr.complete(id, output), "hypothesis {i} must be known");
        }
        mgr.prune();
        let surviving = mgr.by_state(HypothesisState::Completed);
        assert!(surviving.len() <= 2, "too many survived: {}", surviving.len());
    }

    #[test]
    fn test_quality_score_high_for_readable() {
        let text = b"GetProcAddress kernel32 LoadLibraryA VirtualAlloc";
        let score = QualityScore::compute(text);
        assert!(score.printable_ratio > 0.9);
        assert!(score.string_count > 0);
    }

    #[test]
    fn test_hypothesis_generator() {
        let mut mgr = HypothesisManager::new(20, 0.0);
        let hgen = HypothesisGenerator::default();
        let ids = hgen.generate(&mut mgr);
        assert!(ids.len() >= 6, "not enough hypotheses generated: {}", ids.len());
    }
}
