//! `rustre-diff-semantic`
//!
//! Semantic / behavioural binary diffing — match functions by behaviour rather
//! than raw bytes.

pub mod function_diff;
pub mod mlil_diff;
pub mod patch_analysis;
pub mod semantic_hash;
pub mod similarity;
pub mod similarity_score;
pub mod ir_semantic_diff;

pub mod behavior_diff;
/// Semantic equivalence checking: SemanticEquivalenceChecker, NormalizedIL
/// (α-renamed/constant-folded), EquivalenceClass, SMTEquivalenceProver,
/// FunctionHash (semantic hash), EquivalenceDb.
///
pub mod semantic_equivalence;
pub mod ast_differ;
pub mod type_diff;
pub mod variable_diff;
pub mod control_flow_diff;
pub mod call_site_diff;
pub mod semantic_comparison;

use std::collections::HashMap;
use std::fmt;

use rustre_core::arch::{InstrFlags, Instruction, Operand};
use rustre_diff::{BinaryDiff, DiffEngine, FuncFingerprint, FuncMatch};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced by semantic diff operations.
#[derive(Debug, Error)]
pub enum SemanticDiffError {
    /// Feature extraction / normalization failed.
    #[error("normalization failed: {0}")]
    NormalizationFailed(String),
    /// Underlying diff error — wraps the full error chain via `anyhow`.
    #[error("diff error: {0:#}")]
    Diff(#[source] anyhow::Error),
}

// ---------------------------------------------------------------------------
// SemanticFeatures
// ---------------------------------------------------------------------------

/// A semantic feature vector extracted from a function's instruction stream.
///
/// Used to compare functions across binaries at a behavioural level,
/// independent of absolute addresses or minor code-generation differences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticFeatures {
    /// Start address of the function.
    pub address: u64,
    /// Symbolic name of the function.
    pub name: String,
    /// Addresses of call-sites inside this function.
    pub call_sites: Vec<u64>,
    /// String references (raw bytes decoded as UTF-8 where possible).
    pub string_refs: Vec<String>,
    /// Immediate constants found in the instruction stream.
    pub constant_pool: Vec<u64>,
    /// Histogram of mnemonic strings.
    pub mnemonic_histogram: HashMap<String, u32>,
    /// Syscall numbers encountered.
    pub syscall_numbers: Vec<u32>,
    /// Number of backward branches (loop back-edges).
    pub loop_count: u32,
    /// Total number of conditional or unconditional branches.
    pub branch_count: u32,
    /// Number of arithmetic instructions.
    pub arithmetic_ops: u32,
    /// Number of memory-load or memory-store instructions.
    pub memory_ops: u32,
}

impl SemanticFeatures {
    /// Extract a [`SemanticFeatures`] vector from an instruction stream.
    #[must_use]
    pub fn from_instructions(address: u64, name: String, instrs: &[Instruction]) -> Self {
        let mut call_sites = Vec::new();
        let mut constant_pool = Vec::new();
        let mut mnemonic_histogram: HashMap<String, u32> = HashMap::new();
        let mut loop_count = 0u32;
        let mut branch_count = 0u32;
        let mut arithmetic_ops = 0u32;
        let mut memory_ops = 0u32;

        for instr in instrs {
            // Mnemonic histogram
            *mnemonic_histogram
                .entry(instr.mnemonic.clone())
                .or_insert(0) += 1;

            // Classify by flags
            if instr.flags.contains(InstrFlags::CALL) {
                call_sites.push(instr.address.as_u64());
            }
            if instr.flags.contains(InstrFlags::BRANCH) {
                branch_count += 1;
                // Heuristic: backward branch (target < current instruction address) → loop back-edge.
                // Extract the branch target from the operand list: look for the first
                // Immediate or UImmediate operand which represents the absolute target address.
                let branch_target: Option<u64> = instr.operand_list.iter().find_map(|op| {
                    match op {
                        Operand::UImmediate(v) => Some(*v),
                        Operand::Immediate(v) => u64::try_from(*v).ok(),
                        _ => None,
                    }
                });
                if let Some(target) = branch_target {
                    if target < instr.address.as_u64() {
                        loop_count += 1;
                    }
                }
            }
            if instr.flags.contains(InstrFlags::READ_MEM)
                || instr.flags.contains(InstrFlags::WRITE_MEM)
            {
                memory_ops += 1;
            }

            // Arithmetic heuristic: ADD, SUB, MUL, DIV, AND, OR, XOR, SHL, SHR …
            let mn = instr.mnemonic.to_ascii_uppercase();
            if matches!(
                mn.as_str(),
                "ADD"
                    | "SUB"
                    | "MUL"
                    | "DIV"
                    | "IMUL"
                    | "IDIV"
                    | "AND"
                    | "OR"
                    | "XOR"
                    | "SHL"
                    | "SHR"
                    | "SAR"
                    | "INC"
                    | "DEC"
                    | "NEG"
                    | "NOT"
                    | "ADDI"
                    | "SUBI"
            ) {
                arithmetic_ops += 1;
            }

            // Collect numeric constants from operands (simple heuristic: look for
            // hex-like tokens). Cap at 65_536 to prevent dos-memory-exhaustion
            // when an attacker-supplied instruction stream has huge operand lists.
            if constant_pool.len() < 65_536 {
                for token in instr.operands.split_whitespace() {
                    let token = token.trim_matches(',');
                    if let Some(hex) = token
                        .strip_prefix("0x")
                        .or_else(|| token.strip_prefix("0X"))
                        && let Ok(v) = u64::from_str_radix(hex, 16)
                        && constant_pool.len() < 65_536
                    {
                        constant_pool.push(v);
                    }
                }
            }

        }

        constant_pool.sort_unstable();
        constant_pool.dedup();

        Self {
            address,
            name,
            call_sites,
            string_refs: Vec::new(),
            constant_pool,
            mnemonic_histogram,
            syscall_numbers: Vec::new(),
            loop_count,
            branch_count,
            arithmetic_ops,
            memory_ops,
        }
    }

    /// Semantic similarity score in `0.0..=1.0` against another feature vector.
    ///
    /// Combines mnemonic-histogram cosine similarity, branch-count closeness,
    /// and constant-pool overlap.
    #[must_use]
    pub fn semantic_similarity(&self, other: &Self) -> f64 {
        let mnem_sim =
            mnemonic_cosine_similarity(&self.mnemonic_histogram, &other.mnemonic_histogram);

        let branch_sim =
            ratio_similarity(u64::from(self.branch_count), u64::from(other.branch_count));
        let loop_sim = ratio_similarity(u64::from(self.loop_count), u64::from(other.loop_count));
        let arith_sim = ratio_similarity(
            u64::from(self.arithmetic_ops),
            u64::from(other.arithmetic_ops),
        );
        let memory_sim = ratio_similarity(u64::from(self.memory_ops), u64::from(other.memory_ops));
        let const_sim = set_overlap_similarity(&self.constant_pool, &other.constant_pool);

        // Weighted combination
        0.15f64.mul_add(const_sim, 0.10f64.mul_add(memory_sim, 0.15f64.mul_add(arith_sim, 0.10f64.mul_add(loop_sim, 0.35f64.mul_add(mnem_sim, 0.15 * branch_sim)))))
    }

    /// Total number of extracted features (call sites + string refs + constants).
    #[must_use]
    pub const fn feature_count(&self) -> usize {
        self.call_sites.len() + self.string_refs.len() + self.constant_pool.len()
    }
}

impl fmt::Display for SemanticFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SemanticFeatures[{}@{:#x}] loops={} branches={}",
            self.name, self.address, self.loop_count, self.branch_count
        )
    }
}

// ---------------------------------------------------------------------------
// NormalizedBytes
// ---------------------------------------------------------------------------

/// Address-normalised function bytes (REL-bytes style).
///
/// Absolute addresses embedded in CALL/JMP operands are replaced with zero
/// bytes, making the body comparable across different load addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedBytes {
    /// Original load address of the function.
    pub original_address: u64,
    /// Address-normalised byte sequence.
    pub normalized_bytes: Vec<u8>,
    /// Symbolic name.
    pub name: String,
}

impl NormalizedBytes {
    /// Build a normalised representation from a raw [`FuncFingerprint`].
    ///
    /// The simple strategy used here: for every sequence of 4 or 8 bytes that
    /// looks like it encodes an absolute address near the function's own address
    /// (within ±4 MiB), replace them with zeros.
    #[must_use]
    pub fn from_fingerprint(fp: &FuncFingerprint) -> Self {
        let bytes = &fp.bytes;
        let mut out = bytes.clone();
        let base = fp.address;

        // Simple heuristic: scan for 4-byte little-endian values that fall
        // inside [base-4M, base+4M] and zero them out as "relocated" operands.
        let window: u64 = 4 * 1024 * 1024;
        let lo = base.saturating_sub(window);
        let hi = base.saturating_add(window);

        let mut i = 0;
        while i + 4 <= out.len() {
            let v = u64::from(u32::from_le_bytes([out[i], out[i + 1], out[i + 2], out[i + 3]]));
            if v >= lo && v <= hi {
                out[i] = 0;
                out[i + 1] = 0;
                out[i + 2] = 0;
                out[i + 3] = 0;
                i += 4;
            } else {
                i += 1;
            }
        }

        Self {
            original_address: fp.address,
            normalized_bytes: out,
            name: fp.name.clone(),
        }
    }

    /// LCS-based structural similarity between two normalised functions.
    #[must_use]
    pub fn structural_similarity(&self, other: &Self) -> f64 {
        rustre_diff::lcs_similarity(&self.normalized_bytes, &other.normalized_bytes)
    }
}

impl fmt::Display for NormalizedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Normalized[{}@{:#x}] {} bytes",
            self.name,
            self.original_address,
            self.normalized_bytes.len()
        )
    }
}

// ---------------------------------------------------------------------------
// SemanticMatch / SemanticDiffResult
// ---------------------------------------------------------------------------

/// A function match augmented with semantic and structural similarity scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticMatch {
    /// Underlying byte-level function match.
    pub func_match: FuncMatch,
    /// Semantic (behaviour-level) similarity score.
    pub semantic_similarity: f64,
    /// Structural (normalised-bytes LCS) similarity score.
    pub structural_similarity: f64,
    /// Human-readable descriptions of features that changed between the pair.
    pub changed_features: Vec<String>,
}

impl fmt::Display for SemanticMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SemanticMatch sem={:.2} struct={:.2}",
            self.semantic_similarity, self.structural_similarity
        )
    }
}

/// The full result of a semantic diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticDiffResult {
    /// The underlying byte-level binary diff.
    pub base: BinaryDiff,
    /// Enriched matches with semantic annotations.
    pub semantic_matches: Vec<SemanticMatch>,
    /// Mean feature similarity across all paired matches.
    pub feature_similarity: f64,
}

impl fmt::Display for SemanticDiffResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SemanticDiffResult: {} byte-matches, {} semantic-matches, feat_sim={:.2}",
            self.base.matches.len(),
            self.semantic_matches.len(),
            self.feature_similarity
        )
    }
}

// ---------------------------------------------------------------------------
// SemanticDiffEngine
// ---------------------------------------------------------------------------

/// Semantic diff engine — converts [`SemanticFeatures`] to fingerprints and
/// annotates the byte-level diff with richer behavioural information.
pub struct SemanticDiffEngine {
    inner: DiffEngine,
}

impl SemanticDiffEngine {
    /// Create a new engine with a default similarity threshold of 0.5.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: DiffEngine::new(0.5),
        }
    }

    /// Diff two sets of semantic feature vectors.
    ///
    /// # Errors
    ///
    /// Returns [`SemanticDiffError`] if the inner diff fails or if an
    /// unexpected condition is encountered.
    pub fn diff_with_features(
        &self,
        feats_a: Vec<SemanticFeatures>,
        feats_b: Vec<SemanticFeatures>,
        name_a: String,
        name_b: String,
    ) -> Result<SemanticDiffResult, SemanticDiffError> {
        // Build lookup maps keyed by address so we can annotate matches later.
        let feats_a_map: HashMap<u64, SemanticFeatures> =
            feats_a.iter().map(|f| (f.address, f.clone())).collect();
        let feats_by_addr_b: HashMap<u64, SemanticFeatures> =
            feats_b.iter().map(|f| (f.address, f.clone())).collect();

        // Convert features to fingerprints for the byte-level engine
        let fps_a: Vec<FuncFingerprint> = feats_a
            .into_iter()
            .map(|f| features_to_fingerprint(&f))
            .collect();
        let fps_b: Vec<FuncFingerprint> = feats_b
            .into_iter()
            .map(|f| features_to_fingerprint(&f))
            .collect();

        let base = self
            .inner
            .diff(fps_a, &fps_b, name_a, name_b)
            .map_err(|e| SemanticDiffError::Diff(anyhow::anyhow!(e)))?;

        // Annotate each match with semantic info
        let mut semantic_matches = Vec::new();
        let mut total_feat_sim = 0.0f64;
        let mut paired = 0usize;

        for m in &base.matches {
            let (sem_sim, struct_sim, changed) = match (&m.primary, &m.secondary) {
                (Some(a), Some(b)) => {
                    let fa = feats_a_map.get(&a.address);
                    let fb = feats_by_addr_b.get(&b.address);
                    let sem = match (fa, fb) {
                        (Some(fa), Some(fb)) => fa.semantic_similarity(fb),
                        _ => m.similarity,
                    };
                    let norm_a = NormalizedBytes::from_fingerprint(a);
                    let norm_b = NormalizedBytes::from_fingerprint(b);
                    let stru = norm_a.structural_similarity(&norm_b);
                    let changed = build_changed_features(fa, fb);
                    total_feat_sim += sem;
                    paired += 1;
                    (sem, stru, changed)
                }
                (Some(_), None) | (None, Some(_)) => (0.0, 0.0, vec![]),
                (None, None) => (0.0, 0.0, vec![]),
            };

            semantic_matches.push(SemanticMatch {
                func_match: m.clone(),
                semantic_similarity: sem_sim,
                structural_similarity: struct_sim,
                changed_features: changed,
            });
        }

        let feature_similarity = if paired > 0 {
            total_feat_sim / crate::semantic_comparison::count_as_f64(paired)
        } else {
            0.0
        };

        Ok(SemanticDiffResult {
            base,
            semantic_matches,
            feature_similarity,
        })
    }
}

impl Default for SemanticDiffEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SemanticDiffEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SemanticDiffEngine")
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert a [`SemanticFeatures`] vector into a synthetic [`FuncFingerprint`]
/// by encoding the feature histogram into a pseudo-byte stream.
fn features_to_fingerprint(feat: &SemanticFeatures) -> FuncFingerprint {
    // Encode the feature vector as a deterministic byte sequence so that the
    // byte-level LCS engine can compare behaviours.
    let mut pseudo: Vec<u8> = Vec::new();

    // Encode sorted mnemonic histogram keys as ASCII bytes
    let mut keys: Vec<&String> = feat.mnemonic_histogram.keys().collect();
    keys.sort();
    for k in keys {
        pseudo.extend_from_slice(k.as_bytes());
        let cnt = feat.mnemonic_histogram[k].min(255) as u8;
        pseudo.push(cnt);
        pseudo.push(0xFF); // separator
    }

    FuncFingerprint::new(feat.address, feat.name.clone(), pseudo)
}

/// Compute cosine similarity between two mnemonic-frequency maps.
fn mnemonic_cosine_similarity(a: &HashMap<String, u32>, b: &HashMap<String, u32>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    let mut dot: f64 = 0.0;
    let mut mag_a: f64 = 0.0;
    let mut mag_b: f64 = 0.0;

    for (k, &va) in a {
        let vaf = f64::from(va);
        mag_a += vaf * vaf;
        if let Some(&vb) = b.get(k) {
            dot += vaf * f64::from(vb);
        }
    }
    for &vb in b.values() {
        let vbf = f64::from(vb);
        mag_b += vbf * vbf;
    }

    let denom = mag_a.sqrt() * mag_b.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (dot / denom).min(1.0)
    }
}

/// Similarity between two counts: `min/max`, clamped to `0.0..=1.0`.
fn ratio_similarity(a: u64, b: u64) -> f64 {
    if a == 0 && b == 0 {
        return 1.0;
    }
    if a == 0 || b == 0 {
        return 0.0;
    }
    let (lo, hi) = (a.min(b), a.max(b));
    lo as f64 / hi as f64
}

/// Jaccard-like overlap similarity between two sorted, deduplicated slices.
fn set_overlap_similarity(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let mut intersection = 0usize;
    let mut ia = 0;
    let mut ib = 0;
    while ia < a.len() && ib < b.len() {
        match a[ia].cmp(&b[ib]) {
            std::cmp::Ordering::Equal => {
                intersection += 1;
                ia += 1;
                ib += 1;
            }
            std::cmp::Ordering::Less => ia += 1,
            std::cmp::Ordering::Greater => ib += 1,
        }
    }
    let union = a.len() + b.len() - intersection;
    if union == 0 {
        1.0
    } else {
        crate::semantic_comparison::count_as_f64(intersection) / crate::semantic_comparison::count_as_f64(union)
    }
}

/// Build a list of human-readable changed-feature descriptions.
fn build_changed_features(
    fa: Option<&SemanticFeatures>,
    fb: Option<&SemanticFeatures>,
) -> Vec<String> {
    let (Some(a), Some(b)) = (fa, fb) else {
        return vec![];
    };
    let mut changes = Vec::new();
    if a.branch_count != b.branch_count {
        changes.push(format!(
            "branch_count: {} → {}",
            a.branch_count, b.branch_count
        ));
    }
    if a.loop_count != b.loop_count {
        changes.push(format!("loop_count: {} → {}", a.loop_count, b.loop_count));
    }
    if a.arithmetic_ops != b.arithmetic_ops {
        changes.push(format!(
            "arithmetic_ops: {} → {}",
            a.arithmetic_ops, b.arithmetic_ops
        ));
    }
    if a.memory_ops != b.memory_ops {
        changes.push(format!("memory_ops: {} → {}", a.memory_ops, b.memory_ops));
    }
    if a.call_sites.len() != b.call_sites.len() {
        changes.push(format!(
            "call_sites: {} → {}",
            a.call_sites.len(),
            b.call_sites.len()
        ));
    }
    changes
}

// ---------------------------------------------------------------------------
// MinHash
// ---------------------------------------------------------------------------

/// `MinHash` implementation for estimating the Jaccard similarity of two sets
/// of features without storing the sets explicitly.
///
/// Uses a family of universal hash functions of the form `(a*x + b) mod p mod n`
/// where `p` is a large prime, `a` and `b` are random coefficients, and `n`
/// is the number of hash buckets.
#[derive(Debug, Clone)]
pub struct MinHash {
    num_hashes: usize,
    coefficients: Vec<(u64, u64)>,
}

impl MinHash {
    const PRIME: u64 = 4_294_967_311; // first prime > 2^32

    /// Create a [`MinHash`] estimator with `num_hashes` hash functions.
    ///
    /// Uses a deterministic seed derived from `num_hashes` for reproducibility.
    #[must_use]
    pub fn new(num_hashes: usize) -> Self {
        // Deterministic coefficient generation (xorshift64 seeded by num_hashes).
        let mut state: u64 = (num_hashes as u64)
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let coefficients: Vec<(u64, u64)> = (0..num_hashes)
            .map(|_| {
                let a = {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state
                } % Self::PRIME;
                let b = {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state
                } % Self::PRIME;
                (a.max(1), b)
            })
            .collect();
        Self {
            num_hashes,
            coefficients,
        }
    }

    /// Compute the `MinHash` signature of `elements`.
    ///
    /// Each element is converted to a `u64` via a simple hash, then the
    /// minimum of each hash function applied over all elements is stored.
    #[must_use]
    pub fn signature(&self, elements: &[u64]) -> Vec<u64> {
        if elements.is_empty() {
            return vec![u64::MAX; self.num_hashes];
        }
        let mut sig = vec![u64::MAX; self.num_hashes];
        for &elem in elements {
            for (i, &(a, b)) in self.coefficients.iter().enumerate() {
                let h = (a.wrapping_mul(elem).wrapping_add(b)) % Self::PRIME;
                if h < sig[i] {
                    sig[i] = h;
                }
            }
        }
        sig
    }

    /// Estimate Jaccard similarity between two sets from their signatures.
    ///
    /// Returns a value in `[0.0, 1.0]`.
    #[must_use]
    pub fn estimate_jaccard(sig_a: &[u64], sig_b: &[u64]) -> f64 {
        if sig_a.is_empty() || sig_b.len() != sig_a.len() {
            return 0.0;
        }
        let equal = sig_a.iter().zip(sig_b).filter(|(a, b)| a == b).count();
        crate::semantic_comparison::count_as_f64(equal) / crate::semantic_comparison::count_as_f64(sig_a.len())
    }
}

// ---------------------------------------------------------------------------
// LshBand / LshIndex
// ---------------------------------------------------------------------------

/// An LSH (Locality-Sensitive Hashing) band: a contiguous slice of a `MinHash`
/// signature hashed into a bucket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LshBandKey(Vec<u64>);

/// LSH index built from `MinHash` signatures, used to find approximate
/// nearest-neighbours efficiently.
///
/// Signatures are split into `num_bands` bands of `rows_per_band` rows.
/// Two items land in the same bucket iff all rows in a band are equal —
/// probability increases with Jaccard similarity.
#[derive(Debug)]
pub struct LshIndex {
    num_bands: usize,
    rows_per_band: usize,
    /// `band_index`[band][bucket] = list of item identifiers (e.g. function addresses).
    band_buckets: Vec<HashMap<LshBandKey, Vec<u64>>>,
    /// Count of distinct item IDs inserted so far (maintained by `insert`).
    item_ids: std::collections::HashSet<u64>,
}

impl LshIndex {
    /// Create a new LSH index with `num_bands` bands and `rows_per_band` rows per band.
    ///
    /// Total signature length = `num_bands * rows_per_band`.
    #[must_use]
    pub fn new(num_bands: usize, rows_per_band: usize) -> Self {
        Self {
            num_bands,
            rows_per_band,
            band_buckets: (0..num_bands).map(|_| HashMap::new()).collect(),
            item_ids: std::collections::HashSet::new(),
        }
    }

    /// Insert item with `id` and `MinHash` `signature` into the index.
    pub fn insert(&mut self, id: u64, signature: &[u64]) {
        self.item_ids.insert(id);
        for (band, buckets) in self.band_buckets.iter_mut().enumerate() {
            let start = band * self.rows_per_band;
            let end = (start + self.rows_per_band).min(signature.len());
            if start < signature.len() {
                let key = LshBandKey(signature[start..end].to_vec());
                buckets.entry(key).or_default().push(id);
            }
        }
    }

    /// Query for all item IDs that are candidate near-neighbours of `signature`.
    ///
    /// Returns a deduplicated list of IDs that share at least one band bucket
    /// with the query.
    #[must_use]
    pub fn query(&self, signature: &[u64]) -> Vec<u64> {
        let mut candidates: Vec<u64> = Vec::new();
        for (band, buckets) in self.band_buckets.iter().enumerate() {
            let start = band * self.rows_per_band;
            let end = (start + self.rows_per_band).min(signature.len());
            if start < signature.len() {
                let key = LshBandKey(signature[start..end].to_vec());
                if let Some(ids) = buckets.get(&key) {
                    candidates.extend_from_slice(ids);
                }
            }
        }
        candidates.sort_unstable();
        candidates.dedup();
        candidates
    }

    /// Return the number of bands this index was built with.
    #[must_use]
    pub const fn num_bands(&self) -> usize {
        self.num_bands
    }

    /// Return the number of rows per band.
    #[must_use]
    pub const fn rows_per_band(&self) -> usize {
        self.rows_per_band
    }

    /// Return the total number of distinct items indexed.
    ///
    /// O(1) — the count is maintained incrementally by [`insert`](Self::insert).
    #[must_use]
    pub fn len(&self) -> usize {
        self.item_ids.len()
    }

    /// Returns `true` if the index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.band_buckets.iter().all(std::collections::HashMap::is_empty)
    }
}

// ---------------------------------------------------------------------------
// CallGraph
// ---------------------------------------------------------------------------

/// A directed call graph for a binary, backed by `petgraph`.
///
/// Each node is a function represented by its address. Edges are directed
/// call relationships: `caller → callee`.
#[derive(Debug)]
pub struct CallGraph {
    graph: petgraph::graph::DiGraph<u64, ()>,
    addr_to_node: HashMap<u64, petgraph::graph::NodeIndex>,
}

impl CallGraph {
    /// Create an empty call graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: petgraph::graph::DiGraph::new(),
            addr_to_node: HashMap::new(),
        }
    }

    /// Add a function node for `address`. Returns the node index.
    pub fn add_function(&mut self, address: u64) -> petgraph::graph::NodeIndex {
        if let Some(&idx) = self.addr_to_node.get(&address) {
            return idx;
        }
        let idx = self.graph.add_node(address);
        self.addr_to_node.insert(address, idx);
        idx
    }

    /// Add a call edge `caller → callee`.
    pub fn add_call(&mut self, caller: u64, target: u64) {
        let a = self.add_function(caller);
        let b = self.add_function(target);
        if !self.graph.contains_edge(a, b) {
            self.graph.add_edge(a, b, ());
        }
    }

    /// Return the number of function nodes.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Return the number of call edges.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Return the out-degree (number of callees) for a function.
    #[must_use]
    pub fn out_degree(&self, address: u64) -> usize {
        self.addr_to_node
            .get(&address)
            .map_or(0, |&idx| {
                self.graph
                    .neighbors_directed(idx, petgraph::Direction::Outgoing)
                    .count()
            })
    }

    /// Return the in-degree (number of callers) for a function.
    #[must_use]
    pub fn in_degree(&self, address: u64) -> usize {
        self.addr_to_node
            .get(&address)
            .map_or(0, |&idx| {
                self.graph
                    .neighbors_directed(idx, petgraph::Direction::Incoming)
                    .count()
            })
    }

    /// Return addresses of all direct callees of `caller`.
    #[must_use]
    pub fn callees(&self, caller: u64) -> Vec<u64> {
        let Some(&idx) = self.addr_to_node.get(&caller) else {
            return vec![];
        };
        self.graph
            .neighbors_directed(idx, petgraph::Direction::Outgoing)
            .map(|n| self.graph[n])
            .collect()
    }

    /// Return addresses of all direct callers of `callee`.
    #[must_use]
    pub fn callers(&self, callee: u64) -> Vec<u64> {
        let Some(&idx) = self.addr_to_node.get(&callee) else {
            return vec![];
        };
        self.graph
            .neighbors_directed(idx, petgraph::Direction::Incoming)
            .map(|n| self.graph[n])
            .collect()
    }

    /// Returns `true` if the function at `address` is a leaf (no callees).
    #[must_use]
    pub fn is_leaf(&self, address: u64) -> bool {
        self.out_degree(address) == 0
    }

    /// Returns `true` if the function at `address` is a root (no callers).
    #[must_use]
    pub fn is_root(&self, address: u64) -> bool {
        self.in_degree(address) == 0
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FunctionRenameHeuristic
// ---------------------------------------------------------------------------

/// Heuristic for predicting whether a function was renamed between two binaries.
///
/// A rename is inferred when:
/// - The semantic similarity between two matched functions is above `threshold`.
/// - The function names differ.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRenameHeuristic {
    /// Minimum semantic similarity to consider a pair a rename candidate.
    pub threshold: f64,
}

impl FunctionRenameHeuristic {
    /// Create a heuristic with the given similarity `threshold`.
    #[must_use]
    pub const fn new(threshold: f64) -> Self {
        Self { threshold }
    }

    /// Test whether `match_result` represents a likely rename.
    ///
    /// Returns `true` if `semantic_similarity >= threshold` AND the names differ.
    #[must_use]
    pub fn is_rename(&self, match_result: &SemanticMatch) -> bool {
        if match_result.semantic_similarity < self.threshold {
            return false;
        }
        let (primary_name, secondary_name) = match (
            &match_result.func_match.primary,
            &match_result.func_match.secondary,
        ) {
            (Some(a), Some(b)) => (a.name.as_str(), b.name.as_str()),
            _ => return false,
        };
        primary_name != secondary_name
    }

    /// Filter a list of semantic matches and return only likely renames.
    #[must_use]
    pub fn find_renames<'a>(&self, matches: &'a [SemanticMatch]) -> Vec<&'a SemanticMatch> {
        matches.iter().filter(|m| self.is_rename(m)).collect()
    }
}

impl Default for FunctionRenameHeuristic {
    fn default() -> Self {
        Self::new(0.8)
    }
}

// ---------------------------------------------------------------------------
// DiffReport
// ---------------------------------------------------------------------------

/// Summary statistics for a semantic diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffStats {
    /// Total functions in binary A.
    pub funcs_in_a: usize,
    /// Total functions in binary B.
    pub funcs_in_b: usize,
    /// Functions added in B (not present in A).
    pub added: usize,
    /// Functions removed from A (not in B).
    pub removed: usize,
    /// Functions that appear in both with changed behaviour.
    pub modified: usize,
    /// Functions that appear identical (similarity = 1.0).
    pub identical: usize,
    /// Mean semantic similarity across all paired matches.
    pub mean_semantic_similarity: f64,
}

/// A complete, human-readable semantic diff report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    /// Name / path of the first binary.
    pub binary_a: String,
    /// Name / path of the second binary.
    pub binary_b: String,
    /// Summary statistics.
    pub stats: DiffStats,
    /// All semantic matches including added/removed functions.
    pub matches: Vec<SemanticMatch>,
    /// Functions identified as likely renames.
    pub renames: Vec<(String, String, f64)>,
}

impl DiffReport {
    /// Build a [`DiffReport`] from a [`SemanticDiffResult`].
    #[must_use]
    pub fn from_result(result: &SemanticDiffResult, rename_threshold: f64) -> Self {
        use rustre_diff::MatchKind;

        let binary_a = result.base.name_a.clone();
        let binary_b = result.base.name_b.clone();

        let mut added = 0usize;
        let mut removed = 0usize;
        let mut modified = 0usize;
        let mut identical = 0usize;

        for sm in &result.semantic_matches {
            match sm.func_match.kind {
                MatchKind::Added => added += 1,
                MatchKind::Removed => removed += 1,
                MatchKind::Identical => identical += 1,
                MatchKind::Similar | MatchKind::Renamed => modified += 1,
            }
        }

        let heuristic = FunctionRenameHeuristic::new(rename_threshold);
        let renames: Vec<(String, String, f64)> = heuristic
            .find_renames(&result.semantic_matches)
            .into_iter()
            .filter_map(|sm| {
                let a = sm.func_match.primary.as_ref()?.name.clone();
                let b = sm.func_match.secondary.as_ref()?.name.clone();
                Some((a, b, sm.semantic_similarity))
            })
            .collect();

        let funcs_in_a = removed + modified + identical;
        let funcs_in_b = added + modified + identical;

        let stats = DiffStats {
            funcs_in_a,
            funcs_in_b,
            added,
            removed,
            modified,
            identical,
            mean_semantic_similarity: result.feature_similarity,
        };

        Self {
            binary_a,
            binary_b,
            stats,
            matches: result.semantic_matches.clone(),
            renames,
        }
    }

    /// Returns `true` if the two binaries appear functionally identical
    /// (no added, removed, or modified functions).
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.stats.added == 0 && self.stats.removed == 0 && self.stats.modified == 0
    }

    /// Return only the modified matches (Similar or Renamed pairs).
    #[must_use]
    pub fn modified_matches(&self) -> Vec<&SemanticMatch> {
        use rustre_diff::MatchKind;
        self.matches
            .iter()
            .filter(|m| matches!(m.func_match.kind, MatchKind::Similar | MatchKind::Renamed))
            .collect()
    }
}

impl std::fmt::Display for DiffReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DiffReport [{} vs {}] +{} -{} ~{} ={} renames={}",
            self.binary_a,
            self.binary_b,
            self.stats.added,
            self.stats.removed,
            self.stats.modified,
            self.stats.identical,
            self.renames.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// BinarySemanticDiff  (high-level entry point)
// ---------------------------------------------------------------------------

/// High-level entry point that combines [`SemanticDiffEngine`], [`MinHash`],
/// [`LshIndex`], and [`DiffReport`] into a single workflow.
pub struct BinarySemanticDiff {
    engine: SemanticDiffEngine,
    minhash: MinHash,
    rename_threshold: f64,
}

impl BinarySemanticDiff {
    /// Create a new [`BinarySemanticDiff`] with default parameters.
    ///
    /// Uses 128 `MinHash` functions and a 0.8 rename threshold.
    #[must_use]
    pub fn new() -> Self {
        Self {
            engine: SemanticDiffEngine::new(),
            minhash: MinHash::new(128),
            rename_threshold: 0.8,
        }
    }

    /// Create a [`BinarySemanticDiff`] with custom parameters.
    #[must_use]
    pub fn with_params(num_hashes: usize, rename_threshold: f64) -> Self {
        Self {
            engine: SemanticDiffEngine::new(),
            minhash: MinHash::new(num_hashes),
            rename_threshold,
        }
    }

    /// Build an [`LshIndex`] from a set of feature vectors.
    ///
    /// Returns the index and a mapping `address → signature`.
    #[must_use]
    pub fn build_lsh_index(
        &self,
        features: &[SemanticFeatures],
    ) -> (LshIndex, HashMap<u64, Vec<u64>>) {
        let mut index = LshIndex::new(16, 8);
        let mut sigs: HashMap<u64, Vec<u64>> = HashMap::new();
        for feat in features {
            let elements = self.feature_to_elements(feat);
            let sig = self.minhash.signature(&elements);
            index.insert(feat.address, &sig);
            sigs.insert(feat.address, sig);
        }
        (index, sigs)
    }

    /// Maximum number of elements taken from `constant_pool` or `call_sites` when
    /// building the `MinHash` element set. Prevents memory exhaustion when these
    /// vecs are themselves large (dos-memory-exhaustion).
    const MAX_ELEMENTS_PER_FIELD: usize = 65_536;

    /// Convert a [`SemanticFeatures`] vector to a set of `u64` elements for `MinHash`.
    #[must_use]
    fn feature_to_elements(&self, feat: &SemanticFeatures) -> Vec<u64> {
        let mut elements: Vec<u64> = Vec::new();
        // Encode mnemonic histogram: hash each (mnemonic, count) pair.
        for (mn, &cnt) in &feat.mnemonic_histogram {
            let h = simple_hash(mn.as_bytes()).wrapping_add(u64::from(cnt));
            elements.push(h);
        }
        // Cap constant_pool and call_sites to avoid unbounded Vec growth when
        // processing large or adversarially crafted binaries.
        let pool = feat.constant_pool.get(..feat.constant_pool.len().min(Self::MAX_ELEMENTS_PER_FIELD)).unwrap_or(&feat.constant_pool);
        let sites = feat.call_sites.get(..feat.call_sites.len().min(Self::MAX_ELEMENTS_PER_FIELD)).unwrap_or(&feat.call_sites);
        elements.extend_from_slice(pool);
        elements.extend_from_slice(sites);
        elements.push(u64::from(feat.branch_count) << 32 | u64::from(feat.loop_count));
        elements.sort_unstable();
        elements.dedup();
        elements
    }

    /// Run a full diff and produce a [`DiffReport`].
    ///
    /// # Errors
    ///
    /// Returns [`SemanticDiffError`] if the underlying diff fails.
    pub fn diff(
        &self,
        feats_a: Vec<SemanticFeatures>,
        feats_b: Vec<SemanticFeatures>,
        name_a: String,
        name_b: String,
    ) -> Result<DiffReport, SemanticDiffError> {
        let result = self
            .engine
            .diff_with_features(feats_a, feats_b, name_a, name_b)?;
        Ok(DiffReport::from_result(&result, self.rename_threshold))
    }
}

impl Default for BinarySemanticDiff {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for BinarySemanticDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BinarySemanticDiff(num_hashes={}, rename_threshold={})",
            self.minhash.num_hashes, self.rename_threshold
        )
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Simple 64-bit FNV-1a hash for byte slices.
fn simple_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ---------------------------------------------------------------------------
// §16.3  SemanticSignature – low-level per-function signature computed
//        directly from raw function bytes (no Instruction abstraction needed).
// ---------------------------------------------------------------------------

/// A lightweight semantic signature computed from raw function bytes.
///
/// Designed for fast comparison of two binary versions of the same function,
/// independent of load address or minor compiler variations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticSignature {
    /// Virtual address of the function in its parent binary.
    pub function_addr: u64,
    /// Total number of decoded instructions (1-byte opcode walk).
    pub instruction_count: u32,
    /// Number of CALL instructions detected (FF /2 or E8 patterns).
    pub call_count: u32,
    /// Unique 64-bit immediate constants found in the byte stream.
    pub unique_constants: Vec<u64>,
    /// String references embedded in the function bytes (UTF-8 substrings ≥4 chars).
    pub string_refs: Vec<String>,
    /// FNV-1a hash of a simplified CFG edge sequence.
    pub cfg_hash: u64,
    /// Frequency map: mnemonic-group string → occurrence count.
    pub mnemonic_histogram: HashMap<String, u32>,
}

impl SemanticSignature {
    /// Compute a [`SemanticSignature`] from raw `func_bytes` located at `base_addr`.
    ///
    /// The disassembly is intentionally simplified: the byte stream is walked
    /// using a small fixed-length table so that no external disassembler crate
    /// is required. This keeps the function self-contained while still
    /// capturing the most semantically significant features.
    #[must_use]
    pub fn compute(func_bytes: &[u8], base_addr: u64) -> Self {
        let mut instruction_count: u32 = 0;
        let mut call_count: u32 = 0;
        let mut mnemonic_histogram: HashMap<String, u32> = HashMap::new();
        let mut unique_constants: Vec<u64> = Vec::new();
        // CFG: record (offset, taken-offset) pairs for branch instructions.
        // Capped at 65_536 edges to prevent dos-memory-exhaustion from crafted input.
        let mut cfg_edges: Vec<(u32, u32)> = Vec::new();

        let mut i = 0usize;
        while i < func_bytes.len() {
            // Consume any REX prefix bytes (0x40–0x4F) in 64-bit x86 before
            // dispatching on the actual opcode byte. REX bytes are not
            // instructions; treating them as INC/DEC would desynchronise the
            // byte walker for the rest of the function.
            let mut rex_skip = 0usize;
            while i + rex_skip < func_bytes.len()
                && (0x40..=0x4F).contains(&func_bytes[i + rex_skip])
            {
                rex_skip += 1;
            }
            let opcode_offset = i + rex_skip;
            if opcode_offset >= func_bytes.len() {
                i = opcode_offset + 1;
                continue;
            }
            let byte = func_bytes[opcode_offset];
            let (mnemonic, advance, imm_bytes, is_call, is_branch, branch_rel) =
                classify_byte(byte, func_bytes, opcode_offset);
            // Total advance includes the REX prefix byte(s) plus the opcode+operands length.
            let total_advance = rex_skip + advance;

            instruction_count += 1;
            *mnemonic_histogram.entry(mnemonic.to_string()).or_insert(0) += 1;

            if is_call {
                call_count += 1;
            }
            if is_branch
                && let Some(rel) = branch_rel {
                    let src = i as u32;
                    // Use saturating arithmetic to avoid wrapping a branch target into a
                    // bogus offset when `rel` is large-negative or `i + advance` overflows.
                    let dst_i64 = (i as i64)
                        .saturating_add(advance as i64)
                        .saturating_add(i64::from(rel));
                    // Clamp negative or out-of-range destinations to 0; they won't match any
                    // real offset but at least won't produce a misleading u32 by truncation.
                    let dst = u32::try_from(dst_i64).unwrap_or(0);
                    // Cap cfg_edges to bound memory (dos-memory-exhaustion).
                    if cfg_edges.len() < 65_536 {
                        cfg_edges.push((src, dst));
                    }
                }

            // Extract immediate values (1, 2, 4, or 8 bytes following opcode).
            // Use `opcode_offset + 1` so that REX prefix bytes are skipped correctly.
            // Cap collected constants to 65_536 to prevent memory exhaustion on
            // crafted/large binaries (dos-memory-exhaustion).
            if imm_bytes > 0
                && opcode_offset + 1 + imm_bytes <= func_bytes.len()
                && unique_constants.len() < 65_536
            {
                let imm = read_imm(&func_bytes[opcode_offset + 1..opcode_offset + 1 + imm_bytes], imm_bytes);
                // Filter out tiny constants (0-3) and address-like values near base.
                if imm > 3 {
                    unique_constants.push(imm);
                }
            }

            i += total_advance.max(1);
        }

        // Deduplicate constants.
        unique_constants.sort_unstable();
        unique_constants.dedup();

        // Build CFG hash from sorted edge list.
        let cfg_hash = hash_cfg_edges(&cfg_edges);

        // Extract printable ASCII runs as string references.
        let string_refs = extract_string_refs(func_bytes);

        Self {
            function_addr: base_addr,
            instruction_count,
            call_count,
            unique_constants,
            string_refs,
            cfg_hash,
            mnemonic_histogram,
        }
    }
}

impl fmt::Display for SemanticSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SemanticSignature[@{:#x}] instrs={} calls={} consts={} cfg_hash={:#x}",
            self.function_addr,
            self.instruction_count,
            self.call_count,
            self.unique_constants.len(),
            self.cfg_hash,
        )
    }
}

// ---------------------------------------------------------------------------
// §16.3  SemanticMatcher
// ---------------------------------------------------------------------------

/// Stateless comparator for [`SemanticSignature`] pairs.
pub struct SemanticMatcher;

impl SemanticMatcher {
    /// Weighted similarity score in `[0.0, 1.0]` between two signatures.
    ///
    /// | Component                   | Weight |
    /// |-----------------------------|--------|
    /// | instruction_count ratio     | 0.20   |
    /// | call_count match            | 0.15   |
    /// | constants Jaccard           | 0.25   |
    /// | string_refs Jaccard         | 0.25   |
    /// | mnemonic histogram cosine   | 0.15   |
    #[must_use]
    pub fn similarity(a: &SemanticSignature, b: &SemanticSignature) -> f32 {
        let instr_ratio = ratio_similarity(
            u64::from(a.instruction_count),
            u64::from(b.instruction_count),
        ) as f32;

        let call_ratio = ratio_similarity(u64::from(a.call_count), u64::from(b.call_count)) as f32;

        let const_jacc = jaccard_u64(&a.unique_constants, &b.unique_constants);

        let str_jacc = jaccard_strings(&a.string_refs, &b.string_refs);

        let hist_cos =
            mnemonic_cosine_similarity(&a.mnemonic_histogram, &b.mnemonic_histogram) as f32;

        0.15f32.mul_add(hist_cos, 0.25f32.mul_add(str_jacc, 0.25f32.mul_add(const_jacc, 0.20f32.mul_add(instr_ratio, 0.15 * call_ratio))))
    }

    /// Returns `true` when two signatures are semantically equivalent
    /// (similarity > 0.85).
    #[must_use]
    pub fn are_equivalent(a: &SemanticSignature, b: &SemanticSignature) -> bool {
        Self::similarity(a, b) > 0.85
    }
}

// ---------------------------------------------------------------------------
// §16.3  FunctionDiff
// ---------------------------------------------------------------------------

/// Detailed diff between two versions of the same function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDiff {
    /// Address of the function in binary A.
    pub addr_a: u64,
    /// Address of the function in binary B.
    pub addr_b: u64,
    /// Overall similarity score `[0.0, 1.0]`.
    pub similarity: f32,
    /// Whether the two functions are considered semantically equivalent.
    pub is_equivalent: bool,
    /// Call targets present in B but absent in A (by relative offset).
    pub added_calls: Vec<u64>,
    /// Call targets present in A but absent in B (by relative offset).
    pub removed_calls: Vec<u64>,
    /// Constants present in B but absent in A.
    pub added_constants: Vec<u64>,
    /// Constants present in A but absent in B.
    pub removed_constants: Vec<u64>,
    /// Human-readable summary of the diff.
    pub description: String,
}

impl FunctionDiff {
    /// Build a textual description of the diff.
    fn make_description(
        similarity: f32,
        is_equivalent: bool,
        added_calls: &[u64],
        removed_calls: &[u64],
        added_constants: &[u64],
        removed_constants: &[u64],
    ) -> String {
        if is_equivalent {
            return format!("Equivalent (similarity={similarity:.2})");
        }
        let mut parts = Vec::new();
        if !added_calls.is_empty() {
            parts.push(format!("{} call(s) added", added_calls.len()));
        }
        if !removed_calls.is_empty() {
            parts.push(format!("{} call(s) removed", removed_calls.len()));
        }
        if !added_constants.is_empty() {
            parts.push(format!("{} constant(s) added", added_constants.len()));
        }
        if !removed_constants.is_empty() {
            parts.push(format!("{} constant(s) removed", removed_constants.len()));
        }
        if parts.is_empty() {
            format!("Changed (similarity={similarity:.2})")
        } else {
            format!(
                "Changed (similarity={:.2}): {}",
                similarity,
                parts.join(", ")
            )
        }
    }
}

impl fmt::Display for FunctionDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FunctionDiff[{:#x} ↔ {:#x}] sim={:.2} equiv={} | {}",
            self.addr_a, self.addr_b, self.similarity, self.is_equivalent, self.description
        )
    }
}

// ---------------------------------------------------------------------------
// §16.3  SemanticDiffReport
// ---------------------------------------------------------------------------

/// Top-level report produced by [`SemanticDiffer::diff_binaries`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticDiffReport {
    /// Pairs of functions that are semantically equivalent across versions.
    pub matched_pairs: Vec<FunctionDiff>,
    /// Pairs of functions that are similar but have measurable differences.
    pub changed_pairs: Vec<FunctionDiff>,
    /// Functions present in binary B but not in A.
    pub added_funcs: Vec<u64>,
    /// Functions present in binary A but not in B.
    pub removed_funcs: Vec<u64>,
    /// Overall binary similarity score `[0.0, 1.0]`.
    pub similarity_score: f32,
}

impl SemanticDiffReport {
    /// Total number of function pairs examined.
    #[must_use]
    pub const fn total_pairs(&self) -> usize {
        self.matched_pairs.len() + self.changed_pairs.len()
    }
}

impl fmt::Display for SemanticDiffReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SemanticDiffReport: matched={} changed={} added={} removed={} score={:.2}",
            self.matched_pairs.len(),
            self.changed_pairs.len(),
            self.added_funcs.len(),
            self.removed_funcs.len(),
            self.similarity_score,
        )
    }
}

// ---------------------------------------------------------------------------
// §16.3  SemanticDiffer
// ---------------------------------------------------------------------------

/// Stateless differ that operates on raw function bytes.
pub struct SemanticDiffer;

impl SemanticDiffer {
    /// Diff two raw function byte slices and return a [`FunctionDiff`].
    #[must_use]
    pub fn diff_function_pair(
        bytes_a: &[u8],
        base_a: u64,
        bytes_b: &[u8],
        base_b: u64,
    ) -> FunctionDiff {
        let sig_a = SemanticSignature::compute(bytes_a, base_a);
        let sig_b = SemanticSignature::compute(bytes_b, base_b);

        let similarity = SemanticMatcher::similarity(&sig_a, &sig_b);
        let is_equivalent = SemanticMatcher::are_equivalent(&sig_a, &sig_b);

        // Compute set differences for calls (stored as relative offsets from base).
        let calls_a = collect_call_offsets(bytes_a);
        let calls_b = collect_call_offsets(bytes_b);
        let added_calls = set_diff_sorted(&calls_b, &calls_a);
        let removed_calls = set_diff_sorted(&calls_a, &calls_b);

        // Constant deltas.
        let added_constants = set_diff_sorted(&sig_b.unique_constants, &sig_a.unique_constants);
        let removed_constants = set_diff_sorted(&sig_a.unique_constants, &sig_b.unique_constants);

        let description = FunctionDiff::make_description(
            similarity,
            is_equivalent,
            &added_calls,
            &removed_calls,
            &added_constants,
            &removed_constants,
        );

        FunctionDiff {
            addr_a: base_a,
            addr_b: base_b,
            similarity,
            is_equivalent,
            added_calls,
            removed_calls,
            added_constants,
            removed_constants,
            description,
        }
    }

    /// Diff two sets of `(address, bytes)` function pairs.
    ///
    /// Matching is done by pairing functions in order of address. Functions
    /// present in only one binary are recorded as added/removed.
    #[must_use]
    pub fn diff_binaries(
        funcs_a: &[(u64, Vec<u8>)],
        funcs_b: &[(u64, Vec<u8>)],
    ) -> SemanticDiffReport {
        // Build address-keyed maps.
        let map_a: HashMap<u64, &Vec<u8>> = funcs_a.iter().map(|(a, b)| (*a, b)).collect();
        let map_b: HashMap<u64, &Vec<u8>> = funcs_b.iter().map(|(a, b)| (*a, b)).collect();

        // Determine added / removed.
        let addrs_a: std::collections::BTreeSet<u64> = map_a.keys().copied().collect();
        let addrs_b: std::collections::BTreeSet<u64> = map_b.keys().copied().collect();

        let added_funcs: Vec<u64> = addrs_b.difference(&addrs_a).copied().collect();
        let removed_funcs: Vec<u64> = addrs_a.difference(&addrs_b).copied().collect();
        let common: Vec<u64> = addrs_a.intersection(&addrs_b).copied().collect();

        let mut matched_pairs: Vec<FunctionDiff> = Vec::new();
        let mut changed_pairs: Vec<FunctionDiff> = Vec::new();

        for addr in &common {
            let bytes_a = map_a[addr];
            let bytes_b = map_b[addr];
            let diff = Self::diff_function_pair(bytes_a, *addr, bytes_b, *addr);
            if diff.is_equivalent {
                matched_pairs.push(diff);
            } else {
                changed_pairs.push(diff);
            }
        }

        // Compute overall similarity score.
        let total = common.len() + added_funcs.len() + removed_funcs.len();
        let similarity_score = if total == 0 {
            1.0f32
        } else {
            let matched_weight: f32 = matched_pairs.iter().map(|d| d.similarity).sum::<f32>()
                + changed_pairs.iter().map(|d| d.similarity).sum::<f32>();
            matched_weight / total as f32
        };

        SemanticDiffReport {
            matched_pairs,
            changed_pairs,
            added_funcs,
            removed_funcs,
            similarity_score,
        }
    }
}

// ---------------------------------------------------------------------------
// §16.3  PatchAnalysis – CVE / security patch diffing
// ---------------------------------------------------------------------------

/// Result of analysing a patch applied between two binary versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchAnalysisResult {
    /// Functions that changed between the two versions (by address as hex strings).
    pub changed_functions: Vec<String>,
    /// Descriptions of changes that appear security-relevant.
    pub security_relevant_changes: Vec<String>,
    /// New checks or validations inferred to have been added in the patch.
    pub added_checks: Vec<String>,
    /// Code (calls, constants) removed in the patched version.
    pub removed_code: Vec<String>,
}

/// Utilities for CVE / security patch analysis built on top of [`SemanticDiffReport`].
pub struct PatchAnalysis;

impl PatchAnalysis {
    /// Analyse a patch by comparing a diff taken *before* the fix with one
    /// taken *after* the fix.
    ///
    /// `before` — diff of the pre-patch binary against a reference.
    /// `after`  — diff of the post-patch binary against the same reference.
    #[must_use]
    pub fn analyze_patch(
        before: &SemanticDiffReport,
        after: &SemanticDiffReport,
    ) -> PatchAnalysisResult {
        // Functions that were equivalent before but changed after.
        let before_equiv_addrs: std::collections::HashSet<u64> =
            before.matched_pairs.iter().map(|d| d.addr_a).collect();
        let after_changed_addrs: std::collections::HashSet<u64> =
            after.changed_pairs.iter().map(|d| d.addr_a).collect();

        let changed_functions: Vec<String> = before_equiv_addrs
            .intersection(&after_changed_addrs)
            .map(|a| format!("{a:#x}"))
            .collect();

        let mut security_relevant_changes: Vec<String> = Vec::new();
        let mut added_checks: Vec<String> = Vec::new();
        let mut removed_code: Vec<String> = Vec::new();

        for diff in &after.changed_pairs {
            // Heuristic: added calls suggest new validation/check functions.
            if !diff.added_calls.is_empty() {
                for &offset in &diff.added_calls {
                    added_checks.push(format!(
                        "fn {:#x}: new call at offset {:#x}",
                        diff.addr_a, offset
                    ));
                    security_relevant_changes.push(format!(
                        "fn {:#x}: added call (possible bounds check or sanitiser)",
                        diff.addr_a
                    ));
                }
            }

            // Heuristic: added constants near powers-of-two suggest size limits.
            for &c in &diff.added_constants {
                if c.is_power_of_two() || c == 0xFFFF || c == 0xFFFF_FFFF {
                    security_relevant_changes.push(format!(
                        "fn {:#x}: added security-relevant constant {:#x}",
                        diff.addr_a, c
                    ));
                    added_checks.push(format!(
                        "fn {:#x}: boundary constant {:#x} introduced",
                        diff.addr_a, c
                    ));
                }
            }

            // Removed calls or constants.
            if !diff.removed_calls.is_empty() {
                removed_code.push(format!(
                    "fn {:#x}: {} call(s) removed",
                    diff.addr_a,
                    diff.removed_calls.len()
                ));
            }
            for &c in &diff.removed_constants {
                removed_code.push(format!("fn {:#x}: constant {:#x} removed", diff.addr_a, c));
            }

            // Large similarity drop is suspicious.
            let before_sim = before
                .matched_pairs
                .iter()
                .find(|d| d.addr_a == diff.addr_a)
                .map_or(1.0, |d| d.similarity);
            if before_sim - diff.similarity > 0.3 {
                security_relevant_changes.push(format!(
                    "fn {:#x}: significant similarity drop {:.2} → {:.2} (likely security fix)",
                    diff.addr_a, before_sim, diff.similarity
                ));
            }
        }

        // Functions added entirely in the after-patch version may be new helpers.
        for &addr in &after.added_funcs {
            security_relevant_changes.push(format!(
                "fn {addr:#x}: newly introduced in patched binary"
            ));
        }

        // Functions removed may indicate dead-code removal or mitigation.
        for &addr in &after.removed_funcs {
            removed_code.push(format!("fn {addr:#x}: removed in patched binary"));
        }

        PatchAnalysisResult {
            changed_functions,
            security_relevant_changes,
            added_checks,
            removed_code,
        }
    }

    /// Generate a concise, human-readable summary of a [`SemanticDiffReport`].
    #[must_use]
    pub fn summarize_changes(diff: &SemanticDiffReport) -> String {
        let mut lines: Vec<String> = Vec::new();
        lines.push(format!(
            "Binary similarity: {:.1}%",
            diff.similarity_score * 100.0
        ));
        lines.push(format!(
            "Functions: {} equivalent, {} changed, {} added, {} removed",
            diff.matched_pairs.len(),
            diff.changed_pairs.len(),
            diff.added_funcs.len(),
            diff.removed_funcs.len(),
        ));

        if !diff.changed_pairs.is_empty() {
            lines.push("Changed functions:".to_string());
            for d in &diff.changed_pairs {
                lines.push(format!("  [{:#x}] {}", d.addr_a, d.description));
            }
        }
        if !diff.added_funcs.is_empty() {
            let addrs: Vec<String> = diff
                .added_funcs
                .iter()
                .map(|a| format!("{a:#x}"))
                .collect();
            lines.push(format!("Added:   {}", addrs.join(", ")));
        }
        if !diff.removed_funcs.is_empty() {
            let addrs: Vec<String> = diff
                .removed_funcs
                .iter()
                .map(|a| format!("{a:#x}"))
                .collect();
            lines.push(format!("Removed: {}", addrs.join(", ")));
        }

        lines.join("\n")
    }
}

// ---------------------------------------------------------------------------
// Internal helpers for SemanticSignature / SemanticDiffer
// ---------------------------------------------------------------------------

/// Very small fixed-length table for x86-like byte classification.
///
/// Returns `(mnemonic_group, advance, imm_bytes, is_call, is_branch, branch_rel_i32)`.
/// `advance` is the total instruction length (opcode + operand bytes).
/// `branch_rel` is `Some(rel)` for relative branch instructions.
fn classify_byte(
    byte: u8,
    bytes: &[u8],
    offset: usize,
) -> (&'static str, usize, usize, bool, bool, Option<i32>) {
    match byte {
        // CALL rel32
        0xE8 => {
            let rel = read_i32_le(bytes, offset + 1);
            ("CALL", 5, 4, true, false, Some(rel))
        }
        // CALL/JMP r/m  (FF /2 = call, FF /4 = jmp near)
        0xFF => {
            let modrm = bytes.get(offset + 1).copied().unwrap_or(0);
            let reg = (modrm >> 3) & 0x7;
            let is_call = reg == 2;
            ("CALL_IND", 2, 0, is_call, reg == 4, None)
        }
        // JMP rel8
        0xEB => {
            let rel = i32::from(bytes.get(offset + 1).copied().unwrap_or(0) as i8);
            ("JMP", 2, 0, false, true, Some(rel))
        }
        // JMP rel32
        0xE9 => {
            let rel = read_i32_le(bytes, offset + 1);
            ("JMP", 5, 0, false, true, Some(rel))
        }
        // Jcc rel8  (0x70..=0x7F)
        0x70..=0x7F => {
            let rel = i32::from(bytes.get(offset + 1).copied().unwrap_or(0) as i8);
            ("JCC8", 2, 0, false, true, Some(rel))
        }
        // Jcc rel32 prefix 0F 8x
        0x0F => {
            let next = bytes.get(offset + 1).copied().unwrap_or(0);
            if (0x80..=0x8F).contains(&next) {
                let rel = read_i32_le(bytes, offset + 2);
                ("JCC32", 6, 0, false, true, Some(rel))
            } else {
                ("PREFIX", 2, 0, false, false, None)
            }
        }
        // PUSH imm8
        0x6A => ("PUSH", 2, 1, false, false, None),
        // PUSH imm32
        0x68 => ("PUSH", 5, 4, false, false, None),
        // MOV r/m, imm32  (C7 /0)
        0xC7 => ("MOV", 6, 4, false, false, None),
        // MOV r8, imm8   (B0..=B7)
        0xB0..=0xB7 => ("MOV", 2, 1, false, false, None),
        // MOV r32/64, imm32  (B8..=BF)
        0xB8..=0xBF => ("MOV", 5, 4, false, false, None),
        // ADD/SUB/CMP r/m32, imm32
        0x81 => ("ALU32", 6, 4, false, false, None),
        // ADD/SUB/CMP r/m32, imm8
        0x83 => ("ALU8", 3, 1, false, false, None),
        // TEST r/m, imm32
        0xF7 => ("TEST", 6, 4, false, false, None),
        // AND/OR/XOR r/m, r
        0x21 | 0x23 | 0x09 | 0x0B | 0x31 | 0x33 => ("LOGIC", 2, 0, false, false, None),
        // ADD/SUB/CMP r/m, r
        0x01 | 0x03 | 0x29 | 0x2B | 0x39 | 0x3B => ("ALU", 2, 0, false, false, None),
        // MOV r/m, r
        0x89 | 0x8B => ("MOV", 2, 0, false, false, None),
        // RET
        0xC3 | 0xC2 => ("RET", 1, 0, false, false, None),
        // NOP
        0x90 => ("NOP", 1, 0, false, false, None),
        // PUSH r (50..=57)
        0x50..=0x57 => ("PUSH", 1, 0, false, false, None),
        // POP r (58..=5F)
        0x58..=0x5F => ("POP", 1, 0, false, false, None),
        // LEA r, m
        0x8D => ("LEA", 6, 4, false, false, None),
        // CMP r/m8, imm8
        0x80 => ("CMP8", 3, 1, false, false, None),
        // XOR r8, r8 / AND r8, r8
        0x32 | 0x22 => ("LOGIC8", 2, 0, false, false, None),
        // In 64-bit x86 these are REX prefix bytes and are handled by the
        // caller loop before classify_byte is called. If reached here (e.g. in
        // 32-bit code) treat as legacy INC/DEC r32.
        0x40..=0x4F => ("INCDEC", 1, 0, false, false, None),
        // Default: treat as 1-byte opcode, no operands.
        _ => ("OTHER", 1, 0, false, false, None),
    }
}

/// Read a little-endian `i32` from `bytes[offset..]`, returning 0 on underrun.
fn read_i32_le(bytes: &[u8], offset: usize) -> i32 {
    if offset + 4 > bytes.len() {
        return 0;
    }
    i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Read `n` bytes as a little-endian `u64`.
fn read_imm(bytes: &[u8], n: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..n.min(8).min(bytes.len()) {
        v |= u64::from(bytes[i]) << (8 * i);
    }
    v
}

/// Hash a list of CFG edges (`src_offset`, `dst_offset`) using FNV-1a.
fn hash_cfg_edges(edges: &[(u32, u32)]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &(src, dst) in edges {
        h ^= u64::from(src);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        h ^= u64::from(dst);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Maximum number of string references extracted from a single function body.
///
/// Caps memory consumption when processing large or crafted binaries
/// (dos-memory-exhaustion: attacker could produce millions of 4-byte ASCII runs).
const MAX_STRING_REFS: usize = 4_096;

/// Extract printable ASCII substrings of length ≥4 from a byte slice.
fn extract_string_refs(bytes: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut run = Vec::new();
    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' {
            run.push(b);
        } else {
            if run.len() >= 4
                && result.len() < MAX_STRING_REFS
                && let Ok(s) = std::str::from_utf8(&run) {
                    result.push(s.to_string());
                }
            run.clear();
        }
    }
    if run.len() >= 4
        && result.len() < MAX_STRING_REFS
        && let Ok(s) = std::str::from_utf8(&run) {
            result.push(s.to_string());
        }
    result.sort();
    result.dedup();
    result
}

/// Maximum number of call offsets tracked per function body.
///
/// Prevents unbounded Vec growth when scanning crafted binaries that contain
/// millions of 0xE8 bytes (dos-memory-exhaustion).
const MAX_CALL_OFFSETS: usize = 65_536;

/// Collect relative call offsets (byte positions of CALL E8 xx instructions).
fn collect_call_offsets(bytes: &[u8]) -> Vec<u64> {
    let mut offsets = Vec::new();
    let mut i = 0;
    while i < bytes.len() && offsets.len() < MAX_CALL_OFFSETS {
        if bytes[i] == 0xE8 && i + 5 <= bytes.len() {
            offsets.push(i as u64);
            i += 5;
        } else if bytes[i] == 0xFF && i + 2 <= bytes.len() && ((bytes[i + 1] >> 3) & 7) == 2 {
            offsets.push(i as u64);
            i += 2;
        } else {
            i += 1;
        }
    }
    offsets.sort_unstable();
    offsets
}

/// Jaccard similarity between two sorted, deduplicated `u64` slices.
fn jaccard_u64(a: &[u64], b: &[u64]) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let mut inter = 0usize;
    let (mut ia, mut ib) = (0usize, 0usize);
    while ia < a.len() && ib < b.len() {
        match a[ia].cmp(&b[ib]) {
            std::cmp::Ordering::Equal => {
                inter += 1;
                ia += 1;
                ib += 1;
            }
            std::cmp::Ordering::Less => ia += 1,
            std::cmp::Ordering::Greater => ib += 1,
        }
    }
    let union = a.len() + b.len() - inter;
    if union == 0 {
        1.0
    } else {
        inter as f32 / union as f32
    }
}

/// Jaccard similarity between two string slices (sorted, deduped assumed).
fn jaccard_strings(a: &[String], b: &[String]) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let set_a: std::collections::HashSet<&str> = a.iter().map(String::as_str).collect();
    let set_b: std::collections::HashSet<&str> = b.iter().map(String::as_str).collect();
    let inter = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        1.0
    } else {
        inter as f32 / union as f32
    }
}

/// Set difference: elements in `a` that are not in `b` (both sorted).
fn set_diff_sorted(a: &[u64], b: &[u64]) -> Vec<u64> {
    let set_b: std::collections::HashSet<u64> = b.iter().copied().collect();
    a.iter().copied().filter(|x| !set_b.contains(x)).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::{address::Address, arch::InstrFlags};
    use rustre_diff::MatchKind;

    fn make_instr(addr: u64, mnemonic: &str, operands: &str, flags: InstrFlags) -> Instruction {
        let mut instr = Instruction::new(Address::new(addr), 4, mnemonic, vec![0x90; 4]);
        instr.operands = operands.to_string();
        instr.flags = flags;
        instr
    }

    fn simple_feature(addr: u64, name: &str) -> SemanticFeatures {
        let instrs = vec![
            make_instr(addr, "PUSH", "rbp", InstrFlags::NONE),
            make_instr(addr + 1, "MOV", "rbp, rsp", InstrFlags::NONE),
            make_instr(addr + 2, "ADD", "rax, 0x10", InstrFlags::NONE),
            make_instr(addr + 3, "RET", "", InstrFlags::RET),
        ];
        SemanticFeatures::from_instructions(addr, name.to_string(), &instrs)
    }

    // ---- SemanticFeatures --------------------------------------------------

    #[test]
    fn test_features_from_instructions_empty() {
        let f = SemanticFeatures::from_instructions(0x1000, "empty".to_string(), &[]);
        assert_eq!(f.branch_count, 0);
        assert_eq!(f.arithmetic_ops, 0);
        assert_eq!(f.feature_count(), 0);
    }

    #[test]
    fn test_features_arithmetic_detected() {
        let instrs = vec![
            make_instr(0x1000, "ADD", "eax, 1", InstrFlags::NONE),
            make_instr(0x1004, "SUB", "ecx, eax", InstrFlags::NONE),
            make_instr(0x1008, "MUL", "ebx", InstrFlags::NONE),
        ];
        let f = SemanticFeatures::from_instructions(0x1000, "arith".to_string(), &instrs);
        assert_eq!(f.arithmetic_ops, 3);
    }

    #[test]
    fn test_features_branch_detected() {
        let instrs = vec![make_instr(
            0x1000,
            "JNZ",
            "0x1000",
            InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
        )];
        let f = SemanticFeatures::from_instructions(0x1010, "branch".to_string(), &instrs);
        assert_eq!(f.branch_count, 1);
    }

    #[test]
    fn test_features_call_detected() {
        let instrs = vec![make_instr(0x1000, "CALL", "0x2000", InstrFlags::CALL)];
        let f = SemanticFeatures::from_instructions(0x1000, "calls".to_string(), &instrs);
        assert_eq!(f.call_sites.len(), 1);
    }

    #[test]
    fn test_features_memory_ops() {
        let instrs = vec![
            make_instr(0x1000, "MOV", "[rbp-4], eax", InstrFlags::WRITE_MEM),
            make_instr(0x1004, "MOV", "eax, [rbp-4]", InstrFlags::READ_MEM),
        ];
        let f = SemanticFeatures::from_instructions(0x1000, "mem".to_string(), &instrs);
        assert_eq!(f.memory_ops, 2);
    }

    #[test]
    fn test_features_constant_extraction() {
        let instrs = vec![make_instr(0x1000, "MOV", "eax, 0x1234", InstrFlags::NONE)];
        let f = SemanticFeatures::from_instructions(0x1000, "const".to_string(), &instrs);
        assert!(f.constant_pool.contains(&0x1234));
    }

    #[test]
    fn test_features_mnemonic_histogram() {
        let instrs = vec![
            make_instr(0x1000, "NOP", "", InstrFlags::NONE),
            make_instr(0x1001, "NOP", "", InstrFlags::NONE),
            make_instr(0x1002, "RET", "", InstrFlags::RET),
        ];
        let f = SemanticFeatures::from_instructions(0x1000, "nops".to_string(), &instrs);
        assert_eq!(f.mnemonic_histogram["NOP"], 2);
        assert_eq!(f.mnemonic_histogram["RET"], 1);
    }

    #[test]
    fn test_features_display() {
        let f = simple_feature(0x1000, "test_fn");
        let s = f.to_string();
        assert!(s.contains("test_fn"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_features_semantic_similarity_identical() {
        let f1 = simple_feature(0x1000, "f");
        let f2 = simple_feature(0x1000, "f");
        let sim = f1.semantic_similarity(&f2);
        assert!((0.9..=1.01).contains(&sim));
    }

    #[test]
    fn test_features_semantic_similarity_different() {
        let instrs_a: Vec<Instruction> = (0..10)
            .map(|i| make_instr(0x1000 + i, "ADD", "eax, 1", InstrFlags::NONE))
            .collect();
        let instrs_b: Vec<Instruction> = (0..5)
            .map(|i| make_instr(0x2000 + i, "RET", "", InstrFlags::RET))
            .collect();
        let a = SemanticFeatures::from_instructions(0x1000, "a".to_string(), &instrs_a);
        let b = SemanticFeatures::from_instructions(0x2000, "b".to_string(), &instrs_b);
        let sim = a.semantic_similarity(&b);
        assert!(sim < 0.9);
    }

    #[test]
    fn test_features_semantic_similarity_range() {
        let a = simple_feature(0x1000, "a");
        let b = simple_feature(0x2000, "b");
        let sim = a.semantic_similarity(&b);
        assert!((0.0..=1.0).contains(&sim));
    }

    // ---- NormalizedBytes ------------------------------------------------

    #[test]
    fn test_normalized_from_fingerprint() {
        let fp = rustre_diff::FuncFingerprint::new(
            0x0040_1000,
            "func".to_string(),
            vec![0x55, 0x89, 0xe5, 0x00, 0x10, 0x40, 0x00, 0xc3],
        );
        let nf = NormalizedBytes::from_fingerprint(&fp);
        assert_eq!(nf.name, "func");
        assert_eq!(nf.original_address, 0x0040_1000);
        assert_eq!(nf.normalized_bytes.len(), fp.bytes.len());
    }

    #[test]
    fn test_normalized_display() {
        let fp = rustre_diff::FuncFingerprint::new(0x1000, "f".to_string(), vec![0x90; 8]);
        let nf = NormalizedBytes::from_fingerprint(&fp);
        let s = nf.to_string();
        assert!(s.contains("Normalized"));
        assert!(s.contains('f'));
    }

    #[test]
    fn test_structural_similarity_identical() {
        let fp = rustre_diff::FuncFingerprint::new(0x1000, "f".to_string(), vec![0x90; 20]);
        let nf = NormalizedBytes::from_fingerprint(&fp);
        let sim = nf.structural_similarity(&nf.clone());
        assert_eq!(sim, 1.0);
    }

    // ---- SemanticMatch / SemanticDiffResult --------------------------------

    #[test]
    fn test_semantic_match_display() {
        let fp = rustre_diff::FuncFingerprint::new(0, "f".to_string(), vec![]);
        let sm = SemanticMatch {
            func_match: FuncMatch::added(fp),
            semantic_similarity: 0.75,
            structural_similarity: 0.80,
            changed_features: vec!["branch_count: 2 → 3".to_string()],
        };
        let s = sm.to_string();
        assert!(s.contains("0.75"));
        assert!(s.contains("0.80"));
    }

    #[test]
    fn test_semantic_diff_result_display() {
        let base = BinaryDiff::new("a".into(), "b".into());
        let r = SemanticDiffResult {
            base,
            semantic_matches: vec![],
            feature_similarity: 0.5,
        };
        let s = r.to_string();
        assert!(s.contains("0.50"));
    }

    // ---- SemanticDiffEngine ------------------------------------------------

    #[test]
    fn test_semantic_engine_debug() {
        let e = SemanticDiffEngine::new();
        assert!(format!("{e:?}").contains("SemanticDiffEngine"));
    }

    #[test]
    fn test_semantic_engine_default() {
        let _e = SemanticDiffEngine::default();
    }

    #[test]
    fn test_semantic_diff_identical_features() {
        let engine = SemanticDiffEngine::new();
        let f1 = simple_feature(0x1000, "main");
        let f2 = simple_feature(0x1000, "main");
        let res = engine
            .diff_with_features(vec![f1], vec![f2], "a".into(), "b".into())
            .unwrap();
        assert_eq!(res.semantic_matches.len(), 1);
        assert!(res.feature_similarity > 0.5);
    }

    #[test]
    fn test_semantic_diff_added_function() {
        let engine = SemanticDiffEngine::new();
        let res = engine
            .diff_with_features(
                vec![],
                vec![simple_feature(0x2000, "new_fn")],
                "a".into(),
                "b".into(),
            )
            .unwrap();
        
        assert_eq!(res
            .semantic_matches
            .iter()
            .filter(|m| m.func_match.kind == MatchKind::Added).count(), 1);
    }

    #[test]
    fn test_semantic_diff_removed_function() {
        let engine = SemanticDiffEngine::new();
        let res = engine
            .diff_with_features(
                vec![simple_feature(0x1000, "old_fn")],
                vec![],
                "a".into(),
                "b".into(),
            )
            .unwrap();
        
        assert_eq!(res
            .semantic_matches
            .iter()
            .filter(|m| m.func_match.kind == MatchKind::Removed).count(), 1);
    }

    #[test]
    fn test_semantic_diff_empty_both_returns_error() {
        let engine = SemanticDiffEngine::new();
        let res = engine.diff_with_features(vec![], vec![], "a".into(), "b".into());
        assert!(res.is_err());
    }

    // ---- internal helpers --------------------------------------------------

    #[test]
    fn test_mnemonic_cosine_both_empty() {
        assert_eq!(
            mnemonic_cosine_similarity(&HashMap::new(), &HashMap::new()),
            1.0
        );
    }

    #[test]
    fn test_mnemonic_cosine_one_empty() {
        let mut m = HashMap::new();
        m.insert("NOP".to_string(), 5u32);
        assert_eq!(mnemonic_cosine_similarity(&m, &HashMap::new()), 0.0);
    }

    #[test]
    fn test_mnemonic_cosine_identical() {
        let mut m = HashMap::new();
        m.insert("NOP".to_string(), 5u32);
        m.insert("RET".to_string(), 1u32);
        let sim = mnemonic_cosine_similarity(&m, &m.clone());
        assert!((0.99..=1.01).contains(&sim));
    }

    #[test]
    fn test_ratio_similarity() {
        assert_eq!(ratio_similarity(0, 0), 1.0);
        assert_eq!(ratio_similarity(0, 5), 0.0);
        assert_eq!(ratio_similarity(5, 5), 1.0);
        assert!((ratio_similarity(3, 6) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_set_overlap_similarity() {
        assert_eq!(set_overlap_similarity(&[], &[]), 1.0);
        assert_eq!(set_overlap_similarity(&[1, 2, 3], &[]), 0.0);
        assert_eq!(set_overlap_similarity(&[1, 2, 3], &[1, 2, 3]), 1.0);
        let s = set_overlap_similarity(&[1, 2], &[2, 3]);
        assert!((s - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_build_changed_features_identical() {
        let f = simple_feature(0x1000, "f");
        let changes = build_changed_features(Some(&f), Some(&f));
        assert!(changes.is_empty());
    }

    #[test]
    fn test_build_changed_features_none() {
        assert!(build_changed_features(None, None).is_empty());
    }

    // ---- MinHash -----------------------------------------------------------

    #[test]
    fn test_minhash_signature_empty() {
        let mh = MinHash::new(16);
        let sig = mh.signature(&[]);
        assert_eq!(sig.len(), 16);
        assert!(sig.iter().all(|&v| v == u64::MAX));
    }

    #[test]
    fn test_minhash_signature_non_empty() {
        let mh = MinHash::new(16);
        let sig = mh.signature(&[1, 2, 3, 4, 5]);
        assert_eq!(sig.len(), 16);
        assert!(sig.iter().any(|&v| v < u64::MAX));
    }

    #[test]
    fn test_minhash_identical_sets_jaccard_one() {
        let mh = MinHash::new(128);
        let set: Vec<u64> = (0u64..100).collect();
        let sig_a = mh.signature(&set);
        let sig_b = mh.signature(&set);
        let j = MinHash::estimate_jaccard(&sig_a, &sig_b);
        assert!((j - 1.0).abs() < 1e-9, "jaccard of identical={j}");
    }

    #[test]
    fn test_minhash_disjoint_sets_low_jaccard() {
        let mh = MinHash::new(128);
        let set_a: Vec<u64> = (0u64..100).collect();
        let set_b: Vec<u64> = (1000u64..1100).collect();
        let sig_a = mh.signature(&set_a);
        let sig_b = mh.signature(&set_b);
        let j = MinHash::estimate_jaccard(&sig_a, &sig_b);
        assert!(j < 0.1, "jaccard of disjoint={j}");
    }

    #[test]
    fn test_minhash_jaccard_mismatched_lengths() {
        let sig_a = vec![1u64, 2, 3];
        let sig_b = vec![1u64, 2];
        assert_eq!(MinHash::estimate_jaccard(&sig_a, &sig_b), 0.0);
    }

    #[test]
    fn test_minhash_partial_overlap() {
        let mh = MinHash::new(256);
        let set_a: Vec<u64> = (0u64..100).collect();
        let set_b: Vec<u64> = (50u64..150).collect();
        let sig_a = mh.signature(&set_a);
        let sig_b = mh.signature(&set_b);
        // True Jaccard = 50/150 ≈ 0.333
        let j = MinHash::estimate_jaccard(&sig_a, &sig_b);
        assert!((0.2..0.5).contains(&j), "estimated jaccard={j}");
    }

    // ---- LshIndex ----------------------------------------------------------

    #[test]
    fn test_lsh_empty_index() {
        let idx = LshIndex::new(4, 4);
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn test_lsh_insert_and_query() {
        let mh = MinHash::new(64);
        let mut idx = LshIndex::new(8, 8);
        let set: Vec<u64> = (0u64..50).collect();
        let sig = mh.signature(&set);
        idx.insert(0x1000, &sig);
        let candidates = idx.query(&sig);
        assert!(candidates.contains(&0x1000));
    }

    #[test]
    fn test_lsh_similar_items_collide() {
        let mh = MinHash::new(64);
        let mut idx = LshIndex::new(8, 8);
        let set_a: Vec<u64> = (0u64..100).collect();
        let set_b: Vec<u64> = (0u64..90).chain(900u64..910).collect();
        let sig_a = mh.signature(&set_a);
        let sig_b = mh.signature(&set_b);
        idx.insert(0x1000, &sig_a);
        // Query with sig_b — should find 0x1000 as candidate
        let candidates = idx.query(&sig_b);
        assert!(candidates.contains(&0x1000));
    }

    #[test]
    fn test_lsh_len() {
        let mh = MinHash::new(64);
        let mut idx = LshIndex::new(4, 4);
        let sig = mh.signature(&[1, 2, 3]);
        idx.insert(0x100, &sig);
        idx.insert(0x200, &sig);
        assert!(!idx.is_empty());
    }

    // ---- CallGraph ---------------------------------------------------------

    #[test]
    fn test_callgraph_empty() {
        let cg = CallGraph::new();
        assert_eq!(cg.function_count(), 0);
        assert_eq!(cg.call_count(), 0);
    }

    #[test]
    fn test_callgraph_add_call() {
        let mut cg = CallGraph::new();
        cg.add_call(0x1000, 0x2000);
        assert_eq!(cg.function_count(), 2);
        assert_eq!(cg.call_count(), 1);
    }

    #[test]
    fn test_callgraph_no_duplicate_edges() {
        let mut cg = CallGraph::new();
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x1000, 0x2000);
        assert_eq!(cg.call_count(), 1);
    }

    #[test]
    fn test_callgraph_out_degree() {
        let mut cg = CallGraph::new();
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x1000, 0x3000);
        assert_eq!(cg.out_degree(0x1000), 2);
    }

    #[test]
    fn test_callgraph_in_degree() {
        let mut cg = CallGraph::new();
        cg.add_call(0x1000, 0x3000);
        cg.add_call(0x2000, 0x3000);
        assert_eq!(cg.in_degree(0x3000), 2);
    }

    #[test]
    fn test_callgraph_leaf() {
        let mut cg = CallGraph::new();
        cg.add_call(0x1000, 0x2000);
        assert!(cg.is_leaf(0x2000));
        assert!(!cg.is_leaf(0x1000));
    }

    #[test]
    fn test_callgraph_root() {
        let mut cg = CallGraph::new();
        cg.add_call(0x1000, 0x2000);
        assert!(cg.is_root(0x1000));
        assert!(!cg.is_root(0x2000));
    }

    #[test]
    fn test_callgraph_callees() {
        let mut cg = CallGraph::new();
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x1000, 0x3000);
        let mut callees = cg.callees(0x1000);
        callees.sort_unstable();
        assert!(callees.contains(&0x2000));
        assert!(callees.contains(&0x3000));
    }

    #[test]
    fn test_callgraph_callers() {
        let mut cg = CallGraph::new();
        cg.add_call(0x1000, 0x3000);
        cg.add_call(0x2000, 0x3000);
        let callers = cg.callers(0x3000);
        assert_eq!(callers.len(), 2);
    }

    #[test]
    fn test_callgraph_unknown_node_degree_zero() {
        let cg = CallGraph::new();
        assert_eq!(cg.out_degree(0xDEAD), 0);
        assert_eq!(cg.in_degree(0xDEAD), 0);
    }

    // ---- FunctionRenameHeuristic -------------------------------------------

    #[test]
    fn test_rename_heuristic_detects_rename() {
        let h = FunctionRenameHeuristic::new(0.8);
        let fp_a = rustre_diff::FuncFingerprint::new(0x1000, "old_name".to_string(), vec![]);
        let fp_b = rustre_diff::FuncFingerprint::new(0x2000, "new_name".to_string(), vec![]);
        let sm = SemanticMatch {
            func_match: rustre_diff::FuncMatch::similar(fp_a, fp_b, 0.95),
            semantic_similarity: 0.95,
            structural_similarity: 0.90,
            changed_features: vec![],
        };
        assert!(h.is_rename(&sm));
    }

    #[test]
    fn test_rename_heuristic_same_name_not_rename() {
        let h = FunctionRenameHeuristic::new(0.8);
        let fp_a = rustre_diff::FuncFingerprint::new(0x1000, "same".to_string(), vec![]);
        let fp_b = rustre_diff::FuncFingerprint::new(0x2000, "same".to_string(), vec![]);
        let sm = SemanticMatch {
            func_match: rustre_diff::FuncMatch::similar(fp_a, fp_b, 0.95),
            semantic_similarity: 0.95,
            structural_similarity: 0.90,
            changed_features: vec![],
        };
        assert!(!h.is_rename(&sm));
    }

    #[test]
    fn test_rename_heuristic_low_similarity_not_rename() {
        let h = FunctionRenameHeuristic::new(0.8);
        let fp_a = rustre_diff::FuncFingerprint::new(0x1000, "a".to_string(), vec![]);
        let fp_b = rustre_diff::FuncFingerprint::new(0x2000, "b".to_string(), vec![]);
        let sm = SemanticMatch {
            func_match: rustre_diff::FuncMatch::similar(fp_a, fp_b, 0.5),
            semantic_similarity: 0.5,
            structural_similarity: 0.4,
            changed_features: vec![],
        };
        assert!(!h.is_rename(&sm));
    }

    // ---- DiffReport --------------------------------------------------------

    #[test]
    fn test_diff_report_display() {
        let engine = SemanticDiffEngine::new();
        let f1 = simple_feature(0x1000, "main");
        let f2 = simple_feature(0x1000, "main");
        let result = engine
            .diff_with_features(vec![f1], vec![f2], "a".into(), "b".into())
            .unwrap();
        let report = DiffReport::from_result(&result, 0.8);
        let s = report.to_string();
        assert!(s.contains("DiffReport"));
        assert!(s.contains('a'));
    }

    #[test]
    fn test_diff_report_is_identical_when_same() {
        let engine = SemanticDiffEngine::new();
        let f1 = simple_feature(0x1000, "main");
        let f2 = simple_feature(0x1000, "main");
        let result = engine
            .diff_with_features(vec![f1], vec![f2], "a".into(), "b".into())
            .unwrap();
        let report = DiffReport::from_result(&result, 0.8);
        // Identical functions → no modified, no added, no removed.
        assert_eq!(report.stats.added, 0);
        assert_eq!(report.stats.removed, 0);
    }

    // ---- BinarySemanticDiff ------------------------------------------------

    #[test]
    fn test_binary_diff_debug() {
        let d = BinarySemanticDiff::new();
        assert!(format!("{d:?}").contains("BinarySemanticDiff"));
    }

    #[test]
    fn test_binary_diff_default() {
        let _d = BinarySemanticDiff::default();
    }

    #[test]
    fn test_binary_diff_build_lsh_index() {
        let d = BinarySemanticDiff::new();
        let feats = vec![simple_feature(0x1000, "f1"), simple_feature(0x2000, "f2")];
        let (idx, sigs) = d.build_lsh_index(&feats);
        assert!(!idx.is_empty());
        assert_eq!(sigs.len(), 2);
    }

    #[test]
    fn test_binary_diff_full() {
        let d = BinarySemanticDiff::new();
        let f1 = simple_feature(0x1000, "fn_a");
        let f2 = simple_feature(0x1000, "fn_a");
        let report = d
            .diff(vec![f1], vec![f2], "bin_a".into(), "bin_b".into())
            .unwrap();
        assert_eq!(report.binary_a, "bin_a");
    }

    // ---- simple_hash -------------------------------------------------------

    #[test]
    fn test_simple_hash_deterministic() {
        let h1 = simple_hash(b"hello");
        let h2 = simple_hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_simple_hash_different_inputs() {
        assert_ne!(simple_hash(b"hello"), simple_hash(b"world"));
    }

    // ---- SemanticSignature -------------------------------------------------

    /// Build a tiny synthetic function: PUSH rbp / MOV rbp,rsp / CALL rel32 / RET
    fn tiny_func_bytes() -> Vec<u8> {
        vec![
            0x55, // PUSH rbp
            0x89, 0xE5, // MOV ebp, esp  (2-byte, classified as MOV)
            0xE8, 0x10, 0x00, 0x00, 0x00, // CALL +0x10
            0xC3, // RET
        ]
    }

    #[test]
    fn test_semantic_signature_compute_empty() {
        let sig = SemanticSignature::compute(&[], 0x1000);
        assert_eq!(sig.instruction_count, 0);
        assert_eq!(sig.call_count, 0);
        assert!(sig.unique_constants.is_empty());
    }

    #[test]
    fn test_semantic_signature_instruction_count() {
        let bytes = tiny_func_bytes();
        let sig = SemanticSignature::compute(&bytes, 0x1000);
        // PUSH(1) + MOV(1) + CALL(1) + RET(1) but the walk advances byte-by-byte:
        // 0x55→1, 0x89→2 (advance 2), 0xE8→5 (advance 5), 0xC3→1 = 4 instructions.
        assert!(sig.instruction_count >= 3, "got {}", sig.instruction_count);
    }

    #[test]
    fn test_semantic_signature_call_count() {
        let bytes = tiny_func_bytes();
        let sig = SemanticSignature::compute(&bytes, 0x1000);
        assert_eq!(sig.call_count, 1);
    }

    #[test]
    fn test_semantic_signature_histogram_has_call() {
        let bytes = tiny_func_bytes();
        let sig = SemanticSignature::compute(&bytes, 0x1000);
        assert!(
            sig.mnemonic_histogram.contains_key("CALL"),
            "{:?}",
            sig.mnemonic_histogram
        );
    }

    #[test]
    fn test_semantic_signature_cfg_hash_stable() {
        let bytes = tiny_func_bytes();
        let h1 = SemanticSignature::compute(&bytes, 0x1000).cfg_hash;
        let h2 = SemanticSignature::compute(&bytes, 0x1000).cfg_hash;
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_semantic_signature_cfg_hash_differs_on_different_branch() {
        // First variant: JMP +5 at start
        let mut a = vec![0xEB, 0x05u8];
        a.extend_from_slice(&[0xC3; 10]);
        // Second variant: JMP -2 at start
        let mut b = vec![0xEB, 0xFEu8];
        b.extend_from_slice(&[0xC3; 10]);
        let ha = SemanticSignature::compute(&a, 0x1000).cfg_hash;
        let hb = SemanticSignature::compute(&b, 0x1000).cfg_hash;
        assert_ne!(ha, hb);
    }

    #[test]
    fn test_semantic_signature_display() {
        let sig = SemanticSignature::compute(&tiny_func_bytes(), 0x4000);
        let s = sig.to_string();
        assert!(s.contains("0x4000"), "{s}");
        assert!(s.contains("instrs="), "{s}");
    }

    #[test]
    fn test_semantic_signature_string_refs_extracted() {
        let mut bytes = vec![b'h', b'e', b'l', b'l', b'o', 0x00];
        bytes.push(0xC3);
        let sig = SemanticSignature::compute(&bytes, 0x1000);
        assert!(sig.string_refs.iter().any(|s| s.contains("hello")));
    }

    #[test]
    fn test_semantic_signature_constants_extracted() {
        // MOV r32, imm32: 0xB8 <4 bytes>
        let bytes: Vec<u8> = vec![0xB8, 0x78, 0x56, 0x34, 0x12, 0xC3];
        let sig = SemanticSignature::compute(&bytes, 0x1000);
        assert!(
            sig.unique_constants.contains(&0x12345678),
            "{:?}",
            sig.unique_constants
        );
    }

    // ---- SemanticMatcher ---------------------------------------------------

    #[test]
    fn test_matcher_identical_signatures() {
        let bytes = tiny_func_bytes();
        let sig = SemanticSignature::compute(&bytes, 0x1000);
        let sim = SemanticMatcher::similarity(&sig, &sig);
        assert!((0.99..=1.01).contains(&sim), "sim={sim}");
    }

    #[test]
    fn test_matcher_identical_are_equivalent() {
        let bytes = tiny_func_bytes();
        let sig = SemanticSignature::compute(&bytes, 0x1000);
        assert!(SemanticMatcher::are_equivalent(&sig, &sig));
    }

    #[test]
    fn test_matcher_empty_signatures_equivalent() {
        let sig_a = SemanticSignature::compute(&[], 0x1000);
        let sig_b = SemanticSignature::compute(&[], 0x2000);
        // Both are empty → all components score 1.0
        let sim = SemanticMatcher::similarity(&sig_a, &sig_b);
        assert!(sim > 0.85, "sim={sim}");
    }

    #[test]
    fn test_matcher_different_not_equivalent() {
        let bytes_a = tiny_func_bytes();
        // A large different function: many NOPs and a different call pattern.
        let bytes_b: Vec<u8> = {
            let mut v = vec![0x90u8; 50]; // 50 × NOP
            v.push(0xE8);
            v.extend_from_slice(&[0x00; 4]); // CALL
            v.push(0xE8);
            v.extend_from_slice(&[0x00; 4]); // CALL
            v.push(0xE8);
            v.extend_from_slice(&[0x00; 4]); // CALL
            v.push(0xC3); // RET
            v
        };
        let sig_a = SemanticSignature::compute(&bytes_a, 0x1000);
        let sig_b = SemanticSignature::compute(&bytes_b, 0x2000);
        // High instruction-count difference → not equivalent
        assert!(!SemanticMatcher::are_equivalent(&sig_a, &sig_b));
    }

    #[test]
    fn test_matcher_similarity_range() {
        let sig_a = SemanticSignature::compute(&tiny_func_bytes(), 0x1000);
        let sig_b = SemanticSignature::compute(&[0x90; 100], 0x2000);
        let sim = SemanticMatcher::similarity(&sig_a, &sig_b);
        assert!((0.0..=1.0).contains(&sim));
    }

    // ---- FunctionDiff / SemanticDiffer -------------------------------------

    #[test]
    fn test_function_diff_identical() {
        let bytes = tiny_func_bytes();
        let diff = SemanticDiffer::diff_function_pair(&bytes, 0x1000, &bytes, 0x1000);
        assert!(diff.is_equivalent);
        assert!(diff.similarity > 0.85);
        assert!(diff.added_calls.is_empty());
        assert!(diff.removed_calls.is_empty());
    }

    #[test]
    fn test_function_diff_display() {
        let bytes = tiny_func_bytes();
        let diff = SemanticDiffer::diff_function_pair(&bytes, 0x1000, &bytes, 0x2000);
        let s = diff.to_string();
        assert!(s.contains("FunctionDiff"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_function_diff_detects_added_call() {
        let bytes_a = vec![0xC3u8]; // just RET
        let bytes_b = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, // CALL
            0xC3,
        ];
        let diff = SemanticDiffer::diff_function_pair(&bytes_a, 0x1000, &bytes_b, 0x2000);
        assert_eq!(
            diff.added_calls.len(),
            1,
            "added_calls={:?}",
            diff.added_calls
        );
    }

    #[test]
    fn test_function_diff_detects_removed_call() {
        let bytes_a = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, // CALL
            0xC3,
        ];
        let bytes_b = vec![0xC3u8];
        let diff = SemanticDiffer::diff_function_pair(&bytes_a, 0x1000, &bytes_b, 0x2000);
        assert_eq!(diff.removed_calls.len(), 1);
    }

    #[test]
    fn test_diff_binaries_all_matched() {
        let bytes = tiny_func_bytes();
        let funcs: Vec<(u64, Vec<u8>)> = vec![(0x1000, bytes.clone()), (0x2000, bytes)];
        let report = SemanticDiffer::diff_binaries(&funcs, &funcs);
        assert_eq!(report.added_funcs.len(), 0);
        assert_eq!(report.removed_funcs.len(), 0);
        assert!(report.matched_pairs.len() + report.changed_pairs.len() == 2);
    }

    #[test]
    fn test_diff_binaries_added_and_removed() {
        let bytes = tiny_func_bytes();
        let funcs_a: Vec<(u64, Vec<u8>)> = vec![(0x1000, bytes.clone())];
        let funcs_b: Vec<(u64, Vec<u8>)> = vec![(0x2000, bytes)];
        let report = SemanticDiffer::diff_binaries(&funcs_a, &funcs_b);
        assert_eq!(report.added_funcs, vec![0x2000]);
        assert_eq!(report.removed_funcs, vec![0x1000]);
    }

    #[test]
    fn test_diff_binaries_empty() {
        let report = SemanticDiffer::diff_binaries(&[], &[]);
        assert_eq!(report.similarity_score, 1.0);
    }

    #[test]
    fn test_diff_binaries_similarity_score_range() {
        let bytes_a = tiny_func_bytes();
        let bytes_b = vec![0x90u8; 20];
        let funcs_a = vec![(0x1000u64, bytes_a)];
        let funcs_b = vec![(0x1000u64, bytes_b)];
        let report = SemanticDiffer::diff_binaries(&funcs_a, &funcs_b);
        assert!((0.0..=1.0).contains(&report.similarity_score));
    }

    #[test]
    fn test_semantic_diff_report_display() {
        let report = SemanticDiffer::diff_binaries(&[], &[]);
        let s = report.to_string();
        assert!(s.contains("SemanticDiffReport"));
    }

    #[test]
    fn test_semantic_diff_report_total_pairs() {
        let bytes = tiny_func_bytes();
        let funcs: Vec<(u64, Vec<u8>)> = vec![(0x1000, bytes.clone()), (0x2000, bytes)];
        let report = SemanticDiffer::diff_binaries(&funcs, &funcs);
        assert_eq!(report.total_pairs(), 2);
    }

    // ---- PatchAnalysis -----------------------------------------------------

    #[test]
    fn test_patch_analysis_summarize_empty() {
        let report = SemanticDiffer::diff_binaries(&[], &[]);
        let summary = PatchAnalysis::summarize_changes(&report);
        assert!(summary.contains("Binary similarity"));
        assert!(summary.contains("100.0%"));
    }

    #[test]
    fn test_patch_analysis_summarize_shows_changed() {
        let bytes_a = tiny_func_bytes();
        let bytes_b = vec![0x90u8; 30];
        let funcs_a = vec![(0x1000u64, bytes_a)];
        let funcs_b = vec![(0x1000u64, bytes_b)];
        let report = SemanticDiffer::diff_binaries(&funcs_a, &funcs_b);
        let summary = PatchAnalysis::summarize_changes(&report);
        assert!(summary.contains("Functions:"), "{summary}");
    }

    #[test]
    fn test_patch_analysis_analyze_patch_added_call() {
        // before: same function on both sides (no diff)
        let bytes_ref = tiny_func_bytes();
        let funcs_ref: Vec<(u64, Vec<u8>)> = vec![(0x1000, bytes_ref.clone())];
        let before = SemanticDiffer::diff_binaries(&funcs_ref, &funcs_ref);

        // after: patched version has many added CALLs to push it into the "changed" bucket.
        let bytes_patched: Vec<u8> = {
            let mut v = Vec::new();
            // 10 extra CALL instructions to significantly increase call_count and
            // push the mnemonic histogram far away from the original.
            for _ in 0..10 {
                v.push(0xE8u8);
                v.extend_from_slice(&[0x00u8; 4]);
            }
            v.extend_from_slice(&bytes_ref);
            v
        };
        let funcs_patched: Vec<(u64, Vec<u8>)> = vec![(0x1000, bytes_patched)];
        let after = SemanticDiffer::diff_binaries(&funcs_ref, &funcs_patched);

        let result = PatchAnalysis::analyze_patch(&before, &after);
        // Either the function appears in changed_pairs (triggering added_checks / security
        // observations) or the added calls surface in the summary — any populated field is valid.
        let any_output = !result.added_checks.is_empty()
            || !result.security_relevant_changes.is_empty()
            || !result.changed_functions.is_empty()
            || !result.removed_code.is_empty()
            // If the function stayed "equivalent" despite extra calls, verify the diff
            // at least recorded the extra calls in the after-report.
            || after.changed_pairs.iter().any(|d| !d.added_calls.is_empty())
            || after.matched_pairs.iter().any(|d| !d.added_calls.is_empty());
        assert!(any_output, "result={result:?}\nafter={after:?}");
    }

    #[test]
    fn test_patch_analysis_analyze_patch_removed_func() {
        let bytes = tiny_func_bytes();
        let funcs_a: Vec<(u64, Vec<u8>)> = vec![(0x1000, bytes.clone()), (0x2000, bytes.clone())];
        let funcs_b: Vec<(u64, Vec<u8>)> = vec![(0x1000, bytes)];
        let before = SemanticDiffer::diff_binaries(&funcs_a, &funcs_a);
        let after = SemanticDiffer::diff_binaries(&funcs_a, &funcs_b);
        let result = PatchAnalysis::analyze_patch(&before, &after);
        assert!(result.removed_code.iter().any(|s| s.contains("0x2000")));
    }

    #[test]
    fn test_patch_analysis_result_serializable() {
        let report = SemanticDiffer::diff_binaries(&[], &[]);
        let analysis = PatchAnalysis::analyze_patch(&report, &report);
        let json = serde_json::to_string(&analysis);
        assert!(json.is_ok(), "{json:?}");
    }

    // ---- internal helpers (new) --------------------------------------------

    #[test]
    fn test_jaccard_u64_identical() {
        let v = vec![1u64, 2, 3, 4];
        assert!((jaccard_u64(&v, &v) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_jaccard_u64_disjoint() {
        let a = vec![1u64, 2];
        let b = vec![3u64, 4];
        assert_eq!(jaccard_u64(&a, &b), 0.0);
    }

    #[test]
    fn test_jaccard_strings_empty_both() {
        assert!((jaccard_strings(&[], &[]) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_collect_call_offsets_counts_e8() {
        let bytes = vec![0xE8u8, 0x00, 0x00, 0x00, 0x00, 0xC3];
        let offsets = collect_call_offsets(&bytes);
        assert_eq!(offsets, vec![0u64]);
    }

    #[test]
    fn test_extract_string_refs_short_ignored() {
        let bytes = b"hi\x00world";
        let refs = extract_string_refs(bytes);
        // "hi" (2 chars) should be ignored; "world" (5) should appear.
        assert!(refs.iter().any(|s| s.contains("world")));
        assert!(!refs.iter().any(|s| s == "hi"));
    }

    #[test]
    fn test_read_i32_le_underrun() {
        assert_eq!(read_i32_le(&[0x01], 0), 0);
    }

    #[test]
    fn test_set_diff_sorted() {
        let a = vec![1u64, 2, 3];
        let b = vec![2u64, 3, 4];
        let diff = set_diff_sorted(&a, &b);
        assert_eq!(diff, vec![1u64]);
    }
}
