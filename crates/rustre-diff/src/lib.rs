//! `rustre-diff`
//!
//! Binary diffing core — compare two binaries/functions and identify
//! changed, added, and removed functions.

pub mod basic_block_diff;
pub mod function_diff;
pub mod patch_generator;
pub mod binary_diff;
pub mod bindiff_engine;
pub mod instruction_diff;
pub mod patch_classifier;
pub mod patch_diff;
pub mod signature_diff;
pub mod structural;
pub mod structural_diff;

/// Function matching for binary diff: FunctionMatcher, MatchScore
/// (name/signature/content/cg), MatchingStrategy, NameHashMatch,
/// CallgraphContextMatch, BbHashMatch, UnmatchedFunctions, MatchReport.
///
pub mod function_matching;
pub mod semantic_diff;
pub mod patch_detector;
pub mod bindiff_format;
pub mod diff_algorithm;
pub mod function_hasher;
pub mod diff_visualizer;

pub use basic_block_diff::{BasicBlock, BasicBlockDiffer, BlockDiff, BlockMatch, BlockMatchKind};
pub use instruction_diff::{
    DiffInstr, InstrDiff, InstrDiffEntry, InstrDiffKind, InstrDiffer, OperandDiff, operand_changes,
};
pub use structural::{
    DiffFunction, DiffReport, StructuralDiffer, StructuralMatch, StructuralMatchKind,
    histogram_cosine, jaccard, ratio,
};

use std::collections::HashMap;
use std::fmt;
use ahash::AHashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced by diff operations.
#[derive(Debug, Error)]
pub enum DiffError {
    /// One of the inputs was unexpectedly empty.
    #[error("empty input: {0}")]
    EmptyInput(String),
    /// A hashing step failed.
    #[error("hash error: {0}")]
    HashError(String),
    /// Any other error.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// FuncFingerprint
// ---------------------------------------------------------------------------

/// A function fingerprint used for diffing — byte-level representation of a
/// function together with structural metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncFingerprint {
    /// Start address of the function in its binary.
    pub address: u64,
    /// Symbolic name of the function.
    pub name: String,
    /// Byte length of the function.
    pub size: usize,
    /// FNV-based hash of the raw bytes.
    pub hash: u64,
    /// Number of call instructions inside the function.
    pub call_count: usize,
    /// Number of basic blocks.
    pub block_count: usize,
    /// Number of control-flow edges.
    pub edge_count: usize,
    /// Raw bytes of the function body.
    pub bytes: Vec<u8>,
}

impl FuncFingerprint {
    /// Create a new fingerprint from raw bytes; structural metadata defaults to 0.
    #[must_use]
    pub fn new(address: u64, name: String, bytes: Vec<u8>) -> Self {
        let hash = simple_hash(&bytes);
        let size = bytes.len();
        Self {
            address,
            name,
            size,
            hash,
            call_count: 0,
            block_count: 0,
            edge_count: 0,
            bytes,
        }
    }

    /// Similarity score in `0.0..=1.0` against another fingerprint.
    ///
    /// Combines LCS byte similarity with a structural component based on size
    /// difference.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f64 {
        if self.hash == other.hash {
            return 1.0;
        }
        let byte_sim = lcs_similarity(&self.bytes, &other.bytes);
        // Structural penalty: penalise large size discrepancies
        let size_ratio = if self.size == 0 && other.size == 0 {
            1.0
        } else if self.size == 0 || other.size == 0 {
            0.0
        } else {
            let (a, b) = (self.size.min(other.size), self.size.max(other.size));
            f64::from(u32::try_from(a).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(b).unwrap_or(u32::MAX))
        };
        0.7f64.mul_add(byte_sim, 0.3 * size_ratio)
    }
}

impl fmt::Display for FuncFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{:#x} sz={}", self.name, self.address, self.size)
    }
}

// ---------------------------------------------------------------------------
// MatchKind
// ---------------------------------------------------------------------------

/// Classification of how two functions are related across the two binaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MatchKind {
    /// Byte-for-byte identical functions.
    Identical,
    /// Same function, changed implementation.
    Similar,
    /// Function exists only in the new binary.
    Added,
    /// Function exists only in the old binary.
    Removed,
    /// Same function body under a different name.
    Renamed,
}

impl fmt::Display for MatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// FuncMatch
// ---------------------------------------------------------------------------

/// A pairing (or unpaired entry) for a single function across the two binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncMatch {
    /// Function from binary A, if present.
    pub primary: Option<FuncFingerprint>,
    /// Function from binary B, if present.
    pub secondary: Option<FuncFingerprint>,
    /// How the two sides relate.
    pub kind: MatchKind,
    /// Similarity score `0.0..=1.0`.
    pub similarity: f64,
    /// Confidence `0..=100`.
    pub confidence: u32,
}

impl FuncMatch {
    /// Create an identical match (byte-for-byte equal).
    #[must_use]
    pub const fn identical(a: FuncFingerprint, b: FuncFingerprint) -> Self {
        Self {
            primary: Some(a),
            secondary: Some(b),
            kind: MatchKind::Identical,
            similarity: 1.0,
            confidence: 100,
        }
    }

    /// Create a similar match with computed similarity.
    #[must_use]
    pub fn similar(a: FuncFingerprint, b: FuncFingerprint, similarity: f64) -> Self {
        let confidence = {
            let pct = (similarity.clamp(0.0, 1.0) * 100.0).round();
            // Find the largest integer n in [0, 100] such that f64::from(n) <= pct.
            // This avoids any f64-to-integer cast that clippy would flag.
            (0u32..=100).rfind(|&n| f64::from(n) <= pct).unwrap_or(0)
        };
        Self {
            primary: Some(a),
            secondary: Some(b),
            kind: MatchKind::Similar,
            similarity,
            confidence,
        }
    }

    /// Create a renamed match (same body, different name).
    #[must_use]
    pub fn renamed(a: FuncFingerprint, b: FuncFingerprint, similarity: f64) -> Self {
        let confidence = {
            let pct = (similarity.clamp(0.0, 1.0) * 100.0).round();
            // Find the largest integer n in [0, 100] such that f64::from(n) <= pct.
            // This avoids any f64-to-integer cast that clippy would flag.
            (0u32..=100).rfind(|&n| f64::from(n) <= pct).unwrap_or(0)
        };
        Self {
            primary: Some(a),
            secondary: Some(b),
            kind: MatchKind::Renamed,
            similarity,
            confidence,
        }
    }

    /// Create an "added" entry — function only in binary B.
    #[must_use]
    pub const fn added(b: FuncFingerprint) -> Self {
        Self {
            primary: None,
            secondary: Some(b),
            kind: MatchKind::Added,
            similarity: 0.0,
            confidence: 100,
        }
    }

    /// Create a "removed" entry — function only in binary A.
    #[must_use]
    pub const fn removed(a: FuncFingerprint) -> Self {
        Self {
            primary: Some(a),
            secondary: None,
            kind: MatchKind::Removed,
            similarity: 0.0,
            confidence: 100,
        }
    }

    /// Returns `true` if the function changed in any way between the two binaries.
    #[must_use]
    pub const fn is_changed(&self) -> bool {
        !matches!(self.kind, MatchKind::Identical)
    }
}

impl fmt::Display for FuncMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name_a = self.primary.as_ref().map_or("<none>", |p| p.name.as_str());
        let name_b = self
            .secondary
            .as_ref()
            .map_or("<none>", |s| s.name.as_str());
        write!(
            f,
            "{} \u{2194} {} ({:?} {:.1}%)",
            name_a,
            name_b,
            self.kind,
            self.similarity * 100.0
        )
    }
}

// ---------------------------------------------------------------------------
// BinaryDiff
// ---------------------------------------------------------------------------

/// The complete diff result between two binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryDiff {
    /// Name / path of binary A (the "old" version).
    pub name_a: String,
    /// Name / path of binary B (the "new" version).
    pub name_b: String,
    /// All function matches and unpaired entries.
    pub matches: Vec<FuncMatch>,
    /// Total function count in binary A.
    pub total_functions_a: usize,
    /// Total function count in binary B.
    pub total_functions_b: usize,
    /// Wall-clock time taken to compute the diff, in milliseconds.
    pub diff_time_ms: u64,
}

impl BinaryDiff {
    /// Create an empty diff result.
    #[must_use]
    pub const fn new(name_a: String, name_b: String) -> Self {
        Self {
            name_a,
            name_b,
            matches: Vec::new(),
            total_functions_a: 0,
            total_functions_b: 0,
            diff_time_ms: 0,
        }
    }

    /// Count of byte-identical function pairs.
    #[must_use]
    pub fn identical_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.kind == MatchKind::Identical)
            .count()
    }

    /// Count of functions present only in binary B.
    #[must_use]
    pub fn added_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.kind == MatchKind::Added)
            .count()
    }

    /// Count of functions present only in binary A.
    #[must_use]
    pub fn removed_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.kind == MatchKind::Removed)
            .count()
    }

    /// Count of changed (similar or renamed) function pairs.
    #[must_use]
    pub fn changed_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| matches!(m.kind, MatchKind::Similar | MatchKind::Renamed))
            .count()
    }

    /// Average pairwise similarity over all non-added/removed matches.
    #[must_use]
    pub fn similarity_ratio(&self) -> f64 {
        let paired: Vec<f64> = self
            .matches
            .iter()
            .filter(|m| m.primary.is_some() && m.secondary.is_some())
            .map(|m| m.similarity)
            .collect();
        if paired.is_empty() {
            return 0.0;
        }
        paired.iter().sum::<f64>()
            / f64::from(u32::try_from(paired.len()).unwrap_or(u32::MAX))
    }
}

impl fmt::Display for BinaryDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Diff {} vs {}: +{} -{} ~{} ={}",
            self.name_a,
            self.name_b,
            self.added_count(),
            self.removed_count(),
            self.changed_count(),
            self.identical_count()
        )
    }
}

// ---------------------------------------------------------------------------
// simple_hash / lcs_similarity
// ---------------------------------------------------------------------------

/// FNV-1a 64-bit hash over the given byte slice.
#[must_use]
pub fn simple_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Longest-Common-Subsequence-based byte similarity in `0.0..=1.0`.
///
/// Capped at 512 bytes per side for performance.  When inputs exceed 512 bytes
/// the score is scaled down proportionally to the fraction of each input that
/// was actually compared, so a truncated comparison cannot return a misleadingly
/// high similarity for the full buffers.
#[must_use]
pub fn lcs_similarity(a: &[u8], b: &[u8]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let full_len_a = a.len();
    let full_len_b = b.len();
    let la = full_len_a.min(512);
    let lb = full_len_b.min(512);
    let mut dp = vec![vec![0usize; lb + 1]; la + 1];
    for i in 1..=la {
        for j in 1..=lb {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }
    let lcs = f64::from(u32::try_from(dp[la][lb]).unwrap_or(u32::MAX));
    let raw_score = 2.0 * lcs
        / f64::from(u32::try_from(la + lb).unwrap_or(u32::MAX));
    // Scale down when inputs were truncated so the score reflects coverage of
    // the full buffers, not just the sampled prefix.
    let coverage_a = f64::from(u32::try_from(la).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(full_len_a).unwrap_or(u32::MAX));
    let coverage_b = f64::from(u32::try_from(lb).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(full_len_b).unwrap_or(u32::MAX));
    let coverage = coverage_a.min(coverage_b);
    raw_score * coverage
}

// ---------------------------------------------------------------------------
// DiffEngine
// ---------------------------------------------------------------------------

/// The main diffing engine.
///
/// Matches functions first by identical hash, then greedily by similarity.
pub struct DiffEngine {
    similarity_threshold: f64,
}

impl DiffEngine {
    /// Create a new engine with the given similarity threshold.
    #[must_use]
    pub const fn new(similarity_threshold: f64) -> Self {
        Self {
            similarity_threshold,
        }
    }

    /// Diff two sets of function fingerprints.
    ///
    /// # Errors
    ///
    /// Returns [`DiffError::EmptyInput`] if both `funcs_a` and `funcs_b` are empty.
    pub fn diff(
        &self,
        funcs_a: Vec<FuncFingerprint>,
        funcs_b: &[FuncFingerprint],
        name_a: String,
        name_b: String,
    ) -> Result<BinaryDiff, DiffError> {
        if funcs_a.is_empty() && funcs_b.is_empty() {
            return Err(DiffError::EmptyInput("both inputs are empty".into()));
        }

        let total_a = funcs_a.len();
        let total_b = funcs_b.len();

        let mut result = BinaryDiff::new(name_a, name_b);
        result.total_functions_a = total_a;
        result.total_functions_b = total_b;

        // Build hash index for B.
        // FNV hashes are attacker-influenced (derived from untrusted function
        // bytes); use AHashMap so the adversary cannot force O(n²) bucket
        // collisions by crafting functions whose FNV hashes all land in the
        // same bucket.
        let mut hash_map_b: AHashMap<u64, Vec<usize>> = AHashMap::new();
        for (i, fp) in funcs_b.iter().enumerate() {
            hash_map_b.entry(fp.hash).or_default().push(i);
        }

        let mut used_b = vec![false; funcs_b.len()];

        // Pass 1: identical hash matches
        let mut unmatched_a: Vec<FuncFingerprint> = Vec::new();
        for fp_a in funcs_a {
            if let Some(candidates) = hash_map_b.get(&fp_a.hash) {
                // find first unused candidate
                let found = candidates.iter().find(|&&i| !used_b[i]).copied();
                if let Some(idx) = found {
                    used_b[idx] = true;
                    result
                        .matches
                        .push(FuncMatch::identical(fp_a, funcs_b[idx].clone()));
                } else {
                    unmatched_a.push(fp_a);
                }
            } else {
                unmatched_a.push(fp_a);
            }
        }

        // Remaining unmatched B candidates
        let unmatched_b: Vec<FuncFingerprint> = funcs_b
            .iter()
            .enumerate()
            .filter_map(|(i, fp)| if used_b[i] { None } else { Some(fp.clone()) })
            .collect();

        let mut used_unmatched_b = vec![false; unmatched_b.len()];

        // Pass 2: greedy similarity matching
        for fp_a in &unmatched_a {
            if let Some((idx, sim)) = self.find_best_match(fp_a, &unmatched_b, &used_unmatched_b) {
                used_unmatched_b[idx] = true;
                let fp_b = unmatched_b[idx].clone();
                if fp_a.name != fp_b.name && sim > 0.9 {
                    // Same body, different name → renamed
                    result.matches.push(FuncMatch::renamed(fp_a.clone(), fp_b, sim));
                    continue;
                }
                result.matches.push(FuncMatch::similar(fp_a.clone(), fp_b, sim));
            } else {
                result.matches.push(FuncMatch::removed(fp_a.clone()));
            }
        }

        // Remaining B functions are additions
        for (i, fp_b) in unmatched_b.into_iter().enumerate() {
            if !used_unmatched_b[i] {
                result.matches.push(FuncMatch::added(fp_b));
            }
        }

        Ok(result)
    }

    /// Find the best unmatched candidate from `candidates` that exceeds the
    /// similarity threshold.  Returns `(index, similarity)`.
    fn find_best_match(
        &self,
        target: &FuncFingerprint,
        candidates: &[FuncFingerprint],
        used: &[bool],
    ) -> Option<(usize, f64)> {
        let mut best_idx = None;
        let mut best_sim = self.similarity_threshold;
        for (i, cand) in candidates.iter().enumerate() {
            if used[i] {
                continue;
            }
            let sim = target.similarity(cand);
            if sim > best_sim {
                best_sim = sim;
                best_idx = Some(i);
            }
        }
        best_idx.map(|i| (i, best_sim))
    }
}

impl Default for DiffEngine {
    fn default() -> Self {
        Self::new(0.6)
    }
}

impl fmt::Debug for DiffEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DiffEngine(threshold={})", self.similarity_threshold)
    }
}

// ---------------------------------------------------------------------------
// ChangeType
// ---------------------------------------------------------------------------

/// Classification of a single function's change status between two binaries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChangeType {
    /// Function was added in binary B (not present in A).
    Added,
    /// Function was removed from binary B (was in A, absent in B).
    Removed,
    /// Function is present in both binaries but its bytes differ.
    Modified {
        /// Byte-level similarity score in `0.0..=1.0`.
        similarity: f64,
    },
    /// Function is byte-for-byte identical in both binaries.
    Unchanged,
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added => write!(f, "Added"),
            Self::Removed => write!(f, "Removed"),
            Self::Modified { similarity } => write!(f, "Modified({:.1}%)", similarity * 100.0),
            Self::Unchanged => write!(f, "Unchanged"),
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionDiff
// ---------------------------------------------------------------------------

/// A diff record for a single function across two binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDiff {
    /// Start address in binary A (`None` for added functions).
    pub addr_a: Option<u64>,
    /// Start address in binary B (`None` for removed functions).
    pub addr_b: Option<u64>,
    /// Function name in binary A (`None` for added functions).
    pub name_a: Option<String>,
    /// Function name in binary B (`None` for removed functions).
    pub name_b: Option<String>,
    /// Byte-level similarity score in `0.0..=1.0`.
    pub similarity: f64,
    /// How this function changed between the two binaries.
    pub change_type: ChangeType,
}

impl FunctionDiff {
    /// Canonical display name: prefer A's name, fall back to B's.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.name_a
            .as_deref()
            .or(self.name_b.as_deref())
            .unwrap_or("<unknown>")
    }
}

impl fmt::Display for FunctionDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] sim={:.1}%",
            self.display_name(),
            self.change_type,
            self.similarity * 100.0
        )
    }
}

// ---------------------------------------------------------------------------
// NamedBinaryDiff  (high-level diff_by_name result)
// ---------------------------------------------------------------------------

/// Diff result produced by [`diff_by_name`].
///
/// Contains per-function records plus an overall similarity score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedBinaryDiff {
    /// Per-function diff records.
    pub functions: Vec<FunctionDiff>,
    /// Weighted overall similarity of the two binaries in `0.0..=1.0`.
    pub overall_similarity: f64,
}

impl NamedBinaryDiff {
    /// Count of functions classified as [`ChangeType::Added`].
    #[must_use]
    pub fn added_count(&self) -> usize {
        self.functions
            .iter()
            .filter(|d| d.change_type == ChangeType::Added)
            .count()
    }

    /// Count of functions classified as [`ChangeType::Removed`].
    #[must_use]
    pub fn removed_count(&self) -> usize {
        self.functions
            .iter()
            .filter(|d| d.change_type == ChangeType::Removed)
            .count()
    }

    /// Count of functions classified as [`ChangeType::Modified`] (any similarity).
    #[must_use]
    pub fn modified_count(&self) -> usize {
        self.functions
            .iter()
            .filter(|d| matches!(d.change_type, ChangeType::Modified { .. }))
            .count()
    }

    /// Count of functions classified as [`ChangeType::Unchanged`].
    #[must_use]
    pub fn unchanged_count(&self) -> usize {
        self.functions
            .iter()
            .filter(|d| d.change_type == ChangeType::Unchanged)
            .count()
    }
}

// ---------------------------------------------------------------------------
// byte_histogram_similarity
// ---------------------------------------------------------------------------

/// Similarity between two byte slices using byte-value histogram comparison.
///
/// Each byte value 0–255 is counted; the two histograms are compared with the
/// Bhattacharyya coefficient (`sum(sqrt(p_i * q_i))` over normalised counts).
/// Returns `1.0` for identical histograms and `0.0` when the histograms are
/// completely disjoint.
///
/// This is O(n+m) and cheaper than LCS for large functions.
#[must_use]
pub fn byte_histogram_similarity(a: &[u8], b: &[u8]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let mut hist_a = [0u64; 256];
    let mut hist_b = [0u64; 256];
    for &byte in a {
        hist_a[byte as usize] += 1;
    }
    for &byte in b {
        hist_b[byte as usize] += 1;
    }
    let len_a = f64::from(u32::try_from(a.len()).unwrap_or(u32::MAX));
    let len_b = f64::from(u32::try_from(b.len()).unwrap_or(u32::MAX));
    let mut bhatt: f64 = 0.0;
    for i in 0..256 {
        let pa = f64::from(u32::try_from(hist_a[i]).unwrap_or(u32::MAX)) / len_a;
        let pb = f64::from(u32::try_from(hist_b[i]).unwrap_or(u32::MAX)) / len_b;
        bhatt += (pa * pb).sqrt();
    }
    bhatt.clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// ngram_jaccard_similarity
// ---------------------------------------------------------------------------

/// Byte-level n-gram Jaccard similarity between two byte slices.
///
/// Builds the set of all byte n-grams (default `n = 4`) for each slice and
/// returns `|intersection| / |union|`.  Returns `1.0` for identical slices
/// and `0.0` for completely different slices.
///
/// Input is capped at 4096 bytes per side to bound memory use; when inputs
/// exceed this limit the similarity of the prefix is returned (conservative).
/// The internal set uses `ahash` to prevent hash-collision `DoS` on attacker-
/// controlled byte content.
#[must_use]
pub fn ngram_jaccard_similarity(a: &[u8], b: &[u8], n: usize) -> f64 {
    use ahash::AHashSet;
    // Cap per-side input to bound memory allocation from untrusted data.
    const MAX_INPUT: usize = 4096;
    let a = &a[..a.len().min(MAX_INPUT)];
    let b = &b[..b.len().min(MAX_INPUT)];
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() || n == 0 {
        return 0.0;
    }
    // Encode each n-gram as a u64 (works for n <= 8; capped at 8 otherwise).
    let n = n.min(8);
    let ngrams_of = |bytes: &[u8]| -> AHashSet<u64> {
        if bytes.len() < n {
            return AHashSet::new();
        }
        bytes
            .windows(n)
            .map(|w| {
                let mut v = 0u64;
                for &b in w {
                    v = (v << 8) | u64::from(b);
                }
                v
            })
            .collect()
    };
    let sa = ngrams_of(a);
    let sb = ngrams_of(b);
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    let intersection = sa.intersection(&sb).count();
    let union_size = sa.len() + sb.len() - intersection;
    if union_size == 0 {
        return 1.0;
    }
    f64::from(u32::try_from(intersection).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(union_size).unwrap_or(u32::MAX))
}

// ---------------------------------------------------------------------------
// combined_byte_similarity  (histogram + n-gram blend)
// ---------------------------------------------------------------------------

/// Combined byte similarity: 60% byte-histogram Bhattacharyya + 40% 4-gram Jaccard.
#[must_use]
pub fn combined_byte_similarity(a: &[u8], b: &[u8]) -> f64 {
    let hist = byte_histogram_similarity(a, b);
    let ngram = ngram_jaccard_similarity(a, b, 4);
    0.6_f64.mul_add(hist, 0.4 * ngram)
}

// ---------------------------------------------------------------------------
// diff_by_name
// ---------------------------------------------------------------------------

/// Diff two sets of named byte slices (e.g. function name → bytes).
///
/// Matching is done purely by name:
/// * Functions present in both maps are compared with [`combined_byte_similarity`].
/// * Functions only in `map_a` become [`ChangeType::Removed`] entries.
/// * Functions only in `map_b` become [`ChangeType::Added`] entries.
///
/// The `overall_similarity` is the mean similarity of all paired functions,
/// weighted by coverage (how many functions could be paired).
#[must_use]
pub fn diff_by_name<S: ::std::hash::BuildHasher>(
    map_a: &HashMap<String, Vec<u8>, S>,
    map_b: &HashMap<String, Vec<u8>, S>,
) -> NamedBinaryDiff {
    let mut functions: Vec<FunctionDiff> = Vec::new();
    let mut pair_sim_sum: f64 = 0.0;
    let mut pair_count: usize = 0;

    // Paired functions (matching names).
    for (name, bytes_a) in map_a {
        if let Some(bytes_b) = map_b.get(name) {
            let sim = combined_byte_similarity(bytes_a, bytes_b);
            let change_type = if (sim - 1.0_f64).abs() < f64::EPSILON {
                ChangeType::Unchanged
            } else {
                ChangeType::Modified { similarity: sim }
            };
            functions.push(FunctionDiff {
                addr_a: None,
                addr_b: None,
                name_a: Some(name.clone()),
                name_b: Some(name.clone()),
                similarity: sim,
                change_type,
            });
            pair_sim_sum += sim;
            pair_count += 1;
        } else {
            // Only in A → removed.
            functions.push(FunctionDiff {
                addr_a: None,
                addr_b: None,
                name_a: Some(name.clone()),
                name_b: None,
                similarity: 0.0,
                change_type: ChangeType::Removed,
            });
        }
    }

    // Functions only in B → added.
    for name in map_b.keys() {
        if !map_a.contains_key(name) {
            functions.push(FunctionDiff {
                addr_a: None,
                addr_b: None,
                name_a: None,
                name_b: Some(name.clone()),
                similarity: 0.0,
                change_type: ChangeType::Added,
            });
        }
    }

    // Sort for deterministic output: unchanged first, then modified desc sim,
    // then removed, then added.
    functions.sort_by(|a, b| {
        let rank = |ct: &ChangeType| match ct {
            ChangeType::Unchanged => 0,
            ChangeType::Modified { .. } => 1,
            ChangeType::Removed => 2,
            ChangeType::Added => 3,
        };
        rank(&a.change_type)
            .cmp(&rank(&b.change_type))
            .then_with(|| {
                b.similarity
                    .partial_cmp(&a.similarity)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.display_name().cmp(b.display_name()))
    });

    let total = map_a.len().max(map_b.len());
    let coverage = if total > 0 {
        f64::from(u32::try_from(pair_count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    } else {
        0.0
    };
    let mean_sim = if pair_count > 0 {
        pair_sim_sum / f64::from(u32::try_from(pair_count).unwrap_or(u32::MAX))
    } else {
        0.0
    };
    let overall_similarity = (mean_sim * coverage).clamp(0.0, 1.0);

    NamedBinaryDiff {
        functions,
        overall_similarity,
    }
}

// ---------------------------------------------------------------------------
// ExportEntry / ExportDiff  (local, format-agnostic)
// ---------------------------------------------------------------------------

/// A single entry from an export table, format-agnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportEntry {
    /// Symbol name, or `None` for anonymous/ordinal-only exports.
    pub name: Option<String>,
    /// Export ordinal.
    pub ordinal: u32,
    /// Virtual address of the exported symbol.
    pub address: u64,
}

/// Diff of two export tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportDiff {
    /// Exports present only in the old binary.
    pub removed: Vec<ExportEntry>,
    /// Exports present only in the new binary.
    pub added: Vec<ExportEntry>,
    /// Exports present in both but with a different address.
    pub moved: Vec<(ExportEntry, ExportEntry)>,
    /// Exports identical in both binaries (same name, ordinal, and address).
    pub unchanged: Vec<ExportEntry>,
}

impl ExportDiff {
    /// `true` if there are no differences between the two export tables.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.removed.is_empty() && self.added.is_empty() && self.moved.is_empty()
    }
}

impl fmt::Display for ExportDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExportDiff: +{} -{} ~{} ={} ",
            self.added.len(),
            self.removed.len(),
            self.moved.len(),
            self.unchanged.len()
        )
    }
}

/// Diff two export tables.
///
/// Matching is performed by the export `name` (for named exports) or by
/// `ordinal` (for anonymous exports).  Entries with the same key but
/// different virtual addresses are collected in `moved`.
///
/// Uses `ahash`-backed maps so that attacker-controlled export names cannot
/// trigger hash-collision `DoS`.
#[must_use]
pub fn diff_exports(a: &[ExportEntry], b: &[ExportEntry]) -> ExportDiff {
    let mut map_a: ahash::AHashMap<String, &ExportEntry> = ahash::AHashMap::new();
    for e in a {
        let key = e.name.clone().unwrap_or_else(|| format!("@{}", e.ordinal));
        map_a.insert(key, e);
    }
    let mut map_b: ahash::AHashMap<String, &ExportEntry> = ahash::AHashMap::new();
    for e in b {
        let key = e.name.clone().unwrap_or_else(|| format!("@{}", e.ordinal));
        map_b.insert(key, e);
    }

    let mut removed = Vec::new();
    let mut moved = Vec::new();
    let mut unchanged = Vec::new();
    let mut added = Vec::new();

    for (key, ea) in &map_a {
        if let Some(eb) = map_b.get(key) {
            if ea.address == eb.address {
                unchanged.push((*ea).clone());
            } else {
                moved.push(((*ea).clone(), (*eb).clone()));
            }
        } else {
            removed.push((*ea).clone());
        }
    }
    for (key, eb) in &map_b {
        if !map_a.contains_key(key) {
            added.push((*eb).clone());
        }
    }

    // Sort for determinism.
    removed.sort_by_key(|e| e.ordinal);
    added.sort_by_key(|e| e.ordinal);
    unchanged.sort_by_key(|e| e.ordinal);
    moved.sort_by_key(|(e, _)| e.ordinal);

    ExportDiff {
        removed,
        added,
        moved,
        unchanged,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(addr: u64, name: &str, bytes: &[u8]) -> FuncFingerprint {
        FuncFingerprint::new(addr, name.to_string(), bytes.to_vec())
    }

    // ---- simple_hash -------------------------------------------------------

    #[test]
    fn test_simple_hash_empty() {
        let h = simple_hash(&[]);
        // FNV offset basis
        assert_eq!(h, 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn test_simple_hash_consistency() {
        let a = simple_hash(b"hello");
        let b = simple_hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn test_simple_hash_different() {
        assert_ne!(simple_hash(b"foo"), simple_hash(b"bar"));
    }

    // ---- lcs_similarity ----------------------------------------------------

    #[test]
    fn test_lcs_both_empty() {
        assert_eq!(lcs_similarity(&[], &[]), 1.0);
    }

    #[test]
    fn test_lcs_one_empty() {
        assert_eq!(lcs_similarity(&[1, 2, 3], &[]), 0.0);
        assert_eq!(lcs_similarity(&[], &[1, 2, 3]), 0.0);
    }

    #[test]
    fn test_lcs_identical() {
        let data = vec![0x90u8; 20];
        assert_eq!(lcs_similarity(&data, &data), 1.0);
    }

    #[test]
    fn test_lcs_completely_different() {
        let a = vec![0x00u8; 10];
        let b = vec![0xFFu8; 10];
        assert_eq!(lcs_similarity(&a, &b), 0.0);
    }

    #[test]
    fn test_lcs_partial() {
        let a = b"ABCDE";
        let b = b"AXXDE";
        let s = lcs_similarity(a, b);
        assert!(s > 0.0 && s < 1.0);
    }

    #[test]
    fn test_lcs_long_inputs_capped() {
        // Should not panic and should return a value in range
        let a = vec![0xABu8; 1000];
        let b = vec![0xABu8; 1000];
        let s = lcs_similarity(&a, &b);
        assert!((0.0..=1.0).contains(&s));
    }

    // ---- FuncFingerprint ---------------------------------------------------

    #[test]
    fn test_fingerprint_new() {
        let fp = FuncFingerprint::new(0x1000, "main".to_string(), vec![0x90; 10]);
        assert_eq!(fp.address, 0x1000);
        assert_eq!(fp.name, "main");
        assert_eq!(fp.size, 10);
        assert_ne!(fp.hash, 0);
    }

    #[test]
    fn test_fingerprint_display() {
        let fp = FuncFingerprint::new(0x2000, "foo".to_string(), vec![0x90; 5]);
        assert!(fp.to_string().contains("foo"));
        assert!(fp.to_string().contains("0x2000"));
    }

    #[test]
    fn test_fingerprint_similarity_identical() {
        let a = fp(0x1000, "a", &[1, 2, 3, 4, 5]);
        let b = fp(0x1000, "a", &[1, 2, 3, 4, 5]);
        assert_eq!(a.similarity(&b), 1.0);
    }

    #[test]
    fn test_fingerprint_similarity_empty() {
        let a = FuncFingerprint::new(0, "a".to_string(), vec![]);
        let b = FuncFingerprint::new(0, "b".to_string(), vec![]);
        // Both empty → hash collision → 1.0
        assert_eq!(a.similarity(&b), 1.0);
    }

    #[test]
    fn test_fingerprint_similarity_one_empty() {
        let a = fp(0, "a", &[1, 2, 3]);
        let b = FuncFingerprint::new(0, "b".to_string(), vec![]);
        let s = a.similarity(&b);
        assert!(s < 0.5);
    }

    // ---- MatchKind ---------------------------------------------------------

    #[test]
    fn test_match_kind_display() {
        assert_eq!(MatchKind::Identical.to_string(), "Identical");
        assert_eq!(MatchKind::Added.to_string(), "Added");
        assert_eq!(MatchKind::Removed.to_string(), "Removed");
        assert_eq!(MatchKind::Similar.to_string(), "Similar");
        assert_eq!(MatchKind::Renamed.to_string(), "Renamed");
    }

    // ---- FuncMatch ---------------------------------------------------------

    #[test]
    fn test_func_match_identical() {
        let a = fp(0, "f", &[1, 2]);
        let b = fp(0, "f", &[1, 2]);
        let m = FuncMatch::identical(a, b);
        assert_eq!(m.kind, MatchKind::Identical);
        assert_eq!(m.similarity, 1.0);
        assert_eq!(m.confidence, 100);
        assert!(!m.is_changed());
    }

    #[test]
    fn test_func_match_added() {
        let b = fp(0x1000, "new_func", &[0x90; 5]);
        let m = FuncMatch::added(b);
        assert_eq!(m.kind, MatchKind::Added);
        assert!(m.primary.is_none());
        assert!(m.secondary.is_some());
        assert!(m.is_changed());
    }

    #[test]
    fn test_func_match_removed() {
        let a = fp(0x1000, "old_func", &[0x90; 5]);
        let m = FuncMatch::removed(a);
        assert_eq!(m.kind, MatchKind::Removed);
        assert!(m.primary.is_some());
        assert!(m.secondary.is_none());
        assert!(m.is_changed());
    }

    #[test]
    fn test_func_match_similar() {
        let a = fp(0x1000, "f", &[1, 2, 3, 4, 5]);
        let b = fp(0x2000, "f", &[1, 2, 3, 4, 9]);
        let m = FuncMatch::similar(a, b, 0.8);
        assert_eq!(m.kind, MatchKind::Similar);
        assert!(m.is_changed());
    }

    #[test]
    fn test_func_match_display() {
        let _a = fp(0, "func_a", &[1]);
        let b = fp(0, "func_b", &[2]);
        let m = FuncMatch::added(b);
        let s = m.to_string();
        assert!(s.contains("func_b"));
    }

    // ---- BinaryDiff --------------------------------------------------------

    #[test]
    fn test_binary_diff_new() {
        let d = BinaryDiff::new("a.exe".into(), "b.exe".into());
        assert_eq!(d.identical_count(), 0);
        assert_eq!(d.added_count(), 0);
        assert_eq!(d.removed_count(), 0);
        assert_eq!(d.changed_count(), 0);
        assert_eq!(d.similarity_ratio(), 0.0);
    }

    #[test]
    fn test_binary_diff_display() {
        let d = BinaryDiff::new("a.exe".into(), "b.exe".into());
        let s = d.to_string();
        assert!(s.contains("a.exe"));
        assert!(s.contains("b.exe"));
    }

    // ---- DiffEngine --------------------------------------------------------

    #[test]
    fn test_diff_both_empty_returns_error() {
        let eng = DiffEngine::default();
        let err = eng.diff(vec![], &[], "a".into(), "b".into());
        assert!(err.is_err());
    }

    #[test]
    fn test_diff_identical_functions() {
        let eng = DiffEngine::default();
        let funcs_a = vec![fp(0x1000, "main", &[0x55, 0x8b, 0xec])];
        let funcs_b = vec![fp(0x1000, "main", &[0x55, 0x8b, 0xec])];
        let diff = eng.diff(funcs_a, &funcs_b, "a".into(), "b".into()).unwrap();
        assert_eq!(diff.identical_count(), 1);
        assert_eq!(diff.added_count(), 0);
        assert_eq!(diff.removed_count(), 0);
    }

    #[test]
    fn test_diff_added_function() {
        let eng = DiffEngine::default();
        let funcs_a = vec![];
        let funcs_b = vec![fp(0x1000, "new_fn", &[0x90; 10])];
        let diff = eng.diff(funcs_a, &funcs_b, "a".into(), "b".into()).unwrap();
        assert_eq!(diff.added_count(), 1);
        assert_eq!(diff.removed_count(), 0);
    }

    #[test]
    fn test_diff_removed_function() {
        let eng = DiffEngine::default();
        let funcs_a = vec![fp(0x1000, "old_fn", &[0x90; 10])];
        let funcs_b = vec![];
        let diff = eng.diff(funcs_a, &funcs_b, "a".into(), "b".into()).unwrap();
        assert_eq!(diff.removed_count(), 1);
        assert_eq!(diff.added_count(), 0);
    }

    #[test]
    fn test_diff_similar_functions() {
        let eng = DiffEngine::new(0.5);
        let bytes_a: Vec<u8> = (0u8..20).collect();
        let mut bytes_b = bytes_a.clone();
        bytes_b[19] = 0xFF; // one byte change
        let funcs_a = vec![fp(0x1000, "f", &bytes_a)];
        let funcs_b = vec![fp(0x2000, "f", &bytes_b)];
        let diff = eng.diff(funcs_a, &funcs_b, "a".into(), "b".into()).unwrap();
        // Should be either Similar or Identical
        assert_eq!(diff.matches.len(), 1);
    }

    #[test]
    fn test_diff_engine_debug() {
        let eng = DiffEngine::new(0.7);
        let s = format!("{eng:?}");
        assert!(s.contains("0.7"));
    }

    #[test]
    fn test_diff_engine_default_threshold() {
        let eng = DiffEngine::default();
        let s = format!("{eng:?}");
        assert!(s.contains("0.6"));
    }

    #[test]
    fn test_similarity_ratio_no_pairs() {
        let d = BinaryDiff::new("a".into(), "b".into());
        assert_eq!(d.similarity_ratio(), 0.0);
    }

    #[test]
    fn test_diff_multiple_functions() {
        let eng = DiffEngine::default();
        let funcs_a = vec![
            fp(0x1000, "main", &[0x55, 0x8b, 0xec, 0x83, 0xec, 0x10]),
            fp(0x1100, "helper", &[0x90; 20]),
            fp(0x1200, "old_fn", &[0x33, 0xc0, 0xc3]),
        ];
        let funcs_b = vec![
            fp(0x1000, "main", &[0x55, 0x8b, 0xec, 0x83, 0xec, 0x10]),
            fp(0x1100, "helper", &[0x90; 20]),
            fp(0x1300, "new_fn", &[0x31, 0xc0, 0xc3]),
        ];
        let diff = eng.diff(funcs_a, &funcs_b, "a".into(), "b".into()).unwrap();
        assert_eq!(diff.total_functions_a, 3);
        assert_eq!(diff.total_functions_b, 3);
        assert_eq!(diff.identical_count(), 2);
    }
}
