//! `function_matcher` — Match functions across two binary versions.
//!
//! Computes similarity scores based on:
//! 1. Instruction-sequence signature (normalised basic block hash sequences)
//! 2. Control-flow structure (block count, edge count, call count)
//! 3. Callee fingerprint (set of callee hashes)
//! 4. String-reference fingerprint
//!
//! Produces a ranked list of `MatchResult` pairs.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ── SimilarityScore ───────────────────────────────────────────────────────────

/// Decomposed similarity between two functions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SimilarityScore {
    /// Instruction sequence similarity [0.0, 1.0].
    pub sequence: f32,
    /// CFG structure similarity [0.0, 1.0].
    pub cfg_structure: f32,
    /// Callee fingerprint Jaccard similarity [0.0, 1.0].
    pub callee_overlap: f32,
    /// String reference Jaccard similarity [0.0, 1.0].
    pub string_overlap: f32,
    /// Combined weighted score [0.0, 1.0].
    pub combined: f32,
}

impl SimilarityScore {
    /// Compute from components using fixed weights.
    #[must_use]
    pub fn from_components(sequence: f32, cfg: f32, callee: f32, strings: f32) -> Self {
        let combined = 0.45 * sequence + 0.25 * cfg + 0.20 * callee + 0.10 * strings;
        Self {
            sequence: sequence.clamp(0.0, 1.0),
            cfg_structure: cfg.clamp(0.0, 1.0),
            callee_overlap: callee.clamp(0.0, 1.0),
            string_overlap: strings.clamp(0.0, 1.0),
            combined: combined.clamp(0.0, 1.0),
        }
    }

    /// Returns `true` if combined score ≥ 0.85 (high confidence match).
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.combined >= 0.85
    }

    /// Returns `true` if combined score ≥ 0.60 (probable match).
    #[must_use]
    pub fn is_probable(&self) -> bool {
        self.combined >= 0.60
    }
}

// ── MatchKind ─────────────────────────────────────────────────────────────────

/// Classification of the match type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MatchKind {
    /// Byte-for-byte identical (combined = 1.0).
    Identical,
    /// Very high structural similarity with minor constant changes.
    NearIdentical,
    /// Significant match; likely the same function with localised changes.
    HighSimilarity,
    /// Probable match; notable changes but same purpose.
    ModerateSimilarity,
    /// Weak / uncertain match.
    WeakSimilarity,
    /// Unmatched (present in only one binary).
    Unmatched,
}

impl MatchKind {
    #[must_use]
    fn from_score(score: f32) -> Self {
        match score {
            s if s >= 0.999 => Self::Identical,
            s if s >= 0.90  => Self::NearIdentical,
            s if s >= 0.75  => Self::HighSimilarity,
            s if s >= 0.60  => Self::ModerateSimilarity,
            s if s > 0.0    => Self::WeakSimilarity,
            _               => Self::Unmatched,
        }
    }
}

impl std::fmt::Display for MatchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── MatchResult ───────────────────────────────────────────────────────────────

/// A single function-pair match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    /// Offset in binary A.
    pub offset_a: u64,
    /// Offset in binary B.
    pub offset_b: u64,
    /// Name from binary A (if available).
    pub name_a: Option<String>,
    /// Name from binary B (if available).
    pub name_b: Option<String>,
    /// Similarity scores.
    pub score: SimilarityScore,
    /// Classification.
    pub kind: MatchKind,
}

impl MatchResult {
    #[must_use]
    fn new(
        offset_a: u64,
        offset_b: u64,
        score: SimilarityScore,
        name_a: Option<String>,
        name_b: Option<String>,
    ) -> Self {
        let kind = MatchKind::from_score(score.combined);
        Self { offset_a, offset_b, name_a, name_b, score, kind }
    }
}

// ── FunctionDescriptor ────────────────────────────────────────────────────────

/// Structural descriptor for a single function, used as input to the matcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDescriptor {
    /// Byte offset (virtual address).
    pub offset: u64,
    /// Optional symbol name.
    pub name: Option<String>,
    /// Sorted sequence of basic-block hashes (FNV-1a 64-bit).
    pub block_hashes: Vec<u64>,
    /// Number of basic blocks.
    pub block_count: usize,
    /// Number of CFG edges.
    pub edge_count: usize,
    /// Number of call instructions.
    pub call_count: usize,
    /// Set of callee offsets / hashes.
    pub callee_fingerprint: HashSet<u64>,
    /// Set of string content hashes referenced.
    pub string_fingerprint: HashSet<u64>,
}

impl FunctionDescriptor {
    /// Create a new descriptor with minimal fields.
    #[must_use]
    pub fn new(offset: u64) -> Self {
        Self {
            offset,
            name: None,
            block_hashes: Vec::new(),
            block_count: 0,
            edge_count: 0,
            call_count: 0,
            callee_fingerprint: HashSet::new(),
            string_fingerprint: HashSet::new(),
        }
    }

    /// Builder: set name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Builder: add block hashes.
    #[must_use]
    pub fn with_blocks(mut self, hashes: Vec<u64>, edges: usize) -> Self {
        self.block_count = hashes.len();
        self.edge_count = edges;
        self.block_hashes = hashes;
        self
    }

    /// Builder: set call count.
    #[must_use]
    pub const fn with_calls(mut self, n: usize) -> Self {
        self.call_count = n;
        self
    }

    /// Builder: set callee fingerprint.
    #[must_use]
    pub fn with_callees(mut self, callees: HashSet<u64>) -> Self {
        self.callee_fingerprint = callees;
        self
    }

    /// Builder: set string fingerprint.
    #[must_use]
    pub fn with_strings(mut self, strings: HashSet<u64>) -> Self {
        self.string_fingerprint = strings;
        self
    }

    /// Sorted block-hash sequence hash (FNV-1a over all block hashes in order).
    #[must_use]
    pub fn sequence_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &bh in &self.block_hashes {
            for byte in bh.to_le_bytes() {
                h ^= byte as u64;
                h = h.wrapping_mul(0x00000100000001B3);
            }
        }
        h
    }
}

// ── similarity helpers ────────────────────────────────────────────────────────

fn jaccard(a: &HashSet<u64>, b: &HashSet<u64>) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0; // both empty → identical
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 { 1.0 } else { intersection as f32 / union as f32 }
}

fn sequence_similarity(a: &[u64], b: &[u64]) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    // LCS length via dynamic programming (bounded at 512×512).
    let n = a.len().min(512);
    let m = b.len().min(512);
    let a = &a[..n];
    let b = &b[..m];

    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in 1..=n {
        for j in 1..=m {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }
    let lcs = dp[n][m];
    (2 * lcs) as f32 / (n + m) as f32
}

fn cfg_similarity(a: &FunctionDescriptor, b: &FunctionDescriptor) -> f32 {
    // Compare block count, edge count, call count with normalised distance.
    let diff_blocks = (a.block_count as f32 - b.block_count as f32).abs();
    let max_blocks = (a.block_count.max(b.block_count).max(1)) as f32;
    let diff_edges = (a.edge_count as f32 - b.edge_count as f32).abs();
    let max_edges = (a.edge_count.max(b.edge_count).max(1)) as f32;
    let diff_calls = (a.call_count as f32 - b.call_count as f32).abs();
    let max_calls = (a.call_count.max(b.call_count).max(1)) as f32;

    let sim_blocks = 1.0 - (diff_blocks / max_blocks).min(1.0);
    let sim_edges  = 1.0 - (diff_edges  / max_edges ).min(1.0);
    let sim_calls  = 1.0 - (diff_calls  / max_calls ).min(1.0);

    (sim_blocks + sim_edges + sim_calls) / 3.0
}

fn compute_similarity(a: &FunctionDescriptor, b: &FunctionDescriptor) -> SimilarityScore {
    let seq  = sequence_similarity(&a.block_hashes, &b.block_hashes);
    let cfg  = cfg_similarity(a, b);
    let cal  = jaccard(&a.callee_fingerprint, &b.callee_fingerprint);
    let str  = jaccard(&a.string_fingerprint, &b.string_fingerprint);
    SimilarityScore::from_components(seq, cfg, cal, str)
}

// ── FunctionMatcher ───────────────────────────────────────────────────────────

/// Matches functions across two sets of descriptors.
pub struct FunctionMatcher {
    /// Minimum combined score to include in results.
    pub min_score: f32,
    /// If `true`, a function in A can match at most one in B (one-to-one).
    pub one_to_one: bool,
}

impl Default for FunctionMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionMatcher {
    /// Create with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self { min_score: 0.50, one_to_one: true }
    }

    /// Set minimum score.
    #[must_use]
    pub const fn with_min_score(mut self, s: f32) -> Self {
        self.min_score = s;
        self
    }

    /// Allow many-to-many matches.
    #[must_use]
    pub const fn many_to_many(mut self) -> Self {
        self.one_to_one = false;
        self
    }

    /// Match all functions from `funcs_a` against `funcs_b`.
    ///
    /// Returns a sorted list of best matches (highest combined score first).
    #[must_use]
    pub fn match_functions(
        &self,
        funcs_a: &[FunctionDescriptor],
        funcs_b: &[FunctionDescriptor],
    ) -> Vec<MatchResult> {
        // First pass: compute all pairwise candidate scores.
        let mut candidates: Vec<(usize, usize, SimilarityScore)> = Vec::new();
        for (ia, fa) in funcs_a.iter().enumerate() {
            for (ib, fb) in funcs_b.iter().enumerate() {
                let score = compute_similarity(fa, fb);
                if score.combined >= self.min_score {
                    candidates.push((ia, ib, score));
                }
            }
        }

        // Sort: highest score first.
        candidates.sort_by(|a, b| {
            b.2.combined.partial_cmp(&a.2.combined).unwrap_or(std::cmp::Ordering::Equal)
        });

        if !self.one_to_one {
            return candidates
                .into_iter()
                .map(|(ia, ib, score)| {
                    MatchResult::new(
                        funcs_a[ia].offset, funcs_b[ib].offset,
                        score,
                        funcs_a[ia].name.clone(), funcs_b[ib].name.clone(),
                    )
                })
                .collect();
        }

        // One-to-one: greedy assignment.
        let mut used_a: HashSet<usize> = HashSet::new();
        let mut used_b: HashSet<usize> = HashSet::new();
        let mut results: Vec<MatchResult> = Vec::new();

        for (ia, ib, score) in candidates {
            if used_a.contains(&ia) || used_b.contains(&ib) {
                continue;
            }
            used_a.insert(ia);
            used_b.insert(ib);
            results.push(MatchResult::new(
                funcs_a[ia].offset, funcs_b[ib].offset,
                score,
                funcs_a[ia].name.clone(), funcs_b[ib].name.clone(),
            ));
        }

        results
    }

    /// Match by exact sequence hash (fast O(n+m) path for identical functions).
    #[must_use]
    pub fn match_identical(
        funcs_a: &[FunctionDescriptor],
        funcs_b: &[FunctionDescriptor],
    ) -> Vec<MatchResult> {
        let map_b: HashMap<u64, &FunctionDescriptor> =
            funcs_b.iter().map(|f| (f.sequence_hash(), f)).collect();

        let score = SimilarityScore::from_components(1.0, 1.0, 1.0, 1.0);

        funcs_a.iter()
            .filter_map(|fa| {
                map_b.get(&fa.sequence_hash()).map(|fb| {
                    MatchResult::new(fa.offset, fb.offset, score, fa.name.clone(), fb.name.clone())
                })
            })
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(offset: u64, hashes: Vec<u64>, _blocks: usize, edges: usize) -> FunctionDescriptor {
        FunctionDescriptor::new(offset).with_blocks(hashes, edges).with_calls(1)
    }

    #[test]
    fn test_match_identical_functions() {
        let hashes = vec![0xABCDu64, 0x1234, 0x5678];
        let a = make_func(0x1000, hashes.clone(), 3, 2);
        let b = make_func(0x2000, hashes.clone(), 3, 2);
        let results = FunctionMatcher::match_identical(&[a], &[b]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, MatchKind::Identical);
    }

    #[test]
    fn test_match_different_functions() {
        let a = make_func(0x1000, vec![0xAAAAu64, 0xBBBB], 2, 1);
        let b = make_func(0x2000, vec![0xCCCCu64, 0xDDDD], 2, 1);
        let results = FunctionMatcher::match_identical(&[a], &[b]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_matcher_returns_results() {
        let a = make_func(0x1000, vec![0x01u64, 0x02, 0x03], 3, 2);
        let b = make_func(0x2000, vec![0x01u64, 0x02, 0x04], 3, 2);
        let m = FunctionMatcher::new().with_min_score(0.30);
        let results = m.match_functions(&[a], &[b]);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_match_kind_from_score() {
        assert_eq!(MatchKind::from_score(1.0), MatchKind::Identical);
        assert_eq!(MatchKind::from_score(0.95), MatchKind::NearIdentical);
        assert_eq!(MatchKind::from_score(0.80), MatchKind::HighSimilarity);
        assert_eq!(MatchKind::from_score(0.65), MatchKind::ModerateSimilarity);
        assert_eq!(MatchKind::from_score(0.0), MatchKind::Unmatched);
    }

    #[test]
    fn test_similarity_score_combined() {
        let s = SimilarityScore::from_components(1.0, 1.0, 1.0, 1.0);
        assert!((s.combined - 1.0).abs() < 1e-4);
    }

    #[test]
    fn test_similarity_score_is_high_confidence() {
        let s = SimilarityScore::from_components(1.0, 1.0, 1.0, 1.0);
        assert!(s.is_high_confidence());
        let s2 = SimilarityScore::from_components(0.1, 0.1, 0.1, 0.1);
        assert!(!s2.is_high_confidence());
    }

    #[test]
    fn test_jaccard_identical_sets() {
        let mut a = HashSet::new();
        a.insert(1u64); a.insert(2); a.insert(3);
        let b = a.clone();
        assert!((jaccard(&a, &b) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_jaccard_disjoint_sets() {
        let mut a = HashSet::new(); a.insert(1u64);
        let mut b = HashSet::new(); b.insert(2u64);
        assert!((jaccard(&a, &b) - 0.0).abs() < 1e-6);
    }

    #[test]
    fn test_sequence_similarity_identical() {
        let h = vec![0x10u64, 0x20, 0x30];
        assert!((sequence_similarity(&h, &h) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_sequence_similarity_empty() {
        assert!((sequence_similarity(&[], &[]) - 1.0).abs() < 1e-6);
        assert!((sequence_similarity(&[1u64], &[]) - 0.0).abs() < 1e-6);
    }

    #[test]
    fn test_one_to_one_constraint() {
        let a1 = make_func(0x1000, vec![0x01u64, 0x02], 2, 1);
        let a2 = make_func(0x1100, vec![0x01u64, 0x02], 2, 1);
        let b  = make_func(0x2000, vec![0x01u64, 0x02], 2, 1);
        let m = FunctionMatcher::new().with_min_score(0.0);
        let results = m.match_functions(&[a1, a2], &[b]);
        // one-to-one: only 1 A can claim the single B
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_many_to_many() {
        let a1 = make_func(0x1000, vec![0x01u64, 0x02], 2, 1);
        let a2 = make_func(0x1100, vec![0x01u64, 0x02], 2, 1);
        let b  = make_func(0x2000, vec![0x01u64, 0x02], 2, 1);
        let m = FunctionMatcher::new().with_min_score(0.0).many_to_many();
        let results = m.match_functions(&[a1, a2], &[b]);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_function_descriptor_builder() {
        let f = FunctionDescriptor::new(0x1000)
            .with_name("foo")
            .with_blocks(vec![1, 2, 3], 2)
            .with_calls(5);
        assert_eq!(f.name.as_deref(), Some("foo"));
        assert_eq!(f.block_count, 3);
        assert_eq!(f.call_count, 5);
    }

    #[test]
    fn test_sequence_hash_deterministic() {
        let f = FunctionDescriptor::new(0x1000).with_blocks(vec![1u64, 2, 3], 2);
        assert_eq!(f.sequence_hash(), f.sequence_hash());
    }
}
