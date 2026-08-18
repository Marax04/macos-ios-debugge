//! `BbMatching` — basic-block matching algorithm for BinDiff-style diffing.
//!
//! Computes per-block feature vectors, a similarity matrix, and a matching
//! that maximises total similarity across two sets of basic blocks.

use std::collections::HashMap;

/// Index that groups blocks by their feature-hash bucket, exposed so callers
/// driving incremental diffs can pre-build the same lookup table the internal
/// matcher uses.
pub type BlockFeatureBuckets = HashMap<u64, Vec<usize>>;

// ── BlockFeature ─────────────────────────────────────────────────────────────

/// Feature vector describing a single basic block.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockFeature {
    /// Number of instructions in the block.
    pub insn_count: u32,
    /// Number of outgoing edges (successor count).
    pub succ_count: u32,
    /// Number of incoming edges (predecessor count).
    pub pred_count: u32,
    /// Cyclomatic-style call count (calls inside the block).
    pub call_count: u32,
    /// Mnemonic prime-product hash (from `prime_product_hash`).
    pub mnemonic_hash: u64,
    /// Simple checksum of all constant operand values.
    pub const_checksum: u64,
    /// Block byte size.
    pub byte_size: u32,
    /// Whether this block ends with an unconditional jump.
    pub ends_unconditional: bool,
    /// Whether this block ends with a return instruction.
    pub ends_return: bool,
}

impl BlockFeature {
    /// Create a minimal feature vector.
    #[must_use]
    pub const fn new(insn_count: u32, byte_size: u32) -> Self {
        Self {
            insn_count,
            succ_count: 0,
            pred_count: 0,
            call_count: 0,
            mnemonic_hash: 0,
            const_checksum: 0,
            byte_size,
            ends_unconditional: false,
            ends_return: false,
        }
    }

    /// Structural equality ignoring hashes (used for coarse matching).
    #[must_use]
    pub const fn structurally_equal(&self, other: &Self) -> bool {
        self.insn_count == other.insn_count
            && self.succ_count == other.succ_count
            && self.pred_count == other.pred_count
    }

    /// Full equality including content hashes.
    #[must_use]
    pub fn content_equal(&self, other: &Self) -> bool {
        self.structurally_equal(other)
            && self.mnemonic_hash == other.mnemonic_hash
            && self.const_checksum == other.const_checksum
    }
}

// ── BlockSimilarity ───────────────────────────────────────────────────────────

/// Weighted similarity score between two basic blocks, in [0.0, 1.0].
#[derive(Debug, Clone, PartialEq)]
pub struct BlockSimilarity {
    /// Block index in the *old* function.
    pub old_idx: usize,
    /// Block index in the *new* function.
    pub new_idx: usize,
    /// Structural similarity (topology).
    pub structural: f64,
    /// Content similarity (mnemonics + constants).
    pub content: f64,
    /// Weighted combined score.
    pub combined: f64,
}

impl BlockSimilarity {
    /// Compute from two feature vectors using fixed weights.
    #[must_use]
    pub fn compute(old_idx: usize, new_idx: usize, a: &BlockFeature, b: &BlockFeature) -> Self {
        let structural = Self::structural_sim(a, b);
        let content = Self::content_sim(a, b);
        let combined = 0.4 * structural + 0.6 * content;
        Self {
            old_idx,
            new_idx,
            structural,
            content,
            combined,
        }
    }

    fn structural_sim(a: &BlockFeature, b: &BlockFeature) -> f64 {
        let mut matches = 0u32;
        let total = 3u32;
        if a.insn_count == b.insn_count {
            matches += 1;
        }
        if a.succ_count == b.succ_count {
            matches += 1;
        }
        if a.pred_count == b.pred_count {
            matches += 1;
        }
        matches as f64 / total as f64
    }

    fn content_sim(a: &BlockFeature, b: &BlockFeature) -> f64 {
        let mut score = 0.0f64;
        if a.mnemonic_hash == b.mnemonic_hash {
            score += 0.6;
        }
        if a.const_checksum == b.const_checksum {
            score += 0.4;
        }
        score
    }
}

// ── MatchingStrategy ──────────────────────────────────────────────────────────

/// Strategy controlling how the block matcher proceeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchingStrategy {
    /// Only accept exact content matches (hash equality).
    ExactOnly,
    /// Accept structural matches first, then fill with similarity.
    StructuralFirst,
    /// Full greedy similarity matching on the `NxM` matrix.
    GreedySimilarity,
    /// Hungarian algorithm for global optimum (O(n³)).
    Hungarian,
}

impl Default for MatchingStrategy {
    fn default() -> Self {
        Self::GreedySimilarity
    }
}

// ── ConfidenceScore ───────────────────────────────────────────────────────────

/// Confidence score for an individual block match.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfidenceScore {
    /// Combined similarity in [0.0, 1.0].
    pub score: f64,
    /// Whether the match was exact (hash equality).
    pub is_exact: bool,
    /// Whether the match was structurally identical.
    pub is_structural: bool,
}

impl ConfidenceScore {
    /// Construct from a similarity value.
    #[must_use]
    pub fn from_similarity(sim: f64) -> Self {
        Self {
            score: sim,
            is_exact: sim >= 1.0,
            is_structural: sim >= 0.6,
        }
    }

    /// Returns `true` if this match is considered high-confidence.
    #[must_use]
    pub fn is_high(&self) -> bool {
        self.score >= 0.75
    }

    /// Returns `true` if this is a low-confidence / tentative match.
    #[must_use]
    pub fn is_low(&self) -> bool {
        self.score < 0.4
    }
}

// ── BlockMatchReport ──────────────────────────────────────────────────────────

/// Summary report produced by `BbMatching::run`.
#[derive(Debug, Clone, Default)]
pub struct BlockMatchReport {
    /// Number of blocks in the old function.
    pub old_block_count: usize,
    /// Number of blocks in the new function.
    pub new_block_count: usize,
    /// Matched pairs: (`old_idx`, `new_idx`, confidence).
    pub matched: Vec<(usize, usize, ConfidenceScore)>,
    /// Old block indices with no match.
    pub unmatched_old: Vec<usize>,
    /// New block indices with no match.
    pub unmatched_new: Vec<usize>,
    /// Overall function similarity derived from block matches.
    pub function_similarity: f64,
    /// Strategy used for this run.
    pub strategy: MatchingStrategy,
}

impl BlockMatchReport {
    /// Fraction of old blocks that were matched.
    #[must_use]
    pub fn old_coverage(&self) -> f64 {
        if self.old_block_count == 0 {
            return 1.0;
        }
        self.matched.len() as f64 / self.old_block_count as f64
    }

    /// Fraction of new blocks that were matched.
    #[must_use]
    pub fn new_coverage(&self) -> f64 {
        if self.new_block_count == 0 {
            return 1.0;
        }
        self.matched.len() as f64 / self.new_block_count as f64
    }

    /// Returns only high-confidence matches.
    pub fn high_confidence_matches(&self) -> impl Iterator<Item = &(usize, usize, ConfidenceScore)> {
        self.matched.iter().filter(|(_, _, c)| c.is_high())
    }

    /// Number of exact matches.
    #[must_use]
    pub fn exact_match_count(&self) -> usize {
        self.matched.iter().filter(|(_, _, c)| c.is_exact).count()
    }
}

// ── BbMatching ────────────────────────────────────────────────────────────────

/// Main basic-block matching engine.
pub struct BbMatching {
    strategy: MatchingStrategy,
    /// Minimum similarity threshold; pairs below this are rejected.
    min_similarity: f64,
}

impl BbMatching {
    /// Create a new matcher with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            strategy: MatchingStrategy::default(),
            min_similarity: 0.1,
        }
    }

    /// Set the matching strategy.
    #[must_use]
    pub const fn with_strategy(mut self, s: MatchingStrategy) -> Self {
        self.strategy = s;
        self
    }

    /// Set the minimum similarity threshold.
    #[must_use]
    pub const fn with_min_similarity(mut self, t: f64) -> Self {
        // `clamp` propagates NaN; a NaN threshold rejects every block pair in
        // silence, because all comparisons against NaN are false.
        self.min_similarity = if t.is_nan() { 0.0 } else { t.clamp(0.0, 1.0) };
        self
    }

    /// Run the matcher on two sets of block features.
    ///
    /// Returns a `BlockMatchReport` describing all matches and unmatched blocks.
    #[must_use]
    pub fn run(
        &self,
        old_blocks: &[BlockFeature],
        new_blocks: &[BlockFeature],
    ) -> BlockMatchReport {
        let mut report = BlockMatchReport {
            old_block_count: old_blocks.len(),
            new_block_count: new_blocks.len(),
            strategy: self.strategy.clone(),
            ..Default::default()
        };

        match self.strategy {
            MatchingStrategy::ExactOnly => {
                self.exact_match(old_blocks, new_blocks, &mut report);
            }
            MatchingStrategy::StructuralFirst => {
                self.exact_match(old_blocks, new_blocks, &mut report);
                self.structural_fill(old_blocks, new_blocks, &mut report);
            }
            MatchingStrategy::GreedySimilarity => {
                self.greedy_similarity(old_blocks, new_blocks, &mut report);
            }
            MatchingStrategy::Hungarian => {
                self.hungarian_match(old_blocks, new_blocks, &mut report);
            }
        }

        // Compute unmatched sets
        let matched_old: std::collections::HashSet<usize> =
            report.matched.iter().map(|(o, _, _)| *o).collect();
        let matched_new: std::collections::HashSet<usize> =
            report.matched.iter().map(|(_, n, _)| *n).collect();
        report.unmatched_old = (0..old_blocks.len())
            .filter(|i| !matched_old.contains(i))
            .collect();
        report.unmatched_new = (0..new_blocks.len())
            .filter(|i| !matched_new.contains(i))
            .collect();

        // Compute function similarity
        report.function_similarity = self.function_similarity(&report, old_blocks, new_blocks);

        report
    }

    // ── Internal matching phases ──────────────────────────────────────────

    fn exact_match(
        &self,
        old_blocks: &[BlockFeature],
        new_blocks: &[BlockFeature],
        report: &mut BlockMatchReport,
    ) {
        let mut used_new: std::collections::HashSet<usize> = std::collections::HashSet::new();

        for (oi, old) in old_blocks.iter().enumerate() {
            for (ni, new) in new_blocks.iter().enumerate() {
                if used_new.contains(&ni) {
                    continue;
                }
                if old.content_equal(new) {
                    let conf = ConfidenceScore {
                        score: 1.0,
                        is_exact: true,
                        is_structural: true,
                    };
                    report.matched.push((oi, ni, conf));
                    used_new.insert(ni);
                    break;
                }
            }
        }
    }

    fn structural_fill(
        &self,
        old_blocks: &[BlockFeature],
        new_blocks: &[BlockFeature],
        report: &mut BlockMatchReport,
    ) {
        let matched_old: std::collections::HashSet<usize> =
            report.matched.iter().map(|(o, _, _)| *o).collect();
        // Must stay LIVE while this phase runs: a snapshot taken once up front
        // does not see the matches created below, so several `old` blocks could
        // all claim the same `new` block and the 1-to-1 invariant broke.
        // `exact_match` above already does this with its `used_new` set.
        let mut matched_new: std::collections::HashSet<usize> =
            report.matched.iter().map(|(_, n, _)| *n).collect();

        for (oi, old) in old_blocks.iter().enumerate() {
            if matched_old.contains(&oi) {
                continue;
            }
            for (ni, new) in new_blocks.iter().enumerate() {
                if matched_new.contains(&ni) {
                    continue;
                }
                if old.structurally_equal(new) {
                    let sim = BlockSimilarity::compute(oi, ni, old, new);
                    if sim.combined >= self.min_similarity {
                        let conf = ConfidenceScore::from_similarity(sim.combined);
                        report.matched.push((oi, ni, conf));
                        matched_new.insert(ni);
                        break;
                    }
                }
            }
        }
    }

    fn greedy_similarity(
        &self,
        old_blocks: &[BlockFeature],
        new_blocks: &[BlockFeature],
        report: &mut BlockMatchReport,
    ) {
        // Build full similarity matrix
        let mut pairs: Vec<BlockSimilarity> = Vec::new();
        for (oi, old) in old_blocks.iter().enumerate() {
            for (ni, new) in new_blocks.iter().enumerate() {
                let sim = BlockSimilarity::compute(oi, ni, old, new);
                if sim.combined >= self.min_similarity {
                    pairs.push(sim);
                }
            }
        }
        // Sort by descending combined score
        pairs.sort_by(|a, b| b.combined.partial_cmp(&a.combined).unwrap());

        let mut used_old = std::collections::HashSet::new();
        let mut used_new = std::collections::HashSet::new();

        for sim in pairs {
            if used_old.contains(&sim.old_idx) || used_new.contains(&sim.new_idx) {
                continue;
            }
            let conf = ConfidenceScore::from_similarity(sim.combined);
            report.matched.push((sim.old_idx, sim.new_idx, conf));
            used_old.insert(sim.old_idx);
            used_new.insert(sim.new_idx);
        }
    }

    fn hungarian_match(
        &self,
        old_blocks: &[BlockFeature],
        new_blocks: &[BlockFeature],
        report: &mut BlockMatchReport,
    ) {
        let n = old_blocks.len();
        let m = new_blocks.len();
        if n == 0 || m == 0 {
            return;
        }
        // Build cost matrix (1.0 - similarity, so minimise cost = maximise similarity)
        let dim = n.max(m);
        let mut cost = vec![vec![1.0f64; dim]; dim];
        for i in 0..n {
            for j in 0..m {
                let sim = BlockSimilarity::compute(i, j, &old_blocks[i], &new_blocks[j]);
                cost[i][j] = 1.0 - sim.combined;
            }
        }
        let assignment = hungarian_algorithm(&cost, dim);
        for (i, j) in assignment.into_iter().enumerate() {
            if i >= n || j >= m {
                continue;
            }
            let sim = 1.0 - cost[i][j];
            if sim < self.min_similarity {
                continue;
            }
            let conf = ConfidenceScore::from_similarity(sim);
            report.matched.push((i, j, conf));
        }
    }

    fn function_similarity(
        &self,
        report: &BlockMatchReport,
        old_blocks: &[BlockFeature],
        _new_blocks: &[BlockFeature],
    ) -> f64 {
        if old_blocks.is_empty() {
            return 1.0;
        }
        let sum: f64 = report.matched.iter().map(|(_, _, c)| c.score).sum();
        let denom = old_blocks.len().max(report.new_block_count) as f64;
        (sum / denom).min(1.0)
    }
}

impl Default for BbMatching {
    fn default() -> Self {
        Self::new()
    }
}

// ── Hungarian algorithm helper ────────────────────────────────────────────────

/// Minimal O(n³) Hungarian algorithm for square cost matrix.
/// Returns assignment[i] = j meaning row i is assigned to column j.
fn hungarian_algorithm(cost: &[Vec<f64>], n: usize) -> Vec<usize> {
    // Simple O(n^3) implementation via potential / label correction
    let inf = f64::INFINITY;
    let mut u = vec![0.0f64; n + 1];
    let mut v = vec![0.0f64; n + 1];
    let mut p = vec![0usize; n + 1]; // p[j] = row assigned to col j
    let mut way = vec![0usize; n + 1];

    for i in 1..=n {
        p[0] = i;
        let mut j0 = 0usize;
        let mut minv = vec![inf; n + 1];
        let mut used = vec![false; n + 1];
        loop {
            used[j0] = true;
            let i0 = p[j0];
            let mut delta = inf;
            let mut j1 = 0usize;
            for j in 1..=n {
                if !used[j] {
                    let i0z = if i0 == 0 { 0 } else { i0 - 1 };
                    let jz = j - 1;
                    let val = if i0 == 0 {
                        cost[0][jz]
                    } else {
                        cost[i0z][jz]
                    } - u[i0]
                        - v[j];
                    if val < minv[j] {
                        minv[j] = val;
                        way[j] = j0;
                    }
                    if minv[j] < delta {
                        delta = minv[j];
                        j1 = j;
                    }
                }
            }
            for j in 0..=n {
                if used[j] {
                    u[p[j]] += delta;
                    v[j] -= delta;
                } else {
                    minv[j] -= delta;
                }
            }
            j0 = j1;
            if p[j0] == 0 {
                break;
            }
        }
        loop {
            p[j0] = p[way[j0]];
            j0 = way[j0];
            if j0 == 0 {
                break;
            }
        }
    }

    // p[j] = row (1-based) assigned to col j (1-based)
    let mut assignment = vec![0usize; n];
    for j in 1..=n {
        if p[j] > 0 {
            assignment[p[j] - 1] = j - 1;
        }
    }
    assignment
}

// ── Similarity matrix helper ──────────────────────────────────────────────────

/// Build the full `NxM` similarity matrix for two feature sets.
#[must_use]
pub fn build_similarity_matrix(
    old_blocks: &[BlockFeature],
    new_blocks: &[BlockFeature],
) -> Vec<Vec<f64>> {
    old_blocks
        .iter()
        .enumerate()
        .map(|(oi, old)| {
            new_blocks
                .iter()
                .enumerate()
                .map(|(ni, new)| BlockSimilarity::compute(oi, ni, old, new).combined)
                .collect()
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn feat(insn: u32, succ: u32, pred: u32, mhash: u64, cchk: u64) -> BlockFeature {
        BlockFeature {
            insn_count: insn,
            succ_count: succ,
            pred_count: pred,
            call_count: 0,
            mnemonic_hash: mhash,
            const_checksum: cchk,
            byte_size: insn * 3,
            ends_unconditional: false,
            ends_return: false,
        }
    }

    // ── BlockFeature ─────────────────────────────────────────────────────

    #[test]
    fn test_feature_new() {
        let f = BlockFeature::new(5, 15);
        assert_eq!(f.insn_count, 5);
        assert_eq!(f.byte_size, 15);
    }

    #[test]
    fn test_structurally_equal_true() {
        let a = feat(3, 2, 1, 0xAA, 0xBB);
        let b = feat(3, 2, 1, 0xCC, 0xDD);
        assert!(a.structurally_equal(&b));
    }

    #[test]
    fn test_structurally_equal_false_insn() {
        let a = feat(3, 2, 1, 0, 0);
        let b = feat(4, 2, 1, 0, 0);
        assert!(!a.structurally_equal(&b));
    }

    #[test]
    fn test_content_equal_true() {
        let a = feat(3, 2, 1, 0xAA, 0xBB);
        let b = feat(3, 2, 1, 0xAA, 0xBB);
        assert!(a.content_equal(&b));
    }

    #[test]
    fn test_content_equal_false_hash() {
        let a = feat(3, 2, 1, 0xAA, 0xBB);
        let b = feat(3, 2, 1, 0xCC, 0xBB);
        assert!(!a.content_equal(&b));
    }

    // ── BlockSimilarity ───────────────────────────────────────────────────

    #[test]
    fn test_similarity_identical() {
        let a = feat(3, 2, 1, 0xDEAD, 0xBEEF);
        let b = feat(3, 2, 1, 0xDEAD, 0xBEEF);
        let sim = BlockSimilarity::compute(0, 0, &a, &b);
        assert!((sim.combined - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_similarity_completely_different() {
        let a = feat(1, 0, 0, 0x01, 0x01);
        let b = feat(9, 4, 4, 0xFF, 0xFF);
        let sim = BlockSimilarity::compute(0, 1, &a, &b);
        assert!(sim.combined < 0.5);
    }

    #[test]
    fn test_similarity_indices() {
        let a = feat(2, 1, 1, 0, 0);
        let b = feat(2, 1, 1, 0, 0);
        let sim = BlockSimilarity::compute(3, 7, &a, &b);
        assert_eq!(sim.old_idx, 3);
        assert_eq!(sim.new_idx, 7);
    }

    #[test]
    fn test_similarity_in_range() {
        let a = feat(5, 2, 1, 0xABCD, 0x1234);
        let b = feat(5, 3, 1, 0xABCD, 0x9999);
        let sim = BlockSimilarity::compute(0, 0, &a, &b);
        assert!(sim.combined >= 0.0 && sim.combined <= 1.0);
    }

    // ── ConfidenceScore ───────────────────────────────────────────────────

    #[test]
    fn test_confidence_exact() {
        let c = ConfidenceScore::from_similarity(1.0);
        assert!(c.is_exact);
        assert!(c.is_structural);
        assert!(c.is_high());
    }

    #[test]
    fn test_confidence_low() {
        let c = ConfidenceScore::from_similarity(0.2);
        assert!(!c.is_exact);
        assert!(c.is_low());
        assert!(!c.is_high());
    }

    #[test]
    fn test_confidence_structural() {
        let c = ConfidenceScore::from_similarity(0.65);
        assert!(c.is_structural);
        assert!(!c.is_low());
    }

    // ── BbMatching – ExactOnly ────────────────────────────────────────────

    #[test]
    fn test_exact_match_one_pair() {
        let old = vec![feat(3, 1, 0, 0xABC, 0x123)];
        let new = vec![feat(3, 1, 0, 0xABC, 0x123)];
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::ExactOnly)
            .run(&old, &new);
        assert_eq!(m.matched.len(), 1);
        assert!(m.matched[0].2.is_exact);
    }

    #[test]
    fn test_exact_match_no_match() {
        let old = vec![feat(3, 1, 0, 0xABC, 0x123)];
        let new = vec![feat(3, 1, 0, 0xDEF, 0x456)];
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::ExactOnly)
            .run(&old, &new);
        assert_eq!(m.matched.len(), 0);
        assert_eq!(m.unmatched_old.len(), 1);
        assert_eq!(m.unmatched_new.len(), 1);
    }

    #[test]
    fn test_exact_match_multiple() {
        let old = vec![
            feat(2, 1, 0, 0x10, 0x20),
            feat(5, 2, 1, 0x30, 0x40),
        ];
        let new = vec![
            feat(5, 2, 1, 0x30, 0x40),
            feat(2, 1, 0, 0x10, 0x20),
        ];
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::ExactOnly)
            .run(&old, &new);
        assert_eq!(m.matched.len(), 2);
    }

    // ── BbMatching – StructuralFirst ──────────────────────────────────────

    #[test]
    fn test_structural_first_fallback() {
        // exact hash differs but structure matches
        let old = vec![feat(3, 2, 1, 0xAA, 0xBB)];
        let new = vec![feat(3, 2, 1, 0xCC, 0xDD)];
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::StructuralFirst)
            .with_min_similarity(0.0)
            .run(&old, &new);
        assert_eq!(m.matched.len(), 1);
        assert!(!m.matched[0].2.is_exact);
    }

    // ── BbMatching – GreedySimilarity ─────────────────────────────────────

    #[test]
    fn test_greedy_all_match() {
        let blocks: Vec<BlockFeature> = (0u64..4)
            .map(|i| feat(i as u32 + 1, 1, 0, i * 100, i * 200))
            .collect();
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::GreedySimilarity)
            .run(&blocks, &blocks);
        assert_eq!(m.matched.len(), 4);
        for (_, _, c) in &m.matched {
            assert!(c.is_exact);
        }
    }

    #[test]
    fn test_greedy_partial_match() {
        let old = vec![
            feat(1, 0, 0, 0x01, 0x01),
            feat(2, 1, 0, 0x02, 0x02),
        ];
        let new = vec![
            feat(2, 1, 0, 0x02, 0x02),
            feat(9, 5, 3, 0xFF, 0xFF),
        ];
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::GreedySimilarity)
            .with_min_similarity(0.0)
            .run(&old, &new);
        // block 1 (insn=2) should match new block 0 (insn=2, same hash)
        let has_exact = m.matched.iter().any(|(_, _, c)| c.is_exact);
        assert!(has_exact);
    }

    #[test]
    fn test_greedy_no_below_threshold() {
        let old = vec![feat(1, 0, 0, 0x01, 0x01)];
        let new = vec![feat(9, 5, 5, 0xFF, 0xFF)];
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::GreedySimilarity)
            .with_min_similarity(0.9)
            .run(&old, &new);
        assert_eq!(m.matched.len(), 0);
    }

    // ── BbMatching – Hungarian ────────────────────────────────────────────

    #[test]
    fn test_hungarian_identical() {
        let blocks: Vec<BlockFeature> = (0u64..3)
            .map(|i| feat(i as u32 + 1, 1, 0, i * 111, i * 222))
            .collect();
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::Hungarian)
            .run(&blocks, &blocks);
        assert_eq!(m.matched.len(), 3);
    }

    #[test]
    fn test_hungarian_empty_old() {
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::Hungarian)
            .run(&[], &[feat(1, 0, 0, 0, 0)]);
        assert_eq!(m.matched.len(), 0);
        assert_eq!(m.unmatched_new.len(), 1);
    }

    #[test]
    fn test_hungarian_empty_new() {
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::Hungarian)
            .run(&[feat(1, 0, 0, 0, 0)], &[]);
        assert_eq!(m.matched.len(), 0);
        assert_eq!(m.unmatched_old.len(), 1);
    }

    // ── BlockMatchReport ─────────────────────────────────────────────────

    #[test]
    fn test_report_old_coverage() {
        let old = vec![feat(1, 0, 0, 0, 0), feat(2, 0, 0, 0, 0)];
        let new = vec![feat(1, 0, 0, 0, 0)];
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::ExactOnly)
            .run(&old, &new);
        // only 1 of 2 old blocks matched
        assert!((m.old_coverage() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_report_function_similarity_identical() {
        let blocks = vec![feat(3, 1, 0, 0xABC, 0x123)];
        let m = BbMatching::new().run(&blocks, &blocks);
        assert!(m.function_similarity > 0.9);
    }

    #[test]
    fn test_report_exact_match_count() {
        let blocks = vec![
            feat(1, 0, 0, 0x01, 0x01),
            feat(2, 0, 0, 0x02, 0x02),
        ];
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::ExactOnly)
            .run(&blocks, &blocks);
        assert_eq!(m.exact_match_count(), 2);
    }

    #[test]
    fn test_report_unmatched() {
        let old = vec![
            feat(1, 0, 0, 0x01, 0x01),
            feat(2, 0, 0, 0x02, 0x02),
        ];
        let new = vec![feat(1, 0, 0, 0x01, 0x01)];
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::ExactOnly)
            .run(&old, &new);
        assert_eq!(m.unmatched_old.len(), 1);
        assert_eq!(m.unmatched_new.len(), 0);
    }

    // ── build_similarity_matrix ───────────────────────────────────────────

    #[test]
    fn test_build_similarity_matrix_shape() {
        let old = vec![feat(1, 0, 0, 0, 0), feat(2, 0, 0, 0, 0)];
        let new = vec![feat(1, 0, 0, 0, 0), feat(2, 0, 0, 0, 0), feat(3, 0, 0, 0, 0)];
        let mat = build_similarity_matrix(&old, &new);
        assert_eq!(mat.len(), 2);
        assert_eq!(mat[0].len(), 3);
    }

    #[test]
    fn test_build_similarity_matrix_diagonal_identity() {
        let blocks = vec![feat(3, 2, 1, 0xDE, 0xAD)];
        let mat = build_similarity_matrix(&blocks, &blocks);
        assert!((mat[0][0] - 1.0).abs() < 1e-9);
    }

    // ── Hungarian helper ──────────────────────────────────────────────────

    #[test]
    fn test_hungarian_1x1() {
        let cost = vec![vec![0.3]];
        let a = hungarian_algorithm(&cost, 1);
        assert_eq!(a[0], 0);
    }

    #[test]
    fn test_hungarian_2x2() {
        // optimal: row 0 → col 1 (cost 0.1), row 1 → col 0 (cost 0.2)
        let cost = vec![vec![0.5, 0.1], vec![0.2, 0.8]];
        let a = hungarian_algorithm(&cost, 2);
        assert_eq!(a[0], 1);
        assert_eq!(a[1], 0);
    }

    // ── Edge cases ────────────────────────────────────────────────────────

    #[test]
    fn test_run_empty_both() {
        let m = BbMatching::new().run(&[], &[]);
        assert_eq!(m.matched.len(), 0);
        assert_eq!(m.function_similarity, 1.0);
    }

    #[test]
    fn test_min_similarity_zero_allows_all() {
        let old = vec![feat(1, 0, 0, 0x01, 0x01)];
        let new = vec![feat(9, 5, 5, 0xFF, 0xFF)];
        let m = BbMatching::new()
            .with_strategy(MatchingStrategy::GreedySimilarity)
            .with_min_similarity(0.0)
            .run(&old, &new);
        assert_eq!(m.matched.len(), 1);
    }

    #[test]
    fn test_default_strategy_is_greedy() {
        let m = BbMatching::new();
        assert_eq!(m.strategy, MatchingStrategy::GreedySimilarity);
    }

    #[test]
    fn test_high_confidence_filter() {
        let old = vec![
            feat(3, 1, 0, 0xABC, 0x123), // exact match → high confidence
            feat(9, 5, 5, 0xFF, 0xFF),   // no match
        ];
        let new = vec![feat(3, 1, 0, 0xABC, 0x123)];
        let m = BbMatching::new().run(&old, &new);
        let high: Vec<_> = m.high_confidence_matches().collect();
        assert!(!high.is_empty());
    }
}
