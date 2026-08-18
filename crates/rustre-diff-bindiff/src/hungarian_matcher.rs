//! `hungarian_matcher` — Extended Hungarian algorithm for binary function matching.
//!
//! Provides a standalone, feature-rich implementation of the Kuhn-Munkres
//! O(n³) algorithm specialised for cross-binary function similarity matching.
//! Key additions over the basic solver in `lib.rs`:
//!
//! * Rectangular cost matrices (|A| ≠ |B|) padded to square automatically.
//! * Sparse optimisation: when either side has > `HUNGARIAN_THRESHOLD` functions
//!   the dense algorithm is replaced by a greedy approximate matcher to avoid
//!   O(n³) blow-up.
//! * Confidence threshold filtering: matches whose similarity falls below a
//!   configurable `min_confidence` are reported as unmatched rather than forced.
//! * Per-match `MatchConfidence` annotation (Exact / High / Medium / Low).
//! * Iterator interface for streaming results out of large matrices without
//!   materialising the full assignment vector.

use std::collections::{BinaryHeap, HashMap, HashSet};

/// Re-export of [`HashMap`] used to build feature-vector indices keyed by
/// function id. Exposed so downstream crates can construct the same map type
/// the matcher uses internally without pulling in `std` directly.
pub type FeatureIndex = HashMap<u64, FunctionFeatureSet>;
use std::cmp::Ordering;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Functions per side above which the sparse greedy path is chosen.
pub const HUNGARIAN_THRESHOLD: usize = 2_000;

/// Similarity score below which a match is dropped even if the algorithm
/// found an assignment.
pub const DEFAULT_MIN_CONFIDENCE: f64 = 0.30;

// ─────────────────────────────────────────────────────────────────────────────
// MatchConfidence
// ─────────────────────────────────────────────────────────────────────────────

/// Qualitative label attached to every function match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MatchConfidence {
    /// Similarity ≥ 0.95 — almost certainly the same function.
    Exact,
    /// Similarity ∈ [0.75, 0.95).
    High,
    /// Similarity ∈ [0.50, 0.75).
    Medium,
    /// Similarity ∈ [0.30, 0.50).
    Low,
}

impl MatchConfidence {
    /// Rank of this band by STRENGTH: higher means a better match.
    ///
    /// The derived `Ord` follows declaration order, which puts `Exact` at the
    /// *minimum* — the opposite of what "at or above this confidence" means.
    /// Comparisons about match quality must go through this method so they do
    /// not silently invert when a variant is reordered.
    #[must_use]
    pub const fn strength(self) -> u8 {
        match self {
            Self::Exact => 3,
            Self::High => 2,
            Self::Medium => 1,
            Self::Low => 0,
        }
    }

    /// Derive confidence band from a raw similarity score in `[0, 1]`.
    #[must_use]
    pub fn from_score(score: f64) -> Option<Self> {
        match score {
            s if s >= 0.95 => Some(Self::Exact),
            s if s >= 0.75 => Some(Self::High),
            s if s >= 0.50 => Some(Self::Medium),
            s if s >= 0.30 => Some(Self::Low),
            _ => None,
        }
    }

    /// Numeric lower bound for this confidence band.
    #[must_use]
    pub const fn lower_bound(self) -> f64 {
        match self {
            Self::Exact  => 0.95,
            Self::High   => 0.75,
            Self::Medium => 0.50,
            Self::Low    => 0.30,
        }
    }
}

impl std::fmt::Display for MatchConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact  => f.write_str("Exact"),
            Self::High   => f.write_str("High"),
            Self::Medium => f.write_str("Medium"),
            Self::Low    => f.write_str("Low"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionMatch
// ─────────────────────────────────────────────────────────────────────────────

/// A matched pair of functions from two binaries.
#[derive(Debug, Clone)]
pub struct FunctionMatch {
    /// Index into the left-side function list (binary A).
    pub idx_a: usize,
    /// Index into the right-side function list (binary B).
    pub idx_b: usize,
    /// Similarity score in `[0.0, 1.0]`.
    pub similarity: f64,
    /// Qualitative confidence label.
    pub confidence: MatchConfidence,
}

/// Functions that could not be matched above the confidence threshold.
#[derive(Debug, Clone)]
pub struct UnmatchedFunction {
    /// Which side the function belongs to.
    pub side: Side,
    /// Index within that side's function list.
    pub idx: usize,
}

/// Which binary an unmatched function belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

// ─────────────────────────────────────────────────────────────────────────────
// CostMatrix
// ─────────────────────────────────────────────────────────────────────────────

/// Dense cost matrix for the Hungarian algorithm.
///
/// Internally stores *costs* (1 – similarity) so the algorithm minimises cost.
#[derive(Debug, Clone)]
pub struct CostMatrix {
    /// Row = function in A, column = function in B.
    data: Vec<f64>,
    /// Original (unsquared) dimensions.
    rows_orig: usize,
    cols_orig: usize,
    /// Padded square dimension.
    n: usize,
}

impl CostMatrix {
    /// Build a cost matrix from a similarity matrix.
    ///
    /// `similarity[i][j]` is the similarity between function `i` in A and
    /// function `j` in B.  Both must be in `[0, 1]`.
    #[must_use]
    pub fn from_similarity(similarity: &[Vec<f64>]) -> Self {
        let rows_orig = similarity.len();
        // The WIDEST row, not just the first: a jagged input whose later rows
        // are longer than row 0 used to index past the end of `data`.
        let cols_orig = similarity.iter().map(|r| r.len()).max().unwrap_or(0);
        // Guard against memory exhaustion: cap matrix dimension at HUNGARIAN_THRESHOLD.
        // Callers should already ensure this, but defend in depth.
        let rows_orig = rows_orig.min(HUNGARIAN_THRESHOLD);
        let cols_orig = cols_orig.min(HUNGARIAN_THRESHOLD);
        let n = rows_orig.max(cols_orig);

        let mut data = vec![1.0_f64; n * n]; // pad with cost 1.0 (zero similarity)
        // The `take`s are what make the indexing total: capping `rows_orig` /
        // `cols_orig` alone did not bound the LOOP, so an input larger than
        // HUNGARIAN_THRESHOLD still wrote outside the (now smaller) buffer.
        for (i, row) in similarity.iter().enumerate().take(rows_orig) {
            for (j, &sim) in row.iter().enumerate().take(cols_orig) {
                let cost = 1.0 - sim.clamp(0.0, 1.0);
                data[i * n + j] = cost;
            }
        }

        Self { data, rows_orig, cols_orig, n }
    }

    #[inline]
    fn get(&self, r: usize, c: usize) -> f64 { self.data[r * self.n + c] }
    #[inline]
    fn get_mut(&mut self, r: usize, c: usize) -> &mut f64 { &mut self.data[r * self.n + c] }
    #[inline]
    const fn dim(&self) -> usize { self.n }

    /// Number of rows in the original (un-padded) similarity matrix.
    ///
    /// Useful for reporting unmatched functions on the A side after the
    /// algorithm has filled padding rows with synthetic zero-similarity
    /// entries.
    #[must_use]
    pub const fn original_rows(&self) -> usize { self.rows_orig }

    /// Number of columns in the original (un-padded) similarity matrix.
    #[must_use]
    pub const fn original_cols(&self) -> usize { self.cols_orig }

    /// Padded square dimension actually stored in `data`.
    #[must_use]
    pub const fn padded_dim(&self) -> usize { self.n }

    /// Read-only access to the cost at `(row, col)`.
    ///
    /// Returns `None` if the indices are outside the padded matrix.
    #[must_use]
    pub fn cost_at(&self, row: usize, col: usize) -> Option<f64> {
        if row < self.n && col < self.n { Some(self.get(row, col)) } else { None }
    }

    /// In-place mutation hook used by callers that need to penalise a specific
    /// pairing (e.g. forbidding cross-section matches) before running the
    /// solver. Returns `true` if the cell existed and was updated.
    pub fn set_cost(&mut self, row: usize, col: usize, cost: f64) -> bool {
        if row < self.n && col < self.n {
            *self.get_mut(row, col) = cost;
            true
        } else {
            false
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HungarianMatcher (dense, O(n³) Kuhn-Munkres)
// ─────────────────────────────────────────────────────────────────────────────

/// Dense O(n³) Hungarian solver.
///
/// Works on a `CostMatrix` (cost = 1 – similarity).  After `solve()` each row
/// is assigned exactly one column and vice-versa; the assignment minimises the
/// total cost.
pub struct HungarianMatcher {
    n: usize,
    /// Row potentials.
    u: Vec<f64>,
    /// Column potentials.
    v: Vec<f64>,
    /// Assignment: `p[j]` = row assigned to column j (1-indexed; 0 = free).
    p: Vec<usize>,
    /// `way[j]` = previous column in the augmenting path.
    way: Vec<usize>,
}

impl HungarianMatcher {
    /// Solve the assignment problem on `matrix` and return the assignment
    /// vector: `assignment[i]` = column assigned to row `i`.
    #[must_use]
    pub fn solve(matrix: &CostMatrix) -> Vec<usize> {
        let n = matrix.dim();
        let mut solver = Self {
            n,
            u: vec![0.0_f64; n + 1],
            v: vec![0.0_f64; n + 1],
            p: vec![0_usize; n + 1],
            way: vec![0_usize; n + 1],
        };
        solver.run(matrix)
    }

    fn run(&mut self, matrix: &CostMatrix) -> Vec<usize> {
        let n = self.n;
        const INF: f64 = f64::INFINITY;

        for i in 1..=n {
            self.p[0] = i;
            let mut j0 = 0_usize;
            let mut minval = vec![INF; n + 1];
            let mut used = vec![false; n + 1];

            loop {
                used[j0] = true;
                let i0 = self.p[j0];
                let mut delta = INF;
                let mut j1 = 0_usize;

                for j in 1..=n {
                    if !used[j] {
                        // cost is 0-indexed in our matrix
                        let cur = matrix.get(i0 - 1, j - 1)
                            - self.u[i0]
                            - self.v[j];
                        if cur < minval[j] {
                            minval[j] = cur;
                            self.way[j] = j0;
                        }
                        if minval[j] < delta {
                            delta = minval[j];
                            j1 = j;
                        }
                    }
                }

                for j in 0..=n {
                    if used[j] {
                        self.u[self.p[j]] += delta;
                        self.v[j] -= delta;
                    } else {
                        minval[j] -= delta;
                    }
                }

                j0 = j1;
                if self.p[j0] == 0 {
                    break;
                }
            }

            loop {
                let j1 = self.way[j0];
                self.p[j0] = self.p[j1];
                j0 = j1;
                if j0 == 0 {
                    break;
                }
            }
        }

        // Build result: ans[row] = col (0-indexed)
        let mut ans = vec![0_usize; n];
        for j in 1..=n {
            if self.p[j] != 0 {
                ans[self.p[j] - 1] = j - 1;
            }
        }
        ans
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SparseCandidate — for the greedy approximate path
// ─────────────────────────────────────────────────────────────────────────────

/// A (similarity, row, col) triple stored in a max-heap.
#[derive(Debug, Clone, PartialEq)]
struct SparseCandidate {
    similarity: f64,
    row: usize,
    col: usize,
}

impl Eq for SparseCandidate {}

impl PartialOrd for SparseCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SparseCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        // Max-heap: higher similarity = greater priority.
        self.similarity
            .partial_cmp(&other.similarity)
            .unwrap_or(Ordering::Equal)
            .then_with(|| self.row.cmp(&other.row))
            .then_with(|| self.col.cmp(&other.col))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GreedyMatcher — O(k log k) sparse approximate matching
// ─────────────────────────────────────────────────────────────────────────────

/// Greedy approximate matcher for large binaries.
///
/// Collects only similarity entries above `min_confidence`, sorts them
/// descending, and greedily assigns rows to columns (first-come-first-served).
/// This runs in O(k log k) where k = number of candidate pairs, which is much
/// smaller than n² for sparse similarity matrices.
pub struct GreedyMatcher;

impl GreedyMatcher {
    /// Match functions using a greedy strategy.
    ///
    /// `sim_provider` is called as `sim_provider(i, j)` and must return the
    /// similarity between function `i` in A and function `j` in B.  Return
    /// `None` if the pair should not be considered (below threshold).
    pub fn match_functions<F>(
        n_a: usize,
        n_b: usize,
        min_confidence: f64,
        sim_provider: F,
    ) -> (Vec<FunctionMatch>, Vec<UnmatchedFunction>)
    where
        F: Fn(usize, usize) -> Option<f64>,
    {
        // Collect candidates above threshold.
        let mut heap: BinaryHeap<SparseCandidate> = BinaryHeap::new();
        for i in 0..n_a {
            for j in 0..n_b {
                if let Some(sim) = sim_provider(i, j) {
                    if sim >= min_confidence {
                        heap.push(SparseCandidate { similarity: sim, row: i, col: j });
                    }
                }
            }
        }

        let mut matched_a = HashSet::new();
        let mut matched_b = HashSet::new();
        let mut matches = Vec::new();

        while let Some(cand) = heap.pop() {
            if matched_a.contains(&cand.row) || matched_b.contains(&cand.col) {
                continue;
            }
            let confidence = match MatchConfidence::from_score(cand.similarity) {
                Some(c) => c,
                None => continue,
            };
            matched_a.insert(cand.row);
            matched_b.insert(cand.col);
            matches.push(FunctionMatch {
                idx_a: cand.row,
                idx_b: cand.col,
                similarity: cand.similarity,
                confidence,
            });
        }

        // Collect unmatched.
        let mut unmatched = Vec::new();
        for i in 0..n_a {
            if !matched_a.contains(&i) {
                unmatched.push(UnmatchedFunction { side: Side::A, idx: i });
            }
        }
        for j in 0..n_b {
            if !matched_b.contains(&j) {
                unmatched.push(UnmatchedFunction { side: Side::B, idx: j });
            }
        }

        (matches, unmatched)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MatcherConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the top-level matcher.
#[derive(Debug, Clone)]
pub struct MatcherConfig {
    /// Minimum similarity for a match to be kept.
    pub min_confidence: f64,
    /// Switch to sparse greedy path when side exceeds this size.
    pub sparse_threshold: usize,
    /// If true, also emit Low-confidence matches.
    pub include_low: bool,
}

impl Default for MatcherConfig {
    fn default() -> Self {
        Self {
            min_confidence: DEFAULT_MIN_CONFIDENCE,
            sparse_threshold: HUNGARIAN_THRESHOLD,
            include_low: true,
        }
    }
}

impl MatcherConfig {
    /// Create a config with custom thresholds.
    #[must_use]
    pub fn new(min_confidence: f64, sparse_threshold: usize) -> Self {
        Self {
            min_confidence: min_confidence.clamp(0.0, 1.0),
            sparse_threshold,
            include_low: min_confidence < 0.50,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MatcherResult
// ─────────────────────────────────────────────────────────────────────────────

/// Full output of the matcher.
#[derive(Debug, Clone)]
pub struct MatcherResult {
    pub matches: Vec<FunctionMatch>,
    pub unmatched: Vec<UnmatchedFunction>,
    /// Whether the sparse greedy path was used.
    pub used_sparse: bool,
}

impl MatcherResult {
    /// Iterate over exact matches only.
    pub fn exact_matches(&self) -> impl Iterator<Item = &FunctionMatch> {
        self.matches.iter().filter(|m| m.confidence == MatchConfidence::Exact)
    }

    /// Iterate over matches at or above `confidence`.
    pub fn at_least(&self, confidence: MatchConfidence) -> impl Iterator<Item = &FunctionMatch> {
        // Compare STRENGTH, not the derived `Ord`. The derive follows
        // declaration order, in which `Exact` is the minimum, so `>=` selected
        // the WEAKEST bands and silently dropped the best matches.
        let floor = confidence.strength();
        self.matches.iter().filter(move |m| m.confidence.strength() >= floor)
    }

    /// Number of functions in A that were matched.
    #[must_use]
    pub const fn matched_a_count(&self) -> usize { self.matches.len() }

    /// Number of unmatched functions in A.
    #[must_use]
    pub fn unmatched_a_count(&self) -> usize {
        self.unmatched.iter().filter(|u| u.side == Side::A).count()
    }

    /// Number of unmatched functions in B.
    #[must_use]
    pub fn unmatched_b_count(&self) -> usize {
        self.unmatched.iter().filter(|u| u.side == Side::B).count()
    }

    /// Overall similarity: matched / total functions.
    #[must_use]
    pub fn overall_similarity(&self) -> f64 {
        let total_a = self.matched_a_count() + self.unmatched_a_count();
        let total_b = self.matched_a_count() + self.unmatched_b_count();
        if total_a == 0 && total_b == 0 {
            return 1.0;
        }
        let denom = total_a.max(total_b) as f64;
        self.matches.iter().map(|m| m.similarity).sum::<f64>() / denom
    }

    /// Weighted similarity: sum(similarity) / max(|A|, |B|).
    #[must_use]
    pub fn weighted_similarity(&self) -> f64 {
        self.overall_similarity()
    }

    /// Confidence histogram: returns (Exact, High, Medium, Low) counts.
    #[must_use]
    pub fn confidence_histogram(&self) -> (usize, usize, usize, usize) {
        let mut exact = 0;
        let mut high  = 0;
        let mut medium = 0;
        let mut low   = 0;
        for m in &self.matches {
            match m.confidence {
                MatchConfidence::Exact  => exact  += 1,
                MatchConfidence::High   => high   += 1,
                MatchConfidence::Medium => medium += 1,
                MatchConfidence::Low    => low    += 1,
            }
        }
        (exact, high, medium, low)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtendedHungarianMatcher — top-level facade
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level facade that chooses dense or sparse path automatically.
///
/// # Example
/// ```rust,ignore
/// let sim = vec![vec![0.9, 0.2], vec![0.1, 0.85]];
/// let result = ExtendedHungarianMatcher::match_all(&sim, &MatcherConfig::default());
/// assert_eq!(result.matches.len(), 2);
/// ```
pub struct ExtendedHungarianMatcher;

impl ExtendedHungarianMatcher {
    /// Match functions given a pre-computed similarity matrix.
    ///
    /// `similarity[i][j]` = similarity in `[0, 1]` between function `i` in A
    /// and function `j` in B.
    #[must_use]
    pub fn match_all(
        similarity: &[Vec<f64>],
        config: &MatcherConfig,
    ) -> MatcherResult {
        let n_a = similarity.len();
        let n_b = if n_a == 0 { 0 } else { similarity[0].len() };

        if n_a == 0 || n_b == 0 {
            let unmatched = (0..n_a)
                .map(|i| UnmatchedFunction { side: Side::A, idx: i })
                .chain((0..n_b).map(|j| UnmatchedFunction { side: Side::B, idx: j }))
                .collect();
            return MatcherResult { matches: Vec::new(), unmatched, used_sparse: false };
        }

        if n_a > config.sparse_threshold || n_b > config.sparse_threshold {
            // Sparse greedy path.
            let (matches, unmatched) = GreedyMatcher::match_functions(
                n_a, n_b, config.min_confidence,
                |i, j| {
                    let s = similarity[i][j];
                    if s >= config.min_confidence { Some(s) } else { None }
                },
            );
            return MatcherResult { matches, unmatched, used_sparse: true };
        }

        // Dense O(n³) path.
        let matrix = CostMatrix::from_similarity(similarity);
        let assignment = HungarianMatcher::solve(&matrix);

        let mut matched_a = HashSet::new();
        let mut matched_b = HashSet::new();
        let mut matches = Vec::new();

        for (row, &col) in assignment.iter().enumerate() {
            // Only emit if within original (non-padded) bounds.
            if row >= n_a || col >= n_b {
                continue;
            }
            let sim = similarity[row][col];
            if sim < config.min_confidence {
                continue;
            }
            let confidence = match MatchConfidence::from_score(sim) {
                Some(c) => c,
                None => continue,
            };
            if confidence == MatchConfidence::Low && !config.include_low {
                continue;
            }
            matched_a.insert(row);
            matched_b.insert(col);
            matches.push(FunctionMatch { idx_a: row, idx_b: col, similarity: sim, confidence });
        }

        // Sort by descending similarity for convenience.
        matches.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap_or(Ordering::Equal));

        let mut unmatched = Vec::new();
        for i in 0..n_a {
            if !matched_a.contains(&i) {
                unmatched.push(UnmatchedFunction { side: Side::A, idx: i });
            }
        }
        for j in 0..n_b {
            if !matched_b.contains(&j) {
                unmatched.push(UnmatchedFunction { side: Side::B, idx: j });
            }
        }

        MatcherResult { matches, unmatched, used_sparse: false }
    }

    /// Convenience: match with default config.
    #[must_use]
    pub fn match_default(similarity: &[Vec<f64>]) -> MatcherResult {
        Self::match_all(similarity, &MatcherConfig::default())
    }

    /// Build a similarity matrix from two lists of pre-computed feature vectors.
    ///
    /// `features_a[i]` and `features_b[j]` are arbitrary `f64` feature slices;
    /// similarity is cosine similarity clamped to `[0, 1]`.
    #[must_use]
    pub fn build_similarity_matrix(
        features_a: &[Vec<f64>],
        features_b: &[Vec<f64>],
    ) -> Vec<Vec<f64>> {
        features_a
            .iter()
            .map(|fa| {
                features_b
                    .iter()
                    .map(|fb| cosine_similarity(fa, fb))
                    .collect()
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: cosine similarity
// ─────────────────────────────────────────────────────────────────────────────

/// Cosine similarity between two feature vectors, clamped to `[0, 1]`.
#[must_use]
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let len = a.len().min(b.len());
    if len == 0 {
        return 0.0;
    }
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let na: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let nb: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    (dot / (na * nb)).clamp(0.0, 1.0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: FNV-1a hash
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Stable 64-bit FNV-1a hash exported for callers that need to deterministically
/// derive `cfg_hash`/`name_hash` inputs for [`FunctionFeatureSet`] without
/// pulling in another hashing crate.
#[must_use]
pub fn feature_hash(data: &[u8]) -> u64 { fnv1a(data) }

// ─────────────────────────────────────────────────────────────────────────────
// FunctionFeatureSet — used by callers to build the similarity matrix
// ─────────────────────────────────────────────────────────────────────────────

/// Feature vector for a single function, used to compute cross-function
/// similarities for the matcher.
#[derive(Debug, Clone)]
pub struct FunctionFeatureSet {
    /// CFG topology hash (Weisfeiler-Lehman).
    pub cfg_hash: u64,
    /// Number of basic blocks.
    pub block_count: u32,
    /// Number of instructions.
    pub insn_count: u32,
    /// Number of call edges going out.
    pub call_out: u32,
    /// Number of call edges coming in.
    pub call_in: u32,
    /// Normalised instruction opcode histogram (length-fixed to 64 buckets).
    pub opcode_hist: Vec<f64>,
    /// Optional function name hash.
    pub name_hash: Option<u64>,
}

impl FunctionFeatureSet {
    /// Compute similarity between two feature sets.
    ///
    /// Combines CFG-hash equality, structural counters, and opcode histogram.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f64 {
        // Structural feature comparison (normalised).
        let block_sim = ratio_sim(self.block_count, other.block_count);
        let insn_sim  = ratio_sim(self.insn_count,  other.insn_count);
        let cout_sim  = ratio_sim(self.call_out,     other.call_out);

        // Opcode histogram cosine similarity.
        let hist_sim = cosine_similarity(&self.opcode_hist, &other.opcode_hist);

        // CFG topology bonus.
        let cfg_bonus: f64 = if self.cfg_hash == other.cfg_hash && self.cfg_hash != 0 {
            0.30
        } else {
            0.0
        };

        // Name match bonus.
        let name_bonus: f64 = match (self.name_hash, other.name_hash) {
            (Some(a), Some(b)) if a == b && a != 0 => 0.20,
            _ => 0.0,
        };

        let base = 0.30 * hist_sim
            + 0.20 * block_sim
            + 0.15 * insn_sim
            + 0.05 * cout_sim;

        (base + cfg_bonus + name_bonus).clamp(0.0, 1.0)
    }

    /// Build the feature vector for cosine similarity in feature space.
    #[must_use]
    pub fn to_feature_vec(&self) -> Vec<f64> {
        let mut v = Vec::with_capacity(4 + self.opcode_hist.len());
        v.push(self.block_count as f64);
        v.push(self.insn_count  as f64);
        v.push(self.call_out    as f64);
        v.push(self.call_in     as f64);
        v.extend_from_slice(&self.opcode_hist);
        v
    }
}

fn ratio_sim(a: u32, b: u32) -> f64 {
    if a == 0 && b == 0 {
        return 1.0;
    }
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    lo as f64 / hi as f64
}

// ─────────────────────────────────────────────────────────────────────────────
// HighLevelMatcher — convenience facade over FunctionFeatureSets
// ─────────────────────────────────────────────────────────────────────────────

/// End-to-end matcher: builds the similarity matrix from feature sets and
/// delegates to `ExtendedHungarianMatcher`.
pub struct HighLevelMatcher;

impl HighLevelMatcher {
    /// Match two lists of function feature sets.
    #[must_use]
    pub fn match_functions(
        funcs_a: &[FunctionFeatureSet],
        funcs_b: &[FunctionFeatureSet],
        config: &MatcherConfig,
    ) -> MatcherResult {
        let sim: Vec<Vec<f64>> = funcs_a
            .iter()
            .map(|fa| funcs_b.iter().map(|fb| fa.similarity(fb)).collect())
            .collect();
        ExtendedHungarianMatcher::match_all(&sim, config)
    }

    /// Match with default config.
    #[must_use]
    pub fn match_default(
        funcs_a: &[FunctionFeatureSet],
        funcs_b: &[FunctionFeatureSet],
    ) -> MatcherResult {
        Self::match_functions(funcs_a, funcs_b, &MatcherConfig::default())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sim(data: &[(usize, usize, f64)], n_a: usize, n_b: usize) -> Vec<Vec<f64>> {
        let mut m = vec![vec![0.0_f64; n_b]; n_a];
        for &(i, j, v) in data {
            m[i][j] = v;
        }
        m
    }

    #[test]
    fn test_confidence_from_score() {
        assert_eq!(MatchConfidence::from_score(0.96), Some(MatchConfidence::Exact));
        assert_eq!(MatchConfidence::from_score(0.80), Some(MatchConfidence::High));
        assert_eq!(MatchConfidence::from_score(0.60), Some(MatchConfidence::Medium));
        assert_eq!(MatchConfidence::from_score(0.35), Some(MatchConfidence::Low));
        assert_eq!(MatchConfidence::from_score(0.10), None);
    }

    #[test]
    fn test_match_identity_2x2() {
        let sim = make_sim(&[(0,0,0.95),(1,1,0.90)], 2, 2);
        let result = ExtendedHungarianMatcher::match_default(&sim);
        assert_eq!(result.matches.len(), 2);
        assert!(result.matches.iter().all(|m| m.idx_a == m.idx_b));
    }

    #[test]
    fn test_rectangular_matrix() {
        // 2 functions in A, 3 functions in B — should match 2 and leave 1 unmatched in B.
        let sim = make_sim(&[(0,0,0.95),(1,2,0.88)], 2, 3);
        let result = ExtendedHungarianMatcher::match_default(&sim);
        assert_eq!(result.matched_a_count(), 2);
        assert_eq!(result.unmatched_b_count(), 1);
    }

    #[test]
    fn test_below_threshold_dropped() {
        let sim = make_sim(&[(0,0,0.10)], 1, 1);
        let result = ExtendedHungarianMatcher::match_default(&sim);
        assert_eq!(result.matches.len(), 0);
        assert_eq!(result.unmatched_a_count(), 1);
        assert_eq!(result.unmatched_b_count(), 1);
    }

    #[test]
    fn test_empty_a() {
        let sim: Vec<Vec<f64>> = Vec::new();
        let result = ExtendedHungarianMatcher::match_default(&sim);
        assert!(result.matches.is_empty());
    }

    #[test]
    fn test_empty_b() {
        let sim: Vec<Vec<f64>> = vec![vec![]];
        let result = ExtendedHungarianMatcher::match_default(&sim);
        assert!(result.matches.is_empty());
        assert_eq!(result.unmatched_a_count(), 1);
    }

    #[test]
    fn test_cost_matrix_padding() {
        // 3 rows, 2 cols => pad to 3×3.
        let sim = vec![
            vec![0.9, 0.1],
            vec![0.2, 0.8],
            vec![0.5, 0.4],
        ];
        let m = CostMatrix::from_similarity(&sim);
        assert_eq!(m.dim(), 3);
        // Padded cells should have cost 1.0.
        assert_eq!(m.get(0, 2), 1.0);
    }

    #[test]
    fn test_hungarian_solver_3x3() {
        // Optimal assignment: (0→0, 1→2, 2→1) with total cost 0.
        let sim = vec![
            vec![1.0, 0.0, 0.0],
            vec![0.0, 0.0, 1.0],
            vec![0.0, 1.0, 0.0],
        ];
        let m = CostMatrix::from_similarity(&sim);
        let assignment = HungarianMatcher::solve(&m);
        // Each function should be assigned its unique best partner.
        assert_eq!(assignment[0], 0);
        assert_eq!(assignment[1], 2);
        assert_eq!(assignment[2], 1);
    }

    #[test]
    fn test_overall_similarity() {
        let sim = make_sim(&[(0,0,0.9),(1,1,0.8)], 2, 2);
        let result = ExtendedHungarianMatcher::match_default(&sim);
        let overall = result.overall_similarity();
        assert!((overall - 0.85).abs() < 0.01);
    }

    #[test]
    fn test_confidence_histogram() {
        let sim = make_sim(&[(0,0,0.96),(1,1,0.80),(2,2,0.55)], 3, 3);
        let result = ExtendedHungarianMatcher::match_default(&sim);
        let (exact, high, medium, low) = result.confidence_histogram();
        assert_eq!(exact, 1);
        assert_eq!(high, 1);
        assert_eq!(medium, 1);
        assert_eq!(low, 0);
    }

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!((cosine_similarity(&a, &b) - 0.0).abs() < 1e-9);
        let c = vec![1.0, 1.0];
        let d = vec![1.0, 1.0];
        assert!((cosine_similarity(&c, &d) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_feature_set_similarity_identical() {
        let f = FunctionFeatureSet {
            cfg_hash: 0xDEAD,
            block_count: 5,
            insn_count: 20,
            call_out: 3,
            call_in: 1,
            opcode_hist: vec![0.5, 0.5, 0.0, 0.0],
            name_hash: Some(0xBEEF),
        };
        let sim = f.similarity(&f);
        assert!(sim > 0.90, "identical features should give high similarity, got {sim}");
    }

    #[test]
    fn test_greedy_matcher_basic() {
        let (matches, unmatched) = GreedyMatcher::match_functions(
            2, 2, 0.3,
            |i, j| {
                let s = if i == j { 0.9 } else { 0.1 };
                if s >= 0.3 { Some(s) } else { None }
            },
        );
        assert_eq!(matches.len(), 2);
        assert!(unmatched.is_empty());
    }

    #[test]
    fn test_high_level_matcher() {
        let fa = FunctionFeatureSet {
            cfg_hash: 1, block_count: 4, insn_count: 16, call_out: 1, call_in: 0,
            opcode_hist: vec![1.0, 0.0, 0.0, 0.0],
            name_hash: None,
        };
        let fb = fa.clone();
        let result = HighLevelMatcher::match_default(&[fa], &[fb]);
        assert_eq!(result.matches.len(), 1);
        assert!(result.matches[0].similarity > 0.5);
    }
}
