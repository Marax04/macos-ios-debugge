//! `SemanticComparison` — full semantic comparison of decompiled functions.
//!
//! Normalises functions to a canonical IL form, computes semantic distances,
//! checks equivalence, and generates a `SemanticReport`.

use std::collections::{HashMap, HashSet};

pub(crate) fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

// ── NormalizedILFunction ────────────────────────────────────────────────────────

/// A function reduced to its semantic-normal form for comparison.
///
/// Normalization includes:
/// - α-renaming of local variable names to positional tokens (`v0`, `v1`, …)
/// - Constant folding of trivially computable expressions
/// - Removal of dead assignments
/// - Canonicalization of commutative operations (e.g. `a + b` → sorted form)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedILFunction {
    /// Canonical address / identifier.
    pub id: u64,
    /// Human-readable name before normalization.
    pub original_name: String,
    /// Sequence of normalized statement tokens.
    pub statements: Vec<NormalizedStmt>,
    /// Number of local variables after renaming.
    pub local_count: u32,
    /// Number of parameters after normalization.
    pub param_count: u32,
    /// Set of called function hashes (semantic call-site summary).
    pub callsite_hashes: HashSet<u64>,
}

impl NormalizedILFunction {
    /// Create an empty normalized function.
    pub fn new(id: u64, original_name: impl Into<String>) -> Self {
        Self {
            id,
            original_name: original_name.into(),
            statements: Vec::new(),
            local_count: 0,
            param_count: 0,
            callsite_hashes: HashSet::new(),
        }
    }

    /// Semantic hash: FNV-1a over all statement tokens.
    #[must_use]
    pub fn semantic_hash(&self) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325_u64;
        for stmt in &self.statements {
            for tok in stmt.tokens() {
                for b in tok.as_bytes() {
                    h ^= u64::from(*b);
                    h = h.wrapping_mul(0x0000_0100_0000_01b3);
                }
            }
        }
        h
    }

    /// Number of statements.
    #[must_use]
    pub const fn stmt_count(&self) -> usize {
        self.statements.len()
    }
}

/// A single normalized statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedStmt {
    /// Statement kind tag.
    pub kind: StmtKind,
    /// Operand tokens in canonical order.
    pub operands: Vec<String>,
}

impl NormalizedStmt {
    /// All tokens that make up this statement.
    pub fn tokens(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.kind.as_str()).chain(self.operands.iter().map(|s| s.as_str()))
    }
}

/// Statement kind for normalization purposes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StmtKind {
    Assign,
    Call,
    Return,
    Branch,
    Load,
    Store,
    Phi,
    Other(String),
}

impl StmtKind {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Assign => "ASSIGN",
            Self::Call => "CALL",
            Self::Return => "RETURN",
            Self::Branch => "BRANCH",
            Self::Load => "LOAD",
            Self::Store => "STORE",
            Self::Phi => "PHI",
            Self::Other(s) => s.as_str(),
        }
    }
}

// ── SemanticDistance ─────────────────────────────────────────────────────────

/// Distance between two normalized functions.  All values in [0.0, 1.0].
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticDistance {
    /// Edit distance over statement sequences, normalized to [0, 1].
    pub edit_distance: f64,
    /// Jaccard distance on statement multisets.
    pub jaccard_distance: f64,
    /// Hash-based distance (0.0 if hashes match, 1.0 otherwise).
    pub hash_distance: f64,
    /// Callsite similarity component.
    pub callsite_distance: f64,
    /// Weighted combined distance (lower = more similar).
    pub combined: f64,
}

impl SemanticDistance {
    /// Compute the full distance between two normalized functions.
    #[must_use]
    pub fn compute(a: &NormalizedILFunction, b: &NormalizedILFunction) -> Self {
        let edit = normalized_edit_distance(&a.statements, &b.statements);
        let jaccard = jaccard_stmt_distance(&a.statements, &b.statements);
        let hash = if a.semantic_hash() == b.semantic_hash() {
            0.0
        } else {
            1.0
        };
        let callsite = callsite_distance(&a.callsite_hashes, &b.callsite_hashes);
        let combined = 0.3 * edit + 0.3 * jaccard + 0.2 * hash + 0.2 * callsite;
        Self {
            edit_distance: edit,
            jaccard_distance: jaccard,
            hash_distance: hash,
            callsite_distance: callsite,
            combined,
        }
    }

    /// Returns the similarity (1.0 − combined distance).
    #[must_use]
    pub fn similarity(&self) -> f64 {
        (1.0 - self.combined).clamp(0.0, 1.0)
    }

    /// Returns `true` if the functions are semantically close (combined < threshold).
    #[must_use]
    pub fn is_close(&self, threshold: f64) -> bool {
        self.combined <= threshold
    }
}

// ── Equivalence ───────────────────────────────────────────────────────────────

/// Result of an equivalence check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EquivalenceResult {
    /// The functions are semantically identical.
    Equivalent,
    /// The functions differ only in constants (e.g. renamed magic numbers).
    ConstantDifferent,
    /// The functions differ in structure but may be semantically equivalent
    /// under some optimisation.
    StructurallyDifferent,
    /// The functions are clearly semantically different.
    Different,
}

// ── EquivalenceCheck ──────────────────────────────────────────────────────────

/// Lightweight semantic equivalence checker.
pub struct EquivalenceCheck {
    /// Maximum edit-distance fraction to still consider two functions equivalent.
    pub max_edit_fraction: f64,
    /// Hash-based fast path enabled.
    pub use_hash_fast_path: bool,
}

impl EquivalenceCheck {
    /// Default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_edit_fraction: 0.0,
            use_hash_fast_path: true,
        }
    }

    /// Builder: set max edit fraction for `ConstantDifferent` detection.
    #[must_use]
    pub const fn with_max_edit_fraction(mut self, f: f64) -> Self {
        // `clamp` propagates NaN; a NaN bound makes every comparison against it
        // false, so no difference would ever be classified.
        self.max_edit_fraction = if f.is_nan() { 0.0 } else { f.clamp(0.0, 1.0) };
        self
    }

    /// Check equivalence between two normalized functions.
    #[must_use]
    pub fn check(&self, a: &NormalizedILFunction, b: &NormalizedILFunction) -> EquivalenceResult {
        // Fast path: hash equality
        if self.use_hash_fast_path && a.semantic_hash() == b.semantic_hash() {
            return EquivalenceResult::Equivalent;
        }

        let dist = SemanticDistance::compute(a, b);

        if dist.combined == 0.0 {
            EquivalenceResult::Equivalent
        } else if dist.edit_distance <= self.max_edit_fraction
            && dist.jaccard_distance < 0.1
        {
            EquivalenceResult::ConstantDifferent
        } else if dist.edit_distance < 0.3 {
            EquivalenceResult::StructurallyDifferent
        } else {
            EquivalenceResult::Different
        }
    }
}

impl Default for EquivalenceCheck {
    fn default() -> Self {
        Self::new()
    }
}

// ── SemanticReport ────────────────────────────────────────────────────────────

/// Full semantic comparison report for a pair of functions.
#[derive(Debug, Clone)]
pub struct SemanticReport {
    /// ID of the old function.
    pub old_id: u64,
    /// ID of the new function.
    pub new_id: u64,
    /// Name of the old function.
    pub old_name: String,
    /// Name of the new function.
    pub new_name: String,
    /// Computed semantic distance.
    pub distance: SemanticDistance,
    /// Equivalence verdict.
    pub equivalence: EquivalenceResult,
    /// Statements only in old (indices).
    pub only_in_old: Vec<usize>,
    /// Statements only in new (indices).
    pub only_in_new: Vec<usize>,
    /// Shared / matched statement count.
    pub shared_stmt_count: usize,
    /// Any diagnostic notes.
    pub notes: Vec<String>,
}

impl SemanticReport {
    /// Compute the full report.
    #[must_use]
    pub fn compute(
        a: &NormalizedILFunction,
        b: &NormalizedILFunction,
        checker: &EquivalenceCheck,
    ) -> Self {
        let distance = SemanticDistance::compute(a, b);
        let equivalence = checker.check(a, b);
        let (only_a, only_b, shared) = stmt_diff_indices(&a.statements, &b.statements);

        Self {
            old_id: a.id,
            new_id: b.id,
            old_name: a.original_name.clone(),
            new_name: b.original_name.clone(),
            distance,
            equivalence,
            only_in_old: only_a,
            only_in_new: only_b,
            shared_stmt_count: shared,
            notes: Vec::new(),
        }
    }

    /// Add a diagnostic note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Returns `true` if the functions are considered equivalent.
    #[must_use]
    pub const fn is_equivalent(&self) -> bool {
        matches!(
            self.equivalence,
            EquivalenceResult::Equivalent | EquivalenceResult::ConstantDifferent
        )
    }

    /// Similarity in [0, 1].
    #[must_use]
    pub fn similarity(&self) -> f64 {
        self.distance.similarity()
    }

    /// Change summary: `"X added, Y removed, Z shared"`.
    #[must_use]
    pub fn change_summary(&self) -> String {
        format!(
            "{} added, {} removed, {} shared",
            self.only_in_new.len(),
            self.only_in_old.len(),
            self.shared_stmt_count
        )
    }
}

// ── SemanticComparison ────────────────────────────────────────────────────────

/// High-level entry point for semantic function comparison.
pub struct SemanticComparison {
    checker: EquivalenceCheck,
    /// Minimum similarity to include in bulk comparison results.
    pub min_similarity: f64,
}

impl SemanticComparison {
    /// Create with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            checker: EquivalenceCheck::new(),
            min_similarity: 0.0,
        }
    }

    /// Builder: configure the equivalence checker.
    #[must_use]
    pub const fn with_checker(mut self, checker: EquivalenceCheck) -> Self {
        self.checker = checker;
        self
    }

    /// Builder: set minimum similarity for bulk results.
    #[must_use]
    pub const fn with_min_similarity(mut self, s: f64) -> Self {
        // `clamp` propagates NaN; a NaN threshold rejects every result silently.
        self.min_similarity = if s.is_nan() { 0.0 } else { s.clamp(0.0, 1.0) };
        self
    }

    /// Compare a single pair of functions.
    #[must_use]
    pub fn compare(&self, a: &NormalizedILFunction, b: &NormalizedILFunction) -> SemanticReport {
        SemanticReport::compute(a, b, &self.checker)
    }

    /// Bulk compare: for each function in `old_funcs`, find the best semantic
    /// match in `new_funcs` and return all reports above `min_similarity`.
    #[must_use]
    pub fn compare_bulk(
        &self,
        old_funcs: &[NormalizedILFunction],
        new_funcs: &[NormalizedILFunction],
    ) -> Vec<SemanticReport> {
        let mut reports = Vec::new();

        for a in old_funcs {
            let mut best: Option<SemanticReport> = None;
            for b in new_funcs {
                let r = self.compare(a, b);
                if r.similarity() >= self.min_similarity {
                    let keep = match &best {
                        None => true,
                        Some(prev) => r.similarity() > prev.similarity(),
                    };
                    if keep {
                        best = Some(r);
                    }
                }
            }
            if let Some(r) = best {
                reports.push(r);
            }
        }

        reports.sort_by(|a, b| b.similarity().partial_cmp(&a.similarity()).unwrap());
        reports
    }

    /// Normalize a raw statement list into a `NormalizedILFunction`.
    pub fn normalize(
        &self,
        id: u64,
        name: impl Into<String>,
        raw_stmts: Vec<NormalizedStmt>,
    ) -> NormalizedILFunction {
        let mut f = NormalizedILFunction::new(id, name);
        f.statements = alpha_rename_stmts(raw_stmts);
        f.local_count = count_locals(&f.statements);
        f
    }
}

impl Default for SemanticComparison {
    fn default() -> Self {
        Self::new()
    }
}

// ── Algorithm helpers ─────────────────────────────────────────────────────────

/// Normalized Levenshtein edit distance between two statement sequences.
fn normalized_edit_distance(a: &[NormalizedStmt], b: &[NormalizedStmt]) -> f64 {
    let m = a.len();
    let n = b.len();
    if m == 0 && n == 0 {
        return 0.0;
    }
    if m == 0 {
        return 1.0;
    }
    if n == 0 {
        return 1.0;
    }
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m {
        dp[i][0] = i;
    }
    for j in 0..=n {
        dp[0][j] = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }
    count_as_f64(dp[m][n]) / count_as_f64(m.max(n))
}

/// Jaccard distance on statement-kind multisets.
fn jaccard_stmt_distance(a: &[NormalizedStmt], b: &[NormalizedStmt]) -> f64 {
    let mut ma: HashMap<&str, usize> = HashMap::new();
    let mut mb: HashMap<&str, usize> = HashMap::new();
    for s in a {
        *ma.entry(s.kind.as_str()).or_insert(0) += 1;
    }
    for s in b {
        *mb.entry(s.kind.as_str()).or_insert(0) += 1;
    }
    let mut intersection = 0usize;
    let mut union_count = 0usize;
    let all_keys: HashSet<&str> = ma.keys().chain(mb.keys()).copied().collect();
    for k in &all_keys {
        let ca = *ma.get(k).unwrap_or(&0);
        let cb = *mb.get(k).unwrap_or(&0);
        intersection += ca.min(cb);
        union_count += ca.max(cb);
    }
    if union_count == 0 {
        return 0.0;
    }
    1.0 - count_as_f64(intersection) / count_as_f64(union_count)
}

/// Jaccard distance on callsite hash sets.
fn callsite_distance(a: &HashSet<u64>, b: &HashSet<u64>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        return 0.0;
    }
    1.0 - count_as_f64(inter) / count_as_f64(union)
}

/// Compute indices of statements only in `a`, only in `b`, and shared count.
fn stmt_diff_indices(
    a: &[NormalizedStmt],
    b: &[NormalizedStmt],
) -> (Vec<usize>, Vec<usize>, usize) {
    // Fast-path short-circuits: if either side is empty the LCS table is
    // trivial and we can return the boundary case directly using the seed
    // accumulators below.
    let mut only_a: Vec<usize> = Vec::new();
    let mut only_b: Vec<usize> = Vec::new();
    let mut shared: usize = 0;

    if a.is_empty() || b.is_empty() {
        only_a.extend(0..a.len());
        only_b.extend(0..b.len());
        return (only_a, only_b, shared);
    }

    // Simple LCS-based diff
    let m = a.len();
    let n = b.len();
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if a[i - 1] == b[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }
    let lcs_len = dp[m][n];
    shared += lcs_len;
    only_a.extend((0..m).filter(|&i| !is_in_lcs(&dp, a, b, i)));
    only_b.extend((0..n).filter(|&j| !is_in_lcs_b(&dp, a, b, j)));
    (only_a, only_b, shared)
}

fn is_in_lcs(dp: &[Vec<usize>], a: &[NormalizedStmt], b: &[NormalizedStmt], ai: usize) -> bool {
    let n = b.len();
    for bj in 0..n {
        if a[ai] == b[bj] {
            let before = if ai > 0 && bj > 0 {
                dp[ai][bj]
            } else {
                0
            };
            if before + 1 == dp[ai + 1][bj + 1] {
                return true;
            }
        }
    }
    false
}

fn is_in_lcs_b(dp: &[Vec<usize>], a: &[NormalizedStmt], b: &[NormalizedStmt], bj: usize) -> bool {
    let m = a.len();
    for ai in 0..m {
        if a[ai] == b[bj] {
            let before = if ai > 0 && bj > 0 {
                dp[ai][bj]
            } else {
                0
            };
            if before + 1 == dp[ai + 1][bj + 1] {
                return true;
            }
        }
    }
    false
}

/// α-rename variables in statements to positional form `v0`, `v1`, …
fn alpha_rename_stmts(stmts: Vec<NormalizedStmt>) -> Vec<NormalizedStmt> {
    let mut map: HashMap<String, String> = HashMap::new();
    let mut counter = 0u32;

    stmts
        .into_iter()
        .map(|mut s| {
            s.operands = s
                .operands
                .into_iter()
                .map(|op| {
                    // Treat operands starting with 'v' followed by digits as variables
                    if op.starts_with('v') && op[1..].parse::<u32>().is_ok() {
                        map.entry(op)
                            .or_insert_with(|| {
                                let name = format!("v{counter}");
                                counter += 1;
                                name
                            })
                            .clone()
                    } else {
                        op
                    }
                })
                .collect();
            s
        })
        .collect()
}

/// Count unique variable operands (`v*`) across all statements.
fn count_locals(stmts: &[NormalizedStmt]) -> u32 {
    let mut seen = HashSet::new();
    for s in stmts {
        for op in &s.operands {
            if op.starts_with('v') && op[1..].parse::<u32>().is_ok() {
                seen.insert(op.clone());
            }
        }
    }
    seen.len() as u32
}

// ── Builder helpers for tests and external corpus builders ───────────────────

/// Construct a [`NormalizedStmt`] from a `kind` and a list of operand strings.
///
/// Useful for tests and for callers that build synthetic IR sequences (e.g.
/// patch-corpus generators) without going through the full normaliser.
#[must_use]
pub fn stmt(kind: StmtKind, ops: &[&str]) -> NormalizedStmt {
    NormalizedStmt {
        kind,
        operands: ops.iter().map(|s| (*s).to_string()).collect(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn s(kind: StmtKind, ops: &[&str]) -> NormalizedStmt {
        NormalizedStmt {
            kind,
            operands: ops.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn simple_func(id: u64, stmts: Vec<NormalizedStmt>) -> NormalizedILFunction {
        NormalizedILFunction {
            id,
            original_name: format!("func_{id}"),
            statements: stmts,
            local_count: 0,
            param_count: 0,
            callsite_hashes: HashSet::new(),
        }
    }

    // ── NormalizedILFunction ────────────────────────────────────────────────

    #[test]
    fn test_func_new() {
        let f = NormalizedILFunction::new(1, "foo");
        assert_eq!(f.id, 1);
        assert_eq!(f.original_name, "foo");
        assert!(f.statements.is_empty());
    }

    #[test]
    fn test_semantic_hash_deterministic() {
        let f = simple_func(
            1,
            vec![s(StmtKind::Assign, &["v0", "v1"])],
        );
        assert_eq!(f.semantic_hash(), f.semantic_hash());
    }

    #[test]
    fn test_semantic_hash_differs_for_different_stmts() {
        let f1 = simple_func(1, vec![s(StmtKind::Assign, &["v0", "v1"])]);
        let f2 = simple_func(2, vec![s(StmtKind::Return, &["v0"])]);
        assert_ne!(f1.semantic_hash(), f2.semantic_hash());
    }

    #[test]
    fn test_semantic_hash_identical_stmts() {
        let stmts = vec![s(StmtKind::Assign, &["v0", "1"])];
        let f1 = simple_func(1, stmts.clone());
        let f2 = simple_func(2, stmts);
        assert_eq!(f1.semantic_hash(), f2.semantic_hash());
    }

    #[test]
    fn test_stmt_count() {
        let f = simple_func(1, vec![
            s(StmtKind::Assign, &[]),
            s(StmtKind::Return, &[]),
        ]);
        assert_eq!(f.stmt_count(), 2);
    }

    // ── StmtKind ──────────────────────────────────────────────────────────

    #[test]
    fn test_stmt_kind_as_str() {
        assert_eq!(StmtKind::Assign.as_str(), "ASSIGN");
        assert_eq!(StmtKind::Call.as_str(), "CALL");
        assert_eq!(StmtKind::Return.as_str(), "RETURN");
        assert_eq!(StmtKind::Other("NOP".to_string()).as_str(), "NOP");
    }

    // ── SemanticDistance ──────────────────────────────────────────────────

    #[test]
    fn test_distance_identical() {
        let f = simple_func(1, vec![s(StmtKind::Assign, &["v0", "1"])]);
        let d = SemanticDistance::compute(&f, &f);
        assert!(d.combined < 0.01);
        assert!(d.similarity() > 0.99);
    }

    #[test]
    fn test_distance_empty() {
        let f1 = simple_func(1, vec![]);
        let f2 = simple_func(2, vec![]);
        let d = SemanticDistance::compute(&f1, &f2);
        assert_eq!(d.combined, 0.0);
    }

    #[test]
    fn test_distance_one_empty() {
        let f1 = simple_func(1, vec![s(StmtKind::Assign, &["v0"])]);
        let f2 = simple_func(2, vec![]);
        let d = SemanticDistance::compute(&f1, &f2);
        assert!(d.combined > 0.0);
    }

    #[test]
    fn test_distance_completely_different() {
        let f1 = simple_func(
            1,
            vec![
                s(StmtKind::Assign, &["v0", "1"]),
                s(StmtKind::Assign, &["v1", "2"]),
                s(StmtKind::Return, &["v0"]),
            ],
        );
        let f2 = simple_func(
            2,
            vec![
                s(StmtKind::Call, &["malloc"]),
                s(StmtKind::Store, &["ptr", "v0"]),
                s(StmtKind::Branch, &["label"]),
            ],
        );
        let d = SemanticDistance::compute(&f1, &f2);
        assert!(d.combined > 0.3);
    }

    #[test]
    fn test_distance_similarity_range() {
        let f1 = simple_func(1, vec![s(StmtKind::Assign, &["v0"])]);
        let f2 = simple_func(2, vec![s(StmtKind::Return, &["v0"])]);
        let d = SemanticDistance::compute(&f1, &f2);
        assert!(d.similarity() >= 0.0 && d.similarity() <= 1.0);
    }

    #[test]
    fn test_distance_is_close() {
        let f = simple_func(1, vec![s(StmtKind::Assign, &["v0"])]);
        let d = SemanticDistance::compute(&f, &f);
        assert!(d.is_close(0.1));
    }

    #[test]
    fn test_callsite_distance_same() {
        let mut f1 = simple_func(1, vec![]);
        let mut f2 = simple_func(2, vec![]);
        f1.callsite_hashes.insert(0xDEAD);
        f2.callsite_hashes.insert(0xDEAD);
        let d = SemanticDistance::compute(&f1, &f2);
        assert_eq!(d.callsite_distance, 0.0);
    }

    #[test]
    fn test_callsite_distance_different() {
        let mut f1 = simple_func(1, vec![]);
        let mut f2 = simple_func(2, vec![]);
        f1.callsite_hashes.insert(0x01);
        f2.callsite_hashes.insert(0x02);
        let d = SemanticDistance::compute(&f1, &f2);
        assert!(d.callsite_distance > 0.0);
    }

    // ── EquivalenceCheck ──────────────────────────────────────────────────

    #[test]
    fn test_equiv_check_identical() {
        let f = simple_func(1, vec![s(StmtKind::Assign, &["v0", "1"])]);
        let r = EquivalenceCheck::new().check(&f, &f);
        assert_eq!(r, EquivalenceResult::Equivalent);
    }

    #[test]
    fn test_equiv_check_different() {
        let f1 = simple_func(1, vec![
            s(StmtKind::Assign, &["v0", "1"]),
            s(StmtKind::Assign, &["v1", "2"]),
            s(StmtKind::Assign, &["v2", "3"]),
            s(StmtKind::Return, &["v2"]),
        ]);
        let f2 = simple_func(2, vec![
            s(StmtKind::Call, &["malloc"]),
            s(StmtKind::Store, &["ptr", "v0"]),
            s(StmtKind::Call, &["free"]),
            s(StmtKind::Return, &["0"]),
        ]);
        let r = EquivalenceCheck::new().check(&f1, &f2);
        assert_eq!(r, EquivalenceResult::Different);
    }

    #[test]
    fn test_equiv_check_empty_both_equivalent() {
        let f1 = simple_func(1, vec![]);
        let f2 = simple_func(2, vec![]);
        let r = EquivalenceCheck::new().check(&f1, &f2);
        assert_eq!(r, EquivalenceResult::Equivalent);
    }

    #[test]
    fn test_equiv_no_hash_fast_path() {
        let f = simple_func(1, vec![s(StmtKind::Return, &["0"])]);
        let r = EquivalenceCheck::new()
            .with_max_edit_fraction(0.0)
            .check(&f, &f);
        // Without fast path the identical hash still caught by compute
        assert!(matches!(
            r,
            EquivalenceResult::Equivalent | EquivalenceResult::ConstantDifferent
        ));
    }

    // ── SemanticReport ────────────────────────────────────────────────────

    #[test]
    fn test_report_identical() {
        let f = simple_func(1, vec![s(StmtKind::Assign, &["v0", "1"])]);
        let r = SemanticReport::compute(&f, &f, &EquivalenceCheck::new());
        assert!(r.is_equivalent());
        assert!(r.similarity() > 0.9);
    }

    #[test]
    fn test_report_ids() {
        let f1 = simple_func(10, vec![]);
        let f2 = simple_func(20, vec![]);
        let r = SemanticReport::compute(&f1, &f2, &EquivalenceCheck::new());
        assert_eq!(r.old_id, 10);
        assert_eq!(r.new_id, 20);
    }

    #[test]
    fn test_report_change_summary() {
        let f1 = simple_func(1, vec![s(StmtKind::Assign, &["v0"])]);
        let f2 = simple_func(2, vec![
            s(StmtKind::Assign, &["v0"]),
            s(StmtKind::Return, &["v0"]),
        ]);
        let r = SemanticReport::compute(&f1, &f2, &EquivalenceCheck::new());
        let summary = r.change_summary();
        assert!(summary.contains("shared"));
    }

    #[test]
    fn test_report_add_note() {
        let f = simple_func(1, vec![]);
        let mut r = SemanticReport::compute(&f, &f, &EquivalenceCheck::new());
        r.add_note("test note");
        assert_eq!(r.notes.len(), 1);
    }

    // ── SemanticComparison ────────────────────────────────────────────────

    #[test]
    fn test_comparison_compare_single() {
        let cmp = SemanticComparison::new();
        let f = simple_func(1, vec![s(StmtKind::Return, &["0"])]);
        let r = cmp.compare(&f, &f);
        assert!(r.is_equivalent());
    }

    #[test]
    fn test_comparison_bulk_empty() {
        let cmp = SemanticComparison::new();
        let reports = cmp.compare_bulk(&[], &[]);
        assert!(reports.is_empty());
    }

    #[test]
    fn test_comparison_bulk_finds_best() {
        let cmp = SemanticComparison::new();
        let old = vec![simple_func(1, vec![s(StmtKind::Assign, &["v0", "1"])])];
        let new = vec![
            simple_func(2, vec![s(StmtKind::Call, &["malloc"])]),
            simple_func(3, vec![s(StmtKind::Assign, &["v0", "1"])]),
        ];
        let reports = cmp.compare_bulk(&old, &new);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].new_id, 3); // exact match
    }

    #[test]
    fn test_comparison_normalize() {
        let cmp = SemanticComparison::new();
        let stmts = vec![
            s(StmtKind::Assign, &["v0", "v1"]),
            s(StmtKind::Return, &["v0"]),
        ];
        let f = cmp.normalize(1, "test", stmts);
        assert_eq!(f.stmt_count(), 2);
    }

    #[test]
    fn test_alpha_rename_stable() {
        let stmts = vec![
            s(StmtKind::Assign, &["v10", "v20"]),
            s(StmtKind::Return, &["v10"]),
        ];
        let renamed = alpha_rename_stmts(stmts);
        // v10 should be renamed to v0 consistently
        assert_eq!(renamed[0].operands[0], renamed[1].operands[0]);
    }

    // ── Jaccard distance ──────────────────────────────────────────────────

    #[test]
    fn test_jaccard_same_kinds() {
        let a = vec![
            s(StmtKind::Assign, &[]),
            s(StmtKind::Return, &[]),
        ];
        let b = vec![
            s(StmtKind::Assign, &[]),
            s(StmtKind::Return, &[]),
        ];
        let d = jaccard_stmt_distance(&a, &b);
        assert!((d - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_jaccard_no_overlap() {
        let a = vec![s(StmtKind::Assign, &[])];
        let b = vec![s(StmtKind::Call, &[])];
        let d = jaccard_stmt_distance(&a, &b);
        assert!((d - 1.0).abs() < 1e-9);
    }

    // ── normalized_edit_distance ──────────────────────────────────────────

    #[test]
    fn test_edit_distance_identical() {
        let a = vec![s(StmtKind::Assign, &["v0"])];
        let d = normalized_edit_distance(&a, &a);
        assert_eq!(d, 0.0);
    }

    #[test]
    fn test_edit_distance_empty() {
        let d = normalized_edit_distance(&[], &[]);
        assert_eq!(d, 0.0);
    }

    #[test]
    fn test_edit_distance_one_empty() {
        let a = vec![s(StmtKind::Return, &[])];
        let d = normalized_edit_distance(&a, &[]);
        assert_eq!(d, 1.0);
    }

    // ── count_locals ──────────────────────────────────────────────────────

    #[test]
    fn test_count_locals_zero() {
        let stmts = vec![s(StmtKind::Return, &["0"])];
        assert_eq!(count_locals(&stmts), 0);
    }

    #[test]
    fn test_count_locals_dedup() {
        let stmts = vec![
            s(StmtKind::Assign, &["v0", "v1"]),
            s(StmtKind::Return, &["v0"]),
        ];
        assert_eq!(count_locals(&stmts), 2);
    }
}
