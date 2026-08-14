//! `function_matching` — Function matching for binary diff in RustRE.
//!
//! Provides [`FunctionMatcher`], [`MatchScore`], [`MatchingStrategy`],
//! [`NameHashMatch`], [`CallgraphContextMatch`], [`BbHashMatch`],
//! [`UnmatchedFunctions`], and [`MatchReport`].

use ahash::AHashMap;
use std::collections::HashMap;
use std::fmt;

// ── FunctionProfile ───────────────────────────────────────────────────────────

/// A function's profile for matching purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionProfile {
    pub address: u64,
    pub name: String,
    /// MD5-like hash of instruction bytes.
    pub bytes_hash: u64,
    /// Hash of the basic-block structure (address-independent).
    pub bb_hash: u64,
    /// Hash of the call-graph neighbourhood.
    pub cg_hash: u64,
    /// Hash of the instruction mnemonics (no operands).
    pub mnem_hash: u64,
    /// Number of basic blocks.
    pub bb_count: u32,
    /// Number of instructions.
    pub insn_count: u32,
    /// Number of outgoing calls.
    pub call_out: u32,
    /// Number of incoming calls.
    pub call_in: u32,
    /// Is this an imported function?
    pub is_import: bool,
    /// Is this a library function (identified by FLIRT)?
    pub is_library: bool,
    /// Callee addresses.
    pub callees: Vec<u64>,
    /// Caller addresses.
    pub callers: Vec<u64>,
}

impl FunctionProfile {
    #[must_use] 
    pub fn new(address: u64, name: &str) -> Self {
        Self {
            address,
            name: name.to_owned(),
            bytes_hash: 0,
            bb_hash: 0,
            cg_hash: 0,
            mnem_hash: 0,
            bb_count: 1,
            insn_count: 0,
            call_out: 0,
            call_in: 0,
            is_import: false,
            is_library: false,
            callees: Vec::new(),
            callers: Vec::new(),
        }
    }

    /// Is this function a "trivial" stub (0-1 instructions)?
    #[must_use] 
    pub const fn is_trivial(&self) -> bool {
        self.insn_count <= 1
    }
}

impl fmt::Display for FunctionProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{:#x}", self.name, self.address)
    }
}

// ── MatchScore ────────────────────────────────────────────────────────────────

/// Matching score for two functions.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchScore {
    pub addr_a: u64,
    pub addr_b: u64,
    /// Name match score (0.0 = no match, 1.0 = exact).
    pub name_score: f64,
    /// Signature (bytes hash) match score.
    pub signature_score: f64,
    /// Content (mnemonic hash) match score.
    pub content_score: f64,
    /// Call-graph context score.
    pub cg_score: f64,
    /// Basic-block hash score.
    pub bb_score: f64,
    /// Weighted aggregate score [0.0, 1.0].
    pub total_score: f64,
    /// Matching strategy that produced this result.
    pub strategy: MatchingStrategy,
}

impl MatchScore {
    #[must_use] 
    pub fn compute(
        a: &FunctionProfile,
        b: &FunctionProfile,
        w_name: f64,
        w_sig: f64,
        w_content: f64,
        w_cg: f64,
        w_bb: f64,
    ) -> Self {
        let name_score = if !a.name.is_empty()
            && !b.name.is_empty()
            && a.name == b.name
            && !a.name.starts_with("sub_")
        {
            1.0
        } else if !a.name.is_empty()
            && !b.name.is_empty()
            && a.name.contains(&b.name[..b.name.len().min(8)])
        {
            0.5
        } else {
            0.0
        };

        let signature_score = if a.bytes_hash == b.bytes_hash && a.bytes_hash != 0 {
            1.0
        } else {
            0.0
        };

        let content_score = if a.mnem_hash == b.mnem_hash && a.mnem_hash != 0 {
            1.0
        } else {
            let diff = (f64::from(a.insn_count) - f64::from(b.insn_count)).abs();
            let mx = f64::from(a.insn_count.max(b.insn_count));
            if mx == 0.0 {
                1.0
            } else {
                1.0 - (diff / mx).min(1.0)
            }
        };

        let cg_score = if a.cg_hash == b.cg_hash && a.cg_hash != 0 {
            1.0
        } else {
            let call_diff = (f64::from(a.call_out) - f64::from(b.call_out)).abs();
            let call_mx = f64::from(a.call_out.max(b.call_out));
            if call_mx == 0.0 {
                1.0
            } else {
                1.0 - (call_diff / call_mx).min(1.0)
            }
        };

        let bb_score = if a.bb_hash == b.bb_hash && a.bb_hash != 0 {
            1.0
        } else {
            let bb_diff = (f64::from(a.bb_count) - f64::from(b.bb_count)).abs();
            let bb_mx = f64::from(a.bb_count.max(b.bb_count));
            if bb_mx == 0.0 {
                1.0
            } else {
                1.0 - (bb_diff / bb_mx).min(1.0)
            }
        };

        let total = w_bb.mul_add(bb_score, w_cg.mul_add(cg_score, w_content.mul_add(content_score, w_name.mul_add(name_score, w_sig * signature_score))))
            / (w_name + w_sig + w_content + w_cg + w_bb);

        let strategy = if (signature_score - 1.0).abs() < f64::EPSILON {
            MatchingStrategy::Exact
        } else if total >= 0.8 {
            MatchingStrategy::Heuristic
        } else {
            MatchingStrategy::Structural
        };

        Self {
            addr_a: a.address,
            addr_b: b.address,
            name_score,
            signature_score,
            content_score,
            cg_score,
            bb_score,
            total_score: total,
            strategy,
        }
    }

    #[must_use] 
    pub const fn is_exact(&self) -> bool {
        matches!(self.strategy, MatchingStrategy::Exact)
    }
    #[must_use] 
    pub fn is_renamed(&self) -> bool {
        self.signature_score >= 0.99 && self.name_score < 0.5
    }
}

// ── MatchingStrategy ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchingStrategy {
    /// Exact byte-for-byte match.
    Exact,
    /// Heuristic similarity match.
    Heuristic,
    /// Structural (CFG topology) match.
    Structural,
    /// Name-only match (symbol export).
    NameOnly,
    /// Call-graph propagation match.
    CallgraphPropagation,
}

impl fmt::Display for MatchingStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Exact => "exact",
            Self::Heuristic => "heuristic",
            Self::Structural => "structural",
            Self::NameOnly => "name_only",
            Self::CallgraphPropagation => "callgraph_propagation",
        };
        f.write_str(s)
    }
}

// ── NameHashMatch ─────────────────────────────────────────────────────────────

/// Simple name-and-hash-based match.
pub struct NameHashMatch;

impl NameHashMatch {
    /// Find all functions in `b` that match `a` by name or by exact bytes hash.
    #[must_use] 
    pub fn find_matches<'a>(
        a: &FunctionProfile,
        b_funcs: &'a [FunctionProfile],
    ) -> Vec<&'a FunctionProfile> {
        b_funcs
            .iter()
            .filter(|b| {
                (a.name == b.name && !a.name.is_empty() && !a.name.starts_with("sub_"))
                    || (a.bytes_hash == b.bytes_hash && a.bytes_hash != 0)
            })
            .collect()
    }
}

// ── CallgraphContextMatch ─────────────────────────────────────────────────────

/// Match functions based on call-graph context.
pub struct CallgraphContextMatch;

impl CallgraphContextMatch {
    #[must_use] 
    pub fn score(a: &FunctionProfile, b: &FunctionProfile) -> f64 {
        // Only treat cg_hash equality as a definitive 1.0 when callee/caller
        // sets actually agree as well — a synthetic cg_hash collision with
        // disjoint neighbourhoods should fall through to the overlap scoring.
        let outbound_sim = Self::set_overlap(&a.callees, &b.callees);
        let inbound_sim  = Self::set_overlap(&a.callers, &b.callers);
        if a.cg_hash == b.cg_hash
            && a.cg_hash != 0
            && (outbound_sim - 1.0).abs() < f64::EPSILON
            && (inbound_sim - 1.0).abs() < f64::EPSILON
        {
            return 1.0;
        }
        f64::midpoint(outbound_sim, inbound_sim)
    }

    fn set_overlap(a: &[u64], b: &[u64]) -> f64 {
        if a.is_empty() && b.is_empty() {
            return 1.0;
        }
        if a.is_empty() || b.is_empty() {
            return 0.0;
        }
        let set_a: std::collections::HashSet<u64> = a.iter().copied().collect();
        let set_b: std::collections::HashSet<u64> = b.iter().copied().collect();
        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();
        if union == 0 {
            1.0
        } else {
            f64::from(u32::try_from(intersection).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(union).unwrap_or(u32::MAX))
        }
    }
}

// ── BbHashMatch ───────────────────────────────────────────────────────────────

/// Match based on basic-block hash.
pub struct BbHashMatch;

impl BbHashMatch {
    #[must_use] 
    pub const fn is_exact_match(a: &FunctionProfile, b: &FunctionProfile) -> bool {
        // A true exact basic-block match requires both the BB hash and the
        // structural BB/instruction counts to agree — otherwise functions of
        // very different sizes that happen to share a derived hash would be
        // reported as identical.
        a.bb_hash != 0
            && a.bb_hash == b.bb_hash
            && a.bb_count == b.bb_count
            && a.insn_count == b.insn_count
    }

    #[must_use] 
    pub fn approximate_score(a: &FunctionProfile, b: &FunctionProfile) -> f64 {
        let bb_diff = (f64::from(a.bb_count) - f64::from(b.bb_count)).abs();
        let bb_mx = f64::from(a.bb_count.max(b.bb_count));
        if bb_mx == 0.0 {
            1.0
        } else {
            1.0 - (bb_diff / bb_mx).min(1.0)
        }
    }
}

// ── UnmatchedFunctions ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct UnmatchedFunctions {
    pub only_in_a: Vec<u64>,
    pub only_in_b: Vec<u64>,
}

impl UnmatchedFunctions {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_a(&mut self, addr: u64) {
        self.only_in_a.push(addr);
    }
    pub fn add_b(&mut self, addr: u64) {
        self.only_in_b.push(addr);
    }
    #[must_use] 
    pub const fn total(&self) -> usize {
        self.only_in_a.len() + self.only_in_b.len()
    }
}

// ── MatchReport ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MatchReport {
    pub binary_a: String,
    pub binary_b: String,
    pub matches: Vec<MatchScore>,
    pub unmatched: UnmatchedFunctions,
}

impl MatchReport {
    #[must_use] 
    pub fn new(binary_a: &str, binary_b: &str) -> Self {
        Self {
            binary_a: binary_a.to_owned(),
            binary_b: binary_b.to_owned(),
            matches: Vec::new(),
            unmatched: UnmatchedFunctions::new(),
        }
    }

    pub fn add_match(&mut self, m: MatchScore) {
        self.matches.push(m);
    }

    #[must_use] 
    pub fn similarity_score(&self) -> f64 {
        if self.matches.is_empty() {
            return 0.0;
        }
        self.matches.iter().map(|m| m.total_score).sum::<f64>()
            / f64::from(u32::try_from(self.matches.len()).unwrap_or(u32::MAX))
    }

    #[must_use] 
    pub fn exact_matches(&self) -> Vec<&MatchScore> {
        self.matches.iter().filter(|m| m.is_exact()).collect()
    }

    #[must_use] 
    pub fn renamed_functions(&self) -> Vec<&MatchScore> {
        self.matches.iter().filter(|m| m.is_renamed()).collect()
    }

    #[must_use] 
    pub fn strategy_counts(&self) -> HashMap<MatchingStrategy, usize> {
        let mut counts = HashMap::new();
        for m in &self.matches {
            *counts.entry(m.strategy).or_insert(0) += 1;
        }
        counts
    }

    #[must_use] 
    pub const fn matched_count(&self) -> usize {
        self.matches.len()
    }
    #[must_use] 
    pub fn changed_functions(&self) -> Vec<&MatchScore> {
        self.matches
            .iter()
            .filter(|m| m.total_score < 0.99 && m.total_score >= 0.5)
            .collect()
    }
}

impl fmt::Display for MatchReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MatchReport '{}' vs '{}': {}/{} matched, {:.1}% similar",
            self.binary_a,
            self.binary_b,
            self.matched_count(),
            self.matched_count() + self.unmatched.total(),
            self.similarity_score() * 100.0
        )
    }
}

// ── FunctionMatcher ───────────────────────────────────────────────────────────

/// Main function matcher.
pub struct FunctionMatcher {
    pub w_name: f64,
    pub w_sig: f64,
    pub w_content: f64,
    pub w_cg: f64,
    pub w_bb: f64,
    pub threshold: f64,
}

impl FunctionMatcher {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            w_name: 1.5,
            w_sig: 3.0,
            w_content: 1.5,
            w_cg: 0.5,
            w_bb: 1.0,
            threshold: 0.4,
        }
    }

    #[must_use] 
    pub const fn with_threshold(mut self, t: f64) -> Self {
        self.threshold = t;
        self
    }

    /// Match all functions in `funcs_a` against `funcs_b`.
    #[must_use] 
    pub fn match_all(
        &self,
        funcs_a: &[FunctionProfile],
        funcs_b: &[FunctionProfile],
    ) -> MatchReport {
        let mut report = MatchReport::new("A", "B");

        // Phase 1: exact hash matches.
        let mut matched_a = std::collections::HashSet::new();
        let mut matched_b = std::collections::HashSet::new();

        // Score matrix.
        let mut scores: Vec<MatchScore> = Vec::new();
        for fa in funcs_a {
            for fb in funcs_b {
                let score = MatchScore::compute(
                    fa,
                    fb,
                    self.w_name,
                    self.w_sig,
                    self.w_content,
                    self.w_cg,
                    self.w_bb,
                );
                if score.total_score >= self.threshold {
                    scores.push(score);
                }
            }
        }
        // Sort by descending total score.
        scores.sort_by(|x, y| {
            y.total_score
                .partial_cmp(&x.total_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for score in scores {
            if !matched_a.contains(&score.addr_a) && !matched_b.contains(&score.addr_b) {
                matched_a.insert(score.addr_a);
                matched_b.insert(score.addr_b);
                report.add_match(score);
            }
        }

        // Collect unmatched.
        for fa in funcs_a {
            if !matched_a.contains(&fa.address) {
                report.unmatched.add_a(fa.address);
            }
        }
        for fb in funcs_b {
            if !matched_b.contains(&fb.address) {
                report.unmatched.add_b(fb.address);
            }
        }

        report
    }

    /// Quick exact match: only match functions with identical `bytes_hash`.
    #[must_use] 
    pub fn exact_match_only(
        &self,
        funcs_a: &[FunctionProfile],
        funcs_b: &[FunctionProfile],
    ) -> Vec<(u64, u64)> {
        // bytes_hash values are derived from attacker-controlled function bytes;
        // use AHashMap to prevent hash-collision DoS.
        let b_by_hash: AHashMap<u64, u64> = funcs_b
            .iter()
            .filter(|f| f.bytes_hash != 0)
            .map(|f| (f.bytes_hash, f.address))
            .collect();
        funcs_a
            .iter()
            .filter_map(|fa| {
                b_by_hash
                    .get(&fa.bytes_hash)
                    .map(|&addr_b| (fa.address, addr_b))
            })
            .collect()
    }
}

impl Default for FunctionMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fn(
        addr: u64,
        name: &str,
        bytes_hash: u64,
        bb_count: u32,
        insns: u32,
    ) -> FunctionProfile {
        let mut f = FunctionProfile::new(addr, name);
        f.bytes_hash = bytes_hash;
        f.mnem_hash = bytes_hash;
        f.bb_hash = bytes_hash ^ 0x1234;
        f.cg_hash = bytes_hash ^ 0x5678;
        f.bb_count = bb_count;
        f.insn_count = insns;
        f
    }

    // ── FunctionProfile ───────────────────────────────────────────────────────

    #[test]
    fn test_profile_display() {
        let f = make_fn(0x1000, "main", 0xDEAD, 5, 50);
        assert!(f.to_string().contains("main"));
        assert!(f.to_string().contains("0x1000"));
    }

    #[test]
    fn test_profile_is_trivial() {
        let mut f = FunctionProfile::new(0x1000, "stub");
        f.insn_count = 1;
        assert!(f.is_trivial());
        f.insn_count = 10;
        assert!(!f.is_trivial());
    }

    // ── MatchScore ────────────────────────────────────────────────────────────

    #[test]
    fn test_match_score_exact_same_fn() {
        let a = make_fn(0x1000, "main", 0xABC, 5, 50);
        let b = make_fn(0x2000, "main", 0xABC, 5, 50);
        let score = MatchScore::compute(&a, &b, 1.5, 3.0, 1.5, 0.5, 1.0);
        assert!(score.total_score >= 0.9, "score={}", score.total_score);
        assert!(score.is_exact());
    }

    #[test]
    fn test_match_score_different_names() {
        let a = make_fn(0x1000, "sub_1000", 0x111, 3, 30);
        let b = make_fn(0x2000, "sub_2000", 0x222, 4, 35);
        let score = MatchScore::compute(&a, &b, 1.5, 3.0, 1.5, 0.5, 1.0);
        assert!(score.name_score < 0.1);
        assert_eq!(score.signature_score, 0.0);
    }

    #[test]
    fn test_match_score_is_renamed() {
        let a = make_fn(0x1000, "old_func", 0xBEEF, 2, 20);
        let b = make_fn(0x2000, "new_name", 0xBEEF, 2, 20);
        let score = MatchScore::compute(&a, &b, 1.5, 3.0, 1.5, 0.5, 1.0);
        assert!(score.is_renamed());
    }

    // ── MatchingStrategy ──────────────────────────────────────────────────────

    #[test]
    fn test_strategy_display() {
        assert_eq!(MatchingStrategy::Exact.to_string(), "exact");
        assert_eq!(MatchingStrategy::Heuristic.to_string(), "heuristic");
        assert_eq!(MatchingStrategy::Structural.to_string(), "structural");
    }

    // ── NameHashMatch ─────────────────────────────────────────────────────────

    #[test]
    fn test_name_hash_match_by_name() {
        let a = make_fn(0x1000, "foo", 0, 1, 10);
        let b_funcs = vec![
            make_fn(0x2000, "foo", 0, 1, 10),
            make_fn(0x3000, "bar", 0, 1, 5),
        ];
        let matches = NameHashMatch::find_matches(&a, &b_funcs);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address, 0x2000);
    }

    #[test]
    fn test_name_hash_match_by_hash() {
        let a = make_fn(0x1000, "sub_1000", 0xDEAD, 1, 5);
        let b_funcs = vec![make_fn(0x2000, "sub_2000", 0xDEAD, 1, 5)];
        let matches = NameHashMatch::find_matches(&a, &b_funcs);
        assert_eq!(matches.len(), 1);
    }

    // ── CallgraphContextMatch ─────────────────────────────────────────────────

    #[test]
    fn test_cg_score_same_cg_hash() {
        let mut a = make_fn(0x1000, "f", 0, 1, 10);
        let mut b = make_fn(0x2000, "f", 0, 1, 10);
        a.cg_hash = 0x42;
        b.cg_hash = 0x42;
        let score = CallgraphContextMatch::score(&a, &b);
        assert!((score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_cg_score_shared_callees() {
        let mut a = make_fn(0x1000, "f", 0, 2, 20);
        let mut b = make_fn(0x2000, "g", 0, 2, 20);
        a.callees = vec![0xA000, 0xB000];
        b.callees = vec![0xA000, 0xC000];
        let score = CallgraphContextMatch::score(&a, &b);
        assert!(score > 0.0 && score < 1.0, "score={score}");
    }

    // ── BbHashMatch ───────────────────────────────────────────────────────────

    #[test]
    fn test_bb_hash_exact_match() {
        let mut a = make_fn(0x1000, "f", 0, 1, 10);
        let mut b = make_fn(0x2000, "f", 0, 1, 10);
        a.bb_hash = 0x999;
        b.bb_hash = 0x999;
        assert!(BbHashMatch::is_exact_match(&a, &b));
    }

    #[test]
    fn test_bb_hash_no_match() {
        let a = make_fn(0x1000, "f", 0, 1, 10);
        let b = make_fn(0x2000, "g", 0, 5, 50);
        assert!(!BbHashMatch::is_exact_match(&a, &b));
    }

    // ── FunctionMatcher ───────────────────────────────────────────────────────

    #[test]
    fn test_matcher_match_all_identical() {
        let funcs = vec![
            make_fn(0x1000, "main", 0xABC, 5, 50),
            make_fn(0x2000, "init", 0xDEF, 2, 20),
        ];
        let matcher = FunctionMatcher::new();
        let report = matcher.match_all(&funcs, &funcs);
        assert_eq!(report.matched_count(), 2);
        assert_eq!(report.unmatched.total(), 0);
    }

    #[test]
    fn test_matcher_match_all_no_match() {
        let funcs_a = vec![make_fn(0x1000, "foo", 0x111, 1, 5)];
        let funcs_b = vec![make_fn(0x2000, "bar", 0x222, 10, 100)];
        let matcher = FunctionMatcher::new().with_threshold(0.99);
        let report = matcher.match_all(&funcs_a, &funcs_b);
        assert_eq!(report.matched_count(), 0);
        assert_eq!(report.unmatched.only_in_a.len(), 1);
        assert_eq!(report.unmatched.only_in_b.len(), 1);
    }

    #[test]
    fn test_matcher_exact_only() {
        let funcs_a = vec![
            make_fn(0x1000, "foo", 0xABC, 1, 5),
            make_fn(0x2000, "bar", 0xDEF, 1, 5),
        ];
        let funcs_b = vec![
            make_fn(0x3000, "foo2", 0xABC, 1, 5), // same hash
            make_fn(0x4000, "baz", 0x999, 1, 5),  // different hash
        ];
        let matcher = FunctionMatcher::new();
        let exact = matcher.exact_match_only(&funcs_a, &funcs_b);
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0], (0x1000, 0x3000));
    }

    #[test]
    fn test_report_similarity_score() {
        let mut report = MatchReport::new("a", "b");
        report.add_match(MatchScore {
            addr_a: 0,
            addr_b: 0,
            name_score: 1.0,
            signature_score: 1.0,
            content_score: 1.0,
            cg_score: 1.0,
            bb_score: 1.0,
            total_score: 1.0,
            strategy: MatchingStrategy::Exact,
        });
        report.add_match(MatchScore {
            addr_a: 1,
            addr_b: 1,
            name_score: 0.0,
            signature_score: 0.0,
            content_score: 0.5,
            cg_score: 0.5,
            bb_score: 0.5,
            total_score: 0.5,
            strategy: MatchingStrategy::Heuristic,
        });
        let score = report.similarity_score();
        assert!((score - 0.75).abs() < 1e-6, "score={score}");
    }

    #[test]
    fn test_report_strategy_counts() {
        let mut report = MatchReport::new("a", "b");
        report.add_match(MatchScore {
            addr_a: 0,
            addr_b: 0,
            name_score: 1.0,
            signature_score: 1.0,
            content_score: 1.0,
            cg_score: 1.0,
            bb_score: 1.0,
            total_score: 1.0,
            strategy: MatchingStrategy::Exact,
        });
        let counts = report.strategy_counts();
        assert_eq!(counts[&MatchingStrategy::Exact], 1);
    }

    #[test]
    fn test_report_display() {
        let report = MatchReport::new("old.bin", "new.bin");
        let s = report.to_string();
        assert!(s.contains("old.bin"), "display='{s}'");
        assert!(s.contains("new.bin"), "display='{s}'");
    }

    #[test]
    fn test_unmatched_functions() {
        let mut u = UnmatchedFunctions::new();
        u.add_a(0x1000);
        u.add_a(0x2000);
        u.add_b(0x3000);
        assert_eq!(u.total(), 3);
    }

    #[test]
    fn test_matcher_default() {
        let m = FunctionMatcher::default();
        assert!(m.threshold > 0.0 && m.threshold < 1.0);
    }
}
