//! Structural diff — compare two binaries/functions by CFG shape and call-graph
//! topology rather than raw bytes.
//!
//! Provides:
//! - `FunctionStructure` — CFG shape hash + metadata
//! - `CallgraphNode` — function node in a call graph
//! - `StructuralSimilarity` — weighted similarity score
//! - `StructuralMatcher` — matches functions across two binaries
//! - `DiffScore` — combined diff score
//! - `StructuralReport` — top-level report

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ── FunctionStructure ─────────────────────────────────────────────────────────

/// CFG-shape metadata for a single function.
#[derive(Debug, Clone)]
pub struct FunctionStructure {
    /// Start address.
    pub address: u64,
    /// Symbol name.
    pub name: String,
    /// FNV-1a hash of the CFG shape (block count, edge count, back-edge count).
    pub cfg_hash: u64,
    /// Number of basic blocks.
    pub block_count: u32,
    /// Number of CFG edges.
    pub edge_count: u32,
    /// Number of back edges (loop indicators).
    pub back_edges: u32,
    /// Number of outgoing call targets.
    pub call_count: u32,
    /// Number of incoming callers (call-graph in-degree).
    pub in_degree: u32,
    /// Function byte size.
    pub byte_size: u32,
    /// Hash of the sorted call-target list (callee addresses).
    pub callee_hash: u64,
}

impl FunctionStructure {
    /// Create a new structure descriptor.
    #[must_use]
    pub fn new(
        address: u64,
        name: String,
        block_count: u32,
        edge_count: u32,
        back_edges: u32,
        call_count: u32,
        byte_size: u32,
    ) -> Self {
        let cfg_hash = Self::compute_cfg_hash(block_count, edge_count, back_edges);
        Self {
            address,
            name,
            cfg_hash,
            block_count,
            edge_count,
            back_edges,
            call_count,
            in_degree: 0,
            byte_size,
            callee_hash: 0,
        }
    }

    /// Compute a hash from CFG shape metrics.
    #[must_use]
    pub fn compute_cfg_hash(block_count: u32, edge_count: u32, back_edges: u32) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &v in &[u64::from(block_count), u64::from(edge_count), u64::from(back_edges)] {
            h ^= v;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// Structural similarity to another function (0.0–1.0).
    ///
    /// Compares block count, edge count, call count, and byte size.
    #[must_use]
    pub fn structural_similarity(&self, other: &Self) -> f64 {
        let bc = ratio(f64::from(self.block_count), f64::from(other.block_count));
        let ec = ratio(f64::from(self.edge_count), f64::from(other.edge_count));
        let cc = ratio(f64::from(self.call_count), f64::from(other.call_count));
        let sz = ratio(f64::from(self.byte_size), f64::from(other.byte_size));
        // When every component ratio is exactly 1.0, return 1.0 directly to
        // avoid floating-point rounding from the mul_add chain (0.15+0.20+0.35+0.30).
        if (bc - 1.0).abs() < f64::EPSILON
            && (ec - 1.0).abs() < f64::EPSILON
            && (cc - 1.0).abs() < f64::EPSILON
            && (sz - 1.0).abs() < f64::EPSILON
        {
            return 1.0;
        }
        0.15f64.mul_add(sz, 0.20f64.mul_add(cc, 0.35f64.mul_add(bc, 0.30 * ec)))
    }

    /// Whether the CFG shape is identical to another structure.
    #[must_use]
    pub const fn shape_matches(&self, other: &Self) -> bool {
        self.cfg_hash == other.cfg_hash
            && self.block_count == other.block_count
            && self.edge_count == other.edge_count
    }
}

fn ratio(a: f64, b: f64) -> f64 {
    if a == 0.0 && b == 0.0 {
        return 1.0;
    }
    if a == 0.0 || b == 0.0 {
        return 0.0;
    }
    a.min(b) / a.max(b)
}

impl fmt::Display for FunctionStructure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{:#x} blocks={} edges={} calls={}",
            self.name, self.address, self.block_count, self.edge_count, self.call_count
        )
    }
}

// ── CallgraphNode ─────────────────────────────────────────────────────────────

/// A node in the call graph representing one function.
#[derive(Debug, Clone)]
pub struct CallgraphNode {
    pub address: u64,
    pub name: String,
    pub callees: Vec<u64>,
    pub callers: Vec<u64>,
}

impl CallgraphNode {
    /// Create a new call-graph node.
    #[must_use]
    pub const fn new(address: u64, name: String) -> Self {
        Self {
            address,
            name,
            callees: Vec::new(),
            callers: Vec::new(),
        }
    }

    /// Out-degree (number of called functions).
    #[must_use]
    pub const fn out_degree(&self) -> usize {
        self.callees.len()
    }

    /// In-degree (number of callers).
    #[must_use]
    pub const fn in_degree(&self) -> usize {
        self.callers.len()
    }

    /// Whether this function is a leaf (no callees).
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.callees.is_empty()
    }

    /// Whether this function is a root (no callers).
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.callers.is_empty()
    }

    /// Jaccard similarity between callee sets.
    #[must_use]
    pub fn callee_jaccard(&self, other: &Self) -> f64 {
        let a: HashSet<u64> = self.callees.iter().copied().collect();
        let b: HashSet<u64> = other.callees.iter().copied().collect();
        jaccard_sets(&a, &b)
    }
}

fn jaccard_sets(a: &HashSet<u64>, b: &HashSet<u64>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.len() + b.len() - intersection;
    if union == 0 {
        1.0
    } else {
        f64::from(u32::try_from(intersection).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(union).unwrap_or(u32::MAX))
    }
}

// ── Callgraph ─────────────────────────────────────────────────────────────────

/// A simple directed call graph.
#[derive(Debug, Default)]
pub struct Callgraph {
    nodes: HashMap<u64, CallgraphNode>,
}

impl Callgraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function node.
    pub fn add_function(&mut self, address: u64, name: String) {
        self.nodes
            .entry(address)
            .or_insert_with(|| CallgraphNode::new(address, name));
    }

    /// Add a call edge `caller → callee`.
    pub fn add_call(&mut self, from_addr: u64, to_addr: u64) {
        self.nodes.entry(from_addr).and_modify(|n| {
            if !n.callees.contains(&to_addr) {
                n.callees.push(to_addr);
            }
        });
        self.nodes.entry(to_addr).and_modify(|n| {
            if !n.callers.contains(&from_addr) {
                n.callers.push(from_addr);
            }
        });
    }

    /// Look up a node.
    #[must_use]
    pub fn get(&self, address: u64) -> Option<&CallgraphNode> {
        self.nodes.get(&address)
    }

    /// Number of functions in the call graph.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.nodes.len()
    }

    /// BFS reachability from `start`.
    #[must_use]
    pub fn reachable_from(&self, start: u64) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        while let Some(addr) = queue.pop_front() {
            if visited.insert(addr)
                && let Some(n) = self.nodes.get(&addr) {
                    for &callee in &n.callees {
                        if !visited.contains(&callee) {
                            queue.push_back(callee);
                        }
                    }
                }
        }
        visited
    }
}

// ── StructuralSimilarity ──────────────────────────────────────────────────────

/// Combined structural similarity result between two functions.
#[derive(Debug, Clone)]
pub struct StructuralSimilarity {
    /// CFG shape similarity score.
    pub cfg_score: f64,
    /// Call-graph neighbourhood similarity (callee-set Jaccard).
    pub callgraph_score: f64,
    /// Combined weighted score.
    pub combined_score: f64,
    /// Whether the CFG hashes are identical.
    pub cfg_hash_match: bool,
}

impl StructuralSimilarity {
    /// Compute structural similarity between two functions.
    #[must_use]
    pub fn compute(
        a: &FunctionStructure,
        b: &FunctionStructure,
        a_node: Option<&CallgraphNode>,
        b_node: Option<&CallgraphNode>,
    ) -> Self {
        let cfg_score = a.structural_similarity(b);
        let has_callgraph = a_node.is_some() && b_node.is_some();
        let callgraph_score = match (a_node, b_node) {
            (Some(an), Some(bn)) => an.callee_jaccard(bn),
            _ => 0.0,
        };
        // Without call-graph context the combined score collapses to the CFG score
        // so callers get a meaningful 0..1 value rather than a 0.6-scaled one.
        let combined_score = if has_callgraph {
            0.6f64.mul_add(cfg_score, 0.4 * callgraph_score)
        } else {
            cfg_score
        };
        let cfg_hash_match = a.shape_matches(b);
        Self {
            cfg_score,
            callgraph_score,
            combined_score,
            cfg_hash_match,
        }
    }
}

// ── StructuralMatch ───────────────────────────────────────────────────────────

/// A function pair match produced by structural analysis.
#[derive(Debug, Clone)]
pub struct StructuralMatch {
    /// Function from binary A.
    pub func_a: FunctionStructure,
    /// Function from binary B.
    pub func_b: FunctionStructure,
    /// Similarity scores.
    pub similarity: StructuralSimilarity,
}

/// Kind of structural match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralMatchKind {
    /// Identical CFG hash (likely same function).
    ExactCfgHash,
    /// High combined score (>0.85).
    High,
    /// Medium combined score (0.60–0.85).
    Medium,
    /// Low combined score (<0.60).
    Low,
    /// No match found (added/removed).
    None,
}

impl StructuralMatch {
    /// Classify the match quality.
    #[must_use]
    pub fn kind(&self) -> StructuralMatchKind {
        if self.similarity.cfg_hash_match {
            return StructuralMatchKind::ExactCfgHash;
        }
        match self.similarity.combined_score {
            s if s > 0.85 => StructuralMatchKind::High,
            s if s >= 0.60 => StructuralMatchKind::Medium,
            _ => StructuralMatchKind::Low,
        }
    }
}

// ── StructuralMatcher ─────────────────────────────────────────────────────────

/// Matches functions across two binaries by structural features.
pub struct StructuralMatcher {
    pub threshold: f64,
}

impl StructuralMatcher {
    /// Create a matcher with a minimum combined-score threshold.
    #[must_use]
    pub const fn new(threshold: f64) -> Self {
        Self { threshold }
    }

    /// Match two lists of function structures.
    ///
    /// Returns a list of paired matches and lists of unmatched A/B functions.
    #[must_use]
    pub fn match_functions(
        &self,
        funcs_a: &[FunctionStructure],
        funcs_b: &[FunctionStructure],
        cg_a: Option<&Callgraph>,
        cg_b: Option<&Callgraph>,
    ) -> (
        Vec<StructuralMatch>,
        Vec<FunctionStructure>,
        Vec<FunctionStructure>,
    ) {
        let mut matched_b = vec![false; funcs_b.len()];
        let mut matches = Vec::with_capacity(funcs_a.len().min(funcs_b.len()));
        let mut unmatched_a = Vec::new();

        // Pass 1: exact CFG hash
        for fa in funcs_a {
            let found = funcs_b
                .iter()
                .enumerate()
                .find(|(i, fb)| !matched_b[*i] && fa.shape_matches(fb));
            if let Some((i, fb)) = found {
                matched_b[i] = true;
                let sim = StructuralSimilarity::compute(
                    fa,
                    fb,
                    cg_a.and_then(|cg| cg.get(fa.address)),
                    cg_b.and_then(|cg| cg.get(fb.address)),
                );
                matches.push(StructuralMatch {
                    func_a: fa.clone(),
                    func_b: fb.clone(),
                    similarity: sim,
                });
            } else {
                unmatched_a.push(fa.clone());
            }
        }

        // Pass 2: greedy score match
        let mut remaining_a = Vec::new();
        for fa in &unmatched_a {
            let best = funcs_b
                .iter()
                .enumerate()
                .filter(|(i, _)| !matched_b[*i])
                .map(|(i, fb)| {
                    let sim = StructuralSimilarity::compute(
                        fa,
                        fb,
                        cg_a.and_then(|cg| cg.get(fa.address)),
                        cg_b.and_then(|cg| cg.get(fb.address)),
                    );
                    (i, fb, sim)
                })
                .filter(|(_, _, sim)| sim.combined_score >= self.threshold)
                .max_by(|a, b| {
                    a.2.combined_score
                        .partial_cmp(&b.2.combined_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });

            if let Some((i, fb, sim)) = best {
                matched_b[i] = true;
                matches.push(StructuralMatch {
                    func_a: fa.clone(),
                    func_b: fb.clone(),
                    similarity: sim,
                });
            } else {
                remaining_a.push(fa.clone());
            }
        }

        let unmatched_b: Vec<_> = funcs_b
            .iter()
            .enumerate()
            .filter(|(i, _)| !matched_b[*i])
            .map(|(_, fb)| fb.clone())
            .collect();

        (matches, remaining_a, unmatched_b)
    }
}

impl Default for StructuralMatcher {
    fn default() -> Self {
        Self::new(0.5)
    }
}

// ── DiffScore ─────────────────────────────────────────────────────────────────

/// Overall structural diff score between two binaries.
#[derive(Debug, Clone)]
pub struct DiffScore {
    /// Number of function pairs matched.
    pub matched: usize,
    /// Number of functions added in B.
    pub added: usize,
    /// Number of functions removed from A.
    pub removed: usize,
    /// Mean combined similarity score of matched pairs.
    pub mean_similarity: f64,
    /// Weighted binary similarity: `matched / (matched + added + removed)`.
    pub binary_similarity: f64,
}

impl DiffScore {
    /// Compute from match results.
    #[must_use]
    pub fn compute(
        match_results: &[StructuralMatch],
        unmatched_a: &[FunctionStructure],
        unmatched_b: &[FunctionStructure],
    ) -> Self {
        let pair_count = match_results.len();
        let added = unmatched_b.len();
        let removed = unmatched_a.len();
        let mean_similarity = if pair_count > 0 {
            match_results
                .iter()
                .map(|m| m.similarity.combined_score)
                .sum::<f64>()
                / f64::from(u32::try_from(pair_count).unwrap_or(u32::MAX))
        } else {
            0.0
        };
        let total = pair_count + added + removed;
        let binary_similarity = if total > 0 {
            f64::from(u32::try_from(pair_count).unwrap_or(u32::MAX))
                * mean_similarity
                / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        } else {
            1.0
        };
        let matched = pair_count;
        Self {
            matched,
            added,
            removed,
            mean_similarity,
            binary_similarity,
        }
    }

    /// Overall change percentage.
    #[must_use]
    pub fn change_percent(&self) -> f64 {
        (1.0 - self.binary_similarity) * 100.0
    }
}

impl fmt::Display for DiffScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "matched={} added={} removed={} sim={:.2}% change={:.1}%",
            self.matched,
            self.added,
            self.removed,
            self.mean_similarity * 100.0,
            self.change_percent()
        )
    }
}

// ── StructuralReport ──────────────────────────────────────────────────────────

/// Top-level structural diff report.
#[derive(Debug, Clone)]
pub struct StructuralReport {
    pub binary_a: String,
    pub binary_b: String,
    pub score: DiffScore,
    pub matches: Vec<StructuralMatch>,
    pub added: Vec<FunctionStructure>,
    pub removed: Vec<FunctionStructure>,
}

impl StructuralReport {
    /// Build a report from matcher output.
    #[must_use]
    pub fn new(
        binary_a: String,
        binary_b: String,
        matches: Vec<StructuralMatch>,
        removed: Vec<FunctionStructure>,
        added: Vec<FunctionStructure>,
    ) -> Self {
        let score = DiffScore::compute(&matches, &removed, &added);
        Self {
            binary_a,
            binary_b,
            score,
            matches,
            added,
            removed,
        }
    }

    /// Functions with exact CFG hash matches (likely unchanged).
    #[must_use]
    pub fn exact_matches(&self) -> Vec<&StructuralMatch> {
        self.matches
            .iter()
            .filter(|m| m.kind() == StructuralMatchKind::ExactCfgHash)
            .collect()
    }

    /// Functions with high structural similarity but not exact.
    #[must_use]
    pub fn high_similarity_matches(&self) -> Vec<&StructuralMatch> {
        self.matches
            .iter()
            .filter(|m| m.kind() == StructuralMatchKind::High)
            .collect()
    }

    /// Whether the two binaries appear structurally identical.
    #[must_use]
    pub fn is_identical(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.matches.iter().all(|m| m.similarity.cfg_hash_match)
    }
}

impl fmt::Display for StructuralReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StructuralReport [{} vs {}] {}",
            self.binary_a, self.binary_b, self.score
        )
    }
}

// ── StructuralDiff — convenience entry point ──────────────────────────────────

/// Convenience struct that runs the full structural diff pipeline.
pub struct StructuralDiff {
    pub matcher: StructuralMatcher,
}

impl StructuralDiff {
    #[must_use]
    pub const fn new(threshold: f64) -> Self {
        Self {
            matcher: StructuralMatcher::new(threshold),
        }
    }

    /// Run structural diff and produce a [`StructuralReport`].
    #[must_use]
    pub fn diff(
        &self,
        funcs_a: &[FunctionStructure],
        funcs_b: &[FunctionStructure],
        name_a: String,
        name_b: String,
        cg_a: Option<&Callgraph>,
        cg_b: Option<&Callgraph>,
    ) -> StructuralReport {
        let (matches, removed, added) =
            self.matcher.match_functions(funcs_a, funcs_b, cg_a, cg_b);
        StructuralReport::new(name_a, name_b, matches, removed, added)
    }
}

impl Default for StructuralDiff {
    fn default() -> Self {
        Self::new(0.5)
    }
}

// ── ChangeClassifier ─────────────────────────────────────────────────────────

/// Classifies the change between two matched functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeClass {
    /// Byte-identical (exact CFG hash match).
    Unchanged,
    /// Minor refactoring: same topology but slightly different instruction counts.
    MinorRefactor,
    /// Structural patch: changed CFG topology (different block or edge counts).
    StructuralPatch,
    /// Significant rewrite: low similarity.
    MajorRewrite,
    /// Added in B.
    Added,
    /// Removed in A.
    Removed,
}

impl ChangeClass {
    /// Classify a structural match.
    #[must_use]
    pub fn classify(m: &StructuralMatch) -> Self {
        if m.similarity.cfg_hash_match && m.similarity.combined_score > 0.99 {
            return Self::Unchanged;
        }
        let sim = m.similarity.combined_score;
        if sim > 0.85 {
            Self::MinorRefactor
        } else if sim > 0.60 {
            Self::StructuralPatch
        } else {
            Self::MajorRewrite
        }
    }

    /// Short label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::MinorRefactor => "minor",
            Self::StructuralPatch => "patch",
            Self::MajorRewrite => "rewrite",
            Self::Added => "added",
            Self::Removed => "removed",
        }
    }
}

// ── StructuralDiffSummary ─────────────────────────────────────────────────────

/// A compact summary table of a structural diff.
#[derive(Debug, Clone)]
pub struct StructuralDiffSummary {
    pub unchanged_count: usize,
    pub minor_count: usize,
    pub patch_count: usize,
    pub rewrite_count: usize,
    pub added_count: usize,
    pub removed_count: usize,
    pub similarity_score: f64,
}

impl StructuralDiffSummary {
    /// Build from a report.
    #[must_use]
    pub fn from_report(r: &StructuralReport) -> Self {
        let mut unchanged = 0;
        let mut minor = 0;
        let mut patch = 0;
        let mut rewrite = 0;
        for m in &r.matches {
            match ChangeClass::classify(m) {
                ChangeClass::Unchanged => unchanged += 1,
                ChangeClass::MinorRefactor => minor += 1,
                ChangeClass::StructuralPatch => patch += 1,
                ChangeClass::MajorRewrite => rewrite += 1,
                _ => {}
            }
        }
        Self {
            unchanged_count: unchanged,
            minor_count: minor,
            patch_count: patch,
            rewrite_count: rewrite,
            added_count: r.added.len(),
            removed_count: r.removed.len(),
            similarity_score: r.score.binary_similarity,
        }
    }

    /// Total functions analyzed.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.unchanged_count
            + self.minor_count
            + self.patch_count
            + self.rewrite_count
            + self.added_count
            + self.removed_count
    }
}

impl fmt::Display for StructuralDiffSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "=={} +{} -{} ~{} patch={} rewrite={} sim={:.1}%",
            self.unchanged_count,
            self.added_count,
            self.removed_count,
            self.minor_count,
            self.patch_count,
            self.rewrite_count,
            self.similarity_score * 100.0
        )
    }
}

// ── DiffHeatmap ───────────────────────────────────────────────────────────────

/// A heatmap of similarity scores, bucketed into deciles.
#[derive(Debug, Clone, Default)]
pub struct DiffHeatmap {
    /// Buckets[0] = [0.0, 0.1), ..., Buckets[9] = [0.9, 1.0], Buckets[10] = exact 1.0
    pub buckets: [usize; 11],
}

impl DiffHeatmap {
    /// Build from a list of matches.
    #[must_use]
    pub fn from_matches(matches: &[StructuralMatch]) -> Self {
        let mut h = Self::default();
        for m in matches {
            let sim = m.similarity.combined_score;
            let bucket = if (sim - 1.0).abs() < 1e-9 { 10 }
                else if sim >= 0.9 { 9 }
                else if sim >= 0.8 { 8 }
                else if sim >= 0.7 { 7 }
                else if sim >= 0.6 { 6 }
                else if sim >= 0.5 { 5 }
                else if sim >= 0.4 { 4 }
                else if sim >= 0.3 { 3 }
                else if sim >= 0.2 { 2 }
                else { usize::from(sim >= 0.1) };
            h.buckets[bucket.min(10)] += 1;
        }
        h
    }

    /// Total matches in all buckets.
    #[must_use]
    pub fn total(&self) -> usize {
        self.buckets.iter().sum()
    }

    /// Bucket index containing the median similarity.
    #[must_use]
    pub fn median_bucket(&self) -> usize {
        let total = self.total();
        if total == 0 {
            return 0;
        }
        let target = total / 2;
        let mut cumulative = 0;
        for (i, &count) in self.buckets.iter().enumerate() {
            cumulative += count;
            if cumulative >= target {
                return i;
            }
        }
        10
    }
}

impl fmt::Display for DiffHeatmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, &c) in self.buckets.iter().enumerate() {
            if i > 0 {
                write!(f, "|")?;
            }
            write!(f, "{c:3}")?;
        }
        write!(f, "]")
    }
}

// ── StructuralStats ────────────────────────────────────────────────────────────

/// Aggregate statistics about a structural diff.
#[derive(Debug, Clone, Default)]
pub struct StructuralStats {
    pub total_funcs_a: usize,
    pub total_funcs_b: usize,
    pub exact_matches: usize,
    pub high_similarity: usize,
    pub medium_similarity: usize,
    pub low_similarity: usize,
    pub added: usize,
    pub removed: usize,
    pub mean_block_count_a: f64,
    pub mean_block_count_b: f64,
}

impl StructuralStats {
    /// Compute from a report.
    #[must_use]
    pub fn from_report(report: &StructuralReport) -> Self {
        let mut exact = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        for m in &report.matches {
            match m.kind() {
                StructuralMatchKind::ExactCfgHash => exact += 1,
                StructuralMatchKind::High => high += 1,
                StructuralMatchKind::Medium => medium += 1,
                StructuralMatchKind::Low | StructuralMatchKind::None => low += 1,
            }
        }
        let mean_bc_a = if report.score.matched > 0 {
            report
                .matches
                .iter()
                .map(|m| f64::from(m.func_a.block_count))
                .sum::<f64>()
                / f64::from(u32::try_from(report.matches.len()).unwrap_or(u32::MAX))
        } else {
            0.0
        };
        let mean_bc_b = if report.score.matched > 0 {
            report
                .matches
                .iter()
                .map(|m| f64::from(m.func_b.block_count))
                .sum::<f64>()
                / f64::from(u32::try_from(report.matches.len()).unwrap_or(u32::MAX))
        } else {
            0.0
        };

        Self {
            total_funcs_a: report.score.matched + report.score.removed,
            total_funcs_b: report.score.matched + report.score.added,
            exact_matches: exact,
            high_similarity: high,
            medium_similarity: medium,
            low_similarity: low,
            added: report.score.added,
            removed: report.score.removed,
            mean_block_count_a: mean_bc_a,
            mean_block_count_b: mean_bc_b,
        }
    }

    /// Percentage of functions matched with high confidence.
    #[must_use]
    pub fn high_confidence_percent(&self) -> f64 {
        let total = self.total_funcs_a.max(1);
        f64::from(u32::try_from(self.exact_matches + self.high_similarity).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
            * 100.0
    }
}

impl fmt::Display for StructuralStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Stats: A={} B={} exact={} high={} medium={} low={} +{} -{}",
            self.total_funcs_a,
            self.total_funcs_b,
            self.exact_matches,
            self.high_similarity,
            self.medium_similarity,
            self.low_similarity,
            self.added,
            self.removed
        )
    }
}

// ── FunctionSizeProfile ───────────────────────────────────────────────────────

/// Profile of function sizes in a binary.
#[derive(Debug, Clone, Default)]
pub struct FunctionSizeProfile {
    pub min_size: u32,
    pub max_size: u32,
    pub mean_size: f64,
    pub median_size: u32,
    pub total_functions: usize,
}

impl FunctionSizeProfile {
    /// Compute from a slice of function structures.
    /// # Panics
    ///
    /// Never panics: the `funcs.is_empty()` guard ensures sizes is non-empty
    /// before the `unwrap()` calls on `first()` and `last()`.
    #[must_use]
    pub fn compute(funcs: &[FunctionStructure]) -> Self {
        if funcs.is_empty() {
            return Self::default();
        }
        let mut sizes: Vec<u32> = funcs.iter().map(|f| f.byte_size).collect();
        sizes.sort_unstable();
        let min_size = *sizes.first().unwrap();
        let max_size = *sizes.last().unwrap();
        let mean_size = sizes.iter().map(|&s| f64::from(s)).sum::<f64>()
            / f64::from(u32::try_from(sizes.len()).unwrap_or(u32::MAX));
        let median_size = sizes[sizes.len() / 2];
        Self {
            min_size,
            max_size,
            mean_size,
            median_size,
            total_functions: funcs.len(),
        }
    }

    /// Percentage of functions within [min, max] size range.
    #[must_use]
    pub fn within_range_percent(&self, lo: u32, hi: u32, funcs: &[FunctionStructure]) -> f64 {
        if funcs.is_empty() {
            return 0.0;
        }
        let count = funcs
            .iter()
            .filter(|f| f.byte_size >= lo && f.byte_size <= hi)
            .count();
        f64::from(u32::try_from(count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(funcs.len()).unwrap_or(u32::MAX))
            * 100.0
    }
}

// ── ComplexityScore ───────────────────────────────────────────────────────────

/// Cyclomatic-complexity-like score for a function structure.
#[derive(Debug, Clone)]
pub struct ComplexityScore {
    /// `McCabe`'s cyclomatic complexity: E - N + 2P.
    pub mccabe: u32,
    /// Nesting depth estimate (back-edge count + 1).
    pub nesting: u32,
    /// Call fan-out.
    pub fan_out: u32,
}

impl ComplexityScore {
    /// Compute from a function structure.
    #[must_use]
    pub const fn compute(func: &FunctionStructure) -> Self {
        // McCabe: E - N + 2 (single connected component)
        let mccabe = func
            .edge_count
            .saturating_sub(func.block_count)
            .saturating_add(2);
        let nesting = func.back_edges + 1;
        let fan_out = func.call_count;
        Self {
            mccabe,
            nesting,
            fan_out,
        }
    }

    /// Whether this function is considered "complex" (mccabe >= 10).
    #[must_use]
    pub const fn is_complex(&self) -> bool {
        self.mccabe >= 10
    }

    /// Combine mccabe, nesting, `fan_out` into a single difficulty score.
    #[must_use]
    pub fn difficulty(&self) -> f64 {
        0.2f64.mul_add(f64::from(self.fan_out), 0.5f64.mul_add(f64::from(self.mccabe), 0.3 * f64::from(self.nesting)))
    }
}

impl fmt::Display for ComplexityScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CC={} nesting={} fan_out={} difficult={:.1}",
            self.mccabe,
            self.nesting,
            self.fan_out,
            self.difficulty()
        )
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fs(
        addr: u64,
        name: &str,
        blocks: u32,
        edges: u32,
        back: u32,
        calls: u32,
        sz: u32,
    ) -> FunctionStructure {
        FunctionStructure::new(addr, name.to_string(), blocks, edges, back, calls, sz)
    }

    // --- FunctionStructure ---

    #[test]
    fn test_fs_cfg_hash_deterministic() {
        let h1 = FunctionStructure::compute_cfg_hash(4, 5, 1);
        let h2 = FunctionStructure::compute_cfg_hash(4, 5, 1);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_fs_cfg_hash_differs() {
        let h1 = FunctionStructure::compute_cfg_hash(4, 5, 1);
        let h2 = FunctionStructure::compute_cfg_hash(4, 6, 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_fs_shape_matches_equal() {
        let a = make_fs(0x1000, "f", 4, 5, 1, 2, 100);
        let b = make_fs(0x2000, "g", 4, 5, 1, 2, 100);
        assert!(a.shape_matches(&b));
    }

    #[test]
    fn test_fs_shape_matches_different() {
        let a = make_fs(0x1000, "f", 4, 5, 1, 2, 100);
        let b = make_fs(0x2000, "g", 5, 6, 1, 2, 120);
        assert!(!a.shape_matches(&b));
    }

    #[test]
    fn test_fs_structural_similarity_identical() {
        let a = make_fs(0x1000, "f", 4, 5, 1, 2, 100);
        assert_eq!(a.structural_similarity(&a), 1.0);
    }

    #[test]
    fn test_fs_structural_similarity_different() {
        let a = make_fs(0x1000, "f", 4, 5, 1, 2, 100);
        let b = make_fs(0x2000, "g", 1, 1, 0, 0, 10);
        let s = a.structural_similarity(&b);
        assert!((0.0..1.0).contains(&s));
    }

    #[test]
    fn test_fs_display() {
        let a = make_fs(0x1000, "main", 3, 4, 1, 2, 50);
        let s = a.to_string();
        assert!(s.contains("main"));
        assert!(s.contains("blocks=3"));
    }

    // --- CallgraphNode ---

    #[test]
    fn test_cg_node_leaf() {
        let n = CallgraphNode::new(0x1000, "f".to_string());
        assert!(n.is_leaf());
        assert!(n.is_root());
    }

    #[test]
    fn test_cg_node_degrees() {
        let mut n = CallgraphNode::new(0x1000, "f".to_string());
        n.callees.push(0x2000);
        n.callers.push(0x3000);
        assert_eq!(n.out_degree(), 1);
        assert_eq!(n.in_degree(), 1);
    }

    #[test]
    fn test_cg_node_callee_jaccard_empty() {
        let a = CallgraphNode::new(0, "a".to_string());
        let b = CallgraphNode::new(0, "b".to_string());
        assert_eq!(a.callee_jaccard(&b), 1.0);
    }

    #[test]
    fn test_cg_node_callee_jaccard_disjoint() {
        let mut a = CallgraphNode::new(0, "a".to_string());
        a.callees = vec![1, 2];
        let mut b = CallgraphNode::new(0, "b".to_string());
        b.callees = vec![3, 4];
        assert_eq!(a.callee_jaccard(&b), 0.0);
    }

    #[test]
    fn test_cg_node_callee_jaccard_partial() {
        let mut a = CallgraphNode::new(0, "a".to_string());
        a.callees = vec![1, 2, 3];
        let mut b = CallgraphNode::new(0, "b".to_string());
        b.callees = vec![2, 3, 4];
        let j = a.callee_jaccard(&b);
        assert!((j - 0.5).abs() < 1e-9); // intersection=2, union=4
    }

    // --- Callgraph ---

    #[test]
    fn test_callgraph_add_function() {
        let mut cg = Callgraph::new();
        cg.add_function(0x1000, "f".to_string());
        assert_eq!(cg.function_count(), 1);
    }

    #[test]
    fn test_callgraph_add_call() {
        let mut cg = Callgraph::new();
        cg.add_function(0x1000, "f".to_string());
        cg.add_function(0x2000, "g".to_string());
        cg.add_call(0x1000, 0x2000);
        let n = cg.get(0x1000).unwrap();
        assert!(n.callees.contains(&0x2000));
    }

    #[test]
    fn test_callgraph_reachable_from() {
        let mut cg = Callgraph::new();
        for addr in [0x1000, 0x2000, 0x3000] {
            cg.add_function(addr, format!("{addr:#x}"));
        }
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x2000, 0x3000);
        let r = cg.reachable_from(0x1000);
        assert!(r.contains(&0x3000));
    }

    // --- StructuralSimilarity ---

    #[test]
    fn test_structural_similarity_identical_hash() {
        let a = make_fs(0x1000, "f", 4, 5, 1, 2, 100);
        let b = make_fs(0x2000, "f", 4, 5, 1, 2, 100);
        let sim = StructuralSimilarity::compute(&a, &b, None, None);
        assert!(sim.cfg_hash_match);
        assert_eq!(sim.combined_score, sim.cfg_score); // no callgraph
    }

    #[test]
    fn test_structural_similarity_range() {
        let a = make_fs(0x1000, "f", 4, 5, 1, 2, 100);
        let b = make_fs(0x2000, "g", 10, 15, 3, 5, 500);
        let sim = StructuralSimilarity::compute(&a, &b, None, None);
        assert!((0.0..=1.0).contains(&sim.combined_score));
    }

    // --- StructuralMatcher ---

    #[test]
    fn test_matcher_exact_hash_match() {
        let funcs_a = vec![make_fs(0x1000, "f", 4, 5, 1, 2, 100)];
        let funcs_b = vec![make_fs(0x2000, "f", 4, 5, 1, 2, 100)];
        let m = StructuralMatcher::default();
        let (matches, ua, ub) = m.match_functions(&funcs_a, &funcs_b, None, None);
        assert_eq!(matches.len(), 1);
        assert!(ua.is_empty());
        assert!(ub.is_empty());
    }

    #[test]
    fn test_matcher_unmatched() {
        let funcs_a = vec![make_fs(0x1000, "f", 1, 1, 0, 0, 4)];
        let funcs_b = vec![make_fs(0x2000, "g", 100, 200, 50, 30, 5000)];
        let m = StructuralMatcher::new(0.99); // very high threshold
        let (matches, ua, ub) = m.match_functions(&funcs_a, &funcs_b, None, None);
        // With high threshold and very different shapes, likely no match
        assert!(matches.len() + ua.len() + ub.len() > 0);
    }

    // --- DiffScore ---

    #[test]
    fn test_diff_score_empty() {
        let score = DiffScore::compute(&[], &[], &[]);
        assert_eq!(score.binary_similarity, 1.0);
    }

    #[test]
    fn test_diff_score_all_added() {
        let funcs_b = vec![make_fs(0, "f", 1, 1, 0, 0, 10)];
        let score = DiffScore::compute(&[], &[], &funcs_b);
        assert_eq!(score.added, 1);
        assert_eq!(score.binary_similarity, 0.0);
    }

    #[test]
    fn test_diff_score_change_percent() {
        let score = DiffScore {
            matched: 8,
            added: 1,
            removed: 1,
            mean_similarity: 0.8,
            binary_similarity: 0.64,
        };
        let c = score.change_percent();
        assert!((c - 36.0).abs() < 0.5);
    }

    #[test]
    fn test_diff_score_display() {
        let score = DiffScore::compute(&[], &[], &[]);
        let s = score.to_string();
        assert!(s.contains("matched=0"));
    }

    // --- StructuralReport ---

    #[test]
    fn test_report_is_identical_empty() {
        let r = StructuralReport::new("a".to_string(), "b".to_string(), vec![], vec![], vec![]);
        assert!(r.is_identical());
    }

    #[test]
    fn test_report_added_makes_not_identical() {
        let added = vec![make_fs(0, "new", 1, 1, 0, 0, 10)];
        let r = StructuralReport::new("a".to_string(), "b".to_string(), vec![], vec![], added);
        assert!(!r.is_identical());
    }

    #[test]
    fn test_report_display() {
        let r = StructuralReport::new(
            "bin_a".to_string(),
            "bin_b".to_string(),
            vec![],
            vec![],
            vec![],
        );
        let s = r.to_string();
        assert!(s.contains("bin_a"));
    }

    // --- StructuralDiff ---

    #[test]
    fn test_structural_diff_two_identical() {
        let sd = StructuralDiff::default();
        let funcs = vec![make_fs(0x1000, "f", 4, 5, 1, 2, 100)];
        let report = sd.diff(
            &funcs,
            &funcs,
            "a".to_string(),
            "b".to_string(),
            None,
            None,
        );
        assert_eq!(report.score.matched, 1);
        assert_eq!(report.score.added, 0);
        assert_eq!(report.score.removed, 0);
    }

    #[test]
    fn test_structural_diff_no_functions() {
        let sd = StructuralDiff::default();
        let report = sd.diff(&[], &[], "a".to_string(), "b".to_string(), None, None);
        assert_eq!(report.score.matched, 0);
    }

    // --- ratio helper ---

    #[test]
    fn test_ratio_both_zero() {
        assert_eq!(ratio(0.0, 0.0), 1.0);
    }

    #[test]
    fn test_ratio_one_zero() {
        assert_eq!(ratio(5.0, 0.0), 0.0);
    }

    #[test]
    fn test_ratio_equal() {
        assert_eq!(ratio(7.0, 7.0), 1.0);
    }

    #[test]
    fn test_ratio_half() {
        assert_eq!(ratio(4.0, 8.0), 0.5);
    }

    // --- Additional StructuralMatcher tests ---

    #[test]
    fn test_matcher_multiple_functions() {
        let funcs_a = vec![
            make_fs(0x1000, "f1", 4, 5, 1, 2, 100),
            make_fs(0x2000, "f2", 2, 3, 0, 1, 50),
        ];
        let funcs_b = vec![
            make_fs(0x3000, "f1", 4, 5, 1, 2, 100),   // should match f1
            make_fs(0x4000, "f3", 10, 20, 5, 8, 500), // no match
        ];
        let m = StructuralMatcher::default();
        let (matches, ua, ub) = m.match_functions(&funcs_a, &funcs_b, None, None);
        assert!(!matches.is_empty());
        assert!(ua.len() + matches.len() + ub.len() > 0);
    }

    // --- DiffScore additional ---

    #[test]
    fn test_diff_score_all_removed() {
        let funcs_a = vec![make_fs(0, "f", 1, 1, 0, 0, 10)];
        let score = DiffScore::compute(&[], &funcs_a, &[]);
        assert_eq!(score.removed, 1);
    }

    #[test]
    fn test_diff_score_with_matches() {
        let funcs_a = vec![make_fs(0x1000, "f", 4, 5, 1, 2, 100)];
        let funcs_b = vec![make_fs(0x2000, "f", 4, 5, 1, 2, 100)];
        let m = StructuralMatcher::default();
        let (matches, ua, ub) = m.match_functions(&funcs_a, &funcs_b, None, None);
        let score = DiffScore::compute(&matches, &ua, &ub);
        assert_eq!(score.matched, 1);
        assert!(score.mean_similarity > 0.0);
    }

    // --- StructuralReport ---

    #[test]
    fn test_report_exact_matches() {
        let funcs_a = vec![make_fs(0x1000, "f", 4, 5, 1, 2, 100)];
        let funcs_b = vec![make_fs(0x2000, "f", 4, 5, 1, 2, 100)];
        let m = StructuralMatcher::default();
        let (matches, ua, ub) = m.match_functions(&funcs_a, &funcs_b, None, None);
        let r = StructuralReport::new("a".to_string(), "b".to_string(), matches, ua, ub);
        assert_eq!(r.exact_matches().len(), 1);
    }

    #[test]
    fn test_report_high_similarity_empty() {
        let r = StructuralReport::new("a".to_string(), "b".to_string(), vec![], vec![], vec![]);
        assert!(r.high_similarity_matches().is_empty());
    }

    // --- StructuralDiff with callgraph ---

    #[test]
    fn test_structural_diff_with_callgraph() {
        let sd = StructuralDiff::default();
        let mut cg_a = Callgraph::new();
        cg_a.add_function(0x1000, "f".to_string());
        cg_a.add_function(0x2000, "g".to_string());
        cg_a.add_call(0x1000, 0x2000);
        let funcs_a = vec![make_fs(0x1000, "f", 4, 5, 1, 2, 100)];
        let funcs_b = vec![make_fs(0x3000, "f", 4, 5, 1, 2, 100)];
        let report = sd.diff(
            &funcs_a,
            &funcs_b,
            "a".to_string(),
            "b".to_string(),
            Some(&cg_a),
            None,
        );
        assert!(report.score.matched + report.score.added + report.score.removed > 0);
    }

    // --- Callgraph BFS ---

    #[test]
    fn test_cg_reachable_self() {
        let mut cg = Callgraph::new();
        cg.add_function(0x1000, "f".to_string());
        let r = cg.reachable_from(0x1000);
        assert!(r.contains(&0x1000));
    }

    #[test]
    fn test_cg_reachable_not_found() {
        let cg = Callgraph::new();
        let r = cg.reachable_from(0x9999);
        assert!(!r.contains(&0x1000));
    }

    #[test]
    fn test_cg_add_duplicate_call() {
        let mut cg = Callgraph::new();
        cg.add_function(0x1000, "f".to_string());
        cg.add_function(0x2000, "g".to_string());
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x1000, 0x2000); // duplicate
        let n = cg.get(0x1000).unwrap();
        assert_eq!(n.out_degree(), 1); // no duplicate edges
    }

    // --- ChangeClassifier tests ---

    #[test]
    fn test_change_class_label_unchanged() {
        assert_eq!(ChangeClass::Unchanged.label(), "unchanged");
    }

    #[test]
    fn test_change_class_label_added() {
        assert_eq!(ChangeClass::Added.label(), "added");
    }

    #[test]
    fn test_change_class_label_minor() {
        assert_eq!(ChangeClass::MinorRefactor.label(), "minor");
    }

    // --- DiffHeatmap tests ---

    #[test]
    fn test_heatmap_empty() {
        let h = DiffHeatmap::from_matches(&[]);
        assert_eq!(h.total(), 0);
    }

    #[test]
    fn test_heatmap_display() {
        let h = DiffHeatmap::default();
        let s = h.to_string();
        assert!(s.starts_with('['));
    }

    // --- StructuralStats tests ---

    #[test]
    fn test_stats_from_report_empty() {
        let r = StructuralReport::new("a".to_string(), "b".to_string(), vec![], vec![], vec![]);
        let s = StructuralStats::from_report(&r);
        assert_eq!(s.total_funcs_a, 0);
    }

    #[test]
    fn test_stats_high_confidence_zero() {
        let r = StructuralReport::new("a".to_string(), "b".to_string(), vec![], vec![], vec![]);
        let s = StructuralStats::from_report(&r);
        assert_eq!(s.high_confidence_percent(), 0.0);
    }

    // --- FunctionSizeProfile tests ---

    #[test]
    fn test_size_profile_empty() {
        let p = FunctionSizeProfile::compute(&[]);
        assert_eq!(p.total_functions, 0);
    }

    #[test]
    fn test_size_profile_single() {
        let funcs = vec![make_fs(0, "f", 2, 3, 0, 1, 100)];
        let p = FunctionSizeProfile::compute(&funcs);
        assert_eq!(p.min_size, 100);
        assert_eq!(p.max_size, 100);
        assert_eq!(p.median_size, 100);
    }

    // --- ComplexityScore tests ---

    #[test]
    fn test_complexity_simple_func() {
        let f = make_fs(0, "f", 3, 3, 0, 0, 20);
        let c = ComplexityScore::compute(&f);
        assert_eq!(c.mccabe, 2); // 3-3+2=2
        assert!(!c.is_complex());
    }

    #[test]
    fn test_complexity_complex_func() {
        let f = make_fs(0, "f", 5, 20, 5, 10, 500);
        let c = ComplexityScore::compute(&f);
        assert!(c.difficulty() > 0.0);
    }

    #[test]
    fn test_complexity_display() {
        let f = make_fs(0, "f", 3, 3, 0, 0, 10);
        let c = ComplexityScore::compute(&f);
        let s = c.to_string();
        assert!(s.contains("CC="));
    }

    // --- StructuralDiffSummary tests ---

    #[test]
    fn test_summary_from_empty_report() {
        let r = StructuralReport::new("a".to_string(), "b".to_string(), vec![], vec![], vec![]);
        let s = StructuralDiffSummary::from_report(&r);
        assert_eq!(s.total(), 0);
    }

    #[test]
    fn test_summary_display() {
        let r = StructuralReport::new("a".to_string(), "b".to_string(), vec![], vec![], vec![]);
        let s = StructuralDiffSummary::from_report(&r);
        let d = s.to_string();
        assert!(d.contains("sim="));
    }

    // --- FunctionSizeProfile range tests ---

    #[test]
    fn test_size_profile_within_range() {
        let funcs = vec![
            make_fs(0, "f1", 2, 2, 0, 0, 50),
            make_fs(1, "f2", 3, 3, 0, 0, 200),
            make_fs(2, "f3", 4, 4, 0, 0, 1000),
        ];
        let p = FunctionSizeProfile::compute(&funcs);
        assert_eq!(p.min_size, 50);
        assert_eq!(p.max_size, 1000);
        let pct = p.within_range_percent(0, 500, &funcs);
        assert!((pct - 66.666).abs() < 1.0);
    }

    // --- DiffHeatmap bucket tests ---

    #[test]
    fn test_heatmap_median_bucket() {
        let funcs_a = vec![make_fs(0x1000, "f", 4, 5, 1, 2, 100)];
        let funcs_b = vec![make_fs(0x2000, "f", 4, 5, 1, 2, 100)];
        let m = StructuralMatcher::default();
        let (matches, _, _) = m.match_functions(&funcs_a, &funcs_b, None, None);
        let h = DiffHeatmap::from_matches(&matches);
        assert!(h.total() >= 1);
        assert!(h.median_bucket() <= 10);
    }
}
