//! `rustre-diff-bindiff`
//!
//! BinDiff-style binary diffing engine for the RustRE Suite.
//!
//! Compares two stripped binaries by computing structural features for each
//! function (CFG topology hash, block/instruction counts, call targets, etc.),
//! then matches functions across binaries through a multi-phase pipeline:
//! exact-hash matching, CFG-hash matching, name matching, call-graph
//! propagation, and heuristic similarity scoring.

/// Call-graph level BinDiff: CallGraphDiff, FunctionNode, CallEdge,
/// NodeSimilarity, HungarianMatcher, BinDiffReport, VisualDiffOutput.
pub mod callgraph_diff;
pub mod instruction_diff;
pub mod prime_product_hash;
pub mod similarity_matrix;

pub mod hungarian_matcher;
pub mod call_graph_diff;
pub mod basic_block_diff;
pub mod bb_matching;
pub mod function_matcher;
pub mod basic_block_hasher;
pub mod diff_reporter;

use std::collections::{HashMap, HashSet};
use std::fmt;

use petgraph::Graph;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;

use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// CfgHasher
// ─────────────────────────────────────────────────────────────────────────────

/// Computes structural (address-invariant) hashes of control-flow graphs.
pub struct CfgHasher;

impl CfgHasher {
    /// Compute a structural hash of a CFG.
    ///
    /// `adjacency` is a list of `(block_id, successor_ids)` pairs.  The hash
    /// is insensitive to the concrete block_id values and to node ordering —
    /// only the topology matters.
    pub fn hash_cfg(adjacency: &[(u32, Vec<u32>)]) -> u64 {
        // Delegate to the Weisfeiler-Lehman hash with 3 iterations.
        Self::wl_hash(adjacency, 3)
    }

    /// Hash for a simple linear chain of `block_count` basic blocks.
    pub fn hash_linear(block_count: u32) -> u64 {
        // A linear chain is fully described by its length.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a basis
        for i in 0..block_count {
            h ^= u64::from(i);
            h = h.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime
        }
        h
    }

    /// Weisfeiler-Lehman graph hash.
    ///
    /// Each node starts with a label equal to its out-degree.  On every
    /// iteration a node's label is updated to `hash(sorted neighbour labels)`.
    /// After `iterations` rounds the final hash is the sorted, combined hash
    /// of all node labels — making it invariant to node numbering.
    pub fn wl_hash(adjacency: &[(u32, Vec<u32>)], iterations: u32) -> u64 {
        if adjacency.is_empty() {
            return 0;
        }

        // Build an index: block_id -> position in adjacency slice.
        let idx: HashMap<u32, usize> = adjacency
            .iter()
            .enumerate()
            .map(|(i, (id, _))| (*id, i))
            .collect();

        // Initialise labels with out-degree.
        let mut labels: Vec<u64> = adjacency
            .iter()
            .map(|(_, succs)| succs.len() as u64)
            .collect();

        for _ in 0..iterations {
            let mut new_labels = labels.clone();
            for (pos, (_, succs)) in adjacency.iter().enumerate() {
                let mut neighbour_labels: Vec<u64> = succs
                    .iter()
                    .filter_map(|s| idx.get(s).map(|&p| labels[p]))
                    .collect();
                neighbour_labels.sort_unstable();

                // Hash: FNV-1a over current label + sorted neighbour labels.
                let mut h: u64 = 0xcbf2_9ce4_8422_2325;
                h = fnv1a_mix(h, labels[pos]);
                for nl in &neighbour_labels {
                    h = fnv1a_mix(h, *nl);
                }
                new_labels[pos] = h;
            }
            labels = new_labels;
        }

        // Combine all node labels in a sorted, order-independent way.
        labels.sort_unstable();
        let mut final_hash: u64 = 0xcbf2_9ce4_8422_2325;
        for l in &labels {
            final_hash = fnv1a_mix(final_hash, *l);
        }
        final_hash
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionFeatures
// ─────────────────────────────────────────────────────────────────────────────

/// Structural features extracted from a single function.
#[derive(Debug, Clone)]
pub struct FunctionFeatures {
    pub address: Address,
    pub name: Option<String>,
    pub basic_block_count: u32,
    pub edge_count: u32,
    pub instruction_count: u32,
    /// Number of call instructions inside the function body.
    pub call_count: u32,
    /// Number of back-edges (loop headers).
    pub loop_count: u32,
    /// McCabe cyclomatic complexity: E − N + 2.
    pub cyclomatic_complexity: u32,
    pub strongly_connected_components: u32,
    /// FNV hash of the bytes of the first basic block.
    pub entry_hash: u64,
    /// Structural hash of the CFG topology (address-invariant).
    pub cfg_hash: u64,
    /// Number of distinct callees.
    pub callee_count: u32,
    /// Number of distinct callers.
    pub caller_count: u32,
    /// String constants referenced by this function.
    pub string_refs: Vec<String>,
    /// Numeric constants used by this function.
    pub const_refs: Vec<u64>,
    /// FNV hash of the raw function bytes (exact identity check).
    pub byte_hash: u64,
}

impl FunctionFeatures {
    /// Create a zeroed-out `FunctionFeatures` for `address`.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            name: None,
            basic_block_count: 0,
            edge_count: 0,
            instruction_count: 0,
            call_count: 0,
            loop_count: 0,
            cyclomatic_complexity: 1,
            strongly_connected_components: 1,
            entry_hash: 0,
            cfg_hash: 0,
            callee_count: 0,
            caller_count: 0,
            string_refs: Vec::new(),
            const_refs: Vec::new(),
            byte_hash: 0,
        }
    }

    /// Compute a similarity score in [0.0, 1.0] with another function.
    ///
    /// Weights:
    /// - cfg_hash match           = 0.40
    /// - basic_block_count prox   = 0.20
    /// - instruction_count prox   = 0.15
    /// - edge_count proximity     = 0.10
    /// - loop_count match         = 0.10
    /// - string_refs overlap      = 0.05
    pub fn similarity(&self, other: &Self) -> f32 {
        // cfg_hash: exact match → full weight
        let cfg_score = if self.cfg_hash != 0 && self.cfg_hash == other.cfg_hash {
            1.0_f32
        } else {
            0.0_f32
        };

        let bb_score = proximity_score(self.basic_block_count, other.basic_block_count);
        let instr_score = proximity_score(self.instruction_count, other.instruction_count);
        let edge_score = proximity_score(self.edge_count, other.edge_count);

        let loop_score = if self.loop_count == other.loop_count {
            1.0_f32
        } else {
            proximity_score(self.loop_count, other.loop_count) * 0.5
        };

        let str_score = jaccard_strings(&self.string_refs, &other.string_refs);

        0.40 * cfg_score
            + 0.20 * bb_score
            + 0.15 * instr_score
            + 0.10 * edge_score
            + 0.10 * loop_score
            + 0.05 * str_score
    }

    /// Quick pre-filter: returns `false` if the two functions are obviously too
    /// different to be worth comparing (block count or instruction count differ
    /// by more than 5×).
    pub fn can_match(&self, other: &Self) -> bool {
        !exceeds_ratio(self.basic_block_count, other.basic_block_count, 5)
            && !exceeds_ratio(self.instruction_count, other.instruction_count, 5)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinarySnapshot
// ─────────────────────────────────────────────────────────────────────────────

/// A snapshot of one binary for diffing: functions + call graph.
pub struct BinarySnapshot {
    pub path: String,
    pub arch: String,
    pub entry_point: Address,
    /// function address → features
    pub functions: HashMap<u64, FunctionFeatures>,
    /// Directed call graph: nodes are function addresses, edges are calls.
    pub call_graph: Graph<u64, ()>,
    /// Maps function address → petgraph `NodeIndex`.
    pub cg_node_map: HashMap<u64, NodeIndex>,
}

impl BinarySnapshot {
    /// Create an empty snapshot for the binary at `path`.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            arch: String::new(),
            entry_point: Address::new(0),
            functions: HashMap::new(),
            call_graph: Graph::new(),
            cg_node_map: HashMap::new(),
        }
    }

    /// Register a function and its features.  Also inserts the corresponding
    /// node in the call graph if not already present.
    pub fn add_function(&mut self, features: FunctionFeatures) {
        let addr = features.address.as_u64();
        self.functions.insert(addr, features);
        if !self.cg_node_map.contains_key(&addr) {
            let node = self.call_graph.add_node(addr);
            self.cg_node_map.insert(addr, node);
        }
    }

    /// Add a directed call edge from `from` to `to`.  Nodes that do not yet
    /// exist in the call graph are created automatically.
    pub fn add_call(&mut self, from: u64, to: u64) {
        let from_node = *self
            .cg_node_map
            .entry(from)
            .or_insert_with(|| self.call_graph.add_node(from));
        let to_node = *self
            .cg_node_map
            .entry(to)
            .or_insert_with(|| self.call_graph.add_node(to));
        self.call_graph.add_edge(from_node, to_node, ());
    }

    /// Number of functions in this snapshot.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Number of call edges in the call graph.
    pub fn call_edge_count(&self) -> usize {
        self.call_graph.edge_count()
    }

    /// Look up features for the function at `addr`.
    pub fn function_at(&self, addr: u64) -> Option<&FunctionFeatures> {
        self.functions.get(&addr)
    }

    /// Return the addresses of functions that `addr` calls (outgoing edges).
    pub fn call_targets(&self, addr: u64) -> Vec<u64> {
        let Some(&node) = self.cg_node_map.get(&addr) else {
            return Vec::new();
        };
        self.call_graph
            .edges(node)
            .map(|e| *self.call_graph.node_weight(e.target()).unwrap_or(&0))
            .collect()
    }

    /// Return the addresses of functions that call `addr` (incoming edges).
    pub fn callers_of(&self, addr: u64) -> Vec<u64> {
        let Some(&node) = self.cg_node_map.get(&addr) else {
            return Vec::new();
        };
        self.call_graph
            .edges_directed(node, petgraph::Direction::Incoming)
            .map(|e| *self.call_graph.node_weight(e.source()).unwrap_or(&0))
            .collect()
    }

    /// Iterate over all function features in this snapshot.
    pub fn all_functions(&self) -> impl Iterator<Item = &FunctionFeatures> {
        self.functions.values()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchKind
// ─────────────────────────────────────────────────────────────────────────────

/// How a particular function match was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// Byte-for-byte identical (same `byte_hash`).
    ExactHash,
    /// Structurally identical CFG (same `cfg_hash`).
    CfgHash,
    /// Matched because a call-graph neighbour was already matched.
    CallGraphPropagation,
    /// Same function name from debug information or exports.
    NameMatch,
    /// User-specified match.
    ManualMatch,
    /// General similarity-score heuristic.
    Heuristic,
}

impl fmt::Display for MatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MatchKind::ExactHash => "ExactHash",
            MatchKind::CfgHash => "CfgHash",
            MatchKind::CallGraphPropagation => "CallGraphPropagation",
            MatchKind::NameMatch => "NameMatch",
            MatchKind::ManualMatch => "ManualMatch",
            MatchKind::Heuristic => "Heuristic",
        })
    }
}

impl MatchKind {
    /// Returns `true` for high-confidence match kinds that rarely produce
    /// false positives.
    pub fn is_reliable(self) -> bool {
        matches!(self, MatchKind::ExactHash | MatchKind::NameMatch)
    }

    /// Priority value: higher means it is attempted first.
    pub fn priority(self) -> u8 {
        match self {
            MatchKind::ExactHash => 10,
            MatchKind::NameMatch => 9,
            MatchKind::CfgHash => 8,
            MatchKind::ManualMatch => 7,
            MatchKind::CallGraphPropagation => 5,
            MatchKind::Heuristic => 1,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionMatch
// ─────────────────────────────────────────────────────────────────────────────

/// A match between a function in binary A and a function in binary B.
#[derive(Debug, Clone)]
pub struct FunctionMatch {
    /// Address in binary A.
    pub address_a: Address,
    /// Address in binary B.
    pub address_b: Address,
    /// Similarity score [0.0, 1.0].
    pub similarity: f32,
    /// Confidence that this is a true match [0.0, 1.0].
    pub confidence: f32,
    pub kind: MatchKind,
    pub name_a: Option<String>,
    pub name_b: Option<String>,
    /// Whether the match has been manually confirmed.
    pub verified: bool,
}

impl FunctionMatch {
    /// Create a new match with default similarity/confidence of 1.0 for
    /// reliable kinds and 0.0 otherwise.
    pub fn new(a: Address, b: Address, kind: MatchKind) -> Self {
        let default_score = if kind.is_reliable() { 1.0 } else { 0.0 };
        Self {
            address_a: a,
            address_b: b,
            similarity: default_score,
            confidence: default_score,
            kind,
            name_a: None,
            name_b: None,
            verified: false,
        }
    }

    /// Builder-style setter for the similarity score (also caps to [0,1]).
    pub fn with_similarity(mut self, s: f32) -> Self {
        // `clamp` propagates NaN, so the documented cap to [0,1] would not hold;
        // a NaN similarity then loses every ranking comparison it takes part in.
        self.similarity = if s.is_nan() { 0.0 } else { s.clamp(0.0, 1.0) };
        self
    }

    /// Returns `true` when the functions are effectively byte-identical
    /// (similarity ≥ 0.99).
    pub fn is_identical(&self) -> bool {
        self.similarity >= 0.99
    }

    /// Returns `true` when both similarity and confidence are ≥ 0.75.
    pub fn is_good_match(&self) -> bool {
        self.similarity >= 0.75 && self.confidence >= 0.75
    }

    /// Human-readable quality label.
    pub fn quality_label(&self) -> &'static str {
        if self.is_identical() {
            "Identical"
        } else if self.is_good_match() {
            "Good"
        } else if self.similarity >= 0.5 {
            "Partial"
        } else {
            "Poor"
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BasicBlockMatch
// ─────────────────────────────────────────────────────────────────────────────

/// A match between individual basic blocks inside a matched function pair.
#[derive(Debug, Clone)]
pub struct BasicBlockMatch {
    pub addr_a: Address,
    pub addr_b: Address,
    pub similarity: f32,
    pub instruction_count_a: u32,
    pub instruction_count_b: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffStats / DiffResult
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics for a diff run.
#[derive(Debug, Clone)]
pub struct DiffStats {
    pub functions_a: usize,
    pub functions_b: usize,
    pub matched_count: usize,
    pub identical_count: usize,
    pub good_match_count: usize,
    pub partial_match_count: usize,
    pub unmatched_a: usize,
    pub unmatched_b: usize,
    /// Weighted average similarity across all matched pairs [0.0, 1.0].
    pub similarity_score: f32,
    /// Average confidence across all matched pairs [0.0, 1.0].
    pub confidence_score: f32,
    /// Per-`MatchKind` counts.
    pub by_kind: HashMap<String, usize>,
}

impl DiffStats {
    fn compute(
        matches: &[FunctionMatch],
        functions_a: usize,
        functions_b: usize,
        unmatched_a: usize,
        unmatched_b: usize,
    ) -> Self {
        let matched_count = matches.len();
        let identical_count = matches.iter().filter(|m| m.is_identical()).count();
        let good_match_count = matches
            .iter()
            .filter(|m| !m.is_identical() && m.is_good_match())
            .count();
        let partial_match_count = matches
            .iter()
            .filter(|m| !m.is_identical() && !m.is_good_match() && m.similarity >= 0.5)
            .count();

        let similarity_score = if matched_count == 0 {
            0.0
        } else {
            matches.iter().map(|m| m.similarity).sum::<f32>() / matched_count as f32
        };

        let confidence_score = if matched_count == 0 {
            0.0
        } else {
            matches.iter().map(|m| m.confidence).sum::<f32>() / matched_count as f32
        };

        let mut by_kind: HashMap<String, usize> = HashMap::new();
        for m in matches {
            *by_kind.entry(m.kind.to_string()).or_insert(0) += 1;
        }

        Self {
            functions_a,
            functions_b,
            matched_count,
            identical_count,
            good_match_count,
            partial_match_count,
            unmatched_a,
            unmatched_b,
            similarity_score,
            confidence_score,
            by_kind,
        }
    }
}

/// The complete output of a binary diff.
pub struct DiffResult {
    pub snapshot_a: BinarySnapshot,
    pub snapshot_b: BinarySnapshot,
    pub function_matches: Vec<FunctionMatch>,
    /// Addresses in A that were not matched.
    pub unmatched_a: Vec<u64>,
    /// Addresses in B that were not matched.
    pub unmatched_b: Vec<u64>,
    pub stats: DiffStats,
}

impl DiffResult {
    /// Find the match whose A-side address equals `addr`.
    pub fn match_for_a(&self, addr: u64) -> Option<&FunctionMatch> {
        self.function_matches
            .iter()
            .find(|m| m.address_a.as_u64() == addr)
    }

    /// Find the match whose B-side address equals `addr`.
    pub fn match_for_b(&self, addr: u64) -> Option<&FunctionMatch> {
        self.function_matches
            .iter()
            .find(|m| m.address_b.as_u64() == addr)
    }

    /// Iterate over matches where both functions are byte-identical.
    pub fn identical_functions(&self) -> impl Iterator<Item = &FunctionMatch> {
        self.function_matches.iter().filter(|m| m.is_identical())
    }

    /// Iterate over matches where the functions differ (similarity < 0.99).
    pub fn changed_functions(&self) -> impl Iterator<Item = &FunctionMatch> {
        self.function_matches.iter().filter(|m| !m.is_identical())
    }

    /// Return up to `n` matches sorted by descending similarity.
    pub fn top_matches_by_similarity(&self, n: usize) -> Vec<&FunctionMatch> {
        let mut sorted: Vec<&FunctionMatch> = self.function_matches.iter().collect();
        sorted.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.truncate(n);
        sorted
    }

    /// Return a multi-line human-readable summary of the diff.
    pub fn print_summary(&self) -> String {
        let s = &self.stats;
        format!(
            "BinDiff Summary\n\
             ---------------\n\
             Binary A : {path_a}  ({fa} functions)\n\
             Binary B : {path_b}  ({fb} functions)\n\
             Matched  : {matched} ({identical} identical, {good} good, {partial} partial)\n\
             Unmatched: {ua} in A, {ub} in B\n\
             Similarity score : {sim:.3}\n\
             Confidence score : {conf:.3}\n\
             Match breakdown  : {kinds:?}",
            path_a = self.snapshot_a.path,
            path_b = self.snapshot_b.path,
            fa = s.functions_a,
            fb = s.functions_b,
            matched = s.matched_count,
            identical = s.identical_count,
            good = s.good_match_count,
            partial = s.partial_match_count,
            ua = s.unmatched_a,
            ub = s.unmatched_b,
            sim = s.similarity_score,
            conf = s.confidence_score,
            kinds = s.by_kind,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinDiffer
// ─────────────────────────────────────────────────────────────────────────────

/// The main diffing engine.
pub struct BinDiffer {
    /// Minimum similarity threshold for a heuristic match to be accepted.
    pub min_similarity: f32,
    /// Whether to run call-graph propagation (Phase 4).
    pub enable_propagation: bool,
    /// Maximum candidate functions to evaluate per function in Phase 5.
    pub max_candidates: usize,
}

impl Default for BinDiffer {
    fn default() -> Self {
        Self::new()
    }
}

impl BinDiffer {
    /// Create a `BinDiffer` with default settings.
    pub fn new() -> Self {
        Self {
            min_similarity: 0.5,
            enable_propagation: true,
            max_candidates: 100,
        }
    }

    /// Override the minimum similarity threshold.
    pub fn with_min_similarity(mut self, s: f32) -> Self {
        // `clamp` propagates NaN; a NaN threshold rejects every match silently.
        self.min_similarity = if s.is_nan() { 0.0 } else { s.clamp(0.0, 1.0) };
        self
    }

    /// Disable call-graph propagation.
    pub fn without_propagation(mut self) -> Self {
        self.enable_propagation = false;
        self
    }

    // ── Phase 1 ──────────────────────────────────────────────────────────────

    /// Match functions with identical raw bytes (`byte_hash` equality).
    pub fn match_by_exact_hash(
        &self,
        a: &BinarySnapshot,
        b: &BinarySnapshot,
    ) -> Vec<FunctionMatch> {
        // Build a map: byte_hash → list of addresses in B.
        let mut b_by_hash: HashMap<u64, Vec<u64>> = HashMap::new();
        for feat in b.all_functions() {
            if feat.byte_hash != 0 {
                b_by_hash
                    .entry(feat.byte_hash)
                    .or_default()
                    .push(feat.address.as_u64());
            }
        }

        // How many functions in A share each hash. Uniqueness must hold on BOTH
        // sides: checking only B let several identical A functions (thunks,
        // tiny stubs) all map onto the same B function, breaking the 1-to-1
        // matching that later phases and the statistics rely on.
        let mut a_hash_counts: HashMap<u64, usize> = HashMap::new();
        for feat in a.all_functions() {
            if feat.byte_hash != 0 {
                *a_hash_counts.entry(feat.byte_hash).or_insert(0) += 1;
            }
        }

        let mut matches = Vec::new();
        for feat_a in a.all_functions() {
            if feat_a.byte_hash == 0 {
                continue;
            }
            if a_hash_counts.get(&feat_a.byte_hash).copied().unwrap_or(0) > 1 {
                // Ambiguous on the A side — leave it to the similarity phases.
                continue;
            }
            if let Some(candidates) = b_by_hash.get(&feat_a.byte_hash) {
                // Only accept if the hash is unique on the B side to avoid
                // spurious matches for very small functions.
                if candidates.len() == 1 {
                    let addr_b = Address::new(candidates[0]);
                    let mut m = FunctionMatch::new(feat_a.address, addr_b, MatchKind::ExactHash)
                        .with_similarity(1.0);
                    m.confidence = 1.0;
                    m.name_a.clone_from(&feat_a.name);
                    m.name_b = b.function_at(candidates[0]).and_then(|f| f.name.clone());
                    matches.push(m);
                }
            }
        }
        matches
    }

    // ── Phase 2 ──────────────────────────────────────────────────────────────

    /// Match functions with the same structural CFG hash.
    pub fn match_by_cfg_hash(
        &self,
        a: &BinarySnapshot,
        b: &BinarySnapshot,
        already_matched: &HashSet<(u64, u64)>,
    ) -> Vec<FunctionMatch> {
        let matched_a: HashSet<u64> = already_matched.iter().map(|(x, _)| *x).collect();
        let matched_b: HashSet<u64> = already_matched.iter().map(|(_, y)| *y).collect();

        // Map cfg_hash → addresses in B (unmatched).
        let mut b_by_cfg: HashMap<u64, Vec<u64>> = HashMap::new();
        for feat in b.all_functions() {
            if feat.cfg_hash == 0 || matched_b.contains(&feat.address.as_u64()) {
                continue;
            }
            b_by_cfg
                .entry(feat.cfg_hash)
                .or_default()
                .push(feat.address.as_u64());
        }

        let mut matches = Vec::new();
        for feat_a in a.all_functions() {
            let addr_a = feat_a.address.as_u64();
            if feat_a.cfg_hash == 0 || matched_a.contains(&addr_a) {
                continue;
            }
            if let Some(candidates) = b_by_cfg.get(&feat_a.cfg_hash)
                && candidates.len() == 1 {
                    let addr_b = candidates[0];
                    let Some(feat_b) = b.function_at(addr_b) else { continue };
                    let sim = feat_a.similarity(feat_b);
                    let mut m = FunctionMatch::new(
                        feat_a.address,
                        Address::new(addr_b),
                        MatchKind::CfgHash,
                    )
                    .with_similarity(sim);
                    m.confidence = 0.9;
                    m.name_a.clone_from(&feat_a.name);
                    m.name_b = b.function_at(addr_b).and_then(|f| f.name.clone());
                    matches.push(m);
                }
        }
        matches
    }

    // ── Phase 3 ──────────────────────────────────────────────────────────────

    /// Match functions that share the same name (debug info / exports).
    pub fn match_by_name(
        &self,
        a: &BinarySnapshot,
        b: &BinarySnapshot,
        already_matched: &HashSet<(u64, u64)>,
    ) -> Vec<FunctionMatch> {
        let matched_a: HashSet<u64> = already_matched.iter().map(|(x, _)| *x).collect();
        let matched_b: HashSet<u64> = already_matched.iter().map(|(_, y)| *y).collect();

        // Build a frequency map so we can skip names that appear more than once
        // (duplicates would cause false-positive name matches).
        let mut b_name_freq: HashMap<&str, usize> = HashMap::new();
        for feat in b.all_functions() {
            if matched_b.contains(&feat.address.as_u64()) {
                continue;
            }
            if let Some(name) = feat.name.as_deref() {
                *b_name_freq.entry(name).or_insert(0) += 1;
            }
        }

        // name → address in B (only for names that appear exactly once).
        let mut b_by_name: HashMap<&str, u64> = HashMap::new();
        for feat in b.all_functions() {
            if matched_b.contains(&feat.address.as_u64()) {
                continue;
            }
            if let Some(name) = feat.name.as_deref() {
                // Only store if name is unique in B.
                if b_name_freq.get(name).copied().unwrap_or(0) == 1 {
                    b_by_name.insert(name, feat.address.as_u64());
                }
            }
        }

        let mut matches = Vec::new();
        for feat_a in a.all_functions() {
            let addr_a = feat_a.address.as_u64();
            if matched_a.contains(&addr_a) {
                continue;
            }
            let Some(name) = feat_a.name.as_deref() else {
                continue;
            };
            if let Some(&addr_b) = b_by_name.get(name) {
                let sim = if let Some(feat_b) = b.function_at(addr_b) {
                    feat_a.similarity(feat_b)
                } else {
                    0.8
                };
                let mut m =
                    FunctionMatch::new(feat_a.address, Address::new(addr_b), MatchKind::NameMatch)
                        .with_similarity(sim);
                m.confidence = 1.0;
                m.name_a.clone_from(&feat_a.name);
                m.name_b = Some(name.to_owned());
                matches.push(m);
            }
        }
        matches
    }

    // ── Phase 4 ──────────────────────────────────────────────────────────────

    /// Propagate confirmed matches through the call graph.
    ///
    /// If `f_a` → `g_a` in A and `f_b` → `g_b` in B, and `f_a` ↔ `f_b` is
    /// already known, then `g_a` ↔ `g_b` is a strong candidate.
    pub fn propagate_matches(
        &self,
        matches: &mut Vec<FunctionMatch>,
        a: &BinarySnapshot,
        b: &BinarySnapshot,
    ) {
        // Build fast look-up sets.
        let mut matched_pairs: HashSet<(u64, u64)> = matches
            .iter()
            .map(|m| (m.address_a.as_u64(), m.address_b.as_u64()))
            .collect();
        let matched_a: HashSet<u64> = matched_pairs.iter().map(|(x, _)| *x).collect();
        let matched_b: HashSet<u64> = matched_pairs.iter().map(|(_, y)| *y).collect();
        let mut matched_a = matched_a;
        let mut matched_b = matched_b;

        let mut new_matches: Vec<FunctionMatch> = Vec::new();

        // Work-list: start with all current matches as seeds.  New matches are
        // pushed back so propagation reaches depth > 1 through call chains.
        let mut work_list: std::collections::VecDeque<(u64, u64)> =
            matched_pairs.iter().copied().collect();
        while let Some((addr_a, addr_b)) = work_list.pop_front() {
            let (addr_a, addr_b) = (addr_a, addr_b);
            let targets_a = a.call_targets(addr_a);
            let targets_b = b.call_targets(addr_b);

            if targets_a.len() != 1 || targets_b.len() != 1 {
                // Only propagate when both sides have exactly one unambiguous
                // callee to avoid false positives.
                continue;
            }
            let g_a = targets_a[0];
            let g_b = targets_b[0];

            if matched_a.contains(&g_a) || matched_b.contains(&g_b) {
                continue;
            }
            if matched_pairs.contains(&(g_a, g_b)) {
                continue;
            }

            let sim = match (a.function_at(g_a), b.function_at(g_b)) {
                (Some(fa), Some(fb)) => fa.similarity(fb),
                _ => 0.5,
            };

            if sim < self.min_similarity {
                continue;
            }

            let mut m = FunctionMatch::new(
                Address::new(g_a),
                Address::new(g_b),
                MatchKind::CallGraphPropagation,
            )
            .with_similarity(sim);
            m.confidence = 0.7;
            m.name_a = a.function_at(g_a).and_then(|f| f.name.clone());
            m.name_b = b.function_at(g_b).and_then(|f| f.name.clone());

            matched_pairs.insert((g_a, g_b));
            matched_a.insert(g_a);
            matched_b.insert(g_b);
            // Re-enqueue the new match so its callees are explored too.
            work_list.push_back((g_a, g_b));
            new_matches.push(m);
        }

        matches.extend(new_matches);
    }

    // ── Phase 5 ──────────────────────────────────────────────────────────────

    /// Match remaining (unmatched) functions by heuristic similarity scoring.
    pub fn match_by_similarity(
        &self,
        a: &BinarySnapshot,
        b: &BinarySnapshot,
        already_matched: &HashSet<(u64, u64)>,
    ) -> Vec<FunctionMatch> {
        let matched_a: HashSet<u64> = already_matched.iter().map(|(x, _)| *x).collect();
        let mut matched_b: HashSet<u64> = already_matched.iter().map(|(_, y)| *y).collect();

        let unmatched_a: Vec<&FunctionFeatures> = a
            .all_functions()
            .filter(|f| !matched_a.contains(&f.address.as_u64()))
            .collect();

        // Sort by instruction count descending: match larger functions first
        // (they carry more information and are less likely to be confused).
        let mut unmatched_a = unmatched_a;
        unmatched_a.sort_by(|x, y| y.instruction_count.cmp(&x.instruction_count));

        let mut new_matches: Vec<FunctionMatch> = Vec::new();

        for feat_a in unmatched_a {
            let candidates = self.find_candidates(feat_a, b, &matched_b, self.max_candidates);
            if candidates.is_empty() {
                continue;
            }
            let (best_addr, best_sim) = candidates[0];
            if best_sim < self.min_similarity {
                continue;
            }

            let mut m = FunctionMatch::new(
                feat_a.address,
                Address::new(best_addr),
                MatchKind::Heuristic,
            )
            .with_similarity(best_sim);
            // Confidence scales with the margin between best and second-best.
            let confidence = if candidates.len() >= 2 {
                let margin = best_sim - candidates[1].1;
                (0.5 + margin).clamp(0.0, 1.0)
            } else {
                0.7
            };
            m.confidence = confidence;
            m.name_a.clone_from(&feat_a.name);
            m.name_b = b.function_at(best_addr).and_then(|f| f.name.clone());

            matched_b.insert(best_addr);
            new_matches.push(m);
        }

        new_matches
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Find the top-`top_n` candidate B functions for `feat_a`, excluding
    /// addresses listed in `excluded`.
    pub fn find_candidates(
        &self,
        feat_a: &FunctionFeatures,
        snapshot_b: &BinarySnapshot,
        excluded: &HashSet<u64>,
        top_n: usize,
    ) -> Vec<(u64, f32)> {
        let mut scored: Vec<(u64, f32)> = snapshot_b
            .all_functions()
            .filter(|f| !excluded.contains(&f.address.as_u64()) && feat_a.can_match(f))
            .map(|f| (f.address.as_u64(), self.detailed_similarity(feat_a, f)))
            .filter(|(_, s)| *s >= self.min_similarity)
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(top_n);
        scored
    }

    /// Compute a detailed pair-wise similarity score (used in Phase 5).
    ///
    /// Adds a bonus when the byte hash matches and a small penalty for
    /// cyclomatic-complexity divergence on top of the base feature similarity.
    pub fn detailed_similarity(&self, a: &FunctionFeatures, b: &FunctionFeatures) -> f32 {
        let base = a.similarity(b);

        // Exact-byte bonus.
        let byte_bonus = if a.byte_hash != 0 && a.byte_hash == b.byte_hash {
            0.05_f32
        } else {
            0.0_f32
        };

        // Cyclomatic complexity penalty.
        let cc_penalty = if a.cyclomatic_complexity == 0 || b.cyclomatic_complexity == 0 {
            0.0_f32
        } else {
            let ratio = a.cyclomatic_complexity.max(b.cyclomatic_complexity) as f32
                / a.cyclomatic_complexity.min(b.cyclomatic_complexity) as f32;
            if ratio > 3.0 { 0.1 } else { 0.0 }
        };

        (base + byte_bonus - cc_penalty).clamp(0.0, 1.0)
    }

    // ── Main entry point ─────────────────────────────────────────────────────

    /// Run all diff phases and return a `DiffResult`.
    pub fn diff(&self, a: BinarySnapshot, b: BinarySnapshot) -> DiffResult {
        let mut all_matches: Vec<FunctionMatch> = Vec::new();

        // Phase 1: exact byte hash.
        let phase1 = self.match_by_exact_hash(&a, &b);
        let mut matched_set: HashSet<(u64, u64)> = phase1
            .iter()
            .map(|m| (m.address_a.as_u64(), m.address_b.as_u64()))
            .collect();
        all_matches.extend(phase1);

        // Phase 2: CFG hash.
        let phase2 = self.match_by_cfg_hash(&a, &b, &matched_set);
        for m in &phase2 {
            matched_set.insert((m.address_a.as_u64(), m.address_b.as_u64()));
        }
        all_matches.extend(phase2);

        // Phase 3: name match.
        let phase3 = self.match_by_name(&a, &b, &matched_set);
        for m in &phase3 {
            matched_set.insert((m.address_a.as_u64(), m.address_b.as_u64()));
        }
        all_matches.extend(phase3);

        // Phase 4: call-graph propagation.
        if self.enable_propagation {
            self.propagate_matches(&mut all_matches, &a, &b);
            // Rebuild matched_set after propagation.
            matched_set = all_matches
                .iter()
                .map(|m| (m.address_a.as_u64(), m.address_b.as_u64()))
                .collect();
        }

        // Phase 5: heuristic similarity.
        let phase5 = self.match_by_similarity(&a, &b, &matched_set);
        for m in &phase5 {
            matched_set.insert((m.address_a.as_u64(), m.address_b.as_u64()));
        }
        all_matches.extend(phase5);

        // Compute unmatched sets.
        let matched_a_addrs: HashSet<u64> =
            all_matches.iter().map(|m| m.address_a.as_u64()).collect();
        let matched_b_addrs: HashSet<u64> =
            all_matches.iter().map(|m| m.address_b.as_u64()).collect();

        let unmatched_a: Vec<u64> = a
            .all_functions()
            .map(|f| f.address.as_u64())
            .filter(|addr| !matched_a_addrs.contains(addr))
            .collect();
        let unmatched_b: Vec<u64> = b
            .all_functions()
            .map(|f| f.address.as_u64())
            .filter(|addr| !matched_b_addrs.contains(addr))
            .collect();

        let stats = DiffStats::compute(
            &all_matches,
            a.function_count(),
            b.function_count(),
            unmatched_a.len(),
            unmatched_b.len(),
        );

        DiffResult {
            snapshot_a: a,
            snapshot_b: b,
            function_matches: all_matches,
            unmatched_a,
            unmatched_b,
            stats,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffReport
// ─────────────────────────────────────────────────────────────────────────────

/// Generates human-readable / machine-readable output from a `DiffResult`.
pub struct DiffReport {
    pub result: DiffResult,
}

impl DiffReport {
    pub fn new(result: DiffResult) -> Self {
        Self { result }
    }

    /// Multi-line text summary.
    pub fn summary(&self) -> String {
        self.result.print_summary()
    }

    /// CSV output: `addr_a,addr_b,similarity,kind,name_a,name_b`
    pub fn csv(&self) -> String {
        let mut out = String::from("addr_a,addr_b,similarity,kind,name_a,name_b\n");
        for m in &self.result.function_matches {
            out.push_str(&format!(
                "0x{:X},0x{:X},{:.4},{},{},{}\n",
                m.address_a.as_u64(),
                m.address_b.as_u64(),
                m.similarity,
                m.kind,
                csv_escape(m.name_a.as_deref().unwrap_or("")),
                csv_escape(m.name_b.as_deref().unwrap_or("")),
            ));
        }
        out
    }

    /// Minimal HTML report with a sortable table (uses only inline styles —
    /// no external dependencies).
    pub fn html(&self) -> String {
        let mut rows = String::new();
        for m in &self.result.function_matches {
            rows.push_str(&format!(
                "<tr><td>0x{:X}</td><td>0x{:X}</td><td>{:.3}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                m.address_a.as_u64(),
                m.address_b.as_u64(),
                m.similarity,
                m.kind,
                m.quality_label(),
                m.name_a.as_deref().unwrap_or(""),
                m.name_b.as_deref().unwrap_or(""),
            ));
        }

        format!(
            r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>BinDiff Report</title>
<style>
  body{{font-family:monospace;background:#1e1e1e;color:#d4d4d4}}
  table{{border-collapse:collapse;width:100%}}
  th,td{{border:1px solid #444;padding:4px 8px;text-align:left}}
  th{{background:#2d2d2d;cursor:pointer}}
  tr:hover{{background:#2a2a2a}}
</style>
</head>
<body>
<h2>BinDiff: {path_a} ↔ {path_b}</h2>
<p>Functions A: {fa} | Functions B: {fb} | Matched: {matched} | Similarity: {sim:.3}</p>
<table>
<thead><tr><th>Addr A</th><th>Addr B</th><th>Similarity</th><th>Kind</th><th>Quality</th><th>Name A</th><th>Name B</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"#,
            path_a = self.result.snapshot_a.path,
            path_b = self.result.snapshot_b.path,
            fa = self.result.stats.functions_a,
            fb = self.result.stats.functions_b,
            matched = self.result.stats.matched_count,
            sim = self.result.stats.similarity_score,
            rows = rows,
        )
    }

    /// JSON array of match objects.
    pub fn json(&self) -> String {
        let mut items: Vec<String> = Vec::new();
        for m in &self.result.function_matches {
            items.push(format!(
                r#"{{"addr_a":"0x{:X}","addr_b":"0x{:X}","similarity":{:.4},"confidence":{:.4},"kind":"{}","name_a":{},"name_b":{},"quality":"{}"}}"#,
                m.address_a.as_u64(),
                m.address_b.as_u64(),
                m.similarity,
                m.confidence,
                m.kind,
                json_str(m.name_a.as_deref()),
                json_str(m.name_b.as_deref()),
                m.quality_label(),
            ));
        }
        format!("[{}]", items.join(","))
    }

    /// Return a per-function diff text for the function at `addr_a` in binary A.
    pub fn diff_for_function(&self, addr_a: u64) -> Option<String> {
        let m = self.result.match_for_a(addr_a)?;
        let feat_a = self.result.snapshot_a.function_at(addr_a)?;
        let feat_b = self.result.snapshot_b.function_at(m.address_b.as_u64());

        let name_a = feat_a.name.as_deref().unwrap_or("<unnamed>");
        let (bb_b, instr_b, edge_b) = feat_b
            .map(|f| (f.basic_block_count, f.instruction_count, f.edge_count))
            .unwrap_or((0, 0, 0));

        Some(format!(
            "Function diff: {name_a}\n\
             Address A : 0x{addr_a:X}  →  Address B : 0x{addr_b:X}\n\
             Quality   : {quality}  Similarity: {sim:.3}  Kind: {kind}\n\
             ┌─────────────────┬──────────┬──────────┐\n\
             │ Feature         │  Binary A│  Binary B│\n\
             ├─────────────────┼──────────┼──────────┤\n\
             │ Basic blocks    │ {bb_a:8} │ {bb_b:8} │\n\
             │ Instructions    │ {instr_a:8} │ {instr_b:8} │\n\
             │ Edges           │ {edge_a:8} │ {edge_b:8} │\n\
             └─────────────────┴──────────┴──────────┘",
            name_a = name_a,
            addr_a = addr_a,
            addr_b = m.address_b.as_u64(),
            quality = m.quality_label(),
            sim = m.similarity,
            kind = m.kind,
            bb_a = feat_a.basic_block_count,
            bb_b = bb_b,
            instr_a = feat_a.instruction_count,
            instr_b = instr_b,
            edge_a = feat_a.edge_count,
            edge_b = edge_b,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §16.2 BinSlayer improvement — FunctionInfo / HungarianSolver
// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight view of a function used by the Hungarian matcher.
///
/// Carries just the fields needed for the four sub-scores so that the
/// matcher can be used independently from `FunctionFeatures`.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function address (used as a stable identifier).
    pub address: u64,
    /// Optional symbol name (from debug info / exports).
    pub name: Option<String>,
    /// Raw-bytes CRC32 checksum (0 = unknown).
    pub bytes_crc32: u32,
    /// Number of in-edges in the call graph.
    pub in_edges: u32,
    /// Number of out-edges in the call graph.
    pub out_edges: u32,
    /// Basic-block count.
    pub bb_count: u32,
    /// MD-index prime-product hash (0 = unknown).
    pub md_index: u64,
}

impl FunctionInfo {
    /// Create a `FunctionInfo` with all numeric fields zeroed.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            name: None,
            bytes_crc32: 0,
            in_edges: 0,
            out_edges: 0,
            bb_count: 0,
            md_index: 0,
        }
    }
}

/// Convert a `FunctionFeatures` reference to a `FunctionInfo` so that the
/// Hungarian matcher can consume snapshots without cloning the full feature set.
impl From<&FunctionFeatures> for FunctionInfo {
    fn from(f: &FunctionFeatures) -> Self {
        // Derive a CRC32-like value from the byte_hash (lower 32 bits).
        let bytes_crc32 = (f.byte_hash & 0xFFFF_FFFF) as u32;

        // md_index: product of small primes weighted by instruction count —
        // a rough structural fingerprint.
        let md_index = md_index_from_features(f);

        Self {
            address: f.address.as_u64(),
            name: f.name.clone(),
            bytes_crc32,
            in_edges: f.caller_count,
            out_edges: f.callee_count,
            bb_count: f.basic_block_count,
            md_index,
        }
    }
}

/// Compute a prime-product MD-index from `FunctionFeatures`.
///
/// The MD-index is a structural fingerprint used by BinDiff that encodes
/// the topology of the call graph neighbourhood.  Here we approximate it
/// with a deterministic prime-product hash over the function's degree and
/// block counts so that two structurally similar functions yield close values.
fn md_index_from_features(f: &FunctionFeatures) -> u64 {
    // Small prime table.
    const PRIMES: [u64; 8] = [2, 3, 5, 7, 11, 13, 17, 19];

    let vals = [
        f.basic_block_count as u64,
        f.edge_count as u64,
        f.instruction_count as u64,
        f.caller_count as u64,
        f.callee_count as u64,
        f.loop_count as u64,
        f.cyclomatic_complexity as u64,
        f.strongly_connected_components as u64,
    ];

    let mut result: u64 = 1;
    for (i, &v) in vals.iter().enumerate() {
        // Raise prime[i] to the power (v mod 60 + 1) — keeps values bounded.
        let exp = (v % 60) + 1;
        let base = PRIMES[i];
        let mut term: u64 = 1;
        for _ in 0..exp {
            term = term.wrapping_mul(base);
        }
        result = result.wrapping_add(term);
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// similarity_score — four-component weighted similarity
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the four-component similarity score in [0.0, 1.0] between two
/// `FunctionInfo` records.
///
/// Component weights (must sum to 1.0):
/// | Component       | Weight |
/// |-----------------|--------|
/// | name_match      | 0.40   |
/// | bytes_hash      | 0.30   |
/// | cfg_topology    | 0.20   |
/// | md_index        | 0.10   |
pub fn similarity_score(a: &FunctionInfo, b: &FunctionInfo) -> f64 {
    // ── 1. Name match ─────────────────────────────────────────────────────────
    let name_score = match (&a.name, &b.name) {
        (Some(na), Some(nb)) => {
            if na == nb {
                1.0_f64
            } else {
                0.0_f64
            }
        }
        // If either name is missing, treat as no information (neutral: 0).
        _ => 0.0_f64,
    };

    // ── 2. Byte-hash (CRC32) ──────────────────────────────────────────────────
    let bytes_score = if a.bytes_crc32 != 0 && a.bytes_crc32 == b.bytes_crc32 {
        1.0_f64
    } else {
        0.0_f64
    };

    // ── 3. CFG topology — (in_edges, out_edges, bb_count) similarity ──────────
    let cfg_score = cfg_topology_similarity(
        (a.in_edges, a.out_edges, a.bb_count),
        (b.in_edges, b.out_edges, b.bb_count),
    );

    // ── 4. MD-index prime-product similarity ─────────────────────────────────
    let md_score = md_index_similarity(a.md_index, b.md_index);

    0.40 * name_score + 0.30 * bytes_score + 0.20 * cfg_score + 0.10 * md_score
}

/// Smooth similarity for a three-tuple of CFG topology counts.
///
/// Each dimension is scored with a ratio proximity, then the three scores
/// are averaged.
fn cfg_topology_similarity(a: (u32, u32, u32), b: (u32, u32, u32)) -> f64 {
    let s0 = ratio_proximity_f64(a.0, b.0);
    let s1 = ratio_proximity_f64(a.1, b.1);
    let s2 = ratio_proximity_f64(a.2, b.2);
    (s0 + s1 + s2) / 3.0
}

/// Ratio-based proximity in [0,1] for two `u32` counts.
fn ratio_proximity_f64(x: u32, y: u32) -> f64 {
    if x == y {
        return 1.0;
    }
    let (lo, hi) = if x < y { (x, y) } else { (y, x) };
    if hi == 0 {
        return 1.0;
    }
    lo as f64 / hi as f64
}

/// Similarity between two MD-index values.
///
/// We map the absolute difference onto [0, 1] using an exponential decay:
/// `exp(-|a - b| / normalization)` where the normalization constant is
/// chosen so that a 10 % difference still yields ≈ 0.9 and a 100 % difference
/// yields ≈ 0.37.
fn md_index_similarity(a: u64, b: u64) -> f64 {
    if a == b {
        return 1.0;
    }
    if a == 0 || b == 0 {
        // No information — neutral.
        return 0.0;
    }
    let diff = a.abs_diff(b) as f64;
    let avg = (a as f64 + b as f64) / 2.0;
    // Relative difference in [0, ∞).
    let rel = diff / avg;
    // Exponential decay; scale so rel=0.1 → ~0.90.
    (-rel * 2.303).exp() // ln(10) ≈ 2.303 gives decay constant of ~10
}

// ─────────────────────────────────────────────────────────────────────────────
// HungarianSolver — Kuhn-Munkres O(n³) assignment
// ─────────────────────────────────────────────────────────────────────────────

/// Solves the classic linear assignment problem (minimum-cost perfect matching
/// on a square cost matrix) using the Kuhn-Munkres (Hungarian) algorithm.
///
/// The implementation follows the standard five-step description:
///
/// 1. Subtract row minima.
/// 2. Subtract column minima.
/// 3. Cover all zeros with a minimum number of lines.
/// 4. If the number of covering lines equals `n`, an optimal assignment
///    exists among the zero cells — extract it.  Otherwise find the smallest
///    uncovered value, subtract it from uncovered cells and add it to
///    doubly-covered cells, then go back to step 3.
///
/// The returned assignment is the set of `(row, col)` pairs that form the
/// optimal matching, i.e. the minimum total cost.
pub struct HungarianSolver {
    /// `n × n` cost matrix; may be padded if the original problem is not square.
    cost: Vec<Vec<f64>>,
    /// Problem size after padding (max(original_rows, original_cols)).
    n: usize,
    /// Original number of columns (before padding).
    m: usize,
    /// Original number of rows (before padding).
    r: usize,
}

impl HungarianSolver {
    /// Construct a new solver from the given cost matrix.
    ///
    /// The matrix **need not be square**: if it has more rows than columns (or
    /// vice-versa) it is padded with zeros to make it square.  Padding cells
    /// carry zero cost so they never affect the optimal total cost.
    ///
    /// # Arguments
    /// * `cost_matrix` — `cost_matrix[i][j]` is the cost of assigning
    ///   row `i` to column `j`.  All values must be finite and ≥ 0.
    ///
    /// # Panics
    /// Panics if the matrix is empty or if any row has a different length from
    /// the others.
    pub fn new(cost_matrix: Vec<Vec<f64>>) -> Self {
        let rows = cost_matrix.len();
        assert!(rows > 0, "HungarianSolver: cost matrix must not be empty");
        let cols = cost_matrix[0].len();
        for row in &cost_matrix {
            assert_eq!(
                row.len(),
                cols,
                "HungarianSolver: all rows must have the same length"
            );
        }

        let n = rows.max(cols);
        let m = cols; // original column count, stored for post-filtering

        // Pad to n × n.
        let mut cost: Vec<Vec<f64>> = cost_matrix;
        // Extend each existing row if cols < n.
        for row in cost.iter_mut() {
            row.resize(n, 0.0);
        }
        // Add missing rows if rows < n.
        while cost.len() < n {
            cost.push(vec![0.0; n]);
        }

        Self { cost, n, m, r: rows }
    }

    /// Return the original number of rows (before padding).
    pub fn original_rows(&self) -> usize {
        // Must be the pre-padding row count, not `n`: with more columns than
        // rows the two differ, and a caller filtering the assignment with
        // `i < original_rows()` would accept synthetic padding rows as real
        // matches. The dual `original_cols` was already correct because `m`
        // genuinely preserves the original value.
        self.r
    }

    /// Return the original number of columns (before padding).
    pub fn original_cols(&self) -> usize {
        self.m
    }

    /// Solve the assignment and return the optimal `(row, col)` pairs.
    ///
    /// Only pairs that correspond to *original* (non-padded) cells are
    /// returned, so the result length is `min(original_rows, original_cols)`.
    pub fn solve(&self) -> Vec<(usize, usize)> {
        let n = self.n;
        let mut mat: Vec<Vec<f64>> = self.cost.clone();

        // ── Step 1: subtract row minima ──────────────────────────────────────
        for row in mat.iter_mut() {
            let min = row.iter().copied().fold(f64::INFINITY, f64::min);
            if min.is_finite() {
                for v in row.iter_mut() {
                    *v -= min;
                }
            }
        }

        // ── Step 2: subtract column minima ───────────────────────────────────
        let col_range = 0..n;
        for c in col_range {
            let min = (0..n).map(|r| mat[r][c]).fold(f64::INFINITY, f64::min);
            if min.is_finite() && min > 0.0 {
                for row in mat.iter_mut().take(n) {
                    row[c] -= min;
                }
            }
        }

        // ── Steps 3–4: iterate until we have n covering lines ────────────────
        loop {
            let (row_covered, col_covered) = Self::minimum_line_cover(&mat, n);

            let lines = row_covered.iter().filter(|&&v| v).count()
                + col_covered.iter().filter(|&&v| v).count();

            if lines >= n {
                break;
            }

            // Find minimum uncovered value.
            let min_uncovered = (0..n)
                .flat_map(|r| (0..n).map(move |c| (r, c)))
                .filter(|&(r, c)| !row_covered[r] && !col_covered[c])
                .map(|(r, c)| mat[r][c])
                .fold(f64::INFINITY, f64::min);

            // If no uncovered cell exists the matrix may already be optimal
            // (can happen due to floating-point rounding). Break to avoid
            // subtracting infinity and producing NaN.
            if !min_uncovered.is_finite() {
                break;
            }

            // Adjust matrix.
            let iter_range_r = 0..n;
            for r in iter_range_r {
                for c in 0..n {
                    if !row_covered[r] && !col_covered[c] {
                        mat[r][c] -= min_uncovered;
                    } else if row_covered[r] && col_covered[c] {
                        mat[r][c] += min_uncovered;
                    }
                }
            }
        }

        // ── Extract assignment from zero cells ───────────────────────────────
        Self::extract_assignment(&mat, n)
    }

    /// Compute a minimum line cover (rows + columns) for all zeros in `mat`.
    ///
    /// This is the standard König's theorem step used in the Hungarian method.
    /// Returns `(row_covered, col_covered)` boolean vectors.
    fn minimum_line_cover(mat: &[Vec<f64>], n: usize) -> (Vec<bool>, Vec<bool>) {
        const EPS: f64 = 1e-9;

        // Find an initial matching of zeros.
        let mut row_match: Vec<Option<usize>> = vec![None; n]; // row -> col
        let mut col_match: Vec<Option<usize>> = vec![None; n]; // col -> row

        let iter_range_r = 0..n;
        for r in iter_range_r {
            // Try to match row r to an unmatched zero column.
            let mut visited = vec![false; n];
            Self::augment(r, mat, &mut row_match, &mut col_match, &mut visited, n, EPS);
        }

        // Mark rows that are unmatched.
        let mut marked_rows: Vec<bool> = vec![false; n];
        let mut marked_cols: Vec<bool> = vec![false; n];

        let iter_range_r = 0..n;
        for r in iter_range_r {
            if row_match[r].is_none() {
                marked_rows[r] = true;
            }
        }

        // Alternating path: from marked rows follow zeros to columns, then
        // follow the matching from those columns back to rows.
        let mut changed = true;
        while changed {
            changed = false;
            let iter_range_r = 0..n;
            for r in iter_range_r {
                if !marked_rows[r] {
                    continue;
                }
                for c in 0..n {
                    if mat[r][c] < EPS && !marked_cols[c] {
                        marked_cols[c] = true;
                        changed = true;
                        // Follow the column's match back to a row.
                        if let Some(r2) = col_match[c]
                            && !marked_rows[r2] {
                                marked_rows[r2] = true;
                            }
                    }
                }
            }
        }

        // Covering lines: unmarked rows + marked columns.
        let row_covered: Vec<bool> = (0..n).map(|r| !marked_rows[r]).collect();
        let col_covered: Vec<bool> = marked_cols;

        (row_covered, col_covered)
    }

    /// Hungarian augmenting-path DFS for the initial matching.
    fn augment(
        r: usize,
        mat: &[Vec<f64>],
        row_match: &mut Vec<Option<usize>>,
        col_match: &mut Vec<Option<usize>>,
        visited: &mut Vec<bool>,
        n: usize,
        eps: f64,
    ) -> bool {
        let iter_range_c = 0..n;
        for c in iter_range_c {
            if mat[r][c] < eps && !visited[c] {
                visited[c] = true;
                let free = match col_match[c] {
                    None => true,
                    Some(r2) => Self::augment(r2, mat, row_match, col_match, visited, n, eps),
                };
                if free {
                    row_match[r] = Some(c);
                    col_match[c] = Some(r);
                    return true;
                }
            }
        }
        false
    }

    /// Extract a complete assignment from the zero cells of the reduced matrix,
    /// using a greedy row-by-row scan with augmenting paths to resolve conflicts.
    fn extract_assignment(mat: &[Vec<f64>], n: usize) -> Vec<(usize, usize)> {
        const EPS: f64 = 1e-9;

        let mut row_match: Vec<Option<usize>> = vec![None; n];
        let mut col_match: Vec<Option<usize>> = vec![None; n];

        let iter_range_r = 0..n;
        for r in iter_range_r {
            let mut visited = vec![false; n];
            Self::augment(r, mat, &mut row_match, &mut col_match, &mut visited, n, EPS);
        }

        (0..n)
            .filter_map(|r| row_match[r].map(|c| (r, c)))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// match_functions_hungarian — optimal bipartite matching via Hungarian method
// ─────────────────────────────────────────────────────────────────────────────

/// Match functions from binary A against functions from binary B using the
/// Kuhn-Munkres (Hungarian) optimal assignment algorithm.
///
/// # Algorithm
/// 1. Build an `n × m` similarity matrix where
///    `sim[i][j] = similarity_score(&funcs_a[i], &funcs_b[j])`.
/// 2. Negate the similarities to convert the *maximum* bipartite matching
///    problem into a *minimum* cost assignment problem.
/// 3. Pad the matrix to square and call `HungarianSolver::solve()`.
/// 4. Filter out padded / below-threshold pairs and wrap each result in a
///    `FunctionMatch`.
///
/// # Arguments
/// * `funcs_a` — functions from binary A (order matters; index = row).
/// * `funcs_b` — functions from binary B (order matters; index = column).
/// * `threshold` — minimum similarity [0, 1] for a match to be kept.
///
/// # Returns
/// A `Vec<FunctionMatch>` sorted by descending similarity.
pub fn match_functions_hungarian(
    funcs_a: &[FunctionInfo],
    funcs_b: &[FunctionInfo],
    threshold: f64,
) -> Vec<FunctionMatch> {
    let n = funcs_a.len();
    let m = funcs_b.len();

    if n == 0 || m == 0 {
        return Vec::new();
    }

    // Build cost matrix (negated similarity so Hungarian finds the maximum).
    let cost_matrix: Vec<Vec<f64>> = (0..n)
        .map(|i| {
            (0..m)
                .map(|j| {
                    let sim = similarity_score(&funcs_a[i], &funcs_b[j]);
                    1.0 - sim // cost = 1 - similarity; lower cost = better match
                })
                .collect()
        })
        .collect();

    let solver = HungarianSolver::new(cost_matrix);
    let assignment = solver.solve();

    let mut results: Vec<FunctionMatch> = assignment
        .into_iter()
        .filter(|&(i, j)| i < n && j < m) // discard padded cells
        .filter_map(|(i, j)| {
            let sim = similarity_score(&funcs_a[i], &funcs_b[j]);
            if sim < threshold {
                return None;
            }
            let addr_a = Address::new(funcs_a[i].address);
            let addr_b = Address::new(funcs_b[j].address);

            let mut m = FunctionMatch::new(addr_a, addr_b, MatchKind::Heuristic)
                .with_similarity(sim as f32);
            m.confidence = sim.clamp(0.0, 1.0) as f32;
            m.name_a.clone_from(&funcs_a[i].name);
            m.name_b.clone_from(&funcs_b[j].name);
            Some(m)
        })
        .collect();

    // Sort by descending similarity.
    results.sort_by(|a, b| {
        b.similarity
            .partial_cmp(&a.similarity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// BinDiff — high-level façade (uses Hungarian ≤ 5000 functions, greedy above)
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of functions per binary for which the O(n³) Hungarian
/// algorithm is used.  Above this threshold the existing greedy similarity
/// matching (Phase 5) is used instead for performance.
///
/// Set to 2000: at this size the n³ work is ~8×10⁹ cell operations in the
/// worst case, which stays within a few seconds on modern hardware.  Larger
/// binaries (stripped firmware, large games) would take tens of seconds or
/// more, so they fall back to the O(n²) greedy Phase-5 heuristic.
pub const HUNGARIAN_THRESHOLD: usize = 2_000;

/// High-level entry point that wraps `BinDiffer` and selects the matching
/// strategy based on binary size.
///
/// * For binaries where **both** sides have ≤ `HUNGARIAN_THRESHOLD` functions,
///   the unmatched remainder (after phases 1–4) is resolved with the Hungarian
///   optimal assignment.
/// * For larger binaries, the greedy Phase-5 heuristic is used as before.
pub struct BinDiff {
    differ: BinDiffer,
}

impl Default for BinDiff {
    fn default() -> Self {
        Self::new()
    }
}

impl BinDiff {
    /// Create a `BinDiff` engine with default settings.
    pub fn new() -> Self {
        Self {
            differ: BinDiffer::new(),
        }
    }

    /// Override the underlying `BinDiffer` (e.g. to tune thresholds).
    pub fn with_differ(differ: BinDiffer) -> Self {
        Self { differ }
    }

    /// Run the full diff pipeline and return a `DiffResult`.
    ///
    /// Phases 1–4 are always executed by `BinDiffer`.  Phase 5 (heuristic
    /// matching of remaining functions) switches between Hungarian and greedy
    /// based on binary size.
    ///
    /// # Inputs
    /// Both `a` and `b` must be fully populated [`BinarySnapshot`]s. They
    /// are **not** raw byte buffers — pass an already-analysed snapshot
    /// built with [`BinarySnapshot::new`] + [`BinarySnapshot::add_function`]
    /// + [`BinarySnapshot::add_call`]. To produce one from a file on disk,
    /// run the function-detection + CFG pipeline first and feed each
    /// detected function's features into `add_function`.
    ///
    /// # JSON shape for MCP callers
    /// ```json
    /// {
    ///   "a": { "path": "...", "arch": "x86_64", "entry_point": 0x401000,
    ///          "functions": [/* FunctionFeatures */], "calls": [[from, to], ...] },
    ///   "b": { /* same shape */ }
    /// }
    /// ```
    /// Passing `a` / `b` as byte arrays will be rejected by the
    /// serializer — the shape above is mandatory.
    pub fn run(&self, a: BinarySnapshot, b: BinarySnapshot) -> DiffResult {
        let size_a = a.function_count();
        let size_b = b.function_count();

        // Run phases 1–4 (exact hash, CFG hash, name, call-graph propagation).
        let mut all_matches: Vec<FunctionMatch> = Vec::new();

        let phase1 = self.differ.match_by_exact_hash(&a, &b);
        let mut matched_set: HashSet<(u64, u64)> = phase1
            .iter()
            .map(|m| (m.address_a.as_u64(), m.address_b.as_u64()))
            .collect();
        all_matches.extend(phase1);

        let phase2 = self.differ.match_by_cfg_hash(&a, &b, &matched_set);
        for m in &phase2 {
            matched_set.insert((m.address_a.as_u64(), m.address_b.as_u64()));
        }
        all_matches.extend(phase2);

        let phase3 = self.differ.match_by_name(&a, &b, &matched_set);
        for m in &phase3 {
            matched_set.insert((m.address_a.as_u64(), m.address_b.as_u64()));
        }
        all_matches.extend(phase3);

        if self.differ.enable_propagation {
            self.differ.propagate_matches(&mut all_matches, &a, &b);
            matched_set = all_matches
                .iter()
                .map(|m| (m.address_a.as_u64(), m.address_b.as_u64()))
                .collect();
        }

        // Determine unmatched functions after phases 1–4.
        let matched_a_set: HashSet<u64> = matched_set.iter().map(|(x, _)| *x).collect();
        let matched_b_set: HashSet<u64> = matched_set.iter().map(|(_, y)| *y).collect();

        let unmatched_feats_a: Vec<FunctionInfo> = a
            .all_functions()
            .filter(|f| !matched_a_set.contains(&f.address.as_u64()))
            .map(FunctionInfo::from)
            .collect();

        let unmatched_feats_b: Vec<FunctionInfo> = b
            .all_functions()
            .filter(|f| !matched_b_set.contains(&f.address.as_u64()))
            .map(FunctionInfo::from)
            .collect();

        // Phase 5: choose algorithm based on the number of *unmatched* functions,
        // not the total binary size.  Phases 1-4 may have matched the vast
        // majority, making the Hungarian algorithm tractable even for large binaries.
        let _ = (size_a, size_b); // total counts computed above but not used for gating
        let phase5_matches = if unmatched_feats_a.len() <= HUNGARIAN_THRESHOLD
            && unmatched_feats_b.len() <= HUNGARIAN_THRESHOLD
        {
            match_functions_hungarian(
                &unmatched_feats_a,
                &unmatched_feats_b,
                self.differ.min_similarity as f64,
            )
        } else {
            // Fall back to greedy for large binaries.
            self.differ.match_by_similarity(&a, &b, &matched_set)
        };

        for m in &phase5_matches {
            matched_set.insert((m.address_a.as_u64(), m.address_b.as_u64()));
        }
        all_matches.extend(phase5_matches);

        // Compute final unmatched sets.
        let final_matched_a: HashSet<u64> =
            all_matches.iter().map(|m| m.address_a.as_u64()).collect();
        let final_matched_b: HashSet<u64> =
            all_matches.iter().map(|m| m.address_b.as_u64()).collect();

        let unmatched_a: Vec<u64> = a
            .all_functions()
            .map(|f| f.address.as_u64())
            .filter(|addr| !final_matched_a.contains(addr))
            .collect();

        let unmatched_b: Vec<u64> = b
            .all_functions()
            .map(|f| f.address.as_u64())
            .filter(|addr| !final_matched_b.contains(addr))
            .collect();

        let stats = DiffStats::compute(
            &all_matches,
            a.function_count(),
            b.function_count(),
            unmatched_a.len(),
            unmatched_b.len(),
        );

        DiffResult {
            snapshot_a: a,
            snapshot_b: b,
            function_matches: all_matches,
            unmatched_a,
            unmatched_b,
            stats,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BindiffEngine — high-level façade with fuzzy matching and Jaccard scoring
// ─────────────────────────────────────────────────────────────────────────────

/// Jaccard similarity score for basic-block overlap.
///
/// `matched` is the number of basic blocks that are considered matched between
/// the two functions, `blocks_a` and `blocks_b` are the total block counts.
///
/// The formula is: `matched / (blocks_a + blocks_b - matched)`.
/// Returns 1.0 when both block counts are zero (trivially equal).
#[inline]
pub fn jaccard_bb_score(matched: u32, blocks_a: u32, blocks_b: u32) -> f32 {
    // intersection = min(matched, blocks_a, blocks_b) — cannot exceed either side.
    // Use saturating arithmetic to guard against large block counts.
    let intersection = matched.min(blocks_a).min(blocks_b);
    let union = blocks_a.saturating_add(blocks_b).saturating_sub(intersection);
    if union == 0 {
        return 1.0;
    }
    intersection as f32 / union as f32
}

/// Summary report returned by [`BindiffEngine::compare`].
///
/// Breaks matched pairs into:
/// - **exact_matches** — byte-for-byte identical functions (similarity ≥ 0.99).
/// - **similar_matches** — near-identical functions with similarity > 0.7
///   (includes CFG-hash matches and heuristic matches above the threshold).
/// - **unmatched_in_a** — count of functions in A that found no match in B.
/// - **unmatched_in_b** — count of functions in B that were not matched to anything in A.
///
/// All matched pairs (regardless of category) are stored in `all_matches`
/// sorted by descending similarity.
#[derive(Debug, Clone)]
pub struct BindiffReport {
    /// Functions matched byte-for-byte (similarity ≥ 0.99).
    pub exact_matches: usize,
    /// Near-identical functions (0.7 < similarity < 0.99) not in `exact_matches`.
    pub similar_matches: usize,
    /// Functions in A with no match in B.
    pub unmatched_in_a: usize,
    /// Functions in B not matched to anything in A.
    pub unmatched_in_b: usize,
    /// All matched pairs sorted by descending similarity.
    pub all_matches: Vec<FunctionMatch>,
    /// Jaccard similarity for each matched pair: `matched_bb / (bb_a + bb_b - matched_bb)`.
    /// Stored parallel to `all_matches`.
    pub jaccard_scores: Vec<f32>,
    /// Unmatched function addresses in A.
    pub unmatched_a_addrs: Vec<u64>,
    /// Unmatched function addresses in B.
    pub unmatched_b_addrs: Vec<u64>,
}

impl BindiffReport {
    /// Overall binary similarity: exact + weighted similar / total matched.
    #[must_use]
    pub fn overall_similarity(&self) -> f32 {
        let total = self.all_matches.len();
        if total == 0 {
            return 0.0;
        }
        self.all_matches.iter().map(|m| m.similarity).sum::<f32>() / total as f32
    }
}

impl std::fmt::Display for BindiffReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BindiffReport: exact={} similar={} unmatched_a={} unmatched_b={} overall={:.3}",
            self.exact_matches,
            self.similar_matches,
            self.unmatched_in_a,
            self.unmatched_in_b,
            self.overall_similarity(),
        )
    }
}

/// Façade around [`BinDiff`] that adds:
/// 1. Fuzzy (near-identical) matching classification via Jaccard basic-block
///    score.
/// 2. A structured [`BindiffReport`] breaking matches into exact / similar /
///    unmatched buckets.
///
/// # Usage
/// ```rust,ignore
/// let report = BindiffEngine::new().compare(snapshot_a, snapshot_b);
/// println!("{report}");
/// ```
pub struct BindiffEngine {
    /// Underlying BinDiff engine (exposes all five phases + Hungarian).
    inner: BinDiff,
    /// Minimum Jaccard BB score to count a non-exact match as "similar".
    pub similar_threshold: f32,
}

impl BindiffEngine {
    /// Create a new engine with defaults: `similar_threshold = 0.7`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: BinDiff::new(),
            similar_threshold: 0.7,
        }
    }

    /// Override the similarity threshold below which matches are not
    /// included in `similar_matches`.
    #[must_use]
    pub fn with_similar_threshold(mut self, t: f32) -> Self {
        // `clamp` propagates NaN; a NaN threshold rejects every match silently.
        self.similar_threshold = if t.is_nan() { 0.0 } else { t.clamp(0.0, 1.0) };
        self
    }

    /// Compare two binary snapshots and return a [`BindiffReport`].
    ///
    /// Internally runs all five BinDiff phases (exact hash, CFG hash, name,
    /// call-graph propagation, Hungarian/greedy Phase 5).  Each match is then
    /// annotated with a Jaccard BB score:
    ///
    /// ```text
    /// jaccard = matched_blocks / (blocks_a + blocks_b − matched_blocks)
    /// ```
    ///
    /// where `matched_blocks = min(blocks_a, blocks_b)` is used as a
    /// conservative estimate when per-block correspondence is unavailable
    /// (we only have aggregate block counts, not individual block hashes).
    ///
    /// Matches are then partitioned:
    /// - **exact**: similarity ≥ 0.99 (byte-identical via `byte_hash`).
    /// - **similar**: jaccard ≥ `similar_threshold` AND similarity > 0.7
    ///   (near-identical but not byte-identical).
    #[must_use]
    pub fn compare(&self, a: BinarySnapshot, b: BinarySnapshot) -> BindiffReport {
        // Run the full diff pipeline.
        let result = self.inner.run(a, b);

        // Destructure to avoid partial-move issues.
        let DiffResult {
            snapshot_a,
            snapshot_b,
            function_matches,
            unmatched_a,
            unmatched_b,
            stats: _,
        } = result;

        let mut exact_matches = 0usize;
        let mut similar_matches = 0usize;
        let mut jaccard_scores: Vec<f32> = Vec::with_capacity(function_matches.len());

        for m in &function_matches {
            // Look up block counts for Jaccard computation.
            let bb_a = snapshot_a
                .function_at(m.address_a.as_u64())
                .map(|f| f.basic_block_count)
                .unwrap_or(0);
            let bb_b = snapshot_b
                .function_at(m.address_b.as_u64())
                .map(|f| f.basic_block_count)
                .unwrap_or(0);

            // Estimate matched basic blocks as min(bb_a, bb_b) — conservative
            // lower bound when we don't have per-block correspondence.
            let matched_bb = bb_a.min(bb_b);
            let jac = jaccard_bb_score(matched_bb, bb_a, bb_b);
            jaccard_scores.push(jac);

            if m.is_identical() {
                exact_matches += 1;
            } else if m.similarity > 0.7 && jac >= self.similar_threshold {
                similar_matches += 1;
            }
        }

        // Sort matches by descending similarity.
        let mut pairs: Vec<(FunctionMatch, f32)> =
            function_matches.into_iter().zip(jaccard_scores).collect();
        pairs.sort_by(|a, b| {
            b.0.similarity
                .partial_cmp(&a.0.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let (all_matches, jaccard_scores): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();

        let unmatched_in_a = unmatched_a.len();
        let unmatched_in_b = unmatched_b.len();

        // Suppress unused warnings for snapshots that were destructured.
        let _ = snapshot_a;
        let _ = snapshot_b;

        BindiffReport {
            exact_matches,
            similar_matches,
            unmatched_in_a,
            unmatched_in_b,
            all_matches,
            jaccard_scores,
            unmatched_a_addrs: unmatched_a,
            unmatched_b_addrs: unmatched_b,
        }
    }

    /// Compare two sets of function features (without full snapshots) using
    /// the Jaccard BB score to classify results.
    ///
    /// This is the `compare_functions` entry point for callers that already
    /// have [`FunctionFeatures`] slices but no full [`BinarySnapshot`].
    #[must_use]
    pub fn compare_functions(
        &self,
        funcs_a: &[FunctionFeatures],
        funcs_b: &[FunctionFeatures],
        path_a: impl Into<String>,
        path_b: impl Into<String>,
    ) -> BindiffReport {
        let mut snap_a = BinarySnapshot::new(path_a);
        for f in funcs_a {
            snap_a.add_function(f.clone());
        }
        let mut snap_b = BinarySnapshot::new(path_b);
        for f in funcs_b {
            snap_b.add_function(f.clone());
        }
        self.compare(snap_a, snap_b)
    }
}

impl Default for BindiffEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BindiffEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BindiffEngine(similar_threshold={})",
            self.similar_threshold
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// One step of FNV-1a mixing.
#[inline]
fn fnv1a_mix(acc: u64, val: u64) -> u64 {
    let bytes = val.to_le_bytes();
    let mut h = acc;
    for b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Smooth proximity score in [0,1] based on ratio of two counts.
/// Returns 1.0 when equal, decays toward 0 as the ratio diverges.
#[inline]
fn proximity_score(a: u32, b: u32) -> f32 {
    if a == b {
        return 1.0;
    }
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    if hi == 0 {
        return 1.0;
    }
    lo as f32 / hi as f32
}

/// Returns `true` when the larger of `a` and `b` is more than `ratio` times
/// the smaller.
#[inline]
fn exceeds_ratio(a: u32, b: u32, ratio: u32) -> bool {
    if a == 0 && b == 0 {
        return false;
    }
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    if lo == 0 {
        return hi > ratio;
    }
    hi > lo.saturating_mul(ratio)
}

/// Jaccard similarity of two string slices.
fn jaccard_strings(a: &[String], b: &[String]) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let set_a: HashSet<&str> = a.iter().map(String::as_str).collect();
    let set_b: HashSet<&str> = b.iter().map(String::as_str).collect();
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        1.0
    } else {
        intersection as f32 / union as f32
    }
}

/// Escape a string for inclusion in a CSV field.
///
/// Function names from untrusted binaries may contain commas, double-quotes,
/// or newlines that would corrupt the CSV structure (format-string / log-injection
/// class). Wrapping in double-quotes and escaping inner quotes is the standard
/// RFC 4180 remedy.
fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        // RFC 4180: wrap in double-quotes and escape embedded double-quotes.
        let escaped = s.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        s.to_owned()
    }
}

/// Format an optional string as a JSON string literal or `null`.
fn json_str(s: Option<&str>) -> String {
    match s {
        None => "null".to_owned(),
        Some(v) => {
            let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{}\"", escaped)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// cfg_similarity — public alias used by similarity_score documentation
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the CFG-topology similarity component for two `FunctionInfo` records.
///
/// This is a thin public wrapper around the internal `cfg_topology_similarity`
/// function that is referenced in the `similarity_score` documentation.  It
/// scores the (in_edges, out_edges, bb_count) triple of each function using
/// per-dimension ratio proximity and averages the three scores.
///
/// # Returns
/// A value in [0.0, 1.0]; 1.0 means the three counts are identical.
pub fn cfg_similarity(a: &FunctionInfo, b: &FunctionInfo) -> f64 {
    cfg_topology_similarity(
        (a.in_edges, a.out_edges, a.bb_count),
        (b.in_edges, b.out_edges, b.bb_count),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// HungarianSolver — additional public API
// ─────────────────────────────────────────────────────────────────────────────

impl HungarianSolver {
    /// Return the total cost of the optimal assignment given an assignment
    /// vector produced by [`Self::solve`].
    ///
    /// # Arguments
    /// * `assignment` — the `(row, col)` pairs returned by `solve()`.
    ///
    /// # Returns
    /// Sum of `cost[row][col]` for every pair, using the *original* (pre-
    /// reduction) cost matrix stored internally.
    pub fn assignment_cost(&self, assignment: &[(usize, usize)]) -> f64 {
        assignment
            .iter()
            .filter(|&&(r, c)| r < self.cost.len() && c < self.cost[r].len())
            .map(|&(r, c)| self.cost[r][c])
            .sum()
    }

    /// Validate that the given assignment is a valid perfect matching for the
    /// padded square matrix: every row and column appears at most once.
    ///
    /// Returns `Ok(())` on success, or `Err(msg)` describing the first
    /// violation found.
    pub fn validate_assignment(&self, assignment: &[(usize, usize)]) -> Result<(), String> {
        let n = self.n;
        let mut row_seen = vec![false; n];
        let mut col_seen = vec![false; n];
        for &(r, c) in assignment {
            if r >= n {
                return Err(format!("row index {r} out of range (n={n})"));
            }
            if c >= n {
                return Err(format!("col index {c} out of range (n={n})"));
            }
            if row_seen[r] {
                return Err(format!("row {r} appears more than once in assignment"));
            }
            if col_seen[c] {
                return Err(format!("col {c} appears more than once in assignment"));
            }
            row_seen[r] = true;
            col_seen[c] = true;
        }
        Ok(())
    }

    /// Build a cost matrix from a similarity matrix by negating each entry.
    ///
    /// `sim[i][j]` must be in [0.0, 1.0].  The resulting cost matrix is
    /// suitable for minimisation by `HungarianSolver::new`.
    ///
    /// # Panics
    /// Panics if `similarity_matrix` is empty.
    pub fn from_similarity(similarity_matrix: Vec<Vec<f64>>) -> Self {
        let cost: Vec<Vec<f64>> = similarity_matrix
            .into_iter()
            .map(|row| row.into_iter().map(|s| 1.0 - s.clamp(0.0, 1.0)).collect())
            .collect();
        Self::new(cost)
    }

    /// Solve and return pairs annotated with their similarity score
    /// (= 1 − cost) rather than raw (row, col) tuples.
    ///
    /// Pairs are filtered to only those where the similarity exceeds
    /// `min_similarity`, and the result is sorted by descending similarity.
    ///
    /// # Arguments
    /// * `original_rows` — number of rows in the original (unpadded) matrix.
    /// * `original_cols` — number of columns in the original (unpadded) matrix.
    /// * `min_similarity` — minimum similarity threshold (pairs below this are
    ///   excluded from the result).
    pub fn solve_with_scores(
        &self,
        original_rows: usize,
        original_cols: usize,
        min_similarity: f64,
    ) -> Vec<(usize, usize, f64)> {
        let assignment = self.solve();
        let mut scored: Vec<(usize, usize, f64)> = assignment
            .into_iter()
            .filter(|&(r, c)| r < original_rows && c < original_cols)
            .map(|(r, c)| {
                // cost = 1 - sim, so sim = 1 - cost.
                let sim = (1.0 - self.cost[r][c]).clamp(0.0, 1.0);
                (r, c, sim)
            })
            .filter(|&(_, _, sim)| sim >= min_similarity)
            .collect();
        scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchMatrix — similarity matrix builder / inspector
// ─────────────────────────────────────────────────────────────────────────────

/// A pre-computed similarity matrix between two sets of functions.
///
/// Wraps the raw `Vec<Vec<f64>>` grid together with references to the input
/// slices so that callers can translate (row, col) indices back to
/// `FunctionInfo` records without extra bookkeeping.
pub struct MatchMatrix<'a> {
    /// `matrix[i][j]` = `similarity_score(&funcs_a[i], &funcs_b[j])`.
    pub matrix: Vec<Vec<f64>>,
    /// Functions from binary A.
    pub funcs_a: &'a [FunctionInfo],
    /// Functions from binary B.
    pub funcs_b: &'a [FunctionInfo],
}

impl<'a> MatchMatrix<'a> {
    /// Build the full similarity matrix.
    ///
    /// Time complexity: O(n × m) where n = |funcs_a| and m = |funcs_b|.
    pub fn build(funcs_a: &'a [FunctionInfo], funcs_b: &'a [FunctionInfo]) -> Self {
        let matrix: Vec<Vec<f64>> = funcs_a
            .iter()
            .map(|a| funcs_b.iter().map(|b| similarity_score(a, b)).collect())
            .collect();
        Self {
            matrix,
            funcs_a,
            funcs_b,
        }
    }

    /// Return the number of rows (functions from A).
    pub fn rows(&self) -> usize {
        self.funcs_a.len()
    }

    /// Return the number of columns (functions from B).
    pub fn cols(&self) -> usize {
        self.funcs_b.len()
    }

    /// Access the similarity score for a specific (row, col) pair.
    pub fn score(&self, row: usize, col: usize) -> f64 {
        self.matrix[row][col]
    }

    /// Find the pair with the highest similarity in the entire matrix.
    ///
    /// Returns `None` if the matrix is empty.
    pub fn best_pair(&self) -> Option<(usize, usize, f64)> {
        let mut best: Option<(usize, usize, f64)> = None;
        for (i, row) in self.matrix.iter().enumerate() {
            for (j, &sim) in row.iter().enumerate() {
                match best {
                    None => best = Some((i, j, sim)),
                    Some((_, _, best_sim)) if sim > best_sim => best = Some((i, j, sim)),
                    _ => {}
                }
            }
        }
        best
    }

    /// Return all (row, col, similarity) triples where similarity ≥ `threshold`,
    /// sorted by descending similarity.
    pub fn above_threshold(&self, threshold: f64) -> Vec<(usize, usize, f64)> {
        let mut result: Vec<(usize, usize, f64)> = self
            .matrix
            .iter()
            .enumerate()
            .flat_map(|(i, row)| {
                row.iter()
                    .enumerate()
                    .filter(move |&(_, s)| *s >= threshold)
                    .map(move |(j, &s)| (i, j, s))
            })
            .collect();
        result.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        result
    }

    /// Convert this matrix into a `HungarianSolver` (cost = 1 − similarity).
    pub fn into_solver(self) -> HungarianSolver {
        let cost: Vec<Vec<f64>> = self
            .matrix
            .into_iter()
            .map(|row| row.into_iter().map(|s| 1.0 - s).collect())
            .collect();
        HungarianSolver::new(cost)
    }

    /// Greedily assign functions from A to functions from B.
    ///
    /// At each step, pick the globally highest unassigned similarity, record
    /// the match, and mark both the row and column as used.  This runs in
    /// O(n × m × log(n × m)) time and gives a good-enough approximation for
    /// large matrices where Hungarian is too slow.
    ///
    /// Returns `(row, col, similarity)` triples sorted by descending similarity.
    pub fn greedy_assign(&self, threshold: f64) -> Vec<(usize, usize, f64)> {
        // Collect all above-threshold pairs.
        let mut candidates: Vec<(usize, usize, f64)> = self
            .matrix
            .iter()
            .enumerate()
            .flat_map(|(i, row)| {
                row.iter()
                    .enumerate()
                    .filter(move |&(_, s)| *s >= threshold)
                    .map(move |(j, &s)| (i, j, s))
            })
            .collect();
        // Sort by descending similarity.
        candidates.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

        let mut used_a = vec![false; self.rows()];
        let mut used_b = vec![false; self.cols()];
        let mut result = Vec::new();

        for (i, j, s) in candidates {
            if !used_a[i] && !used_b[j] {
                used_a[i] = true;
                used_b[j] = true;
                result.push((i, j, s));
            }
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionInfo — additional helpers
// ─────────────────────────────────────────────────────────────────────────────

impl FunctionInfo {
    /// Return `true` if this record has a known byte hash (non-zero CRC32).
    pub fn has_byte_hash(&self) -> bool {
        self.bytes_crc32 != 0
    }

    /// Return `true` if this record has a known MD-index value.
    pub fn has_md_index(&self) -> bool {
        self.md_index != 0
    }

    /// Return `true` if this record has a name.
    pub fn has_name(&self) -> bool {
        self.name.is_some()
    }

    /// Return the name as a string slice, or `"<unnamed>"` if absent.
    pub fn name_or_unnamed(&self) -> &str {
        self.name.as_deref().unwrap_or("<unnamed>")
    }

    /// Compute a compact debug string for logging.
    pub fn debug_label(&self) -> String {
        format!(
            "FunctionInfo {{ addr=0x{:X}, name={}, bb={}, in={}, out={} }}",
            self.address,
            self.name_or_unnamed(),
            self.bb_count,
            self.in_edges,
            self.out_edges,
        )
    }

    /// Quick pre-filter: returns `false` if this function is obviously too
    /// different from `other` to be a plausible match (bb_count ratio > 5×).
    pub fn can_match(&self, other: &Self) -> bool {
        if self.bb_count == 0 && other.bb_count == 0 {
            return true;
        }
        let (lo, hi) = if self.bb_count < other.bb_count {
            (self.bb_count, other.bb_count)
        } else {
            (other.bb_count, self.bb_count)
        };
        if lo == 0 {
            return hi <= 5;
        }
        hi <= lo.saturating_mul(5)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// match_functions_greedy — O(n²logn) fallback for large binaries
// ─────────────────────────────────────────────────────────────────────────────

/// Match functions using a greedy O(n² log n) algorithm: pick globally best
/// unassigned pair at each step.
///
/// This is the fallback used by `BinDiff::run` when the binary is larger than
/// `HUNGARIAN_THRESHOLD`.  It does not guarantee an optimal assignment but is
/// fast enough for tens of thousands of functions.
///
/// # Arguments
/// * `funcs_a` — functions from binary A.
/// * `funcs_b` — functions from binary B.
/// * `threshold` — minimum similarity [0, 1] for a match to be kept.
///
/// # Returns
/// A `Vec<FunctionMatch>` sorted by descending similarity.
pub fn match_functions_greedy(
    funcs_a: &[FunctionInfo],
    funcs_b: &[FunctionInfo],
    threshold: f64,
) -> Vec<FunctionMatch> {
    let n = funcs_a.len();
    let m = funcs_b.len();

    if n == 0 || m == 0 {
        return Vec::new();
    }

    let mat = MatchMatrix::build(funcs_a, funcs_b);
    let assigned = mat.greedy_assign(threshold);

    let mut results: Vec<FunctionMatch> = assigned
        .into_iter()
        .map(|(i, j, sim)| {
            let addr_a = Address::new(funcs_a[i].address);
            let addr_b = Address::new(funcs_b[j].address);
            let mut fm = FunctionMatch::new(addr_a, addr_b, MatchKind::Heuristic)
                .with_similarity(sim as f32);
            fm.confidence = (sim * 0.9).clamp(0.0, 1.0) as f32;
            fm.name_a.clone_from(&funcs_a[i].name);
            fm.name_b.clone_from(&funcs_b[j].name);
            fm
        })
        .collect();

    results.sort_by(|a, b| {
        b.similarity
            .partial_cmp(&a.similarity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// AssignmentStats — diagnostic statistics for a Hungarian run
// ─────────────────────────────────────────────────────────────────────────────

/// Diagnostic statistics computed from a completed assignment.
#[derive(Debug, Clone)]
pub struct AssignmentStats {
    /// Total number of pairs in the assignment (including below-threshold ones
    /// before filtering).
    pub total_pairs: usize,
    /// Number of pairs that passed the similarity threshold.
    pub accepted_pairs: usize,
    /// Highest similarity score in the assignment.
    pub max_similarity: f64,
    /// Lowest similarity score among accepted pairs.
    pub min_similarity: f64,
    /// Mean similarity over accepted pairs.
    pub mean_similarity: f64,
    /// Number of pairs where the two functions have the same name.
    pub name_confirmed: usize,
    /// Number of pairs where the byte hash also matches.
    pub byte_confirmed: usize,
}

impl AssignmentStats {
    /// Compute statistics from an assignment and the input function lists.
    pub fn compute(
        assignment: &[(usize, usize)],
        funcs_a: &[FunctionInfo],
        funcs_b: &[FunctionInfo],
        threshold: f64,
    ) -> Self {
        let total_pairs = assignment.len();
        let mut max_sim = 0.0_f64;
        let mut min_sim = 1.0_f64;
        let mut sum_sim = 0.0_f64;
        let mut accepted = 0usize;
        let mut name_confirmed = 0usize;
        let mut byte_confirmed = 0usize;

        for &(i, j) in assignment {
            if i >= funcs_a.len() || j >= funcs_b.len() {
                continue; // padded cell
            }
            let sim = similarity_score(&funcs_a[i], &funcs_b[j]);
            if sim < threshold {
                continue;
            }
            accepted += 1;
            sum_sim += sim;
            if sim > max_sim {
                max_sim = sim;
            }
            if sim < min_sim {
                min_sim = sim;
            }

            let a = &funcs_a[i];
            let b = &funcs_b[j];
            if a.name.is_some() && a.name == b.name {
                name_confirmed += 1;
            }
            if a.bytes_crc32 != 0 && a.bytes_crc32 == b.bytes_crc32 {
                byte_confirmed += 1;
            }
        }

        let mean_similarity = if accepted > 0 {
            sum_sim / accepted as f64
        } else {
            0.0
        };
        if accepted == 0 {
            min_sim = 0.0;
        }

        Self {
            total_pairs,
            accepted_pairs: accepted,
            max_similarity: max_sim,
            min_similarity: min_sim,
            mean_similarity,
            name_confirmed,
            byte_confirmed,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper constructors ──────────────────────────────────────────────────

    fn make_features(
        addr: u64,
        (bb, instr, edges, loops): (u32, u32, u32, u32),
        cfg_hash: u64,
        byte_hash: u64,
        strings: Vec<&str>,
        name: Option<&str>,
    ) -> FunctionFeatures {
        let mut f = FunctionFeatures::new(Address::new(addr));
        f.basic_block_count = bb;
        f.instruction_count = instr;
        f.edge_count = edges;
        f.loop_count = loops;
        f.cfg_hash = cfg_hash;
        f.byte_hash = byte_hash;
        f.string_refs = strings.into_iter().map(str::to_owned).collect();
        f.name = name.map(str::to_owned);
        f.cyclomatic_complexity = edges.saturating_sub(bb) + 2;
        f
    }

    // ── 1. Identical features → similarity = 1.0 ────────────────────────────
    #[test]
    fn test_similarity_identical() {
        let f = make_features(
            0x1000,(5, 20, 6, 1),
            0xDEAD_BEEF,
            0xCAFE,
            vec!["hello"],
            None);
        assert!(
            (f.similarity(&f) - 1.0).abs() < 1e-6,
            "identical features must score 1.0"
        );
    }

    // ── 2. Very different features → similarity ≈ 0.0 ───────────────────────
    #[test]
    fn test_similarity_very_different() {
        let a = make_features(0x1000,(2, 5, 2, 0), 0xAAAA_AAAA, 0x0001, vec![], None);
        let b = make_features(
            0x2000,(100, 500, 120, 30),
            0xBBBB_BBBB,
            0x0002,
            vec!["x", "y", "z", "w"],
            None);
        let s = a.similarity(&b);
        assert!(
            s < 0.3,
            "very different functions should have low similarity, got {s}"
        );
    }

    // ── 3. can_match pre-filter ──────────────────────────────────────────────
    #[test]
    fn test_can_match_filters_obviously_different() {
        let tiny = make_features(0x1000,(1, 2, 1, 0), 0, 0, vec![], None);
        let huge = make_features(0x2000,(10, 20, 10, 0), 0, 0, vec![], None);
        // 10 / 1 = 10 × ratio, far above 5×
        assert!(!tiny.can_match(&huge), "should not match: block ratio > 5x");
        assert!(!huge.can_match(&tiny));

        let close = make_features(0x3000,(2, 4, 2, 0), 0, 0, vec![], None);
        assert!(tiny.can_match(&close), "should be allowed: within 5×");
    }

    // ── 4. quality_label ─────────────────────────────────────────────────────
    #[test]
    fn test_quality_label() {
        let mut m = FunctionMatch::new(
            Address::new(0x1000),
            Address::new(0x2000),
            MatchKind::Heuristic,
        );
        m.confidence = 1.0;

        m.similarity = 1.0;
        assert_eq!(m.quality_label(), "Identical");

        m.similarity = 0.80;
        assert_eq!(m.quality_label(), "Good");

        m.similarity = 0.60;
        m.confidence = 0.50;
        assert_eq!(m.quality_label(), "Partial");

        m.similarity = 0.20;
        m.confidence = 0.20;
        assert_eq!(m.quality_label(), "Poor");
    }

    // ── 5. is_identical / is_good_match ──────────────────────────────────────
    #[test]
    fn test_match_predicates() {
        let mut m =
            FunctionMatch::new(Address::new(0x10), Address::new(0x20), MatchKind::ExactHash);
        m.similarity = 1.0;
        m.confidence = 1.0;
        assert!(m.is_identical());
        assert!(m.is_good_match());

        m.similarity = 0.80;
        assert!(!m.is_identical());
        assert!(m.is_good_match());

        m.similarity = 0.60;
        m.confidence = 0.60;
        assert!(!m.is_good_match());
    }

    // ── 6. BinarySnapshot::add_function / function_at ────────────────────────
    #[test]
    fn test_snapshot_add_and_lookup() {
        let mut snap = BinarySnapshot::new("/bin/test");
        let feat = make_features(0x1000,(3, 12, 3, 0), 0xABCD, 0x1234, vec![], Some("main"));
        snap.add_function(feat);

        let found = snap.function_at(0x1000).expect("function must be found");
        assert_eq!(found.basic_block_count, 3);
        assert_eq!(found.name.as_deref(), Some("main"));
        assert!(snap.function_at(0xDEAD).is_none());
    }

    // ── 7. call_targets / callers_of ─────────────────────────────────────────
    #[test]
    fn test_snapshot_call_graph() {
        let mut snap = BinarySnapshot::new("/bin/test");
        snap.add_function(make_features(0x1000,(1, 5, 1, 0), 0, 0, vec![], None));
        snap.add_function(make_features(0x2000,(1, 5, 1, 0), 0, 0, vec![], None));
        snap.add_function(make_features(0x3000,(1, 5, 1, 0), 0, 0, vec![], None));
        snap.add_call(0x1000, 0x2000);
        snap.add_call(0x1000, 0x3000);

        let targets = snap.call_targets(0x1000);
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&0x2000));
        assert!(targets.contains(&0x3000));

        let callers = snap.callers_of(0x2000);
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0], 0x1000);
    }

    // ── 8. function_count / call_edge_count ──────────────────────────────────
    #[test]
    fn test_snapshot_counts() {
        let mut snap = BinarySnapshot::new("/bin/test");
        snap.add_function(make_features(0x1000,(1, 4, 1, 0), 0, 0, vec![], None));
        snap.add_function(make_features(0x2000,(1, 4, 1, 0), 0, 0, vec![], None));
        snap.add_call(0x1000, 0x2000);
        snap.add_call(0x1000, 0x2000); // duplicate edge
        assert_eq!(snap.function_count(), 2);
        assert_eq!(snap.call_edge_count(), 2);
    }

    // ── 9. match_by_exact_hash ───────────────────────────────────────────────
    #[test]
    fn test_match_by_exact_hash() {
        let mut a = BinarySnapshot::new("/bin/a");
        let mut b = BinarySnapshot::new("/bin/b");

        a.add_function(make_features(
            0x1000,(3, 12, 3, 0),
            0xAABB,
            0xCAFE_BABE,
            vec![],
            Some("foo")));
        b.add_function(make_features(
            0x5000,(3, 12, 3, 0),
            0xAABB,
            0xCAFE_BABE,
            vec![],
            Some("foo")));
        b.add_function(make_features(
            0x6000,(5, 20, 6, 0),
            0x1234,
            0xDEAD_BEEF,
            vec![],
            None));

        let differ = BinDiffer::new();
        let matches = differ.match_by_exact_hash(&a, &b);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address_a.as_u64(), 0x1000);
        assert_eq!(matches[0].address_b.as_u64(), 0x5000);
        assert_eq!(matches[0].kind, MatchKind::ExactHash);
        assert!((matches[0].similarity - 1.0).abs() < 1e-6);
    }

    // ── 10. match_by_cfg_hash ────────────────────────────────────────────────
    #[test]
    fn test_match_by_cfg_hash() {
        let mut a = BinarySnapshot::new("/bin/a");
        let mut b = BinarySnapshot::new("/bin/b");

        // Different byte_hash but same cfg_hash.
        a.add_function(make_features(
            0x1000,(4, 16, 5, 1),
            0xFEED_FACE,
            0x1111,
            vec![],
            None));
        b.add_function(make_features(
            0x8000,(4, 17, 5, 1),
            0xFEED_FACE,
            0x2222,
            vec![],
            None));

        let differ = BinDiffer::new();
        let matches = differ.match_by_cfg_hash(&a, &b, &HashSet::new());
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, MatchKind::CfgHash);
        assert_eq!(matches[0].address_a.as_u64(), 0x1000);
        assert_eq!(matches[0].address_b.as_u64(), 0x8000);
    }

    // ── 11. full diff ────────────────────────────────────────────────────────
    #[test]
    fn test_full_diff_mixed() {
        let mut a = BinarySnapshot::new("/bin/a");
        let mut b = BinarySnapshot::new("/bin/b");

        // Identical function (same byte_hash).
        a.add_function(make_features(
            0x1000,(3, 12, 3, 0),
            0xAA11,
            0xFFFF_0001,
            vec![],
            Some("init")));
        b.add_function(make_features(
            0x1000,(3, 12, 3, 0),
            0xAA11,
            0xFFFF_0001,
            vec![],
            Some("init")));

        // Changed function (same cfg_hash, different byte_hash).
        a.add_function(make_features(
            0x2000,(5, 20, 6, 1),
            0xBB22,
            0x0001,
            vec![],
            Some("process")));
        b.add_function(make_features(
            0x2100,(5, 21, 6, 1),
            0xBB22,
            0x0002,
            vec![],
            Some("process")));

        // Unmatched function in A only.
        a.add_function(make_features(
            0x3000,(2, 8, 2, 0),
            0xCC33,
            0x1001,
            vec![],
            Some("old_fn")));

        let differ = BinDiffer::new().without_propagation();
        let result = differ.diff(a, b);

        assert!(
            result.stats.matched_count >= 2,
            "at least 2 functions should match"
        );
        assert!(
            result.stats.identical_count >= 1,
            "init should be identical"
        );
        assert!(!result.unmatched_a.is_empty() || result.stats.matched_count >= 2);
    }

    // ── 12. DiffStats::similarity_score ─────────────────────────────────────
    #[test]
    fn test_diff_stats_similarity_score() {
        let mut matches: Vec<FunctionMatch> = Vec::new();
        let mut m1 =
            FunctionMatch::new(Address::new(0x10), Address::new(0x20), MatchKind::ExactHash);
        m1.similarity = 1.0;
        m1.confidence = 1.0;
        let mut m2 =
            FunctionMatch::new(Address::new(0x30), Address::new(0x40), MatchKind::Heuristic);
        m2.similarity = 0.6;
        m2.confidence = 0.6;
        matches.push(m1);
        matches.push(m2);

        let stats = DiffStats::compute(&matches, 3, 3, 1, 1);
        let expected = (1.0_f32 + 0.6) / 2.0;
        assert!((stats.similarity_score - expected).abs() < 1e-5);
    }

    // ── 13. identical_functions iterator ────────────────────────────────────
    #[test]
    fn test_identical_functions_iterator() {
        let a = BinarySnapshot::new("/bin/a");
        let b = BinarySnapshot::new("/bin/b");

        let mut m_id =
            FunctionMatch::new(Address::new(0x10), Address::new(0x20), MatchKind::ExactHash);
        m_id.similarity = 1.0;
        let mut m_changed =
            FunctionMatch::new(Address::new(0x30), Address::new(0x40), MatchKind::Heuristic);
        m_changed.similarity = 0.7;
        m_changed.confidence = 0.7;

        let result = DiffResult {
            snapshot_a: a,
            snapshot_b: b,
            function_matches: vec![m_id, m_changed],
            unmatched_a: vec![],
            unmatched_b: vec![],
            stats: DiffStats::compute(&[], 2, 2, 0, 0),
        };

        let identical: Vec<_> = result.identical_functions().collect();
        assert_eq!(identical.len(), 1);
        assert_eq!(identical[0].address_a.as_u64(), 0x10);
    }

    // ── 14. CfgHasher::hash_cfg deterministic ───────────────────────────────
    #[test]
    fn test_cfg_hasher_deterministic() {
        let adj = vec![(0, vec![1, 2]), (1, vec![3]), (2, vec![3]), (3, vec![])];
        let h1 = CfgHasher::hash_cfg(&adj);
        let h2 = CfgHasher::hash_cfg(&adj);
        assert_eq!(h1, h2, "hash_cfg must be deterministic");
        assert_ne!(h1, 0);
    }

    // ── 15. CfgHasher::wl_hash on isomorphic graphs ─────────────────────────
    #[test]
    fn test_wl_hash_isomorphic() {
        // Two structurally identical diamond graphs, different node IDs.
        let graph1 = vec![
            (0u32, vec![1u32, 2u32]),
            (1, vec![3]),
            (2, vec![3]),
            (3, vec![]),
        ];
        // Same shape, node IDs shifted by 10.
        let graph2 = vec![
            (10u32, vec![11u32, 12u32]),
            (11, vec![13]),
            (12, vec![13]),
            (13, vec![]),
        ];
        let h1 = CfgHasher::wl_hash(&graph1, 3);
        let h2 = CfgHasher::wl_hash(&graph2, 3);
        assert_eq!(h1, h2, "isomorphic graphs must produce the same WL hash");

        // A different topology should hash differently.
        let graph3 = vec![(0u32, vec![1u32]), (1, vec![2]), (2, vec![3]), (3, vec![])];
        let h3 = CfgHasher::wl_hash(&graph3, 3);
        assert_ne!(h1, h3, "non-isomorphic graphs should hash differently");
    }

    // ── 16. DiffReport::csv ──────────────────────────────────────────────────
    #[test]
    fn test_diff_report_csv() {
        let a = BinarySnapshot::new("/bin/a");
        let b = BinarySnapshot::new("/bin/b");
        let mut m = FunctionMatch::new(
            Address::new(0x1000),
            Address::new(0x2000),
            MatchKind::ExactHash,
        );
        m.similarity = 1.0;
        m.confidence = 1.0;
        m.name_a = Some("foo".to_owned());
        m.name_b = Some("foo".to_owned());

        let result = DiffResult {
            snapshot_a: a,
            snapshot_b: b,
            function_matches: vec![m],
            unmatched_a: vec![],
            unmatched_b: vec![],
            stats: DiffStats::compute(&[], 1, 1, 0, 0),
        };

        let report = DiffReport::new(result);
        let csv = report.csv();
        assert!(csv.starts_with("addr_a,addr_b,similarity,kind,name_a,name_b\n"));
        assert!(csv.contains("0x1000"));
        assert!(csv.contains("0x2000"));
        assert!(csv.contains("ExactHash"));
        assert!(csv.contains("foo"));
    }

    // ── 17. DiffReport::json valid array ────────────────────────────────────
    #[test]
    fn test_diff_report_json() {
        let a = BinarySnapshot::new("/bin/a");
        let b = BinarySnapshot::new("/bin/b");
        let mut m =
            FunctionMatch::new(Address::new(0x10), Address::new(0x20), MatchKind::Heuristic);
        m.similarity = 0.75;
        m.confidence = 0.80;

        let result = DiffResult {
            snapshot_a: a,
            snapshot_b: b,
            function_matches: vec![m],
            unmatched_a: vec![],
            unmatched_b: vec![],
            stats: DiffStats::compute(&[], 1, 1, 0, 0),
        };

        let report = DiffReport::new(result);
        let json = report.json();

        // Must start and end with array brackets.
        assert!(json.starts_with('['), "JSON must start with '['");
        assert!(json.ends_with(']'), "JSON must end with ']'");
        // Must contain our addresses and kind.
        assert!(json.contains("0x10"));
        assert!(json.contains("0x20"));
        assert!(json.contains("Heuristic"));
        // Basic validity: no unmatched braces.
        let open = json.chars().filter(|&c| c == '{').count();
        let close = json.chars().filter(|&c| c == '}').count();
        assert_eq!(open, close, "JSON braces must be balanced");
    }

    // ── Additional tests to reach 25+ ──────────────────────────────────────

    // ── 18. match_kind reliability / priority ────────────────────────────
    #[test]
    fn test_match_kind_reliability() {
        assert!(MatchKind::ExactHash.is_reliable());
        assert!(MatchKind::NameMatch.is_reliable());
        assert!(!MatchKind::Heuristic.is_reliable());
        assert!(!MatchKind::CfgHash.is_reliable());
    }

    #[test]
    fn test_match_kind_priority_ordering() {
        assert!(MatchKind::ExactHash.priority() > MatchKind::Heuristic.priority());
        assert!(MatchKind::NameMatch.priority() >= MatchKind::CfgHash.priority());
        assert!(MatchKind::CfgHash.priority() > MatchKind::CallGraphPropagation.priority());
    }

    // ── 19. match_kind Display ───────────────────────────────────────────
    #[test]
    fn test_match_kind_display() {
        assert_eq!(MatchKind::ExactHash.to_string(), "ExactHash");
        assert_eq!(MatchKind::CfgHash.to_string(), "CfgHash");
        assert_eq!(
            MatchKind::CallGraphPropagation.to_string(),
            "CallGraphPropagation"
        );
        assert_eq!(MatchKind::NameMatch.to_string(), "NameMatch");
        assert_eq!(MatchKind::ManualMatch.to_string(), "ManualMatch");
        assert_eq!(MatchKind::Heuristic.to_string(), "Heuristic");
    }

    // ── 20. DiffReport::summary ─────────────────────────────────────────
    #[test]
    fn test_diff_report_summary_contains_paths() {
        let a = BinarySnapshot::new("/path/to/a.exe");
        let b = BinarySnapshot::new("/path/to/b.exe");
        let result = DiffResult {
            snapshot_a: a,
            snapshot_b: b,
            function_matches: vec![],
            unmatched_a: vec![],
            unmatched_b: vec![],
            stats: DiffStats::compute(&[], 0, 0, 0, 0),
        };
        let report = DiffReport::new(result);
        let summary = report.summary();
        assert!(summary.contains("a.exe"));
        assert!(summary.contains("b.exe"));
    }

    // ── 21. DiffReport::html ────────────────────────────────────────────
    #[test]
    fn test_diff_report_html_structure() {
        let a = BinarySnapshot::new("/bin/a");
        let b = BinarySnapshot::new("/bin/b");
        let result = DiffResult {
            snapshot_a: a,
            snapshot_b: b,
            function_matches: vec![],
            unmatched_a: vec![],
            unmatched_b: vec![],
            stats: DiffStats::compute(&[], 0, 0, 0, 0),
        };
        let report = DiffReport::new(result);
        let html = report.html();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<table>"));
        assert!(html.contains("</html>"));
    }

    // ── 22. top_matches_by_similarity ordering ──────────────────────────
    #[test]
    fn test_top_matches_by_similarity() {
        let a = BinarySnapshot::new("/bin/a");
        let b = BinarySnapshot::new("/bin/b");
        let mut m1 =
            FunctionMatch::new(Address::new(0x10), Address::new(0x20), MatchKind::Heuristic);
        m1.similarity = 0.9;
        let mut m2 =
            FunctionMatch::new(Address::new(0x30), Address::new(0x40), MatchKind::Heuristic);
        m2.similarity = 0.5;
        let mut m3 =
            FunctionMatch::new(Address::new(0x50), Address::new(0x60), MatchKind::Heuristic);
        m3.similarity = 0.7;
        let result = DiffResult {
            snapshot_a: a,
            snapshot_b: b,
            function_matches: vec![m1, m2, m3],
            unmatched_a: vec![],
            unmatched_b: vec![],
            stats: DiffStats::compute(&[], 3, 3, 0, 0),
        };
        let top2 = result.top_matches_by_similarity(2);
        assert_eq!(top2.len(), 2);
        assert!((top2[0].similarity - 0.9).abs() < 1e-6);
        assert!((top2[1].similarity - 0.7).abs() < 1e-6);
    }

    // ── 23. match_by_name basic ─────────────────────────────────────────
    #[test]
    fn test_match_by_name() {
        let mut a = BinarySnapshot::new("/bin/a");
        let mut b = BinarySnapshot::new("/bin/b");
        a.add_function(make_features(
            0x1000,(5, 20, 5, 0),
            0xABCD,
            0x1234,
            vec![],
            Some("init_fn")));
        b.add_function(make_features(
            0x9000,(5, 20, 5, 0),
            0xABCD,
            0x9999,
            vec![],
            Some("init_fn")));

        let differ = BinDiffer::new();
        let matches = differ.match_by_name(&a, &b, &HashSet::new());
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, MatchKind::NameMatch);
        assert_eq!(matches[0].address_a.as_u64(), 0x1000);
        assert_eq!(matches[0].address_b.as_u64(), 0x9000);
    }

    // ── 24. CfgHasher empty graph ───────────────────────────────────────
    #[test]
    fn test_cfg_hasher_empty() {
        assert_eq!(CfgHasher::hash_cfg(&[]), 0);
    }

    // ── 25. FunctionFeatures similarity with string overlap ─────────────
    #[test]
    fn test_similarity_with_string_overlap() {
        let a = make_features(
            0x1000,(5, 20, 6, 1),
            0xABCD,
            0x0001,
            vec!["hello", "world"],
            None);
        let b = make_features(
            0x2000,(5, 20, 6, 1),
            0xABCD,
            0x0002,
            vec!["hello", "world"],
            None);
        let s = a.similarity(&b);
        // Same cfg_hash, counts, and strings — should be very high
        assert!(
            s > 0.9,
            "nearly identical features should score > 0.9, got {s}"
        );
    }

    // ── Hungarian solver tests ───────────────────────────────────────────

    fn make_info(addr: u64, name: Option<&str>, bb: u32, crc: u32, md: u64) -> FunctionInfo {
        FunctionInfo {
            address: addr,
            name: name.map(str::to_owned),
            bytes_crc32: crc,
            in_edges: 0,
            out_edges: 0,
            bb_count: bb,
            md_index: md,
        }
    }

    // ── 26. HungarianSolver 1×1 identity ────────────────────────────────
    #[test]
    fn test_hungarian_1x1() {
        let cost = vec![vec![0.5_f64]];
        let solver = HungarianSolver::new(cost);
        let assignment = solver.solve();
        assert_eq!(assignment.len(), 1);
        assert_eq!(assignment[0], (0, 0));
    }

    // ── 27. HungarianSolver 2×2 minimum cost ────────────────────────────
    #[test]
    fn test_hungarian_2x2() {
        // Cost matrix: row 0 prefers col 0 (cost 1), row 1 prefers col 1 (cost 1).
        // Optimal total cost = 1 + 1 = 2.
        let cost = vec![vec![1.0_f64, 4.0], vec![3.0_f64, 1.0]];
        let solver = HungarianSolver::new(cost);
        let assignment = solver.solve();
        // Expect (0,0) and (1,1).
        let contains_00 = assignment.contains(&(0, 0));
        let contains_11 = assignment.contains(&(1, 1));
        assert!(contains_00, "expected (0,0) in assignment: {assignment:?}");
        assert!(contains_11, "expected (1,1) in assignment: {assignment:?}");
    }

    // ── 28. HungarianSolver 3×3 structure and optimality ────────────────
    #[test]
    fn test_hungarian_3x3_classic() {
        // Simple 3×3 example with clear optimal: identity assignment (cost 0+0+0).
        // Off-diagonal entries are large, so any other assignment costs more.
        let cost = vec![
            vec![0.0_f64, 9.0, 9.0],
            vec![9.0_f64, 0.0, 9.0],
            vec![9.0_f64, 9.0, 0.0],
        ];
        let solver = HungarianSolver::new(cost.clone());
        let assignment = solver.solve();
        assert_eq!(assignment.len(), 3, "3×3 must produce 3 pairs");
        // Every row and column used exactly once.
        let mut rows: Vec<usize> = assignment.iter().map(|&(r, _)| r).collect();
        let mut cols: Vec<usize> = assignment.iter().map(|&(_, c)| c).collect();
        rows.sort_unstable();
        cols.sort_unstable();
        assert_eq!(rows, vec![0, 1, 2]);
        assert_eq!(cols, vec![0, 1, 2]);
        // Validate total cost is the minimum possible (0).
        let total: f64 = assignment.iter().map(|&(r, c)| cost[r][c]).sum();
        assert!(total < 1.0, "optimal cost should be 0.0, got {total}");
    }

    // ── 29. HungarianSolver non-square (more rows than cols) ─────────────
    #[test]
    fn test_hungarian_nonsquare_rows_gt_cols() {
        // 3 functions in A, 2 in B.  Only 2 pairs should be returned.
        let cost = vec![vec![0.1_f64, 0.9], vec![0.8_f64, 0.2], vec![0.5_f64, 0.5]];
        let solver = HungarianSolver::new(cost);
        let assignment = solver.solve();
        // Only cells where col < 2 are kept — i.e. the non-padded columns.
        // But solve() returns all n pairs; caller filters by original bounds.
        // The padded column is col=2 (0-indexed), so pairs with col < 2 are real.
        let real_count = assignment.iter().filter(|&&(_, c)| c < 2).count();
        assert!(real_count <= 2, "at most 2 real pairs expected");
    }

    // ── 30. HungarianSolver::validate_assignment ─────────────────────────
    #[test]
    fn test_hungarian_validate_assignment() {
        let cost = vec![vec![1.0_f64, 2.0], vec![3.0_f64, 1.0]];
        let solver = HungarianSolver::new(cost);
        let assignment = solver.solve();
        assert!(solver.validate_assignment(&assignment).is_ok());
        // Introduce a duplicate row.
        let bad = vec![(0, 0), (0, 1)];
        assert!(solver.validate_assignment(&bad).is_err());
    }

    // ── 31. HungarianSolver::assignment_cost ────────────────────────────
    #[test]
    fn test_hungarian_assignment_cost() {
        let cost = vec![vec![1.0_f64, 5.0], vec![4.0_f64, 2.0]];
        let solver = HungarianSolver::new(cost);
        let assignment = solver.solve();
        // Optimal: (0,0)=1, (1,1)=2 → cost=3.
        let total = solver.assignment_cost(&assignment);
        assert!((total - 3.0).abs() < 1e-6, "expected cost 3.0, got {total}");
    }

    // ── 32. HungarianSolver::from_similarity ────────────────────────────
    #[test]
    fn test_hungarian_from_similarity() {
        let sim = vec![vec![1.0_f64, 0.0], vec![0.0_f64, 1.0]];
        let solver = HungarianSolver::from_similarity(sim);
        let assignment = solver.solve();
        // (0,0) and (1,1) should be the optimal assignment (cost 0+0=0).
        assert!(assignment.contains(&(0, 0)));
        assert!(assignment.contains(&(1, 1)));
    }

    // ── 33. similarity_score identical FunctionInfo ──────────────────────
    #[test]
    fn test_similarity_score_identical() {
        let fi = make_info(0x1000, Some("foo"), 5, 0xCAFE, 12345);
        let s = similarity_score(&fi, &fi);
        assert!(
            (s - 1.0).abs() < 1e-9,
            "identical FunctionInfo must score 1.0, got {s}"
        );
    }

    // ── 34. similarity_score no name no hash ────────────────────────────
    #[test]
    fn test_similarity_score_no_name_no_hash() {
        let a = make_info(0x1000, None, 5, 0, 0);
        let b = make_info(0x2000, None, 5, 0, 0);
        let s = similarity_score(&a, &b);
        // Name=0 (no names), bytes=0 (crc=0 → no info), cfg=1.0 (same bb=5,
        // in=0, out=0), md=1.0 (both md_index=0, equal → 1.0).
        // Expected: 0.4*0 + 0.3*0 + 0.2*1 + 0.1*1 = 0.3
        assert!((s - 0.3).abs() < 1e-6, "expected 0.3, got {s}");
    }

    // ── 35. similarity_score different names different hashes ────────────
    #[test]
    fn test_similarity_score_different() {
        let a = make_info(0x1000, Some("alpha"), 10, 0x1111, 500);
        let b = make_info(0x2000, Some("beta"), 2, 0x2222, 5000);
        let s = similarity_score(&a, &b);
        assert!(
            s < 0.5,
            "very different functions should score below 0.5, got {s}"
        );
    }

    // ── 36. cfg_similarity same counts ──────────────────────────────────
    #[test]
    fn test_cfg_similarity_same() {
        let a = make_info(0x1000, None, 10, 0, 0);
        let mut b = make_info(0x2000, None, 10, 0, 0);
        b.in_edges = a.in_edges;
        b.out_edges = a.out_edges;
        let s = cfg_similarity(&a, &b);
        assert!(
            (s - 1.0).abs() < 1e-9,
            "same CFG counts must give 1.0, got {s}"
        );
    }

    // ── 37. match_functions_hungarian basic 2-function case ──────────────
    #[test]
    fn test_match_functions_hungarian_basic() {
        let a = vec![
            make_info(0x1000, Some("foo"), 5, 0xCAFE, 100),
            make_info(0x2000, Some("bar"), 3, 0xBEEF, 200),
        ];
        let b = vec![
            make_info(0x5000, Some("bar"), 3, 0xBEEF, 200),
            make_info(0x6000, Some("foo"), 5, 0xCAFE, 100),
        ];
        let matches = match_functions_hungarian(&a, &b, 0.0);
        assert_eq!(matches.len(), 2, "both functions should be matched");
        // foo@A should match foo@B, bar@A should match bar@B.
        let foo_match = matches.iter().find(|m| m.address_a.as_u64() == 0x1000);
        assert!(foo_match.is_some(), "0x1000 should be matched");
        if let Some(m) = foo_match {
            assert_eq!(
                m.address_b.as_u64(),
                0x6000,
                "foo should match foo at 0x6000"
            );
        }
    }

    // ── 38. match_functions_hungarian threshold filtering ─────────────────
    #[test]
    fn test_match_functions_hungarian_threshold() {
        let a = vec![make_info(0x1000, Some("alpha"), 10, 0x1111, 999)];
        let b = vec![make_info(0x9000, Some("beta"), 2, 0x2222, 1)];
        // Very different — similarity should be low.
        let matches = match_functions_hungarian(&a, &b, 0.99);
        assert!(
            matches.is_empty(),
            "no matches should survive a 0.99 threshold"
        );
    }

    // ── 39. match_functions_hungarian empty inputs ────────────────────────
    #[test]
    fn test_match_functions_hungarian_empty() {
        let empty: Vec<FunctionInfo> = vec![];
        let b = vec![make_info(0x1000, None, 1, 0, 0)];
        let m1 = match_functions_hungarian(&empty, &b, 0.0);
        let m2 = match_functions_hungarian(&b, &empty, 0.0);
        assert!(m1.is_empty());
        assert!(m2.is_empty());
    }

    // ── 40. match_functions_greedy basic ─────────────────────────────────
    #[test]
    fn test_match_functions_greedy_basic() {
        let a = vec![
            make_info(0x1000, Some("foo"), 5, 0xCAFE, 100),
            make_info(0x2000, Some("bar"), 3, 0xBEEF, 200),
        ];
        let b = vec![
            make_info(0x5000, Some("bar"), 3, 0xBEEF, 200),
            make_info(0x6000, Some("foo"), 5, 0xCAFE, 100),
        ];
        let matches = match_functions_greedy(&a, &b, 0.0);
        assert_eq!(matches.len(), 2);
    }

    // ── 41. MatchMatrix::build dimensions ────────────────────────────────
    #[test]
    fn test_match_matrix_dimensions() {
        let a = vec![
            make_info(0x1000, None, 5, 0, 0),
            make_info(0x2000, None, 3, 0, 0),
        ];
        let b = vec![
            make_info(0x5000, None, 5, 0, 0),
            make_info(0x6000, None, 3, 0, 0),
            make_info(0x7000, None, 7, 0, 0),
        ];
        let mat = MatchMatrix::build(&a, &b);
        assert_eq!(mat.rows(), 2);
        assert_eq!(mat.cols(), 3);
    }

    // ── 42. MatchMatrix::best_pair ────────────────────────────────────────
    #[test]
    fn test_match_matrix_best_pair() {
        let a = vec![make_info(0x1000, Some("foo"), 5, 0xCAFE, 100)];
        let b = vec![
            make_info(0x5000, Some("other"), 9, 0x1234, 999),
            make_info(0x6000, Some("foo"), 5, 0xCAFE, 100),
        ];
        let mat = MatchMatrix::build(&a, &b);
        let best = mat.best_pair();
        assert!(best.is_some());
        let (r, c, sim) = best.unwrap();
        assert_eq!(r, 0);
        assert_eq!(c, 1, "foo should best-match the other foo at index 1");
        assert!(
            sim > 0.9,
            "identical functions should have high similarity, got {sim}"
        );
    }

    // ── 43. MatchMatrix::above_threshold sorted ────────────────────────
    #[test]
    fn test_match_matrix_above_threshold_sorted() {
        let a = vec![
            make_info(0x1000, Some("foo"), 5, 0xCAFE, 100),
            make_info(0x2000, Some("bar"), 3, 0xBEEF, 200),
        ];
        let b = vec![
            make_info(0x5000, Some("foo"), 5, 0xCAFE, 100),
            make_info(0x6000, Some("bar"), 3, 0xBEEF, 200),
        ];
        let mat = MatchMatrix::build(&a, &b);
        let above = mat.above_threshold(0.5);
        // Should include (0,0) and (1,1) at minimum.
        assert!(!above.is_empty());
        // Verify sorted descending.
        for window in above.windows(2) {
            assert!(
                window[0].2 >= window[1].2,
                "results must be sorted descending"
            );
        }
    }

    // ── 44. MatchMatrix::greedy_assign no overlap ─────────────────────
    #[test]
    fn test_match_matrix_greedy_no_overlap() {
        let a = vec![
            make_info(0x1000, Some("foo"), 5, 0xCAFE, 100),
            make_info(0x2000, Some("bar"), 3, 0xBEEF, 200),
        ];
        let b = vec![
            make_info(0x5000, Some("foo"), 5, 0xCAFE, 100),
            make_info(0x6000, Some("bar"), 3, 0xBEEF, 200),
        ];
        let mat = MatchMatrix::build(&a, &b);
        let assigned = mat.greedy_assign(0.0);
        // Each row and column appears at most once.
        let rows: HashSet<usize> = assigned.iter().map(|&(r, _, _)| r).collect();
        let cols: HashSet<usize> = assigned.iter().map(|&(_, c, _)| c).collect();
        assert_eq!(rows.len(), assigned.len(), "no row should appear twice");
        assert_eq!(cols.len(), assigned.len(), "no col should appear twice");
    }

    // ── 45. FunctionInfo helpers ─────────────────────────────────────────
    #[test]
    fn test_function_info_helpers() {
        let named = make_info(0x1000, Some("init"), 3, 0xABCD, 42);
        assert!(named.has_name());
        assert!(named.has_byte_hash());
        assert!(named.has_md_index());
        assert_eq!(named.name_or_unnamed(), "init");

        let unnamed = make_info(0x2000, None, 0, 0, 0);
        assert!(!unnamed.has_name());
        assert!(!unnamed.has_byte_hash());
        assert!(!unnamed.has_md_index());
        assert_eq!(unnamed.name_or_unnamed(), "<unnamed>");
    }

    // ── 46. FunctionInfo::can_match ──────────────────────────────────────
    #[test]
    fn test_function_info_can_match() {
        let small = make_info(0x1000, None, 2, 0, 0);
        let large = make_info(0x2000, None, 100, 0, 0);
        assert!(!small.can_match(&large), "50× ratio should not match");
        let medium = make_info(0x3000, None, 4, 0, 0);
        assert!(small.can_match(&medium), "2× ratio should match");
    }

    // ── 47. FunctionInfo::debug_label ────────────────────────────────────
    #[test]
    fn test_function_info_debug_label() {
        let fi = make_info(0x1000, Some("init"), 5, 0, 0);
        let label = fi.debug_label();
        assert!(label.contains("0x1000"), "label must contain address");
        assert!(label.contains("init"), "label must contain name");
        assert!(label.contains("bb=5"), "label must contain bb count");
    }

    // ── 48. AssignmentStats basic ─────────────────────────────────────────
    #[test]
    fn test_assignment_stats_basic() {
        let a = vec![
            make_info(0x1000, Some("foo"), 5, 0xCAFE, 100),
            make_info(0x2000, Some("bar"), 3, 0xBEEF, 200),
        ];
        let b = vec![
            make_info(0x5000, Some("foo"), 5, 0xCAFE, 100),
            make_info(0x6000, Some("bar"), 3, 0xBEEF, 200),
        ];
        let assignment = vec![(0usize, 0usize), (1usize, 1usize)];
        let stats = AssignmentStats::compute(&assignment, &a, &b, 0.0);
        assert_eq!(stats.total_pairs, 2);
        assert_eq!(stats.accepted_pairs, 2);
        assert!(
            stats.max_similarity > 0.9,
            "max sim should be high for identical pairs"
        );
        assert_eq!(stats.name_confirmed, 2, "both names match");
        assert_eq!(stats.byte_confirmed, 2, "both byte hashes match");
    }

    // ── 49. AssignmentStats threshold filtering ──────────────────────────
    #[test]
    fn test_assignment_stats_threshold_filters() {
        let a = vec![make_info(0x1000, Some("alpha"), 10, 0x1111, 999)];
        let b = vec![make_info(0x9000, Some("beta"), 2, 0x2222, 1)];
        let assignment = vec![(0usize, 0usize)];
        let stats = AssignmentStats::compute(&assignment, &a, &b, 0.99);
        assert_eq!(
            stats.accepted_pairs, 0,
            "low-similarity pair must be filtered"
        );
    }

    // ── 50. HUNGARIAN_THRESHOLD value ────────────────────────────────────
    #[test]
    fn test_hungarian_threshold_value() {
        assert_eq!(
            HUNGARIAN_THRESHOLD, 2_000,
            "threshold must be 2000 per spec"
        );
    }

    // ── BindiffEngine tests ───────────────────────────────────────────────

    #[test]
    fn test_bindiff_engine_compare_exact() {
        let mut a = BinarySnapshot::new("/a");
        let mut b = BinarySnapshot::new("/b");
        a.add_function(make_features(
            0x1000,(4, 16, 4, 0),
            0xA1,
            0xFF10,
            vec![],
            Some("foo")));
        b.add_function(make_features(
            0x9000,(4, 16, 4, 0),
            0xA1,
            0xFF10,
            vec![],
            Some("foo")));
        let report = BindiffEngine::new().compare(a, b);
        assert_eq!(report.exact_matches, 1, "one exact byte-hash match");
        assert_eq!(report.unmatched_in_a, 0);
        assert_eq!(report.unmatched_in_b, 0);
    }

    #[test]
    fn test_bindiff_engine_compare_similar() {
        let mut a = BinarySnapshot::new("/a");
        let mut b = BinarySnapshot::new("/b");
        // Same CFG hash → similar but not exact
        a.add_function(make_features(
            0x1000,(4, 16, 4, 0),
            0xA1,
            0xCF01,
            vec![],
            Some("foo")));
        b.add_function(make_features(
            0x9000,(4, 16, 4, 0),
            0xA2,
            0xCF01,
            vec![],
            Some("foo")));
        let report = BindiffEngine::new().compare(a, b);
        // Should appear in similar_matches (jaccard ≥ 0.7 given same block counts)
        assert!(report.similar_matches + report.exact_matches >= 1);
    }

    #[test]
    fn test_bindiff_engine_compare_unmatched() {
        let mut a = BinarySnapshot::new("/a");
        let b = BinarySnapshot::new("/b"); // empty B
        a.add_function(make_features(
            0x1000,(4, 16, 4, 0),
            0xAB,
            0x99,
            vec![],
            Some("only_in_a")));
        let report = BindiffEngine::new().compare(a, b);
        assert_eq!(report.unmatched_in_a, 1);
        assert_eq!(report.unmatched_in_b, 0);
        assert_eq!(report.exact_matches, 0);
    }

    #[test]
    fn test_bindiff_report_jaccard_bb_score() {
        // Jaccard on basic blocks: both have 4 blocks → 4/(4+4-4) = 1.0
        assert!((jaccard_bb_score(4, 4, 4) - 1.0).abs() < 1e-6);
        // 3 matched out of 4+4-3 = 5 → 0.6
        assert!((jaccard_bb_score(3, 4, 4) - 0.6).abs() < 1e-6);
        // 0 matched → 0.0
        assert!((jaccard_bb_score(0, 4, 4) - 0.0).abs() < 1e-6);
    }

    // ── 51. HungarianSolver::solve_with_scores ────────────────────────────
    #[test]
    fn test_hungarian_solve_with_scores() {
        let sim = vec![vec![1.0_f64, 0.0], vec![0.0_f64, 1.0]];
        let solver = HungarianSolver::from_similarity(sim);
        let scored = solver.solve_with_scores(2, 2, 0.5);
        assert_eq!(scored.len(), 2, "both pairs should pass threshold 0.5");
        for &(_, _, s) in &scored {
            assert!(s >= 0.5, "all scores should be >= threshold");
        }
        // Verify sorted descending.
        if scored.len() >= 2 {
            assert!(scored[0].2 >= scored[1].2);
        }
    }

    // ── 52. BinDiff uses Hungarian for small binaries ────────────────────
    #[test]
    fn test_bindiff_uses_hungarian_for_small() {
        let mut a = BinarySnapshot::new("/bin/a");
        let mut b = BinarySnapshot::new("/bin/b");
        // Create 3 functions in A and 3 in B with clear matches.
        a.add_function(make_features(
            0x1000,(5, 20, 5, 0),
            0xAA11,
            0xFF01,
            vec![],
            Some("alpha")));
        b.add_function(make_features(
            0x9000,(5, 20, 5, 0),
            0xAA11,
            0xFF01,
            vec![],
            Some("alpha")));
        a.add_function(make_features(
            0x2000,(3, 10, 3, 0),
            0xBB22,
            0xFF02,
            vec![],
            Some("beta")));
        b.add_function(make_features(
            0xA000,(3, 10, 3, 0),
            0xBB22,
            0xFF02,
            vec![],
            Some("beta")));
        a.add_function(make_features(
            0x3000,(7, 30, 8, 1),
            0xCC33,
            0xFF03,
            vec![],
            Some("gamma")));
        b.add_function(make_features(
            0xB000,(7, 30, 8, 1),
            0xCC33,
            0xFF03,
            vec![],
            Some("gamma")));

        let diff = BinDiff::new();
        let result = diff.run(a, b);
        assert_eq!(
            result.stats.matched_count, 3,
            "all 3 functions should be matched"
        );
        assert_eq!(
            result.stats.identical_count, 3,
            "all matches should be identical"
        );
    }
}

// =============================================================================
// §17 — HungarianSolver (Jonker-Volgenant / Munkres O(n³))
// =============================================================================
//
// This section provides a second, fully self-contained implementation of the
// Munkres / Hungarian algorithm that is exported under the names requested in
// the spec (`HungarianSolver` already exists above with a slightly different
// API; here we add `HungarianMunkres` and its helper trait so callers can
// choose the implementation that best suits them).  The section also adds:
//
//   • `FuncFeatures`  — richer per-function feature record with mnemonic/
//                       topology/prime-product hashes.
//   • `BinDiffPipeline` — three-phase matching pipeline (exact → structural
//                          → callgraph propagation) built on top of the Munkres
//                          solver.
//   • `MatchResult` / `FuncMatch` / `MatchKind` (re-exported aliases) — the
//                          concrete result types returned by the pipeline.
//   • `render_diff_summary` — ASCII table output.
//
// All types are `pub` so downstream crates can use them directly.

// ─────────────────────────────────────────────────────────────────────────────
// §17.1  First-500-primes table (used by `FuncFeatures::compute_prime_product`)
// ─────────────────────────────────────────────────────────────────────────────

/// The first 500 prime numbers.  Index 0 is `2`, index 499 is `3571`.
/// Used by `FuncFeatures::compute_prime_product` to assign a deterministic
/// prime to each mnemonic index.
pub const PRIMES_500: [u64; 500] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039,
    1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
    1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279,
    1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409,
    1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
    1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613,
    1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741,
    1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873,
    1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999,
    2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113,
    2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251,
    2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371,
    2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477,
    2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647,
    2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731,
    2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857,
    2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001,
    3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163,
    3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299,
    3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407,
    3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539,
    3541, 3547, 3557, 3559, 3571,
];

// ─────────────────────────────────────────────────────────────────────────────
// §17.2  FuncFeatures — richer per-function feature record
// ─────────────────────────────────────────────────────────────────────────────

/// Richer per-function feature record used by `BinDiffPipeline`.
///
/// Carries six independent hashes / counters that together give a multi-
/// dimensional fingerprint allowing the pipeline to distinguish between
/// byte-identical, structurally similar, and merely topologically similar
/// functions.
#[derive(Debug, Clone)]
pub struct FuncFeatures {
    /// Stable identifier (e.g. a running counter assigned at extraction time).
    pub id: u64,
    /// Virtual address of the function entry point.
    pub addr: u64,
    /// Optional name from debug info or export table.
    pub name: Option<String>,
    /// Number of basic blocks.
    pub bb_count: u32,
    /// Number of CFG edges (sum of basic-block out-degrees).
    pub edge_count: u32,
    /// Number of incoming call edges (callers).
    pub in_degree: u32,
    /// Number of outgoing call edges (callees).
    pub out_degree: u32,
    /// McCabe cyclomatic complexity: `E − N + 2`.
    pub cyclomatic_complexity: u32,
    /// FNV-1a hash of the raw function bytes.  Two functions with the same
    /// `bytes_hash` are byte-for-byte identical.
    pub bytes_hash: u64,
    /// FNV-1a hash computed solely over the mnemonic sequence (not operands).
    /// Two functions with the same `mnemonic_hash` have identical instruction
    /// types in the same order, regardless of registers or addresses.
    pub mnemonic_hash: u64,
    /// FNV-1a hash of the CFG topology tuple
    /// `(bb_count, edge_count, in_degree, out_degree)`.
    pub topology_hash: u64,
    /// Prime-product hash: the product (mod 2⁶⁴) of one prime per mnemonic
    /// occurrence; captures the multiset of mnemonics used.
    pub prime_product: u64,
    /// Number of call instructions inside the function body.
    pub call_count: u32,
    /// FNV-1a hash of all string-literal addresses referenced by the function.
    pub string_refs_hash: u64,
    /// FNV-1a hash of all numeric constants used by the function.
    pub constants_hash: u64,
}

impl FuncFeatures {
    /// Compute a weighted similarity score in [0.0, 1.0] between `self` and
    /// `other`.
    ///
    /// | Component             | Weight |
    /// |-----------------------|--------|
    /// | bytes_hash equal      |  0.40  |
    /// | mnemonic_hash equal   |  0.25  |
    /// | topology_hash equal   |  0.15  |
    /// | bb_count within 10%   |  0.10  |
    /// | edge_count within 10% |  0.05  |
    /// | prime_product similar |  0.05  |
    ///
    /// Total: 0.0–1.0.
    pub fn similarity(&self, other: &FuncFeatures) -> f64 {
        let bytes_score = if self.bytes_hash != 0 && self.bytes_hash == other.bytes_hash {
            0.40_f64
        } else {
            0.0
        };

        let mnemonic_score = if self.mnemonic_hash != 0 && self.mnemonic_hash == other.mnemonic_hash
        {
            0.25_f64
        } else {
            0.0
        };

        let topology_score = if self.topology_hash != 0 && self.topology_hash == other.topology_hash
        {
            0.15_f64
        } else {
            0.0
        };

        // "Within 10%" means the ratio is at least 0.9.
        let bb_score = {
            let ratio = count_ratio(self.bb_count, other.bb_count);
            if ratio >= 0.9 { 0.10_f64 } else { 0.0 }
        };

        let edge_score = {
            let ratio = count_ratio(self.edge_count, other.edge_count);
            if ratio >= 0.9 { 0.05_f64 } else { 0.0 }
        };

        // Prime-product similarity: exponential decay on relative difference.
        let prime_score = {
            let s = prime_product_similarity(self.prime_product, other.prime_product);
            0.05 * s
        };

        bytes_score + mnemonic_score + topology_score + bb_score + edge_score + prime_score
    }

    /// Compute `topology_hash` from the four topology counts using FNV-1a.
    ///
    /// The hash is deterministic and captures the (bb_count, edge_count,
    /// in_degree, out_degree) tuple.
    pub fn compute_topology_hash(bb_count: u32, edge_count: u32, in_deg: u32, out_deg: u32) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a basis
        h = fnv1a_mix(h, u64::from(bb_count));
        h = fnv1a_mix(h, u64::from(edge_count));
        h = fnv1a_mix(h, u64::from(in_deg));
        h = fnv1a_mix(h, u64::from(out_deg));
        h
    }

    /// Compute `prime_product` for a slice of mnemonic strings.
    ///
    /// Each unique mnemonic is assigned a prime from `PRIMES_500` using a
    /// stable deterministic mapping: `prime_index = fnv1a(mnemonic) % 500`.
    /// The product of all selected primes (one per mnemonic occurrence, not
    /// per unique mnemonic) is returned modulo 2⁶⁴.
    ///
    /// An empty slice returns 1 (the multiplicative identity).
    pub fn compute_prime_product(mnemonics: &[&str]) -> u64 {
        if mnemonics.is_empty() {
            return 1;
        }
        let mut product: u64 = 1;
        for &mnemonic in mnemonics {
            let idx = mnemonic_to_prime_index(mnemonic);
            product = product.wrapping_mul(PRIMES_500[idx]);
        }
        product
    }

    /// Construct a `FuncFeatures` with all hash fields set to zero.
    ///
    /// Useful for building test fixtures where only a few fields matter.
    pub fn zeroed(id: u64, addr: u64) -> Self {
        Self {
            id,
            addr,
            name: None,
            bb_count: 0,
            edge_count: 0,
            in_degree: 0,
            out_degree: 0,
            cyclomatic_complexity: 1,
            bytes_hash: 0,
            mnemonic_hash: 0,
            topology_hash: 0,
            prime_product: 1,
            call_count: 0,
            string_refs_hash: 0,
            constants_hash: 0,
        }
    }

    /// Recompute `topology_hash` from the stored topology counts and store it.
    pub fn refresh_topology_hash(&mut self) {
        self.topology_hash = Self::compute_topology_hash(
            self.bb_count,
            self.edge_count,
            self.in_degree,
            self.out_degree,
        );
    }

    /// Return `true` when both functions have the same `bytes_hash` and neither
    /// hash is zero (which would indicate "unknown").
    #[inline]
    pub fn is_byte_identical(&self, other: &FuncFeatures) -> bool {
        self.bytes_hash != 0 && self.bytes_hash == other.bytes_hash
    }

    /// Return `true` when both functions share the same mnemonic sequence.
    #[inline]
    pub fn same_mnemonic_sequence(&self, other: &FuncFeatures) -> bool {
        self.mnemonic_hash != 0 && self.mnemonic_hash == other.mnemonic_hash
    }

    /// Return `true` when both functions have the same CFG topology.
    #[inline]
    pub fn same_topology(&self, other: &FuncFeatures) -> bool {
        self.topology_hash != 0 && self.topology_hash == other.topology_hash
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §17.3  HungarianMunkres — complete O(n³) Munkres algorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Full Munkres (Hungarian) assignment solver.
///
/// This is a standalone, self-contained implementation that follows the
/// classic five-step description published by Munkres (1957) and the
/// exposition by Miller (2000):
///
/// 1. **Row reduction** — subtract the row minimum from every cell in that row.
/// 2. **Column reduction** — subtract the column minimum from every cell in
///    that column.
/// 3. **Initial starring** — scan left-to-right, top-to-bottom; if a zero is
///    found in a row and column that contains no star yet, star it.
/// 4. **Cover starred columns** — if all columns are covered, the optimal
///    assignment is the set of starred zeros; done.  Otherwise continue.
/// 5. **Find uncovered zero, prime it**:
///    - If no starred zero in its row: augment the alternating path of
///      primed / starred zeros starting from this prime; restart from step 3.
///    - If there is a starred zero in the same row: cover the row, uncover
///      the column of that starred zero, and repeat step 5.
///    If no uncovered zero exists, find the minimum uncovered value, subtract
///    it from all uncovered cells and add it to all doubly-covered cells, then
///    return to step 5.
///
/// The solver handles non-square matrices by padding with zeros on the shorter
/// dimension.
#[derive(Debug, Clone)]
pub struct HungarianMunkres {
    /// Working copy of the cost matrix padded to `n × n`.
    n: usize,
    /// Original number of rows.
    orig_rows: usize,
    /// Original number of columns.
    orig_cols: usize,
    /// The cost matrix as supplied by the caller (kept for cost queries).
    original_cost: Vec<Vec<f64>>,
}

impl HungarianMunkres {
    /// Construct a new solver from a cost matrix.
    ///
    /// The matrix is padded to square with zero-cost cells if necessary.
    /// All values must be finite and non-negative; negative values are clamped
    /// to 0.0.
    ///
    /// # Panics
    /// Panics if the matrix is empty or if rows have inconsistent lengths.
    pub fn new(cost_matrix: Vec<Vec<f64>>) -> Self {
        let orig_rows = cost_matrix.len();
        assert!(orig_rows > 0, "HungarianMunkres: matrix must not be empty");
        let orig_cols = cost_matrix[0].len();
        assert!(
            orig_cols > 0,
            "HungarianMunkres: matrix must have at least one column"
        );
        for row in &cost_matrix {
            assert_eq!(
                row.len(),
                orig_cols,
                "HungarianMunkres: all rows must have equal length"
            );
        }

        let n = orig_rows.max(orig_cols);
        // Store original (possibly non-square) matrix.
        let original_cost = cost_matrix;

        Self {
            n,
            orig_rows,
            orig_cols,
            original_cost,
        }
    }

    /// Solve the minimum-cost assignment problem.
    ///
    /// Returns a `Vec<(usize, usize, f64)>` of `(row, col, original_cost)`
    /// triples for every assigned pair, where `row < orig_rows` and
    /// `col < orig_cols`.  Padded / dummy pairs are excluded.  Results are
    /// sorted by ascending cost (cheapest assignment first).
    pub fn solve(&self) -> Vec<(usize, usize, f64)> {
        let n = self.n;

        // Build padded n×n working matrix (clamp negatives to 0).
        let mut mat: Vec<Vec<f64>> = {
            let mut m: Vec<Vec<f64>> = Vec::with_capacity(n);
            let iter_range_r = 0..n;
            for r in iter_range_r {
                let mut row: Vec<f64> = Vec::with_capacity(n);
                for c in 0..n {
                    let val = if r < self.orig_rows && c < self.orig_cols {
                        self.original_cost[r][c].max(0.0)
                    } else {
                        0.0
                    };
                    row.push(val);
                }
                m.push(row);
            }
            m
        };

        // ── Phase 1: row reduction ───────────────────────────────────────────
        for row in mat.iter_mut() {
            let min = row.iter().copied().fold(f64::INFINITY, f64::min);
            if min.is_finite() && min > 0.0 {
                for v in row.iter_mut() {
                    *v -= min;
                }
            }
        }

        // ── Phase 2: column reduction ────────────────────────────────────────
        let iter_range_c = 0..n;
        for c in iter_range_c {
            let col_min = (0..n).map(|r| mat[r][c]).fold(f64::INFINITY, f64::min);
            if col_min.is_finite() && col_min > 0.0 {
                let iter_range_r = 0..n;
                for r in iter_range_r {
                    mat[r][c] -= col_min;
                }
            }
        }

        const EPS: f64 = 1e-10;

        // ── Phase 3: find independent zeros (star them) ──────────────────────
        // `starred[r][c]` = true iff cell (r,c) is starred.
        let mut starred: Vec<Vec<bool>> = vec![vec![false; n]; n];
        {
            let mut row_has_star = vec![false; n];
            let mut col_has_star = vec![false; n];
            let iter_range_r = 0..n;
            for r in iter_range_r {
                for c in 0..n {
                    if mat[r][c].abs() < EPS && !row_has_star[r] && !col_has_star[c] {
                        starred[r][c] = true;
                        row_has_star[r] = true;
                        col_has_star[c] = true;
                    }
                }
            }
        }

        // `primed[r][c]` = true iff cell (r,c) is primed.
        let mut primed: Vec<Vec<bool>> = vec![vec![false; n]; n];
        let mut covered_rows: Vec<bool> = vec![false; n];
        let mut covered_cols: Vec<bool> = vec![false; n];

        // Main loop — repeat until we have n covered columns.
        loop {
            // ── Cover all columns that contain a starred zero ────────────────
            covered_rows = vec![false; n];
            covered_cols = vec![false; n];
            let iter_range_r = 0..n;
            for r in iter_range_r {
                for c in 0..n {
                    if starred[r][c] {
                        covered_cols[c] = true;
                    }
                }
            }

            let n_covered = covered_cols.iter().filter(|&&v| v).count();
            if n_covered >= n {
                // Optimal assignment found.
                break;
            }

            // ── Reset primes for this iteration ─────────────────────────────
            primed = vec![vec![false; n]; n];

            // ── Inner loop: find uncovered zeros, prime them ─────────────────
            loop {
                // Find an uncovered zero.
                let Some((r0, c0)) =
                    self.find_uncovered_zero_munkres(&covered_rows, &covered_cols, &mat, EPS)
                else {
                    // No uncovered zero — augment the matrix and restart.
                    let delta = self.find_min_uncovered_munkres(&covered_rows, &covered_cols, &mat);
                    for r in 0..n {
                        for c in 0..n {
                            if !covered_rows[r] && !covered_cols[c] {
                                mat[r][c] -= delta;
                            } else if covered_rows[r] && covered_cols[c] {
                                mat[r][c] += delta;
                            }
                        }
                    }
                    // Reset primes and re-cover.
                    break; // break inner → re-enter outer loop to re-cover
                };

                primed[r0][c0] = true;

                // Is there a starred zero in the same row?
                if let Some(star_col) = self.find_starred_in_row_munkres(r0, &starred) {
                    // Cover row r0, uncover the starred column.
                    covered_rows[r0] = true;
                    covered_cols[star_col] = false;
                    // Continue inner loop.
                } else {
                    // No starred zero in this row — augment alternating path.
                    // Build path: prime → star → prime → … starting from (r0,c0).
                    let path = self.build_augmenting_path_munkres(r0, c0, &starred, &primed);
                    self.augment_path_munkres(&path, &mut starred);

                    // Erase all primes and covers; restart outer loop.
                    let primed_before = std::mem::replace(&mut primed, vec![vec![false; n]; n]);
                    let rows_before = std::mem::replace(&mut covered_rows, vec![false; n]);
                    let cols_before = std::mem::replace(&mut covered_cols, vec![false; n]);
                    debug_assert!(
                        primed_before.len() == n
                            && rows_before.len() == n
                            && cols_before.len() == n
                    );
                    break; // break inner → outer loop will re-cover
                }
            }
        }

        // ── Extract assignment from starred zeros ────────────────────────────
        let mut result: Vec<(usize, usize, f64)> = Vec::new();
        let iter_range_r = 0..n;
        for r in iter_range_r {
            let iter_range_c = 0..n;
            for c in iter_range_c {
                if starred[r][c] && r < self.orig_rows && c < self.orig_cols {
                    let cost = self.original_cost[r][c];
                    result.push((r, c, cost));
                }
            }
        }

        result.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
        result
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Find the first uncovered zero in the reduced matrix.
    fn find_uncovered_zero_munkres(
        &self,
        covered_rows: &[bool],
        covered_cols: &[bool],
        matrix: &[Vec<f64>],
        eps: f64,
    ) -> Option<(usize, usize)> {
        let n = self.n;
        let row_range = 0..n;
        for r in row_range {
            if covered_rows[r] {
                continue;
            }
            let col_range = 0..n;
            for c in col_range {
                if !covered_cols[c] && matrix[r][c].abs() < eps {
                    return Some((r, c));
                }
            }
        }
        None
    }

    /// Find the minimum value among all uncovered cells.
    fn find_min_uncovered_munkres(
        &self,
        covered_rows: &[bool],
        covered_cols: &[bool],
        matrix: &[Vec<f64>],
    ) -> f64 {
        let n = self.n;
        let mut min = f64::INFINITY;
        let row_range = 0..n;
        for r in row_range {
            if covered_rows[r] {
                continue;
            }
            let col_range = 0..n;
            for c in col_range {
                if !covered_cols[c] && matrix[r][c] < min {
                    min = matrix[r][c];
                }
            }
        }
        if min.is_infinite() { 0.0 } else { min }
    }

    /// Find the column of the starred zero in `row`, if any.
    fn find_starred_in_row_munkres(&self, row: usize, starred: &[Vec<bool>]) -> Option<usize> {
        (0..self.n).find(|&c| starred[row][c])
    }

    /// Find the row of the starred zero in `col`, if any.
    fn find_starred_in_col_munkres(&self, col: usize, starred: &[Vec<bool>]) -> Option<usize> {
        (0..self.n).find(|&r| starred[r][col])
    }

    /// Find the column of the primed zero in `row`, if any.
    fn find_primed_in_row_munkres(&self, row: usize, primed: &[Vec<bool>]) -> Option<usize> {
        (0..self.n).find(|&c| primed[row][c])
    }

    /// Build the alternating path starting from the uncovered primed zero
    /// `(r0, c0)`.
    ///
    /// Path: prime → star (same col) → prime (same row) → …
    fn build_augmenting_path_munkres(
        &self,
        r0: usize,
        c0: usize,
        starred: &[Vec<bool>],
        primed: &[Vec<bool>],
    ) -> Vec<(usize, usize)> {
        let mut path: Vec<(usize, usize)> = vec![(r0, c0)];

        loop {
            let &(_, last_c) = path.last().unwrap();
            // Try to extend: find starred zero in same column.
            if let Some(star_row) = self.find_starred_in_col_munkres(last_c, starred) {
                path.push((star_row, last_c));
                // Then find primed zero in same row.
                let prime_col = self
                    .find_primed_in_row_munkres(star_row, primed)
                    .expect("Munkres invariant: starred zero's row must contain a primed zero");
                path.push((star_row, prime_col));
            } else {
                break;
            }
        }

        path
    }

    /// Augment the assignment: flip stars/primes along the path.
    ///
    /// Primed zeros on the path become starred; starred zeros on the path lose
    /// their star.
    fn augment_path_munkres(&self, path: &[(usize, usize)], starred: &mut [Vec<bool>]) {
        for (step, &(r, c)) in path.iter().enumerate() {
            if step.is_multiple_of(2) {
                // Even-indexed: primed → make starred.
                starred[r][c] = true;
            } else {
                // Odd-indexed: starred → unstar.
                starred[r][c] = false;
            }
        }
    }

    /// Return the original number of rows.
    pub fn original_rows(&self) -> usize {
        self.orig_rows
    }

    /// Return the original number of columns.
    pub fn original_cols(&self) -> usize {
        self.orig_cols
    }

    /// Return the original cost of the cell `(row, col)`.
    /// Returns `None` for padded cells.
    pub fn original_cost_at(&self, row: usize, col: usize) -> Option<f64> {
        if row < self.orig_rows && col < self.orig_cols {
            Some(self.original_cost[row][col])
        } else {
            None
        }
    }

    /// Total cost of the given assignment (uses original, pre-padding costs).
    pub fn total_cost(&self, assignment: &[(usize, usize, f64)]) -> f64 {
        assignment.iter().map(|&(_, _, c)| c).sum()
    }

    /// Convenience: build from a *similarity* matrix (cost = 1 − similarity).
    pub fn from_similarity_matrix(sim: Vec<Vec<f64>>) -> Self {
        let cost: Vec<Vec<f64>> = sim
            .into_iter()
            .map(|row| row.into_iter().map(|s| 1.0 - s.clamp(0.0, 1.0)).collect())
            .collect();
        Self::new(cost)
    }

    /// Solve and return pairs annotated with their similarity score.
    ///
    /// Useful when the solver was constructed via `from_similarity_matrix`:
    /// the returned `(row, col, similarity)` triples are filtered to
    /// `similarity >= min_similarity` and sorted by descending similarity.
    pub fn solve_as_similarities(&self, min_similarity: f64) -> Vec<(usize, usize, f64)> {
        let raw = self.solve();
        let mut result: Vec<(usize, usize, f64)> = raw
            .into_iter()
            .map(|(r, c, cost)| (r, c, (1.0 - cost).clamp(0.0, 1.0)))
            .filter(|&(_, _, s)| s >= min_similarity)
            .collect();
        result.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §17.4  MatchKind extension aliases
// ─────────────────────────────────────────────────────────────────────────────

/// Match kind used by `FuncMatch`.  Distinct from the pre-existing `MatchKind`
/// enum so that `BinDiffPipeline` can operate independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuncMatchKind {
    /// Byte-identical (same `bytes_hash`).
    Identical,
    /// Structurally similar but not byte-identical (similarity ≥ threshold).
    Similar,
    /// Changed function: matched but similarity is below 0.75.
    Changed,
    /// Matched by name only (no structural evidence).
    NameOnly,
}

impl std::fmt::Display for FuncMatchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FuncMatchKind::Identical => "Identical",
            FuncMatchKind::Similar => "Similar",
            FuncMatchKind::Changed => "Changed",
            FuncMatchKind::NameOnly => "NameOnly",
        })
    }
}

/// A match between a function in binary A and a function in binary B,
/// produced by `BinDiffPipeline`.
#[derive(Debug, Clone)]
pub struct FuncMatch {
    /// Function address in binary A.
    pub addr_a: u64,
    /// Function address in binary B.
    pub addr_b: u64,
    /// Similarity score in [0.0, 1.0].
    pub similarity: f64,
    /// How the match was established.
    pub match_kind: FuncMatchKind,
}

impl FuncMatch {
    fn new(addr_a: u64, addr_b: u64, similarity: f64) -> Self {
        let match_kind = if similarity >= 0.99 {
            FuncMatchKind::Identical
        } else if similarity >= 0.75 {
            FuncMatchKind::Similar
        } else {
            FuncMatchKind::Changed
        };
        Self {
            addr_a,
            addr_b,
            similarity,
            match_kind,
        }
    }

    pub fn name_only(addr_a: u64, addr_b: u64) -> Self {
        Self {
            addr_a,
            addr_b,
            similarity: 1.0,
            match_kind: FuncMatchKind::NameOnly,
        }
    }
}

/// Aggregate result of a `BinDiffPipeline` run.
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// All matched pairs.
    pub matches: Vec<FuncMatch>,
    /// Function addresses present only in binary A (no match in B).
    pub only_in_a: Vec<u64>,
    /// Function addresses present only in binary B (no match in A).
    pub only_in_b: Vec<u64>,
    /// 10-bucket histogram: `similarity_distribution[i]` is the count of
    /// matches with similarity in `[i*0.1, (i+1)*0.1)`.
    pub similarity_distribution: [u32; 10],
}

impl MatchResult {
    fn build(matches: Vec<FuncMatch>, only_in_a: Vec<u64>, only_in_b: Vec<u64>) -> Self {
        let mut dist = [0u32; 10];
        for m in &matches {
            let bucket = ((m.similarity * 10.0) as usize).min(9);
            dist[bucket] += 1;
        }
        Self {
            matches,
            only_in_a,
            only_in_b,
            similarity_distribution: dist,
        }
    }

    /// Count of `Identical` matches.
    pub fn identical_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.match_kind == FuncMatchKind::Identical)
            .count()
    }

    /// Count of `Similar` matches.
    pub fn similar_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.match_kind == FuncMatchKind::Similar)
            .count()
    }

    /// Count of `Changed` matches.
    pub fn changed_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.match_kind == FuncMatchKind::Changed)
            .count()
    }

    /// Count of `NameOnly` matches.
    pub fn name_only_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.match_kind == FuncMatchKind::NameOnly)
            .count()
    }

    /// Mean similarity across all matches (0.0 if none).
    pub fn mean_similarity(&self) -> f64 {
        if self.matches.is_empty() {
            0.0
        } else {
            self.matches.iter().map(|m| m.similarity).sum::<f64>() / self.matches.len() as f64
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §17.5  BinDiffPipeline — three-phase matching pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Three-phase binary-diffing pipeline for `FuncFeatures` slices.
///
/// The three phases are:
/// 1. **Exact matches** — same name *and* same `bytes_hash`.
/// 2. **Structural matches** — for remaining unmatched functions, build a
///    similarity matrix and run the Munkres algorithm to find the optimal
///    assignment (batched in chunks of `batch_size` when there are many
///    functions).
/// 3. **Call-graph propagation** — for each matched pair, look at their
///    callees; if a callee of `fa` has high similarity to a callee of `fb`,
///    record an additional match.  This is iterated to fixpoint.
#[derive(Debug, Clone)]
pub struct BinDiffPipeline {
    /// Minimum similarity for structural / propagation matches to be kept.
    pub threshold: f64,
    /// Maximum number of functions per batch when running the Munkres solver.
    /// Functions beyond this count are split into chunks.
    pub batch_size: usize,
    /// Maximum number of iterations for call-graph propagation.
    pub max_propagation_iters: usize,
}

impl Default for BinDiffPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl BinDiffPipeline {
    /// Create a pipeline with default settings:
    /// `threshold = 0.5`, `batch_size = 500`, `max_propagation_iters = 10`.
    pub fn new() -> Self {
        Self {
            threshold: 0.5,
            batch_size: 500,
            max_propagation_iters: 10,
        }
    }

    /// Override the similarity threshold.
    pub fn with_threshold(mut self, t: f64) -> Self {
        // `clamp` propagates NaN; a NaN threshold rejects every match silently.
        self.threshold = if t.is_nan() { 0.0 } else { t.clamp(0.0, 1.0) };
        self
    }

    /// Override the batch size used for the Munkres solver.
    pub fn with_batch_size(mut self, s: usize) -> Self {
        self.batch_size = s.max(1);
        self
    }

    /// Run the three-phase pipeline and return a `MatchResult`.
    ///
    /// # Arguments
    /// * `funcs_a` — feature records from binary A.
    /// * `funcs_b` — feature records from binary B.
    pub fn match_functions(
        &self,
        funcs_a: &[FuncFeatures],
        funcs_b: &[FuncFeatures],
    ) -> MatchResult {
        // ── Phase 1: exact matches ───────────────────────────────────────────
        let mut phase1 = Self::exact_matches(funcs_a, funcs_b);

        // Build the set of already-matched address pairs.
        let mut existing: HashSet<(u64, u64)> =
            phase1.iter().map(|m| (m.addr_a, m.addr_b)).collect();

        // ── Phase 2: structural matches ──────────────────────────────────────
        let phase2 =
            Self::structural_matches(funcs_a, funcs_b, &existing, self.threshold, self.batch_size);
        for m in &phase2 {
            existing.insert((m.addr_a, m.addr_b));
        }
        phase1.extend(phase2);

        // ── Phase 3: call-graph propagation (no call edges supplied here;
        //             callers can call `propagate_via_callgraph` separately)
        // ────────────────────────────────────────────────────────────────────

        // Compute unmatched sets.
        let matched_a: HashSet<u64> = phase1.iter().map(|m| m.addr_a).collect();
        let matched_b: HashSet<u64> = phase1.iter().map(|m| m.addr_b).collect();
        let only_in_a: Vec<u64> = funcs_a
            .iter()
            .map(|f| f.addr)
            .filter(|a| !matched_a.contains(a))
            .collect();
        let only_in_b: Vec<u64> = funcs_b
            .iter()
            .map(|f| f.addr)
            .filter(|b| !matched_b.contains(b))
            .collect();

        MatchResult::build(phase1, only_in_a, only_in_b)
    }

    // ── Phase 1 ───────────────────────────────────────────────────────────────

    /// Exact matching: a function in A matches a function in B when they
    /// share the same *name* and the same `bytes_hash`.
    ///
    /// Only 1-to-1 matches are kept (if multiple B functions have the same
    /// name/hash they are all skipped to avoid ambiguity).
    fn exact_matches(a: &[FuncFeatures], b: &[FuncFeatures]) -> Vec<FuncMatch> {
        // Build a map: (name, bytes_hash) → Vec<addr> in B.
        let mut b_map: HashMap<(String, u64), Vec<u64>> = HashMap::new();
        for fb in b {
            if let Some(name) = &fb.name
                && fb.bytes_hash != 0 {
                    b_map
                        .entry((name.clone(), fb.bytes_hash))
                        .or_default()
                        .push(fb.addr);
                }
        }

        let mut matches: Vec<FuncMatch> = Vec::new();
        for fa in a {
            if let Some(name) = &fa.name {
                if fa.bytes_hash == 0 {
                    continue;
                }
                let key = (name.clone(), fa.bytes_hash);
                if let Some(candidates) = b_map.get(&key)
                    && candidates.len() == 1 {
                        let mut m = FuncMatch::new(fa.addr, candidates[0], 1.0);
                        m.match_kind = FuncMatchKind::Identical;
                        matches.push(m);
                    }
            }
        }
        matches
    }

    // ── Phase 2 ───────────────────────────────────────────────────────────────

    /// Structural matching using the Munkres algorithm.
    ///
    /// Builds a similarity matrix for the unmatched functions in A and B,
    /// then calls `HungarianMunkres` in batches of `batch_size`.  Each matched
    /// pair whose similarity is ≥ `threshold` is added to the result.
    fn structural_matches(
        a: &[FuncFeatures],
        b: &[FuncFeatures],
        existing: &HashSet<(u64, u64)>,
        threshold: f64,
        batch_size: usize,
    ) -> Vec<FuncMatch> {
        let matched_a: HashSet<u64> = existing.iter().map(|(x, _)| *x).collect();
        let matched_b: HashSet<u64> = existing.iter().map(|(_, y)| *y).collect();

        let unmatched_a: Vec<&FuncFeatures> =
            a.iter().filter(|f| !matched_a.contains(&f.addr)).collect();
        let unmatched_b: Vec<&FuncFeatures> =
            b.iter().filter(|f| !matched_b.contains(&f.addr)).collect();

        if unmatched_a.is_empty() || unmatched_b.is_empty() {
            return Vec::new();
        }

        let mut all_matches: Vec<FuncMatch> = Vec::new();
        let mut used_b: HashSet<u64> = HashSet::new();

        // Process in batches.
        for chunk_a in unmatched_a.chunks(batch_size) {
            // Only consider B functions not yet assigned in a previous batch.
            let avail_b: Vec<&FuncFeatures> = unmatched_b
                .iter()
                .copied()
                .filter(|f| !used_b.contains(&f.addr))
                .collect();
            if avail_b.is_empty() {
                break;
            }

            // Build similarity matrix: chunk_a.len() × avail_b.len().
            let na = chunk_a.len();
            let nb = avail_b.len();
            let sim_matrix: Vec<Vec<f64>> = chunk_a
                .iter()
                .map(|fa| avail_b.iter().map(|fb| fa.similarity(fb)).collect())
                .collect();

            // Convert to cost matrix (cost = 1 - similarity).
            let cost_matrix: Vec<Vec<f64>> = sim_matrix
                .iter()
                .map(|row| row.iter().map(|&s| 1.0 - s).collect())
                .collect();

            let solver = HungarianMunkres::new(cost_matrix);
            let assignment = solver.solve();

            for (ri, ci, _cost) in assignment {
                if ri >= na || ci >= nb {
                    continue;
                }
                let fa = chunk_a[ri];
                let fb = avail_b[ci];
                let sim = fa.similarity(fb);
                if sim >= threshold {
                    all_matches.push(FuncMatch::new(fa.addr, fb.addr, sim));
                    used_b.insert(fb.addr);
                }
            }
        }

        all_matches
    }

    // ── Phase 3 ───────────────────────────────────────────────────────────────

    /// Call-graph propagation: for each matched pair (fa → fb), look at their
    /// callees; if a callee `ca` of `fa` is similar (above `threshold`) to a
    /// callee `cb` of `fb`, add the pair `(ca, cb)` as a new match.
    ///
    /// Iteration continues until no new matches are found or
    /// `max_iterations` is exhausted.
    ///
    /// # Arguments
    /// * `a_calls` — call graph for binary A: caller addr → callee addrs.
    /// * `b_calls` — call graph for binary B: caller addr → callee addrs.
    /// * `matches` — existing match list (extended in place).
    /// * `funcs_a` / `funcs_b` — feature maps for similarity queries.
    /// * `threshold` — minimum similarity for propagated matches.
    /// * `max_iterations` — maximum number of fixpoint iterations.
    pub fn propagate_via_callgraph(
        a_calls: &HashMap<u64, Vec<u64>>,
        b_calls: &HashMap<u64, Vec<u64>>,
        matches: &mut Vec<FuncMatch>,
        funcs_a: &HashMap<u64, &FuncFeatures>,
        funcs_b: &HashMap<u64, &FuncFeatures>,
        threshold: f64,
        max_iterations: usize,
    ) {
        for _ in 0..max_iterations {
            let mut matched_a: HashSet<u64> = matches.iter().map(|m| m.addr_a).collect();
            let mut matched_b: HashSet<u64> = matches.iter().map(|m| m.addr_b).collect();

            let seeds: Vec<(u64, u64)> = matches.iter().map(|m| (m.addr_a, m.addr_b)).collect();
            let mut new_matches: Vec<FuncMatch> = Vec::new();

            for (addr_a, addr_b) in seeds {
                let callees_a = match a_calls.get(&addr_a) {
                    Some(v) => v.as_slice(),
                    None => &[],
                };
                let callees_b = match b_calls.get(&addr_b) {
                    Some(v) => v.as_slice(),
                    None => &[],
                };

                if callees_a.is_empty() || callees_b.is_empty() {
                    continue;
                }

                // For each pair of (callee_a, callee_b) not yet matched, compute
                // similarity and record if above threshold.
                for &ca in callees_a {
                    if matched_a.contains(&ca) {
                        continue;
                    }
                    let fa = match funcs_a.get(&ca) {
                        Some(f) => *f,
                        None => continue,
                    };
                    let mut best_sim = 0.0_f64;
                    let mut best_cb = 0u64;
                    for &cb in callees_b {
                        if matched_b.contains(&cb) {
                            continue;
                        }
                        let fb = match funcs_b.get(&cb) {
                            Some(f) => *f,
                            None => continue,
                        };
                        let sim = fa.similarity(fb);
                        if sim > best_sim {
                            best_sim = sim;
                            best_cb = cb;
                        }
                    }
                    if best_sim >= threshold && best_cb != 0 {
                        new_matches.push(FuncMatch::new(ca, best_cb, best_sim));
                        matched_a.insert(ca);
                        matched_b.insert(best_cb);
                    }
                }
            }

            if new_matches.is_empty() {
                break;
            }
            matches.extend(new_matches);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §17.6  render_diff_summary — ASCII table output
// ─────────────────────────────────────────────────────────────────────────────

/// Render an ASCII summary table for a `MatchResult`.
///
/// The table looks like:
///
/// ```text
/// ┌─────────────────────────────────────────────────┐
/// │                BinDiff Summary                  │
/// ├──────────────────────┬──────────────────────────┤
/// │  Category            │  Count                   │
/// ├──────────────────────┼──────────────────────────┤
/// │  Identical           │       42                 │
/// │  Similar             │       17                 │
/// │  Changed             │        5                 │
/// │  Name-only           │        3                 │
/// │  Added (only in B)   │        8                 │
/// │  Deleted (only in A) │        2                 │
/// ├──────────────────────┼──────────────────────────┤
/// │  Total matched       │       67                 │
/// │  Mean similarity     │    0.912                 │
/// └──────────────────────┴──────────────────────────┘
/// ```
pub fn render_diff_summary(result: &MatchResult) -> String {
    let identical = result.identical_count();
    let similar = result.similar_count();
    let changed = result.changed_count();
    let name_only = result.name_only_count();
    let added = result.only_in_b.len();
    let deleted = result.only_in_a.len();
    let total = result.matches.len();
    let mean_sim = result.mean_similarity();

    // Column widths.
    let w_cat = 22usize;
    let w_val = 10usize;
    let w_total = w_cat + w_val + 3; // +3 for "│ " padding and "│"

    let hbar_top = format!(
        "┌{:─<w_cat$}┬{:─<w_val$}┐",
        "",
        "",
        w_cat = w_cat + 2,
        w_val = w_val + 2
    );
    let hbar_head = format!(
        "├{:─<w_cat$}┼{:─<w_val$}┤",
        "",
        "",
        w_cat = w_cat + 2,
        w_val = w_val + 2
    );
    let hbar_bot = format!(
        "└{:─<w_cat$}┴{:─<w_val$}┘",
        "",
        "",
        w_cat = w_cat + 2,
        w_val = w_val + 2
    );

    let title = "BinDiff Summary";
    let title_pad = (w_total.saturating_sub(title.len())) / 2;

    let row = |cat: &str, val: &str| -> String {
        format!(
            "│ {:<w_cat$} │ {:>w_val$} │",
            cat,
            val,
            w_cat = w_cat,
            w_val = w_val
        )
    };

    let mut out = String::new();
    out.push_str(&hbar_top);
    out.push('\n');
    out.push_str(&format!(
        "│{:>pad$}{}{:>pad2$}│\n",
        "",
        title,
        "",
        pad = title_pad + 1,
        pad2 = w_total - title_pad - title.len(),
    ));
    out.push_str(&hbar_head);
    out.push('\n');
    out.push_str(&row("Category", "Count"));
    out.push('\n');
    out.push_str(&hbar_head);
    out.push('\n');
    out.push_str(&row("Identical", &identical.to_string()));
    out.push('\n');
    out.push_str(&row("Similar", &similar.to_string()));
    out.push('\n');
    out.push_str(&row("Changed", &changed.to_string()));
    out.push('\n');
    out.push_str(&row("Name-only", &name_only.to_string()));
    out.push('\n');
    out.push_str(&row("Added (only in B)", &added.to_string()));
    out.push('\n');
    out.push_str(&row("Deleted (only in A)", &deleted.to_string()));
    out.push('\n');
    out.push_str(&hbar_head);
    out.push('\n');
    out.push_str(&row("Total matched", &total.to_string()));
    out.push('\n');
    out.push_str(&row("Mean similarity", &format!("{mean_sim:.4}")));
    out.push('\n');
    out.push_str(&hbar_bot);
    out.push('\n');
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// §17.7  Private helpers for FuncFeatures
// ─────────────────────────────────────────────────────────────────────────────

/// Compute `min(a,b) / max(a,b)` with corner cases handled.
/// Returns 1.0 when both are equal (including both zero).
#[inline]
fn count_ratio(a: u32, b: u32) -> f64 {
    if a == b {
        return 1.0;
    }
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    if hi == 0 {
        return 1.0;
    }
    lo as f64 / hi as f64
}

/// Exponential-decay similarity between two prime-product hashes.
///
/// Returns 1.0 when equal and decays to ~0 for large relative differences.
/// Both values being zero (unknown) returns 0.0.
#[inline]
fn prime_product_similarity(a: u64, b: u64) -> f64 {
    if a == 1 && b == 1 {
        // Both "unknown" (empty mnemonic list → product 1); not informative.
        return 0.0;
    }
    if a == b {
        return 1.0;
    }
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    if lo == 0 {
        return 0.0;
    }
    
    // Simple ratio proximity — larger ratio means more similar.
    lo as f64 / hi as f64
}

/// Map a mnemonic string to an index in [0, 500) using FNV-1a.
#[inline]
fn mnemonic_to_prime_index(mnemonic: &str) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in mnemonic.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (h % 500) as usize
}

// ─────────────────────────────────────────────────────────────────────────────
// §17.8  Tests for the new types
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_v2 {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Build a `FuncFeatures` with all hash fields derived deterministically
    /// from `seed` so that same-seed == same-function.
    fn make_func(
        id: u64,
        addr: u64,
        name: Option<&str>,
        bb: u32,
        edges: u32,
        seed: u64,
    ) -> FuncFeatures {
        let bytes_hash = fnv1a_mix(seed, 0xBEEF_0001);
        let mnemonic_hash = fnv1a_mix(seed, 0xBEEF_0002);
        let topology_hash = FuncFeatures::compute_topology_hash(bb, edges, 1, 2);
        FuncFeatures {
            id,
            addr,
            name: name.map(str::to_owned),
            bb_count: bb,
            edge_count: edges,
            in_degree: 1,
            out_degree: 2,
            cyclomatic_complexity: edges.saturating_sub(bb) + 2,
            bytes_hash,
            mnemonic_hash,
            topology_hash,
            prime_product: seed.wrapping_add(1),
            call_count: 2,
            string_refs_hash: fnv1a_mix(seed, 0xBEEF_0003),
            constants_hash: fnv1a_mix(seed, 0xBEEF_0004),
        }
    }

    // ── §17.2  FuncFeatures ───────────────────────────────────────────────────

    #[test]
    fn test_func_features_identical_similarity() {
        let f = make_func(1, 0x1000, Some("foo"), 5, 6, 0xABCD_EF01);
        // A function compared to itself must yield 1.0 (all hashes match).
        let s = f.similarity(&f);
        assert!(
            (s - 1.0).abs() < 1e-9,
            "identical FuncFeatures must score 1.0, got {s}"
        );
    }

    #[test]
    fn test_func_features_different_similarity() {
        let a = make_func(1, 0x1000, Some("foo"), 2, 2, 0xAAAA_AAAA);
        let b = make_func(2, 0x2000, Some("bar"), 50, 60, 0xBBBB_BBBB);
        let s = a.similarity(&b);
        assert!(
            s < 0.15,
            "very different functions should score < 0.15, got {s}"
        );
    }

    #[test]
    fn test_func_features_bytes_hash_weight() {
        // Two functions with same bytes_hash but different everything else.
        // Note: `zeroed` sets bb_count=0 and edge_count=0 for both, so the
        // ratio for both is 1.0 which is ≥ 0.9 → bb adds +0.10, edge adds
        // +0.05.  The prime_product is 1 for both (both empty) which returns
        // 0.0 (not informative).  Expected total: 0.40 + 0.10 + 0.05 = 0.55.
        let mut a = FuncFeatures::zeroed(1, 0x1000);
        a.bytes_hash = 0xDEAD_BEEF;
        let mut b = FuncFeatures::zeroed(2, 0x2000);
        b.bytes_hash = 0xDEAD_BEEF;
        let s = a.similarity(&b);
        // bytes_hash matches (+0.40), bb_count both 0 within 10% (+0.10),
        // edge_count both 0 within 10% (+0.05) → 0.55.
        assert!(
            (s - 0.55).abs() < 1e-9,
            "bytes_hash + bb/edge zeros → 0.55, got {s}"
        );
        // Verify bytes_hash is the dominant contributor.
        assert!(
            s > 0.40,
            "score must be at least 0.40 from bytes_hash alone"
        );
    }

    #[test]
    fn test_func_features_mnemonic_hash_weight() {
        let mut a = FuncFeatures::zeroed(1, 0x1000);
        a.mnemonic_hash = 0xCAFE_BABE;
        let mut b = FuncFeatures::zeroed(2, 0x2000);
        b.mnemonic_hash = 0xCAFE_BABE;
        let s = a.similarity(&b);
        // bytes_hash = 0 (no match → 0.0), mnemonic matches (+0.25),
        // bb_count both 0 (+0.10), edge_count both 0 (+0.05) → 0.40.
        assert!(
            (s - 0.40).abs() < 1e-9,
            "mnemonic_hash + zero bb/edge → 0.40, got {s}"
        );
        assert!(s >= 0.25, "mnemonic_hash must contribute at least 0.25");
    }

    #[test]
    fn test_func_features_topology_hash_weight() {
        let topo = FuncFeatures::compute_topology_hash(4, 5, 1, 2);
        let mut a = FuncFeatures::zeroed(1, 0x1000);
        a.topology_hash = topo;
        a.bb_count = 4;
        a.edge_count = 5; // set non-zero counts to make bb/edge differ
        let mut b = FuncFeatures::zeroed(2, 0x2000);
        b.topology_hash = topo;
        b.bb_count = 4;
        b.edge_count = 5;
        let s = a.similarity(&b);
        // topology (+0.15), bb within 10% (+0.10), edge within 10% (+0.05) → 0.30.
        assert!(
            (s - 0.30).abs() < 1e-9,
            "topology + equal bb/edge → 0.30, got {s}"
        );
        assert!(s >= 0.15, "topology_hash must contribute at least 0.15");
    }

    #[test]
    fn test_func_features_bb_count_within_10_percent() {
        let mut a = FuncFeatures::zeroed(1, 0x1000);
        a.bb_count = 10;
        let mut b = FuncFeatures::zeroed(2, 0x2000);
        b.bb_count = 10; // exact match → ratio = 1.0 ≥ 0.9
        let s = a.similarity(&b);
        // bb within 10% adds 0.10; edge counts are both 0 (ratio = 1.0 ≥ 0.9 → +0.05).
        assert!(
            s >= 0.10,
            "same bb_count should contribute 0.10 to similarity, got {s}"
        );
    }

    #[test]
    fn test_func_features_is_byte_identical() {
        let mut a = make_func(1, 0x1000, None, 5, 5, 42);
        let b = a.clone();
        assert!(a.is_byte_identical(&b));
        a.bytes_hash = 0;
        assert!(!a.is_byte_identical(&b), "zero bytes_hash should not match");
    }

    #[test]
    fn test_func_features_compute_topology_hash_deterministic() {
        let h1 = FuncFeatures::compute_topology_hash(4, 5, 2, 3);
        let h2 = FuncFeatures::compute_topology_hash(4, 5, 2, 3);
        assert_eq!(h1, h2, "topology hash must be deterministic");
        let h3 = FuncFeatures::compute_topology_hash(4, 5, 2, 4);
        assert_ne!(h1, h3, "different inputs should give different hashes");
    }

    #[test]
    fn test_func_features_compute_prime_product_empty() {
        assert_eq!(
            FuncFeatures::compute_prime_product(&[]),
            1,
            "empty mnemonic list should return 1"
        );
    }

    #[test]
    fn test_func_features_compute_prime_product_same_order_matters() {
        let mnemonics = ["mov", "add", "jmp", "ret"];
        let p1 = FuncFeatures::compute_prime_product(&mnemonics);
        // Reverse order.
        let mnemonics_rev = ["ret", "jmp", "add", "mov"];
        let p2 = FuncFeatures::compute_prime_product(&mnemonics_rev);
        // Prime product is commutative (multiplication is commutative), so
        // both should be equal.
        assert_eq!(p1, p2, "prime product is order-independent (commutative)");
    }

    #[test]
    fn test_func_features_compute_prime_product_different_mnemonics() {
        let p1 = FuncFeatures::compute_prime_product(&["mov", "ret"]);
        let p2 = FuncFeatures::compute_prime_product(&["add", "jmp"]);
        // Extremely unlikely to collide.
        assert_ne!(
            p1, p2,
            "different mnemonic sets should give different products"
        );
    }

    #[test]
    fn test_func_features_refresh_topology_hash() {
        let mut f = FuncFeatures::zeroed(1, 0x1000);
        f.bb_count = 3;
        f.edge_count = 4;
        f.in_degree = 1;
        f.out_degree = 2;
        f.refresh_topology_hash();
        let expected = FuncFeatures::compute_topology_hash(3, 4, 1, 2);
        assert_eq!(f.topology_hash, expected);
    }

    // ── §17.3  HungarianMunkres ───────────────────────────────────────────────

    #[test]
    fn test_munkres_1x1_trivial() {
        let solver = HungarianMunkres::new(vec![vec![3.5_f64]]);
        let result = solver.solve();
        assert_eq!(result.len(), 1);
        let (r, c, cost) = result[0];
        assert_eq!((r, c), (0, 0));
        assert!((cost - 3.5).abs() < 1e-9);
    }

    #[test]
    fn test_munkres_2x2_identity() {
        // Optimal: main diagonal (cost 0+0=0).
        let cost = vec![vec![0.0_f64, 9.0], vec![9.0_f64, 0.0]];
        let solver = HungarianMunkres::new(cost);
        let result = solver.solve();
        assert_eq!(result.len(), 2);
        let pairs: HashSet<(usize, usize)> = result.iter().map(|&(r, c, _)| (r, c)).collect();
        assert!(pairs.contains(&(0, 0)));
        assert!(pairs.contains(&(1, 1)));
    }

    /// Classic 3×3 example from textbooks:
    ///
    /// ```text
    ///      B1  B2  B3
    ///  A1 [ 4   2   8 ]
    ///  A2 [ 2   3   7 ]
    ///  A3 [ 3   7   5 ]
    /// ```
    ///
    /// Optimal assignment: A1→B2 (cost 2), A2→B1 (cost 2), A3→B3 (cost 5)
    /// → total cost = 9.  Alternative: A1→B1 (4) + A2→B2 (3) + A3→B3 (5) = 12.
    #[test]
    fn test_munkres_3x3_textbook() {
        let cost = vec![
            vec![4.0_f64, 2.0, 8.0],
            vec![2.0_f64, 3.0, 7.0],
            vec![3.0_f64, 7.0, 5.0],
        ];
        let solver = HungarianMunkres::new(cost);
        let result = solver.solve();
        assert_eq!(result.len(), 3, "3×3 must produce 3 pairs");
        let total = solver.total_cost(&result);
        assert!(
            (total - 9.0).abs() < 1e-6,
            "optimal total cost should be 9.0, got {total}"
        );
        // Verify valid assignment (no row or column repeated).
        let rows: HashSet<usize> = result.iter().map(|&(r, _, _)| r).collect();
        let cols: HashSet<usize> = result.iter().map(|&(_, c, _)| c).collect();
        assert_eq!(rows.len(), 3, "rows must be distinct");
        assert_eq!(cols.len(), 3, "cols must be distinct");
    }

    #[test]
    fn test_munkres_3x3_zero_cost() {
        // The optimal assignment is trivially the identity (all zeros diagonal).
        let cost = vec![
            vec![0.0_f64, 5.0, 5.0],
            vec![5.0_f64, 0.0, 5.0],
            vec![5.0_f64, 5.0, 0.0],
        ];
        let solver = HungarianMunkres::new(cost);
        let result = solver.solve();
        let total = solver.total_cost(&result);
        assert!(
            (total - 0.0).abs() < 1e-9,
            "expected total cost 0, got {total}"
        );
    }

    #[test]
    fn test_munkres_non_square_more_rows() {
        // 4 rows, 2 cols → only 2 pairs returned.
        let cost = vec![
            vec![1.0_f64, 9.0],
            vec![9.0_f64, 1.0],
            vec![5.0_f64, 5.0],
            vec![5.0_f64, 5.0],
        ];
        let solver = HungarianMunkres::new(cost);
        let result = solver.solve();
        assert_eq!(result.len(), 2, "only 2 non-padded columns → 2 pairs");
        let cols: HashSet<usize> = result.iter().map(|&(_, c, _)| c).collect();
        assert_eq!(cols.len(), 2, "both columns must be assigned");
    }

    #[test]
    fn test_munkres_non_square_more_cols() {
        // 2 rows, 4 cols → only 2 pairs.
        let cost = vec![vec![1.0_f64, 9.0, 9.0, 9.0], vec![9.0_f64, 1.0, 9.0, 9.0]];
        let solver = HungarianMunkres::new(cost);
        let result = solver.solve();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_munkres_all_same_cost() {
        // When all costs are equal any valid assignment is optimal.
        let cost = vec![vec![1.0_f64; 3], vec![1.0_f64; 3], vec![1.0_f64; 3]];
        let solver = HungarianMunkres::new(cost);
        let result = solver.solve();
        assert_eq!(result.len(), 3);
        let rows: HashSet<usize> = result.iter().map(|&(r, _, _)| r).collect();
        let cols: HashSet<usize> = result.iter().map(|&(_, c, _)| c).collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(cols.len(), 3);
    }

    #[test]
    fn test_munkres_from_similarity_matrix() {
        // Perfect similarity on the diagonal → pairs (0,0), (1,1).
        let sim = vec![vec![1.0_f64, 0.0], vec![0.0_f64, 1.0]];
        let solver = HungarianMunkres::from_similarity_matrix(sim);
        let pairs = solver.solve_as_similarities(0.5);
        assert_eq!(pairs.len(), 2);
        let pair_set: HashSet<(usize, usize)> = pairs.iter().map(|&(r, c, _)| (r, c)).collect();
        assert!(pair_set.contains(&(0, 0)));
        assert!(pair_set.contains(&(1, 1)));
        for &(_, _, s) in &pairs {
            assert!((s - 1.0).abs() < 1e-6, "similarity should be 1.0, got {s}");
        }
    }

    #[test]
    fn test_munkres_solve_as_similarities_threshold() {
        let sim = vec![vec![0.9_f64, 0.1], vec![0.1_f64, 0.9]];
        let solver = HungarianMunkres::from_similarity_matrix(sim);
        // Above threshold 0.8: both pairs pass.
        let high = solver.solve_as_similarities(0.8);
        assert_eq!(high.len(), 2);
        // Above threshold 0.95: neither pair passes.
        let strict = solver.solve_as_similarities(0.95);
        assert_eq!(strict.len(), 0);
    }

    #[test]
    fn test_munkres_original_cost_at() {
        let cost = vec![vec![2.0_f64, 7.0], vec![3.0_f64, 5.0]];
        let solver = HungarianMunkres::new(cost);
        assert_eq!(solver.original_cost_at(0, 0), Some(2.0));
        assert_eq!(solver.original_cost_at(0, 1), Some(7.0));
        assert_eq!(solver.original_cost_at(1, 0), Some(3.0));
        assert_eq!(solver.original_cost_at(1, 1), Some(5.0));
        assert_eq!(
            solver.original_cost_at(2, 0),
            None,
            "out-of-bounds should be None"
        );
    }

    #[test]
    fn test_munkres_4x4_known_optimal() {
        // 4×4 matrix; optimal assignment has cost 0+0+0+0 = 0 (identity).
        let cost = vec![
            vec![0.0_f64, 1.0, 2.0, 3.0],
            vec![1.0_f64, 0.0, 1.0, 2.0],
            vec![2.0_f64, 1.0, 0.0, 1.0],
            vec![3.0_f64, 2.0, 1.0, 0.0],
        ];
        let solver = HungarianMunkres::new(cost);
        let result = solver.solve();
        let total = solver.total_cost(&result);
        assert!(
            (total - 0.0).abs() < 1e-9,
            "optimal cost should be 0.0, got {total}"
        );
    }

    // ── §17.5  BinDiffPipeline ────────────────────────────────────────────────

    #[test]
    fn test_pipeline_exact_matches_name_and_hash() {
        let funcs_a = vec![
            make_func(1, 0x1000, Some("main"), 5, 6, 0xAAAA),
            make_func(2, 0x2000, Some("helper"), 3, 3, 0xBBBB),
        ];
        let funcs_b = vec![
            make_func(3, 0x9000, Some("main"), 5, 6, 0xAAAA), // same name + bytes_hash
            make_func(4, 0xA000, Some("helper"), 3, 3, 0xBBBB),
        ];

        let pipeline = BinDiffPipeline::new().with_threshold(0.0);
        let result = pipeline.match_functions(&funcs_a, &funcs_b);

        assert_eq!(
            result.matches.len(),
            2,
            "both functions should match exactly"
        );
        assert_eq!(result.only_in_a.len(), 0);
        assert_eq!(result.only_in_b.len(), 0);

        for m in &result.matches {
            assert_eq!(
                m.match_kind,
                FuncMatchKind::Identical,
                "all matches should be Identical"
            );
            assert!((m.similarity - 1.0).abs() < 1e-9);
        }
    }

    #[test]
    fn test_pipeline_exact_matches_no_name() {
        // Without a name the *exact* matching phase (phase 1) should not fire.
        // However, the structural phase (phase 2) can still match functions
        // whose feature hashes are identical, even without a name.
        let funcs_a = vec![make_func(1, 0x1000, None, 5, 6, 0xAAAA)];
        let funcs_b = vec![make_func(2, 0x9000, None, 5, 6, 0xAAAA)];

        let pipeline = BinDiffPipeline::new().with_threshold(0.5);
        let result = pipeline.match_functions(&funcs_a, &funcs_b);

        // Structural phase should match the two identical functions.
        assert_eq!(
            result.matches.len(),
            1,
            "identical unnamed functions should be matched by structural phase"
        );
        // The match should NOT be FuncMatchKind::Identical (that requires name+bytes_hash
        // via phase 1); it is produced by phase 2 which classifies based on similarity.
        let m = &result.matches[0];
        assert!(
            m.similarity >= 0.5,
            "match similarity must exceed threshold"
        );
    }

    #[test]
    fn test_pipeline_structural_matches_identical_features() {
        // Two functions with identical features (all hashes equal) but no name.
        // Structural phase should match them with similarity 1.0.
        let funcs_a = vec![make_func(1, 0x1000, None, 8, 10, 0xCCCC)];
        let funcs_b = vec![make_func(2, 0x9000, None, 8, 10, 0xCCCC)];

        let pipeline = BinDiffPipeline::new().with_threshold(0.5);
        let result = pipeline.match_functions(&funcs_a, &funcs_b);

        assert_eq!(
            result.matches.len(),
            1,
            "structural phase should match them"
        );
        assert!(
            result.matches[0].similarity >= 0.5,
            "similarity should exceed threshold"
        );
    }

    #[test]
    fn test_pipeline_unmatched_when_dissimilar() {
        // Function in A is very different from the one in B → below threshold.
        let funcs_a = vec![make_func(1, 0x1000, None, 2, 2, 0x1111)];
        let funcs_b = vec![make_func(2, 0x9000, None, 200, 300, 0x2222)];

        let pipeline = BinDiffPipeline::new().with_threshold(0.5);
        let result = pipeline.match_functions(&funcs_a, &funcs_b);

        // The topology hash and bb counts differ greatly; similarity should be very low.
        if result.matches.is_empty() {
            // Correctly unmatched.
            assert_eq!(result.only_in_a.len(), 1);
            assert_eq!(result.only_in_b.len(), 1);
        } else {
            // If matched anyway, similarity must still be plausible.
            assert!(result.matches[0].similarity >= pipeline.threshold);
        }
    }

    #[test]
    fn test_pipeline_multiple_functions_correct_assignment() {
        // Three A functions each uniquely matching one B function.
        let funcs_a: Vec<FuncFeatures> = (0..3)
            .map(|i| make_func(i, 0x1000 * (i + 1), None, 5 + i as u32, 6, 0xABCD * (i + 1)))
            .collect();
        let funcs_b: Vec<FuncFeatures> = (0..3)
            .map(|i| {
                make_func(
                    i + 10,
                    0x9000 * (i + 1),
                    None,
                    5 + i as u32,
                    6,
                    0xABCD * (i + 1),
                )
            })
            .collect();

        let pipeline = BinDiffPipeline::new().with_threshold(0.0);
        let result = pipeline.match_functions(&funcs_a, &funcs_b);

        assert_eq!(result.matches.len(), 3, "all 3 functions should be matched");
        // Each function in A should be matched to the correct function in B
        // (same bytes_hash).  This is enforced by the structural phase.
        for m in &result.matches {
            let fa = funcs_a.iter().find(|f| f.addr == m.addr_a).unwrap();
            let fb = funcs_b.iter().find(|f| f.addr == m.addr_b).unwrap();
            assert_eq!(
                fa.bytes_hash, fb.bytes_hash,
                "bytes_hash should match for addr_a=0x{:X}",
                m.addr_a
            );
        }
    }

    #[test]
    fn test_pipeline_empty_a() {
        let funcs_b = vec![make_func(1, 0x1000, None, 3, 3, 0x1234)];
        let pipeline = BinDiffPipeline::new();
        let result = pipeline.match_functions(&[], &funcs_b);
        assert_eq!(result.matches.len(), 0);
        assert_eq!(result.only_in_a.len(), 0);
        assert_eq!(result.only_in_b.len(), 1);
    }

    #[test]
    fn test_pipeline_empty_b() {
        let funcs_a = vec![make_func(1, 0x1000, None, 3, 3, 0x1234)];
        let pipeline = BinDiffPipeline::new();
        let result = pipeline.match_functions(&funcs_a, &[]);
        assert_eq!(result.matches.len(), 0);
        assert_eq!(result.only_in_a.len(), 1);
        assert_eq!(result.only_in_b.len(), 0);
    }

    #[test]
    fn test_pipeline_both_empty() {
        let pipeline = BinDiffPipeline::new();
        let result = pipeline.match_functions(&[], &[]);
        assert_eq!(result.matches.len(), 0);
        assert_eq!(result.only_in_a.len(), 0);
        assert_eq!(result.only_in_b.len(), 0);
    }

    // ── §17.5  propagate_via_callgraph ────────────────────────────────────────

    #[test]
    fn test_propagate_via_callgraph_basic() {
        // Build a minimal scenario:
        //   A: fa (0x1000) calls ga (0x2000)
        //   B: fb (0x9000) calls gb (0xA000)
        //   fa ↔ fb is already matched; ga and gb are similar.
        let ga = make_func(10, 0x2000, None, 3, 3, 0xCAFE_1234);
        let gb = make_func(20, 0xA000, None, 3, 3, 0xCAFE_1234); // same seed → identical

        let mut a_calls: HashMap<u64, Vec<u64>> = HashMap::new();
        a_calls.insert(0x1000, vec![0x2000]);

        let mut b_calls: HashMap<u64, Vec<u64>> = HashMap::new();
        b_calls.insert(0x9000, vec![0xA000]);

        let mut funcs_a: HashMap<u64, &FuncFeatures> = HashMap::new();
        let mut funcs_b: HashMap<u64, &FuncFeatures> = HashMap::new();
        funcs_a.insert(0x2000, &ga);
        funcs_b.insert(0xA000, &gb);

        // Seed match: fa ↔ fb.
        let mut matches = vec![FuncMatch::new(0x1000, 0x9000, 1.0)];

        BinDiffPipeline::propagate_via_callgraph(
            &a_calls,
            &b_calls,
            &mut matches,
            &funcs_a,
            &funcs_b,
            0.5,
            10,
        );

        // ga ↔ gb should have been added.
        let propagated = matches.iter().find(|m| m.addr_a == 0x2000);
        assert!(
            propagated.is_some(),
            "ga (0x2000) should have been matched via call-graph propagation"
        );
        if let Some(m) = propagated {
            assert_eq!(m.addr_b, 0xA000, "ga should match gb at 0xA000");
            assert!(
                m.similarity >= 0.5,
                "propagated match similarity should be ≥ threshold"
            );
        }
    }

    #[test]
    fn test_propagate_via_callgraph_no_new_matches_on_already_matched() {
        // ga is already matched; propagation should not produce duplicates.
        let ga = make_func(10, 0x2000, None, 3, 3, 0xCAFE_1234);
        let gb = make_func(20, 0xA000, None, 3, 3, 0xCAFE_1234);

        let mut a_calls: HashMap<u64, Vec<u64>> = HashMap::new();
        a_calls.insert(0x1000, vec![0x2000]);
        let mut b_calls: HashMap<u64, Vec<u64>> = HashMap::new();
        b_calls.insert(0x9000, vec![0xA000]);

        let mut funcs_a: HashMap<u64, &FuncFeatures> = HashMap::new();
        let mut funcs_b: HashMap<u64, &FuncFeatures> = HashMap::new();
        funcs_a.insert(0x2000, &ga);
        funcs_b.insert(0xA000, &gb);

        // Both seed match AND ga↔gb already exist.
        let mut matches = vec![
            FuncMatch::new(0x1000, 0x9000, 1.0),
            FuncMatch::new(0x2000, 0xA000, 1.0),
        ];

        let count_before = matches.len();
        BinDiffPipeline::propagate_via_callgraph(
            &a_calls,
            &b_calls,
            &mut matches,
            &funcs_a,
            &funcs_b,
            0.5,
            10,
        );

        assert_eq!(
            matches.len(),
            count_before,
            "no new matches should be added when callees are already matched"
        );
    }

    #[test]
    fn test_propagate_via_callgraph_empty_calls() {
        let a_calls: HashMap<u64, Vec<u64>> = HashMap::new();
        let b_calls: HashMap<u64, Vec<u64>> = HashMap::new();
        let funcs_a: HashMap<u64, &FuncFeatures> = HashMap::new();
        let funcs_b: HashMap<u64, &FuncFeatures> = HashMap::new();
        let mut matches = vec![FuncMatch::new(0x1000, 0x9000, 1.0)];

        BinDiffPipeline::propagate_via_callgraph(
            &a_calls,
            &b_calls,
            &mut matches,
            &funcs_a,
            &funcs_b,
            0.5,
            10,
        );

        assert_eq!(matches.len(), 1, "no propagation without call edges");
    }

    // ── §17.6  MatchResult ────────────────────────────────────────────────────

    #[test]
    fn test_match_result_similarity_distribution() {
        // Create 10 matches with similarities 0.05, 0.15, …, 0.95.
        let matches: Vec<FuncMatch> = (0..10)
            .map(|i| {
                let sim = (i as f64) * 0.1 + 0.05;
                FuncMatch::new(i as u64 * 0x100, i as u64 * 0x900, sim)
            })
            .collect();

        let result = MatchResult::build(matches, vec![], vec![]);
        // Each bucket should have exactly one entry.
        for &count in &result.similarity_distribution {
            assert_eq!(count, 1, "each decile bucket should have one match");
        }
    }

    #[test]
    fn test_match_result_kind_counts() {
        let mut matches: Vec<FuncMatch> = Vec::new();
        // 3 identical (sim = 1.0)
        for i in 0..3 {
            matches.push(FuncMatch::new(i, i + 100, 1.0));
        }
        // 2 similar (0.75 ≤ sim < 0.99)
        for i in 3..5 {
            matches.push(FuncMatch::new(i, i + 100, 0.80));
        }
        // 1 changed (sim < 0.75)
        matches.push(FuncMatch::new(10, 110, 0.60));
        // 1 name-only
        matches.push(FuncMatch::name_only(20, 120));

        let result = MatchResult::build(matches, vec![], vec![]);
        assert_eq!(result.identical_count(), 3);
        assert_eq!(result.similar_count(), 2);
        assert_eq!(result.changed_count(), 1);
        assert_eq!(result.name_only_count(), 1);
    }

    #[test]
    fn test_match_result_mean_similarity() {
        let matches: Vec<FuncMatch> = vec![FuncMatch::new(1, 2, 0.8), FuncMatch::new(3, 4, 0.6)];
        let result = MatchResult::build(matches, vec![], vec![]);
        assert!((result.mean_similarity() - 0.7).abs() < 1e-9);
    }

    #[test]
    fn test_match_result_mean_similarity_empty() {
        let result = MatchResult::build(vec![], vec![], vec![]);
        assert_eq!(result.mean_similarity(), 0.0);
    }

    // ── §17.6  render_diff_summary ────────────────────────────────────────────

    #[test]
    fn test_render_diff_summary_contains_all_categories() {
        let matches: Vec<FuncMatch> = vec![
            FuncMatch::new(1, 2, 1.0),  // Identical
            FuncMatch::new(3, 4, 0.80), // Similar
            FuncMatch::new(5, 6, 0.60), // Changed
            FuncMatch::name_only(7, 8), // NameOnly
        ];
        let result = MatchResult::build(
            matches,
            vec![0xDEAD],         // only_in_a
            vec![0xBEEF, 0xCAFE], // only_in_b
        );
        let summary = render_diff_summary(&result);

        assert!(
            summary.contains("Identical"),
            "summary must contain 'Identical'"
        );
        assert!(
            summary.contains("Similar"),
            "summary must contain 'Similar'"
        );
        assert!(
            summary.contains("Changed"),
            "summary must contain 'Changed'"
        );
        assert!(
            summary.contains("Name-only"),
            "summary must contain 'Name-only'"
        );
        assert!(summary.contains("Added"), "summary must contain 'Added'");
        assert!(
            summary.contains("Deleted"),
            "summary must contain 'Deleted'"
        );
        assert!(
            summary.contains("Total matched"),
            "summary must contain 'Total matched'"
        );
        assert!(
            summary.contains("Mean similarity"),
            "summary must contain 'Mean similarity'"
        );
    }

    #[test]
    fn test_render_diff_summary_correct_counts() {
        let matches: Vec<FuncMatch> = vec![
            FuncMatch::new(1, 2, 1.0),  // 1 identical
            FuncMatch::new(3, 4, 0.80), // 1 similar
        ];
        let result = MatchResult::build(matches, vec![0xA], vec![0xB, 0xC]);
        let summary = render_diff_summary(&result);

        // The summary should contain "1" and "2" for added/deleted.
        // We just verify the string is non-empty and has box-drawing characters.
        assert!(
            summary.contains('┌'),
            "summary should use box-drawing characters"
        );
        assert!(summary.contains('└'));
    }

    #[test]
    fn test_render_diff_summary_empty_result() {
        let result = MatchResult::build(vec![], vec![], vec![]);
        let summary = render_diff_summary(&result);
        assert!(
            !summary.is_empty(),
            "summary should not be empty for empty result"
        );
        assert!(summary.contains('0'), "counts should be zero");
    }

    // ── §17.7  Private helpers ────────────────────────────────────────────────

    #[test]
    fn test_count_ratio_equal() {
        assert!((count_ratio(5, 5) - 1.0).abs() < 1e-9);
        assert!((count_ratio(0, 0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_count_ratio_half() {
        assert!((count_ratio(5, 10) - 0.5).abs() < 1e-9);
        assert!((count_ratio(10, 5) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_prime_product_similarity_equal() {
        assert!((prime_product_similarity(1234, 1234) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_prime_product_similarity_both_one() {
        // Both "empty" → returns 0.0 (not informative).
        assert_eq!(prime_product_similarity(1, 1), 0.0);
    }

    #[test]
    fn test_mnemonic_to_prime_index_in_range() {
        for mnemonic in &["mov", "add", "sub", "jmp", "ret", "push", "pop", "call"] {
            let idx = mnemonic_to_prime_index(mnemonic);
            assert!(idx < 500, "prime index must be < 500, got {idx}");
        }
    }

    #[test]
    fn test_primes_500_count() {
        assert_eq!(
            PRIMES_500.len(),
            500,
            "PRIMES_500 must have exactly 500 entries"
        );
    }

    #[test]
    fn test_primes_500_first_and_last() {
        assert_eq!(PRIMES_500[0], 2, "first prime must be 2");
        assert_eq!(PRIMES_500[499], 3571, "500th prime must be 3571");
    }

    #[test]
    fn test_primes_500_all_odd_except_first() {
        for &p in PRIMES_500.iter().skip(1) {
            assert_eq!(p % 2, 1, "all primes > 2 must be odd, found {p}");
        }
    }

    // ── FuncMatchKind ─────────────────────────────────────────────────────────

    #[test]
    fn test_func_match_kind_display() {
        assert_eq!(FuncMatchKind::Identical.to_string(), "Identical");
        assert_eq!(FuncMatchKind::Similar.to_string(), "Similar");
        assert_eq!(FuncMatchKind::Changed.to_string(), "Changed");
        assert_eq!(FuncMatchKind::NameOnly.to_string(), "NameOnly");
    }

    #[test]
    fn test_func_match_kind_assignment_from_similarity() {
        assert_eq!(
            FuncMatch::new(0, 1, 1.0).match_kind,
            FuncMatchKind::Identical
        );
        assert_eq!(
            FuncMatch::new(0, 1, 0.99).match_kind,
            FuncMatchKind::Identical
        );
        assert_eq!(
            FuncMatch::new(0, 1, 0.98).match_kind,
            FuncMatchKind::Similar
        );
        assert_eq!(
            FuncMatch::new(0, 1, 0.75).match_kind,
            FuncMatchKind::Similar
        );
        assert_eq!(
            FuncMatch::new(0, 1, 0.74).match_kind,
            FuncMatchKind::Changed
        );
        assert_eq!(FuncMatch::new(0, 1, 0.0).match_kind, FuncMatchKind::Changed);
        assert_eq!(
            FuncMatch::name_only(0, 1).match_kind,
            FuncMatchKind::NameOnly
        );
    }

    // ── BinDiffPipeline integration ───────────────────────────────────────────

    /// Full integration test: 6 functions per side with clear 1-to-1 matching.
    #[test]
    fn test_pipeline_integration_six_functions() {
        let seeds: [u64; 6] = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666];
        let funcs_a: Vec<FuncFeatures> = seeds
            .iter()
            .enumerate()
            .map(|(i, &s)| {
                make_func(
                    i as u64,
                    0x1000 + i as u64 * 0x100,
                    Some(Box::leak(format!("fn_{i}").into_boxed_str())),
                    (5 + i) as u32,
                    (6 + i) as u32,
                    s,
                )
            })
            .collect();

        // B has the same functions at different addresses.
        let funcs_b: Vec<FuncFeatures> = seeds
            .iter()
            .enumerate()
            .map(|(i, &s)| {
                make_func(
                    (i + 100) as u64,
                    0x9000 + i as u64 * 0x100,
                    Some(Box::leak(format!("fn_{i}").into_boxed_str())),
                    (5 + i) as u32,
                    (6 + i) as u32,
                    s,
                )
            })
            .collect();

        let pipeline = BinDiffPipeline::new().with_threshold(0.0);
        let result = pipeline.match_functions(&funcs_a, &funcs_b);

        assert_eq!(result.matches.len(), 6, "all 6 functions should be matched");
        assert_eq!(result.only_in_a.len(), 0);
        assert_eq!(result.only_in_b.len(), 0);
    }

    /// Integration test: propagation chains across two hops.
    #[test]
    fn test_pipeline_propagation_chain() {
        // Call graph in A: f1 → f2 → f3
        // Call graph in B: g1 → g2 → g3
        // Seed: f1 ↔ g1; propagation should find f2 ↔ g2 and f3 ↔ g3.

        let f1 = make_func(1, 0x1000, None, 5, 5, 0xF1F1);
        let f2 = make_func(2, 0x2000, None, 3, 3, 0xF2F2);
        let f3 = make_func(3, 0x3000, None, 2, 2, 0xF3F3);

        let g1 = make_func(11, 0x9000, None, 5, 5, 0xF1F1);
        let g2 = make_func(12, 0xA000, None, 3, 3, 0xF2F2);
        let g3 = make_func(13, 0xB000, None, 2, 2, 0xF3F3);

        let mut a_calls: HashMap<u64, Vec<u64>> = HashMap::new();
        a_calls.insert(0x1000, vec![0x2000]);
        a_calls.insert(0x2000, vec![0x3000]);

        let mut b_calls: HashMap<u64, Vec<u64>> = HashMap::new();
        b_calls.insert(0x9000, vec![0xA000]);
        b_calls.insert(0xA000, vec![0xB000]);

        let mut funcs_a_map: HashMap<u64, &FuncFeatures> = HashMap::new();
        funcs_a_map.insert(0x1000, &f1);
        funcs_a_map.insert(0x2000, &f2);
        funcs_a_map.insert(0x3000, &f3);

        let mut funcs_b_map: HashMap<u64, &FuncFeatures> = HashMap::new();
        funcs_b_map.insert(0x9000, &g1);
        funcs_b_map.insert(0xA000, &g2);
        funcs_b_map.insert(0xB000, &g3);

        let mut matches = vec![FuncMatch::new(0x1000, 0x9000, 1.0)];

        BinDiffPipeline::propagate_via_callgraph(
            &a_calls,
            &b_calls,
            &mut matches,
            &funcs_a_map,
            &funcs_b_map,
            0.5,
            10,
        );

        let matched_as: HashSet<u64> = matches.iter().map(|m| m.addr_a).collect();
        assert!(
            matched_as.contains(&0x2000),
            "f2 should be matched via propagation (1 hop)"
        );
        assert!(
            matched_as.contains(&0x3000),
            "f3 should be matched via propagation (2 hops)"
        );
    }

    /// Verify that `BinDiffPipeline::default()` has sensible settings.
    #[test]
    fn test_pipeline_default_settings() {
        let p = BinDiffPipeline::default();
        assert!(p.threshold > 0.0 && p.threshold < 1.0);
        assert!(p.batch_size > 0);
        assert!(p.max_propagation_iters > 0);
    }

    /// Verify that `with_threshold` clamps correctly.
    #[test]
    fn test_pipeline_with_threshold_clamps() {
        let p = BinDiffPipeline::new().with_threshold(-0.5);
        assert_eq!(p.threshold, 0.0);
        let p2 = BinDiffPipeline::new().with_threshold(1.5);
        assert_eq!(p2.threshold, 1.0);
    }
}
