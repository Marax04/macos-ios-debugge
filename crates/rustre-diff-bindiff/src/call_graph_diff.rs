//! `call_graph_diff` — Call-graph level approximate diffing.
//!
//! Given two binaries A and B (each represented as a directed call graph),
//! this module:
//!
//! 1. **Seeds** certain matches via exact CFG-hash equality or name equality.
//! 2. **Propagates** the seeded matches through neighbourhood voting: a
//!    function in A is matched to a function in B if their already-matched
//!    callers/callees agree.
//! 3. **Iteratively refines** until no new matches are made or a maximum
//!    number of rounds is reached.
//! 4. **Classifies** unmatched functions as Added, Removed, Renamed, or
//!    Refactored based on partial similarity evidence.

use std::collections::{HashMap, HashSet, VecDeque};

/// FIFO worklist type used by the neighbourhood-propagation phase to schedule
/// pending match-candidate visits in BFS order. Re-exported so external
/// pipelines that drive a custom propagation loop can reuse the same type.
pub type PropagationQueue = VecDeque<(usize, usize)>;

// ─────────────────────────────────────────────────────────────────────────────
// FunctionNode
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata for a single function within a call graph.
#[derive(Debug, Clone)]
pub struct FunctionNode {
    /// Stable index within this binary's function list.
    pub idx: usize,
    /// CFG topology hash (Weisfeiler-Lehman, address-invariant).
    pub cfg_hash: u64,
    /// Optional debug/export name hash (FNV-1a of the name string).
    pub name_hash: Option<u64>,
    /// Human-readable name, if available.
    pub name: Option<String>,
    /// Structural features: (`block_count`, `insn_count`, `call_out`).
    pub features: (u32, u32, u32),
}

impl FunctionNode {
    /// Quick structural similarity in [0, 1] between two nodes.
    #[must_use]
    pub fn structural_similarity(&self, other: &Self) -> f64 {
        let (ba, ia, oa) = self.features;
        let (bb, ib, ob) = other.features;

        fn ratio(a: u32, b: u32) -> f64 {
            if a == 0 && b == 0 { return 1.0; }
            let (lo, hi) = if a < b { (a, b) } else { (b, a) };
            lo as f64 / hi as f64
        }

        let cfg_bonus = if self.cfg_hash == other.cfg_hash && self.cfg_hash != 0 { 0.40 } else { 0.0 };
        let name_bonus = match (self.name_hash, other.name_hash) {
            (Some(a), Some(b)) if a == b && a != 0 => 0.20,
            _ => 0.0,
        };

        let base = 0.20 * ratio(ba, bb) + 0.15 * ratio(ia, ib) + 0.05 * ratio(oa, ob);
        (base + cfg_bonus + name_bonus).clamp(0.0, 1.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallEdge
// ─────────────────────────────────────────────────────────────────────────────

/// A directed call edge: caller → callee (both indices into the same binary's
/// function list).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallEdge {
    pub caller: usize,
    pub callee: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraph
// ─────────────────────────────────────────────────────────────────────────────

/// A complete call graph for one binary.
#[derive(Debug, Clone)]
pub struct CallGraph {
    pub functions: Vec<FunctionNode>,
    pub edges: Vec<CallEdge>,
    /// `callees[i]` = set of functions called by function i.
    pub callees: Vec<HashSet<usize>>,
    /// `callers[i]` = set of functions that call function i.
    pub callers: Vec<HashSet<usize>>,
}

impl CallGraph {
    /// Build a `CallGraph` from a list of functions and edges.
    #[must_use]
    pub fn new(functions: Vec<FunctionNode>, edges: Vec<CallEdge>) -> Self {
        let n = functions.len();
        let mut callees = vec![HashSet::new(); n];
        let mut callers = vec![HashSet::new(); n];
        for &CallEdge { caller, callee } in &edges {
            if caller < n && callee < n {
                callees[caller].insert(callee);
                callers[callee].insert(caller);
            }
        }
        Self { functions, edges, callees, callers }
    }

    /// Number of functions in this graph.
    #[must_use]
    pub const fn len(&self) -> usize { self.functions.len() }

    /// Returns true if the graph has no functions.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.functions.is_empty() }

    /// Iterator over all (`caller_idx`, `callee_idx`) pairs.
    pub fn edge_pairs(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.edges.iter().map(|e| (e.caller, e.callee))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchState
// ─────────────────────────────────────────────────────────────────────────────

/// How a function match was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchSource {
    /// CFG topology hash matched exactly.
    ExactCfgHash,
    /// Export/debug name matched exactly.
    ExactName,
    /// Propagated from neighbour votes.
    NeighbourhoodVote,
    /// Greedy heuristic (final pass).
    Heuristic,
}

/// A confirmed match between function in A and function in B.
#[derive(Debug, Clone)]
pub struct CallGraphMatch {
    pub idx_a: usize,
    pub idx_b: usize,
    pub similarity: f64,
    pub source: MatchSource,
}

/// Classification for an unmatched function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmatchedKind {
    /// Present in A, absent in B — function was removed.
    Removed,
    /// Present in B, absent in A — function was added.
    Added,
    /// Present in both but name changed (structural match, name mismatch).
    Renamed,
    /// Present in both but significantly changed (partial structural match).
    Refactored,
}

/// An unmatched function from either binary.
#[derive(Debug, Clone)]
pub struct UnmatchedCallGraphFn {
    /// Which binary: true = A, false = B.
    pub from_a: bool,
    pub idx: usize,
    pub kind: UnmatchedKind,
    /// Best partial similarity score found, if any.
    pub best_partial: Option<f64>,
    /// Index of the best partial match in the other binary.
    pub best_partial_idx: Option<usize>,
}

// ─────────────────────────────────────────────────────────────────────────────
// NeighbourhoodVoter
// ─────────────────────────────────────────────────────────────────────────────

/// Core neighbourhood voting propagation engine.
///
/// For each candidate pair (`a_i`, `b_j`) that is not yet matched, counts how many
/// of `a_i`'s neighbours are already matched to `b_j`'s neighbours.  A pair is
/// promoted to a match when votes ≥ `vote_threshold`.
struct NeighbourhoodVoter<'a> {
    cg_a: &'a CallGraph,
    cg_b: &'a CallGraph,
    /// Current confirmed matches: `a_idx` → `b_idx`.
    matches_a_to_b: HashMap<usize, usize>,
    /// Reverse: `b_idx` → `a_idx`.
    matches_b_to_a: HashMap<usize, usize>,
    vote_threshold: u32,
    sim_threshold: f64,
}

impl<'a> NeighbourhoodVoter<'a> {
    fn new(
        cg_a: &'a CallGraph,
        cg_b: &'a CallGraph,
        initial_a_to_b: HashMap<usize, usize>,
        vote_threshold: u32,
        sim_threshold: f64,
    ) -> Self {
        let matches_b_to_a = initial_a_to_b.iter().map(|(&a, &b)| (b, a)).collect();
        Self {
            cg_a, cg_b,
            matches_a_to_b: initial_a_to_b,
            matches_b_to_a,
            vote_threshold,
            sim_threshold,
        }
    }

    /// Run one propagation round.  Returns the number of new matches added.
    fn propagate_round(&mut self) -> usize {
        let mut new_matches: Vec<(usize, usize, f64)> = Vec::new();

        // Collect candidates: for every unmatched a_i, look at its neighbours'
        // matches to see which b_j accumulates votes.
        let unmatched_a: Vec<usize> = (0..self.cg_a.len())
            .filter(|i| !self.matches_a_to_b.contains_key(i))
            .collect();

        for &ai in &unmatched_a {
            let mut votes: HashMap<usize, u32> = HashMap::new();

            // Callee vote: if a_i calls a_k, and a_k is matched to b_k,
            // then b_j = b_k's caller is a candidate for a_i.
            for &ak in &self.cg_a.callees[ai] {
                if let Some(&bk) = self.matches_a_to_b.get(&ak) {
                    for &bj in &self.cg_b.callers[bk] {
                        if !self.matches_b_to_a.contains_key(&bj) {
                            *votes.entry(bj).or_insert(0) += 1;
                        }
                    }
                }
            }

            // Caller vote: symmetric.
            for &ak in &self.cg_a.callers[ai] {
                if let Some(&bk) = self.matches_a_to_b.get(&ak) {
                    for &bj in &self.cg_b.callees[bk] {
                        if !self.matches_b_to_a.contains_key(&bj) {
                            // `or_insert(0)`, matching the callee branch above:
                            // seeding at 1 made the first caller vote count
                            // twice, so a single neighbour could clear a
                            // threshold of 2 and promote a bogus match.
                            *votes.entry(bj).or_insert(0) += 1;
                        }
                    }
                }
            }

            // Find best candidate above vote threshold.
            let best = votes.iter()
                .filter(|(_, v)| **v >= self.vote_threshold)
                .max_by_key(|(_, v)| *v);

            if let Some((&bj, _)) = best {
                let sim = self.cg_a.functions[ai].structural_similarity(&self.cg_b.functions[bj]);
                if sim >= self.sim_threshold {
                    new_matches.push((ai, bj, sim));
                }
            }
        }

        // Commit new matches (avoiding conflicts — take best sim for each b_j).
        let mut committed_b: HashSet<usize> = HashSet::new();
        new_matches.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        let mut added = 0;
        for (ai, bj, _) in new_matches {
            if self.matches_a_to_b.contains_key(&ai) || committed_b.contains(&bj) {
                continue;
            }
            self.matches_a_to_b.insert(ai, bj);
            self.matches_b_to_a.insert(bj, ai);
            committed_b.insert(bj);
            added += 1;
        }
        added
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraphDiffConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the call-graph diff engine.
#[derive(Debug, Clone)]
pub struct CallGraphDiffConfig {
    /// Minimum votes for neighbourhood promotion.
    pub vote_threshold: u32,
    /// Minimum structural similarity for neighbourhood promotion.
    pub sim_threshold: f64,
    /// Maximum propagation rounds.
    pub max_rounds: u32,
    /// Similarity threshold for classifying an unmatched function as Renamed.
    pub renamed_threshold: f64,
    /// Similarity threshold for Refactored (vs. fully Added/Removed).
    pub refactored_threshold: f64,
}

impl Default for CallGraphDiffConfig {
    fn default() -> Self {
        Self {
            vote_threshold: 1,
            sim_threshold: 0.40,
            max_rounds: 20,
            renamed_threshold: 0.80,
            refactored_threshold: 0.40,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraphDiffResult
// ─────────────────────────────────────────────────────────────────────────────

/// Full output of the call-graph diff.
#[derive(Debug, Clone)]
pub struct CallGraphDiffResult {
    pub matches: Vec<CallGraphMatch>,
    pub unmatched: Vec<UnmatchedCallGraphFn>,
    /// Number of propagation rounds that ran.
    pub rounds_run: u32,
    /// Similarity score: matched (weighted) / total.
    pub overall_similarity: f64,
}

impl CallGraphDiffResult {
    /// Number of functions matched.
    #[must_use]
    pub const fn matched_count(&self) -> usize { self.matches.len() }

    /// Functions added to B.
    pub fn added(&self) -> impl Iterator<Item = &UnmatchedCallGraphFn> {
        self.unmatched.iter().filter(|u| u.kind == UnmatchedKind::Added)
    }

    /// Functions removed from A.
    pub fn removed(&self) -> impl Iterator<Item = &UnmatchedCallGraphFn> {
        self.unmatched.iter().filter(|u| u.kind == UnmatchedKind::Removed)
    }

    /// Functions renamed between A and B.
    pub fn renamed(&self) -> impl Iterator<Item = &UnmatchedCallGraphFn> {
        self.unmatched.iter().filter(|u| u.kind == UnmatchedKind::Renamed)
    }

    /// Functions refactored between A and B.
    pub fn refactored(&self) -> impl Iterator<Item = &UnmatchedCallGraphFn> {
        self.unmatched.iter().filter(|u| u.kind == UnmatchedKind::Refactored)
    }

    /// Pretty-print a summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let added = self.added().count();
        let removed = self.removed().count();
        let renamed = self.renamed().count();
        let refactored = self.refactored().count();
        format!(
            "Matched: {} | Added: {} | Removed: {} | Renamed: {} | Refactored: {} | Similarity: {:.2}%",
            self.matched_count(), added, removed, renamed, refactored,
            self.overall_similarity * 100.0,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraphDiffer — main engine
// ─────────────────────────────────────────────────────────────────────────────

/// Main call-graph diffing engine.
pub struct CallGraphDiffer {
    config: CallGraphDiffConfig,
}

impl CallGraphDiffer {
    /// Create a differ with the given config.
    #[must_use]
    pub const fn new(config: CallGraphDiffConfig) -> Self {
        Self { config }
    }

    /// Create with default config.
    #[must_use]
    pub fn default_config() -> Self {
        Self { config: CallGraphDiffConfig::default() }
    }

    /// Diff two call graphs and return the full result.
    #[must_use]
    pub fn diff(&self, cg_a: &CallGraph, cg_b: &CallGraph) -> CallGraphDiffResult {
        // Phase 1: exact seeds.
        let (mut a_to_b, mut seeded_matches) = self.seed_exact(cg_a, cg_b);
        // Stabilise the seed list so the `seeded_pairs` HashSet build below and
        // any downstream consumers observe a deterministic order regardless of
        // HashMap iteration order in `seed_exact`.
        seeded_matches.sort_by_key(|m| (m.idx_a, m.idx_b));

        // Phase 2: neighbourhood propagation.
        let mut voter = NeighbourhoodVoter::new(
            cg_a, cg_b, a_to_b,
            self.config.vote_threshold,
            self.config.sim_threshold,
        );

        let mut rounds_run = 0;
        for _ in 0..self.config.max_rounds {
            let added = voter.propagate_round();
            rounds_run += 1;
            if added == 0 {
                break;
            }
        }

        a_to_b = voter.matches_a_to_b;
        let b_to_a = voter.matches_b_to_a;

        // Build match list with proper sources.
        let seeded_pairs: HashSet<(usize, usize)> =
            seeded_matches.iter().map(|m| (m.idx_a, m.idx_b)).collect();

        let mut matches: Vec<CallGraphMatch> = a_to_b.iter().map(|(&ai, &bj)| {
            let sim = cg_a.functions[ai].structural_similarity(&cg_b.functions[bj]);
            let source = if seeded_pairs.contains(&(ai, bj)) {
                // Distinguish cfg-hash from name seed.
                if cg_a.functions[ai].cfg_hash == cg_b.functions[bj].cfg_hash
                    && cg_a.functions[ai].cfg_hash != 0
                {
                    MatchSource::ExactCfgHash
                } else {
                    MatchSource::ExactName
                }
            } else {
                MatchSource::NeighbourhoodVote
            };
            CallGraphMatch { idx_a: ai, idx_b: bj, similarity: sim, source }
        }).collect();

        // Phase 3: heuristic final pass for remaining unmatched.
        let extra = self.heuristic_pass(cg_a, cg_b, &a_to_b, &b_to_a);
        for (ai, bj) in extra {
            let sim = cg_a.functions[ai].structural_similarity(&cg_b.functions[bj]);
            matches.push(CallGraphMatch { idx_a: ai, idx_b: bj, similarity: sim, source: MatchSource::Heuristic });
            a_to_b.insert(ai, bj);
        }

        // Build unmatched list.
        let unmatched = self.classify_unmatched(cg_a, cg_b, &a_to_b);

        // Compute overall similarity.
        let total = cg_a.len().max(cg_b.len()) as f64;
        let weighted_sum: f64 = matches.iter().map(|m| m.similarity).sum();
        let overall_similarity = if total > 0.0 { weighted_sum / total } else { 1.0 };

        CallGraphDiffResult { matches, unmatched, rounds_run, overall_similarity }
    }

    // ── Phase 1: exact seeding ───────────────────────────────────────────────

    fn seed_exact(
        &self,
        cg_a: &CallGraph,
        cg_b: &CallGraph,
    ) -> (HashMap<usize, usize>, Vec<CallGraphMatch>) {
        let mut a_to_b: HashMap<usize, usize> = HashMap::new();
        let mut b_used: HashSet<usize> = HashSet::new();
        let mut matches: Vec<CallGraphMatch> = Vec::new();

        // Build lookup tables for B.
        let mut b_by_cfg: HashMap<u64, Vec<usize>> = HashMap::new();
        let mut b_by_name: HashMap<u64, Vec<usize>> = HashMap::new();
        for fn_b in &cg_b.functions {
            if fn_b.cfg_hash != 0 {
                b_by_cfg.entry(fn_b.cfg_hash).or_default().push(fn_b.idx);
            }
            if let Some(nh) = fn_b.name_hash {
                b_by_name.entry(nh).or_default().push(fn_b.idx);
            }
        }

        // Seed by CFG hash (exact topology match, unique).
        for fn_a in &cg_a.functions {
            if a_to_b.contains_key(&fn_a.idx) { continue; }
            if let Some(candidates) = b_by_cfg.get(&fn_a.cfg_hash) {
                if candidates.len() == 1 {
                    let bj = candidates[0];
                    if !b_used.contains(&bj) {
                        a_to_b.insert(fn_a.idx, bj);
                        b_used.insert(bj);
                        matches.push(CallGraphMatch {
                            idx_a: fn_a.idx, idx_b: bj,
                            similarity: 1.0,
                            source: MatchSource::ExactCfgHash,
                        });
                    }
                }
            }
        }

        // Seed by name hash (unique name).
        for fn_a in &cg_a.functions {
            if a_to_b.contains_key(&fn_a.idx) { continue; }
            if let Some(nh) = fn_a.name_hash {
                if let Some(candidates) = b_by_name.get(&nh) {
                    if candidates.len() == 1 {
                        let bj = candidates[0];
                        if !b_used.contains(&bj) {
                            a_to_b.insert(fn_a.idx, bj);
                            b_used.insert(bj);
                            let sim = fn_a.structural_similarity(&cg_b.functions[bj]);
                            matches.push(CallGraphMatch {
                                idx_a: fn_a.idx, idx_b: bj,
                                similarity: sim,
                                source: MatchSource::ExactName,
                            });
                        }
                    }
                }
            }
        }

        (a_to_b, matches)
    }

    // ── Phase 3: heuristic fallback ──────────────────────────────────────────

    fn heuristic_pass(
        &self,
        cg_a: &CallGraph,
        cg_b: &CallGraph,
        a_to_b: &HashMap<usize, usize>,
        b_to_a: &HashMap<usize, usize>,
    ) -> Vec<(usize, usize)> {
        let unmatched_a: Vec<usize> = (0..cg_a.len())
            .filter(|i| !a_to_b.contains_key(i))
            .collect();
        let unmatched_b: Vec<usize> = (0..cg_b.len())
            .filter(|j| !b_to_a.contains_key(j))
            .collect();

        if unmatched_a.is_empty() || unmatched_b.is_empty() {
            return Vec::new();
        }

        // Build a similarity list; take best matches above threshold.
        let mut candidates: Vec<(f64, usize, usize)> = Vec::new();
        for &ai in &unmatched_a {
            for &bj in &unmatched_b {
                let sim = cg_a.functions[ai].structural_similarity(&cg_b.functions[bj]);
                if sim >= self.config.sim_threshold {
                    candidates.push((sim, ai, bj));
                }
            }
        }
        candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        let mut used_a = HashSet::new();
        let mut used_b = HashSet::new();
        let mut result = Vec::new();
        for (_, ai, bj) in candidates {
            if used_a.contains(&ai) || used_b.contains(&bj) { continue; }
            used_a.insert(ai);
            used_b.insert(bj);
            result.push((ai, bj));
        }
        result
    }

    // ── Classification of unmatched functions ────────────────────────────────

    fn classify_unmatched(
        &self,
        cg_a: &CallGraph,
        cg_b: &CallGraph,
        a_to_b: &HashMap<usize, usize>,
    ) -> Vec<UnmatchedCallGraphFn> {
        let b_matched: HashSet<usize> = a_to_b.values().copied().collect();
        let mut result = Vec::new();

        // Unmatched in A.
        for i in 0..cg_a.len() {
            if a_to_b.contains_key(&i) { continue; }
            let (best_sim, best_j) = self.best_partial_match_in_b(cg_a, cg_b, i, &b_matched);
            let kind = self.classify_a_side(cg_a, cg_b, i, best_sim, best_j);
            result.push(UnmatchedCallGraphFn {
                from_a: true,
                idx: i,
                kind,
                best_partial: Some(best_sim),
                best_partial_idx: best_j,
            });
        }

        // Unmatched in B.
        for j in 0..cg_b.len() {
            if b_matched.contains(&j) { continue; }
            // For B-side unmatched, we just classify as Added (no partial in A available here).
            result.push(UnmatchedCallGraphFn {
                from_a: false,
                idx: j,
                kind: UnmatchedKind::Added,
                best_partial: None,
                best_partial_idx: None,
            });
        }

        result
    }

    fn best_partial_match_in_b(
        &self,
        cg_a: &CallGraph,
        cg_b: &CallGraph,
        ai: usize,
        b_matched: &HashSet<usize>,
    ) -> (f64, Option<usize>) {
        let mut best_sim = 0.0_f64;
        let mut best_j = None;
        for j in 0..cg_b.len() {
            if b_matched.contains(&j) { continue; }
            let sim = cg_a.functions[ai].structural_similarity(&cg_b.functions[j]);
            if sim > best_sim {
                best_sim = sim;
                best_j = Some(j);
            }
        }
        (best_sim, best_j)
    }

    fn classify_a_side(
        &self,
        cg_a: &CallGraph,
        cg_b: &CallGraph,
        ai: usize,
        best_sim: f64,
        best_j: Option<usize>,
    ) -> UnmatchedKind {
        if best_sim < self.config.refactored_threshold {
            return UnmatchedKind::Removed;
        }
        // If name hash differs but struct matches → Renamed.
        if best_sim >= self.config.renamed_threshold {
            if let Some(j) = best_j {
                let name_match = match (cg_a.functions[ai].name_hash, cg_b.functions[j].name_hash) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                };
                if !name_match {
                    return UnmatchedKind::Renamed;
                }
            }
        }
        UnmatchedKind::Refactored
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience builder
// ─────────────────────────────────────────────────────────────────────────────

/// Build a `CallGraph` quickly from flat arrays.
///
/// `functions`: list of `(cfg_hash, name_hash, block_count, insn_count, call_out)`.
/// `edges`: list of `(caller_idx, callee_idx)`.
#[must_use]
pub fn build_call_graph(
    functions: &[(u64, Option<u64>, u32, u32, u32)],
    edges: &[(usize, usize)],
) -> CallGraph {
    let nodes: Vec<FunctionNode> = functions
        .iter()
        .enumerate()
        .map(|(i, &(cfg_hash, name_hash, bc, ic, co))| FunctionNode {
            idx: i,
            cfg_hash,
            name_hash,
            name: None,
            features: (bc, ic, co),
        })
        .collect();
    let edge_list: Vec<CallEdge> = edges
        .iter()
        .map(|&(caller, callee)| CallEdge { caller, callee })
        .collect();
    CallGraph::new(nodes, edge_list)
}

// ─────────────────────────────────────────────────────────────────────────────
// FNV-1a helper
// ─────────────────────────────────────────────────────────────────────────────

#[must_use]
pub fn fnv1a_str(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_graph() -> CallGraph {
        // 3 functions: 0→1, 1→2.
        build_call_graph(
            &[
                (0xAAA, Some(0x01), 5, 20, 1),
                (0xBBB, Some(0x02), 3, 10, 1),
                (0xCCC, Some(0x03), 2, 5, 0),
            ],
            &[(0, 1), (1, 2)],
        )
    }

    #[test]
    fn test_call_graph_construction() {
        let cg = simple_graph();
        assert_eq!(cg.len(), 3);
        assert!(cg.callees[0].contains(&1));
        assert!(cg.callers[1].contains(&0));
    }

    #[test]
    fn test_exact_cfg_seed() {
        let cg_a = simple_graph();
        let cg_b = simple_graph(); // identical
        let differ = CallGraphDiffer::default_config();
        let result = differ.diff(&cg_a, &cg_b);
        // All 3 should match via exact CFG hash.
        assert_eq!(result.matched_count(), 3);
        assert!(result.unmatched.is_empty());
    }

    #[test]
    fn test_exact_name_seed() {
        // Same names, different cfg_hash.
        let cg_a = build_call_graph(
            &[(0x111, Some(0x01), 5, 20, 1), (0x222, Some(0x02), 3, 10, 0)],
            &[(0, 1)],
        );
        let cg_b = build_call_graph(
            &[(0x333, Some(0x01), 5, 20, 1), (0x444, Some(0x02), 3, 10, 0)],
            &[(0, 1)],
        );
        let differ = CallGraphDiffer::default_config();
        let result = differ.diff(&cg_a, &cg_b);
        assert_eq!(result.matched_count(), 2);
    }

    #[test]
    fn test_neighbourhood_propagation() {
        // A: 0→1→2; B: 0→1→2 with only function 0 having same cfg_hash.
        let cg_a = build_call_graph(
            &[(0x111, None, 5, 20, 1), (0x222, None, 3, 10, 1), (0x333, None, 2, 5, 0)],
            &[(0, 1), (1, 2)],
        );
        let cg_b = build_call_graph(
            &[(0x111, None, 5, 20, 1), (0x999, None, 3, 10, 1), (0xAAA, None, 2, 5, 0)],
            &[(0, 1), (1, 2)],
        );
        let differ = CallGraphDiffer::default_config();
        let result = differ.diff(&cg_a, &cg_b);
        // Function 0 seeded; 1 and 2 should propagate.
        assert!(result.matched_count() >= 1);
    }

    #[test]
    fn test_added_functions() {
        // B has one extra function.
        let cg_a = build_call_graph(&[(0xAAA, Some(0x01), 5, 20, 0)], &[]);
        let cg_b = build_call_graph(
            &[(0xAAA, Some(0x01), 5, 20, 0), (0xBBB, None, 3, 10, 0)],
            &[],
        );
        let differ = CallGraphDiffer::default_config();
        let result = differ.diff(&cg_a, &cg_b);
        assert_eq!(result.added().count(), 1);
    }

    #[test]
    fn test_removed_functions() {
        let cg_a = build_call_graph(
            &[(0xAAA, Some(0x01), 5, 20, 0), (0xBBB, None, 3, 10, 0)],
            &[],
        );
        let cg_b = build_call_graph(&[(0xAAA, Some(0x01), 5, 20, 0)], &[]);
        let differ = CallGraphDiffer::default_config();
        let result = differ.diff(&cg_a, &cg_b);
        assert_eq!(result.removed().count(), 1);
    }

    #[test]
    fn test_overall_similarity_identical() {
        let cg = simple_graph();
        let differ = CallGraphDiffer::default_config();
        let result = differ.diff(&cg, &cg);
        assert!(result.overall_similarity > 0.9);
    }

    #[test]
    fn test_empty_graphs() {
        let cg_a = build_call_graph(&[], &[]);
        let cg_b = build_call_graph(&[], &[]);
        let differ = CallGraphDiffer::default_config();
        let result = differ.diff(&cg_a, &cg_b);
        assert_eq!(result.matched_count(), 0);
        assert!(result.unmatched.is_empty());
    }

    #[test]
    fn test_structural_similarity_identical() {
        let f = FunctionNode {
            idx: 0, cfg_hash: 0xDEAD, name_hash: Some(0xBEEF),
            name: None, features: (5, 20, 2),
        };
        assert!(f.structural_similarity(&f) > 0.9);
    }

    #[test]
    fn test_fnv1a_str_deterministic() {
        let h1 = fnv1a_str("foo");
        let h2 = fnv1a_str("foo");
        assert_eq!(h1, h2);
        assert_ne!(fnv1a_str("foo"), fnv1a_str("bar"));
    }

    #[test]
    fn test_summary_string() {
        let cg = simple_graph();
        let differ = CallGraphDiffer::default_config();
        let result = differ.diff(&cg, &cg);
        let s = result.summary();
        assert!(s.contains("Matched: 3"));
    }

    #[test]
    fn test_config_default() {
        let cfg = CallGraphDiffConfig::default();
        assert_eq!(cfg.vote_threshold, 1);
        assert!(cfg.max_rounds > 0);
    }
}
