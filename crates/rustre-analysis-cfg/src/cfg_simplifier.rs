//! CFG simplification: dead-block removal, empty-block threading, fall-through
//! merging, and chain collapse.
//!
//! The main entry point is [`CfgSimplifier`], which applies a fixed-point
//! sequence of local transformations to a [`ControlFlowGraph`] until no
//! further simplification is possible.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::{BasicBlock, CfgEdge, ControlFlowGraph, DominatorTree, EdgeKind, PostDominatorTree};
use rustre_core::address::Address;
use rustre_il_llil::LlilInstruction;

// ─────────────────────────────────────────────────────────────────────────────
// MergeCandidate
// ─────────────────────────────────────────────────────────────────────────────

/// A pair of basic blocks that are eligible for merging.
///
/// Two blocks `(pred, succ)` form a merge candidate when:
/// - `pred` has exactly one outgoing edge, which leads to `succ`.
/// - `succ` has exactly one incoming edge, which comes from `pred`.
/// - Neither block is the CFG entry (to preserve the entry invariant).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MergeCandidate {
    /// The predecessor block that will absorb `succ`.
    pub pred: Address,
    /// The successor block that will be consumed.
    pub succ: Address,
}

impl MergeCandidate {
    /// Create a new merge candidate.
    #[must_use]
    pub const fn new(pred: Address, succ: Address) -> Self {
        Self { pred, succ }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SimplifyResult
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of one simplification pass over the CFG.
#[derive(Debug, Clone)]
pub struct SimplifyResult {
    /// Number of block pairs that were merged during this pass.
    pub merges: usize,
    /// Number of unreachable blocks that were removed.
    pub dead_blocks_removed: usize,
    /// Number of empty pass-through blocks that were eliminated (jump threading).
    pub threaded_blocks: usize,
    /// Whether the CFG changed at all in this pass.
    pub changed: bool,
}

impl SimplifyResult {
    const fn zero() -> Self {
        Self {
            merges: 0,
            dead_blocks_removed: 0,
            threaded_blocks: 0,
            changed: false,
        }
    }

    const fn combine(mut self, other: &Self) -> Self {
        self.merges += other.merges;
        self.dead_blocks_removed += other.dead_blocks_removed;
        self.threaded_blocks += other.threaded_blocks;
        self.changed |= other.changed;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BlockRelation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Count outgoing edges from `addr` in the edge list.
fn out_degree(addr: Address, edges: &[CfgEdge]) -> usize {
    edges.iter().filter(|e| e.from == addr).count()
}

/// Count incoming edges to `addr` in the edge list.
fn in_degree(addr: Address, edges: &[CfgEdge]) -> usize {
    edges.iter().filter(|e| e.to == addr).count()
}

/// Return the single successor of `addr`, or `None` if the out-degree is not 1.
fn single_successor(addr: Address, edges: &[CfgEdge]) -> Option<Address> {
    let succs: Vec<Address> = edges
        .iter()
        .filter(|e| e.from == addr)
        .map(|e| e.to)
        .collect();
    if succs.len() == 1 {
        Some(succs[0])
    } else {
        None
    }
}

/// Return the single predecessor of `addr`, or `None` if the in-degree is not 1.
fn single_predecessor(addr: Address, edges: &[CfgEdge]) -> Option<Address> {
    let preds: Vec<Address> = edges
        .iter()
        .filter(|e| e.to == addr)
        .map(|e| e.from)
        .collect();
    if preds.len() == 1 {
        Some(preds[0])
    } else {
        None
    }
}

/// Collect all blocks reachable from `entry` via BFS.
fn reachable(entry: Address, blocks: &HashMap<Address, BasicBlock>, edges: &[CfgEdge]) -> HashSet<Address> {
    let mut visited: HashSet<Address> = HashSet::new();
    let mut queue: VecDeque<Address> = VecDeque::new();
    if blocks.contains_key(&entry) {
        queue.push_back(entry);
        visited.insert(entry);
    }
    while let Some(node) = queue.pop_front() {
        for e in edges.iter().filter(|e| e.from == node) {
            if blocks.contains_key(&e.to) && visited.insert(e.to) {
                queue.push_back(e.to);
            }
        }
    }
    visited
}

// ─────────────────────────────────────────────────────────────────────────────
// CfgSimplifier
// ─────────────────────────────────────────────────────────────────────────────

/// Applies repeated local transformations to a [`ControlFlowGraph`] to produce
/// a simplified but semantically equivalent graph.
///
/// The simplifier performs three classes of transformation:
///
/// 1. **Dead-block elimination**: blocks not reachable from the entry are
///    removed along with all their edges.
/// 2. **Block merging**: if block A has exactly one outgoing edge to block B
///    and block B has exactly one incoming edge from A, merge them.
/// 3. **Jump threading**: if block B is empty (no instructions other than a
///    single unconditional jump) redirect its predecessors directly to B's
///    successor, then remove B.
#[derive(Debug, Clone)]
pub struct CfgSimplifier {
    /// Maximum number of full simplification rounds before giving up.
    pub max_rounds: usize,
    /// If `true`, perform jump threading in addition to merging.
    pub enable_threading: bool,
    /// If `true`, eliminate dead (unreachable) blocks.
    pub eliminate_dead: bool,
}

impl Default for CfgSimplifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CfgSimplifier {
    /// Create a simplifier with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_rounds: 64,
            enable_threading: true,
            eliminate_dead: true,
        }
    }

    /// Run all enabled passes until convergence or `max_rounds` is reached.
    ///
    /// Returns the accumulated [`SimplifyResult`] for the whole session.
    #[must_use]
    pub fn simplify(&self, cfg: &mut ControlFlowGraph) -> SimplifyResult {
        let mut total = SimplifyResult::zero();
        for _ in 0..self.max_rounds {
            let pass = self.single_pass(cfg);
            let changed = pass.changed;
            total = total.combine(&pass);
            if !changed {
                break;
            }
        }
        // Recompute derived fields after simplification.
        recompute_derived(cfg);
        total
    }

    /// Execute one full pass: dead elimination, then merging, then threading.
    fn single_pass(&self, cfg: &mut ControlFlowGraph) -> SimplifyResult {
        let mut result = SimplifyResult::zero();

        if self.eliminate_dead {
            let r = eliminate_dead_blocks(cfg);
            result = result.combine(&r);
        }

        let r = merge_blocks(cfg);
        result = result.combine(&r);

        if self.enable_threading {
            let r = thread_empty_blocks(cfg);
            result = result.combine(&r);
        }

        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// merge_blocks  (public)
// ─────────────────────────────────────────────────────────────────────────────

/// Merge all eligible block pairs in `cfg` and return a [`SimplifyResult`].
///
/// A merge removes the successor block and extends the predecessor's
/// instruction list with the successor's instructions.  After merging, all
/// edges that previously pointed to the successor are redirected to the
/// predecessor.
pub fn merge_blocks(cfg: &mut ControlFlowGraph) -> SimplifyResult {
    let mut result = SimplifyResult::zero();
    loop {
        let candidates = find_merge_candidates(cfg);
        if candidates.is_empty() {
            break;
        }
        for c in &candidates {
            if apply_merge(cfg, c) {
                result.merges += 1;
                result.changed = true;
            }
        }
        // If none applied (already merged or stale), stop.
        if result.merges == 0 && !result.changed {
            break;
        }
        // We might have created new candidates; iterate.
    }
    result
}

/// Find all current merge candidates in `cfg`.
#[must_use]
pub fn find_merge_candidates(cfg: &ControlFlowGraph) -> Vec<MergeCandidate> {
    let mut candidates = Vec::new();
    for &addr in cfg.blocks.keys() {
        if addr == cfg.entry {
            continue;
        }
        if let Some(pred) = single_predecessor(addr, &cfg.edges)
            && (pred == cfg.entry || pred != addr)
                && let Some(succ_of_pred) = single_successor(pred, &cfg.edges)
                    && succ_of_pred == addr && pred != addr {
                        candidates.push(MergeCandidate::new(pred, addr));
                    }
    }
    // Deduplicate (ordering may vary).
    candidates.sort_by(|a, b| a.pred.0.cmp(&b.pred.0).then(a.succ.0.cmp(&b.succ.0)));
    candidates.dedup();
    candidates
}

/// Apply a single merge, returning `true` if the merge was performed.
fn apply_merge(cfg: &mut ControlFlowGraph, c: &MergeCandidate) -> bool {
    // Guard: both blocks must still exist and the candidate must still be valid.
    if !cfg.blocks.contains_key(&c.pred) || !cfg.blocks.contains_key(&c.succ) {
        return false;
    }
    if single_successor(c.pred, &cfg.edges) != Some(c.succ) {
        return false;
    }
    if single_predecessor(c.succ, &cfg.edges) != Some(c.pred) {
        return false;
    }

    // Take the successor's instructions.
    let succ_block = cfg.blocks.remove(&c.succ).expect("succ must exist");
    let pred_block = cfg.blocks.get_mut(&c.pred).expect("pred must exist");

    // Extend predecessor instructions with successor instructions.
    pred_block.instructions.extend(succ_block.instructions);
    pred_block.end = succ_block.end;

    // Remove edges from pred→succ and from succ→*.
    cfg.edges.retain(|e| !(e.from == c.pred && e.to == c.succ));
    // Collect edges that came out of succ.
    let out_edges: Vec<CfgEdge> = cfg
        .edges
        .iter()
        .filter(|e| e.from == c.succ)
        .cloned()
        .collect();
    cfg.edges.retain(|e| e.from != c.succ);

    // Re-add them as if they came from pred.
    for mut e in out_edges {
        e.from = c.pred;
        cfg.edges.push(e);
    }

    true
}

// ─────────────────────────────────────────────────────────────────────────────
// eliminate_dead_blocks
// ─────────────────────────────────────────────────────────────────────────────

fn eliminate_dead_blocks(cfg: &mut ControlFlowGraph) -> SimplifyResult {
    let live = reachable(cfg.entry, &cfg.blocks, &cfg.edges);
    let all: Vec<Address> = cfg.blocks.keys().copied().collect();
    let mut removed = 0;
    for addr in all {
        if !live.contains(&addr) {
            cfg.blocks.remove(&addr);
            cfg.edges.retain(|e| e.from != addr && e.to != addr);
            removed += 1;
        }
    }
    SimplifyResult {
        dead_blocks_removed: removed,
        changed: removed > 0,
        ..SimplifyResult::zero()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// thread_empty_blocks
// ─────────────────────────────────────────────────────────────────────────────

/// A block is "empty" (threadable) when it contains no instructions (or only
/// a single unconditional jump) and has exactly one outgoing edge.
fn is_threadable(addr: Address, cfg: &ControlFlowGraph) -> bool {
    if addr == cfg.entry {
        return false;
    }
    let block = match cfg.blocks.get(&addr) {
        Some(b) => b,
        None => return false,
    };
    // The block must be instruction-free, or contain only `Nop`s optionally
    // followed by a single unconditional-jump terminator (the "jump
    // placeholder" case described above). Previously this only recognised
    // all-`Nop` blocks, so a block that legitimately compiled down to just
    // an unconditional jump (the common case for a threadable block) was
    // never threaded because its terminator instruction was neither
    // `Nop` nor absent.
    let n = block.instructions.len();
    let trivial = block.instructions.iter().enumerate().all(|(idx, i)| {
        matches!(i, LlilInstruction::Nop)
            || (idx + 1 == n
                && matches!(
                    i,
                    LlilInstruction::JumpDest { .. } | LlilInstruction::Jump(_)
                ))
    });
    trivial && out_degree(addr, &cfg.edges) == 1
}

fn thread_empty_blocks(cfg: &mut ControlFlowGraph) -> SimplifyResult {
    let mut threaded = 0;
    loop {
        let threadable: Vec<Address> = cfg
            .blocks
            .keys()
            .copied()
            .filter(|&a| is_threadable(a, cfg))
            .collect();
        if threadable.is_empty() {
            break;
        }
        let mut any = false;
        for addr in threadable {
            // Find the single successor.
            let target = match single_successor(addr, &cfg.edges) {
                Some(t) => t,
                None => continue,
            };
            if target == addr {
                continue; // self-loop; skip
            }

            // Redirect all predecessors of `addr` to `target`.
            let preds: Vec<Address> = cfg
                .edges
                .iter()
                .filter(|e| e.to == addr)
                .map(|e| e.from)
                .collect();

            // Remove all edges touching `addr`.
            cfg.edges.retain(|e| e.from != addr && e.to != addr);

            // Add new edges from each predecessor directly to target.
            for pred in preds {
                // Determine edge kind: use Unconditional since we're threading
                // a trivially-straight block.
                cfg.edges.push(CfgEdge {
                    from: pred,
                    to: target,
                    kind: EdgeKind::Unconditional,
                });
            }

            // Remove the now-orphaned block.
            cfg.blocks.remove(&addr);
            threaded += 1;
            any = true;
        }
        if !any {
            break;
        }
    }
    SimplifyResult {
        threaded_blocks: threaded,
        changed: threaded > 0,
        ..SimplifyResult::zero()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// recompute_derived — rebuild dom tree, post-dom tree, loops after edits
// ─────────────────────────────────────────────────────────────────────────────

fn recompute_derived(cfg: &mut ControlFlowGraph) {
    let dom = DominatorTree::compute(&cfg.blocks, &cfg.edges, cfg.entry);
    let post_dom = PostDominatorTree::compute(&cfg.blocks, &cfg.edges);
    cfg.dom_tree = dom;
    cfg.post_dom_tree = post_dom;
    cfg.loops = crate::find_natural_loops(cfg);
}

// ─────────────────────────────────────────────────────────────────────────────
// SimplifierStats  — summary across multiple functions
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated simplification statistics across a batch of functions.
#[derive(Debug, Clone, Default)]
pub struct SimplifierStats {
    /// Total number of block merges performed.
    pub total_merges: usize,
    /// Total number of dead blocks removed.
    pub total_dead_removed: usize,
    /// Total number of empty blocks threaded.
    pub total_threaded: usize,
    /// Number of functions that were changed at all.
    pub functions_changed: usize,
    /// Number of functions processed.
    pub functions_total: usize,
}

impl SimplifierStats {
    /// Incorporate the result from one function.
    pub const fn record(&mut self, result: &SimplifyResult) {
        self.total_merges += result.merges;
        self.total_dead_removed += result.dead_blocks_removed;
        self.total_threaded += result.threaded_blocks;
        self.functions_total += 1;
        if result.changed {
            self.functions_changed += 1;
        }
    }

    /// Fraction of functions changed (0.0 if none processed).
    #[must_use]
    pub fn change_rate(&self) -> f64 {
        if self.functions_total == 0 {
            0.0
        } else {
            self.functions_changed as f64 / self.functions_total as f64
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BlockMergePlan — offline plan before committing mutations
// ─────────────────────────────────────────────────────────────────────────────

/// A pre-computed plan for merging a set of candidate pairs.
///
/// Used when the caller wants to inspect what would happen before committing
/// mutations (e.g., for logging or approval gates).
#[derive(Debug, Clone)]
pub struct BlockMergePlan {
    /// The ordered list of merges to apply.
    pub merges: Vec<MergeCandidate>,
    /// Estimated block count after the plan is applied.
    pub estimated_block_count: usize,
}

impl BlockMergePlan {
    /// Build a plan from a CFG without modifying it.
    #[must_use]
    pub fn build(cfg: &ControlFlowGraph) -> Self {
        let merges = find_merge_candidates(cfg);
        let estimated_block_count = cfg.blocks.len().saturating_sub(merges.len());
        Self {
            merges,
            estimated_block_count,
        }
    }

    /// Apply the plan to `cfg`, consuming the plan.
    pub fn apply(self, cfg: &mut ControlFlowGraph) -> SimplifyResult {
        let mut result = SimplifyResult::zero();
        for c in &self.merges {
            if apply_merge(cfg, c) {
                result.merges += 1;
                result.changed = true;
            }
        }
        if result.changed {
            recompute_derived(cfg);
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChainCollapser  — collapse long chains into single blocks
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies maximal straight-line chains (paths with no branching) in the
/// CFG and returns them as a list of ordered block sequences.
///
/// A chain is a maximal sequence `[b0, b1, …, bN]` where:
/// - `out_degree(bi) == 1` for `i < N`.
/// - `in_degree(bi+1) == 1` for `i < N`.
/// - All blocks are distinct.
#[must_use]
pub fn find_chains(cfg: &ControlFlowGraph) -> Vec<Vec<Address>> {
    // A block is a chain *head* if it has in-degree != 1 or is the entry.
    // `cfg.blocks` is a HashMap; sort so the returned chain list (and the
    // merge order `collapse_chains` derives from it) is deterministic
    // instead of reflecting hash-iteration order.
    let mut heads: Vec<Address> = cfg
        .blocks
        .keys()
        .copied()
        .filter(|&a| a == cfg.entry || in_degree(a, &cfg.edges) != 1)
        .collect();
    heads.sort_by_key(|a| a.0);

    let mut chains = Vec::new();

    for head in heads {
        let mut chain = vec![head];
        let mut cur = head;
        loop {
            if out_degree(cur, &cfg.edges) != 1 {
                break;
            }
            let next = match single_successor(cur, &cfg.edges) {
                Some(n) => n,
                None => break,
            };
            if in_degree(next, &cfg.edges) != 1 || next == head {
                break;
            }
            chain.push(next);
            cur = next;
        }
        if chain.len() > 1 {
            chains.push(chain);
        }
    }

    chains
}

/// Collapse all identified straight-line chains in `cfg` into single blocks.
///
/// Returns the number of chains collapsed.
pub fn collapse_chains(cfg: &mut ControlFlowGraph) -> usize {
    let chains = find_chains(cfg);
    let mut collapsed = 0;
    for chain in &chains {
        // Merge chain[0] with chain[1..] sequentially.
        for i in 1..chain.len() {
            let c = MergeCandidate::new(chain[0], chain[i]);
            if apply_merge(cfg, &c) {
                collapsed += 1;
            }
        }
    }
    if collapsed > 0 {
        recompute_derived(cfg);
    }
    collapsed
}

// ─────────────────────────────────────────────────────────────────────────────
// ReachabilityMap  — block-level reachability query
// ─────────────────────────────────────────────────────────────────────────────

/// A precomputed forward-reachability map for the CFG.
///
/// `can_reach(a, b)` answers "does a path from `a` to `b` exist in the CFG?"
/// in O(1) after O(n²) preprocessing.
#[derive(Debug, Clone)]
pub struct ReachabilityMap {
    /// `matrix[from][to]` — precomputed via multi-source BFS.
    matrix: HashMap<Address, HashSet<Address>>,
}

impl ReachabilityMap {
    /// Build the reachability map for `cfg` (forward reachability from each block).
    #[must_use]
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let mut matrix: HashMap<Address, HashSet<Address>> = HashMap::new();
        for &start in cfg.blocks.keys() {
            let r = reachable(start, &cfg.blocks, &cfg.edges);
            matrix.insert(start, r);
        }
        Self { matrix }
    }

    /// Return `true` if `from` can reach `to` in the CFG.
    #[must_use]
    pub fn can_reach(&self, from: Address, to: Address) -> bool {
        self.matrix
            .get(&from)
            .is_some_and(|s| s.contains(&to))
    }

    /// All blocks reachable from `from`.
    #[must_use]
    pub fn reachable_from(&self, from: Address) -> &HashSet<Address> {
        static EMPTY: std::sync::OnceLock<HashSet<Address>> = std::sync::OnceLock::new();
        self.matrix
            .get(&from)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SimplifyConfig  — builder pattern for CfgSimplifier
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for [`CfgSimplifier`] with a fluent API.
#[derive(Debug, Clone)]
pub struct SimplifyConfig {
    inner: CfgSimplifier,
}

impl Default for SimplifyConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl SimplifyConfig {
    /// Start with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: CfgSimplifier::new(),
        }
    }

    /// Set the maximum number of simplification rounds.
    #[must_use]
    pub const fn max_rounds(mut self, n: usize) -> Self {
        self.inner.max_rounds = n;
        self
    }

    /// Enable or disable jump threading.
    #[must_use]
    pub const fn threading(mut self, enable: bool) -> Self {
        self.inner.enable_threading = enable;
        self
    }

    /// Enable or disable dead-block elimination.
    #[must_use]
    pub const fn dead_elimination(mut self, enable: bool) -> Self {
        self.inner.eliminate_dead = enable;
        self
    }

    /// Finish building and return the [`CfgSimplifier`].
    #[must_use]
    pub const fn build(self) -> CfgSimplifier {
        self.inner
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BasicBlock, CfgEdge, ControlFlowGraph, DominatorTree, EdgeKind, PostDominatorTree};
    use rustre_core::address::Address;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    fn make_cfg(
        blocks: Vec<(u64, Vec<rustre_il_llil::LlilInstruction>)>,
        edges: Vec<(u64, u64, EdgeKind)>,
        entry: u64,
    ) -> ControlFlowGraph {
        let block_map: HashMap<Address, BasicBlock> = blocks
            .into_iter()
            .map(|(a, instrs)| {
                let address = addr(a);
                (
                    address,
                    BasicBlock {
                        start: address,
                        end: address,
                        instructions: instrs,
                    },
                )
            })
            .collect();
        let edge_vec: Vec<CfgEdge> = edges
            .into_iter()
            .map(|(f, t, k)| CfgEdge {
                from: addr(f),
                to: addr(t),
                kind: k,
            })
            .collect();
        let entry_addr = addr(entry);
        let dom = DominatorTree::compute(&block_map, &edge_vec, entry_addr);
        let post_dom = PostDominatorTree::compute(&block_map, &edge_vec);
        let mut cfg = ControlFlowGraph {
            blocks: block_map,
            edges: edge_vec,
            entry: entry_addr,
            dom_tree: dom,
            post_dom_tree: post_dom,
            loops: vec![],
        };
        cfg.loops = crate::find_natural_loops(&cfg);
        cfg
    }

    #[test]
    fn test_merge_linear_chain() {
        // 0 → 1 → 2  (both edges unconditional, each block has unique pred/succ)
        let cfg = &mut make_cfg(
            vec![(0, vec![]), (1, vec![]), (2, vec![])],
            vec![(0, 1, EdgeKind::Unconditional), (1, 2, EdgeKind::Unconditional)],
            0,
        );
        let result = merge_blocks(cfg);
        // After merging: 0 absorbs 1, then 0 absorbs 2 → single block.
        assert!(result.merges >= 1);
    }

    #[test]
    fn test_no_merge_diamond() {
        // 0 → {1, 2} → 3: block 1 and 2 each have two in-edges at 3.
        let cfg = &mut make_cfg(
            vec![(0, vec![]), (1, vec![]), (2, vec![]), (3, vec![])],
            vec![
                (0, 1, EdgeKind::TrueBranch),
                (0, 2, EdgeKind::FalseBranch),
                (1, 3, EdgeKind::Unconditional),
                (2, 3, EdgeKind::Unconditional),
            ],
            0,
        );
        let result = merge_blocks(cfg);
        // No merges: 3 has two predecessors, 0 has two successors.
        assert_eq!(result.merges, 0);
    }

    #[test]
    fn test_dead_block_elimination() {
        // 0 → 1, block 2 is unreachable.
        let cfg = &mut make_cfg(
            vec![(0, vec![]), (1, vec![]), (2, vec![])],
            vec![(0, 1, EdgeKind::Unconditional)],
            0,
        );
        let result = eliminate_dead_blocks(cfg);
        assert_eq!(result.dead_blocks_removed, 1);
        assert!(!cfg.blocks.contains_key(&addr(2)));
    }

    #[test]
    fn test_find_chains() {
        let cfg = make_cfg(
            vec![(0, vec![]), (1, vec![]), (2, vec![])],
            vec![(0, 1, EdgeKind::Unconditional), (1, 2, EdgeKind::Unconditional)],
            0,
        );
        let chains = find_chains(&cfg);
        assert!(!chains.is_empty());
        // The chain starting from 0 should include at least 0,1,2.
        let long_chain = chains.iter().find(|c| c.len() >= 2);
        assert!(long_chain.is_some());
    }

    #[test]
    fn test_reachability_map() {
        let cfg = make_cfg(
            vec![(0, vec![]), (1, vec![]), (2, vec![])],
            vec![(0, 1, EdgeKind::Unconditional), (1, 2, EdgeKind::Unconditional)],
            0,
        );
        let rm = ReachabilityMap::compute(&cfg);
        assert!(rm.can_reach(addr(0), addr(2)));
        assert!(!rm.can_reach(addr(2), addr(0)));
    }

    #[test]
    fn test_simplify_config_builder() {
        let s = SimplifyConfig::new()
            .max_rounds(10)
            .threading(false)
            .dead_elimination(true)
            .build();
        assert_eq!(s.max_rounds, 10);
        assert!(!s.enable_threading);
        assert!(s.eliminate_dead);
    }

    #[test]
    fn test_simplifier_stats_change_rate() {
        let mut stats = SimplifierStats::default();
        let r1 = SimplifyResult {
            merges: 2,
            dead_blocks_removed: 0,
            threaded_blocks: 0,
            changed: true,
        };
        let r2 = SimplifyResult {
            merges: 0,
            dead_blocks_removed: 0,
            threaded_blocks: 0,
            changed: false,
        };
        stats.record(&r1);
        stats.record(&r2);
        assert_eq!(stats.functions_total, 2);
        assert_eq!(stats.functions_changed, 1);
        assert!((stats.change_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_thread_block_with_actual_jump_instruction() {
        // 0 -> 1 -> 2, where block 1's only instruction is a real
        // unconditional-jump terminator (not a `Nop`). This is the common
        // real-world "empty" block shape and must be threaded away just
        // like an all-`Nop` block.
        use rustre_il_llil::{Size, llil_const};
        let jump_instr = LlilInstruction::JumpDest {
            dest: llil_const(2, Size::QWord),
        };
        let cfg = &mut make_cfg(
            vec![(0, vec![]), (1, vec![jump_instr]), (2, vec![])],
            vec![
                (0, 1, EdgeKind::Unconditional),
                (1, 2, EdgeKind::Unconditional),
            ],
            0,
        );
        assert!(is_threadable(addr(1), cfg));
        let result = thread_empty_blocks(cfg);
        assert_eq!(result.threaded_blocks, 1);
        assert!(!cfg.blocks.contains_key(&addr(1)));
        // Block 0 should now point directly at block 2.
        assert!(
            cfg.edges
                .iter()
                .any(|e| e.from == addr(0) && e.to == addr(2))
        );
    }

    #[test]
    fn test_merge_plan_build() {
        let cfg = make_cfg(
            vec![(0, vec![]), (1, vec![])],
            vec![(0, 1, EdgeKind::Unconditional)],
            0,
        );
        let plan = BlockMergePlan::build(&cfg);
        // 0→1: 1 has one predecessor (0), 0 has one successor (1) → candidate.
        assert!(!plan.merges.is_empty());
    }
}
