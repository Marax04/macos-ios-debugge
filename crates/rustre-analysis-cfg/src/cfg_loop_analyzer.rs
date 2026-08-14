//! Loop structure analysis for control flow graphs.
//!
//! This module provides [`CfgLoopAnalyzer`] which identifies all loops in a
//! CFG, classifies them by [`LoopKind`], builds the [`LoopNest`] nesting tree,
//! and exposes helpers for querying loop membership and exit edges.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::{ControlFlowGraph, DominatorTree};
use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// LoopKind
// ─────────────────────────────────────────────────────────────────────────────

/// High-level classification of a natural loop's iteration structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoopKind {
    /// A `while`-style loop: the condition is tested at the header before
    /// any body instruction executes.  The header has two successors, one of
    /// which exits the loop.
    WhileLoop,
    /// A `do-while`-style loop: the body executes at least once before the
    /// condition is checked.  The back-edge source is the block that contains
    /// the condition.
    DoWhileLoop,
    /// A counted loop whose induction variable can be statically bounded
    /// (best-effort detection from CFG shape alone).
    CountedLoop,
    /// An infinite loop with no statically-visible exit edge.
    InfiniteLoop,
    /// An irreducible loop (multiple headers; cannot be represented with a
    /// single back edge).
    Irreducible,
    /// The loop kind could not be determined from the CFG shape alone.
    Unknown,
}

impl std::fmt::Display for LoopKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WhileLoop => write!(f, "while"),
            Self::DoWhileLoop => write!(f, "do-while"),
            Self::CountedLoop => write!(f, "counted"),
            Self::InfiniteLoop => write!(f, "infinite"),
            Self::Irreducible => write!(f, "irreducible"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loop
// ─────────────────────────────────────────────────────────────────────────────

/// A single loop identified in the CFG.
#[derive(Debug, Clone)]
pub struct Loop {
    /// Unique identifier for this loop (index into the analyzer's loop list).
    pub id: usize,
    /// The loop header block (target of all back edges into this loop).
    pub header: Address,
    /// All back-edge source blocks (latches).
    pub latches: Vec<Address>,
    /// All blocks in the loop body, including the header.
    pub body: HashSet<Address>,
    /// Blocks outside the loop that are direct successors of loop blocks.
    pub exit_targets: Vec<Address>,
    /// The block(s) inside the loop whose successor(s) include `exit_targets`.
    pub exit_sources: Vec<Address>,
    /// Classified loop kind.
    pub kind: LoopKind,
    /// Nesting depth (0 = outermost).
    pub depth: u32,
    /// Index of the immediately enclosing loop, if any.
    pub parent: Option<usize>,
    /// Indices of directly nested (child) loops.
    pub children: Vec<usize>,
}

impl Loop {
    /// Return `true` if `addr` is part of this loop's body.
    #[must_use]
    pub fn contains(&self, addr: Address) -> bool {
        self.body.contains(&addr)
    }

    /// Number of blocks in the loop body.
    #[must_use]
    pub fn body_size(&self) -> usize {
        self.body.len()
    }

    /// Return `true` if this loop has no inner loops (leaf in the nest tree).
    #[must_use]
    pub const fn is_innermost(&self) -> bool {
        self.children.is_empty()
    }

    /// Return `true` if this loop has no enclosing loop (root in the nest tree).
    #[must_use]
    pub const fn is_outermost(&self) -> bool {
        self.parent.is_none()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopNest
// ─────────────────────────────────────────────────────────────────────────────

/// The loop nesting forest for a single function's CFG.
///
/// Loops are stored in the order they were discovered.  The nesting
/// relationships are encoded via the `parent` and `children` fields of each
/// [`Loop`].
#[derive(Debug, Clone)]
pub struct LoopNest {
    /// All loops identified in the CFG, ordered by discovery.
    pub loops: Vec<Loop>,
    /// Indices of top-level (outermost) loops.
    pub roots: Vec<usize>,
}

impl LoopNest {
    /// Return `true` if there are no loops.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.loops.is_empty()
    }

    /// Number of loops.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.loops.len()
    }

    /// Return the loop (if any) that most-tightly contains `addr`.
    ///
    /// "Most-tightly" means the loop with the greatest nesting depth whose
    /// body includes `addr`.
    #[must_use]
    pub fn innermost_loop_for(&self, addr: Address) -> Option<&Loop> {
        self.loops
            .iter()
            .filter(|l| l.contains(addr))
            .max_by_key(|l| l.depth)
    }

    /// Collect all loops that contain `addr`, from outermost to innermost.
    #[must_use]
    pub fn loops_containing(&self, addr: Address) -> Vec<&Loop> {
        let mut containing: Vec<&Loop> = self
            .loops
            .iter()
            .filter(|l| l.contains(addr))
            .collect();
        containing.sort_by_key(|l| l.depth);
        containing
    }

    /// Maximum nesting depth across all loops.
    #[must_use]
    pub fn max_depth(&self) -> u32 {
        self.loops.iter().map(|l| l.depth).max().unwrap_or(0)
    }

    /// Iterate over loops in pre-order (parents before children).
    #[must_use]
    pub fn pre_order(&self) -> Vec<&Loop> {
        let mut result = Vec::new();
        let mut stack: Vec<usize> = self.roots.iter().rev().copied().collect();
        while let Some(idx) = stack.pop() {
            let lp = &self.loops[idx];
            result.push(lp);
            for &child in lp.children.iter().rev() {
                stack.push(child);
            }
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfgLoopAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Analyzes the loop structure of a control flow graph.
///
/// The analysis proceeds in three phases:
/// 1. **Back-edge discovery**: find all edges `(latch, header)` where
///    `header` dominates `latch`.
/// 2. **Body computation**: for each back-edge group with the same header,
///    collect body blocks via reverse BFS from the latches up to the header.
/// 3. **Classification**: apply heuristics to assign a [`LoopKind`].
/// 4. **Nesting**: build the parent/child nesting structure.
#[derive(Debug, Clone, Default)]
pub struct CfgLoopAnalyzer {
    /// If `true`, merge loops sharing the same header into one entry.
    pub merge_shared_headers: bool,
}

impl CfgLoopAnalyzer {
    /// Create a new analyzer with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            merge_shared_headers: true,
        }
    }

    /// Run the loop analysis on `cfg` and return the [`LoopNest`].
    #[must_use]
    pub fn analyze(&self, cfg: &ControlFlowGraph) -> LoopNest {
        find_loops(cfg, self.merge_shared_headers)
    }

    /// Run the loop analysis using an externally supplied [`DominatorTree`].
    ///
    /// This is useful when callers have already computed a dominator tree
    /// (e.g. via [`crate::cfg_dominators::LengauerTarjanDominator`]) and want
    /// to reuse it instead of relying on `cfg.dom_tree`. The supplied tree
    /// must match the topology of `cfg`.
    #[must_use]
    pub fn analyze_with_dom(
        &self,
        cfg: &ControlFlowGraph,
        dom_tree: &DominatorTree,
    ) -> LoopNest {
        find_loops_with_dom(cfg, dom_tree, self.merge_shared_headers)
    }
}

/// Identify natural loops in `cfg` using an externally provided dominator tree.
///
/// Mirrors [`find_loops`] but routes all `dominates`/`depth` queries through
/// `dom_tree` rather than `cfg.dom_tree`.
#[must_use]
pub fn find_loops_with_dom(
    cfg: &ControlFlowGraph,
    dom_tree: &DominatorTree,
    merge_shared_headers: bool,
) -> LoopNest {
    // Bug fix (iteration 6): previously this function computed
    // `header_to_latches` from the supplied `dom_tree` purely to decide
    // whether to early-return, then unconditionally delegated to
    // `find_loops(cfg, merge_shared_headers)`, which recomputes everything
    // from `cfg.dom_tree` instead. Whenever the caller's `dom_tree` differs
    // from `cfg.dom_tree` (e.g. a caller-maintained/incrementally-updated
    // dominator tree that hasn't been written back into `cfg`), the back-edge
    // detection and `classify_loop`'s irreducibility depth check silently
    // used the wrong (stale or simply different) dominator tree, producing
    // incorrect loop headers/latches/kinds with no error. `dom_tree` is now
    // threaded through the whole computation via `find_loops_impl`.
    find_loops_impl(cfg, dom_tree, merge_shared_headers)
}

// ─────────────────────────────────────────────────────────────────────────────
// find_loops  (public entry point)
// ─────────────────────────────────────────────────────────────────────────────

/// Identify all natural loops in `cfg` and build a [`LoopNest`].
///
/// When `merge_shared_headers` is `true`, multiple back edges to the same
/// header are merged into a single [`Loop`] with multiple `latches`.
#[must_use]
pub fn find_loops(cfg: &ControlFlowGraph, merge_shared_headers: bool) -> LoopNest {
    find_loops_impl(cfg, &cfg.dom_tree, merge_shared_headers)
}

/// Shared implementation behind [`find_loops`] and [`find_loops_with_dom`].
///
/// Always uses `dom_tree` for every dominance/depth query, never
/// `cfg.dom_tree` directly, so the two public entry points cannot diverge.
fn find_loops_impl(
    cfg: &ControlFlowGraph,
    dom_tree: &DominatorTree,
    merge_shared_headers: bool,
) -> LoopNest {
    if cfg.blocks.is_empty() {
        return LoopNest { loops: vec![], roots: vec![] };
    }

    // ── 1. Collect back edges ───────────────────────────────────────────────
    // Group latches by header.
    let mut header_to_latches: HashMap<Address, Vec<Address>> = HashMap::new();
    for edge in &cfg.edges {
        if dom_tree.dominates(edge.to, edge.from) {
            // edge.to is the header, edge.from is the latch.
            header_to_latches
                .entry(edge.to)
                .or_default()
                .push(edge.from);
        }
    }

    if header_to_latches.is_empty() {
        return LoopNest { loops: vec![], roots: vec![] };
    }

    // ── 2. Build loop bodies ────────────────────────────────────────────────
    // Build the predecessor and successor adjacency maps once. Previously
    // `compute_loop_body` rebuilt a full predecessor `HashMap` from
    // `cfg.edges` on every call (once per loop header), making the whole
    // pass O(H*E). `collect_exit_sources`/`collect_exit_targets`/
    // `classify_loop` also each re-scanned `cfg.edges` with `.iter().filter`
    // per loop/header. Hoisting both maps here and threading them through
    // makes the pass O(H + E) overall.
    let mut preds: HashMap<Address, Vec<Address>> = HashMap::new();
    let mut succs: HashMap<Address, Vec<Address>> = HashMap::new();
    for e in &cfg.edges {
        preds.entry(e.to).or_default().push(e.from);
        succs.entry(e.from).or_default().push(e.to);
    }

    let mut raw_loops: Vec<(Address, Vec<Address>, HashSet<Address>)> = Vec::new();

    // `header_to_latches` is a HashMap, so iterating it directly (as this
    // used to) visits headers in nondeterministic hash order. The
    // size-only sort below is stable, so any two loops with the same body
    // size would keep that nondeterministic relative order, leaking into
    // `Loop::id` and `LoopNest.roots`/`children` ordering. Sort headers by
    // address first so the traversal itself is deterministic.
    let mut headers: Vec<&Address> = header_to_latches.keys().collect();
    headers.sort_by_key(|a| a.0);
    for header in headers {
        let latches = &header_to_latches[header];
        let body = compute_loop_body(*header, latches, &preds);
        if merge_shared_headers {
            raw_loops.push((*header, latches.clone(), body));
        } else {
            // One loop per latch.
            for &latch in latches {
                let single_body = compute_loop_body(*header, &[latch], &preds);
                raw_loops.push((*header, vec![latch], single_body));
            }
        }
    }

    // ── 3. Sort by body size (smallest first) for stable nesting detection ──
    // Secondary key on `header.0` makes ties deterministic (see note above).
    raw_loops.sort_by_key(|(header, _, body)| (body.len(), header.0));

    // ── 4. Build Loop structs with classification ───────────────────────────
    let n = raw_loops.len();
    let mut loops: Vec<Loop> = raw_loops
        .into_iter()
        .enumerate()
        .map(|(id, (header, latches, body))| {
            let exit_sources = collect_exit_sources(&body, &succs);
            let exit_targets = collect_exit_targets(&body, &succs);
            let kind = classify_loop(header, &latches, &body, &exit_targets, dom_tree, &succs);
            Loop {
                id,
                header,
                latches,
                body,
                exit_targets,
                exit_sources,
                kind,
                depth: 0,
                parent: None,
                children: vec![],
            }
        })
        .collect();

    // ── 5. Build nesting relationships ─────────────────────────────────────
    // Loop i is nested inside loop j if i.body ⊂ j.body (and i != j).
    // We find the *tightest* parent: the loop j with the smallest body that
    // strictly contains loop i.
    for i in 0..n {
        let mut best_parent: Option<usize> = None;
        let mut best_size = usize::MAX;
        for j in 0..n {
            if i == j {
                continue;
            }
            // Check if loops[i].body ⊂ loops[j].body — STRICTLY, as the comment
            // above says. Testing only ⊆ meant that two loops with identical
            // bodies (same header reached by two back edges, which is exactly
            // what `merge_shared_headers: false` produces) each became the
            // other's parent. `roots` is then empty, the depth BFS never
            // starts, every depth stays 0 and `pre_order()` returns nothing —
            // the whole loop forest disappears.
            // `body` is a HashSet, so subset + strictly larger cardinality is
            // exactly proper containment. The sibling implementations
            // (`NaturalLoop::is_nested_in`, `contains_loop`) avoid the same
            // trap by requiring distinct headers.
            let i_in_j = loops[i].body.len() < loops[j].body.len()
                && loops[i].body.iter().all(|a| loops[j].body.contains(a));
            if i_in_j && loops[j].body.len() < best_size {
                best_size = loops[j].body.len();
                best_parent = Some(j);
            }
        }
        loops[i].parent = best_parent;
    }

    // Fill in children (reverse of parent).
    for i in 0..n {
        if let Some(p) = loops[i].parent {
            loops[p].children.push(i);
        }
    }

    // Assign depths (BFS from roots).
    let roots: Vec<usize> = (0..n).filter(|&i| loops[i].parent.is_none()).collect();
    let mut depth_queue: VecDeque<(usize, u32)> =
        roots.iter().map(|&i| (i, 0)).collect();
    while let Some((idx, depth)) = depth_queue.pop_front() {
        loops[idx].depth = depth;
        for &child in &loops[idx].children.clone() {
            depth_queue.push_back((child, depth + 1));
        }
    }

    LoopNest { loops, roots }
}

// ─────────────────────────────────────────────────────────────────────────────
// Body / exit helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the loop body via reverse BFS from `latches` up to `header`.
///
/// `preds` is the predecessor adjacency map built once by the caller
/// (`find_loops`) from `cfg.edges`, shared across all loop headers instead
/// of being rebuilt per call.
fn compute_loop_body(
    header: Address,
    latches: &[Address],
    preds: &HashMap<Address, Vec<Address>>,
) -> HashSet<Address> {
    let mut body: HashSet<Address> = HashSet::new();
    body.insert(header);
    let mut worklist: VecDeque<Address> = VecDeque::new();

    for &latch in latches {
        if body.insert(latch) {
            worklist.push_back(latch);
        }
    }

    while let Some(node) = worklist.pop_front() {
        if node == header {
            continue;
        }
        for &pred in preds.get(&node).into_iter().flatten() {
            if body.insert(pred) {
                worklist.push_back(pred);
            }
        }
    }

    body
}

/// Collect the exit sources: loop blocks that have at least one successor
/// outside the loop.
///
/// `succs` is the successor adjacency map built once by `find_loops`,
/// avoiding a per-loop `cfg.edges.iter().filter(...)` scan.
fn collect_exit_sources(
    body: &HashSet<Address>,
    succs: &HashMap<Address, Vec<Address>>,
) -> Vec<Address> {
    let mut sources: Vec<Address> = body
        .iter()
        .filter(|&&b| {
            succs
                .get(&b)
                .is_some_and(|s| s.iter().any(|to| !body.contains(to)))
        })
        .copied()
        .collect();
    sources.sort_by_key(|a| a.0);
    sources
}

/// Collect the exit targets: blocks outside the loop that are successors of
/// loop blocks.
fn collect_exit_targets(
    body: &HashSet<Address>,
    succs: &HashMap<Address, Vec<Address>>,
) -> Vec<Address> {
    let mut targets: HashSet<Address> = HashSet::new();
    for &b in body {
        for &to in succs.get(&b).into_iter().flatten() {
            if !body.contains(&to) {
                targets.insert(to);
            }
        }
    }
    let mut v: Vec<Address> = targets.into_iter().collect();
    v.sort_by_key(|a| a.0);
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// classify_loop  — LoopKind heuristics
// ─────────────────────────────────────────────────────────────────────────────

fn classify_loop(
    header: Address,
    latches: &[Address],
    body: &HashSet<Address>,
    exit_targets: &[Address],
    dom_tree: &DominatorTree,
    succs: &HashMap<Address, Vec<Address>>,
) -> LoopKind {
    // Irreducible: multiple distinct headers (latches that are not dominated
    // by a single header).
    // We use a simple check: if any latch is not in the body dominated by header,
    // it could be irreducible.  For now we use the presence of >1 latch with
    // different DT depths as a heuristic.
    if latches.len() > 1 {
        let depths: HashSet<u32> = latches
            .iter()
            .map(|&l| dom_tree.depth(l))
            .collect();
        if depths.len() > 1 {
            return LoopKind::Irreducible;
        }
    }

    // Infinite: no exit targets.
    if exit_targets.is_empty() {
        return LoopKind::InfiniteLoop;
    }

    // Check header out-degree.
    let header_exits_count = succs
        .get(&header)
        .into_iter()
        .flatten()
        .filter(|s| !body.contains(s))
        .count();

    // while-loop: header directly exits the loop.
    if header_exits_count > 0 {
        // Further check: is there any induction-like pattern? (Simple heuristic:
        // if the body is small with exactly one latch, call it counted.)
        if body.len() <= 4 && latches.len() == 1 {
            return LoopKind::CountedLoop;
        }
        return LoopKind::WhileLoop;
    }

    // do-while: the back-edge latch has an exit edge.
    let latch_exits = latches.iter().any(|&l| {
        succs
            .get(&l)
            .is_some_and(|s| s.iter().any(|to| !body.contains(to)))
    });

    if latch_exits {
        return LoopKind::DoWhileLoop;
    }

    LoopKind::Unknown
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopMetrics  — per-loop metrics
// ─────────────────────────────────────────────────────────────────────────────

/// Metrics for a single loop.
#[derive(Debug, Clone)]
pub struct LoopMetrics {
    /// Number of blocks in the body.
    pub body_size: usize,
    /// Number of exit edges (edges leaving the loop body).
    pub exit_edge_count: usize,
    /// Number of back edges into this loop.
    pub back_edge_count: usize,
    /// Nesting depth.
    pub depth: u32,
    /// Classified kind.
    pub kind: LoopKind,
}

impl LoopMetrics {
    /// Compute metrics for a loop given the full CFG.
    #[must_use]
    pub fn compute(lp: &Loop, cfg: &ControlFlowGraph) -> Self {
        let exit_edge_count = cfg
            .edges
            .iter()
            .filter(|e| lp.body.contains(&e.from) && !lp.body.contains(&e.to))
            .count();
        let back_edge_count = lp.latches.len();
        Self {
            body_size: lp.body_size(),
            exit_edge_count,
            back_edge_count,
            depth: lp.depth,
            kind: lp.kind,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopSummary  — whole-function summary
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics for the loop structure of a function.
#[derive(Debug, Clone, Default)]
pub struct LoopSummary {
    /// Total loop count.
    pub total: usize,
    /// Deepest nesting level.
    pub max_depth: u32,
    /// Number of outermost loops.
    pub outermost_count: usize,
    /// Number of innermost (leaf) loops.
    pub innermost_count: usize,
    /// Number of while loops.
    pub while_count: usize,
    /// Number of do-while loops.
    pub do_while_count: usize,
    /// Number of counted loops.
    pub counted_count: usize,
    /// Number of infinite loops.
    pub infinite_count: usize,
    /// Number of irreducible loops.
    pub irreducible_count: usize,
}

impl LoopSummary {
    /// Build a summary from a [`LoopNest`].
    #[must_use]
    pub fn from_nest(nest: &LoopNest) -> Self {
        let mut s = Self::default();
        s.total = nest.len();
        s.max_depth = nest.max_depth();
        s.outermost_count = nest.roots.len();
        for lp in &nest.loops {
            if lp.is_innermost() {
                s.innermost_count += 1;
            }
            match lp.kind {
                LoopKind::WhileLoop => s.while_count += 1,
                LoopKind::DoWhileLoop => s.do_while_count += 1,
                LoopKind::CountedLoop => s.counted_count += 1,
                LoopKind::InfiniteLoop => s.infinite_count += 1,
                LoopKind::Irreducible => s.irreducible_count += 1,
                LoopKind::Unknown => {}
            }
        }
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopQuery  — query interface over a LoopNest
// ─────────────────────────────────────────────────────────────────────────────

/// Provides fast query operations over a [`LoopNest`].
#[derive(Debug, Clone)]
pub struct LoopQuery<'a> {
    nest: &'a LoopNest,
    /// Maps each block address to the indices of loops that contain it.
    membership: HashMap<Address, Vec<usize>>,
}

impl<'a> LoopQuery<'a> {
    /// Build the query index.
    #[must_use]
    pub fn build(nest: &'a LoopNest) -> Self {
        let mut membership: HashMap<Address, Vec<usize>> = HashMap::new();
        for (i, lp) in nest.loops.iter().enumerate() {
            for &addr in &lp.body {
                membership.entry(addr).or_default().push(i);
            }
        }
        Self { nest, membership }
    }

    /// Returns `true` if `addr` is inside any loop.
    #[must_use]
    pub fn is_in_loop(&self, addr: Address) -> bool {
        self.membership.contains_key(&addr)
    }

    /// Returns the nesting depth of `addr` (0 if not in any loop).
    #[must_use]
    pub fn depth_of(&self, addr: Address) -> u32 {
        self.membership
            .get(&addr)
            .and_then(|indices| indices.iter().map(|&i| self.nest.loops[i].depth).max())
            .unwrap_or(0)
    }

    /// Return the innermost loop containing `addr`, if any.
    #[must_use]
    pub fn innermost_for(&self, addr: Address) -> Option<&Loop> {
        self.membership
            .get(&addr)?
            .iter()
            .max_by_key(|&&i| self.nest.loops[i].depth)
            .map(|&i| &self.nest.loops[i])
    }

    /// Return all loops containing `addr` in order from outermost to innermost.
    #[must_use]
    pub fn all_loops_for(&self, addr: Address) -> Vec<&Loop> {
        let Some(indices) = self.membership.get(&addr) else {
            return vec![];
        };
        let mut loops: Vec<&Loop> = indices.iter().map(|&i| &self.nest.loops[i]).collect();
        loops.sort_by_key(|l| l.depth);
        loops
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
    use std::collections::HashMap;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    fn make_cfg(
        addrs: &[u64],
        edges: Vec<(u64, u64)>,
        entry: u64,
    ) -> ControlFlowGraph {
        let blocks: HashMap<Address, BasicBlock> = addrs
            .iter()
            .map(|&a| {
                let address = addr(a);
                (
                    address,
                    BasicBlock { start: address, end: address, instructions: vec![] },
                )
            })
            .collect();
        let edge_vec: Vec<CfgEdge> = edges
            .into_iter()
            .map(|(f, t)| CfgEdge {
                from: addr(f),
                to: addr(t),
                kind: EdgeKind::Unconditional,
            })
            .collect();
        let entry_addr = addr(entry);
        let dom = DominatorTree::compute(&blocks, &edge_vec, entry_addr);
        let post_dom = PostDominatorTree::compute(&blocks, &edge_vec);
        let mut cfg = ControlFlowGraph {
            blocks,
            edges: edge_vec,
            entry: entry_addr,
            dom_tree: dom,
            post_dom_tree: post_dom,
            loops: vec![],
        };
        cfg.loops = crate::find_natural_loops(&cfg);
        cfg
    }

    /// Regression test (iteration 6): `find_loops_with_dom` must honor the
    /// *supplied* `dom_tree`, not silently fall back to `cfg.dom_tree`.
    ///
    /// Uses the same block/edge set (0→1, 1→2, 2→1 back edge, 2→3) under two
    /// different dominator trees: `cfg.dom_tree`, computed from the real
    /// edges (where 1 dominates 2, so 2→1 is a genuine back edge), and an
    /// alternate `dom_tree` computed from an unrelated diamond edge set over
    /// the same addresses (0→1, 0→2, 1→3, 2→3) where 1 does *not* dominate 2.
    /// Under the alternate tree the 2→1 edge is not a back edge, so no loop
    /// should be found — proving the function actually consults `dom_tree`
    /// and does not recompute from `cfg.dom_tree`.
    #[test]
    fn test_find_loops_with_dom_uses_supplied_tree_not_cfg_dom_tree() {
        let cfg = make_cfg(
            &[0, 1, 2, 3],
            vec![(0, 1), (1, 2), (2, 1), (2, 3)],
            0,
        );

        // Sanity: the CFG's own dominator tree finds the loop.
        let via_cfg_dom = find_loops(&cfg, true);
        assert_eq!(via_cfg_dom.loops.len(), 1, "expected one loop via cfg.dom_tree");

        // An unrelated diamond dominator tree over the same addresses: 1 does
        // not dominate 2, so 2→1 is no longer classified as a back edge.
        let diamond_edges = vec![
            CfgEdge { from: addr(0), to: addr(1), kind: EdgeKind::Unconditional },
            CfgEdge { from: addr(0), to: addr(2), kind: EdgeKind::Unconditional },
            CfgEdge { from: addr(1), to: addr(3), kind: EdgeKind::Unconditional },
            CfgEdge { from: addr(2), to: addr(3), kind: EdgeKind::Unconditional },
        ];
        let alt_dom = DominatorTree::compute(&cfg.blocks, &diamond_edges, addr(0));
        assert!(!alt_dom.dominates(addr(1), addr(2)));

        let via_alt_dom = find_loops_with_dom(&cfg, &alt_dom, true);
        assert_eq!(
            via_alt_dom.loops.len(),
            0,
            "find_loops_with_dom must use the supplied dom_tree, not cfg.dom_tree"
        );
    }

    #[test]
    fn test_simple_while_loop() {
        // 0 → 1 (header) → 2 (body) → 1 (back), 1 → 3 (exit)
        let cfg = make_cfg(
            &[0, 1, 2, 3],
            vec![(0, 1), (1, 2), (2, 1), (1, 3)],
            0,
        );
        let nest = find_loops(&cfg, true);
        assert_eq!(nest.len(), 1);
        assert_eq!(nest.loops[0].header, addr(1));
        assert!(nest.loops[0].body.contains(&addr(1)));
        assert!(nest.loops[0].body.contains(&addr(2)));
    }

    #[test]
    fn test_equal_size_loops_ordered_deterministically_by_header() {
        // Regression test: `header_to_latches` used to be iterated directly
        // (a HashMap), so two loops with equal body size (a sort tie) could
        // come out in either order across runs since the stable sort kept
        // whatever nondeterministic hash order they were pushed in. With the
        // header-address secondary sort key, ties must always resolve the
        // same way regardless of how many times this runs.
        //
        // Two independent same-size while loops off one entry:
        // 0 -> 1 -> 2 -> 1 (back), 1 -> 5 (exit)
        // 0 -> 3 -> 4 -> 3 (back), 3 -> 6 (exit)
        let cfg = make_cfg(
            &[0, 1, 2, 3, 4, 5, 6],
            vec![
                (0, 1),
                (1, 2),
                (2, 1),
                (1, 5),
                (0, 3),
                (3, 4),
                (4, 3),
                (3, 6),
            ],
            0,
        );
        for _ in 0..20 {
            let nest = find_loops(&cfg, true);
            assert_eq!(nest.len(), 2);
            // Both bodies are size 2, so id ordering is determined solely by
            // the header-address tiebreak: header 1 must precede header 3.
            assert_eq!(nest.loops[0].header, addr(1));
            assert_eq!(nest.loops[1].header, addr(3));
        }
    }

    #[test]
    fn test_no_loops() {
        let cfg = make_cfg(&[0, 1, 2], vec![(0, 1), (1, 2)], 0);
        let nest = find_loops(&cfg, true);
        assert!(nest.is_empty());
    }

    #[test]
    fn test_infinite_loop() {
        // 0 → 1 → 1 (self-loop, no exit)
        let cfg = make_cfg(&[0, 1], vec![(0, 1), (1, 1)], 0);
        let nest = find_loops(&cfg, true);
        assert_eq!(nest.len(), 1);
        assert_eq!(nest.loops[0].kind, LoopKind::InfiniteLoop);
    }

    #[test]
    fn test_nested_loops() {
        // Outer: 0 → 1 → 2 → 3 → 1 (outer back)
        // Inner: 2 → 2 (self-loop)
        let cfg = make_cfg(
            &[0, 1, 2, 3],
            vec![(0, 1), (1, 2), (2, 2), (2, 3), (3, 1)],
            0,
        );
        let nest = find_loops(&cfg, true);
        // Should have at least two loops.
        assert!(nest.len() >= 2);
        let summary = LoopSummary::from_nest(&nest);
        assert!(summary.max_depth >= 1);
    }

    #[test]
    fn test_loop_query_membership() {
        let cfg = make_cfg(
            &[0, 1, 2, 3],
            vec![(0, 1), (1, 2), (2, 1), (1, 3)],
            0,
        );
        let nest = find_loops(&cfg, true);
        let query = LoopQuery::build(&nest);
        assert!(query.is_in_loop(addr(1)));
        assert!(query.is_in_loop(addr(2)));
        assert!(!query.is_in_loop(addr(0)));
        assert!(!query.is_in_loop(addr(3)));
    }

    #[test]
    fn test_loop_metrics() {
        let cfg = make_cfg(
            &[0, 1, 2, 3],
            vec![(0, 1), (1, 2), (2, 1), (1, 3)],
            0,
        );
        let nest = find_loops(&cfg, true);
        assert_eq!(nest.len(), 1);
        let metrics = LoopMetrics::compute(&nest.loops[0], &cfg);
        assert!(metrics.exit_edge_count >= 1);
        assert_eq!(metrics.back_edge_count, 1);
    }

    #[test]
    fn test_loop_pre_order() {
        let cfg = make_cfg(
            &[0, 1, 2, 3],
            vec![(0, 1), (1, 2), (2, 2), (2, 3), (3, 1)],
            0,
        );
        let nest = find_loops(&cfg, true);
        let pre = nest.pre_order();
        // Pre-order: parents before children.
        if pre.len() >= 2 {
            let parent_idx = pre[0].id;
            let child_idx = pre[1].id;
            assert!(nest.loops[child_idx].depth >= nest.loops[parent_idx].depth);
        }
    }

    #[test]
    fn test_loop_summary_counts() {
        // One while loop, one infinite loop.
        // While: 0→1→2→1 (exit at 1→3)
        let cfg = make_cfg(
            &[0, 1, 2, 3],
            vec![(0, 1), (1, 2), (2, 1), (1, 3)],
            0,
        );
        let nest = find_loops(&cfg, true);
        let summary = LoopSummary::from_nest(&nest);
        assert_eq!(summary.total, 1);
        assert!(summary.while_count + summary.counted_count >= 1);
    }

    #[test]
    fn test_cfg_loop_analyzer_default() {
        let cfg = make_cfg(
            &[0, 1, 2],
            vec![(0, 1), (1, 2), (2, 1)],
            0,
        );
        let analyzer = CfgLoopAnalyzer::new();
        let nest = analyzer.analyze(&cfg);
        assert_eq!(nest.len(), 1);
    }

    #[test]
    fn test_find_loops_merge_shared_headers_false_splits_by_latch() {
        // Header 1 has two independent back edges (from 2 and from 3).
        // merge_shared_headers=true should produce ONE loop with two latches;
        // merge_shared_headers=false should produce TWO loops, one per latch.
        let cfg = make_cfg(
            &[0, 1, 2, 3, 4],
            vec![(0, 1), (1, 2), (2, 1), (1, 3), (3, 1), (1, 4)],
            0,
        );

        let merged = find_loops(&cfg, true);
        assert_eq!(merged.len(), 1, "shared-header loops must merge into one");
        assert_eq!(merged.loops[0].latches.len(), 2);
        assert_eq!(merged.loops[0].body, HashSet::from([addr(1), addr(2), addr(3)]));

        let split = find_loops(&cfg, false);
        assert_eq!(split.len(), 2, "merge_shared_headers=false must split per latch");
        for lp in &split.loops {
            assert_eq!(lp.header, addr(1));
            assert_eq!(lp.latches.len(), 1);
            // Each split loop's body must NOT include the other latch's block.
            assert_eq!(lp.body.len(), 2);
        }
    }

    #[test]
    fn test_analyze_with_dom_matches_cfg_dom_tree_when_consistent() {
        let cfg = make_cfg(
            &[0, 1, 2, 3],
            vec![(0, 1), (1, 2), (2, 1), (1, 3)],
            0,
        );
        let analyzer = CfgLoopAnalyzer::new();
        let via_analyze = analyzer.analyze(&cfg);
        let via_dom = analyzer.analyze_with_dom(&cfg, &cfg.dom_tree);
        assert_eq!(via_analyze.len(), via_dom.len());
        assert_eq!(via_analyze.loops[0].header, via_dom.loops[0].header);
        assert_eq!(via_analyze.loops[0].body, via_dom.loops[0].body);
    }

    #[test]
    fn test_loop_is_outermost_and_is_innermost() {
        // Outer: 0 -> 1 -> 2 -> 2(self) -> 3 -> 1 (outer back)
        let cfg = make_cfg(
            &[0, 1, 2, 3],
            vec![(0, 1), (1, 2), (2, 2), (2, 3), (3, 1)],
            0,
        );
        let nest = find_loops(&cfg, true);
        assert_eq!(nest.len(), 2);
        let outer = nest.loops.iter().find(|l| l.header == addr(1)).unwrap();
        let inner = nest.loops.iter().find(|l| l.header == addr(2)).unwrap();
        assert!(outer.is_outermost());
        assert!(!outer.is_innermost());
        assert!(!inner.is_outermost());
        assert!(inner.is_innermost());
    }

    #[test]
    fn test_loop_query_depth_innermost_and_all_loops_for() {
        // Outer: 0 -> 1 -> 2 -> 2(self) -> 3 -> 1 (outer back)
        let cfg = make_cfg(
            &[0, 1, 2, 3],
            vec![(0, 1), (1, 2), (2, 2), (2, 3), (3, 1)],
            0,
        );
        let nest = find_loops(&cfg, true);
        let query = LoopQuery::build(&nest);

        // Block 2 is in both the inner self-loop and the outer loop.
        assert_eq!(query.depth_of(addr(2)), 1);
        let inner = query.innermost_for(addr(2)).unwrap();
        assert_eq!(inner.header, addr(2));

        let all = query.all_loops_for(addr(2));
        assert_eq!(all.len(), 2);
        // Outermost first (depth ascending).
        assert_eq!(all[0].header, addr(1));
        assert_eq!(all[1].header, addr(2));

        // Block 1 is only in the outer loop.
        assert_eq!(query.depth_of(addr(1)), 0);
        assert_eq!(query.innermost_for(addr(1)).unwrap().header, addr(1));

        // Block 0 is in no loop.
        assert_eq!(query.depth_of(addr(0)), 0);
        assert!(query.innermost_for(addr(0)).is_none());
        assert!(query.all_loops_for(addr(0)).is_empty());
    }
}
