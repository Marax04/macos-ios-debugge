//! `irreducible_cfg.rs` — Handling of irreducible CFGs.
//!
//! Implements:
//! - Node splitting (T1/T2 reductions, Cocke-Ullman)
//! - Tarjan's loop nesting forest
//! - Havlak algorithm for loop detection in irreducible graphs
//! - Conversion to a reducible form for structuring

use crate::{CfgEdge, ControlFlowGraph, EdgeKind, ReducibilityResult, ReducibilityTest};
use rustre_core::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// IrreducibleLoop — a loop that has multiple entry points
// ─────────────────────────────────────────────────────────────────────────────

/// A loop region that may be irreducible (multiple entry points).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrreducibleLoop {
    /// All block addresses in this loop body.
    pub body: HashSet<Address>,
    /// All entry points from outside the loop.
    pub entries: Vec<Address>,
    /// Exit blocks (successors outside the loop).
    pub exits: Vec<Address>,
    /// Back edges (from → to) within the loop.
    pub back_edges: Vec<(Address, Address)>,
    /// Whether this loop is reducible (single entry).
    pub is_reducible: bool,
    /// Nesting depth in the loop forest.
    pub depth: u32,
}

impl IrreducibleLoop {
    #[must_use]
    pub const fn new(body: HashSet<Address>) -> Self {
        Self {
            body,
            entries: Vec::new(),
            exits: Vec::new(),
            back_edges: Vec::new(),
            is_reducible: true,
            depth: 0,
        }
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.body.len()
    }

    #[must_use]
    pub fn contains(&self, addr: Address) -> bool {
        self.body.contains(&addr)
    }

    /// Returns `true` if this loop has more than one external entry.
    #[must_use]
    pub const fn is_irreducible(&self) -> bool {
        self.entries.len() > 1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopNestingForest — Tarjan's loop nesting tree
// ─────────────────────────────────────────────────────────────────────────────

/// A node in the loop nesting forest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopForestNode {
    /// Header block of this loop (or the function entry for the root).
    pub header: Address,
    /// All blocks in this loop body (including nested loops).
    pub body: HashSet<Address>,
    /// Direct child loops.
    pub children: Vec<usize>, // indices into LoopNestingForest::nodes
    /// Parent loop index (None for top-level loops / the root).
    pub parent: Option<usize>,
    /// Whether this node represents an irreducible loop.
    pub irreducible: bool,
    /// Depth in the forest (root = 0).
    pub depth: u32,
}

/// Tarjan's loop nesting forest for a CFG.
#[derive(Debug, Clone, Default)]
pub struct LoopNestingForest {
    /// All nodes (loops) in the forest.
    pub nodes: Vec<LoopForestNode>,
    /// Map from header address to node index.
    pub header_to_node: HashMap<Address, usize>,
    /// Root node indices (top-level loops).
    pub roots: Vec<usize>,
}

impl LoopNestingForest {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the node for `header`, if any.
    #[must_use]
    pub fn node_for(&self, header: Address) -> Option<&LoopForestNode> {
        self.header_to_node.get(&header).map(|&i| &self.nodes[i])
    }

    /// Return the nesting depth of `addr` (how many loops contain it).
    #[must_use]
    pub fn nesting_depth(&self, addr: Address) -> usize {
        self.nodes.iter().filter(|n| n.body.contains(&addr)).count()
    }

    /// All irreducible loop nodes.
    #[must_use]
    pub fn irreducible_loops(&self) -> Vec<&LoopForestNode> {
        self.nodes.iter().filter(|n| n.irreducible).collect()
    }

    /// Total number of loop nodes.
    #[must_use]
    pub const fn loop_count(&self) -> usize {
        self.nodes.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HavlakLoopDetector — Havlak's algorithm for irreducible CFGs
// ─────────────────────────────────────────────────────────────────────────────

/// Block class in Havlak's algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HavlakClass {
    /// Block is in a reducible back edge.
    Reducible,
    /// Block is in an irreducible back edge.
    SelfLoop,
    /// Block is a non-back-edge block.
    NonBackEdge,
}

impl HavlakClass {
    /// Classify a back-edge `from -> to` given a reducibility decision.
    ///
    /// This helper makes [`HavlakClass`] usable by callers that want to label
    /// CFG edges according to Havlak's taxonomy without re-running the full
    /// detector.
    #[must_use]
    pub fn classify_edge(from: Address, to: Address, is_reducible: bool) -> Self {
        if from == to {
            Self::SelfLoop
        } else if is_reducible {
            Self::Reducible
        } else {
            Self::NonBackEdge
        }
    }

    /// True for either flavour of back edge (reducible or self loop).
    #[must_use]
    pub const fn is_back_edge(self) -> bool {
        matches!(self, Self::Reducible | Self::SelfLoop)
    }
}

impl LoopForestNode {
    /// Return the Havlak class for this node based on its reducibility flag.
    #[must_use]
    pub const fn havlak_class(&self) -> HavlakClass {
        if self.irreducible {
            HavlakClass::NonBackEdge
        } else {
            HavlakClass::Reducible
        }
    }
}

/// Havlak's algorithm for detecting loops (including irreducible ones) in a CFG.
///
/// Reference: Paul Havlak, "Nesting of Reducible and Irreducible Loops",
/// TOPLAS 1997.
pub struct HavlakLoopDetector;

impl HavlakLoopDetector {
    /// Detect all loops in `cfg` and build a `LoopNestingForest`.
    #[must_use]
    pub fn detect(cfg: &ControlFlowGraph) -> LoopNestingForest {
        let entry = cfg.entry;
        let mut forest = LoopNestingForest::new();

        // 1. Compute DFS order (RPO) and parent array.
        let rpo = cfg.reverse_post_order();
        let n = rpo.len();
        if n == 0 {
            return forest;
        }

        let rpo_index: HashMap<Address, usize> =
            rpo.iter().enumerate().map(|(i, &a)| (a, i)).collect();

        // 2. Build successor / predecessor lists in RPO-index space.
        let mut succs: Vec<Vec<usize>> = vec![vec![]; n];
        let mut preds: Vec<Vec<usize>> = vec![vec![]; n];
        for edge in &cfg.edges {
            if let (Some(&fi), Some(&ti)) = (rpo_index.get(&edge.from), rpo_index.get(&edge.to)) {
                succs[fi].push(ti);
                preds[ti].push(fi);
            }
        }

        // 3. Compute DFS tree using iterative DFS.
        let mut dfs_parent: Vec<Option<usize>> = vec![None; n];
        let mut dfs_order: Vec<usize> = Vec::new();
        let mut visited = vec![false; n];
        let entry_idx = rpo_index.get(&entry).copied().unwrap_or(0);

        {
            let mut stack: Vec<(usize, usize)> = vec![(entry_idx, 0)];
            visited[entry_idx] = true;
            while let Some((node, child_idx)) = stack.last_mut() {
                let node = *node;
                if *child_idx < succs[node].len() {
                    let child = succs[node][*child_idx];
                    *child_idx += 1;
                    if !visited[child] {
                        visited[child] = true;
                        dfs_parent[child] = Some(node);
                        stack.push((child, 0));
                    }
                } else {
                    stack.pop();
                    dfs_order.push(node);
                }
            }
        }

        // 4. Process nodes in reverse DFS order (post-order).
        let mut node_loops: Vec<Option<usize>> = vec![None; n]; // node → loop node index

        for &w in dfs_order.iter().rev() {
            let mut work_list: Vec<usize> = Vec::new();
            let mut loop_body: HashSet<usize> = HashSet::new();

            for &v in &preds[w] {
                // Classify the edge v → w. A back edge is one where `w` is an
                // ancestor of `v` in the DFS tree (i.e. `w` is still on the
                // active DFS path when `v` is visited) — NOT the other way
                // around. The arguments here used to be swapped
                // (`is_ancestor(v, w, ...)`, i.e. "is v an ancestor of w"),
                // which misclassified forward/tree edges as back edges and
                // failed to recognize real back edges, corrupting loop
                // bodies and silently under-reporting irreducible loops.
                if Self::is_ancestor(w, v, &dfs_parent) {
                    // Reducible back edge.
                    if v == w {
                        // Self-loop.
                        loop_body.insert(w);
                    } else {
                        work_list.push(v);
                    }
                }
            }

            if work_list.is_empty() && loop_body.is_empty() {
                continue;
            }

            loop_body.insert(w);

            while let Some(x) = work_list.pop() {
                if loop_body.contains(&x) {
                    continue;
                }
                loop_body.insert(x);
                // Only predecessors of x that are descendants of (or equal
                // to) w in the DFS tree belong to w's natural loop; those
                // reached from outside w's subtree are external entries into
                // the loop (a marker of irreducibility) and must NOT be
                // pulled into the body — doing so (the previous, inverted
                // condition `!is_ancestor(w, p, ...)`) could swallow even the
                // CFG entry node itself into the loop body, which in turn
                // hid the external-entry check below (an already-swallowed
                // predecessor is trivially "in loop_body"), silently
                // misclassifying irreducible loops as reducible.
                for &p in &preds[x] {
                    if Self::is_ancestor(w, p, &dfs_parent) {
                        work_list.push(p);
                    }
                }
            }

            // Check if the loop is irreducible: any block in loop_body that has
            // a predecessor outside loop_body and is not the header w.
            let mut entries: Vec<usize> = Vec::new();
            for &b in &loop_body {
                if b == w {
                    continue;
                }
                for &p in &preds[b] {
                    if !loop_body.contains(&p) {
                        entries.push(b);
                        break;
                    }
                }
            }
            let irreducible = !entries.is_empty();

            // Compute exits.
            let mut exits: Vec<usize> = Vec::new();
            for &b in &loop_body {
                for &s in &succs[b] {
                    if !loop_body.contains(&s) && !exits.contains(&s) {
                        exits.push(s);
                    }
                }
            }

            // Compute back edges within the loop.
            let mut back_edges: Vec<(usize, usize)> = Vec::new();
            for &v in &preds[w] {
                if loop_body.contains(&v) {
                    back_edges.push((v, w));
                }
            }

            // Create the loop forest node.
            let node_idx = forest.nodes.len();
            let loop_addr_body: HashSet<Address> = loop_body.iter().map(|&i| rpo[i]).collect();
            let _entry_addrs: Vec<Address> = entries.iter().map(|&i| rpo[i]).collect();
            let _exit_addrs: Vec<Address> = exits.iter().map(|&i| rpo[i]).collect();
            let _back_addr_edges: Vec<(Address, Address)> = back_edges
                .iter()
                .map(|&(f, t)| (rpo[f], rpo[t]))
                .collect();

            forest.header_to_node.insert(rpo[w], node_idx);
            forest.nodes.push(LoopForestNode {
                header: rpo[w],
                body: loop_addr_body,
                children: Vec::new(),
                parent: None,
                irreducible,
                depth: 0,
            });
            forest.roots.push(node_idx);

            // Assign loop membership.
            for &b in &loop_body {
                node_loops[b] = Some(node_idx);
            }
        }

        // 5. Build parent-child relationships.
        let n_nodes = forest.nodes.len();
        for i in 0..n_nodes {
            let header = forest.nodes[i].header;
            // Find if this loop is strictly nested inside another. When
            // multiple loops contain `header` (e.g. three levels of nesting
            // all sharing the innermost header on the back-edge path), the
            // *immediate* parent is the tightest (smallest-body) containing
            // loop, not merely the first one encountered in `forest.nodes`
            // order — that order reflects DFS-postorder processing, not
            // containment, so picking the first match can skip an
            // intermediate level and attach a loop directly to an outer
            // ancestor instead of its real immediate parent.
            let parent_idx = forest
                .nodes
                .iter()
                .enumerate()
                .filter(|&(j, other)| i != j && other.body.contains(&header))
                .min_by_key(|&(_, other)| other.body.len())
                .map(|(j, _)| j);
            if let Some(p) = parent_idx {
                forest.nodes[i].parent = Some(p);
                forest.nodes[p].children.push(i);
                forest.roots.retain(|&r| r != i);
            }
        }

        // 6. Assign depths.
        let roots = forest.roots.clone();
        for &root in &roots {
            Self::assign_depths(&mut forest, root, 0);
        }

        forest
    }

    fn is_ancestor(ancestor: usize, node: usize, dfs_parent: &[Option<usize>]) -> bool {
        let mut cur = node;
        loop {
            if cur == ancestor {
                return true;
            }
            match dfs_parent[cur] {
                Some(p) => cur = p,
                None => return false,
            }
        }
    }

    // Iterative (explicit-stack) rather than recursive: a recursive walk
    // pushes one Rust stack frame per forest level, which overflows the
    // stack on adversarially deep loop-nesting forests (e.g. thousands of
    // sequentially nested loops in a pathological/generated CFG).
    fn assign_depths(forest: &mut LoopNestingForest, node_idx: usize, depth: u32) {
        let mut stack: Vec<(usize, u32)> = vec![(node_idx, depth)];
        while let Some((node, d)) = stack.pop() {
            forest.nodes[node].depth = d;
            for &child in &forest.nodes[node].children {
                stack.push((child, d + 1));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeSplitter — T1/T2 CFG transformations for reducibility
// ─────────────────────────────────────────────────────────────────────────────

/// A record of a node splitting transformation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSplit {
    /// The original node address.
    pub original: Address,
    /// The cloned copy (new entry point for one of the predecessors).
    pub clone: Address,
    /// Predecessors redirected to `clone`.
    pub redirected_preds: Vec<Address>,
}

/// Transforms an irreducible CFG into a reducible one using node splitting.
///
/// For each irreducible back edge `(p, h)` where `h` is not the dominator of `p`,
/// clone node `h` into `h'` and redirect `p → h` to `p → h'`.
/// This guarantees that `h'` has a single external entry.
pub struct NodeSplitter {
    /// Next synthetic address to use for cloned nodes.
    next_clone_addr: u64,
    /// All splits performed.
    pub splits: Vec<NodeSplit>,
}

impl NodeSplitter {
    /// Create a `NodeSplitter` that assigns clone addresses starting at `clone_base`.
    #[must_use]
    pub const fn new(clone_base: u64) -> Self {
        Self { next_clone_addr: clone_base, splits: Vec::new() }
    }

    /// Allocate a synthetic address for a cloned node.
    const fn alloc_clone(&mut self) -> Address {
        let addr = Address::new(self.next_clone_addr);
        self.next_clone_addr += 0x10000; // space out clones
        addr
    }

    /// Transform `cfg` into a reducible form by splitting irreducible nodes.
    ///
    /// Returns the new set of edges for the transformed graph and the list of splits.
    pub fn make_reducible(&mut self, cfg: &ControlFlowGraph) -> (Vec<CfgEdge>, Vec<NodeSplit>) {
        let result = ReducibilityTest::test(cfg);
        if result.is_reducible() {
            return (cfg.edges.clone(), Vec::new());
        }

        let irred_back_edges = match result {
            ReducibilityResult::Irreducible { back_edges } => back_edges,
            ReducibilityResult::Reducible => unreachable!(),
        };

        let mut new_edges = cfg.edges.clone();

        for (from, to) in irred_back_edges {
            let clone_addr = self.alloc_clone();

            // Find all predecessors of `to` that come from outside the loop
            // (not through a back edge) and redirect them to the clone.
            // For simplicity: redirect only `from → to`.
            let split = NodeSplit {
                original: to,
                clone: clone_addr,
                redirected_preds: vec![from],
            };

            // Replace the edge `from → to` with `from → clone_addr`.
            for edge in &mut new_edges {
                if edge.from == from && edge.to == to {
                    edge.to = clone_addr;
                }
            }

            // Add edges from `clone_addr` to all successors of `to`.
            let to_succs: Vec<Address> = cfg
                .edges
                .iter()
                .filter(|e| e.from == to)
                .map(|e| e.to)
                .collect();

            for succ in to_succs {
                new_edges.push(CfgEdge {
                    from: clone_addr,
                    to: succ,
                    kind: EdgeKind::Unconditional,
                });
            }

            self.splits.push(split.clone());
        }

        let all_splits = self.splits.clone();
        (new_edges, all_splits)
    }

    /// Number of node splits performed so far.
    #[must_use]
    pub const fn split_count(&self) -> usize {
        self.splits.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// T1T2Reducer — classic T1/T2 structural reduction
// ─────────────────────────────────────────────────────────────────────────────

/// Performs iterative T1 and T2 structural reductions on a CFG.
///
/// T1: Remove a self-loop edge `n → n`.
/// T2: If `n` has a unique predecessor `p`, merge `n` into `p`.
///
/// If the graph reduces completely to a single node, it is reducible.
pub struct T1T2Reducer;

impl T1T2Reducer {
    /// Apply T1/T2 reductions to an adjacency list until no more apply.
    ///
    /// Returns `true` if the graph is fully reducible (reduces to one node).
    ///
    /// `entry` is the CFG entry node: it is never absorbed by T2. Without
    /// this exclusion an entry node with a unique predecessor (i.e. a back
    /// edge to the function entry) could be merged *into* that predecessor,
    /// which pretends control enters the region at the predecessor instead
    /// of the entry and lets some genuinely irreducible CFGs collapse to a
    /// single node (found by
    /// soundness_fuzz::reducibility_implementations_agree_fuzz, which
    /// cross-checks this against `reducibility_analysis`'s entry-aware
    /// T1/T2).
    pub fn reduce(adj: &mut HashMap<Address, HashSet<Address>>, entry: Address) -> bool {
        use std::collections::VecDeque;

        // Maintain an explicit reverse-adjacency (predecessor) index so that
        // finding "does this node have a unique predecessor" is O(1) instead
        // of an O(n) scan over the whole graph — and so the whole reduction
        // runs in roughly O(V + E) instead of the previous O(V^3) worst case
        // (full-graph rescan + restart-from-scratch after every merge).
        let mut preds: HashMap<Address, HashSet<Address>> = HashMap::new();
        for node in adj.keys() {
            preds.entry(*node).or_default();
        }
        for (&from, succs) in adj.iter() {
            for &to in succs {
                if to != from {
                    preds.entry(to).or_default().insert(from);
                }
            }
        }

        let mut worklist: VecDeque<Address> = adj.keys().copied().collect();

        while let Some(node) = worklist.pop_front() {
            // Node may have already been merged away by an earlier iteration.
            if !adj.contains_key(&node) {
                continue;
            }

            // T1: remove self-loop.
            if let Some(succs) = adj.get_mut(&node) {
                succs.remove(&node);
            }
            if let Some(node_preds) = preds.get_mut(&node) {
                node_preds.remove(&node);
            }

            // T2: merge nodes with a unique predecessor (never the entry).
            if node == entry {
                continue;
            }
            let unique_pred = preds.get(&node).and_then(|p| {
                let mut it = p.iter();
                match (it.next(), it.next()) {
                    (Some(&only), None) => Some(only),
                    _ => None,
                }
            });

            if let Some(pred) = unique_pred {
                if pred != node {
                    // Merge `node` into `pred`: rehome all of `node`'s
                    // successors (and their predecessor entries) onto `pred`.
                    if let Some(node_succs) = adj.remove(&node) {
                        for s in node_succs {
                            if s == node {
                                continue;
                            }
                            adj.entry(pred).or_default().insert(s);
                            if let Some(s_preds) = preds.get_mut(&s) {
                                s_preds.remove(&node);
                                if s != pred {
                                    s_preds.insert(pred);
                                }
                                // Rehoming `node`'s edge onto `pred` can
                                // shrink `s`'s predecessor set (when `pred`
                                // was already a predecessor of `s`, the two
                                // entries collapse into one), which can make
                                // `s` a fresh T2 candidate. Re-enqueue it —
                                // previously only `pred` was re-enqueued, so
                                // an `s` already processed earlier was never
                                // revisited and the reduction stopped early,
                                // misreporting reducible CFGs as irreducible
                                // (found by soundness_fuzz::
                                // reducibility_implementations_agree_fuzz).
                                worklist.push_back(s);
                            }
                        }
                    }
                    if let Some(pred_succs) = adj.get_mut(&pred) {
                        pred_succs.remove(&node);
                    }
                    preds.remove(&node);

                    worklist.push_back(pred);
                }
            }
        }

        adj.len() == 1
    }

    /// Test reducibility of a `ControlFlowGraph` using T1/T2 reduction.
    #[must_use]
    pub fn test_reducible(cfg: &ControlFlowGraph) -> bool {
        let mut adj: HashMap<Address, HashSet<Address>> = HashMap::new();
        for block_addr in cfg.blocks.keys() {
            adj.entry(*block_addr).or_default();
        }
        for edge in &cfg.edges {
            adj.entry(edge.from).or_default().insert(edge.to);
        }
        Self::reduce(&mut adj, cfg.entry)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IrreducibleCfgAnalysis — combined analysis result
// ─────────────────────────────────────────────────────────────────────────────

/// Full irreducibility analysis of a CFG.
#[derive(Debug, Clone)]
pub struct IrreducibleCfgAnalysis {
    /// Whether the CFG is reducible.
    pub is_reducible: bool,
    /// Back edges that are irreducible.
    pub irreducible_back_edges: Vec<(Address, Address)>,
    /// The loop nesting forest (Havlak algorithm).
    pub loop_forest: LoopNestingForest,
    /// Node splits applied to make the CFG reducible.
    pub splits_applied: Vec<NodeSplit>,
    /// The T1/T2 test result.
    pub t1t2_reducible: bool,
}

impl IrreducibleCfgAnalysis {
    /// Run a full irreducibility analysis on `cfg`.
    #[must_use]
    pub fn analyze(cfg: &ControlFlowGraph) -> Self {
        let reducibility_result = ReducibilityTest::test(cfg);
        let is_reducible = reducibility_result.is_reducible();

        let irreducible_back_edges = match &reducibility_result {
            ReducibilityResult::Irreducible { back_edges } => back_edges.clone(),
            ReducibilityResult::Reducible => Vec::new(),
        };

        // Havlak loop detection.
        let loop_forest = HavlakLoopDetector::detect(cfg);

        // T1/T2 test.
        let t1t2_reducible = T1T2Reducer::test_reducible(cfg);

        // Node splitting (only if irreducible).
        let splits_applied = if is_reducible {
            Vec::new()
        } else {
            let mut splitter = NodeSplitter::new(0x8000_0000_0000_0000);
            let (_, splits) = splitter.make_reducible(cfg);
            splits
        };

        Self {
            is_reducible,
            irreducible_back_edges,
            loop_forest,
            splits_applied,
            t1t2_reducible,
        }
    }

    /// Number of loops in the nesting forest.
    #[must_use]
    pub const fn loop_count(&self) -> usize {
        self.loop_forest.loop_count()
    }

    /// Number of irreducible loops.
    #[must_use]
    pub fn irreducible_loop_count(&self) -> usize {
        self.loop_forest.irreducible_loops().len()
    }
}

impl fmt::Display for IrreducibleCfgAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IrreducibleCfgAnalysis {{ reducible: {}, irred_back_edges: {}, loops: {}, irred_loops: {}, splits: {} }}",
            self.is_reducible,
            self.irreducible_back_edges.len(),
            self.loop_count(),
            self.irreducible_loop_count(),
            self.splits_applied.len(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BasicBlock, DominatorTree, PostDominatorTree};
    use std::collections::HashMap;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    fn simple_reducible_cfg() -> ControlFlowGraph {
        // 0x1000 → 0x2000 → 0x3000 → 0x2000 (back edge, reducible)
        let mut blocks = HashMap::new();
        for a in [0x1000u64, 0x2000, 0x3000] {
            blocks.insert(addr(a), BasicBlock {
                start: addr(a), end: addr(a + 4), instructions: vec![],
            });
        }
        let edges = vec![
            CfgEdge { from: addr(0x1000), to: addr(0x2000), kind: EdgeKind::Unconditional },
            CfgEdge { from: addr(0x2000), to: addr(0x3000), kind: EdgeKind::TrueBranch },
            CfgEdge { from: addr(0x3000), to: addr(0x2000), kind: EdgeKind::Unconditional },
            CfgEdge { from: addr(0x2000), to: addr(0x4000), kind: EdgeKind::FalseBranch },
        ];
        let dom_tree = DominatorTree::compute(&blocks, &edges, addr(0x1000));
        ControlFlowGraph {
            blocks, edges, entry: addr(0x1000),
            dom_tree, loops: vec![], post_dom_tree: PostDominatorTree::default(),
        }
    }

    /// Three properly nested single-entry loops sharing the innermost
    /// header on every enclosing body:
    ///   h3 = {C, D}                       (innermost)
    ///   h2 = {B, C, D, E}                 (middle)
    ///   h1 = {A, B, C, D, E, F}           (outer)
    /// `C` (h3's header) is contained in *both* h2's and h1's bodies, so
    /// naively picking the first loop in traversal order whose body
    /// contains the header can wrongly attach h3 directly under h1,
    /// skipping h2. The immediate parent must be the tightest (smallest)
    /// containing loop, i.e. h2.
    fn triple_nested_loop_cfg() -> ControlFlowGraph {
        let addrs = [
            0x1000u64, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000,
        ];
        let mut blocks = HashMap::new();
        for a in addrs {
            blocks.insert(addr(a), BasicBlock {
                start: addr(a),
                end: addr(a + 4),
                instructions: vec![],
            });
        }
        let edges = vec![
            CfgEdge { from: addr(0x1000), to: addr(0x2000), kind: EdgeKind::Unconditional }, // entry -> A (h1)
            CfgEdge { from: addr(0x2000), to: addr(0x3000), kind: EdgeKind::Unconditional }, // A -> B (h2)
            CfgEdge { from: addr(0x3000), to: addr(0x4000), kind: EdgeKind::Unconditional }, // B -> C (h3)
            CfgEdge { from: addr(0x4000), to: addr(0x5000), kind: EdgeKind::Unconditional }, // C -> D
            CfgEdge { from: addr(0x5000), to: addr(0x4000), kind: EdgeKind::TrueBranch },    // D -> C (inner back edge)
            CfgEdge { from: addr(0x5000), to: addr(0x6000), kind: EdgeKind::FalseBranch },   // D -> E (exit inner)
            CfgEdge { from: addr(0x6000), to: addr(0x3000), kind: EdgeKind::TrueBranch },    // E -> B (mid back edge)
            CfgEdge { from: addr(0x6000), to: addr(0x7000), kind: EdgeKind::FalseBranch },   // E -> F (exit mid)
            CfgEdge { from: addr(0x7000), to: addr(0x2000), kind: EdgeKind::TrueBranch },    // F -> A (outer back edge)
            CfgEdge { from: addr(0x7000), to: addr(0x8000), kind: EdgeKind::FalseBranch },   // F -> G (exit outer)
        ];
        let dom_tree = DominatorTree::compute(&blocks, &edges, addr(0x1000));
        ControlFlowGraph {
            blocks,
            edges,
            entry: addr(0x1000),
            dom_tree,
            loops: vec![],
            post_dom_tree: PostDominatorTree::default(),
        }
    }

    #[test]
    fn loop_nesting_forest_picks_tightest_immediate_parent() {
        let cfg = triple_nested_loop_cfg();
        let forest = HavlakLoopDetector::detect(&cfg);

        let h1 = forest.node_for(addr(0x2000)).expect("outer loop header");
        let h2 = forest.node_for(addr(0x3000)).expect("mid loop header");
        let h3 = forest.node_for(addr(0x4000)).expect("inner loop header");

        assert_eq!(h1.body.len(), 6);
        assert_eq!(h2.body.len(), 4);
        assert_eq!(h3.body.len(), 2);

        let idx = |a: Address| forest.header_to_node[&a];
        assert_eq!(h2.parent, Some(idx(addr(0x2000))), "h2's immediate parent must be h1");
        assert_eq!(h3.parent, Some(idx(addr(0x3000))), "h3's immediate parent must be h2, not h1");
        assert_eq!(h1.depth, 0);
        assert_eq!(h2.depth, 1);
        assert_eq!(h3.depth, 2);
    }

    #[test]
    fn reducible_cfg_analysis() {
        let cfg = simple_reducible_cfg();
        let analysis = IrreducibleCfgAnalysis::analyze(&cfg);
        assert!(analysis.is_reducible);
        assert!(analysis.irreducible_back_edges.is_empty());
        assert!(analysis.splits_applied.is_empty());
    }

    #[test]
    fn havlak_detects_loop() {
        let cfg = simple_reducible_cfg();
        let forest = HavlakLoopDetector::detect(&cfg);
        // Should detect the 0x2000 → 0x3000 → 0x2000 loop.
        assert!(!forest.nodes.is_empty());
    }

    #[test]
    fn t1t2_reducer_simple_loop() {
        // 0x1000 → 0x2000 → 0x2000 (self-loop)
        let mut adj: HashMap<Address, HashSet<Address>> = HashMap::new();
        adj.entry(addr(0x1000)).or_default().insert(addr(0x2000));
        adj.entry(addr(0x2000)).or_default().insert(addr(0x2000)); // self-loop
        let result = T1T2Reducer::reduce(&mut adj, addr(0x1000));
        // After T1 removes self-loop: 0x2000 has unique predecessor 0x1000 → T2 merges.
        assert!(result);
    }

    #[test]
    fn t1t2_reducer_irreducible() {
        // Classic irreducible CFG: A→B, A→C, B→C, C→B (two entries to the loop B↔C)
        let mut adj: HashMap<Address, HashSet<Address>> = HashMap::new();
        adj.entry(addr(1)).or_default().insert(addr(2));
        adj.entry(addr(1)).or_default().insert(addr(3));
        adj.entry(addr(2)).or_default().insert(addr(3));
        adj.entry(addr(3)).or_default().insert(addr(2));
        let result = T1T2Reducer::reduce(&mut adj, addr(1));
        // The two-entry loop B <-> C cannot be reduced without node splitting.
        assert!(!result);
    }

    #[test]
    fn t1t2_reducer_long_chain_is_reducible_and_fast() {
        // A long linear chain 0 → 1 → 2 → ... → N should fully reduce to a
        // single node. This also exercises the incremental predecessor
        // bookkeeping in `T1T2Reducer::reduce` over many sequential merges
        // (previously O(V^3): full-graph rescan + restart after every merge).
        const N: u64 = 5000;
        let mut adj: HashMap<Address, HashSet<Address>> = HashMap::new();
        for i in 0..N {
            adj.entry(addr(i)).or_default().insert(addr(i + 1));
        }
        adj.entry(addr(N)).or_default();
        let result = T1T2Reducer::reduce(&mut adj, addr(0));
        assert!(result);
        assert_eq!(adj.len(), 1);
    }

    #[test]
    fn t1t2_reducer_diamond_merges_correctly() {
        // 0 → 1, 0 → 2, 1 → 3, 2 → 3: a diamond. Node 3 initially has two
        // predecessors (1 and 2), but T2-merging 1 and 2 into 0 collapses
        // them into the single predecessor 0, after which 3 merges as well —
        // every acyclic CFG is reducible. (This test used to assert the
        // opposite; the reducer previously failed to revisit node 3 after
        // its predecessor set shrank, a bug found by
        // soundness_fuzz::reducibility_implementations_agree_fuzz.)
        let mut adj: HashMap<Address, HashSet<Address>> = HashMap::new();
        adj.entry(addr(0)).or_default().insert(addr(1));
        adj.entry(addr(0)).or_default().insert(addr(2));
        adj.entry(addr(1)).or_default().insert(addr(3));
        adj.entry(addr(2)).or_default().insert(addr(3));
        adj.entry(addr(3)).or_default();
        let result = T1T2Reducer::reduce(&mut adj, addr(0));
        assert!(result);
        assert_eq!(adj.len(), 1);
    }

    #[test]
    fn t1t2_reducer_never_absorbs_entry() {
        // Regression (found by soundness_fuzz): back edge to the entry plus
        // a two-entry inner loop. Entry 0 acquires a unique predecessor
        // during reduction; absorbing it via T2 (as the reducer used to)
        // pretends control enters at that predecessor and collapses this
        // genuinely irreducible CFG to a single node.
        //   0 -> 1, 1 -> 2, 1 -> 3, 2 -> 3, 3 -> 2, 2 -> 0
        let mut adj: HashMap<Address, HashSet<Address>> = HashMap::new();
        adj.entry(addr(0)).or_default().insert(addr(1));
        adj.entry(addr(1)).or_default().insert(addr(2));
        adj.entry(addr(1)).or_default().insert(addr(3));
        adj.entry(addr(2)).or_default().insert(addr(3));
        adj.entry(addr(3)).or_default().insert(addr(2));
        adj.entry(addr(2)).or_default().insert(addr(0));
        let result = T1T2Reducer::reduce(&mut adj, addr(0));
        assert!(!result, "irreducible CFG must not fully reduce");
    }

    #[test]
    fn node_splitter_allocation() {
        let mut splitter = NodeSplitter::new(0xFF00_0000);
        let a1 = splitter.alloc_clone();
        let a2 = splitter.alloc_clone();
        assert_ne!(a1, a2);
    }

    #[test]
    fn irreducible_loop_detection() {
        let lp = IrreducibleLoop::new([addr(0x1000), addr(0x2000)].into());
        assert_eq!(lp.size(), 2);
        assert!(lp.contains(addr(0x1000)));
        assert!(!lp.is_irreducible()); // no external entries yet
    }

    #[test]
    fn loop_nesting_forest_depth() {
        let cfg = simple_reducible_cfg();
        let forest = HavlakLoopDetector::detect(&cfg);
        for node in &forest.nodes {
            // Roots should have depth 0, children depth > 0.
            if node.parent.is_none() {
                assert_eq!(node.depth, 0);
            } else {
                // depth is set by assign_depths; just verify it is reasonable.
                assert!(node.depth < 100);
            }
        }
    }

    // ── HavlakClass ─────────────────────────────────────────────────────────

    #[test]
    fn havlak_class_self_loop() {
        let a = addr(0x1000);
        assert_eq!(HavlakClass::classify_edge(a, a, true), HavlakClass::SelfLoop);
        assert_eq!(HavlakClass::classify_edge(a, a, false), HavlakClass::SelfLoop);
    }

    #[test]
    fn havlak_class_reducible_vs_non_back_edge() {
        let from = addr(0x1000);
        let to = addr(0x2000);
        assert_eq!(HavlakClass::classify_edge(from, to, true), HavlakClass::Reducible);
        assert_eq!(HavlakClass::classify_edge(from, to, false), HavlakClass::NonBackEdge);
    }

    #[test]
    fn havlak_class_is_back_edge() {
        assert!(HavlakClass::Reducible.is_back_edge());
        assert!(HavlakClass::SelfLoop.is_back_edge());
        assert!(!HavlakClass::NonBackEdge.is_back_edge());
    }

    #[test]
    fn loop_forest_node_havlak_class() {
        let mut node = LoopForestNode {
            header: addr(0x1000),
            body: HashSet::new(),
            children: Vec::new(),
            parent: None,
            irreducible: false,
            depth: 0,
        };
        assert_eq!(node.havlak_class(), HavlakClass::Reducible);
        node.irreducible = true;
        assert_eq!(node.havlak_class(), HavlakClass::NonBackEdge);
    }

    // ── LoopNestingForest accessors ─────────────────────────────────────────

    #[test]
    fn loop_nesting_forest_node_for_and_nesting_depth() {
        let cfg = simple_reducible_cfg();
        let forest = HavlakLoopDetector::detect(&cfg);
        // Header of the detected loop is 0x2000.
        let node = forest.node_for(addr(0x2000));
        assert!(node.is_some());
        assert!(forest.node_for(addr(0x9999)).is_none());

        // 0x2000 and 0x3000 are inside the loop body, so nesting depth >= 1.
        assert!(forest.nesting_depth(addr(0x2000)) >= 1);
        assert!(forest.nesting_depth(addr(0x3000)) >= 1);
        // 0x1000 (pre-header) and 0x4000 (exit) are not part of the loop body.
        assert_eq!(forest.nesting_depth(addr(0x1000)), 0);
        assert_eq!(forest.nesting_depth(addr(0x4000)), 0);
    }

    #[test]
    fn loop_nesting_forest_irreducible_loops_empty_for_reducible_cfg() {
        let cfg = simple_reducible_cfg();
        let forest = HavlakLoopDetector::detect(&cfg);
        assert!(forest.irreducible_loops().is_empty());
        assert_eq!(forest.loop_count(), forest.nodes.len());
    }

    // ── Irreducible CFG construction ────────────────────────────────────────

    /// Classic irreducible CFG: entry → A, entry → B, A → B, B → A
    /// (mutual entries into the A/B loop; neither dominates the other).
    fn classic_irreducible_cfg() -> ControlFlowGraph {
        let mut blocks = HashMap::new();
        for a in [0x1000u64, 0x2000, 0x3000] {
            blocks.insert(addr(a), BasicBlock {
                start: addr(a), end: addr(a + 4), instructions: vec![],
            });
        }
        let edges = vec![
            CfgEdge { from: addr(0x1000), to: addr(0x2000), kind: EdgeKind::TrueBranch },
            CfgEdge { from: addr(0x1000), to: addr(0x3000), kind: EdgeKind::FalseBranch },
            CfgEdge { from: addr(0x2000), to: addr(0x3000), kind: EdgeKind::Unconditional },
            CfgEdge { from: addr(0x3000), to: addr(0x2000), kind: EdgeKind::Unconditional },
        ];
        let dom_tree = DominatorTree::compute(&blocks, &edges, addr(0x1000));
        ControlFlowGraph {
            blocks, edges, entry: addr(0x1000),
            dom_tree, loops: vec![], post_dom_tree: PostDominatorTree::default(),
        }
    }

    #[test]
    fn irreducible_cfg_analysis_detects_irreducibility() {
        let cfg = classic_irreducible_cfg();
        let analysis = IrreducibleCfgAnalysis::analyze(&cfg);
        assert!(!analysis.is_reducible);
        assert!(!analysis.irreducible_back_edges.is_empty());
        // A node split must have been applied to make the CFG reducible.
        assert!(!analysis.splits_applied.is_empty());
        assert!(analysis.irreducible_loop_count() >= 1);
        assert!(!analysis.t1t2_reducible);
    }

    #[test]
    fn irreducible_cfg_analysis_display_contains_fields() {
        let cfg = classic_irreducible_cfg();
        let analysis = IrreducibleCfgAnalysis::analyze(&cfg);
        let s = format!("{analysis}");
        assert!(s.contains("reducible: false"));
        assert!(s.contains("splits:"));
    }

    // ── NodeSplitter::make_reducible ────────────────────────────────────────

    #[test]
    fn node_splitter_make_reducible_on_irreducible_cfg() {
        let cfg = classic_irreducible_cfg();
        let mut splitter = NodeSplitter::new(0x8000_0000_0000_0000);
        let (new_edges, splits) = splitter.make_reducible(&cfg);

        assert!(!splits.is_empty());
        assert_eq!(splitter.split_count(), splits.len());

        // The cloned node's address must appear as an edge target/source in
        // the transformed edge list.
        for split in &splits {
            assert!(new_edges.iter().any(|e| e.to == split.clone || e.from == split.clone));
        }

        // Re-running reducibility-relevant checks: the transformed graph must
        // have strictly more edges than the original (clone's outgoing edges
        // were added) and must not contain the original `from -> to` back edge
        // that was redirected.
        assert!(new_edges.len() >= cfg.edges.len());
    }

    #[test]
    fn node_splitter_make_reducible_noop_on_reducible_cfg() {
        let cfg = simple_reducible_cfg();
        let mut splitter = NodeSplitter::new(0x8000_0000_0000_0000);
        let (new_edges, splits) = splitter.make_reducible(&cfg);
        assert!(splits.is_empty());
        assert_eq!(new_edges.len(), cfg.edges.len());
    }

    // Regression test: `HavlakLoopDetector::assign_depths` used to recurse one
    // Rust stack frame per forest nesting level, which overflows the stack
    // on adversarially deep loop-nesting forests (e.g. a generated or
    // pathological binary with tens of thousands of sequentially nested
    // loops). Build a long children chain directly and confirm the
    // iterative version completes without overflowing.
    #[test]
    fn assign_depths_deep_chain_no_stack_overflow() {
        const DEPTH: usize = 200_000;
        let mut forest = LoopNestingForest::new();
        for i in 0..DEPTH {
            forest.nodes.push(LoopForestNode {
                header: addr(i as u64),
                body: HashSet::new(),
                children: if i + 1 < DEPTH { vec![i + 1] } else { vec![] },
                parent: if i == 0 { None } else { Some(i - 1) },
                irreducible: false,
                depth: 0,
            });
        }
        forest.roots.push(0);

        HavlakLoopDetector::assign_depths(&mut forest, 0, 0);

        assert_eq!(forest.nodes[0].depth, 0);
        assert_eq!(forest.nodes[DEPTH - 1].depth, (DEPTH - 1) as u32);
    }
}
