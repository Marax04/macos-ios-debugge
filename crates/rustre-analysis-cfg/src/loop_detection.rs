//! Loop detection via Tarjan SCC decomposition and natural-loop extraction.
//!
//! This module provides:
//! - [`TarjanScc`]: iterative Tarjan SCC algorithm for CFGs.
//! - [`LoopTree`]: a tree where each node represents one natural loop and its
//!   children are immediately-nested loops.
//! - [`LoopForest`]: the forest of top-level loops (loops with no enclosing loop).
//! - Helper functions for SCC-to-loop mapping and nesting-depth computation.
//!
//! The entry point for most callers is [`detect_loops`], which returns a
//! fully-populated [`LoopForest`] from a CFG edge list.

use crate::{CfgEdge, DominatorTree};
use rustre_core::address::Address;
use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// SccNode — one strongly-connected component
// ─────────────────────────────────────────────────────────────────────────────

/// A strongly-connected component (SCC) of the CFG.
///
/// A trivial SCC (single node with no self-loop) is *not* a loop.
/// A non-trivial SCC (more than one node, or a single node with a self-edge)
/// represents a cycle and corresponds to a potential natural loop.
#[derive(Debug, Clone)]
pub struct SccNode {
    /// Nodes (block start addresses) in this SCC.
    pub members: Vec<Address>,
    /// `true` when this SCC contains more than one block, or a single block
    /// with a self-loop (i.e. it forms a cycle).
    pub is_cycle: bool,
    /// The *header* of the SCC — the block with the lowest DFS discovery time
    /// among all blocks reachable from the CFG entry.  For reducible CFGs this
    /// is the unique loop header; for irreducible regions it may be one of
    /// several entry nodes.
    pub header: Address,
}

impl SccNode {
    /// Number of blocks in this SCC.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.members.len()
    }

    /// Whether `addr` belongs to this SCC.
    #[must_use]
    pub fn contains(&self, addr: Address) -> bool {
        self.members.contains(&addr)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TarjanScc — iterative Tarjan SCC
// ─────────────────────────────────────────────────────────────────────────────

/// Iterative Tarjan SCC decomposition of a CFG.
///
/// All stack overflows are avoided by using an explicit work-stack.
pub struct TarjanScc {
    /// SCCs in reverse topological order of the condensation DAG (SCCs with
    /// no outgoing edges first).
    pub sccs: Vec<SccNode>,
    /// Maps each block address to the index of its SCC in `sccs`.
    pub scc_of: HashMap<Address, usize>,
}

impl TarjanScc {
    /// Compute SCCs for a CFG described by `blocks` and `edges`.
    ///
    /// `entry` is used to break ties when choosing the SCC header — the block
    /// closest in DFS order to `entry` wins.
    #[must_use]
    pub fn compute(blocks: &[Address], edges: &[CfgEdge], entry: Address) -> Self {
        // Build adjacency map.
        let mut adj: HashMap<Address, Vec<Address>> = HashMap::new();
        for &b in blocks {
            adj.entry(b).or_default();
        }
        for e in edges {
            adj.entry(e.from).or_default().push(e.to);
        }

        let n = blocks.len();
        let addr_to_idx: HashMap<Address, usize> =
            blocks.iter().enumerate().map(|(i, &a)| (a, i)).collect();

        let mut index: Vec<Option<u32>> = vec![None; n];
        let mut lowlink: Vec<u32> = vec![0; n];
        let mut on_stack: Vec<bool> = vec![false; n];
        let mut stack: Vec<usize> = Vec::new();
        let mut counter = 0u32;
        let mut raw_sccs: Vec<Vec<usize>> = Vec::new();

        // Iterative Tarjan using an explicit call-stack simulation.
        #[derive(Clone)]
        struct Frame {
            v: usize,
            child_iter: usize,
        }

        for start in 0..n {
            if index[start].is_some() {
                continue;
            }
            let mut call_stack: Vec<Frame> = vec![Frame {
                v: start,
                child_iter: 0,
            }];

            while let Some(frame) = call_stack.last_mut() {
                let v = frame.v;
                // First visit: initialize.
                if index[v].is_none() {
                    index[v] = Some(counter);
                    lowlink[v] = counter;
                    counter += 1;
                    stack.push(v);
                    on_stack[v] = true;
                }

                let addr_v = blocks[v];
                let children: Vec<Address> = adj.get(&addr_v).cloned().unwrap_or_default();
                let ci = frame.child_iter;

                if ci < children.len() {
                    frame.child_iter += 1;
                    let w_addr = children[ci];
                    if let Some(&w) = addr_to_idx.get(&w_addr) {
                        if index[w].is_none() {
                            // Tree edge — recurse.
                            call_stack.push(Frame {
                                v: w,
                                child_iter: 0,
                            });
                        } else if on_stack[w] {
                            // Back edge — update lowlink.
                            if index[w].unwrap() < lowlink[v] {
                                lowlink[v] = index[w].unwrap();
                            }
                        }
                    }
                } else {
                    // All children processed — check if root of SCC.
                    call_stack.pop();
                    if let Some(parent_frame) = call_stack.last() {
                        let u = parent_frame.v;
                        if lowlink[v] < lowlink[u] {
                            lowlink[u] = lowlink[v];
                        }
                    }
                    if lowlink[v] == index[v].unwrap() {
                        // Pop SCC from stack.
                        let mut scc = Vec::new();
                        loop {
                            let w = stack.pop().expect("Tarjan stack invariant");
                            on_stack[w] = false;
                            scc.push(w);
                            if w == v {
                                break;
                            }
                        }
                        raw_sccs.push(scc);
                    }
                }
            }
        }

        // Determine self-loop edges for single-node SCCs.
        let has_self_loop: HashSet<Address> = edges
            .iter()
            .filter(|e| e.from == e.to)
            .map(|e| e.from)
            .collect();

        // Pick header = block with smallest DFS discovery index (closest to entry).
        // We reuse the `index` array which holds discovery order.
        let entry_dfs = addr_to_idx
            .get(&entry)
            .and_then(|&i| index[i])
            .unwrap_or(u32::MAX);
        let _ = entry_dfs; // used conceptually; we minimise index[member].

        let mut scc_nodes = Vec::new();
        let mut scc_of: HashMap<Address, usize> = HashMap::new();

        for (scc_idx, members_local) in raw_sccs.iter().enumerate() {
            let members: Vec<Address> = members_local.iter().map(|&i| blocks[i]).collect();
            let is_cycle =
                members.len() > 1 || members.first().is_some_and(|a| has_self_loop.contains(a));

            // Header = member with the smallest DFS index.
            let header = members
                .iter()
                .min_by_key(|&&a| {
                    addr_to_idx
                        .get(&a)
                        .and_then(|&i| index[i])
                        .unwrap_or(u32::MAX)
                })
                .copied()
                .unwrap_or(entry);

            for &a in &members {
                scc_of.insert(a, scc_idx);
            }

            scc_nodes.push(SccNode {
                members,
                is_cycle,
                header,
            });
        }

        Self {
            sccs: scc_nodes,
            scc_of,
        }
    }

    /// All SCCs that are cycles (non-trivial or self-looping).
    #[must_use]
    pub fn cycle_sccs(&self) -> Vec<&SccNode> {
        self.sccs.iter().filter(|s| s.is_cycle).collect()
    }

    /// Total number of SCCs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.sccs.len()
    }

    /// Whether there are no SCCs.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sccs.is_empty()
    }

    /// SCC index for block `addr`, if it exists.
    #[must_use]
    pub fn scc_of(&self, addr: Address) -> Option<usize> {
        self.scc_of.get(&addr).copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NaturalLoopInfo — one natural loop
// ─────────────────────────────────────────────────────────────────────────────

/// All information about a single natural loop.
#[derive(Debug, Clone)]
pub struct NaturalLoopInfo {
    /// Loop header: the entry point of the loop (dominated by it).
    pub header: Address,
    /// Back-edge source(s): blocks with an edge back to `header`.
    pub latches: Vec<Address>,
    /// All blocks in the loop body, including header and latches.
    pub body: HashSet<Address>,
    /// Blocks outside the loop that are successors of loop blocks (exits).
    pub exits: Vec<Address>,
    /// Nesting depth: 0 = outermost loop.
    pub depth: usize,
    /// Whether this loop contains no other loop.
    pub is_innermost: bool,
}

impl NaturalLoopInfo {
    /// Whether `addr` is inside this loop body.
    #[must_use]
    pub fn contains(&self, addr: Address) -> bool {
        self.body.contains(&addr)
    }

    /// Number of blocks in the loop body.
    #[must_use]
    pub fn size(&self) -> usize {
        self.body.len()
    }

    /// Whether this loop has more than one latch (complex / multi-entry region).
    #[must_use]
    pub const fn is_multi_latch(&self) -> bool {
        self.latches.len() > 1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopTreeNode — one node in the nesting tree
// ─────────────────────────────────────────────────────────────────────────────

/// A node in the loop nesting tree.
#[derive(Debug, Clone)]
pub struct LoopTreeNode {
    /// The loop this node represents.
    pub info: NaturalLoopInfo,
    /// Indices of immediately-nested child loops within the [`LoopTree`].
    pub children: Vec<usize>,
    /// Index of the parent loop, or `None` for a top-level loop.
    pub parent: Option<usize>,
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopTree
// ─────────────────────────────────────────────────────────────────────────────

/// The complete loop nesting tree for a function.
///
/// Loops are stored in a flat `Vec`; parent-child relationships are encoded
/// via index references so that BFS/DFS traversal is O(n).
#[derive(Debug, Clone, Default)]
pub struct LoopTree {
    /// All loops, in discovery order (outer loops tend to appear before inner).
    pub nodes: Vec<LoopTreeNode>,
    /// Indices of top-level (outermost) loops with no parent.
    pub roots: Vec<usize>,
    /// Maps each block address to the index of its innermost enclosing loop.
    pub loop_of: HashMap<Address, usize>,
}

impl LoopTree {
    /// Build a `LoopTree` from a flat slice of [`NaturalLoopInfo`] values.
    ///
    /// Parent-child relationships are inferred by body containment: loop *A*
    /// is the parent of loop *B* iff *A.body* is the smallest body that
    /// strictly contains *B.body*.
    #[must_use]
    pub fn build(loops: Vec<NaturalLoopInfo>) -> Self {
        let n = loops.len();
        // Sort so that smaller bodies come first (inner loops).
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&i| loops[i].body.len());

        // For each loop find its immediate parent = smallest loop that
        // strictly contains it.
        let mut parent: Vec<Option<usize>> = vec![None; n];
        for &i in &order {
            for &j in &order {
                if i == j {
                    continue;
                }
                if loops[i].body.is_subset(&loops[j].body) && loops[i].body != loops[j].body {
                    // j strictly contains i.
                    match parent[i] {
                        None => parent[i] = Some(j),
                        Some(cur) => {
                            // Choose the smaller (tighter) parent.
                            if loops[j].body.len() < loops[cur].body.len() {
                                parent[i] = Some(j);
                            }
                        }
                    }
                }
            }
        }

        // Build children lists.
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut roots = Vec::new();
        for i in 0..n {
            match parent[i] {
                Some(p) => children[p].push(i),
                None => roots.push(i),
            }
        }

        // Assign depths via BFS from roots.
        let mut depths = vec![0usize; n];
        let mut bfs: VecDeque<usize> = roots.iter().copied().collect();
        while let Some(idx) = bfs.pop_front() {
            for &child in &children[idx] {
                depths[child] = depths[idx] + 1;
                bfs.push_back(child);
            }
        }

        // Build loop_of: each block mapped to its innermost loop.
        let mut loop_of: HashMap<Address, usize> = HashMap::new();
        // Process from innermost outward (smallest bodies first).
        for &i in &order {
            for &addr in &loops[i].body {
                // Only overwrite if this is a deeper (inner) loop.
                let should_update = match loop_of.get(&addr) {
                    None => true,
                    Some(&existing) => depths[i] > depths[existing],
                };
                if should_update {
                    loop_of.insert(addr, i);
                }
            }
        }

        let mut loop_infos = loops;
        // Patch depth and is_innermost.
        for i in 0..n {
            loop_infos[i].depth = depths[i];
            loop_infos[i].is_innermost = children[i].is_empty();
        }

        let nodes: Vec<LoopTreeNode> = (0..n)
            .map(|i| LoopTreeNode {
                info: loop_infos[i].clone(),
                children: children[i].clone(),
                parent: parent[i],
            })
            .collect();

        Self {
            nodes,
            roots,
            loop_of,
        }
    }

    /// Total number of natural loops.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether no loops were found.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Innermost loop containing `addr`, if any.
    #[must_use]
    pub fn innermost_loop_of(&self, addr: Address) -> Option<&NaturalLoopInfo> {
        self.loop_of.get(&addr).map(|&i| &self.nodes[i].info)
    }

    /// Nesting depth of `addr` (0 = not in any loop).
    #[must_use]
    pub fn nesting_depth(&self, addr: Address) -> usize {
        self.loop_of
            .get(&addr)
            .map_or(0, |&i| self.nodes[i].info.depth + 1)
    }

    /// Maximum nesting depth among all blocks.
    #[must_use]
    pub fn max_nesting_depth(&self) -> usize {
        self.nodes
            .iter()
            .map(|n| n.info.depth + 1)
            .max()
            .unwrap_or(0)
    }

    /// All loops that are innermost (no child loops).
    #[must_use]
    pub fn innermost_loops(&self) -> Vec<&NaturalLoopInfo> {
        self.nodes
            .iter()
            .filter(|n| n.children.is_empty())
            .map(|n| &n.info)
            .collect()
    }

    /// Walk the loop tree in pre-order (parent before children), returning
    /// references to all loop infos.
    #[must_use]
    pub fn preorder(&self) -> Vec<&NaturalLoopInfo> {
        let mut result = Vec::with_capacity(self.nodes.len());
        let mut stack: Vec<usize> = self.roots.clone();
        while let Some(idx) = stack.pop() {
            result.push(&self.nodes[idx].info);
            for &child in self.nodes[idx].children.iter().rev() {
                stack.push(child);
            }
        }
        result
    }

    /// Walk the loop tree in post-order (children before parent).
    #[must_use]
    pub fn postorder(&self) -> Vec<&NaturalLoopInfo> {
        let mut result = Vec::with_capacity(self.nodes.len());
        let mut stack: Vec<(usize, bool)> = self.roots.iter().map(|&i| (i, false)).collect();
        while let Some((idx, processed)) = stack.pop() {
            if processed {
                result.push(&self.nodes[idx].info);
            } else {
                stack.push((idx, true));
                for &child in self.nodes[idx].children.iter().rev() {
                    stack.push((child, false));
                }
            }
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopForest — public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// The full set of natural loops for a function, organised as a nesting forest.
#[derive(Debug, Clone, Default)]
pub struct LoopForest {
    /// Underlying nesting tree.
    pub tree: LoopTree,
    /// All block addresses the forest was built over (used to populate
    /// depth-0 entries in [`LoopDepthMap`] for blocks outside any loop).
    pub all_blocks: Vec<Address>,
}

impl LoopForest {
    /// Number of natural loops.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.tree.len()
    }

    /// Whether no loops were detected.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// All loops (flat slice).
    #[must_use]
    pub fn loops(&self) -> Vec<&NaturalLoopInfo> {
        self.tree.nodes.iter().map(|n| &n.info).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_loops — main public function
// ─────────────────────────────────────────────────────────────────────────────

/// Detect all natural loops in a CFG and return a [`LoopForest`].
///
/// Algorithm:
/// 1. Compute the dominator tree using Cooper et al. iterative algorithm.
/// 2. Find all back edges: `(from, to)` where `dom.dominates(to, from)`.
/// 3. For each back edge, BFS backwards from `from` up to `to` (the header)
///    to collect the loop body.
/// 4. Build a [`LoopTree`] from the flat list of bodies.
///
/// Works for both reducible and irreducible CFGs (irreducible regions produce
/// approximate natural loops based on the dominator tree).
#[must_use]
pub fn detect_loops(
    blocks: &[Address],
    edges: &[CfgEdge],
    entry: Address,
    dom: &DominatorTree,
) -> LoopForest {
    // Build predecessor adjacency.
    let mut preds: HashMap<Address, Vec<Address>> = HashMap::new();
    for &b in blocks {
        preds.entry(b).or_default();
    }
    for e in edges {
        preds.entry(e.to).or_default().push(e.from);
    }

    // Build successor adjacency for exit computation.
    let mut succs: HashMap<Address, Vec<Address>> = HashMap::new();
    for &b in blocks {
        succs.entry(b).or_default();
    }
    for e in edges {
        succs.entry(e.from).or_default().push(e.to);
    }

    // Find all back edges.
    let back_edges: Vec<(Address, Address)> = edges
        .iter()
        .filter(|e| dom.dominates(e.to, e.from))
        .map(|e| (e.from, e.to))
        .collect();

    if back_edges.is_empty() {
        return LoopForest {
            tree: LoopTree::default(),
            all_blocks: blocks.to_vec(),
        };
    }

    // Sanity: every back-edge header must be reachable from `entry` via the
    // dominator tree (otherwise it is a stray cycle in dead code). Drop any
    // back edges whose header is not dominated by — or equal to — entry.
    let back_edges: Vec<(Address, Address)> = back_edges
        .into_iter()
        .filter(|(_, header)| *header == entry || dom.dominates(entry, *header))
        .collect();

    if back_edges.is_empty() {
        return LoopForest {
            tree: LoopTree::default(),
            all_blocks: blocks.to_vec(),
        };
    }

    // Group back edges by header to merge multi-latch loops.
    let mut latches_by_header: HashMap<Address, Vec<Address>> = HashMap::new();
    for (latch, header) in &back_edges {
        latches_by_header.entry(*header).or_default().push(*latch);
    }

    let mut loop_infos: Vec<NaturalLoopInfo> = Vec::new();

    for (header, latches) in &latches_by_header {
        let header = *header;

        // Collect body via backward BFS from all latches up to header.
        let mut body: HashSet<Address> = HashSet::new();
        body.insert(header);
        let mut worklist: Vec<Address> = latches.clone();
        while let Some(node) = worklist.pop() {
            if body.insert(node) {
                for &pred in preds.get(&node).into_iter().flatten() {
                    if !body.contains(&pred) {
                        worklist.push(pred);
                    }
                }
            }
        }

        // Compute exit blocks.
        let exits: Vec<Address> = body
            .iter()
            .flat_map(|&b| succs.get(&b).into_iter().flatten().copied())
            .filter(|&succ| !body.contains(&succ))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        loop_infos.push(NaturalLoopInfo {
            header,
            latches: latches.clone(),
            body,
            exits,
            depth: 0,           // patched by LoopTree::build
            is_innermost: true, // patched by LoopTree::build
        });
    }

    LoopForest {
        tree: LoopTree::build(loop_infos),
        all_blocks: blocks.to_vec(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopDepthMap
// ─────────────────────────────────────────────────────────────────────────────

/// Precomputed nesting depth for each block in a function.
///
/// Depth 0 means the block is not inside any loop.
/// Depth *k* means the block is inside *k* nested loops.
#[derive(Debug, Clone, Default)]
pub struct LoopDepthMap {
    pub depths: HashMap<Address, usize>,
}

impl LoopDepthMap {
    /// Build a depth map from a [`LoopForest`].
    #[must_use]
    pub fn from_forest(forest: &LoopForest) -> Self {
        let mut depths: HashMap<Address, usize> = HashMap::new();
        for &addr in &forest.all_blocks {
            depths.entry(addr).or_insert(0);
        }
        for node in &forest.tree.nodes {
            for &addr in &node.info.body {
                let d = node.info.depth + 1;
                let e = depths.entry(addr).or_insert(0);
                if d > *e {
                    *e = d;
                }
            }
        }
        Self { depths }
    }

    /// Nesting depth of `addr` (0 = not in any loop).
    #[must_use]
    pub fn depth_of(&self, addr: Address) -> usize {
        self.depths.get(&addr).copied().unwrap_or(0)
    }

    /// Maximum depth in the entire function.
    #[must_use]
    pub fn max_depth(&self) -> usize {
        self.depths.values().copied().max().unwrap_or(0)
    }

    /// All blocks at exactly depth `d`.
    #[must_use]
    pub fn blocks_at_depth(&self, d: usize) -> Vec<Address> {
        self.depths
            .iter()
            .filter_map(|(&a, &depth)| if depth == d { Some(a) } else { None })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IrreducibleRegion — detect irreducibility
// ─────────────────────────────────────────────────────────────────────────────

/// Describes an irreducible region: a set of blocks that form cycles reachable
/// from multiple entry points (i.e. no single dominating header).
#[derive(Debug, Clone)]
pub struct IrreducibleRegion {
    /// All blocks in the irreducible region.
    pub members: Vec<Address>,
    /// Multiple entry points into the region.
    pub entries: Vec<Address>,
}

/// Find all irreducible regions in a CFG.
///
/// An SCC is irreducible when more than one of its blocks is reachable
/// directly from outside the SCC (i.e. it has more than one "entry" block).
#[must_use]
pub fn find_irreducible_regions(
    blocks: &[Address],
    edges: &[CfgEdge],
    entry: Address,
) -> Vec<IrreducibleRegion> {
    let scc = TarjanScc::compute(blocks, edges, entry);

    // For each SCC, find which of its members have a predecessor outside the SCC.
    let mut regions = Vec::new();

    for scc_node in scc.sccs.iter().filter(|s| s.is_cycle) {
        let members_set: HashSet<Address> = scc_node.members.iter().copied().collect();
        let mut entries_into_region: HashSet<Address> = HashSet::new();

        for e in edges {
            if !members_set.contains(&e.from) && members_set.contains(&e.to) {
                entries_into_region.insert(e.to);
            }
        }

        if entries_into_region.len() > 1 {
            // Multiple entries = irreducible region.
            let mut entries: Vec<Address> = entries_into_region.into_iter().collect();
            entries.sort_by_key(|a| a.as_u64());
            regions.push(IrreducibleRegion {
                members: scc_node.members.clone(),
                entries,
            });
        }
    }

    regions
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BasicBlock, DominatorTree, EdgeKind,
    };
    use std::collections::HashMap;

    fn a(n: u64) -> Address {
        Address::new(n)
    }

    fn make_dom(
        block_addrs: &[u64],
        raw_edges: &[(u64, u64)],
        entry: u64,
    ) -> (Vec<Address>, Vec<CfgEdge>, DominatorTree) {
        let blocks: HashMap<Address, BasicBlock> = block_addrs
            .iter()
            .map(|&n| {
                let addr = a(n);
                (
                    addr,
                    BasicBlock {
                        start: addr,
                        end: addr,
                        instructions: vec![],
                    },
                )
            })
            .collect();
        let edges: Vec<CfgEdge> = raw_edges
            .iter()
            .map(|&(f, t)| CfgEdge {
                from: a(f),
                to: a(t),
                kind: EdgeKind::Unconditional,
            })
            .collect();
        let dom = DominatorTree::compute(&blocks, &edges, a(entry));
        let block_addrs_v: Vec<Address> = block_addrs.iter().map(|&n| a(n)).collect();
        (block_addrs_v, edges, dom)
    }

    // ── TarjanScc ─────────────────────────────────────────────────────────

    #[test]
    fn tarjan_linear_no_cycles() {
        let blocks = vec![a(0), a(1), a(2)];
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
        ];
        let scc = TarjanScc::compute(&blocks, &edges, a(0));
        assert!(scc.cycle_sccs().is_empty(), "linear chain has no cycles");
        assert_eq!(scc.len(), 3);
    }

    #[test]
    fn tarjan_self_loop_is_cycle() {
        let blocks = vec![a(0), a(1)];
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(1),
                kind: EdgeKind::Unconditional,
            }, // self-loop
        ];
        let scc = TarjanScc::compute(&blocks, &edges, a(0));
        assert_eq!(scc.cycle_sccs().len(), 1);
    }

    #[test]
    fn tarjan_simple_back_edge() {
        // 0→1→2→1 (back edge 2→1).
        let blocks = vec![a(0), a(1), a(2), a(3)];
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(2),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(3),
                kind: EdgeKind::Unconditional,
            },
        ];
        let scc = TarjanScc::compute(&blocks, &edges, a(0));
        let cycles = scc.cycle_sccs();
        assert_eq!(cycles.len(), 1);
        assert!(cycles[0].contains(a(1)));
        assert!(cycles[0].contains(a(2)));
    }

    #[test]
    fn tarjan_nested_loops() {
        // outer: 0→1→2→3→2(back), 3→1(back), 1→4
        let blocks: Vec<Address> = [0u64, 1, 2, 3, 4].iter().map(|&n| a(n)).collect();
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(2),
                to: a(3),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(3),
                to: a(2),
                kind: EdgeKind::Unconditional,
            }, // inner back
            CfgEdge {
                from: a(3),
                to: a(1),
                kind: EdgeKind::Unconditional,
            }, // outer back
            CfgEdge {
                from: a(1),
                to: a(4),
                kind: EdgeKind::Unconditional,
            },
        ];
        let scc = TarjanScc::compute(&blocks, &edges, a(0));
        // All of {1,2,3} form one big SCC; {2,3} is absorbed into it.
        assert!(!scc.cycle_sccs().is_empty());
    }

    #[test]
    fn tarjan_scc_of_mapping() {
        let blocks = vec![a(0), a(1), a(2)];
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(2),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
        ];
        let scc = TarjanScc::compute(&blocks, &edges, a(0));
        let scc1 = scc.scc_of(a(1));
        let scc2 = scc.scc_of(a(2));
        assert!(scc1.is_some());
        assert_eq!(scc1, scc2, "1 and 2 are in the same SCC");
    }

    // ── detect_loops ──────────────────────────────────────────────────────

    #[test]
    fn detect_loops_no_loops() {
        let (blocks, edges, dom) = make_dom(&[0, 1, 2], &[(0, 1), (1, 2)], 0);
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        assert!(forest.is_empty());
    }

    #[test]
    fn detect_loops_simple_while() {
        let (blocks, edges, dom) = make_dom(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (1, 3)], 0);
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        assert_eq!(forest.len(), 1);
        let lp = &forest.loops()[0];
        assert_eq!(lp.header, a(1));
        assert!(lp.body.contains(&a(2)));
        assert!(lp.exits.contains(&a(3)));
    }

    #[test]
    fn detect_loops_nested() {
        let (blocks, edges, dom) = make_dom(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        assert_eq!(forest.len(), 2, "expected outer and inner loop");
        let inner = forest.loops().into_iter().find(|l| l.header == a(2));
        let outer = forest.loops().into_iter().find(|l| l.header == a(1));
        assert!(inner.is_some(), "inner loop header at 2");
        assert!(outer.is_some(), "outer loop header at 1");
    }

    #[test]
    fn detect_loops_self_loop() {
        let (blocks, edges, dom) = make_dom(&[0, 1], &[(0, 1), (1, 1)], 0);
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        assert_eq!(forest.len(), 1);
        assert!(forest.loops()[0].body.contains(&a(1)));
    }

    // ── LoopTree ──────────────────────────────────────────────────────────

    #[test]
    fn loop_tree_nesting_depth() {
        let (blocks, edges, dom) = make_dom(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        let tree = &forest.tree;
        assert_eq!(tree.max_nesting_depth(), 2);
        // Block 3 is in both inner and outer loops → depth 2.
        let d3 = tree.nesting_depth(a(3));
        assert_eq!(d3, 2);
    }

    #[test]
    fn loop_tree_innermost_only_flag() {
        let (blocks, edges, dom) = make_dom(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        let innermost: Vec<_> = forest.tree.innermost_loops();
        assert!(!innermost.is_empty());
        // The inner loop (header=2) should be innermost.
        assert!(innermost.iter().any(|l| l.header == a(2)));
    }

    #[test]
    fn loop_depth_map_correct() {
        let (blocks, edges, dom) = make_dom(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        let map = LoopDepthMap::from_forest(&forest);
        assert_eq!(map.depth_of(a(0)), 0); // not in any loop
        assert!(map.depth_of(a(2)) >= 1); // in at least the inner loop
        assert!(map.max_depth() >= 2);
    }

    // ── LoopTree traversal ────────────────────────────────────────────────

    #[test]
    fn loop_tree_preorder_visits_all() {
        let (blocks, edges, dom) = make_dom(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        let pre = forest.tree.preorder();
        assert_eq!(pre.len(), forest.len());
    }

    #[test]
    fn loop_tree_postorder_children_before_parent() {
        let (blocks, edges, dom) = make_dom(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        let post = forest.tree.postorder();
        // Inner loop (header=2) should appear before outer loop (header=1).
        if let (Some(i_inner), Some(i_outer)) = (
            post.iter().position(|l| l.header == a(2)),
            post.iter().position(|l| l.header == a(1)),
        ) {
            assert!(i_inner < i_outer, "inner before outer in postorder");
        }
    }

    // ── Irreducible region detection ──────────────────────────────────────

    #[test]
    fn find_irreducible_empty_on_reducible() {
        let blocks: Vec<Address> = [0u64, 1, 2, 3].iter().map(|&n| a(n)).collect();
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(2),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(3),
                kind: EdgeKind::Unconditional,
            },
        ];
        let regions = find_irreducible_regions(&blocks, &edges, a(0));
        assert!(
            regions.is_empty(),
            "reducible CFG has no irreducible regions"
        );
    }

    #[test]
    fn find_irreducible_detects_multi_entry_region() {
        // 0→1, 0→2, 1→2, 2→1 — {1,2} form a cycle with two entries (1 from 0 and 2 from 0).
        let blocks: Vec<Address> = [0u64, 1, 2].iter().map(|&n| a(n)).collect();
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(0),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(2),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
        ];
        let regions = find_irreducible_regions(&blocks, &edges, a(0));
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].entries.len(), 2);
    }

    // ── NaturalLoopInfo ───────────────────────────────────────────────────

    #[test]
    fn natural_loop_multi_latch_flag() {
        // Two back edges to the same header.
        let (blocks, edges, dom) = make_dom(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 1), (1, 3), (3, 1), (1, 4)],
            0,
        );
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        let lp = forest.loops().into_iter().find(|l| l.header == a(1));
        assert!(lp.is_some());
        let lp = lp.unwrap();
        assert!(lp.is_multi_latch(), "two latches expected");
    }

    #[test]
    fn loop_tree_roots_are_outermost() {
        let (blocks, edges, dom) = make_dom(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        for &root_idx in &forest.tree.roots {
            let node = &forest.tree.nodes[root_idx];
            assert_eq!(node.info.depth, 0, "root loops have depth 0");
            assert!(node.parent.is_none(), "root loops have no parent");
        }
    }

    #[test]
    fn tarjan_empty_graph() {
        let scc = TarjanScc::compute(&[], &[], a(0));
        assert!(scc.is_empty());
    }

    #[test]
    fn tarjan_single_node_no_self_loop() {
        let blocks = vec![a(0)];
        let scc = TarjanScc::compute(&blocks, &[], a(0));
        assert_eq!(scc.len(), 1);
        assert!(scc.cycle_sccs().is_empty());
    }

    #[test]
    fn scc_node_size_and_contains() {
        let blocks = vec![a(0), a(1), a(2)];
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(2),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
        ];
        let scc = TarjanScc::compute(&blocks, &edges, a(0));
        let cycle = scc.cycle_sccs()[0];
        assert_eq!(cycle.size(), 2);
        assert!(cycle.contains(a(1)));
        assert!(cycle.contains(a(2)));
        assert!(!cycle.contains(a(0)));

        // Trivial (non-cycle) SCC has size 1.
        let trivial = scc.sccs.iter().find(|s| !s.is_cycle).unwrap();
        assert_eq!(trivial.size(), 1);
    }

    #[test]
    fn natural_loop_info_size_and_contains() {
        let (blocks, edges, dom) = make_dom(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (1, 3)], 0);
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        let lp = &forest.loops()[0];
        assert_eq!(lp.size(), lp.body.len());
        assert!(lp.contains(a(1)));
        assert!(lp.contains(a(2)));
        assert!(!lp.contains(a(3)), "exit block must not be in the loop body");
    }

    #[test]
    fn loop_tree_innermost_loop_of() {
        let (blocks, edges, dom) = make_dom(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        // Block 2 is inside both loops -> innermost is the header=2 loop.
        let inner = forest.tree.innermost_loop_of(a(2));
        assert!(inner.is_some());
        assert_eq!(inner.unwrap().header, a(2));

        // Block 0 is not in any loop.
        assert!(forest.tree.innermost_loop_of(a(0)).is_none());
    }

    #[test]
    fn loop_depth_map_blocks_at_depth() {
        let (blocks, edges, dom) = make_dom(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (1, 3)], 0);
        let forest = detect_loops(&blocks, &edges, a(0), &dom);
        let map = LoopDepthMap::from_forest(&forest);
        let at1 = map.blocks_at_depth(1);
        assert!(at1.contains(&a(1)) || at1.contains(&a(2)));
        let at0 = map.blocks_at_depth(0);
        assert!(at0.contains(&a(0)));
    }
}
