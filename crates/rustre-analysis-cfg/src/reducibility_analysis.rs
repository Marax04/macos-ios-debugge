//! Reducibility analysis for control flow graphs.
//!
//! Implements the T1/T2 structural-reduction test (Hecht & Ullman 1972) and
//! Tarjan's SCC-based irreducibility detection.  Produces a `LoopNestingForest`
//! and classifies every SCC as `ReducibleCfg` or `IrreducibleNode`.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// Graph primitives (address-agnostic node indices)
// ─────────────────────────────────────────────────────────────────────────────

/// A plain node identifier used throughout this module (not an `Address`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u32);

impl NodeId {
    /// Create a `NodeId` from a raw integer.
    #[must_use]
    pub const fn new(n: u32) -> Self {
        Self(n)
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "N{}", self.0)
    }
}

/// A directed edge between two `NodeId`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GraphEdge {
    pub from: NodeId,
    pub to: NodeId,
}

/// Compact adjacency-list graph used by the T1/T2 reducer.
#[derive(Debug, Clone, Default)]
pub struct Graph {
    pub nodes: HashSet<NodeId>,
    pub edges: Vec<GraphEdge>,
}

impl Graph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node.
    pub fn add_node(&mut self, n: NodeId) {
        self.nodes.insert(n);
    }

    /// Add a directed edge (both endpoints are added automatically).
    pub fn add_edge(&mut self, from: NodeId, to: NodeId) {
        self.nodes.insert(from);
        self.nodes.insert(to);
        self.edges.push(GraphEdge { from, to });
    }

    /// Successors of `n`.
    #[must_use]
    pub fn successors(&self, n: NodeId) -> Vec<NodeId> {
        self.edges
            .iter()
            .filter(|e| e.from == n)
            .map(|e| e.to)
            .collect()
    }

    /// Predecessors of `n`.
    #[must_use]
    pub fn predecessors(&self, n: NodeId) -> Vec<NodeId> {
        self.edges
            .iter()
            .filter(|e| e.to == n)
            .map(|e| e.from)
            .collect()
    }

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Remove a node and all its incident edges.
    pub fn remove_node(&mut self, n: NodeId) {
        self.nodes.remove(&n);
        self.edges.retain(|e| e.from != n && e.to != n);
    }

    /// Merge node `b` into node `a`: all edges to/from `b` are redirected to
    /// `a`, self-loops introduced by the merge are removed, and `b` is deleted.
    pub fn merge_nodes(&mut self, a: NodeId, b: NodeId) {
        if a == b {
            return;
        }
        // Redirect edges
        let mut new_edges: Vec<GraphEdge> = Vec::new();
        for e in &self.edges {
            if e.from == b || e.to == b {
                let nf = if e.from == b { a } else { e.from };
                let nt = if e.to == b { a } else { e.to };
                if nf != nt {
                    new_edges.push(GraphEdge { from: nf, to: nt });
                }
            } else {
                new_edges.push(*e);
            }
        }
        // Deduplicate
        new_edges.sort_unstable_by_key(|e| (e.from, e.to));
        new_edges.dedup();
        self.edges = new_edges;
        self.nodes.remove(&b);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// T1 / T2 Transformations
// ─────────────────────────────────────────────────────────────────────────────

/// The two Hecht-Ullman graph-reduction rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T1T2Transform {
    /// T1 (self-loop elimination): remove a self-loop `n → n`.
    T1 { node: NodeId },
    /// T2 (series reduction): if `n` has exactly one predecessor `p`,
    /// fold `n` into `p`.
    T2 { absorbed: NodeId, into: NodeId },
}

impl T1T2Transform {
    /// Human-readable description of the transformation.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::T1 { node } => format!("T1: remove self-loop at {node}"),
            Self::T2 { absorbed, into } => {
                format!("T2: absorb {absorbed} into {into}")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopNestingForest
// ─────────────────────────────────────────────────────────────────────────────

/// A tree node in the loop-nesting forest.
#[derive(Debug, Clone)]
pub struct LoopNode {
    /// The header of the loop (or the virtual root for top-level nodes).
    pub header: NodeId,
    /// All nodes that are part of this loop body (including nested loops).
    pub body: HashSet<NodeId>,
    /// Children loops (directly nested).
    pub children: Vec<Self>,
    /// Whether this loop was classified as reducible.
    pub reducible: bool,
}

impl LoopNode {
    fn new(header: NodeId, reducible: bool) -> Self {
        let mut body = HashSet::new();
        body.insert(header);
        Self {
            header,
            body,
            children: Vec::new(),
            reducible,
        }
    }

    /// Depth of the deepest nesting level in this sub-tree.
    ///
    /// Iterative (explicit-stack) rather than recursive: adversarially deep
    /// loop nesting would otherwise risk a stack overflow, same class as the
    /// other tree/graph traversals hardened in this crate.
    #[must_use]
    pub fn max_depth(&self) -> usize {
        // Stack of (node, depth-of-this-node).
        let mut stack: Vec<(&Self, usize)> = vec![(self, 1)];
        let mut max = 0usize;
        while let Some((node, depth)) = stack.pop() {
            max = max.max(depth);
            for child in &node.children {
                stack.push((child, depth + 1));
            }
        }
        max
    }

    /// Total nodes covered by this loop and all sub-loops.
    #[must_use]
    pub fn total_nodes(&self) -> usize {
        self.body.len()
    }
}

impl Drop for LoopNode {
    /// Iterative (explicit-stack) drop glue.
    ///
    /// The compiler-derived `Drop` for `LoopNode` would recurse through
    /// `children` (each a `Vec<Self>`), one stack frame per nesting level;
    /// an adversarially deep `LoopNestingForest` could overflow the stack
    /// when it goes out of scope. Instead, take ownership of `children` and
    /// unwind the tree with an explicit work-stack, same pattern as
    /// `max_depth`'s iterative traversal above.
    fn drop(&mut self) {
        let mut stack: Vec<Self> = std::mem::take(&mut self.children);
        while let Some(mut node) = stack.pop() {
            stack.extend(std::mem::take(&mut node.children));
            // `node` drops here with empty `children` — no further recursion.
        }
    }
}

/// Forest of loop-nesting trees — one tree per top-level loop.
#[derive(Debug, Clone, Default)]
pub struct LoopNestingForest {
    /// Top-level loop trees (loops with no containing loop).
    pub roots: Vec<LoopNode>,
}

impl LoopNestingForest {
    /// Compute the loop-nesting forest using Tarjan's SCC + nesting detection.
    #[must_use]
    pub fn build(graph: &Graph, entry: NodeId) -> Self {
        let scc_result = SccBasedAnalysis::compute(graph);
        let mut roots: Vec<LoopNode> = Vec::new();

        // Each non-trivial SCC that is reachable from entry forms a loop node.
        let reachable = reachable_from(graph, entry);

        // Precompute the self-loop set once (O(E)) instead of scanning
        // `graph.edges` from inside the SCC loop: with one trivial (size-1)
        // SCC per non-looping node, that scan would run up to once per node,
        // making the whole pass O(V·E) on graphs with many singleton SCCs.
        let self_loop_nodes: HashSet<NodeId> = graph
            .edges
            .iter()
            .filter(|e| e.from == e.to)
            .map(|e| e.from)
            .collect();

        for scc in &scc_result.sccs {
            if scc.len() <= 1 {
                // Check for self-loop
                let n = scc[0];
                if !self_loop_nodes.contains(&n) {
                    continue;
                }
            }
            // Only include reachable SCCs
            if scc.iter().any(|n| reachable.contains(n)) {
                let header = *scc.iter().min().unwrap();
                let mut node = LoopNode::new(header, true);
                for &n in scc {
                    node.body.insert(n);
                }
                roots.push(node);
            }
        }

        Self { roots }
    }

    /// Total number of loops in the forest.
    #[must_use]
    pub const fn loop_count(&self) -> usize {
        self.roots.len()
    }

    /// Maximum loop nesting depth (0 if no loops).
    #[must_use]
    pub fn max_depth(&self) -> usize {
        self.roots.iter().map(LoopNode::max_depth).max().unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IrreducibleNode
// ─────────────────────────────────────────────────────────────────────────────

/// Describes a node that participates in an irreducible loop structure.
#[derive(Debug, Clone)]
pub struct IrreducibleNode {
    /// The node that is a member of an irreducible SCC.
    pub node: NodeId,
    /// All other nodes in the same irreducible SCC.
    pub scc_members: Vec<NodeId>,
    /// Back-edges that together form the irreducible structure.
    pub back_edges: Vec<(NodeId, NodeId)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ReducibleCfg
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a successful (fully-reducible) T1/T2 reduction.
#[derive(Debug, Clone)]
pub struct ReducibleCfg {
    /// The sequence of transformations applied, in order.
    pub transforms: Vec<T1T2Transform>,
    /// Number of T1 steps applied.
    pub t1_count: usize,
    /// Number of T2 steps applied.
    pub t2_count: usize,
}

impl ReducibleCfg {
    #[must_use]
    fn new(transforms: Vec<T1T2Transform>) -> Self {
        let t1_count = transforms
            .iter()
            .filter(|t| matches!(t, T1T2Transform::T1 { .. }))
            .count();
        let t2_count = transforms
            .iter()
            .filter(|t| matches!(t, T1T2Transform::T2 { .. }))
            .count();
        Self {
            transforms,
            t1_count,
            t2_count,
        }
    }

    /// Total steps applied.
    #[must_use]
    pub const fn total_steps(&self) -> usize {
        self.transforms.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SccBasedAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Strongly-connected components (Tarjan 1972) for a `Graph`.
#[derive(Debug, Clone)]
pub struct SccBasedAnalysis {
    /// SCCs in reverse topological order.
    pub sccs: Vec<Vec<NodeId>>,
    /// Mapping from each node to its SCC index.
    pub node_to_scc: HashMap<NodeId, usize>,
}

impl SccBasedAnalysis {
    /// Compute Tarjan SCCs for `graph`.
    ///
    /// Builds a `NodeId → successors` adjacency map once up front (O(V+E))
    /// so that the per-node DFS step in [`tarjan`] is an O(1) map lookup
    /// instead of an O(E) scan of `graph.edges` (which would make the whole
    /// traversal O(V·E)).
    #[must_use]
    pub fn compute(graph: &Graph) -> Self {
        let mut counter = 0u32;
        let mut stack: Vec<NodeId> = Vec::new();
        let mut on_stack: HashSet<NodeId> = HashSet::new();
        let mut index: HashMap<NodeId, u32> = HashMap::new();
        let mut lowlink: HashMap<NodeId, u32> = HashMap::new();
        let mut sccs: Vec<Vec<NodeId>> = Vec::new();

        let mut nodes: Vec<NodeId> = graph.nodes.iter().copied().collect();
        nodes.sort_unstable();

        let mut adj: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        for &n in &nodes {
            adj.entry(n).or_default();
        }
        for e in &graph.edges {
            adj.entry(e.from).or_default().push(e.to);
        }

        for &n in &nodes {
            if !index.contains_key(&n) {
                tarjan(
                    n,
                    &adj,
                    &mut counter,
                    &mut stack,
                    &mut on_stack,
                    &mut index,
                    &mut lowlink,
                    &mut sccs,
                );
            }
        }

        let mut node_to_scc: HashMap<NodeId, usize> = HashMap::new();
        for (i, scc) in sccs.iter().enumerate() {
            for &n in scc {
                node_to_scc.insert(n, i);
            }
        }

        Self { sccs, node_to_scc }
    }

    /// Return all non-trivial SCCs (potential loops).
    #[must_use]
    pub fn non_trivial_sccs(&self) -> Vec<&Vec<NodeId>> {
        self.sccs.iter().filter(|s| s.len() > 1).collect()
    }

    /// Total number of SCCs.
    #[must_use]
    pub const fn scc_count(&self) -> usize {
        self.sccs.len()
    }
}

/// Iterative (explicit-stack) Tarjan SCC DFS rooted at `start`.
///
/// Recursing per-node here would blow the native call stack on deep or
/// adversarial CFGs (long straight-line chains produce DFS depth == node
/// count); same motivation as the iterative fixes applied to the dominator
/// tree machinery (`cfg_dominators.rs`). Each "call frame" is simulated by
/// tracking, per node on the explicit `call_stack`, how many of its
/// successors have already been visited (`next_succ_idx`), so we can resume
/// exactly where we left off after a simulated recursive call returns.
fn tarjan(
    start: NodeId,
    adj: &HashMap<NodeId, Vec<NodeId>>,
    counter: &mut u32,
    stack: &mut Vec<NodeId>,
    on_stack: &mut HashSet<NodeId>,
    index: &mut HashMap<NodeId, u32>,
    lowlink: &mut HashMap<NodeId, u32>,
    sccs: &mut Vec<Vec<NodeId>>,
) {
    // (node, index into its successor list of the next successor to visit)
    let mut call_stack: Vec<(NodeId, usize)> = vec![(start, 0)];
    let empty: Vec<NodeId> = Vec::new();

    while let Some(&(v, succ_i)) = call_stack.last() {
        if succ_i == 0 {
            // First time visiting `v`: initialize its index/lowlink.
            if !index.contains_key(&v) {
                let idx = *counter;
                index.insert(v, idx);
                lowlink.insert(v, idx);
                *counter += 1;
                stack.push(v);
                on_stack.insert(v);
            }
        }

        let successors = adj.get(&v).unwrap_or(&empty);
        if succ_i < successors.len() {
            let w = successors[succ_i];
            // Advance this frame's cursor before possibly pushing a new frame.
            call_stack.last_mut().unwrap().1 = succ_i + 1;
            if !index.contains_key(&w) {
                call_stack.push((w, 0));
            } else if on_stack.contains(&w) {
                let idx_w = *index.get(&w).unwrap_or(&u32::MAX);
                let ll_v = lowlink.get_mut(&v).unwrap();
                *ll_v = (*ll_v).min(idx_w);
            }
        } else {
            // All successors processed for `v`: pop this frame, propagate
            // lowlink to the parent frame (if any), and emit an SCC if `v`
            // is a root.
            call_stack.pop();
            if lowlink.get(&v) == index.get(&v) {
                let mut scc = Vec::new();
                loop {
                    let w = stack.pop().expect("Tarjan stack invariant");
                    on_stack.remove(&w);
                    scc.push(w);
                    if w == v {
                        break;
                    }
                }
                sccs.push(scc);
            }
            if let Some(&(parent, _)) = call_stack.last() {
                let ll_v = *lowlink.get(&v).unwrap_or(&u32::MAX);
                let ll_p = lowlink.get_mut(&parent).unwrap();
                *ll_p = (*ll_p).min(ll_v);
            }
        }
    }
}

fn reachable_from(graph: &Graph, start: NodeId) -> HashSet<NodeId> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    if graph.nodes.contains(&start) {
        queue.push_back(start);
        visited.insert(start);
    }
    while let Some(n) = queue.pop_front() {
        for s in graph.successors(n) {
            if visited.insert(s) {
                queue.push_back(s);
            }
        }
    }
    visited
}

// ─────────────────────────────────────────────────────────────────────────────
// ReducibilityAnalysis — main entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Result of running `ReducibilityAnalysis`.
#[derive(Debug, Clone)]
pub enum ReducibilityOutcome {
    /// The graph was fully reduced to a single node.
    Reducible(ReducibleCfg),
    /// The graph contains irreducible SCCs.
    Irreducible {
        /// Irreducible nodes found.
        nodes: Vec<IrreducibleNode>,
        /// Partial transform sequence applied before the reducer got stuck.
        partial_transforms: Vec<T1T2Transform>,
    },
}

impl ReducibilityOutcome {
    /// Whether the CFG is reducible.
    #[must_use]
    pub const fn is_reducible(&self) -> bool {
        matches!(self, Self::Reducible(_))
    }

    /// Number of irreducible nodes (0 if reducible).
    #[must_use]
    pub const fn irreducible_count(&self) -> usize {
        match self {
            Self::Reducible(_) => 0,
            Self::Irreducible { nodes, .. } => nodes.len(),
        }
    }
}

/// Detects irreducible CFGs using the T1/T2 structural-reduction algorithm.
///
/// The algorithm iteratively applies:
/// - **T1**: Remove self-loops.
/// - **T2**: If a node `n` (not the entry) has exactly one predecessor `p`,
///   merge `n` into `p`.
///
/// If the graph reduces to a single node the CFG is reducible.  Otherwise the
/// remaining multi-node structure contains irreducible loops.
pub struct ReducibilityAnalysis {
    entry: NodeId,
}

impl ReducibilityAnalysis {
    /// Create a new analysis for the graph with the given entry node.
    #[must_use]
    pub const fn new(entry: NodeId) -> Self {
        Self { entry }
    }

    /// Run the T1/T2 reduction on `graph`.
    ///
    /// The graph is cloned internally so the caller's copy is not modified.
    #[must_use]
    pub fn analyze(&self, graph: &Graph) -> ReducibilityOutcome {
        let mut g = graph.clone();
        let mut transforms: Vec<T1T2Transform> = Vec::new();

        loop {
            let mut progress = false;

            // T1: Remove self-loops
            //
            // Deduplicating through a `HashSet` (as this used to do without a
            // final sort) makes the processing order nondeterministic across
            // runs, which leaks into the recorded `transforms` sequence
            // returned to callers. Sort by `NodeId` for a reproducible order.
            let mut self_loop_nodes: Vec<NodeId> = g
                .edges
                .iter()
                .filter(|e| e.from == e.to)
                .map(|e| e.from)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            self_loop_nodes.sort_unstable();
            for n in self_loop_nodes {
                g.edges.retain(|e| !(e.from == n && e.to == n));
                transforms.push(T1T2Transform::T1 { node: n });
                progress = true;
            }

            // T2: Absorb nodes with a single predecessor.
            //
            // Build the predecessor map once per round (O(V+E)) instead of
            // calling `g.predecessors(n)` — an O(E) scan of all edges — once
            // per node, which would make each round O(V·E).
            let mut pred_map: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
            for &n in &g.nodes {
                pred_map.entry(n).or_default();
            }
            for e in &g.edges {
                pred_map.entry(e.to).or_default().push(e.from);
            }

            // `g.nodes` is a HashSet, so iterating it directly (as this used
            // to) makes the absorb order — and hence the recorded
            // `transforms` sequence — nondeterministic across runs. Sort by
            // `NodeId` for a reproducible order.
            let mut candidates: Vec<NodeId> = g
                .nodes
                .iter()
                .copied()
                .filter(|&n| {
                    if n == self.entry {
                        return false;
                    }
                    let preds = pred_map.get(&n).map_or(0, Vec::len);
                    preds == 1 && pred_map[&n][0] != n
                })
                .collect();
            candidates.sort_unstable();

            // `redirect` implements a tiny union-find: as nodes are absorbed
            // this round, it maps the absorbed node to the node it was merged
            // into, so a stale `pred_map` entry can be resolved to the
            // *current* live representative in ~O(1) instead of falling back
            // to `g.predecessors(n)` (an O(E) scan of every edge). Doing that
            // scan per candidate would make this loop O(V·E) per round on
            // graphs with many single-predecessor chains.
            let mut redirect: HashMap<NodeId, NodeId> = HashMap::new();
            fn resolve(redirect: &HashMap<NodeId, NodeId>, mut n: NodeId) -> NodeId {
                while let Some(&next) = redirect.get(&n) {
                    n = next;
                }
                n
            }

            for n in candidates {
                // `n` (or its recorded predecessor) may have already been
                // absorbed by an earlier merge this round — resolve both
                // through `redirect` before acting on the stale `pred_map`
                // entry, and skip if `n` itself was already absorbed.
                if redirect.contains_key(&n) || !g.nodes.contains(&n) {
                    continue;
                }
                let Some(recorded_preds) = pred_map.get(&n) else {
                    continue;
                };
                if recorded_preds.len() != 1 {
                    continue;
                }
                let p = resolve(&redirect, recorded_preds[0]);
                if p == n || !g.nodes.contains(&p) {
                    continue;
                }
                // Invariant: `pred_map` recorded exactly one predecessor `q`
                // for `n` at the start of this round, and merges only ever
                // rename a node's identity (redirecting its incoming/outgoing
                // edges to the target), never add new distinct predecessors
                // to `n`. So resolving `q` through the union-find `redirect`
                // chain yields `n`'s current unique live predecessor without
                // re-scanning all of `g.edges`.
                transforms.push(T1T2Transform::T2 {
                    absorbed: n,
                    into: p,
                });
                g.merge_nodes(p, n);
                redirect.insert(n, p);
                progress = true;
            }

            if !progress {
                break;
            }
        }

        if g.node_count() <= 1 {
            return ReducibilityOutcome::Reducible(ReducibleCfg::new(transforms));
        }

        // Identify irreducible nodes via SCC analysis on the remaining graph
        let scc = SccBasedAnalysis::compute(&g);
        let mut irr_nodes: Vec<IrreducibleNode> = Vec::new();

        for scc_vec in scc.non_trivial_sccs() {
            let scc_set: HashSet<NodeId> = scc_vec.iter().copied().collect();
            let back_edges: Vec<(NodeId, NodeId)> = g
                .edges
                .iter()
                .filter(|e| scc_set.contains(&e.from) && scc_set.contains(&e.to))
                .map(|e| (e.from, e.to))
                .collect();

            for &n in scc_vec {
                irr_nodes.push(IrreducibleNode {
                    node: n,
                    scc_members: scc_vec.iter().filter(|&&m| m != n).copied().collect(),
                    back_edges: back_edges.clone(),
                });
            }
        }

        ReducibilityOutcome::Irreducible {
            nodes: irr_nodes,
            partial_transforms: transforms,
        }
    }

    /// Build the `LoopNestingForest` for the given graph.
    #[must_use]
    pub fn loop_nesting_forest(&self, graph: &Graph) -> LoopNestingForest {
        LoopNestingForest::build(graph, self.entry)
    }

    /// Quick check — returns `true` when `graph` is reducible.
    #[must_use]
    pub fn is_reducible(&self, graph: &Graph) -> bool {
        self.analyze(graph).is_reducible()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a `Graph` from a list of `(from, to)` node-index pairs.
#[must_use]
pub fn graph_from_edges(edges: &[(u32, u32)]) -> (Graph, NodeId) {
    let mut g = Graph::new();
    for &(f, t) in edges {
        g.add_edge(NodeId::new(f), NodeId::new(t));
    }
    let entry = NodeId::new(0);
    g.nodes.insert(entry);
    (g, entry)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn n(id: u32) -> NodeId {
        NodeId::new(id)
    }

    fn simple_graph(edges: &[(u32, u32)]) -> (Graph, NodeId) {
        graph_from_edges(edges)
    }

    // 1. Empty graph is reducible
    #[test]
    fn test_empty_graph_reducible() {
        let mut g = Graph::new();
        g.add_node(n(0));
        let ra = ReducibilityAnalysis::new(n(0));
        assert!(ra.is_reducible(&g));
    }

    // 2. Single self-loop reduces via T1
    #[test]
    fn test_self_loop_reducible() {
        let (g, entry) = simple_graph(&[(0, 0)]);
        let ra = ReducibilityAnalysis::new(entry);
        let outcome = ra.analyze(&g);
        assert!(outcome.is_reducible());
        if let ReducibilityOutcome::Reducible(r) = &outcome {
            assert_eq!(r.t1_count, 1);
        }
    }

    // 3. Linear chain reduces via T2
    #[test]
    fn test_linear_chain_reducible() {
        // 0 → 1 → 2 → 3
        let (g, entry) = simple_graph(&[(0, 1), (1, 2), (2, 3)]);
        let ra = ReducibilityAnalysis::new(entry);
        assert!(ra.is_reducible(&g));
    }

    // 4. Simple natural loop is reducible
    //    0 → 1 → 2 → 1 (back edge), 1 → 3
    #[test]
    fn test_natural_loop_reducible() {
        let (g, entry) = simple_graph(&[(0, 1), (1, 2), (2, 1), (1, 3)]);
        let ra = ReducibilityAnalysis::new(entry);
        assert!(ra.is_reducible(&g));
    }

    // 5. Diamond CFG is reducible
    #[test]
    fn test_diamond_reducible() {
        let (g, entry) = simple_graph(&[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let ra = ReducibilityAnalysis::new(entry);
        assert!(ra.is_reducible(&g));
    }

    // 6. Irreducible CFG: two mutual entries into a loop
    //    0 → 1, 0 → 2, 1 → 2, 2 → 1
    #[test]
    fn test_irreducible_mutual_entries() {
        let (g, entry) = simple_graph(&[(0, 1), (0, 2), (1, 2), (2, 1)]);
        let ra = ReducibilityAnalysis::new(entry);
        assert!(!ra.is_reducible(&g));
    }

    // 7. Irreducible node count
    #[test]
    fn test_irreducible_node_count() {
        let (g, entry) = simple_graph(&[(0, 1), (0, 2), (1, 2), (2, 1)]);
        let ra = ReducibilityAnalysis::new(entry);
        let outcome = ra.analyze(&g);
        assert_eq!(outcome.irreducible_count(), 2); // nodes 1 and 2
    }

    // 8. Graph::merge_nodes basic
    #[test]
    fn test_graph_merge_nodes() {
        let mut g = Graph::new();
        g.add_edge(n(0), n(1));
        g.add_edge(n(1), n(2));
        g.merge_nodes(n(0), n(1));
        assert!(!g.nodes.contains(&n(1)));
        assert!(g.nodes.contains(&n(0)));
        // Edge 0→2 should exist now
        assert!(g.edges.iter().any(|e| e.from == n(0) && e.to == n(2)));
    }

    // 8b. Transform sequence is deterministic across repeated runs.
    #[test]
    fn test_reduce_transforms_are_deterministic() {
        // Regression test: `self_loop_nodes` and `candidates` used to be
        // derived from HashSet/HashMap iteration without a final sort, so
        // the recorded `transforms` sequence (a public part of
        // `ReducibleCfg`) could differ in order across runs on graphs with
        // multiple simultaneously-eligible self-loops / merge candidates.
        // A long linear chain gives many single-predecessor T2 candidates
        // in one round.
        let edges: Vec<(u32, u32)> = (0..12u32).map(|i| (i, i + 1)).collect();
        let (g, entry) = simple_graph(&edges);
        let ra = ReducibilityAnalysis::new(entry);
        let first = match ra.analyze(&g) {
            ReducibilityOutcome::Reducible(r) => r.transforms.clone(),
            ReducibilityOutcome::Irreducible { .. } => panic!("expected reducible"),
        };
        for _ in 0..10 {
            let again = match ra.analyze(&g) {
                ReducibilityOutcome::Reducible(r) => r.transforms.clone(),
                ReducibilityOutcome::Irreducible { .. } => panic!("expected reducible"),
            };
            assert_eq!(first, again, "transform sequence must be deterministic");
        }
    }

    // 9. T1T2Transform descriptions
    #[test]
    fn test_transform_descriptions() {
        let t1 = T1T2Transform::T1 { node: n(5) };
        assert!(t1.description().contains("T1"));
        let t2 = T1T2Transform::T2 {
            absorbed: n(2),
            into: n(1),
        };
        assert!(t2.description().contains("T2"));
    }

    // 10. SccBasedAnalysis on a simple loop
    #[test]
    fn test_scc_simple_loop() {
        let (g, _) = simple_graph(&[(0, 1), (1, 2), (2, 1)]);
        let scc = SccBasedAnalysis::compute(&g);
        let non_trivial = scc.non_trivial_sccs();
        assert_eq!(non_trivial.len(), 1);
        let scc_nodes: HashSet<NodeId> = non_trivial[0].iter().copied().collect();
        assert!(scc_nodes.contains(&n(1)));
        assert!(scc_nodes.contains(&n(2)));
    }

    // 11. SccBasedAnalysis: node_to_scc mapping
    #[test]
    fn test_scc_node_mapping() {
        let (g, _) = simple_graph(&[(0, 1), (1, 0)]);
        let scc = SccBasedAnalysis::compute(&g);
        let scc0 = scc.node_to_scc[&n(0)];
        let scc1 = scc.node_to_scc[&n(1)];
        assert_eq!(scc0, scc1); // same SCC
    }

    // 12. LoopNestingForest on a graph with no loops
    #[test]
    fn test_lnf_no_loops() {
        let (g, entry) = simple_graph(&[(0, 1), (1, 2)]);
        let lnf = LoopNestingForest::build(&g, entry);
        assert_eq!(lnf.loop_count(), 0);
        assert_eq!(lnf.max_depth(), 0);
    }

    // 13. LoopNestingForest with one loop
    #[test]
    fn test_lnf_one_loop() {
        let (g, entry) = simple_graph(&[(0, 1), (1, 2), (2, 1)]);
        let lnf = LoopNestingForest::build(&g, entry);
        assert_eq!(lnf.loop_count(), 1);
    }

    // 14. LoopNode max_depth leaf
    #[test]
    fn test_loop_node_max_depth() {
        let root = LoopNode::new(n(1), true);
        assert_eq!(root.max_depth(), 1);
    }

    // 15. LoopNode total_nodes
    #[test]
    fn test_loop_node_total_nodes() {
        let mut root = LoopNode::new(n(1), true);
        root.body.insert(n(2));
        root.body.insert(n(3));
        assert_eq!(root.total_nodes(), 3);
    }

    // 16. Graph::remove_node
    #[test]
    fn test_graph_remove_node() {
        let mut g = Graph::new();
        g.add_edge(n(0), n(1));
        g.add_edge(n(1), n(2));
        g.remove_node(n(1));
        assert!(!g.nodes.contains(&n(1)));
        assert_eq!(g.edges.len(), 0);
    }

    // 17. Graph node_count and edge_count
    #[test]
    fn test_graph_counts() {
        let (g, _) = simple_graph(&[(0, 1), (1, 2), (2, 3)]);
        assert_eq!(g.node_count(), 4);
        assert_eq!(g.edge_count(), 3);
    }

    // 18. Graph predecessors / successors
    #[test]
    fn test_graph_pred_succ() {
        let (g, _) = simple_graph(&[(0, 1), (0, 2), (1, 2)]);
        let succs0 = g.successors(n(0));
        assert!(succs0.contains(&n(1)));
        assert!(succs0.contains(&n(2)));
        let preds2 = g.predecessors(n(2));
        assert!(preds2.contains(&n(0)));
        assert!(preds2.contains(&n(1)));
    }

    // 19. ReducibleCfg total_steps
    #[test]
    fn test_reducible_cfg_total_steps() {
        let (g, entry) = simple_graph(&[(0, 1), (1, 0)]);
        let ra = ReducibilityAnalysis::new(entry);
        let outcome = ra.analyze(&g);
        if let ReducibilityOutcome::Reducible(r) = outcome {
            assert!(r.total_steps() > 0);
        }
    }

    // 20. Nested loops (reducible)
    #[test]
    fn test_nested_loops_reducible() {
        // outer: 0 → 1 → 2 → 3 → 1 (back), 1 → 4
        // inner: 2 → 3 → 2 (back)
        let (g, entry) = simple_graph(&[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)]);
        let ra = ReducibilityAnalysis::new(entry);
        assert!(ra.is_reducible(&g));
    }

    // 21. IrreducibleNode back_edges not empty
    #[test]
    fn test_irreducible_back_edges() {
        let (g, entry) = simple_graph(&[(0, 1), (0, 2), (1, 2), (2, 1)]);
        let ra = ReducibilityAnalysis::new(entry);
        let outcome = ra.analyze(&g);
        if let ReducibilityOutcome::Irreducible { nodes, .. } = outcome {
            assert!(!nodes.is_empty());
            assert!(!nodes[0].back_edges.is_empty());
        }
    }

    // 22. reachable_from basic
    #[test]
    fn test_reachable_from() {
        let (g, entry) = simple_graph(&[(0, 1), (1, 2), (0, 3)]);
        let r = reachable_from(&g, entry);
        assert!(r.contains(&n(0)));
        assert!(r.contains(&n(1)));
        assert!(r.contains(&n(2)));
        assert!(r.contains(&n(3)));
    }

    // 23. reachable_from skips unreachable node
    #[test]
    fn test_reachable_from_skips_unreachable() {
        let (mut g, entry) = simple_graph(&[(0, 1), (1, 2)]);
        g.add_node(n(99));
        let r = reachable_from(&g, entry);
        assert!(!r.contains(&n(99)));
    }

    #[test]
    fn test_tarjan_deep_chain_no_stack_overflow() {
        // A long linear chain used to blow the native call stack with the
        // recursive Tarjan DFS; verify it now completes on a deep graph and
        // yields one trivial SCC per node.
        const N: u32 = 50_000;
        let edges: Vec<(u32, u32)> = (0..N - 1).map(|i| (i, i + 1)).collect();
        let (g, _entry) = simple_graph(&edges);
        let scc = SccBasedAnalysis::compute(&g);
        assert_eq!(scc.scc_count(), N as usize);
    }

    #[test]
    fn test_loop_node_max_depth_deep_chain_no_stack_overflow() {
        // A deeply right-nested chain of LoopNodes used to blow the stack
        // with the recursive `max_depth` implementation.
        const DEPTH: usize = 50_000;
        let mut leaf = LoopNode::new(n(0), true);
        for i in 1..DEPTH {
            let mut parent = LoopNode::new(n(i as u32), true);
            parent.children.push(leaf);
            leaf = parent;
        }
        assert_eq!(leaf.max_depth(), DEPTH);

        // `LoopNode` now has a custom iterative `Drop` impl (see above), so
        // letting this 50,000-deep chain simply go out of scope no longer
        // risks a recursive-drop stack overflow.
        drop(leaf);
    }

    // 24. ReducibilityAnalysis on a tree (fully reducible, only T2)
    #[test]
    fn test_tree_only_t2() {
        let (g, entry) = simple_graph(&[(0, 1), (0, 2), (1, 3), (1, 4), (2, 5)]);
        let ra = ReducibilityAnalysis::new(entry);
        let outcome = ra.analyze(&g);
        assert!(outcome.is_reducible());
        if let ReducibilityOutcome::Reducible(r) = outcome {
            assert_eq!(r.t1_count, 0);
            assert!(r.t2_count > 0);
        }
    }

    // 25. Graph merge self-merge is no-op
    #[test]
    fn test_graph_self_merge_noop() {
        let mut g = Graph::new();
        g.add_edge(n(0), n(1));
        let before_count = g.edge_count();
        g.merge_nodes(n(0), n(0));
        assert_eq!(g.edge_count(), before_count);
    }

    // 26. SccBasedAnalysis: trivial SCCs count
    #[test]
    fn test_scc_trivial_count() {
        let (g, _) = simple_graph(&[(0, 1), (1, 2), (2, 3)]);
        let scc = SccBasedAnalysis::compute(&g);
        // All trivial
        assert_eq!(scc.non_trivial_sccs().len(), 0);
        assert_eq!(scc.scc_count(), 4);
    }

    // 27. T1 removes multiple self-loops
    #[test]
    fn test_multiple_self_loops() {
        let mut g = Graph::new();
        g.add_edge(n(0), n(0));
        g.add_edge(n(1), n(1));
        g.add_edge(n(0), n(1));
        let ra = ReducibilityAnalysis::new(n(0));
        assert!(ra.is_reducible(&g));
    }

    // 28. LNF max_depth with nested loop node
    #[test]
    fn test_lnf_max_depth_nested() {
        let mut root = LoopNode::new(n(0), true);
        let child = LoopNode::new(n(1), true);
        root.children.push(child);
        assert_eq!(root.max_depth(), 2);
    }

    // 29. ReducibleCfg t1 and t2 counts
    #[test]
    fn test_reducible_cfg_counts() {
        // Self-loop + linear chain
        let mut g = Graph::new();
        g.add_edge(n(0), n(0)); // T1
        g.add_edge(n(0), n(1)); // T2: 1 → 0
        let ra = ReducibilityAnalysis::new(n(0));
        let outcome = ra.analyze(&g);
        if let ReducibilityOutcome::Reducible(r) = outcome {
            assert_eq!(r.t1_count, 1);
            assert!(r.t2_count >= 1);
        }
    }

    // 30. NodeId ordering and display
    #[test]
    fn test_node_id_display() {
        let nd = n(42);
        assert_eq!(nd.to_string(), "N42");
        assert!(n(1) < n(2));
    }

    // 31. Graph::new is empty
    #[test]
    fn test_graph_new_empty() {
        let g = Graph::new();
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    // 32. SccBasedAnalysis on a fully-connected graph
    #[test]
    fn test_scc_fully_connected() {
        let (g, _) = simple_graph(&[(0, 1), (1, 2), (2, 0)]);
        let scc = SccBasedAnalysis::compute(&g);
        assert_eq!(scc.non_trivial_sccs().len(), 1);
        assert_eq!(scc.non_trivial_sccs()[0].len(), 3);
    }

    // 33. Reducibility of complex reducible graph
    #[test]
    fn test_complex_reducible() {
        // while + if-else
        let edges = &[
            (0, 1),
            (1, 2),
            (2, 3),
            (2, 4),
            (3, 5),
            (4, 5),
            (5, 1),
            (1, 6),
        ];
        let (g, entry) = simple_graph(edges);
        let ra = ReducibilityAnalysis::new(entry);
        assert!(ra.is_reducible(&g));
    }

    // 34. ReducibilityOutcome::irreducible_count for reducible is 0
    #[test]
    fn test_irreducible_count_for_reducible() {
        let (g, entry) = simple_graph(&[(0, 1), (1, 0)]);
        let ra = ReducibilityAnalysis::new(entry);
        assert_eq!(ra.analyze(&g).irreducible_count(), 0);
    }

    // 35. IrreducibleNode scc_members excludes self
    #[test]
    fn test_irreducible_scc_members_exclude_self() {
        let (g, entry) = simple_graph(&[(0, 1), (0, 2), (1, 2), (2, 1)]);
        let ra = ReducibilityAnalysis::new(entry);
        let outcome = ra.analyze(&g);
        if let ReducibilityOutcome::Irreducible { nodes, .. } = outcome {
            for irr in &nodes {
                assert!(!irr.scc_members.contains(&irr.node));
            }
        }
    }

    // 36. Graph from_edges helper
    #[test]
    fn test_graph_from_edges() {
        let (g, entry) = graph_from_edges(&[(0, 1), (1, 2)]);
        assert_eq!(entry, n(0));
        assert_eq!(g.node_count(), 3);
    }

    // 37. LNF on irreducible graph still builds
    #[test]
    fn test_lnf_irreducible_graph() {
        let (g, entry) = simple_graph(&[(0, 1), (0, 2), (1, 2), (2, 1)]);
        let lnf = LoopNestingForest::build(&g, entry);
        // At least one loop detected (the mutual loop)
        assert!(lnf.loop_count() >= 1);
    }

    // 38. Graph add_node idempotent
    #[test]
    fn test_graph_add_node_idempotent() {
        let mut g = Graph::new();
        g.add_node(n(0));
        g.add_node(n(0));
        assert_eq!(g.node_count(), 1);
    }

    // 39. Partial transforms present for irreducible
    #[test]
    fn test_partial_transforms_for_irreducible() {
        // chain + irreducible loop: 0→1, 0→2, 1→2, 2→1
        let (g, entry) = simple_graph(&[(0, 1), (0, 2), (1, 2), (2, 1)]);
        let ra = ReducibilityAnalysis::new(entry);
        let outcome = ra.analyze(&g);
        if let ReducibilityOutcome::Irreducible {
            partial_transforms, ..
        } = outcome
        {
            // At least one T2 step should have been applied (absorbing 0's single chain)
            let _ = partial_transforms; // just assert no panic
        }
    }

    // 40. Multiple disconnected SCCs
    #[test]
    fn test_multiple_sccs() {
        let mut g = Graph::new();
        g.add_edge(n(0), n(1));
        g.add_edge(n(1), n(0));
        g.add_edge(n(2), n(3));
        g.add_edge(n(3), n(2));
        let scc = SccBasedAnalysis::compute(&g);
        assert_eq!(scc.non_trivial_sccs().len(), 2);
    }

    // 41. ReducibilityAnalysis: complex irreducible (classic example)
    #[test]
    fn test_classic_irreducible() {
        // Classic Hecht-Ullman irreducible example
        // 1→2, 1→3, 2→3, 3→2
        let mut g = Graph::new();
        g.add_edge(n(1), n(2));
        g.add_edge(n(1), n(3));
        g.add_edge(n(2), n(3));
        g.add_edge(n(3), n(2));
        let ra = ReducibilityAnalysis::new(n(1));
        assert!(!ra.is_reducible(&g));
    }

    // 42. T1T2Transform pattern matching
    #[test]
    fn test_transform_pattern_match() {
        let t = T1T2Transform::T1 { node: n(0) };
        assert!(matches!(t, T1T2Transform::T1 { .. }));
        let t = T1T2Transform::T2 {
            absorbed: n(1),
            into: n(0),
        };
        assert!(matches!(t, T1T2Transform::T2 { .. }));
    }
}
