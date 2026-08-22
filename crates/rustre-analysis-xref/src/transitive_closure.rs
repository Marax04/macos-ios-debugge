//! Transitive closure computation for cross-reference graphs.
//!
//! Provides:
//! - Floyd-Warshall for small graphs.
//! - BFS-based reachability sets.
//! - Tarjan's SCC algorithm.
//! - Call-graph transitive closure.
//! - Shortest-path xref chains.
//!
//! ## Consumer status (audited 2026-07-12)
//!
//! This entire module — including its own [`DiGraph`]/[`TransitiveClosure`]
//! types — has **zero consumers** anywhere else in this crate or in any
//! external workspace crate; only its own tests exercise it. The type that
//! actually backs [`crate::XrefQueryEngine::closure`] and is re-exported at
//! the crate root (`rustre_analysis_xref::TransitiveClosure`) is the
//! same-named but independently-implemented [`crate::xref_query::TransitiveClosure`].
//! Kept in place (not deleted) pending explicit user sign-off — see the
//! module-doc note on `xref_query::TransitiveClosure` for the reverse
//! cross-reference.

use std::collections::{HashMap, HashSet, VecDeque};
use crate::XrefKind;

// ── Graph representation ──────────────────────────────────────────────────────

/// A directed graph stored as an adjacency map.
#[derive(Debug, Clone, Default)]
pub struct DiGraph {
    /// `node_id` → set of successor `node_ids`.
    pub edges: HashMap<u64, HashSet<u64>>,
}

impl DiGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_edge(&mut self, from: u64, to: u64) {
        self.edges.entry(from).or_default().insert(to);
        // Ensure `to` has an entry even if it has no outgoing edges.
        self.edges.entry(to).or_default();
    }

    #[must_use] 
    pub fn node_count(&self) -> usize {
        self.edges.len()
    }

    #[must_use] 
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(std::collections::HashSet::len).sum()
    }

    pub fn successors(&self, node: u64) -> impl Iterator<Item = u64> + '_ {
        self.edges
            .get(&node)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }

    #[must_use] 
    pub fn predecessors(&self, node: u64) -> Vec<u64> {
        self.edges
            .iter()
            .filter(|(_, succs)| succs.contains(&node))
            .map(|(&n, _)| n)
            .collect()
    }

    pub fn nodes(&self) -> impl Iterator<Item = u64> + '_ {
        self.edges.keys().copied()
    }

    #[must_use] 
    pub fn has_edge(&self, from: u64, to: u64) -> bool {
        self.edges.get(&from).is_some_and(|s| s.contains(&to))
    }
}

// ── TransitiveClosure ─────────────────────────────────────────────────────────

/// Floyd-Warshall transitive closure for small graphs (≤ 1000 nodes).
///
/// Stores a boolean reachability matrix.
///
/// # Naming collision (audited, not a bug)
///
/// This crate also defines [`crate::xref_query::TransitiveClosure`], a
/// separate, unrelated type operating on `CallGraph`/`Address` with a
/// BFS/topo-order O(V·E) algorithm, and that is the one re-exported at the
/// crate root (`crate::TransitiveClosure`) — this `DiGraph`-based,
/// `u64`-keyed, Floyd-Warshall O(V³) type is only reachable via the fully
/// qualified `transitive_closure::TransitiveClosure` path and is not used
/// anywhere else in this crate today. The two are never mixed up by the
/// compiler (different concrete types), so there is no type-confusion risk,
/// but the shared name is confusing for readers/greppers — do not assume
/// `TransitiveClosure` always means this one. Left in place (not dead code:
/// it is public API) per repo policy against deleting pre-existing code.
pub struct TransitiveClosure {
    nodes: Vec<u64>,
    index: HashMap<u64, usize>,
    /// reach[i][j] = true if j is reachable from i.
    reach: Vec<Vec<bool>>,
}

impl TransitiveClosure {
    /// Compute transitive closure using Floyd-Warshall.
    #[must_use] 
    pub fn compute(graph: &DiGraph) -> Self {
        let nodes: Vec<u64> = {
            let mut v: Vec<u64> = graph.edges.keys().copied().collect();
            v.sort_unstable();
            v
        };
        let n = nodes.len();
        let index: HashMap<u64, usize> = nodes.iter().enumerate().map(|(i, &id)| (id, i)).collect();

        let mut reach = vec![vec![false; n]; n];
        // Initialize direct edges.
        for (&from, succs) in &graph.edges {
            if let Some(&fi) = index.get(&from) {
                for &to in succs {
                    if let Some(&ti) = index.get(&to) {
                        reach[fi][ti] = true;
                    }
                }
                // NOTE: the diagonal is deliberately NOT force-set here. The
                // matrix stores pure (non-reflexive) transitive reachability,
                // so `reach[i][i]` is true only when node `i` lies on a real
                // cycle (or has a self-loop). `is_reachable` layers the
                // documented reflexive view on top; `reachable_from` /
                // `can_reach` need the pure matrix to honour their
                // "excluding itself unless there's a cycle" contract.
            }
        }

        // Floyd-Warshall.
        for k in 0..n {
            for i in 0..n {
                for j in 0..n {
                    if reach[i][k] && reach[k][j] {
                        reach[i][j] = true;
                    }
                }
            }
        }

        Self {
            nodes,
            index,
            reach,
        }
    }

    /// Return `true` if `target` is reachable from `source`.
    ///
    /// Reflexive: a known node always reaches itself.
    #[must_use]
    pub fn is_reachable(&self, source: u64, target: u64) -> bool {
        match (self.index.get(&source), self.index.get(&target)) {
            (Some(&si), Some(&ti)) => si == ti || self.reach[si][ti],
            _ => false,
        }
    }

    /// Return all nodes reachable from `source` (excluding itself unless there's a cycle).
    #[must_use] 
    pub fn reachable_from(&self, source: u64) -> Vec<u64> {
        if let Some(&si) = self.index.get(&source) {
            self.nodes
                .iter()
                .enumerate()
                .filter(|(ti, _)| self.reach[si][*ti])
                .map(|(_, &n)| n)
                .collect()
        } else {
            vec![]
        }
    }

    /// Return all nodes that can reach `target`.
    #[must_use] 
    pub fn can_reach(&self, target: u64) -> Vec<u64> {
        if let Some(&ti) = self.index.get(&target) {
            self.nodes
                .iter()
                .enumerate()
                .filter(|(si, _)| self.reach[*si][ti])
                .map(|(_, &n)| n)
                .collect()
        } else {
            vec![]
        }
    }

    #[must_use] 
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

// ── ReachabilitySet ───────────────────────────────────────────────────────────

/// Per-node reachability set computed by BFS.
#[derive(Debug, Clone, Default)]
pub struct ReachabilitySet {
    pub sets: HashMap<u64, HashSet<u64>>,
}

impl ReachabilitySet {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute BFS reachability for every node in the graph.
    #[must_use] 
    pub fn compute(graph: &DiGraph) -> Self {
        let mut sets: HashMap<u64, HashSet<u64>> = HashMap::new();
        for &start in graph.edges.keys() {
            sets.insert(start, BfsReachability::bfs_reachable(graph, start));
        }
        Self { sets }
    }

    #[must_use] 
    pub fn reachable_from(&self, node: u64) -> Option<&HashSet<u64>> {
        self.sets.get(&node)
    }

    #[must_use] 
    pub fn is_reachable(&self, from: u64, to: u64) -> bool {
        self.sets.get(&from).is_some_and(|s| s.contains(&to))
    }
}

// ── BfsReachability ───────────────────────────────────────────────────────────

/// BFS-based reachability queries.
pub struct BfsReachability;

impl BfsReachability {
    /// Return all nodes reachable from `start` using BFS.
    #[must_use] 
    pub fn bfs_reachable(graph: &DiGraph, start: u64) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited.insert(start);
        while let Some(node) = queue.pop_front() {
            for succ in graph.successors(node) {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
        visited
    }

    /// Return the shortest path from `start` to `goal` using BFS.
    /// Returns `None` if no path exists.
    ///
    /// # Panics
    /// Panics if the internal BFS path queue yields an empty path (should never happen).
    #[must_use]
    pub fn shortest_path(graph: &DiGraph, start: u64, goal: u64) -> Option<Vec<u64>> {
        if start == goal {
            return Some(vec![start]);
        }
        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<Vec<u64>> = VecDeque::new();
        queue.push_back(vec![start]);
        visited.insert(start);
        while let Some(path) = queue.pop_front() {
            let last = *path.last().unwrap();
            for succ in graph.successors(last) {
                if succ == goal {
                    let mut p = path;
                    p.push(goal);
                    return Some(p);
                }
                if visited.insert(succ) {
                    let mut p = path.clone();
                    p.push(succ);
                    queue.push_back(p);
                }
            }
        }
        None
    }
}

// ── SccDecomposition ─────────────────────────────────────────────────────────

/// Tarjan's SCC algorithm.
#[derive(Debug, Clone)]
pub struct SccDecomposition {
    pub sccs: Vec<Vec<u64>>,
}

struct TarjanSccState<'a> {
    graph: &'a DiGraph,
    index_counter: usize,
    stack: Vec<u64>,
    on_stack: HashSet<u64>,
    indices: HashMap<u64, usize>,
    lowlinks: HashMap<u64, usize>,
    sccs: Vec<Vec<u64>>,
}

impl<'a> TarjanSccState<'a> {
    fn new(graph: &'a DiGraph) -> Self {
        Self {
            graph,
            index_counter: 0,
            stack: Vec::new(),
            on_stack: HashSet::new(),
            indices: HashMap::new(),
            lowlinks: HashMap::new(),
            sccs: Vec::new(),
        }
    }

    /// Iterative Tarjan SCC — avoids stack overflow on large graphs.
    ///
    /// Each entry on the work stack is `(node, successor_index)`.  When
    /// `successor_index == 0` we perform the "first visit" initialisation;
    /// when it equals the neighbor count we perform the "post-visit" SCC-root
    /// check.  In between we step through each successor one at a time,
    /// mirroring the recursive descent without consuming OS stack frames.
    fn strongconnect(&mut self, start: u64) {
        // Work stack: (node, next_successor_index_to_process, precomputed_neighbors)
        let mut work: Vec<(u64, usize, Vec<u64>)> = Vec::new();

        // Initialise the start node.
        self.visit_node(start);
        let start_neighbors: Vec<u64> = self.graph.successors(start).collect();
        work.push((start, 0, start_neighbors));

        while let Some((v, succ_idx, neighbors)) = work.last_mut() {
            let v = *v;
            if *succ_idx < neighbors.len() {
                let w = neighbors[*succ_idx];
                *succ_idx += 1;

                if !self.indices.contains_key(&w) {
                    // Tree edge: push w and process it next.
                    self.visit_node(w);
                    let w_neighbors: Vec<u64> = self.graph.successors(w).collect();
                    work.push((w, 0, w_neighbors));
                } else if self.on_stack.contains(&w) {
                    // Back/cross edge to an on-stack node.
                    let w_idx = self.indices[&w];
                    let vll = self.lowlinks.get_mut(&v).unwrap();
                    if w_idx < *vll {
                        *vll = w_idx;
                    }
                }
                // else: already fully visited, ignore
            } else {
                // All successors processed — pop and propagate lowlink upward.
                work.pop();
                if let Some((parent, _, _)) = work.last() {
                    let vll = self.lowlinks[&v];
                    let pll = self.lowlinks.get_mut(parent).unwrap();
                    if vll < *pll {
                        *pll = vll;
                    }
                }
                // Check if v is an SCC root.
                if self.lowlinks[&v] == self.indices[&v] {
                    let mut scc = Vec::new();
                    loop {
                        let w = self.stack.pop().unwrap();
                        self.on_stack.remove(&w);
                        scc.push(w);
                        if w == v {
                            break;
                        }
                    }
                    self.sccs.push(scc);
                }
            }
        }
    }

    /// Assign an index/lowlink to `node` and push it onto the Tarjan stack.
    fn visit_node(&mut self, node: u64) {
        let idx = self.index_counter;
        self.indices.insert(node, idx);
        self.lowlinks.insert(node, idx);
        self.index_counter += 1;
        self.stack.push(node);
        self.on_stack.insert(node);
    }
}

impl SccDecomposition {
    /// Compute SCCs using Tarjan's algorithm.
    #[must_use]
    pub fn compute(graph: &DiGraph) -> Self {
        let nodes: Vec<u64> = {
            let mut v: Vec<u64> = graph.edges.keys().copied().collect();
            v.sort_unstable();
            v
        };

        let mut state = TarjanSccState::new(graph);
        for &v in &nodes {
            if !state.indices.contains_key(&v) {
                state.strongconnect(v);
            }
        }

        Self { sccs: state.sccs }
    }

    /// Return `true` if `a` and `b` are in the same SCC.
    #[must_use] 
    pub fn same_scc(&self, a: u64, b: u64) -> bool {
        self.sccs
            .iter()
            .any(|scc| scc.contains(&a) && scc.contains(&b))
    }

    /// Return the SCC containing `node`, or `None`.
    #[must_use] 
    pub fn scc_of(&self, node: u64) -> Option<&Vec<u64>> {
        self.sccs.iter().find(|scc| scc.contains(&node))
    }

    /// Number of non-trivial SCCs (size > 1).
    #[must_use] 
    pub fn non_trivial_count(&self) -> usize {
        self.sccs.iter().filter(|scc| scc.len() > 1).count()
    }
}

// ── CallGraphClosure ──────────────────────────────────────────────────────────

/// Computes transitive caller/callee sets for a call graph.
pub struct CallGraphClosure {
    pub call_graph: DiGraph,
    pub reachability: ReachabilitySet,
}

impl CallGraphClosure {
    #[must_use] 
    pub fn new(call_graph: DiGraph) -> Self {
        let reachability = ReachabilitySet::compute(&call_graph);
        Self {
            call_graph,
            reachability,
        }
    }

    /// Return all functions transitively called by `func`.
    #[must_use] 
    pub fn all_callees(&self, func: u64) -> HashSet<u64> {
        let mut callees = self
            .reachability
            .reachable_from(func)
            .cloned()
            .unwrap_or_default();
        callees.remove(&func);
        callees
    }

    /// Return all functions that transitively call `func`.
    #[must_use] 
    pub fn all_callers(&self, func: u64) -> HashSet<u64> {
        let mut callers = HashSet::new();
        for (&node, reach_set) in &self.reachability.sets {
            if node != func && reach_set.contains(&func) {
                callers.insert(node);
            }
        }
        callers
    }

    /// Return the shortest call chain from `from_fn` to `to_fn`.
    #[must_use]
    pub fn call_chain(&self, from_fn: u64, to_fn: u64) -> Option<XrefChain> {
        BfsReachability::shortest_path(&self.call_graph, from_fn, to_fn).map(|path| XrefChain {
            nodes: path,
            kind: XrefKind::CodeCall,
        })
    }

    /// Return the depth of the call graph (longest path from any root).
    #[must_use]
    pub fn max_depth(&self) -> usize {
        let nodes: Vec<u64> = self.call_graph.nodes().collect();
        // Roots = nodes with no predecessors.
        let mut roots: Vec<u64> = nodes
            .iter()
            .copied()
            .filter(|&n| self.call_graph.predecessors(n).is_empty())
            .collect();
        // A graph with no predecessor-free nodes is fully cyclic (e.g. every
        // function is part of a mutual-recursion cycle). In that case there
        // is no "true" root, but the graph still has real depth — fall back
        // to treating every node as a candidate start so the cycle's depth
        // is still reported instead of silently collapsing to 0.
        if roots.is_empty() {
            roots = nodes;
        }
        roots
            .iter()
            .map(|&root| self.dfs_depth(root, &mut HashSet::new()))
            .max()
            .unwrap_or(0)
    }

    /// Iterative DFS longest-path depth from `root`.
    ///
    /// Implemented with an explicit work stack (rather than recursion) so
    /// that deep or cyclic call graphs — common in real binaries — cannot
    /// blow the OS stack; this mirrors the iterative Tarjan implementations
    /// used elsewhere in this crate for the same reason.
    fn dfs_depth(&self, root: u64, _visited: &mut HashSet<u64>) -> usize {
        // (node, next-successor-index, on-path-set-membership-guard, best-child-depth-seen)
        let mut work: Vec<(u64, Vec<u64>, usize, usize)> = Vec::new();
        let mut on_path: HashSet<u64> = HashSet::new();
        let mut memo: HashMap<u64, usize> = HashMap::new();

        let start_neighbors: Vec<u64> = self.call_graph.successors(root).collect();
        on_path.insert(root);
        work.push((root, start_neighbors, 0, 0));

        while let Some((node, neighbors, idx, best)) = work.last_mut() {
            if *idx < neighbors.len() {
                let succ = neighbors[*idx];
                *idx += 1;
                if on_path.contains(&succ) {
                    // Cycle: contributes no additional depth along this path.
                    continue;
                }
                if let Some(&d) = memo.get(&succ) {
                    *best = (*best).max(d);
                    continue;
                }
                let succ_neighbors: Vec<u64> = self.call_graph.successors(succ).collect();
                on_path.insert(succ);
                work.push((succ, succ_neighbors, 0, 0));
            } else {
                let depth = 1 + *best;
                let node = *node;
                memo.insert(node, depth);
                on_path.remove(&node);
                work.pop();
                if let Some((_, _, _, parent_best)) = work.last_mut() {
                    *parent_best = (*parent_best).max(depth);
                }
            }
        }
        memo.get(&root).copied().unwrap_or(0)
    }
}

// ── XrefChain ─────────────────────────────────────────────────────────────────

/// A path (chain of addresses) connecting two nodes in an xref graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrefChain {
    pub nodes: Vec<u64>,
    pub kind: XrefKind,
}

impl XrefChain {
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.nodes.len()
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    #[must_use] 
    pub fn source(&self) -> Option<u64> {
        self.nodes.first().copied()
    }
    #[must_use] 
    pub fn sink(&self) -> Option<u64> {
        self.nodes.last().copied()
    }
}

impl std::fmt::Display for XrefChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path: Vec<String> = self.nodes.iter().map(|a| format!("{a:#x}")).collect();
        write!(f, "{:?} chain: {}", self.kind, path.join(" → "))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn chain_graph() -> DiGraph {
        // 1 → 2 → 3 → 4
        let mut g = DiGraph::new();
        g.add_edge(1, 2);
        g.add_edge(2, 3);
        g.add_edge(3, 4);
        g
    }

    fn cycle_graph() -> DiGraph {
        // 1 → 2 → 3 → 1 (cycle)
        let mut g = DiGraph::new();
        g.add_edge(1, 2);
        g.add_edge(2, 3);
        g.add_edge(3, 1);
        g
    }

    fn diamond_graph() -> DiGraph {
        // 1 → 2, 1 → 3, 2 → 4, 3 → 4
        let mut g = DiGraph::new();
        g.add_edge(1, 2);
        g.add_edge(1, 3);
        g.add_edge(2, 4);
        g.add_edge(3, 4);
        g
    }

    // ── DiGraph ───────────────────────────────────────────────────────────────

    #[test]
    fn test_digraph_add_edge() {
        let mut g = DiGraph::new();
        g.add_edge(1, 2);
        assert!(g.has_edge(1, 2));
        assert!(!g.has_edge(2, 1));
    }

    #[test]
    fn test_digraph_node_count() {
        let g = chain_graph();
        assert_eq!(g.node_count(), 4);
    }

    #[test]
    fn test_digraph_edge_count() {
        let g = chain_graph();
        assert_eq!(g.edge_count(), 3);
    }

    #[test]
    fn test_digraph_predecessors() {
        let g = chain_graph();
        let preds = g.predecessors(3);
        assert_eq!(preds, vec![2]);
    }

    #[test]
    fn test_digraph_no_predecessors() {
        let g = chain_graph();
        let preds = g.predecessors(1);
        assert!(preds.is_empty());
    }

    // ── TransitiveClosure ─────────────────────────────────────────────────────

    #[test]
    fn test_closure_direct_edge() {
        let g = chain_graph();
        let tc = TransitiveClosure::compute(&g);
        assert!(tc.is_reachable(1, 2));
    }

    #[test]
    fn test_closure_transitive() {
        let g = chain_graph();
        let tc = TransitiveClosure::compute(&g);
        assert!(tc.is_reachable(1, 4));
    }

    #[test]
    fn test_closure_not_reachable() {
        let g = chain_graph();
        let tc = TransitiveClosure::compute(&g);
        assert!(!tc.is_reachable(4, 1));
    }

    #[test]
    fn test_closure_reachable_from() {
        let g = chain_graph();
        let tc = TransitiveClosure::compute(&g);
        let reach = tc.reachable_from(1);
        assert!(reach.contains(&2));
        assert!(reach.contains(&3));
        assert!(reach.contains(&4));
    }

    #[test]
    fn test_closure_can_reach() {
        let g = chain_graph();
        let tc = TransitiveClosure::compute(&g);
        let callers = tc.can_reach(4);
        assert!(callers.contains(&1));
        assert!(callers.contains(&2));
        assert!(callers.contains(&3));
    }

    #[test]
    fn test_closure_cycle() {
        let g = cycle_graph();
        let tc = TransitiveClosure::compute(&g);
        assert!(tc.is_reachable(1, 3));
        assert!(tc.is_reachable(3, 1)); // cycle
    }

    #[test]
    fn test_closure_diamond() {
        let g = diamond_graph();
        let tc = TransitiveClosure::compute(&g);
        assert!(tc.is_reachable(1, 4));
        assert!(!tc.is_reachable(4, 1));
    }

    #[test]
    fn test_closure_unknown_node() {
        let g = chain_graph();
        let tc = TransitiveClosure::compute(&g);
        assert!(!tc.is_reachable(99, 1));
    }

    #[test]
    fn test_closure_reachable_from_includes_self_on_cycle() {
        // Regression (2026-07-18 differential test): `reachable_from` /
        // `can_reach` are documented "excluding itself unless there's a
        // cycle", but the self index was filtered unconditionally, so a node
        // on a cycle was wrongly omitted from its own reachable set.
        let g = cycle_graph(); // 1 → 2 → 3 → 1
        let tc = TransitiveClosure::compute(&g);
        let reach = tc.reachable_from(1);
        assert!(reach.contains(&1), "cycle member must reach itself");
        assert!(tc.can_reach(1).contains(&1));

        // Self-loop counts as a cycle too.
        let mut sl = DiGraph::new();
        sl.add_edge(5, 5);
        sl.add_edge(5, 6);
        let tc = TransitiveClosure::compute(&sl);
        assert!(tc.reachable_from(5).contains(&5));
        assert!(!tc.reachable_from(6).contains(&6), "no cycle at 6");
    }

    #[test]
    fn test_closure_reachable_from_excludes_self_without_cycle() {
        let g = chain_graph(); // 1 → 2 → 3 → 4, acyclic
        let tc = TransitiveClosure::compute(&g);
        assert!(!tc.reachable_from(1).contains(&1));
        assert!(!tc.can_reach(4).contains(&4));
        // is_reachable stays reflexive for known nodes.
        assert!(tc.is_reachable(1, 1));
        assert!(tc.is_reachable(4, 4));
    }

    // ── BfsReachability ───────────────────────────────────────────────────────

    #[test]
    fn test_bfs_reachable() {
        let g = chain_graph();
        let reach = BfsReachability::bfs_reachable(&g, 1);
        assert!(reach.contains(&1));
        assert!(reach.contains(&4));
        assert!(!reach.contains(&99));
    }

    #[test]
    fn test_bfs_shortest_path_direct() {
        let g = chain_graph();
        let path = BfsReachability::shortest_path(&g, 1, 2).unwrap();
        assert_eq!(path, vec![1, 2]);
    }

    #[test]
    fn test_bfs_shortest_path_multi_hop() {
        let g = chain_graph();
        let path = BfsReachability::shortest_path(&g, 1, 4).unwrap();
        assert_eq!(path, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_bfs_shortest_path_same_node() {
        let g = chain_graph();
        let path = BfsReachability::shortest_path(&g, 2, 2).unwrap();
        assert_eq!(path, vec![2]);
    }

    #[test]
    fn test_bfs_no_path() {
        let g = chain_graph();
        let path = BfsReachability::shortest_path(&g, 4, 1);
        assert!(path.is_none());
    }

    #[test]
    fn test_bfs_diamond_shortest() {
        let g = diamond_graph();
        let path = BfsReachability::shortest_path(&g, 1, 4).unwrap();
        assert_eq!(path.first(), Some(&1));
        assert_eq!(path.last(), Some(&4));
        assert!(path.len() == 3); // 1 → 2 → 4 or 1 → 3 → 4
    }

    // ── SccDecomposition ─────────────────────────────────────────────────────

    #[test]
    fn test_scc_no_cycles() {
        let g = chain_graph();
        let scc = SccDecomposition::compute(&g);
        // All nodes are in their own trivial SCC.
        assert_eq!(scc.sccs.len(), 4);
        assert_eq!(scc.non_trivial_count(), 0);
    }

    #[test]
    fn test_scc_full_cycle() {
        let g = cycle_graph();
        let scc = SccDecomposition::compute(&g);
        assert_eq!(scc.non_trivial_count(), 1);
        let nontrivial = scc.sccs.iter().find(|s| s.len() > 1).unwrap();
        assert!(nontrivial.contains(&1));
        assert!(nontrivial.contains(&2));
        assert!(nontrivial.contains(&3));
    }

    #[test]
    fn test_scc_same_scc_true() {
        let g = cycle_graph();
        let scc = SccDecomposition::compute(&g);
        assert!(scc.same_scc(1, 2));
    }

    #[test]
    fn test_scc_same_scc_false() {
        let g = chain_graph();
        let scc = SccDecomposition::compute(&g);
        assert!(!scc.same_scc(1, 2));
    }

    #[test]
    fn test_scc_of_node() {
        let g = cycle_graph();
        let scc = SccDecomposition::compute(&g);
        let scc1 = scc.scc_of(1).unwrap();
        assert!(scc1.len() > 1);
    }

    // ── ReachabilitySet ───────────────────────────────────────────────────────

    #[test]
    fn test_reachability_set_all_nodes() {
        let g = chain_graph();
        let rs = ReachabilitySet::compute(&g);
        assert!(rs.is_reachable(1, 4));
        assert!(!rs.is_reachable(4, 1));
    }

    #[test]
    fn test_reachability_set_from() {
        let g = chain_graph();
        let rs = ReachabilitySet::compute(&g);
        let r = rs.reachable_from(2).unwrap();
        assert!(r.contains(&3));
        assert!(r.contains(&4));
        assert!(!r.contains(&1));
    }

    // ── CallGraphClosure ──────────────────────────────────────────────────────

    #[test]
    fn test_callgraph_all_callees() {
        let mut g = DiGraph::new();
        g.add_edge(0x1000, 0x2000);
        g.add_edge(0x2000, 0x3000);
        let cgc = CallGraphClosure::new(g);
        let callees = cgc.all_callees(0x1000);
        assert!(callees.contains(&0x2000));
        assert!(callees.contains(&0x3000));
    }

    #[test]
    fn test_callgraph_all_callers() {
        let mut g = DiGraph::new();
        g.add_edge(0x1000, 0x3000);
        g.add_edge(0x2000, 0x3000);
        let cgc = CallGraphClosure::new(g);
        let callers = cgc.all_callers(0x3000);
        assert!(callers.contains(&0x1000));
        assert!(callers.contains(&0x2000));
    }

    #[test]
    fn test_callgraph_call_chain() {
        let mut g = DiGraph::new();
        g.add_edge(0x100, 0x200);
        g.add_edge(0x200, 0x300);
        let cgc = CallGraphClosure::new(g);
        let chain = cgc.call_chain(0x100, 0x300).unwrap();
        assert_eq!(chain.nodes, vec![0x100, 0x200, 0x300]);
        assert_eq!(chain.kind, XrefKind::CodeCall);
    }

    #[test]
    fn test_callgraph_max_depth_linear() {
        let mut g = DiGraph::new();
        g.add_edge(1, 2);
        g.add_edge(2, 3);
        g.add_edge(3, 4);
        let cgc = CallGraphClosure::new(g);
        assert_eq!(cgc.max_depth(), 4);
    }

    #[test]
    fn test_callgraph_max_depth_with_cycle_does_not_hang_or_overflow() {
        // A genuine root (0) feeds into a 3-node cycle (1→2→3→1), with a
        // branch (3→4) escaping the cycle. The recursive edge must not cause
        // infinite recursion/overflow, and depth should be finite and reflect
        // the longest acyclic prefix from the root.
        let mut g = DiGraph::new();
        g.add_edge(0, 1);
        g.add_edge(1, 2);
        g.add_edge(2, 3);
        g.add_edge(3, 1); // cycle back into the loop (not to the root)
        g.add_edge(3, 4); // branch out of the cycle
        let cgc = CallGraphClosure::new(g);
        let depth = cgc.max_depth();
        assert!(depth >= 4, "expected depth to cover the acyclic branch, got {depth}");
    }

    #[test]
    fn test_callgraph_max_depth_fully_cyclic_graph_is_nonzero() {
        // No node has an in-degree of 0 (pure mutual recursion, no external
        // entry point ever recorded in this graph) -- max_depth must not
        // silently collapse to 0 just because there is no "root".
        let mut g = DiGraph::new();
        g.add_edge(1, 2);
        g.add_edge(2, 3);
        g.add_edge(3, 1);
        let cgc = CallGraphClosure::new(g);
        assert!(
            cgc.max_depth() > 0,
            "fully-cyclic call graph should still report nonzero depth"
        );
    }

    #[test]
    fn test_callgraph_no_chain() {
        let mut g = DiGraph::new();
        g.add_edge(0x100, 0x200);
        let cgc = CallGraphClosure::new(g);
        assert!(cgc.call_chain(0x200, 0x100).is_none());
    }

    // ── XrefChain ─────────────────────────────────────────────────────────────

    #[test]
    fn test_xrefchain_source_sink() {
        let chain = XrefChain {
            nodes: vec![1, 2, 3],
            kind: XrefKind::CodeCall,
        };
        assert_eq!(chain.source(), Some(1));
        assert_eq!(chain.sink(), Some(3));
    }

    #[test]
    fn test_xrefchain_len() {
        let chain = XrefChain {
            nodes: vec![1, 2, 3, 4],
            kind: XrefKind::DataPointer,
        };
        assert_eq!(chain.len(), 4);
    }

    #[test]
    fn test_xrefchain_display() {
        let chain = XrefChain {
            nodes: vec![0x1000, 0x2000],
            kind: XrefKind::CodeCall,
        };
        let s = chain.to_string();
        assert!(s.contains("0x1000"));
        assert!(s.contains("0x2000"));
    }
}

/// Differential test: this crate ships FOUR independent reachability
/// implementations — Floyd-Warshall (`TransitiveClosure`), BFS-per-node
/// (`ReachabilitySet`), on-demand BFS (`BfsReachability`), and
/// `xref_query::TransitiveClosure` (reverse-topo sweep with a cyclic-fixpoint
/// fallback, over a `CallGraph` built from an `XrefDatabase`). They were only
/// ever tested in isolation. On any graph they must agree pairwise for every
/// ordered pair of DISTINCT nodes (self-reachability contracts differ by
/// design: `xref_query`'s closure includes `u` in `reach[u]` unconditionally,
/// Floyd-Warshall only via an actual cycle — so `u == v` is excluded).
#[cfg(test)]
mod reachability_differential {
    use super::*;
    use crate::test_prng::Rng;
    use crate::{xref_query, Xref, XrefDatabase, XrefKind};
    use rustre_core::address::Address;

    #[test]
    fn four_reachability_impls_agree_on_random_graphs() {
        let mut rng = Rng::new(0xD1FF_5EED);
        for round in 0..300 {
            let n = 2 + rng.below(7) as u64; // 2..=8 nodes
            let node = |i: u64| 0x1000 + i * 0x10;
            let mut edges: Vec<(u64, u64)> = Vec::new();
            for u in 0..n {
                for v in 0..n {
                    // ~30% density, self-loops allowed.
                    if rng.below(100) < 30 {
                        edges.push((node(u), node(v)));
                    }
                }
            }
            if edges.is_empty() {
                continue;
            }

            let mut g = DiGraph::new();
            for &(u, v) in &edges {
                g.add_edge(u, v);
            }
            let fw = TransitiveClosure::compute(&g);
            let rs = ReachabilitySet::compute(&g);

            let mut db = XrefDatabase::new();
            for &(u, v) in &edges {
                db.add(Xref::new(Address::new(u), Address::new(v), XrefKind::CodeCall, 5));
            }
            let cg = xref_query::CallGraph::build(&db);
            let xq = xref_query::TransitiveClosure::compute(&cg);

            let nodes: Vec<u64> = g.nodes().collect();
            for &u in &nodes {
                let bfs = BfsReachability::bfs_reachable(&g, u);
                for &v in &nodes {
                    if u == v {
                        continue;
                    }
                    let oracle = bfs.contains(&v);
                    assert_eq!(
                        fw.is_reachable(u, v), oracle,
                        "round {round}: Floyd-Warshall disagrees with BFS on {u:#x}->{v:#x}, edges={edges:?}"
                    );
                    assert_eq!(
                        rs.is_reachable(u, v), oracle,
                        "round {round}: ReachabilitySet disagrees with BFS on {u:#x}->{v:#x}, edges={edges:?}"
                    );
                    assert_eq!(
                        xq.can_reach(Address::new(u), Address::new(v)), oracle,
                        "round {round}: xref_query closure disagrees with BFS on {u:#x}->{v:#x}, edges={edges:?}"
                    );
                }
            }
        }
    }
}

/// Differential test: the crate's THREE Tarjan SCC implementations
/// (`SccDecomposition` here, `call_graph_builder::SCCDecomposition`,
/// `GlobalXrefAnalysis::clusters`) were each oracle-tested in isolation but
/// never against each other. Feed the same random edge set to all three and
/// compare the SCC PARTITIONS (normalized as sorted sets of sorted member
/// lists — SCC ids and emission order are implementation details).
#[cfg(test)]
mod scc_differential {
    use super::*;
    use crate::call_graph_builder::{CallEdge, CallGraph as BuilderGraph, CallType, SCCDecomposition};
    use crate::global_xref_analysis::GlobalXrefAnalysis;
    use crate::test_prng::Rng;
    use std::collections::BTreeSet;

    fn normalize(sccs: Vec<Vec<u64>>) -> BTreeSet<Vec<u64>> {
        sccs.into_iter()
            .map(|mut s| {
                s.sort_unstable();
                s
            })
            .collect()
    }

    #[test]
    fn three_tarjan_impls_agree_on_random_graphs() {
        let mut rng = Rng::new(0x5CC_5CC_5CC);
        for round in 0..300 {
            let n = 2 + rng.below(7) as u64;
            let node = |i: u64| 0x1000 + i * 0x10;
            let mut edges: Vec<(u64, u64)> = Vec::new();
            for u in 0..n {
                for v in 0..n {
                    if rng.below(100) < 30 {
                        edges.push((node(u), node(v)));
                    }
                }
            }
            if edges.is_empty() {
                continue;
            }

            let mut g = DiGraph::new();
            let mut bg = BuilderGraph::new();
            let mut gxa = GlobalXrefAnalysis::new();
            for &(u, v) in &edges {
                g.add_edge(u, v);
                bg.add_edge(CallEdge::new(u, v, CallType::Direct));
                gxa.add_call(u, v);
            }

            let a = normalize(SccDecomposition::compute(&g).sccs);
            let b = normalize(SCCDecomposition::compute(&bg).sccs.into_iter().map(|s| s.nodes).collect());
            let c = normalize(gxa.clusters().into_iter().map(|cl| cl.members).collect());

            assert_eq!(a, b, "round {round}: SccDecomposition vs builder SCCDecomposition differ, edges={edges:?}");
            assert_eq!(a, c, "round {round}: SccDecomposition vs GlobalXrefAnalysis clusters differ, edges={edges:?}");
        }
    }
}
