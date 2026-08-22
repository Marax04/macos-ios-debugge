//! Fast xref queries built on top of [`XrefDatabase`].
//!
//! This module provides:
//!
//! - [`XrefQueryEngine`]: a high-level query facade that caches petgraph-based
//!   call-graph views and answers common xref questions in O(1) or O(degree).
//! - [`CallGraph`]: a directed call graph (petgraph `DiGraph`) with
//!   `Address`-weighted nodes and `u32`-weighted edges (call count).
//! - [`TransitiveClosure`]: precomputed reachability matrix for small / medium
//!   CFGs (≤ 8 192 nodes).
//! - Helper functions for common queries: callers, callees, all-callers-of,
//!   call-path finding, strongly-connected-components.

use crate::{XrefDatabase, XrefKind};
use rustre_core::address::Address;
use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// CallGraph — petgraph-based directed call graph
// ─────────────────────────────────────────────────────────────────────────────

/// A directed call graph.
///
/// Each node carries the function's entry `Address`; each directed edge
/// represents one or more call sites (`weight` = number of distinct call sites).
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    /// Adjacency list: caller → list of (callee, call-site count).
    pub adj: HashMap<Address, Vec<(Address, u32)>>,
    /// Reverse adjacency: callee → list of (caller, call-site count).
    pub rev: HashMap<Address, Vec<(Address, u32)>>,
    /// All nodes present in the graph.
    pub nodes: HashSet<Address>,
}

impl CallGraph {
    /// Build a call graph from an [`XrefDatabase`].
    ///
    /// Only `CodeCall` xrefs are included.  Multiple call sites between the
    /// same (caller, callee) pair are collapsed into a single edge with an
    /// incremented weight.
    #[must_use]
    pub fn build(db: &XrefDatabase) -> Self {
        let mut edge_counts: HashMap<(Address, Address), u32> = HashMap::new();
        let mut nodes: HashSet<Address> = HashSet::new();

        for xref in db.iter_all() {
            if xref.kind == XrefKind::CodeCall {
                nodes.insert(xref.from);
                nodes.insert(xref.to);
                *edge_counts.entry((xref.from, xref.to)).or_insert(0) += 1;
            }
        }

        let mut adj: HashMap<Address, Vec<(Address, u32)>> = HashMap::new();
        let mut rev: HashMap<Address, Vec<(Address, u32)>> = HashMap::new();

        for &n in &nodes {
            adj.entry(n).or_default();
            rev.entry(n).or_default();
        }

        // `edge_counts` is a `HashMap`; iterating it directly would make the
        // per-node adjacency-list order (and therefore every traversal that
        // walks `adj`/`rev` in order — topological sort ties, SCC discovery
        // order, BFS path selection) depend on hash iteration order, which is
        // not stable across runs/processes. Sort by (from, to) first.
        let mut sorted_edges: Vec<((Address, Address), u32)> = edge_counts.into_iter().collect();
        sorted_edges.sort_by_key(|a| a.0);
        for ((from, to), count) in sorted_edges {
            adj.entry(from).or_default().push((to, count));
            rev.entry(to).or_default().push((from, count));
        }

        Self { adj, rev, nodes }
    }

    /// Direct callees of `caller`.
    #[must_use]
    pub fn callees(&self, caller: Address) -> Vec<Address> {
        self.adj
            .get(&caller)
            .map(|v| v.iter().map(|(a, _)| *a).collect())
            .unwrap_or_default()
    }

    /// Direct callers of `callee`.
    #[must_use]
    pub fn callers(&self, callee: Address) -> Vec<Address> {
        self.rev
            .get(&callee)
            .map(|v| v.iter().map(|(a, _)| *a).collect())
            .unwrap_or_default()
    }

    /// Number of call sites from `caller` to `callee`.
    #[must_use]
    pub fn call_count(&self, from_fn: Address, to_fn: Address) -> u32 {
        self.adj
            .get(&from_fn)
            .and_then(|v| v.iter().find(|(a, _)| *a == to_fn))
            .map_or(0, |(_, c)| *c)
    }

    /// Total number of unique function nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total number of directed call edges (caller → callee pairs).
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.adj.values().map(std::vec::Vec::len).sum()
    }

    /// Out-degree of `addr` (number of distinct callees).
    #[must_use]
    pub fn out_degree(&self, addr: Address) -> usize {
        self.adj.get(&addr).map_or(0, Vec::len)
    }

    /// In-degree of `addr` (number of distinct callers).
    #[must_use]
    pub fn in_degree(&self, addr: Address) -> usize {
        self.rev.get(&addr).map_or(0, Vec::len)
    }

    /// Whether `addr` is a leaf function (makes no calls).
    #[must_use]
    pub fn is_leaf(&self, addr: Address) -> bool {
        self.out_degree(addr) == 0
    }

    /// Whether `addr` is a root function (never called by another function).
    #[must_use]
    pub fn is_root(&self, addr: Address) -> bool {
        self.in_degree(addr) == 0
    }

    /// All root functions (entry points / unreferenced functions), sorted
    /// ascending for deterministic output (`self.nodes` is a `HashSet`; its
    /// iteration order is not stable across runs).
    #[must_use]
    pub fn roots(&self) -> Vec<Address> {
        let mut v: Vec<Address> = self
            .nodes
            .iter()
            .filter(|&&a| self.is_root(a))
            .copied()
            .collect();
        v.sort_unstable();
        v
    }

    /// All leaf functions, sorted ascending for deterministic output
    /// (`self.nodes` is a `HashSet`; its iteration order is not stable across
    /// runs).
    #[must_use]
    pub fn leaves(&self) -> Vec<Address> {
        let mut v: Vec<Address> = self
            .nodes
            .iter()
            .filter(|&&a| self.is_leaf(a))
            .copied()
            .collect();
        v.sort_unstable();
        v
    }

    /// BFS: all functions reachable from `start` (inclusive).
    #[must_use]
    pub fn reachable_from(&self, start: Address) -> HashSet<Address> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        if self.nodes.contains(&start) {
            queue.push_back(start);
            visited.insert(start);
        }
        while let Some(node) = queue.pop_front() {
            for &callee in &self.callees(node) {
                if visited.insert(callee) {
                    queue.push_back(callee);
                }
            }
        }
        visited
    }

    /// BFS: all functions that can (transitively) reach `target`.
    #[must_use]
    pub fn can_reach(&self, target: Address) -> HashSet<Address> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        if self.nodes.contains(&target) {
            queue.push_back(target);
            visited.insert(target);
        }
        while let Some(node) = queue.pop_front() {
            for &caller in &self.callers(node) {
                if visited.insert(caller) {
                    queue.push_back(caller);
                }
            }
        }
        visited
    }

    /// Shortest call path from `src` to `dst` (in edges), using BFS.
    #[must_use]
    pub fn shortest_path(&self, src: Address, dst: Address) -> Option<Vec<Address>> {
        if src == dst {
            return Some(vec![src]);
        }
        let mut pred: HashMap<Address, Address> = HashMap::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(src);
        visited.insert(src);

        'outer: while let Some(node) = queue.pop_front() {
            for &callee in &self.callees(node) {
                if visited.insert(callee) {
                    pred.insert(callee, node);
                    if callee == dst {
                        break 'outer;
                    }
                    queue.push_back(callee);
                }
            }
        }

        if !pred.contains_key(&dst) {
            return None;
        }

        let mut path = vec![dst];
        let mut cur = dst;
        while cur != src {
            cur = *pred.get(&cur)?;
            path.push(cur);
        }
        path.reverse();
        Some(path)
    }

    /// Topological sort (Kahn's algorithm). Returns `None` if cycles exist.
    #[must_use]
    pub fn topological_sort(&self) -> Option<Vec<Address>> {
        let mut in_deg: HashMap<Address, usize> = self.nodes.iter().map(|&n| (n, 0)).collect();
        for edges in self.adj.values() {
            for &(to, _) in edges {
                *in_deg.entry(to).or_insert(0) += 1;
            }
        }
        // Seed the queue in sorted order: `in_deg` is a `HashMap`, so
        // iterating it directly would make tie-breaks among same-in-degree
        // nodes depend on hash iteration order (nondeterministic across
        // runs/processes).
        let mut zero_deg: Vec<Address> = in_deg
            .iter()
            .filter(|&(_, d)| *d == 0)
            .map(|(&n, _)| n)
            .collect();
        zero_deg.sort_unstable();
        let mut queue: VecDeque<Address> = zero_deg.into_iter().collect();
        let mut sorted = Vec::new();
        while let Some(n) = queue.pop_front() {
            sorted.push(n);
            for &(to, _) in self.adj.get(&n).into_iter().flatten() {
                let d = in_deg.entry(to).or_insert(0);
                *d = d.saturating_sub(1);
                if *d == 0 {
                    queue.push_back(to);
                }
            }
        }
        if sorted.len() == self.nodes.len() {
            Some(sorted)
        } else {
            None // cycle
        }
    }

    /// Tarjan SCC decomposition; returns SCCs in reverse topological order.
    #[must_use]
    pub fn strongly_connected_components(&self) -> Vec<Vec<Address>> {
        struct TarjanQState<'a> {
            nodes: &'a [Address],
            adj: &'a HashMap<Address, Vec<(Address, u32)>>,
            idx: &'a HashMap<Address, usize>,
            index: Vec<usize>,
            lowlink: Vec<usize>,
            on_stack: Vec<bool>,
            stack: Vec<usize>,
            counter: usize,
            sccs: Vec<Vec<Address>>,
        }

        impl TarjanQState<'_> {
            fn sc(&mut self, v: usize) {
                self.index[v] = self.counter;
                self.lowlink[v] = self.counter;
                self.counter += 1;
                self.stack.push(v);
                self.on_stack[v] = true;

                let neighbors: Vec<Address> = self.adj
                    .get(&self.nodes[v])
                    .into_iter()
                    .flatten()
                    .map(|&(nb, _)| nb)
                    .collect();
                for nb in neighbors {
                    if let Some(&w) = self.idx.get(&nb) {
                        if self.index[w] == usize::MAX {
                            self.sc(w);
                            self.lowlink[v] = self.lowlink[v].min(self.lowlink[w]);
                        } else if self.on_stack[w] {
                            self.lowlink[v] = self.lowlink[v].min(self.index[w]);
                        }
                    }
                }

                if self.lowlink[v] == self.index[v] {
                    let mut scc = Vec::new();
                    loop {
                        let w = self.stack.pop().unwrap();
                        self.on_stack[w] = false;
                        scc.push(self.nodes[w]);
                        if w == v { break; }
                    }
                    self.sccs.push(scc);
                }
            }
        }

        // `self.nodes` is a `HashSet`; collecting it directly would make the
        // Tarjan visit order (and hence within-SCC member ordering and the
        // choice among tied outer `sccs.push` orderings) depend on hash
        // iteration order, which is not stable across runs/processes.
        let mut nodes: Vec<Address> = self.nodes.iter().copied().collect();
        nodes.sort_unstable();
        let idx: HashMap<Address, usize> = nodes.iter().enumerate().map(|(i, &n)| (n, i)).collect();
        let n = nodes.len();

        let mut state = TarjanQState {
            nodes: &nodes,
            adj: &self.adj,
            idx: &idx,
            index: vec![usize::MAX; n],
            lowlink: vec![0usize; n],
            on_stack: vec![false; n],
            stack: Vec::new(),
            counter: 0,
            sccs: Vec::new(),
        };

        for i in 0..n {
            if state.index[i] == usize::MAX {
                state.sc(i);
            }
        }
        state.sccs
    }

    /// All functions in the transitive closure reachable from any of `seeds`.
    #[must_use]
    pub fn closure_of(&self, seeds: &[Address]) -> HashSet<Address> {
        let mut visited = HashSet::new();
        let mut queue: VecDeque<Address> = seeds.iter().copied().collect();
        for &s in seeds {
            visited.insert(s);
        }
        while let Some(node) = queue.pop_front() {
            for &callee in &self.callees(node) {
                if visited.insert(callee) {
                    queue.push_back(callee);
                }
            }
        }
        visited
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TransitiveClosure — precomputed reachability for small call graphs
// ─────────────────────────────────────────────────────────────────────────────

/// Precomputed transitive closure for a `CallGraph`.
///
/// For each node `u` the set `can_reach[u]` contains every node reachable
/// from `u` via the call graph (including `u` itself).
///
/// This is O(V²) in space and O(V·E) to build, so it is only practical for
/// call graphs up to ~8 000 nodes.
///
/// # Naming collision (audited, not a bug)
///
/// This crate also defines [`crate::transitive_closure::TransitiveClosure`],
/// a separate `DiGraph`/`u64`-based Floyd-Warshall implementation with a
/// different API shape. This module's type is the one re-exported at the
/// crate root (`crate::TransitiveClosure`) since it is listed first in
/// `lib.rs`'s `pub use xref_query::{...}`. They are distinct concrete types
/// (no type confusion possible), but callers should not assume which one a
/// bare `TransitiveClosure` mention refers to outside this crate's own code.
pub struct TransitiveClosure {
    /// Reachable set indexed by local node index.
    reach: Vec<HashSet<Address>>,
    /// Ordered list of all nodes (defines the local index).
    nodes: Vec<Address>,
    /// Reverse map: Address → local index.
    idx: HashMap<Address, usize>,
}

impl TransitiveClosure {
    /// Build the transitive closure for `graph`.
    ///
    /// Iterates in reverse topological order (from callee to caller) so that
    /// each node's reachable set can be built from its callees' sets in O(V)
    /// time per edge.  Falls back to BFS for irreducible graphs.
    #[must_use]
    pub fn compute(graph: &CallGraph) -> Self {
        let nodes: Vec<Address> = {
            let mut v: Vec<Address> = graph.nodes.iter().copied().collect();
            v.sort_by_key(|a| a.as_u64());
            v
        };
        let n = nodes.len();
        let idx: HashMap<Address, usize> = nodes.iter().enumerate().map(|(i, &a)| (a, i)).collect();

        let mut reach: Vec<HashSet<Address>> = vec![HashSet::new(); n];
        for (vi, &node) in nodes.iter().enumerate() {
            reach[vi].insert(node);
        }

        // Precompute each node's callee local-indices once (avoids repeated
        // `graph.callees()` allocation + `idx` lookups in the hot loop below).
        let callee_idx: Vec<Vec<usize>> = nodes
            .iter()
            .map(|&node| {
                graph
                    .callees(node)
                    .into_iter()
                    .filter_map(|c| idx.get(&c).copied())
                    .collect()
            })
            .collect();

        if let Some(order) = graph.topological_sort() {
            // Acyclic: a single reverse-topological-order sweep suffices —
            // each node's callees are fully resolved before the node itself
            // is processed.
            for &node in order.iter().rev() {
                if let Some(&vi) = idx.get(&node) {
                    for &ci in &callee_idx[vi] {
                        if ci != vi {
                            let (lo, hi) = if vi < ci { (vi, ci) } else { (ci, vi) };
                            let (left, right) = reach.split_at_mut(hi);
                            let (dst, src) = if vi < ci {
                                (&mut left[lo], &right[0])
                            } else {
                                (&mut right[0], &left[lo])
                            };
                            dst.extend(src.iter().copied());
                        }
                    }
                }
            }
        } else {
            // Cyclic graph: a single ordered sweep is not sufficient because
            // no node ordering can guarantee every node's callees are fully
            // resolved before the node itself (that's precisely what makes
            // the graph cyclic). Iterate the sweep to a fixpoint instead:
            // each pass can only grow reach sets (monotone), and a set can
            // grow at most `n` times, so this converges in at most `n`
            // passes; in practice cycles are local and it converges in a
            // handful of passes.
            loop {
                let mut changed = false;
                for vi in 0..n {
                    for &ci in &callee_idx[vi] {
                        if ci != vi {
                            let (lo, hi) = if vi < ci { (vi, ci) } else { (ci, vi) };
                            let (left, right) = reach.split_at_mut(hi);
                            let (dst, src) = if vi < ci {
                                (&mut left[lo], &right[0])
                            } else {
                                (&mut right[0], &left[lo])
                            };
                            let before = dst.len();
                            dst.extend(src.iter().copied());
                            if dst.len() != before {
                                changed = true;
                            }
                        }
                    }
                }
                if !changed {
                    break;
                }
            }
        }

        Self { reach, nodes, idx }
    }

    /// Whether function `from_fn` can (transitively) call `to_fn`.
    #[must_use]
    pub fn can_reach(&self, from_fn: Address, to_fn: Address) -> bool {
        self.idx
            .get(&from_fn)
            .and_then(|&i| self.reach.get(i))
            .is_some_and(|set| set.contains(&to_fn))
    }

    /// All functions reachable from `caller`.
    #[must_use]
    pub fn reachable_from(&self, caller: Address) -> &HashSet<Address> {
        static EMPTY: std::sync::OnceLock<HashSet<Address>> = std::sync::OnceLock::new();
        self.idx
            .get(&caller)
            .and_then(|&i| self.reach.get(i))
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }

    /// Total number of nodes in the closure.
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XrefQueryEngine — high-level query facade
// ─────────────────────────────────────────────────────────────────────────────

/// High-level xref query engine.
///
/// Builds and caches a [`CallGraph`] on first use.  Provides ergonomic methods
/// for the most common binary-analysis questions.
pub struct XrefQueryEngine<'db> {
    db: &'db XrefDatabase,
    call_graph: Option<CallGraph>,
    closure: Option<TransitiveClosure>,
}

impl<'db> XrefQueryEngine<'db> {
    /// Create a new engine backed by `db`.
    #[must_use]
    pub const fn new(db: &'db XrefDatabase) -> Self {
        Self {
            db,
            call_graph: None,
            closure: None,
        }
    }

    /// Build (or return the cached) call graph.
    pub fn call_graph(&mut self) -> &CallGraph {
        self.call_graph
            .get_or_insert_with(|| CallGraph::build(self.db))
    }

    /// Build (or return the cached) transitive closure.
    ///
    /// # Panics
    /// Never panics in practice; the internal `unwrap` is guarded by the preceding `is_none` check.
    pub fn closure(&mut self) -> &TransitiveClosure {
        if self.call_graph.is_none() {
            self.call_graph = Some(CallGraph::build(self.db));
        }
        let cg = self.call_graph.as_ref().unwrap();
        self.closure
            .get_or_insert_with(|| TransitiveClosure::compute(cg))
    }

    // ── Direct callers / callees ──────────────────────────────────────────

    /// Direct callers of `addr` (functions that call `addr`).
    #[must_use]
    pub fn who_calls(&self, addr: Address) -> Vec<Address> {
        self.db.callers_of(addr)
    }

    /// Direct callees of `addr` (functions called by `addr`).
    #[must_use]
    pub fn who_refs(&self, addr: Address) -> Vec<Address> {
        self.db.callees_of(addr)
    }

    /// All callers of `addr` in the entire database, by any xref kind.
    #[must_use]
    pub fn all_refs_to(&self, addr: Address) -> Vec<Address> {
        self.db.xrefs_to(addr).iter().map(|x| x.from).collect()
    }

    // ── Transitive callers ────────────────────────────────────────────────

    /// All callers of `addr` (transitively) — uses BFS on the call graph.
    pub fn all_callers_of(&mut self, addr: Address) -> HashSet<Address> {
        self.call_graph().can_reach(addr)
    }

    /// All functions transitively called by `addr`.
    pub fn all_callees_of(&mut self, addr: Address) -> HashSet<Address> {
        self.call_graph().reachable_from(addr)
    }

    // ── Shortest path ─────────────────────────────────────────────────────

    /// Shortest call path from `src` to `dst`, or `None` if unreachable.
    pub fn call_path(&mut self, src: Address, dst: Address) -> Option<Vec<Address>> {
        self.call_graph().shortest_path(src, dst)
    }

    // ── Hot functions ─────────────────────────────────────────────────────

    /// The `top_n` most-called functions (by call-site count).
    #[must_use]
    pub fn hottest_functions(&self, top_n: usize) -> Vec<(Address, usize)> {
        self.db.hot_functions(top_n)
    }

    // ── Leaf / root functions ─────────────────────────────────────────────

    /// All leaf functions (make no outgoing calls).
    pub fn leaf_functions(&mut self) -> Vec<Address> {
        self.call_graph().leaves()
    }

    /// All root functions (not called by any other function).
    pub fn root_functions(&mut self) -> Vec<Address> {
        self.call_graph().roots()
    }

    // ── SCCs ─────────────────────────────────────────────────────────────

    /// Strongly-connected components of the call graph, largest first.
    pub fn call_sccs(&mut self) -> Vec<Vec<Address>> {
        let mut sccs = self.call_graph().strongly_connected_components();
        sccs.sort_by_key(|b| std::cmp::Reverse(b.len()));
        sccs
    }

    // ── Reachability with precomputed closure ─────────────────────────────

    /// Whether `from_fn` can transitively call `to_fn` (uses precomputed closure).
    pub fn can_reach(&mut self, from_fn: Address, to_fn: Address) -> bool {
        self.closure().can_reach(from_fn, to_fn)
    }

    // ── Data-reference queries ────────────────────────────────────────────

    /// All code addresses that read from data address `addr`.
    #[must_use]
    pub fn readers_of(&self, addr: Address) -> Vec<Address> {
        self.db
            .xrefs_to(addr)
            .iter()
            .filter(|x| x.kind == XrefKind::DataRead)
            .map(|x| x.from)
            .collect()
    }

    /// All code addresses that write to data address `addr`.
    #[must_use]
    pub fn writers_of(&self, addr: Address) -> Vec<Address> {
        self.db
            .xrefs_to(addr)
            .iter()
            .filter(|x| x.kind == XrefKind::DataWrite)
            .map(|x| x.from)
            .collect()
    }

    /// All code addresses that take the address of `addr` (LEA / MOV-imm).
    #[must_use]
    pub fn address_takers(&self, addr: Address) -> Vec<Address> {
        self.db
            .xrefs_to(addr)
            .iter()
            .filter(|x| x.kind == XrefKind::DataAddress)
            .map(|x| x.from)
            .collect()
    }

    // ── Import / export queries ───────────────────────────────────────────

    /// All call sites that reference import `name`.
    #[must_use]
    pub fn call_sites_for_import(&self, name: &str) -> Vec<Address> {
        self.db
            .xrefs_to_import(name)
            .iter()
            .map(|x| x.from)
            .collect()
    }

    // ── String queries ────────────────────────────────────────────────────

    /// All code addresses that reference the string literal `content`.
    #[must_use]
    pub fn string_reference_sites(&self, content: &str) -> Vec<Address> {
        self.db.string_ref_sites(content).to_vec()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraphMetrics — statistics about a call graph
// ─────────────────────────────────────────────────────────────────────────────

/// Summary metrics for a [`CallGraph`].
#[derive(Debug, Clone, Default)]
pub struct CallGraphMetrics {
    pub node_count: usize,
    pub edge_count: usize,
    pub leaf_count: usize,
    pub root_count: usize,
    /// Functions that both call and are called (internal utility functions).
    pub internal_count: usize,
    pub max_out_degree: usize,
    pub max_in_degree: usize,
    /// Average out-degree (number of unique callees per function).
    pub avg_out_degree: f64,
    /// Number of strongly connected components (SCCs) of size > 1 (recursive groups).
    pub recursive_groups: usize,
}

impl CallGraphMetrics {
    /// Compute metrics for `graph`.
    #[must_use]
    pub fn compute(graph: &CallGraph) -> Self {
        let node_count = graph.node_count();
        let edge_count = graph.edge_count();

        let mut leaf_count = 0;
        let mut root_count = 0;
        let mut internal_count = 0;
        let mut max_out = 0;
        let mut max_in = 0;
        let mut total_out = 0u64;

        for &n in &graph.nodes {
            let out = graph.out_degree(n);
            let r#in = graph.in_degree(n);
            if out == 0 {
                leaf_count += 1;
            }
            if r#in == 0 {
                root_count += 1;
            }
            if out > 0 && r#in > 0 {
                internal_count += 1;
            }
            max_out = max_out.max(out);
            max_in = max_in.max(r#in);
            total_out += u64::try_from(out).unwrap_or(u64::MAX);
        }

        let avg_out_degree = if node_count > 0 {
            f64::from(u32::try_from(total_out).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(node_count).unwrap_or(u32::MAX))
        } else {
            0.0
        };

        let sccs = graph.strongly_connected_components();
        let recursive_groups = sccs.iter().filter(|s| s.len() > 1).count();

        Self {
            node_count,
            edge_count,
            leaf_count,
            root_count,
            internal_count,
            max_out_degree: max_out,
            max_in_degree: max_in,
            avg_out_degree,
            recursive_groups,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::XrefDatabase;

    fn a(n: u64) -> Address {
        Address::new(n)
    }

    fn make_db(calls: &[(u64, u64)]) -> XrefDatabase {
        let mut db = XrefDatabase::new();
        for &(from, to) in calls {
            db.add_call(a(from), a(to), 5);
        }
        db
    }

    /// Differential soundness: `TransitiveClosure::compute` (which takes an
    /// acyclic reverse-topo fast path and a cyclic fixpoint path) must agree
    /// exactly with the `CallGraph`'s own plain BFS `reachable_from` on random
    /// graphs — including graphs with cycles, where a buggy `topological_sort`
    /// returning `Some` for a cyclic graph would make the fast path silently
    /// under-approximate reachability.
    #[test]
    fn transitive_closure_matches_bfs_on_random_graphs() {
        use crate::test_prng::xorshift as xs;
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..600 {
            let n = 2 + (xs(&mut state) % 7) as u64; // 2..=8 nodes
            let node = |i: u64| 0x1000 + i * 0x10;
            let mut edges: Vec<(u64, u64)> = Vec::new();
            // Random edge set (allows cycles and self-loops).
            for u in 0..n {
                for v in 0..n {
                    if xs(&mut state) % 100 < 30 {
                        edges.push((node(u), node(v)));
                    }
                }
            }
            if edges.is_empty() {
                edges.push((node(0), node(1)));
            }
            let db = make_db(&edges);
            let cg = CallGraph::build(&db);
            let tc = TransitiveClosure::compute(&cg);
            for u in 0..n {
                let start = a(node(u));
                if !cg.nodes.contains(&start) {
                    continue;
                }
                let bfs = cg.reachable_from(start);
                let closure = tc.reachable_from(start);
                assert_eq!(
                    &bfs, closure,
                    "TransitiveClosure disagrees with BFS from {start:?}: bfs={bfs:?} tc={closure:?} edges={edges:?}"
                );
            }
        }
    }

    // Regression: leaves/roots/topological_sort/SCCs must be deterministic
    // across repeated calls — none of these should depend on HashMap/HashSet
    // iteration order.
    #[test]
    fn call_graph_determinism_across_repeated_calls() {
        let db = make_db(&[
            (0x1000, 0x1010),
            (0x1000, 0x1020),
            (0x1010, 0x1030),
            (0x1020, 0x1030),
            (0x1000, 0x1040),
            (0x1050, 0x1060),
            (0x1060, 0x1050), // 2-cycle for SCC coverage
        ]);
        let cg = CallGraph::build(&db);

        let leaves1 = cg.leaves();
        let roots1 = cg.roots();
        let topo1 = cg.topological_sort();
        let sccs1 = cg.strongly_connected_components();
        for _ in 0..5 {
            assert_eq!(cg.leaves(), leaves1);
            assert_eq!(cg.roots(), roots1);
            assert_eq!(cg.topological_sort(), topo1);
            assert_eq!(cg.strongly_connected_components(), sccs1);
        }
        let mut sorted_leaves = leaves1.clone();
        sorted_leaves.sort_unstable();
        assert_eq!(leaves1, sorted_leaves);
        let mut sorted_roots = roots1.clone();
        sorted_roots.sort_unstable();
        assert_eq!(roots1, sorted_roots);
    }

    // ── CallGraph::build ──────────────────────────────────────────────────

    #[test]
    fn call_graph_empty_db() {
        let db = XrefDatabase::new();
        let cg = CallGraph::build(&db);
        assert_eq!(cg.node_count(), 0);
        assert_eq!(cg.edge_count(), 0);
    }

    #[test]
    fn call_graph_single_call() {
        let db = make_db(&[(0x1000, 0x2000)]);
        let cg = CallGraph::build(&db);
        assert_eq!(cg.node_count(), 2);
        assert_eq!(cg.edge_count(), 1);
        assert_eq!(cg.callees(a(0x1000)), vec![a(0x2000)]);
        assert_eq!(cg.callers(a(0x2000)), vec![a(0x1000)]);
    }

    #[test]
    fn call_graph_call_count_aggregation() {
        // Two calls from same site to same callee → single edge with weight 2.
        let mut db = XrefDatabase::new();
        db.add_call(a(0x1000), a(0x2000), 5);
        db.add_call(a(0x1000), a(0x2000), 5); // second call at same (from,to)
        let cg = CallGraph::build(&db);
        assert_eq!(cg.call_count(a(0x1000), a(0x2000)), 2);
    }

    #[test]
    fn call_graph_leaf_detection() {
        let db = make_db(&[(0x1000, 0x2000)]);
        let cg = CallGraph::build(&db);
        assert!(cg.is_leaf(a(0x2000)));
        assert!(!cg.is_leaf(a(0x1000)));
    }

    #[test]
    fn call_graph_root_detection() {
        let db = make_db(&[(0x1000, 0x2000)]);
        let cg = CallGraph::build(&db);
        assert!(cg.is_root(a(0x1000)));
        assert!(!cg.is_root(a(0x2000)));
    }

    #[test]
    fn call_graph_reachable_from() {
        let db = make_db(&[(0x1000, 0x2000), (0x2000, 0x3000)]);
        let cg = CallGraph::build(&db);
        let r = cg.reachable_from(a(0x1000));
        assert!(r.contains(&a(0x1000)));
        assert!(r.contains(&a(0x2000)));
        assert!(r.contains(&a(0x3000)));
    }

    #[test]
    fn call_graph_can_reach() {
        let db = make_db(&[(0x1000, 0x2000), (0x2000, 0x3000)]);
        let cg = CallGraph::build(&db);
        let cr = cg.can_reach(a(0x3000));
        assert!(cr.contains(&a(0x1000)));
        assert!(cr.contains(&a(0x2000)));
        assert!(cr.contains(&a(0x3000)));
    }

    #[test]
    fn call_graph_shortest_path() {
        let db = make_db(&[(0x1, 0x2), (0x2, 0x3), (0x1, 0x3)]);
        let cg = CallGraph::build(&db);
        let p = cg.shortest_path(a(0x1), a(0x3)).unwrap();
        assert_eq!(p.len(), 2); // direct 1→3
    }

    #[test]
    fn call_graph_shortest_path_none() {
        let db = make_db(&[(0x1, 0x2)]);
        let cg = CallGraph::build(&db);
        assert!(cg.shortest_path(a(0x2), a(0x1)).is_none()); // reverse
    }

    #[test]
    fn call_graph_topological_sort_linear() {
        let db = make_db(&[(0x1, 0x2), (0x2, 0x3)]);
        let cg = CallGraph::build(&db);
        let topo = cg.topological_sort().unwrap();
        let pos: HashMap<u64, usize> = topo
            .iter()
            .enumerate()
            .map(|(i, &a)| (a.as_u64(), i))
            .collect();
        assert!(pos[&0x1] < pos[&0x2]);
        assert!(pos[&0x2] < pos[&0x3]);
    }

    #[test]
    fn call_graph_topo_sort_cyclic_returns_none() {
        let db = make_db(&[(0x1, 0x2), (0x2, 0x1)]); // mutual recursion
        let cg = CallGraph::build(&db);
        assert!(cg.topological_sort().is_none());
    }

    #[test]
    fn call_graph_scc_detects_cycle() {
        let db = make_db(&[(0x1, 0x2), (0x2, 0x1), (0x1, 0x3)]); // 1↔2 cycle
        let cg = CallGraph::build(&db);
        let sccs = cg.strongly_connected_components();
        let has_cycle = sccs.iter().any(|s| s.len() > 1);
        assert!(has_cycle);
    }

    #[test]
    fn call_graph_closure_of() {
        let db = make_db(&[(0x1, 0x2), (0x2, 0x3), (0x4, 0x5)]);
        let cg = CallGraph::build(&db);
        let c = cg.closure_of(&[a(0x1)]);
        assert!(c.contains(&a(0x2)));
        assert!(c.contains(&a(0x3)));
        assert!(!c.contains(&a(0x5)));
    }

    #[test]
    fn call_graph_degree_methods() {
        let db = make_db(&[(0x1, 0x2), (0x1, 0x3), (0x4, 0x2)]);
        let cg = CallGraph::build(&db);
        assert_eq!(cg.out_degree(a(0x1)), 2);
        assert_eq!(cg.in_degree(a(0x2)), 2);
        assert_eq!(cg.in_degree(a(0x1)), 0);
    }

    // ── TransitiveClosure ─────────────────────────────────────────────────

    #[test]
    fn closure_can_reach_direct() {
        let db = make_db(&[(0x1, 0x2)]);
        let cg = CallGraph::build(&db);
        let tc = TransitiveClosure::compute(&cg);
        assert!(tc.can_reach(a(0x1), a(0x2)));
        assert!(!tc.can_reach(a(0x2), a(0x1)));
    }

    #[test]
    fn closure_can_reach_transitive() {
        let db = make_db(&[(0x1, 0x2), (0x2, 0x3)]);
        let cg = CallGraph::build(&db);
        let tc = TransitiveClosure::compute(&cg);
        assert!(tc.can_reach(a(0x1), a(0x3)));
    }

    #[test]
    fn closure_self_reachable() {
        let db = make_db(&[(0x1, 0x2)]);
        let cg = CallGraph::build(&db);
        let tc = TransitiveClosure::compute(&cg);
        assert!(tc.can_reach(a(0x1), a(0x1)));
        assert!(tc.can_reach(a(0x2), a(0x2)));
    }

    #[test]
    fn closure_cyclic_graph_full_reachability() {
        // C -> A -> B -> A (mutual recursion A<->B), plus C -> A.
        // Previously, `TransitiveClosure::compute` fell back to a single
        // address-sorted sweep for cyclic graphs, which could leave `C`
        // missing `B` in its reach set depending on node ordering (C is
        // processed after A/B in address order, so its single pass over A's
        // *not-yet-complete* reach set would miss B). A correct closure must
        // report the full reachable set regardless of graph structure.
        let db = make_db(&[(0x1, 0x2), (0x2, 0x1), (0x3, 0x1)]);
        let cg = CallGraph::build(&db);
        let tc = TransitiveClosure::compute(&cg);
        assert!(tc.can_reach(a(0x3), a(0x1)));
        assert!(tc.can_reach(a(0x3), a(0x2)), "C must transitively reach B through the A<->B cycle");
        assert!(tc.can_reach(a(0x1), a(0x2)));
        assert!(tc.can_reach(a(0x2), a(0x1)));
    }

    #[test]
    fn closure_reachable_from_set() {
        let db = make_db(&[(0x1, 0x2), (0x2, 0x3)]);
        let cg = CallGraph::build(&db);
        let tc = TransitiveClosure::compute(&cg);
        let r = tc.reachable_from(a(0x1));
        assert!(r.contains(&a(0x2)));
        assert!(r.contains(&a(0x3)));
    }

    // ── XrefQueryEngine ───────────────────────────────────────────────────

    #[test]
    fn engine_who_calls_returns_callers() {
        let db = make_db(&[(0x1000, 0x2000), (0x3000, 0x2000)]);
        let engine = XrefQueryEngine::new(&db);
        let callers = engine.who_calls(a(0x2000));
        assert_eq!(callers.len(), 2);
        assert!(callers.contains(&a(0x1000)));
        assert!(callers.contains(&a(0x3000)));
    }

    #[test]
    fn engine_who_refs_returns_callees() {
        let db = make_db(&[(0x1000, 0x2000), (0x1000, 0x3000)]);
        let engine = XrefQueryEngine::new(&db);
        let callees = engine.who_refs(a(0x1000));
        assert_eq!(callees.len(), 2);
        assert!(callees.contains(&a(0x2000)));
        assert!(callees.contains(&a(0x3000)));
    }

    #[test]
    fn engine_all_callers_of_transitive() {
        let db = make_db(&[(0x1, 0x2), (0x2, 0x3), (0x4, 0x3)]);
        let mut engine = XrefQueryEngine::new(&db);
        let all = engine.all_callers_of(a(0x3));
        assert!(all.contains(&a(0x1)));
        assert!(all.contains(&a(0x2)));
        assert!(all.contains(&a(0x4)));
    }

    #[test]
    fn engine_call_path_direct() {
        let db = make_db(&[(0x1, 0x2), (0x2, 0x3)]);
        let mut engine = XrefQueryEngine::new(&db);
        let path = engine.call_path(a(0x1), a(0x3));
        assert!(path.is_some());
        let p = path.unwrap();
        assert_eq!(p.first().copied(), Some(a(0x1)));
        assert_eq!(p.last().copied(), Some(a(0x3)));
    }

    #[test]
    fn engine_hottest_functions() {
        let mut db = XrefDatabase::new();
        for _ in 0..5 {
            db.add_call(a(0x100), a(0x200), 5);
        }
        db.add_call(a(0x300), a(0x400), 5);
        let engine = XrefQueryEngine::new(&db);
        let hot = engine.hottest_functions(1);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].0, a(0x200));
        assert_eq!(hot[0].1, 5);
    }

    #[test]
    fn engine_leaf_and_root_functions() {
        let db = make_db(&[(0x1, 0x2), (0x1, 0x3)]);
        let mut engine = XrefQueryEngine::new(&db);
        let leaves = engine.leaf_functions();
        assert!(leaves.contains(&a(0x2)));
        assert!(leaves.contains(&a(0x3)));
        let roots = engine.root_functions();
        assert!(roots.contains(&a(0x1)));
    }

    #[test]
    fn engine_can_reach_via_closure() {
        let db = make_db(&[(0x1, 0x2), (0x2, 0x3)]);
        let mut engine = XrefQueryEngine::new(&db);
        assert!(engine.can_reach(a(0x1), a(0x3)));
        assert!(!engine.can_reach(a(0x3), a(0x1)));
    }

    #[test]
    fn engine_data_readers_writers() {
        let mut db = XrefDatabase::new();
        db.add_data_read(a(0x1000), a(0x5000));
        db.add_data_write(a(0x2000), a(0x5000));
        let engine = XrefQueryEngine::new(&db);
        let readers = engine.readers_of(a(0x5000));
        assert!(readers.contains(&a(0x1000)));
        let writers = engine.writers_of(a(0x5000));
        assert!(writers.contains(&a(0x2000)));
    }

    #[test]
    fn engine_import_call_sites() {
        let mut db = XrefDatabase::new();
        db.add_import_by_name(a(0x1000), a(0x9000), "malloc");
        db.add_import_by_name(a(0x2000), a(0x9000), "malloc");
        let engine = XrefQueryEngine::new(&db);
        let sites = engine.call_sites_for_import("malloc");
        assert_eq!(sites.len(), 2);
    }

    #[test]
    fn engine_string_reference_sites() {
        let mut db = XrefDatabase::new();
        db.add_string_ref(a(0x1000), a(0xD000), "hello world");
        let engine = XrefQueryEngine::new(&db);
        let sites = engine.string_reference_sites("hello world");
        // string_reference_sites returns code addresses (the `from` side of the
        // xref), not the string data address. The instruction site is 0x1000.
        assert!(sites.contains(&a(0x1000)));
    }

    // ── CallGraphMetrics ──────────────────────────────────────────────────

    #[test]
    fn metrics_basic() {
        let db = make_db(&[(0x1, 0x2), (0x1, 0x3), (0x2, 0x3)]);
        let cg = CallGraph::build(&db);
        let m = CallGraphMetrics::compute(&cg);
        assert_eq!(m.node_count, 3);
        assert_eq!(m.edge_count, 3);
        assert_eq!(m.leaf_count, 1); // 0x3
        assert_eq!(m.root_count, 1); // 0x1
        assert_eq!(m.max_out_degree, 2); // 0x1 calls 0x2 and 0x3
    }

    #[test]
    fn metrics_recursive_groups() {
        let db = make_db(&[(0x1, 0x2), (0x2, 0x1)]); // mutual recursion
        let cg = CallGraph::build(&db);
        let m = CallGraphMetrics::compute(&cg);
        assert_eq!(m.recursive_groups, 1);
    }

    #[test]
    fn metrics_empty_graph() {
        let db = XrefDatabase::new();
        let cg = CallGraph::build(&db);
        let m = CallGraphMetrics::compute(&cg);
        assert_eq!(m.node_count, 0);
        assert_eq!(m.avg_out_degree, 0.0);
    }

    // ── Previously-zero-coverage XrefQueryEngine methods ─────────────────

    #[test]
    fn engine_all_refs_to_mixed_kinds() {
        // all_refs_to should return every xref "from" address regardless of
        // kind (calls, data reads, data writes), unlike who_calls which is
        // call-only.
        let mut db = XrefDatabase::new();
        db.add_call(a(0x1000), a(0x5000), 5);
        db.add_data_read(a(0x2000), a(0x5000));
        db.add_data_write(a(0x3000), a(0x5000));
        let engine = XrefQueryEngine::new(&db);
        let refs = engine.all_refs_to(a(0x5000));
        assert_eq!(refs.len(), 3);
        assert!(refs.contains(&a(0x1000)));
        assert!(refs.contains(&a(0x2000)));
        assert!(refs.contains(&a(0x3000)));
    }

    #[test]
    fn engine_all_callees_of_transitive() {
        let db = make_db(&[(0x1, 0x2), (0x2, 0x3), (0x1, 0x4)]);
        let mut engine = XrefQueryEngine::new(&db);
        let all = engine.all_callees_of(a(0x1));
        // Includes the start node itself plus everything transitively reachable.
        assert!(all.contains(&a(0x1)));
        assert!(all.contains(&a(0x2)));
        assert!(all.contains(&a(0x3)));
        assert!(all.contains(&a(0x4)));
    }

    #[test]
    fn engine_all_callees_of_leaf_is_singleton() {
        let db = make_db(&[(0x1, 0x2)]);
        let mut engine = XrefQueryEngine::new(&db);
        let all = engine.all_callees_of(a(0x2));
        assert_eq!(all.len(), 1);
        assert!(all.contains(&a(0x2)));
    }

    #[test]
    fn engine_call_sccs_sorted_largest_first() {
        // A 3-node cycle (1,2,3) plus a trivial singleton (4) that only calls
        // into the cycle. The 3-node SCC must sort before the 1-node SCC.
        let db = make_db(&[
            (0x1, 0x2),
            (0x2, 0x3),
            (0x3, 0x1),
            (0x4, 0x1),
        ]);
        let mut engine = XrefQueryEngine::new(&db);
        let sccs = engine.call_sccs();
        assert_eq!(sccs.len(), 2);
        assert_eq!(sccs[0].len(), 3);
        assert_eq!(sccs[1].len(), 1);
        let big: HashSet<Address> = sccs[0].iter().copied().collect();
        assert!(big.contains(&a(0x1)) && big.contains(&a(0x2)) && big.contains(&a(0x3)));
        assert_eq!(sccs[1][0], a(0x4));
    }

    #[test]
    fn engine_call_sccs_all_trivial_when_acyclic() {
        let db = make_db(&[(0x1, 0x2), (0x1, 0x3), (0x2, 0x3)]);
        let mut engine = XrefQueryEngine::new(&db);
        let sccs = engine.call_sccs();
        assert_eq!(sccs.len(), 3);
        assert!(sccs.iter().all(|s| s.len() == 1));
    }
}
