//! Differential cross-check matrix over the crate's graph algorithms.
//!
//! Modelled after `rustre-analysis`'s `soundness_fuzz.rs`: generate random
//! small call graphs (xorshift PRNG, no external dev-deps, <=12 nodes, cycles
//! and self-loops allowed) and cross-check the crate's *independent*
//! implementations against brute-force oracles and each other.
//!
//! The crate contains six independently-written Tarjan SCC implementations,
//! two Kahn topological sorts, and several reachability / transitive-closure
//! implementations. Any disagreement between an implementation and the
//! brute-force oracle (or between two implementations) is a bug in at least
//! one of them.
//!
//! Oracles:
//! * SCC: two nodes share an SCC iff they are mutually reachable (BFS both
//!   directions).
//! * Topological sort: a valid order exists (every edge `u -> v` places `u`
//!   before `v`) iff the graph is acyclic (no self-loop and no non-trivial
//!   SCC); otherwise the sort must report a cycle.
//! * Transitive closure / reachability: brute-force BFS from each node.

#![cfg(test)]

use crate::call_graph_builder::{
    CallEdge, CallGraph as CgbCallGraph, CallType, SCCDecomposition,
};
use crate::call_hierarchy::CallHierarchy;
use crate::transitive_closure::{
    BfsReachability, DiGraph, SccDecomposition, TransitiveClosure as FwClosure,
};
use crate::xref_query::{CallGraph as QCallGraph, TransitiveClosure as QClosure};
use crate::{XrefGraph, XrefKind};
use rustre_core::address::Address;
use std::collections::{HashMap, HashSet};

// ── xorshift PRNG ─────────────────────────────────────────────────────────────

use crate::test_prng::Rng;

// ── random graph ──────────────────────────────────────────────────────────────

/// A randomly generated directed graph over node indices `0..n`.
struct Graph {
    n: usize,
    /// Directed edges as index pairs (self-loops and duplicates allowed).
    edges: Vec<(usize, usize)>,
}

impl Graph {
    fn random(rng: &mut Rng) -> Self {
        let n = 1 + rng.below(12); // 1..=12 nodes
        // Edge count up to ~2n, occasionally denser to force big SCCs.
        let max_edges = 2 * n + rng.below(n + 1);
        let mut edges = Vec::new();
        for _ in 0..max_edges {
            if rng.below(100) < 15 {
                continue; // sparser sometimes
            }
            let u = rng.below(n);
            let v = rng.below(n); // may equal u -> self-loop
            edges.push((u, v));
        }
        Self { n, edges }
    }

    /// Node index `i` mapped to a synthetic address.
    fn addr(i: usize) -> u64 {
        0x1000 + (i as u64) * 8
    }

    /// Successor adjacency (as index sets, deduped).
    fn adj(&self) -> Vec<HashSet<usize>> {
        let mut a = vec![HashSet::new(); self.n];
        for &(u, v) in &self.edges {
            a[u].insert(v);
        }
        a
    }

    /// Brute-force reachability matrix, `reach[i][j]` = j reachable from i,
    /// *including* i itself (a node always reaches itself).
    fn reach_matrix(&self) -> Vec<Vec<bool>> {
        let adj = self.adj();
        let mut reach = vec![vec![false; self.n]; self.n];
        for s in 0..self.n {
            // BFS from s.
            let mut stack = vec![s];
            reach[s][s] = true;
            while let Some(u) = stack.pop() {
                for &v in &adj[u] {
                    if !reach[s][v] {
                        reach[s][v] = true;
                        stack.push(v);
                    }
                }
            }
        }
        reach
    }

    fn has_self_loop(&self) -> bool {
        self.edges.iter().any(|&(u, v)| u == v)
    }
}

// ── builders for each independent graph type ──────────────────────────────────

fn build_cgb(g: &Graph) -> CgbCallGraph {
    let mut cg = CgbCallGraph::new();
    for i in 0..g.n {
        cg.add_node(crate::call_graph_builder::CallNode::new(Graph::addr(i), ""));
    }
    for &(u, v) in &g.edges {
        cg.add_edge(CallEdge::new(Graph::addr(u), Graph::addr(v), CallType::Direct));
    }
    cg
}

fn build_digraph(g: &Graph) -> DiGraph {
    let mut dg = DiGraph::new();
    for i in 0..g.n {
        dg.edges.entry(Graph::addr(i)).or_default();
    }
    for &(u, v) in &g.edges {
        dg.add_edge(Graph::addr(u), Graph::addr(v));
    }
    dg
}

fn build_qcallgraph(g: &Graph) -> QCallGraph {
    let mut cg = QCallGraph::default();
    for i in 0..g.n {
        let a = Address::new(Graph::addr(i));
        cg.nodes.insert(a);
        cg.adj.entry(a).or_default();
        cg.rev.entry(a).or_default();
    }
    // Collapse duplicate (u,v) into weighted edges (matches CallGraph::build).
    let mut counts: HashMap<(usize, usize), u32> = HashMap::new();
    for &(u, v) in &g.edges {
        *counts.entry((u, v)).or_insert(0) += 1;
    }
    let mut sorted: Vec<((usize, usize), u32)> = counts.into_iter().collect();
    sorted.sort_by_key(|&((u, v), _)| (u, v));
    for ((u, v), c) in sorted {
        let (fa, ta) = (Address::new(Graph::addr(u)), Address::new(Graph::addr(v)));
        cg.adj.entry(fa).or_default().push((ta, c));
        cg.rev.entry(ta).or_default().push((fa, c));
    }
    cg
}

fn build_xrefgraph(g: &Graph) -> XrefGraph {
    let mut adj: HashMap<u64, Vec<(u64, XrefKind, usize)>> = HashMap::new();
    let mut nodes: HashSet<u64> = HashSet::new();
    for i in 0..g.n {
        nodes.insert(Graph::addr(i));
        adj.entry(Graph::addr(i)).or_default();
    }
    let mut counts: HashMap<(usize, usize), usize> = HashMap::new();
    for &(u, v) in &g.edges {
        *counts.entry((u, v)).or_insert(0) += 1;
    }
    let mut incoming: HashMap<u64, HashSet<u64>> = HashMap::new();
    let mut sorted: Vec<((usize, usize), usize)> = counts.into_iter().collect();
    sorted.sort();
    for ((u, v), c) in sorted {
        adj.entry(Graph::addr(u))
            .or_default()
            .push((Graph::addr(v), XrefKind::CodeCall, c));
        incoming
            .entry(Graph::addr(v))
            .or_default()
            .insert(Graph::addr(u));
    }
    let in_degree = incoming.into_iter().map(|(t, s)| (t, s.len())).collect();
    XrefGraph {
        adj,
        in_degree,
        nodes,
        kinds: vec![XrefKind::CodeCall],
    }
}

fn build_hierarchy(g: &Graph) -> CallHierarchy {
    let mut h = CallHierarchy::new();
    for i in 0..g.n {
        h.add_node(Graph::addr(i), "");
    }
    for &(u, v) in &g.edges {
        h.add_call(Graph::addr(u), Graph::addr(v));
    }
    h
}

// ── SCC oracle check helper ───────────────────────────────────────────────────

/// Given a partition (list of components as index sets) and the brute-force
/// reach matrix, assert it is a valid SCC decomposition:
///   * every node appears exactly once, and
///   * two nodes share a component iff they are mutually reachable.
fn assert_valid_scc(label: &str, seed: u64, partition: &[Vec<usize>], reach: &[Vec<bool>], n: usize) {
    // Coverage: exactly-once.
    let mut seen = vec![0u32; n];
    for comp in partition {
        for &i in comp {
            seen[i] += 1;
        }
    }
    for (i, &c) in seen.iter().enumerate() {
        assert_eq!(
            c, 1,
            "[{label}] seed {seed}: node {i} appears {c} times in partition (expected 1)"
        );
    }
    // comp_of[i] = component id.
    let mut comp_of = vec![usize::MAX; n];
    for (cid, comp) in partition.iter().enumerate() {
        for &i in comp {
            comp_of[i] = cid;
        }
    }
    for i in 0..n {
        for j in 0..n {
            let mutually = reach[i][j] && reach[j][i];
            let same_comp = comp_of[i] == comp_of[j];
            assert_eq!(
                mutually, same_comp,
                "[{label}] seed {seed}: nodes {i},{j} mutually_reachable={mutually} \
                 but same_component={same_comp}"
            );
        }
    }
}

/// Map a partition of addresses back to index-space using the `addr(i)` scheme.
fn addr_to_index(a: u64) -> usize {
    ((a - 0x1000) / 8) as usize
}

// ── the fuzz test ─────────────────────────────────────────────────────────────

#[test]
fn differential_cross_check_matrix() {
    let mut rng = Rng::new(0x9E37_79B9_7F4A_7C15);
    let trials = 4000;

    for seed in 0..trials {
        let g = Graph::random(&mut rng);
        let n = g.n;
        let reach = g.reach_matrix();
        let has_cycle = g.has_self_loop()
            || (0..n).any(|i| (0..n).any(|j| i != j && reach[i][j] && reach[j][i]));

        // ── (1) SCC: all four independent Tarjan impls vs the oracle ──────────

        // 1a. call_graph_builder::SCCDecomposition (iterative, index-based).
        let cgb = build_cgb(&g);
        let scc_cgb = SCCDecomposition::compute(&cgb);
        let part_cgb: Vec<Vec<usize>> = scc_cgb
            .sccs
            .iter()
            .map(|s| s.nodes.iter().map(|&a| addr_to_index(a)).collect())
            .collect();
        assert_valid_scc("cgb::SCCDecomposition", seed, &part_cgb, &reach, n);

        // 1b. transitive_closure::SccDecomposition (iterative, HashMap-based).
        let dg = build_digraph(&g);
        let scc_tc = SccDecomposition::compute(&dg);
        let part_tc: Vec<Vec<usize>> = scc_tc
            .sccs
            .iter()
            .map(|s| s.iter().map(|&a| addr_to_index(a)).collect())
            .collect();
        assert_valid_scc("transitive_closure::SccDecomposition", seed, &part_tc, &reach, n);

        // 1c. XrefGraph::strongly_connected_components (lib.rs, iterative).
        let xg = build_xrefgraph(&g);
        let scc_xg = xg.strongly_connected_components();
        let part_xg: Vec<Vec<usize>> = scc_xg
            .iter()
            .map(|s| s.iter().map(|a| addr_to_index(a.0)).collect())
            .collect();
        assert_valid_scc("XrefGraph::scc", seed, &part_xg, &reach, n);

        // 1d. xref_query::CallGraph::strongly_connected_components (recursive).
        let qcg = build_qcallgraph(&g);
        let scc_q = qcg.strongly_connected_components();
        let part_q: Vec<Vec<usize>> = scc_q
            .iter()
            .map(|s| s.iter().map(|a| addr_to_index(a.0)).collect())
            .collect();
        assert_valid_scc("xref_query::CallGraph::scc", seed, &part_q, &reach, n);

        // ── (2) Topological sort vs cycle oracle ──────────────────────────────

        // 2a. call_graph_builder::CallGraph::topological_sort (Kahn, Result).
        match cgb.topological_sort() {
            Ok(order) => {
                assert!(
                    !has_cycle,
                    "[cgb::topo] seed {seed}: returned Ok on a cyclic graph"
                );
                assert_topo_valid_cgb("cgb::topo", seed, &order, &g);
            }
            Err(_) => assert!(
                has_cycle,
                "[cgb::topo] seed {seed}: returned Err on an acyclic graph"
            ),
        }

        // 2b. xref_query::CallGraph::topological_sort (Kahn, Option).
        match qcg.topological_sort() {
            Some(order) => {
                assert!(
                    !has_cycle,
                    "[q::topo] seed {seed}: returned Some on a cyclic graph"
                );
                let idx_order: Vec<usize> = order.iter().map(|a| addr_to_index(a.0)).collect();
                assert_topo_valid("q::topo", seed, &idx_order, &g);
            }
            None => assert!(
                has_cycle,
                "[q::topo] seed {seed}: returned None on an acyclic graph"
            ),
        }

        // ── (3) Reachability / transitive-closure impls vs brute-force BFS ────

        let fw = FwClosure::compute(&dg);
        let qclosure = QClosure::compute(&qcg);
        let hier = build_hierarchy(&g);

        for i in 0..n {
            let ai = Graph::addr(i);
            let ai_addr = Address::new(ai);

            // Collect each impl's reachable-from-i set (inclusive of i where
            // that impl includes self).
            let r_cgb = cgb.reachable_from(ai);
            let r_q = qcg.reachable_from(ai_addr);
            let r_bfs = BfsReachability::bfs_reachable(&dg, ai);
            let r_xg = xg.reachable_from(ai_addr);
            let r_qclos = qclosure.reachable_from(ai_addr);
            // call_hierarchy excludes the start node.
            let r_hier: HashSet<u64> = hier
                .reachable_callees(ai, 0)
                .into_iter()
                .collect();

            for j in 0..n {
                let aj = Graph::addr(j);
                let aj_addr = Address::new(aj);
                let expect = reach[i][j]; // includes self at i==j

                assert_eq!(
                    r_cgb.contains(&aj),
                    expect,
                    "[cgb::reachable_from] seed {seed}: {i}->{j}"
                );
                assert_eq!(
                    r_q.contains(&aj_addr),
                    expect,
                    "[q::reachable_from] seed {seed}: {i}->{j}"
                );
                assert_eq!(
                    r_bfs.contains(&aj),
                    expect,
                    "[BfsReachability] seed {seed}: {i}->{j}"
                );
                assert_eq!(
                    r_xg.contains(&aj_addr),
                    expect,
                    "[XrefGraph::reachable_from] seed {seed}: {i}->{j}"
                );
                assert_eq!(
                    xg.is_reachable(ai_addr, aj_addr),
                    expect,
                    "[XrefGraph::is_reachable] seed {seed}: {i}->{j}"
                );
                // xref_query TransitiveClosure (reverse-topo/fixpoint sweep).
                assert_eq!(
                    r_qclos.contains(&aj_addr),
                    expect,
                    "[QClosure::reachable_from] seed {seed}: {i}->{j}"
                );
                assert_eq!(
                    qclosure.can_reach(ai_addr, aj_addr),
                    expect,
                    "[QClosure::can_reach] seed {seed}: {i}->{j}"
                );
                // Floyd-Warshall closure (is_reachable includes self-diagonal).
                assert_eq!(
                    fw.is_reachable(ai, aj),
                    expect,
                    "[FwClosure::is_reachable] seed {seed}: {i}->{j}"
                );
                // call_hierarchy excludes self.
                let hier_expect = expect && i != j;
                assert_eq!(
                    r_hier.contains(&aj),
                    hier_expect,
                    "[CallHierarchy::reachable_callees] seed {seed}: {i}->{j}"
                );
            }
        }
    }
}

/// Verify `order` (index space) is a valid topological order for `g`.
fn assert_topo_valid(label: &str, seed: u64, order: &[usize], g: &Graph) {
    assert_eq!(order.len(), g.n, "[{label}] seed {seed}: order length mismatch");
    let mut pos = vec![usize::MAX; g.n];
    for (p, &node) in order.iter().enumerate() {
        pos[node] = p;
    }
    for (i, &p) in pos.iter().enumerate() {
        assert_ne!(p, usize::MAX, "[{label}] seed {seed}: node {i} missing from order");
    }
    for &(u, v) in &g.edges {
        assert!(
            pos[u] < pos[v],
            "[{label}] seed {seed}: edge {u}->{v} violates order (pos {} !< {})",
            pos[u],
            pos[v]
        );
    }
}

/// Same as `assert_topo_valid` but for address-space output.
fn assert_topo_valid_cgb(label: &str, seed: u64, order: &[u64], g: &Graph) {
    let idx: Vec<usize> = order.iter().map(|&a| addr_to_index(a)).collect();
    assert_topo_valid(label, seed, &idx, g);
}
