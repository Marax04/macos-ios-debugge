//! Cross-crate differential test: independently-written reachability /
//! transitive-closure implementations from three crates must agree with a
//! brute-force BFS oracle on random directed graphs (cycles, self-loops,
//! duplicate edges included).
//!
//! Implementations under test (each bridged to its documented semantics):
//!   1. rustre-analysis-cfg   `ControlFlowGraph::reachable_from`
//!      (start-inclusive BFS over CfgEdges)
//!   2. rustre-analysis-xref  `xref_query::CallGraph::reachable_from` /
//!      `can_reach` (start-inclusive BFS) and
//!      `xref_query::TransitiveClosure::compute` (topo-sweep / fixpoint,
//!      self-inclusive) — also oracle-fuzzed in-crate (soundness fuzz in
//!      xref_query's tests), re-checked here against the shared oracle.
//!   3. rustre-analysis-xref  `transitive_closure` module (orphaned
//!      Floyd-Warshall `TransitiveClosure`, `BfsReachability`,
//!      `ReachabilitySet`) — FW `reachable_from`/`can_reach` exclude self
//!      unless the node is on a genuine cycle; `is_reachable` is reflexive.
//!   4. rustre-analysis-dataflow `trace_callers_backward` /
//!      `trace_callees_forward` (level-BFS over (caller, callee) edge
//!      slices; union of levels = strict reachability, origin excluded,
//!      hops capped at 10 — always enough for n ≤ 10 nodes).
//!
//! Style follows tests/cross_crate_scc.rs (same XorShift, same graph
//! generator, same oracle matrix).

use rustre_analysis_cfg::{
    BasicBlock, CfgEdge, ControlFlowGraph, DominatorTree, EdgeKind, PostDominatorTree,
};
use rustre_analysis_dataflow::{trace_callees_forward, trace_callers_backward};
use rustre_analysis_xref::transitive_closure as fwtc;
use rustre_analysis_xref::xref_query::CallGraph as QCallGraph;
use rustre_analysis_xref::xref_query::TransitiveClosure as QClosure;
use rustre_core::address::Address;
use std::collections::{BTreeSet, HashMap};

fn addr(i: usize) -> u64 {
    0x1000 + (i as u64) * 8
}

fn to_index(a: u64) -> usize {
    ((a - 0x1000) / 8) as usize
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Random directed graph over indices 0..n, self-loops and duplicates allowed.
struct Graph {
    n: usize,
    edges: Vec<(usize, usize)>,
}

impl Graph {
    fn random(rng: &mut XorShift) -> Self {
        let n = 2 + (rng.below(9) as usize); // 2..=10 nodes
        let edge_count = rng.below((2 * n + 2) as u64) as usize;
        let mut edges = Vec::new();
        for _ in 0..edge_count {
            let u = rng.below(n as u64) as usize;
            let v = rng.below(n as u64) as usize; // may equal u -> self-loop
            edges.push((u, v));
        }
        Self { n, edges }
    }

    /// Oracle: strict reachability `strict[s]` = nodes reachable from `s`
    /// via a path of >= 1 edge (so `s` itself is included iff it lies on a
    /// cycle / self-loop). Plain BFS, independent of every implementation
    /// under test.
    fn strict_reach(&self) -> Vec<BTreeSet<usize>> {
        let mut adj = vec![Vec::new(); self.n];
        for &(u, v) in &self.edges {
            adj[u].push(v);
        }
        (0..self.n)
            .map(|s| {
                let mut seen: BTreeSet<usize> = BTreeSet::new();
                let mut stack: Vec<usize> = adj[s].clone();
                while let Some(u) = stack.pop() {
                    if seen.insert(u) {
                        stack.extend(adj[u].iter().copied());
                    }
                }
                seen
            })
            .collect()
    }
}

/// Start-inclusive view of the oracle set.
fn inclusive(strict: &BTreeSet<usize>, s: usize) -> BTreeSet<usize> {
    let mut out = strict.clone();
    out.insert(s);
    out
}

/// Strict backward oracle: nodes that reach `t` via >= 1 edge.
fn strict_coreach(strict: &[BTreeSet<usize>], t: usize) -> BTreeSet<usize> {
    strict
        .iter()
        .enumerate()
        .filter(|(_, r)| r.contains(&t))
        .map(|(u, _)| u)
        .collect()
}

// ── builders per implementation ──────────────────────────────────────────────

fn build_cfg(g: &Graph) -> ControlFlowGraph {
    let mut blocks: HashMap<Address, BasicBlock> = HashMap::new();
    for i in 0..g.n {
        blocks.insert(
            Address::new(addr(i)),
            BasicBlock {
                start: Address::new(addr(i)),
                end: Address::new(addr(i)),
                instructions: Vec::new(),
            },
        );
    }
    let edges: Vec<CfgEdge> = g
        .edges
        .iter()
        .map(|&(u, v)| CfgEdge {
            from: Address::new(addr(u)),
            to: Address::new(addr(v)),
            kind: EdgeKind::Unconditional,
        })
        .collect();
    ControlFlowGraph {
        blocks,
        edges,
        entry: Address::new(addr(0)),
        dom_tree: DominatorTree::default(),
        loops: Vec::new(),
        post_dom_tree: PostDominatorTree::default(),
    }
}

fn build_qcallgraph(g: &Graph) -> QCallGraph {
    let mut cg = QCallGraph::default();
    for i in 0..g.n {
        let a = Address::new(addr(i));
        cg.nodes.insert(a);
        cg.adj.entry(a).or_default();
        cg.rev.entry(a).or_default();
    }
    // Collapse duplicate (u,v) into weighted edges, matching CallGraph::build.
    let mut counts: HashMap<(usize, usize), u32> = HashMap::new();
    for &(u, v) in &g.edges {
        *counts.entry((u, v)).or_insert(0) += 1;
    }
    let mut sorted: Vec<((usize, usize), u32)> = counts.into_iter().collect();
    sorted.sort_by_key(|&((u, v), _)| (u, v));
    for ((u, v), c) in sorted {
        let (fa, ta) = (Address::new(addr(u)), Address::new(addr(v)));
        cg.adj.entry(fa).or_default().push((ta, c));
        cg.rev.entry(ta).or_default().push((fa, c));
    }
    cg
}

fn build_digraph(g: &Graph) -> fwtc::DiGraph {
    let mut dg = fwtc::DiGraph::new();
    for &(u, v) in &g.edges {
        dg.add_edge(addr(u), addr(v));
    }
    dg
}

fn addrs_to_indices<I: IntoIterator<Item = u64>>(it: I) -> BTreeSet<usize> {
    it.into_iter().map(to_index).collect()
}

// ── the differential test ────────────────────────────────────────────────────

#[test]
fn reachability_agrees_across_crates_and_oracle() {
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    for trial in 0..1000 {
        let g = Graph::random(&mut rng);
        let strict = g.strict_reach();

        let cfg = build_cfg(&g);
        let qcg = build_qcallgraph(&g);
        let qtc = QClosure::compute(&qcg);
        let dg = build_digraph(&g);
        let fw = fwtc::TransitiveClosure::compute(&dg);
        let rset = fwtc::ReachabilitySet::compute(&dg);
        let flat: Vec<(u64, u64)> = g
            .edges
            .iter()
            .map(|&(u, v)| (addr(u), addr(v)))
            .collect();
        // Nodes that actually exist in the edge-only DiGraph.
        let dg_nodes: BTreeSet<usize> = g
            .edges
            .iter()
            .flat_map(|&(u, v)| [u, v])
            .collect();

        let ctx = |label: &str, s: usize| {
            format!(
                "trial {trial}: [{label}] from node {s} (n={}, edges={:?})",
                g.n, g.edges
            )
        };

        for s in 0..g.n {
            let incl = inclusive(&strict[s], s);
            let co = strict_coreach(&strict, s);
            let co_incl = {
                let mut c = co.clone();
                c.insert(s);
                c
            };

            // 1. cfg BFS: start-inclusive.
            let got = addrs_to_indices(
                cfg.reachable_from(Address::new(addr(s)))
                    .into_iter()
                    .map(|a| a.as_u64()),
            );
            assert_eq!(got, incl, "{}", ctx("cfg::reachable_from", s));

            // 2a. xref_query CallGraph BFS: start-inclusive, forward + backward.
            let got = addrs_to_indices(
                qcg.reachable_from(Address::new(addr(s)))
                    .into_iter()
                    .map(|a| a.as_u64()),
            );
            assert_eq!(got, incl, "{}", ctx("xref_query::CallGraph::reachable_from", s));
            let got = addrs_to_indices(
                qcg.can_reach(Address::new(addr(s)))
                    .into_iter()
                    .map(|a| a.as_u64()),
            );
            assert_eq!(got, co_incl, "{}", ctx("xref_query::CallGraph::can_reach", s));

            // 2b. xref_query TransitiveClosure: self-inclusive sets.
            let got = addrs_to_indices(
                qtc.reachable_from(Address::new(addr(s)))
                    .iter()
                    .map(|a| a.as_u64()),
            );
            assert_eq!(got, incl, "{}", ctx("xref_query::TransitiveClosure", s));

            // 3. Orphaned Floyd-Warshall module (only nodes present in the
            //    edge-built DiGraph; absent nodes return empty sets, and the
            //    oracle strict set for an isolated node is empty too).
            let got = addrs_to_indices(fw.reachable_from(addr(s)));
            assert_eq!(
                got, strict[s],
                "{}",
                ctx("transitive_closure::TransitiveClosure::reachable_from", s)
            );
            let got = addrs_to_indices(fw.can_reach(addr(s)));
            assert_eq!(
                got, co,
                "{}",
                ctx("transitive_closure::TransitiveClosure::can_reach", s)
            );
            for t in 0..g.n {
                let expect = if dg_nodes.contains(&s) && dg_nodes.contains(&t) {
                    s == t || strict[s].contains(&t) // reflexive for known nodes
                } else {
                    false // unknown to the DiGraph
                };
                assert_eq!(
                    fw.is_reachable(addr(s), addr(t)),
                    expect,
                    "{} -> node {t}",
                    ctx("transitive_closure::TransitiveClosure::is_reachable", s)
                );
            }
            let got = addrs_to_indices(fwtc::BfsReachability::bfs_reachable(&dg, addr(s)));
            assert_eq!(got, incl, "{}", ctx("transitive_closure::BfsReachability", s));
            if dg_nodes.contains(&s) {
                let got = addrs_to_indices(
                    rset.reachable_from(addr(s)).unwrap().iter().copied(),
                );
                assert_eq!(got, incl, "{}", ctx("transitive_closure::ReachabilitySet", s));
            }

            // 4. dataflow level-BFS traces: union of levels = strict
            //    reachability with the origin excluded (10-hop cap can never
            //    bind at n <= 10 nodes: the longest simple path is 9 edges).
            let ft = trace_callees_forward(addr(s), 10, &flat);
            let got: BTreeSet<usize> = ft
                .levels
                .iter()
                .flatten()
                .map(|n| to_index(n.addr))
                .collect();
            let mut expect = strict[s].clone();
            expect.remove(&s);
            assert_eq!(got, expect, "{}", ctx("dataflow::trace_callees_forward", s));
            assert_eq!(ft.total, got.len(), "{} total", ctx("dataflow forward total", s));

            let bt = trace_callers_backward(addr(s), 10, &flat);
            let got: BTreeSet<usize> = bt
                .levels
                .iter()
                .flatten()
                .map(|n| to_index(n.addr))
                .collect();
            let mut expect = co.clone();
            expect.remove(&s);
            assert_eq!(got, expect, "{}", ctx("dataflow::trace_callers_backward", s));
            assert_eq!(bt.total, got.len(), "{} total", ctx("dataflow backward total", s));
        }
    }
}

/// Fixed pathological shapes every implementation must agree on.
#[test]
fn reachability_agrees_on_fixed_shapes() {
    let shapes: Vec<Graph> = vec![
        // Self-loop plus isolated node.
        Graph { n: 2, edges: vec![(0, 0)] },
        // 2-cycle.
        Graph { n: 2, edges: vec![(0, 1), (1, 0)] },
        // Cycle with a chord and a tail.
        Graph { n: 5, edges: vec![(0, 1), (1, 2), (2, 3), (3, 0), (1, 3), (3, 4)] },
        // Two disjoint cycles bridged one-way.
        Graph { n: 6, edges: vec![(0, 1), (1, 0), (1, 2), (2, 3), (3, 4), (4, 2), (4, 5)] },
        // Duplicate edges and a self-loop on a cycle member.
        Graph { n: 3, edges: vec![(0, 1), (0, 1), (1, 0), (1, 1), (1, 2)] },
    ];
    for (k, g) in shapes.iter().enumerate() {
        let strict = g.strict_reach();
        let cfg = build_cfg(g);
        let dg = build_digraph(g);
        let fw = fwtc::TransitiveClosure::compute(&dg);
        let qcg = build_qcallgraph(g);
        let qtc = QClosure::compute(&qcg);
        for s in 0..g.n {
            let incl = inclusive(&strict[s], s);
            let got = addrs_to_indices(
                cfg.reachable_from(Address::new(addr(s)))
                    .into_iter()
                    .map(|a| a.as_u64()),
            );
            assert_eq!(got, incl, "shape {k}: cfg from {s}");
            let got = addrs_to_indices(
                qtc.reachable_from(Address::new(addr(s)))
                    .iter()
                    .map(|a| a.as_u64()),
            );
            assert_eq!(got, incl, "shape {k}: xref_query closure from {s}");
            let got = addrs_to_indices(fw.reachable_from(addr(s)));
            assert_eq!(got, strict[s], "shape {k}: FW closure from {s}");
        }
    }
}
