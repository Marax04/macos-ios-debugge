//! Independent brute-force oracles for `call_graph_builder`, plus a randomized
//! differential test against the production implementation.
//!
//! Every oracle here is derived from the *definition* of the property, never
//! from the shape of the production algorithm:
//!   * reachability  — transitive closure by repeated squaring over an edge set
//!   * ancestors     — reachability on the reversed edge set
//!   * SCC           — `u ~ v` iff `u ->* v` and `v ->* u` (closure, not Tarjan)
//!   * leaf/root     — direct predicate over the raw edge list
//!   * toposort      — *checked*, not recomputed: every edge must point forward

use rustre_analysis_xref::call_graph_builder::{
    CallEdge, CallGraph, CallNode, CallType, SCCDecomposition,
};
use std::collections::{BTreeMap, BTreeSet};

// ── NEGATIVE CONTROL SWITCH ──────────────────────────────────────────────────
// Flip to `true` to corrupt the oracles and prove the differential test bites.
const CORRUPT_ORACLE: bool = false;

// ── tiny deterministic RNG (no dev-deps) ─────────────────────────────────────
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 ^ (self.0 >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

/// A graph as raw data — the oracle's only input. Deliberately NOT a CallGraph.
#[derive(Clone, Debug)]
struct RawGraph {
    nodes: Vec<u64>,
    edges: Vec<(u64, u64)>,
}

impl RawGraph {
    fn to_call_graph(&self) -> CallGraph {
        let mut cg = CallGraph::new();
        for (i, &n) in self.nodes.iter().enumerate() {
            cg.add_node(CallNode::new(n, format!("f{i}")));
        }
        for &(a, b) in &self.edges {
            cg.add_edge(CallEdge::new(a, b, CallType::Direct));
        }
        cg
    }

    /// Adjacency as sets. The single corruption point: drop one edge.
    fn adj(&self) -> BTreeMap<u64, BTreeSet<u64>> {
        let mut m: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for &n in &self.nodes {
            m.entry(n).or_default();
        }
        let skip = if CORRUPT_ORACLE { 1 } else { 0 };
        for &(a, b) in self.edges.iter().skip(skip) {
            m.entry(a).or_default().insert(b);
            m.entry(b).or_default();
        }
        m
    }

    fn radj(&self) -> BTreeMap<u64, BTreeSet<u64>> {
        let rev = RawGraph {
            nodes: self.nodes.clone(),
            edges: self.edges.iter().map(|&(a, b)| (b, a)).collect(),
        };
        rev.adj()
    }
}

/// Transitive closure by repeated squaring. `closure[u]` = every `v` with a
/// path `u -> ... -> v` of length >= 1.
fn closure(adj: &BTreeMap<u64, BTreeSet<u64>>) -> BTreeMap<u64, BTreeSet<u64>> {
    let mut c = adj.clone();
    loop {
        let mut next = c.clone();
        let keys: Vec<u64> = c.keys().copied().collect();
        for u in keys {
            let outs: Vec<u64> = c[&u].iter().copied().collect();
            for v in outs {
                if let Some(vs) = c.get(&v) {
                    let add: Vec<u64> = vs.iter().copied().collect();
                    next.get_mut(&u).unwrap().extend(add);
                }
            }
        }
        if next == c {
            return c;
        }
        c = next;
    }
}

/// Reflexive reachable set from `start` (definition of `reachable_from`).
fn oracle_reachable(g: &RawGraph, start: u64) -> BTreeSet<u64> {
    let c = closure(&g.adj());
    let mut s: BTreeSet<u64> = c.get(&start).cloned().unwrap_or_default();
    s.insert(start);
    s
}

fn oracle_ancestors(g: &RawGraph, target: u64) -> BTreeSet<u64> {
    let c = closure(&g.radj());
    let mut s: BTreeSet<u64> = c.get(&target).cloned().unwrap_or_default();
    s.insert(target);
    s
}

/// SCC partition by definition: mutual reachability (self-loops make a node
/// reach itself; a lone node is its own singleton component regardless).
fn oracle_scc_partition(g: &RawGraph) -> BTreeSet<BTreeSet<u64>> {
    let c = closure(&g.adj());
    let mut parts: BTreeSet<BTreeSet<u64>> = BTreeSet::new();
    let mut done: BTreeSet<u64> = BTreeSet::new();
    for &u in &g.nodes {
        if done.contains(&u) {
            continue;
        }
        let mut comp: BTreeSet<u64> = BTreeSet::new();
        comp.insert(u);
        for &v in &g.nodes {
            if v == u {
                continue;
            }
            let uv = c.get(&u).is_some_and(|s| s.contains(&v));
            let vu = c.get(&v).is_some_and(|s| s.contains(&u));
            if uv && vu {
                comp.insert(v);
            }
        }
        for &x in &comp {
            done.insert(x);
        }
        parts.insert(comp);
    }
    parts
}

fn oracle_leaves(g: &RawGraph) -> Vec<u64> {
    let mut v: Vec<u64> = g
        .nodes
        .iter()
        .copied()
        .filter(|n| !g.edges.iter().any(|&(a, _)| a == *n))
        .collect();
    v.sort_unstable();
    v
}

fn oracle_roots(g: &RawGraph) -> Vec<u64> {
    let mut v: Vec<u64> = g
        .nodes
        .iter()
        .copied()
        .filter(|n| !g.edges.iter().any(|&(_, b)| b == *n))
        .collect();
    v.sort_unstable();
    v
}

/// Acyclic by definition: no node reaches itself.
fn oracle_is_acyclic(g: &RawGraph) -> bool {
    let c = closure(&g.adj());
    !g.nodes.iter().any(|n| c.get(n).is_some_and(|s| s.contains(n)))
}

// ── generator ────────────────────────────────────────────────────────────────

fn gen_graph(rng: &mut Rng) -> RawGraph {
    let n = rng.below(9); // 0..=8, includes the empty and single-node graphs
    let nodes: Vec<u64> = (0..n).map(|i| 0x1000 + (i as u64) * 0x10).collect();
    let mut edges = Vec::new();
    if n > 0 {
        let m = rng.below(n * 2 + 2);
        for _ in 0..m {
            let a = nodes[rng.below(n)];
            let b = nodes[rng.below(n)]; // may equal a -> self-loop
            edges.push((a, b));
        }
        // Deliberately seed an irreducible shape sometimes: two distinct
        // entries into one 2-cycle.
        if n >= 4 && rng.below(3) == 0 {
            edges.push((nodes[2], nodes[3]));
            edges.push((nodes[3], nodes[2]));
            edges.push((nodes[0], nodes[2]));
            edges.push((nodes[1], nodes[3]));
        }
    }
    RawGraph { nodes, edges }
}

// ── differential test ────────────────────────────────────────────────────────

#[test]
fn differential_call_graph_vs_oracle() {
    let mut rng = Rng(0xDECAF_BAD);
    let mut saw_selfloop = false;
    let mut saw_cycle = false;
    let mut saw_unreachable = false;
    let mut saw_irreducible = false;

    for iter in 0..3000 {
        let g = gen_graph(&mut rng);
        let cg = g.to_call_graph();

        if g.edges.iter().any(|&(a, b)| a == b) {
            saw_selfloop = true;
        }
        if !oracle_is_acyclic(&g) {
            saw_cycle = true;
        }
        if is_irreducible(&g) {
            saw_irreducible = true;
        }

        // leaf / root
        assert_eq!(cg.leaf_functions(), oracle_leaves(&g), "leaves @{iter}: {g:?}");
        assert_eq!(cg.root_functions(), oracle_roots(&g), "roots @{iter}: {g:?}");

        for &s in &g.nodes {
            // reachability
            let got: BTreeSet<u64> = cg.reachable_from(s).into_iter().collect();
            assert_eq!(got, oracle_reachable(&g, s), "reachable_from({s:#x}) @{iter}: {g:?}");
            if got.len() < g.nodes.len() {
                saw_unreachable = true;
            }
            // ancestors
            let got_a: BTreeSet<u64> = cg.ancestors_of(s).into_iter().collect();
            assert_eq!(got_a, oracle_ancestors(&g, s), "ancestors_of({s:#x}) @{iter}: {g:?}");
        }

        // SCC: compare partitions, not Tarjan internals.
        let d = SCCDecomposition::compute(&cg);
        let got_parts: BTreeSet<BTreeSet<u64>> = d
            .sccs
            .iter()
            .map(|s| s.nodes.iter().copied().collect())
            .collect();
        assert_eq!(got_parts, oracle_scc_partition(&g), "scc @{iter}: {g:?}");
        // node_scc must agree with sccs
        for scc in &d.sccs {
            for &n in &scc.nodes {
                assert_eq!(d.node_scc.get(&n), Some(&scc.id), "node_scc @{iter}: {g:?}");
            }
        }

        // topological sort: CHECK the answer, don't recompute one.
        match cg.topological_sort() {
            Ok(order) => {
                assert!(oracle_is_acyclic(&g), "Ok toposort on cyclic graph @{iter}: {g:?}");
                let set: BTreeSet<u64> = order.iter().copied().collect();
                assert_eq!(set, g.nodes.iter().copied().collect::<BTreeSet<_>>(),
                    "toposort not a permutation @{iter}: {g:?}");
                assert_eq!(set.len(), order.len(), "toposort has duplicates @{iter}");
                let pos: BTreeMap<u64, usize> =
                    order.iter().enumerate().map(|(i, &v)| (v, i)).collect();
                for &(a, b) in &g.edges {
                    assert!(pos[&a] < pos[&b],
                        "edge {a:#x}->{b:#x} points backward @{iter}: {order:?} {g:?}");
                }
            }
            Err(partial) => {
                assert!(!oracle_is_acyclic(&g), "Err toposort on acyclic graph @{iter}: {g:?}");
                // the partial prefix must still be internally consistent
                let set: BTreeSet<u64> = partial.iter().copied().collect();
                assert_eq!(set.len(), partial.len(), "partial has duplicates @{iter}");
                assert!(partial.len() < g.nodes.len(), "partial is complete @{iter}");
            }
        }

        // determinism: same input, same output, twice.
        let cg2 = g.to_call_graph();
        assert_eq!(cg.topological_sort(), cg2.topological_sort(), "toposort nondeterministic @{iter}");
        assert_eq!(cg.leaf_functions(), cg2.leaf_functions(), "leaves nondeterministic @{iter}");
        let d2 = SCCDecomposition::compute(&cg2);
        let p2: BTreeSet<BTreeSet<u64>> =
            d2.sccs.iter().map(|s| s.nodes.iter().copied().collect()).collect();
        assert_eq!(got_parts, p2, "scc nondeterministic @{iter}");
    }

    assert!(saw_selfloop, "generator never produced a self-loop");
    assert!(saw_cycle, "generator never produced a cycle");
    assert!(saw_unreachable, "generator never produced an unreachable node");
    assert!(saw_irreducible, "generator never produced an irreducible loop");
}

/// Irreducible = a cycle with two distinct external entry points.
fn is_irreducible(g: &RawGraph) -> bool {
    let parts = oracle_scc_partition(g);
    parts.iter().any(|comp| {
        if comp.len() < 2 {
            return false;
        }
        let entries: BTreeSet<u64> = comp
            .iter()
            .filter(|n| g.edges.iter().any(|&(a, b)| b == **n && !comp.contains(&a)))
            .copied()
            .collect();
        entries.len() >= 2
    })
}

#[test]
fn empty_and_singleton_graphs() {
    let g = RawGraph { nodes: vec![], edges: vec![] };
    let cg = g.to_call_graph();
    assert_eq!(cg.topological_sort(), Ok(vec![]));
    assert!(cg.leaf_functions().is_empty());

    let g = RawGraph { nodes: vec![0x1000], edges: vec![(0x1000, 0x1000)] };
    let cg = g.to_call_graph();
    assert!(cg.topological_sort().is_err(), "self-loop must not toposort");
    assert_eq!(
        SCCDecomposition::compute(&cg).sccs.len(),
        1
    );
}

/// Documented behavioural gap: a self-recursive function *is* a cycle, but
/// `SCC::is_cycle()` is defined as `nodes.len() > 1`, so `cycles()` misses it.
/// Pinned here so a future change to either side is a deliberate one.
#[test]
fn self_recursion_is_not_reported_as_a_cycle() {
    let g = RawGraph { nodes: vec![0x1000], edges: vec![(0x1000, 0x1000)] };
    let cg = g.to_call_graph();
    let d = SCCDecomposition::compute(&cg);
    assert!(d.cycles().is_empty(), "if this fires, cycles() now sees self-recursion");
    assert_eq!(d.trivial().len(), 1);
    // ...yet the graph is genuinely cyclic by definition:
    assert!(!oracle_is_acyclic(&g));
    assert!(cg.topological_sort().is_err());
}
