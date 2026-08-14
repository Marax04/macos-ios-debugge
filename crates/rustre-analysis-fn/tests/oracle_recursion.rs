//! Independent brute-force oracles for `recursive_detection` + `callgraph`.
//!
//! The oracles are derived from the DEFINITIONS of the properties, never from
//! the production algorithms:
//!   * direct recursion  — `f` is directly recursive iff some path of length 1
//!     goes `f -> f` (enumerated over the raw edge list).
//!   * mutual recursion  — `u ~ v` iff `u` reaches `v` AND `v` reaches `u`,
//!     with reachability computed as a boolean transitive closure by repeated
//!     squaring.  No Tarjan, no low-links, no DFS stack.
//!   * call-graph slice  — node set = `{n : dist(root,n) <= D}` where `dist`
//!     is derived from *exactly-k-step* path enumeration; edge set = every
//!     graph edge whose source sits strictly inside the depth bound.
//!
//! NEGATIVE CONTROL: set the env var `ORACLE_CORRUPT` to one of
//! `drop_edge` / `intersect_to_union` / `depth_off_by_one` and re-run; the
//! differential tests must FAIL.  See the report in the PR description.

use std::collections::{BTreeSet, HashMap};

use rustre_analysis_fn::callgraph::callgraph_from;
use rustre_analysis_fn::recursive_detection::{
    CallEdge, CallGraph, find_direct_recursion, find_mutual_recursion, tarjan_sccs,
};
use rustre_core::address::Address;

// ───────────────────────────── corruption switch ─────────────────────────────

fn corrupt(kind: &str) -> bool {
    std::env::var("ORACLE_CORRUPT").is_ok_and(|v| v == kind)
}

// ───────────────────────────── tiny deterministic PRNG ───────────────────────

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

// ───────────────────────────── generator ─────────────────────────────────────

/// A raw graph description: node addresses + directed edges.
#[derive(Clone, Debug)]
struct RawGraph {
    nodes: Vec<u64>,
    edges: Vec<(u64, u64)>,
}

impl RawGraph {
    fn build(&self) -> CallGraph {
        let mut g = CallGraph::new();
        for &n in &self.nodes {
            g.add_node(Address::new(n));
        }
        for &(a, b) in &self.edges {
            g.add_edge(CallEdge {
                caller: Address::new(a),
                callee: Address::new(b),
                is_tail_call: false,
            });
        }
        g
    }
}

/// Random graph generator biased towards the shapes that break naive code:
/// self-loops, multiple back edges, unreachable nodes, disconnected
/// components, single-node and empty graphs, and irreducible loops
/// (two distinct entries into one cycle).
fn gen_graph(rng: &mut Rng) -> RawGraph {
    let n = rng.below(9); // 0..=8, so empty and single-node graphs occur
    let nodes: Vec<u64> = (0..n).map(|i| 0x1000 + (i as u64) * 0x10).collect();
    let mut edges: Vec<(u64, u64)> = Vec::new();
    if n == 0 {
        return RawGraph { nodes, edges };
    }

    // Dense-ish random edge soup: every ordered pair (incl. self-pairs) gets a
    // chance, so cycles, back edges and self-loops all arise naturally.
    for &a in &nodes {
        for &b in &nodes {
            if rng.below(100) < 22 {
                edges.push((a, b));
            }
        }
    }

    // Explicitly plant an irreducible region ~1 time in 3: a 2-cycle c0<->c1
    // entered from two *different* predecessors (classic irreducible loop).
    if n >= 4 && rng.below(3) == 0 {
        let (e0, e1, c0, c1) = (nodes[0], nodes[1], nodes[2], nodes[3]);
        edges.push((c0, c1));
        edges.push((c1, c0));
        edges.push((e0, c0));
        edges.push((e1, c1));
    }

    // Sometimes duplicate an edge — add_edge pushes into full_edges without
    // dedup, so parallel edges must not perturb SCC results.
    if !edges.is_empty() && rng.below(4) == 0 {
        let i = rng.below(edges.len());
        edges.push(edges[i]);
    }

    RawGraph { nodes, edges }
}

// ───────────────────────────── oracles ───────────────────────────────────────

/// Definitional: `f` directly recursive iff the edge list contains `f -> f`.
fn oracle_direct(g: &RawGraph) -> BTreeSet<u64> {
    let mut out = BTreeSet::new();
    for &(a, b) in &g.edges {
        if a == b && g.nodes.contains(&a) {
            out.insert(a);
        }
    }
    out
}

/// Boolean transitive closure by repeated squaring (index space = g.nodes).
/// `reach[i][j]` == "there is a path of length >= 1 from i to j".
fn oracle_reach(g: &RawGraph) -> (Vec<u64>, Vec<Vec<bool>>) {
    let idx: HashMap<u64, usize> = g.nodes.iter().enumerate().map(|(i, &a)| (a, i)).collect();
    let n = g.nodes.len();
    let mut m = vec![vec![false; n]; n];
    for (k, &(a, b)) in g.edges.iter().enumerate() {
        // NEGATIVE CONTROL: silently drop the first edge.
        if corrupt("drop_edge") && k == 0 {
            continue;
        }
        if let (Some(&i), Some(&j)) = (idx.get(&a), idx.get(&b)) {
            m[i][j] = true;
        }
    }
    // reach = m + m^2 + ... ; repeated squaring of (I + m) then strip nothing:
    // easier and still definitional — iterate `ceil(log2(n))+1` squarings of
    // the reflexive closure, then AND out the identity we added.
    let mut r = m.clone();
    for i in 0..n {
        r[i][i] = true; // reflexive, so squaring accumulates all path lengths
    }
    let mut steps = 1usize;
    while steps < n.max(1) {
        let mut sq = vec![vec![false; n]; n];
        for i in 0..n {
            for k in 0..n {
                if r[i][k] {
                    for j in 0..n {
                        sq[i][j] |= r[k][j];
                    }
                }
            }
        }
        r = sq;
        steps *= 2;
    }
    // Restore the true (irreflexive-unless-real-cycle) relation: i reaches i
    // only if some real edge path exists, i.e. via some successor.
    let mut reach = r.clone();
    for i in 0..n {
        reach[i][i] = (0..n).any(|k| m[i][k] && r[k][i]);
    }
    (g.nodes.clone(), reach)
}

/// `u ~ v` iff u reaches v and v reaches u. Returns the non-trivial classes.
fn oracle_mutual(g: &RawGraph) -> BTreeSet<BTreeSet<u64>> {
    let (nodes, reach) = oracle_reach(g);
    let n = nodes.len();
    let mut classes: BTreeSet<BTreeSet<u64>> = BTreeSet::new();
    for i in 0..n {
        let mut c: BTreeSet<u64> = BTreeSet::new();
        c.insert(nodes[i]);
        for j in 0..n {
            // NEGATIVE CONTROL: turn the AND (intersection of the two
            // reachability directions) into an OR (union).
            let related = if corrupt("intersect_to_union") {
                reach[i][j] || reach[j][i]
            } else {
                reach[i][j] && reach[j][i]
            };
            if i != j && related {
                c.insert(nodes[j]);
            }
        }
        if c.len() > 1 {
            classes.insert(c);
        }
    }
    classes
}

/// Every SCC (including singletons), as an equivalence partition.
fn oracle_all_sccs(g: &RawGraph) -> BTreeSet<BTreeSet<u64>> {
    let (nodes, reach) = oracle_reach(g);
    let n = nodes.len();
    let mut classes: BTreeSet<BTreeSet<u64>> = BTreeSet::new();
    for i in 0..n {
        let mut c: BTreeSet<u64> = BTreeSet::new();
        c.insert(nodes[i]);
        for j in 0..n {
            if i != j && reach[i][j] && reach[j][i] {
                c.insert(nodes[j]);
            }
        }
        classes.insert(c);
    }
    classes
}

/// Distance from `root` by *exactly-k-step* path enumeration (definitional).
fn oracle_dist(g: &RawGraph, root: u64, max: u32) -> HashMap<u64, u32> {
    let mut dist: HashMap<u64, u32> = HashMap::new();
    dist.insert(root, 0);
    let mut frontier: BTreeSet<u64> = BTreeSet::new();
    frontier.insert(root);
    for k in 1..=max {
        let mut next: BTreeSet<u64> = BTreeSet::new();
        for &(a, b) in &g.edges {
            if frontier.contains(&a) {
                next.insert(b);
            }
        }
        for b in next.iter().copied() {
            dist.entry(b).or_insert(k);
        }
        frontier = next;
    }
    dist
}

/// Slice oracle: nodes within `d` hops; edges whose source is strictly inside.
fn oracle_slice(g: &RawGraph, root: u64, d: u32) -> (BTreeSet<u64>, BTreeSet<(u64, u64)>) {
    // NEGATIVE CONTROL: off-by-one the depth bound.
    let d = if corrupt("depth_off_by_one") { d + 1 } else { d };
    let dist = oracle_dist(g, root, d);
    let nodes: BTreeSet<u64> = dist.keys().copied().collect();
    let mut edges: BTreeSet<(u64, u64)> = BTreeSet::new();
    for &(a, b) in &g.edges {
        if dist.get(&a).is_some_and(|&da| da < d) {
            edges.insert((a, b));
        }
    }
    (nodes, edges)
}

// ───────────────────────────── differential tests ────────────────────────────

#[test]
fn diff_direct_recursion_vs_oracle() {
    for seed in 0..600u64 {
        let mut rng = Rng::new(seed);
        let raw = gen_graph(&mut rng);
        let g = raw.build();
        let got: BTreeSet<u64> = find_direct_recursion(&g).iter().map(|a| a.as_u64()).collect();
        assert_eq!(got, oracle_direct(&raw), "seed {seed}: {raw:?}");
    }
}

#[test]
fn diff_mutual_recursion_vs_transitive_closure() {
    for seed in 0..600u64 {
        let mut rng = Rng::new(seed);
        let raw = gen_graph(&mut rng);
        let g = raw.build();
        let got: BTreeSet<BTreeSet<u64>> = find_mutual_recursion(&g)
            .iter()
            .map(|s| s.members.iter().map(|a| a.as_u64()).collect())
            .collect();
        assert_eq!(got, oracle_mutual(&raw), "seed {seed}: {raw:?}");
    }
}

#[test]
fn diff_all_sccs_form_the_reachability_partition() {
    for seed in 0..600u64 {
        let mut rng = Rng::new(seed);
        let raw = gen_graph(&mut rng);
        let g = raw.build();
        let sccs = tarjan_sccs(&g);
        // Partition property: every node appears exactly once.
        let total: usize = sccs.iter().map(|s| s.members.len()).sum();
        assert_eq!(total, raw.nodes.len(), "seed {seed}: SCCs not a partition");
        let got: BTreeSet<BTreeSet<u64>> = sccs
            .iter()
            .map(|s| s.members.iter().map(|a| a.as_u64()).collect())
            .collect();
        assert_eq!(got, oracle_all_sccs(&raw), "seed {seed}: {raw:?}");
    }
}

#[test]
fn diff_callgraph_slice_vs_path_enumeration() {
    let names: HashMap<u64, String> = HashMap::new();
    for seed in 0..600u64 {
        let mut rng = Rng::new(seed);
        let raw = gen_graph(&mut rng);
        if raw.nodes.is_empty() {
            continue;
        }
        let g = raw.build();
        let root = raw.nodes[rng.below(raw.nodes.len())];
        for depth in 1..=4u32 {
            let slice = callgraph_from(&g, Address::new(root), depth, &names);
            let got_nodes: BTreeSet<u64> = slice.nodes.iter().map(|n| n.addr).collect();
            let got_edges: BTreeSet<(u64, u64)> = slice.edges.iter().copied().collect();
            let (want_nodes, want_edges) = oracle_slice(&raw, root, depth);
            assert_eq!(got_nodes, want_nodes, "seed {seed} d{depth} nodes: {raw:?}");
            assert_eq!(got_edges, want_edges, "seed {seed} d{depth} edges: {raw:?}");
            // Node list must be duplicate-free.
            assert_eq!(got_nodes.len(), slice.nodes.len(), "seed {seed}: dup nodes");
        }
    }
}

#[test]
fn determinism_same_input_same_output() {
    let names: HashMap<u64, String> = HashMap::new();
    for seed in 0..200u64 {
        let mut rng = Rng::new(seed);
        let raw = gen_graph(&mut rng);
        // Rebuild the CallGraph each time: fresh HashMaps, fresh iteration order.
        let a = raw.build();
        let b = raw.build();
        assert_eq!(find_direct_recursion(&a), find_direct_recursion(&b), "seed {seed}");
        let sa: Vec<Vec<u64>> = tarjan_sccs(&a)
            .iter()
            .map(|s| s.members.iter().map(|a| a.as_u64()).collect())
            .collect();
        let sb: Vec<Vec<u64>> = tarjan_sccs(&b)
            .iter()
            .map(|s| s.members.iter().map(|a| a.as_u64()).collect())
            .collect();
        assert_eq!(sa, sb, "seed {seed}: tarjan_sccs order not deterministic");
        if let Some(&root) = raw.nodes.first() {
            let x = callgraph_from(&a, Address::new(root), 3, &names);
            let y = callgraph_from(&b, Address::new(root), 3, &names);
            assert_eq!(x, y, "seed {seed}: slice not deterministic");
        }
    }
}

#[test]
fn generator_produces_the_hard_shapes() {
    let (mut self_loop, mut empty, mut single, mut unreachable_n, mut irreducible) =
        (0, 0, 0, 0, 0);
    for seed in 0..600u64 {
        let mut rng = Rng::new(seed);
        let raw = gen_graph(&mut rng);
        if raw.nodes.is_empty() {
            empty += 1;
            continue;
        }
        if raw.nodes.len() == 1 {
            single += 1;
        }
        if raw.edges.iter().any(|&(a, b)| a == b) {
            self_loop += 1;
        }
        let root = raw.nodes[0];
        let dist = oracle_dist(&raw, root, 32);
        if raw.nodes.iter().any(|n| !dist.contains_key(n)) {
            unreachable_n += 1;
        }
        // Irreducible: some SCC of size >= 2 with >= 2 distinct external entries.
        for scc in oracle_all_sccs(&raw) {
            if scc.len() < 2 {
                continue;
            }
            let entries: BTreeSet<u64> = raw
                .edges
                .iter()
                .filter(|(a, b)| !scc.contains(a) && scc.contains(b))
                .map(|&(_, b)| b)
                .collect();
            if entries.len() >= 2 {
                irreducible += 1;
                break;
            }
        }
    }
    assert!(empty > 0, "no empty graphs");
    assert!(single > 0, "no single-node graphs");
    assert!(self_loop > 10, "too few self-loops: {self_loop}");
    assert!(unreachable_n > 10, "too few unreachable nodes: {unreachable_n}");
    assert!(irreducible > 10, "too few irreducible loops: {irreducible}");
}
