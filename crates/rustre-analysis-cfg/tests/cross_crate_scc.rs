//! Cross-crate differential test: four independently-written SCC
//! implementations from three crates must produce the same partition
//! (as a set of node-sets) on random directed graphs, and that partition
//! must match a brute-force mutual-reachability oracle.
//!
//! Implementations under test:
//!   1. rustre-analysis-cfg   `CfgScc::compute` (Address-keyed iterative Tarjan)
//!   2. rustre-analysis-xref  `call_graph_builder::SCCDecomposition::compute`
//!      (index-based iterative Tarjan over u64 addresses)
//!   3. rustre-analysis-xref  `xref_query::CallGraph::strongly_connected_components`
//!      (Address-keyed Tarjan)
//!   4. rustre-analysis-fn    `recursive_detection::tarjan_sccs`
//!      (petgraph::algo::tarjan_scc over NodeIndex)
//!
//! Style follows tests/cross_crate_dominators.rs and rustre-analysis-xref's
//! in-crate soundness_fuzz.rs.

use rustre_analysis_cfg::{
    BasicBlock, CfgEdge, CfgScc, ControlFlowGraph, DominatorTree, EdgeKind, PostDominatorTree,
};
use rustre_analysis_fn::recursive_detection as fnrec;
use rustre_analysis_xref::call_graph_builder as cgb;
use rustre_analysis_xref::xref_query::CallGraph as QCallGraph;
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

    /// Brute-force reachability matrix (reflexive: reach[i][i] = true).
    fn reach_matrix(&self) -> Vec<Vec<bool>> {
        let mut adj = vec![Vec::new(); self.n];
        for &(u, v) in &self.edges {
            adj[u].push(v);
        }
        let mut reach = vec![vec![false; self.n]; self.n];
        for s in 0..self.n {
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
}

/// Canonical partition form: set of sets of node indices.
type Partition = BTreeSet<BTreeSet<usize>>;

fn canon(parts: impl IntoIterator<Item = Vec<usize>>) -> Partition {
    parts
        .into_iter()
        .map(|c| c.into_iter().collect::<BTreeSet<usize>>())
        .collect()
}

/// Oracle SCC partition from the mutual-reachability matrix.
fn oracle_partition(reach: &[Vec<bool>], n: usize) -> Partition {
    let mut out: Partition = BTreeSet::new();
    for i in 0..n {
        let comp: BTreeSet<usize> = (0..n).filter(|&j| reach[i][j] && reach[j][i]).collect();
        out.insert(comp);
    }
    out
}

// ── builders per implementation ──────────────────────────────────────────────

fn scc_cfg(g: &Graph) -> Partition {
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
    // CfgScc::compute only reads blocks/edges; dominator machinery can stay empty.
    let cfg = ControlFlowGraph {
        blocks,
        edges,
        entry: Address::new(addr(0)),
        dom_tree: DominatorTree::default(),
        loops: Vec::new(),
        post_dom_tree: PostDominatorTree::default(),
    };
    canon(
        CfgScc::compute(&cfg)
            .components
            .into_iter()
            .map(|c| c.nodes.into_iter().map(|a| to_index(a.as_u64())).collect()),
    )
}

fn scc_xref_builder(g: &Graph) -> Partition {
    let mut cg = cgb::CallGraph::new();
    for i in 0..g.n {
        cg.add_node(cgb::CallNode::new(addr(i), ""));
    }
    for &(u, v) in &g.edges {
        cg.add_edge(cgb::CallEdge::new(addr(u), addr(v), cgb::CallType::Direct));
    }
    canon(
        cgb::SCCDecomposition::compute(&cg)
            .sccs
            .into_iter()
            .map(|s| s.nodes.into_iter().map(to_index).collect()),
    )
}

fn scc_xref_query(g: &Graph) -> Partition {
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
    canon(
        cg.strongly_connected_components()
            .into_iter()
            .map(|s| s.into_iter().map(|a| to_index(a.as_u64())).collect()),
    )
}

fn scc_fn(g: &Graph) -> Partition {
    let mut cg = fnrec::CallGraph::new();
    for i in 0..g.n {
        cg.add_node(Address::new(addr(i)));
    }
    for &(u, v) in &g.edges {
        cg.add_edge(fnrec::CallEdge {
            caller: Address::new(addr(u)),
            callee: Address::new(addr(v)),
            is_tail_call: false,
        });
    }
    canon(
        fnrec::tarjan_sccs(&cg)
            .into_iter()
            .map(|s| s.members.into_iter().map(|a| to_index(a.as_u64())).collect()),
    )
}

// ── the differential test ────────────────────────────────────────────────────

#[test]
fn scc_partitions_agree_across_crates_and_oracle() {
    let mut rng = XorShift(0x0123_4567_89ab_cdef);
    for trial in 0..1000 {
        let g = Graph::random(&mut rng);
        let reach = g.reach_matrix();
        let oracle = oracle_partition(&reach, g.n);

        let p_cfg = scc_cfg(&g);
        let p_cgb = scc_xref_builder(&g);
        let p_q = scc_xref_query(&g);
        let p_fn = scc_fn(&g);

        for (label, p) in [
            ("cfg::CfgScc", &p_cfg),
            ("xref::call_graph_builder::SCCDecomposition", &p_cgb),
            ("xref::xref_query::CallGraph::scc", &p_q),
            ("fn::recursive_detection::tarjan_sccs", &p_fn),
        ] {
            assert_eq!(
                p, &oracle,
                "trial {trial}: [{label}] partition disagrees with mutual-reachability \
                 oracle (n={}, edges={:?})",
                g.n, g.edges
            );
        }
    }
}

/// Directed pathological shapes every implementation must agree on.
#[test]
fn scc_partitions_agree_on_fixed_shapes() {
    let shapes: Vec<Graph> = vec![
        // Single self-loop plus isolated node.
        Graph { n: 2, edges: vec![(0, 0)] },
        // 2-cycle.
        Graph { n: 2, edges: vec![(0, 1), (1, 0)] },
        // Full 4-cycle with a chord and a tail.
        Graph { n: 5, edges: vec![(0, 1), (1, 2), (2, 3), (3, 0), (1, 3), (3, 4)] },
        // Two disjoint cycles bridged one-way.
        Graph { n: 6, edges: vec![(0, 1), (1, 0), (1, 2), (2, 3), (3, 4), (4, 2), (4, 5)] },
        // Duplicate edges and a self-loop on a cycle member.
        Graph { n: 3, edges: vec![(0, 1), (0, 1), (1, 0), (1, 1), (1, 2)] },
    ];
    for (k, g) in shapes.iter().enumerate() {
        let oracle = oracle_partition(&g.reach_matrix(), g.n);
        assert_eq!(scc_cfg(g), oracle, "shape {k}: cfg");
        assert_eq!(scc_xref_builder(g), oracle, "shape {k}: cgb");
        assert_eq!(scc_xref_query(g), oracle, "shape {k}: q");
        assert_eq!(scc_fn(g), oracle, "shape {k}: fn");
    }
}
