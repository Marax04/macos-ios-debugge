//! Randomized cross-implementation soundness tests (test-only module).
//!
//! This crate deliberately contains several *independent* implementations of
//! the same textbook CFG analyses (dominators, natural loops, reducibility)
//! operating on different graph representations.  These tests generate
//! bounded random CFGs with a deterministic xorshift PRNG (no external
//! dev-dependencies) and cross-check:
//!
//! * dominance frontiers (`lib.rs::DominatorTree::frontiers` and
//!   `loop_analysis::DominanceFrontier`) against the brute-force definition,
//! * natural-loop detection agreement between `cfg_algorithms`,
//!   `loop_analysis`, `cfg_loop_analyzer` and the crate-root
//!   `find_natural_loops`,
//! * reducibility agreement between `cfg_algorithms::IrreducibleCfgDetector`,
//!   `loop_analysis::{is_reducible, has_irreducible_control_flow}`,
//!   `reducibility_analysis::ReducibilityAnalysis` (T1/T2), and the Havlak
//!   detector in `irreducible_cfg`,
//! * structural invariants of the `simplify::CfgSimplifier` passes
//!   (no dangling edges, entry preserved, reachability/instruction content
//!   preserved).

use crate::cfg_algorithms::{self, SimpleCfg};
use crate::loop_analysis::{self, Cfg as LaCfg, BasicBlock as LaBlock};
use crate::reducibility_analysis::{graph_from_edges, ReducibilityAnalysis};
use crate::irreducible_cfg::{HavlakLoopDetector, IrreducibleCfgAnalysis};
use crate::simplify::CfgSimplifier;
use crate::cfg_dominators::{LengauerTarjanDominator, PostDominatorComputer};
use crate::lengauer_tarjan::compute_lt;
use crate::post_dominator::FullPostDomTree;
use crate::loop_detection::detect_loops;
use crate::back_edge::{
    classify_dfs_edges, dfs_back_edges, find_loop_headers, BackEdgeSet, DfsEdgeKind,
};
use crate::{
    find_natural_loops, BasicBlock, CfgEdge, ControlFlowGraph, DominatorTree, EdgeKind,
    PostDominatorTree,
};
use rustre_core::address::Address;
use std::collections::{BTreeSet, HashMap, HashSet};

use crate::test_prng::Xorshift;

/// Generate a random edge list over nodes `0..n_nodes`, then prune it to the
/// subgraph reachable from node 0 so that every independent implementation
/// sees the same well-formed, entry-rooted CFG (implementations differ in how
/// they treat unreachable nodes, which is not what these tests target).
fn random_reachable_edges(rng: &mut Xorshift, max_nodes: u64) -> (Vec<u64>, Vec<(u64, u64)>) {
    let n_nodes = 3 + rng.range(max_nodes - 2);
    let n_edges = n_nodes + rng.range(n_nodes + 3);
    let mut edges: BTreeSet<(u64, u64)> = BTreeSet::new();
    for _ in 0..n_edges {
        edges.insert((rng.range(n_nodes), rng.range(n_nodes)));
    }
    // Reachability from 0.
    let mut succs: HashMap<u64, Vec<u64>> = HashMap::new();
    for &(f, t) in &edges {
        succs.entry(f).or_default().push(t);
    }
    let mut reach: HashSet<u64> = HashSet::new();
    let mut stack = vec![0u64];
    while let Some(n) = stack.pop() {
        if reach.insert(n) {
            for &s in succs.get(&n).map_or(&[][..], |v| v.as_slice()) {
                stack.push(s);
            }
        }
    }
    let pruned: Vec<(u64, u64)> = edges
        .into_iter()
        .filter(|(f, t)| reach.contains(f) && reach.contains(t))
        .collect();
    let mut nodes: Vec<u64> = reach.into_iter().collect();
    nodes.sort_unstable();
    (nodes, pruned)
}

// ── Builders for each graph representation ──────────────────────────────────

fn build_simple(nodes: &[u64], edges: &[(u64, u64)]) -> SimpleCfg {
    let mut cfg = SimpleCfg::new(0);
    for &n in nodes {
        cfg.add_node(n);
    }
    for &(f, t) in edges {
        cfg.add_edge(f, t);
    }
    cfg
}

fn build_la(nodes: &[u64], edges: &[(u64, u64)]) -> LaCfg {
    let mut cfg = LaCfg::new(0);
    for &n in nodes {
        cfg.add_block(LaBlock::new(n as u32, n, n));
    }
    for &(f, t) in edges {
        cfg.add_edge(f as u32, t as u32);
    }
    cfg
}

fn a(v: u64) -> Address {
    Address::new(v)
}

/// Build a crate-root `ControlFlowGraph`. `nonempty` selects which blocks get
/// an instruction (relevant only for the simplify tests; loop tests pass all).
fn build_cfg(nodes: &[u64], edges: &[(u64, u64)], nonempty: &HashSet<u64>) -> ControlFlowGraph {
    let blocks: HashMap<Address, BasicBlock> = nodes
        .iter()
        .map(|&n| {
            let addr = a(n);
            let instructions = if nonempty.contains(&n) {
                vec![rustre_il_llil::LlilInstruction::Ret]
            } else {
                vec![]
            };
            (addr, BasicBlock { start: addr, end: addr, instructions })
        })
        .collect();
    let cfg_edges: Vec<CfgEdge> = edges
        .iter()
        .map(|&(f, t)| CfgEdge { from: a(f), to: a(t), kind: EdgeKind::Unconditional })
        .collect();
    let entry = a(0);
    let dom_tree = DominatorTree::compute(&blocks, &cfg_edges, entry);
    let post_dom_tree = PostDominatorTree::compute(&blocks, &cfg_edges);
    let mut cfg = ControlFlowGraph {
        blocks,
        edges: cfg_edges,
        entry,
        dom_tree,
        post_dom_tree,
        loops: vec![],
    };
    cfg.loops = find_natural_loops(&cfg);
    cfg
}

// ── Brute-force oracles ──────────────────────────────────────────────────────

/// `a` dominates `b` iff deleting `a` makes `b` unreachable from `entry`
/// (graphs here are pruned to entry-reachable nodes, so no vacuous cases).
fn reference_dominates(edges: &[(u64, u64)], entry: u64, a: u64, b: u64) -> bool {
    if a == b {
        return true;
    }
    let mut visited = HashSet::new();
    let mut stack = vec![entry];
    while let Some(n) = stack.pop() {
        if n == a || !visited.insert(n) {
            continue;
        }
        for &(f, t) in edges {
            if f == n {
                stack.push(t);
            }
        }
    }
    !visited.contains(&b)
}

// ── Dominance frontier fuzz ─────────────────────────────────────────────────

/// DF(n) = { y | n dominates some predecessor of y, and n does not strictly
/// dominate y } — checked with the brute-force dominance oracle.
fn reference_frontier(nodes: &[u64], edges: &[(u64, u64)], n: u64) -> BTreeSet<u64> {
    let mut df = BTreeSet::new();
    for &y in nodes {
        let strictly_dom = n != y && reference_dominates(edges, 0, n, y);
        if strictly_dom {
            continue;
        }
        let has_dominated_pred = edges
            .iter()
            .any(|&(f, t)| t == y && reference_dominates(edges, 0, n, f));
        if has_dominated_pred {
            df.insert(y);
        }
    }
    df
}

#[test]
fn dominance_frontier_matches_definition_fuzz() {
    let mut rng = Xorshift(0xABCDEF9876543211);
    for trial in 0..1200 {
        let (nodes, edges) = random_reachable_edges(&mut rng, 8);

        // Implementation 1: crate-root DominatorTree::frontiers.
        let all: HashSet<u64> = nodes.iter().copied().collect();
        let cfg = build_cfg(&nodes, &edges, &all);
        // Implementation 2: loop_analysis::DominanceFrontier.
        let la = build_la(&nodes, &edges);
        let la_dom = loop_analysis::DominatorTree::build(&la);
        let la_df = loop_analysis::DominanceFrontier::build(&la, &la_dom);

        for &n in &nodes {
            let expected = reference_frontier(&nodes, &edges, n);

            let got1: BTreeSet<u64> = cfg
                .dom_tree
                .dominance_frontier(a(n))
                .iter()
                .map(|addr| addr.0)
                .collect();
            assert_eq!(
                got1, expected,
                "trial {trial}: lib DominatorTree DF({n}) mismatch on edges {edges:?}"
            );

            let got2: BTreeSet<u64> = la_df.get(n as u32).iter().map(|&b| u64::from(b)).collect();
            assert_eq!(
                got2, expected,
                "trial {trial}: loop_analysis DominanceFrontier DF({n}) mismatch on edges {edges:?}"
            );
        }
    }
}

// ── Loop detection agreement fuzz ────────────────────────────────────────────

/// Collect `header -> union of loop bodies` maps from each implementation and
/// require them to be identical.
#[test]
fn loop_detection_implementations_agree_fuzz() {
    let mut rng = Xorshift(0x1234567890ABCDEF);
    for trial in 0..1200 {
        let (nodes, edges) = random_reachable_edges(&mut rng, 8);

        // A: cfg_algorithms::find_natural_loops (per back edge; union by header).
        let simple = build_simple(&nodes, &edges);
        let Ok(dom) = cfg_algorithms::DominatorTree::compute(&simple) else {
            continue;
        };
        let mut by_header_a: HashMap<u64, BTreeSet<u64>> = HashMap::new();
        for lp in cfg_algorithms::find_natural_loops(&simple, &dom) {
            by_header_a
                .entry(lp.header)
                .or_default()
                .extend(lp.body.iter().copied());
        }

        // B: loop_analysis::find_natural_loops (merged per header).
        let la = build_la(&nodes, &edges);
        let mut by_header_b: HashMap<u64, BTreeSet<u64>> = HashMap::new();
        for lp in loop_analysis::find_natural_loops(&la) {
            by_header_b
                .entry(u64::from(lp.header))
                .or_default()
                .extend(lp.body.iter().map(|&b| u64::from(b)));
        }

        // C: cfg_loop_analyzer::find_loops (merged per header).
        let all: HashSet<u64> = nodes.iter().copied().collect();
        let cfg = build_cfg(&nodes, &edges, &all);
        let nest = crate::cfg_loop_analyzer::find_loops(&cfg, true);
        let mut by_header_c: HashMap<u64, BTreeSet<u64>> = HashMap::new();
        for lp in &nest.loops {
            by_header_c
                .entry(lp.header.0)
                .or_default()
                .extend(lp.body.iter().map(|addr| addr.0));
        }

        // D: crate-root find_natural_loops (per back edge; union by header).
        let mut by_header_d: HashMap<u64, BTreeSet<u64>> = HashMap::new();
        for lp in &cfg.loops {
            by_header_d
                .entry(lp.header.0)
                .or_default()
                .extend(lp.body.iter().map(|addr| addr.0));
        }

        let norm = |m: &HashMap<u64, BTreeSet<u64>>| -> Vec<(u64, BTreeSet<u64>)> {
            let mut v: Vec<_> = m.iter().map(|(k, s)| (*k, s.clone())).collect();
            v.sort();
            v
        };
        let na = norm(&by_header_a);
        assert_eq!(na, norm(&by_header_b), "trial {trial}: cfg_algorithms vs loop_analysis loops mismatch on edges {edges:?}");
        assert_eq!(na, norm(&by_header_c), "trial {trial}: cfg_algorithms vs cfg_loop_analyzer loops mismatch on edges {edges:?}");
        assert_eq!(na, norm(&by_header_d), "trial {trial}: cfg_algorithms vs lib find_natural_loops mismatch on edges {edges:?}");
    }
}

// ── Reducibility agreement fuzz ──────────────────────────────────────────────

#[test]
fn reducibility_implementations_agree_fuzz() {
    let mut rng = Xorshift(0x0F1E2D3C4B5A6978);
    for trial in 0..1200 {
        let (nodes, edges) = random_reachable_edges(&mut rng, 8);

        // Oracle-ish: T1/T2 structural reduction (reducibility_analysis).
        let e32: Vec<(u32, u32)> = edges.iter().map(|&(f, t)| (f as u32, t as u32)).collect();
        let (graph, entry) = graph_from_edges(&e32);
        let t1t2_irreducible = !ReducibilityAnalysis::new(entry).is_reducible(&graph);

        // cfg_algorithms detector.
        let simple = build_simple(&nodes, &edges);
        let Ok(dom) = cfg_algorithms::DominatorTree::compute(&simple) else {
            continue;
        };
        let detector = cfg_algorithms::IrreducibleCfgDetector::is_irreducible(&simple, &dom);

        // loop_analysis: DFS back-edge dominance check + SCC multi-entry check.
        let la = build_la(&nodes, &edges);
        let back_edge_irreducible = !loop_analysis::is_reducible(&la);
        let scc_irreducible = loop_analysis::has_irreducible_control_flow(&la);

        // irreducible_cfg: full analysis (dominance test + T1/T2) and Havlak.
        let all: HashSet<u64> = nodes.iter().copied().collect();
        let cfg = build_cfg(&nodes, &edges, &all);
        let analysis = IrreducibleCfgAnalysis::analyze(&cfg);
        let havlak_irreducible = HavlakLoopDetector::detect(&cfg)
            .nodes
            .iter()
            .any(|n| n.irreducible);

        assert_eq!(detector, t1t2_irreducible, "trial {trial}: IrreducibleCfgDetector vs T1/T2 mismatch on edges {edges:?}");
        assert_eq!(back_edge_irreducible, t1t2_irreducible, "trial {trial}: loop_analysis::is_reducible vs T1/T2 mismatch on edges {edges:?}");
        assert_eq!(scc_irreducible, t1t2_irreducible, "trial {trial}: has_irreducible_control_flow vs T1/T2 mismatch on edges {edges:?}");
        assert_eq!(!analysis.is_reducible, t1t2_irreducible, "trial {trial}: IrreducibleCfgAnalysis::is_reducible vs T1/T2 mismatch on edges {edges:?}");
        assert_eq!(!analysis.t1t2_reducible, t1t2_irreducible, "trial {trial}: irreducible_cfg T1T2Reducer vs reducibility_analysis T1/T2 mismatch on edges {edges:?}");
        assert_eq!(havlak_irreducible, t1t2_irreducible, "trial {trial}: Havlak vs T1/T2 mismatch on edges {edges:?}");
    }
}

// ── Simplify invariants fuzz ────────────────────────────────────────────────

fn reachable_addrs(cfg: &ControlFlowGraph) -> HashSet<Address> {
    cfg.reachable_from(cfg.entry)
}

fn reachable_instruction_count(cfg: &ControlFlowGraph) -> usize {
    let reach = reachable_addrs(cfg);
    cfg.blocks
        .iter()
        .filter(|(addr, _)| reach.contains(addr))
        .map(|(_, b)| b.instructions.len())
        .sum()
}

fn assert_simplify_invariants(
    label: &str,
    trial: usize,
    edges: &[(u64, u64)],
    before_reach: &HashSet<Address>,
    before_instrs: usize,
    cfg: &ControlFlowGraph,
) {
    // 1. Entry block must survive.
    assert!(
        cfg.blocks.contains_key(&cfg.entry),
        "{label} trial {trial}: entry block removed (edges {edges:?})"
    );
    // 2. No dangling edges.
    for e in &cfg.edges {
        assert!(
            cfg.blocks.contains_key(&e.from),
            "{label} trial {trial}: dangling edge from {:?} (edges {edges:?})",
            e.from
        );
        assert!(
            cfg.blocks.contains_key(&e.to),
            "{label} trial {trial}: dangling edge to {:?} (edges {edges:?})",
            e.to
        );
    }
    // 3. Reachability preserved for surviving blocks.
    let after_reach = reachable_addrs(cfg);
    for addr in cfg.blocks.keys() {
        assert_eq!(
            after_reach.contains(addr),
            before_reach.contains(addr),
            "{label} trial {trial}: reachability of {addr:?} changed (edges {edges:?})"
        );
    }
    // 4. Total instruction count over reachable blocks preserved.
    assert_eq!(
        reachable_instruction_count(cfg),
        before_instrs,
        "{label} trial {trial}: reachable instruction content changed (edges {edges:?})"
    );
}

// ── Dominator agreement fuzz ─────────────────────────────────────────────────

/// Successor adjacency (Address space) for the `compute_lt` / post-dom helpers.
fn succs_adj(nodes: &[u64], edges: &[(u64, u64)]) -> HashMap<Address, Vec<Address>> {
    let mut succs: HashMap<Address, Vec<Address>> = HashMap::new();
    for &n in nodes {
        succs.entry(a(n)).or_default();
    }
    for &(f, t) in edges {
        succs.entry(a(f)).or_default().push(a(t));
    }
    succs
}

/// Cross-check every independent dominator implementation against the
/// brute-force "delete `d`, is `n` still reachable from entry?" oracle AND
/// against each other, on the same random CFGs.
#[test]
fn dominator_implementations_agree_fuzz() {
    let mut rng = Xorshift(0x2468ACE013579BDF);
    for trial in 0..1500 {
        let (nodes, edges) = random_reachable_edges(&mut rng, 12);

        // Impl 1: crate-root DominatorTree (Cooper/Harvey/Kennedy iterative).
        let all: HashSet<u64> = nodes.iter().copied().collect();
        let cfg = build_cfg(&nodes, &edges, &all);

        // Impl 2: cfg_dominators Lengauer-Tarjan.
        let lt_tree = LengauerTarjanDominator::compute(&cfg).to_dominator_tree();

        // Impl 3: lengauer_tarjan::compute_lt (independent LT on adjacency).
        let node_addrs: Vec<Address> = nodes.iter().map(|&n| a(n)).collect();
        let succs = succs_adj(&nodes, &edges);
        let lt2 = compute_lt(&node_addrs, &succs, a(0)).expect("entry present");

        for &d in &nodes {
            for &n in &nodes {
                let oracle = reference_dominates(&edges, 0, d, n);

                let got1 = cfg.dom_tree.dominates(a(d), a(n));
                assert_eq!(
                    got1, oracle,
                    "trial {trial}: lib DominatorTree dominates({d},{n})={got1} != oracle {oracle} on edges {edges:?}"
                );

                let got2 = lt_tree.dominates(a(d), a(n));
                assert_eq!(
                    got2, oracle,
                    "trial {trial}: cfg_dominators LT dominates({d},{n})={got2} != oracle {oracle} on edges {edges:?}"
                );

                let got3 = lt2.dominates(a(d), a(n));
                assert_eq!(
                    got3, oracle,
                    "trial {trial}: lengauer_tarjan compute_lt dominates({d},{n})={got3} != oracle {oracle} on edges {edges:?}"
                );
            }
        }
    }
}

/// Regression for the `cfg_dominators::LengauerTarjanDominator` reverse-postorder
/// numbering bug (minimized from a fuzz counterexample). On this CFG preorder
/// and RPO diverge; the buggy version numbered vertices in RPO and computed
/// idom(7)=idom(8)=idom(11)=0 instead of 3, which made `dominates(3, 6)` wrong.
#[test]
fn lt_dominator_preorder_regression() {
    let nodes: Vec<u64> = vec![0, 1, 2, 3, 6, 7, 8, 9, 10, 11];
    let edges: Vec<(u64, u64)> = vec![
        (0, 2), (0, 3), (1, 3), (1, 7), (1, 11), (2, 3), (2, 10), (3, 1),
        (3, 2), (3, 9), (6, 7), (7, 0), (7, 11), (8, 1), (8, 11), (9, 1),
        (9, 3), (9, 8), (9, 11), (11, 6), (11, 8),
    ];
    let all: HashSet<u64> = nodes.iter().copied().collect();
    let cfg = build_cfg(&nodes, &edges, &all);
    let lt = LengauerTarjanDominator::compute(&cfg).to_dominator_tree();
    for &n in &nodes {
        for &d in &nodes {
            assert_eq!(
                lt.dominates(a(d), a(n)),
                reference_dominates(&edges, 0, d, n),
                "LT dominates({d},{n}) disagrees with brute-force oracle"
            );
        }
    }
    // Spot-check the exact idoms that regressed.
    assert_eq!(lt.idom.get(&a(7)).copied().flatten(), Some(a(3)));
    assert_eq!(lt.idom.get(&a(8)).copied().flatten(), Some(a(3)));
    assert_eq!(lt.idom.get(&a(11)).copied().flatten(), Some(a(3)));
    assert!(lt.dominates(a(3), a(6)));
}

// ── Post-dominator agreement fuzz ────────────────────────────────────────────

/// Exit nodes: nodes with no outgoing edge.
fn exit_nodes(nodes: &[u64], edges: &[(u64, u64)]) -> Vec<u64> {
    let has_succ: HashSet<u64> = edges.iter().map(|&(f, _)| f).collect();
    nodes.iter().copied().filter(|n| !has_succ.contains(n)).collect()
}

/// Whether `n` can reach any exit in the forward graph (optionally with `del`
/// deleted). Returns true if some exit is reachable from `n`.
fn reaches_exit(nodes: &[u64], edges: &[(u64, u64)], exits: &HashSet<u64>, n: u64, del: Option<u64>) -> bool {
    if Some(n) == del {
        return false;
    }
    let mut visited = HashSet::new();
    let mut stack = vec![n];
    while let Some(c) = stack.pop() {
        if Some(c) == del || !visited.insert(c) {
            continue;
        }
        if exits.contains(&c) {
            return true;
        }
        for &(f, t) in edges {
            if f == c {
                stack.push(t);
            }
        }
    }
    let _ = nodes;
    false
}

/// `d` post-dominates `n` iff every path from `n` to any exit passes through
/// `d` — checked by deletion: after removing `d`, `n` can no longer reach any
/// exit. Only meaningful when `n` can reach an exit at all (returns `None`
/// otherwise, signalling the pair should be skipped).
fn reference_postdominates(nodes: &[u64], edges: &[(u64, u64)], exits: &HashSet<u64>, d: u64, n: u64) -> Option<bool> {
    if !reaches_exit(nodes, edges, exits, n, None) {
        return None; // vacuous / implementation-dependent
    }
    if d == n {
        return Some(true);
    }
    Some(!reaches_exit(nodes, edges, exits, n, Some(d)))
}

/// Cross-check every post-dominator implementation against the brute-force
/// "delete `d`, can `n` still reach an exit?" oracle AND against each other.
#[test]
fn post_dominator_implementations_agree_fuzz() {
    let mut rng = Xorshift(0x13579BDF2468ACE0);
    for trial in 0..1500 {
        let (nodes, edges) = random_reachable_edges(&mut rng, 12);
        let exits_v = exit_nodes(&nodes, &edges);
        let exits: HashSet<u64> = exits_v.iter().copied().collect();

        // Impl 1: crate-root PostDominatorTree (built inside build_cfg).
        let all: HashSet<u64> = nodes.iter().copied().collect();
        let cfg = build_cfg(&nodes, &edges, &all);

        // Impl 2: cfg_dominators PostDominatorComputer.
        let pd2 = PostDominatorComputer::compute(&cfg);

        // Impl 3: post_dominator::FullPostDomTree.
        let exit_addrs: Vec<Address> = exits_v.iter().map(|&n| a(n)).collect();
        let pd3 = FullPostDomTree::compute(&cfg.blocks, &cfg.edges, &exit_addrs);

        for &d in &nodes {
            for &n in &nodes {
                let Some(oracle) = reference_postdominates(&nodes, &edges, &exits, d, n) else {
                    continue;
                };

                let got1 = cfg.post_dom_tree.post_dominates(a(d), a(n));
                assert_eq!(
                    got1, oracle,
                    "trial {trial}: lib PostDominatorTree postdom({d},{n})={got1} != oracle {oracle} on edges {edges:?}"
                );

                let got2 = pd2.post_dominates(a(d), a(n));
                assert_eq!(
                    got2, oracle,
                    "trial {trial}: cfg_dominators PostDominatorComputer postdom({d},{n})={got2} != oracle {oracle} on edges {edges:?}"
                );

                let got3 = pd3.post_dominates(a(d), a(n));
                assert_eq!(
                    got3, oracle,
                    "trial {trial}: post_dominator FullPostDomTree postdom({d},{n})={got3} != oracle {oracle} on edges {edges:?}"
                );
            }
        }
    }
}

// ── Loop-detection / back-edge agreement fuzz ────────────────────────────────

/// Fold `loop_detection::detect_loops` into the header→body agreement check,
/// and `back_edge::{find_loop_headers, BackEdgeSet}` into the loop-header /
/// latch agreement check, cross-validated against the crate-root
/// `find_natural_loops` on the same random CFGs.
#[test]
fn loop_detection_and_back_edge_agree_fuzz() {
    let mut rng = Xorshift(0x0BADC0DE0FF1CE42);
    for trial in 0..1500 {
        let (nodes, edges) = random_reachable_edges(&mut rng, 12);
        let all: HashSet<u64> = nodes.iter().copied().collect();
        let cfg = build_cfg(&nodes, &edges, &all);

        // Canonical: crate-root find_natural_loops (per back edge, union by header).
        let mut by_header_ref: HashMap<u64, BTreeSet<u64>> = HashMap::new();
        for lp in &cfg.loops {
            by_header_ref
                .entry(lp.header.0)
                .or_default()
                .extend(lp.body.iter().map(|addr| addr.0));
        }

        // E: loop_detection::detect_loops (merged per header via LoopForest).
        let node_addrs: Vec<Address> = nodes.iter().map(|&n| a(n)).collect();
        let forest = detect_loops(&node_addrs, &cfg.edges, cfg.entry, &cfg.dom_tree);
        let mut by_header_e: HashMap<u64, BTreeSet<u64>> = HashMap::new();
        for lp in forest.loops() {
            by_header_e
                .entry(lp.header.0)
                .or_default()
                .extend(lp.body.iter().map(|addr| addr.0));
        }

        let norm = |m: &HashMap<u64, BTreeSet<u64>>| -> Vec<(u64, BTreeSet<u64>)> {
            let mut v: Vec<_> = m.iter().map(|(k, s)| (*k, s.clone())).collect();
            v.sort();
            v
        };
        assert_eq!(
            norm(&by_header_ref),
            norm(&by_header_e),
            "trial {trial}: lib find_natural_loops vs loop_detection::detect_loops mismatch on edges {edges:?}"
        );

        // Back-edge loop headers must equal the set of natural-loop headers.
        let ref_headers: BTreeSet<u64> = by_header_ref.keys().copied().collect();
        let be_headers: BTreeSet<u64> =
            find_loop_headers(&cfg.edges, &cfg.dom_tree).iter().map(|h| h.0).collect();
        assert_eq!(
            ref_headers, be_headers,
            "trial {trial}: find_natural_loops headers vs back_edge::find_loop_headers mismatch on edges {edges:?}"
        );

        // BackEdgeSet reports BOTH natural (dominator) and irreducible (DFS)
        // back edges; the dominator-based (`dom_based`) subset must exactly
        // reproduce the brute-force dominator back edges, and its headers must
        // equal the natural-loop headers.
        let be_set = BackEdgeSet::compute(&node_addrs, &cfg.edges, &cfg.dom_tree);
        let mut expected_dom_backs: BTreeSet<(u64, u64)> = BTreeSet::new();
        for &(f, t) in &edges {
            if cfg.dom_tree.dominates(a(t), a(f)) {
                expected_dom_backs.insert((f, t));
            }
        }
        let got_dom_backs: BTreeSet<(u64, u64)> = be_set
            .edges
            .iter()
            .filter(|e| e.dom_based)
            .map(|e| (e.from.0, e.to.0))
            .collect();
        assert_eq!(
            expected_dom_backs, got_dom_backs,
            "trial {trial}: BackEdgeSet dom-based back edges vs brute-force dominator back edges mismatch on edges {edges:?}"
        );
        let be_natural_headers: BTreeSet<u64> =
            expected_dom_backs.iter().map(|&(_, t)| t).collect();
        assert_eq!(
            ref_headers, be_natural_headers,
            "trial {trial}: find_natural_loops headers vs BackEdgeSet natural headers mismatch on edges {edges:?}"
        );
    }
}

#[test]
fn simplify_passes_preserve_invariants_fuzz() {
    let mut rng = Xorshift(0x5DEECE66D2C4E01B);
    for trial in 0..1200 {
        let (nodes, edges) = random_reachable_edges(&mut rng, 8);
        // Randomly mark ~half the blocks as non-empty (entry always non-empty
        // so instruction-count accounting is non-trivial).
        let mut nonempty: HashSet<u64> = HashSet::new();
        nonempty.insert(0);
        for &n in &nodes {
            if rng.range(2) == 0 {
                nonempty.insert(n);
            }
        }
        let base = build_cfg(&nodes, &edges, &nonempty);
        let before_reach = reachable_addrs(&base);
        let before_instrs = reachable_instruction_count(&base);

        let mut c1 = base.clone();
        CfgSimplifier::remove_empty_blocks(&mut c1);
        assert_simplify_invariants("remove_empty_blocks", trial, &edges, &before_reach, before_instrs, &c1);

        let mut c2 = base.clone();
        CfgSimplifier::merge_straight_chains(&mut c2);
        assert_simplify_invariants("merge_straight_chains", trial, &edges, &before_reach, before_instrs, &c2);

        let mut c3 = base.clone();
        let _ = CfgSimplifier::simplify_to_fixpoint(&mut c3);
        assert_simplify_invariants("simplify_to_fixpoint", trial, &edges, &before_reach, before_instrs, &c3);
    }
}

// ── DFS edge classification vs textbook definition ───────────────────────────

/// Independent DFS-tree oracle. Replicates the exact traversal used by
/// `classify_dfs_edges` (roots visited in `blocks` order, children in the order
/// edges were pushed into the adjacency list) and computes discovery/finish
/// timestamps + tree-parent for every node with a *shared* clock so the
/// parenthesis theorem holds. Returns `(disc, fin, parent)`.
fn dfs_oracle(
    blocks: &[Address],
    edges: &[CfgEdge],
) -> (
    HashMap<Address, u32>,
    HashMap<Address, u32>,
    HashMap<Address, Address>,
) {
    // Build adjacency identically to classify_dfs_edges.
    let mut adj: HashMap<Address, Vec<Address>> = HashMap::new();
    for &b in blocks {
        adj.entry(b).or_default();
    }
    for e in edges {
        adj.entry(e.from).or_default().push(e.to);
    }

    let mut disc: HashMap<Address, u32> = HashMap::new();
    let mut fin: HashMap<Address, u32> = HashMap::new();
    let mut parent: HashMap<Address, Address> = HashMap::new();
    let mut clock: u32 = 0;

    // Iterative DFS (avoid recursion depth issues), same order as the impl.
    // Also include any adjacency-only targets the impl would visit.
    let mut roots: Vec<Address> = blocks.to_vec();
    for k in adj.keys() {
        if !roots.contains(k) {
            roots.push(*k);
        }
    }

    for &start in &roots {
        if disc.contains_key(&start) {
            continue;
        }
        let mut stack: Vec<(Address, usize)> = vec![(start, 0)];
        disc.insert(start, clock);
        clock += 1;
        while let Some((node, ci)) = stack.last_mut() {
            let node = *node;
            let children = adj.get(&node).cloned().unwrap_or_default();
            if *ci < children.len() {
                let child = children[*ci];
                *ci += 1;
                if !disc.contains_key(&child) {
                    parent.insert(child, node);
                    disc.insert(child, clock);
                    clock += 1;
                    stack.push((child, 0));
                }
            } else {
                fin.insert(node, clock);
                clock += 1;
                stack.pop();
            }
        }
    }

    (disc, fin, parent)
}

#[test]
fn classify_dfs_edges_matches_dfs_tree_definition_fuzz() {
    let mut rng = Xorshift(0x00C0FFEE_DEADBEEF);
    for trial in 0..2500 {
        let (nodes, raw_edges) = random_reachable_edges(&mut rng, 10);
        let node_addrs: Vec<Address> = nodes.iter().map(|&n| a(n)).collect();
        let cfg_edges: Vec<CfgEdge> = raw_edges
            .iter()
            .map(|&(f, t)| CfgEdge { from: a(f), to: a(t), kind: EdgeKind::Unconditional })
            .collect();

        let cls = classify_dfs_edges(&node_addrs, &cfg_edges);
        let (disc, fin, parent) = dfs_oracle(&node_addrs, &cfg_edges);

        // Ancestor-or-self test via the parenthesis theorem.
        let is_anc_or_self = |anc: Address, desc: Address| -> bool {
            disc[&anc] <= disc[&desc] && fin[&desc] <= fin[&anc]
        };

        // Every distinct edge must be classified, and exactly per the
        // textbook definition.
        let distinct: BTreeSet<(u64, u64)> = raw_edges.iter().copied().collect();
        assert_eq!(
            cls.len(),
            distinct.len(),
            "trial {trial}: classify_dfs_edges produced {} entries for {} distinct edges on {raw_edges:?}",
            cls.len(),
            distinct.len()
        );

        for &(u, v) in &distinct {
            let (au, av) = (a(u), a(v));
            let got = cls[&(au, av)];
            let expected = if parent.get(&av) == Some(&au) {
                DfsEdgeKind::Tree
            } else if is_anc_or_self(av, au) {
                // v is an ancestor of (or equal to) u on the DFS stack.
                DfsEdgeKind::Back
            } else if is_anc_or_self(au, av) {
                // v is a proper descendant of u reached by a non-tree edge.
                DfsEdgeKind::Forward
            } else {
                DfsEdgeKind::Cross
            };
            assert_eq!(
                got, expected,
                "trial {trial}: edge {u}->{v} classified {got:?} but oracle says {expected:?} on {raw_edges:?}"
            );
        }

        // Structural invariant: tree edges form a forest — every non-root node
        // has at most one incoming tree edge, and it is its DFS parent.
        let mut tree_parents: HashMap<Address, Address> = HashMap::new();
        for (&(from, to), &k) in &cls {
            if k == DfsEdgeKind::Tree {
                assert!(
                    tree_parents.insert(to, from).is_none(),
                    "trial {trial}: node {to:?} has two tree parents on {raw_edges:?}"
                );
            }
        }
        assert_eq!(tree_parents, parent, "trial {trial}: tree-edge set != DFS tree on {raw_edges:?}");
    }
}

// ── Back-edge irreducibility vs independent T1/T2 oracle ──────────────────────

#[test]
fn back_edge_irreducibility_matches_t1t2_fuzz() {
    let mut rng = Xorshift(0xF00DBABE_12345678);
    for trial in 0..2500 {
        let (nodes, raw_edges) = random_reachable_edges(&mut rng, 10);
        // node_addrs sorted with entry (node 0) first, matching the documented
        // contract that the DFS in BackEdgeSet is rooted at the entry.
        let node_addrs: Vec<Address> = nodes.iter().map(|&n| a(n)).collect();
        assert_eq!(node_addrs.first().copied(), Some(a(0)));
        let cfg_edges: Vec<CfgEdge> = raw_edges
            .iter()
            .map(|&(f, t)| CfgEdge { from: a(f), to: a(t), kind: EdgeKind::Unconditional })
            .collect();
        let blocks_map: HashMap<Address, BasicBlock> = nodes
            .iter()
            .map(|&n| (a(n), BasicBlock { start: a(n), end: a(n), instructions: vec![] }))
            .collect();
        let dom = DominatorTree::compute(&blocks_map, &cfg_edges, a(0));

        // Independent oracle: T1/T2 structural reduction.
        let e32: Vec<(u32, u32)> = raw_edges.iter().map(|&(f, t)| (f as u32, t as u32)).collect();
        let (graph, entry) = graph_from_edges(&e32);
        let t1t2_irreducible = !ReducibilityAnalysis::new(entry).is_reducible(&graph);

        let be_set = BackEdgeSet::compute(&node_addrs, &cfg_edges, &dom);
        assert_eq!(
            be_set.has_irreducible, t1t2_irreducible,
            "trial {trial}: BackEdgeSet.has_irreducible={} vs T1/T2 irreducible={} on {raw_edges:?}",
            be_set.has_irreducible, t1t2_irreducible
        );
        assert_eq!(be_set.is_reducible(), !t1t2_irreducible);

        // Definitional cross-check: irreducible iff some DFS retreating edge is
        // not a dominator back edge (the "retreating but not a back edge" test).
        let dfs_backs = dfs_back_edges(&node_addrs, &cfg_edges);
        let has_bad_retreat = dfs_backs
            .iter()
            .any(|&(f, t)| !dom.dominates(t, f));
        assert_eq!(
            has_bad_retreat, t1t2_irreducible,
            "trial {trial}: retreating-not-backedge oracle={} vs T1/T2={} on {raw_edges:?}",
            has_bad_retreat, t1t2_irreducible
        );

        // Every dominator back edge is always a DFS retreating edge (rooted at
        // entry), regardless of reducibility.
        for e in &cfg_edges {
            if dom.dominates(e.to, e.from) {
                assert!(
                    dfs_backs.contains(&(e.from, e.to)),
                    "trial {trial}: dominator back edge {:?}->{:?} is not a DFS retreating edge on {raw_edges:?}",
                    e.from, e.to
                );
            }
        }
    }
}

// ── Loop nesting-tree structure vs enclosing-header oracle ────────────────────

#[test]
fn loop_nesting_tree_structure_fuzz() {
    let mut rng = Xorshift(0xBADDCAFE_5EED1234);
    let mut reducible_trials = 0usize;
    for trial in 0..3000 {
        let (nodes, raw_edges) = random_reachable_edges(&mut rng, 10);

        // Restrict to reducible CFGs: the "loops containing a block form a
        // chain" invariant this oracle relies on holds only for reducible CFGs.
        let e32: Vec<(u32, u32)> = raw_edges.iter().map(|&(f, t)| (f as u32, t as u32)).collect();
        let (graph, entry) = graph_from_edges(&e32);
        if !ReducibilityAnalysis::new(entry).is_reducible(&graph) {
            continue;
        }
        reducible_trials += 1;

        let node_addrs: Vec<Address> = nodes.iter().map(|&n| a(n)).collect();
        let cfg_edges: Vec<CfgEdge> = raw_edges
            .iter()
            .map(|&(f, t)| CfgEdge { from: a(f), to: a(t), kind: EdgeKind::Unconditional })
            .collect();
        let blocks_map: HashMap<Address, BasicBlock> = nodes
            .iter()
            .map(|&n| (a(n), BasicBlock { start: a(n), end: a(n), instructions: vec![] }))
            .collect();
        let dom = DominatorTree::compute(&blocks_map, &cfg_edges, a(0));
        let forest = detect_loops(&node_addrs, &cfg_edges, a(0), &dom);
        let tree = &forest.tree;
        let n = tree.nodes.len();

        // Oracle 1: depth(i) == number of *other* loops whose body strictly
        // contains body(i) (i.e. the count of distinct enclosing loop headers).
        for i in 0..n {
            let bi = &tree.nodes[i].info.body;
            let enclosing = (0..n)
                .filter(|&j| j != i)
                .filter(|&j| {
                    let bj = &tree.nodes[j].info.body;
                    bi.is_subset(bj) && bi != bj
                })
                .count();
            assert_eq!(
                tree.nodes[i].info.depth, enclosing,
                "trial {trial}: loop header {:?} depth={} but {enclosing} enclosing loops on {raw_edges:?}",
                tree.nodes[i].info.header, tree.nodes[i].info.depth
            );
        }

        // Oracle 2: parent/child consistency with body containment.
        for i in 0..n {
            let node = &tree.nodes[i];
            match node.parent {
                None => {
                    assert_eq!(node.info.depth, 0, "trial {trial}: root loop with nonzero depth");
                    assert!(tree.roots.contains(&i));
                }
                Some(p) => {
                    let bi = &node.info.body;
                    let bp = &tree.nodes[p].info.body;
                    assert!(
                        bi.is_subset(bp) && bi != bp,
                        "trial {trial}: loop {i} parent {p} but body not strictly contained on {raw_edges:?}"
                    );
                    assert_eq!(
                        node.info.depth,
                        tree.nodes[p].info.depth + 1,
                        "trial {trial}: loop {i} depth != parent depth + 1"
                    );
                    // Parent must be the *minimal* enclosing loop: no loop j
                    // sits strictly between body(i) and body(p).
                    for j in 0..n {
                        if j == i || j == p {
                            continue;
                        }
                        let bj = &tree.nodes[j].info.body;
                        let between = bi.is_subset(bj) && bi != bj && bj.is_subset(bp) && bj != bp;
                        assert!(
                            !between,
                            "trial {trial}: loop {j} sits strictly between {i} and its parent {p} on {raw_edges:?}"
                        );
                    }
                    assert!(tree.nodes[p].children.contains(&i));
                }
            }
        }

        // Oracle 3: per-block nesting depth == number of loops whose body
        // contains that block.
        for &b in &node_addrs {
            let containing = tree.nodes.iter().filter(|nd| nd.info.body.contains(&b)).count();
            assert_eq!(
                tree.nesting_depth(b), containing,
                "trial {trial}: block {b:?} nesting_depth={} but contained by {containing} loops on {raw_edges:?}",
                tree.nesting_depth(b)
            );
        }
    }
    assert!(reducible_trials > 100, "too few reducible trials ({reducible_trials})");
}
