//! Randomized graph-law property tests against brute-force oracles
//! (test-only module).
//!
//! `soundness_fuzz` already cross-checks dominators / dominance frontiers /
//! loops / reducibility, but it deliberately prunes every generated CFG to
//! the subgraph reachable from the entry.  This module deliberately covers
//! the *adversarial* shapes it excludes — unreachable nodes, disconnected
//! components, self-loops, duplicate edges, and an entry that has
//! predecessors — and adds oracles for algorithms `soundness_fuzz` does not
//! touch at all:
//!
//! * `loop_detection::TarjanScc` vs a brute-force mutual-reachability
//!   partition,
//! * `cfg_algorithms::NaturalLoop::build` body vs the "reaches the tail
//!   without passing through the header" definition,
//! * `path_query::PathQuery::{reachable, can_reach}` vs BFS,
//! * `DominatorTree` idom vs the removal test (`d` is the unique immediate
//!   dominator of `n` iff deleting `d` makes `n` unreachable and no other
//!   such node is dominated by it).
//!
//! All PRNG use is a seeded xorshift so failures reproduce exactly.

use crate::cfg_algorithms::{self, SimpleCfg};
use crate::loop_detection::TarjanScc;
use crate::path_query::PathQuery;
use crate::{BasicBlock, CfgEdge, DominatorTree, EdgeKind, PostDominatorTree};
use rustre_core::address::Address;
use std::collections::{BTreeSet, HashMap, HashSet};

// ── PRNG ─────────────────────────────────────────────────────────────────────

use crate::test_prng::Xs;

fn a(v: u64) -> Address {
    Address::new(v)
}

/// Random graph over nodes `0..n`, **not** pruned to the reachable subgraph:
/// unreachable nodes, disconnected components, self-loops and edges into the
/// entry are all possible and intended.
fn random_graph(rng: &mut Xs, max_nodes: u64) -> (Vec<u64>, Vec<(u64, u64)>) {
    let n = 1 + rng.range(max_nodes);
    let m = rng.range(n * 2 + 3);
    let mut edges: BTreeSet<(u64, u64)> = BTreeSet::new();
    for _ in 0..m {
        edges.insert((rng.range(n), rng.range(n)));
    }
    ((0..n).collect(), edges.into_iter().collect())
}

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

fn cfg_edges(edges: &[(u64, u64)]) -> Vec<CfgEdge> {
    edges
        .iter()
        .map(|&(f, t)| CfgEdge {
            from: a(f),
            to: a(t),
            kind: EdgeKind::Unconditional,
        })
        .collect()
}

fn blocks_map(nodes: &[u64]) -> HashMap<Address, BasicBlock> {
    nodes
        .iter()
        .map(|&n| {
            (
                a(n),
                BasicBlock {
                    start: a(n),
                    end: a(n),
                    instructions: Vec::new(),
                },
            )
        })
        .collect()
}

// ── brute-force oracles ──────────────────────────────────────────────────────

fn succ_map(edges: &[(u64, u64)]) -> HashMap<u64, Vec<u64>> {
    let mut m: HashMap<u64, Vec<u64>> = HashMap::new();
    for &(f, t) in edges {
        m.entry(f).or_default().push(t);
    }
    m
}

/// Nodes reachable from `src`, optionally with `deleted` removed.
fn bfs_reach(succs: &HashMap<u64, Vec<u64>>, src: u64, deleted: Option<u64>) -> HashSet<u64> {
    let mut seen = HashSet::new();
    if deleted == Some(src) {
        return seen;
    }
    let mut stack = vec![src];
    seen.insert(src);
    while let Some(n) = stack.pop() {
        for &s in succs.get(&n).map_or(&[][..], Vec::as_slice) {
            if deleted == Some(s) {
                continue;
            }
            if seen.insert(s) {
                stack.push(s);
            }
        }
    }
    seen
}

/// Brute-force dominance: `d` dominates `n` iff `n` is unreachable from the
/// entry once `d` is deleted (and `n` is reachable at all).
fn oracle_dominates(succs: &HashMap<u64, Vec<u64>>, entry: u64, d: u64, n: u64) -> bool {
    if d == n {
        return true;
    }
    !bfs_reach(succs, entry, Some(d)).contains(&n)
}

// ── P1: SCC partition == mutual reachability ─────────────────────────────────

#[test]
fn scc_partition_matches_mutual_reachability_oracle() {
    for seed in 0..1200u64 {
        let mut rng = Xs::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xC0FFEE);
        let (nodes, edges) = random_graph(&mut rng, 9);
        let succs = succ_map(&edges);

        let addrs: Vec<Address> = nodes.iter().map(|&n| a(n)).collect();
        let scc = TarjanScc::compute(&addrs, &cfg_edges(&edges), a(0));

        // Oracle: u ~ v iff u reaches v and v reaches u.
        let reach: HashMap<u64, HashSet<u64>> = nodes
            .iter()
            .map(|&n| (n, bfs_reach(&succs, n, None)))
            .collect();

        // Every node must belong to exactly one SCC.
        for &n in &nodes {
            assert!(
                scc.scc_of(a(n)).is_some(),
                "seed {seed}: node {n} in no SCC (nodes {nodes:?}, edges {edges:?})"
            );
        }
        for &u in &nodes {
            for &v in &nodes {
                let same_impl = scc.scc_of(a(u)) == scc.scc_of(a(v));
                let same_oracle = reach[&u].contains(&v) && reach[&v].contains(&u);
                assert_eq!(
                    same_impl, same_oracle,
                    "seed {seed}: SCC({u},{v}) impl={same_impl} oracle={same_oracle} \
                     nodes {nodes:?} edges {edges:?}"
                );
            }
        }

        // `is_cycle` must mean "the members lie on a real cycle".
        for comp in &scc.sccs {
            let m0 = comp.members[0].0;
            let on_cycle = comp.members.len() > 1
                || succs.get(&m0).is_some_and(|s| s.contains(&m0));
            assert_eq!(
                comp.is_cycle, on_cycle,
                "seed {seed}: is_cycle wrong for {:?} (edges {edges:?})",
                comp.members
            );
        }
    }
}

// ── P2: natural-loop body exactness ──────────────────────────────────────────

#[test]
fn natural_loop_body_matches_back_edge_definition_oracle() {
    for seed in 0..1200u64 {
        let mut rng = Xs::new(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) ^ 0xBEEF);
        let (nodes, edges) = random_graph(&mut rng, 8);
        let cfg = build_simple(&nodes, &edges);
        let Ok(dom) = cfg_algorithms::DominatorTree::compute(&cfg) else {
            continue;
        };
        let succs = succ_map(&edges);

        for lp in cfg_algorithms::find_natural_loops(&cfg, &dom) {
            let (h, t) = (lp.header, lp.back_edge_tail);
            // Oracle: body = {h} ∪ {n : n can reach t without passing through h}.
            // Computed as a backward walk from t that never expands through h.
            let mut oracle: HashSet<u64> = HashSet::new();
            oracle.insert(h);
            oracle.insert(t);
            let mut stack = if t == h { vec![] } else { vec![t] };
            while let Some(n) = stack.pop() {
                for &(f, to) in &edges {
                    if to == n && oracle.insert(f) && f != h {
                        stack.push(f);
                    }
                }
            }
            let got: HashSet<u64> = lp.body.iter().copied().collect();
            assert_eq!(
                got, oracle,
                "seed {seed}: loop body header={h} tail={t} edges {edges:?}"
            );
            // Header must dominate every body node (definition of natural loop).
            for &n in &got {
                assert!(
                    oracle_dominates(&succs, 0, h, n)
                        || bfs_reach(&succs, 0, None).contains(&n) == false,
                    "seed {seed}: header {h} does not dominate body node {n} \
                     (edges {edges:?})"
                );
            }
        }
    }
}

// ── P3: dominance under adversarial shapes vs removal-test oracle ────────────

#[test]
fn dominator_tree_matches_removal_oracle_with_unreachable_nodes() {
    for seed in 0..1500u64 {
        let mut rng = Xs::new(seed.wrapping_mul(0x1000_0000_1B3) ^ 0xD1CE);
        let (nodes, edges) = random_graph(&mut rng, 9);
        let succs = succ_map(&edges);
        let reachable = bfs_reach(&succs, 0, None);

        let dom = DominatorTree::compute(&blocks_map(&nodes), &cfg_edges(&edges), a(0));

        // The tree must describe exactly the reachable nodes.
        let described: HashSet<u64> = dom.idom.keys().map(|x| x.0).collect();
        assert_eq!(
            described, reachable,
            "seed {seed}: idom domain != reachable set (edges {edges:?})"
        );

        for &d in &nodes {
            for &n in &nodes {
                if !reachable.contains(&n) || !reachable.contains(&d) {
                    continue;
                }
                let got = dom.dominates(a(d), a(n));
                let want = oracle_dominates(&succs, 0, d, n);
                assert_eq!(
                    got, want, "seed {seed}: dominates({d},{n}) got={got} want={want} \
                     edges {edges:?}"
                );
            }
        }

        // idom(n) must be the *unique* immediate dominator: the strict
        // dominator of n that every other strict dominator dominates.
        for &n in &reachable {
            if n == 0 {
                continue;
            }
            let strict: Vec<u64> = reachable
                .iter()
                .copied()
                .filter(|&d| d != n && oracle_dominates(&succs, 0, d, n))
                .collect();
            let unique: Vec<u64> = strict
                .iter()
                .copied()
                .filter(|&c| strict.iter().all(|&o| o == c || oracle_dominates(&succs, 0, o, c)))
                .collect();
            assert_eq!(unique.len(), 1, "seed {seed}: node {n} has {unique:?} idom candidates");
            assert_eq!(
                dom.idom.get(&a(n)).copied().flatten().map(|x| x.0),
                Some(unique[0]),
                "seed {seed}: idom({n}) mismatch (edges {edges:?})"
            );
        }
    }
}

// ── P4: post-dominance vs oracle on adversarial graphs ───────────────────────

#[test]
fn post_dominator_matches_oracle_with_unreachable_nodes() {
    for seed in 0..1200u64 {
        let mut rng = Xs::new(seed.wrapping_mul(0x27BB_2EE6_87B0_B0FD) ^ 0x5EED);
        let (nodes, edges) = random_graph(&mut rng, 8);
        let succs = succ_map(&edges);
        let exits: HashSet<u64> = nodes
            .iter()
            .copied()
            .filter(|n| succs.get(n).is_none_or(Vec::is_empty))
            .collect();
        if exits.is_empty() {
            continue;
        }

        let pdt = PostDominatorTree::compute(&blocks_map(&nodes), &cfg_edges(&edges));

        // Oracle: `d` post-dominates `n` iff every path n → exit hits d, i.e.
        // no exit is reachable from n once d is deleted (and n does reach one).
        for &n in &nodes {
            let reaches_exit = bfs_reach(&succs, n, None).iter().any(|x| exits.contains(x));
            if !reaches_exit {
                continue;
            }
            for &d in &nodes {
                if !pdt.idom.contains_key(&a(d)) || !pdt.idom.contains_key(&a(n)) {
                    continue;
                }
                let want = d == n
                    || !bfs_reach(&succs, n, Some(d)).iter().any(|x| exits.contains(x));
                let got = pdt.post_dominates(a(d), a(n));
                assert_eq!(
                    got, want,
                    "seed {seed}: post_dominates({d},{n}) got={got} want={want} \
                     edges {edges:?} exits {exits:?}"
                );
            }
        }
    }
}

// ── P5: PathQuery reachability vs BFS ────────────────────────────────────────

#[test]
fn path_query_reachability_matches_bfs_oracle() {
    for seed in 0..1000u64 {
        let mut rng = Xs::new(seed.wrapping_mul(0x9E37_79B1) ^ 0xAB1E);
        let (nodes, edges) = random_graph(&mut rng, 8);
        let succs = succ_map(&edges);
        let mut preds: HashMap<u64, Vec<u64>> = HashMap::new();
        for &(f, t) in &edges {
            preds.entry(t).or_default().push(f);
        }
        // Depth bound generous enough to be equivalent to unbounded here.
        let pq = PathQuery::new(&cfg_edges(&edges), 64, 64);

        for &n in &nodes {
            let fwd: HashSet<u64> = pq.reachable(a(n)).iter().map(|x| x.0).collect();
            assert_eq!(
                fwd,
                bfs_reach(&succs, n, None),
                "seed {seed}: reachable({n}) edges {edges:?}"
            );
            let back: HashSet<u64> = pq.can_reach(a(n)).iter().map(|x| x.0).collect();
            assert_eq!(
                back,
                bfs_reach(&preds, n, None),
                "seed {seed}: can_reach({n}) edges {edges:?}"
            );
        }
    }
}

// ── P6: determinism ──────────────────────────────────────────────────────────

#[test]
fn cfg_analyses_are_deterministic_across_runs() {
    for seed in 0..600u64 {
        let mut rng = Xs::new(seed.wrapping_mul(0x7FEB_352D) ^ 0xD37E);
        let (nodes, edges) = random_graph(&mut rng, 9);
        let blocks = blocks_map(&nodes);
        let ce = cfg_edges(&edges);

        let run = || {
            let dom = DominatorTree::compute(&blocks, &ce, a(0));
            let pdt = PostDominatorTree::compute(&blocks, &ce);
            let addrs: Vec<Address> = nodes.iter().map(|&n| a(n)).collect();
            let scc = TarjanScc::compute(&addrs, &ce, a(0));
            let doms: Vec<(u64, Option<u64>)> = {
                let mut v: Vec<_> = dom
                    .idom
                    .iter()
                    .map(|(k, v)| (k.0, v.map(|x| x.0)))
                    .collect();
                v.sort_unstable();
                v
            };
            let fronts: Vec<(u64, Vec<u64>)> = {
                let mut v: Vec<_> = dom
                    .frontiers
                    .iter()
                    .map(|(k, v)| (k.0, v.iter().map(|x| x.0).collect::<Vec<_>>()))
                    .collect();
                v.sort();
                v
            };
            let pdoms: Vec<(u64, Option<u64>)> = {
                let mut v: Vec<_> = pdt
                    .idom
                    .iter()
                    .map(|(k, v)| (k.0, v.map(|x| x.0)))
                    .collect();
                v.sort_unstable();
                v
            };
            let sccs: Vec<Vec<u64>> = {
                let mut v: Vec<Vec<u64>> = scc
                    .sccs
                    .iter()
                    .map(|c| {
                        let mut m: Vec<u64> = c.members.iter().map(|x| x.0).collect();
                        m.sort_unstable();
                        m
                    })
                    .collect();
                v.sort();
                v
            };
            // Dominator-tree children lists are part of the public API and
            // must be order-stable too.
            let kids: Vec<(u64, Vec<u64>)> = {
                let mut v: Vec<_> = dom
                    .children
                    .iter()
                    .map(|(k, v)| (k.0, v.iter().map(|x| x.0).collect::<Vec<_>>()))
                    .collect();
                v.sort();
                v
            };
            (doms, fronts, pdoms, sccs, kids)
        };

        assert_eq!(run(), run(), "seed {seed}: analysis not deterministic");
    }
}

// ── P7: adversarial inputs must not panic ────────────────────────────────────

#[test]
fn adversarial_cfgs_do_not_panic() {
    let cases: Vec<(Vec<u64>, Vec<(u64, u64)>)> = vec![
        (vec![], vec![]),                                  // empty CFG
        (vec![0], vec![]),                                 // single node
        (vec![0], vec![(0, 0)]),                           // self-loop on entry
        (vec![0, 1], vec![(1, 0)]),                        // entry has a predecessor
        (vec![0, 1], vec![]),                              // disconnected
        (vec![0, 1, 2], vec![(1, 2), (2, 1)]),             // unreachable cycle
        (vec![0, 1, 2], vec![(0, 1), (1, 1), (1, 2)]),     // interior self-loop
        (vec![0, 1, 2], vec![(0, 1), (0, 1), (0, 2)]),     // duplicate edges
        (vec![0, 1, 2, 3], vec![(0, 1), (0, 2), (1, 3), (2, 3), (3, 1)]), // irreducible-ish
        (vec![0, 1, 2], vec![(0, 1), (1, 2), (2, 0)]),     // cycle through entry
        (vec![0, 5], vec![(0, 5), (5, 9)]),                // edge to an undeclared node
    ];

    for (i, (nodes, edges)) in cases.iter().enumerate() {
        let blocks = blocks_map(nodes);
        let ce = cfg_edges(edges);
        let _ = DominatorTree::compute(&blocks, &ce, a(0));
        let _ = PostDominatorTree::compute(&blocks, &ce);
        let addrs: Vec<Address> = nodes.iter().map(|&n| a(n)).collect();
        let scc = TarjanScc::compute(&addrs, &ce, a(0));
        let _ = scc.cycle_sccs();
        let pq = PathQuery::new(&ce, 16, 16);
        for &n in nodes {
            let _ = pq.reachable(a(n));
            let _ = pq.can_reach(a(n));
        }
        let cfg = build_simple(nodes, edges);
        if let Ok(dom) = cfg_algorithms::DominatorTree::compute(&cfg) {
            let _ = cfg_algorithms::find_natural_loops(&cfg, &dom);
            let _ = cfg_algorithms::IrreducibleCfgDetector::is_irreducible(&cfg, &dom);
        }
        let _ = cfg_algorithms::PostDominatorTree::compute(&cfg);
        let _ = i;
    }
}
