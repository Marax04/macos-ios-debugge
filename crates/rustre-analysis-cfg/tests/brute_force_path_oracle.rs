//! Brute-force PATH-ENUMERATION oracle for dominators and post-dominators.
//!
//! Independent by construction: the oracle is the textbook DEFINITION, not a
//! dataflow fixpoint, not a removal-reachability trick, and not a sibling
//! crate's algorithm.
//!
//!   `d dom n`  iff every path entry -> n  contains `d`.
//!   `m pdom b` iff every path b -> exit   contains `m`.
//!
//! Simple paths suffice: any walk that avoids `d` contains a simple subpath
//! with the same endpoints that also avoids `d`, so quantifying over simple
//! paths is equivalent. Graphs are kept tiny (<= 7 nodes) so full enumeration
//! is cheap.

use rustre_analysis_cfg::{BasicBlock, CfgEdge, DominatorTree, EdgeKind, PostDominatorTree};
use rustre_core::address::Address;
use std::collections::HashMap;

fn a(v: u64) -> Address {
    Address::new(v)
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

/// Enumerate every simple path from `from` to any node in `targets`.
/// Calls `sink` with the node-set (bitmask) of each such path, endpoints
/// included.
fn enum_simple_paths(
    n: usize,
    succ: &[Vec<usize>],
    from: usize,
    is_target: &dyn Fn(usize) -> bool,
    sink: &mut dyn FnMut(u32),
) {
    fn go(
        u: usize,
        n: usize,
        succ: &[Vec<usize>],
        visited: u32,
        is_target: &dyn Fn(usize) -> bool,
        sink: &mut dyn FnMut(u32),
    ) {
        let vis = visited | (1u32 << u);
        if is_target(u) {
            sink(vis);
        }
        for &v in &succ[u] {
            if v < n && (vis & (1u32 << v)) == 0 {
                go(v, n, succ, vis, is_target, sink);
            }
        }
    }
    go(from, n, succ, 0, is_target, sink);
}

/// Dominator SETS by path enumeration. `None` = node unreachable from entry.
fn oracle_dom_sets(n: usize, succ: &[Vec<usize>], entry: usize) -> Vec<Option<u32>> {
    let mut out = vec![None; n];
    for target in 0..n {
        let mut acc: Option<u32> = None;
        enum_simple_paths(n, succ, entry, &|u| u == target, &mut |mask| {
            acc = Some(match acc {
                None => mask,
                Some(prev) => prev & mask, // intersection over all paths
            });
        });
        out[target] = acc;
    }
    out
}

/// Immediate dominator of each reachable node: the strict dominator with the
/// largest dominator set. `None` for the entry (and for nodes whose only
/// strict dominator set is empty, which cannot happen for reachable non-entry).
fn oracle_idom(n: usize, succ: &[Vec<usize>], entry: usize) -> Vec<Option<usize>> {
    let doms = oracle_dom_sets(n, succ, entry);
    let mut out = vec![None; n];
    for b in 0..n {
        let Some(db) = doms[b] else { continue };
        if b == entry {
            continue;
        }
        let strict: Vec<usize> = (0..n)
            .filter(|&d| d != b && (db & (1u32 << d)) != 0)
            .collect();
        out[b] = strict
            .into_iter()
            .max_by_key(|&d| doms[d].unwrap_or(0).count_ones());
    }
    out
}

/// Post-dominator sets by path enumeration toward exit nodes (no successors).
/// `None` = node cannot reach any exit.
fn oracle_pdom_sets(n: usize, succ: &[Vec<usize>]) -> Vec<Option<u32>> {
    let mut out = vec![None; n];
    for b in 0..n {
        let mut acc: Option<u32> = None;
        enum_simple_paths(n, succ, b, &|u| succ[u].is_empty(), &mut |mask| {
            acc = Some(match acc {
                None => mask,
                Some(prev) => prev & mask,
            });
        });
        out[b] = acc;
    }
    out
}

/// Immediate post-dominator, matching `PostDominatorTree` conventions:
///  - outer `None`      = node cannot reach an exit (absent from the tree);
///  - `Some(None)`      = immediate post-dominator is the virtual exit;
///  - `Some(Some(m))`   = m.
fn oracle_ipdom(n: usize, succ: &[Vec<usize>]) -> Vec<Option<Option<usize>>> {
    let pd = oracle_pdom_sets(n, succ);
    let mut out = vec![None; n];
    for b in 0..n {
        let Some(pb) = pd[b] else { continue };
        let strict: Vec<usize> = (0..n)
            .filter(|&m| m != b && (pb & (1u32 << m)) != 0)
            .collect();
        let ip = strict
            .into_iter()
            // Nearest strict post-dominator = the one with the LARGEST
            // post-dominator set (post-dominators of b form a chain).
            .max_by_key(|&m| pd[m].unwrap_or(0).count_ones());
        out[b] = Some(ip);
    }
    out
}

/// Random graph generator covering the shapes that break naive dominance:
/// self-loops, duplicate/multiple back edges, unreachable nodes, disconnected
/// components, single-node graphs, and irreducible loops (two distinct entries
/// into one cycle).
fn gen_graph(rng: &mut XorShift, trial: usize) -> (usize, Vec<Vec<usize>>) {
    let n = 1 + (rng.below(7) as usize); // 1..=7
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    let edge_count = rng.below((2 * n + 1) as u64) as usize; // may be 0
    for _ in 0..edge_count {
        let f = rng.below(n as u64) as usize;
        let t = rng.below(n as u64) as usize;
        succ[f].push(t); // self-loops + duplicate edges allowed
    }
    match trial % 5 {
        0 => {
            // explicit self-loop
            let f = rng.below(n as u64) as usize;
            succ[f].push(f);
        }
        1 => {
            // extra back edge into the entry
            let f = rng.below(n as u64) as usize;
            succ[f].push(0);
        }
        2 if n >= 4 => {
            // IRREDUCIBLE: 0 -> {2,3}, and 2 <-> 3 form a cycle with two entries
            succ[0].push(2);
            succ[0].push(3);
            succ[2].push(3);
            succ[3].push(2);
        }
        3 if n >= 3 => {
            // disconnected component with its own cycle, unreachable from 0
            succ[n - 1].push(n - 2);
            succ[n - 2].push(n - 1);
        }
        _ => {}
    }
    (n, succ)
}

fn build(n: usize, succ: &[Vec<usize>]) -> (HashMap<Address, BasicBlock>, Vec<CfgEdge>) {
    let mut blocks = HashMap::new();
    for i in 0..n {
        blocks.insert(
            a(i as u64),
            BasicBlock { start: a(i as u64), end: a(i as u64), instructions: Vec::new() },
        );
    }
    let mut edges = Vec::new();
    for (f, ts) in succ.iter().enumerate() {
        for &t in ts {
            edges.push(CfgEdge {
                from: a(f as u64),
                to: a(t as u64),
                kind: EdgeKind::Unconditional,
            });
        }
    }
    (blocks, edges)
}

#[test]
fn dominators_match_path_enumeration_oracle() {
    let mut rng = XorShift(0x0bad_c0de_dead_beef);
    for trial in 0..3000 {
        let (n, succ) = gen_graph(&mut rng, trial);
        let entry = 0usize;
        let want = oracle_idom(n, &succ, entry);
        let reach = oracle_dom_sets(n, &succ, entry);

        let (blocks, edges) = build(n, &succ);
        let tree = DominatorTree::compute(&blocks, &edges, a(entry as u64));

        for b in 0..n {
            if reach[b].is_none() {
                continue; // unreachable: outside the dominator relation
            }
            let got = tree.idom.get(&a(b as u64)).copied().flatten();
            let expect = want[b].map(|d| a(d as u64));
            assert_eq!(
                got, expect,
                "trial {trial}: idom({b}) = {got:?}, path-oracle = {:?} (n={n}, succ={succ:?})",
                want[b]
            );
        }
    }
}

#[test]
fn post_dominators_match_path_enumeration_oracle() {
    let mut rng = XorShift(0x5eed_1234_9876_fedc);
    for trial in 0..3000 {
        let (n, succ) = gen_graph(&mut rng, trial);
        let want = oracle_ipdom(n, &succ);

        let (blocks, edges) = build(n, &succ);
        let pdt = PostDominatorTree::compute(&blocks, &edges);

        for b in 0..n {
            let got = pdt.idom.get(&a(b as u64)).copied();
            match want[b] {
                None => assert!(
                    got.is_none(),
                    "trial {trial}: node {b} cannot reach an exit but ipdom = {got:?} (succ={succ:?})"
                ),
                Some(inner) => {
                    let expect = inner.map(|m| a(m as u64));
                    assert_eq!(
                        got,
                        Some(expect),
                        "trial {trial}: ipdom({b}) = {got:?}, path-oracle = {inner:?} (succ={succ:?})"
                    );
                }
            }
        }
    }
}

/// Any dependence on HashMap iteration order would be a defect in itself.
#[test]
fn dominator_and_postdominator_results_are_deterministic() {
    let mut rng = XorShift(0x2222_3333_4444_5555);
    for trial in 0..600 {
        let (n, succ) = gen_graph(&mut rng, trial);
        let (blocks, edges) = build(n, &succ);
        let d1 = DominatorTree::compute(&blocks, &edges, a(0));
        let d2 = DominatorTree::compute(&blocks, &edges, a(0));
        assert_eq!(d1.idom, d2.idom, "trial {trial}: nondeterministic idom (succ={succ:?})");
        let p1 = PostDominatorTree::compute(&blocks, &edges);
        let p2 = PostDominatorTree::compute(&blocks, &edges);
        assert_eq!(p1.idom, p2.idom, "trial {trial}: nondeterministic ipdom (succ={succ:?})");
    }
}
