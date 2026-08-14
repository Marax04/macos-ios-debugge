//! Definitional oracle for `rustre_analysis_cfg::find_natural_loops`.
//!
//! The oracle is the TEXTBOOK DEFINITION, computed by brute force:
//!
//!   * `h dom n`  iff every path entry -> n contains `h`  (path enumeration;
//!     the crate's `DominatorTree` is NOT consulted by the oracle).
//!   * `n -> h` is a BACK EDGE iff it is an edge and `h dom n`.
//!   * the natural loop of that back edge is
//!         {h} union {v : v can reach n without passing through h}
//!     computed by plain reachability in the graph with `h` deleted.
//!   * `exits` = successors of body nodes that lie outside the body.
//!   * `is_innermost` = no other reported loop's body is a strict subset.
//!
//! Irreducible graphs: a multi-entry cycle has no node dominating the others,
//! so it contributes NO back edge and the function reports no loop for it.
//! That is the contract of natural-loop detection (it is defined only for
//! back edges), and the oracle encodes the same definition independently --
//! agreement on irreducible graphs is therefore a real check that the
//! implementation does not invent loops there.

use rustre_analysis_cfg::{
    find_natural_loops, BasicBlock, CfgEdge, ControlFlowGraph, DominatorTree, EdgeKind,
    PostDominatorTree,
};
use rustre_core::address::Address;
use std::collections::{HashMap, HashSet};

fn a(v: usize) -> Address {
    Address::new(v as u64)
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
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

// ── oracle primitives ────────────────────────────────────────────────────────

/// Nodes reachable from `from` in the graph, skipping any node in `blocked`.
fn reach(n: usize, succ: &[Vec<usize>], from: usize, blocked: Option<usize>) -> Vec<bool> {
    let mut seen = vec![false; n];
    if blocked == Some(from) {
        return seen;
    }
    let mut stack = vec![from];
    seen[from] = true;
    while let Some(u) = stack.pop() {
        for &v in &succ[u] {
            if blocked != Some(v) && !seen[v] {
                seen[v] = true;
                stack.push(v);
            }
        }
    }
    seen
}

/// `dom[h][v]` = true iff h dominates v, by the DEFINITION: v is unreachable
/// from entry when h is deleted (and v != h), or v == h.
///
/// This is the "every entry->v path contains h" definition restated via
/// deletion, which is equivalent for v reachable from entry: a path avoiding h
/// exists iff v is still reachable after deleting h.
fn oracle_dominates(n: usize, succ: &[Vec<usize>], entry: usize) -> Vec<Vec<bool>> {
    let mut out = vec![vec![false; n]; n];
    for h in 0..n {
        let r = reach(n, succ, entry, Some(h));
        for v in 0..n {
            out[h][v] = v == h || !r[v];
        }
    }
    out
}

#[derive(Debug, Clone)]
struct OracleLoop {
    header: usize,
    tail: usize,
    body: HashSet<usize>,
    exits: HashSet<usize>,
    is_innermost: bool,
}

fn oracle_loops(n: usize, succ: &[Vec<usize>], entry: usize) -> Vec<OracleLoop> {
    let dom = oracle_dominates(n, succ, entry);
    let reachable = reach(n, succ, entry, None);

    // predecessor adjacency for "can reach n avoiding h"
    let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
    for u in 0..n {
        for &v in &succ[u] {
            pred[v].push(u);
        }
    }

    let mut out: Vec<OracleLoop> = Vec::new();
    for tail in 0..n {
        if !reachable[tail] {
            continue;
        }
        for &h in &succ[tail] {
            if !dom[h][tail] {
                continue;
            }
            // body = {h} + {v : v reaches tail without passing through h}
            // = {h} + {v : tail is reachable from v in graph minus h}
            // computed as backward reachability from tail avoiding h.
            let mut body: HashSet<usize> = HashSet::new();
            body.insert(h);
            if tail != h {
                // self-loop h->h: body is exactly {h}
                let back = reach(n, &pred, tail, Some(h));
                for (v, &hit) in back.iter().enumerate() {
                    if hit && v != h {
                        body.insert(v);
                    }
                }
            }
            let mut exits: HashSet<usize> = HashSet::new();
            for &b in &body {
                for &s in &succ[b] {
                    if !body.contains(&s) {
                        exits.insert(s);
                    }
                }
            }
            out.push(OracleLoop { header: h, tail, body, exits, is_innermost: true });
        }
    }
    for i in 0..out.len() {
        let mut inner = true;
        for j in 0..out.len() {
            if i != j && out[j].body.is_subset(&out[i].body) && out[j].body != out[i].body {
                inner = false;
                break;
            }
        }
        out[i].is_innermost = inner;
    }
    out
}

// ── graph construction ───────────────────────────────────────────────────────

/// Build a connected random digraph: every node > 0 gets a tree edge from a
/// random earlier node (so all nodes are reachable from entry 0), then extra
/// random edges (including backward and cross edges) create loops, nesting,
/// self-loops and irreducibility.
fn gen_graph(rng: &mut XorShift, n: usize, extra: usize) -> Vec<Vec<usize>> {
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    for v in 1..n {
        let p = rng.below(v);
        succ[p].push(v);
    }
    for _ in 0..extra {
        let u = rng.below(n);
        let v = rng.below(n);
        if !succ[u].contains(&v) {
            succ[u].push(v);
        }
    }
    succ
}

fn build_cfg(n: usize, succ: &[Vec<usize>], entry: usize) -> ControlFlowGraph {
    let mut blocks: HashMap<Address, BasicBlock> = HashMap::new();
    for i in 0..n {
        blocks.insert(
            a(i),
            BasicBlock { start: a(i), end: a(i), instructions: Vec::new() },
        );
    }
    let mut edges: Vec<CfgEdge> = Vec::new();
    for u in 0..n {
        for &v in &succ[u] {
            edges.push(CfgEdge { from: a(u), to: a(v), kind: EdgeKind::Unconditional });
        }
    }
    let dom_tree = DominatorTree::compute(&blocks, &edges, a(entry));
    let post_dom_tree = PostDominatorTree::compute(&blocks, &edges);
    ControlFlowGraph {
        blocks,
        edges,
        entry: a(entry),
        dom_tree,
        loops: Vec::new(),
        post_dom_tree,
    }
}

/// True iff the graph has a cycle with two distinct entry points from outside
/// (irreducible): some SCC of size >= 2 that has >= 2 distinct nodes with a
/// predecessor outside the SCC or equal to entry.
fn is_irreducible(n: usize, succ: &[Vec<usize>], entry: usize) -> bool {
    // SCC by brute force: u,v same SCC iff mutually reachable.
    let r: Vec<Vec<bool>> = (0..n).map(|u| reach(n, succ, u, None)).collect();
    let mut comp = vec![usize::MAX; n];
    let mut nc = 0;
    for u in 0..n {
        if comp[u] != usize::MAX {
            continue;
        }
        for v in u..n {
            if comp[v] == usize::MAX && r[u][v] && r[v][u] {
                comp[v] = nc;
            }
        }
        nc += 1;
    }
    for c in 0..nc {
        let members: Vec<usize> = (0..n).filter(|&v| comp[v] == c).collect();
        if members.len() < 2 {
            continue;
        }
        let mut entries = 0;
        for &m in &members {
            let outside = (0..n).any(|u| comp[u] != c && succ[u].contains(&m)) || m == entry;
            if outside {
                entries += 1;
            }
        }
        if entries >= 2 {
            return true;
        }
    }
    false
}

// ── the differential test ────────────────────────────────────────────────────

#[test]
fn find_natural_loops_matches_definitional_oracle() {
    let mut rng = XorShift(0x5eed_1234_abcd_0001);

    let mut cov_self_loop = 0usize;
    let mut cov_nested = 0usize; // strict subset relation between two loops
    let mut cov_shared_header = 0usize; // two back edges to same header
    let mut cov_irreducible = 0usize;
    let mut cov_multi_exit = 0usize;
    let mut cov_no_loops = 0usize;

    for trial in 0..4000 {
        let n = 2 + rng.below(8); // 2..=9
        let extra = rng.below(n * 2 + 1);
        let succ = gen_graph(&mut rng, n, extra);
        let entry = 0usize;

        let want = oracle_loops(n, &succ, entry);
        let cfg = build_cfg(n, &succ, entry);
        let got = find_natural_loops(&cfg);

        // coverage bookkeeping
        if succ.iter().enumerate().any(|(u, s)| s.contains(&u)) {
            cov_self_loop += 1;
        }
        if want.is_empty() {
            cov_no_loops += 1;
        }
        if want.iter().any(|l| l.exits.len() >= 2) {
            cov_multi_exit += 1;
        }
        if want
            .iter()
            .any(|x| want.iter().any(|y| y.body.is_subset(&x.body) && y.body != x.body))
        {
            cov_nested += 1;
        }
        {
            let mut hs: HashMap<usize, usize> = HashMap::new();
            for l in &want {
                *hs.entry(l.header).or_insert(0) += 1;
            }
            if hs.values().any(|&c| c > 1) {
                cov_shared_header += 1;
            }
        }
        if is_irreducible(n, &succ, entry) {
            cov_irreducible += 1;
        }

        // ── compare, keyed on (header, back_edge_src) ──
        assert_eq!(
            got.len(),
            want.len(),
            "trial {trial}: loop COUNT mismatch. succ={succ:?} \
             got={:?} want={:?}",
            got.iter().map(|l| (l.header.as_u64(), l.back_edge_src.as_u64())).collect::<Vec<_>>(),
            want.iter().map(|l| (l.header, l.tail)).collect::<Vec<_>>()
        );

        for w in &want {
            let g = got
                .iter()
                .find(|g| {
                    g.header.as_u64() as usize == w.header
                        && g.back_edge_src.as_u64() as usize == w.tail
                })
                .unwrap_or_else(|| {
                    panic!(
                        "trial {trial}: no reported loop for back edge {}->{}. succ={succ:?}",
                        w.tail, w.header
                    )
                });

            let gbody: HashSet<usize> =
                g.body.iter().map(|x| x.as_u64() as usize).collect();
            assert_eq!(
                gbody, w.body,
                "trial {trial}: BODY mismatch for back edge {}->{}. succ={succ:?}",
                w.tail, w.header
            );

            let gexits: HashSet<usize> =
                g.exits.iter().map(|x| x.as_u64() as usize).collect();
            assert_eq!(
                gexits, w.exits,
                "trial {trial}: EXITS mismatch for back edge {}->{}. succ={succ:?}",
                w.tail, w.header
            );
            assert_eq!(
                g.exits.len(),
                gexits.len(),
                "trial {trial}: duplicate entries in exits {:?}. succ={succ:?}",
                g.exits
            );

            assert_eq!(
                g.is_innermost, w.is_innermost,
                "trial {trial}: is_innermost mismatch for back edge {}->{} \
                 (got {}, want {}). succ={succ:?}",
                w.tail, w.header, g.is_innermost, w.is_innermost
            );
        }

        // The header must dominate every body node, per the definition
        // (checked against the oracle's own dominance relation).
        let dom = oracle_dominates(n, &succ, entry);
        for w in &want {
            for &v in &w.body {
                assert!(
                    dom[w.header][v],
                    "trial {trial}: oracle body node {v} not dominated by header {} \
                     -- oracle self-check. succ={succ:?}",
                    w.header
                );
            }
        }
    }

    // ── generator coverage assertions ──
    assert!(cov_self_loop >= 50, "generator produced too few self-loops: {cov_self_loop}");
    assert!(cov_nested >= 50, "generator produced too few nested loops: {cov_nested}");
    assert!(
        cov_shared_header >= 50,
        "generator produced too few shared-header multi-back-edge cases: {cov_shared_header}"
    );
    assert!(
        cov_irreducible >= 50,
        "generator produced too few irreducible graphs: {cov_irreducible}"
    );
    assert!(cov_multi_exit >= 50, "generator produced too few multi-exit loops: {cov_multi_exit}");
    assert!(cov_no_loops >= 50, "generator produced too few loop-free graphs: {cov_no_loops}");
}

/// Determinism: the same CFG must yield the same result, element for element,
/// including the ORDER of `exits`. A result that varies between calls is a
/// defect, not something to paper over with sorting.
///
/// KNOWN OPEN DEFECT (2026-07-21): this test FAILS. `find_natural_loops`
/// builds `exits` by iterating the `HashSet` loop body, so the ORDER of the
/// returned `exits` vector varies between two calls on the *same* CFG.
/// The exit SET is always correct; only the order is unstable. Marked
/// `#[ignore]` so it does not redden the suite while the defect is open --
/// run with `cargo test -p rustre-analysis-cfg -- --ignored` to see it.
/// Minimal repro: succ = [[1,3,5,7],[2],[4],[7],[7],[6,0],[7,0,2],[]], entry 0.
#[test]
// FIXED 2026-07-21: `find_natural_loops` now sorts `exits` (lib.rs), so this
// no longer needs ignoring. It was parked here as a known-open defect.
fn find_natural_loops_is_deterministic() {
    let mut rng = XorShift(0xdead_beef_0000_0007);
    for trial in 0..300 {
        let n = 3 + rng.below(7);
        let extra = rng.below(n * 2 + 1);
        let succ = gen_graph(&mut rng, n, extra);
        let cfg = build_cfg(n, &succ, 0);
        let r1 = find_natural_loops(&cfg);
        let r2 = find_natural_loops(&cfg);
        assert_eq!(r1.len(), r2.len(), "trial {trial}: length varies between calls");
        for (x, y) in r1.iter().zip(r2.iter()) {
            assert_eq!(x.header, y.header, "trial {trial}: header order varies");
            assert_eq!(x.back_edge_src, y.back_edge_src, "trial {trial}: tail order varies");
            assert_eq!(x.body, y.body, "trial {trial}: body varies");
            assert_eq!(
                x.exits, y.exits,
                "trial {trial}: exits VECTOR (order included) varies between identical calls \
                 on the same CFG -- nondeterministic output. succ={succ:?}"
            );
        }
    }
}
