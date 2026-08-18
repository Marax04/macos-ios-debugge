//! Differential test for `PostDominatorTree::compute` in rustre-analysis-cfg.
//!
//! Cross-checks against:
//!  (a) a brute-force post-dominance oracle: `m` post-dominates `b` iff every
//!      path from `b` to any exit passes through `m`, computed by removal on
//!      reachability toward exit nodes;
//!  (b) `DominatorTree::compute` run on an explicitly reversed CFG with a
//!      virtual single exit built by the test itself.
//!
//! Conventions of `PostDominatorTree` (read from the impl):
//!  - "exit" = block with no outgoing edges;
//!  - nodes that cannot reach any exit (e.g. all nodes when the whole graph is
//!    cyclic with no exit) are simply absent from `idom`;
//!  - `idom[b] == None` means b's immediate post-dominator is the virtual
//!    exit, i.e. b has no proper post-dominator among real nodes.

use rustre_analysis_cfg::{BasicBlock, CfgEdge, DominatorTree, EdgeKind, PostDominatorTree};
use rustre_core::address::Address;
use std::collections::{HashMap, HashSet, VecDeque};

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

/// Exit nodes: no outgoing edges.
fn exits(n: usize, succ: &[Vec<usize>]) -> Vec<usize> {
    (0..n).filter(|&i| succ[i].is_empty()).collect()
}

/// Can `b` reach any exit node, optionally with one node removed (`removed`
/// may be `usize::MAX` for "none")? A path never "passes through" `b` itself,
/// so `removed == b` is disallowed by callers.
fn reaches_exit_without(
    n: usize,
    succ: &[Vec<usize>],
    exit_set: &HashSet<usize>,
    b: usize,
    removed: usize,
) -> bool {
    if b == removed {
        return false;
    }
    let mut seen = HashSet::new();
    let mut q = VecDeque::new();
    seen.insert(b);
    q.push_back(b);
    while let Some(u) = q.pop_front() {
        if exit_set.contains(&u) {
            return true;
        }
        for &v in &succ[u] {
            if v < n && v != removed && seen.insert(v) {
                q.push_back(v);
            }
        }
    }
    false
}

/// Brute-force immediate post-dominators by definition.
/// Returns `pdom_sets[b]` (strict post-dominators) and `ipdom[b]`:
///  - `None` outer = b cannot reach any exit (not in the post-dom tree);
///  - `Some(None)` = b's immediate post-dominator is the virtual exit;
///  - `Some(Some(m))` = m is b's immediate post-dominator.
/// The oracle's answer: per-block post-dominator sets, and per-block immediate
/// post-dominator where `None` means "block does not reach the exit" and
/// `Some(None)` means "the immediate post-dominator is the virtual exit".
///
/// Named because the nested `Option<Option<usize>>` is exactly the shape that
/// needed a `type_complexity` allow, and exactly the shape a reader must be
/// told the meaning of.
type IPostDomOracle = (Vec<HashSet<usize>>, Vec<Option<Option<usize>>>);

fn oracle_ipdom(n: usize, succ: &[Vec<usize>]) -> IPostDomOracle {
    let exit_set: HashSet<usize> = exits(n, succ).into_iter().collect();
    let live: Vec<usize> = (0..n)
        .filter(|&b| reaches_exit_without(n, succ, &exit_set, b, usize::MAX))
        .collect();
    let live_set: HashSet<usize> = live.iter().copied().collect();
    // pdoms[b] = strict post-dominators of b.
    let mut pdoms: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    for &b in &live {
        for &m in &live {
            if m != b && !reaches_exit_without(n, succ, &exit_set, b, m) {
                pdoms[b].insert(m);
            }
        }
    }
    let mut out: Vec<Option<Option<usize>>> = vec![None; n];
    for &b in &live {
        if pdoms[b].is_empty() {
            out[b] = Some(None); // immediate post-dominator is the virtual exit
        } else {
            // ipdom(b) = strict post-dominator post-dominated by all the
            // others, i.e. the one with the largest strict-pdom set.
            let ip = pdoms[b]
                .iter()
                .copied()
                .max_by_key(|&d| pdoms[d].len())
                .unwrap();
            out[b] = Some(Some(ip));
        }
    }
    let _ = live_set;
    (pdoms, out)
}

fn make_blocks(n: usize) -> HashMap<Address, BasicBlock> {
    (0..n)
        .map(|i| {
            (
                a(i as u64),
                BasicBlock { start: a(i as u64), end: a(i as u64), instructions: Vec::new() },
            )
        })
        .collect()
}

fn make_edges(succ: &[Vec<usize>]) -> Vec<CfgEdge> {
    let mut edges = Vec::new();
    for (f, ts) in succ.iter().enumerate() {
        for &t in ts {
            edges.push(CfgEdge { from: a(f as u64), to: a(t as u64), kind: EdgeKind::Unconditional });
        }
    }
    edges
}

/// Random CFG generator shared by the trials. `force_no_exit` makes every
/// node have at least one successor (all nodes end up in/feeding cycles, so
/// there is no exit at all). `force_multi_exit` leaves at least two sinks.
fn random_succ(rng: &mut XorShift, n: usize, force_no_exit: bool, force_multi_exit: bool) -> Vec<Vec<usize>> {
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    let edge_count = 1 + (rng.below((2 * n) as u64) as usize);
    for _ in 0..edge_count {
        let f = rng.below(n as u64) as usize;
        let t = rng.below(n as u64) as usize;
        succ[f].push(t); // self-loops and duplicates allowed
    }
    if force_no_exit {
        for i in 0..n {
            if succ[i].is_empty() {
                let t = rng.below(n as u64) as usize;
                succ[i].push(t);
            }
        }
    } else if force_multi_exit && n >= 3 {
        // Clear outgoing edges of two distinct nodes so they are sinks (rets).
        let e1 = rng.below(n as u64) as usize;
        let e2 = (e1 + 1 + rng.below((n - 1) as u64) as usize) % n;
        succ[e1].clear();
        succ[e2].clear();
        // Wire something into them so they are not trivially isolated.
        let f = rng.below(n as u64) as usize;
        if f != e1 {
            succ[f].push(e1);
        }
        let g = rng.below(n as u64) as usize;
        if g != e2 {
            succ[g].push(e2);
        }
    }
    succ
}

#[test]
fn postdom_matches_oracle_and_reversed_dominators() {
    let mut rng = XorShift(0x0f1e_2d3c_4b5a_6978);
    // Test-local virtual exit for the reversed-CFG cross-check; must not
    // collide with node addresses 0..10.
    let vexit = a(0xffff_0000);

    for trial in 0..1000u32 {
        let n = 2 + (rng.below(9) as usize); // 2..=10 nodes
        let force_no_exit = trial % 5 == 3; // some trials: no exit at all
        let force_multi_exit = trial % 5 == 1; // some trials: >= 2 rets
        let succ = random_succ(&mut rng, n, force_no_exit, force_multi_exit);

        let exit_list = exits(n, &succ);
        let exit_set: HashSet<usize> = exit_list.iter().copied().collect();
        if force_no_exit {
            assert!(exit_list.is_empty(), "trial {trial}: generator broke no-exit invariant");
        }

        let (pdom_sets, oracle) = oracle_ipdom(n, &succ);

        let blocks = make_blocks(n);
        let edges = make_edges(&succ);
        let pdt = PostDominatorTree::compute(&blocks, &edges);

        // ── (a) oracle cross-check ──
        for b in 0..n {
            let got = pdt.idom.get(&a(b as u64)).copied();
            match oracle[b] {
                None => assert_eq!(
                    got, None,
                    "trial {trial}: node {b} cannot reach any exit but PostDominatorTree \
                     has idom entry {got:?} (succ={succ:?})"
                ),
                Some(want) => {
                    let want_addr = want.map(|m| a(m as u64));
                    assert_eq!(
                        got,
                        Some(want_addr),
                        "trial {trial}: ipdom({b}) = {got:?}, oracle = {want:?} (succ={succ:?})"
                    );
                }
            }
        }

        // post_dominates() must agree with the oracle's full strict-pdom sets
        // for every live pair.
        for b in 0..n {
            if oracle[b].is_none() {
                continue;
            }
            for m in 0..n {
                if m == b || oracle[m].is_none() {
                    continue;
                }
                let want = pdom_sets[b].contains(&m);
                let got = pdt.post_dominates(a(m as u64), a(b as u64));
                assert_eq!(
                    got, want,
                    "trial {trial}: post_dominates({m}, {b}) = {got}, oracle = {want} (succ={succ:?})"
                );
            }
        }

        // ── (b) DominatorTree on the explicitly reversed CFG ──
        let mut rev_blocks = make_blocks(n);
        rev_blocks.insert(
            vexit,
            BasicBlock { start: vexit, end: vexit, instructions: Vec::new() },
        );
        let mut rev_edges: Vec<CfgEdge> = Vec::new();
        for (f, ts) in succ.iter().enumerate() {
            for &t in ts {
                rev_edges.push(CfgEdge { from: a(t as u64), to: a(f as u64), kind: EdgeKind::Unconditional });
            }
        }
        let mut sorted_exits = exit_list.clone();
        sorted_exits.sort_unstable();
        for &e in &sorted_exits {
            rev_edges.push(CfgEdge { from: vexit, to: a(e as u64), kind: EdgeKind::Unconditional });
        }
        let rev_dom = DominatorTree::compute(&rev_blocks, &rev_edges, vexit);

        for b in 0..n {
            let rev = rev_dom
                .idom
                .get(&a(b as u64))
                .copied()
                .map(|p| p.and_then(|p| if p == vexit { None } else { Some(p) }));
            let got = pdt.idom.get(&a(b as u64)).copied();
            assert_eq!(
                got, rev,
                "trial {trial}: PostDominatorTree vs reversed DominatorTree disagree on \
                 ipdom({b}) (succ={succ:?})"
            );
        }

        // Sanity: an exit node post-dominates itself and has ipdom = virtual
        // exit (None).
        for &e in &exit_set {
            assert_eq!(
                pdt.idom.get(&a(e as u64)).copied(),
                Some(None),
                "trial {trial}: exit node {e} must map to Some(None) (succ={succ:?})"
            );
        }
    }
}
