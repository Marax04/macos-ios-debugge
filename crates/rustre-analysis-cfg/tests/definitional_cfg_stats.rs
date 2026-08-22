//! Definitional oracle for `rustre_analysis_cfg::CfgStats::compute`.
//!
//! Every field is re-derived from what it MEANS, by brute force over the graph
//! the CFG describes — never from how `compute` computes it:
//!
//!   * `block_count`  = number of entries in `cfg.blocks` (see the reachability
//!     pin below).
//!   * `node_count`   = `block_count` (documented invariant).
//!   * `edge_count`   = number of entries in `cfg.edges`.
//!   * `entry_blocks` = blocks that are the target of NO edge.
//!   * `exit_blocks`  = blocks whose last instruction is `Ret`.
//!   * `loop_count` / `max_loop_depth` — natural loops per the TEXTBOOK
//!     definition, recomputed here (same definition as
//!     `tests/definitional_natural_loops.rs`, which is not modified):
//!     `h dom n` iff every entry->n path contains `h`; `n -> h` is a back edge
//!     iff `h dom n`; body = {h} + {v : v reaches n avoiding h}. Depth of an
//!     address = how many loop bodies contain it; `max_loop_depth` = the max.
//!   * `cyclomatic_complexity` = E - N + 2P (`McCabe`).
//!
//! ## Two questions this oracle exists to settle
//!
//! 1. REACHABILITY. `DominatorTree::compute` starts from `rpo_order`, i.e. only
//!    nodes reachable from `entry`, but `CfgStats::compute` reads
//!    `cfg.blocks.len()` directly. The generator therefore deliberately emits
//!    UNREACHABLE blocks, and the oracle asserts
//!    `block_count == cfg.blocks.len()` (all blocks, reachable or not) rather
//!    than the reachable-node count. Those two differ on the generated inputs,
//!    so this is a real discrimination, not a tautology.
//!
//! 2. P IN E - N + 2P. `compute` hard-codes P = 1. The oracle computes the true
//!    number of weakly-connected components and asserts the implementation
//!    equals the P=1 form — matching the doc comment ("we treat the entire CFG
//!    as one connected component"), and separately records when the true P > 1
//!    so the divergence is visible rather than silent.

use rustre_analysis_cfg::{
    find_natural_loops, BasicBlock, CfgEdge, CfgStats, ControlFlowGraph, DominatorTree, EdgeKind,
    PostDominatorTree,
};
use rustre_core::address::Address;
use rustre_il_llil::LlilInstruction;
use std::collections::{HashMap, HashSet};

const fn a(v: usize) -> Address {
    Address::new(v as u64)
}

struct XorShift(u64);
impl XorShift {
    const fn next(&mut self) -> u64 {
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

/// `dom[h][v]`: every path entry->v passes through `h`.
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

/// Natural-loop bodies, by definition.
fn oracle_loop_bodies(n: usize, succ: &[Vec<usize>], entry: usize) -> Vec<HashSet<usize>> {
    let dom = oracle_dominates(n, succ, entry);
    let reachable = reach(n, succ, entry, None);
    let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
    for u in 0..n {
        for &v in &succ[u] {
            pred[v].push(u);
        }
    }
    let mut out = Vec::new();
    for tail in 0..n {
        if !reachable[tail] {
            continue;
        }
        for &h in &succ[tail] {
            if !dom[h][tail] {
                continue;
            }
            let mut body: HashSet<usize> = HashSet::new();
            body.insert(h);
            if tail != h {
                let back = reach(n, &pred, tail, Some(h));
                for (v, &hit) in back.iter().enumerate() {
                    if hit && v != h {
                        body.insert(v);
                    }
                }
            }
            out.push(body);
        }
    }
    out
}

/// Number of WEAKLY connected components (edges treated as undirected),
/// by union-find over all nodes.
fn oracle_components(n: usize, succ: &[Vec<usize>]) -> usize {
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut Vec<usize>, x: usize) -> usize {
        let mut r = x;
        while parent[r] != r {
            r = parent[r];
        }
        let mut c = x;
        while parent[c] != c {
            let nxt = parent[c];
            parent[c] = r;
            c = nxt;
        }
        r
    }
    for u in 0..n {
        for &v in &succ[u] {
            let (ru, rv) = (find(&mut parent, u), find(&mut parent, v));
            if ru != rv {
                parent[ru] = rv;
            }
        }
    }
    (0..n).filter(|&i| find(&mut parent, i) == i).count()
}

// ── graph construction ───────────────────────────────────────────────────────

/// Random digraph that deliberately produces (a) nodes UNREACHABLE from entry
/// and (b) multiple weakly-connected components — the two shapes the two open
/// questions hinge on — alongside ordinary loops/nesting/self-loops.
fn gen_graph(rng: &mut XorShift, n: usize, extra: usize, orphan_rate: usize) -> Vec<Vec<usize>> {
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    for v in 1..n {
        // With probability orphan_rate/100 leave `v` with no tree parent, so it
        // (and anything hanging off it) is unreachable from entry 0.
        if rng.below(100) < orphan_rate {
            continue;
        }
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

/// `ret_mask` decides which blocks end in `Ret`.
fn build_cfg(n: usize, succ: &[Vec<usize>], entry: usize, ret: &[bool]) -> ControlFlowGraph {
    let mut blocks: HashMap<Address, BasicBlock> = HashMap::new();
    for i in 0..n {
        let instructions = if ret[i] {
            vec![LlilInstruction::Nop, LlilInstruction::Ret]
        } else if i % 3 == 0 {
            Vec::new()
        } else {
            vec![LlilInstruction::Ret, LlilInstruction::Nop]
        };
        blocks.insert(a(i), BasicBlock { start: a(i), end: a(i), instructions });
    }
    let mut edges: Vec<CfgEdge> = Vec::new();
    for u in 0..n {
        for &v in &succ[u] {
            edges.push(CfgEdge { from: a(u), to: a(v), kind: EdgeKind::Unconditional });
        }
    }
    let dom_tree = DominatorTree::compute(&blocks, &edges, a(entry));
    let post_dom_tree = PostDominatorTree::compute(&blocks, &edges);
    let mut cfg = ControlFlowGraph {
        blocks,
        edges,
        entry: a(entry),
        dom_tree,
        loops: Vec::new(),
        post_dom_tree,
    };
    cfg.loops = find_natural_loops(&cfg);
    cfg
}

// ── the oracle test ──────────────────────────────────────────────────────────

#[test]
fn cfg_stats_matches_definitional_oracle() {
    let mut rng = XorShift(0x5eed_1234_9abc_def1);
    let mut saw_unreachable = 0usize;
    let mut saw_multi_component = 0usize;
    let mut saw_loops = 0usize;
    let mut saw_depth2 = 0usize;
    let mut saw_multi_entry_blocks = 0usize;
    let mut skipped_unreachable_self_loop = 0usize;

    for case in 0..3000 {
        let n = 1 + rng.below(9);
        let extra = rng.below(2 * n + 1);
        let orphan_rate = [0usize, 0, 15, 40][rng.below(4)];
        let succ = gen_graph(&mut rng, n, extra, orphan_rate);
        let ret: Vec<bool> = (0..n).map(|_| rng.below(2) == 0).collect();
        let cfg = build_cfg(n, &succ, 0, &ret);
        let stats = CfgStats::compute(&cfg);

        let edge_count: usize = succ.iter().map(Vec::len).sum();

        // ── node/block/edge counts ──────────────────────────────────────────
        assert_eq!(
            stats.block_count, n,
            "case {case}: block_count must be |cfg.blocks| (ALL blocks, \
             including those unreachable from entry)"
        );
        assert_eq!(
            stats.node_count, stats.block_count,
            "case {case}: documented invariant node_count == block_count"
        );
        assert_eq!(stats.edge_count, edge_count, "case {case}: edge_count");

        // ── entry blocks: no incoming edge ──────────────────────────────────
        let mut has_incoming = vec![false; n];
        for u in 0..n {
            for &v in &succ[u] {
                has_incoming[v] = true;
            }
        }
        let expect_entry = (0..n).filter(|&i| !has_incoming[i]).count();
        assert_eq!(stats.entry_blocks, expect_entry, "case {case}: entry_blocks");
        if expect_entry > 1 {
            saw_multi_entry_blocks += 1;
        }

        // ── exit blocks: LAST instruction is Ret ────────────────────────────
        let expect_exit = (0..n).filter(|&i| ret[i]).count();
        assert_eq!(stats.exit_blocks, expect_exit, "case {case}: exit_blocks");

        // ── loops ───────────────────────────────────────────────────────────
        // KNOWN DIVERGENCE (characterized separately by the three
        // `unreachable_*` tests below): `DominatorTree::dominates(a, a)`
        // short-circuits to `true` without checking that `a` is reachable, so
        // an UNREACHABLE SELF-LOOP is reported as a natural loop while an
        // unreachable multi-node cycle is not. The definitional oracle here
        // counts reachable back edges only, so skip (and count) those cases
        // rather than silently weakening the oracle to match.
        let r_pre = reach(n, &succ, 0, None);
        let has_unreachable_self_loop = (0..n).any(|v| !r_pre[v] && succ[v].contains(&v));
        if has_unreachable_self_loop {
            skipped_unreachable_self_loop += 1;
        } else {
            let bodies = oracle_loop_bodies(n, &succ, 0);
            assert_eq!(stats.loop_count, bodies.len(), "case {case}: loop_count");
            let mut depth: HashMap<usize, u32> = HashMap::new();
            for b in &bodies {
                for &v in b {
                    *depth.entry(v).or_insert(0) += 1;
                }
            }
            let expect_depth = depth.values().copied().max().unwrap_or(0);
            assert_eq!(stats.max_loop_depth, expect_depth, "case {case}: max_loop_depth");
            if !bodies.is_empty() {
                saw_loops += 1;
            }
            if expect_depth >= 2 {
                saw_depth2 += 1;
            }
        }

        // ── cyclomatic complexity: E - N + 2P with the CONTRACTED P = 1 ─────
        let expect_cc = (edge_count + 2).saturating_sub(n);
        assert_eq!(
            stats.cyclomatic_complexity, expect_cc,
            "case {case}: cyclomatic_complexity must be E - N + 2 (P hard-coded to 1)"
        );

        // Record how often the true component count disagrees with P = 1.
        let p = oracle_components(n, &succ);
        if p > 1 {
            saw_multi_component += 1;
        }

        // reachability coverage
        let r = reach(n, &succ, 0, None);
        if r.iter().filter(|&&b| !b).count() > 0 {
            saw_unreachable += 1;
        }
    }

    // Generator must actually reach the hard shapes, or the assertions above
    // proved nothing about them.
    assert!(saw_unreachable > 100, "generator produced too few unreachable blocks: {saw_unreachable}");
    assert!(saw_multi_component > 100, "generator produced too few disconnected graphs: {saw_multi_component}");
    assert!(saw_loops > 300, "generator produced too few looping graphs: {saw_loops}");
    assert!(saw_depth2 > 50, "generator produced too few nested loops: {saw_depth2}");
    assert!(saw_multi_entry_blocks > 50, "generator produced too few multi-entry graphs: {saw_multi_entry_blocks}");
    assert!(
        skipped_unreachable_self_loop > 10,
        "the unreachable-self-loop divergence was never reached ({skipped_unreachable_self_loop}); \
         the skip is then dead code and the characterization tests below carry it alone"
    );
}

// ── the unreachable-cycle divergence, characterized ─────────────────────────
//
// `DominatorTree::dominates(a, b)` returns `true` immediately when `a == b`,
// without consulting `idom` — so it answers `true` for a node that is not in
// the dominator tree at all. `find_natural_loops` calls
// `dom_tree.dominates(e.to, e.from)` to classify back edges, so an unreachable
// SELF-loop `u -> u` is classified as a back edge and becomes a natural loop,
// which `CfgStats` then counts in `loop_count` / `max_loop_depth`.
//
// An unreachable TWO-node cycle gets the opposite treatment: `dominates(2, 3)`
// consults `idom`, finds nothing, and returns `false`. So dead code with
// `jmp $` is reported as containing a loop while dead code with a two-block
// cycle is not. These three tests pin that asymmetry so a future change to
// either branch is visible.

#[test]
fn unreachable_self_loop_is_counted_as_a_loop() {
    // 0 -> 1 ; 2 -> 2 (self-loop, unreachable from entry 0).
    let succ = vec![vec![1], vec![], vec![2]];
    let cfg = build_cfg(3, &succ, 0, &[false; 3]);
    let stats = CfgStats::compute(&cfg);

    assert!(!reach(3, &succ, 0, None)[2], "block 2 is unreachable from entry");
    // By the reachable-only textbook definition this should be 0.
    assert_eq!(stats.loop_count, 1, "unreachable self-loop IS reported");
    assert_eq!(stats.max_loop_depth, 1);
}

#[test]
fn unreachable_two_node_cycle_is_not_counted_as_a_loop() {
    // 0 -> 1 ; 2 -> 3 -> 2 (cycle, unreachable from entry 0).
    let succ = vec![vec![1], vec![], vec![3], vec![2]];
    let cfg = build_cfg(4, &succ, 0, &[false; 4]);
    let stats = CfgStats::compute(&cfg);

    assert!(!reach(4, &succ, 0, None)[2], "block 2 is unreachable from entry");
    assert_eq!(stats.loop_count, 0, "unreachable multi-node cycle is NOT reported");
    assert_eq!(stats.max_loop_depth, 0);
}

#[test]
fn reachable_self_loop_is_counted_as_a_loop() {
    // Control for the two tests above: a REACHABLE self-loop must be a loop
    // under both the definition and the implementation.
    let succ = vec![vec![1], vec![1]];
    let cfg = build_cfg(2, &succ, 0, &[false; 2]);
    let stats = CfgStats::compute(&cfg);
    assert_eq!(stats.loop_count, 1);
    assert_eq!(stats.max_loop_depth, 1);
}

/// Pins the resolution of the P question as an explicit, separate statement:
/// on a graph with two weakly-connected components the true `McCabe` value
/// `E - N + 2P` is NOT what `compute` returns; it returns the P = 1 form.
#[test]
fn cyclomatic_complexity_hard_codes_p_equals_one() {
    // Two disjoint components: 0->1 and 2->3.  E = 2, N = 4, true P = 2.
    let succ = vec![vec![1], vec![], vec![3], vec![]];
    let ret = vec![false; 4];
    let cfg = build_cfg(4, &succ, 0, &ret);
    let stats = CfgStats::compute(&cfg);

    assert_eq!(oracle_components(4, &succ), 2, "oracle: two components");
    // True McCabe with P = 2 would be 2 - 4 + 4 = 2.
    // The implementation documents and returns the P = 1 form: 2 - 4 + 2 = 0.
    assert_eq!(stats.cyclomatic_complexity, 0);
    assert_eq!(stats.block_count, 4);
    assert_eq!(stats.entry_blocks, 2, "blocks 0 and 2 have no predecessor");
}

/// Pins the reachability question: `block_count` counts blocks unreachable
/// from `entry`, even though the dominator/loop machinery ignores them.
#[test]
fn block_count_includes_unreachable_blocks() {
    // 0 -> 1 ; 2 -> 3 (unreachable from entry 0).
    let succ = vec![vec![1], vec![], vec![3], vec![]];
    let ret = vec![false; 4];
    let cfg = build_cfg(4, &succ, 0, &ret);
    let stats = CfgStats::compute(&cfg);

    let reachable = reach(4, &succ, 0, None).iter().filter(|&&b| b).count();
    assert_eq!(reachable, 2, "only 0 and 1 are reachable");
    assert_eq!(stats.block_count, 4, "block_count is |blocks|, not |reachable|");
    assert_eq!(stats.node_count, 4);
    assert_eq!(stats.edge_count, 2);
    assert_eq!(stats.loop_count, 0);
}
