//! Cross-crate differential test: rustre-analysis-cfg's `DominatorTree`
//! (Cooper/Harvey/Kennedy over `HashMap<Address, BasicBlock>`) vs
//! rustre-analysis-dataflow's independent `compute_dominators` (index-based
//! RPO fixpoint). Two fully independent implementations of the same
//! algorithm family must agree on the immediate dominator of every
//! reachable node for random CFGs, including cycles, self-loops, and
//! unreachable nodes.

use rustre_analysis_cfg::{BasicBlock, CfgEdge, DominatorTree, EdgeKind};
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

fn reachable(n: usize, succ: &[Vec<usize>], entry: usize) -> HashSet<usize> {
    let mut seen = HashSet::new();
    let mut q = VecDeque::new();
    seen.insert(entry);
    q.push_back(entry);
    while let Some(u) = q.pop_front() {
        for &v in &succ[u] {
            if v < n && seen.insert(v) {
                q.push_back(v);
            }
        }
    }
    seen
}

/// Reachability with one node removed (never the entry). Used by the
/// brute-force dominance oracle: `m` dominates `b` iff removing `m` makes
/// `b` unreachable from the entry.
fn reachable_without(n: usize, succ: &[Vec<usize>], entry: usize, removed: usize) -> HashSet<usize> {
    let mut seen = HashSet::new();
    let mut q = VecDeque::new();
    if entry == removed {
        return seen;
    }
    seen.insert(entry);
    q.push_back(entry);
    while let Some(u) = q.pop_front() {
        for &v in &succ[u] {
            if v < n && v != removed && seen.insert(v) {
                q.push_back(v);
            }
        }
    }
    seen
}

/// Brute-force immediate dominators by definition. Returns `idom[b]` for
/// every reachable `b != entry`; entry and unreachable nodes map to `None`.
fn oracle_idom(n: usize, succ: &[Vec<usize>], entry: usize) -> Vec<Option<usize>> {
    let live = reachable(n, succ, entry);
    // doms[b] = strict dominators of b (excluding b itself).
    let mut doms: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    for &m in &live {
        let r = reachable_without(n, succ, entry, m);
        for &b in &live {
            if b != m && !r.contains(&b) {
                doms[b].insert(m);
            }
        }
    }
    let mut out = vec![None; n];
    for &b in &live {
        if b == entry {
            continue;
        }
        // idom(b) = the strict dominator dominated by all other strict
        // dominators, i.e. the one with the largest strict-dominator set.
        let idom = doms[b]
            .iter()
            .copied()
            .max_by_key(|&d| doms[d].len())
            .expect("every reachable non-entry node is dominated by the entry");
        out[b] = Some(idom);
    }
    out
}

/// Three-way differential idom check across fully independent implementations:
///  1. rustre-analysis-cfg `DominatorTree::compute` (Cooper/Harvey/Kennedy, Address-based)
///  2. rustre-analysis-cfg `lengauer_tarjan::compute_lt` (Lengauer-Tarjan)
///  3. rustre-analysis `DominanceFrontier::compute` (Cooper, index-based)
/// All are validated against a brute-force removal-based dominance oracle so a
/// disagreement pins down which implementation is wrong.
#[test]
fn three_way_idom_cross_check_against_oracle() {
    use rustre_analysis::control_flow_analysis as base;

    let mut rng = XorShift(0x1357_9bdf_2468_ace0);
    for trial in 0..1500 {
        let n = 2 + (rng.below(9) as usize); // 2..=10 nodes
        let entry = 0usize;

        let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
        let edge_count = 1 + (rng.below((2 * n) as u64) as usize);
        for _ in 0..edge_count {
            let f = rng.below(n as u64) as usize;
            let t = rng.below(n as u64) as usize;
            succ[f].push(t); // self-loops and duplicates allowed
        }
        // Bias toward back-edges into the entry (historical bug class).
        if trial % 3 == 0 {
            let f = rng.below(n as u64) as usize;
            succ[f].push(entry);
        }

        let oracle = oracle_idom(n, &succ, entry);
        let live = reachable(n, &succ, entry);

        // ── (1) cfg crate: DominatorTree (Cooper over Address space) ──
        let mut blocks: HashMap<Address, BasicBlock> = HashMap::new();
        for i in 0..n {
            blocks.insert(
                a(i as u64),
                BasicBlock { start: a(i as u64), end: a(i as u64), instructions: Vec::new() },
            );
        }
        let mut edges: Vec<CfgEdge> = Vec::new();
        for (f, ts) in succ.iter().enumerate() {
            for &t in ts {
                edges.push(CfgEdge { from: a(f as u64), to: a(t as u64), kind: EdgeKind::Unconditional });
            }
        }
        let tree = DominatorTree::compute(&blocks, &edges, a(entry as u64));

        // ── (2) cfg crate: Lengauer-Tarjan ──
        let nodes: Vec<Address> = (0..n).map(|i| a(i as u64)).collect();
        let mut lt_succ: HashMap<Address, Vec<Address>> = HashMap::new();
        for i in 0..n {
            lt_succ.insert(a(i as u64), succ[i].iter().map(|&t| a(t as u64)).collect());
        }
        let lt = rustre_analysis_cfg::lengauer_tarjan::compute_lt(&nodes, &lt_succ, a(entry as u64))
            .expect("entry is always in nodes");

        // ── (3) base crate: compute_idom via DominanceFrontier ──
        let mut base_blocks: Vec<base::BasicBlock> = (0..n).map(base::BasicBlock::new).collect();
        for (f, ts) in succ.iter().enumerate() {
            for &t in ts {
                if !base_blocks[f].successors.contains(&t) {
                    base_blocks[f].successors.push(t);
                }
                if !base_blocks[t].predecessors.contains(&f) {
                    base_blocks[t].predecessors.push(f);
                }
            }
        }
        let cfg = base::CFG { blocks: base_blocks, entry };
        let base_idom = base::DominanceFrontier::compute(&cfg).idom;

        for &node in &live {
            let cooper = tree.idom.get(&a(node as u64)).copied().flatten();
            let lt_i = lt.idom_of(a(node as u64));
            if node == entry {
                assert_eq!(cooper, None, "trial {trial}: cfg Cooper entry idom (succ={succ:?})");
                assert_eq!(lt_i, None, "trial {trial}: LT entry idom (succ={succ:?})");
                assert_eq!(base_idom[node], entry, "trial {trial}: base entry sentinel (succ={succ:?})");
                continue;
            }
            let want = oracle[node];
            let want_addr = want.map(|d| a(d as u64));
            assert_eq!(
                cooper, want_addr,
                "trial {trial}: cfg DominatorTree idom({node}) = {cooper:?}, oracle = {want:?} (succ={succ:?})"
            );
            assert_eq!(
                lt_i, want_addr,
                "trial {trial}: Lengauer-Tarjan idom({node}) = {lt_i:?}, oracle = {want:?} (succ={succ:?})"
            );
            assert_eq!(
                Some(base_idom[node]), want,
                "trial {trial}: base-crate compute_idom({node}) = {}, oracle = {want:?} (succ={succ:?})",
                base_idom[node]
            );
        }
        // Unreachable nodes: LT must not report an idom; base crate uses the
        // self-sentinel.
        for node in 0..n {
            if !live.contains(&node) {
                assert_eq!(
                    lt.idom_of(a(node as u64)),
                    None,
                    "trial {trial}: LT idom for unreachable {node} (succ={succ:?})"
                );
                assert_eq!(
                    base_idom[node], node,
                    "trial {trial}: base sentinel for unreachable {node} (succ={succ:?})"
                );
            }
        }
    }
}

#[test]
fn cfg_dominance_frontier_matches_dataflow() {
    let mut rng = XorShift(0xdead_beef_1234_5678);
    for trial in 0..1500 {
        let n = 2 + (rng.below(9) as usize);
        let entry = 0usize;

        let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
        let edge_count = 1 + (rng.below((2 * n) as u64) as usize);
        for _ in 0..edge_count {
            let f = rng.below(n as u64) as usize;
            let t = rng.below(n as u64) as usize;
            succ[f].push(t);
        }
        // Bias: every third trial add an explicit back-edge to the entry so
        // the entry-is-a-loop-header case (the historical DF bug class) is
        // exercised often, not just by chance.
        if trial % 3 == 0 {
            let f = rng.below(n as u64) as usize;
            succ[f].push(entry);
        }

        let df_idom = rustre_analysis_dataflow::compute_dominators(n, &succ, entry);
        let df_front =
            rustre_analysis_dataflow::compute_dominance_frontiers(n, &succ, &df_idom);

        let mut blocks: HashMap<Address, BasicBlock> = HashMap::new();
        for i in 0..n {
            blocks.insert(
                a(i as u64),
                BasicBlock {
                    start: a(i as u64),
                    end: a(i as u64),
                    instructions: Vec::new(),
                },
            );
        }
        let mut edges: Vec<CfgEdge> = Vec::new();
        for (f, ts) in succ.iter().enumerate() {
            for &t in ts {
                edges.push(CfgEdge {
                    from: a(f as u64),
                    to: a(t as u64),
                    kind: EdgeKind::Unconditional,
                });
            }
        }
        let tree = DominatorTree::compute(&blocks, &edges, a(entry as u64));

        let live = reachable(n, &succ, entry);
        for &node in &live {
            let mut cfg_df: Vec<u64> = tree
                .dominance_frontier(a(node as u64))
                .iter()
                .map(|addr| addr.as_u64())
                .collect();
            cfg_df.sort_unstable();
            let dataflow_df: Vec<u64> = df_front[node]
                .iter()
                .copied()
                .filter(|y| live.contains(y))
                .map(|y| y as u64)
                .collect();
            assert_eq!(
                cfg_df, dataflow_df,
                "trial {trial}: DF({node}) disagrees — cfg={cfg_df:?} dataflow={dataflow_df:?} (succ={succ:?})"
            );
        }
    }
}

#[test]
fn cfg_dominator_tree_matches_dataflow_compute_dominators() {
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    for trial in 0..1500 {
        let n = 2 + (rng.below(9) as usize); // 2..=10 nodes
        let entry = 0usize;

        // Random edge set; density varies per trial. Self-loops and
        // duplicate edges allowed — both sides must handle them.
        let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
        let edge_count = 1 + (rng.below((2 * n) as u64) as usize);
        for _ in 0..edge_count {
            let f = rng.below(n as u64) as usize;
            let t = rng.below(n as u64) as usize;
            succ[f].push(t);
        }

        // dataflow side (index-based).
        let df_idom = rustre_analysis_dataflow::compute_dominators(n, &succ, entry);

        // cfg side (Address-based).
        let mut blocks: HashMap<Address, BasicBlock> = HashMap::new();
        for i in 0..n {
            blocks.insert(
                a(i as u64),
                BasicBlock {
                    start: a(i as u64),
                    end: a(i as u64),
                    instructions: Vec::new(),
                },
            );
        }
        let mut edges: Vec<CfgEdge> = Vec::new();
        for (f, ts) in succ.iter().enumerate() {
            for &t in ts {
                edges.push(CfgEdge {
                    from: a(f as u64),
                    to: a(t as u64),
                    kind: EdgeKind::Unconditional,
                });
            }
        }
        let tree = DominatorTree::compute(&blocks, &edges, a(entry as u64));

        let live = reachable(n, &succ, entry);
        for &node in &live {
            let cfg_idom = tree.idom.get(&a(node as u64)).copied().flatten();
            if node == entry {
                assert_eq!(
                    cfg_idom, None,
                    "trial {trial}: entry must have no idom in cfg crate (succ={succ:?})"
                );
                assert_eq!(
                    df_idom[node], entry,
                    "trial {trial}: entry idom sentinel mismatch in dataflow crate"
                );
            } else {
                let df = df_idom[node];
                assert_eq!(
                    cfg_idom,
                    Some(a(df as u64)),
                    "trial {trial}: idom({node}) disagrees — cfg={cfg_idom:?} dataflow={df} (succ={succ:?})"
                );
            }
        }
    }
}
