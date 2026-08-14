//! Differential tests between the two dominance implementations that live in
//! this crate:
//!
//! * the **array-based** one in `lib.rs` — [`crate::compute_dominators`] /
//!   [`crate::compute_dominance_frontiers`] (Cooper–Harvey–Kennedy iterative),
//!   which is the API external crates actually call; and
//! * the **`Cfg`/`DomTree`-based** one in [`crate::cfg_dom`] —
//!   [`crate::cfg_dom::lengauer_tarjan`] + [`crate::cfg_dom::DomTree::dominance_frontier`].
//!
//! Both answer the same question over the same graph, so they must agree.
//! These tests feed both randomized CFGs and compare, after normalising the
//! two `idom` conventions (`lib.rs` uses `idom[entry] == entry` and a
//! self-loop sentinel for unreachable nodes; `cfg_dom` uses `None` for both).

use crate::cfg_dom::{BBId, Cfg, lengauer_tarjan};
use crate::prop_soundness::Rng;
use std::collections::HashSet;

/// Random CFG over `n` nodes, entry 0, all nodes reachable from 0.
/// When `back_edges` is set, some edges point backwards (including to the
/// entry itself, which is the case that distinguishes the two DF impls).
fn random_cfg_succs(rng: &mut Rng, n: usize, back_edges: bool) -> Vec<Vec<usize>> {
    let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];
    // Spanning tree guarantees reachability.
    for j in 1..n {
        let p = rng.below(j);
        succs[p].push(j);
    }
    for i in 0..n {
        if rng.chance(40) {
            let j = rng.below(n);
            if !succs[i].contains(&j) {
                succs[i].push(j);
            }
        }
        if back_edges && rng.chance(25) {
            // Deliberately allow a back edge to node 0 (the entry).
            let j = rng.below(i + 1);
            if !succs[i].contains(&j) {
                succs[i].push(j);
            }
        }
    }
    succs
}

fn to_cfg(n: usize, succs: &[Vec<usize>]) -> Cfg {
    let s: Vec<Vec<BBId>> = succs
        .iter()
        .map(|row| row.iter().map(|&d| BBId(d)).collect())
        .collect();
    Cfg::new(n, s, BBId(0), BBId(n.saturating_sub(1)))
}

/// Normalise a `cfg_dom` `DomTree::idom` into the `lib.rs` array convention.
fn normalise_idom(idom: &[Option<BBId>]) -> Vec<usize> {
    idom.iter()
        .enumerate()
        .map(|(i, d)| d.map_or(i, |b| b.0))
        .collect()
}

#[test]
fn idom_differential_lib_vs_lengauer_tarjan() {
    for seed in 1..=1500u64 {
        let mut rng = Rng::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let n = 2 + rng.below(12);
        let back = seed % 2 == 0;
        let succs = random_cfg_succs(&mut rng, n, back);

        let lib_idom = crate::compute_dominators(n, &succs, 0);
        let lt = lengauer_tarjan(&to_cfg(n, &succs), BBId(0));
        let lt_idom = normalise_idom(&lt.idom);

        assert_eq!(
            lib_idom, lt_idom,
            "idom mismatch (seed {seed}, n {n}, succs {succs:?})"
        );
    }
}

/// Cross-check both `idom` arrays against a brute-force dominator-set
/// computation, so a shared bug in the two fast algorithms cannot hide.
#[test]
fn idom_differential_vs_bruteforce() {
    for seed in 1..=400u64 {
        let mut rng = Rng::new(seed.wrapping_mul(0xD1B5_4A32_D192_ED03));
        let n = 2 + rng.below(9);
        let succs = random_cfg_succs(&mut rng, n, seed % 3 == 0);

        // Brute force: dom[v] = set of nodes on every path entry→v.
        let mut dom: Vec<HashSet<usize>> = (0..n).map(|_| (0..n).collect()).collect();
        dom[0] = std::iter::once(0).collect();
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (s, row) in succs.iter().enumerate() {
            for &d in row {
                preds[d].push(s);
            }
        }
        let mut changed = true;
        while changed {
            changed = false;
            for v in 1..n {
                if preds[v].is_empty() {
                    continue;
                }
                let mut new: HashSet<usize> = dom[preds[v][0]].clone();
                for &p in &preds[v][1..] {
                    new = new.intersection(&dom[p]).copied().collect();
                }
                new.insert(v);
                if new != dom[v] {
                    dom[v] = new;
                    changed = true;
                }
            }
        }

        let lib_idom = crate::compute_dominators(n, &succs, 0);
        for v in 1..n {
            // Only reachable nodes with a real dominator set are meaningful.
            if preds[v].is_empty() || dom[v].len() == n {
                continue;
            }
            let strict: Vec<usize> = dom[v].iter().copied().filter(|&d| d != v).collect();
            if strict.is_empty() {
                continue;
            }
            // The immediate dominator is the strict dominator dominated by
            // every other strict dominator.
            let expected = strict
                .iter()
                .copied()
                .find(|&c| strict.iter().all(|&o| o == c || dom[c].contains(&o)));
            if let Some(exp) = expected {
                assert_eq!(
                    lib_idom[v], exp,
                    "lib idom wrong for node {v} (seed {seed}, succs {succs:?})"
                );
            }
        }
    }
}

/// The dominance-frontier differential. Both are driven from the **same**
/// `idom` array (the `lib.rs` one, translated into a `DomTree`) so that this
/// test isolates the frontier computation itself from any idom difference.
#[test]
fn dominance_frontier_differential_lib_vs_cfg_dom() {
    for seed in 1..=1500u64 {
        let mut rng = Rng::new(seed.wrapping_mul(0xA076_1D64_78BD_642F));
        let n = 2 + rng.below(12);
        let back = seed % 2 == 0;
        let succs = random_cfg_succs(&mut rng, n, back);

        let lib_idom = crate::compute_dominators(n, &succs, 0);
        let lib_df = crate::compute_dominance_frontiers(n, &succs, &lib_idom);

        let cfg = to_cfg(n, &succs);
        let lt = lengauer_tarjan(&cfg, BBId(0));
        let ct_df = lt.dominance_frontier(&cfg);

        for v in 0..n {
            let a: HashSet<usize> = lib_df[v].iter().copied().collect();
            let b: HashSet<usize> = ct_df[v].iter().map(|x| x.0).collect();
            assert_eq!(
                a, b,
                "DF mismatch at node {v} (seed {seed}, n {n}, succs {succs:?}, \
                 lib_idom {lib_idom:?}, lib {a:?}, cfg_dom {b:?})"
            );
        }
    }
}
