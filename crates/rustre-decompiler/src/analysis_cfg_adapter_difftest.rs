//! DIFFERENTIAL PROOF for `analysis_cfg_adapter`.
//!
//! The decompiler-private block graph (the `Vec<MlilBasicBlock>` that
//! `build_mlil_cfg` produces, whose `predecessors`/`successors` are
//! index-space adjacency computed by the decompiler itself) must agree with
//! the `rustre-analysis-cfg` graph the adapter builds from it, on:
//!   * block set (start addresses)
//!   * entry
//!   * edge set
//!   * per-block predecessors and successors
//!   * immediate dominators
//!
//! Immediate dominators are cross-checked against an INDEPENDENT naive
//! iterative set-based dominator computation over the private graph's own
//! index-space edges — a different algorithm (full dominator sets) from the
//! Cooper/Harvey/Kennedy RPO algorithm inside `rustre-analysis-cfg`.

use super::to_analysis_cfg;
use rustre_core::address::Address;
use rustre_il_mlil::MlilBasicBlock;
use std::collections::{BTreeSet, HashSet};

fn mk(n: usize, succs: &[Vec<u32>]) -> Vec<MlilBasicBlock> {
    let mut preds: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (i, s) in succs.iter().enumerate() {
        for &t in s {
            preds[t as usize].push(i as u32);
        }
    }
    (0..n)
        .map(|i| MlilBasicBlock {
            id: i as u32,
            start: Address::new(0x1000 + (i as u64) * 0x10),
            end: Address::new(0x1000 + (i as u64) * 0x10 + 8),
            instrs: Vec::new(),
            predecessors: preds[i].clone(),
            successors: succs[i].clone(),
        })
        .collect()
}

/// Independent reference: full dominator SETS iterated to a fixpoint, then
/// idom = the strict dominator dominated by every other strict dominator.
/// Index space. `None` marks an unreachable node.
fn naive_idom(n: usize, succs: &[Vec<u32>]) -> Vec<Option<Option<usize>>> {
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, s) in succs.iter().enumerate() {
        for &t in s {
            preds[t as usize].push(i);
        }
    }
    let mut reach = vec![false; n];
    let mut stack = vec![0usize];
    if n > 0 {
        reach[0] = true;
    }
    while let Some(x) = stack.pop() {
        for &t in &succs[x] {
            if !reach[t as usize] {
                reach[t as usize] = true;
                stack.push(t as usize);
            }
        }
    }
    let all: BTreeSet<usize> = (0..n).filter(|&i| reach[i]).collect();
    let mut dom: Vec<BTreeSet<usize>> =
        (0..n).map(|i| if i == 0 { BTreeSet::from([0]) } else { all.clone() }).collect();
    loop {
        let mut changed = false;
        for i in 1..n {
            if !reach[i] {
                continue;
            }
            let mut acc: Option<BTreeSet<usize>> = None;
            for &p in preds[i].iter().filter(|&&p| reach[p]) {
                acc = Some(match acc {
                    None => dom[p].clone(),
                    Some(a) => a.intersection(&dom[p]).copied().collect(),
                });
            }
            let mut new = acc.unwrap_or_default();
            new.insert(i);
            if new != dom[i] {
                dom[i] = new;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    (0..n)
        .map(|i| {
            if !reach[i] {
                return None;
            }
            if i == 0 {
                return Some(None);
            }
            let strict: Vec<usize> = dom[i].iter().copied().filter(|&d| d != i).collect();
            Some(strict.iter().copied().find(|&c| strict.iter().all(|&o| o == c || dom[c].contains(&o))))
        })
        .collect()
}

fn check(n: usize, succs: &[Vec<u32>]) {
    let priv_blocks = mk(n, succs);
    let cfg = to_analysis_cfg(&priv_blocks).expect("non-empty");

    // 1. block set
    let a: BTreeSet<u64> = priv_blocks.iter().map(|b| b.start.0).collect();
    let b: BTreeSet<u64> = cfg.blocks.keys().map(|k| k.0).collect();
    assert_eq!(a, b, "block sets differ");

    // 2. entry
    assert_eq!(cfg.entry, priv_blocks[0].start, "entry differs");

    // 3. edge set
    let mut ea: BTreeSet<(u64, u64)> = BTreeSet::new();
    for blk in &priv_blocks {
        for &s in &blk.successors {
            ea.insert((blk.start.0, priv_blocks[s as usize].start.0));
        }
    }
    let eb: BTreeSet<(u64, u64)> = cfg.edges.iter().map(|e| (e.from.0, e.to.0)).collect();
    assert_eq!(ea, eb, "edge sets differ");

    // 4. per-block preds/succs
    for blk in &priv_blocks {
        let ps: BTreeSet<u64> =
            blk.predecessors.iter().map(|&p| priv_blocks[p as usize].start.0).collect();
        let qs: BTreeSet<u64> = cfg.predecessors(blk.start).iter().map(|x| x.0).collect();
        assert_eq!(ps, qs, "predecessors differ for block {}", blk.id);
        let ss: BTreeSet<u64> =
            blk.successors.iter().map(|&s| priv_blocks[s as usize].start.0).collect();
        let ts: BTreeSet<u64> = cfg.successors(blk.start).iter().map(|x| x.0).collect();
        assert_eq!(ss, ts, "successors differ for block {}", blk.id);
    }

    // 5. immediate dominators vs the independent implementation
    for (i, r) in naive_idom(n, succs).iter().enumerate() {
        let addr = priv_blocks[i].start;
        match r {
            None => assert!(
                cfg.immediate_dominator(addr).is_none(),
                "block {i} is unreachable but analysis-cfg reported an idom (succs={succs:?})"
            ),
            Some(expect) => {
                let got = cfg.immediate_dominator(addr).map(|x| x.0);
                let want = expect.map(|j| priv_blocks[j].start.0);
                assert_eq!(got, want, "idom differs for block {i} (succs={succs:?})");
            }
        }
    }
}

#[test]
fn agrees_on_hand_shaped_cfgs() {
    check(1, &[vec![]]);
    check(3, &[vec![1], vec![2], vec![]]); // straight line
    check(4, &[vec![1, 2], vec![3], vec![3], vec![]]); // diamond
    check(3, &[vec![1], vec![1, 2], vec![]]); // self loop
    check(5, &[vec![1], vec![2], vec![3, 4], vec![1], vec![]]); // nested loop
    check(4, &[vec![1, 2], vec![3], vec![3], vec![1]]); // irreducible
    check(4, &[vec![1], vec![], vec![3], vec![]]); // unreachable blocks
}

#[test]
fn agrees_on_random_block_graphs() {
    // xorshift64 — deterministic, no dev-dependency needed.
    let mut s: u64 = 0x2026_0719_CFD1_FF01;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    for _ in 0..3000 {
        let n = 1 + (next() % 12) as usize;
        let succs: Vec<Vec<u32>> = (0..n)
            .map(|_| {
                let k = (next() % 3) as usize; // 0, 1 or 2 successors
                let mut v: Vec<u32> = Vec::new();
                let mut seen = HashSet::new();
                for _ in 0..k {
                    let t = (next() % n as u64) as u32;
                    if seen.insert(t) {
                        v.push(t);
                    }
                }
                v
            })
            .collect();
        check(n, &succs);
    }
}
