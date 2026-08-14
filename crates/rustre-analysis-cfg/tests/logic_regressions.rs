//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! Every one of these returned a well-formed, plausible answer that was simply
//! wrong. Where the crate already contains a second, correct implementation of
//! the same quantity, the test asserts that the two AGREE — that cross-check is
//! stronger than any single hand-written expectation, and it is what would have
//! caught these defects in the first place.

use std::collections::HashMap;

use rustre_analysis_cfg::cfg_dominators::DominanceFrontierComputer;
use rustre_analysis_cfg::loop_analysis::{InductionVariable, LoopBoundsInference};
use rustre_analysis_cfg::post_dominator::FullPostDomTree;
use rustre_analysis_cfg::{BasicBlock, CfgEdge, DominatorTree, EdgeKind};
use rustre_core::address::Address;

fn a(n: u64) -> Address {
    Address(n)
}

fn blocks(addrs: &[u64]) -> HashMap<Address, BasicBlock> {
    addrs
        .iter()
        .map(|&n| {
            (
                a(n),
                BasicBlock {
                    start: a(n),
                    end: a(n),
                    instructions: vec![],
                },
            )
        })
        .collect()
}

fn edges(pairs: &[(u64, u64)]) -> Vec<CfgEdge> {
    pairs
        .iter()
        .map(|&(f, t)| CfgEdge {
            from: a(f),
            to: a(t),
            kind: EdgeKind::Unconditional,
        })
        .collect()
}

// ── InductionVariable::trip_count ──────────────────────────────────────────

fn iv(init: i64, bound: i64, step: i64, ascending: bool) -> InductionVariable {
    InductionVariable {
        name: "i".to_string(),
        init: Some(init),
        bound: Some(bound),
        step,
        is_ascending: ascending,
    }
}

/// `for (i = 0; i < 5; i += 2)` runs three times (0, 2, 4). Truncating
/// division reported two: the count is ceil((bound - init) / step).
#[test]
fn trip_count_rounds_up_on_a_partial_final_step() {
    assert_eq!(iv(0, 5, 2, true).trip_count(), Some(3));
    assert_eq!(iv(0, 7, 3, true).trip_count(), Some(3)); // 0, 3, 6
    assert_eq!(iv(0, 1, 4, true).trip_count(), Some(1)); // 0
}

#[test]
fn trip_count_is_exact_when_the_span_divides_evenly() {
    assert_eq!(iv(0, 6, 2, true).trip_count(), Some(3)); // 0, 2, 4
    assert_eq!(iv(0, 10, 1, true).trip_count(), Some(10));
}

#[test]
fn empty_and_degenerate_loops_are_still_zero_or_none() {
    assert_eq!(iv(5, 5, 1, true).trip_count(), Some(0));
    assert_eq!(iv(9, 3, 1, true).trip_count(), Some(0));
    assert_eq!(iv(0, 5, 0, true).trip_count(), None);
}

/// The crate carries two implementations of the same quantity. They must not
/// diverge — that divergence WAS the defect.
#[test]
fn trip_count_agrees_with_loop_bounds_inference() {
    for init in [-7i64, -1, 0, 3] {
        for span in 0i64..12 {
            for step in 1i64..5 {
                let up = iv(init, init + span, step, true);
                assert_eq!(
                    up.trip_count(),
                    LoopBoundsInference::trip_count_for_loop(init, init + span, step),
                    "ascending init={init} bound={} step={step}",
                    init + span
                );

                let down = iv(init, init - span, step, false);
                assert_eq!(
                    down.trip_count(),
                    LoopBoundsInference::trip_count_for_loop(init, init - span, -step),
                    "descending init={init} bound={} step={step}",
                    init - span
                );
            }
        }
    }
}

// ── DominanceFrontier ──────────────────────────────────────────────────────

/// A back edge to the entry puts the entry in its OWN dominance frontier.
/// Mapping the entry's absent idom onto itself stopped the ascent one node
/// early, so DF(entry) came out empty and the phi at the loop header was
/// never placed.
#[test]
fn entry_appears_in_its_own_dominance_frontier() {
    let b = blocks(&[0, 1]);
    let e = edges(&[(0, 1), (1, 0)]);
    let dom = DominatorTree::compute(&b, &e, a(0));
    let df = DominanceFrontierComputer::compute(&dom, &e);

    assert_eq!(df.get(&a(0)).map(Vec::as_slice), Some(&[a(0)][..]));
    assert_eq!(df.get(&a(1)).map(Vec::as_slice), Some(&[a(0)][..]));
}

/// A branch with no loop: the merge point is the frontier of both arms, and
/// the entry's frontier is empty.
#[test]
fn diamond_dominance_frontier_is_the_merge_point() {
    let b = blocks(&[0, 1, 2, 3]);
    let e = edges(&[(0, 1), (0, 2), (1, 3), (2, 3)]);
    let dom = DominatorTree::compute(&b, &e, a(0));
    let df = DominanceFrontierComputer::compute(&dom, &e);

    assert_eq!(df.get(&a(1)).map(Vec::as_slice), Some(&[a(3)][..]));
    assert_eq!(df.get(&a(2)).map(Vec::as_slice), Some(&[a(3)][..]));
    assert!(df.get(&a(0)).is_none_or(Vec::is_empty));
}

// ── control dependence ─────────────────────────────────────────────────────

/// A node executed BEFORE the branch cannot depend on it. Ignoring `pred`'s
/// successors let every node that merely failed to post-dominate `pred` into
/// the result — including its own predecessor.
#[test]
fn predecessors_are_not_control_dependent_on_a_later_branch() {
    // E → A, A → B, A → C, B → D, C → D.
    let all = [4u64, 0, 1, 2, 3]; // E=4, A=0, B=1, C=2, D=3
    let b = blocks(&all);
    let e = edges(&[(4, 0), (0, 1), (0, 2), (1, 3), (2, 3)]);
    let pdt = FullPostDomTree::compute(&b, &e, &[a(3)]);

    let deps = pdt.control_dependent_on(a(0), &e);
    assert!(deps.contains(&a(1)), "B depends on the branch at A");
    assert!(deps.contains(&a(2)), "C depends on the branch at A");
    assert!(
        !deps.contains(&a(4)),
        "E runs before A and cannot depend on it, got {deps:?}"
    );
    assert!(!deps.contains(&a(3)), "D is the merge point, got {deps:?}");
}

/// A straight chain has no branch, so nothing is control-dependent.
#[test]
fn a_chain_has_no_control_dependences() {
    let b = blocks(&[0, 1, 2]);
    let e = edges(&[(0, 1), (1, 2)]);
    let pdt = FullPostDomTree::compute(&b, &e, &[a(2)]);
    assert!(pdt.control_dependent_on(a(0), &e).is_empty());
}

/// A node with no outgoing edges depends on nothing.
#[test]
fn an_exit_node_has_no_control_dependences() {
    let b = blocks(&[0, 1, 2, 3]);
    let e = edges(&[(0, 1), (0, 2), (1, 3), (2, 3)]);
    let pdt = FullPostDomTree::compute(&b, &e, &[a(3)]);
    assert!(pdt.control_dependent_on(a(3), &e).is_empty());
}
