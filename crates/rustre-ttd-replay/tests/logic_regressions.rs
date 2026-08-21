//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.
//!
//! Note: three further defects in this crate already had RED tests of their own
//! in `src/` when this file was written (`backward_stepper::tests::
//! step_back_over_call`, `call_stack::tests::all_stacks_at`,
//! `replay_state_manager::tests::step_forward_advances_position`). Those assert
//! contracts the code violated; they are fixed alongside these and are not
//! duplicated here.

use std::sync::Arc;

use rustre_ttd::{EventKind, TraceEvent, TraceMetadata, TracePosition, TtdTrace};
use rustre_ttd_replay::call_stack::{build_call_tree, CallEvent, CallEventKind};
use rustre_ttd_replay::replay_analysis::{CallChainAnalysis, MemoryPatternAnalysis};
use rustre_ttd_replay::time_travel_queries::TimeTravelQueryEngine;

const fn ev(seq: u64, kind: EventKind) -> TraceEvent {
    TraceEvent::new(TracePosition::new(seq, 0), 1, kind)
}

const fn call_ev(seq: u64, from: u64, to: u64) -> CallEvent {
    CallEvent {
        position: TracePosition::new(seq, 0),
        tid: 1,
        kind: CallEventKind::Call { from, to },
    }
}

// ── deepest_chain never matched anything ───────────────────────────────────

/// Frame depths are 0-based but `max_depth` is a COUNT, so `f.depth ==
/// max_depth` is off by one and can never hold: the deepest chain of any
/// non-empty trace came back empty.
#[test]
fn the_deepest_chain_of_a_single_call_is_that_call() {
    let events = vec![ev(0, EventKind::Call { from: 0x1000, to: 0x2000 })];
    let analysis = CallChainAnalysis::build_from_events(&events);

    assert_eq!(analysis.frames.len(), 1);
    let chain = analysis.deepest_chain();
    assert_eq!(
        chain.len(),
        1,
        "one frame at depth 0 with max_depth 1: the deepest chain is that frame"
    );
    assert_eq!(chain[0].callee, 0x2000);
}

/// With nesting, only the deepest frames are returned.
#[test]
fn the_deepest_chain_picks_the_innermost_frames() {
    let events = vec![
        ev(0, EventKind::Call { from: 0x1000, to: 0x2000 }),
        ev(1, EventKind::Call { from: 0x2000, to: 0x3000 }),
    ];
    let analysis = CallChainAnalysis::build_from_events(&events);
    let chain = analysis.deepest_chain();

    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].callee, 0x3000, "0x3000 is the innermost");
}

/// An empty trace has no chain — the fix must not invent one.
#[test]
fn an_empty_trace_has_no_deepest_chain() {
    let analysis = CallChainAnalysis::build_from_events(&[]);
    assert!(analysis.deepest_chain().is_empty());
}

// ── a strided run reaching the end of the trace was never emitted ──────────

/// The run is only recorded when the stride CHANGES, so a run that continues
/// to the last event — the common case for a loop that walks an array and then
/// the trace stops — is silently dropped.
#[test]
fn a_strided_run_that_reaches_the_end_of_the_trace_is_reported() {
    let events: Vec<TraceEvent> = (0..5)
        .map(|i| {
            ev(
                i,
                EventKind::MemRead {
                    addr: 0x1000 + i * 8,
                    len: 8,
                },
            )
        })
        .collect();

    let analysis = MemoryPatternAnalysis::build_from_events(&events);
    assert_eq!(
        analysis.strided_accesses.len(),
        1,
        "five reads at stride 8 are one strided run"
    );
    let sa = &analysis.strided_accesses[0];
    assert_eq!(sa.stride, 8);
    assert_eq!(
        sa.base, 0x1000,
        "the base is where the run STARTS, not where it ended"
    );
    assert!(!sa.is_write);
}

/// Scattered accesses must not be reported as a stride.
#[test]
fn scattered_accesses_are_not_a_strided_run() {
    let addrs = [0x1000u64, 0x2000, 0x1008, 0x9000];
    let events: Vec<TraceEvent> = addrs
        .iter()
        .enumerate()
        .map(|(i, &a)| ev(i as u64, EventKind::MemRead { addr: a, len: 8 }))
        .collect();

    let analysis = MemoryPatternAnalysis::build_from_events(&events);
    assert!(analysis.strided_accesses.is_empty());
}

// ── build_call_tree attached grandchildren to phantom roots ───────────────

/// The parent is looked up among the ROOTS only, so at depth 2 the lookup
/// fails, a phantom root is created for the parent, and the tree is flattened:
/// B appears both as A's child and as a second root, and C hangs off the
/// phantom.
#[test]
fn a_three_deep_call_chain_is_one_nested_tree() {
    let events = vec![
        call_ev(0, 0x0FF0, 0xA),
        call_ev(1, 0xA, 0xB),
        call_ev(2, 0xB, 0xC),
    ];

    let roots = build_call_tree(&events);
    assert_eq!(
        roots.len(),
        1,
        "there is one root (0xA); got {:?}",
        roots.iter().map(|n| n.address).collect::<Vec<_>>()
    );
    assert_eq!(roots[0].address, 0xA);
    assert_eq!(roots[0].children.len(), 1);
    assert_eq!(roots[0].children[0].address, 0xB);
    assert_eq!(
        roots[0].children[0].children.len(),
        1,
        "0xC is a child of 0xB, not a grandchild of a phantom root"
    );
    assert_eq!(roots[0].children[0].children[0].address, 0xC);
}

/// Siblings and returns must still nest correctly.
#[test]
fn siblings_stay_siblings_after_a_return() {
    let events = vec![
        call_ev(0, 0x0FF0, 0xA),
        call_ev(1, 0xA, 0xB),
        CallEvent {
            position: TracePosition::new(2, 0),
            tid: 1,
            kind: CallEventKind::Return { from: 0xB, to: 0xA },
        },
        call_ev(3, 0xA, 0xC),
    ];

    let roots = build_call_tree(&events);
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].children.len(), 2, "0xB and 0xC are both A's children");
}

// ── find_memory_write compared the whole write to a shorter query ─────────

/// The query asks "was the byte at 0x1000 written 0xAA?". The engine read
/// `max(query_len, write_len)` bytes and compared the FULL stored value to the
/// shorter pattern, so an exact match on a prefix of a wider write never fired.
///
/// The correct containment logic already exists a few functions away, in
/// `find_last_writer_before`.
#[test]
fn a_one_byte_query_matches_a_four_byte_write() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(
        0,
        EventKind::MemWrite {
            addr: 0x1000,
            data: vec![0xAA, 0xBB, 0xCC, 0xDD],
        },
    ));

    let engine = TimeTravelQueryEngine::new(Arc::new(t));
    let result = engine.find_memory_write(0x1000, vec![0xAA]);
    assert_eq!(
        result.matches.len(),
        1,
        "the byte at 0x1000 was written 0xAA"
    );
}

/// A query for the wrong value must still not match.
#[test]
fn a_query_for_the_wrong_byte_does_not_match() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(
        0,
        EventKind::MemWrite {
            addr: 0x1000,
            data: vec![0xAA, 0xBB, 0xCC, 0xDD],
        },
    ));

    let engine = TimeTravelQueryEngine::new(Arc::new(t));
    assert!(engine.find_memory_write(0x1000, vec![0x11]).matches.is_empty());
}

/// A full-width query must keep working exactly as before.
#[test]
fn a_full_width_query_still_matches() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(
        0,
        EventKind::MemWrite {
            addr: 0x1000,
            data: vec![0xAA, 0xBB, 0xCC, 0xDD],
        },
    ));

    let engine = TimeTravelQueryEngine::new(Arc::new(t));
    assert_eq!(
        engine
            .find_memory_write(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD])
            .matches
            .len(),
        1
    );
}
