//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.
//!
//! Four of the five share one root cause: a time-travel trace interleaves ALL
//! threads into a single event stream, and this crate walked it with a single
//! global call stack. Every per-thread quantity derived from it — call/return
//! pairing, call depth, recursion — was therefore a property of the
//! interleaving rather than of the program.

use std::sync::Arc;

use rustre_ttd::{EventKind, TraceEvent, TraceMetadata, TracePosition, TtdTrace};
use rustre_ttd_query::memory_timeline::MemoryTimeline;
use rustre_ttd_query::ttd_call_query::{CallQuery, TtdCallQuery};
use rustre_ttd_query::QueryEngine;

fn trace(events: Vec<(u64, u32, EventKind)>) -> TtdTrace {
    let t = TtdTrace::new(TraceMetadata::default());
    for (seq, tid, kind) in events {
        t.add_event(TraceEvent::new(TracePosition::new(seq, 0), tid, kind));
    }
    t
}

const fn call(from: u64, to: u64) -> EventKind {
    EventKind::Call { from, to }
}

// ── call/return pairing crossed thread boundaries ──────────────────────────

/// The pairing used ONE stack for the whole trace, so a return on thread 1
/// popped whatever call happened to be on top — which may well belong to
/// thread 2. Here thread 1's call to 0xA is left forever unpaired (no
/// duration) while thread 2's unrelated call to 0xB is credited with thread
/// 1's return.
#[test]
fn a_return_pairs_with_a_call_on_its_own_thread() {
    let t = trace(vec![
        (0, 1, call(0x1000, 0xA)),
        (1, 2, call(0x2000, 0xB)),
        (
            2,
            1,
            EventKind::Return {
                from: 0xA,
                to: 0x1005,
            },
        ),
    ]);

    let q = TtdCallQuery::new(t);
    let records = q.execute(&CallQuery::all());

    let a = records
        .iter()
        .find(|r| r.callee_address == 0xA)
        .expect("call to 0xA recorded");
    let b = records
        .iter()
        .find(|r| r.callee_address == 0xB)
        .expect("call to 0xB recorded");

    assert_eq!(
        a.return_sequence,
        Some(2),
        "the return on thread 1 belongs to thread 1's call"
    );
    assert_eq!(
        b.return_sequence, None,
        "thread 2 never returned; it must not inherit thread 1's return"
    );
}

/// Call depth is per thread. The first frame on a freshly scheduled thread is
/// at depth 0 no matter how deep another thread happens to be.
#[test]
fn call_depth_is_counted_per_thread() {
    let t = trace(vec![
        (0, 1, call(0x1000, 0xA)),
        (1, 2, call(0x2000, 0xB)),
    ]);

    let q = TtdCallQuery::new(t);
    let records = q.execute(&CallQuery::all());
    let b = records.iter().find(|r| r.callee_address == 0xB).unwrap();

    assert_eq!(
        b.call_depth, 0,
        "0xB is the first frame on thread 2, whatever thread 1 is doing"
    );
}

/// Ordinary single-threaded nesting must still be paired and measured.
#[test]
fn single_threaded_nesting_still_pairs_correctly() {
    let t = trace(vec![
        (0, 1, call(0x1000, 0xA)),
        (1, 1, call(0x1100, 0xB)),
        (
            2,
            1,
            EventKind::Return {
                from: 0xB,
                to: 0x1105,
            },
        ),
        (
            3,
            1,
            EventKind::Return {
                from: 0xA,
                to: 0x1005,
            },
        ),
    ]);

    let q = TtdCallQuery::new(t);
    let records = q.execute(&CallQuery::all());
    let a = records.iter().find(|r| r.callee_address == 0xA).unwrap();
    let b = records.iter().find(|r| r.callee_address == 0xB).unwrap();

    assert_eq!(a.call_depth, 0);
    assert_eq!(b.call_depth, 1);
    assert_eq!(a.return_sequence, Some(3));
    assert_eq!(b.return_sequence, Some(2));
}

// ── CallRecord::position truncated the sequence away ───────────────────────

/// `position` was filled with `event.position.as_u128() as u64`. `as_u128`
/// packs the sequence in the HIGH 64 bits, so the `as u64` cast keeps only the
/// step: every record of a trace whose steps are 0 — which is every trace this
/// crate builds — reported position 0.
#[test]
fn the_record_position_keeps_the_sequence() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(TraceEvent::new(
        TracePosition::new(5, 3),
        1,
        call(0x1000, 0xA),
    ));

    let q = TtdCallQuery::new(t);
    let records = q.execute(&CallQuery::all());
    assert_eq!(records.len(), 1);
    assert_ne!(
        records[0].position, 3,
        "position 3 is the STEP; the sequence 5 was cast away"
    );
    assert_ne!(records[0].position, 0);
}

/// Two records at different sequences must not collapse onto the same
/// position — that is what made the field useless as an ordering key.
#[test]
fn distinct_sequences_yield_distinct_positions() {
    let t = trace(vec![
        (7, 1, call(0x1000, 0xA)),
        (9, 1, call(0x1000, 0xB)),
    ]);

    let q = TtdCallQuery::new(t);
    let records = q.execute(&CallQuery::all());
    let a = records.iter().find(|r| r.callee_address == 0xA).unwrap();
    let b = records.iter().find(|r| r.callee_address == 0xB).unwrap();
    assert_ne!(a.position, b.position);
    assert!(a.position < b.position, "position must order like the trace");
}

// ── find_recursive_calls: cross-thread false positives, wrong depth ────────

/// Two threads each calling 0xA once is not recursion — neither of them called
/// itself. The single global stack made it look like one.
#[test]
fn two_threads_calling_the_same_function_is_not_recursion() {
    let t = trace(vec![
        (0, 1, call(0x1000, 0xA)),
        (1, 2, call(0x2000, 0xA)),
    ]);

    let engine = QueryEngine::new(Arc::new(t));
    let chains = engine.find_recursive_calls();
    assert!(
        chains.is_empty(),
        "neither thread recursed; got {chains:?}"
    );
}

/// Recursion depth is how many activations of the function are on the stack,
/// not the distance to the nearest one — which is always 1 for direct
/// recursion, so the reported depth never grew past 1.
#[test]
fn recursion_depth_counts_the_activations_on_the_stack() {
    let t = trace(vec![
        (0, 1, call(0x1000, 0xA)),
        (1, 1, call(0xA, 0xA)),
        (2, 1, call(0xA, 0xA)),
    ]);

    let engine = QueryEngine::new(Arc::new(t));
    let chains = engine.find_recursive_calls();
    assert_eq!(chains.len(), 1);
    assert_eq!(
        chains[0].max_depth, 3,
        "the third call finds [A, A] already on the stack"
    );
}

/// Genuine single-thread recursion must still be found.
#[test]
fn direct_recursion_is_still_detected() {
    let t = trace(vec![(0, 1, call(0x1000, 0xA)), (1, 1, call(0xA, 0xA))]);
    let engine = QueryEngine::new(Arc::new(t));
    assert_eq!(engine.find_recursive_calls().len(), 1);
}

// ── memory ranges were treated as points ───────────────────────────────────

/// An access covers `[addr, addr + size)`, not just `addr`. A 16-byte write
/// starting at 0x0FF8 covers 8 bytes of `[0x1000, 0x1010)`, yet the query
/// indexed only the start address and reported nothing at all.
///
/// The correct predicate already exists on the event —
/// `MemoryAccessEvent::overlaps_range` — and was simply not used.
#[test]
fn an_access_straddling_the_range_start_is_found() {
    let t = trace(vec![(
        0,
        1,
        EventKind::MemWrite {
            addr: 0x0FF8,
            data: vec![0u8; 16],
        },
    )]);

    let tl = MemoryTimeline::build(&t);
    assert_eq!(
        tl.accesses_in_range(0x1000, 0x1010).len(),
        1,
        "the write covers 0x1000..0x1008, which is inside the range"
    );

    let heat = tl.build_heatmap(0x1000, 0x1010, 8).expect("heatmap");
    assert!(
        heat.iter().any(|c| c.read_count + c.write_count > 0),
        "the same write left the heatmap completely cold"
    );
}

/// An access entirely outside the range must still be excluded.
#[test]
fn an_access_outside_the_range_is_still_excluded() {
    let t = trace(vec![(
        0,
        1,
        EventKind::MemWrite {
            addr: 0x0F00,
            data: vec![0u8; 8],
        },
    )]);
    let tl = MemoryTimeline::build(&t);
    assert!(tl.accesses_in_range(0x1000, 0x1010).is_empty());
}

/// Two threads writing OVERLAPPING but not identical addresses is a data race.
/// Comparing start addresses only made it invisible.
#[test]
fn overlapping_writes_from_two_threads_are_a_cross_thread_access() {
    let t = trace(vec![
        (
            0,
            1,
            EventKind::MemWrite {
                addr: 0x1000,
                data: vec![0u8; 8],
            },
        ),
        (
            1,
            2,
            EventKind::MemWrite {
                addr: 0x1004,
                data: vec![0u8; 4],
            },
        ),
    ]);

    let tl = MemoryTimeline::build(&t);
    assert!(
        !tl.detect_cross_thread_accesses().is_empty(),
        "bytes 0x1004..0x1008 are written by both threads"
    );
}

/// Disjoint writes from two threads are not a cross-thread access.
#[test]
fn disjoint_writes_from_two_threads_are_not_flagged() {
    let t = trace(vec![
        (
            0,
            1,
            EventKind::MemWrite {
                addr: 0x1000,
                data: vec![0u8; 4],
            },
        ),
        (
            1,
            2,
            EventKind::MemWrite {
                addr: 0x2000,
                data: vec![0u8; 4],
            },
        ),
    ]);
    let tl = MemoryTimeline::build(&t);
    assert!(tl.detect_cross_thread_accesses().is_empty());
}

// ── max_depth_on disagreed with compute_max_depths ─────────────────────────

use rustre_ttd_query::ttd_call_stack_query::TtdCallStackQuery;
use rustre_ttd_query::ttd_memory_query::MemoryPosition;

const fn mp(seq: u64) -> MemoryPosition {
    MemoryPosition::new(seq, 0)
}

/// A return unwinds every frame up to the one whose return address matches —
/// which is exactly what `ThreadCallState::pop` (and therefore
/// `compute_max_depths`) does. The incremental tally decremented by ONE per
/// return, so after a multi-frame unwind the running depth stayed permanently
/// too high and the reported peak was inflated.
///
/// Two functions answering the same question must not give two answers.
#[test]
fn the_incremental_depth_agrees_with_the_recomputed_one() {
    let mut q = TtdCallStackQuery::new();
    q.record_call(mp(1), 0x10, 0xA, 0x100, 1);
    q.record_call(mp(2), 0x20, 0xB, 0x200, 1);
    // Returning to 0x100 unwinds BOTH frames: real depth is now 0.
    q.record_return(mp(3), 0xB, 0x100, 1);
    q.record_call(mp(4), 0x30, 0xC, 0x300, 1);
    q.record_call(mp(5), 0x40, 0xD, 0x400, 1);

    let recomputed = q.compute_max_depths().get(&1).copied().unwrap_or(0);
    assert_eq!(
        q.max_depth_on(1),
        recomputed,
        "the incremental tally and the full recomputation must agree"
    );
    assert_eq!(recomputed, 2, "the deepest the stack ever got is 2");
}
