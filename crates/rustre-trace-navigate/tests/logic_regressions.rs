//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.

use rustre_trace_navigate::trace_slice_extractor::{
    SliceCriterion, SliceDirection, TraceSliceExtractor,
};
use rustre_trace_navigate::{EntryKind, ExecutionTrace, TraceEntry};

fn entry(idx: usize, pc: u64, kind: EntryKind) -> TraceEntry {
    TraceEntry {
        idx,
        pc,
        tid: 1,
        reg_snapshot: Vec::new(),
        mem_writes: Vec::new(),
        mem_reads: Vec::new(),
        tsc: None,
        kind,
        disasm: String::new(),
    }
}

// ── backward slicing produced no memory dependencies ──────────────────────

/// A write at index 0 and a read of the SAME address at index 2. Slicing
/// backward from the read must reach the write: that edge is the whole point
/// of "which instruction produced this value".
#[test]
fn a_read_depends_on_the_write_that_produced_it() {
    let mut w = entry(0, 0x1000, EntryKind::Insn);
    w.mem_writes.push((0x2000, vec![1]));

    let middle = entry(1, 0x1004, EntryKind::Insn);

    let mut r = entry(2, 0x1008, EntryKind::Insn);
    r.mem_reads.push((0x2000, 8));

    let trace = ExecutionTrace::new(vec![w, middle, r], "t");
    let graph = TraceSliceExtractor::new().extract(
        &trace,
        &SliceCriterion::TraceIndex { idx: 2 },
        SliceDirection::Backward,
    );

    assert!(
        graph.edge_count() >= 1,
        "the read at index 2 depends on the write at index 0, but the slice has \
         {} nodes and {} edges",
        graph.node_count(),
        graph.edge_count()
    );
    assert!(
        graph.ancestors(2).contains(&0),
        "index 0 must be an ancestor of index 2; got {:?}",
        graph.ancestors(2)
    );
}

/// A read of an address nobody wrote has no memory ancestor — the fix must not
/// invent edges.
#[test]
fn a_read_of_an_unwritten_address_has_no_ancestor() {
    let mut r = entry(0, 0x1000, EntryKind::Insn);
    r.mem_reads.push((0x9999, 8));

    let trace = ExecutionTrace::new(vec![r], "t");
    let graph = TraceSliceExtractor::new().extract(
        &trace,
        &SliceCriterion::TraceIndex { idx: 0 },
        SliceDirection::Backward,
    );
    assert!(graph.ancestors(0).is_empty());
}

/// Only the MOST RECENT write before the read is the producer; an earlier write
/// to the same address was overwritten.
#[test]
fn the_producer_is_the_most_recent_preceding_write() {
    let mut old = entry(0, 0x1000, EntryKind::Insn);
    old.mem_writes.push((0x2000, vec![0xAA]));

    let mut new = entry(1, 0x1004, EntryKind::Insn);
    new.mem_writes.push((0x2000, vec![0xBB]));

    let mut r = entry(2, 0x1008, EntryKind::Insn);
    r.mem_reads.push((0x2000, 8));

    let trace = ExecutionTrace::new(vec![old, new, r], "t");
    let graph = TraceSliceExtractor::new().extract(
        &trace,
        &SliceCriterion::TraceIndex { idx: 2 },
        SliceDirection::Backward,
    );

    let anc = graph.ancestors(2);
    assert!(anc.contains(&1), "index 1 is the producing write; got {anc:?}");
}

// ── find_caller returned frames that had already been popped ──────────────

use rustre_trace_navigate::backward_nav::BackwardNavigator;

/// ```text
///   0: call  pc=0x3000 -> 0x1000, ret 0x3005
///   1: insn  pc=0x1000
///   2: call  pc=0x1001 -> 0x0400, ret 0x1006
///   3: insn  pc=0x0400
///   4: ret   pc=0x0401 -> 0x1006      <-- frame from index 2 is popped here
///   5: insn  pc=0x1006
/// ```
/// At index 5 the only live frame is the one opened at index 0. The call at
/// index 2 was closed by the return at index 4.
fn nested_calls() -> ExecutionTrace {
    ExecutionTrace::new(
        vec![
            entry(
                0,
                0x3000,
                EntryKind::Call {
                    target: 0x1000,
                    ret_addr: 0x3005,
                },
            ),
            entry(1, 0x1000, EntryKind::Insn),
            entry(
                2,
                0x1001,
                EntryKind::Call {
                    target: 0x0400,
                    ret_addr: 0x1006,
                },
            ),
            entry(3, 0x0400, EntryKind::Insn),
            entry(4, 0x0401, EntryKind::Ret { target: 0x1006 }),
            entry(5, 0x1006, EntryKind::Insn),
        ],
        "t",
    )
}

/// `find_caller` walks backward for a `Call` whose target is at or below the
/// current pc and stops at the FIRST one, without ever counting the returns it
/// passes. It therefore hands back frames that have already been popped: at
/// index 5 it reports the call to 0x0400, which the return at index 4 closed.
///
/// The same shape was already fixed in `rustre-ttd-replay`'s backward stepper:
/// a return seen while walking backward means one more call to skip.
#[test]
fn find_caller_skips_frames_that_already_returned() {
    let nav = BackwardNavigator::new(nested_calls());
    let (_, frame) = nav.find_caller(5).expect("index 5 is inside a function");

    assert_eq!(
        frame.fn_addr, 0x1000,
        "the live frame at index 5 is the one entered at index 0; the call to \
         {:#x} was popped by the return at index 4",
        frame.fn_addr
    );
    assert_eq!(frame.ret_addr, 0x3005);
}

/// Inside the inner function the inner frame IS the live one.
#[test]
fn find_caller_returns_the_inner_frame_while_it_is_live() {
    let nav = BackwardNavigator::new(nested_calls());
    let (_, frame) = nav.find_caller(3).expect("index 3 is inside 0x0400");

    assert_eq!(frame.fn_addr, 0x0400, "index 3 runs inside the inner call");
    assert_eq!(frame.ret_addr, 0x1006);
}

// ── undo restored the cursor to where the search LANDED ───────────────────

use rustre_trace_navigate::time_travel_search::TimeTravelSearch;

/// A trace whose index 3 is the only "push".
fn searchable() -> ExecutionTrace {
    let mut v = Vec::new();
    for i in 0..4usize {
        let mut e = entry(i, 0x1000 + i as u64 * 4, EntryKind::Insn);
        e.disasm = if i == 3 { "push rbp".into() } else { "nop".into() };
        v.push(e);
    }
    ExecutionTrace::new(v, "t")
}

/// `undo` pops the last search result and sets the cursor to THAT RESULT'S
/// index — i.e. where the search landed, not where the cursor was before it.
/// Undoing a search that moved the cursor from 0 to 3 therefore leaves it at 3
/// and reports `Some(3)`: it undoes nothing at all.
///
/// The existing `tts_history_and_undo` test never looks at the cursor, only at
/// `history.len()`, so it passes either way.
#[test]
fn undo_restores_the_position_from_before_the_search() {
    let trace = searchable();
    let mut tts = TimeTravelSearch::new(&trace);

    tts.find_pc(0x1000).expect("index 0");
    let before = tts.cursor;

    tts.find_disasm("push").expect("index 3");
    assert_eq!(tts.cursor, 3, "the search moved the cursor to the match");

    let restored = tts.undo();
    assert_eq!(
        tts.cursor, before,
        "undo must put the cursor back where it was before the search"
    );
    assert_eq!(restored, Some(before));
}

/// Undoing with nothing left to undo must not move the cursor.
#[test]
fn undo_on_an_empty_history_does_nothing() {
    let trace = searchable();
    let mut tts = TimeTravelSearch::new(&trace);
    tts.cursor = 2;
    assert_eq!(tts.undo(), None);
    assert_eq!(tts.cursor, 2);
}
