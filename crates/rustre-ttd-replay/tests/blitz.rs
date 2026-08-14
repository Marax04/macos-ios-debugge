//! Exhaustive test suite for `rustre-ttd-replay` (lib.rs public API).

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;

use rustre_ttd::{
    EventKind, TraceEvent, TraceMetadata, TracePosition, TtdTrace, build_test_trace,
};
use rustre_ttd_replay::{
    BreakpointCondition, DeltaCompressor, MemDiff, MemPage, MemoryDelta, MemoryState,
    ReplayBreakpoint, ReplayCheckpoint, ReplayEngine, ReplayError, ReplayState, ReplayStopReason,
    Snapshot, SnapshotCache, TtdRecordingFile, WatchAddress, Watchpoint, WatchpointKind,
    WatchpointSet,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

const fn evt(seq: u64, tid: u32, kind: EventKind) -> TraceEvent {
    TraceEvent::new(TracePosition::new(seq, 0), tid, kind)
}

fn trace_from(events: Vec<TraceEvent>) -> Arc<TtdTrace> {
    let meta = TraceMetadata { thread_ids: vec![1, 2], ..TraceMetadata::default() };
    let t = Arc::new(TtdTrace::new(meta));
    for e in events {
        t.add_event(e);
    }
    t
}

// ─── MemoryState ─────────────────────────────────────────────────────────────

#[test]
fn memstate_new_is_empty() {
    let m = MemoryState::new();
    assert_eq!(m.page_count(), 0);
    assert_eq!(m.read(0, 0), Some(vec![]));
    assert_eq!(m.read(0x1000, 1), None);
}

#[test]
fn memstate_apply_write_empty_noop() {
    let mut m = MemoryState::new();
    m.apply_write(0x1000, &[]);
    assert_eq!(m.page_count(), 0);
}

#[test]
fn memstate_apply_write_and_read_within_page() {
    let mut m = MemoryState::new();
    m.apply_write(0x1000, &[1, 2, 3, 4]);
    assert_eq!(m.page_count(), 1);
    assert_eq!(m.read(0x1000, 4), Some(vec![1, 2, 3, 4]));
    assert_eq!(m.read(0x1001, 2), Some(vec![2, 3]));
}

#[test]
fn memstate_read_zero_len_unmapped_ok() {
    let m = MemoryState::new();
    assert_eq!(m.read(0xdead_beef, 0), Some(vec![]));
}

#[test]
fn memstate_apply_write_crosses_page_boundary() {
    let mut m = MemoryState::new();
    // start near end of page 0x1000, write 8 bytes -> spills into 0x2000
    m.apply_write(0x1ffc, &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(m.page_count(), 2);
    assert_eq!(m.read(0x1ffc, 8), Some(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(m.read(0x2000, 4), Some(vec![5, 6, 7, 8]));
}

#[test]
fn memstate_read_partially_unmapped_returns_none() {
    let mut m = MemoryState::new();
    m.apply_write(0x1000, &[1, 2, 3, 4]);
    // try to read across into unmapped page
    assert_eq!(m.read(0x1ffc, 8), None);
}

#[test]
fn memstate_diff_identical() {
    let mut a = MemoryState::new();
    let mut b = MemoryState::new();
    a.apply_write(0x1000, &[1, 2, 3]);
    b.apply_write(0x1000, &[1, 2, 3]);
    assert_eq!(a.diff(&b).len(), 0);
}

#[test]
fn memstate_diff_detects_changes() {
    let mut a = MemoryState::new();
    let mut b = MemoryState::new();
    a.apply_write(0x1000, &[1, 2, 3]);
    b.apply_write(0x1000, &[1, 9, 3]);
    let d = a.diff(&b);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].address, 0x1000);
}

#[test]
fn memstate_diff_detects_new_pages() {
    let mut a = MemoryState::new();
    let mut b = MemoryState::new();
    a.apply_write(0x1000, &[1]);
    b.apply_write(0x1000, &[1]);
    b.apply_write(0x2000, &[2]);
    assert_eq!(a.diff(&b).len(), 1);
}

#[test]
fn mempage_new_is_zero_dirty_false() {
    let p = MemPage::new(0x4000);
    assert_eq!(p.base, 0x4000);
    assert_eq!(p.data.len(), 4096);
    assert!(p.data.iter().all(|&b| b == 0));
    assert!(!p.dirty);
}

// ─── Watchpoint ──────────────────────────────────────────────────────────────

#[test]
fn watchpoint_overlaps_basic() {
    let w = Watchpoint::new(1, 0x1000, 8, WatchpointKind::Write);
    assert!(w.overlaps(0x1000, 1));
    assert!(w.overlaps(0x1007, 1));
    assert!(!w.overlaps(0x1008, 1));
    assert!(!w.overlaps(0xfff, 1));
    assert!(w.overlaps(0xfff, 2));
}

#[test]
fn watchpoint_overlaps_zero_len() {
    let w = Watchpoint::new(1, 0x1000, 8, WatchpointKind::Read);
    // zero-length access at offset 0: [0x1000, 0x1000) does not overlap.
    assert!(!w.overlaps(0x1000, 0));
}

#[test]
fn watchpoint_overlaps_saturating() {
    let w = Watchpoint::new(1, u64::MAX - 1, 100, WatchpointKind::Write);
    assert!(w.overlaps(u64::MAX - 1, 1));
}

#[test]
fn watchpoint_display_contains_id_and_address() {
    let w = Watchpoint::new(7, 0xdead, 4, WatchpointKind::ReadWrite);
    let s = format!("{w}");
    assert!(s.contains("WP#7"));
    assert!(s.contains("dead"));
}

// ─── ReplayBreakpoint ────────────────────────────────────────────────────────

#[test]
fn breakpoint_default_fires_on_address_match() {
    let bp = ReplayBreakpoint::new(1, 0x4000);
    let regs = HashMap::new();
    let mem = MemoryState::new();
    assert!(bp.fires(0x4000, &regs, &mem));
    assert!(!bp.fires(0x4001, &regs, &mem));
}

#[test]
fn breakpoint_disabled_never_fires() {
    let mut bp = ReplayBreakpoint::new(1, 0x4000);
    bp.enabled = false;
    assert!(!bp.fires(0x4000, &HashMap::new(), &MemoryState::new()));
}

#[test]
fn breakpoint_register_equals_condition() {
    let bp = ReplayBreakpoint::new(1, 0x4000).with_condition(
        BreakpointCondition::RegisterEquals { reg: "rax".into(), value: 42 },
    );
    let mut regs = HashMap::new();
    regs.insert("rax".to_string(), 42u64);
    assert!(bp.fires(0x4000, &regs, &MemoryState::new()));
    regs.insert("rax".to_string(), 7u64);
    assert!(!bp.fires(0x4000, &regs, &MemoryState::new()));
}

#[test]
fn breakpoint_memory_equals_condition() {
    let bp = ReplayBreakpoint::new(1, 0x4000).with_condition(
        BreakpointCondition::MemoryEquals { addr: 0x9000, value: vec![1, 2, 3] },
    );
    let mut mem = MemoryState::new();
    mem.apply_write(0x9000, &[1, 2, 3]);
    assert!(bp.fires(0x4000, &HashMap::new(), &mem));

    let mut mem2 = MemoryState::new();
    mem2.apply_write(0x9000, &[9, 9, 9]);
    assert!(!bp.fires(0x4000, &HashMap::new(), &mem2));
}

#[test]
fn breakpoint_hit_count_multiple_condition() {
    let bp = ReplayBreakpoint::new(1, 0x4000)
        .with_condition(BreakpointCondition::HitCountMultiple(3));
    // hit_count is 0, so (0+1)=1; 1 % 3 != 0
    assert!(!bp.fires(0x4000, &HashMap::new(), &MemoryState::new()));

    let mut bp2 = ReplayBreakpoint::new(1, 0x4000)
        .with_condition(BreakpointCondition::HitCountMultiple(3));
    bp2.hit_count = 2;
    assert!(bp2.fires(0x4000, &HashMap::new(), &MemoryState::new()));
}

#[test]
fn breakpoint_hit_count_multiple_zero_never_fires() {
    let bp = ReplayBreakpoint::new(1, 0x4000)
        .with_condition(BreakpointCondition::HitCountMultiple(0));
    // n == 0 must not divide; doc says n>0 guard prevents %0.
    assert!(!bp.fires(0x4000, &HashMap::new(), &MemoryState::new()));
}

#[test]
fn breakpoint_display_format() {
    let bp = ReplayBreakpoint::new(3, 0xabc);
    let s = format!("{bp}");
    assert!(s.contains("BP#3"));
    assert!(s.contains("abc"));
}

// ─── SnapshotCache ───────────────────────────────────────────────────────────

#[test]
fn snapshot_cache_insert_and_nearest() {
    let mut c = SnapshotCache::new(100);
    let s1 = Snapshot::new(TracePosition::new(10, 0), MemoryState::new(), HashMap::new());
    let s2 = Snapshot::new(TracePosition::new(20, 0), MemoryState::new(), HashMap::new());
    c.insert(s1);
    c.insert(s2);
    assert_eq!(c.snapshot_count(), 2);
    assert_eq!(
        c.nearest_before(TracePosition::new(15, 0)).unwrap().position,
        TracePosition::new(10, 0)
    );
    assert_eq!(
        c.nearest_before(TracePosition::new(20, 0)).unwrap().position,
        TracePosition::new(20, 0)
    );
    assert!(c.nearest_before(TracePosition::new(5, 0)).is_none());
}

#[test]
fn snapshot_cache_clear_and_contains() {
    let mut c = SnapshotCache::new(100);
    let p = TracePosition::new(10, 0);
    c.insert(Snapshot::new(p, MemoryState::new(), HashMap::new()));
    assert!(c.contains(p));
    c.clear();
    assert!(!c.contains(p));
    assert_eq!(c.snapshot_count(), 0);
}

// ─── WatchpointSet (legacy) ──────────────────────────────────────────────────

#[test]
fn watchpointset_add_remove_match() {
    let mut s = WatchpointSet::new();
    s.add(0x1000, 4);
    s.add(0x2000, 8);
    assert!(s.matches(0x1002, 1));
    assert!(s.matches(0x2007, 1));
    assert!(!s.matches(0x3000, 1));
    assert!(s.remove(0x1000));
    assert!(!s.remove(0x1000));
    assert!(!s.matches(0x1002, 1));
}

#[test]
fn watchpointset_display_count() {
    let mut s = WatchpointSet::new();
    s.add(0x1000, 4);
    assert!(format!("{s}").contains('1'));
}

#[test]
fn watchaddress_display() {
    let w = WatchAddress { addr: 0xfeed, size: 8 };
    let s = format!("{w}");
    assert!(s.contains("feed"));
    assert!(s.contains('8'));
}

// ─── DeltaCompressor ─────────────────────────────────────────────────────────

#[test]
fn delta_compute_and_apply() {
    let before = vec![1u8, 2, 3, 4];
    let after = vec![1u8, 9, 3, 4];
    let d = DeltaCompressor::compute_delta(0x100, &before, &after);
    assert_eq!(d.address, 0x100);
    let applied = DeltaCompressor::apply_delta(&before, &d);
    assert_eq!(applied, after);
}

#[test]
fn delta_apply_grows_base_if_needed() {
    let base = vec![0u8; 2];
    let d = MemoryDelta { address: 0, before: vec![], after: vec![1, 2, 3, 4] };
    let r = DeltaCompressor::apply_delta(&base, &d);
    assert_eq!(r, vec![1, 2, 3, 4]);
}

// ─── ReplayState ─────────────────────────────────────────────────────────────

#[test]
fn replaystate_default_has_canonical_registers() {
    let s = ReplayState::default();
    assert_eq!(s.position, TracePosition::start());
    assert_eq!(s.thread_id, 0);
    assert_eq!(s.registers.get("rax"), Some(&0u64));
    assert_eq!(s.registers.get("rsp"), Some(&0x7fff_0000u64));
    assert_eq!(s.registers.get("rip"), Some(&0u64));
}

#[test]
fn replaystate_display_does_not_panic() {
    let s = ReplayState::default();
    let _ = format!("{s}");
}

// ─── ReplayEngine: trivial accessors ─────────────────────────────────────────

#[test]
fn engine_new_starts_at_start() {
    let trace = build_test_trace(10);
    let eng = ReplayEngine::new(trace);
    assert_eq!(eng.current_position(), TracePosition::start());
    assert_eq!(eng.memory_state().page_count(), 0);
    assert!(eng.breakpoints().is_empty());
    assert!(eng.watchpoints().is_empty());
    assert!(eng.history().is_empty());
    assert_eq!(eng.snapshot_cache().interval, 1000);
}

#[test]
fn engine_with_snapshot_interval() {
    let trace = build_test_trace(10);
    let eng = ReplayEngine::with_snapshot_interval(trace, 5);
    assert_eq!(eng.snapshot_cache().interval, 5);
}

#[test]
fn engine_debug_does_not_panic() {
    let trace = build_test_trace(5);
    let eng = ReplayEngine::new(trace);
    let _ = format!("{eng:?}");
}

// ─── ReplayEngine: breakpoints ───────────────────────────────────────────────

#[test]
fn engine_add_remove_breakpoint() {
    let trace = build_test_trace(5);
    let mut eng = ReplayEngine::new(trace);
    let id1 = eng.add_breakpoint(0x1000);
    let id2 = eng.add_breakpoint(0x2000);
    assert_ne!(id1, id2);
    assert_eq!(eng.breakpoints().len(), 2);
    assert!(eng.remove_breakpoint(id1));
    assert_eq!(eng.breakpoints().len(), 1);
    assert!(!eng.remove_breakpoint(9999));
}

#[test]
fn engine_enable_disable_breakpoint() {
    let trace = build_test_trace(5);
    let mut eng = ReplayEngine::new(trace);
    let id = eng.add_breakpoint(0x1000);
    assert!(eng.disable_breakpoint(id));
    assert!(!eng.breakpoints()[0].enabled);
    assert!(eng.enable_breakpoint(id));
    assert!(eng.breakpoints()[0].enabled);
    assert!(!eng.enable_breakpoint(99999));
    assert!(!eng.disable_breakpoint(99999));
}

#[test]
fn engine_add_breakpoint_with_condition() {
    let trace = build_test_trace(5);
    let mut eng = ReplayEngine::new(trace);
    let id = eng.add_breakpoint_with_condition(
        0x1000,
        BreakpointCondition::Always,
    );
    assert_eq!(id, 1);
    assert!(eng.breakpoints()[0].condition.is_some());
}

// ─── ReplayEngine: watchpoints ───────────────────────────────────────────────

#[test]
fn engine_add_remove_watchpoint() {
    let trace = build_test_trace(5);
    let mut eng = ReplayEngine::new(trace);
    let id = eng.add_watchpoint(0x9000, 4, WatchpointKind::Write);
    assert_eq!(eng.watchpoints().len(), 1);
    assert!(eng.remove_watchpoint(id));
    assert!(!eng.remove_watchpoint(id));
}

#[test]
fn engine_set_watchpoints_replaces() {
    let trace = build_test_trace(5);
    let mut eng = ReplayEngine::new(trace);
    eng.add_watchpoint(0x1000, 4, WatchpointKind::Read);
    let mut ws = WatchpointSet::new();
    ws.add(0x2000, 8);
    ws.add(0x3000, 4);
    eng.set_watchpoints(ws);
    assert_eq!(eng.watchpoints().len(), 2);
    for w in eng.watchpoints() {
        assert_eq!(w.kind, WatchpointKind::Write);
    }
}

// ─── ReplayEngine: stepping ──────────────────────────────────────────────────

#[test]
fn engine_step_forward_once() {
    let trace = build_test_trace(3);
    let mut eng = ReplayEngine::new(trace);
    let r = eng.step_forward().unwrap();
    match r {
        ReplayStopReason::StepComplete { position } => {
            assert_eq!(position, TracePosition::new(0, 0));
        }
        other => panic!("unexpected stop reason: {other:?}"),
    }
}

#[test]
fn engine_step_forward_until_end() {
    let trace = build_test_trace(3);
    let mut eng = ReplayEngine::new(trace);
    for _ in 0..3 {
        let _ = eng.step_forward().unwrap();
    }
    let r = eng.step_forward().unwrap();
    assert!(matches!(r, ReplayStopReason::End));
}

#[test]
fn engine_step_backward_at_start_returns_start() {
    let trace = build_test_trace(3);
    let mut eng = ReplayEngine::new(trace);
    let r = eng.step_backward().unwrap();
    assert!(matches!(r, ReplayStopReason::Start));
}

#[test]
fn engine_step_backward_after_one_step_returns_start() {
    let trace = build_test_trace(3);
    let mut eng = ReplayEngine::new(trace);
    eng.step_forward().unwrap();
    let r = eng.step_backward().unwrap();
    assert!(matches!(r, ReplayStopReason::Start));
    assert_eq!(eng.current_position(), TracePosition::start());
}

#[test]
fn engine_go_to_end_then_start() {
    let trace = build_test_trace(5);
    let mut eng = ReplayEngine::new(trace);
    let r = eng.go_to_end().unwrap();
    assert!(matches!(r, ReplayStopReason::End));
    let r2 = eng.go_to_start().unwrap();
    assert!(matches!(r2, ReplayStopReason::Start));
    assert_eq!(eng.current_position(), TracePosition::start());
    assert_eq!(eng.memory_state().page_count(), 0);
}

#[test]
fn engine_go_to_end_empty_trace() {
    let meta = TraceMetadata::default();
    let trace = Arc::new(TtdTrace::new(meta));
    let mut eng = ReplayEngine::new(trace);
    let r = eng.go_to_end().unwrap();
    assert!(matches!(r, ReplayStopReason::End));
}

// ─── ReplayEngine: run_forward_to_position ──────────────────────────────────

#[test]
fn engine_run_forward_to_valid_position() {
    let trace = build_test_trace(10);
    let mut eng = ReplayEngine::new(trace);
    let r = eng.run_forward_to_position(TracePosition::new(5, 0)).unwrap();
    match r {
        ReplayStopReason::StepComplete { position } => {
            assert_eq!(position, TracePosition::new(5, 0));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn engine_run_forward_to_unknown_position_errs() {
    let trace = build_test_trace(10);
    let mut eng = ReplayEngine::new(trace);
    let err = eng
        .run_forward_to_position(TracePosition::new(99, 0))
        .unwrap_err();
    assert!(matches!(err, ReplayError::PositionNotFound(_)));
}

#[test]
fn engine_run_backward_to_position_no_snapshots() {
    let trace = build_test_trace(10);
    let mut eng = ReplayEngine::with_snapshot_interval(trace, 0); // disabled snapshots
    eng.go_to_end().unwrap();
    let r = eng.run_backward_to_position(TracePosition::new(2, 0)).unwrap();
    match r {
        ReplayStopReason::StepComplete { position } => {
            assert_eq!(position, TracePosition::new(2, 0));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn engine_run_backward_to_future_position_errs() {
    let trace = build_test_trace(10);
    let mut eng = ReplayEngine::new(trace);
    eng.run_forward_to_position(TracePosition::new(2, 0)).unwrap();
    let err = eng
        .run_backward_to_position(TracePosition::new(7, 0))
        .unwrap_err();
    assert!(matches!(err, ReplayError::PositionNotFound(_)));
}

// ─── ReplayEngine: breakpoint-driven ─────────────────────────────────────────

#[test]
fn engine_run_to_breakpoint_forward_hits() {
    // Trace with a Call event at position 3 to addr 0xCAFE
    let events = vec![
        evt(0, 1, EventKind::MemRead { addr: 0x1, len: 1 }),
        evt(1, 1, EventKind::MemRead { addr: 0x2, len: 1 }),
        evt(2, 1, EventKind::MemRead { addr: 0x3, len: 1 }),
        evt(3, 1, EventKind::Call { from: 0x100, to: 0xCAFE }),
        evt(4, 1, EventKind::MemRead { addr: 0x5, len: 1 }),
    ];
    let trace = trace_from(events);
    let mut eng = ReplayEngine::new(trace);
    let bp_id = eng.add_breakpoint(0xCAFE);
    let r = eng.run_to_breakpoint_forward().unwrap();
    match r {
        ReplayStopReason::BreakpointHit { bp_id: id, position } => {
            assert_eq!(id, bp_id);
            assert_eq!(position, TracePosition::new(3, 0));
        }
        other => panic!("expected BreakpointHit, got {other:?}"),
    }
}

#[test]
fn engine_run_to_breakpoint_forward_no_hit_returns_end() {
    let trace = build_test_trace(5);
    let mut eng = ReplayEngine::new(trace);
    eng.add_breakpoint(0xDEAD_BEEF_CAFE);
    let r = eng.run_to_breakpoint_forward().unwrap();
    assert!(matches!(r, ReplayStopReason::End));
}

#[test]
fn engine_run_to_breakpoint_backward_no_hit_returns_start() {
    let trace = build_test_trace(5);
    let mut eng = ReplayEngine::new(trace);
    eng.go_to_end().unwrap();
    eng.add_breakpoint(0xDEAD_BEEF_CAFE);
    let r = eng.run_to_breakpoint_backward().unwrap();
    assert!(matches!(r, ReplayStopReason::Start));
}

#[test]
fn engine_run_to_breakpoint_backward_at_start() {
    let trace = build_test_trace(5);
    let mut eng = ReplayEngine::new(trace);
    let r = eng.run_to_breakpoint_backward().unwrap();
    assert!(matches!(r, ReplayStopReason::Start));
}

// ─── ReplayEngine: watchpoint-driven ─────────────────────────────────────────

#[test]
fn engine_step_forward_hits_write_watchpoint() {
    let events = vec![
        evt(0, 1, EventKind::MemWrite { addr: 0x9000, data: vec![1, 2, 3, 4] }),
    ];
    let trace = trace_from(events);
    let mut eng = ReplayEngine::new(trace);
    let wp_id = eng.add_watchpoint(0x9000, 4, WatchpointKind::Write);
    let r = eng.step_forward().unwrap();
    match r {
        ReplayStopReason::WatchpointHit { wp_id: id, new_value, .. } => {
            assert_eq!(id, wp_id);
            assert_eq!(new_value, vec![1, 2, 3, 4]);
        }
        other => panic!("expected WatchpointHit, got {other:?}"),
    }
}

#[test]
fn engine_step_forward_hits_read_watchpoint() {
    let events = vec![
        evt(0, 1, EventKind::MemRead { addr: 0x9000, len: 8 }),
    ];
    let trace = trace_from(events);
    let mut eng = ReplayEngine::new(trace);
    let wp_id = eng.add_watchpoint(0x9000, 8, WatchpointKind::Read);
    let r = eng.step_forward().unwrap();
    match r {
        ReplayStopReason::WatchpointHit { wp_id: id, .. } => assert_eq!(id, wp_id),
        other => panic!("expected WatchpointHit, got {other:?}"),
    }
}

#[test]
fn engine_write_watchpoint_ignores_reads() {
    let events = vec![evt(0, 1, EventKind::MemRead { addr: 0x9000, len: 8 })];
    let trace = trace_from(events);
    let mut eng = ReplayEngine::new(trace);
    eng.add_watchpoint(0x9000, 8, WatchpointKind::Write);
    let r = eng.step_forward().unwrap();
    assert!(matches!(r, ReplayStopReason::StepComplete { .. }));
}

// ─── ReplayEngine: query APIs ────────────────────────────────────────────────

#[test]
fn engine_find_first_and_last_write_to() {
    let events = vec![
        evt(0, 1, EventKind::MemWrite { addr: 0xA000, data: vec![1] }),
        evt(1, 1, EventKind::MemWrite { addr: 0xB000, data: vec![2] }),
        evt(2, 1, EventKind::MemWrite { addr: 0xA000, data: vec![3] }),
    ];
    let trace = trace_from(events);
    let eng = ReplayEngine::new(trace);
    assert_eq!(eng.find_first_write_to(0xA000), Some(TracePosition::new(0, 0)));
    assert_eq!(eng.find_last_write_to(0xA000), Some(TracePosition::new(2, 0)));
    assert_eq!(eng.find_first_write_to(0xC000), None);
}

#[test]
fn engine_find_all_writes_reads_calls() {
    let events = vec![
        evt(0, 1, EventKind::MemWrite { addr: 0xA000, data: vec![1, 2] }),
        evt(1, 1, EventKind::MemRead { addr: 0xA000, len: 4 }),
        evt(2, 1, EventKind::Call { from: 0x100, to: 0x200 }),
        evt(3, 1, EventKind::Call { from: 0x100, to: 0x300 }),
        evt(4, 1, EventKind::MemWrite { addr: 0xA000, data: vec![9] }),
    ];
    let trace = trace_from(events);
    let eng = ReplayEngine::new(trace);
    let writes = eng.find_all_writes_to(0xA000);
    assert_eq!(writes.len(), 2);
    let reads = eng.find_all_reads_from(0xA000);
    assert_eq!(reads.len(), 1);
    let calls_to_200 = eng.find_all_calls_to(0x200);
    assert_eq!(calls_to_200.len(), 1);
    let calls_from_100 = eng.find_all_calls_from(0x100);
    assert_eq!(calls_from_100.len(), 2);
}

#[test]
fn engine_find_value_at() {
    let events = vec![
        evt(0, 1, EventKind::MemWrite { addr: 0xA000, data: vec![1, 2] }),
        evt(1, 1, EventKind::MemWrite { addr: 0xA000, data: vec![9, 9] }),
        evt(2, 1, EventKind::MemWrite { addr: 0xA000, data: vec![1, 2] }),
    ];
    let trace = trace_from(events);
    let eng = ReplayEngine::new(trace);
    let positions = eng.find_value_at(0xA000, &[1, 2]);
    assert_eq!(positions.len(), 2);
    assert_eq!(positions[0], TracePosition::new(0, 0));
    assert_eq!(positions[1], TracePosition::new(2, 0));
}

#[test]
fn engine_get_memory_at_reconstructs_history() {
    let events = vec![
        evt(0, 1, EventKind::MemWrite { addr: 0xA000, data: vec![1, 2, 3, 4] }),
        evt(1, 1, EventKind::MemWrite { addr: 0xA000, data: vec![9, 9] }),
    ];
    let trace = trace_from(events);
    let eng = ReplayEngine::new(trace);
    let bytes = eng.get_memory_at(TracePosition::new(1, 0), 0xA000, 4).unwrap();
    assert_eq!(bytes, vec![9, 9, 3, 4]);
    let bytes0 = eng.get_memory_at(TracePosition::new(0, 0), 0xA000, 4).unwrap();
    assert_eq!(bytes0, vec![1, 2, 3, 4]);
}

#[test]
fn engine_get_memory_at_unknown_position() {
    let trace = build_test_trace(3);
    let eng = ReplayEngine::new(trace);
    assert!(eng.get_memory_at(TracePosition::new(999, 0), 0x1000, 4).is_none());
}

#[test]
fn engine_get_register_at_after_call() {
    let events = vec![
        evt(0, 1, EventKind::Call { from: 0x100, to: 0xBEEF }),
    ];
    let trace = trace_from(events);
    let eng = ReplayEngine::new(trace);
    let rip = eng.get_register_at(TracePosition::new(0, 0), 1, "rip");
    assert_eq!(rip, Some(0xBEEF));
}

#[test]
fn engine_get_register_at_after_syscall_enter() {
    let events = vec![
        evt(0, 1, EventKind::SyscallEnter { nr: 42, args: [1, 2, 3, 4, 5, 6] }),
    ];
    let trace = trace_from(events);
    let eng = ReplayEngine::new(trace);
    let pos = TracePosition::new(0, 0);
    assert_eq!(eng.get_register_at(pos, 1, "rax"), Some(42));
    assert_eq!(eng.get_register_at(pos, 1, "rdi"), Some(1));
    assert_eq!(eng.get_register_at(pos, 1, "rdx"), Some(3));
}

// ─── ReplayEngine: checkpoint / state ────────────────────────────────────────

#[test]
fn engine_save_and_restore_checkpoint() {
    let trace = build_test_trace(5);
    let mut eng = ReplayEngine::new(trace);
    eng.run_forward_to_position(TracePosition::new(2, 0)).unwrap();
    let cp = eng.save_checkpoint();
    eng.go_to_start().unwrap();
    eng.restore_checkpoint(&cp).unwrap();
    assert_eq!(eng.current_position(), TracePosition::new(2, 0));
}

#[test]
fn engine_restore_checkpoint_unknown_position_errs() {
    let trace = build_test_trace(5);
    let mut eng = ReplayEngine::new(trace);
    let cp = ReplayCheckpoint {
        position: TracePosition::new(9999, 0),
        state: ReplayState::default(),
    };
    let err = eng.restore_checkpoint(&cp).unwrap_err();
    assert!(matches!(err, ReplayError::StateRestoreError(_)));
}

#[test]
fn engine_legacy_step_forward_state() {
    let trace = build_test_trace(3);
    let mut eng = ReplayEngine::new(trace);
    let s = eng.step_forward_state().unwrap();
    assert_eq!(s.position, TracePosition::new(0, 0));
}

#[test]
fn engine_legacy_step_backward_state() {
    let trace = build_test_trace(3);
    let mut eng = ReplayEngine::new(trace);
    eng.step_forward().unwrap();
    let s = eng.step_backward_state().unwrap();
    assert_eq!(s.position, TracePosition::start());
}

#[test]
fn engine_legacy_goto() {
    let trace = build_test_trace(5);
    let mut eng = ReplayEngine::new(trace);
    let s = eng.goto(TracePosition::new(3, 0)).unwrap();
    assert_eq!(s.position, TracePosition::new(3, 0));
    assert!(eng.goto(TracePosition::new(999, 0)).is_err());
}

// ─── ReplayEngine: snapshot index ────────────────────────────────────────────

#[test]
fn engine_build_snapshot_index_creates_snapshots() {
    let trace = build_test_trace(20);
    let mut eng = ReplayEngine::with_snapshot_interval(trace, 5);
    eng.build_snapshot_index();
    // 20 events, interval 5, snapshots taken at i+1 = 5,10,15,20 => 4
    assert_eq!(eng.snapshot_cache().snapshot_count(), 4);
    // build_snapshot_index must restore state — current pos must remain Start
    assert_eq!(eng.current_position(), TracePosition::start());
}

#[test]
fn engine_build_snapshot_index_zero_interval_noop() {
    let trace = build_test_trace(20);
    let mut eng = ReplayEngine::with_snapshot_interval(trace, 0);
    eng.build_snapshot_index();
    assert_eq!(eng.snapshot_cache().snapshot_count(), 0);
}

// ─── apply_event_to_state (static legacy) ────────────────────────────────────

#[test]
fn apply_event_to_state_mem_write_into_pages() {
    let mut s = ReplayState::default();
    let e = evt(0, 1, EventKind::MemWrite { addr: 0x1000, data: vec![1, 2, 3, 4] });
    ReplayEngine::apply_event_to_state(&mut s, &e);
    assert_eq!(s.thread_id, 1);
    let page = s.memory_pages.get(&0x1000).unwrap();
    assert_eq!(&page[0..4], &[1, 2, 3, 4]);
}

#[test]
fn apply_event_to_state_call_sets_rip() {
    let mut s = ReplayState::default();
    let e = evt(0, 1, EventKind::Call { from: 0x100, to: 0xC0DE });
    ReplayEngine::apply_event_to_state(&mut s, &e);
    assert_eq!(s.registers.get("rip"), Some(&0xC0DE));
}

#[test]
fn apply_event_to_state_syscall_exit() {
    let mut s = ReplayState::default();
    let e = evt(0, 1, EventKind::SyscallExit { nr: 1, ret: 0xfeed });
    ReplayEngine::apply_event_to_state(&mut s, &e);
    assert_eq!(s.registers.get("rax"), Some(&0xfeed));
}

// ─── TtdRecordingFile: round-trip and error paths ───────────────────────────

#[test]
fn recording_roundtrip_empty() {
    let rec = TtdRecordingFile::new(TraceMetadata::default());
    let mut buf = Vec::new();
    rec.write_to(&mut buf).unwrap();
    let mut cur = Cursor::new(buf);
    let back = TtdRecordingFile::read_from(&mut cur).unwrap();
    assert_eq!(back.events.len(), 0);
    assert_eq!(back.metadata.process_name, "unknown");
}

#[test]
fn recording_roundtrip_with_events() {
    let trace = build_test_trace(5);
    let rec = TtdRecordingFile::from_trace(&trace);
    let mut buf = Vec::new();
    rec.write_to(&mut buf).unwrap();
    let mut cur = Cursor::new(buf);
    let back = TtdRecordingFile::read_from(&mut cur).unwrap();
    assert_eq!(back.events.len(), 5);
    // into_trace round-trips event count
    let back_trace = back.into_trace();
    assert_eq!(back_trace.event_count(), 5);
}

#[test]
fn recording_bad_magic_rejected() {
    let mut buf = vec![0u8; 16];
    buf[0..8].copy_from_slice(b"WRONGMAG");
    let mut cur = Cursor::new(buf);
    let err = TtdRecordingFile::read_from(&mut cur).unwrap_err();
    match err {
        ReplayError::InvalidTrace(s) => assert!(s.contains("magic")),
        other => panic!("expected InvalidTrace, got {other:?}"),
    }
}

#[test]
fn recording_bad_version_rejected() {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RSTRETTD");
    buf.extend_from_slice(&99u32.to_le_bytes());
    let mut cur = Cursor::new(buf);
    let err = TtdRecordingFile::read_from(&mut cur).unwrap_err();
    match err {
        ReplayError::InvalidTrace(s) => assert!(s.contains("version")),
        other => panic!("expected InvalidTrace, got {other:?}"),
    }
}

#[test]
fn recording_truncated_after_magic_errs() {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RSTRETTD");
    // No version bytes
    let mut cur = Cursor::new(buf);
    let err = TtdRecordingFile::read_from(&mut cur).unwrap_err();
    assert!(matches!(err, ReplayError::IoError(_)));
}

#[test]
fn recording_truncated_metadata_errs() {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RSTRETTD");
    buf.extend_from_slice(&1u32.to_le_bytes());
    // claim metadata len 1000, supply nothing
    buf.extend_from_slice(&1000u32.to_le_bytes());
    let mut cur = Cursor::new(buf);
    let err = TtdRecordingFile::read_from(&mut cur).unwrap_err();
    assert!(matches!(err, ReplayError::IoError(_)));
}

#[test]
fn recording_garbage_metadata_json_errs() {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RSTRETTD");
    buf.extend_from_slice(&1u32.to_le_bytes());
    let garbage = b"not json {{{";
    buf.extend_from_slice(&(u32::try_from(garbage.len()).unwrap_or(u32::MAX)).to_le_bytes());
    buf.extend_from_slice(garbage);
    let mut cur = Cursor::new(buf);
    let err = TtdRecordingFile::read_from(&mut cur).unwrap_err();
    assert!(matches!(err, ReplayError::SerializationError(_)));
}

#[test]
fn recording_debug_format() {
    let rec = TtdRecordingFile::new(TraceMetadata::default());
    let s = format!("{rec:?}");
    assert!(s.contains("TtdRecordingFile"));
}

// ─── ReplayStopReason Display ────────────────────────────────────────────────

#[test]
fn stop_reason_display_variants() {
    let p = TracePosition::new(1, 0);
    assert!(format!("{}", ReplayStopReason::End).contains("End"));
    assert!(format!("{}", ReplayStopReason::Start).contains("Start"));
    assert!(
        format!("{}", ReplayStopReason::StepComplete { position: p }).contains("StepComplete")
    );
    assert!(
        format!("{}", ReplayStopReason::BreakpointHit { bp_id: 7, position: p })
            .contains("BP")
            || format!("{}", ReplayStopReason::BreakpointHit { bp_id: 7, position: p })
                .contains("Breakpoint")
    );
    assert!(
        format!(
            "{}",
            ReplayStopReason::WatchpointHit {
                wp_id: 3,
                position: p,
                old_value: vec![],
                new_value: vec![]
            }
        )
        .contains("Watchpoint")
    );
}

// ─── MemDiff Display ─────────────────────────────────────────────────────────

#[test]
fn memdiff_display() {
    let d = MemDiff { address: 0x1000, before: vec![0; 4], after: vec![1; 4] };
    let s = format!("{d}");
    assert!(s.contains("1000"));
    assert!(s.contains('4'));
}

// ─── run_to_next_event_of_kind ───────────────────────────────────────────────

#[test]
fn engine_run_to_next_event_of_kind_matches() {
    let events = vec![
        evt(0, 1, EventKind::MemRead { addr: 0x1, len: 1 }),
        evt(1, 1, EventKind::Call { from: 0x100, to: 0x200 }),
        evt(2, 1, EventKind::MemRead { addr: 0x2, len: 1 }),
    ];
    let trace = trace_from(events);
    let mut eng = ReplayEngine::new(trace);
    let r = eng
        .run_to_next_event_of_kind(&|k| matches!(k, EventKind::Call { .. }))
        .unwrap();
    match r {
        ReplayStopReason::EventKindMatch { position } => {
            assert_eq!(position, TracePosition::new(1, 0));
        }
        other => panic!("expected EventKindMatch, got {other:?}"),
    }
}

#[test]
fn engine_run_to_next_event_of_kind_no_match() {
    let trace = build_test_trace(3);
    let mut eng = ReplayEngine::new(trace);
    let r = eng
        .run_to_next_event_of_kind(&|k| matches!(k, EventKind::Exception { .. }))
        .unwrap();
    assert!(matches!(r, ReplayStopReason::End));
}
