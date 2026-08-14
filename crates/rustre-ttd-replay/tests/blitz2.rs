//! Deep adversarial integration tests for `rustre-ttd-replay`.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use rustre_ttd::{EventKind, TraceEvent, TraceMetadata, TracePosition, TtdTrace};
use rustre_ttd_replay::{
    BreakpointCondition, CallEdge, DeltaCompressor, EngineStateDb, MemDiff, MemPage, MemoryAccessStats,
    MemoryDelta, MemoryState, ReplayBreakpoint, ReplayCheckpoint, ReplayEngine, ReplayError,
    ReplayState, ReplayStopReason, Snapshot, SnapshotCache, TtdRecordingFile, WatchAddress,
    Watchpoint, WatchpointKind, WatchpointSet, build_call_graph, compute_memory_access_stats,
    split_by_thread,
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn meta() -> TraceMetadata {
    TraceMetadata {
        version: 1,
        process_name: "blitz2".into(),
        pid: 42,
        arch: "x86_64".into(),
        start_time: 0,
        end_time: 1000,
        thread_count: 1,
        ..Default::default()
    }
}

fn trace_with(events: Vec<(u64, EventKind)>) -> Arc<TtdTrace> {
    let t = Arc::new(TtdTrace::new(meta()));
    for (i, k) in events {
        t.add_event(TraceEvent {
            position: TracePosition::new(i, 0),
            thread_id: 1,
            kind: k,
        });
    }
    t
}

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ── MemoryState round-trip / fuzz ────────────────────────────────────────────

#[test]
fn t01_memory_write_read_roundtrip_50() {
    let mut g = lcg();
    let mut m = MemoryState::new();
    let mut expected: Vec<(u64, Vec<u8>)> = Vec::new();
    for _ in 0..50 {
        let addr = (g() & 0xffff) | 0x10000;
        let len = (usize::try_from(g()).unwrap_or(usize::MAX) % 32) + 1;
        let data: Vec<u8> = (0..len).map(|_| (g() & 0xff) as u8).collect();
        m.apply_write(addr, &data);
        expected.push((addr, data));
    }
    for (addr, data) in &expected {
        let r = m.read(*addr, data.len()).expect("must read");
        assert_eq!(r, *data);
    }
}

#[test]
fn t02_memory_state_zero_len_read() {
    let m = MemoryState::new();
    assert_eq!(m.read(0, 0), Some(vec![]));
    assert_eq!(m.read(u64::MAX, 0), Some(vec![]));
}

#[test]
fn t03_memory_apply_write_empty_is_noop() {
    let mut m = MemoryState::new();
    m.apply_write(0x1000, &[]);
    assert_eq!(m.page_count(), 0);
}

#[test]
fn t04_memory_cross_page_boundary_off_by_one() {
    let mut m = MemoryState::new();
    let page_size: u64 = 4096;
    for off in &[1u64, 2, 4095, 4096, 4097] {
        let addr = page_size - 4 + *off;
        m.apply_write(addr, &[0xAB; 8]);
        let r = m.read(addr, 8).unwrap();
        assert_eq!(r, vec![0xAB; 8]);
    }
}

#[test]
fn t05_memory_diff_symmetry() {
    let mut a = MemoryState::new();
    let mut b = MemoryState::new();
    a.apply_write(0x1000, &[1, 2, 3]);
    b.apply_write(0x1000, &[4, 5, 6]);
    let d1 = a.diff(&b);
    let d2 = b.diff(&a);
    assert_eq!(d1.len(), d2.len());
}

#[test]
fn t06_memory_diff_identity_empty() {
    let mut a = MemoryState::new();
    a.apply_write(0x1000, &[1, 2, 3]);
    let b = a.clone();
    assert!(a.diff(&b).is_empty());
}

#[test]
fn t07_memory_read_unmapped_returns_none() {
    let m = MemoryState::new();
    assert!(m.read(0xdead_beef, 1).is_none());
    assert!(m.read(0, 4).is_none());
}

#[test]
fn t08_memory_page_count_after_disjoint_writes() {
    let mut m = MemoryState::new();
    for i in 0..10u64 {
        m.apply_write(i * 0x10000, &[u8::try_from(i).unwrap_or(u8::MAX)]);
    }
    assert_eq!(m.page_count(), 10);
}

#[test]
fn t09_mempage_new_size_invariant() {
    for base in [0u64, 0x1000, 0x10000, !0xfff] {
        let p = MemPage::new(base);
        assert_eq!(p.base, base);
        assert_eq!(p.data.len(), 4096);
        assert!(!p.dirty);
    }
}

// ── SnapshotCache ────────────────────────────────────────────────────────────

#[test]
fn t10_snapshot_cache_ordering() {
    let mut c = SnapshotCache::new(10);
    for i in [5u64, 1, 9, 3, 7] {
        c.insert(Snapshot::new(
            TracePosition::new(i, 0),
            MemoryState::new(),
            HashMap::new(),
        ));
    }
    assert_eq!(c.snapshot_count(), 5);
    let near = c.nearest_before(TracePosition::new(4, 0)).unwrap();
    assert_eq!(near.position, TracePosition::new(3, 0));
}

#[test]
fn t11_snapshot_cache_clear() {
    let mut c = SnapshotCache::new(5);
    c.insert(Snapshot::new(
        TracePosition::new(1, 0),
        MemoryState::new(),
        HashMap::new(),
    ));
    c.clear();
    assert_eq!(c.snapshot_count(), 0);
    assert!(!c.contains(TracePosition::new(1, 0)));
}

#[test]
fn t12_snapshot_cache_contains_exact() {
    let mut c = SnapshotCache::new(1);
    let p = TracePosition::new(42, 0);
    c.insert(Snapshot::new(p, MemoryState::new(), HashMap::new()));
    assert!(c.contains(p));
    assert!(!c.contains(TracePosition::new(42, 1)));
}

// ── Breakpoints ──────────────────────────────────────────────────────────────

#[test]
fn t13_breakpoint_disabled_never_fires() {
    let regs = HashMap::new();
    let mem = MemoryState::new();
    let mut bp = ReplayBreakpoint::new(1, 0x4000);
    bp.enabled = false;
    assert!(!bp.fires(0x4000, &regs, &mem));
}

#[test]
fn t14_breakpoint_wrong_rip_no_fire() {
    let regs = HashMap::new();
    let mem = MemoryState::new();
    let bp = ReplayBreakpoint::new(1, 0x4000);
    for addr in [0u64, 1, 0x3fff, 0x4001, u64::MAX] {
        assert!(!bp.fires(addr, &regs, &mem));
    }
}

#[test]
fn t15_breakpoint_register_equals_missing_register() {
    let regs = HashMap::new();
    let mem = MemoryState::new();
    let bp = ReplayBreakpoint::new(1, 0x4000).with_condition(
        BreakpointCondition::RegisterEquals { reg: "rax".into(), value: 42 },
    );
    assert!(!bp.fires(0x4000, &regs, &mem));
}

#[test]
fn t16_breakpoint_memory_equals() {
    let mut mem = MemoryState::new();
    mem.apply_write(0x1000, &[0xde, 0xad, 0xbe, 0xef]);
    let regs = HashMap::new();
    let bp = ReplayBreakpoint::new(1, 0x4000).with_condition(BreakpointCondition::MemoryEquals {
        addr: 0x1000,
        value: vec![0xde, 0xad, 0xbe, 0xef],
    });
    assert!(bp.fires(0x4000, &regs, &mem));
    let bp2 = ReplayBreakpoint::new(2, 0x4000).with_condition(BreakpointCondition::MemoryEquals {
        addr: 0x1000,
        value: vec![0, 0, 0, 0],
    });
    assert!(!bp2.fires(0x4000, &regs, &mem));
}

#[test]
fn t17_breakpoint_hit_count_zero_never_fires() {
    let regs = HashMap::new();
    let mem = MemoryState::new();
    let bp = ReplayBreakpoint {
        id: 1,
        address: 0x1000,
        enabled: true,
        hit_count: 0,
        condition: Some(BreakpointCondition::HitCountMultiple(0)),
    };
    assert!(!bp.fires(0x1000, &regs, &mem));
}

#[test]
fn t18_breakpoint_display_contains_id_and_addr() {
    let bp = ReplayBreakpoint::new(7, 0xcafe);
    let s = bp.to_string();
    assert!(s.contains("BP#7"));
    assert!(s.contains("0xcafe"));
}

// ── Watchpoints ──────────────────────────────────────────────────────────────

#[test]
fn t19_watchpoint_overlap_boundary() {
    let wp = Watchpoint::new(1, 0x1000, 16, WatchpointKind::Write);
    assert!(wp.overlaps(0x1000, 1));
    assert!(wp.overlaps(0x1000 + 15, 1));
    assert!(!wp.overlaps(0x1000 + 16, 1));
    assert!(!wp.overlaps(0x0fff, 1));
}

#[test]
fn t20_watchpoint_saturating_overlap_no_panic() {
    let wp = Watchpoint::new(1, u64::MAX - 4, 8, WatchpointKind::ReadWrite);
    // Should not panic on overflow.
    let _ = wp.overlaps(u64::MAX, 8);
    let _ = wp.overlaps(0, usize::MAX);
}

#[test]
fn t21_watchpoint_kind_equality() {
    assert_eq!(WatchpointKind::Read, WatchpointKind::Read);
    assert_ne!(WatchpointKind::Read, WatchpointKind::Write);
    assert_ne!(WatchpointKind::Read, WatchpointKind::ReadWrite);
}

// ── WatchpointSet ────────────────────────────────────────────────────────────

#[test]
fn t22_watchpoint_set_remove_nonexistent() {
    let mut ws = WatchpointSet::new();
    assert!(!ws.remove(0x9999));
    ws.add(0x1000, 4);
    assert!(ws.remove(0x1000));
    assert!(!ws.remove(0x1000));
}

#[test]
fn t23_watchpoint_set_matches_overlap_fuzz() {
    let mut g = lcg();
    let mut ws = WatchpointSet::new();
    ws.add(0x1000, 16);
    for _ in 0..50 {
        let addr = g();
        let size = (usize::try_from(g()).unwrap_or(usize::MAX) & 0x3f) + 1;
        // Should never panic.
        let _ = ws.matches(addr, size);
    }
}

// ── ReplayEngine navigation ──────────────────────────────────────────────────

fn linear_trace(n: u64) -> Arc<TtdTrace> {
    let mut v = Vec::new();
    for i in 0..n {
        v.push((
            i,
            EventKind::MemWrite {
                addr: 0x10000 + i * 8,
                data: vec![(i & 0xff) as u8; 4],
            },
        ));
    }
    trace_with(v)
}

#[test]
fn t24_engine_step_forward_advances_through_trace() {
    let t = linear_trace(10);
    let mut eng = ReplayEngine::new(t);
    for i in 0..10 {
        let r = eng.step_forward().unwrap();
        assert!(matches!(r, ReplayStopReason::StepComplete { .. }));
        assert_eq!(eng.current_position(), TracePosition::new(i, 0));
    }
    let r = eng.step_forward().unwrap();
    assert!(matches!(r, ReplayStopReason::End));
}

#[test]
fn t25_engine_backward_inverse_of_forward() {
    let t = linear_trace(8);
    let mut eng = ReplayEngine::with_snapshot_interval(t, 2);
    // Step forward 5 then back 5 — must land at Start
    for _ in 0..5 {
        eng.step_forward().unwrap();
    }
    for _ in 0..5 {
        eng.step_backward().unwrap();
    }
    let r = eng.step_backward().unwrap();
    assert!(matches!(r, ReplayStopReason::Start));
}

#[test]
fn t26_engine_run_forward_to_position_invalid_pos_err() {
    let t = linear_trace(5);
    let mut eng = ReplayEngine::new(t);
    let r = eng.run_forward_to_position(TracePosition::new(99999, 0));
    assert!(matches!(r, Err(ReplayError::PositionNotFound(_))));
}

#[test]
fn t27_engine_run_backward_to_position_invalid_pos_err() {
    let t = linear_trace(5);
    let mut eng = ReplayEngine::new(t);
    eng.go_to_end().unwrap();
    let r = eng.run_backward_to_position(TracePosition::new(99999, 0));
    assert!(matches!(r, Err(ReplayError::PositionNotFound(_))));
}

#[test]
fn t28_engine_go_to_start_resets_state() {
    let t = linear_trace(10);
    let mut eng = ReplayEngine::new(t);
    eng.go_to_end().unwrap();
    eng.go_to_start().unwrap();
    assert_eq!(eng.current_position(), TracePosition::start());
    assert_eq!(eng.memory_state().page_count(), 0);
    assert!(eng.history().is_empty());
}

#[test]
fn t29_engine_go_to_end_on_empty_trace() {
    let t = Arc::new(TtdTrace::new(meta()));
    let mut eng = ReplayEngine::new(t);
    let r = eng.go_to_end().unwrap();
    assert!(matches!(r, ReplayStopReason::End));
}

#[test]
fn t30_engine_breakpoint_add_disable_run() {
    let t = trace_with(vec![(
        0,
        EventKind::Call { from: 0x1000, to: 0x4000 },
    )]);
    let mut eng = ReplayEngine::new(t);
    let id = eng.add_breakpoint(0x4000);
    eng.disable_breakpoint(id);
    let r = eng.run_to_breakpoint_forward().unwrap();
    assert!(matches!(r, ReplayStopReason::End));
}

#[test]
fn t31_engine_breakpoint_with_condition_register() {
    let t = trace_with(vec![
        (0, EventKind::SyscallEnter { nr: 5, args: [10, 0, 0, 0, 0, 0] }),
        (1, EventKind::Call { from: 0x1000, to: 0x4000 }),
    ]);
    let mut eng = ReplayEngine::new(t);
    eng.add_breakpoint_with_condition(
        0x4000,
        BreakpointCondition::RegisterEquals { reg: "rdi".into(), value: 10 },
    );
    let r = eng.run_to_breakpoint_forward().unwrap();
    assert!(matches!(r, ReplayStopReason::BreakpointHit { .. }));
}

#[test]
fn t32_engine_run_backward_to_breakpoint_no_bp() {
    let t = linear_trace(10);
    let mut eng = ReplayEngine::new(t);
    eng.go_to_end().unwrap();
    let r = eng.run_to_breakpoint_backward().unwrap();
    assert!(matches!(r, ReplayStopReason::Start));
}

#[test]
fn t33_engine_watchpoint_read_kind() {
    let t = trace_with(vec![(0, EventKind::MemRead { addr: 0x2000, len: 4 })]);
    let mut eng = ReplayEngine::new(t);
    eng.add_watchpoint(0x2000, 4, WatchpointKind::Read);
    let r = eng.step_forward().unwrap();
    assert!(matches!(r, ReplayStopReason::WatchpointHit { .. }));
}

#[test]
fn t34_engine_watchpoint_write_only_ignores_reads() {
    let t = trace_with(vec![(0, EventKind::MemRead { addr: 0x2000, len: 4 })]);
    let mut eng = ReplayEngine::new(t);
    eng.add_watchpoint(0x2000, 4, WatchpointKind::Write);
    let r = eng.step_forward().unwrap();
    assert!(matches!(r, ReplayStopReason::StepComplete { .. }));
}

// ── Query APIs ───────────────────────────────────────────────────────────────

#[test]
fn t35_find_first_last_write_returns_none() {
    let t = linear_trace(5);
    let eng = ReplayEngine::new(t);
    assert!(eng.find_first_write_to(0xdead).is_none());
    assert!(eng.find_last_write_to(0xdead).is_none());
}

#[test]
fn t36_find_all_writes_to_count() {
    let t = trace_with(vec![
        (0, EventKind::MemWrite { addr: 0x1000, data: vec![1] }),
        (1, EventKind::MemWrite { addr: 0x2000, data: vec![2] }),
        (2, EventKind::MemWrite { addr: 0x1000, data: vec![3] }),
        (3, EventKind::MemWrite { addr: 0x1000, data: vec![4] }),
    ]);
    let eng = ReplayEngine::new(t);
    assert_eq!(eng.find_all_writes_to(0x1000).len(), 3);
    assert_eq!(eng.find_all_writes_to(0x2000).len(), 1);
    assert_eq!(eng.find_all_writes_to(0x9999).len(), 0);
}

#[test]
fn t37_find_all_calls_to_and_from() {
    let t = trace_with(vec![
        (0, EventKind::Call { from: 0xA, to: 0xB }),
        (1, EventKind::Call { from: 0xA, to: 0xC }),
        (2, EventKind::Call { from: 0xD, to: 0xB }),
    ]);
    let eng = ReplayEngine::new(t);
    assert_eq!(eng.find_all_calls_to(0xB).len(), 2);
    assert_eq!(eng.find_all_calls_from(0xA).len(), 2);
    assert_eq!(eng.find_all_calls_to(0x99).len(), 0);
}

#[test]
fn t38_get_memory_at_invalid_position_none() {
    let t = linear_trace(3);
    let eng = ReplayEngine::new(t);
    assert!(eng
        .get_memory_at(TracePosition::new(999, 0), 0, 1)
        .is_none());
}

// ── DeltaCompressor round-trip / fuzz ────────────────────────────────────────

#[test]
fn t39_delta_compressor_fuzz_50() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (usize::try_from(g()).unwrap_or(usize::MAX) & 0x7f) + 1;
        let before: Vec<u8> = (0..len).map(|_| (g() & 0xff) as u8).collect();
        let after: Vec<u8> = (0..len).map(|_| (g() & 0xff) as u8).collect();
        let d = DeltaCompressor::compute_delta(0, &before, &after);
        let applied = DeltaCompressor::apply_delta(&before, &d);
        assert_eq!(&applied[..len], &after[..]);
    }
}

#[test]
fn t40_delta_compressor_empty_after() {
    let d = DeltaCompressor::compute_delta(0, &[1, 2, 3], &[]);
    let r = DeltaCompressor::apply_delta(&[9, 9, 9], &d);
    assert_eq!(r, vec![9, 9, 9]);
}

// ── TtdRecordingFile round-trip / malformed ──────────────────────────────────

fn build_rec_trace() -> Arc<TtdTrace> {
    trace_with(vec![
        (0, EventKind::MemWrite { addr: 0x100, data: vec![1, 2] }),
        (1, EventKind::Call { from: 0xA, to: 0xB }),
        (2, EventKind::Return { from: 0xB, to: 0xA }),
        (3, EventKind::MemRead { addr: 0x100, len: 2 }),
    ])
}

#[test]
fn t41_recording_file_roundtrip_with_events() {
    let t = build_rec_trace();
    let rec = TtdRecordingFile::from_trace(&t);
    let mut buf = Vec::new();
    rec.write_to(&mut buf).unwrap();
    let rec2 = TtdRecordingFile::read_from(&mut buf.as_slice()).unwrap();
    assert_eq!(rec2.events.len(), 4);
    assert_eq!(rec2.metadata.process_name, "blitz2");
}

#[test]
fn t42_recording_file_truncated_header_err() {
    let bad = vec![0u8; 3];
    let r = TtdRecordingFile::read_from(&mut bad.as_slice());
    assert!(r.is_err());
}

#[test]
fn t43_recording_file_bad_magic_err() {
    let bad: Vec<u8> = b"NOTTTDXX\x01\x00\x00\x00".to_vec();
    let r = TtdRecordingFile::read_from(&mut bad.as_slice());
    match r {
        Err(ReplayError::InvalidTrace(_)) => {}
        other => panic!("expected InvalidTrace, got {other:?}"),
    }
}

#[test]
fn t44_recording_file_bad_version_err() {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RSTRETTD");
    buf.extend_from_slice(&99u32.to_le_bytes());
    // Just enough bytes for the parser to read the version then fail
    buf.extend_from_slice(&0u32.to_le_bytes());
    let r = TtdRecordingFile::read_from(&mut buf.as_slice());
    assert!(matches!(r, Err(ReplayError::InvalidTrace(_))));
}

#[test]
fn t45_recording_file_oversized_event_count_err() {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RSTRETTD");
    buf.extend_from_slice(&1u32.to_le_bytes()); // version
    // Empty metadata json: write "{}"
    let meta_json = serde_json::to_string(&meta()).unwrap();
    let mb = meta_json.as_bytes();
    buf.extend_from_slice(&(u32::try_from(mb.len()).unwrap_or(u32::MAX)).to_le_bytes());
    buf.extend_from_slice(mb);
    // Event count > 100M
    buf.extend_from_slice(&200_000_000u64.to_le_bytes());
    let r = TtdRecordingFile::read_from(&mut buf.as_slice());
    assert!(matches!(r, Err(ReplayError::SerializationError(_))));
}

#[test]
fn t46_recording_file_random_garbage_never_panics() {
    let mut g = lcg();
    for _ in 0..30 {
        let len = (usize::try_from(g()).unwrap_or(usize::MAX) & 0xff) + 8;
        let blob: Vec<u8> = (0..len).map(|_| (g() & 0xff) as u8).collect();
        // Should produce an Err, not panic.
        let _ = TtdRecordingFile::read_from(&mut blob.as_slice());
    }
}

#[test]
fn t47_recording_file_into_trace_preserves_event_count() {
    let t = build_rec_trace();
    let rec = TtdRecordingFile::from_trace(&t);
    let t2 = rec.into_trace();
    assert_eq!(t2.all_events().len(), 4);
}

// ── EngineStateDb ────────────────────────────────────────────────────────────

#[test]
fn t48_engine_state_db_roundtrip_empty() {
    let db = EngineStateDb::open_in_memory().unwrap();
    assert!(db.load_breakpoints().unwrap().is_empty());
    assert!(db.load_watchpoints().unwrap().is_empty());
    assert!(db.load_history().unwrap().is_empty());
}

#[test]
fn t49_engine_state_db_breakpoints_30_pairs() {
    let db = EngineStateDb::open_in_memory().unwrap();
    let mut g = lcg();
    let mut bps = Vec::new();
    for i in 1..=30u32 {
        // Mask address and hit_count to i64::MAX — rusqlite stores INTEGER as
        // signed i64, so u64 values with the high bit set fail to convert.
        bps.push(ReplayBreakpoint {
            id: i,
            address: g() & (i64::MAX as u64),
            enabled: g() & 1 == 0,
            hit_count: g() & 0xff,
            condition: None,
        });
    }
    db.save_breakpoints(&bps).unwrap();
    let loaded = db.load_breakpoints().unwrap();
    assert_eq!(loaded.len(), 30);
    for (a, b) in bps.iter().zip(loaded.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.address, b.address);
        assert_eq!(a.enabled, b.enabled);
        assert_eq!(a.hit_count, b.hit_count);
    }
}

#[test]
fn t50_engine_state_db_watchpoints_kind_preservation() {
    let db = EngineStateDb::open_in_memory().unwrap();
    let wps = vec![
        Watchpoint::new(1, 0x1000, 4, WatchpointKind::Read),
        Watchpoint::new(2, 0x2000, 8, WatchpointKind::Write),
        Watchpoint::new(3, 0x3000, 16, WatchpointKind::ReadWrite),
    ];
    db.save_watchpoints(&wps).unwrap();
    let loaded = db.load_watchpoints().unwrap();
    assert_eq!(loaded.len(), 3);
    assert_eq!(loaded[0].kind, WatchpointKind::Read);
    assert_eq!(loaded[1].kind, WatchpointKind::Write);
    assert_eq!(loaded[2].kind, WatchpointKind::ReadWrite);
}

// ── compute_memory_access_stats ──────────────────────────────────────────────

#[test]
fn t51_memory_access_stats_boundary_range() {
    let t = trace_with(vec![
        (0, EventKind::MemWrite { addr: 0x1000, data: vec![1; 16] }),
        (1, EventKind::MemRead { addr: 0x100c, len: 4 }),
        (2, EventKind::MemRead { addr: 0x1010, len: 4 }), // out of range
    ]);
    let s = compute_memory_access_stats(&t, 0x1000, 0x1010);
    assert_eq!(s.read_count, 1);
    assert_eq!(s.write_count, 1);
    assert_eq!(s.total_accesses(), 2);
}

#[test]
fn t52_memory_access_stats_empty_trace() {
    let t = Arc::new(TtdTrace::new(meta()));
    let s = compute_memory_access_stats(&t, 0, u64::MAX);
    assert_eq!(s.total_accesses(), 0);
    assert!(s.first_access.is_none());
}

// ── call graph / split_by_thread ─────────────────────────────────────────────

#[test]
fn t53_call_graph_counts_grouping() {
    let t = trace_with(vec![
        (0, EventKind::Call { from: 1, to: 2 }),
        (1, EventKind::Call { from: 1, to: 2 }),
        (2, EventKind::Call { from: 1, to: 3 }),
        (3, EventKind::Call { from: 4, to: 2 }),
    ]);
    let g = build_call_graph(&t);
    assert_eq!(g.len(), 3);
    let total: u64 = g.iter().map(|e| e.count).sum();
    assert_eq!(total, 4);
}

#[test]
fn t54_call_graph_empty_trace() {
    let t = Arc::new(TtdTrace::new(meta()));
    let g: Vec<CallEdge> = build_call_graph(&t);
    assert!(g.is_empty());
}

#[test]
fn t55_split_by_thread_distinct_tids() {
    let t = Arc::new(TtdTrace::new(meta()));
    for i in 0u64..6 {
        t.add_event(TraceEvent {
            position: TracePosition::new(i, 0),
            thread_id: (i % 3) as u32 + 1,
            kind: EventKind::MemRead { addr: 0x1000, len: 1 },
        });
    }
    let m = split_by_thread(&t);
    assert_eq!(m.len(), 3);
    for tl in m.values() {
        assert_eq!(tl.event_count(), 2);
    }
}

// ── ReplayStopReason / errors display + round-trip ──────────────────────────

#[test]
fn t56_stop_reason_display_variants() {
    let pos = TracePosition::new(1, 2);
    let cases = [
        ReplayStopReason::Start,
        ReplayStopReason::End,
        ReplayStopReason::StepComplete { position: pos },
        ReplayStopReason::ConditionMet { position: pos },
        ReplayStopReason::EventKindMatch { position: pos },
        ReplayStopReason::BreakpointHit { bp_id: 1, position: pos },
        ReplayStopReason::WatchpointHit {
            wp_id: 2,
            position: pos,
            old_value: vec![1],
            new_value: vec![2],
        },
    ];
    for c in &cases {
        let s = c.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn t57_replay_error_all_variants_display() {
    let errs = [
        ReplayError::InvalidTrace("a".into()),
        ReplayError::PositionNotFound(TracePosition::new(1, 0)),
        ReplayError::StateRestoreError("b".into()),
        ReplayError::EmulationError("c".into()),
        ReplayError::SerializationError("d".into()),
    ];
    for e in &errs {
        assert!(!e.to_string().is_empty());
    }
}

// ── Checkpoint round-trip ────────────────────────────────────────────────────

#[test]
fn t58_checkpoint_roundtrip_preserves_position() {
    let t = linear_trace(20);
    let mut eng = ReplayEngine::new(t);
    eng.goto(TracePosition::new(10, 0)).unwrap();
    let cp = eng.save_checkpoint();
    let original = eng.current_position();
    eng.goto(TracePosition::new(15, 0)).unwrap();
    eng.restore_checkpoint(&cp).unwrap();
    assert_eq!(eng.current_position(), original);
}

#[test]
fn t59_checkpoint_invalid_position_err() {
    let t = linear_trace(5);
    let mut eng = ReplayEngine::new(t);
    let bogus = ReplayCheckpoint {
        position: TracePosition::new(99, 0),
        state: ReplayState::default(),
    };
    let r = eng.restore_checkpoint(&bogus);
    assert!(matches!(r, Err(ReplayError::StateRestoreError(_))));
}

// ── apply_event_to_state cross-page (regression-style) ───────────────────────

#[test]
fn t60_apply_event_to_state_cross_page() {
    let mut s = ReplayState::default();
    let addr = 4096u64 - 2;
    let e = TraceEvent {
        position: TracePosition::new(0, 0),
        thread_id: 1,
        kind: EventKind::MemWrite {
            addr,
            data: vec![0xAA, 0xBB, 0xCC, 0xDD],
        },
    };
    ReplayEngine::apply_event_to_state(&mut s, &e);
    let p0 = s.memory_pages.get(&0).expect("page 0 exists");
    assert_eq!(p0[4094], 0xAA);
    assert_eq!(p0[4095], 0xBB);
    let p1 = s.memory_pages.get(&4096).expect("page 1 exists");
    assert_eq!(p1[0], 0xCC);
    assert_eq!(p1[1], 0xDD);
}

// ── Send/Sync threaded stress ────────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn t61_types_send_sync_static_assert() {
    assert_send_sync::<MemoryState>();
    assert_send_sync::<ReplayBreakpoint>();
    assert_send_sync::<Watchpoint>();
    assert_send_sync::<WatchpointKind>();
    assert_send_sync::<TtdRecordingFile>();
    assert_send_sync::<Snapshot>();
}

#[test]
fn t62_memory_state_threaded_clone_read() {
    let mut base = MemoryState::new();
    base.apply_write(0x1000, &[1, 2, 3, 4, 5, 6, 7, 8]);
    let base = Arc::new(base);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let b = Arc::clone(&base);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let r = b.read(0x1000, 8).unwrap();
                assert_eq!(r, vec![1, 2, 3, 4, 5, 6, 7, 8]);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t63_recording_file_threaded_decode() {
    let t = build_rec_trace();
    let rec = TtdRecordingFile::from_trace(&t);
    let mut buf = Vec::new();
    rec.write_to(&mut buf).unwrap();
    let buf = Arc::new(buf);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let b = Arc::clone(&buf);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let r = TtdRecordingFile::read_from(&mut b.as_slice()).unwrap();
                assert_eq!(r.events.len(), 4);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── Display round-trip-ish ───────────────────────────────────────────────────

#[test]
fn t64_displays_nonempty() {
    let mp = MemDiff { address: 0x10, before: vec![1], after: vec![2] };
    let md = MemoryDelta { address: 0x20, before: vec![1], after: vec![2] };
    let wa = WatchAddress { addr: 0x30, size: 4 };
    let s = MemoryAccessStats::default();
    let ws = WatchpointSet::new();
    assert!(!mp.to_string().is_empty());
    assert!(!md.to_string().is_empty());
    assert!(!wa.to_string().is_empty());
    assert!(!s.to_string().is_empty());
    assert!(!ws.to_string().is_empty());
}

// ── ReplayState legacy default ───────────────────────────────────────────────

#[test]
fn t65_replay_state_default_invariants() {
    let s = ReplayState::default();
    // All 14 GPR plus rsp/rbp/rip
    for r in [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
        "r15", "rsp", "rbp", "rip",
    ] {
        assert!(s.registers.contains_key(r), "missing {r}");
    }
    assert_eq!(s.thread_id, 0);
    assert_eq!(s.position, TracePosition::start());
}
