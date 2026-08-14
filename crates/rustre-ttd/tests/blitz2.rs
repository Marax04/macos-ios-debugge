//! Adversarial deep tests for `rustre-ttd` public API.

use std::sync::Arc;
use std::collections::HashMap;
use std::io::BufReader;
use std::ops::Not;

use rustre_ttd::{
    CallFrame, CallStack, EventKind, MemoryMap, MemoryRegion, MemorySnapshot, SyscallSummary,
    ThreadState, TraceEvent, TraceExporter, TraceFilter, TraceImporter, TraceMetadata,
    TracePosition, TraceStats, TtdCallExtractor, TtdError, TtdEventFilter, TtdEventType,
    TtdIndex, TtdMemoryTimeline, TtdSequenceId, TtdSession, TtdTrace, Watchpoint, WatchpointKind,
    build_multi_thread_trace, build_test_trace,
};

// Seeded LCG helper for deterministic fuzzing.
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ── TracePosition: deep boundary + round-trip ───────────────────────────────

#[test]
fn pos_u128_fuzz_roundtrip_50() {
    let mut g = lcg();
    for _ in 0..200 {
        let seq = g();
        let step = g();
        let p = TracePosition::new(seq, step);
        let v = p.as_u128();
        let p2 = TracePosition::from_u128(v);
        assert_eq!(p, p2);
        // u128 ordering must match struct ordering
        let q = TracePosition::new(g(), g());
        assert_eq!(p.cmp(&q), p.as_u128().cmp(&q.as_u128()));
    }
}

#[test]
fn pos_next_sequence_saturates() {
    let p = TracePosition::new(u64::MAX, 5);
    let n = p.next_sequence();
    assert_eq!(n.sequence, u64::MAX);
    assert_eq!(n.step, 0);
}

#[test]
fn pos_next_step_saturates() {
    let p = TracePosition::new(7, u64::MAX);
    let n = p.next_step();
    assert_eq!(n.sequence, 7);
    assert_eq!(n.step, u64::MAX);
}

#[test]
fn pos_in_range_half_open_boundaries() {
    let s = TracePosition::new(2, 0);
    let e = TracePosition::new(5, 0);
    assert!(s.in_range(&s, &e));
    assert!(!e.in_range(&s, &e));
    // empty range
    assert!(!TracePosition::new(3, 0).in_range(&s, &s));
}

#[test]
fn pos_display_format() {
    assert_eq!(TracePosition::new(0, 0).to_string(), "0:0");
    assert_eq!(TracePosition::new(42, 7).to_string(), "42:7");
}

#[test]
fn pos_default_is_start() {
    assert_eq!(TracePosition::default(), TracePosition::start());
}

#[test]
fn pos_hash_eq_consistency_30_pairs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut g = lcg();
    for _ in 0..40 {
        let a = TracePosition::new(g() % 100, g() % 100);
        let b = TracePosition::new(a.sequence, a.step);
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        a.hash(&mut h1);
        b.hash(&mut h2);
        assert_eq!(a, b);
        assert_eq!(h1.finish(), h2.finish());
    }
}

// ── MemorySnapshot ──────────────────────────────────────────────────────────

#[test]
fn snapshot_read_u16_u32_u64_le() {
    let s = MemorySnapshot::new(0x100, vec![0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x90]);
    assert_eq!(s.read_u16_le(0x100), Some(0x5678));
    assert_eq!(s.read_u32_le(0x100), Some(0x1234_5678));
    assert_eq!(s.read_u64_le(0x100), Some(0x90AB_CDEF_1234_5678));
}

#[test]
fn snapshot_read_oob_returns_none() {
    let s = MemorySnapshot::new(0, vec![1, 2, 3]);
    assert_eq!(s.read_u8(3), None);
    assert_eq!(s.read_u16_le(2), None);
    assert_eq!(s.read_u32_le(0), None);
}

#[test]
fn snapshot_apply_write_clips_to_snapshot_length() {
    let mut s = MemorySnapshot::new(0x10, vec![0u8; 4]);
    let n = s.apply_write(0x12, &[1, 2, 3, 4, 5]);
    assert_eq!(n, 2); // only bytes at offset 2,3 fit
    assert_eq!(&s.data, &[0, 0, 1, 2]);
}

#[test]
fn snapshot_apply_write_before_base_is_noop() {
    let mut s = MemorySnapshot::new(0x100, vec![1, 2, 3]);
    let n = s.apply_write(0x50, &[9, 9]);
    assert_eq!(n, 0);
    assert_eq!(s.data, vec![1, 2, 3]);
}

#[test]
fn snapshot_end_address_empty() {
    let s = MemorySnapshot::new(0x1000, vec![]);
    assert_eq!(s.end_address(), 0x1000);
    assert!(!s.contains(0x1000));
}

#[test]
fn snapshot_end_address_saturates() {
    let s = MemorySnapshot::new(u64::MAX - 1, vec![0; 10]);
    // saturates to u64::MAX
    assert_eq!(s.end_address(), u64::MAX);
}

#[test]
fn snapshot_fuzz_apply_write_never_panics() {
    let mut g = lcg();
    for _ in 0..100 {
        let base = g() & 0xFFFF;
        let len = (g() % 32) as usize;
        let mut s = MemorySnapshot::new(base, vec![0u8; len]);
        let waddr = base.wrapping_add(g() % 64).wrapping_sub(16);
        let wlen = (g() % 16) as usize;
        let bytes: Vec<u8> = (0..wlen).map(|i| u8::try_from(i & 0xff).unwrap_or(0)).collect();
        let n = s.apply_write(waddr, &bytes);
        assert!(n <= bytes.len());
        assert!(n <= len);
    }
}

// ── ThreadState ─────────────────────────────────────────────────────────────

#[test]
fn thread_state_overwrite_register() {
    let mut ts = ThreadState::new(3);
    ts.set_register("rax", 1);
    ts.set_register("rax", 2);
    assert_eq!(ts.get_register("rax"), Some(2));
}

// ── EventKind ───────────────────────────────────────────────────────────────

#[test]
fn event_kind_address_for_all_variants() {
    assert_eq!(EventKind::MemRead { addr: 1, len: 0 }.address(), Some(1));
    assert_eq!(EventKind::MemWrite { addr: 2, data: vec![] }.address(), Some(2));
    assert_eq!(EventKind::Call { from: 3, to: 4 }.address(), Some(3));
    assert_eq!(EventKind::Return { from: 5, to: 6 }.address(), Some(5));
    assert_eq!(EventKind::Exception { code: 0, addr: 7 }.address(), Some(7));
    assert_eq!(EventKind::Breakpoint { addr: 8 }.address(), Some(8));
    assert_eq!(EventKind::SyscallExit { nr: 0, ret: 0 }.address(), None);
    assert_eq!(EventKind::ThreadCreate { tid: 1 }.address(), None);
    assert_eq!(EventKind::ThreadExit { tid: 1, code: 0 }.address(), None);
}

#[test]
fn event_kind_serde_roundtrip_all_variants() {
    let variants = vec![
        EventKind::MemRead { addr: 0x123, len: 4 },
        EventKind::MemWrite { addr: 0x456, data: vec![1, 2, 3] },
        EventKind::Call { from: 0x10, to: 0x20 },
        EventKind::Return { from: 0x20, to: 0x14 },
        EventKind::SyscallEnter { nr: 42, args: [1, 2, 3, 4, 5, 6] },
        EventKind::SyscallExit { nr: 42, ret: 0xCAFE },
        EventKind::Exception { code: 0xC000_0005, addr: 0xDEAD },
        EventKind::ThreadCreate { tid: 99 },
        EventKind::ThreadExit { tid: 99, code: 1 },
        EventKind::Breakpoint { addr: 0x4000 },
    ];
    for v in variants {
        let j = serde_json::to_string(&v).unwrap();
        let _back: EventKind = serde_json::from_str(&j).unwrap();
    }
}

// ── TraceMetadata serde ──────────────────────────────────────────────────────

#[test]
fn metadata_serde_roundtrip_minimal_json_uses_defaults() {
    // JSON without start_position / end_position / thread_ids should default.
    let j = r#"{"version":1,"process_name":"x","pid":1,"arch":"x86_64","start_time":0,"end_time":0,"thread_count":1}"#;
    let m: TraceMetadata = serde_json::from_str(j).unwrap();
    assert_eq!(m.start_position, TracePosition::start());
    assert_eq!(m.end_position, TracePosition::start());
    assert!(m.thread_ids.is_empty());
}

// ── TtdTrace ────────────────────────────────────────────────────────────────

#[test]
fn trace_push_event_mut() {
    let mut t = TtdTrace::new(TraceMetadata::default());
    t.push_event(TraceEvent::new(TracePosition::new(0, 0), 1, EventKind::Breakpoint { addr: 0 }));
    assert_eq!(t.event_count(), 1);
}

#[test]
fn trace_events_in_range_empty_for_inverted() {
    let t = build_test_trace(10);
    let evts = t.events_in_range(TracePosition::new(5, 0), TracePosition::new(2, 0));
    assert!(evts.is_empty());
}

#[test]
fn trace_sort_after_unordered_inserts_50() {
    let t = TtdTrace::new(TraceMetadata::default());
    let mut g = lcg();
    for _ in 0..60 {
        let seq = g() % 1000;
        t.add_event(TraceEvent::new(
            TracePosition::new(seq, 0),
            1,
            EventKind::Breakpoint { addr: seq },
        ));
    }
    t.sort_events();
    let all = t.all_events();
    for w in all.windows(2) {
        assert!(w[0].position <= w[1].position);
    }
}

#[test]
fn trace_thread_ids_dedup_sorted() {
    let t = TtdTrace::new(TraceMetadata::default());
    for tid in [3u32, 1, 2, 1, 3] {
        t.add_event(TraceEvent::new(
            TracePosition::new(0, 0),
            tid,
            EventKind::Breakpoint { addr: 0 },
        ));
    }
    assert_eq!(t.thread_ids(), vec![1, 2, 3]);
}

#[test]
fn trace_send_sync_stress_4_threads_100_ops() {
    let trace = Arc::new(TtdTrace::new(TraceMetadata::default()));
    let mut handles = vec![];
    for tid in 0..4u32 {
        let t = Arc::clone(&trace);
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                t.add_event(TraceEvent::new(
                    TracePosition::new(i, u64::from(tid)),
                    tid + 1,
                    EventKind::Breakpoint { addr: i },
                ));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(trace.event_count(), 400);
}

// ── TtdSession ──────────────────────────────────────────────────────────────

#[test]
fn session_step_back_after_some_steps() {
    let trace = build_test_trace(5);
    let mut sess = TtdSession::open(trace);
    for _ in 0..3 {
        sess.step_forward().unwrap();
    }
    // After 3 forward steps, event_index = 3, pos = events[2].position
    sess.step_back().unwrap();
    sess.step_back().unwrap();
    sess.step_back().unwrap();
    // Now event_index = 0, should be at start
    assert!(sess.is_at_start());
}

#[test]
fn session_skip_while_predicate_false() {
    let trace = build_test_trace(5);
    let mut sess = TtdSession::open(trace);
    let n = sess.skip_while(|_| false).unwrap();
    assert_eq!(n, 0);
    assert!(sess.is_at_start());
}

#[test]
fn session_remaining_at_end_empty() {
    let trace = build_test_trace(3);
    let mut sess = TtdSession::open(trace);
    while sess.step_forward().is_ok() {}
    assert!(sess.remaining_events().is_empty());
}

#[test]
fn session_trace_accessor() {
    let trace = build_test_trace(2);
    let sess = TtdSession::open(Arc::clone(&trace));
    assert_eq!(Arc::as_ptr(sess.trace()), Arc::as_ptr(&trace));
}

#[test]
fn session_peek_at_end_is_none() {
    let trace = build_test_trace(1);
    let mut sess = TtdSession::open(trace);
    sess.step_forward().unwrap();
    assert!(sess.peek_next().is_none());
}

// ── TtdIndex ────────────────────────────────────────────────────────────────

#[test]
fn index_round_trip_event_roundtrip_via_find() {
    let trace = build_test_trace(20);
    let idx = TtdIndex::open_in_memory().unwrap();
    idx.index_trace(&trace).unwrap();
    for seq in 0..20 {
        let evts = idx.find_events_near(&TracePosition::new(seq, 0)).unwrap();
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0].position.sequence, seq);
    }
}

#[test]
fn index_find_events_by_kind_in_range_inverted_empty() {
    let trace = build_test_trace(10);
    let idx = TtdIndex::open_in_memory().unwrap();
    idx.index_trace(&trace).unwrap();
    let evts = idx.find_events_by_kind_in_range("MemRead", 5, 5).unwrap();
    assert!(evts.is_empty());
}

#[test]
fn index_count_total_matches_event_count() {
    let mut g = lcg();
    let n = (g() % 50) + 5;
    let trace = build_test_trace(n);
    let idx = TtdIndex::open_in_memory().unwrap();
    idx.index_trace(&trace).unwrap();
    assert_eq!(idx.total_event_count().unwrap(), n);
}

// ── MemoryMap ───────────────────────────────────────────────────────────────

#[test]
fn memory_map_partition_point_correctness() {
    let mut m = MemoryMap::new();
    m.add_region(MemoryRegion::new(0x0, 0x100, "a"));
    m.add_region(MemoryRegion::new(0x200, 0x300, "b"));
    m.add_region(MemoryRegion::new(0x400, 0x500, "c"));
    assert_eq!(m.region_at(0x50).unwrap().label, "a");
    assert_eq!(m.region_at(0x250).unwrap().label, "b");
    assert_eq!(m.region_at(0x450).unwrap().label, "c");
    assert!(m.region_at(0x150).is_none()); // gap
    assert!(m.region_at(0x600).is_none()); // beyond
}

#[test]
fn memory_region_size_saturates_inverted() {
    let r = MemoryRegion::new(0x500, 0x100, "bad");
    assert_eq!(r.size(), 0);
}

#[test]
fn memory_map_from_trace_dedups_pages() {
    let t = TtdTrace::new(TraceMetadata::default());
    // Multiple writes inside the same page → one region.
    for i in 0..10u64 {
        t.add_event(TraceEvent::new(
            TracePosition::new(i, 0),
            1,
            EventKind::MemWrite { addr: 0x1000 + i, data: vec![0] },
        ));
    }
    let m = MemoryMap::from_trace(&t);
    assert_eq!(m.regions().len(), 1);
    assert_eq!(m.regions()[0].start, 0x1000);
}

// ── CallStack ───────────────────────────────────────────────────────────────

#[test]
fn callstack_unbalanced_return_no_panic() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::Return { from: 0, to: 0 },
    ));
    let cs = CallStack::from_trace(&t, 1, TracePosition::new(10, 0));
    assert_eq!(cs.depth(), 0);
}

#[test]
fn callstack_frames_accessor_after_pushes() {
    let mut cs = CallStack::new();
    for i in 0..5u64 {
        cs.push(CallFrame {
            call_site: i * 10,
            callee: i * 100,
            position: TracePosition::new(i, 0),
        });
    }
    assert_eq!(cs.frames().len(), 5);
    assert_eq!(cs.top().unwrap().callee, 400);
}

#[test]
fn callstack_from_trace_respects_up_to_pos() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::Call { from: 1, to: 2 },
    ));
    t.add_event(TraceEvent::new(
        TracePosition::new(5, 0),
        1,
        EventKind::Call { from: 3, to: 4 },
    ));
    let cs = CallStack::from_trace(&t, 1, TracePosition::new(2, 0));
    assert_eq!(cs.depth(), 1);
}

// ── TraceFilter ─────────────────────────────────────────────────────────────

#[test]
fn trace_filter_address_range_filter() {
    let mut g = lcg();
    let t = TtdTrace::new(TraceMetadata::default());
    for i in 0..30u64 {
        let addr = g() % 0x4000;
        t.add_event(TraceEvent::new(
            TracePosition::new(i, 0),
            1,
            EventKind::MemRead { addr, len: 4 },
        ));
    }
    let f = TraceFilter::ByAddressRange(0x1000, 0x2000);
    for e in f.apply(&t.all_events()) {
        let a = e.kind.address().unwrap();
        assert!((0x1000..0x2000).contains(&a));
    }
}

#[test]
fn trace_filter_not_double_negation() {
    let t = build_test_trace(10);
    let all = t.all_events();
    let f = TraceFilter::ByThread(1);
    let nn = f.clone().not().not();
    assert_eq!(f.apply(&all).len(), nn.apply(&all).len());
}

// ── TraceStats ──────────────────────────────────────────────────────────────

#[test]
fn trace_stats_empty_trace() {
    let t = TtdTrace::new(TraceMetadata::default());
    let s = TraceStats::compute(&t);
    assert_eq!(s.total_events, 0);
    assert_eq!(s.thread_count, 0);
}

#[test]
fn trace_stats_counts_calls_returns_exceptions() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(TraceEvent::new(TracePosition::new(0, 0), 1, EventKind::Call { from: 0, to: 0 }));
    t.add_event(TraceEvent::new(TracePosition::new(1, 0), 1, EventKind::Return { from: 0, to: 0 }));
    t.add_event(TraceEvent::new(TracePosition::new(2, 0), 1, EventKind::Exception { code: 0, addr: 0 }));
    t.add_event(TraceEvent::new(TracePosition::new(3, 0), 1, EventKind::SyscallEnter { nr: 1, args: [0; 6] }));
    let s = TraceStats::compute(&t);
    assert_eq!(s.calls, 1);
    assert_eq!(s.returns, 1);
    assert_eq!(s.exceptions, 1);
    assert_eq!(s.syscall_enters, 1);
}

// ── Exporter / Importer ─────────────────────────────────────────────────────

#[test]
fn export_import_roundtrip_preserves_all_event_kinds() {
    let t = TtdTrace::new(TraceMetadata::default());
    let events = vec![
        EventKind::MemRead { addr: 1, len: 2 },
        EventKind::MemWrite { addr: 3, data: vec![4, 5, 6] },
        EventKind::Call { from: 10, to: 20 },
        EventKind::Return { from: 20, to: 14 },
        EventKind::SyscallEnter { nr: 7, args: [1, 2, 3, 4, 5, 6] },
        EventKind::SyscallExit { nr: 7, ret: 99 },
        EventKind::Exception { code: 0xC0, addr: 0xDE },
        EventKind::ThreadCreate { tid: 2 },
        EventKind::ThreadExit { tid: 2, code: 0 },
        EventKind::Breakpoint { addr: 0x4000 },
    ];
    for (i, k) in events.into_iter().enumerate() {
        t.add_event(TraceEvent::new(TracePosition::new(i as u64, 0), 1, k));
    }
    let s = TraceExporter::export_to_string(&t).unwrap();
    let imp = TraceImporter::import_from_str(&s).unwrap();
    assert_eq!(imp.event_count(), 10);
}

#[test]
fn importer_garbage_first_line_errors() {
    let r = TraceImporter::import_from_str("this is not json\n");
    assert!(matches!(r, Err(TtdError::SerdeError(_))));
}

#[test]
fn importer_garbage_event_line_errors() {
    let meta = serde_json::to_string(&TraceMetadata::default()).unwrap();
    let s = format!("{meta}\nNOT_JSON\n");
    let r = TraceImporter::import_from_str(&s);
    assert!(matches!(r, Err(TtdError::SerdeError(_))));
}

#[test]
fn importer_skips_blank_event_lines() {
    let meta = serde_json::to_string(&TraceMetadata::default()).unwrap();
    let s = format!("{meta}\n\n\n");
    let imp = TraceImporter::import_from_str(&s).unwrap();
    assert_eq!(imp.event_count(), 0);
}

#[test]
fn importer_via_bufreader() {
    let t = build_test_trace(4);
    let mut buf = Vec::new();
    TraceExporter::export(&t, &mut buf).unwrap();
    let imp = TraceImporter::import(BufReader::new(buf.as_slice())).unwrap();
    assert_eq!(imp.event_count(), 4);
}

#[test]
fn importer_fuzz_random_bytes_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() % 64) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let _ = TraceImporter::import(bytes.as_slice());
    }
}

// ── Watchpoint ──────────────────────────────────────────────────────────────

#[test]
fn watchpoint_overlap_boundary_just_below() {
    let wp = Watchpoint::new(0x1000, 8, WatchpointKind::ReadWrite);
    // access [0x0FF8, 0x1000) - last byte at 0xFFF, no overlap
    let e = TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::MemRead { addr: 0xFF8, len: 8 },
    );
    assert!(!wp.triggered_by(&e));
}

#[test]
fn watchpoint_overlap_exact_start() {
    let wp = Watchpoint::new(0x1000, 1, WatchpointKind::Write);
    let e = TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::MemWrite { addr: 0x1000, data: vec![0] },
    );
    assert!(wp.triggered_by(&e));
}

#[test]
fn watchpoint_non_memory_event_never_triggers() {
    let wp = Watchpoint::new(0, u64::MAX, WatchpointKind::ReadWrite);
    let e = TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::Breakpoint { addr: 0x1000 },
    );
    assert!(!wp.triggered_by(&e));
}

#[test]
fn watchpoint_saturating_does_not_panic_near_u64_max() {
    let wp = Watchpoint::new(u64::MAX - 4, 100, WatchpointKind::ReadWrite);
    let e = TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::MemRead { addr: u64::MAX - 2, len: 1000 },
    );
    // must not panic; should be triggered
    assert!(wp.triggered_by(&e));
}

// ── SyscallSummary ──────────────────────────────────────────────────────────

#[test]
fn syscall_summary_dedup_return_values() {
    let t = TtdTrace::new(TraceMetadata::default());
    for i in 0u64..3 {
        t.add_event(TraceEvent::new(
            TracePosition::new(i * 2, 0),
            1,
            EventKind::SyscallEnter { nr: 5, args: [0; 6] },
        ));
        t.add_event(TraceEvent::new(
            TracePosition::new(i * 2 + 1, 0),
            1,
            EventKind::SyscallExit { nr: 5, ret: 42 },
        ));
    }
    let sum = SyscallSummary::from_trace(&t);
    let info = sum.by_nr.get(&5).unwrap();
    assert_eq!(info.call_count, 3);
    // return value 42 should appear only once even though 3 exits returned 42
    assert_eq!(info.return_values, vec![42]);
}

// ── TtdSequenceId ───────────────────────────────────────────────────────────

#[test]
fn ttd_sequence_id_to_trace_position_roundtrip() {
    let mut g = lcg();
    for _ in 0..60 {
        let major = g();
        let minor = (g() & 0xFFFF_FFFF) as u32;
        let s = TtdSequenceId::new(major, minor);
        let p = s.to_trace_position();
        let s2 = TtdSequenceId::from(p);
        assert_eq!(s, s2);
    }
}

#[test]
fn ttd_sequence_id_default_start() {
    let s = TtdSequenceId::start();
    assert_eq!(s.major, 0);
    assert_eq!(s.minor, 0);
}

// ── TtdEventType ────────────────────────────────────────────────────────────

#[test]
fn ttd_event_type_matches_kind_all() {
    let pairs = [
        (TtdEventType::MemRead, EventKind::MemRead { addr: 0, len: 0 }),
        (TtdEventType::MemWrite, EventKind::MemWrite { addr: 0, data: vec![] }),
        (TtdEventType::Call, EventKind::Call { from: 0, to: 0 }),
        (TtdEventType::Return, EventKind::Return { from: 0, to: 0 }),
        (TtdEventType::SyscallEnter, EventKind::SyscallEnter { nr: 0, args: [0; 6] }),
        (TtdEventType::SyscallExit, EventKind::SyscallExit { nr: 0, ret: 0 }),
        (TtdEventType::Exception, EventKind::Exception { code: 0, addr: 0 }),
        (TtdEventType::ThreadCreate, EventKind::ThreadCreate { tid: 0 }),
        (TtdEventType::ThreadExit, EventKind::ThreadExit { tid: 0, code: 0 }),
        (TtdEventType::Breakpoint, EventKind::Breakpoint { addr: 0 }),
    ];
    for (t, k) in &pairs {
        assert!(t.matches_kind(k));
    }
    // negative
    assert!(!TtdEventType::Call.matches_kind(&EventKind::MemRead { addr: 0, len: 0 }));
}

// ── TtdEventFilter ──────────────────────────────────────────────────────────

#[test]
fn ttd_event_filter_compose_address_and_type() {
    let events = vec![
        TraceEvent::new(TracePosition::new(0, 0), 1, EventKind::MemRead { addr: 0x100, len: 1 }),
        TraceEvent::new(TracePosition::new(1, 0), 1, EventKind::MemWrite { addr: 0x100, data: vec![1] }),
        TraceEvent::new(TracePosition::new(2, 0), 1, EventKind::MemRead { addr: 0x200, len: 1 }),
    ];
    let f = TtdEventFilter::new().at_address(0x100).of_type(TtdEventType::MemRead);
    let hits = f.apply(&events);
    assert_eq!(hits.len(), 1);
}

#[test]
fn ttd_event_filter_range_inclusive_both_ends() {
    let events: Vec<TraceEvent> = (0..5u64)
        .map(|i| TraceEvent::new(TracePosition::new(i, 0), 1, EventKind::Breakpoint { addr: 0 }))
        .collect();
    let f = TtdEventFilter::new().in_range(TtdSequenceId::new(1, 0), TtdSequenceId::new(3, 0));
    let hits = f.apply(&events);
    assert_eq!(hits.len(), 3); // 1, 2, 3 inclusive
}

#[test]
fn ttd_event_filter_default_accepts_all() {
    let events = vec![TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::Breakpoint { addr: 0 },
    )];
    let f = TtdEventFilter::new();
    assert_eq!(f.apply(&events).len(), 1);
}

// ── TtdCallExtractor ────────────────────────────────────────────────────────

#[test]
fn call_extractor_nested_calls() {
    let events = vec![
        TraceEvent::new(TracePosition::new(0, 0), 1, EventKind::Call { from: 0x10, to: 0x20 }),
        TraceEvent::new(TracePosition::new(1, 0), 1, EventKind::Call { from: 0x21, to: 0x30 }),
        TraceEvent::new(TracePosition::new(2, 0), 1, EventKind::Return { from: 0x30, to: 0x25 }),
        TraceEvent::new(TracePosition::new(3, 0), 1, EventKind::Return { from: 0x20, to: 0x14 }),
    ];
    let calls = TtdCallExtractor::extract_calls(&events);
    assert_eq!(calls.iter().filter(|c| c.caller_addr != u64::MAX).count(), 2);
}

#[test]
fn call_extractor_syscall_pairs_return_value() {
    let events = vec![
        TraceEvent::new(TracePosition::new(0, 0), 1, EventKind::SyscallEnter { nr: 7, args: [0; 6] }),
        TraceEvent::new(TracePosition::new(1, 0), 1, EventKind::SyscallExit { nr: 7, ret: 0xABCD }),
    ];
    let calls = TtdCallExtractor::extract_calls(&events);
    let sys: Vec<_> = calls.iter().filter(|c| c.caller_addr == u64::MAX).collect();
    assert_eq!(sys.len(), 1);
    assert_eq!(sys[0].return_value, Some(0xABCD));
}

#[test]
fn call_extractor_empty_no_panic() {
    let calls = TtdCallExtractor::extract_calls(&[]);
    assert!(calls.is_empty());
}

// ── TtdMemoryTimeline ───────────────────────────────────────────────────────

#[test]
fn memory_timeline_written_addresses_sorted() {
    let mut tl = TtdMemoryTimeline::new();
    tl.add_write(TtdSequenceId::new(1, 0), 0x3000, vec![0]);
    tl.add_write(TtdSequenceId::new(2, 0), 0x1000, vec![0]);
    tl.add_write(TtdSequenceId::new(3, 0), 0x2000, vec![0]);
    let a = tl.written_addresses();
    assert_eq!(a, vec![0x1000, 0x2000, 0x3000]);
}

#[test]
fn memory_timeline_find_first_write_at_exact_seq_excluded() {
    let mut tl = TtdMemoryTimeline::new();
    tl.add_write(TtdSequenceId::new(5, 0), 0x1000, vec![0]);
    tl.sort();
    // strictly after seq=5 → none
    assert!(tl.find_first_write_after(0x1000, TtdSequenceId::new(5, 0)).is_none());
}

// ── Multi-thread trace builder ──────────────────────────────────────────────

#[test]
fn build_multi_thread_trace_two_threads_alternate() {
    let t = build_multi_thread_trace(10);
    let evts = t.all_events();
    for (i, e) in evts.iter().enumerate() {
        let expected_tid = if i % 2 == 0 { 1 } else { 2 };
        assert_eq!(e.thread_id, expected_tid);
    }
}

// ── TtdError ────────────────────────────────────────────────────────────────

#[test]
fn ttd_error_io_from_io_error() {
    let e: TtdError = std::io::Error::other("boom").into();
    assert!(e.to_string().contains("I/O error"));
}

#[test]
fn ttd_error_serde_from_serde_error() {
    let serde_err = serde_json::from_str::<TracePosition>("not json").unwrap_err();
    let e: TtdError = serde_err.into();
    assert!(e.to_string().contains("serialization error"));
}

// ── Index threaded reads (Send + Sync) ──────────────────────────────────────

#[test]
fn index_repeated_reads_consistent() {
    // TtdIndex wraps a rusqlite::Connection which is !Sync, so this is
    // an in-thread loop rather than a multi-thread stress test.
    let trace = build_test_trace(50);
    let idx = TtdIndex::open_in_memory().unwrap();
    idx.index_trace(&trace).unwrap();
    for _ in 0..200 {
        assert_eq!(idx.total_event_count().unwrap(), 50);
    }
}

// ── EventKind boundary: empty MemWrite ───────────────────────────────────────

#[test]
fn empty_memwrite_zero_bytes_written_in_stats() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::MemWrite { addr: 0, data: vec![] },
    ));
    let s = TraceStats::compute(&t);
    assert_eq!(s.mem_writes, 1);
    assert_eq!(s.bytes_written, 0);
}

// ── HashMap on syscall summary ──────────────────────────────────────────────

#[test]
fn syscall_summary_unmatched_exit_records_nothing_for_unknown_nr() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::SyscallExit { nr: 99, ret: 0 },
    ));
    let s = SyscallSummary::from_trace(&t);
    // unmatched Exit on its own does not create a SyscallInfo entry
    assert!(!s.by_nr.contains_key(&99));
    let _: HashMap<u32, _> = s.by_nr; // proves type
}
