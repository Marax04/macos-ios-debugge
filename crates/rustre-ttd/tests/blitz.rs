//! Exhaustive integration tests for `rustre-ttd`.
//!
//! Focused on edge cases of the public API in `lib.rs` and adversarial inputs
//! for the `nirvana_format` parser.

use std::ops::Not;
use std::sync::Arc;

use rustre_ttd::nirvana_format::{
    HEADER_SIZE, NirvanaError, TTD_MAGIC, TTD_VERSION_MAJOR, TtdHeader, TtdModuleEntry,
};
use rustre_ttd::{
    CallFrame, CallStack, EventKind, MemoryMap, MemoryRegion, MemorySnapshot, SyscallSummary,
    ThreadState, TraceEvent, TraceExporter, TraceFilter, TraceImporter, TraceMetadata,
    TracePosition, TraceStats, TtdCallExtractor, TtdError, TtdEventFilter, TtdEventType, TtdIndex,
    TtdMemoryTimeline, TtdSequenceId, TtdSession, TtdTrace, Watchpoint, WatchpointKind,
    build_multi_thread_trace, build_test_trace,
};

// ── TracePosition edge cases ─────────────────────────────────────────────────

#[test]
fn trace_position_u128_max() {
    let p = TracePosition::new(u64::MAX, u64::MAX);
    let v = p.as_u128();
    let p2 = TracePosition::from_u128(v);
    assert_eq!(p, p2);
}

#[test]
fn trace_position_u128_zero() {
    let p = TracePosition::start();
    assert_eq!(p.as_u128(), 0);
    assert_eq!(TracePosition::from_u128(0), p);
}

#[test]
fn trace_position_u128_ordering_preserved() {
    let a = TracePosition::new(1, u64::MAX);
    let b = TracePosition::new(2, 0);
    assert!(a < b);
    assert!(a.as_u128() < b.as_u128());
}

#[test]
fn trace_position_in_range_equal_to_start() {
    let s = TracePosition::new(1, 0);
    let e = TracePosition::new(5, 0);
    assert!(s.in_range(&s, &e));
}

#[test]
fn trace_position_in_range_empty_range_is_empty() {
    let s = TracePosition::new(3, 0);
    assert!(!s.in_range(&s, &s));
}

#[test]
fn trace_position_default_is_start() {
    let d = TracePosition::default();
    assert_eq!(d, TracePosition::start());
}

#[test]
fn trace_position_hash_consistent_with_eq() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(TracePosition::new(2, 3));
    assert!(set.contains(&TracePosition::new(2, 3)));
    assert!(!set.contains(&TracePosition::new(2, 4)));
}

// ── MemorySnapshot edge cases ────────────────────────────────────────────────

#[test]
fn memory_snapshot_empty_data_contains_nothing() {
    let s = MemorySnapshot::new(0x100, vec![]);
    assert!(!s.contains(0x100));
    assert_eq!(s.end_address(), 0x100);
}

#[test]
fn memory_snapshot_end_address_saturating() {
    let s = MemorySnapshot::new(u64::MAX - 2, vec![0; 10]);
    // saturating_add should clamp to u64::MAX, not overflow.
    assert_eq!(s.end_address(), u64::MAX);
}

#[test]
fn memory_snapshot_read_u16_le_correct_endianness() {
    let s = MemorySnapshot::new(0, vec![0x34, 0x12]);
    assert_eq!(s.read_u16_le(0), Some(0x1234));
}

#[test]
fn memory_snapshot_read_u64_le_correct_endianness() {
    let s = MemorySnapshot::new(0, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert_eq!(s.read_u64_le(0), Some(0x0807_0605_0403_0201));
}

#[test]
fn memory_snapshot_read_u32_le_partial_oob() {
    let s = MemorySnapshot::new(0, vec![0xAA, 0xBB]);
    assert_eq!(s.read_u32_le(0), None);
}

#[test]
fn memory_snapshot_apply_write_partial_overflow() {
    let mut s = MemorySnapshot::new(0, vec![0u8; 4]);
    // Writing 6 bytes starting at offset 2 should only patch 2 bytes (positions 2,3).
    let n = s.apply_write(2, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    assert_eq!(n, 2);
    assert_eq!(s.data, vec![0, 0, 0xAA, 0xBB]);
}

#[test]
fn memory_snapshot_apply_write_at_exact_end_returns_zero() {
    let mut s = MemorySnapshot::new(0x100, vec![0u8; 4]);
    // end_address is 0x104; writing at 0x104 must be rejected.
    assert_eq!(s.apply_write(0x104, &[0xFF]), 0);
}

#[test]
fn memory_snapshot_apply_write_before_start_returns_zero() {
    let mut s = MemorySnapshot::new(0x100, vec![0u8; 4]);
    assert_eq!(s.apply_write(0x50, &[0xFF]), 0);
}

// ── EventKind ─────────────────────────────────────────────────────────────────

#[test]
fn event_kind_address_for_return_uses_from() {
    let k = EventKind::Return {
        from: 0xAA,
        to: 0xBB,
    };
    assert_eq!(k.address(), Some(0xAA));
}

#[test]
fn event_kind_address_for_breakpoint() {
    let k = EventKind::Breakpoint { addr: 0x4444 };
    assert_eq!(k.address(), Some(0x4444));
}

#[test]
fn event_kind_address_for_exception() {
    let k = EventKind::Exception {
        code: 1,
        addr: 0xDEAD,
    };
    assert_eq!(k.address(), Some(0xDEAD));
}

#[test]
fn event_kind_address_thread_events_none() {
    assert_eq!(EventKind::ThreadCreate { tid: 1 }.address(), None);
    assert_eq!(EventKind::ThreadExit { tid: 1, code: 0 }.address(), None);
    assert_eq!(EventKind::SyscallExit { nr: 0, ret: 0 }.address(), None);
}

#[test]
fn event_kind_not_memory_access_for_call() {
    assert!(!EventKind::Call { from: 0, to: 0 }.is_memory_access());
    assert!(!EventKind::Breakpoint { addr: 0 }.is_memory_access());
}

#[test]
fn event_kind_not_control_flow_for_mem() {
    assert!(!EventKind::MemRead { addr: 0, len: 0 }.is_control_flow());
}

// ── TtdTrace concurrency ─────────────────────────────────────────────────────

#[test]
fn ttd_trace_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TtdTrace>();
}

#[test]
fn ttd_trace_concurrent_add() {
    use std::thread;
    let trace = Arc::new(TtdTrace::new(TraceMetadata::default()));
    let mut handles = Vec::new();
    for tid in 0..4u32 {
        let t = Arc::clone(&trace);
        handles.push(thread::spawn(move || {
            for i in 0..25u64 {
                t.add_event(TraceEvent::new(
                    TracePosition::new(i, u64::from(tid)),
                    tid,
                    EventKind::Breakpoint { addr: i },
                ));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(trace.event_count(), 100);
}

#[test]
fn ttd_trace_empty_thread_ids() {
    let t = TtdTrace::new(TraceMetadata::default());
    assert!(t.thread_ids().is_empty());
}

#[test]
fn ttd_trace_thread_ids_dedup_and_sort() {
    let t = TtdTrace::new(TraceMetadata::default());
    for &tid in &[5u32, 1, 3, 1, 5, 2] {
        t.add_event(TraceEvent::new(
            TracePosition::new(0, 0),
            tid,
            EventKind::Breakpoint { addr: 0 },
        ));
    }
    let ids = t.thread_ids();
    assert_eq!(ids, vec![1, 2, 3, 5]);
}

#[test]
fn ttd_trace_events_in_range_empty_range() {
    let t = build_test_trace(10);
    let pos = TracePosition::new(3, 0);
    let v = t.events_in_range(pos, pos);
    assert!(v.is_empty());
}

#[test]
fn ttd_trace_events_in_range_full() {
    let t = build_test_trace(10);
    let v = t.events_in_range(TracePosition::start(), TracePosition::new(u64::MAX, 0));
    assert_eq!(v.len(), 10);
}

#[test]
fn ttd_trace_push_event_mut_variant() {
    let mut t = TtdTrace::new(TraceMetadata::default());
    t.push_event(TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::Breakpoint { addr: 0 },
    ));
    assert_eq!(t.event_count(), 1);
}

// ── TtdSession ────────────────────────────────────────────────────────────────

#[test]
fn ttd_session_empty_trace_step_forward_errors() {
    let trace = Arc::new(TtdTrace::new(TraceMetadata::default()));
    let mut sess = TtdSession::open(trace);
    assert!(sess.is_at_start());
    assert!(sess.is_at_end());
    assert!(sess.step_forward().is_err());
}

#[test]
fn ttd_session_back_after_full_walk() {
    let trace = build_test_trace(3);
    let mut sess = TtdSession::open(trace);
    for _ in 0..3 {
        sess.step_forward().unwrap();
    }
    // Walking back the same number of times must succeed.
    for _ in 0..3 {
        sess.step_back().expect("step back");
    }
    assert!(sess.is_at_start());
}

#[test]
fn ttd_session_peek_at_end_returns_none() {
    let trace = build_test_trace(2);
    let mut sess = TtdSession::open(trace);
    sess.step_forward().unwrap();
    sess.step_forward().unwrap();
    assert!(sess.peek_next().is_none());
}

#[test]
fn ttd_session_skip_while_partial() {
    let trace = build_test_trace(10);
    let mut sess = TtdSession::open(trace);
    // Only skip MemRead events. build_test_trace alternates Read/Write at even/odd seqs.
    let skipped = sess
        .skip_while(|e| matches!(e.kind, EventKind::MemRead { .. }))
        .unwrap();
    assert_eq!(skipped, 1, "first event is MemRead, second is MemWrite, so stop after one");
}

#[test]
fn ttd_session_goto_then_forward_advances() {
    let trace = build_test_trace(10);
    let mut sess = TtdSession::open(Arc::clone(&trace));
    sess.goto_position(TracePosition::new(5, 0)).unwrap();
    let e = sess.step_forward().unwrap();
    assert_eq!(e.position, TracePosition::new(5, 0));
}

#[test]
fn ttd_session_trace_accessor() {
    let trace = build_test_trace(3);
    let sess = TtdSession::open(Arc::clone(&trace));
    assert!(Arc::ptr_eq(sess.trace(), &trace));
}

// ── TtdIndex extras ───────────────────────────────────────────────────────────

#[test]
fn ttd_index_multi_thread_count() {
    let trace = build_multi_thread_trace(8);
    let idx = TtdIndex::open_in_memory().unwrap();
    idx.index_trace(&trace).unwrap();
    let counts = idx.event_count_by_thread().unwrap();
    assert_eq!(counts.values().sum::<u64>(), 8);
    assert_eq!(counts.len(), 2);
}

#[test]
fn ttd_index_kind_filter_empty_range() {
    let trace = build_test_trace(10);
    let idx = TtdIndex::open_in_memory().unwrap();
    idx.index_trace(&trace).unwrap();
    let v = idx.find_events_by_kind_in_range("MemRead", 100, 200).unwrap();
    assert!(v.is_empty());
}

#[test]
fn ttd_index_clear_then_reindex() {
    let trace = build_test_trace(5);
    let idx = TtdIndex::open_in_memory().unwrap();
    idx.index_trace(&trace).unwrap();
    idx.clear().unwrap();
    idx.index_trace(&trace).unwrap();
    assert_eq!(idx.total_event_count().unwrap(), 5);
}

// ── MemoryMap edge cases ──────────────────────────────────────────────────────

#[test]
fn memory_map_empty_region_at_returns_none() {
    let m = MemoryMap::new();
    assert!(m.region_at(0x1000).is_none());
}

#[test]
fn memory_map_region_at_lower_boundary() {
    let mut m = MemoryMap::new();
    m.add_region(MemoryRegion::new(0x1000, 0x2000, "x"));
    assert!(m.region_at(0x1000).is_some());
    assert!(m.region_at(0x0FFF).is_none());
    assert!(m.region_at(0x2000).is_none()); // end exclusive
}

#[test]
fn memory_map_adjacent_regions() {
    let mut m = MemoryMap::new();
    m.add_region(MemoryRegion::new(0x1000, 0x2000, "a"));
    m.add_region(MemoryRegion::new(0x2000, 0x3000, "b"));
    assert_eq!(m.region_at(0x1FFF).unwrap().label, "a");
    assert_eq!(m.region_at(0x2000).unwrap().label, "b");
}

#[test]
fn memory_region_size_saturating() {
    // end < start should saturate to 0, not underflow.
    let r = MemoryRegion::new(0x2000, 0x1000, "weird");
    assert_eq!(r.size(), 0);
}

// ── CallStack ─────────────────────────────────────────────────────────────────

#[test]
fn call_stack_unbalanced_return_pops_nothing() {
    let trace = TtdTrace::new(TraceMetadata::default());
    trace.add_event(TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::Return {
            from: 0x100,
            to: 0x200,
        },
    ));
    let cs = CallStack::from_trace(&trace, 1, TracePosition::new(0, 0));
    assert_eq!(cs.depth(), 0);
}

#[test]
fn call_stack_frames_in_push_order() {
    let mut cs = CallStack::new();
    for i in 0..3 {
        cs.push(CallFrame {
            call_site: i,
            callee: i + 100,
            position: TracePosition::new(i, 0),
        });
    }
    assert_eq!(cs.frames().len(), 3);
    assert_eq!(cs.top().unwrap().callee, 102);
}

#[test]
fn call_stack_from_trace_respects_up_to_pos() {
    let trace = TtdTrace::new(TraceMetadata::default());
    trace.add_event(TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::Call { from: 0, to: 1 },
    ));
    trace.add_event(TraceEvent::new(
        TracePosition::new(5, 0),
        1,
        EventKind::Call { from: 2, to: 3 },
    ));
    // Up-to-pos before second call.
    let cs = CallStack::from_trace(&trace, 1, TracePosition::new(2, 0));
    assert_eq!(cs.depth(), 1);
}

#[test]
fn call_frame_display() {
    let f = CallFrame {
        call_site: 0xAA,
        callee: 0xBB,
        position: TracePosition::new(1, 2),
    };
    let s = f.to_string();
    assert!(s.contains("CallFrame"));
    assert!(s.contains("0xaa"));
}

// ── TraceFilter ───────────────────────────────────────────────────────────────

#[test]
fn trace_filter_by_address_range() {
    let trace = build_test_trace(10);
    let all = trace.all_events();
    let f = TraceFilter::ByAddressRange(0x2000, 0x3000);
    let filtered = f.apply(&all);
    assert!(filtered.iter().all(|e| e.kind.address().unwrap() < 0x3000));
}

#[test]
fn trace_filter_de_morgan() {
    let trace = build_test_trace(10);
    let all = trace.all_events();
    // NOT(A AND B) === (NOT A) OR (NOT B)
    let a = TraceFilter::ByKind(String::from("MemRead"));
    let b = TraceFilter::ByThread(1);
    let lhs = TraceFilter::Not(Box::new(a.clone().and(b.clone())));
    let rhs = a.not().or(b.not());
    assert_eq!(lhs.apply(&all).len(), rhs.apply(&all).len());
}

// ── TraceStats ────────────────────────────────────────────────────────────────

#[test]
fn trace_stats_empty_trace() {
    let t = TtdTrace::new(TraceMetadata::default());
    let s = TraceStats::compute(&t);
    assert_eq!(s.total_events, 0);
    assert_eq!(s.thread_count, 0);
}

#[test]
fn trace_stats_counts_each_kind() {
    let t = TtdTrace::new(TraceMetadata::default());
    let kinds = vec![
        EventKind::MemRead { addr: 0, len: 4 },
        EventKind::MemWrite {
            addr: 0,
            data: vec![1, 2, 3],
        },
        EventKind::Call { from: 0, to: 0 },
        EventKind::Return { from: 0, to: 0 },
        EventKind::SyscallEnter {
            nr: 1,
            args: [0; 6],
        },
        EventKind::Exception { code: 0, addr: 0 },
    ];
    for (i, k) in kinds.into_iter().enumerate() {
        t.add_event(TraceEvent::new(TracePosition::new(i as u64, 0), 1, k));
    }
    let s = TraceStats::compute(&t);
    assert_eq!(s.mem_reads, 1);
    assert_eq!(s.mem_writes, 1);
    assert_eq!(s.calls, 1);
    assert_eq!(s.returns, 1);
    assert_eq!(s.syscall_enters, 1);
    assert_eq!(s.exceptions, 1);
    assert_eq!(s.bytes_read, 4);
    assert_eq!(s.bytes_written, 3);
}

// ── Export/Import round-trip ──────────────────────────────────────────────────

#[test]
fn trace_export_import_preserves_kinds() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(TraceEvent::new(
        TracePosition::new(0, 0),
        9,
        EventKind::SyscallEnter {
            nr: 7,
            args: [1, 2, 3, 4, 5, 6],
        },
    ));
    t.add_event(TraceEvent::new(
        TracePosition::new(1, 0),
        9,
        EventKind::Exception {
            code: 0xC000_0005,
            addr: 0xDEAD,
        },
    ));
    let s = TraceExporter::export_to_string(&t).unwrap();
    let imported = TraceImporter::import_from_str(&s).unwrap();
    assert_eq!(imported.event_count(), 2);
    let evts = imported.all_events();
    match &evts[0].kind {
        EventKind::SyscallEnter { nr, args } => {
            assert_eq!(*nr, 7);
            assert_eq!(args[5], 6);
        }
        _ => panic!("wrong kind"),
    }
}

#[test]
fn trace_importer_only_metadata_no_events() {
    let t = TtdTrace::new(TraceMetadata::default());
    let s = TraceExporter::export_to_string(&t).unwrap();
    let imported = TraceImporter::import_from_str(&s).unwrap();
    assert_eq!(imported.event_count(), 0);
}

#[test]
fn trace_importer_invalid_metadata_errors() {
    let result = TraceImporter::import_from_str("not json at all\n");
    assert!(matches!(result, Err(TtdError::SerdeError(_))));
}

#[test]
fn trace_importer_invalid_event_line_errors() {
    let mut s = String::new();
    s.push_str(&serde_json::to_string(&TraceMetadata::default()).unwrap());
    s.push('\n');
    s.push_str("garbage\n");
    let result = TraceImporter::import_from_str(&s);
    assert!(matches!(result, Err(TtdError::SerdeError(_))));
}

#[test]
fn trace_importer_blank_lines_skipped() {
    let mut s = String::new();
    s.push_str(&serde_json::to_string(&TraceMetadata::default()).unwrap());
    s.push_str("\n\n\n");
    let imported = TraceImporter::import_from_str(&s).unwrap();
    assert_eq!(imported.event_count(), 0);
}

// ── Watchpoint ────────────────────────────────────────────────────────────────

#[test]
fn watchpoint_no_overlap_at_exact_end() {
    let wp = Watchpoint::new(0x1000, 4, WatchpointKind::ReadWrite);
    let ev = TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::MemRead {
            addr: 0x1004,
            len: 4,
        },
    );
    assert!(!wp.triggered_by(&ev));
}

#[test]
fn watchpoint_partial_overlap_left() {
    let wp = Watchpoint::new(0x1000, 4, WatchpointKind::Write);
    let ev = TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::MemWrite {
            addr: 0x0FFE,
            data: vec![0, 0, 0, 0], // covers 0x0FFE..0x1002
        },
    );
    assert!(wp.triggered_by(&ev));
}

#[test]
fn watchpoint_readwrite_triggers_on_both() {
    let wp = Watchpoint::new(0x1000, 4, WatchpointKind::ReadWrite);
    let r = TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::MemRead {
            addr: 0x1000,
            len: 1,
        },
    );
    let w = TraceEvent::new(
        TracePosition::new(1, 0),
        1,
        EventKind::MemWrite {
            addr: 0x1000,
            data: vec![1],
        },
    );
    assert!(wp.triggered_by(&r));
    assert!(wp.triggered_by(&w));
}

#[test]
fn watchpoint_ignores_non_mem_events() {
    let wp = Watchpoint::new(0x1000, 4, WatchpointKind::ReadWrite);
    let ev = TraceEvent::new(
        TracePosition::new(0, 0),
        1,
        EventKind::Breakpoint { addr: 0x1000 },
    );
    assert!(!wp.triggered_by(&ev));
}

// ── SyscallSummary ────────────────────────────────────────────────────────────

#[test]
fn syscall_summary_unique_return_values() {
    let trace = TtdTrace::new(TraceMetadata::default());
    for (i, ret) in [10u64, 10, 20, 10].into_iter().enumerate() {
        trace.add_event(TraceEvent::new(
            TracePosition::new(i as u64 * 2, 0),
            1,
            EventKind::SyscallEnter {
                nr: 1,
                args: [0; 6],
            },
        ));
        trace.add_event(TraceEvent::new(
            TracePosition::new(i as u64 * 2 + 1, 0),
            1,
            EventKind::SyscallExit { nr: 1, ret },
        ));
    }
    let summary = SyscallSummary::from_trace(&trace);
    let info = summary.by_nr.get(&1).unwrap();
    assert_eq!(info.call_count, 4);
    // Only two unique returns: 10 and 20.
    assert_eq!(info.return_values.len(), 2);
}

#[test]
fn syscall_summary_no_syscalls_empty() {
    let trace = build_test_trace(5);
    let summary = SyscallSummary::from_trace(&trace);
    assert_eq!(summary.total_calls(), 0);
    assert!(summary.top_syscalls().is_empty());
}

// ── TtdSequenceId ─────────────────────────────────────────────────────────────

#[test]
fn ttd_sequence_id_from_trace_position_truncates_step() {
    // Step values > u32::MAX get truncated when converted to TtdSequenceId.
    let p = TracePosition::new(1, u64::from(u32::MAX) + 5);
    let s = TtdSequenceId::from(p);
    // Documented as truncating cast (no explicit bound check in source).
    assert_eq!(s.major, 1);
    assert_eq!(s.minor, 4); // overflow wraps
}

#[test]
fn ttd_sequence_id_to_trace_position_roundtrip_within_u32() {
    let s = TtdSequenceId::new(42, 7);
    let p = s.to_trace_position();
    assert_eq!(p.sequence, 42);
    assert_eq!(p.step, 7);
}

#[test]
fn ttd_sequence_id_start() {
    let s = TtdSequenceId::start();
    assert_eq!(s.major, 0);
    assert_eq!(s.minor, 0);
}

// ── TtdEventFilter ────────────────────────────────────────────────────────────

#[test]
fn ttd_event_filter_default_matches_all() {
    let events = vec![
        TraceEvent::new(
            TracePosition::new(0, 0),
            1,
            EventKind::Breakpoint { addr: 0 },
        ),
        TraceEvent::new(
            TracePosition::new(1, 0),
            1,
            EventKind::Call { from: 0, to: 0 },
        ),
    ];
    let f = TtdEventFilter::new();
    assert_eq!(f.apply(&events).len(), 2);
}

#[test]
fn ttd_event_filter_combined_address_and_type() {
    let events = vec![
        TraceEvent::new(
            TracePosition::new(0, 0),
            1,
            EventKind::MemRead {
                addr: 0x1000,
                len: 4,
            },
        ),
        TraceEvent::new(
            TracePosition::new(1, 0),
            1,
            EventKind::MemWrite {
                addr: 0x1000,
                data: vec![0],
            },
        ),
    ];
    let f = TtdEventFilter::new()
        .at_address(0x1000)
        .of_type(TtdEventType::MemRead);
    let hits = f.apply(&events);
    assert_eq!(hits.len(), 1);
    assert!(matches!(hits[0].kind, EventKind::MemRead { .. }));
}

#[test]
fn ttd_event_filter_range_inclusive_upper_bound() {
    let events: Vec<TraceEvent> = (0u64..10)
        .map(|i| {
            TraceEvent::new(
                TracePosition::new(i, 0),
                1,
                EventKind::Breakpoint { addr: i },
            )
        })
        .collect();
    let f = TtdEventFilter::new().in_range(TtdSequenceId::new(5, 0), TtdSequenceId::new(5, 0));
    let hits = f.apply(&events);
    assert_eq!(hits.len(), 1, "filter range is documented as inclusive");
}

// ── TtdCallExtractor ─────────────────────────────────────────────────────────

#[test]
fn ttd_call_extractor_nested_calls() {
    let events = vec![
        TraceEvent::new(
            TracePosition::new(0, 0),
            1,
            EventKind::Call { from: 0x10, to: 0x20 },
        ),
        TraceEvent::new(
            TracePosition::new(1, 0),
            1,
            EventKind::Call { from: 0x21, to: 0x30 },
        ),
        TraceEvent::new(
            TracePosition::new(2, 0),
            1,
            EventKind::Return {
                from: 0x30,
                to: 0x22,
            },
        ),
        TraceEvent::new(
            TracePosition::new(3, 0),
            1,
            EventKind::Return {
                from: 0x20,
                to: 0x11,
            },
        ),
    ];
    let calls = TtdCallExtractor::extract_calls(&events);
    assert_eq!(calls.iter().filter(|c| c.caller_addr != u64::MAX).count(), 2);
}

#[test]
fn ttd_call_extractor_syscall_pairing() {
    let events = vec![
        TraceEvent::new(
            TracePosition::new(0, 0),
            1,
            EventKind::SyscallEnter {
                nr: 42,
                args: [0; 6],
            },
        ),
        TraceEvent::new(
            TracePosition::new(1, 0),
            1,
            EventKind::SyscallExit { nr: 42, ret: 99 },
        ),
    ];
    let calls = TtdCallExtractor::extract_calls(&events);
    let syscalls: Vec<_> = calls.iter().filter(|c| c.caller_addr == u64::MAX).collect();
    assert_eq!(syscalls.len(), 1);
    assert_eq!(syscalls[0].return_value, Some(99));
}

#[test]
fn ttd_call_extractor_empty_input() {
    let calls = TtdCallExtractor::extract_calls(&[]);
    assert!(calls.is_empty());
}

// ── TtdMemoryTimeline ─────────────────────────────────────────────────────────

#[test]
fn ttd_memory_timeline_written_addresses_sorted() {
    let mut tl = TtdMemoryTimeline::new();
    tl.add_write(TtdSequenceId::new(0, 0), 0x3000, vec![1]);
    tl.add_write(TtdSequenceId::new(0, 0), 0x1000, vec![2]);
    tl.add_write(TtdSequenceId::new(0, 0), 0x2000, vec![3]);
    let addrs = tl.written_addresses();
    assert_eq!(addrs, vec![0x1000, 0x2000, 0x3000]);
}

#[test]
fn ttd_memory_timeline_find_first_write_after_strict() {
    let mut tl = TtdMemoryTimeline::new();
    tl.add_write(TtdSequenceId::new(5, 0), 0x100, vec![1]);
    tl.sort();
    // Strictly after: query at 5 should NOT include 5.
    assert_eq!(tl.find_first_write_after(0x100, TtdSequenceId::new(5, 0)), None);
    assert_eq!(
        tl.find_first_write_after(0x100, TtdSequenceId::new(4, 0)),
        Some(TtdSequenceId::new(5, 0))
    );
}

// ── ThreadState ───────────────────────────────────────────────────────────────

#[test]
fn thread_state_register_overwrites() {
    let mut ts = ThreadState::new(7);
    ts.set_register("rax", 1);
    ts.set_register("rax", 2);
    assert_eq!(ts.get_register("rax"), Some(2));
}

// ── nirvana_format::TtdHeader ─────────────────────────────────────────────────

#[test]
fn nirvana_header_roundtrip() {
    let h = TtdHeader::new("myapp.exe", 1234);
    let bytes = h.to_bytes();
    assert_eq!(bytes.len(), HEADER_SIZE);
    let h2 = TtdHeader::from_bytes(&bytes).unwrap();
    assert_eq!(h.magic, h2.magic);
    assert_eq!(h.version_major, h2.version_major);
    assert_eq!(h.pid, h2.pid);
    assert_eq!(h2.process_name_str(), "myapp.exe");
}

#[test]
fn nirvana_header_validate_ok() {
    let h = TtdHeader::new("x", 0);
    assert!(h.validate().is_ok());
}

#[test]
fn nirvana_header_validate_bad_magic() {
    let mut h = TtdHeader::new("x", 0);
    h.magic = 0xDEAD;
    assert!(matches!(h.validate(), Err(NirvanaError::BadMagic { .. })));
}

#[test]
fn nirvana_header_validate_unsupported_version() {
    let mut h = TtdHeader::new("x", 0);
    h.version_major = TTD_VERSION_MAJOR + 1;
    assert!(matches!(
        h.validate(),
        Err(NirvanaError::UnsupportedVersion { .. })
    ));
}

#[test]
fn nirvana_header_from_bytes_truncated() {
    let r = TtdHeader::from_bytes(&[0u8; 10]);
    assert!(matches!(r, Err(NirvanaError::Truncated { .. })));
}

#[test]
fn nirvana_header_process_name_truncation() {
    let long = "a".repeat(100);
    let h = TtdHeader::new(&long, 0);
    let s = h.process_name_str();
    // Must fit within 63 bytes (last byte reserved for NUL).
    assert!(s.len() <= 63);
    assert!(s.chars().all(|c| c == 'a'));
}

#[test]
fn nirvana_header_read_write_roundtrip() {
    let h = TtdHeader::new("hello", 99);
    let mut buf = Vec::new();
    h.write(&mut buf).unwrap();
    let h2 = TtdHeader::read(&mut buf.as_slice()).unwrap();
    assert_eq!(h, h2);
}

#[test]
fn nirvana_header_read_truncated_input() {
    let r = TtdHeader::read(&mut [0u8; 5].as_slice());
    assert!(matches!(r, Err(NirvanaError::Truncated { .. })));
}

#[test]
fn nirvana_magic_constant_value() {
    // Magic must round-trip through LE bytes to "INRNVTTD".
    let bytes = TTD_MAGIC.to_le_bytes();
    assert_eq!(&bytes, b"INRNVTTD");
}

#[test]
fn nirvana_module_entry_contains_addr() {
    let m = TtdModuleEntry::new(0x1000, 0x100, 0, "test.dll", TracePosition::start());
    assert!(m.contains_addr(0x1000));
    assert!(m.contains_addr(0x10FF));
    assert!(!m.contains_addr(0x1100));
}

#[test]
fn nirvana_module_entry_loaded_at_default_still_loaded() {
    let m = TtdModuleEntry::new(0x1000, 0x100, 0, "test.dll", TracePosition::new(5, 0));
    assert!(!m.loaded_at(TracePosition::new(0, 0)));
    assert!(m.loaded_at(TracePosition::new(5, 0)));
    assert!(m.loaded_at(TracePosition::new(1_000_000, 0)));
}

#[test]
fn nirvana_module_entry_record_exit() {
    let mut m = TtdModuleEntry::new(0x1000, 0x100, 0, "test.dll", TracePosition::new(5, 0));
    m.record_exit(TracePosition::new(10, 0), 0);
    assert!(m.loaded_at(TracePosition::new(7, 0)));
    assert!(!m.loaded_at(TracePosition::new(10, 0)));
}

#[test]
fn nirvana_module_entry_end_saturating() {
    let m = TtdModuleEntry::new(u64::MAX, u32::MAX, 0, "x", TracePosition::start());
    // end() must saturate, not overflow.
    assert_eq!(m.end(), u64::MAX);
}
