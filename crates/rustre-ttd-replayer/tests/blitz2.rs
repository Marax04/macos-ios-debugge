//! Deep adversarial tests for the rustre-ttd-replayer public API.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use rustre_ttd_replayer::{
    find_root_cause, CausalStep, MemWriteRecord, QueryAst, QueryValue, ReplayError, ReplayState,
    RootCauseReport, TraceBuilder, TraceEvent, TraceSnapshot, TraceStats, TtdQuery, TtdReplayer,
    TtdTrace, DEFAULT_SNAPSHOT_INTERVAL, MAX_MEM_WRITES_PER_EVENT, REPLAY_PAGE_SIZE,
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn lcg_seed() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn build_simple_trace() -> TtdTrace {
    let mut b = TraceBuilder::new(DEFAULT_SNAPSHOT_INTERVAL);
    // tick 0
    let _ = b.syscall_entry(1, [10, 20, 30, 40, 50, 60]);
    // tick 1
    let _ = b.syscall_exit(0, vec![MemWriteRecord::new(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD])]);
    // tick 2
    let _ = b.signal(9, 0x4000);
    b.build()
}

// ── constants ────────────────────────────────────────────────────────────────

#[test]
fn const_default_snapshot_interval_is_256() {
    assert_eq!(DEFAULT_SNAPSHOT_INTERVAL, 256);
}

#[test]
fn const_max_mem_writes_per_event_positive() {
    assert!(MAX_MEM_WRITES_PER_EVENT > 0);
}

#[test]
fn const_replay_page_size_is_power_of_two() {
    assert!(REPLAY_PAGE_SIZE.is_power_of_two());
    assert_eq!(REPLAY_PAGE_SIZE, 4096);
}

// ── MemWriteRecord ───────────────────────────────────────────────────────────

#[test]
fn memwrite_basic_size_and_end() {
    let w = MemWriteRecord::new(0x1000, vec![1, 2, 3, 4]);
    assert_eq!(w.size(), 4);
    assert_eq!(w.end_addr(), 0x1003);
}

#[test]
fn memwrite_empty_end_addr_saturates() {
    let w = MemWriteRecord::new(0, vec![]);
    // saturating_sub(1) from 0 == 0
    assert_eq!(w.end_addr(), 0);
    assert_eq!(w.size(), 0);
}

#[test]
fn memwrite_overlap_boundaries() {
    let w = MemWriteRecord::new(100, vec![0u8; 10]); // [100,110)
    assert!(w.overlaps(100, 1));
    assert!(w.overlaps(109, 1));
    assert!(!w.overlaps(110, 1));
    assert!(!w.overlaps(99, 1));
    assert!(w.overlaps(99, 2)); // [99,101) overlaps 100
    assert!(w.overlaps(50, 100)); // covers fully
}

#[test]
fn memwrite_overlap_zero_size_range_is_no_overlap() {
    let w = MemWriteRecord::new(100, vec![1, 2, 3]);
    assert!(!w.overlaps(100, 0));
}

#[test]
fn memwrite_bytes_in_range_clip() {
    let w = MemWriteRecord::new(100, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(w.bytes_in_range(100, 4), vec![1, 2, 3, 4]);
    assert_eq!(w.bytes_in_range(102, 3), vec![3, 4, 5]);
    assert_eq!(w.bytes_in_range(106, 10), vec![7, 8]);
    // Test-side fix: query range must cover the write (write is at 100..108)
    assert_eq!(w.bytes_in_range(0, 200), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(w.bytes_in_range(200, 4).is_empty());
}

#[test]
fn memwrite_overlap_at_u64_max_boundary() {
    let w = MemWriteRecord::new(u64::MAX - 3, vec![1, 2, 3, 4]);
    // saturating arithmetic guards
    assert!(w.overlaps(u64::MAX - 3, 1));
    assert!(w.overlaps(u64::MAX, 1));
}

#[test]
fn memwrite_display_format() {
    let w = MemWriteRecord::new(0xABCD, vec![1, 2]);
    let s = format!("{w}");
    assert!(s.contains("0xabcd"));
    assert!(s.contains("size: 2"));
}

#[test]
fn memwrite_eq_and_clone() {
    let a = MemWriteRecord::new(1, vec![1, 2, 3]);
    let b = a.clone();
    assert_eq!(a, b);
    let c = MemWriteRecord::new(1, vec![1, 2, 4]);
    assert_ne!(a, c);
}

#[test]
fn memwrite_fuzz_overlap_no_panic() {
    let mut g = lcg_seed();
    for _ in 0..200 {
        let addr = g();
        let len = (g() & 0xFF) as usize;
        let data = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let w = MemWriteRecord::new(addr, data);
        let q_addr = g();
        let q_size = (g() & 0xFF) as usize;
        // Must never panic
        let _ = w.overlaps(q_addr, q_size);
        let _ = w.bytes_in_range(q_addr, q_size);
        let _ = w.end_addr();
    }
}

// ── TraceEvent ───────────────────────────────────────────────────────────────

#[test]
fn event_tick_extraction() {
    let e = TraceEvent::SyscallEntry { tick: 42, nr: 1, args: [0; 6] };
    assert_eq!(e.tick(), 42);
    let e = TraceEvent::SyscallExit { tick: 43, retval: 0, mem_writes: vec![] };
    assert_eq!(e.tick(), 43);
    let e = TraceEvent::SignalDelivered { tick: 44, signal: 9, pc: 0 };
    assert_eq!(e.tick(), 44);
}

#[test]
fn event_kind_names() {
    assert_eq!(TraceEvent::SyscallEntry { tick: 0, nr: 0, args: [0; 6] }.kind_name(), "SyscallEntry");
    assert_eq!(TraceEvent::SyscallExit { tick: 0, retval: 0, mem_writes: vec![] }.kind_name(), "SyscallExit");
    assert_eq!(TraceEvent::SignalDelivered { tick: 0, signal: 0, pc: 0 }.kind_name(), "SignalDelivered");
}

#[test]
fn event_has_mem_writes_only_when_exit_has_data() {
    let entry = TraceEvent::SyscallEntry { tick: 0, nr: 0, args: [0; 6] };
    let exit_empty = TraceEvent::SyscallExit { tick: 0, retval: 0, mem_writes: vec![] };
    let exit_with = TraceEvent::SyscallExit {
        tick: 0,
        retval: 0,
        mem_writes: vec![MemWriteRecord::new(0, vec![1])],
    };
    assert!(!entry.has_mem_writes());
    assert!(!exit_empty.has_mem_writes());
    assert!(exit_with.has_mem_writes());
    assert!(entry.mem_writes().is_empty());
    assert!(exit_with.mem_writes().len() == 1);
}

#[test]
fn event_syscall_nr_only_on_entry() {
    let entry = TraceEvent::SyscallEntry { tick: 0, nr: 7, args: [0; 6] };
    let exit = TraceEvent::SyscallExit { tick: 0, retval: 0, mem_writes: vec![] };
    let signal = TraceEvent::SignalDelivered { tick: 0, signal: 11, pc: 0 };
    assert_eq!(entry.syscall_nr(), Some(7));
    assert_eq!(exit.syscall_nr(), None);
    assert_eq!(signal.syscall_nr(), None);
}

#[test]
fn event_display_does_not_panic_for_each_variant() {
    let e1 = TraceEvent::SyscallEntry { tick: 1, nr: 2, args: [3; 6] };
    let e2 = TraceEvent::SyscallExit { tick: 4, retval: -1, mem_writes: vec![] };
    let e3 = TraceEvent::SignalDelivered { tick: 5, signal: 15, pc: 0x1234 };
    for e in &[e1, e2, e3] {
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}

// ── TraceSnapshot ────────────────────────────────────────────────────────────

#[test]
fn snapshot_register_set_get() {
    let mut s = TraceSnapshot::new(10);
    s.set_reg("rax", 42);
    s.set_reg("rip", 0x1000);
    assert_eq!(s.get_reg("rax"), Some(42));
    assert_eq!(s.get_reg("rbx"), None);
    assert_eq!(s.tick, 10);
}

#[test]
fn snapshot_write_then_read_page_aligned() {
    let mut s = TraceSnapshot::new(0);
    s.write_mem(0x1000, &[1, 2, 3, 4]);
    assert_eq!(s.read_mem(0x1000, 4), Some(vec![1, 2, 3, 4]));
    assert_eq!(s.page_count(), 1);
}

#[test]
fn snapshot_write_crossing_page_boundary() {
    let mut s = TraceSnapshot::new(0);
    let base = REPLAY_PAGE_SIZE as u64 - 2; // straddle page boundary
    s.write_mem(base, &[1, 2, 3, 4]);
    assert_eq!(s.read_mem(base, 4), Some(vec![1, 2, 3, 4]));
    assert_eq!(s.page_count(), 2);
}

#[test]
fn snapshot_read_unmapped_returns_none() {
    let s = TraceSnapshot::new(0);
    assert!(s.read_mem(0x0010_0000, 4).is_none());
}

#[test]
fn snapshot_footprint_grows_with_pages() {
    let mut s = TraceSnapshot::new(0);
    let f0 = s.memory_footprint();
    s.write_mem(0, &[0u8; 8]);
    let f1 = s.memory_footprint();
    assert!(f1 > f0);
}

#[test]
fn snapshot_fuzz_writes_then_reads_round_trip() {
    let mut g = lcg_seed();
    let mut s = TraceSnapshot::new(0);
    // Write 50 random small ranges in one page, then verify last-write-wins.
    let base = 0x4000u64;
    let mut shadow = vec![0u8; 4096];
    for _ in 0..50 {
        let off = (g() & 0xFFF) as usize;
        let len = ((g() & 0x3F) as usize).max(1);
        let len = len.min(shadow.len() - off);
        let bytes: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        s.write_mem(base + off as u64, &bytes);
        shadow[off..off + len].copy_from_slice(&bytes);
    }
    let read = s.read_mem(base, 4096).expect("page present");
    assert_eq!(read, shadow);
}

// ── TtdTrace ────────────────────────────────────────────────────────────────

#[test]
fn trace_new_is_empty() {
    let t = TtdTrace::new();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert_eq!(t.min_tick(), 0);
    assert_eq!(t.max_tick(), 0);
}

#[test]
fn trace_default_eq_new() {
    let a = TtdTrace::new();
    let b = TtdTrace::default();
    assert_eq!(a.events.len(), b.events.len());
}

#[test]
fn trace_push_event_updates_tick_index() {
    let mut t = TtdTrace::new();
    t.push_event(TraceEvent::SyscallEntry { tick: 5, nr: 1, args: [0; 6] });
    t.push_event(TraceEvent::SyscallEntry { tick: 10, nr: 1, args: [0; 6] });
    assert_eq!(t.len(), 2);
    assert_eq!(t.min_tick(), 5);
    assert_eq!(t.max_tick(), 10);
    assert_eq!(t.first_event_at_or_after(0), Some(0));
    assert_eq!(t.first_event_at_or_after(6), Some(1));
    assert_eq!(t.first_event_at_or_after(11), None);
    assert_eq!(t.last_event_at_or_before(10), Some(1));
    assert_eq!(t.last_event_at_or_before(4), None);
}

#[test]
fn trace_push_snapshot_keeps_sorted_order() {
    let mut t = TtdTrace::new();
    t.push_snapshot(TraceSnapshot::new(20));
    t.push_snapshot(TraceSnapshot::new(5));
    t.push_snapshot(TraceSnapshot::new(15));
    let ticks: Vec<u64> = t.snapshots.iter().map(|s| s.tick).collect();
    assert_eq!(ticks, vec![5, 15, 20]);
}

#[test]
fn trace_nearest_snapshot_before_finds_correct() {
    let mut t = TtdTrace::new();
    t.push_snapshot(TraceSnapshot::new(0));
    t.push_snapshot(TraceSnapshot::new(100));
    t.push_snapshot(TraceSnapshot::new(200));
    assert_eq!(t.nearest_snapshot_before(0).map(|s| s.tick), Some(0));
    assert_eq!(t.nearest_snapshot_before(50).map(|s| s.tick), Some(0));
    assert_eq!(t.nearest_snapshot_before(100).map(|s| s.tick), Some(100));
    assert_eq!(t.nearest_snapshot_before(150).map(|s| s.tick), Some(100));
    assert_eq!(t.nearest_snapshot_before(200).map(|s| s.tick), Some(200));
    assert_eq!(t.nearest_snapshot_before(999).map(|s| s.tick), Some(200));
}

#[test]
fn trace_nearest_snapshot_before_empty() {
    let t = TtdTrace::new();
    assert!(t.nearest_snapshot_before(0).is_none());
}

#[test]
fn trace_events_in_range_inclusive() {
    let mut t = TtdTrace::new();
    for i in 0..10u64 {
        t.push_event(TraceEvent::SyscallEntry { tick: i, nr: 0, args: [0; 6] });
    }
    let v: Vec<_> = t.events_in_range(3, 5).collect();
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].tick(), 3);
    assert_eq!(v[2].tick(), 5);
}

#[test]
fn trace_event_counts() {
    let t = build_simple_trace();
    let counts = t.event_counts();
    assert_eq!(counts.get("SyscallEntry"), Some(&1));
    assert_eq!(counts.get("SyscallExit"), Some(&1));
    assert_eq!(counts.get("SignalDelivered"), Some(&1));
}

#[test]
fn trace_from_parts_rebuilds_index() {
    let evs = vec![
        TraceEvent::SyscallEntry { tick: 10, nr: 1, args: [0; 6] },
        TraceEvent::SyscallEntry { tick: 20, nr: 2, args: [0; 6] },
    ];
    let snaps = vec![TraceSnapshot::new(0)];
    let t = TtdTrace::from_parts(evs, snaps);
    assert_eq!(t.tick_index.len(), 2);
    assert_eq!(t.min_tick(), 10);
    assert_eq!(t.max_tick(), 20);
}

#[test]
fn trace_all_writes_touching() {
    let mut b = TraceBuilder::new(64);
    let _ = b.syscall_entry(0, [0; 6]);
    let _ = b.syscall_exit(
        0,
        vec![
            MemWriteRecord::new(0x100, vec![1; 16]),
            MemWriteRecord::new(0x200, vec![2; 16]),
        ],
    );
    let t = b.build();
    let writes = t.all_writes_touching(0x100, 8);
    assert_eq!(writes.len(), 1);
    let writes2 = t.all_writes_touching(0x150, 0x100);
    assert_eq!(writes2.len(), 1); // spans into 0x200 region
}

// ── ReplayState ──────────────────────────────────────────────────────────────

#[test]
fn replay_state_default_eq_new() {
    let a = ReplayState::new();
    let b = ReplayState::default();
    assert_eq!(a.regs.len(), b.regs.len());
    assert_eq!(a.mem.len(), b.mem.len());
}

#[test]
fn replay_state_reg_default_zero() {
    let s = ReplayState::new();
    assert_eq!(s.reg("rax"), 0);
}

#[test]
fn replay_state_apply_write_then_read() {
    let mut s = ReplayState::new();
    let wr = MemWriteRecord::new(0x1000, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    s.apply_write(&wr);
    assert_eq!(s.read(0x1000, 4), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    assert!(s.read(0x9000, 1).is_none());
}

#[test]
fn replay_state_program_counter_resolution_order() {
    let mut s = ReplayState::new();
    assert_eq!(s.program_counter(), None);
    s.set_reg("ip", 0x1);
    assert_eq!(s.program_counter(), Some(0x1));
    s.set_reg("rip", 0x2);
    assert_eq!(s.program_counter(), Some(0x2)); // rip preferred
}

#[test]
fn replay_state_apply_write_crosses_page() {
    let mut s = ReplayState::new();
    let base = REPLAY_PAGE_SIZE as u64 - 3;
    let wr = MemWriteRecord::new(base, vec![9, 9, 9, 9, 9, 9]);
    s.apply_write(&wr);
    assert_eq!(s.read(base, 6), Some(vec![9; 6]));
    assert_eq!(s.mem.len(), 2);
}

#[test]
fn replay_state_fuzz_round_trip() {
    let mut g = lcg_seed();
    let mut s = ReplayState::new();
    let base = 0x10_0000u64;
    let mut shadow = vec![0u8; 8192];
    for _ in 0..100 {
        let off = (g() & 0x1FFF) as usize;
        let len = ((g() & 0x3F) as usize).max(1);
        let len = len.min(shadow.len() - off);
        let bytes: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        s.apply_write(&MemWriteRecord::new(base + off as u64, bytes.clone()));
        shadow[off..off + len].copy_from_slice(&bytes);
    }
    let read = s.read(base, 8192).expect("mapped");
    assert_eq!(read, shadow);
}

// ── TtdReplayer ──────────────────────────────────────────────────────────────

#[test]
fn replayer_new_positions_at_min_tick() {
    let t = build_simple_trace();
    let r = TtdReplayer::new(t);
    assert!(r.at_start());
    assert!(!r.at_end());
    assert_eq!(r.remaining_events(), 3);
}

#[test]
fn replayer_step_forward_through_trace() {
    let t = build_simple_trace();
    let mut r = TtdReplayer::new(t);
    let e1 = r.step_forward().expect("ok").clone();
    assert!(matches!(e1, TraceEvent::SyscallEntry { tick: 0, .. }));
    let _ = r.step_forward().expect("ok");
    let _ = r.step_forward().expect("ok");
    assert!(r.at_end());
    match r.step_forward() {
        Err(ReplayError::AtEnd) => {}
        other => panic!("expected AtEnd, got {other:?}"),
    }
}

#[test]
fn replayer_step_backward_at_start_errors() {
    let t = build_simple_trace();
    let mut r = TtdReplayer::new(t);
    match r.step_backward() {
        Err(ReplayError::AtStart) => {}
        other => panic!("expected AtStart, got {other:?}"),
    }
}

#[test]
fn replayer_goto_out_of_range_errors() {
    let t = build_simple_trace();
    let mut r = TtdReplayer::new(t);
    let max = r.trace.max_tick();
    match r.goto(max + 1000) {
        Err(ReplayError::TickOutOfRange(want, end)) => {
            assert_eq!(want, max + 1000);
            assert_eq!(end, max);
        }
        other => panic!("expected TickOutOfRange, got {other:?}"),
    }
}

#[test]
fn replayer_goto_reconstructs_state_via_replay() {
    let mut b = TraceBuilder::new(64);
    let _ = b.syscall_entry(0, [0; 6]);
    let _ = b.syscall_exit(0, vec![MemWriteRecord::new(0x2000, vec![0x11, 0x22, 0x33, 0x44])]);
    let _ = b.syscall_exit(0, vec![MemWriteRecord::new(0x2000, vec![0xAA, 0xBB, 0xCC, 0xDD])]);
    let t = b.build();
    let mut r = TtdReplayer::new(t);
    r.goto(1).expect("goto");
    assert_eq!(r.state.read(0x2000, 4), Some(vec![0x11, 0x22, 0x33, 0x44]));
    r.goto(2).expect("goto");
    assert_eq!(r.state.read(0x2000, 4), Some(vec![0xAA, 0xBB, 0xCC, 0xDD]));
}

#[test]
fn replayer_find_last_write_before_picks_latest() {
    let mut b = TraceBuilder::new(64);
    let _ = b.syscall_entry(0, [0; 6]);
    let _ = b.syscall_exit(0, vec![MemWriteRecord::new(0x500, vec![1, 2, 3, 4])]);
    let _ = b.syscall_exit(0, vec![MemWriteRecord::new(0x500, vec![5, 6, 7, 8])]);
    let _ = b.syscall_exit(0, vec![MemWriteRecord::new(0x500, vec![9, 10, 11, 12])]);
    let t = b.build();
    let r = TtdReplayer::new(t);
    let (tick, _) = r.find_last_write_before(0x500, 3).expect("found");
    assert_eq!(tick, 2);
    assert!(r.find_last_write_before(0x500, 0).is_none());
}

#[test]
fn replayer_read_memory_at_tick_uses_snapshot() {
    let mut b = TraceBuilder::new(64);
    let _ = b.syscall_entry(0, [0; 6]);
    let _ = b.syscall_exit(0, vec![MemWriteRecord::new(0x3000, vec![1, 2, 3, 4])]);
    let t = b.build();
    let r = TtdReplayer::new(t);
    let bytes = r.read_memory_at_tick(1, 0x3000, 4).expect("ok");
    assert_eq!(bytes, vec![1, 2, 3, 4]);
    match r.read_memory_at_tick(999, 0x3000, 4) {
        Err(ReplayError::TickOutOfRange(_, _)) => {}
        other => panic!("expected TickOutOfRange got {other:?}"),
    }
    match r.read_memory_at_tick(1, 0xFFFF_0000, 4) {
        Err(ReplayError::AddressNotMapped(addr, tick)) => {
            assert_eq!(addr, 0xFFFF_0000);
            assert_eq!(tick, 1);
        }
        other => panic!("expected AddressNotMapped got {other:?}"),
    }
}

#[test]
fn replayer_reset_returns_to_start() {
    let t = build_simple_trace();
    let mut r = TtdReplayer::new(t);
    let _ = r.step_forward();
    let _ = r.step_forward();
    r.reset();
    assert!(r.at_start());
}

// ── TtdQuery DSL ────────────────────────────────────────────────────────────

#[test]
fn query_parse_empty_errors() {
    match TtdQuery::parse("") {
        Err(ReplayError::QueryParse(_)) => {}
        other => panic!("expected QueryParse, got {other:?}"),
    }
}

#[test]
fn query_parse_unknown_command_errors() {
    match TtdQuery::parse("hellothere") {
        Err(ReplayError::QueryParse(s)) => assert!(s.contains("unknown")),
        other => panic!("expected QueryParse, got {other:?}"),
    }
}

#[test]
fn query_parse_read_mem_hex_and_dec() {
    let q = TtdQuery::parse("read_mem 5 0x1000 4").expect("parse");
    match q.ast {
        QueryAst::ReadMem { tick: 5, addr: 0x1000, size: 4 } => {}
        other => panic!("wrong ast: {other:?}"),
    }
    let q = TtdQuery::parse("read_mem 5 4096 4").expect("parse");
    match q.ast {
        QueryAst::ReadMem { tick: 5, addr: 4096, size: 4 } => {}
        other => panic!("wrong ast: {other:?}"),
    }
}

#[test]
fn query_parse_read_mem_rejects_huge_size() {
    match TtdQuery::parse("read_mem 0 0 1073741824") {
        Err(ReplayError::QueryParse(s)) => assert!(s.contains("exceeds")),
        other => panic!("expected QueryParse, got {other:?}"),
    }
}

#[test]
fn query_parse_find_writes_rejects_huge_size() {
    match TtdQuery::parse("find_writes 0 1073741824") {
        Err(ReplayError::QueryParse(s)) => assert!(s.contains("exceeds")),
        other => panic!("expected QueryParse, got {other:?}"),
    }
}

#[test]
fn query_parse_max_min_tick_simple() {
    matches!(TtdQuery::parse("max_tick").unwrap().ast, QueryAst::MaxTick);
    matches!(TtdQuery::parse("min_tick").unwrap().ast, QueryAst::MinTick);
}

#[test]
fn query_parse_list_syscalls_optional_nr() {
    match TtdQuery::parse("list_syscalls").unwrap().ast {
        QueryAst::ListSyscalls { nr: None } => {}
        other => panic!("wrong ast {other:?}"),
    }
    match TtdQuery::parse("list_syscalls 42").unwrap().ast {
        QueryAst::ListSyscalls { nr: Some(42) } => {}
        other => panic!("wrong ast {other:?}"),
    }
}

#[test]
fn query_execute_max_min_tick() {
    let t = build_simple_trace();
    let mut r = TtdReplayer::new(t);
    let v = TtdQuery::parse("max_tick").unwrap().execute(&mut r).unwrap();
    assert_eq!(v, QueryValue::Int(2));
    let v = TtdQuery::parse("min_tick").unwrap().execute(&mut r).unwrap();
    assert_eq!(v, QueryValue::Int(0));
}

#[test]
fn query_execute_count_events() {
    let t = build_simple_trace();
    let mut r = TtdReplayer::new(t);
    let v = TtdQuery::parse("count_events SyscallEntry").unwrap().execute(&mut r).unwrap();
    assert_eq!(v, QueryValue::Int(1));
    let v = TtdQuery::parse("count_events Nothing").unwrap().execute(&mut r).unwrap();
    assert_eq!(v, QueryValue::Int(0));
}

#[test]
fn query_execute_list_signals_returns_events() {
    let t = build_simple_trace();
    let mut r = TtdReplayer::new(t);
    match TtdQuery::parse("list_signals").unwrap().execute(&mut r).unwrap() {
        QueryValue::EventList(v) => assert_eq!(v.len(), 1),
        other => panic!("wrong val {other:?}"),
    }
}

#[test]
fn query_value_display_variants() {
    assert_eq!(format!("{}", QueryValue::Int(42)), "42");
    assert_eq!(format!("{}", QueryValue::SignedInt(-1)), "-1");
    assert!(format!("{}", QueryValue::Bytes(vec![1, 2])).contains("len=2"));
    assert!(format!("{}", QueryValue::WriteList(vec![])).contains("count=0"));
    assert!(format!("{}", QueryValue::EventList(vec![])).contains("count=0"));
    assert_eq!(format!("{}", QueryValue::Text("hi".into())), "hi");
    assert_eq!(format!("{}", QueryValue::Null), "null");
}

#[test]
fn query_fuzz_parse_no_panic() {
    let mut g = lcg_seed();
    let cmds = [
        "read_mem", "find_writes", "last_write", "list_syscalls", "list_signals",
        "read_reg", "count_events", "root_cause", "max_tick", "min_tick", "garbage",
    ];
    for _ in 0..200 {
        let idx = (g() as usize) % cmds.len();
        let a = g();
        let b = g();
        let c = (g() & 0xFFFF) as usize;
        let s = format!("{} {} 0x{:x} {}", cmds[idx], a, b, c);
        let _ = TtdQuery::parse(&s); // must not panic
    }
}

// ── RootCauseReport / find_root_cause ────────────────────────────────────────

#[test]
fn root_cause_no_writes_low_confidence() {
    let mut b = TraceBuilder::new(64);
    let _ = b.syscall_entry(0, [0; 6]);
    let _ = b.signal(11, 0xDEAD_BEEF);
    let t = b.build();
    let mut r = TtdReplayer::new(t);
    let report = find_root_cause(&mut r, 1, 0xDEAD).expect("ok");
    assert_eq!(report.crash_tick, 1);
    assert_eq!(report.crash_addr, 0xDEAD);
    assert!(report.confidence <= 0.3);
    assert!(!report.summary.is_empty());
}

#[test]
fn root_cause_with_write_higher_confidence() {
    let mut b = TraceBuilder::new(64);
    let _ = b.syscall_entry(1, [0; 6]);
    let _ = b.syscall_exit(0, vec![MemWriteRecord::new(0x500, vec![1, 2, 3, 4, 5, 6, 7, 8])]);
    let _ = b.signal(11, 0x500);
    let t = b.build();
    let mut r = TtdReplayer::new(t);
    let report = find_root_cause(&mut r, 2, 0x500).expect("ok");
    assert!(report.confidence > 0.3);
    assert!(report.earliest_cause().is_some());
}

#[test]
fn root_cause_display_contains_header() {
    let r = RootCauseReport::new(5, 0x42);
    let s = format!("{r}");
    assert!(s.contains("Root Cause Report"));
    assert!(s.contains("0x42"));
}

#[test]
fn causal_step_builders() {
    let step = CausalStep::new(10, "hello").with_addr(0xABC).with_data(vec![1, 2]);
    assert_eq!(step.tick, 10);
    assert_eq!(step.description, "hello");
    assert_eq!(step.addr, Some(0xABC));
    assert_eq!(step.data, Some(vec![1, 2]));
}

// ── TraceBuilder ─────────────────────────────────────────────────────────────

#[test]
fn builder_tick_counter_advances() {
    let mut b = TraceBuilder::new(0);
    assert_eq!(b.syscall_entry(0, [0; 6]), 0);
    assert_eq!(b.syscall_exit(0, vec![]), 1);
    assert_eq!(b.signal(0, 0), 2);
}

#[test]
fn builder_snapshot_boundary_check() {
    let mut b = TraceBuilder::new(2);
    assert!(b.next_tick_is_snapshot_boundary()); // tick 0
    let _ = b.syscall_entry(0, [0; 6]);
    assert!(!b.next_tick_is_snapshot_boundary());
    let _ = b.syscall_entry(0, [0; 6]);
    assert!(b.next_tick_is_snapshot_boundary());
    assert_eq!(b.snapshot_interval(), 2);
}

#[test]
fn builder_snapshot_interval_zero_never_boundary() {
    let b = TraceBuilder::new(0);
    assert!(!b.next_tick_is_snapshot_boundary());
}

#[test]
fn builder_snapshot_attach_with_current_tick() {
    let mut b = TraceBuilder::new(2);
    let _ = b.syscall_entry(0, [0; 6]);
    b.snapshot(HashMap::new(), HashMap::new());
    let trace = b.build();
    assert_eq!(trace.snapshots.len(), 1);
    assert_eq!(trace.snapshots[0].tick, 1);
}

// ── TraceStats ───────────────────────────────────────────────────────────────

#[test]
fn stats_compute_basic_counts() {
    let mut b = TraceBuilder::new(64);
    let _ = b.syscall_entry(1, [0; 6]);
    let _ = b.syscall_entry(2, [0; 6]);
    let _ = b.syscall_entry(1, [0; 6]);
    let _ = b.syscall_exit(0, vec![MemWriteRecord::new(0x10, vec![1; 8]), MemWriteRecord::new(0x20, vec![1; 4])]);
    let _ = b.signal(9, 0);
    let t = b.build();
    let s = TraceStats::compute(&t);
    assert_eq!(s.syscall_entries, 3);
    assert_eq!(s.syscall_exits, 1);
    assert_eq!(s.signals, 1);
    assert_eq!(s.total_bytes_written, 12);
    assert_eq!(s.unique_write_addrs, 2);
    assert_eq!(s.syscall_freq.get(&1), Some(&2));
    assert_eq!(s.syscall_freq.get(&2), Some(&1));
}

#[test]
fn stats_compute_empty_trace() {
    let t = TtdTrace::new();
    let s = TraceStats::compute(&t);
    assert_eq!(s.total_events, 0);
    assert_eq!(s.min_tick, 0);
    assert_eq!(s.max_tick, 0);
}

#[test]
fn stats_display_does_not_panic() {
    let t = build_simple_trace();
    let s = TraceStats::compute(&t);
    let str_ = format!("{s}");
    assert!(str_.contains("TraceStats"));
}

// ── Send + Sync threaded stress ─────────────────────────────────────────────

#[test]
fn trace_is_send_and_sync_threaded() {
    let t = build_simple_trace();
    let arc = Arc::new(t);
    let mut handles = vec![];
    for _ in 0..4 {
        let c = Arc::clone(&arc);
        handles.push(thread::spawn(move || {
            let mut sum: u64 = 0;
            for _ in 0..100 {
                sum = sum.wrapping_add(c.max_tick());
                let _ = c.first_event_at_or_after(0);
                let _ = c.event_counts();
            }
            sum
        }));
    }
    let mut total: u64 = 0;
    for h in handles {
        total = total.wrapping_add(h.join().unwrap());
    }
    // 4 threads × 100 ops × max_tick(=2) = 800
    assert_eq!(total, 800);
}

#[test]
fn snapshot_send_sync_threaded() {
    let mut s = TraceSnapshot::new(0);
    s.set_reg("rip", 0x1000);
    s.write_mem(0x4000, &[1, 2, 3, 4]);
    let arc = Arc::new(s);
    let mut handles = vec![];
    for _ in 0..4 {
        let c = Arc::clone(&arc);
        handles.push(thread::spawn(move || {
            let mut acc = 0u64;
            for _ in 0..100 {
                acc = acc.wrapping_add(c.get_reg("rip").unwrap_or(0));
                let _ = c.read_mem(0x4000, 4);
            }
            acc
        }));
    }
    for h in handles {
        let v = h.join().unwrap();
        assert_eq!(v, 0x1000u64.wrapping_mul(100));
    }
}

// ── Serde round trip ────────────────────────────────────────────────────────

#[test]
fn trace_serde_round_trip_json() {
    let t = build_simple_trace();
    let json = serde_json::to_string(&t).expect("ser");
    let back: TtdTrace = serde_json::from_str(&json).expect("de");
    assert_eq!(back.len(), t.len());
    assert_eq!(back.max_tick(), t.max_tick());
}

#[test]
fn memwrite_serde_round_trip_fuzz() {
    let mut g = lcg_seed();
    for _ in 0..50 {
        let addr = g();
        let len = (g() & 0x1F) as usize;
        let data: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let w = MemWriteRecord::new(addr, data);
        let json = serde_json::to_string(&w).unwrap();
        let back: MemWriteRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }
}
