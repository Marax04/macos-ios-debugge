//! Blitz test suite for rustre-ttd-replayer public API.
//!
//! Focused on the surface re-exported from lib.rs: `MemWriteRecord`, `TraceEvent`,
//! `TraceSnapshot`, `TtdTrace`, `ReplayState`, `TtdReplayer`, `TtdQuery`, `RootCauseReport`,
//! `TraceBuilder`, `TraceStats`, `MemoryDiff`, `ReplayIterator`, `SyscallSummary`,
//! `WatchpointHit`, `TickRange`, `EventFilter`, `ReplayCheckpoint`, `ReplaySession`,
//! `MemoryRegion`, `MemoryMap`, `QueryBatch`, helpers (`hex_dump`, `parse_hex`, `format_tick`),
//! `find_root_cause`, `build_syscall_summaries`, `scan_for_writes`.

use std::collections::HashMap;

use rustre_ttd_replayer::{
    build_syscall_summaries, find_root_cause, format_tick, hex_dump, parse_hex, scan_for_writes,
    CausalStep, EventFilter, MemWriteRecord, MemoryDiff, MemoryMap, MemoryRegion, QueryAst,
    QueryBatch, QueryValue, ReplayCheckpoint, ReplayError, ReplayIterator, ReplaySession,
    ReplayState, RootCauseReport, SyscallSummary, TickRange, TraceBuilder, TraceEvent,
    TraceSnapshot, TraceStats, TtdQuery, TtdReplayer, TtdTrace, DEFAULT_SNAPSHOT_INTERVAL,
    MAX_MEM_WRITES_PER_EVENT, REPLAY_PAGE_SIZE,
};

// ─── helpers ──────────────────────────────────────────────────────────────────

// NOT a `const fn`: `Vec<u8>` has a destructor, which is not permitted in a
// const context, so const-ness here could never have compiled regardless of
// the duplicated keyword this replaces.
const fn write(addr: u64, data: Vec<u8>) -> MemWriteRecord {
    MemWriteRecord::new(addr, data)
}

fn small_trace() -> TtdTrace {
    let mut b = TraceBuilder::new(8);
    b.syscall_entry(1, [0; 6]);
    b.syscall_exit(0, vec![write(0x1000, vec![1, 2, 3, 4, 5, 6, 7, 8])]);
    b.syscall_entry(2, [0; 6]);
    b.syscall_exit(0, vec![write(0x2000, vec![0xAA; 16])]);
    b.signal(11, 0xBAD);
    b.build()
}

// ─── constants ────────────────────────────────────────────────────────────────

#[test]
fn const_defaults() {
    assert_eq!(DEFAULT_SNAPSHOT_INTERVAL, 256);
    assert_eq!(REPLAY_PAGE_SIZE, 4096);
    assert_eq!(MAX_MEM_WRITES_PER_EVENT, 1024);
}

// ─── MemWriteRecord ───────────────────────────────────────────────────────────

#[test]
fn mwr_size_and_end_addr() {
    let w = write(0x10, vec![0u8; 16]);
    assert_eq!(w.size(), 16);
    assert_eq!(w.end_addr(), 0x1F);
}

#[test]
fn mwr_end_addr_empty() {
    // Empty write: end_addr saturates. 0 + 0 - 1 saturates to 0.
    let w = write(0x10, vec![]);
    assert_eq!(w.size(), 0);
    // saturating_sub on 0x10 - 1 = 0xF. (addr + len = 0x10; -1 = 0xF.)
    assert_eq!(w.end_addr(), 0xF);
}

#[test]
fn mwr_end_addr_saturates_at_zero() {
    let w = write(0, vec![]);
    assert_eq!(w.end_addr(), 0); // saturates at 0, not underflow
}

#[test]
fn mwr_overlaps_basic() {
    let w = write(100, vec![0u8; 10]); // [100,110)
    assert!(w.overlaps(100, 1));
    assert!(w.overlaps(109, 1));
    assert!(!w.overlaps(110, 1));
    assert!(!w.overlaps(99, 1));
    assert!(w.overlaps(99, 2));
    assert!(w.overlaps(105, 100));
    assert!(w.overlaps(0, 1000));
}

#[test]
fn mwr_overlaps_zero_size() {
    let w = write(100, vec![0u8; 10]);
    // A zero-length range overlaps NOTHING — an empty interval contains no
    // byte, so it cannot share one with [100, 110).
    //
    // This assertion used to be inverted: it pinned the old arithmetic
    // (range_end == addr, so addr=105 landed strictly inside the record) and
    // its own comment conceded the pinned behaviour was "arguably wrong".
    // `MemWriteRecord::overlaps` now early-returns false for `size == 0`
    // (lib.rs:135), so the test was pinning a bug that had already been fixed.
    // It stayed invisible because a duplicated `const` keyword above kept this
    // whole file from compiling.
    assert!(!w.overlaps(105, 0), "a zero-length range overlaps nothing");
    // Interior, non-empty range still overlaps — guards against "fixing" the
    // zero-size case by making overlaps() reject everything.
    assert!(w.overlaps(105, 1));
}

#[test]
fn mwr_bytes_in_range_full() {
    let w = write(0, (0u8..16).collect());
    assert_eq!(w.bytes_in_range(0, 16), (0u8..16).collect::<Vec<_>>());
}

#[test]
fn mwr_bytes_in_range_partial_start() {
    let w = write(10, vec![1, 2, 3, 4, 5]);
    assert_eq!(w.bytes_in_range(8, 4), vec![1, 2]);
}

#[test]
fn mwr_bytes_in_range_partial_end() {
    let w = write(10, vec![1, 2, 3, 4, 5]); // [10,15)
    assert_eq!(w.bytes_in_range(13, 100), vec![4, 5]);
}

#[test]
fn mwr_bytes_in_range_no_overlap() {
    let w = write(10, vec![1, 2, 3]);
    assert!(w.bytes_in_range(100, 4).is_empty());
}

#[test]
fn mwr_display() {
    let w = write(0x1000, vec![0u8; 4]);
    let s = format!("{w}");
    assert!(s.contains("0x1000"));
    assert!(s.contains("size: 4"));
}

#[test]
fn mwr_equality() {
    assert_eq!(write(1, vec![1, 2]), write(1, vec![1, 2]));
    assert_ne!(write(1, vec![1, 2]), write(2, vec![1, 2]));
}

#[test]
fn mwr_serde_roundtrip() {
    let w = write(0xCAFE, vec![1, 2, 3]);
    let j = serde_json::to_string(&w).unwrap();
    let back: MemWriteRecord = serde_json::from_str(&j).unwrap();
    assert_eq!(w, back);
}

// ─── TraceEvent ───────────────────────────────────────────────────────────────

#[test]
fn te_syscall_nr() {
    let e = TraceEvent::SyscallEntry { tick: 0, nr: 42, args: [0; 6] };
    assert_eq!(e.syscall_nr(), Some(42));
    let e = TraceEvent::SyscallExit { tick: 0, retval: 0, mem_writes: vec![] };
    assert_eq!(e.syscall_nr(), None); // exit doesn't carry nr
    let e = TraceEvent::SignalDelivered { tick: 0, signal: 9, pc: 0 };
    assert_eq!(e.syscall_nr(), None);
}

#[test]
fn te_mem_writes_empty_for_non_exit() {
    let e = TraceEvent::SyscallEntry { tick: 0, nr: 0, args: [0; 6] };
    assert!(e.mem_writes().is_empty());
    let e = TraceEvent::SignalDelivered { tick: 0, signal: 0, pc: 0 };
    assert!(e.mem_writes().is_empty());
}

#[test]
fn te_display_each_variant() {
    let s = format!("{}", TraceEvent::SyscallEntry { tick: 7, nr: 1, args: [0; 6] });
    assert!(s.contains("SyscallEntry"));
    assert!(s.contains("[7]"));
    let s = format!("{}", TraceEvent::SyscallExit { tick: 8, retval: -1, mem_writes: vec![] });
    assert!(s.contains("SyscallExit"));
    assert!(s.contains("retval=-1"));
    let s = format!("{}", TraceEvent::SignalDelivered { tick: 9, signal: 11, pc: 0xBAD });
    assert!(s.contains("SignalDelivered"));
    assert!(s.contains("signal=11"));
}

// ─── TraceSnapshot ────────────────────────────────────────────────────────────

#[test]
fn snap_page_count_and_footprint() {
    let mut s = TraceSnapshot::new(0);
    s.write_mem(0, &[1, 2, 3]);
    s.write_mem(REPLAY_PAGE_SIZE as u64, &[1]);
    assert_eq!(s.page_count(), 2);
    assert!(s.memory_footprint() >= 2 * REPLAY_PAGE_SIZE);
}

#[test]
fn snap_read_partial_returns_none() {
    let mut s = TraceSnapshot::new(0);
    s.write_mem(0, &[1, 2, 3, 4]);
    // Read past end of mapped page boundary into unmapped page.
    let r = s.read_mem(REPLAY_PAGE_SIZE as u64 - 2, 4);
    assert!(r.is_none());
}

#[test]
fn snap_overwrite_same_address() {
    let mut s = TraceSnapshot::new(0);
    s.write_mem(0x10, &[1, 1, 1, 1]);
    s.write_mem(0x10, &[2, 2]);
    assert_eq!(s.read_mem(0x10, 4).unwrap(), vec![2, 2, 1, 1]);
}

#[test]
fn snap_write_empty_is_noop() {
    let mut s = TraceSnapshot::new(0);
    s.write_mem(0x10, &[]);
    assert_eq!(s.page_count(), 0);
}

// ─── TtdTrace ────────────────────────────────────────────────────────────────

#[test]
fn trace_empty_defaults() {
    let t = TtdTrace::new();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert_eq!(t.min_tick(), 0);
    assert_eq!(t.max_tick(), 0);
    assert!(t.first_event_at_or_after(0).is_none());
    assert!(t.last_event_at_or_before(0).is_none());
    assert!(t.nearest_snapshot_before(100).is_none());
}

#[test]
fn trace_default_eq_new() {
    let a = TtdTrace::default();
    let b = TtdTrace::new();
    assert_eq!(a.events.len(), b.events.len());
}

#[test]
fn trace_push_event_keeps_tick_index_sorted() {
    let mut t = TtdTrace::new();
    t.push_event(TraceEvent::SyscallEntry { tick: 5, nr: 0, args: [0; 6] });
    t.push_event(TraceEvent::SyscallEntry { tick: 1, nr: 0, args: [0; 6] });
    t.push_event(TraceEvent::SyscallEntry { tick: 3, nr: 0, args: [0; 6] });
    let ticks: Vec<u64> = t.tick_index.iter().map(|&(t, _)| t).collect();
    assert_eq!(ticks, vec![1, 3, 5]);
}

#[test]
fn trace_first_event_at_or_after() {
    let t = small_trace();
    // Events at ticks 0,1,2,3,4. Query at 2 -> idx for tick 2.
    let idx = t.first_event_at_or_after(2).unwrap();
    assert_eq!(t.events[idx].tick(), 2);
    let idx = t.first_event_at_or_after(0).unwrap();
    assert_eq!(t.events[idx].tick(), 0);
    assert!(t.first_event_at_or_after(1000).is_none());
}

#[test]
fn trace_last_event_at_or_before() {
    let t = small_trace();
    let idx = t.last_event_at_or_before(3).unwrap();
    assert_eq!(t.events[idx].tick(), 3);
    assert!(t.last_event_at_or_before(0).is_some());
}

#[test]
fn trace_push_snapshot_sorted() {
    let mut t = TtdTrace::new();
    t.push_snapshot(TraceSnapshot::new(10));
    t.push_snapshot(TraceSnapshot::new(2));
    t.push_snapshot(TraceSnapshot::new(7));
    let ticks: Vec<u64> = t.snapshots.iter().map(|s| s.tick).collect();
    assert_eq!(ticks, vec![2, 7, 10]);
}

#[test]
fn trace_nearest_snapshot_before_exact() {
    let mut t = TtdTrace::new();
    t.push_snapshot(TraceSnapshot::new(5));
    let s = t.nearest_snapshot_before(5).unwrap();
    assert_eq!(s.tick, 5);
}

#[test]
fn trace_event_counts_empty() {
    let t = TtdTrace::new();
    assert!(t.event_counts().is_empty());
}

#[test]
fn trace_all_writes_touching_multiple() {
    let mut b = TraceBuilder::new(8);
    b.syscall_exit(0, vec![write(0x100, vec![0u8; 16])]);
    b.syscall_exit(0, vec![write(0x108, vec![0u8; 4])]);
    b.syscall_exit(0, vec![write(0x200, vec![0u8; 4])]);
    let t = b.build();
    let writes = t.all_writes_touching(0x100, 16);
    assert_eq!(writes.len(), 2);
}

// ─── ReplayState ──────────────────────────────────────────────────────────────

#[test]
fn rs_reg_default_zero() {
    let s = ReplayState::new();
    assert_eq!(s.reg("rax"), 0);
}

#[test]
fn rs_apply_write_cross_page() {
    let mut s = ReplayState::new();
    s.apply_write(&write(REPLAY_PAGE_SIZE as u64 - 4, vec![1, 2, 3, 4, 5, 6, 7, 8]));
    let r = s.read(REPLAY_PAGE_SIZE as u64 - 4, 8).unwrap();
    assert_eq!(r, vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn rs_program_counter_priority() {
    let mut s = ReplayState::new();
    s.set_reg("eip", 0xAAAA);
    s.set_reg("rip", 0xBBBB);
    // "rip" comes first in lookup order.
    assert_eq!(s.program_counter(), Some(0xBBBB));
}

#[test]
fn rs_program_counter_none() {
    let s = ReplayState::new();
    assert!(s.program_counter().is_none());
}

#[test]
fn rs_program_counter_pc_alias() {
    let mut s = ReplayState::new();
    s.set_reg("pc", 0x1234);
    assert_eq!(s.program_counter(), Some(0x1234));
}

#[test]
fn rs_load_snapshot_replaces_state() {
    let mut s = ReplayState::new();
    s.set_reg("rax", 99);
    s.apply_write(&write(0x10, vec![1, 2, 3]));
    let mut snap = TraceSnapshot::new(0);
    snap.set_reg("rbx", 7);
    s.load_snapshot(&snap);
    assert_eq!(s.reg("rax"), 0);
    assert_eq!(s.reg("rbx"), 7);
    assert!(s.read(0x10, 1).is_none());
}

// ─── TtdReplayer navigation ───────────────────────────────────────────────────

#[test]
fn replayer_new_empty_trace() {
    let r = TtdReplayer::new(TtdTrace::new());
    assert!(r.at_start());
    assert!(r.at_end());
    assert_eq!(r.remaining_events(), 0);
    assert!(r.pc().is_none());
}

#[test]
fn replayer_step_forward_then_at_end() {
    let mut r = TtdReplayer::new(small_trace());
    let mut count = 0;
    while r.step_forward().is_ok() {
        count += 1;
    }
    assert_eq!(count, 5);
    assert!(r.at_end());
    assert!(matches!(r.step_forward(), Err(ReplayError::AtEnd)));
}

#[test]
fn replayer_step_backward_at_start() {
    let mut r = TtdReplayer::new(small_trace());
    assert!(matches!(r.step_backward(), Err(ReplayError::AtStart)));
}

#[test]
fn replayer_goto_oob() {
    let mut r = TtdReplayer::new(small_trace());
    let e = r.goto(9999).unwrap_err();
    assert!(matches!(e, ReplayError::TickOutOfRange(9999, _)));
}

#[test]
fn replayer_goto_then_back() {
    let mut r = TtdReplayer::new(small_trace());
    r.goto(3).unwrap();
    // After tick 3, write at 0x2000 should be visible.
    assert_eq!(r.state.read(0x2000, 16), Some(vec![0xAA; 16]));
    r.goto(1).unwrap();
    // After tick 1, write at 0x1000 visible but not 0x2000.
    assert_eq!(r.state.read(0x1000, 8), Some(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    assert!(r.state.read(0x2000, 1).is_none());
}

#[test]
fn replayer_reset() {
    let mut r = TtdReplayer::new(small_trace());
    r.goto(3).unwrap();
    r.reset();
    assert_eq!(r.current_tick, 0);
}

#[test]
fn replayer_step_backward_after_forward() {
    let mut r = TtdReplayer::new(small_trace());
    r.step_forward().unwrap(); // applied event 0 (tick 0)
    r.step_forward().unwrap(); // applied event 1 (tick 1)
    let ev = r.step_backward().unwrap().clone();
    // step_backward seeks to event before last applied, so we should be at tick 0.
    assert_eq!(ev.tick(), 0);
}

#[test]
fn replayer_find_all_writes_to() {
    let r = TtdReplayer::new(small_trace());
    let hits = r.find_all_writes_to(0x1000, 8);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].0, 1);
    assert_eq!(hits[0].1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn replayer_read_memory_at_tick_oob() {
    let r = TtdReplayer::new(small_trace());
    let e = r.read_memory_at_tick(9999, 0, 1).unwrap_err();
    assert!(matches!(e, ReplayError::TickOutOfRange(_, _)));
}

#[test]
fn replayer_read_memory_at_tick_unmapped() {
    let r = TtdReplayer::new(small_trace());
    let e = r.read_memory_at_tick(4, 0xFEED_FACE, 4).unwrap_err();
    assert!(matches!(e, ReplayError::AddressNotMapped(_, _)));
}

#[test]
fn replayer_read_memory_at_tick_returns_latest() {
    // Write at tick 1; reading at tick 4 should show the same bytes.
    let r = TtdReplayer::new(small_trace());
    let bytes = r.read_memory_at_tick(4, 0x1000, 8).unwrap();
    assert_eq!(bytes, vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn replayer_find_last_write_before() {
    let mut b = TraceBuilder::new(8);
    b.syscall_exit(0, vec![write(0x100, vec![0xAA; 4])]); // tick 0
    b.syscall_exit(0, vec![write(0x100, vec![0xBB; 4])]); // tick 1
    b.syscall_exit(0, vec![write(0x100, vec![0xCC; 4])]); // tick 2
    let t = b.build();
    let r = TtdReplayer::new(t);
    let (tick, _) = r.find_last_write_before(0x100, 2).unwrap();
    assert_eq!(tick, 1);
    assert!(r.find_last_write_before(0x100, 0).is_none());
}

#[test]
fn replayer_find_last_write_range_before() {
    let mut b = TraceBuilder::new(8);
    b.syscall_exit(0, vec![write(0x100, vec![1; 8])]); // tick 0
    b.syscall_exit(0, vec![write(0x100, vec![2; 8])]); // tick 1
    let t = b.build();
    let r = TtdReplayer::new(t);
    let (tick, bytes) = r.find_last_write_range_before(0x100, 8, 5).unwrap();
    assert_eq!(tick, 1);
    assert_eq!(bytes, vec![2; 8]);
}

// ─── TraceBuilder ─────────────────────────────────────────────────────────────

#[test]
fn builder_tick_counter_monotonic() {
    let mut b = TraceBuilder::new(4);
    let t0 = b.syscall_entry(1, [0; 6]);
    let t1 = b.syscall_exit(0, vec![]);
    let t2 = b.signal(11, 0);
    assert_eq!(t0, 0);
    assert_eq!(t1, 1);
    assert_eq!(t2, 2);
}

#[test]
fn builder_snapshot_boundary_zero_interval() {
    let b = TraceBuilder::new(0);
    // Zero interval: never on a boundary (per current implementation).
    assert!(!b.next_tick_is_snapshot_boundary());
}

#[test]
fn builder_snapshot_boundary_nonzero() {
    let b = TraceBuilder::new(4);
    assert!(b.next_tick_is_snapshot_boundary()); // tick 0 % 4 == 0
}

#[test]
fn builder_snapshot_interval_getter() {
    let b = TraceBuilder::new(13);
    assert_eq!(b.snapshot_interval(), 13);
}

#[test]
fn builder_build_rebuilds_tick_index() {
    let mut b = TraceBuilder::new(4);
    b.syscall_entry(1, [0; 6]);
    b.syscall_exit(0, vec![]);
    let t = b.build();
    assert_eq!(t.tick_index.len(), 2);
    assert!(t.first_event_at_or_after(0).is_some());
}

#[test]
fn builder_snapshot_attaches_at_current_tick() {
    let mut b = TraceBuilder::new(4);
    b.syscall_entry(1, [0; 6]); // tick 0, counter -> 1
    let mut regs = HashMap::new();
    regs.insert("rax".into(), 7);
    b.snapshot(regs, HashMap::new());
    let t = b.build();
    assert_eq!(t.snapshots.len(), 1);
    assert_eq!(t.snapshots[0].tick, 1);
}

// ─── QueryAst / TtdQuery ──────────────────────────────────────────────────────

#[test]
fn query_parse_read_mem() {
    let q = TtdQuery::parse("read_mem 10 0x1000 4").unwrap();
    assert!(matches!(q.ast, QueryAst::ReadMem { tick: 10, addr: 0x1000, size: 4 }));
}

#[test]
fn query_parse_find_writes_dec() {
    let q = TtdQuery::parse("find_writes 4096 8").unwrap();
    assert!(matches!(q.ast, QueryAst::FindWrites { addr: 4096, size: 8 }));
}

#[test]
fn query_parse_hex_uppercase_prefix() {
    let q = TtdQuery::parse("last_write 0XCAFE 5").unwrap();
    assert!(matches!(q.ast, QueryAst::LastWrite { addr: 0xCAFE, tick: 5 }));
}

#[test]
fn query_parse_empty_fails() {
    let e = TtdQuery::parse("").unwrap_err();
    assert!(matches!(e, ReplayError::QueryParse(_)));
}

#[test]
fn query_parse_unknown_cmd() {
    let e = TtdQuery::parse("frobnicate 1 2").unwrap_err();
    if let ReplayError::QueryParse(s) = e {
        assert!(s.contains("unknown command"));
    } else {
        panic!();
    }
}

#[test]
fn query_parse_missing_args() {
    assert!(TtdQuery::parse("read_mem").is_err());
    assert!(TtdQuery::parse("read_mem 1").is_err());
    assert!(TtdQuery::parse("read_mem 1 0x1000").is_err());
    assert!(TtdQuery::parse("find_writes").is_err());
    assert!(TtdQuery::parse("last_write 1").is_err());
    assert!(TtdQuery::parse("read_reg 1").is_err());
    assert!(TtdQuery::parse("count_events").is_err());
    assert!(TtdQuery::parse("root_cause 1").is_err());
}

#[test]
fn query_parse_bad_int() {
    let e = TtdQuery::parse("read_mem abc 0x10 4").unwrap_err();
    assert!(matches!(e, ReplayError::QueryParse(_)));
}

#[test]
fn query_parse_list_syscalls_no_filter() {
    let q = TtdQuery::parse("list_syscalls").unwrap();
    assert!(matches!(q.ast, QueryAst::ListSyscalls { nr: None }));
}

#[test]
fn query_parse_list_syscalls_with_nr() {
    let q = TtdQuery::parse("list_syscalls 42").unwrap();
    assert!(matches!(q.ast, QueryAst::ListSyscalls { nr: Some(42) }));
}

#[test]
fn query_parse_min_max_tick() {
    assert!(matches!(TtdQuery::parse("max_tick").unwrap().ast, QueryAst::MaxTick));
    assert!(matches!(TtdQuery::parse("min_tick").unwrap().ast, QueryAst::MinTick));
}

#[test]
fn query_execute_max_min_tick() {
    let mut r = TtdReplayer::new(small_trace());
    let v = TtdQuery::parse("max_tick").unwrap().execute(&mut r).unwrap();
    assert_eq!(v, QueryValue::Int(4));
    let v = TtdQuery::parse("min_tick").unwrap().execute(&mut r).unwrap();
    assert_eq!(v, QueryValue::Int(0));
}

#[test]
fn query_execute_count_events() {
    let mut r = TtdReplayer::new(small_trace());
    let v = TtdQuery::parse("count_events SyscallEntry").unwrap().execute(&mut r).unwrap();
    assert_eq!(v, QueryValue::Int(2));
    let v = TtdQuery::parse("count_events SignalDelivered").unwrap().execute(&mut r).unwrap();
    assert_eq!(v, QueryValue::Int(1));
    let v = TtdQuery::parse("count_events Bogus").unwrap().execute(&mut r).unwrap();
    assert_eq!(v, QueryValue::Int(0));
}

#[test]
fn query_execute_list_syscalls_filter() {
    let mut r = TtdReplayer::new(small_trace());
    let v = TtdQuery::parse("list_syscalls 1").unwrap().execute(&mut r).unwrap();
    if let QueryValue::EventList(l) = v {
        assert_eq!(l.len(), 1);
    } else {
        panic!();
    }
}

#[test]
fn query_execute_list_signals() {
    let mut r = TtdReplayer::new(small_trace());
    let v = TtdQuery::parse("list_signals").unwrap().execute(&mut r).unwrap();
    if let QueryValue::EventList(l) = v {
        assert_eq!(l.len(), 1);
    } else {
        panic!();
    }
}

#[test]
fn query_execute_read_mem() {
    let mut r = TtdReplayer::new(small_trace());
    let v = TtdQuery::parse("read_mem 4 0x1000 4").unwrap().execute(&mut r).unwrap();
    assert_eq!(v, QueryValue::Bytes(vec![1, 2, 3, 4]));
}

#[test]
fn query_execute_find_writes() {
    let mut r = TtdReplayer::new(small_trace());
    let v = TtdQuery::parse("find_writes 0x1000 8").unwrap().execute(&mut r).unwrap();
    if let QueryValue::WriteList(l) = v {
        assert_eq!(l.len(), 1);
    } else {
        panic!();
    }
}

#[test]
fn query_execute_last_write_none() {
    let mut r = TtdReplayer::new(small_trace());
    let v = TtdQuery::parse("last_write 0xDEADBEEF 100").unwrap().execute(&mut r).unwrap();
    assert_eq!(v, QueryValue::Null);
}

#[test]
fn query_execute_read_reg() {
    let mut r = TtdReplayer::new(small_trace());
    let v = TtdQuery::parse("read_reg 4 nonexistent").unwrap().execute(&mut r).unwrap();
    assert_eq!(v, QueryValue::Int(0));
}

#[test]
fn query_value_display() {
    assert_eq!(format!("{}", QueryValue::Int(42)), "42");
    assert_eq!(format!("{}", QueryValue::SignedInt(-1)), "-1");
    assert_eq!(format!("{}", QueryValue::Null), "null");
    assert_eq!(format!("{}", QueryValue::Text("hi".into())), "hi");
    assert!(format!("{}", QueryValue::Bytes(vec![0; 3])).contains("len=3"));
}

// ─── find_root_cause / RootCauseReport ────────────────────────────────────────

#[test]
fn root_cause_no_prior_writes() {
    let mut r = TtdReplayer::new(TtdTrace::new());
    let rep = find_root_cause(&mut r, 100, 0xDEAD).unwrap();
    assert_eq!(rep.crash_tick, 100);
    assert_eq!(rep.crash_addr, 0xDEAD);
    assert!(rep.confidence > 0.0);
    assert!(!rep.chain.is_empty());
}

#[test]
fn root_cause_with_prior_write() {
    let mut b = TraceBuilder::new(8);
    b.syscall_entry(1, [0; 6]); // tick 0
    b.syscall_exit(0, vec![write(0x4000, vec![0; 8])]); // tick 1
    let t = b.build();
    let mut r = TtdReplayer::new(t);
    let rep = find_root_cause(&mut r, 5, 0x4000).unwrap();
    assert!(rep.chain.len() >= 2);
    assert!(rep.confidence >= 0.5);
}

#[test]
fn root_cause_report_earliest_cause() {
    let mut rep = RootCauseReport::new(0, 0);
    rep.push_step(CausalStep::new(1, "first"));
    rep.push_step(CausalStep::new(2, "second"));
    assert_eq!(rep.earliest_cause().unwrap().description, "second");
}

#[test]
fn root_cause_display() {
    let mut rep = RootCauseReport::new(10, 0xDEAD);
    rep.push_step(CausalStep::new(5, "boom").with_addr(0x100).with_data(vec![1, 2, 3]));
    let s = format!("{rep}");
    assert!(s.contains("Root Cause"));
    assert!(s.contains("0xdead"));
    assert!(s.contains("boom"));
}

// ─── TraceStats ───────────────────────────────────────────────────────────────

#[test]
fn stats_compute() {
    let t = small_trace();
    let s = TraceStats::compute(&t);
    assert_eq!(s.total_events, 5);
    assert_eq!(s.syscall_entries, 2);
    assert_eq!(s.syscall_exits, 2);
    assert_eq!(s.signals, 1);
    assert_eq!(s.total_bytes_written, 8 + 16);
    assert_eq!(s.unique_write_addrs, 2);
    assert!(s.syscall_freq.contains_key(&1));
}

#[test]
fn stats_compute_empty() {
    let s = TraceStats::compute(&TtdTrace::new());
    assert_eq!(s.total_events, 0);
    assert_eq!(s.min_tick, 0);
    assert_eq!(s.max_tick, 0);
}

#[test]
fn stats_display() {
    let t = small_trace();
    let s = format!("{}", TraceStats::compute(&t));
    assert!(s.contains("TraceStats"));
    assert!(s.contains("total_events"));
}

// ─── MemoryDiff ───────────────────────────────────────────────────────────────

#[test]
fn diff_empty_states() {
    let d = MemoryDiff::compute(&ReplayState::new(), &ReplayState::new());
    assert!(d.is_empty());
    assert_eq!(d.differing_bytes(), 0);
}

#[test]
fn diff_added_pages() {
    let old = ReplayState::new();
    let mut new = ReplayState::new();
    new.apply_write(&write(0, vec![1; 16]));
    let d = MemoryDiff::compute(&old, &new);
    assert_eq!(d.added_pages.len(), 1);
    assert!(d.removed_pages.is_empty());
}

#[test]
fn diff_removed_pages() {
    let mut old = ReplayState::new();
    old.apply_write(&write(0, vec![1; 16]));
    let new = ReplayState::new();
    let d = MemoryDiff::compute(&old, &new);
    assert_eq!(d.removed_pages.len(), 1);
}

#[test]
fn diff_modified_pages_byte_count() {
    let mut old = ReplayState::new();
    let mut new = ReplayState::new();
    old.apply_write(&write(0, vec![1; 8]));
    new.apply_write(&write(0, vec![2; 8]));
    let d = MemoryDiff::compute(&old, &new);
    assert_eq!(d.modified_pages.len(), 1);
    assert_eq!(d.differing_bytes(), 8);
}

// ─── ReplayIterator ───────────────────────────────────────────────────────────

#[test]
fn iter_drives_to_end() {
    let mut r = TtdReplayer::new(small_trace());
    let it = ReplayIterator::new(&mut r);
    let events: Vec<TraceEvent> = it.collect();
    assert_eq!(events.len(), 5);
}

// ─── build_syscall_summaries ─────────────────────────────────────────────────

#[test]
fn syscall_summaries_basic() {
    let t = small_trace();
    let m = build_syscall_summaries(&t);
    assert!(m.contains_key(&1));
    assert!(m.contains_key(&2));
    assert_eq!(m[&1].call_count, 1);
    assert_eq!(m[&1].entry_ticks, vec![0]);
}

#[test]
fn syscall_summary_new() {
    let s = SyscallSummary::new(99);
    assert_eq!(s.nr, 99);
    assert_eq!(s.call_count, 0);
    assert!(s.retvals.is_empty());
}

// ─── scan_for_writes ─────────────────────────────────────────────────────────

#[test]
fn scan_writes_finds_hits() {
    let t = small_trace();
    let hits = scan_for_writes(&t, 0x2000, 16);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].tick, 3);
    assert_eq!(hits[0].addr, 0x2000);
}

#[test]
fn scan_writes_no_hits() {
    let t = small_trace();
    let hits = scan_for_writes(&t, 0xFEED_FACE, 4);
    assert!(hits.is_empty());
}

// ─── TickRange ────────────────────────────────────────────────────────────────

#[test]
fn tick_range_ok() {
    let r = TickRange::new(1, 10).unwrap();
    assert_eq!(r.duration(), 9);
    assert!(r.contains(1));
    assert!(r.contains(10));
    assert!(!r.contains(11));
}

#[test]
fn tick_range_inverted_errors() {
    assert!(TickRange::new(10, 1).is_err());
}

#[test]
fn tick_range_single_point() {
    let r = TickRange::new(5, 5).unwrap();
    assert_eq!(r.duration(), 0);
    assert!(r.contains(5));
}

#[test]
fn tick_range_overlaps() {
    let a = TickRange::new(1, 5).unwrap();
    let b = TickRange::new(4, 10).unwrap();
    let c = TickRange::new(6, 7).unwrap();
    assert!(a.overlaps(&b));
    assert!(!a.overlaps(&c));
}

#[test]
fn tick_range_display() {
    let r = TickRange::new(2, 9).unwrap();
    assert_eq!(format!("{r}"), "[2..9]");
}

// ─── EventFilter ──────────────────────────────────────────────────────────────

#[test]
fn filter_any() {
    let t = small_trace();
    let r = EventFilter::Any.apply(&t);
    assert_eq!(r.len(), t.events.len());
}

#[test]
fn filter_syscall_only_variants() {
    let t = small_trace();
    assert_eq!(EventFilter::SyscallEntryOnly.apply(&t).len(), 2);
    assert_eq!(EventFilter::SyscallExitOnly.apply(&t).len(), 2);
    assert_eq!(EventFilter::SignalOnly.apply(&t).len(), 1);
}

#[test]
fn filter_signal_nr() {
    let t = small_trace();
    assert_eq!(EventFilter::SignalNr(11).apply(&t).len(), 1);
    assert_eq!(EventFilter::SignalNr(99).apply(&t).len(), 0);
}

#[test]
fn filter_syscall_nr() {
    let t = small_trace();
    assert_eq!(EventFilter::SyscallNr(1).apply(&t).len(), 1);
    assert_eq!(EventFilter::SyscallNr(99).apply(&t).len(), 0);
}

#[test]
fn filter_writes_to_addr() {
    let t = small_trace();
    assert_eq!(EventFilter::WritesToAddr(0x1000).apply(&t).len(), 1);
    assert_eq!(EventFilter::WritesToAddr(0x9999).apply(&t).len(), 0);
}

#[test]
fn filter_range() {
    let t = small_trace();
    let f = EventFilter::TickInRange(TickRange::new(1, 3).unwrap());
    assert_eq!(f.apply(&t).len(), 3);
}

#[test]
fn filter_logic_and_or_not() {
    let t = small_trace();
    let f = EventFilter::And(
        Box::new(EventFilter::SyscallEntryOnly),
        Box::new(EventFilter::SyscallNr(1)),
    );
    assert_eq!(f.apply(&t).len(), 1);
    let f = EventFilter::Or(
        Box::new(EventFilter::SyscallNr(1)),
        Box::new(EventFilter::SyscallNr(2)),
    );
    assert_eq!(f.apply(&t).len(), 2);
    let f = EventFilter::Not(Box::new(EventFilter::SignalOnly));
    assert_eq!(f.apply(&t).len(), 4);
}

// ─── ReplayCheckpoint / ReplaySession ────────────────────────────────────────

#[test]
fn checkpoint_save_restore() {
    let mut r = TtdReplayer::new(small_trace());
    r.step_forward().unwrap();
    r.step_forward().unwrap();
    let cp = ReplayCheckpoint::save(&r, "mid");
    r.step_forward().unwrap();
    let new_tick = r.current_tick;
    cp.restore(&mut r);
    assert_ne!(r.current_tick, new_tick);
    assert_eq!(cp.label, "mid");
}

#[test]
fn session_checkpoint_lifecycle() {
    let mut sess = ReplaySession::new(small_trace());
    sess.step_forward().unwrap();
    let idx = sess.save_checkpoint("a");
    assert_eq!(idx, 0);
    assert_eq!(sess.checkpoint_labels(), vec!["a"]);
    sess.step_forward().unwrap();
    assert!(sess.restore_checkpoint(0));
    assert!(!sess.restore_checkpoint(99));
}

#[test]
fn session_step_backward() {
    let mut sess = ReplaySession::new(small_trace());
    sess.step_forward().unwrap();
    sess.step_forward().unwrap();
    let ev = sess.step_backward().unwrap();
    assert_eq!(ev.tick(), 0);
}

#[test]
fn session_goto() {
    let mut sess = ReplaySession::new(small_trace());
    sess.goto(2).unwrap();
    assert_eq!(sess.replayer.current_tick, 2);
}

// ─── MemoryRegion / MemoryMap ────────────────────────────────────────────────

#[test]
fn region_basics() {
    let r = MemoryRegion::new(0x1000, 0x2000, "heap");
    assert!(r.contains(0x1000));
    assert!(r.contains(0x1FFF));
    assert!(!r.contains(0x2000));
    assert_eq!(r.size(), 0x1000);
    let s = format!("{r}");
    assert!(s.contains("heap"));
    assert!(s.contains("rw-"));
}

#[test]
fn map_add_and_find() {
    let mut m = MemoryMap::new();
    m.add_region(MemoryRegion::new(0x2000, 0x3000, "b"));
    m.add_region(MemoryRegion::new(0x1000, 0x2000, "a"));
    // Should be sorted by start.
    assert_eq!(m.regions[0].start, 0x1000);
    assert!(m.is_mapped(0x1500));
    assert!(!m.is_mapped(0x9999));
    assert_eq!(m.find(0x2500).unwrap().label, "b");
}

// ─── QueryBatch ──────────────────────────────────────────────────────────────

#[test]
fn batch_executes_all() {
    let mut r = TtdReplayer::new(small_trace());
    let mut b = QueryBatch::new();
    b.parse_and_add("max_tick").unwrap();
    b.parse_and_add("min_tick").unwrap();
    b.add(TtdQuery::parse("count_events SyscallEntry").unwrap());
    let results = b.execute_all(&mut r);
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(std::result::Result::is_ok));
}

#[test]
fn batch_default() {
    let b = QueryBatch::default();
    let mut r = TtdReplayer::new(TtdTrace::new());
    assert!(b.execute_all(&mut r).is_empty());
}

#[test]
fn batch_parse_error_propagates() {
    let mut b = QueryBatch::new();
    assert!(b.parse_and_add("bogus_cmd").is_err());
}

// ─── utils ───────────────────────────────────────────────────────────────────

#[test]
fn hex_dump_basic() {
    assert_eq!(hex_dump(&[0xDE, 0xAD, 0xBE, 0xEF]), "DE AD BE EF");
    assert_eq!(hex_dump(&[]), "");
}

#[test]
fn parse_hex_variants() {
    assert_eq!(parse_hex("0xCAFE"), Some(0xCAFE));
    assert_eq!(parse_hex("0XCAFE"), Some(0xCAFE));
    assert_eq!(parse_hex("CAFE"), Some(0xCAFE));
    assert_eq!(parse_hex("  ff  "), Some(0xFF));
    assert_eq!(parse_hex("nothex"), None);
}

#[test]
fn format_tick_zero_padded() {
    assert_eq!(format_tick(1), "0000000000000001");
    assert_eq!(format_tick(0), "0000000000000000");
}

// ─── concurrency ─────────────────────────────────────────────────────────────

#[test]
fn trace_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TtdTrace>();
    assert_send_sync::<TraceEvent>();
    assert_send_sync::<MemWriteRecord>();
    assert_send_sync::<TraceSnapshot>();
    assert_send_sync::<ReplayState>();
}
