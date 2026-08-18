//! Exhaustive blitz tests for rustre-ttd-query (lib.rs surface).

use std::sync::Arc;

use rustre_trace::TraceFilter;
use rustre_ttd::{EventKind, TraceEvent, TraceMetadata, TracePosition, TtdTrace};
use rustre_ttd_query::*;

fn pos(s: u64, st: u64) -> TracePosition {
    TracePosition::new(s, st)
}

fn ev(s: u64, st: u64, tid: u32, kind: EventKind) -> TraceEvent {
    TraceEvent::new(pos(s, st), tid, kind)
}

fn empty_trace() -> Arc<TtdTrace> {
    Arc::new(TtdTrace::new(TraceMetadata::default()))
}

/// Build a deterministic mixed trace.
fn mixed_trace() -> Arc<TtdTrace> {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::Call { from: 0x100, to: 0x200 }));
    t.add_event(ev(1, 0, 1, EventKind::MemWrite { addr: 0x1000, data: vec![0xAA, 0xBB] }));
    t.add_event(ev(2, 0, 1, EventKind::MemRead { addr: 0x1000, len: 2 }));
    t.add_event(ev(3, 0, 2, EventKind::MemWrite { addr: 0x1000, data: vec![0xCC] }));
    t.add_event(ev(4, 0, 1, EventKind::SyscallEnter { nr: 42, args: [1, 2, 3, 4, 5, 6] }));
    t.add_event(ev(5, 0, 1, EventKind::SyscallExit { nr: 42, ret: 0 }));
    t.add_event(ev(6, 0, 1, EventKind::SyscallExit { nr: 99, ret: u64::MAX })); // negative as i64
    t.add_event(ev(7, 0, 1, EventKind::Return { from: 0x200, to: 0x100 }));
    t.add_event(ev(8, 0, 1, EventKind::Exception { code: 0xC0000005, addr: 0xDEAD }));
    t.add_event(ev(9, 0, 3, EventKind::Breakpoint { addr: 0x300 }));
    t.add_event(ev(10, 0, 3, EventKind::ThreadCreate { tid: 4 }));
    t.add_event(ev(11, 0, 4, EventKind::ThreadExit { tid: 4, code: 0 }));
    t.add_event(ev(12, 0, 1, EventKind::Call { from: 0x100, to: 0x500 }));
    t.add_event(ev(13, 0, 1, EventKind::Call { from: 0x500, to: 0x500 })); // recursion
    t.add_event(ev(14, 0, 1, EventKind::Call { from: 0x500, to: 0x500 }));
    t.add_event(ev(15, 0, 1, EventKind::Return { from: 0x500, to: 0x500 }));
    t.add_event(ev(16, 0, 1, EventKind::Return { from: 0x500, to: 0x500 }));
    t.add_event(ev(17, 0, 1, EventKind::Return { from: 0x500, to: 0x100 }));
    Arc::new(t)
}

// ── TimeRange ────────────────────────────────────────────────────────────────

#[test]
fn timerange_contains_inclusive_both_ends() {
    let r = TimeRange::new(pos(1, 0), pos(5, 0));
    assert!(r.contains(&pos(1, 0)));
    assert!(r.contains(&pos(5, 0)));
    assert!(r.contains(&pos(3, 0)));
    assert!(!r.contains(&pos(0, 9)));
    assert!(!r.contains(&pos(5, 1)));
}

#[test]
fn timerange_display() {
    let r = TimeRange::new(pos(1, 0), pos(2, 3));
    let s = format!("{r}");
    assert!(s.starts_with('[') && s.ends_with(']'));
}

// ── QueryFilter ──────────────────────────────────────────────────────────────

#[test]
fn filter_memread_no_range_exact() {
    let f = QueryFilter::MemoryRead { addr: 0x1000, range_bytes: None };
    assert!(f.matches(&ev(0, 0, 1, EventKind::MemRead { addr: 0x1000, len: 1 })));
    assert!(!f.matches(&ev(0, 0, 1, EventKind::MemRead { addr: 0x1001, len: 1 })));
}

#[test]
fn filter_memread_with_range() {
    let f = QueryFilter::MemoryRead { addr: 0x1000, range_bytes: Some(0x10) };
    assert!(f.matches(&ev(0, 0, 1, EventKind::MemRead { addr: 0x1005, len: 1 })));
    assert!(!f.matches(&ev(0, 0, 1, EventKind::MemRead { addr: 0x1100, len: 1 })));
}

#[test]
fn filter_memread_range_overflow_clamps() {
    let f = QueryFilter::MemoryRead { addr: u64::MAX - 1, range_bytes: Some(100) };
    assert!(f.matches(&ev(0, 0, 1, EventKind::MemRead { addr: u64::MAX, len: 1 })));
}

#[test]
fn filter_memread_range_underflow_saturates() {
    let f = QueryFilter::MemoryRead { addr: 5, range_bytes: Some(100) };
    assert!(f.matches(&ev(0, 0, 1, EventKind::MemRead { addr: 0, len: 1 })));
}

#[test]
fn filter_memwrite_matches_only_write() {
    let f = QueryFilter::MemoryWrite { addr: 0x1000, range_bytes: None };
    assert!(f.matches(&ev(0, 0, 1, EventKind::MemWrite { addr: 0x1000, data: vec![1] })));
    assert!(!f.matches(&ev(0, 0, 1, EventKind::MemRead { addr: 0x1000, len: 1 })));
}

#[test]
fn filter_thread_matches() {
    let f = QueryFilter::Thread { tid: 7 };
    assert!(f.matches(&ev(0, 0, 7, EventKind::Breakpoint { addr: 0 })));
    assert!(!f.matches(&ev(0, 0, 8, EventKind::Breakpoint { addr: 0 })));
}

#[test]
fn filter_call_to_from() {
    let to_f = QueryFilter::CallTo { target: 0x200 };
    let from_f = QueryFilter::CallFrom { source: 0x100 };
    let e = ev(0, 0, 1, EventKind::Call { from: 0x100, to: 0x200 });
    assert!(to_f.matches(&e));
    assert!(from_f.matches(&e));
    assert!(!QueryFilter::CallTo { target: 0x999 }.matches(&e));
}

#[test]
fn filter_syscall_matches_enter_and_exit() {
    let f = QueryFilter::SyscallNumber { nr: 5 };
    assert!(f.matches(&ev(0, 0, 1, EventKind::SyscallEnter { nr: 5, args: [0; 6] })));
    assert!(f.matches(&ev(0, 0, 1, EventKind::SyscallExit { nr: 5, ret: 0 })));
    assert!(!f.matches(&ev(0, 0, 1, EventKind::SyscallEnter { nr: 6, args: [0; 6] })));
}

#[test]
fn filter_in_time_range() {
    let f = QueryFilter::InTimeRange(TimeRange::new(pos(1, 0), pos(3, 0)));
    assert!(f.matches(&ev(2, 0, 1, EventKind::Breakpoint { addr: 0 })));
    assert!(!f.matches(&ev(4, 0, 1, EventKind::Breakpoint { addr: 0 })));
}

#[test]
fn filter_exception_thread_lifecycle() {
    let f = QueryFilter::ExceptionCode { code: 0xC0000005 };
    assert!(f.matches(&ev(0, 0, 1, EventKind::Exception { code: 0xC0000005, addr: 0 })));
    let tc = QueryFilter::ThreadCreate;
    assert!(tc.matches(&ev(0, 0, 1, EventKind::ThreadCreate { tid: 5 })));
    let te = QueryFilter::ThreadExit;
    assert!(te.matches(&ev(0, 0, 1, EventKind::ThreadExit { tid: 5, code: 0 })));
}

#[test]
fn filter_display_contains_kind_name() {
    let f = QueryFilter::MemoryRead { addr: 0x10, range_bytes: Some(2) };
    assert!(format!("{f}").contains("MemoryRead"));
}

// ── QueryLogic ───────────────────────────────────────────────────────────────

#[test]
fn querylogic_and_or_not_single() {
    let e = ev(0, 0, 1, EventKind::MemRead { addr: 0x10, len: 1 });
    let f1 = QueryFilter::MemoryRead { addr: 0x10, range_bytes: None };
    let f2 = QueryFilter::Thread { tid: 1 };
    assert!(QueryLogic::And(vec![f1.clone(), f2.clone()]).matches(&e));
    assert!(QueryLogic::Or(vec![f1.clone(), QueryFilter::Thread { tid: 99 }]).matches(&e));
    assert!(!QueryLogic::Not(Box::new(f1.clone())).matches(&e));
    assert!(QueryLogic::Single(f1).matches(&e));
}

// ── EventPattern ─────────────────────────────────────────────────────────────

#[test]
fn pattern_any_variants() {
    let e_call = ev(0, 0, 1, EventKind::Call { from: 1, to: 2 });
    let e_ret = ev(0, 0, 1, EventKind::Return { from: 1, to: 2 });
    let e_sys = ev(0, 0, 1, EventKind::SyscallEnter { nr: 0, args: [0; 6] });
    assert!(EventPattern::AnyCall.matches(&e_call));
    assert!(EventPattern::AnyReturn.matches(&e_ret));
    assert!(EventPattern::AnySyscall.matches(&e_sys));
    assert!(!EventPattern::AnyCall.matches(&e_ret));
}

#[test]
fn pattern_memwrite_with_data() {
    let e = ev(0, 0, 1, EventKind::MemWrite { addr: 0x10, data: vec![1, 2, 3] });
    assert!(EventPattern::MemWriteWithData(0x10, vec![1, 2, 3]).matches(&e));
    assert!(!EventPattern::MemWriteWithData(0x10, vec![1, 2]).matches(&e));
    assert!(!EventPattern::MemWriteWithData(0x11, vec![1, 2, 3]).matches(&e));
}

#[test]
fn pattern_in_position_range_inclusive() {
    let e = ev(5, 0, 1, EventKind::Breakpoint { addr: 0 });
    assert!(EventPattern::InPositionRange(pos(1, 0), pos(5, 0)).matches(&e));
    assert!(EventPattern::InPositionRange(pos(5, 0), pos(5, 0)).matches(&e));
    assert!(!EventPattern::InPositionRange(pos(6, 0), pos(10, 0)).matches(&e));
}

#[test]
fn pattern_display_all_variants_compile() {
    let pats = [
        EventPattern::AnyMemRead, EventPattern::AnyMemWrite, EventPattern::AnyCall,
        EventPattern::AnyReturn, EventPattern::AnySyscall, EventPattern::MemReadAt(1),
        EventPattern::MemWriteAt(1), EventPattern::CallTo(1), EventPattern::CallFrom(1),
        EventPattern::ReturnFrom(1), EventPattern::ReturnTo(1), EventPattern::SyscallNr(1),
        EventPattern::Exception(1), EventPattern::ThreadId(1),
        EventPattern::InPositionRange(pos(0, 0), pos(1, 0)),
        EventPattern::MemWriteWithData(1, vec![0]),
        EventPattern::AnyException, EventPattern::Breakpoint(1),
    ];
    for p in &pats {
        assert!(!format!("{p}").is_empty());
    }
}

// ── EventKindFilter ──────────────────────────────────────────────────────────

#[test]
fn event_kind_filter_any_matches_all() {
    let kinds = [
        EventKind::MemRead { addr: 0, len: 0 },
        EventKind::Call { from: 0, to: 0 },
        EventKind::ThreadCreate { tid: 0 },
    ];
    for k in &kinds {
        assert!(EventKindFilter::Any.matches_kind(k));
    }
}

#[test]
fn event_kind_filter_specific() {
    assert!(EventKindFilter::MemRead.matches_kind(&EventKind::MemRead { addr: 0, len: 0 }));
    assert!(!EventKindFilter::MemRead.matches_kind(&EventKind::MemWrite { addr: 0, data: vec![] }));
    assert!(EventKindFilter::Breakpoint.matches_kind(&EventKind::Breakpoint { addr: 0 }));
}

// ── MatchContext ─────────────────────────────────────────────────────────────

#[test]
fn match_context_empty() {
    let c = MatchContext::empty();
    assert!(c.before.is_empty() && c.after.is_empty());
}

#[test]
fn match_context_with_context_clamps_bounds() {
    let evs: Vec<TraceEvent> = (0..5)
        .map(|i| ev(i, 0, 1, EventKind::Breakpoint { addr: i }))
        .collect();
    let c = MatchContext::with_context(&evs, 0, 2);
    assert!(c.before.is_empty());
    assert_eq!(c.after.len(), 2);
    let c = MatchContext::with_context(&evs, 4, 2);
    assert_eq!(c.before.len(), 2);
    assert!(c.after.is_empty());
    let c = MatchContext::with_context(&evs, 2, 1);
    assert_eq!(c.before.len(), 1);
    assert_eq!(c.after.len(), 1);
}

// ── QueryIndex ───────────────────────────────────────────────────────────────

#[test]
fn query_index_build_populates_indices() {
    let t = mixed_trace();
    let idx = QueryIndex::build(&t.all_events());
    assert!(!idx.calls_to_address(0x200).is_empty());
    assert!(!idx.calls_from_address(0x100).is_empty());
    assert!(!idx.syscalls_for_nr(42).is_empty());
    assert!(!idx.accesses_to_address(0x1000).is_empty());
    assert!(!idx.events_for_thread(1).is_empty());
    assert!(idx.events_for_thread(999).is_empty());
    assert!(idx.calls_to_address(0xdeadbeef).is_empty());
}

#[test]
fn query_index_debug_does_not_panic() {
    let idx = QueryIndex::build(&[]);
    let _ = format!("{idx:?}");
}

// ── QueryEngine: basic queries ───────────────────────────────────────────────

#[test]
fn engine_all_events_returns_all() {
    let t = mixed_trace();
    let n = t.event_count();
    let eng = QueryEngine::new(t);
    let r = eng.execute(&Query::AllEvents);
    assert_eq!(r.len(), n);
    assert!(!r.is_empty());
    assert_eq!(r.events_scanned, n as u64);
    assert_eq!(r.positions().len(), n);
}

#[test]
fn engine_empty_trace_returns_empty() {
    let eng = QueryEngine::new(empty_trace());
    assert!(eng.execute(&Query::AllEvents).is_empty());
    assert!(eng.execute(&Query::EventsOfKind(EventKindFilter::Any)).is_empty());
}

#[test]
fn engine_events_of_kind_filter() {
    let eng = QueryEngine::new(mixed_trace());
    let calls = eng.execute(&Query::EventsOfKind(EventKindFilter::Call));
    assert_eq!(calls.len(), 4);
    let bps = eng.execute(&Query::EventsOfKind(EventKindFilter::Breakpoint));
    assert_eq!(bps.len(), 1);
}

#[test]
fn engine_events_in_range_overlap_semantics() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::MemWrite { addr: 0xFE, data: vec![1, 2, 3, 4] })); // 0xFE..0x102 overlaps [0x100,0x200)
    t.add_event(ev(1, 0, 1, EventKind::MemWrite { addr: 0x200, data: vec![1] })); // exact end, exclusive
    t.add_event(ev(2, 0, 1, EventKind::MemRead { addr: 0x150, len: 4 }));
    let eng = QueryEngine::new(Arc::new(t));
    let r = eng.execute(&Query::EventsInRange { start: 0x100, end: 0x200, kind: MemAccessKind::Any });
    assert_eq!(r.len(), 2, "overlap at 0xFE with len 4 + 0x150 read should match; 0x200 excluded");
}

#[test]
fn engine_events_in_range_filters_read_vs_write() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::MemRead { addr: 0x100, len: 1 }));
    t.add_event(ev(1, 0, 1, EventKind::MemWrite { addr: 0x100, data: vec![1] }));
    let eng = QueryEngine::new(Arc::new(t));
    assert_eq!(eng.execute(&Query::EventsInRange { start: 0, end: 0x1000, kind: MemAccessKind::Read }).len(), 1);
    assert_eq!(eng.execute(&Query::EventsInRange { start: 0, end: 0x1000, kind: MemAccessKind::Write }).len(), 1);
    assert_eq!(eng.execute(&Query::EventsInRange { start: 0, end: 0x1000, kind: MemAccessKind::Any }).len(), 2);
}

#[test]
fn engine_pattern_query() {
    let eng = QueryEngine::new(mixed_trace());
    let r = eng.execute(&Query::Pattern(EventPattern::AnyException));
    assert_eq!(r.len(), 1);
    let r = eng.execute(&Query::Pattern(EventPattern::Breakpoint(0x300)));
    assert_eq!(r.len(), 1);
}

#[test]
fn engine_thread_filter() {
    let eng = QueryEngine::new(mixed_trace());
    let r = eng.execute(&Query::Thread(3));
    assert_eq!(r.len(), 2); // breakpoint + threadcreate
}

#[test]
fn engine_in_time_range_query() {
    let eng = QueryEngine::new(mixed_trace());
    let r = eng.execute(&Query::InTimeRange(TimeRange::new(pos(0, 0), pos(2, 0))));
    assert_eq!(r.len(), 3);
}

#[test]
fn engine_call_chain_finds_calls_from_when_target_present() {
    let eng = QueryEngine::new(mixed_trace());
    let r = eng.execute(&Query::CallChain { from: 0x100, to: 0x200 });
    assert!(!r.is_empty());
    let r2 = eng.execute(&Query::CallChain { from: 0x100, to: 0xDEAD });
    assert!(r2.is_empty(), "no call to 0xDEAD exists");
}

#[test]
fn engine_data_flow_source_before_sink() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::MemWrite { addr: 0xAAA, data: vec![1] })); // source write
    t.add_event(ev(1, 0, 1, EventKind::MemWrite { addr: 0xBBB, data: vec![1] })); // sink after
    t.add_event(ev(2, 0, 1, EventKind::MemWrite { addr: 0xAAA, data: vec![2] })); // source after sink — no downstream sink
    let eng = QueryEngine::new(Arc::new(t));
    let r = eng.execute(&Query::DataFlow { source_addr: 0xAAA, sink_addr: 0xBBB });
    assert_eq!(r.len(), 1);
    assert_eq!(r.matches[0].position, pos(0, 0));
}

#[test]
fn engine_loops_min_iterations() {
    let eng = QueryEngine::new(mixed_trace());
    // 0x500 is called 3 times.
    let r = eng.execute(&Query::Loops { min_iterations: 3 });
    assert!(r.len() >= 3);
    let r2 = eng.execute(&Query::Loops { min_iterations: 100 });
    assert!(r2.is_empty());
}

#[test]
fn engine_sequence_empty_returns_empty() {
    let eng = QueryEngine::new(mixed_trace());
    let r = eng.execute(&Query::Sequence(vec![]));
    assert!(r.is_empty());
}

#[test]
fn engine_sequence_basic_match() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::Call { from: 1, to: 2 }));
    t.add_event(ev(1, 0, 1, EventKind::Return { from: 2, to: 1 }));
    t.add_event(ev(2, 0, 1, EventKind::Call { from: 1, to: 2 }));
    t.add_event(ev(3, 0, 1, EventKind::Return { from: 2, to: 1 }));
    let eng = QueryEngine::new(Arc::new(t));
    let r = eng.execute(&Query::Sequence(vec![EventPattern::AnyCall, EventPattern::AnyReturn]));
    assert_eq!(r.len(), 2, "two complete call/return pairs");
}

#[test]
fn engine_before_after_temporal() {
    let eng = QueryEngine::new(mixed_trace());
    let a = Box::new(Query::Pattern(EventPattern::AnyMemWrite));
    let b = Box::new(Query::Pattern(EventPattern::AnyException));
    let before = eng.execute(&Query::Before { a: a.clone(), b: b.clone() });
    let after = eng.execute(&Query::After { a, b });
    assert!(!before.is_empty(), "writes happen before exception");
    assert!(after.is_empty(), "no writes after the only exception");
}

#[test]
fn engine_and_or_not_composition() {
    let eng = QueryEngine::new(mixed_trace());
    let and = eng.execute(&Query::And(vec![
        Query::Pattern(EventPattern::AnyCall),
        Query::Thread(1),
    ]));
    assert!(!and.is_empty());

    let or = eng.execute(&Query::Or(vec![
        Query::Pattern(EventPattern::AnyException),
        Query::Pattern(EventPattern::Breakpoint(0x300)),
    ]));
    assert_eq!(or.len(), 2);

    let not = eng.execute(&Query::Not(Box::new(Query::Pattern(EventPattern::AnyCall))));
    let total = eng.execute(&Query::AllEvents).len();
    let calls = eng.execute(&Query::Pattern(EventPattern::AnyCall)).len();
    assert_eq!(not.len(), total - calls);
}

#[test]
fn engine_and_empty_returns_empty() {
    let eng = QueryEngine::new(mixed_trace());
    let r = eng.execute(&Query::And(vec![]));
    assert!(r.is_empty());
}

// ── explain ──────────────────────────────────────────────────────────────────

#[test]
fn engine_explain_all_query_variants() {
    let eng = QueryEngine::new(mixed_trace());
    let qs = vec![
        Query::AllEvents,
        Query::EventsOfKind(EventKindFilter::Any),
        Query::EventsInRange { start: 0, end: 0x1000, kind: MemAccessKind::Any },
        Query::CallChain { from: 1, to: 2 },
        Query::DataFlow { source_addr: 1, sink_addr: 2 },
        Query::Loops { min_iterations: 1 },
        Query::Sequence(vec![EventPattern::AnyCall]),
        Query::Pattern(EventPattern::AnyCall),
        Query::Thread(1),
        Query::InTimeRange(TimeRange::new(pos(0, 0), pos(1, 0))),
        Query::Before { a: Box::new(Query::AllEvents), b: Box::new(Query::AllEvents) },
        Query::After { a: Box::new(Query::AllEvents), b: Box::new(Query::AllEvents) },
        Query::And(vec![Query::AllEvents]),
        Query::Or(vec![Query::AllEvents]),
        Query::Not(Box::new(Query::AllEvents)),
    ];
    for q in &qs {
        let plan = eng.explain(q);
        assert!(!plan.description.is_empty());
        let _ = format!("{plan}");
        let _ = format!("{q}");
    }
}

// ── bridges: core address & TraceFilter ──────────────────────────────────────

#[test]
fn engine_execute_in_core_address_range_bridges() {
    use rustre_core::address::Address as A;
    let eng = QueryEngine::new(mixed_trace());
    let r = eng.execute_in_core_address_range(A::new(0), A::new(0x10000), MemAccessKind::Any);
    assert!(!r.is_empty());
}

#[test]
fn engine_execute_with_trace_filter_address_and_thread() {
    let eng = QueryEngine::new(mixed_trace());
    let mut f = TraceFilter::default();
    f.min_addr = Some(0);
    f.max_addr = Some(0x10000);
    f.thread_id = Some(2);
    let r = eng.execute_with_trace_filter(&f);
    assert!(r.matches.iter().all(|m| m.event.thread_id == 2));
}

#[test]
fn engine_execute_with_trace_filter_no_range_falls_back_to_all() {
    let eng = QueryEngine::new(mixed_trace());
    let f = TraceFilter::default();
    let r = eng.execute_with_trace_filter(&f);
    let total = eng.execute(&Query::AllEvents).len();
    assert_eq!(r.len(), total);
}

// ── legacy filter helpers ────────────────────────────────────────────────────

#[test]
fn engine_execute_logic_and_count_and_first_last() {
    let eng = QueryEngine::new(mixed_trace());
    let f = QueryFilter::Thread { tid: 1 };
    let logic = QueryLogic::Single(f.clone());
    let r = eng.execute_logic(&logic);
    assert_eq!(r.total_matched, r.events.len());
    assert!(eng.count(&f) > 0);
    assert!(eng.first_occurrence(&f).is_some());
    assert!(eng.last_occurrence(&f).is_some());
    let no = QueryFilter::Thread { tid: 99 };
    assert_eq!(eng.count(&no), 0);
    assert!(eng.first_occurrence(&no).is_none());
    assert!(eng.last_occurrence(&no).is_none());
}

#[test]
fn engine_execute_filter_against_supplied_events() {
    let eng = QueryEngine::new(empty_trace());
    let evs = vec![
        ev(0, 0, 1, EventKind::Breakpoint { addr: 1 }),
        ev(1, 0, 2, EventKind::Breakpoint { addr: 1 }),
    ];
    let out = eng.execute_filter(&QueryFilter::Thread { tid: 2 }, &evs);
    assert_eq!(out.len(), 1);
}

// ── analysis ─────────────────────────────────────────────────────────────────

#[test]
fn analyze_memory_access_patterns_counts_correctly() {
    let eng = QueryEngine::new(mixed_trace());
    let rep = eng.analyze_memory_access_patterns(0, 0x10000);
    assert_eq!(rep.range_start, 0);
    assert_eq!(rep.range_end, 0x10000);
    assert!(rep.total_reads >= 1);
    assert!(rep.total_writes >= 2);
    assert!(rep.first_access.is_some());
    assert!(rep.last_access.is_some());
}

#[test]
fn analyze_memory_access_patterns_empty_range() {
    let eng = QueryEngine::new(mixed_trace());
    let rep = eng.analyze_memory_access_patterns(0x90000, 0x99000);
    assert_eq!(rep.total_reads, 0);
    assert_eq!(rep.total_writes, 0);
    assert!(rep.first_access.is_none());
}

#[test]
fn analyze_call_frequency_sorted_desc() {
    let eng = QueryEngine::new(mixed_trace());
    let freq = eng.analyze_call_frequency();
    for w in freq.windows(2) {
        assert!(w[0].1 >= w[1].1);
    }
    // 0x500 called 3 times so should be top
    assert_eq!(freq[0].0, 0x500);
    assert_eq!(freq[0].1, 3);
}

#[test]
fn find_recursive_calls_detects_self_recursion() {
    let eng = QueryEngine::new(mixed_trace());
    let chains = eng.find_recursive_calls();
    assert!(chains.iter().any(|c| c.address == 0x500), "0x500 self-recurses");
}

#[test]
fn detect_heap_operations_returns_report() {
    let eng = QueryEngine::new(mixed_trace());
    let h = eng.detect_heap_operations();
    assert_eq!(h.total_allocs, h.allocs.len() as u64);
    assert_eq!(h.total_frees, h.frees.len() as u64);
}

#[test]
fn find_string_accesses_only_returns_ascii_strings() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::MemWrite { addr: 0x100, data: b"hello".to_vec() }));
    t.add_event(ev(1, 0, 1, EventKind::MemWrite { addr: 0x200, data: vec![0xFF, 0xFE] })); // not ascii
    t.add_event(ev(2, 0, 1, EventKind::MemWrite { addr: 0x300, data: b"ab".to_vec() })); // too short
    let eng = QueryEngine::new(Arc::new(t));
    let s = eng.find_string_accesses();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].address, 0x100);
    assert_eq!(s[0].content, "hello");
}

#[test]
fn summarize_syscalls_counts_errors_and_calls() {
    let eng = QueryEngine::new(mixed_trace());
    let s = eng.summarize_syscalls();
    let s42 = s.get(&42).expect("nr 42");
    assert_eq!(s42.call_count, 1);
    assert_eq!(s42.error_count, 0);
    let s99 = s.get(&99).expect("nr 99");
    assert_eq!(s99.error_count, 1, "u64::MAX as i64 is negative");
}

#[test]
fn find_data_races_heuristic_finds_multi_thread_write() {
    let eng = QueryEngine::new(mixed_trace());
    let races = eng.find_data_races_heuristic();
    assert!(races.iter().any(|r| r.address == 0x1000 && r.threads.len() >= 2));
}

#[test]
fn compute_code_coverage_basic() {
    let eng = QueryEngine::new(mixed_trace());
    let rep = eng.compute_code_coverage(&[(0x100, 0x600)]);
    assert!(rep.covered_addresses > 0);
    assert!(rep.coverage_percentage > 0.0);
    let zero = eng.compute_code_coverage(&[]);
    assert_eq!(zero.total_range_bytes, 0);
    assert_eq!(zero.coverage_percentage, 0.0);
}

// ── histograms ───────────────────────────────────────────────────────────────

#[test]
fn event_histogram_by_kind_sums_to_total() {
    let eng = QueryEngine::new(mixed_trace());
    let h = eng.event_histogram_by_kind();
    let total: u64 = h.values().sum();
    assert_eq!(total as usize, eng.execute(&Query::AllEvents).len());
}

#[test]
fn event_histogram_by_thread_distribution() {
    let eng = QueryEngine::new(mixed_trace());
    let h = eng.event_histogram_by_thread();
    assert!(h.get(&1).is_some_and(|&n| n > 0));
}

#[test]
fn event_histogram_over_time_bucket_zero_returns_empty() {
    let eng = QueryEngine::new(mixed_trace());
    assert!(eng.event_histogram_over_time(0).is_empty());
}

#[test]
fn event_histogram_over_time_bucket_one_each_per_event() {
    let eng = QueryEngine::new(mixed_trace());
    let h = eng.event_histogram_over_time(1);
    // 18 distinct sequences => 18 buckets each with at least 1
    assert!(!h.is_empty());
    let sum: u64 = h.iter().map(|(_, c)| c).sum();
    assert_eq!(sum as usize, eng.execute(&Query::AllEvents).len());
}

#[test]
fn most_accessed_and_most_called_top_n() {
    let eng = QueryEngine::new(mixed_trace());
    let acc = eng.most_accessed_addresses(1);
    assert_eq!(acc.len(), 1);
    let calls = eng.most_called_functions(2);
    assert!(calls.len() <= 2);
    let zero = eng.most_accessed_addresses(0);
    assert!(zero.is_empty());
}

// ── export ───────────────────────────────────────────────────────────────────

#[test]
fn export_to_csv_writer_no_filter_includes_header() {
    let eng = QueryEngine::new(mixed_trace());
    let mut buf = Vec::new();
    eng.export_to_csv_writer(&mut buf, None).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.starts_with("sequence,step,thread_id,kind,addr,data"));
    let lines = s.lines().count();
    assert_eq!(lines, eng.execute(&Query::AllEvents).len() + 1);
}

#[test]
fn export_to_csv_writer_with_filter() {
    let eng = QueryEngine::new(mixed_trace());
    let mut buf = Vec::new();
    eng.export_to_csv_writer(&mut buf, Some(&QueryFilter::Thread { tid: 3 })).unwrap();
    let lines = String::from_utf8(buf).unwrap().lines().count();
    assert_eq!(lines, 2 + 1); // 2 thread-3 events + header
}

#[test]
fn export_call_graph_dot_well_formed() {
    let eng = QueryEngine::new(mixed_trace());
    let mut buf = Vec::new();
    eng.export_call_graph_dot(&mut buf).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("digraph callgraph"));
    assert!(s.contains("->"));
    assert!(s.trim_end().ends_with('}'));
}

#[test]
fn export_timeline_json_brackets_and_count() {
    let eng = QueryEngine::new(mixed_trace());
    let mut buf = Vec::new();
    eng.export_timeline_json(&mut buf, None).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.trim_start().starts_with('['));
    assert!(s.trim_end().ends_with(']'));
    // Should parse as JSON array
    let v: serde_json::Value = serde_json::from_str(&s).expect("valid json");
    assert_eq!(v.as_array().unwrap().len(), eng.execute(&Query::AllEvents).len());
}

#[test]
fn export_timeline_json_with_filter_empty_array_valid() {
    let eng = QueryEngine::new(mixed_trace());
    let mut buf = Vec::new();
    eng.export_timeline_json(&mut buf, Some(&QueryFilter::Thread { tid: 999 })).unwrap();
    let s = String::from_utf8(buf).unwrap();
    let v: serde_json::Value = serde_json::from_str(&s).expect("must be valid JSON even when no matches");
    assert!(v.is_array());
    assert!(v.as_array().unwrap().is_empty());
}

// ── targeted helpers ─────────────────────────────────────────────────────────

#[test]
fn filter_by_address_range_basic() {
    let eng = QueryEngine::new(mixed_trace());
    let r = eng.filter_by_address_range(0x1000, 0x1001);
    assert_eq!(r.len(), 3); // 1 read + 2 writes at 0x1000
    let r = eng.filter_by_address_range(0x9000, 0x9100);
    assert!(r.is_empty());
}

#[test]
fn find_calls_to_returns_first_hit_or_none() {
    let eng = QueryEngine::new(mixed_trace());
    let e = eng.find_calls_to(0x200).expect("call to 0x200 exists");
    assert!(matches!(e.kind, EventKind::Call { to: 0x200, .. }));
    assert!(eng.find_calls_to(0xDEADBEEF).is_none());
}

#[test]
fn find_memory_accesses_returns_both_kinds() {
    let eng = QueryEngine::new(mixed_trace());
    let r = eng.find_memory_accesses(0x1000);
    assert_eq!(r.len(), 3);
}

// ── QueryError ───────────────────────────────────────────────────────────────

#[test]
fn query_error_display_variants() {
    let e = QueryError::InvalidQuery("x".into());
    assert!(format!("{e}").contains("invalid query"));
    let e = QueryError::TraceError("x".into());
    assert!(format!("{e}").contains("trace error"));
    let e = QueryError::ParseError("x".into());
    assert!(format!("{e}").contains("parse error"));
    let e = QueryError::ExportError("x".into());
    assert!(format!("{e}").contains("export error"));
}

#[test]
fn query_error_io_from() {
    let io = std::io::Error::other("oops");
    let e: QueryError = io.into();
    assert!(matches!(e, QueryError::IoError(_)));
}

// ── serde round-trip of public types ─────────────────────────────────────────

#[test]
fn serde_roundtrip_query_filter() {
    let f = QueryFilter::MemoryWrite { addr: 0x10, range_bytes: Some(4) };
    let s = serde_json::to_string(&f).unwrap();
    let back: QueryFilter = serde_json::from_str(&s).unwrap();
    let e = ev(0, 0, 1, EventKind::MemWrite { addr: 0x12, data: vec![0] });
    assert_eq!(f.matches(&e), back.matches(&e));
}

#[test]
fn serde_roundtrip_query() {
    let q = Query::And(vec![
        Query::Pattern(EventPattern::AnyCall),
        Query::Thread(1),
        Query::InTimeRange(TimeRange::new(pos(0, 0), pos(10, 0))),
    ]);
    let s = serde_json::to_string(&q).unwrap();
    let _back: Query = serde_json::from_str(&s).unwrap();
}

// ── QueryEngine Send/Sync sanity (it holds Arc<TtdTrace>) ────────────────────

#[test]
fn query_engine_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<QueryEngine>();
}
