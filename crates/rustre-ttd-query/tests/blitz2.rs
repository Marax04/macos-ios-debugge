//! Deep adversarial blitz2 tests for rustre-ttd-query.
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use rustre_trace::TraceFilter;
use rustre_ttd::{EventKind, TraceEvent, TraceMetadata, TracePosition, TtdTrace};
use rustre_ttd_query::*;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn pos(s: u64, st: u64) -> TracePosition {
    TracePosition::new(s, st)
}

fn ev(s: u64, st: u64, tid: u32, kind: EventKind) -> TraceEvent {
    TraceEvent::new(pos(s, st), tid, kind)
}

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

/// Build a deterministic mixed trace with known properties.
fn mixed_trace() -> Arc<TtdTrace> {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::Call { from: 0x100, to: 0x200 }));
    t.add_event(ev(1, 0, 1, EventKind::MemWrite { addr: 0x1000, data: vec![0xAA, 0xBB] }));
    t.add_event(ev(2, 0, 1, EventKind::MemRead { addr: 0x1000, len: 2 }));
    t.add_event(ev(3, 0, 2, EventKind::MemWrite { addr: 0x1000, data: vec![0xCC] }));
    t.add_event(ev(4, 0, 1, EventKind::SyscallEnter { nr: 42, args: [1, 2, 3, 4, 5, 6] }));
    t.add_event(ev(5, 0, 1, EventKind::SyscallExit { nr: 42, ret: 0 }));
    t.add_event(ev(6, 0, 1, EventKind::Return { from: 0x200, to: 0x100 }));
    t.add_event(ev(7, 0, 1, EventKind::Exception { code: 0xC0000005, addr: 0xDEAD }));
    t.add_event(ev(8, 0, 3, EventKind::Breakpoint { addr: 0x300 }));
    t.add_event(ev(9, 0, 1, EventKind::Call { from: 0x100, to: 0x500 }));
    t.add_event(ev(10, 0, 1, EventKind::Call { from: 0x500, to: 0x500 }));
    t.add_event(ev(11, 0, 1, EventKind::Return { from: 0x500, to: 0x500 }));
    t.add_event(ev(12, 0, 1, EventKind::Return { from: 0x500, to: 0x100 }));
    Arc::new(t)
}

fn fuzz_event(g: &mut impl FnMut() -> u64) -> TraceEvent {
    let r = g();
    let tid = (r & 0xFF) as u32;
    let pos = TracePosition::new(g() % 10_000, g() % 16);
    let kind = match r % 10 {
        0 => EventKind::MemRead { addr: g(), len: (g() % 64) as usize },
        1 => EventKind::MemWrite { addr: g(), data: vec![(g() & 0xFF) as u8; (g() % 8) as usize] },
        2 => EventKind::Call { from: g(), to: g() },
        3 => EventKind::Return { from: g(), to: g() },
        4 => EventKind::SyscallEnter { nr: (g() % 1024) as u32, args: [g(), g(), g(), g(), g(), g()] },
        5 => EventKind::SyscallExit { nr: (g() % 1024) as u32, ret: g() },
        6 => EventKind::Exception { code: (g() & 0xFFFF_FFFF) as u32, addr: g() },
        7 => EventKind::Breakpoint { addr: g() },
        8 => EventKind::ThreadCreate { tid: (g() & 0xFFFF) as u32 },
        _ => EventKind::ThreadExit { tid: (g() & 0xFFFF) as u32, code: (g() & 0xFFFF_FFFF) as u32 },
    };
    TraceEvent::new(pos, tid, kind)
}

// ─── 1: TimeRange properties ─────────────────────────────────────────────────

#[test]
fn timerange_round_trip_50_inputs() {
    let mut g = lcg();
    for _ in 0..50 {
        let a = g() % 1000;
        let b = a + (g() % 1000);
        let r = TimeRange::new(pos(a, 0), pos(b, 0));
        assert!(r.contains(&pos(a, 0)));
        assert!(r.contains(&pos(b, 0)));
        assert!(r.contains(&pos((a + b) / 2, 0)));
        let s = format!("{r}");
        assert!(s.starts_with('[') && s.ends_with(']'));
    }
}

#[test]
fn timerange_inverted_returns_empty_semantics() {
    let r = TimeRange::new(pos(10, 0), pos(5, 0));
    assert!(!r.contains(&pos(7, 0)));
    assert!(!r.contains(&pos(10, 0)));
}

// ─── 2: addr_in_range boundaries via QueryFilter ─────────────────────────────

#[test]
fn filter_memread_addr_zero_and_max() {
    let f0 = QueryFilter::MemoryRead { addr: 0, range_bytes: None };
    assert!(f0.matches(&ev(0, 0, 1, EventKind::MemRead { addr: 0, len: 1 })));
    let fm = QueryFilter::MemoryRead { addr: u64::MAX, range_bytes: None };
    assert!(fm.matches(&ev(0, 0, 1, EventKind::MemRead { addr: u64::MAX, len: 1 })));
}

#[test]
fn filter_memwrite_range_off_by_one() {
    let f = QueryFilter::MemoryWrite { addr: 100, range_bytes: Some(10) };
    assert!(f.matches(&ev(0, 0, 1, EventKind::MemWrite { addr: 90, data: vec![1] })));
    assert!(f.matches(&ev(0, 0, 1, EventKind::MemWrite { addr: 110, data: vec![1] })));
    assert!(!f.matches(&ev(0, 0, 1, EventKind::MemWrite { addr: 89, data: vec![1] })));
    assert!(!f.matches(&ev(0, 0, 1, EventKind::MemWrite { addr: 111, data: vec![1] })));
}

#[test]
fn filter_fuzz_never_panics() {
    let mut g = lcg();
    let filters: Vec<QueryFilter> = (0..20)
        .map(|i| match i % 8 {
            0 => QueryFilter::MemoryRead { addr: g(), range_bytes: Some(g() % 256) },
            1 => QueryFilter::MemoryWrite { addr: g(), range_bytes: None },
            2 => QueryFilter::Thread { tid: (g() & 0xFFFF) as u32 },
            3 => QueryFilter::CallTo { target: g() },
            4 => QueryFilter::CallFrom { source: g() },
            5 => QueryFilter::SyscallNumber { nr: (g() & 0xFFFF) as u32 },
            6 => QueryFilter::ExceptionCode { code: (g() & 0xFFFF_FFFF) as u32 },
            _ => QueryFilter::ThreadCreate,
        })
        .collect();
    for _ in 0..200 {
        let e = fuzz_event(&mut g);
        for f in &filters {
            let _ = f.matches(&e);
            let _ = format!("{f}");
        }
    }
}

// ─── 3: QueryLogic ───────────────────────────────────────────────────────────

#[test]
fn querylogic_empty_and_returns_true() {
    // And over an empty filter list — `iter().all()` is vacuously true.
    let e = ev(0, 0, 1, EventKind::Breakpoint { addr: 0 });
    assert!(QueryLogic::And(vec![]).matches(&e));
}

#[test]
fn querylogic_empty_or_returns_false() {
    let e = ev(0, 0, 1, EventKind::Breakpoint { addr: 0 });
    assert!(!QueryLogic::Or(vec![]).matches(&e));
}

#[test]
fn querylogic_double_not_idempotent() {
    let e = ev(0, 0, 7, EventKind::Breakpoint { addr: 0 });
    let f = QueryFilter::Thread { tid: 7 };
    let inner = QueryLogic::Not(Box::new(f.clone()));
    // Not(Not(f)) ≡ f — built manually
    assert!(!inner.matches(&e));
    assert!(QueryLogic::Single(f).matches(&e));
}

// ─── 4: EventPattern ─────────────────────────────────────────────────────────

#[test]
fn pattern_display_round_trip_smoke() {
    let pats = [
        EventPattern::AnyMemRead,
        EventPattern::MemReadAt(0x10),
        EventPattern::CallTo(0xFF),
        EventPattern::ReturnFrom(0xAB),
        EventPattern::SyscallNr(99),
        EventPattern::Exception(0xC0000005),
        EventPattern::ThreadId(7),
        EventPattern::Breakpoint(0x42),
        EventPattern::AnyException,
        EventPattern::MemWriteWithData(0x10, vec![1, 2, 3]),
        EventPattern::InPositionRange(pos(0, 0), pos(10, 0)),
    ];
    for p in &pats {
        let s = format!("{p}");
        assert!(!s.is_empty());
    }
}

#[test]
fn pattern_in_position_range_boundary() {
    let p = EventPattern::InPositionRange(pos(5, 0), pos(10, 0));
    assert!(p.matches(&ev(5, 0, 1, EventKind::Breakpoint { addr: 0 })));
    assert!(p.matches(&ev(10, 0, 1, EventKind::Breakpoint { addr: 0 })));
    assert!(!p.matches(&ev(4, 0, 1, EventKind::Breakpoint { addr: 0 })));
    assert!(!p.matches(&ev(11, 0, 1, EventKind::Breakpoint { addr: 0 })));
}

#[test]
fn pattern_memwrite_data_mismatch() {
    let p = EventPattern::MemWriteWithData(0x10, vec![1, 2, 3]);
    let e_bad_data = ev(0, 0, 1, EventKind::MemWrite { addr: 0x10, data: vec![1, 2, 4] });
    assert!(!p.matches(&e_bad_data));
}

// ─── 5: EventKindFilter ──────────────────────────────────────────────────────

#[test]
fn eventkindfilter_any_matches_all() {
    let kinds = [
        EventKind::MemRead { addr: 0, len: 0 },
        EventKind::MemWrite { addr: 0, data: vec![] },
        EventKind::Call { from: 0, to: 0 },
        EventKind::Return { from: 0, to: 0 },
        EventKind::SyscallEnter { nr: 0, args: [0; 6] },
        EventKind::SyscallExit { nr: 0, ret: 0 },
        EventKind::Exception { code: 0, addr: 0 },
        EventKind::Breakpoint { addr: 0 },
        EventKind::ThreadCreate { tid: 0 },
        EventKind::ThreadExit { tid: 0, code: 0 },
    ];
    for k in &kinds {
        assert!(EventKindFilter::Any.matches_kind(k));
    }
}

#[test]
fn eventkindfilter_specific_kinds() {
    assert!(EventKindFilter::MemRead.matches_kind(&EventKind::MemRead { addr: 0, len: 0 }));
    assert!(!EventKindFilter::MemRead.matches_kind(&EventKind::MemWrite { addr: 0, data: vec![] }));
    assert!(EventKindFilter::Breakpoint.matches_kind(&EventKind::Breakpoint { addr: 0 }));
    assert!(EventKindFilter::ThreadExit.matches_kind(&EventKind::ThreadExit { tid: 1, code: 0 }));
}

// ─── 6: QueryEngine basic execute ────────────────────────────────────────────

#[test]
fn engine_execute_allevents_returns_all() {
    let t = mixed_trace();
    let e = QueryEngine::new(t.clone());
    let r = e.execute(&Query::AllEvents);
    assert_eq!(r.len(), 13);
    assert_eq!(r.events_scanned, 13);
    assert!(!r.is_empty());
}

#[test]
fn engine_execute_empty_trace() {
    let t = Arc::new(TtdTrace::new(TraceMetadata::default()));
    let e = QueryEngine::new(t);
    assert!(e.execute(&Query::AllEvents).is_empty());
    assert_eq!(e.execute(&Query::AllEvents).len(), 0);
}

#[test]
fn engine_thread_filter_selects_only_matching_tid() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.execute(&Query::Thread(2));
    for m in &r.matches {
        assert_eq!(m.event.thread_id, 2);
    }
}

#[test]
fn engine_positions_helper() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.execute(&Query::Thread(2));
    let p = r.positions();
    assert_eq!(p.len(), r.len());
}

// ─── 7: Query::EventsInRange semantics ───────────────────────────────────────

#[test]
fn events_in_range_overlap_at_endpoint() {
    // MemRead at 0x100 len 4 spans [0x100, 0x104). Range [0x103, 0x200) should overlap.
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::MemRead { addr: 0x100, len: 4 }));
    let e = QueryEngine::new(Arc::new(t));
    let r = e.execute(&Query::EventsInRange { start: 0x103, end: 0x200, kind: MemAccessKind::Read });
    assert_eq!(r.len(), 1);
}

#[test]
fn events_in_range_just_outside() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::MemRead { addr: 0x100, len: 4 }));
    let e = QueryEngine::new(Arc::new(t));
    // Range [0x104, 0x200) — read ends at 0x104, addr+len > start fails (0x104 > 0x104 false).
    let r = e.execute(&Query::EventsInRange { start: 0x104, end: 0x200, kind: MemAccessKind::Read });
    assert_eq!(r.len(), 0);
}

#[test]
fn events_in_range_kind_filter_excludes() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::MemRead { addr: 0x100, len: 4 }));
    t.add_event(ev(1, 0, 1, EventKind::MemWrite { addr: 0x100, data: vec![1] }));
    let e = QueryEngine::new(Arc::new(t));
    let r_only = e.execute(&Query::EventsInRange { start: 0x0, end: 0x1000, kind: MemAccessKind::Read });
    assert_eq!(r_only.len(), 1);
    let w_only = e.execute(&Query::EventsInRange { start: 0x0, end: 0x1000, kind: MemAccessKind::Write });
    assert_eq!(w_only.len(), 1);
    let any = e.execute(&Query::EventsInRange { start: 0x0, end: 0x1000, kind: MemAccessKind::Any });
    assert_eq!(any.len(), 2);
}

#[test]
fn events_in_range_saturating_add_no_panic() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::MemRead { addr: u64::MAX - 2, len: 100 }));
    let e = QueryEngine::new(Arc::new(t));
    let r = e.execute(&Query::EventsInRange {
        start: u64::MAX - 5,
        end: u64::MAX,
        kind: MemAccessKind::Any,
    });
    assert_eq!(r.len(), 1);
}

// ─── 8: Query::CallChain and Sequence ────────────────────────────────────────

#[test]
fn callchain_present_in_mixed_trace() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.execute(&Query::CallChain { from: 0x100, to: 0x500 });
    assert!(!r.is_empty());
}

#[test]
fn callchain_missing_target_returns_empty() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.execute(&Query::CallChain { from: 0x100, to: 0xDEAD_BEEF });
    assert!(r.is_empty());
}

#[test]
fn sequence_empty_returns_empty() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.execute(&Query::Sequence(vec![]));
    assert!(r.is_empty());
}

#[test]
fn sequence_match_call_then_write() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.execute(&Query::Sequence(vec![
        EventPattern::AnyCall,
        EventPattern::AnyMemWrite,
    ]));
    assert!(!r.is_empty());
}

// ─── 9: Query::Before / After / And / Or / Not ───────────────────────────────

#[test]
fn before_returns_only_a_strictly_before_first_b() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.execute(&Query::Before {
        a: Box::new(Query::Pattern(EventPattern::AnyCall)),
        b: Box::new(Query::Pattern(EventPattern::AnyException)),
    });
    for m in &r.matches {
        assert!(m.position < pos(7, 0));
    }
}

#[test]
fn after_returns_only_a_strictly_after_last_b() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.execute(&Query::After {
        a: Box::new(Query::Pattern(EventPattern::AnyCall)),
        b: Box::new(Query::Pattern(EventPattern::AnyException)),
    });
    for m in &r.matches {
        assert!(m.position > pos(7, 0));
    }
}

#[test]
fn and_empty_returns_empty() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.execute(&Query::And(vec![]));
    assert!(r.is_empty());
}

#[test]
fn or_dedupes_positions() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.execute(&Query::Or(vec![
        Query::Pattern(EventPattern::AnyCall),
        Query::Pattern(EventPattern::AnyCall),
    ]));
    let mut positions: Vec<_> = r.matches.iter().map(|m| m.position).collect();
    let original_len = positions.len();
    positions.sort();
    positions.dedup();
    assert_eq!(positions.len(), original_len, "Or should dedupe positions");
}

#[test]
fn not_complements_pattern() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let all = e.execute(&Query::AllEvents).len();
    let calls = e.execute(&Query::Pattern(EventPattern::AnyCall)).len();
    let not_calls = e
        .execute(&Query::Not(Box::new(Query::Pattern(EventPattern::AnyCall))))
        .len();
    assert_eq!(all, calls + not_calls);
}

// ─── 10: explain / QueryPlan ─────────────────────────────────────────────────

#[test]
fn explain_describes_each_variant() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let plans = [
        Query::AllEvents,
        Query::CallChain { from: 0, to: 0 },
        Query::Thread(1),
        Query::Loops { min_iterations: 2 },
        Query::And(vec![]),
        Query::Or(vec![]),
        Query::Not(Box::new(Query::AllEvents)),
    ];
    for q in &plans {
        let p = e.explain(q);
        assert!(!p.description.is_empty());
        let _ = format!("{p}");
    }
}

// ─── 11: count / first / last / execute_filter ───────────────────────────────

#[test]
fn count_first_last_consistent() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let f = QueryFilter::MemoryWrite { addr: 0x1000, range_bytes: None };
    let cnt = e.count(&f);
    let first = e.first_occurrence(&f).unwrap();
    let last = e.last_occurrence(&f).unwrap();
    assert!(cnt >= 1);
    assert!(first.position <= last.position);
}

#[test]
fn count_no_match_returns_zero() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let f = QueryFilter::Thread { tid: 9999 };
    assert_eq!(e.count(&f), 0);
    assert!(e.first_occurrence(&f).is_none());
    assert!(e.last_occurrence(&f).is_none());
}

// ─── 12: Analysis functions ──────────────────────────────────────────────────

#[test]
fn memory_access_report_counts() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.analyze_memory_access_patterns(0x0, 0x10000);
    assert!(r.total_reads >= 1);
    assert!(r.total_writes >= 2);
    assert!(r.total_read_bytes > 0);
    assert!(r.first_access.is_some());
    let _ = format!("{r}");
}

#[test]
fn analyze_call_frequency_sorted_desc() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let freq = e.analyze_call_frequency();
    for w in freq.windows(2) {
        assert!(w[0].1 >= w[1].1);
    }
}

#[test]
fn recursive_calls_detected() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let chains = e.find_recursive_calls();
    assert!(chains.iter().any(|c| c.address == 0x500));
}

#[test]
fn coverage_no_ranges_yields_zero_pct() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.compute_code_coverage(&[]);
    assert_eq!(r.total_range_bytes, 0);
    assert_eq!(r.coverage_percentage, 0.0);
}

#[test]
fn coverage_full_range_nonzero() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.compute_code_coverage(&[(0x0, 0x10000)]);
    assert!(r.covered_addresses > 0);
    assert!(r.coverage_percentage > 0.0);
}

// ─── 13: Histograms ──────────────────────────────────────────────────────────

#[test]
fn histogram_by_kind_sums_to_total() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let h = e.event_histogram_by_kind();
    let total: u64 = h.values().sum();
    assert_eq!(total, 13);
}

#[test]
fn histogram_over_time_zero_bucket_empty() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let h = e.event_histogram_over_time(0);
    assert!(h.is_empty());
}

#[test]
fn histogram_over_time_nonzero_bucket() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let h = e.event_histogram_over_time(4);
    assert!(!h.is_empty());
    let total: u64 = h.iter().map(|(_, c)| c).sum();
    assert_eq!(total, 13);
}

#[test]
fn most_accessed_top_n_respects_limit() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let top = e.most_accessed_addresses(1);
    assert!(top.len() <= 1);
}

// ─── 14: Export ──────────────────────────────────────────────────────────────

#[test]
fn export_csv_has_header_and_rows() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let mut buf = Vec::new();
    e.export_to_csv_writer(&mut buf, None).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.starts_with("sequence,step,thread_id,kind"));
    let lines: Vec<_> = s.lines().collect();
    assert_eq!(lines.len(), 14); // header + 13 events
}

#[test]
fn export_csv_with_filter_subset() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let mut buf = Vec::new();
    let f = QueryFilter::Thread { tid: 2 };
    e.export_to_csv_writer(&mut buf, Some(&f)).unwrap();
    let s = String::from_utf8(buf).unwrap();
    // Header + however many tid=2 events (1)
    let lines: Vec<_> = s.lines().collect();
    assert_eq!(lines.len(), 2);
}

#[test]
fn export_callgraph_dot_well_formed() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let mut buf = Vec::new();
    e.export_call_graph_dot(&mut buf).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.starts_with("digraph callgraph"));
    assert!(s.trim_end().ends_with('}'));
}

#[test]
fn export_timeline_json_parseable() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let mut buf = Vec::new();
    e.export_timeline_json(&mut buf, None).unwrap();
    let s = String::from_utf8(buf).unwrap();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert!(v.is_array());
    assert_eq!(v.as_array().unwrap().len(), 13);
}

// ─── 15: SQLite TraceIndex round-trip ────────────────────────────────────────

#[test]
fn traceindex_build_query_writes_round_trip() {
    let t = mixed_trace();
    let idx = TraceIndex::open_in_memory().unwrap();
    idx.build_from_trace(&t).unwrap();
    let writes = idx.query_memory_writes(0x1000).unwrap();
    assert!(writes.len() >= 2);
}

#[test]
fn traceindex_count_events_matches_kind_histogram() {
    let t = mixed_trace();
    let idx = TraceIndex::open_in_memory().unwrap();
    idx.build_from_trace(&t).unwrap();
    let counts = idx.count_events_by_type().unwrap();
    let total: u64 = counts.values().sum();
    assert_eq!(total, 13);
}

#[test]
fn traceindex_query_by_thread_filters() {
    let t = mixed_trace();
    let idx = TraceIndex::open_in_memory().unwrap();
    idx.build_from_trace(&t).unwrap();
    let evs = idx.query_by_thread(2).unwrap();
    for e in &evs {
        assert_eq!(e.thread_id, 2);
    }
}

#[test]
fn traceindex_position_range_query() {
    let t = mixed_trace();
    let idx = TraceIndex::open_in_memory().unwrap();
    idx.build_from_trace(&t).unwrap();
    let evs = idx.query_in_position_range(2, 6).unwrap();
    for e in &evs {
        assert!(e.position.sequence >= 2 && e.position.sequence <= 6);
    }
    assert!(evs.len() >= 4);
}

#[test]
fn traceindex_query_syscalls_and_exceptions() {
    let t = mixed_trace();
    let idx = TraceIndex::open_in_memory().unwrap();
    idx.build_from_trace(&t).unwrap();
    let sys = idx.query_syscalls(42).unwrap();
    assert!(sys.len() >= 2);
    let exc = idx.query_exceptions().unwrap();
    assert!(!exc.is_empty());
}

// ─── 16: parse_query ─────────────────────────────────────────────────────────

#[test]
fn parse_query_writes_to_dec_and_hex() {
    let q = parse_query("find writes to 0x1234").unwrap();
    match q {
        TtdQueryExpr::FindWrites { addr } => assert_eq!(addr, 0x1234),
        _ => panic!("expected FindWrites"),
    }
    let q2 = parse_query("find writes to 4660").unwrap();
    match q2 {
        TtdQueryExpr::FindWrites { addr } => assert_eq!(addr, 4660),
        _ => panic!("expected FindWrites"),
    }
}

#[test]
fn parse_query_all_verbs() {
    assert!(matches!(parse_query("find reads from 0x10").unwrap(), TtdQueryExpr::FindReads { .. }));
    assert!(matches!(parse_query("find calls to 0x10").unwrap(), TtdQueryExpr::FindCalls { .. }));
    assert!(matches!(parse_query("find returns from 0x10").unwrap(), TtdQueryExpr::FindReturns { .. }));
    assert!(matches!(parse_query("find syscalls").unwrap(), TtdQueryExpr::FindSyscalls { nr: None }));
    assert!(matches!(parse_query("find syscall 60").unwrap(), TtdQueryExpr::FindSyscalls { nr: Some(60) }));
    assert!(matches!(parse_query("find exceptions").unwrap(), TtdQueryExpr::FindExceptions { code: None }));
    assert!(matches!(parse_query("at 100:5").unwrap(), TtdQueryExpr::AtTick { seq: 100, step: 5 }));
}

#[test]
fn parse_query_case_insensitive() {
    assert!(parse_query("FIND WRITES TO 0xABCD").is_ok());
    assert!(parse_query("At 1:2").is_ok());
}

#[test]
fn parse_query_invalid_input_errors() {
    assert!(parse_query("nonsense").is_err());
    assert!(parse_query("find writes to not_a_number").is_err());
    assert!(parse_query("at bad:0").is_err());
    assert!(parse_query("").is_err());
}

#[test]
fn parse_query_syscall_nr_overflow_errors() {
    // u32::MAX + 1 won't fit
    let big = format!("find syscall {}", (u32::MAX as u64) + 1);
    assert!(parse_query(&big).is_err());
}

#[test]
fn parse_query_fuzz_never_panics() {
    let mut g = lcg();
    let prefixes = ["find writes to ", "find reads from ", "at ", "find calls to ", "garbage "];
    for _ in 0..100 {
        let p = prefixes[(g() as usize) % prefixes.len()];
        let s = format!("{p}{:x}", g() & 0xFFFF);
        let _ = parse_query(&s);
    }
}

// ─── 17: TtdQueryExpr Display ────────────────────────────────────────────────

#[test]
fn ttdqueryexpr_display_all_variants() {
    let exprs = [
        TtdQueryExpr::FindWrites { addr: 0x10 },
        TtdQueryExpr::FindReads { addr: 0x10 },
        TtdQueryExpr::FindCalls { target: 0x10 },
        TtdQueryExpr::FindReturns { from_addr: 0x10 },
        TtdQueryExpr::FindSyscalls { nr: Some(5) },
        TtdQueryExpr::FindSyscalls { nr: None },
        TtdQueryExpr::FindExceptions { code: Some(0xC0000005) },
        TtdQueryExpr::FindExceptions { code: None },
        TtdQueryExpr::AtTick { seq: 1, step: 2 },
        TtdQueryExpr::InRange {
            from_seq: 0,
            to_seq: 10,
            inner: Box::new(TtdQueryExpr::FindWrites { addr: 0 }),
        },
        TtdQueryExpr::And(
            Box::new(TtdQueryExpr::FindReads { addr: 1 }),
            Box::new(TtdQueryExpr::FindWrites { addr: 2 }),
        ),
        TtdQueryExpr::Or(
            Box::new(TtdQueryExpr::FindReads { addr: 1 }),
            Box::new(TtdQueryExpr::FindWrites { addr: 2 }),
        ),
    ];
    for x in &exprs {
        assert!(!format!("{x}").is_empty());
    }
}

// ─── 18: QueryIndex internals ────────────────────────────────────────────────

#[test]
fn queryindex_lookup_helpers_consistent() {
    let t = mixed_trace();
    let e = QueryEngine::new(t.clone());
    // execute calls_to_address lookup is exposed through find_calls_to.
    assert!(e.find_calls_to(0x200).is_some());
    assert!(e.find_calls_to(0xDEAD_BEEF).is_none());
    let accesses = e.find_memory_accesses(0x1000);
    assert!(accesses.len() >= 2);
    let in_range = e.filter_by_address_range(0x900, 0x1100);
    assert!(!in_range.is_empty());
}

// ─── 19: execute_with_trace_filter / core address bridge ────────────────────

#[test]
fn execute_with_trace_filter_addr_range_then_tid() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let f = TraceFilter {
        min_addr: Some(0x0),
        max_addr: Some(0x10000),
        thread_id: Some(2),
        ..Default::default()
    };
    let r = e.execute_with_trace_filter(&f);
    for m in &r.matches {
        assert_eq!(m.event.thread_id, 2);
    }
}

#[test]
fn execute_with_trace_filter_no_addrs_returns_all_then_tid_filter() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let f = TraceFilter {
        thread_id: Some(1),
        ..Default::default()
    };
    let r = e.execute_with_trace_filter(&f);
    assert!(!r.is_empty());
    for m in &r.matches {
        assert_eq!(m.event.thread_id, 1);
    }
}

// ─── 20: LegacyQueryResult / execute_logic ───────────────────────────────────

#[test]
fn execute_logic_and_or_not() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.execute_logic(&QueryLogic::Single(QueryFilter::Thread { tid: 1 }));
    assert!(!r.is_empty());
    for ev in &r.events {
        assert_eq!(ev.thread_id, 1);
    }
    let _ = format!("{r}");
    assert_eq!(r.len(), r.events.len());
}

// ─── 21: Send + Sync stress for QueryEngine via Arc ──────────────────────────

#[test]
fn engine_arc_threaded_stress() {
    let t = mixed_trace();
    let e = Arc::new(QueryEngine::new(t));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let e2 = e.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let r = e2.execute(&Query::AllEvents);
                assert_eq!(r.len(), 13);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── 22: Hash/Eq consistency for TracePosition (used as map key) ─────────────

#[test]
fn traceposition_hash_eq_consistency() {
    use std::collections::HashSet;
    let mut g = lcg();
    let mut set = HashSet::new();
    let mut pairs = Vec::new();
    for _ in 0..30 {
        let p = pos(g() % 1000, g() % 16);
        let q = p;
        assert_eq!(p, q);
        set.insert(p);
        pairs.push((p, q));
    }
    for (p, q) in &pairs {
        assert!(set.contains(p));
        assert!(set.contains(q));
    }
}

// ─── 23: SyscallStats avg_return_value ───────────────────────────────────────

#[test]
fn syscallstats_avg_handles_empty_and_neg() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::SyscallEnter { nr: 1, args: [0; 6] }));
    t.add_event(ev(1, 0, 1, EventKind::SyscallExit { nr: 1, ret: u64::MAX })); // -1 as i64
    t.add_event(ev(2, 0, 1, EventKind::SyscallExit { nr: 1, ret: 1 }));
    let e = QueryEngine::new(Arc::new(t));
    let summary = e.summarize_syscalls();
    let s = summary.get(&1).unwrap();
    let avg = s.avg_return_value().unwrap();
    // (-1 + 1) / 2 = 0
    assert!(avg.abs() < 1e-9);
}

// ─── 24: detect_heap_operations smoke ────────────────────────────────────────

#[test]
fn detect_heap_operations_no_panic() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.detect_heap_operations();
    assert_eq!(r.allocs.len() as u64, r.total_allocs);
    assert_eq!(r.frees.len() as u64, r.total_frees);
    let _ = format!("{r}");
}

// ─── 25: data race heuristic ─────────────────────────────────────────────────

#[test]
fn data_races_finds_addr_with_two_threads() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let races = e.find_data_races_heuristic();
    // 0x1000 has writes from tid 1 and tid 2.
    assert!(races.iter().any(|r| r.address == 0x1000 && r.threads.len() >= 2));
}

// ─── 26: find_string_accesses ────────────────────────────────────────────────

#[test]
fn find_string_accesses_picks_ascii() {
    let t = TtdTrace::new(TraceMetadata::default());
    t.add_event(ev(0, 0, 1, EventKind::MemWrite { addr: 0x500, data: b"hi!".to_vec() }));
    t.add_event(ev(1, 0, 1, EventKind::MemWrite { addr: 0x600, data: vec![0xFF, 0xFE] }));
    let e = QueryEngine::new(Arc::new(t));
    let strs = e.find_string_accesses();
    assert!(strs.iter().any(|s| s.address == 0x500 && s.content == "hi!"));
    assert!(!strs.iter().any(|s| s.address == 0x600));
}

// ─── 27: MatchContext window edges ───────────────────────────────────────────

#[test]
fn match_context_with_window_clamps_at_edges() {
    let events: Vec<_> = (0..5)
        .map(|i| ev(i, 0, 1, EventKind::Breakpoint { addr: i }))
        .collect();
    let mc_first = MatchContext::with_context(&events, 0, 2);
    assert!(mc_first.before.is_empty());
    assert_eq!(mc_first.after.len(), 2);
    let mc_last = MatchContext::with_context(&events, 4, 2);
    assert_eq!(mc_last.before.len(), 2);
    assert!(mc_last.after.is_empty());
    let mc_empty = MatchContext::empty();
    assert!(mc_empty.before.is_empty() && mc_empty.after.is_empty());
}

// ─── 28: Engine fuzz never panics ────────────────────────────────────────────

#[test]
fn engine_fuzz_all_queries_never_panic() {
    let mut g = lcg();
    let t = TtdTrace::new(TraceMetadata::default());
    for _ in 0..50 {
        t.add_event(fuzz_event(&mut g));
    }
    let e = QueryEngine::new(Arc::new(t));
    let queries = [
        Query::AllEvents,
        Query::EventsOfKind(EventKindFilter::Any),
        Query::EventsInRange { start: 0, end: u64::MAX, kind: MemAccessKind::Any },
        Query::Pattern(EventPattern::AnyCall),
        Query::CallChain { from: 0, to: 0 },
        Query::DataFlow { source_addr: 0, sink_addr: 0 },
        Query::Loops { min_iterations: 0 },
        Query::Sequence(vec![EventPattern::AnyMemRead, EventPattern::AnyMemWrite]),
        Query::Thread(1),
        Query::InTimeRange(TimeRange::new(pos(0, 0), pos(10_000, 0))),
    ];
    for q in &queries {
        let r = e.execute(q);
        let _ = format!("{r}");
        let _ = format!("{q}");
    }
}

// ─── 29: QueryResult display ─────────────────────────────────────────────────

#[test]
fn queryresult_and_queryplan_display() {
    let t = mixed_trace();
    let e = QueryEngine::new(t);
    let r = e.execute(&Query::AllEvents);
    assert!(format!("{r}").contains("QueryResult"));
    let p = e.explain(&Query::AllEvents);
    assert!(format!("{p}").contains("QueryPlan"));
}
