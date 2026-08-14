//! External integration tests for rustre-trace.
//! Goal: exercise public API surface, edge cases, and adversarial inputs.

use rustre_trace::*;

// ───────────────────────── helpers ─────────────────────────

fn ins(addr: u64) -> TraceEvent {
    TraceEvent::Instruction { addr, size: 4 }
}

fn populated_session() -> TraceSession {
    let mut s = TraceSession::new("sess", "x86_64");
    s.push(ins(0x1000), 1, 100);
    s.push(ins(0x1004), 1, 200);
    s.push(TraceEvent::MemRead { addr: 0x2000, size: 8, value: 0xdead }, 2, 300);
    s.push(TraceEvent::Call { from: 0x1004, to: 0x3000 }, 1, 400);
    s.push(TraceEvent::Return { from: 0x3010, to: 0x1008 }, 1, 500);
    s
}

// ───────────────────── primary_addr & type_name ─────────────────────

#[test]
fn primary_addr_each_variant() {
    assert_eq!(TraceEvent::Instruction { addr: 0xAA, size: 1 }.primary_addr(), 0xAA);
    assert_eq!(TraceEvent::MemRead { addr: 0xBB, size: 1, value: 0 }.primary_addr(), 0xBB);
    assert_eq!(TraceEvent::MemWrite { addr: 0xCC, size: 1, value: 0 }.primary_addr(), 0xCC);
    assert_eq!(TraceEvent::Call { from: 0xDD, to: 0 }.primary_addr(), 0xDD);
    assert_eq!(TraceEvent::Return { from: 0xEE, to: 0 }.primary_addr(), 0xEE);
    assert_eq!(TraceEvent::Exception { code: 0, addr: 0xFF }.primary_addr(), 0xFF);
    assert_eq!(TraceEvent::Branch { from: 0x11, to: 0, taken: true }.primary_addr(), 0x11);
    assert_eq!(TraceEvent::ModuleLoad { base: 0x22, size: 0, name: "x".into() }.primary_addr(), 0x22);
    assert_eq!(TraceEvent::Syscall { number: 0x42, args: vec![] }.primary_addr(), 0x42);
    assert_eq!(TraceEvent::RegisterChange { name: "r".into(), old_value: 0, new_value: 0 }.primary_addr(), 0);
}

#[test]
fn type_name_each_variant() {
    assert_eq!(TraceEvent::Instruction { addr: 0, size: 1 }.type_name(), "Instruction");
    assert_eq!(TraceEvent::MemRead { addr: 0, size: 1, value: 0 }.type_name(), "MemRead");
    assert_eq!(TraceEvent::MemWrite { addr: 0, size: 1, value: 0 }.type_name(), "MemWrite");
    assert_eq!(TraceEvent::Call { from: 0, to: 0 }.type_name(), "Call");
    assert_eq!(TraceEvent::Return { from: 0, to: 0 }.type_name(), "Return");
    assert_eq!(TraceEvent::Exception { code: 0, addr: 0 }.type_name(), "Exception");
    assert_eq!(TraceEvent::Syscall { number: 0, args: vec![] }.type_name(), "Syscall");
    assert_eq!(TraceEvent::Branch { from: 0, to: 0, taken: false }.type_name(), "Branch");
    assert_eq!(TraceEvent::ModuleLoad { base: 0, size: 0, name: String::new() }.type_name(), "ModuleLoad");
    assert_eq!(TraceEvent::RegisterChange { name: "r".into(), old_value: 0, new_value: 0 }.type_name(), "RegisterChange");
}

// ───────────────────── TraceRecord Display ─────────────────────

#[test]
fn record_display_contains_fields() {
    let r = TraceRecord::new(42, ins(0xABCD), 7, 999);
    let s = format!("{r}");
    assert!(s.contains("42"));
    assert!(s.contains("tid=7"));
    assert!(s.contains("999"));
    assert!(s.contains("abcd"));
}

// ───────────────────── TraceFrame ─────────────────────

#[test]
fn frame_basic_accessors() {
    let rec = TraceRecord::new(5, ins(0x800), 3, 50);
    let mut f = TraceFrame::new(rec);
    assert_eq!(f.seq(), 5);
    assert_eq!(f.thread_id(), 3);
    assert_eq!(f.timestamp_ns(), 50);
    assert_eq!(f.instruction_pointer(), Some(0x800));
    assert_eq!(f.call_depth, 0);
    f.set_register("rax", 0x1234);
    assert_eq!(f.get_register("rax"), Some(0x1234));
    assert_eq!(f.get_register("rbx"), None);
}

#[test]
fn frame_ip_none_for_non_instruction() {
    let rec = TraceRecord::new(0, TraceEvent::Call { from: 1, to: 2 }, 0, 0);
    let f = TraceFrame::new(rec);
    assert_eq!(f.instruction_pointer(), None);
}

// ───────────────────── TraceFilter ─────────────────────

#[test]
fn filter_default_is_empty_matches_all() {
    let f = TraceFilter::new();
    assert!(f.is_empty());
    let rec = TraceRecord::new(0, ins(0x100), 0, 0);
    assert!(f.matches(&rec));
}

#[test]
fn filter_constructors() {
    assert!(!TraceFilter::instructions_only().is_empty());
    assert!(!TraceFilter::for_thread(1).is_empty());
    assert!(!TraceFilter::address_range(0, 10).is_empty());
    assert!(!TraceFilter::time_range(0, 10).is_empty());
}

#[test]
fn filter_max_addr_is_exclusive() {
    // max_addr is exclusive per source: addr >= max → reject.
    let f = TraceFilter { max_addr: Some(0x1000), ..Default::default() };
    let r_at = TraceRecord::new(0, ins(0x1000), 0, 0);
    let r_below = TraceRecord::new(1, ins(0xFFF), 0, 0);
    assert!(!f.matches(&r_at));
    assert!(f.matches(&r_below));
}

#[test]
fn filter_min_addr_is_inclusive() {
    let f = TraceFilter { min_addr: Some(0x1000), ..Default::default() };
    assert!(f.matches(&TraceRecord::new(0, ins(0x1000), 0, 0)));
    assert!(!f.matches(&TraceRecord::new(1, ins(0xFFF), 0, 0)));
}

#[test]
fn filter_time_range_inclusive() {
    let f = TraceFilter::time_range(100, 200);
    assert!(f.matches(&TraceRecord::new(0, ins(0), 0, 100)));
    assert!(f.matches(&TraceRecord::new(0, ins(0), 0, 200)));
    assert!(!f.matches(&TraceRecord::new(0, ins(0), 0, 99)));
    assert!(!f.matches(&TraceRecord::new(0, ins(0), 0, 201)));
}

#[test]
fn filter_seq_range_half_open() {
    let f = TraceFilter { seq_range: Some((5, 10)), ..Default::default() };
    assert!(f.matches(&TraceRecord::new(5, ins(0), 0, 0)));
    assert!(f.matches(&TraceRecord::new(9, ins(0), 0, 0)));
    assert!(!f.matches(&TraceRecord::new(10, ins(0), 0, 0)));
    assert!(!f.matches(&TraceRecord::new(4, ins(0), 0, 0)));
}

#[test]
fn filter_kinds_fallback() {
    let f = TraceFilter { kinds: vec!["Call".to_string()], ..Default::default() };
    assert!(f.matches(&TraceRecord::new(0, TraceEvent::Call { from: 0, to: 0 }, 0, 0)));
    assert!(!f.matches(&TraceRecord::new(0, ins(0), 0, 0)));
}

#[test]
fn filter_event_types_overrides_kinds() {
    let f = TraceFilter {
        event_types: vec!["Instruction".into()],
        kinds: vec!["Call".into()],
        ..Default::default()
    };
    assert!(f.matches(&TraceRecord::new(0, ins(0), 0, 0)));
    assert!(!f.matches(&TraceRecord::new(0, TraceEvent::Call { from: 0, to: 0 }, 0, 0)));
}

#[test]
fn filter_validate_both_set_is_err() {
    let f = TraceFilter {
        event_types: vec!["a".into()],
        kinds: vec!["b".into()],
        ..Default::default()
    };
    assert!(f.validate().is_err());
}

#[test]
fn filter_validate_ok_when_one_or_neither() {
    assert!(TraceFilter::new().validate().is_ok());
    assert!(TraceFilter { event_types: vec!["x".into()], ..Default::default() }.validate().is_ok());
    assert!(TraceFilter { kinds: vec!["x".into()], ..Default::default() }.validate().is_ok());
}

#[test]
fn filter_apply_returns_subset() {
    let s = populated_session();
    let f = TraceFilter::instructions_only();
    let out = f.apply(&s.records);
    assert_eq!(out.len(), 2);
}

// ───────────────────── TraceSession ─────────────────────

#[test]
fn session_seq_is_monotonic() {
    let mut s = TraceSession::new("a", "x");
    for i in 0..10 {
        s.push(ins(i), 0, i);
    }
    for (i, r) in s.records.iter().enumerate() {
        assert_eq!(r.seq, i as u64);
    }
}

#[test]
fn session_push_event_alias() {
    let mut s = TraceSession::new("a", "x");
    s.push_event(ins(1), 0, 0);
    assert_eq!(s.record_count(), 1);
}

#[test]
fn session_record_count_and_first_last() {
    let s = populated_session();
    assert_eq!(s.record_count(), 5);
    assert_eq!(s.first_record().unwrap().seq, 0);
    assert_eq!(s.last_record().unwrap().seq, 4);
}

#[test]
fn session_thread_ids() {
    let s = populated_session();
    let tids = s.thread_ids();
    assert!(tids.contains(&1));
    assert!(tids.contains(&2));
    assert_eq!(tids.len(), 2);
}

#[test]
fn session_event_type_counts() {
    let s = populated_session();
    let c = s.event_type_counts();
    assert_eq!(c.get("Instruction"), Some(&2));
    assert_eq!(c.get("MemRead"), Some(&1));
    assert_eq!(c.get("Call"), Some(&1));
    assert_eq!(c.get("Return"), Some(&1));
}

#[test]
fn session_duration_ns() {
    let s = populated_session();
    assert_eq!(s.duration_ns(), 400);
}

#[test]
fn session_duration_empty() {
    let s = TraceSession::new("e", "x");
    assert_eq!(s.duration_ns(), 0);
}

#[test]
fn session_slice_basic() {
    let s = populated_session();
    let v = s.slice(1, 3).unwrap();
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].seq, 1);
    assert_eq!(v[2].seq, 3);
}

#[test]
fn session_slice_start_gt_end_errors() {
    let s = populated_session();
    let err = s.slice(5, 2).unwrap_err();
    matches!(err, TraceError::SliceOutOfBounds { .. });
}

#[test]
fn session_slice_empty_session_zero_zero_ok() {
    let s = TraceSession::new("e", "x");
    let v = s.slice(0, 0).unwrap();
    assert!(v.is_empty());
}

#[test]
fn session_merge_ok_same_arch() {
    let mut a = populated_session();
    let b = populated_session();
    let orig = a.record_count();
    a.merge(&b).unwrap();
    assert_eq!(a.record_count(), orig * 2);
    // Sequences must be re-sequenced contiguously.
    for (i, r) in a.records.iter().enumerate() {
        assert_eq!(r.seq, i as u64);
    }
}

#[test]
fn session_merge_arch_mismatch_errors() {
    let mut a = TraceSession::new("a", "x86_64");
    let b = TraceSession::new("b", "arm64");
    let err = a.merge(&b).unwrap_err();
    assert!(matches!(err, TraceError::MergeMismatch(_)));
}

#[test]
fn session_records_for_thread() {
    let s = populated_session();
    let t1 = s.records_for_thread(1);
    assert_eq!(t1.len(), 4);
    let t2 = s.records_for_thread(2);
    assert_eq!(t2.len(), 1);
    assert_eq!(s.records_for_thread(99).len(), 0);
}

#[test]
fn session_coverage_set_equals_unique_pcs() {
    let s = populated_session();
    assert_eq!(s.coverage_set(), s.unique_pcs());
}

#[test]
fn session_build_heat_map() {
    let mut s = TraceSession::new("h", "x");
    s.push(ins(0x10), 0, 0);
    s.push(ins(0x10), 0, 0);
    s.push(ins(0x20), 0, 0);
    let hm = s.build_heat_map();
    assert_eq!(hm.count(0x10), 2);
    assert_eq!(hm.count(0x20), 1);
    assert_eq!(hm.count(0x99), 0);
}

#[test]
fn session_build_index() {
    let s = populated_session();
    let idx = s.build_index().unwrap();
    assert_eq!(idx.total_indexed(), s.record_count());
    assert!(!idx.seqs_at_addr(0x1000).is_empty());
}

// ───────────────────── TraceRecorder ─────────────────────

#[test]
fn recorder_basic_flow() {
    let mut r = TraceRecorder::new("rec", "x86");
    r.record_instruction(0x100, 4, 1, 0);
    r.record_mem_read(0x200, 8, 0xAA, 1, 1);
    r.record_mem_write(0x300, 4, 0xBB, 1, 2);
    r.record_call(0x100, 0x400, 1, 3);
    r.record_return(0x4FF, 0x108, 1, 4);
    r.record_exception(0xC0, 0x500, 1, 5);
    r.record_syscall(60, vec![1, 2, 3], 1, 6);
    assert_eq!(r.event_count, 7);
    let sess = r.finish();
    assert_eq!(sess.record_count(), 7);
}

#[test]
fn recorder_max_events_drops_excess() {
    let mut r = TraceRecorder::with_max_events("r", "x", 3);
    for i in 0..10 {
        r.record_instruction(i, 4, 0, 0);
    }
    assert!(r.is_full());
    assert_eq!(r.event_count, 3);
    assert_eq!(r.session().record_count(), 3);
}

#[test]
fn recorder_unlimited_is_not_full() {
    let r = TraceRecorder::new("r", "x");
    assert!(!r.is_full());
    assert_eq!(r.flushed_count(), 0);
}

// ───────────────────── TracePlayer ─────────────────────

#[test]
fn player_iteration_and_progress() {
    let s = populated_session();
    let mut p = TracePlayer::new(s);
    assert_eq!(p.total(), 5);
    assert_eq!(p.remaining(), 5);
    assert!(!p.is_done());
    assert_eq!(p.progress(), 0.0);
    let mut count = 0;
    while p.next().is_some() {
        count += 1;
    }
    assert_eq!(count, 5);
    assert!(p.is_done());
    assert_eq!(p.progress(), 1.0);
    assert_eq!(p.remaining(), 0);
    p.reset();
    assert_eq!(p.cursor, 0);
}

#[test]
fn player_peek_does_not_advance() {
    let s = populated_session();
    let p = TracePlayer::new(s);
    let a = p.peek().map(|r| r.seq);
    let b = p.peek().map(|r| r.seq);
    assert_eq!(a, b);
    assert_eq!(p.cursor, 0);
}

#[test]
fn player_seek_to_seq() {
    let s = populated_session();
    let mut p = TracePlayer::new(s);
    assert!(p.seek_to_seq(3));
    assert_eq!(p.peek().unwrap().seq, 3);
    assert!(!p.seek_to_seq(9999));
}

#[test]
fn player_step_back() {
    let s = populated_session();
    let mut p = TracePlayer::new(s);
    assert!(!p.step_back());
    let _ = p.next();
    let _ = p.next();
    assert!(p.step_back());
    assert_eq!(p.cursor, 1);
}

#[test]
fn player_progress_empty_is_one() {
    let s = TraceSession::new("e", "x");
    let p = TracePlayer::new(s);
    assert_eq!(p.progress(), 1.0);
}

#[test]
fn player_peek_all_remaining_slice() {
    let s = populated_session();
    let mut p = TracePlayer::new(s);
    let _ = p.next();
    let rem = p.peek_all_remaining();
    assert_eq!(rem.len(), 4);
}

// ───────────────────── TraceDiff ─────────────────────

#[test]
fn diff_identical_sessions() {
    let a = populated_session();
    let b = populated_session();
    let d = TraceDiff::compute(&a, &b);
    assert!(d.is_identical());
    assert_eq!(d.similarity(), 1.0);
}

#[test]
fn diff_disjoint() {
    let mut a = TraceSession::new("a", "x");
    a.push(ins(0x1), 0, 0);
    let mut b = TraceSession::new("b", "x");
    b.push(ins(0x2), 0, 0);
    let d = TraceDiff::compute(&a, &b);
    assert!(!d.is_identical());
    assert_eq!(d.common_count, 0);
    assert_eq!(d.only_in_left.len(), 1);
    assert_eq!(d.only_in_right.len(), 1);
    assert_eq!(d.similarity(), 0.0);
}

#[test]
fn diff_empty_both_is_identical_similarity_one() {
    let a = TraceSession::new("a", "x");
    let b = TraceSession::new("b", "x");
    let d = TraceDiff::compute(&a, &b);
    assert!(d.is_identical());
    assert_eq!(d.similarity(), 1.0);
    assert_eq!(d.total_unique(), 0);
}

// ───────────────────── CoverageMap ─────────────────────

#[test]
fn coverage_record_hit_and_count() {
    let mut c = CoverageMap::new();
    c.record_hit(0x10);
    c.record_hit(0x10);
    c.record_hit(0x20);
    assert_eq!(c.hit_count(0x10), 2);
    assert_eq!(c.hit_count(0x20), 1);
    assert_eq!(c.hit_count(0x99), 0);
    assert_eq!(c.unique_addresses_hit(), 2);
    assert_eq!(c.total_hits(), 3);
}

#[test]
fn coverage_record_hits_batch() {
    let mut c = CoverageMap::new();
    c.record_hits(0x10, 5);
    c.record_hits(0x10, 3);
    assert_eq!(c.hit_count(0x10), 8);
}

#[test]
fn coverage_ratio_empty_zero_total() {
    let c = CoverageMap::new();
    // total=0, empty counts → 1.0
    assert_eq!(c.coverage_ratio(), 1.0);
}

#[test]
fn coverage_ratio_zero_total_nonempty_zero() {
    let mut c = CoverageMap::new();
    c.record_hit(1);
    assert_eq!(c.coverage_ratio(), 0.0);
}

#[test]
fn coverage_ratio_normal() {
    let mut c = CoverageMap::with_total(10);
    for i in 0..5 {
        c.record_hit(i);
    }
    assert!((c.coverage_ratio() - 0.5).abs() < 1e-9);
}

#[test]
fn coverage_merge() {
    let mut a = CoverageMap::with_total(100);
    a.record_hit(1);
    let mut b = CoverageMap::with_total(200);
    b.record_hit(1);
    b.record_hit(2);
    a.merge(&b);
    assert_eq!(a.hit_count(1), 2);
    assert_eq!(a.hit_count(2), 1);
    assert_eq!(a.total_addresses, 200);
}

#[test]
fn coverage_hottest_addresses_partial_and_full() {
    let mut c = CoverageMap::new();
    c.record_hits(0x10, 5);
    c.record_hits(0x20, 1);
    c.record_hits(0x30, 10);
    c.record_hits(0x40, 3);
    let top2 = c.hottest_addresses(2);
    assert_eq!(top2.len(), 2);
    assert_eq!(top2[0].0, 0x30);
    assert_eq!(top2[0].1, 10);
    assert_eq!(top2[1].0, 0x10);
    // Full
    let top10 = c.hottest_addresses(10);
    assert_eq!(top10.len(), 4);
}

#[test]
fn coverage_hottest_addresses_zero_returns_empty() {
    let mut c = CoverageMap::new();
    c.record_hit(1);
    let v = c.hottest_addresses(0);
    // select_nth_unstable_by panics if n == len, but n=0 with non-empty pairs: 0 < 1, select_nth(0) is valid; truncate(0) returns empty.
    assert!(v.is_empty());
}

#[test]
fn coverage_uncovered_in_range() {
    let mut c = CoverageMap::new();
    c.record_hit(0x10);
    c.record_hit(0x14);
    let unc = c.uncovered_in_range(0x10, 0x20, 4);
    // Range: 0x10,0x14,0x18,0x1C. Hits: 0x10,0x14. Uncovered: 0x18,0x1C.
    assert_eq!(unc, vec![0x18, 0x1C]);
}

#[test]
fn coverage_uncovered_in_range_zero_step_treated_as_one() {
    let c = CoverageMap::new();
    let unc = c.uncovered_in_range(0, 3, 0);
    assert_eq!(unc, vec![0, 1, 2]);
}

#[test]
fn coverage_from_session() {
    let s = populated_session();
    let c = CoverageMap::from_session(&s);
    assert_eq!(c.unique_addresses_hit(), 2);
    assert_eq!(c.hit_count(0x1000), 1);
    assert_eq!(c.hit_count(0x1004), 1);
}

// ───────────────────── TraceIndex ─────────────────────

#[test]
fn index_lookups() {
    let s = populated_session();
    let idx = s.build_index().unwrap();
    assert!(idx.seqs_at_addr(0x1000).contains(&0));
    assert!(idx.seqs_for_thread(2).len() == 1);
    assert!(!idx.seqs_by_type("Instruction").is_empty());
    assert!(idx.seqs_at_addr(0xDEAD).is_empty());
    assert!(idx.seqs_for_thread(99).is_empty());
    assert!(idx.seqs_by_type("Nope").is_empty());
    assert!(idx.all_addresses().len() >= 2);
    assert!(idx.all_thread_ids().len() >= 2);
    assert!(!idx.all_event_types().is_empty());
}

// ───────────────────── InMemoryTraceProvider ─────────────────────

#[test]
fn provider_start_stop_replays_events() {
    let evs = vec![ins(0x1), ins(0x2), ins(0x3)];
    let mut p = InMemoryTraceProvider::with_pre_recorded("p", "x86", evs);
    assert_eq!(p.name(), "p");
    p.start().unwrap();
    let sess = p.stop().unwrap();
    assert_eq!(sess.record_count(), 3);
}

#[test]
fn provider_start_twice_errors() {
    let mut p = InMemoryTraceProvider::with_events("p", "x", vec![]);
    p.start().unwrap();
    assert!(matches!(p.start().unwrap_err(), TraceError::AlreadyRunning));
}

#[test]
fn provider_stop_without_start_errors() {
    let mut p = InMemoryTraceProvider::with_events("p", "x", vec![]);
    assert!(matches!(p.stop().unwrap_err(), TraceError::NotRunning));
}

#[test]
fn provider_with_events_alias() {
    let p = InMemoryTraceProvider::with_events("n", "x", vec![ins(1)]);
    assert_eq!(p.name, "n");
}

#[test]
fn provider_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<InMemoryTraceProvider>();
}

// ───────────────────── Trace facade ─────────────────────

#[test]
fn trace_basic_accessors() {
    let s = populated_session();
    let t = Trace::with_description(s, "desc");
    assert_eq!(t.len(), 5);
    assert!(!t.is_empty());
    assert_eq!(t.name(), "sess");
    assert_eq!(t.arch(), "x86_64");
    assert_eq!(t.description, "desc");
    assert_eq!(t.records().len(), 5);
}

#[test]
fn trace_empty() {
    let t = Trace::new(TraceSession::new("e", "x"));
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
}

#[test]
fn trace_json_roundtrip() {
    let t = Trace::new(populated_session());
    let bytes = t.to_json().unwrap();
    let t2 = Trace::from_json(&bytes).unwrap();
    assert_eq!(t2.len(), t.len());
    assert_eq!(t2.name(), t.name());
}

#[test]
fn trace_json_pretty_is_string() {
    let t = Trace::new(populated_session());
    let s = t.to_json_pretty().unwrap();
    assert!(s.contains("sess"));
    // Pretty has indentation/newlines.
    assert!(s.contains('\n'));
}

#[test]
fn trace_from_json_invalid() {
    let r = Trace::from_json(b"not json");
    assert!(matches!(r.unwrap_err(), TraceError::Deserialization(_)));
}

#[test]
fn trace_binary_roundtrip() {
    let t = Trace::new(populated_session());
    let bin = t.to_binary().unwrap();
    let t2 = Trace::from_binary(&bin).unwrap();
    assert_eq!(t2.len(), t.len());
}

#[test]
fn trace_from_binary_too_short() {
    let r = Trace::from_binary(&[0, 1]);
    assert!(matches!(r.unwrap_err(), TraceError::Deserialization(_)));
}

#[test]
fn trace_from_binary_truncated() {
    // length header says 100 but only 4 bytes follow.
    let mut buf = (100u32).to_le_bytes().to_vec();
    buf.extend_from_slice(b"abcd");
    let r = Trace::from_binary(&buf);
    assert!(matches!(r.unwrap_err(), TraceError::Deserialization(_)));
}

#[test]
fn trace_from_binary_garbage_payload() {
    let mut buf = (4u32).to_le_bytes().to_vec();
    buf.extend_from_slice(b"zzzz");
    let r = Trace::from_binary(&buf);
    assert!(matches!(r.unwrap_err(), TraceError::Deserialization(_)));
}

#[test]
fn trace_filtered_keeps_only_matching() {
    let t = Trace::new(populated_session());
    let f = TraceFilter::instructions_only();
    let t2 = t.filtered(&f);
    assert_eq!(t2.len(), 2);
    assert!(t2.name().ends_with("-filtered"));
}

#[test]
fn trace_player_consistency() {
    let t = Trace::new(populated_session());
    let mut p = t.player();
    let mut n = 0;
    while p.next().is_some() { n += 1; }
    assert_eq!(n, t.len());
}

#[test]
fn trace_coverage_map_and_diff() {
    let t = Trace::new(populated_session());
    let c = t.coverage_map();
    assert_eq!(c.unique_addresses_hit(), 2);
    let d = t.diff(&t);
    assert!(d.is_identical());
}

#[test]
fn trace_visualization_data() {
    let t = Trace::new(populated_session());
    let v = t.visualization_data();
    assert_eq!(v.total_events, 5);
    assert_eq!(v.thread_count, 2);
    assert_eq!(v.unique_addresses, 2);
    assert_eq!(v.time_range, (100, 500));
}

// ───────────────────── TraceCompressor ─────────────────────

#[test]
fn compressor_compresses_runs() {
    let mut s = TraceSession::new("c", "x");
    for _ in 0..5 {
        s.push(ins(0x10), 1, 0);
    }
    s.push(ins(0x20), 1, 100);
    let blocks = TraceCompressor::compress(&s);
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].count, 5);
    assert_eq!(blocks[1].count, 1);
}

#[test]
fn compressor_roundtrip_preserves_count() {
    let mut s = TraceSession::new("c", "x");
    for i in 0..10 {
        s.push(ins(if i < 5 { 0x10 } else { 0x20 }), 1, i * 100);
    }
    let blocks = TraceCompressor::compress(&s);
    let s2 = TraceCompressor::decompress(&blocks, "c2", "x");
    assert_eq!(s2.record_count(), s.record_count());
}

#[test]
fn compressor_ratio() {
    assert_eq!(TraceCompressor::compression_ratio(10, 2), 5.0);
    assert_eq!(TraceCompressor::compression_ratio(10, 0), 0.0);
}

#[test]
fn compressor_empty_session() {
    let s = TraceSession::new("c", "x");
    let blocks = TraceCompressor::compress(&s);
    assert!(blocks.is_empty());
    let s2 = TraceCompressor::decompress(&blocks, "x", "x");
    assert_eq!(s2.record_count(), 0);
}

// ───────────────────── LegacyTraceRecord ─────────────────────

#[test]
fn legacy_record_helpers() {
    let mut r = LegacyTraceRecord::new(1, 0x100, 2, 999);
    assert!(!r.has_memory_access());
    assert!(!r.has_syscall());
    r.add_mem_read(0x200, 4, 0xAA);
    r.add_mem_write(0x300, 8, 0xBB);
    r.set_register("rax", 0x42);
    assert!(r.has_memory_access());
    assert_eq!(r.mem_reads.len(), 1);
    assert_eq!(r.mem_writes.len(), 1);
    assert_eq!(r.registers.get("rax"), Some(&0x42));
}

#[test]
fn legacy_filter_address_range_half_open() {
    let f = LegacyTraceFilter {
        address_range: Some((0x100, 0x200)),
        ..Default::default()
    };
    let r_in = LegacyTraceRecord::new(0, 0x100, 0, 0);
    let r_at_max = LegacyTraceRecord::new(0, 0x200, 0, 0);
    let r_below = LegacyTraceRecord::new(0, 0xFF, 0, 0);
    assert!(f.matches(&r_in));
    assert!(!f.matches(&r_at_max));
    assert!(!f.matches(&r_below));
}

#[test]
fn legacy_filter_thread_and_time() {
    let f = LegacyTraceFilter {
        thread_id: Some(3),
        time_range: Some((100, 200)),
        ..Default::default()
    };
    assert!(f.matches(&LegacyTraceRecord::new(0, 0, 3, 150)));
    assert!(!f.matches(&LegacyTraceRecord::new(0, 0, 4, 150)));
    assert!(!f.matches(&LegacyTraceRecord::new(0, 0, 3, 99)));
}

#[test]
fn legacy_filter_apply_with_limit() {
    let recs: Vec<_> = (0..10).map(|i| LegacyTraceRecord::new(i, i * 4, 0, 0)).collect();
    let f = LegacyTraceFilter {
        instruction_limit: Some(3),
        ..Default::default()
    };
    let v = f.apply(&recs);
    assert_eq!(v.len(), 3);
}

// ───────────────────── HeatMap ─────────────────────

#[test]
fn heatmap_basic_ops() {
    let mut hm = HeatMap::new();
    hm.record(0x10);
    hm.record(0x10);
    hm.record(0x20);
    assert_eq!(hm.count(0x10), 2);
    assert_eq!(hm.count(0x99), 0);
    assert_eq!(hm.unique_addresses(), 2);
    assert_eq!(hm.total_executions(), 3);
    assert_eq!(hm.max_count(), 2);
    assert_eq!(hm.min_count(), 1);
}

#[test]
fn heatmap_empty_min_max() {
    let hm = HeatMap::new();
    assert_eq!(hm.max_count(), 0);
    assert_eq!(hm.min_count(), 0);
}

#[test]
fn heatmap_sorted_entries() {
    let mut hm = HeatMap::new();
    hm.record(0x30);
    hm.record(0x10);
    hm.record(0x20);
    let v = hm.sorted_entries();
    assert_eq!(v[0].0, 0x10);
    assert_eq!(v[1].0, 0x20);
    assert_eq!(v[2].0, 0x30);
}

#[test]
fn heatmap_top_n() {
    let mut hm = HeatMap::new();
    hm.record(0x10);
    hm.record(0x10);
    hm.record(0x10);
    hm.record(0x20);
    hm.record(0x30);
    hm.record(0x30);
    let t = hm.top_n(2);
    assert_eq!(t.len(), 2);
    assert_eq!(t[0].0, 0x10);
    assert_eq!(t[0].1, 3);
}

#[test]
fn heatmap_top_n_larger_than_len() {
    let mut hm = HeatMap::new();
    hm.record(1);
    let t = hm.top_n(100);
    assert_eq!(t.len(), 1);
}

#[test]
fn heatmap_merge() {
    let mut a = HeatMap::new();
    a.record(0x10);
    let mut b = HeatMap::new();
    b.record(0x10);
    b.record(0x20);
    a.merge(&b);
    assert_eq!(a.count(0x10), 2);
    assert_eq!(a.count(0x20), 1);
}

#[test]
fn heatmap_sorted_by_heat_stable_tiebreak_on_addr() {
    let mut hm = HeatMap::new();
    hm.record(0x20);
    hm.record(0x10);
    let v = hm.sorted_by_heat();
    // counts equal → ascending addr
    assert_eq!(v[0].0, 0x10);
    assert_eq!(v[1].0, 0x20);
}

// ───────────────────── merge_sessions / coverage_percent ─────────────────────

#[test]
fn merge_sessions_empty_input() {
    let out = merge_sessions(&[]).unwrap();
    assert_eq!(out.name, "merged");
    assert_eq!(out.arch, "unknown");
    assert_eq!(out.record_count(), 0);
}

#[test]
fn merge_sessions_concatenates() {
    let a = populated_session();
    let b = populated_session();
    let out = merge_sessions(&[a.clone(), b.clone()]).unwrap();
    assert_eq!(out.record_count(), a.record_count() + b.record_count());
}

#[test]
fn merge_sessions_arch_mismatch() {
    let a = TraceSession::new("a", "x86");
    let b = TraceSession::new("b", "arm");
    let r = merge_sessions(&[a, b]);
    assert!(matches!(r.unwrap_err(), TraceError::MergeMismatch(_)));
}

#[test]
fn coverage_percent_basic() {
    assert!((coverage_percent(5, 10) - 50.0).abs() < 1e-9);
    assert_eq!(coverage_percent(0, 0), 100.0);
    assert_eq!(coverage_percent(10, 10), 100.0);
    assert_eq!(coverage_percent(0, 10), 0.0);
}

// ───────────────────── TraceStore (SQLite, in-memory) ─────────────────────

fn make_legacy(id: u64, addr: u64, tid: u32, ts: u64) -> LegacyTraceRecord {
    let mut r = LegacyTraceRecord::new(id, addr, tid, ts);
    r.set_register("rax", 0x42);
    r.add_mem_read(0xAA, 4, 1);
    r.add_mem_write(0xBB, 4, 2);
    r
}

#[test]
fn store_insert_and_get() {
    let s = TraceStore::open_memory().unwrap();
    let r = make_legacy(1, 0x100, 2, 999);
    s.insert(&r).unwrap();
    let got = s.get(1).unwrap();
    assert_eq!(got.id, 1);
    assert_eq!(got.address, 0x100);
    assert_eq!(got.thread_id, 2);
    assert_eq!(got.timestamp, 999);
    assert_eq!(got.registers.get("rax"), Some(&0x42));
    assert_eq!(got.mem_reads.len(), 1);
    assert_eq!(got.mem_writes.len(), 1);
}

#[test]
fn store_get_missing_errors() {
    let s = TraceStore::open_memory().unwrap();
    let r = s.get(42);
    assert!(r.is_err());
}

#[test]
fn store_count_and_batch_insert() {
    let s = TraceStore::open_memory().unwrap();
    let batch: Vec<_> = (0..10).map(|i| make_legacy(i, i * 4, 1, i)).collect();
    s.insert_batch(&batch).unwrap();
    assert_eq!(s.count().unwrap(), 10);
}

#[test]
fn store_get_range_pagination() {
    let s = TraceStore::open_memory().unwrap();
    let batch: Vec<_> = (0..20).map(|i| make_legacy(i, i, 1, i)).collect();
    s.insert_batch(&batch).unwrap();
    let v = s.get_range(5, 3).unwrap();
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].id, 5);
    assert_eq!(v[2].id, 7);
}

#[test]
fn store_distinct_addresses_sorted() {
    let s = TraceStore::open_memory().unwrap();
    s.insert(&make_legacy(1, 0x300, 0, 0)).unwrap();
    s.insert(&make_legacy(2, 0x100, 0, 0)).unwrap();
    s.insert(&make_legacy(3, 0x200, 0, 0)).unwrap();
    s.insert(&make_legacy(4, 0x100, 0, 0)).unwrap();
    let v = s.distinct_addresses().unwrap();
    assert_eq!(v, vec![0x100, 0x200, 0x300]);
}

#[test]
fn store_by_thread() {
    let s = TraceStore::open_memory().unwrap();
    s.insert(&make_legacy(1, 0x10, 1, 0)).unwrap();
    s.insert(&make_legacy(2, 0x20, 2, 0)).unwrap();
    s.insert(&make_legacy(3, 0x30, 1, 0)).unwrap();
    let v = s.by_thread(1).unwrap();
    assert_eq!(v.len(), 2);
}

#[test]
fn store_by_address_range_half_open() {
    let s = TraceStore::open_memory().unwrap();
    s.insert(&make_legacy(1, 0x100, 0, 0)).unwrap();
    s.insert(&make_legacy(2, 0x200, 0, 0)).unwrap();
    s.insert(&make_legacy(3, 0x300, 0, 0)).unwrap();
    let v = s.by_address_range(0x100, 0x300).unwrap();
    assert_eq!(v.len(), 2);
}

#[test]
fn open_trace_file_memory_marker() {
    use std::path::Path;
    let p = Path::new(":memory:");
    let s = open_trace_file(p).unwrap();
    assert_eq!(s.count().unwrap(), 0);
}

// ───────────────────── Round-trips for TraceEvent JSON ─────────────────────

#[test]
fn event_serde_roundtrip_all_variants() {
    let events = vec![
        TraceEvent::Instruction { addr: 1, size: 2 },
        TraceEvent::MemRead { addr: 1, size: 2, value: 3 },
        TraceEvent::MemWrite { addr: 1, size: 2, value: 3 },
        TraceEvent::Call { from: 1, to: 2 },
        TraceEvent::Return { from: 1, to: 2 },
        TraceEvent::Exception { code: 1, addr: 2 },
        TraceEvent::Syscall { number: 1, args: vec![2, 3] },
        TraceEvent::Branch { from: 1, to: 2, taken: false },
        TraceEvent::ModuleLoad { base: 1, size: 2, name: "x".into() },
        TraceEvent::RegisterChange { name: "r".into(), old_value: 1, new_value: 2 },
    ];
    for e in events {
        let j = serde_json::to_string(&e).unwrap();
        let back: TraceEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}

// ───────────────────── Provider trait object Send + Sync ─────────────────────

#[test]
fn provider_trait_object_compiles() {
    let mut p: Box<dyn TraceProvider> =
        Box::new(InMemoryTraceProvider::with_events("n", "x", vec![]));
    assert_eq!(p.name(), "n");
    p.start().unwrap();
    let s = p.stop().unwrap();
    assert_eq!(s.record_count(), 0);
}
