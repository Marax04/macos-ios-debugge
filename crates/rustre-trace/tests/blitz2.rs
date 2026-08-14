//! blitz2: deep adversarial tests for rustre-trace public API.

use rustre_trace::{
    CompressedBlock, CoverageMap, HeatMap, InMemoryTraceProvider, LegacyTraceFilter,
    LegacyTraceRecord, MemAccess, SyscallRecord, Trace, TraceCompressor, TraceDiff, TraceEvent,
    TraceFilter, TraceFrame, TracePlayer, TraceProvider, TraceRecord, TraceRecorder,
    TraceSession, TraceStore, TraceVisualizationData, coverage_percent, merge_sessions,
};
use std::sync::Arc;

fn lcg_seed() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}
fn step(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s
}

fn rand_event(s: &mut u64) -> TraceEvent {
    let kind = step(s) % 10;
    match kind {
        0 => TraceEvent::Instruction {
            addr: step(s),
            size: (step(s) & 0xF) as u8,
        },
        1 => TraceEvent::MemRead {
            addr: step(s),
            size: (step(s) & 0xF) as u8,
            value: step(s),
        },
        2 => TraceEvent::MemWrite {
            addr: step(s),
            size: (step(s) & 0xF) as u8,
            value: step(s),
        },
        3 => TraceEvent::Call {
            from: step(s),
            to: step(s),
        },
        4 => TraceEvent::Return {
            from: step(s),
            to: step(s),
        },
        5 => TraceEvent::Exception {
            code: step(s) as u32,
            addr: step(s),
        },
        6 => TraceEvent::Syscall {
            number: step(s),
            args: (0..(step(s) % 4)).map(|_| step(s)).collect(),
        },
        7 => TraceEvent::Branch {
            from: step(s),
            to: step(s),
            taken: step(s) & 1 == 0,
        },
        8 => TraceEvent::ModuleLoad {
            base: step(s),
            size: step(s),
            name: format!("mod{}", step(s) % 1000),
        },
        _ => TraceEvent::RegisterChange {
            name: format!("r{}", step(s) % 16),
            old_value: step(s),
            new_value: step(s),
        },
    }
}

fn make_session(n: usize) -> TraceSession {
    let mut s = lcg_seed();
    let mut sess = TraceSession::new("t", "x86_64");
    for i in 0..n {
        let ev = rand_event(&mut s);
        sess.push(ev, (i as u32) % 4, (i as u64) * 100);
    }
    sess
}

// ── 1: TraceEvent primary_addr / type_name ─────────────────────────────────────

#[test]
fn t01_primary_addr_instruction() {
    let e = TraceEvent::Instruction { addr: 0x42, size: 1 };
    assert_eq!(e.primary_addr(), 0x42);
    assert_eq!(e.type_name(), "Instruction");
}

#[test]
fn t02_primary_addr_register_change_is_zero() {
    let e = TraceEvent::RegisterChange {
        name: "rax".into(),
        old_value: 1,
        new_value: 2,
    };
    assert_eq!(e.primary_addr(), 0);
    assert_eq!(e.type_name(), "RegisterChange");
}

#[test]
fn t03_primary_addr_syscall_is_number() {
    let e = TraceEvent::Syscall {
        number: 60,
        args: vec![],
    };
    assert_eq!(e.primary_addr(), 60);
}

#[test]
fn t04_event_predicates_disjoint() {
    let mut s = lcg_seed();
    for _ in 0..200 {
        let e = rand_event(&mut s);
        let n =
            usize::from(e.is_instruction()) + usize::from(e.is_memory_access()) + usize::from(e.is_control_flow()) + usize::from(e.is_syscall()) + usize::from(e.is_exception());
        // Each event belongs to at most one category; some (ModuleLoad,
        // RegisterChange) belong to zero.
        assert!(n <= 1, "event {:?} matched {} predicates", e, n);
    }
}

// ── 2: Display ─────────────────────────────────────────────────────────────────

#[test]
fn t05_event_display_never_panics_fuzz() {
    let mut s = lcg_seed();
    for _ in 0..200 {
        let e = rand_event(&mut s);
        let out = format!("{}", e);
        assert!(!out.is_empty());
    }
}

#[test]
fn t06_record_display_contains_seq_and_tid() {
    let rec = TraceRecord::new(
        7,
        TraceEvent::Instruction { addr: 0x10, size: 1 },
        3,
        123,
    );
    let s = format!("{}", rec);
    assert!(s.contains("7"));
    assert!(s.contains("tid=3"));
    assert!(s.contains("123"));
}

// ── 3: TraceFrame ──────────────────────────────────────────────────────────────

#[test]
fn t07_frame_instruction_pointer_present() {
    let rec = TraceRecord::new(
        0,
        TraceEvent::Instruction { addr: 0xabc, size: 4 },
        1,
        0,
    );
    let f = TraceFrame::new(rec);
    assert_eq!(f.instruction_pointer(), Some(0xabc));
    assert_eq!(f.seq(), 0);
    assert_eq!(f.thread_id(), 1);
    assert_eq!(f.timestamp_ns(), 0);
}

#[test]
fn t08_frame_instruction_pointer_none_for_non_instruction() {
    let rec = TraceRecord::new(
        0,
        TraceEvent::Call { from: 1, to: 2 },
        0,
        0,
    );
    let f = TraceFrame::new(rec);
    assert!(f.instruction_pointer().is_none());
}

#[test]
fn t09_frame_register_set_get() {
    let rec = TraceRecord::new(0, TraceEvent::Instruction { addr: 0, size: 1 }, 0, 0);
    let mut f = TraceFrame::new(rec);
    f.set_register("rax", 0xdead);
    assert_eq!(f.get_register("rax"), Some(0xdead));
    assert_eq!(f.get_register("rbx"), None);
}

// ── 4: TraceFilter ─────────────────────────────────────────────────────────────

#[test]
fn t10_filter_default_passes_all() {
    let f = TraceFilter::default();
    assert!(f.is_empty());
    let sess = make_session(100);
    for r in &sess.records {
        assert!(f.matches(r));
    }
}

#[test]
fn t11_filter_instructions_only_passes_only_instructions() {
    let f = TraceFilter::instructions_only();
    assert!(!f.is_empty());
    let mut s = lcg_seed();
    for _ in 0..200 {
        let e = rand_event(&mut s);
        let want = matches!(e, TraceEvent::Instruction { .. });
        let rec = TraceRecord::new(0, e, 0, 0);
        assert_eq!(f.matches(&rec), want);
    }
}

#[test]
fn t12_filter_for_thread() {
    let f = TraceFilter::for_thread(5);
    let r0 = TraceRecord::new(0, TraceEvent::Instruction { addr: 0, size: 1 }, 5, 0);
    let r1 = TraceRecord::new(0, TraceEvent::Instruction { addr: 0, size: 1 }, 6, 0);
    assert!(f.matches(&r0));
    assert!(!f.matches(&r1));
}

#[test]
fn t13_filter_address_range_boundaries() {
    let f = TraceFilter::address_range(10, 20);
    let mk = |a| TraceRecord::new(0, TraceEvent::Instruction { addr: a, size: 1 }, 0, 0);
    assert!(!f.matches(&mk(9)));
    assert!(f.matches(&mk(10)));
    assert!(f.matches(&mk(19)));
    assert!(!f.matches(&mk(20))); // exclusive upper
    assert!(!f.matches(&mk(21)));
}

#[test]
fn t14_filter_time_range() {
    let f = TraceFilter::time_range(100, 200);
    let mk = |t| TraceRecord::new(0, TraceEvent::Instruction { addr: 0, size: 1 }, 0, t);
    assert!(!f.matches(&mk(99)));
    assert!(f.matches(&mk(100)));
    assert!(f.matches(&mk(200))); // inclusive
    assert!(!f.matches(&mk(201)));
}

#[test]
fn t15_filter_seq_range_half_open() {
    let mut f = TraceFilter::new();
    f.seq_range = Some((5, 10));
    let mk = |s| TraceRecord::new(s, TraceEvent::Instruction { addr: 0, size: 1 }, 0, 0);
    assert!(!f.matches(&mk(4)));
    assert!(f.matches(&mk(5)));
    assert!(f.matches(&mk(9)));
    assert!(!f.matches(&mk(10))); // half-open
}

#[test]
fn t16_filter_validate_conflict() {
    let mut f = TraceFilter::new();
    f.event_types.push("Instruction".to_string());
    f.kinds.push("Call".to_string());
    assert!(f.validate().is_err());
    f.kinds.clear();
    assert!(f.validate().is_ok());
}

#[test]
fn t17_filter_apply_returns_subset() {
    let f = TraceFilter::instructions_only();
    let sess = make_session(200);
    let kept = f.apply(&sess.records);
    let n_instr = sess
        .records
        .iter()
        .filter(|r| matches!(r.event, TraceEvent::Instruction { .. }))
        .count();
    assert_eq!(kept.len(), n_instr);
}

// ── 5: TraceSession ────────────────────────────────────────────────────────────

#[test]
fn t18_session_push_assigns_monotonic_seq() {
    let mut sess = TraceSession::new("s", "x86_64");
    for i in 0..50 {
        sess.push(
            TraceEvent::Instruction { addr: i, size: 1 },
            0,
            i,
        );
    }
    for (i, r) in sess.records.iter().enumerate() {
        assert_eq!(r.seq, i as u64);
    }
}

#[test]
fn t19_session_instruction_count_and_unique_pcs() {
    let mut sess = TraceSession::new("s", "x86_64");
    sess.push(TraceEvent::Instruction { addr: 1, size: 1 }, 0, 0);
    sess.push(TraceEvent::Instruction { addr: 1, size: 1 }, 0, 1);
    sess.push(TraceEvent::Instruction { addr: 2, size: 1 }, 0, 2);
    sess.push(TraceEvent::Call { from: 0, to: 0 }, 0, 3);
    assert_eq!(sess.instruction_count(), 3);
    assert_eq!(sess.unique_pcs().len(), 2);
    assert_eq!(sess.unique_addresses().len(), 2);
}

#[test]
fn t20_session_slice_inclusive_and_oob() {
    let mut sess = TraceSession::new("s", "x86_64");
    for i in 0..10 {
        sess.push(TraceEvent::Instruction { addr: i, size: 1 }, 0, i);
    }
    let out = sess.slice(2, 5).unwrap();
    assert_eq!(out.len(), 4);
    // start > end is an error
    assert!(sess.slice(5, 2).is_err());
    // start == end with valid seq returns 1 record
    let out2 = sess.slice(3, 3).unwrap();
    assert_eq!(out2.len(), 1);
}

#[test]
fn t21_session_merge_arch_mismatch() {
    let mut a = TraceSession::new("a", "x86_64");
    let b = TraceSession::new("b", "arm64");
    assert!(a.merge(&b).is_err());
}

#[test]
fn t22_session_merge_re_sequences() {
    let mut a = TraceSession::new("a", "x86_64");
    a.push(TraceEvent::Instruction { addr: 1, size: 1 }, 0, 0);
    let mut b = TraceSession::new("b", "x86_64");
    b.push(TraceEvent::Instruction { addr: 2, size: 1 }, 1, 100);
    a.merge(&b).unwrap();
    assert_eq!(a.records.len(), 2);
    assert_eq!(a.records[1].seq, 1);
    assert_eq!(a.records[1].thread_id, 1);
}

#[test]
fn t23_session_thread_ids_event_type_counts() {
    let sess = make_session(200);
    let tids = sess.thread_ids();
    assert!(tids.len() <= 4);
    let counts = sess.event_type_counts();
    let total: usize = counts.values().sum();
    assert_eq!(total, sess.records.len());
}

#[test]
fn t24_session_duration_saturating() {
    let sess_empty = TraceSession::new("e", "x86_64");
    assert_eq!(sess_empty.duration_ns(), 0);
    let mut sess = TraceSession::new("s", "x86_64");
    sess.push(TraceEvent::Instruction { addr: 0, size: 1 }, 0, 10);
    sess.push(TraceEvent::Instruction { addr: 0, size: 1 }, 0, 90);
    assert_eq!(sess.duration_ns(), 80);
}

#[test]
fn t25_session_records_for_thread() {
    let mut sess = TraceSession::new("s", "x86_64");
    for i in 0..20 {
        sess.push(
            TraceEvent::Instruction { addr: i, size: 1 },
            (i as u32) % 3,
            i,
        );
    }
    let for_1 = sess.records_for_thread(1);
    for r in &for_1 {
        assert_eq!(r.thread_id, 1);
    }
}

#[test]
fn t26_session_build_index_and_heat() {
    let sess = make_session(100);
    let idx = sess.build_index().unwrap();
    assert_eq!(idx.total_indexed(), sess.records.len());
    let hm = sess.build_heat_map();
    assert_eq!(hm.total_executions() as usize, sess.instruction_count());
}

// ── 6: TraceRecorder ───────────────────────────────────────────────────────────

#[test]
fn t27_recorder_max_events_limits() {
    let mut r = TraceRecorder::with_max_events("r", "x86_64", 3);
    for i in 0..10 {
        r.record_instruction(i, 1, 0, i);
    }
    assert!(r.is_full());
    assert_eq!(r.event_count, 3);
    let s = r.finish();
    assert_eq!(s.records.len(), 3);
}

#[test]
fn t28_recorder_unlimited_when_zero() {
    let mut r = TraceRecorder::new("r", "x86_64");
    for i in 0..100 {
        r.record_instruction(i, 1, 0, i);
    }
    assert!(!r.is_full());
    assert_eq!(r.event_count, 100);
    assert_eq!(r.flushed_count(), 0);
}

#[test]
fn t29_recorder_typed_helpers() {
    let mut r = TraceRecorder::new("r", "x86_64");
    r.record_mem_read(1, 4, 7, 0, 0);
    r.record_mem_write(2, 4, 9, 0, 0);
    r.record_call(3, 4, 0, 0);
    r.record_return(4, 5, 0, 0);
    r.record_exception(0xC0, 6, 0, 0);
    r.record_syscall(60, vec![1, 2, 3], 0, 0);
    let s = r.finish();
    assert_eq!(s.records.len(), 6);
}

// ── 7: TracePlayer ─────────────────────────────────────────────────────────────

#[test]
fn t30_player_walks_all_then_done() {
    let mut sess = TraceSession::new("s", "x86_64");
    for i in 0..5 {
        sess.push(TraceEvent::Instruction { addr: i, size: 1 }, 0, i);
    }
    let mut p = TracePlayer::new(sess);
    assert_eq!(p.total(), 5);
    let mut n = 0;
    while p.next().is_some() {
        n += 1;
    }
    assert_eq!(n, 5);
    assert!(p.is_done());
    assert_eq!(p.remaining(), 0);
    assert!((p.progress() - 1.0).abs() < 1e-9);
}

#[test]
fn t31_player_seek_and_step_back() {
    let mut sess = TraceSession::new("s", "x86_64");
    for i in 0..5 {
        sess.push(TraceEvent::Instruction { addr: i, size: 1 }, 0, i);
    }
    let mut p = TracePlayer::new(sess);
    assert!(p.seek_to_seq(3));
    assert_eq!(p.peek().unwrap().seq, 3);
    assert!(p.step_back());
    assert_eq!(p.peek().unwrap().seq, 2);
    p.reset();
    assert_eq!(p.cursor, 0);
    assert!(!p.step_back());
    assert!(!p.seek_to_seq(999));
}

#[test]
fn t32_player_empty_progress_is_one() {
    let sess = TraceSession::new("s", "x86_64");
    let p = TracePlayer::new(sess);
    assert!(p.is_done());
    assert!((p.progress() - 1.0).abs() < 1e-9);
}

// ── 8: TraceDiff ───────────────────────────────────────────────────────────────

#[test]
fn t33_diff_identical_sessions() {
    let a = make_session(50);
    let b = a.clone();
    let d = TraceDiff::compute(&a, &b);
    assert!(d.is_identical());
    assert!((d.similarity() - 1.0).abs() < 1e-9);
}

#[test]
fn t34_diff_disjoint_sessions() {
    let mut a = TraceSession::new("a", "x86_64");
    a.push(TraceEvent::Instruction { addr: 1, size: 1 }, 0, 0);
    let mut b = TraceSession::new("b", "x86_64");
    b.push(TraceEvent::Instruction { addr: 2, size: 1 }, 0, 0);
    let d = TraceDiff::compute(&a, &b);
    assert!(!d.is_identical());
    assert_eq!(d.common_count, 0);
    assert_eq!(d.only_in_left.len(), 1);
    assert_eq!(d.only_in_right.len(), 1);
}

#[test]
fn t35_diff_empty_similarity_is_one() {
    let a = TraceSession::new("a", "x86_64");
    let b = TraceSession::new("b", "x86_64");
    let d = TraceDiff::compute(&a, &b);
    assert!((d.similarity() - 1.0).abs() < 1e-9);
}

// ── 9: CoverageMap ─────────────────────────────────────────────────────────────

#[test]
fn t36_coverage_record_and_query() {
    let mut c = CoverageMap::new();
    c.record_hit(10);
    c.record_hits(20, 5);
    assert_eq!(c.hit_count(10), 1);
    assert_eq!(c.hit_count(20), 5);
    assert_eq!(c.hit_count(99), 0);
    assert_eq!(c.unique_addresses_hit(), 2);
    assert_eq!(c.total_hits(), 6);
}

#[test]
fn t37_coverage_ratio_zero_total() {
    let c = CoverageMap::new();
    assert!((c.coverage_ratio() - 1.0).abs() < 1e-9);
    let c2 = CoverageMap::with_total(100);
    assert_eq!(c2.coverage_ratio(), 0.0);
}

#[test]
fn t38_coverage_merge_and_hottest() {
    let mut a = CoverageMap::with_total(100);
    a.record_hits(1, 10);
    a.record_hits(2, 5);
    let mut b = CoverageMap::with_total(200);
    b.record_hits(1, 1);
    b.record_hits(3, 7);
    a.merge(&b);
    assert_eq!(a.hit_count(1), 11);
    assert_eq!(a.total_addresses, 200);
    let top = a.hottest_addresses(2);
    assert_eq!(top.len(), 2);
    assert_eq!(top[0].0, 1); // 11 hits
}

#[test]
fn t39_coverage_uncovered_range_step_zero_becomes_one() {
    let mut c = CoverageMap::new();
    c.record_hit(2);
    let u = c.uncovered_in_range(0, 5, 0);
    assert_eq!(u, vec![0, 1, 3, 4]);
}

#[test]
fn t40_coverage_from_session_counts_only_instructions() {
    let mut sess = TraceSession::new("s", "x86_64");
    sess.push(TraceEvent::Instruction { addr: 1, size: 1 }, 0, 0);
    sess.push(TraceEvent::MemRead { addr: 1, size: 1, value: 0 }, 0, 1);
    sess.push(TraceEvent::Instruction { addr: 2, size: 1 }, 0, 2);
    let c = CoverageMap::from_session(&sess);
    assert_eq!(c.unique_addresses_hit(), 2);
    assert_eq!(c.total_hits(), 2);
}

// ── 10: TraceIndex ─────────────────────────────────────────────────────────────

#[test]
fn t41_index_lookups() {
    let mut sess = TraceSession::new("s", "x86_64");
    sess.push(TraceEvent::Instruction { addr: 100, size: 1 }, 1, 0);
    sess.push(TraceEvent::Instruction { addr: 100, size: 1 }, 1, 1);
    sess.push(TraceEvent::Call { from: 100, to: 200 }, 2, 2);
    let idx = sess.build_index().unwrap();
    assert_eq!(idx.seqs_at_addr(100).len(), 3); // Call.from = 100 too
    assert_eq!(idx.seqs_for_thread(1).len(), 2);
    assert_eq!(idx.seqs_for_thread(2).len(), 1);
    assert_eq!(idx.seqs_by_type("Instruction").len(), 2);
    assert!(idx.seqs_at_addr(99).is_empty());
    assert!(idx.seqs_by_type("Nope").is_empty());
    assert_eq!(idx.total_indexed(), 3);
    assert!(!idx.all_addresses().is_empty());
    assert!(!idx.all_thread_ids().is_empty());
    assert!(!idx.all_event_types().is_empty());
}

// ── 11: InMemoryTraceProvider ──────────────────────────────────────────────────

#[test]
fn t42_provider_lifecycle() {
    let events = vec![
        TraceEvent::Instruction { addr: 1, size: 1 },
        TraceEvent::Instruction { addr: 2, size: 1 },
    ];
    let mut p = InMemoryTraceProvider::with_pre_recorded("p", "x86_64", events);
    assert_eq!(p.name(), "p");
    assert!(p.stop().is_err()); // not running
    p.start().unwrap();
    assert!(p.start().is_err()); // already running
    let s = p.stop().unwrap();
    assert_eq!(s.records.len(), 2);
    // Reusable
    p.start().unwrap();
    let s2 = p.stop().unwrap();
    assert_eq!(s2.records.len(), 4);
}

#[test]
fn t43_provider_with_events_alias() {
    let p = InMemoryTraceProvider::with_events("p", "x86_64", vec![]);
    assert_eq!(p.name(), "p");
}

// ── 12: Trace facade JSON round-trip and binary ───────────────────────────────

#[test]
fn t44_trace_json_roundtrip_fuzz() {
    for n in [0usize, 1, 5, 50] {
        let t = Trace::new(make_session(n));
        let bytes = t.to_json().unwrap();
        let t2 = Trace::from_json(&bytes).unwrap();
        assert_eq!(t2.len(), n);
        let pretty = t.to_json_pretty().unwrap();
        assert!(!pretty.is_empty());
    }
}

#[test]
fn t45_trace_binary_roundtrip() {
    let t = Trace::new(make_session(20));
    let bin = t.to_binary().unwrap();
    let t2 = Trace::from_binary(&bin).unwrap();
    assert_eq!(t.len(), t2.len());
}

#[test]
fn t46_trace_from_binary_truncated_errors() {
    assert!(Trace::from_binary(&[]).is_err());
    assert!(Trace::from_binary(&[1, 2, 3]).is_err());
    // header says 100 bytes but body absent
    let mut bad = vec![];
    bad.extend_from_slice(&100u32.to_le_bytes());
    bad.extend_from_slice(b"x");
    assert!(Trace::from_binary(&bad).is_err());
}

#[test]
fn t47_trace_from_binary_corrupt_payload() {
    let mut bad = vec![];
    bad.extend_from_slice(&3u32.to_le_bytes());
    bad.extend_from_slice(b"abc");
    assert!(Trace::from_binary(&bad).is_err());
}

#[test]
fn t48_trace_from_json_malformed_fuzz() {
    let mut s = lcg_seed();
    for _ in 0..20 {
        let len = (step(&mut s) % 32) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| step(&mut s) as u8).collect();
        // Must not panic.
        let _ = Trace::from_json(&bytes);
        let _ = Trace::from_binary(&bytes);
    }
}

#[test]
fn t49_trace_filtered_and_player_and_viz() {
    let t = Trace::new(make_session(100));
    let filt = TraceFilter::instructions_only();
    let f = t.filtered(&filt);
    assert!(f.len() <= t.len());
    assert!(f.name().contains("filtered"));
    let p = t.player();
    assert_eq!(p.total(), t.len());
    let v = t.visualization_data();
    assert_eq!(v.total_events, t.len());
    let v2 = TraceVisualizationData::from_trace(&t);
    assert_eq!(v.total_events, v2.total_events);
    assert_eq!(t.arch(), "x86_64");
}

#[test]
fn t50_trace_with_description() {
    let t = Trace::with_description(make_session(5), "hello");
    assert_eq!(t.description, "hello");
    assert!(!t.is_empty());
    assert_eq!(t.records().len(), 5);
    let cov = t.coverage_map();
    assert!(cov.unique_addresses_hit() <= 5);
}

// ── 13: TraceCompressor round-trip ─────────────────────────────────────────────

#[test]
fn t51_compressor_roundtrip_fuzz() {
    for n in [0usize, 1, 5, 50, 200] {
        let sess = make_session(n);
        let blocks = TraceCompressor::compress(&sess);
        let restored = TraceCompressor::decompress(&blocks, "r", "x86_64");
        // Event sequence must be preserved.
        assert_eq!(restored.records.len(), sess.records.len());
        for (a, b) in sess.records.iter().zip(restored.records.iter()) {
            assert_eq!(a.event, b.event);
            assert_eq!(a.thread_id, b.thread_id);
        }
    }
}

#[test]
fn t52_compressor_ratio() {
    assert_eq!(TraceCompressor::compression_ratio(0, 0), 0.0);
    assert_eq!(TraceCompressor::compression_ratio(10, 2), 5.0);
}

#[test]
fn t53_compressed_block_serde() {
    let b = CompressedBlock {
        start_seq: 0,
        event: TraceEvent::Instruction { addr: 1, size: 1 },
        count: 7,
        thread_id: 0,
        first_timestamp_ns: 0,
    };
    let j = serde_json::to_string(&b).unwrap();
    let b2: CompressedBlock = serde_json::from_str(&j).unwrap();
    assert_eq!(b2.count, 7);
}

// ── 14: LegacyTraceRecord / LegacyTraceFilter ─────────────────────────────────

#[test]
fn t54_legacy_record_ops() {
    let mut r = LegacyTraceRecord::new(1, 0x100, 2, 50);
    assert!(!r.has_memory_access());
    assert!(!r.has_syscall());
    r.add_mem_read(0x10, 4, 5);
    r.add_mem_write(0x20, 4, 6);
    r.set_register("rax", 7);
    assert!(r.has_memory_access());
    assert_eq!(r.mem_reads.len(), 1);
    assert_eq!(r.mem_writes.len(), 1);
    assert_eq!(r.registers["rax"], 7);
}

#[test]
fn t55_legacy_filter_address_range_exclusive_hi() {
    let f = LegacyTraceFilter {
        address_range: Some((10, 20)),
        ..Default::default()
    };
    let mk = |a| LegacyTraceRecord::new(0, a, 0, 0);
    assert!(!f.matches(&mk(9)));
    assert!(f.matches(&mk(10)));
    assert!(f.matches(&mk(19)));
    assert!(!f.matches(&mk(20)));
}

#[test]
fn t56_legacy_filter_thread_time_limit() {
    let f = LegacyTraceFilter {
        thread_id: Some(2),
        time_range: Some((100, 200)),
        instruction_limit: Some(2),
        ..Default::default()
    };
    let recs = vec![
        LegacyTraceRecord::new(0, 0, 2, 100),
        LegacyTraceRecord::new(1, 0, 2, 150),
        LegacyTraceRecord::new(2, 0, 2, 200),
        LegacyTraceRecord::new(3, 0, 3, 150),
        LegacyTraceRecord::new(4, 0, 2, 50),
    ];
    let kept = f.apply(&recs);
    assert_eq!(kept.len(), 2);
}

// ── 15: TraceStore SQLite ─────────────────────────────────────────────────────

#[test]
fn t57_store_in_memory_crud() {
    let s = TraceStore::open_memory().unwrap();
    assert_eq!(s.count().unwrap(), 0);
    let mut r = LegacyTraceRecord::new(7, 0x1000, 1, 100);
    r.set_register("rax", 1);
    r.add_mem_read(0x10, 4, 0xdead);
    r.syscall = Some(SyscallRecord {
        number: 60,
        name: "exit".into(),
        args: vec![0],
        ret: 0,
    });
    s.insert(&r).unwrap();
    assert_eq!(s.count().unwrap(), 1);
    let got = s.get(7).unwrap();
    assert_eq!(got.address, 0x1000);
    assert_eq!(got.thread_id, 1);
    assert_eq!(got.registers["rax"], 1);
    assert_eq!(got.syscall.as_ref().unwrap().name, "exit");
    assert!(s.get(999).is_err());
}

#[test]
fn t58_store_batch_and_queries() {
    let s = TraceStore::open_memory().unwrap();
    let recs: Vec<LegacyTraceRecord> = (0..10)
        .map(|i| LegacyTraceRecord::new(i, i * 0x10, (i as u32) % 2, i * 100))
        .collect();
    s.insert_batch(&recs).unwrap();
    assert_eq!(s.count().unwrap(), 10);
    let page = s.get_range(0, 5).unwrap();
    assert_eq!(page.len(), 5);
    let by_addr = s.by_address_range(0, 0x30).unwrap();
    assert_eq!(by_addr.len(), 3);
    let by_thread = s.by_thread(0).unwrap();
    assert_eq!(by_thread.len(), 5);
    let addrs = s.distinct_addresses().unwrap();
    assert_eq!(addrs.len(), 10);
}

#[test]
fn t59_open_trace_file_memory() {
    use std::path::Path;
    let s = rustre_trace::open_trace_file(Path::new(":memory:")).unwrap();
    assert_eq!(s.count().unwrap(), 0);
}

// ── 16: HeatMap ───────────────────────────────────────────────────────────────

#[test]
fn t60_heatmap_ops() {
    let mut h = HeatMap::new();
    for _ in 0..3 {
        h.record(0x10);
    }
    h.record(0x20);
    assert_eq!(h.count(0x10), 3);
    assert_eq!(h.count(0x99), 0);
    assert_eq!(h.unique_addresses(), 2);
    assert_eq!(h.total_executions(), 4);
    assert_eq!(h.max_count(), 3);
    assert_eq!(h.min_count(), 1);
    let sorted = h.sorted_entries();
    assert_eq!(sorted[0].0, 0x10);
    let top = h.top_n(1);
    assert_eq!(top.len(), 1);
    assert_eq!(top[0], (0x10, 3));
    let heat = h.sorted_by_heat();
    assert_eq!(heat[0].0, 0x10);
}

#[test]
fn t61_heatmap_merge() {
    let mut a = HeatMap::new();
    a.record(1);
    let mut b = HeatMap::new();
    b.record(1);
    b.record(2);
    a.merge(&b);
    assert_eq!(a.count(1), 2);
    assert_eq!(a.count(2), 1);
}

// ── 17: utility functions ────────────────────────────────────────────────────

#[test]
fn t62_coverage_percent() {
    assert_eq!(coverage_percent(0, 0), 100.0);
    assert_eq!(coverage_percent(1, 2), 50.0);
    assert_eq!(coverage_percent(0, 1), 0.0);
}

#[test]
fn t63_merge_sessions_empty_and_mismatch() {
    let m = merge_sessions(&[]).unwrap();
    assert_eq!(m.records.len(), 0);
    let a = TraceSession::new("a", "x86_64");
    let b = TraceSession::new("b", "arm64");
    assert!(merge_sessions(&[a, b]).is_err());
}

#[test]
fn t64_merge_sessions_preserves_count() {
    let a = make_session(20);
    let b = make_session(15);
    let m = merge_sessions(&[a.clone(), b.clone()]).unwrap();
    assert_eq!(m.records.len(), a.records.len() + b.records.len());
}

// ── 18: Send/Sync stress on TraceStore (Arc<Mutex<Connection>>) ───────────────

#[test]
fn t65_store_threaded_stress() {
    let s = Arc::new(TraceStore::open_memory().unwrap());
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let s = Arc::clone(&s);
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                let id = t * 1000 + i;
                let rec = LegacyTraceRecord::new(id, id * 8, t as u32, i);
                s.insert(&rec).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(s.count().unwrap(), 400);
}

// ── 19: TraceFilter kinds field fallback ───────────────────────────────────────

#[test]
fn t66_filter_kinds_fallback_when_event_types_empty() {
    let mut f = TraceFilter::new();
    f.kinds.push("Call".to_string());
    let r0 = TraceRecord::new(0, TraceEvent::Call { from: 0, to: 1 }, 0, 0);
    let r1 = TraceRecord::new(0, TraceEvent::Instruction { addr: 0, size: 1 }, 0, 0);
    assert!(f.matches(&r0));
    assert!(!f.matches(&r1));
}

// ── 20: Eq/Hash consistency for TraceEvent on 30+ pairs ───────────────────────

#[test]
fn t67_event_eq_consistency() {
    let mut s = lcg_seed();
    for _ in 0..40 {
        let a = rand_event(&mut s);
        let b = a.clone();
        assert_eq!(a, b);
    }
}

// ── 21: MemAccess / SyscallRecord serde round-trip ────────────────────────────

#[test]
fn t68_memaccess_syscall_roundtrip() {
    let m = MemAccess { address: 1, size: 4, value: 7 };
    let j = serde_json::to_string(&m).unwrap();
    let m2: MemAccess = serde_json::from_str(&j).unwrap();
    assert_eq!(m, m2);
    let sc = SyscallRecord {
        number: 1,
        name: "x".into(),
        args: vec![1, 2],
        ret: -1,
    };
    let j = serde_json::to_string(&sc).unwrap();
    let sc2: SyscallRecord = serde_json::from_str(&j).unwrap();
    assert_eq!(sc, sc2);
}

// ── 22: TraceFilter core_address_range bridge ─────────────────────────────────

#[test]
fn t69_filter_core_address_range() {
    use rustre_core::address::Address;
    let f = TraceFilter::core_address_range(Address::new(10), Address::new(20));
    let mk = |a| TraceRecord::new(0, TraceEvent::Instruction { addr: a, size: 1 }, 0, 0);
    assert!(f.matches(&mk(10)));
    assert!(!f.matches(&mk(20)));
}

// ── 23: peek_all_remaining ────────────────────────────────────────────────────

#[test]
fn t70_player_peek_all_remaining() {
    let mut sess = TraceSession::new("s", "x86_64");
    for i in 0..5 {
        sess.push(TraceEvent::Instruction { addr: i, size: 1 }, 0, i);
    }
    let mut p = TracePlayer::new(sess);
    assert_eq!(p.peek_all_remaining().len(), 5);
    let _ = p.next();
    let _ = p.next();
    assert_eq!(p.peek_all_remaining().len(), 3);
}
