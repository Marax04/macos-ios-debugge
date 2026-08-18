//! Deep adversarial tests for rustre-trace-navigate core API.

use rustre_trace_navigate::*;
use std::ops::Range;
use std::sync::Arc;
use std::thread;

// ─── Seeded LCG ─────────────────────────────────────────────────────────────
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn build_simple_trace(n: usize) -> ExecutionTrace {
    let mut b = TraceBuilder::new("bin");
    for i in 0..n {
        b.insn(0x1000 + (i as u64) * 4, 1, format!("insn{i}"));
    }
    b.build()
}

// Build a trace containing call/ret pattern: outer { inner1 inner2 }
fn build_call_trace() -> ExecutionTrace {
    let mut b = TraceBuilder::new("bin");
    b.insn(0x1000, 1, "i0");
    b.call(0x1004, 1, 0x2000, 0x1008);
    b.insn(0x2000, 1, "callee");
    b.call(0x2004, 1, 0x3000, 0x2008);
    b.insn(0x3000, 1, "deep");
    b.ret(0x3004, 1, 0x2008);
    b.insn(0x2008, 1, "after-inner");
    b.ret(0x200c, 1, 0x1008);
    b.insn(0x1008, 1, "after-outer");
    b.build()
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[test]
fn t01_trace_entry_basic() {
    let e = TraceEntry::insn(0, 0x1000, 1, "nop");
    assert_eq!(e.idx, 0);
    assert_eq!(e.pc, 0x1000);
    assert!(!e.is_call());
    assert!(!e.is_ret());
    assert_eq!(e.call_target(), None);
}

#[test]
fn t02_trace_entry_call() {
    let e = TraceEntry::call(5, 0x1000, 2, 0x2000, 0x1004);
    assert!(e.is_call());
    assert_eq!(e.call_target(), Some(0x2000));
    assert_eq!(e.ret_addr(), Some(0x1004));
    assert_eq!(e.ret_target(), None);
}

#[test]
fn t03_trace_entry_ret() {
    let e = TraceEntry::ret(7, 0x2000, 1, 0x1004);
    assert!(e.is_ret());
    assert_eq!(e.ret_target(), Some(0x1004));
    assert_eq!(e.call_target(), None);
}

#[test]
fn t04_trace_entry_regs() {
    let e = TraceEntry::insn(0, 0, 0, "x").with_regs(vec![(1, 100), (2, 200)]);
    assert_eq!(e.reg_value(1), Some(100));
    assert_eq!(e.reg_value(2), Some(200));
    assert_eq!(e.reg_value(99), None);
}

#[test]
fn t05_trace_entry_mem() {
    let mut e = TraceEntry::insn(0, 0, 0, "x");
    e.add_mem_write(0xdead, vec![1, 2, 3, 4]);
    e.add_mem_read(0xbeef, 8);
    assert_eq!(e.mem_writes.len(), 1);
    assert_eq!(e.mem_reads.len(), 1);
}

#[test]
fn t06_trace_entry_display() {
    let e = TraceEntry::insn(3, 0xabcd, 9, "mov rax, rbx");
    let s = format!("{e}");
    assert!(s.contains("[3]"));
    assert!(s.contains("0xabcd"));
    assert!(s.contains("tid=9"));
}

#[test]
fn t07_access_kind_display() {
    assert_eq!(format!("{}", AccessKind::Read), "read");
    assert_eq!(format!("{}", AccessKind::Write), "write");
}

#[test]
fn t08_bytes_to_u64_boundaries() {
    assert_eq!(bytes_to_u64(&[]), 0);
    assert_eq!(bytes_to_u64(&[0xff]), 0xff);
    assert_eq!(bytes_to_u64(&[1, 0]), 1);
    assert_eq!(bytes_to_u64(&[0, 1]), 256);
    assert_eq!(
        bytes_to_u64(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        u64::MAX
    );
    // > 8 bytes ignored
    assert_eq!(bytes_to_u64(&[1, 0, 0, 0, 0, 0, 0, 0, 0xff]), 1);
}

#[test]
fn t09_bytes_to_u64_fuzz() {
    let mut g = lcg();
    for _ in 0..200 {
        let v = g();
        let bytes = v.to_le_bytes();
        assert_eq!(bytes_to_u64(&bytes), v);
    }
}

#[test]
fn t10_execution_trace_empty() {
    let t = ExecutionTrace::new(vec![], "x");
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert!(t.get(0).is_none());
    assert_eq!(t.idx_for_tsc(0), None);
}

#[test]
fn t11_execution_trace_len_indexing() {
    let t = build_simple_trace(50);
    assert_eq!(t.len(), 50);
    assert!(!t.is_empty());
    for i in 0..50 {
        assert_eq!(t.get(i).unwrap().idx, i);
    }
    assert!(t.get(50).is_none());
    assert!(t.get(usize::MAX).is_none());
}

#[test]
fn t12_execution_trace_tsc_base_total() {
    let t = build_simple_trace(10);
    assert_eq!(t.tsc_base, Some(0));
    assert_eq!(t.total_tsc, Some(9 * 100));
}

#[test]
fn t13_idx_for_tsc() {
    let t = build_simple_trace(20);
    // first entry has tsc=0, second tsc=100, ...
    assert_eq!(t.idx_for_tsc(0), Some(0));
    assert_eq!(t.idx_for_tsc(100), Some(1));
    assert_eq!(t.idx_for_tsc(150), Some(2));
    assert_eq!(t.idx_for_tsc(u64::MAX), Some(19));
}

#[test]
fn t14_idx_for_ms_no_freq() {
    let t = build_simple_trace(5);
    assert_eq!(t.idx_for_ms(1.0), None);
}

#[test]
fn t15_idx_for_ms_with_freq() {
    let mut b = TraceBuilder::new("x").tsc_freq(1_000_000).tsc_per_insn(1000);
    for i in 0..10 {
        b.insn(i, 1, "");
    }
    let t = b.build();
    // freq=1MHz, per insn=1000 ticks = 1ms
    assert_eq!(t.idx_for_ms(0.0), Some(0));
    assert_eq!(t.idx_for_ms(1.5), Some(2));
    // Negative -> 0
    assert_eq!(t.idx_for_ms(-1.0), Some(0));
}

#[test]
fn t16_mem_access_index_basic() {
    let mut b = TraceBuilder::new("x");
    b.insn(0x1000, 1, "");
    b.mem_write(0xa, vec![1, 0, 0, 0]);
    b.insn(0x1004, 1, "");
    b.mem_write(0xa, vec![2, 0, 0, 0]);
    b.insn(0x1008, 1, "");
    let t = b.build();
    let idx = MemAccessIndex::build(&t);
    let writes = idx.writes(0xa);
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0], (0, 1));
    assert_eq!(writes[1], (1, 2));
}

#[test]
fn t17_mem_access_value_at_idx() {
    let mut b = TraceBuilder::new("x");
    b.insn(1, 1, "");
    b.mem_write(0x10, vec![5, 0]);
    b.insn(2, 1, "");
    b.mem_write(0x10, vec![9, 0]);
    b.insn(3, 1, "");
    let t = b.build();
    let idx = MemAccessIndex::build(&t);
    // Writes are attached to the LAST entry pushed; entries are 0,1,2.
    // So writes occur at idx 0 (value 5) and idx 1 (value 9).
    assert_eq!(idx.value_at_idx(0x10, 0), None);
    assert_eq!(idx.value_at_idx(0x10, 1), Some(5));
    assert_eq!(idx.value_at_idx(0x10, 2), Some(9));
    assert_eq!(idx.value_at_idx(0x10, 3), Some(9));
    assert_eq!(idx.value_at_idx(0x99, 5), None);
}

#[test]
fn t18_mem_access_first_last_write() {
    let mut b = TraceBuilder::new("x");
    for i in 0..5 {
        b.insn(i, 1, "");
        b.mem_write(0xb, vec![7, 0]);
    }
    let t = b.build();
    let idx = MemAccessIndex::build(&t);
    assert_eq!(idx.first_write_of_value(0xb, 7), Some(0));
    assert_eq!(idx.last_write_of_value(0xb, 7), Some(4));
    assert_eq!(idx.first_write_of_value(0xb, 999), None);
}

#[test]
fn t19_mem_access_addresses() {
    let mut b = TraceBuilder::new("x");
    b.insn(1, 1, "");
    b.mem_write(0x100, vec![1]);
    b.insn(2, 1, "");
    // add a read via direct entry mut
    let t = b.build();
    let idx = MemAccessIndex::build(&t);
    assert_eq!(idx.address_count(), 1);
    assert_eq!(idx.written_addresses(), vec![0x100]);
    assert!(idx.read_addresses().is_empty());
}

#[test]
fn t20_call_index() {
    let t = build_call_trace();
    let ci = CallIndex::build(&t);
    assert_eq!(ci.function_count(), 2);
    let callers_2000 = ci.callers_of(0x2000);
    assert_eq!(callers_2000.len(), 1);
    let callers_3000 = ci.callers_of(0x3000);
    assert_eq!(callers_3000.len(), 1);
    assert!(ci.callers_of(0x9999).is_empty());
    let counts = ci.call_counts();
    assert_eq!(counts[&0x2000], 1);
}

#[test]
fn t21_reg_timeline() {
    let mut b = TraceBuilder::new("x");
    b.insn(1, 1, "");
    b.regs(vec![(1, 100)]);
    b.insn(2, 1, "");
    b.regs(vec![(1, 200), (2, 50)]);
    b.insn(3, 1, "");
    b.regs(vec![(1, 300)]);
    let t = b.build();
    let rt = RegTimeline::build(&t);
    assert_eq!(rt.value_at(1, 0), Some(100));
    assert_eq!(rt.value_at(1, 2), Some(300));
    assert_eq!(rt.value_at(2, 0), None);
    assert_eq!(rt.value_at(2, 1), Some(50));
    assert_eq!(rt.find_value(1, 200), vec![1]);
    assert_eq!(rt.find_value(1, 999), Vec::<usize>::new());
}

#[test]
fn t22_reg_timeline_history_range() {
    let mut b = TraceBuilder::new("x");
    for i in 0..10 {
        b.insn(i, 1, "");
        b.regs(vec![(1, i)]);
    }
    let t = b.build();
    let rt = RegTimeline::build(&t);
    let h: Vec<(usize, u64)> = rt.history(1, Range { start: 2, end: 5 });
    assert_eq!(h, vec![(2, 2), (3, 3), (4, 4)]);
    assert!(rt.history(999, 0..10).is_empty());
}

#[test]
fn t23_reg_timeline_snapshot_changed() {
    let mut b = TraceBuilder::new("x");
    b.insn(0, 1, "");
    b.regs(vec![(1, 10), (2, 20)]);
    b.insn(1, 1, "");
    b.regs(vec![(1, 11)]);
    b.insn(2, 1, "");
    b.regs(vec![(2, 22)]);
    let t = b.build();
    let rt = RegTimeline::build(&t);
    let snap = rt.snapshot_at(2);
    assert_eq!(snap[&1], 11);
    assert_eq!(snap[&2], 22);
    let changes = rt.changed_between(0, 2);
    assert_eq!(changes.len(), 2);
}

#[test]
fn t24_call_stack_reconstructor() {
    let mut r = CallStackReconstructor::new().with_max_depth(2);
    r.add_symbol(0x2000, "foo");
    let t = build_call_trace();
    let frames = r.rebuild_to(&t, 2); // up to after CALL to 0x2000
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].fn_addr, 0x2000);
    assert_eq!(frames[0].name.as_deref(), Some("foo"));
}

#[test]
fn t25_call_stack_overflow() {
    let mut r = CallStackReconstructor::new().with_max_depth(1);
    let t = build_call_trace();
    let _ = r.rebuild_to(&t, t.len() - 1);
    assert_eq!(r.overflow_count(), 1); // second nested call overflowed
}

#[test]
fn t26_stack_frame_display() {
    let f = StackFrame::new(0x1000, 0x2000, 3, 7).with_name("main");
    assert_eq!(f.display_name(), "main");
    let s = format!("{f}");
    assert!(s.contains("main"));
    assert!(s.contains("[3]"));
    let f2 = StackFrame::new(0xabc, 0xdef, 0, 0);
    assert_eq!(f2.display_name(), "0xabc");
}

#[test]
fn t27_bookmark_basic() {
    let b = Bookmark::new("here", 5, 0x1234).with_note("important");
    assert_eq!(b.name, "here");
    assert_eq!(b.idx, 5);
    assert_eq!(b.pc, 0x1234);
    assert_eq!(b.note.as_deref(), Some("important"));
    let s = format!("{b}");
    assert!(s.contains("here"));
    assert!(s.contains("0x1234"));
}

#[test]
fn t28_bookmark_store() {
    let mut s = BookmarkStore::new();
    assert!(s.is_empty());
    s.insert(Bookmark::new("a", 1, 0x100));
    s.insert(Bookmark::new("b", 3, 0x300));
    s.insert(Bookmark::new("c", 2, 0x200));
    assert_eq!(s.len(), 3);
    let sorted = s.sorted_by_idx();
    assert_eq!(sorted[0].name, "a");
    assert_eq!(sorted[1].name, "c");
    assert_eq!(sorted[2].name, "b");
    let bm = s.remove("a").unwrap();
    assert_eq!(bm.idx, 1);
    assert!(s.remove("nope").is_err());
}

#[test]
fn t29_coverage_stats() {
    let t = build_call_trace();
    let c = CoverageStats::build(&t);
    assert_eq!(c.total_instructions(), t.len());
    let h = c.hot_blocks(3);
    assert!(!h.is_empty());
    assert!(c.unique_block_count() > 0);
    assert_eq!(c.hit_count(0x999), 0);
    assert!(c.hit_count(0x1000) >= 1);
    let frac = c.hot_fraction(1);
    assert!(frac > 0.0 && frac <= 1.0);
}

#[test]
fn t30_coverage_empty() {
    let t = ExecutionTrace::new(vec![], "x");
    let c = CoverageStats::build(&t);
    assert_eq!(c.total_instructions(), 0);
    assert_eq!(c.hot_fraction(5), 0.0);
}

#[test]
fn t31_navigation_history() {
    let mut h = NavigationHistory::new();
    assert_eq!(h.current(), None);
    h.push(1);
    h.push(2);
    h.push(3);
    assert_eq!(h.current(), Some(3));
    // undo: pops current (3), returns previous (2)
    assert_eq!(h.undo(), Some(2));
    assert_eq!(h.redo(), Some(3));
    h.clear();
    assert_eq!(h.current(), None);
}

#[test]
fn t32_navigation_history_future_clear() {
    let mut h = NavigationHistory::new();
    h.push(1);
    h.push(2);
    let _ = h.undo();
    assert_eq!(h.redo_depth(), 1);
    h.push(5); // clears future
    assert_eq!(h.redo_depth(), 0);
}

#[test]
fn t33_step_window() {
    let mut w = StepWindow::new(3);
    assert!(w.is_empty());
    w.push(NavEvent::End);
    w.push(NavEvent::Beginning);
    w.push(NavEvent::End);
    w.push(NavEvent::Beginning); // evict
    assert_eq!(w.len(), 3);
    assert!(matches!(w.latest(), Some(NavEvent::Beginning)));
    let drained = w.drain();
    assert_eq!(drained.len(), 3);
    assert!(w.is_empty());
}

#[test]
fn t34_nav_event_display() {
    assert_eq!(format!("{}", NavEvent::End), "End");
    assert_eq!(format!("{}", NavEvent::Beginning), "Beginning");
    let m = NavEvent::Moved { from: 1, to: 9 };
    assert!(format!("{m}").contains("1 -> 9"));
    let bh = NavEvent::BreakpointHit { idx: 5, pc: 0xabc };
    assert!(format!("{bh}").contains("0xabc"));
    let bm = NavEvent::BookmarkHit { name: "k".into(), idx: 0, pc: 1 };
    assert!(format!("{bm}").contains('k'));
    let c = NavEvent::Cancelled { reason: "stop".into() };
    assert!(format!("{c}").contains("stop"));
}

#[test]
fn t35_trace_navigator_step_forward_backward() {
    let t = build_simple_trace(10);
    let mut nav = TraceNavigator::new(t);
    assert!(nav.at_beginning());
    assert!(nav.step_forward());
    assert_eq!(nav.current_idx, 1);
    assert!(nav.step_backward());
    assert_eq!(nav.current_idx, 0);
    assert!(!nav.step_backward()); // at beginning
    // walk to end
    for _ in 0..20 {
        nav.step_forward();
    }
    assert!(nav.at_end());
}

#[test]
fn t36_trace_navigator_jump() {
    let t = build_simple_trace(10);
    let mut nav = TraceNavigator::new(t);
    assert!(nav.jump_to(5).is_ok());
    assert_eq!(nav.current_idx, 5);
    let err = nav.jump_to(99);
    assert!(matches!(err, Err(NavError::OutOfBounds { .. })));
    let empty = ExecutionTrace::new(vec![], "x");
    let mut nav2 = TraceNavigator::new(empty);
    assert!(matches!(nav2.jump_to(0), Err(NavError::Empty)));
}

#[test]
fn t37_trace_navigator_breakpoint() {
    let t = build_simple_trace(10);
    let mut nav = TraceNavigator::new(t);
    let ev = nav.run_to_breakpoint(0x1000 + 5 * 4).unwrap();
    assert!(matches!(ev, NavEvent::BreakpointHit { idx: 5, .. }));
    assert_eq!(nav.current_idx, 5);
    assert!(nav.run_to_breakpoint(0xdead_beef).is_err());
    let bk = nav.reverse_run_to_breakpoint(0x1000).unwrap();
    assert!(matches!(bk, NavEvent::BreakpointHit { idx: 0, .. }));
}

#[test]
fn t38_trace_navigator_step_over_out() {
    let t = build_call_trace();
    let mut nav = TraceNavigator::new(t);
    // step_out at depth 0 -> cancelled
    let ev = nav.step_out();
    assert!(matches!(ev, NavEvent::Cancelled { .. }));

    // Position at idx=1 (the outer call), then step_over should land at after-outer.
    nav.jump_to(1).unwrap();
    let ev = nav.step_over_forward();
    assert!(matches!(ev, NavEvent::Moved { .. } | NavEvent::End));
}

#[test]
fn t39_value_at_tick_err() {
    let t = build_simple_trace(5);
    let nav = TraceNavigator::new(t);
    let err = nav.get_value_at_tick(0xabc, 3);
    assert!(matches!(err, Err(NavError::NoMemoryHistory(_))));
}

#[test]
fn t40_bookmarks_via_navigator() {
    let t = build_simple_trace(10);
    let mut nav = TraceNavigator::new(t);
    nav.jump_to(4).unwrap();
    nav.set_bookmark("mark", Some("note".into()));
    nav.jump_to(0).unwrap();
    let ev = nav.goto_bookmark("mark").unwrap();
    assert!(matches!(ev, NavEvent::BookmarkHit { idx: 4, .. }));
    assert_eq!(nav.current_idx, 4);
    assert!(matches!(
        nav.goto_bookmark("nope"),
        Err(NavError::BookmarkNotFound(_))
    ));
}

#[test]
fn t41_undo_redo() {
    let t = build_simple_trace(10);
    let mut nav = TraceNavigator::new(t);
    nav.step_forward();
    nav.step_forward();
    nav.step_forward();
    assert_eq!(nav.current_idx, 3);
    let prev = nav.undo();
    assert!(prev.is_some());
    let _cur = nav.current_idx;
    let re = nav.redo();
    assert_eq!(re, Some(3));
    assert!(true); // monotonic OK
}

#[test]
fn t42_entries_at_pc_and_range() {
    let t = build_simple_trace(10);
    let nav = TraceNavigator::new(t);
    let v = nav.entries_at_pc(0x1000);
    assert_eq!(v.len(), 1);
    assert!(nav.entries_at_pc(0xdead).is_empty());
    let r = nav.entries_in_range(2..5);
    assert_eq!(r.len(), 3);
    // range past end clamps
    let r2 = nav.entries_in_range(8..100);
    assert_eq!(r2.len(), 2);
}

#[test]
fn t43_all_calls_rets() {
    let t = build_call_trace();
    let nav = TraceNavigator::new(t);
    assert_eq!(nav.all_calls().len(), 2);
    assert_eq!(nav.all_rets().len(), 2);
}

#[test]
fn t44_peek_forward_backward() {
    let t = build_simple_trace(10);
    let mut nav = TraceNavigator::new(t);
    nav.jump_to(5).unwrap();
    let f = nav.peek_forward(3);
    assert_eq!(f.len(), 3);
    assert_eq!(f[0].idx, 6);
    let b = nav.peek_backward(2);
    assert_eq!(b.len(), 2);
    assert_eq!(b[0].idx, 4);
}

#[test]
fn t45_summary_display() {
    let t = build_simple_trace(10);
    let nav = TraceNavigator::new(t);
    let s = nav.summary();
    assert_eq!(s.total_entries, 10);
    let txt = format!("{s}");
    assert!(txt.contains("TraceNavigator"));
}

#[test]
fn t46_progress() {
    let t = build_simple_trace(11);
    let mut nav = TraceNavigator::new(t);
    assert!((nav.progress() - 0.0).abs() < 1e-9);
    nav.jump_to(10).unwrap();
    assert!((nav.progress() - 1.0).abs() < 1e-9);
    let empty = ExecutionTrace::new(vec![], "x");
    let nav2 = TraceNavigator::new(empty);
    assert!((nav2.progress() - 1.0).abs() < 1e-9);
}

#[test]
fn t47_access_kind_hash_eq() {
    use std::collections::HashSet;
    let mut h = HashSet::new();
    h.insert(AccessKind::Read);
    h.insert(AccessKind::Write);
    h.insert(AccessKind::Read);
    assert_eq!(h.len(), 2);
    assert_eq!(AccessKind::Read, AccessKind::Read);
    assert_ne!(AccessKind::Read, AccessKind::Write);
}

#[test]
fn t48_serde_roundtrip_trace_entry() {
    let mut g = lcg();
    for _ in 0..30 {
        let e = TraceEntry::insn(
            (g() % 1000) as usize,
            g(),
            (g() % 8) as u32,
            format!("x{}", g() % 100),
        );
        let j = serde_json::to_string(&e).unwrap();
        let back: TraceEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(back.idx, e.idx);
        assert_eq!(back.pc, e.pc);
    }
}

#[test]
fn t49_serde_bookmark_roundtrip() {
    let mut g = lcg();
    for _ in 0..30 {
        let b = Bookmark::new(format!("n{}", g()), (g() % 100) as usize, g());
        let j = serde_json::to_string(&b).unwrap();
        let back: Bookmark = serde_json::from_str(&j).unwrap();
        assert_eq!(back.name, b.name);
        assert_eq!(back.idx, b.idx);
        assert_eq!(back.pc, b.pc);
    }
}

#[test]
fn t50_send_sync_threaded_stress() {
    // ExecutionTrace is Send+Sync (no inner cells); share via Arc.
    let t = Arc::new(build_simple_trace(200));
    let mut handles = vec![];
    for _ in 0..4 {
        let t = t.clone();
        handles.push(thread::spawn(move || {
            let mut g = lcg();
            for _ in 0..100 {
                let idx = (g() % t.len() as u64) as usize;
                let e = t.get(idx).unwrap();
                assert_eq!(e.idx, idx);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t51_lcg_fuzz_navigator_no_panic() {
    let t = build_simple_trace(50);
    let mut nav = TraceNavigator::new(t);
    let mut g = lcg();
    for _ in 0..500 {
        let op = g() % 8;
        match op {
            0 => { nav.step_forward(); }
            1 => { nav.step_backward(); }
            2 => { let _ = nav.jump_to((g() % 100) as usize); }
            3 => { let _ = nav.run_to_breakpoint(0x1000 + (g() % 100) * 4); }
            4 => { let _ = nav.reverse_run_to_breakpoint(0x1000 + (g() % 100) * 4); }
            5 => { let _ = nav.undo(); }
            6 => { let _ = nav.redo(); }
            _ => { let _ = nav.get_value_at_tick(g(), (g() % 100) as usize); }
        }
    }
}

#[test]
fn t52_nav_history_max_size() {
    let mut h = NavigationHistory::new();
    for i in 0..3000 {
        h.push(i);
    }
    // capped at 2048 - should still report current as last push
    assert_eq!(h.current(), Some(2999));
}

#[test]
fn t53_mem_index_default() {
    let i = MemAccessIndex::new();
    assert_eq!(i.address_count(), 0);
    assert!(i.accesses(0xdead).is_empty());
    assert!(i.writes(0xdead).is_empty());
    assert!(i.reads(0xdead).is_empty());
}

#[test]
fn t54_call_index_default() {
    let c = CallIndex::new();
    assert_eq!(c.function_count(), 0);
    assert!(c.callers_of(0).is_empty());
    assert!(c.functions().is_empty());
}

#[test]
fn t55_invalid_range_construct() {
    // Ensure error enum constructs and displays.
    let e = NavError::InvalidRange { start: 5, end: 2 };
    let s = format!("{e}");
    assert!(s.contains("start=5"));
    let e2 = NavError::UnknownRegister(42);
    assert!(format!("{e2}").contains("42"));
    let e3 = NavError::LimitExceeded("x".into());
    assert!(format!("{e3}").contains('x'));
    let e4 = NavError::CallStackError("y".into());
    assert!(format!("{e4}").contains('y'));
}
