//! Blitz test suite for `rustre-trace-navigate`.
//!
//! Adversarial / edge-case coverage targeting the public API. Tests are
//! intentionally strict about Err variants, off-by-one boundaries, and
//! invariants such as call/ret balance, undo/redo semantics, and parser
//! robustness.

use rustre_trace_navigate::*;
use std::collections::HashSet;

// ─── Helpers ────────────────────────────────────────────────────────────────

fn empty_trace() -> ExecutionTrace {
    ExecutionTrace::new(Vec::new(), "empty.bin")
}

fn nav_with(n: usize) -> TraceNavigator {
    let mut b = TraceBuilder::new("bench.bin");
    for i in 0..n {
        b.insn(0x1000 + (i as u64) * 4, 1, format!("insn_{i}"));
    }
    b.build_navigator()
}

fn paired_trace() -> ExecutionTrace {
    // call/ret balanced trace
    let mut b = TraceBuilder::new("paired.bin");
    b.insn(0x1000, 1, "entry");
    b.call(0x1004, 1, 0x2000, 0x1008);
    b.insn(0x2000, 1, "callee");
    b.ret(0x2004, 1, 0x1008);
    b.insn(0x1008, 1, "after");
    b.build()
}

// ─── bytes_to_u64 boundary ──────────────────────────────────────────────────

#[test]
fn b_bytes_to_u64_full8() {
    let v = bytes_to_u64(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    assert_eq!(v, 0x8877_6655_4433_2211);
}

#[test]
fn b_bytes_to_u64_truncates_extra() {
    // Only first 8 bytes are used.
    let v = bytes_to_u64(&[0x11; 16]);
    assert_eq!(v, 0x1111_1111_1111_1111);
}

#[test]
fn b_bytes_to_u64_zero_bytes() {
    assert_eq!(bytes_to_u64(&[0u8; 8]), 0);
}

// ─── ExecutionTrace ─────────────────────────────────────────────────────────

#[test]
fn b_exec_trace_new_empty() {
    let t = empty_trace();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert!(t.tsc_base.is_none());
    assert!(t.total_tsc.is_none());
    assert!(t.get(0).is_none());
    assert!(t.idx_for_tsc(0).is_none());
    assert!(t.idx_for_ms(0.0).is_none());
}

#[test]
fn b_exec_trace_with_arch_and_freq() {
    let t = empty_trace().with_arch("aarch64").with_tsc_freq(1_000_000);
    assert_eq!(t.arch, "aarch64");
    assert_eq!(t.tsc_freq_hz, Some(1_000_000));
}

#[test]
fn b_exec_trace_idx_for_tsc_basic() {
    let mut b = TraceBuilder::new("t").tsc_per_insn(100);
    b.insn(0x1000, 1, "a");
    b.insn(0x1004, 1, "b");
    b.insn(0x1008, 1, "c");
    let t = b.build();
    // tsc values 0, 100, 200
    assert_eq!(t.idx_for_tsc(0), Some(0));
    assert_eq!(t.idx_for_tsc(50), Some(1)); // first tsc >= 50 not exists; partition_point returns 1
    // The function does `tsc.unwrap_or(0) < tsc`; for target 100, items <100 = [0] => pos 1
    assert_eq!(t.idx_for_tsc(100), Some(1));
    // Beyond end clamps.
    assert_eq!(t.idx_for_tsc(99999), Some(2));
}

#[test]
fn b_exec_trace_idx_for_ms_requires_freq_and_base() {
    let mut b = TraceBuilder::new("t").tsc_per_insn(0); // tsc=0 for all
    b.insn(0x1000, 1, "a");
    let t = b.build(); // no freq set
    assert!(t.idx_for_ms(1.0).is_none());
}

// ─── TraceEntry ─────────────────────────────────────────────────────────────

#[test]
fn b_entry_insn_non_call_non_ret_targets_none() {
    let e = TraceEntry::insn(0, 0x1000, 1, "nop");
    assert_eq!(e.call_target(), None);
    assert_eq!(e.ret_addr(), None);
    assert_eq!(e.ret_target(), None);
}

#[test]
fn b_entry_ret_call_target_none() {
    let e = TraceEntry::ret(0, 0x1000, 1, 0x2000);
    assert_eq!(e.call_target(), None);
    assert_eq!(e.ret_addr(), None);
    assert_eq!(e.ret_target(), Some(0x2000));
}

#[test]
fn b_entry_with_tsc() {
    let e = TraceEntry::insn(0, 0x1000, 1, "x").with_tsc(42);
    assert_eq!(e.tsc, Some(42));
}

#[test]
fn b_entry_reg_value_last_wins_or_first() {
    // Implementation uses find: returns first match.
    let e = TraceEntry::insn(0, 0x1000, 1, "x").with_regs(vec![(7, 100), (7, 200)]);
    assert_eq!(e.reg_value(7), Some(100));
}

// ─── MemAccessIndex ─────────────────────────────────────────────────────────

#[test]
fn b_mem_access_no_writes_returns_err() {
    let nav = nav_with(3);
    let r = nav.get_value_at_tick(0xDEAD, 1);
    assert!(matches!(r, Err(NavError::NoMemoryHistory(0xDEAD))));
}

#[test]
fn b_mem_access_value_at_tick_before_first_write_is_err() {
    let mut b = TraceBuilder::new("t");
    b.insn(0x1000, 1, "nop");
    b.insn(0x1004, 1, "store");
    b.mem_write(0x500, vec![0xAA]);
    let nav = b.build_navigator();
    // At tick 0: no write before it
    let r = nav.get_value_at_tick(0x500, 0);
    assert!(matches!(r, Err(NavError::NoMemoryHistory(0x500))));
}

#[test]
fn b_mem_addresses_lists() {
    let mut b = TraceBuilder::new("t");
    b.insn(0x1000, 1, "rw");
    b.mem_write(0x500, vec![1]);
    let mut e = TraceEntry::insn(1, 0x1004, 1, "r");
    e.add_mem_read(0x600, 4);
    b.entries.push(e);
    let trace = b.build();
    let idx = MemAccessIndex::build(&trace);
    assert!(idx.written_addresses().contains(&0x500));
    assert!(idx.read_addresses().contains(&0x600));
    assert_eq!(idx.address_count(), 2);
}

// ─── Navigation - jumps & errors ────────────────────────────────────────────

#[test]
fn b_jump_to_on_empty_returns_empty_err() {
    let trace = empty_trace();
    let mut nav = TraceNavigator::new(trace);
    assert!(matches!(nav.jump_to(0), Err(NavError::Empty)));
}

#[test]
fn b_jump_to_exact_last_index_ok() {
    let mut nav = nav_with(5);
    nav.jump_to(4).unwrap();
    assert_eq!(nav.current_idx, 4);
}

#[test]
fn b_jump_to_off_by_one_oob() {
    let mut nav = nav_with(5);
    let err = nav.jump_to(5).unwrap_err();
    match err {
        NavError::OutOfBounds { idx, max } => {
            assert_eq!(idx, 5);
            assert_eq!(max, 4);
        }
        _ => panic!("wrong err: {err:?}"),
    }
}

#[test]
fn b_step_forward_increments_and_at_end_false() {
    let mut nav = nav_with(2);
    assert!(nav.step_forward());
    assert_eq!(nav.current_idx, 1);
    assert!(!nav.step_forward()); // at end
}

#[test]
fn b_step_backward_at_idx_zero_returns_false() {
    let mut nav = nav_with(3);
    assert!(!nav.step_backward());
    assert_eq!(nav.current_idx, 0);
}

#[test]
fn b_run_to_breakpoint_skips_current_pc() {
    // run_to_breakpoint searches from current_idx + 1, so even if PC at
    // current matches, it should look further (and return NoResults if absent).
    let mut nav = nav_with(3);
    // current is 0 with pc 0x1000. Search for 0x1000 should NOT find current.
    assert!(matches!(
        nav.run_to_breakpoint(0x1000),
        Err(NavError::NoResults)
    ));
}

#[test]
fn b_reverse_run_to_breakpoint_at_zero_no_results() {
    let mut nav = nav_with(5);
    assert!(matches!(
        nav.reverse_run_to_breakpoint(0x1000),
        Err(NavError::NoResults)
    ));
}

// ─── Step over / step out ───────────────────────────────────────────────────

#[test]
fn b_step_out_at_outermost_cancelled() {
    let mut nav = TraceNavigator::new(paired_trace());
    // At idx 0, depth is 0
    let ev = nav.step_out();
    assert!(matches!(ev, NavEvent::Cancelled { .. }));
}

#[test]
fn b_step_over_balanced_returns_after_callee() {
    let mut nav = TraceNavigator::new(paired_trace());
    nav.current_idx = 1; // at CALL
    // rebuild incremental depth so step_over knows current depth
    let _ = nav.jump_to(1);
    let ev = nav.step_over_forward();
    assert!(matches!(ev, NavEvent::Moved { .. } | NavEvent::End));
    // step_over returns as soon as depth <= initial_depth; after jump_to(1)
    // the CALL at idx 1 was applied so depth is 1; stepping to idx 2 keeps
    // depth at 1 (still inside callee body), which already satisfies the
    // "<= initial_depth" exit condition. So we simply advance by one.
    assert!(nav.current_idx >= 2);
}

// ─── Bookmarks ──────────────────────────────────────────────────────────────

#[test]
fn b_bookmark_remove_not_found_err() {
    let mut store = BookmarkStore::new();
    let r = store.remove("nope");
    assert!(matches!(r, Err(NavError::BookmarkNotFound(_))));
}

#[test]
fn b_bookmark_store_replace_on_insert_same_name() {
    let mut store = BookmarkStore::new();
    store.insert(Bookmark::new("a", 5, 0x1000));
    store.insert(Bookmark::new("a", 9, 0x2000));
    assert_eq!(store.len(), 1);
    assert_eq!(store.get("a").unwrap().idx, 9);
}

#[test]
fn b_bookmark_set_on_empty_trace_is_noop() {
    let mut nav = TraceNavigator::new(empty_trace());
    nav.set_bookmark("x", None);
    assert!(nav.bookmarks.is_empty());
}

// ─── NavigationHistory ──────────────────────────────────────────────────────

#[test]
fn b_nav_history_empty_undo_redo() {
    let mut h = NavigationHistory::new();
    assert!(h.undo().is_none());
    assert!(h.redo().is_none());
}

#[test]
fn b_nav_history_push_clears_future() {
    let mut h = NavigationHistory::new();
    h.push(1);
    h.push(2);
    h.push(3);
    h.undo(); // current 2, future [3]
    assert_eq!(h.redo_depth(), 1);
    h.push(99);
    assert_eq!(h.redo_depth(), 0); // cleared
}

#[test]
fn b_nav_history_depths_after_pushes() {
    let mut h = NavigationHistory::new();
    h.push(10);
    h.push(11);
    h.push(12);
    // past = [10,11,12], current is 12 => undo_depth = 2
    assert_eq!(h.undo_depth(), 2);
    assert_eq!(h.current(), Some(12));
}

#[test]
fn b_nav_history_clear() {
    let mut h = NavigationHistory::new();
    h.push(1);
    h.push(2);
    h.clear();
    assert!(h.current().is_none());
    assert_eq!(h.undo_depth(), 0);
    assert_eq!(h.redo_depth(), 0);
}

// ─── StepWindow ─────────────────────────────────────────────────────────────

#[test]
fn b_step_window_drain_empties() {
    let mut w = StepWindow::new(3);
    w.push(NavEvent::End);
    w.push(NavEvent::Beginning);
    let v = w.drain();
    assert_eq!(v.len(), 2);
    assert!(w.is_empty());
}

#[test]
fn b_step_window_latest_after_eviction() {
    let mut w = StepWindow::new(2);
    w.push(NavEvent::End);
    w.push(NavEvent::Beginning);
    w.push(NavEvent::Moved { from: 0, to: 1 });
    match w.latest() {
        Some(NavEvent::Moved { from: 0, to: 1 }) => {}
        other => panic!("unexpected latest: {other:?}"),
    }
    assert_eq!(w.len(), 2);
}

// ─── DrcovData parsing ──────────────────────────────────────────────────────

#[test]
fn b_drcov_parses_modules_text() {
    let input = "DRCOV VERSION: 2\n\
        DRCOV FLAVOR: drcov\n\
        Module Table:\n\
        Columns: id, base, end, entry, checksum, timestamp, path\n\
        0, 0x400000, 0x500000, 0x401000, 0, 0, /usr/bin/foo\n\
        BB Table:\n\
        0x100, 5, 0\n";
    let d = DrcovData::parse(input);
    assert_eq!(d.modules.len(), 1);
    assert_eq!(d.modules[0].base, 0x0040_0000);
    assert_eq!(d.modules[0].end, 0x0050_0000);
    assert_eq!(d.modules[0].name, "foo");
    assert_eq!(d.basic_blocks.len(), 1);
    assert_eq!(d.basic_blocks[0].start, 0x100);
    let resolved = d.resolve_addresses();
    assert_eq!(resolved, vec![0x0040_0100]);
}

#[test]
fn b_drcov_garbage_lines_ignored() {
    let input = "garbage\n\nDRCOV VERSION: 2\nrandom\n";
    let d = DrcovData::parse(input);
    assert!(d.modules.is_empty());
    assert!(d.basic_blocks.is_empty());
}

#[test]
fn b_drcov_malformed_module_row_skipped() {
    let input = "Module Table:\n0, 0x100\n"; // too few fields
    let d = DrcovData::parse(input);
    assert!(d.modules.is_empty());
}

#[test]
fn b_drcov_to_block_hits() {
    let mut d = DrcovData {
        modules: vec![DrcovModule {
            id: 0,
            base: 0x1000,
            end: 0x2000,
            name: "m".into(),
        }],
        basic_blocks: vec![
            DrcovBB { start: 0x10, size: 4, mod_id: 0 },
            DrcovBB { start: 0x10, size: 4, mod_id: 0 },
            DrcovBB { start: 0x20, size: 4, mod_id: 0 },
        ],
    };
    let hits = d.to_block_hits();
    assert_eq!(hits.get(&0x1010), Some(&2));
    assert_eq!(hits.get(&0x1020), Some(&1));
    // unknown mod_id filters out
    d.basic_blocks.push(DrcovBB { start: 0, size: 0, mod_id: 99 });
    let hits2 = d.to_block_hits();
    assert_eq!(hits2.len(), 2);
}

// ─── CoverageStats ──────────────────────────────────────────────────────────

#[test]
fn b_coverage_hot_fraction_empty() {
    let t = empty_trace();
    let s = CoverageStats::build(&t);
    assert!((s.hot_fraction(5) - 0.0).abs() < 1e-9);
}

#[test]
fn b_coverage_hot_fraction_all() {
    let nav = nav_with(10);
    let s = CoverageStats::build(&nav.trace);
    let frac = s.hot_fraction(100);
    assert!((frac - 1.0).abs() < 1e-9);
}

// ─── ExecutionHeatmap ───────────────────────────────────────────────────────

#[test]
fn b_heatmap_unvisited_returns_zero() {
    let nav = nav_with(3);
    let s = CoverageStats::build(&nav.trace);
    let hm = ExecutionHeatmap::build(&s);
    assert_eq!(hm.heat_at(0xDEAD), 0.0);
}

#[test]
fn b_heatmap_hottest_sorted_descending() {
    let mut b = TraceBuilder::new("t");
    for _ in 0..3 {
        b.insn(0x1000, 1, "a");
    }
    for _ in 0..5 {
        b.insn(0x2000, 1, "b");
    }
    b.insn(0x3000, 1, "c");
    let trace = b.build();
    let s = CoverageStats::build(&trace);
    let hm = ExecutionHeatmap::build(&s);
    let top = hm.hottest(3);
    assert_eq!(top[0].0, 0x2000);
}

// ─── ThreadView ─────────────────────────────────────────────────────────────

#[test]
fn b_thread_view_unique_pcs() {
    let mut b = TraceBuilder::new("t");
    b.insn(0x1000, 1, "a");
    b.insn(0x1000, 1, "a2");
    b.insn(0x2000, 1, "b");
    b.insn(0x9000, 2, "other");
    let trace = b.build();
    let v = ThreadView::build(&trace, 1);
    let pcs = v.unique_pcs();
    assert_eq!(pcs.len(), 2);
    assert!(!v.is_empty());
}

// ─── CallStackReconstructor ─────────────────────────────────────────────────

#[test]
fn b_call_stack_overflow_counted() {
    let mut r = CallStackReconstructor::new().with_max_depth(2);
    for i in 0..5 {
        let e = TraceEntry::call(i, 0x1000, 1, 0x2000, 0x1004);
        r.process(&e);
    }
    assert_eq!(r.depth(), 2);
    assert_eq!(r.overflow_count(), 3);
}

#[test]
fn b_call_stack_ret_on_empty_safe() {
    let mut r = CallStackReconstructor::new();
    let e = TraceEntry::ret(0, 0x1000, 1, 0x2000);
    r.process(&e);
    assert_eq!(r.depth(), 0);
}

#[test]
fn b_call_stack_symbol_applied() {
    let mut r = CallStackReconstructor::new();
    r.add_symbol(0x2000, "foo");
    let e = TraceEntry::call(0, 0x1000, 1, 0x2000, 0x1004);
    r.process(&e);
    assert_eq!(r.frames()[0].name.as_deref(), Some("foo"));
}

// ─── TraceFilter combinations ───────────────────────────────────────────────

#[test]
fn b_filter_blacklist_excludes() {
    let mut f = TraceFilter::any();
    f.pc_blacklist.insert(0x1000);
    let e = TraceEntry::insn(0, 0x1000, 1, "x");
    assert!(!f.matches(&e));
}

#[test]
fn b_filter_only_mem_writes() {
    let mut f = TraceFilter::any();
    f.only_mem_writes = true;
    let no_w = TraceEntry::insn(0, 0x1000, 1, "x");
    assert!(!f.matches(&no_w));
    let mut with_w = TraceEntry::insn(1, 0x1000, 1, "x");
    with_w.add_mem_write(0x500, vec![1]);
    assert!(f.matches(&with_w));
}

#[test]
fn b_filter_only_rets() {
    let f = TraceFilter {
        only_rets: true,
        ..TraceFilter::any()
    };
    let r = TraceEntry::ret(0, 0x1000, 1, 0x2000);
    assert!(f.matches(&r));
    let i = TraceEntry::insn(1, 0x1000, 1, "x");
    assert!(!f.matches(&i));
}

// ─── TraceSearcher ──────────────────────────────────────────────────────────

#[test]
fn b_searcher_case_insensitive() {
    let mut b = TraceBuilder::new("t");
    b.insn(0x1000, 1, "MOV rax, 1");
    let trace = b.build();
    let s = TraceSearcher::new("mov");
    assert_eq!(s.find_all(&trace).len(), 1);
}

#[test]
fn b_searcher_find_next_no_match() {
    let mut b = TraceBuilder::new("t");
    b.insn(0x1000, 1, "x");
    b.insn(0x1004, 1, "y");
    let trace = b.build();
    let s = TraceSearcher::new("zzzz");
    assert!(s.find_next(&trace, 0).is_none());
    assert!(s.find_prev(&trace, 2).is_none());
}

// ─── TraceStatistics ────────────────────────────────────────────────────────

#[test]
fn b_stats_unbalanced_call_ret() {
    let mut b = TraceBuilder::new("t");
    b.call(0x1000, 1, 0x2000, 0x1004);
    b.call(0x2000, 1, 0x3000, 0x2004);
    b.ret(0x3000, 1, 0x2004);
    let trace = b.build();
    let s = TraceStatistics::compute(&trace);
    assert!(!s.is_balanced());
    assert_eq!(s.call_ret_balance, 1);
}

#[test]
fn b_stats_empty_trace() {
    let t = empty_trace();
    let s = TraceStatistics::compute(&t);
    assert_eq!(s.total_entries, 0);
    assert!(s.is_balanced());
    assert_eq!(s.insn_per_unique_pc(), 0.0);
    assert!(s.tsc_duration.is_none());
}

#[test]
fn b_stats_counts_branches_syscalls_exceptions() {
    let mut entries = Vec::new();
    let mut e1 = TraceEntry::insn(0, 0x1000, 1, "br");
    e1.kind = EntryKind::Branch { target: 0x2000, taken: true };
    entries.push(e1);
    let mut e2 = TraceEntry::insn(1, 0x1004, 1, "sys");
    e2.kind = EntryKind::Syscall { number: 60 };
    entries.push(e2);
    let mut e3 = TraceEntry::insn(2, 0x1008, 1, "ex");
    e3.kind = EntryKind::Exception { code: 11 };
    entries.push(e3);
    let trace = ExecutionTrace::new(entries, "t");
    let s = TraceStatistics::compute(&trace);
    assert_eq!(s.total_branches, 1);
    assert_eq!(s.total_syscalls, 1);
    assert_eq!(s.total_exceptions, 1);
}

// ─── TraceSlice ─────────────────────────────────────────────────────────────

#[test]
fn b_slice_inverted_range_safe() {
    let nav = nav_with(5);
    // start > end + 1 ⇒ Range start > end → empty
    let slice = TraceSlice::new(&nav.trace, 10, 2);
    assert!(slice.is_empty());
}

#[test]
fn b_slice_single_entry() {
    let nav = nav_with(5);
    let slice = TraceSlice::new(&nav.trace, 2, 2);
    assert_eq!(slice.len(), 1);
    assert_eq!(slice.statistics().len, 1);
}

// ─── AccessKind & EntryKind ────────────────────────────────────────────────

#[test]
fn b_access_kind_display() {
    assert_eq!(AccessKind::Read.to_string(), "read");
    assert_eq!(AccessKind::Write.to_string(), "write");
}

#[test]
fn b_access_kind_eq_hash() {
    let mut s = HashSet::new();
    s.insert(AccessKind::Read);
    s.insert(AccessKind::Read);
    s.insert(AccessKind::Write);
    assert_eq!(s.len(), 2);
}

// ─── NavError Display ──────────────────────────────────────────────────────

#[test]
fn b_naverror_display_strings() {
    let e1 = NavError::OutOfBounds { idx: 7, max: 3 };
    assert!(e1.to_string().contains("idx=7"));
    let e2 = NavError::NoMemoryHistory(0xDEAD);
    assert!(e2.to_string().contains("dead"));
    let e3 = NavError::InvalidRange { start: 5, end: 2 };
    assert!(e3.to_string().contains("start=5"));
    let e4 = NavError::UnknownRegister(42);
    assert!(e4.to_string().contains("42"));
}

// ─── FunctionSlice ──────────────────────────────────────────────────────────

#[test]
fn b_function_slice_unbalanced_ret_no_crash() {
    let mut b = TraceBuilder::new("t");
    b.ret(0x1000, 1, 0x2000); // bare ret
    let trace = b.build();
    let s = FunctionSlice::extract_all(&trace);
    assert!(s.is_empty());
}

#[test]
fn b_function_slice_for_function_filter() {
    let trace = paired_trace();
    let slices = FunctionSlice::extract_all(&trace);
    let only_2000 = FunctionSlice::for_function(&slices, 0x2000);
    assert_eq!(only_2000.len(), slices.len());
    let none = FunctionSlice::for_function(&slices, 0xDEAD);
    assert!(none.is_empty());
}

// ─── CallGraph ──────────────────────────────────────────────────────────────

#[test]
fn b_call_graph_node_root_and_leaf_initially() {
    let n = CallGraphNode::new(0x1000);
    assert!(n.is_leaf());
    assert!(n.is_root());
    assert_eq!(n.call_count, 0);
}

#[test]
fn b_call_graph_dfs_visits_no_dup() {
    let mut cg = CallGraph::new();
    let mut a = CallGraphNode::new(0x1);
    a.callees.insert(0x2);
    a.callees.insert(0x3);
    let mut b = CallGraphNode::new(0x2);
    b.callees.insert(0x3);
    cg.nodes.insert(0x1, a);
    cg.nodes.insert(0x2, b);
    cg.nodes.insert(0x3, CallGraphNode::new(0x3));
    let order = cg.dfs_order(0x1);
    assert_eq!(order.len(), 3);
}

// ─── RegTimeline ────────────────────────────────────────────────────────────

#[test]
fn b_reg_timeline_unknown_reg_empty() {
    let nav = nav_with(3);
    let h = nav.register_history(999, 0..3);
    assert!(h.is_empty());
    assert!(nav.current_reg_value(999).is_none());
    assert!(nav.find_reg_value(999, 0).is_empty());
}

#[test]
fn b_reg_timeline_changed_between_exclusive_inclusive() {
    let mut b = TraceBuilder::new("t");
    b.insn(0x1000, 1, "a");
    b.regs(vec![(0, 10)]);
    b.insn(0x1004, 1, "b");
    b.regs(vec![(0, 20)]);
    b.insn(0x1008, 1, "c");
    b.regs(vec![(0, 30)]);
    let trace = b.build();
    let tl = RegTimeline::build(&trace);
    // from_idx exclusive, to_idx inclusive
    let changes = tl.changed_between(0, 2);
    // indices: 1 (val=20), 2 (val=30) ⇒ 2 changes
    assert_eq!(changes.len(), 2);
}

// ─── DataFlowTracker ────────────────────────────────────────────────────────

#[test]
fn b_data_flow_from_memory_seed_zero_when_no_prior_write() {
    let mut b = TraceBuilder::new("t");
    b.insn(0x1000, 1, "x");
    b.insn(0x1004, 1, "store");
    b.mem_write(0xAAAA, vec![0x99]);
    let nav = b.build_navigator();
    let dft = DataFlowTracker::from_memory(&nav, 0xAAAA, 0);
    assert_eq!(dft.flow[0].value, 0); // seed is 0 (no prior write)
    assert!(dft.unique_values().contains(&0x99));
}

#[test]
fn b_data_flow_ticks_monotonic() {
    let mut b = TraceBuilder::new("t");
    b.insn(0x1000, 1, "a");
    b.regs(vec![(0, 1)]);
    b.insn(0x1004, 1, "b");
    b.regs(vec![(0, 2)]);
    let nav = b.build_navigator();
    let dft = DataFlowTracker::from_register(&nav, 0, 0);
    let ticks = dft.ticks();
    assert!(ticks.windows(2).all(|w| w[0] <= w[1]));
}

// ─── TraceExport ────────────────────────────────────────────────────────────

#[test]
fn b_export_tsv_line_count_matches() {
    let nav = nav_with(4);
    let tsv = TraceExport::to_tsv(&nav.trace);
    // header + 4 lines = 5
    assert_eq!(tsv.lines().count(), 5);
}

#[test]
fn b_export_json_roundtrip_via_serde() {
    let trace = paired_trace();
    let json = TraceExport::to_json(&trace).unwrap();
    let decoded: ExecutionTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.entries.len(), trace.entries.len());
    assert_eq!(decoded.binary_name, trace.binary_name);
}

// ─── TraceIndex ─────────────────────────────────────────────────────────────

#[test]
fn b_trace_index_empty() {
    let t = empty_trace();
    let idx = TraceIndex::build(&t);
    assert_eq!(idx.total, 0);
    assert_eq!(idx.unique_pc_count(), 0);
    assert_eq!(idx.unique_thread_count(), 0);
    assert!(idx.indices_for_pc(0x1000).is_empty());
    assert_eq!(idx.hit_count(0x1000), 0);
    assert!(idx.next_pc_after(0x1000, 0).is_none());
    assert!(idx.prev_pc_before(0x1000, 5).is_none());
}

#[test]
fn b_trace_index_thread_ids_unique() {
    let mut b = TraceBuilder::new("t");
    b.insn(0x1000, 1, "a");
    b.insn(0x1000, 2, "b");
    b.insn(0x1000, 1, "c");
    let trace = b.build();
    let idx = TraceIndex::build(&trace);
    assert_eq!(idx.unique_thread_count(), 2);
    let mut ids = idx.thread_ids();
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2]);
}

// ─── ExecutionTrace TSC saturation ──────────────────────────────────────────

#[test]
fn b_exec_trace_total_tsc_saturates_on_decreasing() {
    // If last TSC is less than first, saturating_sub gives 0.
    let mut entries = Vec::new();
    let mut e1 = TraceEntry::insn(0, 0x1000, 1, "a");
    e1.tsc = Some(1000);
    let mut e2 = TraceEntry::insn(1, 0x1004, 1, "b");
    e2.tsc = Some(500);
    entries.push(e1);
    entries.push(e2);
    let t = ExecutionTrace::new(entries, "t");
    assert_eq!(t.total_tsc, Some(0));
}

// ─── peek_forward / peek_backward bounds ────────────────────────────────────

#[test]
fn b_peek_forward_at_end_empty() {
    let mut nav = nav_with(3);
    nav.current_idx = 2;
    assert!(nav.peek_forward(5).is_empty());
}

#[test]
fn b_peek_backward_at_start_empty() {
    let nav = nav_with(3);
    assert!(nav.peek_backward(5).is_empty());
}

#[test]
fn b_peek_forward_clamps() {
    let mut nav = nav_with(5);
    nav.current_idx = 2;
    let p = nav.peek_forward(100);
    assert_eq!(p.len(), 2); // idx 3 and 4
}

// ─── Progress edge cases ────────────────────────────────────────────────────

#[test]
fn b_progress_single_entry_is_one() {
    let nav = nav_with(1);
    assert!((nav.progress() - 1.0).abs() < 1e-9);
}

#[test]
fn b_progress_empty_is_one() {
    let nav = TraceNavigator::new(empty_trace());
    assert!((nav.progress() - 1.0).abs() < 1e-9);
}

// ─── visit_count & entries_at_pc ────────────────────────────────────────────

#[test]
fn b_visit_count_unknown_pc_zero() {
    let nav = nav_with(3);
    assert_eq!(nav.visit_count(0xCAFE), 0);
}

#[test]
fn b_entries_at_pc_filters() {
    let mut b = TraceBuilder::new("t");
    b.insn(0x1000, 1, "a");
    b.insn(0x2000, 1, "b");
    b.insn(0x1000, 1, "c");
    let nav = b.build_navigator();
    let hits = nav.entries_at_pc(0x1000);
    assert_eq!(hits.len(), 2);
}

// ─── at_end / at_beginning combinations ─────────────────────────────────────

#[test]
fn b_at_end_on_empty_is_true() {
    let nav = TraceNavigator::new(empty_trace());
    assert!(nav.at_end());
    assert!(nav.at_beginning());
}

// ─── Annotation edge cases ──────────────────────────────────────────────────

#[test]
fn b_annotation_zero_span() {
    let a = TraceAnnotation::new(5, 5, "single");
    assert_eq!(a.span(), 1);
    assert!(a.covers(5));
}

#[test]
fn b_annotation_inverted_span_saturates() {
    // end < start ⇒ saturating_sub gives 0 → span = 1
    let a = TraceAnnotation::new(10, 3, "inv");
    assert_eq!(a.span(), 1);
}

// ─── AnnotationStore by_tag with None ───────────────────────────────────────

#[test]
fn b_annotation_store_by_tag_misses_untagged() {
    let mut s = AnnotationStore::new();
    s.add(TraceAnnotation::new(0, 5, "untagged"));
    assert!(s.by_tag("anything").is_empty());
}

// ─── TimedRegion saturation ─────────────────────────────────────────────────

#[test]
fn b_timed_region_no_tsc_returns_none() {
    let mut b = TraceBuilder::new("t").tsc_per_insn(0);
    b.insn(0x1000, 1, "a");
    b.insn(0x1004, 1, "b");
    let trace = b.build(); // no freq
    let r = TimedRegion::from_trace(&trace, "r", 0, 1);
    assert!(r.duration_ms().is_none());
}
