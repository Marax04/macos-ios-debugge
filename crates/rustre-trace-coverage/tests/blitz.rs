//! Blitz test suite for rustre-trace-coverage.

use rustre_trace_coverage::*;

// ───── CovBitmap ─────────────────────────────────────────────────────────────

#[test]
fn bitmap_new_zero() {
    let b = CovBitmap::new(0);
    assert_eq!(b.size, 0);
    assert_eq!(b.bits.len(), 0);
    assert!(b.is_empty());
    assert!(b.is_full()); // count_set==size==0
}

#[test]
fn bitmap_new_nonmultiple() {
    let b = CovBitmap::new(10);
    assert_eq!(b.size, 10);
    assert_eq!(b.bits.len(), 2);
}

#[test]
fn bitmap_set_get_clear_toggle() {
    let mut b = CovBitmap::new(64);
    assert!(!b.get(0));
    b.set(0);
    assert!(b.get(0));
    b.clear(0);
    assert!(!b.get(0));
    b.toggle(5);
    assert!(b.get(5));
    b.toggle(5);
    assert!(!b.get(5));
}

#[test]
fn bitmap_set_oob_silent() {
    let mut b = CovBitmap::new(8);
    b.set(100); // out-of-range should be a no-op
    b.clear(100);
    b.toggle(100);
    assert!(!b.get(100));
    assert_eq!(b.count_set(), 0);
}

#[test]
fn bitmap_count_set_clear() {
    let mut b = CovBitmap::new(16);
    b.set(0);
    b.set(7);
    b.set(15);
    assert_eq!(b.count_set(), 3);
    assert_eq!(b.count_clear(), 13);
}

#[test]
fn bitmap_count_clear_overflow_bits() {
    // size=10, but bytes hold 16 bits. count_set could count bits beyond size if set.
    // saturating_sub ensures clear is at most size.
    let mut b = CovBitmap::new(10);
    // bit 9 within range
    b.set(9);
    assert_eq!(b.count_set(), 1);
    assert_eq!(b.count_clear(), 9);
}

#[test]
fn bitmap_from_afl() {
    let data = vec![0xFFu8; 8];
    let b = CovBitmap::from_afl_bitmap(&data);
    assert_eq!(b.size, 64);
    assert_eq!(b.count_set(), 64);
    assert!(b.is_full());
}

#[test]
fn bitmap_union() {
    let mut a = CovBitmap::new(16);
    let mut b = CovBitmap::new(16);
    a.set(0);
    b.set(1);
    let u = a.union(&b);
    assert!(u.get(0));
    assert!(u.get(1));
    assert_eq!(u.size, 16);
}

#[test]
fn bitmap_intersection() {
    let mut a = CovBitmap::new(16);
    let mut b = CovBitmap::new(16);
    a.set(0);
    a.set(5);
    b.set(5);
    let i = a.intersection(&b);
    assert!(!i.get(0));
    assert!(i.get(5));
}

#[test]
fn bitmap_difference() {
    let mut a = CovBitmap::new(16);
    let mut b = CovBitmap::new(16);
    a.set(0);
    a.set(5);
    b.set(5);
    let d = a.difference(&b);
    assert!(d.get(0));
    assert!(!d.get(5));
}

#[test]
fn bitmap_or_assign_grows() {
    let mut a = CovBitmap::new(8);
    let mut b = CovBitmap::new(32);
    b.set(20);
    a.or_assign(&b);
    assert_eq!(a.size, 32);
    assert!(a.get(20));
}

#[test]
fn bitmap_jaccard_empty() {
    let a = CovBitmap::new(8);
    let b = CovBitmap::new(8);
    assert_eq!(a.jaccard(&b), 1.0);
}

#[test]
fn bitmap_jaccard_disjoint() {
    let mut a = CovBitmap::new(16);
    let mut b = CovBitmap::new(16);
    a.set(0);
    b.set(1);
    assert_eq!(a.jaccard(&b), 0.0);
}

#[test]
fn bitmap_jaccard_identical() {
    let mut a = CovBitmap::new(16);
    let mut b = CovBitmap::new(16);
    a.set(3);
    b.set(3);
    assert!((a.jaccard(&b) - 1.0).abs() < 1e-9);
}

#[test]
fn bitmap_coverage_ratio_empty_size_zero() {
    let b = CovBitmap::new(0);
    assert_eq!(b.coverage_ratio(), 1.0);
}

#[test]
fn bitmap_coverage_ratio_half() {
    let mut b = CovBitmap::new(8);
    for i in 0..4 {
        b.set(i);
    }
    assert!((b.coverage_ratio() - 0.5).abs() < 1e-9);
}

#[test]
fn bitmap_set_bits_clear_bits() {
    let mut b = CovBitmap::new(4);
    b.set(0);
    b.set(2);
    assert_eq!(b.set_bits(), vec![0, 2]);
    assert_eq!(b.clear_bits(), vec![1, 3]);
}

#[test]
fn bitmap_record_edge_size_zero_no_panic() {
    let mut b = CovBitmap::new(0);
    b.record_edge(0x1000, 0x2000);
    assert!(b.is_empty());
}

#[test]
fn bitmap_record_edge_hashes() {
    let mut b = CovBitmap::new(256);
    b.record_edge(0x100, 0x200);
    assert_eq!(b.count_set(), 1);
}

// ───── CovEdge ───────────────────────────────────────────────────────────────

#[test]
fn cov_edge_display() {
    let e = CovEdge::new(0xabcd, 0x1234);
    assert_eq!(e.to_string(), "0xabcd->0x1234");
}

#[test]
fn cov_edge_eq_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(CovEdge::new(1, 2));
    s.insert(CovEdge::new(1, 2));
    assert_eq!(s.len(), 1);
}

// ───── CoverageRun ───────────────────────────────────────────────────────────

#[test]
fn run_new_empty() {
    let r = CoverageRun::new("x");
    assert_eq!(r.name, "x");
    assert_eq!(r.unique_bbs(), 0);
    assert_eq!(r.unique_edges(), 0);
    assert_eq!(r.total_bb_executions(), 0);
}

#[test]
fn run_with_timestamp_source() {
    let r = CoverageRun::new("r").with_timestamp(123).with_source_tag("tag");
    assert_eq!(r.timestamp, 123);
    assert_eq!(r.source_tag, "tag");
}

#[test]
fn run_record_bb_increments() {
    let mut r = CoverageRun::new("r");
    r.record_bb(0x100);
    r.record_bb(0x100);
    r.record_bb_n(0x100, 3);
    assert_eq!(r.visit_count(0x100), 5);
    assert!(r.is_covered(0x100));
    assert!(!r.is_covered(0x200));
    assert_eq!(r.visit_count(0x200), 0);
}

#[test]
fn run_record_edge() {
    let mut r = CoverageRun::new("r");
    r.record_edge(1, 2);
    r.record_edge_n(1, 2, 4);
    assert_eq!(r.unique_edges(), 1);
    assert_eq!(*r.edge_hits.get(&(1, 2)).unwrap(), 5);
}

#[test]
fn run_hot_bbs_sorted_desc() {
    let mut r = CoverageRun::new("r");
    r.record_bb_n(1, 10);
    r.record_bb_n(2, 5);
    r.record_bb_n(3, 20);
    let hot = r.hot_bbs(2);
    assert_eq!(hot.len(), 2);
    assert_eq!(hot[0], (3, 20));
    assert_eq!(hot[1], (1, 10));
}

#[test]
fn run_heatmap_sorted_by_addr() {
    let mut r = CoverageRun::new("r");
    r.record_bb(3);
    r.record_bb(1);
    r.record_bb(2);
    let hm = r.heatmap();
    assert_eq!(hm.iter().map(|(a, _)| *a).collect::<Vec<_>>(), vec![1, 2, 3]);
}

// ───── CoverageData ──────────────────────────────────────────────────────────

#[test]
fn data_merge_all_sums() {
    let mut d = CoverageData::new("d");
    let mut r1 = CoverageRun::new("r1");
    r1.record_bb_n(0x10, 5);
    let mut r2 = CoverageRun::new("r2");
    r2.record_bb_n(0x10, 7);
    r2.record_bb_n(0x20, 1);
    d.add_run(r1);
    d.add_run(r2);
    let m = d.merge_all();
    assert_eq!(m.visit_count(0x10), 12);
    assert_eq!(m.visit_count(0x20), 1);
}

#[test]
fn data_total_unique_bbs() {
    let mut d = CoverageData::new("d");
    let mut r1 = CoverageRun::new("r1");
    r1.record_bb(1);
    r1.record_bb(2);
    let mut r2 = CoverageRun::new("r2");
    r2.record_bb(2);
    r2.record_bb(3);
    d.add_run(r1);
    d.add_run(r2);
    assert_eq!(d.total_unique_bbs(), 3);
    assert_eq!(d.run_count(), 2);
    assert_eq!(d.all_bb_addresses().len(), 3);
}

#[test]
fn data_merge_all_empty() {
    let d = CoverageData::new("lbl");
    let m = d.merge_all();
    assert_eq!(m.name, "lbl");
    assert_eq!(m.unique_bbs(), 0);
}

// ───── CoverageDiff ──────────────────────────────────────────────────────────

#[test]
fn diff_basic() {
    let mut a = CoverageRun::new("a");
    let mut b = CoverageRun::new("b");
    a.record_bb(1);
    a.record_bb(2);
    b.record_bb(2);
    b.record_bb(3);
    a.record_edge(1, 2);
    b.record_edge(2, 3);
    let d = CoverageDiff::compute(&a, &b);
    assert!(d.new_in_a.contains(&1));
    assert!(d.new_in_b.contains(&3));
    assert!(d.in_both.contains(&2));
    assert!(d.edges_only_in_a.contains(&(1, 2)));
    assert!(d.edges_only_in_b.contains(&(2, 3)));
    // jaccard = 1/3
    assert!((d.jaccard - 1.0 / 3.0).abs() < 1e-9);
    assert!((d.overlap_pct() - 100.0 / 3.0).abs() < 1e-9);
}

#[test]
fn diff_both_empty_jaccard_one() {
    let a = CoverageRun::new("a");
    let b = CoverageRun::new("b");
    let d = CoverageDiff::compute(&a, &b);
    assert_eq!(d.jaccard, 1.0);
}

// ───── FunctionStats ─────────────────────────────────────────────────────────

#[test]
fn func_stats_pct_zero_total() {
    let f = FunctionStats::new("f", 0, 100, 0);
    assert_eq!(f.coverage_pct(), 100.0);
    assert!(!f.is_fully_covered()); // requires total_bb > 0
    assert!(!f.was_called());
}

#[test]
fn func_stats_pct_half() {
    let mut f = FunctionStats::new("f", 0, 100, 4);
    f.covered_bb = 2;
    assert!((f.coverage_pct() - 50.0).abs() < 1e-9);
}

#[test]
fn func_stats_fully_covered() {
    let mut f = FunctionStats::new("f", 0, 100, 4);
    f.covered_bb = 4;
    assert!(f.is_fully_covered());
}

#[test]
fn compute_function_stats_basic() {
    let mut r = CoverageRun::new("r");
    r.record_bb_n(0x100, 3);
    r.record_bb(0x110);
    r.record_bb(0x200); // outside f
    let funcs = vec![FunctionStats::new("f", 0x100, 0x200, 5)];
    let res = compute_function_stats(&r, &funcs);
    assert_eq!(res[0].covered_bb, 2); // 0x100 and 0x110
    assert_eq!(res[0].call_count, 3);
}

#[test]
fn compute_function_stats_no_hits() {
    let r = CoverageRun::new("r");
    let funcs = vec![FunctionStats::new("f", 0x100, 0x200, 5)];
    let res = compute_function_stats(&r, &funcs);
    assert_eq!(res[0].covered_bb, 0);
    assert_eq!(res[0].call_count, 0);
}

// ───── DRcov ─────────────────────────────────────────────────────────────────

#[test]
fn drcov_parse_basic() {
    let input = "\
DRCOV VERSION: 2
DRCOV FLAVOR: drcov
Module Table: version 2, count 1
Columns: id, base, end, entry, checksum, timestamp, path
0, 0x400000, 0x500000, 0x401000, 0xABCD, 0x1234, /path/to/binary
BB Table: 2 bbs
0x1000, 10, 0
0x2000, 20, 0
";
    let d = DrcovData::parse(input);
    assert_eq!(d.modules.len(), 1);
    assert_eq!(d.modules[0].base, 0x400000);
    assert_eq!(d.modules[0].end, 0x500000);
    assert_eq!(d.modules[0].name, "binary");
    assert_eq!(d.basic_blocks.len(), 2);
    let addrs = d.resolve_addresses();
    assert!(addrs.contains(&(0x400000 + 0x1000)));
    assert!(addrs.contains(&(0x400000 + 0x2000)));
}

#[test]
fn drcov_to_run() {
    let input = "\
Module Table: version 2, count 1
Columns: id, base, end, entry, checksum, timestamp, path
0, 0x400000, 0x500000, 0x401000, 0xABCD, 0x1234, /p/binary
BB Table: 1 bbs
0x1000, 10, 0
";
    let d = DrcovData::parse(input);
    let r = d.to_run("rn");
    assert_eq!(r.name, "rn");
    assert!(r.is_covered(0x401000));
}

#[test]
fn drcov_parse_empty() {
    let d = DrcovData::parse("");
    assert!(d.modules.is_empty());
    assert!(d.basic_blocks.is_empty());
}

#[test]
fn drcov_parse_garbage_lines_skipped() {
    let d = DrcovData::parse("garbage\nnope\n");
    assert!(d.modules.is_empty());
}

#[test]
fn drcov_unresolved_bb_filtered() {
    // BB with mod_id with no module
    let input = "\
BB Table: 1 bbs
0x1000, 10, 5
";
    let d = DrcovData::parse(input);
    assert_eq!(d.basic_blocks.len(), 1);
    assert!(d.resolve_addresses().is_empty());
}

// ───── LCOV ──────────────────────────────────────────────────────────────────

#[test]
fn lcov_parse_full_record() {
    let input = "\
TN:test
SF:src/foo.rs
FN:10,foo
FNDA:5,foo
FNF:1
FNH:1
DA:10,5
DA:11,0
LF:2
LH:1
BRDA:10,0,0,3
BRF:1
BRH:1
end_of_record
";
    let recs = parse_lcov(input);
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r.test_name, "test");
    assert_eq!(r.source_file, "src/foo.rs");
    assert_eq!(r.line_hits.get(&10), Some(&5));
    assert_eq!(r.line_hits.get(&11), Some(&0));
    assert_eq!(r.function_hits.get("foo"), Some(&(10, 5)));
    assert_eq!(r.branch_hits.get(&(10, 0, 0)), Some(&3));
    assert_eq!(r.lines_found, 2);
    assert_eq!(r.lines_hit, 1);
    assert!((r.line_coverage_ratio() - 0.5).abs() < 1e-9);
    assert!((r.function_coverage_ratio() - 1.0).abs() < 1e-9);
}

#[test]
fn lcov_ratios_empty() {
    let r = LcovRecord::new();
    assert_eq!(r.line_coverage_ratio(), 1.0);
    assert_eq!(r.function_coverage_ratio(), 1.0);
}

#[test]
fn lcov_trailing_record_no_end() {
    let input = "SF:foo.rs\nDA:1,1\n";
    let recs = parse_lcov(input);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].source_file, "foo.rs");
}

#[test]
fn lcov_no_trailing_empty_record() {
    // Empty record without source_file should be skipped.
    let recs = parse_lcov("");
    assert_eq!(recs.len(), 0);
}

#[test]
fn lcov_roundtrip_minimal() {
    let mut r = LcovRecord::new();
    r.test_name = "t".into();
    r.source_file = "f.rs".into();
    r.line_hits.insert(1, 1);
    r.lines_found = 1;
    r.lines_hit = 1;
    let s = to_lcov_string(&[r.clone()]);
    let back = parse_lcov(&s);
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].source_file, "f.rs");
    assert_eq!(back[0].line_hits.get(&1), Some(&1));
}

// ───── Custom Binary ─────────────────────────────────────────────────────────

#[test]
fn custom_binary_roundtrip() {
    let mut r = CoverageRun::new("x");
    r.record_bb_n(0xdead, 5);
    r.record_bb_n(0xbeef, 9);
    let bytes = to_custom_binary(&r);
    assert_eq!(bytes.len(), 32);
    let r2 = parse_custom_binary(&bytes).unwrap();
    assert_eq!(r2.visit_count(0xdead), 5);
    assert_eq!(r2.visit_count(0xbeef), 9);
}

#[test]
fn custom_binary_empty_ok() {
    let r = parse_custom_binary(&[]).unwrap();
    assert_eq!(r.unique_bbs(), 0);
}

#[test]
fn custom_binary_bad_length_errors() {
    let bytes = vec![0u8; 15];
    let err = parse_custom_binary(&bytes).unwrap_err();
    match err {
        CovError::ParseError(_) => {}
        _ => panic!("expected ParseError"),
    }
}

// ───── AFL ───────────────────────────────────────────────────────────────────

#[test]
fn afl_load_and_count() {
    let data = vec![0x01u8, 0x02, 0x04];
    let b = load_afl_bitmap(&data);
    assert_eq!(afl_bitmap_coverage(&b), 3);
}

#[test]
fn afl_new_coverage_count() {
    let a = load_afl_bitmap(&[0x01]);
    let b = load_afl_bitmap(&[0x03]);
    assert_eq!(afl_new_coverage(&a, &b), 1);
}

// ───── merge_runs ────────────────────────────────────────────────────────────

#[test]
fn merge_runs_sums() {
    let mut a = CoverageRun::new("a");
    a.record_bb_n(1, 3);
    let mut b = CoverageRun::new("b");
    b.record_bb_n(1, 4);
    b.record_bb_n(2, 1);
    let m = merge_runs(&a, &b, "m");
    assert_eq!(m.name, "m");
    assert_eq!(m.visit_count(1), 7);
    assert_eq!(m.visit_count(2), 1);
}

#[test]
fn merge_all_runs_proxy() {
    let mut d = CoverageData::new("d");
    let mut r = CoverageRun::new("r");
    r.record_bb(1);
    d.add_run(r);
    let m = merge_all_runs(&d);
    assert_eq!(m.unique_bbs(), 1);
}

// ───── LighthouseJson ────────────────────────────────────────────────────────

#[test]
fn lighthouse_roundtrip() {
    let mut r = CoverageRun::new("x");
    r.timestamp = 42;
    r.record_bb_n(0xabc, 9);
    let lh = LighthouseJson::from_run(&r);
    let j = lh.to_json().unwrap();
    let lh2 = LighthouseJson::from_json(&j).unwrap();
    let r2 = lh2.to_run();
    assert_eq!(r2.name, "x");
    assert_eq!(r2.timestamp, 42);
    assert_eq!(r2.visit_count(0xabc), 9);
}

#[test]
fn lighthouse_from_json_invalid() {
    let err = LighthouseJson::from_json("not json").unwrap_err();
    match err {
        CovError::ParseError(_) => {}
        _ => panic!("expected ParseError"),
    }
}

// ───── HTML Report ───────────────────────────────────────────────────────────

#[test]
fn html_report_contains_basic_fields() {
    let mut r = CoverageRun::new("x");
    r.record_bb_n(0x100, 5);
    let f = FunctionStats::new("myfn", 0x100, 0x200, 1);
    let html = generate_html_report("Title", &r, &[f]);
    assert!(html.contains("Title"));
    assert!(html.contains("myfn"));
    assert!(html.contains("0x100"));
}

// ───── Heatmap ───────────────────────────────────────────────────────────────

#[test]
fn heatmap_build_and_heat_at() {
    let mut r = CoverageRun::new("r");
    r.record_bb_n(0x10, 1);
    r.record_bb_n(0x20, 10);
    let h = CoverageHeatmap::build(&r);
    assert_eq!(h.max_count, 10);
    assert!((h.heat_at(0x20) - 1.0).abs() < 1e-9);
    assert!((h.heat_at(0x10) - 0.1).abs() < 1e-9);
    assert_eq!(h.heat_at(0xff), 0.0);
}

#[test]
fn heatmap_hottest_top_n() {
    let mut r = CoverageRun::new("r");
    r.record_bb_n(1, 1);
    r.record_bb_n(2, 5);
    r.record_bb_n(3, 3);
    let h = CoverageHeatmap::build(&r);
    let top = h.hottest(2);
    assert_eq!(top.len(), 2);
    assert_eq!(top[0].0, 2);
    assert_eq!(top[1].0, 3);
}

#[test]
fn heatmap_empty_max_one() {
    let r = CoverageRun::new("r");
    let h = CoverageHeatmap::build(&r);
    assert_eq!(h.max_count, 1);
    assert!(h.entries.is_empty());
}

// ───── BlockColorInfo ────────────────────────────────────────────────────────

#[test]
fn block_color_uncovered_grey() {
    let r = CoverageRun::new("r");
    let bc = BlockColorInfo::for_addr(&r, 0x1, 10);
    assert!(!bc.is_covered);
    assert_eq!(bc.visit_count, 0);
    assert_eq!(bc.rgba_color(), (64, 64, 64, 255));
}

#[test]
fn block_color_covered_heat() {
    let mut r = CoverageRun::new("r");
    r.record_bb_n(0x10, 10);
    let bc = BlockColorInfo::for_addr(&r, 0x10, 10);
    assert!(bc.is_covered);
    assert_eq!(bc.visit_count, 10);
    assert!((bc.heat - 1.0).abs() < 1e-9);
    let (rr, _gg, bb, aa) = bc.rgba_color();
    assert_eq!(rr, 255);
    assert_eq!(bb, 0);
    assert_eq!(aa, 255);
}

#[test]
fn block_color_max_zero_safe() {
    let mut r = CoverageRun::new("r");
    r.record_bb(0x1);
    // max_count=0 should be clamped to 1, avoiding div by zero
    let bc = BlockColorInfo::for_addr(&r, 0x1, 0);
    assert!(bc.heat.is_finite());
}

#[test]
fn generate_block_colors_all() {
    let mut r = CoverageRun::new("r");
    r.record_bb_n(0x1, 1);
    r.record_bb_n(0x2, 5);
    let v = generate_block_colors(&r, &[0x1, 0x2, 0x3]);
    assert_eq!(v.len(), 3);
    assert!(v[0].is_covered);
    assert!(v[1].is_covered);
    assert!(!v[2].is_covered);
}

// ───── CovError display ──────────────────────────────────────────────────────

#[test]
fn cov_error_displays() {
    let e = CovError::SizeMismatch { a: 1, b: 2 };
    assert!(e.to_string().contains('1'));
    let e = CovError::InvalidIndex(7);
    assert!(e.to_string().contains('7'));
    let e = CovError::SourceNotFound("x".into());
    assert!(e.to_string().contains('x'));
}

// ───── Send/Sync invariants ──────────────────────────────────────────────────

#[test]
fn types_are_send_sync() {
    fn assert_ss<T: Send + Sync>() {}
    assert_ss::<CovBitmap>();
    assert_ss::<CoverageRun>();
    assert_ss::<CoverageData>();
    assert_ss::<CoverageDiff>();
    assert_ss::<FunctionStats>();
    assert_ss::<DrcovData>();
    assert_ss::<LcovRecord>();
    assert_ss::<LighthouseJson>();
    assert_ss::<CoverageHeatmap>();
    assert_ss::<BlockColorInfo>();
    assert_ss::<CovEdge>();
}
