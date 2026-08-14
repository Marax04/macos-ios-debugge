//! Deep adversarial test suite (blitz2) for rustre-trace-coverage core API.

use rustre_trace_coverage::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// --- CovEdge ----------------------------------------------------------------

#[test]
fn edge_new_display() {
    let e = CovEdge::new(0x100, 0x200);
    assert_eq!(e.from, 0x100);
    assert_eq!(e.to, 0x200);
    assert_eq!(format!("{e}"), "0x100->0x200");
}

#[test]
fn edge_hash_eq_30_pairs() {
    let mut g = lcg();
    let mut seen: HashSet<CovEdge> = HashSet::new();
    for _ in 0..30 {
        let f = g();
        let t = g();
        let e1 = CovEdge::new(f, t);
        let e2 = CovEdge::new(f, t);
        assert_eq!(e1, e2);
        // hashing into set; reinserting same key shouldn't grow
        let before = seen.len();
        seen.insert(e1.clone());
        seen.insert(e2);
        let after = seen.len();
        // both insertions of equal edges: net growth at most 1
        assert!(after - before <= 1);
    }
}

#[test]
fn edge_extremes() {
    let e = CovEdge::new(0, u64::MAX);
    assert_eq!(format!("{e}"), format!("0x0->0x{:x}", u64::MAX));
}

// --- CovBitmap --------------------------------------------------------------

#[test]
fn bitmap_set_get_roundtrip_50() {
    let mut b = CovBitmap::new(1024);
    let mut g = lcg();
    let mut expect = vec![false; 1024];
    for _ in 0..50 {
        let idx = (g() as usize) % 1024;
        b.set(idx);
        expect[idx] = true;
    }
    for i in 0..1024 {
        assert_eq!(b.get(i), expect[i], "idx={i}");
    }
}

#[test]
fn bitmap_set_oob_noop() {
    let mut b = CovBitmap::new(10);
    b.set(100);
    b.set(usize::MAX);
    assert!(b.is_empty());
}

#[test]
fn bitmap_get_oob_false() {
    let b = CovBitmap::new(10);
    assert!(!b.get(10));
    assert!(!b.get(usize::MAX));
}

#[test]
fn bitmap_toggle_clear() {
    let mut b = CovBitmap::new(64);
    b.set(5);
    assert!(b.get(5));
    b.toggle(5);
    assert!(!b.get(5));
    b.toggle(5);
    assert!(b.get(5));
    b.clear(5);
    assert!(!b.get(5));
    // OOB clear/toggle no-op
    b.clear(1000);
    b.toggle(1000);
}

#[test]
fn bitmap_count_set_clear_invariant() {
    let mut b = CovBitmap::new(100);
    let mut g = lcg();
    for _ in 0..200 {
        let i = (g() as usize) % 100;
        b.set(i);
    }
    assert_eq!(b.count_set() + b.count_clear(), 100);
}

#[test]
fn bitmap_union_intersection_difference_laws() {
    let mut a = CovBitmap::new(128);
    let mut b = CovBitmap::new(128);
    let mut g = lcg();
    for _ in 0..40 {
        a.set((g() as usize) % 128);
        b.set((g() as usize) % 128);
    }
    let u = a.union(&b);
    let i = a.intersection(&b);
    let d = a.difference(&b);
    // |A∪B| = |A| + |B| - |A∩B|
    assert_eq!(u.count_set(), a.count_set() + b.count_set() - i.count_set());
    // A\B disjoint from B
    for idx in d.set_bits() {
        assert!(!b.get(idx));
        assert!(a.get(idx));
    }
}

#[test]
fn bitmap_union_size_max() {
    let a = CovBitmap::new(16);
    let b = CovBitmap::new(32);
    assert_eq!(a.union(&b).size, 32);
    assert_eq!(a.intersection(&b).size, 16);
}

#[test]
fn bitmap_or_assign_grows() {
    let mut a = CovBitmap::new(16);
    let mut b = CovBitmap::new(64);
    b.set(40);
    a.or_assign(&b);
    assert_eq!(a.size, 64);
    assert!(a.get(40));
}

#[test]
fn bitmap_jaccard_identical_one() {
    let mut a = CovBitmap::new(64);
    a.set(1);
    a.set(7);
    assert!((a.jaccard(&a) - 1.0).abs() < 1e-9);
}

#[test]
fn bitmap_jaccard_disjoint_zero() {
    let mut a = CovBitmap::new(64);
    let mut b = CovBitmap::new(64);
    a.set(1);
    b.set(2);
    assert!(a.jaccard(&b).abs() < 1e-9);
}

#[test]
fn bitmap_jaccard_empty_one() {
    let a = CovBitmap::new(0);
    let b = CovBitmap::new(0);
    assert!((a.jaccard(&b) - 1.0).abs() < 1e-9);
}

#[test]
fn bitmap_coverage_ratio_empty() {
    let b = CovBitmap::new(0);
    assert!((b.coverage_ratio() - 1.0).abs() < 1e-9);
}

#[test]
fn bitmap_is_full_is_empty() {
    let mut b = CovBitmap::new(8);
    assert!(b.is_empty() && !b.is_full());
    for i in 0..8 {
        b.set(i);
    }
    assert!(b.is_full() && !b.is_empty());
}

#[test]
fn bitmap_from_afl_roundtrip() {
    let data = vec![0xAB, 0xCD, 0xEF, 0x12];
    let b = CovBitmap::from_afl_bitmap(&data);
    assert_eq!(b.size, 32);
    assert_eq!(b.bits, data);
}

#[test]
fn bitmap_record_edge_zero_size_noop() {
    let mut b = CovBitmap::new(0);
    b.record_edge(0x1000, 0x2000);
    assert!(b.is_empty());
}

#[test]
fn bitmap_record_edge_in_range() {
    let mut b = CovBitmap::new(256);
    b.record_edge(0x1234, 0x5678);
    assert_eq!(b.count_set(), 1);
}

// --- CoverageRun ------------------------------------------------------------

#[test]
fn run_record_and_query() {
    let mut r = CoverageRun::new("r1");
    for _ in 0..3 {
        r.record_bb(0x400);
    }
    assert_eq!(r.visit_count(0x400), 3);
    assert!(r.is_covered(0x400));
    assert!(!r.is_covered(0x500));
    assert_eq!(r.visit_count(0x500), 0);
}

#[test]
fn run_record_bb_n_accumulates() {
    let mut r = CoverageRun::new("r");
    r.record_bb_n(0x10, 5);
    r.record_bb_n(0x10, 7);
    assert_eq!(r.visit_count(0x10), 12);
    assert_eq!(r.unique_bbs(), 1);
}

#[test]
fn run_edges_unique_count() {
    let mut r = CoverageRun::new("r");
    r.record_edge(1, 2);
    r.record_edge(1, 2);
    r.record_edge(2, 3);
    assert_eq!(r.unique_edges(), 2);
    assert_eq!(r.edge_hits[&(1, 2)], 2);
}

#[test]
fn run_total_bb_executions_sum() {
    let mut r = CoverageRun::new("r");
    let mut g = lcg();
    let mut expected = 0u64;
    for _ in 0..50 {
        let addr = g() & 0xFF;
        let n = (g() % 5) + 1;
        r.record_bb_n(addr, n);
        expected += n;
    }
    assert_eq!(r.total_bb_executions(), expected);
}

#[test]
fn run_hot_bbs_descending() {
    let mut r = CoverageRun::new("r");
    r.record_bb_n(1, 10);
    r.record_bb_n(2, 50);
    r.record_bb_n(3, 30);
    let hot = r.hot_bbs(2);
    assert_eq!(hot.len(), 2);
    assert!(hot[0].1 >= hot[1].1);
    assert_eq!(hot[0], (2, 50));
}

#[test]
fn run_hot_bbs_truncate_zero() {
    let mut r = CoverageRun::new("r");
    r.record_bb(1);
    assert!(r.hot_bbs(0).is_empty());
}

#[test]
fn run_heatmap_sorted_by_addr() {
    let mut r = CoverageRun::new("r");
    let mut g = lcg();
    for _ in 0..30 {
        r.record_bb(g() & 0xFFFF);
    }
    let hm = r.heatmap();
    for w in hm.windows(2) {
        assert!(w[0].0 <= w[1].0);
    }
}

#[test]
fn run_builders_ts_tag() {
    let r = CoverageRun::new("x").with_timestamp(42).with_source_tag("tag");
    assert_eq!(r.timestamp, 42);
    assert_eq!(r.source_tag, "tag");
}

// --- CoverageData -----------------------------------------------------------

#[test]
fn data_merge_all_sums() {
    let mut data = CoverageData::new("d");
    let mut a = CoverageRun::new("a");
    a.record_bb_n(1, 2);
    a.record_edge_n(1, 2, 3);
    let mut b = CoverageRun::new("b");
    b.record_bb_n(1, 4);
    b.record_bb_n(2, 1);
    b.record_edge_n(1, 2, 5);
    data.add_run(a);
    data.add_run(b);
    let m = data.merge_all();
    assert_eq!(m.bb_hits[&1], 6);
    assert_eq!(m.bb_hits[&2], 1);
    assert_eq!(m.edge_hits[&(1, 2)], 8);
    assert_eq!(data.run_count(), 2);
    assert_eq!(data.total_unique_bbs(), 2);
    assert_eq!(data.all_bb_addresses().len(), 2);
}

// --- CoverageDiff -----------------------------------------------------------

#[test]
fn diff_disjoint_and_overlap() {
    let mut a = CoverageRun::new("a");
    a.record_bb(1);
    a.record_bb(2);
    a.record_edge(1, 2);
    let mut b = CoverageRun::new("b");
    b.record_bb(2);
    b.record_bb(3);
    b.record_edge(2, 3);
    let d = CoverageDiff::compute(&a, &b);
    assert!(d.new_in_a.contains(&1));
    assert!(d.new_in_b.contains(&3));
    assert!(d.in_both.contains(&2));
    assert!((d.jaccard - 1.0 / 3.0).abs() < 1e-9);
    assert!((d.overlap_pct() - 100.0 / 3.0).abs() < 1e-9);
    assert!(d.edges_only_in_a.contains(&(1, 2)));
    assert!(d.edges_only_in_b.contains(&(2, 3)));
}

#[test]
fn diff_empty_runs_jaccard_one() {
    let a = CoverageRun::new("a");
    let b = CoverageRun::new("b");
    let d = CoverageDiff::compute(&a, &b);
    assert!((d.jaccard - 1.0).abs() < 1e-9);
}

// --- FunctionStats ----------------------------------------------------------

#[test]
fn fn_stats_pct_and_flags() {
    let mut f = FunctionStats::new("f", 0x100, 0x200, 10);
    assert!((f.coverage_pct() - 0.0).abs() < 1e-9);
    f.covered_bb = 5;
    assert!((f.coverage_pct() - 50.0).abs() < 1e-9);
    f.covered_bb = 10;
    assert!(f.is_fully_covered());
    f.call_count = 3;
    assert!(f.was_called());
    let g = FunctionStats::new("g", 0, 0, 0);
    assert!((g.coverage_pct() - 100.0).abs() < 1e-9);
    assert!(!g.is_fully_covered()); // total=0 special
}

#[test]
fn compute_function_stats_attribution() {
    let mut run = CoverageRun::new("r");
    run.record_bb_n(0x100, 7);
    run.record_bb(0x110);
    run.record_bb(0x150);
    run.record_bb(0x300); // out of any fn
    let tbl = vec![
        FunctionStats::new("f1", 0x100, 0x200, 3),
        FunctionStats::new("f2", 0x200, 0x300, 5),
    ];
    let stats = compute_function_stats(&run, &tbl);
    assert_eq!(stats[0].covered_bb, 3);
    assert_eq!(stats[0].call_count, 7);
    assert_eq!(stats[1].covered_bb, 0);
    assert_eq!(stats[1].call_count, 0);
}

// --- DRcov parser -----------------------------------------------------------

#[test]
fn drcov_parse_basic() {
    let txt = "DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\n\
Module Table: version 2, count 1\n\
Columns: id, base, end, entry, checksum, timestamp, path\n\
0, 0x400000, 0x500000, 0x401000, 0xABCD, 0x1234, /tmp/foo/bin\n\
BB Table: 2 bbs\n\
0x1234, 10, 0\n\
0x5678, 20, 0\n";
    let d = DrcovData::parse(txt);
    assert_eq!(d.modules.len(), 1);
    assert_eq!(d.modules[0].base, 0x400000);
    assert_eq!(d.modules[0].name, "bin");
    assert_eq!(d.basic_blocks.len(), 2);
    let addrs = d.resolve_addresses();
    assert!(addrs.contains(&0x401234));
    assert!(addrs.contains(&0x405678));
    let run = d.to_run("rn");
    assert_eq!(run.unique_bbs(), 2);
}

#[test]
fn drcov_parse_garbage_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() as usize) % 200;
        let bytes: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let s = String::from_utf8_lossy(&bytes);
        let _ = DrcovData::parse(&s);
    }
}

#[test]
fn drcov_resolve_empty() {
    let d = DrcovData {
        modules: vec![],
        basic_blocks: vec![DrcovBasicBlock { start: 1, size: 4, mod_id: 0 }],
    };
    assert!(d.resolve_addresses().is_empty());
}

#[test]
fn drcov_decimal_base() {
    let txt = "Module Table: count 1\n\
0, 4194304, 5242880, 0, 0, 0, /a/b\n\
BB Table: 1\n\
16, 4, 0\n";
    let d = DrcovData::parse(txt);
    let addrs = d.resolve_addresses();
    assert_eq!(addrs, vec![4194304 + 16]);
}

// --- LCOV -------------------------------------------------------------------

#[test]
fn lcov_roundtrip() {
    let mut rec = LcovRecord::new();
    rec.source_file = "src.c".into();
    rec.test_name = "t".into();
    rec.line_hits.insert(10, 3);
    rec.line_hits.insert(20, 0);
    rec.function_hits.insert("foo".into(), (5, 2));
    rec.branch_hits.insert((10, 0, 1), 4);
    rec.lines_found = 2;
    rec.lines_hit = 1;
    rec.functions_found = 1;
    rec.functions_hit = 1;
    rec.branches_found = 1;
    rec.branches_hit = 1;
    let s = to_lcov_string(&[rec.clone()]);
    let parsed = parse_lcov(&s);
    assert_eq!(parsed.len(), 1);
    let p = &parsed[0];
    assert_eq!(p.source_file, "src.c");
    assert_eq!(p.line_hits.get(&10), Some(&3));
    assert_eq!(p.function_hits.get("foo"), Some(&(5, 2)));
    assert_eq!(p.branch_hits.get(&(10, 0, 1)), Some(&4));
}

#[test]
fn lcov_ratios_empty() {
    let rec = LcovRecord::new();
    assert!((rec.line_coverage_ratio() - 1.0).abs() < 1e-9);
    assert!((rec.function_coverage_ratio() - 1.0).abs() < 1e-9);
}

#[test]
fn lcov_parse_garbage_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() as usize) % 300;
        let bytes: Vec<u8> = (0..len).map(|_| (g() & 0x7F) as u8).collect();
        let s = String::from_utf8_lossy(&bytes);
        let _ = parse_lcov(&s);
    }
}

#[test]
fn lcov_trailing_no_end_of_record_kept() {
    let txt = "TN:t\nSF:f\nDA:1,1\nLF:1\nLH:1\n";
    let p = parse_lcov(txt);
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].source_file, "f");
}

// --- Custom binary ----------------------------------------------------------

#[test]
fn custom_binary_roundtrip() {
    let mut r = CoverageRun::new("r");
    r.record_bb_n(0x1000, 3);
    r.record_bb_n(0x2000, 7);
    let bytes = to_custom_binary(&r);
    assert_eq!(bytes.len(), 32);
    let r2 = parse_custom_binary(&bytes).unwrap();
    assert_eq!(r2.visit_count(0x1000), 3);
    assert_eq!(r2.visit_count(0x2000), 7);
}

#[test]
fn custom_binary_bad_length() {
    let bytes = vec![0u8; 15];
    let err = parse_custom_binary(&bytes).unwrap_err();
    match err {
        CovError::ParseError(_) => {}
        _ => panic!("expected ParseError"),
    }
}

#[test]
fn custom_binary_empty_ok() {
    let r = parse_custom_binary(&[]).unwrap();
    assert_eq!(r.unique_bbs(), 0);
}

#[test]
fn custom_binary_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() as usize) % 64;
        let bytes: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let _ = parse_custom_binary(&bytes);
    }
}

// --- AFL helpers ------------------------------------------------------------

#[test]
fn afl_helpers() {
    let data = vec![0xFFu8; 8];
    let bm = load_afl_bitmap(&data);
    assert_eq!(afl_bitmap_coverage(&bm), 64);
    let empty = CovBitmap::new(64);
    assert_eq!(afl_new_coverage(&empty, &bm), 64);
    assert_eq!(afl_new_coverage(&bm, &bm), 0);
}

// --- Merge ------------------------------------------------------------------

#[test]
fn merge_runs_unions_with_sum() {
    let mut a = CoverageRun::new("a");
    a.record_bb_n(1, 1);
    a.record_edge_n(1, 2, 1);
    let mut b = CoverageRun::new("b");
    b.record_bb_n(1, 1);
    b.record_bb_n(2, 1);
    b.record_edge_n(1, 2, 1);
    let m = merge_runs(&a, &b, "m");
    assert_eq!(m.name, "m");
    assert_eq!(m.bb_hits[&1], 2);
    assert_eq!(m.bb_hits[&2], 1);
    assert_eq!(m.edge_hits[&(1, 2)], 2);

    let mut data = CoverageData::new("d");
    data.add_run(a);
    data.add_run(b);
    let m2 = merge_all_runs(&data);
    assert_eq!(m2.bb_hits[&1], 2);
}

// --- LighthouseJson round-trip ---------------------------------------------

#[test]
fn lighthouse_roundtrip_50_inputs() {
    let mut g = lcg();
    for _ in 0..50 {
        let mut r = CoverageRun::new("rn").with_timestamp(g() & 0xFFFF);
        for _ in 0..10 {
            r.record_bb_n(g() & 0xFFFF, (g() % 8) + 1);
        }
        let lh = LighthouseJson::from_run(&r);
        let s = lh.to_json().unwrap();
        let lh2 = LighthouseJson::from_json(&s).unwrap();
        let r2 = lh2.to_run();
        // Same set of addresses & same counts.
        assert_eq!(r.bb_hits.len(), r2.bb_hits.len());
        for (&addr, &cnt) in &r.bb_hits {
            assert_eq!(r2.bb_hits.get(&addr), Some(&cnt));
        }
        assert_eq!(r.timestamp, r2.timestamp);
    }
}

#[test]
fn lighthouse_from_json_error() {
    let err = LighthouseJson::from_json("not json").unwrap_err();
    matches!(err, CovError::ParseError(_));
}

// --- Heatmap / BlockColor ---------------------------------------------------

#[test]
fn heatmap_normalised_and_sorted() {
    let mut r = CoverageRun::new("r");
    r.record_bb_n(0x10, 1);
    r.record_bb_n(0x20, 5);
    r.record_bb_n(0x30, 10);
    let h = CoverageHeatmap::build(&r);
    assert_eq!(h.max_count, 10);
    for w in h.entries.windows(2) {
        assert!(w[0].0 <= w[1].0);
    }
    assert!((h.heat_at(0x30) - 1.0).abs() < 1e-9);
    assert!((h.heat_at(0x10) - 0.1).abs() < 1e-9);
    assert!((h.heat_at(0x999) - 0.0).abs() < 1e-9);
    let hottest = h.hottest(2);
    assert_eq!(hottest.len(), 2);
    assert!(hottest[0].1 >= hottest[1].1);
}

#[test]
fn block_color_rgba_buckets() {
    let mut r = CoverageRun::new("r");
    r.record_bb_n(1, 10);
    r.record_bb_n(2, 5);
    let info = BlockColorInfo::for_addr(&r, 1, 10);
    assert!(info.is_covered);
    assert_eq!(info.visit_count, 10);
    assert!((info.heat - 1.0).abs() < 1e-9);
    let (rr, _gg, bb, aa) = info.rgba_color();
    assert_eq!(rr, 255);
    assert_eq!(bb, 0);
    assert_eq!(aa, 255);
    let uncov = BlockColorInfo::for_addr(&r, 999, 10);
    assert!(!uncov.is_covered);
    assert_eq!(uncov.rgba_color(), (64, 64, 64, 255));
    let colors = generate_block_colors(&r, &[1, 2, 3]);
    assert_eq!(colors.len(), 3);
    assert!(colors[2].heat.abs() < 1e-9);
}

// --- CoverageSession --------------------------------------------------------

#[test]
fn session_accumulates_and_exports() {
    let mut s = CoverageSession::new("sess");
    let mut r1 = CoverageRun::new("r1");
    r1.record_bb_n(0x100, 2);
    r1.record_bb_n(0x200, 3);
    s.add_run(r1);
    let mut r2 = CoverageRun::new("r2");
    r2.record_bb_n(0x100, 5);
    s.add_run(r2);
    assert_eq!(s.run_count(), 2);
    let merged = s.merged();
    assert_eq!(merged.bb_hits[&0x100], 7);
    let summary = s.summary();
    assert_eq!(summary.unique_bbs, 2);
    assert!(summary.bitmap_coverage_ratio > 0.0);
    let lh = s.export_lighthouse_json().unwrap();
    assert!(lh.contains("0x100"));
    let lcov = s.export_lcov();
    assert!(lcov.contains("SF:sess"));
    assert!(lcov.contains("end_of_record"));
}

// --- HTML report ------------------------------------------------------------

#[test]
fn html_report_basics() {
    let mut r = CoverageRun::new("r");
    r.record_bb(0x100);
    r.record_bb(0x200);
    let stats = vec![FunctionStats {
        name: "foo".into(),
        start_addr: 0x100,
        end_addr: 0x300,
        total_bb: 4,
        covered_bb: 2,
        call_count: 1,
    }];
    let html = generate_html_report("TestRpt", &r, &stats);
    assert!(html.contains("TestRpt"));
    assert!(html.contains("foo"));
    assert!(html.contains("50.0%"));
}

// --- Threaded Send+Sync stress ---------------------------------------------

#[test]
fn run_send_sync_threaded() {
    let mut base = CoverageRun::new("base");
    for i in 0..16 {
        base.record_bb(i);
    }
    let arc = Arc::new(base);
    let mut handles = vec![];
    for t in 0..4 {
        let a = Arc::clone(&arc);
        handles.push(thread::spawn(move || {
            let mut total = 0u64;
            for _ in 0..100 {
                total = total.wrapping_add(a.visit_count(t as u64));
                assert!(a.is_covered(t as u64));
            }
            total
        }));
    }
    for h in handles {
        let _ = h.join().unwrap();
    }
}

#[test]
fn bitmap_send_sync_threaded() {
    let mut b = CovBitmap::new(4096);
    for i in 0..100 {
        b.set(i * 7);
    }
    let arc = Arc::new(b);
    let mut handles = vec![];
    for _ in 0..4 {
        let a = Arc::clone(&arc);
        handles.push(thread::spawn(move || {
            let mut s = 0usize;
            for _ in 0..100 {
                s = s.wrapping_add(a.count_set());
            }
            s
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// --- Integer overflow paths -------------------------------------------------

#[test]
fn record_bb_n_no_overflow_on_u64_max_safe() {
    // The implementation uses += on u64 entries. Test that adding small values
    // to large values does not panic (wrapping is the worst that can happen
    // in release; in debug, we keep values modest).
    let mut r = CoverageRun::new("r");
    r.record_bb_n(0x1, u64::MAX - 5);
    r.record_bb_n(0x1, 5);
    assert_eq!(r.visit_count(0x1), u64::MAX);
}

#[test]
fn jaccard_ratio_in_range() {
    let mut g = lcg();
    for _ in 0..20 {
        let mut a = CovBitmap::new(256);
        let mut b = CovBitmap::new(256);
        for _ in 0..20 {
            a.set((g() as usize) % 256);
            b.set((g() as usize) % 256);
        }
        let j = a.jaccard(&b);
        assert!((0.0..=1.0).contains(&j));
        let r = a.coverage_ratio();
        assert!((0.0..=1.0).contains(&r));
    }
}

// --- LCOV record sub-API consistency ---------------------------------------

#[test]
fn lcov_default_eq_new() {
    let a = LcovRecord::default();
    let b = LcovRecord::new();
    assert_eq!(a.source_file, b.source_file);
    assert_eq!(a.lines_found, b.lines_found);
}

#[test]
fn lcov_partial_ratios() {
    let mut rec = LcovRecord::new();
    rec.lines_found = 10;
    rec.lines_hit = 4;
    rec.functions_found = 5;
    rec.functions_hit = 2;
    assert!((rec.line_coverage_ratio() - 0.4).abs() < 1e-9);
    assert!((rec.function_coverage_ratio() - 0.4).abs() < 1e-9);
}
