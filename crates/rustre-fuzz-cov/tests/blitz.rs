//! Exhaustive black-box test suite for `rustre-fuzz-cov` public API.
//!
//! Targets edge cases, malformed input, round-trips, and boundary
//! conditions across the types re-exported from the crate root and
//! the `lcov_export` module.

use rustre_fuzz_cov::lcov_export::{
    CoverageDiffReport, CoverageReport, DrcovImporter, LcovRecord as ExportRecord, LcovWriter,
};
use rustre_fuzz_cov::{
    CmplogEntry, CmplogMap, CorpusPruner, CovError, CoverageData, CoverageDatabase,
    CoverageDatabaseV2, CoverageDiff, CoverageHistogram, CoverageRun, CoverageRunV2,
    DrcovBasicBlock, DrcovEntry, DrcovFile, DrcovFileV2, DrcovHeader, DrcovModule, DrcovModuleV2,
    EdgeCoverageMap, FileCoverage, HeatmapColors, LcovInfoParser, LcovParser, LcovRecord,
    PcGuardBitmap,
};

// ─── helpers ─────────────────────────────────────────────────────────────────

fn drcov_bytes(bb_count_field: usize, real_bbs: usize) -> Vec<u8> {
    let text = format!(
        "DRCOV VERSION: 2\n\
         DRCOV FLAVOR: drcov\n\
         Module Table: version 2, count 1\n\
         Columns: id, base, end, entry, checksum, timestamp, path\n\
         0, 0x1000, 0x5000, 0x1100, 0x0, 0x0, /bin/test\n\
         BB Table: {bb_count_field} bbs\n"
    );
    let mut v = text.into_bytes();
    for i in 0..real_bbs {
        v.extend_from_slice(&u32::try_from(0x100 + i * 0x10).unwrap_or(u32::MAX).to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
    }
    v
}

// ─── DrcovModule ─────────────────────────────────────────────────────────────

#[test]
fn drcov_module_to_offset_boundary_end_exclusive() {
    let m = DrcovModule::new(0, "/x", 0x1000, 0x2000);
    // end is exclusive
    assert_eq!(m.to_offset(0x2000), None);
    assert_eq!(m.to_offset(0x1fff), Some(0xfff));
}

#[test]
fn drcov_module_size_zero_when_base_eq_end() {
    let m = DrcovModule::new(0, "/x", 0x1000, 0x1000);
    assert_eq!(m.size(), 0);
    assert!(!m.contains(0x1000));
}

#[test]
fn drcov_module_with_checksum_preserves_other_fields() {
    let m = DrcovModule::new(7, "/p", 1, 2).with_checksum(42);
    assert_eq!(m.id, 7);
    assert_eq!(m.path, "/p");
    assert_eq!(m.base, 1);
    assert_eq!(m.end, 2);
    assert_eq!(m.checksum, 42);
}

// ─── DrcovEntry ──────────────────────────────────────────────────────────────

#[test]
fn drcov_entry_end_addr_no_match() {
    let modules: Vec<DrcovModule> = vec![];
    let e = DrcovEntry::new(3, 0x10, 4);
    assert_eq!(e.end_addr(&modules), None);
}

#[test]
fn drcov_entry_module_id_u16_max() {
    let m = DrcovModule::new(u32::from(u16::MAX), "/p", 0x1000, 0x2000);
    let e = DrcovEntry::new(u16::MAX, 0x20, 8);
    assert_eq!(e.absolute_addr(std::slice::from_ref(&m)), Some(0x1020));
}

// ─── DrcovFile parse / serialise ─────────────────────────────────────────────

#[test]
fn drcov_parse_missing_version_line_errors() {
    let res = DrcovFile::parse(b"");
    assert!(matches!(res, Err(CovError::Parse(_))));
}

#[test]
fn drcov_parse_invalid_utf8_errors() {
    let res = DrcovFile::parse(&[0xff, 0xfe, 0xfd]);
    assert!(matches!(res, Err(CovError::Parse(_))));
}

#[test]
fn drcov_parse_bad_version_number_errors() {
    let raw = b"DRCOV VERSION: notanumber\nDRCOV FLAVOR: drcov\nModule Table: count 0\n";
    assert!(matches!(DrcovFile::parse(raw), Err(CovError::Parse(_))));
}

#[test]
fn drcov_parse_missing_flavor_errors() {
    let raw = b"DRCOV VERSION: 2\n";
    assert!(DrcovFile::parse(raw).is_err());
}

#[test]
fn drcov_parse_truncated_module_table_errors() {
    let raw = b"DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\nModule Table: version 2, count 5\nColumns: id, base, end, entry, checksum, timestamp, path\n";
    let res = DrcovFile::parse(raw);
    assert!(res.is_err(), "expected error for truncated module table");
}

#[test]
fn drcov_parse_round_trip_bbs() {
    let raw = drcov_bytes(2, 2);
    let f = DrcovFile::parse(&raw).expect("parse");
    assert_eq!(f.modules.len(), 1);
    assert_eq!(f.bbs.len(), 2);
    assert_eq!(f.bbs[0].start, 0x100);
    assert_eq!(f.bbs[1].start, 0x110);
}

#[test]
fn drcov_parse_bb_count_larger_than_data_clamps() {
    // Header says 100 BBs, only 1 actually present.
    let raw = drcov_bytes(100, 1);
    let f = DrcovFile::parse(&raw).expect("parse");
    assert_eq!(f.bbs.len(), 1);
}

// ─── CoverageRun ─────────────────────────────────────────────────────────────

#[test]
fn coverage_run_density_zero_total() {
    let mut r = CoverageRun::new("r");
    r.hit(1);
    assert!((r.density(0) - 0.0).abs() < 1e-9);
}

#[test]
fn coverage_run_merge_total_executions_summed() {
    let mut a = CoverageRun::new("a");
    a.total_executions = 5;
    let mut b = CoverageRun::new("b");
    b.total_executions = 7;
    a.merge(&b);
    assert_eq!(a.total_executions, 12);
}

#[test]
fn coverage_run_hot_blocks_sorted_unique() {
    let mut r = CoverageRun::new("r");
    r.hit_n(0x300, 5);
    r.hit_n(0x100, 5);
    r.hit_n(0x200, 5);
    let hot = r.hot_blocks(1);
    assert_eq!(hot, vec![0x100, 0x200, 0x300]);
}

// ─── CoverageDiff ────────────────────────────────────────────────────────────

#[test]
fn coverage_diff_jaccard_empty_returns_one() {
    let d = CoverageDiff::default();
    assert!((d.jaccard() - 1.0).abs() < 1e-12);
    assert!(d.is_identical());
}

#[test]
fn coverage_database_diff_disjoint() {
    let mut a = CoverageRun::new("a");
    a.hit(1);
    let mut b = CoverageRun::new("b");
    b.hit(2);
    let d = CoverageDatabase::diff(&a, &b);
    assert_eq!(d.only_in_a, vec![1]);
    assert_eq!(d.only_in_b, vec![2]);
    assert!(d.in_both.is_empty());
    assert!((d.jaccard() - 0.0).abs() < 1e-9);
}

// ─── CoverageDatabase ────────────────────────────────────────────────────────

#[test]
fn database_intersection_empty_db() {
    let db = CoverageDatabase::new();
    assert!(db.intersection().is_empty());
    assert!(db.union_coverage().is_empty());
}

#[test]
fn database_unique_runs_deduplicates() {
    let mut db = CoverageDatabase::new();
    let mut r1 = CoverageRun::new("r1");
    r1.hit(1);
    r1.hit(2);
    let mut r2 = CoverageRun::new("r2");
    r2.hit(1); // adds nothing new
    let mut r3 = CoverageRun::new("r3");
    r3.hit(3);
    db.add_run(r1);
    db.add_run(r2);
    db.add_run(r3);
    let unique = db.unique_runs();
    let names: Vec<&str> = unique.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, vec!["r1", "r3"]);
}

#[test]
fn database_stats_zero_total_yields_zero_pct() {
    let r = CoverageRun::new("r");
    let s = CoverageDatabase::stats(&r, 0);
    assert_eq!(s.hit_blocks, 0);
    assert_eq!(s.total_blocks, 0);
    assert!((s.coverage_pct - 0.0).abs() < 1e-9);
}

// ─── LcovParser ──────────────────────────────────────────────────────────────

#[test]
fn lcov_parser_empty_string() {
    let mut p = LcovParser::new();
    p.parse("").unwrap();
    assert!(p.records.is_empty());
    assert!((p.overall_line_coverage_pct() - 0.0).abs() < 1e-9);
}

#[test]
fn lcov_parser_strips_comments_and_blanks() {
    let mut p = LcovParser::new();
    p.parse("# comment\n\nSF:/x\nDA:1,1\nend_of_record\n").unwrap();
    assert_eq!(p.records.len(), 1);
    assert_eq!(*p.records[0].line_hits.get(&1).unwrap(), 1);
}

#[test]
fn lcov_record_is_fully_covered_requires_lines_found() {
    let r = LcovRecord::default();
    assert!(!r.is_fully_covered());
}

// ─── PcGuardBitmap ───────────────────────────────────────────────────────────

#[test]
fn pcguard_record_hit_saturates_at_255() {
    let mut b = PcGuardBitmap::new(4);
    for _ in 0..300 {
        b.record_hit(0);
    }
    assert_eq!(b.bits[0], u8::MAX);
}

#[test]
fn pcguard_record_hit_out_of_bounds_is_ignored() {
    // `PcGuardBitmap::record_hit` documents "Silently ignored if
    // `idx >= self.bits.len()`", and the implementation matches: it goes through
    // `bits.get_mut(idx)`, so an out-of-range guard index cannot panic.
    //
    // This test previously asserted the opposite — that the call panicked — and
    // was left behind when the method was made bounds-safe. Asserting the
    // current contract is what makes the leniency deliberate rather than
    // accidental: a coverage bitmap is fed guard indices by instrumented code,
    // and taking the process down on a stale index would be worse than dropping
    // the sample.
    let mut b = PcGuardBitmap::new(2);
    b.record_hit(10);

    assert_eq!(
        b.bits,
        vec![0, 0],
        "an out-of-range hit must leave the bitmap untouched"
    );
    assert_eq!(b.coverage_count(), 0);

    // Premise: in-range hits are still recorded, so the assertions above are not
    // passing because `record_hit` stopped working altogether.
    b.record_hit(1);
    assert_eq!(b.bits, vec![0, 1]);
    assert_eq!(b.coverage_count(), 1);
}

#[test]
fn pcguard_from_bytes_preserves_bits() {
    let b = PcGuardBitmap::from_bytes(vec![0, 1, 2, 3]);
    assert_eq!(b.bits, vec![0, 1, 2, 3]);
    assert_eq!(b.coverage_count(), 3);
}

#[test]
fn pcguard_density_empty_zero() {
    let b = PcGuardBitmap::new(0);
    assert!((b.density() - 0.0).abs() < 1e-9);
}

#[test]
fn pcguard_merge_different_lengths_uses_min() {
    let mut a = PcGuardBitmap::new(4);
    let mut b = PcGuardBitmap::new(8);
    b.record_hit(5);
    a.merge(&b);
    // index 5 is past `a`'s len, no panic, no effect
    assert_eq!(a.coverage_count(), 0);
}

#[test]
fn pcguard_hash_differs_on_change() {
    let b1 = PcGuardBitmap::new(8);
    let mut b2 = PcGuardBitmap::new(8);
    b2.record_hit(0);
    assert_ne!(b1.hash(), b2.hash());
}

// ─── EdgeCoverageMap ─────────────────────────────────────────────────────────

#[test]
fn edge_map_reset_clears_all() {
    let mut m = EdgeCoverageMap::new();
    m.record(1, 2);
    m.record(3, 4);
    m.reset();
    assert_eq!(m.edge_count(), 0);
    assert_eq!(m.total_traversals(), 0);
}

#[test]
fn edge_map_successors_isolates_from_addr() {
    let mut m = EdgeCoverageMap::new();
    m.record(0x100, 0x200);
    m.record(0x101, 0x300); // different src
    let succ = m.successors(0x100);
    assert_eq!(succ, vec![0x200]);
}

#[test]
fn edge_map_edge_hits_missing_returns_zero() {
    let m = EdgeCoverageMap::new();
    assert_eq!(m.edge_hits(99, 100), 0);
    assert!(!m.has_edge(99, 100));
}

// ─── CmplogEntry ─────────────────────────────────────────────────────────────

#[test]
fn cmplog_entry_mask_size_8_is_u64_max() {
    let e = CmplogEntry::new(0, 0, 0, 8, false);
    assert_eq!(e.mask(), u64::MAX);
}

#[test]
fn cmplog_entry_mask_unknown_size_falls_through_to_u64_max() {
    // size 3 hits the default `_` branch → u64::MAX
    let e = CmplogEntry::new(0, 0, 0, 3, false);
    assert_eq!(e.mask(), u64::MAX);
}

#[test]
fn cmplog_entry_bit_diff_zero_when_equal() {
    let e = CmplogEntry::new(0, 0xabcd, 0xabcd, 8, true);
    assert_eq!(e.bit_diff(), 0);
    assert!(e.is_equal());
}

#[test]
fn cmplog_map_suggest_mutations_size_clamped_to_8() {
    let mut m = CmplogMap::new();
    m.record(CmplogEntry::new(0, 0, 0xdead_beef_dead_beef, 8, false));
    let muts = m.suggest_mutations();
    assert_eq!(muts.len(), 1);
    assert_eq!(muts[0].len(), 8);
}

#[test]
fn cmplog_map_unique_pcs_sorted() {
    let mut m = CmplogMap::new();
    m.record(CmplogEntry::new(0x300, 0, 0, 1, false));
    m.record(CmplogEntry::new(0x100, 0, 0, 1, false));
    m.record(CmplogEntry::new(0x200, 0, 0, 1, false));
    assert_eq!(m.unique_pcs(), vec![0x100, 0x200, 0x300]);
}

// ─── CorpusPruner ────────────────────────────────────────────────────────────

#[test]
fn corpus_pruner_covers_all_edges() {
    let pruner = CorpusPruner::new();
    let inputs = vec![
        (0usize, vec![1u64, 2]),
        (1usize, vec![3u64, 4]),
        (2usize, vec![5u64]),
    ];
    let selected = pruner.prune(inputs);
    // All edges {1,2,3,4,5} must be covered: each input contributes uniquely.
    assert_eq!(selected.len(), 3);
}

#[test]
fn corpus_pruner_redundant_inputs_dropped() {
    let pruner = CorpusPruner::new();
    let inputs = vec![
        (0usize, vec![1u64, 2, 3]),
        (1usize, vec![1u64]), // redundant
        (2usize, vec![2u64]), // redundant
    ];
    let selected = pruner.prune(inputs);
    assert_eq!(selected, vec![0]);
}

// ─── CoverageHistogram ───────────────────────────────────────────────────────

#[test]
fn histogram_median_single_bucket() {
    let mut r = CoverageRun::new("r");
    for i in 0..10u64 {
        r.hit_n(0x1000 + i, 5);
    }
    let h = CoverageHistogram::from_run(&r);
    assert_eq!(h.median(), 5);
}

#[test]
fn histogram_total_blocks_matches_distinct_blocks() {
    let mut r = CoverageRun::new("r");
    r.hit_n(1, 1);
    r.hit_n(2, 99);
    r.hit_n(3, 99);
    let h = CoverageHistogram::from_run(&r);
    assert_eq!(h.total_blocks(), 3);
}

// ─── CovError display ────────────────────────────────────────────────────────

#[test]
fn cov_error_overflow_display() {
    let e = CovError::Overflow("add".to_string());
    assert!(e.to_string().contains("add"));
}

#[test]
fn cov_error_empty_input_display() {
    let e = CovError::EmptyInput;
    assert!(!e.to_string().is_empty());
}

// ─── DrcovHeader ─────────────────────────────────────────────────────────────

#[test]
fn drcov_header_crlf_lines() {
    let raw = b"DRCOV VERSION: 2\r\nDRCOV FLAVOR: drcov\r\nModule Table: version 2, count 0\r\n";
    let (hdr, consumed) = DrcovHeader::parse(raw).expect("parse CRLF");
    assert_eq!(hdr.version, 2);
    assert_eq!(hdr.flavor, "drcov");
    assert_eq!(hdr.module_count, 0);
    assert_eq!(consumed, raw.len());
}

#[test]
fn drcov_header_consumed_lf_lines() {
    let raw = b"DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\nModule Table: count 0\n";
    let (_hdr, consumed) = DrcovHeader::parse(raw).expect("parse LF");
    assert_eq!(consumed, raw.len());
}

// ─── DrcovModuleV2 ───────────────────────────────────────────────────────────

#[test]
fn drcov_module_v2_parse_table_tab_separated() {
    let text = "0\t0x1000\t0x2000\t0x1100\t/some/path\n";
    let modules = DrcovModuleV2::parse_table(text.as_bytes(), 1).expect("parse");
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].base, 0x1000);
    assert_eq!(modules[0].path, "/some/path");
}

#[test]
fn drcov_module_v2_parse_table_respects_count_limit() {
    // 3 data rows, count=2 → only 2 parsed
    let text = "Columns: id, base, end, entry, checksum, timestamp, path\n\
                0, 0x1000, 0x2000, 0x0, 0x0, 0x0, /a\n\
                1, 0x2000, 0x3000, 0x0, 0x0, 0x0, /b\n\
                2, 0x3000, 0x4000, 0x0, 0x0, 0x0, /c\n";
    let modules = DrcovModuleV2::parse_table(text.as_bytes(), 2).expect("parse");
    assert_eq!(modules.len(), 2);
}

#[test]
fn drcov_module_v2_parse_table_too_few_columns_errors() {
    let text = "0, 0x1000, 0x2000\n";
    assert!(DrcovModuleV2::parse_table(text.as_bytes(), 1).is_err());
}

// ─── DrcovBasicBlock ─────────────────────────────────────────────────────────

#[test]
fn drcov_basic_block_absolute_addr_saturates_on_overflow() {
    let bb = DrcovBasicBlock {
        start: u32::MAX,
        size: 1,
        module_id: 0,
    };
    let addr = bb.absolute_addr(u64::MAX);
    assert_eq!(addr, u64::MAX);
}

#[test]
fn drcov_basic_block_parse_bb_table_zero_count() {
    let data = b"BB Table: 0 bbs\n";
    let bbs = DrcovBasicBlock::parse_bb_table(data).expect("parse");
    assert!(bbs.is_empty());
}

// ─── DrcovFileV2 ─────────────────────────────────────────────────────────────

#[test]
fn drcov_file_v2_bbs_in_range_exclusive_end() {
    let raw = drcov_bytes(3, 3);
    let f = DrcovFileV2::parse(&raw).expect("parse");
    // offsets 0x100, 0x110, 0x120 → absolutes 0x1100, 0x1110, 0x1120
    let in_range = f.bbs_in_range(0x1100, 0x1120);
    assert_eq!(in_range.len(), 2);
}

#[test]
fn drcov_file_v2_absolute_bbs_skips_unknown_module() {
    let mut raw = drcov_bytes(1, 0);
    // append a BB entry with unknown module_id 99
    raw.extend_from_slice(&0u32.to_le_bytes());
    raw.extend_from_slice(&4u16.to_le_bytes());
    raw.extend_from_slice(&99u16.to_le_bytes());
    // Re-parse with header bb_count=1 still
    let f = DrcovFileV2::parse(&raw).expect("parse");
    let abs = f.absolute_bbs();
    assert!(abs.is_empty(), "unknown module_id should be filtered out");
}

// ─── LcovInfoParser ──────────────────────────────────────────────────────────

#[test]
fn lcov_info_parser_bad_da_line_returns_error() {
    let res = LcovInfoParser::parse("SF:/x\nDA:notanumber,1\nend_of_record\n");
    assert!(matches!(res, Err(CovError::Parse(_))));
}

#[test]
fn lcov_info_parser_handles_da_with_checksum() {
    // 3rd comma-field is checksum — should be ignored.
    let data = LcovInfoParser::parse("SF:/x\nDA:10,5,abcdef\nend_of_record\n").expect("parse");
    let f = &data.files["/x"];
    assert_eq!(f.lines.get(&10), Some(&5));
}

// ─── HeatmapColors ───────────────────────────────────────────────────────────

#[test]
fn heatmap_zero_max_nonzero_hits_returns_bright_red() {
    // max_hits == 0 but hits != 0 → "hits >= max_hits" branch → bright red
    assert_eq!(HeatmapColors::color_for_hits(5, 0), [255, 64, 64]);
}

// ─── CoverageDatabaseV2 ──────────────────────────────────────────────────────

#[test]
fn db_v2_remove_run_out_of_range_silent() {
    let mut db = CoverageDatabaseV2::new();
    db.remove_run(0); // no panic
    db.remove_run(100); // no panic
    assert!(db.is_empty());
}

#[test]
fn db_v2_enabled_runs_filter() {
    let mut db = CoverageDatabaseV2::new();
    let f = drcov_bytes(0, 0);
    let parsed = DrcovFileV2::parse(&f).expect("parse");
    db.runs.push(CoverageRunV2::new("a", parsed.clone(), [0, 0, 0]));
    db.runs.push(CoverageRunV2::new("b", parsed, [0, 0, 0]));
    db.toggle_run(0); // disable a
    let enabled: Vec<&str> = db.enabled_runs().map(|r| r.name.as_str()).collect();
    assert_eq!(enabled, vec!["b"]);
}

#[test]
fn db_v2_max_hit_count_empty_zero() {
    let db = CoverageDatabaseV2::new();
    assert_eq!(db.max_hit_count(), 0);
}

#[test]
fn db_v2_toggle_run_out_of_range_silent() {
    let mut db = CoverageDatabaseV2::new();
    db.toggle_run(5); // no panic
    assert!(db.is_empty());
}

// ─── FileCoverage / CoverageData ─────────────────────────────────────────────

#[test]
fn file_coverage_pct_only_zero_hits() {
    let mut fc = FileCoverage::default();
    fc.lines.insert(1, 0);
    fc.lines.insert(2, 0);
    assert_eq!(fc.lines_hit(), 0);
    assert!((fc.line_coverage_pct() - 0.0).abs() < 1e-6);
}

#[test]
fn coverage_data_overall_pct_empty() {
    let d = CoverageData::new();
    assert!((d.overall_line_coverage_pct() - 0.0).abs() < 1e-6);
}

// ─── lcov_export::LcovRecord / LcovWriter ────────────────────────────────────

#[test]
fn lcov_export_recompute_summaries_branches() {
    let mut r = ExportRecord::new("x.rs");
    r.add_branch(1, 0, 0, 0);
    r.add_branch(1, 0, 1, 5);
    r.add_branch(2, 0, 0, 1);
    r.recompute_summaries();
    assert_eq!(r.brh, 2);
}

#[test]
fn lcov_export_writer_roundtrip_preserves_branches() {
    let mut r = ExportRecord::new("x.rs");
    r.add_line(1, 1);
    r.add_branch(1, 0, 0, 3);
    r.recompute_summaries();
    let s = LcovWriter::write(std::slice::from_ref(&r));
    let parsed = LcovWriter::parse(&s);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].branch_data, r.branch_data);
}

#[test]
fn lcov_export_writer_parse_handles_no_end_of_record() {
    // Trailing record without end_of_record marker.
    let text = "SF:/x\nDA:1,1\n";
    let parsed = LcovWriter::parse(text);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].source_file, "/x");
}

#[test]
fn lcov_export_branch_pct_no_branches() {
    let r = ExportRecord::new("x.rs");
    assert!((r.branch_coverage_pct() - 0.0).abs() < 1e-9);
}

#[test]
fn lcov_export_function_pct_no_functions() {
    let r = ExportRecord::new("x.rs");
    assert!((r.function_coverage_pct() - 0.0).abs() < 1e-9);
}

#[test]
fn lcov_export_drcov_importer_propagates_parse_error() {
    let res = DrcovImporter::import(b"garbage", "x");
    assert!(res.is_err());
}

#[test]
fn lcov_export_coverage_report_uncovered_lines_collected() {
    let mut r = ExportRecord::new("x.rs");
    r.add_line(1, 0);
    r.add_line(2, 5);
    r.add_line(3, 0);
    r.recompute_summaries();
    let rep = CoverageReport::from_record(&r);
    assert_eq!(rep.uncovered_lines, vec![1, 3]);
    assert!(!rep.is_fully_covered());
}

#[test]
fn lcov_export_diff_no_change_self() {
    let mut r = ExportRecord::new("x.rs");
    r.add_line(1, 1);
    r.add_line(2, 0);
    r.recompute_summaries();
    let d = CoverageDiffReport::diff(&r, &r);
    assert!(!d.has_new_coverage());
    assert!(!d.has_regression());
}

// ─── Send/Sync surface invariants ────────────────────────────────────────────

#[test]
fn types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DrcovFile>();
    assert_send_sync::<DrcovFileV2>();
    assert_send_sync::<CoverageRun>();
    assert_send_sync::<CoverageDatabase>();
    assert_send_sync::<CoverageDatabaseV2>();
    assert_send_sync::<PcGuardBitmap>();
    assert_send_sync::<EdgeCoverageMap>();
    assert_send_sync::<CmplogMap>();
    assert_send_sync::<CovError>();
}

// ─── Serde round-trips ───────────────────────────────────────────────────────

#[test]
fn serde_drcov_module_round_trip() {
    let m = DrcovModule::new(1, "/a", 10, 20).with_checksum(7);
    let j = serde_json::to_string(&m).unwrap();
    let m2: DrcovModule = serde_json::from_str(&j).unwrap();
    assert_eq!(m, m2);
}

#[test]
fn serde_coverage_diff_round_trip() {
    let d = CoverageDiff {
        only_in_a: vec![1, 2],
        only_in_b: vec![3],
        in_both: vec![4, 5, 6],
    };
    let j = serde_json::to_string(&d).unwrap();
    let d2: CoverageDiff = serde_json::from_str(&j).unwrap();
    assert_eq!(d.only_in_a, d2.only_in_a);
    assert_eq!(d.only_in_b, d2.only_in_b);
    assert_eq!(d.in_both, d2.in_both);
}
