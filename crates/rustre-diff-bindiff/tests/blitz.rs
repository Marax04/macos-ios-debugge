//! Exhaustive blitz tests for rustre-diff-bindiff public API surface.
use std::collections::HashSet;

use rustre_core::address::Address;
use rustre_diff_bindiff::*;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn feat(addr: u64) -> FunctionFeatures {
    FunctionFeatures::new(Address::new(addr))
}

fn make(
    addr: u64,
    bb: u32,
    instr: u32,
    edges: u32,
    cfg_hash: u64,
    byte_hash: u64,
    name: Option<&str>,
) -> FunctionFeatures {
    let mut f = feat(addr);
    f.basic_block_count = bb;
    f.instruction_count = instr;
    f.edge_count = edges;
    f.cfg_hash = cfg_hash;
    f.byte_hash = byte_hash;
    f.name = name.map(str::to_owned);
    f
}

fn info(addr: u64, name: Option<&str>, crc: u32, bb: u32, in_e: u32, out_e: u32, md: u64) -> FunctionInfo {
    let mut i = FunctionInfo::new(addr);
    i.name = name.map(str::to_owned);
    i.bytes_crc32 = crc;
    i.bb_count = bb;
    i.in_edges = in_e;
    i.out_edges = out_e;
    i.md_index = md;
    i
}

// ─── CfgHasher ──────────────────────────────────────────────────────────────

#[test]
fn cfg_hasher_empty_is_zero() {
    assert_eq!(CfgHasher::hash_cfg(&[]), 0);
    assert_eq!(CfgHasher::wl_hash(&[], 3), 0);
}

#[test]
fn cfg_hasher_single_node() {
    let adj = vec![(0u32, vec![])];
    let h = CfgHasher::hash_cfg(&adj);
    assert_ne!(h, 0);
}

#[test]
fn cfg_hasher_topology_isomorphic_same_hash() {
    // Same shape, different IDs/order.
    let a = vec![(1u32, vec![2, 3]), (2, vec![]), (3, vec![])];
    let b = vec![(99u32, vec![]), (10u32, vec![99, 11]), (11, vec![])];
    let ha = CfgHasher::hash_cfg(&a);
    let hb = CfgHasher::hash_cfg(&b);
    assert_eq!(ha, hb, "isomorphic CFGs must hash identically");
}

#[test]
fn cfg_hasher_different_topology_different_hash() {
    let chain = vec![(0u32, vec![1]), (1, vec![2]), (2, vec![])];
    let star = vec![(0u32, vec![1, 2]), (1, vec![]), (2, vec![])];
    assert_ne!(CfgHasher::hash_cfg(&chain), CfgHasher::hash_cfg(&star));
}

#[test]
fn cfg_hasher_linear_distinct_lengths() {
    let mut seen = HashSet::new();
    for i in 1..50u32 {
        assert!(seen.insert(CfgHasher::hash_linear(i)));
    }
}

#[test]
fn cfg_hasher_linear_zero() {
    // For 0 blocks, the loop body never executes; the FNV basis is returned.
    let h = CfgHasher::hash_linear(0);
    assert_eq!(h, 0xcbf2_9ce4_8422_2325);
}

// ─── FunctionFeatures ───────────────────────────────────────────────────────

#[test]
fn features_new_defaults() {
    let f = feat(0xABCD);
    assert_eq!(f.address.as_u64(), 0xABCD);
    assert_eq!(f.basic_block_count, 0);
    assert_eq!(f.cyclomatic_complexity, 1);
    assert_eq!(f.strongly_connected_components, 1);
    assert!(f.string_refs.is_empty());
}

#[test]
fn features_similarity_self_is_one() {
    let mut f = make(0x100, 5, 20, 6, 0xABC, 0xDEF, Some("foo"));
    f.string_refs = vec!["a".into(), "b".into()];
    let s = f.similarity(&f);
    assert!((s - 1.0).abs() < 1e-5, "got {s}");
}

#[test]
fn features_similarity_in_unit_interval() {
    let a = make(1, 10, 50, 12, 0, 0, None);
    let b = make(2, 11, 55, 13, 0, 0, None);
    let s = a.similarity(&b);
    assert!((0.0..=1.0).contains(&s));
}

#[test]
fn features_can_match_zero_zero() {
    let a = feat(1);
    let b = feat(2);
    // both zero: exceeds_ratio returns false → can_match true
    assert!(a.can_match(&b));
}

#[test]
fn features_can_match_5x_boundary() {
    let a = make(1, 1, 1, 0, 0, 0, None);
    let b5 = make(2, 5, 5, 0, 0, 0, None);
    let b6 = make(3, 6, 6, 0, 0, 0, None);
    assert!(a.can_match(&b5), "5x exactly should match");
    assert!(!a.can_match(&b6), "6x should not match");
}

// ─── BinarySnapshot ─────────────────────────────────────────────────────────

#[test]
fn snapshot_add_function_creates_cg_node() {
    let mut s = BinarySnapshot::new("p");
    s.add_function(feat(0x1000));
    assert_eq!(s.function_count(), 1);
    assert!(s.cg_node_map.contains_key(&0x1000));
}

#[test]
fn snapshot_add_call_auto_creates_nodes() {
    let mut s = BinarySnapshot::new("p");
    s.add_call(0x1000, 0x2000);
    assert_eq!(s.call_edge_count(), 1);
    assert_eq!(s.call_targets(0x1000), vec![0x2000]);
    assert_eq!(s.callers_of(0x2000), vec![0x1000]);
}

#[test]
fn snapshot_unknown_addr_returns_empty() {
    let s = BinarySnapshot::new("p");
    assert!(s.call_targets(0xDEAD).is_empty());
    assert!(s.callers_of(0xDEAD).is_empty());
    assert!(s.function_at(0xDEAD).is_none());
}

#[test]
fn snapshot_duplicate_add_function_overwrites() {
    let mut s = BinarySnapshot::new("p");
    s.add_function(make(0x100, 1, 1, 0, 0, 0, Some("a")));
    s.add_function(make(0x100, 5, 5, 0, 0, 0, Some("b")));
    assert_eq!(s.function_count(), 1);
    assert_eq!(s.function_at(0x100).unwrap().name.as_deref(), Some("b"));
}

// ─── MatchKind ──────────────────────────────────────────────────────────────

#[test]
fn matchkind_display_and_priority() {
    assert_eq!(MatchKind::ExactHash.to_string(), "ExactHash");
    assert_eq!(MatchKind::Heuristic.to_string(), "Heuristic");
    assert!(MatchKind::ExactHash.priority() > MatchKind::Heuristic.priority());
    assert!(MatchKind::ExactHash.is_reliable());
    assert!(MatchKind::NameMatch.is_reliable());
    assert!(!MatchKind::Heuristic.is_reliable());
    assert!(!MatchKind::CfgHash.is_reliable());
}

// ─── FunctionMatch ──────────────────────────────────────────────────────────

#[test]
fn match_new_reliable_kinds_get_score_one() {
    let m = FunctionMatch::new(Address::new(1), Address::new(2), MatchKind::ExactHash);
    assert_eq!(m.similarity, 1.0);
    assert_eq!(m.confidence, 1.0);
    let m2 = FunctionMatch::new(Address::new(1), Address::new(2), MatchKind::Heuristic);
    assert_eq!(m2.similarity, 0.0);
}

#[test]
fn match_with_similarity_clamps() {
    let m = FunctionMatch::new(Address::new(1), Address::new(2), MatchKind::Heuristic)
        .with_similarity(2.5);
    assert_eq!(m.similarity, 1.0);
    let m2 = FunctionMatch::new(Address::new(1), Address::new(2), MatchKind::Heuristic)
        .with_similarity(-1.0);
    assert_eq!(m2.similarity, 0.0);
}

#[test]
fn match_quality_label_boundaries() {
    let mut m = FunctionMatch::new(Address::new(1), Address::new(2), MatchKind::Heuristic);
    m.confidence = 1.0;
    m.similarity = 0.99;
    assert_eq!(m.quality_label(), "Identical");
    m.similarity = 0.75;
    assert_eq!(m.quality_label(), "Good");
    m.similarity = 0.50;
    m.confidence = 0.50;
    assert_eq!(m.quality_label(), "Partial");
    m.similarity = 0.49;
    assert_eq!(m.quality_label(), "Poor");
}

// ─── BinDiffer phases ───────────────────────────────────────────────────────

#[test]
fn exact_hash_skips_zero_hash() {
    let mut a = BinarySnapshot::new("a");
    a.add_function(make(0x1, 1, 1, 0, 0, 0, None)); // byte_hash = 0
    let mut b = BinarySnapshot::new("b");
    b.add_function(make(0x2, 1, 1, 0, 0, 0, None));
    let d = BinDiffer::new();
    assert!(d.match_by_exact_hash(&a, &b).is_empty());
}

#[test]
fn exact_hash_unique_match() {
    let mut a = BinarySnapshot::new("a");
    a.add_function(make(0x1, 1, 1, 0, 0, 0xCAFE, None));
    let mut b = BinarySnapshot::new("b");
    b.add_function(make(0x2, 1, 1, 0, 0, 0xCAFE, None));
    let d = BinDiffer::new();
    let m = d.match_by_exact_hash(&a, &b);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].address_a.as_u64(), 1);
    assert_eq!(m[0].address_b.as_u64(), 2);
    assert_eq!(m[0].kind, MatchKind::ExactHash);
}

#[test]
fn exact_hash_skips_when_ambiguous_in_b() {
    let mut a = BinarySnapshot::new("a");
    a.add_function(make(0x1, 1, 1, 0, 0, 0xCAFE, None));
    let mut b = BinarySnapshot::new("b");
    b.add_function(make(0x2, 1, 1, 0, 0, 0xCAFE, None));
    b.add_function(make(0x3, 1, 1, 0, 0, 0xCAFE, None));
    let d = BinDiffer::new();
    assert!(d.match_by_exact_hash(&a, &b).is_empty());
}

#[test]
fn cfg_hash_match_unique() {
    let mut a = BinarySnapshot::new("a");
    a.add_function(make(0x1, 5, 20, 6, 0xC0DE, 0, None));
    let mut b = BinarySnapshot::new("b");
    b.add_function(make(0x2, 5, 20, 6, 0xC0DE, 0, None));
    let d = BinDiffer::new();
    let m = d.match_by_cfg_hash(&a, &b, &HashSet::new());
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].kind, MatchKind::CfgHash);
}

#[test]
fn name_match_uniqueness_required() {
    let mut a = BinarySnapshot::new("a");
    a.add_function(make(0x1, 1, 1, 0, 0, 0, Some("dup")));
    let mut b = BinarySnapshot::new("b");
    b.add_function(make(0x2, 1, 1, 0, 0, 0, Some("dup")));
    b.add_function(make(0x3, 1, 1, 0, 0, 0, Some("dup")));
    let d = BinDiffer::new();
    assert!(d.match_by_name(&a, &b, &HashSet::new()).is_empty());
}

#[test]
fn name_match_basic() {
    let mut a = BinarySnapshot::new("a");
    a.add_function(make(0x1, 1, 1, 0, 0, 0, Some("foo")));
    let mut b = BinarySnapshot::new("b");
    b.add_function(make(0x2, 1, 1, 0, 0, 0, Some("foo")));
    let d = BinDiffer::new();
    let m = d.match_by_name(&a, &b, &HashSet::new());
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].kind, MatchKind::NameMatch);
    assert_eq!(m[0].confidence, 1.0);
}

#[test]
fn diff_full_pipeline_identical_snapshots() {
    let mut a = BinarySnapshot::new("a");
    let mut b = BinarySnapshot::new("b");
    for i in 0..5 {
        a.add_function(make(0x1000 + i, 3, 10, 3, 100 + i, 200 + i, Some("fn")));
        b.add_function(make(0x2000 + i, 3, 10, 3, 100 + i, 200 + i, Some("fn")));
    }
    let d = BinDiffer::new().with_min_similarity(0.5);
    let r = d.diff(a, b);
    assert_eq!(r.stats.matched_count, 5);
    assert_eq!(r.unmatched_a.len(), 0);
    assert_eq!(r.unmatched_b.len(), 0);
}

#[test]
fn diff_min_similarity_clamps() {
    let d = BinDiffer::new().with_min_similarity(5.0);
    assert_eq!(d.min_similarity, 1.0);
    let d = BinDiffer::new().with_min_similarity(-2.0);
    assert_eq!(d.min_similarity, 0.0);
}

#[test]
fn diff_without_propagation_sets_flag() {
    let d = BinDiffer::new().without_propagation();
    assert!(!d.enable_propagation);
}

// ─── DiffResult / DiffReport ────────────────────────────────────────────────

#[test]
fn diff_result_lookups() {
    let mut a = BinarySnapshot::new("a");
    let mut b = BinarySnapshot::new("b");
    a.add_function(make(0x10, 3, 10, 3, 0xABC, 0xDEF, Some("f")));
    b.add_function(make(0x20, 3, 10, 3, 0xABC, 0xDEF, Some("f")));
    let r = BinDiffer::new().diff(a, b);
    assert!(r.match_for_a(0x10).is_some());
    assert!(r.match_for_b(0x20).is_some());
    assert!(r.match_for_a(0xFFFF).is_none());
}

#[test]
fn diff_report_csv_and_json_and_html() {
    let mut a = BinarySnapshot::new("a");
    let mut b = BinarySnapshot::new("b");
    a.add_function(make(0x10, 1, 1, 0, 0, 0xABC, Some("f\"x")));
    b.add_function(make(0x20, 1, 1, 0, 0, 0xABC, Some("f\"x")));
    let r = BinDiffer::new().diff(a, b);
    let report = DiffReport::new(r);
    let csv = report.csv();
    assert!(csv.starts_with("addr_a,addr_b,"));
    let json = report.json();
    assert!(json.starts_with('['));
    assert!(json.contains("\\\""), "json must escape quotes");
    let html = report.html();
    assert!(html.contains("<table>"));
    assert!(report.summary().contains("BinDiff Summary"));
    assert!(report.diff_for_function(0x10).is_some());
    assert!(report.diff_for_function(0xDEAD).is_none());
}

// ─── FunctionInfo ───────────────────────────────────────────────────────────

#[test]
fn function_info_helpers() {
    let i = info(0x10, Some("foo"), 0xABC, 5, 1, 2, 42);
    assert!(i.has_byte_hash());
    assert!(i.has_md_index());
    assert!(i.has_name());
    assert_eq!(i.name_or_unnamed(), "foo");
    assert!(i.debug_label().contains("0x10"));

    let z = info(0x20, None, 0, 0, 0, 0, 0);
    assert!(!z.has_byte_hash());
    assert!(!z.has_md_index());
    assert!(!z.has_name());
    assert_eq!(z.name_or_unnamed(), "<unnamed>");
}

#[test]
fn function_info_can_match_zero_zero() {
    let a = info(1, None, 0, 0, 0, 0, 0);
    let b = info(2, None, 0, 0, 0, 0, 0);
    assert!(a.can_match(&b));
}

#[test]
fn function_info_can_match_5x_ratio() {
    let a = info(1, None, 0, 1, 0, 0, 0);
    let b5 = info(2, None, 0, 5, 0, 0, 0);
    let b6 = info(3, None, 0, 6, 0, 0, 0);
    assert!(a.can_match(&b5));
    assert!(!a.can_match(&b6));
}

#[test]
fn function_info_from_features_copies_fields() {
    let mut f = make(0x100, 5, 20, 7, 0, 0xCAFE_BABE_DEAD_BEEF, Some("x"));
    f.caller_count = 3;
    f.callee_count = 4;
    let i: FunctionInfo = (&f).into();
    assert_eq!(i.address, 0x100);
    assert_eq!(i.in_edges, 3);
    assert_eq!(i.out_edges, 4);
    assert_eq!(i.bb_count, 5);
    assert_eq!(i.bytes_crc32, 0xDEAD_BEEF);
    assert!(i.md_index != 0);
}

// ─── similarity_score (FunctionInfo) ────────────────────────────────────────

#[test]
fn similarity_score_identical_named_and_hashed() {
    let a = info(1, Some("f"), 0xABC, 5, 2, 3, 42);
    let b = info(2, Some("f"), 0xABC, 5, 2, 3, 42);
    let s = similarity_score(&a, &b);
    assert!((s - 1.0).abs() < 1e-6, "got {s}");
}

#[test]
fn similarity_score_in_unit_range() {
    let a = info(1, Some("f"), 0xABC, 5, 2, 3, 42);
    let b = info(2, Some("g"), 0xDEF, 50, 20, 30, 9999);
    let s = similarity_score(&a, &b);
    assert!((0.0..=1.0).contains(&s), "got {s}");
}

#[test]
fn similarity_score_empty_names_neutral() {
    let a = info(1, None, 0, 5, 2, 3, 42);
    let b = info(2, None, 0, 5, 2, 3, 42);
    let s = similarity_score(&a, &b);
    // 0 (name) + 0 (crc) + 0.2 * 1 (cfg) + 0.1 * 1 (md) = 0.30
    assert!((s - 0.30).abs() < 1e-6, "got {s}");
}

#[test]
fn cfg_similarity_identical_is_one() {
    let a = info(1, None, 0, 5, 2, 3, 0);
    let b = info(2, None, 0, 5, 2, 3, 0);
    assert!((cfg_similarity(&a, &b) - 1.0).abs() < 1e-9);
}

// ─── HungarianSolver ────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "must not be empty")]
fn hungarian_empty_panics() {
    let _ = HungarianSolver::new(vec![]);
}

#[test]
fn hungarian_1x1_trivial() {
    let s = HungarianSolver::new(vec![vec![0.7]]);
    let a = s.solve();
    assert_eq!(a, vec![(0, 0)]);
    assert!(s.validate_assignment(&a).is_ok());
}

#[test]
fn hungarian_2x2_optimal() {
    // Optimal: (0,1)=1.0 + (1,0)=2.0 = 3.0  vs (0,0)+(1,1)=4+3=7.
    let s = HungarianSolver::new(vec![vec![4.0, 1.0], vec![2.0, 3.0]]);
    let a = s.solve();
    let cost = s.assignment_cost(&a);
    assert!((cost - 3.0).abs() < 1e-6, "got cost {cost}");
}

#[test]
fn hungarian_rectangular_padded() {
    // 2 rows, 3 cols.
    let s = HungarianSolver::new(vec![vec![1.0, 2.0, 3.0], vec![4.0, 5.0, 6.0]]);
    assert_eq!(s.original_cols(), 3);
    let a = s.solve();
    // Each row appears once; n=3 after padding.
    assert!(s.validate_assignment(&a).is_ok());
}

#[test]
fn hungarian_from_similarity_inverts() {
    let s = HungarianSolver::from_similarity(vec![vec![1.0, 0.0], vec![0.0, 1.0]]);
    let a = s.solve();
    let cost = s.assignment_cost(&a);
    assert!(cost.abs() < 1e-9, "got cost {cost}");
}

#[test]
fn hungarian_solve_with_scores_filters_threshold() {
    let s = HungarianSolver::from_similarity(vec![vec![0.9, 0.1], vec![0.1, 0.4]]);
    let scored = s.solve_with_scores(2, 2, 0.5);
    // Only one pair above threshold 0.5
    assert_eq!(scored.len(), 1);
    assert!(scored[0].2 >= 0.5);
}

#[test]
fn hungarian_validate_assignment_detects_dupes() {
    let s = HungarianSolver::new(vec![vec![1.0, 2.0], vec![3.0, 4.0]]);
    let bad = vec![(0, 0), (1, 0)];
    assert!(s.validate_assignment(&bad).is_err());
}

// ─── match_functions_hungarian / greedy ─────────────────────────────────────

#[test]
fn match_functions_hungarian_empty_inputs() {
    let r = match_functions_hungarian(&[], &[], 0.5);
    assert!(r.is_empty());
    let one = vec![info(1, None, 0, 1, 0, 0, 0)];
    let r2 = match_functions_hungarian(&one, &[], 0.5);
    assert!(r2.is_empty());
}

#[test]
fn match_functions_hungarian_perfect_pair() {
    let a = vec![info(1, Some("foo"), 0xABC, 3, 1, 1, 100)];
    let b = vec![info(2, Some("foo"), 0xABC, 3, 1, 1, 100)];
    let r = match_functions_hungarian(&a, &b, 0.5);
    assert_eq!(r.len(), 1);
    assert!(r[0].similarity > 0.9);
}

#[test]
fn match_functions_greedy_matches_best() {
    let a = vec![
        info(1, Some("foo"), 0xABC, 3, 1, 1, 100),
        info(2, Some("bar"), 0xDEF, 5, 2, 1, 200),
    ];
    let b = vec![
        info(10, Some("bar"), 0xDEF, 5, 2, 1, 200),
        info(11, Some("foo"), 0xABC, 3, 1, 1, 100),
    ];
    let r = match_functions_greedy(&a, &b, 0.5);
    assert_eq!(r.len(), 2);
    // sorted descending
    assert!(r[0].similarity >= r[1].similarity);
}

// ─── MatchMatrix ────────────────────────────────────────────────────────────

#[test]
fn match_matrix_build_and_query() {
    let a = vec![info(1, Some("x"), 0, 1, 0, 0, 0), info(2, Some("y"), 0, 2, 0, 0, 0)];
    let b = vec![info(3, Some("x"), 0, 1, 0, 0, 0)];
    let m = MatchMatrix::build(&a, &b);
    assert_eq!(m.rows(), 2);
    assert_eq!(m.cols(), 1);
    let best = m.best_pair().unwrap();
    assert_eq!(best.0, 0); // row 0 matches name "x"
}

#[test]
fn match_matrix_above_threshold_sorted() {
    let a = vec![info(1, Some("x"), 0, 1, 0, 0, 0)];
    let b = vec![
        info(2, Some("x"), 0, 1, 0, 0, 0),
        info(3, Some("y"), 0, 1, 0, 0, 0),
    ];
    let m = MatchMatrix::build(&a, &b);
    let pairs = m.above_threshold(0.4);
    assert!(!pairs.is_empty());
    for w in pairs.windows(2) {
        assert!(w[0].2 >= w[1].2);
    }
}

#[test]
fn match_matrix_greedy_assign_no_double_use() {
    let a = vec![
        info(1, Some("x"), 0, 1, 0, 0, 0),
        info(2, Some("y"), 0, 1, 0, 0, 0),
    ];
    let b = vec![
        info(3, Some("x"), 0, 1, 0, 0, 0),
        info(4, Some("y"), 0, 1, 0, 0, 0),
    ];
    let m = MatchMatrix::build(&a, &b);
    let assigned = m.greedy_assign(0.1);
    let mut rows: HashSet<usize> = HashSet::new();
    let mut cols: HashSet<usize> = HashSet::new();
    for (i, j, _) in &assigned {
        assert!(rows.insert(*i));
        assert!(cols.insert(*j));
    }
}

#[test]
fn match_matrix_into_solver() {
    let a = vec![info(1, Some("x"), 0, 1, 0, 0, 0)];
    let b = vec![info(2, Some("x"), 0, 1, 0, 0, 0)];
    let m = MatchMatrix::build(&a, &b);
    let solver = m.into_solver();
    let asg = solver.solve();
    assert_eq!(asg.len(), 1);
}

// ─── jaccard_bb_score ───────────────────────────────────────────────────────

#[test]
fn jaccard_bb_zero_zero_returns_one() {
    assert_eq!(jaccard_bb_score(0, 0, 0), 1.0);
}

#[test]
fn jaccard_bb_full_overlap() {
    assert_eq!(jaccard_bb_score(5, 5, 5), 1.0);
}

#[test]
fn jaccard_bb_partial() {
    let s = jaccard_bb_score(3, 5, 5); // 3 / (5+5-3) = 3/7
    assert!((s - 3.0 / 7.0).abs() < 1e-6);
}

#[test]
fn jaccard_bb_saturating() {
    // matched capped to min(blocks_a, blocks_b)
    let s = jaccard_bb_score(100, 5, 5);
    assert_eq!(s, 1.0);
}

// ─── BinDiff / BindiffEngine ────────────────────────────────────────────────

#[test]
fn bindiff_runs_end_to_end() {
    let mut a = BinarySnapshot::new("a");
    let mut b = BinarySnapshot::new("b");
    a.add_function(make(0x10, 3, 10, 3, 0xABC, 0xDEF, Some("main")));
    b.add_function(make(0x20, 3, 10, 3, 0xABC, 0xDEF, Some("main")));
    let r = BinDiff::new().run(a, b);
    assert_eq!(r.stats.matched_count, 1);
}

#[test]
fn bindiff_engine_compare_and_report() {
    let mut a = BinarySnapshot::new("a");
    let mut b = BinarySnapshot::new("b");
    for i in 0..3 {
        a.add_function(make(0x10 + i, 3, 10, 3, 100 + i, 200 + i, Some("fn")));
        b.add_function(make(0x20 + i, 3, 10, 3, 100 + i, 200 + i, Some("fn")));
    }
    let report = BindiffEngine::new().compare(a, b);
    assert!(report.exact_matches + report.similar_matches >= 1);
    let _ = format!("{report}");
    assert!(report.overall_similarity() >= 0.0);
    assert!(report.overall_similarity() <= 1.0);
}

#[test]
fn bindiff_engine_compare_functions_helper() {
    let fa = vec![make(0x10, 1, 1, 0, 0, 0xCAFE, Some("a"))];
    let fb = vec![make(0x20, 1, 1, 0, 0, 0xCAFE, Some("a"))];
    let r = BindiffEngine::new().compare_functions(&fa, &fb, "pa", "pb");
    assert_eq!(r.exact_matches + r.similar_matches, 1);
}

#[test]
fn bindiff_engine_similar_threshold_clamps() {
    let e = BindiffEngine::new().with_similar_threshold(5.0);
    assert_eq!(e.similar_threshold, 1.0);
    let e = BindiffEngine::new().with_similar_threshold(-1.0);
    assert_eq!(e.similar_threshold, 0.0);
}

#[test]
fn bindiff_report_overall_empty() {
    let r = BindiffReport {
        exact_matches: 0,
        similar_matches: 0,
        unmatched_in_a: 0,
        unmatched_in_b: 0,
        all_matches: vec![],
        jaccard_scores: vec![],
        unmatched_a_addrs: vec![],
        unmatched_b_addrs: vec![],
    };
    assert_eq!(r.overall_similarity(), 0.0);
}

// ─── AssignmentStats ────────────────────────────────────────────────────────

#[test]
fn assignment_stats_basic() {
    let a = vec![
        info(1, Some("x"), 0xABC, 1, 0, 0, 0),
        info(2, Some("y"), 0xDEF, 1, 0, 0, 0),
    ];
    let b = vec![
        info(3, Some("x"), 0xABC, 1, 0, 0, 0),
        info(4, Some("y"), 0xDEF, 1, 0, 0, 0),
    ];
    let asg = vec![(0, 0), (1, 1)];
    let s = AssignmentStats::compute(&asg, &a, &b, 0.0);
    assert_eq!(s.total_pairs, 2);
    assert_eq!(s.accepted_pairs, 2);
    assert_eq!(s.name_confirmed, 2);
    assert_eq!(s.byte_confirmed, 2);
    assert!(s.mean_similarity > 0.0);
    assert!(s.max_similarity >= s.min_similarity);
}

#[test]
fn assignment_stats_below_threshold_empty() {
    let a = vec![info(1, None, 0, 1, 0, 0, 0)];
    let b = vec![info(2, None, 0, 100, 50, 50, 0)];
    let asg = vec![(0, 0)];
    let s = AssignmentStats::compute(&asg, &a, &b, 0.99);
    assert_eq!(s.accepted_pairs, 0);
    assert_eq!(s.mean_similarity, 0.0);
}

// ─── Propagation ────────────────────────────────────────────────────────────

#[test]
fn propagate_matches_extends_through_chain() {
    let mut a = BinarySnapshot::new("a");
    let mut b = BinarySnapshot::new("b");
    // root -> child  (only single edge => propagatable)
    a.add_function(make(0x100, 1, 1, 0, 0xAA, 0, Some("root")));
    a.add_function(make(0x200, 2, 4, 1, 0xBB, 0, None));
    a.add_call(0x100, 0x200);
    b.add_function(make(0x100, 1, 1, 0, 0xAA, 0, Some("root")));
    b.add_function(make(0x200, 2, 4, 1, 0xBB, 0, None));
    b.add_call(0x100, 0x200);

    // Seed the root match.
    let seed = FunctionMatch::new(Address::new(0x100), Address::new(0x100), MatchKind::ExactHash);
    let mut matches = vec![seed];
    BinDiffer::new().propagate_matches(&mut matches, &a, &b);
    assert!(matches.iter().any(|m| m.kind == MatchKind::CallGraphPropagation));
}

// ─── HUNGARIAN_THRESHOLD constant ───────────────────────────────────────────

#[test]
fn hungarian_threshold_is_reasonable() {
    assert!(HUNGARIAN_THRESHOLD >= 1000);
}
