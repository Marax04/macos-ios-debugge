//! Blitz test suite for `rustre-analysis-xref`.
//!
//! Focuses on edge cases, invariants between primary and secondary indices,
//! adversarial inputs to scanners, and round-trip properties.

use rustre_analysis_xref::*;
use rustre_core::address::{Address, AddressRange};

const fn a(v: u64) -> Address {
    Address::new(v)
}

const fn r(s: u64, e: u64) -> AddressRange {
    AddressRange::new(a(s), a(e))
}

// ---------------------------------------------------------------------------
// XrefKind classifier predicates
// ---------------------------------------------------------------------------

#[test]
fn kind_is_code_covers_call_jump_return_thunk() {
    assert!(XrefKind::CodeCall.is_code());
    assert!(XrefKind::CodeJump.is_code());
    assert!(XrefKind::CodeReturn.is_code());
    assert!(XrefKind::ThunkCall.is_code());
    assert!(!XrefKind::DataRead.is_code());
    assert!(!XrefKind::StringRef.is_code());
}

#[test]
fn kind_is_data_excludes_imports_strings_types() {
    assert!(XrefKind::DataRead.is_data());
    assert!(XrefKind::DataWrite.is_data());
    assert!(XrefKind::DataAddress.is_data());
    assert!(XrefKind::DataPointer.is_data());
    assert!(!XrefKind::ImportByName.is_data());
    assert!(!XrefKind::StringRef.is_data());
    assert!(!XrefKind::TypeRef.is_data());
    assert!(!XrefKind::CodeCall.is_data());
}

#[test]
fn kind_is_import() {
    assert!(XrefKind::ImportByName.is_import());
    assert!(XrefKind::ImportByOrdinal.is_import());
    assert!(!XrefKind::CodeCall.is_import());
}

#[test]
fn kind_all_contains_every_variant() {
    let all = XrefKind::all();
    assert_eq!(all.len(), 12);
    // Display strings should all round-trip via from_json/to_json indirectly.
    let names: Vec<String> = all.iter().map(ToString::to_string).collect();
    for n in &names {
        assert!(!n.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Xref convenience
// ---------------------------------------------------------------------------

#[test]
fn xref_with_tag_sets_tag() {
    let x = Xref::with_tag(a(1), a(2), XrefKind::StringRef, 0, "hi");
    assert_eq!(x.tag.as_deref(), Some("hi"));
    assert!(x.is_data() == false);
}

#[test]
fn xref_display_includes_tag() {
    let x = Xref::with_tag(a(0x1000), a(0x2000), XrefKind::StringRef, 0, "hello");
    let s = x.to_string();
    assert!(s.contains("0x00001000"));
    assert!(s.contains("0x00002000"));
    assert!(s.contains("StringRef"));
    assert!(s.contains("hello"));
}

#[test]
fn xref_display_no_tag_no_quotes() {
    let x = Xref::new(a(0x1000), a(0x2000), XrefKind::CodeCall, 5);
    let s = x.to_string();
    assert!(!s.contains('"'));
}

// ---------------------------------------------------------------------------
// XrefDatabase: secondary-index consistency under removals
// ---------------------------------------------------------------------------

#[test]
fn remove_to_rebuilds_string_index() {
    let mut db = XrefDatabase::new();
    db.add_string_ref(a(0x1000), a(0x5000), "alpha");
    db.add_string_ref(a(0x1010), a(0x5000), "alpha");
    db.add_string_ref(a(0x1020), a(0x6000), "beta");
    assert_eq!(db.string_ref_sites("alpha").len(), 2);

    db.remove_to(a(0x5000));

    // After removing every xref pointing to 0x5000, "alpha" must not appear.
    assert_eq!(
        db.string_ref_sites("alpha").len(),
        0,
        "secondary string index must be rebuilt after remove_to"
    );
    assert_eq!(db.string_ref_sites("beta").len(), 1);
}

#[test]
fn remove_from_rebuilds_import_index() {
    let mut db = XrefDatabase::new();
    db.add_import_by_name(a(0x1000), a(0x9000), "malloc");
    db.add_import_by_name(a(0x1010), a(0x9000), "malloc");
    db.add_import_by_name(a(0x2000), a(0x9100), "free");

    db.remove_from(a(0x1000));
    assert_eq!(db.xrefs_to_import("malloc").len(), 1);
    db.remove_from(a(0x1010));
    assert_eq!(db.xrefs_to_import("malloc").len(), 0);
    assert_eq!(db.xrefs_to_import("free").len(), 1);
}

#[test]
fn remove_exact_only_removes_matching_kind() {
    let mut db = XrefDatabase::new();
    db.add_call(a(0x1000), a(0x2000), 5);
    db.add_jump(a(0x1000), a(0x2000), 5);
    let removed = db.remove_exact(a(0x1000), a(0x2000), XrefKind::CodeCall);
    assert!(removed);
    assert_eq!(db.total_count(), 1);
    let remaining = db.xrefs_from(a(0x1000));
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].kind, XrefKind::CodeJump);
}

#[test]
fn remove_exact_returns_false_when_missing() {
    let mut db = XrefDatabase::new();
    db.add_call(a(0x1000), a(0x2000), 5);
    assert!(!db.remove_exact(a(0x1000), a(0x2000), XrefKind::CodeJump));
    assert_eq!(db.total_count(), 1);
}

#[test]
fn total_count_matches_iter_all_after_mutations() {
    let mut db = XrefDatabase::new();
    db.add_call(a(1), a(2), 5);
    db.add_jump(a(3), a(4), 5);
    db.add_string_ref(a(5), a(6), "x");
    db.remove_from(a(3));
    db.add_call(a(7), a(8), 5);
    db.remove_exact(a(1), a(2), XrefKind::CodeCall);
    let counted: usize = db.iter_all().count();
    assert_eq!(counted, db.total_count());
}

// ---------------------------------------------------------------------------
// XrefDatabase: merge
// ---------------------------------------------------------------------------

#[test]
fn merge_concatenates_and_rebuilds_indices() {
    let mut a_db = XrefDatabase::new();
    a_db.add_call(a(0x1000), a(0x2000), 5);
    a_db.add_string_ref(a(0x1010), a(0x3000), "abc");

    let mut b_db = XrefDatabase::new();
    b_db.add_call(a(0x1100), a(0x2000), 5);
    b_db.add_string_ref(a(0x1110), a(0x3000), "abc");

    a_db.merge(b_db);
    assert_eq!(a_db.total_count(), 4);
    assert_eq!(a_db.callers_of(a(0x2000)).len(), 2);
    assert_eq!(a_db.string_ref_sites("abc").len(), 2);
}

// ---------------------------------------------------------------------------
// JSON round-trip
// ---------------------------------------------------------------------------

#[test]
fn json_round_trip_preserves_all_kinds_and_tags() {
    let mut db = XrefDatabase::new();
    db.add_call(a(0x1000), a(0x2000), 5);
    db.add_jump(a(0x1010), a(0x1020), 2);
    db.add_return(a(0x1030), a(0x1040));
    db.add_data_read(a(0x1050), a(0x5000));
    db.add_data_write(a(0x1060), a(0x5000));
    db.add_data_addr(a(0x1070), a(0x5000));
    db.add_data_pointer(a(0x4000), a(0x2000));
    db.add_import_by_name(a(0x1080), a(0x9000), "puts");
    db.add_import_by_ordinal(a(0x1090), a(0x9100), 7);
    db.add_string_ref(a(0x10A0), a(0x6000), "hello");
    db.add_type_ref(a(0x10B0), a(0x7000), "MyType");
    db.add_thunk(a(0x10C0), a(0x10D0), 5);

    let json = db.to_json().unwrap();
    let db2 = XrefDatabase::from_json(&json).unwrap();
    assert_eq!(db2.total_count(), db.total_count());
    assert_eq!(db2.xrefs_to_import("puts").len(), 1);
    assert_eq!(db2.xrefs_to_import("7").len(), 1);
    assert_eq!(db2.string_ref_sites("hello").len(), 1);
    assert_eq!(db2.xrefs_to_type("MyType").len(), 1);
}

#[test]
fn from_json_rejects_unknown_kind() {
    let bad = r#"[{"from":1,"to":2,"kind":"NotAKind","instr_size":0,"tag":null}]"#;
    let err = XrefDatabase::from_json(bad).err().unwrap();
    match err {
        XrefError::UnknownKind(s) => assert_eq!(s, "NotAKind"),
        other => panic!("expected UnknownKind, got {other:?}"),
    }
}

#[test]
fn from_json_rejects_malformed() {
    let err = XrefDatabase::from_json("not json").err().unwrap();
    matches!(err, XrefError::Json(_));
}

#[test]
fn from_json_empty_array_yields_empty_db() {
    let db = XrefDatabase::from_json("[]").unwrap();
    assert!(db.is_empty());
    assert_eq!(db.total_count(), 0);
}

// ---------------------------------------------------------------------------
// XrefFilter
// ---------------------------------------------------------------------------

#[test]
fn filter_require_tag_excludes_untagged() {
    let mut db = XrefDatabase::new();
    db.add_call(a(0x1000), a(0x2000), 5);
    db.add_string_ref(a(0x1010), a(0x3000), "tagged");
    let f = XrefFilter::new().with_tag_required();
    let res = db.filter_all(&f);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].kind, XrefKind::StringRef);
}

#[test]
fn filter_min_from_and_max_to() {
    let mut db = XrefDatabase::new();
    db.add_call(a(0x500), a(0x9000), 5);
    db.add_call(a(0x1500), a(0x2000), 5);
    db.add_call(a(0x2500), a(0x3000), 5);

    let f = XrefFilter::new().min_from(0x1000).max_to(0x5000);
    let res = db.filter_all(&f);
    assert_eq!(res.len(), 2);
}

#[test]
fn filter_empty_matches_all() {
    let mut db = XrefDatabase::new();
    db.add_call(a(0x1000), a(0x2000), 5);
    db.add_jump(a(0x1010), a(0x1020), 2);
    let f = XrefFilter::new();
    assert_eq!(db.filter_all(&f).len(), 2);
}

#[test]
fn filter_from_addr_and_to_addr_helpers() {
    let mut db = XrefDatabase::new();
    db.add_call(a(0x1000), a(0x2000), 5);
    db.add_call(a(0x1000), a(0x3000), 5);
    db.add_call(a(0x1010), a(0x2000), 5);

    let f_calls_only = XrefFilter::new().with_kinds([XrefKind::CodeCall]);
    let from_res = db.filter_from(a(0x1000), &f_calls_only);
    assert_eq!(from_res.len(), 2);

    let to_res = db.filter_to(a(0x2000), &f_calls_only);
    assert_eq!(to_res.len(), 2);
}

// ---------------------------------------------------------------------------
// XrefGraph reachability/degree
// ---------------------------------------------------------------------------

#[test]
fn graph_self_loop_creates_singleton_scc_of_size_one() {
    // A node with a single self-loop is its own SCC of size >= 1.
    let mut db = XrefDatabase::new();
    db.add_call(a(0x1000), a(0x1000), 5);
    let g = XrefGraph::call_graph(&db);
    let sccs = g.strongly_connected_components();
    assert_eq!(sccs.len(), 1);
    assert_eq!(sccs[0].len(), 1);
    assert!(g.is_reachable(a(0x1000), a(0x1000)));
}

#[test]
fn graph_in_out_degree() {
    let mut db = XrefDatabase::new();
    db.add_call(a(0x1000), a(0x2000), 5);
    db.add_call(a(0x1010), a(0x2000), 5);
    db.add_call(a(0x2000), a(0x3000), 5);
    let g = XrefGraph::call_graph(&db);
    assert_eq!(g.in_degree(a(0x2000)), 2);
    assert_eq!(g.out_degree(a(0x2000)), 1);
    assert_eq!(g.out_degree(a(0xDEAD)), 0);
}

#[test]
fn graph_full_graph_includes_all_kinds() {
    let mut db = XrefDatabase::new();
    db.add_call(a(1), a(2), 5);
    db.add_jump(a(3), a(4), 2);
    db.add_data_read(a(5), a(6));
    db.add_string_ref(a(7), a(8), "x");
    let g = XrefGraph::full_graph(&db);
    assert!(g.contains(a(8)));
    assert!(g.node_count() >= 8);
}

#[test]
fn graph_data_graph_excludes_calls() {
    let mut db = XrefDatabase::new();
    db.add_call(a(1), a(2), 5);
    db.add_data_read(a(3), a(4));
    let g = XrefGraph::data_graph(&db);
    assert!(g.contains(a(3)));
    assert!(g.contains(a(4)));
    assert!(!g.contains(a(1)));
}

#[test]
fn graph_successors_unknown_node_empty() {
    let db = XrefDatabase::new();
    let g = XrefGraph::call_graph(&db);
    assert!(g.successors(a(0xBEEF)).is_empty());
}

#[test]
fn graph_topo_sort_disconnected_dag() {
    let mut db = XrefDatabase::new();
    db.add_call(a(1), a(2), 5);
    db.add_call(a(3), a(4), 5);
    let g = XrefGraph::call_graph(&db);
    let order = g.topological_sort().expect("DAG should sort");
    assert_eq!(order.len(), 4);
}

#[test]
fn graph_reachable_from_includes_start() {
    let mut db = XrefDatabase::new();
    db.add_call(a(1), a(2), 5);
    let g = XrefGraph::call_graph(&db);
    let set = g.reachable_from(a(1));
    assert!(set.contains(&a(1)));
    assert!(set.contains(&a(2)));
}

// ---------------------------------------------------------------------------
// X86XrefScanner — adversarial / boundary inputs
// ---------------------------------------------------------------------------

#[test]
fn scanner_empty_input_no_panic() {
    let scanner = X86XrefScanner::new(r(0x1000, 0x2000), 8);
    let mut db = XrefDatabase::new();
    scanner.scan_code(a(0x1000), &[], &mut db);
    assert_eq!(db.total_count(), 0);
}

#[test]
fn scanner_truncated_call_no_panic() {
    let scanner = X86XrefScanner::new(r(0x1000, 0x2000), 8);
    // E8 followed by only 2 bytes: should not panic or emit garbage call.
    let bytes = [0xE8u8, 0x00, 0x00];
    let mut db = XrefDatabase::new();
    // The main loop advances i by 5 on 0xE8 unconditionally; this would index OOB.
    // Catch via std::panic::catch_unwind so we report a real bug rather than aborting.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scanner.scan_code(a(0x1000), &bytes, &mut db);
    }));
    assert!(result.is_ok(), "scanner panicked on truncated E8 input");
}

#[test]
fn scanner_target_outside_code_range_dropped() {
    let scanner = X86XrefScanner::new(r(0x1000, 0x2000), 8);
    // CALL targeting far outside the range.
    let rel: i32 = 0x7FFF_FFFF;
    let mut bytes = vec![0u8; 5];
    bytes[0] = 0xE8;
    bytes[1..5].copy_from_slice(&rel.to_le_bytes());
    let mut db = XrefDatabase::new();
    scanner.scan_code(a(0x1000), &bytes, &mut db);
    assert_eq!(db.total_count(), 0);
}

#[test]
fn scanner_short_jmp_eb_within_range() {
    let scanner = X86XrefScanner::new(r(0x1000, 0x2000), 8);
    // EB +5 at offset 0x1000 -> target 0x1007.
    let bytes = [0xEBu8, 5, 0x90, 0x90, 0x90, 0x90, 0x90];
    let mut db = XrefDatabase::new();
    scanner.scan_code(a(0x1000), &bytes, &mut db);
    let jumps: Vec<&Xref> = db.iter_all().filter(|x| x.kind == XrefKind::CodeJump).collect();
    assert_eq!(jumps.len(), 1);
    assert_eq!(jumps[0].to, a(0x1007));
}

#[test]
fn scanner_thunk_at_offset_zero() {
    // E9 at offset 0 with detect_thunks=true (default), function_entries empty -> ThunkCall.
    let scanner = X86XrefScanner::new(r(0x1000, 0x2000), 8);
    let rel: i32 = 0x1100i64.wrapping_sub(0x1005i64) as i32;
    let mut bytes = vec![0u8; 5];
    bytes[0] = 0xE9;
    bytes[1..5].copy_from_slice(&rel.to_le_bytes());
    let mut db = XrefDatabase::new();
    scanner.scan_code(a(0x1000), &bytes, &mut db);
    let thunks: Vec<&Xref> = db.iter_all().filter(|x| x.kind == XrefKind::ThunkCall).collect();
    assert_eq!(thunks.len(), 1);
    assert_eq!(thunks[0].to, a(0x1100));
}

#[test]
fn scanner_thunk_detection_disabled_yields_jump() {
    let scanner = X86XrefScanner::new(r(0x1000, 0x2000), 8).without_thunk_detection();
    let rel: i32 = 0x1100i64.wrapping_sub(0x1005i64) as i32;
    let mut bytes = vec![0u8; 5];
    bytes[0] = 0xE9;
    bytes[1..5].copy_from_slice(&rel.to_le_bytes());
    let mut db = XrefDatabase::new();
    scanner.scan_code(a(0x1000), &bytes, &mut db);
    assert!(db.iter_all().all(|x| x.kind != XrefKind::ThunkCall));
}

#[test]
fn scanner_data_pointer_zero_step_does_nothing() {
    let scanner = X86XrefScanner::new(r(0x1000, 0x2000), 0);
    let mut db = XrefDatabase::new();
    scanner.scan_data_pointers(a(0x4000), &[1, 2, 3, 4, 5, 6, 7, 8], &mut db);
    assert_eq!(db.total_count(), 0);
}

#[test]
fn scanner_data_pointer_too_small_data_no_panic() {
    let scanner = X86XrefScanner::new(r(0x1000, 0x2000), 8);
    let mut db = XrefDatabase::new();
    scanner.scan_data_pointers(a(0x4000), &[1, 2, 3], &mut db);
    assert_eq!(db.total_count(), 0);
}

// ---------------------------------------------------------------------------
// StringXrefScanner
// ---------------------------------------------------------------------------

#[test]
fn string_scanner_empty_input() {
    let s = StringXrefScanner::new(4);
    assert!(s.scan_ascii(a(0), &[]).is_empty());
}

#[test]
fn string_scanner_min_length_boundary() {
    let s = StringXrefScanner::new(4);
    let data = b"abcd\0abc\0abcd\0";
    let res = s.scan_ascii(a(0), data);
    // "abcd" qualifies (len 4 >= 4), "abc" does not (len 3).
    assert_eq!(res.iter().filter(|(_, t)| t == "abcd").count(), 2);
    assert!(res.iter().all(|(_, t)| t != "abc"));
}

#[test]
fn string_scanner_unterminated_not_returned() {
    let s = StringXrefScanner::new(3);
    // No NUL terminator -> nothing recorded.
    let res = s.scan_ascii(a(0), b"hello");
    assert!(res.is_empty());
}

#[test]
fn string_scanner_utf16_disabled_returns_empty() {
    let s = StringXrefScanner::new(2);
    // UTF-16LE "hi": 68 00 69 00 00 00
    let data = [0x68u8, 0, 0x69, 0, 0, 0];
    assert!(s.scan_utf16le(a(0), &data).is_empty());
}

#[test]
fn string_scanner_utf16_enabled_finds_string() {
    let s = StringXrefScanner::new(2).with_utf16();
    let data = [0x68u8, 0, 0x69, 0, 0, 0];
    let res = s.scan_utf16le(a(0x1000), &data);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].1, "hi");
}

// ---------------------------------------------------------------------------
// ImportXrefScanner
// ---------------------------------------------------------------------------

#[test]
fn import_scanner_iat_skips_zero_slots() {
    let scanner = ImportXrefScanner::new(a(0x9000), 8);
    let mut db = XrefDatabase::new();
    let mut bytes = vec![0u8; 24];
    // slot 1 (offset 8) = 0xDEADBEEF
    bytes[8..16].copy_from_slice(&0xDEADBEEFu64.to_le_bytes());
    scanner.scan_iat(&bytes, &mut db);
    assert_eq!(db.total_count(), 1);
    let xrefs = db.xrefs_from(a(0x9008));
    assert_eq!(xrefs[0].to, a(0xDEADBEEF));
}

#[test]
fn import_scanner_iat_zero_step_no_panic() {
    let scanner = ImportXrefScanner::new(a(0x9000), 0);
    let mut db = XrefDatabase::new();
    scanner.scan_iat(&[1, 2, 3, 4], &mut db);
    assert!(db.is_empty());
}

#[test]
fn import_scanner_records_named_and_ordinal() {
    let scanner = ImportXrefScanner::new(a(0x9000), 8);
    let mut db = XrefDatabase::new();
    scanner.record_named_import(&mut db, a(0x9000), a(0xA000), "GetProcAddress");
    scanner.record_ordinal_import(&mut db, a(0x9008), a(0xA100), 17);
    assert_eq!(db.xrefs_to_import("GetProcAddress").len(), 1);
    assert_eq!(db.xrefs_to_import("17").len(), 1);
}

// ---------------------------------------------------------------------------
// XrefGrouper
// ---------------------------------------------------------------------------

#[test]
fn grouper_before_first_returns_none() {
    let g = XrefGrouper::new(vec![a(0x1000), a(0x2000)]);
    assert!(g.enclosing_function(a(0x500)).is_none());
}

#[test]
fn grouper_exact_match_returns_self() {
    let g = XrefGrouper::new(vec![a(0x1000), a(0x2000)]);
    assert_eq!(g.enclosing_function(a(0x1000)), Some(a(0x1000)));
    assert_eq!(g.enclosing_function(a(0x2000)), Some(a(0x2000)));
}

#[test]
fn grouper_group_by_function_buckets_correctly() {
    let mut db = XrefDatabase::new();
    db.add_call(a(0x1010), a(0x9000), 5);
    db.add_call(a(0x1020), a(0x9000), 5);
    db.add_call(a(0x2010), a(0x9000), 5);
    let g = XrefGrouper::new(vec![a(0x1000), a(0x2000)]);
    let groups = g.group_by_function(&db);
    assert_eq!(groups[&a(0x1000)].len(), 2);
    assert_eq!(groups[&a(0x2000)].len(), 1);
}

#[test]
fn grouper_unsorted_input_still_correct() {
    // Constructor should sort.
    let g = XrefGrouper::new(vec![a(0x2000), a(0x1000), a(0x3000)]);
    assert_eq!(g.enclosing_function(a(0x1500)), Some(a(0x1000)));
    assert_eq!(g.enclosing_function(a(0x2500)), Some(a(0x2000)));
    assert_eq!(g.enclosing_function(a(0x3500)), Some(a(0x3000)));
}

// ---------------------------------------------------------------------------
// BinaryXrefIndex
// ---------------------------------------------------------------------------

#[test]
fn binary_index_build_from_empty() {
    let idx = BinaryXrefIndex::build_from_binary(&[], 0x1000, "x86_64");
    assert!(idx.is_empty());
    assert_eq!(idx.total(), 0);
}

#[test]
fn binary_index_e8_call_decodes_target() {
    // E8 rel32: at base 0x1000, rel = 0x100 -> target = 0x1000 + 5 + 0x100 = 0x1105
    let mut bytes = vec![0xE8u8, 0, 0, 0, 0];
    bytes[1..5].copy_from_slice(&0x100i32.to_le_bytes());
    let idx = BinaryXrefIndex::build_from_binary(&bytes, 0x1000, "x86_64");
    let from = idx.xrefs_from(0x1000);
    assert_eq!(from.len(), 1);
    assert_eq!(from[0].kind, SimpleXrefKind::Call);
    assert_eq!(from[0].to, 0x1105);
}

#[test]
fn binary_index_indirect_call_uses_target_zero() {
    // FF /2 (CALL r/m) — modrm = 0x15 (mod=00 reg=2 rm=5)
    let bytes = [0xFFu8, 0x15, 0, 0, 0, 0];
    let idx = BinaryXrefIndex::build_from_binary(&bytes, 0x1000, "x86_64");
    let from = idx.xrefs_from(0x1000);
    assert_eq!(from.len(), 1);
    assert_eq!(from[0].kind, SimpleXrefKind::Call);
    assert_eq!(from[0].to, 0);
}

#[test]
fn binary_index_truncated_e8_does_not_panic() {
    // E8 with fewer than 4 displacement bytes — guarded by `start + 4 < len`.
    let bytes = [0xE8u8, 0, 0];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        BinaryXrefIndex::build_from_binary(&bytes, 0x1000, "x86_64")
    }));
    assert!(result.is_ok());
}

#[test]
fn binary_index_hot_call_targets_orders_by_count() {
    let mut idx = BinaryXrefIndex::new();
    idx.add_call(0x1, 0x100, 5);
    idx.add_call(0x2, 0x100, 5);
    idx.add_call(0x3, 0x100, 5);
    idx.add_call(0x4, 0x200, 5);
    let hot = idx.hot_call_targets(2);
    assert_eq!(hot.len(), 2);
    assert_eq!(hot[0].0, 0x100);
    assert_eq!(hot[0].1, 3);
    assert_eq!(hot[1].0, 0x200);
}

#[test]
fn binary_index_is_leaf_only_considers_outgoing_calls() {
    let mut idx = BinaryXrefIndex::new();
    idx.add_jump(0x1000, 0x2000, 5);
    // No CALL out -> leaf.
    assert!(idx.is_leaf(0x1000));
    idx.add_call(0x1000, 0x3000, 5);
    assert!(!idx.is_leaf(0x1000));
}

#[test]
fn binary_index_data_refs_to_filters_kinds() {
    let mut idx = BinaryXrefIndex::new();
    idx.add_data_read(1, 0x100);
    idx.add_data_write(2, 0x100);
    idx.add_data_addr(3, 0x100);
    idx.add_call(4, 0x100, 5);
    let refs = idx.data_refs_to(0x100);
    assert_eq!(refs.len(), 3);
    assert!(!refs.contains(&4));
}

#[test]
fn binary_index_count_kind() {
    let mut idx = BinaryXrefIndex::new();
    idx.add_call(1, 2, 5);
    idx.add_call(3, 4, 5);
    idx.add_jump(5, 6, 2);
    assert_eq!(idx.count_kind(SimpleXrefKind::Call), 2);
    assert_eq!(idx.count_kind(SimpleXrefKind::Jump), 1);
    assert_eq!(idx.count_kind(SimpleXrefKind::DataRead), 0);
}

// ---------------------------------------------------------------------------
// XrefSummary
// ---------------------------------------------------------------------------

#[test]
fn summary_unreferenced_address() {
    let db = XrefDatabase::new();
    let s = XrefSummary::compute(&db, a(0x1000));
    assert!(s.is_unreferenced());
    assert!(!s.is_function_entry());
}

#[test]
fn summary_counts_imports_and_strings_in() {
    let mut db = XrefDatabase::new();
    db.add_import_by_name(a(0x1000), a(0x5000), "X");
    db.add_string_ref(a(0x1010), a(0x5000), "msg");
    db.add_type_ref(a(0x1020), a(0x5000), "T");
    let s = XrefSummary::compute(&db, a(0x5000));
    assert_eq!(s.import_in, 1);
    assert_eq!(s.string_in, 1);
    assert_eq!(s.type_in, 1);
}

// ---------------------------------------------------------------------------
// XrefStats report formatting
// ---------------------------------------------------------------------------

#[test]
fn stats_format_report_runs_without_panic() {
    let mut db = XrefDatabase::new();
    db.add_call(a(1), a(2), 5);
    db.add_string_ref(a(3), a(4), "x");
    let stats = XrefStats::compute(&db);
    let report = stats.format_report();
    assert!(report.contains("Total xrefs"));
    assert!(report.contains("CodeCall"));
}

// ---------------------------------------------------------------------------
// XrefRecoveryPass: Send/Sync + default
// ---------------------------------------------------------------------------

#[test]
fn xref_recovery_pass_default_is_empty() {
    let pass = XrefRecoveryPass::default();
    assert!(pass.index().is_empty());
}

#[test]
fn xref_recovery_pass_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<XrefRecoveryPass>();
}
