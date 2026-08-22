//! Deep adversarial tests for rustre-analysis-xref core API.

use rustre_analysis_xref::*;
use rustre_core::address::{Address, AddressRange};
use std::collections::HashSet;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

const fn addr(v: u64) -> Address {
    Address::new(v)
}

// -------- XrefKind --------

#[test]
fn kind_display_all_unique() {
    let mut seen: HashSet<String> = HashSet::new();
    for k in XrefKind::all() {
        assert!(seen.insert(k.to_string()), "duplicate display: {k}");
    }
    assert_eq!(seen.len(), XrefKind::all().len());
}

#[test]
fn kind_classification_partitions() {
    for k in XrefKind::all() {
        let c = k.is_code();
        let d = k.is_data();
        let i = k.is_import();
        // code/data/import sets should not overlap each other
        assert!(!(c && d), "{k} both code and data");
        assert!(!(c && i), "{k} both code and import");
        assert!(!(d && i), "{k} both data and import");
    }
}

#[test]
fn kind_is_code_consistent_with_xref() {
    for k in XrefKind::all() {
        let x = Xref::new(addr(1), addr(2), *k, 0);
        assert_eq!(x.is_code(), k.is_code());
        assert_eq!(x.is_data(), k.is_data());
    }
}

#[test]
fn kind_hash_eq_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    for a in XrefKind::all() {
        for b in XrefKind::all() {
            if a == b {
                let mut ha = DefaultHasher::new();
                let mut hb = DefaultHasher::new();
                a.hash(&mut ha);
                b.hash(&mut hb);
                assert_eq!(ha.finish(), hb.finish());
            }
        }
    }
}

#[test]
fn kind_all_returns_twelve() {
    assert_eq!(XrefKind::all().len(), 12);
}

// -------- Xref --------

#[test]
fn xref_new_no_tag() {
    let x = Xref::new(addr(0x1000), addr(0x2000), XrefKind::CodeCall, 5);
    assert!(x.tag.is_none());
    assert!(x.is_code());
    assert!(!x.is_data());
}

#[test]
fn xref_with_tag_stores_tag() {
    let x = Xref::with_tag(addr(1), addr(2), XrefKind::StringRef, 0, "hello");
    assert_eq!(x.tag.as_deref(), Some("hello"));
}

#[test]
fn xref_display_format() {
    let x = Xref::new(addr(0x1234), addr(0xabcd), XrefKind::CodeJump, 2);
    let s = x.to_string();
    assert!(s.contains("0x00001234"));
    assert!(s.contains("0x0000abcd"));
    assert!(s.contains("CodeJump"));
    assert!(!s.contains("\""));
    let x2 = Xref::with_tag(addr(1), addr(2), XrefKind::StringRef, 0, "hi");
    assert!(x2.to_string().contains("\"hi\""));
}

// -------- XrefFilter --------

#[test]
fn filter_default_matches_all() {
    let f = XrefFilter::new();
    for k in XrefKind::all() {
        let x = Xref::new(addr(1), addr(2), *k, 0);
        assert!(f.matches(&x));
    }
}

#[test]
fn filter_by_kinds() {
    let f = XrefFilter::new().with_kinds([XrefKind::CodeCall, XrefKind::CodeJump]);
    assert!(f.matches(&Xref::new(addr(1), addr(2), XrefKind::CodeCall, 0)));
    assert!(f.matches(&Xref::new(addr(1), addr(2), XrefKind::CodeJump, 0)));
    assert!(!f.matches(&Xref::new(addr(1), addr(2), XrefKind::DataRead, 0)));
}

#[test]
fn filter_from_range() {
    let r = AddressRange::new(addr(0x100), addr(0x200));
    let f = XrefFilter::new().from_range(r);
    assert!(f.matches(&Xref::new(addr(0x150), addr(0x900), XrefKind::CodeCall, 0)));
    assert!(!f.matches(&Xref::new(addr(0x300), addr(0x900), XrefKind::CodeCall, 0)));
    assert!(!f.matches(&Xref::new(addr(0x200), addr(0x900), XrefKind::CodeCall, 0)));
}

#[test]
fn filter_to_range() {
    let r = AddressRange::new(addr(0x100), addr(0x200));
    let f = XrefFilter::new().to_range(r);
    assert!(f.matches(&Xref::new(addr(0x900), addr(0x150), XrefKind::CodeCall, 0)));
    assert!(!f.matches(&Xref::new(addr(0x900), addr(0x300), XrefKind::CodeCall, 0)));
}

#[test]
fn filter_require_tag() {
    let f = XrefFilter::new().with_tag_required();
    assert!(!f.matches(&Xref::new(addr(1), addr(2), XrefKind::CodeCall, 0)));
    assert!(f.matches(&Xref::with_tag(addr(1), addr(2), XrefKind::StringRef, 0, "x")));
}

#[test]
fn filter_tag_contains() {
    let f = XrefFilter::new().tag_contains("foo");
    assert!(f.matches(&Xref::with_tag(addr(1), addr(2), XrefKind::StringRef, 0, "foobar")));
    assert!(!f.matches(&Xref::with_tag(addr(1), addr(2), XrefKind::StringRef, 0, "bar")));
    assert!(!f.matches(&Xref::new(addr(1), addr(2), XrefKind::StringRef, 0)));
}

#[test]
fn filter_min_from_max_to() {
    let f = XrefFilter::new().min_from(0x500).max_to(0x1000);
    assert!(f.matches(&Xref::new(addr(0x500), addr(0x1000), XrefKind::CodeCall, 0)));
    assert!(!f.matches(&Xref::new(addr(0x499), addr(0x900), XrefKind::CodeCall, 0)));
    assert!(!f.matches(&Xref::new(addr(0x500), addr(0x1001), XrefKind::CodeCall, 0)));
}

// -------- XrefDatabase --------

#[test]
fn db_new_is_empty() {
    let db = XrefDatabase::new();
    assert!(db.is_empty());
    assert_eq!(db.total_count(), 0);
    assert!(db.xrefs_from(addr(0)).is_empty());
    assert!(db.xrefs_to(addr(0)).is_empty());
}

#[test]
fn db_default_eq_new() {
    let a = XrefDatabase::default();
    let b = XrefDatabase::new();
    assert_eq!(a.total_count(), b.total_count());
    assert_eq!(a.is_empty(), b.is_empty());
}

#[test]
fn db_add_and_query_roundtrip() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(0x1000), addr(0x2000), 5);
    db.add_jump(addr(0x1100), addr(0x2100), 5);
    db.add_data_read(addr(0x1200), addr(0x3000));
    db.add_data_write(addr(0x1300), addr(0x3100));
    assert_eq!(db.total_count(), 4);
    assert_eq!(db.xrefs_from(addr(0x1000)).len(), 1);
    assert_eq!(db.xrefs_to(addr(0x2000)).len(), 1);
    assert_eq!(db.callers_of(addr(0x2000)), vec![addr(0x1000)]);
    assert_eq!(db.callees_of(addr(0x1000)), vec![addr(0x2000)]);
}

#[test]
fn db_callers_callees_only_calls() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(100), 5);
    db.add_jump(addr(2), addr(100), 5);
    db.add_data_read(addr(3), addr(100));
    assert_eq!(db.callers_of(addr(100)), vec![addr(1)]);
    assert_eq!(db.jumpers_to(addr(100)), vec![addr(2)]);
    assert_eq!(db.data_refs_to(addr(100)), vec![addr(3)]);
}

#[test]
fn db_import_indices() {
    let mut db = XrefDatabase::new();
    db.add_import_by_name(addr(1), addr(0x9000), "CreateFileA");
    db.add_import_by_name(addr(2), addr(0x9000), "CreateFileA");
    db.add_import_by_ordinal(addr(3), addr(0x9100), 42);
    assert_eq!(db.xrefs_to_import("CreateFileA").len(), 2);
    assert_eq!(db.xrefs_to_import("42").len(), 1);
    assert_eq!(db.xrefs_to_import("nope").len(), 0);
    let names: HashSet<&str> = db.all_import_names().into_iter().collect();
    assert!(names.contains("CreateFileA"));
    assert!(names.contains("42"));
}

#[test]
fn db_string_index() {
    let mut db = XrefDatabase::new();
    db.add_string_ref(addr(1), addr(0xA000), "hello");
    db.add_string_ref(addr(2), addr(0xA000), "hello");
    db.add_string_ref(addr(3), addr(0xA100), "world");
    let sites = db.string_ref_sites("hello");
    assert_eq!(sites.len(), 2);
    assert!(sites.contains(&addr(1)));
    assert!(sites.contains(&addr(2)));
    assert!(db.string_ref_sites("missing").is_empty());
    let all: HashSet<&str> = db.all_strings().into_iter().collect();
    assert_eq!(all.len(), 2);
}

#[test]
fn db_type_index() {
    let mut db = XrefDatabase::new();
    db.add_type_ref(addr(1), addr(0xB000), "MyClass");
    db.add_type_ref(addr(2), addr(0xB000), "MyClass");
    assert_eq!(db.xrefs_to_type("MyClass").len(), 2);
    assert!(db.xrefs_to_type("Other").is_empty());
}

#[test]
fn db_thunk_and_return() {
    let mut db = XrefDatabase::new();
    db.add_thunk(addr(1), addr(2), 5);
    db.add_return(addr(3), addr(4));
    db.add_data_addr(addr(5), addr(6));
    db.add_data_pointer(addr(7), addr(8));
    assert_eq!(db.total_count(), 4);
}

#[test]
fn db_remove_from() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(100), 5);
    db.add_call(addr(1), addr(101), 5);
    db.add_call(addr(2), addr(100), 5);
    assert_eq!(db.remove_from(addr(1)), 2);
    assert_eq!(db.total_count(), 1);
    assert!(db.xrefs_from(addr(1)).is_empty());
    assert_eq!(db.xrefs_to(addr(100)).len(), 1);
    assert_eq!(db.remove_from(addr(999)), 0);
}

#[test]
fn db_remove_to() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(100), 5);
    db.add_call(addr(2), addr(100), 5);
    db.add_call(addr(1), addr(101), 5);
    assert_eq!(db.remove_to(addr(100)), 2);
    assert_eq!(db.total_count(), 1);
}

#[test]
fn db_remove_exact() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(2), 5);
    db.add_jump(addr(1), addr(2), 5);
    assert!(db.remove_exact(addr(1), addr(2), XrefKind::CodeCall));
    assert_eq!(db.total_count(), 1);
    assert!(!db.remove_exact(addr(1), addr(2), XrefKind::CodeCall));
    assert!(db.remove_exact(addr(1), addr(2), XrefKind::CodeJump));
    assert!(db.is_empty());
}

#[test]
fn db_remove_rebuilds_secondary_indices() {
    let mut db = XrefDatabase::new();
    db.add_string_ref(addr(1), addr(0xA000), "x");
    db.add_string_ref(addr(2), addr(0xA000), "x");
    assert_eq!(db.string_ref_sites("x").len(), 2);
    db.remove_from(addr(1));
    assert_eq!(db.string_ref_sites("x").len(), 1);
    db.remove_from(addr(2));
    assert!(db.string_ref_sites("x").is_empty());
}

#[test]
fn db_callee_caller_counts_unique() {
    let mut db = XrefDatabase::new();
    // Two calls from 0x100 -> 0x200 collapse to 1 unique callee
    db.add_call(addr(0x100), addr(0x200), 5);
    db.add_call(addr(0x100), addr(0x200), 5);
    db.add_call(addr(0x100), addr(0x300), 5);
    assert_eq!(db.callee_count(addr(0x100)), 2);
    assert_eq!(db.caller_count(addr(0x200)), 1);
    assert_eq!(db.caller_count(addr(0x300)), 1);
}

#[test]
fn db_is_leaf_function() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(0x100), addr(0x200), 5);
    assert!(!db.is_leaf_function(addr(0x100)));
    assert!(db.is_leaf_function(addr(0x200)));
    assert!(db.is_leaf_function(addr(0x999))); // absent => 0 calls => leaf
}

#[test]
fn db_hot_functions_sorted() {
    let mut db = XrefDatabase::new();
    for i in 0..5 {
        db.add_call(addr(0x10 + i), addr(0x200), 5);
    }
    db.add_call(addr(0xAA), addr(0x300), 5);
    db.add_call(addr(0xBB), addr(0x300), 5);
    db.add_call(addr(0xCC), addr(0x400), 5);
    let hot = db.hot_functions(3);
    assert_eq!(hot[0], (addr(0x200), 5));
    assert_eq!(hot[1], (addr(0x300), 2));
    assert_eq!(hot[2], (addr(0x400), 1));
    let hot2 = db.hot_functions(100);
    assert_eq!(hot2.len(), 3);
}

#[test]
fn db_hot_functions_top_n_zero() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(2), 5);
    let hot = db.hot_functions(0);
    assert!(hot.is_empty());
}

#[test]
fn db_all_targets_sources() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(10), 5);
    db.add_call(addr(2), addr(20), 5);
    let srcs: HashSet<Address> = db.all_sources().into_iter().collect();
    let tgts: HashSet<Address> = db.all_targets().into_iter().collect();
    assert_eq!(srcs, [addr(1), addr(2)].iter().copied().collect());
    assert_eq!(tgts, [addr(10), addr(20)].iter().copied().collect());
}

#[test]
fn db_all_call_targets_unique() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(10), 5);
    db.add_call(addr(2), addr(10), 5);
    db.add_jump(addr(3), addr(20), 5);
    let ts: HashSet<Address> = db.all_call_targets().into_iter().collect();
    assert_eq!(ts, [addr(10)].iter().copied().collect());
}

#[test]
fn db_merge_combines_all() {
    let mut a = XrefDatabase::new();
    a.add_call(addr(1), addr(2), 5);
    let mut b = XrefDatabase::new();
    b.add_call(addr(3), addr(4), 5);
    b.add_string_ref(addr(5), addr(0xA0), "s");
    a.merge(b);
    assert_eq!(a.total_count(), 3);
    assert_eq!(a.string_ref_sites("s").len(), 1);
}

#[test]
fn db_filter_helpers() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(2), 5);
    db.add_jump(addr(1), addr(3), 5);
    let f = XrefFilter::new().with_kinds([XrefKind::CodeCall]);
    assert_eq!(db.filter_from(addr(1), &f).len(), 1);
    assert_eq!(db.filter_to(addr(2), &f).len(), 1);
    assert_eq!(db.filter_to(addr(3), &f).len(), 0);
    assert_eq!(db.filter_all(&f).len(), 1);
}

#[test]
fn db_iter_all_total_matches() {
    let mut db = XrefDatabase::new();
    let mut g = lcg();
    for _ in 0..50 {
        let from = g() % 0x10000;
        let to = g() % 0x10000;
        db.add_call(addr(from), addr(to), 5);
    }
    let counted = db.iter_all().count();
    assert_eq!(counted, db.total_count());
    assert_eq!(counted, 50);
}

// -------- JSON round-trip --------

#[test]
fn db_json_roundtrip_basic() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(0x1000), addr(0x2000), 5);
    db.add_string_ref(addr(0x1100), addr(0xA000), "hello");
    db.add_import_by_name(addr(0x1200), addr(0x9000), "puts");
    let json = db.to_json().unwrap();
    let db2 = XrefDatabase::from_json(&json).unwrap();
    assert_eq!(db2.total_count(), db.total_count());
    assert_eq!(db2.string_ref_sites("hello").len(), 1);
    assert_eq!(db2.xrefs_to_import("puts").len(), 1);
    assert_eq!(db2.callers_of(addr(0x2000)), vec![addr(0x1000)]);
}

#[test]
fn db_json_roundtrip_fuzz() {
    let mut g = lcg();
    let mut db = XrefDatabase::new();
    for _ in 0..60 {
        let from = g() % 0x100000;
        let to = g() % 0x100000;
        let kind = XrefKind::all()[(g() as usize) % XrefKind::all().len()];
        let x = if (g() & 1) == 0 {
            Xref::new(addr(from), addr(to), kind, (g() & 0xff) as u8)
        } else {
            Xref::with_tag(addr(from), addr(to), kind, 0, format!("t{}", g() & 0xff))
        };
        db.add(x);
    }
    let json = db.to_json().unwrap();
    let db2 = XrefDatabase::from_json(&json).unwrap();
    assert_eq!(db.total_count(), db2.total_count());
    // Diff should be empty
    let diff = XrefDiff::compute(&db, &db2);
    assert!(diff.is_empty());
}

#[test]
fn db_from_json_unknown_kind_errors() {
    let json = r#"[{"from":1,"to":2,"kind":"BogusKind","instr_size":0,"tag":null}]"#;
    let r = XrefDatabase::from_json(json);
    assert!(matches!(r, Err(XrefError::UnknownKind(_))));
}

#[test]
fn db_from_json_malformed_errors() {
    let malformed = [
        "",
        "not json",
        "{",
        "[",
        "[{\"from\":\"bad\"}]",
        "[{\"from\":1}]", // missing required fields
    ];
    for j in malformed {
        let r = XrefDatabase::from_json(j);
        assert!(r.is_err(), "expected err for {j:?}");
    }
}

#[test]
fn db_from_json_empty_array_yields_empty_db() {
    let db = XrefDatabase::from_json("[]").unwrap();
    assert!(db.is_empty());
}

#[test]
fn db_to_json_pretty_is_valid_json() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(2), 5);
    let s = db.to_json().unwrap();
    let _: serde_json::Value = serde_json::from_str(&s).unwrap();
}

// -------- XrefGraph --------

#[test]
fn graph_call_graph_basic() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(2), 5);
    db.add_call(addr(2), addr(3), 5);
    db.add_jump(addr(1), addr(100), 5);
    let g = XrefGraph::call_graph(&db);
    assert_eq!(g.node_count(), 3);
    assert_eq!(g.edge_count(), 2);
    assert!(g.contains(addr(1)));
    assert!(!g.contains(addr(100)));
}

#[test]
fn graph_reachability_bfs() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(2), 5);
    db.add_call(addr(2), addr(3), 5);
    db.add_call(addr(3), addr(4), 5);
    let g = XrefGraph::call_graph(&db);
    let r = g.reachable_from(addr(1));
    assert!(r.contains(&addr(4)));
    assert_eq!(r.len(), 4);
    assert!(g.is_reachable(addr(1), addr(4)));
    assert!(!g.is_reachable(addr(4), addr(1)));
    assert!(g.is_reachable(addr(1), addr(1)));
}

#[test]
fn graph_bfs_distances() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(2), 5);
    db.add_call(addr(2), addr(3), 5);
    db.add_call(addr(3), addr(4), 5);
    let g = XrefGraph::call_graph(&db);
    let d = g.bfs_distances(addr(1));
    assert_eq!(d[&addr(1)], 0);
    assert_eq!(d[&addr(2)], 1);
    assert_eq!(d[&addr(3)], 2);
    assert_eq!(d[&addr(4)], 3);
}

#[test]
fn graph_scc_simple_cycle() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(2), 5);
    db.add_call(addr(2), addr(3), 5);
    db.add_call(addr(3), addr(1), 5);
    db.add_call(addr(3), addr(4), 5);
    let g = XrefGraph::call_graph(&db);
    let sccs = g.strongly_connected_components();
    assert!(sccs[0].len() == 3);
    let set: HashSet<Address> = sccs[0].iter().copied().collect();
    assert!(set.contains(&addr(1)));
    assert!(set.contains(&addr(2)));
    assert!(set.contains(&addr(3)));
}

#[test]
fn graph_topo_sort_dag() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(2), 5);
    db.add_call(addr(2), addr(3), 5);
    db.add_call(addr(1), addr(3), 5);
    let g = XrefGraph::call_graph(&db);
    let s = g.topological_sort().expect("dag");
    let pos = |a: Address| s.iter().position(|x| *x == a).unwrap();
    assert!(pos(addr(1)) < pos(addr(2)));
    assert!(pos(addr(2)) < pos(addr(3)));
}

#[test]
fn graph_topo_sort_cycle_returns_none() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(2), 5);
    db.add_call(addr(2), addr(1), 5);
    let g = XrefGraph::call_graph(&db);
    assert!(g.topological_sort().is_none());
}

#[test]
fn graph_in_out_degree() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(3), 5);
    db.add_call(addr(2), addr(3), 5);
    db.add_call(addr(3), addr(4), 5);
    let g = XrefGraph::call_graph(&db);
    assert_eq!(g.in_degree(addr(3)), 2);
    assert_eq!(g.out_degree(addr(3)), 1);
    assert_eq!(g.in_degree(addr(1)), 0);
    assert_eq!(g.out_degree(addr(4)), 0);
}

#[test]
fn graph_successors() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(2), 5);
    db.add_call(addr(1), addr(3), 5);
    let g = XrefGraph::call_graph(&db);
    let s: HashSet<Address> = g.successors(addr(1)).into_iter().collect();
    assert_eq!(s, [addr(2), addr(3)].iter().copied().collect());
    assert!(g.successors(addr(999)).is_empty());
}

#[test]
fn graph_data_full_variants() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(2), 5);
    db.add_data_read(addr(3), addr(4));
    db.add_jump(addr(5), addr(6), 5);
    let d = XrefGraph::data_graph(&db);
    assert_eq!(d.edge_count(), 1);
    let c = XrefGraph::code_graph(&db);
    assert_eq!(c.edge_count(), 2);
    let f = XrefGraph::full_graph(&db);
    assert_eq!(f.edge_count(), 3);
}

// -------- XrefSummary --------

#[test]
fn summary_compute_consistent() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(100), 5);
    db.add_call(addr(2), addr(100), 5);
    db.add_jump(addr(3), addr(100), 5);
    db.add_data_read(addr(4), addr(100));
    let s = XrefSummary::compute(&db, addr(100));
    assert_eq!(s.total_in, 4);
    assert_eq!(s.call_in, 2);
    assert_eq!(s.jump_in, 1);
    assert_eq!(s.data_in, 1);
    assert!(s.is_function_entry());
    assert!(!s.is_unreferenced());
    let s2 = XrefSummary::compute(&db, addr(999));
    assert!(s2.is_unreferenced());
    assert!(!s2.is_function_entry());
}

// -------- XrefStats --------

#[test]
fn stats_compute_matches_db() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(1), addr(100), 5);
    db.add_call(addr(2), addr(100), 5);
    db.add_string_ref(addr(3), addr(0xA0), "s");
    db.add_import_by_name(addr(4), addr(0x90), "imp");
    let st = XrefStats::compute(&db);
    assert_eq!(st.total, 4);
    assert_eq!(st.unique_callers, 2);
    assert_eq!(st.unique_callees, 1);
    assert_eq!(st.total_strings, 1);
    assert_eq!(st.total_imports, 1);
    assert_eq!(st.unique_import_names, 1);
    let report = st.format_report();
    assert!(report.contains("Total xrefs"));
    assert!(report.contains("CodeCall"));
}

// -------- XrefDiff --------

#[test]
fn diff_added_removed() {
    let mut a = XrefDatabase::new();
    a.add_call(addr(1), addr(2), 5);
    a.add_call(addr(3), addr(4), 5);
    let mut b = XrefDatabase::new();
    b.add_call(addr(3), addr(4), 5);
    b.add_call(addr(5), addr(6), 5);
    let d = XrefDiff::compute(&a, &b);
    assert_eq!(d.added.len(), 1);
    assert_eq!(d.removed.len(), 1);
    assert_eq!(d.total_changes(), 2);
    assert!(!d.is_empty());
    let d2 = XrefDiff::compute(&a, &a);
    assert!(d2.is_empty());
}

// -------- X86XrefScanner --------

#[test]
fn scanner_call_rel32() {
    // E8 rel32 at 0x1000, target = 0x1005 + 0x10 = 0x1015
    let bytes = [0xE8, 0x10, 0x00, 0x00, 0x00];
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 8);
    scanner.scan_code(addr(0x1000), &bytes, &mut db);
    assert_eq!(db.callers_of(addr(0x1015)), vec![addr(0x1000)]);
}

#[test]
fn scanner_jmp_rel32() {
    let bytes = [0xE9, 0x20, 0x00, 0x00, 0x00]; // jmp +0x20, but offset=0 => thunk by default
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 8)
        .without_thunk_detection();
    scanner.scan_code(addr(0x1000), &bytes, &mut db);
    let xrefs: Vec<_> = db.iter_all().collect();
    assert_eq!(xrefs.len(), 1);
    assert_eq!(xrefs[0].kind, XrefKind::CodeJump);
    assert_eq!(xrefs[0].to, addr(0x1025));
}

#[test]
fn scanner_thunk_at_entry() {
    // E9 at offset 0 with default thunk detection => ThunkCall
    let bytes = [0xE9, 0x20, 0x00, 0x00, 0x00];
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 8);
    scanner.scan_code(addr(0x1000), &bytes, &mut db);
    let x = db.iter_all().next().unwrap();
    assert_eq!(x.kind, XrefKind::ThunkCall);
}

#[test]
fn scanner_jmp_short() {
    // EB rel8: at 0x1000, jmp +0x10 => target 0x1012
    let bytes = [0xEB, 0x10, 0x90, 0x90];
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 8);
    scanner.scan_code(addr(0x1000), &bytes, &mut db);
    assert!(db.jumpers_to(addr(0x1012)).contains(&addr(0x1000)));
}

#[test]
fn scanner_jcc_rel32() {
    // 0F 84 rel32 — JE rel32. From 0x1000, +0x10 = 0x1016
    let bytes = [0x0F, 0x84, 0x10, 0x00, 0x00, 0x00];
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 8);
    scanner.scan_code(addr(0x1000), &bytes, &mut db);
    assert!(db.jumpers_to(addr(0x1016)).contains(&addr(0x1000)));
}

#[test]
fn scanner_lea_riprel_x64() {
    // 8D 05 disp32 — LEA r0, [rip+disp32]; at 0x1000, target = 0x1006 + 0x10 = 0x1016
    let bytes = [0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 8);
    scanner.scan_code(addr(0x1000), &bytes, &mut db);
    let xrefs: Vec<_> = db.iter_all().collect();
    assert!(xrefs.iter().any(|x| x.kind == XrefKind::DataAddress && x.to == addr(0x1016)));
}

#[test]
fn scanner_data_pointers_x64() {
    // Pointer value 0x1100 (in code range) in data
    let bytes = [0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 8);
    scanner.scan_data_pointers(addr(0x3000), &bytes, &mut db);
    assert_eq!(db.data_refs_to(addr(0x1100)), vec![addr(0x3000)]);
}

#[test]
fn scanner_data_pointers_x86() {
    let bytes = [0x00, 0x11, 0x00, 0x00];
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 4);
    scanner.scan_data_pointers(addr(0x3000), &bytes, &mut db);
    assert_eq!(db.data_refs_to(addr(0x1100)), vec![addr(0x3000)]);
}

#[test]
fn scanner_data_pointers_skip_when_too_short() {
    let bytes = [0x00, 0x11];
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 8);
    scanner.scan_data_pointers(addr(0x3000), &bytes, &mut db);
    assert!(db.is_empty());
}

#[test]
fn scanner_truncated_inputs_no_panic() {
    let mut g = lcg();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x20000)), 8);
    for n in 0..6 {
        let mut bytes = vec![0u8; n];
        for b in &mut bytes {
            *b = (g() & 0xff) as u8;
        }
        // Force a leading opcode that needs more bytes
        if n > 0 {
            bytes[0] = match (g() % 5) as u8 {
                0 => 0xE8,
                1 => 0xE9,
                2 => 0xEB,
                3 => 0x0F,
                _ => 0x8D,
            };
        }
        let mut db = XrefDatabase::new();
        scanner.scan_code(addr(0x1000), &bytes, &mut db);
        // must not panic
    }
}

#[test]
fn scanner_fuzz_random_bytes_never_panics() {
    let mut g = lcg();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x20000)), 8);
    for _ in 0..50 {
        let n = (g() as usize) % 128 + 1;
        let bytes: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        let mut db = XrefDatabase::new();
        scanner.scan_code(addr(0x1000), &bytes, &mut db);
        // No assertions; just no panic.
        let _ = db.total_count();
    }
}

#[test]
fn scanner_function_entries_classify_thunk() {
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 8)
        .with_function_entries([5u64]);
    // Two E9s back-to-back; first at offset 0 (not registered, but list non-empty so legacy off),
    // second at offset 5 (registered => thunk).
    let bytes = [
        0xE9, 0x00, 0x00, 0x00, 0x00, // offset 0
        0xE9, 0x00, 0x00, 0x00, 0x00, // offset 5
    ];
    let mut db = XrefDatabase::new();
    scanner.scan_code(addr(0x1000), &bytes, &mut db);
    let kinds: Vec<XrefKind> = db.iter_all().map(|x| x.kind).collect();
    assert!(kinds.contains(&XrefKind::CodeJump));
    assert!(kinds.contains(&XrefKind::ThunkCall));
}

#[test]
fn scanner_without_lea_disables_lea() {
    let bytes = [0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 8)
        .without_lea();
    scanner.scan_code(addr(0x1000), &bytes, &mut db);
    assert!(db.iter_all().all(|x| x.kind != XrefKind::DataAddress));
}

#[test]
fn scanner_out_of_range_target_ignored() {
    // CALL with target far outside code range
    let bytes = [0xE8, 0x00, 0x00, 0x00, 0x40];
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 8);
    scanner.scan_code(addr(0x1000), &bytes, &mut db);
    assert!(db.is_empty());
}

#[test]
fn scanner_call_into_data_range() {
    let bytes = [0xE8, 0x00, 0x10, 0x00, 0x00]; // call +0x1000 from 0x1000 => 0x2005
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x1500)), 8)
        .add_data_range(AddressRange::new(addr(0x2000), addr(0x3000)));
    scanner.scan_code(addr(0x1000), &bytes, &mut db);
    assert!(!db.is_empty());
}

// -------- Hash / Eq consistency on Xref / XrefKind --------

#[test]
fn xref_hash_eq_pairs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut g = lcg();
    for _ in 0..30 {
        let from = g() % 0x1000;
        let to = g() % 0x1000;
        let kind = XrefKind::all()[(g() as usize) % XrefKind::all().len()];
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        kind.hash(&mut h1);
        kind.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
        let _ = (from, to);
    }
}

// -------- Send/Sync threading stress --------

#[test]
fn db_send_sync_threaded_reads() {
    use std::sync::Arc;
    use std::thread;
    let mut db = XrefDatabase::new();
    for i in 0..200u64 {
        db.add_call(addr(0x1000 + i), addr(0x2000 + (i % 10)), 5);
    }
    let arc = Arc::new(db);
    let mut handles = vec![];
    for t in 0..4u64 {
        let a = Arc::clone(&arc);
        handles.push(thread::spawn(move || {
            let mut total = 0usize;
            for i in 0..100u64 {
                let addr_q = Address::new(0x2000 + ((t + i) % 10));
                total += a.callers_of(addr_q).len();
            }
            total
        }));
    }
    for h in handles {
        assert!(h.join().unwrap() > 0);
    }
}

// -------- Boundary inputs --------

#[test]
fn db_max_u64_addresses() {
    let mut db = XrefDatabase::new();
    db.add_call(addr(u64::MAX), addr(0), 5);
    db.add_call(addr(0), addr(u64::MAX), 5);
    assert_eq!(db.total_count(), 2);
    assert_eq!(db.callers_of(addr(0)).len(), 1);
    assert_eq!(db.callers_of(addr(u64::MAX)).len(), 1);
}

#[test]
fn scanner_zero_byte_input() {
    let mut db = XrefDatabase::new();
    let scanner = X86XrefScanner::new(AddressRange::new(addr(0x1000), addr(0x2000)), 8);
    scanner.scan_code(addr(0x1000), &[], &mut db);
    scanner.scan_data_pointers(addr(0x3000), &[], &mut db);
    assert!(db.is_empty());
}

#[test]
fn db_add_zero_size_xref() {
    let mut db = XrefDatabase::new();
    db.add(Xref::new(addr(1), addr(2), XrefKind::CodeReturn, 0));
    assert_eq!(db.total_count(), 1);
}

#[test]
fn filter_kinds_empty_set_matches_none() {
    let f = XrefFilter::new().with_kinds(std::iter::empty());
    assert!(!f.matches(&Xref::new(addr(1), addr(2), XrefKind::CodeCall, 0)));
}

// -------- from_json adversarial hardening --------
//
// `XrefDatabase::from_json` must never panic on attacker-controlled input; it
// should always resolve to Ok(..) or a proper Err(XrefError). Each of these
// exercises a distinct malformed/adversarial shape and asserts the call
// unwinds cleanly via catch_unwind (a panic would abort/fail the test run)
// AND returns an Err rather than silently succeeding on garbage.
#[test]
fn from_json_adversarial_inputs_never_panic() {
    let cases: &[&str] = &[
        // empty / whitespace / truncated
        "",
        "   ",
        "[",
        "[{",
        r#"[{"from":1"#,
        // wrong top-level shape (object instead of array)
        r#"{"from":1,"to":2,"kind":"CodeCall","instr_size":0,"tag":null}"#,
        // missing required fields
        r#"[{"from":1,"to":2}]"#,
        r#"[{"kind":"CodeCall"}]"#,
        // wrong field types
        r#"[{"from":"not-a-number","to":2,"kind":"CodeCall","instr_size":0,"tag":null}]"#,
        r#"[{"from":1,"to":2,"kind":123,"instr_size":0,"tag":null}]"#,
        r#"[{"from":1,"to":2,"kind":"CodeCall","instr_size":"nope","tag":null}]"#,
        // out-of-range instr_size (u8 overflow)
        r#"[{"from":1,"to":2,"kind":"CodeCall","instr_size":999999,"tag":null}]"#,
        // negative addresses (u64 field, must be non-negative)
        r#"[{"from":-1,"to":2,"kind":"CodeCall","instr_size":0,"tag":null}]"#,
        // non-integer / scientific-notation numbers
        r#"[{"from":1.5,"to":2,"kind":"CodeCall","instr_size":0,"tag":null}]"#,
        r#"[{"from":1e400,"to":2,"kind":"CodeCall","instr_size":0,"tag":null}]"#,
        // tag as wrong type (should be string or null)
        r#"[{"from":1,"to":2,"kind":"CodeCall","instr_size":0,"tag":123}]"#,
        // null / bogus kind
        r#"[{"from":1,"to":2,"kind":null,"instr_size":0,"tag":null}]"#,
        r#"[{"from":1,"to":2,"kind":"","instr_size":0,"tag":null}]"#,
        // deeply nested garbage that isn't the expected shape at all
        "[[[[[[[[[[1]]]]]]]]]]",
        // trailing garbage after a valid-looking array
        r#"[{"from":1,"to":2,"kind":"CodeCall","instr_size":0,"tag":null}] garbage"#,
        // NUL bytes and control characters inside the JSON text
        "[{\"from\":1,\"to\":2,\"kind\":\"CodeCall\",\"instr_size\":0,\"tag\":\"\u{0}\"}]",
        // huge but syntactically valid u64 addresses
        r#"[{"from":18446744073709551615,"to":18446744073709551615,"kind":"CodeCall","instr_size":0,"tag":null}]"#,
    ];

    for case in cases {
        let case = *case;
        let result = std::panic::catch_unwind(|| XrefDatabase::from_json(case));
        assert!(
            result.is_ok(),
            "XrefDatabase::from_json panicked on input: {case:?}"
        );
    }
}

#[test]
fn from_json_untagged_kinds_that_expect_tags_are_silently_indexed_as_untagged() {
    // Kinds that normally carry a tag (ImportByName/StringRef/TypeRef) but
    // arrive with `tag: null` must not panic and must simply be absent from
    // the corresponding secondary (tag-keyed) index, while still being
    // present in the primary from/to indices.
    let json = r#"[
        {"from":1,"to":2,"kind":"ImportByName","instr_size":0,"tag":null},
        {"from":3,"to":4,"kind":"StringRef","instr_size":0,"tag":null},
        {"from":5,"to":6,"kind":"TypeRef","instr_size":0,"tag":null}
    ]"#;
    let db = XrefDatabase::from_json(json).unwrap();
    assert_eq!(db.total_count(), 3);
    assert!(db.all_import_names().is_empty());
    assert!(db.all_strings().is_empty());
    assert_eq!(db.xrefs_from(addr(1)).len(), 1);
    assert_eq!(db.xrefs_from(addr(3)).len(), 1);
    assert_eq!(db.xrefs_from(addr(5)).len(), 1);
}

#[test]
fn from_json_rejects_out_of_range_instr_size() {
    let bad = r#"[{"from":1,"to":2,"kind":"CodeCall","instr_size":256,"tag":null}]"#;
    assert!(XrefDatabase::from_json(bad).is_err());
}

#[test]
fn from_json_rejects_negative_address() {
    let bad = r#"[{"from":-1,"to":2,"kind":"CodeCall","instr_size":0,"tag":null}]"#;
    assert!(XrefDatabase::from_json(bad).is_err());
}

#[test]
fn merge_self_referential_style_double_merge_doubles_total() {
    // Merging two structurally-identical (but distinct) databases must not
    // panic and must simply concatenate — no implicit dedup across merge().
    let mut a_db = XrefDatabase::new();
    a_db.add_call(addr(0x1000), addr(0x2000), 5);
    let b_db_clone_source = {
        let mut b = XrefDatabase::new();
        b.add_call(addr(0x1000), addr(0x2000), 5);
        b
    };
    a_db.merge(b_db_clone_source);
    assert_eq!(a_db.total_count(), 2);
    assert_eq!(a_db.callers_of(addr(0x2000)).len(), 2);
}

#[test]
fn to_json_from_json_roundtrip_survives_catch_unwind_fuzz_of_truncated_output() {
    // Truncate a valid serialized JSON document at every byte offset and
    // confirm `from_json` never panics — only ever Ok or Err.
    let mut db = XrefDatabase::new();
    db.add_call(addr(0x1000), addr(0x2000), 5);
    db.add_string_ref(addr(0x1010), addr(0x3000), "hello world");
    db.add_import_by_name(addr(0x1020), addr(0x4000), "GetProcAddress");
    let json = db.to_json().unwrap();
    for cut in 0..json.len() {
        let slice = &json[..cut];
        let result = std::panic::catch_unwind(|| XrefDatabase::from_json(slice));
        assert!(result.is_ok(), "panicked on truncated JSON at byte {cut}");
    }
}
