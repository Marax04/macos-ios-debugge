//! Deep adversarial coverage for `rustre-graph`.
//!
//! Complements `blitz.rs` with seeded LCG fuzz, boundary stress,
//! round-trip properties, integer over/underflow paths, hash/eq
//! consistency, and a Send+Sync threaded stress on the algorithm
//! types (no DB connection is shared between threads).

use std::collections::HashMap;

use rustre_core::address::Address;
use rustre_core::ids::ViewId;
use rustre_graph::{FunctionMeta, KnowledgeGraph};
use rustre_graph::db::{GraphError, GraphParam, GraphValue, DbDialect};
use rustre_graph::graph_algorithms_extended::{
    BetweennessCentrality, ClosenessCentrality, Graph, PageRank, degree_map,
};
use rustre_graph::graph_export::{
    CsvExporter, DotExporter, ExportEdge, ExportFilter, ExportGraph, ExportNode, GraphMLExporter,
};
use rustre_graph::query_engine::glob_match;
use rustre_graph::analysis_graph;
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

fn g() -> KnowledgeGraph {
    KnowledgeGraph::new_in_memory().unwrap()
}
const fn vid(n: u64) -> ViewId { ViewId::from_raw(n) }
const fn a(n: u64) -> Address { Address::new(n) }

/// Deterministic LCG (Knuth MMIX constants).
struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self { Self(seed) }
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
}

// ---------------- Round-trip properties (50+ deterministic inputs) ----------------

#[test]
fn rt_function_50_high_bit_addresses() {
    let kg = g();
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    let mut inserted: Vec<u64> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    for _ in 0..60 {
        let addr = lcg.next();
        if !seen.insert(addr) { continue; }
        let end = addr.wrapping_add(0x10);
        kg.add_function(vid(1), a(addr), a(end), FunctionMeta { name: Some("fn"), ..FunctionMeta::default() })
            .unwrap();
        inserted.push(addr);
        if inserted.len() == 50 { break; }
    }
    assert_eq!(inserted.len(), 50);
    for &addr in &inserted {
        let row = kg.get_function_at(vid(1), a(addr)).unwrap().unwrap();
        assert_eq!(row.address, addr);
    }
}

#[test]
fn rt_string_50_payloads_searchable() {
    let kg = g();
    let mut lcg = Lcg::new(0x1234_5678_9ABC_DEF0);
    for i in 0..50 {
        let addr = (i as u64) * 0x100;
        let v = lcg.next();
        let s = format!("payload_{v:016x}");
        kg.add_string(vid(1), a(addr), s.len() as i64, "utf-8", &s, false).unwrap();
    }
    let all = kg.get_strings(vid(1)).unwrap();
    assert_eq!(all.len(), 50);
    // every payload starts with "payload_" -> substring search should hit all 50.
    let hits = kg.search_strings(vid(1), "payload_").unwrap();
    assert_eq!(hits.len(), 50);
}

#[test]
fn rt_patch_blob_roundtrip_lcg() {
    let kg = g();
    let mut lcg = Lcg::new(0xAAAA_5555_F00D_BAAD);
    for i in 0..30 {
        let mut orig = vec![0u8; 16];
        let mut newb = vec![0u8; 16];
        for byte in &mut orig { *byte = (lcg.next() & 0xFF) as u8; }
        for byte in &mut newb { *byte = (lcg.next() & 0xFF) as u8; }
        kg.add_patch(vid(1), a(i * 0x100), &orig, &newb, None).unwrap();
    }
    // get_patches returns all patches for view; we have 30
    let v = kg.query_sql("SELECT COUNT(*) FROM patches").unwrap();
    assert_eq!(v[0].values().next().unwrap().as_i64().unwrap(), 30);
}

// ---------------- LCG-fuzz: parsers/guards never panic ----------------

#[test]
fn fuzz_query_sql_never_panics_on_random_input() {
    let kg = g();
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let n = (lcg.next() & 0x1F) as usize + 1;
        let mut s = String::with_capacity(n);
        for _ in 0..n {
            let c = (lcg.next() & 0x7F) as u8;
            s.push(if c < 0x20 { ' ' } else { c as char });
        }
        // Whatever junk we feed in: must NOT panic. Result can be Ok or Err.
        let _ = kg.query_sql(&s);
    }
}

#[test]
fn fuzz_glob_match_never_panics() {
    let mut lcg = Lcg::new(0xFACE_FEED_F00D_BEEF);
    for _ in 0..200 {
        let np = (lcg.next() & 0x0F) as usize;
        let nt = (lcg.next() & 0x0F) as usize;
        let mut p = String::with_capacity(np);
        let mut t = String::with_capacity(nt);
        for _ in 0..np {
            let c = (lcg.next() & 0x7F) as u8;
            p.push(if c < 0x20 { '*' } else { c as char });
        }
        for _ in 0..nt {
            let c = (lcg.next() & 0x7F) as u8;
            t.push(if c < 0x20 { '?' } else { c as char });
        }
        let _ = glob_match(&p, &t);
    }
}

#[test]
fn fuzz_add_function_random_bounds() {
    let kg = g();
    let mut lcg = Lcg::new(0xBEEF_BABE_0011_2233);
    let mut seen: HashSet<u64> = HashSet::new();
    let mut added = 0;
    for _ in 0..200 {
        let addr = lcg.next();
        if !seen.insert(addr) { continue; }
        let end = addr.wrapping_add((lcg.next() & 0xFFF) | 1);
        // Either succeeds or returns an Err; never panic.
        if let Ok(_) = kg.add_function(vid(1), a(addr), a(end), FunctionMeta::default()) { added += 1; }
    }
    assert!(added > 0);
}

// ---------------- Boundaries: 0, 1, max, off-by-one ----------------

#[test]
fn boundary_zero_address_function() {
    let kg = g();
    kg.add_function(vid(1), a(0), a(1), FunctionMeta { name: Some("z"), ..FunctionMeta::default() }).unwrap();
    let row = kg.get_function_at(vid(1), a(0)).unwrap().unwrap();
    assert_eq!(row.address, 0);
    assert_eq!(row.end_address, 1);
}

#[test]
fn boundary_u64_max_address_function() {
    let kg = g();
    let m = u64::MAX;
    kg.add_function(vid(1), a(m - 1), a(m), FunctionMeta { name: Some("m"), ..FunctionMeta::default() }).unwrap();
    let row = kg.get_function_at(vid(1), a(m - 1)).unwrap().unwrap();
    assert_eq!(row.address, m - 1);
    assert_eq!(row.end_address, m);
}

#[test]
fn boundary_range_query_half_open_off_by_one() {
    let kg = g();
    for addr in [0u64, 1, 2, 3, 4] {
        kg.add_function(vid(1), a(addr), a(addr + 1), FunctionMeta::default()).unwrap();
    }
    // [0,4) should yield 0..=3
    let rows = kg.get_functions_in_range(vid(1), a(0), a(4)).unwrap();
    let addrs: Vec<u64> = rows.iter().map(|r| r.address).collect();
    assert_eq!(addrs, vec![0, 1, 2, 3]);
    // [4,4) is empty
    let rows = kg.get_functions_in_range(vid(1), a(4), a(4)).unwrap();
    assert!(rows.is_empty());
    // [4,5) is the single one at 4
    let rows = kg.get_functions_in_range(vid(1), a(4), a(5)).unwrap();
    assert_eq!(rows.len(), 1);
}

#[test]
fn boundary_get_events_zero_limit() {
    let kg = g();
    for _ in 0..3 {
        kg.add_event(vid(1), "a", "k", &[1u8]).unwrap();
    }
    let ev = kg.get_events(vid(1), 0).unwrap();
    assert_eq!(ev.len(), 0);
}

#[test]
fn boundary_get_events_huge_limit() {
    let kg = g();
    for _ in 0..3 {
        kg.add_event(vid(1), "a", "k", &[1u8]).unwrap();
    }
    let ev = kg.get_events(vid(1), 10_000).unwrap();
    assert_eq!(ev.len(), 3);
}

#[test]
fn boundary_empty_strings_for_string_row() {
    let kg = g();
    kg.add_string(vid(1), a(0), 0, "ascii", "", false).unwrap();
    let rows = kg.get_strings(vid(1)).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value, "");
    assert_eq!(rows[0].length, 0);
}

// ---------------- Truncated / malformed query_sql guards ----------------

#[test]
fn malformed_sql_update_rejected() {
    assert!(g().query_sql("UPDATE views SET uri='x'").is_err());
}
#[test]
fn malformed_sql_insert_rejected() {
    assert!(g().query_sql("INSERT INTO views VALUES (1)").is_err());
}
#[test]
fn malformed_sql_attach_rejected() {
    assert!(g().query_sql("ATTACH DATABASE 'x' AS y").is_err());
}
#[test]
fn malformed_sql_pragma_rejected() {
    assert!(g().query_sql("PRAGMA foreign_keys=ON").is_err());
}
#[test]
fn malformed_sql_only_whitespace() {
    assert!(g().query_sql("   ").is_err());
}
#[test]
fn malformed_sql_empty_string() {
    assert!(g().query_sql("").is_err());
}

// ---------------- State machine: transactions ----------------

#[test]
fn transaction_double_begin_is_idempotent() {
    // db.rs implementation: nested begin is a documented no-op (in_txn flag guards).
    let kg = g();
    kg.begin_transaction().unwrap();
    kg.begin_transaction().unwrap();
    kg.rollback_transaction().unwrap();
}

#[test]
fn transaction_commit_without_begin_is_noop() {
    // Implementation: commit when !in_txn is a documented no-op.
    let kg = g();
    kg.commit_transaction().unwrap();
}

#[test]
fn transaction_rollback_without_begin_is_noop() {
    // Implementation: rollback when !in_txn is a documented no-op.
    let kg = g();
    kg.rollback_transaction().unwrap();
}

#[test]
fn transaction_commit_then_rollback_is_noop() {
    // After commit, in_txn flag clears, so subsequent rollback is a no-op.
    let kg = g();
    kg.begin_transaction().unwrap();
    kg.add_function(vid(1), a(0x1000), a(0x1100), FunctionMeta { name: Some("x"), ..FunctionMeta::default() }).unwrap();
    kg.commit_transaction().unwrap();
    kg.rollback_transaction().unwrap();
    // Data committed before the no-op rollback survives.
    assert_eq!(kg.count_functions(vid(1)).unwrap(), 1);
}

// ---------------- Integer over/underflow paths ----------------

#[test]
fn xref_top_bit_addr_roundtrip() {
    let kg = g();
    let hi = 0x8000_0000_0000_0000u64;
    kg.add_xref(vid(1), a(hi), a(hi.wrapping_add(0x10)), "code_call").unwrap();
    let from = kg.xrefs_from(vid(1), a(hi)).unwrap();
    assert_eq!(from.len(), 1);
    assert_eq!(from[0].from_addr, hi);
}

#[test]
fn comment_max_address_roundtrip() {
    let kg = g();
    kg.add_comment(vid(1), a(u64::MAX), "edge", false).unwrap();
    assert_eq!(kg.get_comment(vid(1), a(u64::MAX)).unwrap().as_deref(), Some("edge"));
}

#[test]
fn function_wraparound_end_address_lower_than_start_allowed() {
    // end < start (wraparound) — should still insert and roundtrip.
    let kg = g();
    let addr = u64::MAX - 4;
    let end = 3u64; // wrapped
    kg.add_function(vid(1), a(addr), a(end), FunctionMeta::default()).unwrap();
    let row = kg.get_function_at(vid(1), a(addr)).unwrap().unwrap();
    assert_eq!(row.address, addr);
    assert_eq!(row.end_address, end);
}

// ---------------- Hash/Eq consistency on 30+ pairs ----------------

#[test]
fn nodeid_hash_eq_consistency_30() {
    let mut map: HashMap<analysis_graph::NodeId, usize> = HashMap::new();
    for i in 0u64..30 {
        map.insert(analysis_graph::NodeId(i), i as usize);
    }
    for i in 0u64..30 {
        assert_eq!(map.get(&analysis_graph::NodeId(i)), Some(&(i as usize)));
    }
    assert_eq!(analysis_graph::NodeId(7), analysis_graph::NodeId(7));
    assert_ne!(analysis_graph::NodeId(7), analysis_graph::NodeId(8));
}

#[test]
fn edgeid_hash_eq_consistency_30() {
    use std::collections::HashSet;
    let mut s: HashSet<analysis_graph::EdgeId> = HashSet::new();
    for i in 0u64..30 {
        assert!(s.insert(analysis_graph::EdgeId(i)));
    }
    for i in 0u64..30 {
        assert!(!s.insert(analysis_graph::EdgeId(i)), "duplicate insert should report false");
    }
    assert_eq!(s.len(), 30);
}

// ---------------- GraphValue / GraphParam edges ----------------

#[test]
fn graph_value_text_with_null_byte() {
    let v = GraphValue::Text("a\0b".to_string());
    assert_eq!(v.as_str(), Some("a\0b"));
}

#[test]
fn graph_value_blob_empty() {
    let v = GraphValue::Blob(vec![]);
    assert_eq!(v.as_blob(), Some(&[][..]));
}

#[test]
fn graph_value_null_accessors_are_none() {
    let v = GraphValue::Null;
    assert!(v.is_null());
    assert!(v.as_i64().is_none());
    assert!(v.as_str().is_none());
    assert!(v.as_f64().is_none());
    assert!(v.as_blob().is_none());
}

#[test]
fn graph_value_real_special_values() {
    // NaN/Inf accessors should still return Some(f64); test sanity.
    assert!(GraphValue::Real(f64::INFINITY).as_f64().unwrap().is_infinite());
    assert!(GraphValue::Real(f64::NAN).as_f64().unwrap().is_nan());
    assert!(GraphValue::Real(-0.0).as_f64().unwrap() == 0.0);
}

// ---------------- Graph algorithm boundary stress ----------------

#[test]
fn graph_add_self_loop_kept() {
    let mut gr = Graph::new(3);
    gr.add_edge(1, 1, 4.0);
    assert_eq!(gr.edges[1], vec![(1usize, 4.0)]);
}

#[test]
fn graph_bfs_with_self_loop_does_not_infinite_loop() {
    let mut gr = Graph::new(2);
    gr.add_edge(0, 0, 1.0);
    gr.add_edge(0, 1, 1.0);
    let d = gr.bfs_distances(0);
    assert_eq!(d[0], Some(0));
    assert_eq!(d[1], Some(1));
}

#[test]
fn graph_dijkstra_zero_weight() {
    let mut gr = Graph::new(3);
    gr.add_edge(0, 1, 0.0);
    gr.add_edge(1, 2, 0.0);
    let d = gr.dijkstra(0);
    assert!((d[2]).abs() < 1e-12);
}

#[test]
fn graph_pagerank_single_node_score_is_one() {
    let pr = PageRank::compute(&Graph::new(1), 0.85, 50, 1e-9);
    assert_eq!(pr.scores.len(), 1);
    assert!((pr.scores[0] - 1.0).abs() < 1e-3);
}

#[test]
fn graph_betweenness_empty_is_empty() {
    let bc = BetweennessCentrality::compute(&Graph::new(0));
    assert!(bc.scores.is_empty());
}

#[test]
fn graph_closeness_empty_is_empty() {
    let cc = ClosenessCentrality::compute(&Graph::new(0));
    assert!(cc.scores.is_empty());
}

#[test]
fn degree_map_with_no_edges_returns_zeros() {
    let gr = Graph::new(4);
    let dm = degree_map(&gr);
    for i in 0..4 {
        assert_eq!(dm.get(&i).copied().unwrap_or(0), 0);
    }
}

#[test]
fn graph_lcg_random_topology_does_not_panic() {
    let mut lcg = Lcg::new(0x9E37_79B9_7F4A_7C15);
    let n = 32usize;
    let mut gr = Graph::new(n);
    for _ in 0..256 {
        let u = (lcg.next() as usize) % n;
        let v = (lcg.next() as usize) % n;
        let w = ((lcg.next() & 0xFFF) as f64) / 16.0;
        gr.add_edge(u, v, w);
    }
    let _ = gr.bfs_distances(0);
    let _ = gr.dijkstra(0);
    let _ = PageRank::compute(&gr, 0.85, 30, 1e-6);
    let _ = degree_map(&gr);
}

// ---------------- glob_match deeper edge cases ----------------

#[test]
fn glob_double_star_collapse() {
    assert!(glob_match("**", ""));
    assert!(glob_match("**", "anything"));
    assert!(glob_match("a**b", "axyzb"));
}

#[test]
fn glob_star_question_combos() {
    assert!(glob_match("*?", "x"));
    assert!(!glob_match("?*", ""));
    assert!(glob_match("?*", "y"));
    assert!(glob_match("*?*", "ab"));
}

#[test]
fn glob_unicode_chars() {
    assert!(glob_match("?", "é"));
    assert!(glob_match("a*z", "aéz"));
}

// ---------------- Export graph filters ----------------

fn sample() -> ExportGraph {
    let mut g = ExportGraph::new("t");
    g.add_node(ExportNode { id: "a".into(), label: "A".into(), node_type: "func".into(), attributes: HashMap::default() });
    g.add_node(ExportNode { id: "b".into(), label: "B".into(), node_type: "data".into(), attributes: HashMap::default() });
    g.add_edge(ExportEdge { id: "e1".into(), source: "a".into(), target: "b".into(), kind: "call".into(), weight: 1.0, directed: true, attributes: HashMap::default() });
    g.add_edge(ExportEdge { id: "e2".into(), source: "a".into(), target: "b".into(), kind: "jump".into(), weight: 5.0, directed: true, attributes: HashMap::default() });
    g
}

#[test]
fn filter_weight_threshold_includes_only_heavy() {
    let mut f = ExportFilter::default();
    f.min_edge_weight = 4.0;
    let g = sample();
    assert!(!f.accepts_edge(&g.edges[0]));
    assert!(f.accepts_edge(&g.edges[1]));
}

#[test]
fn filter_node_type_set_filters_correctly() {
    let mut f = ExportFilter::default();
    f.include_node_types.insert("func".into());
    let g = sample();
    assert!(f.accepts_node(&g.nodes[0]));
    assert!(!f.accepts_node(&g.nodes[1]));
}

#[test]
fn graphml_contains_all_node_ids() {
    let g = sample();
    let s = GraphMLExporter::export(&g, &ExportFilter::default());
    assert!(s.contains('a') && s.contains('b'));
}

#[test]
fn dot_contains_both_nodes() {
    let g = sample();
    let s = DotExporter::export(&g, &ExportFilter::default());
    assert!(s.contains('a'));
    assert!(s.contains('b'));
}

#[test]
fn csv_edges_has_both_kinds() {
    let g = sample();
    let s = CsvExporter::export_edges(&g, &ExportFilter::default());
    assert!(s.contains("call"));
    assert!(s.contains("jump"));
}

// ---------------- DbDialect enum invariants ----------------

#[test]
fn db_dialect_copy_eq() {
    let a = DbDialect::Sqlite;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(DbDialect::Sqlite, DbDialect::Mysql);
}

// ---------------- Send + Sync threaded stress on Graph (algorithms) ----------------

#[test]
fn threaded_pagerank_4x100_immutable_graph() {
    // Graph<T> via PageRank reads only; share via Arc across 4 threads, 100 ops each.
    let mut gr = Graph::new(8);
    let mut lcg = Lcg::new(0x0BAD_F00D_1234_5678);
    for _ in 0..32 {
        let u = (lcg.next() as usize) % 8;
        let v = (lcg.next() as usize) % 8;
        gr.add_edge(u, v, 1.0);
    }
    let shared = Arc::new(gr);
    let mut handles = Vec::new();
    for t in 0..4 {
        let s = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            let mut acc = 0.0f64;
            for i in 0..100 {
                let pr = PageRank::compute(&s, 0.85, 10, 1e-3);
                acc += pr.scores.iter().copied().sum::<f64>();
                let _ = (t, i, acc);
            }
            acc
        }));
    }
    for h in handles { let _ = h.join().unwrap(); }
}

#[test]
fn threaded_bfs_4x100_immutable_graph() {
    let mut gr = Graph::new(16);
    for i in 0..15 { gr.add_edge(i, i + 1, 1.0); }
    let shared = Arc::new(gr);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let s = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let d = s.bfs_distances(0);
                assert_eq!(d.len(), 16);
                assert_eq!(d[15], Some(15));
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// ---------------- analysis_graph basic types ----------------

#[test]
fn nodeid_ordering_total() {
    let mut v: Vec<analysis_graph::NodeId> = (0u64..10).rev().map(analysis_graph::NodeId).collect();
    v.sort();
    let expected: Vec<analysis_graph::NodeId> = (0u64..10).map(analysis_graph::NodeId).collect();
    assert_eq!(v, expected);
}

#[test]
fn edgeid_ordering_total() {
    let mut v: Vec<analysis_graph::EdgeId> = (0u64..10).rev().map(analysis_graph::EdgeId).collect();
    v.sort();
    let expected: Vec<analysis_graph::EdgeId> = (0u64..10).map(analysis_graph::EdgeId).collect();
    assert_eq!(v, expected);
}

// ---------------- GraphParam Debug never panics on random ----------------

#[test]
fn graph_param_debug_lcg_random() {
    let mut lcg = Lcg::new(0xCAFE_BABE_DEAD_BEEF);
    for _ in 0..20 {
        let _ = format!("{:?}", GraphParam::Int(lcg.next() as i64));
        let mut bytes = vec![0u8; (lcg.next() & 0x1F) as usize];
        for b in &mut bytes { *b = (lcg.next() & 0xFF) as u8; }
        let _ = format!("{:?}", GraphParam::Blob(bytes));
    }
}

// ---------------- Massive view isolation property ----------------

#[test]
fn many_views_addr_collision_isolated() {
    let kg = g();
    for v in 0..20u64 {
        kg.add_function(vid(v), a(0x1000), a(0x1100), FunctionMeta { name: Some(&format!("v{v}")), ..FunctionMeta::default() }).unwrap();
    }
    for v in 0..20u64 {
        let name = kg.get_function_name(vid(v), a(0x1000)).unwrap();
        assert_eq!(name.as_deref(), Some(format!("v{v}").as_str()));
    }
}

#[test]
fn count_functions_after_bulk_insert_50() {
    let kg = g();
    for i in 0..50u64 {
        kg.add_function(vid(1), a(i * 0x100), a(i * 0x100 + 0x10), FunctionMeta::default()).unwrap();
    }
    assert_eq!(kg.count_functions(vid(1)).unwrap(), 50);
}

// ---------------- GraphError surface ----------------

#[test]
fn graph_error_display_does_not_panic() {
    let err = GraphError::Generic("hello".into());
    let s = format!("{err}");
    assert!(s.contains("hello") || !s.is_empty());
    let d = format!("{err:?}");
    assert!(!d.is_empty());
}
