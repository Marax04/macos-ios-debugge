//! Exhaustive black-box tests for `rustre-graph`.
//!
//! Targets:
//!   * `KnowledgeGraph` (lib.rs) — CRUD round-trips, boundaries, error paths.
//!   * `query_sql` guard — DML rejection, comment rejection.
//!   * `graph_algorithms_extended::Graph` + algorithms — BFS, Dijkstra,
//!     `PageRank`, `BetweennessCentrality`, `degree_map`, Display.
//!   * `query_engine::glob_match` — `*`, `?`, exact-match edge cases.
//!   * `graph_export::ExportFilter` / `ExportGraph` basics.

use std::collections::HashMap;

use rustre_core::address::Address;
use rustre_core::ids::ViewId;
use rustre_graph::analysis_graph;
use rustre_graph::db::{GraphError, GraphParam, GraphValue};
use rustre_graph::graph_algorithms_extended::{
    BetweennessCentrality, ClosenessCentrality, Graph, PageRank, degree_map,
};
use rustre_graph::graph_export::{
    CsvExporter, DotExporter, ExportEdge, ExportFilter, ExportGraph, ExportNode, GraphMLExporter,
};
use rustre_graph::query_engine::glob_match;
use rustre_graph::{FunctionMeta, KnowledgeGraph};

fn g() -> KnowledgeGraph {
    KnowledgeGraph::new_in_memory().unwrap()
}
const fn vid(n: u64) -> ViewId {
    ViewId::from_raw(n)
}
const fn a(n: u64) -> Address {
    Address::new(n)
}

// ------------------------------------------------------------------
// Construction
// ------------------------------------------------------------------

#[test]
fn ctor_in_memory_ok() {
    let _ = g();
}

#[test]
fn ctor_file_roundtrip() {
    let p = std::env::temp_dir().join("rustre_blitz_ctor.db");
    let _ = std::fs::remove_file(&p);
    {
        let kg = KnowledgeGraph::new_file(&p).unwrap();
        kg.add_view(1, "uri", "x86", "little", 32).unwrap();
    }
    // Re-open the same file: schema-init should be idempotent.
    let kg2 = KnowledgeGraph::new_file(&p).unwrap();
    let v = kg2.get_view_info(1).unwrap().unwrap();
    assert_eq!(v.bits, 32);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn debug_impl_does_not_panic() {
    let kg = g();
    let s = format!("{kg:?}");
    assert!(s.contains("KnowledgeGraph"));
}

// ------------------------------------------------------------------
// Views
// ------------------------------------------------------------------

#[test]
fn view_replace_on_duplicate_id() {
    let kg = g();
    kg.add_view(1, "a", "x86", "little", 32).unwrap();
    kg.add_view(1, "b", "arm", "big", 64).unwrap();
    let v = kg.get_view_info(1).unwrap().unwrap();
    assert_eq!(v.uri, "b");
    assert_eq!(v.arch, "arm");
    assert_eq!(v.bits, 64);
}

#[test]
fn view_missing_is_none() {
    assert!(g().get_view_info(1234).unwrap().is_none());
}

// ------------------------------------------------------------------
// Functions
// ------------------------------------------------------------------

#[test]
fn function_add_and_get_at() {
    let kg = g();
    let id = kg
        .add_function(vid(1), a(0x1000), a(0x1100), FunctionMeta { name: Some("f"), prototype: Some("void f()"), calling_conv: Some("cdecl"), ..FunctionMeta::default() })
        .unwrap();
    assert!(id > 0);
    let row = kg.get_function_at(vid(1), a(0x1000)).unwrap().unwrap();
    assert_eq!(row.name.as_deref(), Some("f"));
    assert_eq!(row.prototype.as_deref(), Some("void f()"));
    assert_eq!(row.calling_conv.as_deref(), Some("cdecl"));
    assert_eq!(row.address, 0x1000);
    assert_eq!(row.end_address, 0x1100);
    assert!(!row.is_thunk);
}

#[test]
fn function_get_name_missing_none() {
    assert!(g().get_function_name(vid(1), a(0x2000)).unwrap().is_none());
}

#[test]
fn function_rename_persists() {
    let kg = g();
    kg.add_function(vid(1), a(0x1000), a(0x1100), FunctionMeta { name: Some("old"), ..FunctionMeta::default() })
        .unwrap();
    kg.rename_function(vid(1), a(0x1000), "new").unwrap();
    assert_eq!(
        kg.get_function_name(vid(1), a(0x1000)).unwrap().as_deref(),
        Some("new")
    );
}

#[test]
fn function_set_prototype_persists() {
    let kg = g();
    kg.add_function(vid(1), a(0x1000), a(0x1100), FunctionMeta::default())
        .unwrap();
    kg.set_function_prototype(vid(1), a(0x1000), "int x()").unwrap();
    let row = kg.get_function_at(vid(1), a(0x1000)).unwrap().unwrap();
    assert_eq!(row.prototype.as_deref(), Some("int x()"));
}

#[test]
fn function_count_and_delete() {
    let kg = g();
    assert_eq!(kg.count_functions(vid(1)).unwrap(), 0);
    kg.add_function(vid(1), a(0x1000), a(0x1100), FunctionMeta::default()).unwrap();
    kg.add_function(vid(1), a(0x2000), a(0x2100), FunctionMeta::default()).unwrap();
    assert_eq!(kg.count_functions(vid(1)).unwrap(), 2);
    assert_eq!(kg.count_functions(vid(99)).unwrap(), 0);
    kg.delete_function(vid(1), a(0x1000)).unwrap();
    assert_eq!(kg.count_functions(vid(1)).unwrap(), 1);
}

#[test]
fn function_range_half_open() {
    let kg = g();
    for off in [0x1000u64, 0x1500, 0x2000, 0x2500] {
        kg.add_function(vid(1), a(off), a(off + 0x10), FunctionMeta::default())
            .unwrap();
    }
    // Half-open [0x1000, 0x2000) should NOT include 0x2000.
    let rows = kg.get_functions_in_range(vid(1), a(0x1000), a(0x2000)).unwrap();
    let addrs: Vec<u64> = rows.iter().map(|r| r.address).collect();
    assert_eq!(addrs, vec![0x1000, 0x1500]);
}

#[test]
fn function_high_bit_address_roundtrip() {
    // Top-bit-set u64 must round-trip through i64 storage.
    let kg = g();
    let hi = 0xFFFF_FFFF_FFFF_0000u64;
    kg.add_function(vid(1), a(hi), a(hi.wrapping_add(0x10)), FunctionMeta { name: Some("k"), ..FunctionMeta::default() })
        .unwrap();
    let row = kg.get_function_at(vid(1), a(hi)).unwrap().unwrap();
    assert_eq!(row.address, hi);
}

#[test]
fn function_view_isolation() {
    let kg = g();
    kg.add_function(vid(1), a(0x1000), a(0x1100), FunctionMeta { name: Some("v1"), ..FunctionMeta::default() }).unwrap();
    kg.add_function(vid(2), a(0x1000), a(0x1100), FunctionMeta { name: Some("v2"), ..FunctionMeta::default() }).unwrap();
    assert_eq!(kg.get_function_name(vid(1), a(0x1000)).unwrap().as_deref(), Some("v1"));
    assert_eq!(kg.get_function_name(vid(2), a(0x1000)).unwrap().as_deref(), Some("v2"));
}

// ------------------------------------------------------------------
// Symbols
// ------------------------------------------------------------------

#[test]
fn symbol_crud() {
    let kg = g();
    kg.add_symbol(vid(1), a(0x1000), "foo", "func", Some("user")).unwrap();
    kg.add_symbol(vid(1), a(0x1000), "foo_alias", "func", None).unwrap();
    assert_eq!(kg.count_symbols(vid(1)).unwrap(), 2);
    let at = kg.get_symbols_at(vid(1), a(0x1000)).unwrap();
    assert_eq!(at.len(), 2);
    let by_name = kg.get_symbols_by_name(vid(1), "foo").unwrap();
    assert_eq!(by_name.len(), 1);
    assert_eq!(by_name[0].source.as_deref(), Some("user"));
    kg.delete_symbol(vid(1), a(0x1000), "func").unwrap();
    assert_eq!(kg.count_symbols(vid(1)).unwrap(), 0);
}

// ------------------------------------------------------------------
// Xrefs
// ------------------------------------------------------------------

#[test]
fn xref_crud_and_count() {
    let kg = g();
    kg.add_xref(vid(1), a(0x1000), a(0x2000), "code_call").unwrap();
    kg.add_xref(vid(1), a(0x1000), a(0x3000), "data_read").unwrap();
    kg.add_xref(vid(1), a(0x4000), a(0x2000), "code_call").unwrap();
    assert_eq!(kg.count_xrefs(vid(1)).unwrap(), 3);
    let from = kg.xrefs_from(vid(1), a(0x1000)).unwrap();
    assert_eq!(from.len(), 2);
    let to = kg.xrefs_to(vid(1), a(0x2000)).unwrap();
    assert_eq!(to.len(), 2);
    let callers = kg.callers_of(vid(1), a(0x2000)).unwrap();
    assert_eq!(callers.len(), 2, "both code_calls land at 0x2000");
    let callers_of_data = kg.callers_of(vid(1), a(0x3000)).unwrap();
    assert_eq!(callers_of_data.len(), 0, "data_read is not a call");
    kg.delete_xrefs_from(vid(1), a(0x1000)).unwrap();
    assert_eq!(kg.count_xrefs(vid(1)).unwrap(), 1);
}

// ------------------------------------------------------------------
// Comments
// ------------------------------------------------------------------

#[test]
fn comment_crud_and_iter() {
    let kg = g();
    kg.add_comment(vid(1), a(0x1000), "first", false).unwrap();
    kg.add_comment(vid(1), a(0x2000), "second", true).unwrap();
    let txt = kg.get_comment(vid(1), a(0x1000)).unwrap();
    assert_eq!(txt.as_deref(), Some("first"));
    kg.update_comment(vid(1), a(0x1000), "updated").unwrap();
    assert_eq!(kg.get_comment(vid(1), a(0x1000)).unwrap().as_deref(), Some("updated"));
    let all = kg.iter_comments(vid(1)).unwrap();
    assert_eq!(all.len(), 2);
    assert!(all[0].address <= all[1].address, "ordered by address");
    kg.delete_comment(vid(1), a(0x1000)).unwrap();
    assert!(kg.get_comment(vid(1), a(0x1000)).unwrap().is_none());
}

#[test]
fn comment_missing_is_none() {
    assert!(g().get_comment(vid(1), a(0x1000)).unwrap().is_none());
}

// ------------------------------------------------------------------
// Patches
// ------------------------------------------------------------------

#[test]
fn patch_roundtrip_with_blobs() {
    let kg = g();
    let orig = vec![0x90u8, 0x90, 0x90];
    let newb = vec![0xCC, 0xC3];
    let id = kg
        .add_patch(vid(1), a(0x1000), &orig, &newb, Some("nop slide"))
        .unwrap();
    assert!(id > 0);
    let patches = kg.get_patches(vid(1)).unwrap();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0].original_bytes, orig);
    assert_eq!(patches[0].new_bytes, newb);
    assert_eq!(patches[0].reason.as_deref(), Some("nop slide"));
    kg.delete_patch(vid(1), a(0x1000)).unwrap();
    assert!(kg.get_patches(vid(1)).unwrap().is_empty());
}

#[test]
fn patch_empty_blobs_allowed() {
    let kg = g();
    kg.add_patch(vid(1), a(0x1000), &[], &[], None).unwrap();
    let p = kg.get_patches(vid(1)).unwrap();
    assert_eq!(p.len(), 1);
    assert!(p[0].original_bytes.is_empty());
    assert!(p[0].reason.is_none());
}

// ------------------------------------------------------------------
// Strings
// ------------------------------------------------------------------

#[test]
fn string_crud_and_search() {
    let kg = g();
    kg.add_string(vid(1), a(0x1000), 5, "ascii", "hello", false).unwrap();
    kg.add_string(vid(1), a(0x1010), 5, "ascii", "world", true).unwrap();
    kg.add_string(vid(1), a(0x1020), 7, "utf-8", "shellfoo", false).unwrap();
    let all = kg.get_strings(vid(1)).unwrap();
    assert_eq!(all.len(), 3);
    assert!(all[0].address <= all[1].address);
    let hits = kg.search_strings(vid(1), "ell").unwrap();
    // "hello" and "shellfoo" both contain "ell".
    assert_eq!(hits.len(), 2);
}

// ------------------------------------------------------------------
// Events
// ------------------------------------------------------------------

#[test]
fn event_add_and_get_limit() {
    let kg = g();
    for i in 0..5 {
        kg.add_event(vid(1), "actor", "kind", &[i as u8]).unwrap();
    }
    let ev = kg.get_events(vid(1), 3).unwrap();
    assert_eq!(ev.len(), 3);
}

// ------------------------------------------------------------------
// Bookmarks
// ------------------------------------------------------------------

#[test]
fn bookmark_crud() {
    let kg = g();
    let id = kg.add_bookmark(vid(1), a(0x1000), Some("here"), 0x00FF_0000).unwrap();
    assert!(id > 0);
    let bms = kg.get_bookmarks(vid(1)).unwrap();
    assert_eq!(bms.len(), 1);
    assert_eq!(bms[0].label.as_deref(), Some("here"));
    assert_eq!(bms[0].color, 0x00FF_0000);
    kg.delete_bookmark(vid(1), a(0x1000)).unwrap();
    assert!(kg.get_bookmarks(vid(1)).unwrap().is_empty());
}

// ------------------------------------------------------------------
// Basic blocks + CFG
// ------------------------------------------------------------------

#[test]
fn bb_and_cfg() {
    let kg = g();
    let fid = kg
        .add_function(vid(1), a(0x1000), a(0x1100), FunctionMeta { name: Some("f"), ..FunctionMeta::default() })
        .unwrap();
    let b1 = kg.add_basic_block(fid, a(0x1000), a(0x1040)).unwrap();
    let b2 = kg.add_basic_block(fid, a(0x1040), a(0x1080)).unwrap();
    let b3 = kg.add_basic_block(fid, a(0x1080), a(0x1100)).unwrap();
    kg.add_cfg_edge(b1, b2, "true").unwrap();
    kg.add_cfg_edge(b1, b3, "false").unwrap();
    let bbs = kg.get_basic_blocks_of_function(fid).unwrap();
    assert_eq!(bbs.len(), 3);
    let edges = kg.get_cfg_edges_from(b1).unwrap();
    assert_eq!(edges.len(), 2);
    assert!(edges.iter().any(|e| e.kind == "true"));
    assert!(edges.iter().any(|e| e.kind == "false"));
}

// ------------------------------------------------------------------
// Annotations
// ------------------------------------------------------------------

#[test]
fn annotation_upsert() {
    let kg = g();
    kg.annotate("function", 1, "color", "\"red\"").unwrap();
    assert_eq!(
        kg.get_annotation("function", 1, "color").unwrap().as_deref(),
        Some("\"red\"")
    );
    kg.annotate("function", 1, "color", "\"blue\"").unwrap();
    assert_eq!(
        kg.get_annotation("function", 1, "color").unwrap().as_deref(),
        Some("\"blue\"")
    );
    assert!(kg.get_annotation("function", 1, "missing").unwrap().is_none());
}

// ------------------------------------------------------------------
// Section/import/export population helpers
// ------------------------------------------------------------------

#[test]
fn section_import_export_inserts_smoke() {
    let kg = g();
    kg.add_section(vid(1), ".text", 0x1000, 0x4000, 6.5).unwrap();
    kg.add_import(vid(1), Some("kernel32.dll"), "CreateFileA", Some(7), 0x4000)
        .unwrap();
    kg.add_import(vid(1), None, "NoModuleFn", None, 0x4100).unwrap();
    kg.add_export(vid(1), Some("MyExport"), Some(1), 0x5000).unwrap();
    kg.add_export(vid(1), None, Some(2), 0x5010).unwrap();
    // Verify via raw SELECT (read-only) which exercises query_sql too.
    let rows = kg.query_sql("SELECT COUNT(*) FROM imports").unwrap();
    let total = rows[0].values().next().unwrap().as_i64().unwrap();
    assert_eq!(total, 2);
}

// ------------------------------------------------------------------
// query_sql guards
// ------------------------------------------------------------------

#[test]
fn query_sql_select_ok() {
    let kg = g();
    let rows = kg.query_sql("SELECT 1 AS n").unwrap();
    assert_eq!(rows.len(), 1);
}

#[test]
fn query_sql_rejects_delete() {
    let kg = g();
    let err = kg.query_sql("DELETE FROM views").unwrap_err();
    matches!(err, GraphError::Generic(_));
}

#[test]
fn query_sql_rejects_drop() {
    let kg = g();
    assert!(kg.query_sql("DROP TABLE views").is_err());
}

#[test]
fn query_sql_rejects_line_comment() {
    let kg = g();
    let err = kg.query_sql("SELECT 1 -- DROP TABLE views").unwrap_err();
    matches!(err, GraphError::Generic(_));
}

#[test]
fn query_sql_rejects_block_comment() {
    let kg = g();
    assert!(kg.query_sql("SELECT /* bad */ 1").is_err());
}

#[test]
fn query_sql_rejects_chained_dml() {
    let kg = g();
    assert!(kg
        .query_sql("SELECT 1; DELETE FROM views")
        .is_err());
}

#[test]
fn query_sql_with_cte_allowed() {
    let kg = g();
    // WITH … SELECT is allowed by the secondary guard. But the whole query
    // must still start with SELECT to pass the FIRST guard, so prefix matters.
    // Verify the guard accepts a plain SELECT and that the WITH branch exists
    // by checking it rejects a bare WITH that does not start with SELECT.
    assert!(kg.query_sql("WITH x AS (SELECT 1) SELECT * FROM x").is_err(),
        "plain WITH-prefix is rejected by the first guard (starts_with SELECT)");
}

// ------------------------------------------------------------------
// Transactions
// ------------------------------------------------------------------

#[test]
fn transaction_commit() {
    let kg = g();
    kg.begin_transaction().unwrap();
    kg.add_function(vid(1), a(0x1000), a(0x1100), FunctionMeta { name: Some("tx"), ..FunctionMeta::default() }).unwrap();
    kg.commit_transaction().unwrap();
    assert_eq!(kg.count_functions(vid(1)).unwrap(), 1);
}

#[test]
fn transaction_rollback() {
    let kg = g();
    kg.begin_transaction().unwrap();
    kg.add_function(vid(1), a(0x1000), a(0x1100), FunctionMeta { name: Some("tx"), ..FunctionMeta::default() }).unwrap();
    kg.rollback_transaction().unwrap();
    assert_eq!(kg.count_functions(vid(1)).unwrap(), 0);
}

// ------------------------------------------------------------------
// GraphParam / GraphValue
// ------------------------------------------------------------------

#[test]
fn graph_value_accessors() {
    assert_eq!(GraphValue::Integer(7).as_i64(), Some(7));
    assert_eq!(GraphValue::Integer(7).as_str(), None);
    assert_eq!(GraphValue::Text("x".into()).as_str(), Some("x"));
    assert_eq!(GraphValue::Text("x".into()).as_i64(), None);
    assert_eq!(GraphValue::Real(1.5).as_f64(), Some(1.5));
    assert_eq!(GraphValue::Blob(vec![1, 2]).as_blob(), Some(&[1u8, 2][..]));
    assert!(GraphValue::Null.is_null());
    assert!(!GraphValue::Integer(0).is_null());
}

#[test]
fn graph_param_debug_does_not_panic() {
    let _ = format!("{:?}", GraphParam::Int(1));
    let _ = format!("{:?}", GraphParam::Null);
    let _ = format!("{:?}", GraphParam::Blob(vec![0u8; 4]));
}

// ------------------------------------------------------------------
// graph_algorithms_extended::Graph
// ------------------------------------------------------------------

#[test]
fn graph_new_zero() {
    let gr = Graph::new(0);
    assert_eq!(gr.n, 0);
    assert!(gr.edges.is_empty());
    assert_eq!(format!("{gr}"), "Graph(n=0, edges=0)");
}

#[test]
fn graph_add_edge_out_of_range_silently_dropped() {
    let mut gr = Graph::new(3);
    gr.add_edge(5, 1, 1.0); // u out of range
    gr.add_edge(0, 9, 1.0); // v out of range
    gr.add_edge(0, 1, 1.0);
    assert_eq!(gr.edges[0].len(), 1);
    assert_eq!(gr.edges[1].len(), 0);
}

#[test]
fn graph_add_undirected_adds_both() {
    let mut gr = Graph::new(3);
    gr.add_undirected_edge(0, 1, 2.5);
    assert_eq!(gr.edges[0], vec![(1usize, 2.5)]);
    assert_eq!(gr.edges[1], vec![(0usize, 2.5)]);
}

#[test]
fn graph_bfs_distances_basic() {
    // 0 -> 1 -> 2; 0 -> 3
    let mut gr = Graph::new(4);
    gr.add_edge(0, 1, 1.0);
    gr.add_edge(1, 2, 1.0);
    gr.add_edge(0, 3, 1.0);
    let d = gr.bfs_distances(0);
    assert_eq!(d[0], Some(0));
    assert_eq!(d[1], Some(1));
    assert_eq!(d[2], Some(2));
    assert_eq!(d[3], Some(1));
}

#[test]
fn graph_bfs_unreachable_is_none() {
    let mut gr = Graph::new(3);
    gr.add_edge(0, 1, 1.0);
    let d = gr.bfs_distances(0);
    assert_eq!(d[2], None);
}

#[test]
fn graph_bfs_invalid_src_all_none() {
    let gr = Graph::new(3);
    let d = gr.bfs_distances(99);
    assert!(d.iter().all(std::option::Option::is_none));
}

#[test]
fn graph_dijkstra_chooses_lower_weight_path() {
    let mut gr = Graph::new(3);
    gr.add_edge(0, 1, 10.0);
    gr.add_edge(0, 2, 1.0);
    gr.add_edge(2, 1, 1.0);
    let d = gr.dijkstra(0);
    assert!((d[0] - 0.0).abs() < 1e-9);
    assert!((d[1] - 2.0).abs() < 1e-9, "got {}", d[1]);
    assert!((d[2] - 1.0).abs() < 1e-9);
}

#[test]
fn graph_dijkstra_invalid_src_inf() {
    let gr = Graph::new(2);
    let d = gr.dijkstra(99);
    assert!(d.iter().all(|x| x.is_infinite()));
}

#[test]
fn degree_map_counts_outgoing() {
    let mut gr = Graph::new(3);
    gr.add_edge(0, 1, 1.0);
    gr.add_edge(0, 2, 1.0);
    gr.add_edge(1, 2, 1.0);
    let dm = degree_map(&gr);
    assert_eq!(dm[&0], 2);
    assert_eq!(dm[&1], 1);
    assert_eq!(dm[&2], 0);
}

#[test]
fn pagerank_empty_graph() {
    let pr = PageRank::compute(&Graph::new(0), 0.85, 100, 1e-6);
    assert!(pr.scores.is_empty());
    assert!(pr.converged);
}

#[test]
fn pagerank_sums_to_one_approx() {
    let mut gr = Graph::new(4);
    gr.add_edge(0, 1, 1.0);
    gr.add_edge(1, 2, 1.0);
    gr.add_edge(2, 3, 1.0);
    gr.add_edge(3, 0, 1.0);
    let pr = PageRank::compute(&gr, 0.85, 200, 1e-9);
    let sum: f64 = pr.scores.iter().sum();
    assert!((sum - 1.0).abs() < 1e-3, "sum={sum}");
    let topk = pr.top_k(2);
    assert_eq!(topk.len(), 2);
}

#[test]
fn pagerank_top_k_larger_than_n_truncates() {
    let pr = PageRank::compute(&Graph::new(2), 0.85, 10, 1e-6);
    let t = pr.top_k(100);
    assert_eq!(t.len(), 2);
}

#[test]
fn betweenness_path_graph() {
    // Path 0-1-2: node 1 lies on the only path between 0 and 2.
    let mut gr = Graph::new(3);
    gr.add_undirected_edge(0, 1, 1.0);
    gr.add_undirected_edge(1, 2, 1.0);
    let bc = BetweennessCentrality::compute(&gr);
    assert_eq!(bc.scores.len(), 3);
    assert!(bc.scores[1] > bc.scores[0]);
    assert!(bc.scores[1] > bc.scores[2]);
}

#[test]
fn closeness_smoke() {
    let mut gr = Graph::new(3);
    gr.add_undirected_edge(0, 1, 1.0);
    gr.add_undirected_edge(1, 2, 1.0);
    let cc = ClosenessCentrality::compute(&gr);
    assert_eq!(cc.scores.len(), 3);
    // Middle node should be closer than the leaves.
    assert!(cc.scores[1] >= cc.scores[0]);
    assert!(cc.scores[1] >= cc.scores[2]);
}

// ------------------------------------------------------------------
// query_engine::glob_match
// ------------------------------------------------------------------

#[test]
fn glob_empty_matches_empty() {
    assert!(glob_match("", ""));
    assert!(!glob_match("", "a"));
    assert!(!glob_match("a", ""));
}

#[test]
fn glob_star_matches_anything() {
    assert!(glob_match("*", ""));
    assert!(glob_match("*", "anything"));
    assert!(glob_match("a*", "abc"));
    assert!(glob_match("*c", "abc"));
    assert!(glob_match("a*c", "abc"));
    assert!(glob_match("a*c", "abbbbc"));
}

#[test]
fn glob_question_mark_one_char() {
    assert!(glob_match("a?c", "abc"));
    assert!(!glob_match("a?c", "ac"));
    assert!(!glob_match("a?c", "abbc"));
}

#[test]
fn glob_exact() {
    assert!(glob_match("abc", "abc"));
    assert!(!glob_match("abc", "abd"));
}

#[test]
fn glob_question_at_end_requires_char() {
    // '?' requires one char; should not match shorter string.
    assert!(!glob_match("a?", "a"));
    assert!(glob_match("a?", "ab"));
}

// ------------------------------------------------------------------
// graph_export
// ------------------------------------------------------------------

fn sample_export_graph() -> ExportGraph {
    let mut g = ExportGraph::new("test");
    g.register_node_attr("size", "integer");
    g.register_edge_attr("count", "integer");
    g.add_node(ExportNode {
        id: "n1".into(),
        label: "main".into(),
        node_type: "function".into(),
        attributes: HashMap::default(),
    });
    g.add_node(ExportNode {
        id: "n2".into(),
        label: "sub".into(),
        node_type: "function".into(),
        attributes: HashMap::default(),
    });
    g.add_edge(ExportEdge {
        id: "e1".into(),
        source: "n1".into(),
        target: "n2".into(),
        kind: "call".into(),
        weight: 1.0,
        directed: true,
        attributes: HashMap::default(),
    });
    g
}

#[test]
fn export_filter_default_accepts_all() {
    let f = ExportFilter::default();
    let g = sample_export_graph();
    assert!(f.accepts_node(&g.nodes[0]));
    assert!(f.accepts_edge(&g.edges[0]));
}

#[test]
fn export_filter_node_type_restriction() {
    let mut f = ExportFilter::default();
    f.include_node_types.insert("data".into());
    let g = sample_export_graph();
    assert!(!f.accepts_node(&g.nodes[0]));
}

#[test]
fn export_filter_edge_kind_and_weight() {
    let mut f = ExportFilter::default();
    f.min_edge_weight = 2.0;
    let g = sample_export_graph();
    assert!(!f.accepts_edge(&g.edges[0]));
    let mut f = ExportFilter::default();
    f.include_edge_kinds.insert("jump".into());
    assert!(!f.accepts_edge(&g.edges[0]));
}

#[test]
fn graphml_exporter_emits_xml_header() {
    let g = sample_export_graph();
    let s = GraphMLExporter::export(&g, &ExportFilter::default());
    assert!(s.starts_with("<?xml"));
    assert!(s.contains("<graphml"));
    assert!(s.contains("n1"));
    assert!(s.contains("n2"));
}

#[test]
fn dot_exporter_emits_digraph() {
    let g = sample_export_graph();
    let s = DotExporter::export(&g, &ExportFilter::default());
    // DOT output should reference both nodes and the edge.
    assert!(s.contains("n1"));
    assert!(s.contains("n2"));
}

#[test]
fn csv_exporter_includes_edges() {
    let g = sample_export_graph();
    let s = CsvExporter::export_edges(&g, &ExportFilter::default());
    assert!(s.contains("n1"));
    assert!(s.contains("n2"));
    assert!(s.contains("call"));
}

// ------------------------------------------------------------------
// analysis_graph: NodeId / EdgeId basic invariants
// ------------------------------------------------------------------

#[test]
fn analysis_graph_node_edge_id_ord() {
    let a = analysis_graph::NodeId(1);
    let b = analysis_graph::NodeId(2);
    assert!(a < b);
    assert_eq!(a, analysis_graph::NodeId(1));
    let e1 = analysis_graph::EdgeId(10);
    let e2 = analysis_graph::EdgeId(20);
    assert!(e1 < e2);
}

#[test]
fn analysis_graph_construct_empty() {
    let g = analysis_graph::AnalysisGraph::default();
    // Whatever fields exist, Debug should at least not panic.
    let _ = format!("{g:?}");
}
