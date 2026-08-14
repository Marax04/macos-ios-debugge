//! Exhaustive blitz tests for rustre-knowledge.

use rustre_knowledge::*;
use rustre_knowledge::knowledge_importer::{
    GraphJson, ImportConfig, ImportStats, NodeJson, EdgeJson, minimal_graph_json,
};
use rustre_knowledge::knowledge_exporter::{ExportConfig, ExportStats};
use rustre_knowledge::knowledge_merger::{ConflictResolution, MergeStats};
use rustre_knowledge::events::EventLog;
use rustre_knowledge::query::*;

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// KnowledgeGraph core
// ---------------------------------------------------------------------------

#[test]
fn graph_new_is_empty() {
    let g = KnowledgeGraph::new();
    assert_eq!(g.node_count(), 0);
    assert_eq!(g.edge_count(), 0);
}

#[test]
fn graph_add_node_overwrites_same_id() {
    let mut g = KnowledgeGraph::new();
    g.add_node(KnowledgeNode::new("a", "label1", "k"));
    g.add_node(KnowledgeNode::new("a", "label2", "k"));
    assert_eq!(g.node_count(), 1);
    assert_eq!(g.nodes["a"].label, "label2");
}

#[test]
fn graph_add_edge_appends() {
    let mut g = KnowledgeGraph::new();
    g.add_edge(KnowledgeEdge::new("a", "b", "calls"));
    g.add_edge(KnowledgeEdge::new("a", "b", "calls"));
    assert_eq!(g.edge_count(), 2);
}

#[test]
fn graph_outgoing_incoming() {
    let mut g = KnowledgeGraph::new();
    g.add_edge(KnowledgeEdge::new("a", "b", "r1"));
    g.add_edge(KnowledgeEdge::new("a", "c", "r2"));
    g.add_edge(KnowledgeEdge::new("c", "a", "r3"));
    assert_eq!(g.outgoing("a").len(), 2);
    assert_eq!(g.incoming("a").len(), 1);
    assert_eq!(g.outgoing("nope").len(), 0);
}

#[test]
fn knowledge_node_new_no_metadata() {
    let n = KnowledgeNode::new("id", "lbl", "kind");
    assert!(n.metadata.is_empty());
}

#[test]
fn knowledge_edge_new_no_weight() {
    let e = KnowledgeEdge::new("a", "b", "rel");
    assert_eq!(e.weight, None);
}

#[test]
fn graph_eq_equal_graphs() {
    let n1 = KnowledgeNode::new("a", "a", "k");
    let n2 = KnowledgeNode::new("a", "a", "k");
    assert_eq!(n1, n2);
}

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

#[test]
fn entity_id_display_is_uuid() {
    let id = EntityId::new();
    let s = id.to_string();
    assert_eq!(s.len(), 36); // standard UUID hyphenated
}

#[test]
fn entity_id_from_uuid_roundtrip() {
    let u = uuid::Uuid::new_v4();
    let id = EntityId::from_uuid(u);
    assert_eq!(id.as_uuid(), u);
}

#[test]
fn entity_kind_all_names() {
    for (k, name) in [
        (EntityKind::Symbol, "symbol"),
        (EntityKind::Function, "function"),
        (EntityKind::Type, "type"),
        (EntityKind::Comment, "comment"),
        (EntityKind::Xref, "xref"),
        (EntityKind::Patch, "patch"),
        (EntityKind::Bookmark, "bookmark"),
        (EntityKind::Trace, "trace"),
        (EntityKind::Tag, "tag"),
    ] {
        assert_eq!(k.name(), name);
        assert_eq!(k.to_string(), name);
    }
}

#[test]
fn function_size_zero_when_end_eq_entry() {
    let f = Function::new(0x1000, 0x1000, "f");
    assert_eq!(f.size(), 0);
    assert!(!f.contains(0x1000));
}

#[test]
fn function_size_saturating_when_end_less_than_entry() {
    // documented as saturating_sub, so size = 0
    let f = Function::new(0x2000, 0x1000, "f");
    assert_eq!(f.size(), 0);
}

#[test]
fn function_contains_boundary() {
    let f = Function::new(10, 20, "f");
    assert!(f.contains(10));
    assert!(f.contains(19));
    assert!(!f.contains(20));
    assert!(!f.contains(9));
}

#[test]
fn entity_snapshot_empty_total_zero() {
    let s = EntitySnapshot::new();
    assert!(s.is_empty());
    assert_eq!(s.total_entities(), 0);
}

#[test]
fn entity_snapshot_total_across_tables() {
    let mut s = EntitySnapshot::new();
    let sym = Symbol::new(1, "a", SymbolScope::Local);
    let f = Function::new(0, 1, "f");
    let t = TypeDef::new(TypeKind::Primitive, "int", "int");
    s.symbols.insert(sym.id, sym);
    s.functions.insert(f.id, f);
    s.types.insert(t.id, t);
    assert_eq!(s.total_entities(), 3);
}

#[test]
fn symbol_round_trip_serde() {
    let sym = Symbol::new(0xdead, "foo", SymbolScope::Global);
    let s = serde_json::to_string(&sym).unwrap();
    let back: Symbol = serde_json::from_str(&s).unwrap();
    assert_eq!(sym, back);
}

#[test]
fn patch_default_not_applied() {
    let p = Patch::new(0x10, vec![1], vec![2]);
    assert!(!p.applied);
    assert!(p.description.is_none());
}

// ---------------------------------------------------------------------------
// EventLog / events
// ---------------------------------------------------------------------------

#[test]
fn event_log_new_empty() {
    let l = EventLog::new();
    assert!(l.is_empty());
    assert_eq!(l.len(), 0);
    assert_eq!(l.next_seq(), 0);
}

#[test]
fn event_log_record_assigns_monotonic_seq() {
    let mut l = EventLog::new();
    let s1 = Symbol::new(1, "a", SymbolScope::Local);
    let s2 = Symbol::new(2, "b", SymbolScope::Local);
    let e1 = l.record("u", None, EventPayload::UpsertSymbol(s1));
    let e2 = l.record("u", None, EventPayload::UpsertSymbol(s2));
    assert_eq!(e1.seq, 0);
    assert_eq!(e2.seq, 1);
}

#[test]
fn event_replay_full_state() {
    let mut l = EventLog::new();
    let s = Symbol::new(1, "a", SymbolScope::Local);
    let id = s.id;
    l.record("u", None, EventPayload::UpsertSymbol(s));
    let snap = l.replay().unwrap();
    assert_eq!(snap.symbols.len(), 1);
    assert!(snap.symbols.contains_key(&id));
}

#[test]
fn event_replay_up_to_filters() {
    let mut l = EventLog::new();
    let s1 = Symbol::new(1, "a", SymbolScope::Local);
    let s2 = Symbol::new(2, "b", SymbolScope::Local);
    l.record("u", None, EventPayload::UpsertSymbol(s1));
    l.record("u", None, EventPayload::UpsertSymbol(s2));
    let s = l.replay_up_to(0).unwrap();
    assert_eq!(s.symbols.len(), 1);
}

#[test]
fn event_remove_missing_returns_notfound() {
    let mut l = EventLog::new();
    let bogus = EntityId::new();
    l.record("u", None, EventPayload::RemoveSymbol(bogus));
    let err = l.replay().unwrap_err();
    match err {
        EventError::NotFound { kind, id } => {
            assert_eq!(kind, EntityKind::Symbol);
            assert_eq!(id, bogus);
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn event_payload_kind_for_all_variants() {
    let sym = Symbol::new(1, "a", SymbolScope::Local);
    let func = Function::new(0, 1, "f");
    let ty = TypeDef::new(TypeKind::Struct, "T", "{}");
    let cm = Comment::new(CommentScope::Function, 0, "u", "x");
    let xr = Xref::new(0, 1, XrefKind::Call);
    let pt = Patch::new(0, vec![], vec![]);
    let bm = Bookmark::new(0, "t");
    let tr = Trace::new(0, 1);
    let tag = Tag::new(EntityId::new(), EntityKind::Symbol, "k", "v");
    let id = EntityId::new();

    assert_eq!(EventPayload::UpsertSymbol(sym).kind(), EntityKind::Symbol);
    assert_eq!(EventPayload::RemoveSymbol(id).kind(), EntityKind::Symbol);
    assert_eq!(EventPayload::UpsertFunction(func).kind(), EntityKind::Function);
    assert_eq!(EventPayload::RemoveFunction(id).kind(), EntityKind::Function);
    assert_eq!(EventPayload::UpsertType(ty).kind(), EntityKind::Type);
    assert_eq!(EventPayload::RemoveType(id).kind(), EntityKind::Type);
    assert_eq!(EventPayload::UpsertComment(cm).kind(), EntityKind::Comment);
    assert_eq!(EventPayload::RemoveComment(id).kind(), EntityKind::Comment);
    assert_eq!(EventPayload::UpsertXref(xr).kind(), EntityKind::Xref);
    assert_eq!(EventPayload::RemoveXref(id).kind(), EntityKind::Xref);
    assert_eq!(EventPayload::UpsertPatch(pt).kind(), EntityKind::Patch);
    assert_eq!(EventPayload::RemovePatch(id).kind(), EntityKind::Patch);
    assert_eq!(EventPayload::UpsertBookmark(bm).kind(), EntityKind::Bookmark);
    assert_eq!(EventPayload::RemoveBookmark(id).kind(), EntityKind::Bookmark);
    assert_eq!(EventPayload::UpsertTrace(tr).kind(), EntityKind::Trace);
    assert_eq!(EventPayload::RemoveTrace(id).kind(), EntityKind::Trace);
    assert_eq!(EventPayload::UpsertTag(tag).kind(), EntityKind::Tag);
    assert_eq!(EventPayload::RemoveTag(id).kind(), EntityKind::Tag);
}

#[test]
fn event_payload_is_upsert_vs_remove() {
    let s = Symbol::new(1, "a", SymbolScope::Local);
    assert!(EventPayload::UpsertSymbol(s).is_upsert());
    assert!(!EventPayload::RemoveSymbol(EntityId::new()).is_upsert());
}

#[test]
fn knowledge_event_with_txn_sets_field() {
    let ev = KnowledgeEvent::new(0, "a", EventPayload::RemoveSymbol(EntityId::new()))
        .with_txn(42);
    assert_eq!(ev.txn, Some(42));
}

#[test]
fn knowledge_event_display_contains_seq_author_kind() {
    let ev = KnowledgeEvent::new(7, "alice",
        EventPayload::UpsertSymbol(Symbol::new(0, "x", SymbolScope::Local)));
    let s = ev.to_string();
    assert!(s.contains('7'));
    assert!(s.contains("alice"));
    assert!(s.contains("symbol"));
    assert!(s.contains("upsert"));
}

// ---------------------------------------------------------------------------
// Store / Transaction
// ---------------------------------------------------------------------------

#[test]
fn store_in_memory_default_empty() {
    let s = KnowledgeStore::in_memory();
    assert_eq!(s.event_count(), 0);
    assert!(s.snapshot().is_empty());
}

#[test]
fn store_commit_increments_event_count() {
    let s = KnowledgeStore::in_memory();
    let mut t = s.begin("u");
    t.upsert_symbol(Symbol::new(1, "x", SymbolScope::Local));
    t.upsert_symbol(Symbol::new(2, "y", SymbolScope::Local));
    let evs = t.commit().unwrap();
    assert_eq!(evs.len(), 2);
    assert_eq!(s.event_count(), 2);
}

#[test]
fn store_empty_commit_is_noop() {
    let s = KnowledgeStore::in_memory();
    let t = s.begin("u");
    let evs = t.commit().unwrap();
    assert!(evs.is_empty());
    assert_eq!(s.event_count(), 0);
}

#[test]
fn store_rollback_drops_pending() {
    let s = KnowledgeStore::in_memory();
    let mut t = s.begin("u");
    t.upsert_symbol(Symbol::new(1, "x", SymbolScope::Local));
    assert_eq!(t.pending(), 1);
    t.rollback();
    assert_eq!(s.event_count(), 0);
}

#[test]
fn store_drop_without_commit_rolls_back() {
    let s = KnowledgeStore::in_memory();
    {
        let mut t = s.begin("u");
        t.upsert_symbol(Symbol::new(1, "x", SymbolScope::Local));
    }
    assert!(s.snapshot().symbols.is_empty());
}

#[test]
fn store_commit_failure_rolls_back_partial() {
    let s = KnowledgeStore::in_memory();
    // Seed
    let mut t = s.begin("u");
    let sym = Symbol::new(1, "a", SymbolScope::Local);
    let id = sym.id;
    t.upsert_symbol(sym);
    t.commit().unwrap();

    // stage: 1 good upsert + 1 bad remove → commit should fail and restore.
    let mut t = s.begin("u");
    t.upsert_symbol(Symbol::new(2, "b", SymbolScope::Local));
    t.remove_symbol(EntityId::new());
    assert!(t.commit().is_err());
    let snap = s.snapshot();
    assert_eq!(snap.symbols.len(), 1);
    assert!(snap.symbols.contains_key(&id));
    assert_eq!(s.event_count(), 1);
}

#[test]
fn store_with_txn_helper_commits() {
    let s = KnowledgeStore::in_memory();
    let r: Result<usize, StoreError> = s.with_txn("u", |t| {
        t.upsert_symbol(Symbol::new(1, "a", SymbolScope::Local));
        Ok(t.pending())
    });
    assert_eq!(r.unwrap(), 1);
    assert_eq!(s.event_count(), 1);
}

#[test]
fn store_with_txn_helper_propagates_user_err() {
    let s = KnowledgeStore::in_memory();
    let r: Result<(), StoreError> = s.with_txn("u", |t| {
        t.upsert_symbol(Symbol::new(1, "a", SymbolScope::Local));
        Err(StoreError::Persist("intentional".into()))
    });
    assert!(r.is_err());
    assert_eq!(s.event_count(), 0); // rolled back
}

#[test]
fn store_transaction_id_unique_per_begin() {
    let s = KnowledgeStore::in_memory();
    let t1 = s.begin("u");
    let t2 = s.begin("u");
    assert_ne!(t1.id(), t2.id());
}

#[test]
fn store_query_returns_value() {
    let s = KnowledgeStore::in_memory();
    let n = s.query(|snap| snap.symbols.len());
    assert_eq!(n, 0);
}

#[test]
fn store_event_log_clone() {
    let s = KnowledgeStore::in_memory();
    let mut t = s.begin("u");
    t.upsert_symbol(Symbol::new(1, "a", SymbolScope::Local));
    t.commit().unwrap();
    let log = s.event_log();
    assert_eq!(log.len(), 1);
}

#[test]
fn store_debug_format_contains_counts() {
    let s = KnowledgeStore::in_memory();
    let d = format!("{s:?}");
    assert!(d.contains("KnowledgeStore"));
}

#[test]
fn store_default_eq_in_memory() {
    let s = KnowledgeStore::default();
    assert_eq!(s.event_count(), 0);
}

#[test]
fn store_null_backend_flush_ok() {
    let s = KnowledgeStore::in_memory();
    assert!(s.flush().is_ok());
}

#[test]
fn null_backend_load_none() {
    let b = NullBackend;
    assert!(b.load().unwrap().is_none());
}

#[test]
fn json_backend_roundtrip_via_open_json() {
    let dir = std::env::temp_dir().join(format!("blitz-rk-{}", uuid::Uuid::new_v4()));
    {
        let s = KnowledgeStore::open_json(&dir).unwrap();
        let mut t = s.begin("u");
        t.upsert_symbol(Symbol::new(0x10, "foo", SymbolScope::Global));
        t.commit().unwrap();
        s.flush().unwrap();
    }
    let s2 = KnowledgeStore::open_json(&dir).unwrap();
    assert_eq!(s2.snapshot().symbols.len(), 1);
    assert_eq!(s2.event_count(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn json_backend_load_missing_returns_none() {
    let dir = std::env::temp_dir().join(format!("blitz-rk-missing-{}", uuid::Uuid::new_v4()));
    let backend = JsonBackend::new(&dir);
    assert!(backend.load().unwrap().is_none());
}

#[test]
fn store_with_backend_restores_next_txn() {
    // simulate restoring
    struct Mem { snap: EntitySnapshot, log: EventLog }
    impl PersistBackend for Mem {
        fn save(&self, _: &EntitySnapshot, _: &EventLog) -> Result<(), StoreError> { Ok(()) }
        fn load(&self) -> Result<Option<(EntitySnapshot, EventLog)>, StoreError> {
            Ok(Some((self.snap.clone(), self.log.clone())))
        }
    }
    let s = KnowledgeStore::in_memory();
    let mut t = s.begin("u");
    t.upsert_symbol(Symbol::new(1, "a", SymbolScope::Local));
    let txn_id_used = t.id();
    t.commit().unwrap();
    let log = s.event_log();
    let snap = s.snapshot();
    let restored = KnowledgeStore::with_backend(Box::new(Mem { snap, log })).unwrap();
    // Next begin should yield an id > txn_id_used because next_txn was recovered.
    let t2 = restored.begin("u");
    assert!(t2.id() > txn_id_used);
}

// ---------------------------------------------------------------------------
// Importer
// ---------------------------------------------------------------------------

fn sample_json_string() -> String {
    minimal_graph_json(
        &[("f1", "main", "function"), ("f2", "helper", "function"), ("t1", "MyType", "type")],
        &[("f1", "f2", "calls"), ("f2", "t1", "references")],
    )
}

#[test]
fn import_basic_counts() {
    let r = import_from_json(&sample_json_string()).unwrap();
    assert_eq!(r.graph.node_count(), 3);
    assert_eq!(r.graph.edge_count(), 2);
    assert_eq!(r.total_imported(), 5);
    assert!(r.is_clean());
}

#[test]
fn import_empty_string_emptysource() {
    let err = import_from_json("").unwrap_err();
    assert!(matches!(err, knowledge_importer::ImportError::EmptySource));
}

#[test]
fn import_invalid_json_returns_json_err() {
    let err = import_from_json("{not valid").unwrap_err();
    assert!(matches!(err, knowledge_importer::ImportError::Json(_)));
}

#[test]
fn import_dangling_edge_skipped_and_warned() {
    let j = minimal_graph_json(&[("a","A","function")], &[("a","b","calls")]);
    let r = import_from_json(&j).unwrap();
    assert_eq!(r.graph.edge_count(), 0);
    assert_eq!(r.stats.edges_skipped, 1);
    assert!(!r.is_clean());
}

#[test]
fn import_filter_node_kinds() {
    let imp = KnowledgeImporter::new().filter_node_kinds(vec!["function".into()]);
    let r = imp.import_json_str(&sample_json_string()).unwrap();
    assert_eq!(r.graph.node_count(), 2);
    assert_eq!(r.stats.nodes_skipped, 1);
}

#[test]
fn import_filter_relations() {
    let imp = KnowledgeImporter::new().filter_relations(vec!["calls".into()]);
    let r = imp.import_json_str(&sample_json_string()).unwrap();
    assert_eq!(r.graph.edge_count(), 1);
}

#[test]
fn import_max_nodes_cap() {
    let imp = KnowledgeImporter::new().max_nodes(2);
    let r = imp.import_json_str(&sample_json_string()).unwrap();
    assert_eq!(r.graph.node_count(), 2);
    assert!(r.stats.warnings.iter().any(|w| w.contains("node limit")));
}

#[test]
fn import_empty_node_id_skipped() {
    let j = r#"{"nodes":[{"id":"","label":"x","kind":"function"}],"edges":[]}"#;
    let r = import_from_json(j).unwrap();
    assert_eq!(r.graph.node_count(), 0);
    assert_eq!(r.stats.nodes_skipped, 1);
}

#[test]
fn import_skip_duplicate_nodes_when_enabled() {
    let j = r#"{"nodes":[
        {"id":"a","label":"A","kind":"function"},
        {"id":"a","label":"A2","kind":"function"}
    ],"edges":[]}"#;
    let cfg = ImportConfig { skip_duplicate_nodes: true, ..Default::default() };
    let imp = KnowledgeImporter::with_config(cfg);
    let r = imp.import_json_str(j).unwrap();
    assert_eq!(r.graph.node_count(), 1);
    assert_eq!(r.graph.nodes["a"].label, "A"); // kept the first
    assert_eq!(r.stats.nodes_skipped, 1);
}

#[test]
fn import_duplicate_nodes_default_overwrite() {
    let j = r#"{"nodes":[
        {"id":"a","label":"A","kind":"function"},
        {"id":"a","label":"A2","kind":"function"}
    ],"edges":[]}"#;
    let r = KnowledgeImporter::new().import_json_str(j).unwrap();
    assert_eq!(r.graph.node_count(), 1);
    assert_eq!(r.graph.nodes["a"].label, "A2");
}

#[test]
fn import_source_json_string_read() {
    let src = ImportSource::JsonString("hi".into());
    assert_eq!(src.read_string().unwrap(), "hi");
    assert_eq!(src.read_bytes().unwrap(), b"hi");
}

#[test]
fn import_source_bytes() {
    let src = ImportSource::Bytes(vec![1, 2, 3]);
    assert_eq!(src.read_bytes().unwrap(), vec![1, 2, 3]);
}

#[test]
fn import_source_in_memory_display() {
    let src = ImportSource::InMemory(vec![1, 2, 3]);
    let s = src.to_string();
    assert!(s.contains("memory:3"));
}

#[test]
fn import_source_bytes_display() {
    let src = ImportSource::Bytes(vec![1, 2]);
    assert!(src.to_string().contains("bytes:2"));
}

#[test]
fn import_source_json_string_invalid_utf8() {
    let bytes = vec![0xff, 0xfe, 0xfd];
    let src = ImportSource::Bytes(bytes);
    let err = src.read_string().unwrap_err();
    assert!(matches!(err, knowledge_importer::ImportError::InvalidStructure(_)));
}

#[test]
fn import_source_json_file_roundtrip() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("rk-blitz-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&path, sample_json_string()).unwrap();
    let r = KnowledgeImporter::new().import_json_file(&path).unwrap();
    assert_eq!(r.graph.node_count(), 3);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn import_source_json_file_missing() {
    let p = std::env::temp_dir().join(format!("definitely-not-here-{}.json", uuid::Uuid::new_v4()));
    let err = KnowledgeImporter::new().import_json_file(&p).unwrap_err();
    assert!(matches!(err, knowledge_importer::ImportError::Io(_)));
}

#[test]
fn import_graph_json_direct() {
    let gj = GraphJson::from_json_str(&sample_json_string()).unwrap();
    let r = KnowledgeImporter::new().import_graph_json(gj).unwrap();
    assert_eq!(r.graph.node_count(), 3);
}

#[test]
fn import_stats_display_format() {
    let s = ImportStats {
        nodes_imported: 5, edges_imported: 3, nodes_skipped: 1,
        edges_skipped: 0, warnings: vec!["w".into()],
    };
    let d = s.to_string();
    assert!(d.contains("nodes:5"));
    assert!(d.contains("edges:3"));
    assert!(d.contains("warnings:1"));
}

#[test]
fn import_result_display_contains_label() {
    let r = import_from_json(&sample_json_string()).unwrap();
    assert!(r.to_string().contains("ImportResult"));
}

#[test]
fn importer_skip_dangling_off_keeps_edge() {
    let j = minimal_graph_json(&[("a","A","f")], &[("a","b","calls")]);
    let imp = KnowledgeImporter::new().skip_dangling(false);
    let r = imp.import_json_str(&j).unwrap();
    assert_eq!(r.graph.edge_count(), 1);
}

#[test]
fn importer_debug_includes_skip_dangling() {
    let imp = KnowledgeImporter::new();
    let d = format!("{imp:?}");
    assert!(d.contains("KnowledgeImporter"));
}

#[test]
fn import_graph_json_missing_nodes_field_errs() {
    // nodes is required (no #[serde(default)])
    let err = GraphJson::from_json_str(r#"{"edges":[]}"#);
    assert!(err.is_err());
}

// ---------------------------------------------------------------------------
// Exporter
// ---------------------------------------------------------------------------

fn sample_graph() -> KnowledgeGraph {
    let mut g = KnowledgeGraph::new();
    g.add_node(KnowledgeNode::new("f1", "main", "function"));
    g.add_node(KnowledgeNode::new("f2", "helper", "function"));
    g.add_node(KnowledgeNode::new("t1", "MyType", "type"));
    g.add_edge(KnowledgeEdge { from: "f1".into(), to: "f2".into(), relation: "calls".into(), weight: Some(3) });
    g.add_edge(KnowledgeEdge { from: "f2".into(), to: "t1".into(), relation: "references".into(), weight: None });
    g
}

#[test]
fn export_json_compact_no_newlines_in_body() {
    let r = export_to_json(&sample_graph()).unwrap();
    let s = r.as_str().unwrap();
    assert!(!s.contains("\n  ")); // not pretty-indented
    assert!(s.contains("\"nodes\""));
}

#[test]
fn export_json_pretty_has_indentation() {
    let r = KnowledgeExporter::new().export(&sample_graph(), ExportFormat::JsonPretty).unwrap();
    let s = r.as_str().unwrap();
    assert!(s.contains('\n'));
}

#[test]
fn export_graphml_contains_xml() {
    let r = KnowledgeExporter::new().export(&sample_graph(), ExportFormat::GraphMl).unwrap();
    let s = r.as_str().unwrap();
    assert!(s.contains("<?xml"));
    assert!(s.contains("<graphml"));
}

#[test]
fn export_dot_contains_arrows() {
    let r = KnowledgeExporter::new().export(&sample_graph(), ExportFormat::Dot).unwrap();
    let s = r.as_str().unwrap();
    assert!(s.contains("digraph"));
    assert!(s.contains("->"));
}

#[test]
fn export_csv_has_two_sections() {
    let r = KnowledgeExporter::new().export(&sample_graph(), ExportFormat::Csv).unwrap();
    let s = r.as_str().unwrap();
    assert!(s.contains("id,label,kind"));
    assert!(s.contains("from,to,relation,weight"));
}

#[test]
fn export_gexf_contains_gexf_tag() {
    let r = KnowledgeExporter::new().export(&sample_graph(), ExportFormat::Gexf).unwrap();
    let s = r.as_str().unwrap();
    assert!(s.contains("<gexf"));
}

#[test]
fn export_format_names_and_extensions() {
    assert_eq!(ExportFormat::JsonCompact.extension(), "json");
    assert_eq!(ExportFormat::JsonPretty.extension(), "json");
    assert_eq!(ExportFormat::GraphMl.extension(), "graphml");
    assert_eq!(ExportFormat::Dot.extension(), "dot");
    assert_eq!(ExportFormat::Csv.extension(), "csv");
    assert_eq!(ExportFormat::Gexf.extension(), "gexf");
}

#[test]
fn export_format_mime_types() {
    assert_eq!(ExportFormat::JsonCompact.mime_type(), "application/json");
    assert_eq!(ExportFormat::GraphMl.mime_type(), "application/xml");
    assert_eq!(ExportFormat::Gexf.mime_type(), "application/xml");
    assert_eq!(ExportFormat::Dot.mime_type(), "text/vnd.graphviz");
    assert_eq!(ExportFormat::Csv.mime_type(), "text/csv");
}

#[test]
fn export_format_is_json_xml() {
    assert!(ExportFormat::JsonCompact.is_json());
    assert!(ExportFormat::JsonPretty.is_json());
    assert!(!ExportFormat::Dot.is_json());
    assert!(ExportFormat::GraphMl.is_xml());
    assert!(ExportFormat::Gexf.is_xml());
    assert!(!ExportFormat::Csv.is_xml());
}

#[test]
fn export_format_display() {
    assert_eq!(ExportFormat::Dot.to_string(), "dot");
}

#[test]
fn export_filter_node_kinds_drops_edges_with_dropped_endpoint() {
    let g = sample_graph();
    let exp = KnowledgeExporter::new().filter_node_kinds(vec!["function".into()]);
    let r = exp.export(&g, ExportFormat::JsonCompact).unwrap();
    assert_eq!(r.stats.nodes_exported, 2);
    // edge f2 -> t1 should be dropped because t1 was filtered out
    assert_eq!(r.stats.edges_exported, 1);
}

#[test]
fn export_include_metadata_false() {
    let g = sample_graph();
    let r = KnowledgeExporter::new().include_metadata(false)
        .export(&g, ExportFormat::JsonPretty).unwrap();
    let s = r.as_str().unwrap();
    assert!(s.contains("\"metadata\": {}"));
}

#[test]
fn export_with_config_no_weights_dot() {
    let cfg = ExportConfig { include_weights: false, ..Default::default() };
    let r = KnowledgeExporter::with_config(cfg).export(&sample_graph(), ExportFormat::Dot).unwrap();
    let s = r.as_str().unwrap();
    // No "(3)" weight annotation
    assert!(!s.contains("(3)"));
}

#[test]
fn export_stats_total_bytes_matches_data_len() {
    let r = export_to_json(&sample_graph()).unwrap();
    assert_eq!(r.stats.output_bytes, r.size_bytes());
}

#[test]
fn export_stats_display() {
    let s = ExportStats {
        nodes_exported: 1, edges_exported: 2, nodes_skipped: 0, edges_skipped: 0,
        output_bytes: 99,
    };
    assert!(s.to_string().contains("bytes:99"));
}

#[test]
fn export_result_display_format() {
    let r = export_to_json(&sample_graph()).unwrap();
    assert!(r.to_string().contains("ExportResult"));
}

#[test]
fn export_result_as_str_valid_utf8() {
    let r = export_to_json(&sample_graph()).unwrap();
    assert!(r.as_str().is_some());
}

#[test]
fn export_to_file_writes_disk() {
    let g = sample_graph();
    let p = std::env::temp_dir().join(format!("rk-export-{}.json", uuid::Uuid::new_v4()));
    let r = KnowledgeExporter::new().export_to_file(&g, &p, ExportFormat::JsonCompact).unwrap();
    let on_disk = std::fs::read(&p).unwrap();
    assert_eq!(on_disk, r.data);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn exporter_debug() {
    let e = KnowledgeExporter::new();
    let d = format!("{e:?}");
    assert!(d.contains("KnowledgeExporter"));
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn export_then_import_preserves_counts() {
    let g = sample_graph();
    let r = export_to_json(&g).unwrap();
    let s = r.as_str().unwrap();
    let back = import_from_json(s).unwrap();
    assert_eq!(back.graph.node_count(), g.node_count());
    assert_eq!(back.graph.edge_count(), g.edge_count());
}

#[test]
fn export_then_import_preserves_edge_weights() {
    let g = sample_graph();
    let s = export_to_json(&g).unwrap();
    let back = import_from_json(s.as_str().unwrap()).unwrap();
    // Find the calls edge — must keep weight 3
    let e = back.graph.edges.iter().find(|e| e.relation == "calls").unwrap();
    assert_eq!(e.weight, Some(3));
}

// ---------------------------------------------------------------------------
// Merger
// ---------------------------------------------------------------------------

fn node(id: &str, kind: &str) -> KnowledgeNode {
    KnowledgeNode::new(id, id, kind)
}

fn left_g() -> KnowledgeGraph {
    let mut g = KnowledgeGraph::new();
    g.add_node(node("a", "function"));
    g.add_node(node("b", "function"));
    g.add_node(node("c", "type"));
    g.add_edge(KnowledgeEdge::new("a", "b", "calls"));
    g.add_edge(KnowledgeEdge::new("b", "c", "uses"));
    g
}

fn right_g() -> KnowledgeGraph {
    let mut g = KnowledgeGraph::new();
    g.add_node(node("b", "function"));
    g.add_node(node("d", "variable"));
    g.add_node(node("e", "function"));
    g.add_edge(KnowledgeEdge::new("b", "d", "reads"));
    g.add_edge(KnowledgeEdge::new("d", "e", "references"));
    g
}

#[test]
fn merge_union_counts() {
    let r = merge_graphs(&left_g(), &right_g()).unwrap();
    assert_eq!(r.graph.node_count(), 5);
    assert_eq!(r.graph.edge_count(), 4);
}

#[test]
fn merge_both_empty_errors() {
    let e = merge_graphs(&KnowledgeGraph::new(), &KnowledgeGraph::new());
    assert!(matches!(e, Err(knowledge_merger::MergeError::EmptyInput)));
}

#[test]
fn merge_one_empty_returns_other_size() {
    let r = merge_graphs(&left_g(), &KnowledgeGraph::new()).unwrap();
    assert_eq!(r.graph.node_count(), 3);
}

#[test]
fn merge_strategy_names() {
    use MergeStrategy::*;
    assert_eq!(LeftWins.name(), "left-wins");
    assert_eq!(RightWins.name(), "right-wins");
    assert_eq!(Union.name(), "union");
    assert_eq!(Intersection.name(), "intersection");
    assert_eq!(LeftMinus.name(), "left-minus");
    assert_eq!(Semantic.name(), "semantic");
}

#[test]
fn merge_strategy_can_grow() {
    assert!(MergeStrategy::Union.can_grow());
    assert!(MergeStrategy::Semantic.can_grow());
    assert!(!MergeStrategy::LeftWins.can_grow());
    assert!(!MergeStrategy::Intersection.can_grow());
}

#[test]
fn merge_left_wins_keeps_left_node_data() {
    let mut l = KnowledgeGraph::new();
    let mut n = KnowledgeNode::new("a", "left-label", "k");
    n.metadata.insert("src".into(), serde_json::json!("L"));
    l.add_node(n);
    let mut r = KnowledgeGraph::new();
    let mut n2 = KnowledgeNode::new("a", "right-label", "k");
    n2.metadata.insert("src".into(), serde_json::json!("R"));
    r.add_node(n2);

    let res = KnowledgeMerger::new(MergeStrategy::LeftWins).merge(&l, &r).unwrap();
    assert_eq!(res.graph.nodes["a"].label, "left-label");
    assert_eq!(res.left_wins_count(), 1);
}

#[test]
fn merge_right_wins_keeps_right_node_data() {
    let mut l = KnowledgeGraph::new();
    l.add_node(KnowledgeNode::new("a", "L", "k"));
    let mut r = KnowledgeGraph::new();
    r.add_node(KnowledgeNode::new("a", "R", "k"));
    let res = KnowledgeMerger::new(MergeStrategy::RightWins).merge(&l, &r).unwrap();
    assert_eq!(res.graph.nodes["a"].label, "R");
    assert_eq!(res.right_wins_count(), 1);
}

#[test]
fn merge_intersection_only_shared() {
    let r = KnowledgeMerger::new(MergeStrategy::Intersection)
        .merge(&left_g(), &right_g()).unwrap();
    assert_eq!(r.graph.node_count(), 1);
    assert!(r.graph.nodes.contains_key("b"));
}

#[test]
fn merge_left_minus() {
    let r = KnowledgeMerger::new(MergeStrategy::LeftMinus)
        .merge(&left_g(), &right_g()).unwrap();
    assert_eq!(r.graph.node_count(), 2);
    assert!(r.graph.nodes.contains_key("a"));
    assert!(r.graph.nodes.contains_key("c"));
}

#[test]
fn merge_semantic_chooses_richer_metadata() {
    let mut l = KnowledgeGraph::new();
    let mut ln = KnowledgeNode::new("a", "L", "k");
    ln.metadata.insert("x".into(), serde_json::json!(1));
    ln.metadata.insert("y".into(), serde_json::json!(2));
    l.add_node(ln);
    let mut r = KnowledgeGraph::new();
    r.add_node(KnowledgeNode::new("a", "R", "k")); // 0 metadata
    let res = KnowledgeMerger::new(MergeStrategy::Semantic).merge(&l, &r).unwrap();
    assert_eq!(res.graph.nodes["a"].label, "L");
    assert_eq!(res.left_wins_count(), 1);
}

#[test]
fn merge_union_metadata_merged() {
    let mut l = KnowledgeGraph::new();
    let mut ln = KnowledgeNode::new("a", "L", "k");
    ln.metadata.insert("only_left".into(), serde_json::json!(1));
    l.add_node(ln);
    let mut r = KnowledgeGraph::new();
    let mut rn = KnowledgeNode::new("a", "R", "k");
    rn.metadata.insert("only_right".into(), serde_json::json!(2));
    r.add_node(rn);
    let res = merge_graphs(&l, &r).unwrap();
    let merged = &res.graph.nodes["a"];
    assert!(merged.metadata.contains_key("only_left"));
    assert!(merged.metadata.contains_key("only_right"));
    assert_eq!(res.conflicts.len(), 1);
    assert_eq!(res.conflicts[0].resolution, ConflictResolution::MergedMetadata);
}

#[test]
fn merge_edges_dedup_default() {
    let mut l = KnowledgeGraph::new();
    l.add_node(node("a", "f"));
    l.add_node(node("b", "f"));
    l.add_edge(KnowledgeEdge::new("a", "b", "calls"));
    let mut r = KnowledgeGraph::new();
    r.add_node(node("a", "f"));
    r.add_node(node("b", "f"));
    r.add_edge(KnowledgeEdge::new("a", "b", "calls"));
    let res = merge_graphs(&l, &r).unwrap();
    assert_eq!(res.graph.edge_count(), 1);
    assert_eq!(res.stats.duplicate_edges, 1);
}

#[test]
fn merge_edges_no_dedup_keeps_duplicates() {
    let mut l = KnowledgeGraph::new();
    l.add_node(node("a", "f"));
    l.add_node(node("b", "f"));
    l.add_edge(KnowledgeEdge::new("a", "b", "calls"));
    let mut r = KnowledgeGraph::new();
    r.add_node(node("a", "f"));
    r.add_node(node("b", "f"));
    r.add_edge(KnowledgeEdge::new("a", "b", "calls"));
    let res = KnowledgeMerger::new(MergeStrategy::Union).dedup_edges(false).merge(&l, &r).unwrap();
    assert_eq!(res.graph.edge_count(), 2);
}

#[test]
fn merge_drop_edges_with_missing_endpoint_default() {
    // Build an intersection that should drop edges whose endpoints aren't shared.
    let r = KnowledgeMerger::new(MergeStrategy::Intersection).merge(&left_g(), &right_g()).unwrap();
    // Only 'b' is shared; no edges with both ends in {b}.
    assert_eq!(r.graph.edge_count(), 0);
}

#[test]
fn merge_allow_dangling_keeps_edges() {
    let mut l = KnowledgeGraph::new();
    l.add_node(node("a", "f"));
    l.add_edge(KnowledgeEdge::new("a", "ghost", "calls"));
    let mut r = KnowledgeGraph::new();
    r.add_node(node("z", "f"));
    let res = KnowledgeMerger::new(MergeStrategy::Union).allow_dangling(true).merge(&l, &r).unwrap();
    assert!(res.graph.edges.iter().any(|e| e.to == "ghost"));
}

#[test]
fn merge_many_single_input() {
    let r = KnowledgeMerger::new(MergeStrategy::Union).merge_many(&[left_g()]).unwrap();
    assert_eq!(r.graph.node_count(), 3);
}

#[test]
fn merge_many_empty_errors() {
    let e = KnowledgeMerger::new(MergeStrategy::Union).merge_many(&[]);
    assert!(matches!(e, Err(knowledge_merger::MergeError::EmptyInput)));
}

#[test]
fn merge_many_multiple_graphs() {
    let g3 = {
        let mut g = KnowledgeGraph::new();
        g.add_node(node("z", "function"));
        g
    };
    let r = KnowledgeMerger::new(MergeStrategy::Union)
        .merge_many(&[left_g(), right_g(), g3]).unwrap();
    assert!(r.graph.nodes.contains_key("z"));
}

#[test]
fn merge_default_strategy_union() {
    let m = KnowledgeMerger::default();
    let r = m.merge(&left_g(), &right_g()).unwrap();
    assert_eq!(r.strategy, MergeStrategy::Union);
}

#[test]
fn merge_result_display_format() {
    let r = merge_graphs(&left_g(), &right_g()).unwrap();
    let s = r.to_string();
    assert!(s.contains("MergeResult"));
    assert!(s.contains("union"));
}

#[test]
fn merge_stats_display_format() {
    let s = MergeStats { left_nodes: 1, right_nodes: 2, result_nodes: 3, ..Default::default() };
    let d = s.to_string();
    assert!(d.contains("left(n=1"));
}

#[test]
fn conflict_resolution_display() {
    assert_eq!(ConflictResolution::TookLeft.to_string(), "took-left");
    assert_eq!(ConflictResolution::TookRight.to_string(), "took-right");
    assert_eq!(ConflictResolution::MergedMetadata.to_string(), "merged-metadata");
    assert_eq!(ConflictResolution::Dropped.to_string(), "dropped");
}

#[test]
fn merger_debug() {
    let m = KnowledgeMerger::new(MergeStrategy::Union);
    assert!(format!("{m:?}").contains("union"));
}

// ---------------------------------------------------------------------------
// Query helpers
// ---------------------------------------------------------------------------

fn seed_snap() -> EntitySnapshot {
    let mut s = EntitySnapshot::new();
    let s1 = Symbol::new(0x1000, "main", SymbolScope::Global);
    let s2 = Symbol::new(0x2000, "helper", SymbolScope::Local);
    let f1 = Function::new(0x1000, 0x1100, "main");
    let f2 = Function::new(0x2000, 0x2080, "helper");
    let ty = TypeDef::new(TypeKind::Struct, "Foo", "{}");
    let cm = Comment::new(CommentScope::Instruction, 0x1004, "u", "hi");
    let cm2 = Comment::new(CommentScope::Function, 0x1004, "u", "fn hdr");
    let xr = Xref::new(0x1004, 0x2000, XrefKind::Call);
    let xr2 = Xref::new(0x1008, 0x2000, XrefKind::Jump);
    let mut pt = Patch::new(0x1010, vec![0x90], vec![0xCC]);
    pt.applied = true;
    let pt2 = Patch::new(0x1020, vec![0], vec![0]);
    let bm = Bookmark::new(0x1020, "look");
    let tr = Trace::new(0x1000, 100);
    let tr2 = Trace::new(0x1000, 200);
    let tag = Tag::new(s1.id, EntityKind::Symbol, "cat", "entry");
    let tag2 = Tag::new(s2.id, EntityKind::Symbol, "cat", "helper");

    s.symbols.insert(s1.id, s1);
    s.symbols.insert(s2.id, s2);
    s.functions.insert(f1.id, f1);
    s.functions.insert(f2.id, f2);
    s.types.insert(ty.id, ty);
    s.comments.insert(cm.id, cm);
    s.comments.insert(cm2.id, cm2);
    s.xrefs.insert(xr.id, xr);
    s.xrefs.insert(xr2.id, xr2);
    s.patches.insert(pt.id, pt);
    s.patches.insert(pt2.id, pt2);
    s.bookmarks.insert(bm.id, bm);
    s.traces.insert(tr.id, tr);
    s.traces.insert(tr2.id, tr2);
    s.tags.insert(tag.id, tag);
    s.tags.insert(tag2.id, tag2);
    s
}

#[test]
fn q_find_symbol_by_addr() {
    let s = seed_snap();
    assert_eq!(find_symbol_by_addr(&s, 0x1000).unwrap().name, "main");
    assert!(find_symbol_by_addr(&s, 0xDEAD).is_none());
}

#[test]
fn q_find_symbol_by_name() {
    let s = seed_snap();
    assert!(find_symbol_by_name(&s, "helper").is_some());
    assert!(find_symbol_by_name(&s, "missing").is_none());
}

#[test]
fn q_symbols_in_range_half_open() {
    let s = seed_snap();
    let v = symbols_in_range(&s, 0x1000, 0x2000);
    assert_eq!(v.len(), 1);
    let v2 = symbols_in_range(&s, 0x1000, 0x2001);
    assert_eq!(v2.len(), 2);
}

#[test]
fn q_function_by_entry() {
    let s = seed_snap();
    assert_eq!(find_function_by_entry(&s, 0x1000).unwrap().name, "main");
}

#[test]
fn q_function_containing() {
    let s = seed_snap();
    assert_eq!(function_containing(&s, 0x1050).unwrap().name, "main");
    assert!(function_containing(&s, 0x9999).is_none());
}

#[test]
fn q_functions_in_range() {
    let s = seed_snap();
    assert_eq!(functions_in_range(&s, 0, 0x10000).len(), 2);
}

#[test]
fn q_find_type_by_name() {
    let s = seed_snap();
    assert!(find_type_by_name(&s, "Foo").is_some());
    assert!(find_type_by_name(&s, "Bar").is_none());
}

#[test]
fn q_comments_at_and_scoped() {
    let s = seed_snap();
    assert_eq!(comments_at(&s, 0x1004).len(), 2);
    assert_eq!(comments_at_scope(&s, 0x1004, CommentScope::Instruction).len(), 1);
    assert_eq!(comments_at_scope(&s, 0x1004, CommentScope::Function).len(), 1);
    assert_eq!(comments_at_scope(&s, 0x1004, CommentScope::Type).len(), 0);
}

#[test]
fn q_xrefs_to_from_kind() {
    let s = seed_snap();
    assert_eq!(xrefs_to(&s, 0x2000).len(), 2);
    assert_eq!(xrefs_from(&s, 0x1004).len(), 1);
    assert_eq!(xrefs_of_kind(&s, XrefKind::Call).len(), 1);
    assert_eq!(xrefs_of_kind(&s, XrefKind::Jump).len(), 1);
    assert_eq!(xrefs_of_kind(&s, XrefKind::Read).len(), 0);
}

#[test]
fn q_patches_and_applied() {
    let s = seed_snap();
    assert_eq!(patches_at(&s, 0x1010).len(), 1);
    assert_eq!(applied_patches(&s).len(), 1);
}

#[test]
fn q_bookmarks_at() {
    let s = seed_snap();
    assert_eq!(bookmarks_at(&s, 0x1020).len(), 1);
    assert_eq!(bookmarks_at(&s, 0).len(), 0);
}

#[test]
fn q_traces_in_window_half_open() {
    let s = seed_snap();
    assert_eq!(traces_in_window(&s, 0, 200).len(), 1);
    assert_eq!(traces_in_window(&s, 0, 201).len(), 2);
    assert_eq!(traces_at(&s, 0x1000).len(), 2);
}

#[test]
fn q_tags_for_and_key() {
    let s = seed_snap();
    let sym = find_symbol_by_addr(&s, 0x1000).unwrap();
    assert_eq!(tags_for(&s, sym.id).len(), 1);
    assert_eq!(tags_with_key(&s, "cat").len(), 2);
    assert_eq!(tags_with_key(&s, "no").len(), 0);
}

#[test]
fn q_count_by_kind_all() {
    let s = seed_snap();
    assert_eq!(count(&s, EntityKind::Symbol), 2);
    assert_eq!(count(&s, EntityKind::Function), 2);
    assert_eq!(count(&s, EntityKind::Type), 1);
    assert_eq!(count(&s, EntityKind::Comment), 2);
    assert_eq!(count(&s, EntityKind::Xref), 2);
    assert_eq!(count(&s, EntityKind::Patch), 2);
    assert_eq!(count(&s, EntityKind::Bookmark), 1);
    assert_eq!(count(&s, EntityKind::Trace), 2);
    assert_eq!(count(&s, EntityKind::Tag), 2);
}

// ---------------------------------------------------------------------------
// Adversarial / boundary
// ---------------------------------------------------------------------------

#[test]
fn import_max_address_u64() {
    // Just ensure values like u64::MAX round trip via the importer's address-agnostic graph.
    let j = format!(
        r#"{{"nodes":[{{"id":"x","label":"x","kind":"function","metadata":{{"addr":{}}}}}],"edges":[]}}"#,
        u64::MAX
    );
    let r = import_from_json(&j).unwrap();
    assert_eq!(r.graph.node_count(), 1);
}

#[test]
fn function_size_at_u64_max() {
    let f = Function::new(0, u64::MAX, "f");
    assert_eq!(f.size(), u64::MAX);
}

#[test]
fn entity_kind_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<EntityKind>();
    assert_send_sync::<EntityId>();
    assert_send_sync::<Symbol>();
    assert_send_sync::<KnowledgeGraph>();
    assert_send_sync::<KnowledgeStore>();
}

#[test]
fn import_huge_graph_under_max_edges() {
    let mut nodes: Vec<(String, String, String)> = (0..200)
        .map(|i| (format!("n{i}"), format!("L{i}"), "function".to_string()))
        .collect();
    let mut edges: Vec<(String, String, String)> = Vec::new();
    for i in 0..199 {
        edges.push((format!("n{i}"), format!("n{}", i+1), "calls".to_string()));
    }
    let node_refs: Vec<(&str,&str,&str)> = nodes.iter_mut().map(|(a,b,c)| (a.as_str(), b.as_str(), c.as_str())).collect();
    let edge_refs: Vec<(&str,&str,&str)> = edges.iter().map(|(a,b,c)| (a.as_str(), b.as_str(), c.as_str())).collect();
    let j = minimal_graph_json(&node_refs, &edge_refs);
    let cfg = ImportConfig { max_edges: 10, ..Default::default() };
    let r = KnowledgeImporter::with_config(cfg).import_json_str(&j).unwrap();
    assert_eq!(r.graph.edge_count(), 10);
}

#[test]
fn knowledge_node_metadata_preserved_through_export_import() {
    let mut g = KnowledgeGraph::new();
    let mut n = KnowledgeNode::new("a", "A", "function");
    n.metadata.insert("k".into(), serde_json::json!("v"));
    g.add_node(n);
    g.add_edge(KnowledgeEdge::new("a", "a", "self"));
    let r = export_to_json(&g).unwrap();
    let back = import_from_json(r.as_str().unwrap()).unwrap();
    assert_eq!(back.graph.nodes["a"].metadata.get("k").unwrap(), &serde_json::json!("v"));
}

#[test]
fn graph_json_node_edge_fields_defaults() {
    // metadata optional, weight optional
    let j = r#"{"nodes":[{"id":"a","label":"A","kind":"function"}],"edges":[{"from":"a","to":"a","relation":"r"}]}"#;
    let gj = GraphJson::from_json_str(j).unwrap();
    assert!(gj.nodes[0].metadata.is_empty());
    assert!(gj.edges[0].weight.is_none());
}

#[test]
fn nodejson_edgejson_serializable() {
    let n = NodeJson { id: "a".into(), label: "A".into(), kind: "f".into(), metadata: HashMap::new() };
    let e = EdgeJson { from: "a".into(), to: "b".into(), relation: "r".into(), weight: Some(5) };
    let _ = serde_json::to_string(&n).unwrap();
    let _ = serde_json::to_string(&e).unwrap();
}
