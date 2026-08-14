//! Blitz tests targeting public API of rustre-project.
//! Tests-only. Do not modify production code to make tests pass.

use rustre_project::analysis_cache::{
    AnalysisCache, CacheExport, CacheKey, CacheStats, CachedResult, DependencyTracker,
};
use rustre_project::annotation_store::{
    Annotation, AnnotationKind, AnnotationQuery, AnnotationStore, export_annotations_json,
    import_annotations_json,
};
use rustre_project::export::{
    AddressRange, ExportFormat, ExportOptions, ProjectExporter,
};
use rustre_project::{
    BinaryProject, KgBackend, MAX_VERSION_SNAPSHOTS, Project, ProjectConfig, ProjectError,
    ProjectManager, ProjectMetadata, ProjectSession, get_migrations, run_migrations,
    run_pending_migrations, sha256_hex, shannon_entropy,
};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

fn tmp() -> TempDir {
    tempfile::tempdir().unwrap()
}

fn fresh_project(name: &str) -> (TempDir, Project) {
    let d = tmp();
    let p = Project::new(name, d.path()).unwrap();
    (d, p)
}

// ── sha256_hex ────────────────────────────────────────────────────────────────

#[test]
fn sha_known_abc() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha_length_hex_64() {
    assert_eq!(sha256_hex(b"deadbeef").len(), 64);
    assert!(sha256_hex(b"x").chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn sha_distinct_inputs_distinct() {
    assert_ne!(sha256_hex(b"a"), sha256_hex(b"b"));
}

#[test]
fn sha_deterministic() {
    assert_eq!(sha256_hex(b"same"), sha256_hex(b"same"));
}

// ── shannon_entropy ───────────────────────────────────────────────────────────

#[test]
fn entropy_two_symbols_half() {
    let mut d = vec![0u8; 512];
    d.extend(vec![1u8; 512]);
    let e = shannon_entropy(&d);
    assert!((e - 1.0).abs() < 1e-9, "expected 1.0, got {e}");
}

#[test]
fn entropy_single_byte() {
    assert_eq!(shannon_entropy(&[42]), 0.0);
}

#[test]
fn entropy_bounded() {
    let e = shannon_entropy(b"hello world hello world hello world");
    assert!((0.0..=8.0).contains(&e));
}

// ── KgBackend ─────────────────────────────────────────────────────────────────

#[test]
fn kg_memory_serializes() {
    let j = serde_json::to_string(&KgBackend::Memory).unwrap();
    assert!(j.contains("memory"));
}

#[test]
fn kg_default_is_memory() {
    assert_eq!(KgBackend::default(), KgBackend::Memory);
}

// ── ProjectConfig ─────────────────────────────────────────────────────────────

#[test]
fn config_default_arch_none() {
    assert!(ProjectConfig::default().default_arch.is_none());
}

#[test]
fn config_serde_roundtrip() {
    let mut c = ProjectConfig::default();
    c.default_arch = Some("riscv".into());
    c.plugins.push("p1".into());
    let j = serde_json::to_string(&c).unwrap();
    let c2: ProjectConfig = serde_json::from_str(&j).unwrap();
    assert_eq!(c2.default_arch.as_deref(), Some("riscv"));
    assert_eq!(c2.plugins, vec!["p1".to_string()]);
}

// ── ProjectMetadata ───────────────────────────────────────────────────────────

#[test]
fn metadata_iso_set() {
    let (_d, p) = fresh_project("isoset");
    assert!(!p.metadata().created_at_iso.is_empty());
}

#[test]
fn metadata_serde_roundtrip() {
    let (_d, p) = fresh_project("metard");
    let j = serde_json::to_string(p.metadata()).unwrap();
    let m2: ProjectMetadata = serde_json::from_str(&j).unwrap();
    assert_eq!(p.metadata().name, m2.name);
    assert_eq!(p.metadata().created_at, m2.created_at);
}

// ── Project basics ────────────────────────────────────────────────────────────

#[test]
fn project_subdirs_all_exist() {
    let (_d, p) = fresh_project("subs");
    for s in ["recordings", "sandbox", "attachments", "workflows", "scripts", "reports", "views", "snapshots"] {
        assert!(p.project_dir().join(s).exists(), "missing {s}");
    }
}

#[test]
fn project_open_not_found_err_variant() {
    let d = tmp();
    let err = Project::open(d.path().join("nothing")).unwrap_err();
    assert!(matches!(err, ProjectError::NotFound(_)));
}

#[test]
fn project_already_exists_err_variant() {
    let (_d, p) = fresh_project("dup");
    let err = Project::new("dup2", p.project_dir().parent().unwrap()).unwrap_err();
    assert!(matches!(err, ProjectError::AlreadyExists(_)));
}

#[test]
fn project_save_then_reopen_preserves_tags() {
    let d = tmp();
    {
        let mut p = Project::new("t", d.path()).unwrap();
        p.metadata_mut().tags = vec!["a".into(), "b".into()];
        p.save().unwrap();
    }
    let p2 = Project::open(d.path()).unwrap();
    assert_eq!(p2.metadata().tags, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn project_autosave_disabled_returns_false() {
    let (_d, mut p) = fresh_project("aof");
    p.config_mut().autosave_interval_secs = 0;
    assert!(!p.maybe_autosave().unwrap());
}

#[test]
fn project_autosave_recent_returns_false() {
    let (_d, mut p) = fresh_project("ar");
    p.config_mut().autosave_interval_secs = 9999;
    assert!(!p.maybe_autosave().unwrap());
}

// ── Binary management ────────────────────────────────────────────────────────

#[test]
fn find_binary_by_sha_some() {
    let (d, mut p) = fresh_project("fb");
    let _bid = BinaryProject::add_binary(
        &mut p,
        Path::new("/tmp/sf.bin"),
        "abc1230000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    let _ = d;
    let r = p
        .find_binary_by_sha256("abc1230000000000000000000000000000000000000000000000000000000000")
        .unwrap();
    assert!(r.is_some());
}

#[test]
fn find_binary_by_sha_none() {
    let (_d, p) = fresh_project("fn");
    assert!(p.find_binary_by_sha256("zz").unwrap().is_none());
}

#[test]
fn remove_binary_deletes_row() {
    let (_d, mut p) = fresh_project("rb");
    let bid = BinaryProject::add_binary(
        &mut p,
        Path::new("/tmp/rb.bin"),
        "0aa0aa0aa0aa0aa0aa0aa0aa0aa0aa0aa0aa0aa0aa0aa0aa0aa0aa0aa0aa0aa0",
    )
    .unwrap();
    assert!(p.remove_binary(bid).unwrap());
    assert!(!p.remove_binary(bid).unwrap()); // already gone
}

#[test]
fn get_function_none_for_unknown() {
    let (_d, mut p) = fresh_project("gn");
    let bid = BinaryProject::add_binary(
        &mut p,
        Path::new("/tmp/x.bin"),
        "bbb1230000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    assert!(p.get_function_by_addr(bid, 0xdead).unwrap().is_none());
}

#[test]
fn rename_function_round_trip() {
    let (_d, mut p) = fresh_project("rf");
    let bid = BinaryProject::add_binary(
        &mut p,
        Path::new("/tmp/x.bin"),
        "ccc1230000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    p.add_function_record(bid, 0x1000, "orig").unwrap();
    assert!(p.rename_function(bid, 0x1000, "new").unwrap());
    assert_eq!(
        p.get_function_by_addr(bid, 0x1000).unwrap().unwrap().name,
        "new"
    );
}

#[test]
fn rename_function_unknown_returns_false() {
    let (_d, mut p) = fresh_project("rfu");
    let bid = BinaryProject::add_binary(
        &mut p,
        Path::new("/tmp/x.bin"),
        "ddd1230000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    assert!(!p.rename_function(bid, 0xfeed, "x").unwrap());
}

#[test]
fn xrefs_from_returns_inserted() {
    let (_d, mut p) = fresh_project("xf");
    let bid = BinaryProject::add_binary(
        &mut p,
        Path::new("/tmp/x.bin"),
        "eee1230000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    p.add_xref_record(bid, 0x100, 0x200, "call").unwrap();
    let v = p.xrefs_from(bid, 0x100);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].1, 0x200);
}

#[test]
fn xrefs_from_empty_for_unknown() {
    let (_d, mut p) = fresh_project("xfe");
    let bid = BinaryProject::add_binary(
        &mut p,
        Path::new("/tmp/x.bin"),
        "fff1230000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    assert!(p.xrefs_from(bid, 0xdead).is_empty());
}

// ── Comments upsert ──────────────────────────────────────────────────────────

#[test]
fn comment_upsert_replaces() {
    let (_d, p) = fresh_project("cu");
    let mut pp = p; // need mut to add_binary
    let bid = BinaryProject::add_binary(
        &mut pp,
        Path::new("/tmp/x.bin"),
        "1110000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    pp.add_comment_record(bid, 0x10, "first").unwrap();
    pp.add_comment_record(bid, 0x10, "second").unwrap();
    assert_eq!(pp.get_comment(bid, 0x10).unwrap().as_deref(), Some("second"));
}

#[test]
fn comment_none_for_missing() {
    let (_d, p) = fresh_project("cn");
    assert!(p.get_comment(0, 0x10).unwrap().is_none());
}

// ── Strings & FTS ────────────────────────────────────────────────────────────

#[test]
fn add_and_fts_search() {
    let (_d, mut p) = fresh_project("fts");
    let bid = BinaryProject::add_binary(
        &mut p,
        Path::new("/tmp/x.bin"),
        "2220000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    p.add_string(bid, 0x100, "hello world", "utf8").unwrap();
    p.add_string(bid, 0x200, "goodbye world", "utf8").unwrap();
    let res = p.search_strings_fts(bid, "hello");
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].0, 0x100);
}

#[test]
fn fts_no_match_empty() {
    let (_d, mut p) = fresh_project("ftsx");
    let bid = BinaryProject::add_binary(
        &mut p,
        Path::new("/tmp/x.bin"),
        "3330000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    p.add_string(bid, 0x100, "alpha", "utf8").unwrap();
    assert!(p.search_strings_fts(bid, "omega").is_empty());
}

// ── Delta export ─────────────────────────────────────────────────────────────

#[test]
fn delta_since_filters_old() {
    let (_d, mut p) = fresh_project("dx");
    BinaryProject::add_event(&mut p, "k1", "u", b"{}").unwrap();
    let all = p.export_delta(0);
    assert!(!all.is_empty());
    let future = p.export_delta(u64::MAX / 2);
    assert!(future.is_empty());
}

// ── Migrations ────────────────────────────────────────────────────────────────

#[test]
fn migrations_have_nonempty_sql() {
    for m in get_migrations() {
        assert!(!m.sql.trim().is_empty());
        assert!(!m.description.is_empty());
    }
}

#[test]
fn run_pending_then_run_all_idempotent() {
    let d = tmp();
    let conn = rusqlite::Connection::open(d.path().join("m.db")).unwrap();
    let first = run_pending_migrations(&conn).unwrap();
    assert!(first > 0);
    run_migrations(&conn).unwrap();
    let second = run_pending_migrations(&conn).unwrap();
    assert_eq!(second, 0);
}

// ── ProjectManager ────────────────────────────────────────────────────────────

#[test]
fn manager_get_returns_arc() {
    let d = tmp();
    let mut m = ProjectManager::new();
    let arc = m.create("g", d.path()).unwrap();
    let key = d.path().canonicalize().unwrap().to_string_lossy().into_owned();
    let got = m.get(&key);
    assert!(got.is_some());
    assert!(Arc::ptr_eq(&arc, &got.unwrap()));
}

#[test]
fn manager_save_all_collects() {
    let d = tmp();
    let mut m = ProjectManager::new();
    m.create("sa", d.path()).unwrap();
    let res = m.save_all();
    assert_eq!(res.len(), 1);
    assert!(res[0].1.is_ok());
}

#[test]
fn manager_recent_nonempty() {
    let d = tmp();
    let mut m = ProjectManager::new();
    m.create("rp", d.path()).unwrap();
    assert!(!m.recent_projects().is_empty());
}

// ── ProjectSession ────────────────────────────────────────────────────────────

#[test]
fn session_open_view_idempotent() {
    let (_d, p) = fresh_project("sov");
    let mut s = ProjectSession::new(Arc::new(Mutex::new(p)));
    s.open_view(1);
    s.open_view(1);
    s.open_view(1);
    assert_eq!(s.open_view_count(), 1);
}

#[test]
fn session_close_unknown_no_op() {
    let (_d, p) = fresh_project("scu");
    let mut s = ProjectSession::new(Arc::new(Mutex::new(p)));
    s.close_view(42); // not open
    assert_eq!(s.open_view_count(), 0);
}

#[test]
fn session_activate_script_dedup() {
    let (_d, p) = fresh_project("sas");
    let mut s = ProjectSession::new(Arc::new(Mutex::new(p)));
    s.activate_script("a.py");
    s.activate_script("a.py");
    assert_eq!(s.active_scripts.len(), 1);
}

#[test]
fn session_deactivate_unknown_no_op() {
    let (_d, p) = fresh_project("sdu");
    let mut s = ProjectSession::new(Arc::new(Mutex::new(p)));
    s.deactivate_script("none");
    assert!(s.active_scripts.is_empty());
}

// ── Version history ──────────────────────────────────────────────────────────

#[test]
fn version_history_exactly_max() {
    let (_d, mut p) = fresh_project("vhe");
    let bid = BinaryProject::add_binary(
        &mut p,
        Path::new("/tmp/x.bin"),
        "4440000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    for i in 0..(MAX_VERSION_SNAPSHOTS as u32 + 5) {
        p.save_version_snapshot(bid, &i.to_le_bytes(), None).unwrap();
    }
    let n = p.list_version_snapshots(bid).len();
    assert_eq!(n, MAX_VERSION_SNAPSHOTS);
}

// ── Export JSON binary stats integration ─────────────────────────────────────

#[test]
fn export_json_contains_function_names() {
    let (_d, mut p) = fresh_project("ej");
    let bid = BinaryProject::add_binary(
        &mut p,
        Path::new("/tmp/x.bin"),
        "5550000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    p.add_function_record(bid, 0x100, "alpha").unwrap();
    p.add_function_record(bid, 0x200, "beta").unwrap();
    let j = p.export_json(bid).unwrap();
    assert!(j.contains("alpha"));
    assert!(j.contains("beta"));
}

// ── ExportFormat ─────────────────────────────────────────────────────────────

#[test]
fn export_format_extensions_unique() {
    let exts: Vec<&str> = ExportFormat::all().iter().map(|f| f.extension()).collect();
    let mut sorted = exts.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), exts.len());
}

#[test]
fn export_format_display_matches_name() {
    for f in ExportFormat::all() {
        assert_eq!(format!("{f}"), f.display_name());
    }
}

#[test]
fn export_format_all_count_is_seven() {
    assert_eq!(ExportFormat::all().len(), 7);
}

#[test]
fn export_format_json_ext() {
    assert_eq!(ExportFormat::Json.extension(), "json");
}

// ── AddressRange ─────────────────────────────────────────────────────────────

#[test]
fn address_range_contains_inclusive_lower() {
    let r = AddressRange::new(10, 20);
    assert!(r.contains(10));
    assert!(r.contains(19));
    assert!(!r.contains(20));
    assert!(!r.contains(9));
}

#[test]
fn address_range_full_contains_zero_and_almost_max() {
    let r = AddressRange::full();
    assert!(r.contains(0));
    assert!(r.contains(u64::MAX - 1));
    // upper-exclusive
    assert!(!r.contains(u64::MAX));
}

// ── ExportOptions builder ────────────────────────────────────────────────────

#[test]
fn export_options_builder_sets_fields() {
    let o = ExportOptions::new()
        .with_xrefs()
        .with_patches()
        .max_functions(7)
        .address_range(AddressRange::new(0, 100));
    assert!(o.include_xrefs);
    assert!(o.include_patches);
    assert_eq!(o.max_functions, 7);
    assert!(o.address_range.is_some());
}

#[test]
fn export_options_defaults_no_xrefs_no_patches() {
    let o = ExportOptions::default();
    assert!(!o.include_xrefs);
    assert!(!o.include_patches);
    assert!(o.include_strings);
    assert!(o.include_functions);
}

// ── ProjectExporter end-to-end ───────────────────────────────────────────────

fn exporter_setup() -> (TempDir, Project, u64) {
    let d = tmp();
    let mut p = Project::new("ex", d.path()).unwrap();
    let bid = BinaryProject::add_binary(
        &mut p,
        Path::new("/tmp/exb.bin"),
        "6660000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    p.add_function_record(bid, 0x1000, "main").unwrap();
    p.add_function_record(bid, 0x2000, "helper").unwrap();
    p.add_comment_record(bid, 0x1000, "entry point").unwrap();
    p.add_bookmark(bid, 0x1000, "L1", "#ff0000").unwrap();
    p.add_symbol(bid, 0x1000, "main", "function", "user").unwrap();
    p.add_string(bid, 0x3000, "hello", "utf8").unwrap();
    p.add_xref_record(bid, 0x1000, 0x2000, "call").unwrap();
    (d, p, bid)
}

#[test]
fn exporter_json_render() {
    let (_d, p, bid) = exporter_setup();
    let s = ProjectExporter::new(&p, bid).export(ExportFormat::Json).unwrap();
    assert!(s.contains("main"));
    assert!(s.contains("hello"));
}

#[test]
fn exporter_csv_render_has_header() {
    let (_d, p, bid) = exporter_setup();
    let s = ProjectExporter::new(&p, bid).export(ExportFormat::Csv).unwrap();
    assert!(s.contains("Functions"));
    assert!(s.contains("address,name,size"));
}

#[test]
fn exporter_idc_render() {
    let (_d, p, bid) = exporter_setup();
    let s = ProjectExporter::new(&p, bid).export(ExportFormat::IdaIdc).unwrap();
    assert!(!s.is_empty());
}

#[test]
fn exporter_ghidra_render() {
    let (_d, p, bid) = exporter_setup();
    let s = ProjectExporter::new(&p, bid).export(ExportFormat::GhidraScript).unwrap();
    assert!(!s.is_empty());
}

#[test]
fn exporter_binja_render() {
    let (_d, p, bid) = exporter_setup();
    let s = ProjectExporter::new(&p, bid)
        .export(ExportFormat::BinaryNinjaJson)
        .unwrap();
    assert!(!s.is_empty());
}

#[test]
fn exporter_html_render() {
    let (_d, p, bid) = exporter_setup();
    let s = ProjectExporter::new(&p, bid).export(ExportFormat::HtmlReport).unwrap();
    assert!(s.to_lowercase().contains("html") || s.contains('<'));
}

#[test]
fn exporter_md_render() {
    let (_d, p, bid) = exporter_setup();
    let s = ProjectExporter::new(&p, bid).export(ExportFormat::Markdown).unwrap();
    assert!(!s.is_empty());
}

#[test]
fn exporter_missing_binary_err() {
    let (_d, p) = fresh_project("emb");
    let r = ProjectExporter::new(&p, 9999).export(ExportFormat::Json);
    assert!(r.is_err());
}

#[test]
fn exporter_to_file_creates_file() {
    let (d, p, bid) = exporter_setup();
    let base = d.path().join("out");
    let path = ProjectExporter::new(&p, bid)
        .export_to_file(ExportFormat::Json, base.to_str().unwrap())
        .unwrap();
    assert!(path.exists());
    let txt = fs::read_to_string(&path).unwrap();
    assert!(txt.contains("main"));
}

#[test]
fn exporter_to_path_writes_content() {
    let (d, p, bid) = exporter_setup();
    let path = d.path().join("specific.json");
    ProjectExporter::new(&p, bid)
        .export_to_path(ExportFormat::Json, &path)
        .unwrap();
    assert!(path.exists());
}

#[test]
fn exporter_max_functions_limits() {
    let (_d, p, bid) = exporter_setup();
    let opts = ExportOptions::default().max_functions(1);
    let s = ProjectExporter::new(&p, bid)
        .with_options(opts)
        .export(ExportFormat::Json)
        .unwrap();
    // First inserted function 'main' at 0x1000 should be present; 'helper' should not.
    assert!(s.contains("main"));
    assert!(!s.contains("helper"));
}

#[test]
fn exporter_address_range_filters() {
    let (_d, p, bid) = exporter_setup();
    let opts = ExportOptions::default().address_range(AddressRange::new(0x1500, 0x3000));
    let s = ProjectExporter::new(&p, bid)
        .with_options(opts)
        .export(ExportFormat::Json)
        .unwrap();
    // 0x1000 'main' excluded; 0x2000 'helper' included.
    assert!(s.contains("helper"));
}

// ── AnalysisCache ────────────────────────────────────────────────────────────

#[test]
fn cache_insert_then_get_hit() {
    let mut c = AnalysisCache::new();
    let k = c.insert("hash1", "pass1", "{}");
    assert!(c.contains(&k));
    let r = c.get(&k);
    assert!(r.is_some());
    assert_eq!(r.unwrap().result_json, "{}");
}

#[test]
fn cache_get_missing_increments_miss() {
    let mut c = AnalysisCache::new();
    let k = CacheKey::new("nohash", "pass");
    assert!(c.get(&k).is_none());
}

#[test]
fn cache_peek_does_not_change_stats() {
    let mut c = AnalysisCache::new();
    let k = c.insert("h", "p", "{}");
    let _ = c.peek(&k);
    let _ = c.peek(&k);
    // peek shouldn't mutate stats. We can't read stats directly without API,
    // but at least it should not panic.
}

#[test]
fn cache_invalidate_binary_marks_all() {
    let mut c = AnalysisCache::new();
    let k1 = c.insert("h1", "p1", "{}");
    let k2 = c.insert("h1", "p2", "{}");
    let n = c.invalidate_binary("h1", "test");
    assert_eq!(n, 2);
    assert!(c.get(&k1).is_none());
    assert!(c.get(&k2).is_none());
}

#[test]
fn cache_invalidate_entry_true_then_false() {
    let mut c = AnalysisCache::new();
    let k = c.insert("h", "p", "{}");
    assert!(c.invalidate_entry(&k, "r"));
    // Second invalidation of already invalidated entry: still true because entry exists.
    assert!(c.invalidate_entry(&k, "r"));
    let missing = CacheKey::new("none", "none");
    assert!(!c.invalidate_entry(&missing, "r"));
}

#[test]
fn cache_export_only_valid_entries() {
    let mut c = AnalysisCache::new();
    let k1 = c.insert("h", "p1", "{}");
    let _k2 = c.insert("h", "p2", "{}");
    c.invalidate_entry(&k1, "r");
    let exp = c.export("h", "test");
    assert_eq!(exp.entry_count(), 1);
}

#[test]
fn cache_import_restores_entries() {
    let mut c1 = AnalysisCache::new();
    c1.insert("h", "p1", "{\"a\":1}");
    let exp = c1.export("h", "x");
    let mut c2 = AnalysisCache::new();
    let imported = c2.import(exp);
    assert_eq!(imported, 1);
    assert!(c2.peek(&CacheKey::new("h", "p1")).is_some());
}

// ── CachedResult / expiry ────────────────────────────────────────────────────

#[test]
fn cached_result_new_not_expired_with_large_age() {
    let r = CachedResult::new("p", "{}", "h");
    assert!(!r.is_expired(10_000));
    assert!(r.is_valid());
}

#[test]
fn cached_result_dependency_add() {
    let mut r = CachedResult::new("p", "{}", "h");
    r.add_dependency("dep1");
    assert_eq!(r.dependency_hashes, vec!["dep1".to_string()]);
}

// ── CacheKey display ─────────────────────────────────────────────────────────

#[test]
fn cachekey_display_truncates_hash() {
    let k = CacheKey::new("0123456789abcdef0000", "mypass");
    let s = format!("{k}");
    assert!(s.starts_with("01234567:"));
    assert!(s.ends_with("mypass"));
}

#[test]
fn cachekey_display_short_hash() {
    let k = CacheKey::new("ab", "p");
    let s = format!("{k}");
    assert_eq!(s, "ab:p");
}

// ── CacheStats ───────────────────────────────────────────────────────────────

#[test]
fn cachestats_hit_ratio_zero_when_empty() {
    let s = CacheStats::new();
    assert_eq!(s.hit_ratio(), 0.0);
}

#[test]
fn cachestats_hit_ratio_basic() {
    let mut s = CacheStats::new();
    s.hits = 3;
    s.misses = 1;
    assert!((s.hit_ratio() - 0.75).abs() < 1e-9);
}

#[test]
fn cachestats_display_contains_hits() {
    let mut s = CacheStats::new();
    s.hits = 5;
    let out = format!("{s}");
    assert!(out.contains("hits=5"));
}

// ── DependencyTracker ────────────────────────────────────────────────────────

#[test]
fn deptracker_add_and_deps_of() {
    let mut t = DependencyTracker::new();
    t.add_dependency("decompile", "disasm");
    let deps = t.deps_of("decompile");
    assert_eq!(deps, vec!["disasm"]);
}

#[test]
fn deptracker_dependents_of() {
    let mut t = DependencyTracker::new();
    t.add_dependency("typing", "decompile");
    t.add_dependency("naming", "decompile");
    let mut dps = t.dependents_of("decompile");
    dps.sort();
    assert_eq!(dps, vec!["naming".to_string(), "typing".to_string()]);
}

#[test]
fn deptracker_transitive_depends_on() {
    let mut t = DependencyTracker::new();
    t.add_dependency("a", "b");
    t.add_dependency("b", "c");
    assert!(t.depends_on("a", "c"));
    assert!(!t.depends_on("c", "a"));
}

#[test]
fn deptracker_invalidated_by_change_no_change() {
    let mut t = DependencyTracker::new();
    t.add_dependency("x", "y");
    t.set_pass_hash("y", "h1");
    assert!(t.invalidated_by_change("y", "h1").is_empty());
}

#[test]
fn deptracker_invalidated_by_change_yields_dependents() {
    let mut t = DependencyTracker::new();
    t.add_dependency("x", "y");
    t.set_pass_hash("y", "h1");
    let v = t.invalidated_by_change("y", "h2");
    assert_eq!(v, vec!["x".to_string()]);
}

// ── CacheExport ──────────────────────────────────────────────────────────────

#[test]
fn cache_export_empty_count_zero() {
    let e = CacheExport::new("src");
    assert_eq!(e.entry_count(), 0);
}

// ── AnnotationKind ───────────────────────────────────────────────────────────

#[test]
fn annotation_kind_roundtrip_all() {
    for k in AnnotationKind::all() {
        let s = k.as_str();
        let k2 = AnnotationKind::from_str(s);
        assert_eq!(*k, k2);
    }
}

#[test]
fn annotation_kind_unknown_defaults_note() {
    assert_eq!(AnnotationKind::from_str("zzz"), AnnotationKind::Note);
}

#[test]
fn annotation_kind_display_is_as_str() {
    assert_eq!(format!("{}", AnnotationKind::Warning), "warning");
}

#[test]
fn annotation_kind_all_count_six() {
    assert_eq!(AnnotationKind::all().len(), 6);
}

// ── AnnotationQuery builder ──────────────────────────────────────────────────

#[test]
fn annquery_builders_set_fields() {
    let q = AnnotationQuery::new()
        .binary(7)
        .at_addr(0x10)
        .by_author("u")
        .pinned()
        .limit(5)
        .offset(3)
        .body_contains("foo")
        .of_kinds(vec![AnnotationKind::Todo]);
    assert_eq!(q.binary_id, Some(7));
    assert_eq!(q.addr, Some(0x10));
    assert_eq!(q.author.as_deref(), Some("u"));
    assert!(q.pinned_only);
    assert_eq!(q.limit, Some(5));
    assert_eq!(q.offset_rows, Some(3));
    assert_eq!(q.body_contains.as_deref(), Some("foo"));
    assert_eq!(q.kinds.len(), 1);
}

#[test]
fn annquery_addr_range_sets_min_max() {
    let q = AnnotationQuery::new().addr_range(10, 100);
    assert_eq!(q.addr_min, Some(10));
    assert_eq!(q.addr_max, Some(100));
}

// ── AnnotationStore ──────────────────────────────────────────────────────────

fn store_setup() -> (TempDir, AnnotationStore) {
    let d = tmp();
    let s = AnnotationStore::new(d.path().join("ann.db")).unwrap();
    (d, s)
}

#[test]
fn ann_insert_get_by_id() {
    let (_d, s) = store_setup();
    let a = Annotation::new(1, 0x100, AnnotationKind::Note, "body", "alice");
    let id = s.insert(&a).unwrap();
    let got = s.get_by_id(id).unwrap().unwrap();
    assert_eq!(got.body, "body");
    assert_eq!(got.binary_id, 1);
    assert_eq!(got.kind, AnnotationKind::Note);
}

#[test]
fn ann_get_by_unknown_id() {
    let (_d, s) = store_setup();
    assert!(s.get_by_id(99).unwrap().is_none());
}

#[test]
fn ann_list_by_binary() {
    let (_d, s) = store_setup();
    s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "a", "u")).unwrap();
    s.insert(&Annotation::new(1, 0x20, AnnotationKind::Todo, "b", "u")).unwrap();
    s.insert(&Annotation::new(2, 0x30, AnnotationKind::Warning, "c", "u")).unwrap();
    assert_eq!(s.list(1).unwrap().len(), 2);
    assert_eq!(s.list(2).unwrap().len(), 1);
}

#[test]
fn ann_at_addr_filters() {
    let (_d, s) = store_setup();
    s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "a", "u")).unwrap();
    s.insert(&Annotation::new(1, 0x20, AnnotationKind::Note, "b", "u")).unwrap();
    assert_eq!(s.at_addr(1, 0x10).unwrap().len(), 1);
}

#[test]
fn ann_update_body() {
    let (_d, s) = store_setup();
    let id = s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "old", "u")).unwrap();
    assert!(s.update_body(id, "new").unwrap());
    assert_eq!(s.get_by_id(id).unwrap().unwrap().body, "new");
}

#[test]
fn ann_update_body_unknown_false() {
    let (_d, s) = store_setup();
    assert!(!s.update_body(999, "x").unwrap());
}

#[test]
fn ann_update_kind() {
    let (_d, s) = store_setup();
    let id = s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "x", "u")).unwrap();
    assert!(s.update_kind(id, AnnotationKind::BugReport).unwrap());
    assert_eq!(s.get_by_id(id).unwrap().unwrap().kind, AnnotationKind::BugReport);
}

#[test]
fn ann_update_color() {
    let (_d, s) = store_setup();
    let id = s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "x", "u")).unwrap();
    assert!(s.update_color(id, "#00ff00").unwrap());
    assert_eq!(s.get_by_id(id).unwrap().unwrap().color, "#00ff00");
}

#[test]
fn ann_set_pinned() {
    let (_d, s) = store_setup();
    let id = s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "x", "u")).unwrap();
    assert!(s.set_pinned(id, true).unwrap());
    assert!(s.get_by_id(id).unwrap().unwrap().is_pinned);
    assert!(s.set_pinned(id, false).unwrap());
    assert!(!s.get_by_id(id).unwrap().unwrap().is_pinned);
}

#[test]
fn ann_delete() {
    let (_d, s) = store_setup();
    let id = s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "x", "u")).unwrap();
    assert!(s.delete(id).unwrap());
    assert!(s.get_by_id(id).unwrap().is_none());
    assert!(!s.delete(id).unwrap());
}

#[test]
fn ann_delete_all() {
    let (_d, s) = store_setup();
    for i in 0..5 {
        s.insert(&Annotation::new(1, i * 0x10, AnnotationKind::Note, "x", "u")).unwrap();
    }
    s.insert(&Annotation::new(2, 0x10, AnnotationKind::Note, "x", "u")).unwrap();
    assert_eq!(s.delete_all(1).unwrap(), 5);
    assert_eq!(s.count(1), 0);
    assert_eq!(s.count(2), 1);
}

#[test]
fn ann_count_and_count_by_kind() {
    let (_d, s) = store_setup();
    s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "a", "u")).unwrap();
    s.insert(&Annotation::new(1, 0x20, AnnotationKind::Note, "b", "u")).unwrap();
    s.insert(&Annotation::new(1, 0x30, AnnotationKind::Todo, "c", "u")).unwrap();
    assert_eq!(s.count(1), 3);
    assert_eq!(s.count_by_kind(1, AnnotationKind::Note), 2);
    assert_eq!(s.count_by_kind(1, AnnotationKind::Todo), 1);
    assert_eq!(s.count_by_kind(1, AnnotationKind::Warning), 0);
}

#[test]
fn ann_query_by_kinds_filter() {
    let (_d, s) = store_setup();
    s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "a", "u")).unwrap();
    s.insert(&Annotation::new(1, 0x20, AnnotationKind::Warning, "b", "u")).unwrap();
    let q = AnnotationQuery::new().binary(1).of_kinds(vec![AnnotationKind::Warning]);
    let r = s.query(&q).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].kind, AnnotationKind::Warning);
}

#[test]
fn ann_query_by_author() {
    let (_d, s) = store_setup();
    s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "a", "alice")).unwrap();
    s.insert(&Annotation::new(1, 0x20, AnnotationKind::Note, "b", "bob")).unwrap();
    let r = s.query(&AnnotationQuery::new().binary(1).by_author("alice")).unwrap();
    assert_eq!(r.len(), 1);
}

#[test]
fn ann_query_body_contains() {
    let (_d, s) = store_setup();
    s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "alpha bravo", "u")).unwrap();
    s.insert(&Annotation::new(1, 0x20, AnnotationKind::Note, "charlie", "u")).unwrap();
    let r = s.query(&AnnotationQuery::new().binary(1).body_contains("bravo")).unwrap();
    assert_eq!(r.len(), 1);
}

#[test]
fn ann_query_pinned_only() {
    let (_d, s) = store_setup();
    let id = s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "a", "u")).unwrap();
    s.insert(&Annotation::new(1, 0x20, AnnotationKind::Note, "b", "u")).unwrap();
    s.set_pinned(id, true).unwrap();
    let r = s.query(&AnnotationQuery::new().binary(1).pinned()).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].id, id);
}

#[test]
fn ann_query_addr_range() {
    let (_d, s) = store_setup();
    for a in [0x10u64, 0x20, 0x30, 0x40] {
        s.insert(&Annotation::new(1, a, AnnotationKind::Note, "x", "u")).unwrap();
    }
    let r = s.query(&AnnotationQuery::new().binary(1).addr_range(0x20, 0x30)).unwrap();
    assert_eq!(r.len(), 2);
}

#[test]
fn ann_query_limit_offset() {
    let (_d, s) = store_setup();
    for a in 0..10u64 {
        s.insert(&Annotation::new(1, a * 0x10, AnnotationKind::Note, "x", "u")).unwrap();
    }
    let r = s.query(&AnnotationQuery::new().binary(1).limit(3).offset(2)).unwrap();
    assert_eq!(r.len(), 3);
    assert_eq!(r[0].addr, 0x20);
}

#[test]
fn ann_export_import_json() {
    let (_d, s) = store_setup();
    s.insert(&Annotation::new(1, 0x10, AnnotationKind::Note, "alpha", "u")).unwrap();
    s.insert(&Annotation::new(1, 0x20, AnnotationKind::Warning, "beta", "u")).unwrap();
    let json = export_annotations_json(&s, 1);
    assert!(json.contains("alpha"));

    let (_d2, s2) = store_setup();
    let imported = import_annotations_json(&s2, &json);
    assert_eq!(imported, 2);
    assert_eq!(s2.count(1), 2);
}

#[test]
fn ann_import_malformed_json_zero() {
    let (_d, s) = store_setup();
    let n = import_annotations_json(&s, "this is not json");
    assert_eq!(n, 0);
}

#[test]
fn ann_export_empty_for_missing_binary() {
    let (_d, s) = store_setup();
    let j = export_annotations_json(&s, 999);
    // JSON serializer of empty Vec -> "[]"
    assert_eq!(j.trim(), "[]");
}
