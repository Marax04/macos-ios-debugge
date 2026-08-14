//! blitz2: deep adversarial tests for rustre-project public API.
#![allow(clippy::bool_assert_comparison)]

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rustre_project::{
    BinaryProject, BinaryStats, KgBackend, Project, ProjectConfig, ProjectError, ProjectManager,
    ProjectMetadata, ProjectSession, CURRENT_SCHEMA_VERSION, DEFAULT_AUTOSAVE_INTERVAL_SECS,
    MAX_VERSION_SNAPSHOTS, PROJECT_DIR_NAME, get_migrations, run_migrations,
    run_pending_migrations, sha256_hex, shannon_entropy,
};
use tempfile::TempDir;

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// Seeded LCG fuzz generator (no rand crate, no `std::time`).
struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            out.extend_from_slice(&self.next().to_le_bytes());
        }
        out.truncate(n);
        out
    }
}

fn sha_hex(idx: u64) -> String {
    // 64 hex chars deterministic
    let mut s = String::with_capacity(64);
    let mut v = idx.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for _ in 0..16 {
        s.push_str(&format!("{:04x}", (v & 0xFFFF) as u16));
        v = v.wrapping_mul(31).wrapping_add(7);
    }
    s.truncate(64);
    while s.len() < 64 {
        s.push('0');
    }
    s
}

// ── 1. sha256 known-vector regression ────────────────────────────────────────

#[test]
fn sha256_hex_empty_known() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_hex_abc() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_hex_deterministic_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next() % 4096) as usize;
        let data = g.bytes(len);
        let a = sha256_hex(&data);
        let b = sha256_hex(&data);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[test]
fn sha256_hex_different_inputs() {
    let a = sha256_hex(b"hello");
    let b = sha256_hex(b"world");
    assert_ne!(a, b);
}

// ── 2. Shannon entropy boundaries ────────────────────────────────────────────

#[test]
fn entropy_empty_zero() {
    assert_eq!(shannon_entropy(b""), 0.0);
}

#[test]
fn entropy_single_byte_zero() {
    assert_eq!(shannon_entropy(&[42]), 0.0);
}

#[test]
fn entropy_uniform_all_one_byte_zero() {
    assert!(shannon_entropy(&vec![0xAA; 4096]).abs() < 1e-9);
}

#[test]
fn entropy_max_full_alphabet() {
    let data: Vec<u8> = (0u8..=255).collect();
    assert!((shannon_entropy(&data) - 8.0).abs() < 1e-9);
}

#[test]
fn entropy_in_range_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next() % 2048) as usize + 1;
        let data = g.bytes(len);
        let e = shannon_entropy(&data);
        assert!((0.0..=8.0001).contains(&e), "entropy out of range: {e}");
    }
}

// ── 3. detect_format_arch via add_binary ────────────────────────────────────

#[test]
fn detect_pe_via_add() {
    let d = tmp();
    let p = Project::new("pe", d.path()).unwrap();
    let f = d.path().join("a.exe");
    fs::write(&f, b"MZ\0\0").unwrap();
    let e = p.add_binary_from_path(&f).unwrap();
    assert_eq!(e.format, "PE");
}

#[test]
fn detect_elf_via_add() {
    let d = tmp();
    let p = Project::new("elf", d.path()).unwrap();
    let f = d.path().join("a.elf");
    let mut bytes = vec![0x7f, b'E', b'L', b'F'];
    bytes.extend([0u8; 32]);
    fs::write(&f, &bytes).unwrap();
    let e = p.add_binary_from_path(&f).unwrap();
    assert_eq!(e.format, "ELF");
}

#[test]
fn detect_macho_via_add() {
    let d = tmp();
    let p = Project::new("mo", d.path()).unwrap();
    let f = d.path().join("a.macho");
    fs::write(&f, [0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0]).unwrap();
    let e = p.add_binary_from_path(&f).unwrap();
    assert_eq!(e.format, "MachO");
}

#[test]
fn detect_wasm_via_add() {
    let d = tmp();
    let p = Project::new("w", d.path()).unwrap();
    let f = d.path().join("a.wasm");
    fs::write(&f, b"\0asm\x01\0\0\0").unwrap();
    let e = p.add_binary_from_path(&f).unwrap();
    assert_eq!(e.format, "WASM");
}

#[test]
fn detect_dex_via_add() {
    let d = tmp();
    let p = Project::new("dx", d.path()).unwrap();
    let f = d.path().join("a.dex");
    fs::write(&f, b"dex\n035\0").unwrap();
    let e = p.add_binary_from_path(&f).unwrap();
    assert_eq!(e.format, "DEX");
}

#[test]
fn detect_unknown_short_input() {
    let d = tmp();
    let p = Project::new("u", d.path()).unwrap();
    let f = d.path().join("a.bin");
    fs::write(&f, b"\x00\x01\x02").unwrap();
    let e = p.add_binary_from_path(&f).unwrap();
    assert_eq!(e.format, "unknown");
}

#[test]
fn detect_truncated_mz_only() {
    // MZ but file far smaller than 0x40 — format=PE arch=unknown
    let d = tmp();
    let p = Project::new("mzt", d.path()).unwrap();
    let f = d.path().join("trunc.exe");
    fs::write(&f, b"MZ").unwrap();
    let e = p.add_binary_from_path(&f).unwrap();
    assert_eq!(e.format, "PE");
    assert_eq!(e.arch, "unknown");
}

#[test]
fn detect_format_fuzz_no_panic() {
    let mut g = Lcg::new();
    let d = tmp();
    let p = Project::new("fz", d.path()).unwrap();
    for i in 0..50u64 {
        let len = (g.next() % 256) as usize;
        let data = g.bytes(len);
        let f = d.path().join(format!("f{i}.bin"));
        fs::write(&f, &data).unwrap();
        // Should never panic. Empty files are allowed.
        let _ = p.add_binary_from_path(&f);
    }
}

// ── 4. Project: new / open lifecycle ────────────────────────────────────────

#[test]
fn project_new_duplicate_err() {
    let d = tmp();
    Project::new("a", d.path()).unwrap();
    let err = Project::new("b", d.path()).unwrap_err();
    assert!(matches!(err, ProjectError::AlreadyExists(_)));
}

#[test]
fn project_open_missing_err() {
    let d = tmp();
    let err = Project::open(d.path().join("does-not-exist")).unwrap_err();
    assert!(matches!(err, ProjectError::NotFound(_)));
}

#[test]
fn project_open_after_new_preserves_name() {
    let d = tmp();
    let _ = Project::new("preserved", d.path()).unwrap();
    let p2 = Project::open(d.path()).unwrap();
    assert_eq!(p2.name(), "preserved");
}

#[test]
fn project_meta_roundtrip_tags() {
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
fn project_subdirs_created() {
    let d = tmp();
    let p = Project::new("sd", d.path()).unwrap();
    for sub in [
        "recordings",
        "sandbox",
        "attachments",
        "workflows",
        "scripts",
        "reports",
        "views",
        "snapshots",
    ] {
        assert!(p.project_dir().join(sub).exists(), "{sub} missing");
    }
}

// ── 5. add_binary dedup & list ───────────────────────────────────────────────

#[test]
fn add_binary_dedup_same_content() {
    let d = tmp();
    let p = Project::new("dd", d.path()).unwrap();
    let f = d.path().join("x");
    fs::write(&f, b"hello world").unwrap();
    let a = p.add_binary_from_path(&f).unwrap();
    let b = p.add_binary_from_path(&f).unwrap();
    assert_eq!(a.sha256, b.sha256);
    assert_eq!(p.list_binaries().len(), 1);
}

#[test]
fn add_binary_distinct_content_diff_id() {
    let d = tmp();
    let p = Project::new("dd2", d.path()).unwrap();
    let f1 = d.path().join("a"); fs::write(&f1, b"AAA").unwrap();
    let f2 = d.path().join("b"); fs::write(&f2, b"BBB").unwrap();
    let a = p.add_binary_from_path(&f1).unwrap();
    let b = p.add_binary_from_path(&f2).unwrap();
    assert_ne!(a.id, b.id);
    assert_eq!(p.list_binaries().len(), 2);
}

#[test]
fn find_binary_by_sha256_roundtrip() {
    let d = tmp();
    let p = Project::new("fb", d.path()).unwrap();
    let f = d.path().join("a"); fs::write(&f, b"data").unwrap();
    let e = p.add_binary_from_path(&f).unwrap();
    let found = p.find_binary_by_sha256(&e.sha256).unwrap().unwrap();
    assert_eq!(found.id, e.id);
    assert!(p.find_binary_by_sha256("ff".repeat(32).as_str()).unwrap().is_none());
}

#[test]
fn remove_binary_works() {
    let d = tmp();
    let p = Project::new("rm", d.path()).unwrap();
    let f = d.path().join("a"); fs::write(&f, b"x").unwrap();
    let e = p.add_binary_from_path(&f).unwrap();
    assert!(p.remove_binary(e.id).unwrap());
    assert!(p.list_binaries().is_empty());
    // Removing a non-existent binary returns false
    assert!(!p.remove_binary(99_999).unwrap());
}

// ── 6. Functions ─────────────────────────────────────────────────────────────

#[test]
fn functions_add_get_rename() {
    let d = tmp();
    let mut p = Project::new("fn", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/n.bin"), &sha_hex(1)).unwrap();
    let fid = p.add_function_record(bid, 0x1000, "old").unwrap();
    assert!(fid > 0);
    let got = p.get_function_by_addr(bid, 0x1000).unwrap().unwrap();
    assert_eq!(got.name, "old");
    assert!(p.rename_function(bid, 0x1000, "new").unwrap());
    let got2 = p.get_function_by_addr(bid, 0x1000).unwrap().unwrap();
    assert_eq!(got2.name, "new");
}

#[test]
fn functions_get_missing_none() {
    let d = tmp();
    let mut p = Project::new("fm", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/n.bin"), &sha_hex(2)).unwrap();
    assert!(p.get_function_by_addr(bid, 0xdead).unwrap().is_none());
}

#[test]
fn functions_dedup_same_addr() {
    let d = tmp();
    let mut p = Project::new("fd", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/n.bin"), &sha_hex(3)).unwrap();
    let a = p.add_function_record(bid, 0x4000, "fa").unwrap();
    let b = p.add_function_record(bid, 0x4000, "fb").unwrap();
    assert_eq!(a, b);
    assert_eq!(p.list_functions(bid).len(), 1);
}

#[test]
fn functions_addr_boundaries() {
    let d = tmp();
    let mut p = Project::new("fb2", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/n.bin"), &sha_hex(4)).unwrap();
    for addr in [0u64, 1, i64::MAX as u64] {
        p.add_function_record(bid, addr, "f").unwrap();
        let g = p.get_function_by_addr(bid, addr).unwrap();
        assert!(g.is_some(), "missing at addr {addr}");
        assert_eq!(g.unwrap().addr, addr);
    }
}

// ── 7. Comments ──────────────────────────────────────────────────────────────

#[test]
fn comment_upsert_overwrites_body() {
    let d = tmp();
    let mut p = Project::new("c", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/c.bin"), &sha_hex(5)).unwrap();
    p.add_comment_record(bid, 0x1000, "first").unwrap();
    p.add_comment_record(bid, 0x1000, "second").unwrap();
    assert_eq!(p.get_comment(bid, 0x1000).unwrap().as_deref(), Some("second"));
}

#[test]
fn comment_missing_none() {
    let d = tmp();
    let mut p = Project::new("c2", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/c.bin"), &sha_hex(6)).unwrap();
    assert!(p.get_comment(bid, 0xfeed).unwrap().is_none());
}

// ── 8. Xrefs ─────────────────────────────────────────────────────────────────

#[test]
fn xrefs_to_and_from_symmetry() {
    let d = tmp();
    let mut p = Project::new("xr", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/x.bin"), &sha_hex(7)).unwrap();
    p.add_xref_record(bid, 0x100, 0x200, "call").unwrap();
    p.add_xref_record(bid, 0x100, 0x300, "data").unwrap();
    p.add_xref_record(bid, 0x400, 0x200, "call").unwrap();
    let to_200 = p.xrefs_to(bid, 0x200);
    assert_eq!(to_200.len(), 2);
    let from_100 = p.xrefs_from(bid, 0x100);
    assert_eq!(from_100.len(), 2);
}

#[test]
fn xrefs_dedup() {
    let d = tmp();
    let mut p = Project::new("xrd", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/x.bin"), &sha_hex(8)).unwrap();
    p.add_xref_record(bid, 1, 2, "call").unwrap();
    p.add_xref_record(bid, 1, 2, "call").unwrap();
    assert_eq!(p.xrefs_to(bid, 2).len(), 1);
}

// ── 9. Events ────────────────────────────────────────────────────────────────

#[test]
fn events_add_list_by_kind() {
    let d = tmp();
    let p = Project::new("ev", d.path()).unwrap();
    p.add_event_record("k1", None, b"payload-a").unwrap();
    p.add_event_record("k1", None, b"payload-b").unwrap();
    p.add_event_record("k2", None, b"payload-c").unwrap();
    assert_eq!(p.list_events("k1").len(), 2);
    assert_eq!(p.list_events("k2").len(), 1);
    assert_eq!(p.list_events("nope").len(), 0);
}

#[test]
fn delta_export_since_filters() {
    let d = tmp();
    let p = Project::new("dx", d.path()).unwrap();
    p.add_event_record("e", None, b"x").unwrap();
    let all = p.export_delta(0);
    assert!(!all.is_empty());
    let none = p.export_delta(u64::MAX);
    assert!(none.is_empty());
}

#[test]
fn delta_import_idempotent_same_payload_distinct_id() {
    // No UNIQUE on events, so import always inserts.
    let d1 = tmp(); let d2 = tmp();
    let p1 = Project::new("s", d1.path()).unwrap();
    let p2 = Project::new("d", d2.path()).unwrap();
    p1.add_event_record("k", None, b"{}").unwrap();
    let delta = p1.export_delta(0);
    let n = p2.import_delta(&delta).unwrap();
    assert_eq!(n, delta.len() as u64);
}

// ── 10. Bookmarks / Symbols / Strings ───────────────────────────────────────

#[test]
fn bookmarks_replace_on_same_addr() {
    let d = tmp();
    let mut p = Project::new("bm", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/b.bin"), &sha_hex(9)).unwrap();
    p.add_bookmark(bid, 0x1000, "old", "#ff0000").unwrap();
    p.add_bookmark(bid, 0x1000, "new", "#00ff00").unwrap();
    let bms = p.list_bookmarks(bid);
    assert_eq!(bms.len(), 1);
    assert_eq!(bms[0].1, "new");
}

#[test]
fn symbols_search_prefix() {
    let d = tmp();
    let mut p = Project::new("sy", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/s.bin"), &sha_hex(10)).unwrap();
    p.add_symbol(bid, 0x1, "malloc", "function", "import").unwrap();
    p.add_symbol(bid, 0x2, "memcpy", "function", "import").unwrap();
    p.add_symbol(bid, 0x3, "free", "function", "import").unwrap();
    assert_eq!(p.search_symbols(bid, "m").len(), 2);
    assert_eq!(p.search_symbols(bid, "f").len(), 1);
    assert_eq!(p.search_symbols(bid, "zz").len(), 0);
}

#[test]
fn strings_fts_search() {
    let d = tmp();
    let mut p = Project::new("st", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/s.bin"), &sha_hex(11)).unwrap();
    p.add_string(bid, 0x100, "hello world", "utf8").unwrap();
    p.add_string(bid, 0x200, "goodbye world", "utf8").unwrap();
    let hits = p.search_strings_fts(bid, "hello");
    assert_eq!(hits.len(), 1);
    let any_world = p.search_strings_fts(bid, "world");
    assert_eq!(any_world.len(), 2);
}

// ── 11. Triage / Patches / Version history ──────────────────────────────────

#[test]
fn triage_upsert_replaces_same_scanner() {
    let d = tmp();
    let mut p = Project::new("tr", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/x.bin"), &sha_hex(12)).unwrap();
    let a = p.upsert_triage_result(bid, "yara", "susp", 0.5, "r1").unwrap();
    let b = p.upsert_triage_result(bid, "yara", "clean", 0.0, "r2").unwrap();
    assert_eq!(a, b);
    let r = p.list_triage_results(bid);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].verdict, "clean");
}

#[test]
fn patches_replace_on_same_addr() {
    let d = tmp();
    let mut p = Project::new("pa", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/p.bin"), &sha_hex(13)).unwrap();
    p.add_patch(bid, 0x1, &[0x90], &[0xCC], "v1").unwrap();
    p.add_patch(bid, 0x1, &[0x91], &[0xCD], "v2").unwrap();
    let ps = p.list_patches(bid);
    assert_eq!(ps.len(), 1);
    assert_eq!(ps[0].3, "v2");
}

#[test]
fn version_history_prunes_to_max() {
    let d = tmp();
    let mut p = Project::new("vh", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/v.bin"), &sha_hex(14)).unwrap();
    for i in 0u32..(MAX_VERSION_SNAPSHOTS as u32 + 5) {
        p.save_version_snapshot(bid, &i.to_le_bytes(), Some(&format!("s{i}"))).unwrap();
    }
    let snaps = p.list_version_snapshots(bid);
    assert!(snaps.len() <= MAX_VERSION_SNAPSHOTS, "got {}", snaps.len());
}

// ── 12. Migrations ───────────────────────────────────────────────────────────

#[test]
fn migrations_ascending_and_count() {
    let m = get_migrations();
    assert_eq!(m.len(), 4);
    assert_eq!(m.len() as u32, CURRENT_SCHEMA_VERSION);
    for w in m.windows(2) {
        assert!(w[1].version > w[0].version);
    }
}

#[test]
fn migrations_idempotent_repeated_runs() {
    let d = tmp();
    let conn = rusqlite::Connection::open(d.path().join("a.db")).unwrap();
    assert_eq!(run_pending_migrations(&conn).unwrap(), 4);
    assert_eq!(run_pending_migrations(&conn).unwrap(), 0);
    run_migrations(&conn).unwrap();
}

// ── 13. KgBackend Display/FromStr-like JSON roundtrip ───────────────────────

#[test]
fn kg_backend_serde_roundtrip_sqlite() {
    let b = KgBackend::Sqlite { path: "/x/y.db".into() };
    let s = serde_json::to_string(&b).unwrap();
    let back: KgBackend = serde_json::from_str(&s).unwrap();
    assert_eq!(b, back);
}

#[test]
fn kg_backend_serde_roundtrip_memory_default() {
    let b = KgBackend::default();
    assert_eq!(b, KgBackend::Memory);
    let s = serde_json::to_string(&b).unwrap();
    let back: KgBackend = serde_json::from_str(&s).unwrap();
    assert_eq!(b, back);
}

#[test]
fn project_config_serde_roundtrip_defaults() {
    let c = ProjectConfig::default();
    let s = serde_json::to_string(&c).unwrap();
    let back: ProjectConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(back.wal_mode, c.wal_mode);
    assert_eq!(back.undo_limit, c.undo_limit);
    assert_eq!(back.autosave_interval_secs, c.autosave_interval_secs);
}

// ── 14. ProjectManager ───────────────────────────────────────────────────────

#[test]
fn manager_create_open_same_arc() {
    let d = tmp();
    let mut m = ProjectManager::new();
    Project::new("x", d.path()).unwrap();
    let a = m.open(d.path()).unwrap();
    let b = m.open(d.path()).unwrap();
    assert!(Arc::ptr_eq(&a, &b));
}

#[test]
fn manager_empty_list_and_len() {
    let m = ProjectManager::new();
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
    assert!(m.list().is_empty());
}

#[test]
fn manager_close_removes_entry() {
    let d = tmp();
    let mut m = ProjectManager::new();
    m.create("k", d.path()).unwrap();
    let keys = m.list();
    assert_eq!(keys.len(), 1);
    m.close(&keys[0]);
    assert!(m.is_empty());
}

// ── 15. ProjectSession ───────────────────────────────────────────────────────

#[test]
fn session_open_view_dedup_and_close() {
    let d = tmp();
    let p = Project::new("s", d.path()).unwrap();
    let arc = Arc::new(Mutex::new(p));
    let mut s = ProjectSession::new(arc);
    s.open_view(1);
    s.open_view(1); // dedup
    s.open_view(2);
    assert_eq!(s.open_view_count(), 2);
    assert!(s.is_view_open(1));
    s.close_view(1);
    assert!(!s.is_view_open(1));
    assert_eq!(s.open_view_count(), 1);
}

#[test]
fn session_script_dedup() {
    let d = tmp();
    let p = Project::new("ss", d.path()).unwrap();
    let arc = Arc::new(Mutex::new(p));
    let mut s = ProjectSession::new(arc);
    s.activate_script("a.py");
    s.activate_script("a.py"); // dedup
    s.activate_script("b.py");
    assert_eq!(s.active_scripts.len(), 2);
    s.deactivate_script("a.py");
    assert_eq!(s.active_scripts.len(), 1);
    s.deactivate_script("missing.py"); // no-op
    assert_eq!(s.active_scripts.len(), 1);
}

// ── 16. Send+Sync stress on Project via Arc<Mutex<_>> ───────────────────────

#[test]
fn project_send_sync_threaded_stress() {
    let d = tmp();
    let mut p = Project::new("ts", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/ts.bin"), &sha_hex(99)).unwrap();
    let arc = Arc::new(Mutex::new(p));
    let mut handles = vec![];
    for t in 0..4u64 {
        let arc = Arc::clone(&arc);
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                let proj = arc.lock().unwrap();
                let addr = t * 1_000_000 + i;
                proj.add_function_record(bid, addr, &format!("t{t}_{i}")).unwrap();
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    let p = arc.lock().unwrap();
    assert_eq!(p.list_functions(bid).len(), 400);
}

// ── 17. Notes / Scripts / Layout / Undo log ─────────────────────────────────

#[test]
fn notes_save_list() {
    let d = tmp();
    let p = Project::new("nt", d.path()).unwrap();
    p.save_note("t1", "body1").unwrap();
    p.save_note("t2", "body2").unwrap();
    let n = p.list_notes();
    assert_eq!(n.len(), 2);
}

#[test]
fn scripts_upsert_get_list() {
    let d = tmp();
    let p = Project::new("sc", d.path()).unwrap();
    p.save_script("a", "python", "v1").unwrap();
    p.save_script("a", "python", "v2").unwrap();
    let (_, body) = p.get_script("a").unwrap().unwrap();
    assert_eq!(body, "v2");
    assert!(p.get_script("missing").unwrap().is_none());
    assert_eq!(p.list_scripts().len(), 1);
}

#[test]
fn layout_save_load_roundtrip() {
    let d = tmp();
    let p = Project::new("ly", d.path()).unwrap();
    assert!(p.load_layout().unwrap().is_none());
    p.save_layout(r#"{"panels":[]}"#).unwrap();
    assert!(p.load_layout().unwrap().unwrap().contains("panels"));
    // Save twice — should replace, not error.
    p.save_layout(r#"{"panels":["x"]}"#).unwrap();
    let l = p.load_layout().unwrap().unwrap();
    assert!(l.contains('x'));
}

#[test]
fn undo_log_ordering_and_dedup() {
    let d = tmp();
    let p = Project::new("ul", d.path()).unwrap();
    p.append_undo_entry("s", 0, "functions", "INSERT", 1, None, Some("{}")).unwrap();
    p.append_undo_entry("s", 1, "functions", "UPDATE", 1, Some("{}"), Some("{}"))
        .unwrap();
    // duplicate (session_id, seq) — IGNOREd
    p.append_undo_entry("s", 1, "functions", "UPDATE", 1, None, None).unwrap();
    let log = p.list_undo_log("s");
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].0, 0);
    assert_eq!(log[1].0, 1);
}

// ── 18. Binary stats ─────────────────────────────────────────────────────────

#[test]
fn binary_stats_counts_match() {
    let d = tmp();
    let mut p = Project::new("bs", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/bs.bin"), &sha_hex(20)).unwrap();
    for a in 0..5u64 {
        p.add_function_record(bid, a, "f").unwrap();
    }
    p.add_xref_record(bid, 0, 1, "call").unwrap();
    p.add_symbol(bid, 0, "n", "function", "user").unwrap();
    p.add_comment_record(bid, 0, "c").unwrap();
    p.add_string(bid, 0, "s", "utf8").unwrap();
    p.add_bookmark(bid, 0, "l", "#ffffff").unwrap();
    let s: BinaryStats = p.binary_stats(bid);
    assert_eq!(s.function_count, 5);
    assert_eq!(s.xref_count, 1);
    assert_eq!(s.symbol_count, 1);
    assert_eq!(s.comment_count, 1);
    assert_eq!(s.string_count, 1);
    assert_eq!(s.bookmark_count, 1);
}

// ── 19. Export JSON ─────────────────────────────────────────────────────────

#[test]
fn export_json_includes_function() {
    let d = tmp();
    let mut p = Project::new("ej", d.path()).unwrap();
    let bid = BinaryProject::add_binary(&mut p, Path::new("/tmp/ej.bin"), &sha_hex(21)).unwrap();
    p.add_function_record(bid, 0x4242, "uniquefn").unwrap();
    let json = p.export_json(bid).unwrap();
    assert!(json.contains("uniquefn"));
    assert!(json.contains("metadata"));
    // Roundtrip-parse
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("metadata").is_some());
}

// ── 20. Constants sanity ─────────────────────────────────────────────────────

#[test]
fn constants_match_doc() {
    assert_eq!(PROJECT_DIR_NAME, ".rustre-project");
    assert_eq!(DEFAULT_AUTOSAVE_INTERVAL_SECS, 300);
    assert_eq!(MAX_VERSION_SNAPSHOTS, 10);
}

// ── 21. Metadata fuzz round-trip ────────────────────────────────────────────

#[test]
fn metadata_serde_roundtrip_fuzz() {
    let mut g = Lcg::new();
    for i in 0..50u64 {
        let m = ProjectMetadata {
            name: format!("n{i}"),
            created_at: g.next(),
            last_modified: g.next(),
            created_at_iso: "1970-01-01T00:00:00+00:00".into(),
            version: "1.0.0".into(),
            description: if i % 2 == 0 { None } else { Some(format!("d{i}")) },
            tags: vec![format!("t{i}")],
            author: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        let m2: ProjectMetadata = serde_json::from_str(&s).unwrap();
        assert_eq!(m.name, m2.name);
        assert_eq!(m.tags, m2.tags);
        assert_eq!(m.description, m2.description);
    }
}
