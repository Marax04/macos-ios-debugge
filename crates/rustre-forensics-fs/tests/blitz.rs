//! Comprehensive integration tests for `rustre-forensics-fs`.
//!
//! Covers the top-level `MemFsNode`, `MemFsNodeV2`, `MemoryFs`, walkers,
//! `to_export_dir`, `mount_memory_fs`, the `export` module's `ExportOptions`
//! / `ExportResult` / `export_memfs`, and the self-contained `model` module
//! (`ProcessRecord`, `ModuleRecord`, `NetConnRecord`, `HandleRecord`,
//! `MemoryRange`, `Proto`, `Content`, `VfsNode`, `VfsTree`, `VfsBuilder`,
//! `TreeStats`, and CSV/text generators).

use rustre_forensics_fs::export::{ExportOptions, ExportResult, export_memfs};
use rustre_forensics_fs::model::{
    Content, HandleRecord, MemoryRange, ModuleRecord, NetConnRecord, ProcessRecord, Proto,
    TreeStats, VfsBuilder, VfsNode, VfsTree, connections_csv, handles_csv, modules_csv,
    process_csv, process_info_text,
};
use rustre_forensics_fs::{
    MemFs, MemFsContent, MemFsError, MemFsNode, MemFsNodeV2, MemFsV2Walker, MemFsWalker, MemoryFs,
    mount_memory_fs, to_export_dir,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

// ── helpers ──────────────────────────────────────────────────────────────────

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("rustre_ffs_blitz_{name}"));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn assert_send_sync<T: Send + Sync>() {}

// ── MemFsNode ────────────────────────────────────────────────────────────────

#[test]
fn memfsnode_file_is_file_not_dir() {
    let f = MemFsNode::File(vec![1, 2, 3]);
    assert!(f.is_file());
    assert!(!f.is_dir());
}

#[test]
fn memfsnode_directory_is_dir_not_file() {
    let d = MemFsNode::Directory(vec![]);
    assert!(d.is_dir());
    assert!(!d.is_file());
}

#[test]
fn memfsnode_lazy_is_file() {
    let l = MemFsNode::LazyFile(Box::new(|| vec![9, 9]));
    assert!(l.is_file());
    assert!(!l.is_dir());
}

#[test]
fn memfsnode_read_bytes_file() {
    let f = MemFsNode::File(b"abc".to_vec());
    assert_eq!(f.read_bytes(), Some(b"abc".to_vec()));
}

#[test]
fn memfsnode_read_bytes_lazy() {
    let l = MemFsNode::LazyFile(Box::new(|| b"xy".to_vec()));
    assert_eq!(l.read_bytes(), Some(b"xy".to_vec()));
}

#[test]
fn memfsnode_read_bytes_dir_is_none() {
    let d = MemFsNode::Directory(vec![]);
    assert!(d.read_bytes().is_none());
}

#[test]
fn memfsnode_children_dir() {
    let d = MemFsNode::Directory(vec![
        ("a".to_string(), MemFsNode::File(vec![])),
        ("b".to_string(), MemFsNode::File(vec![])),
    ]);
    let names = d.children().unwrap();
    assert_eq!(names, vec!["a", "b"]);
}

#[test]
fn memfsnode_children_file_is_none() {
    let f = MemFsNode::File(vec![]);
    assert!(f.children().is_none());
}

#[test]
fn memfsnode_child_lookup() {
    let d = MemFsNode::Directory(vec![("a".to_string(), MemFsNode::File(vec![1]))]);
    assert!(d.child("a").is_some());
    assert!(d.child("missing").is_none());
}

#[test]
fn memfsnode_child_on_file_is_none() {
    let f = MemFsNode::File(vec![]);
    assert!(f.child("anything").is_none());
}

// ── MemFsNodeV2 ──────────────────────────────────────────────────────────────

#[test]
fn v2_new_file_fields() {
    let n = MemFsNodeV2::new_file("a.txt", vec![1, 2, 3, 4], 7);
    assert_eq!(n.name, "a.txt");
    assert_eq!(n.inode, 7);
    assert_eq!(n.size(), 4);
    assert!(n.is_file());
    assert!(!n.is_dir());
    assert!(n.created > 0);
    assert!(n.modified >= n.created);
}

#[test]
fn v2_new_dir_fields() {
    let n = MemFsNodeV2::new_dir("d", 3);
    assert_eq!(n.name, "d");
    assert_eq!(n.inode, 3);
    assert_eq!(n.size(), 0);
    assert!(n.is_dir());
}

#[test]
fn v2_empty_file_size_zero() {
    let n = MemFsNodeV2::new_file("e", vec![], 1);
    assert_eq!(n.size(), 0);
}

#[test]
fn v2_add_child_and_find() {
    let mut d = MemFsNodeV2::new_dir("parent", 1);
    d.add_child(MemFsNodeV2::new_file("c.txt", b"x".to_vec(), 2));
    assert!(d.find_child("c.txt").is_some());
    assert!(d.find_child("nope").is_none());
}

#[test]
#[should_panic(expected = "add_child")]
fn v2_add_child_on_file_panics() {
    // The library documents this panic; verifying it is part of the API
    // contract, not masking a discrepancy.
    let mut f = MemFsNodeV2::new_file("f", vec![], 1);
    f.add_child(MemFsNodeV2::new_file("c", vec![], 2));
}

#[test]
fn v2_find_child_on_file_returns_none() {
    let f = MemFsNodeV2::new_file("f", vec![], 1);
    assert!(f.find_child("x").is_none());
}

#[test]
fn v2_find_by_inode_self() {
    let n = MemFsNodeV2::new_dir("r", 5);
    assert!(n.find_by_inode(5).is_some());
    assert!(n.find_by_inode(6).is_none());
}

#[test]
fn v2_find_by_inode_recursive() {
    let mut root = MemFsNodeV2::new_dir("r", 1);
    let mut sub = MemFsNodeV2::new_dir("sub", 2);
    sub.add_child(MemFsNodeV2::new_file("deep", b"z".to_vec(), 3));
    root.add_child(sub);
    assert!(root.find_by_inode(3).is_some());
    assert!(root.find_by_inode(99).is_none());
}

#[test]
fn v2_readdir_entries_dir() {
    let mut d = MemFsNodeV2::new_dir("d", 1);
    d.add_child(MemFsNodeV2::new_file("a", vec![], 2));
    d.add_child(MemFsNodeV2::new_dir("sub", 3));
    let e = d.readdir_entries();
    assert_eq!(e.len(), 2);
    let dir_flags: Vec<bool> = e.iter().map(|(_, _, is_dir)| *is_dir).collect();
    assert!(dir_flags.contains(&true));
    assert!(dir_flags.contains(&false));
}

#[test]
fn v2_readdir_entries_file_empty() {
    let f = MemFsNodeV2::new_file("f", vec![], 1);
    assert!(f.readdir_entries().is_empty());
}

// ── MemoryFs ─────────────────────────────────────────────────────────────────

#[test]
fn memoryfs_new_root_inode_1() {
    let fs = MemoryFs::new();
    assert_eq!(fs.root().inode, 1);
    assert!(fs.root().is_dir());
}

#[test]
fn memoryfs_default_equals_new() {
    let a = MemoryFs::default();
    let b = MemoryFs::new();
    assert_eq!(a.root().inode, b.root().inode);
}

#[test]
fn memoryfs_build_process_tree_empty_inputs() {
    let fs = MemoryFs::build_process_tree(&[], &[]);
    let procs = fs.root().find_child("processes").expect("processes dir");
    assert!(procs.is_dir());
    match &procs.content {
        MemFsContent::Dir(children) => assert!(children.is_empty()),
        _ => panic!("processes should be a dir"),
    }
}

#[test]
fn memoryfs_into_root_yields_root() {
    let fs = MemoryFs::new();
    let r = fs.into_root();
    assert_eq!(r.inode, 1);
}

// ── to_export_dir ────────────────────────────────────────────────────────────

#[test]
fn to_export_dir_writes_file() {
    let mut root = MemFsNodeV2::new_dir("root", 1);
    root.add_child(MemFsNodeV2::new_file("hello.txt", b"hi".to_vec(), 2));
    let dir = tmp("to_export_dir_file");
    to_export_dir(&root, &dir).unwrap();
    assert!(dir.exists());
    let content = std::fs::read(dir.join("hello.txt")).unwrap();
    assert_eq!(content, b"hi");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn to_export_dir_writes_nested() {
    let mut root = MemFsNodeV2::new_dir("root", 1);
    let mut sub = MemFsNodeV2::new_dir("sub", 2);
    sub.add_child(MemFsNodeV2::new_file("inner.bin", vec![0xAA, 0xBB], 3));
    root.add_child(sub);
    let dir = tmp("to_export_dir_nested");
    to_export_dir(&root, &dir).unwrap();
    assert!(dir.join("sub").join("inner.bin").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

// ── mount_memory_fs (non-Unix path) ──────────────────────────────────────────

#[cfg(not(unix))]
#[test]
fn mount_memory_fs_errors_on_non_unix() {
    let root = MemFsNodeV2::new_dir("r", 1);
    let res = mount_memory_fs(root, Path::new("C:/tmp/whatever"));
    assert!(res.is_err());
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains("FUSE") || msg.contains("Linux") || msg.contains("macOS"),
        "unexpected error message: {msg}"
    );
}

// ── MemFsError ───────────────────────────────────────────────────────────────

#[test]
fn memfs_error_from_io() {
    let io = std::io::Error::new(std::io::ErrorKind::Other, "boom");
    let e: MemFsError = io.into();
    match e {
        MemFsError::Io(_) => {}
        other => panic!("expected Io, got {other:?}"),
    }
}

#[test]
fn memfs_error_from_serde_json() {
    let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
    let e: MemFsError = json_err.into();
    match e {
        MemFsError::Serialization(_) => {}
        other => panic!("expected Serialization, got {other:?}"),
    }
}

#[test]
fn memfs_error_notfound_display() {
    let e = MemFsError::NotFound("/x".into());
    let s = format!("{e}");
    assert!(s.contains("/x"));
}

#[test]
fn memfs_error_not_a_directory_display() {
    let e = MemFsError::NotADirectory("/y".into());
    let s = format!("{e}");
    assert!(s.contains("/y"));
}

// ── export module ────────────────────────────────────────────────────────────

#[test]
fn export_options_defaults() {
    let o = ExportOptions::new("/tmp/x");
    assert!(o.include_empty_dirs);
    assert!(o.overwrite);
    assert!(!o.write_json_metadata);
    assert_eq!(o.max_file_size, 256 * 1024 * 1024);
}

#[test]
fn export_options_builder_chain() {
    let o = ExportOptions::new("/tmp/x")
        .without_empty_dirs()
        .with_max_file_size(7)
        .no_overwrite()
        .with_json_metadata();
    assert!(!o.include_empty_dirs);
    assert_eq!(o.max_file_size, 7);
    assert!(!o.overwrite);
    assert!(o.write_json_metadata);
}

#[test]
fn export_result_default_clean() {
    let r = ExportResult::default();
    assert!(r.is_clean());
    assert_eq!(r.total_items(), 0);
}

#[test]
fn export_result_total_items_sum() {
    let r = ExportResult {
        files_written: 3,
        dirs_created: 2,
        bytes_written: 50,
        skipped: 4,
        errors: vec![],
    };
    assert_eq!(r.total_items(), 9);
}

#[test]
fn export_result_with_errors_not_clean() {
    let r = ExportResult {
        errors: vec!["x".into()],
        ..Default::default()
    };
    assert!(!r.is_clean());
}

#[test]
fn export_memfs_writes_files_and_bytes() {
    let root = MemFsNode::Directory(vec![
        ("a.txt".into(), MemFsNode::File(b"hello".to_vec())),
        (
            "sub".into(),
            MemFsNode::Directory(vec![("b.bin".into(), MemFsNode::File(b"world".to_vec()))]),
        ),
    ]);
    let dir = tmp("export_memfs_basic");
    let opts = ExportOptions::new(&dir);
    let r = export_memfs(&root, &opts).unwrap();
    assert!(dir.join("a.txt").exists());
    assert!(dir.join("sub").join("b.bin").exists());
    assert_eq!(r.bytes_written, 10);
    assert!(r.files_written >= 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn export_memfs_skips_oversize() {
    let root = MemFsNode::Directory(vec![
        ("big".into(), MemFsNode::File(vec![0; 200])),
        ("ok".into(), MemFsNode::File(b"k".to_vec())),
    ]);
    let dir = tmp("export_memfs_oversize");
    let opts = ExportOptions::new(&dir).with_max_file_size(100);
    let r = export_memfs(&root, &opts).unwrap();
    assert_eq!(r.skipped, 1);
    assert!(!dir.join("big").exists());
    assert!(dir.join("ok").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn export_memfs_lazyfile_evaluated() {
    let count = std::sync::Arc::new(AtomicU32::new(0));
    let c2 = count.clone();
    let root = MemFsNode::Directory(vec![(
        "lz.txt".into(),
        MemFsNode::LazyFile(Box::new(move || {
            c2.fetch_add(1, Ordering::SeqCst);
            b"computed".to_vec()
        })),
    )]);
    let dir = tmp("export_memfs_lazy");
    export_memfs(&root, &ExportOptions::new(&dir)).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(dir.join("lz.txt")).unwrap(), b"computed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn export_memfs_metadata_sidecar() {
    let root = MemFsNode::Directory(vec![(
        "x.txt".into(),
        MemFsNode::File(b"y".to_vec()),
    )]);
    let dir = tmp("export_memfs_meta");
    let opts = ExportOptions::new(&dir).with_json_metadata();
    export_memfs(&root, &opts).unwrap();
    let meta = std::fs::read_to_string(dir.join("_metadata.json")).unwrap();
    assert!(meta.contains("x.txt"));
    assert!(meta.contains("file"));
    let _ = std::fs::remove_dir_all(&dir);
}

// ── model: ProcessRecord ────────────────────────────────────────────────────

#[test]
fn process_record_new_defaults() {
    let p = ProcessRecord::new(42, 1, "init");
    assert_eq!(p.pid, 42);
    assert_eq!(p.ppid, 1);
    assert_eq!(p.name, "init");
    assert_eq!(p.cmdline, "init");
    assert_eq!(p.base, 0);
    assert_eq!(p.size, 0);
    assert_eq!(p.handle_count, 0);
    assert!(p.modules.is_empty());
    assert!(p.memory_ranges.is_empty());
    assert!(p.handles.is_empty());
}

#[test]
fn process_record_builders() {
    let p = ProcessRecord::new(4, 0, "System")
        .with_image(0x1000, 0x2000)
        .with_cmdline("System cmd")
        .with_module(ModuleRecord::new("ntdll", 0x10, 0x20, "C:/ntdll"))
        .with_memory_range(MemoryRange::new(0, 0x10, "r--"))
        .with_handle(HandleRecord::new(1, "File", "f", 0x1F));
    assert_eq!(p.base, 0x1000);
    assert_eq!(p.size, 0x2000);
    assert_eq!(p.cmdline, "System cmd");
    assert_eq!(p.modules.len(), 1);
    assert_eq!(p.memory_ranges.len(), 1);
    assert_eq!(p.handles.len(), 1);
    assert_eq!(p.handle_count, 1);
}

#[test]
fn process_record_with_handle_increments_count() {
    let p = ProcessRecord::new(1, 0, "a")
        .with_handle(HandleRecord::new(1, "t", "n", 0))
        .with_handle(HandleRecord::new(2, "t", "n", 0));
    assert_eq!(p.handle_count, 2);
}

#[test]
fn process_record_with_handle_saturates() {
    let mut p = ProcessRecord::new(1, 0, "a");
    p.handle_count = u32::MAX;
    let p = p.with_handle(HandleRecord::new(9, "t", "n", 0));
    assert_eq!(p.handle_count, u32::MAX);
}

#[test]
fn process_record_eq() {
    let a = ProcessRecord::new(1, 0, "x");
    let b = ProcessRecord::new(1, 0, "x");
    assert_eq!(a, b);
}

// ── model: ModuleRecord ─────────────────────────────────────────────────────

#[test]
fn module_record_new() {
    let m = ModuleRecord::new("k.so", 0xABCD, 1024, "/lib/k.so");
    assert_eq!(m.name, "k.so");
    assert_eq!(m.base, 0xABCD);
    assert_eq!(m.size, 1024);
    assert_eq!(m.path, "/lib/k.so");
}

// ── model: Proto ────────────────────────────────────────────────────────────

#[test]
fn proto_as_str_all() {
    assert_eq!(Proto::Tcp.as_str(), "tcp");
    assert_eq!(Proto::Udp.as_str(), "udp");
    assert_eq!(Proto::Tcp6.as_str(), "tcp6");
    assert_eq!(Proto::Udp6.as_str(), "udp6");
}

#[test]
fn proto_eq_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(Proto::Tcp);
    s.insert(Proto::Tcp);
    s.insert(Proto::Udp);
    assert_eq!(s.len(), 2);
}

#[test]
fn proto_copy() {
    let p = Proto::Tcp6;
    let q = p; // Copy
    assert_eq!(p, q);
}

// ── model: NetConnRecord ────────────────────────────────────────────────────

#[test]
fn netconn_record_new() {
    let n = NetConnRecord::new(Proto::Tcp, "127.0.0.1", 80, "1.2.3.4", 443, "EST", 99);
    assert_eq!(n.proto, Proto::Tcp);
    assert_eq!(n.local_port, 80);
    assert_eq!(n.remote_addr, "1.2.3.4");
    assert_eq!(n.state, "EST");
    assert_eq!(n.pid, 99);
}

// ── model: HandleRecord ─────────────────────────────────────────────────────

#[test]
fn handle_record_new() {
    let h = HandleRecord::new(0xDEAD, "Key", "HKLM", 0x1F);
    assert_eq!(h.handle, 0xDEAD);
    assert_eq!(h.object_type, "Key");
    assert_eq!(h.name, "HKLM");
    assert_eq!(h.access, 0x1F);
}

// ── model: MemoryRange ──────────────────────────────────────────────────────

#[test]
fn memory_range_new_empty_bytes() {
    let r = MemoryRange::new(0x100, 0x200, "rwx");
    assert_eq!(r.start, 0x100);
    assert_eq!(r.end, 0x200);
    assert_eq!(r.protection, "rwx");
    assert!(r.bytes.is_empty());
}

#[test]
fn memory_range_len() {
    let r = MemoryRange::new(10, 30, "r");
    assert_eq!(r.len(), 20);
}

#[test]
fn memory_range_len_saturates() {
    let r = MemoryRange::new(100, 50, "r");
    assert_eq!(r.len(), 0);
}

#[test]
fn memory_range_is_empty() {
    assert!(MemoryRange::new(10, 10, "r").is_empty());
    assert!(MemoryRange::new(20, 5, "r").is_empty());
    assert!(!MemoryRange::new(5, 6, "r").is_empty());
}

#[test]
fn memory_range_with_bytes() {
    let r = MemoryRange::new(0, 4, "r").with_bytes(vec![1, 2, 3, 4]);
    assert_eq!(r.bytes, vec![1, 2, 3, 4]);
}

// ── model: Content ──────────────────────────────────────────────────────────

#[test]
fn content_bytes_roundtrip() {
    let c = Content::bytes(vec![1, 2, 3]);
    assert_eq!(c.read(), vec![1, 2, 3]);
    assert_eq!(c.size(), 3);
}

#[test]
fn content_text_roundtrip() {
    let c = Content::text("hello");
    assert_eq!(c.read(), b"hello".to_vec());
    assert_eq!(c.size(), 5);
}

#[test]
fn content_provider_called_each_read() {
    let counter = std::sync::Arc::new(AtomicU32::new(0));
    let c = {
        let counter = counter.clone();
        Content::provider(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            vec![1, 2]
        })
    };
    let _ = c.read();
    let _ = c.size();
    assert!(counter.load(Ordering::SeqCst) >= 2);
}

#[test]
fn content_debug_bytes() {
    let s = format!("{:?}", Content::bytes(vec![1, 2, 3]));
    assert!(s.contains("Bytes"));
}

#[test]
fn content_debug_provider() {
    let s = format!("{:?}", Content::provider(|| vec![]));
    assert!(s.contains("Provider"));
}

#[test]
fn content_send_sync() {
    assert_send_sync::<Content>();
}

// ── model: VfsNode ──────────────────────────────────────────────────────────

#[test]
fn vfsnode_dir_default_empty() {
    let n = VfsNode::dir();
    assert!(n.is_dir());
    assert!(!n.is_file());
    assert!(n.child_names().unwrap().is_empty());
}

#[test]
fn vfsnode_file_bytes_and_text() {
    let b = VfsNode::file_bytes(vec![1]);
    let t = VfsNode::file_text("hi");
    assert!(b.is_file());
    assert!(t.is_file());
    assert_eq!(b.size(), 1);
    assert_eq!(t.size(), 2);
}

#[test]
fn vfsnode_insert_sorts_children() {
    let mut d = VfsNode::dir();
    assert!(d.insert("b", VfsNode::file_text("")));
    assert!(d.insert("a", VfsNode::file_text("")));
    assert!(d.insert("c", VfsNode::file_text("")));
    assert_eq!(d.child_names().unwrap(), vec!["a", "b", "c"]);
}

#[test]
fn vfsnode_insert_replaces_existing() {
    let mut d = VfsNode::dir();
    d.insert("a", VfsNode::file_text("old"));
    d.insert("a", VfsNode::file_text("new"));
    assert_eq!(d.child_names().unwrap(), vec!["a"]);
    assert_eq!(d.child("a").unwrap().read().unwrap(), b"new".to_vec());
}

#[test]
fn vfsnode_insert_on_file_fails() {
    let mut f = VfsNode::file_text("x");
    assert!(!f.insert("a", VfsNode::dir()));
}

#[test]
fn vfsnode_child_on_file_none() {
    let f = VfsNode::file_text("");
    assert!(f.child("any").is_none());
    assert!(f.child_names().is_none());
}

#[test]
fn vfsnode_read_dir_none() {
    let d = VfsNode::dir();
    assert!(d.read().is_none());
    assert_eq!(d.size(), 0);
}

// ── model: VfsTree / VfsBuilder ─────────────────────────────────────────────

fn sample_tree() -> VfsTree {
    let procs = vec![
        ProcessRecord::new(4, 0, "System")
            .with_image(0x1000, 0x100)
            .with_memory_range(MemoryRange::new(0x1000, 0x1010, "r-x"))
            .with_handle(HandleRecord::new(1, "File", "log", 0x1F)),
        ProcessRecord::new(100, 4, "explorer.exe"),
    ];
    let kmods = vec![ModuleRecord::new("ntoskrnl.exe", 0x80000, 0x1000, "C:/")];
    let conns = vec![NetConnRecord::new(
        Proto::Tcp,
        "127.0.0.1",
        80,
        "0.0.0.0",
        0,
        "LISTEN",
        100,
    )];
    VfsBuilder::new()
        .with_processes(procs)
        .with_kernel_modules(kmods)
        .with_connections(conns)
        .build()
}

#[test]
fn vfstree_has_top_dirs() {
    let t = sample_tree();
    assert!(t.resolve("/processes").unwrap().is_dir());
    assert!(t.resolve("/kernel").unwrap().is_dir());
    assert!(t.resolve("/network").unwrap().is_dir());
    assert!(t.resolve("/summary.csv").unwrap().is_file());
}

#[test]
fn vfstree_resolve_root_variants() {
    let t = sample_tree();
    assert!(t.resolve("").unwrap().is_dir());
    assert!(t.resolve("/").unwrap().is_dir());
}

#[test]
fn vfstree_resolve_missing_none() {
    let t = sample_tree();
    assert!(t.resolve("/does/not/exist").is_none());
}

#[test]
fn vfstree_resolve_double_slash_ignored() {
    let t = sample_tree();
    assert!(t.resolve("//processes//").is_some());
}

#[test]
fn vfstree_list_dir_processes() {
    let t = sample_tree();
    let names = t.list_dir("/processes").unwrap();
    assert!(names.iter().any(|n| n.contains("System")));
    assert!(names.iter().any(|n| n.contains("explorer.exe")));
}

#[test]
fn vfstree_list_dir_on_file_none() {
    let t = sample_tree();
    assert!(t.list_dir("/summary.csv").is_none());
}

#[test]
fn vfstree_read_file_kernel_modules() {
    let t = sample_tree();
    let data = t.read_file("/kernel/modules.csv").unwrap();
    let s = String::from_utf8(data).unwrap();
    assert!(s.starts_with("name,base,size,path"));
    assert!(s.contains("ntoskrnl.exe"));
}

#[test]
fn vfstree_read_file_on_dir_none() {
    let t = sample_tree();
    assert!(t.read_file("/processes").is_none());
}

#[test]
fn vfstree_process_has_expected_files() {
    let t = sample_tree();
    let dir = t.list_dir("/processes").unwrap();
    let proc_dir = dir.iter().find(|n| n.contains("System")).unwrap();
    let p = format!("/processes/{proc_dir}");
    let files = t.list_dir(&p).unwrap();
    for f in ["info.txt", "cmdline.txt", "modules.csv", "handles.csv", "memory"] {
        assert!(files.contains(&f.to_string()), "missing {f}");
    }
}

#[test]
fn vfstree_memory_range_zero_filled_lazy() {
    let t = sample_tree();
    let dir = t.list_dir("/processes").unwrap();
    let proc_dir = dir.iter().find(|n| n.contains("System")).unwrap();
    let mem = t.list_dir(&format!("/processes/{proc_dir}/memory")).unwrap();
    assert!(!mem.is_empty());
    let fname = &mem[0];
    let data = t
        .read_file(&format!("/processes/{proc_dir}/memory/{fname}"))
        .unwrap();
    // 0x1010 - 0x1000 = 0x10 zero bytes
    assert_eq!(data.len(), 0x10);
    assert!(data.iter().all(|&b| b == 0));
}

#[test]
fn vfstree_stats() {
    let t = sample_tree();
    let s = t.stats();
    assert!(s.total_nodes > 0);
    assert!(s.files > 0);
    assert!(s.directories > 0);
    assert_eq!(s.total_nodes, s.files + s.directories);
}

#[test]
fn vfstree_walk_starts_at_root() {
    let t = sample_tree();
    let w = t.walk();
    assert_eq!(w[0].0, "/");
    assert!(w[0].1);
}

#[test]
fn vfstree_walk_finds_summary_csv() {
    let t = sample_tree();
    let w = t.walk();
    assert!(w.iter().any(|(p, _)| p == "/summary.csv"));
}

#[test]
fn vfstree_new_wraps_root() {
    let mut r = VfsNode::dir();
    r.insert("only", VfsNode::file_text("data"));
    let t = VfsTree::new(r);
    assert!(t.resolve("/only").is_some());
    assert!(t.root().is_dir());
}

#[test]
fn vfsbuilder_add_process() {
    let t = VfsBuilder::new()
        .add_process(ProcessRecord::new(1, 0, "a"))
        .add_process(ProcessRecord::new(2, 0, "b"))
        .build();
    let procs = t.list_dir("/processes").unwrap();
    assert_eq!(procs.len(), 2);
}

#[test]
fn vfsbuilder_default_empty() {
    let t = VfsBuilder::default().build();
    assert!(t.list_dir("/processes").unwrap().is_empty());
}

// ── model: TreeStats ────────────────────────────────────────────────────────

#[test]
fn tree_stats_default_zero() {
    let s = TreeStats::default();
    assert_eq!(s.total_nodes, 0);
    assert_eq!(s.files, 0);
    assert_eq!(s.directories, 0);
    assert_eq!(s.total_size, 0);
}

#[test]
fn tree_stats_copy_eq() {
    let s = TreeStats::default();
    let t = s; // Copy
    assert_eq!(s, t);
}

// ── model: CSV / text generators ────────────────────────────────────────────

#[test]
fn process_csv_header_and_row() {
    let s = process_csv(&[ProcessRecord::new(4, 0, "System")]);
    assert!(s.starts_with("pid,ppid,name,base,size,handle_count\n"));
    assert!(s.contains("4,0,System"));
}

#[test]
fn process_csv_empty_just_header() {
    let s = process_csv(&[]);
    assert_eq!(s, "pid,ppid,name,base,size,handle_count\n");
}

#[test]
fn modules_csv_header_and_row() {
    let s = modules_csv(&[ModuleRecord::new("ntdll.dll", 0x10, 1024, "C:/ntdll.dll")]);
    assert!(s.starts_with("name,base,size,path\n"));
    assert!(s.contains("ntdll.dll"));
}

#[test]
fn modules_csv_escapes_commas() {
    let s = modules_csv(&[ModuleRecord::new("a,b", 0, 0, "p")]);
    assert!(s.contains("\"a,b\""));
}

#[test]
fn connections_csv_header_and_row() {
    let s = connections_csv(&[NetConnRecord::new(
        Proto::Udp,
        "0.0.0.0",
        53,
        "0.0.0.0",
        0,
        "LISTEN",
        1,
    )]);
    assert!(s.starts_with("proto,local_addr,local_port,remote_addr,remote_port,state,pid\n"));
    assert!(s.contains("udp,"));
}

#[test]
fn handles_csv_header_and_row() {
    let s = handles_csv(&[HandleRecord::new(0xABCD, "File", "log.txt", 0x1F)]);
    assert!(s.starts_with("handle,object_type,name,access\n"));
    assert!(s.contains("0xabcd"));
    assert!(s.contains("File"));
}

#[test]
fn handles_csv_escapes_quotes() {
    let s = handles_csv(&[HandleRecord::new(1, "T", "a\"b", 0)]);
    assert!(s.contains("\"a\"\"b\""));
}

#[test]
fn process_info_text_fields_present() {
    let p = ProcessRecord::new(42, 1, "init").with_image(0x1234, 0x100);
    let s = process_info_text(&p);
    assert!(s.contains("pid:"));
    assert!(s.contains("42"));
    assert!(s.contains("ppid:"));
    assert!(s.contains("init"));
    assert!(s.contains("0x0000000000001234"));
    assert!(s.contains("handle_count:"));
}

// ── MemFs (image-backed) — sanity over the public API ──────────────────────

#[test]
fn memfs_build_with_mock_image() {
    use rustre_forensics::{MemoryImage, OsType};
    use rustre_forensics_mem::build_mock_image;
    let img = build_mock_image(OsType::Windows);
    let fs = MemFs::build(&img as &dyn MemoryImage).expect("build");
    let entries = fs.list_dir("/").unwrap();
    assert!(entries.contains(&"processes".to_string()));
    assert!(entries.contains(&"network".to_string()));
    assert!(entries.contains(&"kernel".to_string()));
}

#[test]
fn memfs_root_is_dir() {
    use rustre_forensics::{MemoryImage, OsType};
    use rustre_forensics_mem::build_mock_image;
    let img = build_mock_image(OsType::Windows);
    let fs = MemFs::build(&img as &dyn MemoryImage).unwrap();
    assert!(fs.root().is_dir());
}

#[test]
fn memfs_walker_starts_at_root() {
    use rustre_forensics::{MemoryImage, OsType};
    use rustre_forensics_mem::build_mock_image;
    let img = build_mock_image(OsType::Windows);
    let fs = MemFs::build(&img as &dyn MemoryImage).unwrap();
    let mut w = MemFsWalker::new(&fs);
    let first = w.next().unwrap();
    assert_eq!(first.0, "/");
    assert!(first.1);
}

#[test]
fn memfsv2_walker_starts_at_root() {
    let fs = MemoryFs::new();
    let mut w = MemFsV2Walker::new(&fs);
    let first = w.next().unwrap();
    assert_eq!(first.0, "/");
    assert!(first.1);
}

#[test]
fn memfsv2_walker_visits_added_child() {
    let img_processes = [];
    let img_modules = [];
    let fs = MemoryFs::build_process_tree(&img_processes, &img_modules);
    let w = MemFsV2Walker::new(&fs);
    let paths: Vec<String> = w.map(|(p, _)| p).collect();
    assert!(paths.iter().any(|p| p == "/processes"));
}
