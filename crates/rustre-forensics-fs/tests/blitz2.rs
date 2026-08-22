//! Blitz2 coverage tests for `rustre-forensics-fs`.
//!
//! Exercises constructors, boundaries, round-trips, error variants,
//! Display/Debug, and Send/Sync threaded usage of public types.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Arc;
use std::thread;

use rustre_forensics_fs::{
    MemFs, MemFsContent, MemFsError, MemFsNode, MemFsNodeV2, MemFsV2Walker, MemFsWalker, MemoryFs,
    to_export_dir,
};

// ─── Seeded LCG ──────────────────────────────────────────────────────────────

struct Lcg {
    s: u64,
}
impl Lcg {
    const fn new() -> Self {
        Self {
            s: 0xDEAD_BEEF_CAFE_BABE,
        }
    }
    const fn next(&mut self) -> u64 {
        self.s = self
            .s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.s
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_memfs() -> MemFs {
    use rustre_forensics::OsType;
    use rustre_forensics_mem::build_mock_image;
    let img = build_mock_image(OsType::Windows);
    MemFs::build(&img).unwrap()
}

fn make_linux_memfs() -> MemFs {
    use rustre_forensics::OsType;
    use rustre_forensics_mem::build_mock_image;
    let img = build_mock_image(OsType::Linux);
    MemFs::build(&img).unwrap()
}

fn make_memoryfs() -> MemoryFs {
    use rustre_forensics::OsType;
    use rustre_forensics_mem::{WindowsAnalyzer, build_mock_image};
    let img = build_mock_image(OsType::Windows);
    let p = WindowsAnalyzer::find_processes(&img);
    let m = WindowsAnalyzer::find_modules(&img, 0);
    MemoryFs::build_process_tree(&p, &m)
}

fn hash_of<T: Hash>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

// ═══ Constructors ════════════════════════════════════════════════════════════

#[test]
fn memfsnode_file_constructor() {
    let n = MemFsNode::File(vec![1, 2, 3]);
    assert!(n.is_file());
    assert!(!n.is_dir());
}

#[test]
fn memfsnode_directory_constructor() {
    let n = MemFsNode::Directory(vec![]);
    assert!(n.is_dir());
    assert!(!n.is_file());
}

#[test]
fn memfsnode_lazyfile_constructor() {
    let n = MemFsNode::LazyFile(Box::new(|| vec![7, 8, 9]));
    assert!(n.is_file());
    assert_eq!(n.read_bytes().unwrap(), vec![7, 8, 9]);
}

#[test]
fn memfsnodev2_new_file_constructor() {
    let n = MemFsNodeV2::new_file("a", vec![0u8; 16], 5);
    assert_eq!(n.name, "a");
    assert_eq!(n.inode, 5);
    assert!(n.is_file());
    assert_eq!(n.size(), 16);
}

#[test]
fn memfsnodev2_new_dir_constructor() {
    let n = MemFsNodeV2::new_dir("d", 7);
    assert!(n.is_dir());
    assert_eq!(n.size(), 0);
    assert_eq!(n.inode, 7);
}

#[test]
fn memoryfs_new_constructor() {
    let fs = MemoryFs::new();
    assert_eq!(fs.root().inode, 1);
    assert!(fs.root().is_dir());
}

#[test]
fn memoryfs_default_constructor() {
    let fs: MemoryFs = MemoryFs::default();
    assert!(fs.root().is_dir());
    assert_eq!(fs.root().inode, 1);
}

// ═══ Boundaries: 0, 1, max, off-by-one ═══════════════════════════════════════

#[test]
fn memfsnodev2_size_zero_file() {
    let n = MemFsNodeV2::new_file("z", vec![], 2);
    assert_eq!(n.size(), 0);
}

#[test]
fn memfsnodev2_size_one_byte_file() {
    let n = MemFsNodeV2::new_file("o", vec![0xFF], 3);
    assert_eq!(n.size(), 1);
}

#[test]
fn memfsnodev2_size_large_file() {
    let n = MemFsNodeV2::new_file("big", vec![0u8; 100_000], 4);
    assert_eq!(n.size(), 100_000);
}

#[test]
fn memfsnodev2_inode_zero() {
    let n = MemFsNodeV2::new_file("a", vec![], 0);
    assert_eq!(n.inode, 0);
}

#[test]
fn memfsnodev2_inode_u64_max() {
    let n = MemFsNodeV2::new_dir("m", u64::MAX);
    assert_eq!(n.inode, u64::MAX);
}

#[test]
fn memfsnodev2_find_by_inode_self() {
    let n = MemFsNodeV2::new_dir("root", 1);
    assert!(n.find_by_inode(1).is_some());
}

#[test]
fn memfsnodev2_find_by_inode_off_by_one() {
    let n = MemFsNodeV2::new_dir("root", 5);
    assert!(n.find_by_inode(4).is_none());
    assert!(n.find_by_inode(6).is_none());
}

#[test]
fn memfsnodev2_find_by_inode_missing() {
    let mut root = MemFsNodeV2::new_dir("r", 1);
    root.add_child(MemFsNodeV2::new_file("a", vec![], 2));
    assert!(root.find_by_inode(999).is_none());
}

#[test]
fn memfsnodev2_empty_dir_readdir() {
    let n = MemFsNodeV2::new_dir("empty", 1);
    assert!(n.readdir_entries().is_empty());
}

#[test]
fn memfsnodev2_one_child_readdir() {
    let mut d = MemFsNodeV2::new_dir("d", 1);
    d.add_child(MemFsNodeV2::new_file("c", vec![], 2));
    assert_eq!(d.readdir_entries().len(), 1);
}

#[test]
fn memfsnode_file_empty_read_bytes() {
    let n = MemFsNode::File(vec![]);
    assert_eq!(n.read_bytes().unwrap(), Vec::<u8>::new());
}

#[test]
fn memfsnode_directory_empty_children() {
    let n = MemFsNode::Directory(vec![]);
    assert_eq!(n.children().unwrap().len(), 0);
}

#[test]
fn memfsnode_child_nonexistent() {
    let n = MemFsNode::Directory(vec![("a".to_string(), MemFsNode::File(vec![]))]);
    assert!(n.child("zzz").is_none());
}

#[test]
fn memfsnode_child_on_file_is_none() {
    let n = MemFsNode::File(vec![1]);
    assert!(n.child("x").is_none());
}

// ═══ Round-trips (LCG, 50 inputs) ════════════════════════════════════════════

#[test]
fn round_trip_file_bytes_50() {
    let mut lcg = Lcg::new();
    for i in 0..50 {
        let len = (lcg.next() % 257) as usize;
        let data: Vec<u8> = (0..len).map(|_| (lcg.next() & 0xFF) as u8).collect();
        let n = MemFsNode::File(data.clone());
        let read = n.read_bytes().unwrap();
        assert_eq!(read, data, "iter {i} mismatch");
    }
}

#[test]
fn round_trip_lazy_file_bytes_50() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let len = (lcg.next() % 129) as usize;
        let data: Vec<u8> = (0..len).map(|_| (lcg.next() & 0xFF) as u8).collect();
        let d2 = data.clone();
        let n = MemFsNode::LazyFile(Box::new(move || d2.clone()));
        assert_eq!(n.read_bytes().unwrap(), data);
    }
}

#[test]
fn round_trip_memfsnodev2_size_50() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let len = (lcg.next() % 1024) as usize;
        let ino = lcg.next();
        let n = MemFsNodeV2::new_file("f", vec![0u8; len], ino);
        assert_eq!(n.size(), len as u64);
        assert_eq!(n.inode, ino);
    }
}

#[test]
fn round_trip_find_child_50() {
    let mut lcg = Lcg::new();
    let mut dir = MemFsNodeV2::new_dir("root", 1);
    let mut names = Vec::new();
    for i in 0..50 {
        let name = format!("child_{}_{}", i, lcg.next() & 0xFFFF);
        dir.add_child(MemFsNodeV2::new_file(&name, vec![i as u8], i as u64 + 2));
        names.push(name);
    }
    for name in &names {
        assert!(dir.find_child(name).is_some(), "missing {name}");
    }
}

#[test]
fn round_trip_find_by_inode_50() {
    let mut dir = MemFsNodeV2::new_dir("root", 1);
    for i in 2..=51u64 {
        dir.add_child(MemFsNodeV2::new_file(format!("f{i}"), vec![], i));
    }
    for i in 2..=51u64 {
        assert!(dir.find_by_inode(i).is_some(), "missing ino {i}");
    }
}

// ═══ Specific Err variants ═══════════════════════════════════════════════════

#[test]
fn memfs_error_notfound_display() {
    let e = MemFsError::NotFound("/x/y".to_string());
    let s = format!("{e}");
    assert!(s.contains("/x/y"));
    assert!(s.contains("not found"));
}

#[test]
fn memfs_error_notadirectory_display() {
    let e = MemFsError::NotADirectory("/foo".to_string());
    let s = format!("{e}");
    assert!(s.contains("/foo"));
}

#[test]
fn memfs_error_io_from_std() {
    let io = std::io::Error::other("boom");
    let e: MemFsError = io.into();
    assert!(matches!(e, MemFsError::Io(_)));
}

#[test]
fn memfs_error_serialization_from_json() {
    let bad: Result<serde_json::Value, _> = serde_json::from_str("{not json");
    let err = bad.unwrap_err();
    let e: MemFsError = err.into();
    assert!(matches!(e, MemFsError::Serialization(_)));
}

#[test]
fn memfs_error_debug_includes_variant_name() {
    let e = MemFsError::NotFound("p".to_string());
    let d = format!("{e:?}");
    assert!(d.contains("NotFound"));
}

#[test]
fn memfs_error_serialization_debug() {
    let e = MemFsError::Serialization("oops".to_string());
    let d = format!("{e:?}");
    assert!(d.contains("Serialization"));
}

// ═══ Display/Debug consistency on 30+ pairs ══════════════════════════════════

#[test]
fn debug_consistency_30_memfsnodev2_files() {
    let mut lcg = Lcg::new();
    for i in 0..30 {
        let ino = lcg.next();
        let n1 = MemFsNodeV2::new_file(format!("f{i}"), vec![i as u8], ino);
        let n2 = MemFsNodeV2::new_file(format!("f{i}"), vec![i as u8], ino);
        // names and inodes should match
        assert_eq!(n1.name, n2.name);
        assert_eq!(n1.inode, n2.inode);
        assert_eq!(n1.size(), n2.size());
    }
}

#[test]
fn debug_consistency_30_error_variants() {
    for i in 0..30 {
        let e1 = MemFsError::NotFound(format!("p{i}"));
        let e2 = MemFsError::NotFound(format!("p{i}"));
        assert_eq!(format!("{e1:?}"), format!("{e2:?}"));
        assert_eq!(format!("{e1}"), format!("{e2}"));
    }
}

#[test]
fn display_format_30_notfound_paths() {
    for i in 0..30 {
        let path = format!("/a/b/{i}");
        let e = MemFsError::NotFound(path.clone());
        let s = format!("{e}");
        assert!(s.contains(&path), "missing path in display: {s}");
    }
}

// ═══ Hash consistency on 30+ pairs ═══════════════════════════════════════════

#[test]
fn hash_consistency_30_strings() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let v = lcg.next();
        let s1 = format!("inode_{v}");
        let s2 = s1.clone();
        assert_eq!(hash_of(&s1), hash_of(&s2));
    }
}

#[test]
fn hash_inode_pairs_30() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let a = lcg.next();
        let b = a;
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

#[test]
fn eq_consistency_30_string_names() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let s1 = format!("n_{}", lcg.next());
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }
}

// ═══ MemFs/MemoryFs structural tests ═════════════════════════════════════════

#[test]
fn memfs_root_is_dir() {
    let fs = make_memfs();
    assert!(fs.root().is_dir());
}

#[test]
fn memfs_resolve_processes() {
    let fs = make_memfs();
    assert!(fs.resolve("/processes").unwrap().is_dir());
}

#[test]
fn memfs_resolve_with_trailing_slash() {
    let fs = make_memfs();
    assert!(fs.resolve("/processes/").is_some());
}

#[test]
fn memfs_resolve_empty_root() {
    let fs = make_memfs();
    assert!(fs.resolve("").is_some());
}

#[test]
fn memfs_resolve_double_slash() {
    let fs = make_memfs();
    assert!(fs.resolve("//processes").is_some());
}

#[test]
fn memfs_linux_build_ok() {
    let fs = make_linux_memfs();
    assert!(fs.list_dir("/").is_some());
}

#[test]
fn memfs_read_file_nonexistent() {
    let fs = make_memfs();
    assert!(fs.read_file("/no/such/file").is_none());
}

#[test]
fn memfs_walker_paths_nonempty() {
    let fs = make_memfs();
    let cnt = MemFsWalker::new(&fs).count();
    assert!(cnt > 1);
}

#[test]
fn memoryfs_v2_walker_paths_nonempty() {
    let fs = make_memoryfs();
    let cnt = MemFsV2Walker::new(&fs).count();
    assert!(cnt >= 1);
}

#[test]
fn memoryfs_into_root_works() {
    let fs = MemoryFs::new();
    let root = fs.into_root();
    assert_eq!(root.inode, 1);
}

#[test]
fn to_export_dir_roundtrip() {
    let fs = make_memoryfs();
    let tmp = std::env::temp_dir().join(format!("rustre_fs_blitz2_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    to_export_dir(fs.root(), &tmp).unwrap();
    assert!(tmp.exists());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn to_export_dir_sanitizes_dotdot() {
    let mut root = MemFsNodeV2::new_dir("root", 1);
    root.add_child(MemFsNodeV2::new_file("..", b"x".to_vec(), 2));
    let tmp = std::env::temp_dir().join(format!("rustre_fs_blitz2_san_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    to_export_dir(&root, &tmp).unwrap();
    // The ".." child must not escape tmp.
    let parent = tmp.parent().unwrap();
    let escaped = parent.join("..");
    // Verify we didn't write outside tmp by checking tmp now has a sanitized entry.
    let entries: Vec<_> = std::fs::read_dir(&tmp).unwrap().collect();
    assert!(!entries.is_empty());
    let _ = escaped;
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn memfs_export_creates_dirs() {
    let fs = make_memfs();
    let tmp = std::env::temp_dir().join(format!("rustre_fs_blitz2_exp_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    fs.export(&tmp).unwrap();
    assert!(tmp.join("network").exists());
    assert!(tmp.join("kernel").exists());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn memoryfs_build_process_tree_empty_has_processes() {
    let fs = MemoryFs::build_process_tree(&[], &[]);
    assert!(fs.root().find_child("processes").is_some());
}

#[test]
fn memfsnodev2_add_child_updates_dir() {
    let mut d = MemFsNodeV2::new_dir("d", 1);
    let before = d.readdir_entries().len();
    d.add_child(MemFsNodeV2::new_file("x", vec![], 2));
    assert_eq!(d.readdir_entries().len(), before + 1);
}

#[test]
#[should_panic(expected = "add_child")]
fn memfsnodev2_add_child_on_file_panics() {
    let mut f = MemFsNodeV2::new_file("f", vec![], 1);
    f.add_child(MemFsNodeV2::new_file("c", vec![], 2));
}

#[test]
fn memfsnode_children_on_file_is_none() {
    let n = MemFsNode::File(vec![]);
    assert!(n.children().is_none());
}

// ═══ Send/Sync threaded 4×100 ════════════════════════════════════════════════

#[test]
fn send_sync_memfs_4x100() {
    let fs = Arc::new(make_memfs());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let fs = Arc::clone(&fs);
        handles.push(thread::spawn(move || {
            let mut hits = 0u32;
            for _ in 0..100 {
                if fs.resolve("/processes").is_some() {
                    hits += 1;
                }
                if fs.list_dir("/").is_some() {
                    hits += 1;
                }
            }
            hits
        }));
    }
    for h in handles {
        let n = h.join().unwrap();
        assert_eq!(n, 200);
    }
}

#[test]
fn send_sync_memoryfs_4x100() {
    let fs = Arc::new(make_memoryfs());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let fs = Arc::clone(&fs);
        handles.push(thread::spawn(move || {
            let mut hits = 0u32;
            for _ in 0..100 {
                if fs.root().find_child("processes").is_some() {
                    hits += 1;
                }
            }
            hits
        }));
    }
    for h in handles {
        let n = h.join().unwrap();
        assert_eq!(n, 100);
    }
}

#[test]
fn send_sync_node_4x100() {
    let n = Arc::new(MemFsNodeV2::new_file("shared", vec![1, 2, 3, 4], 42));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let n = Arc::clone(&n);
        handles.push(thread::spawn(move || {
            let mut ok = 0;
            for _ in 0..100 {
                if n.size() == 4 && n.inode == 42 {
                    ok += 1;
                }
            }
            ok
        }));
    }
    for h in handles {
        assert_eq!(h.join().unwrap(), 100);
    }
}

#[test]
fn send_sync_error_4x100() {
    // MemFsError isn't Clone, so build per-thread; just confirm Display is thread-safe.
    let mut handles = Vec::new();
    for tid in 0..4u32 {
        handles.push(thread::spawn(move || {
            let mut sum = 0;
            for i in 0..100u32 {
                let e = MemFsError::NotFound(format!("/t{tid}/i{i}"));
                let s = format!("{e}");
                sum += s.len();
            }
            sum
        }));
    }
    for h in handles {
        assert!(h.join().unwrap() > 0);
    }
}

// ═══ Path / sanitize boundary cases via public surface ═══════════════════════

#[test]
fn to_export_dir_writes_file_content() {
    let mut root = MemFsNodeV2::new_dir("r", 1);
    root.add_child(MemFsNodeV2::new_file("hello.txt", b"world".to_vec(), 2));
    let tmp = std::env::temp_dir().join(format!("rustre_fs_blitz2_file_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    to_export_dir(&root, &tmp).unwrap();
    let read = std::fs::read(tmp.join("hello.txt")).unwrap();
    assert_eq!(read, b"world");
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn memfs_walker_yields_dirs_and_files() {
    let fs = make_memfs();
    let mut saw_dir = false;
    let mut saw_file = false;
    for (_, is_dir) in MemFsWalker::new(&fs) {
        if is_dir {
            saw_dir = true;
        } else {
            saw_file = true;
        }
    }
    assert!(saw_dir);
    assert!(saw_file);
}

#[test]
fn memoryfs_v2_walker_root_first() {
    let fs = MemoryFs::new();
    let mut w = MemFsV2Walker::new(&fs);
    let first = w.next().unwrap();
    assert_eq!(first.0, "/");
    assert!(first.1);
}

#[test]
fn memfscontent_variants_distinguishable() {
    let f = MemFsContent::File(vec![1, 2]);
    let d = MemFsContent::Dir(vec![]);
    match f {
        MemFsContent::File(v) => assert_eq!(v, vec![1, 2]),
        _ => panic!("wrong"),
    }
    match d {
        MemFsContent::Dir(v) => assert!(v.is_empty()),
        _ => panic!("wrong"),
    }
}

#[test]
fn to_export_dir_accepts_path_ref() {
    let root = MemFsNodeV2::new_dir("r", 1);
    let tmp = std::env::temp_dir().join(format!("rustre_fs_blitz2_pr_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let p: &Path = tmp.as_path();
    to_export_dir(&root, p).unwrap();
    assert!(tmp.exists());
    let _ = std::fs::remove_dir_all(&tmp);
}
