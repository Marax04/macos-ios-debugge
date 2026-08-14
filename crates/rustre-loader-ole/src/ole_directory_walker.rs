//! `ole_directory_walker` — Walk the OLE2 (CFB) directory tree.
//!
//! Reconstructs the red-black tree of directory entries stored in the CFB
//! container and provides iterators, path lookup, and listing helpers.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

// ── DirEntryKind ──────────────────────────────────────────────────────────────

/// Kind of a CFB directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirEntryKind {
    /// The root storage (always entry 0).
    RootStorage,
    /// An intermediate storage (like a directory).
    Storage,
    /// A leaf stream (like a file).
    Stream,
    /// An unused / free directory entry.
    Empty,
}

impl fmt::Display for DirEntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::RootStorage => "Root",
            Self::Storage => "Storage",
            Self::Stream => "Stream",
            Self::Empty => "Empty",
        };
        f.write_str(s)
    }
}

impl DirEntryKind {
    /// Return `true` if the entry can contain children.
    #[must_use]
    pub const fn is_container(&self) -> bool {
        matches!(self, Self::RootStorage | Self::Storage)
    }

    /// Return `true` if the entry carries stream data.
    #[must_use]
    pub const fn is_stream(&self) -> bool {
        matches!(self, Self::Stream)
    }
}

// ── DirEntry ──────────────────────────────────────────────────────────────────

/// A single directory entry in the OLE2 (CFB) directory.
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Directory entry index (0-based, 0 = root).
    pub index: u32,
    /// Entry name (UTF-16 decoded).
    pub name: String,
    /// Kind of entry.
    pub kind: DirEntryKind,
    /// Size of the stream data in bytes (0 for storages).
    pub size: u64,
    /// Starting sector / mini-sector of the stream (0xFFFFFFFE for none).
    pub start_sector: u32,
    /// Colour bit for the CFB red-black tree (0 = red, 1 = black).
    pub color: u8,
    /// Index of the left sibling entry (0xFFFFFFFF if none).
    pub left_sibling: u32,
    /// Index of the right sibling entry (0xFFFFFFFF if none).
    pub right_sibling: u32,
    /// Index of the first child entry (0xFFFFFFFF if none).
    pub child: u32,
    /// CLSID (only for storages).
    pub clsid: Option<[u8; 16]>,
    /// Creation time (Windows FILETIME).
    pub create_time: u64,
    /// Modified time (Windows FILETIME).
    pub modify_time: u64,
    /// Index of this entry's parent in the tree (filled by walker).
    pub parent_index: Option<u32>,
}

const NOENT: u32 = 0xFFFF_FFFF;

/// Deepest directory nesting the walkers will follow.
///
/// The `depth` parameter was already threaded through `walk_recursive`,
/// `walk_children` and `format_tree_recursive`, incremented at every level — but
/// never compared against anything, so it bounded nothing.  That mattered
/// because the cycle protection in those functions does not span the recursion:
/// each call builds its **own** `visited` set, which guards the sibling stack at
/// that one level while the `child` recursion starts afresh.  A container whose
/// child is a container that points back at it therefore recursed until the
/// stack overflowed — a crash, not an error a caller could handle — while
/// pushing an entry per level into the output.
///
/// Sibling links were guarded and child links were not, so the file already
/// treated a cycle as reachable; this makes the second axis agree with the
/// first.  Real CFB trees nest a handful of levels deep, so 64 rejects nothing
/// a well-formed container does.
const MAX_TREE_DEPTH: usize = 64;

impl DirEntry {
    /// Create a root storage entry.
    #[must_use]
    pub fn root() -> Self {
        Self {
            index: 0,
            name: "Root Entry".into(),
            kind: DirEntryKind::RootStorage,
            size: 0,
            start_sector: NOENT,
            color: 1,
            left_sibling: NOENT,
            right_sibling: NOENT,
            child: 1,
            clsid: None,
            create_time: 0,
            modify_time: 0,
            parent_index: None,
        }
    }

    /// Create a storage (folder) entry.
    #[must_use]
    pub fn storage(index: u32, name: impl Into<String>, parent: u32) -> Self {
        Self {
            index,
            name: name.into(),
            kind: DirEntryKind::Storage,
            size: 0,
            start_sector: NOENT,
            color: 1,
            left_sibling: NOENT,
            right_sibling: NOENT,
            child: NOENT,
            clsid: None,
            create_time: 0,
            modify_time: 0,
            parent_index: Some(parent),
        }
    }

    /// Create a stream entry.
    #[must_use]
    pub fn stream(index: u32, name: impl Into<String>, parent: u32, size: u64, sector: u32) -> Self {
        Self {
            index,
            name: name.into(),
            kind: DirEntryKind::Stream,
            size,
            start_sector: sector,
            color: 0,
            left_sibling: NOENT,
            right_sibling: NOENT,
            child: NOENT,
            clsid: None,
            create_time: 0,
            modify_time: 0,
            parent_index: Some(parent),
        }
    }

    /// Return `true` if this entry has no left sibling.
    #[must_use]
    pub const fn has_left(&self) -> bool {
        self.left_sibling != NOENT
    }

    /// Return `true` if this entry has a right sibling.
    #[must_use]
    pub const fn has_right(&self) -> bool {
        self.right_sibling != NOENT
    }

    /// Return `true` if this entry has a child.
    #[must_use]
    pub const fn has_child(&self) -> bool {
        self.child != NOENT
    }
}

impl fmt::Display for DirEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:04}] {:20} ({}) size={} sector=0x{:08x}",
            self.index, self.name, self.kind, self.size, self.start_sector,
        )
    }
}

// ── OleDirectoryWalker ────────────────────────────────────────────────────────

/// Walks the OLE2 (CFB) directory tree and provides navigation / listing APIs.
#[derive(Debug)]
pub struct OleDirectoryWalker {
    /// All directory entries, indexed by their position.
    pub entries: HashMap<u32, DirEntry>,
    /// Maximum tree depth observed.
    pub max_depth: usize,
}

impl OleDirectoryWalker {
    /// Create a new walker with no entries.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_depth: 0,
        }
    }

    /// Add a directory entry.
    pub fn add_entry(&mut self, entry: DirEntry) {
        self.entries.insert(entry.index, entry);
    }

    /// Build a default OLE layout similar to a minimal Office document.
    ///
    /// Root (0)
    ///   `WorkBook` (1) — stream
    ///   VBA (2) — storage
    ///     _`VBA_PROJECT` (3) — stream
    ///     dir (4) — stream
    ///     Module1 (5) — stream
    pub fn build_default_layout(&mut self) {
        let root = DirEntry::root();
        let workbook = {
            let mut s = DirEntry::stream(1, "Workbook", 0, 4096, 0x00);
            s.right_sibling = 2;
            s
        };
        let vba_storage = {
            let mut s = DirEntry::storage(2, "VBA", 0);
            s.child = 4;
            s
        };
        let vba_project = DirEntry::stream(3, "_VBA_PROJECT", 2, 512, 0x10);
        let dir_stream = {
            let mut s = DirEntry::stream(4, "dir", 2, 256, 0x12);
            s.left_sibling = 3;
            s.right_sibling = 5;
            s
        };
        let module1 = DirEntry::stream(5, "Module1", 2, 1024, 0x14);

        for e in [root, workbook, vba_storage, vba_project, dir_stream, module1] {
            self.add_entry(e);
        }
    }

    /// Walk the directory tree starting from `root_index` and return
    /// entries in pre-order (storage before its children).
    #[must_use]
    pub fn walk_directory(&self) -> Vec<&DirEntry> {
        let mut result = Vec::new();
        self.walk_recursive(0, 0, &mut result);
        result
    }

    fn walk_recursive<'a>(
        &'a self,
        index: u32,
        depth: usize,
        out: &mut Vec<&'a DirEntry>,
    ) {
        if depth > MAX_TREE_DEPTH {
            return;
        }
        let entry = match self.entries.get(&index) {
            Some(e) => e,
            None => return,
        };
        out.push(entry);
        if entry.kind.is_container() && entry.child != NOENT {
            // Walk the red-black tree of children iteratively via the sibling links.
            self.walk_children(entry.child, depth + 1, out);
        }
    }

    fn walk_children<'a>(
        &'a self,
        start: u32,
        depth: usize,
        out: &mut Vec<&'a DirEntry>,
    ) {
        if depth > MAX_TREE_DEPTH {
            return;
        }
        // Collect child indices via sibling traversal (left, self, right).
        let mut stack: Vec<u32> = vec![start];
        let mut visited = std::collections::HashSet::new();
        while let Some(idx) = stack.pop() {
            if idx == NOENT || !visited.insert(idx) {
                continue;
            }
            let entry = match self.entries.get(&idx) {
                Some(e) => e,
                None => continue,
            };
            out.push(entry);
            // Recurse into children.
            if entry.kind.is_container() && entry.child != NOENT {
                self.walk_children(entry.child, depth + 1, out);
            }
            if entry.left_sibling != NOENT {
                stack.push(entry.left_sibling);
            }
            if entry.right_sibling != NOENT {
                stack.push(entry.right_sibling);
            }
        }
    }

    /// Find an entry by exact name (case-sensitive).
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&DirEntry> {
        self.entries.values().find(|e| e.name == name)
    }

    /// List all stream entries (non-container, non-empty).
    #[must_use]
    pub fn streams(&self) -> Vec<&DirEntry> {
        let mut v: Vec<&DirEntry> = self
            .entries
            .values()
            .filter(|e| e.kind == DirEntryKind::Stream)
            .collect();
        v.sort_by_key(|e| e.index);
        v
    }

    /// List all storage entries.
    #[must_use]
    pub fn storages(&self) -> Vec<&DirEntry> {
        let mut v: Vec<&DirEntry> = self
            .entries
            .values()
            .filter(|e| e.kind.is_container())
            .collect();
        v.sort_by_key(|e| e.index);
        v
    }

    /// Build the full path of an entry (e.g., `/Root Entry/VBA/Module1`).
    #[must_use]
    pub fn path_of(&self, index: u32) -> Option<PathBuf> {
        let entry = self.entries.get(&index)?;
        let mut components = vec![entry.name.clone()];
        let mut current = entry.parent_index;
        while let Some(pi) = current {
            let parent = self.entries.get(&pi)?;
            components.push(parent.name.clone());
            current = parent.parent_index;
        }
        components.reverse();
        let mut path = PathBuf::new();
        for c in components {
            path.push(c);
        }
        Some(path)
    }

    /// Return total bytes across all stream entries.
    #[must_use]
    pub fn total_stream_bytes(&self) -> u64 {
        self.entries
            .values()
            .filter(|e| e.kind == DirEntryKind::Stream)
            .map(|e| e.size)
            .sum()
    }

    /// Print a tree-style listing (similar to `oledump.py`).
    #[must_use]
    pub fn format_tree(&self) -> String {
        let mut out = String::new();
        self.format_tree_recursive(0, 0, &mut out);
        out
    }

    fn format_tree_recursive(&self, index: u32, depth: usize, out: &mut String) {
        if depth > MAX_TREE_DEPTH {
            return;
        }
        let entry = match self.entries.get(&index) {
            Some(e) => e,
            None => return,
        };
        let indent = "  ".repeat(depth);
        let prefix = if entry.kind.is_container() { "[+]" } else { "   " };
        out.push_str(&format!("{indent}{prefix} {}\n", entry.name));
        if entry.kind.is_container() && entry.child != NOENT {
            let mut visited = std::collections::HashSet::new();
            let mut stack = vec![entry.child];
            while let Some(idx) = stack.pop() {
                if idx == NOENT || !visited.insert(idx) {
                    continue;
                }
                self.format_tree_recursive(idx, depth + 1, out);
                if let Some(child_entry) = self.entries.get(&idx) {
                    if child_entry.left_sibling != NOENT {
                        stack.push(child_entry.left_sibling);
                    }
                    if child_entry.right_sibling != NOENT {
                        stack.push(child_entry.right_sibling);
                    }
                }
            }
        }
    }
}

impl Default for OleDirectoryWalker {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_walker() -> OleDirectoryWalker {
        let mut w = OleDirectoryWalker::new();
        w.build_default_layout();
        w
    }

    #[test]
    fn test_build_default_layout() {
        let w = make_walker();
        assert_eq!(w.entries.len(), 6);
    }

    #[test]
    fn test_find_by_name_workbook() {
        let w = make_walker();
        let e = w.find_by_name("Workbook").unwrap();
        assert_eq!(e.kind, DirEntryKind::Stream);
    }

    #[test]
    fn test_find_by_name_vba() {
        let w = make_walker();
        let e = w.find_by_name("VBA").unwrap();
        assert_eq!(e.kind, DirEntryKind::Storage);
    }

    #[test]
    fn test_find_missing() {
        let w = make_walker();
        assert!(w.find_by_name("DoesNotExist").is_none());
    }

    #[test]
    fn test_streams_count() {
        let w = make_walker();
        // Workbook, _VBA_PROJECT, dir, Module1
        assert_eq!(w.streams().len(), 4);
    }

    #[test]
    fn test_storages_count() {
        let w = make_walker();
        // Root + VBA
        assert_eq!(w.storages().len(), 2);
    }

    #[test]
    fn test_walk_directory_visits_all() {
        let w = make_walker();
        let visited = w.walk_directory();
        // Should visit all 6 entries
        assert_eq!(visited.len(), 6);
    }

    #[test]
    fn test_walk_directory_root_first() {
        let w = make_walker();
        let visited = w.walk_directory();
        assert_eq!(visited[0].index, 0); // Root Entry
    }

    #[test]
    fn test_total_stream_bytes() {
        let w = make_walker();
        // 4096 + 512 + 256 + 1024 = 5888
        assert_eq!(w.total_stream_bytes(), 5888);
    }

    #[test]
    fn test_path_of_root() {
        let w = make_walker();
        let p = w.path_of(0).unwrap();
        assert_eq!(p.to_string_lossy(), "Root Entry");
    }

    #[test]
    fn test_path_of_stream() {
        let w = make_walker();
        let p = w.path_of(1).unwrap();
        // Parent is Root Entry
        assert!(p.to_string_lossy().contains("Workbook"));
    }

    #[test]
    fn test_format_tree_contains_names() {
        let w = make_walker();
        let tree = w.format_tree();
        assert!(tree.contains("Root Entry"));
        assert!(tree.contains("Workbook"));
        assert!(tree.contains("VBA"));
    }

    #[test]
    fn test_dir_entry_root() {
        let r = DirEntry::root();
        assert_eq!(r.kind, DirEntryKind::RootStorage);
        assert_eq!(r.index, 0);
    }

    #[test]
    fn test_dir_entry_storage() {
        let s = DirEntry::storage(2, "VBA", 0);
        assert_eq!(s.kind, DirEntryKind::Storage);
        assert_eq!(s.parent_index, Some(0));
    }

    #[test]
    fn test_dir_entry_stream() {
        let s = DirEntry::stream(1, "Workbook", 0, 4096, 0x00);
        assert_eq!(s.kind, DirEntryKind::Stream);
        assert_eq!(s.size, 4096);
    }

    #[test]
    fn test_dir_entry_display() {
        let s = DirEntry::stream(1, "Workbook", 0, 4096, 0x00);
        let d = s.to_string();
        assert!(d.contains("Workbook"));
        assert!(d.contains("Stream"));
    }

    #[test]
    fn test_dir_entry_kind_is_container() {
        assert!(DirEntryKind::RootStorage.is_container());
        assert!(DirEntryKind::Storage.is_container());
        assert!(!DirEntryKind::Stream.is_container());
        assert!(!DirEntryKind::Empty.is_container());
    }

    #[test]
    fn test_dir_entry_kind_is_stream() {
        assert!(DirEntryKind::Stream.is_stream());
        assert!(!DirEntryKind::Storage.is_stream());
    }

    #[test]
    fn test_dir_entry_kind_display() {
        assert_eq!(DirEntryKind::RootStorage.to_string(), "Root");
        assert_eq!(DirEntryKind::Stream.to_string(), "Stream");
    }

    #[test]
    fn test_has_child() {
        let r = DirEntry::root();
        assert!(r.has_child()); // child = 1
    }

    #[test]
    fn test_empty_walker() {
        let w = OleDirectoryWalker::new();
        assert!(w.entries.is_empty());
        assert_eq!(w.total_stream_bytes(), 0);
        assert!(w.streams().is_empty());
    }
}
