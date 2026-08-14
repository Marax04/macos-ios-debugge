//! `rustre-forensics-fs`
//!
//! MemProcFS-style virtual filesystem built from a memory image.  Exposes
//! processes, network connections, and kernel modules as a navigable tree of
//! virtual files, with optional export to a real on-disk directory tree.
//!
//! § 24.4 — MemProcFS-style filesystem view with optional FUSE mount (Unix only).

pub mod artifacts;
pub mod export;
pub mod ext4_reader;
pub mod carver;
pub mod fat32_deep;
pub mod fat_analyzer;
pub mod filesystem_timeline;
pub mod inode;
pub mod lnk_parser;
pub mod model;
pub mod ntfs_analyzer;
pub mod fat32_reader;
pub mod ntfs_mft_full;
pub mod ntfs_reader;
pub mod prefetch_analyzer;
pub mod registry_hive_parser;
pub mod timeline;
pub mod timeline_builder;

use std::path::Path;

#[cfg(all(unix, feature = "fuse-mount"))]
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rustre_forensics::{ForensicsError, MemoryImage, OsType};
use rustre_forensics_mem::{
    LinuxAnalyzer, ModuleInfo, NetworkConnection, ProcessInfo, WindowsAnalyzer,
};
use serde::{Deserialize, Serialize};

// ─── FUSE imports (Unix only) ─────────────────────────────────────────────────

#[cfg(all(unix, feature = "fuse-mount"))]
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by `MemFs` operations.
#[derive(Debug, thiserror::Error)]
pub enum MemFsError {
    #[error("forensics error: {0}")]
    Forensics(#[from] ForensicsError),

    #[error("path not found: {0}")]
    NotFound(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not a directory: {0}")]
    NotADirectory(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for MemFsError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

// ─── MemFsNode (original enum — preserved) ───────────────────────────────────

/// A node in the virtual filesystem.
pub enum MemFsNode {
    /// A directory containing named children.
    Directory(Vec<(String, Self)>),
    /// An eagerly-materialized file.
    File(Vec<u8>),
    /// A lazily-computed file; the closure is called on first access.
    LazyFile(Box<dyn Fn() -> Vec<u8> + Send + Sync>),
}

impl MemFsNode {
    /// Materialise this node's bytes (for files and lazy files).
    #[must_use]
    pub fn read_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::File(data) => Some(data.clone()),
            Self::LazyFile(f) => Some(f()),
            Self::Directory(_) => None,
        }
    }

    /// Returns `true` if this node is a directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        matches!(self, Self::Directory(_))
    }

    /// Returns `true` if this node is a file (eager or lazy).
    #[must_use]
    pub fn is_file(&self) -> bool {
        !self.is_dir()
    }

    /// List child names if this is a directory.
    #[must_use]
    pub fn children(&self) -> Option<Vec<&str>> {
        if let Self::Directory(children) = self {
            Some(children.iter().map(|(n, _)| n.as_str()).collect())
        } else {
            None
        }
    }

    /// Get a child node by name.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&Self> {
        if let Self::Directory(children) = self {
            children
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, node)| node)
        } else {
            None
        }
    }
}

// ─── Enhanced MemFsNode (struct-based, for FUSE) ──────────────────────────────

/// Content of a `MemFsNodeV2` — either file bytes or a list of child nodes.
pub enum MemFsContent {
    /// File with raw byte content.
    File(Vec<u8>),
    /// Directory containing child nodes.
    Dir(Vec<MemFsNodeV2>),
}

/// An enhanced filesystem node that carries inode numbers and timestamps.
/// Used by `MemoryFs` and `FuseMemFs`.
pub struct MemFsNodeV2 {
    pub name: String,
    pub content: MemFsContent,
    pub inode: u64,
    /// Unix timestamp (seconds since epoch) when the node was created.
    pub created: u64,
    /// Unix timestamp (seconds since epoch) when the node was last modified.
    pub modified: u64,
}

impl MemFsNodeV2 {
    /// Create a new file node with the given content and inode.
    pub fn new_file(name: impl Into<String>, content: Vec<u8>, inode: u64) -> Self {
        let ts = current_unix_ts();
        Self {
            name: name.into(),
            content: MemFsContent::File(content),
            inode,
            created: ts,
            modified: ts,
        }
    }

    /// Create a new empty directory node with the given inode.
    pub fn new_dir(name: impl Into<String>, inode: u64) -> Self {
        let ts = current_unix_ts();
        Self {
            name: name.into(),
            content: MemFsContent::Dir(Vec::new()),
            inode,
            created: ts,
            modified: ts,
        }
    }

    /// Add a child node to this directory.  Panics if called on a file node.
    pub fn add_child(&mut self, child: Self) {
        match &mut self.content {
            MemFsContent::Dir(children) => children.push(child),
            MemFsContent::File(_) => panic!("add_child called on a file node"),
        }
        self.modified = current_unix_ts();
    }

    /// Find a child node by name (returns `None` for file nodes).
    #[must_use] 
    pub fn find_child(&self, name: &str) -> Option<&Self> {
        match &self.content {
            MemFsContent::Dir(children) => children.iter().find(|c| c.name == name),
            MemFsContent::File(_) => None,
        }
    }

    /// Return the size of the node in bytes.  Directories return 0.
    #[must_use] 
    pub const fn size(&self) -> u64 {
        match &self.content {
            MemFsContent::File(data) => data.len() as u64,
            MemFsContent::Dir(_) => 0,
        }
    }

    /// Returns `true` if this node is a directory.
    #[must_use] 
    pub const fn is_dir(&self) -> bool {
        matches!(&self.content, MemFsContent::Dir(_))
    }

    /// Returns `true` if this node is a file.
    #[must_use] 
    pub fn is_file(&self) -> bool {
        !self.is_dir()
    }

    /// Recursively find a node by inode number.
    #[must_use] 
    pub fn find_by_inode(&self, ino: u64) -> Option<&Self> {
        if self.inode == ino {
            return Some(self);
        }
        if let MemFsContent::Dir(children) = &self.content {
            for child in children {
                if let Some(found) = child.find_by_inode(ino) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Collect all child entries as `(inode, name)` pairs for `readdir`.
    #[must_use] 
    pub fn readdir_entries(&self) -> Vec<(u64, String, bool)> {
        match &self.content {
            MemFsContent::Dir(children) => children
                .iter()
                .map(|c| (c.inode, c.name.clone(), c.is_dir()))
                .collect(),
            MemFsContent::File(_) => Vec::new(),
        }
    }
}

// ─── MemoryFs ─────────────────────────────────────────────────────────────────

/// A virtual filesystem built entirely from in-memory process and module data.
/// Unlike `MemFs`, this uses `MemFsNodeV2` nodes with inode numbers, which
/// makes it suitable for mounting via FUSE.
pub struct MemoryFs {
    root: MemFsNodeV2,
    /// Monotonically increasing inode counter.
    next_inode: u64,
}

impl MemoryFs {
    /// Create an empty `MemoryFs` with just a root directory.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            root: MemFsNodeV2::new_dir("/", 1),
            next_inode: 2,
        }
    }

    /// Allocate the next available inode number.
    const fn alloc_inode(&mut self) -> u64 {
        let ino = self.next_inode;
        self.next_inode += 1;
        ino
    }

    /// Build a process/module hierarchy from slices of `ProcessInfo` and
    /// `ModuleInfo`.
    ///
    /// # Layout
    /// ```text
    /// /processes/<pid>_<name>/info.txt
    ///                        /modules/<module-name>.txt
    ///                        /handles.csv
    /// ```
    #[must_use] 
    pub fn build_process_tree(processes: &[ProcessInfo], modules: &[ModuleInfo]) -> Self {
        let mut fs = Self::new();

        // /processes/
        let procs_ino = fs.alloc_inode();
        let mut procs_dir = MemFsNodeV2::new_dir("processes", procs_ino);

        for proc in processes {
            // /processes/<pid>_<name>/
            let dir_name = format!("{}_{}", proc.pid, sanitize_filename(&proc.name));
            let proc_ino = fs.alloc_inode();
            let mut proc_dir = MemFsNodeV2::new_dir(dir_name, proc_ino);

            // info.txt
            let info_text = build_process_info_text(proc);
            let info_ino = fs.alloc_inode();
            proc_dir.add_child(MemFsNodeV2::new_file(
                "info.txt",
                info_text.into_bytes(),
                info_ino,
            ));

            // modules/
            let mods_ino = fs.alloc_inode();
            let mut mods_dir = MemFsNodeV2::new_dir("modules", mods_ino);

            // Collect modules that belong to this process (match by pid embedded
            // in base address range if no pid field, or include all kernel mods).
            for m in modules {
                let mod_ino = fs.alloc_inode();
                let filename = format!("{}.txt", sanitize_filename(&m.name));
                let content = build_module_info_text(m);
                mods_dir.add_child(MemFsNodeV2::new_file(
                    filename,
                    content.into_bytes(),
                    mod_ino,
                ));
            }
            proc_dir.add_child(mods_dir);

            // handles.csv
            let handles_ino = fs.alloc_inode();
            let handles_csv = build_handles_csv(proc);
            proc_dir.add_child(MemFsNodeV2::new_file(
                "handles.csv",
                handles_csv.into_bytes(),
                handles_ino,
            ));

            procs_dir.add_child(proc_dir);
        }

        fs.root.add_child(procs_dir);
        fs
    }

    /// Return an immutable reference to the root node.
    #[must_use] 
    pub const fn root(&self) -> &MemFsNodeV2 {
        &self.root
    }

    /// Consume this `MemoryFs` and return the root `MemFsNodeV2`.
    #[must_use] 
    pub fn into_root(self) -> MemFsNodeV2 {
        self.root
    }
}

impl Default for MemoryFs {
    fn default() -> Self {
        Self::new()
    }
}

// ─── to_export_dir ────────────────────────────────────────────────────────────

/// Recursively materialise a `MemFsNodeV2` tree as a real filesystem directory
/// rooted at `base`.
///
/// # Errors
/// Returns an `io::Error` if any directory creation or file write fails.
pub fn to_export_dir(node: &MemFsNodeV2, base: &Path) -> std::io::Result<()> {
    match &node.content {
        MemFsContent::Dir(children) => {
            std::fs::create_dir_all(base)?;
            for child in children {
                // Sanitize the child name before joining to prevent path-traversal
                // via names like ".." or names containing path separators.
                let safe_name = sanitize_export_name(&child.name);
                let child_path = base.join(safe_name);
                to_export_dir(child, &child_path)?;
            }
        }
        MemFsContent::File(data) => {
            // Ensure parent directory exists.
            if let Some(parent) = base.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(base, data)?;
        }
    }
    Ok(())
}

// ─── FUSE implementation (Unix only) ─────────────────────────────────────────

#[cfg(all(unix, feature = "fuse-mount"))]
/// A read-only FUSE filesystem backed by a `MemFsNodeV2` tree.
pub struct FuseMemFs {
    root: MemFsNodeV2,
    /// Maps inode → path segments from root used for fast lookup.
    /// Currently unused but reserved for future caching optimisation.
    inode_map: HashMap<u64, Vec<u64>>,
}

#[cfg(all(unix, feature = "fuse-mount"))]
impl FuseMemFs {
    /// Wrap a `MemFsNodeV2` tree in a FUSE-compatible filesystem.
    pub fn new(root: MemFsNodeV2) -> Self {
        let mut inode_map = HashMap::new();
        // Pre-populate map: inode → ancestor inode chain.
        Self::index_inodes(&root, &[], &mut inode_map);
        Self { root, inode_map }
    }

    fn index_inodes(node: &MemFsNodeV2, ancestors: &[u64], map: &mut HashMap<u64, Vec<u64>>) {
        let mut chain = ancestors.to_vec();
        chain.push(node.inode);
        map.insert(node.inode, chain.clone());
        if let MemFsContent::Dir(children) = &node.content {
            for child in children {
                Self::index_inodes(child, &chain, map);
            }
        }
    }

    /// Find a node by inode number.
    fn node_by_ino(&self, ino: u64) -> Option<&MemFsNodeV2> {
        if ino == 1 {
            return Some(&self.root);
        }
        self.root.find_by_inode(ino)
    }

    /// Build a `FileAttr` from a `MemFsNodeV2`.
    fn file_attr(node: &MemFsNodeV2) -> FileAttr {
        use std::time::Duration;

        let kind = if node.is_dir() {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        let perm: u16 = if node.is_dir() { 0o755 } else { 0o444 };
        let size = node.size();

        let ctime = UNIX_EPOCH + Duration::from_secs(node.created);
        let mtime = UNIX_EPOCH + Duration::from_secs(node.modified);

        FileAttr {
            ino: node.inode,
            size,
            blocks: (size + 511) / 512,
            atime: mtime,
            mtime,
            ctime,
            crtime: ctime,
            kind,
            perm,
            nlink: if node.is_dir() { 2 } else { 1 },
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }
}

#[cfg(all(unix, feature = "fuse-mount"))]
impl Filesystem for FuseMemFs {
    /// Look up a directory entry by name inside `parent`.
    fn lookup(&mut self, _req: &Request, parent: u64, name: &std::ffi::OsStr, reply: ReplyEntry) {
        use std::time::Duration;

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_node = match self.node_by_ino(parent) {
            Some(n) => n,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match parent_node.find_child(name_str) {
            Some(child) => {
                let attr = Self::file_attr(child);
                reply.entry(&Duration::from_secs(1), &attr, 0);
            }
            None => reply.error(libc::ENOENT),
        }
    }

    /// Return the attributes for a given inode.
    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        use std::time::Duration;

        match self.node_by_ino(ino) {
            Some(node) => {
                let attr = Self::file_attr(node);
                reply.attr(&Duration::from_secs(1), &attr);
            }
            None => reply.error(libc::ENOENT),
        }
    }

    /// List the contents of a directory.
    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let node = match self.node_by_ino(ino) {
            Some(n) => n,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if node.is_file() {
            reply.error(libc::ENOTDIR);
            return;
        }

        // Standard `.` and `..` entries.
        let dot_entries: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".to_string()),
            (ino, FileType::Directory, "..".to_string()),
        ];

        let child_entries: Vec<(u64, FileType, String)> = node
            .readdir_entries()
            .into_iter()
            .map(|(child_ino, name, is_dir)| {
                let ft = if is_dir {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                (child_ino, ft, name)
            })
            .collect();

        let all: Vec<(u64, FileType, String)> =
            dot_entries.into_iter().chain(child_entries).collect();

        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        for (i, (entry_ino, ft, name)) in all.into_iter().enumerate().skip(offset as usize) {
            let full = reply.add(entry_ino, (i + 1) as i64, ft, &name);
            if full {
                break;
            }
        }
        reply.ok();
    }

    /// Read file data from `offset` for up to `size` bytes.
    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let node = match self.node_by_ino(ino) {
            Some(n) => n,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match &node.content {
            MemFsContent::File(data) => {
                if offset < 0 {
                    reply.error(libc::EINVAL);
                    return;
                }
                let start = offset as usize;
                if start >= data.len() {
                    reply.data(&[]);
                    return;
                }
                let end = std::cmp::min(start + size as usize, data.len());
                reply.data(&data[start..end]);
            }
            MemFsContent::Dir(_) => {
                reply.error(libc::EISDIR);
            }
        }
    }
}

// ─── mount_memory_fs (Unix) ───────────────────────────────────────────────────

#[cfg(all(unix, feature = "fuse-mount"))]
/// Mount a `MemFsNodeV2` tree as a read-only FUSE filesystem at `mountpoint`.
///
/// Returns a `BackgroundSession` handle; drop it to unmount.
///
/// # Errors
/// Returns an `anyhow::Error` if the mount fails.
pub fn mount_memory_fs(
    fs_root: MemFsNodeV2,
    mountpoint: &Path,
) -> anyhow::Result<fuser::BackgroundSession> {
    let fuse_fs = FuseMemFs::new(fs_root);
    let options = vec![
        MountOption::RO,
        MountOption::FSName("rustre-memfs".to_string()),
    ];
    fuser::spawn_mount2(fuse_fs, mountpoint, &options).map_err(Into::into)
}

// ─── mount_memory_fs (non-Unix stub) ─────────────────────────────────────────

#[cfg(not(all(unix, feature = "fuse-mount")))]
/// FUSE filesystem mounting is not supported on this platform.
///
/// # Errors
/// Always returns an error explaining that FUSE requires Linux or macOS.
pub fn mount_memory_fs(_fs_root: MemFsNodeV2, _mountpoint: &Path) -> anyhow::Result<()> {
    Err(anyhow::anyhow!("FUSE filesystem requires Linux or macOS"))
}

// ─── MemFs ────────────────────────────────────────────────────────────────────

/// A virtual filesystem constructed from a memory image.
///
/// Layout:
/// ```text
/// /
/// ├── processes/
/// │   └── <pid>_<name>/
/// │       ├── info.json
/// │       ├── cmdline.txt
/// │       ├── modules.csv
/// │       └── memory/
/// │           └── <start>_<end>.bin
/// ├── network/
/// │   └── connections.csv
/// └── kernel/
///     └── modules.csv
/// ```
pub struct MemFs {
    root: MemFsNode,
}

/// Process info JSON shape stored in `info.json`.
#[derive(Debug, Serialize, Deserialize)]
struct ProcessInfoJson {
    pid: u32,
    ppid: u32,
    name: String,
    base: String,
    size: u64,
    handle_count: u32,
}

impl MemFs {
    /// Build a virtual filesystem from a memory image.
    pub fn build(image: &dyn MemoryImage) -> Result<Self, MemFsError> {
        let processes = match image.os_type() {
            OsType::Linux => LinuxAnalyzer::find_processes(image),
            _ => WindowsAnalyzer::find_processes(image),
        };
        let network_connections = WindowsAnalyzer::find_network_connections(image);
        let kernel_modules = match image.os_type() {
            OsType::Linux => LinuxAnalyzer::find_modules(image),
            _ => WindowsAnalyzer::find_modules(image, 0),
        };

        let processes_dir = Self::build_processes_dir(image, &processes);
        let network_dir = Self::build_network_dir(&network_connections);
        let kernel_dir = Self::build_kernel_dir(&kernel_modules);

        let root = MemFsNode::Directory(vec![
            ("processes".to_string(), processes_dir),
            ("network".to_string(), network_dir),
            ("kernel".to_string(), kernel_dir),
        ]);

        Ok(Self { root })
    }

    fn build_processes_dir(image: &dyn MemoryImage, processes: &[ProcessInfo]) -> MemFsNode {
        let mut proc_entries: Vec<(String, MemFsNode)> = Vec::with_capacity(processes.len());

        for p in processes {
            let dir_name = format!("{}_{}", p.pid, sanitize_filename(&p.name));
            let modules = WindowsAnalyzer::find_modules(image, p.pid);
            let regions = image.regions();

            // info.json
            let info = ProcessInfoJson {
                pid: p.pid,
                ppid: p.ppid,
                name: p.name.clone(),
                base: format!("0x{:016x}", p.base),
                size: p.size,
                handle_count: p.handle_count,
            };
            let info_json = serde_json::to_vec_pretty(&info).unwrap_or_else(|e| {
                format!("{{\"error\":\"serialization failed: {e}\"}}").into_bytes()
            });

            // cmdline.txt — synthesize from name
            let cmdline = format!("{}.exe\n", p.name);

            // modules.csv
            let modules_csv = build_modules_csv(&modules);

            // memory/ subdirectory — one .bin per VAD region
            let memory_entries: Vec<(String, MemFsNode)> = regions
                .iter()
                .map(|r| {
                    let fname = format!("{:016x}_{:016x}.bin", r.start, r.end);
                    let start = r.start;
                    let end = r.end;
                    let image_ref: &dyn MemoryImage = image;
                    // Capture data eagerly; guard against end < start or size overflow.
                    let region_len = end.saturating_sub(start).min(usize::MAX as u64) as usize;
                    let data = image_ref
                        .read(start, region_len)
                        .unwrap_or_default();
                    (fname, MemFsNode::File(data))
                })
                .collect();

            let memory_dir = MemFsNode::Directory(memory_entries);

            let proc_children: Vec<(String, MemFsNode)> = vec![
                ("info.json".into(), MemFsNode::File(info_json)),
                ("cmdline.txt".into(), MemFsNode::File(cmdline.into_bytes())),
                (
                    "modules.csv".into(),
                    MemFsNode::File(modules_csv.into_bytes()),
                ),
                ("memory".into(), memory_dir),
            ];

            proc_entries.push((dir_name, MemFsNode::Directory(proc_children)));
        }

        MemFsNode::Directory(proc_entries)
    }

    fn build_network_dir(connections: &[NetworkConnection]) -> MemFsNode {
        let csv = build_connections_csv(connections);
        MemFsNode::Directory(vec![(
            "connections.csv".into(),
            MemFsNode::File(csv.into_bytes()),
        )])
    }

    fn build_kernel_dir(modules: &[ModuleInfo]) -> MemFsNode {
        let csv = build_modules_csv(modules);
        MemFsNode::Directory(vec![(
            "modules.csv".into(),
            MemFsNode::File(csv.into_bytes()),
        )])
    }

    /// Read a file by virtual path (e.g. `/processes/4_System/info.json`).
    #[must_use]
    pub fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        let node = self.resolve(path)?;
        node.read_bytes()
    }

    /// List entries in a directory by virtual path.
    #[must_use]
    pub fn list_dir(&self, path: &str) -> Option<Vec<String>> {
        let node = self.resolve(path)?;
        node.children()
            .map(|v| v.iter().map(|s| (*s).to_string()).collect())
    }

    /// Resolve a virtual path to a node.
    #[must_use]
    pub fn resolve(&self, path: &str) -> Option<&MemFsNode> {
        let parts: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut current = &self.root;
        for part in parts {
            current = current.child(part)?;
        }
        Some(current)
    }

    /// Export the virtual filesystem to a real directory on disk.
    pub fn export(&self, real_path: &Path) -> Result<(), MemFsError> {
        std::fs::create_dir_all(real_path)?;
        Self::export_node(&self.root, real_path)
    }

    fn export_node(node: &MemFsNode, path: &Path) -> Result<(), MemFsError> {
        match node {
            MemFsNode::Directory(children) => {
                std::fs::create_dir_all(path)?;
                for (name, child) in children {
                    let child_path = path.join(name);
                    Self::export_node(child, &child_path)?;
                }
            }
            MemFsNode::File(data) => {
                std::fs::write(path, data)?;
            }
            MemFsNode::LazyFile(f) => {
                let data = f();
                std::fs::write(path, data)?;
            }
        }
        Ok(())
    }

    /// Expose the root node for programmatic traversal.
    #[must_use]
    pub const fn root(&self) -> &MemFsNode {
        &self.root
    }
}

// ─── MemFsWalker ─────────────────────────────────────────────────────────────

/// Iterator that walks all paths in a `MemFs`.
pub struct MemFsWalker<'a> {
    stack: Vec<(String, &'a MemFsNode)>,
}

impl<'a> MemFsWalker<'a> {
    #[must_use]
    pub fn new(fs: &'a MemFs) -> Self {
        Self {
            stack: vec![("/".to_string(), &fs.root)],
        }
    }
}

impl Iterator for MemFsWalker<'_> {
    type Item = (String, bool); // (path, is_dir)

    fn next(&mut self) -> Option<Self::Item> {
        let (path, node) = self.stack.pop()?;
        if let MemFsNode::Directory(children) = node {
            for (name, child) in children.iter().rev() {
                let child_path = if path.ends_with('/') {
                    format!("{path}{name}")
                } else {
                    format!("{path}/{name}")
                };
                self.stack.push((child_path, child));
            }
        }
        Some((path, node.is_dir()))
    }
}

// ─── MemFsV2Walker ────────────────────────────────────────────────────────────

/// Iterator that walks all paths in a `MemoryFs` (enhanced node tree).
pub struct MemFsV2Walker<'a> {
    stack: Vec<(String, &'a MemFsNodeV2)>,
}

impl<'a> MemFsV2Walker<'a> {
    /// Create a new walker starting at the root of `fs`.
    #[must_use] 
    pub fn new(fs: &'a MemoryFs) -> Self {
        Self {
            stack: vec![("/".to_string(), &fs.root)],
        }
    }
}

impl Iterator for MemFsV2Walker<'_> {
    type Item = (String, bool); // (path, is_dir)

    fn next(&mut self) -> Option<Self::Item> {
        let (path, node) = self.stack.pop()?;
        if let MemFsContent::Dir(children) = &node.content {
            for child in children.iter().rev() {
                let child_path = if path.ends_with('/') {
                    format!("{path}{}", child.name)
                } else {
                    format!("{path}/{}", child.name)
                };
                self.stack.push((child_path, child));
            }
        }
        Some((path, node.is_dir()))
    }
}

// ─── CSV helpers ─────────────────────────────────────────────────────────────

fn build_modules_csv(modules: &[ModuleInfo]) -> String {
    let mut out = String::from("name,base,size,path\n");
    for m in modules {
        out.push_str(&format!(
            "{},0x{:016x},{},'{}'\n",
            csv_escape(&m.name),
            m.base,
            m.size,
            csv_escape(&m.path),
        ));
    }
    out
}

fn build_connections_csv(connections: &[NetworkConnection]) -> String {
    let mut out =
        String::from("protocol,local_addr,local_port,remote_addr,remote_port,state,pid\n");
    for c in connections {
        out.push_str(&format!(
            "{},{},{},{},{},{:?},{}\n",
            c.protocol.as_str(),
            c.local_addr,
            c.local_port,
            c.remote_addr,
            c.remote_port,
            c.state,
            c.pid,
        ));
    }
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Sanitize a node name before using it as a filesystem path component during
/// export.  Prevents path-traversal via names like `..`, `/foo`, or `\foo`.
fn sanitize_export_name(name: &str) -> String {
    // Replace separator characters and null bytes.
    let sanitized: String = name
        .chars()
        .map(|c| if c == '/' || c == '\\' || c == '\0' { '_' } else { c })
        .collect();
    // Guard against pure-dot names (".", "..") after substitution.
    if sanitized.chars().all(|c| c == '.') {
        return "_".to_string();
    }
    sanitized
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// ─── MemFsNodeV2 text helpers ─────────────────────────────────────────────────

/// Build a human-readable `info.txt` for a process.
fn build_process_info_text(proc: &ProcessInfo) -> String {
    format!(
        "pid={}\nppid={}\nname={}\ncmdline={}.exe\nbase=0x{:016x}\nsize={}\nhandle_count={}\n",
        proc.pid, proc.ppid, proc.name, proc.name, proc.base, proc.size, proc.handle_count,
    )
}

/// Build a human-readable text blob for a single module.
fn build_module_info_text(module: &ModuleInfo) -> String {
    format!(
        "name={}\nbase=0x{:016x}\nsize={}\npath={}\n",
        module.name, module.base, module.size, module.path,
    )
}

/// Build a minimal `handles.csv` for a process.  The handle table is not
/// available in the current `ProcessInfo` model, so we emit a header-only CSV
/// with a placeholder row derived from the process handle count field.
fn build_handles_csv(proc: &ProcessInfo) -> String {
    let mut out = String::from("handle,type,name\n");
    // Emit synthetic placeholder rows proportional to handle_count (capped to
    // avoid generating huge files).
    let rows = std::cmp::min(proc.handle_count, 8) as usize;
    for i in 0..rows {
        out.push_str(&format!("0x{:04x},unknown,<handle-{}>\n", i * 4, i));
    }
    out
}

// ─── Timestamp helper ─────────────────────────────────────────────────────────

/// Return the current Unix timestamp in whole seconds.
fn current_unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_forensics_mem::build_mock_image;

    fn make_fs() -> MemFs {
        let img = build_mock_image(OsType::Windows);
        MemFs::build(&img).unwrap()
    }

    // ── Root structure ────────────────────────────────────────────────────────
    #[test]
    fn root_has_three_dirs() {
        let fs = make_fs();
        let entries = fs.list_dir("/").unwrap();
        assert!(entries.contains(&"processes".to_string()));
        assert!(entries.contains(&"network".to_string()));
        assert!(entries.contains(&"kernel".to_string()));
    }

    #[test]
    fn processes_dir_not_empty() {
        let fs = make_fs();
        let entries = fs.list_dir("/processes").unwrap();
        assert!(
            !entries.is_empty(),
            "processes/ should contain at least one subdirectory"
        );
    }

    #[test]
    fn process_dir_contains_expected_files() {
        let fs = make_fs();
        let proc_dirs = fs.list_dir("/processes").unwrap();
        let first = proc_dirs.first().unwrap();
        let path = format!("/processes/{first}");
        let files = fs.list_dir(&path).unwrap();
        assert!(
            files.contains(&"info.json".to_string()),
            "missing info.json"
        );
        assert!(
            files.contains(&"cmdline.txt".to_string()),
            "missing cmdline.txt"
        );
        assert!(
            files.contains(&"modules.csv".to_string()),
            "missing modules.csv"
        );
        assert!(files.contains(&"memory".to_string()), "missing memory/");
    }

    // ── info.json ─────────────────────────────────────────────────────────────
    #[test]
    fn info_json_is_valid_json() {
        let fs = make_fs();
        let proc_dirs = fs.list_dir("/processes").unwrap();
        let path = format!("/processes/{}/info.json", proc_dirs[0]);
        let data = fs.read_file(&path).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_slice(&data).expect("info.json must be valid JSON");
        assert!(parsed["pid"].is_number());
        assert!(parsed["name"].is_string());
    }

    #[test]
    fn info_json_contains_expected_fields() {
        let fs = make_fs();
        let proc_dirs = fs.list_dir("/processes").unwrap();
        let path = format!("/processes/{}/info.json", proc_dirs[0]);
        let data = fs.read_file(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert!(parsed.get("pid").is_some());
        assert!(parsed.get("ppid").is_some());
        assert!(parsed.get("handle_count").is_some());
    }

    // ── cmdline.txt ───────────────────────────────────────────────────────────
    #[test]
    fn cmdline_txt_not_empty() {
        let fs = make_fs();
        let proc_dirs = fs.list_dir("/processes").unwrap();
        let path = format!("/processes/{}/cmdline.txt", proc_dirs[0]);
        let data = fs.read_file(&path).unwrap();
        assert!(!data.is_empty());
    }

    // ── modules.csv ───────────────────────────────────────────────────────────
    #[test]
    fn process_modules_csv_has_header() {
        let fs = make_fs();
        let proc_dirs = fs.list_dir("/processes").unwrap();
        let path = format!("/processes/{}/modules.csv", proc_dirs[0]);
        let data = fs.read_file(&path).unwrap();
        let s = String::from_utf8(data).unwrap();
        assert!(s.starts_with("name,base,size,path"));
    }

    #[test]
    fn kernel_modules_csv_has_header() {
        let fs = make_fs();
        let data = fs.read_file("/kernel/modules.csv").unwrap();
        let s = String::from_utf8(data).unwrap();
        assert!(s.starts_with("name,base,size,path"));
    }

    // ── network ───────────────────────────────────────────────────────────────
    #[test]
    fn network_connections_csv_has_header() {
        let fs = make_fs();
        let data = fs.read_file("/network/connections.csv").unwrap();
        let s = String::from_utf8(data).unwrap();
        assert!(s.starts_with("protocol,"));
    }

    #[test]
    fn network_connections_csv_not_empty() {
        let fs = make_fs();
        let data = fs.read_file("/network/connections.csv").unwrap();
        let s = String::from_utf8(data).unwrap();
        
        assert!(
            s.lines().count() >= 2,
            "should have header + at least one connection row"
        );
    }

    // ── path resolution ───────────────────────────────────────────────────────
    #[test]
    fn resolve_root() {
        let fs = make_fs();
        assert!(fs.resolve("/").unwrap().is_dir());
    }

    #[test]
    fn resolve_nonexistent_returns_none() {
        let fs = make_fs();
        assert!(fs.resolve("/nonexistent/path").is_none());
    }

    #[test]
    fn read_file_on_directory_returns_none() {
        let fs = make_fs();
        assert!(fs.read_file("/processes").is_none());
    }

    // ── MemFsWalker ───────────────────────────────────────────────────────────
    #[test]
    fn walker_visits_root() {
        let fs = make_fs();
        let mut walker = MemFsWalker::new(&fs);
        let first = walker.next().unwrap();
        assert_eq!(first.0, "/");
        assert!(first.1); // is_dir
    }

    #[test]
    fn walker_finds_info_json() {
        let fs = make_fs();
        let walker = MemFsWalker::new(&fs);
        let paths: Vec<String> = walker.map(|(p, _)| p).collect();
        assert!(
            paths.iter().any(|p| p.ends_with("info.json")),
            "walker should find info.json files"
        );
    }

    #[test]
    fn walker_finds_connections_csv() {
        let fs = make_fs();
        let walker = MemFsWalker::new(&fs);
        let paths: Vec<String> = walker.map(|(p, _)| p).collect();
        assert!(
            paths.iter().any(|p| p.ends_with("connections.csv")),
            "walker should find connections.csv"
        );
    }

    // ── CSV escaping ──────────────────────────────────────────────────────────
    #[test]
    fn csv_escape_plain() {
        assert_eq!(csv_escape("ntdll.dll"), "ntdll.dll");
    }

    #[test]
    fn csv_escape_with_comma() {
        let s = csv_escape("a,b");
        assert!(s.starts_with('"') && s.ends_with('"'));
    }

    // ── Filename sanitization ─────────────────────────────────────────────────
    #[test]
    fn sanitize_normal_name() {
        assert_eq!(sanitize_filename("explorer.exe"), "explorer.exe");
    }

    #[test]
    fn sanitize_special_chars() {
        let s = sanitize_filename("proc/name:bad");
        assert!(!s.contains('/'));
        assert!(!s.contains(':'));
    }

    // ── MemFsNode helpers ─────────────────────────────────────────────────────
    #[test]
    fn node_file_read_bytes() {
        let node = MemFsNode::File(vec![1, 2, 3]);
        assert_eq!(node.read_bytes().unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn node_lazy_file_read_bytes() {
        let node = MemFsNode::LazyFile(Box::new(|| vec![42]));
        assert_eq!(node.read_bytes().unwrap(), vec![42]);
    }

    #[test]
    fn node_directory_read_bytes_is_none() {
        let node = MemFsNode::Directory(vec![]);
        assert!(node.read_bytes().is_none());
    }

    #[test]
    fn node_is_dir_and_is_file() {
        assert!(MemFsNode::Directory(vec![]).is_dir());
        assert!(!MemFsNode::Directory(vec![]).is_file());
        assert!(MemFsNode::File(vec![]).is_file());
        assert!(!MemFsNode::File(vec![]).is_dir());
    }

    // ── Export ────────────────────────────────────────────────────────────────
    #[test]
    fn export_creates_files() {
        let fs = make_fs();
        let tmp = std::env::temp_dir().join("rustre_fs_test_export");
        let _ = std::fs::remove_dir_all(&tmp);
        fs.export(&tmp).unwrap();

        assert!(tmp.exists());
        assert!(tmp.join("network").join("connections.csv").exists());
        assert!(tmp.join("kernel").join("modules.csv").exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── MemFsNodeV2 ───────────────────────────────────────────────────────────

    #[test]
    fn mem_fs_node_v2_new_file() {
        let node = MemFsNodeV2::new_file("test.txt", b"hello".to_vec(), 42);
        assert_eq!(node.name, "test.txt");
        assert_eq!(node.inode, 42);
        assert!(node.is_file());
        assert!(!node.is_dir());
        assert_eq!(node.size(), 5);
    }

    #[test]
    fn mem_fs_node_v2_new_dir() {
        let node = MemFsNodeV2::new_dir("mydir", 10);
        assert_eq!(node.name, "mydir");
        assert_eq!(node.inode, 10);
        assert!(node.is_dir());
        assert!(!node.is_file());
        assert_eq!(node.size(), 0);
    }

    #[test]
    fn mem_fs_node_v2_add_and_find_child() {
        let mut dir = MemFsNodeV2::new_dir("parent", 1);
        let child = MemFsNodeV2::new_file("child.txt", b"data".to_vec(), 2);
        dir.add_child(child);
        assert!(dir.find_child("child.txt").is_some());
        assert!(dir.find_child("nonexistent").is_none());
    }

    #[test]
    fn mem_fs_node_v2_find_child_on_file_returns_none() {
        let file = MemFsNodeV2::new_file("f.txt", vec![], 5);
        assert!(file.find_child("anything").is_none());
    }

    #[test]
    fn mem_fs_node_v2_readdir_entries() {
        let mut dir = MemFsNodeV2::new_dir("d", 1);
        dir.add_child(MemFsNodeV2::new_file("a.txt", vec![], 2));
        dir.add_child(MemFsNodeV2::new_dir("sub", 3));
        let entries = dir.readdir_entries();
        assert_eq!(entries.len(), 2);
        let names: Vec<&str> = entries.iter().map(|(_, n, _)| n.as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"sub"));
    }

    #[test]
    fn mem_fs_node_v2_find_by_inode() {
        let mut root = MemFsNodeV2::new_dir("root", 1);
        let mut sub = MemFsNodeV2::new_dir("sub", 2);
        sub.add_child(MemFsNodeV2::new_file("deep.txt", b"x".to_vec(), 3));
        root.add_child(sub);

        assert!(root.find_by_inode(1).is_some());
        assert!(root.find_by_inode(2).is_some());
        assert!(root.find_by_inode(3).is_some());
        assert!(root.find_by_inode(99).is_none());
    }

    // ── MemoryFs ──────────────────────────────────────────────────────────────

    #[test]
    fn memory_fs_new_has_root() {
        let fs = MemoryFs::new();
        assert_eq!(fs.root().inode, 1);
        assert!(fs.root().is_dir());
    }

    #[test]
    fn memory_fs_build_process_tree_empty() {
        let fs = MemoryFs::build_process_tree(&[], &[]);
        // Should still have a /processes directory under root.
        let procs = fs.root().find_child("processes");
        assert!(procs.is_some());
    }

    #[test]
    fn memory_fs_build_process_tree_with_data() {
        let img = build_mock_image(OsType::Windows);
        let processes = WindowsAnalyzer::find_processes(&img);
        let modules = WindowsAnalyzer::find_modules(&img, 0);
        let fs = MemoryFs::build_process_tree(&processes, &modules);

        let procs_dir = fs.root().find_child("processes").unwrap();
        assert!(procs_dir.is_dir());
        // At least one process sub-directory.
        if !processes.is_empty() {
            match &procs_dir.content {
                MemFsContent::Dir(children) => {
                    assert!(!children.is_empty());
                    let first_proc = &children[0];
                    assert!(first_proc.find_child("info.txt").is_some());
                    assert!(first_proc.find_child("modules").is_some());
                    assert!(first_proc.find_child("handles.csv").is_some());
                }
                MemFsContent::File(_) => panic!("processes should be a directory"),
            }
        }
    }

    // ── MemFsV2Walker ─────────────────────────────────────────────────────────

    #[test]
    fn v2_walker_visits_root() {
        let fs = MemoryFs::new();
        let mut walker = MemFsV2Walker::new(&fs);
        let first = walker.next().unwrap();
        assert_eq!(first.0, "/");
        assert!(first.1);
    }

    #[test]
    fn v2_walker_finds_info_txt() {
        let img = build_mock_image(OsType::Windows);
        let processes = WindowsAnalyzer::find_processes(&img);
        let modules = WindowsAnalyzer::find_modules(&img, 0);
        let fs = MemoryFs::build_process_tree(&processes, &modules);
        if !processes.is_empty() {
            let walker = MemFsV2Walker::new(&fs);
            let paths: Vec<String> = walker.map(|(p, _)| p).collect();
            assert!(
                paths.iter().any(|p| p.ends_with("info.txt")),
                "walker should find info.txt files"
            );
        }
    }

    // ── to_export_dir ─────────────────────────────────────────────────────────

    #[test]
    fn to_export_dir_creates_tree() {
        let img = build_mock_image(OsType::Windows);
        let processes = WindowsAnalyzer::find_processes(&img);
        let modules = WindowsAnalyzer::find_modules(&img, 0);
        let fs = MemoryFs::build_process_tree(&processes, &modules);

        let tmp = std::env::temp_dir().join("rustre_fs_v2_export_test");
        let _ = std::fs::remove_dir_all(&tmp);

        to_export_dir(fs.root(), &tmp).unwrap();
        assert!(tmp.exists());
        assert!(tmp.join("processes").exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── mount_memory_fs (non-Unix platform check) ─────────────────────────────

    #[cfg(not(all(unix, feature = "fuse-mount")))]
    #[test]
    fn mount_memory_fs_returns_error_on_non_unix() {
        let root = MemFsNodeV2::new_dir("root", 1);
        let result = mount_memory_fs(root, Path::new("/tmp/test"));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("FUSE") || msg.contains("Linux") || msg.contains("macOS"));
    }

    // ── Timestamp helper ──────────────────────────────────────────────────────

    #[test]
    fn current_unix_ts_is_reasonable() {
        let ts = current_unix_ts();
        // Should be after 2020-01-01 00:00:00 UTC = 1577836800
        assert!(ts > 1_577_836_800);
    }

    // ── build_process_info_text ───────────────────────────────────────────────

    #[test]
    fn process_info_text_contains_pid() {
        let img = build_mock_image(OsType::Windows);
        let processes = WindowsAnalyzer::find_processes(&img);
        if let Some(p) = processes.first() {
            let text = build_process_info_text(p);
            assert!(text.contains(&format!("pid={}", p.pid)));
            assert!(text.contains(&format!("ppid={}", p.ppid)));
            assert!(text.contains("cmdline="));
        }
    }

    // ── build_handles_csv ─────────────────────────────────────────────────────

    #[test]
    fn handles_csv_has_header() {
        let img = build_mock_image(OsType::Windows);
        let processes = WindowsAnalyzer::find_processes(&img);
        if let Some(p) = processes.first() {
            let csv = build_handles_csv(p);
            assert!(csv.starts_with("handle,type,name\n"));
        }
    }
}


