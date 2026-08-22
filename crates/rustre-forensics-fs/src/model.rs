//! Self-contained MemProcFS-style virtual filesystem model.
//!
//! This module provides a fully self-contained, std-only model of a virtual
//! filesystem laid over a memory image, in the spirit of `MemProcFS`. It does
//! **not** depend on the heavier `rustre-forensics-mem` analyzers; instead it
//! defines its own lightweight record types ([`ProcessRecord`],
//! [`ModuleRecord`], [`NetConnRecord`], [`HandleRecord`]) that callers populate
//! from whatever source they have.
//!
//! The model is pure in-memory data structures: the OS-mount layer (FUSE /
//! `WinFsp`) is intentionally out of scope. File content is produced lazily
//! through a [`Content`] provider so that large blobs (such as memory range
//! dumps) are not materialised until they are actually read.
//!
//! # Example
//! ```
//! use rustre_forensics_fs::model::{ProcessRecord, VfsBuilder};
//!
//! let procs = vec![ProcessRecord::new(4, 0, "System")];
//! let tree = VfsBuilder::new().with_processes(procs).build();
//!
//! assert!(tree.resolve("/processes").is_some());
//! assert!(tree.resolve("/does/not/exist").is_none());
//! ```

use std::fmt::Write as _;
use std::sync::Arc;

// ─── Records ────────────────────────────────────────────────────────────────

/// A lightweight in-memory description of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    /// Process identifier.
    pub pid: u32,
    /// Parent process identifier.
    pub ppid: u32,
    /// Short image name (e.g. `explorer.exe`).
    pub name: String,
    /// Virtual base address of the main image.
    pub base: u64,
    /// Virtual size of the main image, in bytes.
    pub size: u64,
    /// Number of open handles, if known.
    pub handle_count: u32,
    /// Full command line, if recovered.
    pub cmdline: String,
    /// Modules loaded into this process.
    pub modules: Vec<ModuleRecord>,
    /// Committed memory ranges belonging to this process.
    pub memory_ranges: Vec<MemoryRange>,
    /// Open handles owned by this process.
    pub handles: Vec<HandleRecord>,
}

impl ProcessRecord {
    /// Create a process record with the given pid, ppid and name and empty
    /// collections.
    #[must_use]
    pub fn new(pid: u32, ppid: u32, name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            pid,
            ppid,
            cmdline: name.clone(),
            name,
            base: 0,
            size: 0,
            handle_count: 0,
            modules: Vec::new(),
            memory_ranges: Vec::new(),
            handles: Vec::new(),
        }
    }

    /// Builder: set the image base address and size.
    #[must_use]
    pub const fn with_image(mut self, base: u64, size: u64) -> Self {
        self.base = base;
        self.size = size;
        self
    }

    /// Builder: set the command line.
    #[must_use]
    pub fn with_cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.cmdline = cmdline.into();
        self
    }

    /// Builder: attach a module.
    #[must_use]
    pub fn with_module(mut self, module: ModuleRecord) -> Self {
        self.modules.push(module);
        self
    }

    /// Builder: attach a memory range.
    #[must_use]
    pub fn with_memory_range(mut self, range: MemoryRange) -> Self {
        self.memory_ranges.push(range);
        self
    }

    /// Builder: attach a handle.
    #[must_use]
    pub fn with_handle(mut self, handle: HandleRecord) -> Self {
        self.handle_count = self.handle_count.saturating_add(1);
        self.handles.push(handle);
        self
    }
}

/// A lightweight in-memory description of a loaded module / shared library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRecord {
    /// Short module name (e.g. `ntdll.dll`).
    pub name: String,
    /// Virtual base address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// Full on-disk path, if known.
    pub path: String,
}

impl ModuleRecord {
    /// Create a module record.
    #[must_use]
    pub fn new(name: impl Into<String>, base: u64, size: u64, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            base,
            size,
            path: path.into(),
        }
    }
}

/// Transport protocol for a network connection record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// TCP over IPv6.
    Tcp6,
    /// UDP over IPv6.
    Udp6,
}

impl Proto {
    /// Lowercase wire name used in CSV output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Tcp6 => "tcp6",
            Self::Udp6 => "udp6",
        }
    }
}

/// A lightweight in-memory description of a network connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetConnRecord {
    /// Transport protocol.
    pub proto: Proto,
    /// Local address (textual).
    pub local_addr: String,
    /// Local port.
    pub local_port: u16,
    /// Remote address (textual).
    pub remote_addr: String,
    /// Remote port.
    pub remote_port: u16,
    /// Connection state (e.g. `ESTABLISHED`, `LISTEN`).
    pub state: String,
    /// Owning process id.
    pub pid: u32,
}

impl NetConnRecord {
    /// Create a network-connection record.
    #[must_use]
    pub fn new(
        proto: Proto,
        local_addr: impl Into<String>,
        local_port: u16,
        remote_addr: impl Into<String>,
        remote_port: u16,
        state: impl Into<String>,
        pid: u32,
    ) -> Self {
        Self {
            proto,
            local_addr: local_addr.into(),
            local_port,
            remote_addr: remote_addr.into(),
            remote_port,
            state: state.into(),
            pid,
        }
    }
}

/// A lightweight in-memory description of an open kernel handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleRecord {
    /// Handle value (object table index).
    pub handle: u64,
    /// Object type (e.g. `File`, `Key`, `Process`).
    pub object_type: String,
    /// Object name / target, if known.
    pub name: String,
    /// Granted access mask.
    pub access: u32,
}

impl HandleRecord {
    /// Create a handle record.
    #[must_use]
    pub fn new(
        handle: u64,
        object_type: impl Into<String>,
        name: impl Into<String>,
        access: u32,
    ) -> Self {
        Self {
            handle,
            object_type: object_type.into(),
            name: name.into(),
            access,
        }
    }
}

/// A committed virtual-memory range of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRange {
    /// Start virtual address (inclusive).
    pub start: u64,
    /// End virtual address (exclusive).
    pub end: u64,
    /// Protection string (e.g. `rwx`, `r-x`).
    pub protection: String,
    /// Eagerly-captured bytes for this range (may be empty / truncated).
    pub bytes: Vec<u8>,
}

impl MemoryRange {
    /// Create a memory range covering `[start, end)`.
    #[must_use]
    pub fn new(start: u64, end: u64, protection: impl Into<String>) -> Self {
        Self {
            start,
            end,
            protection: protection.into(),
            bytes: Vec::new(),
        }
    }

    /// Builder: attach captured bytes for this range.
    #[must_use]
    pub fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.bytes = bytes;
        self
    }

    /// Logical length of this range in bytes (`end - start`), saturating.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` if the range is empty (`end <= start`).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

// ─── Content provider ─────────────────────────────────────────────────────────

/// Content of a virtual file.
///
/// Files may carry eagerly-materialised bytes or a lazily-evaluated provider
/// closure that is only invoked on read. The closure variant lets large
/// payloads (memory dumps) stay un-materialised until needed.
#[derive(Clone)]
pub enum Content {
    /// Eagerly-stored bytes.
    Bytes(Arc<Vec<u8>>),
    /// Lazily-produced bytes; the closure is called on every read.
    Provider(Arc<dyn Fn() -> Vec<u8> + Send + Sync>),
}

impl Content {
    /// Wrap an owned byte buffer.
    #[must_use]
    pub fn bytes(data: Vec<u8>) -> Self {
        Self::Bytes(Arc::new(data))
    }

    /// Wrap a string's UTF-8 bytes.
    #[must_use]
    pub fn text(s: impl Into<String>) -> Self {
        Self::Bytes(Arc::new(s.into().into_bytes()))
    }

    /// Wrap a closure that produces bytes on demand.
    #[must_use]
    pub fn provider<F>(f: F) -> Self
    where
        F: Fn() -> Vec<u8> + Send + Sync + 'static,
    {
        Self::Provider(Arc::new(f))
    }

    /// Materialise the content bytes.
    #[must_use]
    pub fn read(&self) -> Vec<u8> {
        match self {
            Self::Bytes(b) => b.as_ref().clone(),
            Self::Provider(f) => f(),
        }
    }

    /// Logical size of the content.
    ///
    /// For [`Content::Bytes`] this is exact and cheap. For
    /// [`Content::Provider`] the provider is invoked to determine the length.
    #[must_use]
    pub fn size(&self) -> u64 {
        match self {
            Self::Bytes(b) => b.len() as u64,
            Self::Provider(f) => f().len() as u64,
        }
    }
}

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes(b) => f.debug_tuple("Bytes").field(&b.len()).finish_non_exhaustive(),
            Self::Provider(_) => f.write_str("Provider(..)"),
        }
    }
}

// ─── VfsNode ────────────────────────────────────────────────────────────────

/// A node in the self-contained virtual filesystem.
#[derive(Debug, Clone)]
pub enum VfsNode {
    /// A directory containing named children, kept sorted by name.
    Directory(Vec<(String, Self)>),
    /// A file with [`Content`].
    File(Content),
}

impl VfsNode {
    /// Create an empty directory node.
    #[must_use]
    pub const fn dir() -> Self {
        Self::Directory(Vec::new())
    }

    /// Create a file node from raw bytes.
    #[must_use]
    pub fn file_bytes(data: Vec<u8>) -> Self {
        Self::File(Content::bytes(data))
    }

    /// Create a file node from text.
    #[must_use]
    pub fn file_text(s: impl Into<String>) -> Self {
        Self::File(Content::text(s))
    }

    /// Returns `true` if this is a directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        matches!(self, Self::Directory(_))
    }

    /// Returns `true` if this is a file.
    #[must_use]
    pub const fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }

    /// Insert or replace a child by name (directories only). The child list is
    /// kept sorted so listings and exports are deterministic.
    ///
    /// Returns `false` if this node is not a directory.
    pub fn insert(&mut self, name: impl Into<String>, node: Self) -> bool {
        let Self::Directory(children) = self else {
            return false;
        };
        let name = name.into();
        match children.binary_search_by(|(n, _)| n.as_str().cmp(name.as_str())) {
            Ok(idx) => children[idx].1 = node,
            Err(idx) => children.insert(idx, (name, node)),
        }
        true
    }

    /// Look up an immediate child by name.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&Self> {
        if let Self::Directory(children) = self {
            children
                .binary_search_by(|(n, _)| n.as_str().cmp(name))
                .ok()
                .map(|idx| &children[idx].1)
        } else {
            None
        }
    }

    /// List immediate child names (directories only).
    #[must_use]
    pub fn child_names(&self) -> Option<Vec<&str>> {
        if let Self::Directory(children) = self {
            Some(children.iter().map(|(n, _)| n.as_str()).collect())
        } else {
            None
        }
    }

    /// Read the bytes of a file node. Returns `None` for directories.
    #[must_use]
    pub fn read(&self) -> Option<Vec<u8>> {
        match self {
            Self::File(c) => Some(c.read()),
            Self::Directory(_) => None,
        }
    }

    /// Logical size of a file node in bytes; directories report `0`.
    #[must_use]
    pub fn size(&self) -> u64 {
        match self {
            Self::File(c) => c.size(),
            Self::Directory(_) => 0,
        }
    }
}

// ─── VfsTree ────────────────────────────────────────────────────────────────

/// A self-contained virtual filesystem tree with a single directory root.
///
/// Layout produced by [`VfsBuilder`]:
/// ```text
/// /
/// ├── processes/
/// │   └── <pid>_<name>/
/// │       ├── info.txt
/// │       ├── cmdline.txt
/// │       ├── modules.csv
/// │       ├── handles.csv
/// │       └── memory/
/// │           └── <start>-<end>.bin
/// ├── kernel/
/// │   └── modules.csv
/// └── network/
///     └── connections.csv
/// ```
#[derive(Debug, Clone)]
pub struct VfsTree {
    root: VfsNode,
}

impl VfsTree {
    /// Wrap a root directory node.
    #[must_use]
    pub const fn new(root: VfsNode) -> Self {
        Self { root }
    }

    /// Borrow the root node.
    #[must_use]
    pub const fn root(&self) -> &VfsNode {
        &self.root
    }

    /// Resolve a `/`-separated path to a node.
    ///
    /// Both `/`-prefixed and bare paths are accepted; empty components (from
    /// leading, trailing, or doubled slashes) are ignored. The empty path or
    /// `/` resolves to the root.
    #[must_use]
    pub fn resolve(&self, path: &str) -> Option<&VfsNode> {
        let mut current = &self.root;
        for part in path.split('/').filter(|s| !s.is_empty()) {
            current = current.child(part)?;
        }
        Some(current)
    }

    /// List the child names of the directory at `path`.
    ///
    /// Returns `None` if the path does not exist or is not a directory.
    #[must_use]
    pub fn list_dir(&self, path: &str) -> Option<Vec<String>> {
        self.resolve(path)?
            .child_names()
            .map(|names| names.into_iter().map(str::to_string).collect())
    }

    /// Read the bytes of the file at `path`.
    ///
    /// Returns `None` if the path does not exist or is a directory.
    #[must_use]
    pub fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        self.resolve(path)?.read()
    }

    /// Compute aggregate statistics over the whole tree.
    #[must_use]
    pub fn stats(&self) -> TreeStats {
        let mut stats = TreeStats::default();
        Self::accumulate(&self.root, &mut stats);
        stats
    }

    fn accumulate(node: &VfsNode, stats: &mut TreeStats) {
        stats.total_nodes += 1;
        match node {
            VfsNode::Directory(children) => {
                stats.directories += 1;
                for (_, child) in children {
                    Self::accumulate(child, stats);
                }
            }
            VfsNode::File(content) => {
                stats.files += 1;
                stats.total_size += content.size();
            }
        }
    }

    /// Walk every node, yielding `(absolute_path, is_dir)` pairs in a stable
    /// pre-order traversal. The root is reported as `/`.
    #[must_use]
    pub fn walk(&self) -> Vec<(String, bool)> {
        let mut out = Vec::new();
        Self::walk_into(&self.root, "/", &mut out);
        out
    }

    fn walk_into(node: &VfsNode, path: &str, out: &mut Vec<(String, bool)>) {
        out.push((path.to_string(), node.is_dir()));
        if let VfsNode::Directory(children) = node {
            for (name, child) in children {
                let child_path = if path.ends_with('/') {
                    format!("{path}{name}")
                } else {
                    format!("{path}/{name}")
                };
                Self::walk_into(child, &child_path, out);
            }
        }
    }
}

// ─── TreeStats ────────────────────────────────────────────────────────────────

/// Aggregate statistics over a [`VfsTree`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TreeStats {
    /// Total number of nodes (files + directories), including the root.
    pub total_nodes: usize,
    /// Number of file nodes.
    pub files: usize,
    /// Number of directory nodes (including the root).
    pub directories: usize,
    /// Sum of all file content sizes, in bytes.
    pub total_size: u64,
}

// ─── VfsBuilder ─────────────────────────────────────────────────────────────

/// Builder that assembles a [`VfsTree`] from in-memory records.
#[derive(Debug, Default)]
pub struct VfsBuilder {
    processes: Vec<ProcessRecord>,
    kernel_modules: Vec<ModuleRecord>,
    connections: Vec<NetConnRecord>,
}

impl VfsBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the process list (replaces any previous list).
    #[must_use]
    pub fn with_processes(mut self, processes: Vec<ProcessRecord>) -> Self {
        self.processes = processes;
        self
    }

    /// Set the kernel module list.
    #[must_use]
    pub fn with_kernel_modules(mut self, modules: Vec<ModuleRecord>) -> Self {
        self.kernel_modules = modules;
        self
    }

    /// Set the network connection list.
    #[must_use]
    pub fn with_connections(mut self, connections: Vec<NetConnRecord>) -> Self {
        self.connections = connections;
        self
    }

    /// Add a single process.
    #[must_use]
    pub fn add_process(mut self, process: ProcessRecord) -> Self {
        self.processes.push(process);
        self
    }

    /// Consume the builder and produce a [`VfsTree`].
    #[must_use]
    pub fn build(self) -> VfsTree {
        let mut root = VfsNode::dir();

        // /processes
        let mut processes_dir = VfsNode::dir();
        for proc in &self.processes {
            let dir_name = format!("{}_{}", proc.pid, sanitize(&proc.name));
            processes_dir.insert(dir_name, Self::build_process_node(proc));
        }
        root.insert("processes", processes_dir);

        // /kernel/modules.csv
        let mut kernel_dir = VfsNode::dir();
        kernel_dir.insert(
            "modules.csv",
            VfsNode::file_text(modules_csv(&self.kernel_modules)),
        );
        root.insert("kernel", kernel_dir);

        // /network/connections.csv
        let mut network_dir = VfsNode::dir();
        network_dir.insert(
            "connections.csv",
            VfsNode::file_text(connections_csv(&self.connections)),
        );
        root.insert("network", network_dir);

        // /summary
        root.insert(
            "summary.csv",
            VfsNode::file_text(process_csv(&self.processes)),
        );

        VfsTree::new(root)
    }

    fn build_process_node(proc: &ProcessRecord) -> VfsNode {
        let mut node = VfsNode::dir();
        node.insert("info.txt", VfsNode::file_text(process_info_text(proc)));
        node.insert(
            "cmdline.txt",
            VfsNode::file_text(format!("{}\n", proc.cmdline)),
        );
        node.insert(
            "modules.csv",
            VfsNode::file_text(modules_csv(&proc.modules)),
        );
        node.insert(
            "handles.csv",
            VfsNode::file_text(handles_csv(&proc.handles)),
        );

        let mut memory_dir = VfsNode::dir();
        for range in &proc.memory_ranges {
            let fname = format!("{:016x}-{:016x}.bin", range.start, range.end);
            if range.bytes.is_empty() {
                // Provide a lazy zero-fill provider sized to the range so the
                // file appears with the correct logical size without holding
                // the bytes in memory eagerly.
                let len = usize::try_from(range.len()).unwrap_or(usize::MAX);
                memory_dir.insert(
                    fname,
                    VfsNode::File(Content::provider(move || vec![0u8; len])),
                );
            } else {
                memory_dir.insert(fname, VfsNode::file_bytes(range.bytes.clone()));
            }
        }
        node.insert("memory", memory_dir);
        node
    }
}

// ─── CSV / text generators ─────────────────────────────────────────────────────

/// Render a process list as CSV with header
/// `pid,ppid,name,base,size,handle_count`.
#[must_use]
pub fn process_csv(processes: &[ProcessRecord]) -> String {
    let mut out = String::from("pid,ppid,name,base,size,handle_count\n");
    for p in processes {
        let _ = writeln!(out, 
            "{},{},{},0x{:016x},{},{}",
            p.pid,
            p.ppid,
            csv_escape(&p.name),
            p.base,
            p.size,
            p.handle_count,
        );
    }
    out
}

/// Render a module list as CSV with header `name,base,size,path`.
#[must_use]
pub fn modules_csv(modules: &[ModuleRecord]) -> String {
    let mut out = String::from("name,base,size,path\n");
    for m in modules {
        let _ = writeln!(out, 
            "{},0x{:016x},{},{}",
            csv_escape(&m.name),
            m.base,
            m.size,
            csv_escape(&m.path),
        );
    }
    out
}

/// Render a network-connection list as CSV with header
/// `proto,local_addr,local_port,remote_addr,remote_port,state,pid`.
#[must_use]
pub fn connections_csv(connections: &[NetConnRecord]) -> String {
    let mut out = String::from("proto,local_addr,local_port,remote_addr,remote_port,state,pid\n");
    for c in connections {
        let _ = writeln!(out, 
            "{},{},{},{},{},{},{}",
            c.proto.as_str(),
            csv_escape(&c.local_addr),
            c.local_port,
            csv_escape(&c.remote_addr),
            c.remote_port,
            csv_escape(&c.state),
            c.pid,
        );
    }
    out
}

/// Render a handle list as CSV with header `handle,object_type,name,access`.
#[must_use]
pub fn handles_csv(handles: &[HandleRecord]) -> String {
    let mut out = String::from("handle,object_type,name,access\n");
    for h in handles {
        let _ = writeln!(out, 
            "0x{:x},{},{},0x{:08x}",
            h.handle,
            csv_escape(&h.object_type),
            csv_escape(&h.name),
            h.access,
        );
    }
    out
}

/// Render a human-readable `info.txt` body for a single process.
#[must_use]
pub fn process_info_text(p: &ProcessRecord) -> String {
    format!(
        "pid:           {}\n\
         ppid:          {}\n\
         name:          {}\n\
         base:          0x{:016x}\n\
         size:          {}\n\
         handle_count:  {}\n\
         module_count:  {}\n\
         memory_ranges: {}\n",
        p.pid,
        p.ppid,
        p.name,
        p.base,
        p.size,
        p.handle_count,
        p.modules.len(),
        p.memory_ranges.len(),
    )
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn sanitize(name: &str) -> String {
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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_processes() -> Vec<ProcessRecord> {
        let system = ProcessRecord::new(4, 0, "System")
            .with_image(0xfffff800_00000000, 0x1000)
            .with_module(ModuleRecord::new(
                "ntoskrnl.exe",
                0xfffff800_00000000,
                0x800000,
                "C:\\Windows\\System32\\ntoskrnl.exe",
            ))
            .with_handle(HandleRecord::new(0x4, "Process", "System", 0x1fffff));

        let explorer = ProcessRecord::new(1337, 4, "explorer.exe")
            .with_image(0x7ff6_00000000, 0x300000)
            .with_cmdline("C:\\Windows\\explorer.exe /factory")
            .with_module(ModuleRecord::new(
                "ntdll.dll",
                0x7fff_00000000,
                0x200000,
                "C:\\Windows\\System32\\ntdll.dll",
            ))
            .with_module(ModuleRecord::new(
                "kernel32.dll",
                0x7fff_00200000,
                0x100000,
                "C:\\Windows\\System32\\kernel32.dll",
            ))
            .with_memory_range(
                MemoryRange::new(0x10000, 0x11000, "rw-").with_bytes(vec![0xaa; 0x1000]),
            )
            .with_memory_range(MemoryRange::new(0x20000, 0x22000, "r-x"))
            .with_handle(HandleRecord::new(0x10, "File", "\\Device\\Foo", 0x120089));

        vec![system, explorer]
    }

    fn mock_modules() -> Vec<ModuleRecord> {
        vec![
            ModuleRecord::new(
                "ntoskrnl.exe",
                0xfffff800_00000000,
                0x800000,
                "ntoskrnl.exe",
            ),
            ModuleRecord::new("hal.dll", 0xfffff800_00800000, 0x80000, "hal.dll"),
        ]
    }

    fn mock_connections() -> Vec<NetConnRecord> {
        vec![
            NetConnRecord::new(
                Proto::Tcp,
                "10.0.0.5",
                49152,
                "93.184.216.34",
                443,
                "ESTABLISHED",
                1337,
            ),
            NetConnRecord::new(Proto::Udp, "0.0.0.0", 53, "0.0.0.0", 0, "LISTEN", 4),
        ]
    }

    fn build() -> VfsTree {
        VfsBuilder::new()
            .with_processes(mock_processes())
            .with_kernel_modules(mock_modules())
            .with_connections(mock_connections())
            .build()
    }

    // ── records ────────────────────────────────────────────────────────────────

    #[test]
    fn process_record_builder() {
        let p = ProcessRecord::new(1, 0, "init")
            .with_image(0x1000, 0x2000)
            .with_cmdline("/sbin/init")
            .with_handle(HandleRecord::new(1, "File", "/etc", 1));
        assert_eq!(p.pid, 1);
        assert_eq!(p.base, 0x1000);
        assert_eq!(p.cmdline, "/sbin/init");
        assert_eq!(p.handle_count, 1);
        assert_eq!(p.handles.len(), 1);
    }

    #[test]
    fn proto_as_str() {
        assert_eq!(Proto::Tcp.as_str(), "tcp");
        assert_eq!(Proto::Udp6.as_str(), "udp6");
    }

    #[test]
    fn memory_range_len_and_empty() {
        let r = MemoryRange::new(0x1000, 0x3000, "rw-");
        assert_eq!(r.len(), 0x2000);
        assert!(!r.is_empty());
        assert!(MemoryRange::new(0x10, 0x10, "rw-").is_empty());
    }

    // ── content ─────────────────────────────────────────────────────────────────

    #[test]
    fn content_bytes_read_and_size() {
        let c = Content::bytes(vec![1, 2, 3]);
        assert_eq!(c.read(), vec![1, 2, 3]);
        assert_eq!(c.size(), 3);
    }

    #[test]
    fn content_provider_lazy() {
        let c = Content::provider(|| vec![7u8; 10]);
        assert_eq!(c.size(), 10);
        assert_eq!(c.read().len(), 10);
    }

    #[test]
    fn content_text() {
        let c = Content::text("hello");
        assert_eq!(c.read(), b"hello");
    }

    // ── node ─────────────────────────────────────────────────────────────────────

    #[test]
    fn node_insert_keeps_sorted() {
        let mut d = VfsNode::dir();
        assert!(d.insert("zeta", VfsNode::file_text("z")));
        assert!(d.insert("alpha", VfsNode::file_text("a")));
        assert!(d.insert("mid", VfsNode::file_text("m")));
        assert_eq!(d.child_names().unwrap(), vec!["alpha", "mid", "zeta"]);
    }

    #[test]
    fn node_insert_replaces() {
        let mut d = VfsNode::dir();
        d.insert("a", VfsNode::file_text("one"));
        d.insert("a", VfsNode::file_text("two"));
        assert_eq!(d.child("a").unwrap().read().unwrap(), b"two");
        assert_eq!(d.child_names().unwrap().len(), 1);
    }

    #[test]
    fn node_insert_on_file_fails() {
        let mut f = VfsNode::file_text("x");
        assert!(!f.insert("child", VfsNode::dir()));
    }

    #[test]
    fn node_read_on_dir_is_none() {
        assert!(VfsNode::dir().read().is_none());
        assert_eq!(VfsNode::dir().size(), 0);
    }

    // ── tree build + resolve ─────────────────────────────────────────────────────

    #[test]
    fn root_has_expected_children() {
        let names = build().list_dir("/").unwrap();
        assert!(names.contains(&"processes".to_string()));
        assert!(names.contains(&"kernel".to_string()));
        assert!(names.contains(&"network".to_string()));
        assert!(names.contains(&"summary.csv".to_string()));
    }

    #[test]
    fn resolve_root_variants() {
        let t = build();
        assert!(t.resolve("/").unwrap().is_dir());
        assert!(t.resolve("").unwrap().is_dir());
        assert!(t.resolve("///").unwrap().is_dir());
    }

    #[test]
    fn resolve_existing_process_path() {
        let t = build();
        // explorer.exe pid 1337
        let node = t.resolve("/processes/1337_explorer.exe/info.txt");
        assert!(node.is_some());
        assert!(node.unwrap().is_file());
    }

    #[test]
    fn resolve_missing_path_is_none() {
        let t = build();
        assert!(t.resolve("/processes/9999_nope/info.txt").is_none());
        assert!(t.resolve("/nope").is_none());
        assert!(t.resolve("/network/connections.csv/extra").is_none());
    }

    #[test]
    fn list_dir_on_file_is_none() {
        let t = build();
        assert!(t.list_dir("/summary.csv").is_none());
    }

    #[test]
    fn list_process_subdir() {
        let t = build();
        let files = t.list_dir("/processes/1337_explorer.exe").unwrap();
        assert!(files.contains(&"info.txt".to_string()));
        assert!(files.contains(&"cmdline.txt".to_string()));
        assert!(files.contains(&"modules.csv".to_string()));
        assert!(files.contains(&"handles.csv".to_string()));
        assert!(files.contains(&"memory".to_string()));
    }

    // ── reading generated files ──────────────────────────────────────────────────

    #[test]
    fn read_summary_csv_has_rows() {
        let t = build();
        let data = t.read_file("/summary.csv").unwrap();
        let s = String::from_utf8(data).unwrap();
        assert!(s.starts_with("pid,ppid,name,base,size,handle_count"));
        assert!(s.contains("\n4,0,System,"));
        assert!(s.contains("explorer.exe"));
        // header + 2 process rows
        assert_eq!(s.lines().count(), 3);
    }

    #[test]
    fn read_kernel_modules_csv() {
        let t = build();
        let s = String::from_utf8(t.read_file("/kernel/modules.csv").unwrap()).unwrap();
        assert!(s.starts_with("name,base,size,path"));
        assert!(s.contains("ntoskrnl.exe"));
        assert!(s.contains("hal.dll"));
    }

    #[test]
    fn read_connections_csv() {
        let t = build();
        let s = String::from_utf8(t.read_file("/network/connections.csv").unwrap()).unwrap();
        assert!(s.starts_with("proto,local_addr,local_port,remote_addr,remote_port,state,pid"));
        assert!(s.contains("tcp,10.0.0.5,49152,93.184.216.34,443,ESTABLISHED,1337"));
        assert!(s.contains("udp,0.0.0.0,53"));
    }

    #[test]
    fn read_process_handles_csv() {
        let t = build();
        let s = String::from_utf8(
            t.read_file("/processes/1337_explorer.exe/handles.csv")
                .unwrap(),
        )
        .unwrap();
        assert!(s.starts_with("handle,object_type,name,access"));
        assert!(s.contains("File"));
    }

    #[test]
    fn read_memory_range_eager_bytes() {
        let t = build();
        let data = t
            .read_file("/processes/1337_explorer.exe/memory/0000000000010000-0000000000011000.bin")
            .unwrap();
        assert_eq!(data.len(), 0x1000);
        assert!(data.iter().all(|&b| b == 0xaa));
    }

    #[test]
    fn read_memory_range_lazy_zerofill() {
        let t = build();
        // 0x20000..0x22000 has no bytes → lazy zero-fill of 0x2000
        let data = t
            .read_file("/processes/1337_explorer.exe/memory/0000000000020000-0000000000022000.bin")
            .unwrap();
        assert_eq!(data.len(), 0x2000);
        assert!(data.iter().all(|&b| b == 0));
    }

    // ── stats ────────────────────────────────────────────────────────────────────

    #[test]
    fn stats_counts_consistent() {
        let t = build();
        let s = t.stats();
        assert_eq!(s.total_nodes, s.files + s.directories);
        assert!(s.files > 0);
        assert!(s.directories >= 5); // root, processes, 2 proc dirs, 2 memory dirs, kernel, network
        assert!(s.total_size > 0);
    }

    #[test]
    fn stats_empty_tree() {
        let t = VfsBuilder::new().build();
        let s = t.stats();
        // root + processes + kernel + network dirs, plus 2 csv + summary files
        assert!(s.directories >= 4);
        assert!(s.files >= 3);
        assert_eq!(s.total_nodes, s.files + s.directories);
    }

    #[test]
    fn stats_size_matches_summary() {
        let t = build();
        let summary_len = t.read_file("/summary.csv").unwrap().len() as u64;
        // total_size must be at least the summary file we can read directly.
        assert!(t.stats().total_size >= summary_len);
    }

    // ── walk ──────────────────────────────────────────────────────────────────────

    #[test]
    fn walk_visits_root_first() {
        let t = build();
        let walk = t.walk();
        assert_eq!(walk[0].0, "/");
        assert!(walk[0].1);
    }

    #[test]
    fn walk_finds_info_files() {
        let t = build();
        let paths: Vec<String> = t.walk().into_iter().map(|(p, _)| p).collect();
        assert!(paths.iter().any(|p| p.ends_with("/info.txt")));
        assert!(paths.iter().any(|p| p.ends_with("/connections.csv")));
        assert!(paths.contains(&"/processes/4_System".to_string()));
    }

    #[test]
    fn walk_count_matches_total_nodes() {
        let t = build();
        assert_eq!(t.walk().len(), t.stats().total_nodes);
    }

    // ── csv generators direct ──────────────────────────────────────────────────────

    #[test]
    fn process_csv_escapes_commas() {
        let p = ProcessRecord::new(1, 0, "weird,name");
        let s = process_csv(std::slice::from_ref(&p));
        assert!(s.contains("\"weird,name\""));
    }

    #[test]
    fn add_process_appends() {
        let t = VfsBuilder::new()
            .add_process(ProcessRecord::new(1, 0, "a"))
            .add_process(ProcessRecord::new(2, 1, "b"))
            .build();
        assert_eq!(t.list_dir("/processes").unwrap().len(), 2);
    }

    #[test]
    fn sanitize_replaces_separators() {
        let t = VfsBuilder::new()
            .add_process(ProcessRecord::new(7, 0, "a/b:c"))
            .build();
        let names = t.list_dir("/processes").unwrap();
        assert_eq!(names, vec!["7_a_b_c".to_string()]);
    }
}
