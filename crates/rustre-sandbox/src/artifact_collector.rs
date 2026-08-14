//! `artifact_collector` — Sandbox artifact collection and diffing.
//!
//! Collects artifacts produced during sandboxed execution: dropped files,
//! registry modifications, process trees, network connections, suspicious
//! memory allocations, and screenshots. Supports before/after snapshots for
//! detecting all changes introduced by the analysed binary.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ─── Timestamp ────────────────────────────────────────────────────────────────

pub type Timestamp = u64;

fn now_ms() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX))
        .try_into()
        .unwrap_or(u64::MAX)
}

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("snapshot not available: {0}")]
    NoSnapshot(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("collector not initialised")]
    NotInitialised,
    #[error("access denied to path: {0}")]
    AccessDenied(PathBuf),
}

impl From<std::io::Error> for CollectorError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

// ─── Dropped File ─────────────────────────────────────────────────────────────

/// A file created by the sandboxed process that did not exist before execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedFile {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
    pub md5: String,
    pub created_at_ms: Timestamp,
    pub is_executable: bool,
    pub file_type: FileType,
    pub content_preview: Vec<u8>, // first 256 bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileType {
    Pe,     // Windows PE (MZ header)
    Elf,    // ELF binary
    Script, // .bat/.ps1/.sh/.py/.vbs
    Archive, // .zip/.rar/.7z
    Document,
    Image,
    Unknown,
}

impl FileType {
    #[must_use] 
    pub fn from_magic(bytes: &[u8]) -> Self {
        if bytes.len() >= 2 {
            match &bytes[..2] {
                b"MZ" => return Self::Pe,
                b"\x7fE" if bytes.len() >= 4 && &bytes[..4] == b"\x7fELF" => return Self::Elf,
                b"PK" => return Self::Archive,
                _ => {}
            }
        }
        if bytes.len() >= 4 && &bytes[..4] == b"Rar!" {
            return Self::Archive;
        }
        Self::Unknown
    }

    pub fn from_extension(path: &std::path::Path) -> Self {
        match path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref() {
            Some("exe" | "dll" | "sys" | "scr") => Self::Pe,
            Some("elf" | "so" | "ko") => Self::Elf,
            Some("bat" | "cmd" | "ps1" | "sh" | "py" | "vbs" | "js") => Self::Script,
            Some("zip" | "rar" | "7z" | "tar" | "gz") => Self::Archive,
            Some("doc" | "docx" | "pdf" | "xls" | "xlsx") => Self::Document,
            Some("png" | "jpg" | "jpeg" | "bmp" | "gif") => Self::Image,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pe => write!(f, "PE"),
            Self::Elf => write!(f, "ELF"),
            Self::Script => write!(f, "Script"),
            Self::Archive => write!(f, "Archive"),
            Self::Document => write!(f, "Document"),
            Self::Image => write!(f, "Image"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─── Registry Modification ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryModification {
    pub timestamp_ms: Timestamp,
    pub key_path: String,
    pub value_name: String,
    pub operation: RegOperation,
    pub old_value: Option<RegistryValue>,
    pub new_value: Option<RegistryValue>,
    pub pid: u32,
    pub process_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegOperation {
    Create,
    Modify,
    Delete,
    CreateKey,
    DeleteKey,
}

impl std::fmt::Display for RegOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => write!(f, "Create"),
            Self::Modify => write!(f, "Modify"),
            Self::Delete => write!(f, "Delete"),
            Self::CreateKey => write!(f, "CreateKey"),
            Self::DeleteKey => write!(f, "DeleteKey"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryValue {
    Sz(String),
    ExpandSz(String),
    Dword(u32),
    Qword(u64),
    Binary(Vec<u8>),
    MultiSz(Vec<String>),
}

impl RegistryValue {
    #[must_use] 
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Sz(_) => "REG_SZ",
            Self::ExpandSz(_) => "REG_EXPAND_SZ",
            Self::Dword(_) => "REG_DWORD",
            Self::Qword(_) => "REG_QWORD",
            Self::Binary(_) => "REG_BINARY",
            Self::MultiSz(_) => "REG_MULTI_SZ",
        }
    }
}

// ─── Process Tree ─────────────────────────────────────────────────────────────

/// A node in the process tree observed during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub command_line: String,
    pub image_path: PathBuf,
    pub start_time_ms: Timestamp,
    pub end_time_ms: Option<Timestamp>,
    pub exit_code: Option<i32>,
    pub user: String,
    pub integrity_level: IntegrityLevel,
    pub loaded_modules: Vec<String>,
    pub children: Vec<u32>, // child PIDs
}

impl ProcessNode {
    #[must_use] 
    pub const fn is_alive(&self) -> bool {
        self.end_time_ms.is_none()
    }

    #[must_use] 
    pub fn lifetime_ms(&self) -> Option<u64> {
        self.end_time_ms.map(|e| e.saturating_sub(self.start_time_ms))
    }

    #[must_use] 
    pub fn depth(&self, tree: &ProcessTree) -> usize {
        if self.parent_pid == self.pid || self.parent_pid == 0 {
            return 0;
        }
        tree.nodes.get(&self.parent_pid)
            .map_or(0, |p| 1 + p.depth(tree))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    High,
    System,
    Unknown,
}

impl std::fmt::Display for IntegrityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Untrusted => write!(f, "Untrusted"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::System => write!(f, "System"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Complete process tree from sandbox execution.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProcessTree {
    pub nodes: HashMap<u32, ProcessNode>,
    pub root_pid: Option<u32>,
}

impl ProcessTree {
    pub fn add_process(&mut self, node: ProcessNode) {
        let pid = node.pid;
        let parent = node.parent_pid;
        self.nodes.insert(pid, node);
        if let Some(p) = self.nodes.get_mut(&parent)
            && !p.children.contains(&pid) {
                p.children.push(pid);
            }
    }

    #[must_use] 
    pub fn descendants(&self, pid: u32) -> Vec<u32> {
        let mut result = Vec::new();
        let mut queue = vec![pid];
        while let Some(p) = queue.pop() {
            if let Some(node) = self.nodes.get(&p) {
                for &child in &node.children {
                    result.push(child);
                    queue.push(child);
                }
            }
        }
        result
    }

    #[must_use] 
    pub fn max_depth(&self) -> usize {
        self.nodes.values().map(|n| n.depth(self)).max().unwrap_or(0)
    }

    #[must_use] 
    pub fn process_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns all processes with SYSTEM integrity level.
    #[must_use] 
    pub fn elevated_processes(&self) -> Vec<&ProcessNode> {
        self.nodes.values()
            .filter(|n| matches!(n.integrity_level, IntegrityLevel::High | IntegrityLevel::System))
            .collect()
    }
}

// ─── Network Connection ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub pid: u32,
    pub process_name: String,
    pub protocol: TransportProtocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub first_seen_ms: Timestamp,
    pub last_seen_ms: Timestamp,
    pub hostname: Option<String>, // resolved reverse DNS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    RawSocket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Listen,
    SynSent,
    Established,
    CloseWait,
    TimeWait,
    Closed,
    Unknown,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Listen => write!(f, "LISTEN"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::Established => write!(f, "ESTABLISHED"),
            Self::CloseWait => write!(f, "CLOSE_WAIT"),
            Self::TimeWait => write!(f, "TIME_WAIT"),
            Self::Closed => write!(f, "CLOSED"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

// ─── Memory Dump Entry ────────────────────────────────────────────────────────

/// A suspicious memory region flagged for dumping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDumpEntry {
    pub pid: u32,
    pub base_address: u64,
    pub size: usize,
    pub permissions: MemPermissions,
    pub reason: SuspicionReason,
    pub data: Vec<u8>,
    pub sha256: String,
    pub timestamp_ms: Timestamp,
    pub region_type: MemRegionType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl std::fmt::Display for MemPermissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.read { "r" } else { "-" },
            if self.write { "w" } else { "-" },
            if self.execute { "x" } else { "-" },
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuspicionReason {
    Rwx,              // RWX region (classic shellcode indicator)
    UnbackedExecutable, // Executable memory not backed by a file
    InjectedCode,     // Detected via parent/child page diff
    HeapShellcode,    // PE/shellcode pattern found in heap
    EncryptedBlob,    // High-entropy region
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemRegionType {
    Heap,
    Stack,
    MappedFile,
    Anonymous,
    Unknown,
}

// ─── Screenshot ───────────────────────────────────────────────────────────────

/// A screenshot captured at a point in time during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Screenshot {
    pub timestamp_ms: Timestamp,
    pub width: u32,
    pub height: u32,
    pub format: ImageFormat,
    pub data: Vec<u8>,
    pub trigger: ScreenshotTrigger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageFormat {
    Png,
    Jpeg,
    Bmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScreenshotTrigger {
    Periodic,
    WindowCreated,
    InputRequested,
    SuspiciousActivity,
    OnExit,
}

// ─── Filesystem Snapshot ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct FilesystemSnapshot {
    pub taken_at_ms: Timestamp,
    /// Map of path → (size, sha256)
    pub entries: HashMap<PathBuf, (u64, String)>,
}

impl FilesystemSnapshot {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            taken_at_ms: now_ms(),
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, path: PathBuf, size: u64, hash: String) {
        self.entries.insert(path, (size, hash));
    }

    /// Compute diff: files added/removed/modified between `before` and `after`.
    #[must_use] 
    pub fn diff(before: &Self, after: &Self) -> FilesystemDiff {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut modified = Vec::new();

        for (path, (size_after, hash_after)) in &after.entries {
            if let Some((size_before, hash_before)) = before.entries.get(path) {
                if hash_after != hash_before {
                    modified.push(FileChange {
                        path: path.clone(),
                        change: ChangeKind::Modified,
                        size_before: Some(*size_before),
                        size_after: Some(*size_after),
                        hash_before: Some(hash_before.clone()),
                        hash_after: Some(hash_after.clone()),
                    });
                }
            } else {
                added.push(FileChange {
                    path: path.clone(),
                    change: ChangeKind::Added,
                    size_before: None,
                    size_after: Some(*size_after),
                    hash_before: None,
                    hash_after: Some(hash_after.clone()),
                });
            }
        }

        for (path, (size_before, hash_before)) in &before.entries {
            if !after.entries.contains_key(path) {
                removed.push(FileChange {
                    path: path.clone(),
                    change: ChangeKind::Removed,
                    size_before: Some(*size_before),
                    size_after: None,
                    hash_before: Some(hash_before.clone()),
                    hash_after: None,
                });
            }
        }

        FilesystemDiff { added, removed, modified }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: PathBuf,
    pub change: ChangeKind,
    pub size_before: Option<u64>,
    pub size_after: Option<u64>,
    pub hash_before: Option<String>,
    pub hash_after: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Default)]
pub struct FilesystemDiff {
    pub added: Vec<FileChange>,
    pub removed: Vec<FileChange>,
    pub modified: Vec<FileChange>,
}

impl FilesystemDiff {
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    #[must_use] 
    pub const fn total_changes(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }
}

// ─── Registry Snapshot ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct RegistrySnapshot {
    pub taken_at_ms: Timestamp,
    pub entries: HashMap<String, RegistryValue>,
}

impl RegistrySnapshot {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            taken_at_ms: now_ms(),
            entries: HashMap::new(),
        }
    }

    #[must_use] 
    pub fn diff(before: &Self, after: &Self) -> Vec<RegistryModification> {
        let mut mods = Vec::new();
        for (key, new_val) in &after.entries {
            if let Some(old_val) = before.entries.get(key) {
                let old_str = format!("{old_val:?}");
                let new_str = format!("{new_val:?}");
                if old_str != new_str {
                    let (key_path, value_name) = Self::split_key(key);
                    mods.push(RegistryModification {
                        timestamp_ms: now_ms(),
                        key_path,
                        value_name,
                        operation: RegOperation::Modify,
                        old_value: Some(old_val.clone()),
                        new_value: Some(new_val.clone()),
                        pid: 0,
                        process_name: String::new(),
                    });
                }
            } else {
                let (key_path, value_name) = Self::split_key(key);
                mods.push(RegistryModification {
                    timestamp_ms: now_ms(),
                    key_path,
                    value_name,
                    operation: RegOperation::Create,
                    old_value: None,
                    new_value: Some(new_val.clone()),
                    pid: 0,
                    process_name: String::new(),
                });
            }
        }
        for key in before.entries.keys() {
            if !after.entries.contains_key(key) {
                let (key_path, value_name) = Self::split_key(key);
                mods.push(RegistryModification {
                    timestamp_ms: now_ms(),
                    key_path,
                    value_name,
                    operation: RegOperation::Delete,
                    old_value: before.entries.get(key).cloned(),
                    new_value: None,
                    pid: 0,
                    process_name: String::new(),
                });
            }
        }
        mods
    }

    fn split_key(full: &str) -> (String, String) {
        full.rfind('\\').map_or_else(
            || (full.to_owned(), String::new()),
            |pos| (full[..pos].to_owned(), full[pos + 1..].to_owned()),
        )
    }
}

// ─── Artifact Collector ───────────────────────────────────────────────────────

/// Main artifact collection engine.
#[derive(Debug, Default)]
pub struct ArtifactCollector {
    pub dropped_files: Vec<DroppedFile>,
    pub registry_modifications: Vec<RegistryModification>,
    pub process_tree: ProcessTree,
    pub network_connections: Vec<NetworkConnection>,
    pub memory_dumps: Vec<MemoryDumpEntry>,
    pub screenshots: Vec<Screenshot>,
    pub filesystem_snapshot_before: Option<FilesystemSnapshot>,
    pub filesystem_snapshot_after: Option<FilesystemSnapshot>,
    pub registry_snapshot_before: Option<RegistrySnapshot>,
    pub registry_snapshot_after: Option<RegistrySnapshot>,
}

impl ArtifactCollector {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    // ── Dropped files ────────────────────────────────────────────────────────

    pub fn add_dropped_file(&mut self, file: DroppedFile) {
        self.dropped_files.push(file);
    }

    /// Build a `DroppedFile` from raw bytes (content preview only, no actual I/O).
    pub fn record_dropped_file(
        &mut self,
        path: PathBuf,
        content: &[u8],
        is_executable: bool,
    ) {
        let file_type = if content.len() >= 4 {
            let ft = FileType::from_magic(content);
            if matches!(ft, FileType::Unknown) {
                FileType::from_extension(&path)
            } else {
                ft
            }
        } else {
            FileType::from_extension(&path)
        };

        let preview: Vec<u8> = content[..content.len().min(256)].to_vec();
        // Pseudo-hash for testing purposes (real impl would use sha2 crate)
        let sha256 = format!("sha256:{:08x}", content.len());
        let md5 = format!("md5:{:08x}", content.len() ^ 0xDEAD);

        self.dropped_files.push(DroppedFile {
            path,
            size_bytes: content.len() as u64,
            sha256,
            md5,
            created_at_ms: now_ms(),
            is_executable,
            file_type,
            content_preview: preview,
        });
    }

    // ── Registry ─────────────────────────────────────────────────────────────

    pub fn add_registry_modification(&mut self, rm: RegistryModification) {
        self.registry_modifications.push(rm);
    }

    pub fn compute_registry_diff(&mut self) {
        if let (Some(before), Some(after)) = (
            &self.registry_snapshot_before,
            &self.registry_snapshot_after,
        ) {
            let mods = RegistrySnapshot::diff(before, after);
            self.registry_modifications.extend(mods);
        }
    }

    // ── Process tree ─────────────────────────────────────────────────────────

    pub fn add_process(&mut self, node: ProcessNode) {
        self.process_tree.add_process(node);
    }

    pub fn mark_process_exit(&mut self, pid: u32, exit_code: i32) {
        if let Some(node) = self.process_tree.nodes.get_mut(&pid) {
            node.end_time_ms = Some(now_ms());
            node.exit_code = Some(exit_code);
        }
    }

    // ── Network ───────────────────────────────────────────────────────────────

    pub fn add_connection(&mut self, conn: NetworkConnection) {
        self.network_connections.push(conn);
    }

    #[must_use] 
    pub fn unique_remote_ips(&self) -> Vec<String> {
        let mut ips: Vec<String> = self.network_connections
            .iter()
            .map(|c| c.remote_addr.clone())
            .collect();
        ips.sort();
        ips.dedup();
        ips
    }

    // ── Memory dumps ─────────────────────────────────────────────────────────

    pub fn add_memory_dump(&mut self, dump: MemoryDumpEntry) {
        self.memory_dumps.push(dump);
    }

    #[must_use] 
    pub fn rwx_regions(&self) -> Vec<&MemoryDumpEntry> {
        self.memory_dumps.iter()
            .filter(|d| d.permissions.read && d.permissions.write && d.permissions.execute)
            .collect()
    }

    // ── Screenshots ───────────────────────────────────────────────────────────

    pub fn add_screenshot(&mut self, ss: Screenshot) {
        self.screenshots.push(ss);
    }

    // ── Filesystem diff ───────────────────────────────────────────────────────

    #[must_use] 
    pub fn filesystem_diff(&self) -> Option<FilesystemDiff> {
        let before = self.filesystem_snapshot_before.as_ref()?;
        let after = self.filesystem_snapshot_after.as_ref()?;
        Some(FilesystemSnapshot::diff(before, after))
    }

    // ── Summary ───────────────────────────────────────────────────────────────

    #[must_use] 
    pub fn summary(&self) -> ArtifactSummary {
        let fs_diff = self.filesystem_diff();
        ArtifactSummary {
            dropped_files: self.dropped_files.len(),
            executable_drops: self.dropped_files.iter().filter(|f| f.is_executable).count(),
            registry_modifications: self.registry_modifications.len(),
            processes_spawned: self.process_tree.process_count(),
            max_process_depth: self.process_tree.max_depth(),
            elevated_processes: self.process_tree.elevated_processes().len(),
            network_connections: self.network_connections.len(),
            unique_remote_ips: self.unique_remote_ips().len(),
            memory_dumps: self.memory_dumps.len(),
            rwx_regions: self.rwx_regions().len(),
            screenshots: self.screenshots.len(),
            files_added: fs_diff.as_ref().map_or(0, |d| d.added.len()),
            files_removed: fs_diff.as_ref().map_or(0, |d| d.removed.len()),
            files_modified: fs_diff.as_ref().map_or(0, |d| d.modified.len()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSummary {
    pub dropped_files: usize,
    pub executable_drops: usize,
    pub registry_modifications: usize,
    pub processes_spawned: usize,
    pub max_process_depth: usize,
    pub elevated_processes: usize,
    pub network_connections: usize,
    pub unique_remote_ips: usize,
    pub memory_dumps: usize,
    pub rwx_regions: usize,
    pub screenshots: usize,
    pub files_added: usize,
    pub files_removed: usize,
    pub files_modified: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_type_detection() {
        assert_eq!(FileType::from_magic(b"MZ\x90\x00"), FileType::Pe);
        assert_eq!(FileType::from_magic(b"\x7fELF"), FileType::Elf);
        assert_eq!(FileType::from_magic(b"PK\x03\x04"), FileType::Archive);
        let path = std::path::Path::new("evil.bat");
        assert_eq!(FileType::from_extension(path), FileType::Script);
    }

    #[test]
    fn test_filesystem_diff() {
        let mut before = FilesystemSnapshot::new();
        before.insert(PathBuf::from("C:\\Windows\\file.exe"), 1024, "aabbcc".to_owned());
        before.insert(PathBuf::from("C:\\Users\\user\\Desktop\\doc.pdf"), 512, "112233".to_owned());

        let mut after = FilesystemSnapshot::new();
        after.insert(PathBuf::from("C:\\Windows\\file.exe"), 1024, "aabbcc".to_owned()); // unchanged
        after.insert(PathBuf::from("C:\\Temp\\malware.exe"), 2048, "deadbeef".to_owned()); // added
        // doc.pdf removed

        let diff = FilesystemSnapshot::diff(&before, &after);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.modified.len(), 0);
        assert_eq!(diff.added[0].path, PathBuf::from("C:\\Temp\\malware.exe"));
    }

    #[test]
    fn test_process_tree_depth() {
        let mut tree = ProcessTree::default();
        tree.add_process(ProcessNode {
            pid: 1000,
            parent_pid: 0,
            name: "malware.exe".to_owned(),
            command_line: "malware.exe".to_owned(),
            image_path: PathBuf::from("C:\\Temp\\malware.exe"),
            start_time_ms: now_ms(),
            end_time_ms: None,
            exit_code: None,
            user: "SYSTEM".to_owned(),
            integrity_level: IntegrityLevel::High,
            loaded_modules: Vec::new(),
            children: Vec::new(),
        });
        tree.add_process(ProcessNode {
            pid: 2000,
            parent_pid: 1000,
            name: "cmd.exe".to_owned(),
            command_line: "cmd.exe /c whoami".to_owned(),
            image_path: PathBuf::from("C:\\Windows\\cmd.exe"),
            start_time_ms: now_ms(),
            end_time_ms: None,
            exit_code: None,
            user: "SYSTEM".to_owned(),
            integrity_level: IntegrityLevel::High,
            loaded_modules: Vec::new(),
            children: Vec::new(),
        });

        assert_eq!(tree.process_count(), 2);
        assert_eq!(tree.max_depth(), 1);
        assert_eq!(tree.elevated_processes().len(), 2);
    }

    #[test]
    fn test_artifact_collector_summary() {
        let mut collector = ArtifactCollector::new();
        collector.record_dropped_file(
            PathBuf::from("C:\\Temp\\dropped.exe"),
            b"MZ\x90\x00more content here",
            true,
        );
        let summary = collector.summary();
        assert_eq!(summary.dropped_files, 1);
        assert_eq!(summary.executable_drops, 1);
    }
}
