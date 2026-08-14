// file_tracker.rs — File operation tracker for sandbox monitoring
// Tracks create/read/write/delete/rename/move operations on files.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// File operation type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FileOperation {
    Create,
    Open,
    Read,
    Write,
    Append,
    Delete,
    Rename,
    Move,
    SetAttributes,
    GetAttributes,
    Lock,
    Unlock,
    Close,
    Flush,
    Truncate,
    CreateSymlink,
    CreateHardlink,
}

impl FileOperation {
    #[must_use] 
    pub const fn is_write(&self) -> bool {
        matches!(self,
            Self::Create | Self::Write | Self::Append |
            Self::Delete | Self::Rename | Self::Move |
            Self::Truncate | Self::CreateSymlink |
            Self::CreateHardlink | Self::SetAttributes
        )
    }

    #[must_use] 
    pub const fn is_read(&self) -> bool {
        matches!(self, Self::Read | Self::GetAttributes | Self::Open)
    }
}

impl std::fmt::Display for FileOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// File content snapshot (first/last N bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FileContent {
    /// First `cap` bytes written/read
    pub head: Vec<u8>,
    /// Last `cap` bytes written/read
    pub tail: Vec<u8>,
    pub total_bytes: u64,
    pub cap: usize,
}

impl FileContent {
    #[must_use] 
    pub const fn new(cap: usize) -> Self {
        Self { head: Vec::new(), tail: Vec::new(), total_bytes: 0, cap }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.total_bytes += data.len() as u64;
        let want = self.cap;
        if self.head.len() < want {
            let take = (want - self.head.len()).min(data.len());
            self.head.extend_from_slice(&data[..take]);
        }
        // Keep the last `cap` bytes in tail
        let tail_data = if data.len() >= want { &data[data.len() - want..] } else { data };
        if self.tail.len() + tail_data.len() > want {
            let keep = want.saturating_sub(tail_data.len());
            let drain = self.tail.len().saturating_sub(keep);
            self.tail.drain(..drain);
        }
        self.tail.extend_from_slice(tail_data);
    }

    #[must_use] 
    pub fn is_pe(&self) -> bool {
        self.head.starts_with(b"MZ")
    }

    #[must_use] 
    pub fn is_elf(&self) -> bool {
        self.head.starts_with(b"\x7FELF")
    }

    #[must_use] 
    pub fn is_zip(&self) -> bool {
        self.head.starts_with(b"PK\x03\x04") || self.head.starts_with(b"PK\x05\x06")
    }
}

// ---------------------------------------------------------------------------
// Suspicious extension check
// ---------------------------------------------------------------------------

#[must_use] 
pub fn suspicious_extension_check(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_str()?.to_lowercase();
    match ext.as_str() {
        "exe" | "dll" | "sys" | "drv" => Some("Executable"),
        "bat" | "cmd" | "ps1" | "vbs" | "js" | "wsf" | "hta" => Some("Script"),
        "lnk" | "url" | "pif" => Some("Shortcut/Launcher"),
        "jar" | "class" => Some("Java"),
        "scr" => Some("Screensaver (often malware)"),
        "cpl" => Some("Control Panel Extension"),
        "inf" => Some("Setup Information"),
        "reg" => Some("Registry Export"),
        "tmp" | "dat" => Some("Temp/Data (often dropped payloads)"),
        _ => None,
    }
}

/// Return true if `path` is in a suspicious location (temp, appdata, recycle bin, etc.)
#[must_use] 
pub fn is_suspicious_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    let suspicious_dirs = [
        "\\temp\\",
        "\\tmp\\",
        "\\appdata\\roaming\\",
        "\\appdata\\local\\temp\\",
        "%temp%",
        "\\$recycle.bin\\",
        "\\windows\\temp\\",
        "\\users\\public\\",
        "\\programdata\\",
    ];
    suspicious_dirs.iter().any(|d| path_str.contains(d))
}

// ---------------------------------------------------------------------------
// FilePath wrapper with metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FilePath {
    pub path: PathBuf,
    pub canonical: String,
}

impl FilePath {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let p: PathBuf = path.into();
        let canonical = p.to_string_lossy().to_lowercase();
        Self { path: p, canonical }
    }

    #[must_use] 
    pub fn extension(&self) -> Option<&str> {
        self.path.extension()?.to_str()
    }

    #[must_use] 
    pub fn filename(&self) -> Option<&str> {
        self.path.file_name()?.to_str()
    }

    #[must_use] 
    pub fn parent_dir(&self) -> Option<&Path> {
        self.path.parent()
    }
}

// ---------------------------------------------------------------------------
// File tracker entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub id: u64,
    pub operation: FileOperation,
    pub path: FilePath,
    pub dest_path: Option<FilePath>,   // for rename/move
    pub bytes_transferred: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub timestamp_ns: u64,
    pub result_code: u32,
    pub handle: u64,
    pub content_snapshot: Option<FileContent>,
}

impl FileEntry {
    #[must_use] 
    pub const fn new(
        id: u64,
        operation: FileOperation,
        path: FilePath,
        bytes: u64,
        pid: u32,
        tid: u32,
        ts: u64,
        result: u32,
    ) -> Self {
        Self {
            id,
            operation,
            path,
            dest_path: None,
            bytes_transferred: bytes,
            process_id: pid,
            thread_id: tid,
            timestamp_ns: ts,
            result_code: result,
            handle: 0,
            content_snapshot: None,
        }
    }

    #[must_use] 
    pub const fn is_success(&self) -> bool { self.result_code == 0 }

    #[must_use] 
    pub fn format(&self) -> String {
        let dest = self.dest_path.as_ref()
            .map(|d| format!(" -> {}", d.path.display()))
            .unwrap_or_default();
        format!(
            "[{:6}] {} {}{} [{} bytes, PID:{}, result:0x{:08X}]",
            self.id,
            self.operation,
            self.path.path.display(),
            dest,
            self.bytes_transferred,
            self.process_id,
            self.result_code,
        )
    }
}

// ---------------------------------------------------------------------------
// File statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct FileStats {
    pub total_ops: u64,
    pub creates: u64,
    pub reads: u64,
    pub writes: u64,
    pub deletes: u64,
    pub renames: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub failed_ops: u64,
    pub suspicious_files: u64,
    pub unique_paths: HashSet<String>,
}

impl FileStats {
    pub fn update(&mut self, entry: &FileEntry) {
        self.total_ops += 1;
        match entry.operation {
            FileOperation::Create => self.creates += 1,
            FileOperation::Read   => { self.reads += 1; self.bytes_read += entry.bytes_transferred; }
            FileOperation::Write | FileOperation::Append => {
                self.writes += 1;
                self.bytes_written += entry.bytes_transferred;
            }
            FileOperation::Delete => self.deletes += 1,
            FileOperation::Rename | FileOperation::Move => self.renames += 1,
            _ => {}
        }
        if !entry.is_success() { self.failed_ops += 1; }
        if suspicious_extension_check(&entry.path.path).is_some()
            || is_suspicious_path(&entry.path.path)
        {
            self.suspicious_files += 1;
        }
        self.unique_paths.insert(entry.path.canonical.clone());
    }
}

// ---------------------------------------------------------------------------
// FileTracker
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct FileTracker {
    pub entries: Vec<FileEntry>,
    pub stats: FileStats,
    pub next_id: u64,
    pub max_entries: usize,
    /// Maps open handle -> path
    pub open_handles: HashMap<u64, FilePath>,
    /// Per-file write content accumulators
    pub content_accum: HashMap<String, FileContent>,
    pub content_cap: usize,
}

impl FileTracker {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            stats: FileStats::default(),
            next_id: 1,
            max_entries: 200_000,
            open_handles: HashMap::new(),
            content_accum: HashMap::new(),
            content_cap: 256,
        }
    }

    #[must_use] 
    pub const fn with_max_entries(mut self, n: usize) -> Self {
        self.max_entries = n;
        self
    }

    #[must_use] 
    pub const fn with_content_cap(mut self, cap: usize) -> Self {
        self.content_cap = cap;
        self
    }

    /// Record a file event.
    pub fn record(
        &mut self,
        operation: FileOperation,
        path: FilePath,
        dest_path: Option<FilePath>,
        bytes: u64,
        pid: u32,
        tid: u32,
        timestamp_ns: u64,
        result: u32,
        handle: u64,
    ) {
        let id = self.next_id;
        self.next_id += 1;

        let mut entry = FileEntry::new(id, operation.clone(), path.clone(), bytes, pid, tid, timestamp_ns, result);
        entry.dest_path = dest_path;
        entry.handle = handle;

        // Track open handles
        match operation {
            FileOperation::Create | FileOperation::Open => {
                if handle != 0 {
                    self.open_handles.insert(handle, path);
                }
            }
            FileOperation::Close => {
                self.open_handles.remove(&handle);
            }
            _ => {}
        }

        self.stats.update(&entry);

        if self.entries.len() < self.max_entries {
            self.entries.push(entry);
        }
    }

    /// Feed content bytes for a file path (e.g. from a write hook).
    pub fn feed_content(&mut self, path: &FilePath, data: &[u8]) {
        let cap = self.content_cap;
        self.content_accum
            .entry(path.canonical.clone())
            .or_insert_with(|| FileContent::new(cap))
            .feed(data);
    }

    /// Return content snapshot for a path.
    #[must_use] 
    pub fn content_for(&self, path: &FilePath) -> Option<&FileContent> {
        self.content_accum.get(&path.canonical)
    }

    /// Filter entries.
    pub fn filter<F: Fn(&FileEntry) -> bool>(&self, pred: F) -> Vec<&FileEntry> {
        self.entries.iter().filter(|e| pred(e)).collect()
    }

    /// Return writes only.
    #[must_use] 
    pub fn writes(&self) -> Vec<&FileEntry> {
        self.filter(|e| e.operation.is_write())
    }

    /// Return deletes only.
    #[must_use] 
    pub fn deletes(&self) -> Vec<&FileEntry> {
        self.filter(|e| e.operation == FileOperation::Delete)
    }

    /// Return all entries for a given path.
    #[must_use] 
    pub fn ops_on(&self, path: &FilePath) -> Vec<&FileEntry> {
        self.filter(|e| e.path.canonical == path.canonical)
    }

    /// Detect suspicious activity.
    #[must_use] 
    pub fn detect_suspicious(&self) -> Vec<FileSuspicion> {
        let mut findings = Vec::new();

        // Mass file deletions (ransomware cleanup, wiper)
        if self.stats.deletes > 100 {
            findings.push(FileSuspicion {
                kind: FileSuspicionKind::Wiper,
                description: format!("{} file deletions observed — possible wiper", self.stats.deletes),
                severity: FileSuspicionSeverity::Critical,
                paths: self.deletes().iter().take(5).map(|e| e.path.path.display().to_string()).collect(),
            });
        }

        // Executable dropped in temp/appdata
        let dropped_exes: Vec<&FileEntry> = self.entries.iter().filter(|e| {
            e.operation == FileOperation::Create
                && suspicious_extension_check(&e.path.path).is_some()
                && is_suspicious_path(&e.path.path)
        }).collect();
        if !dropped_exes.is_empty() {
            findings.push(FileSuspicion {
                kind: FileSuspicionKind::DroppedExecutable,
                description: format!(
                    "{} executable(s) created in suspicious directories",
                    dropped_exes.len()
                ),
                severity: FileSuspicionSeverity::High,
                paths: dropped_exes.iter().map(|e| e.path.path.display().to_string()).collect(),
            });
        }

        // High-frequency writes to many unique files (ransomware encryption)
        if self.stats.writes > 200 && self.stats.unique_paths.len() > 100 {
            findings.push(FileSuspicion {
                kind: FileSuspicionKind::MassEncryption,
                description: format!(
                    "{} writes to {} unique files — possible ransomware",
                    self.stats.writes,
                    self.stats.unique_paths.len()
                ),
                severity: FileSuspicionSeverity::Critical,
                paths: Vec::new(),
            });
        }

        // Self-deletion attempt
        let self_del = self.entries.iter().any(|e| {
            e.operation == FileOperation::Delete
                && e.path.path.extension().is_some_and(|x| x == "exe")
        });
        if self_del {
            findings.push(FileSuspicion {
                kind: FileSuspicionKind::SelfDeletion,
                description: "Deletion of an executable file observed (possible self-deletion)".to_string(),
                severity: FileSuspicionSeverity::Medium,
                paths: Vec::new(),
            });
        }

        findings
    }

    /// Summary report string.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "FileTracker: {} ops, {} creates, {} reads, {} writes, {} deletes, {} renames | {} bytes read, {} bytes written | {} unique paths",
            self.stats.total_ops,
            self.stats.creates,
            self.stats.reads,
            self.stats.writes,
            self.stats.deletes,
            self.stats.renames,
            self.stats.bytes_read,
            self.stats.bytes_written,
            self.stats.unique_paths.len(),
        )
    }
}

impl Default for FileTracker {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Suspicion types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FileSuspicion {
    pub kind: FileSuspicionKind,
    pub description: String,
    pub severity: FileSuspicionSeverity,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileSuspicionKind {
    Wiper,
    DroppedExecutable,
    MassEncryption,
    SelfDeletion,
    SuspiciousLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileSuspicionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_path(s: &str) -> FilePath {
        FilePath::new(s)
    }

    fn record_op(tracker: &mut FileTracker, op: FileOperation, path: &str, bytes: u64, result: u32) {
        tracker.record(op, make_path(path), None, bytes, 100, 200, 0, result, 0);
    }

    #[test]
    fn test_suspicious_extension() {
        assert_eq!(suspicious_extension_check(Path::new("evil.exe")), Some("Executable"));
        assert_eq!(suspicious_extension_check(Path::new("script.ps1")), Some("Script"));
        assert_eq!(suspicious_extension_check(Path::new("readme.txt")), None);
    }

    #[test]
    fn test_is_suspicious_path() {
        assert!(is_suspicious_path(Path::new("C:\\Windows\\Temp\\payload.exe")));
        assert!(is_suspicious_path(Path::new("C:\\Users\\user\\AppData\\Roaming\\malware.dll")));
        assert!(!is_suspicious_path(Path::new("C:\\Program Files\\Firefox\\firefox.exe")));
    }

    #[test]
    fn test_file_content_feed() {
        let mut fc = FileContent::new(4);
        fc.feed(b"ABCDEFGH");
        assert_eq!(fc.head, b"ABCD");
        assert_eq!(fc.tail, b"EFGH");
        assert_eq!(fc.total_bytes, 8);
    }

    #[test]
    fn test_file_content_is_pe() {
        let mut fc = FileContent::new(16);
        fc.feed(b"MZ\x90\x00");
        assert!(fc.is_pe());
    }

    #[test]
    fn test_file_content_is_elf() {
        let mut fc = FileContent::new(16);
        fc.feed(b"\x7FELF\x02\x01\x01\x00");
        assert!(fc.is_elf());
    }

    #[test]
    fn test_tracker_record_write() {
        let mut tracker = FileTracker::new();
        record_op(&mut tracker, FileOperation::Write, "C:\\test.txt", 1024, 0);
        assert_eq!(tracker.stats.total_ops, 1);
        assert_eq!(tracker.stats.writes, 1);
        assert_eq!(tracker.stats.bytes_written, 1024);
    }

    #[test]
    fn test_tracker_record_delete() {
        let mut tracker = FileTracker::new();
        record_op(&mut tracker, FileOperation::Delete, "C:\\foo.exe", 0, 0);
        assert_eq!(tracker.stats.deletes, 1);
    }

    #[test]
    fn test_tracker_filter_writes() {
        let mut tracker = FileTracker::new();
        record_op(&mut tracker, FileOperation::Write, "C:\\a.txt", 100, 0);
        record_op(&mut tracker, FileOperation::Read, "C:\\b.txt", 50, 0);
        let writes = tracker.writes();
        assert_eq!(writes.len(), 1);
    }

    #[test]
    fn test_tracker_ops_on() {
        let mut tracker = FileTracker::new();
        record_op(&mut tracker, FileOperation::Create, "C:\\file.dat", 0, 0);
        record_op(&mut tracker, FileOperation::Write, "C:\\file.dat", 100, 0);
        record_op(&mut tracker, FileOperation::Read, "C:\\other.dat", 50, 0);
        let ops = tracker.ops_on(&make_path("C:\\file.dat"));
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn test_detect_self_deletion() {
        let mut tracker = FileTracker::new();
        record_op(&mut tracker, FileOperation::Delete, "C:\\malware.exe", 0, 0);
        let findings = tracker.detect_suspicious();
        assert!(findings.iter().any(|f| f.kind == FileSuspicionKind::SelfDeletion));
    }

    #[test]
    fn test_detect_wiper() {
        let mut tracker = FileTracker::new();
        for i in 0..150 {
            record_op(&mut tracker, FileOperation::Delete, &format!("C:\\doc{}.docx", i), 0, 0);
        }
        let findings = tracker.detect_suspicious();
        assert!(findings.iter().any(|f| f.kind == FileSuspicionKind::Wiper));
    }

    #[test]
    fn test_content_accumulate_and_retrieve() {
        let mut tracker = FileTracker::new().with_content_cap(8);
        let fp = make_path("C:\\payload.bin");
        tracker.feed_content(&fp, b"AAAABBBB");
        let snap = tracker.content_for(&fp).unwrap();
        assert_eq!(snap.total_bytes, 8);
        assert!(snap.head.starts_with(b"AAAA"));
    }

    #[test]
    fn test_file_operation_classification() {
        assert!(FileOperation::Write.is_write());
        assert!(FileOperation::Read.is_read());
        assert!(!FileOperation::Read.is_write());
        assert!(FileOperation::Delete.is_write());
    }

    #[test]
    fn test_file_entry_format() {
        let path = make_path("C:\\windows\\system32\\calc.exe");
        let e = FileEntry::new(1, FileOperation::Write, path, 2048, 1, 2, 0, 0);
        let s = e.format();
        assert!(s.contains("Write"));
        assert!(s.contains("calc.exe"));
        assert!(s.contains("2048 bytes"));
    }

    #[test]
    fn test_handle_tracking() {
        let mut tracker = FileTracker::new();
        let fp = make_path("C:\\data.bin");
        tracker.record(FileOperation::Create, fp.clone(), None, 0, 1, 2, 0, 0, 0xABCD);
        assert!(tracker.open_handles.contains_key(&0xABCD));
        tracker.record(FileOperation::Close, fp, None, 0, 1, 2, 1000, 0, 0xABCD);
        assert!(!tracker.open_handles.contains_key(&0xABCD));
    }
}
