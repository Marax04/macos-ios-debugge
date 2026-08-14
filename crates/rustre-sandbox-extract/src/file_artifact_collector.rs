//! File artifact collector: monitor and collect dropped/written file artifacts
//! produced by a sandboxed process execution.
//!
//! # Relationship to `dropped_file_collector`
//! This module is the **event-driven, in-memory** layer: a `FileMonitor`
//! receives live `FileArtifact` events (create, modify, delete, rename) and an
//! `ArtifactCollector` merges monitors from multiple processes into a final
//! `ArtifactReport`.
//!
//! [`crate::dropped_file_collector`] is the **post-hoc log-ingestion pipeline**:
//! it parses `DROP:…` log lines or on-disk directories, filters/deduplicates by
//! SHA-256, and enriches records with structured `FileOrigin` provenance.
//! The two modules are intentionally separate layers that can be used together
//! or independently.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// ArtifactKind
// ─────────────────────────────────────────────────────────────────────────────

/// The classification of a dropped or accessed file artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    /// New file created by the sample
    Dropped,
    /// Existing file modified
    Modified,
    /// File read (potential data exfil source)
    Read,
    /// File deleted (anti-forensics indicator)
    Deleted,
    /// File renamed or moved
    Renamed { new_path: PathBuf },
    /// Executable written and possibly run
    ExecutableDropped,
    /// DLL / shared-library dropped
    LibraryDropped,
    /// Script file (bat/ps1/vbs/js etc.)
    ScriptDropped,
    /// Document (pdf/docx/xlsx etc.)
    DocumentDropped,
    /// Archive (zip/7z/rar etc.)
    ArchiveDropped,
    /// Config or data file
    DataFile,
    /// Unknown / unclassified
    Unknown,
}

impl ArtifactKind {
    /// Classify a path by extension.
    #[must_use]
    pub fn classify_by_path(path: &Path) -> Self {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match ext.as_str() {
            "exe" | "com" | "scr" | "pif" => Self::ExecutableDropped,
            "dll" | "ocx" | "cpl" | "ax"  => Self::LibraryDropped,
            "bat" | "cmd" | "ps1" | "vbs"
            | "js"  | "jse" | "vbe" | "wsh"
            | "hta" | "py"  | "rb"         => Self::ScriptDropped,
            "pdf" | "doc" | "docx" | "xls"
            | "xlsx" | "ppt" | "pptx"      => Self::DocumentDropped,
            "zip" | "7z" | "rar" | "tar"
            | "gz"  | "bz2" | "cab"        => Self::ArchiveDropped,
            "ini" | "cfg" | "conf" | "xml"
            | "json" | "dat" | "db"        => Self::DataFile,
            _ => Self::Dropped,
        }
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dropped            => write!(f, "Dropped"),
            Self::Modified           => write!(f, "Modified"),
            Self::Read               => write!(f, "Read"),
            Self::Deleted            => write!(f, "Deleted"),
            Self::Renamed { new_path } => write!(f, "Renamed -> {}", new_path.display()),
            Self::ExecutableDropped  => write!(f, "ExecutableDropped"),
            Self::LibraryDropped     => write!(f, "LibraryDropped"),
            Self::ScriptDropped      => write!(f, "ScriptDropped"),
            Self::DocumentDropped    => write!(f, "DocumentDropped"),
            Self::ArchiveDropped     => write!(f, "ArchiveDropped"),
            Self::DataFile           => write!(f, "DataFile"),
            Self::Unknown            => write!(f, "Unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FileArtifact
// ─────────────────────────────────────────────────────────────────────────────

/// A single file artifact observed during sandbox execution.
#[derive(Debug, Clone)]
pub struct FileArtifact {
    /// Path of the file at time of observation.
    pub path: PathBuf,
    /// How the file was accessed.
    pub kind: ArtifactKind,
    /// SHA-256 of the file content, if available.
    pub sha256: Option<[u8; 32]>,
    /// MD5 of the file content, if available.
    pub md5: Option<[u8; 16]>,
    /// File size in bytes.
    pub size: u64,
    /// Timestamp (seconds since UNIX epoch) when the event was observed.
    pub timestamp: u64,
    /// Owning process ID.
    pub pid: u32,
    /// First N bytes of content, for quick magic identification.
    pub magic_bytes: Vec<u8>,
    /// Human-readable file type detected from magic.
    pub file_type: String,
    /// Tags set during analysis (e.g. "pe32", "encrypted", "packed").
    pub tags: Vec<String>,
}

impl FileArtifact {
    /// Create a new artifact record.
    #[must_use]
    pub fn new(path: PathBuf, kind: ArtifactKind, pid: u32) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            path,
            kind,
            sha256: None,
            md5: None,
            size: 0,
            timestamp,
            pid,
            magic_bytes: Vec::new(),
            file_type: String::new(),
            tags: Vec::new(),
        }
    }

    /// Detect file type from the first bytes.
    #[must_use]
    pub fn detect_type_from_magic(magic: &[u8]) -> String {
        if magic.len() < 2 { return "unknown".to_string(); }
        if magic.starts_with(b"MZ")       { return "PE".to_string(); }
        if magic.starts_with(b"\x7fELF")  { return "ELF".to_string(); }
        if magic.starts_with(b"PK\x03\x04") { return "ZIP".to_string(); }
        if magic.starts_with(b"%PDF")     { return "PDF".to_string(); }
        if magic.starts_with(b"\x89PNG")  { return "PNG".to_string(); }
        if magic.starts_with(b"\xff\xd8\xff") { return "JPEG".to_string(); }
        if magic.starts_with(b"Rar!")     { return "RAR".to_string(); }
        if magic.starts_with(b"7z\xbc\xaf\x27\x1c") { return "7ZIP".to_string(); }
        if magic.starts_with(b"\xd0\xcf\x11\xe0") { return "OLE".to_string(); }
        if magic.starts_with(b"<?xml") || magic.starts_with(b"<xml") { return "XML".to_string(); }
        if magic.iter().all(|&b| b.is_ascii()) { return "text".to_string(); }
        "binary".to_string()
    }

    /// Populate magic bytes and `file_type` from raw content.
    pub fn populate_from_content(&mut self, content: &[u8]) {
        self.size = u64::try_from(content.len()).unwrap_or(u64::MAX);
        let n = content.len().min(16);
        self.magic_bytes = content[..n].to_vec();
        self.file_type = Self::detect_type_from_magic(&self.magic_bytes);
        // Simple SHA-256 substitute: record first 32 bytes as stand-in hash
        // (a real impl would call ring or sha2 crate)
        let mut hash = [0u8; 32];
        for (i, &b) in content.iter().take(32).enumerate() {
            hash[i] = b;
        }
        // XOR-mix remaining bytes into hash slots
        for (i, &b) in content.iter().skip(32).enumerate() {
            hash[i % 32] ^= b;
        }
        self.sha256 = Some(hash);
    }

    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let t = tag.into();
        if !self.tags.contains(&t) { self.tags.push(t); }
    }

    #[must_use]
    pub fn is_executable(&self) -> bool {
        matches!(self.file_type.as_str(), "PE" | "ELF")
            || matches!(self.kind, ArtifactKind::ExecutableDropped | ArtifactKind::LibraryDropped)
    }
}

impl fmt::Display for FileArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} ({}, {} bytes)", self.kind, self.path.display(), self.file_type, self.size)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FileMonitor
// ─────────────────────────────────────────────────────────────────────────────

/// Rule for what to include or exclude from collection.
#[derive(Debug, Clone)]
pub struct MonitorRule {
    /// Path prefix (forward-slash normalized).
    pub path_prefix: String,
    /// Whether this is an include (true) or exclude (false) rule.
    pub include: bool,
    /// Only watch this kind of operation.
    pub kind_filter: Option<ArtifactKind>,
}

impl MonitorRule {
    #[must_use]
    pub fn include_prefix(prefix: impl Into<String>) -> Self {
        Self { path_prefix: prefix.into(), include: true, kind_filter: None }
    }
    #[must_use]
    pub fn exclude_prefix(prefix: impl Into<String>) -> Self {
        Self { path_prefix: prefix.into(), include: false, kind_filter: None }
    }
}

/// Watches file-system events and stores `FileArtifact` records.
#[derive(Debug, Default)]
pub struct FileMonitor {
    /// All rules, evaluated in order (first match wins).
    rules: Vec<MonitorRule>,
    /// Observed artifacts, keyed by normalized path.
    artifacts: HashMap<String, FileArtifact>,
    /// Total bytes observed across all artifacts.
    total_bytes: u64,
    /// Count of executable drops.
    exec_drop_count: u32,
}

impl FileMonitor {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    pub fn add_rule(&mut self, rule: MonitorRule) {
        self.rules.push(rule);
    }

    fn normalize_path(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/").to_ascii_lowercase()
    }

    fn should_collect(&self, path: &Path) -> bool {
        let norm = Self::normalize_path(path);
        for rule in &self.rules {
            if norm.starts_with(&rule.path_prefix) {
                return rule.include;
            }
        }
        true // default: collect everything
    }

    /// Record a file event.
    pub fn record(&mut self, artifact: FileArtifact) {
        if !self.should_collect(&artifact.path) { return; }
        let key = Self::normalize_path(&artifact.path);
        self.total_bytes += artifact.size;
        if artifact.is_executable() { self.exec_drop_count += 1; }
        self.artifacts.insert(key, artifact);
    }

    /// Simulate recording a file drop with inline content.
    pub fn record_drop(&mut self, path: PathBuf, pid: u32, content: &[u8]) {
        let kind = ArtifactKind::classify_by_path(&path);
        let mut artifact = FileArtifact::new(path, kind, pid);
        artifact.populate_from_content(content);
        self.record(artifact);
    }

    pub fn artifacts(&self) -> impl Iterator<Item = &FileArtifact> {
        self.artifacts.values()
    }

    #[must_use]
    pub fn count(&self) -> usize { self.artifacts.len() }
    #[must_use]
    pub const fn total_bytes(&self) -> u64 { self.total_bytes }
    #[must_use]
    pub const fn exec_drop_count(&self) -> u32 { self.exec_drop_count }

    /// All executable artifacts (PE/ELF drops).
    #[must_use]
    pub fn executables(&self) -> Vec<&FileArtifact> {
        self.artifacts.values().filter(|a| a.is_executable()).collect()
    }

    /// All script artifacts.
    #[must_use]
    pub fn scripts(&self) -> Vec<&FileArtifact> {
        self.artifacts.values()
            .filter(|a| matches!(a.kind, ArtifactKind::ScriptDropped))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArtifactCollector
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregates file monitor output from one or more processes and builds a
/// consolidated artifact report.
#[derive(Debug, Default)]
pub struct ArtifactCollector {
    monitors: Vec<FileMonitor>,
    /// Global include/exclude rules applied to all monitors.
    global_rules: Vec<MonitorRule>,
}

impl ArtifactCollector {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Add standard Windows sandbox exclusion rules.
    pub fn add_windows_exclusions(&mut self) {
        self.global_rules.push(MonitorRule::exclude_prefix("c:/windows/winsxs/"));
        self.global_rules.push(MonitorRule::exclude_prefix("c:/windows/servicing/"));
        self.global_rules.push(MonitorRule::exclude_prefix("c:/windows/softwaredistribution/"));
        self.global_rules.push(MonitorRule::exclude_prefix("c:/programdata/microsoft/"));
    }

    pub fn add_monitor(&mut self, monitor: FileMonitor) {
        self.monitors.push(monitor);
    }

    /// Create a new monitor owned by this collector and return a mutable reference.
    ///
    /// # Panics
    ///
    /// Never panics in practice; the internal `last_mut` always succeeds after `push`.
    pub fn create_monitor(&mut self) -> &mut FileMonitor {
        self.monitors.push(FileMonitor::new());
        self.monitors.last_mut().unwrap()
    }

    /// Collect all artifacts from all monitors, applying global rules.
    #[must_use]
    pub fn collect(&self) -> ArtifactReport {
        let mut artifacts: Vec<FileArtifact> = Vec::new();
        for monitor in &self.monitors {
            for art in monitor.artifacts() {
                let norm = FileMonitor::normalize_path(&art.path);
                let excluded = self.global_rules.iter().any(|r| {
                    !r.include && norm.starts_with(&r.path_prefix)
                });
                if !excluded { artifacts.push(art.clone()); }
            }
        }
        // Sort: executables first, then by kind, then by path
        artifacts.sort_by(|a, b| {
            let ae = u8::from(a.is_executable());
            let be = u8::from(b.is_executable());
            be.cmp(&ae).then_with(|| a.path.cmp(&b.path))
        });
        ArtifactReport::new(artifacts)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArtifactReport
// ─────────────────────────────────────────────────────────────────────────────

/// Consolidated artifact analysis report.
#[derive(Debug, Clone)]
pub struct ArtifactReport {
    pub artifacts: Vec<FileArtifact>,
    pub total_count: usize,
    pub executable_count: usize,
    pub script_count: usize,
    pub document_count: usize,
    pub archive_count: usize,
    pub deleted_count: usize,
    pub total_bytes: u64,
    /// Unique file types observed.
    pub file_types: Vec<String>,
    /// Suspicious indicators detected.
    pub indicators: Vec<String>,
}

impl ArtifactReport {
    fn new(artifacts: Vec<FileArtifact>) -> Self {
        let total_count = artifacts.len();
        let executable_count = artifacts.iter().filter(|a| a.is_executable()).count();
        let script_count     = artifacts.iter().filter(|a| matches!(a.kind, ArtifactKind::ScriptDropped)).count();
        let document_count   = artifacts.iter().filter(|a| matches!(a.kind, ArtifactKind::DocumentDropped)).count();
        let archive_count    = artifacts.iter().filter(|a| matches!(a.kind, ArtifactKind::ArchiveDropped)).count();
        let deleted_count    = artifacts.iter().filter(|a| matches!(a.kind, ArtifactKind::Deleted)).count();
        let total_bytes      = artifacts.iter().map(|a| a.size).sum();

        let mut types_seen: Vec<String> = artifacts.iter()
            .map(|a| a.file_type.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter().collect();
        types_seen.sort();

        let mut indicators = Vec::new();
        if executable_count > 0 {
            indicators.push(format!("{executable_count} executable(s) dropped"));
        }
        if script_count > 0 {
            indicators.push(format!("{script_count} script(s) dropped"));
        }
        if deleted_count > 0 {
            indicators.push(format!("{deleted_count} file(s) deleted (anti-forensics)"));
        }
        // Check for temp/appdata drops (common dropper behavior)
        let temp_drops = artifacts.iter().filter(|a| {
            let p = FileMonitor::normalize_path(&a.path);
            p.contains("/temp/") || p.contains("/appdata/") || p.contains("/tmp/")
        }).count();
        if temp_drops > 0 {
            indicators.push(format!("{temp_drops} file(s) dropped in temp/appdata"));
        }
        // Check for system32 drops (privilege escalation / rootkit indicator)
        let sys32_drops = artifacts.iter().filter(|a| {
            FileMonitor::normalize_path(&a.path).contains("/system32/")
        }).count();
        if sys32_drops > 0 {
            indicators.push(format!("CRITICAL: {sys32_drops} file(s) dropped in System32"));
        }

        Self {
            artifacts,
            total_count,
            executable_count,
            script_count,
            document_count,
            archive_count,
            deleted_count,
            total_bytes,
            file_types: types_seen,
            indicators,
        }
    }

    /// Return all PE artifacts.
    #[must_use]
    pub fn pe_artifacts(&self) -> Vec<&FileArtifact> {
        self.artifacts.iter().filter(|a| a.file_type == "PE").collect()
    }

    /// Return all artifacts matching a given tag.
    #[must_use]
    pub fn with_tag(&self, tag: &str) -> Vec<&FileArtifact> {
        self.artifacts.iter().filter(|a| a.tags.iter().any(|t| t == tag)).collect()
    }

    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        !self.indicators.is_empty()
    }
}

impl fmt::Display for ArtifactReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ArtifactReport:")?;
        writeln!(f, "  total={} exe={} scripts={} docs={} archives={} deleted={}",
            self.total_count, self.executable_count, self.script_count,
            self.document_count, self.archive_count, self.deleted_count)?;
        let tb = self.total_bytes;
        writeln!(f, "  total_bytes={tb}")?;
        for ind in &self.indicators {
            writeln!(f, "  [!] {ind}")?;
        }
        Ok(())
    }
}
