//! `dropped_file_collector` — Collect and classify files dropped to disk by
//! a sandboxed process.
//!
//! Provides [`DroppedFileCollector`] which ingests raw sandbox event streams
//! or report directories, deduplicates entries, infers file types from magic
//! bytes, and builds structured [`DroppedFile`] records with enriched metadata.
//!
//! # Relationship to `file_artifact_collector`
//! [`crate::file_artifact_collector`] is the **event-driven, in-memory**
//! file-monitor layer: it receives real-time `FileArtifact` events from a
//! `FileMonitor` and aggregates them into an `ArtifactReport`.
//!
//! This module is the **post-hoc collection pipeline**: it ingests structured
//! log lines (`DROP:…`) or on-disk directories, applies configurable size/path/
//! extension filters, deduplicates by SHA-256, and tracks rich `FileOrigin`
//! provenance (direct write, `LOLBin`, download, archive extraction, memory dump).
//! The two layers are intentionally distinct and complement each other.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors that can occur while collecting dropped files.
#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("io error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("duplicate sha256: {0}")]
    Duplicate(String),
}

// ─── FileOrigin ───────────────────────────────────────────────────────────────

/// How a dropped file came to be on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOrigin {
    /// Written directly by the malware process.
    DirectWrite {
        /// PID of the writing process.
        pid: u32,
        /// Win32 API used (e.g. `"WriteFile"`, `"NtWriteFile"`).
        api: String,
    },
    /// Decoded from Base64/hex embedded in a script or document.
    DecodedPayload {
        /// Script or document that contained the encoded data.
        source_path: String,
    },
    /// Downloaded from a remote URL.
    Downloaded {
        /// Source URL.
        url: String,
        /// HTTP status code, if known.
        status_code: Option<u16>,
    },
    /// Extracted from an archive (ZIP, CAB, RAR, etc.).
    ExtractedFromArchive {
        /// Path to the outer archive.
        archive_path: String,
    },
    /// Injected PE section dumped to disk during analysis.
    MemoryDump {
        /// PID of the process whose memory was dumped.
        pid: u32,
        /// Virtual address of the dumped region.
        va: u64,
    },
    /// Dropped by a `LOLBin` (e.g. `certutil`, `bitsadmin`).
    LolBin {
        /// The `LOLBin` name.
        tool: String,
    },
    /// Origin could not be determined.
    Unknown,
}

impl fmt::Display for FileOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectWrite { pid, api } => write!(f, "write(pid={pid}, api={api})"),
            Self::DecodedPayload { source_path } => write!(f, "decoded_from({source_path})"),
            Self::Downloaded { url, .. } => write!(f, "downloaded({url})"),
            Self::ExtractedFromArchive { archive_path } => {
                write!(f, "extracted_from({archive_path})")
            }
            Self::MemoryDump { pid, va } => write!(f, "memdump(pid={pid}, va={va:#x})"),
            Self::LolBin { tool } => write!(f, "lolbin({tool})"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── MagicKind ────────────────────────────────────────────────────────────────

/// File type inferred from magic bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MagicKind {
    /// Windows PE executable (EXE/DLL/SYS).
    Pe,
    /// ELF binary.
    Elf,
    /// ZIP archive (includes DOCX/XLSX/PPTX/APK/JAR).
    Zip,
    /// 7-Zip archive.
    SevenZip,
    /// RAR archive.
    Rar,
    /// MS Cabinet.
    Cabinet,
    /// PDF document.
    Pdf,
    /// Windows Script Host script.
    Wsh,
    /// `PowerShell` script (text-based; detected by extension).
    Powershell,
    /// Batch script (text-based; detected by extension).
    Batch,
    /// `VBScript` (text-based; detected by extension).
    Vbs,
    /// JavaScript (text-based; detected by extension).
    Javascript,
    /// XML document.
    Xml,
    /// Bitmap image.
    Bmp,
    /// PNG image.
    Png,
    /// JPEG image.
    Jpeg,
    /// Unknown / binary blob.
    Unknown,
}

impl MagicKind {
    /// Infer the file type from the first bytes and optional extension hint.
    #[must_use]
    pub fn detect(header: &[u8], ext: &str) -> Self {
        // Magic-byte checks take priority.
        if header.starts_with(&[0x4d, 0x5a]) {
            return Self::Pe;
        }
        if header.starts_with(&[0x7f, b'E', b'L', b'F']) {
            return Self::Elf;
        }
        if header.starts_with(&[0x50, 0x4b, 0x03, 0x04])
            || header.starts_with(&[0x50, 0x4b, 0x05, 0x06])
        {
            return Self::Zip;
        }
        if header.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
            return Self::SevenZip;
        }
        if header.starts_with(b"Rar!") {
            return Self::Rar;
        }
        if header.starts_with(b"MSCF") {
            return Self::Cabinet;
        }
        if header.starts_with(b"%PDF") {
            return Self::Pdf;
        }
        if header.starts_with(&[0xff, 0xd8, 0xff]) {
            return Self::Jpeg;
        }
        if header.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
            return Self::Png;
        }
        if header.starts_with(b"BM") {
            return Self::Bmp;
        }
        if header.starts_with(b"<?xml") || header.starts_with(b"<xml") {
            return Self::Xml;
        }

        // Extension fallback.
        match ext.to_ascii_lowercase().as_str() {
            "ps1" => Self::Powershell,
            "bat" | "cmd" => Self::Batch,
            "vbs" | "vbe" => Self::Vbs,
            "js" | "jse" => Self::Javascript,
            "wsh" | "wsf" | "hta" => Self::Wsh,
            "xml" => Self::Xml,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this kind is considered executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        matches!(
            self,
            Self::Pe
                | Self::Elf
                | Self::Powershell
                | Self::Batch
                | Self::Vbs
                | Self::Javascript
                | Self::Wsh
        )
    }

    /// Returns a human-readable MIME-like label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Pe => "application/x-dosexec",
            Self::Elf => "application/x-elf",
            Self::Zip => "application/zip",
            Self::SevenZip => "application/x-7z-compressed",
            Self::Rar => "application/x-rar-compressed",
            Self::Cabinet => "application/vnd.ms-cab-compressed",
            Self::Pdf => "application/pdf",
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::Bmp => "image/bmp",
            Self::Xml => "text/xml",
            Self::Powershell => "text/x-powershell",
            Self::Batch => "text/x-batch",
            Self::Vbs => "text/vbscript",
            Self::Javascript => "text/javascript",
            Self::Wsh => "text/x-wsh",
            Self::Unknown => "application/octet-stream",
        }
    }
}

impl fmt::Display for MagicKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ─── DroppedFile ──────────────────────────────────────────────────────────────

/// A file dropped to disk by the sandboxed process, enriched with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedFile {
    /// Path on the guest filesystem.
    pub path: String,
    /// File size in bytes.
    pub size: usize,
    /// SHA-256 hex digest of the file contents.
    pub sha256: String,
    /// MD5 hex digest (may be empty if not computed).
    pub md5: String,
    /// First 64 bytes of the file for magic detection.
    pub header: Vec<u8>,
    /// Inferred file type.
    pub kind: MagicKind,
    /// MIME type label derived from `kind`.
    pub mime: String,
    /// Shannon entropy of the header bytes (approximate indicator of encryption).
    pub header_entropy: f64,
    /// Milliseconds since execution start when the file was first seen.
    pub first_seen_ms: u64,
    /// PID that created the file.
    pub pid: u32,
    /// Structured origin record.
    pub origin: FileOrigin,
    /// Tags assigned during enrichment (e.g. `"packer"`, `"config"`, `"lolbin"`).
    pub tags: Vec<String>,
}

impl DroppedFile {
    /// Create a new dropped file record from minimal fields.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        size: usize,
        sha256: impl Into<String>,
        pid: u32,
        origin: FileOrigin,
    ) -> Self {
        Self {
            path: path.into(),
            size,
            sha256: sha256.into(),
            md5: String::new(),
            header: Vec::new(),
            kind: MagicKind::Unknown,
            mime: MagicKind::Unknown.label().to_string(),
            header_entropy: 0.0,
            first_seen_ms: 0,
            pid,
            origin,
            tags: Vec::new(),
        }
    }

    /// Set the file header bytes and re-detect the magic kind.
    pub fn set_header(&mut self, header: Vec<u8>) {
        let ext = self.extension().to_ascii_lowercase();
        self.kind = MagicKind::detect(&header, &ext);
        self.mime = self.kind.label().to_string();
        self.header_entropy = entropy(&header);
        self.header = header;
    }

    /// Return the file extension (lowercase, without leading dot).
    #[must_use]
    pub fn extension(&self) -> &str {
        if let Some(pos) = self.path.rfind('.') {
            &self.path[pos + 1..]
        } else {
            ""
        }
    }

    /// Return the file name component of the path (after last `\` or `/`).
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(self.path.as_str())
    }

    /// Return `true` if the file is an executable type.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.kind.is_executable()
    }

    /// Return `true` if the header entropy exceeds 7.0 (likely encrypted/packed).
    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.header_entropy > 7.0
    }

    /// Add a tag to this file if not already present.
    pub fn tag(&mut self, t: impl Into<String>) {
        let s = t.into();
        if !self.tags.contains(&s) {
            self.tags.push(s);
        }
    }

    /// Return `true` if this file has the given tag.
    #[must_use]
    pub fn has_tag(&self, t: &str) -> bool {
        self.tags.iter().any(|tag| tag == t)
    }
}

// ─── CollectorConfig ──────────────────────────────────────────────────────────

/// Configuration for the dropped-file collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorConfig {
    /// Minimum file size in bytes to include (smaller files are skipped).
    pub min_size: usize,
    /// Maximum file size in bytes to include (larger files are skipped).
    pub max_size: usize,
    /// Paths containing these substrings are excluded (case-insensitive).
    pub exclude_path_fragments: Vec<String>,
    /// Path must contain one of these substrings (empty = no filter).
    pub include_path_fragments: Vec<String>,
    /// Only include files matching these extensions (empty = all).
    pub include_extensions: Vec<String>,
    /// Deduplicate by SHA-256.
    pub dedup_by_hash: bool,
    /// Automatically tag PE files with `"pe"`.
    pub auto_tag_pe: bool,
    /// Automatically tag high-entropy files with `"encrypted"`.
    pub auto_tag_high_entropy: bool,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            min_size: 0,
            max_size: 256 * 1024 * 1024, // 256 MiB
            exclude_path_fragments: vec![
                "\\Windows\\Temp\\~".to_string(),
                "thumbs.db".to_string(),
                "desktop.ini".to_string(),
            ],
            include_path_fragments: Vec::new(),
            include_extensions: Vec::new(),
            dedup_by_hash: true,
            auto_tag_pe: true,
            auto_tag_high_entropy: true,
        }
    }
}

// ─── CollectorStats ───────────────────────────────────────────────────────────

/// Statistics accumulated during collection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollectorStats {
    /// Total records processed (before filtering).
    pub total_seen: usize,
    /// Records excluded by size filter.
    pub excluded_size: usize,
    /// Records excluded by path filter.
    pub excluded_path: usize,
    /// Records excluded by extension filter.
    pub excluded_ext: usize,
    /// Records deduplicated (hash already seen).
    pub deduped: usize,
    /// Final number of accepted records.
    pub accepted: usize,
}

impl CollectorStats {
    /// Total number of excluded records.
    #[must_use]
    pub const fn total_excluded(&self) -> usize {
        self.excluded_size + self.excluded_path + self.excluded_ext + self.deduped
    }
}

// ─── DroppedFileCollector ─────────────────────────────────────────────────────

/// Collects, filters, deduplicates, and enriches files dropped to disk during
/// sandbox execution.
///
/// # Example
/// ```rust,no_run
/// # use rustre_sandbox_extract::dropped_file_collector::*;
/// let mut collector = DroppedFileCollector::new(CollectorConfig::default());
/// collector.ingest_raw("DROP:/tmp/payload.exe:deadbeef:4096:1000:write:WriteFile");
/// let files = collector.collect();
/// ```
#[derive(Debug)]
pub struct DroppedFileCollector {
    config: CollectorConfig,
    /// Accumulated file records before deduplication.
    pending: Vec<DroppedFile>,
    /// SHA-256 hashes already emitted (for deduplication).
    seen_hashes: HashSet<String>,
    /// Statistics accumulated during this session.
    stats: CollectorStats,
}

impl DroppedFileCollector {
    /// Create a new collector with the given configuration.
    #[must_use]
    pub fn new(config: CollectorConfig) -> Self {
        Self {
            config,
            pending: Vec::new(),
            seen_hashes: HashSet::new(),
            stats: CollectorStats::default(),
        }
    }

    /// Create a new collector with default settings.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(CollectorConfig::default())
    }

    /// Ingest a single raw log line.
    ///
    /// Expected format:
    /// `DROP:<path>:<sha256>:<size>:<pid>:<origin_kind>[:<origin_detail>]`
    ///
    /// Returns `Ok(true)` if the line was recognised and accepted,
    /// `Ok(false)` if it was filtered, and `Err` if it could not be parsed.
    pub fn ingest_raw(&mut self, line: &str) -> Result<bool, CollectorError> {
        let parts: Vec<&str> = line.splitn(8, ':').collect();
        if parts.first() != Some(&"DROP") || parts.len() < 5 {
            return Err(CollectorError::Parse(format!(
                "not a DROP line: {line}"
            )));
        }
        let path = parts[1];
        let sha256 = parts[2];
        let size: usize = parts[3]
            .parse()
            .map_err(|_| CollectorError::Parse(format!("bad size: {}", parts[3])))?;
        let pid: u32 = parts[4]
            .parse()
            .map_err(|_| CollectorError::Parse(format!("bad pid: {}", parts[4])))?;

        let origin = if parts.len() >= 6 {
            parse_origin(parts[5], parts.get(6).copied().unwrap_or(""))
        } else {
            FileOrigin::Unknown
        };

        let mut f = DroppedFile::new(path, size, sha256, pid, origin);
        self.ingest_file(&mut f)
    }

    /// Ingest a pre-built [`DroppedFile`] record, applying filters.
    ///
    /// Returns `Ok(true)` if accepted, `Ok(false)` if filtered.
    pub fn ingest_file(&mut self, f: &mut DroppedFile) -> Result<bool, CollectorError> {
        self.stats.total_seen += 1;

        // Size filter.
        if f.size < self.config.min_size || f.size > self.config.max_size {
            self.stats.excluded_size += 1;
            return Ok(false);
        }

        // Path exclusion.
        let path_lower = f.path.to_ascii_lowercase();
        for frag in &self.config.exclude_path_fragments {
            if path_lower.contains(frag.to_ascii_lowercase().as_str()) {
                self.stats.excluded_path += 1;
                return Ok(false);
            }
        }

        // Path inclusion.
        if !self.config.include_path_fragments.is_empty() {
            let found = self
                .config
                .include_path_fragments
                .iter()
                .any(|frag| path_lower.contains(frag.to_ascii_lowercase().as_str()));
            if !found {
                self.stats.excluded_path += 1;
                return Ok(false);
            }
        }

        // Extension filter.
        if !self.config.include_extensions.is_empty() {
            let ext = f.extension().to_ascii_lowercase();
            if !self
                .config
                .include_extensions
                .iter()
                .any(|e| e.to_ascii_lowercase() == ext)
            {
                self.stats.excluded_ext += 1;
                return Ok(false);
            }
        }

        // Deduplication.
        if self.config.dedup_by_hash && !f.sha256.is_empty() {
            if self.seen_hashes.contains(&f.sha256) {
                self.stats.deduped += 1;
                return Ok(false);
            }
            self.seen_hashes.insert(f.sha256.clone());
        }

        // Auto-tagging.
        if self.config.auto_tag_pe && f.kind == MagicKind::Pe {
            f.tag("pe");
        }
        if self.config.auto_tag_high_entropy && f.is_high_entropy() {
            f.tag("encrypted");
        }

        self.stats.accepted += 1;
        self.pending.push(f.clone());
        Ok(true)
    }

    /// Consume all accepted files and return them as a sorted `Vec`.
    ///
    /// Files are sorted by `first_seen_ms` ascending.
    #[must_use]
    pub fn collect(mut self) -> Vec<DroppedFile> {
        self.pending
            .sort_by_key(|f| (f.first_seen_ms, f.path.clone()));
        self.pending
    }

    /// Return a reference to the current statistics.
    #[must_use]
    pub const fn stats(&self) -> &CollectorStats {
        &self.stats
    }

    /// Return the number of pending (accepted) files.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pending.len()
    }

    /// Return `true` if no files have been accepted yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Ingest multiple raw log lines, skipping blank and comment lines.
    ///
    /// Returns a map of `line_index → error` for lines that failed to parse.
    pub fn ingest_log(&mut self, log: &str) -> HashMap<usize, CollectorError> {
        let mut errors = HashMap::new();
        for (i, line) in log.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if !trimmed.starts_with("DROP:") {
                continue;
            }
            if let Err(e) = self.ingest_raw(trimmed) {
                errors.insert(i, e);
            }
        }
        errors
    }

    /// Scan an actual directory on the analysis host and ingest every regular
    /// file found. Each file is treated as `FileOrigin::Unknown` with the
    /// filesystem path as the `path` field.
    ///
    /// # Errors
    /// Returns [`CollectorError::Io`] if the directory cannot be read.
    pub fn ingest_directory(&mut self, dir: &Path) -> Result<(), CollectorError> {
        let rd =
            std::fs::read_dir(dir).map_err(|e| CollectorError::Io(e.to_string()))?;

        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            let size = meta.len() as usize;
            let path_str = path.to_string_lossy().to_string();

            // Read header bytes for magic detection.
            let header: Vec<u8> = std::fs::read(&path)
                .ok()
                .map(|data| data.into_iter().take(64).collect())
                .unwrap_or_default();

            let mut f = DroppedFile::new(path_str, size, "", 0, FileOrigin::Unknown);
            f.set_header(header);

            let _ = self.ingest_file(&mut f);
        }
        Ok(())
    }

    /// Classify all accepted files by their [`MagicKind`].
    ///
    /// Returns a map of `MagicKind` label → count.
    #[must_use]
    pub fn classify_by_kind(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for f in &self.pending {
            *map.entry(f.kind.label().to_string()).or_insert(0) += 1;
        }
        map
    }

    /// Return all accepted files that are executable.
    #[must_use]
    pub fn executables(&self) -> Vec<&DroppedFile> {
        self.pending.iter().filter(|f| f.is_executable()).collect()
    }

    /// Return all accepted files with the given tag.
    #[must_use]
    pub fn tagged(&self, tag: &str) -> Vec<&DroppedFile> {
        self.pending
            .iter()
            .filter(|f| f.has_tag(tag))
            .collect()
    }

    /// Group accepted files by the PID that created them.
    #[must_use]
    pub fn by_pid(&self) -> HashMap<u32, Vec<&DroppedFile>> {
        let mut map: HashMap<u32, Vec<&DroppedFile>> = HashMap::new();
        for f in &self.pending {
            map.entry(f.pid).or_default().push(f);
        }
        map
    }

    /// Return all PE files that appear to be in high-entropy sections (packed/encrypted).
    #[must_use]
    pub fn packed_executables(&self) -> Vec<&DroppedFile> {
        self.pending
            .iter()
            .filter(|f| f.kind == MagicKind::Pe && f.is_high_entropy())
            .collect()
    }

    /// Produce a human-readable summary of collected files.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "DroppedFileCollector: {} file(s) accepted",
            self.pending.len()
        ));
        let by_kind = self.classify_by_kind();
        let mut kinds: Vec<(&String, &usize)> = by_kind.iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(a.1));
        for (kind, count) in kinds {
            lines.push(format!("  {kind}: {count}"));
        }
        lines.push(format!(
            "Stats: seen={} excluded_size={} excluded_path={} deduped={} accepted={}",
            self.stats.total_seen,
            self.stats.excluded_size,
            self.stats.excluded_path,
            self.stats.deduped,
            self.stats.accepted,
        ));
        lines.join("\n")
    }
}

// ─── FileOriginAnnotator ──────────────────────────────────────────────────────

/// Enriches a list of dropped files with structured origin records by
/// cross-referencing API call names and arguments.
#[derive(Debug, Default)]
pub struct FileOriginAnnotator;

/// A simplified API call record used for annotation.
#[derive(Debug, Clone)]
pub struct ApiCallRef<'a> {
    /// API function name.
    pub name: &'a str,
    /// Arguments (string representations).
    pub args: &'a [String],
    /// PID of the caller.
    pub pid: u32,
}

impl FileOriginAnnotator {
    /// Create a new annotator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Annotate `files` in-place by correlating paths against API call records.
    pub fn annotate(&self, files: &mut [DroppedFile], api_calls: &[ApiCallRef<'_>]) {
        // Build a path → API call index for fast lookup.
        let mut path_map: HashMap<String, &ApiCallRef<'_>> = HashMap::new();
        for call in api_calls {
            let name_lower = call.name.to_ascii_lowercase();
            if !name_lower.contains("writefile")
                && !name_lower.contains("createfile")
                && !name_lower.contains("ntwritefile")
                && !name_lower.contains("ntopenfile")
            {
                continue;
            }
            if let Some(path_arg) = call.args.first() {
                path_map.insert(path_arg.to_ascii_lowercase(), call);
            }
        }

        for file in files.iter_mut() {
            let path_lower = file.path.to_ascii_lowercase();
            if let Some(call) = path_map.get(&path_lower) {
                file.origin = FileOrigin::DirectWrite {
                    pid: call.pid,
                    api: call.name.to_string(),
                };
                file.pid = call.pid;
            }
        }
    }

    /// Identify files whose origin is a `LOLBin` process by checking if the
    /// creating process name is a known `LOLBin`.
    pub fn tag_lolbin_drops(&self, files: &mut [DroppedFile], lolbins: &[&str]) {
        for file in files.iter_mut() {
            if let FileOrigin::DirectWrite { ref api, pid } = file.origin {
                let api_lower = api.to_ascii_lowercase();
                for lol in lolbins {
                    if api_lower.contains(&lol.to_ascii_lowercase()) {
                        let tool = lol.to_string();
                        file.origin = FileOrigin::LolBin {
                            tool: tool.clone(),
                        };
                        file.tag("lolbin");
                        file.tag(*lol);
                        let _ = pid; // silence unused warning
                        break;
                    }
                }
            }
        }
    }
}

// ─── DroppedFileSummary ───────────────────────────────────────────────────────

/// High-level summary statistics over a collection of dropped files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedFileSummary {
    pub total: usize,
    pub pe_count: usize,
    pub elf_count: usize,
    pub script_count: usize,
    pub archive_count: usize,
    pub high_entropy_count: usize,
    pub lolbin_origin_count: usize,
    pub download_origin_count: usize,
    pub unique_pids: usize,
    pub largest_size: usize,
    pub smallest_size: usize,
}

impl DroppedFileSummary {
    /// Build a summary over a slice of dropped files.
    #[must_use]
    pub fn from_files(files: &[DroppedFile]) -> Self {
        if files.is_empty() {
            return Self {
                total: 0,
                pe_count: 0,
                elf_count: 0,
                script_count: 0,
                archive_count: 0,
                high_entropy_count: 0,
                lolbin_origin_count: 0,
                download_origin_count: 0,
                unique_pids: 0,
                largest_size: 0,
                smallest_size: 0,
            };
        }

        let mut pe_count = 0usize;
        let mut elf_count = 0usize;
        let mut script_count = 0usize;
        let mut archive_count = 0usize;
        let mut high_entropy_count = 0usize;
        let mut lolbin_origin_count = 0usize;
        let mut download_origin_count = 0usize;
        let mut pids = HashSet::new();
        let mut largest_size = 0usize;
        let mut smallest_size = usize::MAX;

        for f in files {
            match f.kind {
                MagicKind::Pe => pe_count += 1,
                MagicKind::Elf => elf_count += 1,
                MagicKind::Powershell
                | MagicKind::Batch
                | MagicKind::Vbs
                | MagicKind::Javascript
                | MagicKind::Wsh => script_count += 1,
                MagicKind::Zip
                | MagicKind::SevenZip
                | MagicKind::Rar
                | MagicKind::Cabinet => archive_count += 1,
                _ => {}
            }
            if f.is_high_entropy() {
                high_entropy_count += 1;
            }
            if matches!(f.origin, FileOrigin::LolBin { .. }) {
                lolbin_origin_count += 1;
            }
            if matches!(f.origin, FileOrigin::Downloaded { .. }) {
                download_origin_count += 1;
            }
            pids.insert(f.pid);
            if f.size > largest_size {
                largest_size = f.size;
            }
            if f.size < smallest_size {
                smallest_size = f.size;
            }
        }

        Self {
            total: files.len(),
            pe_count,
            elf_count,
            script_count,
            archive_count,
            high_entropy_count,
            lolbin_origin_count,
            download_origin_count,
            unique_pids: pids.len(),
            largest_size,
            smallest_size,
        }
    }

    /// Return `true` if there are any concerning attributes (PE drops, high entropy, etc.).
    #[must_use]
    pub const fn has_indicators(&self) -> bool {
        self.pe_count > 0
            || self.high_entropy_count > 0
            || self.lolbin_origin_count > 0
            || self.download_origin_count > 0
    }
}

impl fmt::Display for DroppedFileSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DroppedFileSummary {{ total={}, pe={}, elf={}, scripts={}, archives={}, \
             high_entropy={}, lolbin_origin={}, download_origin={}, pids={} }}",
            self.total,
            self.pe_count,
            self.elf_count,
            self.script_count,
            self.archive_count,
            self.high_entropy_count,
            self.lolbin_origin_count,
            self.download_origin_count,
            self.unique_pids,
        )
    }
}

// ─── PathFilter ───────────────────────────────────────────────────────────────

/// A composable path filter used by higher-level collection pipelines.
#[derive(Debug, Clone, Default)]
pub struct PathFilter {
    /// Must contain all of these fragments (AND logic, case-insensitive).
    must_contain: Vec<String>,
    /// Must not contain any of these fragments (case-insensitive).
    must_not_contain: Vec<String>,
    /// File name must end with one of these extensions (case-insensitive).
    extensions: Vec<String>,
}

impl PathFilter {
    /// Create an empty (pass-all) filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Require all paths to contain `fragment`.
    pub fn require(mut self, fragment: impl Into<String>) -> Self {
        self.must_contain.push(fragment.into());
        self
    }

    /// Exclude any path containing `fragment`.
    pub fn exclude(mut self, fragment: impl Into<String>) -> Self {
        self.must_not_contain.push(fragment.into());
        self
    }

    /// Restrict to files with one of the given extensions.
    pub fn extension(mut self, ext: impl Into<String>) -> Self {
        self.extensions.push(ext.into());
        self
    }

    /// Return `true` if the path passes this filter.
    #[must_use]
    pub fn accepts(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();

        for frag in &self.must_contain {
            if !lower.contains(frag.to_ascii_lowercase().as_str()) {
                return false;
            }
        }

        for frag in &self.must_not_contain {
            if lower.contains(frag.to_ascii_lowercase().as_str()) {
                return false;
            }
        }

        if !self.extensions.is_empty() {
            let file_ext = if let Some(pos) = lower.rfind('.') {
                &lower[pos + 1..]
            } else {
                ""
            };
            if !self
                .extensions
                .iter()
                .any(|e| e.to_ascii_lowercase() == file_ext)
            {
                return false;
            }
        }

        true
    }
}

// ─── PathBuf helpers ──────────────────────────────────────────────────────────

/// Build a canonical report path for a dropped file given a sandbox run id.
#[must_use]
pub fn artifact_path(run_id: &str, sha256: &str, ext: &str) -> PathBuf {
    PathBuf::from(format!(
        "artifacts/{}/{}.{}",
        run_id,
        &sha256[..16.min(sha256.len())],
        ext
    ))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Compute Shannon entropy of a byte slice.
fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / n;
            h -= p * p.log2();
        }
    }
    h
}

/// Parse a `FileOrigin` from the origin kind string and optional detail.
fn parse_origin(kind: &str, detail: &str) -> FileOrigin {
    match kind {
        "write" => FileOrigin::DirectWrite {
            pid: 0,
            api: detail.to_string(),
        },
        "decoded" => FileOrigin::DecodedPayload {
            source_path: detail.to_string(),
        },
        "download" | "downloaded" => FileOrigin::Downloaded {
            url: detail.to_string(),
            status_code: None,
        },
        "archive" | "extracted" => FileOrigin::ExtractedFromArchive {
            archive_path: detail.to_string(),
        },
        "memdump" => {
            let va = u64::from_str_radix(detail.trim_start_matches("0x"), 16).unwrap_or(0);
            FileOrigin::MemoryDump { pid: 0, va }
        }
        "lolbin" => FileOrigin::LolBin {
            tool: detail.to_string(),
        },
        _ => FileOrigin::Unknown,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_detect_pe() {
        let header = [0x4d, 0x5a, 0x90, 0x00];
        assert_eq!(MagicKind::detect(&header, "exe"), MagicKind::Pe);
    }

    #[test]
    fn magic_detect_zip() {
        let header = [0x50, 0x4b, 0x03, 0x04];
        assert_eq!(MagicKind::detect(&header, "zip"), MagicKind::Zip);
    }

    #[test]
    fn magic_detect_elf() {
        let header = [0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00];
        assert_eq!(MagicKind::detect(&header, ""), MagicKind::Elf);
    }

    #[test]
    fn magic_detect_ps1_by_ext() {
        assert_eq!(MagicKind::detect(&[], "ps1"), MagicKind::Powershell);
    }

    #[test]
    fn dropped_file_extension() {
        let f = DroppedFile::new(
            r"C:\Windows\Temp\payload.exe",
            1024,
            "abc",
            1000,
            FileOrigin::Unknown,
        );
        assert_eq!(f.extension(), "exe");
        assert_eq!(f.file_name(), "payload.exe");
    }

    #[test]
    fn dropped_file_set_header_pe() {
        let mut f = DroppedFile::new(r"C:\x.exe", 512, "abc", 1, FileOrigin::Unknown);
        f.set_header(vec![0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
        assert_eq!(f.kind, MagicKind::Pe);
        assert!(f.is_executable());
    }

    #[test]
    fn collector_accepts_drop_line() {
        let mut c = DroppedFileCollector::default_config();
        let result = c.ingest_raw("DROP:/tmp/test.exe:deadbeef:4096:1234:write:WriteFile");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn collector_rejects_non_drop_line() {
        let mut c = DroppedFileCollector::default_config();
        let result = c.ingest_raw("NET:1.2.3.4:443:tcp");
        assert!(result.is_err());
    }

    #[test]
    fn collector_dedup_same_hash() {
        let mut c = DroppedFileCollector::default_config();
        c.ingest_raw("DROP:/a.exe:aabbccdd:1024:1:write:").unwrap();
        c.ingest_raw("DROP:/b.exe:aabbccdd:1024:1:write:").unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c.stats().deduped, 1);
    }

    #[test]
    fn collector_size_filter() {
        let mut cfg = CollectorConfig::default();
        cfg.min_size = 1024;
        let mut c = DroppedFileCollector::new(cfg);
        c.ingest_raw("DROP:/small.exe:hash1:100:1:write:").unwrap();
        assert_eq!(c.len(), 0);
        assert_eq!(c.stats().excluded_size, 1);
    }

    #[test]
    fn path_filter_accepts() {
        let f = PathFilter::new()
            .require("windows")
            .exclude("thumbs.db")
            .extension("exe");
        assert!(f.accepts(r"C:\Windows\System32\calc.exe"));
        assert!(!f.accepts(r"C:\Windows\thumbs.db"));
        assert!(!f.accepts(r"C:\Windows\System32\calc.dll"));
    }

    #[test]
    fn dropped_file_summary_from_empty() {
        let s = DroppedFileSummary::from_files(&[]);
        assert_eq!(s.total, 0);
        assert!(!s.has_indicators());
    }

    #[test]
    fn dropped_file_summary_from_files() {
        let mut f1 = DroppedFile::new("/tmp/a.exe", 4096, "h1", 100, FileOrigin::Unknown);
        f1.set_header(vec![0x4d, 0x5a]);
        let f2 = DroppedFile::new("/tmp/b.ps1", 512, "h2", 100, FileOrigin::Unknown);
        let files = [f1, f2];
        let s = DroppedFileSummary::from_files(&files);
        assert_eq!(s.total, 2);
        assert_eq!(s.pe_count, 1);
        assert_eq!(s.script_count, 0); // ps1 has no header, kind=Unknown
        assert!(s.has_indicators());
    }

    #[test]
    fn artifact_path_format() {
        let p = artifact_path("run123", "deadbeef1234567890ab", "exe");
        assert!(p.to_string_lossy().contains("run123"));
        assert!(p.to_string_lossy().contains("deadbeef12345678"));
    }

    #[test]
    fn log_ingestion() {
        let log = "
# comment line
DROP:/a.exe:aaaa:2048:1:write:WriteFile
DROP:/b.dll:bbbb:4096:2:write:NtWriteFile
NET:1.2.3.4:443:tcp
";
        let mut c = DroppedFileCollector::default_config();
        let errors = c.ingest_log(log);
        assert!(errors.is_empty());
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn collector_collect_sorted() {
        let mut c = DroppedFileCollector::default_config();
        let mut f1 = DroppedFile::new("/b.exe", 100, "h1", 1, FileOrigin::Unknown);
        f1.first_seen_ms = 200;
        let mut f2 = DroppedFile::new("/a.exe", 100, "h2", 1, FileOrigin::Unknown);
        f2.first_seen_ms = 100;
        c.ingest_file(&mut f1).unwrap();
        c.ingest_file(&mut f2).unwrap();
        let collected = c.collect();
        assert_eq!(collected[0].path, "/a.exe");
        assert_eq!(collected[1].path, "/b.exe");
    }
}
