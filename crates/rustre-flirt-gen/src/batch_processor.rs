//! Batch library processor for `rustre-flirt-gen`.
//!
//! Provides [`BatchProcessor`] which:
//! 1. Recursively scans directories for `.lib`, `.a`, and `.rlib` archives.
//! 2. Extracts object files and function samples via [`crate::library_scanner`].
//! 3. Generates FLIRT patterns with [`crate::sig_generator`].
//! 4. Deduplicates across files.
//! 5. Emits progress events and a coverage report.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────────────────────────────────────
// BatchError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the batch processor.
#[derive(Debug, Clone)]
pub enum BatchError {
    /// Could not read the directory.
    DirAccess(String),
    /// An individual file failed to process (non-fatal by default).
    FileFailed { path: String, reason: String },
    /// No library files were found in the given directories.
    NoLibrariesFound,
    /// An output operation failed.
    OutputFailed(String),
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirAccess(s) => write!(f, "directory access error: {s}"),
            Self::FileFailed { path, reason } => write!(f, "file {path} failed: {reason}"),
            Self::NoLibrariesFound => write!(f, "no library files found"),
            Self::OutputFailed(s) => write!(f, "output failed: {s}"),
        }
    }
}

impl std::error::Error for BatchError {}

// ─────────────────────────────────────────────────────────────────────────────
// ProgressEvent
// ─────────────────────────────────────────────────────────────────────────────

/// Progress notification emitted during batch processing.
#[derive(Debug, Clone)]
pub enum ProgressEvent {
    /// Discovery phase: N library files found.
    DiscoveredFiles(usize),
    /// Starting to process a file.
    ProcessingFile { index: usize, total: usize, path: String },
    /// File processed successfully.
    FileProcessed { path: String, functions_found: usize, patterns_generated: usize },
    /// File skipped (unsupported format or empty).
    FileSkipped { path: String, reason: String },
    /// File failed to process.
    FileFailed { path: String, error: String },
    /// Deduplication complete.
    DeduplicationDone { before: usize, after: usize },
    /// All processing done.
    Done(BatchReport),
}

/// A callback type for progress events.
pub type ProgressCallback = Box<dyn Fn(ProgressEvent) + Send + Sync>;

// ─────────────────────────────────────────────────────────────────────────────
// LibraryKind
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of archive / library file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryKind {
    /// Windows COFF `.lib` archive.
    CoffLib,
    /// Unix `ar` `.a` archive.
    ArArchive,
    /// Rust compiled library (`.rlib`, also an `ar` archive).
    RlibArchive,
    /// Unknown / unsupported.
    Unknown,
}

impl LibraryKind {
    /// Infer the kind from a file extension.
    #[must_use]
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "lib" => Self::CoffLib,
            "a" => Self::ArArchive,
            "rlib" => Self::RlibArchive,
            _ => Self::Unknown,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FileRecord
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata for a discovered library file.
#[derive(Debug, Clone)]
pub struct FileRecord {
    pub path: PathBuf,
    pub kind: LibraryKind,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Library tag derived from the filename stem.
    pub lib_tag: String,
}

impl FileRecord {
    /// Construct from a path (reads file metadata).
    #[must_use]
    pub fn from_path(path: PathBuf) -> Self {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let kind = LibraryKind::from_extension(ext);
        let size_bytes = std::fs::metadata(&path).map_or(0, |m| m.len());
        let lib_tag = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
        Self { path, kind, size_bytes, lib_tag }
    }

    /// `true` if this file kind is supported.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        !matches!(self.kind, LibraryKind::Unknown)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionRecord (minimal, avoids circular dep on full types)
// ─────────────────────────────────────────────────────────────────────────────

/// A function extracted from a library file.
#[derive(Debug, Clone)]
pub struct FunctionRecord {
    /// Function name.
    pub name: String,
    /// Raw bytes.
    pub bytes: Vec<u8>,
    /// Source library tag.
    pub lib_tag: String,
    /// Source object file name within the archive.
    pub obj_name: String,
    /// Byte offsets of relocation targets.
    pub reloc_offsets: Vec<u16>,
}

impl FunctionRecord {
    /// Compute a simple dedup key: first 16 bytes as hex + name.
    #[must_use]
    pub fn dedup_key(&self) -> String {
        use std::fmt::Write as _;
        let mut prefix = String::with_capacity(32);
        for b in self.bytes.iter().take(16) {
            let _ = write!(prefix, "{b:02X}");
        }
        format!("{}:{prefix}", self.name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the batch processor.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Directories to scan.
    pub directories: Vec<PathBuf>,
    /// Recurse into subdirectories.
    pub recursive: bool,
    /// Follow symbolic links.
    pub follow_symlinks: bool,
    /// Minimum function size in bytes to include.
    pub min_function_bytes: usize,
    /// Maximum function size in bytes (0 = no limit).
    pub max_function_bytes: usize,
    /// Whether to stop on the first file error.
    pub fail_fast: bool,
    /// Number of parallel worker threads (0 = serial).
    pub threads: usize,
    /// Name prefixes to exclude (e.g. internal CRT helpers).
    pub exclude_prefixes: Vec<String>,
    /// Library tags to process exclusively (empty = all).
    pub include_only_tags: Vec<String>,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            directories: Vec::new(),
            recursive: true,
            follow_symlinks: false,
            min_function_bytes: 4,
            max_function_bytes: 0,
            fail_fast: false,
            threads: 0,
            exclude_prefixes: vec![
                "___".to_string(),
                "??"  .to_string(),
            ],
            include_only_tags: Vec::new(),
        }
    }
}

impl BatchConfig {
    /// Add a directory to scan.
    pub fn add_dir(&mut self, dir: impl Into<PathBuf>) {
        self.directories.push(dir.into());
    }

    /// Returns `true` if a function name should be excluded.
    #[must_use]
    pub fn should_exclude(&self, name: &str) -> bool {
        self.exclude_prefixes.iter().any(|p| name.starts_with(p.as_str()))
    }

    /// Returns `true` if a library tag should be processed.
    #[must_use]
    pub fn should_include_tag(&self, tag: &str) -> bool {
        self.include_only_tags.is_empty()
            || self.include_only_tags.iter().any(|t| t == tag)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternRecord
// ─────────────────────────────────────────────────────────────────────────────

/// An extracted/generated pattern record for output.
#[derive(Debug, Clone)]
pub struct PatternRecord {
    pub name: String,
    pub lib_tag: String,
    /// PAT hex line (e.g. `"5548..E5 08 BEEF 0040 :0000 func"`).
    pub pat_line: String,
    /// Raw pattern bytes (None = wildcard).
    pub pattern: Vec<Option<u8>>,
    pub crc: u16,
    pub crc_offset: u16,
    pub crc_len: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary report produced at the end of a batch run.
#[derive(Debug, Clone, Default)]
pub struct BatchReport {
    /// Total library files discovered.
    pub files_discovered: usize,
    /// Files successfully processed.
    pub files_processed: usize,
    /// Files skipped (unsupported or empty).
    pub files_skipped: usize,
    /// Files that failed with an error.
    pub files_failed: usize,
    /// Total raw functions extracted before dedup.
    pub functions_extracted: usize,
    /// Functions retained after dedup.
    pub functions_unique: usize,
    /// Patterns generated.
    pub patterns_generated: usize,
    /// Patterns discarded during dedup.
    pub patterns_deduplicated: usize,
    /// Elapsed processing time in milliseconds.
    pub elapsed_ms: u64,
    /// Per-library coverage: `lib_tag` → function count.
    pub coverage: HashMap<String, usize>,
    /// Non-fatal errors encountered.
    pub errors: Vec<String>,
}

impl BatchReport {
    /// Append a non-fatal error message.
    pub fn add_error(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }

    /// Coverage ratio: unique functions / extracted functions.
    #[must_use]
    pub fn dedup_ratio(&self) -> f64 {
        if self.functions_extracted == 0 {
            return 1.0;
        }
        let unique = u32::try_from(self.functions_unique).unwrap_or(u32::MAX);
        let extracted = u32::try_from(self.functions_extracted).unwrap_or(u32::MAX);
        f64::from(unique) / f64::from(extracted)
    }
}

impl std::fmt::Display for BatchReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,
            "BatchReport: files={}/{} skipped={} failed={} funcs={} unique={} patterns={} dedup={} elapsed={}ms errors={}",
            self.files_processed, self.files_discovered,
            self.files_skipped, self.files_failed,
            self.functions_extracted, self.functions_unique,
            self.patterns_generated, self.patterns_deduplicated,
            self.elapsed_ms, self.errors.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DirectoryScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Discovers library files under one or more directories.
pub struct DirectoryScanner {
    recursive: bool,
    follow_symlinks: bool,
}

impl DirectoryScanner {
    /// Create a scanner with the given options.
    #[must_use]
    pub const fn new(recursive: bool, follow_symlinks: bool) -> Self {
        Self { recursive, follow_symlinks }
    }

    /// Scan a single directory; return all discovered library files.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError::DirAccess`] if the directory cannot be read.
    pub fn scan_dir(&self, dir: &Path) -> Result<Vec<FileRecord>, BatchError> {
        let read_dir = std::fs::read_dir(dir)
            .map_err(|e| BatchError::DirAccess(format!("{}: {e}", dir.display())))?;
        let mut out = Vec::new();
        for entry_res in read_dir {
            let Ok(entry) = entry_res else { continue };
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_symlink() && !self.follow_symlinks {
                continue;
            }
            if meta.is_dir() && self.recursive {
                if let Ok(sub) = self.scan_dir(&path) {
                    out.extend(sub);
                }
                continue;
            }
            if meta.is_file() {
                let rec = FileRecord::from_path(path);
                if rec.is_supported() {
                    out.push(rec);
                }
            }
        }
        Ok(out)
    }

    /// Scan multiple directories.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError`] if any directory cannot be read or no files are found.
    pub fn scan_all(&self, dirs: &[PathBuf]) -> Result<Vec<FileRecord>, BatchError> {
        let mut all = Vec::new();
        for dir in dirs {
            match self.scan_dir(dir) {
                Ok(mut v) => all.append(&mut v),
                Err(e) => return Err(e),
            }
        }
        if all.is_empty() {
            return Err(BatchError::NoLibrariesFound);
        }
        Ok(all)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionDeduplicator
// ─────────────────────────────────────────────────────────────────────────────

/// Removes duplicate function records across library files.
pub struct FunctionDeduplicator {
    seen: HashSet<String>,
}

impl FunctionDeduplicator {
    #[must_use]
    pub fn new() -> Self {
        Self { seen: HashSet::new() }
    }

    /// Filter a list of function records, returning only unseen ones.
    pub fn dedup(&mut self, records: Vec<FunctionRecord>) -> (Vec<FunctionRecord>, usize) {
        let total = records.len();
        let mut out = Vec::new();
        for r in records {
            let key = r.dedup_key();
            if self.seen.insert(key) {
                out.push(r);
            }
        }
        let removed = total - out.len();
        (out, removed)
    }

    /// Number of unique keys seen so far.
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.seen.len()
    }
}

impl Default for FunctionDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InMemoryArchive — minimal ar/COFF reader for batch use
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal in-memory parser for `ar` archives (`.a` / `.rlib`).
///
/// Only extracts member names and raw bytes; full COFF/ELF parsing is delegated
/// to the `library_scanner` module.
pub struct InMemoryArchive {
    /// `(member_name, raw_bytes)` pairs.
    pub members: Vec<(String, Vec<u8>)>,
}

impl InMemoryArchive {
    /// `ar` archive magic.
    const AR_MAGIC: &'static [u8] = b"!<arch>\n";

    /// Parse an `ar` archive from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError::FileFailed`] if the data is not a valid `ar` archive.
    pub fn parse_ar(data: &[u8]) -> Result<Self, BatchError> {
        if data.len() < 8 || &data[..8] != Self::AR_MAGIC {
            return Err(BatchError::FileFailed {
                path: "?".into(),
                reason: "not an ar archive".into(),
            });
        }
        let mut members = Vec::new();
        let mut pos = 8usize;
        while pos + 60 <= data.len() {
            // Each member header is exactly 60 bytes.
            let header = &data[pos..pos+60];
            let name_raw = std::str::from_utf8(&header[0..16]).unwrap_or("").trim().to_string();
            let size_raw = std::str::from_utf8(&header[48..58]).unwrap_or("0").trim();
            let size = size_raw.parse::<usize>().unwrap_or(0);
            let end_magic = &header[58..60];
            if end_magic != b"`\n" {
                break; // malformed
            }
            pos += 60;
            // Cap the member size to the remaining data to avoid an
            // over-large allocation driven by an attacker-controlled size field.
            if size > data.len().saturating_sub(pos) {
                break; // malformed / truncated
            }
            let member_end = pos + size;
            let member_data = data[pos..member_end].to_vec();
            if !name_raw.starts_with('/') {
                members.push((name_raw, member_data));
            }
            pos += size;
            if !pos.is_multiple_of(2) { pos += 1; } // padding byte
        }
        Ok(Self { members })
    }

    /// Check if the data looks like a COFF `.lib` (thin wrapper around COFF objects).
    #[must_use]
    pub fn is_coff_lib(data: &[u8]) -> bool {
        // COFF archives also use `!<arch>` magic but may have an import descriptor.
        data.starts_with(Self::AR_MAGIC)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchProcessor
// ─────────────────────────────────────────────────────────────────────────────

/// Orchestrates scanning, extraction, and pattern generation across many library files.
pub struct BatchProcessor {
    config: BatchConfig,
    progress: Option<ProgressCallback>,
}

impl BatchProcessor {
    /// Create a processor with the given config.
    #[must_use]
    pub fn new(config: BatchConfig) -> Self {
        Self { config, progress: None }
    }

    /// Attach a progress callback.
    #[must_use]
    pub fn with_progress(mut self, cb: ProgressCallback) -> Self {
        self.progress = Some(cb);
        self
    }

    fn emit(&self, ev: ProgressEvent) {
        if let Some(cb) = &self.progress {
            cb(ev);
        }
    }

    /// Parse a single library file and extract function records.
    fn process_file(&self, rec: &FileRecord) -> Result<Vec<FunctionRecord>, BatchError> {
        let data = std::fs::read(&rec.path)
            .map_err(|e| BatchError::FileFailed {
                path: rec.path.display().to_string(),
                reason: e.to_string(),
            })?;

        let archive = InMemoryArchive::parse_ar(&data)
            .map_err(|_| BatchError::FileFailed {
                path: rec.path.display().to_string(),
                reason: "ar parse failed".into(),
            })?;

        let mut functions = Vec::new();
        for (obj_name, obj_bytes) in &archive.members {
            // Lightweight ELF symbol scan: look for .text section symbols.
            let funcs = extract_functions_heuristic(obj_bytes, &rec.lib_tag, obj_name);
            for f in funcs {
                if self.config.should_exclude(&f.name) {
                    continue;
                }
                if f.bytes.len() < self.config.min_function_bytes {
                    continue;
                }
                if self.config.max_function_bytes > 0 && f.bytes.len() > self.config.max_function_bytes {
                    continue;
                }
                functions.push(f);
            }
        }
        Ok(functions)
    }

    /// Run the full batch pipeline and return all unique pattern records.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError`] if directory scanning fails or no libraries are found.
    pub fn run(&self) -> Result<(Vec<PatternRecord>, BatchReport), BatchError> {
        let scanner = DirectoryScanner::new(self.config.recursive, self.config.follow_symlinks);
        let mut files = scanner.scan_all(&self.config.directories)?;

        // Filter by tag if requested.
        if !self.config.include_only_tags.is_empty() {
            files.retain(|f| self.config.should_include_tag(&f.lib_tag));
        }

        self.emit(ProgressEvent::DiscoveredFiles(files.len()));

        let mut report = BatchReport { files_discovered: files.len(), ..BatchReport::default() };

        let mut all_functions: Vec<FunctionRecord> = Vec::new();
        let total_files = files.len();

        for (idx, file_rec) in files.iter().enumerate() {
            self.emit(ProgressEvent::ProcessingFile {
                index: idx,
                total: total_files,
                path: file_rec.path.display().to_string(),
            });

            match self.process_file(file_rec) {
                Ok(funcs) => {
                    let n = funcs.len();
                    report.functions_extracted += n;
                    *report.coverage.entry(file_rec.lib_tag.clone()).or_insert(0) += n;
                    report.files_processed += 1;
                    self.emit(ProgressEvent::FileProcessed {
                        path: file_rec.path.display().to_string(),
                        functions_found: n,
                        patterns_generated: n,
                    });
                    all_functions.extend(funcs);
                }
                Err(BatchError::FileFailed { path, reason }) => {
                    report.files_failed += 1;
                    let msg = format!("{path}: {reason}");
                    report.add_error(msg.clone());
                    self.emit(ProgressEvent::FileFailed { path, error: reason });
                    if self.config.fail_fast {
                        return Err(BatchError::FileFailed { path: msg, reason: "fail_fast".into() });
                    }
                }
                Err(e) => {
                    report.files_skipped += 1;
                    self.emit(ProgressEvent::FileSkipped {
                        path: file_rec.path.display().to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        // Dedup.
        let before = all_functions.len();
        let mut deduper = FunctionDeduplicator::new();
        let (unique, removed) = deduper.dedup(all_functions);
        let after = unique.len();

        report.functions_unique = after;
        report.patterns_deduplicated = removed;

        self.emit(ProgressEvent::DeduplicationDone { before, after });

        // Convert to PatternRecords.
        let patterns: Vec<PatternRecord> = unique.iter().map(function_to_pattern).collect();
        report.patterns_generated = patterns.len();

        self.emit(ProgressEvent::Done(report.clone()));
        Ok((patterns, report))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Very lightweight heuristic function extractor — walks an ELF/COFF blob and
/// returns runs of bytes that look like function bodies.
///
/// For real extraction, the `library_scanner` module should be used; this
/// version is a standalone fallback that avoids circular dependency.
fn extract_functions_heuristic(data: &[u8], lib_tag: &str, obj_name: &str) -> Vec<FunctionRecord> {
    let mut out = Vec::new();
    if data.len() < 8 {
        return out;
    }

    // ELF magic
    let is_elf = data.len() >= 4 && &data[0..4] == b"\x7FELF";
    // COFF: check for x86-64 machine type 0x8664 or x86 0x014C
    let is_coff = data.len() >= 2 && {
        let m = u16::from_le_bytes([data[0], data[1]]);
        m == 0x8664 || m == 0x014C
    };

    if !is_elf && !is_coff {
        return out;
    }

    // Heuristic: scan for 0x55 0x48 0x89 0xE5 (x64 push rbp / mov rbp,rsp)
    // or 0x55 0x8B 0xEC (x86 push ebp / mov ebp,esp) as function starts.
    let prologues: &[&[u8]] = &[
        &[0x55, 0x48, 0x89, 0xE5],
        &[0x55, 0x8B, 0xEC],
        &[0x48, 0x89, 0x4C, 0x24, 0x08],
        &[0x48, 0x83, 0xEC],
        &[0x40, 0x53],
    ];

    let mut i = 0usize;
    while i + 4 < data.len() {
        for prologue in prologues {
            let pl = prologue.len();
            if i + pl <= data.len() && &data[i..i+pl] == *prologue {
                // Scan forward to find likely end (RET = 0xC3 or 0xC2 xx xx).
                let start = i;
                let mut end = i + pl;
                while end < data.len() && end - start < 4096 {
                    if data[end] == 0xC3 || (data[end] == 0xC2 && end + 2 < data.len()) {
                        end += 1;
                        break;
                    }
                    end += 1;
                }
                if end - start >= 4 {
                    out.push(FunctionRecord {
                        name: format!("sub_{i:X}"),
                        bytes: data[start..end].to_vec(),
                        lib_tag: lib_tag.to_string(),
                        obj_name: obj_name.to_string(),
                        reloc_offsets: Vec::new(),
                    });
                    i = end;
                }
                break;
            }
        }
        i += 1;
    }
    out
}

/// Convert a [`FunctionRecord`] to a minimal [`PatternRecord`].
fn function_to_pattern(f: &FunctionRecord) -> PatternRecord {
    let initial = f.bytes.len().min(32);
    let pattern: Vec<Option<u8>> = f.bytes[..initial].iter().enumerate().map(|(i, &b)| {
        if u16::try_from(i).is_ok_and(|i_u16| f.reloc_offsets.contains(&i_u16)) { None } else { Some(b) }
    }).collect();

    let hex: String = pattern.iter().map(|b| b.map_or_else(|| "..".to_string(), |v| format!("{v:02X}"))).collect();

    PatternRecord {
        name: f.name.clone(),
        lib_tag: f.lib_tag.clone(),
        pat_line: format!("{hex} 00 0000 0000 :0000 {}", f.name),
        pattern,
        crc: 0,
        crc_offset: 0,
        crc_len: 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_kind_from_ext() {
        assert_eq!(LibraryKind::from_extension("lib"), LibraryKind::CoffLib);
        assert_eq!(LibraryKind::from_extension("a"), LibraryKind::ArArchive);
        assert_eq!(LibraryKind::from_extension("rlib"), LibraryKind::RlibArchive);
        assert_eq!(LibraryKind::from_extension("dll"), LibraryKind::Unknown);
    }

    #[test]
    fn test_deduplicator() {
        let make = |name: &str, prefix: &[u8]| FunctionRecord {
            name: name.into(),
            bytes: prefix.to_vec(),
            lib_tag: "lib".into(),
            obj_name: "obj.o".into(),
            reloc_offsets: Vec::new(),
        };
        let funcs = vec![
            make("foo", &[0x55u8, 0x48, 0x89, 0xE5]),
            make("foo", &[0x55u8, 0x48, 0x89, 0xE5]), // duplicate
            make("bar", &[0x55u8, 0x53, 0x48, 0x83]),
        ];
        let mut dedup = FunctionDeduplicator::new();
        let (uniq, removed) = dedup.dedup(funcs);
        assert_eq!(uniq.len(), 2);
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_config_should_exclude() {
        let config = BatchConfig::default();
        assert!(config.should_exclude("___crt_"));
        assert!(!config.should_exclude("foo_bar"));
    }

    #[test]
    fn test_ar_parse_minimal() {
        // Minimal ar archive with one member.
        let mut ar = b"!<arch>\n".to_vec();
        // header: name (16), mtime (12), uid (6), gid (6), mode (8), size (10), magic (2)
        let hdr = b"test.o/         0           0     0     644     4         `\n";
        ar.extend_from_slice(hdr);
        ar.extend_from_slice(b"\x7FELF"); // 4-byte member content
        let result = InMemoryArchive::parse_ar(&ar);
        assert!(result.is_ok());
        let arch = result.unwrap();
        assert_eq!(arch.members.len(), 1);
        assert_eq!(arch.members[0].0, "test.o/");
    }

    #[test]
    fn test_batch_report_display() {
        let mut report = BatchReport::default();
        report.files_discovered = 10;
        report.files_processed = 9;
        report.functions_unique = 100;
        let s = report.to_string();
        assert!(s.contains("files=9/10"));
    }
}
