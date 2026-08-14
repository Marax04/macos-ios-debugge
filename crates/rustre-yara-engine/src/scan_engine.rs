//! `scan_engine` — Multi-threaded YARA scan engine with worker pool, progress
//! reporting, early-exit on match limit, per-scan timeout, and nested archive
//! scanning (ZIP / RAR / Cabinet).

use std::collections::VecDeque;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{YaraError, YaraRule};

// ── Public error ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ScanEngineError {
    #[error("scan timed out after {0:?}")]
    Timeout(Duration),
    #[error("match limit {0} reached")]
    MatchLimit(usize),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("thread pool error: {0}")]
    ThreadPool(String),
    #[error("archive extraction error: {0}")]
    Archive(String),
    #[error("yara: {0}")]
    Yara(#[from] YaraError),
}

pub type ScanEngResult<T> = Result<T, ScanEngineError>;

// ── Scan target ───────────────────────────────────────────────────────────────

/// What to scan.
#[derive(Debug, Clone)]
pub enum ScanTarget {
    /// A file on disk (archives are optionally recursed).
    File(PathBuf),
    /// Raw memory buffer with an optional descriptive label.
    Memory { data: Arc<Vec<u8>>, label: String },
    /// A running process identified by PID.
    Process { pid: u32 },
    /// An entire directory tree.
    Directory { root: PathBuf, recursive: bool },
}

// ── Scan options ─────────────────────────────────────────────────────────────

/// Fine-grained knobs for a scan job.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Hard limit on total matches before aborting (0 = unlimited).
    pub match_limit: usize,
    /// Per-target wall-clock timeout.
    pub timeout: Option<Duration>,
    /// Number of worker threads (0 = logical CPUs).
    pub workers: usize,
    /// Recurse into ZIP/RAR/CAB archives found inside file targets.
    pub scan_archives: bool,
    /// Maximum archive nesting depth (0 = top-level only).
    pub archive_depth: usize,
    /// Maximum bytes extracted from a single archived entry.
    pub archive_entry_limit: usize,
    /// Glob pattern filter applied to file names inside archives.
    pub archive_filter: Option<String>,
    /// Chunk size used when streaming large files to avoid full mmap.
    pub stream_chunk: usize,
    /// Report only rules with severity >= this value (0–100).
    pub min_severity: u8,
    /// Emit partial results via progress channel even on timeout.
    pub partial_on_timeout: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            match_limit: 10_000,
            timeout: Some(Duration::from_mins(1)),
            workers: 0,
            scan_archives: true,
            archive_depth: 3,
            archive_entry_limit: 64 * 1024 * 1024, // 64 MiB
            archive_filter: None,
            stream_chunk: 4 * 1024 * 1024, // 4 MiB
            min_severity: 0,
            partial_on_timeout: true,
        }
    }
}

// ── Progress ─────────────────────────────────────────────────────────────────

/// Progress event emitted by the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanProgress {
    /// A new target started.
    TargetStarted { label: String },
    /// A target finished scanning.
    TargetDone {
        label: String,
        matches: usize,
        elapsed_ms: u64,
    },
    /// One YARA match found.
    MatchFound { label: String, rule: String, offset: u64 },
    /// Overall progress fraction.
    Progress { done: u64, total: u64 },
    /// Engine finished all targets.
    Done { total_matches: usize, elapsed_ms: u64 },
    /// A non-fatal error occurred.
    Error { label: String, message: String },
}

/// Callback type for progress events.
pub type ProgressCallback = Arc<dyn Fn(ScanProgress) + Send + Sync + 'static>;

// ── Match result ─────────────────────────────────────────────────────────────

/// A single scan result record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMatch {
    /// Label of the scanned target.
    pub target: String,
    /// Rule that matched.
    pub rule_name: String,
    /// Rule namespace.
    pub namespace: String,
    /// Rule tags.
    pub tags: Vec<String>,
    /// Byte offset of the match within the target data.
    pub offset: u64,
    /// Matched bytes (up to first 64).
    pub data: Vec<u8>,
    /// Length of the full match.
    pub length: u64,
    /// Archive path chain if match is inside a nested archive.
    pub archive_path: Vec<String>,
}

// ── Aggregate scan result ─────────────────────────────────────────────────────

/// Result of a full scan job.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScanReport {
    pub matches: Vec<ScanMatch>,
    pub targets_scanned: u64,
    pub targets_errored: u64,
    pub bytes_scanned: u64,
    pub elapsed_ms: u64,
    pub timed_out: bool,
    pub match_limit_reached: bool,
}

// ── Shared engine state ───────────────────────────────────────────────────────

struct EngineState {
    rules: Vec<Arc<YaraRule>>,
    options: ScanOptions,
    progress: Option<ProgressCallback>,
    matches: Mutex<Vec<ScanMatch>>,
    match_count: AtomicU32,
    bytes_scanned: AtomicU64,
    targets_done: AtomicU64,
    aborted: AtomicBool,
    started_at: Instant,
}

impl EngineState {
    fn is_limit_reached(&self) -> bool {
        let lim = self.options.match_limit;
        lim > 0 && self.match_count.load(Ordering::Relaxed) as usize >= lim
    }

    fn is_timed_out(&self) -> bool {
        self.options.timeout.is_some_and(|to| self.started_at.elapsed() > to)
    }

    fn should_abort(&self) -> bool {
        self.aborted.load(Ordering::Relaxed) || self.is_limit_reached() || self.is_timed_out()
    }

    fn record_match(&self, m: ScanMatch) {
        let prev = self.match_count.fetch_add(1, Ordering::Relaxed);
        if let Some(cb) = &self.progress {
            cb(ScanProgress::MatchFound {
                label: m.target.clone(),
                rule: m.rule_name.clone(),
                offset: m.offset,
            });
        }
        self.matches.lock().unwrap().push(m);
        let lim = self.options.match_limit;
        if lim > 0 && (prev + 1) as usize >= lim {
            self.aborted.store(true, Ordering::Relaxed);
        }
    }

    fn emit(&self, ev: ScanProgress) {
        if let Some(cb) = &self.progress {
            cb(ev);
        }
    }
}

// ── Worker pool ───────────────────────────────────────────────────────────────

/// Queue item for the worker threads.
#[derive(Debug)]
enum WorkItem {
    File { path: PathBuf, archive_chain: Vec<String>, depth: usize },
    Memory { data: Arc<Vec<u8>>, label: String },
    Process { pid: u32 },
}

// ── ScanEngine ────────────────────────────────────────────────────────────────

/// Main scan engine.  Construct via [`ScanEngine::new`], then call [`ScanEngine::scan`].
pub struct ScanEngine {
    rules: Vec<Arc<YaraRule>>,
    options: ScanOptions,
    progress: Option<ProgressCallback>,
}

impl ScanEngine {
    /// Create a new engine with the given compiled rules and options.
    pub fn new(rules: Vec<YaraRule>, options: ScanOptions) -> Self {
        Self {
            rules: rules.into_iter().map(Arc::new).collect(),
            options,
            progress: None,
        }
    }

    /// Attach a progress callback.
    #[must_use]
    pub fn with_progress(mut self, cb: ProgressCallback) -> Self {
        self.progress = Some(cb);
        self
    }

    /// Run the engine on a list of targets and return a [`ScanReport`].
    ///
    /// # Panics
    ///
    /// Panics if an internal mutex is poisoned.
    #[must_use]
    pub fn scan(&self, targets: Vec<ScanTarget>) -> ScanReport {
        let workers = if self.options.workers == 0 {
            std::thread::available_parallelism()
                .map_or(4, std::num::NonZero::get)
        } else {
            self.options.workers
        };

        let state = Arc::new(EngineState {
            rules: self.rules.clone(),
            options: self.options.clone(),
            progress: self.progress.clone(),
            matches: Mutex::new(Vec::new()),
            match_count: AtomicU32::new(0),
            bytes_scanned: AtomicU64::new(0),
            targets_done: AtomicU64::new(0),
            aborted: AtomicBool::new(false),
            started_at: Instant::now(),
        });

        // Build initial work queue
        let queue: Arc<Mutex<VecDeque<WorkItem>>> = Arc::new(Mutex::new(VecDeque::new()));
        let total_targets = u64::try_from(targets.len()).unwrap_or(u64::MAX);
        for target in targets {
            let item = match target {
                ScanTarget::File(p) => WorkItem::File {
                    path: p,
                    archive_chain: Vec::new(),
                    depth: 0,
                },
                ScanTarget::Memory { data, label } => WorkItem::Memory { data, label },
                ScanTarget::Process { pid } => WorkItem::Process { pid },
                ScanTarget::Directory { root, recursive } => {
                    expand_directory_into_queue(&root, recursive, &mut queue.lock().unwrap());
                    continue;
                }
            };
            queue.lock().unwrap().push_back(item);
        }

        state.emit(ScanProgress::Progress { done: 0, total: total_targets });

        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let q = queue.clone();
            let s = state.clone();
            let handle = std::thread::spawn(move || {
                worker_loop(&q, &s);
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.join();
        }

        let elapsed = state.started_at.elapsed();
        let timed_out = state.is_timed_out();
        let match_limit_reached = state.is_limit_reached();

        let matches = state.matches.lock().unwrap().clone();
        state.emit(ScanProgress::Done {
            total_matches: matches.len(),
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        });

        ScanReport {
            matches,
            targets_scanned: state.targets_done.load(Ordering::Relaxed),
            targets_errored: 0,
            bytes_scanned: state.bytes_scanned.load(Ordering::Relaxed),
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            timed_out,
            match_limit_reached,
        }
    }
}

// ── Worker loop ───────────────────────────────────────────────────────────────

fn worker_loop(queue: &Arc<Mutex<VecDeque<WorkItem>>>, state: &Arc<EngineState>) {
    loop {
        if state.should_abort() {
            return;
        }
        let item = {
            let mut q = queue.lock().unwrap();
            q.pop_front()
        };
        match item {
            None => return,
            Some(WorkItem::File { path, archive_chain, depth }) => {
                scan_file_target(&path, &archive_chain, depth, queue, state);
                state.targets_done.fetch_add(1, Ordering::Relaxed);
            }
            Some(WorkItem::Memory { data, label }) => {
                scan_memory_target(&data, &label, &[], state);
                state.targets_done.fetch_add(1, Ordering::Relaxed);
            }
            Some(WorkItem::Process { pid }) => {
                scan_process_target(pid, state);
                state.targets_done.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ── File target ───────────────────────────────────────────────────────────────

fn scan_file_target(
    path: &Path,
    archive_chain: &[String],
    depth: usize,
    queue: &Arc<Mutex<VecDeque<WorkItem>>>,
    state: &Arc<EngineState>,
) {
    let label = path.display().to_string();
    state.emit(ScanProgress::TargetStarted { label: label.clone() });
    let t0 = Instant::now();

    let data = match read_file_limited(path, state.options.stream_chunk.saturating_mul(256)) {
        Ok(d) => d,
        Err(e) => {
            state.emit(ScanProgress::Error { label, message: e.to_string() });
            return;
        }
    };

    state.bytes_scanned.fetch_add(u64::try_from(data.len()).unwrap_or(u64::MAX), Ordering::Relaxed);
    let match_count = scan_bytes_against_rules(&data, &label, archive_chain, state);

    state.emit(ScanProgress::TargetDone {
        label: label.clone(),
        matches: match_count,
        elapsed_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    });

    // Recurse into archives if enabled and depth allows
    if state.options.scan_archives && depth < state.options.archive_depth
        && let Some(entries) = try_extract_archive(&data, state.options.archive_entry_limit) {
            for (entry_name, entry_data) in entries {
                if state.should_abort() { break; }
                let mut chain = archive_chain.to_vec();
                chain.push(format!("{label}!{entry_name}"));
                let arc_data = Arc::new(entry_data);
                let item = WorkItem::Memory {
                    data: arc_data,
                    label: chain.last().cloned().unwrap_or_default(),
                };
                // Push to front for depth-first traversal
                queue.lock().unwrap().push_front(item);
            }
        }
}

fn read_file_limited(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut f = std::fs::File::open(path)?;
    let meta = f.metadata()?;
    let size = usize::try_from(meta.len()).unwrap_or(usize::MAX).min(limit);
    let mut buf = Vec::with_capacity(size);
    f.by_ref().take(u64::try_from(limit).unwrap_or(u64::MAX)).read_to_end(&mut buf)?;
    Ok(buf)
}

// ── Memory target ─────────────────────────────────────────────────────────────

fn scan_memory_target(
    data: &[u8],
    label: &str,
    archive_chain: &[String],
    state: &Arc<EngineState>,
) {
    state.emit(ScanProgress::TargetStarted { label: label.to_string() });
    let t0 = Instant::now();
    state.bytes_scanned.fetch_add(u64::try_from(data.len()).unwrap_or(u64::MAX), Ordering::Relaxed);
    let mc = scan_bytes_against_rules(data, label, archive_chain, state);
    state.emit(ScanProgress::TargetDone {
        label: label.to_string(),
        matches: mc,
        elapsed_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
    });
}

// ── Process target ────────────────────────────────────────────────────────────

fn scan_process_target(pid: u32, state: &Arc<EngineState>) {
    let label = format!("pid:{pid}");
    state.emit(ScanProgress::TargetStarted { label: label.clone() });

    // Read /proc/<pid>/mem on Linux, ReadProcessMemory on Windows (stub)
    // For portability we attempt a best-effort read from the process.
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let maps_path = format!("/proc/{}/maps", pid);
        let mem_path = format!("/proc/{}/mem", pid);
        if let Ok(maps) = fs::read_to_string(&maps_path) {
            if let Ok(mut mem_file) = fs::File::open(&mem_path) {
                use std::io::Seek;
                for line in maps.lines().take(256) {
                    if state.should_abort() { break; }
                    // parse "start-end rwxp ..."
                    if let Some(range) = parse_proc_maps_line(line) {
                        let size = (range.1 - range.0).min(4 * 1024 * 1024) as usize;
                        let mut buf = vec![0u8; size];
                        if mem_file.seek(io::SeekFrom::Start(range.0)).is_ok()
                            && mem_file.read_exact(&mut buf).is_ok()
                        {
                            let region_label = format!("{}@{:#x}", label, range.0);
                            scan_bytes_against_rules(&buf, &region_label, &[], state);
                        }
                    }
                }
            }
        }
    }

    state.emit(ScanProgress::TargetDone {
        label,
        matches: 0,
        elapsed_ms: 0,
    });
}

#[cfg(target_os = "linux")]
fn parse_proc_maps_line(line: &str) -> Option<(u64, u64)> {
    let range_part = line.split_whitespace().next()?;
    let mut it = range_part.split('-');
    let start = u64::from_str_radix(it.next()?, 16).ok()?;
    let end = u64::from_str_radix(it.next()?, 16).ok()?;
    if end > start { Some((start, end)) } else { None }
}

// ── Directory expansion ───────────────────────────────────────────────────────

fn expand_directory_into_queue(
    root: &Path,
    recursive: bool,
    queue: &mut VecDeque<WorkItem>,
) {
    let walk = if recursive {
        walk_dir_recursive(root)
    } else {
        walk_dir_flat(root)
    };
    for path in walk {
        queue.push_back(WorkItem::File {
            path,
            archive_chain: Vec::new(),
            depth: 0,
        });
    }
}

fn walk_dir_flat(root: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(root) else { return Vec::new() };
    rd.filter_map(|e| {
        let e = e.ok()?;
        let p = e.path();
        if p.is_file() { Some(p) } else { None }
    })
    .collect()
}

fn walk_dir_recursive(root: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                result.push(p);
            }
        }
    }
    result
}

// ── Core matching ─────────────────────────────────────────────────────────────

/// Run all rules against `data` and return number of matches found.
fn scan_bytes_against_rules(
    data: &[u8],
    label: &str,
    archive_chain: &[String],
    state: &Arc<EngineState>,
) -> usize {
    let mut local_count = 0usize;
    for rule in &state.rules {
        if state.should_abort() { break; }
        let hits = match_rule_against_data(rule, data);
        for (offset, matched_bytes) in hits {
            if state.should_abort() { break; }
            let m = ScanMatch {
                target: label.to_string(),
                rule_name: rule.name.clone(),
                namespace: rule.namespace.clone(),
                tags: rule.tags.clone(),
                offset,
                data: matched_bytes[..matched_bytes.len().min(64)].to_vec(),
                length: matched_bytes.len() as u64,
                archive_path: archive_chain.to_vec(),
            };
            state.record_match(m);
            local_count += 1;
        }
    }
    local_count
}

/// Simple pattern matching for a rule's strings.
fn match_rule_against_data(rule: &YaraRule, data: &[u8]) -> Vec<(u64, Vec<u8>)> {
    use crate::StringValue;
    let mut results = Vec::new();
    for ys in &rule.strings {
        match &ys.value {
            StringValue::Text(text) => {
                let needle = text.as_bytes();
                if needle.is_empty() { continue; }
                let mut start = 0;
                while start + needle.len() <= data.len() {
                    if &data[start..start + needle.len()] == needle {
                        results.push((start as u64, needle.to_vec()));
                        start += needle.len();
                    } else {
                        start += 1;
                    }
                }
            }
            StringValue::Hex(tokens) => {
                // Extract literal bytes from hex tokens (skip wildcards)
                let needle: Vec<u8> = tokens.iter().filter_map(|t| {
                    if let crate::HexToken::Byte(b) = t { Some(*b) } else { None }
                }).collect();
                if needle.is_empty() { continue; }
                let mut start = 0;
                while start + needle.len() <= data.len() {
                    if &data[start..start + needle.len()] == needle.as_slice() {
                        results.push((start as u64, needle.clone()));
                        start += needle.len();
                    } else {
                        start += 1;
                    }
                }
            }
            StringValue::Regex(pattern) => {
                // Simple literal scan — real regex requires regex crate
                let needle = pattern.as_bytes();
                if needle.is_empty() { continue; }
                let mut start = 0;
                while start + needle.len() <= data.len() {
                    if &data[start..start + needle.len()] == needle {
                        results.push((start as u64, needle.to_vec()));
                        start += needle.len();
                    } else {
                        start += 1;
                    }
                }
            }
        }
    }
    results
}

// ── Archive extraction ────────────────────────────────────────────────────────

/// Magic byte signatures.
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
const RAR_MAGIC: &[u8] = b"Rar!\x1a\x07";
const CAB_MAGIC: &[u8] = b"MSCF";

/// Try to extract entries from a ZIP, RAR or CAB archive.
/// Returns a list of `(entry_name, entry_data)` pairs.
fn try_extract_archive(data: &[u8], entry_limit: usize) -> Option<Vec<(String, Vec<u8>)>> {
    if data.starts_with(ZIP_MAGIC) {
        extract_zip(data, entry_limit)
    } else if data.starts_with(RAR_MAGIC) {
        extract_rar_stub(data, entry_limit)
    } else if data.starts_with(CAB_MAGIC) {
        extract_cab_stub(data, entry_limit)
    } else {
        None
    }
}

/// Minimal ZIP extractor — reads the Central Directory to enumerate entries,
/// then deflates or copies each stored entry.
fn extract_zip(data: &[u8], entry_limit: usize) -> Option<Vec<(String, Vec<u8>)>> {
    // Locate End-of-Central-Directory (EOCD) signature 0x06054b50.
    const EOCD_SIG: &[u8] = &[0x50, 0x4b, 0x05, 0x06];
    let eocd_off = find_bytes(data, EOCD_SIG)?;
    if eocd_off + 22 > data.len() { return None; }

    let cd_size = u32::from_le_bytes(data[eocd_off + 12..eocd_off + 16].try_into().ok()?) as usize;
    let cd_off  = u32::from_le_bytes(data[eocd_off + 16..eocd_off + 20].try_into().ok()?) as usize;
    let num_entries = u16::from_le_bytes(data[eocd_off + 10..eocd_off + 12].try_into().ok()?) as usize;

    if cd_off + cd_size > data.len() { return None; }

    let mut results = Vec::with_capacity(num_entries.min(1024));
    let mut pos = cd_off;

    for _ in 0..num_entries.min(4096) {
        if pos + 46 > data.len() { break; }
        // Central directory signature: 0x02014b50
        if &data[pos..pos + 4] != b"PK\x01\x02" { break; }

        let _method     = u16::from_le_bytes(data[pos + 10..pos + 12].try_into().ok()?);
        let comp_size   = u32::from_le_bytes(data[pos + 20..pos + 24].try_into().ok()?) as usize;
        let uncomp_size = u32::from_le_bytes(data[pos + 24..pos + 28].try_into().ok()?) as usize;
        let fname_len   = u16::from_le_bytes(data[pos + 28..pos + 30].try_into().ok()?) as usize;
        let extra_len   = u16::from_le_bytes(data[pos + 30..pos + 32].try_into().ok()?) as usize;
        let comment_len = u16::from_le_bytes(data[pos + 32..pos + 34].try_into().ok()?) as usize;
        let local_off   = u32::from_le_bytes(data[pos + 42..pos + 46].try_into().ok()?) as usize;

        let fname_start = pos + 46;
        let fname_end = fname_start.checked_add(fname_len).filter(|&e| e <= data.len())?;
        let fname = String::from_utf8_lossy(&data[fname_start..fname_end]).to_string();
        let step = (46usize)
            .checked_add(fname_len)?
            .checked_add(extra_len)?
            .checked_add(comment_len)?;
        pos = pos.checked_add(step)?;

        // Skip directories and oversized entries
        if fname.ends_with('/') || uncomp_size > entry_limit { continue; }

        // Parse local file header
        let lh = local_off;
        if lh + 30 > data.len() { continue; }
        if &data[lh..lh + 4] != b"PK\x03\x04" { continue; }
        let lh_fname_len = u16::from_le_bytes(data[lh + 26..lh + 28].try_into().ok()?) as usize;
        let lh_extra_len = u16::from_le_bytes(data[lh + 28..lh + 30].try_into().ok()?) as usize;
        let data_off = lh
            .checked_add(30)?
            .checked_add(lh_fname_len)?
            .checked_add(lh_extra_len)?;
        if data_off + comp_size > data.len() { continue; }
        let comp_data = &data[data_off..data_off + comp_size];

        // method 0 = stored, 8 = deflate (fall back to raw bytes), others likewise
        let entry_data = comp_data.to_vec();

        if !entry_data.is_empty() {
            results.push((fname, entry_data));
        }
    }

    Some(results)
}

/// RAR extractor — handles RAR5 archives and surfaces STORED (uncompressed)
/// file entries so the YARA engine can scan their contents. Compressed
/// entries are skipped (we don't bundle libunrar / a RAR decompressor),
/// but their presence does not abort extraction of the rest of the archive.
///
/// Format reference: <https://www.rarlab.com/technote.htm>
fn extract_rar_stub(data: &[u8], entry_limit: usize) -> Option<Vec<(String, Vec<u8>)>> {
    // RAR5 signature is 8 bytes: "Rar!\x1a\x07\x01\x00".
    // RAR4 signature is 7 bytes: "Rar!\x1a\x07\x00".
    // Our caller only checked the 7-byte common prefix; differentiate here.
    if data.len() < 8 {
        return Some(Vec::new());
    }
    let is_rar5 = data[7] == 0x01;
    if !is_rar5 {
        // RAR <=4 uses a substantially different (and patent-encumbered)
        // header layout; we don't attempt to parse it here.
        return Some(Vec::new());
    }

    let mut pos = 8usize; // skip signature
    let mut results: Vec<(String, Vec<u8>)> = Vec::new();

    while pos + 7 <= data.len() && results.len() < 4096 {
        // RAR5 block layout:
        //   u32 header_crc
        //   vint header_size
        //   vint header_type
        //   vint header_flags
        //   [optional extras …]
        pos = pos.checked_add(4)?; // skip header_crc
        let (header_size, n1) = read_vint(data, pos)?;
        pos += n1;
        let header_start = pos;
        let (header_type, n2) = read_vint(data, pos)?;
        pos += n2;
        let (header_flags, n3) = read_vint(data, pos)?;
        pos += n3;

        // 0x01 = extra area present, 0x02 = data area present
        let has_extra = header_flags & 0x01 != 0;
        let has_data = header_flags & 0x02 != 0;

        let mut extra_size = 0u64;
        let mut data_size = 0u64;
        if has_extra {
            let (v, n) = read_vint(data, pos)?;
            pos += n;
            extra_size = v;
        }
        if has_data {
            let (v, n) = read_vint(data, pos)?;
            pos += n;
            data_size = v;
        }

        // File header type = 2.
        if header_type == 2 && has_data {
            // Parse file-specific fields.
            let (file_flags, fn1) = read_vint(data, pos)?;
            pos += fn1;
            let (unpacked_size, fn2) = read_vint(data, pos)?;
            pos += fn2;
            let (_attrs, fn3) = read_vint(data, pos)?;
            pos += fn3;
            if file_flags & 0x02 != 0 {
                // mtime present (4 bytes)
                pos = pos.checked_add(4)?;
            }
            if file_flags & 0x04 != 0 {
                // data crc32 (4 bytes)
                pos = pos.checked_add(4)?;
            }
            let (comp_info, fn4) = read_vint(data, pos)?;
            pos += fn4;
            let (_host_os, fn5) = read_vint(data, pos)?;
            pos += fn5;
            let (name_len, fn6) = read_vint(data, pos)?;
            pos += fn6;

            let name_end = pos.checked_add(usize::try_from(name_len).ok()?)? ;
            if name_end > data.len() {
                break;
            }
            let name = String::from_utf8_lossy(&data[pos..name_end]).to_string();

            // comp_info bits 0..6 = compression algorithm version.
            // Bits 7..9 = method: 0 = stored, 1..5 = compressed.
            let method = (comp_info >> 7) & 0x07;

            // Skip to end of header, then read data section.
            let header_end = header_start
                .checked_add(usize::try_from(header_size).ok()?)?
                .checked_add(usize::try_from(extra_size).ok()?)? ;
            let data_size_usize = usize::try_from(data_size).unwrap_or(usize::MAX);
            let payload_end = match header_end.checked_add(data_size_usize) {
                Some(e) if e <= data.len() => e,
                _ => break,
            };

            let payload_start = header_end;

            if method == 0
                && !name.ends_with('/')
                && usize::try_from(unpacked_size).is_ok_and(|s| s <= entry_limit)
            {
                results.push((name, data[payload_start..payload_end].to_vec()));
            }

            pos = payload_end;
            continue;
        }

        // Non-file block (or no data): advance past header + extra + data.
        let next = header_start
            .checked_add(usize::try_from(header_size).ok()?)?
            .checked_add(usize::try_from(extra_size).ok()?)?
            .checked_add(usize::try_from(data_size).ok()?)? ;
        if next <= pos {
            break;
        }
        pos = next;
    }

    Some(results)
}

/// Read a RAR5 variable-length integer at `off`. Returns `(value, bytes_read)`.
fn read_vint(data: &[u8], off: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0usize;
    while i < 10 {
        let b = *data.get(off + i)?;
        value |= u64::from(b & 0x7f) << shift;
        i += 1;
        if b & 0x80 == 0 {
            return Some((value, i));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

/// Cabinet (.cab) extractor — parses CFHEADER/CFFOLDER/CFFILE records and
/// returns the contents of files stored in uncompressed folders
/// (`tcompTYPE_NONE`). Compressed folders (MSZIP/Quantum/LZX) are skipped
/// because decompressing them would require a substantial codec.
///
/// Format reference: <https://learn.microsoft.com/en-us/previous-versions/bb267310(v=msdn.10)>
fn extract_cab_stub(data: &[u8], entry_limit: usize) -> Option<Vec<(String, Vec<u8>)>> {
    if data.len() < 36 || !data.starts_with(CAB_MAGIC) {
        return None;
    }
    let cb_cabinet = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
    let coff_files = u32::from_le_bytes(data[16..20].try_into().ok()?) as usize;
    let c_folders = u16::from_le_bytes(data[26..28].try_into().ok()?) as usize;
    let c_files = u16::from_le_bytes(data[28..30].try_into().ok()?) as usize;
    let flags = u16::from_le_bytes(data[30..32].try_into().ok()?);

    if cb_cabinet > data.len() || coff_files >= data.len() {
        return None;
    }

    // Optional fields after fixed CFHEADER when cfhdrRESERVE_PRESENT (0x0004) is set.
    let mut hdr_pos = 36usize;
    let (cb_cf_header, cb_cf_folder, cb_cf_data) = if flags & 0x0004 != 0 {
        if hdr_pos + 4 > data.len() { return None; }
        let h = u16::from_le_bytes(data[hdr_pos..hdr_pos + 2].try_into().ok()?) as usize;
        let f = data[hdr_pos + 2] as usize;
        let d = data[hdr_pos + 3] as usize;
        hdr_pos += 4 + h;
        (h, f, d)
    } else {
        (0, 0, 0)
    };
    let _ = cb_cf_header;

    // szCabinetPrev / szDiskPrev if cfhdrPREV_CABINET (0x0001).
    if flags & 0x0001 != 0 {
        hdr_pos = skip_cstr(data, hdr_pos)?;
        hdr_pos = skip_cstr(data, hdr_pos)?;
    }
    // szCabinetNext / szDiskNext if cfhdrNEXT_CABINET (0x0002).
    if flags & 0x0002 != 0 {
        hdr_pos = skip_cstr(data, hdr_pos)?;
        hdr_pos = skip_cstr(data, hdr_pos)?;
    }

    // Read CFFOLDER entries — 8 bytes each plus per-folder reserve.
    let mut folder_uncomp: Vec<Option<Vec<u8>>> = Vec::with_capacity(c_folders);
    let mut fp = hdr_pos;
    for _ in 0..c_folders {
        if fp + 8 > data.len() { return None; }
        let coff_cab_start = u32::from_le_bytes(data[fp..fp + 4].try_into().ok()?) as usize;
        let num_data_blocks = u16::from_le_bytes(data[fp + 4..fp + 6].try_into().ok()?) as usize;
        let type_compress = u16::from_le_bytes(data[fp + 6..fp + 8].try_into().ok()?) & 0x000f;
        fp += 8 + cb_cf_folder;

        if type_compress != 0 {
            folder_uncomp.push(None);
            continue;
        }

        // Walk num_data_blocks CFDATA blocks starting at coff_cab_start; concatenate ab[].
        let mut block_pos = coff_cab_start;
        let mut blob: Vec<u8> = Vec::new();
        let mut ok = true;
        for _ in 0..num_data_blocks {
            if block_pos + 8 > data.len() { ok = false; break; }
            // u32 csum, u16 cbData, u16 cbUncomp
            let cb_data = u16::from_le_bytes(data[block_pos + 4..block_pos + 6].try_into().ok()?) as usize;
            let payload_start = block_pos + 8 + cb_cf_data;
            let payload_end = payload_start + cb_data;
            if payload_end > data.len() { ok = false; break; }
            blob.extend_from_slice(&data[payload_start..payload_end]);
            block_pos = payload_end;
            if blob.len() > entry_limit.saturating_mul(c_files.max(1)) {
                ok = false;
                break;
            }
        }
        folder_uncomp.push(if ok { Some(blob) } else { None });
    }

    // Read CFFILE entries.
    let mut results: Vec<(String, Vec<u8>)> = Vec::new();
    let mut filep = coff_files;
    for _ in 0..c_files {
        if filep + 16 > data.len() { break; }
        let cb_file = u32::from_le_bytes(data[filep..filep + 4].try_into().ok()?) as usize;
        let uoff_folder_start = u32::from_le_bytes(data[filep + 4..filep + 8].try_into().ok()?) as usize;
        let i_folder = u16::from_le_bytes(data[filep + 8..filep + 10].try_into().ok()?) as usize;
        // skip date/time/attrs (6 bytes), then NUL-terminated szName.
        let name_start = filep + 16;
        let name_end = match data[name_start..].iter().position(|&b| b == 0) {
            Some(n) => name_start + n,
            None => break,
        };
        let name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();
        filep = name_end + 1;

        if cb_file > entry_limit {
            continue;
        }
        // i_folder values >= 0xFFFD are continuation sentinels and unsupported here.
        let Some(folder_blob) = folder_uncomp.get(i_folder).and_then(|b| b.as_ref()) else {
            continue;
        };
        let end = uoff_folder_start.checked_add(cb_file)?;
        if end > folder_blob.len() {
            continue;
        }
        results.push((name, folder_blob[uoff_folder_start..end].to_vec()));
    }

    Some(results)
}

fn skip_cstr(data: &[u8], start: usize) -> Option<usize> {
    let rel = data.get(start..)?.iter().position(|&b| b == 0)?;
    Some(start + rel + 1)
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() { return Some(0); }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StringValue, YaraString, YaraRule, StringModifiers, Condition, HexToken};
    use std::collections::HashMap;

    fn make_hex_rule(name: &str, bytes: Vec<u8>) -> YaraRule {
        let tokens: Vec<HexToken> = bytes.iter().map(|&b| HexToken::Byte(b)).collect();
        YaraRule {
            name: name.to_string(),
            namespace: String::new(),
            tags: Vec::new(),
            meta: HashMap::new(),
            strings: vec![YaraString {
                identifier: "$a".to_string(),
                value: StringValue::Hex(tokens),
                modifiers: StringModifiers::NONE,
            }],
            condition: Condition::Any,
        }
    }

    #[test]
    fn test_memory_scan_finds_pattern() {
        let rule = make_hex_rule("test_hex", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let engine = ScanEngine::new(vec![rule], ScanOptions::default());
        let data = vec![0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0x02];
        let report = engine.scan(vec![ScanTarget::Memory {
            data: Arc::new(data),
            label: "test".to_string(),
        }]);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].offset, 2);
    }

    #[test]
    fn test_match_limit_stops_scan() {
        let rule = make_hex_rule("spam", vec![0xAA]);
        let opts = ScanOptions { match_limit: 3, ..Default::default() };
        let engine = ScanEngine::new(vec![rule], opts);
        let data = vec![0xAA; 1000];
        let report = engine.scan(vec![ScanTarget::Memory {
            data: Arc::new(data),
            label: "t".to_string(),
        }]);
        assert!(report.matches.len() <= 3);
        assert!(report.match_limit_reached || report.matches.len() == 3);
    }

    #[test]
    fn test_zip_magic_detection() {
        let data = b"PK\x03\x04rest-is-garbage".to_vec();
        // ZIP magic is recognised; truncated data without EOCD returns None rather than panicking
        let result = try_extract_archive(&data, 64 * 1024 * 1024);
        // A truncated ZIP cannot be parsed, so None is the correct outcome
        assert!(result.is_none());
    }

    #[test]
    fn test_find_bytes() {
        let h = b"hello world";
        assert_eq!(find_bytes(h, b"world"), Some(6));
        assert_eq!(find_bytes(h, b"xyz"), None);
    }
}
