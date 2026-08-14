//! `file_monitor` — Filemon/ProcMon filesystem equivalent
//!
//! Intercept filesystem operations, I/O stack tracing, filter by process/path/extension,
//! event streaming with timestamps.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::SysinternalsError;

/// Convert `u64` to `f64` via two `u32` halves to avoid precision-loss cast.
fn u64_to_f64(x: u64) -> f64 {
    let lo = u32::try_from(x & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    let hi = u32::try_from(x >> 32).unwrap_or(u32::MAX);
    f64::from(hi).mul_add(4_294_967_296.0_f64, f64::from(lo))
}

// ─── Global sequence counter ──────────────────────────────────────────────────

static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn next_sequence() -> u64 {
    EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

fn unix_ts_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

// ─── FileOperation ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileOperation {
    Create,
    Open,
    Close,
    Read,
    Write,
    QueryInfo,
    SetInfo,
    Delete,
    Rename,
    DirectoryEnum,
    DirectoryNotify,
    Flush,
    Lock,
    Unlock,
    SetSecurity,
    QuerySecurity,
    CreateHardLink,
    CreateSymLink,
    Truncate,
    Append,
}

impl fmt::Display for FileOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Create => "Create",
            Self::Open => "Open",
            Self::Close => "Close",
            Self::Read => "Read",
            Self::Write => "Write",
            Self::QueryInfo => "QueryInfo",
            Self::SetInfo => "SetInfo",
            Self::Delete => "Delete",
            Self::Rename => "Rename",
            Self::DirectoryEnum => "DirectoryEnum",
            Self::DirectoryNotify => "DirectoryNotify",
            Self::Flush => "Flush",
            Self::Lock => "Lock",
            Self::Unlock => "Unlock",
            Self::SetSecurity => "SetSecurity",
            Self::QuerySecurity => "QuerySecurity",
            Self::CreateHardLink => "CreateHardLink",
            Self::CreateSymLink => "CreateSymLink",
            Self::Truncate => "Truncate",
            Self::Append => "Append",
        };
        write!(f, "{s}")
    }
}

// ─── OperationResult ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationResult {
    Success,
    AccessDenied,
    NotFound,
    PathNotFound,
    AlreadyExists,
    SharingViolation,
    DiskFull,
    Timeout,
    InvalidParameter,
    NotSupported,
    Unknown(u32),
}

impl fmt::Display for OperationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "SUCCESS"),
            Self::AccessDenied => write!(f, "ACCESS_DENIED"),
            Self::NotFound => write!(f, "NOT_FOUND"),
            Self::PathNotFound => write!(f, "PATH_NOT_FOUND"),
            Self::AlreadyExists => write!(f, "ALREADY_EXISTS"),
            Self::SharingViolation => write!(f, "SHARING_VIOLATION"),
            Self::DiskFull => write!(f, "DISK_FULL"),
            Self::Timeout => write!(f, "TIMEOUT"),
            Self::InvalidParameter => write!(f, "INVALID_PARAMETER"),
            Self::NotSupported => write!(f, "NOT_SUPPORTED"),
            Self::Unknown(code) => write!(f, "0x{code:08X}"),
        }
    }
}

impl OperationResult {
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }

    #[must_use]
    pub const fn from_ntstatus(status: u32) -> Self {
        match status {
            0x0000_0000 => Self::Success,
            0xC000_0022 => Self::AccessDenied,
            0xC000_0034 => Self::NotFound,
            0xC000_0003 | 0xC000_003A => Self::PathNotFound,
            0xC000_0035 => Self::AlreadyExists,
            0xC000_0043 => Self::SharingViolation,
            0xC000_007F => Self::DiskFull,
            0xC000_0102 => Self::Timeout,
            0xC000_000D => Self::InvalidParameter,
            0xC000_0002 => Self::NotSupported,
            other => Self::Unknown(other),
        }
    }
}

// ─── IoStack ─────────────────────────────────────────────────────────────────

/// An I/O stack frame captured for detailed call tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoStackFrame {
    /// Driver name or "ntfs.sys", "fastfat.sys", etc.
    pub driver: String,
    /// Duration spent in this driver layer in microseconds.
    pub duration_us: u64,
    /// NTSTATUS returned from this layer.
    pub status: u32,
    /// Optional annotation.
    pub note: String,
}

impl IoStackFrame {
    #[must_use]
    pub fn new(driver: impl Into<String>, duration_us: u64, status: u32) -> Self {
        Self {
            driver: driver.into(),
            duration_us,
            status,
            note: String::new(),
        }
    }
}

// ─── FileEventFlags ───────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct FileEventFlags: u32 {
        const NONE           = 0;
        const WRITE_THROUGH  = 1;
        const SEQUENTIAL     = 2;
        const NO_BUFFERING   = 4;
        const OVERLAPPED     = 8;
        const DELETE_ON_CLOSE = 16;
        const DIRECTORY      = 32;
        const REPARSE_POINT  = 64;
        const CACHED         = 128;
        const ENCRYPTED      = 256;
    }
}

// ─── FileEvent ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Timestamp in microseconds since UNIX epoch.
    pub timestamp_us: u64,
    /// Duration of the operation in microseconds.
    pub duration_us: u64,
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Process name.
    pub process_name: String,
    /// File system operation.
    pub operation: FileOperation,
    /// Full path to the target file or directory.
    pub path: String,
    /// Operation result.
    pub result: OperationResult,
    /// Bytes transferred (for read/write).
    pub bytes_transferred: u64,
    /// Byte offset for read/write operations.
    pub offset: u64,
    /// Additional detail (rename target, query class, etc.).
    pub detail: String,
    /// I/O flags.
    pub flags: FileEventFlags,
    /// I/O stack trace (optional, populated for detailed mode).
    pub io_stack: Vec<IoStackFrame>,
    /// File size at time of event (if known).
    pub file_size: Option<u64>,
}

impl FileEvent {
    #[must_use]
    pub fn new(
        pid: u32,
        tid: u32,
        process_name: impl Into<String>,
        operation: FileOperation,
        path: impl Into<String>,
        result: OperationResult,
    ) -> Self {
        Self {
            sequence: next_sequence(),
            timestamp_us: unix_ts_micros(),
            duration_us: 0,
            pid,
            tid,
            process_name: process_name.into(),
            operation,
            path: path.into(),
            result,
            bytes_transferred: 0,
            offset: 0,
            detail: String::new(),
            flags: FileEventFlags::NONE,
            io_stack: Vec::new(),
            file_size: None,
        }
    }

    /// Return the file extension of the path (lowercase).
    #[must_use]
    pub fn extension(&self) -> String {
        Path::new(&self.path)
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_lowercase)
            .unwrap_or_default()
    }

    /// Return the filename component.
    #[must_use]
    pub fn filename(&self) -> String {
        Path::new(&self.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned()
    }

    /// CSV row.
    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{}",
            self.sequence,
            self.timestamp_us,
            self.pid,
            crate::csv_field(&self.process_name),
            self.operation,
            self.result,
            self.bytes_transferred,
            self.duration_us,
            crate::csv_field(&self.path),
        )
    }
}

// ─── EventFilter ──────────────────────────────────────────────────────────────

/// Composable filter for `FileEvent` streams.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// If set, only events from these PIDs pass.
    pub pids: Vec<u32>,
    /// If set, only events where the path starts with one of these prefixes.
    pub path_prefixes: Vec<String>,
    /// If set, only events with these file extensions (lowercase, no dot).
    pub extensions: Vec<String>,
    /// If set, only these operations pass.
    pub operations: Vec<FileOperation>,
    /// If set, only events with this result pass.
    pub results: Vec<OperationResult>,
    /// If set, only events with process name matching this substring.
    pub process_name_contains: Option<String>,
    /// If set, exclude events with paths matching these substrings.
    pub path_excludes: Vec<String>,
    /// If set, only events longer than this duration pass (slow I/O filter).
    pub min_duration_us: Option<u64>,
}

impl EventFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Test if an event passes the filter.
    #[must_use]
    pub fn matches(&self, event: &FileEvent) -> bool {
        if !self.pids.is_empty() && !self.pids.contains(&event.pid) {
            return false;
        }
        if !self.path_prefixes.is_empty()
            && !self
                .path_prefixes
                .iter()
                .any(|p| event.path.starts_with(p.as_str()))
        {
            return false;
        }
        if !self.extensions.is_empty() {
            let ext = event.extension();
            if !self.extensions.iter().any(|e| e == &ext) {
                return false;
            }
        }
        if !self.operations.is_empty() && !self.operations.contains(&event.operation) {
            return false;
        }
        if !self.results.is_empty() && !self.results.contains(&event.result) {
            return false;
        }
        if let Some(ref sub) = self.process_name_contains
            && !event
                .process_name
                .to_lowercase()
                .contains(sub.to_lowercase().as_str())
        {
            return false;
        }
        if self
            .path_excludes
            .iter()
            .any(|ex| event.path.contains(ex.as_str()))
        {
            return false;
        }
        if let Some(min_dur) = self.min_duration_us
            && event.duration_us < min_dur
        {
            return false;
        }
        true
    }

    #[must_use]
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pids.push(pid);
        self
    }

    #[must_use]
    pub fn with_extension(mut self, ext: impl Into<String>) -> Self {
        self.extensions.push(ext.into());
        self
    }

    #[must_use]
    pub fn with_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.path_prefixes.push(prefix.into());
        self
    }

    #[must_use]
    pub fn with_operation(mut self, op: FileOperation) -> Self {
        self.operations.push(op);
        self
    }

    #[must_use]
    pub fn with_result(mut self, r: OperationResult) -> Self {
        self.results.push(r);
        self
    }

    #[must_use]
    pub fn with_process_name(mut self, name: impl Into<String>) -> Self {
        self.process_name_contains = Some(name.into());
        self
    }

    #[must_use]
    pub fn exclude_path(mut self, path: impl Into<String>) -> Self {
        self.path_excludes.push(path.into());
        self
    }

    #[must_use]
    pub const fn with_min_duration_us(mut self, us: u64) -> Self {
        self.min_duration_us = Some(us);
        self
    }
}

// ─── PathAccessSummary ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathAccessSummary {
    pub path: String,
    pub read_count: u64,
    pub write_count: u64,
    pub delete_count: u64,
    pub other_count: u64,
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    pub process_pids: Vec<u32>,
    pub last_access_us: u64,
}

impl PathAccessSummary {
    pub fn record(&mut self, event: &FileEvent) {
        match event.operation {
            FileOperation::Read => {
                self.read_count += 1;
                self.total_bytes_read += event.bytes_transferred;
            }
            FileOperation::Write | FileOperation::Append => {
                self.write_count += 1;
                self.total_bytes_written += event.bytes_transferred;
            }
            FileOperation::Delete => {
                self.delete_count += 1;
            }
            _ => {
                self.other_count += 1;
            }
        }
        if !self.process_pids.contains(&event.pid) {
            self.process_pids.push(event.pid);
        }
        if event.timestamp_us > self.last_access_us {
            self.last_access_us = event.timestamp_us;
        }
    }

    #[must_use]
    pub const fn total_accesses(&self) -> u64 {
        self.read_count + self.write_count + self.delete_count + self.other_count
    }

    #[must_use]
    pub const fn is_hotspot(&self, threshold: u64) -> bool {
        self.total_accesses() >= threshold
    }
}

// ─── ProcessFileSummary ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessFileSummary {
    pub pid: u32,
    pub process_name: String,
    pub files_opened: u64,
    pub files_created: u64,
    pub files_deleted: u64,
    pub files_read: u64,
    pub files_written: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub unique_paths: std::collections::HashSet<String>,
    pub error_count: u64,
}

impl ProcessFileSummary {
    pub fn record(&mut self, event: &FileEvent) {
        self.unique_paths.insert(event.path.clone());
        match event.operation {
            FileOperation::Open => self.files_opened += 1,
            FileOperation::Create => self.files_created += 1,
            FileOperation::Delete => self.files_deleted += 1,
            FileOperation::Read => {
                self.files_read += 1;
                self.bytes_read += event.bytes_transferred;
            }
            FileOperation::Write | FileOperation::Append => {
                self.files_written += 1;
                self.bytes_written += event.bytes_transferred;
            }
            _ => {}
        }
        if !event.result.is_success() {
            self.error_count += 1;
        }
    }
}

// ─── FileMonitorRingBuffer ────────────────────────────────────────────────────

/// Ring buffer for file events with configurable capacity.
pub struct FileMonitorRingBuffer {
    capacity: usize,
    buffer: VecDeque<FileEvent>,
}

impl FileMonitorRingBuffer {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            buffer: VecDeque::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, event: FileEvent) {
        if self.buffer.len() >= self.capacity {
            self.buffer.pop_front();
        }
        self.buffer.push_back(event);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &FileEvent> {
        self.buffer.iter()
    }

    pub fn drain_filtered(&mut self, filter: &EventFilter) -> Vec<FileEvent> {
        let mut keep = VecDeque::new();
        let mut result = Vec::new();
        while let Some(ev) = self.buffer.pop_front() {
            if filter.matches(&ev) {
                result.push(ev);
            } else {
                keep.push_back(ev);
            }
        }
        self.buffer = keep;
        result
    }

    /// Return all events matching the filter (does not remove).
    #[must_use]
    pub fn query(&self, filter: &EventFilter) -> Vec<&FileEvent> {
        self.buffer.iter().filter(|e| filter.matches(e)).collect()
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

// ─── IoPipeline ──────────────────────────────────────────────────────────────

/// A simulated I/O filter pipeline: events pass through a series of transformers.
pub trait IoEventTransformer: Send + Sync {
    fn transform(&self, event: &mut FileEvent);
    fn name(&self) -> &'static str;
}

pub struct IoPipeline {
    transformers: Vec<Box<dyn IoEventTransformer>>,
}

impl IoPipeline {
    #[must_use]
    pub fn new() -> Self {
        Self {
            transformers: Vec::new(),
        }
    }

    pub fn add<T: IoEventTransformer + 'static>(&mut self, t: T) {
        self.transformers.push(Box::new(t));
    }

    pub fn process(&self, event: &mut FileEvent) {
        for t in &self.transformers {
            t.transform(event);
        }
    }
}

impl Default for IoPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Built-in transformer: marks events longer than a threshold as "slow".
pub struct SlowIoAnnotator {
    threshold_us: u64,
}

impl SlowIoAnnotator {
    #[must_use]
    pub const fn new(threshold_us: u64) -> Self {
        Self { threshold_us }
    }
}

impl IoEventTransformer for SlowIoAnnotator {
    fn transform(&self, event: &mut FileEvent) {
        if event.duration_us >= self.threshold_us {
            use std::fmt::Write as _;
            let _ = write!(event.detail, " [SLOW: {}µs]", event.duration_us);
        }
    }

    fn name(&self) -> &'static str {
        "SlowIoAnnotator"
    }
}

/// Built-in transformer: tags events with known sensitive paths.
pub struct SensitivePathAnnotator;

const SENSITIVE_PATHS: &[&str] = &[
    "\\Windows\\System32\\",
    "\\Windows\\SysWOW64\\",
    "\\Program Files\\",
    "\\WINDOWS\\",
    "C:\\Users\\",
    "\\AppData\\Roaming\\Microsoft\\",
    "\\Local Settings\\Temp\\",
    "\\SAM",
    "\\SYSTEM",
    "\\SECURITY",
    "\\ntds.dit",
    "lsass",
];

impl IoEventTransformer for SensitivePathAnnotator {
    fn transform(&self, event: &mut FileEvent) {
        for &s in SENSITIVE_PATHS {
            if event.path.contains(s) {
                event.detail.push_str(" [SENSITIVE]");
                break;
            }
        }
    }

    fn name(&self) -> &'static str {
        "SensitivePathAnnotator"
    }
}

// ─── FileMonitor ──────────────────────────────────────────────────────────────

/// Main file monitor — accepts injected events, applies pipeline, stores in ring buffer.
pub struct FileMonitor {
    buffer: FileMonitorRingBuffer,
    pipeline: IoPipeline,
    filter: EventFilter,
    path_summaries: HashMap<String, PathAccessSummary>,
    process_summaries: HashMap<u32, ProcessFileSummary>,
    total_events: u64,
    started_at: Instant,
    /// Paths that triggered an alert.
    alerts: Vec<String>,
}

impl FileMonitor {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let mut pipeline = IoPipeline::new();
        pipeline.add(SlowIoAnnotator::new(10_000)); // 10ms
        pipeline.add(SensitivePathAnnotator);
        Self {
            buffer: FileMonitorRingBuffer::new(capacity),
            pipeline,
            filter: EventFilter::new(),
            path_summaries: HashMap::new(),
            process_summaries: HashMap::new(),
            total_events: 0,
            started_at: Instant::now(),
            alerts: Vec::new(),
        }
    }

    pub fn set_filter(&mut self, filter: EventFilter) {
        self.filter = filter;
    }

    /// Ingest a file event (called by the platform driver shim).
    pub fn ingest(&mut self, mut event: FileEvent) {
        self.pipeline.process(&mut event);
        self.total_events += 1;

        // Update path summary.
        let path_summary = self
            .path_summaries
            .entry(event.path.clone())
            .or_insert_with(|| PathAccessSummary {
                path: event.path.clone(),
                ..Default::default()
            });
        path_summary.record(&event);

        // Check for hotspot alert.
        if path_summary.is_hotspot(1000) && !self.alerts.contains(&event.path) {
            self.alerts.push(event.path.clone());
        }

        // Update process summary.
        let proc_summary = self
            .process_summaries
            .entry(event.pid)
            .or_insert_with(|| ProcessFileSummary {
                pid: event.pid,
                process_name: event.process_name.clone(),
                ..Default::default()
            });
        proc_summary.record(&event);

        if self.filter.matches(&event) {
            self.buffer.push(event);
        }
    }

    #[must_use]
    pub fn query(&self, filter: &EventFilter) -> Vec<&FileEvent> {
        self.buffer.query(filter)
    }

    #[must_use]
    pub const fn total_events(&self) -> u64 {
        self.total_events
    }

    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    #[must_use]
    pub fn events_per_second(&self) -> f64 {
        let elapsed = self.elapsed().as_secs_f64();
        if elapsed < 0.001 {
            0.0
        } else {
            u64_to_f64(self.total_events) / elapsed
        }
    }

    #[must_use]
    pub fn top_paths_by_access(&self, n: usize) -> Vec<&PathAccessSummary> {
        let mut v: Vec<&PathAccessSummary> = self.path_summaries.values().collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.total_accesses()));
        v.truncate(n);
        v
    }

    #[must_use]
    pub fn top_processes_by_writes(&self, n: usize) -> Vec<&ProcessFileSummary> {
        let mut v: Vec<&ProcessFileSummary> = self.process_summaries.values().collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.bytes_written));
        v.truncate(n);
        v
    }

    #[must_use]
    pub fn alerts(&self) -> &[String] {
        &self.alerts
    }

    /// Export buffer to CSV.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "Seq,TimestampUs,PID,Process,Operation,Result,Bytes,DurationUs,Path\n",
        );
        for ev in self.buffer.iter() {
            out.push_str(&ev.to_csv_row());
            out.push('\n');
        }
        out
    }

    /// # Errors
    /// Returns an error if the underlying operation fails.
    /// Export buffer to JSON.
    pub fn to_json(&self) -> Result<String, SysinternalsError> {
        let events: Vec<&FileEvent> = self.buffer.iter().collect();
        serde_json::to_string_pretty(&events)
            .map_err(|e| SysinternalsError::InvalidData(e.to_string()))
    }
}

// ─── FileTimeline ─────────────────────────────────────────────────────────────

/// Reconstructs a timeline of file access for a given path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTimelineEntry {
    pub timestamp_us: u64,
    pub pid: u32,
    pub process_name: String,
    pub operation: FileOperation,
    pub result: OperationResult,
    pub bytes: u64,
    pub duration_us: u64,
}

pub struct FileTimeline;

impl FileTimeline {
    /// Build a timeline for a specific path from a collection of events.
    #[must_use]
    pub fn for_path<'a>(
        path: &str,
        events: impl Iterator<Item = &'a FileEvent>,
    ) -> Vec<FileTimelineEntry> {
        let mut entries: Vec<FileTimelineEntry> = events
            .filter(|e| e.path == path)
            .map(|e| FileTimelineEntry {
                timestamp_us: e.timestamp_us,
                pid: e.pid,
                process_name: e.process_name.clone(),
                operation: e.operation,
                result: e.result,
                bytes: e.bytes_transferred,
                duration_us: e.duration_us,
            })
            .collect();
        entries.sort_by_key(|e| e.timestamp_us);
        entries
    }

    /// Group timeline entries into time buckets of `bucket_us` microseconds.
    #[must_use]
    pub fn bucket(entries: &[FileTimelineEntry], bucket_us: u64) -> HashMap<u64, usize> {
        let mut buckets = HashMap::new();
        for entry in entries {
            let bucket = (entry.timestamp_us / bucket_us) * bucket_us;
            *buckets.entry(bucket).or_default() += 1;
        }
        buckets
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(pid: u32, op: FileOperation, path: &str, result: OperationResult) -> FileEvent {
        FileEvent::new(pid, pid * 10, "test.exe", op, path, result)
    }

    #[test]
    fn test_file_event_extension() {
        let ev = make_event(1, FileOperation::Read, "C:\\data\\file.TXT", OperationResult::Success);
        assert_eq!(ev.extension(), "txt");
    }

    #[test]
    fn test_file_event_filename() {
        let ev = make_event(1, FileOperation::Write, "C:\\data\\file.bin", OperationResult::Success);
        assert_eq!(ev.filename(), "file.bin");
    }

    #[test]
    fn test_event_filter_by_pid() {
        let filter = EventFilter::new().with_pid(42);
        let ev1 = make_event(42, FileOperation::Read, "C:\\x", OperationResult::Success);
        let ev2 = make_event(99, FileOperation::Read, "C:\\x", OperationResult::Success);
        assert!(filter.matches(&ev1));
        assert!(!filter.matches(&ev2));
    }

    #[test]
    fn test_event_filter_by_extension() {
        let filter = EventFilter::new().with_extension("exe");
        let ev1 = make_event(1, FileOperation::Create, "C:\\malware.exe", OperationResult::Success);
        let ev2 = make_event(1, FileOperation::Create, "C:\\file.txt", OperationResult::Success);
        assert!(filter.matches(&ev1));
        assert!(!filter.matches(&ev2));
    }

    #[test]
    fn test_event_filter_by_operation() {
        let filter = EventFilter::new().with_operation(FileOperation::Write);
        let ev1 = make_event(1, FileOperation::Write, "C:\\x", OperationResult::Success);
        let ev2 = make_event(1, FileOperation::Read, "C:\\x", OperationResult::Success);
        assert!(filter.matches(&ev1));
        assert!(!filter.matches(&ev2));
    }

    #[test]
    fn test_event_filter_exclude_path() {
        let filter = EventFilter::new().exclude_path("\\Temp\\");
        let ev1 = make_event(1, FileOperation::Write, "C:\\Temp\\x.exe", OperationResult::Success);
        let ev2 = make_event(1, FileOperation::Write, "C:\\App\\x.exe", OperationResult::Success);
        assert!(!filter.matches(&ev1));
        assert!(filter.matches(&ev2));
    }

    #[test]
    fn test_event_filter_min_duration() {
        let filter = EventFilter::new().with_min_duration_us(5000);
        let mut ev1 = make_event(1, FileOperation::Read, "C:\\x", OperationResult::Success);
        ev1.duration_us = 10_000;
        let mut ev2 = make_event(1, FileOperation::Read, "C:\\x", OperationResult::Success);
        ev2.duration_us = 1_000;
        assert!(filter.matches(&ev1));
        assert!(!filter.matches(&ev2));
    }

    #[test]
    fn test_ring_buffer_capacity() {
        let mut buf = FileMonitorRingBuffer::new(3);
        for i in 0u32..5 {
            buf.push(make_event(i, FileOperation::Read, "C:\\x", OperationResult::Success));
        }
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn test_ring_buffer_query() {
        let mut buf = FileMonitorRingBuffer::new(100);
        buf.push(make_event(1, FileOperation::Write, "C:\\a.exe", OperationResult::Success));
        buf.push(make_event(2, FileOperation::Read, "C:\\b.txt", OperationResult::Success));
        let filter = EventFilter::new().with_extension("exe");
        let results = buf.query(&filter);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_file_monitor_ingest_and_query() {
        let mut monitor = FileMonitor::new(100);
        monitor.ingest(make_event(1, FileOperation::Write, "C:\\evil.exe", OperationResult::Success));
        monitor.ingest(make_event(2, FileOperation::Read, "C:\\data.txt", OperationResult::Success));
        assert_eq!(monitor.total_events(), 2);
        let filter = EventFilter::new().with_pid(1);
        let results = monitor.query(&filter);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_file_monitor_csv() {
        let mut monitor = FileMonitor::new(10);
        monitor.ingest(make_event(1, FileOperation::Read, "C:\\x", OperationResult::Success));
        let csv = monitor.to_csv();
        assert!(csv.contains("Seq"));
        assert!(csv.contains("C:\\x"));
    }

    #[test]
    fn test_path_access_summary() {
        let mut summary = PathAccessSummary {
            path: "C:\\file".into(),
            ..Default::default()
        };
        let mut ev = make_event(1, FileOperation::Read, "C:\\file", OperationResult::Success);
        ev.bytes_transferred = 4096;
        summary.record(&ev);
        assert_eq!(summary.read_count, 1);
        assert_eq!(summary.total_bytes_read, 4096);
    }

    #[test]
    fn test_sensitive_path_annotator() {
        let annotator = SensitivePathAnnotator;
        let mut ev = make_event(1, FileOperation::Read, "C:\\Windows\\System32\\ntdll.dll", OperationResult::Success);
        annotator.transform(&mut ev);
        assert!(ev.detail.contains("[SENSITIVE]"));
    }

    #[test]
    fn test_slow_io_annotator() {
        let annotator = SlowIoAnnotator::new(5_000);
        let mut ev = make_event(1, FileOperation::Read, "C:\\x", OperationResult::Success);
        ev.duration_us = 10_000;
        annotator.transform(&mut ev);
        assert!(ev.detail.contains("SLOW"));
    }

    #[test]
    fn test_operation_result_from_ntstatus() {
        assert_eq!(OperationResult::from_ntstatus(0), OperationResult::Success);
        assert_eq!(OperationResult::from_ntstatus(0xC000_0022), OperationResult::AccessDenied);
        assert!(OperationResult::Success.is_success());
    }

    #[test]
    fn test_file_timeline_for_path() {
        let ev1 = make_event(1, FileOperation::Write, "C:\\target.bin", OperationResult::Success);
        let ev2 = make_event(2, FileOperation::Read, "C:\\other.bin", OperationResult::Success);
        let ev3 = make_event(3, FileOperation::Read, "C:\\target.bin", OperationResult::Success);
        let events = [ev1, ev2, ev3];
        let timeline = FileTimeline::for_path("C:\\target.bin", events.iter());
        assert_eq!(timeline.len(), 2);
    }
}
