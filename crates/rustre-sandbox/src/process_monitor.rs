//! Process monitor for sandboxed execution.
//!
//! Tracks syscalls, file accesses, and registry operations with timestamps,
//! providing a structured view of everything a sandboxed process does.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

// ── Timestamp helpers ─────────────────────────────────────────────────────────

/// Milliseconds since the monitor was started.
pub type TimestampMs = u64;

fn elapsed_ms(start: Instant) -> TimestampMs {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

// ── SyscallEvent ──────────────────────────────────────────────────────────────

/// Category of a syscall, used for quick filtering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallCategory {
    Memory,
    FileSystem,
    Process,
    Network,
    Registry,
    Synchronisation,
    Crypto,
    AntiDebug,
    Unknown,
}

impl SyscallCategory {
    /// Infer the category from the syscall name.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        if name.contains("Alloc")
            || name.contains("VirtualAlloc")
            || name.contains("MapView")
            || name.contains("Memory")
        {
            return Self::Memory;
        }
        if name.contains("File")
            || name.contains("Directory")
            || name.contains("Path")
            || name.contains("Open")
            || name.contains("Create")
            || name.contains("Delete")
            || name.contains("Write")
            || name.contains("Read")
        {
            return Self::FileSystem;
        }
        if name.contains("Process")
            || name.contains("Thread")
            || name.contains("Spawn")
            || name.contains("Exit")
        {
            return Self::Process;
        }
        if name.contains("Socket")
            || name.contains("Connect")
            || name.contains("Send")
            || name.contains("Recv")
            || name.contains("Http")
            || name.contains("Dns")
        {
            return Self::Network;
        }
        if name.contains("Reg")
            || name.contains("Key")
            || name.contains("Value")
            || name.contains("Hive")
        {
            return Self::Registry;
        }
        if name.contains("Mutex")
            || name.contains("Semaphore")
            || name.contains("Event")
            || name.contains("Wait")
            || name.contains("Lock")
        {
            return Self::Synchronisation;
        }
        if name.contains("Crypt") || name.contains("BCrypt") || name.contains("Hash") {
            return Self::Crypto;
        }
        if name.contains("Debugger")
            || name.contains("Debug")
            || name.contains("Timing")
            || name.contains("Yield")
        {
            return Self::AntiDebug;
        }
        Self::Unknown
    }
}

/// A single syscall event captured during sandboxed execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// Platform-specific syscall number.
    pub number: u32,
    /// Symbolic name (e.g. `"NtCreateFile"`).
    pub name: String,
    /// Inferred category.
    pub category: SyscallCategory,
    /// String representations of arguments (best-effort).
    pub args: Vec<String>,
    /// Return value (`None` if the call did not return within the trace window).
    pub return_value: Option<i64>,
    /// Timestamp in milliseconds since monitor start.
    pub timestamp_ms: TimestampMs,
    /// PID of the calling process.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Whether this event was flagged as suspicious.
    pub suspicious: bool,
    /// Optional human-readable note added during analysis.
    pub note: Option<String>,
}

impl SyscallEvent {
    /// Create a new event.
    #[must_use]
    pub fn new(number: u32, name: impl Into<String>, pid: u32, timestamp_ms: TimestampMs) -> Self {
        let name = name.into();
        let category = SyscallCategory::from_name(&name);
        Self {
            number,
            name,
            category,
            args: Vec::new(),
            return_value: None,
            timestamp_ms,
            pid,
            tid: 0,
            suspicious: false,
            note: None,
        }
    }

    /// Builder: add an argument string.
    #[must_use]
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Builder: set return value.
    #[must_use]
    pub const fn with_return(mut self, ret: i64) -> Self {
        self.return_value = Some(ret);
        self
    }

    /// Builder: mark as suspicious with an optional note.
    #[must_use]
    pub fn mark_suspicious(mut self, note: impl Into<String>) -> Self {
        self.suspicious = true;
        self.note = Some(note.into());
        self
    }

    /// Builder: set the thread ID.
    #[must_use]
    pub const fn with_tid(mut self, tid: u32) -> Self {
        self.tid = tid;
        self
    }

    /// Returns `true` if the syscall is memory-manipulation related.
    #[must_use]
    pub const fn is_memory_op(&self) -> bool {
        matches!(self.category, SyscallCategory::Memory)
    }

    /// Returns `true` if the syscall may indicate anti-analysis behaviour.
    #[must_use]
    pub const fn is_anti_debug(&self) -> bool {
        matches!(self.category, SyscallCategory::AntiDebug)
    }
}

// ── FileAccessEvent ───────────────────────────────────────────────────────────

/// Type of file-system operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOperation {
    Create,
    Open,
    Read,
    Write,
    Delete,
    Rename { new_path: String },
    SetAttribute,
    GetAttribute,
    Enumerate,
}

impl FileOperation {
    /// Short tag string for logging and display.
    #[must_use]
    pub const fn tag(&self) -> &str {
        match self {
            Self::Create => "create",
            Self::Open => "open",
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Rename { .. } => "rename",
            Self::SetAttribute => "set_attr",
            Self::GetAttribute => "get_attr",
            Self::Enumerate => "enumerate",
        }
    }
}

/// A file-system access recorded during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessEvent {
    /// The path accessed.
    pub path: String,
    /// Type of operation.
    pub operation: FileOperation,
    /// Number of bytes transferred (meaningful for Read/Write).
    pub bytes_transferred: u64,
    /// Whether the operation succeeded.
    pub succeeded: bool,
    /// Timestamp in milliseconds since monitor start.
    pub timestamp_ms: TimestampMs,
    /// PID performing the operation.
    pub pid: u32,
    /// Whether this access looks like a dropper action.
    pub is_dropper_indicator: bool,
}

impl FileAccessEvent {
    /// Create a new file access event.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        operation: FileOperation,
        pid: u32,
        timestamp_ms: TimestampMs,
    ) -> Self {
        let path = path.into();
        let is_dropper_indicator = Self::detect_dropper(&path, &operation);
        Self {
            path,
            operation,
            bytes_transferred: 0,
            succeeded: true,
            timestamp_ms,
            pid,
            is_dropper_indicator,
        }
    }

    fn detect_dropper(path: &str, op: &FileOperation) -> bool {
        if !matches!(op, FileOperation::Create | FileOperation::Write) {
            return false;
        }
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        matches!(
            ext.as_deref(),
            Some("exe" | "dll" | "bat" | "cmd" | "ps1" | "vbs" | "js" | "hta" | "scr")
        )
    }

    /// Builder: set bytes transferred.
    #[must_use]
    pub const fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes_transferred = bytes;
        self
    }

    /// Builder: mark as failed.
    #[must_use]
    pub const fn failed(mut self) -> Self {
        self.succeeded = false;
        self
    }

    /// Returns `true` if the path is in a system-sensitive directory.
    #[must_use]
    pub fn is_system_path(&self) -> bool {
        let lp = self.path.to_lowercase();
        lp.contains("\\windows\\system32")
            || lp.contains("\\windows\\syswow64")
            || lp.contains("/etc/")
            || lp.contains("/lib/")
            || lp.contains("/usr/bin/")
    }
}

// ── RegistryEvent ─────────────────────────────────────────────────────────────

/// Registry operation type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryOperation {
    CreateKey,
    OpenKey,
    DeleteKey,
    SetValue { data: Option<String> },
    QueryValue,
    DeleteValue,
    EnumerateKeys,
    EnumerateValues,
}

impl RegistryOperation {
    /// Short tag.
    #[must_use]
    pub const fn tag(&self) -> &str {
        match self {
            Self::CreateKey => "create_key",
            Self::OpenKey => "open_key",
            Self::DeleteKey => "delete_key",
            Self::SetValue { .. } => "set_value",
            Self::QueryValue => "query_value",
            Self::DeleteValue => "delete_value",
            Self::EnumerateKeys => "enum_keys",
            Self::EnumerateValues => "enum_values",
        }
    }
}

/// A Windows registry operation recorded during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    /// Full registry key path (e.g. `HKCU\Software\...`).
    pub key: String,
    /// Value name (empty for key-level operations).
    pub value_name: String,
    /// Operation type.
    pub operation: RegistryOperation,
    /// Whether the operation succeeded.
    pub succeeded: bool,
    /// Timestamp in milliseconds since monitor start.
    pub timestamp_ms: TimestampMs,
    /// PID performing the operation.
    pub pid: u32,
    /// Whether this key is a known persistence location.
    pub is_persistence_key: bool,
}

impl RegistryEvent {
    /// Create a new registry event.
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        value_name: impl Into<String>,
        operation: RegistryOperation,
        pid: u32,
        timestamp_ms: TimestampMs,
    ) -> Self {
        let key = key.into();
        let is_persistence_key = Self::detect_persistence(&key);
        Self {
            key,
            value_name: value_name.into(),
            operation,
            succeeded: true,
            timestamp_ms,
            pid,
            is_persistence_key,
        }
    }

    fn detect_persistence(key: &str) -> bool {
        let lk = key.to_lowercase();
        lk.contains("\\run\\")
            || lk.contains("\\runonce\\")
            || lk.contains("\\services\\")
            || lk.contains("\\winlogon\\")
            || lk.contains("\\userinit")
            || lk.contains("\\shell\\")
            || lk.contains("\\policies\\explorer\\run")
            || lk.contains("\\startup")
    }

    /// Builder: mark as failed.
    #[must_use]
    pub const fn failed(mut self) -> Self {
        self.succeeded = false;
        self
    }

    /// Returns `true` if the operation writes a value to a persistence key.
    #[must_use]
    pub const fn is_write_to_persistence(&self) -> bool {
        self.is_persistence_key && matches!(self.operation, RegistryOperation::SetValue { .. })
    }
}

// ── ProcessMonitor ────────────────────────────────────────────────────────────

/// Configuration for the process monitor.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Whether to record all syscalls or only suspicious ones.
    pub record_all_syscalls: bool,
    /// Whether to record registry events.
    pub record_registry: bool,
    /// Whether to record file access events.
    pub record_file_access: bool,
    /// Maximum number of events to keep (older events are dropped first).
    pub max_events: usize,
    /// Syscall names that are always considered suspicious.
    pub suspicious_syscalls: Vec<String>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            record_all_syscalls: true,
            record_registry: true,
            record_file_access: true,
            max_events: 100_000,
            suspicious_syscalls: vec![
                "NtWriteVirtualMemory".into(),
                "NtCreateThreadEx".into(),
                "VirtualAllocEx".into(),
                "WriteProcessMemory".into(),
                "CreateRemoteThread".into(),
                "NtMapViewOfSection".into(),
                "SetWindowsHookEx".into(),
                "IsDebuggerPresent".into(),
                "CheckRemoteDebuggerPresent".into(),
                "NtQueryInformationProcess".into(),
            ],
        }
    }
}

/// Statistics snapshot from a `ProcessMonitor`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MonitorStats {
    pub total_syscalls: usize,
    pub suspicious_syscalls: usize,
    pub file_reads: usize,
    pub file_writes: usize,
    pub file_creates: usize,
    pub file_deletes: usize,
    pub dropper_indicators: usize,
    pub registry_reads: usize,
    pub registry_writes: usize,
    pub persistence_writes: usize,
    pub unique_pids: usize,
    pub duration_ms: u64,
}

/// Central monitor that accumulates all process-level events during sandbox run.
pub struct ProcessMonitor {
    config: MonitorConfig,
    syscalls: Arc<Mutex<Vec<SyscallEvent>>>,
    file_events: Arc<Mutex<Vec<FileAccessEvent>>>,
    registry_events: Arc<Mutex<Vec<RegistryEvent>>>,
    start: Instant,
}

/// Events for a single PID: `(syscalls, file_events, registry_events)`.
type PidEvents = (Vec<SyscallEvent>, Vec<FileAccessEvent>, Vec<RegistryEvent>);

impl ProcessMonitor {
    /// Create a new monitor with the given configuration.
    #[must_use]
    pub fn new(config: MonitorConfig) -> Self {
        Self {
            config,
            syscalls: Arc::new(Mutex::new(Vec::new())),
            file_events: Arc::new(Mutex::new(Vec::new())),
            registry_events: Arc::new(Mutex::new(Vec::new())),
            start: Instant::now(),
        }
    }

    /// Create a monitor with default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(MonitorConfig::default())
    }

    /// Current elapsed time since the monitor was created.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Current timestamp in milliseconds (since monitor start).
    #[must_use]
    pub fn now_ms(&self) -> TimestampMs {
        elapsed_ms(self.start)
    }

    /// Record a syscall event.  Automatically flags events matching `suspicious_syscalls`.
    pub fn record_syscall(&self, mut event: SyscallEvent) {
        if self.config.suspicious_syscalls.contains(&event.name) && !event.suspicious {
            let name = event.name.clone();
            event = event.mark_suspicious(format!("known suspicious syscall: {name}"));
        }
        let mut guard = self.syscalls.lock();
        if guard.len() < self.config.max_events {
            guard.push(event);
        }
    }

    /// Record a file access event.
    pub fn record_file_access(&self, event: FileAccessEvent) {
        if !self.config.record_file_access {
            return;
        }
        let mut guard = self.file_events.lock();
        if guard.len() < self.config.max_events {
            guard.push(event);
        }
    }

    /// Record a registry event.
    pub fn record_registry(&self, event: RegistryEvent) {
        if !self.config.record_registry {
            return;
        }
        let mut guard = self.registry_events.lock();
        if guard.len() < self.config.max_events {
            guard.push(event);
        }
    }

    /// Snapshot of all recorded syscall events.
    #[must_use]
    pub fn syscalls(&self) -> Vec<SyscallEvent> {
        self.syscalls.lock().clone()
    }

    /// Snapshot of all recorded file access events.
    #[must_use]
    pub fn file_events(&self) -> Vec<FileAccessEvent> {
        self.file_events.lock().clone()
    }

    /// Snapshot of all recorded registry events.
    #[must_use]
    pub fn registry_events(&self) -> Vec<RegistryEvent> {
        self.registry_events.lock().clone()
    }

    /// Compute statistics over all recorded events.
    #[must_use]
    pub fn stats(&self) -> MonitorStats {
        let syscalls = self.syscalls.lock().clone();
        let files = self.file_events.lock().clone();
        let reg = self.registry_events.lock().clone();

        let total_syscalls = syscalls.len();
        let suspicious_syscalls = syscalls.iter().filter(|s| s.suspicious).count();

        let file_reads = files
            .iter()
            .filter(|f| matches!(f.operation, FileOperation::Read))
            .count();
        let file_writes = files
            .iter()
            .filter(|f| matches!(f.operation, FileOperation::Write))
            .count();
        let file_creates = files
            .iter()
            .filter(|f| matches!(f.operation, FileOperation::Create))
            .count();
        let file_deletes = files
            .iter()
            .filter(|f| matches!(f.operation, FileOperation::Delete))
            .count();
        let dropper_indicators = files.iter().filter(|f| f.is_dropper_indicator).count();

        let registry_reads = reg
            .iter()
            .filter(|r| {
                matches!(
                    r.operation,
                    RegistryOperation::QueryValue | RegistryOperation::OpenKey
                )
            })
            .count();
        let registry_writes = reg
            .iter()
            .filter(|r| {
                matches!(
                    r.operation,
                    RegistryOperation::SetValue { .. } | RegistryOperation::CreateKey
                )
            })
            .count();
        let persistence_writes = reg.iter().filter(|r| r.is_write_to_persistence()).count();

        let mut pids: Vec<u32> = syscalls.iter().map(|s| s.pid).collect();
        pids.extend(files.iter().map(|f| f.pid));
        pids.extend(reg.iter().map(|r| r.pid));
        pids.sort_unstable();
        pids.dedup();
        let unique_pids = pids.len();

        MonitorStats {
            total_syscalls,
            suspicious_syscalls,
            file_reads,
            file_writes,
            file_creates,
            file_deletes,
            dropper_indicators,
            registry_reads,
            registry_writes,
            persistence_writes,
            unique_pids,
            duration_ms: self.now_ms(),
        }
    }

    /// Return all suspicious syscall events.
    #[must_use]
    pub fn suspicious_syscalls(&self) -> Vec<SyscallEvent> {
        self.syscalls
            .lock()
            .iter()
            .filter(|s| s.suspicious)
            .cloned()
            .collect()
    }

    /// Return all dropper-indicator file access events.
    #[must_use]
    pub fn dropper_indicators(&self) -> Vec<FileAccessEvent> {
        self.file_events
            .lock()
            .iter()
            .filter(|f| f.is_dropper_indicator)
            .cloned()
            .collect()
    }

    /// Return all persistence-write registry events.
    #[must_use]
    pub fn persistence_writes(&self) -> Vec<RegistryEvent> {
        self.registry_events
            .lock()
            .iter()
            .filter(|r| r.is_write_to_persistence())
            .cloned()
            .collect()
    }

    /// Events grouped by PID: `pid -> (syscalls, file_events, registry_events)`.
    #[must_use]
    pub fn events_by_pid(
        &self,
    ) -> HashMap<u32, PidEvents> {
        let mut map: HashMap<u32, PidEvents> = HashMap::new();
        {
            let guard = self.syscalls.lock();
            for s in guard.iter() {
                map.entry(s.pid).or_default().0.push(s.clone());
            }
        }
        {
            let guard = self.file_events.lock();
            for f in guard.iter() {
                map.entry(f.pid).or_default().1.push(f.clone());
            }
        }
        {
            let guard = self.registry_events.lock();
            for r in guard.iter() {
                map.entry(r.pid).or_default().2.push(r.clone());
            }
        }
        map
    }

    /// Timeline: all events sorted by timestamp, tagged by type.
    #[must_use]
    pub fn timeline(&self) -> Vec<TimelineEntry> {
        let mut entries = Vec::new();
        for s in self.syscalls.lock().iter() {
            entries.push(TimelineEntry {
                timestamp_ms: s.timestamp_ms,
                pid: s.pid,
                kind: TimelineKind::Syscall(s.name.clone()),
                suspicious: s.suspicious,
            });
        }
        for f in self.file_events.lock().iter() {
            entries.push(TimelineEntry {
                timestamp_ms: f.timestamp_ms,
                pid: f.pid,
                kind: TimelineKind::FileAccess {
                    path: f.path.clone(),
                    op: f.operation.tag().to_string(),
                },
                suspicious: f.is_dropper_indicator,
            });
        }
        for r in self.registry_events.lock().iter() {
            entries.push(TimelineEntry {
                timestamp_ms: r.timestamp_ms,
                pid: r.pid,
                kind: TimelineKind::Registry {
                    key: r.key.clone(),
                    op: r.operation.tag().to_string(),
                },
                suspicious: r.is_persistence_key,
            });
        }
        entries.sort_by_key(|e| e.timestamp_ms);
        entries
    }

    /// Clear all recorded events (used between phases of multi-step analysis).
    pub fn clear(&self) {
        self.syscalls.lock().clear();
        self.file_events.lock().clear();
        self.registry_events.lock().clear();
    }
}

impl std::fmt::Debug for ProcessMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stats = self.stats();
        write!(
            f,
            "ProcessMonitor {{ syscalls: {}, files: {}, registry: {}, elapsed_ms: {} }}",
            stats.total_syscalls,
            stats.file_reads + stats.file_writes + stats.file_creates + stats.file_deletes,
            stats.registry_reads + stats.registry_writes,
            stats.duration_ms
        )
    }
}

// ── Timeline ──────────────────────────────────────────────────────────────────

/// Kind of event in the unified timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimelineKind {
    Syscall(String),
    FileAccess { path: String, op: String },
    Registry { key: String, op: String },
}

/// An entry in the unified event timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp_ms: TimestampMs,
    pub pid: u32,
    pub kind: TimelineKind,
    pub suspicious: bool,
}

impl TimelineEntry {
    /// One-line string summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let prefix = if self.suspicious { "[!] " } else { "    " };
        match &self.kind {
            TimelineKind::Syscall(name) => {
                format!("{prefix}[+{:6}ms] PID {:5} syscall  {name}", self.timestamp_ms, self.pid)
            }
            TimelineKind::FileAccess { path, op } => {
                format!("{prefix}[+{:6}ms] PID {:5} file/{op}  {path}", self.timestamp_ms, self.pid)
            }
            TimelineKind::Registry { key, op } => {
                format!("{prefix}[+{:6}ms] PID {:5} reg/{op}  {key}", self.timestamp_ms, self.pid)
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor() -> ProcessMonitor {
        ProcessMonitor::default_config()
    }

    #[test]
    fn test_syscall_category_inferred() {
        let ev = SyscallEvent::new(40, "VirtualAllocEx", 100, 0);
        assert_eq!(ev.category, SyscallCategory::Memory);
    }

    #[test]
    fn test_syscall_anti_debug_category() {
        let ev = SyscallEvent::new(10, "IsDebuggerPresent", 100, 5);
        assert_eq!(ev.category, SyscallCategory::AntiDebug);
    }

    #[test]
    fn test_syscall_suspicious_auto_flagged() {
        let m = monitor();
        let ev = SyscallEvent::new(41, "VirtualAllocEx", 100, 0);
        m.record_syscall(ev);
        let all = m.syscalls();
        assert!(all[0].suspicious);
    }

    #[test]
    fn test_file_access_dropper_indicator() {
        let ev = FileAccessEvent::new(
            "C:\\Windows\\Temp\\payload.exe",
            FileOperation::Create,
            200,
            10,
        );
        assert!(ev.is_dropper_indicator);
    }

    #[test]
    fn test_file_access_non_dropper() {
        let ev = FileAccessEvent::new("C:\\Users\\user\\document.docx", FileOperation::Read, 200, 10);
        assert!(!ev.is_dropper_indicator);
    }

    #[test]
    fn test_registry_persistence_detected() {
        let ev = RegistryEvent::new(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware",
            "Malware",
            RegistryOperation::SetValue {
                data: Some("payload.exe".into()),
            },
            100,
            50,
        );
        assert!(ev.is_persistence_key);
        assert!(ev.is_write_to_persistence());
    }

    #[test]
    fn test_stats_counts() {
        let m = monitor();
        m.record_syscall(SyscallEvent::new(1, "NtCreateFile", 100, 0));
        m.record_file_access(
            FileAccessEvent::new("C:\\tmp\\x.exe", FileOperation::Create, 100, 5)
        );
        m.record_registry(RegistryEvent::new(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\X",
            "X",
            RegistryOperation::SetValue { data: None },
            100,
            10,
        ));
        let s = m.stats();
        assert_eq!(s.total_syscalls, 1);
        assert_eq!(s.file_creates, 1);
        assert_eq!(s.dropper_indicators, 1);
        assert_eq!(s.persistence_writes, 1);
    }

    #[test]
    fn test_timeline_sorted() {
        let m = monitor();
        m.record_syscall(SyscallEvent::new(1, "NtCreateFile", 100, 20));
        m.record_file_access(
            FileAccessEvent::new("x.txt", FileOperation::Read, 100, 5)
        );
        let tl = m.timeline();
        assert!(tl.len() >= 2);
        assert!(tl[0].timestamp_ms <= tl[1].timestamp_ms);
    }

    #[test]
    fn test_events_by_pid() {
        let m = monitor();
        m.record_syscall(SyscallEvent::new(1, "foo", 101, 0));
        m.record_syscall(SyscallEvent::new(2, "bar", 102, 1));
        let byp = m.events_by_pid();
        assert!(byp.contains_key(&101));
        assert!(byp.contains_key(&102));
    }

    #[test]
    fn test_clear() {
        let m = monitor();
        m.record_syscall(SyscallEvent::new(1, "foo", 100, 0));
        m.clear();
        assert!(m.syscalls().is_empty());
    }

    #[test]
    fn test_timeline_entry_summary_non_suspicious() {
        let e = TimelineEntry {
            timestamp_ms: 12,
            pid: 99,
            kind: TimelineKind::Syscall("NtReadFile".into()),
            suspicious: false,
        };
        assert!(e.summary().contains("NtReadFile"));
    }
}
