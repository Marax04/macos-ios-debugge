//! Windows registry monitoring for the `RustRE` analysis platform.
//!
//! [`RegistryMonitor`] records registry operations intercepted during
//! emulation or API-hook tracing, and provides filtering, aggregation, and
//! export facilities.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── result / error ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, RegistryError>;

#[derive(Debug, Clone, thiserror::Error)]
pub enum RegistryError {
    #[error("invalid key path: {0}")]
    InvalidPath(String),
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("value not found: {value} under {key}")]
    ValueNotFound { key: String, value: String },
    #[error("filter error: {0}")]
    FilterError(String),
}

// ── registry operation kind ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegistryOperation {
    /// `RegOpenKey` / `NtOpenKey`
    OpenKey,
    /// `RegCreateKey` / `NtCreateKey`
    CreateKey,
    /// `RegDeleteKey` / `NtDeleteKey`
    DeleteKey,
    /// `RegQueryValue` / `NtQueryValueKey`
    QueryValue,
    /// `RegSetValue` / `NtSetValueKey`
    SetValue,
    /// `RegDeleteValue` / `NtDeleteValueKey`
    DeleteValue,
    /// `RegEnumKey` / `NtEnumerateKey`
    EnumKey,
    /// `RegEnumValue` / `NtEnumerateValueKey`
    EnumValue,
    /// `RegQueryInfoKey`
    QueryInfo,
    /// `RegFlushKey`
    FlushKey,
    /// `RegLoadKey`
    LoadKey,
    /// `RegUnloadKey`
    UnloadKey,
    /// `RegSaveKey` / `RegRestoreKey`
    SaveKey,
    /// `RegRenameKey` (undocumented `NtRenameKey`)
    RenameKey,
    /// Unknown or extension operation
    Other(String),
}

impl RegistryOperation {
    /// Short tag used in display and filtering.
    #[must_use]
    pub const fn tag(&self) -> &str {
        match self {
            Self::OpenKey      => "OpenKey",
            Self::CreateKey    => "CreateKey",
            Self::DeleteKey    => "DeleteKey",
            Self::QueryValue   => "QueryValue",
            Self::SetValue     => "SetValue",
            Self::DeleteValue  => "DeleteValue",
            Self::EnumKey      => "EnumKey",
            Self::EnumValue    => "EnumValue",
            Self::QueryInfo    => "QueryInfo",
            Self::FlushKey     => "FlushKey",
            Self::LoadKey      => "LoadKey",
            Self::UnloadKey    => "UnloadKey",
            Self::SaveKey      => "SaveKey",
            Self::RenameKey    => "RenameKey",
            Self::Other(s)     => s.as_str(),
        }
    }

    /// True if this operation writes to the registry.
    #[must_use]
    pub const fn is_write(&self) -> bool {
        matches!(
            self,
            Self::CreateKey | Self::DeleteKey | Self::SetValue
                | Self::DeleteValue | Self::LoadKey | Self::UnloadKey
                | Self::SaveKey | Self::RenameKey
        )
    }

    /// True if this operation reads from the registry.
    #[must_use]
    pub const fn is_read(&self) -> bool {
        matches!(
            self,
            Self::OpenKey | Self::QueryValue | Self::EnumKey
                | Self::EnumValue | Self::QueryInfo
        )
    }
}

// ── registry value type ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValueType {
    None,
    Sz(String),
    ExpandSz(String),
    Binary(Vec<u8>),
    Dword(u32),
    DwordBigEndian(u32),
    Link(String),
    MultiSz(Vec<String>),
    Qword(u64),
    Unknown(u32),
}

impl RegValueType {
    /// Windows `REG_*` constant.
    #[must_use]
    pub const fn type_id(&self) -> u32 {
        match self {
            Self::None            => 0,
            Self::Sz(_)           => 1,
            Self::ExpandSz(_)     => 2,
            Self::Binary(_)       => 3,
            Self::Dword(_)        => 4,
            Self::DwordBigEndian(_) => 5,
            Self::Link(_)         => 6,
            Self::MultiSz(_)      => 7,
            Self::Qword(_)        => 11,
            Self::Unknown(id)     => *id,
        }
    }
}

// ── registry event ────────────────────────────────────────────────────────────

/// A single intercepted registry access.
#[derive(Debug, Clone)]
pub struct RegistryEvent {
    /// Sequential event identifier.
    pub id: u64,
    /// UNIX-epoch milliseconds at the time of interception.
    pub timestamp_ms: u64,
    /// Key path (NT format: `\REGISTRY\MACHINE\SOFTWARE\...`).
    pub key_path: String,
    /// Value name, if applicable (empty string for key-level operations).
    pub value_name: String,
    /// What was done.
    pub operation: RegistryOperation,
    /// NT status code returned (0 = `STATUS_SUCCESS`).
    pub status: u32,
    /// PID of the process that performed the operation.
    pub pid: u32,
    /// Name of the calling module (e.g. `kernel32.dll`).
    pub caller_module: String,
    /// Address of the call instruction.
    pub call_address: u64,
    /// Data involved in set/query operations.
    pub value_data: Option<RegValueType>,
    /// Free-form annotation added by analysis passes.
    pub annotation: Option<String>,
}

impl RegistryEvent {
    /// True if this event was flagged as suspicious by [`RegistryMonitor::flag_suspicious`].
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.annotation
            .as_deref()
            .is_some_and(|a| a.starts_with("[SUSPICIOUS]"))
    }
}

// ── filter ────────────────────────────────────────────────────────────────────

/// Predicate used to select a subset of events.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// If set, only events whose `key_path` contains this substring.
    pub key_contains: Option<String>,
    /// If set, only events of this operation.
    pub operation: Option<RegistryOperation>,
    /// If set, only events from this PID.
    pub pid: Option<u32>,
    /// If set, only events with this NT status code.
    pub status: Option<u32>,
    /// If set, only events in [`from_ms`, `to_ms`).
    pub time_range: Option<(u64, u64)>,
    /// If true, only write operations.
    pub writes_only: bool,
    /// If true, only read operations.
    pub reads_only: bool,
    /// If true, only suspicious events.
    pub suspicious_only: bool,
}

impl EventFilter {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    #[must_use]
    pub fn key_contains(mut self, s: impl Into<String>) -> Self {
        self.key_contains = Some(s.into()); self
    }
    #[must_use]
    pub fn operation(mut self, op: RegistryOperation) -> Self {
        self.operation = Some(op); self
    }
    #[must_use]
    pub const fn pid(mut self, pid: u32) -> Self { self.pid = Some(pid); self }
    #[must_use]
    pub const fn status(mut self, s: u32) -> Self { self.status = Some(s); self }
    #[must_use]
    pub const fn time_range(mut self, from: u64, to: u64) -> Self {
        self.time_range = Some((from, to)); self
    }
    #[must_use]
    pub const fn writes_only(mut self) -> Self { self.writes_only = true; self }
    #[must_use]
    pub const fn reads_only(mut self) -> Self { self.reads_only = true; self }
    #[must_use]
    pub const fn suspicious_only(mut self) -> Self { self.suspicious_only = true; self }

    fn matches(&self, ev: &RegistryEvent) -> bool {
        if self.key_contains.as_deref().is_some_and(|sub| !ev.key_path.contains(sub)) {
            return false;
        }
        if self.operation.as_ref().is_some_and(|op| &ev.operation != op) {
            return false;
        }
        if self.pid.is_some_and(|pid| ev.pid != pid) {
            return false;
        }
        if self.status.is_some_and(|st| ev.status != st) {
            return false;
        }
        if self.time_range.is_some_and(|(from, to)| ev.timestamp_ms < from || ev.timestamp_ms >= to) {
            return false;
        }
        if self.writes_only && !ev.operation.is_write() { return false; }
        if self.reads_only  && !ev.operation.is_read()  { return false; }
        if self.suspicious_only && !ev.is_suspicious()  { return false; }
        true
    }
}

// ── suspicious-key patterns ───────────────────────────────────────────────────

static SUSPICIOUS_KEY_PATTERNS: &[&str] = &[
    "\\Run\\",
    "\\RunOnce\\",
    "\\Services\\",
    "\\Winlogon\\",
    "\\AppInit_DLLs",
    "\\Image File Execution Options\\",
    "\\SecurityProviders",
    "\\LSA\\",
    "\\BootExecute",
    "\\KnownDLLs",
    "\\Session Manager\\",
    "\\CurrentVersion\\Shell Extensions",
    "\\Policies\\Explorer",
];

fn is_suspicious_key(path: &str) -> bool {
    SUSPICIOUS_KEY_PATTERNS.iter().any(|p| path.contains(p))
}

// ── aggregated stats ──────────────────────────────────────────────────────────

/// Summary of all events recorded by a [`RegistryMonitor`].
#[derive(Debug, Clone, Default)]
pub struct RegistryStats {
    pub total_events: u64,
    pub write_events: u64,
    pub read_events:  u64,
    pub failed_events: u64,
    /// Counts per operation tag.
    pub op_counts: HashMap<String, u64>,
    /// Counts per unique key path.
    pub key_counts: HashMap<String, u64>,
    /// Number of events that touched a suspicious key.
    pub suspicious_count: u64,
}

// ── record context ────────────────────────────────────────────────────────────

/// Caller-supplied context for a single [`RegistryMonitor::record`] call.
#[derive(Debug, Clone)]
pub struct RecordCtx {
    /// NT status code returned by the operation (0 = `STATUS_SUCCESS`).
    pub status: u32,
    /// PID of the calling process.
    pub pid: u32,
    /// Name of the calling module (e.g. `kernel32.dll`).
    pub caller_module: String,
    /// Virtual address of the call instruction.
    pub call_address: u64,
}

impl RecordCtx {
    /// Convenience constructor.
    #[must_use]
    pub fn new(
        status: u32,
        pid: u32,
        caller_module: impl Into<String>,
        call_address: u64,
    ) -> Self {
        Self { status, pid, caller_module: caller_module.into(), call_address }
    }
}

// ── monitor ───────────────────────────────────────────────────────────────────

/// Records, filters, and analyses Windows registry events.
pub struct RegistryMonitor {
    events: Vec<RegistryEvent>,
    next_id: u64,
    /// Maximum events retained in memory (oldest dropped when exceeded).
    capacity: usize,
    stats: RegistryStats,
}

impl Default for RegistryMonitor {
    fn default() -> Self { Self::new(65536) }
}

impl RegistryMonitor {
    /// Create a monitor with the given event-buffer capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity.min(1024)),
            next_id: 1,
            capacity,
            stats: RegistryStats::default(),
        }
    }

    // ── recording ─────────────────────────────────────────────────────────

    /// Record a registry event.  Returns the assigned event ID.
    pub fn record(
        &mut self,
        key_path: impl Into<String>,
        value_name: impl Into<String>,
        operation: RegistryOperation,
        ctx: RecordCtx,
        value_data: Option<RegValueType>,
    ) -> u64 {
        let key_path      = key_path.into();
        let value_name    = value_name.into();

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);

        let suspicious = is_suspicious_key(&key_path);

        let annotation = if suspicious {
            Some("[SUSPICIOUS] key matches watchlist".to_owned())
        } else {
            None
        };

        let id = self.next_id;
        self.next_id += 1;

        let ev = RegistryEvent {
            id,
            timestamp_ms,
            key_path: key_path.clone(),
            value_name,
            operation,
            status: ctx.status,
            pid: ctx.pid,
            caller_module: ctx.caller_module,
            call_address: ctx.call_address,
            value_data,
            annotation,
        };

        // Update stats.
        self.stats.total_events += 1;
        if ev.operation.is_write() { self.stats.write_events += 1; }
        if ev.operation.is_read()  { self.stats.read_events  += 1; }
        if ctx.status != 0       { self.stats.failed_events += 1; }
        if suspicious            { self.stats.suspicious_count += 1; }
        *self.stats.op_counts.entry(ev.operation.tag().to_owned()).or_insert(0) += 1;
        *self.stats.key_counts.entry(key_path).or_insert(0) += 1;

        // Evict oldest if over capacity.
        if self.events.len() >= self.capacity {
            self.events.remove(0);
        }
        self.events.push(ev);
        id
    }

    // ── filtering ─────────────────────────────────────────────────────────

    /// Return all events matching the given filter.
    #[must_use]
    pub fn filter_events(&self, filter: &EventFilter) -> Vec<&RegistryEvent> {
        self.events.iter().filter(|ev| filter.matches(ev)).collect()
    }

    /// Return all events for keys under a given root path prefix.
    #[must_use]
    pub fn events_under(&self, prefix: &str) -> Vec<&RegistryEvent> {
        self.events
            .iter()
            .filter(|ev| ev.key_path.starts_with(prefix))
            .collect()
    }

    /// Return events that set a specific value (case-insensitive).
    #[must_use]
    pub fn set_value_events(&self, value_name: &str) -> Vec<&RegistryEvent> {
        let lower = value_name.to_ascii_lowercase();
        self.events
            .iter()
            .filter(|ev| {
                ev.operation == RegistryOperation::SetValue
                    && ev.value_name.to_ascii_lowercase() == lower
            })
            .collect()
    }

    /// Return all failed events.
    #[must_use]
    pub fn failed_events(&self) -> Vec<&RegistryEvent> {
        self.events.iter().filter(|ev| ev.status != 0).collect()
    }

    /// Return suspicious events (touching autorun, services, LSA, etc.).
    #[must_use]
    pub fn suspicious_events(&self) -> Vec<&RegistryEvent> {
        self.events.iter().filter(|ev| ev.is_suspicious()).collect()
    }

    // ── annotation ────────────────────────────────────────────────────────

    /// Add an annotation to an event by ID.
    pub fn annotate(&mut self, id: u64, note: impl Into<String>) -> bool {
        if let Some(ev) = self.events.iter_mut().find(|ev| ev.id == id) {
            ev.annotation = Some(note.into());
            true
        } else {
            false
        }
    }

    /// Mark an event as suspicious by prepending the sentinel prefix.
    pub fn flag_suspicious(&mut self, id: u64, reason: &str) -> bool {
        if let Some(ev) = self.events.iter_mut().find(|ev| ev.id == id) {
            let existing = ev.annotation.take().unwrap_or_default();
            ev.annotation = Some(format!("[SUSPICIOUS] {reason} | {existing}"));
            self.stats.suspicious_count += 1;
            true
        } else {
            false
        }
    }

    // ── aggregation ───────────────────────────────────────────────────────

    /// Snapshot of the current statistics.
    #[must_use]
    pub const fn stats(&self) -> &RegistryStats { &self.stats }

    /// Top-N most-accessed keys by event count.
    #[must_use]
    pub fn top_keys(&self, n: usize) -> Vec<(String, u64)> {
        let mut pairs: Vec<(String, u64)> = self.stats.key_counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    /// Top-N most-used operations by event count.
    #[must_use]
    pub fn top_operations(&self, n: usize) -> Vec<(String, u64)> {
        let mut pairs: Vec<(String, u64)> = self.stats.op_counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    /// Return per-PID event counts.
    #[must_use]
    pub fn events_per_pid(&self) -> HashMap<u32, u64> {
        let mut map: HashMap<u32, u64> = HashMap::with_capacity(self.events.len().min(64));
        for ev in &self.events {
            *map.entry(ev.pid).or_insert(0) += 1;
        }
        map
    }

    // ── housekeeping ──────────────────────────────────────────────────────

    /// Total events stored in the buffer.
    #[must_use]
    pub const fn len(&self) -> usize { self.events.len() }
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.events.is_empty() }

    /// Clear all stored events (stats are reset too).
    pub fn clear(&mut self) {
        self.events.clear();
        self.stats = RegistryStats::default();
    }

    /// Return all events (no filtering).
    #[must_use]
    pub fn all_events(&self) -> &[RegistryEvent] { &self.events }

    /// Iterate events in chronological order.
    pub fn iter(&self) -> std::slice::Iter<'_, RegistryEvent> {
        self.events.iter()
    }

    /// Export events as a CSV-formatted string.
    #[must_use]
    pub fn export_csv(&self) -> String {
        let header = "id,timestamp_ms,operation,key_path,value_name,status,pid,caller_module,call_address\n";
        let mut out = String::with_capacity(header.len() + self.events.len() * 80);
        out.push_str(header);
        for ev in &self.events {
            use std::fmt::Write as _;
            let _ = writeln!(
                out,
                "{},{},{},{},{},{},{},{},{:#x}",
                ev.id,
                ev.timestamp_ms,
                ev.operation.tag(),
                ev.key_path,
                ev.value_name,
                ev.status,
                ev.pid,
                ev.caller_module,
                ev.call_address,
            );
        }
        out
    }
}

impl<'a> IntoIterator for &'a RegistryMonitor {
    type Item = &'a RegistryEvent;
    type IntoIter = std::slice::Iter<'a, RegistryEvent>;

    fn into_iter(self) -> Self::IntoIter {
        self.events.iter()
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_monitor() -> RegistryMonitor {
        RegistryMonitor::new(256)
    }

    fn record_simple(m: &mut RegistryMonitor, key: &str, op: RegistryOperation) -> u64 {
        m.record(key, "", op, RecordCtx::new(0, 1000, "ntdll.dll", 0x1234), None)
    }

    #[test]
    fn record_and_count() {
        let mut m = make_monitor();
        record_simple(&mut m, r"\REGISTRY\MACHINE\SOFTWARE\Test", RegistryOperation::OpenKey);
        record_simple(&mut m, r"\REGISTRY\MACHINE\SOFTWARE\Test", RegistryOperation::QueryValue);
        assert_eq!(m.len(), 2);
        assert_eq!(m.stats().total_events, 2);
    }

    #[test]
    fn filter_by_operation() {
        let mut m = make_monitor();
        record_simple(&mut m, r"\REGISTRY\MACHINE\Test", RegistryOperation::OpenKey);
        record_simple(&mut m, r"\REGISTRY\MACHINE\Test", RegistryOperation::SetValue);
        let f = EventFilter::new().operation(RegistryOperation::SetValue);
        let hits = m.filter_events(&f);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].operation, RegistryOperation::SetValue);
    }

    #[test]
    fn filter_key_contains() {
        let mut m = make_monitor();
        record_simple(&mut m, r"\REGISTRY\MACHINE\Run\evil.exe", RegistryOperation::SetValue);
        record_simple(&mut m, r"\REGISTRY\MACHINE\SOFTWARE\Harmless", RegistryOperation::OpenKey);
        let f = EventFilter::new().key_contains("Run");
        let hits = m.filter_events(&f);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn suspicious_autorun() {
        let mut m = make_monitor();
        record_simple(
            &mut m,
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil",
            RegistryOperation::SetValue,
        );
        let sus = m.suspicious_events();
        assert_eq!(sus.len(), 1);
        assert!(sus[0].is_suspicious());
    }

    #[test]
    fn writes_only_filter() {
        let mut m = make_monitor();
        record_simple(&mut m, r"\REGISTRY\MACHINE\Test", RegistryOperation::QueryValue);
        record_simple(&mut m, r"\REGISTRY\MACHINE\Test", RegistryOperation::SetValue);
        let hits = m.filter_events(&EventFilter::new().writes_only());
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn top_keys() {
        let mut m = make_monitor();
        for _ in 0..3 {
            record_simple(&mut m, r"\REGISTRY\A", RegistryOperation::OpenKey);
        }
        record_simple(&mut m, r"\REGISTRY\B", RegistryOperation::OpenKey);
        let top = m.top_keys(1);
        assert_eq!(top[0].0, r"\REGISTRY\A");
        assert_eq!(top[0].1, 3);
    }

    #[test]
    fn annotate_event() {
        let mut m = make_monitor();
        let id = record_simple(&mut m, r"\REGISTRY\TEST", RegistryOperation::OpenKey);
        let ok = m.annotate(id, "custom note");
        assert!(ok);
        let ev = m.all_events().iter().find(|e| e.id == id).unwrap();
        assert_eq!(ev.annotation.as_deref(), Some("custom note"));
    }

    #[test]
    fn clear_resets() {
        let mut m = make_monitor();
        record_simple(&mut m, r"\REGISTRY\TEST", RegistryOperation::OpenKey);
        m.clear();
        assert!(m.is_empty());
        assert_eq!(m.stats().total_events, 0);
    }

    #[test]
    fn csv_export() {
        let mut m = make_monitor();
        record_simple(&mut m, r"\REGISTRY\MACHINE\Test", RegistryOperation::OpenKey);
        let csv = m.export_csv();
        assert!(csv.contains("OpenKey"));
        assert!(csv.contains(r"\REGISTRY\MACHINE\Test"));
    }

    #[test]
    fn operation_is_write_read() {
        assert!(RegistryOperation::SetValue.is_write());
        assert!(!RegistryOperation::SetValue.is_read());
        assert!(RegistryOperation::QueryValue.is_read());
        assert!(!RegistryOperation::QueryValue.is_write());
    }
}
