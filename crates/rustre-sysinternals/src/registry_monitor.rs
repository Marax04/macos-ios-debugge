//! `registry_monitor` — Regmon-equivalent
//!
//! Intercepts registry operations (`RegOpenKey`, `RegQueryValue`, `RegSetValue`, `RegDeleteKey`),
//! filtering, timeline reconstruction, hive analysis.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{RegistryDataType, SysinternalsError};

// ─── Sequence counter ─────────────────────────────────────────────────────────

static REG_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn next_seq() -> u64 {
    REG_SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

fn unix_ts_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

// ─── RegistryHive ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryHive {
    LocalMachine,
    CurrentUser,
    Users,
    ClassesRoot,
    CurrentConfig,
    PerformanceData,
    Unknown,
}

impl fmt::Display for RegistryHive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::LocalMachine => "HKLM",
            Self::CurrentUser => "HKCU",
            Self::Users => "HKU",
            Self::ClassesRoot => "HKCR",
            Self::CurrentConfig => "HKCC",
            Self::PerformanceData => "HKPD",
            Self::Unknown => "HKUNK",
        };
        write!(f, "{s}")
    }
}

impl RegistryHive {
    #[must_use]
    pub fn from_path(path: &str) -> Self {
        let p = path.to_uppercase();
        if p.starts_with("HKEY_LOCAL_MACHINE") || p.starts_with("HKLM") {
            Self::LocalMachine
        } else if p.starts_with("HKEY_CURRENT_USER") || p.starts_with("HKCU") {
            Self::CurrentUser
        } else if p.starts_with("HKEY_USERS") || p.starts_with("HKU") {
            Self::Users
        } else if p.starts_with("HKEY_CLASSES_ROOT") || p.starts_with("HKCR") {
            Self::ClassesRoot
        } else if p.starts_with("HKEY_CURRENT_CONFIG") || p.starts_with("HKCC") {
            Self::CurrentConfig
        } else if p.starts_with("HKEY_PERFORMANCE_DATA") || p.starts_with("HKPD") {
            Self::PerformanceData
        } else {
            Self::Unknown
        }
    }
}

// ─── RegistryOperation ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryOperation {
    OpenKey,
    CreateKey,
    CloseKey,
    DeleteKey,
    QueryKey,
    EnumKey,
    QueryValue,
    SetValue,
    DeleteValue,
    EnumValue,
    QueryMultipleValues,
    SetKeySecurity,
    QueryKeySecurity,
    FlushKey,
    LoadKey,
    UnLoadKey,
    SaveKey,
    RestoreKey,
    ReplaceKey,
    NotifyChangeKey,
    OpenKeyEx,
    QueryKeyEx,
}

impl fmt::Display for RegistryOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::OpenKey => "RegOpenKey",
            Self::CreateKey => "RegCreateKey",
            Self::CloseKey => "RegCloseKey",
            Self::DeleteKey => "RegDeleteKey",
            Self::QueryKey => "RegQueryKey",
            Self::EnumKey => "RegEnumKey",
            Self::QueryValue => "RegQueryValue",
            Self::SetValue => "RegSetValue",
            Self::DeleteValue => "RegDeleteValue",
            Self::EnumValue => "RegEnumValue",
            Self::QueryMultipleValues => "RegQueryMultipleValues",
            Self::SetKeySecurity => "RegSetKeySecurity",
            Self::QueryKeySecurity => "RegQueryKeySecurity",
            Self::FlushKey => "RegFlushKey",
            Self::LoadKey => "RegLoadKey",
            Self::UnLoadKey => "RegUnLoadKey",
            Self::SaveKey => "RegSaveKey",
            Self::RestoreKey => "RegRestoreKey",
            Self::ReplaceKey => "RegReplaceKey",
            Self::NotifyChangeKey => "RegNotifyChangeKey",
            Self::OpenKeyEx => "RegOpenKeyEx",
            Self::QueryKeyEx => "RegQueryKeyEx",
        };
        write!(f, "{s}")
    }
}

impl RegistryOperation {
    #[must_use]
    pub const fn is_write_op(self) -> bool {
        matches!(
            self,
            Self::CreateKey
                | Self::DeleteKey
                | Self::SetValue
                | Self::DeleteValue
                | Self::SetKeySecurity
                | Self::LoadKey
                | Self::UnLoadKey
                | Self::RestoreKey
                | Self::ReplaceKey
        )
    }

    #[must_use]
    pub const fn is_read_op(self) -> bool {
        matches!(
            self,
            Self::OpenKey
                | Self::OpenKeyEx
                | Self::QueryKey
                | Self::QueryKeyEx
                | Self::EnumKey
                | Self::QueryValue
                | Self::EnumValue
                | Self::QueryMultipleValues
                | Self::QueryKeySecurity
        )
    }
}

// ─── RegistryResult ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryResult {
    Success,
    NotFound,
    AccessDenied,
    InvalidHandle,
    InvalidParameter,
    MoreData,
    NoMoreItems,
    AlreadyExists,
    BadKey,
    Unknown(u32),
}

impl fmt::Display for RegistryResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "SUCCESS"),
            Self::NotFound => write!(f, "NOT_FOUND"),
            Self::AccessDenied => write!(f, "ACCESS_DENIED"),
            Self::InvalidHandle => write!(f, "INVALID_HANDLE"),
            Self::InvalidParameter => write!(f, "INVALID_PARAMETER"),
            Self::MoreData => write!(f, "MORE_DATA"),
            Self::NoMoreItems => write!(f, "NO_MORE_ITEMS"),
            Self::AlreadyExists => write!(f, "ALREADY_EXISTS"),
            Self::BadKey => write!(f, "BAD_KEY"),
            Self::Unknown(c) => write!(f, "0x{c:08X}"),
        }
    }
}

impl RegistryResult {
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success | Self::AlreadyExists)
    }

    #[must_use]
    pub const fn from_win32(code: u32) -> Self {
        match code {
            0 => Self::Success,
            2 | 1008 => Self::NotFound,
            5 => Self::AccessDenied,
            6 => Self::InvalidHandle,
            87 => Self::InvalidParameter,
            234 => Self::MoreData,
            259 => Self::NoMoreItems,
            183 => Self::AlreadyExists,
            1 | 14 => Self::BadKey,
            other => Self::Unknown(other),
        }
    }
}

// ─── RegistryValueData ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryValueData {
    Sz(String),
    ExpandSz(String),
    Binary(Vec<u8>),
    Dword(u32),
    Qword(u64),
    MultiSz(Vec<String>),
    None,
}

impl RegistryValueData {
    #[must_use]
    pub const fn data_type(&self) -> RegistryDataType {
        match self {
            Self::Sz(_) => RegistryDataType::RegSz,
            Self::ExpandSz(_) => RegistryDataType::RegExpandSz,
            Self::Binary(_) | Self::None => RegistryDataType::RegBinary,
            Self::Dword(_) => RegistryDataType::RegDword,
            Self::Qword(_) => RegistryDataType::RegQword,
            Self::MultiSz(_) => RegistryDataType::RegMultiSz,
        }
    }

    #[must_use]
    pub fn as_string_lossy(&self) -> String {
        match self {
            Self::Sz(s) | Self::ExpandSz(s) => s.clone(),
            Self::Dword(d) => d.to_string(),
            Self::Qword(q) => q.to_string(),
            Self::MultiSz(v) => v.join(" | "),
            Self::Binary(b) => b
                .iter()
                .take(32)
                .map(|x| format!("{x:02X}"))
                .collect::<Vec<_>>()
                .join(" "),
            Self::None => String::new(),
        }
    }

    #[must_use]
    pub fn byte_size(&self) -> usize {
        match self {
            Self::Sz(s) | Self::ExpandSz(s) => (s.len() + 1) * 2,
            Self::Binary(b) => b.len(),
            Self::Dword(_) => 4,
            Self::Qword(_) => 8,
            Self::MultiSz(v) => v.iter().map(|s| (s.len() + 1) * 2).sum::<usize>() + 2,
            Self::None => 0,
        }
    }
}

// ─── RegistryEvent ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub sequence: u64,
    pub timestamp_us: u64,
    pub duration_us: u64,
    pub pid: u32,
    pub tid: u32,
    pub process_name: String,
    pub operation: RegistryOperation,
    pub hive: RegistryHive,
    /// Full registry path (e.g. HKLM\SOFTWARE\Microsoft\Windows\...).
    pub key_path: String,
    /// Value name (for value operations).
    pub value_name: Option<String>,
    /// Result of the operation.
    pub result: RegistryResult,
    /// Data involved (for `SetValue`, `QueryValue`).
    pub data: Option<RegistryValueData>,
    /// Access mask used when opening a key.
    pub desired_access: u32,
    /// Handle value returned/used.
    pub handle: u64,
    /// Additional annotation.
    pub detail: String,
}

impl RegistryEvent {
    #[must_use]
    pub fn new(
        pid: u32,
        tid: u32,
        process_name: impl Into<String>,
        operation: RegistryOperation,
        key_path: impl Into<String>,
        result: RegistryResult,
    ) -> Self {
        let key_path = key_path.into();
        let hive = RegistryHive::from_path(&key_path);
        Self {
            sequence: next_seq(),
            timestamp_us: unix_ts_micros(),
            duration_us: 0,
            pid,
            tid,
            process_name: process_name.into(),
            operation,
            hive,
            key_path,
            value_name: None,
            result,
            data: None,
            desired_access: 0,
            handle: 0,
            detail: String::new(),
        }
    }

    /// True if this event modifies registry state.
    #[must_use]
    pub const fn is_write(&self) -> bool {
        self.operation.is_write_op()
    }

    /// True if this targets a known persistence key.
    #[must_use]
    pub fn is_persistence_key(&self) -> bool {
        let lp = self.key_path.to_lowercase();
        PERSISTENCE_PATHS
            .iter()
            .any(|&p| lp.contains(&p.to_lowercase()))
    }

    /// CSV row.
    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{}",
            self.sequence,
            self.timestamp_us,
            self.pid,
            self.process_name,
            self.operation,
            self.hive,
            self.key_path,
            self.value_name.as_deref().unwrap_or(""),
            self.result,
        )
    }
}

// ─── Known persistence registry paths ────────────────────────────────────────

pub const PERSISTENCE_PATHS: &[&str] = &[
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"SYSTEM\CurrentControlSet\Services",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"SOFTWARE\Classes\exefile\shell\open\command",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"SOFTWARE\Policies\Microsoft\Windows\System\Scripts",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
    r"SYSTEM\CurrentControlSet\Control\Lsa",
    r"SYSTEM\CurrentControlSet\Control\NetworkProvider\Order",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers",
];

// ─── RegistryEventFilter ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct RegistryEventFilter {
    pub pids: Vec<u32>,
    pub hives: Vec<RegistryHive>,
    pub key_path_contains: Vec<String>,
    pub operations: Vec<RegistryOperation>,
    pub results: Vec<RegistryResult>,
    pub write_only: bool,
    pub persistence_only: bool,
    pub process_name_contains: Option<String>,
}

impl RegistryEventFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn matches(&self, event: &RegistryEvent) -> bool {
        if !self.pids.is_empty() && !self.pids.contains(&event.pid) {
            return false;
        }
        if !self.hives.is_empty() && !self.hives.contains(&event.hive) {
            return false;
        }
        if !self.key_path_contains.is_empty() {
            let lp = event.key_path.to_lowercase();
            if !self
                .key_path_contains
                .iter()
                .any(|k| lp.contains(k.to_lowercase().as_str()))
            {
                return false;
            }
        }
        if !self.operations.is_empty() && !self.operations.contains(&event.operation) {
            return false;
        }
        if !self.results.is_empty() && !self.results.contains(&event.result) {
            return false;
        }
        if self.write_only && !event.is_write() {
            return false;
        }
        if self.persistence_only && !event.is_persistence_key() {
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
        true
    }

    #[must_use]
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pids.push(pid);
        self
    }

    #[must_use]
    pub fn with_hive(mut self, hive: RegistryHive) -> Self {
        self.hives.push(hive);
        self
    }

    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.key_path_contains.push(path.into());
        self
    }

    #[must_use]
    pub const fn writes_only(mut self) -> Self {
        self.write_only = true;
        self
    }

    #[must_use]
    pub const fn persistence_only(mut self) -> Self {
        self.persistence_only = true;
        self
    }
}

// ─── RegistryAccessSummary ────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryAccessSummary {
    pub key_path: String,
    pub open_count: u64,
    pub query_count: u64,
    pub set_count: u64,
    pub delete_count: u64,
    pub error_count: u64,
    pub accessing_pids: Vec<u32>,
    pub last_access_us: u64,
    /// True if this key is in a persistence location.
    pub is_persistence: bool,
}

impl RegistryAccessSummary {
    pub fn record(&mut self, event: &RegistryEvent) {
        match event.operation {
            RegistryOperation::OpenKey | RegistryOperation::OpenKeyEx => self.open_count += 1,
            RegistryOperation::QueryKey
            | RegistryOperation::QueryKeyEx
            | RegistryOperation::QueryValue
            | RegistryOperation::EnumKey
            | RegistryOperation::EnumValue => self.query_count += 1,
            RegistryOperation::SetValue | RegistryOperation::CreateKey => self.set_count += 1,
            RegistryOperation::DeleteKey | RegistryOperation::DeleteValue => {
                self.delete_count += 1;
            }
            _ => {}
        }
        if !event.result.is_success() {
            self.error_count += 1;
        }
        if !self.accessing_pids.contains(&event.pid) {
            self.accessing_pids.push(event.pid);
        }
        if event.timestamp_us > self.last_access_us {
            self.last_access_us = event.timestamp_us;
        }
        if event.is_persistence_key() {
            self.is_persistence = true;
        }
    }

    #[must_use]
    pub const fn total_accesses(&self) -> u64 {
        self.open_count + self.query_count + self.set_count + self.delete_count
    }
}

// ─── RegistryTimeline ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryTimelineEntry {
    pub timestamp_us: u64,
    pub pid: u32,
    pub process_name: String,
    pub operation: RegistryOperation,
    pub value_name: Option<String>,
    pub result: RegistryResult,
    pub data_summary: String,
}

// ─── RegistryMonitor ──────────────────────────────────────────────────────────

pub struct RegistryMonitor {
    buffer: VecDeque<RegistryEvent>,
    capacity: usize,
    summaries: HashMap<String, RegistryAccessSummary>,
    total_events: u64,
    persistence_alerts: Vec<RegistryEvent>,
}

impl RegistryMonitor {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity),
            capacity: capacity.max(1),
            summaries: HashMap::new(),
            total_events: 0,
            persistence_alerts: Vec::new(),
        }
    }

    pub fn ingest(&mut self, event: RegistryEvent) {
        self.total_events += 1;

        // Summarise.
        let summary = self
            .summaries
            .entry(event.key_path.clone())
            .or_insert_with(|| RegistryAccessSummary {
                key_path: event.key_path.clone(),
                ..Default::default()
            });
        summary.record(&event);

        // Persistence alert.
        if event.is_persistence_key() && event.is_write() {
            self.persistence_alerts.push(event.clone());
        }

        // Ring buffer.
        if self.buffer.len() >= self.capacity {
            self.buffer.pop_front();
        }
        self.buffer.push_back(event);
    }

    #[must_use]
    pub fn query(&self, filter: &RegistryEventFilter) -> Vec<&RegistryEvent> {
        self.buffer
            .iter()
            .filter(|e| filter.matches(e))
            .collect()
    }

    #[must_use]
    pub fn persistence_alerts(&self) -> &[RegistryEvent] {
        &self.persistence_alerts
    }

    #[must_use]
    pub const fn total_events(&self) -> u64 {
        self.total_events
    }

    #[must_use]
    pub fn top_keys_by_access(&self, n: usize) -> Vec<&RegistryAccessSummary> {
        let mut v: Vec<&RegistryAccessSummary> = self.summaries.values().collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.total_accesses()));
        v.truncate(n);
        v
    }

    /// Build a timeline for a specific key.
    #[must_use]
    pub fn timeline_for_key(&self, key: &str) -> Vec<RegistryTimelineEntry> {
        let mut entries: Vec<RegistryTimelineEntry> = self
            .buffer
            .iter()
            .filter(|e| e.key_path.eq_ignore_ascii_case(key))
            .map(|e| RegistryTimelineEntry {
                timestamp_us: e.timestamp_us,
                pid: e.pid,
                process_name: e.process_name.clone(),
                operation: e.operation,
                value_name: e.value_name.clone(),
                result: e.result,
                data_summary: e
                    .data
                    .as_ref()
                    .map(RegistryValueData::as_string_lossy)
                    .unwrap_or_default(),
            })
            .collect();
        entries.sort_by_key(|e| e.timestamp_us);
        entries
    }

    /// Export to CSV.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "Seq,TimestampUs,PID,Process,Operation,Hive,Key,ValueName,Result\n",
        );
        for ev in &self.buffer {
            out.push_str(&ev.to_csv_row());
            out.push('\n');
        }
        out
    }

    /// # Errors
    /// Returns an error if the underlying operation fails.
    pub fn to_json(&self) -> Result<String, SysinternalsError> {
        let events: Vec<&RegistryEvent> = self.buffer.iter().collect();
        serde_json::to_string_pretty(&events)
            .map_err(|e| SysinternalsError::InvalidData(e.to_string()))
    }
}

// ─── RegistryHiveDiff ─────────────────────────────────────────────────────────

/// Represents a change detected between two snapshots of registry values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValueChange {
    pub key_path: String,
    pub value_name: String,
    pub before: Option<RegistryValueData>,
    pub after: Option<RegistryValueData>,
    pub change_type: ValueChangeType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueChangeType {
    Added,
    Removed,
    Modified,
}

impl fmt::Display for ValueChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added => write!(f, "Added"),
            Self::Removed => write!(f, "Removed"),
            Self::Modified => write!(f, "Modified"),
        }
    }
}

/// Compare two snapshots and return all changes.
#[must_use]
pub fn diff_registry_snapshots<S: ::std::hash::BuildHasher>(
    before: &HashMap<String, RegistryValueData, S>,
    after: &HashMap<String, RegistryValueData, S>,
) -> Vec<RegistryValueChange> {
    let mut changes = Vec::new();

    // Check for removed or modified.
    for (key, before_val) in before {
        match after.get(key) {
            None => changes.push(RegistryValueChange {
                key_path: key.clone(),
                value_name: String::new(),
                before: Some(before_val.clone()),
                after: None,
                change_type: ValueChangeType::Removed,
            }),
            Some(after_val) => {
                // Compare by string representation (sufficient for change detection).
                if before_val.as_string_lossy() != after_val.as_string_lossy() {
                    changes.push(RegistryValueChange {
                        key_path: key.clone(),
                        value_name: String::new(),
                        before: Some(before_val.clone()),
                        after: Some(after_val.clone()),
                        change_type: ValueChangeType::Modified,
                    });
                }
            }
        }
    }

    // Check for added.
    for (key, after_val) in after {
        if !before.contains_key(key) {
            changes.push(RegistryValueChange {
                key_path: key.clone(),
                value_name: String::new(),
                before: None,
                after: Some(after_val.clone()),
                change_type: ValueChangeType::Added,
            });
        }
    }

    changes
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(pid: u32, op: RegistryOperation, key: &str) -> RegistryEvent {
        RegistryEvent::new(pid, pid * 10, "test.exe", op, key, RegistryResult::Success)
    }

    #[test]
    fn test_hive_from_path() {
        assert_eq!(RegistryHive::from_path("HKLM\\Software"), RegistryHive::LocalMachine);
        assert_eq!(RegistryHive::from_path("HKCU\\"), RegistryHive::CurrentUser);
        assert_eq!(RegistryHive::from_path("HKEY_USERS\\"), RegistryHive::Users);
        assert_eq!(RegistryHive::from_path("nonsense"), RegistryHive::Unknown);
    }

    #[test]
    fn test_operation_is_write() {
        assert!(RegistryOperation::SetValue.is_write_op());
        assert!(RegistryOperation::DeleteKey.is_write_op());
        assert!(!RegistryOperation::QueryValue.is_write_op());
        assert!(!RegistryOperation::OpenKey.is_write_op());
    }

    #[test]
    fn test_persistence_key_detection() {
        let ev = make_event(
            1,
            RegistryOperation::SetValue,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        );
        assert!(ev.is_persistence_key());
        assert!(ev.is_write());
    }

    #[test]
    fn test_non_persistence_key() {
        let ev = make_event(1, RegistryOperation::QueryValue, r"HKLM\SOFTWARE\Random");
        assert!(!ev.is_persistence_key());
    }

    #[test]
    fn test_registry_event_filter_write_only() {
        let filter = RegistryEventFilter::new().writes_only();
        let write_ev = make_event(1, RegistryOperation::SetValue, r"HKLM\Run");
        let read_ev = make_event(1, RegistryOperation::QueryValue, r"HKLM\Run");
        assert!(filter.matches(&write_ev));
        assert!(!filter.matches(&read_ev));
    }

    #[test]
    fn test_registry_event_filter_persistence_only() {
        let filter = RegistryEventFilter::new().persistence_only();
        let persist_ev = make_event(
            1,
            RegistryOperation::SetValue,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        );
        let other_ev = make_event(1, RegistryOperation::SetValue, r"HKLM\SOFTWARE\Other");
        assert!(filter.matches(&persist_ev));
        assert!(!filter.matches(&other_ev));
    }

    #[test]
    fn test_registry_event_filter_pid() {
        let filter = RegistryEventFilter::new().with_pid(42);
        let ev1 = make_event(42, RegistryOperation::QueryValue, r"HKLM\x");
        let ev2 = make_event(99, RegistryOperation::QueryValue, r"HKLM\x");
        assert!(filter.matches(&ev1));
        assert!(!filter.matches(&ev2));
    }

    #[test]
    fn test_registry_monitor_ingest_and_query() {
        let mut mon = RegistryMonitor::new(100);
        mon.ingest(make_event(1, RegistryOperation::SetValue, r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"));
        mon.ingest(make_event(2, RegistryOperation::QueryValue, r"HKLM\OTHER"));
        assert_eq!(mon.total_events(), 2);
        let filter = RegistryEventFilter::new().writes_only();
        let results = mon.query(&filter);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_registry_monitor_persistence_alert() {
        let mut mon = RegistryMonitor::new(100);
        let ev = make_event(
            1,
            RegistryOperation::SetValue,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        );
        mon.ingest(ev);
        assert!(!mon.persistence_alerts().is_empty());
    }

    #[test]
    fn test_registry_monitor_csv() {
        let mut mon = RegistryMonitor::new(10);
        mon.ingest(make_event(1, RegistryOperation::QueryValue, r"HKCU\x"));
        let csv = mon.to_csv();
        assert!(csv.contains("HKCU"));
    }

    #[test]
    fn test_registry_value_data_string_lossy() {
        let d = RegistryValueData::Sz("hello".into());
        assert_eq!(d.as_string_lossy(), "hello");
        let d2 = RegistryValueData::Dword(42);
        assert_eq!(d2.as_string_lossy(), "42");
    }

    #[test]
    fn test_diff_registry_snapshots_added() {
        let before = HashMap::new();
        let mut after = HashMap::new();
        after.insert(
            r"HKLM\Run\evil".to_string(),
            RegistryValueData::Sz("evil.exe".into()),
        );
        let changes = diff_registry_snapshots(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ValueChangeType::Added);
    }

    #[test]
    fn test_diff_registry_snapshots_removed() {
        let mut before = HashMap::new();
        before.insert(
            r"HKLM\Run\old".to_string(),
            RegistryValueData::Sz("old.exe".into()),
        );
        let after = HashMap::new();
        let changes = diff_registry_snapshots(&before, &after);
        assert_eq!(changes[0].change_type, ValueChangeType::Removed);
    }

    #[test]
    fn test_diff_registry_snapshots_modified() {
        let mut before = HashMap::new();
        before.insert(
            r"HKLM\Run\entry".to_string(),
            RegistryValueData::Sz("old.exe".into()),
        );
        let mut after = HashMap::new();
        after.insert(
            r"HKLM\Run\entry".to_string(),
            RegistryValueData::Sz("new.exe".into()),
        );
        let changes = diff_registry_snapshots(&before, &after);
        assert_eq!(changes[0].change_type, ValueChangeType::Modified);
    }

    #[test]
    fn test_diff_no_change() {
        let mut snap = HashMap::new();
        snap.insert(r"HKLM\Run\same".to_string(), RegistryValueData::Dword(1));
        let changes = diff_registry_snapshots(&snap, &snap);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_result_from_win32() {
        assert_eq!(RegistryResult::from_win32(0), RegistryResult::Success);
        assert_eq!(RegistryResult::from_win32(5), RegistryResult::AccessDenied);
        assert_eq!(RegistryResult::from_win32(259), RegistryResult::NoMoreItems);
    }

    #[test]
    fn test_registry_timeline_for_key() {
        let mut mon = RegistryMonitor::new(100);
        let key = r"HKLM\SOFTWARE\Test";
        mon.ingest(make_event(1, RegistryOperation::SetValue, key));
        mon.ingest(make_event(2, RegistryOperation::QueryValue, key));
        mon.ingest(make_event(3, RegistryOperation::SetValue, r"HKLM\OTHER"));
        let tl = mon.timeline_for_key(key);
        assert_eq!(tl.len(), 2);
    }
}
