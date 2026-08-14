// registry_watcher.rs — Registry operation watcher
// Tracks and analyzes registry read/write/delete activity from a monitored process.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Registry hive
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegistryHive {
    LocalMachine,
    CurrentUser,
    Users,
    ClassesRoot,
    CurrentConfig,
    PerformanceData,
    Unknown(String),
}

impl RegistryHive {
    #[must_use] 
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "HKEY_LOCAL_MACHINE" | "HKLM" => Self::LocalMachine,
            "HKEY_CURRENT_USER"  | "HKCU" => Self::CurrentUser,
            "HKEY_USERS"         | "HKU"  => Self::Users,
            "HKEY_CLASSES_ROOT"  | "HKCR" => Self::ClassesRoot,
            "HKEY_CURRENT_CONFIG"| "HKCC" => Self::CurrentConfig,
            "HKEY_PERFORMANCE_DATA"        => Self::PerformanceData,
            other => Self::Unknown(other.to_string()),
        }
    }

    #[must_use] 
    pub const fn abbreviation(&self) -> &str {
        match self {
            Self::LocalMachine    => "HKLM",
            Self::CurrentUser     => "HKCU",
            Self::Users           => "HKU",
            Self::ClassesRoot     => "HKCR",
            Self::CurrentConfig   => "HKCC",
            Self::PerformanceData => "HKPD",
            Self::Unknown(s)      => s.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// Registry path
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegPath {
    pub hive: RegistryHive,
    pub subkey: String,
}

impl RegPath {
    pub fn new(hive: RegistryHive, subkey: impl Into<String>) -> Self {
        Self { hive, subkey: subkey.into() }
    }

    /// Parse a full path like `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion`
    #[must_use] 
    pub fn parse(full: &str) -> Self {
        let normalized = full.replace('/', "\\");
        if let Some(idx) = normalized.find('\\') {
            let hive_str = &normalized[..idx];
            let subkey = &normalized[idx + 1..];
            Self::new(RegistryHive::from_str(hive_str), subkey)
        } else {
            Self::new(RegistryHive::from_str(full), "")
        }
    }

    #[must_use] 
    pub fn full_path(&self) -> String {
        format!("{}\\{}", self.hive.abbreviation(), self.subkey)
    }

    #[must_use] 
    pub fn is_autorun_key(&self) -> bool {
        let autorun_paths = [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "SYSTEM\\CurrentControlSet\\Services",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        ];
        let sub_low = self.subkey.to_lowercase();
        autorun_paths.iter().any(|p| sub_low.starts_with(&p.to_lowercase()))
    }

    #[must_use] 
    pub fn is_security_sensitive(&self) -> bool {
        let sensitive = [
            "sam",
            "security",
            "system\\currentcontrolset\\control\\lsa",
            "software\\policies",
            "system\\currentcontrolset\\control\\safeboot",
        ];
        let sub_low = self.subkey.to_lowercase();
        sensitive.iter().any(|s| sub_low.contains(s))
    }
}

// ---------------------------------------------------------------------------
// Registry value type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValueType {
    Sz,
    ExpandSz,
    Binary,
    Dword,
    DwordBigEndian,
    Link,
    MultiSz,
    Qword,
    None,
    Unknown(u32),
}

impl RegValueType {
    #[must_use] 
    pub const fn from_u32(v: u32) -> Self {
        match v {
            1  => Self::Sz,
            2  => Self::ExpandSz,
            3  => Self::Binary,
            4  => Self::Dword,
            5  => Self::DwordBigEndian,
            6  => Self::Link,
            7  => Self::MultiSz,
            11 => Self::Qword,
            0  => Self::None,
            n  => Self::Unknown(n),
        }
    }
}

// ---------------------------------------------------------------------------
// Registry value
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    Sz(String),
    ExpandSz(String),
    Binary(Vec<u8>),
    Dword(u32),
    Qword(u64),
    MultiSz(Vec<String>),
    None,
}

impl RegValue {
    #[must_use] 
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::Sz(s) | Self::ExpandSz(s) => Some(s),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Sz(_)       => "REG_SZ",
            Self::ExpandSz(_) => "REG_EXPAND_SZ",
            Self::Binary(_)   => "REG_BINARY",
            Self::Dword(_)    => "REG_DWORD",
            Self::Qword(_)    => "REG_QWORD",
            Self::MultiSz(_)  => "REG_MULTI_SZ",
            Self::None        => "REG_NONE",
        }
    }
}

// ---------------------------------------------------------------------------
// Registry operation type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegOperation {
    OpenKey,
    CreateKey,
    DeleteKey,
    QueryValue,
    SetValue,
    DeleteValue,
    EnumKeys,
    EnumValues,
    CloseKey,
    QueryInfo,
    LoadKey,
    UnloadKey,
    SaveKey,
    ReplaceKey,
    FlushKey,
}

impl std::fmt::Display for RegOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl RegOperation {
    #[must_use] 
    pub const fn is_write(&self) -> bool {
        matches!(self,
            Self::CreateKey | Self::DeleteKey |
            Self::SetValue  | Self::DeleteValue |
            Self::LoadKey   | Self::UnloadKey |
            Self::SaveKey   | Self::ReplaceKey
        )
    }

    #[must_use] 
    pub const fn is_read(&self) -> bool {
        matches!(self,
            Self::OpenKey | Self::QueryValue |
            Self::EnumKeys | Self::EnumValues |
            Self::QueryInfo
        )
    }
}

// ---------------------------------------------------------------------------
// Registry log entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RegEntry {
    pub id: u64,
    pub operation: RegOperation,
    pub path: RegPath,
    pub value_name: Option<String>,
    pub value: Option<RegValue>,
    pub previous_value: Option<RegValue>,
    pub process_id: u32,
    pub thread_id: u32,
    pub timestamp_ns: u64,
    pub result_code: u32,
    pub handle: u64,
}

impl RegEntry {
    #[must_use] 
    pub const fn new(
        id: u64,
        operation: RegOperation,
        path: RegPath,
        value_name: Option<String>,
        value: Option<RegValue>,
        pid: u32,
        tid: u32,
        ts: u64,
        result: u32,
    ) -> Self {
        Self {
            id,
            operation,
            path,
            value_name,
            value,
            previous_value: None,
            process_id: pid,
            thread_id: tid,
            timestamp_ns: ts,
            result_code: result,
            handle: 0,
        }
    }

    #[must_use] 
    pub const fn is_success(&self) -> bool {
        self.result_code == 0
    }

    #[must_use] 
    pub fn is_autorun_write(&self) -> bool {
        self.operation.is_write() && self.path.is_autorun_key()
    }

    #[must_use] 
    pub fn format(&self) -> String {
        let val_name = self.value_name.as_deref().unwrap_or("(default)");
        let val_str = match &self.value {
            Some(v) => match v {
                RegValue::Sz(s) | RegValue::ExpandSz(s) => format!("\"{s}\""),
                RegValue::Dword(d) => format!("0x{d:08X}"),
                RegValue::Qword(q) => format!("0x{q:016X}"),
                RegValue::Binary(b) => format!("<{} bytes>", b.len()),
                RegValue::MultiSz(v) => format!("[{}]", v.join(", ")),
                RegValue::None => "(none)".to_string(),
            },
            None => String::new(),
        };
        format!(
            "[{:6}] {} {} \\ {} = {} [PID:{} result:0x{:08X}]",
            self.id,
            self.operation,
            self.path.full_path(),
            val_name,
            val_str,
            self.process_id,
            self.result_code,
        )
    }
}

// ---------------------------------------------------------------------------
// Registry snapshot (current values of tracked keys)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct RegistrySnapshot {
    /// Map from `full_path`\\`value_name` to current value
    values: HashMap<String, RegValue>,
}

impl RegistrySnapshot {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    fn key(path: &RegPath, value_name: Option<&str>) -> String {
        format!("{}\\{}", path.full_path(), value_name.unwrap_or("(default)"))
    }

    pub fn set(&mut self, path: &RegPath, value_name: Option<&str>, value: RegValue) {
        self.values.insert(Self::key(path, value_name), value);
    }

    #[must_use] 
    pub fn get(&self, path: &RegPath, value_name: Option<&str>) -> Option<&RegValue> {
        self.values.get(&Self::key(path, value_name))
    }

    pub fn remove(&mut self, path: &RegPath, value_name: Option<&str>) {
        self.values.remove(&Self::key(path, value_name));
    }

    #[must_use] 
    pub fn len(&self) -> usize { self.values.len() }
    #[must_use] 
    pub fn is_empty(&self) -> bool { self.values.is_empty() }
}

// ---------------------------------------------------------------------------
// Registry log
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct RegistryLog {
    pub entries: Vec<RegEntry>,
    pub max_entries: usize,
    pub next_id: u64,
}

impl RegistryLog {
    #[must_use] 
    pub fn new(max_entries: usize) -> Self {
        Self { max_entries, next_id: 1, ..Default::default() }
    }

    pub fn add(&mut self, mut entry: RegEntry) {
        entry.id = self.next_id;
        self.next_id += 1;
        if self.entries.len() < self.max_entries {
            self.entries.push(entry);
        }
    }

    pub fn writes(&self) -> impl Iterator<Item = &RegEntry> {
        self.entries.iter().filter(|e| e.operation.is_write())
    }

    pub fn reads(&self) -> impl Iterator<Item = &RegEntry> {
        self.entries.iter().filter(|e| e.operation.is_read())
    }

    #[must_use] 
    pub fn autorun_writes(&self) -> Vec<&RegEntry> {
        self.entries.iter().filter(|e| e.is_autorun_write()).collect()
    }

    #[must_use] 
    pub fn failed_ops(&self) -> Vec<&RegEntry> {
        self.entries.iter().filter(|e| !e.is_success()).collect()
    }

    #[must_use] 
    pub fn ops_by_key(&self, path: &RegPath) -> Vec<&RegEntry> {
        let fp = path.full_path();
        self.entries.iter().filter(|e| e.path.full_path() == fp).collect()
    }

    #[must_use] 
    pub fn format(&self) -> Vec<String> {
        self.entries.iter().map(RegEntry::format).collect()
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct RegistryStats {
    pub total_ops: u64,
    pub reads: u64,
    pub writes: u64,
    pub creates: u64,
    pub deletes: u64,
    pub failed: u64,
    pub autorun_writes: u64,
    pub unique_paths: std::collections::HashSet<String>,
}

impl RegistryStats {
    pub fn update(&mut self, entry: &RegEntry) {
        self.total_ops += 1;
        if entry.operation.is_read()  { self.reads += 1; }
        if entry.operation.is_write() { self.writes += 1; }
        if entry.operation == RegOperation::CreateKey   { self.creates += 1; }
        if entry.operation == RegOperation::DeleteKey
            || entry.operation == RegOperation::DeleteValue {
            self.deletes += 1;
        }
        if !entry.is_success() { self.failed += 1; }
        if entry.is_autorun_write() { self.autorun_writes += 1; }
        self.unique_paths.insert(entry.path.full_path());
    }
}

// ---------------------------------------------------------------------------
// RegistryWatcher — main type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct RegistryWatcher {
    pub log: RegistryLog,
    pub stats: RegistryStats,
    pub snapshot: RegistrySnapshot,
    pub track_previous_values: bool,
}

impl RegistryWatcher {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            log: RegistryLog::new(100_000),
            stats: RegistryStats::default(),
            snapshot: RegistrySnapshot::new(),
            track_previous_values: false,
        }
    }

    #[must_use] 
    pub const fn with_max_log(mut self, n: usize) -> Self {
        self.log.max_entries = n;
        self
    }

    #[must_use] 
    pub const fn track_previous(mut self) -> Self {
        self.track_previous_values = true;
        self
    }

    /// Record a registry event.
    pub fn record(
        &mut self,
        operation: RegOperation,
        path: RegPath,
        value_name: Option<String>,
        value: Option<RegValue>,
        pid: u32,
        tid: u32,
        timestamp_ns: u64,
        result: u32,
    ) {
        let mut entry = RegEntry::new(
            0,
            operation.clone(),
            path.clone(),
            value_name.clone(),
            value.clone(),
            pid,
            tid,
            timestamp_ns,
            result,
        );

        // Track previous value for set operations
        if self.track_previous_values && operation == RegOperation::SetValue {
            entry.previous_value = self.snapshot
                .get(&path, value_name.as_deref())
                .cloned();
        }

        // Update snapshot
        match operation {
            RegOperation::SetValue => {
                if let Some(v) = value {
                    self.snapshot.set(&path, value_name.as_deref(), v);
                }
            }
            RegOperation::DeleteValue => {
                self.snapshot.remove(&path, value_name.as_deref());
            }
            _ => {}
        }

        self.stats.update(&entry);
        self.log.add(entry);
    }

    /// Return all suspicious observations.
    #[must_use] 
    pub fn detect_suspicious(&self) -> Vec<RegistrySuspicion> {
        let mut findings = Vec::new();

        // Persistence: autorun key writes
        let autoruns = self.log.autorun_writes();
        if !autoruns.is_empty() {
            findings.push(RegistrySuspicion {
                kind: SuspicionKind::Persistence,
                description: format!(
                    "{} write(s) to autorun registry keys detected",
                    autoruns.len()
                ),
                severity: RegistrySuspicionSeverity::High,
                paths: autoruns.iter().map(|e| e.path.full_path()).collect(),
            });
        }

        // Security-sensitive key access
        let sens: Vec<&RegEntry> = self.log.entries.iter()
            .filter(|e| e.path.is_security_sensitive())
            .collect();
        if !sens.is_empty() {
            findings.push(RegistrySuspicion {
                kind: SuspicionKind::PrivilegeEscalation,
                description: format!(
                    "{} access(es) to security-sensitive keys (SAM, LSA, etc.)",
                    sens.len()
                ),
                severity: RegistrySuspicionSeverity::High,
                paths: sens.iter().map(|e| e.path.full_path()).collect(),
            });
        }

        // Mass delete
        if self.stats.deletes > 50 {
            findings.push(RegistrySuspicion {
                kind: SuspicionKind::Destruction,
                description: format!("{} registry key/value deletions — possible cleanup", self.stats.deletes),
                severity: RegistrySuspicionSeverity::Medium,
                paths: Vec::new(),
            });
        }

        // Policy weakening (disable UAC etc.)
        let policy_writes: Vec<&RegEntry> = self.log.entries.iter()
            .filter(|e| {
                e.operation.is_write()
                    && e.path.subkey.to_lowercase().contains("policies")
            })
            .collect();
        if !policy_writes.is_empty() {
            findings.push(RegistrySuspicion {
                kind: SuspicionKind::DefenseEvasion,
                description: format!(
                    "{} write(s) to policy keys — possible UAC/AV bypass",
                    policy_writes.len()
                ),
                severity: RegistrySuspicionSeverity::High,
                paths: policy_writes.iter().map(|e| e.path.full_path()).collect(),
            });
        }

        findings
    }
}

impl Default for RegistryWatcher {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Suspicion types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RegistrySuspicion {
    pub kind: SuspicionKind,
    pub description: String,
    pub severity: RegistrySuspicionSeverity,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuspicionKind {
    Persistence,
    DefenseEvasion,
    PrivilegeEscalation,
    Destruction,
    Exfiltration,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegistrySuspicionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RegistrySuspicionSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(op: RegOperation, path: &str, value_name: Option<&str>, value: Option<RegValue>) -> RegEntry {
        RegEntry::new(
            0, op,
            RegPath::parse(path),
            value_name.map(String::from),
            value,
            1000, 2000, 0, 0,
        )
    }

    #[test]
    fn test_reg_path_parse() {
        let p = RegPath::parse("HKLM\\SOFTWARE\\Microsoft");
        assert_eq!(p.hive, RegistryHive::LocalMachine);
        assert_eq!(p.subkey, "SOFTWARE\\Microsoft");
        assert_eq!(p.full_path(), "HKLM\\SOFTWARE\\Microsoft");
    }

    #[test]
    fn test_reg_path_autorun() {
        let p = RegPath::parse("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        assert!(p.is_autorun_key());
    }

    #[test]
    fn test_reg_path_security_sensitive() {
        let p = RegPath::parse("HKLM\\SAM");
        assert!(p.is_security_sensitive());
    }

    #[test]
    fn test_reg_operation_classification() {
        assert!(RegOperation::SetValue.is_write());
        assert!(RegOperation::QueryValue.is_read());
        assert!(!RegOperation::QueryValue.is_write());
    }

    #[test]
    fn test_reg_entry_format() {
        let e = make_entry(
            RegOperation::SetValue,
            "HKLM\\SOFTWARE\\Test",
            Some("foo"),
            Some(RegValue::Sz("bar".to_string())),
        );
        let s = e.format();
        assert!(s.contains("SetValue"));
        assert!(s.contains("foo"));
        assert!(s.contains("bar"));
    }

    #[test]
    fn test_registry_log_writes_reads() {
        let mut log = RegistryLog::new(100);
        log.add(make_entry(RegOperation::SetValue, "HKLM\\SOFTWARE", Some("k"), None));
        log.add(make_entry(RegOperation::QueryValue, "HKLM\\SOFTWARE", Some("k"), None));
        assert_eq!(log.writes().count(), 1);
        assert_eq!(log.reads().count(), 1);
    }

    #[test]
    fn test_watcher_record_and_snapshot() {
        let mut watcher = RegistryWatcher::new().track_previous();
        watcher.record(
            RegOperation::SetValue,
            RegPath::parse("HKCU\\test"),
            Some("val".to_string()),
            Some(RegValue::Dword(42)),
            1, 2, 0, 0,
        );
        let snap = watcher.snapshot.get(&RegPath::parse("HKCU\\test"), Some("val"));
        assert_eq!(snap, Some(&RegValue::Dword(42)));
        assert_eq!(watcher.stats.writes, 1);
    }

    #[test]
    fn test_detect_persistence() {
        let mut watcher = RegistryWatcher::new();
        watcher.record(
            RegOperation::SetValue,
            RegPath::parse("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            Some("Malware".to_string()),
            Some(RegValue::Sz("C:\\evil.exe".to_string())),
            1, 2, 0, 0,
        );
        let findings = watcher.detect_suspicious();
        assert!(findings.iter().any(|f| f.kind == SuspicionKind::Persistence));
    }

    #[test]
    fn test_detect_security_sensitive() {
        let mut watcher = RegistryWatcher::new();
        watcher.record(
            RegOperation::QueryValue,
            RegPath::parse("HKLM\\SAM\\Domains"),
            None,
            None,
            1, 2, 0, 0,
        );
        let findings = watcher.detect_suspicious();
        assert!(findings.iter().any(|f| f.kind == SuspicionKind::PrivilegeEscalation));
    }

    #[test]
    fn test_snapshot_delete() {
        let mut snap = RegistrySnapshot::new();
        let p = RegPath::parse("HKLM\\test");
        snap.set(&p, Some("k"), RegValue::Dword(1));
        assert!(snap.get(&p, Some("k")).is_some());
        snap.remove(&p, Some("k"));
        assert!(snap.get(&p, Some("k")).is_none());
    }

    #[test]
    fn test_registry_stats_update() {
        let mut stats = RegistryStats::default();
        let e1 = make_entry(RegOperation::SetValue, "HKLM\\test", None, None);
        let e2 = make_entry(RegOperation::QueryValue, "HKLM\\test", None, None);
        stats.update(&e1);
        stats.update(&e2);
        assert_eq!(stats.writes, 1);
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.total_ops, 2);
    }

    #[test]
    fn test_autorun_write_detected() {
        let mut watcher = RegistryWatcher::new();
        watcher.record(
            RegOperation::SetValue,
            RegPath::parse("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            Some("init".to_string()),
            Some(RegValue::Sz("notepad.exe".to_string())),
            999, 1, 100, 0,
        );
        assert_eq!(watcher.stats.autorun_writes, 1);
        assert_eq!(watcher.log.autorun_writes().len(), 1);
    }

    #[test]
    fn test_hive_abbreviation() {
        assert_eq!(RegistryHive::LocalMachine.abbreviation(), "HKLM");
        assert_eq!(RegistryHive::CurrentUser.abbreviation(), "HKCU");
    }
}
