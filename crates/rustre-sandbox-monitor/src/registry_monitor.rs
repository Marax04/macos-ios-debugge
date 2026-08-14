// registry_monitor.rs — registry operation monitor for sandbox analysis
// Tracks registry creates/reads/writes/deletes and detects persistence mechanisms.

use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─── Registry hive ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryHive {
    HkeyLocalMachine,
    HkeyCurrentUser,
    HkeyUsers,
    HkeyClassesRoot,
    HkeyCurrentConfig,
    HkeyPerformanceData,
    Unknown,
}

impl RegistryHive {
    #[must_use] 
    pub fn from_path(path: &str) -> Self {
        let upper = path.to_ascii_uppercase();
        if upper.starts_with("HKLM") || upper.starts_with("HKEY_LOCAL_MACHINE") {
            Self::HkeyLocalMachine
        } else if upper.starts_with("HKCU") || upper.starts_with("HKEY_CURRENT_USER") {
            Self::HkeyCurrentUser
        } else if upper.starts_with("HKU") || upper.starts_with("HKEY_USERS") {
            Self::HkeyUsers
        } else if upper.starts_with("HKCR") || upper.starts_with("HKEY_CLASSES_ROOT") {
            Self::HkeyClassesRoot
        } else if upper.starts_with("HKCC") || upper.starts_with("HKEY_CURRENT_CONFIG") {
            Self::HkeyCurrentConfig
        } else {
            Self::Unknown
        }
    }

    #[must_use] 
    pub const fn abbreviation(self) -> &'static str {
        match self {
            Self::HkeyLocalMachine => "HKLM",
            Self::HkeyCurrentUser => "HKCU",
            Self::HkeyUsers => "HKU",
            Self::HkeyClassesRoot => "HKCR",
            Self::HkeyCurrentConfig => "HKCC",
            Self::HkeyPerformanceData => "HKPD",
            Self::Unknown => "???",
        }
    }
}

// ─── Registry value type ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegValueType {
    Sz,
    ExpandSz,
    Binary,
    Dword,
    DwordBigEndian,
    MultiSz,
    Qword,
    None,
    Unknown(u32),
}

impl RegValueType {
    #[must_use] 
    pub const fn from_type_code(code: u32) -> Self {
        match code {
            0 => Self::None,
            1 => Self::Sz,
            2 => Self::ExpandSz,
            3 => Self::Binary,
            4 => Self::Dword,
            5 => Self::DwordBigEndian,
            7 => Self::MultiSz,
            11 => Self::Qword,
            _ => Self::Unknown(code),
        }
    }

    #[must_use] 
    pub const fn type_code(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Sz => 1,
            Self::ExpandSz => 2,
            Self::Binary => 3,
            Self::Dword => 4,
            Self::DwordBigEndian => 5,
            Self::MultiSz => 7,
            Self::Qword => 11,
            Self::Unknown(c) => *c,
        }
    }

    #[must_use] 
    pub const fn is_string_type(&self) -> bool {
        matches!(self, Self::Sz | Self::ExpandSz | Self::MultiSz)
    }
}

// ─── Registry value data ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegValueData {
    String(String),
    Binary(Vec<u8>),
    Dword(u32),
    Qword(u64),
    MultiString(Vec<String>),
    None,
}

impl RegValueData {
    #[must_use] 
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn as_u32(&self) -> Option<u32> {
        match self {
            Self::Dword(v) => Some(*v),
            _ => None,
        }
    }

    #[must_use] 
    pub fn size_bytes(&self) -> usize {
        match self {
            Self::String(s) => (s.len() + 1) * 2, // UTF-16
            Self::Binary(b) => b.len(),
            Self::Dword(_) => 4,
            Self::Qword(_) => 8,
            Self::MultiString(v) => v.iter().map(|s| (s.len() + 1) * 2).sum::<usize>() + 2,
            Self::None => 0,
        }
    }
}

// ─── Registry operation kind ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegOpKind {
    CreateKey,
    OpenKey,
    DeleteKey,
    QueryKey,
    EnumKey,
    SetValue,
    QueryValue,
    DeleteValue,
    EnumValue,
    LoadKey,
    SaveKey,
    RestoreKey,
    ReplaceKey,
    FlushKey,
}

impl RegOpKind {
    #[must_use] 
    pub const fn is_write(self) -> bool {
        matches!(self, Self::CreateKey | Self::DeleteKey | Self::SetValue | Self::DeleteValue | Self::LoadKey | Self::RestoreKey | Self::ReplaceKey)
    }

    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateKey => "RegCreateKey",
            Self::OpenKey => "RegOpenKey",
            Self::DeleteKey => "RegDeleteKey",
            Self::QueryKey => "RegQueryKey",
            Self::EnumKey => "RegEnumKey",
            Self::SetValue => "RegSetValue",
            Self::QueryValue => "RegQueryValue",
            Self::DeleteValue => "RegDeleteValue",
            Self::EnumValue => "RegEnumValue",
            Self::LoadKey => "RegLoadKey",
            Self::SaveKey => "RegSaveKey",
            Self::RestoreKey => "RegRestoreKey",
            Self::ReplaceKey => "RegReplaceKey",
            Self::FlushKey => "RegFlushKey",
        }
    }
}

// ─── Registry event ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub process_name: String,
    pub op: RegOpKind,
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_type: Option<RegValueType>,
    pub value_data: Option<RegValueData>,
    pub status: u32,
    pub hive: RegistryHive,
}

impl RegistryEvent {
    #[must_use] 
    pub fn new(pid: u32, tid: u32, process_name: String, op: RegOpKind, key_path: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64;
        let hive = RegistryHive::from_path(&key_path);
        Self {
            timestamp, pid, tid, process_name, op, key_path, value_name: None,
            value_type: None, value_data: None, status: 0, hive,
        }
    }

    #[must_use] 
    pub fn with_value(mut self, name: String, vtype: RegValueType, data: RegValueData) -> Self {
        self.value_name = Some(name);
        self.value_type = Some(vtype);
        self.value_data = Some(data);
        self
    }

    #[must_use] 
    pub const fn with_status(mut self, s: u32) -> Self {
        self.status = s;
        self
    }

    #[must_use] 
    pub const fn succeeded(&self) -> bool {
        self.status == 0
    }

    #[must_use] 
    pub fn full_path(&self) -> String {
        match &self.value_name {
            Some(v) => format!("{}\\{}", self.key_path, v),
            None => self.key_path.clone(),
        }
    }
}

// ─── Known persistence key patterns ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistenceType {
    Run,
    RunOnce,
    RunServices,
    ServiceInstall,
    ClsidHijack,
    AppInit,
    WinlogonNotify,
    WinlogonShell,
    WinlogonUserinit,
    BootExecute,
    SeDebugPrivilege,
    FileAssociation,
    BrowserHelper,
    LsaAuth,
    NetshHelper,
    ImageFileExecutionOptions,
    SilentProcessExit,
    TerminalServerInitialProgram,
    ActiveSetup,
    Other(String),
}

impl PersistenceType {
    #[must_use] 
    pub const fn severity(&self) -> u8 {
        match self {
            Self::BootExecute => 10,
            Self::LsaAuth => 10,
            Self::WinlogonShell | Self::WinlogonUserinit => 9,
            Self::ServiceInstall => 9,
            Self::AppInit => 8,
            Self::Run | Self::RunOnce | Self::RunServices => 8,
            Self::ImageFileExecutionOptions => 8,
            Self::SilentProcessExit => 8,
            Self::ClsidHijack => 7,
            Self::WinlogonNotify => 7,
            Self::BrowserHelper => 6,
            Self::NetshHelper => 7,
            Self::ActiveSetup => 7,
            _ => 5,
        }
    }

    #[must_use] 
    pub const fn description(&self) -> &str {
        match self {
            Self::Run => "HKCU/HKLM Run key — auto-start on login",
            Self::RunOnce => "Run-once auto-start on next login",
            Self::RunServices => "Run services on startup",
            Self::ServiceInstall => "Windows service installed",
            Self::ClsidHijack => "COM CLSID hijack",
            Self::AppInit => "AppInit_DLLs — injected into every process",
            Self::WinlogonNotify => "Winlogon notification package",
            Self::WinlogonShell => "Winlogon Shell replacement",
            Self::WinlogonUserinit => "Winlogon Userinit replacement",
            Self::BootExecute => "Boot-time execution via BootExecute",
            Self::SeDebugPrivilege => "SeDebug privilege modification",
            Self::FileAssociation => "File association hijack",
            Self::BrowserHelper => "Browser Helper Object (BHO)",
            Self::LsaAuth => "LSA authentication package",
            Self::NetshHelper => "Netsh helper DLL",
            Self::ImageFileExecutionOptions => "Image File Execution Options debugger hijack",
            Self::SilentProcessExit => "Silent process exit monitoring",
            Self::TerminalServerInitialProgram => "Terminal server initial program",
            Self::ActiveSetup => "Active Setup StubPath",
            Self::Other(s) => s.as_str(),
        }
    }
}

// ─── Persistence key database ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PersistenceKeyDatabase {
    entries: Vec<PersistenceKeyPattern>,
}

#[derive(Debug, Clone)]
struct PersistenceKeyPattern {
    key_fragment: &'static str,
    value_fragment: Option<&'static str>,
    persistence_type: fn() -> PersistenceType,
}

impl PersistenceKeyDatabase {
    #[must_use] 
    pub fn default_db() -> Self {
        let entries = vec![
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", value_fragment: None, persistence_type: || PersistenceType::Run },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", value_fragment: None, persistence_type: || PersistenceType::RunOnce },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices", value_fragment: None, persistence_type: || PersistenceType::RunServices },
            PersistenceKeyPattern { key_fragment: "\\SYSTEM\\CurrentControlSet\\Services", value_fragment: Some("ImagePath"), persistence_type: || PersistenceType::ServiceInstall },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Classes\\CLSID", value_fragment: Some("InprocServer32"), persistence_type: || PersistenceType::ClsidHijack },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Classes\\CLSID", value_fragment: Some("LocalServer32"), persistence_type: || PersistenceType::ClsidHijack },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", value_fragment: Some("AppInit_DLLs"), persistence_type: || PersistenceType::AppInit },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", value_fragment: Some("Notify"), persistence_type: || PersistenceType::WinlogonNotify },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", value_fragment: Some("Shell"), persistence_type: || PersistenceType::WinlogonShell },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", value_fragment: Some("Userinit"), persistence_type: || PersistenceType::WinlogonUserinit },
            PersistenceKeyPattern { key_fragment: "\\SYSTEM\\CurrentControlSet\\Control\\Session Manager", value_fragment: Some("BootExecute"), persistence_type: || PersistenceType::BootExecute },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", value_fragment: Some("Debugger"), persistence_type: || PersistenceType::ImageFileExecutionOptions },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit", value_fragment: None, persistence_type: || PersistenceType::SilentProcessExit },
            PersistenceKeyPattern { key_fragment: "\\SYSTEM\\CurrentControlSet\\Control\\Lsa", value_fragment: Some("Authentication Packages"), persistence_type: || PersistenceType::LsaAuth },
            PersistenceKeyPattern { key_fragment: "\\SYSTEM\\CurrentControlSet\\Control\\Lsa", value_fragment: Some("Security Packages"), persistence_type: || PersistenceType::LsaAuth },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Microsoft\\Netsh", value_fragment: None, persistence_type: || PersistenceType::NetshHelper },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", value_fragment: None, persistence_type: || PersistenceType::BrowserHelper },
            PersistenceKeyPattern { key_fragment: "\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components", value_fragment: Some("StubPath"), persistence_type: || PersistenceType::ActiveSetup },
        ];
        Self { entries }
    }

    #[must_use] 
    pub fn check(&self, event: &RegistryEvent) -> Option<PersistenceType> {
        if !event.op.is_write() || !event.succeeded() {
            return None;
        }
        let key_upper = event.key_path.to_ascii_uppercase();
        let val_upper = event.value_name.as_deref().map(str::to_ascii_uppercase);

        for pattern in &self.entries {
            let frag_upper = pattern.key_fragment.to_ascii_uppercase();
            if !key_upper.contains(&frag_upper) {
                continue;
            }
            if let Some(vf) = pattern.value_fragment {
                let vf_upper = vf.to_ascii_uppercase();
                if val_upper.as_deref().is_none_or(|v| !v.contains(&vf_upper)) {
                    continue;
                }
            }
            return Some((pattern.persistence_type)());
        }
        None
    }
}

// ─── Persistence finding ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceFinding {
    pub persistence_type: PersistenceType,
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_data_summary: Option<String>,
    pub pid: u32,
    pub process_name: String,
    pub timestamp: u64,
    pub severity: u8,
}

impl PersistenceFinding {
    #[must_use] 
    pub fn from_event(event: &RegistryEvent, ptype: PersistenceType) -> Self {
        let severity = ptype.severity();
        let value_data_summary = event.value_data.as_ref().map(|d| match d {
            RegValueData::String(s) => s.clone(),
            RegValueData::Dword(v) => format!("0x{v:08x}"),
            RegValueData::Binary(b) => format!("<binary {} bytes>", b.len()),
            RegValueData::Qword(v) => format!("0x{v:016x}"),
            RegValueData::MultiString(v) => v.join("; "),
            RegValueData::None => String::new(),
        });
        Self {
            persistence_type: ptype,
            key_path: event.key_path.clone(),
            value_name: event.value_name.clone(),
            value_data_summary,
            pid: event.pid,
            process_name: event.process_name.clone(),
            timestamp: event.timestamp,
            severity,
        }
    }
}

// ─── Key access pattern ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyAccessPattern {
    pub key_path: String,
    pub pids_writing: HashSet<u32>,
    pub pids_reading: HashSet<u32>,
    pub write_count: u32,
    pub read_count: u32,
    pub delete_count: u32,
    pub first_seen: u64,
    pub last_seen: u64,
    pub values_set: HashSet<String>,
    pub values_deleted: HashSet<String>,
}

impl KeyAccessPattern {
    #[must_use] 
    pub fn new(key_path: String, ts: u64) -> Self {
        Self { key_path, first_seen: ts, last_seen: ts, ..Default::default() }
    }

    pub fn update(&mut self, event: &RegistryEvent) {
        self.last_seen = self.last_seen.max(event.timestamp);
        self.first_seen = self.first_seen.min(event.timestamp);
        match event.op {
            RegOpKind::SetValue => {
                self.write_count += 1;
                self.pids_writing.insert(event.pid);
                if let Some(v) = &event.value_name {
                    self.values_set.insert(v.clone());
                }
            }
            RegOpKind::CreateKey => {
                self.write_count += 1;
                self.pids_writing.insert(event.pid);
            }
            RegOpKind::DeleteKey | RegOpKind::DeleteValue => {
                self.delete_count += 1;
                self.pids_writing.insert(event.pid);
                if let Some(v) = &event.value_name {
                    self.values_deleted.insert(v.clone());
                }
            }
            RegOpKind::QueryValue | RegOpKind::QueryKey | RegOpKind::EnumKey | RegOpKind::EnumValue => {
                self.read_count += 1;
                self.pids_reading.insert(event.pid);
            }
            _ => {}
        }
    }

    #[must_use] 
    pub fn is_contested(&self) -> bool {
        self.pids_writing.len() > 1
    }
}

// ─── Shadow copy deletion detection ─────────────────────────────────────────

/// Returns `true` if the registry event represents a shadow-copy deletion
/// (a classic pre-encryption step performed by ransomware).
#[must_use] 
pub fn is_shadow_copy_deletion(event: &RegistryEvent) -> bool {
    // Ransomware may delete VSS via registry before using vssadmin
    let key_upper = event.key_path.to_ascii_uppercase();
    key_upper.contains("SHADOW") && event.op == RegOpKind::DeleteKey
}

/// Scan a slice of registry events in parallel and return every entry that
/// matches the shadow-copy-deletion heuristic. Uses Rayon for throughput on
/// large traces.
#[must_use]
pub fn find_shadow_copy_deletions(events: &[RegistryEvent]) -> Vec<RegistryEvent> {
    events
        .par_iter()
        .filter(|e| is_shadow_copy_deletion(e))
        .cloned()
        .collect()
}

// ─── Security-relevant value monitor ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicyChange {
    pub key_path: String,
    pub value_name: String,
    pub new_value: RegValueData,
    pub pid: u32,
    pub process_name: String,
    pub description: String,
}

fn check_security_policy(event: &RegistryEvent) -> Option<SecurityPolicyChange> {
    if !event.op.is_write() { return None; }
    let key_upper = event.key_path.to_ascii_uppercase();
    let val_upper = event.value_name.as_deref().unwrap_or("").to_ascii_uppercase();

    let desc: Option<&'static str> = if key_upper.contains("\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\LSA") && val_upper == "LMCOMPATIBILITYLEVEL" {
        Some("LAN Manager authentication level modified")
    } else if key_upper.contains("WINDOWS DEFENDER") && val_upper == "DISABLEREALTIMEMONITORING" {
        Some("Windows Defender real-time monitoring disabled")
    } else if key_upper.contains("WINDOWS DEFENDER") && val_upper == "DISABLEBEHAVIORMONITORING" {
        Some("Windows Defender behavior monitoring disabled")
    } else if key_upper.contains("WINDOWS DEFENDER") && val_upper == "DISABLEIOAVPROTECTION" {
        Some("Windows Defender IOAV protection disabled")
    } else if key_upper.contains("FIREWALL") && val_upper == "ENABLEFIREWALL" {
        Some("Firewall state modified")
    } else if key_upper.contains("UACSETTINGS") || (key_upper.contains("SYSTEM") && val_upper == "ENABLELUA") {
        Some("UAC setting modified")
    } else if key_upper.contains("DRWATSON") || val_upper.contains("DONTSHOWUI") {
        Some("Error reporting / Dr. Watson modified (anti-forensics)")
    } else if key_upper.contains("SAFE BOOT") {
        Some("Safe boot configuration modified")
    } else {
        None
    };

    desc.map(|d| SecurityPolicyChange {
        key_path: event.key_path.clone(),
        value_name: event.value_name.clone().unwrap_or_default(),
        new_value: event.value_data.clone().unwrap_or(RegValueData::None),
        pid: event.pid,
        process_name: event.process_name.clone(),
        description: d.to_string(),
    })
}

// ─── Registry monitor core ───────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryMonitor {
    events: Vec<RegistryEvent>,
    key_patterns: HashMap<String, KeyAccessPattern>,
    persistence_findings: Vec<PersistenceFinding>,
    security_changes: Vec<SecurityPolicyChange>,
    #[serde(skip, default = "PersistenceKeyDatabase::default_db")]
    persistence_db: PersistenceKeyDatabase,
    ignored_prefixes: Vec<String>,
}

impl RegistryMonitor {
    #[must_use] 
    pub fn new() -> Self {
        let persistence_db = PersistenceKeyDatabase::default_db();
        Self {
            events: Vec::new(),
            key_patterns: HashMap::new(),
            persistence_findings: Vec::new(),
            security_changes: Vec::new(),
            persistence_db,
            ignored_prefixes: vec![
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs".to_ascii_uppercase(),
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad".to_ascii_uppercase(),
            ],
        }
    }

    pub fn with_ignored(mut self, prefixes: impl IntoIterator<Item = String>) -> Self {
        for p in prefixes { self.ignored_prefixes.push(p.to_ascii_uppercase()); }
        self
    }

    fn is_ignored(&self, path: &str) -> bool {
        let upper = path.to_ascii_uppercase();
        self.ignored_prefixes.iter().any(|p| upper.starts_with(p.as_str()))
    }

    pub fn ingest(&mut self, event: RegistryEvent) {
        if self.is_ignored(&event.key_path) {
            return;
        }

        let ts = event.timestamp;
        let pattern = self.key_patterns.entry(event.key_path.clone()).or_insert_with(|| KeyAccessPattern::new(event.key_path.clone(), ts));
        pattern.update(&event);

        if let Some(ptype) = self.persistence_db.check(&event) {
            let finding = PersistenceFinding::from_event(&event, ptype);
            // dedup by key+value
            let already = self.persistence_findings.iter().any(|f| f.key_path == finding.key_path && f.value_name == finding.value_name);
            if !already {
                self.persistence_findings.push(finding);
            }
        }

        if let Some(change) = check_security_policy(&event) {
            self.security_changes.push(change);
        }

        self.events.push(event);
    }

    pub fn ingest_batch(&mut self, events: Vec<RegistryEvent>) {
        for e in events {
            self.ingest(e);
        }
    }

    // ─── Queries ──────────────────────────────────────────────────────────────

    #[must_use] 
    pub fn events_for_pid(&self, pid: u32) -> Vec<&RegistryEvent> {
        self.events.iter().filter(|e| e.pid == pid).collect()
    }

    #[must_use] 
    pub fn events_for_key(&self, key: &str) -> Vec<&RegistryEvent> {
        let key_upper = key.to_ascii_uppercase();
        self.events.iter().filter(|e| e.key_path.to_ascii_uppercase().contains(&key_upper)).collect()
    }

    #[must_use] 
    pub fn write_events(&self) -> Vec<&RegistryEvent> {
        self.events.iter().filter(|e| e.op.is_write() && e.succeeded()).collect()
    }

    #[must_use] 
    pub fn persistence_findings(&self) -> &[PersistenceFinding] {
        &self.persistence_findings
    }

    #[must_use] 
    pub fn high_severity_persistence(&self, min: u8) -> Vec<&PersistenceFinding> {
        self.persistence_findings.iter().filter(|f| f.severity >= min).collect()
    }

    #[must_use] 
    pub fn security_changes(&self) -> &[SecurityPolicyChange] {
        &self.security_changes
    }

    #[must_use] 
    pub fn unique_keys_written(&self) -> HashSet<&str> {
        self.events.iter().filter(|e| e.op.is_write()).map(|e| e.key_path.as_str()).collect()
    }

    #[must_use] 
    pub fn unique_pids(&self) -> HashSet<u32> {
        self.events.iter().map(|e| e.pid).collect()
    }

    #[must_use] 
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    #[must_use] 
    pub fn events(&self) -> &[RegistryEvent] {
        &self.events
    }

    #[must_use] 
    pub const fn key_patterns(&self) -> &HashMap<String, KeyAccessPattern> {
        &self.key_patterns
    }

    #[must_use] 
    pub fn keys_written_by_pid(&self, pid: u32) -> Vec<&str> {
        self.events.iter()
            .filter(|e| e.pid == pid && e.op.is_write() && e.succeeded())
            .map(|e| e.key_path.as_str())
            .collect()
    }

    #[must_use] 
    pub fn most_active_keys(&self, top_n: usize) -> Vec<(&str, u32)> {
        let mut counts: HashMap<&str, u32> = HashMap::new();
        for e in &self.events {
            *counts.entry(e.key_path.as_str()).or_default() += 1;
        }
        let mut v: Vec<_> = counts.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(top_n);
        v
    }

    /// Check if any `DefenderExclusion` key writes were observed (common malware evasion)
    #[must_use] 
    pub fn defender_exclusions_added(&self) -> Vec<&RegistryEvent> {
        self.events.iter().filter(|e| {
            e.op.is_write() && e.key_path.to_ascii_uppercase().contains("DEFENDER\\EXCLUSIONS")
        }).collect()
    }

    /// Detect registry-based process hollowing indicators (`SilentProcessExit` + `MonitorProcess`)
    #[must_use] 
    pub fn process_hollowing_indicators(&self) -> Vec<&RegistryEvent> {
        self.events.iter().filter(|e| {
            let k = e.key_path.to_ascii_uppercase();
            k.contains("SILENTPROCESSEXIT") && e.op.is_write()
        }).collect()
    }

    /// Returns keys modified in the given time window [`start_ms`, `end_ms`]
    #[must_use] 
    pub fn events_in_window(&self, start_ms: u64, end_ms: u64) -> Vec<&RegistryEvent> {
        self.events.iter().filter(|e| e.timestamp >= start_ms && e.timestamp <= end_ms).collect()
    }
}

impl Default for RegistryMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Registry diff ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistrySnapshot {
    pub timestamp: u64,
    pub keys: HashMap<String, Vec<(String, RegValueData)>>, // key → [(value_name, data)]
}

impl RegistrySnapshot {
    #[must_use] 
    pub fn new() -> Self {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_millis() as u64;
        Self { timestamp: ts, keys: HashMap::new() }
    }

    pub fn add_value(&mut self, key: String, value_name: String, data: RegValueData) {
        self.keys.entry(key).or_default().push((value_name, data));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryDiff {
    pub added_keys: Vec<String>,
    pub deleted_keys: Vec<String>,
    pub modified_keys: Vec<String>,
    pub added_values: Vec<(String, String)>,   // (key, value_name)
    pub deleted_values: Vec<(String, String)>,
    pub modified_values: Vec<(String, String)>,
}

impl RegistryDiff {
    #[must_use] 
    pub fn compute(before: &RegistrySnapshot, after: &RegistrySnapshot) -> Self {
        let before_keys: HashSet<&str> = before.keys.keys().map(std::string::String::as_str).collect();
        let after_keys: HashSet<&str> = after.keys.keys().map(std::string::String::as_str).collect();

        let added_keys = after_keys.difference(&before_keys).map(std::string::ToString::to_string).collect();
        let deleted_keys = before_keys.difference(&after_keys).map(std::string::ToString::to_string).collect();

        let mut modified_keys = Vec::new();
        let mut added_values = Vec::new();
        let mut deleted_values = Vec::new();
        let mut modified_values = Vec::new();

        for key in before_keys.intersection(&after_keys) {
            let bvals: HashSet<&str> = before.keys[*key].iter().map(|(n, _)| n.as_str()).collect();
            let avals: HashSet<&str> = after.keys[*key].iter().map(|(n, _)| n.as_str()).collect();

            for v in avals.difference(&bvals) {
                added_values.push((key.to_string(), v.to_string()));
            }
            for v in bvals.difference(&avals) {
                deleted_values.push((key.to_string(), v.to_string()));
            }

            let mut key_modified = false;
            for v in bvals.intersection(&avals) {
                let bdata = before.keys[*key].iter().find(|(n, _)| n == v).map(|(_, d)| d);
                let adata = after.keys[*key].iter().find(|(n, _)| n == v).map(|(_, d)| d);
                if let (Some(b), Some(a)) = (bdata, adata) {
                    let changed = match (b, a) {
                        (RegValueData::String(bs), RegValueData::String(as_)) => bs != as_,
                        (RegValueData::Dword(bv), RegValueData::Dword(av)) => bv != av,
                        (RegValueData::Qword(bv), RegValueData::Qword(av)) => bv != av,
                        (RegValueData::Binary(bb), RegValueData::Binary(ab)) => bb != ab,
                        _ => true,
                    };
                    if changed {
                        modified_values.push((key.to_string(), v.to_string()));
                        key_modified = true;
                    }
                }
            }
            if key_modified || !added_values.is_empty() || !deleted_values.is_empty() {
                modified_keys.push(key.to_string());
            }
        }

        Self { added_keys, deleted_keys, modified_keys, added_values, deleted_values, modified_values }
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.added_keys.is_empty() && self.deleted_keys.is_empty() && self.added_values.is_empty()
            && self.deleted_values.is_empty() && self.modified_values.is_empty()
    }

    #[must_use] 
    pub const fn total_changes(&self) -> usize {
        self.added_keys.len() + self.deleted_keys.len() + self.added_values.len()
            + self.deleted_values.len() + self.modified_values.len()
    }
}

// ─── Registry monitor report ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryMonitorReport {
    pub total_events: usize,
    pub unique_keys_touched: usize,
    pub unique_processes: usize,
    pub persistence_findings: Vec<PersistenceFinding>,
    pub security_policy_changes: Vec<SecurityPolicyChange>,
    pub defender_exclusions: Vec<String>,
    pub top_active_keys: Vec<(String, u32)>,
    pub hollowing_indicators: Vec<String>,
    pub summary: String,
}

impl RegistryMonitorReport {
    #[must_use] 
    pub fn generate(monitor: &RegistryMonitor) -> Self {
        let total_events = monitor.event_count();
        let unique_keys_touched = monitor.key_patterns().len();
        let unique_processes = monitor.unique_pids().len();
        let persistence_findings = monitor.persistence_findings().to_vec();
        let security_policy_changes = monitor.security_changes().to_vec();
        let defender_exclusions = monitor.defender_exclusions_added().iter().map(|e| e.key_path.clone()).collect();
        let top_active_keys = monitor.most_active_keys(10).iter().map(|(k, c)| (k.to_string(), *c)).collect();
        let hollowing_indicators = monitor.process_hollowing_indicators().iter().map(|e| e.key_path.clone()).collect();

        let high_sev = persistence_findings.iter().filter(|f| f.severity >= 7).count();
        let summary = format!(
            "{} registry events; {} unique keys; {} persistence mechanisms ({} high-sev); {} security policy changes",
            total_events, unique_keys_touched, persistence_findings.len(), high_sev, security_policy_changes.len()
        );

        Self {
            total_events, unique_keys_touched, unique_processes,
            persistence_findings, security_policy_changes, defender_exclusions,
            top_active_keys, hollowing_indicators, summary,
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize RegistryMonitorReport")
    }

    #[must_use] 
    pub fn has_critical_findings(&self) -> bool {
        self.persistence_findings.iter().any(|f| f.severity >= 9)
            || !self.security_policy_changes.is_empty()
    }
}

// ─── Batch analysis ──────────────────────────────────────────────────────────

#[must_use] 
pub fn analyze_events_batch(events: Vec<RegistryEvent>) -> RegistryMonitorReport {
    let mut monitor = RegistryMonitor::new();
    monitor.ingest_batch(events);
    RegistryMonitorReport::generate(&monitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_set_value(pid: u32, key: &str, value: &str, data: &str) -> RegistryEvent {
        let mut e = RegistryEvent::new(pid, 1, "test.exe".into(), RegOpKind::SetValue, key.into());
        e.value_name = Some(value.into());
        e.value_data = Some(RegValueData::String(data.into()));
        e.value_type = Some(RegValueType::Sz);
        e
    }

    #[test]
    fn test_run_key_persistence() {
        let mut m = RegistryMonitor::new();
        let e = make_set_value(
            1234,
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Updater",
            "C:\\Users\\victim\\AppData\\Local\\evil.exe",
        );
        m.ingest(e);
        assert!(!m.persistence_findings().is_empty(), "Run key should be flagged");
        let pf = &m.persistence_findings()[0];
        assert_eq!(pf.persistence_type, PersistenceType::Run);
        assert!(pf.severity >= 8);
    }

    #[test]
    fn test_defender_disable() {
        let mut m = RegistryMonitor::new();
        let e = make_set_value(
            999,
            "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
            "DisableRealtimeMonitoring",
            "1",
        );
        m.ingest(e);
        assert!(!m.security_changes().is_empty(), "Defender disable should be flagged");
    }

    #[test]
    fn test_hive_detection() {
        assert_eq!(RegistryHive::from_path("HKLM\\Software"), RegistryHive::HkeyLocalMachine);
        assert_eq!(RegistryHive::from_path("HKCU\\Software"), RegistryHive::HkeyCurrentUser);
        assert_eq!(RegistryHive::from_path("HKEY_LOCAL_MACHINE\\System"), RegistryHive::HkeyLocalMachine);
    }

    #[test]
    fn test_image_file_execution_options() {
        let mut m = RegistryMonitor::new();
        let e = make_set_value(
            5000,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe",
            "Debugger",
            "C:\\malware\\debugger.exe",
        );
        m.ingest(e);
        let ifeop = m.persistence_findings().iter().find(|f| f.persistence_type == PersistenceType::ImageFileExecutionOptions);
        assert!(ifeop.is_some(), "IFEO debugger hijack should be detected");
    }

    #[test]
    fn test_appinit_dlls() {
        let mut m = RegistryMonitor::new();
        let e = make_set_value(
            7777,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
            "AppInit_DLLs",
            "C:\\evil.dll",
        );
        m.ingest(e);
        let finding = m.persistence_findings().iter().find(|f| f.persistence_type == PersistenceType::AppInit);
        assert!(finding.is_some(), "AppInit_DLLs should be detected");
        assert_eq!(finding.unwrap().severity, 8);
    }

    #[test]
    fn test_registry_diff() {
        let mut before = RegistrySnapshot::new();
        before.add_value("HKLM\\Run".into(), "app".into(), RegValueData::String("good.exe".into()));

        let mut after = RegistrySnapshot::new();
        after.add_value("HKLM\\Run".into(), "app".into(), RegValueData::String("evil.exe".into()));
        after.add_value("HKLM\\Run".into(), "new_entry".into(), RegValueData::String("malware.exe".into()));

        let diff = RegistryDiff::compute(&before, &after);
        assert!(!diff.modified_values.is_empty() || !diff.added_values.is_empty());
        assert!(diff.total_changes() > 0);
    }

    #[test]
    fn test_report_generation() {
        let mut m = RegistryMonitor::new();
        for i in 0..5 {
            let e = make_set_value(
                1000 + i,
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                &format!("Persist{}", i),
                &format!("C:\\evil{}.exe", i),
            );
            m.ingest(e);
        }
        let report = RegistryMonitorReport::generate(&m);
        assert!(report.total_events > 0);
        assert!(!report.persistence_findings.is_empty());
        // A Run key is severity 8 by the table above — deliberately BELOW the
        // Winlogon/Service tier (9) and BootExecute/LsaAuth (10). Since
        // `has_critical_findings` asks for >= 9, Run-only input is high but not
        // critical; asserting the opposite contradicted the crate's own tiering,
        // which two neighbouring tests pin at exactly 8.
        assert!(report.persistence_findings.iter().all(|f| f.severity == 8));
        assert!(!report.has_critical_findings());
    }

    #[test]
    fn test_reg_value_type_roundtrip() {
        for code in [0u32, 1, 2, 3, 4, 5, 7, 11, 42] {
            let t = RegValueType::from_type_code(code);
            assert_eq!(t.type_code(), code);
        }
    }
}
