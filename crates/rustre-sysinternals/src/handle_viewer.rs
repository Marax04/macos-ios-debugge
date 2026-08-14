//! `handle_viewer` — Handle.exe-equivalent
//!
//! Enumerate all open handles system-wide, type (file/mutex/event/semaphore/key/token),
//! name, owner process, access mask decoding, object reference counts.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::SysinternalsError;

// ─── ObjectType ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjectType {
    File,
    Directory,
    SymbolicLink,
    Token,
    Process,
    Thread,
    Job,
    Section,
    Key,
    Event,
    EventPair,
    Mutant,
    Semaphore,
    Timer,
    WindowStation,
    Desktop,
    Controller,
    Device,
    Driver,
    IoCompletion,
    WaitablePort,
    Port,
    Adapter,
    TransactionManager,
    Transaction,
    Thread32,
    TpWorkerFactory,
    EtwRegistration,
    EtwConsumer,
    Session,
    UserApcReserve,
    IoCompletionReserve,
    MemoryPartition,
    FilterConnectionPort,
    FilterCommunicationPort,
    Callback,
    Socket,
    Pipe,
    Mailslot,
    DxgkCompositionObject,
    Unknown,
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::File => "File",
            Self::Directory => "Directory",
            Self::SymbolicLink => "SymbolicLink",
            Self::Token => "Token",
            Self::Process => "Process",
            Self::Thread => "Thread",
            Self::Job => "Job",
            Self::Section => "Section",
            Self::Key => "Key",
            Self::Event => "Event",
            Self::EventPair => "EventPair",
            Self::Mutant => "Mutant",
            Self::Semaphore => "Semaphore",
            Self::Timer => "Timer",
            Self::WindowStation => "WindowStation",
            Self::Desktop => "Desktop",
            Self::Controller => "Controller",
            Self::Device => "Device",
            Self::Driver => "Driver",
            Self::IoCompletion => "IoCompletion",
            Self::WaitablePort => "WaitablePort",
            Self::Port => "Port",
            Self::Adapter => "Adapter",
            Self::TransactionManager => "TmTm",
            Self::Transaction => "TmTx",
            Self::Thread32 => "Thread32",
            Self::TpWorkerFactory => "TpWorkerFactory",
            Self::EtwRegistration => "EtwRegistration",
            Self::EtwConsumer => "EtwConsumer",
            Self::Session => "Session",
            Self::UserApcReserve => "UserApcReserve",
            Self::IoCompletionReserve => "IoCompletionReserve",
            Self::MemoryPartition => "MemoryPartition",
            Self::FilterConnectionPort => "FilterConnectionPort",
            Self::FilterCommunicationPort => "FilterCommunicationPort",
            Self::Callback => "Callback",
            Self::Socket => "Socket",
            Self::Pipe => "Pipe",
            Self::Mailslot => "Mailslot",
            Self::DxgkCompositionObject => "DxgkCompositionObject",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

impl FromStr for ObjectType {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "file" => Self::File,
            "directory" => Self::Directory,
            "symboliclink" => Self::SymbolicLink,
            "token" => Self::Token,
            "process" => Self::Process,
            "thread" => Self::Thread,
            "job" => Self::Job,
            "section" => Self::Section,
            "key" => Self::Key,
            "event" => Self::Event,
            "eventpair" => Self::EventPair,
            "mutant" | "mutex" => Self::Mutant,
            "semaphore" => Self::Semaphore,
            "timer" | "waitabletimer" => Self::Timer,
            "windowstation" => Self::WindowStation,
            "desktop" => Self::Desktop,
            "device" => Self::Device,
            "driver" => Self::Driver,
            "iocompletion" | "iocompletionport" => Self::IoCompletion,
            "port" | "iocompletionreserve" => Self::Port,
            "callback" => Self::Callback,
            "socket" => Self::Socket,
            "pipe" | "namedpipe" => Self::Pipe,
            "mailslot" => Self::Mailslot,
            "filterconnectionport" => Self::FilterConnectionPort,
            "filtercommunicationport" => Self::FilterCommunicationPort,
            "etw" | "etwregistration" => Self::EtwRegistration,
            "session" => Self::Session,
            _ => Self::Unknown,
        })
    }
}

impl ObjectType {

    /// Whether this type typically has a meaningful name (path/key name/etc).
    #[must_use]
    pub const fn has_named_objects(self) -> bool {
        matches!(
            self,
            Self::File
                | Self::Directory
                | Self::Key
                | Self::Event
                | Self::Mutant
                | Self::Semaphore
                | Self::Section
                | Self::SymbolicLink
                | Self::Pipe
                | Self::Mailslot
                | Self::Job
        )
    }

    /// Whether this type is commonly security-sensitive.
    #[must_use]
    pub const fn is_security_sensitive(self) -> bool {
        matches!(
            self,
            Self::Token
                | Self::Process
                | Self::Thread
                | Self::Section
                | Self::Key
                | Self::Pipe
        )
    }
}

// ─── AccessMask ───────────────────────────────────────────────────────────────

pub mod access_mask {
    pub const GENERIC_READ: u32 = 0x8000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
    pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F_0000;
    pub const DELETE: u32 = 0x0001_0000;
    pub const READ_CONTROL: u32 = 0x0002_0000;
    pub const WRITE_DAC: u32 = 0x0004_0000;
    pub const WRITE_OWNER: u32 = 0x0008_0000;

    // Process-specific.
    pub const PROCESS_TERMINATE: u32 = 0x0001;
    pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
    pub const PROCESS_VM_OPERATION: u32 = 0x0008;
    pub const PROCESS_VM_READ: u32 = 0x0010;
    pub const PROCESS_VM_WRITE: u32 = 0x0020;
    pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
    pub const PROCESS_CREATE_PROCESS: u32 = 0x0080;
    pub const PROCESS_SET_QUOTA: u32 = 0x0100;
    pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
    pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    pub const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    pub const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;

    // Token-specific.
    pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
    pub const TOKEN_DUPLICATE: u32 = 0x0002;
    pub const TOKEN_IMPERSONATE: u32 = 0x0004;
    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TOKEN_QUERY_SOURCE: u32 = 0x0010;
    pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
    pub const TOKEN_ADJUST_GROUPS: u32 = 0x0040;
    pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
    pub const TOKEN_ALL_ACCESS: u32 = 0x000F_01FF;

    /// Decode access mask bits to a human-readable string.
    #[must_use]
    pub fn decode(mask: u32, object_type: super::ObjectType) -> String {
        let mut parts = Vec::new();
        if mask & GENERIC_ALL != 0 { parts.push("GA"); }
        if mask & GENERIC_READ != 0 { parts.push("GR"); }
        if mask & GENERIC_WRITE != 0 { parts.push("GW"); }
        if mask & GENERIC_EXECUTE != 0 { parts.push("GX"); }
        if mask & DELETE != 0 { parts.push("DE"); }
        if mask & READ_CONTROL != 0 { parts.push("RC"); }
        if mask & WRITE_DAC != 0 { parts.push("WD"); }
        if mask & WRITE_OWNER != 0 { parts.push("WO"); }
        if mask & SYNCHRONIZE != 0 { parts.push("SY"); }
        // Process-specific.
        if object_type == super::ObjectType::Process {
            if mask & PROCESS_VM_READ != 0 { parts.push("VMR"); }
            if mask & PROCESS_VM_WRITE != 0 { parts.push("VMW"); }
            if mask & PROCESS_VM_OPERATION != 0 { parts.push("VMO"); }
            if mask & PROCESS_CREATE_THREAD != 0 { parts.push("CT"); }
            if mask & PROCESS_TERMINATE != 0 { parts.push("TERM"); }
        }
        if parts.is_empty() {
            format!("{mask:#010x}")
        } else {
            parts.join("|")
        }
    }
}

// ─── HandleRecord ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleRecord {
    pub handle_value: u64,
    pub pid: u32,
    pub process_name: String,
    pub object_type: ObjectType,
    pub type_name: String,
    pub object_name: String,
    pub object_address: u64,
    pub access_mask: u32,
    pub access_decoded: String,
    pub attributes: HandleAttributes,
    pub granted_access: u32,
    pub ref_count: u32,
    pub handle_count: u32,
    /// Whether the handle is to a cross-process object.
    pub is_cross_process: bool,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct HandleAttributes: u32 {
        const NONE           = 0x0000;
        const INHERIT        = 0x0002;
        const PROTECT        = 0x0004;
        const AUDIT          = 0x0040;
        const NO_DUP        = 0x0080;
    }
}

impl HandleRecord {
    #[must_use]
    pub fn new(
        handle_value: u64,
        pid: u32,
        process_name: impl Into<String>,
        type_name: impl Into<String>,
        object_name: impl Into<String>,
        access_mask: u32,
    ) -> Self {
        let type_name = type_name.into();
        let object_type: ObjectType = type_name.parse().unwrap_or(ObjectType::Unknown);
        let access_decoded = access_mask::decode(access_mask, object_type);
        Self {
            handle_value,
            pid,
            process_name: process_name.into(),
            object_type,
            type_name,
            object_name: object_name.into(),
            object_address: 0,
            access_mask,
            access_decoded,
            attributes: HandleAttributes::NONE,
            granted_access: access_mask,
            ref_count: 1,
            handle_count: 1,
            is_cross_process: false,
        }
    }

    /// True if handle grants write access.
    #[must_use]
    pub const fn has_write_access(&self) -> bool {
        self.access_mask & access_mask::GENERIC_WRITE != 0
            || self.access_mask & access_mask::GENERIC_ALL != 0
            || self.access_mask & 0x0006 != 0
    }

    /// True if handle grants process memory read.
    #[must_use]
    pub fn has_vm_read(&self) -> bool {
        self.object_type == ObjectType::Process
            && (self.access_mask & access_mask::PROCESS_VM_READ != 0
                || self.access_mask & access_mask::PROCESS_ALL_ACCESS != 0)
    }

    /// True if handle can create a thread in the target.
    #[must_use]
    pub fn has_thread_create(&self) -> bool {
        self.object_type == ObjectType::Process
            && (self.access_mask & access_mask::PROCESS_CREATE_THREAD != 0
                || self.access_mask & access_mask::PROCESS_ALL_ACCESS != 0)
    }

    /// True if this is a token with impersonation right.
    #[must_use]
    pub fn has_token_impersonate(&self) -> bool {
        self.object_type == ObjectType::Token
            && (self.access_mask & access_mask::TOKEN_IMPERSONATE != 0
                || self.access_mask & access_mask::TOKEN_ALL_ACCESS != 0)
    }

    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.has_vm_read()
            || self.has_thread_create()
            || self.has_token_impersonate()
            || (self.object_type == ObjectType::Process
                && self.access_mask & access_mask::PROCESS_ALL_ACCESS != 0)
    }

    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{:#06x},{},{},{}",
            self.pid,
            self.process_name,
            self.object_type,
            self.handle_value,
            self.object_name,
            self.access_decoded,
            self.is_suspicious(),
        )
    }
}

// ─── HandleFilter ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct HandleFilter {
    pub pids: Vec<u32>,
    pub types: Vec<ObjectType>,
    pub name_contains: Option<String>,
    pub process_name_contains: Option<String>,
    pub suspicious_only: bool,
    pub has_write: bool,
    pub has_vm_read: bool,
}

impl HandleFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn matches(&self, h: &HandleRecord) -> bool {
        if !self.pids.is_empty() && !self.pids.contains(&h.pid) {
            return false;
        }
        if !self.types.is_empty() && !self.types.contains(&h.object_type) {
            return false;
        }
        if let Some(ref nc) = self.name_contains
            && !h.object_name.to_lowercase().contains(nc.to_lowercase().as_str())
        {
            return false;
        }
        if let Some(ref pn) = self.process_name_contains
            && !h.process_name.to_lowercase().contains(pn.to_lowercase().as_str())
        {
            return false;
        }
        if self.suspicious_only && !h.is_suspicious() {
            return false;
        }
        if self.has_write && !h.has_write_access() {
            return false;
        }
        if self.has_vm_read && !h.has_vm_read() {
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
    pub fn with_type(mut self, t: ObjectType) -> Self {
        self.types.push(t);
        self
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name_contains = Some(name.into());
        self
    }

    #[must_use]
    pub const fn suspicious_only(mut self) -> Self {
        self.suspicious_only = true;
        self
    }
}

// ─── HandleTable ──────────────────────────────────────────────────────────────

/// System-wide handle table — a flat list of all open handles.
pub struct HandleTable {
    records: Vec<HandleRecord>,
}

impl HandleTable {
    #[must_use]
    pub const fn new() -> Self {
        Self { records: Vec::new() }
    }

    pub fn insert(&mut self, record: HandleRecord) {
        self.records.push(record);
    }

    pub fn bulk_insert(&mut self, records: Vec<HandleRecord>) {
        self.records.extend(records);
    }

    #[must_use]
    pub fn query(&self, filter: &HandleFilter) -> Vec<&HandleRecord> {
        self.records.iter().filter(|h| filter.matches(h)).collect()
    }

    #[must_use]
    pub fn all(&self) -> &[HandleRecord] {
        &self.records
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.records.len()
    }

    /// Group handles by owning PID.
    #[must_use]
    pub fn by_pid(&self) -> HashMap<u32, Vec<&HandleRecord>> {
        let mut map: HashMap<u32, Vec<&HandleRecord>> = HashMap::new();
        for h in &self.records {
            map.entry(h.pid).or_default().push(h);
        }
        map
    }

    /// Group handles by type.
    #[must_use]
    pub fn by_type(&self) -> HashMap<ObjectType, Vec<&HandleRecord>> {
        let mut map: HashMap<ObjectType, Vec<&HandleRecord>> = HashMap::new();
        for h in &self.records {
            map.entry(h.object_type).or_default().push(h);
        }
        map
    }

    /// Find all processes that have a handle to the given object address.
    #[must_use]
    pub fn processes_with_handle_to(&self, object_addr: u64) -> Vec<(u32, &str)> {
        self.records
            .iter()
            .filter(|h| h.object_address == object_addr)
            .map(|h| (h.pid, h.process_name.as_str()))
            .collect()
    }

    /// Find processes holding handles to a named object.
    #[must_use]
    pub fn processes_with_named_handle(&self, name: &str) -> Vec<(u32, &str)> {
        let name_lc = name.to_lowercase();
        self.records
            .iter()
            .filter(|h| h.object_name.to_lowercase().contains(&name_lc))
            .map(|h| (h.pid, h.process_name.as_str()))
            .collect()
    }

    /// All suspicious handles.
    #[must_use]
    pub fn suspicious(&self) -> Vec<&HandleRecord> {
        self.records.iter().filter(|h| h.is_suspicious()).collect()
    }

    /// Count handles per type.
    #[must_use]
    pub fn type_counts(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for h in &self.records {
            *map.entry(h.object_type.to_string()).or_default() += 1;
        }
        map
    }

    /// Top N processes by handle count.
    #[must_use]
    pub fn top_by_handle_count(&self, n: usize) -> Vec<(u32, usize)> {
        let by_pid = self.by_pid();
        let mut counts: Vec<(u32, usize)> = by_pid
            .iter()
            .map(|(&pid, v)| (pid, v.len()))
            .collect();
        counts.sort_by_key(|&(_, c)| std::cmp::Reverse(c));
        counts.truncate(n);
        counts
    }

    /// Export to CSV.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out =
            String::from("PID,Process,Type,Handle,ObjectName,AccessDecoded,Suspicious\n");
        for h in &self.records {
            out.push_str(&h.to_csv_row());
            out.push('\n');
        }
        out
    }

    /// # Errors
    /// Returns an error if the underlying operation fails.
    pub fn to_json(&self) -> Result<String, SysinternalsError> {
        serde_json::to_string_pretty(&self.records)
            .map_err(|e| SysinternalsError::InvalidData(e.to_string()))
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

// ─── HandleAnalyzer ───────────────────────────────────────────────────────────

/// Higher-level analysis on top of `HandleTable`.
pub struct HandleAnalyzer<'a> {
    table: &'a HandleTable,
}

impl<'a> HandleAnalyzer<'a> {
    #[must_use]
    pub const fn new(table: &'a HandleTable) -> Self {
        Self { table }
    }

    /// Find processes that have an open handle to lsass.exe (common injection vector).
    #[must_use]
    pub fn lsass_handle_processes(&self) -> Vec<(u32, &HandleRecord)> {
        self.table
            .records
            .iter()
            .filter(|h| {
                h.object_type == ObjectType::Process
                    && h.object_name.to_lowercase().contains("lsass")
            })
            .map(|h| (h.pid, h))
            .collect()
    }

    /// Find processes with handles that could allow code injection.
    #[must_use]
    pub fn injection_capable_handles(&self) -> Vec<&HandleRecord> {
        self.table
            .records
            .iter()
            .filter(|h| h.has_vm_read() || h.has_thread_create())
            .collect()
    }

    /// Find all named pipes.
    #[must_use]
    pub fn named_pipes(&self) -> Vec<&HandleRecord> {
        let filter = HandleFilter::new().with_type(ObjectType::Pipe);
        self.table.query(&filter)
    }

    /// Find handles to sensitive objects (tokens, processes with write).
    #[must_use]
    pub fn sensitive_handles(&self) -> Vec<&HandleRecord> {
        self.table
            .records
            .iter()
            .filter(|h| h.object_type.is_security_sensitive() && h.has_write_access())
            .collect()
    }

    /// Duplicate handle detection: multiple processes sharing the same object.
    #[must_use]
    pub fn shared_objects(&self) -> Vec<(u64, Vec<u32>)> {
        let mut by_addr: HashMap<u64, Vec<u32>> = HashMap::new();
        for h in &self.table.records {
            if h.object_address != 0 {
                by_addr.entry(h.object_address).or_default().push(h.pid);
            }
        }
        by_addr
            .into_iter()
            .filter(|(_, pids)| pids.len() > 1)
            .collect()
    }

    /// Summary: per-type counts, suspicious count.
    #[must_use]
    pub fn summary(&self) -> HandleSummary {
        HandleSummary {
            total: self.table.count(),
            suspicious_count: self.table.suspicious().len(),
            type_counts: self.table.type_counts(),
            top_handle_owners: self.table.top_by_handle_count(5),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleSummary {
    pub total: usize,
    pub suspicious_count: usize,
    pub type_counts: HashMap<String, usize>,
    pub top_handle_owners: Vec<(u32, usize)>,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(
        pid: u32,
        pname: &str,
        type_name: &str,
        obj_name: &str,
        access: u32,
    ) -> HandleRecord {
        HandleRecord::new(u64::from(pid) * 4, pid, pname, type_name, obj_name, access)
    }

    #[test]
    fn test_object_type_from_str() {
        assert_eq!(ObjectType::from_str("File").unwrap(), ObjectType::File);
        assert_eq!(ObjectType::from_str("mutant").unwrap(), ObjectType::Mutant);
        assert_eq!(ObjectType::from_str("xyz").unwrap(), ObjectType::Unknown);
    }

    #[test]
    fn test_handle_record_vm_read() {
        let h = make_record(1, "evil.exe", "Process", "\\lsass.exe", access_mask::PROCESS_VM_READ);
        assert!(h.has_vm_read());
        assert!(h.is_suspicious());
    }

    #[test]
    fn test_handle_record_thread_create() {
        let h = make_record(
            1,
            "evil.exe",
            "Process",
            "\\target.exe",
            access_mask::PROCESS_CREATE_THREAD,
        );
        assert!(h.has_thread_create());
    }

    #[test]
    fn test_handle_record_token_impersonate() {
        let h = make_record(1, "evil.exe", "Token", "", access_mask::TOKEN_IMPERSONATE);
        assert!(h.has_token_impersonate());
        assert!(h.is_suspicious());
    }

    #[test]
    fn test_handle_filter_by_type() {
        let filter = HandleFilter::new().with_type(ObjectType::File);
        let h1 = make_record(1, "p", "File", "C:\\x", 0x20);
        let h2 = make_record(1, "p", "Key", "HKLM\\x", 0x20);
        assert!(filter.matches(&h1));
        assert!(!filter.matches(&h2));
    }

    #[test]
    fn test_handle_filter_suspicious_only() {
        let filter = HandleFilter::new().suspicious_only();
        let h_safe = make_record(1, "p", "File", "C:\\x", 0x20);
        let h_sus = make_record(1, "p", "Process", "lsass", access_mask::PROCESS_VM_READ);
        assert!(!filter.matches(&h_safe));
        assert!(filter.matches(&h_sus));
    }

    #[test]
    fn test_handle_table_query_by_pid() {
        let mut table = HandleTable::new();
        table.insert(make_record(10, "p1", "File", "C:\\x", 0x20));
        table.insert(make_record(20, "p2", "Key", "HKLM\\x", 0x20));
        let filter = HandleFilter::new().with_pid(10);
        let results = table.query(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 10);
    }

    #[test]
    fn test_handle_table_by_pid() {
        let mut table = HandleTable::new();
        for i in 0u32..3 {
            table.insert(make_record(100, "p", "File", &format!("C:\\{i}"), 0x20));
        }
        let by_pid = table.by_pid();
        assert_eq!(by_pid[&100].len(), 3);
    }

    #[test]
    fn test_handle_table_type_counts() {
        let mut table = HandleTable::new();
        table.insert(make_record(1, "p", "File", "C:\\x", 0x20));
        table.insert(make_record(1, "p", "File", "C:\\y", 0x20));
        table.insert(make_record(1, "p", "Key", "HKLM\\x", 0x20));
        let counts = table.type_counts();
        assert_eq!(counts["File"], 2);
        assert_eq!(counts["Key"], 1);
    }

    #[test]
    fn test_handle_table_top_by_count() {
        let mut table = HandleTable::new();
        for _ in 0..5 {
            table.insert(make_record(1, "p1", "File", "C:\\x", 0x20));
        }
        table.insert(make_record(2, "p2", "File", "C:\\y", 0x20));
        let top = table.top_by_handle_count(1);
        assert_eq!(top[0].0, 1);
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn test_handle_table_csv() {
        let mut table = HandleTable::new();
        table.insert(make_record(1, "p", "File", "C:\\x", 0x20));
        let csv = table.to_csv();
        assert!(csv.contains("PID"));
        assert!(csv.contains("File"));
    }

    #[test]
    fn test_access_mask_decode_process() {
        let decoded = access_mask::decode(
            access_mask::PROCESS_VM_READ | access_mask::SYNCHRONIZE,
            ObjectType::Process,
        );
        assert!(decoded.contains("VMR"));
        assert!(decoded.contains("SY"));
    }

    #[test]
    fn test_handle_analyzer_injection_capable() {
        let mut table = HandleTable::new();
        table.insert(make_record(1, "evil.exe", "Process", "lsass.exe", access_mask::PROCESS_VM_READ | access_mask::PROCESS_CREATE_THREAD));
        table.insert(make_record(2, "legit.exe", "File", "C:\\x", 0x20));
        let analyzer = HandleAnalyzer::new(&table);
        let inj = analyzer.injection_capable_handles();
        assert_eq!(inj.len(), 1);
        assert_eq!(inj[0].pid, 1);
    }

    #[test]
    fn test_handle_analyzer_named_pipes() {
        let mut table = HandleTable::new();
        table.insert(make_record(1, "p", "Pipe", "\\\\.\\pipe\\test", 0x20));
        table.insert(make_record(1, "p", "File", "C:\\x", 0x20));
        let analyzer = HandleAnalyzer::new(&table);
        assert_eq!(analyzer.named_pipes().len(), 1);
    }

    #[test]
    fn test_object_type_security_sensitive() {
        assert!(ObjectType::Token.is_security_sensitive());
        assert!(ObjectType::Process.is_security_sensitive());
        assert!(!ObjectType::Event.is_security_sensitive());
    }

    #[test]
    fn test_handle_attributes_bitflag() {
        let attrs = HandleAttributes::INHERIT | HandleAttributes::PROTECT;
        assert!(attrs.contains(HandleAttributes::INHERIT));
        assert!(!attrs.contains(HandleAttributes::AUDIT));
    }
}
