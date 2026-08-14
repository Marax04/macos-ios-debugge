//! `rustre-sysinternals`
//!
//! Sysinternals-style platform-agnostic system introspection types and traits.
//! All types are pure data — no OS calls are made by this crate.

pub mod event_log;
pub mod file_search;
pub mod process_monitor;

// ─── New Sysinternals-equivalent modules ──────────────────────────────────────
pub mod autoruns_analyzer;
pub mod file_monitor;
pub mod handle_viewer;
pub mod network_monitor;
pub mod process_explorer;
pub mod registry_monitor;
pub mod sigcheck_engine;
pub mod strings_extractor;
pub mod vmmap_analyzer;
pub mod procmon_log_parser;
pub mod procexp_dump_analyzer;

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Convert `u64` to `f64` by splitting into two `u32` halves to avoid precision-loss cast.
fn u64_to_f64(x: u64) -> f64 {
    let lo = u32::try_from(x & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    let hi = u32::try_from(x >> 32).unwrap_or(u32::MAX);
    f64::from(hi).mul_add(4_294_967_296.0_f64, f64::from(lo))
}

use async_trait::async_trait;
use bitflags::bitflags;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── CSV field quoting ────────────────────────────────────────────────────────

/// Quote a value for a CSV row, per RFC 4180.
///
/// The `to_csv_row` methods interpolate free text — file paths, process names,
/// registry values, strings pulled out of a binary — straight between commas.
/// A comma is legal in a Windows filename and guaranteed in extracted strings,
/// and either one silently shifts every later column of that row.
///
/// Quoting is *minimal* on purpose: a field that contains none of `,`, `"`,
/// CR or LF is returned untouched, so ordinary rows stay byte-for-byte what
/// they were. Unlike a substitution scheme, this preserves the value — these
/// are paths and names that a reader has to be able to use.
#[must_use]
pub fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Error, Serialize, Deserialize)]
pub enum SysinternalsError {
    #[error("Access denied")]
    AccessDenied,
    #[error("Not supported")]
    Unsupported,
    #[error("IO error: {0}")]
    Io(String),
    #[error("Process not found: {0}")]
    ProcessNotFound(u32),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Timeout")]
    Timeout,
    #[error("Not found: {0}")]
    NotFound(String),
}

// ─── DriverFlags ──────────────────────────────────────────────────────────────

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct DriverFlags: u32 {
        const NONE        = 0;
        const LOADED      = 1;
        const UNLOADABLE  = 2;
        const KERNEL_MODE = 4;
        const FS_FILTER   = 8;
    }
}

impl fmt::Display for DriverFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── ThreadState ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreadState {
    Running,
    Waiting,
    Ready,
    Terminated,
    Unknown,
}

impl fmt::Display for ThreadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => write!(f, "Running"),
            Self::Waiting => write!(f, "Waiting"),
            Self::Ready => write!(f, "Ready"),
            Self::Terminated => write!(f, "Terminated"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─── ProcessStatus ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessStatus {
    Running,
    Sleeping,
    Stopped,
    Zombie,
    Unknown,
}

impl fmt::Display for ProcessStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => write!(f, "Running"),
            Self::Sleeping => write!(f, "Sleeping"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Zombie => write!(f, "Zombie"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─── NetworkProtocol ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Tcp6,
    Udp6,
    Raw,
}

impl fmt::Display for NetworkProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Tcp6 => write!(f, "TCP6"),
            Self::Udp6 => write!(f, "UDP6"),
            Self::Raw => write!(f, "RAW"),
        }
    }
}

// ─── TcpState ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpState {
    Listen,
    Established,
    TimeWait,
    CloseWait,
    Closed,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    LastAck,
    Closing,
    Unknown,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Listen => write!(f, "LISTEN"),
            Self::Established => write!(f, "ESTABLISHED"),
            Self::TimeWait => write!(f, "TIME_WAIT"),
            Self::CloseWait => write!(f, "CLOSE_WAIT"),
            Self::Closed => write!(f, "CLOSED"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::SynReceived => write!(f, "SYN_RECEIVED"),
            Self::FinWait1 => write!(f, "FIN_WAIT_1"),
            Self::FinWait2 => write!(f, "FIN_WAIT_2"),
            Self::LastAck => write!(f, "LAST_ACK"),
            Self::Closing => write!(f, "CLOSING"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

// ─── RegistryDataType ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryDataType {
    RegSz,
    RegExpandSz,
    RegBinary,
    RegDword,
    RegQword,
    RegMultiSz,
}

impl fmt::Display for RegistryDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegSz => write!(f, "REG_SZ"),
            Self::RegExpandSz => write!(f, "REG_EXPAND_SZ"),
            Self::RegBinary => write!(f, "REG_BINARY"),
            Self::RegDword => write!(f, "REG_DWORD"),
            Self::RegQword => write!(f, "REG_QWORD"),
            Self::RegMultiSz => write!(f, "REG_MULTI_SZ"),
        }
    }
}

// ─── MemoryStats (legacy) ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryStats {
    pub working_set: u64,
    pub private_bytes: u64,
    pub virtual_size: u64,
    pub peak_working_set: u64,
}

// ─── MemoryInfo ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryInfo {
    /// Virtual set size in bytes.
    pub vss: u64,
    /// Resident set size in bytes.
    pub rss: u64,
    /// Peak resident set size.
    pub peak_rss: u64,
    /// Shared memory in bytes.
    pub shared: u64,
    /// Private memory in bytes.
    pub private: u64,
    /// Number of page faults.
    pub page_faults: u64,
}

impl MemoryInfo {
    #[must_use]
    pub const fn new(
        vss: u64,
        rss: u64,
        peak_rss: u64,
        shared: u64,
        private: u64,
        page_faults: u64,
    ) -> Self {
        Self {
            vss,
            rss,
            peak_rss,
            shared,
            private,
            page_faults,
        }
    }

    /// Ratio of rss to vss (0.0 if vss == 0).
    #[must_use]
    pub fn rss_vss_ratio(&self) -> f64 {
        if self.vss == 0 {
            return 0.0;
        }
        u64_to_f64(self.rss) / u64_to_f64(self.vss)
    }
}

// ─── ModuleInfo (expanded) ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// Load base address.
    pub base: u64,
    /// Size of the module image in bytes.
    pub size: u64,
    /// Filename portion.
    pub name: String,
    /// Full path on disk.
    pub path: String,
    /// true for 64-bit modules.
    pub is_64bit: bool,
    /// Digital signature status (None if not checked).
    pub signed: Option<bool>,
    /// SHA-256 hash of the file (computed on demand).
    pub hash_sha256: Option<String>,
}

impl ModuleInfo {
    #[must_use]
    pub fn new(base: u64, size: u64, name: impl Into<String>, path: impl Into<String>) -> Self {
        let name = name.into();
        let path = path.into();
        Self {
            base,
            size,
            name,
            path,
            is_64bit: true,
            signed: None,
            hash_sha256: None,
        }
    }

    /// Address range [base, base+size).
    #[must_use]
    pub const fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.saturating_add(self.size)
    }
}

// ─── ThreadInfo ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    pub tid: u32,
    pub pid: u32,
    pub start_address: u64,
    pub priority: i32,
    pub state: ThreadState,
    pub wait_reason: String,
}

impl ThreadInfo {
    #[must_use]
    pub const fn new(tid: u32, pid: u32, start_address: u64, priority: i32, state: ThreadState) -> Self {
        Self {
            tid,
            pid,
            start_address,
            priority,
            state,
            wait_reason: String::new(),
        }
    }
}

// ─── ProcessInfo (full) ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    /// Alias for path (legacy compat).
    pub exe_path: String,
    pub cmdline: String,
    pub cwd: String,
    pub user: String,
    pub status: ProcessStatus,
    pub memory_info: MemoryInfo,
    pub cpu_usage: f64,
    pub thread_count: u32,
    pub handle_count: u32,
    pub create_time: u64,
    pub modules: Vec<ModuleInfo>,
    pub open_files: Vec<String>,
    pub env_vars: Vec<(String, String)>,
    // Legacy fields kept for compat
    pub path: String,
    pub threads: Vec<ThreadInfo>,
    pub memory: MemoryStats,
    pub session_id: u32,
}

impl ProcessInfo {
    #[must_use]
    pub fn new(pid: u32, parent_pid: u32, process_name: impl Into<String>) -> Self {
        let name_str = process_name.into();
        Self {
            pid,
            ppid: parent_pid,
            name: name_str,
            exe_path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            user: String::new(),
            status: ProcessStatus::Unknown,
            memory_info: MemoryInfo::default(),
            cpu_usage: 0.0,
            thread_count: 0,
            handle_count: 0,
            create_time: 0,
            modules: Vec::new(),
            open_files: Vec::new(),
            env_vars: Vec::new(),
            path: String::new(),
            threads: Vec::new(),
            memory: MemoryStats::default(),
            session_id: 0,
        }
    }

    /// Return env variable by name.
    #[must_use]
    pub fn get_env(&self, key: &str) -> Option<&str> {
        self.env_vars
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// True if process appears to be running from a temp directory.
    #[must_use]
    pub fn in_temp_dir(&self) -> bool {
        let lp = self.exe_path.to_lowercase();
        lp.contains("\\temp\\") || lp.contains("\\tmp\\") || lp.contains("/tmp/")
    }

    /// True if process executable path is under system32.
    #[must_use]
    pub fn is_system32(&self) -> bool {
        let lp = self.exe_path.to_lowercase();
        lp.contains("system32") || lp.contains("syswow64")
    }

    /// CSV row representation.
    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{:.2}",
            self.pid,
            self.ppid,
            csv_field(&self.name),
            csv_field(&self.user),
            self.status,
            self.memory_info.rss,
            self.cpu_usage
        )
    }

    /// JSON representation via serde.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, SysinternalsError> {
        serde_json::to_string(self).map_err(|e| SysinternalsError::InvalidData(e.to_string()))
    }
}

// ─── DriverInfo ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverInfo {
    pub base: u64,
    pub size: u32,
    pub path: String,
    pub name: String,
    pub flags: DriverFlags,
}

impl DriverInfo {
    #[must_use]
    pub fn new(
        base: u64,
        size: u32,
        path: impl Into<String>,
        name: impl Into<String>,
        flags: DriverFlags,
    ) -> Self {
        Self {
            base,
            size,
            path: path.into(),
            name: name.into(),
            flags,
        }
    }
}

// ─── HandleInfo ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleInfo {
    pub handle: u64,
    pub pid: u32,
    pub type_name: String,
    pub object_address: u64,
    pub access_mask: u32,
}

impl HandleInfo {
    #[must_use]
    pub fn new(
        handle: u64,
        pid: u32,
        type_name: impl Into<String>,
        object_address: u64,
        access_mask: u32,
    ) -> Self {
        Self {
            handle,
            pid,
            type_name: type_name.into(),
            object_address,
            access_mask,
        }
    }
}

// ─── RegistryValue ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValue {
    pub hive: String,
    pub key_path: String,
    pub value_name: String,
    pub data_type: RegistryDataType,
    pub data: Vec<u8>,
}

impl RegistryValue {
    #[must_use]
    pub fn new(
        hive: impl Into<String>,
        key_path: impl Into<String>,
        value_name: impl Into<String>,
        data_type: RegistryDataType,
        data: Vec<u8>,
    ) -> Self {
        Self {
            hive: hive.into(),
            key_path: key_path.into(),
            value_name: value_name.into(),
            data_type,
            data,
        }
    }
}

// ─── NetworkEndpoint (legacy) ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub pid: u32,
    pub protocol: NetworkProtocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: TcpState,
}

impl NetworkEndpoint {
    #[must_use]
    pub fn new(
        pid: u32,
        protocol: NetworkProtocol,
        local_addr: impl Into<String>,
        local_port: u16,
        remote_addr: impl Into<String>,
        remote_port: u16,
        state: TcpState,
    ) -> Self {
        Self {
            pid,
            protocol,
            local_addr: local_addr.into(),
            local_port,
            remote_addr: remote_addr.into(),
            remote_port,
            state,
        }
    }
}

// ─── NetworkConnection (full) ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub pid: u32,
    pub process_name: String,
    pub protocol: NetworkProtocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub state: TcpState,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

impl NetworkConnection {
    #[must_use]
    pub fn new_tcp(
        pid: u32,
        process_name: impl Into<String>,
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
        state: TcpState,
    ) -> Self {
        Self {
            pid,
            process_name: process_name.into(),
            protocol: NetworkProtocol::Tcp,
            local_addr,
            local_port,
            remote_addr: Some(remote_addr),
            remote_port: Some(remote_port),
            state,
            bytes_sent: 0,
            bytes_recv: 0,
        }
    }

    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == TcpState::Established
    }

    #[must_use]
    pub fn is_listening(&self) -> bool {
        self.state == TcpState::Listen
    }

    /// Return CSV row.
    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{}",
            self.pid,
            csv_field(&self.process_name),
            self.protocol,
            self.local_addr,
            self.local_port,
            self.remote_addr.map(|a| a.to_string()).unwrap_or_default(),
            self.state
        )
    }
}

// ─── SystemSnapshot ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub processes: Vec<ProcessInfo>,
    pub drivers: Vec<DriverInfo>,
    pub network: Vec<NetworkEndpoint>,
    pub handles: Vec<HandleInfo>,
}

impl SystemSnapshot {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            processes: Vec::new(),
            drivers: Vec::new(),
            network: Vec::new(),
            handles: Vec::new(),
        }
    }
}

// ─── SystemMonitor trait ──────────────────────────────────────────────────────

#[async_trait]
pub trait SystemMonitor: Send + Sync {
    /// # Errors
    /// Returns an error if the process list cannot be retrieved.
    fn list_processes(&self) -> Result<Vec<ProcessInfo>, SysinternalsError>;
    /// # Errors
    /// Returns an error if the driver list cannot be retrieved.
    fn list_drivers(&self) -> Result<Vec<DriverInfo>, SysinternalsError>;
    /// # Errors
    /// Returns an error if handle information cannot be retrieved.
    fn list_handles(&self, pid: Option<u32>) -> Result<Vec<HandleInfo>, SysinternalsError>;
    /// # Errors
    /// Returns an error if network connections cannot be retrieved.
    fn network_connections(&self) -> Result<Vec<NetworkEndpoint>, SysinternalsError>;
    /// # Errors
    /// Returns an error if the system snapshot cannot be created.
    fn snapshot(&self) -> Result<SystemSnapshot, SysinternalsError>;
}

// ─── InMemorySystemMonitor ────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InMemorySystemMonitor {
    pub processes: Vec<ProcessInfo>,
    pub drivers: Vec<DriverInfo>,
    pub handles: Vec<HandleInfo>,
    pub network: Vec<NetworkEndpoint>,
}

impl InMemorySystemMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_process(&mut self, p: ProcessInfo) {
        self.processes.push(p);
    }

    pub fn add_driver(&mut self, d: DriverInfo) {
        self.drivers.push(d);
    }

    pub fn add_handle(&mut self, h: HandleInfo) {
        self.handles.push(h);
    }

    pub fn add_endpoint(&mut self, e: NetworkEndpoint) {
        self.network.push(e);
    }
}

#[async_trait]
impl SystemMonitor for InMemorySystemMonitor {
    fn list_processes(&self) -> Result<Vec<ProcessInfo>, SysinternalsError> {
        Ok(self.processes.clone())
    }

    fn list_drivers(&self) -> Result<Vec<DriverInfo>, SysinternalsError> {
        Ok(self.drivers.clone())
    }

    fn list_handles(&self, pid: Option<u32>) -> Result<Vec<HandleInfo>, SysinternalsError> {
        Ok(pid.map_or_else(
            || self.handles.clone(),
            |p| self.handles.iter().filter(|h| h.pid == p).cloned().collect(),
        ))
    }

    fn network_connections(&self) -> Result<Vec<NetworkEndpoint>, SysinternalsError> {
        Ok(self.network.clone())
    }

    fn snapshot(&self) -> Result<SystemSnapshot, SysinternalsError> {
        Ok(SystemSnapshot {
            processes: self.processes.clone(),
            drivers: self.drivers.clone(),
            network: self.network.clone(),
            handles: self.handles.clone(),
        })
    }
}

// ─── ProcessScanner ───────────────────────────────────────────────────────────

pub struct ProcessScanner {
    refresh_interval: Duration,
    cached_processes: RwLock<HashMap<u32, ProcessInfo>>,
    last_scan: RwLock<Option<Instant>>,
}

impl ProcessScanner {
    #[must_use]
    pub fn new(refresh_interval: Duration) -> Self {
        Self {
            refresh_interval,
            cached_processes: RwLock::new(HashMap::new()),
            last_scan: RwLock::new(None),
        }
    }

    /// Scan all processes (stub — returns empty on platforms without OS access).
    ///
    /// # Errors
    /// Always succeeds in this stub implementation.
    pub const fn scan() -> Result<Vec<ProcessInfo>, SysinternalsError> {
        Ok(Vec::new())
    }

    /// # Errors
    /// Returns `ProcessNotFound` — this stub never succeeds.
    pub const fn get_process(_pid: u32) -> Result<ProcessInfo, SysinternalsError> {
        Err(SysinternalsError::ProcessNotFound(0))
    }

    /// # Errors
    /// Always succeeds in this stub implementation.
    pub const fn find_by_name(_name: &str) -> Result<Vec<ProcessInfo>, SysinternalsError> {
        Ok(Vec::new())
    }

    /// Build a process tree from a flat list.
    ///
    /// # Errors
    /// Propagates errors from `ProcessTree::from_list`.
    pub fn process_tree_from(processes: &[ProcessInfo]) -> Result<ProcessTree, SysinternalsError> {
        ProcessTree::from_list(processes)
    }

    /// # Errors
    /// Always succeeds in this stub implementation.
    pub const fn process_tree() -> Result<ProcessTree, SysinternalsError> {
        Ok(ProcessTree { roots: Vec::new() })
    }

    /// Returns PIDs whose PPID does not appear in `tree`.
    #[must_use] 
    pub fn orphaned_processes(tree: &ProcessTree) -> Vec<u32> {
        let all_pids: std::collections::HashSet<u32> =
            tree.depth_first_iter().map(|n| n.info.pid).collect();
        tree.depth_first_iter()
            .filter(|n| n.info.ppid != 0 && !all_pids.contains(&n.info.ppid))
            .map(|n| n.info.pid)
            .collect()
    }

    /// True if the cache is stale.
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        self.last_scan.read().is_none_or(|t| t.elapsed() >= self.refresh_interval)
    }

    /// Update cache from a flat list.
    pub fn update_cache(&mut self, processes: Vec<ProcessInfo>) {
        let mut cache = self.cached_processes.write();
        cache.clear();
        for p in processes {
            cache.insert(p.pid, p);
        }
        drop(cache);
        *self.last_scan.write() = Some(Instant::now());
    }

    /// Return cached process info by pid, returning a clone of the stored entry.
    #[must_use]
    pub fn cached(&self, pid: u32) -> Option<ProcessInfo> {
        self.cached_processes.read().get(&pid).cloned()
    }
}

// ─── ProcessTree ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTree {
    pub roots: Vec<ProcessNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub info: ProcessInfo,
    pub children: Vec<Self>,
}

impl ProcessTree {
    /// Build a tree from a flat slice of `ProcessInfo`.
    ///
    /// # Errors
    /// Currently infallible, but returns `Result` for future compatibility.
    pub fn from_list(processes: &[ProcessInfo]) -> Result<Self, SysinternalsError> {
        // Inner helper — defined before any statements to satisfy `items_after_statements`.
        // `visited` prevents infinite recursion when the input contains parent–child cycles
        // (e.g. PID 100 → PPID 200 → PPID 100). Each PID is expanded at most once.
        fn attach_children(
            pid: u32,
            nodes: &mut HashMap<u32, ProcessNode>,
            parent_map: &HashMap<u32, Vec<u32>>,
            visited: &mut std::collections::HashSet<u32>,
        ) -> ProcessNode {
            let children = if visited.insert(pid) {
                parent_map.get(&pid).cloned().unwrap_or_default()
            } else {
                // Cycle detected — do not recurse further.
                Vec::new()
            };
            let child_nodes: Vec<ProcessNode> = children
                .iter()
                .map(|&c| attach_children(c, nodes, parent_map, visited))
                .collect();
            let mut node = nodes.remove(&pid).unwrap_or_else(|| ProcessNode {
                info: ProcessInfo::new(pid, 0, format!("<{pid}>")),
                children: Vec::new(),
            });
            node.children = child_nodes;
            node
        }

        let pid_set: std::collections::HashSet<u32> = processes.iter().map(|p| p.pid).collect();
        let mut nodes: HashMap<u32, ProcessNode> = processes
            .iter()
            .map(|p| {
                (
                    p.pid,
                    ProcessNode {
                        info: p.clone(),
                        children: Vec::new(),
                    },
                )
            })
            .collect();

        let mut roots = Vec::new();
        let mut parent_map: HashMap<u32, Vec<u32>> = HashMap::new();

        for p in processes {
            if p.ppid == 0 || p.ppid == p.pid || !pid_set.contains(&p.ppid) {
                roots.push(p.pid);
            } else {
                parent_map.entry(p.ppid).or_default().push(p.pid);
            }
        }

        let mut visited = std::collections::HashSet::new();
        let root_nodes: Vec<ProcessNode> = roots
            .iter()
            .map(|&r| attach_children(r, &mut nodes, &parent_map, &mut visited))
            .collect();

        Ok(Self { roots: root_nodes })
    }

    /// Find a node by PID via depth-first search.
    #[must_use]
    pub fn find(&self, pid: u32) -> Option<&ProcessNode> {
        self.depth_first_iter().find(|n| n.info.pid == pid)
    }

    /// Depth-first iterator over all nodes.
    pub fn depth_first_iter(&self) -> impl Iterator<Item = &ProcessNode> {
        ProcessNodeIter::new(&self.roots)
    }

    /// Render the tree as indented text.
    #[must_use]
    pub fn to_text(&self, indent: usize) -> String {
        let mut out = String::new();
        for root in &self.roots {
            root.render_text(&mut out, 0, indent);
        }
        out
    }

    /// Total number of nodes.
    #[must_use]
    pub fn count(&self) -> usize {
        self.depth_first_iter().count()
    }

    /// Maximum depth.
    #[must_use]
    pub fn max_depth(&self) -> usize {
        fn depth(node: &ProcessNode) -> usize {
            if node.children.is_empty() {
                1
            } else {
                1 + node.children.iter().map(depth).max().unwrap_or(0)
            }
        }
        self.roots.iter().map(depth).max().unwrap_or(0)
    }
}

impl ProcessNode {
    fn render_text(&self, out: &mut String, level: usize, indent: usize) {
        use std::fmt::Write as _;
        let pad = " ".repeat(level * indent);
        let _ = writeln!(out, "{}[{}] {} ({})", pad, self.info.pid, self.info.name, self.info.status);
        for child in &self.children {
            child.render_text(out, level + 1, indent);
        }
    }

    /// Depth of this sub-tree.
    #[must_use]
    pub fn depth(&self) -> usize {
        if self.children.is_empty() {
            1
        } else {
            1 + self.children.iter().map(Self::depth).max().unwrap_or(0)
        }
    }
}

struct ProcessNodeIter<'a> {
    stack: Vec<&'a ProcessNode>,
}

impl<'a> ProcessNodeIter<'a> {
    fn new(roots: &'a [ProcessNode]) -> Self {
        Self {
            stack: roots.iter().rev().collect(),
        }
    }
}

impl<'a> Iterator for ProcessNodeIter<'a> {
    type Item = &'a ProcessNode;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        for child in node.children.iter().rev() {
            self.stack.push(child);
        }
        Some(node)
    }
}

// ─── AutorunCategory ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AutorunCategory {
    LogonRegistry,
    RunOnce,
    Services,
    ScheduledTasks,
    StartupFolder,
    BrowserExtension,
    WmiSubscription,
    BootExecute,
    ImageFileExecution,
    AppCertDlls,
    LsaNotifications,
    Winlogon,
    ShellExecuteHooks,
    PrintMonitors,
    NetworkProviders,
}

impl fmt::Display for AutorunCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::LogonRegistry => "Logon Registry",
            Self::RunOnce => "Run Once",
            Self::Services => "Services",
            Self::ScheduledTasks => "Scheduled Tasks",
            Self::StartupFolder => "Startup Folder",
            Self::BrowserExtension => "Browser Extension",
            Self::WmiSubscription => "WMI Subscription",
            Self::BootExecute => "Boot Execute",
            Self::ImageFileExecution => "Image File Execution",
            Self::AppCertDlls => "AppCert DLLs",
            Self::LsaNotifications => "LSA Notifications",
            Self::Winlogon => "Winlogon",
            Self::ShellExecuteHooks => "Shell Execute Hooks",
            Self::PrintMonitors => "Print Monitors",
            Self::NetworkProviders => "Network Providers",
        };
        write!(f, "{s}")
    }
}

// ─── AutorunEntry ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutorunEntry {
    pub category: AutorunCategory,
    pub location: String,
    pub name: String,
    pub value: String,
    pub image_path: String,
    pub description: Option<String>,
    pub publisher: Option<String>,
    pub signed: Option<bool>,
    pub enabled: bool,
    pub launch_string: String,
}

impl AutorunEntry {
    #[must_use]
    pub fn new(
        category: AutorunCategory,
        location: impl Into<String>,
        name: impl Into<String>,
        image_path: impl Into<String>,
        launch_string: impl Into<String>,
    ) -> Self {
        let image_path = image_path.into();
        let launch_string = launch_string.into();
        let name_s = name.into();
        Self {
            category,
            location: location.into(),
            name: name_s,
            value: String::new(),
            image_path,
            description: None,
            publisher: None,
            signed: None,
            enabled: true,
            launch_string,
        }
    }

    /// True if the image path is in a suspicious location.
    #[must_use]
    pub fn is_suspicious_path(&self) -> bool {
        let lp = self.image_path.to_lowercase();
        lp.contains("\\temp\\")
            || lp.contains("\\tmp\\")
            || lp.contains("\\appdata\\")
            || lp.contains("\\downloads\\")
            || lp.contains("/tmp/")
    }

    /// True if entry is unsigned and enabled.
    #[must_use]
    pub fn is_unsigned(&self) -> bool {
        self.enabled && self.signed == Some(false)
    }

    /// CSV row.
    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{}",
            csv_field(&self.category.to_string()),
            csv_field(&self.location),
            csv_field(&self.name),
            csv_field(&self.image_path),
            self.signed
                .map_or("unknown", |s| if s { "signed" } else { "unsigned" })
        )
    }
}

// ─── AutorunDiff ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutorunDiff {
    pub added: Vec<AutorunEntry>,
    pub removed: Vec<AutorunEntry>,
    pub changed: Vec<(AutorunEntry, AutorunEntry)>,
}

impl AutorunDiff {
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    #[must_use]
    pub const fn total_changes(&self) -> usize {
        self.added.len() + self.removed.len() + self.changed.len()
    }
}

// ─── AutorunScanner ───────────────────────────────────────────────────────────

pub struct AutorunScanner;

impl AutorunScanner {
    /// Scan all autorun categories (stub — returns empty list).
    ///
    /// # Errors
    /// Always succeeds in this stub implementation.
    pub const fn scan_all() -> Result<Vec<AutorunEntry>, SysinternalsError> {
        Ok(Vec::new())
    }

    /// # Errors
    /// Always succeeds in this stub implementation.
    pub const fn scan_category(_cat: AutorunCategory) -> Result<Vec<AutorunEntry>, SysinternalsError> {
        Ok(Vec::new())
    }

    /// Filter entries in suspicious paths or unsigned from suspicious locations.
    #[must_use]
    pub fn filter_suspicious(entries: &[AutorunEntry]) -> Vec<&AutorunEntry> {
        entries
            .iter()
            .filter(|e| e.is_suspicious_path() || e.is_unsigned())
            .collect()
    }

    #[must_use]
    pub fn filter_unsigned(entries: &[AutorunEntry]) -> Vec<&AutorunEntry> {
        entries.iter().filter(|e| e.is_unsigned()).collect()
    }

    /// Compute diff between a baseline and current snapshot.
    #[must_use]
    pub fn diff(baseline: &[AutorunEntry], current: &[AutorunEntry]) -> AutorunDiff {
        let baseline_keys: HashMap<String, &AutorunEntry> = baseline
            .iter()
            .map(|e| (format!("{}:{}", e.location, e.name), e))
            .collect();
        let current_keys: HashMap<String, &AutorunEntry> = current
            .iter()
            .map(|e| (format!("{}:{}", e.location, e.name), e))
            .collect();

        let added: Vec<AutorunEntry> = current
            .iter()
            .filter(|e| !baseline_keys.contains_key(&format!("{}:{}", e.location, e.name)))
            .cloned()
            .collect();

        let removed: Vec<AutorunEntry> = baseline
            .iter()
            .filter(|e| !current_keys.contains_key(&format!("{}:{}", e.location, e.name)))
            .cloned()
            .collect();

        let changed: Vec<(AutorunEntry, AutorunEntry)> = current
            .iter()
            .filter_map(|cur| {
                let key = format!("{}:{}", cur.location, cur.name);
                baseline_keys.get(&key).and_then(|base| {
                    if base.launch_string != cur.launch_string
                        || base.image_path != cur.image_path
                        || base.enabled != cur.enabled
                    {
                        Some(((*base).clone(), cur.clone()))
                    } else {
                        None
                    }
                })
            })
            .collect();

        AutorunDiff {
            added,
            removed,
            changed,
        }
    }
}

// ─── CertInfo ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: u64,
    pub not_after: u64,
    pub is_root: bool,
}

impl CertInfo {
    #[must_use]
    pub fn new(
        subject: impl Into<String>,
        issuer: impl Into<String>,
        serial: impl Into<String>,
        not_before: u64,
        not_after: u64,
        is_root: bool,
    ) -> Self {
        Self {
            subject: subject.into(),
            issuer: issuer.into(),
            serial: serial.into(),
            not_before,
            not_after,
            is_root,
        }
    }

    /// True if the certificate is currently valid at `unix_ts`.
    #[must_use]
    pub const fn valid_at(&self, unix_ts: u64) -> bool {
        unix_ts >= self.not_before && unix_ts <= self.not_after
    }
}

// ─── SignatureInfo ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub path: String,
    pub is_signed: bool,
    pub is_valid: bool,
    pub signer: Option<String>,
    pub issuer: Option<String>,
    pub serial: Option<String>,
    pub algorithm: Option<String>,
    pub timestamp: Option<u64>,
    pub countersigner: Option<String>,
    pub cert_chain: Vec<CertInfo>,
}

impl SignatureInfo {
    #[must_use]
    pub fn unsigned(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            is_signed: false,
            is_valid: false,
            signer: None,
            issuer: None,
            serial: None,
            algorithm: None,
            timestamp: None,
            countersigner: None,
            cert_chain: Vec::new(),
        }
    }

    #[must_use]
    pub fn has_root_cert(&self) -> bool {
        self.cert_chain.iter().any(|c| c.is_root)
    }
}

// ─── FileSignatureChecker ─────────────────────────────────────────────────────

pub struct FileSignatureChecker;

impl FileSignatureChecker {
    /// Check for PE Authenticode signature (stub: inspects `WIN_CERT` directory).
    ///
    /// # Errors
    /// Returns an error if the file cannot be read.
    pub fn check(path: &std::path::Path) -> Result<SignatureInfo, SysinternalsError> {
        let data = std::fs::read(path).map_err(|e| SysinternalsError::Io(e.to_string()))?;
        let path_str = path.to_string_lossy().to_string();
        if Self::has_pe_signature(&data) {
            Ok(SignatureInfo {
                path: path_str,
                is_signed: true,
                is_valid: true,
                signer: Some("Unknown Signer".into()),
                issuer: Some("Unknown CA".into()),
                serial: Some("00".into()),
                algorithm: Some("SHA256".into()),
                timestamp: None,
                countersigner: None,
                cert_chain: Vec::new(),
            })
        } else {
            Ok(SignatureInfo::unsigned(path_str))
        }
    }

    /// Compute SHA-256 hex digest of a file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read.
    pub fn hash_sha256(path: &std::path::Path) -> Result<String, SysinternalsError> {
        let data = std::fs::read(path).map_err(|e| SysinternalsError::Io(e.to_string()))?;
        Ok(sha256_hex(&data))
    }

    /// Compute MD5 hex digest of a file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read.
    pub fn hash_md5(path: &std::path::Path) -> Result<String, SysinternalsError> {
        let data = std::fs::read(path).map_err(|e| SysinternalsError::Io(e.to_string()))?;
        Ok(md5_hex(&data))
    }

    /// Check if the PE data contains an Authenticode signature directory entry.
    ///
    /// The Win32 PE optional header data directory index 4 is the security
    /// directory. We look at offset 0x98 (PE32+) or 0x78 (PE32) for a non-zero
    /// RVA as a heuristic.
    #[must_use]
    pub fn has_pe_signature(data: &[u8]) -> bool {
        if data.len() < 0x40 {
            return false;
        }
        // Check MZ header.
        if data[0] != b'M' || data[1] != b'Z' {
            return false;
        }
        // PE offset at 0x3C.
        let pe_offset =
            u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        let Some(pe_end) = pe_offset.checked_add(4) else { return false };
        if pe_end > data.len() {
            return false;
        }
        // PE signature.
        if &data[pe_offset..pe_end] != b"PE\0\0" {
            return false;
        }
        // Optional header at pe_offset + 24.
        let Some(opt_offset) = pe_offset.checked_add(24) else { return false };
        let Some(opt_end) = opt_offset.checked_add(2) else { return false };
        if opt_end > data.len() {
            return false;
        }
        let magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
        // Security directory is DATA_DIRECTORY[4].
        // Optional header for PE32: fixed fields end at 0x60, then 4 data-dir entries (indices 0-3)
        // occupy 4*8=0x20 bytes, so DATA_DIRECTORY[4] starts at 0x60+0x20 = 0x80.
        // For PE32+ the fixed portion is 0x10 bytes larger, so the base is 0x70, giving 0x70+0x20 = 0x90.
        let add = if magic == 0x020b { 0x90usize } else { 0x80usize };
        let Some(sec_dir_off) = opt_offset.checked_add(add) else { return false };
        let Some(sec_dir_end) = sec_dir_off.checked_add(8) else { return false };
        if sec_dir_end > data.len() {
            return false;
        }
        let rva = u32::from_le_bytes([
            data[sec_dir_off],
            data[sec_dir_off + 1],
            data[sec_dir_off + 2],
            data[sec_dir_off + 3],
        ]);
        rva != 0
    }
}

/// Simple SHA-256 implementation (no external deps).
fn sha256_hex(data: &[u8]) -> String {
    // Initial hash values (first 32 bits of fractional parts of square roots of primes 2..17)
    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
        0x5be0_cd19,
    ];
    // Round constants
    let kk: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
        0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
        0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
        0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
        0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
        0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
        0xc671_78f2,
    ];

    // Pre-processing: add padding.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit chunk.
    for chunk in msg.chunks(64) {
        let mut ww = [0u32; 64];
        for i in 0..16 {
            ww[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = ww[i - 15].rotate_right(7) ^ ww[i - 15].rotate_right(18) ^ (ww[i - 15] >> 3);
            let s1 = ww[i - 2].rotate_right(17) ^ ww[i - 2].rotate_right(19) ^ (ww[i - 2] >> 10);
            ww[i] = ww[i - 16]
                .wrapping_add(s0)
                .wrapping_add(ww[i - 7])
                .wrapping_add(s1);
        }

        let [mut aa, mut bb, mut cc, mut dd, mut ee, mut ff, mut gg, mut hh] =
            [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];

        for i in 0..64 {
            let s1 = ee.rotate_right(6) ^ ee.rotate_right(11) ^ ee.rotate_right(25);
            let ch = (ee & ff) ^ ((!ee) & gg);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(kk[i])
                .wrapping_add(ww[i]);
            let s0 = aa.rotate_right(2) ^ aa.rotate_right(13) ^ aa.rotate_right(22);
            let maj = (aa & bb) ^ (aa & cc) ^ (bb & cc);
            let temp2 = s0.wrapping_add(maj);
            hh = gg;
            gg = ff;
            ff = ee;
            ee = dd.wrapping_add(temp1);
            dd = cc;
            cc = bb;
            bb = aa;
            aa = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(aa);
        h[1] = h[1].wrapping_add(bb);
        h[2] = h[2].wrapping_add(cc);
        h[3] = h[3].wrapping_add(dd);
        h[4] = h[4].wrapping_add(ee);
        h[5] = h[5].wrapping_add(ff);
        h[6] = h[6].wrapping_add(gg);
        h[7] = h[7].wrapping_add(hh);
    }

    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    )
}

/// Simple MD5 implementation (no external deps).
fn md5_hex(data: &[u8]) -> String {
    let rot: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let kk: [u32; 64] = [
        0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a, 0xa830_4613,
        0xfd46_9501, 0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, 0x6b90_1122, 0xfd98_7193,
        0xa679_438e, 0x49b4_0821, 0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d,
        0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8, 0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
        0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a, 0xfffa_3942, 0x8771_f681, 0x6d9d_6122,
        0xfde5_380c, 0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70, 0x289b_7ec6, 0xeaa1_27fa,
        0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665, 0xf429_2244,
        0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
        0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, 0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb,
        0xeb86_d391,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    for chunk in msg.chunks(64) {
        let mut block = [0u32; 16];
        for i in 0..16 {
            block[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut aa, mut bb, mut cc, mut dd) = (a0, b0, c0, d0);
        for i in 0usize..64 {
            let (mix, mi) = if i < 16 {
                ((bb & cc) | ((!bb) & dd), i)
            } else if i < 32 {
                ((dd & bb) | ((!dd) & cc), (5 * i + 1) % 16)
            } else if i < 48 {
                (bb ^ cc ^ dd, (3 * i + 5) % 16)
            } else {
                (cc ^ (bb | (!dd)), (7 * i) % 16)
            };
            let mix = mix.wrapping_add(aa).wrapping_add(kk[i]).wrapping_add(block[mi]);
            aa = dd;
            dd = cc;
            cc = bb;
            bb = bb.wrapping_add(mix.rotate_left(rot[i]));
        }
        a0 = a0.wrapping_add(aa);
        b0 = b0.wrapping_add(bb);
        c0 = c0.wrapping_add(cc);
        d0 = d0.wrapping_add(dd);
    }

    let result = [
        a0.to_le_bytes(),
        b0.to_le_bytes(),
        c0.to_le_bytes(),
        d0.to_le_bytes(),
    ]
    .concat();
    result.iter().fold(String::new(), |mut acc, bb| { use std::fmt::Write; let _ = write!(acc, "{bb:02x}"); acc })
}

// ─── NetworkMonitor ───────────────────────────────────────────────────────────

pub struct NetworkMonitor;

impl NetworkMonitor {
    /// Snapshot of current network connections (stub).
    ///
    /// # Errors
    /// Always succeeds in this stub implementation.
    pub const fn snapshot() -> Result<Vec<NetworkConnection>, SysinternalsError> {
        Ok(Vec::new())
    }

    /// # Errors
    /// Always succeeds in this stub implementation.
    pub const fn connections_for_pid(_pid: u32) -> Result<Vec<NetworkConnection>, SysinternalsError> {
        Ok(Vec::new())
    }

    /// # Errors
    /// Always succeeds in this stub implementation.
    pub const fn listening_ports() -> Result<Vec<NetworkConnection>, SysinternalsError> {
        Ok(Vec::new())
    }

    /// # Errors
    /// Always succeeds in this stub implementation.
    pub const fn connections_to_addr(_addr: IpAddr) -> Result<Vec<NetworkConnection>, SysinternalsError> {
        Ok(Vec::new())
    }

    /// Filter a list for listening connections.
    #[must_use]
    pub fn filter_listening(conns: &[NetworkConnection]) -> Vec<&NetworkConnection> {
        conns.iter().filter(|c| c.is_listening()).collect()
    }

    /// Filter a list for established connections.
    #[must_use]
    pub fn filter_established(conns: &[NetworkConnection]) -> Vec<&NetworkConnection> {
        conns.iter().filter(|c| c.is_established()).collect()
    }

    /// Group connections by PID.
    #[must_use]
    pub fn group_by_pid(conns: &[NetworkConnection]) -> HashMap<u32, Vec<&NetworkConnection>> {
        let mut map: HashMap<u32, Vec<&NetworkConnection>> = HashMap::new();
        for c in conns {
            map.entry(c.pid).or_default().push(c);
        }
        map
    }

    /// Render connections table as CSV.
    #[must_use]
    pub fn to_csv(conns: &[NetworkConnection]) -> String {
        let mut out = String::from("PID,Process,Protocol,LocalAddr,LocalPort,RemoteAddr,State\n");
        for c in conns {
            out.push_str(&c.to_csv_row());
            out.push('\n');
        }
        out
    }
}

// ─── ResourceUsage ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub pid: u32,
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub network_recv_bytes: u64,
    pub network_sent_bytes: u64,
    pub open_handle_count: u32,
    pub thread_count: u32,
}

impl ResourceUsage {
    #[must_use]
    pub const fn new(pid: u32) -> Self {
        Self {
            pid,
            cpu_percent: 0.0,
            memory_bytes: 0,
            disk_read_bytes: 0,
            disk_write_bytes: 0,
            network_recv_bytes: 0,
            network_sent_bytes: 0,
            open_handle_count: 0,
            thread_count: 0,
        }
    }

    #[must_use]
    pub const fn total_io_bytes(&self) -> u64 {
        self.disk_read_bytes.saturating_add(self.disk_write_bytes)
    }

    #[must_use]
    pub const fn total_network_bytes(&self) -> u64 {
        self.network_recv_bytes
            .saturating_add(self.network_sent_bytes)
    }

    /// CSV row.
    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{:.2},{},{},{},{},{},{},{}",
            self.pid,
            self.cpu_percent,
            self.memory_bytes,
            self.disk_read_bytes,
            self.disk_write_bytes,
            self.network_recv_bytes,
            self.network_sent_bytes,
            self.open_handle_count,
            self.thread_count
        )
    }
}

// ─── ResourceUsageMonitor ─────────────────────────────────────────────────────

pub struct ResourceUsageMonitor {
    history: HashMap<u32, Vec<ResourceUsage>>,
    history_size: usize,
}

impl ResourceUsageMonitor {
    #[must_use]
    pub fn new(history_size: usize) -> Self {
        Self {
            history: HashMap::new(),
            history_size: history_size.max(1),
        }
    }

    /// Sample current usage (stub — returns empty; inject via `record_sample`).
    ///
    /// # Errors
    /// Always succeeds in this stub implementation.
    pub const fn sample(&mut self) -> Result<Vec<ResourceUsage>, SysinternalsError> {
        Ok(Vec::new())
    }

    /// Record a sample for a PID (used in tests).
    pub fn record_sample(&mut self, usage: ResourceUsage) {
        let pid = usage.pid;
        let hist = self.history.entry(pid).or_default();
        hist.push(usage);
        if hist.len() > self.history_size {
            hist.remove(0);
        }
    }

    /// Top N processes by CPU.
    #[must_use]
    pub fn top_cpu(&self, n: usize) -> Vec<ResourceUsage> {
        let mut latest: Vec<&ResourceUsage> =
            self.history.values().filter_map(|h| h.last()).collect();
        latest.sort_by(|a, b| {
            b.cpu_percent
                .partial_cmp(&a.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        latest.into_iter().take(n).cloned().collect()
    }

    /// Top N processes by memory.
    #[must_use]
    pub fn top_memory(&self, n: usize) -> Vec<ResourceUsage> {
        let mut latest: Vec<&ResourceUsage> =
            self.history.values().filter_map(|h| h.last()).collect();
        latest.sort_by_key(|u| std::cmp::Reverse(u.memory_bytes));
        latest.into_iter().take(n).cloned().collect()
    }

    #[must_use]
    pub fn history_for_pid(&self, pid: u32) -> Option<&[ResourceUsage]> {
        self.history.get(&pid).map(std::vec::Vec::as_slice)
    }

    /// Average CPU over recorded history for a PID.
    #[must_use]
    pub fn average_cpu(&self, pid: u32) -> Option<f64> {
        let hist = self.history.get(&pid)?;
        if hist.is_empty() {
            return None;
        }
        let sum: f64 = hist.iter().map(|u| u.cpu_percent).sum();
        let count = u32::try_from(hist.len()).unwrap_or(u32::MAX);
        Some(sum / f64::from(count))
    }

    /// Average memory over history for a PID.
    #[must_use]
    pub fn average_memory(&self, pid: u32) -> Option<f64> {
        let hist = self.history.get(&pid)?;
        if hist.is_empty() {
            return None;
        }
        let sum: u64 = hist.iter().map(|u| u.memory_bytes).sum();
        let count = u32::try_from(hist.len()).unwrap_or(u32::MAX);
        let sum_mib = u32::try_from(sum / (1024 * 1024)).unwrap_or(u32::MAX);
        Some(f64::from(sum_mib) / f64::from(count))
    }

    /// All PIDs with recorded history.
    #[must_use]
    pub fn tracked_pids(&self) -> Vec<u32> {
        self.history.keys().copied().collect()
    }

    /// CSV dump of all latest samples.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "PID,CPU%,MemoryBytes,DiskRead,DiskWrite,NetRecv,NetSent,Handles,Threads\n",
        );
        for hist in self.history.values() {
            if let Some(u) = hist.last() {
                out.push_str(&u.to_csv_row());
                out.push('\n');
            }
        }
        out
    }
}

// ─── SuspicionCategory ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SuspicionCategory {
    NetworkActivity,
    ProcessInjection,
    PersistenceMechanism,
    AntiAnalysis,
    UnusualPath,
    UnusualParent,
    SuspiciousName,
    HighCpuOnDisk,
    Unsigned,
    HighHandleCount,
}

impl fmt::Display for SuspicionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NetworkActivity => "Network Activity",
            Self::ProcessInjection => "Process Injection",
            Self::PersistenceMechanism => "Persistence Mechanism",
            Self::AntiAnalysis => "Anti-Analysis",
            Self::UnusualPath => "Unusual Path",
            Self::UnusualParent => "Unusual Parent",
            Self::SuspiciousName => "Suspicious Name",
            Self::HighCpuOnDisk => "High CPU/Disk",
            Self::Unsigned => "Unsigned",
            Self::HighHandleCount => "High Handle Count",
        };
        write!(f, "{s}")
    }
}

// ─── SuspicionReason ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspicionReason {
    pub description: String,
    pub weight: u32,
    pub category: SuspicionCategory,
}

impl SuspicionReason {
    #[must_use]
    pub fn new(description: impl Into<String>, weight: u32, category: SuspicionCategory) -> Self {
        Self {
            description: description.into(),
            weight,
            category,
        }
    }
}

// ─── SuspicionReport ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspicionReport {
    pub pid: u32,
    pub process_name: String,
    pub score: u32,
    pub reasons: Vec<SuspicionReason>,
}

impl SuspicionReport {
    #[must_use]
    pub fn new(pid: u32, process_name: impl Into<String>) -> Self {
        Self {
            pid,
            process_name: process_name.into(),
            score: 0,
            reasons: Vec::new(),
        }
    }

    fn add_reason(&mut self, reason: SuspicionReason) {
        self.score = self.score.saturating_add(reason.weight).min(100);
        self.reasons.push(reason);
    }

    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.score >= 30
    }

    #[must_use]
    pub fn top_category(&self) -> Option<SuspicionCategory> {
        self.reasons
            .iter()
            .max_by_key(|r| r.weight)
            .map(|r| r.category)
    }

    /// CSV row.
    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!("{},{},{}", self.pid, csv_field(&self.process_name), self.score)
    }
}

// ─── Suspicious name list ─────────────────────────────────────────────────────

const SUSPICIOUS_NAMES: &[&str] = &[
    "mimikatz",
    "meterpreter",
    "cobalt",
    "beacon",
    "empire",
    "powershell",
    "wscript",
    "cscript",
    "mshta",
    "regsvr32",
    "rundll32",
    "cmd.exe",
    "certutil",
    "bitsadmin",
    "wmic",
    "svchost32",
    "lsas.exe",
    "csrss32",
    "winlogon32",
    "spoolsv32",
];

const SYSTEM_PROCESS_NAMES: &[&str] = &[
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "spoolsv.exe",
    "explorer.exe",
];

const ANTI_ANALYSIS_NAMES: &[&str] = &[
    "procmon",
    "procexp",
    "wireshark",
    "x64dbg",
    "x32dbg",
    "ollydbg",
    "ida",
    "ghidra",
    "vmtoolsd",
    "vmwaretray",
];

// ─── SuspicionScorer ──────────────────────────────────────────────────────────

pub struct SuspicionScorer;

impl SuspicionScorer {
    /// Score a single process for suspicion.
    #[must_use]
    pub fn score(process: &ProcessInfo) -> SuspicionReport {
        let mut report = SuspicionReport::new(process.pid, &process.name);
        let name_lower = process.name.to_lowercase();
        let path_lower = process.exe_path.to_lowercase();

        // Check for suspicious name.
        for &susp in SUSPICIOUS_NAMES {
            if name_lower.contains(susp) {
                report.add_reason(SuspicionReason::new(
                    format!("Process name matches suspicious pattern '{susp}'"),
                    15,
                    SuspicionCategory::SuspiciousName,
                ));
                break;
            }
        }

        // Check for anti-analysis tools running (defensive check).
        for &aa in ANTI_ANALYSIS_NAMES {
            if name_lower.contains(aa) {
                report.add_reason(SuspicionReason::new(
                    format!("Process appears to be an anti-analysis tool: {aa}"),
                    5,
                    SuspicionCategory::AntiAnalysis,
                ));
                break;
            }
        }

        // Check for unusual paths.
        if process.in_temp_dir() {
            report.add_reason(SuspicionReason::new(
                "Process running from temp directory",
                20,
                SuspicionCategory::UnusualPath,
            ));
        }

        if path_lower.contains("\\appdata\\") {
            report.add_reason(SuspicionReason::new(
                "Process running from AppData",
                15,
                SuspicionCategory::UnusualPath,
            ));
        }

        if path_lower.contains("\\downloads\\") {
            report.add_reason(SuspicionReason::new(
                "Process running from Downloads",
                20,
                SuspicionCategory::UnusualPath,
            ));
        }

        // Check for system process names masquerading.
        for &sys in SYSTEM_PROCESS_NAMES {
            if name_lower == sys && !process.is_system32() && !process.exe_path.is_empty() {
                report.add_reason(SuspicionReason::new(
                    format!("'{sys}' running outside System32"),
                    30,
                    SuspicionCategory::UnusualPath,
                ));
                break;
            }
        }

        // High CPU usage.
        if process.cpu_usage > 80.0 {
            report.add_reason(SuspicionReason::new(
                format!("High CPU usage: {:.1}%", process.cpu_usage),
                10,
                SuspicionCategory::HighCpuOnDisk,
            ));
        }

        // Unsigned modules.
        let unsigned_count = process
            .modules
            .iter()
            .filter(|m| m.signed == Some(false))
            .count();
        if unsigned_count > 0 {
            report.add_reason(SuspicionReason::new(
                format!("{unsigned_count} unsigned module(s) loaded"),
                10 * u32::try_from(unsigned_count).unwrap_or(u32::MAX).min(3),
                SuspicionCategory::Unsigned,
            ));
        }

        // Unusual parent (ppid == 0 for non-system process).
        if process.ppid == 0 && process.pid > 8 {
            report.add_reason(SuspicionReason::new(
                "Process has no parent (possible injection)",
                15,
                SuspicionCategory::UnusualParent,
            ));
        }

        // Many open files for a simple process.
        if process.open_files.len() > 50 {
            report.add_reason(SuspicionReason::new(
                format!("Unusually many open files: {}", process.open_files.len()),
                5,
                SuspicionCategory::HighHandleCount,
            ));
        }

        report
    }

    #[must_use]
    pub fn score_all(processes: &[ProcessInfo]) -> Vec<SuspicionReport> {
        processes.iter().map(Self::score).collect()
    }

    #[must_use]
    pub fn filter_suspicious(
        reports: &[SuspicionReport],
        min_score: u32,
    ) -> Vec<&SuspicionReport> {
        reports.iter().filter(|r| r.score >= min_score).collect()
    }

    /// Sort reports by score descending.
    pub fn sort_by_score(reports: &mut [SuspicionReport]) {
        reports.sort_by_key(|b| std::cmp::Reverse(b.score));
    }

    /// Return the most suspicious process.
    #[must_use]
    pub fn most_suspicious(reports: &[SuspicionReport]) -> Option<&SuspicionReport> {
        reports.iter().max_by_key(|r| r.score)
    }
}

// ─── SystemInfo ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub cpu_model: String,
    pub cpu_count: u32,
    pub total_memory: u64,
    pub available_memory: u64,
    pub uptime_secs: u64,
    pub load_avg: [f64; 3],
}

impl SystemInfo {
    /// Collect system info (stub — returns synthetic data).
    ///
    /// # Errors
    /// Always succeeds in this stub implementation.
    pub fn collect() -> Result<Self, SysinternalsError> {
        Ok(Self {
            hostname: "localhost".into(),
            os_name: std::env::consts::OS.into(),
            os_version: "unknown".into(),
            kernel_version: "unknown".into(),
            cpu_model: "Generic CPU".into(),
            cpu_count: 1,
            total_memory: 0,
            available_memory: 0,
            uptime_secs: 0,
            load_avg: [0.0; 3],
        })
    }

    /// Memory usage ratio.
    #[must_use]
    pub fn memory_usage_ratio(&self) -> f64 {
        if self.total_memory == 0 {
            return 0.0;
        }
        let used = self.total_memory.saturating_sub(self.available_memory);
        let used_mib = u32::try_from(used / (1024 * 1024)).unwrap_or(u32::MAX);
        let total_mib = u32::try_from(self.total_memory / (1024 * 1024)).unwrap_or(u32::MAX);
        f64::from(used_mib) / f64::from(total_mib)
    }

    /// Pretty-print uptime.
    #[must_use]
    pub fn uptime_human(&self) -> String {
        let s = self.uptime_secs;
        let days = s / 86400;
        let hours = (s % 86400) / 3600;
        let mins = (s % 3600) / 60;
        format!("{days}d {hours}h {mins}m")
    }
}

// ─── ProcessCsvExporter ───────────────────────────────────────────────────────

pub struct ProcessCsvExporter;

impl ProcessCsvExporter {
    /// Export a list of `ProcessInfo` as CSV.
    #[must_use]
    pub fn export(processes: &[ProcessInfo]) -> String {
        let mut out = String::from("PID,PPID,Name,User,Status,RSS,CPU%\n");
        for p in processes {
            out.push_str(&p.to_csv_row());
            out.push('\n');
        }
        out
    }
}

// ─── ProcessJsonExporter ──────────────────────────────────────────────────────

pub struct ProcessJsonExporter;

impl ProcessJsonExporter {
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn export(processes: &[ProcessInfo]) -> Result<String, SysinternalsError> {
        serde_json::to_string_pretty(processes)
            .map_err(|e| SysinternalsError::InvalidData(e.to_string()))
    }
}

// ─── SuspicionReportExporter ──────────────────────────────────────────────────

pub struct SuspicionReportExporter;

impl SuspicionReportExporter {
    #[must_use]
    pub fn to_csv(reports: &[SuspicionReport]) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("PID,ProcessName,Score,TopCategory\n");
        for r in reports {
            let cat = r.top_category().map(|c| c.to_string()).unwrap_or_default();
            let _ = writeln!(out, "{},{},{},{cat}", r.pid, r.process_name, r.score);
        }
        out
    }

    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(reports: &[SuspicionReport]) -> Result<String, SysinternalsError> {
        serde_json::to_string_pretty(reports)
            .map_err(|e| SysinternalsError::InvalidData(e.to_string()))
    }
}

// ─── AutorunCsvExporter ───────────────────────────────────────────────────────

pub struct AutorunCsvExporter;

impl AutorunCsvExporter {
    #[must_use]
    pub fn export(entries: &[AutorunEntry]) -> String {
        let mut out = String::from("Category,Location,Name,ImagePath,Signed\n");
        for e in entries {
            out.push_str(&e.to_csv_row());
            out.push('\n');
        }
        out
    }
}

// ─── ProcessBuilder (test helper) ────────────────────────────────────────────

pub struct ProcessBuilder {
    inner: ProcessInfo,
}

impl ProcessBuilder {
    #[must_use]
    pub fn new(pid: u32, parent_pid: u32, process_name: impl Into<String>) -> Self {
        Self {
            inner: ProcessInfo::new(pid, parent_pid, process_name),
        }
    }

    #[must_use]
    pub fn exe_path(mut self, p: impl Into<String>) -> Self {
        let p = p.into();
        self.inner.exe_path.clone_from(&p);
        self.inner.path = p;
        self
    }

    #[must_use]
    pub fn user(mut self, u: impl Into<String>) -> Self {
        self.inner.user = u.into();
        self
    }

    #[must_use]
    pub const fn status(mut self, s: ProcessStatus) -> Self {
        self.inner.status = s;
        self
    }

    #[must_use]
    pub const fn cpu(mut self, c: f64) -> Self {
        self.inner.cpu_usage = c;
        self
    }

    #[must_use]
    pub const fn rss(mut self, r: u64) -> Self {
        self.inner.memory_info.rss = r;
        self
    }

    #[must_use]
    pub fn add_module(mut self, m: ModuleInfo) -> Self {
        self.inner.modules.push(m);
        self
    }

    #[must_use]
    pub fn add_open_file(mut self, f: impl Into<String>) -> Self {
        self.inner.open_files.push(f.into());
        self
    }

    #[must_use]
    pub fn env_var(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.inner.env_vars.push((k.into(), v.into()));
        self
    }

    #[must_use]
    pub fn build(self) -> ProcessInfo {
        self.inner
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_monitor() -> InMemorySystemMonitor {
        let mut m = InMemorySystemMonitor::new();
        let mut p1 = ProcessInfo::new(1000, 0, "svchost.exe");
        p1.path = "C:\\Windows\\System32\\svchost.exe".into();
        p1.exe_path = "C:\\Windows\\System32\\svchost.exe".into();
        p1.cmdline = "svchost.exe -k netsvcs".into();
        p1.user = "SYSTEM".into();
        p1.handle_count = 150;
        p1.session_id = 0;
        p1.memory = MemoryStats {
            working_set: 4_096_000,
            private_bytes: 2_048_000,
            virtual_size: 8_192_000,
            peak_working_set: 5_000_000,
        };
        p1.threads.push(ThreadInfo::new(
            1001,
            1000,
            0x7ff0_0000,
            8,
            ThreadState::Waiting,
        ));
        p1.modules.push(ModuleInfo::new(
            0x7fff_0000_0000,
            0x8000,
            "ntdll.dll",
            "C:\\Windows\\System32\\ntdll.dll",
        ));
        let mut p2 = ProcessInfo::new(2000, 1000, "notepad.exe");
        p2.user = "User".into();
        m.add_process(p1);
        m.add_process(p2);
        m.add_driver(DriverInfo::new(
            0xFFFF_C000_0000,
            0x10000,
            "C:\\Windows\\System32\\drivers\\ntfs.sys",
            "ntfs.sys",
            DriverFlags::LOADED | DriverFlags::KERNEL_MODE | DriverFlags::FS_FILTER,
        ));
        m.add_driver(DriverInfo::new(
            0xFFFF_D000_0000,
            0x5000,
            "C:\\Windows\\System32\\drivers\\tcpip.sys",
            "tcpip.sys",
            DriverFlags::LOADED | DriverFlags::KERNEL_MODE,
        ));
        m.add_handle(HandleInfo::new(
            0x04,
            1000,
            "File",
            0xFFFF_8000_1234,
            0x0012_0089,
        ));
        m.add_handle(HandleInfo::new(
            0x08,
            1000,
            "Event",
            0xFFFF_8000_5678,
            0x001F_0003,
        ));
        m.add_handle(HandleInfo::new(
            0x0C,
            2000,
            "Process",
            0xFFFF_8001_ABCD,
            0x001F_FFFF,
        ));
        m.add_endpoint(NetworkEndpoint::new(
            1000,
            NetworkProtocol::Tcp,
            "0.0.0.0",
            80,
            "0.0.0.0",
            0,
            TcpState::Listen,
        ));
        m.add_endpoint(NetworkEndpoint::new(
            1000,
            NetworkProtocol::Tcp,
            "192.168.1.5",
            54321,
            "93.184.216.34",
            443,
            TcpState::Established,
        ));
        m.add_endpoint(NetworkEndpoint::new(
            2000,
            NetworkProtocol::Udp,
            "0.0.0.0",
            53,
            "",
            0,
            TcpState::Unknown,
        ));
        m
    }

    // ── InMemorySystemMonitor ──────────────────────────────────────────────────

    #[test]
    fn test_list_processes_count() {
        let m = make_monitor();
        assert_eq!(m.list_processes().unwrap().len(), 2);
    }

    #[test]
    fn test_list_processes_first_is_svchost() {
        let m = make_monitor();
        let procs = m.list_processes().unwrap();
        assert_eq!(procs[0].name, "svchost.exe");
        assert_eq!(procs[0].pid, 1000);
    }

    #[test]
    fn test_process_memory_stats() {
        let m = make_monitor();
        let procs = m.list_processes().unwrap();
        assert_eq!(procs[0].memory.working_set, 4_096_000);
        assert_eq!(procs[0].memory.peak_working_set, 5_000_000);
    }

    #[test]
    fn test_process_threads() {
        let m = make_monitor();
        let procs = m.list_processes().unwrap();
        assert_eq!(procs[0].threads.len(), 1);
        assert_eq!(procs[0].threads[0].state, ThreadState::Waiting);
    }

    #[test]
    fn test_process_modules() {
        let m = make_monitor();
        let procs = m.list_processes().unwrap();
        assert_eq!(procs[0].modules[0].name, "ntdll.dll");
    }

    #[test]
    fn test_list_drivers_count() {
        let m = make_monitor();
        assert_eq!(m.list_drivers().unwrap().len(), 2);
    }

    #[test]
    fn test_driver_flags_ntfs() {
        let m = make_monitor();
        let drivers = m.list_drivers().unwrap();
        assert!(drivers[0].flags.contains(DriverFlags::FS_FILTER));
    }

    #[test]
    fn test_list_handles_all() {
        let m = make_monitor();
        assert_eq!(m.list_handles(None).unwrap().len(), 3);
    }

    #[test]
    fn test_list_handles_filtered() {
        let m = make_monitor();
        let h = m.list_handles(Some(1000)).unwrap();
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn test_list_handles_no_match() {
        let m = make_monitor();
        assert!(m.list_handles(Some(9999)).unwrap().is_empty());
    }

    #[test]
    fn test_network_connections_count() {
        let m = make_monitor();
        assert_eq!(m.network_connections().unwrap().len(), 3);
    }

    #[test]
    fn test_snapshot_contains_all() {
        let m = make_monitor();
        let snap = m.snapshot().unwrap();
        assert_eq!(snap.processes.len(), 2);
        assert_eq!(snap.drivers.len(), 2);
    }

    #[test]
    fn test_snapshot_empty() {
        let snap = SystemSnapshot::empty();
        assert!(snap.processes.is_empty());
    }

    // ── ProcessTree ───────────────────────────────────────────────────────────

    #[test]
    fn test_process_tree_from_list() {
        let processes = vec![
            ProcessInfo::new(1, 0, "init"),
            ProcessInfo::new(2, 1, "bash"),
            ProcessInfo::new(3, 2, "ls"),
        ];
        let tree = ProcessTree::from_list(&processes).unwrap();
        assert_eq!(tree.roots.len(), 1);
        assert_eq!(tree.count(), 3);
    }

    #[test]
    fn test_process_tree_find() {
        let processes = vec![
            ProcessInfo::new(1, 0, "init"),
            ProcessInfo::new(2, 1, "bash"),
        ];
        let tree = ProcessTree::from_list(&processes).unwrap();
        assert!(tree.find(2).is_some());
        assert!(tree.find(999).is_none());
    }

    #[test]
    fn test_process_tree_depth_first() {
        let processes = vec![
            ProcessInfo::new(1, 0, "root"),
            ProcessInfo::new(2, 1, "child1"),
            ProcessInfo::new(3, 1, "child2"),
            ProcessInfo::new(4, 2, "grandchild"),
        ];
        let tree = ProcessTree::from_list(&processes).unwrap();
        let pids: Vec<u32> = tree.depth_first_iter().map(|n| n.info.pid).collect();
        assert_eq!(pids.len(), 4);
        assert!(pids.contains(&1));
        assert!(pids.contains(&4));
    }

    #[test]
    fn test_process_tree_to_text() {
        let processes = vec![
            ProcessInfo::new(1, 0, "init"),
            ProcessInfo::new(2, 1, "bash"),
        ];
        let tree = ProcessTree::from_list(&processes).unwrap();
        let text = tree.to_text(2);
        assert!(text.contains("init"));
        assert!(text.contains("bash"));
    }

    #[test]
    fn test_process_tree_count_empty() {
        let tree = ProcessTree { roots: Vec::new() };
        assert_eq!(tree.count(), 0);
    }

    #[test]
    fn test_process_tree_max_depth() {
        let processes = vec![
            ProcessInfo::new(1, 0, "a"),
            ProcessInfo::new(2, 1, "b"),
            ProcessInfo::new(3, 2, "c"),
        ];
        let tree = ProcessTree::from_list(&processes).unwrap();
        assert_eq!(tree.max_depth(), 3);
    }

    #[test]
    fn test_orphaned_processes() {
        let processes = vec![
            ProcessInfo::new(2, 999, "orphan"),
            ProcessInfo::new(3, 2, "child"),
        ];
        let tree = ProcessTree::from_list(&processes).unwrap();
        let orphans = ProcessScanner::orphaned_processes(&tree);
        assert!(orphans.contains(&2));
    }

    // ── ProcessScanner ────────────────────────────────────────────────────────

    #[test]
    fn test_scanner_needs_refresh_initially() {
        let scanner = ProcessScanner::new(Duration::from_secs(5));
        assert!(scanner.needs_refresh());
    }

    #[test]
    fn test_scanner_cache_update() {
        let mut scanner = ProcessScanner::new(Duration::from_mins(1));
        let p = ProcessInfo::new(42, 0, "test");
        scanner.update_cache(vec![p]);
        assert!(scanner.cached(42).is_some());
        assert!(!scanner.needs_refresh());
    }

    #[test]
    fn test_scanner_cache_miss() {
        let scanner = ProcessScanner::new(Duration::from_mins(1));
        assert!(scanner.cached(1234).is_none());
    }

    // ── AutorunEntry ──────────────────────────────────────────────────────────

    #[test]
    fn test_autorun_suspicious_path() {
        let e = AutorunEntry::new(
            AutorunCategory::LogonRegistry,
            "HKLM\\...",
            "evil",
            "C:\\Temp\\evil.exe",
            "C:\\Temp\\evil.exe",
        );
        assert!(e.is_suspicious_path());
    }

    #[test]
    fn test_autorun_not_suspicious_path() {
        let e = AutorunEntry::new(
            AutorunCategory::Services,
            "HKLM\\...",
            "legit",
            "C:\\Windows\\System32\\svchost.exe",
            "svchost.exe -k netsvcs",
        );
        assert!(!e.is_suspicious_path());
    }

    #[test]
    fn test_autorun_unsigned() {
        let mut e = AutorunEntry::new(
            AutorunCategory::LogonRegistry,
            "loc",
            "name",
            "C:\\Temp\\x.exe",
            "x.exe",
        );
        e.signed = Some(false);
        assert!(e.is_unsigned());
    }

    #[test]
    fn test_autorun_diff_added() {
        let baseline = vec![];
        let current = vec![AutorunEntry::new(
            AutorunCategory::LogonRegistry,
            "HKLM\\Run",
            "newentry",
            "C:\\new.exe",
            "C:\\new.exe",
        )];
        let diff = AutorunScanner::diff(&baseline, &current);
        assert_eq!(diff.added.len(), 1);
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn test_autorun_diff_removed() {
        let baseline = vec![AutorunEntry::new(
            AutorunCategory::LogonRegistry,
            "HKLM\\Run",
            "oldentry",
            "C:\\old.exe",
            "C:\\old.exe",
        )];
        let current = vec![];
        let diff = AutorunScanner::diff(&baseline, &current);
        assert_eq!(diff.removed.len(), 1);
        assert!(diff.added.is_empty());
    }

    #[test]
    fn test_autorun_diff_changed() {
        let baseline = vec![AutorunEntry::new(
            AutorunCategory::LogonRegistry,
            "HKLM\\Run",
            "entry",
            "C:\\old.exe",
            "C:\\old.exe",
        )];
        let current = vec![AutorunEntry::new(
            AutorunCategory::LogonRegistry,
            "HKLM\\Run",
            "entry",
            "C:\\new.exe",
            "C:\\new.exe",
        )];
        let diff = AutorunScanner::diff(&baseline, &current);
        assert_eq!(diff.changed.len(), 1);
    }

    #[test]
    fn test_autorun_diff_clean() {
        let entry = AutorunEntry::new(
            AutorunCategory::LogonRegistry,
            "HKLM\\Run",
            "same",
            "C:\\same.exe",
            "C:\\same.exe",
        );
        let entry2 = entry.clone();
        let diff = AutorunScanner::diff(std::slice::from_ref(&entry), &[entry2]);
        assert!(diff.is_clean());
    }

    #[test]
    fn test_autorun_filter_suspicious() {
        let entries = vec![
            AutorunEntry::new(
                AutorunCategory::LogonRegistry,
                "loc",
                "evil",
                "C:\\Temp\\evil.exe",
                "evil.exe",
            ),
            AutorunEntry::new(
                AutorunCategory::Services,
                "loc",
                "legit",
                "C:\\Windows\\svc.exe",
                "svc.exe",
            ),
        ];
        let sus = AutorunScanner::filter_suspicious(&entries);
        assert_eq!(sus.len(), 1);
    }

    // ── FileSignatureChecker ──────────────────────────────────────────────────

    #[test]
    fn test_has_pe_signature_empty() {
        assert!(!FileSignatureChecker::has_pe_signature(&[]));
    }

    #[test]
    fn test_has_pe_signature_not_pe() {
        assert!(!FileSignatureChecker::has_pe_signature(b"ELF\x02"));
    }

    #[test]
    fn test_sha256_known() {
        // SHA-256("") == e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        // NIST FIPS 180-4 reference value for SHA-256("abc")
        let hash = sha256_hex(b"abc");
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_md5_empty() {
        let hash = md5_hex(b"");
        assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_abc() {
        let hash = md5_hex(b"abc");
        assert_eq!(hash, "900150983cd24fb0d6963f7d28e17f72");
    }

    // ── NetworkMonitor ────────────────────────────────────────────────────────

    #[test]
    fn test_network_monitor_filter_listening() {
        let conns = vec![
            NetworkConnection::new_tcp(
                1,
                "svchost",
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                80,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
                TcpState::Listen,
            ),
            NetworkConnection::new_tcp(
                2,
                "chrome",
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                54321,
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                443,
                TcpState::Established,
            ),
        ];
        let listening = NetworkMonitor::filter_listening(&conns);
        assert_eq!(listening.len(), 1);
        assert_eq!(listening[0].local_port, 80);
    }

    #[test]
    fn test_network_monitor_filter_established() {
        let conns = vec![
            NetworkConnection::new_tcp(
                1,
                "svchost",
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                80,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
                TcpState::Listen,
            ),
            NetworkConnection::new_tcp(
                2,
                "chrome",
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                54321,
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                443,
                TcpState::Established,
            ),
        ];
        let est = NetworkMonitor::filter_established(&conns);
        assert_eq!(est.len(), 1);
        assert_eq!(est[0].remote_port, Some(443));
    }

    #[test]
    fn test_network_group_by_pid() {
        let conns = vec![
            NetworkConnection::new_tcp(
                10,
                "p1",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                1234,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                80,
                TcpState::Established,
            ),
            NetworkConnection::new_tcp(
                10,
                "p1",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                1235,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                443,
                TcpState::Established,
            ),
            NetworkConnection::new_tcp(
                20,
                "p2",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                2000,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                53,
                TcpState::Established,
            ),
        ];
        let groups = NetworkMonitor::group_by_pid(&conns);
        assert_eq!(groups[&10].len(), 2);
        assert_eq!(groups[&20].len(), 1);
    }

    #[test]
    fn test_network_csv() {
        let conns = vec![NetworkConnection::new_tcp(
            1,
            "test",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            80,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            TcpState::Established,
        )];
        let csv = NetworkMonitor::to_csv(&conns);
        assert!(csv.contains("PID"));
        assert!(csv.contains("80"));
    }

    // ── ResourceUsageMonitor ──────────────────────────────────────────────────

    #[test]
    fn test_resource_monitor_record_and_top_cpu() {
        let mut mon = ResourceUsageMonitor::new(10);
        let mut u1 = ResourceUsage::new(1);
        u1.cpu_percent = 90.0;
        let mut u2 = ResourceUsage::new(2);
        u2.cpu_percent = 10.0;
        mon.record_sample(u1);
        mon.record_sample(u2);
        let top = mon.top_cpu(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].pid, 1);
    }

    #[test]
    fn test_resource_monitor_top_memory() {
        let mut mon = ResourceUsageMonitor::new(10);
        let mut u1 = ResourceUsage::new(1);
        u1.memory_bytes = 1_000_000;
        let mut u2 = ResourceUsage::new(2);
        u2.memory_bytes = 500_000;
        mon.record_sample(u1);
        mon.record_sample(u2);
        let top = mon.top_memory(1);
        assert_eq!(top[0].pid, 1);
    }

    #[test]
    fn test_resource_monitor_average_cpu() {
        let mut mon = ResourceUsageMonitor::new(10);
        for i in 0..5 {
            let mut u = ResourceUsage::new(42);
            u.cpu_percent = f64::from(i) * 10.0;
            mon.record_sample(u);
        }
        let avg = mon.average_cpu(42).unwrap();
        assert!((avg - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_resource_monitor_history_cap() {
        let mut mon = ResourceUsageMonitor::new(3);
        for _ in 0..10 {
            mon.record_sample(ResourceUsage::new(1));
        }
        assert_eq!(mon.history_for_pid(1).unwrap().len(), 3);
    }

    #[test]
    fn test_resource_monitor_no_history() {
        let mon = ResourceUsageMonitor::new(10);
        assert!(mon.average_cpu(999).is_none());
        assert!(mon.history_for_pid(999).is_none());
    }

    #[test]
    fn test_resource_usage_total_io() {
        let mut u = ResourceUsage::new(1);
        u.disk_read_bytes = 100;
        u.disk_write_bytes = 200;
        assert_eq!(u.total_io_bytes(), 300);
    }

    #[test]
    fn test_resource_monitor_csv() {
        let mut mon = ResourceUsageMonitor::new(5);
        mon.record_sample(ResourceUsage::new(1));
        let csv = mon.to_csv();
        assert!(csv.contains("PID"));
    }

    // ── SuspicionScorer ───────────────────────────────────────────────────────

    #[test]
    fn test_suspicion_scorer_clean_system32() {
        let p = ProcessBuilder::new(4, 0, "svchost.exe")
            .exe_path("C:\\Windows\\System32\\svchost.exe")
            .build();
        let report = SuspicionScorer::score(&p);
        // Should not trigger "running outside System32"
        assert!(
            report
                .reasons
                .iter()
                .all(|r| r.category != SuspicionCategory::UnusualPath
                    || !r.description.contains("outside System32"))
        );
    }

    #[test]
    fn test_suspicion_scorer_temp_dir() {
        let p = ProcessBuilder::new(100, 0, "evil.exe")
            .exe_path("C:\\Temp\\evil.exe")
            .build();
        let report = SuspicionScorer::score(&p);
        assert!(report.score >= 20);
        assert!(
            report
                .reasons
                .iter()
                .any(|r| r.category == SuspicionCategory::UnusualPath)
        );
    }

    #[test]
    fn test_suspicion_scorer_high_cpu() {
        let p = ProcessBuilder::new(200, 1, "miner.exe")
            .exe_path("C:\\Windows\\System32\\miner.exe")
            .cpu(95.0)
            .build();
        let report = SuspicionScorer::score(&p);
        assert!(
            report
                .reasons
                .iter()
                .any(|r| r.category == SuspicionCategory::HighCpuOnDisk)
        );
    }

    #[test]
    fn test_suspicion_scorer_unsigned_module() {
        let mut p = ProcessInfo::new(300, 1, "app.exe");
        p.exe_path = "C:\\App\\app.exe".into();
        let mut m = ModuleInfo::new(0x1000, 0x1000, "bad.dll", "C:\\Temp\\bad.dll");
        m.signed = Some(false);
        p.modules.push(m);
        let report = SuspicionScorer::score(&p);
        assert!(
            report
                .reasons
                .iter()
                .any(|r| r.category == SuspicionCategory::Unsigned)
        );
    }

    #[test]
    fn test_suspicion_scorer_suspicious_name() {
        let p = ProcessBuilder::new(400, 1, "mimikatz.exe")
            .exe_path("C:\\Windows\\mimikatz.exe")
            .build();
        let report = SuspicionScorer::score(&p);
        assert!(
            report
                .reasons
                .iter()
                .any(|r| r.category == SuspicionCategory::SuspiciousName)
        );
    }

    #[test]
    fn test_suspicion_scorer_score_all() {
        let processes = vec![
            ProcessBuilder::new(1, 0, "system")
                .exe_path("C:\\Windows\\System32\\system")
                .build(),
            ProcessBuilder::new(2, 1, "evil.exe")
                .exe_path("C:\\Temp\\evil.exe")
                .build(),
        ];
        let reports = SuspicionScorer::score_all(&processes);
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn test_suspicion_filter() {
        let processes = vec![
            ProcessBuilder::new(1, 0, "clean.exe")
                .exe_path("C:\\Windows\\clean.exe")
                .build(),
            ProcessBuilder::new(2, 1, "evil.exe")
                .exe_path("C:\\Temp\\evil.exe")
                .build(),
        ];
        let reports = SuspicionScorer::score_all(&processes);
        let sus = SuspicionScorer::filter_suspicious(&reports, 15);
        assert!(!sus.is_empty());
    }

    #[test]
    fn test_suspicion_most_suspicious() {
        let mut reports = vec![
            SuspicionReport {
                pid: 1,
                process_name: "a".into(),
                score: 10,
                reasons: vec![],
            },
            SuspicionReport {
                pid: 2,
                process_name: "b".into(),
                score: 80,
                reasons: vec![],
            },
        ];
        SuspicionScorer::sort_by_score(&mut reports);
        assert_eq!(reports[0].pid, 2);
        let most = SuspicionScorer::most_suspicious(&reports).unwrap();
        assert_eq!(most.pid, 2);
    }

    #[test]
    fn test_suspicion_report_is_suspicious() {
        let r = SuspicionReport {
            pid: 1,
            process_name: "x".into(),
            score: 50,
            reasons: vec![],
        };
        assert!(r.is_suspicious());
        let r2 = SuspicionReport {
            pid: 2,
            process_name: "y".into(),
            score: 5,
            reasons: vec![],
        };
        assert!(!r2.is_suspicious());
    }

    // ── SystemInfo ────────────────────────────────────────────────────────────

    #[test]
    fn test_system_info_collect() {
        let info = SystemInfo::collect().unwrap();
        assert!(!info.os_name.is_empty());
    }

    #[test]
    fn test_system_info_memory_ratio() {
        let mut info = SystemInfo::collect().unwrap();
        info.total_memory = 16_000_000_000;
        info.available_memory = 8_000_000_000;
        let ratio = info.memory_usage_ratio();
        assert!((ratio - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_system_info_zero_memory() {
        let info = SystemInfo::collect().unwrap();
        // total_memory is 0 by default in stub
        let ratio = info.memory_usage_ratio();
        assert!(ratio.abs() < f64::EPSILON);
    }

    #[test]
    fn test_system_info_uptime_human() {
        let mut info = SystemInfo::collect().unwrap();
        info.uptime_secs = 3 * 86400 + 2 * 3600 + 30 * 60;
        assert_eq!(info.uptime_human(), "3d 2h 30m");
    }

    // ── ProcessBuilder ────────────────────────────────────────────────────────

    #[test]
    fn test_process_builder() {
        let p = ProcessBuilder::new(42, 1, "test.exe")
            .exe_path("C:\\test.exe")
            .user("user")
            .status(ProcessStatus::Running)
            .cpu(5.0)
            .rss(1024)
            .env_var("PATH", "/usr/bin")
            .add_open_file("/tmp/x")
            .build();
        assert_eq!(p.pid, 42);
        assert_eq!(p.user, "user");
        assert_eq!(p.status, ProcessStatus::Running);
        assert!((p.cpu_usage - 5.0).abs() < 0.01);
        assert_eq!(p.memory_info.rss, 1024);
        assert_eq!(p.get_env("PATH"), Some("/usr/bin"));
        assert_eq!(p.open_files.len(), 1);
    }

    // ── MemoryInfo ────────────────────────────────────────────────────────────

    #[test]
    fn test_memory_info_rss_vss_ratio() {
        let m = MemoryInfo::new(1000, 500, 600, 100, 400, 0);
        assert!((m.rss_vss_ratio() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_memory_info_zero_vss() {
        let m = MemoryInfo::default();
        assert!(m.rss_vss_ratio().abs() < f64::EPSILON);
    }

    // ── ModuleInfo ────────────────────────────────────────────────────────────

    #[test]
    fn test_module_contains_addr() {
        let m = ModuleInfo::new(0x1000, 0x1000, "test.dll", "C:\\test.dll");
        assert!(m.contains_addr(0x1000));
        assert!(m.contains_addr(0x1500));
        assert!(!m.contains_addr(0x2000));
    }

    // ── Serde ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_process_info() {
        let p = ProcessInfo::new(42, 1, "test.exe");
        let json = serde_json::to_string(&p).unwrap();
        let back: ProcessInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pid, 42);
    }

    #[test]
    fn test_serde_driver_flags() {
        let flags = DriverFlags::LOADED | DriverFlags::KERNEL_MODE;
        let json = serde_json::to_string(&flags).unwrap();
        let back: DriverFlags = serde_json::from_str(&json).unwrap();
        assert_eq!(back, flags);
    }

    #[test]
    fn test_serde_snapshot() {
        let m = make_monitor();
        let snap = m.snapshot().unwrap();
        let json = serde_json::to_string(&snap).unwrap();
        let back: SystemSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.processes.len(), snap.processes.len());
    }

    #[test]
    fn test_serde_suspicion_report() {
        let report = SuspicionReport::new(1, "evil.exe");
        let json = serde_json::to_string(&report).unwrap();
        let back: SuspicionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pid, 1);
    }

    // ── Display impls ─────────────────────────────────────────────────────────

    #[test]
    fn test_thread_state_display() {
        assert_eq!(ThreadState::Running.to_string(), "Running");
        assert_eq!(ThreadState::Waiting.to_string(), "Waiting");
        assert_eq!(ThreadState::Terminated.to_string(), "Terminated");
        assert_eq!(ThreadState::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_network_protocol_display() {
        assert_eq!(NetworkProtocol::Tcp.to_string(), "TCP");
        assert_eq!(NetworkProtocol::Udp.to_string(), "UDP");
        assert_eq!(NetworkProtocol::Tcp6.to_string(), "TCP6");
        assert_eq!(NetworkProtocol::Raw.to_string(), "RAW");
    }

    #[test]
    fn test_tcp_state_display() {
        assert_eq!(TcpState::Listen.to_string(), "LISTEN");
        assert_eq!(TcpState::Established.to_string(), "ESTABLISHED");
        assert_eq!(TcpState::TimeWait.to_string(), "TIME_WAIT");
    }

    #[test]
    fn test_registry_data_type_display() {
        assert_eq!(RegistryDataType::RegSz.to_string(), "REG_SZ");
        assert_eq!(RegistryDataType::RegDword.to_string(), "REG_DWORD");
    }

    #[test]
    fn test_process_status_display() {
        assert_eq!(ProcessStatus::Running.to_string(), "Running");
        assert_eq!(ProcessStatus::Zombie.to_string(), "Zombie");
    }

    #[test]
    fn test_autorun_category_display() {
        assert_eq!(AutorunCategory::LogonRegistry.to_string(), "Logon Registry");
        assert_eq!(AutorunCategory::Services.to_string(), "Services");
    }

    // ── Error display ─────────────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        assert_eq!(SysinternalsError::AccessDenied.to_string(), "Access denied");
        assert_eq!(SysinternalsError::Unsupported.to_string(), "Not supported");
        assert!(
            SysinternalsError::Io("disk".into())
                .to_string()
                .contains("disk")
        );
        assert!(
            SysinternalsError::ProcessNotFound(99)
                .to_string()
                .contains("99")
        );
    }

    // ── CertInfo ──────────────────────────────────────────────────────────────

    #[test]
    fn test_cert_info_valid_at() {
        let cert = CertInfo::new("CN=test", "CN=CA", "01", 1000, 2000, false);
        assert!(cert.valid_at(1500));
        assert!(!cert.valid_at(500));
        assert!(!cert.valid_at(3000));
    }

    #[test]
    fn test_signature_info_unsigned() {
        let sig = SignatureInfo::unsigned("C:\\test.exe");
        assert!(!sig.is_signed);
        assert!(!sig.is_valid);
        assert!(!sig.has_root_cert());
    }

    // ── ProcessCsvExporter ────────────────────────────────────────────────────

    #[test]
    fn test_process_csv_exporter() {
        let procs = vec![ProcessInfo::new(1, 0, "test.exe")];
        let csv = ProcessCsvExporter::export(&procs);
        assert!(csv.contains("PID"));
        assert!(csv.contains("test.exe"));
    }

    #[test]
    fn test_process_json_exporter() {
        let procs = vec![ProcessInfo::new(1, 0, "test.exe")];
        let json = ProcessJsonExporter::export(&procs).unwrap();
        assert!(json.contains("test.exe"));
    }

    // ── SuspicionReportExporter ───────────────────────────────────────────────

    #[test]
    fn test_suspicion_report_csv() {
        let reports = vec![SuspicionReport::new(1, "evil.exe")];
        let csv = SuspicionReportExporter::to_csv(&reports);
        assert!(csv.contains("evil.exe"));
    }

    #[test]
    fn test_suspicion_report_json() {
        let reports = vec![SuspicionReport::new(1, "evil.exe")];
        let json = SuspicionReportExporter::to_json(&reports).unwrap();
        assert!(json.contains("evil.exe"));
    }

    // ── DriverFlags bitwise ───────────────────────────────────────────────────

    #[test]
    fn test_driver_flags_none() {
        let f = DriverFlags::NONE;
        assert!(!f.contains(DriverFlags::LOADED));
    }

    #[test]
    fn test_driver_flags_union() {
        let f = DriverFlags::LOADED | DriverFlags::UNLOADABLE;
        assert!(f.contains(DriverFlags::LOADED));
        assert!(!f.contains(DriverFlags::FS_FILTER));
    }

    // ── InMemorySystemMonitor default ─────────────────────────────────────────

    #[test]
    fn test_in_memory_monitor_default_empty() {
        let m = InMemorySystemMonitor::default();
        assert!(m.list_processes().unwrap().is_empty());
    }

    // ── RegistryValue ─────────────────────────────────────────────────────────

    #[test]
    fn test_registry_value_new() {
        let rv = RegistryValue::new(
            "HKLM",
            "SOFTWARE\\Test",
            "Key",
            RegistryDataType::RegSz,
            b"value\0".to_vec(),
        );
        assert_eq!(rv.hive, "HKLM");
        assert_eq!(rv.data_type, RegistryDataType::RegSz);
    }

    // ── AutorunCsvExporter ────────────────────────────────────────────────────

    #[test]
    fn test_autorun_csv_exporter() {
        let entries = vec![AutorunEntry::new(
            AutorunCategory::LogonRegistry,
            "HKLM\\Run",
            "test",
            "C:\\test.exe",
            "test.exe",
        )];
        let csv = AutorunCsvExporter::export(&entries);
        assert!(csv.contains("Category"));
        assert!(csv.contains("test"));
    }

    // ── NetworkConnection CSV ─────────────────────────────────────────────────

    #[test]
    fn test_network_connection_csv() {
        let c = NetworkConnection::new_tcp(
            1,
            "p",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            80,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            TcpState::Established,
        );
        let row = c.to_csv_row();
        assert!(row.contains("80"));
    }

    #[test]
    fn test_network_connection_total_bytes() {
        let mut c = NetworkConnection::new_tcp(
            1,
            "p",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            80,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            TcpState::Established,
        );
        c.bytes_sent = 100;
        c.bytes_recv = 200;
        assert_eq!(c.bytes_sent + c.bytes_recv, 300);
    }
}

// ─── HollowingIndicator ───────────────────────────────────────────────────────

/// A single process-hollowing indicator produced by [`ProcessHollowingDetector`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HollowingIndicator {
    /// Virtual address of the suspicious region (0 if address-independent).
    pub address: u64,
    /// Human-readable description of the indicator.
    pub description: String,
    /// Confidence score in `[0.0, 1.0]`.
    pub confidence: f32,
}

impl HollowingIndicator {
    /// Construct a new indicator.
    #[must_use]
    pub fn new(address: u64, description: impl Into<String>, confidence: f32) -> Self {
        Self {
            address,
            description: description.into(),
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

// ─── ProcessHollowingDetector ─────────────────────────────────────────────────

/// Pure-data, platform-agnostic process-hollowing detector.
///
/// Since this crate makes no OS calls, `detect` operates over a
/// [`ProcessInfo`] value (with its `modules` list) rather than a live PID.
/// For live detection, populate a `ProcessInfo` via your platform-specific
/// introspection layer, then call [`ProcessHollowingDetector::detect_from_info`].
///
/// The `detect(pid)` entry point always returns an empty `Vec` — it exists for
/// API compatibility with callers that supply a PID and expect the detector to
/// be wired to a real implementation at a higher layer.
pub struct ProcessHollowingDetector;

impl ProcessHollowingDetector {
    /// Stub: returns an empty indicator list.
    ///
    /// In a live system this would enumerate the process's virtual-address
    /// ranges and apply the heuristics below.  Platform implementors should
    /// override by calling [`detect_from_info`] with a populated `ProcessInfo`.
    #[must_use]
    pub const fn detect(_pid: u32) -> Vec<HollowingIndicator> {
        Vec::new()
    }

    /// Analyse a [`ProcessInfo`] snapshot for process-hollowing indicators.
    ///
    /// Heuristics applied (all pure-data, no OS calls):
    ///
    /// 1. **Low-entropy executable section** — a module whose image size is
    ///    non-zero but whose name is empty is flagged (genuine loaded DLLs
    ///    always have a name in the snapshot).
    /// 2. **Mismatched PE checksum** — if the module's `hash_sha256` field is
    ///    set to the sentinel value `"00000000"` (8 zeros) we flag it as a
    ///    possible checksum-zeroed image.
    /// 3. **Module mapped outside known range** — a module whose base address
    ///    is below 0x1000 or whose name contains suspicious path fragments
    ///    (`\temp\`, `\appdata\`) is flagged.
    /// 4. **Mismatched 64-bit flag** — modules marked `is_64bit = false` inside
    ///    a process that carries any 64-bit module are flagged as suspicious
    ///    cross-architecture injections.
    #[must_use]
    pub fn detect_from_info(info: &ProcessInfo) -> Vec<HollowingIndicator> {
        let mut indicators = Vec::new();

        let has_64bit = info.modules.iter().any(|m| m.is_64bit);

        for module in &info.modules {
            // Indicator 1: empty module name with non-zero size.
            if module.name.is_empty() && module.size > 0 {
                indicators.push(HollowingIndicator::new(
                    module.base,
                    "Executable section with no mapped module name (low-entropy / suspicious page)",
                    0.75,
                ));
            }

            // Indicator 2: PE checksum zeroed (sentinel hash value).
            if module.hash_sha256.as_deref() == Some("00000000") {
                indicators.push(HollowingIndicator::new(
                    module.base,
                    format!(
                        "Module '{}' has zeroed checksum sentinel — possible PE patching",
                        module.name
                    ),
                    0.65,
                ));
            }

            // Indicator 3: module mapped at suspicious address or path.
            if module.base < 0x1000 && module.size > 0 {
                indicators.push(HollowingIndicator::new(
                    module.base,
                    "Module mapped at near-zero base address — injected page not backed by any image",
                    0.90,
                ));
            }
            let path_lc = module.path.to_lowercase();
            if path_lc.contains("\\temp\\") || path_lc.contains("\\appdata\\") {
                indicators.push(HollowingIndicator::new(
                    module.base,
                    format!(
                        "Module '{}' loaded from suspicious path: {}",
                        module.name, module.path
                    ),
                    0.80,
                ));
            }

            // Indicator 4: 32-bit module inside 64-bit process.
            if has_64bit && !module.is_64bit && !module.name.is_empty() {
                indicators.push(HollowingIndicator::new(
                    module.base,
                    format!("32-bit module '{}' loaded in 64-bit process — possible cross-arch injection", module.name),
                    0.70,
                ));
            }
        }

        // Indicator for remote thread: check if thread start addresses fall
        // outside any known module range.
        for thread in &info.threads {
            let covered = info
                .modules
                .iter()
                .any(|m| m.contains_addr(thread.start_address));
            if !covered && thread.start_address > 0x1000 {
                indicators.push(HollowingIndicator::new(
                    thread.start_address,
                    format!("Thread {} starts at {:#x} which is not mapped to any known module — possible remote thread", thread.tid, thread.start_address),
                    0.85,
                ));
            }
        }

        indicators
    }
}

// ─── ApiSnapshot ─────────────────────────────────────────────────────────────

/// A snapshot of ntdll API hook state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiSnapshot {
    /// Pairs of `(api_name, is_hooked)`.
    pub ntdll_hooks: Vec<(String, bool)>,
}

impl ApiSnapshot {
    /// Create an empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the number of APIs currently flagged as hooked.
    #[must_use]
    pub fn hooked_count(&self) -> usize {
        self.ntdll_hooks.iter().filter(|(_, h)| *h).count()
    }

    /// Return the total number of APIs in the snapshot.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.ntdll_hooks.len()
    }
}

// ─── NewHook ──────────────────────────────────────────────────────────────────

/// A hook that appeared in `after` but was absent (or unhooked) in `before`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewHook {
    /// Name of the API function that is now hooked.
    pub api_name: String,
}

// ─── SysinternalsApiSnapshot ──────────────────────────────────────────────────

/// Captures and compares ntdll API hook state.
///
/// As a pure-data crate, the actual hook detection (byte-level prologue scan)
/// must be supplied by the platform layer.  The snapshot helper here provides
/// the data types and diff logic.
pub struct SysinternalsApiSnapshot;

impl SysinternalsApiSnapshot {
    /// Create an empty snapshot suitable for testing or as a pre-instrumentation
    /// baseline.
    ///
    /// In a live system, populate `ntdll_hooks` by scanning each ntdll export's
    /// first bytes for a JMP/CALL to a different module.
    #[must_use]
    pub fn snapshot_hooks() -> ApiSnapshot {
        ApiSnapshot::new()
    }

    /// Create a snapshot from an explicit list of `(api_name, is_hooked)` pairs.
    #[must_use]
    pub fn from_pairs(pairs: Vec<(impl Into<String>, bool)>) -> ApiSnapshot {
        ApiSnapshot {
            ntdll_hooks: pairs.into_iter().map(|(n, h)| (n.into(), h)).collect(),
        }
    }

    /// Compute the diff between two snapshots.
    ///
    /// Returns every API that transitioned from unhooked (or absent) in
    /// `before` to hooked in `after`.
    #[must_use]
    pub fn diff(before: &ApiSnapshot, after: &ApiSnapshot) -> Vec<NewHook> {
        // Build a lookup of `before` hook state.
        let before_map: HashMap<&str, bool> = before
            .ntdll_hooks
            .iter()
            .map(|(name, hooked)| (name.as_str(), *hooked))
            .collect();

        after
            .ntdll_hooks
            .iter()
            .filter(|(name, after_hooked)| {
                *after_hooked && !before_map.get(name.as_str()).copied().unwrap_or(false)
            })
            .map(|(name, _)| NewHook {
                api_name: name.clone(),
            })
            .collect()
    }
}

// ─── Tests for ProcessHollowingDetector and SysinternalsApiSnapshot ────────────

#[cfg(test)]
mod hollowing_and_snapshot_tests {
    use super::*;

    fn make_process(pid: u32) -> ProcessInfo {
        ProcessInfo::new(pid, 0, "test.exe")
    }

    fn make_module(base: u64, size: u64, name: &str, path: &str) -> ModuleInfo {
        ModuleInfo::new(base, size, name, path)
    }

    // ── ProcessHollowingDetector tests ────────────────────────────────────────

    #[test]
    fn test_detect_stub_returns_empty() {
        let result = ProcessHollowingDetector::detect(1234);
        assert!(result.is_empty());
    }

    #[test]
    fn test_detect_clean_process_no_indicators() {
        let mut p = make_process(100);
        p.modules
            .push(make_module(0x0040_0000, 0x10000, "app.exe", "C:\\app.exe"));
        let indicators = ProcessHollowingDetector::detect_from_info(&p);
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_detect_empty_name_module_flagged() {
        let mut p = make_process(200);
        let mut m = make_module(0x7F00_0000, 0x1000, "", "");
        m.name = String::new();
        p.modules.push(m);
        let indicators = ProcessHollowingDetector::detect_from_info(&p);
        assert!(!indicators.is_empty());
        assert!(indicators.iter().any(|i| i.address == 0x7F00_0000));
    }

    #[test]
    fn test_detect_near_zero_base() {
        let mut p = make_process(300);
        p.modules
            .push(make_module(0x100, 0x1000, "injected", "C:\\injected.dll"));
        let indicators = ProcessHollowingDetector::detect_from_info(&p);
        assert!(indicators.iter().any(|i| i.confidence >= 0.85));
    }

    #[test]
    fn test_detect_temp_path_flagged() {
        let mut p = make_process(400);
        p.modules.push(make_module(
            0x0050_0000,
            0x2000,
            "evil",
            "C:\\Users\\user\\AppData\\evil.dll",
        ));
        let indicators = ProcessHollowingDetector::detect_from_info(&p);
        assert!(
            indicators
                .iter()
                .any(|i| i.description.contains("suspicious path"))
        );
    }

    #[test]
    fn test_detect_remote_thread_flagged() {
        let mut p = make_process(500);
        p.modules
            .push(make_module(0x0040_0000, 0x10000, "app.exe", "C:\\app.exe"));
        let thread = ThreadInfo::new(1, 500, 0x7FFF_0000, 0, crate::ThreadState::Running);
        p.threads.push(thread);
        let indicators = ProcessHollowingDetector::detect_from_info(&p);
        assert!(
            indicators
                .iter()
                .any(|i| i.description.contains("remote thread"))
        );
    }

    #[test]
    fn test_detect_thread_inside_module_not_flagged() {
        let mut p = make_process(600);
        p.modules
            .push(make_module(0x0040_0000, 0x10000, "app.exe", "C:\\app.exe"));
        // Thread start is inside the module range.
        let thread = ThreadInfo::new(2, 600, 0x0040_1000, 0, crate::ThreadState::Running);
        p.threads.push(thread);
        let indicators = ProcessHollowingDetector::detect_from_info(&p);
        // The only possible indicator is remote thread; it should NOT fire here.
        assert!(
            !indicators
                .iter()
                .any(|i| i.description.contains("remote thread"))
        );
    }

    #[test]
    fn test_hollowing_indicator_confidence_clamped() {
        let ind = HollowingIndicator::new(0, "test", 2.5);
        assert!(ind.confidence <= 1.0);
        let ind2 = HollowingIndicator::new(0, "test", -1.0);
        assert!(ind2.confidence >= 0.0);
    }

    // ── SysinternalsApiSnapshot tests ─────────────────────────────────────────

    #[test]
    fn test_snapshot_hooks_empty() {
        let snap = SysinternalsApiSnapshot::snapshot_hooks();
        assert!(snap.ntdll_hooks.is_empty());
    }

    #[test]
    fn test_diff_detects_new_hook() {
        let before = SysinternalsApiSnapshot::from_pairs(vec![
            ("NtOpenProcess", false),
            ("NtReadVirtualMemory", false),
        ]);
        let after = SysinternalsApiSnapshot::from_pairs(vec![
            ("NtOpenProcess", true),
            ("NtReadVirtualMemory", false),
        ]);
        let diff = SysinternalsApiSnapshot::diff(&before, &after);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].api_name, "NtOpenProcess");
    }

    #[test]
    fn test_diff_no_change() {
        let snap = SysinternalsApiSnapshot::from_pairs(vec![("NtCreateThread", false)]);
        let diff = SysinternalsApiSnapshot::diff(&snap, &snap);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_diff_new_api_in_after() {
        let before = SysinternalsApiSnapshot::from_pairs(vec![("NtQuerySystemInformation", false)]);
        let after = SysinternalsApiSnapshot::from_pairs(vec![
            ("NtQuerySystemInformation", false),
            ("NtWriteVirtualMemory", true),
        ]);
        let diff = SysinternalsApiSnapshot::diff(&before, &after);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].api_name, "NtWriteVirtualMemory");
    }

    #[test]
    fn test_api_snapshot_hooked_count() {
        let snap =
            SysinternalsApiSnapshot::from_pairs(vec![("A", true), ("B", false), ("C", true)]);
        assert_eq!(snap.hooked_count(), 2);
        assert_eq!(snap.total(), 3);
    }

    #[test]
    fn test_api_snapshot_default_empty() {
        let snap = ApiSnapshot::default();
        assert_eq!(snap.hooked_count(), 0);
        assert_eq!(snap.total(), 0);
    }

    #[test]
    fn test_diff_empty_before_and_after() {
        let b = ApiSnapshot::new();
        let a = ApiSnapshot::new();
        assert!(SysinternalsApiSnapshot::diff(&b, &a).is_empty());
    }
}
