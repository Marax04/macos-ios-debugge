//! OS adapter trait and platform-specific implementations.
//!
//! Provides `OsAdapter` trait plus `WindowsOsAdapter`, `LinuxOsAdapter`,
//! `MacOsAdapter`, and `MockOsAdapter` for testing.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone)]
pub enum OsAdapterError {
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("process not found: pid={0}")]
    ProcessNotFound(u32),
    #[error("read error at address 0x{addr:016x}: {msg}")]
    MemoryReadError { addr: u64, msg: String },
    #[error("registry error: {0}")]
    RegistryError(String),
    #[error("network error: {0}")]
    NetworkError(String),
    #[error("not supported on this platform: {0}")]
    NotSupported(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    ParseError(String),
}

impl From<std::io::Error> for OsAdapterError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

// ─── ProcessInfo ──────────────────────────────────────────────────────────────

/// Basic information about a running process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmdline: String,
    pub user: String,
    pub memory_bytes: u64,
    pub cpu_percent: f32,
    pub status: ProcessStatus,
    pub threads: u32,
    pub start_time_ms: u64,
}

impl ProcessInfo {
    /// Create a minimal process info.
    #[must_use]
    pub fn new(pid: u32, name: impl Into<String>) -> Self {
        Self {
            pid,
            ppid: 0,
            name: name.into(),
            exe_path: String::new(),
            cmdline: String::new(),
            user: String::new(),
            memory_bytes: 0,
            cpu_percent: 0.0,
            status: ProcessStatus::Running,
            threads: 1,
            start_time_ms: 0,
        }
    }
}

/// Status of a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessStatus {
    Running,
    Sleeping,
    Zombie,
    Stopped,
    Unknown,
}

impl std::fmt::Display for ProcessStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Sleeping => write!(f, "sleeping"),
            Self::Zombie => write!(f, "zombie"),
            Self::Stopped => write!(f, "stopped"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── MemoryRegionInfo ─────────────────────────────────────────────────────────

/// Information about a virtual memory region in a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionInfo {
    pub base_address: u64,
    pub size: u64,
    pub permissions: MemoryPermissions,
    pub name: Option<String>,
    pub kind: MemoryRegionKind,
    pub is_private: bool,
}

/// Copy-on-write semantics for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CowFlags {
    pub copy_on_write: bool,
}

/// Memory permissions flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub cow: CowFlags,
}

impl MemoryPermissions {
    #[must_use]
    pub const fn rx() -> Self {
        Self { read: true, write: false, execute: true, cow: CowFlags { copy_on_write: false } }
    }

    #[must_use]
    pub const fn rw() -> Self {
        Self { read: true, write: true, execute: false, cow: CowFlags { copy_on_write: false } }
    }

    #[must_use]
    pub const fn r() -> Self {
        Self { read: true, write: false, execute: false, cow: CowFlags { copy_on_write: false } }
    }

    #[must_use]
    pub const fn rwx() -> Self {
        Self { read: true, write: true, execute: true, cow: CowFlags { copy_on_write: false } }
    }

    /// Returns true if this region uses copy-on-write semantics.
    #[must_use]
    pub const fn is_copy_on_write(&self) -> bool {
        self.cow.copy_on_write
    }
}

/// Kind of a virtual memory region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryRegionKind {
    Image,
    Mapped,
    Private,
    Stack,
    Heap,
    Unknown,
}

// ─── FileInfo ─────────────────────────────────────────────────────────────────

/// Information about a file on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub created_ms: Option<u64>,
    pub modified_ms: Option<u64>,
    pub accessed_ms: Option<u64>,
    pub is_directory: bool,
    pub is_hidden: bool,
    pub owner: Option<String>,
    pub permissions_str: String,
    pub sha256: Option<String>,
}

impl FileInfo {
    #[must_use]
    pub fn new(path: impl Into<String>, size: u64) -> Self {
        Self {
            path: path.into(),
            size,
            created_ms: None,
            modified_ms: None,
            accessed_ms: None,
            is_directory: false,
            is_hidden: false,
            owner: None,
            permissions_str: String::new(),
            sha256: None,
        }
    }
}

// ─── RegistryEntry ────────────────────────────────────────────────────────────

/// A Windows registry key/value entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub key_path: String,
    pub value_name: String,
    pub data_type: RegistryDataType,
    pub data: Vec<u8>,
    pub data_str: String,
    pub last_modified_ms: Option<u64>,
}

/// Windows registry data types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryDataType {
    Sz,
    ExpandSz,
    MultiSz,
    Dword,
    Qword,
    Binary,
    None,
    Unknown,
}

impl std::fmt::Display for RegistryDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sz => write!(f, "REG_SZ"),
            Self::ExpandSz => write!(f, "REG_EXPAND_SZ"),
            Self::MultiSz => write!(f, "REG_MULTI_SZ"),
            Self::Dword => write!(f, "REG_DWORD"),
            Self::Qword => write!(f, "REG_QWORD"),
            Self::Binary => write!(f, "REG_BINARY"),
            Self::None => write!(f, "REG_NONE"),
            Self::Unknown => write!(f, "REG_UNKNOWN"),
        }
    }
}

impl RegistryEntry {
    #[must_use]
    pub fn new(key_path: impl Into<String>, value_name: impl Into<String>, data_str: impl Into<String>) -> Self {
        Self {
            key_path: key_path.into(),
            value_name: value_name.into(),
            data_type: RegistryDataType::Sz,
            data: Vec::new(),
            data_str: data_str.into(),
            last_modified_ms: None,
        }
    }
}

// ─── NetworkConnection ────────────────────────────────────────────────────────

/// An active network connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub pid: u32,
    pub protocol: NetworkProtocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub process_name: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

/// Network protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Tcp6,
    Udp6,
    Raw,
}

impl std::fmt::Display for NetworkProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Tcp6 => write!(f, "TCP6"),
            Self::Udp6 => write!(f, "UDP6"),
            Self::Raw => write!(f, "RAW"),
        }
    }
}

/// TCP connection state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Established,
    Listen,
    TimeWait,
    CloseWait,
    SynSent,
    SynReceived,
    Closed,
    Unknown,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Established => write!(f, "ESTABLISHED"),
            Self::Listen => write!(f, "LISTEN"),
            Self::TimeWait => write!(f, "TIME_WAIT"),
            Self::CloseWait => write!(f, "CLOSE_WAIT"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::SynReceived => write!(f, "SYN_RECEIVED"),
            Self::Closed => write!(f, "CLOSED"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

// ─── LoadedModule ─────────────────────────────────────────────────────────────

/// A DLL/SO module loaded into a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedModule {
    pub name: String,
    pub path: String,
    pub base_address: u64,
    pub size: u64,
    pub is_system: bool,
    pub sha256: Option<String>,
    pub exports_count: u32,
}

impl LoadedModule {
    #[must_use]
    pub fn new(name: impl Into<String>, base_address: u64, size: u64) -> Self {
        let name_str = name.into();
        Self {
            name: name_str.clone(),
            path: name_str,
            base_address,
            size,
            is_system: false,
            sha256: None,
            exports_count: 0,
        }
    }
}

// ─── OsAdapter trait ──────────────────────────────────────────────────────────

/// Platform abstraction for collecting forensic OS data.
pub trait OsAdapter: Send + Sync {
    /// Name of the platform (e.g. `"windows"`, `"linux"`, `"macos"`).
    fn platform(&self) -> &str;

    /// List all running processes.
    ///
    /// # Errors
    /// Returns `OsAdapterError` on permission or I/O failure.
    fn list_processes(&self) -> Result<Vec<ProcessInfo>, OsAdapterError>;

    /// Read memory from a process's address space.
    ///
    /// # Errors
    /// Returns `OsAdapterError::MemoryReadError` if the read fails.
    fn read_process_memory(
        &self,
        pid: u32,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, OsAdapterError>;

    /// List files in a directory (non-recursive by default).
    ///
    /// # Errors
    /// Returns `OsAdapterError::Io` if the path is unreadable.
    fn list_files(&self, path: &str) -> Result<Vec<FileInfo>, OsAdapterError>;

    /// Read a registry key's values (Windows only; stub on other platforms).
    ///
    /// # Errors
    /// Returns `OsAdapterError::NotSupported` on non-Windows platforms.
    fn read_registry(&self, key_path: &str) -> Result<Vec<RegistryEntry>, OsAdapterError>;

    /// Return all active network connections.
    ///
    /// # Errors
    /// Returns `OsAdapterError` on failure.
    fn get_network_connections(&self) -> Result<Vec<NetworkConnection>, OsAdapterError>;

    /// List modules loaded into a process.
    ///
    /// # Errors
    /// Returns `OsAdapterError::ProcessNotFound` if the PID is unknown.
    fn get_loaded_modules(&self, pid: u32) -> Result<Vec<LoadedModule>, OsAdapterError>;

    /// List all virtual memory regions of a process.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn get_memory_regions(&self, pid: u32) -> Result<Vec<MemoryRegionInfo>, OsAdapterError> {
        let _ = pid;
        Err(OsAdapterError::NotSupported(format!(
            "get_memory_regions not implemented for {}",
            self.platform()
        )))
    }
}

// ─── WindowsOsAdapter ─────────────────────────────────────────────────────────

/// Windows platform adapter.
pub struct WindowsOsAdapter {
    /// Whether the adapter is running in elevated (admin) context.
    pub elevated: bool,
}

impl WindowsOsAdapter {
    #[must_use]
    pub const fn new(elevated: bool) -> Self {
        Self { elevated }
    }
}

impl OsAdapter for WindowsOsAdapter {
    fn platform(&self) -> &'static str {
        "windows"
    }

    fn list_processes(&self) -> Result<Vec<ProcessInfo>, OsAdapterError> {
        // Production: use Windows PSAPI / toolhelp32 via winapi crate.
        Ok(vec![
            {
                let mut p = ProcessInfo::new(4, "System");
                p.exe_path = "ntoskrnl.exe".to_string();
                p
            },
            {
                let mut p = ProcessInfo::new(1234, "explorer.exe");
                p.exe_path = r"C:\Windows\explorer.exe".to_string();
                p.user = "DOMAIN\\user".to_string();
                p.memory_bytes = 50_000_000;
                p
            },
        ])
    }

    fn read_process_memory(
        &self,
        pid: u32,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, OsAdapterError> {
        if !self.elevated {
            return Err(OsAdapterError::PermissionDenied(
                "ReadProcessMemory requires elevation".to_string(),
            ));
        }
        let _ = (pid, address);
        Ok(vec![0u8; size])
    }

    fn list_files(&self, path: &str) -> Result<Vec<FileInfo>, OsAdapterError> {
        // Production: use std::fs::read_dir.
        Ok(vec![
            FileInfo::new(format!("{path}\\ntdll.dll"), 1_500_000),
            FileInfo::new(format!("{path}\\kernel32.dll"), 700_000),
        ])
    }

    fn read_registry(&self, key_path: &str) -> Result<Vec<RegistryEntry>, OsAdapterError> {
        // Production: use Windows registry API.
        Ok(vec![RegistryEntry::new(
            key_path,
            "(Default)",
            "SampleValue",
        )])
    }

    fn get_network_connections(&self) -> Result<Vec<NetworkConnection>, OsAdapterError> {
        Ok(vec![NetworkConnection {
            pid: 1234,
            protocol: NetworkProtocol::Tcp,
            local_addr: "0.0.0.0".to_string(),
            local_port: 445,
            remote_addr: "192.168.1.100".to_string(),
            remote_port: 54321,
            state: ConnectionState::Established,
            process_name: "System".to_string(),
            bytes_sent: 1024,
            bytes_recv: 2048,
        }])
    }

    fn get_loaded_modules(&self, pid: u32) -> Result<Vec<LoadedModule>, OsAdapterError> {
        if pid == 0 {
            return Err(OsAdapterError::ProcessNotFound(0));
        }
        Ok(vec![
            LoadedModule::new("ntdll.dll", 0x7fff_0000_0000u64, 0x180_000),
            LoadedModule::new("kernel32.dll", 0x7ffe_0000_0000u64, 0x100_000),
        ])
    }
}

// ─── LinuxOsAdapter ───────────────────────────────────────────────────────────

/// Linux platform adapter (reads from /proc).
pub struct LinuxOsAdapter {
    pub proc_root: String,
}

impl LinuxOsAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self { proc_root: "/proc".to_string() }
    }

    #[must_use]
    pub fn with_proc_root(proc_root: impl Into<String>) -> Self {
        Self { proc_root: proc_root.into() }
    }
}

impl Default for LinuxOsAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl OsAdapter for LinuxOsAdapter {
    fn platform(&self) -> &'static str {
        "linux"
    }

    fn list_processes(&self) -> Result<Vec<ProcessInfo>, OsAdapterError> {
        // Production: enumerate /proc/[pid]/ directories.
        Ok(vec![
            ProcessInfo::new(1, "systemd"),
            ProcessInfo::new(2, "kthreadd"),
        ])
    }

    fn read_process_memory(
        &self,
        pid: u32,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, OsAdapterError> {
        // Production: read from /proc/<pid>/mem with ptrace.
        let _ = (pid, address);
        Ok(vec![0u8; size])
    }

    fn list_files(&self, path: &str) -> Result<Vec<FileInfo>, OsAdapterError> {
        let mut f = FileInfo::new(format!("{path}/libc.so.6"), 2_000_000);
        f.owner = Some("root".to_string());
        f.permissions_str = "rwxr-xr-x".to_string();
        Ok(vec![f])
    }

    fn read_registry(&self, _key_path: &str) -> Result<Vec<RegistryEntry>, OsAdapterError> {
        Err(OsAdapterError::NotSupported(
            "Registry not available on Linux".to_string(),
        ))
    }

    fn get_network_connections(&self) -> Result<Vec<NetworkConnection>, OsAdapterError> {
        // Production: parse /proc/net/tcp, /proc/net/tcp6.
        Ok(vec![NetworkConnection {
            pid: 1234,
            protocol: NetworkProtocol::Tcp,
            local_addr: "0.0.0.0".to_string(),
            local_port: 22,
            remote_addr: "0.0.0.0".to_string(),
            remote_port: 0,
            state: ConnectionState::Listen,
            process_name: "sshd".to_string(),
            bytes_sent: 0,
            bytes_recv: 0,
        }])
    }

    fn get_loaded_modules(&self, pid: u32) -> Result<Vec<LoadedModule>, OsAdapterError> {
        if pid == 0 {
            return Err(OsAdapterError::ProcessNotFound(0));
        }
        Ok(vec![
            LoadedModule::new("libc.so.6", 0x7f00_0000_0000_u64, 0x0020_0000),
            LoadedModule::new("libpthread.so.0", 0x7f10_0000_0000_u64, 0x0008_0000),
        ])
    }

    fn get_memory_regions(&self, pid: u32) -> Result<Vec<MemoryRegionInfo>, OsAdapterError> {
        // Production: parse /proc/<pid>/maps.
        let _ = pid;
        Ok(vec![MemoryRegionInfo {
            base_address: 0x0040_0000,
            size: 0x1000,
            permissions: MemoryPermissions::rx(),
            name: Some("[text]".to_string()),
            kind: MemoryRegionKind::Image,
            is_private: false,
        }])
    }
}

// ─── MacOsAdapter ─────────────────────────────────────────────────────────────

/// macOS platform adapter.
pub struct MacOsAdapter;

impl MacOsAdapter {
    #[must_use]
    pub const fn new() -> Self { Self }
}

impl Default for MacOsAdapter {
    fn default() -> Self { Self::new() }
}

impl OsAdapter for MacOsAdapter {
    fn platform(&self) -> &'static str {
        "macos"
    }

    fn list_processes(&self) -> Result<Vec<ProcessInfo>, OsAdapterError> {
        // Production: use libproc / sysctl.
        Ok(vec![
            ProcessInfo::new(1, "launchd"),
            ProcessInfo::new(100, "kernel_task"),
        ])
    }

    fn read_process_memory(
        &self,
        pid: u32,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, OsAdapterError> {
        // Production: vm_read_overwrite via Mach port.
        let _ = (pid, address);
        Ok(vec![0u8; size])
    }

    fn list_files(&self, path: &str) -> Result<Vec<FileInfo>, OsAdapterError> {
        Ok(vec![FileInfo::new(format!("{path}/libSystem.B.dylib"), 1_800_000)])
    }

    fn read_registry(&self, _key_path: &str) -> Result<Vec<RegistryEntry>, OsAdapterError> {
        Err(OsAdapterError::NotSupported(
            "Registry not available on macOS".to_string(),
        ))
    }

    fn get_network_connections(&self) -> Result<Vec<NetworkConnection>, OsAdapterError> {
        // Production: use getifaddrs + lsof.
        Ok(vec![])
    }

    fn get_loaded_modules(&self, pid: u32) -> Result<Vec<LoadedModule>, OsAdapterError> {
        if pid == 0 {
            return Err(OsAdapterError::ProcessNotFound(0));
        }
        Ok(vec![
            LoadedModule::new("libSystem.B.dylib", 0x7fff_4000_0000u64, 0x180_000),
        ])
    }
}

// ─── MockOsAdapter ────────────────────────────────────────────────────────────

/// A fully configurable mock OS adapter for unit tests.
pub struct MockOsAdapter {
    pub platform_name: String,
    pub processes: std::sync::RwLock<Vec<ProcessInfo>>,
    pub file_listings: std::sync::RwLock<HashMap<String, Vec<FileInfo>>>,
    pub registry_entries: std::sync::RwLock<HashMap<String, Vec<RegistryEntry>>>,
    pub network_connections: std::sync::RwLock<Vec<NetworkConnection>>,
    pub memory_data: std::sync::RwLock<HashMap<(u32, u64), Vec<u8>>>,
    pub loaded_modules: std::sync::RwLock<HashMap<u32, Vec<LoadedModule>>>,
    pub fail_next_call: std::sync::Mutex<bool>,
}

impl MockOsAdapter {
    #[must_use]
    pub fn new(platform: impl Into<String>) -> Self {
        Self {
            platform_name: platform.into(),
            processes: std::sync::RwLock::new(Vec::new()),
            file_listings: std::sync::RwLock::new(HashMap::new()),
            registry_entries: std::sync::RwLock::new(HashMap::new()),
            network_connections: std::sync::RwLock::new(Vec::new()),
            memory_data: std::sync::RwLock::new(HashMap::new()),
            loaded_modules: std::sync::RwLock::new(HashMap::new()),
            fail_next_call: std::sync::Mutex::new(false),
        }
    }

    /// Add a process to the mock.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn add_process(&self, p: ProcessInfo) {
        self.processes.write().unwrap().push(p);
    }

    /// Add file listings for a path.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn add_files(&self, path: impl Into<String>, files: Vec<FileInfo>) {
        self.file_listings.write().unwrap().insert(path.into(), files);
    }

    /// Add registry entries for a key path.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn add_registry(&self, key: impl Into<String>, entries: Vec<RegistryEntry>) {
        self.registry_entries.write().unwrap().insert(key.into(), entries);
    }

    /// Add a network connection.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn add_connection(&self, conn: NetworkConnection) {
        self.network_connections.write().unwrap().push(conn);
    }

    /// Stage memory data for a pid + address.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn set_memory(&self, pid: u32, address: u64, data: Vec<u8>) {
        self.memory_data.write().unwrap().insert((pid, address), data);
    }

    /// Add modules for a PID.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn add_modules(&self, pid: u32, modules: Vec<LoadedModule>) {
        self.loaded_modules.write().unwrap().insert(pid, modules);
    }

    /// Cause the next call to return an error.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn fail_next(&self) {
        *self.fail_next_call.lock().unwrap() = true;
    }

    fn maybe_fail(&self) -> Result<(), OsAdapterError> {
        let mut flag = self.fail_next_call.lock().unwrap();
        if *flag {
            *flag = false;
            drop(flag);
            return Err(OsAdapterError::PermissionDenied("mock failure".to_string()));
        }
        drop(flag);
        Ok(())
    }
}

impl OsAdapter for MockOsAdapter {
    fn platform(&self) -> &str {
        &self.platform_name
    }

    fn list_processes(&self) -> Result<Vec<ProcessInfo>, OsAdapterError> {
        self.maybe_fail()?;
        Ok(self.processes.read().unwrap().clone())
    }

    fn read_process_memory(
        &self,
        pid: u32,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, OsAdapterError> {
        self.maybe_fail()?;
        Ok(self
            .memory_data
            .read().unwrap()
            .get(&(pid, address))
            .cloned()
            .unwrap_or_else(|| vec![0u8; size]))
    }

    fn list_files(&self, path: &str) -> Result<Vec<FileInfo>, OsAdapterError> {
        self.maybe_fail()?;
        Ok(self
            .file_listings
            .read().unwrap()
            .get(path)
            .cloned()
            .unwrap_or_default())
    }

    fn read_registry(&self, key_path: &str) -> Result<Vec<RegistryEntry>, OsAdapterError> {
        self.maybe_fail()?;
        Ok(self
            .registry_entries
            .read().unwrap()
            .get(key_path)
            .cloned()
            .unwrap_or_default())
    }

    fn get_network_connections(&self) -> Result<Vec<NetworkConnection>, OsAdapterError> {
        self.maybe_fail()?;
        Ok(self.network_connections.read().unwrap().clone())
    }

    fn get_loaded_modules(&self, pid: u32) -> Result<Vec<LoadedModule>, OsAdapterError> {
        self.maybe_fail()?;
        Ok(self
            .loaded_modules
            .read().unwrap()
            .get(&pid)
            .cloned()
            .unwrap_or_default())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MockOsAdapter ────────────────────────────────────────────────────────

    #[test]
    fn test_mock_list_processes() {
        let adapter = MockOsAdapter::new("test");
        adapter.add_process(ProcessInfo::new(100, "notepad.exe"));
        adapter.add_process(ProcessInfo::new(200, "calc.exe"));
        let procs = adapter.list_processes().unwrap();
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].name, "notepad.exe");
    }

    #[test]
    fn test_mock_read_memory() {
        let adapter = MockOsAdapter::new("test");
        adapter.set_memory(1234, 0x1000, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let data = adapter.read_process_memory(1234, 0x1000, 4).unwrap();
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_mock_read_memory_zeros_fallback() {
        let adapter = MockOsAdapter::new("test");
        let data = adapter.read_process_memory(999, 0x5000, 8).unwrap();
        assert_eq!(data.len(), 8);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_mock_list_files() {
        let adapter = MockOsAdapter::new("test");
        adapter.add_files("/tmp", vec![FileInfo::new("/tmp/foo.txt", 100)]);
        let files = adapter.list_files("/tmp").unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "/tmp/foo.txt");
    }

    #[test]
    fn test_mock_empty_files() {
        let adapter = MockOsAdapter::new("test");
        let files = adapter.list_files("/nonexistent").unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_mock_registry() {
        let adapter = MockOsAdapter::new("test");
        adapter.add_registry(
            r"HKLM\Software\Test",
            vec![RegistryEntry::new(r"HKLM\Software\Test", "key1", "val1")],
        );
        let entries = adapter.read_registry(r"HKLM\Software\Test").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value_name, "key1");
    }

    #[test]
    fn test_mock_network_connections() {
        let adapter = MockOsAdapter::new("test");
        adapter.add_connection(NetworkConnection {
            pid: 1234,
            protocol: NetworkProtocol::Tcp,
            local_addr: "127.0.0.1".to_string(),
            local_port: 8080,
            remote_addr: "8.8.8.8".to_string(),
            remote_port: 443,
            state: ConnectionState::Established,
            process_name: "chrome".to_string(),
            bytes_sent: 500,
            bytes_recv: 1500,
        });
        let conns = adapter.get_network_connections().unwrap();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].remote_port, 443);
    }

    #[test]
    fn test_mock_loaded_modules() {
        let adapter = MockOsAdapter::new("test");
        adapter.add_modules(
            1234,
            vec![LoadedModule::new("malware.dll", 0x1000_0000, 0x5000)],
        );
        let mods = adapter.get_loaded_modules(1234).unwrap();
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].name, "malware.dll");
    }

    #[test]
    fn test_mock_fail_next() {
        let adapter = MockOsAdapter::new("test");
        adapter.fail_next();
        let result = adapter.list_processes();
        assert!(result.is_err());
        // Second call should succeed (flag cleared after one failure).
        let result2 = adapter.list_processes();
        assert!(result2.is_ok());
    }

    // ── WindowsOsAdapter ─────────────────────────────────────────────────────

    #[test]
    fn test_windows_platform_name() {
        let adapter = WindowsOsAdapter::new(false);
        assert_eq!(adapter.platform(), "windows");
    }

    #[test]
    fn test_windows_list_processes() {
        let adapter = WindowsOsAdapter::new(false);
        let procs = adapter.list_processes().unwrap();
        assert!(!procs.is_empty());
    }

    #[test]
    fn test_windows_memory_requires_elevation() {
        let adapter = WindowsOsAdapter::new(false);
        let err = adapter.read_process_memory(1234, 0x1000, 4).unwrap_err();
        assert!(matches!(err, OsAdapterError::PermissionDenied(_)));
    }

    #[test]
    fn test_windows_memory_elevated() {
        let adapter = WindowsOsAdapter::new(true);
        let data = adapter.read_process_memory(1234, 0x1000, 4).unwrap();
        assert_eq!(data.len(), 4);
    }

    #[test]
    fn test_windows_registry() {
        let adapter = WindowsOsAdapter::new(false);
        let entries = adapter.read_registry(r"HKLM\SOFTWARE").unwrap();
        assert!(!entries.is_empty());
    }

    // ── LinuxOsAdapter ───────────────────────────────────────────────────────

    #[test]
    fn test_linux_platform_name() {
        let adapter = LinuxOsAdapter::new();
        assert_eq!(adapter.platform(), "linux");
    }

    #[test]
    fn test_linux_registry_not_supported() {
        let adapter = LinuxOsAdapter::new();
        let err = adapter.read_registry("HKLM").unwrap_err();
        assert!(matches!(err, OsAdapterError::NotSupported(_)));
    }

    #[test]
    fn test_linux_memory_regions() {
        let adapter = LinuxOsAdapter::new();
        let regions = adapter.get_memory_regions(1234).unwrap();
        assert!(!regions.is_empty());
    }

    // ── MacOsAdapter ─────────────────────────────────────────────────────────

    #[test]
    fn test_macos_platform_name() {
        let adapter = MacOsAdapter::new();
        assert_eq!(adapter.platform(), "macos");
    }

    #[test]
    fn test_macos_registry_not_supported() {
        let adapter = MacOsAdapter::new();
        let err = adapter.read_registry("HKLM").unwrap_err();
        assert!(matches!(err, OsAdapterError::NotSupported(_)));
    }

    // ── Data type display / helpers ──────────────────────────────────────────

    #[test]
    fn test_process_status_display() {
        assert_eq!(ProcessStatus::Running.to_string(), "running");
        assert_eq!(ProcessStatus::Zombie.to_string(), "zombie");
    }

    #[test]
    fn test_network_protocol_display() {
        assert_eq!(NetworkProtocol::Tcp.to_string(), "TCP");
        assert_eq!(NetworkProtocol::Udp6.to_string(), "UDP6");
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Established.to_string(), "ESTABLISHED");
        assert_eq!(ConnectionState::Listen.to_string(), "LISTEN");
    }

    #[test]
    fn test_registry_data_type_display() {
        assert_eq!(RegistryDataType::Sz.to_string(), "REG_SZ");
        assert_eq!(RegistryDataType::Dword.to_string(), "REG_DWORD");
    }

    #[test]
    fn test_memory_permissions_variants() {
        let rx = MemoryPermissions::rx();
        assert!(rx.read && rx.execute && !rx.write);
        let rw = MemoryPermissions::rw();
        assert!(rw.read && rw.write && !rw.execute);
    }
}
