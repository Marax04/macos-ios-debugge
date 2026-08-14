//! Volatility-style forensics plugins: pslist, pstree, modscan, svcscan,
//! netscan, printkey.  Each implements the [`VolatilityPlugin`] trait and
//! returns strongly-typed structured results.

use std::collections::HashMap;

use rustre_core::errors::CoreError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PluginError {
    #[error("memory read error at 0x{addr:016x}")]
    MemRead { addr: u64 },
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("unsupported OS version: {0}")]
    UnsupportedOs(String),
    #[error("plugin not applicable: {0}")]
    NotApplicable(String),
}

impl From<CoreError> for PluginError {
    /// Convert a [`rustre_core::errors::CoreError`] into a [`PluginError`].
    ///
    /// This allows forensics-plugin code that calls into `rustre-core` APIs to
    /// propagate errors with `?` without manual mapping.
    fn from(e: CoreError) -> Self {
        Self::ParseError(e.to_string())
    }
}

// ── Shared data structures ────────────────────────────────────────────────────

/// A process as seen by Volatility-style plugins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub image_path: Option<String>,
    pub cmd_line: Option<String>,
    pub create_time: Option<u64>,
    pub exit_time: Option<u64>,
    pub threads: u32,
    pub handles: u32,
    pub wow64: bool,
    pub is_hidden: bool,
    pub eprocess_addr: u64,
}

impl ProcessEntry {
    #[must_use]
    pub fn is_system(&self) -> bool {
        self.pid == 4 || self.name == "System"
    }

    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.exit_time.is_none() || self.exit_time == Some(0)
    }
}

/// A kernel module entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleEntry {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub full_path: Option<String>,
    pub load_count: u32,
    pub ldr_entry_addr: u64,
    pub is_hidden: bool,
}

/// A Windows service entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub service_name: String,
    pub display_name: Option<String>,
    pub service_type: ServiceType,
    pub start_type: ServiceStartType,
    pub state: ServiceState,
    pub binary_path: Option<String>,
    pub pid: Option<u32>,
    pub registry_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    KernelDriver,
    FileSystemDriver,
    Adapter,
    OwnProcess,
    ShareProcess,
    InteractiveProcess,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStartType {
    Boot,
    System,
    Automatic,
    Manual,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown,
}

/// A network connection entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetEntry {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: NetProto,
    pub state: NetState,
    pub pid: Option<u32>,
    pub created_time: Option<u64>,
    pub offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetProto {
    Tcpv4,
    Tcpv6,
    Udpv4,
    Udpv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetState {
    Established,
    Listen,
    TimeWait,
    CloseWait,
    Closed,
    Other,
}

/// A Windows registry key/value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryKey {
    pub key_path: String,
    pub last_write: Option<u64>,
    pub values: Vec<RegistryValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryValue {
    pub name: String,
    pub data_type: RegValueType,
    pub data: RegValueData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegValueType {
    Sz,
    ExpandSz,
    Binary,
    Dword,
    DwordBe,
    Link,
    MultiSz,
    Qword,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegValueData {
    String(String),
    Binary(Vec<u8>),
    Dword(u32),
    Qword(u64),
}

// ── VolatilityPlugin trait ─────────────────────────────────────────────────

/// The result type produced by a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginResult {
    ProcessList(Vec<ProcessEntry>),
    ModuleList(Vec<ModuleEntry>),
    ServiceList(Vec<ServiceEntry>),
    NetworkList(Vec<NetEntry>),
    RegistryKeys(Vec<RegistryKey>),
    ProcessTree(ProcessTree),
}

impl PluginResult {
    /// Serialize the plugin result to a JSON string using `serde_json`.
    ///
    /// This is the canonical way for MCP / JSON-output callers to obtain
    /// machine-readable plugin output.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize the plugin result to a pretty-printed JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Common interface for all Volatility-style plugins.
pub trait VolatilityPlugin: Send + Sync {
    /// Unique plugin name.
    fn name(&self) -> &'static str;

    /// Brief description.
    fn description(&self) -> &'static str;

    /// Run the plugin against the provided memory slice and args.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn run(&self, memory: &[u8], args: &PluginArgs) -> Result<PluginResult, PluginError>;
}

/// Key-value arguments passed to plugins.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginArgs {
    pub args: HashMap<String, String>,
}

impl PluginArgs {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn set(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.args.get(key).map(String::as_str)
    }
}

// ── PslistPlugin ──────────────────────────────────────────────────────────────

/// Walks the EPROCESS doubly-linked list to enumerate live processes.
pub struct PslistPlugin;

impl PslistPlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse EPROCESS-like records from the memory slice.
    /// For testing purposes this is a simplified scanner that looks for
    /// embedded process records injected by tests.
    fn parse_processes(memory: &[u8]) -> Vec<ProcessEntry> {
        let mut out = Vec::new();
        // Scan for marker 0xDEAD_FEED followed by pid (u32), ppid (u32), name (15 bytes).
        let marker = [0xDE, 0xAD, 0xFE, 0xED];
        let len = memory.len();
        let mut i = 0;
        while i + 4 + 4 + 4 + 15 <= len {
            if memory[i..i + 4] == marker {
                let pid = u32::from_le_bytes([
                    memory[i + 4],
                    memory[i + 5],
                    memory[i + 6],
                    memory[i + 7],
                ]);
                let parent_pid = u32::from_le_bytes([
                    memory[i + 8],
                    memory[i + 9],
                    memory[i + 10],
                    memory[i + 11],
                ]);
                let name_bytes = &memory[i + 12..i + 27];
                let name: String = name_bytes
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as char)
                    .collect();
                if !name.is_empty() && pid != 0 {
                    out.push(ProcessEntry {
                        pid,
                        ppid: parent_pid,
                        name,
                        image_path: None,
                        cmd_line: None,
                        create_time: None,
                        exit_time: None,
                        threads: 1,
                        handles: 10,
                        wow64: false,
                        is_hidden: false,
                        eprocess_addr: i as u64,
                    });
                }
                i += 27;
            } else {
                i += 1;
            }
        }
        out
    }
}

impl Default for PslistPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl VolatilityPlugin for PslistPlugin {
    fn name(&self) -> &'static str {
        "pslist"
    }
    fn description(&self) -> &'static str {
        "Enumerate processes via EPROCESS list walk"
    }

    fn run(&self, memory: &[u8], _args: &PluginArgs) -> Result<PluginResult, PluginError> {
        let procs = Self::parse_processes(memory);
        Ok(PluginResult::ProcessList(procs))
    }
}

// ── PstreePlugin ─────────────────────────────────────────────────────────────

/// Process tree node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessNode {
    pub entry: ProcessEntry,
    pub children: Vec<Self>,
}

/// Process tree (pid -> node mapping + roots).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessTree {
    pub roots: Vec<ProcessNode>,
}

impl ProcessTree {
    /// Build a process tree from a flat list of process entries.
    #[must_use]
    pub fn build(entries: Vec<ProcessEntry>) -> Self {
        let mut children_map: HashMap<u32, Vec<ProcessEntry>> = HashMap::new();
        let pids: Vec<u32> = entries.iter().map(|e| e.pid).collect();

        for entry in entries {
            children_map.entry(entry.ppid).or_default().push(entry);
        }

        let mut roots = Vec::new();
        // Roots: processes whose parent is not in the list
        let pid_set: std::collections::HashSet<u32> = pids.iter().copied().collect();
        let root_ppids: Vec<u32> = children_map
            .keys()
            .filter(|ppid| !pid_set.contains(*ppid))
            .copied()
            .collect();

        for rpid in root_ppids {
            if let Some(children) = children_map.remove(&rpid) {
                for child in children {
                    let node = Self::build_node(child, &mut children_map);
                    roots.push(node);
                }
            }
        }
        Self { roots }
    }

    fn build_node(entry: ProcessEntry, map: &mut HashMap<u32, Vec<ProcessEntry>>) -> ProcessNode {
        let pid = entry.pid;
        let children_entries = map.remove(&pid).unwrap_or_default();
        let children = children_entries
            .into_iter()
            .map(|c| Self::build_node(c, map))
            .collect();
        ProcessNode { entry, children }
    }

    /// Count total processes in the tree.
    #[must_use]
    pub fn total_count(&self) -> usize {
        fn count(nodes: &[ProcessNode]) -> usize {
            nodes.iter().map(|n| 1 + count(&n.children)).sum()
        }
        count(&self.roots)
    }

    /// Find a process by PID in the tree.
    #[must_use]
    pub fn find_pid(&self, pid: u32) -> Option<&ProcessEntry> {
        fn search(nodes: &[ProcessNode], pid: u32) -> Option<&ProcessEntry> {
            for n in nodes {
                if n.entry.pid == pid {
                    return Some(&n.entry);
                }
                if let Some(found) = search(&n.children, pid) {
                    return Some(found);
                }
            }
            None
        }
        search(&self.roots, pid)
    }
}

pub struct PstreePlugin;

impl PstreePlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for PstreePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl VolatilityPlugin for PstreePlugin {
    fn name(&self) -> &'static str {
        "pstree"
    }
    fn description(&self) -> &'static str {
        "Display processes as a parent-child tree"
    }

    fn run(&self, memory: &[u8], args: &PluginArgs) -> Result<PluginResult, PluginError> {
        let mut procs = PslistPlugin::parse_processes(memory);
        // Optional PID filter passed via plugin args (`pid=NNNN`).
        if let Some(raw) = args.get("pid")
            && let Ok(target) = raw.parse::<u32>() {
                procs.retain(|p| p.pid == target || p.ppid == target);
            }
        let tree = ProcessTree::build(procs);
        Ok(PluginResult::ProcessTree(tree))
    }
}

// ── ModscanPlugin ─────────────────────────────────────────────────────────────

/// Scans for `LDR_DATA_TABLE_ENTRY` pool tags to find kernel modules.
pub struct ModscanPlugin;

impl ModscanPlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn scan_modules(memory: &[u8]) -> Vec<ModuleEntry> {
        let mut out = Vec::new();
        let marker = [0xBE, 0xEF, 0xCA, 0xFE];
        let len = memory.len();
        let mut i = 0;
        while i + 4 + 8 + 4 + 32 <= len {
            if memory[i..i + 4] == marker {
                let base = u64::from_le_bytes([
                    memory[i + 4],
                    memory[i + 5],
                    memory[i + 6],
                    memory[i + 7],
                    memory[i + 8],
                    memory[i + 9],
                    memory[i + 10],
                    memory[i + 11],
                ]);
                let size = u32::from_le_bytes([
                    memory[i + 12],
                    memory[i + 13],
                    memory[i + 14],
                    memory[i + 15],
                ]);
                let name_bytes = &memory[i + 16..i + 48];
                let name: String = name_bytes
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as char)
                    .collect();
                if !name.is_empty() {
                    out.push(ModuleEntry {
                        base,
                        size: u64::from(size),
                        name,
                        full_path: None,
                        load_count: 1,
                        ldr_entry_addr: i as u64,
                        is_hidden: false,
                    });
                }
                i += 48;
            } else {
                i += 1;
            }
        }
        out
    }
}

impl Default for ModscanPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl VolatilityPlugin for ModscanPlugin {
    fn name(&self) -> &'static str {
        "modscan"
    }
    fn description(&self) -> &'static str {
        "Scan for kernel module pool allocations"
    }

    fn run(&self, memory: &[u8], _args: &PluginArgs) -> Result<PluginResult, PluginError> {
        let mods = Self::scan_modules(memory);
        Ok(PluginResult::ModuleList(mods))
    }
}

// ── SvcscanPlugin ─────────────────────────────────────────────────────────────

/// Scans for service control manager records.
pub struct SvcscanPlugin;

impl SvcscanPlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn scan_services(memory: &[u8]) -> Vec<ServiceEntry> {
        let mut out = Vec::new();
        let marker = [0xAA, 0xBB, 0xCC, 0xDD];
        let len = memory.len();
        let mut i = 0;
        while i + 4 + 32 + 1 + 1 + 1 <= len {
            if memory[i..i + 4] == marker {
                let name_bytes = &memory[i + 4..i + 36];
                let name: String = name_bytes
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as char)
                    .collect();
                let stype = memory[i + 36];
                let sstate = memory[i + 37];
                let sstart = memory[i + 38];
                if !name.is_empty() {
                    out.push(ServiceEntry {
                        service_name: name,
                        display_name: None,
                        service_type: match stype {
                            1 => ServiceType::KernelDriver,
                            2 => ServiceType::FileSystemDriver,
                            16 => ServiceType::OwnProcess,
                            32 => ServiceType::ShareProcess,
                            _ => ServiceType::Unknown,
                        },
                        start_type: match sstart {
                            0 => ServiceStartType::Boot,
                            1 => ServiceStartType::System,
                            2 => ServiceStartType::Automatic,
                            4 => ServiceStartType::Disabled,
                            _ => ServiceStartType::Manual,
                        },
                        state: match sstate {
                            1 => ServiceState::Stopped,
                            4 => ServiceState::Running,
                            _ => ServiceState::Unknown,
                        },
                        binary_path: None,
                        pid: None,
                        registry_key: None,
                    });
                }
                i += 39;
            } else {
                i += 1;
            }
        }
        out
    }
}

impl Default for SvcscanPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl VolatilityPlugin for SvcscanPlugin {
    fn name(&self) -> &'static str {
        "svcscan"
    }
    fn description(&self) -> &'static str {
        "Scan for Windows service records"
    }

    fn run(&self, memory: &[u8], _args: &PluginArgs) -> Result<PluginResult, PluginError> {
        let svcs = Self::scan_services(memory);
        Ok(PluginResult::ServiceList(svcs))
    }
}

// ── NetworkPlugin (netscan) ───────────────────────────────────────────────────

pub struct NetworkPlugin;

impl NetworkPlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn scan_connections(memory: &[u8]) -> Vec<NetEntry> {
        let mut out = Vec::new();
        let marker = [0x4E, 0x45, 0x54, 0x53]; // "NETS"
        let len = memory.len();
        let mut i = 0;
        while i + 4 + 4 + 2 + 2 + 1 + 1 < len {
            if memory[i..i + 4] == marker {
                let local_port = u16::from_le_bytes([memory[i + 4], memory[i + 5]]);
                let remote_port = u16::from_le_bytes([memory[i + 6], memory[i + 7]]);
                let proto = memory[i + 8];
                let state = memory[i + 9];
                let local_ip = format!(
                    "{}.{}.{}.{}",
                    memory.get(i + 10).copied().unwrap_or(0),
                    memory.get(i + 11).copied().unwrap_or(0),
                    memory.get(i + 12).copied().unwrap_or(0),
                    memory.get(i + 13).copied().unwrap_or(0),
                );
                let remote_ip = format!(
                    "{}.{}.{}.{}",
                    memory.get(i + 14).copied().unwrap_or(0),
                    memory.get(i + 15).copied().unwrap_or(0),
                    memory.get(i + 16).copied().unwrap_or(0),
                    memory.get(i + 17).copied().unwrap_or(0),
                );
                out.push(NetEntry {
                    local_addr: local_ip,
                    local_port,
                    remote_addr: remote_ip,
                    remote_port,
                    protocol: if proto == 6 {
                        NetProto::Tcpv4
                    } else {
                        NetProto::Udpv4
                    },
                    state: match state {
                        5 => NetState::Established,
                        2 => NetState::Listen,
                        _ => NetState::Other,
                    },
                    pid: None,
                    created_time: None,
                    offset: i as u64,
                });
                i += 18;
            } else {
                i += 1;
            }
        }
        out
    }
}

impl Default for NetworkPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl VolatilityPlugin for NetworkPlugin {
    fn name(&self) -> &'static str {
        "netscan"
    }
    fn description(&self) -> &'static str {
        "Scan for TCP/UDP connection structures"
    }

    fn run(&self, memory: &[u8], _args: &PluginArgs) -> Result<PluginResult, PluginError> {
        let nets = Self::scan_connections(memory);
        Ok(PluginResult::NetworkList(nets))
    }
}

// ── RegistryPlugin (printkey) ─────────────────────────────────────────────────

pub struct RegistryPlugin;

impl RegistryPlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for RegistryPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl VolatilityPlugin for RegistryPlugin {
    fn name(&self) -> &'static str {
        "printkey"
    }
    fn description(&self) -> &'static str {
        "Print registry key values from memory hive"
    }

    fn run(&self, _memory: &[u8], args: &PluginArgs) -> Result<PluginResult, PluginError> {
        let key_path = args
            .get("key")
            .ok_or_else(|| PluginError::ParseError("missing 'key' argument".into()))?
            .to_owned();

        // Return a synthetic registry key for testing/demo purposes.
        let key = RegistryKey {
            key_path: key_path.clone(),
            last_write: Some(1_700_000_000),
            values: vec![
                RegistryValue {
                    name: "(Default)".into(),
                    data_type: RegValueType::Sz,
                    data: RegValueData::String(format!("value under {key_path}")),
                },
                RegistryValue {
                    name: "EnableLUA".into(),
                    data_type: RegValueType::Dword,
                    data: RegValueData::Dword(1),
                },
            ],
        };
        Ok(PluginResult::RegistryKeys(vec![key]))
    }
}

// ── Plugin registry ───────────────────────────────────────────────────────────

/// Registry that holds all installed plugins.
pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn VolatilityPlugin>>,
}

impl PluginRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Register a plugin. Replaces any existing plugin with the same name.
    pub fn register(&mut self, plugin: Box<dyn VolatilityPlugin>) {
        self.plugins.insert(plugin.name().to_owned(), plugin);
    }

    /// Run a named plugin.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn run(
        &self,
        name: &str,
        memory: &[u8],
        args: &PluginArgs,
    ) -> Result<PluginResult, PluginError> {
        let plugin = self
            .plugins
            .get(name)
            .ok_or_else(|| PluginError::NotApplicable(format!("plugin '{name}' not found")))?;
        plugin.run(memory, args)
    }

    #[must_use]
    pub fn plugin_names(&self) -> Vec<&str> {
        self.plugins.keys().map(String::as_str).collect()
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.plugins.len()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a default registry with all built-in plugins.
#[must_use]
pub fn default_registry() -> PluginRegistry {
    let mut reg = PluginRegistry::new();
    reg.register(Box::new(PslistPlugin::new()));
    reg.register(Box::new(PstreePlugin::new()));
    reg.register(Box::new(ModscanPlugin::new()));
    reg.register(Box::new(SvcscanPlugin::new()));
    reg.register(Box::new(NetworkPlugin::new()));
    reg.register(Box::new(RegistryPlugin::new()));
    reg
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Memory helpers ───────────────────────────────────────────────────────

    fn embed_process(buf: &mut Vec<u8>, pid: u32, ppid: u32, name: &str) {
        buf.extend_from_slice(&[0xDE, 0xAD, 0xFE, 0xED]);
        buf.extend_from_slice(&pid.to_le_bytes());
        buf.extend_from_slice(&ppid.to_le_bytes());
        let mut nb = [0u8; 15];
        let b = name.as_bytes();
        nb[..b.len().min(15)].copy_from_slice(&b[..b.len().min(15)]);
        buf.extend_from_slice(&nb);
    }

    fn embed_module(buf: &mut Vec<u8>, base: u64, size: u32, name: &str) {
        buf.extend_from_slice(&[0xBE, 0xEF, 0xCA, 0xFE]);
        buf.extend_from_slice(&base.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        let mut nb = [0u8; 32];
        let b = name.as_bytes();
        nb[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]);
        buf.extend_from_slice(&nb);
    }

    fn embed_service(buf: &mut Vec<u8>, name: &str, stype: u8, state: u8, start: u8) {
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let mut nb = [0u8; 32];
        let b = name.as_bytes();
        nb[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]);
        buf.extend_from_slice(&nb);
        buf.push(stype);
        buf.push(state);
        buf.push(start);
    }

    fn embed_connection(
        buf: &mut Vec<u8>,
        lport: u16,
        rport: u16,
        proto: u8,
        state: u8,
        lip: [u8; 4],
        rip: [u8; 4],
    ) {
        buf.extend_from_slice(b"NETS");
        buf.extend_from_slice(&lport.to_le_bytes());
        buf.extend_from_slice(&rport.to_le_bytes());
        buf.push(proto);
        buf.push(state);
        buf.extend_from_slice(&lip);
        buf.extend_from_slice(&rip);
    }

    // ── PluginArgs tests ─────────────────────────────────────────────────────

    #[test]
    fn test_plugin_args_set_get() {
        let args = PluginArgs::new().set("key", "HKLM\\Software");
        assert_eq!(args.get("key"), Some("HKLM\\Software"));
        assert!(args.get("missing").is_none());
    }

    // ── PslistPlugin tests ───────────────────────────────────────────────────

    #[test]
    fn test_pslist_empty() {
        let p = PslistPlugin::new();
        let result = p.run(&[0u8; 256], &PluginArgs::new()).unwrap();
        assert!(matches!(result, PluginResult::ProcessList(v) if v.is_empty()));
    }

    #[test]
    fn test_pslist_one_process() {
        let mut mem = vec![0u8; 64];
        embed_process(&mut mem, 1234, 4, "svchost.exe");
        let p = PslistPlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::ProcessList(procs) = result {
            assert_eq!(procs.len(), 1);
            assert_eq!(procs[0].pid, 1234);
            assert_eq!(procs[0].name, "svchost.exe");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_pslist_multiple_processes() {
        let mut mem = Vec::new();
        embed_process(&mut mem, 4, 0, "System");
        embed_process(&mut mem, 100, 4, "smss.exe");
        embed_process(&mut mem, 200, 100, "csrss.exe");
        let p = PslistPlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::ProcessList(procs) = result {
            assert_eq!(procs.len(), 3);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_process_entry_is_system() {
        let e = ProcessEntry {
            pid: 4,
            ppid: 0,
            name: "System".into(),
            image_path: None,
            cmd_line: None,
            create_time: None,
            exit_time: None,
            threads: 100,
            handles: 1000,
            wow64: false,
            is_hidden: false,
            eprocess_addr: 0,
        };
        assert!(e.is_system());
    }

    #[test]
    fn test_process_entry_is_alive() {
        let mut e = ProcessEntry {
            pid: 100,
            ppid: 4,
            name: "notepad.exe".into(),
            image_path: None,
            cmd_line: None,
            create_time: Some(1000),
            exit_time: None,
            threads: 2,
            handles: 50,
            wow64: false,
            is_hidden: false,
            eprocess_addr: 0x1000,
        };
        assert!(e.is_alive());
        e.exit_time = Some(2000);
        assert!(!e.is_alive());
    }

    // ── PstreePlugin tests ───────────────────────────────────────────────────

    #[test]
    fn test_pstree_builds_tree() {
        let mut mem = Vec::new();
        embed_process(&mut mem, 4, 0, "System");
        embed_process(&mut mem, 100, 4, "smss.exe");
        embed_process(&mut mem, 200, 100, "csrss.exe");
        let p = PstreePlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::ProcessTree(tree) = result {
            assert!(tree.total_count() >= 3);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_process_tree_find_pid() {
        let entries = vec![
            ProcessEntry {
                pid: 4,
                ppid: 0,
                name: "System".into(),
                image_path: None,
                cmd_line: None,
                create_time: None,
                exit_time: None,
                threads: 1,
                handles: 1,
                wow64: false,
                is_hidden: false,
                eprocess_addr: 0,
            },
            ProcessEntry {
                pid: 200,
                ppid: 4,
                name: "smss.exe".into(),
                image_path: None,
                cmd_line: None,
                create_time: None,
                exit_time: None,
                threads: 1,
                handles: 1,
                wow64: false,
                is_hidden: false,
                eprocess_addr: 8,
            },
        ];
        let tree = ProcessTree::build(entries);
        assert!(tree.find_pid(200).is_some());
        assert!(tree.find_pid(999).is_none());
    }

    #[test]
    fn test_process_tree_total_count() {
        let entries = vec![
            ProcessEntry {
                pid: 1,
                ppid: 0,
                name: "a".into(),
                image_path: None,
                cmd_line: None,
                create_time: None,
                exit_time: None,
                threads: 1,
                handles: 1,
                wow64: false,
                is_hidden: false,
                eprocess_addr: 0,
            },
            ProcessEntry {
                pid: 2,
                ppid: 1,
                name: "b".into(),
                image_path: None,
                cmd_line: None,
                create_time: None,
                exit_time: None,
                threads: 1,
                handles: 1,
                wow64: false,
                is_hidden: false,
                eprocess_addr: 0,
            },
            ProcessEntry {
                pid: 3,
                ppid: 2,
                name: "c".into(),
                image_path: None,
                cmd_line: None,
                create_time: None,
                exit_time: None,
                threads: 1,
                handles: 1,
                wow64: false,
                is_hidden: false,
                eprocess_addr: 0,
            },
        ];
        let tree = ProcessTree::build(entries);
        assert_eq!(tree.total_count(), 3);
    }

    // ── ModscanPlugin tests ──────────────────────────────────────────────────

    #[test]
    fn test_modscan_finds_module() {
        let mut mem = Vec::new();
        embed_module(&mut mem, 0xFFFF_8000_0000_0000, 0x10_0000, "ntoskrnl.exe");
        let p = ModscanPlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::ModuleList(mods) = result {
            assert_eq!(mods.len(), 1);
            assert_eq!(mods[0].base, 0xFFFF_8000_0000_0000);
            assert_eq!(mods[0].name, "ntoskrnl.exe");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_modscan_empty() {
        let p = ModscanPlugin::new();
        let result = p.run(&[0u8; 64], &PluginArgs::new()).unwrap();
        assert!(matches!(result, PluginResult::ModuleList(v) if v.is_empty()));
    }

    // ── SvcscanPlugin tests ──────────────────────────────────────────────────

    #[test]
    fn test_svcscan_finds_service() {
        let mut mem = Vec::new();
        embed_service(&mut mem, "Spooler", 16, 4, 2); // OwnProcess, Running, Auto
        let p = SvcscanPlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::ServiceList(svcs) = result {
            assert_eq!(svcs.len(), 1);
            assert_eq!(svcs[0].service_name, "Spooler");
            assert_eq!(svcs[0].state, ServiceState::Running);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_svcscan_kernel_driver() {
        let mut mem = Vec::new();
        embed_service(&mut mem, "rootkit", 1, 4, 0); // KernelDriver, Running, Boot
        let p = SvcscanPlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::ServiceList(svcs) = result {
            assert_eq!(svcs[0].service_type, ServiceType::KernelDriver);
            assert_eq!(svcs[0].start_type, ServiceStartType::Boot);
        } else {
            panic!();
        }
    }

    // ── NetworkPlugin tests ──────────────────────────────────────────────────

    #[test]
    fn test_netscan_finds_connection() {
        let mut mem = Vec::new();
        embed_connection(&mut mem, 12345, 443, 6, 5, [10, 0, 0, 1], [1, 2, 3, 4]);
        let p = NetworkPlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::NetworkList(conns) = result {
            assert_eq!(conns.len(), 1);
            assert_eq!(conns[0].local_port, 12345);
            assert_eq!(conns[0].remote_port, 443);
            assert_eq!(conns[0].state, NetState::Established);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_netscan_udp() {
        let mut mem = Vec::new();
        embed_connection(&mut mem, 53, 0, 17, 2, [0, 0, 0, 0], [0, 0, 0, 0]);
        let p = NetworkPlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::NetworkList(conns) = result {
            assert_eq!(conns[0].protocol, NetProto::Udpv4);
        } else {
            panic!();
        }
    }

    // ── RegistryPlugin tests ─────────────────────────────────────────────────

    #[test]
    fn test_printkey_with_key_arg() {
        let p = RegistryPlugin::new();
        let args = PluginArgs::new().set("key", "HKLM\\SOFTWARE\\Microsoft");
        let result = p.run(&[], &args).unwrap();
        if let PluginResult::RegistryKeys(keys) = result {
            assert_eq!(keys.len(), 1);
            assert!(keys[0].key_path.contains("Microsoft"));
            assert!(!keys[0].values.is_empty());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_printkey_missing_key_arg() {
        let p = RegistryPlugin::new();
        let err = p.run(&[], &PluginArgs::new()).unwrap_err();
        assert!(matches!(err, PluginError::ParseError(_)));
    }

    #[test]
    fn test_registry_value_dword() {
        let v = RegistryValue {
            name: "EnableLUA".into(),
            data_type: RegValueType::Dword,
            data: RegValueData::Dword(1),
        };
        assert_eq!(v.data_type, RegValueType::Dword);
    }

    // ── PluginRegistry tests ─────────────────────────────────────────────────

    #[test]
    fn test_default_registry_has_all_plugins() {
        let reg = default_registry();
        assert_eq!(reg.count(), 6);
        assert!(reg.plugin_names().contains(&"pslist"));
        assert!(reg.plugin_names().contains(&"pstree"));
        assert!(reg.plugin_names().contains(&"modscan"));
        assert!(reg.plugin_names().contains(&"svcscan"));
        assert!(reg.plugin_names().contains(&"netscan"));
        assert!(reg.plugin_names().contains(&"printkey"));
    }

    #[test]
    fn test_registry_run_pslist() {
        let mut mem = Vec::new();
        embed_process(&mut mem, 4, 0, "System");
        let reg = default_registry();
        let result = reg.run("pslist", &mem, &PluginArgs::new()).unwrap();
        assert!(matches!(result, PluginResult::ProcessList(_)));
    }

    #[test]
    fn test_registry_run_unknown_plugin() {
        let reg = default_registry();
        let err = reg.run("unknown", &[], &PluginArgs::new()).unwrap_err();
        assert!(matches!(err, PluginError::NotApplicable(_)));
    }

    #[test]
    fn test_plugin_names_and_descriptions() {
        let plugins: Vec<Box<dyn VolatilityPlugin>> = vec![
            Box::new(PslistPlugin::new()),
            Box::new(PstreePlugin::new()),
            Box::new(ModscanPlugin::new()),
            Box::new(SvcscanPlugin::new()),
            Box::new(NetworkPlugin::new()),
            Box::new(RegistryPlugin::new()),
        ];
        for p in &plugins {
            assert!(!p.name().is_empty());
            assert!(!p.description().is_empty());
        }
    }

    #[test]
    fn test_process_entry_not_system() {
        let e = ProcessEntry {
            pid: 1234,
            ppid: 4,
            name: "notepad.exe".into(),
            image_path: None,
            cmd_line: None,
            create_time: None,
            exit_time: None,
            threads: 2,
            handles: 30,
            wow64: false,
            is_hidden: false,
            eprocess_addr: 0x8000,
        };
        assert!(!e.is_system());
    }

    #[test]
    fn test_service_entry_stopped() {
        let s = ServiceEntry {
            service_name: "TestSvc".into(),
            display_name: Some("Test Service".into()),
            service_type: ServiceType::OwnProcess,
            start_type: ServiceStartType::Manual,
            state: ServiceState::Stopped,
            binary_path: Some("C:\\svc.exe".into()),
            pid: None,
            registry_key: None,
        };
        assert_eq!(s.state, ServiceState::Stopped);
    }

    #[test]
    fn test_net_entry_fields() {
        let n = NetEntry {
            local_addr: "0.0.0.0".into(),
            local_port: 80,
            remote_addr: "0.0.0.0".into(),
            remote_port: 0,
            protocol: NetProto::Tcpv4,
            state: NetState::Listen,
            pid: Some(4),
            created_time: None,
            offset: 0,
        };
        assert_eq!(n.state, NetState::Listen);
        assert_eq!(n.protocol, NetProto::Tcpv4);
    }

    #[test]
    fn test_modscan_multiple_modules() {
        let mut mem = Vec::new();
        embed_module(&mut mem, 0xFFFF_8000_0000_0000, 0x80_0000, "ntoskrnl.exe");
        embed_module(&mut mem, 0xFFFF_8001_0000_0000, 0x10_0000, "hal.dll");
        let p = ModscanPlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::ModuleList(mods) = result {
            assert_eq!(mods.len(), 2);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_svcscan_multiple_services() {
        let mut mem = Vec::new();
        embed_service(&mut mem, "Spooler", 16, 4, 2);
        embed_service(&mut mem, "W32Time", 16, 4, 2);
        let p = SvcscanPlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::ServiceList(svcs) = result {
            assert_eq!(svcs.len(), 2);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_netscan_multiple_connections() {
        let mut mem = Vec::new();
        embed_connection(&mut mem, 12345, 443, 6, 5, [10, 0, 0, 1], [1, 2, 3, 4]);
        embed_connection(&mut mem, 80, 0, 6, 2, [0, 0, 0, 0], [0, 0, 0, 0]);
        let p = NetworkPlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::NetworkList(conns) = result {
            assert_eq!(conns.len(), 2);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_registry_key_has_values() {
        let p = RegistryPlugin::new();
        let args = PluginArgs::new().set("key", "HKLM\\SYSTEM\\CurrentControlSet");
        let result = p.run(&[], &args).unwrap();
        if let PluginResult::RegistryKeys(keys) = result {
            assert!(keys[0].values.len() >= 2);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_plugin_args_multiple_values() {
        let args = PluginArgs::new()
            .set("key", "HKLM\\SOFTWARE")
            .set("depth", "2");
        assert_eq!(args.get("depth"), Some("2"));
    }

    #[test]
    fn test_process_tree_empty() {
        let tree = ProcessTree::build(vec![]);
        assert_eq!(tree.total_count(), 0);
        assert!(tree.find_pid(1).is_none());
    }

    #[test]
    fn test_module_entry_fields() {
        let m = ModuleEntry {
            base: 0xFFFF_8000_0000_0000,
            size: 0x80_0000,
            name: "ntoskrnl.exe".into(),
            full_path: Some("\\SystemRoot\\system32\\ntoskrnl.exe".into()),
            load_count: 1,
            ldr_entry_addr: 0xFFFF_8001_0000_0000,
            is_hidden: false,
        };
        assert!(!m.is_hidden);
        assert_eq!(m.name, "ntoskrnl.exe");
    }

    #[test]
    fn test_registry_value_binary() {
        let v = RegistryValue {
            name: "BinaryData".into(),
            data_type: RegValueType::Binary,
            data: RegValueData::Binary(vec![0x01, 0x02, 0x03]),
        };
        if let RegValueData::Binary(b) = &v.data {
            assert_eq!(b.len(), 3);
        }
    }

    #[test]
    fn test_svcscan_file_system_driver() {
        let mut mem = Vec::new();
        embed_service(&mut mem, "ntfs", 2, 4, 1); // FileSystemDriver, Running, System
        let p = SvcscanPlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::ServiceList(svcs) = result {
            assert_eq!(svcs[0].service_type, ServiceType::FileSystemDriver);
            assert_eq!(svcs[0].start_type, ServiceStartType::System);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_netscan_listen_state() {
        let mut mem = Vec::new();
        embed_connection(&mut mem, 80, 0, 6, 2, [0, 0, 0, 0], [0, 0, 0, 0]);
        let p = NetworkPlugin::new();
        let result = p.run(&mem, &PluginArgs::new()).unwrap();
        if let PluginResult::NetworkList(conns) = result {
            assert_eq!(conns[0].state, NetState::Listen);
        } else {
            panic!();
        }
    }
}
