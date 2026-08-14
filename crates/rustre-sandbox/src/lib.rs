//! `rustre-sandbox` — Sandbox execution analysis.
//!
//! Provides process isolation, system call monitoring, behavior recording,
//! artifact collection, timeout enforcement, resource limits, network isolation,
//! and filesystem snapshotting for dynamic malware analysis.

pub mod artifact_collector;
pub mod behavioral_analysis;
pub mod evasion_detector;
pub mod network_simulation;
pub mod sandbox_orchestrator;
pub mod sandbox_policy;
pub mod process_monitor;
pub mod network_capture;
pub mod sandbox_reporter;
pub mod behavior_monitor;
pub mod network_simulator;

/// Re-exports and a convenience constructor for all sibling sandbox sub-crates.
#[cfg(feature = "subcrates")]
pub mod registry {
    pub use rustre_sandbox_extract;
    pub use rustre_sandbox_monitor;
    pub use rustre_sandbox_report;
    pub use rustre_sandbox_vm;

    /// Return one default instance of each sibling crate's primary type.
    ///
    /// * `SandboxArtifactExtractor` — zero-arg unit struct
    /// * `ApiMonitor` — empty hook/call monitor
    /// * `SandboxReportBuilder` — builder seeded with an empty report
    /// * `VmSandbox` — sandbox wrapping a default x64/Windows10 VM instance
    #[must_use]
    pub fn all() -> (
        rustre_sandbox_extract::SandboxArtifactExtractor,
        rustre_sandbox_monitor::ApiMonitor,
        rustre_sandbox_report::SandboxReportBuilder,
        rustre_sandbox_vm::VmSandbox,
    ) {
        let report = rustre_sandbox_report::SandboxReport::new("", "");
        let vm_cfg = rustre_sandbox_vm::VmConfig::new(
            "default",
            rustre_sandbox_vm::VmArch::X64,
            rustre_sandbox_vm::VmOs::Windows10,
        );
        let vm_instance = rustre_sandbox_vm::VmInstance::new("default-vm", vm_cfg);
        (
            rustre_sandbox_extract::SandboxArtifactExtractor::new(),
            rustre_sandbox_monitor::ApiMonitor::new(),
            rustre_sandbox_report::SandboxReportBuilder::new(report),
            rustre_sandbox_vm::VmSandbox::new(vm_instance),
        )
    }
}

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bitflags::bitflags;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by sandbox operations.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("spawn failed: {0}")]
    SpawnFailed(String),
    #[error("timeout after {0} seconds")]
    Timeout(u64),
    #[error("policy violation: {0}")]
    PolicyViolation(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),
    #[error("snapshot error: {0}")]
    SnapshotError(String),
    #[error("network error: {0}")]
    NetworkError(String),
    #[error("already running")]
    AlreadyRunning,
    #[error("not running")]
    NotRunning,
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

// ─── ResourceLimits ───────────────────────────────────────────────────────────

/// Hard limits applied to a sandboxed process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum virtual memory in megabytes.
    pub max_memory_mb: u32,
    /// Maximum number of open file descriptors.
    pub max_open_files: u32,
    /// Maximum number of spawned processes/threads.
    pub max_processes: u32,
    /// Maximum disk write in megabytes.
    pub max_disk_write_mb: u32,
    /// Maximum network bandwidth in kilobytes per second.
    pub max_net_kbps: u32,
    /// CPU usage cap as a percentage (1–100).
    pub cpu_percent: u8,
}

impl ResourceLimits {
    /// Generous limits suitable for most analyses.
    #[must_use]
    pub const fn generous() -> Self {
        Self {
            max_memory_mb: 4096,
            max_open_files: 1024,
            max_processes: 64,
            max_disk_write_mb: 512,
            max_net_kbps: 10_240,
            cpu_percent: 80,
        }
    }

    /// Tight limits for high-isolation environments.
    #[must_use]
    pub const fn tight() -> Self {
        Self {
            max_memory_mb: 256,
            max_open_files: 64,
            max_processes: 4,
            max_disk_write_mb: 32,
            max_net_kbps: 256,
            cpu_percent: 50,
        }
    }

    /// Returns `true` if the given memory usage (in MB) exceeds the limit.
    #[must_use]
    pub const fn memory_exceeded(&self, used_mb: u32) -> bool {
        used_mb > self.max_memory_mb
    }

    /// Returns `true` if the given disk write (in MB) exceeds the limit.
    #[must_use]
    pub const fn disk_exceeded(&self, written_mb: u32) -> bool {
        written_mb > self.max_disk_write_mb
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self::generous()
    }
}

// ─── SandboxPolicy ────────────────────────────────────────────────────────────

bitflags! {
    /// Coarse capability switches for a sandboxed process.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SandboxPermissions: u8 {
        const ALLOW_NETWORK  = 0x01;
        const ALLOW_FS       = 0x02;
        const ALLOW_REGISTRY = 0x04;
        const ALLOW_PROCESS  = 0x08;
        const ALLOW_GUI      = 0x10;
        const ALLOW_DEVICES  = 0x20;
    }
}

impl SandboxPermissions {
    #[must_use]
    pub const fn all_on() -> Self {
        Self::from_bits_truncate(
            Self::ALLOW_NETWORK.bits() | Self::ALLOW_FS.bits() | Self::ALLOW_REGISTRY.bits()
            | Self::ALLOW_PROCESS.bits() | Self::ALLOW_GUI.bits() | Self::ALLOW_DEVICES.bits()
        )
    }
    #[must_use]
    pub const fn all_off() -> Self { Self::empty() }
}

/// Governs what a sandboxed process is permitted to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Coarse on/off capability switches.
    pub perms: SandboxPermissions,
    pub timeout_secs: u64,
    pub max_memory_mb: u32,
    /// Allowed outbound domains / IPs (empty = all blocked if `allow_network` is false).
    pub network_allowlist: Vec<String>,
    /// Paths the process is allowed to read from.
    pub fs_read_paths: Vec<String>,
    /// Paths the process is allowed to write to.
    pub fs_write_paths: Vec<String>,
    /// Resource limits applied on top of the policy flags.
    pub limits: ResourceLimits,
}

impl SandboxPolicy {
    /// A permissive policy — everything allowed, generous limits.
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            perms: SandboxPermissions::all_on(),
            timeout_secs: 300,
            max_memory_mb: 2048,
            network_allowlist: Vec::new(),
            fs_read_paths: Vec::new(),
            fs_write_paths: Vec::new(),
            limits: ResourceLimits::generous(),
        }
    }

    /// A restrictive policy — nothing allowed, tight limits.
    #[must_use]
    pub const fn restrictive() -> Self {
        Self {
            perms: SandboxPermissions::all_off(),
            timeout_secs: 30,
            max_memory_mb: 256,
            network_allowlist: Vec::new(),
            fs_read_paths: Vec::new(),
            fs_write_paths: Vec::new(),
            limits: ResourceLimits::tight(),
        }
    }

    /// A balanced policy: network allowed to allowlist only, FS writes restricted.
    #[must_use]
    pub fn balanced() -> Self {
        Self {
            perms: SandboxPermissions::ALLOW_NETWORK | SandboxPermissions::ALLOW_FS
                | SandboxPermissions::ALLOW_REGISTRY | SandboxPermissions::ALLOW_PROCESS,
            timeout_secs: 120,
            max_memory_mb: 1024,
            network_allowlist: vec![],
            fs_read_paths: vec![],
            fs_write_paths: vec!["/tmp".to_string(), "C:\\Windows\\Temp".to_string()],
            limits: ResourceLimits::generous(),
        }
    }

    /// Returns `true` if access to the given domain/IP is allowed.
    #[must_use]
    pub fn is_network_allowed(&self, target: &str) -> bool {
        if !self.perms.contains(SandboxPermissions::ALLOW_NETWORK) {
            return false;
        }
        if self.network_allowlist.is_empty() {
            return true;
        }
        self.network_allowlist
            .iter()
            .any(|a| target.contains(a.as_str()))
    }

    /// Returns `true` if writing to the given path is allowed.
    #[must_use]
    pub fn is_write_allowed(&self, path: &str) -> bool {
        if !self.perms.contains(SandboxPermissions::ALLOW_FS) {
            return false;
        }
        if self.fs_write_paths.is_empty() {
            return true;
        }
        self.fs_write_paths
            .iter()
            .any(|p| path.starts_with(p.as_str()))
    }

    /// Validate the policy for internal consistency.
    ///
    /// # Errors
    /// Returns `SandboxError::InvalidConfig` if the configuration is contradictory.
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.timeout_secs == 0 {
            return Err(SandboxError::InvalidConfig(
                "timeout_secs must be > 0".into(),
            ));
        }
        if self.max_memory_mb == 0 {
            return Err(SandboxError::InvalidConfig(
                "max_memory_mb must be > 0".into(),
            ));
        }
        if self.limits.cpu_percent == 0 || self.limits.cpu_percent > 100 {
            return Err(SandboxError::InvalidConfig(
                "cpu_percent must be 1–100".into(),
            ));
        }
        Ok(())
    }
}

// ─── BehaviorFlag ────────────────────────────────────────────────────────────

bitflags! {
    /// Observed behaviors of the sandboxed sample.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct BehaviorFlag: u32 {
        const NETWORK      = 0x0001;
        const FILESYSTEM   = 0x0002;
        const REGISTRY     = 0x0004;
        const PROCESS      = 0x0008;
        const INJECTION    = 0x0010;
        const CRYPTO       = 0x0020;
        const ANTIANALYSIS = 0x0040;
        const PERSISTENCE  = 0x0080;
        const DROPPER      = 0x0100;
        const DOWNLOADER   = 0x0200;
        const KEYLOGGER    = 0x0400;
        const SCREENSHOT   = 0x0800;
        const C2           = 0x1000;
        const RANSOMWARE   = 0x2000;
        const ROOTKIT      = 0x4000;
        const WORM         = 0x8000;
    }
}

impl BehaviorFlag {
    /// Returns a human-readable list of active behavior names.
    #[must_use]
    pub fn describe(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.contains(Self::NETWORK) {
            names.push("network");
        }
        if self.contains(Self::FILESYSTEM) {
            names.push("filesystem");
        }
        if self.contains(Self::REGISTRY) {
            names.push("registry");
        }
        if self.contains(Self::PROCESS) {
            names.push("process");
        }
        if self.contains(Self::INJECTION) {
            names.push("injection");
        }
        if self.contains(Self::CRYPTO) {
            names.push("crypto");
        }
        if self.contains(Self::ANTIANALYSIS) {
            names.push("anti-analysis");
        }
        if self.contains(Self::PERSISTENCE) {
            names.push("persistence");
        }
        if self.contains(Self::DROPPER) {
            names.push("dropper");
        }
        if self.contains(Self::DOWNLOADER) {
            names.push("downloader");
        }
        if self.contains(Self::KEYLOGGER) {
            names.push("keylogger");
        }
        if self.contains(Self::SCREENSHOT) {
            names.push("screenshot");
        }
        if self.contains(Self::C2) {
            names.push("c2");
        }
        if self.contains(Self::RANSOMWARE) {
            names.push("ransomware");
        }
        if self.contains(Self::ROOTKIT) {
            names.push("rootkit");
        }
        if self.contains(Self::WORM) {
            names.push("worm");
        }
        names
    }

    /// Threat score: sum of per-flag weights (0–100).
    #[must_use]
    pub fn threat_score(&self) -> u32 {
        let mut score = 0u32;
        if self.contains(Self::INJECTION) {
            score += 25;
        }
        if self.contains(Self::ANTIANALYSIS) {
            score += 20;
        }
        if self.contains(Self::RANSOMWARE) {
            score += 30;
        }
        if self.contains(Self::ROOTKIT) {
            score += 30;
        }
        if self.contains(Self::C2) {
            score += 20;
        }
        if self.contains(Self::KEYLOGGER) {
            score += 20;
        }
        if self.contains(Self::PERSISTENCE) {
            score += 15;
        }
        if self.contains(Self::DROPPER) {
            score += 15;
        }
        if self.contains(Self::DOWNLOADER) {
            score += 10;
        }
        if self.contains(Self::NETWORK) {
            score += 5;
        }
        if self.contains(Self::PROCESS) {
            score += 5;
        }
        if self.contains(Self::CRYPTO) {
            score += 5;
        }
        if self.contains(Self::SCREENSHOT) {
            score += 10;
        }
        if self.contains(Self::WORM) {
            score += 20;
        }
        score.min(100)
    }
}

// ─── SandboxStatus ───────────────────────────────────────────────────────────

/// Lifecycle state of a sandbox session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxStatus {
    NotStarted,
    Running,
    Finished,
    Timeout,
    Crashed(String),
    PolicyViolation(String),
    ResourceExhausted(String),
}

impl fmt::Display for SandboxStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStarted => write!(f, "not_started"),
            Self::Running => write!(f, "running"),
            Self::Finished => write!(f, "finished"),
            Self::Timeout => write!(f, "timeout"),
            Self::Crashed(msg) => write!(f, "crashed: {msg}"),
            Self::PolicyViolation(msg) => write!(f, "policy_violation: {msg}"),
            Self::ResourceExhausted(msg) => write!(f, "resource_exhausted: {msg}"),
        }
    }
}

// ─── SyscallTrace ─────────────────────────────────────────────────────────────

/// A single system call captured during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallTrace {
    /// Syscall number (platform-specific).
    pub number: u32,
    /// Symbolic name of the syscall (e.g. `"NtCreateFile"`).
    pub name: String,
    /// Arguments as strings.
    pub args: Vec<String>,
    /// Return value (or `None` if the call did not return).
    pub ret: Option<i64>,
    /// Timestamp in milliseconds since sandbox start.
    pub ts_ms: u64,
    /// PID of the calling process.
    pub pid: u32,
    /// TID of the calling thread.
    pub tid: u32,
    /// Whether this call was flagged as suspicious.
    pub flagged: bool,
}

impl SyscallTrace {
    /// Create a new trace entry.
    #[must_use]
    pub fn new(number: u32, name: impl Into<String>, pid: u32, ts_ms: u64) -> Self {
        Self {
            number,
            name: name.into(),
            args: vec![],
            ret: None,
            ts_ms,
            pid,
            tid: 0,
            flagged: false,
        }
    }

    /// Builder — add an argument.
    #[must_use]
    pub fn with_arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    /// Builder — set return value.
    #[must_use]
    pub const fn with_ret(mut self, r: i64) -> Self {
        self.ret = Some(r);
        self
    }

    /// Builder — mark as flagged.
    #[must_use]
    pub const fn flagged(mut self) -> Self {
        self.flagged = true;
        self
    }
}

// ─── NetworkTrace ─────────────────────────────────────────────────────────────

/// A captured network event (connection, send, or receive).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTrace {
    pub proto: NetworkProto,
    pub local_addr: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub ts_ms: u64,
    pub pid: u32,
    pub dns_query: Option<String>,
}

/// Transport protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkProto {
    Tcp,
    Udp,
    Icmp,
    Http,
    Https,
    Dns,
    Other(String),
}

impl fmt::Display for NetworkProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Icmp => write!(f, "icmp"),
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
            Self::Dns => write!(f, "dns"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl NetworkTrace {
    /// Returns `true` if the remote address is external (non-RFC1918 and non-loopback).
    #[must_use]
    pub fn is_external(&self) -> bool {
        let ip = &self.remote_addr;
        !ip.starts_with("127.")
            && !ip.starts_with("192.168.")
            && !ip.starts_with("10.")
            && !{
                // RFC1918: only 172.16.0.0–172.31.255.255 is private
                ip.strip_prefix("172.").is_some_and(|rest| {
                    let second_octet: u8 = rest
                        .split('.')
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    (16..=31).contains(&second_octet)
                })
            }
            && !ip.starts_with("::1")
    }

    /// Returns `true` if the connection is to a common C2 port.
    #[must_use]
    pub const fn is_c2_port(&self) -> bool {
        matches!(
            self.remote_port,
            443 | 80 | 4444 | 8080 | 8443 | 1337 | 6666 | 31337
        )
    }
}

// ─── FileTrace ────────────────────────────────────────────────────────────────

/// File system operation captured during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTrace {
    pub op: FileOp,
    pub path: String,
    pub bytes: u64,
    pub ts_ms: u64,
    pub pid: u32,
    pub success: bool,
}

/// Type of file operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOp {
    Create,
    Open,
    Read,
    Write,
    Delete,
    Rename,
    Copy,
    SetAttributes,
}

impl fmt::Display for FileOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Open => write!(f, "open"),
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Delete => write!(f, "delete"),
            Self::Rename => write!(f, "rename"),
            Self::Copy => write!(f, "copy"),
            Self::SetAttributes => write!(f, "set_attributes"),
        }
    }
}

impl FileTrace {
    /// Returns `true` if this trace looks like a dropper operation.
    #[must_use]
    pub fn is_dropper_op(&self) -> bool {
        matches!(self.op, FileOp::Create | FileOp::Write)
            && (std::path::Path::new(&self.path).extension().is_some_and(|e| e.eq_ignore_ascii_case("exe"))
                || std::path::Path::new(&self.path).extension().is_some_and(|e| e.eq_ignore_ascii_case("dll"))
                || std::path::Path::new(&self.path).extension().is_some_and(|e| e.eq_ignore_ascii_case("bat"))
                || std::path::Path::new(&self.path).extension().is_some_and(|e| e.eq_ignore_ascii_case("ps1"))
                || std::path::Path::new(&self.path).extension().is_some_and(|e| e.eq_ignore_ascii_case("vbs")))
    }
}

// ─── RegistryTrace ────────────────────────────────────────────────────────────

/// Registry operation captured during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryTrace {
    pub op: RegistryOp,
    pub key: String,
    pub value_name: String,
    pub data: Option<String>,
    pub ts_ms: u64,
    pub pid: u32,
}

/// Type of registry operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryOp {
    CreateKey,
    DeleteKey,
    SetValue,
    QueryValue,
    DeleteValue,
}

impl fmt::Display for RegistryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateKey => write!(f, "create_key"),
            Self::DeleteKey => write!(f, "delete_key"),
            Self::SetValue => write!(f, "set_value"),
            Self::QueryValue => write!(f, "query_value"),
            Self::DeleteValue => write!(f, "delete_value"),
        }
    }
}

impl RegistryTrace {
    /// Returns `true` if this operation targets a persistence-related key.
    #[must_use]
    pub fn is_persistence_op(&self) -> bool {
        matches!(self.op, RegistryOp::SetValue | RegistryOp::CreateKey)
            && (self.key.contains("\\Run\\")
                || self.key.contains("\\RunOnce\\")
                || self.key.contains("\\Services\\")
                || self.key.contains("\\Winlogon\\"))
    }
}

// ─── ProcessNode ─────────────────────────────────────────────────────────────

/// A single node in the process tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub parent_pid: u32,
    pub image: String,
    pub cmdline: String,
    pub start_ms: u64,
    pub exit_code: Option<i32>,
    pub children: Vec<u32>,
}

impl ProcessNode {
    /// Create a new process node.
    #[must_use]
    pub fn new(
        pid: u32,
        parent_pid: u32,
        image: impl Into<String>,
        cmdline: impl Into<String>,
        start_ms: u64,
    ) -> Self {
        Self {
            pid,
            parent_pid,
            image: image.into(),
            cmdline: cmdline.into(),
            start_ms,
            exit_code: None,
            children: vec![],
        }
    }

    /// Returns `true` if this process is still running (no exit code set).
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.exit_code.is_none()
    }
}

// ─── ProcessTree ─────────────────────────────────────────────────────────────

/// Process hierarchy captured during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTree {
    pub nodes: HashMap<u32, ProcessNode>,
    pub root_pid: u32,
}

impl ProcessTree {
    /// Create an empty tree rooted at the given PID.
    #[must_use]
    pub fn new(root_pid: u32) -> Self {
        Self {
            nodes: HashMap::new(),
            root_pid,
        }
    }

    /// Insert a process node.
    pub fn insert(&mut self, node: ProcessNode) {
        let child_pid = node.pid;
        let parent_pid = node.parent_pid;
        self.nodes.insert(child_pid, node);
        if let Some(parent) = self.nodes.get_mut(&parent_pid)
            && !parent.children.contains(&child_pid) {
                parent.children.push(child_pid);
            }
    }

    /// Find a node by PID.
    #[must_use]
    pub fn find(&self, pid: u32) -> Option<&ProcessNode> {
        self.nodes.get(&pid)
    }

    /// Total number of processes in the tree.
    #[must_use]
    pub fn process_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return all leaf processes (processes with no children).
    #[must_use]
    pub fn leaves(&self) -> Vec<&ProcessNode> {
        self.nodes
            .values()
            .filter(|n| n.children.is_empty())
            .collect()
    }

    /// Return max depth of the tree via BFS.
    #[must_use]
    pub fn max_depth(&self) -> usize {
        let Some(root) = self.nodes.get(&self.root_pid) else {
            return 0;
        };
        let mut max = 0usize;
        let mut queue = vec![(root, 0usize)];
        while let Some((node, depth)) = queue.pop() {
            if depth > max {
                max = depth;
            }
            for &child_pid in &node.children {
                if let Some(child) = self.nodes.get(&child_pid) {
                    queue.push((child, depth + 1));
                }
            }
        }
        max
    }
}

// ─── BehaviorRecord ───────────────────────────────────────────────────────────

/// Comprehensive record of all observed behaviors during a sandbox run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRecord {
    pub syscalls: Vec<SyscallTrace>,
    pub network: Vec<NetworkTrace>,
    pub files: Vec<FileTrace>,
    pub registry: Vec<RegistryTrace>,
    pub process_tree: ProcessTree,
    pub flags: BehaviorFlag,
    pub log: Vec<String>,
}

impl BehaviorRecord {
    /// Create a new empty record with an initial root PID.
    #[must_use]
    pub fn new(root_pid: u32) -> Self {
        Self {
            syscalls: vec![],
            network: vec![],
            files: vec![],
            registry: vec![],
            process_tree: ProcessTree::new(root_pid),
            flags: BehaviorFlag::empty(),
            log: vec![],
        }
    }

    /// Record a syscall and update flags if it matches known patterns.
    pub fn record_syscall(&mut self, trace: SyscallTrace) {
        // Detect injection-related syscalls.
        if matches!(
            trace.name.as_str(),
            "NtWriteVirtualMemory"
                | "NtCreateThreadEx"
                | "NtMapViewOfSection"
                | "WriteProcessMemory"
                | "CreateRemoteThread"
                | "VirtualAllocEx"
        ) {
            self.flags |= BehaviorFlag::INJECTION;
        }
        // Detect crypto activity.
        if trace.name.contains("Crypt")
            || trace.name.contains("BCrypt")
            || trace.name.contains("RSA")
        {
            self.flags |= BehaviorFlag::CRYPTO;
        }
        // Detect anti-analysis.
        if matches!(
            trace.name.as_str(),
            "NtQueryInformationProcess"
                | "IsDebuggerPresent"
                | "CheckRemoteDebuggerPresent"
                | "NtSetInformationThread"
                | "NtYieldExecution"
        ) {
            self.flags |= BehaviorFlag::ANTIANALYSIS;
        }
        if trace.flagged {
            self.log.push(format!(
                "[FLAGGED] syscall {} pid={}",
                trace.name, trace.pid
            ));
        }
        self.syscalls.push(trace);
    }

    /// Record a network event and update flags.
    pub fn record_network(&mut self, trace: NetworkTrace) {
        self.flags |= BehaviorFlag::NETWORK;
        if trace.is_c2_port() && trace.is_external() {
            self.flags |= BehaviorFlag::C2;
        }
        self.network.push(trace);
    }

    /// Record a file operation and update flags.
    pub fn record_file(&mut self, trace: FileTrace) {
        self.flags |= BehaviorFlag::FILESYSTEM;
        if trace.is_dropper_op() {
            self.flags |= BehaviorFlag::DROPPER;
        }
        self.files.push(trace);
    }

    /// Record a registry operation and update flags.
    pub fn record_registry(&mut self, trace: RegistryTrace) {
        self.flags |= BehaviorFlag::REGISTRY;
        if trace.is_persistence_op() {
            self.flags |= BehaviorFlag::PERSISTENCE;
        }
        self.registry.push(trace);
    }

    /// Add a log message.
    pub fn log(&mut self, msg: impl Into<String>) {
        self.log.push(msg.into());
    }

    /// Count flagged syscalls.
    #[must_use]
    pub fn flagged_syscall_count(&self) -> usize {
        self.syscalls.iter().filter(|s| s.flagged).count()
    }

    /// Count external network connections.
    #[must_use]
    pub fn external_conn_count(&self) -> usize {
        self.network.iter().filter(|n| n.is_external()).count()
    }

    /// Count dropped executables.
    #[must_use]
    pub fn dropped_exe_count(&self) -> usize {
        self.files.iter().filter(|f| f.is_dropper_op()).count()
    }

    /// Count persistence registry operations.
    #[must_use]
    pub fn persistence_op_count(&self) -> usize {
        self.registry
            .iter()
            .filter(|r| r.is_persistence_op())
            .count()
    }

    /// Create a mock record for testing.
    #[must_use]
    pub fn mock() -> Self {
        let mut rec = Self::new(1000);
        // Root process.
        rec.process_tree.insert(ProcessNode::new(
            1000,
            0,
            "malware.exe",
            "malware.exe --silent",
            0,
        ));
        rec.process_tree.insert(ProcessNode::new(
            1001,
            1000,
            "cmd.exe",
            "cmd.exe /c whoami",
            100,
        ));

        rec.record_syscall(
            SyscallTrace::new(40, "VirtualAllocEx", 1000, 50)
                .with_arg("0x1000")
                .flagged(),
        );
        rec.record_syscall(
            SyscallTrace::new(41, "WriteProcessMemory", 1000, 60)
                .with_arg("notepad.exe")
                .with_ret(1)
                .flagged(),
        );
        rec.record_syscall(SyscallTrace::new(42, "CreateRemoteThread", 1000, 70).flagged());
        rec.record_syscall(SyscallTrace::new(10, "IsDebuggerPresent", 1000, 10).with_ret(0));
        rec.record_network(NetworkTrace {
            proto: NetworkProto::Https,
            local_addr: "192.168.1.100:49152".to_string(),
            remote_addr: "185.220.101.1".to_string(),
            remote_port: 443,
            bytes_sent: 256,
            bytes_recv: 1024,
            ts_ms: 200,
            pid: 1000,
            dns_query: Some("c2server.evil".to_string()),
        });
        rec.record_file(FileTrace {
            op: FileOp::Create,
            path: "C:\\Windows\\Temp\\payload.exe".to_string(),
            bytes: 65536,
            ts_ms: 300,
            pid: 1000,
            success: true,
        });
        rec.record_registry(RegistryTrace {
            op: RegistryOp::SetValue,
            key: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware".to_string(),
            value_name: "Malware".to_string(),
            data: Some("C:\\Windows\\Temp\\payload.exe".to_string()),
            ts_ms: 400,
            pid: 1000,
        });
        rec
    }
}

// ─── SandboxConfig ────────────────────────────────────────────────────────────

/// Configuration for a sandbox session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Name or identifier for this configuration.
    pub name: String,
    /// Policy governing what the sandbox allows.
    pub policy: SandboxPolicy,
    /// Architecture of the sandboxed binary.
    pub arch: SandboxArch,
    /// Operating system environment.
    pub os: SandboxOs,
    /// Working directory inside the sandbox.
    pub workdir: String,
    /// Environment variables to inject.
    pub env_vars: HashMap<String, String>,
    /// Whether to capture screenshots during execution.
    pub capture_screenshots: bool,
    /// Whether to record full pcap of network traffic.
    pub capture_pcap: bool,
    /// Whether to record memory dumps on interesting events.
    pub memory_dumps: bool,
    /// Number of seconds to wait after the process exits before collecting results.
    pub settle_secs: u32,
}

/// CPU architecture for the sandboxed binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxArch {
    X86,
    X64,
    Arm,
    Arm64,
    Mips,
}

impl fmt::Display for SandboxArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X64 => write!(f, "x64"),
            Self::Arm => write!(f, "arm"),
            Self::Arm64 => write!(f, "arm64"),
            Self::Mips => write!(f, "mips"),
        }
    }
}

/// Operating system environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxOs {
    Windows10,
    Windows11,
    Windows7,
    Ubuntu22,
    Debian12,
    AndroidApi33,
    MacOs13,
}

impl fmt::Display for SandboxOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows10 => write!(f, "windows10"),
            Self::Windows11 => write!(f, "windows11"),
            Self::Windows7 => write!(f, "windows7"),
            Self::Ubuntu22 => write!(f, "ubuntu22"),
            Self::Debian12 => write!(f, "debian12"),
            Self::AndroidApi33 => write!(f, "android_api33"),
            Self::MacOs13 => write!(f, "macos13"),
        }
    }
}

impl SandboxConfig {
    /// Create a default config for Windows 10 x64.
    #[must_use]
    pub fn windows_default(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            policy: SandboxPolicy::balanced(),
            arch: SandboxArch::X64,
            os: SandboxOs::Windows10,
            workdir: "C:\\Users\\sandbox\\Desktop".to_string(),
            env_vars: HashMap::new(),
            capture_screenshots: false,
            capture_pcap: true,
            memory_dumps: false,
            settle_secs: 5,
        }
    }

    /// Validate the config.
    ///
    /// # Errors
    /// Returns an error if the policy is invalid.
    pub fn validate(&self) -> Result<(), SandboxError> {
        self.policy.validate()
    }
}

// ─── ArtifactCollector ────────────────────────────────────────────────────────

/// Collects artifacts from a sandbox run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactCollector {
    /// Binary artifacts (e.g., dropped files) captured as `(path, data)`.
    pub binaries: Vec<(String, Vec<u8>)>,
    /// Memory dumps captured as `(label, data)`.
    pub memory_dumps: Vec<(String, Vec<u8>)>,
    /// Network captures (PCAP bytes).
    pub pcap: Option<Vec<u8>>,
    /// Screenshot frames as PNG bytes.
    pub screenshots: Vec<Vec<u8>>,
    /// Log lines.
    pub logs: Vec<String>,
    /// Total bytes collected.
    total_bytes: u64,
}

impl ArtifactCollector {
    /// Create an empty collector.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            binaries: vec![],
            memory_dumps: vec![],
            pcap: None,
            screenshots: vec![],
            logs: vec![],
            total_bytes: 0,
        }
    }

    /// Add a binary artifact.
    pub fn add_binary(&mut self, path: impl Into<String>, data: Vec<u8>) {
        self.total_bytes += data.len() as u64;
        self.binaries.push((path.into(), data));
    }

    /// Add a memory dump.
    pub fn add_memory_dump(&mut self, label: impl Into<String>, data: Vec<u8>) {
        self.total_bytes += data.len() as u64;
        self.memory_dumps.push((label.into(), data));
    }

    /// Set the PCAP data.
    pub fn set_pcap(&mut self, pcap: Vec<u8>) {
        self.total_bytes += pcap.len() as u64;
        self.pcap = Some(pcap);
    }

    /// Add a screenshot.
    pub fn add_screenshot(&mut self, png: Vec<u8>) {
        self.total_bytes += png.len() as u64;
        self.screenshots.push(png);
    }

    /// Add a log line.
    pub fn log(&mut self, msg: impl Into<String>) {
        self.logs.push(msg.into());
    }

    /// Total bytes collected across all artifact types.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Number of binary artifacts collected.
    #[must_use]
    pub const fn binary_count(&self) -> usize {
        self.binaries.len()
    }

    /// Find a binary artifact by path (exact match).
    #[must_use]
    pub fn find_binary(&self, path: &str) -> Option<&[u8]> {
        self.binaries
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, d)| d.as_slice())
    }
}

impl Default for ArtifactCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── FilesystemSnapshot ───────────────────────────────────────────────────────

/// A snapshot of filesystem state before or after sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemSnapshot {
    pub label: String,
    pub ts_ms: u64,
    /// Map from path to SHA-256 hash of the file at snapshot time.
    pub files: HashMap<String, String>,
}

impl FilesystemSnapshot {
    /// Create a new snapshot.
    #[must_use]
    pub fn new(label: impl Into<String>, ts_ms: u64) -> Self {
        Self {
            label: label.into(),
            ts_ms,
            files: HashMap::new(),
        }
    }

    /// Add a file entry.
    pub fn add(&mut self, path: impl Into<String>, sha256: impl Into<String>) {
        self.files.insert(path.into(), sha256.into());
    }

    /// Compute the diff between this snapshot and another.
    /// Returns `(added, removed, modified)` path lists.
    #[must_use]
    pub fn diff(&self, other: &Self) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut modified = Vec::new();

        for (path, hash) in &other.files {
            match self.files.get(path) {
                None => added.push(path.clone()),
                Some(old_hash) if old_hash != hash => modified.push(path.clone()),
                _ => {}
            }
        }
        for path in self.files.keys() {
            if !other.files.contains_key(path) {
                removed.push(path.clone());
            }
        }
        (added, removed, modified)
    }

    /// Number of files in this snapshot.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

// ─── SandboxResult ───────────────────────────────────────────────────────────

/// Full result of a sandbox analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResult {
    pub status: SandboxStatus,
    pub behaviors: BehaviorFlag,
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    pub log: Vec<String>,
    pub behavior_record: Option<BehaviorRecord>,
    pub artifacts: ArtifactCollector,
    pub pre_snapshot: Option<FilesystemSnapshot>,
    pub post_snapshot: Option<FilesystemSnapshot>,
    pub threat_score: u32,
}

impl SandboxResult {
    /// Create a clean (empty) result.
    #[must_use]
    pub const fn clean() -> Self {
        Self {
            status: SandboxStatus::Finished,
            behaviors: BehaviorFlag::empty(),
            duration_ms: 0,
            exit_code: Some(0),
            log: vec![],
            behavior_record: None,
            artifacts: ArtifactCollector::new(),
            pre_snapshot: None,
            post_snapshot: None,
            threat_score: 0,
        }
    }

    /// Returns `true` if the sample showed injection, anti-analysis, or both
    /// network and persistence behaviors.
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.behaviors.contains(BehaviorFlag::INJECTION)
            || self.behaviors.contains(BehaviorFlag::ANTIANALYSIS)
            || self.behaviors.contains(BehaviorFlag::RANSOMWARE)
            || self.behaviors.contains(BehaviorFlag::ROOTKIT)
            || (self.behaviors.contains(BehaviorFlag::NETWORK)
                && self.behaviors.contains(BehaviorFlag::PERSISTENCE))
    }

    /// Returns `true` if the sandbox timed out.
    #[must_use]
    pub fn timed_out(&self) -> bool {
        self.status == SandboxStatus::Timeout
    }

    /// Returns the filesystem diff if both snapshots are available.
    #[must_use]
    pub fn fs_diff(&self) -> Option<(Vec<String>, Vec<String>, Vec<String>)> {
        match (&self.pre_snapshot, &self.post_snapshot) {
            (Some(pre), Some(post)) => Some(pre.diff(post)),
            _ => None,
        }
    }

    /// Add a log message.
    pub fn add_log(&mut self, msg: impl Into<String>) {
        self.log.push(msg.into());
    }

    /// Compute and cache the threat score from observed behaviors.
    pub fn compute_threat_score(&mut self) {
        self.threat_score = self.behaviors.threat_score();
    }

    /// Serialize the result to JSON.
    ///
    /// # Errors
    /// Returns a string description of any serialization error.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| e.to_string())
    }

    /// Create a mock result with realistic data.
    #[must_use]
    pub fn mock() -> Self {
        let behaviors = BehaviorFlag::INJECTION
            | BehaviorFlag::NETWORK
            | BehaviorFlag::PERSISTENCE
            | BehaviorFlag::ANTIANALYSIS
            | BehaviorFlag::C2;

        let mut pre = FilesystemSnapshot::new("pre", 0);
        pre.add("C:\\Windows\\System32\\notepad.exe", "abc123");
        pre.add("C:\\Users\\sandbox\\Desktop\\clean.txt", "def456");

        let mut post = FilesystemSnapshot::new("post", 60_000);
        post.add("C:\\Windows\\System32\\notepad.exe", "abc123");
        post.add("C:\\Users\\sandbox\\Desktop\\clean.txt", "def456");
        post.add("C:\\Windows\\Temp\\payload.exe", "deadbeef");
        post.add(
            "C:\\Users\\sandbox\\AppData\\Roaming\\svchost.exe",
            "cafebabe",
        );

        let mut artifacts = ArtifactCollector::new();
        artifacts.add_binary(
            "C:\\Windows\\Temp\\payload.exe",
            vec![0x4d, 0x5a, 0x90, 0x00],
        );
        artifacts.log("Collected dropped executable");
        artifacts.set_pcap(vec![0xd4, 0xc3, 0xb2, 0xa1]);

        let mut result = Self {
            status: SandboxStatus::Finished,
            behaviors,
            duration_ms: 60_000,
            exit_code: Some(0),
            log: vec![
                "Sample spawned successfully".to_string(),
                "Detected anti-debug check".to_string(),
                "Process injection into notepad.exe".to_string(),
                "C2 beacon sent to 185.220.101.1:443".to_string(),
                "Persistence installed in Run key".to_string(),
            ],
            behavior_record: Some(BehaviorRecord::mock()),
            artifacts,
            pre_snapshot: Some(pre),
            post_snapshot: Some(post),
            threat_score: 0,
        };
        result.compute_threat_score();
        result
    }
}

// ─── SandboxSession ───────────────────────────────────────────────────────────

/// Manages the lifecycle of a running sandbox session.
pub struct SandboxSession {
    pub id: String,
    pub config: SandboxConfig,
    pub status: Arc<RwLock<SandboxStatus>>,
    pub behavior_record: Arc<Mutex<BehaviorRecord>>,
    pub artifacts: Arc<Mutex<ArtifactCollector>>,
    elapsed_ms: Arc<AtomicU64>,
}

impl SandboxSession {
    /// Create a new session (not yet started).
    #[must_use]
    pub fn new(id: impl Into<String>, config: SandboxConfig) -> Self {
        Self {
            id: id.into(),
            config,
            status: Arc::new(RwLock::new(SandboxStatus::NotStarted)),
            behavior_record: Arc::new(Mutex::new(BehaviorRecord::new(0))),
            artifacts: Arc::new(Mutex::new(ArtifactCollector::new())),
            elapsed_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Mark the session as started.
    pub fn start(&self) {
        *self.status.write() = SandboxStatus::Running;
    }

    /// Mark the session as finished.
    pub fn finish(&self, exit_code: Option<i32>) {
        let _ = exit_code;
        *self.status.write() = SandboxStatus::Finished;
    }

    /// Mark the session as timed out.
    pub fn timeout(&self) {
        *self.status.write() = SandboxStatus::Timeout;
    }

    /// Get the current session status.
    #[must_use]
    pub fn current_status(&self) -> SandboxStatus {
        self.status.read().clone()
    }

    /// Advance the elapsed time counter.
    pub fn tick_ms(&self, ms: u64) {
        self.elapsed_ms.fetch_add(ms, Ordering::Relaxed);
    }

    /// Current elapsed time in milliseconds.
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms.load(Ordering::Relaxed)
    }

    /// Returns `true` if the session has exceeded its configured timeout.
    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        let timeout_ms = self.config.policy.timeout_secs.saturating_mul(1000);
        self.elapsed_ms() >= timeout_ms
    }

    /// Collect the final result from the session.
    #[must_use]
    pub fn collect_result(&self) -> SandboxResult {
        let status = self.current_status();
        let record = self.behavior_record.lock().clone();
        let behaviors = record.flags;
        let artifacts = self.artifacts.lock().clone();

        let mut result = SandboxResult {
            status,
            behaviors,
            duration_ms: self.elapsed_ms(),
            exit_code: None,
            log: record.log.clone(),
            behavior_record: Some(record),
            artifacts,
            pre_snapshot: None,
            post_snapshot: None,
            threat_score: 0,
        };
        result.compute_threat_score();
        result
    }
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Trait implemented by all sandbox backends.
pub trait Sandbox: Send + Sync {
    /// Return the name of this sandbox backend.
    fn name(&self) -> &str;

    /// Run a binary and return the analysis result.
    ///
    /// # Errors
    /// Returns a `SandboxError` if the sandbox cannot start or the run fails.
    fn run(&self, binary: &str, policy: &SandboxPolicy) -> Result<SandboxResult, SandboxError>;

    /// Returns `true` if this sandbox supports the given architecture string.
    fn supports_arch(&self, arch: &str) -> bool;
}

// ─── MockSandbox ─────────────────────────────────────────────────────────────

/// Mock sandbox that returns a pre-configured result without actually executing anything.
#[derive(Debug, Clone)]
pub struct MockSandbox {
    pub name: String,
    pub result: SandboxResult,
}

impl MockSandbox {
    /// Create a mock sandbox that returns the given result.
    #[must_use]
    pub fn new(name: impl Into<String>, result: SandboxResult) -> Self {
        Self {
            name: name.into(),
            result,
        }
    }

    /// Create a mock sandbox with a clean (benign) result.
    #[must_use]
    pub fn clean(name: impl Into<String>) -> Self {
        Self::new(name, SandboxResult::clean())
    }

    /// Create a mock sandbox with a malicious result.
    #[must_use]
    pub fn malicious(name: impl Into<String>) -> Self {
        Self::new(name, SandboxResult::mock())
    }
}

impl Sandbox for MockSandbox {
    fn name(&self) -> &str {
        &self.name
    }

    fn run(&self, _binary: &str, _policy: &SandboxPolicy) -> Result<SandboxResult, SandboxError> {
        Ok(self.result.clone())
    }

    fn supports_arch(&self, arch: &str) -> bool {
        matches!(arch, "x86" | "x86_64" | "x64" | "arm" | "arm64")
    }
}

impl SandboxBackend for MockSandbox {
    fn name(&self) -> &str {
        &self.name
    }

    fn supports(&self, _os: &SandboxOs, arch: &SandboxArch) -> bool {
        // Keep arch support consistent with the legacy `Sandbox::supports_arch`
        // impl so that registering a `MockSandbox` via either trait hierarchy
        // (`SandboxManager` or `SandboxOrchestratorV2`) reports the same set of
        // supported architectures.
        let arch_str = match arch {
            SandboxArch::X86 => "x86",
            SandboxArch::X64 => "x86_64",
            SandboxArch::Arm => "arm",
            SandboxArch::Arm64 => "arm64",
            SandboxArch::Mips => return false,
        };
        <Self as Sandbox>::supports_arch(self, arch_str)
    }

    fn submit(&self, job: &SandboxJob) -> Result<JobHandle, SandboxError> {
        // Honor the job's declared architecture so that submission semantics
        // align with the legacy `Sandbox::run` path (which is policy-driven).
        // Without this check the two trait impls diverge: `SandboxBackend::submit`
        // would happily accept jobs for architectures `supports_arch` rejects.
        if !self.supports(&job.os_profile, &job.arch) {
            return Err(SandboxError::InvalidConfig(format!(
                "unsupported arch: {:?}",
                job.arch
            )));
        }
        // Derive a per-job handle id so that `collect` is unambiguous when
        // multiple jobs are submitted concurrently.
        Ok(JobHandle::new(
            format!("mock-{}-{}", self.name, job.id),
            self.name.clone(),
        ))
    }

    fn status(&self, _handle: &JobHandle) -> Result<LiveJobStatus, SandboxError> {
        Ok(LiveJobStatus::Completed)
    }

    fn collect(&self, _handle: &JobHandle) -> Result<SandboxResult, SandboxError> {
        Ok(self.result.clone())
    }

    fn cancel(&self, _handle: &JobHandle) -> Result<(), SandboxError> {
        Ok(())
    }
}

// ─── SandboxBackendAdapter ────────────────────────────────────────────────────

/// Bridges a legacy [`Sandbox`] into the [`SandboxBackend`] trait.
///
/// Allows existing `Sandbox` impls (including `MockSandbox`) to be registered
/// with [`SandboxOrchestratorV2`] without duplication. Submitted jobs are
/// stored in an in-memory map keyed by handle ID so that `status` / `collect`
/// / `cancel` work correctly after `submit`.
pub struct SandboxBackendAdapter<S: Sandbox> {
    inner: S,
    jobs: std::sync::Mutex<std::collections::HashMap<String, SandboxResult>>,
}

impl<S: Sandbox> SandboxBackendAdapter<S> {
    /// Wrap a [`Sandbox`] implementation.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            jobs: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl<S: Sandbox + Send + Sync> SandboxBackend for SandboxBackendAdapter<S> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn supports(&self, _os: &SandboxOs, arch: &SandboxArch) -> bool {
        let arch_str = match arch {
            SandboxArch::X86 => "x86",
            SandboxArch::X64 => "x64",
            SandboxArch::Arm => "arm",
            SandboxArch::Arm64 => "arm64",
            SandboxArch::Mips => "mips",
        };
        self.inner.supports_arch(arch_str)
    }

    fn submit(&self, job: &SandboxJob) -> Result<JobHandle, SandboxError> {
        // Delegate to the legacy Sandbox::run interface using a default policy.
        let policy = SandboxPolicy::balanced();
        let result = self.inner.run(&job.filename, &policy)?;
        let handle = JobHandle::new(self.inner.name().to_string(), job.id.clone());
        if let Ok(mut map) = self.jobs.lock() {
            map.insert(job.id.clone(), result);
        }
        Ok(handle)
    }

    fn status(&self, handle: &JobHandle) -> Result<LiveJobStatus, SandboxError> {
        let map = self
            .jobs
            .lock()
            .map_err(|_| SandboxError::Io("lock poisoned".into()))?;
        if map.contains_key(&handle.id) {
            Ok(LiveJobStatus::Completed)
        } else {
            Ok(LiveJobStatus::Running { started_at: 0, progress_pct: 0 })
        }
    }

    fn collect(&self, handle: &JobHandle) -> Result<SandboxResult, SandboxError> {
        let map = self
            .jobs
            .lock()
            .map_err(|_| SandboxError::Io("lock poisoned".into()))?;
        map.get(&handle.id)
            .cloned()
            .ok_or_else(|| SandboxError::SpawnFailed(format!("job {} not found", handle.id)))
    }

    fn cancel(&self, handle: &JobHandle) -> Result<(), SandboxError> {
        self.jobs
            .lock()
            .map_err(|_| SandboxError::Io("lock poisoned".into()))?
            .remove(&handle.id);
        Ok(())
    }
}

// ─── SandboxManager ───────────────────────────────────────────────────────────

/// Manages multiple sandbox backends and dispatches analysis tasks.
pub struct SandboxManager {
    backends: Vec<Box<dyn Sandbox>>,
    session_counter: AtomicU64,
}

impl SandboxManager {
    /// Create an empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            backends: vec![],
            session_counter: AtomicU64::new(0),
        }
    }

    /// Register a sandbox backend.
    pub fn register(&mut self, backend: Box<dyn Sandbox>) {
        self.backends.push(backend);
    }

    /// Find a backend by name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&dyn Sandbox> {
        self.backends
            .iter()
            .find(|b| b.name() == name)
            .map(std::convert::AsRef::as_ref)
    }

    /// Return the number of registered backends.
    #[must_use]
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// Generate a unique session ID.
    #[must_use]
    pub fn next_session_id(&self) -> String {
        let n = self.session_counter.fetch_add(1, Ordering::Relaxed);
        format!("session-{n:08x}")
    }

    /// Run a binary on the first backend that supports the given architecture.
    ///
    /// # Errors
    /// Returns `SandboxError::NotRunning` (repurposed as "no backend") if no
    /// compatible backend is found, or the backend's own error.
    pub fn run_on_arch(
        &self,
        binary: &str,
        arch: &str,
        policy: &SandboxPolicy,
    ) -> Result<SandboxResult, SandboxError> {
        let backend = self
            .backends
            .iter()
            .find(|b| b.supports_arch(arch))
            .ok_or_else(|| SandboxError::SpawnFailed(format!("no backend for arch {arch}")))?;
        backend.run(binary, policy)
    }
}

impl Default for SandboxManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── JobStatus ────────────────────────────────────────────────────────────────

/// Status of a submitted batch job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Completed(SandboxStatus),
    Failed(String),
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed(s) => write!(f, "completed:{s}"),
            Self::Failed(e) => write!(f, "failed:{e}"),
        }
    }
}

// ─── IocCollection ────────────────────────────────────────────────────────────

/// Indicators of Compromise extracted from a sandbox result.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocCollection {
    /// IP addresses observed in network traces.
    pub ips: Vec<String>,
    /// Domain names from DNS queries.
    pub domains: Vec<String>,
    /// URLs reconstructed from HTTP/HTTPS connections.
    pub urls: Vec<String>,
    /// SHA-256 hashes of dropped files.
    pub file_hashes: Vec<String>,
    /// Dropped file paths.
    pub dropped_paths: Vec<String>,
    /// Registry keys written for persistence.
    pub registry_keys: Vec<String>,
    /// Mutexes or named objects created.
    pub mutexes: Vec<String>,
}

impl IocCollection {
    /// Create an empty collection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of IOCs across all categories.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.ips.len()
            + self.domains.len()
            + self.urls.len()
            + self.file_hashes.len()
            + self.dropped_paths.len()
            + self.registry_keys.len()
            + self.mutexes.len()
    }

    /// Returns `true` if no IOCs were collected.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// Merge another collection into this one, deduplicating all fields.
    pub fn merge(&mut self, other: &Self) {
        fn dedup_extend(dest: &mut Vec<String>, src: &[String]) {
            for item in src {
                if !dest.contains(item) {
                    dest.push(item.clone());
                }
            }
        }
        dedup_extend(&mut self.ips, &other.ips);
        dedup_extend(&mut self.domains, &other.domains);
        dedup_extend(&mut self.urls, &other.urls);
        dedup_extend(&mut self.file_hashes, &other.file_hashes);
        dedup_extend(&mut self.dropped_paths, &other.dropped_paths);
        dedup_extend(&mut self.registry_keys, &other.registry_keys);
        dedup_extend(&mut self.mutexes, &other.mutexes);
    }
}

// ─── SandboxOrchestrator ─────────────────────────────────────────────────────

/// Manages batch submission of samples to sandbox backends, job tracking, and
/// IOC collection from completed analyses.
pub struct SandboxOrchestrator {
    manager: SandboxManager,
    /// In-flight and completed jobs: `job_id` → (status, result).
    jobs: parking_lot::RwLock<HashMap<String, (JobStatus, Option<SandboxResult>)>>,
    job_counter: std::sync::atomic::AtomicU64,
}

impl SandboxOrchestrator {
    /// Create a new orchestrator wrapping a `SandboxManager`.
    #[must_use]
    pub fn new(manager: SandboxManager) -> Self {
        Self {
            manager,
            jobs: parking_lot::RwLock::new(HashMap::new()),
            job_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create an orchestrator with a single mock backend (useful for tests).
    #[must_use]
    pub fn with_mock_backend(name: impl Into<String>, result: SandboxResult) -> Self {
        let mut manager = SandboxManager::new();
        manager.register(Box::new(MockSandbox::new(name, result)));
        Self::new(manager)
    }

    /// Generate a unique job ID.
    fn next_job_id(&self) -> String {
        let n = self
            .job_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("job-{n:08x}")
    }

    /// Submit multiple sample paths for analysis with the given config.
    ///
    /// Each sample is submitted synchronously using the first suitable backend.
    /// Returns a list of job IDs in the same order as `samples`.
    #[must_use]
    pub fn submit_batch(
        &self,
        samples: Vec<std::path::PathBuf>,
        config: SandboxConfig,
    ) -> Vec<String> {
        let mut ids = Vec::with_capacity(samples.len());
        let arch = config.arch.to_string();
        let policy = config.policy;

        for sample in samples {
            let id = self.next_job_id();
            let sample_str = sample.to_string_lossy().to_string();

            // Mark as running immediately.
            self.jobs
                .write()
                .insert(id.clone(), (JobStatus::Running, None));

            let status_and_result = match self.manager.run_on_arch(&sample_str, &arch, &policy) {
                Ok(result) => {
                    let s = result.status.clone();
                    (JobStatus::Completed(s), Some(result))
                }
                Err(e) => (JobStatus::Failed(e.to_string()), None),
            };

            self.jobs.write().insert(id.clone(), status_and_result);
            ids.push(id);
        }
        ids
    }

    /// Wait for a set of jobs to finish, polling until all are in a terminal
    /// state or `timeout` elapses.  Returns a map of `job_id → JobStatus`.
    ///
    /// Because sandbox execution in this implementation is synchronous,
    /// jobs submitted via `submit_batch` are already complete by the time
    /// this function is called.  The timeout logic is kept for API
    /// completeness and future async backends.
    #[must_use]
    pub fn wait_for_jobs(
        &self,
        job_ids: &[String],
        timeout: std::time::Duration,
    ) -> HashMap<String, JobStatus> {
        let deadline = std::time::Instant::now() + timeout;
        let mut result = HashMap::new();

        for id in job_ids {
            loop {
                let status = self
                    .jobs
                    .read()
                    .get(id)
                    .map_or_else(|| JobStatus::Failed("unknown job".to_string()), |(s, _)| s.clone());

                let terminal = matches!(status, JobStatus::Completed(_) | JobStatus::Failed(_));
                result.insert(id.clone(), status);
                if terminal || std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        result
    }

    /// Retrieve the result for a completed job.
    #[must_use]
    pub fn get_result(&self, job_id: &str) -> Option<SandboxResult> {
        self.jobs.read().get(job_id).and_then(|(_, r)| r.clone())
    }

    /// Extract all IOCs from a `SandboxResult`.
    ///
    /// Collects IPs and domains from network traces, dropped paths and hashes
    /// from the artifact collector, and registry persistence keys.
    #[must_use]
    pub fn collect_iocs(result: &SandboxResult) -> IocCollection {
        let mut iocs = IocCollection::new();

        // Network IOCs.
        if let Some(rec) = &result.behavior_record {
            for net in &rec.network {
                let ip = net.remote_addr.clone();
                if net.is_external() && !iocs.ips.contains(&ip) {
                    iocs.ips.push(ip);
                }
                if let Some(domain) = &net.dns_query
                    && !iocs.domains.contains(domain) {
                        iocs.domains.push(domain.clone());
                    }
                // Reconstruct URL for HTTP/HTTPS connections.
                if matches!(net.proto, NetworkProto::Http | NetworkProto::Https) {
                    let scheme = net.proto.to_string();
                    let url = format!("{}://{}:{}", scheme, net.remote_addr, net.remote_port);
                    if !iocs.urls.contains(&url) {
                        iocs.urls.push(url);
                    }
                }
            }

            // Registry persistence IOCs.
            for reg in &rec.registry {
                if reg.is_persistence_op() {
                    let key = reg.key.clone();
                    if !iocs.registry_keys.contains(&key) {
                        iocs.registry_keys.push(key);
                    }
                }
            }
        }

        // Dropped file IOCs from artifact collector.
        for (path, data) in &result.artifacts.binaries {
            if !iocs.dropped_paths.contains(path) {
                iocs.dropped_paths.push(path.clone());
            }
            // Simple hash placeholder — in production a real SHA-256 would be computed.
            let hash = format!(
                "{:08x}{:08x}",
                data.len(),
                data.iter()
                    .fold(0u64, |a, &b| a.wrapping_mul(31).wrapping_add(u64::from(b)))
            );
            if !iocs.file_hashes.contains(&hash) {
                iocs.file_hashes.push(hash);
            }
        }

        // Filesystem diff IOCs.
        if let Some((added, _, _)) = result.fs_diff() {
            for path in added {
                if (std::path::Path::new(&path).extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")) || std::path::Path::new(&path).extension().is_some_and(|e| e.eq_ignore_ascii_case("dll")))
                    && !iocs.dropped_paths.contains(&path) {
                        iocs.dropped_paths.push(path);
                    }
            }
        }

        iocs
    }
}

// ─── BehaviorSignature ────────────────────────────────────────────────────────

/// A single named behavioral signature used for pattern matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorSignature {
    /// Short identifier (e.g., `"run_key_persistence"`).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of what this signature detects.
    pub description: String,
    /// Syscall/API names that must be present (any of them).
    pub syscall_patterns: Vec<String>,
    /// Registry key substrings that indicate a match.
    pub registry_patterns: Vec<String>,
    /// File extension patterns that indicate a match.
    pub file_patterns: Vec<String>,
    /// `BehaviorFlag` bits that must be set.
    pub required_flags: BehaviorFlag,
    /// Severity score contribution (0–30).
    pub severity: u8,
}

impl BehaviorSignature {
    /// Returns `true` if this signature matches the given behavior record.
    #[must_use]
    pub fn matches(&self, record: &BehaviorRecord) -> bool {
        // Check required behavior flags.
        if !self.required_flags.is_empty() && !record.flags.contains(self.required_flags) {
            return false;
        }

        // Check syscall patterns — at least one must appear.
        if !self.syscall_patterns.is_empty() {
            let found = record.syscalls.iter().any(|s| {
                self.syscall_patterns
                    .iter()
                    .any(|p| s.name.contains(p.as_str()))
            });
            if !found {
                return false;
            }
        }

        // Check registry patterns — at least one must match.
        if !self.registry_patterns.is_empty() {
            let found = record.registry.iter().any(|r| {
                self.registry_patterns
                    .iter()
                    .any(|p| r.key.contains(p.as_str()))
            });
            if !found {
                return false;
            }
        }

        // Check file patterns — at least one must match a created/written file.
        if !self.file_patterns.is_empty() {
            let found = record.files.iter().any(|f| {
                matches!(f.op, FileOp::Create | FileOp::Write)
                    && self
                        .file_patterns
                        .iter()
                        .any(|p| f.path.contains(p.as_str()))
            });
            if !found {
                return false;
            }
        }

        true
    }
}

// ─── BehaviorSignatureDb ─────────────────────────────────────────────────────

/// Database of built-in behavioral signatures for common malware patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorSignatureDb {
    pub signatures: Vec<BehaviorSignature>,
}

impl BehaviorSignatureDb {
    /// Create an empty database.
    #[must_use]
    pub const fn new() -> Self {
        Self { signatures: vec![] }
    }

    /// Load the built-in set of 20+ behavioral signatures.
    #[must_use]
    pub fn load_builtin() -> Self {
        let signatures = vec![
            // 1. Persistence via Run key
            BehaviorSignature {
                id: "run_key_persistence".to_string(),
                name: "Run Key Persistence".to_string(),
                description: "Writes to HKCU/HKLM Run or RunOnce registry keys for autostart.".to_string(),
                syscall_patterns: vec![], // registry_patterns check is sufficient
                registry_patterns: vec!["\\Run\\".to_string(), "\\RunOnce\\".to_string()],
                file_patterns: vec![],
                required_flags: BehaviorFlag::REGISTRY,
                severity: 15,
            },
            // 2. Process injection
            BehaviorSignature {
                id: "process_injection".to_string(),
                name: "Process Injection".to_string(),
                description: "Classic VirtualAllocEx → WriteProcessMemory → CreateRemoteThread injection chain.".to_string(),
                syscall_patterns: vec!["VirtualAllocEx".to_string(), "WriteProcessMemory".to_string(), "CreateRemoteThread".to_string()],
                registry_patterns: vec![],
                file_patterns: vec![],
                required_flags: BehaviorFlag::INJECTION,
                severity: 25,
            },
            // 3. Credential harvesting via lsass
            BehaviorSignature {
                id: "credential_harvesting".to_string(),
                name: "Credential Harvesting (LSASS)".to_string(),
                description: "Opens lsass.exe process with read access to harvest credentials.".to_string(),
                syscall_patterns: vec!["OpenProcess".to_string(), "ReadProcessMemory".to_string()],
                registry_patterns: vec![],
                file_patterns: vec!["lsass".to_string()],
                required_flags: BehaviorFlag::PROCESS,
                severity: 28,
            },
            // 4. Ransomware — mass file encryption + ransom note
            BehaviorSignature {
                id: "ransomware".to_string(),
                name: "Ransomware Encryption + Ransom Note".to_string(),
                description: "Encrypts many files and drops a ransom note.".to_string(),
                syscall_patterns: vec!["CryptEncrypt".to_string(), "BCryptEncrypt".to_string()],
                registry_patterns: vec![],
                file_patterns: vec!["README".to_string(), "HOW_TO_DECRYPT".to_string(), "DECRYPT".to_string()],
                required_flags: BehaviorFlag::RANSOMWARE | BehaviorFlag::CRYPTO,
                severity: 30,
            },
            // 5. C2 beacon (periodic HTTP/DNS)
            BehaviorSignature {
                id: "c2_beacon".to_string(),
                name: "C2 Beacon (HTTP/DNS)".to_string(),
                description: "Establishes periodic outbound HTTP or DNS connection to a remote host.".to_string(),
                syscall_patterns: vec!["InternetConnect".to_string(), "WinHttpSendRequest".to_string(), "DnsQuery".to_string()],
                registry_patterns: vec![],
                file_patterns: vec![],
                required_flags: BehaviorFlag::C2,
                severity: 20,
            },
        ];
        let mut db = Self { signatures };
        db.signatures.extend(Self::builtin_sigs_part1b());
        db.signatures.extend(Self::builtin_sigs_part2());
        db.signatures.extend(Self::builtin_sigs_part3());
        db
    }

    fn builtin_sigs_part1b() -> Vec<BehaviorSignature> {
        vec![
            // 6. Domain generation algorithm (DGA)
            BehaviorSignature {
                id: "dga".to_string(),
                name: "Domain Generation Algorithm".to_string(),
                description: "Issues many distinct DNS queries suggesting DGA C2.".to_string(),
                syscall_patterns: vec!["DnsQuery".to_string(), "getaddrinfo".to_string(), "gethostbyname".to_string()],
                registry_patterns: vec![],
                file_patterns: vec![],
                required_flags: BehaviorFlag::NETWORK,
                severity: 18,
            },
            // 7. UAC bypass
            BehaviorSignature {
                id: "uac_bypass".to_string(),
                name: "UAC Bypass".to_string(),
                description: "Attempts to bypass User Account Control using fodhelper, eventvwr, or registry hijack.".to_string(),
                syscall_patterns: vec!["ShellExecute".to_string(), "CreateProcess".to_string()],
                registry_patterns: vec!["\\ms-settings\\".to_string(), "\\mscfile\\".to_string()],
                file_patterns: vec!["fodhelper".to_string(), "eventvwr".to_string()],
                required_flags: BehaviorFlag::PROCESS,
                severity: 22,
            },
            // 8. Anti-VM evasion
            BehaviorSignature {
                id: "anti_vm".to_string(),
                name: "Anti-VM / Sandbox Evasion".to_string(),
                description: "Checks for VM artifacts, debugger presence, or hardware fingerprints.".to_string(),
                syscall_patterns: vec!["IsDebuggerPresent".to_string(), "NtQueryInformationProcess".to_string(), "CheckRemoteDebuggerPresent".to_string()],
                registry_patterns: vec!["HARDWARE\\ACPI\\DSDT\\VBOX".to_string(), "SOFTWARE\\VMware".to_string()],
                file_patterns: vec!["vmtoolsd".to_string(), "vboxservice".to_string()],
                required_flags: BehaviorFlag::ANTIANALYSIS,
                severity: 18,
            },
            // 9. Lateral movement (SMB/WMI/PsExec)
            BehaviorSignature {
                id: "lateral_movement".to_string(),
                name: "Lateral Movement (SMB/WMI/PsExec)".to_string(),
                description: "Connects to SMB shares or uses WMI / PsExec to spread.".to_string(),
                syscall_patterns: vec!["WNetAddConnection".to_string(), "NetUseAdd".to_string()],
                registry_patterns: vec![],
                file_patterns: vec!["\\\\".to_string(), "psexec".to_string()],
                required_flags: BehaviorFlag::NETWORK | BehaviorFlag::PROCESS,
                severity: 22,
            },
            // 10. Keylogger (SetWindowsHookEx + clipboard)
            BehaviorSignature {
                id: "keylogger".to_string(),
                name: "Keylogger".to_string(),
                description: "Installs a global keyboard hook or polls the clipboard for credential capture.".to_string(),
                syscall_patterns: vec!["SetWindowsHookEx".to_string(), "GetAsyncKeyState".to_string(), "OpenClipboard".to_string()],
                registry_patterns: vec![],
                file_patterns: vec![],
                required_flags: BehaviorFlag::KEYLOGGER,
                severity: 22,
            },
            // 11. Download and execute
            BehaviorSignature {
                id: "download_and_execute".to_string(),
                name: "Download and Execute".to_string(),
                description: "Downloads a remote file and executes it as a new process.".to_string(),
                syscall_patterns: vec!["URLDownloadToFile".to_string(), "InternetReadFile".to_string()],
                registry_patterns: vec![],
                file_patterns: vec![".exe".to_string(), ".dll".to_string()],
                required_flags: BehaviorFlag::DOWNLOADER | BehaviorFlag::NETWORK,
                severity: 20,
            },
        ]
    }

    fn builtin_sigs_part2() -> Vec<BehaviorSignature> {
        vec![
            // 12. Startup folder persistence
            BehaviorSignature {
                id: "startup_folder".to_string(),
                name: "Startup Folder Persistence".to_string(),
                description: "Drops a file into the Windows Startup folder for autorun on logon.".to_string(),
                syscall_patterns: vec!["CreateFile".to_string(), "WriteFile".to_string()],
                registry_patterns: vec![],
                file_patterns: vec!["Startup".to_string(), "Start Menu".to_string()],
                required_flags: BehaviorFlag::FILESYSTEM | BehaviorFlag::PERSISTENCE,
                severity: 15,
            },
            // 13. Registry hiding (HKLM startup)
            BehaviorSignature {
                id: "hklm_startup".to_string(),
                name: "HKLM Startup Registry Hiding".to_string(),
                description: "Writes to HKLM Run key, requiring elevation, to persist as all users.".to_string(),
                syscall_patterns: vec!["RegSetValue".to_string()],
                registry_patterns: vec!["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()],
                file_patterns: vec![],
                required_flags: BehaviorFlag::REGISTRY | BehaviorFlag::PERSISTENCE,
                severity: 18,
            },
            // 14. Network enumeration
            BehaviorSignature {
                id: "network_enum".to_string(),
                name: "Network Enumeration".to_string(),
                description: "Scans network neighbors using ARP, ICMP, or NetBIOS enumeration APIs.".to_string(),
                syscall_patterns: vec!["NetViewEnum".to_string(), "GetAdaptersInfo".to_string(), "IcmpSendEcho".to_string()],
                registry_patterns: vec![],
                file_patterns: vec![],
                required_flags: BehaviorFlag::NETWORK | BehaviorFlag::WORM,
                severity: 15,
            },
            // 15. Shadow copy deletion
            BehaviorSignature {
                id: "shadow_copy_deletion".to_string(),
                name: "Shadow Copy Deletion".to_string(),
                description: "Executes vssadmin or WMI to delete Volume Shadow Copies.".to_string(),
                syscall_patterns: vec!["CreateProcess".to_string(), "WMIExec".to_string()],
                registry_patterns: vec![],
                file_patterns: vec!["vssadmin".to_string(), "wmic".to_string()],
                required_flags: BehaviorFlag::RANSOMWARE,
                severity: 28,
            },
            // 16. Token impersonation
            BehaviorSignature {
                id: "token_impersonation".to_string(),
                name: "Token Impersonation / Privilege Escalation".to_string(),
                description: "Steals or duplicates a privileged token to escalate privileges.".to_string(),
                syscall_patterns: vec!["ImpersonateLoggedOnUser".to_string(), "DuplicateTokenEx".to_string(), "AdjustTokenPrivileges".to_string()],
                registry_patterns: vec![],
                file_patterns: vec![],
                required_flags: BehaviorFlag::PROCESS,
                severity: 22,
            },
        ]
    }

    fn builtin_sigs_part3() -> Vec<BehaviorSignature> {
        vec![
            // 17. Rootkit driver load
            BehaviorSignature {
                id: "rootkit_driver".to_string(),
                name: "Rootkit Driver Loading".to_string(),
                description: "Installs a kernel-mode driver via NtLoadDriver or SC Manager.".to_string(),
                syscall_patterns: vec!["NtLoadDriver".to_string(), "CreateService".to_string()],
                registry_patterns: vec!["\\SYSTEM\\CurrentControlSet\\Services\\".to_string()],
                file_patterns: vec![".sys".to_string()],
                required_flags: BehaviorFlag::ROOTKIT,
                severity: 30,
            },
            // 18. Screenshot capture
            BehaviorSignature {
                id: "screenshot_capture".to_string(),
                name: "Screenshot Capture".to_string(),
                description: "Captures the desktop using GDI BitBlt or PrintWindow.".to_string(),
                syscall_patterns: vec!["BitBlt".to_string(), "PrintWindow".to_string(), "GetDC".to_string()],
                registry_patterns: vec![],
                file_patterns: vec![".bmp".to_string(), ".png".to_string(), ".jpg".to_string()],
                required_flags: BehaviorFlag::SCREENSHOT,
                severity: 12,
            },
            // 19. Worm self-replication
            BehaviorSignature {
                id: "worm_replication".to_string(),
                name: "Worm Self-Replication".to_string(),
                description: "Copies itself to removable drives or network shares.".to_string(),
                syscall_patterns: vec!["CopyFile".to_string(), "GetDriveType".to_string()],
                registry_patterns: vec![],
                file_patterns: vec!["autorun.inf".to_string()],
                required_flags: BehaviorFlag::WORM,
                severity: 20,
            },
            // 20. Fileless execution via PowerShell
            BehaviorSignature {
                id: "fileless_powershell".to_string(),
                name: "Fileless Execution via PowerShell".to_string(),
                description: "Encodes and executes a PowerShell payload entirely in memory.".to_string(),
                syscall_patterns: vec!["CreateProcess".to_string(), "VirtualAlloc".to_string()],
                registry_patterns: vec![],
                file_patterns: vec!["powershell".to_string()],
                required_flags: BehaviorFlag::PROCESS,
                severity: 20,
            },
            // 21. DNS tunneling
            BehaviorSignature {
                id: "dns_tunneling".to_string(),
                name: "DNS Tunneling".to_string(),
                description: "Encodes data in DNS TXT/CNAME queries to exfiltrate or receive commands.".to_string(),
                syscall_patterns: vec!["DnsQuery".to_string(), "sendto".to_string()],
                registry_patterns: vec![],
                file_patterns: vec![],
                required_flags: BehaviorFlag::NETWORK | BehaviorFlag::C2,
                severity: 22,
            },
            // 22. Clipboard hijacking
            BehaviorSignature {
                id: "clipboard_hijack".to_string(),
                name: "Clipboard Hijacking".to_string(),
                description: "Monitors and modifies clipboard content (e.g., to replace crypto addresses).".to_string(),
                syscall_patterns: vec!["OpenClipboard".to_string(), "SetClipboardData".to_string(), "GetClipboardData".to_string()],
                registry_patterns: vec![],
                file_patterns: vec![],
                required_flags: BehaviorFlag::KEYLOGGER,
                severity: 15,
            },
        ]
    }

    /// Add a custom signature.
    pub fn add(&mut self, sig: BehaviorSignature) {
        self.signatures.push(sig);
    }

    /// Match all signatures against the given behavior record.
    /// Returns IDs of all matching signatures.
    #[must_use]
    pub fn match_all(&self, record: &BehaviorRecord) -> Vec<&BehaviorSignature> {
        self.signatures
            .iter()
            .filter(|s| s.matches(record))
            .collect()
    }

    /// Total severity score from all matching signatures (capped at 100).
    #[must_use]
    pub fn score(&self, record: &BehaviorRecord) -> u32 {
        self.match_all(record)
            .iter()
            .map(|s| u32::from(s.severity))
            .sum::<u32>()
            .min(100)
    }

    /// Number of signatures in the database.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Returns `true` if the database has no signatures.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

impl Default for BehaviorSignatureDb {
    fn default() -> Self {
        Self::new()
    }
}

// ─── MalwareCategory ─────────────────────────────────────────────────────────

/// High-level malware family category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MalwareCategory {
    Ransomware,
    Rat,
    InfoStealer,
    Dropper,
    Banker,
    Worm,
    Adware,
    Coinminer,
    Rootkit,
    Unknown,
}

impl fmt::Display for MalwareCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ransomware => write!(f, "ransomware"),
            Self::Rat => write!(f, "rat"),
            Self::InfoStealer => write!(f, "info_stealer"),
            Self::Dropper => write!(f, "dropper"),
            Self::Banker => write!(f, "banker"),
            Self::Worm => write!(f, "worm"),
            Self::Adware => write!(f, "adware"),
            Self::Coinminer => write!(f, "coinminer"),
            Self::Rootkit => write!(f, "rootkit"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── MalwareClassification ───────────────────────────────────────────────────

/// Output of the `MalwareFamilyClassifier`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareClassification {
    /// Known family name if detected (e.g., `"WannaCry"`, `"Emotet"`).
    pub family: Option<String>,
    /// Broad category of the detected malware.
    pub category: MalwareCategory,
    /// Confidence in the classification (0.0–1.0).
    pub confidence: f32,
    /// Human-readable evidence items that drove the classification.
    pub evidence: Vec<String>,
}

impl MalwareClassification {
    /// Returns `true` if the classification is high-confidence (≥ 0.7).
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.7
    }

    /// Returns `true` if the sample was positively identified as malicious.
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        !matches!(self.category, MalwareCategory::Unknown)
    }
}

// ─── MalwareFamilyClassifier ─────────────────────────────────────────────────

/// Classifies a sample into a malware family and category using behavioral
/// flags, YARA matches, and signature scoring.
#[derive(Debug, Clone, Default)]
pub struct MalwareFamilyClassifier;

impl MalwareFamilyClassifier {
    /// Create a new classifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Classify a sandbox result using behavioral flags and YARA matches.
    ///
    /// The heuristic scoring prioritises specific YARA-identified families first,
    /// then falls back to flag-based category detection.
    #[must_use]
    pub fn classify(result: &SandboxResult, yara_matches: &[String]) -> MalwareClassification {
        let flags = result.behaviors;
        let mut evidence = Vec::new();
        let mut confidence: f32 = 0.0;
        let mut category = MalwareCategory::Unknown;
        let mut family: Option<String> = None;

        // ── YARA family matching (highest priority) ──────────────────────────
        // Common family name substrings mapped to (category, family, confidence boost).
        let known_families: &[(&str, MalwareCategory, &str, f32)] = &[
            ("wannacry", MalwareCategory::Ransomware, "WannaCry", 0.95),
            ("ryuk", MalwareCategory::Ransomware, "Ryuk", 0.95),
            ("lockbit", MalwareCategory::Ransomware, "LockBit", 0.95),
            ("emotet", MalwareCategory::Banker, "Emotet", 0.93),
            ("trickbot", MalwareCategory::Banker, "TrickBot", 0.93),
            ("cobalt", MalwareCategory::Rat, "CobaltStrike", 0.90),
            ("meterprete", MalwareCategory::Rat, "Meterpreter", 0.90),
            ("remcos", MalwareCategory::Rat, "Remcos", 0.88),
            ("njrat", MalwareCategory::Rat, "njRAT", 0.88),
            ("dridex", MalwareCategory::Banker, "Dridex", 0.90),
            ("mirai", MalwareCategory::Worm, "Mirai", 0.90),
            ("xmrig", MalwareCategory::Coinminer, "XMRig", 0.92),
            ("redline", MalwareCategory::InfoStealer, "RedLine", 0.88),
            ("vidar", MalwareCategory::InfoStealer, "Vidar", 0.88),
            ("formbook", MalwareCategory::InfoStealer, "Formbook", 0.88),
            ("azorult", MalwareCategory::InfoStealer, "AZORult", 0.85),
        ];

        'yara: for m in yara_matches {
            let lower = m.to_lowercase();
            for (pattern, cat, fam, conf) in known_families {
                if lower.contains(pattern) {
                    category = cat.clone();
                    family = Some((*fam).to_string());
                    confidence = *conf;
                    evidence.push(format!("YARA match: {m}"));
                    break 'yara;
                }
            }
        }

        // ── Flag-based category heuristics (if YARA didn't match) ────────────
        if matches!(category, MalwareCategory::Unknown) {
            Self::classify_by_flags(flags, result.threat_score, &mut category, &mut confidence, &mut evidence);
        }

        // ── Additional evidence from behavior flags ───────────────────────────
        if flags.contains(BehaviorFlag::ANTIANALYSIS) {
            evidence.push("anti-analysis / sandbox evasion detected".to_string());
            confidence = (confidence + 0.05).min(1.0);
        }
        if flags.contains(BehaviorFlag::PERSISTENCE) {
            evidence.push("persistence mechanism installed".to_string());
            confidence = (confidence + 0.03).min(1.0);
        }
        if flags.contains(BehaviorFlag::INJECTION) {
            evidence.push("process injection observed".to_string());
        }

        // ── YARA match count as confidence booster ───────────────────────────
        if !yara_matches.is_empty() && matches!(category, MalwareCategory::Unknown) {
            let n = f32::from(u16::try_from(yara_matches.len()).unwrap_or(u16::MAX));
            confidence = (n * 0.1).min(0.55);
            evidence.push(format!(
                "{} YARA rules matched (no family identified)",
                yara_matches.len()
            ));
        }

        MalwareClassification {
            family,
            category,
            confidence,
            evidence,
        }
    }

    fn classify_by_flags(
        flags: BehaviorFlag,
        threat_score: u32,
        category: &mut MalwareCategory,
        confidence: &mut f32,
        evidence: &mut Vec<String>,
    ) {
        if flags.contains(BehaviorFlag::RANSOMWARE)
            || (flags.contains(BehaviorFlag::CRYPTO)
                && flags.contains(BehaviorFlag::FILESYSTEM)
                && threat_score >= 40)
        {
            *category = MalwareCategory::Ransomware;
            *confidence = 0.80;
            evidence.push("RANSOMWARE flag set".to_string());
            if flags.contains(BehaviorFlag::CRYPTO) {
                evidence.push("bulk cryptographic activity detected".to_string());
            }
        } else if flags.contains(BehaviorFlag::ROOTKIT) {
            *category = MalwareCategory::Rootkit;
            *confidence = 0.82;
            evidence.push("ROOTKIT flag set".to_string());
        } else if flags.contains(BehaviorFlag::C2) && flags.contains(BehaviorFlag::INJECTION) {
            *category = MalwareCategory::Rat;
            *confidence = 0.75;
            evidence.push("C2 beacon + process injection".to_string());
        } else if flags.contains(BehaviorFlag::KEYLOGGER) && flags.contains(BehaviorFlag::NETWORK) {
            *category = MalwareCategory::InfoStealer;
            *confidence = 0.72;
            evidence.push("keylogger + network exfiltration".to_string());
        } else if flags.contains(BehaviorFlag::DROPPER) {
            *category = MalwareCategory::Dropper;
            *confidence = 0.65;
            evidence.push("DROPPER flag — executable dropped".to_string());
        } else if flags.contains(BehaviorFlag::WORM) {
            *category = MalwareCategory::Worm;
            *confidence = 0.68;
            evidence.push("WORM flag — self-replication detected".to_string());
        } else if flags.contains(BehaviorFlag::DOWNLOADER) {
            *category = MalwareCategory::Dropper;
            *confidence = 0.60;
            evidence.push("DOWNLOADER flag".to_string());
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn clean_result() -> SandboxResult {
        SandboxResult::clean()
    }

    fn malicious_result() -> SandboxResult {
        SandboxResult {
            status: SandboxStatus::Finished,
            behaviors: BehaviorFlag::INJECTION | BehaviorFlag::NETWORK,
            duration_ms: 2000,
            exit_code: Some(0),
            log: vec!["injected code".to_string()],
            behavior_record: None,
            artifacts: ArtifactCollector::new(),
            pre_snapshot: None,
            post_snapshot: None,
            threat_score: 0,
        }
    }

    // ── ResourceLimits ───────────────────────────────────────────────────────

    #[test]
    fn test_resource_limits_generous() {
        let l = ResourceLimits::generous();
        assert!(l.max_memory_mb >= 1024);
        assert!(l.max_open_files > 0);
    }

    #[test]
    fn test_resource_limits_tight() {
        let l = ResourceLimits::tight();
        assert!(l.max_memory_mb < 512);
    }

    #[test]
    fn test_resource_limits_memory_exceeded_true() {
        let l = ResourceLimits::tight();
        assert!(l.memory_exceeded(l.max_memory_mb + 1));
    }

    #[test]
    fn test_resource_limits_memory_not_exceeded() {
        let l = ResourceLimits::generous();
        assert!(!l.memory_exceeded(100));
    }

    #[test]
    fn test_resource_limits_disk_exceeded() {
        let l = ResourceLimits::tight();
        assert!(l.disk_exceeded(l.max_disk_write_mb + 1));
    }

    // ── SandboxPolicy ────────────────────────────────────────────────────────

    #[test]
    fn test_policy_permissive() {
        let p = SandboxPolicy::permissive();
        assert!(p.perms.contains(SandboxPermissions::ALLOW_NETWORK));
        assert!(p.perms.contains(SandboxPermissions::ALLOW_FS));
        assert!(p.perms.contains(SandboxPermissions::ALLOW_REGISTRY));
        assert!(p.perms.contains(SandboxPermissions::ALLOW_PROCESS));
        assert!(p.timeout_secs > 0);
    }

    #[test]
    fn test_policy_restrictive() {
        let p = SandboxPolicy::restrictive();
        assert!(!p.perms.contains(SandboxPermissions::ALLOW_NETWORK));
        assert!(!p.perms.contains(SandboxPermissions::ALLOW_FS));
        assert!(!p.perms.contains(SandboxPermissions::ALLOW_REGISTRY));
        assert!(!p.perms.contains(SandboxPermissions::ALLOW_PROCESS));
    }

    #[test]
    fn test_policy_balanced() {
        let p = SandboxPolicy::balanced();
        assert!(p.perms.contains(SandboxPermissions::ALLOW_NETWORK));
        assert!(!p.perms.contains(SandboxPermissions::ALLOW_GUI));
    }

    #[test]
    fn test_policy_is_network_allowed_no_network() {
        let p = SandboxPolicy::restrictive();
        assert!(!p.is_network_allowed("1.2.3.4"));
    }

    #[test]
    fn test_policy_is_network_allowed_open() {
        let p = SandboxPolicy::permissive();
        assert!(p.is_network_allowed("any.host"));
    }

    #[test]
    fn test_policy_is_network_allowed_allowlist() {
        let mut p = SandboxPolicy::permissive();
        p.network_allowlist = vec!["trusted.com".to_string()];
        assert!(p.is_network_allowed("trusted.com"));
        assert!(!p.is_network_allowed("evil.com"));
    }

    #[test]
    fn test_policy_is_write_allowed() {
        let mut p = SandboxPolicy::permissive();
        p.fs_write_paths = vec!["/tmp".to_string()];
        assert!(p.is_write_allowed("/tmp/a.exe"));
        assert!(!p.is_write_allowed("/etc/passwd"));
    }

    #[test]
    fn test_policy_validate_ok() {
        assert!(SandboxPolicy::permissive().validate().is_ok());
    }

    #[test]
    fn test_policy_validate_zero_timeout() {
        let mut p = SandboxPolicy::permissive();
        p.timeout_secs = 0;
        assert!(p.validate().is_err());
    }

    // ── BehaviorFlag ─────────────────────────────────────────────────────────

    #[test]
    fn test_behavior_flag_empty() {
        let f = BehaviorFlag::empty();
        assert!(!f.contains(BehaviorFlag::NETWORK));
        assert_eq!(f.describe().len(), 0);
    }

    #[test]
    fn test_behavior_flag_combine() {
        let f = BehaviorFlag::NETWORK | BehaviorFlag::FILESYSTEM;
        assert!(f.contains(BehaviorFlag::NETWORK));
        assert!(f.contains(BehaviorFlag::FILESYSTEM));
        assert!(!f.contains(BehaviorFlag::INJECTION));
    }

    #[test]
    fn test_behavior_flag_describe_injection() {
        let f = BehaviorFlag::INJECTION;
        assert!(f.describe().contains(&"injection"));
    }

    #[test]
    fn test_behavior_flag_threat_score_zero() {
        let f = BehaviorFlag::empty();
        assert_eq!(f.threat_score(), 0);
    }

    #[test]
    fn test_behavior_flag_threat_score_capped() {
        let f = BehaviorFlag::all();
        assert!(f.threat_score() <= 100);
    }

    #[test]
    fn test_behavior_flag_ransomware_score_high() {
        let f = BehaviorFlag::RANSOMWARE | BehaviorFlag::C2 | BehaviorFlag::PERSISTENCE;
        assert!(f.threat_score() >= 60);
    }

    // ── SandboxStatus ────────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_status_display_not_started() {
        assert_eq!(SandboxStatus::NotStarted.to_string(), "not_started");
    }

    #[test]
    fn test_sandbox_status_display_running() {
        assert_eq!(SandboxStatus::Running.to_string(), "running");
    }

    #[test]
    fn test_sandbox_status_display_finished() {
        assert_eq!(SandboxStatus::Finished.to_string(), "finished");
    }

    #[test]
    fn test_sandbox_status_display_timeout() {
        assert_eq!(SandboxStatus::Timeout.to_string(), "timeout");
    }

    #[test]
    fn test_sandbox_status_display_crashed() {
        let s = SandboxStatus::Crashed("segfault".to_string());
        assert!(s.to_string().contains("segfault"));
    }

    #[test]
    fn test_sandbox_status_display_policy_violation() {
        let s = SandboxStatus::PolicyViolation("network blocked".to_string());
        assert!(s.to_string().contains("network blocked"));
    }

    // ── SyscallTrace ─────────────────────────────────────────────────────────

    #[test]
    fn test_syscall_trace_new() {
        let t = SyscallTrace::new(1, "NtCreateFile", 100, 50);
        assert_eq!(t.name, "NtCreateFile");
        assert_eq!(t.pid, 100);
        assert!(!t.flagged);
    }

    #[test]
    fn test_syscall_trace_builder() {
        let t = SyscallTrace::new(1, "NtRead", 1, 0)
            .with_arg("0x1000")
            .with_ret(0)
            .flagged();
        assert_eq!(t.args.len(), 1);
        assert_eq!(t.ret, Some(0));
        assert!(t.flagged);
    }

    // ── NetworkTrace ─────────────────────────────────────────────────────────

    #[test]
    fn test_network_trace_is_external() {
        let t = NetworkTrace {
            proto: NetworkProto::Tcp,
            local_addr: "192.168.1.1:50000".to_string(),
            remote_addr: "8.8.8.8".to_string(),
            remote_port: 443,
            bytes_sent: 0,
            bytes_recv: 0,
            ts_ms: 0,
            pid: 1,
            dns_query: None,
        };
        assert!(t.is_external());
    }

    #[test]
    fn test_network_trace_not_external_loopback() {
        let t = NetworkTrace {
            proto: NetworkProto::Tcp,
            local_addr: "127.0.0.1:9999".to_string(),
            remote_addr: "127.0.0.1".to_string(),
            remote_port: 80,
            bytes_sent: 0,
            bytes_recv: 0,
            ts_ms: 0,
            pid: 1,
            dns_query: None,
        };
        assert!(!t.is_external());
    }

    #[test]
    fn test_network_trace_c2_port() {
        let t = NetworkTrace {
            proto: NetworkProto::Tcp,
            local_addr: "0.0.0.0:0".to_string(),
            remote_addr: "1.2.3.4".to_string(),
            remote_port: 4444,
            bytes_sent: 0,
            bytes_recv: 0,
            ts_ms: 0,
            pid: 1,
            dns_query: None,
        };
        assert!(t.is_c2_port());
    }

    #[test]
    fn test_network_proto_display() {
        assert_eq!(NetworkProto::Tcp.to_string(), "tcp");
        assert_eq!(NetworkProto::Https.to_string(), "https");
        assert_eq!(NetworkProto::Dns.to_string(), "dns");
    }

    // ── FileTrace ────────────────────────────────────────────────────────────

    #[test]
    fn test_file_trace_dropper_op_exe() {
        let t = FileTrace {
            op: FileOp::Create,
            path: "C:\\Temp\\payload.exe".to_string(),
            bytes: 1024,
            ts_ms: 0,
            pid: 1,
            success: true,
        };
        assert!(t.is_dropper_op());
    }

    #[test]
    fn test_file_trace_not_dropper_op_read() {
        let t = FileTrace {
            op: FileOp::Read,
            path: "C:\\Temp\\payload.exe".to_string(),
            bytes: 1024,
            ts_ms: 0,
            pid: 1,
            success: true,
        };
        assert!(!t.is_dropper_op());
    }

    #[test]
    fn test_file_op_display() {
        assert_eq!(FileOp::Create.to_string(), "create");
        assert_eq!(FileOp::Write.to_string(), "write");
        assert_eq!(FileOp::Delete.to_string(), "delete");
    }

    // ── RegistryTrace ────────────────────────────────────────────────────────

    #[test]
    fn test_registry_trace_persistence_op() {
        let t = RegistryTrace {
            op: RegistryOp::SetValue,
            key: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware".to_string(),
            value_name: "Malware".to_string(),
            data: None,
            ts_ms: 0,
            pid: 1,
        };
        assert!(t.is_persistence_op());
    }

    #[test]
    fn test_registry_trace_non_persistence_op() {
        let t = RegistryTrace {
            op: RegistryOp::QueryValue,
            key: r"HKLM\Software\Microsoft\Windows NT\CurrentVersion".to_string(),
            value_name: "ProductName".to_string(),
            data: None,
            ts_ms: 0,
            pid: 1,
        };
        assert!(!t.is_persistence_op());
    }

    // ── ProcessTree ──────────────────────────────────────────────────────────

    #[test]
    fn test_process_tree_insert_and_find() {
        let mut tree = ProcessTree::new(1);
        tree.insert(ProcessNode::new(1, 0, "malware.exe", "", 0));
        assert!(tree.find(1).is_some());
    }

    #[test]
    fn test_process_tree_count() {
        let mut tree = ProcessTree::new(1);
        tree.insert(ProcessNode::new(1, 0, "a.exe", "", 0));
        tree.insert(ProcessNode::new(2, 1, "b.exe", "", 0));
        assert_eq!(tree.process_count(), 2);
    }

    #[test]
    fn test_process_tree_leaves() {
        let mut tree = ProcessTree::new(1);
        tree.insert(ProcessNode::new(1, 0, "a.exe", "", 0));
        tree.insert(ProcessNode::new(2, 1, "b.exe", "", 0));
        // node 2 has no children → it is a leaf
        let leaves = tree.leaves();
        assert!(!leaves.is_empty());
    }

    // ── BehaviorRecord ───────────────────────────────────────────────────────

    #[test]
    fn test_behavior_record_mock() {
        let rec = BehaviorRecord::mock();
        assert!(rec.flags.contains(BehaviorFlag::INJECTION));
        assert!(rec.flags.contains(BehaviorFlag::PERSISTENCE));
        assert!(rec.flags.contains(BehaviorFlag::C2));
    }

    #[test]
    fn test_behavior_record_flagged_syscall_count() {
        let rec = BehaviorRecord::mock();
        assert!(rec.flagged_syscall_count() > 0);
    }

    #[test]
    fn test_behavior_record_external_conn_count() {
        let rec = BehaviorRecord::mock();
        assert!(rec.external_conn_count() > 0);
    }

    #[test]
    fn test_behavior_record_dropped_exe_count() {
        let rec = BehaviorRecord::mock();
        assert!(rec.dropped_exe_count() > 0);
    }

    #[test]
    fn test_behavior_record_persistence_op_count() {
        let rec = BehaviorRecord::mock();
        assert!(rec.persistence_op_count() > 0);
    }

    // ── ArtifactCollector ────────────────────────────────────────────────────

    #[test]
    fn test_artifact_collector_add_binary() {
        let mut col = ArtifactCollector::new();
        col.add_binary("payload.exe", vec![0x4d, 0x5a]);
        assert_eq!(col.binary_count(), 1);
        assert!(col.total_bytes() >= 2);
    }

    #[test]
    fn test_artifact_collector_find_binary() {
        let mut col = ArtifactCollector::new();
        col.add_binary("test.exe", vec![1, 2, 3]);
        let data = col.find_binary("test.exe");
        assert_eq!(data, Some([1u8, 2, 3].as_ref()));
    }

    #[test]
    fn test_artifact_collector_find_binary_miss() {
        let col = ArtifactCollector::new();
        assert!(col.find_binary("nonexistent").is_none());
    }

    // ── FilesystemSnapshot ───────────────────────────────────────────────────

    #[test]
    fn test_fs_snapshot_diff_added() {
        let pre = FilesystemSnapshot::new("pre", 0);
        let mut post = FilesystemSnapshot::new("post", 1000);
        post.add("/tmp/new.exe", "deadbeef");
        let (added, removed, modified) = pre.diff(&post);
        assert_eq!(added.len(), 1);
        assert!(removed.is_empty());
        assert!(modified.is_empty());
    }

    #[test]
    fn test_fs_snapshot_diff_modified() {
        let mut pre = FilesystemSnapshot::new("pre", 0);
        pre.add("/etc/hosts", "aaa");
        let mut post = FilesystemSnapshot::new("post", 1000);
        post.add("/etc/hosts", "bbb");
        let (added, removed, modified) = pre.diff(&post);
        assert!(added.is_empty());
        assert!(removed.is_empty());
        assert_eq!(modified.len(), 1);
    }

    #[test]
    fn test_fs_snapshot_diff_removed() {
        let mut pre = FilesystemSnapshot::new("pre", 0);
        pre.add("/tmp/old.txt", "ccc");
        let post = FilesystemSnapshot::new("post", 1000);
        let (added, removed, _modified) = pre.diff(&post);
        assert!(added.is_empty());
        assert_eq!(removed.len(), 1);
    }

    #[test]
    fn test_fs_snapshot_file_count() {
        let mut snap = FilesystemSnapshot::new("snap", 0);
        snap.add("/a", "h1");
        snap.add("/b", "h2");
        assert_eq!(snap.file_count(), 2);
    }

    // ── SandboxResult ────────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_result_is_not_malicious() {
        let r = clean_result();
        assert!(!r.is_malicious());
    }

    #[test]
    fn test_sandbox_result_is_malicious_injection() {
        let r = malicious_result();
        assert!(r.is_malicious());
    }

    #[test]
    fn test_sandbox_result_is_malicious_antianalysis() {
        let r = SandboxResult {
            behaviors: BehaviorFlag::ANTIANALYSIS,
            ..clean_result()
        };
        assert!(r.is_malicious());
    }

    #[test]
    fn test_sandbox_result_is_malicious_network_persistence() {
        let r = SandboxResult {
            behaviors: BehaviorFlag::NETWORK | BehaviorFlag::PERSISTENCE,
            ..clean_result()
        };
        assert!(r.is_malicious());
    }

    #[test]
    fn test_sandbox_result_add_log() {
        let mut r = clean_result();
        r.add_log("test log");
        assert_eq!(r.log.len(), 1);
        assert_eq!(r.log[0], "test log");
    }

    #[test]
    fn test_sandbox_result_timed_out() {
        let mut r = clean_result();
        r.status = SandboxStatus::Timeout;
        assert!(r.timed_out());
    }

    #[test]
    fn test_sandbox_result_fs_diff_none() {
        let r = clean_result();
        assert!(r.fs_diff().is_none());
    }

    #[test]
    fn test_sandbox_result_fs_diff_some() {
        let r = SandboxResult::mock();
        // mock has both pre and post snapshots
        let diff = r.fs_diff();
        assert!(diff.is_some());
        let (added, _removed, _modified) = diff.unwrap();
        assert!(!added.is_empty());
    }

    #[test]
    fn test_sandbox_result_mock_is_malicious() {
        let r = SandboxResult::mock();
        assert!(r.is_malicious());
    }

    #[test]
    fn test_sandbox_result_mock_threat_score() {
        let r = SandboxResult::mock();
        assert!(r.threat_score > 0);
    }

    #[test]
    fn test_sandbox_result_serialization() {
        let r = malicious_result();
        let json = serde_json::to_string(&r).unwrap();
        let decoded: SandboxResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.behaviors, r.behaviors);
    }

    // ── SandboxSession ───────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_session_initial_state() {
        let cfg = SandboxConfig::windows_default("test");
        let session = SandboxSession::new("sess-1", cfg);
        assert_eq!(session.current_status(), SandboxStatus::NotStarted);
    }

    #[test]
    fn test_sandbox_session_start() {
        let cfg = SandboxConfig::windows_default("test");
        let session = SandboxSession::new("sess-1", cfg);
        session.start();
        assert_eq!(session.current_status(), SandboxStatus::Running);
    }

    #[test]
    fn test_sandbox_session_finish() {
        let cfg = SandboxConfig::windows_default("test");
        let session = SandboxSession::new("sess-1", cfg);
        session.start();
        session.finish(Some(0));
        assert_eq!(session.current_status(), SandboxStatus::Finished);
    }

    #[test]
    fn test_sandbox_session_timeout() {
        let cfg = SandboxConfig::windows_default("test");
        let session = SandboxSession::new("sess-1", cfg);
        session.timeout();
        assert_eq!(session.current_status(), SandboxStatus::Timeout);
    }

    #[test]
    fn test_sandbox_session_elapsed_ms() {
        let cfg = SandboxConfig::windows_default("test");
        let session = SandboxSession::new("sess-1", cfg);
        session.tick_ms(1000);
        session.tick_ms(500);
        assert_eq!(session.elapsed_ms(), 1500);
    }

    #[test]
    fn test_sandbox_session_is_timed_out() {
        let mut cfg = SandboxConfig::windows_default("test");
        cfg.policy.timeout_secs = 2;
        let session = SandboxSession::new("sess-1", cfg);
        session.tick_ms(3000);
        assert!(session.is_timed_out());
    }

    // ── MockSandbox ──────────────────────────────────────────────────────────

    #[test]
    fn test_mock_sandbox_name() {
        let sandbox = MockSandbox::new("test-sandbox", clean_result());
        assert_eq!(Sandbox::name(&sandbox), "test-sandbox");
    }

    #[test]
    fn test_mock_sandbox_run() {
        let sandbox = MockSandbox::new("mock", clean_result());
        let policy = SandboxPolicy::restrictive();
        let result = sandbox.run("binary", &policy).unwrap();
        assert_eq!(result.status, SandboxStatus::Finished);
    }

    #[test]
    fn test_mock_sandbox_supports_arch() {
        let sandbox = MockSandbox::clean("mock");
        assert!(sandbox.supports_arch("x86"));
        assert!(sandbox.supports_arch("x86_64"));
        assert!(sandbox.supports_arch("arm64"));
        assert!(!sandbox.supports_arch("mips"));
    }

    // ── SandboxManager ───────────────────────────────────────────────────────

    #[test]
    fn test_manager_empty() {
        let m = SandboxManager::new();
        assert_eq!(m.backend_count(), 0);
    }

    #[test]
    fn test_manager_register_and_find() {
        let mut m = SandboxManager::new();
        m.register(Box::new(MockSandbox::clean("backend1")));
        assert!(m.find("backend1").is_some());
        assert!(m.find("backend2").is_none());
    }

    #[test]
    fn test_manager_run_on_arch() {
        let mut m = SandboxManager::new();
        m.register(Box::new(MockSandbox::clean("x64_backend")));
        let policy = SandboxPolicy::restrictive();
        let result = m.run_on_arch("malware.exe", "x64", &policy).unwrap();
        assert_eq!(result.status, SandboxStatus::Finished);
    }

    #[test]
    fn test_manager_run_on_arch_no_backend() {
        let m = SandboxManager::new();
        let policy = SandboxPolicy::restrictive();
        let err = m.run_on_arch("malware.exe", "mips", &policy).unwrap_err();
        assert!(matches!(err, SandboxError::SpawnFailed(_)));
    }

    #[test]
    fn test_manager_session_id_unique() {
        let m = SandboxManager::new();
        let id1 = m.next_session_id();
        let id2 = m.next_session_id();
        assert_ne!(id1, id2);
    }

    // ── Error variants ───────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_error_spawn_failed() {
        let e = SandboxError::SpawnFailed("no binary".to_string());
        assert!(e.to_string().contains("no binary"));
    }

    #[test]
    fn test_sandbox_error_timeout() {
        let e = SandboxError::Timeout(60);
        assert!(e.to_string().contains("60"));
    }

    #[test]
    fn test_sandbox_error_policy_violation() {
        let e = SandboxError::PolicyViolation("network denied".to_string());
        assert!(e.to_string().contains("network denied"));
    }

    #[test]
    fn test_sandbox_error_io() {
        let e = SandboxError::Io("disk full".to_string());
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    fn test_sandbox_error_resource_limit() {
        let e = SandboxError::ResourceLimit("memory".to_string());
        assert!(e.to_string().contains("memory"));
    }

    #[test]
    fn test_sandbox_arch_display() {
        assert_eq!(SandboxArch::X64.to_string(), "x64");
        assert_eq!(SandboxArch::Arm64.to_string(), "arm64");
    }

    #[test]
    fn test_sandbox_os_display() {
        assert_eq!(SandboxOs::Windows10.to_string(), "windows10");
        assert_eq!(SandboxOs::Ubuntu22.to_string(), "ubuntu22");
    }

    #[test]
    fn test_policy_serialization() {
        let p = SandboxPolicy::permissive();
        let json = serde_json::to_string(&p).unwrap();
        let decoded: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.timeout_secs, p.timeout_secs);
    }

    #[test]
    fn test_behavior_all_flags() {
        let all = BehaviorFlag::NETWORK
            | BehaviorFlag::FILESYSTEM
            | BehaviorFlag::REGISTRY
            | BehaviorFlag::PROCESS
            | BehaviorFlag::INJECTION
            | BehaviorFlag::CRYPTO
            | BehaviorFlag::ANTIANALYSIS
            | BehaviorFlag::PERSISTENCE;
        assert!(all.contains(BehaviorFlag::CRYPTO));
        assert!(all.contains(BehaviorFlag::PROCESS));
    }

    #[test]
    fn test_sandbox_config_validate_ok() {
        let cfg = SandboxConfig::windows_default("test");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_sandbox_result_collect_from_session() {
        let cfg = SandboxConfig::windows_default("s");
        let session = SandboxSession::new("s1", cfg);
        session.start();
        session.tick_ms(2000);
        session.finish(Some(0));
        let result = session.collect_result();
        assert_eq!(result.status, SandboxStatus::Finished);
        assert_eq!(result.duration_ms, 2000);
    }

    // ── IocCollection ────────────────────────────────────────────────────────

    #[test]
    fn test_ioc_collection_empty() {
        let iocs = IocCollection::new();
        assert!(iocs.is_empty());
        assert_eq!(iocs.total(), 0);
    }

    #[test]
    fn test_ioc_collection_merge() {
        let mut a = IocCollection::new();
        a.ips.push("1.2.3.4".to_string());
        let mut b = IocCollection::new();
        b.ips.push("5.6.7.8".to_string());
        b.ips.push("1.2.3.4".to_string()); // duplicate
        a.merge(&b);
        assert_eq!(a.ips.len(), 2);
    }

    // ── SandboxOrchestrator ──────────────────────────────────────────────────

    #[test]
    fn test_orchestrator_submit_batch() {
        let orc = SandboxOrchestrator::with_mock_backend("mock", SandboxResult::mock());
        let samples = vec![
            std::path::PathBuf::from("sample1.exe"),
            std::path::PathBuf::from("sample2.exe"),
        ];
        let ids = orc.submit_batch(samples, SandboxConfig::windows_default("test"));
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_orchestrator_wait_for_jobs() {
        let orc = SandboxOrchestrator::with_mock_backend("mock", SandboxResult::clean());
        let samples = vec![std::path::PathBuf::from("s.exe")];
        let ids = orc.submit_batch(samples, SandboxConfig::windows_default("t"));
        let statuses = orc.wait_for_jobs(&ids, std::time::Duration::from_secs(5));
        assert_eq!(statuses.len(), 1);
        assert!(matches!(statuses[&ids[0]], JobStatus::Completed(_)));
    }

    #[test]
    fn test_orchestrator_collect_iocs_from_mock() {
        let result = SandboxResult::mock();
        let iocs = SandboxOrchestrator::collect_iocs(&result);
        // Mock result has a network trace to 185.220.101.1
        assert!(!iocs.ips.is_empty());
        // Mock result has a dropped binary
        assert!(!iocs.dropped_paths.is_empty());
        // Mock result has a registry Run key
        assert!(!iocs.registry_keys.is_empty());
    }

    #[test]
    fn test_orchestrator_collect_iocs_clean() {
        let result = SandboxResult::clean();
        let iocs = SandboxOrchestrator::collect_iocs(&result);
        assert!(iocs.is_empty());
    }

    // ── BehaviorSignatureDb ──────────────────────────────────────────────────

    #[test]
    fn test_sig_db_load_builtin_count() {
        let db = BehaviorSignatureDb::load_builtin();
        assert!(db.len() >= 20);
    }

    #[test]
    fn test_sig_db_match_all_mock() {
        let db = BehaviorSignatureDb::load_builtin();
        let rec = BehaviorRecord::mock();
        let matches = db.match_all(&rec);
        // Mock record has injection + persistence + C2 + anti-analysis flags
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_sig_db_score_capped() {
        let db = BehaviorSignatureDb::load_builtin();
        let rec = BehaviorRecord::mock();
        let score = db.score(&rec);
        assert!(score <= 100);
    }

    #[test]
    fn test_sig_db_persistence_signature_matches() {
        let db = BehaviorSignatureDb::load_builtin();
        let rec = BehaviorRecord::mock(); // has Run key write
        
        assert!(db.match_all(&rec).iter().map(|s| s.id.as_str()).any(|x| x == "run_key_persistence"));
    }

    #[test]
    fn test_sig_db_injection_signature_matches() {
        let db = BehaviorSignatureDb::load_builtin();
        let rec = BehaviorRecord::mock(); // has INJECTION flag
        
        assert!(db.match_all(&rec).iter().map(|s| s.id.as_str()).any(|x| x == "process_injection"));
    }

    // ── MalwareFamilyClassifier ──────────────────────────────────────────────

    #[test]
    fn test_classifier_unknown_clean() {
        let r = SandboxResult::clean();
        let cls = MalwareFamilyClassifier::classify(&r, &[]);
        assert!(matches!(cls.category, MalwareCategory::Unknown));
    }

    #[test]
    fn test_classifier_yara_wannacry() {
        let r = SandboxResult::clean();
        let yara = vec!["wannacry_v2".to_string()];
        let cls = MalwareFamilyClassifier::classify(&r, &yara);
        assert!(matches!(cls.category, MalwareCategory::Ransomware));
        assert_eq!(cls.family.as_deref(), Some("WannaCry"));
        assert!(cls.confidence > 0.9);
    }

    #[test]
    fn test_classifier_rat_from_flags() {
        let r = SandboxResult {
            behaviors: BehaviorFlag::C2 | BehaviorFlag::INJECTION | BehaviorFlag::ANTIANALYSIS,
            threat_score: 60,
            ..SandboxResult::clean()
        };
        let cls = MalwareFamilyClassifier::classify(&r, &[]);
        assert!(matches!(cls.category, MalwareCategory::Rat));
    }

    #[test]
    fn test_classifier_ransomware_from_flags() {
        let r = SandboxResult {
            behaviors: BehaviorFlag::RANSOMWARE | BehaviorFlag::CRYPTO | BehaviorFlag::FILESYSTEM,
            threat_score: 50,
            ..SandboxResult::clean()
        };
        let cls = MalwareFamilyClassifier::classify(&r, &[]);
        assert!(matches!(cls.category, MalwareCategory::Ransomware));
    }

    #[test]
    fn test_classifier_infostealer_from_flags() {
        let r = SandboxResult {
            behaviors: BehaviorFlag::KEYLOGGER | BehaviorFlag::NETWORK,
            ..SandboxResult::clean()
        };
        let cls = MalwareFamilyClassifier::classify(&r, &[]);
        assert!(matches!(cls.category, MalwareCategory::InfoStealer));
    }

    #[test]
    fn test_classifier_is_high_confidence() {
        let r = SandboxResult::clean();
        let yara = vec!["emotet_doc_macro".to_string()];
        let cls = MalwareFamilyClassifier::classify(&r, &yara);
        assert!(cls.is_high_confidence());
        assert!(cls.is_malicious());
    }

    #[test]
    fn test_malware_category_display() {
        assert_eq!(MalwareCategory::Ransomware.to_string(), "ransomware");
        assert_eq!(MalwareCategory::Rat.to_string(), "rat");
        assert_eq!(MalwareCategory::InfoStealer.to_string(), "info_stealer");
        assert_eq!(MalwareCategory::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_job_status_display() {
        assert_eq!(JobStatus::Pending.to_string(), "pending");
        assert_eq!(JobStatus::Running.to_string(), "running");
        let cs = JobStatus::Completed(SandboxStatus::Finished);
        assert!(cs.to_string().starts_with("completed"));
    }
}

// ─── SandboxBackend Trait ─────────────────────────────────────────────────────

/// Handle to a submitted sandbox job.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobHandle {
    /// Unique job ID string.
    pub id: String,
    /// Backend name that owns this job.
    pub backend: String,
}

impl JobHandle {
    /// Create a new job handle.
    #[must_use]
    pub fn new(id: impl Into<String>, backend: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            backend: backend.into(),
        }
    }
}

impl fmt::Display for JobHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Job({}/{})", self.backend, self.id)
    }
}

/// Live status of a submitted job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiveJobStatus {
    /// Waiting to be assigned a slot.
    Queued,
    /// Currently running on the backend.
    Running {
        /// When the job started (Unix ms).
        started_at: u64,
        /// Estimated progress 0-100.
        progress_pct: u8,
    },
    /// Finished successfully.
    Completed,
    /// Failed with an error message.
    Failed {
        /// Error description.
        error: String,
    },
    /// Exceeded its timeout.
    Timeout,
    /// Cancelled by the user.
    Cancelled,
}

impl fmt::Display for LiveJobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Running {
                started_at,
                progress_pct,
            } => {
                write!(f, "running(started={started_at}ms, {progress_pct}%)")
            }
            Self::Completed => write!(f, "completed"),
            Self::Failed { error } => write!(f, "failed: {error}"),
            Self::Timeout => write!(f, "timeout"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Network isolation mode for a sandbox job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    /// No network access whatsoever.
    None,
    /// Loopback only.
    Loopback,
    /// `INetSim` (simulated internet).
    INetSim,
    /// Full internet access.
    Internet,
    /// Custom routing rules.
    Custom(String),
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Loopback => write!(f, "loopback"),
            Self::INetSim => write!(f, "inetsim"),
            Self::Internet => write!(f, "internet"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

/// A sample submission for sandbox analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxJob {
    /// Raw sample bytes.
    pub sample_bytes: Vec<u8>,
    /// Filename to present inside the sandbox.
    pub filename: String,
    /// Command-line arguments to pass to the sample.
    pub args: Vec<String>,
    /// Execution timeout in seconds.
    pub timeout: u64,
    /// Network isolation mode.
    pub network_mode: NetworkMode,
    /// Target OS profile.
    pub os_profile: SandboxOs,
    /// Target architecture.
    pub arch: SandboxArch,
    /// Whether to capture full PCAP.
    pub capture_pcap: bool,
    /// Whether to take periodic screenshots.
    pub capture_screenshots: bool,
    /// Whether to record memory dumps on interesting events.
    pub memory_dumps: bool,
    /// Extra environment variables.
    pub env_vars: HashMap<String, String>,
    /// Unique ID assigned at submission time.
    pub id: String,
    /// Priority (0 = lowest, 255 = highest).
    pub priority: u8,
}

impl SandboxJob {
    /// Create a new sandbox job.
    #[must_use]
    pub fn new(
        sample_bytes: Vec<u8>,
        filename: impl Into<String>,
        timeout: u64,
        os_profile: SandboxOs,
    ) -> Self {
        let filename: String = filename.into();
        let id = format!("job-{:016x}", {
            // Deterministic ID derived from the filename, the sample contents,
            // and their length so that distinct samples never share an id.
            let fn_str: &str = filename.as_ref();
            let mut h = fn_str.bytes().fold(0u64, |acc: u64, b| {
                acc.wrapping_mul(31).wrapping_add(u64::from(b))
            });
            for &b in &sample_bytes {
                h = h.wrapping_mul(131).wrapping_add(u64::from(b));
            }
            h ^ sample_bytes.len() as u64
        });
        Self {
            sample_bytes,
            filename,
            args: Vec::new(),
            timeout,
            network_mode: NetworkMode::None,
            os_profile,
            arch: SandboxArch::X64,
            capture_pcap: true,
            capture_screenshots: false,
            memory_dumps: false,
            env_vars: HashMap::new(),
            id,
            priority: 128,
        }
    }

    /// Add command-line arguments.
    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Set network mode.
    #[must_use]
    pub fn with_network(mut self, mode: NetworkMode) -> Self {
        self.network_mode = mode;
        self
    }

    /// Set architecture.
    #[must_use]
    pub const fn with_arch(mut self, arch: SandboxArch) -> Self {
        self.arch = arch;
        self
    }

    /// Enable screenshot capture.
    #[must_use]
    pub const fn with_screenshots(mut self) -> Self {
        self.capture_screenshots = true;
        self
    }

    /// SHA-256 placeholder hash of sample bytes.
    #[must_use]
    pub fn sample_hash(&self) -> String {
        // Simple rolling hash as a placeholder (not cryptographic).
        let hash = self.sample_bytes.iter().fold(0u64, |acc, &b| {
            acc.wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(u64::from(b) + 1)
        });
        format!("{hash:016x}{:016x}", self.sample_bytes.len() as u64)
    }

    /// Returns `true` if the sample looks like a PE executable (MZ header).
    #[must_use]
    pub fn is_pe(&self) -> bool {
        self.sample_bytes.starts_with(b"MZ")
    }

    /// Returns `true` if the sample looks like an ELF binary.
    #[must_use]
    pub fn is_elf(&self) -> bool {
        self.sample_bytes.starts_with(b"\x7fELF")
    }
}

/// Trait implemented by all sandbox backends.
pub trait SandboxBackend: Send + Sync {
    /// Human-readable name of this backend.
    fn name(&self) -> &str;

    /// Returns `true` if this backend can handle the given OS and arch.
    fn supports(&self, os: &SandboxOs, arch: &SandboxArch) -> bool;

    /// Submit a job for execution.
    ///
    /// # Errors
    /// Returns `SandboxError` if the job cannot be submitted.
    fn submit(&self, job: &SandboxJob) -> Result<JobHandle, SandboxError>;

    /// Poll the status of a submitted job.
    ///
    /// # Errors
    /// Returns `SandboxError` if the handle is invalid.
    fn status(&self, handle: &JobHandle) -> Result<LiveJobStatus, SandboxError>;

    /// Collect the result of a completed job.
    ///
    /// # Errors
    /// Returns `SandboxError` if the job has not completed or is invalid.
    fn collect(&self, handle: &JobHandle) -> Result<SandboxResult, SandboxError>;

    /// Cancel a running or queued job.
    ///
    /// # Errors
    /// Returns `SandboxError` if cancellation fails.
    fn cancel(&self, handle: &JobHandle) -> Result<(), SandboxError>;
}

// ─── QemuKvmBackend ───────────────────────────────────────────────────────────

/// QEMU/KVM-based sandbox backend.
///
/// Uses libvirt for VM lifecycle management, snapshot cloning for clean states,
/// and vsock for guest-host communication.
#[derive(Debug, Clone)]
pub struct QemuKvmBackend {
    /// Backend name.
    pub name: String,
    /// Path to the base VM snapshot image.
    pub base_image_path: String,
    /// libvirt connection URI (e.g., "<qemu:///system>").
    pub libvirt_uri: String,
    /// vsock port for agent communication.
    pub vsock_port: u32,
    /// Maximum concurrent VMs.
    pub max_concurrent: usize,
    /// Supported OS profiles.
    pub supported_os: Vec<SandboxOs>,
}

impl QemuKvmBackend {
    /// Create a new QEMU/KVM backend.
    #[must_use]
    pub fn new(name: impl Into<String>, base_image_path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            base_image_path: base_image_path.into(),
            libvirt_uri: "qemu:///system".to_string(),
            vsock_port: 1234,
            max_concurrent: 4,
            supported_os: vec![
                SandboxOs::Windows10,
                SandboxOs::Windows11,
                SandboxOs::Ubuntu22,
            ],
        }
    }

    /// Configure the libvirt URI.
    #[must_use]
    pub fn with_libvirt_uri(mut self, uri: impl Into<String>) -> Self {
        self.libvirt_uri = uri.into();
        self
    }

    /// Configure the vsock port.
    #[must_use]
    pub const fn with_vsock_port(mut self, port: u32) -> Self {
        self.vsock_port = port;
        self
    }

    /// Configure max concurrent VMs.
    #[must_use]
    pub const fn with_max_concurrent(mut self, n: usize) -> Self {
        self.max_concurrent = n;
        self
    }

    /// Simulate cloning a VM snapshot.
    fn clone_snapshot(&self, job_id: &str) -> String {
        format!("{}-snapshot-{}", self.base_image_path, job_id)
    }

    /// Build a sandbox result from the job (simulated).
    fn build_result(&self, job: &SandboxJob) -> SandboxResult {
        let mut result = SandboxResult::clean();
        result.add_log(format!(
            "[QEMU] Executed {} via {}",
            job.filename, self.name
        ));
        result.add_log(format!("[QEMU] Image: {}", self.clone_snapshot(&job.id)));
        result.add_log(format!("[QEMU] Network mode: {}", job.network_mode));
        result.add_log(format!("[QEMU] Timeout: {}s", job.timeout));
        result
    }
}

impl SandboxBackend for QemuKvmBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn supports(&self, os: &SandboxOs, arch: &SandboxArch) -> bool {
        self.supported_os.contains(os) && matches!(arch, SandboxArch::X64 | SandboxArch::X86)
    }

    fn submit(&self, job: &SandboxJob) -> Result<JobHandle, SandboxError> {
        if !self.supports(&job.os_profile, &job.arch) {
            return Err(SandboxError::SpawnFailed(format!(
                "QEMU backend '{}' does not support {} / {}",
                self.name, job.os_profile, job.arch
            )));
        }
        Ok(JobHandle::new(job.id.clone(), &self.name))
    }

    fn status(&self, _handle: &JobHandle) -> Result<LiveJobStatus, SandboxError> {
        Ok(LiveJobStatus::Completed)
    }

    fn collect(&self, handle: &JobHandle) -> Result<SandboxResult, SandboxError> {
        // In a real implementation this would retrieve results from the VM via vsock.
        let dummy_job = SandboxJob::new(
            b"MZ".to_vec(),
            format!("sample-{}", handle.id),
            60,
            SandboxOs::Windows10,
        );
        Ok(self.build_result(&dummy_job))
    }

    fn cancel(&self, _handle: &JobHandle) -> Result<(), SandboxError> {
        // In a real implementation: destroy libvirt domain.
        Ok(())
    }
}

// ─── FirecrackerBackend ───────────────────────────────────────────────────────

/// Firecracker microVM-based sandbox backend.
///
/// Uses the Firecracker VMM API for ultra-fast VM boot, jailer for isolation,
/// and a minimal rootfs for the guest environment.
#[derive(Debug, Clone)]
pub struct FirecrackerBackend {
    /// Backend name.
    pub name: String,
    /// Path to the Firecracker binary.
    pub firecracker_bin: String,
    /// Path to the rootfs image.
    pub rootfs_path: String,
    /// Path to the kernel image.
    pub kernel_path: String,
    /// Firecracker API socket path template.
    pub socket_path_template: String,
    /// Maximum concurrent microVMs.
    pub max_concurrent: usize,
    /// Memory in MiB per microVM.
    pub mem_mib: u32,
    /// vCPUs per microVM.
    pub vcpu_count: u32,
}

impl FirecrackerBackend {
    /// Create a new Firecracker backend.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        firecracker_bin: impl Into<String>,
        rootfs_path: impl Into<String>,
        kernel_path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            firecracker_bin: firecracker_bin.into(),
            rootfs_path: rootfs_path.into(),
            kernel_path: kernel_path.into(),
            socket_path_template: "/tmp/fc-{id}.sock".to_string(),
            max_concurrent: 16,
            mem_mib: 512,
            vcpu_count: 2,
        }
    }

    /// Set memory per microVM.
    #[must_use]
    pub const fn with_mem_mib(mut self, mib: u32) -> Self {
        self.mem_mib = mib;
        self
    }

    /// Set vCPU count.
    #[must_use]
    pub const fn with_vcpus(mut self, n: u32) -> Self {
        self.vcpu_count = n;
        self
    }

    /// API socket path for a given job.
    #[must_use]
    pub fn socket_path(&self, job_id: &str) -> String {
        self.socket_path_template.replace("{id}", job_id)
    }

    /// Build a result (simulated).
    fn build_result(&self, job: &SandboxJob) -> SandboxResult {
        let mut result = SandboxResult::clean();
        result.add_log(format!(
            "[Firecracker] Executed {} | socket={} mem={}MiB vcpus={}",
            job.filename,
            self.socket_path(&job.id),
            self.mem_mib,
            self.vcpu_count,
        ));
        result
    }
}

impl SandboxBackend for FirecrackerBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn supports(&self, os: &SandboxOs, arch: &SandboxArch) -> bool {
        // Firecracker supports Linux guests on x64.
        matches!(os, SandboxOs::Ubuntu22 | SandboxOs::Debian12) && matches!(arch, SandboxArch::X64)
    }

    fn submit(&self, job: &SandboxJob) -> Result<JobHandle, SandboxError> {
        if !self.supports(&job.os_profile, &job.arch) {
            return Err(SandboxError::SpawnFailed(format!(
                "Firecracker backend '{}' does not support {} / {}",
                self.name, job.os_profile, job.arch
            )));
        }
        Ok(JobHandle::new(job.id.clone(), &self.name))
    }

    fn status(&self, _handle: &JobHandle) -> Result<LiveJobStatus, SandboxError> {
        Ok(LiveJobStatus::Completed)
    }

    fn collect(&self, handle: &JobHandle) -> Result<SandboxResult, SandboxError> {
        let dummy = SandboxJob::new(
            b"\x7fELF".to_vec(),
            format!("elf-{}", handle.id),
            30,
            SandboxOs::Ubuntu22,
        );
        Ok(self.build_result(&dummy))
    }

    fn cancel(&self, _handle: &JobHandle) -> Result<(), SandboxError> {
        Ok(())
    }
}

// ─── DockerBackend ────────────────────────────────────────────────────────────

/// Docker container-based sandbox backend.
///
/// Creates an analysis container, injects the sample, starts it, and
/// collects structured logs.
#[derive(Debug, Clone)]
pub struct DockerBackend {
    /// Backend name.
    pub name: String,
    /// Docker image to use for analysis.
    pub analysis_image: String,
    /// Docker API socket path.
    pub docker_socket: String,
    /// Maximum concurrent containers.
    pub max_concurrent: usize,
    /// Container memory limit in MB.
    pub mem_limit_mb: u32,
    /// Network name to attach to (empty = none).
    pub network: String,
}

impl DockerBackend {
    /// Create a new Docker backend.
    #[must_use]
    pub fn new(name: impl Into<String>, analysis_image: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            analysis_image: analysis_image.into(),
            docker_socket: "/var/run/docker.sock".to_string(),
            max_concurrent: 8,
            mem_limit_mb: 512,
            network: String::new(),
        }
    }

    /// Set the memory limit.
    #[must_use]
    pub const fn with_mem_limit(mut self, mb: u32) -> Self {
        self.mem_limit_mb = mb;
        self
    }

    /// Set the Docker network.
    #[must_use]
    pub fn with_network(mut self, net: impl Into<String>) -> Self {
        self.network = net.into();
        self
    }

    fn build_result(&self, job: &SandboxJob) -> SandboxResult {
        let mut result = SandboxResult::clean();
        result.add_log(format!(
            "[Docker] Image={} sample={} mem={}MB net={}",
            self.analysis_image,
            job.filename,
            self.mem_limit_mb,
            if self.network.is_empty() {
                "none"
            } else {
                &self.network
            },
        ));
        result
    }
}

impl SandboxBackend for DockerBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn supports(&self, os: &SandboxOs, arch: &SandboxArch) -> bool {
        // Docker supports Linux guests.
        matches!(os, SandboxOs::Ubuntu22 | SandboxOs::Debian12)
            && matches!(arch, SandboxArch::X64 | SandboxArch::Arm64)
    }

    fn submit(&self, job: &SandboxJob) -> Result<JobHandle, SandboxError> {
        if !self.supports(&job.os_profile, &job.arch) {
            return Err(SandboxError::SpawnFailed(format!(
                "Docker backend '{}' does not support {} / {}",
                self.name, job.os_profile, job.arch
            )));
        }
        Ok(JobHandle::new(job.id.clone(), &self.name))
    }

    fn status(&self, _handle: &JobHandle) -> Result<LiveJobStatus, SandboxError> {
        Ok(LiveJobStatus::Completed)
    }

    fn collect(&self, handle: &JobHandle) -> Result<SandboxResult, SandboxError> {
        let dummy = SandboxJob::new(
            vec![0u8; 64],
            format!("container-{}", handle.id),
            120,
            SandboxOs::Ubuntu22,
        );
        Ok(self.build_result(&dummy))
    }

    fn cancel(&self, _handle: &JobHandle) -> Result<(), SandboxError> {
        Ok(())
    }
}

// ─── ArtifactStore ────────────────────────────────────────────────────────────

/// Central store for sandbox artifacts keyed by sample hash.
#[derive(Debug, Default)]
pub struct ArtifactStore {
    /// hash -> artifact collector
    store: std::collections::HashMap<[u8; 32], ArtifactCollector>,
}

impl ArtifactStore {
    /// Create a new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store an artifact collector for a given hash.
    pub fn insert(&mut self, hash: [u8; 32], artifacts: ArtifactCollector) {
        self.store.insert(hash, artifacts);
    }

    /// Retrieve artifacts for a hash.
    #[must_use]
    pub fn get(&self, hash: &[u8; 32]) -> Option<&ArtifactCollector> {
        self.store.get(hash)
    }

    /// Number of stored artifact sets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Returns `true` if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// All stored hashes.
    #[must_use]
    pub fn hashes(&self) -> Vec<[u8; 32]> {
        self.store.keys().copied().collect()
    }
}

// ─── BehaviorAnalyzer ────────────────────────────────────────────────────────

/// Analyzes behavior records against a set of `BehaviorSignature`s.
pub struct BehaviorAnalyzer {
    pub signatures: Vec<BehaviorSignature>,
}

/// Report produced by the `BehaviorAnalyzer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorReport {
    /// IDs of matched signatures.
    pub matched_signature_ids: Vec<String>,
    /// Human-readable descriptions of matches.
    pub matched_descriptions: Vec<String>,
    /// ATT&CK technique IDs from matched signatures.
    pub technique_ids: Vec<String>,
    /// Total severity score (0-100).
    pub total_severity: u32,
    /// Whether the sample is considered malicious.
    pub is_malicious: bool,
    /// Brief summary.
    pub summary: String,
}

impl BehaviorAnalyzer {
    /// Create an analyzer with a custom signature list.
    #[must_use]
    pub const fn new(signatures: Vec<BehaviorSignature>) -> Self {
        Self { signatures }
    }

    /// Create an analyzer loaded with the built-in signature database.
    #[must_use]
    pub fn with_builtin_signatures() -> Self {
        Self::new(BehaviorSignatureDb::load_builtin().signatures)
    }

    /// Analyze a behavior record and produce a report.
    #[must_use]
    pub fn analyze(&self, record: &BehaviorRecord) -> BehaviorReport {
        let mut matched_ids = Vec::new();
        let mut matched_desc = Vec::new();
        let mut technique_ids = Vec::new();
        let mut total_severity: u32 = 0;

        for sig in &self.signatures {
            if sig.matches(record) {
                matched_ids.push(sig.id.clone());
                matched_desc.push(format!("[{}] {}", sig.id, sig.description));
                total_severity += u32::from(sig.severity);
            }
        }
        total_severity = total_severity.min(100);

        let is_malicious = total_severity >= 20
            || record.flags.contains(BehaviorFlag::INJECTION)
            || record.flags.contains(BehaviorFlag::RANSOMWARE)
            || record.flags.contains(BehaviorFlag::ROOTKIT);

        let summary = if is_malicious {
            format!(
                "MALICIOUS — {} signatures matched, severity={}",
                matched_ids.len(),
                total_severity
            )
        } else {
            "CLEAN — no significant malicious signatures detected".to_string()
        };

        // Simple ATT&CK mapping.
        for id in &matched_ids {
            let technique = match id.as_str() {
                "process_injection" => "T1055",
                "run_key_persistence" | "startup_folder" | "hklm_startup" => "T1547.001",
                "credential_harvesting" => "T1003.001",
                "ransomware" => "T1486",
                "c2_beacon" => "T1071.001",
                "dga" => "T1568.002",
                "uac_bypass" => "T1548.002",
                "anti_vm" => "T1497",
                "lateral_movement" => "T1021.002",
                "keylogger" => "T1056.001",
                "download_and_execute" => "T1105",
                "shadow_copy_deletion" => "T1490",
                "token_impersonation" => "T1134",
                "rootkit_driver" => "T1543.003",
                "screenshot_capture" => "T1113",
                "worm_replication" => "T1080",
                "fileless_powershell" => "T1059.001",
                "dns_tunneling" => "T1071.004",
                "clipboard_hijack" => "T1115",
                "network_enum" => "T1018",
                _ => "",
            };
            if !technique.is_empty() {
                technique_ids.push(technique.to_string());
            }
        }
        technique_ids.dedup();

        BehaviorReport {
            matched_signature_ids: matched_ids,
            matched_descriptions: matched_desc,
            technique_ids,
            total_severity,
            is_malicious,
            summary,
        }
    }
}

// ─── Full SandboxOrchestrator (extended) ─────────────────────────────────────

/// Job queue entry.
#[derive(Debug, Clone)]
pub struct QueuedJob {
    pub job: SandboxJob,
    pub priority: u8,
    pub submitted_at: std::time::Instant,
}

/// Full sandbox orchestration pipeline with backend dispatch, job queue,
/// caching, behavior analysis, and IOC collection.
pub struct SandboxOrchestratorV2 {
    /// Registered backends.
    backends: Vec<Box<dyn SandboxBackend>>,
    /// Pending job queue.
    job_queue: std::collections::VecDeque<QueuedJob>,
    /// Artifact store.
    pub artifact_store: ArtifactStore,
    /// Behavior analyzer.
    pub analyzer: BehaviorAnalyzer,
    /// Max concurrent jobs.
    pub max_concurrent: usize,
    /// Result cache: `sample_hash` -> result.
    results_cache: std::collections::HashMap<[u8; 32], SandboxResult>,
    /// Job ID -> handle mapping.
    submitted_jobs: std::collections::HashMap<String, (JobHandle, SandboxResult)>,
    /// Counter for unique job IDs.
    id_counter: u64,
}

impl SandboxOrchestratorV2 {
    /// Create a new orchestrator.
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            backends: Vec::new(),
            job_queue: std::collections::VecDeque::new(),
            artifact_store: ArtifactStore::new(),
            analyzer: BehaviorAnalyzer::with_builtin_signatures(),
            max_concurrent,
            results_cache: std::collections::HashMap::new(),
            submitted_jobs: std::collections::HashMap::new(),
            id_counter: 0,
        }
    }

    /// Register a sandbox backend.
    pub fn register_backend(&mut self, backend: Box<dyn SandboxBackend>) {
        self.backends.push(backend);
    }

    /// Generate a unique job ID.
    fn next_id(&mut self) -> String {
        let id = self.id_counter;
        self.id_counter += 1;
        format!("orch-job-{id:016x}")
    }

    /// Compute a simple 32-byte hash of `data` (placeholder, not cryptographic).
    #[must_use]
    pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
        let mut h = [0u8; 32];
        for (i, chunk) in data.chunks(4).enumerate() {
            for (j, &b) in chunk.iter().enumerate() {
                let i8 = u8::try_from(i % 256).unwrap_or(u8::MAX);
                let j8 = u8::try_from(j % 256).unwrap_or(u8::MAX);
                h[(i * 4 + j) % 32] ^= b.wrapping_add(i8).wrapping_mul(j8.wrapping_add(1));
            }
        }
        h
    }

    /// Submit a job to the most suitable backend.
    /// Returns the job ID.
    ///
    /// If a cached result exists for the sample hash, returns immediately.
    ///
    /// # Errors
    /// Returns `SandboxError::SpawnFailed` if no compatible backend is found.
    pub fn submit(&mut self, mut job: SandboxJob) -> Result<String, SandboxError> {
        let hash = Self::hash_bytes(&job.sample_bytes);

        // Check cache.
        if let Some(cached) = self.results_cache.get(&hash).cloned() {
            let id = self.next_id();
            self.submitted_jobs
                .insert(id.clone(), (JobHandle::new(id.clone(), "cache"), cached));
            return Ok(id);
        }

        // Assign ID if not set.
        if job.id.is_empty() {
            job.id = self.next_id();
        }
        let job_id = job.id.clone();

        // Find a suitable backend.
        let backend = self
            .backends
            .iter()
            .find(|b| b.supports(&job.os_profile, &job.arch))
            .ok_or_else(|| {
                SandboxError::SpawnFailed(format!(
                    "no backend for {} / {}",
                    job.os_profile, job.arch
                ))
            })?;

        let handle = backend.submit(&job)?;
        let result = backend.collect(&handle)?;

        // Store in cache and submitted jobs.
        self.results_cache.insert(hash, result.clone());
        self.submitted_jobs.insert(job_id.clone(), (handle, result));

        Ok(job_id)
    }

    /// Get the result for a submitted job.
    #[must_use]
    pub fn get_result(&self, job_id: &str) -> Option<&SandboxResult> {
        self.submitted_jobs.get(job_id).map(|(_, r)| r)
    }

    /// Analyze the behavior of a result using the built-in analyzer.
    #[must_use]
    pub fn analyze_result(&self, result: &SandboxResult) -> Option<BehaviorReport> {
        result
            .behavior_record
            .as_ref()
            .map(|rec| self.analyzer.analyze(rec))
    }

    /// Batch-submit multiple jobs. Returns a list of job IDs.
    pub fn submit_batch_v2(&mut self, jobs: Vec<SandboxJob>) -> Vec<Result<String, SandboxError>> {
        jobs.into_iter().map(|j| self.submit(j)).collect()
    }

    /// Number of registered backends.
    #[must_use]
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// Number of cached results.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.results_cache.len()
    }

    /// Drain the queue, executing up to `max_concurrent` pending jobs.
    pub fn flush_queue(&mut self) {
        let limit = self.max_concurrent;
        let mut count = 0;
        while count < limit {
            let Some(entry) = self.job_queue.pop_front() else {
                break;
            };
            let _ = self.submit(entry.job);
            count += 1;
        }
    }

    /// Enqueue a job for deferred execution.
    pub fn enqueue(&mut self, job: SandboxJob) {
        let priority = job.priority;
        let entry = QueuedJob {
            job,
            priority,
            submitted_at: std::time::Instant::now(),
        };
        // Insert in priority order (highest priority first).
        let pos = self
            .job_queue
            .partition_point(|e| e.priority >= entry.priority);
        self.job_queue.insert(pos, entry);
    }

    /// Number of jobs in the queue.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.job_queue.len()
    }

    /// All submitted job IDs.
    #[must_use]
    pub fn job_ids(&self) -> Vec<&str> {
        self.submitted_jobs.keys().map(std::string::String::as_str).collect()
    }

    /// Collect IOCs from all completed results.
    #[must_use]
    pub fn all_iocs(&self) -> IocCollection {
        let mut merged = IocCollection::new();
        for (_, result) in self.submitted_jobs.values() {
            let iocs = SandboxOrchestrator::collect_iocs(result);
            merged.merge(&iocs);
        }
        merged
    }
}

// ─── Additional Sandbox Signatures (30+) ─────────────────────────────────────

impl BehaviorSignatureDb {
    /// Load an extended set of 30+ built-in behavioral signatures.
    #[must_use]
    pub fn load_extended() -> Self {
        let mut db = Self::load_builtin();

        // 23. Bootkit / MBR infection
        db.add(BehaviorSignature {
            id: "bootkit_mbr".to_string(),
            name: "Bootkit / MBR Infection".to_string(),
            description: "Writes to physical disk sectors to infect the MBR.".to_string(),
            syscall_patterns: vec!["NtWriteFile".to_string(), "DeviceIoControl".to_string()],
            registry_patterns: vec![],
            file_patterns: vec![r"\\.\PhysicalDrive".to_string()],
            required_flags: BehaviorFlag::FILESYSTEM | BehaviorFlag::ROOTKIT,
            severity: 30,
        });

        // 24. Browser password harvesting
        db.add(BehaviorSignature {
            id: "browser_password_harvest".to_string(),
            name: "Browser Password Harvesting".to_string(),
            description: "Accesses browser profile directories to steal saved credentials."
                .to_string(),
            syscall_patterns: vec!["CreateFile".to_string(), "ReadFile".to_string()],
            registry_patterns: vec![],
            file_patterns: vec![
                "Login Data".to_string(),
                "Cookies".to_string(),
                "logins.json".to_string(),
                "key4.db".to_string(),
            ],
            required_flags: BehaviorFlag::FILESYSTEM,
            severity: 22,
        });

        // 25. WMI persistence
        db.add(BehaviorSignature {
            id: "wmi_persistence".to_string(),
            name: "WMI Event Subscription Persistence".to_string(),
            description: "Creates a WMI event subscription for persistent execution.".to_string(),
            syscall_patterns: vec![
                "WbemCreateInstance".to_string(),
                "IWbemServices".to_string(),
            ],
            registry_patterns: vec![],
            file_patterns: vec![],
            required_flags: BehaviorFlag::PERSISTENCE,
            severity: 20,
        });

        // 26. Scheduled task persistence
        db.add(BehaviorSignature {
            id: "scheduled_task".to_string(),
            name: "Scheduled Task Creation".to_string(),
            description: "Creates a Windows Task Scheduler task for persistent execution."
                .to_string(),
            syscall_patterns: vec![
                "ITaskScheduler".to_string(),
                "schtasks".to_string(),
                "at.exe".to_string(),
            ],
            registry_patterns: vec![
                "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule".to_string(),
            ],
            file_patterns: vec![
                "Tasks".to_string(),
                "Microsoft\\Windows\\Task Scheduler".to_string(),
            ],
            required_flags: BehaviorFlag::PERSISTENCE,
            severity: 18,
        });

        // 27. Service installation persistence
        db.add(BehaviorSignature {
            id: "service_persistence".to_string(),
            name: "Windows Service Installation".to_string(),
            description: "Installs a Windows service for persistent execution.".to_string(),
            syscall_patterns: vec!["CreateService".to_string(), "OpenSCManager".to_string()],
            registry_patterns: vec!["\\SYSTEM\\CurrentControlSet\\Services".to_string()],
            file_patterns: vec![],
            required_flags: BehaviorFlag::PERSISTENCE,
            severity: 18,
        });

        // 28. Exfiltration via HTTP POST
        db.add(BehaviorSignature {
            id: "http_exfiltration".to_string(),
            name: "Data Exfiltration via HTTP POST".to_string(),
            description: "Sends data to unknown external hosts via HTTP POST requests.".to_string(),
            syscall_patterns: vec![
                "HttpSendRequest".to_string(),
                "InternetOpenUrl".to_string(),
                "WinHttpSendRequest".to_string(),
            ],
            registry_patterns: vec![],
            file_patterns: vec![],
            required_flags: BehaviorFlag::NETWORK | BehaviorFlag::C2,
            severity: 20,
        });

        // 29. Log clearing / event log deletion
        db.add(BehaviorSignature {
            id: "log_clearing".to_string(),
            name: "Event Log Clearing".to_string(),
            description: "Clears Windows event logs to cover tracks.".to_string(),
            syscall_patterns: vec!["ClearEventLog".to_string(), "wevtutil".to_string()],
            registry_patterns: vec![],
            file_patterns: vec!["wevtutil".to_string(), "evtx".to_string()],
            required_flags: BehaviorFlag::ANTIANALYSIS,
            severity: 20,
        });

        for sig in Self::extended_sigs_part2() {
            db.add(sig);
        }
        db
    }

    fn extended_sigs_part2() -> Vec<BehaviorSignature> {
        vec![
            // 30. AV disabling
            BehaviorSignature {
                id: "av_disable".to_string(),
                name: "Antivirus / Defender Disabling".to_string(),
                description: "Modifies registry or calls APIs to disable Windows Defender or AV products.".to_string(),
                syscall_patterns: vec!["RegSetValue".to_string()],
                registry_patterns: vec![
                    "\\SOFTWARE\\Policies\\Microsoft\\Windows Defender".to_string(),
                    "DisableAntiSpyware".to_string(),
                ],
                file_patterns: vec![],
                required_flags: BehaviorFlag::ANTIANALYSIS,
                severity: 25,
            },
            // 31. WScript / mshta / certutil execution
            BehaviorSignature {
                id: "lolbas_execution".to_string(),
                name: "LOLBAS Execution (WScript/mshta/certutil)".to_string(),
                description: "Abuses built-in Windows tools to execute malicious code.".to_string(),
                syscall_patterns: vec!["CreateProcess".to_string()],
                registry_patterns: vec![],
                file_patterns: vec![
                    "wscript.exe".to_string(), "cscript.exe".to_string(),
                    "mshta.exe".to_string(), "certutil.exe".to_string(),
                    "regsvr32.exe".to_string(), "rundll32.exe".to_string(),
                ],
                required_flags: BehaviorFlag::PROCESS,
                severity: 18,
            },
            // 32. Process enumeration / discovery
            BehaviorSignature {
                id: "process_discovery".to_string(),
                name: "Process and System Discovery".to_string(),
                description: "Enumerates running processes and system information for reconnaissance.".to_string(),
                syscall_patterns: vec![
                    "CreateToolhelp32Snapshot".to_string(), "Process32First".to_string(),
                    "Process32Next".to_string(), "NtQuerySystemInformation".to_string(),
                ],
                registry_patterns: vec![],
                file_patterns: vec![],
                required_flags: BehaviorFlag::PROCESS,
                severity: 8,
            },
            // 33. Privilege escalation via local exploit
            BehaviorSignature {
                id: "privilege_escalation".to_string(),
                name: "Privilege Escalation via Token Theft".to_string(),
                description: "Steals a SYSTEM token to gain elevated privileges.".to_string(),
                syscall_patterns: vec![
                    "OpenProcessToken".to_string(), "ImpersonateNamedPipeClient".to_string(),
                    "NtSetInformationThread".to_string(),
                ],
                registry_patterns: vec![],
                file_patterns: vec![],
                required_flags: BehaviorFlag::PROCESS,
                severity: 22,
            },
            // 34. AMSI bypass
            BehaviorSignature {
                id: "amsi_bypass".to_string(),
                name: "AMSI Bypass".to_string(),
                description: "Patches AmsiScanBuffer to bypass AMSI scanning.".to_string(),
                syscall_patterns: vec![
                    "VirtualProtect".to_string(), "WriteProcessMemory".to_string(),
                    "AmsiScanBuffer".to_string(),
                ],
                registry_patterns: vec![],
                file_patterns: vec![],
                required_flags: BehaviorFlag::ANTIANALYSIS | BehaviorFlag::INJECTION,
                severity: 25,
            },
            // 35. Reflective DLL injection
            BehaviorSignature {
                id: "reflective_dll".to_string(),
                name: "Reflective DLL Injection".to_string(),
                description: "Loads a DLL directly from memory without touching the file system.".to_string(),
                syscall_patterns: vec![
                    "VirtualAlloc".to_string(), "VirtualAllocEx".to_string(),
                    "RtlCreateHeap".to_string(),
                ],
                registry_patterns: vec![],
                file_patterns: vec![],
                required_flags: BehaviorFlag::INJECTION,
                severity: 26,
            },
        ]
    }
}

// ─── Extended Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    // ── JobHandle ─────────────────────────────────────────────────────────

    #[test]
    fn test_job_handle_new() {
        let h = JobHandle::new("j1", "qemu");
        assert_eq!(h.id, "j1");
        assert_eq!(h.backend, "qemu");
    }

    #[test]
    fn test_job_handle_display() {
        let h = JobHandle::new("abc", "mock");
        let s = h.to_string();
        assert!(s.contains("abc"));
        assert!(s.contains("mock"));
    }

    // ── LiveJobStatus ─────────────────────────────────────────────────────

    #[test]
    fn test_live_job_status_display_queued() {
        assert_eq!(LiveJobStatus::Queued.to_string(), "queued");
    }

    #[test]
    fn test_live_job_status_display_running() {
        let s = LiveJobStatus::Running {
            started_at: 1000,
            progress_pct: 50,
        };
        assert!(s.to_string().contains("50%"));
    }

    #[test]
    fn test_live_job_status_display_failed() {
        let s = LiveJobStatus::Failed {
            error: "OOM".to_string(),
        };
        assert!(s.to_string().contains("OOM"));
    }

    #[test]
    fn test_live_job_status_completed() {
        assert_eq!(LiveJobStatus::Completed.to_string(), "completed");
    }

    // ── NetworkMode ───────────────────────────────────────────────────────

    #[test]
    fn test_network_mode_display() {
        assert_eq!(NetworkMode::None.to_string(), "none");
        assert_eq!(NetworkMode::Internet.to_string(), "internet");
        assert_eq!(NetworkMode::INetSim.to_string(), "inetsim");
        let c = NetworkMode::Custom("vlan100".to_string());
        assert!(c.to_string().contains("vlan100"));
    }

    // ── SandboxJob ────────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_job_new() {
        let job = SandboxJob::new(b"MZ\x90\x00".to_vec(), "test.exe", 60, SandboxOs::Windows10);
        assert_eq!(job.filename, "test.exe");
        assert_eq!(job.timeout, 60);
        assert!(job.is_pe());
        assert!(!job.is_elf());
    }

    #[test]
    fn test_sandbox_job_elf() {
        let job = SandboxJob::new(b"\x7fELF\x02".to_vec(), "malware", 30, SandboxOs::Ubuntu22);
        assert!(job.is_elf());
        assert!(!job.is_pe());
    }

    #[test]
    fn test_sandbox_job_hash_consistent() {
        let bytes = vec![1u8, 2, 3, 4];
        let a = SandboxJob::new(bytes.clone(), "a.exe", 60, SandboxOs::Windows10);
        let b = SandboxJob::new(bytes, "a.exe", 60, SandboxOs::Windows10);
        assert_eq!(a.sample_hash(), b.sample_hash());
    }

    #[test]
    fn test_sandbox_job_with_args() {
        let job = SandboxJob::new(b"MZ".to_vec(), "x.exe", 30, SandboxOs::Windows10)
            .with_args(vec!["--silent".to_string(), "--persist".to_string()]);
        assert_eq!(job.args.len(), 2);
    }

    #[test]
    fn test_sandbox_job_with_network() {
        let job = SandboxJob::new(b"MZ".to_vec(), "x.exe", 30, SandboxOs::Windows10)
            .with_network(NetworkMode::INetSim);
        assert_eq!(job.network_mode, NetworkMode::INetSim);
    }

    // ── QemuKvmBackend ────────────────────────────────────────────────────

    #[test]
    fn test_qemu_backend_supports_windows10_x64() {
        let b = QemuKvmBackend::new("qemu", "/images/win10.qcow2");
        assert!(b.supports(&SandboxOs::Windows10, &SandboxArch::X64));
    }

    #[test]
    fn test_qemu_backend_does_not_support_android() {
        let b = QemuKvmBackend::new("qemu", "/images/win10.qcow2");
        assert!(!b.supports(&SandboxOs::AndroidApi33, &SandboxArch::Arm64));
    }

    #[test]
    fn test_qemu_backend_submit_ok() {
        let b = QemuKvmBackend::new("qemu", "/images/win10.qcow2");
        let job = SandboxJob::new(b"MZ".to_vec(), "s.exe", 60, SandboxOs::Windows10);
        let handle = b.submit(&job).unwrap();
        assert_eq!(handle.backend, "qemu");
    }

    #[test]
    fn test_qemu_backend_submit_unsupported() {
        let b = QemuKvmBackend::new("qemu", "/images/win10.qcow2");
        let job = SandboxJob::new(b"MZ".to_vec(), "s.exe", 60, SandboxOs::AndroidApi33)
            .with_arch(SandboxArch::Arm64);
        assert!(b.submit(&job).is_err());
    }

    #[test]
    fn test_qemu_backend_collect_ok() {
        let b = QemuKvmBackend::new("qemu", "/images/win10.qcow2");
        let job = SandboxJob::new(b"MZ".to_vec(), "s.exe", 60, SandboxOs::Windows10);
        let handle = b.submit(&job).unwrap();
        let result = b.collect(&handle).unwrap();
        assert!(!result.log.is_empty());
        assert!(result.log[0].contains("QEMU"));
    }

    // ── FirecrackerBackend ────────────────────────────────────────────────

    #[test]
    fn test_firecracker_supports_linux_x64() {
        let b = FirecrackerBackend::new("fc", "/usr/bin/firecracker", "/rootfs.ext4", "/vmlinux");
        assert!(b.supports(&SandboxOs::Ubuntu22, &SandboxArch::X64));
    }

    #[test]
    fn test_firecracker_does_not_support_windows() {
        let b = FirecrackerBackend::new("fc", "/usr/bin/firecracker", "/rootfs.ext4", "/vmlinux");
        assert!(!b.supports(&SandboxOs::Windows10, &SandboxArch::X64));
    }

    #[test]
    fn test_firecracker_socket_path() {
        let b = FirecrackerBackend::new("fc", "/usr/bin/firecracker", "/rootfs.ext4", "/vmlinux");
        let path = b.socket_path("abc123");
        assert!(path.contains("abc123"));
    }

    #[test]
    fn test_firecracker_collect_ok() {
        let b = FirecrackerBackend::new("fc", "/usr/bin/firecracker", "/rootfs.ext4", "/vmlinux");
        let job = SandboxJob::new(b"\x7fELF".to_vec(), "malware", 30, SandboxOs::Ubuntu22);
        let handle = b.submit(&job).unwrap();
        let result = b.collect(&handle).unwrap();
        assert!(result.log[0].contains("Firecracker"));
    }

    // ── DockerBackend ─────────────────────────────────────────────────────

    #[test]
    fn test_docker_supports_linux_x64() {
        let b = DockerBackend::new("docker", "analysis:latest");
        assert!(b.supports(&SandboxOs::Ubuntu22, &SandboxArch::X64));
    }

    #[test]
    fn test_docker_does_not_support_windows() {
        let b = DockerBackend::new("docker", "analysis:latest");
        assert!(!b.supports(&SandboxOs::Windows10, &SandboxArch::X64));
    }

    #[test]
    fn test_docker_collect_ok() {
        let b = DockerBackend::new("docker", "analysis:latest");
        let job = SandboxJob::new(b"MZ".to_vec(), "s.exe", 60, SandboxOs::Ubuntu22);
        let handle = b.submit(&job).unwrap();
        let result = b.collect(&handle).unwrap();
        assert!(result.log[0].contains("Docker"));
    }

    // ── ArtifactStore ─────────────────────────────────────────────────────

    #[test]
    fn test_artifact_store_insert_get() {
        let mut store = ArtifactStore::new();
        let hash = [42u8; 32];
        let col = ArtifactCollector::new();
        store.insert(hash, col);
        assert!(store.get(&hash).is_some());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_artifact_store_miss() {
        let store = ArtifactStore::new();
        assert!(store.get(&[0u8; 32]).is_none());
    }

    // ── BehaviorAnalyzer ──────────────────────────────────────────────────

    #[test]
    fn test_behavior_analyzer_builtin_count() {
        let a = BehaviorAnalyzer::with_builtin_signatures();
        assert!(a.signatures.len() >= 20);
    }

    #[test]
    fn test_behavior_analyzer_analyze_mock() {
        let a = BehaviorAnalyzer::with_builtin_signatures();
        let rec = BehaviorRecord::mock();
        let report = a.analyze(&rec);
        assert!(report.is_malicious);
        assert!(!report.matched_signature_ids.is_empty());
        assert!(report.total_severity > 0);
    }

    #[test]
    fn test_behavior_analyzer_clean() {
        let a = BehaviorAnalyzer::with_builtin_signatures();
        let rec = BehaviorRecord::new(1);
        let report = a.analyze(&rec);
        // Clean record has no flags, so should not be malicious.
        assert!(!report.is_malicious);
    }

    #[test]
    fn test_behavior_report_technique_ids_not_empty_for_mock() {
        let a = BehaviorAnalyzer::with_builtin_signatures();
        let rec = BehaviorRecord::mock();
        let report = a.analyze(&rec);
        assert!(!report.technique_ids.is_empty());
    }

    #[test]
    fn test_behavior_report_summary_malicious() {
        let a = BehaviorAnalyzer::with_builtin_signatures();
        let rec = BehaviorRecord::mock();
        let report = a.analyze(&rec);
        assert!(report.summary.contains("MALICIOUS"));
    }

    // ── BehaviorSignatureDb (extended) ────────────────────────────────────

    #[test]
    fn test_extended_db_count_ge_30() {
        let db = BehaviorSignatureDb::load_extended();
        assert!(db.len() >= 30);
    }

    #[test]
    fn test_extended_db_has_scheduled_task() {
        let db = BehaviorSignatureDb::load_extended();
        assert!(db.signatures.iter().any(|s| s.id == "scheduled_task"));
    }

    #[test]
    fn test_extended_db_has_lolbas() {
        let db = BehaviorSignatureDb::load_extended();
        assert!(db.signatures.iter().any(|s| s.id == "lolbas_execution"));
    }

    #[test]
    fn test_extended_db_has_amsi_bypass() {
        let db = BehaviorSignatureDb::load_extended();
        assert!(db.signatures.iter().any(|s| s.id == "amsi_bypass"));
    }

    // ── SandboxOrchestratorV2 ─────────────────────────────────────────────

    #[test]
    fn test_orchestrator_v2_register_backend() {
        let mut orc = SandboxOrchestratorV2::new(4);
        orc.register_backend(Box::new(DockerBackend::new("docker", "analysis:latest")));
        assert_eq!(orc.backend_count(), 1);
    }

    #[test]
    fn test_orchestrator_v2_submit_ok() {
        let mut orc = SandboxOrchestratorV2::new(4);
        orc.register_backend(Box::new(DockerBackend::new("docker", "analysis:latest")));
        let job = SandboxJob::new(b"MZ".to_vec(), "s.exe", 60, SandboxOs::Ubuntu22);
        let id = orc.submit(job).unwrap();
        let result = orc.get_result(&id);
        assert!(result.is_some());
    }

    #[test]
    fn test_orchestrator_v2_submit_no_backend_err() {
        let mut orc = SandboxOrchestratorV2::new(4);
        let job = SandboxJob::new(b"MZ".to_vec(), "s.exe", 60, SandboxOs::Windows10);
        let err = orc.submit(job).unwrap_err();
        assert!(matches!(err, SandboxError::SpawnFailed(_)));
    }

    #[test]
    fn test_orchestrator_v2_cache_hit() {
        let mut orc = SandboxOrchestratorV2::new(4);
        orc.register_backend(Box::new(DockerBackend::new("docker", "analysis:latest")));
        let bytes = b"MZ\x90\x00".to_vec();
        let job1 = SandboxJob::new(bytes.clone(), "s.exe", 60, SandboxOs::Ubuntu22);
        let job2 = SandboxJob::new(bytes, "s.exe", 60, SandboxOs::Ubuntu22);
        let _id1 = orc.submit(job1).unwrap();
        // Second submit should hit the cache (no backend call needed).
        let _id2 = orc.submit(job2).unwrap();
        // Cache should have exactly one entry for this sample.
        assert!(orc.cache_size() >= 1);
    }

    #[test]
    fn test_orchestrator_v2_all_iocs_empty() {
        let orc = SandboxOrchestratorV2::new(4);
        let iocs = orc.all_iocs();
        assert!(iocs.is_empty());
    }

    #[test]
    fn test_orchestrator_v2_enqueue_and_flush() {
        let mut orc = SandboxOrchestratorV2::new(4);
        orc.register_backend(Box::new(DockerBackend::new("d", "analysis:latest")));
        let job = SandboxJob::new(b"MZ".to_vec(), "e.exe", 30, SandboxOs::Ubuntu22);
        orc.enqueue(job);
        assert_eq!(orc.queue_depth(), 1);
        orc.flush_queue();
        assert_eq!(orc.queue_depth(), 0);
    }

    #[test]
    fn test_orchestrator_v2_priority_queue_ordering() {
        let mut orc = SandboxOrchestratorV2::new(4);
        let mut high = SandboxJob::new(b"HI".to_vec(), "high.exe", 30, SandboxOs::Ubuntu22);
        high.priority = 255;
        let mut low = SandboxJob::new(b"LO".to_vec(), "low.exe", 30, SandboxOs::Ubuntu22);
        low.priority = 0;
        orc.enqueue(low);
        orc.enqueue(high);
        // Top of queue should be the high-priority job.
        let front = orc.job_queue.front().unwrap();
        assert_eq!(front.priority, 255);
    }

    #[test]
    fn test_orchestrator_v2_batch_submit() {
        let mut orc = SandboxOrchestratorV2::new(4);
        orc.register_backend(Box::new(DockerBackend::new("d", "analysis:latest")));
        let jobs = vec![
            SandboxJob::new(b"MZ1".to_vec(), "a.exe", 30, SandboxOs::Ubuntu22),
            SandboxJob::new(b"MZ2".to_vec(), "b.exe", 30, SandboxOs::Ubuntu22),
        ];
        let results = orc.submit_batch_v2(jobs);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(std::result::Result::is_ok));
    }

    #[test]
    fn test_hash_bytes_deterministic() {
        let a = SandboxOrchestratorV2::hash_bytes(b"hello");
        let b = SandboxOrchestratorV2::hash_bytes(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn test_hash_bytes_different_inputs() {
        let a = SandboxOrchestratorV2::hash_bytes(b"hello");
        let b = SandboxOrchestratorV2::hash_bytes(b"world");
        assert_ne!(a, b);
    }
}

// ─── SandboxReport ────────────────────────────────────────────────────────────

/// A complete, structured report produced from a sandbox run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    /// Unique report ID.
    pub report_id: String,
    /// Sample filename.
    pub filename: String,
    /// SHA-256 hash placeholder.
    pub sample_hash: String,
    /// OS profile used.
    pub os: SandboxOs,
    /// Architecture.
    pub arch: SandboxArch,
    /// Analysis result.
    pub result: SandboxResult,
    /// Behavior report (if behavior analysis was run).
    pub behavior_report: Option<BehaviorReport>,
    /// IOCs extracted.
    pub iocs: IocCollection,
    /// Classification.
    pub classification: Option<MalwareClassification>,
    /// Matched YARA rules.
    pub yara_matches: Vec<String>,
    /// Analysis timestamp (Unix ms).
    pub timestamp_ms: u64,
}

impl SandboxReport {
    /// Create a report from a sandbox result.
    #[must_use]
    pub fn from_result(
        filename: impl Into<String>,
        sample_hash: impl Into<String>,
        os: SandboxOs,
        arch: SandboxArch,
        result: SandboxResult,
        yara_matches: Vec<String>,
    ) -> Self {
        let iocs = SandboxOrchestrator::collect_iocs(&result);
        let behavior_report = result
            .behavior_record
            .as_ref()
            .map(|rec| BehaviorAnalyzer::with_builtin_signatures().analyze(rec));
        let classification = Some(MalwareFamilyClassifier::classify(&result, &yara_matches));
        let report_id = format!(
            "rpt-{:016x}",
            u64::from(result.threat_score) ^ result.duration_ms
        );
        Self {
            report_id,
            filename: filename.into(),
            sample_hash: sample_hash.into(),
            os,
            arch,
            result,
            behavior_report,
            iocs,
            classification,
            yara_matches,
            timestamp_ms: 0,
        }
    }

    /// Returns `true` if the sample is likely malicious.
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        self.result.is_malicious()
            || self
                .classification
                .as_ref()
                .is_some_and(MalwareClassification::is_malicious)
    }

    /// Returns the threat score (0-100).
    #[must_use]
    pub const fn threat_score(&self) -> u32 {
        self.result.threat_score
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    /// Returns a string on serialization failure.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// Generate a human-readable text summary.
    #[must_use]
    pub fn summary_text(&self) -> String {
        let verdict = if self.is_malicious() {
            "MALICIOUS"
        } else {
            "CLEAN"
        };
        let category = self
            .classification
            .as_ref().map_or_else(|| "unknown".to_string(), |c| c.category.to_string());
        let family = self
            .classification
            .as_ref()
            .and_then(|c| c.family.clone())
            .unwrap_or_else(|| "unknown".to_string());
        format!(
            "=== Sandbox Report [{}] ===\n\
             File:     {}\n\
             Hash:     {}\n\
             OS/Arch:  {}/{}\n\
             Verdict:  {} (score={})\n\
             Category: {}\n\
             Family:   {}\n\
             IOCs:     {} total ({} IPs, {} domains)\n\
             YARA:     {} matches\n\
             Duration: {}ms",
            self.report_id,
            self.filename,
            self.sample_hash,
            self.os,
            self.arch,
            verdict,
            self.threat_score(),
            category,
            family,
            self.iocs.total(),
            self.iocs.ips.len(),
            self.iocs.domains.len(),
            self.yara_matches.len(),
            self.result.duration_ms,
        )
    }
}

// ─── SandboxPipeline ─────────────────────────────────────────────────────────

/// A complete analysis pipeline: job submission, behavior analysis, classification, reporting.
pub struct SandboxPipeline {
    pub orchestrator: SandboxOrchestratorV2,
    pub signature_db: BehaviorSignatureDb,
}

impl SandboxPipeline {
    /// Create a new pipeline with default backends and extended signatures.
    #[must_use]
    pub fn new() -> Self {
        Self {
            orchestrator: SandboxOrchestratorV2::new(4),
            signature_db: BehaviorSignatureDb::load_extended(),
        }
    }

    /// Register a backend.
    pub fn register_backend(&mut self, backend: Box<dyn SandboxBackend>) {
        self.orchestrator.register_backend(backend);
    }

    /// Submit a job and produce a full `SandboxReport`.
    ///
    /// # Errors
    /// Returns `SandboxError` if submission or collection fails.
    pub fn analyze(
        &mut self,
        job: SandboxJob,
        yara_matches: Vec<String>,
    ) -> Result<SandboxReport, SandboxError> {
        let filename = job.filename.clone();
        let sample_hash_str = format!("{:x}", {
            let h = SandboxOrchestratorV2::hash_bytes(&job.sample_bytes);
            u64::from_le_bytes(h[..8].try_into().unwrap_or([0u8; 8]))
        });
        let os = job.os_profile.clone();
        let arch = job.arch.clone();

        let job_id = self.orchestrator.submit(job)?;
        let result = self
            .orchestrator
            .get_result(&job_id)
            .cloned()
            .ok_or_else(|| SandboxError::Io("result unavailable".to_string()))?;

        let report =
            SandboxReport::from_result(filename, sample_hash_str, os, arch, result, yara_matches);
        Ok(report)
    }

    /// Submit multiple jobs in batch and collect reports.
    pub fn analyze_batch(
        &mut self,
        jobs: Vec<(SandboxJob, Vec<String>)>,
    ) -> Vec<Result<SandboxReport, SandboxError>> {
        jobs.into_iter()
            .map(|(job, yara)| self.analyze(job, yara))
            .collect()
    }

    /// Number of registered backends.
    #[must_use]
    pub fn backend_count(&self) -> usize {
        self.orchestrator.backend_count()
    }
}

impl Default for SandboxPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ─── SandboxPipeline Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    fn linux_job(sample: &[u8]) -> SandboxJob {
        SandboxJob::new(sample.to_vec(), "malware", 30, SandboxOs::Ubuntu22)
    }

    fn windows_job(sample: &[u8]) -> SandboxJob {
        SandboxJob::new(sample.to_vec(), "malware.exe", 60, SandboxOs::Windows10)
    }

    // ── SandboxReport ─────────────────────────────────────────────────────

    #[test]
    fn test_report_from_clean_result() {
        let result = SandboxResult::clean();
        let report = SandboxReport::from_result(
            "clean.exe",
            "abc123",
            SandboxOs::Windows10,
            SandboxArch::X64,
            result,
            vec![],
        );
        assert!(!report.is_malicious());
        assert_eq!(report.threat_score(), 0);
    }

    #[test]
    fn test_report_from_mock_result() {
        let result = SandboxResult::mock();
        let yara = vec!["cobalt_beacon".to_string()];
        let report = SandboxReport::from_result(
            "beacon.exe",
            "deadbeef",
            SandboxOs::Windows10,
            SandboxArch::X64,
            result,
            yara,
        );
        assert!(report.is_malicious());
        assert!(!report.iocs.is_empty());
    }

    #[test]
    fn test_report_summary_text_contains_verdict() {
        let result = SandboxResult::mock();
        let report = SandboxReport::from_result(
            "m.exe",
            "hash",
            SandboxOs::Windows10,
            SandboxArch::X64,
            result,
            vec![],
        );
        let text = report.summary_text();
        assert!(text.contains("MALICIOUS"));
        assert!(text.contains("Sandbox Report"));
    }

    #[test]
    fn test_report_to_json() {
        let result = SandboxResult::clean();
        let report = SandboxReport::from_result(
            "x.exe",
            "h",
            SandboxOs::Windows10,
            SandboxArch::X64,
            result,
            vec![],
        );
        let json = report.to_json().unwrap();
        assert!(json.contains("report_id"));
    }

    #[test]
    fn test_report_yara_classification() {
        let result = SandboxResult::clean();
        let yara = vec!["wannacry_v2_ransomware".to_string()];
        let report = SandboxReport::from_result(
            "wc.exe",
            "h",
            SandboxOs::Windows10,
            SandboxArch::X64,
            result,
            yara,
        );
        let cls = report.classification.as_ref().unwrap();
        assert!(matches!(cls.category, MalwareCategory::Ransomware));
    }

    // ── SandboxPipeline ───────────────────────────────────────────────────

    #[test]
    fn test_pipeline_new() {
        let pipeline = SandboxPipeline::new();
        assert_eq!(pipeline.backend_count(), 0);
    }

    #[test]
    fn test_pipeline_register_backend() {
        let mut pipeline = SandboxPipeline::new();
        pipeline.register_backend(Box::new(DockerBackend::new("d", "img")));
        assert_eq!(pipeline.backend_count(), 1);
    }

    #[test]
    fn test_pipeline_analyze_ok() {
        let mut pipeline = SandboxPipeline::new();
        pipeline.register_backend(Box::new(DockerBackend::new("d", "img")));
        let job = linux_job(b"\x7fELF");
        let result = pipeline.analyze(job, vec![]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pipeline_analyze_no_backend_err() {
        let mut pipeline = SandboxPipeline::new();
        let job = windows_job(b"MZ");
        let result = pipeline.analyze(job, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_pipeline_analyze_batch() {
        let mut pipeline = SandboxPipeline::new();
        pipeline.register_backend(Box::new(DockerBackend::new("d", "img")));
        let jobs = vec![
            (linux_job(b"\x7fELF"), vec![]),
            (linux_job(b"\x7fELF"), vec![]),
        ];
        let reports = pipeline.analyze_batch(jobs);
        assert_eq!(reports.len(), 2);
        assert!(reports.iter().all(std::result::Result::is_ok));
    }

    #[test]
    fn test_pipeline_default() {
        let p = SandboxPipeline::default();
        assert_eq!(p.backend_count(), 0);
    }

    // ── SandboxOrchestratorV2 all_iocs with mock ──────────────────────────

    #[test]
    fn test_orchestrator_v2_all_iocs_with_mock_result() {
        let mut orc = SandboxOrchestratorV2::new(4);
        orc.register_backend(Box::new(MockSandbox::malicious("mock")));
        // MockSandbox supports x86/x64/arm/arm64 but not ubuntu22 specifically
        // Use a backend that does:
        let job = SandboxJob::new(b"MZ".to_vec(), "s.exe", 60, SandboxOs::Windows10)
            .with_arch(SandboxArch::X64);
        // No backend supports Windows10 in orc — add mock that does
        // Actually mock supports all arches, but needs to be checked via supports().
        // MockSandbox::supports_arch checks only arch, not os.
        // Let's just confirm the path runs (even if it fails since mock supports_arch
        // doesn't check os — it will actually succeed).
        let _result = orc.submit(job);
        // just ensure no panic
    }

    // ── BehaviorReport ATT&CK technique ───────────────────────────────────

    #[test]
    fn test_behavior_report_technique_mapping() {
        let analyzer = BehaviorAnalyzer::with_builtin_signatures();
        let rec = BehaviorRecord::mock();
        let report = analyzer.analyze(&rec);
        // process_injection -> T1055
        assert!(report.technique_ids.contains(&"T1055".to_string()));
    }

    #[test]
    fn test_behavior_report_run_key_technique() {
        let analyzer = BehaviorAnalyzer::with_builtin_signatures();
        let rec = BehaviorRecord::mock(); // has run key write
        let report = analyzer.analyze(&rec);
        assert!(report.technique_ids.contains(&"T1547.001".to_string()));
    }

    // ── BehaviorAnalyzer custom signatures ────────────────────────────────

    #[test]
    fn test_custom_signature_matches() {
        let sig = BehaviorSignature {
            id: "custom_test".to_string(),
            name: "Custom Test".to_string(),
            description: "Test signature".to_string(),
            syscall_patterns: vec!["VirtualAllocEx".to_string()],
            registry_patterns: vec![],
            file_patterns: vec![],
            required_flags: BehaviorFlag::INJECTION,
            severity: 5,
        };
        let analyzer = BehaviorAnalyzer::new(vec![sig]);
        let rec = BehaviorRecord::mock();
        let report = analyzer.analyze(&rec);
        assert!(
            report
                .matched_signature_ids
                .contains(&"custom_test".to_string())
        );
    }

    // ── JobHandle equality ────────────────────────────────────────────────

    #[test]
    fn test_job_handle_equality() {
        let a = JobHandle::new("j1", "backend");
        let b = JobHandle::new("j1", "backend");
        assert_eq!(a, b);
    }

    #[test]
    fn test_job_handle_inequality() {
        let a = JobHandle::new("j1", "backend");
        let b = JobHandle::new("j2", "backend");
        assert_ne!(a, b);
    }

    // ── SandboxJob ID uniqueness ──────────────────────────────────────────

    #[test]
    fn test_sandbox_job_different_samples_different_id() {
        let j1 = SandboxJob::new(b"sample1".to_vec(), "a.exe", 30, SandboxOs::Windows10);
        let j2 = SandboxJob::new(b"sample2".to_vec(), "a.exe", 30, SandboxOs::Windows10);
        // Different bytes -> different hash -> different ID
        assert_ne!(j1.id, j2.id);
    }

    // ── QemuKvmBackend clone_snapshot ─────────────────────────────────────

    #[test]
    fn test_qemu_clone_snapshot_path() {
        let b = QemuKvmBackend::new("q", "/images/base.qcow2");
        let path = b.clone_snapshot("job123");
        assert!(path.contains("job123"));
        assert!(path.contains("base.qcow2"));
    }

    // ── FirecrackerBackend with_mem_mib ───────────────────────────────────

    #[test]
    fn test_firecracker_mem_mib() {
        let b = FirecrackerBackend::new("fc", "/fc", "/root", "/vmlinux")
            .with_mem_mib(256)
            .with_vcpus(4);
        assert_eq!(b.mem_mib, 256);
        assert_eq!(b.vcpu_count, 4);
    }

    // ── DockerBackend with_mem_limit ──────────────────────────────────────

    #[test]
    fn test_docker_mem_limit() {
        let b = DockerBackend::new("d", "img").with_mem_limit(1024);
        assert_eq!(b.mem_limit_mb, 1024);
    }

    // ── ArtifactStore hashes ──────────────────────────────────────────────

    #[test]
    fn test_artifact_store_hashes() {
        let mut store = ArtifactStore::new();
        store.insert([0u8; 32], ArtifactCollector::new());
        store.insert([1u8; 32], ArtifactCollector::new());
        let hashes = store.hashes();
        assert_eq!(hashes.len(), 2);
    }
}
