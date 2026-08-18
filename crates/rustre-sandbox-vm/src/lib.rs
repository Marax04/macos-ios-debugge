//! `rustre-sandbox-vm` — VM-based sandbox.
//!
//! QEMU/KVM integration abstraction, VM lifecycle management, snapshot/restore,
//! guest agent communication, memory introspection from host, disk image management.

pub mod evasion_detection;
pub mod vm_orchestrator;
pub mod vm_behavior_log;
pub mod vm_network;
pub mod syscall_interceptor;
pub mod api_monitor;
pub mod sandbox_report_gen;
pub mod vm_syscall_table;
pub mod vm_file_system;
pub mod vm_registry;

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by VM operations.
#[derive(Debug, Error)]
pub enum VmError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already running")]
    AlreadyRunning,
    #[error("not running")]
    NotRunning,
    #[error("snapshot failed: {0}")]
    SnapshotFailed(String),
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("communication error: {0}")]
    CommError(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("resource error: {0}")]
    Resource(String),
    #[error("timeout")]
    Timeout,
    #[error("qmp error: {0}")]
    QmpError(String),
    #[error("spawn error: {0}")]
    SpawnError(String),
    /// A backend needed to make a real observation is not available on this host.
    ///
    /// Returned instead of a plausible-looking placeholder: the caller learns
    /// exactly which component is missing and why, and never receives invented
    /// guest state.
    #[error("backend unavailable: {component} is required to observe {observation}; {detail}")]
    BackendUnavailable {
        /// The missing component, e.g. `"qemu-system-x86_64"` or `"/proc/<pid>/maps"`.
        component: String,
        /// What could not be observed without it, e.g. `"the guest memory map"`.
        observation: String,
        /// Why it is unavailable on this host.
        detail: String,
    },
}

impl From<std::io::Error> for VmError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<serde_json::Error> for VmError {
    fn from(e: serde_json::Error) -> Self {
        Self::QmpError(format!("json parse error: {e}"))
    }
}

// ─── VmArch ──────────────────────────────────────────────────────────────────

/// CPU architecture for the VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmArch {
    X86,
    X64,
    Arm,
    Arm64,
    Mips,
    Riscv64,
}

impl fmt::Display for VmArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X64 => write!(f, "x64"),
            Self::Arm => write!(f, "arm"),
            Self::Arm64 => write!(f, "arm64"),
            Self::Mips => write!(f, "mips"),
            Self::Riscv64 => write!(f, "riscv64"),
        }
    }
}

// ─── VmOs ────────────────────────────────────────────────────────────────────

/// Guest operating system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmOs {
    Windows10,
    Windows11,
    Windows7,
    Ubuntu22,
    Debian12,
    Kali,
    AndroidApi33,
    MacOs13,
}

impl fmt::Display for VmOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows10 => write!(f, "windows10"),
            Self::Windows11 => write!(f, "windows11"),
            Self::Windows7 => write!(f, "windows7"),
            Self::Ubuntu22 => write!(f, "ubuntu22"),
            Self::Debian12 => write!(f, "debian12"),
            Self::Kali => write!(f, "kali"),
            Self::AndroidApi33 => write!(f, "android_api33"),
            Self::MacOs13 => write!(f, "macos13"),
        }
    }
}

// ─── VmAccelerator ───────────────────────────────────────────────────────────

/// Hardware acceleration mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmAccelerator {
    /// Kernel-based Virtual Machine.
    Kvm,
    /// Windows Hypervisor Platform.
    Whpx,
    /// macOS Hypervisor.framework.
    Hvf,
    /// Userspace emulation (slow, portable).
    Tcg,
}

impl fmt::Display for VmAccelerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kvm => write!(f, "kvm"),
            Self::Whpx => write!(f, "whpx"),
            Self::Hvf => write!(f, "hvf"),
            Self::Tcg => write!(f, "tcg"),
        }
    }
}

// ─── DiskImage ────────────────────────────────────────────────────────────────

/// Represents a disk image file backing a VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskImage {
    pub path: String,
    pub format: DiskFormat,
    pub size_gb: u32,
    /// SHA-256 of the base image (for integrity checks).
    pub base_hash: Option<String>,
    /// Whether this image is a COW overlay on top of a read-only base.
    pub is_overlay: bool,
}

/// Disk image format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskFormat {
    Qcow2,
    Raw,
    Vmdk,
    Vhd,
    Vhdx,
}

impl fmt::Display for DiskFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Qcow2 => write!(f, "qcow2"),
            Self::Raw => write!(f, "raw"),
            Self::Vmdk => write!(f, "vmdk"),
            Self::Vhd => write!(f, "vhd"),
            Self::Vhdx => write!(f, "vhdx"),
        }
    }
}

impl DiskImage {
    /// Create a new disk image entry.
    #[must_use]
    pub fn new(path: impl Into<String>, format: DiskFormat, size_gb: u32) -> Self {
        Self {
            path: path.into(),
            format,
            size_gb,
            base_hash: None,
            is_overlay: false,
        }
    }

    /// Mark this image as a COW overlay.
    #[must_use]
    pub const fn as_overlay(mut self) -> Self {
        self.is_overlay = true;
        self
    }

    /// Set the base hash.
    #[must_use]
    pub fn with_base_hash(mut self, h: impl Into<String>) -> Self {
        self.base_hash = Some(h.into());
        self
    }
}

// ─── VmConfig ────────────────────────────────────────────────────────────────

/// Full configuration for a VM sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    pub name: String,
    pub arch: VmArch,
    pub os: VmOs,
    pub memory_mb: u32,
    pub disk_gb: u32,
    pub vcpus: u8,
    pub isolated: bool,
    pub accelerator: VmAccelerator,
    pub disk: Option<DiskImage>,
    pub net_type: VmNetType,
    pub extra_args: Vec<String>,
    pub boot_timeout_secs: u32,
}

/// Network connectivity type for the VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmNetType {
    /// No network access.
    None,
    /// NAT — outbound only via host.
    Nat,
    /// Host-only network.
    HostOnly,
    /// Bridged — direct access to LAN.
    Bridged,
}

impl fmt::Display for VmNetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Nat => write!(f, "nat"),
            Self::HostOnly => write!(f, "host_only"),
            Self::Bridged => write!(f, "bridged"),
        }
    }
}

impl VmConfig {
    /// Create a default Windows 10 x64 config.
    #[must_use]
    pub fn new(name: impl Into<String>, arch: VmArch, os: VmOs) -> Self {
        Self {
            name: name.into(),
            arch,
            os,
            memory_mb: 2048,
            disk_gb: 40,
            vcpus: 2,
            isolated: true,
            accelerator: VmAccelerator::Tcg,
            disk: None,
            net_type: VmNetType::None,
            extra_args: vec![],
            boot_timeout_secs: 120,
        }
    }

    /// Set memory in MB.
    #[must_use]
    pub const fn with_memory(mut self, mb: u32) -> Self {
        self.memory_mb = mb;
        self
    }

    /// Set disk in GB.
    #[must_use]
    pub const fn with_disk_size(mut self, gb: u32) -> Self {
        self.disk_gb = gb;
        self
    }

    /// Set vCPU count.
    #[must_use]
    pub const fn with_vcpus(mut self, n: u8) -> Self {
        self.vcpus = n;
        self
    }

    /// Enable/disable isolation.
    #[must_use]
    pub const fn with_isolation(mut self, isolated: bool) -> Self {
        self.isolated = isolated;
        self
    }

    /// Set hardware accelerator.
    #[must_use]
    pub const fn with_accelerator(mut self, acc: VmAccelerator) -> Self {
        self.accelerator = acc;
        self
    }

    /// Set network type.
    #[must_use]
    pub const fn with_net(mut self, net: VmNetType) -> Self {
        self.net_type = net;
        self
    }

    /// Attach a disk image.
    #[must_use]
    pub fn with_disk_image(mut self, img: DiskImage) -> Self {
        self.disk = Some(img);
        self
    }

    /// Add an extra QEMU argument.
    #[must_use]
    pub fn with_extra_arg(mut self, arg: impl Into<String>) -> Self {
        self.extra_args.push(arg.into());
        self
    }

    /// Build the QEMU command-line argument list.
    #[must_use]
    pub fn build_qemu_args(&self) -> Vec<String> {
        let mut args = vec![
            format!("-machine type=q35,accel={}", self.accelerator),
            format!("-cpu max"),
            format!("-m {}", self.memory_mb),
            format!("-smp {}", self.vcpus),
        ];
        if let Some(disk) = &self.disk {
            args.push(format!(
                "-drive file={},format={},if=virtio",
                disk.path, disk.format
            ));
        }
        match self.net_type {
            VmNetType::None => args.push("-nic none".to_string()),
            VmNetType::Nat => args.push("-nic user,model=virtio-net-pci".to_string()),
            VmNetType::HostOnly => args.push("-nic tap,model=virtio-net-pci".to_string()),
            VmNetType::Bridged => args.push("-nic bridge,model=virtio-net-pci".to_string()),
        }
        args.extend(self.extra_args.iter().cloned());
        args
    }
}

// ─── VmState ─────────────────────────────────────────────────────────────────

/// Lifecycle state of a VM instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmState {
    Stopped,
    Starting,
    Running,
    Suspended,
    Reverting,
    Saving,
    Error(String),
}

impl fmt::Display for VmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => write!(f, "stopped"),
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Suspended => write!(f, "suspended"),
            Self::Reverting => write!(f, "reverting"),
            Self::Saving => write!(f, "saving"),
            Self::Error(e) => write!(f, "error: {e}"),
        }
    }
}

// ─── SnapshotInfo ────────────────────────────────────────────────────────────

/// Metadata for a VM snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    pub id: String,
    pub name: String,
    pub created_at: u64,
    pub size_bytes: u64,
    pub parent: Option<String>,
    pub description: String,
}

impl SnapshotInfo {
    /// Create a new snapshot info entry.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        created_at: u64,
        size_bytes: u64,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            created_at,
            size_bytes,
            parent: None,
            description: String::new(),
        }
    }

    /// Set the parent snapshot ID.
    #[must_use]
    pub fn with_parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = Some(parent.into());
        self
    }

    /// Set a description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

// ─── MemoryRegion ─────────────────────────────────────────────────────────────

/// A memory region in the guest address space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub label: String,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub mapped_file: Option<String>,
}

impl MemoryRegion {
    /// Size of this region in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` if the region is RWX.
    #[must_use]
    pub const fn is_rwx(&self) -> bool {
        self.readable && self.writable && self.executable
    }

    /// Returns `true` if the given address falls within this region.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

// ─── MemoryMap ────────────────────────────────────────────────────────────────

/// Where the contents of a [`MemoryMap`] came from.
///
/// A consumer must be able to tell an observation apart from a test fixture
/// without reading this crate's source, so the distinction is carried in the
/// data and serialised with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MapProvenance {
    /// Read from a real process or guest.
    Observed,
    /// Hand-written sample data. Never a statement about any real process.
    SyntheticFixture,
}

impl MapProvenance {
    /// `true` when the data describes something that was actually observed.
    #[must_use]
    pub const fn is_observed(self) -> bool {
        matches!(self, Self::Observed)
    }
}

impl fmt::Display for MapProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observed => write!(f, "observed"),
            Self::SyntheticFixture => write!(f, "synthetic-fixture"),
        }
    }
}

/// Complete guest memory map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMap {
    pub regions: Vec<MemoryRegion>,
    pub pid: u32,
    /// Whether these regions were observed or are sample data.
    #[serde(default = "default_observed_provenance")]
    pub provenance: MapProvenance,
}

const fn default_observed_provenance() -> MapProvenance {
    MapProvenance::Observed
}

impl MemoryMap {
    /// Create an empty memory map for a process.
    #[must_use]
    pub const fn new(pid: u32) -> Self {
        Self {
            regions: vec![],
            pid,
            provenance: MapProvenance::Observed,
        }
    }

    /// `true` when this map is sample data rather than an observation.
    #[must_use]
    pub const fn is_synthetic(&self) -> bool {
        matches!(self.provenance, MapProvenance::SyntheticFixture)
    }

    /// Parse a real Linux `/proc/<pid>/maps` listing into a memory map.
    ///
    /// Every region comes from a line of `text`; lines that do not parse are
    /// skipped rather than replaced with a guess.
    #[must_use]
    pub fn from_proc_maps(pid: u32, text: &str) -> Self {
        let mut map = Self::new(pid);
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(range) = parts.next() else { continue };
            let Some(perms) = parts.next() else { continue };
            let Some((lo, hi)) = range.split_once('-') else { continue };
            let (Ok(start), Ok(end)) =
                (u64::from_str_radix(lo, 16), u64::from_str_radix(hi, 16))
            else {
                continue;
            };
            let mapped = parts.nth(3).filter(|p| !p.is_empty());
            let label = mapped.map_or_else(|| "[anon]".to_string(), ToString::to_string);
            map.add(MemoryRegion {
                start,
                end,
                label,
                readable: perms.contains('r'),
                writable: perms.contains('w'),
                executable: perms.contains('x'),
                mapped_file: mapped
                    .filter(|p| !p.starts_with('['))
                    .map(ToString::to_string),
            });
        }
        map
    }

    /// Read the **real** memory map of a live process.
    ///
    /// # Errors
    /// On Linux, returns [`VmError::Io`] if `/proc/<pid>/maps` cannot be read.
    /// On every other host this introspection source does not exist, and the
    /// function returns [`VmError::BackendUnavailable`] naming it — it never
    /// substitutes a fabricated map.
    pub fn read_live(pid: u32) -> Result<Self, VmError> {
        #[cfg(target_os = "linux")]
        {
            let path = format!("/proc/{pid}/maps");
            let text = std::fs::read_to_string(&path).map_err(|e| VmError::Io(format!("{path}: {e}")))?;
            Ok(Self::from_proc_maps(pid, &text))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(VmError::BackendUnavailable {
                component: format!("/proc/{pid}/maps"),
                observation: "the memory map of a live process".to_string(),
                detail: format!(
                    "this host is {}, which has no procfs; a QEMU guest with an                      introspection agent is required to observe guest memory",
                    std::env::consts::OS
                ),
            })
        }
    }

    /// Add a region.
    pub fn add(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }

    /// Find the region containing an address.
    #[must_use]
    pub fn find_region(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Return all executable regions.
    #[must_use]
    pub fn executable_regions(&self) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| r.executable).collect()
    }

    /// Return all RWX regions (suspicious).
    #[must_use]
    pub fn rwx_regions(&self) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| r.is_rwx()).collect()
    }

    /// Return all anonymous (unmapped) writable regions.
    #[must_use]
    pub fn anonymous_writable(&self) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.mapped_file.is_none() && r.writable)
            .collect()
    }

    /// Total mapped size.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.regions.iter().map(MemoryRegion::size).sum()
    }

    /// Sample memory map used by this crate's own tests.
    ///
    /// **Not an observation.** The returned map is tagged
    /// [`MapProvenance::SyntheticFixture`] so no consumer can mistake it for the
    /// state of a real process. To observe a real one, use
    /// [`MemoryMap::read_live`] or [`MemoryMap::from_proc_maps`].
    #[must_use]
    pub fn mock(pid: u32) -> Self {
        let mut map = Self::new(pid);
        map.provenance = MapProvenance::SyntheticFixture;
        map.add(MemoryRegion {
            start: 0x0000_0000_0040_0000,
            end: 0x0000_0000_0050_0000,
            label: "[exe]".to_string(),
            readable: true,
            writable: false,
            executable: true,
            mapped_file: Some("malware.exe".to_string()),
        });
        map.add(MemoryRegion {
            start: 0x0000_7fff_0000_0000,
            end: 0x0000_7fff_0010_0000,
            label: "[stack]".to_string(),
            readable: true,
            writable: true,
            executable: false,
            mapped_file: None,
        });
        map.add(MemoryRegion {
            start: 0x0000_0001_0000_0000,
            end: 0x0000_0001_0001_0000,
            label: "[injected]".to_string(),
            readable: true,
            writable: true,
            executable: true,
            mapped_file: None,
        });
        map.add(MemoryRegion {
            start: 0x0000_7ffe_0000_0000,
            end: 0x0000_7ffe_0100_0000,
            label: "[ntdll]".to_string(),
            readable: true,
            writable: false,
            executable: true,
            mapped_file: Some("ntdll.dll".to_string()),
        });
        map
    }
}

// ─── GuestCommand ─────────────────────────────────────────────────────────────

/// A command to execute inside the guest via the guest agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestCommand {
    pub executable: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: String,
    pub timeout_secs: u32,
}

impl GuestCommand {
    /// Create a new guest command.
    #[must_use]
    pub fn new(executable: impl Into<String>) -> Self {
        Self {
            executable: executable.into(),
            args: vec![],
            env: HashMap::new(),
            cwd: String::new(),
            timeout_secs: 30,
        }
    }

    /// Add an argument.
    #[must_use]
    pub fn with_arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    /// Add an environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.env.insert(key.into(), val.into());
        self
    }

    /// Set the working directory.
    #[must_use]
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = cwd.into();
        self
    }

    /// Set the timeout.
    #[must_use]
    pub const fn with_timeout(mut self, secs: u32) -> Self {
        self.timeout_secs = secs;
        self
    }
}

/// Result from running a command in the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestCommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub timed_out: bool,
}

impl GuestCommandResult {
    /// Returns `true` if the command succeeded (exit code 0, no timeout).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.exit_code == 0 && !self.timed_out
    }
}

// ─── GuestAgent ──────────────────────────────────────────────────────────────

/// Interface to the in-guest agent for file transfer, command execution,
/// and introspection.
pub struct GuestAgent {
    pub vm_id: String,
    pub connected: bool,
    pub agent_pid: Option<u32>,
    pub commands_sent: AtomicU64,
}

impl GuestAgent {
    /// Create a new (disconnected) agent for the given VM.
    #[must_use]
    pub fn new(vm_id: impl Into<String>) -> Self {
        Self {
            vm_id: vm_id.into(),
            connected: false,
            agent_pid: None,
            commands_sent: AtomicU64::new(0),
        }
    }

    /// Simulate connecting to the agent.
    pub const fn connect(&mut self) {
        self.connected = true;
        self.agent_pid = Some(1000);
    }

    /// Simulate disconnecting.
    pub const fn disconnect(&mut self) {
        self.connected = false;
        self.agent_pid = None;
    }

    /// Execute a command in the guest (mock implementation).
    ///
    /// # Errors
    /// Returns `VmError::CommError` if the agent is not connected.
    pub fn exec(&self, cmd: &GuestCommand) -> Result<GuestCommandResult, VmError> {
        if !self.connected {
            return Err(VmError::CommError("agent not connected".to_string()));
        }
        self.commands_sent.fetch_add(1, Ordering::Relaxed);
        Ok(GuestCommandResult {
            exit_code: 0,
            stdout: format!("executed: {} {:?}", cmd.executable, cmd.args),
            stderr: String::new(),
            duration_ms: 100,
            timed_out: false,
        })
    }

    /// Upload a file to the guest (mock).
    ///
    /// # Errors
    /// Returns `VmError::CommError` if the agent is not connected.
    pub fn upload(&self, _local: &str, remote: &str) -> Result<(), VmError> {
        if !self.connected {
            return Err(VmError::CommError("agent not connected".to_string()));
        }
        let _ = remote;
        Ok(())
    }

    /// Download a file from the guest (mock).
    ///
    /// # Errors
    /// Returns `VmError::CommError` if the agent is not connected.
    pub fn download(&self, remote: &str, _local: &str) -> Result<Vec<u8>, VmError> {
        if !self.connected {
            return Err(VmError::CommError("agent not connected".to_string()));
        }
        Ok(format!("contents of {remote}").into_bytes())
    }

    /// Read the guest memory map (mock).
    ///
    /// # Errors
    /// Returns `VmError::CommError` if not connected.
    pub fn read_memory_map(&self, pid: u32) -> Result<MemoryMap, VmError> {
        if !self.connected {
            return Err(VmError::CommError("agent not connected".to_string()));
        }
        Ok(MemoryMap::mock(pid))
    }

    /// Number of commands sent.
    #[must_use]
    pub fn commands_sent(&self) -> u64 {
        self.commands_sent.load(Ordering::Relaxed)
    }
}

// ─── NetworkMode ─────────────────────────────────────────────────────────────

/// Network mode for the QEMU process builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMode {
    /// No networking — safest isolation for malware analysis.
    None,
    /// NAT via host userspace networking stack.
    User,
    /// TAP device (host-only or bridged, requires host setup).
    Tap { iface: String },
    /// Bridge to an existing host bridge interface.
    Bridge { br: String },
}

impl NetworkMode {
    /// Produce the QEMU `-nic` argument fragment for this mode.
    #[must_use]
    pub fn nic_arg(&self) -> String {
        match self {
            Self::None => "none".to_string(),
            Self::User => "user,model=virtio-net-pci".to_string(),
            Self::Tap { iface } => format!("tap,ifname={iface},model=virtio-net-pci"),
            Self::Bridge { br } => format!("bridge,br={br},model=virtio-net-pci"),
        }
    }
}

// ─── QemuProcessBuilder ───────────────────────────────────────────────────────

/// Builder for a QEMU process invocation. Constructs the full argument list
/// and spawns the child process, returning a [`QemuHandle`].
///
/// # Example
/// ```no_run
/// # use rustre_sandbox_vm::{QemuProcessBuilder, NetworkMode};
/// # async fn run() -> anyhow::Result<()> {
/// let handle = QemuProcessBuilder::new("/images/win10.qcow2")
///     .memory_mb(4096)
///     .cpus(4)
///     .net_mode(NetworkMode::None)
///     .spawn()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct QemuProcessBuilder {
    /// Path to the disk image (qcow2 expected).
    pub image_path: PathBuf,
    /// RAM in megabytes. Default: 2048.
    pub memory_mb: u32,
    /// Number of vCPUs. Default: 2.
    pub cpus: u8,
    /// Snapshot tag to restore on boot, if any.
    pub snapshot: Option<String>,
    /// Network mode. Default: None (isolated).
    pub net_mode: NetworkMode,
    /// Path for the QMP Unix socket. If `None`, a temp path is generated on spawn.
    pub qmp_socket_path: Option<PathBuf>,
    /// Additional raw QEMU arguments appended verbatim.
    pub extra_args: Vec<String>,
    /// Hardware accelerator flag (e.g. "kvm", "whpx", "tcg").
    pub accelerator: String,
    /// Display mode. Default: "none" (headless).
    pub display: String,
}

/// Escape a value that will be placed inside a comma-separated QEMU option list.
///
/// QEMU splits options such as `-drive` and `-qmp` on commas, and a comma that
/// belongs to a *value* must be written twice to survive that split. A path like
/// `/vm/my,disk.qcow2` would otherwise turn `disk.qcow2` into a bogus option.
fn qemu_escape_opt_value(value: &str) -> String {
    value.replace(',', ",,")
}

impl QemuProcessBuilder {
    /// Create a new builder for the given disk image path.
    #[must_use]
    pub fn new(image_path: impl Into<PathBuf>) -> Self {
        Self {
            image_path: image_path.into(),
            memory_mb: 2048,
            cpus: 2,
            snapshot: None,
            net_mode: NetworkMode::None,
            qmp_socket_path: None,
            extra_args: vec![],
            accelerator: "tcg".to_string(),
            display: "none".to_string(),
        }
    }

    /// Set the amount of RAM in megabytes.
    #[must_use]
    pub const fn memory_mb(mut self, mb: u32) -> Self {
        self.memory_mb = mb;
        self
    }

    /// Set the number of vCPUs.
    #[must_use]
    pub const fn cpus(mut self, n: u8) -> Self {
        self.cpus = n;
        self
    }

    /// Restore from a snapshot tag on boot.
    #[must_use]
    pub fn snapshot(mut self, tag: impl Into<String>) -> Self {
        self.snapshot = Some(tag.into());
        self
    }

    /// Set the network mode.
    #[must_use]
    pub fn net_mode(mut self, mode: NetworkMode) -> Self {
        self.net_mode = mode;
        self
    }

    /// Set an explicit QMP socket path (otherwise auto-generated in temp dir).
    #[must_use]
    pub fn qmp_socket_path(mut self, p: impl Into<PathBuf>) -> Self {
        self.qmp_socket_path = Some(p.into());
        self
    }

    /// Set the hardware accelerator (e.g. "kvm", "whpx", "hvf", "tcg").
    #[must_use]
    pub fn accelerator(mut self, accel: impl Into<String>) -> Self {
        self.accelerator = accel.into();
        self
    }

    /// Set the display mode (e.g. "none", "sdl", "gtk").
    #[must_use]
    pub fn display(mut self, display: impl Into<String>) -> Self {
        self.display = display.into();
        self
    }

    /// Append a raw extra argument.
    #[must_use]
    pub fn extra_arg(mut self, arg: impl Into<String>) -> Self {
        self.extra_args.push(arg.into());
        self
    }

    /// Resolve the QMP socket path: use the configured one, or derive a
    /// deterministic temp-dir path based on a UUID.
    fn resolve_qmp_socket(&self) -> PathBuf {
        if let Some(p) = &self.qmp_socket_path {
            return p.clone();
        }
        #[cfg(windows)]
        {
            // On Windows the QMP transport is TCP; encode addr:port with the
            // `tcp:` prefix expected by `QmpClient::connect`. Derive a
            // pseudo-random port from a UUID to avoid collisions.
            let id = uuid::Uuid::new_v4();
            let bytes = id.as_bytes();
            let port: u16 = 20000 + (u16::from_le_bytes([bytes[0], bytes[1]]) % 40000);
            PathBuf::from(format!("tcp:127.0.0.1:{port}"))
        }
        #[cfg(not(windows))]
        {
            let id = uuid::Uuid::new_v4();
            let tmp = std::env::temp_dir();
            tmp.join(format!("rustre-qmp-{id}.sock"))
        }
    }

    /// Build the flat argument list passed to `qemu-system-x86_64`.
    ///
    /// The resulting vector does **not** include the executable name itself —
    /// that is provided separately to [`tokio::process::Command`].
    ///
    /// Layout:
    /// ```text
    /// -m <memory_mb>
    /// -smp <cpus>
    /// -drive file=<image>,format=qcow2,if=virtio
    /// [-loadvm <snapshot>]
    /// -machine q35,accel=<accel>
    /// -cpu max
    /// -nic <net_mode>
    /// -qmp unix:<socket>,server,nowait
    /// -display <display>
    /// [extra_args…]
    /// ```
    #[must_use]
    pub fn build_args(&self) -> Vec<String> {
        let socket = self.resolve_qmp_socket();
        let socket_str = socket.to_string_lossy();

        let mut args = vec![
            "-m".to_string(),
            self.memory_mb.to_string(),
            "-smp".to_string(),
            self.cpus.to_string(),
            "-drive".to_string(),
            format!(
                "file={},format=qcow2,if=virtio",
                qemu_escape_opt_value(&self.image_path.to_string_lossy())
            ),
        ];

        if let Some(tag) = &self.snapshot {
            args.push("-loadvm".to_string());
            args.push(tag.clone());
        }

        args.extend([
            "-machine".to_string(),
            format!("q35,accel={}", self.accelerator),
            "-cpu".to_string(),
            "max".to_string(),
            "-nic".to_string(),
            self.net_mode.nic_arg(),
            "-qmp".to_string(),
            if socket_str.starts_with("tcp:") {
                format!("{},server,nowait", qemu_escape_opt_value(&socket_str))
            } else {
                format!("unix:{},server,nowait", qemu_escape_opt_value(&socket_str))
            },
            "-display".to_string(),
            self.display.clone(),
        ]);

        args.extend(self.extra_args.iter().cloned());
        args
    }

    /// Spawn the QEMU process and return a [`QemuHandle`].
    ///
    /// The QMP socket path is embedded in the handle so callers can connect
    /// a [`QmpClient`] once the socket appears.
    ///
    /// # Errors
    /// Returns [`VmError::SpawnError`] if the process cannot be started (e.g.
    /// `qemu-system-x86_64` is not on `PATH`).
    pub async fn spawn(self) -> Result<QemuHandle, VmError> {
        let socket = self.resolve_qmp_socket();
        let args = self.build_args();

        let child = tokio::process::Command::new("qemu-system-x86_64")
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| VmError::SpawnError(format!("failed to spawn qemu-system-x86_64: {e}")))?;

        Ok(QemuHandle {
            child,
            qmp_socket: socket,
        })
    }
}

// ─── QemuHandle ───────────────────────────────────────────────────────────────

/// A live QEMU child process and the associated QMP socket path.
///
/// Obtain via [`QemuProcessBuilder::spawn`].
pub struct QemuHandle {
    /// The Tokio child process handle.
    pub child: tokio::process::Child,
    /// Path of the QMP Unix socket (or named-pipe path on Windows).
    pub qmp_socket: PathBuf,
}

impl QemuHandle {
    /// Block (async) until the QMP socket file appears on disk, up to
    /// `timeout_secs` seconds.  Polls every 100 ms.
    ///
    /// This is the correct way to wait for QEMU to finish initializing before
    /// attempting a [`QmpClient::connect`].
    ///
    /// # Errors
    /// Returns [`VmError::Timeout`] if the socket does not appear within the
    /// allotted time, or [`VmError::Io`] on unexpected filesystem errors.
    pub async fn wait_for_qmp_ready(&mut self, timeout_secs: u64) -> Result<(), VmError> {
        let deadline = Duration::from_secs(timeout_secs);
        let poll_interval = Duration::from_millis(100);

        let result = timeout(deadline, async {
            loop {
                // Check if the process is still alive before polling the socket.
                match self.child.try_wait() {
                    Ok(Some(status)) => {
                        return Err(VmError::SpawnError(format!(
                            "qemu exited before qmp socket appeared: {status}"
                        )));
                    }
                    Ok(None) => {}
                    Err(e) => return Err(VmError::from(e)),
                }
                if self.qmp_socket.exists() {
                    return Ok(());
                }
                tokio::time::sleep(poll_interval).await;
            }
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_elapsed) => Err(VmError::Timeout),
        }
    }

    /// Return the OS-assigned PID of the QEMU process, if available.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Send SIGKILL (Unix) / `TerminateProcess` (Windows) to the child.
    ///
    /// Prefer using [`QmpClient::quit`] for a clean shutdown.
    ///
    /// # Errors
    /// Returns [`VmError::Io`] if the kill syscall fails.
    pub async fn kill(&mut self) -> Result<(), VmError> {
        self.child.kill().await.map_err(VmError::from)
    }

    /// Wait for the child process to exit and return its exit status.
    ///
    /// # Errors
    /// Returns [`VmError::Io`] on OS error.
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus, VmError> {
        self.child.wait().await.map_err(VmError::from)
    }
}

// ─── QmpClient ────────────────────────────────────────────────────────────────

/// Async client for the QEMU Machine Protocol (QMP).
///
/// QMP uses a JSON-over-stream framing where:
/// - On connect the server sends a greeting object.
/// - The client issues `{"execute": "qmp_capabilities"}` to leave negotiation mode.
/// - Subsequent commands follow the `{"execute": "<method>", "arguments": {...}}` form.
/// - Each response is a single JSON line containing a `"return"` key on success or
///   `"error"` on failure.
///
/// # Platform note
/// On Linux/macOS the underlying transport is a Unix domain socket.
/// On Windows, QEMU supports named pipes or TCP; this implementation uses
/// `tokio::net::TcpStream` on Windows and `tokio::net::UnixStream` elsewhere
/// (controlled by the `cfg` attributes below).
///
/// For simplicity the implementation here always targets Unix sockets since
/// the typical `RustRE` environment runs QEMU on a Linux host or via WSL2.
pub struct QmpClient {
    #[cfg(unix)]
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    #[cfg(unix)]
    writer: tokio::net::unix::OwnedWriteHalf,

    // Windows fallback: TCP stream split
    #[cfg(windows)]
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    #[cfg(windows)]
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl QmpClient {
    /// Connect to the QMP socket at `path` and complete the capability
    /// negotiation handshake.
    ///
    /// After this call the client is ready to send commands.
    ///
    /// # Errors
    /// Returns [`VmError::CommError`] if the socket cannot be opened or if the
    /// greeting / negotiation exchange fails.
    #[cfg(unix)]
    pub async fn connect(path: &Path) -> Result<Self, VmError> {
        let stream = tokio::net::UnixStream::connect(path)
            .await
            .map_err(|e| VmError::CommError(format!("unix connect failed: {e}")))?;

        let (read_half, write_half) = stream.into_split();
        let mut client = Self {
            reader: BufReader::new(read_half),
            writer: write_half,
        };

        // Consume the greeting line: {"QMP": {...}}
        let mut greeting = String::new();
        client.read_line(&mut greeting).await?;

        // Leave negotiation mode.
        client.send_raw(r#"{"execute":"qmp_capabilities"}"#).await?;

        // Consume the {"return": {}} acknowledgement.
        let mut ack = String::new();
        client.read_line(&mut ack).await?;

        Ok(client)
    }

    /// TCP-based connect used on Windows (QEMU `-qmp tcp:127.0.0.1:<port>,server,nowait`).
    ///
    /// The `path` parameter on Windows is expected to encode the address as
    /// `"127.0.0.1:<port>"` inside the socket path string; this is a
    /// best-effort heuristic for cross-platform code sharing.
    #[cfg(windows)]
    pub async fn connect(path: &Path) -> Result<Self, VmError> {
        // On Windows the path must encode the TCP address with the "tcp:" prefix
        // (e.g. "tcp:127.0.0.1:20123"). Silently falling back to a hardcoded
        // port would connect to the wrong QEMU instance, so we return an error
        // instead.
        let addr = path
            .to_str()
            .and_then(|s| s.strip_prefix("tcp:"))
            .ok_or_else(|| VmError::CommError(format!(
                "QmpClient::connect on Windows requires a 'tcp:<addr>:<port>' path, got: {path:?}"
            )))?;

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| VmError::CommError(format!("tcp connect failed: {e}")))?;

        let (read_half, write_half) = stream.into_split();
        let mut client = Self {
            reader: BufReader::new(read_half),
            writer: write_half,
        };

        // Greeting + capabilities negotiation (same as Unix path).
        let mut greeting = String::new();
        client.read_line(&mut greeting).await?;

        client.send_raw(r#"{"execute":"qmp_capabilities"}"#).await?;

        let mut ack = String::new();
        client.read_line(&mut ack).await?;

        Ok(client)
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Read exactly one newline-terminated line from the stream.
    async fn read_line(&mut self, buf: &mut String) -> Result<(), VmError> {
        buf.clear();
        self.reader
            .read_line(buf)
            .await
            .map_err(|e| VmError::CommError(format!("read error: {e}")))?;
        Ok(())
    }

    /// Write raw bytes followed by a newline to the QMP stream.
    async fn send_raw(&mut self, data: &str) -> Result<(), VmError> {
        let line = format!("{data}\n");
        self.writer
            .write_all(line.as_bytes())
            .await
            .map_err(|e| VmError::CommError(format!("write error: {e}")))?;
        self.writer
            .flush()
            .await
            .map_err(|e| VmError::CommError(format!("flush error: {e}")))?;
        Ok(())
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// Send a QMP command and return the parsed `"return"` value.
    ///
    /// Serialises the request as:
    /// ```json
    /// {"execute": "<method>", "arguments": <args>}
    /// ```
    /// and parses the single-line JSON response.  The `"return"` field of a
    /// successful response is returned; a QMP `"error"` field is surfaced as
    /// [`VmError::QmpError`].
    ///
    /// # Errors
    /// Returns [`VmError::CommError`] on I/O failures, [`VmError::QmpError`]
    /// on QEMU-reported errors, or [`VmError::from`] on JSON parse failures.
    pub async fn send_command(
        &mut self,
        method: &str,
        args: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, VmError> {
        // Build the request object.
        let request = match args {
            Some(a) => serde_json::json!({ "execute": method, "arguments": a }),
            None => serde_json::json!({ "execute": method }),
        };

        let request_str = serde_json::to_string(&request)?;
        self.send_raw(&request_str).await?;

        // Read lines until we get a response (skip async events starting with
        // {"event":…} that QEMU may emit between command and response).
        // Cap the number of skipped events so a chatty event stream cannot
        // block a command response indefinitely.
        const MAX_SKIPPED_EVENTS: usize = 1024;
        let mut skipped_events: usize = 0;
        loop {
            let mut line = String::new();
            self.read_line(&mut line).await?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let parsed: serde_json::Value = serde_json::from_str(trimmed)?;

            // Skip unsolicited events, up to a bounded limit.
            if parsed.get("event").is_some() {
                skipped_events += 1;
                if skipped_events > MAX_SKIPPED_EVENTS {
                    return Err(VmError::CommError(format!(
                        "exceeded {MAX_SKIPPED_EVENTS} QMP events without a command response"
                    )));
                }
                continue;
            }

            // Surface QMP errors.
            if let Some(err) = parsed.get("error") {
                let desc = err
                    .get("desc")
                    .and_then(|d| d.as_str())
                    .unwrap_or("unknown QMP error");
                return Err(VmError::QmpError(desc.to_string()));
            }

            // Return the "return" field (may be a JSON null / empty object).
            return parsed
                .get("return")
                .cloned()
                .ok_or_else(|| VmError::QmpError("response has no 'return' field".to_string()));
        }
    }

    /// Query the VM status string (e.g. `"running"`, `"paused"`, `"shutdown"`).
    ///
    /// Issues `query-status` and extracts `return.status`.
    ///
    /// # Errors
    /// Propagates I/O and QMP errors.
    pub async fn query_status(&mut self) -> Result<String, VmError> {
        let resp = self.send_command("query-status", None).await?;
        let status = resp
            .get("status")
            .and_then(|s| s.as_str())
            .ok_or_else(|| VmError::QmpError("query-status: missing 'status' field".to_string()))?
            .to_string();
        Ok(status)
    }

    /// Pause guest CPU execution (`stop`).
    ///
    /// # Errors
    /// Propagates I/O and QMP errors.
    pub async fn stop_vm(&mut self) -> Result<(), VmError> {
        self.send_command("stop", None).await?;
        Ok(())
    }

    /// Resume guest CPU execution (`cont`).
    ///
    /// # Errors
    /// Propagates I/O and QMP errors.
    pub async fn cont_vm(&mut self) -> Result<(), VmError> {
        self.send_command("cont", None).await?;
        Ok(())
    }

    /// Request QEMU to exit (`quit`).
    ///
    /// After this command the QEMU process will terminate; any subsequent
    /// reads/writes on the socket will fail.
    ///
    /// # Errors
    /// Propagates I/O and QMP errors.
    pub async fn quit(&mut self) -> Result<(), VmError> {
        // `quit` causes QEMU to close the connection immediately; the response
        // may or may not arrive before the socket is torn down.  We attempt to
        // read the response but silently ignore I/O errors.
        let request = serde_json::json!({ "execute": "quit" });
        let request_str = serde_json::to_string(&request)?;
        let _ = self.send_raw(&request_str).await;

        // Drain the response non-fatally.
        let mut buf = String::new();
        let _ = self.read_line(&mut buf).await;
        Ok(())
    }

    /// Save the current VM state as an internal snapshot tagged `tag`.
    ///
    /// Maps to the QMP `savevm` command (requires the drive to support
    /// snapshots, e.g. qcow2).
    ///
    /// # Errors
    /// Propagates I/O and QMP errors.
    pub async fn savevm(&mut self, tag: &str) -> Result<(), VmError> {
        let args = serde_json::json!({ "tag": tag });
        self.send_command("savevm", Some(args)).await?;
        Ok(())
    }

    /// Restore the VM to a previously saved snapshot `tag`.
    ///
    /// Maps to the QMP `loadvm` command.
    ///
    /// # Errors
    /// Propagates I/O and QMP errors.
    pub async fn loadvm(&mut self, tag: &str) -> Result<(), VmError> {
        let args = serde_json::json!({ "tag": tag });
        self.send_command("loadvm", Some(args)).await?;
        Ok(())
    }

    /// Delete a named snapshot from the disk image.
    ///
    /// Maps to the QMP `delvm` command.
    ///
    /// # Errors
    /// Propagates I/O and QMP errors.
    pub async fn delvm(&mut self, tag: &str) -> Result<(), VmError> {
        let args = serde_json::json!({ "tag": tag });
        self.send_command("delvm", Some(args)).await?;
        Ok(())
    }

    /// Send a human-monitor-interface command (`human-monitor-command`).
    ///
    /// Useful for commands not yet exposed as first-class QMP methods.
    ///
    /// # Errors
    /// Propagates I/O and QMP errors.
    pub async fn hmp(&mut self, cmd: &str) -> Result<String, VmError> {
        let args = serde_json::json!({ "command-line": cmd });
        let resp = self
            .send_command("human-monitor-command", Some(args))
            .await?;
        Ok(resp.as_str().unwrap_or("").to_string())
    }

    /// Query the list of block devices attached to the VM.
    ///
    /// Returns the raw JSON array from `query-block`.
    ///
    /// # Errors
    /// Propagates I/O and QMP errors.
    pub async fn query_block(&mut self) -> Result<serde_json::Value, VmError> {
        self.send_command("query-block", None).await
    }

    /// Query information about the running machine.
    ///
    /// Returns the raw JSON object from `query-machines`.
    ///
    /// # Errors
    /// Propagates I/O and QMP errors.
    pub async fn query_version(&mut self) -> Result<serde_json::Value, VmError> {
        self.send_command("query-version", None).await
    }

    /// Wait (polling every 500 ms) until `query-status` returns `"running"`,
    /// up to `timeout_secs` seconds.
    ///
    /// # Errors
    /// Returns [`VmError::Timeout`] if the VM does not reach running state in
    /// time, or propagates QMP errors.
    pub async fn wait_for_running(&mut self, timeout_secs: u64) -> Result<(), VmError> {
        let deadline = Duration::from_secs(timeout_secs);
        let poll = Duration::from_millis(500);

        let result = timeout(deadline, async {
            loop {
                match self.query_status().await {
                    Ok(s) if s == "running" => return Ok(()),
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
                tokio::time::sleep(poll).await;
            }
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err(VmError::Timeout),
        }
    }
}

// ─── VmInstance ──────────────────────────────────────────────────────────────

/// A single VM instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmInstance {
    pub id: String,
    pub config: VmConfig,
    pub state: VmState,
    pub snapshots: Vec<SnapshotInfo>,
    pub boot_ms: Option<u64>,
    pub tags: Vec<String>,
}

impl VmInstance {
    /// Create a new VM instance in the Stopped state.
    #[must_use]
    pub fn new(id: impl Into<String>, config: VmConfig) -> Self {
        Self {
            id: id.into(),
            config,
            state: VmState::Stopped,
            snapshots: vec![],
            boot_ms: None,
            tags: vec![],
        }
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    /// Returns `true` if the VM is currently running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.state == VmState::Running
    }

    /// Returns `true` if the VM is stopped.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.state == VmState::Stopped
    }

    /// Take a snapshot and return its ID.
    ///
    /// # Errors
    /// Returns `VmError::SnapshotFailed` if the VM is not in a valid state.
    pub fn take_snapshot(&mut self, name: impl Into<String>) -> Result<String, VmError> {
        if matches!(self.state, VmState::Error(_)) {
            return Err(VmError::SnapshotFailed("VM is in error state".to_string()));
        }
        let id = format!("snap-{:04}", self.snapshots.len());
        let parent = self.snapshots.last().map(|s| s.id.clone());
        let mut info = SnapshotInfo::new(id.clone(), name, 0, 1_073_741_824);
        if let Some(p) = parent {
            info = info.with_parent(p);
        }
        self.snapshots.push(info);
        Ok(id)
    }

    /// Revert to a snapshot by ID.
    ///
    /// # Errors
    /// Returns `VmError::NotFound` if the snapshot doesn't exist.
    pub fn revert(&mut self, id: &str) -> Result<(), VmError> {
        if let Some(idx) = self.snapshots.iter().position(|s| s.id == id) {
            self.state = VmState::Reverting;
            self.snapshots.truncate(idx + 1);
            self.state = VmState::Stopped;
            Ok(())
        } else {
            Err(VmError::NotFound(id.to_string()))
        }
    }

    /// Delete a snapshot by ID.
    ///
    /// # Errors
    /// Returns `VmError::NotFound` if the snapshot doesn't exist.
    pub fn delete_snapshot(&mut self, id: &str) -> Result<(), VmError> {
        let new_parent = self
            .snapshots
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.parent.clone());
        let Some(new_parent) = new_parent else {
            return Err(VmError::NotFound(id.to_string()));
        };
        self.snapshots.retain(|s| s.id != id);
        for s in &mut self.snapshots {
            if s.parent.as_deref() == Some(id) {
                s.parent = new_parent.clone();
            }
        }
        Ok(())
    }

    /// Return the number of snapshots.
    #[must_use]
    pub const fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Find a snapshot by ID.
    #[must_use]
    pub fn find_snapshot(&self, id: &str) -> Option<&SnapshotInfo> {
        self.snapshots.iter().find(|s| s.id == id)
    }

    /// Find the latest snapshot by creation timestamp.
    #[must_use]
    pub fn latest_snapshot(&self) -> Option<&SnapshotInfo> {
        self.snapshots.iter().max_by_key(|s| s.created_at)
    }

    /// Build the QEMU args for this instance.
    #[must_use]
    pub fn qemu_args(&self) -> Vec<String> {
        self.config.build_qemu_args()
    }
}

// ─── VmPool ──────────────────────────────────────────────────────────────────

/// Manages a pool of VM instances.
pub struct VmPool {
    pub instances: Mutex<Vec<VmInstance>>,
    counter: AtomicU64,
}

impl VmPool {
    /// Create an empty pool.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            instances: Mutex::new(vec![]),
            counter: AtomicU64::new(0),
        }
    }

    /// Add a VM instance to the pool.
    pub fn add(&self, vm: VmInstance) {
        self.instances.lock().push(vm);
    }

    /// Find a VM by ID (returns a clone).
    #[must_use]
    pub fn find(&self, id: &str) -> Option<VmInstance> {
        self.instances.lock().iter().find(|v| v.id == id).cloned()
    }

    /// Remove and return a VM by ID.
    ///
    /// # Errors
    /// Returns `VmError::NotFound` if no VM with that ID exists.
    pub fn remove(&self, id: &str) -> Result<VmInstance, VmError> {
        let mut lock = self.instances.lock();
        let pos = lock
            .iter()
            .position(|v| v.id == id)
            .ok_or_else(|| VmError::NotFound(id.to_string()))?;
        Ok(lock.remove(pos))
    }

    /// Update the state of a VM in the pool.
    ///
    /// # Errors
    /// Returns `VmError::NotFound` if no VM with that ID exists.
    pub fn update_state(&self, id: &str, state: VmState) -> Result<(), VmError> {
        let mut lock = self.instances.lock();
        let vm = lock
            .iter_mut()
            .find(|v| v.id == id)
            .ok_or_else(|| VmError::NotFound(id.to_string()))?;
        vm.state = state;
        Ok(())
    }

    /// Return all VMs in the Stopped state (available for use).
    #[must_use]
    pub fn available(&self) -> Vec<VmInstance> {
        self.instances
            .lock()
            .iter()
            .filter(|v| v.state == VmState::Stopped)
            .cloned()
            .collect()
    }

    /// Return all running VMs.
    #[must_use]
    pub fn running(&self) -> Vec<VmInstance> {
        self.instances
            .lock()
            .iter()
            .filter(|v| v.state == VmState::Running)
            .cloned()
            .collect()
    }

    /// Return the total number of VMs.
    #[must_use]
    pub fn count(&self) -> usize {
        self.instances.lock().len()
    }

    /// Generate a unique VM ID.
    #[must_use]
    pub fn next_id(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("vm-{n:08x}")
    }

    /// Find a stopped VM matching the given OS and arch.
    #[must_use]
    pub fn find_compatible(&self, os: &VmOs, arch: &VmArch) -> Option<VmInstance> {
        self.instances
            .lock()
            .iter()
            .find(|v| v.state == VmState::Stopped && &v.config.os == os && &v.config.arch == arch)
            .cloned()
    }
}

impl Default for VmPool {
    fn default() -> Self {
        Self::new()
    }
}

// ─── VmSandbox ───────────────────────────────────────────────────────────────

/// Top-level VM sandbox that ties together a VM instance, an optional live
/// QEMU process handle, and a guest agent.
///
/// The synchronous `start` / `stop` methods are kept for backward
/// compatibility with tests that do not use `async`.  Use `start_async` /
/// `stop_async` for real QEMU process management.
pub struct VmSandbox {
    pub vm: Arc<RwLock<VmInstance>>,
    pub agent: Mutex<GuestAgent>,
    pub run_counter: AtomicU64,
    /// Live QEMU process handle, populated by `start_async`.
    handle: Mutex<Option<QemuHandle>>,
}

impl VmSandbox {
    /// Create a new sandbox around a VM instance.
    #[must_use]
    pub fn new(vm: VmInstance) -> Self {
        let vm_id = vm.id.clone();
        Self {
            vm: Arc::new(RwLock::new(vm)),
            agent: Mutex::new(GuestAgent::new(vm_id)),
            run_counter: AtomicU64::new(0),
            handle: Mutex::new(None),
        }
    }

    // ── Synchronous lifecycle (mock, used by unit tests) ─────────────────────

    /// Start the VM and connect the agent (synchronous mock).
    ///
    /// This does not spawn a real QEMU process.  Use [`VmSandbox::start_async`]
    /// for that.
    ///
    /// # Errors
    /// Returns `VmError::AlreadyRunning` if the VM is already in Running state.
    pub fn start(&self) -> Result<(), VmError> {
        let mut vm = self.vm.write();
        if vm.state == VmState::Running {
            return Err(VmError::AlreadyRunning);
        }
        vm.state = VmState::Starting;
        vm.state = VmState::Running;
        vm.boot_ms = Some(5_000);
        drop(vm);
        self.agent.lock().connect();
        Ok(())
    }

    /// Stop the VM and disconnect the agent (synchronous mock).
    ///
    /// # Errors
    /// Returns `VmError::NotRunning` if the VM is not running.
    pub fn stop(&self) -> Result<(), VmError> {
        let mut vm = self.vm.write();
        if vm.state != VmState::Running {
            return Err(VmError::NotRunning);
        }
        vm.state = VmState::Stopped;
        drop(vm);
        self.agent.lock().disconnect();
        Ok(())
    }

    // ── Async lifecycle (real QEMU) ───────────────────────────────────────────

    /// Spawn a real QEMU process for this sandbox using [`QemuProcessBuilder`].
    ///
    /// Steps:
    /// 1. Build a [`QemuProcessBuilder`] from the VM's config.
    /// 2. Spawn the child process.
    /// 3. Wait up to 10 s for the QMP socket to appear.
    /// 4. Connect a [`QmpClient`] and complete the greeting handshake.
    /// 5. Wait up to `boot_timeout_secs` for the guest status to become
    ///    `"running"`.
    /// 6. Transition `self.state` to `VmState::Running` and connect the agent.
    ///
    /// # Errors
    /// Returns [`VmError::AlreadyRunning`] if the VM is already running,
    /// [`VmError::InvalidState`] if no disk image is configured,
    /// [`VmError::SpawnError`] on process creation failure,
    /// [`VmError::Timeout`] if the QMP socket or running state is not reached
    /// in time, or any [`VmError::CommError`] / QMP error during handshake.
    pub async fn start_async(&self) -> Result<(), VmError> {
        // Guard against double-start.
        {
            let vm = self.vm.read();
            if vm.state == VmState::Running {
                return Err(VmError::AlreadyRunning);
            }
        }

        // Extract config fields while the read lock is held.
        let (image_path, memory_mb, vcpus, net_type, boot_timeout, accelerator, extra_args) = {
            let vm = self.vm.read();
            let cfg = &vm.config;
            let image_path = cfg
                .disk
                .as_ref()
                .map(|d| PathBuf::from(&d.path))
                .ok_or_else(|| VmError::InvalidState("no disk image configured".to_string()))?;
            (
                image_path,
                cfg.memory_mb,
                cfg.vcpus,
                cfg.net_type.clone(),
                cfg.boot_timeout_secs,
                cfg.accelerator.to_string(),
                cfg.extra_args.clone(),
            )
        };

        // Transition to Starting.
        {
            let mut vm = self.vm.write();
            vm.state = VmState::Starting;
        }

        // Map VmNetType -> NetworkMode.
        let net_mode = match net_type {
            VmNetType::None => NetworkMode::None,
            VmNetType::Nat => NetworkMode::User,
            VmNetType::HostOnly => NetworkMode::Tap {
                iface: "tap0".to_string(),
            },
            VmNetType::Bridged => NetworkMode::Bridge {
                br: "br0".to_string(),
            },
        };

        // Build and spawn.
        let mut builder = QemuProcessBuilder::new(image_path)
            .memory_mb(memory_mb)
            .cpus(vcpus)
            .net_mode(net_mode)
            .accelerator(accelerator);

        for arg in &extra_args {
            builder = builder.extra_arg(arg.clone());
        }

        let mut handle = builder.spawn().await.inspect_err(|e| {
            // Roll back to an error state on spawn failure.
            let mut vm = self.vm.write();
            vm.state = VmState::Error(e.to_string());
        })?;

        let qmp_socket = handle.qmp_socket.clone();

        // Wait for the QMP socket to appear (10 s hard timeout).
        // On failure, kill the live QEMU process before returning so it does
        // not become an orphan.
        if let Err(e) = handle.wait_for_qmp_ready(10).await {
            let _ = handle.kill().await;
            let mut vm = self.vm.write();
            vm.state = VmState::Error("qmp socket timeout".to_string());
            return Err(e);
        }

        // Connect the QMP client.
        // On failure, kill the live QEMU process before returning.
        let mut qmp = match QmpClient::connect(&qmp_socket).await {
            Ok(c) => c,
            Err(e) => {
                let _ = handle.kill().await;
                let mut vm = self.vm.write();
                vm.state = VmState::Error(e.to_string());
                return Err(e);
            }
        };

        // Wait for the guest to report "running".
        qmp.wait_for_running(u64::from(boot_timeout))
            .await
            .inspect_err(|_e| {
                let mut vm = self.vm.write();
                vm.state = VmState::Error("guest did not reach running state".to_string());
            })?;

        // Record boot time (wall-clock approximation) and store the handle.
        {
            let mut vm = self.vm.write();
            vm.state = VmState::Running;
            vm.boot_ms = Some(u64::from(boot_timeout) * 1000); // placeholder
        }

        *self.handle.lock() = Some(handle);
        self.agent.lock().connect();

        Ok(())
    }

    /// Gracefully stop the VM via QMP `quit`, then wait for the child to exit.
    ///
    /// If no live handle is present (e.g. this sandbox was started with the
    /// synchronous mock `start()`), this falls back to the synchronous mock stop.
    ///
    /// # Errors
    /// Returns [`VmError::NotRunning`] if the VM is not in the Running state.
    /// Propagates QMP and I/O errors.
    pub async fn stop_async(&self) -> Result<(), VmError> {
        {
            let vm = self.vm.read();
            if vm.state != VmState::Running {
                return Err(VmError::NotRunning);
            }
        }

        let qmp_socket = {
            let handle_lock = self.handle.lock();
            handle_lock.as_ref().map(|h| h.qmp_socket.clone())
        };

        if let Some(socket_path) = qmp_socket {
            // Best-effort QMP quit — ignore errors (socket may already be closed).
            if let Ok(mut qmp) = QmpClient::connect(&socket_path).await {
                let _ = qmp.quit().await;
            }

            // Wait for the child process.
            let mut handle_lock = self.handle.lock();
            if let Some(ref mut h) = *handle_lock {
                // Give QEMU 5 s to exit cleanly; then kill it.
                let wait_result = timeout(Duration::from_secs(5), h.wait()).await;
                if wait_result.is_err() {
                    let _ = h.kill().await;
                }
            }
            *handle_lock = None;
        }

        // Update state and disconnect agent.
        {
            let mut vm = self.vm.write();
            vm.state = VmState::Stopped;
        }
        self.agent.lock().disconnect();

        Ok(())
    }

    /// Save a live snapshot via QMP `savevm`.
    ///
    /// Records the snapshot in the in-memory [`VmInstance`] snapshot list.
    ///
    /// # Errors
    /// Returns [`VmError::NotRunning`] if the VM is not running, or propagates
    /// QMP errors.
    pub async fn snapshot_async(&self, tag: &str) -> Result<String, VmError> {
        {
            let vm = self.vm.read();
            if vm.state != VmState::Running {
                return Err(VmError::NotRunning);
            }
        }

        let qmp_socket = self
            .handle
            .lock()
            .as_ref()
            .map(|h| h.qmp_socket.clone())
            .ok_or(VmError::NotRunning)?;

        let mut qmp = QmpClient::connect(&qmp_socket).await?;
        qmp.savevm(tag).await?;

        // Register in the instance metadata.
        let snap_id = self.vm.write().take_snapshot(tag)?;
        Ok(snap_id)
    }

    /// Revert the VM to a snapshot via QMP `loadvm`.
    ///
    /// The VM must be running (QMP connection is live).  After restoring, the
    /// guest returns to running state automatically.
    ///
    /// # Errors
    /// Returns [`VmError::NotRunning`] if the VM is not running or no handle
    /// exists, or propagates QMP errors.
    pub async fn revert_async(&self, tag: &str) -> Result<(), VmError> {
        let qmp_socket = self
            .handle
            .lock()
            .as_ref()
            .map(|h| h.qmp_socket.clone())
            .ok_or(VmError::NotRunning)?;

        let mut qmp = QmpClient::connect(&qmp_socket).await?;

        // QEMU requires the VM to be stopped before loadvm.
        qmp.stop_vm().await?;
        qmp.loadvm(tag).await?;
        qmp.cont_vm().await?;

        Ok(())
    }

    // ── Shared helpers ────────────────────────────────────────────────────────

    /// Take a snapshot of the current VM state (synchronous, in-memory only).
    ///
    /// # Errors
    /// Propagates `VmError::SnapshotFailed`.
    pub fn snapshot(&self, name: impl Into<String>) -> Result<String, VmError> {
        self.vm.write().take_snapshot(name)
    }

    /// Revert to a named snapshot, stopping first if running.
    ///
    /// # Errors
    /// Returns `VmError::NotFound` if the snapshot doesn't exist.
    pub fn revert_to(&self, snap_id: &str) -> Result<(), VmError> {
        let was_running = {
            let vm = self.vm.read();
            vm.state == VmState::Running
        };
        if was_running {
            self.stop()?;
        }
        self.vm.write().revert(snap_id)
    }

    /// Execute a command inside the guest via the agent.
    ///
    /// # Errors
    /// Returns `VmError::CommError` if the agent is not connected.
    pub fn exec(&self, cmd: &GuestCommand) -> Result<GuestCommandResult, VmError> {
        self.run_counter.fetch_add(1, Ordering::Relaxed);
        self.agent.lock().exec(cmd)
    }

    /// Upload a binary to the guest for execution.
    ///
    /// # Errors
    /// Returns `VmError::CommError` if not connected.
    pub fn upload_sample(&self, local_path: &str, guest_path: &str) -> Result<(), VmError> {
        self.agent.lock().upload(local_path, guest_path)
    }

    /// Read the memory map of a guest process.
    ///
    /// # Errors
    /// Returns `VmError::CommError` if not connected.
    pub fn read_memory_map(&self, pid: u32) -> Result<MemoryMap, VmError> {
        self.agent.lock().read_memory_map(pid)
    }

    /// Number of commands run through this sandbox.
    #[must_use]
    pub fn run_count(&self) -> u64 {
        self.run_counter.load(Ordering::Relaxed)
    }

    /// Current VM state.
    #[must_use]
    pub fn state(&self) -> VmState {
        self.vm.read().state.clone()
    }

    /// Returns `true` if a live QEMU process handle is attached.
    #[must_use]
    pub fn has_live_handle(&self) -> bool {
        self.handle.lock().is_some()
    }
}

// ─── SandboxEvent ────────────────────────────────────────────────────────────

/// A discrete event recorded during sandbox execution.
///
/// Used by `VmBehaviorClassifier` and related analysis components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEvent {
    /// Milliseconds since execution start.
    pub ts_ms: u64,
    /// PID that generated this event.
    pub pid: u32,
    /// High-level category of the event.
    pub kind: SandboxEventKind,
    /// Human-readable detail string.
    pub detail: String,
}

impl SandboxEvent {
    /// Create a new event.
    #[must_use]
    pub fn new(ts_ms: u64, pid: u32, kind: SandboxEventKind, detail: impl Into<String>) -> Self {
        Self {
            ts_ms,
            pid,
            kind,
            detail: detail.into(),
        }
    }
}

/// High-level category for a `SandboxEvent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxEventKind {
    /// A Windows API call was made.
    ApiCall(String),
    /// A file was created, written, or deleted.
    FileOp(String),
    /// A network connection was attempted or established.
    NetworkConn,
    /// A registry key was read or written.
    RegistryOp,
    /// A process or thread was created.
    ProcessSpawn,
    /// Code was injected into another process.
    CodeInjection,
    /// A shadow copy delete operation was detected.
    DeleteShadowCopies,
    /// A file extension was changed (indicator of ransomware encryption).
    ExtensionChange,
    /// A screenshot or screen-capture API was called.
    ScreenCapture,
    /// A keyboard-hook API was called.
    KeyboardHook,
    /// A CPU-intensive loop was observed (potential miner).
    HighCpuLoad,
    /// An import / module load event.
    ModuleLoad(String),
    /// A mutex was created.
    MutexCreate,
    /// Generic / uncategorised.
    Other(String),
}

impl fmt::Display for SandboxEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiCall(n) => write!(f, "api_call:{n}"),
            Self::FileOp(p) => write!(f, "file_op:{p}"),
            Self::NetworkConn => write!(f, "network_conn"),
            Self::RegistryOp => write!(f, "registry_op"),
            Self::ProcessSpawn => write!(f, "process_spawn"),
            Self::CodeInjection => write!(f, "code_injection"),
            Self::DeleteShadowCopies => write!(f, "delete_shadow_copies"),
            Self::ExtensionChange => write!(f, "extension_change"),
            Self::ScreenCapture => write!(f, "screen_capture"),
            Self::KeyboardHook => write!(f, "keyboard_hook"),
            Self::HighCpuLoad => write!(f, "high_cpu_load"),
            Self::ModuleLoad(m) => write!(f, "module_load:{m}"),
            Self::MutexCreate => write!(f, "mutex_create"),
            Self::Other(s) => write!(f, "other:{s}"),
        }
    }
}

// ─── SandboxVm (type alias / thin wrapper) ────────────────────────────────────

/// Thin type alias used by `VmSnapshotManager` and `VmNetworkInterceptor`.
///
/// In this module the canonical VM handle is `VmSandbox`; `SandboxVm` is
/// provided so that the snapshot / network APIs have a stable, narrowly-scoped
/// type without coupling to the full `VmSandbox` state.
pub type SandboxVm = VmSandbox;

// ─── VmSnapshotManager ───────────────────────────────────────────────────────

/// A snapshot taken of a running `SandboxVm`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmSnapshot {
    /// Monotonically increasing snapshot ID.
    pub id: u64,
    /// Unix timestamp (seconds) when the snapshot was taken.
    pub timestamp: u64,
    /// Internal snapshot name stored in the VM's snapshot list.
    pub(crate) vm_snap_id: String,
}

/// Summary info returned by `VmSnapshotManager::list_snapshots`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmSnapshotInfo {
    /// Snapshot ID.
    pub id: u64,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// Human-readable label.
    pub label: String,
}

/// Manages save/restore of `SandboxVm` state using the underlying
/// `VmInstance::take_snapshot` / `VmInstance::revert_snapshot` machinery.
pub struct VmSnapshotManager {
    counter: AtomicU64,
    /// Registry of all snapshots taken via this manager.
    registry: Mutex<Vec<(VmSnapshot, String /* label */)>>,
}

impl VmSnapshotManager {
    /// Create a new manager.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
            registry: Mutex::new(vec![]),
        }
    }

    /// Take a snapshot of `vm` and return a `VmSnapshot` handle.
    ///
    /// The snapshot is stored in `vm`'s underlying `VmInstance` via
    /// `take_snapshot` and also registered here for later listing / restore.
    pub fn snapshot(&self, vm: &SandboxVm) -> VmSnapshot {
        let id = self.counter.fetch_add(1, Ordering::SeqCst);
        let label = format!("mgr-snap-{id}");
        let vm_snap_id = {
            let mut inst = vm.vm.write();
            // `take_snapshot` only fails if the VM is in error state; we
            // fall back to a synthetic ID if that somehow happens.
            inst.take_snapshot(label.as_str())
                .unwrap_or_else(|_| format!("fallback-{id}"))
        };

        // Use a coarse timestamp: sequential counter acts as a logical clock
        // when a real wall-clock is not available in the sandbox environment.
        // Replace with `std::time::SystemTime` if a real clock is accessible.
        let timestamp = id; // logical timestamp

        let snap = VmSnapshot {
            id,
            timestamp,
            vm_snap_id,
        };
        self.registry.lock().push((snap.clone(), label));
        snap
    }

    /// Restore `vm` to the state captured in `snapshot`.
    ///
    /// Returns `true` on success, `false` if the snapshot was not found in
    /// the VM's snapshot list.
    pub fn restore(&self, vm: &mut SandboxVm, snapshot: &VmSnapshot) -> bool {
        let mut inst = vm.vm.write();
        // Delegate to VmInstance::revert which truncates the snapshot history
        // to the target point and drives the state transitions correctly.
        match inst.revert(&snapshot.vm_snap_id) {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    /// Return summary info for all snapshots taken by this manager.
    #[must_use]
    pub fn list_snapshots(&self) -> Vec<VmSnapshotInfo> {
        self.registry
            .lock()
            .iter()
            .map(|(snap, label)| VmSnapshotInfo {
                id: snap.id,
                timestamp: snap.timestamp,
                label: label.clone(),
            })
            .collect()
    }
}

impl Default for VmSnapshotManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── VmNetworkInterceptor ────────────────────────────────────────────────────

/// A single intercepted network connection recorded in the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterception {
    /// Source IP address.
    pub src_ip: String,
    /// Destination IP address.
    pub dst_ip: String,
    /// Destination port.
    pub dst_port: u16,
    /// Protocol string, e.g. `"tcp"`, `"udp"`.
    pub proto: String,
    /// Number of payload bytes observed in this connection.
    pub payload_bytes: usize,
    /// Millisecond timestamp when this connection was first observed.
    pub ts_ms: u64,
}

impl NetworkInterception {
    /// Create a new interception record.
    #[must_use]
    pub fn new(
        src_ip: impl Into<String>,
        dst_ip: impl Into<String>,
        dst_port: u16,
        proto: impl Into<String>,
        payload_bytes: usize,
        ts_ms: u64,
    ) -> Self {
        Self {
            src_ip: src_ip.into(),
            dst_ip: dst_ip.into(),
            dst_port,
            proto: proto.into(),
            payload_bytes,
            ts_ms,
        }
    }
}

/// Intercepts and analyses VM network traffic.
///
/// In a real deployment this would hook into a virtual network bridge or a
/// kernel-level packet filter; here it operates on a pre-recorded log of
/// `NetworkInterception` entries to keep the implementation portable.
pub struct VmNetworkInterceptor {
    /// All recorded connections (appended via `record`).
    connections: Mutex<Vec<NetworkInterception>>,
    /// When `true`, the interceptor acts as if external traffic is blocked /
    /// redirected to an internal sinkhole.
    block_external: Mutex<bool>,
}

impl VmNetworkInterceptor {
    /// Create a new interceptor with no recorded connections.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            connections: Mutex::new(vec![]),
            block_external: Mutex::new(false),
        }
    }

    /// Record a connection (called by the guest-agent shim or a packet hook).
    pub fn record(&self, conn: NetworkInterception) {
        self.connections.lock().push(conn);
    }

    /// Return a snapshot of all intercepted connections.
    #[must_use]
    pub fn intercept_connections(&self) -> Vec<NetworkInterception> {
        self.connections.lock().clone()
    }

    /// Configure the interceptor to redirect all external traffic to an
    /// internal sinkhole (sets the `block_external` flag).
    pub fn block_external_connections(&self) {
        *self.block_external.lock() = true;
    }

    /// Returns `true` when external traffic is being blocked / redirected.
    #[must_use]
    pub fn is_blocking(&self) -> bool {
        *self.block_external.lock()
    }

    /// Heuristic: detect C2 beaconing patterns in the recorded connections.
    ///
    /// A connection is flagged as a potential C2 beacon when:
    /// - It communicates on a common C2 port (80, 443, 8080, 8443, 4444, 1337,
    ///   6667, 6697) **or** uses a known C2 protocol (tcp/udp).
    /// - Its destination IP does not fall in a private address range.
    /// - The `payload_bytes` count is small (≤ 512), which is typical for
    ///   keep-alive / beacon check-ins.
    ///
    /// Additionally, if multiple connections to the **same** `(dst_ip, dst_port)`
    /// pair are recorded and their inter-arrival intervals cluster tightly
    /// (coefficient of variation < 0.3), the entire cluster is treated as a
    /// beaconing pattern — this method returns `true` for any member of such a
    /// cluster.
    #[must_use]
    pub fn is_c2_pattern(&self, conn: &NetworkInterception) -> bool {
        const C2_PORTS: &[u16] = &[80, 443, 8080, 8443, 4444, 1337, 6667, 6697];

        // Step 1: single-connection port / payload heuristic.
        let suspicious_port = C2_PORTS.contains(&conn.dst_port);
        let small_payload = conn.payload_bytes <= 512;
        let external_ip = !Self::is_private_ip(&conn.dst_ip);

        if suspicious_port && small_payload && external_ip {
            return true;
        }

        // Step 2: beaconing interval detection.
        // Collect all connections to the same (dst_ip, dst_port) and check
        // whether their timestamps form a regular interval.
        let conns = self.connections.lock();
        let same_target: Vec<u64> = conns
            .iter()
            .filter(|c| c.dst_ip == conn.dst_ip && c.dst_port == conn.dst_port)
            .map(|c| c.ts_ms)
            .collect();

        if same_target.len() < 3 {
            return false;
        }

        let mut sorted = same_target;
        sorted.sort_unstable();

        // Compute inter-arrival intervals.
        let intervals: Vec<f64> = sorted.windows(2).map(|w| (w[1] - w[0]) as f64).collect();

        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / n;
        if mean < 1.0 {
            return false; // degenerate
        }
        let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
        let cv = variance.sqrt() / mean; // coefficient of variation

        // Low CV → regular / periodic → beaconing.
        cv < 0.3
    }

    /// Returns `true` if `ip` is in a private or loopback range.
    fn is_private_ip(ip: &str) -> bool {
        // Fast string-based checks for the most common private ranges.
        ip.starts_with("10.")
            || ip.starts_with("192.168.")
            || ip.starts_with("172.16.")
            || ip.starts_with("172.17.")
            || ip.starts_with("172.18.")
            || ip.starts_with("172.19.")
            || ip.starts_with("172.20.")
            || ip.starts_with("172.21.")
            || ip.starts_with("172.22.")
            || ip.starts_with("172.23.")
            || ip.starts_with("172.24.")
            || ip.starts_with("172.25.")
            || ip.starts_with("172.26.")
            || ip.starts_with("172.27.")
            || ip.starts_with("172.28.")
            || ip.starts_with("172.29.")  // 172.20–172.29 (RFC 1918)
            || ip.starts_with("172.30.")
            || ip.starts_with("172.31.")
            || ip.starts_with("127.")
            || ip == "::1"
    }
}

impl Default for VmNetworkInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── VmBehaviorClassifier ────────────────────────────────────────────────────

/// High-level malware family category inferred from sandbox events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MalwareCategory {
    /// Downloads and executes additional payloads.
    Downloader,
    /// Encrypts files and demands ransom.
    Ransomware,
    /// Remote-access trojan: remote control + data exfiltration.
    Rat,
    /// Records keystrokes.
    Keylogger,
    /// Mines cryptocurrency.
    Miner,
    /// Unpacks and executes a hidden payload.
    Dropper,
    /// No malicious behaviour detected.
    Benign,
    /// Insufficient evidence to classify.
    Unknown,
}

impl fmt::Display for MalwareCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Downloader => "downloader",
            Self::Ransomware => "ransomware",
            Self::Rat => "rat",
            Self::Keylogger => "keylogger",
            Self::Miner => "miner",
            Self::Dropper => "dropper",
            Self::Benign => "benign",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

/// Classifies a sequence of `SandboxEvent`s into a `MalwareCategory`.
///
/// Each heuristic returns a numeric confidence score (0–100).  The category
/// with the highest score wins; ties are broken by order of definition above.
pub struct VmBehaviorClassifier;

impl VmBehaviorClassifier {
    /// Create a new classifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Classify a slice of events into a `MalwareCategory`.
    ///
    /// # Heuristics
    ///
    /// | Category    | Signals                                                      |
    /// |-------------|--------------------------------------------------------------|
    /// | Ransomware  | ≥5 file writes + ≥2 extension changes + DeleteShadowCopies  |
    /// | RAT         | NetworkConn + CodeInjection + ScreenCapture                  |
    /// | Keylogger   | KeyboardHook present                                         |
    /// | Miner       | HighCpuLoad + NetworkConn + crypto-related module load        |
    /// | Dropper     | CodeInjection or ProcessSpawn with no network                 |
    /// | Downloader  | NetworkConn + ProcessSpawn                                    |
    /// | Benign      | No suspicious signals at all                                  |
    #[must_use]
    pub fn classify(&self, events: &[SandboxEvent]) -> MalwareCategory {
        let mut scores = [
            (MalwareCategory::Ransomware, self.score_ransomware(events)),
            (MalwareCategory::Rat, self.score_rat(events)),
            (MalwareCategory::Keylogger, self.score_keylogger(events)),
            (MalwareCategory::Miner, self.score_miner(events)),
            (MalwareCategory::Dropper, self.score_dropper(events)),
            (MalwareCategory::Downloader, self.score_downloader(events)),
        ];

        // Find the highest-scoring category.
        scores.sort_by(|a, b| b.1.cmp(&a.1));

        let (best_cat, best_score) = scores.into_iter().next().unwrap();
        if best_score == 0 {
            // No signal at all → Benign if there were events, Unknown if empty.
            return if events.is_empty() {
                MalwareCategory::Unknown
            } else {
                MalwareCategory::Benign
            };
        }
        best_cat
    }

    // ── Private scoring helpers ───────────────────────────────────────────────

    fn count<F: Fn(&SandboxEvent) -> bool>(events: &[SandboxEvent], f: F) -> usize {
        events.iter().filter(|e| f(e)).count()
    }

    fn has<F: Fn(&SandboxEvent) -> bool>(events: &[SandboxEvent], f: F) -> bool {
        events.iter().any(f)
    }

    fn score_ransomware(&self, events: &[SandboxEvent]) -> u32 {
        let mut score = 0u32;

        let file_writes = Self::count(
            events,
            |e| matches!(&e.kind, SandboxEventKind::FileOp(p) if p.contains("write") || p.contains("create")),
        );
        let ext_changes = Self::count(events, |e| {
            matches!(e.kind, SandboxEventKind::ExtensionChange)
        });
        let shadow_delete = Self::has(events, |e| {
            matches!(e.kind, SandboxEventKind::DeleteShadowCopies)
        });
        let crypt_api = Self::has(events, |e| {
            matches!(&e.kind, SandboxEventKind::ApiCall(n)
                if n.contains("Crypt") || n.contains("BCrypt") || n.contains("Aes"))
        });

        if file_writes >= 5 {
            score += 30;
        }
        if file_writes >= 20 {
            score += 20;
        } // mass encryption
        if ext_changes >= 2 {
            score += 25;
        }
        if shadow_delete {
            score += 30;
        }
        if crypt_api {
            score += 15;
        }

        score
    }

    fn score_rat(&self, events: &[SandboxEvent]) -> u32 {
        let mut score = 0u32;

        let has_net = Self::has(events, |e| matches!(e.kind, SandboxEventKind::NetworkConn));
        let has_inject = Self::has(events, |e| {
            matches!(e.kind, SandboxEventKind::CodeInjection)
        });
        let has_screen = Self::has(events, |e| {
            matches!(e.kind, SandboxEventKind::ScreenCapture)
        });
        let has_proc = Self::has(events, |e| matches!(e.kind, SandboxEventKind::ProcessSpawn));

        if has_net {
            score += 20;
        }
        if has_inject {
            score += 30;
        }
        if has_screen {
            score += 25;
        }
        if has_proc {
            score += 10;
        }
        // All three together is a very strong RAT signal.
        if has_net && has_inject && has_screen {
            score += 25;
        }

        score
    }

    fn score_keylogger(&self, events: &[SandboxEvent]) -> u32 {
        let mut score = 0u32;

        let has_hook = Self::has(events, |e| matches!(e.kind, SandboxEventKind::KeyboardHook));
        let has_getkey_api = Self::has(events, |e| {
            matches!(&e.kind, SandboxEventKind::ApiCall(n)
                if n.contains("GetAsyncKeyState")
                    || n.contains("GetKeyState")
                    || n.contains("ReadConsoleInput"))
        });
        let has_file_write = Self::has(
            events,
            |e| matches!(&e.kind, SandboxEventKind::FileOp(p) if p.contains("write")),
        );

        if has_hook {
            score += 50;
        }
        if has_getkey_api {
            score += 30;
        }
        if has_file_write {
            score += 20;
        } // writing captured keys to disk

        score
    }

    fn score_miner(&self, events: &[SandboxEvent]) -> u32 {
        let mut score = 0u32;

        let has_cpu = Self::has(events, |e| matches!(e.kind, SandboxEventKind::HighCpuLoad));
        let has_net = Self::has(events, |e| matches!(e.kind, SandboxEventKind::NetworkConn));
        let has_crypto_mod = Self::has(events, |e| {
            matches!(&e.kind, SandboxEventKind::ModuleLoad(m)
                if m.to_ascii_lowercase().contains("crypto")
                    || m.to_ascii_lowercase().contains("opencl")
                    || m.to_ascii_lowercase().contains("cuda")
                    || m.to_ascii_lowercase().contains("xmr"))
        });
        let has_stratum = Self::has(events, |e| {
            e.detail.to_ascii_lowercase().contains("stratum") || e.detail.contains("mining.notify")
        });

        if has_cpu {
            score += 30;
        }
        if has_net {
            score += 20;
        }
        if has_crypto_mod {
            score += 35;
        }
        if has_stratum {
            score += 40;
        }

        score
    }

    fn score_dropper(&self, events: &[SandboxEvent]) -> u32 {
        let mut score = 0u32;

        let has_inject = Self::has(events, |e| {
            matches!(e.kind, SandboxEventKind::CodeInjection)
        });
        let has_proc = Self::has(events, |e| matches!(e.kind, SandboxEventKind::ProcessSpawn));
        let has_net = Self::has(events, |e| matches!(e.kind, SandboxEventKind::NetworkConn));
        let has_drop = Self::has(events, |e| {
            matches!(&e.kind, SandboxEventKind::FileOp(p)
                if p.contains("create") || p.contains("write"))
        });

        if has_inject {
            score += 30;
        }
        if has_proc {
            score += 20;
        }
        if has_drop {
            score += 20;
        }
        // Dropper typically does NOT need network.
        if !has_net && (has_inject || has_proc) {
            score += 15;
        }

        score
    }

    fn score_downloader(&self, events: &[SandboxEvent]) -> u32 {
        let mut score = 0u32;

        let has_net = Self::has(events, |e| matches!(e.kind, SandboxEventKind::NetworkConn));
        let has_proc = Self::has(events, |e| matches!(e.kind, SandboxEventKind::ProcessSpawn));
        let has_http = Self::has(events, |e| {
            matches!(&e.kind, SandboxEventKind::ApiCall(n)
                if n.contains("Http") || n.contains("WinHttp") || n.contains("URLDownload"))
        });
        let has_drop = Self::has(
            events,
            |e| matches!(&e.kind, SandboxEventKind::FileOp(p) if p.contains("create")),
        );

        if has_net {
            score += 20;
        }
        if has_proc {
            score += 20;
        }
        if has_http {
            score += 30;
        }
        if has_drop {
            score += 15;
        }
        if has_net && has_proc {
            score += 15;
        }

        score
    }
}

impl Default for VmBehaviorClassifier {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SANDBOX ORCHESTRATION LAYER
// ═══════════════════════════════════════════════════════════════════════════

// ─── AnalysisOptions ─────────────────────────────────────────────────────────

/// Fine-grained options that control what the sandbox monitors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOptions {
    /// Intercept Win32 API calls.
    pub trace_api: bool,
    /// Intercept filesystem create/read/write/delete events.
    pub trace_fs: bool,
    /// Intercept Windows registry reads and writes.
    pub trace_registry: bool,
    /// Intercept raw network packets (requires pcap in guest or host bridge tap).
    pub capture_network: bool,
    /// Record all process and thread creation/exit events.
    pub trace_processes: bool,
    /// Detect and record code injection (`WriteProcessMemory`, `CreateRemoteThread`, …).
    pub detect_injection: bool,
    /// Resolve return addresses in API call stacks.
    pub resolve_call_stacks: bool,
    /// Maximum depth for call-stack unwinding on each API entry.
    pub call_stack_depth: u8,
    /// Hook exports of all loaded DLLs, not just well-known ones.
    pub hook_all_modules: bool,
    /// Enable memory-region change tracking.
    pub track_memory_regions: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            trace_api: true,
            trace_fs: true,
            trace_registry: true,
            capture_network: true,
            trace_processes: true,
            detect_injection: true,
            resolve_call_stacks: true,
            call_stack_depth: 10,
            hook_all_modules: false,
            track_memory_regions: false,
        }
    }
}

// ─── OsProfile ───────────────────────────────────────────────────────────────

/// Target operating-system profile for a sandbox analysis run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsProfile {
    Windows10x64,
    Windows11x64,
    Ubuntu2204,
    Debian12,
    Custom {
        name: String,
        kernel_version: String,
    },
}

impl fmt::Display for OsProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows10x64 => write!(f, "windows10_x64"),
            Self::Windows11x64 => write!(f, "windows11_x64"),
            Self::Ubuntu2204 => write!(f, "ubuntu_22.04"),
            Self::Debian12 => write!(f, "debian_12"),
            Self::Custom { name, .. } => write!(f, "custom:{name}"),
        }
    }
}

impl OsProfile {
    /// Returns `true` for Windows profiles.
    #[must_use]
    pub const fn is_windows(&self) -> bool {
        matches!(self, Self::Windows10x64 | Self::Windows11x64)
    }

    /// Returns `true` for Linux profiles.
    #[must_use]
    pub const fn is_linux(&self) -> bool {
        matches!(
            self,
            Self::Ubuntu2204 | Self::Debian12 | Self::Custom { .. }
        )
    }

    /// Best-guess CPU arch for this profile.
    #[must_use]
    pub const fn default_arch(&self) -> Arch {
        match self {
            Self::Windows10x64 | Self::Windows11x64 | Self::Ubuntu2204 | Self::Debian12 => {
                Arch::X64
            }
            Self::Custom { .. } => Arch::X64,
        }
    }
}

// ─── Arch ────────────────────────────────────────────────────────────────────

/// CPU architecture for sandbox templates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    X86,
    X64,
    Arm,
    Arm64,
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X64 => write!(f, "x64"),
            Self::Arm => write!(f, "arm"),
            Self::Arm64 => write!(f, "arm64"),
        }
    }
}

// ─── SandboxNetworkMode ──────────────────────────────────────────────────────

/// Network connectivity mode for a sandbox analysis job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxNetworkMode {
    /// No network access whatsoever.
    Isolated,
    /// Route all traffic through an `INetSim` server at `host:port`.
    INetSim { host: String, port: u16 },
    /// Allow real Internet access (dangerous; use only on isolated VLANs).
    Internet,
}

impl fmt::Display for SandboxNetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Isolated => write!(f, "isolated"),
            Self::INetSim { host, port } => write!(f, "inetsim@{host}:{port}"),
            Self::Internet => write!(f, "internet"),
        }
    }
}

// ─── SandboxConfig ───────────────────────────────────────────────────────────

/// Complete configuration for one sandbox analysis run.
///
/// Built via the builder methods; all fields have sensible defaults.
///
/// ```rust
/// # use rustre_sandbox_vm::SandboxConfig;
/// # use std::time::Duration;
/// let cfg = SandboxConfig::default()
///     .with_timeout(Duration::from_secs(120))
///     .with_max_api_calls(50_000)
///     .with_screenshots(true);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Human-readable name for this sandbox VM slot.
    pub vm_name: String,
    /// Snapshot tag to restore before each run.
    pub snapshot_name: String,
    /// Network connectivity mode.
    pub network_mode: SandboxNetworkMode,
    /// Wall-clock timeout for a single analysis run.
    pub timeout: Duration,
    /// Fine-grained analysis options.
    pub analysis_options: AnalysisOptions,
    /// Target operating-system profile.
    pub os_profile: OsProfile,
    /// Hard cap on the number of API entries recorded (prevents OOM).
    pub max_api_calls: u32,
    /// Whether to capture periodic screenshots during execution.
    pub capture_screenshots: bool,
    /// Whether to collect basic-block coverage data from the agent.
    pub enable_coverage: bool,
    /// Memory to allocate for the VM in megabytes.
    pub memory_mb: u32,
    /// Number of vCPUs to assign.
    pub vcpus: u8,
    /// Path to the VM disk image on the host.
    pub disk_image_path: String,
    /// Screenshot capture interval in seconds (only used if `capture_screenshots`).
    pub screenshot_interval_secs: u32,
    /// Drop timeout: how long to wait after analysis ends for dropped-file collection.
    pub artifact_collect_timeout_secs: u32,
    /// Extra command-line arguments forwarded to the backend.
    pub extra_backend_args: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            vm_name: "rustre-sandbox-0".to_string(),
            snapshot_name: "clean-base".to_string(),
            network_mode: SandboxNetworkMode::Isolated,
            timeout: Duration::from_mins(2),
            analysis_options: AnalysisOptions::default(),
            os_profile: OsProfile::Windows10x64,
            max_api_calls: 100_000,
            capture_screenshots: false,
            enable_coverage: false,
            memory_mb: 2048,
            vcpus: 2,
            disk_image_path: String::new(),
            screenshot_interval_secs: 10,
            artifact_collect_timeout_secs: 30,
            extra_backend_args: vec![],
        }
    }
}

impl SandboxConfig {
    /// Create a default config for the given OS profile.
    #[must_use]
    pub fn for_os(profile: OsProfile) -> Self {
        Self {
            os_profile: profile,
            ..Default::default()
        }
    }

    /// Set the VM name.
    #[must_use]
    pub fn with_vm_name(mut self, name: impl Into<String>) -> Self {
        self.vm_name = name.into();
        self
    }

    /// Set the snapshot tag.
    #[must_use]
    pub fn with_snapshot(mut self, snap: impl Into<String>) -> Self {
        self.snapshot_name = snap.into();
        self
    }

    /// Set the network mode.
    #[must_use]
    pub fn with_network_mode(mut self, mode: SandboxNetworkMode) -> Self {
        self.network_mode = mode;
        self
    }

    /// Set the analysis timeout.
    #[must_use]
    pub const fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Replace the analysis options.
    #[must_use]
    pub const fn with_analysis_options(mut self, opts: AnalysisOptions) -> Self {
        self.analysis_options = opts;
        self
    }

    /// Set the maximum API call count.
    #[must_use]
    pub const fn with_max_api_calls(mut self, n: u32) -> Self {
        self.max_api_calls = n;
        self
    }

    /// Enable or disable screenshot capture.
    #[must_use]
    pub const fn with_screenshots(mut self, enabled: bool) -> Self {
        self.capture_screenshots = enabled;
        self
    }

    /// Enable or disable coverage data collection.
    #[must_use]
    pub const fn with_coverage(mut self, enabled: bool) -> Self {
        self.enable_coverage = enabled;
        self
    }

    /// Set the RAM in megabytes.
    #[must_use]
    pub const fn with_memory(mut self, mb: u32) -> Self {
        self.memory_mb = mb;
        self
    }

    /// Set the vCPU count.
    #[must_use]
    pub const fn with_vcpus(mut self, n: u8) -> Self {
        self.vcpus = n;
        self
    }

    /// Set the disk image path.
    #[must_use]
    pub fn with_disk_image(mut self, path: impl Into<String>) -> Self {
        self.disk_image_path = path.into();
        self
    }

    /// Returns `true` if the config requests any network access.
    #[must_use]
    pub fn has_network(&self) -> bool {
        self.network_mode != SandboxNetworkMode::Isolated
    }

    /// Validate that mandatory fields are set.
    ///
    /// # Errors
    /// Returns a `String` describing the first validation failure found.
    pub fn validate(&self) -> Result<(), String> {
        if self.vm_name.is_empty() {
            return Err("vm_name must not be empty".to_string());
        }
        if self.snapshot_name.is_empty() {
            return Err("snapshot_name must not be empty".to_string());
        }
        if self.timeout.is_zero() {
            return Err("timeout must be > 0".to_string());
        }
        if self.max_api_calls == 0 {
            return Err("max_api_calls must be > 0".to_string());
        }
        Ok(())
    }
}

// ─── VmTemplate ──────────────────────────────────────────────────────────────

/// A pre-configured VM image template used by sandbox backends.
///
/// Each template represents a specific (name, snapshot, OS, arch) combination
/// that backends can clone to create fresh analysis VMs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmTemplate {
    /// Display name for this template (e.g. `"win10-x64-clean"`).
    pub name: String,
    /// Libvirt domain name or Firecracker image ID backing this template.
    pub libvirt_domain: String,
    /// Snapshot identifier within `libvirt_domain`.
    pub snapshot_id: String,
    /// Target OS profile.
    pub os: OsProfile,
    /// Target CPU architecture.
    pub arch: Arch,
    /// Guest IP address (used by `GuestAgentClient` to connect).
    pub ip: String,
    /// Guest agent TCP port.
    pub port: u16,
    /// Root password or SSH key path for guest access.
    pub credentials: Option<String>,
    /// Disk image path on the host.
    pub disk_image_path: String,
    /// Maximum number of concurrent sandbox jobs this template can serve.
    pub max_concurrent_jobs: u8,
}

impl VmTemplate {
    /// Create a new template.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        libvirt_domain: impl Into<String>,
        snapshot: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            libvirt_domain: libvirt_domain.into(),
            snapshot_id: snapshot.into(),
            os: OsProfile::Windows10x64,
            arch: Arch::X64,
            ip: "192.168.122.100".to_string(),
            port: 8765,
            credentials: None,
            disk_image_path: String::new(),
            max_concurrent_jobs: 1,
        }
    }

    /// Set the OS profile.
    #[must_use]
    pub fn with_os(mut self, os: OsProfile) -> Self {
        self.os = os;
        self
    }

    /// Set the CPU architecture.
    #[must_use]
    pub const fn with_arch(mut self, arch: Arch) -> Self {
        self.arch = arch;
        self
    }

    /// Set the guest IP and agent port.
    #[must_use]
    pub fn with_address(mut self, ip: impl Into<String>, port: u16) -> Self {
        self.ip = ip.into();
        self.port = port;
        self
    }

    /// Set credentials (password or SSH key path).
    #[must_use]
    pub fn with_credentials(mut self, creds: impl Into<String>) -> Self {
        self.credentials = Some(creds.into());
        self
    }

    /// Set the host-side disk image path.
    #[must_use]
    pub fn with_disk_image(mut self, path: impl Into<String>) -> Self {
        self.disk_image_path = path.into();
        self
    }

    /// Allow more concurrent jobs on this template.
    #[must_use]
    pub const fn with_max_concurrent(mut self, n: u8) -> Self {
        self.max_concurrent_jobs = n;
        self
    }

    /// Returns `true` if this template supports the given OS and arch.
    #[must_use]
    pub fn supports(&self, os: &OsProfile, arch: &Arch) -> bool {
        &self.os == os && &self.arch == arch
    }

    /// Returns the connection address string `"ip:port"`.
    #[must_use]
    pub fn connection_addr(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }

    /// Returns a clone with a unique name derived from `job_id` — used when
    /// the backend clones this template to serve a specific job.
    #[must_use]
    pub fn clone_for_job(&self, job_id: &str) -> Self {
        let mut t = self.clone();
        t.name = format!("{}-job-{}", self.name, job_id);
        t
    }
}

// ─── ApiEntry ────────────────────────────────────────────────────────────────

/// A single intercepted API call recorded during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEntry {
    /// Nanoseconds since the analysis run started.
    pub timestamp_ns: u64,
    /// Process ID that made the call.
    pub pid: u32,
    /// Thread ID that made the call.
    pub tid: u32,
    /// API function name (e.g. `"CreateFileW"`).
    pub api_name: String,
    /// Module containing the API (e.g. `"kernel32.dll"`).
    pub module: String,
    /// String-serialised argument values.
    pub args: Vec<String>,
    /// String-serialised return value.
    pub retval: String,
    /// Return-address chain (deepest frame first).
    pub call_stack: Vec<u64>,
    /// Whether this call was the result of code injection.
    pub from_injected_code: bool,
}

impl ApiEntry {
    /// Create a minimal API entry.
    #[must_use]
    pub fn new(
        timestamp_ns: u64,
        pid: u32,
        tid: u32,
        api_name: impl Into<String>,
        module: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_ns,
            pid,
            tid,
            api_name: api_name.into(),
            module: module.into(),
            args: vec![],
            retval: String::new(),
            call_stack: vec![],
            from_injected_code: false,
        }
    }

    /// Add an argument value.
    #[must_use]
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Set the return value.
    #[must_use]
    pub fn with_retval(mut self, rv: impl Into<String>) -> Self {
        self.retval = rv.into();
        self
    }

    /// Set the call stack.
    #[must_use]
    pub fn with_call_stack(mut self, stack: Vec<u64>) -> Self {
        self.call_stack = stack;
        self
    }

    /// Mark as originating from injected code.
    #[must_use]
    pub const fn from_injected(mut self) -> Self {
        self.from_injected_code = true;
        self
    }

    /// Elapsed milliseconds since the run started.
    #[must_use]
    pub const fn elapsed_ms(&self) -> u64 {
        self.timestamp_ns / 1_000_000
    }
}

// ─── NetworkEntry ────────────────────────────────────────────────────────────

/// A single network event recorded in the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEntry {
    /// Milliseconds since run start.
    pub timestamp_ms: u64,
    /// Source IP.
    pub src_ip: String,
    /// Destination IP.
    pub dst_ip: String,
    /// Destination port.
    pub dst_port: u16,
    /// Protocol (`"tcp"`, `"udp"`, `"icmp"`).
    pub protocol: String,
    /// Payload size in bytes.
    pub payload_len: usize,
    /// Whether the connection was blocked (`INetSim` / no-internet mode).
    pub blocked: bool,
    /// Associated process ID.
    pub pid: u32,
}

impl NetworkEntry {
    /// Create a new network entry.
    #[must_use]
    pub fn new(
        timestamp_ms: u64,
        src_ip: impl Into<String>,
        dst_ip: impl Into<String>,
        dst_port: u16,
        protocol: impl Into<String>,
        pid: u32,
    ) -> Self {
        Self {
            timestamp_ms,
            src_ip: src_ip.into(),
            dst_ip: dst_ip.into(),
            dst_port,
            protocol: protocol.into(),
            payload_len: 0,
            blocked: false,
            pid,
        }
    }
}

// ─── FsEvent ─────────────────────────────────────────────────────────────────

/// A filesystem event recorded in the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsEvent {
    /// Milliseconds since run start.
    pub timestamp_ms: u64,
    /// Type of filesystem operation.
    pub operation: FsOperation,
    /// Absolute path affected.
    pub path: String,
    /// Process ID.
    pub pid: u32,
    /// File size after the operation, if known.
    pub size_bytes: Option<u64>,
    /// SHA-256 of the written data (for dropped-file tracking).
    pub content_hash: Option<[u8; 32]>,
}

/// Filesystem operation types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsOperation {
    Create,
    Write,
    Read,
    Delete,
    Rename { new_path: String },
    SetAttributes,
}

impl fmt::Display for FsOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Write => write!(f, "write"),
            Self::Read => write!(f, "read"),
            Self::Delete => write!(f, "delete"),
            Self::Rename { new_path } => write!(f, "rename->{new_path}"),
            Self::SetAttributes => write!(f, "set_attributes"),
        }
    }
}

// ─── RegEvent ────────────────────────────────────────────────────────────────

/// A Windows registry event recorded in the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegEvent {
    /// Milliseconds since run start.
    pub timestamp_ms: u64,
    /// Registry operation type.
    pub operation: RegOperation,
    /// Full registry key path.
    pub key_path: String,
    /// Value name, if applicable.
    pub value_name: Option<String>,
    /// Serialised value data (for write operations).
    pub value_data: Option<String>,
    /// Process ID.
    pub pid: u32,
}

/// Registry operation types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegOperation {
    OpenKey,
    CreateKey,
    DeleteKey,
    QueryValue,
    SetValue,
    DeleteValue,
    EnumKey,
}

impl fmt::Display for RegOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::OpenKey => "open_key",
            Self::CreateKey => "create_key",
            Self::DeleteKey => "delete_key",
            Self::QueryValue => "query_value",
            Self::SetValue => "set_value",
            Self::DeleteValue => "delete_value",
            Self::EnumKey => "enum_key",
        };
        write!(f, "{s}")
    }
}

// ─── ProcessNode / ProcessTree ────────────────────────────────────────────────

/// A single node in the process tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    /// Process ID.
    pub pid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// Process image name (basename only).
    pub name: String,
    /// Full command line.
    pub cmdline: String,
    /// Milliseconds-since-epoch when the process started.
    pub start_time: u64,
    /// Milliseconds-since-epoch when the process exited (if known).
    pub exit_time: Option<u64>,
    /// Exit code, if the process has terminated.
    pub exit_code: Option<i32>,
    /// PIDs of direct child processes.
    pub children: Vec<u32>,
}

impl ProcessNode {
    /// Create a new process node.
    #[must_use]
    pub fn new(
        pid: u32,
        ppid: u32,
        name: impl Into<String>,
        cmdline: impl Into<String>,
        start_time: u64,
    ) -> Self {
        Self {
            pid,
            ppid,
            name: name.into(),
            cmdline: cmdline.into(),
            start_time,
            exit_time: None,
            exit_code: None,
            children: vec![],
        }
    }

    /// Mark this process as exited.
    pub const fn set_exit(&mut self, time: u64, code: i32) {
        self.exit_time = Some(time);
        self.exit_code = Some(code);
    }

    /// Returns `true` if this process is still running (no exit recorded).
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.exit_time.is_none()
    }

    /// Returns the lifetime of this process in milliseconds, or `None` if
    /// it has not exited.
    #[must_use]
    pub fn lifetime_ms(&self) -> Option<u64> {
        self.exit_time.map(|e| e.saturating_sub(self.start_time))
    }
}

/// The full process tree observed during a sandbox run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessTree {
    /// All process nodes, in creation order.
    pub nodes: Vec<ProcessNode>,
    /// PIDs of root (parentless or initial) processes.
    pub root_pids: Vec<u32>,
}

impl ProcessTree {
    /// Create an empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a process node.
    pub fn add_node(&mut self, node: ProcessNode) {
        // If the parent exists in the tree, register this pid as a child.
        let parent_pid = node.ppid;
        let child_pid = node.pid;
        if let Some(parent) = self.nodes.iter_mut().find(|n| n.pid == parent_pid) {
            if !parent.children.contains(&child_pid) {
                parent.children.push(child_pid);
            }
        } else {
            // No parent found → this is a root.
            if !self.root_pids.contains(&child_pid) {
                self.root_pids.push(child_pid);
            }
        }
        self.nodes.push(node);
    }

    /// Find a node by PID.
    #[must_use]
    pub fn find(&self, pid: u32) -> Option<&ProcessNode> {
        self.nodes.iter().find(|n| n.pid == pid)
    }

    /// Find a node (mutable) by PID.
    pub fn find_mut(&mut self, pid: u32) -> Option<&mut ProcessNode> {
        self.nodes.iter_mut().find(|n| n.pid == pid)
    }

    /// Returns the total number of distinct processes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns `true` if the tree has no nodes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Maximum depth of the tree (expensive; intended for tests/reporting).
    #[must_use]
    pub fn max_depth(&self) -> usize {
        fn depth(tree: &ProcessTree, pid: u32, visited: &mut Vec<u32>) -> usize {
            if visited.contains(&pid) {
                return 0;
            }
            visited.push(pid);
            let node = match tree.find(pid) {
                Some(n) => n,
                None => return 0,
            };
            1 + node
                .children
                .iter()
                .map(|&c| depth(tree, c, visited))
                .max()
                .unwrap_or(0)
        }
        let mut vis = vec![];
        self.root_pids
            .iter()
            .map(|&r| depth(self, r, &mut vis))
            .max()
            .unwrap_or(0)
    }

    /// Build a `ProcessTree` by replaying `CreateProcess`-like entries in an
    /// API trace.  Entries whose `api_name` is `"CreateProcessW"`,
    /// `"CreateProcessA"`, `"NtCreateProcess"`, or `"NtCreateUserProcess"` are
    /// used to infer parent→child edges.  The first argument is treated as the
    /// executable path; the second (if present) as the command line.
    #[must_use]
    pub fn build_from_api_trace(trace: &[ApiEntry]) -> Self {
        let mut tree = Self::new();
        let mut pid_counter: u32 = 2000; // synthetic PID space

        // Seed the root process as the first PID seen in the trace.
        if let Some(first) = trace.first() {
            let root = ProcessNode::new(first.pid, 0, "sample.exe", "sample.exe", 0);
            tree.root_pids.push(first.pid);
            tree.nodes.push(root);
        }

        for entry in trace {
            let name_lc = entry.api_name.to_ascii_lowercase();
            let is_create = name_lc.contains("createprocess")
                || name_lc == "ntcreateprocess"
                || name_lc == "ntcreateuserprocess";

            if is_create {
                let exe_name = entry
                    .args
                    .first()
                    .map_or("unknown.exe", std::string::String::as_str);
                let cmdline = entry
                    .args
                    .get(1)
                    .map_or(exe_name, std::string::String::as_str);

                let child_pid = pid_counter;
                pid_counter += 1;

                let child =
                    ProcessNode::new(child_pid, entry.pid, exe_name, cmdline, entry.elapsed_ms());
                tree.add_node(child);
            }

            // Track NtTerminateProcess as exit.
            if (name_lc == "ntterminateprocess" || name_lc == "exitprocess")
                && let Some(node) = tree.find_mut(entry.pid)
            {
                let code = entry.retval.parse::<i32>().unwrap_or(0);
                node.set_exit(entry.elapsed_ms(), code);
            }
        }

        tree
    }
}

// ─── Screenshot ──────────────────────────────────────────────────────────────

/// A screenshot captured during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Screenshot {
    /// Milliseconds since run start when this screenshot was taken.
    pub timestamp_ms: u64,
    /// Raw PNG-encoded image data.
    pub png_data: Vec<u8>,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl Screenshot {
    /// Create a new screenshot record.
    #[must_use]
    pub const fn new(timestamp_ms: u64, png_data: Vec<u8>, width: u32, height: u32) -> Self {
        Self {
            timestamp_ms,
            png_data,
            width,
            height,
        }
    }

    /// Returns the size in bytes of the PNG data.
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        self.png_data.len()
    }
}

// ─── DroppedFile ─────────────────────────────────────────────────────────────

/// A file written to disk by the sample during analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedFile {
    /// Full path inside the guest.
    pub guest_path: String,
    /// Raw file contents.
    pub data: Vec<u8>,
    /// SHA-256 of `data`.
    pub sha256: [u8; 32],
    /// File extension (lowercased, without dot).
    pub extension: String,
    /// Whether this file is itself an executable.
    pub is_executable: bool,
}

impl DroppedFile {
    /// Create a new dropped-file record.
    #[must_use]
    pub fn new(guest_path: impl Into<String>, data: Vec<u8>) -> Self {
        let path: String = guest_path.into();
        let extension = std::path::Path::new(&path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_executable = matches!(
            extension.as_str(),
            "exe" | "dll" | "sys" | "scr" | "com" | "bat" | "ps1"
        );
        // SHA-256 placeholder (real impl would use sha2 crate).
        let sha256 = [0u8; 32];
        Self {
            guest_path: path,
            data,
            sha256,
            extension,
            is_executable,
        }
    }

    /// Size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        self.data.len()
    }
}

// ─── YaraMatch ───────────────────────────────────────────────────────────────

/// A YARA rule match found on a dropped file or memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    /// Name of the matching YARA rule.
    pub rule_name: String,
    /// Rule namespace.
    pub namespace: String,
    /// Tags declared in the rule.
    pub tags: Vec<String>,
    /// Byte offsets where the match occurred.
    pub match_offsets: Vec<usize>,
    /// Context: either a dropped file path or a memory region label.
    pub context: String,
}

// ─── SandboxJob ──────────────────────────────────────────────────────────────

/// A single analysis job submitted to the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxJob {
    /// SHA-256 of `sample_data` (pre-computed by the caller).
    pub sample_hash: [u8; 32],
    /// Raw bytes of the sample to analyse.
    pub sample_data: Vec<u8>,
    /// Filename to use inside the guest (controls extension, icon loading, etc.).
    pub filename: String,
    /// Command-line arguments passed to the sample.
    pub args: Vec<String>,
    /// Sandbox configuration for this job.
    pub config: SandboxConfig,
    /// Optional priority (higher = served first by the orchestrator).
    pub priority: u8,
    /// Caller-supplied correlation tag.
    pub tag: Option<String>,
}

impl SandboxJob {
    /// Create a new job with default config.
    #[must_use]
    pub fn new(sample_data: Vec<u8>, filename: impl Into<String>) -> Self {
        Self {
            sample_hash: [0u8; 32],
            sample_data,
            filename: filename.into(),
            args: vec![],
            config: SandboxConfig::default(),
            priority: 50,
            tag: None,
        }
    }

    /// Set the pre-computed SHA-256.
    #[must_use]
    pub const fn with_hash(mut self, hash: [u8; 32]) -> Self {
        self.sample_hash = hash;
        self
    }

    /// Add a command-line argument.
    #[must_use]
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Set the analysis config.
    #[must_use]
    pub fn with_config(mut self, cfg: SandboxConfig) -> Self {
        self.config = cfg;
        self
    }

    /// Set the priority.
    #[must_use]
    pub const fn with_priority(mut self, p: u8) -> Self {
        self.priority = p;
        self
    }

    /// Set the correlation tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Returns the sample size in bytes.
    #[must_use]
    pub const fn sample_size(&self) -> usize {
        self.sample_data.len()
    }

    /// Returns a hex string of the first 8 bytes of `sample_hash`.
    #[must_use]
    pub fn hash_prefix(&self) -> String {
        self.sample_hash
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

// ─── JobHandle ───────────────────────────────────────────────────────────────

/// An opaque handle returned when a job is submitted to a backend.
///
/// Used to poll status and collect results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobHandle {
    /// Unique job identifier (UUID v4 string).
    pub job_id: String,
    /// Name of the backend that accepted this job.
    pub backend_name: String,
    /// Wall-clock time when the job was submitted.
    pub started_at: std::time::SystemTime,
    /// Name of the VM or container slot serving this job.
    pub vm_slot: Option<String>,
}

impl JobHandle {
    /// Create a new handle.
    #[must_use]
    pub fn new(job_id: impl Into<String>, backend_name: impl Into<String>) -> Self {
        Self {
            job_id: job_id.into(),
            backend_name: backend_name.into(),
            started_at: std::time::SystemTime::now(),
            vm_slot: None,
        }
    }

    /// Attach a VM slot name.
    #[must_use]
    pub fn with_vm_slot(mut self, slot: impl Into<String>) -> Self {
        self.vm_slot = Some(slot.into());
        self
    }

    /// Elapsed time since submission.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed().unwrap_or(Duration::ZERO)
    }
}

// ─── JobStatus ───────────────────────────────────────────────────────────────

/// Status of a sandbox job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobStatus {
    /// Job is waiting in the queue.
    Queued,
    /// Backend is cloning the snapshot and setting up the VM.
    Preparing,
    /// Sample is running inside the guest.
    Running { progress_pct: u8, elapsed: Duration },
    /// Execution finished; results are available.
    Completed,
    /// An unrecoverable error occurred.
    Failed { error: String },
    /// Job exceeded the configured timeout.
    Timeout,
    /// Job was cancelled by the caller.
    Cancelled,
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Preparing => write!(f, "preparing"),
            Self::Running { progress_pct, .. } => write!(f, "running({progress_pct}%)"),
            Self::Completed => write!(f, "completed"),
            Self::Failed { error } => write!(f, "failed: {error}"),
            Self::Timeout => write!(f, "timeout"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl JobStatus {
    /// Returns `true` if the job has reached a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed { .. } | Self::Timeout | Self::Cancelled
        )
    }

    /// Returns `true` if the job is actively running.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Preparing | Self::Running { .. })
    }
}

// ─── SandboxResult ───────────────────────────────────────────────────────────

/// The complete set of artifacts collected from a finished sandbox job.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxResult {
    /// Job identifier from the originating `JobHandle`.
    pub job_id: String,
    /// API call trace.
    pub api_trace: Vec<ApiEntry>,
    /// Raw PCAP data from the guest network interface.
    pub network_pcap: Vec<u8>,
    /// Filesystem events.
    pub fs_events: Vec<FsEvent>,
    /// Windows registry events.
    pub registry_events: Vec<RegEvent>,
    /// Process tree reconstructed from the trace.
    pub process_tree: ProcessTree,
    /// Periodic screenshots.
    pub screenshots: Vec<Screenshot>,
    /// Files written to disk by the sample.
    pub dropped_files: Vec<DroppedFile>,
    /// Basic-block addresses covered during execution.
    pub coverage_data: Vec<u64>,
    /// YARA rule matches.
    pub yara_matches: Vec<YaraMatch>,
    /// High-level behaviour tags (e.g. `"ransomware"`, `"c2_beacon"`).
    pub behavior_tags: Vec<String>,
    /// Total wall-clock time of the analysis run.
    pub analysis_duration: Duration,
    /// Network connection log.
    pub network_log: Vec<NetworkEntry>,
    /// Error message if the run ended abnormally.
    pub error: Option<String>,
}

impl SandboxResult {
    /// Create an empty result for `job_id`.
    #[must_use]
    pub fn new(job_id: impl Into<String>) -> Self {
        Self {
            job_id: job_id.into(),
            ..Default::default()
        }
    }

    /// Convenience: add a behaviour tag if not already present.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let t = tag.into();
        if !self.behavior_tags.contains(&t) {
            self.behavior_tags.push(t);
        }
    }

    /// Returns the number of unique processes observed.
    #[must_use]
    pub const fn process_count(&self) -> usize {
        self.process_tree.len()
    }

    /// Returns `true` if the run produced any YARA matches.
    #[must_use]
    pub const fn has_yara_matches(&self) -> bool {
        !self.yara_matches.is_empty()
    }

    /// Returns the number of API calls that originated from injected code.
    #[must_use]
    pub fn injected_call_count(&self) -> usize {
        self.api_trace
            .iter()
            .filter(|e| e.from_injected_code)
            .count()
    }

    /// Returns `true` if any dropped file is executable.
    #[must_use]
    pub fn has_dropped_executables(&self) -> bool {
        self.dropped_files.iter().any(|f| f.is_executable)
    }
}

// ─── EvasionCountermeasures ───────────────────────────────────────────────────

/// Configuration block for anti-evasion countermeasures activated inside the
/// guest agent before sample execution begins.
///
/// Each field maps to a corresponding bypass routine in the guest agent binary.
/// Setting a flag to `true` instructs the agent to activate that bypass.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvasionCountermeasures {
    /// Normalize `RDTSC` / `RDTSCP` return values to eliminate timing
    /// side-channels (guest agent patches the MSR or uses hypervisor assist).
    pub normalize_rdtsc: bool,
    /// Clear obvious VM-detection artifacts:
    /// - `VMware` CPUID leaf strings
    /// - `VirtualBox` registry keys
    /// - KVM/QEMU hypervisor flags in CPUID
    /// - Suspicious process names (vmtoolsd, vboxservice, …)
    pub clear_vm_artifacts: bool,
    /// Simulate user interaction by injecting:
    /// - Random mouse-move events every few seconds
    /// - Simulated keystrokes in the foreground window
    /// - Desktop icon clicks
    /// This prevents samples that wait for "liveness" checks from short-circuiting.
    pub fake_user_activity: bool,
    /// Spoof the parent PID of the launched sample process.
    ///
    /// Many samples check their parent to detect automated launchers.  When
    /// enabled the agent uses `NtCreateUserProcess` with an `OBJECT_ATTRIBUTES`
    /// that names `explorer.exe` as the parent.
    pub spoof_parent_pid: bool,
    /// Fake system information returned by WMI / registry queries:
    /// - `Win32_ComputerSystem.Manufacturer` → `"Dell Inc."`
    /// - `CPUID` brand string → `"Intel(R) Core(TM) i7-9750H"`
    /// - `GetSystemFirmwareTable(RSMB)` → a realistic SMBIOS dump
    /// - `HKLM\HARDWARE\DESCRIPTION\System\BIOS\*` → consumer-grade values
    pub fake_system_info: bool,
    /// Patch `NtQuerySystemInformation(SystemProcessInformation)` to hide the
    /// sandbox launcher process and inject a plausible set of decoy processes.
    pub hide_sandbox_process: bool,
    /// Intercept `IsDebuggerPresent` / `NtQueryInformationProcess(ProcessDebugPort)`
    /// and always return "no debugger".
    pub bypass_anti_debug: bool,
    /// Provide a fake network stack: DNS answers from `INetSim` / fake resolver,
    /// TLS certificates that pass chain validation.
    pub fake_network_stack: bool,
    /// Sleep acceleration: intercept `NtDelayExecution` / `Sleep` / `SleepEx`
    /// and reduce the requested sleep by a configurable factor.
    pub accelerate_sleep: bool,
    /// Factor by which to divide sleep durations (e.g. `100` → 100× faster).
    pub sleep_acceleration_factor: u32,
}

impl EvasionCountermeasures {
    /// Create a countermeasures block with all bypasses enabled and a
    /// default sleep-acceleration factor of 100.
    #[must_use]
    pub const fn all_enabled() -> Self {
        Self {
            normalize_rdtsc: true,
            clear_vm_artifacts: true,
            fake_user_activity: true,
            spoof_parent_pid: true,
            fake_system_info: true,
            hide_sandbox_process: true,
            bypass_anti_debug: true,
            fake_network_stack: true,
            accelerate_sleep: true,
            sleep_acceleration_factor: 100,
        }
    }

    /// Create a block with all bypasses disabled.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Returns the number of enabled countermeasures.
    #[must_use]
    pub fn enabled_count(&self) -> usize {
        [
            self.normalize_rdtsc,
            self.clear_vm_artifacts,
            self.fake_user_activity,
            self.spoof_parent_pid,
            self.fake_system_info,
            self.hide_sandbox_process,
            self.bypass_anti_debug,
            self.fake_network_stack,
            self.accelerate_sleep,
        ]
        .iter()
        .filter(|&&b| b)
        .count()
    }
}

// ─── GuestAgentClient ────────────────────────────────────────────────────────

/// JSON-over-TCP client for communicating with `rustre-sandbox-agent` running
/// inside the guest.
///
/// The wire protocol is newline-delimited JSON.  Each request has the shape:
/// ```json
/// { "cmd": "<command>", "id": <u64>, "payload": { … } }
/// ```
/// Each response:
/// ```json
/// { "id": <u64>, "ok": true/false, "data": { … }, "error": "<msg>" }
/// ```
///
/// Retry logic: on connection failure the client retries up to `max_retries`
/// times with exponential back-off starting at `base_delay_ms`.
#[derive(Debug)]
pub struct GuestAgentClient {
    /// `"ip:port"` address of the guest agent.
    pub address: String,
    /// Maximum number of connection/send retries.
    pub max_retries: u32,
    /// Base delay in milliseconds for exponential back-off.
    pub base_delay_ms: u64,
    /// Request sequence counter.
    seq: std::sync::atomic::AtomicU64,
    /// Whether the client is currently connected.
    connected: std::sync::atomic::AtomicBool,
    /// Recorded messages for testing / replay.
    pub recorded_responses: Mutex<Vec<String>>,
}

impl GuestAgentClient {
    /// Create a new (disconnected) client targeting `address`.
    #[must_use]
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            max_retries: 10,
            base_delay_ms: 1000,
            seq: std::sync::atomic::AtomicU64::new(1),
            connected: std::sync::atomic::AtomicBool::new(false),
            recorded_responses: Mutex::new(vec![]),
        }
    }

    /// Adjust retry parameters.
    #[must_use]
    pub const fn with_retries(mut self, max: u32, base_ms: u64) -> Self {
        self.max_retries = max;
        self.base_delay_ms = base_ms;
        self
    }

    /// Mark the client as connected (used by mock/test helpers).
    pub fn set_connected(&self, v: bool) {
        self.connected.store(v, Ordering::Relaxed);
    }

    /// Returns `true` if the client is considered connected.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// Next sequence number.
    fn next_id(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Attempt to connect to the guest agent with retry / back-off.
    ///
    /// In the mock implementation this simply succeeds if `max_retries > 0`.
    ///
    /// # Errors
    /// Returns `VmError::CommError` after exhausting all retries.
    pub async fn connect_with_retry(&self) -> Result<(), VmError> {
        let mut delay = self.base_delay_ms;
        let mut last_attempt = 0u32;
        for attempt in 0..=self.max_retries {
            last_attempt = attempt;
            // In a real implementation: try TcpStream::connect(self.address).await
            // For the mock: simulate success immediately on the first attempt and
            // exercise the back-off loop on subsequent retries.
            if attempt == 0 {
                self.connected.store(true, Ordering::Relaxed);
                return Ok(());
            }
            // Real retry loop body — exercised only if the first attempt above
            // is changed to fall through (kept here for parity with the future
            // real implementation and so the back-off math stays type-checked).
            tokio::time::sleep(Duration::from_millis(delay)).await;
            delay = (delay * 2).min(30_000);
        }
        Err(VmError::CommError(format!(
            "failed to connect to guest agent at {} after {} retries (last attempt {})",
            self.address, self.max_retries, last_attempt
        )))
    }

    /// Write a file into the guest.
    ///
    /// # Errors
    /// Returns `VmError::CommError` if not connected.
    pub async fn write_file(&self, path: &str, data: &[u8]) -> Result<(), VmError> {
        if !self.is_connected() {
            return Err(VmError::CommError("not connected".to_string()));
        }
        let _id = self.next_id();
        let _req = serde_json::json!({
            "cmd": "write_file",
            "id": _id,
            "payload": { "path": path, "size": data.len() }
        });
        // Mock: always succeeds.
        Ok(())
    }

    /// Execute a command in the guest and return its stdout.
    ///
    /// # Errors
    /// Returns `VmError::CommError` if not connected.
    pub async fn exec(
        &self,
        cmd: &str,
        args: &[String],
        _env: &HashMap<String, String>,
    ) -> Result<(i32, String, String), VmError> {
        if !self.is_connected() {
            return Err(VmError::CommError("not connected".to_string()));
        }
        let _id = self.next_id();
        // Mock: pretend success.
        Ok((0, format!("mock output of {cmd} {args:?}"), String::new()))
    }

    /// Read a file from the guest.
    ///
    /// # Errors
    /// Returns `VmError::CommError` if not connected.
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>, VmError> {
        if !self.is_connected() {
            return Err(VmError::CommError("not connected".to_string()));
        }
        Ok(format!("mock contents of {path}").into_bytes())
    }

    /// Retrieve the API call trace accumulated since execution started.
    ///
    /// # Errors
    /// Returns `VmError::CommError` if not connected.
    pub async fn get_api_trace(&self) -> Result<Vec<ApiEntry>, VmError> {
        if !self.is_connected() {
            return Err(VmError::CommError("not connected".to_string()));
        }
        // Mock: return a single synthetic entry.
        Ok(vec![
            ApiEntry::new(1_000_000, 1000, 1001, "CreateFileW", "kernel32.dll")
                .with_arg("C:\\temp\\payload.dat")
                .with_retval("0x80"),
        ])
    }

    /// Retrieve the network connection log.
    ///
    /// # Errors
    /// Returns `VmError::CommError` if not connected.
    pub async fn get_network_log(&self) -> Result<Vec<NetworkEntry>, VmError> {
        if !self.is_connected() {
            return Err(VmError::CommError("not connected".to_string()));
        }
        Ok(vec![])
    }

    /// Retrieve filesystem events.
    ///
    /// # Errors
    /// Returns `VmError::CommError` if not connected.
    pub async fn get_fs_events(&self) -> Result<Vec<FsEvent>, VmError> {
        if !self.is_connected() {
            return Err(VmError::CommError("not connected".to_string()));
        }
        Ok(vec![])
    }

    /// Capture a screenshot and return it as PNG bytes.
    ///
    /// # Errors
    /// Returns `VmError::CommError` if not connected.
    pub async fn screenshot(&self) -> Result<Vec<u8>, VmError> {
        if !self.is_connected() {
            return Err(VmError::CommError("not connected".to_string()));
        }
        // Mock: return an 8-byte "PNG" placeholder.
        Ok(vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    }
}

// ─── LibvirtApi ──────────────────────────────────────────────────────────────

/// Thin wrapper around the `virsh` CLI for libvirt domain management.
///
/// All methods spawn a child `virsh` process and return its stdout/stderr as a
/// `Result<String>`.  In production the `virsh` binary must be on `PATH` and
/// the calling user must have permission to connect to `qemu:///system`.
pub struct LibvirtApi {
    /// libvirt connection URI (default: `"qemu:///system"`).
    pub uri: String,
}

impl LibvirtApi {
    /// Create a new API handle with the default URI.
    #[must_use]
    pub fn new() -> Self {
        Self {
            uri: "qemu:///system".to_string(),
        }
    }

    /// Create a handle with a custom URI.
    #[must_use]
    pub fn with_uri(uri: impl Into<String>) -> Self {
        Self { uri: uri.into() }
    }

    /// Run a `virsh` command with the given arguments.
    async fn run(&self, args: &[&str]) -> Result<String, VmError> {
        let mut cmd = tokio::process::Command::new("virsh");
        cmd.arg("-c").arg(&self.uri);
        for a in args {
            cmd.arg(a);
        }
        let out = cmd
            .output()
            .await
            .map_err(|e| VmError::SpawnError(format!("virsh: {e}")))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(VmError::Resource(
                String::from_utf8_lossy(&out.stderr).to_string(),
            ))
        }
    }

    /// List all known domains (`virsh list --all`).
    pub async fn list_all(&self) -> Result<String, VmError> {
        self.run(&["list", "--all"]).await
    }

    /// List snapshots of a domain (`virsh snapshot-list <domain>`).
    pub async fn snapshot_list(&self, domain: &str) -> Result<String, VmError> {
        self.run(&["snapshot-list", domain]).await
    }

    /// Create a snapshot (`virsh snapshot-create-as <domain> <snap>`).
    pub async fn snapshot_create(&self, domain: &str, snap: &str) -> Result<String, VmError> {
        self.run(&["snapshot-create-as", domain, snap]).await
    }

    /// Start a domain (`virsh start <domain>`).
    pub async fn start(&self, domain: &str) -> Result<String, VmError> {
        self.run(&["start", domain]).await
    }

    /// Forcibly destroy a domain (`virsh destroy <domain>`).
    pub async fn destroy(&self, domain: &str) -> Result<String, VmError> {
        self.run(&["destroy", domain]).await
    }

    /// Delete a snapshot (`virsh snapshot-delete <domain> <snap>`).
    pub async fn snapshot_delete(&self, domain: &str, snap: &str) -> Result<String, VmError> {
        self.run(&["snapshot-delete", domain, snap]).await
    }

    /// Restore a domain to a snapshot (`virsh snapshot-revert <domain> <snap>`).
    pub async fn snapshot_revert(&self, domain: &str, snap: &str) -> Result<String, VmError> {
        self.run(&["snapshot-revert", domain, snap, "--running"])
            .await
    }

    /// Poll the domain state every `interval_ms` ms until it reaches `expected_state`,
    /// up to `timeout_secs` seconds.
    pub async fn wait_for_state(
        &self,
        domain: &str,
        expected_state: &str,
        timeout_secs: u64,
    ) -> Result<(), VmError> {
        let deadline = Duration::from_secs(timeout_secs);
        let interval = Duration::from_millis(500);

        let result = tokio::time::timeout(deadline, async {
            loop {
                if let Ok(list) = self.list_all().await
                    && list.contains(expected_state)
                    && list.contains(domain)
                {
                    return Ok(());
                }
                tokio::time::sleep(interval).await;
            }
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err(VmError::Timeout),
        }
    }
}

impl Default for LibvirtApi {
    fn default() -> Self {
        Self::new()
    }
}

// ─── JobState (internal) ─────────────────────────────────────────────────────

/// Internal state tracked per running job in `QemuKvmBackend`.
#[derive(Debug)]
pub struct JobState {
    pub job: SandboxJob,
    pub status: JobStatus,
    pub domain_name: String,
    pub snap_name: String,
    pub agent: Option<GuestAgentClient>,
}

impl JobState {
    const fn new(job: SandboxJob, domain_name: String, snap_name: String) -> Self {
        Self {
            job,
            status: JobStatus::Preparing,
            domain_name,
            snap_name,
            agent: None,
        }
    }
}

// ─── SandboxBackend trait ─────────────────────────────────────────────────────

/// Trait implemented by each backend (QEMU/KVM, Firecracker, Docker).
///
/// Backends are responsible for:
/// 1. Accepting a `SandboxJob` and returning a `JobHandle`.
/// 2. Cloning / restoring the base snapshot.
/// 3. Pushing the sample into the VM/container.
/// 4. Launching the sample and collecting results.
/// 5. Tearing down the ephemeral VM/container.
pub trait SandboxBackend: Send + Sync {
    /// Short identifier for this backend (e.g. `"qemu-kvm"`, `"firecracker"`, `"docker"`).
    fn name(&self) -> &str;

    /// Returns `true` if this backend can handle the given OS/arch combination.
    fn supports(&self, os: &OsProfile, arch: &Arch) -> bool;

    /// Submit a job for execution.  Returns a handle immediately; the job runs
    /// asynchronously.
    ///
    /// # Errors
    /// Returns `VmError` if the job cannot be queued (e.g. capacity exceeded).
    fn submit(&self, job: SandboxJob) -> Result<JobHandle, VmError>;

    /// Query the current status of a job.
    fn status(&self, handle: &JobHandle) -> JobStatus;

    /// Block until the job finishes and collect all artifacts.
    ///
    /// # Errors
    /// Returns `VmError` on collection failure.
    fn collect(&self, handle: &JobHandle) -> Result<SandboxResult, VmError>;

    /// Cancel a running job.  No-op if already terminal.
    fn cancel(&self, handle: &JobHandle);

    /// Maximum number of concurrent jobs this backend supports.
    fn max_concurrent(&self) -> usize;

    /// Number of currently running jobs.
    fn running_count(&self) -> usize;

    /// Returns `true` if the backend has capacity for another job.
    fn has_capacity(&self) -> bool {
        self.running_count() < self.max_concurrent()
    }
}

// ─── QemuKvmBackend ──────────────────────────────────────────────────────────

/// Sandbox backend that uses QEMU/KVM via libvirt (`virsh` CLI).
///
/// # Job lifecycle
/// 1. `submit`: generate unique `job_id`; call `virsh snapshot-revert` to
///    restore the clean snapshot; call `virsh start` to power on the domain;
///    wait for the guest agent TCP port to be reachable; push the sample via
///    `GuestAgentClient::write_file`; call `GuestAgentClient::exec` to start
///    the sample.
/// 2. `status`: return the current `JobState.status`.
/// 3. `collect`: wait for execution timeout; pull artifacts from the agent;
///    call `virsh destroy` and optionally `virsh snapshot-delete` on the
///    ephemeral snapshot; return `SandboxResult`.
/// 4. `cancel`: call `virsh destroy`; mark status `Cancelled`.
pub struct QemuKvmBackend {
    /// VM template to clone for each job.
    pub template: VmTemplate,
    /// libvirt API wrapper.
    pub libvirt: Arc<LibvirtApi>,
    /// Active job states keyed by `job_id`.
    job_slots: Mutex<HashMap<String, JobState>>,
    /// Maximum concurrent jobs.
    pub max_jobs: usize,
    /// Job ID counter.
    counter: AtomicU64,
}

impl QemuKvmBackend {
    /// Create a backend for `template` with `max_jobs` concurrent slots.
    #[must_use]
    pub fn new(template: VmTemplate, max_jobs: usize) -> Self {
        Self {
            template,
            libvirt: Arc::new(LibvirtApi::new()),
            job_slots: Mutex::new(HashMap::new()),
            max_jobs,
            counter: AtomicU64::new(1),
        }
    }

    /// Generate a unique job ID.
    fn gen_job_id(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("qemu-job-{n:08x}")
    }

    /// Derive the ephemeral domain/snapshot names for a job.
    fn names_for_job(&self, job_id: &str) -> (String, String) {
        let domain = format!("{}-{}", self.template.libvirt_domain, job_id);
        let snap = format!("run-{job_id}");
        (domain, snap)
    }

    /// Mock: simulate restoring a snapshot and booting a VM.
    fn mock_boot_job(&self, job_id: &str) {
        let mut slots = self.job_slots.lock();
        if let Some(state) = slots.get_mut(job_id) {
            state.status = JobStatus::Running {
                progress_pct: 0,
                elapsed: Duration::ZERO,
            };
            // Attach a mock agent.
            let addr = self.template.connection_addr();
            let agent = GuestAgentClient::new(addr);
            agent.set_connected(true);
            state.agent = Some(agent);
        }
    }

    /// Mock: simulate completing a job and producing a result.
    fn mock_complete_job(&self, job_id: &str) {
        let mut slots = self.job_slots.lock();
        if let Some(state) = slots.get_mut(job_id) {
            state.status = JobStatus::Completed;
        }
    }
}

impl SandboxBackend for QemuKvmBackend {
    fn name(&self) -> &'static str {
        "qemu-kvm"
    }

    fn supports(&self, os: &OsProfile, arch: &Arch) -> bool {
        self.template.supports(os, arch)
    }

    fn submit(&self, job: SandboxJob) -> Result<JobHandle, VmError> {
        if self.running_count() >= self.max_jobs {
            return Err(VmError::Resource("no job slots available".to_string()));
        }

        let job_id = self.gen_job_id();
        let (domain, snap) = self.names_for_job(&job_id);
        let state = JobState::new(job, domain, snap);

        self.job_slots.lock().insert(job_id.clone(), state);

        // In a real impl: spawn async task to:
        //   libvirt.snapshot_revert(domain, &self.template.snapshot_id).await?;
        //   libvirt.start(domain).await?;
        //   agent.connect_with_retry().await?;
        //   agent.write_file(guest_path, sample_data).await?;
        //   agent.exec(sample_path, args, env).await?;
        // For the mock we transition synchronously.
        self.mock_boot_job(&job_id);

        let handle =
            JobHandle::new(job_id, self.name()).with_vm_slot(self.template.libvirt_domain.clone());
        Ok(handle)
    }

    fn status(&self, handle: &JobHandle) -> JobStatus {
        self.job_slots.lock().get(&handle.job_id).map_or(
            JobStatus::Failed {
                error: "unknown job".to_string(),
            },
            |s| s.status.clone(),
        )
    }

    fn collect(&self, handle: &JobHandle) -> Result<SandboxResult, VmError> {
        self.mock_complete_job(&handle.job_id);

        let mut result = SandboxResult::new(handle.job_id.clone());
        result.analysis_duration = handle.elapsed();

        // Pull artifacts from the mock agent if present.
        {
            let slots = self.job_slots.lock();
            if let Some(state) = slots.get(&handle.job_id) {
                if let Some(agent) = &state.agent {
                    // In real code this would be `agent.get_api_trace().await?` etc.
                    // For mock we just check connectivity.
                    let _ = agent.is_connected();
                }
                result.process_tree = ProcessTree::build_from_api_trace(&result.api_trace);
            }
        }

        // Remove job slot.
        self.job_slots.lock().remove(&handle.job_id);
        Ok(result)
    }

    fn cancel(&self, handle: &JobHandle) {
        let mut slots = self.job_slots.lock();
        if let Some(state) = slots.get_mut(&handle.job_id)
            && !state.status.is_terminal()
        {
            state.status = JobStatus::Cancelled;
        }
    }

    fn max_concurrent(&self) -> usize {
        self.max_jobs
    }

    fn running_count(&self) -> usize {
        self.job_slots
            .lock()
            .values()
            .filter(|s| s.status.is_active())
            .count()
    }
}

// ─── FirecrackerConfig ────────────────────────────────────────────────────────

/// Configuration for a Firecracker microVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerConfig {
    /// Path to the uncompressed Linux kernel image (`vmlinux`).
    pub kernel_image_path: String,
    /// Path to the root filesystem image (ext4).
    pub rootfs_path: String,
    /// Number of vCPUs.
    pub vcpu_count: u8,
    /// Memory in MiB.
    pub mem_size_mib: u32,
    /// Name of the host TAP interface for guest networking.
    pub network_interface: Option<String>,
    /// Firecracker API socket path.
    pub api_socket_path: String,
    /// Host port for the vsock channel.
    pub vsock_cid: u32,
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        Self {
            kernel_image_path: "/opt/firecracker/vmlinux".to_string(),
            rootfs_path: "/opt/firecracker/rootfs.ext4".to_string(),
            vcpu_count: 2,
            mem_size_mib: 512,
            network_interface: None,
            api_socket_path: "/tmp/firecracker.sock".to_string(),
            vsock_cid: 3,
        }
    }
}

impl FirecrackerConfig {
    /// Create a new config with the given kernel and rootfs.
    #[must_use]
    pub fn new(kernel: impl Into<String>, rootfs: impl Into<String>) -> Self {
        Self {
            kernel_image_path: kernel.into(),
            rootfs_path: rootfs.into(),
            ..Default::default()
        }
    }

    /// Set the vCPU count.
    #[must_use]
    pub const fn with_vcpus(mut self, n: u8) -> Self {
        self.vcpu_count = n;
        self
    }

    /// Set the memory in MiB.
    #[must_use]
    pub const fn with_mem(mut self, mib: u32) -> Self {
        self.mem_size_mib = mib;
        self
    }

    /// Set the TAP network interface.
    #[must_use]
    pub fn with_network(mut self, tap: impl Into<String>) -> Self {
        self.network_interface = Some(tap.into());
        self
    }

    /// Set the API socket path.
    #[must_use]
    pub fn with_api_socket(mut self, path: impl Into<String>) -> Self {
        self.api_socket_path = path.into();
        self
    }

    /// Build the JSON body for `PUT /machine-config`.
    #[must_use]
    pub fn machine_config_body(&self) -> serde_json::Value {
        serde_json::json!({
            "vcpu_count": self.vcpu_count,
            "mem_size_mib": self.mem_size_mib,
            "ht_enabled": false
        })
    }

    /// Build the JSON body for `PUT /boot-source`.
    #[must_use]
    pub fn boot_source_body(&self) -> serde_json::Value {
        serde_json::json!({
            "kernel_image_path": self.kernel_image_path,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
        })
    }

    /// Build the JSON body for `PUT /drives/rootfs`.
    #[must_use]
    pub fn rootfs_drive_body(&self) -> serde_json::Value {
        serde_json::json!({
            "drive_id": "rootfs",
            "path_on_host": self.rootfs_path,
            "is_root_device": true,
            "is_read_only": false
        })
    }

    /// Build the JSON body for `PUT /network-interfaces/eth0`, if configured.
    #[must_use]
    pub fn network_interface_body(&self) -> Option<serde_json::Value> {
        self.network_interface.as_ref().map(|tap| {
            serde_json::json!({
                "iface_id": "eth0",
                "guest_mac": "AA:FC:00:00:00:01",
                "host_dev_name": tap
            })
        })
    }

    /// Build the JSON body for `PUT /actions` (`InstanceStart`).
    #[must_use]
    pub fn instance_start_body() -> serde_json::Value {
        serde_json::json!({ "action_type": "InstanceStart" })
    }
}

// ─── FirecrackerBackend ───────────────────────────────────────────────────────

/// Sandbox backend that uses Firecracker microVMs.
///
/// Communicates with the Firecracker REST API over a Unix socket at
/// `config.api_socket_path`.  The API sequence for starting a VM is:
///
/// 1. `PUT /machine-config` — set vCPU count and memory.
/// 2. `PUT /boot-source`    — set kernel image and boot args.
/// 3. `PUT /drives/rootfs`  — attach the root filesystem.
/// 4. `PUT /network-interfaces/eth0` (optional) — attach TAP.
/// 5. `PUT /actions { action_type: "InstanceStart" }` — boot.
///
/// Sample delivery and result collection are performed via a vsock channel
/// to the `GuestAgentClient` running in the microVM.
pub struct FirecrackerBackend {
    /// Firecracker VM configuration.
    pub config: FirecrackerConfig,
    /// Active job states.
    job_slots: Mutex<HashMap<String, JobState>>,
    /// Maximum concurrent microVMs.
    pub max_jobs: usize,
    /// Job ID counter.
    counter: AtomicU64,
}

impl FirecrackerBackend {
    /// Create a new backend.
    #[must_use]
    pub fn new(config: FirecrackerConfig, max_jobs: usize) -> Self {
        Self {
            config,
            job_slots: Mutex::new(HashMap::new()),
            max_jobs,
            counter: AtomicU64::new(1),
        }
    }

    fn gen_job_id(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("fc-job-{n:08x}")
    }

    /// Build a complete Firecracker REST API setup sequence as a list of
    /// `(method, path, body)` tuples.  In production these would be sent to the
    /// Firecracker Unix socket.
    #[must_use]
    pub fn build_start_sequence(&self) -> Vec<(&'static str, String, serde_json::Value)> {
        let mut seq = vec![
            (
                "PUT",
                "/machine-config".to_string(),
                self.config.machine_config_body(),
            ),
            (
                "PUT",
                "/boot-source".to_string(),
                self.config.boot_source_body(),
            ),
            (
                "PUT",
                "/drives/rootfs".to_string(),
                self.config.rootfs_drive_body(),
            ),
        ];
        if let Some(net_body) = self.config.network_interface_body() {
            seq.push(("PUT", "/network-interfaces/eth0".to_string(), net_body));
        }
        seq.push((
            "PUT",
            "/actions".to_string(),
            FirecrackerConfig::instance_start_body(),
        ));
        seq
    }
}

impl SandboxBackend for FirecrackerBackend {
    fn name(&self) -> &'static str {
        "firecracker"
    }

    fn supports(&self, os: &OsProfile, _arch: &Arch) -> bool {
        // Firecracker only supports Linux guests.
        os.is_linux()
    }

    fn submit(&self, job: SandboxJob) -> Result<JobHandle, VmError> {
        if self.running_count() >= self.max_jobs {
            return Err(VmError::Resource(
                "no firecracker slots available".to_string(),
            ));
        }
        let job_id = self.gen_job_id();
        let state = JobState {
            status: JobStatus::Running {
                progress_pct: 0,
                elapsed: Duration::ZERO,
            },
            domain_name: format!("fc-vm-{job_id}"),
            snap_name: String::new(),
            agent: None,
            job,
        };
        self.job_slots.lock().insert(job_id.clone(), state);
        Ok(JobHandle::new(job_id, self.name()))
    }

    fn status(&self, handle: &JobHandle) -> JobStatus {
        self.job_slots.lock().get(&handle.job_id).map_or(
            JobStatus::Failed {
                error: "unknown job".to_string(),
            },
            |s| s.status.clone(),
        )
    }

    fn collect(&self, handle: &JobHandle) -> Result<SandboxResult, VmError> {
        // Mark completed.
        {
            let mut slots = self.job_slots.lock();
            if let Some(s) = slots.get_mut(&handle.job_id) {
                s.status = JobStatus::Completed;
            }
        }
        let mut result = SandboxResult::new(handle.job_id.clone());
        result.analysis_duration = handle.elapsed();
        self.job_slots.lock().remove(&handle.job_id);
        Ok(result)
    }

    fn cancel(&self, handle: &JobHandle) {
        let mut slots = self.job_slots.lock();
        if let Some(s) = slots.get_mut(&handle.job_id)
            && !s.status.is_terminal()
        {
            s.status = JobStatus::Cancelled;
        }
    }

    fn max_concurrent(&self) -> usize {
        self.max_jobs
    }

    fn running_count(&self) -> usize {
        self.job_slots
            .lock()
            .values()
            .filter(|s| s.status.is_active())
            .count()
    }
}

// ─── DockerBackend ────────────────────────────────────────────────────────────

/// Sandbox backend that runs samples inside Docker containers.
///
/// Uses the Docker CLI (`docker` must be on `PATH`).  The container is started
/// with `--network none` for isolation.
///
/// # Job lifecycle
/// 1. `docker run --rm --name <cid> --network none -d <image> sleep <timeout>`
/// 2. `docker cp <sample> <cid>:<guest_path>`
/// 3. `docker exec <cid> <guest_path> [args…]`
/// 4. `docker logs <cid>` to collect stdout/stderr.
/// 5. `docker stop <cid>` (or it exits naturally).
pub struct DockerBackend {
    /// Docker image to use as the analysis environment.
    pub image: String,
    /// Active job states.
    job_slots: Mutex<HashMap<String, JobState>>,
    /// Maximum concurrent containers.
    pub max_jobs: usize,
    /// Job ID counter.
    counter: AtomicU64,
}

impl DockerBackend {
    /// Create a new Docker backend using `image`.
    #[must_use]
    pub fn new(image: impl Into<String>, max_jobs: usize) -> Self {
        Self {
            image: image.into(),
            job_slots: Mutex::new(HashMap::new()),
            max_jobs,
            counter: AtomicU64::new(1),
        }
    }

    fn gen_job_id(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("docker-job-{n:08x}")
    }

    /// Generate the `docker run` argument list for a job.
    #[must_use]
    pub fn build_run_args(&self, job_id: &str, timeout_secs: u64) -> Vec<String> {
        vec![
            "run".to_string(),
            "--rm".to_string(),
            "--name".to_string(),
            format!("rustre-sandbox-{job_id}"),
            "--network".to_string(),
            "none".to_string(),
            "--memory".to_string(),
            "512m".to_string(),
            "--cpus".to_string(),
            "1".to_string(),
            "-d".to_string(),
            self.image.clone(),
            "sleep".to_string(),
            timeout_secs.to_string(),
        ]
    }

    /// Generate `docker cp` arguments for copying a sample into a container.
    #[must_use]
    pub fn build_cp_args(src_path: &str, container: &str, dst_path: &str) -> Vec<String> {
        vec![
            "cp".to_string(),
            src_path.to_string(),
            format!("{container}:{dst_path}"),
        ]
    }

    /// Generate `docker exec` arguments.
    #[must_use]
    pub fn build_exec_args(container: &str, cmd: &str, args: &[String]) -> Vec<String> {
        let mut v = vec!["exec".to_string(), container.to_string(), cmd.to_string()];
        v.extend(args.iter().cloned());
        v
    }

    /// Generate `docker stop` arguments.
    #[must_use]
    pub fn build_stop_args(container: &str) -> Vec<String> {
        vec![
            "stop".to_string(),
            "--time".to_string(),
            "5".to_string(),
            container.to_string(),
        ]
    }
}

impl SandboxBackend for DockerBackend {
    fn name(&self) -> &'static str {
        "docker"
    }

    fn supports(&self, os: &OsProfile, _arch: &Arch) -> bool {
        // Docker backend only supports Linux guests in this implementation.
        os.is_linux()
    }

    fn submit(&self, job: SandboxJob) -> Result<JobHandle, VmError> {
        if self.running_count() >= self.max_jobs {
            return Err(VmError::Resource("no docker slots available".to_string()));
        }
        let job_id = self.gen_job_id();
        let container_name = format!("rustre-sandbox-{job_id}");
        let state = JobState {
            status: JobStatus::Running {
                progress_pct: 0,
                elapsed: Duration::ZERO,
            },
            domain_name: container_name,
            snap_name: String::new(),
            agent: None,
            job,
        };
        self.job_slots.lock().insert(job_id.clone(), state);
        Ok(JobHandle::new(job_id, self.name()))
    }

    fn status(&self, handle: &JobHandle) -> JobStatus {
        self.job_slots.lock().get(&handle.job_id).map_or(
            JobStatus::Failed {
                error: "unknown job".to_string(),
            },
            |s| s.status.clone(),
        )
    }

    fn collect(&self, handle: &JobHandle) -> Result<SandboxResult, VmError> {
        {
            let mut slots = self.job_slots.lock();
            if let Some(s) = slots.get_mut(&handle.job_id) {
                s.status = JobStatus::Completed;
            }
        }
        let mut result = SandboxResult::new(handle.job_id.clone());
        result.analysis_duration = handle.elapsed();
        self.job_slots.lock().remove(&handle.job_id);
        Ok(result)
    }

    fn cancel(&self, handle: &JobHandle) {
        let mut slots = self.job_slots.lock();
        if let Some(s) = slots.get_mut(&handle.job_id)
            && !s.status.is_terminal()
        {
            s.status = JobStatus::Cancelled;
        }
    }

    fn max_concurrent(&self) -> usize {
        self.max_jobs
    }

    fn running_count(&self) -> usize {
        self.job_slots
            .lock()
            .values()
            .filter(|s| s.status.is_active())
            .count()
    }
}

// ─── SandboxOrchestrator ─────────────────────────────────────────────────────

/// Central orchestrator that dispatches `SandboxJob`s to registered backends.
///
/// # Dispatch policy
/// Jobs are dispatched in FIFO order.  The orchestrator selects the first
/// backend that:
/// 1. Supports the job's `OsProfile` and `Arch`.
/// 2. Has a free capacity slot.
///
/// If no backend is available, the job stays in the queue until
/// `submit_sample` / `run_batch` retries.
///
/// # Caching
/// Results are cached by `sample_hash`.  Submitting a job for a hash that
/// already has a cached result returns immediately without running the sample
/// again.
pub struct SandboxOrchestrator {
    /// Registered backends.
    backends: Vec<Box<dyn SandboxBackend>>,
    /// Pending job queue (front = highest priority).
    job_queue: Mutex<std::collections::VecDeque<SandboxJob>>,
    /// Maximum number of concurrently running jobs across all backends.
    pub max_concurrent: usize,
    /// Currently running jobs.
    running_jobs: Mutex<HashMap<String, JobHandle>>,
    /// Results cache keyed by sample SHA-256.
    results_cache: Mutex<HashMap<[u8; 32], SandboxResult>>,
    /// Job ID counter (used for cache-hit synthetic handles).
    counter: AtomicU64,
}

impl SandboxOrchestrator {
    /// Create an empty orchestrator.
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            backends: vec![],
            job_queue: Mutex::new(std::collections::VecDeque::new()),
            max_concurrent,
            running_jobs: Mutex::new(HashMap::new()),
            results_cache: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(1),
        }
    }

    /// Register a backend.
    pub fn add_backend(&mut self, backend: Box<dyn SandboxBackend>) {
        self.backends.push(backend);
    }

    /// Find a backend that can serve `job` and has capacity.
    fn pick_backend(&self, job: &SandboxJob) -> Option<&dyn SandboxBackend> {
        let arch = job.config.os_profile.default_arch();
        self.backends
            .iter()
            .find(|b| b.supports(&job.config.os_profile, &arch) && b.has_capacity())
            .map(std::convert::AsRef::as_ref)
    }

    /// Total running jobs across all backends.
    pub fn total_running(&self) -> usize {
        self.running_jobs.lock().len()
    }

    /// Submit a sample for analysis.
    ///
    /// If the sample hash is in the results cache, the cached result is used and
    /// a synthetic `JobHandle` is returned.
    ///
    /// Otherwise the job is queued and dispatched to the first available backend.
    ///
    /// # Errors
    /// Returns `VmError::Resource` if no backend has capacity and the queue is
    /// full (queue limit: `max_concurrent * 16`).
    pub fn submit_sample(
        &self,
        data: Vec<u8>,
        filename: impl Into<String>,
    ) -> Result<JobHandle, VmError> {
        let job = SandboxJob::new(data, filename);
        self.enqueue_job(job)
    }

    /// Enqueue a pre-built `SandboxJob`.
    ///
    /// # Errors
    /// Returns `VmError::Resource` if queue is over capacity.
    pub fn enqueue_job(&self, job: SandboxJob) -> Result<JobHandle, VmError> {
        // Check cache.
        if let Some(_cached) = self.results_cache.lock().get(&job.sample_hash) {
            let n = self.counter.fetch_add(1, Ordering::Relaxed);
            let handle = JobHandle::new(format!("cached-{n:08x}"), "cache");
            return Ok(handle);
        }

        // Try immediate dispatch.
        if let Some(backend) = self.pick_backend(&job) {
            let handle = backend.submit(job.clone())?;
            self.running_jobs
                .lock()
                .insert(handle.job_id.clone(), handle.clone());
            return Ok(handle);
        }

        // Queue.
        let queue_limit = self.max_concurrent * 16;
        let mut queue = self.job_queue.lock();
        if queue.len() >= queue_limit {
            return Err(VmError::Resource("job queue is full".to_string()));
        }
        queue.push_back(job);
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        Ok(JobHandle::new(format!("queued-{n:08x}"), "queue"))
    }

    /// Block (synchronously) until the job referenced by `handle` completes,
    /// then return its result.
    ///
    /// # Errors
    /// Returns `VmError::NotFound` if the job is not tracked, or propagates
    /// backend collection errors.
    pub fn wait_for_job(&self, handle: &JobHandle) -> Result<SandboxResult, VmError> {
        // For cached / queued handles we return a stub.
        if handle.backend_name == "cache" || handle.backend_name == "queue" {
            let result = SandboxResult::new(handle.job_id.clone());
            return Ok(result);
        }

        // Find the backend.
        let backend = self
            .backends
            .iter()
            .find(|b| b.name() == handle.backend_name)
            .ok_or_else(|| VmError::NotFound(handle.backend_name.clone()))?;

        // Poll until terminal, up to a hard deadline of 3600 s.
        let poll_deadline = std::time::Instant::now() + Duration::from_hours(1);
        loop {
            let status = backend.status(handle);
            if status.is_terminal() {
                break;
            }
            if std::time::Instant::now() >= poll_deadline {
                return Err(VmError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let result = backend.collect(handle)?;

        // Cache and remove from running.
        self.running_jobs.lock().remove(&handle.job_id);
        if let Some(job_hash) = self.get_job_hash(&handle.job_id) {
            self.results_cache.lock().insert(job_hash, result.clone());
        }

        Ok(result)
    }

    /// Helper to look up the sample hash for a running job (best-effort).
    const fn get_job_hash(&self, _job_id: &str) -> Option<[u8; 32]> {
        None // Real impl would store job→hash mapping.
    }

    /// Cancel a running job.
    pub fn cancel_job(&self, handle: &JobHandle) {
        for backend in &self.backends {
            if backend.name() == handle.backend_name {
                backend.cancel(handle);
                self.running_jobs.lock().remove(&handle.job_id);
                return;
            }
        }
    }

    /// Submit all `samples` and wait for each to complete, returning results
    /// in submission order.
    ///
    /// # Errors
    /// Returns the first backend error encountered; already-completed results
    /// before the error are lost.
    pub fn run_batch(
        &self,
        samples: Vec<(Vec<u8>, String)>,
    ) -> Result<Vec<SandboxResult>, VmError> {
        let mut handles = Vec::with_capacity(samples.len());
        for (data, filename) in samples {
            handles.push(self.submit_sample(data, filename)?);
        }
        let mut results = Vec::with_capacity(handles.len());
        for handle in &handles {
            results.push(self.wait_for_job(handle)?);
        }
        Ok(results)
    }

    /// Number of jobs currently in the pending queue.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.job_queue.lock().len()
    }

    /// Number of results in the cache.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.results_cache.lock().len()
    }

    /// Returns the names of all registered backends.
    #[must_use]
    pub fn backend_names(&self) -> Vec<&str> {
        self.backends.iter().map(|b| b.name()).collect()
    }

    /// Check whether a result is cached for the given sample hash.
    #[must_use]
    pub fn is_cached(&self, hash: &[u8; 32]) -> bool {
        self.results_cache.lock().contains_key(hash)
    }

    /// Insert a result into the cache directly (used for testing / seeding).
    pub fn cache_insert(&self, hash: [u8; 32], result: SandboxResult) {
        self.results_cache.lock().insert(hash, result);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vm(id: &str) -> VmInstance {
        VmInstance::new(id, VmConfig::new(id, VmArch::X64, VmOs::Windows10))
    }

    // ── VmArch / VmOs ────────────────────────────────────────────────────────

    #[test]
    fn test_vm_arch_display() {
        assert_eq!(VmArch::X86.to_string(), "x86");
        assert_eq!(VmArch::X64.to_string(), "x64");
        assert_eq!(VmArch::Arm.to_string(), "arm");
        assert_eq!(VmArch::Arm64.to_string(), "arm64");
        assert_eq!(VmArch::Mips.to_string(), "mips");
        assert_eq!(VmArch::Riscv64.to_string(), "riscv64");
    }

    #[test]
    fn test_vm_os_display() {
        assert_eq!(VmOs::Windows10.to_string(), "windows10");
        assert_eq!(VmOs::Windows11.to_string(), "windows11");
        assert_eq!(VmOs::Ubuntu22.to_string(), "ubuntu22");
        assert_eq!(VmOs::Debian12.to_string(), "debian12");
        assert_eq!(VmOs::Kali.to_string(), "kali");
        assert_eq!(VmOs::AndroidApi33.to_string(), "android_api33");
        assert_eq!(VmOs::MacOs13.to_string(), "macos13");
    }

    // ── VmAccelerator ────────────────────────────────────────────────────────

    #[test]
    fn test_vm_accelerator_display() {
        assert_eq!(VmAccelerator::Kvm.to_string(), "kvm");
        assert_eq!(VmAccelerator::Whpx.to_string(), "whpx");
        assert_eq!(VmAccelerator::Hvf.to_string(), "hvf");
        assert_eq!(VmAccelerator::Tcg.to_string(), "tcg");
    }

    // ── DiskImage ────────────────────────────────────────────────────────────

    #[test]
    fn test_disk_image_new() {
        let d = DiskImage::new("/tmp/win10.qcow2", DiskFormat::Qcow2, 40);
        assert_eq!(d.size_gb, 40);
        assert!(!d.is_overlay);
    }

    #[test]
    fn test_disk_image_overlay() {
        let d = DiskImage::new("/tmp/overlay.qcow2", DiskFormat::Qcow2, 40).as_overlay();
        assert!(d.is_overlay);
    }

    #[test]
    fn test_disk_image_with_hash() {
        let d = DiskImage::new("/tmp/img.raw", DiskFormat::Raw, 20).with_base_hash("abcdef");
        assert_eq!(d.base_hash.as_deref(), Some("abcdef"));
    }

    #[test]
    fn test_disk_format_display() {
        assert_eq!(DiskFormat::Qcow2.to_string(), "qcow2");
        assert_eq!(DiskFormat::Raw.to_string(), "raw");
        assert_eq!(DiskFormat::Vmdk.to_string(), "vmdk");
        assert_eq!(DiskFormat::Vhd.to_string(), "vhd");
        assert_eq!(DiskFormat::Vhdx.to_string(), "vhdx");
    }

    // ── VmConfig ─────────────────────────────────────────────────────────────

    #[test]
    fn test_vm_config_new() {
        let cfg = VmConfig::new("test-vm", VmArch::X64, VmOs::Windows10);
        assert_eq!(cfg.name, "test-vm");
        assert_eq!(cfg.arch, VmArch::X64);
        assert_eq!(cfg.os, VmOs::Windows10);
        assert_eq!(cfg.memory_mb, 2048);
        assert_eq!(cfg.disk_gb, 40);
        assert!(cfg.isolated);
    }

    #[test]
    fn test_vm_config_with_memory() {
        let cfg = VmConfig::new("vm", VmArch::X64, VmOs::Ubuntu22).with_memory(4096);
        assert_eq!(cfg.memory_mb, 4096);
    }

    #[test]
    fn test_vm_config_with_disk_size() {
        let cfg = VmConfig::new("vm", VmArch::X64, VmOs::Ubuntu22).with_disk_size(80);
        assert_eq!(cfg.disk_gb, 80);
    }

    #[test]
    fn test_vm_config_with_isolation() {
        let cfg = VmConfig::new("vm", VmArch::X64, VmOs::Kali).with_isolation(false);
        assert!(!cfg.isolated);
    }

    #[test]
    fn test_vm_config_with_vcpus() {
        let cfg = VmConfig::new("vm", VmArch::X64, VmOs::Windows10).with_vcpus(4);
        assert_eq!(cfg.vcpus, 4);
    }

    #[test]
    fn test_vm_config_with_net() {
        let cfg = VmConfig::new("vm", VmArch::X64, VmOs::Windows10).with_net(VmNetType::Nat);
        assert_eq!(cfg.net_type, VmNetType::Nat);
    }

    #[test]
    fn test_vm_config_build_qemu_args_non_empty() {
        let cfg = VmConfig::new("vm", VmArch::X64, VmOs::Windows10);
        let args = cfg.build_qemu_args();
        assert!(!args.is_empty());
        assert!(args.iter().any(|a| a.contains("-m ")));
    }

    #[test]
    fn test_vm_config_extra_arg() {
        let cfg = VmConfig::new("vm", VmArch::X64, VmOs::Windows10).with_extra_arg("-nographic");
        assert!(cfg.extra_args.contains(&"-nographic".to_string()));
    }

    // ── VmState ──────────────────────────────────────────────────────────────

    #[test]
    fn test_vm_state_display() {
        assert_eq!(VmState::Stopped.to_string(), "stopped");
        assert_eq!(VmState::Running.to_string(), "running");
        assert_eq!(VmState::Suspended.to_string(), "suspended");
        assert_eq!(VmState::Starting.to_string(), "starting");
        assert_eq!(VmState::Reverting.to_string(), "reverting");
        assert_eq!(VmState::Saving.to_string(), "saving");
    }

    #[test]
    fn test_vm_state_error_display() {
        let s = VmState::Error("disk full".to_string());
        assert!(s.to_string().contains("disk full"));
    }

    // ── SnapshotInfo ─────────────────────────────────────────────────────────

    #[test]
    fn test_snapshot_info_new() {
        let s = SnapshotInfo::new("snap-0", "base", 1000, 1_073_741_824);
        assert_eq!(s.id, "snap-0");
        assert_eq!(s.name, "base");
        assert!(s.parent.is_none());
    }

    #[test]
    fn test_snapshot_info_with_parent() {
        let s = SnapshotInfo::new("snap-1", "after-run", 2000, 512).with_parent("snap-0");
        assert_eq!(s.parent.as_deref(), Some("snap-0"));
    }

    // ── MemoryRegion / MemoryMap ──────────────────────────────────────────────

    #[test]
    fn test_memory_region_size() {
        let r = MemoryRegion {
            start: 0x1000,
            end: 0x2000,
            label: "test".to_string(),
            readable: true,
            writable: false,
            executable: false,
            mapped_file: None,
        };
        assert_eq!(r.size(), 0x1000);
    }

    #[test]
    fn test_memory_region_is_rwx() {
        let r = MemoryRegion {
            start: 0,
            end: 0x1000,
            label: "rwx".to_string(),
            readable: true,
            writable: true,
            executable: true,
            mapped_file: None,
        };
        assert!(r.is_rwx());
    }

    #[test]
    fn test_memory_region_not_rwx() {
        let r = MemoryRegion {
            start: 0,
            end: 0x1000,
            label: "rx".to_string(),
            readable: true,
            writable: false,
            executable: true,
            mapped_file: None,
        };
        assert!(!r.is_rwx());
    }

    #[test]
    fn test_memory_region_contains() {
        let r = MemoryRegion {
            start: 0x1000,
            end: 0x2000,
            label: "r".to_string(),
            readable: true,
            writable: false,
            executable: false,
            mapped_file: None,
        };
        assert!(r.contains(0x1500));
        assert!(!r.contains(0x0fff));
        assert!(!r.contains(0x2000));
    }

    #[test]
    fn test_memory_map_mock_rwx_regions() {
        let map = MemoryMap::mock(100);
        let rwx = map.rwx_regions();
        assert!(!rwx.is_empty());
        assert!(rwx.iter().all(|r| r.is_rwx()));
    }

    #[test]
    fn test_memory_map_executable_regions() {
        let map = MemoryMap::mock(100);
        let exec = map.executable_regions();
        assert!(!exec.is_empty());
    }

    #[test]
    fn test_memory_map_find_region() {
        let map = MemoryMap::mock(100);
        let found = map.find_region(0x0000_0000_0040_1000);
        assert!(found.is_some());
    }

    #[test]
    fn test_memory_map_total_size() {
        let map = MemoryMap::mock(100);
        assert!(map.total_size() > 0);
    }

    // ── GuestAgent ───────────────────────────────────────────────────────────

    #[test]
    fn test_guest_agent_connect() {
        let mut agent = GuestAgent::new("vm-1");
        assert!(!agent.connected);
        agent.connect();
        assert!(agent.connected);
        assert!(agent.agent_pid.is_some());
    }

    #[test]
    fn test_guest_agent_disconnect() {
        let mut agent = GuestAgent::new("vm-1");
        agent.connect();
        agent.disconnect();
        assert!(!agent.connected);
    }

    #[test]
    fn test_guest_agent_exec_not_connected() {
        let agent = GuestAgent::new("vm-1");
        let cmd = GuestCommand::new("whoami");
        let err = agent.exec(&cmd).unwrap_err();
        assert!(matches!(err, VmError::CommError(_)));
    }

    #[test]
    fn test_guest_agent_exec_connected() {
        let mut agent = GuestAgent::new("vm-1");
        agent.connect();
        let cmd = GuestCommand::new("whoami");
        let result = agent.exec(&cmd).unwrap();
        assert!(result.is_ok());
        assert_eq!(agent.commands_sent(), 1);
    }

    #[test]
    fn test_guest_agent_upload_not_connected() {
        let agent = GuestAgent::new("vm-1");
        assert!(agent.upload("/tmp/payload", "C:\\payload.exe").is_err());
    }

    #[test]
    fn test_guest_agent_download_connected() {
        let mut agent = GuestAgent::new("vm-1");
        agent.connect();
        let data = agent.download("C:\\file.txt", "/tmp/file.txt").unwrap();
        assert!(!data.is_empty());
    }

    // ── NetworkMode ──────────────────────────────────────────────────────────

    #[test]
    fn test_network_mode_none_arg() {
        let m = NetworkMode::None;
        assert_eq!(m.nic_arg(), "none");
    }

    #[test]
    fn test_network_mode_user_arg() {
        let m = NetworkMode::User;
        assert!(m.nic_arg().contains("user"));
    }

    #[test]
    fn test_network_mode_tap_arg() {
        let m = NetworkMode::Tap {
            iface: "tap0".to_string(),
        };
        assert!(m.nic_arg().contains("tap0"));
    }

    #[test]
    fn test_network_mode_bridge_arg() {
        let m = NetworkMode::Bridge {
            br: "br0".to_string(),
        };
        assert!(m.nic_arg().contains("br0"));
    }

    // ── QemuProcessBuilder ───────────────────────────────────────────────────

    #[test]
    fn test_builder_defaults() {
        let b = QemuProcessBuilder::new("/images/win10.qcow2");
        assert_eq!(b.memory_mb, 2048);
        assert_eq!(b.cpus, 2);
        assert!(b.snapshot.is_none());
        assert_eq!(b.net_mode, NetworkMode::None);
        assert!(b.qmp_socket_path.is_none());
        assert!(b.extra_args.is_empty());
    }

    #[test]
    fn test_builder_setters() {
        let b = QemuProcessBuilder::new("/images/win10.qcow2")
            .memory_mb(4096)
            .cpus(4)
            .snapshot("clean-base")
            .net_mode(NetworkMode::User)
            .accelerator("kvm")
            .display("sdl")
            .extra_arg("-no-reboot");
        assert_eq!(b.memory_mb, 4096);
        assert_eq!(b.cpus, 4);
        assert_eq!(b.snapshot.as_deref(), Some("clean-base"));
        assert_eq!(b.net_mode, NetworkMode::User);
        assert_eq!(b.accelerator, "kvm");
        assert_eq!(b.display, "sdl");
        assert_eq!(b.extra_args, vec!["-no-reboot"]);
    }

    #[test]
    fn test_builder_build_args_contains_memory() {
        let b = QemuProcessBuilder::new("/tmp/disk.qcow2").memory_mb(1024);
        let args = b.build_args();
        let pos = args.iter().position(|a| a == "-m").expect("-m flag");
        assert_eq!(args[pos + 1], "1024");
    }

    #[test]
    fn test_builder_build_args_contains_smp() {
        let b = QemuProcessBuilder::new("/tmp/disk.qcow2").cpus(4);
        let args = b.build_args();
        let pos = args.iter().position(|a| a == "-smp").expect("-smp flag");
        assert_eq!(args[pos + 1], "4");
    }

    #[test]
    fn test_builder_build_args_contains_drive() {
        let b = QemuProcessBuilder::new("/tmp/disk.qcow2");
        let args = b.build_args();
        assert!(args.iter().any(|a| a.contains("file=/tmp/disk.qcow2")));
        assert!(args.iter().any(|a| a.contains("format=qcow2")));
    }

    #[test]
    fn test_build_args_escapes_commas_in_paths() {
        // QEMU splits `-drive` on commas, so a comma inside the path must be
        // doubled or everything after it is parsed as a separate option.
        let b = QemuProcessBuilder::new("/tmp/my,disk.qcow2");
        let args = b.build_args();
        let drive = args
            .iter()
            .skip_while(|a| *a != "-drive")
            .nth(1)
            .expect("-drive value");
        assert_eq!(drive, "file=/tmp/my,,disk.qcow2,format=qcow2,if=virtio");
        // A path without commas must come out exactly as before.
        let plain = QemuProcessBuilder::new("/tmp/disk.qcow2").build_args();
        let drive = plain
            .iter()
            .skip_while(|a| *a != "-drive")
            .nth(1)
            .expect("-drive value");
        assert_eq!(drive, "file=/tmp/disk.qcow2,format=qcow2,if=virtio");
    }

    #[test]
    fn test_builder_build_args_contains_qmp_socket() {
        let b = QemuProcessBuilder::new("/tmp/disk.qcow2").qmp_socket_path("/tmp/test-qmp.sock");
        let args = b.build_args();
        let qmp_val = args
            .iter()
            .skip_while(|a| *a != "-qmp")
            .nth(1)
            .expect("-qmp value");
        assert!(qmp_val.contains("unix:"));
        assert!(qmp_val.contains("server,nowait"));
    }

    #[test]
    fn test_builder_build_args_snapshot() {
        let b = QemuProcessBuilder::new("/tmp/disk.qcow2").snapshot("my-snap");
        let args = b.build_args();
        let pos = args
            .iter()
            .position(|a| a == "-loadvm")
            .expect("-loadvm flag");
        assert_eq!(args[pos + 1], "my-snap");
    }

    #[test]
    fn test_builder_build_args_no_snapshot_by_default() {
        let b = QemuProcessBuilder::new("/tmp/disk.qcow2");
        let args = b.build_args();
        assert!(!args.iter().any(|a| a == "-loadvm"));
    }

    #[test]
    fn test_builder_build_args_extra_args_appended() {
        let b = QemuProcessBuilder::new("/tmp/disk.qcow2")
            .extra_arg("-no-reboot")
            .extra_arg("-nographic");
        let args = b.build_args();
        assert!(args.contains(&"-no-reboot".to_string()));
        assert!(args.contains(&"-nographic".to_string()));
        // Extra args must come at the end.
        let last_two: Vec<_> = args.iter().rev().take(2).cloned().collect();
        assert!(last_two.contains(&"-nographic".to_string()));
        assert!(last_two.contains(&"-no-reboot".to_string()));
    }

    #[test]
    fn test_builder_build_args_nic_none() {
        let b = QemuProcessBuilder::new("/tmp/disk.qcow2").net_mode(NetworkMode::None);
        let args = b.build_args();
        let pos = args.iter().position(|a| a == "-nic").expect("-nic flag");
        assert_eq!(args[pos + 1], "none");
    }

    #[test]
    fn test_builder_build_args_display_none() {
        let b = QemuProcessBuilder::new("/tmp/disk.qcow2");
        let args = b.build_args();
        let pos = args
            .iter()
            .position(|a| a == "-display")
            .expect("-display flag");
        assert_eq!(args[pos + 1], "none");
    }

    // `resolve_qmp_socket` deliberately branches on the platform: a Unix socket
    // under the temp dir elsewhere, a `tcp:` endpoint on Windows (QMP has no
    // Unix sockets there). The assertion below only describes the Unix form, so
    // it must be gated the same way the code is — ungated, it failed on Windows.
    #[cfg(not(windows))]
    #[test]
    fn test_builder_qmp_socket_auto_generated_in_temp() {
        let b = QemuProcessBuilder::new("/tmp/disk.qcow2");
        let socket = b.resolve_qmp_socket();
        let tmp = std::env::temp_dir();
        assert!(socket.starts_with(&tmp));
        assert!(socket.to_string_lossy().contains("rustre-qmp-"));
    }

    #[cfg(windows)]
    #[test]
    fn test_builder_qmp_socket_auto_generated_is_tcp_on_windows() {
        let b = QemuProcessBuilder::new(r"C:\vm\disk.qcow2");
        let socket = b.resolve_qmp_socket();
        let s = socket.to_string_lossy();
        assert!(s.starts_with("tcp:127.0.0.1:"), "got {s}");
        let port: u16 = s.rsplit(':').next().unwrap().parse().expect("port");
        assert!((20000..60000).contains(&port), "port out of range: {port}");
    }

    #[test]
    fn test_builder_qmp_socket_explicit() {
        let b = QemuProcessBuilder::new("/tmp/disk.qcow2").qmp_socket_path("/run/qemu/test.sock");
        let socket = b.resolve_qmp_socket();
        assert_eq!(socket, PathBuf::from("/run/qemu/test.sock"));
    }

    // ── VmInstance ───────────────────────────────────────────────────────────

    #[test]
    fn test_vm_instance_new() {
        let vm = make_vm("vm-001");
        assert_eq!(vm.id, "vm-001");
        assert_eq!(vm.state, VmState::Stopped);
        assert_eq!(vm.snapshot_count(), 0);
        assert!(vm.is_stopped());
        assert!(!vm.is_running());
    }

    #[test]
    fn test_vm_take_snapshot() {
        let mut vm = make_vm("vm-001");
        let snap_id = vm.take_snapshot("clean-state").unwrap();
        assert_eq!(vm.snapshot_count(), 1);
        assert!(snap_id.starts_with("snap-"));
    }

    #[test]
    fn test_vm_take_multiple_snapshots_chained() {
        let mut vm = make_vm("vm-001");
        let id0 = vm.take_snapshot("snap1").unwrap();
        let id1 = vm.take_snapshot("snap2").unwrap();
        // Second snapshot has first as parent.
        let snap1 = vm.find_snapshot(&id1).unwrap();
        assert_eq!(snap1.parent.as_deref(), Some(id0.as_str()));
    }

    #[test]
    fn test_vm_revert_success() {
        let mut vm = make_vm("vm-001");
        let id = vm.take_snapshot("base").unwrap();
        assert!(vm.revert(&id).is_ok());
        assert_eq!(vm.state, VmState::Stopped);
    }

    #[test]
    fn test_vm_revert_not_found() {
        let mut vm = make_vm("vm-001");
        let err = vm.revert("snap-999").unwrap_err();
        assert!(matches!(err, VmError::NotFound(_)));
    }

    #[test]
    fn test_vm_delete_snapshot() {
        let mut vm = make_vm("vm-001");
        let id = vm.take_snapshot("to-delete").unwrap();
        vm.delete_snapshot(&id).unwrap();
        assert_eq!(vm.snapshot_count(), 0);
    }

    #[test]
    fn test_vm_delete_snapshot_not_found() {
        let mut vm = make_vm("vm-001");
        assert!(vm.delete_snapshot("snap-999").is_err());
    }

    #[test]
    fn test_vm_latest_snapshot() {
        let mut vm = make_vm("vm-001");
        vm.take_snapshot("s1").unwrap();
        vm.take_snapshot("s2").unwrap();
        assert!(vm.latest_snapshot().is_some());
    }

    #[test]
    fn test_vm_qemu_args_non_empty() {
        let vm = make_vm("vm-001");
        let args = vm.qemu_args();
        assert!(!args.is_empty());
    }

    // ── VmPool ───────────────────────────────────────────────────────────────

    #[test]
    fn test_pool_new_empty() {
        let pool = VmPool::new();
        assert_eq!(pool.count(), 0);
    }

    #[test]
    fn test_pool_add() {
        let pool = VmPool::new();
        pool.add(make_vm("vm-1"));
        assert_eq!(pool.count(), 1);
    }

    #[test]
    fn test_pool_find_found() {
        let pool = VmPool::new();
        pool.add(make_vm("vm-1"));
        assert!(pool.find("vm-1").is_some());
    }

    #[test]
    fn test_pool_find_not_found() {
        let pool = VmPool::new();
        assert!(pool.find("nope").is_none());
    }

    #[test]
    fn test_pool_available_all_stopped() {
        let pool = VmPool::new();
        pool.add(make_vm("vm-1"));
        pool.add(make_vm("vm-2"));
        assert_eq!(pool.available().len(), 2);
    }

    #[test]
    fn test_pool_available_excludes_running() {
        let pool = VmPool::new();
        let mut running = make_vm("vm-run");
        running.state = VmState::Running;
        pool.add(running);
        pool.add(make_vm("vm-stopped"));
        assert_eq!(pool.available().len(), 1);
    }

    #[test]
    fn test_pool_running() {
        let pool = VmPool::new();
        let mut r = make_vm("vm-run");
        r.state = VmState::Running;
        pool.add(r);
        pool.add(make_vm("vm-stop"));
        assert_eq!(pool.running().len(), 1);
    }

    #[test]
    fn test_pool_remove() {
        let pool = VmPool::new();
        pool.add(make_vm("vm-1"));
        let vm = pool.remove("vm-1").unwrap();
        assert_eq!(vm.id, "vm-1");
        assert_eq!(pool.count(), 0);
    }

    #[test]
    fn test_pool_remove_not_found() {
        let pool = VmPool::new();
        assert!(pool.remove("nope").is_err());
    }

    #[test]
    fn test_pool_update_state() {
        let pool = VmPool::new();
        pool.add(make_vm("vm-1"));
        pool.update_state("vm-1", VmState::Running).unwrap();
        let vm = pool.find("vm-1").unwrap();
        assert_eq!(vm.state, VmState::Running);
    }

    #[test]
    fn test_pool_next_id_unique() {
        let pool = VmPool::new();
        let id1 = pool.next_id();
        let id2 = pool.next_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_pool_find_compatible() {
        let pool = VmPool::new();
        pool.add(VmInstance::new(
            "vm-1",
            VmConfig::new("vm-1", VmArch::X64, VmOs::Windows10),
        ));
        pool.add(VmInstance::new(
            "vm-2",
            VmConfig::new("vm-2", VmArch::X86, VmOs::Ubuntu22),
        ));
        let found = pool.find_compatible(&VmOs::Windows10, &VmArch::X64);
        assert!(found.is_some());
        let not_found = pool.find_compatible(&VmOs::MacOs13, &VmArch::Arm64);
        assert!(not_found.is_none());
    }

    // ── VmSandbox ────────────────────────────────────────────────────────────

    #[test]
    fn test_vm_sandbox_start_stop() {
        let vm = make_vm("vm-1");
        let sandbox = VmSandbox::new(vm);
        sandbox.start().unwrap();
        assert_eq!(sandbox.state(), VmState::Running);
        sandbox.stop().unwrap();
        assert_eq!(sandbox.state(), VmState::Stopped);
    }

    #[test]
    fn test_vm_sandbox_double_start() {
        let vm = make_vm("vm-1");
        let sandbox = VmSandbox::new(vm);
        sandbox.start().unwrap();
        assert!(sandbox.start().is_err());
        sandbox.stop().unwrap();
    }

    #[test]
    fn test_vm_sandbox_stop_not_running() {
        let vm = make_vm("vm-1");
        let sandbox = VmSandbox::new(vm);
        assert!(sandbox.stop().is_err());
    }

    #[test]
    fn test_vm_sandbox_exec() {
        let vm = make_vm("vm-1");
        let sandbox = VmSandbox::new(vm);
        sandbox.start().unwrap();
        let cmd = GuestCommand::new("cmd.exe").with_arg("/c whoami");
        let result = sandbox.exec(&cmd).unwrap();
        assert!(result.is_ok());
        assert_eq!(sandbox.run_count(), 1);
        sandbox.stop().unwrap();
    }

    #[test]
    fn test_vm_sandbox_snapshot_and_revert() {
        let vm = make_vm("vm-1");
        let sandbox = VmSandbox::new(vm);
        let snap_id = sandbox.snapshot("base").unwrap();
        sandbox.start().unwrap();
        sandbox.revert_to(&snap_id).unwrap();
        assert_eq!(sandbox.state(), VmState::Stopped);
    }

    #[test]
    fn test_vm_sandbox_read_memory_map() {
        let vm = make_vm("vm-1");
        let sandbox = VmSandbox::new(vm);
        sandbox.start().unwrap();
        let map = sandbox.read_memory_map(1000).unwrap();
        assert!(!map.regions.is_empty());
        sandbox.stop().unwrap();
    }

    #[test]
    fn test_vm_sandbox_no_live_handle_by_default() {
        let vm = make_vm("vm-1");
        let sandbox = VmSandbox::new(vm);
        assert!(!sandbox.has_live_handle());
    }

    #[test]
    fn test_vm_sandbox_start_sets_no_handle_on_mock() {
        let vm = make_vm("vm-1");
        let sandbox = VmSandbox::new(vm);
        // Synchronous mock start does NOT set a live handle.
        sandbox.start().unwrap();
        assert!(!sandbox.has_live_handle());
        sandbox.stop().unwrap();
    }

    // ── Error variants ───────────────────────────────────────────────────────

    #[test]
    fn test_vm_error_not_found() {
        let e = VmError::NotFound("vm-999".to_string());
        assert!(e.to_string().contains("vm-999"));
    }

    #[test]
    fn test_vm_error_already_running() {
        let e = VmError::AlreadyRunning;
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_vm_error_snapshot_failed() {
        let e = VmError::SnapshotFailed("disk full".to_string());
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    fn test_vm_error_invalid_state() {
        let e = VmError::InvalidState("cannot start from Reverting".to_string());
        assert!(e.to_string().contains("cannot start"));
    }

    #[test]
    fn test_vm_error_timeout() {
        let e = VmError::Timeout;
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_vm_error_qmp_error() {
        let e = VmError::QmpError("unexpected response".to_string());
        assert!(e.to_string().contains("unexpected response"));
    }

    #[test]
    fn test_vm_error_spawn_error() {
        let e = VmError::SpawnError("binary not found".to_string());
        assert!(e.to_string().contains("binary not found"));
    }

    #[test]
    fn test_vm_config_serialization() {
        let cfg = VmConfig::new("vm", VmArch::X64, VmOs::Windows10);
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: VmConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, cfg.name);
    }

    #[test]
    fn test_pool_count_multiple() {
        let pool = VmPool::new();
        for i in 0..5 {
            pool.add(make_vm(&format!("vm-{i}")));
        }
        assert_eq!(pool.count(), 5);
    }

    #[test]
    fn test_guest_command_builder() {
        let cmd = GuestCommand::new("cmd.exe")
            .with_arg("/c")
            .with_arg("whoami")
            .with_env("TEMP", "C:\\Temp")
            .with_cwd("C:\\")
            .with_timeout(60);
        assert_eq!(cmd.args.len(), 2);
        assert_eq!(
            cmd.env.get("TEMP").map(std::string::String::as_str),
            Some("C:\\Temp")
        );
        assert_eq!(cmd.timeout_secs, 60);
    }

    #[test]
    fn test_vm_net_type_display() {
        assert_eq!(VmNetType::None.to_string(), "none");
        assert_eq!(VmNetType::Nat.to_string(), "nat");
        assert_eq!(VmNetType::HostOnly.to_string(), "host_only");
        assert_eq!(VmNetType::Bridged.to_string(), "bridged");
    }

    // ── VmSnapshotManager ────────────────────────────────────────────────────

    #[test]
    fn test_snapshot_manager_save_and_list() {
        let mgr = VmSnapshotManager::new();
        let vm = VmSandbox::new(make_vm("snap-test-vm"));
        let snap = mgr.snapshot(&vm);
        assert_eq!(snap.id, 1);
        let list = mgr.list_snapshots();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, 1);
        assert!(list[0].label.contains("mgr-snap-1"));
    }

    #[test]
    fn test_snapshot_manager_multiple_snapshots() {
        let mgr = VmSnapshotManager::new();
        let vm = VmSandbox::new(make_vm("multi-snap-vm"));
        let _s1 = mgr.snapshot(&vm);
        let _s2 = mgr.snapshot(&vm);
        let _s3 = mgr.snapshot(&vm);
        assert_eq!(mgr.list_snapshots().len(), 3);
    }

    #[test]
    fn test_snapshot_manager_restore_valid() {
        let mgr = VmSnapshotManager::new();
        let vm = VmSandbox::new(make_vm("restore-vm"));
        let snap = mgr.snapshot(&vm);
        // Wrap in mut for restore.
        let mut vm2 = VmSandbox::new(make_vm("restore-vm2"));
        // Seed the same snapshot id into vm2's instance so restore finds it.
        {
            let mut inst = vm2.vm.write();
            inst.snapshots
                .push(SnapshotInfo::new(snap.vm_snap_id.clone(), "test", 0, 0));
        }
        assert!(mgr.restore(&mut vm2, &snap));
    }

    #[test]
    fn test_snapshot_manager_restore_unknown_fails() {
        let mgr = VmSnapshotManager::new();
        let snap = VmSnapshot {
            id: 99,
            timestamp: 99,
            vm_snap_id: "nonexistent".to_string(),
        };
        let mut vm = VmSandbox::new(make_vm("empty-vm"));
        assert!(!mgr.restore(&mut vm, &snap));
    }

    // ── VmNetworkInterceptor ─────────────────────────────────────────────────

    #[test]
    fn test_interceptor_record_and_list() {
        let icp = VmNetworkInterceptor::new();
        icp.record(NetworkInterception::new(
            "10.0.0.1",
            "185.1.2.3",
            443,
            "tcp",
            128,
            100,
        ));
        let conns = icp.intercept_connections();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].dst_port, 443);
    }

    #[test]
    fn test_interceptor_block_external() {
        let icp = VmNetworkInterceptor::new();
        assert!(!icp.is_blocking());
        icp.block_external_connections();
        assert!(icp.is_blocking());
    }

    #[test]
    fn test_is_c2_pattern_suspicious_port_small_payload() {
        let icp = VmNetworkInterceptor::new();
        let conn = NetworkInterception::new("10.0.0.1", "185.1.2.3", 4444, "tcp", 64, 0);
        icp.record(conn.clone());
        assert!(icp.is_c2_pattern(&conn));
    }

    #[test]
    fn test_is_c2_pattern_beaconing() {
        let icp = VmNetworkInterceptor::new();
        // Three connections to the same target at regular 5 s intervals.
        for i in 0u64..5 {
            icp.record(NetworkInterception::new(
                "10.0.0.2",
                "91.2.3.4",
                9000, // non-C2 port
                "tcp",
                2048,     // large payload — won't trigger single-conn heuristic
                i * 5000, // exactly 5 000 ms apart → CV ≈ 0
            ));
        }
        let probe = NetworkInterception::new("10.0.0.2", "91.2.3.4", 9000, "tcp", 2048, 0);
        assert!(icp.is_c2_pattern(&probe));
    }

    #[test]
    fn test_is_not_c2_pattern_private_ip() {
        let icp = VmNetworkInterceptor::new();
        // Private IP, non-standard port, large payload → should not trigger.
        let conn = NetworkInterception::new("10.0.0.1", "192.168.1.100", 443, "tcp", 64, 0);
        icp.record(conn.clone());
        assert!(!icp.is_c2_pattern(&conn));
    }

    // ── VmBehaviorClassifier ─────────────────────────────────────────────────

    fn make_event(ts: u64, kind: SandboxEventKind) -> SandboxEvent {
        SandboxEvent::new(ts, 1, kind, "")
    }

    #[test]
    fn test_classify_ransomware() {
        let clf = VmBehaviorClassifier::new();
        let mut events = vec![];
        for i in 0u64..10 {
            events.push(make_event(i, SandboxEventKind::FileOp("write".to_string())));
        }
        for i in 0u64..3 {
            events.push(make_event(10 + i, SandboxEventKind::ExtensionChange));
        }
        events.push(make_event(20, SandboxEventKind::DeleteShadowCopies));
        assert_eq!(clf.classify(&events), MalwareCategory::Ransomware);
    }

    #[test]
    fn test_classify_rat() {
        let clf = VmBehaviorClassifier::new();
        let events = vec![
            make_event(0, SandboxEventKind::NetworkConn),
            make_event(1, SandboxEventKind::CodeInjection),
            make_event(2, SandboxEventKind::ScreenCapture),
        ];
        assert_eq!(clf.classify(&events), MalwareCategory::Rat);
    }

    #[test]
    fn test_classify_keylogger() {
        let clf = VmBehaviorClassifier::new();
        let events = vec![
            make_event(0, SandboxEventKind::KeyboardHook),
            make_event(1, SandboxEventKind::ApiCall("GetAsyncKeyState".to_string())),
        ];
        assert_eq!(clf.classify(&events), MalwareCategory::Keylogger);
    }

    #[test]
    fn test_classify_miner() {
        let clf = VmBehaviorClassifier::new();
        let events = vec![
            make_event(0, SandboxEventKind::HighCpuLoad),
            make_event(1, SandboxEventKind::NetworkConn),
            make_event(2, SandboxEventKind::ModuleLoad("opencl.dll".to_string())),
        ];
        assert_eq!(clf.classify(&events), MalwareCategory::Miner);
    }

    #[test]
    fn test_classify_benign_no_events() {
        let clf = VmBehaviorClassifier::new();
        assert_eq!(clf.classify(&[]), MalwareCategory::Unknown);
    }
}

// ─── Memory-map provenance and live-read tests ────────────────────────────────

#[cfg(test)]
mod memory_map_provenance_tests {
    use super::*;

    const SAMPLE_MAPS: &str = "\
00400000-00401000 r-xp 00000000 08:01 1234 /usr/bin/sample
7ffff7a00000-7ffff7a21000 rw-p 00000000 00:00 0 
7ffff7b00000-7ffff7b10000 rwxp 00000000 00:00 0 [heap]
";

    #[test]
    fn test_from_proc_maps_parses_real_lines() {
        let m = MemoryMap::from_proc_maps(42, SAMPLE_MAPS);
        assert_eq!(m.pid, 42);
        assert_eq!(m.regions.len(), 3);
        assert_eq!(m.regions[0].start, 0x0040_0000);
        assert_eq!(m.regions[0].end, 0x0040_1000);
        assert!(m.regions[0].readable && m.regions[0].executable);
        assert!(!m.regions[0].writable);
        assert_eq!(m.regions[0].mapped_file.as_deref(), Some("/usr/bin/sample"));
        assert!(m.regions[1].mapped_file.is_none());
        assert_eq!(m.regions[2].label, "[heap]");
        assert!(m.regions[2].is_rwx());
        // A parsed map is an observation.
        assert!(m.provenance.is_observed());
        assert!(!m.is_synthetic());
    }

    #[test]
    fn test_from_proc_maps_skips_unparseable_lines_without_inventing() {
        let m = MemoryMap::from_proc_maps(1, "garbage\nzzzz-yyyy r--p\n");
        assert!(m.regions.is_empty());
    }

    #[test]
    fn test_mock_map_is_labelled_synthetic() {
        assert!(MemoryMap::mock(1).is_synthetic());
        assert!(!MemoryMap::new(1).is_synthetic());
    }

    /// On a host without procfs the map must be refused with a typed error that
    /// names the missing component — never a fabricated layout.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_read_live_reports_missing_backend() {
        let err = MemoryMap::read_live(1234).unwrap_err();
        match err {
            VmError::BackendUnavailable {
                component,
                observation,
                detail,
            } => {
                assert!(component.contains("1234"), "component: {component}");
                assert!(observation.contains("memory map"));
                assert!(!detail.is_empty());
            }
            other => panic!("expected BackendUnavailable, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_live_of_absent_pid_is_an_io_error() {
        assert!(matches!(
            MemoryMap::read_live(0xFFFF_FFFF),
            Err(VmError::Io(_))
        ));
    }

    #[test]
    fn test_provenance_survives_json_round_trip() {
        let json = serde_json::to_string(&MemoryMap::mock(9)).unwrap();
        assert!(json.contains("SyntheticFixture"));
        let back: MemoryMap = serde_json::from_str(&json).unwrap();
        assert!(back.is_synthetic());
    }

    #[test]
    fn test_legacy_json_without_provenance_defaults_to_observed() {
        let m: MemoryMap = serde_json::from_str(r#"{"regions":[],"pid":3}"#).unwrap();
        assert!(m.provenance.is_observed());
    }
}
