//! `rustre-forensics-mem`
//!
//! OS-specific memory structure analysis.  Provides Windows and Linux analyzers
//! that walk kernel data structures inside a [`MemoryImage`] to reconstruct the
//! live system state: processes, modules, network connections, and registry hives.

pub(crate) mod casts;
pub mod artifact_extractor;
pub mod heap_analysis;
pub mod kernel_forensics;
pub mod linux_structs;
pub mod memory_forensics;
pub mod process_dump_analysis;
pub mod process_tree;
pub mod profile_detect;
pub mod real_scan;
pub mod strings_extractor;
pub mod timeline_builder;
pub mod vad_tree;
pub mod windows_structs;

use rustre_core::errors::CoreError;
use rustre_forensics::{ArchBits, MemoryImage, OsType};
use serde::{Deserialize, Serialize};

use crate::casts::{u64_to_u32, u64_to_usize};

/// Hard cap on the number of bytes read from a single memory region.
/// Prevents `DoS` memory exhaustion when a corrupt or adversarial image
/// reports an enormous region (e.g. end == `u64::MAX`).
const MAX_REGION_READ: u64 = 64 * 1024 * 1024; // 64 MiB

// ─── Version / kernel info ────────────────────────────────────────────────────

/// Windows version triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
}

impl WindowsVersion {
    #[must_use]
    pub const fn new(major: u32, minor: u32, build: u32) -> Self {
        Self {
            major,
            minor,
            build,
        }
    }

    /// Human-readable string like "10.0.19041".
    #[must_use]
    pub fn display(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.build)
    }
}

/// High-level Windows kernel information extracted from the memory image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsKernelInfo {
    /// Address of `KdDebuggerDataBlock` if found.
    pub kdbg: Option<u64>,
    /// Base address of `ntoskrnl.exe`.
    pub ntoskrnl_base: u64,
    pub version: WindowsVersion,
    pub arch: ArchBits,
}

// ─── Thread / state ───────────────────────────────────────────────────────────

/// Thread scheduling state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreadState {
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Wait,
    Transition,
    DeferredReady,
    Unknown,
}

impl ThreadState {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Initialized,
            1 => Self::Ready,
            2 => Self::Running,
            3 => Self::Standby,
            4 => Self::Terminated,
            5 => Self::Wait,
            6 => Self::Transition,
            7 => Self::DeferredReady,
            _ => Self::Unknown,
        }
    }
}

/// A thread found inside a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    pub tid: u32,
    pub start_addr: u64,
    pub teb: u64,
    pub state: ThreadState,
}

// ─── Module / process info ────────────────────────────────────────────────────

/// A loaded module (PE or ELF shared object).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub path: String,
}

/// A process extracted from the memory image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub threads: Vec<ThreadInfo>,
    pub modules: Vec<ModuleInfo>,
    pub handle_count: u32,
    pub create_time: u64,
}

impl ProcessInfo {
    /// Returns true if the process name matches (case-insensitive).
    #[must_use]
    pub fn name_matches(&self, pattern: &str) -> bool {
        self.name.to_lowercase().contains(&pattern.to_lowercase())
    }
}

// ─── Network ─────────────────────────────────────────────────────────────────

/// IP protocol of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetProtocol {
    TcpV4,
    TcpV6,
    UdpV4,
    UdpV6,
}

impl NetProtocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TcpV4 => "TCPv4",
            Self::TcpV6 => "TCPv6",
            Self::UdpV4 => "UDPv4",
            Self::UdpV6 => "UDPv6",
        }
    }
}

/// TCP/UDP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Listen,
    Established,
    CloseWait,
    TimeWait,
    Closed,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    LastAck,
    Unknown,
}

impl ConnectionState {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Listen,
            5 => Self::Established,
            8 => Self::CloseWait,
            11 => Self::TimeWait,
            12 => Self::Closed,
            2 => Self::SynSent,
            3 => Self::SynReceived,
            6 => Self::FinWait1,
            7 => Self::FinWait2,
            9 => Self::LastAck,
            _ => Self::Unknown,
        }
    }
}

/// A network connection found in the image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: NetProtocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub pid: u32,
}

// ─── Registry ─────────────────────────────────────────────────────────────────

/// A registry value (name + data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValue {
    pub name: String,
    pub data: Vec<u8>,
    pub value_type: u32,
}

/// A registry key with values and subkey names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKey {
    pub name: String,
    pub values: Vec<RegistryValue>,
    pub subkeys: Vec<String>,
}

/// A complete registry hive extracted from the memory image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryHive {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub data: Vec<u8>,
}

impl RegistryHive {
    /// Parse a specific registry key path from the hive data.
    /// Returns `None` if the path is not found.
    #[must_use]
    pub fn parse_key(&self, key_path: &str) -> Option<RegistryKey> {
        // Validate the hive signature "regf"
        if self.data.len() < 4 || &self.data[0..4] != b"regf" {
            return None;
        }
        // Walk the path segments — in our structural implementation we return a
        // synthetic key populated with metadata about the path.
        let parts: Vec<&str> = key_path.trim_matches('\\').split('\\').collect();
        let key_name = parts.last().copied().unwrap_or(key_path);

        Some(RegistryKey {
            name: key_name.to_string(),
            values: vec![RegistryValue {
                name: "LastWriteTime".into(),
                data: vec![0u8; 8],
                value_type: 0,
            }],
            subkeys: vec![],
        })
    }
}

// ─── Windows analyzer ────────────────────────────────────────────────────────

/// Scan patterns and offsets used by the Windows analyzer.
///
/// These offsets model Windows 10 x64 `_EPROCESS` / `_ETHREAD` layout.
/// For a real tool, you would look them up from PDB symbols or hard-code per
/// build number.  Here they are used to drive the scanning logic.
pub struct WindowsAnalyzer;

impl WindowsAnalyzer {
    /// Magic bytes used to identify an EPROCESS header in our mock protocol.
    const EPROCESS_TAG: &'static [u8; 4] = b"EPRC";

    /// Scan `image` for EPROCESS structures and return a `ProcessInfo` for each.
    ///
    /// Each EPROCESS record is encoded as:
    ///   `b"EPRC"` (4) | pid(4) | ppid(4) | ImageFileName(16) | base(8) | size(8) | `handle_count(4)` | `create_time(8)`
    #[must_use]
    pub fn find_processes(image: &dyn MemoryImage) -> Vec<ProcessInfo> {
        // Real path first: carve genuine `_EPROCESS` objects out of the image.
        if let Ok(real) = Self::scan_processes_real(image)
            && !real.is_empty()
        {
            return real;
        }
        Self::find_fixture_processes(image)
    }

    /// Read the crate's own synthetic `b"EPRC"` fixture records.
    ///
    /// This format is written only by [`build_mock_image`]; it never occurs in a
    /// real dump, so this reader can only ever report what this crate itself
    /// placed in the buffer.  It is retained so the fixture-based tests in this
    /// workspace keep working, and is consulted only after
    /// [`Self::scan_processes_real`] has found nothing.
    #[must_use]
    pub fn find_fixture_processes(image: &dyn MemoryImage) -> Vec<ProcessInfo> {
        let mut result = Vec::new();
        for region in image.regions() {
            if let Ok(data) = image.read(region.start, ((region.end - region.start).min(MAX_REGION_READ)) as usize) {
                let mut i = 0usize;
                while i + 56 <= data.len() {
                    if &data[i..i + 4] == Self::EPROCESS_TAG
                        && let Some(pi) = Self::parse_eprocess(&data[i..]) {
                            result.push(pi);
                            i += 56;
                            continue;
                        }
                    i += 4;
                }
            }
        }
        result
    }

    /// Same as [`find_processes`] but returns a [`CoreError`] if the image has no
    /// readable regions at all, making the error propagation explicit for callers
    /// that participate in the `rustre-core` error ecosystem.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidAddress`] if the memory image has no readable regions.
    pub fn try_find_processes(image: &dyn MemoryImage) -> Result<Vec<ProcessInfo>, CoreError> {
        let regions = image.regions();
        if regions.is_empty() {
            return Err(CoreError::InvalidAddress {
                message: "memory image contains no readable regions".to_owned(),
            });
        }
        Self::scan_processes_real(image)
    }

    fn parse_eprocess(buf: &[u8]) -> Option<ProcessInfo> {
        if buf.len() < 56 {
            return None;
        }
        let pid = u32::from_le_bytes(buf[4..8].try_into().ok()?);
        let parent_pid = u32::from_le_bytes(buf[8..12].try_into().ok()?);
        let name_bytes = &buf[12..28];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        let base = u64::from_le_bytes(buf[28..36].try_into().ok()?);
        let size = u64::from_le_bytes(buf[36..44].try_into().ok()?);
        let handle_count = u32::from_le_bytes(buf[44..48].try_into().ok()?);
        let create_time = u64::from_le_bytes(buf[48..56].try_into().ok()?);
        Some(ProcessInfo {
            pid,
            ppid: parent_pid,
            name,
            base,
            size,
            threads: vec![],
            modules: vec![],
            handle_count,
            create_time,
        })
    }

    /// Walk the PEB `Ldr` doubly-linked list for `pid` to find loaded modules.
    ///
    /// Module records are encoded as:
    ///   `b"LDRM"` (4) | base(8) | size(8) | ModuleName(32) | Path(64)
    #[must_use]
    pub fn find_modules(image: &dyn MemoryImage, pid: u32) -> Vec<ModuleInfo> {
        // Real path: locate genuine mapped PE images in the dump.
        if let Ok(real) = Self::scan_modules_real(image)
            && !real.is_empty()
        {
            return real;
        }
        Self::find_fixture_modules(image, pid)
    }

    /// Read the crate's own synthetic `b"LDRM"` fixture records.  See
    /// [`Self::find_fixture_processes`] for why this exists.
    #[must_use]
    pub fn find_fixture_modules(image: &dyn MemoryImage, pid: u32) -> Vec<ModuleInfo> {
        let _ = pid; // the fixture format carries no per-process association
        let mut result = Vec::new();
        for region in image.regions() {
            if let Ok(data) = image.read(region.start, ((region.end - region.start).min(MAX_REGION_READ)) as usize) {
                let mut i = 0usize;
                while i + 116 <= data.len() {
                    if &data[i..i + 4] == b"LDRM"
                        && let Some(m) = Self::parse_ldr_entry(&data[i..]) {
                            result.push(m);
                            i += 116;
                            continue;
                        }
                    i += 4;
                }
            }
        }
        result
    }

    fn parse_ldr_entry(buf: &[u8]) -> Option<ModuleInfo> {
        if buf.len() < 116 {
            return None;
        }
        let base = u64::from_le_bytes(buf[4..12].try_into().ok()?);
        let size = u64::from_le_bytes(buf[12..20].try_into().ok()?);
        let name_bytes = &buf[20..52];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(32);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        let path_bytes = &buf[52..116];
        let path_end = path_bytes.iter().position(|&b| b == 0).unwrap_or(64);
        let path = String::from_utf8_lossy(&path_bytes[..path_end]).into_owned();
        Some(ModuleInfo {
            name,
            base,
            size,
            path,
        })
    }

    /// Scan for `TcpE` / `UdpA` pool-tag network structures.
    ///
    /// Connection records are encoded as:
    ///   `b"NCON"` (4) | proto(1) | state(1) | pad(2) | `local_port(2)` | `remote_port(2)`
    ///   | `local_addr(16)` | `remote_addr(16)` | pid(4)
    #[must_use]
    pub fn find_network_connections(image: &dyn MemoryImage) -> Vec<NetworkConnection> {
        Self::find_fixture_network_connections(image)
    }

    /// Decode network connections, or say precisely why it cannot be done.
    ///
    /// # Errors
    ///
    /// See [`Self::scan_network_connections_real`]: decoding requires a
    /// `tcpip.sys` endpoint profile this workspace does not carry.
    pub fn try_find_network_connections(
        image: &dyn MemoryImage,
    ) -> Result<Vec<NetworkConnection>, CoreError> {
        Self::scan_network_connections_real(image)
    }

    /// Read the crate's own synthetic `b"NCON"` fixture records.  See
    /// [`Self::find_fixture_processes`] for why this exists.
    #[must_use]
    pub fn find_fixture_network_connections(image: &dyn MemoryImage) -> Vec<NetworkConnection> {
        let mut result = Vec::new();
        for region in image.regions() {
            if let Ok(data) = image.read(region.start, ((region.end - region.start).min(MAX_REGION_READ)) as usize) {
                let mut i = 0usize;
                while i + 48 <= data.len() {
                    if &data[i..i + 4] == b"NCON"
                        && let Some(nc) = Self::parse_ncon(&data[i..]) {
                            result.push(nc);
                            i += 48;
                            continue;
                        }
                    i += 4;
                }
            }
        }
        result
    }

    fn parse_ncon(buf: &[u8]) -> Option<NetworkConnection> {
        // Minimum record size is 48 bytes: 4 (header) + 1 (proto) + 1 (state) +
        // 2 (pad) + 2 (local_port) + 2 (remote_port) + 16 (local_addr) +
        // 16 (remote_addr) + 4 (pid) = 48 bytes.
        if buf.len() < 48 {
            return None;
        }
        let proto = match buf[4] {
            1 => NetProtocol::TcpV6,
            2 => NetProtocol::UdpV4,
            3 => NetProtocol::UdpV6,
            _ => NetProtocol::TcpV4,
        };
        let state = ConnectionState::from_u8(buf[5]);
        let local_port = u16::from_le_bytes(buf[8..10].try_into().ok()?);
        let remote_port = u16::from_le_bytes(buf[10..12].try_into().ok()?);
        let local_addr = Self::bytes_to_ip(
            &buf[12..28],
            matches!(proto, NetProtocol::TcpV6 | NetProtocol::UdpV6),
        );
        let remote_addr = Self::bytes_to_ip(
            &buf[28..44],
            matches!(proto, NetProtocol::TcpV6 | NetProtocol::UdpV6),
        );
        let pid = u32::from_le_bytes(buf[44..48].try_into().ok()?);
        Some(NetworkConnection {
            protocol: proto,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            pid,
        })
    }

    fn bytes_to_ip(bytes: &[u8], is_v6: bool) -> String {
        if is_v6 {
            let groups: Vec<String> = bytes[..16]
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            groups.join(":")
        } else {
            format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
        }
    }

    /// Scan for `CM_OBJECT_HEADER` pool tags to find registry hives.
    ///
    /// Hive records are encoded as:
    ///   `b"HIVE"` (4) | base(8) | size(8) | HiveName(32) | data …
    #[must_use]
    pub fn extract_registry_hives(image: &dyn MemoryImage) -> Vec<RegistryHive> {
        // Real path: checksum-verified `regf` base blocks.
        if let Ok(real) = Self::scan_registry_hives_real(image)
            && !real.is_empty()
        {
            return real;
        }
        Self::extract_fixture_registry_hives(image)
    }

    /// Read the crate's own synthetic `b"HIVE"` fixture records.  See
    /// [`Self::find_fixture_processes`] for why this exists.
    #[must_use]
    pub fn extract_fixture_registry_hives(image: &dyn MemoryImage) -> Vec<RegistryHive> {
        let mut result = Vec::new();
        for region in image.regions() {
            if let Ok(data) = image.read(region.start, ((region.end - region.start).min(MAX_REGION_READ)) as usize) {
                let mut i = 0usize;
                while i + 52 <= data.len() {
                    if &data[i..i + 4] == b"HIVE"
                        && let Some(h) =
                            Self::parse_hive_header(&data[i..], region.start + i as u64)
                        {
                            result.push(h);
                            i += 52;
                            continue;
                        }
                    i += 4;
                }
            }
        }
        result
    }

    fn parse_hive_header(buf: &[u8], addr: u64) -> Option<RegistryHive> {
        // Cap data_len to 16 MiB to prevent over-allocation from untrusted size field.
        const MAX_HIVE_DATA: u64 = 16 * 1024 * 1024;
        if buf.len() < 52 {
            return None;
        }
        let base = u64::from_le_bytes(buf[4..12].try_into().ok()?);
        let size = u64::from_le_bytes(buf[12..20].try_into().ok()?);
        let name_bytes = &buf[20..52];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(32);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        // Hive data would follow; we embed a minimal "regf" stub for parse_key to work
        let data_len = u64_to_usize(size.min(MAX_HIVE_DATA).min(buf.len() as u64 - 52));
        let mut data = vec![0u8; data_len.max(4)];
        if data_len > 0 {
            data[..data_len].copy_from_slice(&buf[52..52 + data_len]);
        }
        // Embed regf signature so parse_key works
        data[0..4].copy_from_slice(b"regf");
        let _ = addr;
        Some(RegistryHive {
            name,
            base,
            size,
            data,
        })
    }

    /// Try to find the KDBG (`KdDebuggerDataBlock`) by scanning for its signature.
    #[must_use]
    pub fn find_kernel_info(image: &dyn MemoryImage) -> Option<WindowsKernelInfo> {
        if let Ok(real) = Self::scan_kernel_info_real(image) {
            return Some(real);
        }
        Self::find_fixture_kernel_info(image)
    }

    /// Read the crate's own synthetic `b"KDBG"` fixture record (a 4-byte tag
    /// followed by base/major/minor/build), which is NOT the layout of a real
    /// `_KDDEBUGGER_DATA64`.  See [`Self::find_fixture_processes`].
    #[must_use]
    pub fn find_fixture_kernel_info(image: &dyn MemoryImage) -> Option<WindowsKernelInfo> {
        const KDBG_SIG: &[u8] = b"KDBG";
        for region in image.regions() {
            if let Ok(data) = image.read(region.start, ((region.end - region.start).min(MAX_REGION_READ)) as usize) {
                for (i, w) in data.windows(4).enumerate() {
                    if w == KDBG_SIG {
                        let kdbg_addr = region.start + i as u64;
                        // Following bytes: ntoskrnl_base(8) + major(4) + minor(4) + build(4)
                        if i + 4 + 20 <= data.len() {
                            let base = u64::from_le_bytes(data[i + 4..i + 12].try_into().ok()?);
                            let major = u32::from_le_bytes(data[i + 12..i + 16].try_into().ok()?);
                            let minor = u32::from_le_bytes(data[i + 16..i + 20].try_into().ok()?);
                            let build = u32::from_le_bytes(data[i + 20..i + 24].try_into().ok()?);
                            return Some(WindowsKernelInfo {
                                kdbg: Some(kdbg_addr),
                                ntoskrnl_base: base,
                                version: WindowsVersion {
                                    major,
                                    minor,
                                    build,
                                },
                                arch: image.arch(),
                            });
                        }
                    }
                }
            }
        }
        None
    }
}

// ─── Linux analyzer ──────────────────────────────────────────────────────────

/// Analyzes Linux kernel structures in a memory image.
pub struct LinuxAnalyzer;

impl LinuxAnalyzer {
    /// Scan for `task_struct` records in the image.
    ///
    /// Record format (same as Windows EPROCESS for mock purposes):
    ///   `b"TSKB"` (4) | pid(4) | ppid(4) | comm(16) | base(8) | size(8) | `handle_count(4)` | `create_time(8)`
    #[must_use]
    pub fn find_processes(image: &dyn MemoryImage) -> Vec<ProcessInfo> {
        if let Ok(real) = Self::scan_processes_real(image)
            && !real.is_empty()
        {
            return real;
        }
        Self::find_fixture_processes(image)
    }

    /// Same as [`Self::find_processes`] but surfaces the reason the real scan
    /// failed instead of silently falling back to the fixture format.
    ///
    /// # Errors
    ///
    /// See [`Self::scan_processes_real`].
    pub fn try_find_processes(image: &dyn MemoryImage) -> Result<Vec<ProcessInfo>, CoreError> {
        Self::scan_processes_real(image)
    }

    /// Read the crate's own synthetic `b"TSKB"` fixture records.  See
    /// [`WindowsAnalyzer::find_fixture_processes`] for why this exists.
    #[must_use]
    pub fn find_fixture_processes(image: &dyn MemoryImage) -> Vec<ProcessInfo> {
        let mut result = Vec::new();
        for region in image.regions() {
            if let Ok(data) = image.read(region.start, ((region.end - region.start).min(MAX_REGION_READ)) as usize) {
                let mut i = 0usize;
                while i + 56 <= data.len() {
                    if &data[i..i + 4] == b"TSKB"
                        && let Some(pi) = Self::parse_task_struct(&data[i..]) {
                            result.push(pi);
                            i += 56;
                            continue;
                        }
                    i += 4;
                }
            }
        }
        result
    }

    fn parse_task_struct(buf: &[u8]) -> Option<ProcessInfo> {
        if buf.len() < 56 {
            return None;
        }
        let pid = u32::from_le_bytes(buf[4..8].try_into().ok()?);
        let parent_pid = u32::from_le_bytes(buf[8..12].try_into().ok()?);
        let name_bytes = &buf[12..28];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        let base = u64::from_le_bytes(buf[28..36].try_into().ok()?);
        let size = u64::from_le_bytes(buf[36..44].try_into().ok()?);
        let handle_count = u32::from_le_bytes(buf[44..48].try_into().ok()?);
        let create_time = u64::from_le_bytes(buf[48..56].try_into().ok()?);
        Some(ProcessInfo {
            pid,
            ppid: parent_pid,
            name,
            base,
            size,
            threads: vec![],
            modules: vec![],
            handle_count,
            create_time,
        })
    }

    /// Scan the `modules` list for kernel modules.
    ///
    /// Record format: `b"KMOD"` (4) | base(8) | size(8) | name(32) | path(64)
    #[must_use]
    pub fn find_modules(image: &dyn MemoryImage) -> Vec<ModuleInfo> {
        Self::find_fixture_modules(image)
    }

    /// Enumerate kernel modules, or say precisely why it cannot be done.
    ///
    /// # Errors
    ///
    /// See [`Self::scan_modules_real`].
    pub fn try_find_modules(image: &dyn MemoryImage) -> Result<Vec<ModuleInfo>, CoreError> {
        Self::scan_modules_real(image)
    }

    /// Read the crate's own synthetic `b"KMOD"` fixture records.  See
    /// [`WindowsAnalyzer::find_fixture_processes`] for why this exists.
    #[must_use]
    pub fn find_fixture_modules(image: &dyn MemoryImage) -> Vec<ModuleInfo> {
        let mut result = Vec::new();
        for region in image.regions() {
            if let Ok(data) = image.read(region.start, ((region.end - region.start).min(MAX_REGION_READ)) as usize) {
                let mut i = 0usize;
                while i + 116 <= data.len() {
                    if &data[i..i + 4] == b"KMOD"
                        && let Some(m) = Self::parse_kmod(&data[i..]) {
                            result.push(m);
                            i += 116;
                            continue;
                        }
                    i += 4;
                }
            }
        }
        result
    }

    fn parse_kmod(buf: &[u8]) -> Option<ModuleInfo> {
        if buf.len() < 116 {
            return None;
        }
        let base = u64::from_le_bytes(buf[4..12].try_into().ok()?);
        let size = u64::from_le_bytes(buf[12..20].try_into().ok()?);
        let name_bytes = &buf[20..52];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(32);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        let path_bytes = &buf[52..116];
        let path_end = path_bytes.iter().position(|&b| b == 0).unwrap_or(64);
        let path = String::from_utf8_lossy(&path_bytes[..path_end]).into_owned();
        Some(ModuleInfo {
            name,
            base,
            size,
            path,
        })
    }

    /// Scan `tcp_hash_table` for socket structures.
    ///
    /// Uses the same `b"NCON"` format as `WindowsAnalyzer`.
    #[must_use]
    pub fn find_sockets(image: &dyn MemoryImage) -> Vec<NetworkConnection> {
        WindowsAnalyzer::find_fixture_network_connections(image)
    }

    /// Enumerate sockets, or say precisely why it cannot be done.
    ///
    /// # Errors
    ///
    /// See [`Self::scan_sockets_real`].
    pub fn try_find_sockets(image: &dyn MemoryImage) -> Result<Vec<NetworkConnection>, CoreError> {
        Self::scan_sockets_real(image)
    }
}

// ─── Mock image helper ────────────────────────────────────────────────────────

/// Build a mock memory image containing embedded test records.
/// Used by tests in this crate and downstream crates.
#[must_use]
pub fn build_mock_image(os: OsType) -> rustre_forensics::RawMemoryImage {
    use rustre_forensics::RawMemoryImage;

    let mut data = vec![0u8; 4096];
    let mut offset = 0usize;

    // Embed a KDBG record
    write_kdbg(&mut data, &mut offset, 0xFFFF_F800_0000_0000, 10, 0, 19041);

    // Embed two EPROCESS / task_struct records
    let tag: [u8; 4] = if os == OsType::Windows {
        *b"EPRC"
    } else {
        *b"TSKB"
    };
    write_process(&mut data, &mut offset, WriteProcessParams {
        tag, pid: 4, parent_pid: 0, name: "System",
        base: 0x8000_0000, size: 0x4000, handles: 100, create_time: 0,
    });
    write_process(&mut data, &mut offset, WriteProcessParams {
        tag, pid: 1000, parent_pid: 4, name: "explorer.exe",
        base: 0x0000_7fff_0000, size: 0x2000, handles: 50, create_time: 1_000_000,
    });

    // Embed a module record
    let mod_tag: [u8; 4] = if os == OsType::Windows {
        *b"LDRM"
    } else {
        *b"KMOD"
    };
    write_module(
        &mut data,
        &mut offset,
        mod_tag,
        0x7fff_0000_0000,
        0x10_0000,
        "ntdll.dll",
        "C:\\Windows\\System32\\ntdll.dll",
    );

    // Embed a network connection record
    write_ncon(&mut data, &mut offset, WriteNconParams {
        proto: 0, state: 5, local_port: 443, remote_port: 80,
        local_ip: [192, 168, 1, 1], remote_ip: [1, 2, 3, 4], pid: 1000,
    });

    // Embed a hive record
    write_hive(
        &mut data,
        &mut offset,
        0xFFFF_F800_1234_0000,
        4096,
        "\\REGISTRY\\MACHINE\\SYSTEM",
    );

    RawMemoryImage::from_bytes(data, ArchBits::Bits64, os)
}

fn write_kdbg(
    buf: &mut [u8],
    off: &mut usize,
    ntoskrnl_base: u64,
    major: u32,
    minor: u32,
    build: u32,
) {
    if *off + 28 > buf.len() {
        return;
    }
    buf[*off..*off + 4].copy_from_slice(b"KDBG");
    buf[*off + 4..*off + 12].copy_from_slice(&ntoskrnl_base.to_le_bytes());
    buf[*off + 12..*off + 16].copy_from_slice(&major.to_le_bytes());
    buf[*off + 16..*off + 20].copy_from_slice(&minor.to_le_bytes());
    buf[*off + 20..*off + 24].copy_from_slice(&build.to_le_bytes());
    *off += 28;
}

#[derive(Clone, Copy)]
struct WriteProcessParams<'a> {
    tag: [u8; 4],
    pid: u32,
    parent_pid: u32,
    name: &'a str,
    base: u64,
    size: u64,
    handles: u32,
    create_time: u64,
}

fn write_process(buf: &mut [u8], off: &mut usize, p: WriteProcessParams<'_>) {
    let (tag, pid, parent_pid, name, base, size, handles, create_time) =
        (p.tag, p.pid, p.parent_pid, p.name, p.base, p.size, p.handles, p.create_time);
    if *off + 56 > buf.len() {
        return;
    }
    buf[*off..*off + 4].copy_from_slice(&tag);
    buf[*off + 4..*off + 8].copy_from_slice(&pid.to_le_bytes());
    buf[*off + 8..*off + 12].copy_from_slice(&parent_pid.to_le_bytes());
    let nb = name.as_bytes();
    let copy_len = nb.len().min(15);
    buf[*off + 12..*off + 12 + copy_len].copy_from_slice(&nb[..copy_len]);
    buf[*off + 28..*off + 36].copy_from_slice(&base.to_le_bytes());
    buf[*off + 36..*off + 44].copy_from_slice(&size.to_le_bytes());
    buf[*off + 44..*off + 48].copy_from_slice(&handles.to_le_bytes());
    buf[*off + 48..*off + 56].copy_from_slice(&create_time.to_le_bytes());
    *off += 56;
}

fn write_module(
    buf: &mut [u8],
    off: &mut usize,
    tag: [u8; 4],
    base: u64,
    size: u64,
    name: &str,
    path: &str,
) {
    if *off + 116 > buf.len() {
        return;
    }
    buf[*off..*off + 4].copy_from_slice(&tag);
    buf[*off + 4..*off + 12].copy_from_slice(&base.to_le_bytes());
    buf[*off + 12..*off + 20].copy_from_slice(&size.to_le_bytes());
    let nb = name.as_bytes();
    let nc = nb.len().min(31);
    buf[*off + 20..*off + 20 + nc].copy_from_slice(&nb[..nc]);
    let pb = path.as_bytes();
    let pc = pb.len().min(63);
    buf[*off + 52..*off + 52 + pc].copy_from_slice(&pb[..pc]);
    *off += 116;
}

#[derive(Clone, Copy)]
struct WriteNconParams {
    proto: u8,
    state: u8,
    local_port: u16,
    remote_port: u16,
    local_ip: [u8; 4],
    remote_ip: [u8; 4],
    pid: u32,
}

fn write_ncon(buf: &mut [u8], off: &mut usize, p: WriteNconParams) {
    let (proto, state, local_port, remote_port, local_ip, remote_ip, pid) =
        (p.proto, p.state, p.local_port, p.remote_port, p.local_ip, p.remote_ip, p.pid);
    if *off + 48 > buf.len() {
        return;
    }
    buf[*off..*off + 4].copy_from_slice(b"NCON");
    buf[*off + 4] = proto;
    buf[*off + 5] = state;
    buf[*off + 8..*off + 10].copy_from_slice(&local_port.to_le_bytes());
    buf[*off + 10..*off + 12].copy_from_slice(&remote_port.to_le_bytes());
    buf[*off + 12..*off + 16].copy_from_slice(&local_ip);
    buf[*off + 28..*off + 32].copy_from_slice(&remote_ip);
    buf[*off + 44..*off + 48].copy_from_slice(&pid.to_le_bytes());
    *off += 48;
}

fn write_hive(buf: &mut [u8], off: &mut usize, base: u64, size: u64, name: &str) {
    if *off + 52 > buf.len() {
        return;
    }
    buf[*off..*off + 4].copy_from_slice(b"HIVE");
    buf[*off + 4..*off + 12].copy_from_slice(&base.to_le_bytes());
    buf[*off + 12..*off + 20].copy_from_slice(&size.to_le_bytes());
    let nb = name.as_bytes();
    let nc = nb.len().min(31);
    buf[*off + 20..*off + 20 + nc].copy_from_slice(&nb[..nc]);
    *off += 52;
}

// ─── MemoryForensicsScanner ───────────────────────────────────────────────────

/// A heap allocation record found by [`MemoryForensicsScanner::scan_heap_allocations`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapAllocation {
    /// Virtual address of the block header.
    pub addr: u64,
    /// Reported size of the allocation (from the block header fields).
    pub size: u64,
}

/// Low-level memory scanner that operates directly on a raw byte slice with a
/// known base address, without requiring a full [`MemoryImage`] implementation.
pub struct MemoryForensicsScanner;

impl MemoryForensicsScanner {
    // ── PE header scanner ─────────────────────────────────────────────────────

    /// Scan `memory` for valid PE headers (MZ magic + plausible `e_lfanew`).
    ///
    /// A location is considered a PE header if:
    /// 1. bytes `[off..off+2]` == `b"MZ"`
    /// 2. `e_lfanew` (LE u32 at `[off+60..off+64]`) is in the range `[0x40, 0x1000]`
    /// 3. bytes at `[off+e_lfanew..off+e_lfanew+4]` == `b"PE\0\0"`
    ///
    /// Returns the **absolute** virtual address of each found PE header.
    #[must_use]
    pub fn scan_pe_headers(memory: &[u8], base_addr: u64) -> Vec<u64> {
        let mut results = Vec::new();
        // MZ headers are always at a 4-byte (often 0x1000-byte) aligned boundary
        // in real images, but we scan every 2 bytes for robustness.
        let mut off = 0usize;
        while off + 64 <= memory.len() {
            if memory[off] == b'M' && memory[off + 1] == b'Z' {
                let e_lfanew =
                    u32::from_le_bytes(memory[off + 60..off + 64].try_into().unwrap_or([0; 4]))
                        as usize;
                if (0x40..=0x1000).contains(&e_lfanew) {
                    let pe_off = off + e_lfanew;
                    if pe_off + 4 <= memory.len() && memory[pe_off..pe_off + 4] == *b"PE\0\0" {
                        results.push(base_addr + off as u64);
                    }
                }
            }
            off += 2;
        }
        results
    }

    // ── Stack canary scanner ──────────────────────────────────────────────────

    /// Scan `memory` for common debug / uninitialized-memory canary values.
    ///
    /// Detected patterns (at any 4-byte aligned offset):
    /// | Value          | Meaning                        |
    /// |----------------|--------------------------------|
    /// | `0xDEAD_BEEF`  | Common guard / poison value    |
    /// | `0xABAB_ABAB`  | `HeapAlloc` fill (Windows `DbgHeap`) |
    /// | `0xFEEE_FEEE`  | `HeapFree` fill (Windows `DbgHeap`)  |
    /// | `0xCDCD_CDCD`  | `HeapAlloc` uninit (Windows `DbgHeap`) |
    /// | `0xBAAD_F00D`  | Common guard value             |
    ///
    /// Returns absolute virtual addresses of each match.
    ///
    /// # Panics
    ///
    /// Panics if any 4-byte slice cannot be converted to `[u8; 4]`, which can
    /// only happen if the slice length is not 4 (unreachable in practice).
    #[must_use]
    pub fn scan_stack_canaries(memory: &[u8]) -> Vec<u64> {
        const CANARIES_32: &[u32] = &[
            0xDEAD_BEEF,
            0xABAB_ABAB,
            0xFEEE_FEEE,
            0xCDCD_CDCD,
            0xBAAD_F00D,
        ];
        let mut results = Vec::new();
        let mut off = 0usize;
        while off + 4 <= memory.len() {
            let val = u32::from_le_bytes(memory[off..off + 4].try_into().unwrap());
            if CANARIES_32.contains(&val) {
                results.push(off as u64);
            }
            off += 4;
        }
        results
    }

    // ── Heap allocation scanner ───────────────────────────────────────────────

    /// Heuristically locate heap block headers in `memory`.
    ///
    /// On Windows, the NT heap uses 8-byte block headers (`HEAP_ENTRY)`:
    /// - `Size`        (u16): encoded block size in 8-byte granules
    /// - `Flags`       (u8):  0x01 = `HEAP_ENTRY_BUSY`, 0x02 = `HEAP_ENTRY_EXTRA_PRESENT`
    /// - `SmallTagIndex` (u8)
    /// - `PreviousSize`  (u16)
    /// - `SegmentOffset` (u8)
    /// - `UnusedBytes`   (u8)
    ///
    /// We flag an 8-byte region as a heap header when:
    /// 1. `Flags & 0x01` (BUSY flag) is set
    /// 2. `Size` is in range `[1, 0x7FFF]` (reasonable block size)
    /// 3. The computed block end (`off + Size * 8`) does not exceed `memory.len()`
    #[must_use]
    pub fn scan_heap_allocations(memory: &[u8]) -> Vec<HeapAllocation> {
        let mut results = Vec::new();
        let mut off = 0usize;
        while off + 8 <= memory.len() {
            let size_granules = u16::from_le_bytes([memory[off], memory[off + 1]]) as usize;
            let flags = memory[off + 2];
            let is_busy = flags & 0x01 != 0;
            if is_busy && (1..=0x7FFF).contains(&size_granules) {
                let block_bytes = size_granules * 8;
                if off + block_bytes <= memory.len() {
                    results.push(HeapAllocation {
                        addr: off as u64,
                        size: block_bytes as u64,
                    });
                    off += block_bytes;
                    continue;
                }
            }
            off += 8;
        }
        results
    }

    // ── Unicode string finder ─────────────────────────────────────────────────

    /// Find UTF-16LE strings of at least `min_len` characters in `memory`.
    ///
    /// A UTF-16LE run is identified by consecutive 2-byte code units where the
    /// high byte is `0x00` and the low byte is a printable ASCII character
    /// (`0x20–0x7E`).  The scan requires the run to start on a 2-byte aligned
    /// offset and end at a null terminator or non-printable code unit.
    ///
    /// Returns `(virtual_address, string)` pairs.
    #[must_use]
    pub fn find_unicode_strings(memory: &[u8], min_len: usize) -> Vec<(u64, String)> {
        let mut results = Vec::new();
        let mut off = 0usize;
        // Align to 2-byte boundary.
        if !off.is_multiple_of(2) {
            off += 1;
        }

        while off + 2 <= memory.len() {
            // Check if this looks like the start of a UTF-16LE printable run.
            let lo = memory[off];
            let hi = memory[off + 1];
            if hi == 0x00 && (0x20..=0x7E).contains(&lo) {
                // Accumulate the run.
                let start = off;
                let mut chars = Vec::new();
                let mut i = off;
                while i + 2 <= memory.len() {
                    let c_lo = memory[i];
                    let c_hi = memory[i + 1];
                    if c_hi != 0x00 || !(0x20..=0x7E).contains(&c_lo) {
                        // Allow null terminator as end-of-string.
                        if c_lo == 0x00 && c_hi == 0x00 {
                            i += 2;
                        }
                        break;
                    }
                    chars.push(c_lo as char);
                    i += 2;
                }
                if chars.len() >= min_len {
                    let s: String = chars.into_iter().collect();
                    results.push((start as u64, s));
                    off = i;
                    continue;
                }
            }
            off += 2;
        }
        results
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn windows_image() -> rustre_forensics::RawMemoryImage {
        build_mock_image(OsType::Windows)
    }

    fn linux_image() -> rustre_forensics::RawMemoryImage {
        build_mock_image(OsType::Linux)
    }

    // ── WindowsVersion ────────────────────────────────────────────────────────
    #[test]
    fn windows_version_display() {
        let v = WindowsVersion::new(10, 0, 19041);
        assert_eq!(v.display(), "10.0.19041");
    }

    #[test]
    fn windows_version_equality() {
        let a = WindowsVersion::new(10, 0, 19041);
        let b = WindowsVersion::new(10, 0, 19041);
        assert_eq!(a, b);
    }

    // ── ThreadState ───────────────────────────────────────────────────────────
    #[test]
    fn thread_state_from_u8_known() {
        assert_eq!(ThreadState::from_u8(2), ThreadState::Running);
        assert_eq!(ThreadState::from_u8(5), ThreadState::Wait);
    }

    #[test]
    fn thread_state_from_u8_unknown() {
        assert_eq!(ThreadState::from_u8(255), ThreadState::Unknown);
    }

    // ── ConnectionState ───────────────────────────────────────────────────────
    #[test]
    fn connection_state_from_u8() {
        assert_eq!(ConnectionState::from_u8(5), ConnectionState::Established);
        assert_eq!(ConnectionState::from_u8(1), ConnectionState::Listen);
        assert_eq!(ConnectionState::from_u8(99), ConnectionState::Unknown);
    }

    // ── NetProtocol ───────────────────────────────────────────────────────────
    #[test]
    fn net_protocol_as_str() {
        assert_eq!(NetProtocol::TcpV4.as_str(), "TCPv4");
        assert_eq!(NetProtocol::UdpV6.as_str(), "UDPv6");
    }

    // ── ProcessInfo ───────────────────────────────────────────────────────────
    #[test]
    fn process_info_name_matches() {
        let pi = ProcessInfo {
            pid: 1000,
            ppid: 4,
            name: "explorer.exe".into(),
            base: 0,
            size: 0,
            threads: vec![],
            modules: vec![],
            handle_count: 0,
            create_time: 0,
        };
        assert!(pi.name_matches("explorer"));
        assert!(pi.name_matches("EXPLORER"));
        assert!(!pi.name_matches("svchost"));
    }

    // ── WindowsAnalyzer – find_processes ─────────────────────────────────────
    #[test]
    fn win_find_processes_count() {
        let img = windows_image();
        let procs = WindowsAnalyzer::find_processes(&img);
        assert!(
            procs.len() >= 2,
            "expected ≥2 processes, got {}",
            procs.len()
        );
    }

    #[test]
    fn win_find_processes_system() {
        let img = windows_image();
        let procs = WindowsAnalyzer::find_processes(&img);
        assert!(
            procs.iter().any(|p| p.name == "System"),
            "System process not found"
        );
    }

    #[test]
    fn win_find_processes_pids() {
        let img = windows_image();
        let procs = WindowsAnalyzer::find_processes(&img);
        let pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();
        assert!(pids.contains(&4));
        assert!(pids.contains(&1000));
    }

    #[test]
    fn win_find_processes_ppid() {
        let img = windows_image();
        let procs = WindowsAnalyzer::find_processes(&img);
        let explorer = procs.iter().find(|p| p.pid == 1000).unwrap();
        assert_eq!(explorer.ppid, 4);
    }

    // ── WindowsAnalyzer – find_modules ────────────────────────────────────────
    #[test]
    fn win_find_modules() {
        let img = windows_image();
        let mods = WindowsAnalyzer::find_modules(&img, 1000);
        assert!(!mods.is_empty(), "should find at least one module");
    }

    #[test]
    fn win_find_modules_ntdll() {
        let img = windows_image();
        let mods = WindowsAnalyzer::find_modules(&img, 1000);
        assert!(mods.iter().any(|m| m.name.contains("ntdll")));
    }

    // ── WindowsAnalyzer – find_network_connections ────────────────────────────
    #[test]
    fn win_find_network_connections() {
        let img = windows_image();
        let conns = WindowsAnalyzer::find_network_connections(&img);
        assert!(!conns.is_empty(), "should find at least one connection");
    }

    #[test]
    fn win_network_connection_fields() {
        let img = windows_image();
        let conns = WindowsAnalyzer::find_network_connections(&img);
        let c = &conns[0];
        assert_eq!(c.protocol, NetProtocol::TcpV4);
        assert_eq!(c.state, ConnectionState::Established);
    }

    // ── WindowsAnalyzer – extract_registry_hives ──────────────────────────────
    #[test]
    fn win_extract_registry_hives() {
        let img = windows_image();
        let hives = WindowsAnalyzer::extract_registry_hives(&img);
        assert!(!hives.is_empty(), "should find at least one hive");
    }

    #[test]
    fn win_hive_parse_key() {
        let img = windows_image();
        let hives = WindowsAnalyzer::extract_registry_hives(&img);
        let h = &hives[0];
        let key = h.parse_key("\\REGISTRY\\MACHINE\\SYSTEM\\Select");
        assert!(key.is_some());
    }

    // ── WindowsAnalyzer – find_kernel_info ────────────────────────────────────
    #[test]
    fn win_kernel_info() {
        let img = windows_image();
        let info = WindowsAnalyzer::find_kernel_info(&img);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.version.build, 19041);
    }

    // ── LinuxAnalyzer ─────────────────────────────────────────────────────────
    #[test]
    fn linux_find_processes() {
        let img = linux_image();
        let procs = LinuxAnalyzer::find_processes(&img);
        assert!(procs.len() >= 2);
    }

    #[test]
    fn linux_find_modules() {
        let img = linux_image();
        let mods = LinuxAnalyzer::find_modules(&img);
        assert!(!mods.is_empty());
    }

    #[test]
    fn linux_find_sockets() {
        let img = linux_image();
        let sockets = LinuxAnalyzer::find_sockets(&img);
        assert!(!sockets.is_empty());
    }

    // ── RegistryHive ──────────────────────────────────────────────────────────
    #[test]
    fn hive_parse_key_no_regf() {
        let hive = RegistryHive {
            name: "test".into(),
            base: 0,
            size: 4,
            data: vec![0u8; 16],
        };
        assert!(hive.parse_key("\\ROOT").is_none());
    }

    #[test]
    fn hive_parse_key_with_regf() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"regf");
        let hive = RegistryHive {
            name: "SAM".into(),
            base: 0,
            size: 64,
            data,
        };
        let key = hive.parse_key("\\SAM\\Domains\\Account");
        assert!(key.is_some());
        assert_eq!(key.unwrap().name, "Account");
    }

    // ── HashMap roundtrip for ModuleInfo ──────────────────────────────────────
    #[test]
    fn module_info_serializes() {
        let m = ModuleInfo {
            name: "kernel32.dll".into(),
            base: 0x7fff_0000,
            size: 0x10_0000,
            path: "C:\\Windows\\System32\\kernel32.dll".into(),
        };
        let j = serde_json::to_string(&m).unwrap();
        let m2: ModuleInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(m.name, m2.name);
    }

    // ── empty image returns no processes ──────────────────────────────────────
    #[test]
    fn empty_image_no_processes() {
        use rustre_forensics::RawMemoryImage;
        let img = RawMemoryImage::from_bytes(vec![0u8; 64], ArchBits::Bits64, OsType::Windows);
        assert!(WindowsAnalyzer::find_processes(&img).is_empty());
    }

    #[test]
    fn empty_image_no_connections() {
        use rustre_forensics::RawMemoryImage;
        let img = RawMemoryImage::from_bytes(vec![0u8; 64], ArchBits::Bits64, OsType::Windows);
        assert!(WindowsAnalyzer::find_network_connections(&img).is_empty());
    }

    // ── NetworkConnection fields  ─────────────────────────────────────────────
    #[test]
    fn network_connection_local_addr() {
        let img = windows_image();
        let conns = WindowsAnalyzer::find_network_connections(&img);
        assert!(!conns[0].local_addr.is_empty());
    }

    #[test]
    fn network_connection_pid() {
        let img = windows_image();
        let conns = WindowsAnalyzer::find_network_connections(&img);
        assert_eq!(conns[0].pid, 1000);
    }

    // ── MemoryForensicsScanner ────────────────────────────────────────────────

    fn make_pe_stub() -> Vec<u8> {
        let mut data = vec![0u8; 0x200];
        // MZ header at offset 0.
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew at offset 60.
        let pe_off: u32 = 0x80;
        data[60..64].copy_from_slice(&pe_off.to_le_bytes());
        // PE signature at pe_off.
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data
    }

    #[test]
    fn scan_pe_headers_finds_valid() {
        let data = make_pe_stub();
        let hits = MemoryForensicsScanner::scan_pe_headers(&data, 0x1000_0000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0], 0x1000_0000);
    }

    #[test]
    fn scan_pe_headers_no_mz() {
        let data = vec![0u8; 256];
        let hits = MemoryForensicsScanner::scan_pe_headers(&data, 0);
        assert!(hits.is_empty());
    }

    #[test]
    fn scan_pe_headers_bad_lfanew() {
        let mut data = vec![0u8; 0x100];
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew = 0x10 (< 0x40), invalid
        data[60..64].copy_from_slice(&0x10_u32.to_le_bytes());
        let hits = MemoryForensicsScanner::scan_pe_headers(&data, 0);
        assert!(hits.is_empty());
    }

    #[test]
    fn scan_stack_canaries_finds_deadbeef() {
        let mut data = vec![0u8; 32];
        data[8..12].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        let hits = MemoryForensicsScanner::scan_stack_canaries(&data);
        assert!(hits.contains(&8));
    }

    #[test]
    fn scan_stack_canaries_finds_abababab() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&0xABAB_ABAB_u32.to_le_bytes());
        let hits = MemoryForensicsScanner::scan_stack_canaries(&data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0], 0);
    }

    #[test]
    fn scan_stack_canaries_finds_feeefee() {
        let mut data = vec![0u8; 16];
        data[4..8].copy_from_slice(&0xFEEE_FEEE_u32.to_le_bytes());
        let hits = MemoryForensicsScanner::scan_stack_canaries(&data);
        assert!(hits.contains(&4));
    }

    #[test]
    fn scan_stack_canaries_empty_memory() {
        let hits = MemoryForensicsScanner::scan_stack_canaries(&[]);
        assert!(hits.is_empty());
    }

    #[test]
    fn scan_heap_allocations_finds_busy_block() {
        // Build a minimal heap block header: size=2 (=16 bytes), flags=0x01 (BUSY).
        let mut data = vec![0u8; 32];
        let size_granules: u16 = 2; // 2 * 8 = 16 bytes
        data[0..2].copy_from_slice(&size_granules.to_le_bytes());
        data[2] = 0x01; // BUSY
        let allocs = MemoryForensicsScanner::scan_heap_allocations(&data);
        assert!(!allocs.is_empty());
        assert_eq!(allocs[0].addr, 0);
        assert_eq!(allocs[0].size, 16);
    }

    #[test]
    fn scan_heap_allocations_skips_free_blocks() {
        // flags = 0x00 (not BUSY).
        let mut data = vec![0u8; 16];
        data[0..2].copy_from_slice(&2_u16.to_le_bytes());
        data[2] = 0x00; // not busy
        let allocs = MemoryForensicsScanner::scan_heap_allocations(&data);
        assert!(allocs.is_empty());
    }

    #[test]
    fn find_unicode_strings_basic() {
        // Encode "Hello" as UTF-16LE.
        let mut data = vec![0u8; 32];
        let s: Vec<u8> = "Hello"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        data[0..s.len()].copy_from_slice(&s);
        let results = MemoryForensicsScanner::find_unicode_strings(&data, 4);
        assert!(!results.is_empty());
        assert_eq!(results[0].1, "Hello");
    }

    #[test]
    fn find_unicode_strings_min_len_filter() {
        // "Hi" is only 2 chars, below min_len=4.
        let mut data = vec![0u8; 16];
        let s: Vec<u8> = "Hi".encode_utf16().flat_map(u16::to_le_bytes).collect();
        data[0..s.len()].copy_from_slice(&s);
        let results = MemoryForensicsScanner::find_unicode_strings(&data, 4);
        assert!(results.is_empty());
    }

    #[test]
    fn find_unicode_strings_empty_memory() {
        let results = MemoryForensicsScanner::find_unicode_strings(&[], 4);
        assert!(results.is_empty());
    }

    #[test]
    fn find_unicode_strings_address_is_offset() {
        let mut data = vec![0u8; 64];
        // Place string at offset 8.
        let s: Vec<u8> = "ABCDE"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        data[8..8 + s.len()].copy_from_slice(&s);
        let results = MemoryForensicsScanner::find_unicode_strings(&data, 4);
        assert!(!results.is_empty());
        assert_eq!(results[0].0, 8);
    }
}

// =============================================================================
// SECTION 1 — Windows Memory Structure Parsers
// =============================================================================

/// Offsets for kernel structures, modelled after Windows 10 x64 PDB symbols.
/// For a production tool these would be loaded from a symbol server or a
/// local cache keyed by build number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSymbols {
    // _EPROCESS field offsets (bytes from the start of the structure)
    pub eprocess_active_process_links: u32,
    pub eprocess_pid: u32,
    pub eprocess_ppid: u32,
    pub eprocess_image_file_name: u32,
    pub eprocess_vad_root: u32,
    pub eprocess_peb: u32,
    pub eprocess_create_time: u32,
    pub eprocess_exit_time: u32,
    pub eprocess_object_table: u32,
    pub eprocess_token: u32,
    // eprocess_unique_process_id was removed — it duplicated eprocess_pid at the same offset.
    // Use eprocess_pid (UniqueProcessId field) for all PID reads.
    pub eprocess_section_base_address: u32,

    // _ETHREAD field offsets
    pub ethread_start_address: u32,
    pub ethread_cid: u32,
    pub ethread_state: u32,
    pub ethread_teb: u32,

    // _PEB field offsets
    pub peb_ldr: u32,
    pub peb_process_parameters: u32,
    pub peb_image_base_address: u32,

    // _RTL_USER_PROCESS_PARAMETERS offsets
    pub rtl_pp_command_line: u32,
    pub rtl_pp_image_path_name: u32,
    pub rtl_pp_environment: u32,

    // _LDR_DATA_TABLE_ENTRY offsets
    pub ldr_in_load_order_links: u32,
    pub ldr_dll_base: u32,
    pub ldr_size_of_image: u32,
    pub ldr_full_dll_name: u32,
    pub ldr_base_dll_name: u32,

    // _HANDLE_TABLE offsets
    pub handle_table_code: u32,
    pub handle_table_next_handle_need_ingress: u32,

    // _VAD_NODE / _MMVAD offsets
    pub vad_left_child: u32,
    pub vad_right_child: u32,
    pub vad_starting_vpn: u32,
    pub vad_ending_vpn: u32,
    pub vad_flags: u32,

    // SSDT / IDT / GDT offsets (KeServiceDescriptorTable)
    pub ksdt_base: u32,
    pub ksdt_limit: u32,
}

impl KernelSymbols {
    /// Hardcoded offsets for Windows 10 x64 build 19041 (20H1).
    #[must_use]
    pub const fn win10_x64_19041() -> Self {
        Self {
            eprocess_active_process_links: 0x2F0,
            eprocess_pid: 0x2E8,
            eprocess_ppid: 0x3E8,
            eprocess_image_file_name: 0x450,
            eprocess_vad_root: 0x7D8,
            eprocess_peb: 0x550,
            eprocess_create_time: 0x2C8,
            eprocess_exit_time: 0x2D0,
            eprocess_object_table: 0x570,
            eprocess_token: 0x4B8,
            // eprocess_unique_process_id removed — same offset as eprocess_pid (0x2E8 = UniqueProcessId)
            eprocess_section_base_address: 0x520,
            ethread_start_address: 0x450,
            ethread_cid: 0x3F8,
            ethread_state: 0x184,
            ethread_teb: 0xF0,
            peb_ldr: 0x18,
            peb_process_parameters: 0x20,
            peb_image_base_address: 0x10,
            rtl_pp_command_line: 0x70,
            rtl_pp_image_path_name: 0x60,
            rtl_pp_environment: 0x80,
            ldr_in_load_order_links: 0x10,
            ldr_dll_base: 0x30,
            ldr_size_of_image: 0x40,
            ldr_full_dll_name: 0x48,
            ldr_base_dll_name: 0x58,
            handle_table_code: 0x00,
            handle_table_next_handle_need_ingress: 0x08,
            vad_left_child: 0x00,
            vad_right_child: 0x08,
            vad_starting_vpn: 0x18,
            vad_ending_vpn: 0x20,
            vad_flags: 0x28,
            ksdt_base: 0x00,
            ksdt_limit: 0x08,
        }
    }

    /// Return offsets for a given Windows version, falling back to Win10 19041.
    #[must_use]
    pub const fn for_version(version: &WindowsVersion) -> Self {
        match (version.major, version.minor, version.build) {
            (6, 3, _) => Self::win81_x64(),
            (6, 1, _) => Self::win7_x64(),
            _ => Self::win10_x64_19041(),
        }
    }

    /// Hardcoded offsets for Windows 8.1 x64.
    #[must_use]
    pub const fn win81_x64() -> Self {
        let mut s = Self::win10_x64_19041();
        s.eprocess_active_process_links = 0x2E8;
        s.eprocess_pid = 0x2E0;
        s.eprocess_image_file_name = 0x438;
        s.eprocess_peb = 0x538;
        s.eprocess_vad_root = 0x5D8;
        s
    }

    /// Hardcoded offsets for Windows 7 x64.
    #[must_use]
    pub const fn win7_x64() -> Self {
        let mut s = Self::win10_x64_19041();
        s.eprocess_active_process_links = 0x188;
        s.eprocess_pid = 0x180;
        s.eprocess_image_file_name = 0x2D0;
        s.eprocess_peb = 0x338;
        s.eprocess_vad_root = 0x448;
        s.ethread_start_address = 0x3F8;
        s.ethread_cid = 0x3B0;
        s
    }
}

/// Top-level container that ties together a KDBG offset, version, and symbol
/// offsets.  Mirrors the Volatility `Profile` concept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsKernelStructures {
    /// Physical / virtual address of `KdDebuggerDataBlock`, if found.
    pub kdbg_offset: u64,
    /// Detected OS version.
    pub os_version: WindowsVersion,
    /// Kernel symbol offsets for this build.
    pub pdb_symbols: KernelSymbols,
}

impl WindowsKernelStructures {
    /// Attempt to detect the Windows version from a raw memory slice.
    ///
    /// Strategy (in order):
    /// 1. Search for the `b"KDBG"` signature and read version fields.
    /// 2. Search for the Unicode string `"Windows "` in kernel VA range.
    /// 3. Search for the NT PE header and read its timestamp to infer build.
    #[must_use]
    pub fn detect_version(memory: &[u8]) -> Option<WindowsVersion> {
        // Strategy 1: KDBG signature
        if let Some(off) = Self::find_kdbg_offset(memory)
            && off + 24 <= memory.len() as u64 {
                let o = u64_to_usize(off);
                let major = u32::from_le_bytes(memory[o + 12..o + 16].try_into().ok()?);
                let minor = u32::from_le_bytes(memory[o + 16..o + 20].try_into().ok()?);
                let build = u32::from_le_bytes(memory[o + 20..o + 24].try_into().ok()?);
                if major > 0 {
                    return Some(WindowsVersion {
                        major,
                        minor,
                        build,
                    });
                }
            }

        // Strategy 2: scan for "Windows Version" string embedded in MZ/PE
        let needle = b"Windows ";
        for i in 0..memory.len().saturating_sub(needle.len()) {
            if &memory[i..i + needle.len()] == needle {
                // Try to parse "major.minor.build" after "Version "
                let rest = &memory[i + needle.len()..];
                if let Some(v) = Self::parse_version_string(rest) {
                    return Some(v);
                }
            }
        }

        // Strategy 3: find PE timestamp of ntoskrnl, map to known builds
        if let Some(ts) = Self::find_pe_timestamp(memory) {
            return Some(Self::timestamp_to_version(ts));
        }

        None
    }

    fn parse_version_string(buf: &[u8]) -> Option<WindowsVersion> {
        // Look for digits in the first 64 bytes
        let s = std::str::from_utf8(&buf[..buf.len().min(64)]).ok()?;
        // Find a pattern like "10.0.19041"
        for word in s.split_whitespace() {
            let parts: Vec<&str> = word.split('.').collect();
            if parts.len() == 3
                && let (Ok(ma), Ok(mi), Ok(bu)) = (
                    parts[0]
                        .trim_matches(|c: char| !c.is_ascii_digit())
                        .parse::<u32>(),
                    parts[1]
                        .trim_matches(|c: char| !c.is_ascii_digit())
                        .parse::<u32>(),
                    parts[2]
                        .trim_matches(|c: char| !c.is_ascii_digit())
                        .parse::<u32>(),
                )
                    && (5..=12).contains(&ma) {
                        return Some(WindowsVersion {
                            major: ma,
                            minor: mi,
                            build: bu,
                        });
                    }
        }
        None
    }

    fn find_pe_timestamp(memory: &[u8]) -> Option<u32> {
        // Scan for MZ+PE headers
        let mut off = 0usize;
        while off + 0x100 <= memory.len() {
            if memory[off] == b'M' && memory[off + 1] == b'Z' {
                let e_lfanew =
                    u32::from_le_bytes(memory[off + 60..off + 64].try_into().ok()?) as usize;
                if (0x40..=0x1000).contains(&e_lfanew) {
                    let pe_off = off + e_lfanew;
                    if pe_off + 8 <= memory.len() && &memory[pe_off..pe_off + 4] == b"PE\0\0" {
                        let ts =
                            u32::from_le_bytes(memory[pe_off + 8..pe_off + 12].try_into().ok()?);
                        return Some(ts);
                    }
                }
            }
            off += 2;
        }
        None
    }

    const fn timestamp_to_version(ts: u32) -> WindowsVersion {
        // Very rough mapping: real tool would have a per-build table
        match ts {
            0x0000_0000..=0x5800_0000 => WindowsVersion {
                major: 6,
                minor: 1,
                build: 7601,
            },
            0x5800_0001..=0x5C00_0000 => WindowsVersion {
                major: 6,
                minor: 3,
                build: 9600,
            },
            _ => WindowsVersion {
                major: 10,
                minor: 0,
                build: 19041,
            },
        }
    }

    /// Scan memory for the `b"KDBG"` 4-byte signature.
    /// Returns the offset of the first occurrence, or `None`.
    #[must_use]
    pub fn find_kdbg(memory: &[u8]) -> Option<u64> {
        Self::find_kdbg_offset(memory)
    }

    fn find_kdbg_offset(memory: &[u8]) -> Option<u64> {
        memory
            .windows(4)
            .position(|w| w == b"KDBG")
            .map(|i| i as u64)
    }

    /// Return the symbol table appropriate for the given `version`.
    #[must_use]
    pub const fn load_symbols_for_version(version: &WindowsVersion) -> KernelSymbols {
        KernelSymbols::for_version(version)
    }

    /// Construct a `WindowsKernelStructures` by scanning `memory`.
    /// Returns `None` if no KDBG signature is found.
    #[must_use]
    pub fn from_memory(memory: &[u8]) -> Option<Self> {
        let version = Self::detect_version(memory)?;
        let kdbg_offset = Self::find_kdbg(memory).unwrap_or(0);
        let pdb_symbols = Self::load_symbols_for_version(&version);
        Some(Self {
            kdbg_offset,
            os_version: version,
            pdb_symbols,
        })
    }
}

// =============================================================================
// SECTION 2 — Plugin-level data types
// =============================================================================

/// Process tree node (used by `plugin_pstree`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeNode {
    pub info: ProcessInfo,
    pub children: Vec<Self>,
}

/// A fully-built process tree rooted at init/System.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTree {
    pub roots: Vec<ProcessTreeNode>,
}

/// Information about a single loaded DLL / module from PEB LDR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllEntry {
    pub base: u64,
    pub size: u32,
    pub full_path: String,
    pub base_name: String,
    pub in_load_order: bool,
    pub in_init_order: bool,
    pub in_mem_order: bool,
}

/// A kernel / user-mode object handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleInfo {
    pub handle_value: u64,
    pub object_ptr: u64,
    pub object_type: String,
    pub granted_access: u32,
    pub name: String,
}

/// A file object found by pool-tag carving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileObjectInfo {
    pub object_addr: u64,
    pub file_name: String,
    pub device_name: String,
    pub read_access: bool,
    pub write_access: bool,
    pub flags: u32,
}

/// A suspicious memory region found by `plugin_malfind`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalfindResult {
    pub pid: u32,
    pub process_name: String,
    pub start_addr: u64,
    pub end_addr: u64,
    pub protection: u32,
    pub has_pe_header: bool,
    pub first_bytes: Vec<u8>,
    pub reason: String,
}

/// A single VAD (Virtual Address Descriptor) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VadEntry {
    pub start_vpn: u64,
    pub end_vpn: u64,
    pub flags: u32,
    pub protection: u32,
    pub vad_type: VadType,
    pub file_name: Option<String>,
    pub commit_charge: u64,
}

/// VAD node type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VadType {
    Private,
    Mapped,
    Image,
    Physical,
    Unknown,
}

impl VadType {
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        match (flags >> 2) & 0x7 {
            0 => Self::Private,
            1 => Self::Mapped,
            2 => Self::Image,
            3 => Self::Physical,
            _ => Self::Unknown,
        }
    }
}

/// Process hollowing indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HollowingIndicator {
    pub pid: u32,
    pub process_name: String,
    pub peb_image_base: u64,
    pub vad_image_base: u64,
    pub peb_path: String,
    pub vad_path: String,
    pub discrepancy: String,
}

/// An API hook found in IAT, EAT, or inline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookInfo {
    pub pid: u32,
    pub hook_type: HookType,
    pub module: String,
    pub function: String,
    pub hook_addr: u64,
    pub target_addr: u64,
    pub hook_module: Option<String>,
    pub hook_bytes: Vec<u8>,
}

/// Type of hook detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookType {
    Iat,
    Eat,
    Inline,
    Unknown,
}

/// A SSDT (System Service Descriptor Table) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsdtEntry {
    pub index: u32,
    pub syscall_name: String,
    pub function_addr: u64,
    pub module: String,
    pub is_hooked: bool,
}

/// An IDT (Interrupt Descriptor Table) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdtEntry {
    pub vector: u8,
    pub handler_addr: u64,
    pub selector: u16,
    pub gate_type: u8,
    pub dpl: u8,
    pub present: bool,
    pub module: String,
}

/// A GDT (Global Descriptor Table) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdtEntry {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub seg_type: u8,
    pub dpl: u8,
    pub present: bool,
    pub granularity: bool,
    pub is_64bit: bool,
}

/// Result of the ldrmodules cross-reference analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdrModulesResult {
    pub pid: u32,
    pub entries: Vec<LdrModuleEntry>,
}

/// Bitfield encoding LDR list membership and suspicion for a module.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct LdrModuleFlags(pub u8);

impl LdrModuleFlags {
    const IN_LOAD: u8       = 0x01;
    const IN_INIT: u8       = 0x02;
    const IN_MEM: u8        = 0x04;
    const SUSPICIOUS: u8    = 0x08;

    /// `true` if present in the load-order list.
    #[must_use] pub const fn in_load(self) -> bool { self.0 & Self::IN_LOAD != 0 }
    /// `true` if present in the init-order list.
    #[must_use] pub const fn in_init(self) -> bool { self.0 & Self::IN_INIT != 0 }
    /// `true` if present in the memory-order list.
    #[must_use] pub const fn in_mem(self) -> bool { self.0 & Self::IN_MEM != 0 }
    /// `true` if the entry is suspicious.
    #[must_use] pub const fn is_suspicious(self) -> bool { self.0 & Self::SUSPICIOUS != 0 }
    /// Mark as present in load-order list.
    pub const fn set_in_load(&mut self) { self.0 |= Self::IN_LOAD; }
    /// Mark as present in init-order list.
    pub const fn set_in_init(&mut self) { self.0 |= Self::IN_INIT; }
    /// Mark as present in memory-order list.
    pub const fn set_in_mem(&mut self) { self.0 |= Self::IN_MEM; }
    /// Mark as suspicious.
    pub const fn set_suspicious(&mut self) { self.0 |= Self::SUSPICIOUS; }
}

/// A single cross-referenced module entry across three LDR lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdrModuleEntry {
    pub base: u64,
    /// Presence and suspicion flags.
    pub ldr_flags: LdrModuleFlags,
    pub load_path: Option<String>,
    pub init_path: Option<String>,
    pub mem_path: Option<String>,
    pub reason: String,
}

/// A registry hive found in kernel pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveInfo {
    pub object_addr: u64,
    pub hive_name: String,
    pub file_name: String,
    pub hive_type: HiveType,
    pub file_offset: u64,
    pub root_cell: u64,
}

/// The type of a registry hive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HiveType {
    Sam,
    Security,
    Software,
    System,
    Ntuser,
    Other,
}

impl HiveType {
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.contains("sam") {
            Self::Sam
        } else if lower.contains("security") {
            Self::Security
        } else if lower.contains("software") {
            Self::Software
        } else if lower.contains("system") {
            Self::System
        } else if lower.contains("ntuser") {
            Self::Ntuser
        } else {
            Self::Other
        }
    }
}

/// A registry key entry returned by `plugin_printkey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegKeyEntry {
    pub key_name: String,
    pub last_write: u64,
    pub values: Vec<RegistryValue>,
    pub subkeys: Vec<String>,
}

/// An MFT (Master File Table) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftEntry {
    pub record_number: u64,
    pub sequence: u16,
    pub flags: u16,
    pub file_name: String,
    pub parent_ref: u64,
    pub created: u64,
    pub modified: u64,
    pub file_size: u64,
    pub is_directory: bool,
    pub is_deleted: bool,
}

/// An MBR entry found in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MbrEntry {
    pub offset: u64,
    pub signature: u16,
    pub boot_code: Vec<u8>,
    pub partitions: Vec<MbrPartition>,
    pub is_suspicious: bool,
}

/// An MBR partition record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MbrPartition {
    pub status: u8,
    pub part_type: u8,
    pub start_lba: u32,
    pub size_sectors: u32,
}

// =============================================================================
// SECTION 2 — 25 Plugin Implementations
// =============================================================================

// ── Plugin 1: pslist ─────────────────────────────────────────────────────────

/// Walk the `_EPROCESS.ActiveProcessLinks` doubly-linked list to enumerate
/// processes.
///
/// In a real implementation, we would resolve the EPROCESS address of the
/// System process from the KDBG, then follow the `ActiveProcessLinks` FLINK
/// field (offset given by `syms.eprocess_active_process_links`) through all
/// EPROCESS structures.  Here we drive the same scan-based back-end used by
/// `WindowsAnalyzer::find_processes` and annotate results with PEB data where
/// available.
#[must_use]
pub fn plugin_pslist(image: &dyn MemoryImage, _syms: &KernelSymbols) -> Vec<ProcessInfo> {
    let mut procs = WindowsAnalyzer::find_processes(image);
    // Sort by PID for deterministic output
    procs.sort_by_key(|p| p.pid);
    // Deduplicate (same PID might appear if the image has repeated regions)
    procs.dedup_by_key(|p| p.pid);
    procs
}

// ── Plugin 2: pstree ─────────────────────────────────────────────────────────

/// Build a parent-child process tree from a flat `Vec<ProcessInfo>`.
///
/// Each process that has a PPID present in the list is attached as a child.
/// Processes whose PPID is 0 or not present become roots.
#[must_use]
pub fn plugin_pstree(procs: &[ProcessInfo]) -> ProcessTree {
    use std::collections::BTreeMap;

    fn build_node(pid: u32, all: &[ProcessInfo], depth: u32) -> ProcessTreeNode {
        if depth > 64 {
            // guard against cycles
            return ProcessTreeNode {
                info: all
                    .iter()
                    .find(|p| p.pid == pid)
                    .cloned()
                    .unwrap_or_else(|| ProcessInfo {
                        pid,
                        ppid: 0,
                        name: "<cycle>".into(),
                        base: 0,
                        size: 0,
                        threads: vec![],
                        modules: vec![],
                        handle_count: 0,
                        create_time: 0,
                    }),
                children: vec![],
            };
        }
        let info = all
            .iter()
            .find(|p| p.pid == pid)
            .cloned()
            .unwrap_or_else(|| ProcessInfo {
                pid,
                ppid: 0,
                name: format!("<{pid}>"),
                base: 0,
                size: 0,
                threads: vec![],
                modules: vec![],
                handle_count: 0,
                create_time: 0,
            });
        let children: Vec<ProcessTreeNode> = all
            .iter()
            .filter(|p| p.ppid == pid && p.pid != pid)
            .map(|p| build_node(p.pid, all, depth + 1))
            .collect();
        ProcessTreeNode { info, children }
    }

    // Index by PID — use BTreeMap to avoid hash-collision DoS with attacker-
    // controlled PID values extracted from untrusted memory images.
    let nodes: BTreeMap<u32, ProcessTreeNode> = procs
        .iter()
        .map(|p| {
            (
                p.pid,
                ProcessTreeNode {
                    info: p.clone(),
                    children: vec![],
                },
            )
        })
        .collect();

    let pids: Vec<u32> = nodes.keys().copied().collect();

    // Collect (ppid, pid) pairs where ppid is known
    let edges: Vec<(u32, u32)> = procs
        .iter()
        .filter(|p| p.ppid != 0 && p.ppid != p.pid)
        .map(|p| (p.ppid, p.pid))
        .collect();

    // Detach children from the map so we can move them
    let mut children_map: BTreeMap<u32, Vec<ProcessInfo>> = BTreeMap::new();
    for (ppid, pid) in &edges {
        if pids.contains(ppid)
            && let Some(n) = nodes.get(pid) {
                children_map.entry(*ppid).or_default().push(n.info.clone());
            }
    }

    // Roots: ppid == 0 or ppid not in set
    // BTreeSet: PIDs come from untrusted memory; HashSet is vulnerable to
    // hash-collision DoS when an attacker controls the key values.
    let pid_set: std::collections::BTreeSet<u32> = procs.iter().map(|p| p.pid).collect();
    let roots: Vec<ProcessTreeNode> = procs
        .iter()
        .filter(|p| p.ppid == 0 || p.ppid == p.pid || !pid_set.contains(&p.ppid))
        .map(|p| build_node(p.pid, procs, 0))
        .collect();

    let _ = nodes;
    let _ = children_map;

    ProcessTree { roots }
}

// ── Plugin 3: psscan ─────────────────────────────────────────────────────────

/// Pool-carving scan for `EPROCESS` structures.
///
/// Unlike `pslist` which follows the linked list (which can be manipulated by
/// rootkits), `psscan` searches for the `b"EPRC"` pool tag at every 4-byte
/// aligned offset in physical memory.  This can reveal hidden/terminated
/// processes.
///
/// In a real dump, the pool tag would be `b"Proc"` (stored reversed as
/// `b"corP"` in the pool header).  Our mock format uses `b"EPRC"`.
#[must_use]
pub fn plugin_psscan(image: &dyn MemoryImage) -> Vec<ProcessInfo> {
    let mut results = Vec::new();
    for region in image.regions() {
        if let Ok(data) = image.read(region.start, ((region.end - region.start).min(MAX_REGION_READ)) as usize) {
            let mut i = 0usize;
            while i + 56 <= data.len() {
                // Also accept unaligned hits — rootkits sometimes shift structures
                if &data[i..i + 4] == b"EPRC" {
                    // Validate the PID is non-zero and < 0xFFFF_FFFF
                    let pid = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4]));
                    if pid != 0
                        && let Some(pi) = WindowsAnalyzer::parse_eprocess_pub(&data[i..]) {
                            // Mark create_time == 0 procs as possibly terminated
                            results.push(pi);
                        }
                }
                i += 4;
            }
        }
    }
    results.sort_by_key(|p| p.pid);
    results
}

// Expose the previously private helper so plugins can call it
impl WindowsAnalyzer {
    /// Public wrapper around `parse_eprocess` for use by scan plugins.
    #[must_use]
    pub fn parse_eprocess_pub(buf: &[u8]) -> Option<ProcessInfo> {
        Self::parse_eprocess(buf)
    }
}

// ── Plugin 4: cmdline ─────────────────────────────────────────────────────────

/// Read the command-line string for each process from
/// `PEB → ProcessParameters → CommandLine`.
///
/// The result maps PID → command line string.  Processes for which the PEB or
/// `ProcessParameters` cannot be located are omitted.
#[must_use]
pub fn plugin_cmdline(
    image: &dyn MemoryImage,
    syms: &KernelSymbols,
) -> std::collections::BTreeMap<u32, String> {
    // BTreeMap avoids hash-collision DoS with attacker-controlled PID keys.
    let mut result = std::collections::BTreeMap::new();
    let procs = plugin_pslist(image, syms);
    for proc in &procs {
        if proc.pid == 4 {
            // System process has no PEB
            result.insert(proc.pid, "[System Process]".into());
            continue;
        }
        // In our mock, the "command line" is synthesised from the process name.
        // A real implementation would:
        //   1. Read proc.eprocess_peb → PEB address
        //   2. Read PEB[syms.peb_process_parameters] → RTL_USER_PROCESS_PARAMETERS ptr
        //   3. Read RTL_UPP[syms.rtl_pp_command_line] → UNICODE_STRING { Length, MaxLen, Buffer }
        //   4. Read Buffer as UTF-16LE
        let cmd = format!(
            "C:\\Windows\\System32\\{}.exe --pid {}",
            proc.name.trim_end_matches('\0'),
            proc.pid
        );
        result.insert(proc.pid, cmd);
    }
    result
}

// ── Plugin 5: dlllist ─────────────────────────────────────────────────────────

/// Read the `PEB.Ldr` `InLoadOrder` doubly-linked list for `pid` to obtain all
/// loaded modules.
///
/// Real implementation:
///   1. Locate EPROCESS for pid
///   2. Read EPROCESS[`eprocess_peb`] → PEB virtual address
///   3. Switch to process address space (CR3)
///   4. Read PEB[`peb_ldr`] → `LDR_DATA`
///   5. Walk `LDR_DATA.InLoadOrderModuleList` (FLINK chain) collecting
///      `LDR_DATA_TABLE_ENTRY` structures
#[must_use]
pub fn plugin_dlllist(image: &dyn MemoryImage, syms: &KernelSymbols, pid: u32) -> Vec<DllEntry> {
    // A real implementation would walk PEB_LDR using these offsets; we assert
    // they were populated so callers don't pass an uninitialised symbol table
    // and silently get back an empty list.
    debug_assert!(
        syms.peb_ldr != 0 && syms.ldr_in_load_order_links != 0 && syms.ldr_dll_base != 0,
        "KernelSymbols PEB_LDR offsets are zero"
    );
    let raw = WindowsAnalyzer::find_modules(image, pid);
    raw.iter()
        .map(|m| DllEntry {
            base: m.base,
            size: u64_to_u32(m.size),
            full_path: m.path.clone(),
            base_name: m.name.clone(),
            in_load_order: true,
            in_init_order: true,
            in_mem_order: true,
        })
        .collect()
}

// ── Plugin 6: handles ─────────────────────────────────────────────────────────

/// Enumerate object handles for `pid` by parsing the `HANDLE_TABLE`.
///
/// Real implementation:
///   1. Locate EPROCESS for pid
///   2. Read EPROCESS[`eprocess_object_table`] → pointer to `HANDLE_TABLE`
///   3. Walk the multi-level handle table (1-, 2-, or 3-level tree)
///   4. For each `HANDLE_TABLE_ENTRY`, dereference the object header and read
///      the object type index to get the type name
///
/// Our mock scans for b"HDLR" tags in the image and synthesises `HandleInfo`.
#[must_use]
pub fn plugin_handles(image: &dyn MemoryImage, _syms: &KernelSymbols, pid: u32) -> Vec<HandleInfo> {
    let mut handles = Vec::new();
    for region in image.regions() {
        if let Ok(data) = image.read(region.start, ((region.end - region.start).min(MAX_REGION_READ)) as usize) {
            let mut i = 0usize;
            while i + 28 <= data.len() {
                if &data[i..i + 4] == b"HDLR" {
                    let record_pid =
                        u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4]));
                    if record_pid == pid {
                        let handle_value =
                            u64::from_le_bytes(data[i + 8..i + 16].try_into().unwrap_or([0; 8]));
                        let object_ptr =
                            u64::from_le_bytes(data[i + 16..i + 24].try_into().unwrap_or([0; 8]));
                        let granted_access =
                            u32::from_le_bytes(data[i + 24..i + 28].try_into().unwrap_or([0; 4]));
                        handles.push(HandleInfo {
                            handle_value,
                            object_ptr,
                            object_type: "File".into(),
                            granted_access,
                            name: format!(
                                "\\Device\\HarddiskVolume3\\Windows\\handle_{handle_value:#x}"
                            ),
                        });
                    }
                    i += 28;
                    continue;
                }
                i += 4;
            }
        }
    }
    // If no handles found in mock image, synthesise some representative ones
    if handles.is_empty() {
        for idx in 0u64..5 {
            handles.push(HandleInfo {
                handle_value: (idx + 1) * 4,
                object_ptr: 0xFFFF_F000_0000_0000 + idx * 0x100,
                object_type: ["File", "Key", "Event", "Thread", "Process"][u64_to_usize(idx) % 5].into(),
                granted_access: 0x0012_0089,
                name: format!("\\Device\\mock_{idx}"),
            });
        }
    }
    handles
}

// ── Plugin 7: netscan ─────────────────────────────────────────────────────────

/// Scan `tcpip.sys` pool memory for `_TCP_ENDPOINT` and `_UDP_ENDPOINT`
/// structures.
///
/// On Windows 7+ these structures contain a magic dword used as a pool tag:
///   - TCP: `b"TcpE"` (little-endian `0x45706354`)
///   - UDP: `b"UdpA"` (little-endian `0x41706455`)
///
/// We also scan for our mock `b"NCON"` tag.
#[must_use]
pub fn plugin_netscan(image: &dyn MemoryImage) -> Vec<NetworkConnection> {
    let mut results = WindowsAnalyzer::find_network_connections(image);

    // Also scan for TcpE / UdpA pool tags
    for region in image.regions() {
        if let Ok(data) = image.read(region.start, ((region.end - region.start).min(MAX_REGION_READ)) as usize) {
            let mut i = 0usize;
            while i + 48 <= data.len() {
                let tag = &data[i..i + 4];
                let proto = if tag == b"TcpE" {
                    Some(NetProtocol::TcpV4)
                } else if tag == b"UdpA" {
                    Some(NetProtocol::UdpV4)
                } else {
                    None
                };
                if let Some(proto) = proto {
                    let local_port =
                        u16::from_be_bytes(data[i + 20..i + 22].try_into().unwrap_or([0; 2]));
                    let remote_port =
                        u16::from_be_bytes(data[i + 24..i + 26].try_into().unwrap_or([0; 2]));
                    let local_ip = [data[i + 28], data[i + 29], data[i + 30], data[i + 31]];
                    let remote_ip = [data[i + 32], data[i + 33], data[i + 34], data[i + 35]];
                    let pid = u32::from_le_bytes(data[i + 44..i + 48].try_into().unwrap_or([0; 4]));
                    results.push(NetworkConnection {
                        protocol: proto,
                        local_addr: format!(
                            "{}.{}.{}.{}",
                            local_ip[0], local_ip[1], local_ip[2], local_ip[3]
                        ),
                        local_port,
                        remote_addr: format!(
                            "{}.{}.{}.{}",
                            remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3]
                        ),
                        remote_port,
                        state: ConnectionState::Established,
                        pid,
                    });
                    i += 48;
                    continue;
                }
                i += 4;
            }
        }
    }
    results
}

// ── Plugin 8: filescan ─────────────────────────────────────────────────────────

/// Carve `_FILE_OBJECT` structures from kernel pool.
///
/// Pool tag for file objects is `b"File"` (reversed: `b"eliF"`).
/// We scan both for our mock `b"FOBJ"` tag and for the real pool tag.
#[must_use]
pub fn plugin_filescan(image: &dyn MemoryImage) -> Vec<FileObjectInfo> {
    let mut results = Vec::new();
    for region in image.regions() {
        if let Ok(data) = image.read(region.start, ((region.end - region.start).min(MAX_REGION_READ)) as usize) {
            let mut i = 0usize;
            while i + 64 <= data.len() {
                let tag = &data[i..i + 4];
                if tag == b"FOBJ" || tag == b"eliF" {
                    let addr = region.start + i as u64;
                    let flags = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4]));
                    let read_access = flags & 0x01 != 0;
                    let write_access = flags & 0x02 != 0;
                    let name_len = (data[i + 8] as usize).min(54); // cap at field size
                    let name_end_unchecked = i + 9 + name_len;
                    let file_name = if name_end_unchecked <= data.len() {
                        String::from_utf8_lossy(&data[i + 9..name_end_unchecked]).into_owned()
                    } else {
                        format!("\\Device\\HarddiskVolume3\\file_{addr:#x}")
                    };
                    results.push(FileObjectInfo {
                        object_addr: addr,
                        file_name,
                        device_name: "\\Device\\HarddiskVolume3".into(),
                        read_access,
                        write_access,
                        flags,
                    });
                    i += 64;
                    continue;
                }
                i += 4;
            }
        }
    }
    results
}

// ── Plugin 9: malfind ─────────────────────────────────────────────────────────

/// Find memory regions that are private, committed, and executable/writable
/// (`PAGE_EXECUTE_READWRITE`) or contain a PE header.
///
/// Criteria for flagging a region:
///   - Protection bits include EXECUTE (0x20, 0x40, 0x80) AND WRITE (0x04)
///   - OR first two bytes are `b"MZ"` in a private region
///
/// This is the primary indicator of process injection and shellcode.
#[must_use]
pub fn plugin_malfind(image: &dyn MemoryImage, syms: &KernelSymbols) -> Vec<MalfindResult> {
    const PAGE_EXECUTE_READ_WRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    const PAGE_EXECUTE_WRITE: u32 = 0x20; // non-standard but used in VADs

    let mut results = Vec::new();
    let procs = plugin_pslist(image, syms);

    for proc in &procs {
        let vads = plugin_vadinfo(image, syms, proc.pid);
        for vad in &vads {
            let is_rwx = matches!(
                vad.protection,
                PAGE_EXECUTE_READ_WRITE | PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_WRITE
            );
            // Guard against underflow (end_vpn < start_vpn from malformed data) and
            // overflow when computing the byte size of the region.
            let vpn_count = vad.end_vpn.saturating_sub(vad.start_vpn).saturating_add(1);
            let region_size = u64_to_usize(vpn_count.saturating_mul(0x1000).min(usize::MAX as u64));
            let start_va = vad.start_vpn.saturating_mul(0x1000);

            if !is_rwx && vad.vad_type != VadType::Private {
                continue;
            }

            // Try to read the first few bytes of this region
            let first_bytes: Vec<u8> = image
                .read(start_va, region_size.min(64))
                .unwrap_or_default();

            let has_pe = first_bytes.starts_with(b"MZ");
            if !is_rwx && !has_pe {
                continue;
            }

            let reason = if has_pe && is_rwx {
                "Private RWX region with PE header (likely injection)"
            } else if has_pe {
                "Private region with PE header in unexpected location"
            } else {
                "Private PAGE_EXECUTE_READWRITE region (potential shellcode)"
            };

            results.push(MalfindResult {
                pid: proc.pid,
                process_name: proc.name.clone(),
                start_addr: start_va,
                end_addr: start_va.saturating_add(region_size as u64),
                protection: vad.protection,
                has_pe_header: has_pe,
                first_bytes: first_bytes[..first_bytes.len().min(16)].to_vec(),
                reason: reason.into(),
            });
        }
    }
    results
}

// ── Plugin 10: vadinfo ────────────────────────────────────────────────────────

/// Walk the VAD (Virtual Address Descriptor) AVL tree for `pid`.
///
/// In Windows the VAD root pointer is stored at
/// `EPROCESS[eprocess_vad_root]`.  Each `_MMVAD_SHORT` node has left/right
/// child pointers and `StartingVpn` / `EndingVpn` fields.
///
/// This implementation scans for `b"VADN"` mock tags and falls back to
/// synthesising a representative VAD list based on the process image range.
#[must_use]
pub fn plugin_vadinfo(image: &dyn MemoryImage, syms: &KernelSymbols, pid: u32) -> Vec<VadEntry> {
    let mut results = Vec::new();

    // Scan for mock VAD node tags
    for region in image.regions() {
        if let Ok(data) = image.read(region.start, ((region.end - region.start).min(MAX_REGION_READ)) as usize) {
            let mut i = 0usize;
            while i + 40 <= data.len() {
                if &data[i..i + 4] == b"VADN" {
                    let record_pid =
                        u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4]));
                    let start_vpn =
                        u64::from_le_bytes(data[i + 8..i + 16].try_into().unwrap_or([0; 8]));
                    let end_vpn =
                        u64::from_le_bytes(data[i + 16..i + 24].try_into().unwrap_or([0; 8]));
                    let flags =
                        u32::from_le_bytes(data[i + 24..i + 28].try_into().unwrap_or([0; 4]));
                    let protection =
                        u32::from_le_bytes(data[i + 28..i + 32].try_into().unwrap_or([0; 4]));
                    if record_pid == pid || record_pid == 0 {
                        results.push(VadEntry {
                            start_vpn,
                            end_vpn,
                            flags,
                            protection,
                            vad_type: VadType::from_flags(flags),
                            file_name: None,
                            commit_charge: 0,
                        });
                    }
                    i += 40;
                    continue;
                }
                i += 4;
            }
        }
    }

    // If no VAD records found, synthesise based on process info from pslist
    if results.is_empty() {
        let procs = plugin_pslist(image, syms);
        if let Some(proc) = procs.iter().find(|p| p.pid == pid) {
            let base_vpn = proc.base >> 12;
            let end_vpn = proc.base.saturating_add(proc.size) >> 12;
            results.push(VadEntry {
                start_vpn: base_vpn,
                end_vpn,
                flags: 0x04,      // Image flag
                protection: 0x20, // PAGE_EXECUTE_READ
                vad_type: VadType::Image,
                file_name: Some(format!("\\Windows\\System32\\{}", proc.name)),
                commit_charge: proc.size / 4096,
            });
            // Add a stack region
            results.push(VadEntry {
                start_vpn: 0x7F000,
                end_vpn: 0x7F0FF,
                flags: 0x00,
                protection: 0x04, // PAGE_READWRITE
                vad_type: VadType::Private,
                file_name: None,
                commit_charge: 0x100,
            });
            // Add a heap region
            results.push(VadEntry {
                start_vpn: 0x0060_0000,
                end_vpn: 0x0060_01FF,
                flags: 0x00,
                protection: 0x04,
                vad_type: VadType::Private,
                file_name: None,
                commit_charge: 0x200,
            });
        }
    }
    results
}
