//! Memory forensics: kernel object search, pool tag scanning,
//! network connections from kernel structures, hidden driver detection,
//! code-injection pattern recognition, and malware artifact correlation.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::casts::usize_to_u32;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MemForensicsError {
    #[error("read error at 0x{addr:016x}: {msg}")]
    ReadError { addr: u64, msg: String },
    #[error("alignment error: address 0x{addr:016x} not aligned to {align}")]
    AlignmentError { addr: u64, align: usize },
    #[error("pool tag not found: {0}")]
    PoolTagNotFound(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

// ── KernelObjectSearch ────────────────────────────────────────────────────────

/// Type of kernel object being searched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KernelObjectType {
    Process,
    Thread,
    File,
    Event,
    Mutex,
    Semaphore,
    Section,
    Port,
    SymbolicLink,
    Token,
    Driver,
    Device,
}

/// A found kernel object in memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelObject {
    pub object_type: KernelObjectType,
    pub address: u64,
    pub name: Option<String>,
    pub handle_count: u32,
    pub pointer_count: u32,
    pub pool_tag: Option<[u8; 4]>,
}

impl KernelObject {
    #[must_use] 
    pub const fn new(object_type: KernelObjectType, address: u64) -> Self {
        Self {
            object_type,
            address,
            name: None,
            handle_count: 0,
            pointer_count: 0,
            pool_tag: None,
        }
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use] 
    pub const fn with_pool_tag(mut self, tag: [u8; 4]) -> Self {
        self.pool_tag = Some(tag);
        self
    }
}

/// Searches memory for kernel objects by scanning pool headers.
pub struct KernelObjectSearch<'a> {
    memory: &'a [u8],
    base_address: u64,
    arch_bits: u8,
}

impl<'a> KernelObjectSearch<'a> {
    #[must_use] 
    pub const fn new(memory: &'a [u8], base_address: u64, arch_bits: u8) -> Self {
        Self {
            memory,
            base_address,
            arch_bits,
        }
    }

    /// Read a little-endian u32 at a given offset.
    fn read_u32(&self, offset: usize) -> Result<u32, MemForensicsError> {
        if offset + 4 > self.memory.len() {
            return Err(MemForensicsError::ReadError {
                addr: self.base_address + offset as u64,
                msg: "out of bounds".into(),
            });
        }
        Ok(u32::from_le_bytes([
            self.memory[offset],
            self.memory[offset + 1],
            self.memory[offset + 2],
            self.memory[offset + 3],
        ]))
    }

    /// Read a little-endian u64 at a given offset.
    fn read_u64(&self, offset: usize) -> Result<u64, MemForensicsError> {
        if offset + 8 > self.memory.len() {
            return Err(MemForensicsError::ReadError {
                addr: self.base_address + offset as u64,
                msg: "out of bounds".into(),
            });
        }
        Ok(u64::from_le_bytes([
            self.memory[offset],
            self.memory[offset + 1],
            self.memory[offset + 2],
            self.memory[offset + 3],
            self.memory[offset + 4],
            self.memory[offset + 5],
            self.memory[offset + 6],
            self.memory[offset + 7],
        ]))
    }

    /// Scan memory for a 4-byte pool tag and collect hit addresses.
    #[must_use] 
    pub fn scan_for_tag(&self, tag: &[u8; 4]) -> Vec<u64> {
        let mut hits = Vec::new();
        let len = self.memory.len();
        if len < 4 {
            return hits;
        }
        for i in 0..len - 3 {
            if &self.memory[i..i + 4] == tag {
                hits.push(self.base_address + i as u64);
            }
        }
        hits
    }

    /// Try to read an EPROCESS-like object name at an offset (simplified).
    #[must_use] 
    pub fn read_image_name(&self, offset: usize, len: usize) -> Option<String> {
        if offset + len > self.memory.len() {
            return None;
        }
        let bytes = &self.memory[offset..offset + len];
        let name: String = bytes
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '?'
                }
            })
            .collect();
        if name.is_empty() { None } else { Some(name) }
    }

    /// Pointer size in bytes.
    #[must_use] 
    pub const fn ptr_size(&self) -> usize {
        if self.arch_bits == 64 { 8 } else { 4 }
    }

    /// Read a native pointer at offset.
    ///
    /// # Errors
    ///
    /// Returns [`MemForensicsError`] if the read would exceed the region bounds.
    pub fn read_ptr(&self, offset: usize) -> Result<u64, MemForensicsError> {
        if self.arch_bits == 64 {
            self.read_u64(offset)
        } else {
            self.read_u32(offset).map(u64::from)
        }
    }
}

// ── PoolTagScanner ────────────────────────────────────────────────────────────

/// Known Windows pool tags and associated object types.
pub static KNOWN_POOL_TAGS: &[([u8; 4], &str, KernelObjectType)] = &[
    (*b"Proc", "EPROCESS", KernelObjectType::Process),
    (*b"Thre", "ETHREAD", KernelObjectType::Thread),
    (*b"File", "FILE_OBJECT", KernelObjectType::File),
    (*b"Even", "KEVENT", KernelObjectType::Event),
    (*b"Mutw", "KMUTANT", KernelObjectType::Mutex),
    (*b"Sema", "KSEMAPHORE", KernelObjectType::Semaphore),
    (*b"Sect", "SECTION", KernelObjectType::Section),
    (*b"Port", "ALPC_PORT", KernelObjectType::Port),
    (*b"Driv", "DRIVER_OBJECT", KernelObjectType::Driver),
    (*b"Devi", "DEVICE_OBJECT", KernelObjectType::Device),
    (*b"Toke", "TOKEN", KernelObjectType::Token),
];

/// Pool-tag scanner that correlates raw tag hits with object types.
pub struct PoolTagScanner {
    pub hits: HashMap<[u8; 4], Vec<u64>>,
}

impl PoolTagScanner {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            hits: HashMap::new(),
        }
    }

    /// Scan a memory slice for all known pool tags.
    pub fn scan(&mut self, memory: &[u8], base: u64) {
        let searcher = KernelObjectSearch::new(memory, base, 64);
        for (tag, _, _) in KNOWN_POOL_TAGS {
            let hits = searcher.scan_for_tag(tag);
            if !hits.is_empty() {
                self.hits.insert(*tag, hits);
            }
        }
    }

    /// Return all hits for a specific tag string (4 bytes).
    #[must_use] 
    pub fn hits_for_tag(&self, tag: &[u8; 4]) -> &[u64] {
        self.hits.get(tag).map_or(&[], std::vec::Vec::as_slice)
    }

    /// Count total tag hits.
    #[must_use] 
    pub fn total_hits(&self) -> usize {
        self.hits.values().map(std::vec::Vec::len).sum()
    }

    /// Return object type for a tag if known.
    #[must_use] 
    pub fn object_type_for_tag(tag: &[u8; 4]) -> Option<KernelObjectType> {
        KNOWN_POOL_TAGS
            .iter()
            .find(|(t, _, _)| t == tag)
            .map(|(_, _, ty)| *ty)
    }
}

impl Default for PoolTagScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ── NetworkConnections ────────────────────────────────────────────────────────

/// A network connection reconstructed from kernel TCP/IP structures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: NetProtocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: TcpState,
    pub owner_pid: Option<u32>,
    pub owner_process: Option<String>,
    pub created_time: Option<u64>,
    pub address_in_memory: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetProtocol {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown(u8),
}

impl TcpState {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Closed,
            2 => Self::Listen,
            3 => Self::SynSent,
            4 => Self::SynReceived,
            5 => Self::Established,
            6 => Self::FinWait1,
            7 => Self::FinWait2,
            8 => Self::CloseWait,
            9 => Self::Closing,
            10 => Self::LastAck,
            11 => Self::TimeWait,
            12 => Self::DeleteTcb,
            _ => Self::Unknown(v),
        }
    }

    #[must_use] 
    pub const fn is_established(&self) -> bool {
        matches!(self, Self::Established)
    }

    #[must_use] 
    pub const fn is_listening(&self) -> bool {
        matches!(self, Self::Listen)
    }
}

/// Reconstructs network connections from a parsed-structures list.
pub struct NetworkConnections {
    pub connections: Vec<NetworkConnection>,
}

impl NetworkConnections {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            connections: Vec::new(),
        }
    }

    pub fn add(&mut self, conn: NetworkConnection) {
        self.connections.push(conn);
    }

    /// Return only established connections.
    #[must_use] 
    pub fn established(&self) -> Vec<&NetworkConnection> {
        self.connections
            .iter()
            .filter(|c| c.state.is_established())
            .collect()
    }

    /// Return only listening connections.
    #[must_use] 
    pub fn listening(&self) -> Vec<&NetworkConnection> {
        self.connections
            .iter()
            .filter(|c| c.state.is_listening())
            .collect()
    }

    /// Return connections owned by a specific PID.
    #[must_use] 
    pub fn by_pid(&self, pid: u32) -> Vec<&NetworkConnection> {
        self.connections
            .iter()
            .filter(|c| c.owner_pid == Some(pid))
            .collect()
    }

    /// Return connections to a specific remote address.
    #[must_use] 
    pub fn by_remote(&self, remote: &str) -> Vec<&NetworkConnection> {
        self.connections
            .iter()
            .filter(|c| c.remote_addr == remote)
            .collect()
    }

    /// Check for suspicious outbound ports (C2 indicators).
    #[must_use] 
    pub fn suspicious_outbound(&self) -> Vec<&NetworkConnection> {
        let suspicious_ports = [4444, 4445, 8888, 1337, 31337, 9001, 9050];
        self.connections
            .iter()
            .filter(|c| c.state.is_established() && suspicious_ports.contains(&c.remote_port))
            .collect()
    }
}

impl Default for NetworkConnections {
    fn default() -> Self {
        Self::new()
    }
}

// ── HiddenDriver ─────────────────────────────────────────────────────────────

/// Evidence of a hidden driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenDriver {
    pub base_address: u64,
    pub size: u64,
    pub name: Option<String>,
    pub reason: HidingReason,
    pub code_signature_valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HidingReason {
    /// Module not in `PsLoadedModuleList`.
    NotInModuleList,
    /// Module not in `InLoadOrderModuleList`.
    NotInLdrList,
    /// Driver object not in `IoDriverObjectType` type list.
    NotInDriverList,
    /// DKOM: object links patched.
    DkomRemoved,
    /// PE header wiped from memory.
    PeHeaderWiped,
    /// Invalid or spoofed driver name.
    NameSpoofed,
}

/// Hidden driver detector: cross-references multiple module lists.
pub struct HiddenDriverDetector {
    pub module_list_drivers: Vec<(u64, String)>,
    pub pool_tag_drivers: Vec<(u64, Option<String>)>,
    pub hidden: Vec<HiddenDriver>,
}

impl HiddenDriverDetector {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            module_list_drivers: Vec::new(),
            pool_tag_drivers: Vec::new(),
            hidden: Vec::new(),
        }
    }

    /// Add a module found in `PsLoadedModuleList`.
    pub fn add_module_list_entry(&mut self, base: u64, name: impl Into<String>) {
        self.module_list_drivers.push((base, name.into()));
    }

    /// Add a driver found via pool tag scanning.
    pub fn add_pool_tag_driver(&mut self, base: u64, name: Option<String>) {
        self.pool_tag_drivers.push((base, name));
    }

    /// Detect drivers in pool scan that are not in module list.
    pub fn detect_hidden(&mut self) {
        let known_bases: Vec<u64> = self.module_list_drivers.iter().map(|(b, _)| *b).collect();
        for (base, name) in &self.pool_tag_drivers {
            if !known_bases.contains(base) {
                self.hidden.push(HiddenDriver {
                    base_address: *base,
                    size: 0,
                    name: name.clone(),
                    reason: HidingReason::NotInModuleList,
                    code_signature_valid: false,
                });
            }
        }
    }

    #[must_use] 
    pub const fn hidden_count(&self) -> usize {
        self.hidden.len()
    }
}

impl Default for HiddenDriverDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── CodeInjection ─────────────────────────────────────────────────────────────

/// Patterns indicating code injection into a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeInjection {
    pub technique: InjectionTechnique,
    pub target_pid: u32,
    pub target_process: Option<String>,
    pub injected_region: Option<MemoryRegion>,
    pub evidence: Vec<String>,
    pub confidence: u8, // 0-100
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InjectionTechnique {
    ClassicDllInjection,
    ReflectiveDllInjection,
    ProcessHollowing,
    AtomBombing,
    EarlyBirdApc,
    NtCreateThreadEx,
    SetWindowsHookEx,
    ManualMap,
    Ghostwriting,
    TransactedHollowing,
    HeapSpraying,
}

/// A suspicious memory region inside a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub protection: MemProtect,
    pub state: RegionState,
    pub region_type: RegionType,
    pub entropy: Option<u16>, // * 100
    pub has_pe_header: bool,
    pub has_executable_code: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemProtect {
    NoAccess,
    Readonly,
    ReadWrite,
    WriteCopy,
    Execute,
    ExecuteRead,
    ExecuteReadWrite,
    ExecuteWriteCopy,
    Guard,
    NoCache,
    WriteCombine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionState {
    Free,
    Reserved,
    Committed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionType {
    Image,
    Mapped,
    Private,
}

impl MemoryRegion {
    /// Suspicious if RWX or RX private memory with high entropy.
    #[must_use] 
    pub const fn is_suspicious(&self) -> bool {
        let rwx = matches!(
            self.protection,
            MemProtect::ExecuteReadWrite | MemProtect::ExecuteRead | MemProtect::Execute
        );
        let private = matches!(self.region_type, RegionType::Private);
        rwx && private
    }

    /// Entropy as f32 (stored * 100 as u16).
    #[must_use] 
    pub fn entropy_f32(&self) -> Option<f32> {
        self.entropy.map(|e| f32::from(e) / 100.0)
    }
}

/// Code injection scanner.
pub struct CodeInjectionScanner;

impl CodeInjectionScanner {
    /// Heuristically detect suspicious regions in a list of memory regions.
    #[must_use] 
    pub fn scan_regions(
        pid: u32,
        process_name: Option<&str>,
        regions: &[MemoryRegion],
    ) -> Vec<CodeInjection> {
        let mut found = Vec::new();
        for region in regions {
            if !region.is_suspicious() {
                continue;
            }
            let mut evidence = Vec::new();
            let mut technique = InjectionTechnique::ClassicDllInjection;
            let mut confidence = if region.has_pe_header {
                evidence.push("PE header in private RWX region".into());
                technique = InjectionTechnique::ReflectiveDllInjection;
                80u8
            } else {
                50u8
            };

            if let Some(ent) = region.entropy_f32()
                && ent > 7.0 {
                    evidence.push(format!("High entropy ({ent:.2})"));
                    confidence = confidence.saturating_add(10);
                }

            if region.size > 0x10_0000 {
                evidence.push("Large private executable region".into());
            }

            if region.has_executable_code && region.region_type == RegionType::Private {
                evidence.push("Private executable code".into());
            }

            found.push(CodeInjection {
                technique,
                target_pid: pid,
                target_process: process_name.map(std::borrow::ToOwned::to_owned),
                injected_region: Some(region.clone()),
                evidence,
                confidence: confidence.min(100),
            });
        }
        found
    }
}

// ── MalwareArtifacts ─────────────────────────────────────────────────────────

/// Aggregated malware artifact findings from memory.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MalwareArtifacts {
    pub hidden_drivers: Vec<HiddenDriver>,
    pub code_injections: Vec<CodeInjection>,
    pub suspicious_connections: Vec<NetworkConnection>,
    pub suspicious_strings: Vec<SuspiciousString>,
    pub kernel_hooks: Vec<KernelHook>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspiciousString {
    pub value: String,
    pub address: u64,
    pub category: StringCategory,
    pub confidence: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringCategory {
    C2Domain,
    C2IpPort,
    MalwarePath,
    RegistryKey,
    Credential,
    CryptographicKey,
    Base64Payload,
    ShellCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelHook {
    pub hook_type: HookType,
    pub hooked_address: u64,
    pub original_target: Option<u64>,
    pub hook_destination: u64,
    pub hook_module: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookType {
    SsdtInline,
    SsdtEntry,
    IatEntry,
    EatEntry,
    Dkom,
    IdtEntry,
    MsrHook,
}

/// Top-level memory forensics analyser.
pub struct MemoryForensics<'a> {
    pub memory: &'a [u8],
    pub base_address: u64,
    pub arch_bits: u8,
    pub artifacts: MalwareArtifacts,
}

impl<'a> MemoryForensics<'a> {
    #[must_use] 
    pub fn new(memory: &'a [u8], base_address: u64, arch_bits: u8) -> Self {
        Self {
            memory,
            base_address,
            arch_bits,
            artifacts: MalwareArtifacts::default(),
        }
    }

    /// Run pool-tag scanning and return counts.
    #[must_use] 
    pub fn pool_tag_scan(&self) -> PoolTagScanner {
        let mut scanner = PoolTagScanner::new();
        scanner.scan(self.memory, self.base_address);
        scanner
    }

    /// Quick-scan for ASCII strings matching known malware indicators.
    pub fn scan_strings(&mut self) {
        let indicators: &[(&str, StringCategory, u8)] = &[
            ("cmd.exe /c", StringCategory::ShellCommand, 70),
            ("powershell -e", StringCategory::ShellCommand, 80),
            ("mimikatz", StringCategory::Credential, 95),
            ("sekurlsa", StringCategory::Credential, 90),
            (
                "HKEY_LOCAL_MACHINE\\SOFTWARE",
                StringCategory::RegistryKey,
                60,
            ),
            ("CreateRemoteThread", StringCategory::C2IpPort, 75),
            ("VirtualAllocEx", StringCategory::C2IpPort, 70),
        ];

        let memory_str = String::from_utf8_lossy(self.memory);
        for (indicator, category, confidence) in indicators {
            if let Some(pos) = memory_str.find(indicator) {
                self.artifacts.suspicious_strings.push(SuspiciousString {
                    value: indicator.to_string(),
                    address: self.base_address + pos as u64,
                    category: *category,
                    confidence: *confidence,
                });
            }
        }
    }

    /// Summary: is this memory image suspicious?
    #[must_use] 
    pub const fn is_suspicious(&self) -> bool {
        !self.artifacts.hidden_drivers.is_empty()
            || !self.artifacts.code_injections.is_empty()
            || !self.artifacts.suspicious_connections.is_empty()
            || !self.artifacts.suspicious_strings.is_empty()
    }

    /// High confidence score (0-100) based on artifact counts.
    #[must_use] 
    pub fn malware_score(&self) -> u8 {
        // Use saturating arithmetic to avoid overflow when many artifacts are present.
        let mut score = 0u32;
        score = score.saturating_add(
            usize_to_u32(self.artifacts.hidden_drivers.len()).saturating_mul(25),
        );
        score = score.saturating_add(
            usize_to_u32(self.artifacts.code_injections.len()).saturating_mul(20),
        );
        score = score.saturating_add(
            usize_to_u32(self.artifacts.suspicious_connections.len()).saturating_mul(10),
        );
        score = score.saturating_add(
            usize_to_u32(self.artifacts.suspicious_strings.len()).saturating_mul(5),
        );
        score = score.saturating_add(
            usize_to_u32(self.artifacts.kernel_hooks.len()).saturating_mul(30),
        );
        score.min(100) as u8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_memory(size: usize) -> Vec<u8> {
        let mut mem = vec![0u8; size];
        // embed known pool tag "Proc" at offset 16
        mem[16..20].copy_from_slice(b"Proc");
        // embed another at 512
        if mem.len() > 516 {
            mem[512..516].copy_from_slice(b"Thre");
        }
        // embed suspicious string
        let s = b"mimikatz";
        if mem.len() > 1024 + s.len() {
            mem[1024..1024 + s.len()].copy_from_slice(s);
        }
        mem
    }

    // ── KernelObjectSearch tests ────────────────────────────────────────────

    #[test]
    fn test_scan_for_tag_found() {
        let mem = make_test_memory(2048);
        let searcher = KernelObjectSearch::new(&mem, 0xFFFF_8000_0000_0000, 64);
        let hits = searcher.scan_for_tag(b"Proc");
        assert!(!hits.is_empty());
        assert_eq!(hits[0], 0xFFFF_8000_0000_0000 + 16);
    }

    #[test]
    fn test_scan_for_tag_not_found() {
        let mem = vec![0u8; 256];
        let searcher = KernelObjectSearch::new(&mem, 0, 64);
        let hits = searcher.scan_for_tag(b"ZZZZ");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_read_image_name() {
        let mut mem = vec![0u8; 64];
        mem[10..17].copy_from_slice(b"notepad");
        let searcher = KernelObjectSearch::new(&mem, 0, 64);
        let name = searcher.read_image_name(10, 15);
        assert_eq!(name, Some("notepad".to_string()));
    }

    #[test]
    fn test_read_image_name_out_of_bounds() {
        let mem = vec![0u8; 10];
        let searcher = KernelObjectSearch::new(&mem, 0, 64);
        let name = searcher.read_image_name(5, 100);
        assert!(name.is_none());
    }

    #[test]
    fn test_ptr_size_64() {
        let mem = vec![0u8; 8];
        let s = KernelObjectSearch::new(&mem, 0, 64);
        assert_eq!(s.ptr_size(), 8);
    }

    #[test]
    fn test_ptr_size_32() {
        let mem = vec![0u8; 8];
        let s = KernelObjectSearch::new(&mem, 0, 32);
        assert_eq!(s.ptr_size(), 4);
    }

    #[test]
    fn test_read_ptr_64() {
        let val: u64 = 0xDEAD_BEEF_1234_5678;
        let mem = val.to_le_bytes().to_vec();
        let s = KernelObjectSearch::new(&mem, 0, 64);
        assert_eq!(s.read_ptr(0).unwrap(), val);
    }

    #[test]
    fn test_read_ptr_32() {
        let val: u32 = 0xDEAD_BEEF;
        let mem = val.to_le_bytes().to_vec();
        let s = KernelObjectSearch::new(&mem, 0, 32);
        assert_eq!(s.read_ptr(0).unwrap(), u64::from(val));
    }

    // ── PoolTagScanner tests ─────────────────────────────────────────────────

    #[test]
    fn test_pool_tag_scanner_finds_proc() {
        let mem = make_test_memory(2048);
        let mut scanner = PoolTagScanner::new();
        scanner.scan(&mem, 0);
        assert!(!scanner.hits_for_tag(b"Proc").is_empty());
    }

    #[test]
    fn test_pool_tag_scanner_finds_thread() {
        let mem = make_test_memory(2048);
        let mut scanner = PoolTagScanner::new();
        scanner.scan(&mem, 0);
        assert!(!scanner.hits_for_tag(b"Thre").is_empty());
    }

    #[test]
    fn test_pool_tag_scanner_total_hits() {
        let mem = make_test_memory(2048);
        let mut scanner = PoolTagScanner::new();
        scanner.scan(&mem, 0);
        assert!(scanner.total_hits() >= 2);
    }

    #[test]
    fn test_pool_tag_object_type() {
        let ty = PoolTagScanner::object_type_for_tag(b"Proc");
        assert_eq!(ty, Some(KernelObjectType::Process));
    }

    #[test]
    fn test_pool_tag_object_type_unknown() {
        let ty = PoolTagScanner::object_type_for_tag(b"ZZZZ");
        assert!(ty.is_none());
    }

    // ── TcpState tests ───────────────────────────────────────────────────────

    #[test]
    fn test_tcp_state_established() {
        assert!(TcpState::from_u8(5).is_established());
    }

    #[test]
    fn test_tcp_state_listen() {
        assert!(TcpState::from_u8(2).is_listening());
    }

    #[test]
    fn test_tcp_state_unknown() {
        assert_eq!(TcpState::from_u8(99), TcpState::Unknown(99));
    }

    #[test]
    fn test_tcp_state_all_known() {
        for i in 1u8..=12 {
            assert!(!matches!(TcpState::from_u8(i), TcpState::Unknown(_)));
        }
    }

    // ── NetworkConnections tests ─────────────────────────────────────────────

    #[test]
    fn test_network_connections_established() {
        let mut nc = NetworkConnections::new();
        nc.add(NetworkConnection {
            protocol: NetProtocol::Tcp4,
            local_addr: "127.0.0.1".into(),
            local_port: 12345,
            remote_addr: "1.2.3.4".into(),
            remote_port: 443,
            state: TcpState::Established,
            owner_pid: Some(1234),
            owner_process: Some("evil.exe".into()),
            created_time: None,
            address_in_memory: 0xFFFF_0000,
        });
        assert_eq!(nc.established().len(), 1);
        assert!(nc.listening().is_empty());
    }

    #[test]
    fn test_network_connections_by_pid() {
        let mut nc = NetworkConnections::new();
        nc.add(NetworkConnection {
            protocol: NetProtocol::Tcp4,
            local_addr: "0.0.0.0".into(),
            local_port: 80,
            remote_addr: "0.0.0.0".into(),
            remote_port: 0,
            state: TcpState::Listen,
            owner_pid: Some(4),
            owner_process: Some("System".into()),
            created_time: None,
            address_in_memory: 0x1000,
        });
        assert_eq!(nc.by_pid(4).len(), 1);
        assert!(nc.by_pid(99).is_empty());
    }

    #[test]
    fn test_network_connections_suspicious_port() {
        let mut nc = NetworkConnections::new();
        nc.add(NetworkConnection {
            protocol: NetProtocol::Tcp4,
            local_addr: "127.0.0.1".into(),
            local_port: 9999,
            remote_addr: "1.2.3.4".into(),
            remote_port: 4444, // Metasploit default
            state: TcpState::Established,
            owner_pid: Some(666),
            owner_process: None,
            created_time: None,
            address_in_memory: 0x2000,
        });
        assert_eq!(nc.suspicious_outbound().len(), 1);
    }

    #[test]
    fn test_network_connections_by_remote() {
        let mut nc = NetworkConnections::new();
        nc.add(NetworkConnection {
            protocol: NetProtocol::Tcp4,
            local_addr: "10.0.0.1".into(),
            local_port: 1234,
            remote_addr: "evil.c2".into(),
            remote_port: 443,
            state: TcpState::Established,
            owner_pid: None,
            owner_process: None,
            created_time: None,
            address_in_memory: 0x3000,
        });
        assert_eq!(nc.by_remote("evil.c2").len(), 1);
    }

    // ── HiddenDriverDetector tests ───────────────────────────────────────────

    #[test]
    fn test_hidden_driver_detected() {
        let mut det = HiddenDriverDetector::new();
        det.add_module_list_entry(0x1000_0000, "ntoskrnl.exe");
        det.add_pool_tag_driver(0x2000_0000, Some("rootkit.sys".into())); // not in list
        det.detect_hidden();
        assert_eq!(det.hidden_count(), 1);
        assert_eq!(det.hidden[0].reason, HidingReason::NotInModuleList);
    }

    #[test]
    fn test_no_hidden_driver_when_all_known() {
        let mut det = HiddenDriverDetector::new();
        det.add_module_list_entry(0x1000_0000, "ntoskrnl.exe");
        det.add_pool_tag_driver(0x1000_0000, Some("ntoskrnl.exe".into()));
        det.detect_hidden();
        assert_eq!(det.hidden_count(), 0);
    }

    // ── MemoryRegion / CodeInjection tests ───────────────────────────────────

    #[test]
    fn test_memory_region_suspicious_rwx_private() {
        let r = MemoryRegion {
            base: 0x10000,
            size: 0x1000,
            protection: MemProtect::ExecuteReadWrite,
            state: RegionState::Committed,
            region_type: RegionType::Private,
            entropy: Some(750),
            has_pe_header: false,
            has_executable_code: true,
        };
        assert!(r.is_suspicious());
    }

    #[test]
    fn test_memory_region_not_suspicious_image() {
        let r = MemoryRegion {
            base: 0x70000000,
            size: 0x5000,
            protection: MemProtect::ExecuteRead,
            state: RegionState::Committed,
            region_type: RegionType::Image,
            entropy: Some(600),
            has_pe_header: true,
            has_executable_code: true,
        };
        assert!(!r.is_suspicious());
    }

    #[test]
    fn test_code_injection_scanner_finds_pe_header() {
        let region = MemoryRegion {
            base: 0x10000,
            size: 0x5000,
            protection: MemProtect::ExecuteReadWrite,
            state: RegionState::Committed,
            region_type: RegionType::Private,
            entropy: Some(750),
            has_pe_header: true,
            has_executable_code: true,
        };
        let injections = CodeInjectionScanner::scan_regions(1234, Some("svchost.exe"), &[region]);
        assert_eq!(injections.len(), 1);
        assert_eq!(
            injections[0].technique,
            InjectionTechnique::ReflectiveDllInjection
        );
        assert!(injections[0].confidence >= 80);
    }

    #[test]
    fn test_code_injection_no_suspicious_regions() {
        let region = MemoryRegion {
            base: 0x10000,
            size: 0x1000,
            protection: MemProtect::ReadWrite,
            state: RegionState::Committed,
            region_type: RegionType::Private,
            entropy: Some(300),
            has_pe_header: false,
            has_executable_code: false,
        };
        let injections = CodeInjectionScanner::scan_regions(999, None, &[region]);
        assert!(injections.is_empty());
    }

    #[test]
    fn test_entropy_f32() {
        let r = MemoryRegion {
            base: 0,
            size: 0,
            protection: MemProtect::ReadWrite,
            state: RegionState::Committed,
            region_type: RegionType::Private,
            entropy: Some(725),
            has_pe_header: false,
            has_executable_code: false,
        };
        assert!((r.entropy_f32().unwrap() - 7.25).abs() < 0.01);
    }

    // ── MemoryForensics tests ────────────────────────────────────────────────

    #[test]
    fn test_memory_forensics_scan_strings() {
        let mem = make_test_memory(2048);
        let mut mf = MemoryForensics::new(&mem, 0, 64);
        mf.scan_strings();
        assert!(!mf.artifacts.suspicious_strings.is_empty());
        assert!(
            mf.artifacts
                .suspicious_strings
                .iter()
                .any(|s| s.value == "mimikatz")
        );
    }

    #[test]
    fn test_memory_forensics_not_suspicious_clean() {
        let mem = vec![0u8; 512];
        let mf = MemoryForensics::new(&mem, 0, 64);
        assert!(!mf.is_suspicious());
    }

    #[test]
    fn test_memory_forensics_is_suspicious_with_hidden_driver() {
        let mem = vec![0u8; 512];
        let mut mf = MemoryForensics::new(&mem, 0, 64);
        mf.artifacts.hidden_drivers.push(HiddenDriver {
            base_address: 0x1234,
            size: 0x1000,
            name: Some("evil.sys".into()),
            reason: HidingReason::NotInModuleList,
            code_signature_valid: false,
        });
        assert!(mf.is_suspicious());
    }

    #[test]
    fn test_malware_score_zero_clean() {
        let mem = vec![0u8; 512];
        let mf = MemoryForensics::new(&mem, 0, 64);
        assert_eq!(mf.malware_score(), 0);
    }

    #[test]
    fn test_malware_score_increases_with_artifacts() {
        let mem = vec![0u8; 512];
        let mut mf = MemoryForensics::new(&mem, 0, 64);
        mf.artifacts.kernel_hooks.push(KernelHook {
            hook_type: HookType::SsdtEntry,
            hooked_address: 0xFFFF_0000,
            original_target: Some(0xFFFF_1000),
            hook_destination: 0xDEAD_0000,
            hook_module: Some("rootkit.sys".into()),
        });
        let score = mf.malware_score();
        assert!(score > 0);
    }

    #[test]
    fn test_pool_tag_scan_via_forensics() {
        let mem = make_test_memory(2048);
        let mf = MemoryForensics::new(&mem, 0, 64);
        let scanner = mf.pool_tag_scan();
        assert!(scanner.total_hits() > 0);
    }

    #[test]
    fn test_kernel_object_builder() {
        let obj = KernelObject::new(KernelObjectType::Driver, 0xFFFF_8000_1234_0000)
            .with_name("evil.sys")
            .with_pool_tag(*b"Driv");
        assert_eq!(obj.name, Some("evil.sys".to_string()));
        assert_eq!(obj.pool_tag, Some(*b"Driv"));
    }

    #[test]
    fn test_malware_score_capped_at_100() {
        let mem = vec![0u8; 512];
        let mut mf = MemoryForensics::new(&mem, 0, 64);
        for _ in 0..20 {
            mf.artifacts.kernel_hooks.push(KernelHook {
                hook_type: HookType::SsdtInline,
                hooked_address: 0,
                original_target: None,
                hook_destination: 0,
                hook_module: None,
            });
        }
        assert!(mf.malware_score() <= 100);
    }
}
