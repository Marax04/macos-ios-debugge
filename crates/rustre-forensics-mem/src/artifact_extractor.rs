//! Forensic artifact extractor — pulls structured evidence from memory images.
//!
//! Provides `ArtifactExtractor` to harvest `ProcessArtifact`, `NetworkArtifact`,
//! `RegistryArtifact`, and `FileArtifact` records, then assembles them into
//! an `ArtifactReport`.

use std::fmt;

use anyhow::Context as _;
use crate::casts::{u64_to_f64, usize_to_f64};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ExtractorError {
    #[error("memory region 0x{start:016x}..0x{end:016x} is inaccessible")]
    InaccessibleRegion { start: u64, end: u64 },
    #[error("pattern not found: {0}")]
    PatternNotFound(String),
    #[error("corrupt structure at 0x{0:016x}")]
    CorruptStructure(u64),
    #[error("extraction limit reached: {0}")]
    LimitReached(usize),
    #[error("unsupported OS: {0}")]
    UnsupportedOs(String),
}

pub type ExtResult<T> = Result<T, ExtractorError>;

// ─── MemoryRegion ─────────────────────────────────────────────────────────────

/// A flat view of a memory region (virtual base + raw bytes).
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_va: u64,
    pub data: Vec<u8>,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl MemoryRegion {
    #[must_use] 
    pub const fn new(base_va: u64, data: Vec<u8>) -> Self {
        Self { base_va, data, readable: true, writable: false, executable: false }
    }

    #[must_use] 
    pub fn read_u16(&self, offset: usize) -> u16 {
        if offset + 2 > self.data.len() { return 0; }
        u16::from_le_bytes([self.data[offset], self.data[offset + 1]])
    }

    /// # Panics
    /// Panics if the slice-to-array conversion fails (cannot happen given the bounds check).
    #[must_use]
    pub fn read_u32(&self, offset: usize) -> u32 {
        if offset + 4 > self.data.len() { return 0; }
        u32::from_le_bytes(self.data[offset..offset + 4].try_into().unwrap())
    }

    /// # Panics
    /// Panics if the slice-to-array conversion fails (cannot happen given the bounds check).
    #[must_use]
    pub fn read_u64(&self, offset: usize) -> u64 {
        if offset + 8 > self.data.len() { return 0; }
        u64::from_le_bytes(self.data[offset..offset + 8].try_into().unwrap())
    }

    #[must_use] 
    pub fn find_bytes(&self, pattern: &[u8]) -> Vec<usize> {
        let mut matches = Vec::new();
        if pattern.is_empty() || pattern.len() > self.data.len() { return matches; }
        for i in 0..=(self.data.len() - pattern.len()) {
            if self.data[i..i + pattern.len()] == *pattern {
                matches.push(i);
            }
        }
        matches
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ─── ProcessArtifact ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessArtifact {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub image_path: String,
    pub command_line: String,
    pub create_time: u64,
    pub exit_time: u64,
    pub session_id: u32,
    pub token_user: String,
    pub token_elevated: bool,
    pub modules: Vec<LoadedModule>,
    pub handles: Vec<HandleInfo>,
    pub vad_entries: u32,
    pub suspicious: bool,
    pub suspicious_reasons: Vec<String>,
}

impl ProcessArtifact {
    pub fn new(pid: u32, name: impl Into<String>) -> Self {
        Self {
            pid,
            ppid: 0,
            name: name.into(),
            image_path: String::new(),
            command_line: String::new(),
            create_time: 0,
            exit_time: 0,
            session_id: 0,
            token_user: String::new(),
            token_elevated: false,
            modules: Vec::new(),
            handles: Vec::new(),
            vad_entries: 0,
            suspicious: false,
            suspicious_reasons: Vec::new(),
        }
    }

    pub fn mark_suspicious(&mut self, reason: impl Into<String>) {
        self.suspicious = true;
        self.suspicious_reasons.push(reason.into());
    }

    #[must_use] 
    pub const fn is_alive(&self) -> bool {
        self.exit_time == 0
    }

    #[must_use] 
    pub const fn module_count(&self) -> usize {
        self.modules.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedModule {
    pub base_address: u64,
    pub size: u32,
    pub name: String,
    pub full_path: String,
    pub checksum: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleInfo {
    pub handle_value: u64,
    pub handle_type: String,
    pub object_name: String,
    pub access_mask: u32,
}

// ─── NetworkArtifact ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkArtifact {
    pub protocol: NetworkProtocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub pid: u32,
    pub process_name: String,
    pub create_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NetworkProtocol {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConnectionState {
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
    Closed,
    CloseWait,
    LastAck,
    Closing,
    Unknown,
}

impl NetworkArtifact {
    pub fn new(proto: NetworkProtocol, local: impl Into<String>, lport: u16,
               remote: impl Into<String>, rport: u16) -> Self {
        Self {
            protocol: proto,
            local_addr: local.into(),
            local_port: lport,
            remote_addr: remote.into(),
            remote_port: rport,
            state: ConnectionState::Unknown,
            pid: 0,
            process_name: String::new(),
            create_time: 0,
        }
    }

    #[must_use] 
    pub fn is_established(&self) -> bool {
        self.state == ConnectionState::Established
    }

    #[must_use] 
    pub const fn is_outbound(&self) -> bool {
        !matches!(self.state, ConnectionState::Listen)
    }

    #[must_use] 
    pub fn endpoint_str(&self) -> String {
        format!("{}:{}", self.remote_addr, self.remote_port)
    }
}

// ─── RegistryArtifact ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryArtifact {
    pub hive: String,
    pub key_path: String,
    pub value_name: String,
    pub value_type: RegistryValueType,
    pub data: Vec<u8>,
    pub last_written: u64,
    pub suspicious: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistryValueType {
    RegNone,
    RegSz,
    RegExpandSz,
    RegBinary,
    RegDword,
    RegDwordBigEndian,
    RegLink,
    RegMultiSz,
    RegResourceList,
    RegQword,
    Unknown(u32),
}

impl RegistryArtifact {
    pub fn new(hive: impl Into<String>, key: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            hive: hive.into(),
            key_path: key.into(),
            value_name: name.into(),
            value_type: RegistryValueType::RegNone,
            data: Vec::new(),
            last_written: 0,
            suspicious: false,
        }
    }

    #[must_use] 
    pub fn full_path(&self) -> String {
        format!("{}\\{}\\{}", self.hive, self.key_path, self.value_name)
    }

    #[must_use] 
    pub fn as_string(&self) -> Option<String> {
        if matches!(self.value_type, RegistryValueType::RegSz | RegistryValueType::RegExpandSz) {
            let words: Vec<u16> = self.data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&w| w != 0)
                .collect();
            Some(String::from_utf16_lossy(&words))
        } else {
            None
        }
    }

    /// # Panics
    /// Panics if the slice-to-array conversion fails (cannot happen given the bounds check).
    #[must_use]
    pub fn as_dword(&self) -> Option<u32> {
        if self.data.len() >= 4 {
            Some(u32::from_le_bytes(self.data[..4].try_into().unwrap()))
        } else {
            None
        }
    }
}

// ─── FileArtifact ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileArtifact {
    pub path: String,
    pub size: u64,
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub sha256: [u8; 32],
    pub file_type: ArtifactFileType,
    pub mapped_pids: Vec<u32>,
    pub is_deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFileType {
    Pe,
    Elf,
    Script,
    Document,
    Image,
    Archive,
    Unknown,
}

impl FileArtifact {
    pub fn new(path: impl Into<String>, size: u64) -> Self {
        Self {
            path: path.into(),
            size,
            created: 0,
            modified: 0,
            accessed: 0,
            sha256: [0u8; 32],
            file_type: ArtifactFileType::Unknown,
            mapped_pids: Vec::new(),
            is_deleted: false,
        }
    }

    #[must_use] 
    pub const fn is_executable(&self) -> bool {
        matches!(self.file_type, ArtifactFileType::Pe | ArtifactFileType::Elf)
    }

    #[must_use] 
    pub fn sha256_hex(&self) -> String {
        self.sha256.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
    }

    #[must_use] 
    pub const fn is_mapped(&self) -> bool {
        !self.mapped_pids.is_empty()
    }
}

// ─── ArtifactReport ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactReport {
    pub processes: Vec<ProcessArtifact>,
    pub network_connections: Vec<NetworkArtifact>,
    pub registry_keys: Vec<RegistryArtifact>,
    pub files: Vec<FileArtifact>,
    pub analysis_time_ms: u64,
    pub memory_size_bytes: u64,
    pub os_type: String,
    pub notes: Vec<String>,
}

impl ArtifactReport {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn suspicious_processes(&self) -> Vec<&ProcessArtifact> {
        self.processes.iter().filter(|p| p.suspicious).collect()
    }

    #[must_use] 
    pub fn established_connections(&self) -> Vec<&NetworkArtifact> {
        self.network_connections.iter().filter(|n| n.is_established()).collect()
    }

    #[must_use] 
    pub fn suspicious_registry_keys(&self) -> Vec<&RegistryArtifact> {
        self.registry_keys.iter().filter(|r| r.suspicious).collect()
    }

    #[must_use] 
    pub fn executable_files(&self) -> Vec<&FileArtifact> {
        self.files.iter().filter(|f| f.is_executable()).collect()
    }

    #[must_use] 
    pub fn deleted_files(&self) -> Vec<&FileArtifact> {
        self.files.iter().filter(|f| f.is_deleted).collect()
    }

    #[must_use] 
    pub fn risk_score(&self) -> f64 {
        let mut s = 0.0f64;
        s = usize_to_f64(self.suspicious_processes().len()).mul_add(15.0, s);
        s = usize_to_f64(self.established_connections().len()).mul_add(5.0, s);
        s = usize_to_f64(self.suspicious_registry_keys().len()).mul_add(10.0, s);
        s = usize_to_f64(self.deleted_files().len()).mul_add(8.0, s);
        s.min(100.0)
    }

    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "ArtifactReport: {} processes, {} connections, {} registry keys, {} files, risk={:.1}",
            self.processes.len(),
            self.network_connections.len(),
            self.registry_keys.len(),
            self.files.len(),
            self.risk_score(),
        )
    }

    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }
}

impl fmt::Display for ArtifactReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─── ArtifactExtractor ────────────────────────────────────────────────────────

/// Configuration for extraction.
#[derive(Debug, Clone)]
pub struct ExtractorConfig {
    pub max_processes: usize,
    pub max_connections: usize,
    pub max_registry_keys: usize,
    pub max_files: usize,
    pub extract_handles: bool,
    pub extract_vad: bool,
    pub resolve_symbols: bool,
    pub heuristic_threshold: f64,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            max_processes: 1024,
            max_connections: 4096,
            max_registry_keys: 10_000,
            max_files: 50_000,
            extract_handles: true,
            extract_vad: true,
            resolve_symbols: false,
            heuristic_threshold: 0.5,
        }
    }
}

/// Main extractor: scans `MemoryRegion` slices for forensic artefacts.
#[derive(Default)]
pub struct ArtifactExtractor {
    pub config: ExtractorConfig,
}


impl ArtifactExtractor {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn with_config(config: ExtractorConfig) -> Self {
        Self { config }
    }

    /// Full extraction, returning an [`anyhow::Result`] for ergonomic use at the crate boundary.
    ///
    /// Callers that want the specific [`ExtractorError`] variant should use [`Self::extract`].
    ///
    /// # Errors
    /// Returns an error if the underlying extraction fails.
    pub fn extract_anyhow(&self, memory: &[u8]) -> anyhow::Result<ArtifactReport> {
        self.extract(memory).context("artifact extraction failed")
    }

    /// Full extraction from a flat byte slice (simplified simulation).
    ///
    /// # Errors
    /// Returns an error if any sub-extraction step fails.
    pub fn extract(&self, memory: &[u8]) -> ExtResult<ArtifactReport> {
        let mut report = ArtifactReport::new();
        report.memory_size_bytes = memory.len() as u64;

        report.processes = self.extract_processes(memory);
        report.network_connections = self.extract_network(memory);
        report.registry_keys = self.extract_registry(memory);
        report.files = self.extract_files(memory);

        Ok(report)
    }

    fn extract_processes(&self, memory: &[u8]) -> Vec<ProcessArtifact> {
        let region = MemoryRegion::new(0, memory.to_vec());
        let mut procs = Vec::new();

        // Heuristic: search for "PROC" tag as a synthetic kernel structure marker
        let proc_tag = b"PROC";
        let offsets = region.find_bytes(proc_tag);

        for (_i, &off) in offsets.iter().enumerate().take(self.config.max_processes) {
            if off + 16 > memory.len() { continue; }
            let pid = region.read_u32(off + 4);
            let parent_pid = region.read_u32(off + 8);
            let name = read_ascii_string(memory, off + 12, 16);
            let mut p = ProcessArtifact::new(pid, name.clone());
            p.ppid = parent_pid;
            // Heuristic: pid 0 or very large pids are suspicious
            if pid == 0 || pid > 100_000 {
                p.mark_suspicious("anomalous PID");
            }
            procs.push(p);
        }

        if procs.is_empty() {
            // Synthetic: always return at least System/Idle
            let mut system = ProcessArtifact::new(4, "System");
            system.ppid = 0;
            procs.push(ProcessArtifact::new(0, "Idle"));
            procs.push(system);
        }

        procs
    }

    fn extract_network(&self, memory: &[u8]) -> Vec<NetworkArtifact> {
        let region = MemoryRegion::new(0, memory.to_vec());
        let mut conns = Vec::new();
        let tag = b"TCPE"; // synthetic tag for TCP endpoint structures
        for &off in region.find_bytes(tag).iter().take(self.config.max_connections) {
            if off + 20 > memory.len() { continue; }
            let lport = region.read_u16(off + 4);
            let rport = region.read_u16(off + 6);
            let pid = region.read_u32(off + 8);
            let remote_ip = format!("{}.{}.{}.{}", memory[off+12], memory[off+13], memory[off+14], memory[off+15]);
            let mut c = NetworkArtifact::new(NetworkProtocol::Tcp4, "0.0.0.0", lport, remote_ip, rport);
            c.pid = pid;
            c.state = ConnectionState::Established;
            conns.push(c);
        }
        conns
    }

    fn extract_registry(&self, memory: &[u8]) -> Vec<RegistryArtifact> {
        let region = MemoryRegion::new(0, memory.to_vec());
        let mut keys = Vec::new();
        let tag = b"nk\x00\x00"; // HIVE cell signature (simplified)
        for &off in region.find_bytes(tag).iter().take(self.config.max_registry_keys) {
            if off + 8 > memory.len() { continue; }
            let key_name = read_ascii_string(memory, off + 4, 16);
            let mut r = RegistryArtifact::new("HKLM", &key_name, "");
            // Mark run keys as suspicious
            if key_name.contains("Run") {
                r.suspicious = true;
            }
            keys.push(r);
        }
        keys
    }

    fn extract_files(&self, memory: &[u8]) -> Vec<FileArtifact> {
        let region = MemoryRegion::new(0, memory.to_vec());
        let mut files = Vec::new();
        let tag = b"FILE"; // NTFS $FILE record
        for &off in region.find_bytes(tag).iter().take(self.config.max_files) {
            if off + 8 > memory.len() { continue; }
            let size = region.read_u64(off);
            let name = read_ascii_string(memory, off + 4, 24);
            let mut f = FileArtifact::new(format!("\\Device\\HarddiskVolume2\\{name}"), size);
            // Mark .exe files
            if std::path::Path::new(&name).extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")) {
                f.file_type = ArtifactFileType::Pe;
            }
            files.push(f);
        }
        files
    }

    /// Check a process for common hollowing / injection heuristics.
    #[must_use] 
    pub fn check_process_hollowing(&self, _proc: &ProcessArtifact, mapped_image_size: u64, disk_image_size: u64) -> bool {
        // If mapped size differs significantly from disk size, may be hollowed
        if disk_image_size > 0 {
            let ratio = u64_to_f64(mapped_image_size) / u64_to_f64(disk_image_size);
            !(0.5..=3.0).contains(&ratio)
        } else {
            false
        }
    }

    /// Heuristically score a network connection's suspiciousness.
    #[must_use] 
    pub fn score_connection(&self, conn: &NetworkArtifact) -> f64 {
        let mut score = 0.0f64;
        // C2-like ports
        if matches!(conn.remote_port, 4444 | 5555 | 6666 | 7777 | 8888 | 9999 | 1337) {
            score += 0.6;
        }
        if conn.remote_port == 443 { score += 0.1; }
        if conn.is_established() { score += 0.2; }
        score.min(1.0)
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn read_ascii_string(data: &[u8], offset: usize, max_len: usize) -> String {
    let end = (offset + max_len).min(data.len());
    data[offset..end]
        .iter()
        .take_while(|&&b| b.is_ascii_graphic() || b == b' ')
        .map(|&b| b as char)
        .collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_memory(size: usize) -> Vec<u8> {
        vec![0u8; size]
    }

    // ── MemoryRegion ──────────────────────────────────────────────────────────

    #[test]
    fn test_memory_region_find_bytes() {
        let r = MemoryRegion::new(0x1000, vec![0, 1, 2, 3, 1, 2, 3, 4]);
        let hits = r.find_bytes(&[1, 2, 3]);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_memory_region_find_empty_pattern() {
        let r = MemoryRegion::new(0, vec![1, 2, 3]);
        assert!(r.find_bytes(&[]).is_empty());
    }

    #[test]
    fn test_memory_region_read_u32() {
        let r = MemoryRegion::new(0, vec![0x01, 0x00, 0x00, 0x00]);
        assert_eq!(r.read_u32(0), 1);
    }

    #[test]
    fn test_memory_region_read_u64_oob() {
        let r = MemoryRegion::new(0, vec![0u8; 4]);
        assert_eq!(r.read_u64(0), 0);
    }

    #[test]
    fn test_memory_region_len() {
        let r = MemoryRegion::new(0, vec![0u8; 256]);
        assert_eq!(r.len(), 256);
    }

    // ── ProcessArtifact ───────────────────────────────────────────────────────

    #[test]
    fn test_process_artifact_new() {
        let p = ProcessArtifact::new(1234, "explorer.exe");
        assert_eq!(p.pid, 1234);
        assert!(!p.suspicious);
    }

    #[test]
    fn test_process_artifact_mark_suspicious() {
        let mut p = ProcessArtifact::new(1, "evil.exe");
        p.mark_suspicious("injected code");
        assert!(p.suspicious);
        assert_eq!(p.suspicious_reasons.len(), 1);
    }

    #[test]
    fn test_process_artifact_is_alive() {
        let mut p = ProcessArtifact::new(4, "System");
        assert!(p.is_alive());
        p.exit_time = 1000;
        assert!(!p.is_alive());
    }

    #[test]
    fn test_process_artifact_module_count() {
        let mut p = ProcessArtifact::new(100, "svchost.exe");
        p.modules.push(LoadedModule { base_address: 0x1000, size: 4096, name: "ntdll.dll".into(), full_path: "C:\\Windows\\System32\\ntdll.dll".into(), checksum: 0 });
        assert_eq!(p.module_count(), 1);
    }

    // ── NetworkArtifact ───────────────────────────────────────────────────────

    #[test]
    fn test_network_artifact_new() {
        let c = NetworkArtifact::new(NetworkProtocol::Tcp4, "192.168.1.2", 1234, "1.2.3.4", 443);
        assert_eq!(c.local_port, 1234);
        assert_eq!(c.remote_port, 443);
    }

    #[test]
    fn test_network_artifact_is_established() {
        let mut c = NetworkArtifact::new(NetworkProtocol::Tcp4, "0.0.0.0", 0, "0.0.0.0", 0);
        c.state = ConnectionState::Established;
        assert!(c.is_established());
    }

    #[test]
    fn test_network_artifact_endpoint_str() {
        let c = NetworkArtifact::new(NetworkProtocol::Tcp4, "0.0.0.0", 0, "8.8.8.8", 53);
        assert_eq!(c.endpoint_str(), "8.8.8.8:53");
    }

    #[test]
    fn test_network_artifact_is_outbound() {
        let mut c = NetworkArtifact::new(NetworkProtocol::Tcp4, "0.0.0.0", 80, "0.0.0.0", 0);
        c.state = ConnectionState::Listen;
        assert!(!c.is_outbound());
    }

    // ── RegistryArtifact ──────────────────────────────────────────────────────

    #[test]
    fn test_registry_artifact_full_path() {
        let r = RegistryArtifact::new("HKLM", "SOFTWARE\\Microsoft\\Run", "malware");
        assert_eq!(r.full_path(), "HKLM\\SOFTWARE\\Microsoft\\Run\\malware");
    }

    #[test]
    fn test_registry_artifact_as_dword() {
        let mut r = RegistryArtifact::new("HKLM", "key", "val");
        r.data = vec![0x01, 0x00, 0x00, 0x00];
        r.value_type = RegistryValueType::RegDword;
        assert_eq!(r.as_dword(), Some(1));
    }

    #[test]
    fn test_registry_artifact_as_string() {
        let mut r = RegistryArtifact::new("HKCU", "key", "val");
        r.value_type = RegistryValueType::RegSz;
        // "Hi" in UTF-16LE
        r.data = vec![b'H', 0, b'i', 0, 0, 0];
        let s = r.as_string().unwrap();
        assert_eq!(s, "Hi");
    }

    #[test]
    fn test_registry_artifact_as_string_not_sz_type() {
        let mut r = RegistryArtifact::new("HKCU", "key", "val");
        r.value_type = RegistryValueType::RegDword;
        r.data = vec![1, 0, 0, 0];
        assert!(r.as_string().is_none());
    }

    // ── FileArtifact ──────────────────────────────────────────────────────────

    #[test]
    fn test_file_artifact_new() {
        let f = FileArtifact::new("C:\\Windows\\System32\\calc.exe", 28672);
        assert_eq!(f.size, 28672);
        assert!(!f.is_executable());
    }

    #[test]
    fn test_file_artifact_pe_executable() {
        let mut f = FileArtifact::new("test.exe", 1024);
        f.file_type = ArtifactFileType::Pe;
        assert!(f.is_executable());
    }

    #[test]
    fn test_file_artifact_sha256_hex_len() {
        let f = FileArtifact::new("test.bin", 0);
        assert_eq!(f.sha256_hex().len(), 64);
    }

    #[test]
    fn test_file_artifact_is_mapped() {
        let mut f = FileArtifact::new("ntdll.dll", 0);
        assert!(!f.is_mapped());
        f.mapped_pids.push(1234);
        assert!(f.is_mapped());
    }

    // ── ArtifactReport ────────────────────────────────────────────────────────

    #[test]
    fn test_artifact_report_new_empty() {
        let r = ArtifactReport::new();
        assert_eq!(r.processes.len(), 0);
        assert_eq!(r.risk_score(), 0.0);
    }

    #[test]
    fn test_artifact_report_risk_score_grows() {
        let mut r = ArtifactReport::new();
        let mut p = ProcessArtifact::new(1, "evil.exe");
        p.suspicious = true;
        r.processes.push(p);
        assert!(r.risk_score() > 0.0);
    }

    #[test]
    fn test_artifact_report_summary() {
        let r = ArtifactReport::new();
        let s = r.summary();
        assert!(s.contains("ArtifactReport"));
    }

    #[test]
    fn test_artifact_report_to_json() {
        let r = ArtifactReport::new();
        let j = r.to_json().unwrap();
        assert!(j.contains("processes"));
    }

    #[test]
    fn test_artifact_report_add_note() {
        let mut r = ArtifactReport::new();
        r.add_note("test note");
        assert_eq!(r.notes.len(), 1);
    }

    #[test]
    fn test_artifact_report_deleted_files() {
        let mut r = ArtifactReport::new();
        let mut f = FileArtifact::new("C:\\temp\\malware.exe", 1024);
        f.is_deleted = true;
        r.files.push(f);
        assert_eq!(r.deleted_files().len(), 1);
    }

    // ── ArtifactExtractor ─────────────────────────────────────────────────────

    #[test]
    fn test_extractor_new() {
        let e = ArtifactExtractor::new();
        assert_eq!(e.config.max_processes, 1024);
    }

    #[test]
    fn test_extractor_extract_empty_memory_returns_report() {
        let e = ArtifactExtractor::new();
        let report = e.extract(&[]).unwrap();
        // Should return at least synthetic System/Idle processes
        assert!(!report.processes.is_empty());
    }

    #[test]
    fn test_extractor_extract_with_proc_tag() {
        let mut mem = vec![0u8; 256];
        // Inject synthetic PROC marker
        mem[64] = b'P'; mem[65] = b'R'; mem[66] = b'O'; mem[67] = b'C';
        // PID at offset 68
        mem[68] = 100; mem[69] = 0; mem[70] = 0; mem[71] = 0;
        let e = ArtifactExtractor::new();
        let report = e.extract(&mem).unwrap();
        assert!(!report.processes.is_empty());
    }

    #[test]
    fn test_extractor_score_connection_c2_port() {
        let e = ArtifactExtractor::new();
        let mut c = NetworkArtifact::new(NetworkProtocol::Tcp4, "0.0.0.0", 0, "1.2.3.4", 4444);
        c.state = ConnectionState::Established;
        let score = e.score_connection(&c);
        assert!(score > 0.5);
    }

    #[test]
    fn test_extractor_score_connection_normal_port() {
        let e = ArtifactExtractor::new();
        let c = NetworkArtifact::new(NetworkProtocol::Tcp4, "0.0.0.0", 0, "8.8.8.8", 53);
        let score = e.score_connection(&c);
        assert!(score < 0.5);
    }

    #[test]
    fn test_extractor_process_hollowing_detected() {
        let e = ArtifactExtractor::new();
        let p = ProcessArtifact::new(1000, "test.exe");
        assert!(e.check_process_hollowing(&p, 100, 10_000));
    }

    #[test]
    fn test_extractor_process_hollowing_normal() {
        let e = ArtifactExtractor::new();
        let p = ProcessArtifact::new(1000, "test.exe");
        assert!(!e.check_process_hollowing(&p, 10_000, 10_000));
    }

    #[test]
    fn test_extractor_with_config() {
        let cfg = ExtractorConfig {
            max_processes: 10,
            ..Default::default()
        };
        let e = ArtifactExtractor::with_config(cfg);
        assert_eq!(e.config.max_processes, 10);
    }

    // ── read_ascii_string ─────────────────────────────────────────────────────

    #[test]
    fn test_read_ascii_string_basic() {
        let data = b"hello\x00world";
        let s = read_ascii_string(data, 0, 5);
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_read_ascii_string_out_of_bounds() {
        let data = b"ab";
        let s = read_ascii_string(data, 0, 100);
        assert_eq!(s, "ab");
    }
}
