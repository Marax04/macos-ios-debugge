//! `memory_dump_analyzer` — High-level memory dump analysis.
//!
//! Provides [`MemoryDumpAnalyzer`] which drives [`PslistWalker`],
//! [`ModlistWalker`], [`HandlesWalker`], and [`NetworkWalker`] to extract
//! a comprehensive [`DumpReport`] from a raw memory image.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DumpAnalyzerError {
    #[error("read error at 0x{0:016x}: {1}")]
    ReadError(u64, String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("walker error: {0}")]
    WalkerError(String),
    #[error("no kdbg found")]
    NoKdbg,
    #[error("unsupported architecture")]
    UnsupportedArch,
    #[error("insufficient data: {0} bytes")]
    InsufficientData(usize),
    #[error("report error: {0}")]
    ReportError(String),
}

// ─── MemoryImage (minimal shim) ───────────────────────────────────────────────

/// Minimal in-memory representation of a dump, suitable for tests.
#[derive(Debug, Clone)]
pub struct DumpImage {
    pub data: Vec<u8>,
    pub base_offset: u64,
}

impl DumpImage {
    #[must_use] 
    pub const fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            base_offset: 0,
        }
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn read_bytes(&self, offset: u64, len: usize) -> Result<&[u8], DumpAnalyzerError> {
        let off = usize::try_from(offset).unwrap_or(usize::MAX);
        if off + len > self.data.len() {
            return Err(DumpAnalyzerError::ReadError(
                offset,
                format!(
                    "need {} bytes, have {}",
                    len,
                    self.data.len().saturating_sub(off)
                ),
            ));
        }
        Ok(&self.data[off..off + len])
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn read_u32_le(&self, offset: u64) -> Result<u32, DumpAnalyzerError> {
        let b = self.read_bytes(offset, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn read_u64_le(&self, offset: u64) -> Result<u64, DumpAnalyzerError> {
        let b = self.read_bytes(offset, 8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

// ─── ProcessRecord ────────────────────────────────────────────────────────────

/// A process entry extracted from the kernel's process list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub base_addr: u64,
    pub dtb: u64,
    pub handle_count: u32,
    pub thread_count: u32,
    pub create_time_ms: u64,
    pub exit_time_ms: Option<u64>,
    pub peb_addr: u64,
    pub is_wow64: bool,
}

impl ProcessRecord {
    pub fn new(pid: u32, parent_pid: u32, name: impl Into<String>) -> Self {
        Self {
            pid,
            ppid: parent_pid,
            name: name.into(),
            base_addr: 0,
            dtb: 0,
            handle_count: 0,
            thread_count: 0,
            create_time_ms: 0,
            exit_time_ms: None,
            peb_addr: 0,
            is_wow64: false,
        }
    }

    #[must_use] 
    pub const fn is_alive(&self) -> bool {
        self.exit_time_ms.is_none()
    }

    #[must_use] 
    pub fn is_suspicious(&self) -> bool {
        // Heuristic: System-like name but non-system PID, or WoW64 svchost
        (self.name.eq_ignore_ascii_case("svchost.exe") && self.is_wow64)
            || (self.name.eq_ignore_ascii_case("lsass.exe") && self.ppid != 4)
            || self.thread_count == 0
    }

    #[must_use] 
    pub fn display_path(&self) -> String {
        format!("{} (PID {})", self.name, self.pid)
    }
}

impl fmt::Display for ProcessRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<20} PID={:<6} PPID={:<6} handles={} threads={}",
            self.name, self.pid, self.ppid, self.handle_count, self.thread_count
        )
    }
}

// ─── ModuleRecord ─────────────────────────────────────────────────────────────

/// A loaded module entry (kernel or user-space).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRecord {
    pub name: String,
    pub base_addr: u64,
    pub size: u64,
    pub path: String,
    pub is_kernel: bool,
    pub entry_point: u64,
    pub checksum: u32,
}

impl ModuleRecord {
    pub fn new(name: impl Into<String>, base: u64, size: u64) -> Self {
        Self {
            name: name.into(),
            base_addr: base,
            size,
            path: String::new(),
            is_kernel: false,
            entry_point: 0,
            checksum: 0,
        }
    }

    /// Return the module's `path` field parsed as a [`PathBuf`] for filesystem-style queries.
    #[must_use]
    pub fn path_buf(&self) -> PathBuf {
        PathBuf::from(&self.path)
    }

    #[must_use] 
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base_addr && addr < self.base_addr + self.size
    }

    #[must_use] 
    pub const fn end_addr(&self) -> u64 {
        self.base_addr + self.size
    }
}

impl fmt::Display for ModuleRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} base=0x{:016x} size=0x{:x}",
            self.name, self.base_addr, self.size
        )
    }
}

// ─── HandleRecord ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandleType {
    File,
    Process,
    Thread,
    Event,
    Mutex,
    Section,
    Registry,
    Token,
    Unknown,
}

impl fmt::Display for HandleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleRecord {
    pub handle_value: u64,
    pub pid: u32,
    pub handle_type: HandleType,
    pub name: Option<String>,
    pub object_addr: u64,
    pub granted_access: u32,
}

impl HandleRecord {
    #[must_use] 
    pub const fn new(handle_value: u64, pid: u32, handle_type: HandleType) -> Self {
        Self {
            handle_value,
            pid,
            handle_type,
            name: None,
            object_addr: 0,
            granted_access: 0,
        }
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use] 
    pub const fn is_named(&self) -> bool {
        self.name.is_some()
    }
}

// ─── NetworkConnectionRecord ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionRecord {
    pub pid: u32,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: u8, // 6=TCP, 17=UDP
    pub state: u32,
    pub create_time_ms: Option<u64>,
}

impl NetworkConnectionRecord {
    pub fn tcp(
        pid: u32,
        local_ip: impl Into<String>,
        local_port: u16,
        remote_ip: impl Into<String>,
        remote_port: u16,
    ) -> Self {
        Self {
            pid,
            local_ip: local_ip.into(),
            local_port,
            remote_ip: remote_ip.into(),
            remote_port,
            protocol: 6,
            state: 5,
            create_time_ms: None,
        }
    }

    #[must_use] 
    pub const fn is_tcp(&self) -> bool {
        self.protocol == 6
    }

    #[must_use] 
    pub const fn is_udp(&self) -> bool {
        self.protocol == 17
    }

    #[must_use] 
    pub fn endpoint_str(&self) -> String {
        format!(
            "{}:{} → {}:{}",
            self.local_ip, self.local_port, self.remote_ip, self.remote_port
        )
    }
}

// ─── PslistWalker ─────────────────────────────────────────────────────────────

/// Walks the kernel EPROCESS list to extract process records.
#[derive(Debug, Default)]
pub struct PslistWalker {
    processes: Vec<ProcessRecord>,
}

impl PslistWalker {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate from synthetic data (used in tests and simulation).
    pub fn load_synthetic(&mut self, procs: Vec<ProcessRecord>) {
        self.processes = procs;
    }

    /// Walk a simulated EPROCESS chain in `image`.
    /// Expects groups of 32 bytes: [pid u32][ppid u32][name 24 bytes].
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn walk(&mut self, image: &DumpImage) -> Result<usize, DumpAnalyzerError> {
        if image.len() < 32 {
            return Err(DumpAnalyzerError::InsufficientData(image.len()));
        }
        let mut offset = 0u64;
        let mut count = 0;
        while usize::try_from(offset + 32).unwrap_or(usize::MAX) <= image.len() {
            let pid = image.read_u32_le(offset)?;
            let parent_pid = image.read_u32_le(offset + 4)?;
            // read up to 24 bytes as ASCII name
            let name_bytes = image.read_bytes(offset + 8, 20)?;
            let name: String = name_bytes
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as char)
                .collect();
            if pid == 0 && parent_pid == 0 && name.is_empty() {
                break;
            }
            self.processes.push(ProcessRecord::new(pid, parent_pid, name));
            offset += 32;
            count += 1;
        }
        Ok(count)
    }

    #[must_use] 
    pub fn all(&self) -> &[ProcessRecord] {
        &self.processes
    }

    #[must_use] 
    pub const fn count(&self) -> usize {
        self.processes.len()
    }

    #[must_use] 
    pub fn by_pid(&self, pid: u32) -> Option<&ProcessRecord> {
        self.processes.iter().find(|p| p.pid == pid)
    }

    #[must_use] 
    pub fn by_name(&self, name: &str) -> Vec<&ProcessRecord> {
        self.processes
            .iter()
            .filter(|p| p.name.eq_ignore_ascii_case(name))
            .collect()
    }

    #[must_use] 
    pub fn suspicious_processes(&self) -> Vec<&ProcessRecord> {
        self.processes
            .iter()
            .filter(|p| p.is_suspicious())
            .collect()
    }

    #[must_use] 
    pub fn pid_tree(&self) -> HashMap<u32, Vec<u32>> {
        let mut tree: HashMap<u32, Vec<u32>> = HashMap::new();
        for p in &self.processes {
            tree.entry(p.ppid).or_default().push(p.pid);
        }
        tree
    }
}

// ─── ModlistWalker ────────────────────────────────────────────────────────────

/// Walks module (`LDR_DATA_TABLE_ENTRY`) lists.
#[derive(Debug, Default)]
pub struct ModlistWalker {
    modules: Vec<ModuleRecord>,
}

impl ModlistWalker {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_synthetic(&mut self, mods: Vec<ModuleRecord>) {
        self.modules = mods;
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn walk(&mut self, image: &DumpImage) -> Result<usize, DumpAnalyzerError> {
        if image.len() < 24 {
            return Err(DumpAnalyzerError::InsufficientData(image.len()));
        }
        let mut offset = 0u64;
        let mut count = 0;
        while usize::try_from(offset + 24).unwrap_or(usize::MAX) <= image.len() {
            let base = image.read_u64_le(offset)?;
            let size = image.read_u64_le(offset + 8)?;
            let name_bytes = image.read_bytes(offset + 16, 8)?;
            let name: String = name_bytes
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as char)
                .collect();
            if base == 0 && size == 0 {
                break;
            }
            self.modules.push(ModuleRecord::new(name, base, size));
            offset += 24;
            count += 1;
        }
        Ok(count)
    }

    #[must_use] 
    pub fn all(&self) -> &[ModuleRecord] {
        &self.modules
    }

    #[must_use] 
    pub const fn count(&self) -> usize {
        self.modules.len()
    }

    #[must_use] 
    pub fn find_by_addr(&self, addr: u64) -> Option<&ModuleRecord> {
        self.modules.iter().find(|m| m.contains(addr))
    }

    #[must_use] 
    pub fn find_by_name(&self, name: &str) -> Option<&ModuleRecord> {
        self.modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
    }

    #[must_use] 
    pub fn kernel_modules(&self) -> Vec<&ModuleRecord> {
        self.modules.iter().filter(|m| m.is_kernel).collect()
    }

    #[must_use] 
    pub fn orphan_addresses(&self, addrs: &[u64]) -> Vec<u64> {
        addrs
            .iter()
            .copied()
            .filter(|&a| self.find_by_addr(a).is_none())
            .collect()
    }
}

// ─── HandlesWalker ────────────────────────────────────────────────────────────

/// Walks the kernel handle table for each process.
#[derive(Debug, Default)]
pub struct HandlesWalker {
    handles: Vec<HandleRecord>,
}

impl HandlesWalker {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_synthetic(&mut self, handles: Vec<HandleRecord>) {
        self.handles = handles;
    }

    #[must_use] 
    pub fn all(&self) -> &[HandleRecord] {
        &self.handles
    }

    #[must_use] 
    pub const fn count(&self) -> usize {
        self.handles.len()
    }

    #[must_use] 
    pub fn by_pid(&self, pid: u32) -> Vec<&HandleRecord> {
        self.handles.iter().filter(|h| h.pid == pid).collect()
    }

    #[must_use] 
    pub fn by_type(&self, htype: HandleType) -> Vec<&HandleRecord> {
        self.handles
            .iter()
            .filter(|h| h.handle_type == htype)
            .collect()
    }

    #[must_use] 
    pub fn named_handles(&self) -> Vec<&HandleRecord> {
        self.handles.iter().filter(|h| h.is_named()).collect()
    }

    #[must_use] 
    pub fn mutant_names(&self) -> Vec<String> {
        self.handles
            .iter()
            .filter(|h| h.handle_type == HandleType::Mutex)
            .filter_map(|h| h.name.clone())
            .collect()
    }

    #[must_use] 
    pub fn handle_count_by_type(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for h in &self.handles {
            *map.entry(h.handle_type.to_string()).or_insert(0) += 1;
        }
        map
    }
}

// ─── NetworkWalker ────────────────────────────────────────────────────────────

/// Extracts network connection structures from memory.
#[derive(Debug, Default)]
pub struct NetworkWalker {
    connections: Vec<NetworkConnectionRecord>,
}

impl NetworkWalker {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_synthetic(&mut self, conns: Vec<NetworkConnectionRecord>) {
        self.connections = conns;
    }

    #[must_use] 
    pub fn all(&self) -> &[NetworkConnectionRecord] {
        &self.connections
    }

    #[must_use] 
    pub const fn count(&self) -> usize {
        self.connections.len()
    }

    #[must_use] 
    pub fn by_pid(&self, pid: u32) -> Vec<&NetworkConnectionRecord> {
        self.connections.iter().filter(|c| c.pid == pid).collect()
    }

    #[must_use] 
    pub fn tcp_connections(&self) -> Vec<&NetworkConnectionRecord> {
        self.connections.iter().filter(|c| c.is_tcp()).collect()
    }

    #[must_use] 
    pub fn udp_connections(&self) -> Vec<&NetworkConnectionRecord> {
        self.connections.iter().filter(|c| c.is_udp()).collect()
    }

    #[must_use] 
    pub fn unique_remote_ips(&self) -> Vec<String> {
        let mut ips: Vec<String> = self
            .connections
            .iter()
            .map(|c| c.remote_ip.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        ips.sort();
        ips
    }
}

// ─── DumpReport ───────────────────────────────────────────────────────────────

/// Complete analysis report for a memory dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpReport {
    pub process_count: usize,
    pub module_count: usize,
    pub handle_count: usize,
    pub network_conn_count: usize,
    pub suspicious_processes: Vec<String>,
    pub suspicious_network: Vec<String>,
    pub mutex_names: Vec<String>,
    pub unique_remote_ips: Vec<String>,
    pub handle_type_distribution: HashMap<String, usize>,
    pub pid_tree_roots: Vec<u32>,
    pub summary: String,
    pub analysis_errors: Vec<String>,
}

impl DumpReport {
    #[must_use] 
    pub const fn is_clean(&self) -> bool {
        self.suspicious_processes.is_empty() && self.suspicious_network.is_empty()
    }

    #[must_use]
    pub fn threat_score(&self) -> u32 {
        let mut score = 0u32;
        score += u32::try_from(self.suspicious_processes.len()).unwrap_or(u32::MAX).saturating_mul(10);
        score += u32::try_from(self.suspicious_network.len()).unwrap_or(u32::MAX).saturating_mul(5);
        score += if self.mutex_names.is_empty() { 0 } else { 5 };
        score
    }
}

// ─── MemoryDumpAnalyzer ───────────────────────────────────────────────────────

/// Orchestrates walkers to produce a full [`DumpReport`].
#[derive(Debug)]
pub struct MemoryDumpAnalyzer {
    pslist: PslistWalker,
    modlist: ModlistWalker,
    handles: HandlesWalker,
    network: NetworkWalker,
    errors: Vec<String>,
}

impl MemoryDumpAnalyzer {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            pslist: PslistWalker::new(),
            modlist: ModlistWalker::new(),
            handles: HandlesWalker::new(),
            network: NetworkWalker::new(),
            errors: Vec::new(),
        }
    }

    // ── Data loading (synthetic/test path) ────────────────────────────────

    pub fn load_processes(&mut self, procs: Vec<ProcessRecord>) {
        self.pslist.load_synthetic(procs);
    }

    pub fn load_modules(&mut self, mods: Vec<ModuleRecord>) {
        self.modlist.load_synthetic(mods);
    }

    pub fn load_handles(&mut self, handles: Vec<HandleRecord>) {
        self.handles.load_synthetic(handles);
    }

    pub fn load_network(&mut self, conns: Vec<NetworkConnectionRecord>) {
        self.network.load_synthetic(conns);
    }

    // ── Image-based analysis ──────────────────────────────────────────────

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn analyze_image(&mut self, image: &DumpImage) -> Result<(), DumpAnalyzerError> {
        if image.len() < 64 {
            return Err(DumpAnalyzerError::InsufficientData(image.len()));
        }
        // Walk process list
        match self.pslist.walk(image) {
            Ok(_) => {}
            Err(e) => self.errors.push(format!("pslist: {e}")),
        }
        // Walk module list
        match self.modlist.walk(image) {
            Ok(_) => {}
            Err(e) => self.errors.push(format!("modlist: {e}")),
        }
        Ok(())
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    #[must_use] 
    pub const fn pslist(&self) -> &PslistWalker {
        &self.pslist
    }

    #[must_use] 
    pub const fn modlist(&self) -> &ModlistWalker {
        &self.modlist
    }

    #[must_use] 
    pub const fn handles(&self) -> &HandlesWalker {
        &self.handles
    }

    #[must_use] 
    pub const fn network(&self) -> &NetworkWalker {
        &self.network
    }

    #[must_use] 
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    // ── Report generation ─────────────────────────────────────────────────

    #[must_use] 
    pub fn generate_report(&self) -> DumpReport {
        let suspicious_procs: Vec<String> = self
            .pslist
            .suspicious_processes()
            .iter()
            .map(|p| p.display_path())
            .collect();

        let suspicious_net: Vec<String> = self
            .network
            .tcp_connections()
            .iter()
            .filter(|c| c.remote_port > 1024)
            .map(|c| c.endpoint_str())
            .collect();

        let mutex_names = self.handles.mutant_names();
        let unique_ips = self.network.unique_remote_ips();
        let handle_dist = self.handles.handle_count_by_type();
        let tree = self.pslist.pid_tree();
        let roots: Vec<u32> = tree
            .keys()
            .filter(|&&ppid| self.pslist.by_pid(ppid).is_none())
            .copied()
            .collect();

        let summary = format!(
            "procs={} mods={} handles={} net_conns={} suspicious_procs={} errors={}",
            self.pslist.count(),
            self.modlist.count(),
            self.handles.count(),
            self.network.count(),
            suspicious_procs.len(),
            self.errors.len()
        );

        DumpReport {
            process_count: self.pslist.count(),
            module_count: self.modlist.count(),
            handle_count: self.handles.count(),
            network_conn_count: self.network.count(),
            suspicious_processes: suspicious_procs,
            suspicious_network: suspicious_net,
            mutex_names,
            unique_remote_ips: unique_ips,
            handle_type_distribution: handle_dist,
            pid_tree_roots: roots,
            summary,
            analysis_errors: self.errors.clone(),
        }
    }

    /// Quick-check if the dump shows any indicators of compromise.
    #[must_use] 
    pub fn has_ioc(&self) -> bool {
        let report = self.generate_report();
        !report.is_clean() || !report.mutex_names.is_empty()
    }
}

impl Default for MemoryDumpAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: u32, parent_pid: u32, name: &str) -> ProcessRecord {
        ProcessRecord::new(pid, parent_pid, name)
    }

    fn make_mod(name: &str, base: u64, size: u64) -> ModuleRecord {
        ModuleRecord::new(name, base, size)
    }

    fn make_analyzer() -> MemoryDumpAnalyzer {
        let mut a = MemoryDumpAnalyzer::new();
        a.load_processes(vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "svchost.exe"),
            make_proc(200, 4, "explorer.exe"),
            make_proc(300, 200, "cmd.exe"),
        ]);
        a.load_modules(vec![
            make_mod("ntoskrnl.exe", 0xFFFF_0000_0000_0000, 0x80_0000),
            make_mod("kernel32.dll", 0x7FFE_0000, 0x10_0000),
        ]);
        a.load_network(vec![NetworkConnectionRecord::tcp(
            100, "10.0.0.1", 54321, "1.2.3.4", 8080,
        )]);
        a
    }

    // --- DumpImage ---

    #[test]
    fn test_image_read_bytes() {
        let img = DumpImage::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(img.read_bytes(0, 3).unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn test_image_read_out_of_bounds() {
        let img = DumpImage::new(vec![1, 2, 3]);
        assert!(img.read_bytes(0, 10).is_err());
    }

    #[test]
    fn test_image_read_u32() {
        let img = DumpImage::new(vec![0x01, 0x00, 0x00, 0x00]);
        assert_eq!(img.read_u32_le(0).unwrap(), 1);
    }

    #[test]
    fn test_image_read_u64() {
        let mut data = vec![0u8; 8];
        data[0] = 0xFF;
        let img = DumpImage::new(data);
        assert_eq!(img.read_u64_le(0).unwrap(), 0xFF);
    }

    // --- ProcessRecord ---

    #[test]
    fn test_process_is_alive() {
        let p = make_proc(1, 0, "test.exe");
        assert!(p.is_alive());
    }

    #[test]
    fn test_process_display_path() {
        let p = make_proc(42, 0, "foo.exe");
        assert!(p.display_path().contains("42"));
    }

    #[test]
    fn test_process_display() {
        let p = make_proc(100, 4, "svchost.exe");
        let s = p.to_string();
        assert!(s.contains("svchost.exe"));
        assert!(s.contains("100"));
    }

    #[test]
    fn test_process_is_suspicious_wow64() {
        let mut p = make_proc(100, 4, "svchost.exe");
        p.is_wow64 = true;
        assert!(p.is_suspicious());
    }

    #[test]
    fn test_process_is_suspicious_lsass_wrong_parent() {
        let p = make_proc(500, 100, "lsass.exe"); // ppid=100 not 4
        assert!(p.is_suspicious());
    }

    // --- ModuleRecord ---

    #[test]
    fn test_module_contains() {
        // base 0x7FF0_0000 + size 0x10_0000 = 0x8000_0000 (NOT 0x7FF1_0000 —
        // the carry lands in the top nibble). The old assertion expected
        // 0x7FF1_0000 to be outside, but it sits only 64 KiB past the base and
        // is squarely inside the module.
        let m = make_mod("ntdll.dll", 0x7FF0_0000, 0x10_0000);
        assert!(m.contains(0x7FF0_0000), "the base itself is inside");
        assert!(m.contains(0x7FF0_0100));
        assert!(m.contains(0x7FF1_0000), "64 KiB into a 1 MiB module");
        assert!(m.contains(0x7FFF_FFFF), "last byte is inside");
        assert!(!m.contains(0x8000_0000), "end address is exclusive");
        assert!(!m.contains(0x7FEF_FFFF), "one byte below the base is outside");
        assert_eq!(m.end_addr(), 0x8000_0000);
    }

    #[test]
    fn test_module_end_addr() {
        let m = make_mod("x.dll", 0x1000, 0x2000);
        assert_eq!(m.end_addr(), 0x3000);
    }

    #[test]
    fn test_module_display() {
        let m = make_mod("kernel32.dll", 0x7FFF_0000, 0x5_0000);
        let s = m.to_string();
        assert!(s.contains("kernel32.dll"));
    }

    // --- HandleRecord ---

    #[test]
    fn test_handle_new() {
        let h = HandleRecord::new(0x1234, 100, HandleType::File);
        assert!(!h.is_named());
    }

    #[test]
    fn test_handle_with_name() {
        let h = HandleRecord::new(0x1234, 100, HandleType::Mutex).with_name("Global\\MyMutex");
        assert!(h.is_named());
    }

    // --- NetworkConnectionRecord ---

    #[test]
    fn test_conn_is_tcp() {
        let c = NetworkConnectionRecord::tcp(1, "10.0.0.1", 54321, "1.2.3.4", 80);
        assert!(c.is_tcp());
        assert!(!c.is_udp());
    }

    #[test]
    fn test_conn_endpoint_str() {
        let c = NetworkConnectionRecord::tcp(1, "10.0.0.1", 12345, "1.2.3.4", 80);
        assert!(c.endpoint_str().contains("10.0.0.1"));
        assert!(c.endpoint_str().contains("1.2.3.4"));
    }

    // --- PslistWalker ---

    #[test]
    fn test_pslist_count() {
        let a = make_analyzer();
        assert_eq!(a.pslist().count(), 4);
    }

    #[test]
    fn test_pslist_by_pid() {
        let a = make_analyzer();
        assert!(a.pslist().by_pid(100).is_some());
        assert!(a.pslist().by_pid(9999).is_none());
    }

    #[test]
    fn test_pslist_by_name() {
        let a = make_analyzer();
        assert_eq!(a.pslist().by_name("svchost.exe").len(), 1);
    }

    #[test]
    fn test_pslist_pid_tree() {
        let a = make_analyzer();
        let tree = a.pslist().pid_tree();
        assert!(tree.contains_key(&4));
        assert!(tree[&4].contains(&100));
    }

    // --- ModlistWalker ---

    #[test]
    fn test_modlist_count() {
        let a = make_analyzer();
        assert_eq!(a.modlist().count(), 2);
    }

    #[test]
    fn test_modlist_find_by_name() {
        let a = make_analyzer();
        assert!(a.modlist().find_by_name("kernel32.dll").is_some());
        assert!(a.modlist().find_by_name("unknown.dll").is_none());
    }

    #[test]
    fn test_modlist_find_by_addr() {
        let a = make_analyzer();
        // kernel32.dll is at 0x7FFE_0000 with size 0x10_0000
        assert!(a.modlist().find_by_addr(0x7FFE_1000).is_some());
    }

    #[test]
    fn test_modlist_orphan_addresses() {
        let a = make_analyzer();
        let orphans = a.modlist().orphan_addresses(&[0xDEAD_BEEF]);
        assert_eq!(orphans.len(), 1);
    }

    // --- HandlesWalker ---

    #[test]
    fn test_handles_by_type() {
        let mut a = MemoryDumpAnalyzer::new();
        a.load_handles(vec![
            HandleRecord::new(1, 100, HandleType::File),
            HandleRecord::new(2, 100, HandleType::Mutex).with_name("Global\\M"),
        ]);
        assert_eq!(a.handles().by_type(HandleType::File).len(), 1);
        assert_eq!(a.handles().by_type(HandleType::Mutex).len(), 1);
    }

    #[test]
    fn test_handles_mutant_names() {
        let mut a = MemoryDumpAnalyzer::new();
        a.load_handles(vec![
            HandleRecord::new(1, 100, HandleType::Mutex).with_name("Global\\Malware"),
        ]);
        let names = a.handles().mutant_names();
        assert!(names.contains(&"Global\\Malware".to_string()));
    }

    // --- NetworkWalker ---

    #[test]
    fn test_network_count() {
        let a = make_analyzer();
        assert_eq!(a.network().count(), 1);
    }

    #[test]
    fn test_network_unique_ips() {
        let a = make_analyzer();
        assert!(!a.network().unique_remote_ips().is_empty());
    }

    // --- MemoryDumpAnalyzer ---

    #[test]
    fn test_report_summary() {
        let a = make_analyzer();
        let r = a.generate_report();
        assert!(!r.summary.is_empty());
        assert_eq!(r.process_count, 4);
        assert_eq!(r.module_count, 2);
    }

    #[test]
    fn test_report_suspicious_network() {
        let a = make_analyzer();
        let r = a.generate_report();
        // 1.2.3.4:8080 has port > 1024 — suspicious
        assert!(!r.suspicious_network.is_empty());
    }

    #[test]
    fn test_report_is_clean_empty_analyzer() {
        let a = MemoryDumpAnalyzer::new();
        let r = a.generate_report();
        assert!(r.is_clean());
    }

    #[test]
    fn test_report_threat_score() {
        let a = make_analyzer();
        let r = a.generate_report();
        let _ = r.threat_score();
    }

    #[test]
    fn test_analyze_image_too_small() {
        let mut a = MemoryDumpAnalyzer::new();
        let img = DumpImage::new(vec![0u8; 10]);
        assert!(matches!(
            a.analyze_image(&img),
            Err(DumpAnalyzerError::InsufficientData(_))
        ));
    }

    #[test]
    fn test_analyze_image_valid() {
        let mut a = MemoryDumpAnalyzer::new();
        let img = DumpImage::new(vec![0u8; 128]);
        assert!(a.analyze_image(&img).is_ok());
    }

    #[test]
    fn test_has_ioc_with_mutex() {
        let mut a = MemoryDumpAnalyzer::new();
        a.load_handles(vec![
            HandleRecord::new(1, 100, HandleType::Mutex).with_name("Global\\Malware"),
        ]);
        assert!(a.has_ioc());
    }

    #[test]
    fn test_errors_initially_empty() {
        let a = MemoryDumpAnalyzer::new();
        assert!(a.errors().is_empty());
    }
}
