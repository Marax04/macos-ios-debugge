//! Process monitor: enumerate running processes, memory usage, thread count,
//! open handles, loaded modules, and PEB (Process Environment Block) parsing.

use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};

// ─── Process information ──────────────────────────────────────────────────────

/// Snapshot of a running process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmdline: String,
    pub working_dir: String,
    pub threads: Vec<ThreadInfo>,
    pub modules: Vec<ModuleInfo>,
    pub memory: ProcessMemory,
    pub handles: Vec<HandleInfo>,
    pub peb: Option<PebInfo>,
    pub integrity_level: IntegrityLevel,
    pub is_wow64: bool,
    pub create_time_ms: u64,
    pub user: String,
    pub session_id: u32,
}

impl ProcessInfo {
    /// Create a minimal process info for a pid.
    #[must_use]
    pub fn new(pid: u32, name: impl Into<String>) -> Self {
        Self {
            pid,
            ppid: 0,
            name: name.into(),
            exe_path: String::new(),
            cmdline: String::new(),
            working_dir: String::new(),
            threads: vec![],
            modules: vec![],
            memory: ProcessMemory::default(),
            handles: vec![],
            peb: None,
            integrity_level: IntegrityLevel::Medium,
            is_wow64: false,
            create_time_ms: 0,
            user: String::new(),
            session_id: 0,
        }
    }

    /// Returns the main executable module, if present.
    #[must_use]
    pub fn main_module(&self) -> Option<&ModuleInfo> {
        self.modules.first()
    }

    /// Returns `true` if any loaded module matches the given name (case-insensitive).
    #[must_use]
    pub fn has_module(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.modules.iter().any(|m| m.name.to_lowercase() == lower)
    }

    /// Returns the total number of open handles.
    #[must_use]
    pub const fn handle_count(&self) -> usize {
        self.handles.len()
    }

    /// Filter handles by type.
    #[must_use]
    pub fn handles_of_type(&self, ty: HandleType) -> Vec<&HandleInfo> {
        self.handles.iter().filter(|h| h.handle_type == ty).collect()
    }

    /// Returns `true` if the process looks like it is injected (suspicious modules).
    #[must_use]
    pub fn has_suspicious_modules(&self) -> bool {
        let suspicious_names = [
            "inject", "hook", "payload", "shellcode", "loader",
        ];
        self.modules.iter().any(|m| {
            let lower = m.name.to_lowercase();
            suspicious_names.iter().any(|s| lower.contains(s))
        })
    }

    /// Estimate whether this process has elevated privileges.
    #[must_use]
    pub const fn is_elevated(&self) -> bool {
        matches!(self.integrity_level, IntegrityLevel::High | IntegrityLevel::System)
    }
}

// ─── Thread information ───────────────────────────────────────────────────────

/// Information about a thread within a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    pub tid: u32,
    pub pid: u32,
    pub start_address: u64,
    pub state: ThreadState,
    pub priority: i32,
    pub context_switches: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
    pub teb_address: u64,
}

/// Thread execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreadState {
    Running,
    Ready,
    Waiting,
    Standby,
    Terminated,
    Unknown,
}

impl std::fmt::Display for ThreadState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "Running"),
            Self::Ready => write!(f, "Ready"),
            Self::Waiting => write!(f, "Waiting"),
            Self::Standby => write!(f, "Standby"),
            Self::Terminated => write!(f, "Terminated"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─── Module information ───────────────────────────────────────────────────────

/// Boolean attributes of a loaded module.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleFlags {
    pub is_64bit: bool,
    pub is_main: bool,
    pub is_signed: bool,
    pub signature_valid: bool,
}

/// A loaded module (DLL or EXE) in a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: u64,
    pub size: u64,
    pub entry_point: u64,
    pub characteristics: u32,
    pub flags: ModuleFlags,
    pub load_count: u32,
    pub checksum: u32,
    pub timestamp: u32,
}

impl ModuleInfo {
    /// Create a minimal module info.
    #[must_use]
    pub fn new(name: impl Into<String>, base: u64, size: u64) -> Self {
        Self {
            name: name.into(),
            path: String::new(),
            base_address: base,
            size,
            entry_point: 0,
            characteristics: 0,
            flags: ModuleFlags { is_64bit: true, is_main: false, is_signed: false, signature_valid: false },
            load_count: 1,
            checksum: 0,
            timestamp: 0,
        }
    }

    /// Returns `true` if this module is a system DLL (heuristic: path starts with System32/SysWOW64).
    #[must_use]
    pub fn is_system(&self) -> bool {
        let p = self.path.to_lowercase();
        p.contains("system32") || p.contains("syswow64") || p.contains("windows\\system")
    }

    /// Returns the address range [base, base+size).
    #[must_use]
    pub const fn address_range(&self) -> std::ops::Range<u64> {
        self.base_address..self.base_address + self.size
    }

    /// Whether the given address is within this module.
    #[must_use]
    pub fn contains_address(&self, addr: u64) -> bool {
        self.address_range().contains(&addr)
    }
}

// ─── Memory information ───────────────────────────────────────────────────────

/// Memory statistics for a process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessMemory {
    pub working_set_bytes: u64,
    pub peak_working_set_bytes: u64,
    pub private_bytes: u64,
    pub virtual_size_bytes: u64,
    pub page_fault_count: u64,
    pub commit_charge_bytes: u64,
    pub peak_commit_bytes: u64,
    pub regions: Vec<MemoryRegion>,
}

impl ProcessMemory {
    /// Returns total executable region size in bytes.
    #[must_use]
    pub fn executable_size(&self) -> u64 {
        self.regions
            .iter()
            .filter(|r| r.is_executable)
            .map(|r| r.size)
            .sum()
    }

    /// Returns all writable+executable (WX) regions.
    #[must_use]
    pub fn wx_regions(&self) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.is_executable && r.is_writable)
            .collect()
    }

    /// Count heap regions.
    #[must_use]
    pub fn heap_count(&self) -> usize {
        self.regions.iter().filter(|r| r.region_type == RegionType::Heap).count()
    }
}

/// A single memory region in a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: u64,
    pub state: MemoryState,
    pub protect: u32,
    pub region_type: RegionType,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool,
    pub module_name: Option<String>,
}

impl MemoryRegion {
    /// Protection string (e.g., "RWX").
    #[must_use]
    pub fn protect_str(&self) -> String {
        let mut s = String::with_capacity(3);
        if self.is_readable { s.push('R'); }
        if self.is_writable { s.push('W'); }
        if self.is_executable { s.push('X'); }
        if s.is_empty() { s.push_str("---"); }
        s
    }
}

/// Memory region state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryState { Committed, Reserved, Free }

/// Memory region type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionType { Private, Mapped, Image, Heap, Stack, Unknown }

// ─── Handle information ───────────────────────────────────────────────────────

/// An open handle in a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleInfo {
    pub handle_value: u64,
    pub handle_type: HandleType,
    pub object_name: String,
    pub granted_access: u32,
    pub attributes: u32,
    pub ref_count: u32,
    pub pointer_count: u64,
}

/// Type of handle object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandleType {
    File,
    Key,
    Process,
    Thread,
    Section,
    Event,
    Mutex,
    Semaphore,
    Token,
    IoCompletionPort,
    Desktop,
    WindowStation,
    Port,
    Other,
}

impl std::fmt::Display for HandleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File => write!(f, "File"),
            Self::Key => write!(f, "Key"),
            Self::Process => write!(f, "Process"),
            Self::Thread => write!(f, "Thread"),
            Self::Section => write!(f, "Section"),
            Self::Event => write!(f, "Event"),
            Self::Mutex => write!(f, "Mutex"),
            Self::Semaphore => write!(f, "Semaphore"),
            Self::Token => write!(f, "Token"),
            Self::IoCompletionPort => write!(f, "IoCompletionPort"),
            Self::Desktop => write!(f, "Desktop"),
            Self::WindowStation => write!(f, "WindowStation"),
            Self::Port => write!(f, "Port"),
            Self::Other => write!(f, "Other"),
        }
    }
}

// ─── PEB information ──────────────────────────────────────────────────────────

/// Process Environment Block parsed information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PebInfo {
    /// PEB base address.
    pub peb_address: u64,
    /// Whether a debugger is attached (`BeingDebugged` flag).
    pub being_debugged: bool,
    /// `NtGlobalFlag` value.
    pub nt_global_flag: u32,
    /// `ProcessHeap` address.
    pub process_heap: u64,
    /// Image base address from PEB.
    pub image_base: u64,
    /// `OSMajorVersion`.
    pub os_major: u32,
    pub os_minor: u32,
    /// Whether `NtQueryInformationProcess` indicated no debugger.
    pub no_debug_inherit: bool,
    /// `FlsCallback` table (anti-debug check target).
    pub fls_callback_count: usize,
    /// Loader data (`LDR_DATA`) address.
    pub ldr_data: u64,
    /// `NumberOfProcessors`.
    pub cpu_count: u32,
    /// `HideFromDebugger` flag from `NtQueryInfoThread`.
    pub hide_from_debugger: bool,
}

impl PebInfo {
    /// Whether any anti-debug flags are set.
    #[must_use]
    pub const fn has_debug_artifacts(&self) -> bool {
        self.being_debugged
            || (self.nt_global_flag & 0x70) != 0 // heap debug flags
            || self.hide_from_debugger
    }
}

// ─── Integrity level ─────────────────────────────────────────────────────────

/// Windows mandatory integrity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Untrusted = 0,
    Low = 1,
    Medium = 2,
    MediumPlus = 3,
    High = 4,
    System = 5,
    Protected = 6,
}

impl std::fmt::Display for IntegrityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Untrusted => write!(f, "Untrusted"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::MediumPlus => write!(f, "MediumPlus"),
            Self::High => write!(f, "High"),
            Self::System => write!(f, "System"),
            Self::Protected => write!(f, "Protected"),
        }
    }
}

// ─── ProcessSnapshot ─────────────────────────────────────────────────────────

/// A snapshot of all processes at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub timestamp_ms: u64,
    pub processes: Vec<ProcessInfo>,
    pub total_cpu_percent: f32,
    pub total_memory_bytes: u64,
    pub suspicious_pids: Vec<u32>,
}

impl ProcessSnapshot {
    /// Create a new snapshot.
    #[must_use]
    pub const fn new(timestamp_ms: u64) -> Self {
        Self {
            timestamp_ms,
            processes: Vec::new(),
            total_cpu_percent: 0.0,
            total_memory_bytes: 0,
            suspicious_pids: Vec::new(),
        }
    }

    /// Look up a process by PID.
    #[must_use]
    pub fn find_by_pid(&self, pid: u32) -> Option<&ProcessInfo> {
        self.processes.iter().find(|p| p.pid == pid)
    }

    /// Find all processes whose names contain the given substring (case-insensitive).
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&ProcessInfo> {
        let lower = name.to_lowercase();
        self.processes.iter().filter(|p| p.name.to_lowercase().contains(&lower)).collect()
    }

    /// Build a process tree (pid → children).
    #[must_use]
    pub fn process_tree(&self) -> HashMap<u32, Vec<u32>> {
        let mut tree: HashMap<u32, Vec<u32>> = HashMap::new();
        for p in &self.processes {
            tree.entry(p.ppid).or_default().push(p.pid);
        }
        tree
    }

    /// Find processes with WX memory regions (potential shellcode injection).
    #[must_use]
    pub fn wx_processes(&self) -> Vec<&ProcessInfo> {
        self.processes
            .iter()
            .filter(|p| !p.memory.wx_regions().is_empty())
            .collect()
    }

    /// Compute per-module load count across all processes.
    #[must_use]
    pub fn module_prevalence(&self) -> HashMap<String, usize> {
        let mut freq: HashMap<String, usize> = HashMap::new();
        for p in &self.processes {
            for m in &p.modules {
                *freq.entry(m.name.to_lowercase()).or_insert(0) += 1;
            }
        }
        freq
    }

    /// Mark processes with suspicious indicators.
    pub fn analyze_suspicious(&mut self) {
        let suspicious: Vec<u32> = self.processes
            .iter()
            .filter(|p| {
                p.has_suspicious_modules()
                    || !p.memory.wx_regions().is_empty()
                    || p.peb.as_ref().is_some_and(PebInfo::has_debug_artifacts)
            })
            .map(|p| p.pid)
            .collect();
        self.suspicious_pids = suspicious;
    }

    /// Return total process count.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.processes.len()
    }
}

// ─── ProcessMonitor ───────────────────────────────────────────────────────────

/// Main process monitor: collects and tracks process snapshots.
pub struct ProcessMonitor {
    pub snapshots: Vec<ProcessSnapshot>,
    pub filter_pid: Option<u32>,
    pub include_system: bool,
    pub max_depth: usize,
}

impl Default for ProcessMonitor {
    fn default() -> Self {
        Self {
            snapshots: Vec::new(),
            filter_pid: None,
            include_system: false,
            max_depth: 16,
        }
    }
}

impl ProcessMonitor {
    /// Create a new monitor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a snapshot to the history.
    pub fn add_snapshot(&mut self, snap: ProcessSnapshot) {
        self.snapshots.push(snap);
    }

    /// Latest snapshot.
    #[must_use]
    pub fn latest(&self) -> Option<&ProcessSnapshot> {
        self.snapshots.last()
    }

    /// Diff between two snapshots: new processes, exited processes.
    #[must_use]
    pub fn diff(&self, a: &ProcessSnapshot, b: &ProcessSnapshot) -> ProcessDiff {
        let a_pids: std::collections::HashSet<u32> = a.processes.iter().map(|p| p.pid).collect();
        let b_pids: std::collections::HashSet<u32> = b.processes.iter().map(|p| p.pid).collect();

        let new_pids: Vec<u32> = b_pids.difference(&a_pids).copied().collect();
        let exited_pids: Vec<u32> = a_pids.difference(&b_pids).copied().collect();

        let new_processes = b.processes.iter().filter(|p| new_pids.contains(&p.pid)).cloned().collect();
        let exited_processes = a.processes.iter().filter(|p| exited_pids.contains(&p.pid)).cloned().collect();

        ProcessDiff {
            new_processes,
            exited_processes,
            time_delta_ms: b.timestamp_ms.saturating_sub(a.timestamp_ms),
        }
    }

    /// Build synthetic snapshot from a list of [`ProcessInfo`] records.
    #[must_use]
    pub fn build_snapshot(processes: Vec<ProcessInfo>, ts_ms: u64) -> ProcessSnapshot {
        let total_memory: u64 = processes.iter().map(|p| p.memory.working_set_bytes).sum();
        let mut snap = ProcessSnapshot {
            timestamp_ms: ts_ms,
            processes,
            total_cpu_percent: 0.0,
            total_memory_bytes: total_memory,
            suspicious_pids: vec![],
        };
        snap.analyze_suspicious();
        snap
    }

    /// Find processes with WX regions across all snapshots.
    #[must_use]
    pub fn all_wx_processes(&self) -> Vec<(u64, u32)> {
        let mut result = Vec::new();
        for snap in &self.snapshots {
            for p in snap.wx_processes() {
                result.push((snap.timestamp_ms, p.pid));
            }
        }
        result
    }
}

/// Diff between two process snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDiff {
    pub new_processes: Vec<ProcessInfo>,
    pub exited_processes: Vec<ProcessInfo>,
    pub time_delta_ms: u64,
}

// ─── PEB parser ───────────────────────────────────────────────────────────────

/// Parse PEB fields from a raw memory dump of the PEB structure.
///
/// Layout is for 64-bit Windows 10/11 PEB.
///
/// # Errors
///
/// Returns an error if `peb_bytes` is smaller than the minimum expected PEB size.
pub fn parse_peb_64(peb_bytes: &[u8], peb_address: u64) -> Result<PebInfo> {
    if peb_bytes.len() < 0x280 {
        return Err(anyhow!("PEB buffer too small: {} bytes", peb_bytes.len()));
    }
    let read_u8 = |off: usize| -> u8 { peb_bytes[off] };
    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes(peb_bytes[off..off + 4].try_into().unwrap_or([0; 4]))
    };
    let read_u64 = |off: usize| -> u64 {
        u64::from_le_bytes(peb_bytes[off..off + 8].try_into().unwrap_or([0; 8]))
    };

    let being_debugged = read_u8(0x02) != 0;
    let nt_global_flag = read_u32(0xbc);
    let image_base = read_u64(0x10);
    let ldr_data = read_u64(0x18);
    let process_heap = read_u64(0x30);
    let os_major = read_u32(0x118);
    let os_minor = read_u32(0x11c);
    let cpu_count = read_u32(0x64);

    Ok(PebInfo {
        peb_address,
        being_debugged,
        nt_global_flag,
        process_heap,
        image_base,
        os_major,
        os_minor,
        no_debug_inherit: false,
        fls_callback_count: 0,
        ldr_data,
        cpu_count,
        hide_from_debugger: false,
    })
}

/// Parse PEB fields from a 32-bit Windows process PEB.
///
/// # Errors
///
/// Returns an error if `peb_bytes` is smaller than the minimum expected PEB32 size.
pub fn parse_peb_32(peb_bytes: &[u8], peb_address: u64) -> Result<PebInfo> {
    if peb_bytes.len() < 0x100 {
        return Err(anyhow!("PEB32 buffer too small: {} bytes", peb_bytes.len()));
    }
    let read_u8 = |off: usize| -> u8 { peb_bytes[off] };
    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes(peb_bytes[off..off + 4].try_into().unwrap_or([0; 4]))
    };

    let being_debugged = read_u8(0x02) != 0;
    let ldr_data = u64::from(read_u32(0x0c));
    let process_heap = u64::from(read_u32(0x18));
    let nt_global_flag = read_u32(0x68);
    let image_base = u64::from(read_u32(0x08));
    let os_major = read_u32(0xa4);
    let os_minor = read_u32(0xa8);
    let cpu_count = read_u32(0x40);

    Ok(PebInfo {
        peb_address,
        being_debugged,
        nt_global_flag,
        process_heap,
        image_base,
        os_major,
        os_minor,
        no_debug_inherit: false,
        fls_callback_count: 0,
        ldr_data,
        cpu_count,
        hide_from_debugger: false,
    })
}

/// Return the [`PathBuf`] for a process's executable image.
///
/// Centralises conversion of the stringly-typed `exe_path` so callers can
/// reason about the process image as a real filesystem path.
#[must_use]
pub fn process_exe_pathbuf(p: &ProcessInfo) -> PathBuf {
    PathBuf::from(&p.exe_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_process() -> ProcessInfo {
        let mut p = ProcessInfo::new(1234, "test.exe");
        p.modules.push(ModuleInfo::new("test.exe", 0x0040_0000, 0x0010_0000));
        p.memory.regions.push(MemoryRegion {
            base_address: 0x0050_0000,
            size: 0x1000,
            state: MemoryState::Committed,
            protect: 0x40,
            region_type: RegionType::Private,
            is_readable: true,
            is_writable: true,
            is_executable: true,
            module_name: None,
        });
        p
    }

    #[test]
    fn test_process_info_creation() {
        let p = make_test_process();
        assert_eq!(p.pid, 1234);
        assert_eq!(p.name, "test.exe");
    }

    #[test]
    fn test_wx_regions_detected() {
        let p = make_test_process();
        assert_eq!(p.memory.wx_regions().len(), 1);
    }

    #[test]
    fn test_snapshot_wx_processes() {
        let p = make_test_process();
        let snap = ProcessMonitor::build_snapshot(vec![p], 1000);
        assert!(!snap.wx_processes().is_empty());
    }

    #[test]
    fn test_process_tree() {
        let p1 = ProcessInfo::new(1, "system");
        let mut p2 = ProcessInfo::new(100, "explorer.exe");
        p2.ppid = 1;
        let snap = ProcessMonitor::build_snapshot(vec![p1, p2], 0);
        let tree = snap.process_tree();
        assert!(tree.get(&1).is_some());
    }

    #[test]
    fn test_diff_new_process() {
        let monitor = ProcessMonitor::new();
        let snap1 = ProcessMonitor::build_snapshot(vec![], 0);
        let snap2 = ProcessMonitor::build_snapshot(vec![ProcessInfo::new(999, "new.exe")], 1000);
        let diff = monitor.diff(&snap1, &snap2);
        assert_eq!(diff.new_processes.len(), 1);
        assert_eq!(diff.new_processes[0].pid, 999);
    }

    #[test]
    fn test_peb_parse_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_peb_64(&data, 0x1000).is_err());
    }

    #[test]
    fn test_peb_parse_64_zeros() {
        let data = vec![0u8; 0x300];
        let peb = parse_peb_64(&data, 0x7ffe_0000).unwrap();
        assert!(!peb.being_debugged);
        assert_eq!(peb.peb_address, 0x7ffe_0000);
    }

    #[test]
    fn test_module_address_range() {
        let m = ModuleInfo::new("ntdll.dll", 0x7700_0000, 0x0010_0000);
        assert!(m.contains_address(0x7700_0000));
        assert!(m.contains_address(0x770f_ffff));
        assert!(!m.contains_address(0x7710_0000));
    }
}
