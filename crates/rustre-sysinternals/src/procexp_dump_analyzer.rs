//! `procexp_dump_analyzer` — Analyze Process Explorer-style process / handle dumps.
//!
//! Process Explorer can export a text snapshot of all running processes, their
//! loaded DLLs, open handles, and memory maps.  This module parses such exports
//! (or synthesized equivalents built from live Win32 API calls) into typed
//! data structures and provides analysis helpers: suspicious DLL detection,
//! duplicate handle detection, memory anomaly flagging, and process-tree
//! reconstruction.

use std::collections::{HashMap, HashSet};
use std::fmt;

// ── HandleType ────────────────────────────────────────────────────────────────

/// Windows object types that appear as handle entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HandleType {
    File,
    Directory,
    RegistryKey,
    Event,
    Mutant,
    Semaphore,
    Section,
    Thread,
    Process,
    Token,
    Port,
    Desktop,
    WindowStation,
    Timer,
    IoCompletion,
    Unknown(String),
}

impl HandleType {
    /// Parse from the object-type string returned by Procexp / `NtQueryObject`.
    #[must_use]
    pub fn from_type_str(s: &str) -> Self {
        match s.trim() {
            "File" => Self::File,
            "Directory" => Self::Directory,
            "Key" | "Registry Key" => Self::RegistryKey,
            "Event" => Self::Event,
            "Mutant" | "Mutex" => Self::Mutant,
            "Semaphore" => Self::Semaphore,
            "Section" | "MemorySection" => Self::Section,
            "Thread" => Self::Thread,
            "Process" => Self::Process,
            "Token" => Self::Token,
            "ALPC Port" | "Port" => Self::Port,
            "Desktop" => Self::Desktop,
            "WindowStation" => Self::WindowStation,
            "Timer" => Self::Timer,
            "IoCompletionPort" | "IoCompletion" => Self::IoCompletion,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl fmt::Display for HandleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File => write!(f, "File"),
            Self::Directory => write!(f, "Directory"),
            Self::RegistryKey => write!(f, "RegistryKey"),
            Self::Event => write!(f, "Event"),
            Self::Mutant => write!(f, "Mutant"),
            Self::Semaphore => write!(f, "Semaphore"),
            Self::Section => write!(f, "Section"),
            Self::Thread => write!(f, "Thread"),
            Self::Process => write!(f, "Process"),
            Self::Token => write!(f, "Token"),
            Self::Port => write!(f, "Port"),
            Self::Desktop => write!(f, "Desktop"),
            Self::WindowStation => write!(f, "WindowStation"),
            Self::Timer => write!(f, "Timer"),
            Self::IoCompletion => write!(f, "IoCompletion"),
            Self::Unknown(s) => write!(f, "Unknown({s})"),
        }
    }
}

// ── HandleEntry ───────────────────────────────────────────────────────────────

/// A single open handle owned by a process.
#[derive(Debug, Clone)]
pub struct HandleEntry {
    /// Raw handle value (e.g. `0x3c`).
    pub handle_value: u64,
    /// Object type.
    pub handle_type: HandleType,
    /// Object name / path, if available.
    pub name: String,
    /// Number of references (handle count) if reported.
    pub ref_count: Option<u32>,
    /// Granted access mask, if reported.
    pub access_mask: Option<u32>,
}

impl HandleEntry {
    /// Returns `true` if this handle grants write access (bit 1 in the mask).
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.access_mask
            .is_some_and(|m| (m & 0x0002) != 0 || (m & 0x4000_0000) != 0)
    }
}

impl fmt::Display for HandleEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{:04x} {} \"{}\"",
            self.handle_value, self.handle_type, self.name
        )
    }
}

// ── DllEntry ─────────────────────────────────────────────────────────────────

/// A loaded DLL / memory-mapped image in a process.
#[derive(Debug, Clone)]
pub struct DllEntry {
    /// Base address in the process VA space.
    pub base_address: u64,
    /// Image size in bytes.
    pub size: u64,
    /// Full path on disk, if available.
    pub path: String,
    /// Whether this module appears to be a genuine system DLL.
    pub is_system: bool,
    /// Whether the image has been verified (signed / known hash).
    pub is_verified: bool,
}

impl DllEntry {
    /// Returns the filename portion of the path.
    #[must_use]
    pub fn filename(&self) -> &str {
        self.path
            .rfind(['\\', '/'])
            .map_or(self.path.as_str(), |i| &self.path[i + 1..])
    }

    /// Returns `true` if this DLL is potentially suspicious.
    ///
    /// Heuristics: loaded from temp directory, not verified, loaded below 0x1000.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        if !self.is_verified {
            return true;
        }
        let lower = self.path.to_lowercase();
        if lower.contains("\\temp\\") || lower.contains("\\tmp\\") || lower.contains("\\appdata\\local\\temp") {
            return true;
        }
        if self.base_address < 0x1000 && self.base_address != 0 {
            return true;
        }
        false
    }
}

impl fmt::Display for DllEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{:016x}+0x{:x} {}",
            self.base_address, self.size, self.path
        )
    }
}

// ── IntegrityLevel ────────────────────────────────────────────────────────────

/// Windows integrity level of a process token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    Untrusted = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    System = 4,
    Unknown = 5,
}

impl From<&str> for IntegrityLevel {
    fn from(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "untrusted" => Self::Untrusted,
            "low" => Self::Low,
            "medium" | "medium plus" => Self::Medium,
            "high" => Self::High,
            "system" => Self::System,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for IntegrityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untrusted => write!(f, "Untrusted"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::System => write!(f, "System"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ── ProcessEntry ─────────────────────────────────────────────────────────────

/// A single process record from a Process Explorer dump.
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    /// Process identifier.
    pub pid: u32,
    /// Parent process identifier.
    pub parent_pid: u32,
    /// Image base name (e.g. `"svchost.exe"`).
    pub image_name: String,
    /// Full path on disk, if available.
    pub image_path: String,
    /// Command line, if available.
    pub command_line: String,
    /// User name running the process, if available.
    pub user: String,
    /// Token integrity level.
    pub integrity: IntegrityLevel,
    /// CPU usage (0.0–100.0), if available.
    pub cpu_usage: f64,
    /// Working set in bytes, if available.
    pub working_set_bytes: u64,
    /// Private bytes (commit charge), if available.
    pub private_bytes: u64,
    /// Open handles.
    pub handles: Vec<HandleEntry>,
    /// Loaded DLLs / mapped images.
    pub dlls: Vec<DllEntry>,
    /// Whether the process image is verified / signed.
    pub is_verified: bool,
    /// Whether the process has been flagged as potentially malicious.
    pub is_flagged: bool,
}

impl ProcessEntry {
    /// Create a minimal process entry with just pid, ppid, and name.
    #[must_use]
    pub fn new(pid: u32, parent_pid: u32, image_name: impl Into<String>) -> Self {
        Self {
            pid,
            parent_pid,
            image_name: image_name.into(),
            image_path: String::new(),
            command_line: String::new(),
            user: String::new(),
            integrity: IntegrityLevel::Unknown,
            cpu_usage: 0.0,
            working_set_bytes: 0,
            private_bytes: 0,
            handles: Vec::new(),
            dlls: Vec::new(),
            is_verified: false,
            is_flagged: false,
        }
    }

    /// Returns the count of file handles.
    #[must_use]
    pub fn file_handle_count(&self) -> usize {
        self.handles.iter().filter(|h| h.handle_type == HandleType::File).count()
    }

    /// Returns the count of registry-key handles.
    #[must_use]
    pub fn registry_handle_count(&self) -> usize {
        self.handles.iter().filter(|h| h.handle_type == HandleType::RegistryKey).count()
    }

    /// Returns all suspicious DLL entries.
    #[must_use]
    pub fn suspicious_dlls(&self) -> Vec<&DllEntry> {
        self.dlls.iter().filter(|d| d.is_suspicious()).collect()
    }

    /// Returns `true` if the process looks anomalous by simple heuristics.
    #[must_use]
    pub fn is_anomalous(&self) -> bool {
        // Unsigned image.
        if !self.is_verified { return true; }
        // Suspicious DLLs loaded.
        if !self.suspicious_dlls().is_empty() { return true; }
        // svchost without proper path.
        if self.image_name.eq_ignore_ascii_case("svchost.exe")
            && !self.image_path.to_lowercase().contains("system32") {
            return true;
        }
        false
    }
}

impl fmt::Display for ProcessEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PID {:6} (PPID {:6}) [{}] {} handles={} dlls={}",
            self.pid,
            self.parent_pid,
            self.integrity,
            self.image_name,
            self.handles.len(),
            self.dlls.len(),
        )
    }
}

// ── ProcExpDumpAnalyzer ───────────────────────────────────────────────────────

/// Analyzes a set of `ProcessEntry` records (e.g. from a Process Explorer dump).
pub struct ProcExpDumpAnalyzer {
    /// All process entries, keyed by PID.
    pub processes: HashMap<u32, ProcessEntry>,
}

impl ProcExpDumpAnalyzer {
    /// Create an analyzer from a flat list of process entries.
    #[must_use]
    pub fn from_entries(entries: Vec<ProcessEntry>) -> Self {
        let mut processes = HashMap::new();
        for e in entries {
            processes.insert(e.pid, e);
        }
        Self { processes }
    }

    /// Return all children of `parent_pid` (direct children only).
    #[must_use]
    pub fn children_of(&self, parent_pid: u32) -> Vec<&ProcessEntry> {
        self.processes
            .values()
            .filter(|p| p.parent_pid == parent_pid && p.pid != parent_pid)
            .collect()
    }

    /// Reconstruct the process tree as a map from PID → child PIDs.
    #[must_use]
    pub fn process_tree(&self) -> HashMap<u32, Vec<u32>> {
        let mut tree: HashMap<u32, Vec<u32>> = HashMap::new();
        for p in self.processes.values() {
            if p.parent_pid != p.pid {
                tree.entry(p.parent_pid).or_default().push(p.pid);
            }
        }
        tree
    }

    /// Return all processes running at `High` or `System` integrity.
    #[must_use]
    pub fn elevated_processes(&self) -> Vec<&ProcessEntry> {
        self.processes
            .values()
            .filter(|p| p.integrity >= IntegrityLevel::High)
            .collect()
    }

    /// Return all processes flagged as anomalous by heuristics.
    #[must_use]
    pub fn anomalous_processes(&self) -> Vec<&ProcessEntry> {
        self.processes.values().filter(|p| p.is_anomalous()).collect()
    }

    /// Return all processes that have loaded at least one suspicious DLL.
    #[must_use]
    pub fn processes_with_suspicious_dlls(&self) -> Vec<&ProcessEntry> {
        self.processes
            .values()
            .filter(|p| !p.suspicious_dlls().is_empty())
            .collect()
    }

    /// Find duplicate named mutants across all processes (indicator of
    /// infection / coordination).
    #[must_use]
    pub fn shared_named_mutants(&self) -> Vec<(String, Vec<u32>)> {
        let mut mutant_pids: HashMap<String, Vec<u32>> = HashMap::new();
        for p in self.processes.values() {
            for h in &p.handles {
                if h.handle_type == HandleType::Mutant && !h.name.is_empty() {
                    mutant_pids.entry(h.name.clone()).or_default().push(p.pid);
                }
            }
        }
        let mut result: Vec<(String, Vec<u32>)> = mutant_pids
            .into_iter()
            .filter(|(_, pids)| pids.len() > 1)
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    /// Return all network-related handles (sockets, ports) across all processes.
    #[must_use]
    pub fn network_handles(&self) -> Vec<(u32, &HandleEntry)> {
        let mut result = Vec::new();
        for p in self.processes.values() {
            for h in &p.handles {
                if matches!(h.handle_type, HandleType::Port) {
                    result.push((p.pid, h));
                }
            }
        }
        result.sort_by_key(|(pid, _)| *pid);
        result
    }

    /// Find processes whose image name appears multiple times (potential
    /// process hollowing / masquerading).
    #[must_use]
    pub fn duplicate_image_names(&self) -> Vec<(String, Vec<u32>)> {
        let mut name_pids: HashMap<String, Vec<u32>> = HashMap::new();
        for p in self.processes.values() {
            name_pids
                .entry(p.image_name.to_lowercase())
                .or_default()
                .push(p.pid);
        }
        let mut result: Vec<(String, Vec<u32>)> = name_pids
            .into_iter()
            .filter(|(_, pids)| pids.len() > 1)
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    /// Return all unique DLL paths loaded across all processes.
    #[must_use]
    pub fn all_dll_paths(&self) -> Vec<&str> {
        let mut set: HashSet<&str> = HashSet::new();
        for p in self.processes.values() {
            for d in &p.dlls {
                if !d.path.is_empty() {
                    set.insert(d.path.as_str());
                }
            }
        }
        let mut paths: Vec<&str> = set.into_iter().collect();
        paths.sort_unstable();
        paths
    }

    /// Compute total handle count across all processes.
    #[must_use]
    pub fn total_handle_count(&self) -> usize {
        self.processes.values().map(|p| p.handles.len()).sum()
    }

    /// Find processes with more than `threshold` handles.
    #[must_use]
    pub fn handle_heavy_processes(&self, threshold: usize) -> Vec<&ProcessEntry> {
        self.processes
            .values()
            .filter(|p| p.handles.len() > threshold)
            .collect()
    }

    /// Returns a summary string for quick reporting.
    #[must_use]
    pub fn summary(&self) -> String {
        let total = self.processes.len();
        let anomalous = self.anomalous_processes().len();
        let elevated = self.elevated_processes().len();
        let susp_dll = self.processes_with_suspicious_dlls().len();
        format!(
            "Processes: {total} | Anomalous: {anomalous} | Elevated: {elevated} | Suspicious DLLs: {susp_dll}"
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_process(pid: u32, parent_pid: u32, name: &str) -> ProcessEntry {
        let mut p = ProcessEntry::new(pid, parent_pid, name);
        p.is_verified = true;
        p.integrity = IntegrityLevel::Medium;
        p
    }

    fn make_suspicious_process(pid: u32, parent_pid: u32) -> ProcessEntry {
        let mut p = ProcessEntry::new(pid, parent_pid, "evil.exe");
        p.is_verified = false;
        p.dlls.push(DllEntry {
            base_address: 0x1_0000_0000,
            size: 0x1000,
            path: r"C:\Users\user\AppData\Local\Temp\payload.dll".to_string(),
            is_system: false,
            is_verified: false,
        });
        p
    }

    #[test]
    fn test_process_tree() {
        let entries = vec![
            make_process(4, 0, "System"),
            make_process(500, 4, "smss.exe"),
            make_process(800, 500, "csrss.exe"),
        ];
        let analyzer = ProcExpDumpAnalyzer::from_entries(entries);
        let tree = analyzer.process_tree();
        assert!(tree.get(&4).unwrap().contains(&500));
        assert!(tree.get(&500).unwrap().contains(&800));
    }

    #[test]
    fn test_children_of() {
        let entries = vec![
            make_process(1, 0, "init"),
            make_process(2, 1, "child1"),
            make_process(3, 1, "child2"),
            make_process(4, 2, "grandchild"),
        ];
        let analyzer = ProcExpDumpAnalyzer::from_entries(entries);
        let children = analyzer.children_of(1);
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_anomalous_detection() {
        let entries = vec![
            make_process(100, 4, "explorer.exe"),
            make_suspicious_process(200, 100),
        ];
        let analyzer = ProcExpDumpAnalyzer::from_entries(entries);
        let anomalous = analyzer.anomalous_processes();
        assert_eq!(anomalous.len(), 1);
        assert_eq!(anomalous[0].pid, 200);
    }

    #[test]
    fn test_duplicate_image_names() {
        let entries = vec![
            make_process(100, 4, "svchost.exe"),
            make_process(200, 4, "svchost.exe"),
            make_process(300, 4, "explorer.exe"),
        ];
        let analyzer = ProcExpDumpAnalyzer::from_entries(entries);
        let dups = analyzer.duplicate_image_names();
        assert!(!dups.is_empty());
        let svchost = dups.iter().find(|(n, _)| n == "svchost.exe");
        assert!(svchost.is_some());
        assert_eq!(svchost.unwrap().1.len(), 2);
    }

    #[test]
    fn test_shared_named_mutants() {
        let mut p1 = make_process(100, 4, "malware.exe");
        p1.handles.push(HandleEntry {
            handle_value: 0x10,
            handle_type: HandleType::Mutant,
            name: "Global\\EvilMutex".to_string(),
            ref_count: None,
            access_mask: None,
        });
        let mut p2 = make_process(200, 4, "dropper.exe");
        p2.handles.push(HandleEntry {
            handle_value: 0x20,
            handle_type: HandleType::Mutant,
            name: "Global\\EvilMutex".to_string(),
            ref_count: None,
            access_mask: None,
        });
        let analyzer = ProcExpDumpAnalyzer::from_entries(vec![p1, p2]);
        let shared = analyzer.shared_named_mutants();
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].0, "Global\\EvilMutex");
        assert_eq!(shared[0].1.len(), 2);
    }

    #[test]
    fn test_handle_entry_display() {
        let h = HandleEntry {
            handle_value: 0x3c,
            handle_type: HandleType::File,
            name: r"C:\Windows\System32\ntdll.dll".to_string(),
            ref_count: Some(1),
            access_mask: Some(0x0001),
        };
        let s = h.to_string();
        assert!(s.contains("003c"));
        assert!(s.contains("File"));
    }

    #[test]
    fn test_dll_suspicious_temp() {
        let dll = DllEntry {
            base_address: 0x7fff_0000,
            size: 0x1000,
            path: r"C:\Users\foo\AppData\Local\Temp\inject.dll".to_string(),
            is_system: false,
            is_verified: true, // even verified but from temp
        };
        assert!(dll.is_suspicious());
    }

    #[test]
    fn test_elevated_processes() {
        let mut p = make_process(999, 4, "elevated.exe");
        p.integrity = IntegrityLevel::High;
        let analyzer = ProcExpDumpAnalyzer::from_entries(vec![p]);
        assert_eq!(analyzer.elevated_processes().len(), 1);
    }

    #[test]
    fn test_summary_string() {
        let entries = vec![make_process(1, 0, "idle")];
        let analyzer = ProcExpDumpAnalyzer::from_entries(entries);
        let s = analyzer.summary();
        assert!(s.contains("Processes: 1"));
    }

    #[test]
    fn test_total_handle_count() {
        let mut p = make_process(100, 4, "proc.exe");
        p.handles.push(HandleEntry {
            handle_value: 0x4,
            handle_type: HandleType::File,
            name: String::new(),
            ref_count: None,
            access_mask: None,
        });
        let analyzer = ProcExpDumpAnalyzer::from_entries(vec![p]);
        assert_eq!(analyzer.total_handle_count(), 1);
    }
}
