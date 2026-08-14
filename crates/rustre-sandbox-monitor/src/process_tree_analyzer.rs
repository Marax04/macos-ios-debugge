//! Process tree analysis: building, traversing, and scoring process trees
//! for hollowing, injection, and other suspicious parent–child relationships.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── ProcessNode ──────────────────────────────────────────────────────────────

/// A single process node in the process tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: String,
    pub image_path: String,
    pub start_time_ms: u64,
    pub end_time_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub is_injected: bool,
    pub is_hollow: bool,
    pub integrity_level: IntegrityLevel,
    pub user: String,
    pub api_calls: Vec<String>,
    pub tags: Vec<String>,
}

impl ProcessNode {
    /// Create a minimal process node.
    #[must_use]
    pub fn new(pid: u32, parent_pid: u32, proc_name: impl Into<String>, cmdline: impl Into<String>) -> Self {
        Self {
            pid,
            ppid: parent_pid,
            name: proc_name.into(),
            cmdline: cmdline.into(),
            image_path: String::new(),
            start_time_ms: 0,
            end_time_ms: None,
            exit_code: None,
            is_injected: false,
            is_hollow: false,
            integrity_level: IntegrityLevel::Medium,
            user: String::new(),
            api_calls: vec![],
            tags: vec![],
        }
    }

    /// Returns `true` if this process spawned from a shell.
    #[must_use]
    pub fn spawned_from_shell(&self) -> bool {
        let lower = self.name.to_ascii_lowercase();
        lower.contains("cmd")
            || lower.contains("powershell")
            || lower.contains("bash")
            || lower.contains("wscript")
            || lower.contains("cscript")
    }

    /// Returns `true` if the process image is a `LOLBin`.
    #[must_use]
    pub fn is_lolbin(&self) -> bool {
        let lower = self.name.to_ascii_lowercase();
        [
            "certutil",
            "wscript",
            "cscript",
            "mshta",
            "regsvr32",
            "rundll32",
            "msiexec",
            "bitsadmin",
            "wmic",
            "powershell",
            "msbuild",
            "installutil",
            "cmstp",
            "xwizard",
            "syncappvpublishingserver",
        ]
        .iter()
        .any(|l| lower.contains(l))
    }

    /// Duration in milliseconds.
    #[must_use]
    pub fn duration_ms(&self) -> Option<u64> {
        self.end_time_ms
            .map(|e| e.saturating_sub(self.start_time_ms))
    }

    /// Returns `true` if the process is still running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.end_time_ms.is_none()
    }

    /// Add an API call to the history.
    pub fn record_api(&mut self, api: impl Into<String>) {
        self.api_calls.push(api.into());
    }

    /// Add a tag.
    pub fn tag(&mut self, t: impl Into<String>) {
        self.tags.push(t.into());
    }
}

/// Windows integrity levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    High,
    System,
}

impl fmt::Display for IntegrityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untrusted => write!(f, "untrusted"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::System => write!(f, "system"),
        }
    }
}

// ─── ProcessTree ──────────────────────────────────────────────────────────────

/// A tree of process nodes keyed by PID.
#[derive(Debug, Clone, Default)]
pub struct ProcessTree {
    nodes: HashMap<u32, ProcessNode>,
}

impl ProcessTree {
    /// Create an empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a node.
    pub fn insert(&mut self, node: ProcessNode) {
        self.nodes.insert(node.pid, node);
    }

    /// Get a node by PID.
    #[must_use]
    pub fn get(&self, pid: u32) -> Option<&ProcessNode> {
        self.nodes.get(&pid)
    }

    /// Get a mutable reference to a node.
    #[must_use]
    pub fn get_mut(&mut self, pid: u32) -> Option<&mut ProcessNode> {
        self.nodes.get_mut(&pid)
    }

    /// Return all direct children of a PID.
    #[must_use]
    pub fn children(&self, pid: u32) -> Vec<&ProcessNode> {
        self.nodes.values().filter(|n| n.ppid == pid).collect()
    }

    /// Return the parent of a PID, if present.
    #[must_use]
    pub fn parent(&self, pid: u32) -> Option<&ProcessNode> {
        let parent_pid = self.nodes.get(&pid)?.ppid;
        self.nodes.get(&parent_pid)
    }

    /// Return all ancestors of a PID (root first).
    #[must_use]
    pub fn ancestors(&self, pid: u32) -> Vec<&ProcessNode> {
        let mut chain = Vec::new();
        let mut current_pid = pid;
        let mut visited = HashSet::new();
        loop {
            let Some(node) = self.nodes.get(&current_pid) else {
                break;
            };
            if !visited.insert(current_pid) {
                break;
            } // cycle guard
            if node.ppid == 0 || node.ppid == current_pid {
                break;
            }
            current_pid = node.ppid;
            if let Some(parent) = self.nodes.get(&current_pid) {
                chain.push(parent);
            }
        }
        chain.reverse();
        chain
    }

    /// Breadth-first traversal starting from a PID.
    #[must_use]
    pub fn bfs(&self, root_pid: u32) -> Vec<&ProcessNode> {
        let mut result = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(root_pid);
        let mut visited = HashSet::new();
        while let Some(pid) = queue.pop_front() {
            if !visited.insert(pid) {
                continue;
            }
            if let Some(node) = self.nodes.get(&pid) {
                result.push(node);
                for child in self.children(pid) {
                    queue.push_back(child.pid);
                }
            }
        }
        result
    }

    /// Return root processes (PPID not found in tree or PPID == 0).
    #[must_use]
    pub fn roots(&self) -> Vec<&ProcessNode> {
        self.nodes
            .values()
            .filter(|n| n.ppid == 0 || !self.nodes.contains_key(&n.ppid))
            .collect()
    }

    /// Count total nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns `true` if the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Return all nodes.
    #[must_use]
    pub fn all_nodes(&self) -> Vec<&ProcessNode> {
        self.nodes.values().collect()
    }

    /// Build a mock tree for testing.
    #[must_use]
    pub fn mock() -> Self {
        let mut tree = Self::new();
        tree.insert(ProcessNode::new(4, 0, "System", ""));
        tree.insert(ProcessNode::new(
            512,
            4,
            "smss.exe",
            "C:\\Windows\\System32\\smss.exe",
        ));
        tree.insert(ProcessNode::new(
            624,
            512,
            "csrss.exe",
            "C:\\Windows\\System32\\csrss.exe",
        ));
        tree.insert(ProcessNode::new(
            700,
            512,
            "wininit.exe",
            "C:\\Windows\\System32\\wininit.exe",
        ));
        tree.insert(ProcessNode::new(
            788,
            700,
            "services.exe",
            "C:\\Windows\\System32\\services.exe",
        ));
        let mut svchost = ProcessNode::new(
            1024,
            788,
            "svchost.exe",
            "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        );
        svchost.record_api("CreateProcess");
        tree.insert(svchost);
        let mut mal = ProcessNode::new(2000, 1024, "malware.exe", "malware.exe -s");
        mal.is_injected = true;
        mal.record_api("VirtualAllocEx");
        mal.record_api("WriteProcessMemory");
        mal.record_api("CreateRemoteThread");
        tree.insert(mal);
        let mut hollow = ProcessNode::new(3000, 2000, "notepad.exe", "notepad.exe");
        hollow.is_hollow = true;
        tree.insert(hollow);
        tree
    }
}

// ─── ProcessLineage ───────────────────────────────────────────────────────────

/// A chain of parent–child process relationships.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLineage {
    /// Ordered chain from root to leaf.
    pub chain: Vec<(u32, String)>,
}

impl ProcessLineage {
    /// Build lineage from a tree for a given PID.
    #[must_use]
    pub fn build(tree: &ProcessTree, leaf_pid: u32) -> Self {
        let mut chain = Vec::new();
        let mut current_pid = leaf_pid;
        let mut visited = HashSet::new();
        loop {
            let Some(node) = tree.get(current_pid) else {
                break;
            };
            if !visited.insert(current_pid) {
                break;
            }
            chain.push((node.pid, node.name.clone()));
            if node.ppid == 0 || node.ppid == current_pid {
                break;
            }
            current_pid = node.ppid;
        }
        chain.reverse();
        Self { chain }
    }

    /// Returns the depth of the lineage chain.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.chain.len()
    }

    /// Check whether a given process name appears anywhere in the lineage.
    #[must_use]
    pub fn contains_name(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.chain
            .iter()
            .any(|(_, n)| n.to_ascii_lowercase().contains(&lower))
    }

    /// Returns the root entry, if any.
    #[must_use]
    pub fn root(&self) -> Option<&(u32, String)> {
        self.chain.first()
    }

    /// Returns the leaf entry.
    #[must_use]
    pub fn leaf(&self) -> Option<&(u32, String)> {
        self.chain.last()
    }

    /// Pretty-print the lineage.
    #[must_use]
    pub fn display_chain(&self) -> String {
        self.chain
            .iter()
            .map(|(pid, name)| format!("{name}({pid})"))
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}

// ─── SuspiciousProcess ────────────────────────────────────────────────────────

/// A suspicious process identified by the analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousProcess {
    pub pid: u32,
    pub name: String,
    pub reason: SuspicionReason,
    pub score: u8,
    pub lineage: String,
}

/// The reason a process was flagged as suspicious.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuspicionReason {
    /// Process hollowing detected.
    Hollow,
    /// Injection APIs observed.
    InjectionApis,
    /// Unexpected parent process.
    UnexpectedParent,
    /// `LOLBin` executing unusual child.
    LolBinChild,
    /// Very short-lived process (< 100 ms).
    ShortLived,
    /// Running from temp / unusual directory.
    SuspiciousPath,
    /// High number of API calls in short window.
    ApiStorm,
    /// Anti-debugging APIs called.
    AntiDebug,
    /// Named pipe communication.
    NamedPipe,
    Custom(String),
}

impl fmt::Display for SuspicionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hollow => write!(f, "hollow"),
            Self::InjectionApis => write!(f, "injection_apis"),
            Self::UnexpectedParent => write!(f, "unexpected_parent"),
            Self::LolBinChild => write!(f, "lolbin_child"),
            Self::ShortLived => write!(f, "short_lived"),
            Self::SuspiciousPath => write!(f, "suspicious_path"),
            Self::ApiStorm => write!(f, "api_storm"),
            Self::AntiDebug => write!(f, "anti_debug"),
            Self::NamedPipe => write!(f, "named_pipe"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

// ─── HollowingDetector ────────────────────────────────────────────────────────

/// Detects process hollowing from API sequences.
#[derive(Debug, Clone, Default)]
pub struct HollowingDetector;

/// Evidence of a process hollowing attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HollowingEvidence {
    pub target_pid: u32,
    pub confidence: u8,
    pub api_sequence: Vec<String>,
}

impl HollowingDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect hollowing from an ordered list of API calls for a process.
    #[must_use]
    pub fn detect(&self, pid: u32, api_calls: &[&str]) -> Option<HollowingEvidence> {
        // Classic hollowing: CreateProcess(SUSPENDED) + NtUnmapViewOfSection + VirtualAllocEx + WriteProcessMemory + SetThreadContext + ResumeThread
        let has_create_suspended = api_calls
            .iter()
            .any(|&a| a.contains("CreateProcess") || a.contains("NtCreateProcess"));
        let has_unmap = api_calls
            .iter()
            .any(|&a| a.contains("NtUnmapViewOfSection") || a.contains("ZwUnmapViewOfSection"));
        let has_alloc = api_calls
            .iter()
            .any(|&a| a.contains("VirtualAllocEx") || a.contains("NtAllocateVirtualMemory"));
        let has_write = api_calls
            .iter()
            .any(|&a| a.contains("WriteProcessMemory") || a.contains("NtWriteVirtualMemory"));
        let has_resume = api_calls
            .iter()
            .any(|&a| a.contains("ResumeThread") || a.contains("NtResumeThread"));
        let has_context = api_calls
            .iter()
            .any(|&a| a.contains("SetThreadContext") || a.contains("NtSetContextThread"));

        let mut confidence = 0u8;
        let mut detected_apis = Vec::new();

        if has_create_suspended {
            confidence += 20;
            detected_apis.push("CreateProcess(SUSPENDED)".to_string());
        }
        if has_unmap {
            confidence += 25;
            detected_apis.push("NtUnmapViewOfSection".to_string());
        }
        if has_alloc {
            confidence += 15;
            detected_apis.push("VirtualAllocEx".to_string());
        }
        if has_write {
            confidence += 15;
            detected_apis.push("WriteProcessMemory".to_string());
        }
        if has_context {
            confidence += 15;
            detected_apis.push("SetThreadContext".to_string());
        }
        if has_resume {
            confidence += 10;
            detected_apis.push("ResumeThread".to_string());
        }

        if confidence >= 40 {
            Some(HollowingEvidence {
                target_pid: pid,
                confidence: confidence.min(100),
                api_sequence: detected_apis,
            })
        } else {
            None
        }
    }

    /// Scan all processes in a tree for hollowing evidence.
    #[must_use]
    pub fn scan_tree(&self, tree: &ProcessTree) -> Vec<HollowingEvidence> {
        let mut results = Vec::new();
        for node in tree.all_nodes() {
            if node.is_hollow {
                results.push(HollowingEvidence {
                    target_pid: node.pid,
                    confidence: 95,
                    api_sequence: vec!["hollow_flag_set".to_string()],
                });
                continue;
            }
            let refs: Vec<&str> = node
                .api_calls
                .iter()
                .map(std::string::String::as_str)
                .collect();
            if let Some(ev) = self.detect(node.pid, &refs) {
                results.push(ev);
            }
        }
        results
    }
}

// ─── ProcessInjectionDetector ─────────────────────────────────────────────────

/// Detects classic and advanced process injection patterns.
#[derive(Debug, Clone, Default)]
pub struct ProcessInjectionDetector;

/// Evidence of process injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionEvidence {
    pub injector_pid: u32,
    pub target_pid: Option<u32>,
    pub technique: InjectionTechnique,
    pub confidence: u8,
    pub api_evidence: Vec<String>,
}

/// The injection technique identified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InjectionTechnique {
    /// Classic remote thread injection.
    RemoteThread,
    /// APC queue injection.
    ApcQueue,
    /// Section mapping / shared memory.
    SectionMapping,
    /// Reflective DLL injection.
    ReflectiveDll,
    /// Thread hijacking (`SetThreadContext`).
    ThreadHijack,
    /// Process doppelgänging.
    Doppelganging,
    /// Transacted hollowing.
    TransactedHollowing,
    /// Unknown / generic injection.
    Generic,
}

impl fmt::Display for InjectionTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemoteThread => write!(f, "remote_thread"),
            Self::ApcQueue => write!(f, "apc_queue"),
            Self::SectionMapping => write!(f, "section_mapping"),
            Self::ReflectiveDll => write!(f, "reflective_dll"),
            Self::ThreadHijack => write!(f, "thread_hijack"),
            Self::Doppelganging => write!(f, "doppelganging"),
            Self::TransactedHollowing => write!(f, "transacted_hollowing"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

impl ProcessInjectionDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect injection patterns in a process's API call sequence.
    #[must_use]
    pub fn detect(&self, pid: u32, api_calls: &[&str]) -> Vec<InjectionEvidence> {
        let mut results = Vec::new();

        // Classic remote-thread injection
        let alloc = api_calls.iter().any(|a| a.contains("VirtualAllocEx"));
        let write = api_calls.iter().any(|a| a.contains("WriteProcessMemory"));
        let remote = api_calls.iter().any(|a| a.contains("CreateRemoteThread"));
        if alloc && write && remote {
            results.push(InjectionEvidence {
                injector_pid: pid,
                target_pid: None,
                technique: InjectionTechnique::RemoteThread,
                confidence: 95,
                api_evidence: vec![
                    "VirtualAllocEx".into(),
                    "WriteProcessMemory".into(),
                    "CreateRemoteThread".into(),
                ],
            });
        }

        // APC injection
        let queue_apc = api_calls
            .iter()
            .any(|a| a.contains("QueueUserAPC") || a.contains("NtQueueApcThread"));
        if alloc && write && queue_apc {
            results.push(InjectionEvidence {
                injector_pid: pid,
                target_pid: None,
                technique: InjectionTechnique::ApcQueue,
                confidence: 88,
                api_evidence: vec!["QueueUserAPC".into()],
            });
        }

        // Section mapping
        let create_section = api_calls.iter().any(|a| a.contains("NtCreateSection"));
        let map_view = api_calls.iter().any(|a| a.contains("NtMapViewOfSection"));
        if create_section && map_view {
            results.push(InjectionEvidence {
                injector_pid: pid,
                target_pid: None,
                technique: InjectionTechnique::SectionMapping,
                confidence: 82,
                api_evidence: vec!["NtCreateSection".into(), "NtMapViewOfSection".into()],
            });
        }

        // Thread hijack
        let suspend = api_calls
            .iter()
            .any(|a| a.contains("SuspendThread") || a.contains("NtSuspendThread"));
        let set_ctx = api_calls
            .iter()
            .any(|a| a.contains("SetThreadContext") || a.contains("NtSetContextThread"));
        let resume = api_calls
            .iter()
            .any(|a| a.contains("ResumeThread") || a.contains("NtResumeThread"));
        if suspend && set_ctx && resume {
            results.push(InjectionEvidence {
                injector_pid: pid,
                target_pid: None,
                technique: InjectionTechnique::ThreadHijack,
                confidence: 85,
                api_evidence: vec![
                    "SuspendThread".into(),
                    "SetThreadContext".into(),
                    "ResumeThread".into(),
                ],
            });
        }

        results
    }

    /// Scan entire process tree for injection evidence.
    #[must_use]
    pub fn scan_tree(&self, tree: &ProcessTree) -> Vec<InjectionEvidence> {
        let mut results = Vec::new();
        for node in tree.all_nodes() {
            if node.is_injected {
                results.push(InjectionEvidence {
                    injector_pid: node.ppid,
                    target_pid: Some(node.pid),
                    technique: InjectionTechnique::Generic,
                    confidence: 95,
                    api_evidence: vec!["injected_flag".into()],
                });
            }
            let refs: Vec<&str> = node.api_calls.iter().map(String::as_str).collect();
            results.extend(self.detect(node.pid, &refs));
        }
        results
    }
}

// ─── ProcessTreeAnalyzer ──────────────────────────────────────────────────────

/// Top-level analyzer combining hollowing, injection, and lineage analysis.
#[derive(Debug, Default)]
pub struct ProcessTreeAnalyzer {
    pub hollowing: HollowingDetector,
    pub injection: ProcessInjectionDetector,
}

/// Full analysis result for a process tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeAnalysisResult {
    pub total_processes: usize,
    pub suspicious: Vec<SuspiciousProcess>,
    pub hollowing_evidence: Vec<HollowingEvidence>,
    pub injection_evidence: Vec<InjectionEvidence>,
    pub lolbin_count: usize,
    pub injection_count: usize,
    pub hollow_count: usize,
    pub max_depth: usize,
}

impl ProcessTreeAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze a process tree and return the full result.
    #[must_use]
    pub fn analyze(&self, tree: &ProcessTree) -> ProcessTreeAnalysisResult {
        let hollowing_evidence = self.hollowing.scan_tree(tree);
        let injection_evidence = self.injection.scan_tree(tree);

        let mut suspicious = Vec::new();
        let mut lolbin_count = 0usize;

        for node in tree.all_nodes() {
            if node.is_hollow {
                let lineage = ProcessLineage::build(tree, node.pid);
                suspicious.push(SuspiciousProcess {
                    pid: node.pid,
                    name: node.name.clone(),
                    reason: SuspicionReason::Hollow,
                    score: 90,
                    lineage: lineage.display_chain(),
                });
            }
            if node.is_injected {
                let lineage = ProcessLineage::build(tree, node.pid);
                suspicious.push(SuspiciousProcess {
                    pid: node.pid,
                    name: node.name.clone(),
                    reason: SuspicionReason::InjectionApis,
                    score: 85,
                    lineage: lineage.display_chain(),
                });
            }
            if node.is_lolbin() {
                lolbin_count += 1;
            }
            let image_lower = node.image_path.to_ascii_lowercase();
            if image_lower.contains("\\temp\\")
                || image_lower.contains("\\tmp\\")
                || image_lower.contains("\\appdata\\roaming\\")
            {
                let lineage = ProcessLineage::build(tree, node.pid);
                suspicious.push(SuspiciousProcess {
                    pid: node.pid,
                    name: node.name.clone(),
                    reason: SuspicionReason::SuspiciousPath,
                    score: 60,
                    lineage: lineage.display_chain(),
                });
            }
        }

        // Compute max tree depth.
        let max_depth = tree
            .all_nodes()
            .iter()
            .map(|n| ProcessLineage::build(tree, n.pid).depth())
            .max()
            .unwrap_or(0);

        let injection_count = injection_evidence.len();
        let hollow_count = hollowing_evidence.len();

        ProcessTreeAnalysisResult {
            total_processes: tree.len(),
            suspicious,
            hollowing_evidence,
            injection_evidence,
            lolbin_count,
            injection_count,
            hollow_count,
            max_depth,
        }
    }

    /// Identify the most suspicious processes, sorted by score descending.
    #[must_use]
    pub fn top_suspicious(result: &ProcessTreeAnalysisResult, n: usize) -> Vec<&SuspiciousProcess> {
        let mut sorted: Vec<&SuspiciousProcess> = result.suspicious.iter().collect();
        sorted.sort_by(|a, b| b.score.cmp(&a.score));
        sorted.truncate(n);
        sorted
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ProcessNode
    #[test]
    fn test_node_new() {
        let n = ProcessNode::new(100, 4, "svchost.exe", "svchost.exe -k");
        assert_eq!(n.pid, 100);
        assert_eq!(n.ppid, 4);
    }
    #[test]
    fn test_node_is_lolbin_powershell() {
        let n = ProcessNode::new(100, 4, "powershell.exe", "powershell.exe -enc abc");
        assert!(n.is_lolbin());
    }
    #[test]
    fn test_node_is_not_lolbin() {
        let n = ProcessNode::new(100, 4, "notepad.exe", "notepad.exe");
        assert!(!n.is_lolbin());
    }
    #[test]
    fn test_node_spawned_from_shell() {
        let n = ProcessNode::new(100, 4, "cmd.exe", "cmd.exe /c whoami");
        assert!(n.spawned_from_shell());
    }
    #[test]
    fn test_node_duration() {
        let mut n = ProcessNode::new(100, 4, "x", "");
        n.start_time_ms = 1000;
        n.end_time_ms = Some(2500);
        assert_eq!(n.duration_ms(), Some(1500));
    }
    #[test]
    fn test_node_is_running() {
        let n = ProcessNode::new(100, 4, "x", "");
        assert!(n.is_running());
    }
    #[test]
    fn test_node_record_api() {
        let mut n = ProcessNode::new(100, 4, "x", "");
        n.record_api("CreateFile");
        assert_eq!(n.api_calls.len(), 1);
    }

    // ProcessTree
    #[test]
    fn test_tree_insert_and_get() {
        let mut t = ProcessTree::new();
        t.insert(ProcessNode::new(1, 0, "init", ""));
        assert!(t.get(1).is_some());
    }
    #[test]
    fn test_tree_children() {
        let mut t = ProcessTree::new();
        t.insert(ProcessNode::new(1, 0, "init", ""));
        t.insert(ProcessNode::new(2, 1, "sh", ""));
        t.insert(ProcessNode::new(3, 1, "sh", ""));
        assert_eq!(t.children(1).len(), 2);
    }
    #[test]
    fn test_tree_parent() {
        let mut t = ProcessTree::new();
        t.insert(ProcessNode::new(1, 0, "init", ""));
        t.insert(ProcessNode::new(2, 1, "sh", ""));
        assert!(t.parent(2).is_some());
        assert_eq!(t.parent(2).unwrap().pid, 1);
    }
    #[test]
    fn test_tree_roots() {
        let mut t = ProcessTree::new();
        t.insert(ProcessNode::new(4, 0, "System", ""));
        t.insert(ProcessNode::new(100, 4, "child", ""));
        assert_eq!(t.roots().len(), 1);
    }
    #[test]
    fn test_tree_bfs_order() {
        let t = ProcessTree::mock();
        let bfs = t.bfs(4);
        assert!(!bfs.is_empty());
        assert_eq!(bfs[0].pid, 4);
    }
    #[test]
    fn test_tree_len() {
        assert!(!ProcessTree::mock().is_empty());
    }
    #[test]
    fn test_tree_is_empty() {
        assert!(ProcessTree::new().is_empty());
    }
    #[test]
    fn test_tree_ancestors() {
        let t = ProcessTree::mock();
        let anc = t.ancestors(3000);
        assert!(!anc.is_empty());
    }
    #[test]
    fn test_tree_all_nodes_count() {
        let t = ProcessTree::mock();
        assert_eq!(t.all_nodes().len(), t.len());
    }

    // ProcessLineage
    #[test]
    fn test_lineage_build() {
        let t = ProcessTree::mock();
        let lineage = ProcessLineage::build(&t, 3000);
        assert!(!lineage.chain.is_empty());
    }
    #[test]
    fn test_lineage_depth() {
        let t = ProcessTree::mock();
        let lineage = ProcessLineage::build(&t, 3000);
        assert!(lineage.depth() >= 2);
    }
    #[test]
    fn test_lineage_contains_name() {
        let t = ProcessTree::mock();
        let lineage = ProcessLineage::build(&t, 3000);
        assert!(lineage.contains_name("notepad"));
    }
    #[test]
    fn test_lineage_display_chain() {
        let t = ProcessTree::mock();
        let lineage = ProcessLineage::build(&t, 3000);
        let chain = lineage.display_chain();
        assert!(chain.contains("3000"));
    }

    // HollowingDetector
    #[test]
    fn test_hollowing_full_sequence() {
        let d = HollowingDetector::new();
        let apis = [
            "CreateProcess",
            "NtUnmapViewOfSection",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "SetThreadContext",
            "ResumeThread",
        ];
        let ev = d.detect(100, &apis);
        assert!(ev.is_some());
        assert!(ev.unwrap().confidence >= 80);
    }
    #[test]
    fn test_hollowing_partial_sequence() {
        let d = HollowingDetector::new();
        let ev = d.detect(100, &["CreateProcess"]);
        assert!(ev.is_none());
    }
    #[test]
    fn test_hollowing_scan_tree_finds_hollow() {
        let t = ProcessTree::mock();
        let d = HollowingDetector::new();
        let ev = d.scan_tree(&t);
        assert!(!ev.is_empty());
    }

    // ProcessInjectionDetector
    #[test]
    fn test_injection_remote_thread() {
        let d = ProcessInjectionDetector::new();
        let apis = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"];
        let ev = d.detect(100, &apis);
        assert!(!ev.is_empty());
        assert_eq!(ev[0].technique, InjectionTechnique::RemoteThread);
    }
    #[test]
    fn test_injection_apc() {
        let d = ProcessInjectionDetector::new();
        let apis = ["VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC"];
        let ev = d.detect(100, &apis);
        assert!(
            ev.iter()
                .any(|e| e.technique == InjectionTechnique::ApcQueue)
        );
    }
    #[test]
    fn test_injection_section_mapping() {
        let d = ProcessInjectionDetector::new();
        let apis = ["NtCreateSection", "NtMapViewOfSection"];
        let ev = d.detect(100, &apis);
        assert!(
            ev.iter()
                .any(|e| e.technique == InjectionTechnique::SectionMapping)
        );
    }
    #[test]
    fn test_injection_thread_hijack() {
        let d = ProcessInjectionDetector::new();
        let apis = ["SuspendThread", "SetThreadContext", "ResumeThread"];
        let ev = d.detect(100, &apis);
        assert!(
            ev.iter()
                .any(|e| e.technique == InjectionTechnique::ThreadHijack)
        );
    }
    #[test]
    fn test_injection_no_match() {
        let d = ProcessInjectionDetector::new();
        let ev = d.detect(100, &["ReadFile"]);
        assert!(ev.is_empty());
    }
    #[test]
    fn test_injection_scan_tree() {
        let t = ProcessTree::mock();
        let d = ProcessInjectionDetector::new();
        let ev = d.scan_tree(&t);
        assert!(!ev.is_empty());
    }

    // ProcessTreeAnalyzer
    #[test]
    fn test_analyzer_new() {
        let _ = ProcessTreeAnalyzer::new();
    }
    #[test]
    fn test_analyzer_analyze_mock_tree() {
        let t = ProcessTree::mock();
        let a = ProcessTreeAnalyzer::new();
        let r = a.analyze(&t);
        assert!(r.total_processes > 0);
    }
    #[test]
    fn test_analyzer_finds_suspicious() {
        let t = ProcessTree::mock();
        let a = ProcessTreeAnalyzer::new();
        let r = a.analyze(&t);
        assert!(!r.suspicious.is_empty());
    }
    #[test]
    fn test_analyzer_max_depth_positive() {
        let t = ProcessTree::mock();
        let a = ProcessTreeAnalyzer::new();
        let r = a.analyze(&t);
        assert!(r.max_depth >= 1);
    }
    #[test]
    fn test_analyzer_top_suspicious() {
        let t = ProcessTree::mock();
        let a = ProcessTreeAnalyzer::new();
        let r = a.analyze(&t);
        let top = ProcessTreeAnalyzer::top_suspicious(&r, 3);
        assert!(top.len() <= 3);
    }
    #[test]
    fn test_suspicion_reason_display() {
        assert_eq!(SuspicionReason::Hollow.to_string(), "hollow");
        assert_eq!(SuspicionReason::InjectionApis.to_string(), "injection_apis");
    }
    #[test]
    fn test_injection_technique_display() {
        assert_eq!(
            InjectionTechnique::RemoteThread.to_string(),
            "remote_thread"
        );
    }
    #[test]
    fn test_integrity_level_display() {
        assert_eq!(IntegrityLevel::High.to_string(), "high");
        assert_eq!(IntegrityLevel::System.to_string(), "system");
    }
}
