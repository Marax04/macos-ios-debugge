//! `VirusTotal` behavior report parsing and structured representation.
//!
//! Provides strongly-typed structs for sandbox behavior reports including
//! process trees, file operations, registry operations, network calls,
//! and a high-level `BehaviorSummary` view.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// NetworkProtocol
// ---------------------------------------------------------------------------

/// Transport / application protocol of a network call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Http,
    Https,
    Dns,
    Ftp,
    Smtp,
    Unknown,
}

impl std::fmt::Display for NetworkProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Dns => "DNS",
            Self::Ftp => "FTP",
            Self::Smtp => "SMTP",
            Self::Unknown => "UNKNOWN",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// NetworkCall
// ---------------------------------------------------------------------------

/// A single network call observed during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCall {
    /// Destination URL or raw address string.
    pub url: Option<String>,
    /// Destination IP address.
    pub ip: Option<String>,
    /// Destination port.
    pub port: Option<u16>,
    /// Network protocol.
    pub protocol: NetworkProtocol,
    /// HTTP method (GET, POST, …) if applicable.
    pub http_method: Option<String>,
    /// Response status code if available.
    pub response_status: Option<u16>,
    /// Number of bytes sent.
    pub bytes_sent: Option<u64>,
    /// Number of bytes received.
    pub bytes_received: Option<u64>,
    /// Process ID that made the call.
    pub pid: Option<u32>,
    /// Process name that made the call.
    pub process_name: Option<String>,
}

impl NetworkCall {
    /// Create a minimal HTTP call.
    #[must_use]
    pub fn http(url: impl Into<String>) -> Self {
        Self {
            url: Some(url.into()),
            ip: None,
            port: Some(80),
            protocol: NetworkProtocol::Http,
            http_method: Some("GET".to_string()),
            response_status: None,
            bytes_sent: None,
            bytes_received: None,
            pid: None,
            process_name: None,
        }
    }

    /// Create a minimal TCP connection.
    #[must_use]
    pub fn tcp(ip: impl Into<String>, port: u16) -> Self {
        Self {
            url: None,
            ip: Some(ip.into()),
            port: Some(port),
            protocol: NetworkProtocol::Tcp,
            http_method: None,
            response_status: None,
            bytes_sent: None,
            bytes_received: None,
            pid: None,
            process_name: None,
        }
    }

    /// Return `true` if this call targets a suspicious port (C2-common).
    #[must_use]
    pub fn is_suspicious_port(&self) -> bool {
        matches!(self.port, Some(p) if [4444, 1337, 8888, 9999, 31337].contains(&p))
    }
}

// ---------------------------------------------------------------------------
// RegistryOp
// ---------------------------------------------------------------------------

/// The kind of registry operation performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryOpKind {
    Open,
    Read,
    Write,
    Delete,
    Create,
    Enumerate,
}

impl std::fmt::Display for RegistryOpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Open => "open",
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Create => "create",
            Self::Enumerate => "enumerate",
        };
        write!(f, "{s}")
    }
}

/// A registry operation observed during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOp {
    /// Registry key path.
    pub key: String,
    /// Registry value name (optional).
    pub value_name: Option<String>,
    /// Data written (optional).
    pub data: Option<String>,
    /// Operation kind.
    pub kind: RegistryOpKind,
    /// Process ID performing the operation.
    pub pid: Option<u32>,
}

impl RegistryOp {
    /// Create a write operation.
    #[must_use]
    pub fn write(
        key: impl Into<String>,
        value_name: impl Into<String>,
        data: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            value_name: Some(value_name.into()),
            data: Some(data.into()),
            kind: RegistryOpKind::Write,
            pid: None,
        }
    }

    /// Return `true` if this is a persistence-related registry key.
    #[must_use]
    pub fn is_persistence_key(&self) -> bool {
        let k = self.key.to_lowercase();
        k.contains("currentversion\\run")
            || k.contains("currentversion\\runonce")
            || k.contains("winlogon")
            || k.contains("policies\\explorer\\run")
    }
}

// ---------------------------------------------------------------------------
// FileOpKind
// ---------------------------------------------------------------------------

/// The kind of file operation performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOpKind {
    Create,
    Write,
    Read,
    Delete,
    Move,
    Copy,
    SetAttributes,
}

// ---------------------------------------------------------------------------
// FileOp
// ---------------------------------------------------------------------------

/// A file system operation observed during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOp {
    /// File path.
    pub path: String,
    /// Operation kind.
    pub kind: FileOpKind,
    /// Destination path for move/copy operations.
    pub dest_path: Option<String>,
    /// File size in bytes (if known).
    pub size: Option<u64>,
    /// Process ID performing the operation.
    pub pid: Option<u32>,
}

impl FileOp {
    /// Create a file-write operation.
    #[must_use]
    pub fn write(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: FileOpKind::Write,
            dest_path: None,
            size: None,
            pid: None,
        }
    }

    /// Return `true` if this is a suspicious temp-file operation.
    #[must_use]
    pub fn is_temp_file(&self) -> bool {
        let p = self.path.to_lowercase();
        p.contains("\\temp\\") || p.contains("\\tmp\\") || p.contains("/tmp/")
    }

    /// Return `true` if this is a startup-folder drop.
    #[must_use]
    pub fn is_startup_drop(&self) -> bool {
        let p = self.path.to_lowercase();
        p.contains("startup") || p.contains("start menu")
    }
}

// ---------------------------------------------------------------------------
// ProcessNode (process tree)
// ---------------------------------------------------------------------------

/// A node in the process tree observed during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    /// Process identifier.
    pub pid: u32,
    /// Parent process identifier.
    pub parent_pid: Option<u32>,
    /// Process image name.
    pub name: String,
    /// Full command line.
    pub command_line: Option<String>,
    /// Child processes.
    pub children: Vec<Self>,
    /// Files created by this process.
    pub files_created: Vec<String>,
    /// Registry keys modified by this process.
    pub registry_keys: Vec<String>,
    /// Whether this process injected into another.
    pub performed_injection: bool,
}

impl ProcessNode {
    /// Create a minimal process node.
    #[must_use]
    pub fn new(pid: u32, name: impl Into<String>) -> Self {
        Self {
            pid,
            parent_pid: None,
            name: name.into(),
            command_line: None,
            children: Vec::new(),
            files_created: Vec::new(),
            registry_keys: Vec::new(),
            performed_injection: false,
        }
    }

    /// Count the total number of process nodes in the subtree.
    #[must_use]
    pub fn subtree_size(&self) -> usize {
        1 + self
            .children
            .iter()
            .map(Self::subtree_size)
            .sum::<usize>()
    }

    /// Return `true` if the command line contains a suspicious pattern.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        if let Some(ref cmd) = self.command_line {
            let c = cmd.to_lowercase();
            return c.contains("powershell") && c.contains("-enc")
                || c.contains("cmd.exe") && c.contains("/c")
                || c.contains("wscript")
                || c.contains("mshta")
                || c.contains("regsvr32")
                || c.contains("certutil")
                || self.performed_injection;
        }
        self.performed_injection
    }
}

// ---------------------------------------------------------------------------
// ProcessTree
// ---------------------------------------------------------------------------

/// Process tree observed during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessTree {
    /// Root process nodes (typically the initially executed file).
    pub roots: Vec<ProcessNode>,
}

impl ProcessTree {
    /// Create an empty process tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of processes in the tree.
    #[must_use]
    pub fn total_processes(&self) -> usize {
        self.roots.iter().map(ProcessNode::subtree_size).sum()
    }

    /// Return all processes that performed injection.
    #[must_use]
    pub fn injecting_processes(&self) -> Vec<&ProcessNode> {
        fn collect<'a>(node: &'a ProcessNode, out: &mut Vec<&'a ProcessNode>) {
            if node.performed_injection {
                out.push(node);
            }
            for child in &node.children {
                collect(child, out);
            }
        }
        let mut out = Vec::new();
        for root in &self.roots {
            collect(root, &mut out);
        }
        out
    }

    /// Return all suspicious processes.
    #[must_use]
    pub fn suspicious_processes(&self) -> Vec<&ProcessNode> {
        fn collect<'a>(node: &'a ProcessNode, out: &mut Vec<&'a ProcessNode>) {
            if node.is_suspicious() {
                out.push(node);
            }
            for child in &node.children {
                collect(child, out);
            }
        }
        let mut out = Vec::new();
        for root in &self.roots {
            collect(root, &mut out);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// BehaviorReport
// ---------------------------------------------------------------------------

/// Full behavior report extracted from a VT sandbox analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorReport {
    /// SHA-256 of the analysed sample.
    pub sha256: String,
    /// Sandbox environment name.
    pub sandbox_name: String,
    /// Processes spawned during execution.
    pub processes_created: Vec<String>,
    /// Files written during execution.
    pub files_written: Vec<String>,
    /// Files deleted during execution.
    pub files_deleted: Vec<String>,
    /// Registry keys modified.
    pub registry_modified: Vec<String>,
    /// Network calls made.
    pub network_calls: Vec<NetworkCall>,
    /// Mutex names created.
    pub mutexes_created: Vec<String>,
    /// Structured process tree.
    pub process_tree: ProcessTree,
    /// Structured registry operations.
    pub registry_ops: Vec<RegistryOp>,
    /// Structured file operations.
    pub file_ops: Vec<FileOp>,
    /// MITRE ATT&CK techniques inferred from behavior.
    pub mitre_techniques: Vec<String>,
    /// Tags applied by the sandbox.
    pub tags: Vec<String>,
    /// Analysis timestamp (Unix seconds).
    pub analysis_timestamp: u64,
    /// Raw metadata from VT (catch-all).
    pub metadata: HashMap<String, serde_json::Value>,
}

impl BehaviorReport {
    /// Create an empty report.
    #[must_use]
    pub fn new(sha256: impl Into<String>, sandbox_name: impl Into<String>) -> Self {
        Self {
            sha256: sha256.into(),
            sandbox_name: sandbox_name.into(),
            processes_created: Vec::new(),
            files_written: Vec::new(),
            files_deleted: Vec::new(),
            registry_modified: Vec::new(),
            network_calls: Vec::new(),
            mutexes_created: Vec::new(),
            process_tree: ProcessTree::new(),
            registry_ops: Vec::new(),
            file_ops: Vec::new(),
            mitre_techniques: Vec::new(),
            tags: Vec::new(),
            analysis_timestamp: 0,
            metadata: HashMap::new(),
        }
    }

    /// Return all contacted IP addresses.
    #[must_use]
    pub fn contacted_ips(&self) -> Vec<&str> {
        self.network_calls
            .iter()
            .filter_map(|c| c.ip.as_deref())
            .collect()
    }

    /// Return all contacted URLs.
    #[must_use]
    pub fn contacted_urls(&self) -> Vec<&str> {
        self.network_calls
            .iter()
            .filter_map(|c| c.url.as_deref())
            .collect()
    }

    /// Return `true` if any persistence-related registry key was modified.
    #[must_use]
    pub fn has_persistence(&self) -> bool {
        self.registry_ops.iter().any(RegistryOp::is_persistence_key)
            || self.registry_modified.iter().any(|k| {
                let kl = k.to_lowercase();
                kl.contains("currentversion\\run")
            })
    }

    /// Return `true` if any process performed injection.
    #[must_use]
    pub fn has_injection(&self) -> bool {
        !self.process_tree.injecting_processes().is_empty()
    }

    /// Return all processes that created startup-folder drops.
    #[must_use]
    pub fn startup_drops(&self) -> Vec<&FileOp> {
        self.file_ops
            .iter()
            .filter(|op| op.is_startup_drop())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// BehaviorSummary
// ---------------------------------------------------------------------------

/// Compact, human-readable summary of a `BehaviorReport`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorSummary {
    /// SHA-256 of the analysed sample.
    pub sha256: String,
    /// Sandbox name.
    pub sandbox_name: String,
    /// Total unique processes spawned.
    pub process_count: usize,
    /// Total files written.
    pub file_write_count: usize,
    /// Total registry modifications.
    pub registry_mod_count: usize,
    /// Total network calls.
    pub network_call_count: usize,
    /// Total mutexes created.
    pub mutex_count: usize,
    /// Whether the sample established persistence.
    pub has_persistence: bool,
    /// Whether the sample performed process injection.
    pub has_injection: bool,
    /// Unique contacted IP addresses.
    pub contacted_ips: Vec<String>,
    /// Unique contacted URLs.
    pub contacted_urls: Vec<String>,
    /// Suspicious network ports contacted.
    pub suspicious_ports: Vec<u16>,
    /// MITRE ATT&CK techniques inferred.
    pub mitre_techniques: Vec<String>,
    /// Overall risk level: 0 (clean) – 10 (critical).
    pub risk_score: u8,
}

impl BehaviorSummary {
    /// Build a summary from a `BehaviorReport`.
    #[must_use]
    pub fn from_report(report: &BehaviorReport) -> Self {
        let contacted_ips: Vec<String> = {
            let mut v: Vec<String> = report
                .contacted_ips()
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        let contacted_urls: Vec<String> = {
            let mut v: Vec<String> = report
                .contacted_urls()
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        let suspicious_ports: Vec<u16> = report
            .network_calls
            .iter()
            .filter(|c| c.is_suspicious_port())
            .filter_map(|c| c.port)
            .collect();

        let mut risk: u32 = 0;
        if report.has_persistence() {
            risk += 2;
        }
        if report.has_injection() {
            risk += 3;
        }
        risk += (contacted_ips.len() as u32).min(2);
        risk += (report.mutexes_created.len() as u32).min(1);
        if !suspicious_ports.is_empty() {
            risk += 2;
        }
        risk += (report.mitre_techniques.len() as u32 / 2).min(2);

        Self {
            sha256: report.sha256.clone(),
            sandbox_name: report.sandbox_name.clone(),
            process_count: report.processes_created.len(),
            file_write_count: report.files_written.len(),
            registry_mod_count: report.registry_modified.len(),
            network_call_count: report.network_calls.len(),
            mutex_count: report.mutexes_created.len(),
            has_persistence: report.has_persistence(),
            has_injection: report.has_injection(),
            contacted_ips,
            contacted_urls,
            suspicious_ports,
            mitre_techniques: report.mitre_techniques.clone(),
            risk_score: risk.min(10) as u8,
        }
    }

    /// Parse a VT JSON behavior response into a `BehaviorSummary`.
    ///
    /// Expects the `data.attributes` sub-object from the VT behavior endpoint.
    /// Returns a default summary on parse failure.
    #[must_use]
    pub fn from_vt_json(sha256: &str, json: &serde_json::Value) -> Self {
        let sandbox = json
            .get("sandbox_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let mut report = BehaviorReport::new(sha256, sandbox);

        // Network calls.
        if let Some(dns) = json.get("dns_lookups").and_then(|v| v.as_array()) {
            for entry in dns {
                if let Some(host) = entry.get("hostname").and_then(|v| v.as_str()) {
                    report.network_calls.push(NetworkCall {
                        url: Some(host.to_string()),
                        ip: None,
                        port: Some(53),
                        protocol: NetworkProtocol::Dns,
                        http_method: None,
                        response_status: None,
                        bytes_sent: None,
                        bytes_received: None,
                        pid: None,
                        process_name: None,
                    });
                }
            }
        }

        if let Some(http) = json.get("http_requests").and_then(|v| v.as_array()) {
            for entry in http {
                let url = entry
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                report.network_calls.push(NetworkCall {
                    url,
                    ip: None,
                    port: Some(80),
                    protocol: NetworkProtocol::Http,
                    http_method: entry
                        .get("method")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    response_status: entry
                        .get("response_status_code")
                        .and_then(serde_json::Value::as_u64)
                        .map(|n| n as u16),
                    bytes_sent: None,
                    bytes_received: None,
                    pid: None,
                    process_name: None,
                });
            }
        }

        // Files written.
        if let Some(files) = json.get("files_written").and_then(|v| v.as_array()) {
            for f in files {
                if let Some(p) = f.as_str() {
                    report.files_written.push(p.to_string());
                }
            }
        }

        // Registry.
        if let Some(keys) = json.get("registry_keys_set").and_then(|v| v.as_array()) {
            for k in keys {
                if let Some(key) = k.as_str() {
                    report.registry_modified.push(key.to_string());
                }
            }
        }

        // Mutexes.
        if let Some(mutexes) = json.get("mutexes_created").and_then(|v| v.as_array()) {
            for m in mutexes {
                if let Some(name) = m.as_str() {
                    report.mutexes_created.push(name.to_string());
                }
            }
        }

        // Processes.
        if let Some(procs) = json.get("processes_created").and_then(|v| v.as_array()) {
            for p in procs {
                if let Some(name) = p.as_str() {
                    report.processes_created.push(name.to_string());
                }
            }
        }

        Self::from_report(&report)
    }

    /// Return `true` if the sample looks malicious (risk ≥ 5).
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.risk_score >= 5
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> BehaviorReport {
        let mut r = BehaviorReport::new("deadbeef", "TestSandbox");
        r.processes_created.push("cmd.exe".to_string());
        r.files_written
            .push(r"C:\Windows\Temp\dropper.exe".to_string());
        r.files_written
            .push(r"C:\Users\Public\payload.exe".to_string());
        r.registry_modified
            .push(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware".to_string());
        r.mutexes_created.push("Global\\EvilMutex".to_string());
        r.network_calls
            .push(NetworkCall::http("http://c2.evil.com/gate.php"));
        r.network_calls.push(NetworkCall::tcp("203.0.113.1", 4444));
        r.registry_ops.push(RegistryOp::write(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "Startup",
            r"C:\Temp\mal.exe",
        ));

        let mut root = ProcessNode::new(1, "malware.exe");
        let mut child = ProcessNode::new(2, "cmd.exe");
        child.performed_injection = true;
        root.children.push(child);
        r.process_tree.roots.push(root);

        r.mitre_techniques
            .push("T1055 Process Injection".to_string());
        r.mitre_techniques
            .push("T1547.001 Registry Run Keys".to_string());
        r
    }

    // ---- NetworkCall ----

    #[test]
    fn test_network_call_http() {
        let c = NetworkCall::http("https://example.com");
        assert_eq!(c.protocol, NetworkProtocol::Http);
        assert_eq!(c.port, Some(80));
    }

    #[test]
    fn test_network_call_tcp() {
        let c = NetworkCall::tcp("1.2.3.4", 443);
        assert_eq!(c.protocol, NetworkProtocol::Tcp);
        assert_eq!(c.port, Some(443));
    }

    #[test]
    fn test_network_call_suspicious_port() {
        let c = NetworkCall::tcp("1.2.3.4", 4444);
        assert!(c.is_suspicious_port());
    }

    #[test]
    fn test_network_call_normal_port_not_suspicious() {
        let c = NetworkCall::tcp("1.2.3.4", 443);
        assert!(!c.is_suspicious_port());
    }

    // ---- RegistryOp ----

    #[test]
    fn test_registry_op_write() {
        let op = RegistryOp::write(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "Test",
            r"C:\Temp\bad.exe",
        );
        assert_eq!(op.kind, RegistryOpKind::Write);
        assert!(op.is_persistence_key());
    }

    #[test]
    fn test_registry_op_not_persistence() {
        let op = RegistryOp::write(r"HKLM\Software\Mozilla", "Version", "100");
        assert!(!op.is_persistence_key());
    }

    // ---- FileOp ----

    #[test]
    fn test_file_op_temp_file() {
        let op = FileOp::write(r"C:\Windows\Temp\evil.exe");
        assert!(op.is_temp_file());
    }

    #[test]
    fn test_file_op_startup_drop() {
        let op = FileOp::write(
            r"C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\mal.exe",
        );
        assert!(op.is_startup_drop());
    }

    #[test]
    fn test_file_op_regular_not_suspicious() {
        let op = FileOp::write(r"C:\Users\User\Documents\note.txt");
        assert!(!op.is_temp_file());
        assert!(!op.is_startup_drop());
    }

    // ---- ProcessNode ----

    #[test]
    fn test_process_node_subtree_size() {
        let mut root = ProcessNode::new(1, "root.exe");
        root.children.push(ProcessNode::new(2, "child.exe"));
        assert_eq!(root.subtree_size(), 2);
    }

    #[test]
    fn test_process_node_suspicious_injection() {
        let mut p = ProcessNode::new(1, "proc.exe");
        p.performed_injection = true;
        assert!(p.is_suspicious());
    }

    #[test]
    fn test_process_node_suspicious_powershell_encoded() {
        let mut p = ProcessNode::new(1, "powershell.exe");
        p.command_line = Some("powershell.exe -enc SGVsbG8=".to_string());
        assert!(p.is_suspicious());
    }

    #[test]
    fn test_process_node_not_suspicious() {
        let p = ProcessNode::new(1, "notepad.exe");
        assert!(!p.is_suspicious());
    }

    // ---- ProcessTree ----

    #[test]
    fn test_process_tree_total_processes() {
        let report = sample_report();
        // root (1) + child (2) = 2
        assert_eq!(report.process_tree.total_processes(), 2);
    }

    #[test]
    fn test_process_tree_injecting_processes() {
        let report = sample_report();
        assert_eq!(report.process_tree.injecting_processes().len(), 1);
    }

    // ---- BehaviorReport ----

    #[test]
    fn test_report_has_persistence() {
        let r = sample_report();
        assert!(r.has_persistence());
    }

    #[test]
    fn test_report_has_injection() {
        let r = sample_report();
        assert!(r.has_injection());
    }

    #[test]
    fn test_report_contacted_ips() {
        let r = sample_report();
        let ips = r.contacted_ips();
        assert!(ips.contains(&"203.0.113.1"));
    }

    #[test]
    fn test_report_contacted_urls() {
        let r = sample_report();
        let urls = r.contacted_urls();
        assert!(urls.contains(&"http://c2.evil.com/gate.php"));
    }

    // ---- BehaviorSummary ----

    #[test]
    fn test_summary_from_report() {
        let r = sample_report();
        let s = BehaviorSummary::from_report(&r);
        assert_eq!(s.sha256, "deadbeef");
        assert!(s.has_persistence);
        assert!(s.has_injection);
        assert!(!s.contacted_ips.is_empty());
    }

    #[test]
    fn test_summary_risk_score_nonzero() {
        let r = sample_report();
        let s = BehaviorSummary::from_report(&r);
        assert!(s.risk_score > 0);
    }

    #[test]
    fn test_summary_suspicious_ports() {
        let r = sample_report();
        let s = BehaviorSummary::from_report(&r);
        assert!(s.suspicious_ports.contains(&4444));
    }

    #[test]
    fn test_summary_is_malicious() {
        let r = sample_report();
        let s = BehaviorSummary::from_report(&r);
        assert!(s.is_malicious());
    }

    // ---- BehaviorSummary::from_vt_json ----

    #[test]
    fn test_from_vt_json_empty() {
        let json = serde_json::json!({});
        let s = BehaviorSummary::from_vt_json("abc", &json);
        assert_eq!(s.sha256, "abc");
        assert_eq!(s.network_call_count, 0);
    }

    #[test]
    fn test_from_vt_json_with_http() {
        let json = serde_json::json!({
            "sandbox_name": "TestSB",
            "http_requests": [
                {"url": "http://evil.com/c2", "method": "POST"}
            ],
            "mutexes_created": ["EvilMutex"],
            "files_written": ["C:\\Temp\\drop.exe"],
            "registry_keys_set": [],
            "processes_created": [],
            "dns_lookups": []
        });
        let s = BehaviorSummary::from_vt_json("sha", &json);
        assert_eq!(s.network_call_count, 1);
        assert_eq!(s.mutex_count, 1);
        assert_eq!(s.file_write_count, 1);
    }

    #[test]
    fn test_from_vt_json_with_dns() {
        let json = serde_json::json!({
            "sandbox_name": "VT",
            "dns_lookups": [{"hostname": "c2.example.com"}],
            "http_requests": [],
            "files_written": [],
            "registry_keys_set": [],
            "processes_created": [],
            "mutexes_created": []
        });
        let s = BehaviorSummary::from_vt_json("sha2", &json);
        assert_eq!(s.network_call_count, 1);
    }

    // ---- NetworkProtocol display ----

    #[test]
    fn test_protocol_display() {
        assert_eq!(NetworkProtocol::Tcp.to_string(), "TCP");
        assert_eq!(NetworkProtocol::Http.to_string(), "HTTP");
        assert_eq!(NetworkProtocol::Dns.to_string(), "DNS");
    }

    // ---- RegistryOpKind display ----

    #[test]
    fn test_registry_op_kind_display() {
        assert_eq!(RegistryOpKind::Write.to_string(), "write");
        assert_eq!(RegistryOpKind::Delete.to_string(), "delete");
    }

    // ---- BehaviorReport serde roundtrip ----

    #[test]
    fn test_behavior_report_serde() {
        let r = sample_report();
        let json = serde_json::to_string(&r).unwrap();
        let r2: BehaviorReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.sha256, "deadbeef");
        assert_eq!(r2.sandbox_name, "TestSandbox");
        assert_eq!(r2.files_written.len(), 2);
    }

    #[test]
    fn test_behavior_summary_serde() {
        let r = sample_report();
        let s = BehaviorSummary::from_report(&r);
        let json = serde_json::to_string(&s).unwrap();
        let s2: BehaviorSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s2.sha256, s.sha256);
        assert_eq!(s2.risk_score, s.risk_score);
    }

    // ---- Report startup_drops ----

    #[test]
    fn test_report_startup_drops() {
        let mut r = BehaviorReport::new("abc", "SB");
        let mut op = FileOp::write(
            r"C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe",
        );
        op.kind = FileOpKind::Create;
        r.file_ops.push(op);
        let drops = r.startup_drops();
        assert_eq!(drops.len(), 1);
    }

    // ---- ProcessTree suspicious_processes ----

    #[test]
    fn test_process_tree_suspicious_processes() {
        let r = sample_report();
        let suspicious = r.process_tree.suspicious_processes();
        // cmd.exe child with injection should be suspicious.
        assert!(!suspicious.is_empty());
    }

    // ---- BehaviorReport contacted_domains (dns_lookups) ----

    #[test]
    fn test_report_dns_lookup_in_network_calls() {
        let mut r = BehaviorReport::new("abc", "SB");
        r.network_calls.push(NetworkCall {
            url: Some("evil.example.com".to_string()),
            ip: None,
            port: Some(53),
            protocol: NetworkProtocol::Dns,
            http_method: None,
            response_status: None,
            bytes_sent: None,
            bytes_received: None,
            pid: None,
            process_name: None,
        });
        let urls = r.contacted_urls();
        assert!(urls.contains(&"evil.example.com"));
    }

    // ---- FileOp serde ----

    #[test]
    fn test_file_op_serde() {
        let op = FileOp {
            path: r"C:\Temp\evil.exe".to_string(),
            kind: FileOpKind::Create,
            dest_path: None,
            size: Some(4096),
            pid: Some(1234),
        };
        let json = serde_json::to_string(&op).unwrap();
        let op2: FileOp = serde_json::from_str(&json).unwrap();
        assert_eq!(op2.pid, Some(1234));
    }

    // ---- RegistryOp serde ----

    #[test]
    fn test_registry_op_serde() {
        let op = RegistryOp::write(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "Test",
            r"C:\evil.exe",
        );
        let json = serde_json::to_string(&op).unwrap();
        let op2: RegistryOp = serde_json::from_str(&json).unwrap();
        assert!(op2.is_persistence_key());
    }

    // ---- ProcessNode serde ----

    #[test]
    fn test_process_node_serde() {
        let mut p = ProcessNode::new(42, "svchost.exe");
        p.command_line = Some("svchost.exe -k NetworkService".to_string());
        let json = serde_json::to_string(&p).unwrap();
        let p2: ProcessNode = serde_json::from_str(&json).unwrap();
        assert_eq!(p2.pid, 42);
        assert!(!p2.is_suspicious());
    }

    // ---- Summary risk cap ----

    #[test]
    fn test_summary_risk_capped_at_10() {
        let mut r = sample_report();
        // Add many network calls to push score up.
        for i in 0..20 {
            r.network_calls
                .push(NetworkCall::tcp(format!("10.{i}.0.1"), 4444));
        }
        let s = BehaviorSummary::from_report(&r);
        assert!(s.risk_score <= 10);
    }

    // ---- FileOpKind all variants compile ----

    #[test]
    fn test_file_op_kind_variants() {
        let ops = [
            FileOpKind::Create,
            FileOpKind::Write,
            FileOpKind::Read,
            FileOpKind::Delete,
            FileOpKind::Move,
            FileOpKind::Copy,
            FileOpKind::SetAttributes,
        ];
        for op in &ops {
            let _ = serde_json::to_string(op).unwrap();
        }
    }

    // ---- NetworkCall bytes fields ----

    #[test]
    fn test_network_call_bytes() {
        let mut c = NetworkCall::http("https://example.com");
        c.bytes_sent = Some(512);
        c.bytes_received = Some(2048);
        assert_eq!(c.bytes_sent, Some(512));
        assert_eq!(c.bytes_received, Some(2048));
    }

    // ---- RegistryOp enumerate kind ----

    #[test]
    fn test_registry_op_enumerate() {
        let op = RegistryOp {
            key: r"HKLM\SOFTWARE\Microsoft".to_string(),
            value_name: None,
            data: None,
            kind: RegistryOpKind::Enumerate,
            pid: Some(1234),
        };
        assert!(!op.is_persistence_key());
        assert_eq!(op.kind, RegistryOpKind::Enumerate);
    }

    // ---- ProcessNode no command line ----

    #[test]
    fn test_process_node_no_cmd_not_suspicious() {
        let p = ProcessNode::new(5, "explorer.exe");
        assert!(!p.is_suspicious());
    }

    // ---- BehaviorReport empty report ----

    #[test]
    fn test_empty_report_no_persistence() {
        let r = BehaviorReport::new("abc123", "EmptySB");
        assert!(!r.has_persistence());
        assert!(!r.has_injection());
    }

    // ---- Summary from empty report ----

    #[test]
    fn test_summary_from_empty_report() {
        let r = BehaviorReport::new("clean", "SB");
        let s = BehaviorSummary::from_report(&r);
        assert_eq!(s.risk_score, 0);
        assert!(!s.is_malicious());
    }

    // ---- Summary contacted_ips deduplication ----

    #[test]
    fn test_summary_contacted_ips_deduped() {
        let mut r = BehaviorReport::new("abc", "SB");
        r.network_calls.push(NetworkCall::tcp("1.2.3.4", 80));
        r.network_calls.push(NetworkCall::tcp("1.2.3.4", 443)); // same IP
        let s = BehaviorSummary::from_report(&r);
        assert_eq!(s.contacted_ips.len(), 1);
    }

    // ---- ProcessTree empty ----

    #[test]
    fn test_process_tree_empty_total() {
        let t = ProcessTree::new();
        assert_eq!(t.total_processes(), 0);
    }
}
