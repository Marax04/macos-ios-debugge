//! `vt_behavior_summary` — summarise `VirusTotal` behaviour sandbox reports.
//!
//! Parses the JSON payload returned by the VT v3 behaviour-report endpoint
//! and collapses it into three focused views:
//!
//! * [`ProcessTree`]   — spawned processes with their PIDs, parents, and command lines.
//! * [`NetworkSummary`] — contacted domains, IPs, and URLs.
//! * [`FileSummary`]   — created, modified, and deleted files.
//!
//! The top-level [`VtBehaviorSummary`] bundles all three and provides
//! convenience accessors and a text render.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── ProcessNode ───────────────────────────────────────────────────────────────

/// A single process entry in the process tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    /// Process identifier.
    pub pid: u32,
    /// Parent process identifier.
    pub ppid: Option<u32>,
    /// Process name.
    pub name: String,
    /// Full command line.
    pub cmdline: String,
    /// Path to the executable.
    pub image_path: String,
    /// SHA-256 of the executable image (if available).
    pub image_hash: Option<String>,
    /// Child PIDs.
    pub children: Vec<u32>,
}

impl ProcessNode {
    /// Return `true` if this is a root process (no parent).
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.ppid.is_none()
    }
}

impl fmt::Display for ProcessNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} ({})", self.pid, self.name, self.cmdline)
    }
}

// ── ProcessTree ───────────────────────────────────────────────────────────────

/// Hierarchical tree of processes spawned during sandbox execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessTree {
    /// All processes indexed by PID.
    pub nodes: HashMap<u32, ProcessNode>,
    /// PIDs of root processes (no parent).
    pub roots: Vec<u32>,
}

impl ProcessTree {
    /// Create an empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a [`ProcessNode`].
    pub fn insert(&mut self, node: ProcessNode) {
        if (node.is_root() || !self.nodes.contains_key(&node.ppid.unwrap_or(0)))
            && node.ppid.is_none() {
                self.roots.push(node.pid);
            }
        self.nodes.insert(node.pid, node);
    }

    /// Number of processes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Return `true` if the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Return the process with the given PID.
    #[must_use]
    pub fn get(&self, pid: u32) -> Option<&ProcessNode> {
        self.nodes.get(&pid)
    }

    /// Return all process names (deduplicated, sorted).
    #[must_use]
    pub fn process_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .nodes
            .values()
            .map(|n| n.name.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        names.sort();
        names
    }

    /// Build from VT JSON behaviour report `processes_tree` array.
    #[must_use] 
    pub fn from_vt_json(processes_array: &[Value]) -> Self {
        let mut tree = Self::new();
        for p in processes_array {
            let pid = p["process_id"].as_u64().unwrap_or(0) as u32;
            let ppid_raw = p["parent_process_id"].as_u64();
            let ppid = ppid_raw.filter(|&v| v != 0).map(|v| v as u32);
            let name = p["name"].as_str().unwrap_or("").to_string();
            let cmdline = p["command_line"].as_str().unwrap_or("").to_string();
            let image_path = p["image_path"].as_str().unwrap_or("").to_string();
            let image_hash = p["sha256"].as_str().map(std::string::ToString::to_string);
            let children = p["children"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|c| c["process_id"].as_u64()).map(|v| v as u32).collect())
                .unwrap_or_default();

            tree.insert(ProcessNode { pid, ppid, name, cmdline, image_path, image_hash, children });
        }
        tree
    }
}

// ── NetworkConnection ─────────────────────────────────────────────────────────

/// A single network connection or DNS query observed during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    /// Destination IP address.
    pub ip: Option<String>,
    /// Destination domain name.
    pub domain: Option<String>,
    /// Destination port.
    pub port: Option<u16>,
    /// Protocol (TCP, UDP, HTTP, etc.).
    pub protocol: String,
    /// URL accessed (for HTTP/HTTPS connections).
    pub url: Option<String>,
    /// Country code of the IP (if resolved).
    pub country: Option<String>,
}

impl fmt::Display for NetworkConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.url, &self.domain, &self.ip) {
            (Some(u), _, _) => write!(f, "{u}"),
            (_, Some(d), Some(ip)) => write!(f, "{}:{} ({})", d, self.port.unwrap_or(0), ip),
            (_, Some(d), None) => write!(f, "{}:{}", d, self.port.unwrap_or(0)),
            (_, None, Some(ip)) => write!(f, "{}:{}", ip, self.port.unwrap_or(0)),
            _ => write!(f, "<unknown>"),
        }
    }
}

// ── NetworkSummary ────────────────────────────────────────────────────────────

/// Aggregated network activity observed during sandbox execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkSummary {
    /// All distinct contacted domains.
    pub domains: Vec<String>,
    /// All distinct contacted IP addresses.
    pub ips: Vec<String>,
    /// All distinct URLs accessed.
    pub urls: Vec<String>,
    /// Detailed connection log.
    pub connections: Vec<NetworkConnection>,
    /// DNS queries made (hostname → resolved addresses).
    pub dns_lookups: HashMap<String, Vec<String>>,
}

impl NetworkSummary {
    /// Create an empty summary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total unique network artefacts (domains + IPs + URLs).
    #[must_use]
    pub const fn total_iocs(&self) -> usize {
        self.domains.len() + self.ips.len() + self.urls.len()
    }

    /// Build from VT JSON behaviour report top-level object.
    #[must_use] 
    pub fn from_vt_json(report: &Value) -> Self {
        let mut summary = Self::new();

        if let Some(arr) = report["domains"].as_array() {
            for v in arr {
                if let Some(s) = v.as_str() {
                    summary.domains.push(s.to_string());
                }
            }
        }
        if let Some(arr) = report["ip_traffic"].as_array() {
            for v in arr {
                if let Some(ip) = v["destination_ip"].as_str() {
                    let port = v["destination_port"].as_u64().map(|p| p as u16);
                    let proto = v["transport_layer_protocol"].as_str().unwrap_or("tcp").to_string();
                    if !summary.ips.contains(&ip.to_string()) {
                        summary.ips.push(ip.to_string());
                    }
                    summary.connections.push(NetworkConnection {
                        ip: Some(ip.to_string()),
                        domain: None,
                        port,
                        protocol: proto,
                        url: None,
                        country: None,
                    });
                }
            }
        }
        if let Some(arr) = report["http_conversations"].as_array() {
            for v in arr {
                if let Some(url) = v["url"].as_str() {
                    summary.urls.push(url.to_string());
                    summary.connections.push(NetworkConnection {
                        ip: v["destination_ip"].as_str().map(std::string::ToString::to_string),
                        domain: v["request_headers"]["Host"].as_str().map(std::string::ToString::to_string),
                        port: v["destination_port"].as_u64().map(|p| p as u16),
                        protocol: "http".to_string(),
                        url: Some(url.to_string()),
                        country: None,
                    });
                }
            }
        }
        if let Some(arr) = report["dns_lookups"].as_array() {
            for v in arr {
                if let Some(hostname) = v["hostname"].as_str() {
                    let resolved: Vec<String> = v["resolved_ips"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|ip| ip.as_str().map(std::string::ToString::to_string)).collect())
                        .unwrap_or_default();
                    summary.dns_lookups.insert(hostname.to_string(), resolved);
                }
            }
        }

        summary.domains.sort();
        summary.domains.dedup();
        summary.ips.sort();
        summary.ips.dedup();
        summary.urls.sort();
        summary.urls.dedup();
        summary
    }
}

// ── FileOperation ─────────────────────────────────────────────────────────────

/// The kind of file operation performed by a sandboxed sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOpKind {
    /// File was created.
    Created,
    /// File was opened for reading or writing.
    Opened,
    /// File was deleted.
    Deleted,
    /// File was modified (written to).
    Modified,
    /// File was renamed.
    Renamed { new_path: String },
}

/// A single file operation observed during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    /// File path affected.
    pub path: String,
    /// Operation kind.
    pub kind: FileOpKind,
    /// SHA-256 of the resulting file (for create/modify).
    pub sha256: Option<String>,
    /// File size in bytes (if available).
    pub size: Option<u64>,
}

// ── FileSummary ───────────────────────────────────────────────────────────────

/// Aggregated file-system activity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileSummary {
    /// Files created.
    pub created: Vec<String>,
    /// Files modified.
    pub modified: Vec<String>,
    /// Files deleted.
    pub deleted: Vec<String>,
    /// Dropped files with SHA-256 hashes.
    pub dropped_hashes: Vec<String>,
    /// All raw operations.
    pub operations: Vec<FileOperation>,
}

impl FileSummary {
    /// Create an empty summary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total file operations.
    #[must_use]
    pub const fn total_operations(&self) -> usize {
        self.operations.len()
    }

    /// Build from VT JSON behaviour report top-level object.
    #[must_use] 
    pub fn from_vt_json(report: &Value) -> Self {
        let mut summary = Self::new();

        let add_paths = |arr: &Value, out: &mut Vec<String>| {
            if let Some(paths) = arr.as_array() {
                for v in paths {
                    if let Some(s) = v.as_str() {
                        out.push(s.to_string());
                    }
                }
            }
        };

        add_paths(&report["files_written"], &mut summary.modified);
        add_paths(&report["files_deleted"], &mut summary.deleted);
        add_paths(&report["files_opened"], &mut summary.created);

        if let Some(dropped) = report["dropped_files"].as_array() {
            for v in dropped {
                if let Some(hash) = v["sha256"].as_str() {
                    summary.dropped_hashes.push(hash.to_string());
                }
                let path = v["path"].as_str().unwrap_or("").to_string();
                let sha256 = v["sha256"].as_str().map(std::string::ToString::to_string);
                let size = v["size"].as_u64();
                summary.operations.push(FileOperation {
                    path,
                    kind: FileOpKind::Created,
                    sha256,
                    size,
                });
            }
        }

        summary.created.sort();
        summary.created.dedup();
        summary.modified.sort();
        summary.modified.dedup();
        summary.deleted.sort();
        summary.deleted.dedup();
        summary.dropped_hashes.sort();
        summary.dropped_hashes.dedup();
        summary
    }
}

// ── VtBehaviorSummary ─────────────────────────────────────────────────────────

/// Top-level summary of a `VirusTotal` sandbox behaviour report.
///
/// # Example
///
/// ```no_run
/// use rustre_ti_vt::vt_behavior_summary::VtBehaviorSummary;
/// use serde_json::json;
///
/// let report = json!({
///     "sandbox_name": "Triage",
///     "domains": ["evil.com"],
///     "ip_traffic": [],
///     "http_conversations": [],
///     "dns_lookups": [],
///     "files_written": ["/tmp/payload.exe"],
///     "files_deleted": [],
///     "files_opened": [],
///     "dropped_files": [],
///     "processes_tree": []
/// });
///
/// let summary = VtBehaviorSummary::from_vt_json(&report);
/// println!("{}", summary.render());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtBehaviorSummary {
    /// SHA-256 hash of the analysed file.
    pub file_hash: String,
    /// Name of the sandbox that produced this report.
    pub sandbox_name: String,
    /// Process tree from the sandbox execution.
    pub processes: ProcessTree,
    /// Network activity summary.
    pub network: NetworkSummary,
    /// File-system activity summary.
    pub files: FileSummary,
    /// MITRE ATT&CK technique identifiers observed (e.g. "T1082").
    pub attack_techniques: Vec<String>,
    /// Verdict tags (e.g. "dropper", "ransomware").
    pub tags: Vec<String>,
    /// Overall verdict score (0–100).
    pub verdict_score: Option<u32>,
}

impl VtBehaviorSummary {
    /// Build a summary from a raw VT v3 behaviour JSON object.
    #[must_use]
    pub fn from_vt_json(report: &Value) -> Self {
        let file_hash = report["sha256"]
            .as_str()
            .or_else(|| report["id"].as_str())
            .unwrap_or("")
            .to_string();
        let sandbox_name = report["sandbox_name"].as_str().unwrap_or("unknown").to_string();

        let processes = report["processes_tree"]
            .as_array()
            .map(|arr| ProcessTree::from_vt_json(arr))
            .unwrap_or_default();

        let network = NetworkSummary::from_vt_json(report);
        let files = FileSummary::from_vt_json(report);

        let attack_techniques: Vec<String> = report["attack_techniques"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v["id"].as_str().map(std::string::ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let tags: Vec<String> = report["tags"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(std::string::ToString::to_string)).collect())
            .unwrap_or_default();

        let verdict_score = report["verdict"]["score"].as_u64().map(|v| v as u32);

        Self {
            file_hash,
            sandbox_name,
            processes,
            network,
            files,
            attack_techniques,
            tags,
            verdict_score,
        }
    }

    /// Render a human-readable summary.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("=== VT Behavior Summary ===\n");
        out.push_str(&format!("File      : {}\n", self.file_hash));
        out.push_str(&format!("Sandbox   : {}\n", self.sandbox_name));
        if let Some(score) = self.verdict_score {
            out.push_str(&format!("Score     : {score}/100\n"));
        }
        if !self.tags.is_empty() {
            out.push_str(&format!("Tags      : {}\n", self.tags.join(", ")));
        }
        if !self.attack_techniques.is_empty() {
            out.push_str(&format!("ATT&CK    : {}\n", self.attack_techniques.join(", ")));
        }
        out.push_str(&format!("\nProcesses : {}\n", self.processes.len()));
        for name in self.processes.process_names().iter().take(10) {
            out.push_str(&format!("  - {name}\n"));
        }
        out.push_str(&format!("\nNetwork ({} IOCs):\n", self.network.total_iocs()));
        for d in self.network.domains.iter().take(10) {
            out.push_str(&format!("  domain: {d}\n"));
        }
        for ip in self.network.ips.iter().take(10) {
            out.push_str(&format!("  ip: {ip}\n"));
        }
        out.push_str("\nFiles:\n");
        out.push_str(&format!("  created:  {}\n", self.files.created.len()));
        out.push_str(&format!("  modified: {}\n", self.files.modified.len()));
        out.push_str(&format!("  deleted:  {}\n", self.files.deleted.len()));
        out.push_str(&format!("  dropped:  {}\n", self.files.dropped_hashes.len()));
        out
    }

    /// Return `true` if any network IOCs were observed.
    #[must_use]
    pub const fn has_network_activity(&self) -> bool {
        self.network.total_iocs() > 0
    }

    /// Return `true` if any files were dropped.
    #[must_use]
    pub const fn has_dropped_files(&self) -> bool {
        !self.files.dropped_hashes.is_empty()
    }

    /// Return `true` if any ATT&CK techniques were identified.
    #[must_use]
    pub const fn has_attack_techniques(&self) -> bool {
        !self.attack_techniques.is_empty()
    }
}

impl fmt::Display for VtBehaviorSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_report() -> Value {
        json!({
            "sha256": "deadbeef1234",
            "sandbox_name": "TestSandbox",
            "domains": ["evil.com", "malware.org"],
            "ip_traffic": [
                {"destination_ip": "1.2.3.4", "destination_port": 443, "transport_layer_protocol": "tcp"}
            ],
            "http_conversations": [
                {"url": "http://evil.com/payload", "destination_ip": "1.2.3.4", "destination_port": 80}
            ],
            "dns_lookups": [
                {"hostname": "evil.com", "resolved_ips": ["1.2.3.4"]}
            ],
            "files_written": ["/tmp/payload.exe"],
            "files_deleted": ["/tmp/old.tmp"],
            "files_opened": [],
            "dropped_files": [
                {"path": "/tmp/dropper.dll", "sha256": "aabbcc", "size": 1024}
            ],
            "processes_tree": [
                {"process_id": 1, "parent_process_id": 0, "name": "cmd.exe",
                 "command_line": "cmd.exe /c payload", "image_path": "C:\\Windows\\cmd.exe",
                 "children": [{"process_id": 2}]},
                {"process_id": 2, "parent_process_id": 1, "name": "payload.exe",
                 "command_line": "payload.exe", "image_path": "C:\\Temp\\payload.exe", "children": []}
            ],
            "attack_techniques": [{"id": "T1059"}, {"id": "T1082"}],
            "tags": ["dropper", "cmd"],
            "verdict": {"score": 80}
        })
    }

    // ── VtBehaviorSummary ─────────────────────────────────────────────────────

    #[test]
    fn test_from_vt_json_hash() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert_eq!(s.file_hash, "deadbeef1234");
    }

    #[test]
    fn test_from_vt_json_sandbox_name() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert_eq!(s.sandbox_name, "TestSandbox");
    }

    #[test]
    fn test_verdict_score() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert_eq!(s.verdict_score, Some(80));
    }

    #[test]
    fn test_attack_techniques() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert!(s.has_attack_techniques());
        assert!(s.attack_techniques.contains(&"T1059".to_string()));
    }

    #[test]
    fn test_tags() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert!(s.tags.contains(&"dropper".to_string()));
    }

    #[test]
    fn test_has_network_activity() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert!(s.has_network_activity());
    }

    #[test]
    fn test_has_dropped_files() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert!(s.has_dropped_files());
        assert!(s.files.dropped_hashes.contains(&"aabbcc".to_string()));
    }

    // ── NetworkSummary ────────────────────────────────────────────────────────

    #[test]
    fn test_network_domains() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert_eq!(s.network.domains.len(), 2);
        assert!(s.network.domains.contains(&"evil.com".to_string()));
    }

    #[test]
    fn test_network_ips() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert!(s.network.ips.contains(&"1.2.3.4".to_string()));
    }

    #[test]
    fn test_network_urls() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert!(!s.network.urls.is_empty());
    }

    #[test]
    fn test_dns_lookups() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert!(s.network.dns_lookups.contains_key("evil.com"));
    }

    #[test]
    fn test_total_iocs() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert!(s.network.total_iocs() >= 3);
    }

    // ── ProcessTree ───────────────────────────────────────────────────────────

    #[test]
    fn test_process_tree_len() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert_eq!(s.processes.len(), 2);
    }

    #[test]
    fn test_process_tree_root() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        let root = s.processes.get(1).unwrap();
        // pid=1, ppid=0 → treated as root
        assert_eq!(root.name, "cmd.exe");
    }

    #[test]
    fn test_process_names() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        let names = s.processes.process_names();
        assert!(names.contains(&"cmd.exe".to_string()));
        assert!(names.contains(&"payload.exe".to_string()));
    }

    // ── FileSummary ───────────────────────────────────────────────────────────

    #[test]
    fn test_files_modified() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert!(s.files.modified.contains(&"/tmp/payload.exe".to_string()));
    }

    #[test]
    fn test_files_deleted() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        assert!(s.files.deleted.contains(&"/tmp/old.tmp".to_string()));
    }

    #[test]
    fn test_render_non_empty() {
        let s = VtBehaviorSummary::from_vt_json(&sample_report());
        let r = s.render();
        assert!(r.contains("deadbeef1234"));
        assert!(r.contains("TestSandbox"));
    }

    #[test]
    fn test_empty_report_no_panic() {
        let empty = json!({});
        let s = VtBehaviorSummary::from_vt_json(&empty);
        assert!(s.file_hash.is_empty());
        let _ = s.render();
    }

    #[test]
    fn test_network_connection_display() {
        let c = NetworkConnection {
            ip: Some("1.2.3.4".to_string()),
            domain: Some("evil.com".to_string()),
            port: Some(443),
            protocol: "tcp".to_string(),
            url: None,
            country: None,
        };
        let s = c.to_string();
        assert!(s.contains("evil.com") || s.contains("1.2.3.4"));
    }
}
