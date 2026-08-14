//! Process tree rendering for sandbox reports.
//!
//! Builds a process tree from a flat event log and renders it as:
//! - Collapsible HTML tree
//! - JSON export
//! - Plain-text indented listing
//!
//! Also detects suspicious processes (`LOLBins`) such as
//! `powershell`, `wscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, etc.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ProcessTreeError {
    #[error("duplicate PID {0}")]
    DuplicatePid(u32),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("cycle detected in process tree")]
    Cycle,
}

// ── SuspiciousReason ─────────────────────────────────────────────────────────

/// Reason(s) a process is considered suspicious.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousReason {
    pub name: String,
    pub detail: String,
    pub severity: SuspiciousLevel,
}

/// Severity level for a suspicious process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SuspiciousLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SuspiciousLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ── SuspiciousProcess ────────────────────────────────────────────────────────

/// A flagged process with its reasons.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousProcess {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub reasons: Vec<SuspiciousReason>,
    pub max_severity: SuspiciousLevel,
}

impl SuspiciousProcess {
    #[must_use]
    pub fn new(pid: u32, name: String, cmdline: String, reasons: Vec<SuspiciousReason>) -> Self {
        let max_severity = reasons
            .iter()
            .map(|r| r.severity)
            .max()
            .unwrap_or(SuspiciousLevel::Low);
        Self {
            pid,
            name,
            cmdline,
            reasons,
            max_severity,
        }
    }
}

// ── LOLBin detection ─────────────────────────────────────────────────────────

/// Known Living-Off-The-Land Binaries and their default threat levels.
const LOLBINS: &[(&str, SuspiciousLevel, &str)] = &[
    (
        "powershell",
        SuspiciousLevel::High,
        "PowerShell execution can be used for download/execute attacks",
    ),
    ("powershell_ise", SuspiciousLevel::High, "PowerShell ISE"),
    (
        "wscript",
        SuspiciousLevel::High,
        "Windows Script Host can execute VBScript/JScript",
    ),
    (
        "cscript",
        SuspiciousLevel::High,
        "Windows Script Host (console) can execute scripts",
    ),
    (
        "mshta",
        SuspiciousLevel::Critical,
        "MSHTA executes HTML applications; common dropper vector",
    ),
    (
        "rundll32",
        SuspiciousLevel::High,
        "rundll32 can load arbitrary DLLs",
    ),
    (
        "regsvr32",
        SuspiciousLevel::High,
        "regsvr32 can execute remote COM scripts (Squiblydoo)",
    ),
    (
        "certutil",
        SuspiciousLevel::High,
        "certutil can decode Base64 and download files",
    ),
    (
        "bitsadmin",
        SuspiciousLevel::Medium,
        "BITS job can download payloads in background",
    ),
    (
        "msiexec",
        SuspiciousLevel::Medium,
        "msiexec can install remote MSI packages",
    ),
    (
        "cmd",
        SuspiciousLevel::Low,
        "cmd.exe spawned — check for unusual commands",
    ),
    (
        "wmic",
        SuspiciousLevel::High,
        "WMI can be used for lateral movement and persistence",
    ),
    (
        "schtasks",
        SuspiciousLevel::High,
        "Scheduled tasks can be used for persistence",
    ),
    (
        "regasm",
        SuspiciousLevel::High,
        "regasm can execute code via COM registration",
    ),
    (
        "regsvcs",
        SuspiciousLevel::High,
        "regsvcs can execute code via COM registration",
    ),
    (
        "installutil",
        SuspiciousLevel::High,
        "InstallUtil can bypass AppLocker",
    ),
    (
        "cmstp",
        SuspiciousLevel::High,
        "CMSTP can load remote INF scripts",
    ),
    (
        "odbcconf",
        SuspiciousLevel::Medium,
        "odbcconf can execute DLL payloads",
    ),
    (
        "ftp",
        SuspiciousLevel::Medium,
        "FTP can exfiltrate data or download payloads",
    ),
    (
        "curl",
        SuspiciousLevel::Medium,
        "curl can download payloads",
    ),
    (
        "wget",
        SuspiciousLevel::Medium,
        "wget can download payloads",
    ),
    (
        "ntdsutil",
        SuspiciousLevel::Critical,
        "ntdsutil can dump AD credential store",
    ),
    (
        "vssadmin",
        SuspiciousLevel::Critical,
        "vssadmin can delete shadow copies (ransomware)",
    ),
    (
        "wbadmin",
        SuspiciousLevel::High,
        "wbadmin can delete Windows backups",
    ),
    (
        "bcdedit",
        SuspiciousLevel::High,
        "bcdedit can disable recovery (ransomware)",
    ),
];

/// Detect if a process name is a known `LOLBin`.
#[must_use]
pub fn detect_lolbin(name: &str) -> Option<(SuspiciousLevel, &'static str)> {
    let lower = name.to_ascii_lowercase();
    // Strip .exe extension if present.
    let base = lower.strip_suffix(".exe").unwrap_or(&lower);
    for &(lol, level, desc) in LOLBINS {
        if base == lol {
            return Some((level, desc));
        }
    }
    None
}

// ── ProcessNode ───────────────────────────────────────────────────────────────

/// A single node in the process tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID (0 = root / unknown).
    pub ppid: u32,
    /// Process name (base name, without path).
    pub name: String,
    /// Full command line.
    pub cmdline: String,
    /// `true` if this process was detected as injected.
    pub injected: bool,
    /// Suspicious reasons (empty = clean).
    pub suspicious: Vec<SuspiciousReason>,
    /// Child nodes.
    pub children: Vec<Self>,
    /// Time offset in milliseconds from sandbox start.
    pub start_ms: u64,
    /// Exit code (None if still running).
    pub exit_code: Option<i32>,
}

impl ProcessNode {
    /// Create a new node.
    pub fn new(
        process_id: u32,
        parent_pid: u32,
        name: impl Into<String>,
        cmdline: impl Into<String>,
    ) -> Self {
        Self {
            pid: process_id,
            ppid: parent_pid,
            name: name.into(),
            cmdline: cmdline.into(),
            injected: false,
            suspicious: Vec::new(),
            children: Vec::new(),
            start_ms: 0,
            exit_code: None,
        }
    }

    /// Return `true` if this process has any suspicious indicators.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        !self.suspicious.is_empty() || self.injected
    }

    /// Return the maximum suspicion level (None if clean).
    #[must_use]
    pub fn max_severity(&self) -> Option<SuspiciousLevel> {
        self.suspicious.iter().map(|r| r.severity).max()
    }

    /// Total number of descendants (recursive).
    #[must_use]
    pub fn descendant_count(&self) -> usize {
        self.children.iter().map(|c| 1 + c.descendant_count()).sum()
    }
}

// ── ProcessTree ───────────────────────────────────────────────────────────────

/// A hierarchical process tree built from a flat process list.
pub struct ProcessTree {
    /// Root nodes (processes whose PPID is not in the tree, or PPID = 0).
    pub roots: Vec<ProcessNode>,
}

impl ProcessTree {
    /// Build a process tree from a flat list of process records.
    ///
    /// Processes are inserted as children of their parent PID.
    /// Processes whose parent is not in the list become root nodes.
    #[must_use]
    pub fn build(mut nodes: Vec<ProcessNode>) -> Self {
        // Auto-detect LOLBins.
        for node in &mut nodes {
            if let Some((level, desc)) = detect_lolbin(&node.name) {
                node.suspicious.push(SuspiciousReason {
                    name: "LOLBin".into(),
                    detail: desc.to_owned(),
                    severity: level,
                });
            }
        }

        let pids: std::collections::HashSet<u32> = nodes.iter().map(|n| n.pid).collect();

        // Separate roots from children.
        let (root_nodes, child_nodes): (Vec<_>, Vec<_>) = nodes
            .into_iter()
            .partition(|n| n.ppid == 0 || !pids.contains(&n.ppid));

        // Build a map of ppid → children.
        let mut child_map: HashMap<u32, Vec<ProcessNode>> = HashMap::new();
        for node in child_nodes {
            child_map.entry(node.ppid).or_default().push(node);
        }

        // Recursively attach children.
        let roots = root_nodes
            .into_iter()
            .map(|root| Self::attach_children(root, &mut child_map))
            .collect();

        Self { roots }
    }

    fn attach_children(
        mut node: ProcessNode,
        map: &mut HashMap<u32, Vec<ProcessNode>>,
    ) -> ProcessNode {
        if let Some(children) = map.remove(&node.pid) {
            node.children = children
                .into_iter()
                .map(|c| Self::attach_children(c, map))
                .collect();
        }
        node
    }

    /// Collect all suspicious processes across the entire tree.
    #[must_use]
    pub fn suspicious_processes(&self) -> Vec<SuspiciousProcess> {
        let mut result = Vec::new();
        for root in &self.roots {
            Self::collect_suspicious(root, &mut result);
        }
        result
    }

    fn collect_suspicious(node: &ProcessNode, out: &mut Vec<SuspiciousProcess>) {
        if node.is_suspicious() {
            out.push(SuspiciousProcess::new(
                node.pid,
                node.name.clone(),
                node.cmdline.clone(),
                node.suspicious.clone(),
            ));
        }
        for child in &node.children {
            Self::collect_suspicious(child, out);
        }
    }

    /// Render as an indented plain-text listing.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        for root in &self.roots {
            Self::render_node_text(root, 0, &mut out);
        }
        out
    }

    fn render_node_text(node: &ProcessNode, depth: usize, out: &mut String) {
        let indent = "  ".repeat(depth);
        let flag = if node.is_suspicious() { " [!]" } else { "" };
        let _ = writeln!(
            out,
            "{indent}[{pid}] {name} ({cmdline}){flag}",
            pid = node.pid,
            name = node.name,
            cmdline = node.cmdline.get(..60).unwrap_or(&node.cmdline),
        );
        for child in &node.children {
            Self::render_node_text(child, depth + 1, out);
        }
    }

    /// Export as JSON.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessTreeError::SerializationError`] when `serde_json`
    /// fails to encode the tree (e.g. for non-UTF-8 strings in a custom
    /// serializer).
    pub fn to_json(&self) -> Result<String, ProcessTreeError> {
        serde_json::to_string_pretty(&self.roots)
            .map_err(|e| ProcessTreeError::SerializationError(e.to_string()))
    }

    /// Render as an HTML collapsible tree.
    #[must_use]
    pub fn render_html(&self) -> String {
        let mut out = String::new();
        out.push_str(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Process Tree</title>
<style>
body { font-family: monospace; margin: 1em; }
details { margin-left: 1.5em; }
summary { cursor: pointer; }
.suspicious { color: #c0392b; font-weight: bold; }
.injected { color: #8e44ad; font-style: italic; }
.pid { color: #7f8c8d; }
</style>
</head>
<body>
<h2>Process Tree</h2>
"#,
        );
        for root in &self.roots {
            Self::render_node_html(root, &mut out);
        }
        out.push_str("</body></html>\n");
        out
    }

    fn render_node_html(node: &ProcessNode, out: &mut String) {
        let susp_class = if node.is_suspicious() {
            " class=\"suspicious\""
        } else {
            ""
        };
        let inj_str = if node.injected {
            " <span class=\"injected\">[injected]</span>"
        } else {
            ""
        };
        let pid_str = format!("<span class=\"pid\">[{}]</span>", node.pid);

        if node.children.is_empty() {
            let _ = writeln!(
                out,
                "<div{susp_class}>{pid_str} {name}{inj_str}</div>",
                name = html_escape(&node.name),
            );
        } else {
            let _ = writeln!(
                out,
                "<details><summary{susp_class}>{pid_str} {name}{inj_str} ({n} children)</summary>",
                name = html_escape(&node.name),
                n = node.children.len(),
            );
            for child in &node.children {
                Self::render_node_html(child, out);
            }
            out.push_str("</details>\n");
        }
    }

    /// Count total processes in the tree.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.roots.iter().map(|r| 1 + r.descendant_count()).sum()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(process_id: u32, parent_pid: u32, name: &str, cmd: &str) -> ProcessNode {
        ProcessNode::new(process_id, parent_pid, name, cmd)
    }

    #[test]
    fn test_process_node_new() {
        let n = make_node(1234, 1, "svchost.exe", "svchost -k netsvcs");
        assert_eq!(n.pid, 1234);
        assert_eq!(n.ppid, 1);
        assert!(!n.is_suspicious());
    }

    #[test]
    fn test_process_tree_single_root() {
        let nodes = vec![make_node(1, 0, "explorer.exe", "C:\\Windows\\explorer.exe")];
        let tree = ProcessTree::build(nodes);
        assert_eq!(tree.roots.len(), 1);
        assert_eq!(tree.total_count(), 1);
    }

    #[test]
    fn test_process_tree_parent_child() {
        let nodes = vec![
            make_node(1, 0, "explorer.exe", "explorer"),
            make_node(2, 1, "cmd.exe", "cmd /c whoami"),
        ];
        let tree = ProcessTree::build(nodes);
        assert_eq!(tree.roots.len(), 1);
        assert_eq!(tree.roots[0].children.len(), 1);
    }

    #[test]
    fn test_process_tree_three_levels() {
        let nodes = vec![
            make_node(1, 0, "explorer.exe", "explorer"),
            make_node(2, 1, "cmd.exe", "cmd"),
            make_node(3, 2, "powershell.exe", "powershell -e ..."),
        ];
        let tree = ProcessTree::build(nodes);
        assert_eq!(tree.total_count(), 3);
    }

    #[test]
    fn test_lolbin_powershell() {
        let (level, _) = detect_lolbin("powershell.exe").unwrap();
        assert_eq!(level, SuspiciousLevel::High);
    }

    #[test]
    fn test_lolbin_mshta() {
        let (level, _) = detect_lolbin("mshta.exe").unwrap();
        assert_eq!(level, SuspiciousLevel::Critical);
    }

    #[test]
    fn test_lolbin_rundll32() {
        let (level, _) = detect_lolbin("rundll32.exe").unwrap();
        assert_eq!(level, SuspiciousLevel::High);
    }

    #[test]
    fn test_lolbin_not_found() {
        assert!(detect_lolbin("notepad.exe").is_none());
    }

    #[test]
    fn test_lolbin_certutil() {
        assert!(detect_lolbin("certutil.exe").is_some());
    }

    #[test]
    fn test_lolbin_regsvr32() {
        assert!(detect_lolbin("regsvr32").is_some());
    }

    #[test]
    fn test_auto_detect_lolbin_in_tree() {
        let nodes = vec![
            make_node(1, 0, "explorer.exe", "explorer"),
            make_node(2, 1, "powershell.exe", "powershell -enc ..."),
        ];
        let tree = ProcessTree::build(nodes);
        let susp = tree.suspicious_processes();
        assert!(!susp.is_empty());
        assert_eq!(susp[0].name, "powershell.exe");
    }

    #[test]
    fn test_suspicious_process_new() {
        let sp = SuspiciousProcess::new(
            42,
            "wscript.exe".into(),
            "wscript malware.vbs".into(),
            vec![SuspiciousReason {
                name: "LOLBin".into(),
                detail: "Windows Script Host".into(),
                severity: SuspiciousLevel::High,
            }],
        );
        assert_eq!(sp.max_severity, SuspiciousLevel::High);
    }

    #[test]
    fn test_process_tree_render_text_contains_name() {
        let nodes = vec![make_node(1, 0, "cmd.exe", "cmd /c dir")];
        let tree = ProcessTree::build(nodes);
        let text = tree.render_text();
        assert!(text.contains("cmd.exe"), "text: {text}");
    }

    #[test]
    fn test_process_tree_render_html_contains_structure() {
        let nodes = vec![
            make_node(1, 0, "explorer.exe", "explorer"),
            make_node(2, 1, "cmd.exe", "cmd"),
        ];
        let tree = ProcessTree::build(nodes);
        let html = tree.render_html();
        assert!(
            html.contains("<details>") || html.contains("explorer.exe"),
            "html: {html}"
        );
    }

    #[test]
    fn test_process_tree_json_export() {
        let nodes = vec![make_node(1, 0, "svchost.exe", "svchost")];
        let tree = ProcessTree::build(nodes);
        let json = tree.to_json().unwrap();
        assert!(json.contains("svchost.exe"));
    }

    #[test]
    fn test_process_node_descendant_count() {
        let nodes = vec![
            make_node(1, 0, "a.exe", "a"),
            make_node(2, 1, "b.exe", "b"),
            make_node(3, 1, "c.exe", "c"),
            make_node(4, 2, "d.exe", "d"),
        ];
        let tree = ProcessTree::build(nodes);
        assert_eq!(tree.roots[0].descendant_count(), 3);
    }

    #[test]
    fn test_process_node_injected_flag() {
        let mut n = make_node(5, 1, "svchost.exe", "svchost");
        n.injected = true;
        assert!(n.is_suspicious());
    }

    #[test]
    fn test_process_node_max_severity_none() {
        let n = make_node(1, 0, "notepad.exe", "notepad");
        assert!(n.max_severity().is_none());
    }

    #[test]
    fn test_process_node_max_severity_some() {
        let mut n = make_node(1, 0, "wscript.exe", "wscript");
        n.suspicious.push(SuspiciousReason {
            name: "LOLBin".into(),
            detail: String::new(),
            severity: SuspiciousLevel::High,
        });
        assert_eq!(n.max_severity(), Some(SuspiciousLevel::High));
    }

    #[test]
    fn test_suspicious_level_ordering() {
        assert!(SuspiciousLevel::Critical > SuspiciousLevel::High);
        assert!(SuspiciousLevel::High > SuspiciousLevel::Low);
    }

    #[test]
    fn test_orphan_processes_become_roots() {
        // Process with ppid=999 where 999 is not in the list → becomes root.
        let nodes = vec![
            make_node(1, 0, "root.exe", "root"),
            make_node(2, 999, "orphan.exe", "orphan"),
        ];
        let tree = ProcessTree::build(nodes);
        assert_eq!(tree.roots.len(), 2);
    }

    #[test]
    fn test_suspicious_reason_fields() {
        let r = SuspiciousReason {
            name: "Test".into(),
            detail: "detail text".into(),
            severity: SuspiciousLevel::Medium,
        };
        assert_eq!(r.severity, SuspiciousLevel::Medium);
        assert_eq!(r.name, "Test");
    }

    #[test]
    fn test_html_escape_in_render() {
        let n = make_node(1, 0, "test<>exe", "cmd & dir");
        let nodes = vec![n];
        let tree = ProcessTree::build(nodes);
        let html = tree.render_html();
        // Should not contain raw < or > in the name.
        assert!(!html.contains("test<>exe"), "raw < or > in html: {html}");
    }
}
