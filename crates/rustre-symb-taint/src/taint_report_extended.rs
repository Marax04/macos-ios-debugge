//! `taint_report_extended` — extended taint reporting and vulnerability analysis.
//!
//! Provides `TaintReportExtended`, `TaintPath`, `DataFlowGraph`,
//! `VulnerabilityReport`, `TaintedApiCall`, and `SeverityLevel`.

use crate::{
    FindingType, PropagationOp, TaintFinding, TaintId, TaintLocation, TaintSource, taint_bits,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ── SeverityLevel ─────────────────────────────────────────────────────────────

/// CVSS-inspired severity level for a vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SeverityLevel {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityLevel {
    /// Numeric CVSS-like score (0.0–10.0).
    #[must_use]
    pub fn score(&self) -> f32 {
        match self {
            Self::Informational => 0.0,
            Self::Low => 3.0,
            Self::Medium => 5.5,
            Self::High => 7.5,
            Self::Critical => 9.5,
        }
    }

    /// Derive severity from finding type and taint source risk.
    #[must_use]
    pub fn from_finding(finding_type: &FindingType, source_risk: u8) -> Self {
        let base = match finding_type {
            FindingType::CommandInjection => 4,
            FindingType::BufferOverflow => 3,
            FindingType::FormatString => 3,
            FindingType::SqlInjection => 3,
            FindingType::PathTraversal => 2,
            FindingType::UseAfterFree => 4,
            FindingType::IntegerOverflow => 2,
            FindingType::TaintedCondition => 1,
            FindingType::Custom(_) => 1,
        };
        let extra = if source_risk >= 80 { 1 } else { 0 };
        match base + extra {
            0..=1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            _ => Self::Critical,
        }
    }
}

impl fmt::Display for SeverityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Informational => write!(f, "Informational"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

// ── TaintPath ─────────────────────────────────────────────────────────────────

/// A source-to-sink taint propagation path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    /// Source location where taint originates.
    pub source: TaintLocation,
    /// Source type.
    pub source_type: TaintSource,
    /// Ordered steps from source to sink.
    pub steps: Vec<TaintPathStep>,
    /// Sink location.
    pub sink: TaintLocation,
    /// Sink API name.
    pub sink_api: String,
    /// Type of vulnerability this path represents.
    pub vuln_type: FindingType,
    /// Whether any sanitizer appears in the path.
    pub sanitized: bool,
}

impl TaintPath {
    /// Construct a new taint path.
    #[must_use]
    pub fn new(
        source: TaintLocation,
        source_type: TaintSource,
        sink: TaintLocation,
        sink_api: impl Into<String>,
        vuln_type: FindingType,
    ) -> Self {
        Self {
            source,
            source_type,
            sink,
            sink_api: sink_api.into(),
            vuln_type,
            steps: Vec::new(),
            sanitized: false,
        }
    }

    /// Append a propagation step.
    pub fn add_step(&mut self, step: TaintPathStep) {
        self.steps.push(step);
    }

    /// Number of intermediate steps.
    #[must_use]
    pub fn length(&self) -> usize {
        self.steps.len()
    }

    /// Return all intermediate addresses.
    #[must_use]
    pub fn addresses(&self) -> Vec<u64> {
        self.steps.iter().map(|s| s.instruction_address).collect()
    }

    /// Return true if this path traverses more than `limit` steps.
    #[must_use]
    pub fn is_long(&self, limit: usize) -> bool {
        self.steps.len() > limit
    }

    /// Summarize the path as "source → step1 → … → sink".
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} ({}) → [{} steps] → {}({})",
            self.source,
            self.source_type.category(),
            self.steps.len(),
            self.sink_api,
            self.sink,
        )
    }
}

/// A single step in a taint propagation path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPathStep {
    pub from: TaintLocation,
    pub to: TaintLocation,
    pub operation: PropagationOp,
    pub instruction_address: u64,
    pub note: Option<String>,
}

impl TaintPathStep {
    #[must_use]
    pub fn new(from: TaintLocation, to: TaintLocation, op: PropagationOp, addr: u64) -> Self {
        Self {
            from,
            to,
            operation: op,
            instruction_address: addr,
            note: None,
        }
    }

    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

// ── DataFlowGraph ─────────────────────────────────────────────────────────────

/// A data-flow graph capturing taint propagation across a function.
///
/// Nodes are `TaintLocation`s; edges are labeled with `PropagationOp`
/// and instruction addresses.
#[derive(Debug, Default)]
pub struct DataFlowGraph {
    /// Adjacency list: from_node → list of (to_node, op, addr).
    edges: HashMap<usize, Vec<(usize, PropagationOp, u64)>>,
    /// Node index ↔ location mapping.
    nodes: Vec<TaintLocation>,
    /// Reverse index: location → node id.
    node_index: HashMap<String, usize>,
    /// Source nodes.
    pub sources: Vec<usize>,
    /// Sink nodes.
    pub sinks: Vec<usize>,
}

impl DataFlowGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn location_key(loc: &TaintLocation) -> String {
        format!("{loc}")
    }

    /// Get or create a node for `loc`.
    pub fn node_for(&mut self, loc: TaintLocation) -> usize {
        let key = Self::location_key(&loc);
        if let Some(&id) = self.node_index.get(&key) {
            return id;
        }
        let id = self.nodes.len();
        self.nodes.push(loc);
        self.node_index.insert(key, id);
        id
    }

    /// Add a directed edge.
    pub fn add_edge(
        &mut self,
        from: TaintLocation,
        to: TaintLocation,
        op: PropagationOp,
        addr: u64,
    ) {
        let from_id = self.node_for(from);
        let to_id = self.node_for(to);
        self.edges
            .entry(from_id)
            .or_default()
            .push((to_id, op, addr));
    }

    /// Mark a location as a source.
    pub fn mark_source(&mut self, loc: TaintLocation) {
        let id = self.node_for(loc);
        if !self.sources.contains(&id) {
            self.sources.push(id);
        }
    }

    /// Mark a location as a sink.
    pub fn mark_sink(&mut self, loc: TaintLocation) {
        let id = self.node_for(loc);
        if !self.sinks.contains(&id) {
            self.sinks.push(id);
        }
    }

    /// Find all paths from any source to any sink using BFS.
    #[must_use]
    pub fn find_source_sink_paths(&self) -> Vec<Vec<usize>> {
        let mut result = Vec::new();
        for &src in &self.sources {
            for &snk in &self.sinks {
                if let Some(path) = self.bfs_path(src, snk) {
                    result.push(path);
                }
            }
        }
        result
    }

    fn bfs_path(&self, from: usize, to: usize) -> Option<Vec<usize>> {
        if from == to {
            return Some(vec![from]);
        }
        let mut visited = HashSet::new();
        let mut queue: VecDeque<Vec<usize>> = VecDeque::new();
        queue.push_back(vec![from]);
        while let Some(path) = queue.pop_front() {
            let node = *path.last().unwrap();
            if !visited.insert(node) {
                continue;
            }
            if let Some(neighbors) = self.edges.get(&node) {
                for &(next, _, _) in neighbors {
                    let mut new_path = path.clone();
                    new_path.push(next);
                    if next == to {
                        return Some(new_path);
                    }
                    queue.push_back(new_path);
                }
            }
        }
        None
    }

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|v| v.len()).sum()
    }

    /// Get location for node id.
    #[must_use]
    pub fn location_of(&self, id: usize) -> Option<&TaintLocation> {
        self.nodes.get(id)
    }

    /// Check reachability from `from` to `to`.
    #[must_use]
    pub fn reachable(&self, from: TaintLocation, to: TaintLocation) -> bool {
        let from_id = match self.node_index.get(&Self::location_key(&from)) {
            Some(&i) => i,
            None => return false,
        };
        let to_id = match self.node_index.get(&Self::location_key(&to)) {
            Some(&i) => i,
            None => return false,
        };
        self.bfs_path(from_id, to_id).is_some()
    }

    /// All edges as (from_node_id, to_node_id, op, addr) tuples.
    #[must_use]
    pub fn all_edges(&self) -> Vec<(usize, usize, PropagationOp, u64)> {
        self.edges
            .iter()
            .flat_map(|(&from, nexts)| {
                nexts
                    .iter()
                    .map(move |&(to, op, addr)| (from, to, op, addr))
            })
            .collect()
    }

    /// Whether the graph has any edges at all.
    #[must_use]
    pub fn has_edges(&self) -> bool {
        self.edge_count() > 0
    }
}

// ── TaintedApiCall ─────────────────────────────────────────────────────────────

/// A recorded API call where at least one argument is tainted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintedApiCall {
    /// API function name.
    pub function: String,
    /// Call site address.
    pub address: u64,
    /// Per-argument taint masks.
    pub arg_taints: Vec<TaintId>,
    /// Return value taint (if applicable).
    pub return_taint: TaintId,
    /// Source locations contributing to the taint.
    pub taint_sources: Vec<TaintSource>,
    /// Whether this call constitutes a dangerous sink.
    pub is_dangerous: bool,
}

impl TaintedApiCall {
    #[must_use]
    pub fn new(function: impl Into<String>, address: u64) -> Self {
        Self {
            function: function.into(),
            address,
            arg_taints: Vec::new(),
            return_taint: taint_bits::NONE,
            taint_sources: Vec::new(),
            is_dangerous: false,
        }
    }

    /// Add argument taint.
    pub fn add_arg(&mut self, taint: TaintId) {
        self.arg_taints.push(taint);
    }

    /// Union of all argument taints.
    #[must_use]
    pub fn combined_arg_taint(&self) -> TaintId {
        self.arg_taints
            .iter()
            .fold(taint_bits::NONE, |acc, &t| acc | t)
    }

    /// True if any argument is tainted.
    #[must_use]
    pub fn has_tainted_args(&self) -> bool {
        taint_bits::is_tainted(self.combined_arg_taint())
    }

    /// Classify as dangerous based on function name.
    pub fn classify(&mut self) {
        let dangerous = [
            "system",
            "execve",
            "execl",
            "printf",
            "sprintf",
            "strcpy",
            "memcpy",
            "gets",
            "fopen",
            "open",
            "sqlite3_exec",
        ];
        self.is_dangerous = dangerous.iter().any(|&d| self.function == d);
    }
}

// ── VulnerabilityReport ────────────────────────────────────────────────────────

/// A structured vulnerability report correlating taint paths and API calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityReport {
    pub vulnerability_id: String,
    pub title: String,
    pub description: String,
    pub severity: SeverityLevel,
    pub finding_type: FindingType,
    pub taint_paths: Vec<TaintPath>,
    pub tainted_calls: Vec<TaintedApiCall>,
    pub evidence_count: usize,
    pub remediation: String,
}

impl VulnerabilityReport {
    /// Build from a `TaintFinding`.
    #[must_use]
    pub fn from_finding(finding: &TaintFinding, vuln_id: impl Into<String>) -> Self {
        let severity = SeverityLevel::from_finding(&finding.finding_type, 80);
        let remediation = remediation_for(&finding.finding_type);
        Self {
            vulnerability_id: vuln_id.into(),
            title: finding.finding_type.to_string(),
            description: finding.description.clone(),
            severity,
            finding_type: finding.finding_type.clone(),
            taint_paths: Vec::new(),
            tainted_calls: Vec::new(),
            evidence_count: 1,
            remediation,
        }
    }

    /// Add a taint path.
    pub fn add_path(&mut self, path: TaintPath) {
        self.taint_paths.push(path);
    }

    /// Add a tainted API call.
    pub fn add_call(&mut self, call: TaintedApiCall) {
        self.tainted_calls.push(call);
    }

    /// Return true if this is a high or critical severity finding.
    #[must_use]
    pub fn is_severe(&self) -> bool {
        self.severity >= SeverityLevel::High
    }

    /// Total number of taint paths.
    #[must_use]
    pub fn path_count(&self) -> usize {
        self.taint_paths.len()
    }

    /// All unique source categories across all paths.
    #[must_use]
    pub fn source_categories(&self) -> Vec<&'static str> {
        let mut cats: Vec<&'static str> = self
            .taint_paths
            .iter()
            .map(|p| p.source_type.category())
            .collect();
        cats.sort_unstable();
        cats.dedup();
        cats
    }
}

/// Return the CWE identifier for a given finding type.
#[must_use]
pub fn cwe_for(t: &FindingType) -> &'static str {
    match t {
        FindingType::CommandInjection => "CWE-78",
        FindingType::BufferOverflow => "CWE-120",
        FindingType::FormatString => "CWE-134",
        FindingType::SqlInjection => "CWE-89",
        FindingType::PathTraversal => "CWE-22",
        FindingType::UseAfterFree => "CWE-416",
        FindingType::IntegerOverflow => "CWE-190",
        FindingType::TaintedCondition => "CWE-732",
        FindingType::Custom(_) => "CWE-0",
    }
}

fn remediation_for(t: &FindingType) -> String {
    match t {
        FindingType::CommandInjection => "Sanitize all user-controlled data before passing to shell commands. Use parameterized command invocation instead.".into(),
        FindingType::BufferOverflow => "Validate buffer sizes. Use safe string and memory functions with explicit length limits.".into(),
        FindingType::FormatString => "Never pass user-controlled data as the format string argument. Use %s with a fixed format.".into(),
        FindingType::SqlInjection => "Use parameterized queries or prepared statements. Never concatenate user input into SQL.".into(),
        FindingType::PathTraversal => "Normalize and validate all file paths. Reject paths containing '..' components.".into(),
        FindingType::UseAfterFree => "Ensure memory is not accessed after deallocation. Use smart pointers or RAII patterns.".into(),
        FindingType::IntegerOverflow => "Add overflow checks before arithmetic. Use saturating or checked arithmetic.".into(),
        FindingType::TaintedCondition => "Avoid using untrusted data in security-critical conditions.".into(),
        FindingType::Custom(_) => "Review the taint flow and apply appropriate input validation.".into(),
    }
}

// ── TaintReportExtended ────────────────────────────────────────────────────────

/// Extended taint report aggregating multiple vulnerability reports and the
/// underlying data-flow graph.
#[derive(Debug)]
pub struct TaintReportExtended {
    pub vulnerabilities: Vec<VulnerabilityReport>,
    pub data_flow_graph: DataFlowGraph,
    pub all_paths: Vec<TaintPath>,
    pub all_calls: Vec<TaintedApiCall>,
    pub total_instructions_analyzed: u64,
    pub analysis_name: String,
}

impl TaintReportExtended {
    /// Create a new extended report.
    #[must_use]
    pub fn new(analysis_name: impl Into<String>) -> Self {
        Self {
            vulnerabilities: Vec::new(),
            data_flow_graph: DataFlowGraph::new(),
            all_paths: Vec::new(),
            all_calls: Vec::new(),
            total_instructions_analyzed: 0,
            analysis_name: analysis_name.into(),
        }
    }

    /// Add a vulnerability report.
    pub fn add_vulnerability(&mut self, vuln: VulnerabilityReport) {
        self.vulnerabilities.push(vuln);
    }

    /// Add a taint path.
    pub fn add_path(&mut self, path: TaintPath) {
        self.all_paths.push(path);
    }

    /// Add a tainted API call.
    pub fn add_call(&mut self, call: TaintedApiCall) {
        self.all_calls.push(call);
    }

    /// Total number of vulnerabilities.
    #[must_use]
    pub fn vulnerability_count(&self) -> usize {
        self.vulnerabilities.len()
    }

    /// Count of severe (High/Critical) vulnerabilities.
    #[must_use]
    pub fn severe_count(&self) -> usize {
        self.vulnerabilities
            .iter()
            .filter(|v| v.is_severe())
            .count()
    }

    /// Highest severity found.
    #[must_use]
    pub fn max_severity(&self) -> Option<SeverityLevel> {
        self.vulnerabilities.iter().map(|v| v.severity).max()
    }

    /// Filter vulnerabilities by severity.
    #[must_use]
    pub fn by_severity(&self, level: SeverityLevel) -> Vec<&VulnerabilityReport> {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity == level)
            .collect()
    }

    /// All dangerous API calls.
    #[must_use]
    pub fn dangerous_calls(&self) -> Vec<&TaintedApiCall> {
        self.all_calls.iter().filter(|c| c.is_dangerous).collect()
    }

    /// Unique sink API names.
    #[must_use]
    pub fn sink_apis(&self) -> Vec<String> {
        let mut apis: Vec<String> = self.all_paths.iter().map(|p| p.sink_api.clone()).collect();
        apis.sort();
        apis.dedup();
        apis
    }

    /// Generate a plain-text summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} vulns ({} severe), {} paths, {} API calls",
            self.analysis_name,
            self.vulnerability_count(),
            self.severe_count(),
            self.all_paths.len(),
            self.all_calls.len(),
        )
    }

    /// Build the data flow graph from all paths in this report.
    pub fn build_dfg_from_paths(&mut self) {
        for path in &self.all_paths {
            self.data_flow_graph.mark_source(path.source.clone());
            self.data_flow_graph.mark_sink(path.sink.clone());
            for step in &path.steps {
                self.data_flow_graph.add_edge(
                    step.from.clone(),
                    step.to.clone(),
                    step.operation,
                    step.instruction_address,
                );
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint_bits;

    fn cmd_finding() -> TaintFinding {
        TaintFinding::new(
            FindingType::CommandInjection,
            0x1000,
            taint_bits::USER_INPUT,
            "cmd inj",
        )
    }

    fn fmt_finding() -> TaintFinding {
        TaintFinding::new(
            FindingType::FormatString,
            0x2000,
            taint_bits::NETWORK,
            "fmt str",
        )
    }

    fn simple_path() -> TaintPath {
        let mut p = TaintPath::new(
            TaintLocation::Register("rdi".into()),
            TaintSource::UserInput,
            TaintLocation::Register("rax".into()),
            "system",
            FindingType::CommandInjection,
        );
        p.add_step(TaintPathStep::new(
            TaintLocation::Register("rdi".into()),
            TaintLocation::Register("rax".into()),
            PropagationOp::Assign,
            0x100,
        ));
        p
    }

    // ── SeverityLevel ─────────────────────────────────────────────────────────

    #[test]
    fn test_severity_ordering() {
        assert!(SeverityLevel::Critical > SeverityLevel::High);
        assert!(SeverityLevel::High > SeverityLevel::Medium);
        assert!(SeverityLevel::Medium > SeverityLevel::Low);
        assert!(SeverityLevel::Low > SeverityLevel::Informational);
    }

    #[test]
    fn test_severity_score() {
        assert!(SeverityLevel::Critical.score() > SeverityLevel::High.score());
        assert!(SeverityLevel::Informational.score() == 0.0);
    }

    #[test]
    fn test_severity_from_command_injection_high_risk() {
        let sev = SeverityLevel::from_finding(&FindingType::CommandInjection, 90);
        assert_eq!(sev, SeverityLevel::Critical);
    }

    #[test]
    fn test_severity_from_path_traversal_low_risk() {
        let sev = SeverityLevel::from_finding(&FindingType::PathTraversal, 30);
        assert_eq!(sev, SeverityLevel::Medium);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", SeverityLevel::Critical), "Critical");
        assert_eq!(format!("{}", SeverityLevel::Informational), "Informational");
    }

    // ── TaintPath ─────────────────────────────────────────────────────────────

    #[test]
    fn test_path_length() {
        let path = simple_path();
        assert_eq!(path.length(), 1);
    }

    #[test]
    fn test_path_addresses() {
        let path = simple_path();
        assert_eq!(path.addresses(), vec![0x100u64]);
    }

    #[test]
    fn test_path_is_long() {
        let path = simple_path();
        assert!(!path.is_long(5));
        assert!(path.is_long(0));
    }

    #[test]
    fn test_path_summary_contains_source_and_sink() {
        let path = simple_path();
        let s = path.summary();
        assert!(s.contains("system"));
        assert!(s.contains("user-input"));
    }

    #[test]
    fn test_path_sanitized_default_false() {
        let path = simple_path();
        assert!(!path.sanitized);
    }

    #[test]
    fn test_path_step_with_note() {
        let step = TaintPathStep::new(
            TaintLocation::Register("rax".into()),
            TaintLocation::Memory(0x1000),
            PropagationOp::Store,
            0x200,
        )
        .with_note("via memcpy");
        assert_eq!(step.note, Some("via memcpy".into()));
    }

    // ── DataFlowGraph ─────────────────────────────────────────────────────────

    #[test]
    fn test_dfg_add_edge_creates_nodes() {
        let mut dfg = DataFlowGraph::new();
        dfg.add_edge(
            TaintLocation::Register("rax".into()),
            TaintLocation::Memory(0x1000),
            PropagationOp::Store,
            0x100,
        );
        assert_eq!(dfg.node_count(), 2);
        assert_eq!(dfg.edge_count(), 1);
    }

    #[test]
    fn test_dfg_reachable_direct() {
        let mut dfg = DataFlowGraph::new();
        let src = TaintLocation::Register("rax".into());
        let dst = TaintLocation::Memory(0x1000);
        dfg.add_edge(src.clone(), dst.clone(), PropagationOp::Store, 0x100);
        assert!(dfg.reachable(src, dst));
    }

    #[test]
    fn test_dfg_reachable_transitive() {
        let mut dfg = DataFlowGraph::new();
        let a = TaintLocation::Register("rax".into());
        let b = TaintLocation::Memory(0x1000);
        let c = TaintLocation::Register("rdi".into());
        dfg.add_edge(a.clone(), b.clone(), PropagationOp::Store, 0x100);
        dfg.add_edge(b.clone(), c.clone(), PropagationOp::Load, 0x200);
        assert!(dfg.reachable(a, c));
    }

    #[test]
    fn test_dfg_not_reachable() {
        let mut dfg = DataFlowGraph::new();
        let a = TaintLocation::Register("rax".into());
        let b = TaintLocation::Memory(0x1000);
        dfg.add_edge(a.clone(), b.clone(), PropagationOp::Store, 0);
        assert!(!dfg.reachable(b, a)); // reverse not reachable
    }

    #[test]
    fn test_dfg_source_sink_paths() {
        let mut dfg = DataFlowGraph::new();
        let src = TaintLocation::Register("rdi".into());
        let snk = TaintLocation::Register("rax".into());
        dfg.mark_source(src.clone());
        dfg.mark_sink(snk.clone());
        dfg.add_edge(src, snk, PropagationOp::Assign, 0x10);
        let paths = dfg.find_source_sink_paths();
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_dfg_location_of() {
        let mut dfg = DataFlowGraph::new();
        let loc = TaintLocation::Memory(0xDEAD);
        let id = dfg.node_for(loc.clone());
        assert!(dfg.location_of(id).is_some());
    }

    // ── TaintedApiCall ────────────────────────────────────────────────────────

    #[test]
    fn test_api_call_combined_taint() {
        let mut call = TaintedApiCall::new("memcpy", 0x1000);
        call.add_arg(taint_bits::USER_INPUT);
        call.add_arg(taint_bits::NETWORK);
        let combined = call.combined_arg_taint();
        assert!(taint_bits::has_bit(combined, taint_bits::USER_INPUT));
        assert!(taint_bits::has_bit(combined, taint_bits::NETWORK));
    }

    #[test]
    fn test_api_call_has_tainted_args_true() {
        let mut call = TaintedApiCall::new("printf", 0x500);
        call.add_arg(taint_bits::COMMAND_LINE);
        assert!(call.has_tainted_args());
    }

    #[test]
    fn test_api_call_has_tainted_args_false() {
        let call = TaintedApiCall::new("strlen", 0x600);
        assert!(!call.has_tainted_args());
    }

    #[test]
    fn test_api_call_classify_dangerous() {
        let mut call = TaintedApiCall::new("system", 0x700);
        call.classify();
        assert!(call.is_dangerous);
    }

    #[test]
    fn test_api_call_classify_safe() {
        let mut call = TaintedApiCall::new("strlen", 0x800);
        call.classify();
        assert!(!call.is_dangerous);
    }

    // ── VulnerabilityReport ───────────────────────────────────────────────────

    #[test]
    fn test_vuln_report_from_finding() {
        let finding = cmd_finding();
        let report = VulnerabilityReport::from_finding(&finding, "VULN-001");
        assert_eq!(report.vulnerability_id, "VULN-001");
        assert!(!report.remediation.is_empty());
    }

    #[test]
    fn test_vuln_report_is_severe_critical() {
        let finding = cmd_finding();
        let report = VulnerabilityReport::from_finding(&finding, "VULN-002");
        assert!(report.is_severe());
    }

    #[test]
    fn test_vuln_report_add_path() {
        let finding = fmt_finding();
        let mut report = VulnerabilityReport::from_finding(&finding, "VULN-003");
        report.add_path(simple_path());
        assert_eq!(report.path_count(), 1);
    }

    #[test]
    fn test_vuln_report_source_categories() {
        let finding = cmd_finding();
        let mut report = VulnerabilityReport::from_finding(&finding, "VULN-004");
        let mut path = simple_path();
        path.source_type = TaintSource::NetworkSocket { port: 80 };
        report.add_path(path);
        let cats = report.source_categories();
        assert!(cats.contains(&"network"));
    }

    #[test]
    fn test_vuln_report_add_call() {
        let finding = fmt_finding();
        let mut report = VulnerabilityReport::from_finding(&finding, "VULN-005");
        let call = TaintedApiCall::new("printf", 0x300);
        report.add_call(call);
        assert_eq!(report.tainted_calls.len(), 1);
    }

    // ── TaintReportExtended ───────────────────────────────────────────────────

    #[test]
    fn test_extended_report_new() {
        let report = TaintReportExtended::new("test");
        assert_eq!(report.vulnerability_count(), 0);
        assert_eq!(report.severe_count(), 0);
    }

    #[test]
    fn test_extended_report_add_vulnerability() {
        let mut report = TaintReportExtended::new("analysis");
        let finding = cmd_finding();
        let vuln = VulnerabilityReport::from_finding(&finding, "V1");
        report.add_vulnerability(vuln);
        assert_eq!(report.vulnerability_count(), 1);
        assert_eq!(report.severe_count(), 1);
    }

    #[test]
    fn test_extended_report_max_severity() {
        let mut report = TaintReportExtended::new("analysis");
        let finding = cmd_finding();
        let vuln = VulnerabilityReport::from_finding(&finding, "V1");
        report.add_vulnerability(vuln);
        assert_eq!(report.max_severity(), Some(SeverityLevel::Critical));
    }

    #[test]
    fn test_extended_report_by_severity() {
        let mut report = TaintReportExtended::new("analysis");
        let v1 = VulnerabilityReport::from_finding(&cmd_finding(), "V1");
        let v2 = VulnerabilityReport::from_finding(&fmt_finding(), "V2");
        report.add_vulnerability(v1);
        report.add_vulnerability(v2);
        let criticals = report.by_severity(SeverityLevel::Critical);
        assert!(!criticals.is_empty());
    }

    #[test]
    fn test_extended_report_dangerous_calls() {
        let mut report = TaintReportExtended::new("analysis");
        let mut call = TaintedApiCall::new("system", 0x1000);
        call.is_dangerous = true;
        report.add_call(call);
        assert_eq!(report.dangerous_calls().len(), 1);
    }

    #[test]
    fn test_extended_report_sink_apis() {
        let mut report = TaintReportExtended::new("analysis");
        report.add_path(simple_path()); // sink_api = "system"
        let apis = report.sink_apis();
        assert!(apis.contains(&"system".to_string()));
    }

    #[test]
    fn test_extended_report_summary() {
        let mut report = TaintReportExtended::new("myanalysis");
        let vuln = VulnerabilityReport::from_finding(&cmd_finding(), "V1");
        report.add_vulnerability(vuln);
        report.add_path(simple_path());
        let s = report.summary();
        assert!(s.contains("myanalysis"));
        assert!(s.contains("1 vulns"));
    }

    #[test]
    fn test_extended_report_build_dfg_from_paths() {
        let mut report = TaintReportExtended::new("dfg_test");
        report.add_path(simple_path());
        report.build_dfg_from_paths();
        assert!(report.data_flow_graph.node_count() > 0);
    }

    #[test]
    fn test_extended_report_no_severe_when_empty() {
        let report = TaintReportExtended::new("empty");
        assert!(report.max_severity().is_none());
    }
}

// ── TaintFlowAnalyzer ──────────────────────────────────────────────────────────

/// Convenience analyzer that combines `TaintPath` collection, DFG construction,
/// and vulnerability-report generation.
pub struct TaintFlowAnalyzer {
    pub report: TaintReportExtended,
    next_vuln_id: u64,
}

impl TaintFlowAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            report: TaintReportExtended::new(name),
            next_vuln_id: 1,
        }
    }

    /// Record a complete taint flow from source to sink, generating a finding.
    pub fn record_flow(
        &mut self,
        source: TaintLocation,
        source_type: TaintSource,
        sink: TaintLocation,
        sink_api: impl Into<String>,
        vuln_type: FindingType,
        steps: Vec<TaintPathStep>,
    ) {
        let mut path = TaintPath::new(
            source.clone(),
            source_type.clone(),
            sink.clone(),
            sink_api,
            vuln_type.clone(),
        );
        for step in steps {
            path.add_step(step);
        }
        self.report.add_path(path.clone());

        // Generate a vulnerability report for the finding
        let finding = TaintFinding::new(
            vuln_type.clone(),
            0,
            source_type.to_taint_id(),
            "taint flow detected",
        );
        let id = format!("TAINT-{:04}", self.next_vuln_id);
        self.next_vuln_id += 1;
        let mut vuln = VulnerabilityReport::from_finding(&finding, id);
        vuln.add_path(path);
        self.report.add_vulnerability(vuln);
    }

    /// Finalize: build the data-flow graph from all recorded paths.
    pub fn finalize(&mut self) {
        self.report.build_dfg_from_paths();
    }

    /// Summary of the analysis.
    #[must_use]
    pub fn summary(&self) -> String {
        self.report.summary()
    }

    /// Most severe vulnerability found.
    #[must_use]
    pub fn most_severe(&self) -> Option<&VulnerabilityReport> {
        self.report
            .vulnerabilities
            .iter()
            .max_by_key(|v| v.severity)
    }
}

// ── FlowFilter ────────────────────────────────────────────────────────────────

/// Filters taint paths by various criteria.
pub struct FlowFilter;

impl FlowFilter {
    /// Return only paths where the source category matches.
    #[must_use]
    pub fn by_source_category<'a>(paths: &'a [TaintPath], category: &str) -> Vec<&'a TaintPath> {
        paths
            .iter()
            .filter(|p| p.source_type.category() == category)
            .collect()
    }

    /// Return only paths longer than `min_steps`.
    #[must_use]
    pub fn by_min_length(paths: &[TaintPath], min_steps: usize) -> Vec<&TaintPath> {
        paths.iter().filter(|p| p.length() >= min_steps).collect()
    }

    /// Return only paths that are not sanitized.
    #[must_use]
    pub fn unsanitized(paths: &[TaintPath]) -> Vec<&TaintPath> {
        paths.iter().filter(|p| !p.sanitized).collect()
    }

    /// Return paths reaching a specific sink API.
    #[must_use]
    pub fn to_sink<'a>(paths: &'a [TaintPath], api: &str) -> Vec<&'a TaintPath> {
        paths.iter().filter(|p| p.sink_api == api).collect()
    }

    /// Count paths grouped by vulnerability type.
    #[must_use]
    pub fn count_by_type(paths: &[TaintPath]) -> std::collections::HashMap<String, usize> {
        let mut counts = std::collections::HashMap::new();
        for path in paths {
            *counts.entry(path.vuln_type.to_string()).or_insert(0) += 1;
        }
        counts
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    

    fn user_input_path(sink_api: &str) -> TaintPath {
        TaintPath::new(
            TaintLocation::Register("rdi".into()),
            TaintSource::UserInput,
            TaintLocation::Register("rsi".into()),
            sink_api,
            FindingType::CommandInjection,
        )
    }

    fn network_path() -> TaintPath {
        TaintPath::new(
            TaintLocation::Memory(0x1000),
            TaintSource::NetworkSocket { port: 80 },
            TaintLocation::Register("rax".into()),
            "memcpy",
            FindingType::BufferOverflow,
        )
    }

    // ── TaintFlowAnalyzer ────────────────────────────────────────────────────

    #[test]
    fn test_analyzer_record_flow() {
        let mut analyzer = TaintFlowAnalyzer::new("test");
        analyzer.record_flow(
            TaintLocation::Register("rdi".into()),
            TaintSource::UserInput,
            TaintLocation::Register("rsi".into()),
            "system",
            FindingType::CommandInjection,
            vec![],
        );
        assert_eq!(analyzer.report.all_paths.len(), 1);
        assert_eq!(analyzer.report.vulnerability_count(), 1);
    }

    #[test]
    fn test_analyzer_finalize_builds_dfg() {
        let mut analyzer = TaintFlowAnalyzer::new("dfg_test");
        analyzer.record_flow(
            TaintLocation::Register("rdi".into()),
            TaintSource::UserInput,
            TaintLocation::Register("rsi".into()),
            "execve",
            FindingType::CommandInjection,
            vec![TaintPathStep::new(
                TaintLocation::Register("rdi".into()),
                TaintLocation::Register("rsi".into()),
                PropagationOp::Assign,
                0x100,
            )],
        );
        analyzer.finalize();
        assert!(analyzer.report.data_flow_graph.node_count() > 0);
    }

    #[test]
    fn test_analyzer_most_severe() {
        let mut analyzer = TaintFlowAnalyzer::new("sev_test");
        analyzer.record_flow(
            TaintLocation::Register("rdi".into()),
            TaintSource::UserInput,
            TaintLocation::Register("rsi".into()),
            "system",
            FindingType::CommandInjection,
            vec![],
        );
        let most_severe = analyzer.most_severe();
        assert!(most_severe.is_some());
    }

    #[test]
    fn test_analyzer_summary_contains_name() {
        let analyzer = TaintFlowAnalyzer::new("my_analysis");
        assert!(analyzer.summary().contains("my_analysis"));
    }

    // ── FlowFilter ───────────────────────────────────────────────────────────

    #[test]
    fn test_filter_by_source_category() {
        let paths = vec![user_input_path("system"), network_path()];
        let user_paths = FlowFilter::by_source_category(&paths, "user-input");
        assert_eq!(user_paths.len(), 1);
    }

    #[test]
    fn test_filter_to_sink() {
        let paths = vec![user_input_path("system"), network_path()];
        let system_paths = FlowFilter::to_sink(&paths, "system");
        assert_eq!(system_paths.len(), 1);
    }

    #[test]
    fn test_filter_by_min_length() {
        let mut p1 = user_input_path("system");
        p1.add_step(TaintPathStep::new(
            TaintLocation::Register("rdi".into()),
            TaintLocation::Register("rax".into()),
            PropagationOp::Assign,
            0x100,
        ));
        let p2 = network_path();
        let paths = vec![p1, p2];
        let long = FlowFilter::by_min_length(&paths, 1);
        assert_eq!(long.len(), 1);
    }

    #[test]
    fn test_filter_unsanitized() {
        let mut p1 = user_input_path("system");
        p1.sanitized = true;
        let p2 = network_path();
        let paths = vec![p1, p2];
        let unsan = FlowFilter::unsanitized(&paths);
        assert_eq!(unsan.len(), 1);
    }

    #[test]
    fn test_filter_count_by_type() {
        let paths = vec![user_input_path("system"), user_input_path("execve")];
        let counts = FlowFilter::count_by_type(&paths);
        assert_eq!(*counts.get("CommandInjection").unwrap(), 2);
    }
}
