//! TTP (Tactics, Techniques, and Procedures) analysis module.
//!
//! Provides `TtpAnalysis`, `TtpCluster`, `TtpGraph`, `TtpTimeline`,
//! `TtpReport`, and `MitreTtpMapping` for MITRE ATT&CK-centric threat analysis.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ── MitreTactic ───────────────────────────────────────────────────────────────

/// MITRE ATT&CK tactic (kill-chain phase).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MitreTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
    Other(String),
}

impl MitreTactic {
    /// Return the tactic identifier string.
    #[must_use]
    pub const fn id(&self) -> &str {
        match self {
            Self::Reconnaissance => "TA0043",
            Self::ResourceDevelopment => "TA0042",
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::CommandAndControl => "TA0011",
            Self::Exfiltration => "TA0010",
            Self::Impact => "TA0040",
            Self::Other(s) => s.as_str(),
        }
    }

    /// Return the human-readable tactic name.
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::ResourceDevelopment => "Resource Development",
            Self::InitialAccess => "Initial Access",
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::DefenseEvasion => "Defense Evasion",
            Self::CredentialAccess => "Credential Access",
            Self::Discovery => "Discovery",
            Self::LateralMovement => "Lateral Movement",
            Self::Collection => "Collection",
            Self::CommandAndControl => "Command and Control",
            Self::Exfiltration => "Exfiltration",
            Self::Impact => "Impact",
            Self::Other(s) => s.as_str(),
        }
    }

    /// Return the kill-chain phase ordinal (1-based, Recon=1 … Impact=14).
    #[must_use]
    pub const fn phase_ordinal(&self) -> u8 {
        match self {
            Self::Reconnaissance => 1,
            Self::ResourceDevelopment => 2,
            Self::InitialAccess => 3,
            Self::Execution => 4,
            Self::Persistence => 5,
            Self::PrivilegeEscalation => 6,
            Self::DefenseEvasion => 7,
            Self::CredentialAccess => 8,
            Self::Discovery => 9,
            Self::LateralMovement => 10,
            Self::Collection => 11,
            Self::CommandAndControl => 12,
            Self::Exfiltration => 13,
            Self::Impact => 14,
            Self::Other(_) => 99,
        }
    }
}

impl fmt::Display for MitreTactic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.id())
    }
}

// ── TtpEntry ──────────────────────────────────────────────────────────────────

/// A single ATT&CK technique observed in analysed data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpEntry {
    /// ATT&CK technique ID (e.g. `"T1055"`).
    pub technique_id: String,
    /// Sub-technique ID (e.g. `"T1055.001"`), if applicable.
    pub sub_technique_id: Option<String>,
    /// Human-readable technique name.
    pub name: String,
    /// Tactic this technique belongs to.
    pub tactic: MitreTactic,
    /// Description of how this technique was observed.
    pub description: String,
    /// Evidence sources (hashes, rule names, sandbox reports…).
    pub evidence: Vec<String>,
    /// Confidence in [0, 100].
    pub confidence: u8,
    /// MITRE ATT&CK platform(s) (e.g. `["Windows"]`).
    pub platforms: Vec<String>,
    /// Whether this technique has been confirmed in the wild.
    pub confirmed: bool,
    /// First observation timestamp.
    pub first_seen: Option<u64>,
}

impl TtpEntry {
    /// Create a minimal TTP entry.
    #[must_use]
    pub fn new(
        technique_id: impl Into<String>,
        name: impl Into<String>,
        tactic: MitreTactic,
    ) -> Self {
        Self {
            technique_id: technique_id.into(),
            sub_technique_id: None,
            name: name.into(),
            tactic,
            description: String::new(),
            evidence: Vec::new(),
            confidence: 50,
            platforms: vec!["Windows".into()],
            confirmed: false,
            first_seen: None,
        }
    }

    /// Return the effective ID (sub-technique if present, otherwise technique).
    #[must_use]
    pub fn effective_id(&self) -> &str {
        self.sub_technique_id
            .as_deref()
            .unwrap_or(&self.technique_id)
    }

    /// Add an evidence item.
    pub fn add_evidence(&mut self, evidence: impl Into<String>) {
        self.evidence.push(evidence.into());
    }

    /// Return `true` if confidence >= 70.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 70
    }
}

// ── TtpCluster ────────────────────────────────────────────────────────────────

/// A cluster of related TTPs sharing a common tactic or threat actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpCluster {
    /// Cluster identifier.
    pub id: String,
    /// Optional cluster label.
    pub label: Option<String>,
    /// TTPs belonging to this cluster.
    pub ttps: Vec<TtpEntry>,
    /// Dominant tactic in this cluster.
    pub dominant_tactic: Option<MitreTactic>,
    /// Threat actors associated with this cluster.
    pub threat_actors: Vec<String>,
    /// Malware families associated with this cluster.
    pub malware_families: Vec<String>,
    /// Cluster confidence score [0, 100].
    pub confidence: u8,
}

impl TtpCluster {
    /// Create a new, empty cluster.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: None,
            ttps: Vec::new(),
            dominant_tactic: None,
            threat_actors: Vec::new(),
            malware_families: Vec::new(),
            confidence: 50,
        }
    }

    /// Add a TTP to this cluster.
    pub fn add_ttp(&mut self, ttp: TtpEntry) {
        self.ttps.push(ttp);
        self.recalculate_dominant_tactic();
    }

    /// Recalculate the dominant tactic based on frequency.
    fn recalculate_dominant_tactic(&mut self) {
        let mut counts: HashMap<String, (u32, &MitreTactic)> = HashMap::new();
        for ttp in &self.ttps {
            let e = counts
                .entry(ttp.tactic.id().to_string())
                .or_insert((0, &ttp.tactic));
            e.0 += 1;
        }
        // We cannot store refs, so we need a different approach.
        let mut tactic_counts: HashMap<String, u32> = HashMap::new();
        for ttp in &self.ttps {
            *tactic_counts
                .entry(ttp.tactic.id().to_string())
                .or_insert(0) += 1;
        }
        if let Some((dominant_id, _)) = tactic_counts.iter().max_by_key(|&(_, &c)| c) {
            // Find the tactic entry.
            for ttp in &self.ttps {
                if ttp.tactic.id() == dominant_id.as_str() {
                    self.dominant_tactic = Some(ttp.tactic.clone());
                    break;
                }
            }
        }
    }

    /// Number of TTPs.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.ttps.len()
    }

    /// Return unique tactic IDs present in this cluster.
    #[must_use]
    pub fn tactic_ids(&self) -> Vec<String> {
        let mut set: HashSet<String> = HashSet::new();
        for ttp in &self.ttps {
            set.insert(ttp.tactic.id().to_string());
        }
        let mut v: Vec<_> = set.into_iter().collect();
        v.sort();
        v
    }

    /// Return the average confidence across all TTPs.
    #[must_use]
    pub fn avg_confidence(&self) -> f32 {
        if self.ttps.is_empty() {
            return 0.0;
        }
        let sum: f32 = self.ttps.iter().map(|t| f32::from(t.confidence)).sum();
        let n = f32::from(u16::try_from(self.ttps.len()).unwrap_or(u16::MAX));
        sum / n
    }
}

// ── TtpGraph ──────────────────────────────────────────────────────────────────

/// A directed graph of TTP relationships (co-occurrence, precedes, enables).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpEdge {
    /// Source technique ID.
    pub from: String,
    /// Target technique ID.
    pub to: String,
    /// Relationship type.
    pub relation: TtpRelation,
    /// Number of times this edge was observed.
    pub weight: u32,
}

/// Relationship types between two TTPs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TtpRelation {
    /// Both TTPs were observed together.
    CoOccurrence,
    /// Source TTP typically precedes target in kill chain.
    Precedes,
    /// Source TTP enables target TTP.
    Enables,
    /// Source and target are variants.
    Variant,
}

impl fmt::Display for TtpRelation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CoOccurrence => "co-occurrence",
            Self::Precedes => "precedes",
            Self::Enables => "enables",
            Self::Variant => "variant",
        };
        f.write_str(s)
    }
}

/// Directed TTP relationship graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TtpGraph {
    /// All known technique IDs.
    pub nodes: HashSet<String>,
    /// Directed edges.
    pub edges: Vec<TtpEdge>,
}

impl TtpGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node.
    pub fn add_node(&mut self, technique_id: impl Into<String>) {
        self.nodes.insert(technique_id.into());
    }

    /// Add or update an edge.
    pub fn add_edge(
        &mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        relation: TtpRelation,
    ) {
        let from = from.into();
        let to = to.into();
        self.nodes.insert(from.clone());
        self.nodes.insert(to.clone());
        if let Some(e) = self
            .edges
            .iter_mut()
            .find(|e| e.from == from && e.to == to && e.relation == relation)
        {
            e.weight += 1;
        } else {
            self.edges.push(TtpEdge {
                from,
                to,
                relation,
                weight: 1,
            });
        }
    }

    /// Return all outgoing neighbours of a technique.
    #[must_use]
    pub fn neighbours(&self, technique_id: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|e| e.from == technique_id)
            .map(|e| e.to.as_str())
            .collect()
    }

    /// Return all predecessors of a technique.
    #[must_use]
    pub fn predecessors(&self, technique_id: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|e| e.to == technique_id)
            .map(|e| e.from.as_str())
            .collect()
    }

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Return the most strongly co-occurring technique pair.
    #[must_use]
    pub fn strongest_pair(&self) -> Option<(&str, &str, u32)> {
        self.edges
            .iter()
            .filter(|e| e.relation == TtpRelation::CoOccurrence)
            .max_by_key(|e| e.weight)
            .map(|e| (e.from.as_str(), e.to.as_str(), e.weight))
    }
}

// ── TtpTimeline ───────────────────────────────────────────────────────────────

/// A time-ordered sequence of observed TTPs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpTimelineEntry {
    /// Unix timestamp.
    pub timestamp: u64,
    /// Technique ID observed.
    pub technique_id: String,
    /// Associated evidence.
    pub evidence: String,
    /// Confidence.
    pub confidence: u8,
}

/// Kill-chain timeline built from observed TTP events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TtpTimeline {
    /// Indicator this timeline belongs to (hash, campaign, etc.).
    pub subject: String,
    /// Ordered entries (sorted by timestamp ascending).
    pub entries: Vec<TtpTimelineEntry>,
}

impl TtpTimeline {
    /// Create a new timeline.
    #[must_use]
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            entries: Vec::new(),
        }
    }

    /// Add a timeline event.
    pub fn add_event(
        &mut self,
        timestamp: u64,
        technique_id: impl Into<String>,
        evidence: impl Into<String>,
        confidence: u8,
    ) {
        self.entries.push(TtpTimelineEntry {
            timestamp,
            technique_id: technique_id.into(),
            evidence: evidence.into(),
            confidence,
        });
        self.entries.sort_by_key(|e| e.timestamp);
    }

    /// Return the earliest event.
    #[must_use]
    pub fn first_event(&self) -> Option<&TtpTimelineEntry> {
        self.entries.first()
    }

    /// Return the latest event.
    #[must_use]
    pub fn last_event(&self) -> Option<&TtpTimelineEntry> {
        self.entries.last()
    }

    /// Duration of the timeline in seconds.
    #[must_use]
    pub fn duration_secs(&self) -> Option<u64> {
        let first = self.first_event()?.timestamp;
        let last = self.last_event()?.timestamp;
        Some(last.saturating_sub(first))
    }

    /// Return all events within a time window.
    #[must_use]
    pub fn window(&self, from: u64, to: u64) -> Vec<&TtpTimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp >= from && e.timestamp <= to)
            .collect()
    }

    /// Number of events.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the timeline is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all unique technique IDs observed in this timeline.
    #[must_use]
    pub fn unique_techniques(&self) -> Vec<String> {
        let mut set: HashSet<String> = HashSet::new();
        for e in &self.entries {
            set.insert(e.technique_id.clone());
        }
        let mut v: Vec<_> = set.into_iter().collect();
        v.sort();
        v
    }
}

// ── TtpReport ─────────────────────────────────────────────────────────────────

/// A structured TTP analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpReport {
    /// Report title.
    pub title: String,
    /// Report author.
    pub author: String,
    /// Summary.
    pub summary: String,
    /// Identified TTPs.
    pub ttps: Vec<TtpEntry>,
    /// TTP clusters.
    pub clusters: Vec<TtpCluster>,
    /// Kill-chain timeline.
    pub timeline: TtpTimeline,
    /// Tactic coverage (which phases are covered).
    pub covered_tactics: Vec<MitreTactic>,
    /// Report creation timestamp.
    pub created_at: u64,
    /// Risk level (0 = none, 10 = critical).
    pub risk_level: u8,
    /// Recommended mitigations.
    pub mitigations: Vec<String>,
}

impl TtpReport {
    /// Create a new, empty report.
    #[must_use]
    pub fn new(title: impl Into<String>, author: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            title: title.into(),
            author: author.into(),
            summary: String::new(),
            ttps: Vec::new(),
            clusters: Vec::new(),
            timeline: TtpTimeline::new("report"),
            covered_tactics: Vec::new(),
            created_at: now,
            risk_level: 0,
            mitigations: Vec::new(),
        }
    }

    /// Add a TTP to the report and update covered tactics.
    pub fn add_ttp(&mut self, ttp: TtpEntry) {
        let tactic = ttp.tactic.clone();
        self.ttps.push(ttp);
        if !self.covered_tactics.contains(&tactic) {
            self.covered_tactics.push(tactic);
        }
        self.recalculate_risk();
    }

    /// Add a cluster to the report.
    pub fn add_cluster(&mut self, cluster: TtpCluster) {
        self.clusters.push(cluster);
    }

    /// Recalculate risk level based on TTPs.
    fn recalculate_risk(&mut self) {
        let tactic_count = f64::from(u32::try_from(self.covered_tactics.len()).unwrap_or(u32::MAX));
        let avg_confidence: f64 = if self.ttps.is_empty() {
            0.0
        } else {
            let n = f64::from(u32::try_from(self.ttps.len()).unwrap_or(u32::MAX));
            self.ttps.iter().map(|t| f64::from(t.confidence)).sum::<f64>() / n
        };
        // Risk = tactics * 0.3 + confidence * 0.07 capped at 10.
        self.risk_level = (tactic_count.mul_add(0.3, avg_confidence * 0.07).min(255.0) as u8).min(10);
    }

    /// Add a mitigation recommendation.
    pub fn add_mitigation(&mut self, mitigation: impl Into<String>) {
        self.mitigations.push(mitigation.into());
    }

    /// Return the number of TTPs.
    #[must_use]
    pub const fn ttp_count(&self) -> usize {
        self.ttps.len()
    }

    /// Return all high-confidence TTPs.
    #[must_use]
    pub fn high_confidence_ttps(&self) -> Vec<&TtpEntry> {
        self.ttps
            .iter()
            .filter(|t| t.is_high_confidence())
            .collect()
    }

    /// Return a tactic coverage percentage.
    #[must_use]
    pub fn tactic_coverage_pct(&self) -> f32 {
        const TOTAL_TACTICS: f32 = 14.0;
        f32::from(u8::try_from(self.covered_tactics.len()).unwrap_or(u8::MAX)) / TOTAL_TACTICS * 100.0
    }
}

// ── MitreTtpMapping ───────────────────────────────────────────────────────────

/// Static API → ATT&CK technique mapping entries: (api, technique_id, name, tactic).
const API_TECHNIQUE_ENTRIES: &[(&str, &str, &str, MitreTactic)] = &[
    ("CreateRemoteThread", "T1055", "Process Injection", MitreTactic::DefenseEvasion),
    ("WriteProcessMemory", "T1055", "Process Injection", MitreTactic::DefenseEvasion),
    ("VirtualAllocEx", "T1055", "Process Injection", MitreTactic::DefenseEvasion),
    ("VirtualProtect", "T1055", "Process Injection", MitreTactic::DefenseEvasion),
    ("RegSetValueEx", "T1547.001", "Registry Run Keys", MitreTactic::Persistence),
    ("CreateService", "T1543.003", "Windows Service", MitreTactic::Persistence),
    ("URLDownloadToFile", "T1105", "Ingress Tool Transfer", MitreTactic::CommandAndControl),
    ("CryptEncrypt", "T1486", "Data Encrypted for Impact", MitreTactic::Impact),
    ("SetWindowsHookEx", "T1056.001", "Keylogging", MitreTactic::Collection),
    ("GetAsyncKeyState", "T1056.001", "Keylogging", MitreTactic::Collection),
    ("IsDebuggerPresent", "T1622", "Debugger Evasion", MitreTactic::DefenseEvasion),
    ("EnumProcesses", "T1057", "Process Discovery", MitreTactic::Discovery),
    ("GetSystemInfo", "T1082", "System Information Discovery", MitreTactic::Discovery),
    ("WinHttpSendRequest", "T1071.001", "Web Protocols", MitreTactic::CommandAndControl),
    ("OpenProcess", "T1003", "OS Credential Dumping", MitreTactic::CredentialAccess),
    ("ReadProcessMemory", "T1003", "OS Credential Dumping", MitreTactic::CredentialAccess),
    ("BitBlt", "T1113", "Screen Capture", MitreTactic::Collection),
    ("ImpersonateLoggedOnUser", "T1134.001", "Token Impersonation", MitreTactic::PrivilegeEscalation),
    ("WNetAddConnection", "T1021", "Remote Services", MitreTactic::LateralMovement),
    ("FtpPutFile", "T1048", "Exfiltration Over Alternative Protocol", MitreTactic::Exfiltration),
];

/// Maps Windows API names, behaviours, and signatures to ATT&CK techniques.
pub struct MitreTtpMapping;

impl MitreTtpMapping {
    /// Map a list of API names to ATT&CK `TtpEntry` items.
    #[must_use]
    pub fn from_apis(api_names: &[&str]) -> Vec<TtpEntry> {
        let db = Self::api_database();
        let mut result: Vec<TtpEntry> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        for api in api_names {
            if let Some(entries) = db.get(*api) {
                for (tid, name, tactic) in entries {
                    if seen.insert(tid.to_string()) {
                        let mut ttp = TtpEntry::new(*tid, *name, tactic.clone());
                        ttp.add_evidence(format!("API: {api}"));
                        ttp.confidence = 75;
                        result.push(ttp);
                    }
                }
            }
        }
        result
    }

    /// Return techniques associated with a specific behaviour keyword.
    #[must_use]
    pub fn from_behaviour(keyword: &str) -> Vec<TtpEntry> {
        let lower = keyword.to_ascii_lowercase();
        let mut result = Vec::new();
        let behaviours: &[(&str, &str, &str, MitreTactic)] = &[
            (
                "inject",
                "T1055",
                "Process Injection",
                MitreTactic::DefenseEvasion,
            ),
            (
                "persist",
                "T1547",
                "Boot/Logon Autostart Execution",
                MitreTactic::Persistence,
            ),
            (
                "download",
                "T1105",
                "Ingress Tool Transfer",
                MitreTactic::CommandAndControl,
            ),
            (
                "encrypt",
                "T1486",
                "Data Encrypted for Impact",
                MitreTactic::Impact,
            ),
            ("keylog", "T1056", "Input Capture", MitreTactic::Collection),
            (
                "screenshot",
                "T1113",
                "Screen Capture",
                MitreTactic::Collection,
            ),
            (
                "escalat",
                "T1134",
                "Access Token Manipulation",
                MitreTactic::PrivilegeEscalation,
            ),
            (
                "lateral",
                "T1021",
                "Remote Services",
                MitreTactic::LateralMovement,
            ),
            (
                "exfil",
                "T1048",
                "Exfiltration Over Alternative Protocol",
                MitreTactic::Exfiltration,
            ),
            (
                "c2",
                "T1071",
                "Application Layer Protocol",
                MitreTactic::CommandAndControl,
            ),
            (
                "hollow",
                "T1055.012",
                "Process Hollowing",
                MitreTactic::DefenseEvasion,
            ),
            (
                "shellcode",
                "T1055.001",
                "Dynamic-link Library Injection",
                MitreTactic::DefenseEvasion,
            ),
        ];
        for (kw, tid, name, tactic) in behaviours {
            if lower.contains(kw) {
                let mut ttp = TtpEntry::new(*tid, *name, tactic.clone());
                ttp.add_evidence(format!("Behaviour: {keyword}"));
                ttp.confidence = 60;
                result.push(ttp);
            }
        }
        result
    }

    /// Internal API-to-technique database built from [`API_TECHNIQUE_ENTRIES`].
    fn api_database() -> HashMap<&'static str, Vec<(&'static str, &'static str, MitreTactic)>> {
        let mut map: HashMap<&'static str, Vec<(&'static str, &'static str, MitreTactic)>> =
            HashMap::new();
        for (api, tid, name, tactic) in API_TECHNIQUE_ENTRIES {
            map.entry(api)
                .or_default()
                .push((tid, name, tactic.clone()));
        }
        map
    }

    /// Build a TTP graph from a list of TTP entries based on kill-chain order.
    #[must_use]
    pub fn build_graph(ttps: &[TtpEntry]) -> TtpGraph {
        let mut graph = TtpGraph::new();
        for ttp in ttps {
            graph.add_node(ttp.effective_id());
        }
        // Connect techniques whose tactics are adjacent in kill-chain order.
        for i in 0..ttps.len() {
            for j in 0..ttps.len() {
                if i == j {
                    continue;
                }
                let a = &ttps[i];
                let b = &ttps[j];
                if a.tactic.phase_ordinal() + 1 == b.tactic.phase_ordinal() {
                    graph.add_edge(a.effective_id(), b.effective_id(), TtpRelation::Precedes);
                } else if a.technique_id == b.technique_id
                    && a.sub_technique_id != b.sub_technique_id
                {
                    graph.add_edge(a.effective_id(), b.effective_id(), TtpRelation::Variant);
                }
            }
        }
        graph
    }
}

// ── TtpAnalysis ───────────────────────────────────────────────────────────────

/// High-level TTP analysis session that accumulates observations and produces
/// clusters, timelines, graphs, and reports.
#[derive(Debug, Default)]
pub struct TtpAnalysis {
    /// All accumulated TTP entries.
    entries: Vec<TtpEntry>,
    /// Generated clusters.
    clusters: Vec<TtpCluster>,
    /// Generated graph.
    graph: TtpGraph,
    /// Timeline for the current session.
    timeline: TtpTimeline,
    /// Subject of this analysis session.
    pub subject: String,
}

impl TtpAnalysis {
    /// Create a new analysis session.
    #[must_use]
    pub fn new(subject: impl Into<String>) -> Self {
        let subject = subject.into();
        Self {
            entries: Vec::new(),
            clusters: Vec::new(),
            graph: TtpGraph::new(),
            timeline: TtpTimeline::new(&subject),
            subject,
        }
    }

    /// Add a TTP entry from direct observation.
    pub fn add_entry(&mut self, entry: TtpEntry) {
        self.graph.add_node(entry.effective_id());
        self.entries.push(entry);
    }

    /// Add TTPs derived from API names.
    pub fn add_from_apis(&mut self, api_names: &[&str]) {
        for ttp in MitreTtpMapping::from_apis(api_names) {
            self.add_entry(ttp);
        }
    }

    /// Add TTPs derived from behaviour keywords.
    pub fn add_from_behaviour(&mut self, keyword: &str) {
        for ttp in MitreTtpMapping::from_behaviour(keyword) {
            self.add_entry(ttp);
        }
    }

    /// Record a timeline event.
    pub fn record_event(
        &mut self,
        timestamp: u64,
        technique_id: &str,
        evidence: &str,
        confidence: u8,
    ) {
        self.timeline
            .add_event(timestamp, technique_id, evidence, confidence);
    }

    /// Cluster TTPs by tactic.
    pub fn cluster_by_tactic(&mut self) {
        let mut by_tactic: HashMap<String, Vec<TtpEntry>> = HashMap::new();
        for ttp in &self.entries {
            by_tactic
                .entry(ttp.tactic.id().to_string())
                .or_default()
                .push(ttp.clone());
        }
        self.clusters.clear();
        for (tactic_id, ttps) in by_tactic {
            let mut cluster = TtpCluster::new(&tactic_id);
            for ttp in ttps {
                cluster.add_ttp(ttp);
            }
            self.clusters.push(cluster);
        }
    }

    /// Build the internal TTP graph.
    pub fn build_graph(&mut self) {
        self.graph = MitreTtpMapping::build_graph(&self.entries);
    }

    /// Generate a TTP report.
    #[must_use]
    pub fn generate_report(&self, title: &str, author: &str) -> TtpReport {
        let mut report = TtpReport::new(title, author);
        for ttp in &self.entries {
            report.add_ttp(ttp.clone());
        }
        for cluster in &self.clusters {
            report.add_cluster(cluster.clone());
        }
        report.timeline = self.timeline.clone();
        report
    }

    /// Return the number of unique technique IDs.
    #[must_use]
    pub fn unique_technique_count(&self) -> usize {
        let set: HashSet<_> = self
            .entries
            .iter()
            .map(|e| e.technique_id.as_str())
            .collect();
        set.len()
    }

    /// Return all covered tactics.
    #[must_use]
    pub fn covered_tactics(&self) -> Vec<&MitreTactic> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut result = Vec::new();
        for ttp in &self.entries {
            if seen.insert(ttp.tactic.id().to_string()) {
                result.push(&ttp.tactic);
            }
        }
        result
    }

    /// Return the graph reference.
    #[must_use]
    pub const fn graph(&self) -> &TtpGraph {
        &self.graph
    }

    /// Return the timeline reference.
    #[must_use]
    pub const fn timeline(&self) -> &TtpTimeline {
        &self.timeline
    }

    /// Return all entries.
    #[must_use]
    pub fn entries(&self) -> &[TtpEntry] {
        &self.entries
    }

    /// Return all clusters.
    #[must_use]
    pub fn clusters(&self) -> &[TtpCluster] {
        &self.clusters
    }
}

// ── TtpHeatmap ────────────────────────────────────────────────────────────────

/// A heat-map showing the frequency of each ATT&CK tactic across a set of TTPs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TtpHeatmap {
    /// Tactic ID → occurrence count.
    pub cells: HashMap<String, u32>,
    /// Total TTP entries analysed.
    pub total: u32,
}

impl TtpHeatmap {
    /// Build a heat-map from a slice of TTP entries.
    #[must_use]
    pub fn from_entries(entries: &[TtpEntry]) -> Self {
        let mut cells: HashMap<String, u32> = HashMap::new();
        for e in entries {
            *cells.entry(e.tactic.id().to_string()).or_insert(0) += 1;
        }
        Self {
            total: u32::try_from(entries.len()).unwrap_or(u32::MAX),
            cells,
        }
    }

    /// Return the most common tactic ID.
    #[must_use]
    pub fn hottest_tactic(&self) -> Option<&str> {
        self.cells
            .iter()
            .max_by_key(|&(_, &c)| c)
            .map(|(k, _)| k.as_str())
    }

    /// Return the count for a tactic ID.
    #[must_use]
    pub fn count(&self, tactic_id: &str) -> u32 {
        self.cells.get(tactic_id).copied().unwrap_or(0)
    }

    /// Normalised frequency for a tactic [0.0, 1.0].
    #[must_use]
    pub fn frequency(&self, tactic_id: &str) -> f32 {
        if self.total == 0 {
            return 0.0;
        }
        (f64::from(self.count(tactic_id)) / f64::from(self.total)) as f32
    }

    /// Number of distinct tactics represented.
    #[must_use]
    pub fn distinct_tactics(&self) -> usize {
        self.cells.len()
    }
}

// ── TtpComparisonResult ───────────────────────────────────────────────────────

/// Result of comparing two sets of TTPs for overlap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpComparisonResult {
    /// TTPs in set A only.
    pub only_in_a: Vec<String>,
    /// TTPs in set B only.
    pub only_in_b: Vec<String>,
    /// TTPs in both sets.
    pub shared: Vec<String>,
    /// Jaccard similarity [0.0, 1.0].
    pub similarity: f32,
}

impl TtpComparisonResult {
    /// Compare two slices of `TtpEntry` items.
    #[must_use]
    pub fn compare(a: &[TtpEntry], b: &[TtpEntry]) -> Self {
        let ids_a: HashSet<String> = a.iter().map(|e| e.technique_id.clone()).collect();
        let ids_b: HashSet<String> = b.iter().map(|e| e.technique_id.clone()).collect();
        let shared: Vec<String> = ids_a.intersection(&ids_b).cloned().collect();
        let only_in_a: Vec<String> = ids_a.difference(&ids_b).cloned().collect();
        let only_in_b: Vec<String> = ids_b.difference(&ids_a).cloned().collect();
        let union_size = ids_a.union(&ids_b).count();
        let similarity = if union_size == 0 {
            1.0
        } else {
            (f64::from(u32::try_from(shared.len()).unwrap_or(u32::MAX)) / f64::from(u32::try_from(union_size).unwrap_or(u32::MAX))) as f32
        };
        Self {
            only_in_a,
            only_in_b,
            shared,
            similarity,
        }
    }

    /// Return `true` if there is any overlap.
    #[must_use]
    pub const fn has_overlap(&self) -> bool {
        !self.shared.is_empty()
    }
}

// ── TtpSeverityScorer ─────────────────────────────────────────────────────────

/// Computes a severity score for a set of TTPs.
pub struct TtpSeverityScorer {
    /// Base score per TTP.
    pub base_score: f32,
    /// Bonus for high-confidence TTPs.
    pub confidence_bonus: f32,
    /// Bonus per tactic phase covered.
    pub tactic_bonus: f32,
    /// Maximum possible score.
    pub max_score: f32,
}

impl Default for TtpSeverityScorer {
    fn default() -> Self {
        Self {
            base_score: 1.0,
            confidence_bonus: 0.5,
            tactic_bonus: 2.0,
            max_score: 100.0,
        }
    }
}

impl TtpSeverityScorer {
    /// Compute a severity score for a set of TTPs.
    #[must_use]
    pub fn score(&self, ttps: &[TtpEntry]) -> f32 {
        let n = f32::from(u16::try_from(ttps.len()).unwrap_or(u16::MAX));
        let base: f32 = n * self.base_score;
        let hc = f32::from(u16::try_from(ttps.iter().filter(|t| t.is_high_confidence()).count()).unwrap_or(u16::MAX));
        let confidence_bonus: f32 = hc * self.confidence_bonus;
        let tactic_set: HashSet<String> = ttps.iter().map(|t| t.tactic.id().to_string()).collect();
        let tc = f32::from(u8::try_from(tactic_set.len()).unwrap_or(u8::MAX));
        let tactic_bonus = tc * self.tactic_bonus;
        (base + confidence_bonus + tactic_bonus).min(self.max_score)
    }

    /// Classify a score as low/medium/high/critical.
    #[must_use]
    pub fn classify(score: f32) -> &'static str {
        if score >= 75.0 {
            "critical"
        } else if score >= 50.0 {
            "high"
        } else if score >= 25.0 {
            "medium"
        } else {
            "low"
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ttp(tid: &str, tactic: MitreTactic) -> TtpEntry {
        TtpEntry::new(tid, "Sample Technique", tactic)
    }

    // ── MitreTactic ──────────────────────────────────────────────────────────

    #[test]
    fn test_tactic_id() {
        assert_eq!(MitreTactic::Persistence.id(), "TA0003");
        assert_eq!(MitreTactic::Impact.id(), "TA0040");
    }

    #[test]
    fn test_tactic_name() {
        assert_eq!(MitreTactic::Execution.name(), "Execution");
        assert_eq!(MitreTactic::DefenseEvasion.name(), "Defense Evasion");
    }

    #[test]
    fn test_tactic_phase_ordinal() {
        assert!(MitreTactic::Impact.phase_ordinal() > MitreTactic::Reconnaissance.phase_ordinal());
        assert_eq!(MitreTactic::Reconnaissance.phase_ordinal(), 1);
    }

    #[test]
    fn test_tactic_display() {
        let s = format!("{}", MitreTactic::Execution);
        assert!(s.contains("Execution") && s.contains("TA0002"));
    }

    // ── TtpEntry ─────────────────────────────────────────────────────────────

    #[test]
    fn test_ttp_entry_effective_id_no_sub() {
        let t = sample_ttp("T1055", MitreTactic::DefenseEvasion);
        assert_eq!(t.effective_id(), "T1055");
    }

    #[test]
    fn test_ttp_entry_effective_id_with_sub() {
        let mut t = sample_ttp("T1055", MitreTactic::DefenseEvasion);
        t.sub_technique_id = Some("T1055.001".into());
        assert_eq!(t.effective_id(), "T1055.001");
    }

    #[test]
    fn test_ttp_entry_high_confidence() {
        let mut t = sample_ttp("T1055", MitreTactic::DefenseEvasion);
        t.confidence = 80;
        assert!(t.is_high_confidence());
    }

    #[test]
    fn test_ttp_entry_low_confidence() {
        let mut t = sample_ttp("T1055", MitreTactic::DefenseEvasion);
        t.confidence = 50;
        assert!(!t.is_high_confidence());
    }

    #[test]
    fn test_ttp_entry_add_evidence() {
        let mut t = sample_ttp("T1055", MitreTactic::DefenseEvasion);
        t.add_evidence("CreateRemoteThread");
        assert_eq!(t.evidence.len(), 1);
    }

    // ── TtpCluster ───────────────────────────────────────────────────────────

    #[test]
    fn test_cluster_add_ttp() {
        let mut c = TtpCluster::new("cluster-1");
        c.add_ttp(sample_ttp("T1055", MitreTactic::DefenseEvasion));
        assert_eq!(c.size(), 1);
    }

    #[test]
    fn test_cluster_dominant_tactic() {
        let mut c = TtpCluster::new("c");
        c.add_ttp(sample_ttp("T1055", MitreTactic::DefenseEvasion));
        c.add_ttp(sample_ttp("T1059", MitreTactic::DefenseEvasion));
        c.add_ttp(sample_ttp("T1547", MitreTactic::Persistence));
        assert!(c.dominant_tactic.is_some());
    }

    #[test]
    fn test_cluster_tactic_ids() {
        let mut c = TtpCluster::new("c");
        c.add_ttp(sample_ttp("T1055", MitreTactic::DefenseEvasion));
        c.add_ttp(sample_ttp("T1547", MitreTactic::Persistence));
        let ids = c.tactic_ids();
        assert!(ids.len() == 2);
    }

    #[test]
    fn test_cluster_avg_confidence() {
        let mut c = TtpCluster::new("c");
        let mut t1 = sample_ttp("T1055", MitreTactic::DefenseEvasion);
        t1.confidence = 80;
        let mut t2 = sample_ttp("T1059", MitreTactic::Execution);
        t2.confidence = 60;
        c.add_ttp(t1);
        c.add_ttp(t2);
        assert!((c.avg_confidence() - 70.0).abs() < f32::EPSILON);
    }

    // ── TtpGraph ─────────────────────────────────────────────────────────────

    #[test]
    fn test_graph_add_node() {
        let mut g = TtpGraph::new();
        g.add_node("T1055");
        assert_eq!(g.node_count(), 1);
    }

    #[test]
    fn test_graph_add_edge() {
        let mut g = TtpGraph::new();
        g.add_edge("T1055", "T1059", TtpRelation::CoOccurrence);
        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.node_count(), 2);
    }

    #[test]
    fn test_graph_edge_weight_increment() {
        let mut g = TtpGraph::new();
        g.add_edge("T1055", "T1059", TtpRelation::CoOccurrence);
        g.add_edge("T1055", "T1059", TtpRelation::CoOccurrence);
        assert_eq!(g.edges[0].weight, 2);
    }

    #[test]
    fn test_graph_neighbours() {
        let mut g = TtpGraph::new();
        g.add_edge("T1055", "T1059", TtpRelation::Precedes);
        let n = g.neighbours("T1055");
        assert!(n.contains(&"T1059"));
    }

    #[test]
    fn test_graph_predecessors() {
        let mut g = TtpGraph::new();
        g.add_edge("T1043", "T1055", TtpRelation::Enables);
        let p = g.predecessors("T1055");
        assert!(p.contains(&"T1043"));
    }

    // ── TtpTimeline ──────────────────────────────────────────────────────────

    #[test]
    fn test_timeline_add_and_len() {
        let mut t = TtpTimeline::new("sample");
        t.add_event(1000, "T1055", "process injection", 80);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_timeline_sorted() {
        let mut t = TtpTimeline::new("s");
        t.add_event(3000, "T1059", "e", 70);
        t.add_event(1000, "T1055", "e", 80);
        assert_eq!(t.entries[0].timestamp, 1000);
    }

    #[test]
    fn test_timeline_duration() {
        let mut t = TtpTimeline::new("s");
        t.add_event(1000, "T1055", "e", 80);
        t.add_event(5000, "T1059", "e", 70);
        assert_eq!(t.duration_secs(), Some(4000));
    }

    #[test]
    fn test_timeline_window() {
        let mut t = TtpTimeline::new("s");
        for i in 0u64..10 {
            t.add_event(i * 1000, "T1055", "e", 70);
        }
        assert_eq!(t.window(2000, 5000).len(), 4);
    }

    #[test]
    fn test_timeline_unique_techniques() {
        let mut t = TtpTimeline::new("s");
        t.add_event(1, "T1055", "e", 70);
        t.add_event(2, "T1055", "e", 70);
        t.add_event(3, "T1059", "e", 70);
        assert_eq!(t.unique_techniques().len(), 2);
    }

    // ── TtpReport ────────────────────────────────────────────────────────────

    #[test]
    fn test_report_add_ttp() {
        let mut r = TtpReport::new("Test Report", "analyst");
        r.add_ttp(sample_ttp("T1055", MitreTactic::DefenseEvasion));
        assert_eq!(r.ttp_count(), 1);
    }

    #[test]
    fn test_report_covered_tactics() {
        let mut r = TtpReport::new("R", "a");
        r.add_ttp(sample_ttp("T1055", MitreTactic::DefenseEvasion));
        r.add_ttp(sample_ttp("T1059", MitreTactic::Execution));
        assert_eq!(r.covered_tactics.len(), 2);
    }

    #[test]
    fn test_report_high_confidence_ttps() {
        let mut r = TtpReport::new("R", "a");
        let mut t = sample_ttp("T1055", MitreTactic::DefenseEvasion);
        t.confidence = 80;
        r.add_ttp(t);
        assert_eq!(r.high_confidence_ttps().len(), 1);
    }

    #[test]
    fn test_report_risk_level_increases() {
        let mut r = TtpReport::new("R", "a");
        assert_eq!(r.risk_level, 0);
        for i in 0..5u8 {
            let tactic = match i {
                0 => MitreTactic::Persistence,
                1 => MitreTactic::DefenseEvasion,
                2 => MitreTactic::Execution,
                3 => MitreTactic::Collection,
                _ => MitreTactic::Impact,
            };
            r.add_ttp(sample_ttp("T1055", tactic));
        }
        assert!(r.risk_level > 0);
    }

    // ── MitreTtpMapping ──────────────────────────────────────────────────────

    #[test]
    fn test_mapping_from_apis() {
        let ttps = MitreTtpMapping::from_apis(&["CreateRemoteThread", "WriteProcessMemory"]);
        assert!(!ttps.is_empty());
    }

    #[test]
    fn test_mapping_from_behaviour_inject() {
        let ttps = MitreTtpMapping::from_behaviour("process_inject");
        assert!(ttps.iter().any(|t| t.technique_id.starts_with("T1055")));
    }

    #[test]
    fn test_mapping_from_behaviour_encrypt() {
        let ttps = MitreTtpMapping::from_behaviour("encrypt_files");
        assert!(ttps.iter().any(|t| t.technique_id == "T1486"));
    }

    #[test]
    fn test_mapping_build_graph() {
        let ttps = MitreTtpMapping::from_apis(&["CreateRemoteThread", "RegSetValueEx"]);
        let graph = MitreTtpMapping::build_graph(&ttps);
        assert!(graph.node_count() > 0);
    }

    // ── TtpAnalysis ──────────────────────────────────────────────────────────

    #[test]
    fn test_analysis_add_from_apis() {
        let mut a = TtpAnalysis::new("malware.exe");
        a.add_from_apis(&["CreateRemoteThread"]);
        assert!(!a.entries().is_empty());
    }

    #[test]
    fn test_analysis_add_from_behaviour() {
        let mut a = TtpAnalysis::new("sample");
        a.add_from_behaviour("inject");
        assert!(!a.entries().is_empty());
    }

    #[test]
    fn test_analysis_cluster_by_tactic() {
        let mut a = TtpAnalysis::new("s");
        a.add_entry(sample_ttp("T1055", MitreTactic::DefenseEvasion));
        a.add_entry(sample_ttp("T1059", MitreTactic::Execution));
        a.cluster_by_tactic();
        assert_eq!(a.clusters().len(), 2);
    }

    #[test]
    fn test_analysis_generate_report() {
        let mut a = TtpAnalysis::new("sample");
        a.add_from_apis(&["SetWindowsHookEx", "GetAsyncKeyState"]);
        let report = a.generate_report("Keylogger Report", "analyst");
        assert!(!report.ttps.is_empty());
    }

    #[test]
    fn test_analysis_unique_technique_count() {
        let mut a = TtpAnalysis::new("s");
        a.add_entry(sample_ttp("T1055", MitreTactic::DefenseEvasion));
        a.add_entry(sample_ttp("T1055", MitreTactic::DefenseEvasion));
        assert_eq!(a.unique_technique_count(), 1);
    }

    #[test]
    fn test_analysis_covered_tactics() {
        let mut a = TtpAnalysis::new("s");
        a.add_entry(sample_ttp("T1055", MitreTactic::DefenseEvasion));
        a.add_entry(sample_ttp("T1059", MitreTactic::Execution));
        assert_eq!(a.covered_tactics().len(), 2);
    }

    #[test]
    fn test_analysis_timeline() {
        let mut a = TtpAnalysis::new("s");
        a.record_event(1000, "T1055", "process injection", 80);
        assert_eq!(a.timeline().len(), 1);
    }

    #[test]
    fn test_analysis_build_graph() {
        let mut a = TtpAnalysis::new("s");
        a.add_entry(sample_ttp("T1055", MitreTactic::DefenseEvasion));
        a.build_graph();
        assert!(a.graph().node_count() > 0);
    }

    // ── TtpHeatmap ───────────────────────────────────────────────────────────

    #[test]
    fn test_heatmap_from_entries() {
        let ttps = vec![
            sample_ttp("T1055", MitreTactic::DefenseEvasion),
            sample_ttp("T1059", MitreTactic::DefenseEvasion),
            sample_ttp("T1547", MitreTactic::Persistence),
        ];
        let hm = TtpHeatmap::from_entries(&ttps);
        assert_eq!(hm.total, 3);
        assert_eq!(hm.count("TA0005"), 2); // DefenseEvasion = TA0005
    }

    #[test]
    fn test_heatmap_hottest_tactic() {
        let ttps = vec![
            sample_ttp("T1055", MitreTactic::DefenseEvasion),
            sample_ttp("T1059", MitreTactic::DefenseEvasion),
            sample_ttp("T1547", MitreTactic::Persistence),
        ];
        let hm = TtpHeatmap::from_entries(&ttps);
        assert_eq!(hm.hottest_tactic(), Some("TA0005"));
    }

    #[test]
    fn test_heatmap_frequency() {
        let ttps = vec![
            sample_ttp("T1055", MitreTactic::DefenseEvasion),
            sample_ttp("T1547", MitreTactic::Persistence),
        ];
        let hm = TtpHeatmap::from_entries(&ttps);
        assert!((hm.frequency("TA0005") - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_heatmap_empty() {
        let hm = TtpHeatmap::from_entries(&[]);
        assert!(hm.hottest_tactic().is_none());
        assert_eq!(hm.frequency("TA0005"), 0.0);
    }

    #[test]
    fn test_heatmap_distinct_tactics() {
        let ttps = vec![
            sample_ttp("T1055", MitreTactic::DefenseEvasion),
            sample_ttp("T1059", MitreTactic::Execution),
            sample_ttp("T1547", MitreTactic::Persistence),
        ];
        let hm = TtpHeatmap::from_entries(&ttps);
        assert_eq!(hm.distinct_tactics(), 3);
    }

    // ── TtpComparisonResult ──────────────────────────────────────────────────

    #[test]
    fn test_comparison_same_sets() {
        let a = vec![sample_ttp("T1055", MitreTactic::DefenseEvasion)];
        let result = TtpComparisonResult::compare(&a, &a);
        assert!((result.similarity - 1.0).abs() < f32::EPSILON);
        assert!(result.has_overlap());
    }

    #[test]
    fn test_comparison_disjoint_sets() {
        let a = vec![sample_ttp("T1055", MitreTactic::DefenseEvasion)];
        let b = vec![sample_ttp("T1059", MitreTactic::Execution)];
        let result = TtpComparisonResult::compare(&a, &b);
        assert_eq!(result.similarity, 0.0);
        assert!(!result.has_overlap());
    }

    #[test]
    fn test_comparison_partial_overlap() {
        let shared = sample_ttp("T1055", MitreTactic::DefenseEvasion);
        let a = vec![
            shared.clone(),
            sample_ttp("T1547", MitreTactic::Persistence),
        ];
        let b = vec![shared, sample_ttp("T1059", MitreTactic::Execution)];
        let result = TtpComparisonResult::compare(&a, &b);
        assert!(result.has_overlap());
        assert!(result.similarity > 0.0 && result.similarity < 1.0);
    }

    #[test]
    fn test_comparison_only_in_a_b() {
        let a = vec![sample_ttp("T1055", MitreTactic::DefenseEvasion)];
        let b = vec![sample_ttp("T1059", MitreTactic::Execution)];
        let result = TtpComparisonResult::compare(&a, &b);
        assert!(result.only_in_a.contains(&"T1055".to_string()));
        assert!(result.only_in_b.contains(&"T1059".to_string()));
    }

    // ── TtpSeverityScorer ────────────────────────────────────────────────────

    #[test]
    fn test_severity_score_zero() {
        let scorer = TtpSeverityScorer::default();
        assert_eq!(scorer.score(&[]), 0.0);
    }

    #[test]
    fn test_severity_score_increases_with_ttps() {
        let scorer = TtpSeverityScorer::default();
        let few = vec![sample_ttp("T1055", MitreTactic::DefenseEvasion)];
        let many: Vec<_> = vec![
            sample_ttp("T1055", MitreTactic::DefenseEvasion),
            sample_ttp("T1059", MitreTactic::Execution),
            sample_ttp("T1547", MitreTactic::Persistence),
        ];
        assert!(scorer.score(&many) > scorer.score(&few));
    }

    #[test]
    fn test_severity_score_capped_at_max() {
        let scorer = TtpSeverityScorer {
            max_score: 5.0,
            ..Default::default()
        };
        let ttps: Vec<_> = (0..100)
            .map(|_| sample_ttp("T1055", MitreTactic::DefenseEvasion))
            .collect();
        assert_eq!(scorer.score(&ttps), 5.0);
    }

    #[test]
    fn test_severity_classify() {
        assert_eq!(TtpSeverityScorer::classify(80.0), "critical");
        assert_eq!(TtpSeverityScorer::classify(60.0), "high");
        assert_eq!(TtpSeverityScorer::classify(30.0), "medium");
        assert_eq!(TtpSeverityScorer::classify(10.0), "low");
    }

    #[test]
    fn test_severity_high_confidence_bonus() {
        let scorer = TtpSeverityScorer::default();
        let mut t = sample_ttp("T1055", MitreTactic::DefenseEvasion);
        t.confidence = 80;
        let with_conf = vec![t.clone()];
        let mut t2 = t;
        t2.confidence = 30;
        let without_conf = vec![t2];
        assert!(scorer.score(&with_conf) > scorer.score(&without_conf));
    }
}
