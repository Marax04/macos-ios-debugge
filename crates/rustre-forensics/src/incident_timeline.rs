//! `incident_timeline` — Incident response timeline reconstruction.
//!
//! Provides `IncidentTimeline`, `Event`, `EventCorrelator`, `EventCluster`,
//! `TimelineExporter`, and `AttackPhase`.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::fmt::Write as _;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the timeline subsystem.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TimelineError {
    #[error("export error: {0}")]
    Export(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("empty timeline")]
    Empty,
    #[error("invalid time range")]
    InvalidRange,
}

// ─── AttackPhase ──────────────────────────────────────────────────────────────

/// MITRE ATT&CK–inspired attack phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttackPhase {
    Reconnaissance,
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
    Unknown,
}

impl AttackPhase {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Reconnaissance    => "Reconnaissance",
            Self::InitialAccess     => "Initial Access",
            Self::Execution         => "Execution",
            Self::Persistence       => "Persistence",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::DefenseEvasion    => "Defense Evasion",
            Self::CredentialAccess  => "Credential Access",
            Self::Discovery         => "Discovery",
            Self::LateralMovement   => "Lateral Movement",
            Self::Collection        => "Collection",
            Self::CommandAndControl => "Command and Control",
            Self::Exfiltration      => "Exfiltration",
            Self::Impact            => "Impact",
            Self::Unknown           => "Unknown",
        }
    }

    /// All phases in typical kill-chain order.
    #[must_use]
    pub const fn all_ordered() -> &'static [Self] {
        &[
            Self::Reconnaissance, Self::InitialAccess, Self::Execution,
            Self::Persistence, Self::PrivilegeEscalation, Self::DefenseEvasion,
            Self::CredentialAccess, Self::Discovery, Self::LateralMovement,
            Self::Collection, Self::CommandAndControl, Self::Exfiltration,
            Self::Impact,
        ]
    }

    /// Infer the attack phase from an event category string (heuristic).
    #[must_use]
    pub fn infer_from_category(category: &str) -> Self {
        let lower = category.to_ascii_lowercase();
        if lower.contains("recon") { return Self::Reconnaissance; }
        if lower.contains("initial") || lower.contains("phish") || lower.contains("exploit") {
            return Self::InitialAccess;
        }
        if lower.contains("execut") { return Self::Execution; }
        if lower.contains("persist") || lower.contains("autorun") { return Self::Persistence; }
        if lower.contains("privesc") || lower.contains("escalat") { return Self::PrivilegeEscalation; }
        if lower.contains("evasion") || lower.contains("obfusc") || lower.contains("packer") {
            return Self::DefenseEvasion;
        }
        if lower.contains("cred") || lower.contains("password") || lower.contains("lsass") {
            return Self::CredentialAccess;
        }
        if lower.contains("discover") || lower.contains("enum") { return Self::Discovery; }
        if lower.contains("lateral") || lower.contains("movem") { return Self::LateralMovement; }
        if lower.contains("collect") { return Self::Collection; }
        if lower.contains("c2") || lower.contains("command") { return Self::CommandAndControl; }
        if lower.contains("exfil") { return Self::Exfiltration; }
        if lower.contains("impact") || lower.contains("ransom") || lower.contains("destroy") {
            return Self::Impact;
        }
        Self::Unknown
    }
}

impl fmt::Display for AttackPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ─── EventSource ──────────────────────────────────────────────────────────────

/// The data source that produced an event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventSource {
    WindowsEventLog,
    Syslog,
    Pcap,
    SandboxReport,
    FileSystem,
    Registry,
    ProcessList,
    NetworkCapture,
    Antivirus,
    Edr,
    Custom(String),
}

impl EventSource {
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::WindowsEventLog => "Windows Event Log",
            Self::Syslog => "Syslog",
            Self::Pcap => "PCAP",
            Self::SandboxReport => "Sandbox Report",
            Self::FileSystem => "File System",
            Self::Registry => "Registry",
            Self::ProcessList => "Process List",
            Self::NetworkCapture => "Network Capture",
            Self::Antivirus => "Antivirus",
            Self::Edr => "EDR",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for EventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.name()) }
}

// ─── Event ────────────────────────────────────────────────────────────────────

/// A single incident timeline event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event identifier.
    pub id: u64,
    /// Timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: u64,
    /// Source of the event.
    pub source: EventSource,
    /// Event category (arbitrary string).
    pub category: String,
    /// Human-readable description.
    pub description: String,
    /// Indicators of compromise attached to this event.
    pub ioc: Vec<String>,
    /// Confidence score 0–100.
    pub confidence: u8,
    /// Inferred attack phase.
    pub phase: AttackPhase,
    /// Host/asset associated with the event.
    pub host: Option<String>,
    /// User associated with the event.
    pub user: Option<String>,
    /// Raw data (bytes) if available.
    pub raw_data: Vec<u8>,
    /// Arbitrary metadata.
    pub metadata: HashMap<String, String>,
}

impl Event {
    /// Create a new event.
    #[must_use]
    pub fn new(
        id: u64,
        timestamp_ms: u64,
        source: EventSource,
        category: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let cat: String = category.into();
        let phase = AttackPhase::infer_from_category(&cat);
        Self {
            id,
            timestamp_ms,
            source,
            category: cat,
            description: description.into(),
            ioc: vec![],
            confidence: 80,
            phase,
            host: None,
            user: None,
            raw_data: vec![],
            metadata: HashMap::new(),
        }
    }

    /// Builder: add an IOC.
    #[must_use]
    pub fn with_ioc(mut self, ioc: impl Into<String>) -> Self {
        self.ioc.push(ioc.into());
        self
    }

    /// Builder: set confidence.
    #[must_use]
    pub const fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c;
        self
    }

    /// Builder: set host.
    #[must_use]
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Builder: set user.
    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Builder: override the inferred phase.
    #[must_use]
    pub const fn with_phase(mut self, phase: AttackPhase) -> Self {
        self.phase = phase;
        self
    }

    /// Builder: set metadata key/value.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Timestamp in seconds.
    #[must_use]
    pub const fn timestamp_secs(&self) -> u64 { self.timestamp_ms / 1000 }

    /// Return `true` if the event has any IOCs.
    #[must_use]
    pub const fn has_ioc(&self) -> bool { !self.ioc.is_empty() }

    /// Return `true` if the confidence meets the threshold.
    #[must_use]
    pub const fn is_confident(&self, threshold: u8) -> bool { self.confidence >= threshold }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}ms][{}][{}] {} (conf={}%)",
            self.timestamp_ms, self.source, self.phase, self.description, self.confidence
        )
    }
}

// ─── EventCluster ─────────────────────────────────────────────────────────────

/// A group of events that occurred within a configurable time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCluster {
    /// Events in this cluster, in chronological order.
    pub events: Vec<Event>,
    /// Start timestamp of the cluster.
    pub start_ms: u64,
    /// End timestamp of the cluster.
    pub end_ms: u64,
    /// Dominant attack phase across cluster events.
    pub dominant_phase: AttackPhase,
}

impl EventCluster {
    /// Build a cluster from a slice of events (must be non-empty and sorted).
    #[must_use]
    pub fn from_events(events: Vec<Event>) -> Self {
        let start_ms = events.first().map_or(0, |e| e.timestamp_ms);
        let end_ms = events.last().map_or(0, |e| e.timestamp_ms);
        let dominant_phase = Self::dominant_phase(&events);
        Self { events, start_ms, end_ms, dominant_phase }
    }

    /// Infer the dominant phase by majority vote.
    fn dominant_phase(events: &[Event]) -> AttackPhase {
        let mut counts: HashMap<AttackPhase, usize> = HashMap::new();
        for e in events {
            *counts.entry(e.phase).or_insert(0) += 1;
        }
        counts.into_iter().max_by_key(|(_, c)| *c).map_or(AttackPhase::Unknown, |(p, _)| p)
    }

    /// Duration of the cluster in milliseconds.
    #[must_use]
    pub const fn duration_ms(&self) -> u64 {
        self.end_ms.saturating_sub(self.start_ms)
    }

    /// Number of events.
    #[must_use]
    pub const fn len(&self) -> usize { self.events.len() }

    /// Return `true` if the cluster is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.events.is_empty() }

    /// Unique IOCs across all events.
    #[must_use]
    pub fn unique_iocs(&self) -> Vec<String> {
        let mut iocs: std::collections::HashSet<String> = std::collections::HashSet::new();
        for e in &self.events {
            for ioc in &e.ioc { iocs.insert(ioc.clone()); }
        }
        let mut v: Vec<String> = iocs.into_iter().collect();
        v.sort();
        v
    }

    /// Mean confidence across events.
    #[must_use]
    pub fn mean_confidence(&self) -> f64 {
        if self.events.is_empty() { return 0.0; }
        let len_f64 = u32::try_from(self.events.len()).map_or(f64::INFINITY, f64::from);
        self.events.iter().map(|e| f64::from(e.confidence)).sum::<f64>() / len_f64
    }
}

// ─── EventCorrelator ─────────────────────────────────────────────────────────

/// Merges events from multiple sources and groups them into clusters.
pub struct EventCorrelator {
    /// All events added so far.
    events: Vec<Event>,
    /// Cluster window in milliseconds (events within this window are clustered).
    pub cluster_window_ms: u64,
    next_id: u64,
}

impl EventCorrelator {
    /// Create a new correlator with a 5-minute cluster window.
    #[must_use]
    pub const fn new() -> Self {
        Self { events: vec![], cluster_window_ms: 5 * 60 * 1000, next_id: 1 }
    }

    /// Create a correlator with a custom cluster window.
    #[must_use]
    pub const fn with_window(window_ms: u64) -> Self {
        Self { events: vec![], cluster_window_ms: window_ms, next_id: 1 }
    }

    /// Add an event. Auto-assigns a unique ID if `id == 0`.
    pub fn add_event(&mut self, mut event: Event) {
        if event.id == 0 {
            event.id = self.next_id;
            self.next_id += 1;
        }
        self.events.push(event);
    }

    /// Add multiple events at once.
    pub fn add_events(&mut self, events: impl IntoIterator<Item = Event>) {
        for e in events { self.add_event(e); }
    }

    /// Sort events chronologically.
    pub fn sort(&mut self) {
        self.events.sort_by_key(|e| e.timestamp_ms);
    }

    /// Cluster events by time window.
    #[must_use]
    pub fn cluster(&self) -> Vec<EventCluster> {
        if self.events.is_empty() { return vec![]; }
        let mut sorted = self.events.clone();
        sorted.sort_by_key(|e| e.timestamp_ms);

        let mut clusters: Vec<EventCluster> = Vec::new();
        let mut current: Vec<Event> = Vec::new();
        let mut window_start = sorted[0].timestamp_ms;

        for event in sorted {
            if event.timestamp_ms > window_start + self.cluster_window_ms {
                if !current.is_empty() {
                    clusters.push(EventCluster::from_events(std::mem::take(&mut current)));
                }
                window_start = event.timestamp_ms;
            }
            current.push(event);
        }
        if !current.is_empty() {
            clusters.push(EventCluster::from_events(current));
        }
        clusters
    }

    /// Return all events.
    #[must_use]
    pub fn events(&self) -> &[Event] { &self.events }

    /// Return events from a specific source.
    #[must_use]
    pub fn events_by_source(&self, source: &EventSource) -> Vec<&Event> {
        self.events.iter().filter(|e| &e.source == source).collect()
    }

    /// Return events matching a phase.
    #[must_use]
    pub fn events_by_phase(&self, phase: AttackPhase) -> Vec<&Event> {
        self.events.iter().filter(|e| e.phase == phase).collect()
    }

    /// Return events in the time range `[start_ms, end_ms]`.
    #[must_use]
    pub fn events_in_range(&self, start_ms: u64, end_ms: u64) -> Vec<&Event> {
        self.events.iter().filter(|e| e.timestamp_ms >= start_ms && e.timestamp_ms <= end_ms).collect()
    }

    /// Count events per source.
    #[must_use]
    pub fn count_by_source(&self) -> HashMap<String, usize> {
        let mut m: HashMap<String, usize> = HashMap::new();
        for e in &self.events {
            *m.entry(e.source.to_string()).or_insert(0) += 1;
        }
        m
    }

    /// Count events per phase.
    #[must_use]
    pub fn count_by_phase(&self) -> HashMap<AttackPhase, usize> {
        let mut m: HashMap<AttackPhase, usize> = HashMap::new();
        for e in &self.events {
            *m.entry(e.phase).or_insert(0) += 1;
        }
        m
    }

    /// Return all unique IOCs across all events.
    #[must_use]
    pub fn all_iocs(&self) -> Vec<String> {
        let mut iocs: std::collections::HashSet<String> = std::collections::HashSet::new();
        for e in &self.events {
            for ioc in &e.ioc { iocs.insert(ioc.clone()); }
        }
        let mut v: Vec<String> = iocs.into_iter().collect();
        v.sort();
        v
    }

    /// Number of events.
    #[must_use]
    pub const fn len(&self) -> usize { self.events.len() }

    /// Return `true` if no events have been added.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.events.is_empty() }
}

impl Default for EventCorrelator {
    fn default() -> Self { Self::new() }
}

// ─── IncidentTimeline ────────────────────────────────────────────────────────

/// Full incident response timeline.
pub struct IncidentTimeline {
    /// Case identifier.
    pub case_id: String,
    /// Analyst name.
    pub analyst: String,
    /// The correlator containing all events.
    correlator: EventCorrelator,
    /// Computed clusters (cached).
    clusters_cache: Option<Vec<EventCluster>>,
}

impl IncidentTimeline {
    /// Create a new timeline.
    #[must_use]
    pub fn new(case_id: impl Into<String>, analyst: impl Into<String>) -> Self {
        Self {
            case_id: case_id.into(),
            analyst: analyst.into(),
            correlator: EventCorrelator::new(),
            clusters_cache: None,
        }
    }

    /// Add an event and invalidate the cluster cache.
    pub fn add_event(&mut self, event: Event) {
        self.correlator.add_event(event);
        self.clusters_cache = None;
    }

    /// Add events from another correlator.
    pub fn merge_from(&mut self, other: EventCorrelator) {
        for e in other.events { self.correlator.add_event(e); }
        self.clusters_cache = None;
    }

    /// Sort all events chronologically.
    pub fn sort(&mut self) {
        self.correlator.sort();
        self.clusters_cache = None;
    }

    /// Return computed clusters, using the cache if available.
    #[must_use]
    pub fn clusters(&mut self) -> &[EventCluster] {
        if self.clusters_cache.is_none() {
            self.clusters_cache = Some(self.correlator.cluster());
        }
        self.clusters_cache.as_deref().unwrap_or(&[])
    }

    /// Return all events.
    #[must_use]
    pub fn events(&self) -> &[Event] { self.correlator.events() }

    /// Total number of events.
    #[must_use]
    pub const fn event_count(&self) -> usize { self.correlator.len() }

    /// Return all IOCs.
    #[must_use]
    pub fn iocs(&self) -> Vec<String> { self.correlator.all_iocs() }

    /// Return the earliest event timestamp in milliseconds, or `None`.
    #[must_use]
    pub fn start_time_ms(&self) -> Option<u64> {
        self.correlator.events().iter().map(|e| e.timestamp_ms).min()
    }

    /// Return the latest event timestamp in milliseconds, or `None`.
    #[must_use]
    pub fn end_time_ms(&self) -> Option<u64> {
        self.correlator.events().iter().map(|e| e.timestamp_ms).max()
    }

    /// Duration of the incident in milliseconds.
    #[must_use]
    pub fn duration_ms(&self) -> u64 {
        match (self.start_time_ms(), self.end_time_ms()) {
            (Some(s), Some(e)) => e.saturating_sub(s),
            _ => 0,
        }
    }

    /// Attack phases observed (sorted by kill-chain order).
    #[must_use]
    pub fn observed_phases(&self) -> Vec<AttackPhase> {
        let phases: std::collections::HashSet<AttackPhase> =
            self.correlator.events().iter().map(|e| e.phase).collect();
        let mut v: Vec<AttackPhase> = phases.into_iter().collect();
        v.sort();
        v
    }

    /// Events for a specific attack phase.
    #[must_use]
    pub fn events_for_phase(&self, phase: AttackPhase) -> Vec<&Event> {
        self.correlator.events_by_phase(phase)
    }
}

// ─── TimelineExporter ────────────────────────────────────────────────────────

/// Exports an `IncidentTimeline` in multiple formats.
pub struct TimelineExporter;

impl TimelineExporter {
    /// Export events to JSON.
    ///
    /// # Errors
    /// Returns `TimelineError::Export` on serialisation failure.
    pub fn to_json(timeline: &IncidentTimeline) -> Result<String, TimelineError> {
        #[derive(Serialize)]
        struct Export<'a> {
            case_id: &'a str,
            analyst: &'a str,
            event_count: usize,
            events: &'a [Event],
        }
        serde_json::to_string_pretty(&Export {
            case_id: &timeline.case_id,
            analyst: &timeline.analyst,
            event_count: timeline.event_count(),
            events: timeline.events(),
        })
        .map_err(|e| TimelineError::Export(e.to_string()))
    }

    /// Export events to CSV.
    ///
    /// # Errors
    /// Returns `TimelineError::Empty` when there are no events.
    pub fn to_csv(timeline: &IncidentTimeline) -> Result<String, TimelineError> {
        if timeline.event_count() == 0 {
            return Err(TimelineError::Empty);
        }
        let mut out = String::from("id,timestamp_ms,source,category,phase,description,confidence,iocs\n");
        for e in timeline.events() {
            let _ = writeln!(out, "{},{},{},{},{},{},{},{}",
                e.id, e.timestamp_ms, e.source, e.category, e.phase,
                csv_escape(&e.description), e.confidence,
                e.ioc.join(";"));
        }
        Ok(out)
    }

    /// Export events as a simple HTML timeline table.
    ///
    /// # Errors
    /// Returns `TimelineError::Empty` when there are no events.
    pub fn to_html(timeline: &IncidentTimeline) -> Result<String, TimelineError> {
        if timeline.event_count() == 0 {
            return Err(TimelineError::Empty);
        }
        let mut html = format!(
            "<!DOCTYPE html><html><head><title>Incident Timeline - {}</title></head><body>\
            <h1>Case: {} | Analyst: {}</h1>\
            <table border=\"1\"><tr><th>Time</th><th>Source</th><th>Phase</th><th>Description</th><th>IOCs</th><th>Confidence</th></tr>\n",
            timeline.case_id, timeline.case_id, timeline.analyst
        );
        for e in timeline.events() {
            let _ = writeln!(html, "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}%</td></tr>",
                e.timestamp_ms, e.source, e.phase,
                html_escape(&e.description),
                e.ioc.join(", "),
                e.confidence);
        }
        html.push_str("</table></body></html>");
        Ok(html)
    }

    /// Export a text summary.
    #[must_use]
    pub fn to_text(timeline: &IncidentTimeline) -> String {
        let mut out = format!(
            "=== Incident Timeline ===\nCase: {}\nAnalyst: {}\nEvents: {}\n",
            timeline.case_id, timeline.analyst, timeline.event_count()
        );
        for e in timeline.events() {
            let _ = writeln!(out, "  {} | {} | {} | {}",
                e.timestamp_ms, e.source, e.phase, e.description);
        }
        out
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(offset_s: u64) -> u64 { offset_s * 1000 }
    fn ev(id: u64, offset_s: u64, category: &str, desc: &str) -> Event {
        Event::new(id, ts(offset_s), EventSource::Syslog, category, desc)
    }

    // ── AttackPhase ───────────────────────────────────────────────────────────

    #[test]
    fn test_phase_names_unique() {
        let names: std::collections::HashSet<&str> =
            AttackPhase::all_ordered().iter().map(|p| p.name()).collect();
        assert_eq!(names.len(), AttackPhase::all_ordered().len());
    }

    #[test]
    fn test_phase_infer_persistence() {
        assert_eq!(AttackPhase::infer_from_category("persistence"), AttackPhase::Persistence);
    }

    #[test]
    fn test_phase_infer_c2() {
        assert_eq!(AttackPhase::infer_from_category("c2_beacon"), AttackPhase::CommandAndControl);
    }

    #[test]
    fn test_phase_infer_recon() {
        assert_eq!(AttackPhase::infer_from_category("recon_scan"), AttackPhase::Reconnaissance);
    }

    #[test]
    fn test_phase_infer_unknown() {
        assert_eq!(AttackPhase::infer_from_category("xyz"), AttackPhase::Unknown);
    }

    #[test]
    fn test_phase_display() {
        assert!(AttackPhase::LateralMovement.to_string().contains("Lateral"));
    }

    #[test]
    fn test_phase_ordering() {
        assert!(AttackPhase::Reconnaissance < AttackPhase::Impact);
    }

    // ── EventSource ───────────────────────────────────────────────────────────

    #[test]
    fn test_event_source_name() {
        assert_eq!(EventSource::Syslog.name(), "Syslog");
        assert_eq!(EventSource::Custom("custom".into()).name(), "custom");
    }

    #[test]
    fn test_event_source_display() {
        assert_eq!(EventSource::Pcap.to_string(), "PCAP");
    }

    // ── Event ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_event_new_defaults() {
        let e = Event::new(1, 5000, EventSource::Syslog, "persistence", "autorun key added");
        assert_eq!(e.id, 1);
        assert_eq!(e.timestamp_ms, 5000);
        assert_eq!(e.phase, AttackPhase::Persistence);
        assert!(e.ioc.is_empty());
    }

    #[test]
    fn test_event_builders() {
        let e = Event::new(1, 0, EventSource::Syslog, "c2", "beacon")
            .with_ioc("192.168.1.1")
            .with_confidence(95)
            .with_host("victim-pc")
            .with_user("jdoe")
            .with_phase(AttackPhase::CommandAndControl)
            .with_meta("severity", "high");
        assert!(e.has_ioc());
        assert_eq!(e.ioc[0], "192.168.1.1");
        assert_eq!(e.confidence, 95);
        assert_eq!(e.host.as_deref(), Some("victim-pc"));
        assert_eq!(e.user.as_deref(), Some("jdoe"));
        assert_eq!(e.phase, AttackPhase::CommandAndControl);
        assert_eq!(e.metadata["severity"], "high");
    }

    #[test]
    fn test_event_timestamp_secs() {
        let e = ev(1, 120, "exec", "cmd.exe");
        assert_eq!(e.timestamp_secs(), 120);
    }

    #[test]
    fn test_event_is_confident() {
        let e = ev(1, 0, "x", "y").with_confidence(70);
        assert!(e.is_confident(70));
        assert!(!e.is_confident(71));
    }

    #[test]
    fn test_event_display() {
        let e = ev(1, 0, "c2", "test");
        let s = e.to_string();
        assert!(s.contains("Syslog"));
    }

    // ── EventCluster ──────────────────────────────────────────────────────────

    #[test]
    fn test_cluster_from_events_empty() {
        let c = EventCluster::from_events(vec![]);
        assert!(c.is_empty());
    }

    #[test]
    fn test_cluster_duration() {
        let events = vec![
            ev(1, 0, "x", "first"),
            ev(2, 10, "x", "second"),
        ];
        let c = EventCluster::from_events(events);
        assert_eq!(c.duration_ms(), 10_000);
    }

    #[test]
    fn test_cluster_dominant_phase() {
        let events = vec![
            ev(1, 0, "persistence", "p1"),
            ev(2, 1, "persistence", "p2"),
            ev(3, 2, "c2", "c2_event"),
        ];
        let c = EventCluster::from_events(events);
        assert_eq!(c.dominant_phase, AttackPhase::Persistence);
    }

    #[test]
    fn test_cluster_unique_iocs() {
        let events = vec![
            ev(1, 0, "c2", "e1").with_ioc("1.2.3.4"),
            ev(2, 1, "c2", "e2").with_ioc("1.2.3.4").with_ioc("5.6.7.8"),
        ];
        let c = EventCluster::from_events(events);
        assert_eq!(c.unique_iocs().len(), 2);
    }

    #[test]
    fn test_cluster_mean_confidence() {
        let events = vec![
            ev(1, 0, "x", "e1").with_confidence(80),
            ev(2, 1, "x", "e2").with_confidence(100),
        ];
        let c = EventCluster::from_events(events);
        assert!((c.mean_confidence() - 90.0).abs() < 0.01);
    }

    // ── EventCorrelator ───────────────────────────────────────────────────────

    #[test]
    fn test_correlator_add_and_len() {
        let mut c = EventCorrelator::new();
        c.add_event(ev(1, 0, "x", "e1"));
        c.add_event(ev(2, 5, "x", "e2"));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn test_correlator_auto_id() {
        let mut c = EventCorrelator::new();
        c.add_event(ev(0, 0, "x", "no_id"));
        assert_ne!(c.events()[0].id, 0);
    }

    #[test]
    fn test_correlator_cluster_two_windows() {
        let mut c = EventCorrelator::with_window(60_000); // 1 minute
        c.add_event(ev(1, 0, "x", "e1"));
        c.add_event(ev(2, 30, "x", "e2")); // same window
        c.add_event(ev(3, 300, "x", "e3")); // different window
        let clusters = c.cluster();
        assert_eq!(clusters.len(), 2);
    }

    #[test]
    fn test_correlator_events_by_source() {
        let mut c = EventCorrelator::new();
        c.add_event(Event::new(1, 0, EventSource::Syslog, "x", "from syslog"));
        c.add_event(Event::new(2, 0, EventSource::Pcap, "x", "from pcap"));
        let syslog = c.events_by_source(&EventSource::Syslog);
        assert_eq!(syslog.len(), 1);
    }

    #[test]
    fn test_correlator_events_by_phase() {
        let mut c = EventCorrelator::new();
        c.add_event(ev(1, 0, "persistence", "p1"));
        c.add_event(ev(2, 0, "c2", "c2"));
        let persist = c.events_by_phase(AttackPhase::Persistence);
        assert_eq!(persist.len(), 1);
    }

    #[test]
    fn test_correlator_events_in_range() {
        let mut c = EventCorrelator::new();
        c.add_event(ev(1, 0, "x", "before"));
        c.add_event(ev(2, 5, "x", "in range"));
        c.add_event(ev(3, 100, "x", "after"));
        let in_range = c.events_in_range(1000, 10_000);
        assert_eq!(in_range.len(), 1);
    }

    #[test]
    fn test_correlator_all_iocs() {
        let mut c = EventCorrelator::new();
        c.add_event(ev(1, 0, "x", "").with_ioc("a.com"));
        c.add_event(ev(2, 1, "x", "").with_ioc("b.com").with_ioc("a.com"));
        let iocs = c.all_iocs();
        assert_eq!(iocs.len(), 2);
    }

    #[test]
    fn test_correlator_count_by_source() {
        let mut c = EventCorrelator::new();
        c.add_event(Event::new(1, 0, EventSource::Syslog, "x", "a"));
        c.add_event(Event::new(2, 1, EventSource::Syslog, "x", "b"));
        c.add_event(Event::new(3, 2, EventSource::Pcap, "x", "c"));
        let counts = c.count_by_source();
        assert_eq!(counts["Syslog"], 2);
        assert_eq!(counts["PCAP"], 1);
    }

    // ── IncidentTimeline ──────────────────────────────────────────────────────

    #[test]
    fn test_timeline_add_events() {
        let mut t = IncidentTimeline::new("IR-001", "alice");
        t.add_event(ev(1, 0, "x", "first"));
        t.add_event(ev(2, 5, "y", "second"));
        assert_eq!(t.event_count(), 2);
    }

    #[test]
    fn test_timeline_duration() {
        let mut t = IncidentTimeline::new("IR-002", "bob");
        t.add_event(ev(1, 0, "x", "start"));
        t.add_event(ev(2, 60, "y", "end"));
        assert_eq!(t.duration_ms(), 60_000);
    }

    #[test]
    fn test_timeline_observed_phases() {
        let mut t = IncidentTimeline::new("IR-003", "c");
        t.add_event(ev(1, 0, "persistence", "p"));
        t.add_event(ev(2, 1, "c2", "c2"));
        let phases = t.observed_phases();
        assert!(phases.contains(&AttackPhase::Persistence));
        assert!(phases.contains(&AttackPhase::CommandAndControl));
    }

    #[test]
    fn test_timeline_iocs() {
        let mut t = IncidentTimeline::new("IR-004", "d");
        t.add_event(ev(1, 0, "x", "").with_ioc("bad.com"));
        assert_eq!(t.iocs(), vec!["bad.com"]);
    }

    #[test]
    fn test_timeline_events_for_phase() {
        let mut t = IncidentTimeline::new("IR-005", "e");
        t.add_event(ev(1, 0, "exfil", "data sent").with_phase(AttackPhase::Exfiltration));
        let exfil = t.events_for_phase(AttackPhase::Exfiltration);
        assert_eq!(exfil.len(), 1);
    }

    #[test]
    fn test_timeline_clusters() {
        let mut t = IncidentTimeline::new("IR-006", "f");
        t.correlator = EventCorrelator::with_window(60_000);
        t.add_event(ev(1, 0, "x", "e1"));
        t.add_event(ev(2, 100, "x", "e2"));
        let c = t.clusters();
        assert_eq!(c.len(), 2);
    }

    // ── TimelineExporter ──────────────────────────────────────────────────────

    #[test]
    fn test_export_json() {
        let mut t = IncidentTimeline::new("IR-007", "g");
        t.add_event(ev(1, 0, "x", "test"));
        let json = TimelineExporter::to_json(&t).unwrap();
        assert!(json.contains("IR-007"));
    }

    #[test]
    fn test_export_csv() {
        let mut t = IncidentTimeline::new("IR-008", "h");
        t.add_event(ev(1, 0, "x", "test event"));
        let csv = TimelineExporter::to_csv(&t).unwrap();
        assert!(csv.contains("timestamp_ms"));
        assert!(csv.contains("test event"));
    }

    #[test]
    fn test_export_csv_empty() {
        let t = IncidentTimeline::new("IR-009", "i");
        assert!(matches!(TimelineExporter::to_csv(&t), Err(TimelineError::Empty)));
    }

    #[test]
    fn test_export_html() {
        let mut t = IncidentTimeline::new("IR-010", "j");
        t.add_event(ev(1, 0, "x", "<script>alert(1)</script>"));
        let html = TimelineExporter::to_html(&t).unwrap();
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("IR-010"));
    }

    #[test]
    fn test_export_text() {
        let mut t = IncidentTimeline::new("IR-011", "k");
        t.add_event(ev(1, 0, "x", "first event"));
        let text = TimelineExporter::to_text(&t);
        assert!(text.contains("Case: IR-011"));
        assert!(text.contains("first event"));
    }

    #[test]
    fn test_csv_escape_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("plain"), "plain");
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<div>"), "&lt;div&gt;");
        assert_eq!(html_escape("&amp;"), "&amp;amp;");
    }
}
