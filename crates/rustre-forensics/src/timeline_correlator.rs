//! `timeline_correlator` — Multi-source forensic timeline correlation.
//!
//! Merges events from process lists, network connections, filesystem activity,
//! registry changes, prefetch files, and Windows event logs into a unified
//! timeline. Normalises timestamps, identifies behavioural patterns, detects
//! temporal gaps, and exports PLASO-compatible output.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum CorrelatorError {
    #[error("empty event set")]
    EmptyEventSet,
    #[error("timestamp normalisation failed: {0}")]
    NormalisationFailed(String),
    #[error("conflicting timestamps from source {0}: delta {1}ms")]
    ConflictingTimestamps(String, i64),
    #[error("export failed: {0}")]
    ExportFailed(String),
}

// ─── Event Source ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventSource {
    ProcessList,
    NetworkCapture,
    Filesystem,
    Registry,
    Prefetch,
    WindowsEventLog,
    SyslogLinux,
    BrowserHistory,
    MemoryAnalysis,
    Sandbox,
    Custom,
}

impl fmt::Display for EventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessList => write!(f, "ProcessList"),
            Self::NetworkCapture => write!(f, "NetworkCapture"),
            Self::Filesystem => write!(f, "Filesystem"),
            Self::Registry => write!(f, "Registry"),
            Self::Prefetch => write!(f, "Prefetch"),
            Self::WindowsEventLog => write!(f, "WindowsEventLog"),
            Self::SyslogLinux => write!(f, "SyslogLinux"),
            Self::BrowserHistory => write!(f, "BrowserHistory"),
            Self::MemoryAnalysis => write!(f, "MemoryAnalysis"),
            Self::Sandbox => write!(f, "Sandbox"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

// ─── Timeline Event ───────────────────────────────────────────────────────────

/// Severity of a timeline event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for EventSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single normalised forensic event on the unified timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub id: u64,
    /// Unix timestamp in milliseconds (normalised).
    pub timestamp_ms: i64,
    /// Confidence in timestamp accuracy (0–100).
    pub timestamp_confidence: u8,
    pub source: EventSource,
    pub category: EventCategory,
    pub severity: EventSeverity,
    pub description: String,
    pub actor: Option<String>,       // process name, user, IP, etc.
    pub object: Option<String>,      // file, registry key, URL, etc.
    pub related_events: Vec<u64>,    // IDs of correlated events
    pub tags: Vec<String>,
    pub raw: HashMap<String, String>,
}

impl TimelineEvent {
    #[must_use]
    pub fn timestamp_seconds(&self) -> f64 {
        // Split into seconds and milliseconds to keep precision and avoid a
        // direct i64-to-f64 cast (which clippy::cast_precision_loss flags).
        let secs = self.timestamp_ms / 1000;
        let rem_ms = self.timestamp_ms % 1000;
        // Reduce magnitude before float conversion; values fit well within
        // f64 mantissa for any realistic timestamp.
        let secs_high = i32::try_from(secs / 1_000_000).map_or(0.0, f64::from);
        let secs_low = i32::try_from(secs % 1_000_000).map_or(0.0, f64::from);
        let secs_f64 = secs_high.mul_add(1_000_000.0, secs_low);
        let rem_f64 = i16::try_from(rem_ms).map_or(0.0, f64::from);
        secs_f64 + rem_f64 / 1000.0
    }

    #[must_use] 
    pub const fn age_from(&self, reference_ms: i64) -> i64 {
        self.timestamp_ms - reference_ms
    }
}

/// Actor/object pair attached to a timeline event (e.g. a user performing an action on a file).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSubject {
    pub actor: Option<String>,
    pub object: Option<String>,
}

impl EventSubject {
    /// Empty subject (no actor, no object).
    #[must_use]
    pub const fn none() -> Self {
        Self { actor: None, object: None }
    }
}

/// High-level category for timeline events.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventCategory {
    ProcessCreation,
    ProcessTermination,
    NetworkConnect,
    NetworkListen,
    NetworkDns,
    FileCreate,
    FileModify,
    FileDelete,
    FileExecute,
    RegistryCreate,
    RegistryModify,
    RegistryDelete,
    PrefetchEntry,
    UserLogon,
    UserLogoff,
    PrivilegeEscalation,
    LateralMovement,
    DataExfiltration,
    Persistence,
    MemoryInjection,
    CryptoOperation,
    AntiAnalysis,
    Unknown,
}

impl fmt::Display for EventCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = format!("{self:?}");
        write!(f, "{s}")
    }
}

// ─── Timestamp Normaliser ────────────────────────────────────────────────────

/// Per-source timestamp offset to account for clock skew.
#[derive(Debug, Clone, Default)]
pub struct TimestampNormaliser {
    /// Map from `EventSource` to `offset_ms` (positive = source is ahead of ground truth).
    offsets: HashMap<EventSource, i64>,
    /// Reference time (e.g. from NTP-synchronised source).
    reference_time_ms: Option<i64>,
}

impl TimestampNormaliser {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a known clock skew for a source.
    pub fn set_offset(&mut self, source: EventSource, offset_ms: i64) {
        self.offsets.insert(source, offset_ms);
    }

    /// Set a reference timestamp (e.g. from a network packet with known accurate time).
    pub const fn set_reference(&mut self, ts_ms: i64) {
        self.reference_time_ms = Some(ts_ms);
    }

    /// Normalise a raw timestamp from a given source.
    #[must_use] 
    pub fn normalise(&self, raw_ms: i64, source: EventSource) -> i64 {
        let offset = self.offsets.get(&source).copied().unwrap_or(0);
        raw_ms - offset
    }

    /// Compute clock skew between two correlated events that should be simultaneous.
    pub fn compute_skew(&mut self, source_a: EventSource, ts_a: i64, _source_b: EventSource, ts_b: i64) {
        // Assume source_b is the reference — skew = ts_a - ts_b
        let skew = ts_a - ts_b;
        if skew.abs() > 1000 { // > 1 second skew is suspicious
            self.offsets.insert(source_a, skew);
        }
    }
}

// ─── Pattern Detector ─────────────────────────────────────────────────────────

/// A temporal pattern found in the timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalPattern {
    pub pattern_type: PatternType,
    pub events: Vec<u64>,      // event IDs
    pub start_ms: i64,
    pub end_ms: i64,
    pub confidence: f32,       // 0.0–1.0
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternType {
    /// File written → process created → network connect (dropper sequence)
    DropAndExecute,
    /// Process created → registry write (persistence)
    InstallPersistence,
    /// Network connect → file write (download)
    DownloadAndDrop,
    /// Repeated network connections at regular intervals (beacon)
    C2Beacon,
    /// Large file write → network send (exfiltration)
    DataExfiltration,
    /// Lateral movement (process → network → process on remote)
    LateralMovement,
    /// Privilege escalation followed by persistence
    EscalateAndPersist,
    /// Custom sequence
    Custom(String),
}

impl fmt::Display for PatternType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DropAndExecute => write!(f, "Drop-and-Execute"),
            Self::InstallPersistence => write!(f, "Install-Persistence"),
            Self::DownloadAndDrop => write!(f, "Download-and-Drop"),
            Self::C2Beacon => write!(f, "C2-Beacon"),
            Self::DataExfiltration => write!(f, "Data-Exfiltration"),
            Self::LateralMovement => write!(f, "Lateral-Movement"),
            Self::EscalateAndPersist => write!(f, "Escalate-and-Persist"),
            Self::Custom(s) => write!(f, "Custom({s})"),
        }
    }
}

// ─── Gap Analysis ─────────────────────────────────────────────────────────────

/// A temporal gap in the event timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineGap {
    pub start_ms: i64,
    pub end_ms: i64,
    pub duration_ms: i64,
    pub events_before: Vec<u64>,
    pub events_after: Vec<u64>,
    pub significance: GapSignificance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GapSignificance {
    Normal,       // < 5 minutes
    Notable,      // 5–30 minutes
    Suspicious,   // 30 min – 2 hours
    Critical,     // > 2 hours (potential log tampering or hibernation)
}

impl TimelineGap {
    #[must_use] 
    pub const fn classify(duration_ms: i64) -> GapSignificance {
        match duration_ms {
            d if d < 5 * 60 * 1000 => GapSignificance::Normal,
            d if d < 30 * 60 * 1000 => GapSignificance::Notable,
            d if d < 120 * 60 * 1000 => GapSignificance::Suspicious,
            _ => GapSignificance::Critical,
        }
    }
}

// ─── PLASO Export ─────────────────────────────────────────────────────────────

/// A PLASO L2T CSV compatible record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlasoRecord {
    /// Timestamp in microseconds since epoch.
    pub timestamp: i64,
    /// e.g. "MACB" or specific type
    pub timestamp_desc: String,
    pub source: String,
    pub source_long: String,
    pub message: String,
    pub parser: String,
    pub display_name: String,
    pub tag: String,
    pub inode: Option<u64>,
    pub filename: Option<String>,
}

impl PlasoRecord {
    /// Format as L2T CSV line.
    #[must_use] 
    pub fn to_csv_line(&self) -> String {
        let ts_sec = self.timestamp / 1_000_000;
        let ts_us = self.timestamp % 1_000_000;
        let dt = format!("{ts_sec}.{ts_us:06}");
        format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            dt,
            self.timestamp_desc,
            self.source,
            self.source_long,
            self.message.replace(',', ";"),
            self.parser,
            self.display_name,
            self.tag,
            self.inode.map(|i| i.to_string()).unwrap_or_default(),
            self.filename.as_deref().unwrap_or(""),
        )
    }
}

fn event_to_plaso(ev: &TimelineEvent) -> PlasoRecord {
    PlasoRecord {
        timestamp: ev.timestamp_ms * 1000,
        timestamp_desc: format!("{}", ev.category),
        source: format!("{}", ev.source),
        source_long: format!("{:?}", ev.source),
        message: ev.description.clone(),
        parser: "rustre-forensics".to_owned(),
        display_name: ev.actor.clone().unwrap_or_else(|| "unknown".to_owned()),
        tag: ev.tags.join("|"),
        inode: None,
        filename: ev.object.clone(),
    }
}

// ─── Timeline Correlator ──────────────────────────────────────────────────────

/// Main timeline correlation engine.
#[derive(Debug, Default)]
pub struct TimelineCorrelator {
    next_id: u64,
    events: Vec<TimelineEvent>,
    normaliser: TimestampNormaliser,
    patterns: Vec<TemporalPattern>,
    gaps: Vec<TimelineGap>,
    sorted: bool,
}

impl TimelineCorrelator {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn with_normaliser(mut self, normaliser: TimestampNormaliser) -> Self {
        self.normaliser = normaliser;
        self
    }

    const fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    // ── Ingestion ─────────────────────────────────────────────────────────────

    /// Add a pre-built event.
    pub fn add_event(&mut self, mut ev: TimelineEvent) {
        ev.id = self.next_id();
        ev.timestamp_ms = self.normaliser.normalise(ev.timestamp_ms, ev.source);
        self.events.push(ev);
        self.sorted = false;
    }

    /// Convenience: add an event from raw fields.
    pub fn record(
        &mut self,
        timestamp_ms: i64,
        source: EventSource,
        category: EventCategory,
        severity: EventSeverity,
        description: impl Into<String>,
        subject: EventSubject,
    ) -> u64 {
        let EventSubject { actor, object } = subject;
        let id = self.next_id();
        let norm_ts = self.normaliser.normalise(timestamp_ms, source);
        self.events.push(TimelineEvent {
            id,
            timestamp_ms: norm_ts,
            timestamp_confidence: 80,
            source,
            category,
            severity,
            description: description.into(),
            actor,
            object,
            related_events: Vec::new(),
            tags: Vec::new(),
            raw: HashMap::new(),
        });
        self.sorted = false;
        id
    }

    // ── Sorting ───────────────────────────────────────────────────────────────

    pub fn sort(&mut self) {
        self.events.sort_by_key(|e| e.timestamp_ms);
        self.sorted = true;
    }

    #[must_use] 
    pub fn events(&self) -> &[TimelineEvent] {
        &self.events
    }

    pub fn events_sorted(&mut self) -> &[TimelineEvent] {
        if !self.sorted {
            self.sort();
        }
        &self.events
    }

    // ── Filtering ─────────────────────────────────────────────────────────────

    #[must_use] 
    pub fn filter_by_source(&self, source: EventSource) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| e.source == source).collect()
    }

    #[must_use] 
    pub fn filter_by_severity(&self, min_severity: EventSeverity) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| e.severity >= min_severity).collect()
    }

    #[must_use] 
    pub fn filter_by_window(&self, start_ms: i64, end_ms: i64) -> Vec<&TimelineEvent> {
        self.events.iter()
            .filter(|e| e.timestamp_ms >= start_ms && e.timestamp_ms <= end_ms)
            .collect()
    }

    // ── Gap Analysis ─────────────────────────────────────────────────────────

    /// Detect gaps between consecutive events larger than `min_gap_ms`.
    pub fn detect_gaps(&mut self, min_gap_ms: i64) {
        if !self.sorted { self.sort(); }
        self.gaps.clear();
        let events = &self.events;
        for i in 0..events.len().saturating_sub(1) {
            let gap = events[i + 1].timestamp_ms - events[i].timestamp_ms;
            if gap >= min_gap_ms {
                self.gaps.push(TimelineGap {
                    start_ms: events[i].timestamp_ms,
                    end_ms: events[i + 1].timestamp_ms,
                    duration_ms: gap,
                    events_before: vec![events[i].id],
                    events_after: vec![events[i + 1].id],
                    significance: TimelineGap::classify(gap),
                });
            }
        }
    }

    #[must_use] 
    pub fn gaps(&self) -> &[TimelineGap] {
        &self.gaps
    }

    #[must_use] 
    pub fn suspicious_gaps(&self) -> Vec<&TimelineGap> {
        self.gaps.iter()
            .filter(|g| matches!(g.significance, GapSignificance::Suspicious | GapSignificance::Critical))
            .collect()
    }

    // ── Pattern Detection ─────────────────────────────────────────────────────

    /// Detect temporal patterns in the timeline.
    pub fn detect_patterns(&mut self, window_ms: i64) {
        if !self.sorted { self.sort(); }
        self.patterns.clear();

        // Drop-and-Execute: FileCreate → ProcessCreation within window
        self.detect_drop_and_execute(window_ms);
        // Install-Persistence: ProcessCreation → RegistryCreate/Modify within window
        self.detect_install_persistence(window_ms);
        // C2 Beacon: repeated NetworkConnect to same object at regular intervals
        self.detect_c2_beacon(window_ms);
        // Data Exfiltration: many FileCreate/Modify followed by NetworkConnect
        self.detect_data_exfiltration(window_ms);
    }

    fn detect_drop_and_execute(&mut self, window_ms: i64) {
        let file_creates: Vec<(i64, u64, Option<String>)> = self.events.iter()
            .filter(|e| matches!(e.category, EventCategory::FileCreate))
            .map(|e| (e.timestamp_ms, e.id, e.object.clone()))
            .collect();

        let proc_creations: Vec<(i64, u64, Option<String>)> = self.events.iter()
            .filter(|e| matches!(e.category, EventCategory::ProcessCreation))
            .map(|e| (e.timestamp_ms, e.id, e.object.clone()))
            .collect();

        for (fc_ts, fc_id, fc_path) in &file_creates {
            for (pc_ts, pc_id, pc_name) in &proc_creations {
                let delta = pc_ts - fc_ts;
                if delta >= 0 && delta <= window_ms {
                    // Check if process name matches file path (approximate)
                    let name_match = match (fc_path, pc_name) {
                        (Some(fp), Some(pn)) => {
                            let fp_lower = fp.to_ascii_lowercase();
                            let pn_lower = pn.to_ascii_lowercase();
                            fp_lower.contains(&pn_lower) || pn_lower.contains(&fp_lower)
                        }
                        _ => false,
                    };
                    let confidence = if name_match { 0.9 } else { 0.5 };
                    self.patterns.push(TemporalPattern {
                        pattern_type: PatternType::DropAndExecute,
                        events: vec![*fc_id, *pc_id],
                        start_ms: *fc_ts,
                        end_ms: *pc_ts,
                        confidence,
                        description: format!(
                            "File created then process spawned within {delta}ms"
                        ),
                    });
                }
            }
        }
    }

    fn detect_install_persistence(&mut self, window_ms: i64) {
        let proc_creates: Vec<(i64, u64)> = self.events.iter()
            .filter(|e| matches!(e.category, EventCategory::ProcessCreation))
            .map(|e| (e.timestamp_ms, e.id))
            .collect();

        let reg_mods: Vec<(i64, u64, Option<String>)> = self.events.iter()
            .filter(|e| matches!(
                e.category,
                EventCategory::RegistryCreate | EventCategory::RegistryModify
            ))
            .map(|e| (e.timestamp_ms, e.id, e.object.clone()))
            .collect();

        for (pc_ts, pc_id) in &proc_creates {
            for (rm_ts, rm_id, rm_key) in &reg_mods {
                let delta = rm_ts - pc_ts;
                if delta >= 0 && delta <= window_ms {
                    let is_persistence = rm_key.as_deref()
                        .is_some_and(|k| {
                            let kl = k.to_ascii_lowercase();
                            kl.contains("run") || kl.contains("startup") ||
                            kl.contains("services") || kl.contains("schedule")
                        });
                    if is_persistence {
                        self.patterns.push(TemporalPattern {
                            pattern_type: PatternType::InstallPersistence,
                            events: vec![*pc_id, *rm_id],
                            start_ms: *pc_ts,
                            end_ms: *rm_ts,
                            confidence: 0.85,
                            description: format!(
                                "Process created then wrote persistence registry key: {rm_key:?}"
                            ),
                        });
                    }
                }
            }
        }
    }

    fn detect_c2_beacon(&mut self, _window_ms: i64) {
        // Group NetworkConnect events by object (remote endpoint)
        let mut by_endpoint: HashMap<String, Vec<i64>> = HashMap::new();
        for ev in self.events.iter().filter(|e| matches!(e.category, EventCategory::NetworkConnect)) {
            if let Some(obj) = &ev.object {
                by_endpoint.entry(obj.clone()).or_default().push(ev.timestamp_ms);
            }
        }

        for (endpoint, mut times) in by_endpoint {
            times.sort_unstable();
            if times.len() < 3 {
                continue;
            }
            // Compute inter-arrival intervals
            let intervals: Vec<i64> = times.windows(2).map(|w| w[1] - w[0]).collect();
            let n_i64 = i64::try_from(intervals.len()).unwrap_or(i64::MAX).max(1);
            let mean = intervals.iter().sum::<i64>() / n_i64;
            let variance = intervals.iter().map(|&i| (i - mean).pow(2)).sum::<i64>() / n_i64;
            // Integer square root keeps precision and avoids float casts.
            let std_dev = variance.max(0).isqrt();
            // Compute regularity as a ratio kept in integer space where possible.
            // 1000 * (1 - std_dev / mean), clamped to [0, 1000], then divided by 1000.0.
            let regularity_milli: i64 = if mean > 0 {
                1000 - (std_dev.saturating_mul(1000) / mean).min(1000)
            } else {
                0
            };
            // Convert to f64 via i16 (regularity_milli is in 0..=1000).
            let regularity = f64::from(i16::try_from(regularity_milli).unwrap_or(1000)) / 1000.0;

            if regularity > 0.6 {
                let ids: Vec<u64> = self.events.iter()
                    .filter(|e| matches!(e.category, EventCategory::NetworkConnect)
                        && e.object.as_deref() == Some(&endpoint))
                    .map(|e| e.id)
                    .collect();
                self.patterns.push(TemporalPattern {
                    pattern_type: PatternType::C2Beacon,
                    events: ids,
                    start_ms: *times.first().unwrap(),
                    end_ms: *times.last().unwrap(),
                    confidence: f32::from(i16::try_from(regularity_milli).unwrap_or(1000)) / 1000.0,
                    description: format!(
                        "Beacon to {} — {} connections, mean interval {}ms, regularity {:.0}%",
                        endpoint,
                        times.len(),
                        mean,
                        regularity * 100.0
                    ),
                });
            }
        }
    }

    fn detect_data_exfiltration(&mut self, window_ms: i64) {
        let file_ops: Vec<(i64, u64)> = self.events.iter()
            .filter(|e| matches!(e.category, EventCategory::FileCreate | EventCategory::FileModify))
            .map(|e| (e.timestamp_ms, e.id))
            .collect();

        let net_ops: Vec<(i64, u64)> = self.events.iter()
            .filter(|e| matches!(e.category, EventCategory::NetworkConnect))
            .map(|e| (e.timestamp_ms, e.id))
            .collect();

        // Count file ops shortly before each network connection
        for (net_ts, net_id) in &net_ops {
            let preceding_file_ops: Vec<u64> = file_ops.iter()
                .filter(|(f_ts, _)| *net_ts - f_ts >= 0 && *net_ts - f_ts <= window_ms)
                .map(|(_, id)| *id)
                .collect();
            if preceding_file_ops.len() >= 3 {
                let min_ts = preceding_file_ops.iter()
                    .filter_map(|&id| self.events.iter().find(|e| e.id == id))
                    .map(|e| e.timestamp_ms)
                    .min()
                    .unwrap_or(*net_ts);
                let mut ev_ids = preceding_file_ops;
                ev_ids.push(*net_id);
                self.patterns.push(TemporalPattern {
                    pattern_type: PatternType::DataExfiltration,
                    events: ev_ids.clone(),
                    start_ms: min_ts,
                    end_ms: *net_ts,
                    confidence: 0.65,
                    description: format!(
                        "{} file operations followed by network connection — possible exfiltration",
                        ev_ids.len() - 1
                    ),
                });
            }
        }
    }

    #[must_use] 
    pub fn patterns(&self) -> &[TemporalPattern] {
        &self.patterns
    }

    // ── PLASO Export ──────────────────────────────────────────────────────────

    /// Export all events as PLASO L2T CSV.
    #[must_use] 
    pub fn export_plaso_csv(&self) -> String {
        let mut out = String::new();
        out.push_str("timestamp,timestamp_desc,source,source_long,message,parser,display_name,tag,inode,filename\n");
        let mut events = self.events.clone();
        events.sort_by_key(|e| e.timestamp_ms);
        for ev in &events {
            let record = event_to_plaso(ev);
            out.push_str(&record.to_csv_line());
        }
        out
    }

    // ── Summary ───────────────────────────────────────────────────────────────

    pub fn summary(&mut self) -> TimelineSummary {
        if !self.sorted { self.sort(); }
        let start = self.events.first().map_or(0, |e| e.timestamp_ms);
        let end = self.events.last().map_or(0, |e| e.timestamp_ms);

        let mut by_source: HashMap<String, usize> = HashMap::new();
        let mut by_category: HashMap<String, usize> = HashMap::new();
        for ev in &self.events {
            *by_source.entry(format!("{}", ev.source)).or_default() += 1;
            *by_category.entry(format!("{}", ev.category)).or_default() += 1;
        }

        TimelineSummary {
            total_events: self.events.len(),
            start_ms: start,
            end_ms: end,
            duration_ms: end - start,
            events_by_source: by_source,
            events_by_category: by_category,
            patterns_detected: self.patterns.len(),
            gaps_detected: self.gaps.len(),
            suspicious_gaps: self.suspicious_gaps().len(),
            critical_events: self.filter_by_severity(EventSeverity::Critical).len(),
            high_events: self.filter_by_severity(EventSeverity::High).len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineSummary {
    pub total_events: usize,
    pub start_ms: i64,
    pub end_ms: i64,
    pub duration_ms: i64,
    pub events_by_source: HashMap<String, usize>,
    pub events_by_category: HashMap<String, usize>,
    pub patterns_detected: usize,
    pub gaps_detected: usize,
    pub suspicious_gaps: usize,
    pub critical_events: usize,
    pub high_events: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add_event(
        tc: &mut TimelineCorrelator,
        ts: i64,
        src: EventSource,
        cat: EventCategory,
        sev: EventSeverity,
        desc: &str,
        actor: Option<&str>,
        obj: Option<&str>,
    ) -> u64 {
        tc.record(ts, src, cat, sev, desc, EventSubject { actor: actor.map(str::to_owned), object: obj.map(str::to_owned) })
    }

    #[test]
    fn test_basic_ingestion_and_sort() {
        let mut tc = TimelineCorrelator::new();
        add_event(&mut tc, 3000, EventSource::ProcessList, EventCategory::ProcessCreation, EventSeverity::Medium, "proc A", None, None);
        add_event(&mut tc, 1000, EventSource::Filesystem, EventCategory::FileCreate, EventSeverity::Low, "file B", None, None);
        add_event(&mut tc, 2000, EventSource::NetworkCapture, EventCategory::NetworkConnect, EventSeverity::High, "conn C", None, None);
        tc.sort();
        let evs = tc.events();
        assert_eq!(evs[0].timestamp_ms, 1000);
        assert_eq!(evs[1].timestamp_ms, 2000);
        assert_eq!(evs[2].timestamp_ms, 3000);
    }

    #[test]
    fn test_gap_detection() {
        let mut tc = TimelineCorrelator::new();
        add_event(&mut tc, 0, EventSource::Filesystem, EventCategory::FileCreate, EventSeverity::Low, "e1", None, None);
        add_event(&mut tc, 2 * 3600 * 1000, EventSource::NetworkCapture, EventCategory::NetworkConnect, EventSeverity::Low, "e2", None, None);
        tc.detect_gaps(60_000);
        assert_eq!(tc.gaps().len(), 1);
        assert!(matches!(tc.gaps()[0].significance, GapSignificance::Critical));
    }

    #[test]
    fn test_timestamp_normaliser_offset() {
        let mut norm = TimestampNormaliser::new();
        norm.set_offset(EventSource::WindowsEventLog, 500); // event log is 500ms ahead
        let raw = 10_000i64;
        let normalised = norm.normalise(raw, EventSource::WindowsEventLog);
        assert_eq!(normalised, 9_500);
    }

    #[test]
    fn test_persistence_pattern_detection() {
        let mut tc = TimelineCorrelator::new();
        add_event(&mut tc, 1000, EventSource::ProcessList, EventCategory::ProcessCreation, EventSeverity::Medium, "malware.exe", None, Some("malware.exe"));
        add_event(&mut tc, 1500, EventSource::Registry, EventCategory::RegistryCreate, EventSeverity::High, "reg run key", None, Some(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil"));
        tc.detect_patterns(5000);
        assert!(tc.patterns().iter().any(|p| p.pattern_type == PatternType::InstallPersistence));
    }

    #[test]
    fn test_plaso_export_format() {
        let mut tc = TimelineCorrelator::new();
        add_event(&mut tc, 1_000_000, EventSource::Filesystem, EventCategory::FileCreate, EventSeverity::Low, "created evil.exe", Some("explorer.exe"), Some("C:\\Temp\\evil.exe"));
        let csv = tc.export_plaso_csv();
        assert!(csv.contains("FileCreate"));
        assert!(csv.contains("evil.exe"));
    }

    #[test]
    fn test_c2_beacon_detection() {
        let mut tc = TimelineCorrelator::new();
        let base = 1_000_000i64;
        let interval = 60_000i64; // 60s intervals
        for i in 0..6 {
            add_event(
                &mut tc,
                base + i * interval,
                EventSource::NetworkCapture,
                EventCategory::NetworkConnect,
                EventSeverity::Medium,
                "beacon",
                Some("malware.exe"),
                Some("evil.com:443"),
            );
        }
        tc.detect_patterns(120_000);
        assert!(tc.patterns().iter().any(|p| p.pattern_type == PatternType::C2Beacon));
    }
}
