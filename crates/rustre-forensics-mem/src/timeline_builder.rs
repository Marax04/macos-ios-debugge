//! `timeline_builder` — Build a forensic timeline from memory artifacts.
//!
//! Provides [`TimelineBuilder`] which correlates [`ForensicEvent`]s from
//! multiple memory sources into a sorted [`ArtifactTimeline`].
//! [`EventCorrelator`] groups related events; [`TimelineReport`] summarizes
//! the results.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
/// Re-export of [`std::sync::Arc`] so timeline consumers can build shared
/// timeline handles without pulling in `std::sync` themselves.
pub use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::casts::{u128_to_u64, usize_to_f64};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TimelineError {
    #[error("no events")]
    NoEvents,
    #[error("duplicate event id: {0}")]
    DuplicateId(u64),
    #[error("invalid time range: start > end")]
    InvalidTimeRange,
    #[error("correlation error: {0}")]
    CorrelationError(String),
    #[error("report error: {0}")]
    ReportError(String),
}

// ─── EventSource ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventSource {
    ProcessList,
    ModuleList,
    NetworkConnections,
    RegistryActivity,
    FileActivity,
    MemoryRegions,
    Handles,
    Threads,
    Unknown,
}

impl fmt::Display for EventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── EventSeverity ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for EventSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── ForensicEvent ────────────────────────────────────────────────────────────

/// A single forensic event extracted from memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicEvent {
    pub id: u64,
    pub timestamp_ms: u64,
    pub source: EventSource,
    pub severity: EventSeverity,
    pub description: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub artifact: Option<String>,
    pub tags: Vec<String>,
    pub raw_offset: Option<u64>,
}

impl ForensicEvent {
    /// Current Unix wall-clock time in milliseconds. Used when ingesting
    /// live-collected events that need a timestamp synthesised by the
    /// timeline builder rather than supplied by the source.
    #[must_use]
    pub fn now_ms() -> u64 {
        u128_to_u64(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis())
    }

    pub fn new(
        id: u64,
        timestamp_ms: u64,
        source: EventSource,
        severity: EventSeverity,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id,
            timestamp_ms,
            source,
            severity,
            description: description.into(),
            pid: None,
            process_name: None,
            artifact: None,
            tags: Vec::new(),
            raw_offset: None,
        }
    }

    #[must_use] 
    pub const fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    #[must_use]
    pub fn with_process(mut self, name: impl Into<String>) -> Self {
        self.process_name = Some(name.into());
        self
    }

    #[must_use]
    pub fn with_artifact(mut self, art: impl Into<String>) -> Self {
        self.artifact = Some(art.into());
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use] 
    pub fn is_suspicious(&self) -> bool {
        self.severity >= EventSeverity::High
    }

    #[must_use] 
    pub const fn age_from(&self, base_ms: u64) -> u64 {
        self.timestamp_ms.saturating_sub(base_ms)
    }
}

impl fmt::Display for ForensicEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}ms] {} ({}) {}",
            self.timestamp_ms, self.source, self.severity, self.description
        )
    }
}

// ─── TimelineEntry ────────────────────────────────────────────────────────────

/// An annotated entry in the final timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub event: ForensicEvent,
    pub sequence_number: u64,
    pub correlated_ids: Vec<u64>,
    pub note: Option<String>,
}

impl TimelineEntry {
    #[must_use] 
    pub const fn new(event: ForensicEvent, seq: u64) -> Self {
        Self {
            event,
            sequence_number: seq,
            correlated_ids: Vec::new(),
            note: None,
        }
    }

    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    pub fn correlate_with(&mut self, id: u64) {
        if !self.correlated_ids.contains(&id) {
            self.correlated_ids.push(id);
        }
    }

    #[must_use] 
    pub const fn is_isolated(&self) -> bool {
        self.correlated_ids.is_empty()
    }
}

// ─── ArtifactTimeline ─────────────────────────────────────────────────────────

/// A sorted, annotated list of forensic events.
#[derive(Debug, Default)]
pub struct ArtifactTimeline {
    entries: Vec<TimelineEntry>,
    start_ms: u64,
    end_ms: u64,
}

impl ArtifactTimeline {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn from_entries(mut entries: Vec<TimelineEntry>) -> Self {
        entries.sort_by_key(|e| e.event.timestamp_ms);
        let start_ms = entries.first().map_or(0, |e| e.event.timestamp_ms);
        let end_ms = entries.last().map_or(0, |e| e.event.timestamp_ms);
        Self {
            entries,
            start_ms,
            end_ms,
        }
    }

    pub fn add(&mut self, entry: TimelineEntry) {
        let ts = entry.event.timestamp_ms;
        self.entries.push(entry);
        self.entries.sort_by_key(|e| e.event.timestamp_ms);
        if ts < self.start_ms || self.start_ms == 0 {
            self.start_ms = ts;
        }
        if ts > self.end_ms {
            self.end_ms = ts;
        }
    }

    #[must_use] 
    pub fn entries(&self) -> &[TimelineEntry] {
        &self.entries
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use] 
    pub const fn start_ms(&self) -> u64 {
        self.start_ms
    }

    #[must_use] 
    pub const fn end_ms(&self) -> u64 {
        self.end_ms
    }

    #[must_use] 
    pub const fn duration_ms(&self) -> u64 {
        self.end_ms.saturating_sub(self.start_ms)
    }

    #[must_use] 
    pub fn filter_by_source(&self, source: EventSource) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.event.source == source)
            .collect()
    }

    #[must_use] 
    pub fn filter_by_severity(&self, min: EventSeverity) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.event.severity >= min)
            .collect()
    }

    #[must_use] 
    pub fn filter_by_pid(&self, pid: u32) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.event.pid == Some(pid))
            .collect()
    }

    #[must_use] 
    pub fn filter_time_range(&self, start: u64, end: u64) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.event.timestamp_ms >= start && e.event.timestamp_ms <= end)
            .collect()
    }

    #[must_use] 
    pub fn suspicious_entries(&self) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.event.is_suspicious())
            .collect()
    }

    #[must_use]
    pub fn unique_pids(&self) -> Vec<u32> {
        // Use BTreeSet instead of HashSet: PID values come from untrusted
        // memory images and an attacker can craft collisions in a HashSet,
        // causing O(n) per-insert degradation (DoS).
        let mut pids: Vec<u32> = self
            .entries
            .iter()
            .filter_map(|e| e.event.pid)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        pids.sort_unstable();
        pids
    }

    #[must_use] 
    pub fn event_count_by_source(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for e in &self.entries {
            *map.entry(e.event.source.to_string()).or_insert(0) += 1;
        }
        map
    }
}

// ─── CorrelationRule ──────────────────────────────────────────────────────────

/// Defines how events should be grouped/correlated.
#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub name: String,
    pub time_window_ms: u64,
    pub required_sources: Vec<EventSource>,
    pub description_keywords: Vec<String>,
}

impl CorrelationRule {
    pub fn new(name: impl Into<String>, time_window_ms: u64) -> Self {
        Self {
            name: name.into(),
            time_window_ms,
            required_sources: Vec::new(),
            description_keywords: Vec::new(),
        }
    }

    #[must_use] 
    pub fn with_sources(mut self, sources: Vec<EventSource>) -> Self {
        self.required_sources = sources;
        self
    }

    #[must_use] 
    pub fn with_keywords(mut self, kws: Vec<String>) -> Self {
        self.description_keywords = kws;
        self
    }
}

// ─── EventCorrelator ──────────────────────────────────────────────────────────

/// Groups related forensic events together.
#[derive(Debug, Default)]
pub struct EventCorrelator {
    rules: Vec<CorrelationRule>,
}

impl EventCorrelator {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
    }

    #[must_use] 
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Correlate events in-place; returns number of correlations made.
    pub fn correlate(&self, timeline: &mut ArtifactTimeline) -> usize {
        let mut count = 0usize;
        for rule in &self.rules {
            count += Self::apply_rule(rule, timeline);
        }
        count
    }

    fn apply_rule(rule: &CorrelationRule, timeline: &mut ArtifactTimeline) -> usize {
        let mut count = 0;
        let n = timeline.entries.len();
        // Naive O(n²) for simplicity
        for i in 0..n {
            for j in i + 1..n {
                let ti = timeline.entries[i].event.timestamp_ms;
                let tj = timeline.entries[j].event.timestamp_ms;
                if tj.saturating_sub(ti) > rule.time_window_ms {
                    break; // timeline is sorted
                }
                // Check sources
                let si = timeline.entries[i].event.source;
                let sj = timeline.entries[j].event.source;
                let source_match = rule.required_sources.is_empty()
                    || (rule.required_sources.contains(&si) && rule.required_sources.contains(&sj));
                if !source_match {
                    continue;
                }
                // Correlate
                let id_i = timeline.entries[i].event.id;
                let id_j = timeline.entries[j].event.id;
                timeline.entries[i].correlate_with(id_j);
                timeline.entries[j].correlate_with(id_i);
                count += 1;
            }
        }
        count
    }

    /// Group events by PID proximity.
    #[must_use]
    pub fn group_by_pid(&self, timeline: &ArtifactTimeline) -> BTreeMap<u32, Vec<u64>> {
        // BTreeMap avoids hash-collision DoS: PIDs come from untrusted memory
        // images and an attacker can craft them to collide in a HashMap.
        let mut groups: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
        for entry in timeline.entries() {
            if let Some(pid) = entry.event.pid {
                groups.entry(pid).or_default().push(entry.event.id);
            }
        }
        groups
    }
}

// ─── TimelineReport ───────────────────────────────────────────────────────────

/// Summary report produced from an [`ArtifactTimeline`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineReport {
    pub total_events: usize,
    pub suspicious_events: usize,
    pub duration_ms: u64,
    pub event_sources: HashMap<String, usize>,
    pub severity_distribution: HashMap<String, usize>,
    pub top_pids: Vec<(u32, usize)>,
    pub first_event_ms: u64,
    pub last_event_ms: u64,
    pub summary: String,
}

impl TimelineReport {
    #[must_use] 
    pub fn from_timeline(tl: &ArtifactTimeline) -> Self {
        let total = tl.len();
        let suspicious = tl.suspicious_entries().len();
        let mut sev_dist: HashMap<String, usize> = HashMap::new();
        // BTreeMap: PID keys come from untrusted memory; HashMap is vulnerable
        // to hash-collision DoS when an attacker controls the key values.
        let mut pid_count: BTreeMap<u32, usize> = BTreeMap::new();

        for entry in tl.entries() {
            *sev_dist
                .entry(entry.event.severity.to_string())
                .or_insert(0) += 1;
            if let Some(pid) = entry.event.pid {
                *pid_count.entry(pid).or_insert(0) += 1;
            }
        }

        let mut top_pids: Vec<(u32, usize)> = pid_count.into_iter().collect();
        top_pids.sort_by(|a, b| b.1.cmp(&a.1));
        top_pids.truncate(5);

        let summary = format!(
            "{} events ({} suspicious) over {}ms, {} sources",
            total,
            suspicious,
            tl.duration_ms(),
            tl.event_count_by_source().len()
        );

        Self {
            total_events: total,
            suspicious_events: suspicious,
            duration_ms: tl.duration_ms(),
            event_sources: tl.event_count_by_source(),
            severity_distribution: sev_dist,
            top_pids,
            first_event_ms: tl.start_ms(),
            last_event_ms: tl.end_ms(),
            summary,
        }
    }

    #[must_use] 
    pub fn malicious_rate(&self) -> f64 {
        if self.total_events == 0 {
            0.0
        } else {
            usize_to_f64(self.suspicious_events) / usize_to_f64(self.total_events)
        }
    }
}

// ─── TimelineBuilder ──────────────────────────────────────────────────────────

/// Assembles a forensic timeline from multiple raw event streams.
#[derive(Debug)]
pub struct TimelineBuilder {
    events: Mutex<Vec<ForensicEvent>>,
    correlator: EventCorrelator,
    next_seq: std::sync::atomic::AtomicU64,
}

impl TimelineBuilder {
    #[must_use] 
    pub fn new() -> Self {
        let mut correlator = EventCorrelator::new();
        // Default rule: correlate events within 5 seconds
        correlator.add_rule(CorrelationRule::new("proximity_5s", 5000));
        Self {
            events: Mutex::new(Vec::new()),
            correlator,
            next_seq: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn add_event(&self, event: ForensicEvent) {
        self.events.lock().push(event);
    }

    pub fn add_events(&self, events: impl IntoIterator<Item = ForensicEvent>) {
        let mut lock = self.events.lock();
        lock.extend(events);
    }

    pub fn event_count(&self) -> usize {
        self.events.lock().len()
    }

    pub fn clear(&self) {
        self.events.lock().clear();
    }

    pub const fn correlator_mut(&mut self) -> &mut EventCorrelator {
        &mut self.correlator
    }

    /// Build the final timeline, applying correlation.
    ///
    /// # Errors
    /// Returns [`TimelineError::NoEvents`] if no events have been ingested.
    pub fn build(&self) -> Result<ArtifactTimeline, TimelineError> {
        let events = self.events.lock().clone();
        if events.is_empty() {
            return Err(TimelineError::NoEvents);
        }

        // Build entries with sequence numbers
        let mut entries: Vec<TimelineEntry> = events
            .into_iter()
            .map(|ev| {
                let seq = self
                    .next_seq
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                TimelineEntry::new(ev, seq)
            })
            .collect();

        // Sort by timestamp
        entries.sort_by_key(|e| e.event.timestamp_ms);

        let mut timeline = ArtifactTimeline::from_entries(entries);
        self.correlator.correlate(&mut timeline);

        Ok(timeline)
    }

    /// Build timeline and produce report.
    ///
    /// # Errors
    /// Returns [`TimelineError::NoEvents`] if no events have been ingested.
    pub fn build_report(&self) -> Result<(ArtifactTimeline, TimelineReport), TimelineError> {
        let tl = self.build()?;
        let report = TimelineReport::from_timeline(&tl);
        Ok((tl, report))
    }

    /// Convenience: build a synthetic process-spawn event.
    pub fn process_event(
        id: u64,
        ts: u64,
        pid: u32,
        name: impl Into<String>,
        severity: EventSeverity,
    ) -> ForensicEvent {
        ForensicEvent::new(
            id,
            ts,
            EventSource::ProcessList,
            severity,
            "process observed",
        )
        .with_pid(pid)
        .with_process(name)
    }

    /// Convenience: build a network connection event.
    pub fn network_event(id: u64, ts: u64, description: impl Into<String>) -> ForensicEvent {
        ForensicEvent::new(
            id,
            ts,
            EventSource::NetworkConnections,
            EventSeverity::Medium,
            description,
        )
    }
}

impl Default for TimelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(id: u64, ts: u64, sev: EventSeverity) -> ForensicEvent {
        ForensicEvent::new(
            id,
            ts,
            EventSource::ProcessList,
            sev,
            format!("event {id}"),
        )
    }

    fn make_builder_with_events() -> TimelineBuilder {
        let b = TimelineBuilder::new();
        b.add_event(make_event(1, 1000, EventSeverity::Info));
        b.add_event(make_event(2, 2000, EventSeverity::High));
        b.add_event(make_event(3, 3000, EventSeverity::Critical));
        b
    }

    // --- ForensicEvent ---

    #[test]
    fn test_event_new() {
        let ev = make_event(1, 1000, EventSeverity::Info);
        assert_eq!(ev.id, 1);
        assert_eq!(ev.timestamp_ms, 1000);
        assert!(!ev.is_suspicious());
    }

    #[test]
    fn test_event_is_suspicious() {
        let ev = make_event(1, 0, EventSeverity::High);
        assert!(ev.is_suspicious());
        let ev2 = make_event(2, 0, EventSeverity::Critical);
        assert!(ev2.is_suspicious());
    }

    #[test]
    fn test_event_with_pid_process() {
        let ev = make_event(1, 0, EventSeverity::Info)
            .with_pid(1234)
            .with_process("explorer.exe");
        assert_eq!(ev.pid, Some(1234));
        assert_eq!(ev.process_name.as_deref(), Some("explorer.exe"));
    }

    #[test]
    fn test_event_with_artifact() {
        let ev = make_event(1, 0, EventSeverity::Info).with_artifact("C:\\malware.exe");
        assert!(ev.artifact.is_some());
    }

    #[test]
    fn test_event_with_tag() {
        let ev = make_event(1, 0, EventSeverity::Info)
            .with_tag("injection")
            .with_tag("hollowing");
        assert_eq!(ev.tags.len(), 2);
    }

    #[test]
    fn test_event_age_from() {
        let ev = make_event(1, 5000, EventSeverity::Info);
        assert_eq!(ev.age_from(1000), 4000);
    }

    #[test]
    fn test_event_display() {
        let ev = make_event(1, 1234, EventSeverity::Medium);
        let s = ev.to_string();
        assert!(s.contains("1234ms"));
    }

    // --- TimelineEntry ---

    #[test]
    fn test_entry_is_isolated() {
        let entry = TimelineEntry::new(make_event(1, 0, EventSeverity::Info), 1);
        assert!(entry.is_isolated());
    }

    #[test]
    fn test_entry_correlate_with() {
        let mut entry = TimelineEntry::new(make_event(1, 0, EventSeverity::Info), 1);
        entry.correlate_with(2);
        entry.correlate_with(2); // duplicate
        assert_eq!(entry.correlated_ids, vec![2]);
    }

    #[test]
    fn test_entry_with_note() {
        let entry = TimelineEntry::new(make_event(1, 0, EventSeverity::Info), 1)
            .with_note("suspicious hollow");
        assert!(entry.note.is_some());
    }

    // --- ArtifactTimeline ---

    #[test]
    fn test_timeline_sorted_by_timestamp() {
        let entries = vec![
            TimelineEntry::new(make_event(2, 300, EventSeverity::Info), 2),
            TimelineEntry::new(make_event(1, 100, EventSeverity::Info), 1),
        ];
        let tl = ArtifactTimeline::from_entries(entries);
        assert_eq!(tl.entries[0].event.timestamp_ms, 100);
        assert_eq!(tl.entries[1].event.timestamp_ms, 300);
    }

    #[test]
    fn test_timeline_duration() {
        let mut tl = ArtifactTimeline::new();
        tl.add(TimelineEntry::new(
            make_event(1, 1000, EventSeverity::Info),
            1,
        ));
        tl.add(TimelineEntry::new(
            make_event(2, 5000, EventSeverity::Info),
            2,
        ));
        assert_eq!(tl.duration_ms(), 4000);
    }

    #[test]
    fn test_timeline_filter_by_source() {
        let mut tl = ArtifactTimeline::new();
        tl.add(TimelineEntry::new(
            ForensicEvent::new(1, 0, EventSource::ProcessList, EventSeverity::Info, "p"),
            1,
        ));
        tl.add(TimelineEntry::new(
            ForensicEvent::new(
                2,
                0,
                EventSource::NetworkConnections,
                EventSeverity::Info,
                "n",
            ),
            2,
        ));
        assert_eq!(tl.filter_by_source(EventSource::ProcessList).len(), 1);
    }

    #[test]
    fn test_timeline_filter_by_severity() {
        let b = make_builder_with_events();
        let tl = b.build().unwrap();
        let high = tl.filter_by_severity(EventSeverity::High);
        assert_eq!(high.len(), 2); // High + Critical
    }

    #[test]
    fn test_timeline_filter_by_pid() {
        let mut tl = ArtifactTimeline::new();
        let ev = make_event(1, 0, EventSeverity::Info).with_pid(123);
        tl.add(TimelineEntry::new(ev, 1));
        assert_eq!(tl.filter_by_pid(123).len(), 1);
        assert_eq!(tl.filter_by_pid(999).len(), 0);
    }

    #[test]
    fn test_timeline_filter_time_range() {
        let b = make_builder_with_events();
        let tl = b.build().unwrap();
        let range = tl.filter_time_range(1500, 2500);
        assert_eq!(range.len(), 1);
    }

    #[test]
    fn test_timeline_suspicious_entries() {
        let b = make_builder_with_events();
        let tl = b.build().unwrap();
        assert_eq!(tl.suspicious_entries().len(), 2);
    }

    #[test]
    fn test_timeline_unique_pids() {
        let mut tl = ArtifactTimeline::new();
        tl.add(TimelineEntry::new(
            make_event(1, 0, EventSeverity::Info).with_pid(100),
            1,
        ));
        tl.add(TimelineEntry::new(
            make_event(2, 0, EventSeverity::Info).with_pid(100),
            2,
        ));
        tl.add(TimelineEntry::new(
            make_event(3, 0, EventSeverity::Info).with_pid(200),
            3,
        ));
        let pids = tl.unique_pids();
        assert_eq!(pids.len(), 2);
    }

    // --- EventCorrelator ---

    #[test]
    fn test_correlator_correlates_close_events() {
        let mut correlator = EventCorrelator::new();
        correlator.add_rule(CorrelationRule::new("test", 2000));
        let b = make_builder_with_events();
        let mut tl = b.build().unwrap();
        let n = correlator.correlate(&mut tl);
        assert!(n > 0);
    }

    #[test]
    fn test_correlator_group_by_pid() {
        let correlator = EventCorrelator::new();
        let mut tl = ArtifactTimeline::new();
        tl.add(TimelineEntry::new(
            make_event(1, 0, EventSeverity::Info).with_pid(10),
            1,
        ));
        tl.add(TimelineEntry::new(
            make_event(2, 0, EventSeverity::Info).with_pid(10),
            2,
        ));
        let groups = correlator.group_by_pid(&tl);
        assert_eq!(groups[&10].len(), 2);
    }

    // --- TimelineBuilder ---

    #[test]
    fn test_builder_build() {
        let b = make_builder_with_events();
        let tl = b.build().unwrap();
        assert_eq!(tl.len(), 3);
    }

    #[test]
    fn test_builder_empty_returns_error() {
        let b = TimelineBuilder::new();
        assert!(matches!(b.build(), Err(TimelineError::NoEvents)));
    }

    #[test]
    fn test_builder_event_count() {
        let b = make_builder_with_events();
        assert_eq!(b.event_count(), 3);
    }

    #[test]
    fn test_builder_clear() {
        let b = make_builder_with_events();
        b.clear();
        assert_eq!(b.event_count(), 0);
    }

    #[test]
    fn test_builder_build_report() {
        let b = make_builder_with_events();
        let (tl, report) = b.build_report().unwrap();
        assert_eq!(report.total_events, tl.len());
        assert!(report.suspicious_events > 0);
    }

    #[test]
    fn test_builder_process_event() {
        let ev = TimelineBuilder::process_event(1, 1000, 42, "svchost.exe", EventSeverity::Low);
        assert_eq!(ev.pid, Some(42));
        assert_eq!(ev.process_name.as_deref(), Some("svchost.exe"));
    }

    #[test]
    fn test_builder_network_event() {
        let ev = TimelineBuilder::network_event(1, 2000, "outbound connection");
        assert_eq!(ev.source, EventSource::NetworkConnections);
        assert_eq!(ev.severity, EventSeverity::Medium);
    }

    // --- TimelineReport ---

    #[test]
    fn test_report_malicious_rate() {
        let b = make_builder_with_events();
        let tl = b.build().unwrap();
        let report = TimelineReport::from_timeline(&tl);
        let rate = report.malicious_rate();
        assert!(rate > 0.0 && rate <= 1.0);
    }

    #[test]
    fn test_report_summary_non_empty() {
        let b = make_builder_with_events();
        let tl = b.build().unwrap();
        let report = TimelineReport::from_timeline(&tl);
        assert!(!report.summary.is_empty());
    }

    #[test]
    fn test_report_zero_events_rate() {
        let report = TimelineReport {
            total_events: 0,
            suspicious_events: 0,
            duration_ms: 0,
            event_sources: HashMap::new(),
            severity_distribution: HashMap::new(),
            top_pids: vec![],
            first_event_ms: 0,
            last_event_ms: 0,
            summary: String::new(),
        };
        assert_eq!(report.malicious_rate(), 0.0);
    }

    #[test]
    fn test_event_source_display() {
        assert_eq!(EventSource::ProcessList.to_string(), "ProcessList");
        assert_eq!(
            EventSource::NetworkConnections.to_string(),
            "NetworkConnections"
        );
    }

    #[test]
    fn test_severity_ordering() {
        assert!(EventSeverity::Critical > EventSeverity::High);
        assert!(EventSeverity::High > EventSeverity::Medium);
        assert!(EventSeverity::Medium > EventSeverity::Low);
        assert!(EventSeverity::Low > EventSeverity::Info);
    }

    #[test]
    fn test_timeline_event_count_by_source() {
        let b = make_builder_with_events();
        let tl = b.build().unwrap();
        let counts = tl.event_count_by_source();
        assert!(counts.contains_key("ProcessList"));
    }

    #[test]
    fn test_builder_add_events_batch() {
        let b = TimelineBuilder::new();
        let events = vec![
            make_event(1, 100, EventSeverity::Info),
            make_event(2, 200, EventSeverity::Info),
        ];
        b.add_events(events);
        assert_eq!(b.event_count(), 2);
    }

    #[test]
    fn test_report_severity_distribution() {
        let b = make_builder_with_events();
        let tl = b.build().unwrap();
        let report = TimelineReport::from_timeline(&tl);
        assert!(report.severity_distribution.contains_key("Info"));
    }

    #[test]
    fn test_correlation_rule_with_sources() {
        let rule = CorrelationRule::new("test", 1000).with_sources(vec![
            EventSource::ProcessList,
            EventSource::NetworkConnections,
        ]);
        assert_eq!(rule.required_sources.len(), 2);
    }

    #[test]
    fn test_event_with_raw_offset() {
        let mut ev = make_event(1, 0, EventSeverity::Info);
        ev.raw_offset = Some(0xDEADBEEF);
        assert_eq!(ev.raw_offset, Some(0xDEADBEEF));
    }
}
