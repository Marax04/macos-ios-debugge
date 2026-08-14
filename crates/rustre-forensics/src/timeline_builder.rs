//! `timeline_builder` — unified forensic timeline from an artifact store.
//!
//! Provides [`ForensicTimeline`], [`TimelineEvent`], [`TimelineBuilder`],
//! and [`TimelineFilter`] for constructing and querying a merged event
//! timeline from multiple forensic artifact sources.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ─── EventCategory ────────────────────────────────────────────────────────────

/// Broad category for a timeline event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventCategory {
    FileSystem,
    Registry,
    Network,
    Process,
    Memory,
    Authentication,
    Service,
    Scheduled,
    Crypto,
    Custom(String),
}

impl std::fmt::Display for EventCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileSystem => write!(f, "filesystem"),
            Self::Registry => write!(f, "registry"),
            Self::Network => write!(f, "network"),
            Self::Process => write!(f, "process"),
            Self::Memory => write!(f, "memory"),
            Self::Authentication => write!(f, "authentication"),
            Self::Service => write!(f, "service"),
            Self::Scheduled => write!(f, "scheduled"),
            Self::Crypto => write!(f, "crypto"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

// ─── EventSeverity ────────────────────────────────────────────────────────────

/// Severity level for a timeline event (0 = informational, 100 = critical).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EventSeverity(pub u8);

impl EventSeverity {
    pub const INFO: Self = Self(0);
    pub const LOW: Self = Self(25);
    pub const MEDIUM: Self = Self(50);
    pub const HIGH: Self = Self(75);
    pub const CRITICAL: Self = Self(100);

    /// Create a severity clamped to `[0, 100]`.
    #[must_use]
    pub fn new(v: u8) -> Self {
        Self(v.min(100))
    }

    /// Numeric value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Returns `true` if this severity is at or above `threshold`.
    #[must_use]
    pub const fn at_least(self, threshold: Self) -> bool {
        self.0 >= threshold.0
    }
}

impl std::fmt::Display for EventSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0..=24 => write!(f, "info"),
            25..=49 => write!(f, "low"),
            50..=74 => write!(f, "medium"),
            75..=99 => write!(f, "high"),
            _ => write!(f, "critical"),
        }
    }
}

// ─── TimelineEvent ────────────────────────────────────────────────────────────

/// A single event on the forensic timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Unix timestamp in milliseconds.
    pub timestamp: u64,
    /// Originating artifact source (e.g. "`EventLog`", "`PrefetchDB`").
    pub source: String,
    /// Broad category.
    pub category: EventCategory,
    /// Human-readable description.
    pub description: String,
    /// Severity level.
    pub severity: EventSeverity,
    /// Optional actor (user, process name, etc.).
    pub actor: Option<String>,
    /// Linked artifact IDs for cross-referencing.
    pub artifact_ids: Vec<String>,
}

impl TimelineEvent {
    /// Construct a minimal event.
    #[must_use]
    pub fn new(
        timestamp: u64,
        source: impl Into<String>,
        category: EventCategory,
        description: impl Into<String>,
        severity: EventSeverity,
    ) -> Self {
        Self {
            timestamp,
            source: source.into(),
            category,
            description: description.into(),
            severity,
            actor: None,
            artifact_ids: Vec::new(),
        }
    }

    /// Attach an actor name.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Link an artifact ID.
    #[must_use]
    pub fn with_artifact(mut self, id: impl Into<String>) -> Self {
        self.artifact_ids.push(id.into());
        self
    }
}

// ─── TimelineFilter ───────────────────────────────────────────────────────────

/// Predicate for selecting events from a timeline.
#[derive(Debug, Clone, Default)]
pub struct TimelineFilter {
    /// Only include events at or after this timestamp (ms).
    pub start_ts: Option<u64>,
    /// Only include events at or before this timestamp (ms).
    pub end_ts: Option<u64>,
    /// Only include events with this category.
    pub category: Option<EventCategory>,
    /// Only include events whose severity is at least this value.
    pub min_severity: Option<EventSeverity>,
    /// Only include events from this source.
    pub source: Option<String>,
}

impl TimelineFilter {
    /// Create an empty (pass-all) filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to a time range.
    #[must_use]
    pub const fn with_time_range(mut self, start: u64, end: u64) -> Self {
        self.start_ts = Some(start);
        self.end_ts = Some(end);
        self
    }

    /// Restrict to a category.
    #[must_use]
    pub fn with_category(mut self, cat: EventCategory) -> Self {
        self.category = Some(cat);
        self
    }

    /// Restrict to a minimum severity.
    #[must_use]
    pub const fn with_min_severity(mut self, s: EventSeverity) -> Self {
        self.min_severity = Some(s);
        self
    }

    /// Restrict to a specific source.
    #[must_use]
    pub fn with_source(mut self, src: impl Into<String>) -> Self {
        self.source = Some(src.into());
        self
    }

    /// Returns `true` if `event` passes all active predicates.
    #[must_use]
    pub fn matches(&self, event: &TimelineEvent) -> bool {
        if let Some(s) = self.start_ts
            && event.timestamp < s {
                return false;
            }
        if let Some(e) = self.end_ts
            && event.timestamp > e {
                return false;
            }
        if let Some(ref cat) = self.category
            && &event.category != cat {
                return false;
            }
        if let Some(min) = self.min_severity
            && !event.severity.at_least(min) {
                return false;
            }
        if let Some(ref src) = self.source
            && &event.source != src {
                return false;
            }
        true
    }
}

// ─── ForensicTimeline ─────────────────────────────────────────────────────────

/// A chronologically-ordered collection of [`TimelineEvent`]s.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ForensicTimeline {
    events: Vec<TimelineEvent>,
}

impl ForensicTimeline {
    /// Create an empty timeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an event (does not auto-sort; call [`Self::sort`] when done adding).
    pub fn add_event(&mut self, event: TimelineEvent) {
        self.events.push(event);
    }

    /// Sort events by timestamp ascending.
    pub fn sort(&mut self) {
        self.events.sort_by_key(|e| e.timestamp);
    }

    /// Number of events.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` if the timeline has no events.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Access all events as a slice.
    #[must_use]
    pub fn events(&self) -> &[TimelineEvent] {
        &self.events
    }

    /// Apply a filter and return matching events.
    #[must_use]
    pub fn filter<'a>(&'a self, f: &TimelineFilter) -> Vec<&'a TimelineEvent> {
        self.events.iter().filter(|e| f.matches(e)).collect()
    }

    /// Return events in a timestamp range `[start_ms, end_ms]`.
    #[must_use]
    pub fn events_in_range(&self, start_ms: u64, end_ms: u64) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= start_ms && e.timestamp <= end_ms)
            .collect()
    }

    /// Return events whose severity is at or above `threshold`.
    #[must_use]
    pub fn high_severity(&self, threshold: EventSeverity) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.severity.at_least(threshold))
            .collect()
    }

    /// Return all events from `source`.
    #[must_use]
    pub fn events_from_source(&self, source: &str) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| e.source == source).collect()
    }

    /// Export all events as JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.events).unwrap_or_default()
    }

    /// Export all events as CSV.
    ///
    /// Columns: `timestamp_ms,source,category,severity,description`
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = String::from("timestamp_ms,source,category,severity,description\n");
        for e in &self.events {
            let desc = e.description.replace('"', "\"\"");
            let _ = writeln!(
                out,
                "{},{},{},{},\"{}\"",
                e.timestamp,
                csv_escape(&e.source),
                e.category,
                e.severity,
                desc,
            );
        }
        out
    }

    /// Merge another timeline into this one and sort the result.
    pub fn merge(&mut self, other: Self) {
        self.events.extend(other.events);
        self.sort();
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ─── ArtifactEntry ────────────────────────────────────────────────────────────

/// Minimal artifact descriptor used by [`TimelineBuilder`].
#[derive(Debug, Clone)]
pub struct ArtifactEntry {
    pub id: String,
    pub source: String,
    pub timestamp: Option<u64>,
    pub category: EventCategory,
    pub description: String,
    pub severity: EventSeverity,
}

// ─── TimelineBuilder ──────────────────────────────────────────────────────────

/// Constructs a [`ForensicTimeline`] from a collection of artifact descriptors.
#[derive(Debug, Default)]
pub struct TimelineBuilder {
    artifacts: Vec<ArtifactEntry>,
    default_source: String,
}

impl TimelineBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            artifacts: Vec::new(),
            default_source: "unknown".to_string(),
        }
    }

    /// Set the default source label used when an artifact has none.
    #[must_use]
    pub fn with_default_source(mut self, src: impl Into<String>) -> Self {
        self.default_source = src.into();
        self
    }

    /// Add an artifact entry.
    pub fn add_artifact(&mut self, entry: ArtifactEntry) {
        self.artifacts.push(entry);
    }

    /// Add multiple artifact entries.
    pub fn add_artifacts(&mut self, entries: impl IntoIterator<Item = ArtifactEntry>) {
        self.artifacts.extend(entries);
    }

    /// Build the timeline. Artifacts without a timestamp are placed at `t=0`.
    #[must_use]
    pub fn build(self) -> ForensicTimeline {
        let mut tl = ForensicTimeline::new();
        let default_src = self.default_source.clone();
        for art in self.artifacts {
            let ts = art.timestamp.unwrap_or(0);
            let src = if art.source.is_empty() {
                default_src.clone()
            } else {
                art.source
            };
            let ev = TimelineEvent::new(ts, src, art.category, art.description, art.severity)
                .with_artifact(art.id);
            tl.add_event(ev);
        }
        tl.sort();
        tl
    }

    /// Number of queued artifacts.
    #[must_use]
    pub const fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(ts: u64, cat: EventCategory, sev: EventSeverity) -> TimelineEvent {
        TimelineEvent::new(ts, "test-source", cat, "test event", sev)
    }

    // ── EventSeverity ───────────────────────────────────────────────────────

    #[test]
    fn test_severity_ordering() {
        assert!(EventSeverity::CRITICAL > EventSeverity::HIGH);
        assert!(EventSeverity::HIGH > EventSeverity::MEDIUM);
        assert!(EventSeverity::MEDIUM > EventSeverity::LOW);
    }

    #[test]
    fn test_severity_at_least() {
        assert!(EventSeverity::HIGH.at_least(EventSeverity::MEDIUM));
        assert!(!EventSeverity::LOW.at_least(EventSeverity::MEDIUM));
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(EventSeverity::INFO.to_string(), "info");
        assert_eq!(EventSeverity::CRITICAL.to_string(), "critical");
        assert_eq!(EventSeverity(50).to_string(), "medium");
    }

    // ── EventCategory ───────────────────────────────────────────────────────

    #[test]
    fn test_category_display() {
        assert_eq!(EventCategory::Network.to_string(), "network");
        assert_eq!(EventCategory::Custom("ioc".into()).to_string(), "ioc");
    }

    // ── TimelineEvent ───────────────────────────────────────────────────────

    #[test]
    fn test_event_with_actor_and_artifact() {
        let e = TimelineEvent::new(
            1000,
            "src",
            EventCategory::Process,
            "spawned",
            EventSeverity::MEDIUM,
        )
        .with_actor("SYSTEM")
        .with_artifact("art-001");
        assert_eq!(e.actor.as_deref(), Some("SYSTEM"));
        assert_eq!(e.artifact_ids[0], "art-001");
    }

    // ── TimelineFilter ──────────────────────────────────────────────────────

    #[test]
    fn test_filter_time_range() {
        let f = TimelineFilter::new().with_time_range(500, 1500);
        let ev_in = make_event(1000, EventCategory::Network, EventSeverity::LOW);
        let ev_out = make_event(2000, EventCategory::Network, EventSeverity::LOW);
        assert!(f.matches(&ev_in));
        assert!(!f.matches(&ev_out));
    }

    #[test]
    fn test_filter_category() {
        let f = TimelineFilter::new().with_category(EventCategory::Registry);
        let match_ev = make_event(100, EventCategory::Registry, EventSeverity::LOW);
        let no_match = make_event(100, EventCategory::Network, EventSeverity::LOW);
        assert!(f.matches(&match_ev));
        assert!(!f.matches(&no_match));
    }

    #[test]
    fn test_filter_min_severity() {
        let f = TimelineFilter::new().with_min_severity(EventSeverity::HIGH);
        let high = make_event(0, EventCategory::Process, EventSeverity::CRITICAL);
        let low = make_event(0, EventCategory::Process, EventSeverity::LOW);
        assert!(f.matches(&high));
        assert!(!f.matches(&low));
    }

    // ── ForensicTimeline ────────────────────────────────────────────────────

    #[test]
    fn test_timeline_add_and_sort() {
        let mut tl = ForensicTimeline::new();
        tl.add_event(make_event(300, EventCategory::Network, EventSeverity::LOW));
        tl.add_event(make_event(100, EventCategory::Network, EventSeverity::LOW));
        tl.sort();
        assert_eq!(tl.events()[0].timestamp, 100);
    }

    #[test]
    fn test_timeline_events_in_range() {
        let mut tl = ForensicTimeline::new();
        tl.add_event(make_event(100, EventCategory::Process, EventSeverity::LOW));
        tl.add_event(make_event(500, EventCategory::Process, EventSeverity::LOW));
        tl.add_event(make_event(900, EventCategory::Process, EventSeverity::LOW));
        let r = tl.events_in_range(200, 800);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].timestamp, 500);
    }

    #[test]
    fn test_timeline_high_severity() {
        let mut tl = ForensicTimeline::new();
        tl.add_event(make_event(
            0,
            EventCategory::Memory,
            EventSeverity::CRITICAL,
        ));
        tl.add_event(make_event(0, EventCategory::Memory, EventSeverity::LOW));
        let hi = tl.high_severity(EventSeverity::HIGH);
        assert_eq!(hi.len(), 1);
    }

    #[test]
    fn test_timeline_to_csv() {
        let mut tl = ForensicTimeline::new();
        tl.add_event(make_event(
            1000,
            EventCategory::FileSystem,
            EventSeverity::MEDIUM,
        ));
        let csv = tl.to_csv();
        assert!(csv.contains("timestamp_ms"));
        assert!(csv.contains("filesystem"));
    }

    #[test]
    fn test_timeline_to_json() {
        let mut tl = ForensicTimeline::new();
        tl.add_event(make_event(0, EventCategory::Network, EventSeverity::HIGH));
        let json = tl.to_json();
        // `to_json` goes through serde, which serialises a variant under its
        // exact Rust name unless `rename_all` says otherwise — so this is
        // "Network", capitalised. Note that `to_csv` uses `Display` and emits
        // the lowercase "network": the two exports disagree on category
        // spelling, which is recorded as an open question rather than changed
        // here, since altering it would change a public output format.
        assert!(
            json.contains("Network"),
            "serde serialises the variant name verbatim; got: {json}"
        );
    }

    #[test]
    fn test_timeline_merge() {
        let mut tl1 = ForensicTimeline::new();
        tl1.add_event(make_event(100, EventCategory::Process, EventSeverity::LOW));
        let mut tl2 = ForensicTimeline::new();
        tl2.add_event(make_event(200, EventCategory::Process, EventSeverity::LOW));
        tl1.merge(tl2);
        assert_eq!(tl1.len(), 2);
        assert_eq!(tl1.events()[0].timestamp, 100);
    }

    // ── TimelineBuilder ─────────────────────────────────────────────────────

    #[test]
    fn test_builder_builds_timeline() {
        let mut b = TimelineBuilder::new().with_default_source("EventLog");
        b.add_artifact(ArtifactEntry {
            id: "a1".into(),
            source: "EventLog".into(),
            timestamp: Some(5000),
            category: EventCategory::Authentication,
            description: "user logged on".into(),
            severity: EventSeverity::LOW,
        });
        let tl = b.build();
        assert_eq!(tl.len(), 1);
        assert_eq!(tl.events()[0].timestamp, 5000);
    }

    #[test]
    fn test_builder_no_timestamp_defaults_to_zero() {
        let mut b = TimelineBuilder::new();
        b.add_artifact(ArtifactEntry {
            id: "x".into(),
            source: "unknown".into(),
            timestamp: None,
            category: EventCategory::FileSystem,
            description: "no timestamp".into(),
            severity: EventSeverity::INFO,
        });
        let tl = b.build();
        assert_eq!(tl.events()[0].timestamp, 0);
    }

    #[test]
    fn test_builder_artifact_count() {
        let mut b = TimelineBuilder::new();
        assert_eq!(b.artifact_count(), 0);
        b.add_artifact(ArtifactEntry {
            id: "y".into(),
            source: "s".into(),
            timestamp: Some(1),
            category: EventCategory::Network,
            description: "net".into(),
            severity: EventSeverity::MEDIUM,
        });
        assert_eq!(b.artifact_count(), 1);
    }
}
