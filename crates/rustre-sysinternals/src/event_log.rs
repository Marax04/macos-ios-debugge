//! Windows Event Log reader — portable data types and a pure-Rust parser.
//!
//! The implementation is intentionally platform-agnostic: on Windows a real
//! backend would call `EvtQuery`/`EvtNext`; on other platforms the structs and
//! `InMemoryEventLogBackend` enable full unit-testing without OS access.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ─── EventLevel ───────────────────────────────────────────────────────────────

/// Severity level of an event log record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventLevel {
    /// Critical errors.
    Critical = 1,
    /// Errors.
    Error = 2,
    /// Warnings.
    Warning = 3,
    /// Informational events.
    Information = 4,
    /// Verbose / debug events.
    Verbose = 5,
}

impl EventLevel {
    /// Decode from a raw Windows event level byte.
    #[must_use]
    pub const fn from_raw(v: u8) -> Self {
        match v {
            1 => Self::Critical,
            2 => Self::Error,
            3 => Self::Warning,
            5 => Self::Verbose,
            _ => Self::Information,
        }
    }

    /// Raw byte value used by Windows Event Log.
    #[must_use]
    pub const fn as_raw(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for EventLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::Error => write!(f, "Error"),
            Self::Warning => write!(f, "Warning"),
            Self::Information => write!(f, "Information"),
            Self::Verbose => write!(f, "Verbose"),
        }
    }
}

// ─── EventRecord ──────────────────────────────────────────────────────────────

/// A single Windows Event Log record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    /// Event ID (e.g. 4624 for logon).
    pub event_id: u32,
    /// Unix timestamp (seconds since epoch).
    pub time_created: u64,
    /// Event source / provider name.
    pub source: String,
    /// Severity level.
    pub level: EventLevel,
    /// Log channel name (e.g. "System", "Security", "Application").
    pub channel: String,
    /// Process ID that logged this event.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Computer name.
    pub computer: String,
    /// Human-readable message text.
    pub message: String,
    /// Keyword flags (raw bitmask from the event manifest).
    pub keywords: u64,
    /// Record number within the log.
    pub record_id: u64,
    /// Task identifier from the event manifest.
    pub task: u16,
    /// Opcode.
    pub opcode: u8,
    /// Correlation activity ID.
    pub activity_id: Option<String>,
    /// Arbitrary key-value data extracted from the XML.
    pub data: HashMap<String, String>,
}

impl EventRecord {
    /// Create a minimal record for testing.
    #[must_use]
    pub fn new(
        event_id: u32,
        source: impl Into<String>,
        level: EventLevel,
        channel: impl Into<String>,
    ) -> Self {
        Self {
            event_id,
            time_created: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
            source: source.into(),
            level,
            channel: channel.into(),
            pid: 0,
            tid: 0,
            computer: String::new(),
            message: String::new(),
            keywords: 0,
            record_id: 0,
            task: 0,
            opcode: 0,
            activity_id: None,
            data: HashMap::new(),
        }
    }

    /// Returns `true` if this record's `time_created` falls within `[from, to]`.
    #[must_use]
    pub const fn in_time_range(&self, from: u64, to: u64) -> bool {
        self.time_created >= from && self.time_created <= to
    }

    /// Returns `true` if the event is at or above `min_level` severity.
    #[must_use]
    pub fn at_least(&self, min_level: EventLevel) -> bool {
        self.level <= min_level
    }

    /// CSV row: id,time,source,level,channel,message
    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},\"{}\"",
            self.event_id,
            self.time_created,
            self.source,
            self.level,
            self.channel,
            self.message.replace('"', "\"\""),
        )
    }
}

// ─── EventQuery ───────────────────────────────────────────────────────────────

/// Filter criteria for querying event log records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventQuery {
    /// Accept only records whose `event_id` is in this set.
    /// Empty means accept all IDs.
    pub event_ids: Vec<u32>,
    /// Accept only records from these channels.
    /// Empty means accept all channels.
    pub channels: Vec<String>,
    /// Accept only records from these sources.
    /// Empty means accept all sources.
    pub sources: Vec<String>,
    /// Accept only records at or above this level.
    pub min_level: Option<EventLevel>,
    /// Accept records created on or after this Unix timestamp.
    pub from_time: Option<u64>,
    /// Accept records created on or before this Unix timestamp.
    pub to_time: Option<u64>,
    /// Accept only records whose message contains this substring.
    pub message_contains: Option<String>,
    /// Accept only records from this computer.
    pub computer: Option<String>,
    /// Maximum number of records to return.
    pub max_records: Option<usize>,
}

impl EventQuery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by a specific event ID.
    #[must_use]
    pub fn with_event_id(mut self, id: u32) -> Self {
        self.event_ids.push(id);
        self
    }

    /// Filter by channel name.
    #[must_use]
    pub fn with_channel(mut self, ch: impl Into<String>) -> Self {
        self.channels.push(ch.into());
        self
    }

    /// Filter by minimum severity.
    #[must_use]
    pub const fn with_min_level(mut self, l: EventLevel) -> Self {
        self.min_level = Some(l);
        self
    }

    /// Filter by message substring.
    #[must_use]
    pub fn with_message_contains(mut self, s: impl Into<String>) -> Self {
        self.message_contains = Some(s.into());
        self
    }

    /// Limit results.
    #[must_use]
    pub const fn with_max_records(mut self, n: usize) -> Self {
        self.max_records = Some(n);
        self
    }

    /// Returns `true` if `record` passes all active filters.
    #[must_use]
    pub fn matches(&self, record: &EventRecord) -> bool {
        if !self.event_ids.is_empty() && !self.event_ids.contains(&record.event_id) {
            return false;
        }
        if !self.channels.is_empty() && !self.channels.iter().any(|c| c == &record.channel) {
            return false;
        }
        if !self.sources.is_empty() && !self.sources.iter().any(|s| s == &record.source) {
            return false;
        }
        if let Some(min) = self.min_level
            && !record.at_least(min) {
                return false;
            }
        if let Some(from) = self.from_time
            && record.time_created < from {
                return false;
            }
        if let Some(to) = self.to_time
            && record.time_created > to {
                return false;
            }
        if let Some(ref substr) = self.message_contains
            && !record.message.contains(substr.as_str()) {
                return false;
            }
        if let Some(ref computer) = self.computer
            && &record.computer != computer {
                return false;
            }
        true
    }
}

// ─── Interesting event IDs ────────────────────────────────────────────────────

/// Well-known Windows security/system event IDs with descriptions.
pub static INTERESTING_EVENT_IDS: &[(u32, &str)] = &[
    (4624, "An account was successfully logged on"),
    (4625, "An account failed to log on"),
    (4648, "A logon was attempted using explicit credentials"),
    (4656, "A handle to an object was requested"),
    (4663, "An attempt was made to access an object"),
    (4672, "Special privileges assigned to new logon"),
    (4688, "A new process has been created"),
    (4697, "A service was installed in the system"),
    (4698, "A scheduled task was created"),
    (4699, "A scheduled task was deleted"),
    (4700, "A scheduled task was enabled"),
    (4702, "A scheduled task was updated"),
    (4719, "System audit policy was changed"),
    (4720, "A user account was created"),
    (4722, "A user account was enabled"),
    (4724, "An attempt was made to reset an account's password"),
    (
        4728,
        "A member was added to a security-enabled global group",
    ),
    (4732, "A member was added to a security-enabled local group"),
    (4740, "A user account was locked out"),
    (
        4756,
        "A member was added to a security-enabled universal group",
    ),
    (4768, "A Kerberos authentication ticket (TGT) was requested"),
    (4769, "A Kerberos service ticket was requested"),
    (
        4776,
        "The computer attempted to validate the credentials for an account",
    ),
    (4798, "A user's local group membership was enumerated"),
    (
        4799,
        "A security-enabled local group membership was enumerated",
    ),
    (5140, "A network share object was accessed"),
    (
        5145,
        "A network share object was checked to see if client can be granted desired access",
    ),
    (7034, "A service terminated unexpectedly"),
    (7035, "A service was successfully sent a start/stop control"),
    (7036, "A service entered the running/stopped state"),
    (7040, "The start type of a service was changed"),
    (7045, "A new service was installed in the system"),
];

/// Look up the description for a known event ID.
#[must_use]
pub fn event_id_description(id: u32) -> Option<&'static str> {
    INTERESTING_EVENT_IDS
        .iter()
        .find(|(eid, _)| *eid == id)
        .map(|(_, desc)| *desc)
}

/// Returns `true` if this event ID is considered interesting for security analysis.
#[must_use]
pub fn is_interesting_event_id(id: u32) -> bool {
    INTERESTING_EVENT_IDS.iter().any(|(eid, _)| *eid == id)
}

// ─── EventAggregator ─────────────────────────────────────────────────────────

/// Aggregates event records for analysis.
#[derive(Debug, Default)]
pub struct EventAggregator {
    /// Count of records per event ID.
    pub count_by_id: HashMap<u32, usize>,
    /// Count of records per channel.
    pub count_by_channel: HashMap<String, usize>,
    /// Count of records per source.
    pub count_by_source: HashMap<String, usize>,
    /// Count of records per level.
    pub count_by_level: HashMap<String, usize>,
    /// Timeline: count by hour (Unix timestamp truncated to hour boundary).
    pub timeline_by_hour: HashMap<u64, usize>,
    /// Total records ingested.
    pub total: usize,
}

impl EventAggregator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest one record into all aggregation buckets.
    pub fn ingest(&mut self, record: &EventRecord) {
        *self.count_by_id.entry(record.event_id).or_insert(0) += 1;
        *self
            .count_by_channel
            .entry(record.channel.clone())
            .or_insert(0) += 1;
        *self
            .count_by_source
            .entry(record.source.clone())
            .or_insert(0) += 1;
        *self
            .count_by_level
            .entry(record.level.to_string())
            .or_insert(0) += 1;
        let hour = record.time_created / 3600 * 3600;
        *self.timeline_by_hour.entry(hour).or_insert(0) += 1;
        self.total += 1;
    }

    /// Ingest a slice of records.
    pub fn ingest_all(&mut self, records: &[EventRecord]) {
        for r in records {
            self.ingest(r);
        }
    }

    /// Return the top-N event IDs by count.
    #[must_use]
    pub fn top_event_ids(&self, n: usize) -> Vec<(u32, usize)> {
        let mut pairs: Vec<_> = self
            .count_by_id
            .iter()
            .map(|(&id, &cnt)| (id, cnt))
            .collect();
        pairs.sort_by_key(|b| std::cmp::Reverse(b.1));
        pairs.truncate(n);
        pairs
    }

    /// Return the sorted timeline as (`hour_ts`, count) pairs.
    #[must_use]
    pub fn sorted_timeline(&self) -> Vec<(u64, usize)> {
        let mut tl: Vec<_> = self
            .timeline_by_hour
            .iter()
            .map(|(&h, &c)| (h, c))
            .collect();
        tl.sort_by_key(|&(h, _)| h);
        tl
    }

    /// Returns the event IDs that match the interesting list, sorted by count desc.
    #[must_use]
    pub fn interesting_events(&self) -> Vec<(u32, usize, &'static str)> {
        let mut out: Vec<_> = self
            .count_by_id
            .iter()
            .filter_map(|(&id, &cnt)| event_id_description(id).map(|desc| (id, cnt, desc)))
            .collect();
        out.sort_by_key(|b| std::cmp::Reverse(b.1));
        out
    }

    /// Reset all aggregation state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

// ─── EventLogReader trait ─────────────────────────────────────────────────────

/// Trait for reading Windows Event Log records.
pub trait EventLogReader: Send + Sync {
    /// List available channel names.
    fn list_channels(&self) -> Vec<String>;

    /// Query records from a channel, applying the given filter.
    fn query(&self, channel: &str, query: &EventQuery) -> Vec<EventRecord>;

    /// Read all records from a channel (no filter).
    fn read_all(&self, channel: &str) -> Vec<EventRecord> {
        self.query(channel, &EventQuery::new())
    }
}

// ─── InMemoryEventLogBackend ──────────────────────────────────────────────────

/// In-memory event log backend for testing.
#[derive(Debug, Default)]
pub struct InMemoryEventLogBackend {
    /// Channel name → records.
    channels: HashMap<String, Vec<EventRecord>>,
}

impl InMemoryEventLogBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-load default channels.
    #[must_use]
    pub fn with_default_channels() -> Self {
        let mut b = Self::new();
        for ch in &["System", "Security", "Application"] {
            b.channels.insert(ch.to_string(), Vec::new());
        }
        b
    }

    /// Add a record to a channel.
    pub fn push(&mut self, record: EventRecord) {
        self.channels
            .entry(record.channel.clone())
            .or_default()
            .push(record);
    }

    /// Number of records in all channels.
    #[must_use]
    pub fn total_records(&self) -> usize {
        self.channels.values().map(std::vec::Vec::len).sum()
    }
}

impl EventLogReader for InMemoryEventLogBackend {
    fn list_channels(&self) -> Vec<String> {
        let mut channels: Vec<String> = self.channels.keys().cloned().collect();
        channels.sort();
        channels
    }

    fn query(&self, channel: &str, query: &EventQuery) -> Vec<EventRecord> {
        let Some(records) = self.channels.get(channel) else { return Vec::new() };

        let mut out: Vec<EventRecord> = records
            .iter()
            .filter(|r| query.matches(r))
            .cloned()
            .collect();

        if let Some(max) = query.max_records {
            out.truncate(max);
        }
        out
    }
}

// ─── Simplified XML parser ────────────────────────────────────────────────────

/// Simplified Windows Event XML parser.
///
/// Windows Event Log XML looks like:
/// ```xml
/// <Event>
///   <System>
///     <EventID>4624</EventID>
///     <TimeCreated SystemTime="2024-01-15T12:34:56.000Z"/>
///     <Level>4</Level>
///     <Provider Name="Microsoft-Windows-Security-Auditing"/>
///     <Computer>WORKSTATION</Computer>
///     <Channel>Security</Channel>
///     <Execution ProcessID="123" ThreadID="456"/>
///   </System>
///   <EventData>
///     <Data Name="SubjectUserName">SYSTEM</Data>
///   </EventData>
/// </Event>
/// ```
pub struct EventXmlParser;

impl EventXmlParser {
    /// Attempt to parse a minimal event from XML text.
    /// Returns `None` if the XML is unparseable.
    #[must_use]
    pub fn parse(xml: &str) -> Option<EventRecord> {
        let event_id = Self::extract_tag(xml, "EventID")?.parse::<u32>().ok()?;
        let source = Self::extract_attr(xml, "Provider", "Name").unwrap_or_default();
        let level_raw = Self::extract_tag(xml, "Level")
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(4);
        let level = EventLevel::from_raw(level_raw);
        let channel = Self::extract_tag(xml, "Channel").unwrap_or_default();
        let computer = Self::extract_tag(xml, "Computer").unwrap_or_default();
        let pid = Self::extract_attr(xml, "Execution", "ProcessID")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let tid = Self::extract_attr(xml, "Execution", "ThreadID")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let time_created = Self::extract_attr(xml, "TimeCreated", "SystemTime")
            .map_or(0, |s| Self::parse_iso8601(&s));
        let message = Self::extract_tag(xml, "Message").unwrap_or_default();

        // Extract EventData Name attributes
        let mut data = HashMap::new();
        let mut rest = xml;
        while let Some(idx) = rest.find("<Data Name=\"") {
            rest = &rest[idx + 12..];
            if let Some(name_end) = rest.find('"') {
                let name = rest[..name_end].to_string();
                rest = &rest[name_end + 2..]; // skip ">
                if let Some(val_end) = rest.find("</Data>") {
                    let val = rest[..val_end].to_string();
                    data.insert(name, val);
                    rest = &rest[val_end..];
                }
            }
        }

        let mut record = EventRecord::new(event_id, source, level, channel);
        record.computer = computer;
        record.pid = pid;
        record.tid = tid;
        record.time_created = time_created;
        record.message = message;
        record.data = data;
        Some(record)
    }

    /// Extract the text content of the first matching XML tag.
    fn extract_tag(xml: &str, tag: &str) -> Option<String> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = xml.find(&open)? + open.len();
        let end = xml[start..].find(&close)? + start;
        Some(xml[start..end].trim().to_string())
    }

    /// Extract an attribute value from an XML tag.
    fn extract_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
        let needle = format!("<{tag} ");
        let tag_start = xml.find(&needle)? + needle.len();
        let tag_content = &xml[tag_start..];
        let tag_end = tag_content.find('>')?;
        let tag_inner = &tag_content[..tag_end];

        let attr_needle = format!("{attr}=\"");
        let attr_start = tag_inner.find(&attr_needle)? + attr_needle.len();
        let rest = &tag_inner[attr_start..];
        let attr_end = rest.find('"')?;
        Some(rest[..attr_end].to_string())
    }

    /// Parse an ISO-8601 datetime string to a Unix timestamp.
    /// Supports "2024-01-15T12:34:56.000Z" format.
    fn parse_iso8601(s: &str) -> u64 {
        // Very simplified: try to extract date and time parts.
        // Format: YYYY-MM-DDTHH:MM:SS
        let parts: Vec<&str> = s.split('T').collect();
        if parts.len() != 2 {
            return 0;
        }
        let date_parts: Vec<u64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
        let time_parts: Vec<u64> = parts[1]
            .split(':')
            .map(|p| p.trim_end_matches(|c: char| !c.is_ascii_digit()))
            .filter_map(|p| p.parse().ok())
            .collect();

        if date_parts.len() < 3 || time_parts.len() < 3 {
            return 0;
        }

        // Approximate calculation (ignoring leap years, DST, etc.)
        // Use saturating arithmetic throughout: all inputs come from untrusted XML and could
        // be astronomically large, which would overflow u64 in plain multiplication.
        let year = date_parts[0].saturating_sub(1970);
        let days = year.saturating_mul(365)
            .saturating_add(date_parts[1].saturating_sub(1).saturating_mul(30))
            .saturating_add(date_parts[2].saturating_sub(1));
        days.saturating_mul(86400)
            .saturating_add(time_parts[0].saturating_mul(3600))
            .saturating_add(time_parts[1].saturating_mul(60))
            .saturating_add(time_parts[2])
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(id: u32, level: EventLevel, channel: &str) -> EventRecord {
        let mut r = EventRecord::new(id, "TestSource", level, channel);
        r.time_created = 1_700_000_000;
        r.message = format!("Test message for event {id}");
        r.computer = "TESTPC".into();
        r
    }

    // ── EventLevel ────────────────────────────────────────────────────────────

    #[test]
    fn event_level_from_raw_roundtrip() {
        assert_eq!(EventLevel::from_raw(1), EventLevel::Critical);
        assert_eq!(EventLevel::from_raw(2), EventLevel::Error);
        assert_eq!(EventLevel::from_raw(3), EventLevel::Warning);
        assert_eq!(EventLevel::from_raw(4), EventLevel::Information);
        assert_eq!(EventLevel::from_raw(5), EventLevel::Verbose);
    }

    #[test]
    fn event_level_as_raw() {
        assert_eq!(EventLevel::Critical.as_raw(), 1);
        assert_eq!(EventLevel::Verbose.as_raw(), 5);
    }

    #[test]
    fn event_level_ordering() {
        assert!(EventLevel::Critical < EventLevel::Error);
        assert!(EventLevel::Error < EventLevel::Information);
    }

    #[test]
    fn event_level_display() {
        assert_eq!(EventLevel::Error.to_string(), "Error");
        assert_eq!(EventLevel::Warning.to_string(), "Warning");
    }

    // ── EventRecord ───────────────────────────────────────────────────────────

    #[test]
    fn event_record_new_fields() {
        let r = EventRecord::new(
            4624,
            "Security-Auditing",
            EventLevel::Information,
            "Security",
        );
        assert_eq!(r.event_id, 4624);
        assert_eq!(r.source, "Security-Auditing");
        assert_eq!(r.channel, "Security");
        assert_eq!(r.level, EventLevel::Information);
    }

    #[test]
    fn event_record_at_least() {
        let r = sample_record(1, EventLevel::Warning, "System");
        assert!(r.at_least(EventLevel::Warning));
        assert!(r.at_least(EventLevel::Information));
        assert!(!r.at_least(EventLevel::Error));
    }

    #[test]
    fn event_record_in_time_range() {
        let r = sample_record(1, EventLevel::Information, "System");
        assert!(r.in_time_range(1_699_999_000, 1_700_001_000));
        assert!(!r.in_time_range(1_700_001_000, 1_700_002_000));
    }

    #[test]
    fn event_record_csv_row() {
        let r = sample_record(4624, EventLevel::Information, "Security");
        let csv = r.to_csv_row();
        assert!(csv.starts_with("4624,"));
        assert!(csv.contains("Security"));
    }

    // ── EventQuery ────────────────────────────────────────────────────────────

    #[test]
    fn event_query_matches_id() {
        let q = EventQuery::new().with_event_id(4624);
        let r = sample_record(4624, EventLevel::Information, "Security");
        assert!(q.matches(&r));
        let r2 = sample_record(4625, EventLevel::Information, "Security");
        assert!(!q.matches(&r2));
    }

    #[test]
    fn event_query_matches_channel() {
        let q = EventQuery::new().with_channel("Security");
        let r = sample_record(4624, EventLevel::Information, "Security");
        assert!(q.matches(&r));
        let r2 = sample_record(4624, EventLevel::Information, "System");
        assert!(!q.matches(&r2));
    }

    #[test]
    fn event_query_min_level_filter() {
        let q = EventQuery::new().with_min_level(EventLevel::Warning);
        let warn = sample_record(1, EventLevel::Warning, "System");
        let info = sample_record(1, EventLevel::Information, "System");
        assert!(q.matches(&warn));
        assert!(!q.matches(&info));
    }

    #[test]
    fn event_query_message_contains() {
        let q = EventQuery::new().with_message_contains("event 4624");
        let r = sample_record(4624, EventLevel::Information, "Security");
        assert!(q.matches(&r));
        let r2 = sample_record(4625, EventLevel::Information, "Security");
        assert!(!q.matches(&r2));
    }

    #[test]
    fn event_query_max_records() {
        let mut backend = InMemoryEventLogBackend::with_default_channels();
        for i in 0..10 {
            backend.push(sample_record(i + 1, EventLevel::Information, "System"));
        }
        let q = EventQuery::new().with_max_records(3);
        let results = backend.query("System", &q);
        assert_eq!(results.len(), 3);
    }

    // ── InMemoryEventLogBackend ───────────────────────────────────────────────

    #[test]
    fn backend_list_channels() {
        let backend = InMemoryEventLogBackend::with_default_channels();
        let ch = backend.list_channels();
        assert!(ch.contains(&"Security".to_string()));
        assert!(ch.contains(&"System".to_string()));
        assert!(ch.contains(&"Application".to_string()));
    }

    #[test]
    fn backend_query_empty_channel() {
        let backend = InMemoryEventLogBackend::with_default_channels();
        let results = backend.query("Security", &EventQuery::new());
        assert!(results.is_empty());
    }

    #[test]
    fn backend_query_missing_channel() {
        let backend = InMemoryEventLogBackend::new();
        let results = backend.query("NonExistent", &EventQuery::new());
        assert!(results.is_empty());
    }

    #[test]
    fn backend_push_and_query() {
        let mut backend = InMemoryEventLogBackend::with_default_channels();
        backend.push(sample_record(4624, EventLevel::Information, "Security"));
        backend.push(sample_record(4688, EventLevel::Information, "Security"));
        let all = backend.query("Security", &EventQuery::new());
        assert_eq!(all.len(), 2);
        let q = EventQuery::new().with_event_id(4624);
        let filtered = backend.query("Security", &q);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].event_id, 4624);
    }

    #[test]
    fn backend_total_records() {
        let mut backend = InMemoryEventLogBackend::with_default_channels();
        backend.push(sample_record(1, EventLevel::Information, "System"));
        backend.push(sample_record(2, EventLevel::Warning, "Application"));
        assert_eq!(backend.total_records(), 2);
    }

    // ── EventAggregator ───────────────────────────────────────────────────────

    #[test]
    fn aggregator_count_by_id() {
        let mut agg = EventAggregator::new();
        agg.ingest(&sample_record(4624, EventLevel::Information, "Security"));
        agg.ingest(&sample_record(4624, EventLevel::Information, "Security"));
        agg.ingest(&sample_record(4688, EventLevel::Information, "Security"));
        assert_eq!(agg.count_by_id[&4624], 2);
        assert_eq!(agg.count_by_id[&4688], 1);
        assert_eq!(agg.total, 3);
    }

    #[test]
    fn aggregator_count_by_channel() {
        let mut agg = EventAggregator::new();
        agg.ingest(&sample_record(1, EventLevel::Information, "Security"));
        agg.ingest(&sample_record(2, EventLevel::Information, "System"));
        assert_eq!(agg.count_by_channel["Security"], 1);
        assert_eq!(agg.count_by_channel["System"], 1);
    }

    #[test]
    fn aggregator_top_event_ids() {
        let mut agg = EventAggregator::new();
        for _ in 0..5 {
            agg.ingest(&sample_record(4624, EventLevel::Information, "Security"));
        }
        for _ in 0..3 {
            agg.ingest(&sample_record(4688, EventLevel::Information, "Security"));
        }
        let top = agg.top_event_ids(1);
        assert_eq!(top[0].0, 4624);
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn aggregator_interesting_events() {
        let mut agg = EventAggregator::new();
        agg.ingest(&sample_record(4624, EventLevel::Information, "Security"));
        let interesting = agg.interesting_events();
        assert!(!interesting.is_empty());
        assert_eq!(interesting[0].0, 4624);
    }

    #[test]
    fn aggregator_reset() {
        let mut agg = EventAggregator::new();
        agg.ingest(&sample_record(1, EventLevel::Information, "System"));
        agg.reset();
        assert_eq!(agg.total, 0);
        assert!(agg.count_by_id.is_empty());
    }

    // ── Interesting event IDs ─────────────────────────────────────────────────

    #[test]
    fn interesting_event_id_lookup() {
        assert!(event_id_description(4624).is_some());
        assert!(event_id_description(7045).is_some());
        assert!(event_id_description(9999).is_none());
    }

    #[test]
    fn is_interesting_event_id_known() {
        assert!(is_interesting_event_id(4688));
        assert!(is_interesting_event_id(7045));
        assert!(!is_interesting_event_id(1234));
    }

    // ── EventXmlParser ────────────────────────────────────────────────────────

    #[test]
    fn xml_parser_minimal() {
        let xml = r#"<Event><System>
            <EventID>4624</EventID>
            <Level>4</Level>
            <Channel>Security</Channel>
            <Computer>TESTPC</Computer>
            <Provider Name="Microsoft-Windows-Security-Auditing"/>
            <Execution ProcessID="100" ThreadID="200"/>
        </System></Event>"#;
        let r = EventXmlParser::parse(xml);
        assert!(r.is_some());
        let r = r.unwrap();
        assert_eq!(r.event_id, 4624);
        assert_eq!(r.channel, "Security");
        assert_eq!(r.computer, "TESTPC");
        assert_eq!(r.pid, 100);
        assert_eq!(r.tid, 200);
    }

    #[test]
    fn xml_parser_missing_event_id_returns_none() {
        let xml = "<Event><System><Level>4</Level></System></Event>";
        assert!(EventXmlParser::parse(xml).is_none());
    }

    #[test]
    fn xml_parser_extracts_event_data() {
        let xml = r#"<Event>
            <System><EventID>4624</EventID><Level>4</Level><Channel>Security</Channel>
            <Computer>PC</Computer><Provider Name="Prov"/>
            <Execution ProcessID="1" ThreadID="2"/>
            </System>
            <EventData>
                <Data Name="SubjectUserName">SYSTEM</Data>
                <Data Name="LogonType">3</Data>
            </EventData>
        </Event>"#;
        let r = EventXmlParser::parse(xml).unwrap();
        assert_eq!(
            r.data.get("SubjectUserName").map(std::string::String::as_str),
            Some("SYSTEM")
        );
        assert_eq!(r.data.get("LogonType").map(std::string::String::as_str), Some("3"));
    }
}
