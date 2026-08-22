//! Timeline reconstruction for filesystem forensics.
//!
//! Builds a chronological sequence of filesystem events and provides filtering,
//! hot-path analysis, CSV export/import, and summary reporting.

use std::fmt::Write as _;
use std::collections::HashMap;
use std::fmt;

use crate::MemFsError;

// ─── TimelineEventType ────────────────────────────────────────────────────────

/// The kind of filesystem event recorded in the timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelineEventType {
    /// A new file or directory was created.
    Create,
    /// File content or metadata was modified.
    Modify,
    /// File was read or opened for reading.
    Access,
    /// File or directory was deleted.
    Delete,
    /// File was renamed or moved.
    Move { from: String },
    /// A new hard-link was created to this inode.
    HardLink,
    /// A symbolic link was created pointing to this path.
    SymLink,
    /// File permissions changed.
    PermChange,
    /// File ownership (uid/gid) changed.
    OwnerChange,
    /// A filesystem was mounted at this path.
    Mount,
    /// A filesystem was unmounted from this path.
    Unmount,
    /// The file was executed as a process.
    Execute,
}

impl fmt::Display for TimelineEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "Create"),
            Self::Modify => write!(f, "Modify"),
            Self::Access => write!(f, "Access"),
            Self::Delete => write!(f, "Delete"),
            Self::Move { from } => write!(f, "Move({from})"),
            Self::HardLink => write!(f, "HardLink"),
            Self::SymLink => write!(f, "SymLink"),
            Self::PermChange => write!(f, "PermChange"),
            Self::OwnerChange => write!(f, "OwnerChange"),
            Self::Mount => write!(f, "Mount"),
            Self::Unmount => write!(f, "Unmount"),
            Self::Execute => write!(f, "Execute"),
        }
    }
}

impl TimelineEventType {
    /// Returns the base kind name without arguments (used for bucketing in reports).
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Create => "Create",
            Self::Modify => "Modify",
            Self::Access => "Access",
            Self::Delete => "Delete",
            Self::Move { .. } => "Move",
            Self::HardLink => "HardLink",
            Self::SymLink => "SymLink",
            Self::PermChange => "PermChange",
            Self::OwnerChange => "OwnerChange",
            Self::Mount => "Mount",
            Self::Unmount => "Unmount",
            Self::Execute => "Execute",
        }
    }
}

// ─── TimelineEvent ────────────────────────────────────────────────────────────

/// A single event in the filesystem timeline.
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// What happened.
    pub event_type: TimelineEventType,
    /// Absolute path of the affected file or directory.
    pub path: String,
    /// Name of the process that triggered the event, if known.
    pub process: Option<String>,
    /// PID of the process that triggered the event, if known.
    pub pid: Option<u32>,
    /// File size in bytes at the time of the event, if applicable.
    pub size: Option<u64>,
    /// Inode number of the affected file, if known.
    pub inode: Option<u64>,
    /// Arbitrary key-value metadata attached to this event.
    pub extra: HashMap<String, String>,
}

impl TimelineEvent {
    /// Construct a minimal event with just timestamp, type, and path.
    #[must_use]
    pub fn new(timestamp: u64, event_type: TimelineEventType, path: impl Into<String>) -> Self {
        Self {
            timestamp,
            event_type,
            path: path.into(),
            process: None,
            pid: None,
            size: None,
            inode: None,
            extra: HashMap::new(),
        }
    }

    /// Builder: attach process name and PID.
    #[must_use]
    pub fn with_process(mut self, name: impl Into<String>, pid: u32) -> Self {
        self.process = Some(name.into());
        self.pid = Some(pid);
        self
    }

    /// Builder: attach file size.
    #[must_use]
    pub const fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Builder: attach inode number.
    #[must_use]
    pub const fn with_inode(mut self, inode: u64) -> Self {
        self.inode = Some(inode);
        self
    }

    /// Builder: insert an extra metadata key-value pair.
    #[must_use]
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }

    /// Returns the display name for the event type.
    #[must_use]
    pub fn type_name(&self) -> String {
        self.event_type.to_string()
    }
}

// ─── Timeline ────────────────────────────────────────────────────────────────

/// An ordered, searchable collection of filesystem timeline events.
#[derive(Debug, Default)]
pub struct Timeline {
    events: Vec<TimelineEvent>,
}

impl Timeline {
    /// Create an empty timeline.
    #[must_use]
    pub const fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Append an event.
    pub fn push(&mut self, event: TimelineEvent) {
        self.events.push(event);
    }

    /// Sort events by timestamp ascending.
    pub fn sort_by_time(&mut self) {
        self.events.sort_by_key(|e| e.timestamp);
    }

    /// Number of events in the timeline.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` if the timeline has no events.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Return all events whose timestamp falls in `[start, end]` (inclusive).
    #[must_use]
    pub fn filter_by_time(&self, start: u64, end: u64) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    /// Return all events whose event-type display string contains `kind_name`.
    /// For example, `"Move"` matches `Move { from: … }`.
    #[must_use]
    pub fn filter_by_type(&self, kind_name: &str) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type.to_string().starts_with(kind_name))
            .collect()
    }

    /// Return all events whose path starts with `prefix`.
    #[must_use]
    pub fn filter_by_path_prefix(&self, prefix: &str) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.path.starts_with(prefix))
            .collect()
    }

    /// Return events whose timestamp is within ±`window_secs` of `ts`.
    #[must_use]
    pub fn events_near(&self, ts: u64, window_secs: u64) -> Vec<&TimelineEvent> {
        let lo = ts.saturating_sub(window_secs);
        let hi = ts.saturating_add(window_secs);
        self.filter_by_time(lo, hi)
    }

    /// Return the top `top_n` paths by total event count, sorted descending.
    #[must_use]
    pub fn hot_paths(&self, top_n: usize) -> Vec<(String, usize)> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for e in &self.events {
            *counts.entry(e.path.as_str()).or_insert(0) += 1;
        }
        let mut vec: Vec<(String, usize)> = counts
            .into_iter()
            .map(|(p, c)| (p.to_string(), c))
            .collect();
        vec.sort_by(|a, b| b.1.cmp(&a.1));
        vec.truncate(top_n);
        vec
    }

    /// Iterate over raw events.
    pub fn events(&self) -> impl Iterator<Item = &TimelineEvent> {
        self.events.iter()
    }

    // ─── Report ───────────────────────────────────────────────────────────────

    /// Produce a summary report over all events.
    #[must_use]
    pub fn report(&self) -> TimelineReport {
        if self.events.is_empty() {
            return TimelineReport {
                total: 0,
                first_ts: 0,
                last_ts: 0,
                duration_secs: 0,
                events_by_type: HashMap::new(),
                hot_paths: vec![],
                unique_processes: 0,
            };
        }

        let first_ts = self.events.iter().map(|e| e.timestamp).min().unwrap_or(0);
        let last_ts = self.events.iter().map(|e| e.timestamp).max().unwrap_or(0);
        let duration_secs = last_ts.saturating_sub(first_ts);

        let mut events_by_type: HashMap<String, usize> = HashMap::new();
        for e in &self.events {
            *events_by_type
                .entry(e.event_type.kind_name().to_string())
                .or_insert(0) += 1;
        }

        let mut unique_proc_set: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for e in &self.events {
            if let Some(p) = e.process.as_deref() {
                unique_proc_set.insert(p);
            }
        }

        TimelineReport {
            total: self.events.len(),
            first_ts,
            last_ts,
            duration_secs,
            events_by_type,
            hot_paths: self.hot_paths(10),
            unique_processes: unique_proc_set.len(),
        }
    }

    // ─── CSV I/O ──────────────────────────────────────────────────────────────

    /// Serialize the timeline to CSV with header:
    /// `timestamp,type,path,process,pid`
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = String::from("timestamp,type,path,process,pid\n");
        for e in &self.events {
            let proc = e.process.as_deref().unwrap_or("");
            let pid = e.pid.map(|p| p.to_string()).unwrap_or_default();
            let _ = write!(out, 
                "{},{},{},{},{}\n",
                e.timestamp,
                csv_field(&e.event_type.to_string()),
                csv_field(&e.path),
                csv_field(proc),
                pid,
            );
        }
        out
    }

    /// Parse a timeline from CSV produced by [`Timeline::to_csv`].
    pub fn from_csv(csv: &str) -> Result<Self, MemFsError> {
        let mut timeline = Self::new();
        let mut lines = csv.lines();

        // Skip header
        match lines.next() {
            Some(h) if h.starts_with("timestamp") => {}
            Some(other) => {
                return Err(MemFsError::Serialization(format!(
                    "unexpected CSV header: {other}"
                )));
            }
            None => return Ok(timeline),
        }

        for (line_no, line) in lines.enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let fields = parse_csv_line(line);
            if fields.len() < 5 {
                return Err(MemFsError::Serialization(format!(
                    "line {}: expected 5 fields, got {}",
                    line_no + 2,
                    fields.len()
                )));
            }
            let timestamp: u64 = fields[0].parse().map_err(|_| {
                MemFsError::Serialization(format!(
                    "line {}: invalid timestamp {:?}",
                    line_no + 2,
                    fields[0]
                ))
            })?;
            let event_type = parse_event_type(&fields[1]);
            let path = fields[2].clone();
            let process = if fields[3].is_empty() {
                None
            } else {
                Some(fields[3].clone())
            };
            let pid: Option<u32> = if fields[4].is_empty() {
                None
            } else {
                Some(fields[4].parse().map_err(|_| {
                    MemFsError::Serialization(format!(
                        "line {}: invalid pid {:?}",
                        line_no + 2,
                        fields[4]
                    ))
                })?)
            };
            timeline.push(TimelineEvent {
                timestamp,
                event_type,
                path,
                process,
                pid,
                size: None,
                inode: None,
                extra: HashMap::new(),
            });
        }

        Ok(timeline)
    }
}

// ─── TimelineReport ───────────────────────────────────────────────────────────

/// Summary statistics over a [`Timeline`].
#[derive(Debug, Clone)]
pub struct TimelineReport {
    /// Total number of events.
    pub total: usize,
    /// Timestamp of the earliest event.
    pub first_ts: u64,
    /// Timestamp of the latest event.
    pub last_ts: u64,
    /// Duration from first to last event in seconds.
    pub duration_secs: u64,
    /// Event count grouped by type name.
    pub events_by_type: HashMap<String, usize>,
    /// Top-10 most-accessed paths.
    pub hot_paths: Vec<(String, usize)>,
    /// Number of unique process names seen.
    pub unique_processes: usize,
}

// ─── CSV helpers ─────────────────────────────────────────────────────────────

fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' => {
                in_quotes = true;
            }
            ',' if !in_quotes => {
                fields.push(current.clone());
                current.clear();
            }
            other => {
                current.push(other);
            }
        }
    }
    fields.push(current);
    fields
}

fn parse_event_type(s: &str) -> TimelineEventType {
    if s.starts_with("Move(") && s.ends_with(')') {
        let from = s[5..s.len() - 1].to_string();
        return TimelineEventType::Move { from };
    }
    match s {
        "Create" => TimelineEventType::Create,
        "Modify" => TimelineEventType::Modify,
        "Delete" => TimelineEventType::Delete,
        "HardLink" => TimelineEventType::HardLink,
        "SymLink" => TimelineEventType::SymLink,
        "PermChange" => TimelineEventType::PermChange,
        "OwnerChange" => TimelineEventType::OwnerChange,
        "Mount" => TimelineEventType::Mount,
        "Unmount" => TimelineEventType::Unmount,
        "Execute" => TimelineEventType::Execute,
        _ => TimelineEventType::Access, // fallback
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_timeline() -> Timeline {
        let mut t = Timeline::new();
        t.push(
            TimelineEvent::new(1000, TimelineEventType::Create, "/home/user/file.txt")
                .with_process("bash", 1234)
                .with_size(512),
        );
        t.push(
            TimelineEvent::new(1010, TimelineEventType::Modify, "/home/user/file.txt")
                .with_process("vim", 1235),
        );
        t.push(
            TimelineEvent::new(1020, TimelineEventType::Access, "/etc/passwd")
                .with_process("cat", 1236),
        );
        t.push(
            TimelineEvent::new(1030, TimelineEventType::Delete, "/tmp/junk")
                .with_process("bash", 1234),
        );
        t.push(
            TimelineEvent::new(1040, TimelineEventType::Execute, "/usr/bin/ls")
                .with_process("bash", 1234),
        );
        t.push(
            TimelineEvent::new(
                1050,
                TimelineEventType::Move {
                    from: "/tmp/a".into(),
                },
                "/home/user/a",
            )
            .with_process("bash", 1234),
        );
        t
    }

    #[test]
    fn timeline_new_is_empty() {
        let t = Timeline::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn timeline_push_len() {
        let mut t = Timeline::new();
        t.push(TimelineEvent::new(100, TimelineEventType::Create, "/a"));
        assert_eq!(t.len(), 1);
        assert!(!t.is_empty());
    }

    #[test]
    fn timeline_sort_by_time() {
        let mut t = Timeline::new();
        t.push(TimelineEvent::new(200, TimelineEventType::Access, "/b"));
        t.push(TimelineEvent::new(100, TimelineEventType::Create, "/a"));
        t.push(TimelineEvent::new(300, TimelineEventType::Delete, "/c"));
        t.sort_by_time();
        let ts: Vec<u64> = t.events().map(|e| e.timestamp).collect();
        assert_eq!(ts, vec![100, 200, 300]);
    }

    #[test]
    fn filter_by_time_range() {
        let t = make_timeline();
        let filtered = t.filter_by_time(1010, 1030);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn filter_by_time_empty_range() {
        let t = make_timeline();
        assert!(t.filter_by_time(9000, 9999).is_empty());
    }

    #[test]
    fn filter_by_type_create() {
        let t = make_timeline();
        let creates = t.filter_by_type("Create");
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0].path, "/home/user/file.txt");
    }

    #[test]
    fn filter_by_type_move() {
        let t = make_timeline();
        let moves = t.filter_by_type("Move");
        assert_eq!(moves.len(), 1);
    }

    #[test]
    fn filter_by_path_prefix() {
        let t = make_timeline();
        let home_events = t.filter_by_path_prefix("/home/user");
        assert_eq!(home_events.len(), 3);
    }

    #[test]
    fn events_near_window() {
        let t = make_timeline();
        let near = t.events_near(1025, 10);
        // Should include events at 1020, 1030
        assert!(near.iter().any(|e| e.timestamp == 1020));
        assert!(near.iter().any(|e| e.timestamp == 1030));
    }

    #[test]
    fn events_near_no_overflow() {
        let t = make_timeline();
        // ts=5, window=10 → lo=0 (saturating sub)
        let near = t.events_near(5, 10);
        assert!(near.is_empty());
    }

    #[test]
    fn hot_paths_top1() {
        let t = make_timeline();
        let hot = t.hot_paths(1);
        assert_eq!(hot.len(), 1);
        // /home/user/file.txt appears twice
        assert_eq!(hot[0].0, "/home/user/file.txt");
        assert_eq!(hot[0].1, 2);
    }

    #[test]
    fn hot_paths_all() {
        let t = make_timeline();
        let hot = t.hot_paths(100);
        assert_eq!(hot.len(), 5); // 5 unique paths
    }

    #[test]
    fn report_total() {
        let t = make_timeline();
        let r = t.report();
        assert_eq!(r.total, 6);
    }

    #[test]
    fn report_first_last_ts() {
        let t = make_timeline();
        let r = t.report();
        assert_eq!(r.first_ts, 1000);
        assert_eq!(r.last_ts, 1050);
        assert_eq!(r.duration_secs, 50);
    }

    #[test]
    fn report_events_by_type_counts() {
        let t = make_timeline();
        let r = t.report();
        assert_eq!(r.events_by_type.get("Create").copied().unwrap_or(0), 1);
        assert_eq!(r.events_by_type.get("Modify").copied().unwrap_or(0), 1);
        assert_eq!(r.events_by_type.get("Execute").copied().unwrap_or(0), 1);
    }

    #[test]
    fn report_unique_processes() {
        let t = make_timeline();
        let r = t.report();
        // bash, vim, cat
        assert_eq!(r.unique_processes, 3);
    }

    #[test]
    fn report_empty_timeline() {
        let t = Timeline::new();
        let r = t.report();
        assert_eq!(r.total, 0);
        assert_eq!(r.duration_secs, 0);
        assert!(r.events_by_type.is_empty());
    }

    #[test]
    fn to_csv_has_header() {
        let t = make_timeline();
        let csv = t.to_csv();
        assert!(csv.starts_with("timestamp,type,path,process,pid"));
    }

    #[test]
    fn to_csv_line_count() {
        let t = make_timeline();
        let csv = t.to_csv();
        
        // 1 header + 6 data rows
        assert_eq!(csv.lines().count(), 7);
    }

    #[test]
    fn csv_roundtrip() {
        let t = make_timeline();
        let csv = t.to_csv();
        let t2 = Timeline::from_csv(&csv).unwrap();
        assert_eq!(t2.len(), t.len());
    }

    #[test]
    fn csv_roundtrip_timestamps() {
        let t = make_timeline();
        let csv = t.to_csv();
        let t2 = Timeline::from_csv(&csv).unwrap();
        let ts1: Vec<u64> = t.events().map(|e| e.timestamp).collect();
        let ts2: Vec<u64> = t2.events().map(|e| e.timestamp).collect();
        assert_eq!(ts1, ts2);
    }

    #[test]
    fn csv_roundtrip_paths() {
        let t = make_timeline();
        let csv = t.to_csv();
        let t2 = Timeline::from_csv(&csv).unwrap();
        let paths1: Vec<&str> = t.events().map(|e| e.path.as_str()).collect();
        let paths2: Vec<String> = t2.events().map(|e| e.path.clone()).collect();
        assert_eq!(
            paths1,
            paths2.iter().map(std::string::String::as_str).collect::<Vec<_>>()
        );
    }

    #[test]
    fn from_csv_bad_header_errors() {
        let result = Timeline::from_csv("bad,header\n1,Create,/a,,");
        assert!(result.is_err());
    }

    #[test]
    fn from_csv_empty_body() {
        let t = Timeline::from_csv("timestamp,type,path,process,pid\n").unwrap();
        assert!(t.is_empty());
    }

    #[test]
    fn from_csv_move_event() {
        let csv = "timestamp,type,path,process,pid\n1000,\"Move(/tmp/old)\",/new/path,,\n";
        let t = Timeline::from_csv(csv).unwrap();
        assert_eq!(t.len(), 1);
        if let TimelineEventType::Move { from } = &t.events().next().unwrap().event_type {
            assert_eq!(from, "/tmp/old");
        } else {
            panic!("expected Move event");
        }
    }

    #[test]
    fn event_new_builder_process() {
        let e = TimelineEvent::new(999, TimelineEventType::Execute, "/bin/sh")
            .with_process("init", 1)
            .with_size(65536)
            .with_inode(42);
        assert_eq!(e.process.as_deref(), Some("init"));
        assert_eq!(e.pid, Some(1));
        assert_eq!(e.size, Some(65536));
        assert_eq!(e.inode, Some(42));
    }

    #[test]
    fn event_with_extra() {
        let e =
            TimelineEvent::new(100, TimelineEventType::Create, "/a").with_extra("hash", "deadbeef");
        assert_eq!(e.extra.get("hash").map(std::string::String::as_str), Some("deadbeef"));
    }

    #[test]
    fn event_type_display_move() {
        let t = TimelineEventType::Move {
            from: "/old".into(),
        };
        assert_eq!(t.to_string(), "Move(/old)");
    }

    #[test]
    fn event_type_kind_name_move() {
        let t = TimelineEventType::Move {
            from: "/old".into(),
        };
        assert_eq!(t.kind_name(), "Move");
    }

    #[test]
    fn csv_field_escaping() {
        let s = csv_field("a,b");
        assert!(s.starts_with('"') && s.ends_with('"'));
    }

    #[test]
    fn csv_field_no_escaping_needed() {
        assert_eq!(csv_field("hello"), "hello");
    }
}
