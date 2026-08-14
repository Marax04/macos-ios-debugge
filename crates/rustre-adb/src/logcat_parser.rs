//! `logcat_parser` — Parse Android logcat output.
//!
//! Handles multiple logcat formats (brief, threadtime, long, raw) and
//! provides filtering by tag, priority, and PID, plus crash-trace detection.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// LogPriority
// ─────────────────────────────────────────────────────────────────────────────

/// Android logcat priority level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogPriority {
    Unknown = 0,
    Default = 1,
    Verbose = 2,
    Debug = 3,
    Info = 4,
    Warn = 5,
    Error = 6,
    Fatal = 7,
    Silent = 8,
}

impl LogPriority {
    /// Parse a single character ('V', 'D', 'I', 'W', 'E', 'F', 'S') to a priority.
    #[must_use]
    pub const fn from_char(c: char) -> Self {
        match c {
            'V' => Self::Verbose,
            'D' => Self::Debug,
            'I' => Self::Info,
            'W' => Self::Warn,
            'E' => Self::Error,
            'F' => Self::Fatal,
            'S' => Self::Silent,
            _ => Self::Unknown,
        }
    }

    /// Return the single-character representation.
    #[must_use]
    pub const fn as_char(self) -> char {
        match self {
            Self::Verbose => 'V',
            Self::Debug => 'D',
            Self::Info => 'I',
            Self::Warn => 'W',
            Self::Error => 'E',
            Self::Fatal => 'F',
            Self::Silent => 'S',
            Self::Unknown | Self::Default => '?',
        }
    }

    /// Returns `true` if this priority is at least as severe as `min`.
    #[must_use]
    pub const fn at_least(self, min: Self) -> bool {
        (self as u8) >= (min as u8)
    }
}

impl std::fmt::Display for LogPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_char())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LogEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single parsed logcat entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp string as it appeared in the log (may be empty for brief format).
    pub timestamp: String,
    /// Process ID.
    pub pid: Option<u32>,
    /// Thread ID.
    pub tid: Option<u32>,
    /// Priority / log level.
    pub priority: LogPriority,
    /// Tag (component name).
    pub tag: String,
    /// Log message.
    pub message: String,
    /// Log buffer name (main, system, crash, …).
    pub buffer: Option<String>,
}

impl LogEntry {
    /// Returns `true` if this entry has priority >= Error.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self.priority, LogPriority::Error | LogPriority::Fatal)
    }

    /// Returns `true` if this entry looks like part of a stack trace.
    #[must_use]
    pub fn is_stack_frame(&self) -> bool {
        let m = &self.message;
        m.contains("at ") && (m.contains(".java:") || m.contains("(Unknown Source)"))
            || m.starts_with('\t')
            || (m.len() > 2 && m.starts_with("#0"))
    }

    /// Returns `true` if this entry is a crash header line.
    #[must_use]
    pub fn is_crash_header(&self) -> bool {
        let m = &self.message;
        m.contains("FATAL EXCEPTION")
            || m.starts_with("*** *** ***")
            || m.starts_with("*** FATAL SIGNAL")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LogcatParser
// ─────────────────────────────────────────────────────────────────────────────

/// Stateless parser for logcat output in multiple formats.
pub struct LogcatParser;

impl LogcatParser {
    /// Parse a complete logcat text buffer into a list of [`LogEntry`] records.
    ///
    /// Tries threadtime, brief, and raw formats in that order per line.
    #[must_use]
    pub fn parse(text: &str) -> Vec<LogEntry> {
        text.lines().filter_map(Self::parse_line).collect()
    }

    /// Parse a single log line, trying all known formats.
    #[must_use]
    pub fn parse_line(line: &str) -> Option<LogEntry> {
        let line = line.trim();
        if line.is_empty() || line.starts_with("-----") || line.starts_with("--") {
            return None;
        }
        Self::parse_threadtime(line)
            .or_else(|| Self::parse_brief(line))
            .or_else(|| Self::parse_tag_message(line))
    }

    /// Parse a **threadtime** format line:
    /// `MM-DD HH:MM:SS.mmm  PID  TID PRIORITY TAG: MESSAGE`
    #[must_use]
    pub fn parse_threadtime(line: &str) -> Option<LogEntry> {
        // Example: "01-15 12:34:56.789  1234  5678 I ActivityManager: Starting"
        // Use split_ascii_whitespace to handle variable spacing between fields.
        let mut sw = line.split_ascii_whitespace();
        let date = sw.next()?;
        let time = sw.next()?;
        let pid_str = sw.next()?;
        let tid_str = sw.next()?;
        let prio_str = sw.next()?;
        if prio_str.len() != 1 {
            return None;
        }
        // Derive the rest of the line starting after prio_str using pointer offset.
        let prio_end = prio_str.as_ptr() as usize + prio_str.len() - line.as_ptr() as usize;
        let rest = line[prio_end..].trim_start();
        let timestamp = format!("{} {}", date, time);
        let pid: u32 = pid_str.parse().ok()?;
        let tid: u32 = tid_str.parse().ok()?;
        let priority = LogPriority::from_char(prio_str.chars().next()?);
        let colon = rest.find(':')?;
        let tag = rest[..colon].trim().to_owned();
        let message = rest[colon + 1..].trim().to_owned();
        Some(LogEntry {
            timestamp,
            pid: Some(pid),
            tid: Some(tid),
            priority,
            tag,
            message,
            buffer: None,
        })
    }

    /// Parse a **brief** format line:
    /// `PRIORITY/TAG(PID): MESSAGE`
    #[must_use]
    pub fn parse_brief(line: &str) -> Option<LogEntry> {
        // Example: "I/ActivityManager(  432): Starting"
        let line = line.trim();
        if line.len() < 3 {
            return None;
        }
        let prio_char = line.chars().next()?;
        if line.chars().nth(1) != Some('/') {
            return None;
        }
        let priority = LogPriority::from_char(prio_char);
        let rest = &line[2..];
        let open_paren = rest.find('(')?;
        let tag = rest[..open_paren].trim().to_owned();
        let rest2 = &rest[open_paren + 1..];
        let close_paren = rest2.find(')')?;
        let pid_str = rest2[..close_paren].trim();
        let pid: Option<u32> = pid_str.parse().ok();
        let message = rest2[close_paren + 1..]
            .trim_start_matches(':')
            .trim()
            .to_owned();
        Some(LogEntry {
            timestamp: String::new(),
            pid,
            tid: None,
            priority,
            tag,
            message,
            buffer: None,
        })
    }

    /// Parse a raw `TAG: MESSAGE` line with no pid/timestamp.
    #[must_use]
    pub fn parse_tag_message(line: &str) -> Option<LogEntry> {
        let colon = line.find(':')?;
        let tag = line[..colon].trim().to_owned();
        if tag.is_empty() || tag.contains(' ') {
            return None;
        }
        let message = line[colon + 1..].trim().to_owned();
        Some(LogEntry {
            timestamp: String::new(),
            pid: None,
            tid: None,
            priority: LogPriority::Unknown,
            tag,
            message,
            buffer: None,
        })
    }

    /// Parse entries and annotate each with a buffer name extracted from
    /// `--------- beginning of <buffer>` separator lines.
    #[must_use]
    pub fn parse_with_buffers(text: &str) -> Vec<LogEntry> {
        let mut current_buffer: Option<String> = None;
        let mut results = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("--------- beginning of ") {
                current_buffer = Some(rest.trim().to_owned());
                continue;
            }
            if let Some(mut entry) = Self::parse_line(trimmed) {
                entry.buffer.clone_from(&current_buffer);
                results.push(entry);
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LogEntryFilter
// ─────────────────────────────────────────────────────────────────────────────

/// Criteria for filtering a slice of [`LogEntry`] records.
#[derive(Debug, Clone, Default)]
pub struct LogEntryFilter {
    /// Keep only entries at or above this priority.
    pub min_priority: Option<LogPriority>,
    /// Keep only entries whose tag contains this substring (case-insensitive).
    pub tag_contains: Option<String>,
    /// Keep only entries from this PID.
    pub pid: Option<u32>,
    /// Keep only entries whose message contains this substring (case-insensitive).
    pub message_contains: Option<String>,
    /// Keep only entries from this buffer (e.g. `"main"`, `"crash"`).
    pub buffer: Option<String>,
}

impl LogEntryFilter {
    /// Create an empty (pass-all) filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply the filter to a slice of entries.
    #[must_use]
    pub fn apply<'a>(&self, entries: &'a [LogEntry]) -> Vec<&'a LogEntry> {
        entries
            .iter()
            .filter(|e| self.matches(e))
            .collect()
    }

    fn matches(&self, e: &LogEntry) -> bool {
        if let Some(min) = self.min_priority
            && !e.priority.at_least(min)
        {
            return false;
        }
        if let Some(ref tag) = self.tag_contains
            && !e.tag.to_lowercase().contains(&tag.to_lowercase())
        {
            return false;
        }
        if let Some(pid) = self.pid
            && e.pid != Some(pid)
        {
            return false;
        }
        if let Some(ref msg) = self.message_contains
            && !e.message.to_lowercase().contains(&msg.to_lowercase())
        {
            return false;
        }
        if let Some(ref buf) = self.buffer
            && e.buffer.as_deref().unwrap_or("") != buf.as_str()
        {
            return false;
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrashDetector
// ─────────────────────────────────────────────────────────────────────────────

/// A detected crash event extracted from logcat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashEvent {
    /// Process name.
    pub process_name: Option<String>,
    /// PID of the crashed process.
    pub pid: Option<u32>,
    /// Exception class (e.g. `"java.lang.NullPointerException"`).
    pub exception_class: Option<String>,
    /// Short exception message.
    pub exception_message: Option<String>,
    /// All log entries that belong to this crash.
    pub entries: Vec<LogEntry>,
    /// Stack frames extracted from the crash.
    pub stack_frames: Vec<String>,
    /// Whether this appears to be a native crash (signal/tombstone).
    pub is_native: bool,
}

impl CrashEvent {
    /// Return a one-line summary of the crash.
    #[must_use]
    pub fn summary(&self) -> String {
        let pid_str = self
            .pid
            .map_or_else(|| "?".to_string(), |p| p.to_string());
        let exc = self
            .exception_class
            .as_deref()
            .unwrap_or("unknown exception");
        let proc = self.process_name.as_deref().unwrap_or("?");
        format!("CRASH pid={pid_str} proc={proc} exc={exc}")
    }
}

/// Detects crash events in a parsed logcat stream.
pub struct CrashDetector;

impl CrashDetector {
    /// Scan a list of log entries and group them into [`CrashEvent`]s.
    ///
    /// A crash group starts at a `FATAL EXCEPTION` or `*** FATAL SIGNAL` line
    /// and continues as long as subsequent entries have the same PID and include
    /// stack trace lines.
    #[must_use]
    pub fn detect(entries: &[LogEntry]) -> Vec<CrashEvent> {
        let mut crashes: Vec<CrashEvent> = Vec::new();
        let mut i = 0;

        while i < entries.len() {
            let e = &entries[i];
            if e.is_crash_header() {
                let crash_pid = e.pid;
                let is_native = e.message.contains("signal ")
                    || e.message.starts_with("*** FATAL SIGNAL")
                    || e.message.starts_with("*** *** ***");

                let mut crash = CrashEvent {
                    process_name: None,
                    pid: crash_pid,
                    exception_class: None,
                    exception_message: None,
                    entries: Vec::new(),
                    stack_frames: Vec::new(),
                    is_native,
                };
                crash.entries.push(e.clone());

                // Collect related entries.
                let mut j = i + 1;
                while j < entries.len() {
                    let next = &entries[j];
                    let same_pid = crash_pid.is_none() || next.pid == crash_pid;
                    if !same_pid {
                        break;
                    }
                    if next.is_stack_frame() {
                        crash.stack_frames.push(next.message.trim().to_owned());
                    }
                    // Extract process name.
                    if next.message.starts_with("Process: ") {
                        crash.process_name =
                            Some(next.message["Process: ".len()..].trim().to_owned());
                    }
                    // Extract exception class from lines like "java.lang.NullPointerException: ..."
                    if crash.exception_class.is_none()
                        && next.message.starts_with("java.")
                        || next.message.starts_with("android.")
                        || next.message.starts_with("kotlin.")
                    {
                        let first_line = next.message.lines().next().unwrap_or(&next.message);
                        let (class, msg) = first_line.find(": ").map_or_else(
                            || (first_line.to_owned(), None),
                            |colon| (
                                first_line[..colon].to_owned(),
                                Some(first_line[colon + 2..].to_owned()),
                            ),
                        );
                        if class.contains('.') {
                            crash.exception_class = Some(class);
                            crash.exception_message = msg;
                        }
                    }
                    crash.entries.push(next.clone());
                    j += 1;
                    // Stop if we hit another crash header or a large gap.
                    if j < entries.len() && entries[j].is_crash_header() {
                        break;
                    }
                }
                i = j;
                crashes.push(crash);
            } else {
                i += 1;
            }
        }

        crashes
    }

    /// Return only crashes from a specific PID.
    #[must_use]
    pub fn crashes_by_pid(events: &[CrashEvent], pid: u32) -> Vec<&CrashEvent> {
        events.iter().filter(|c| c.pid == Some(pid)).collect()
    }

    /// Return only native crashes.
    #[must_use]
    pub fn native_crashes(events: &[CrashEvent]) -> Vec<&CrashEvent> {
        events.iter().filter(|c| c.is_native).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LogcatStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics over a parsed logcat stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogcatStats {
    /// Total number of entries.
    pub total: usize,
    /// Count per priority level.
    pub by_priority: HashMap<String, usize>,
    /// Top 10 most active tags by entry count.
    pub top_tags: Vec<(String, usize)>,
    /// Top 10 most active PIDs.
    pub top_pids: Vec<(u32, usize)>,
    /// Number of error or fatal entries.
    pub error_count: usize,
}

impl LogcatStats {
    /// Compute statistics from a slice of entries.
    #[must_use]
    pub fn compute(entries: &[LogEntry]) -> Self {
        let total = entries.len();
        let mut by_priority: HashMap<String, usize> = HashMap::new();
        let mut tag_counts: HashMap<String, usize> = HashMap::new();
        let mut pid_counts: HashMap<u32, usize> = HashMap::new();
        let mut error_count = 0usize;

        for e in entries {
            *by_priority.entry(e.priority.to_string()).or_insert(0) += 1;
            *tag_counts.entry(e.tag.clone()).or_insert(0) += 1;
            if let Some(pid) = e.pid {
                *pid_counts.entry(pid).or_insert(0) += 1;
            }
            if e.is_error() {
                error_count += 1;
            }
        }

        // Both maps are HashMaps, so ties are ordered arbitrarily — and the
        // `truncate(10)` turns that into a difference in CONTENT, not just in
        // order: among entries with the same count, which ones make the top ten
        // would change between runs on the same log. Break ties on the key.
        let mut top_tags: Vec<(String, usize)> = tag_counts.into_iter().collect();
        top_tags.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top_tags.truncate(10);

        let mut top_pids: Vec<(u32, usize)> = pid_counts.into_iter().collect();
        top_pids.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top_pids.truncate(10);

        Self {
            total,
            by_priority,
            top_tags,
            top_pids,
            error_count,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_brief_info() {
        let line = "I/ActivityManager(  432): Starting";
        let e = LogcatParser::parse_brief(line).unwrap();
        assert_eq!(e.priority, LogPriority::Info);
        assert_eq!(e.tag, "ActivityManager");
        assert_eq!(e.pid, Some(432));
        assert_eq!(e.message, "Starting");
    }

    #[test]
    fn test_parse_brief_error() {
        let line = "E/AndroidRuntime(1234): FATAL EXCEPTION: main";
        let e = LogcatParser::parse_brief(line).unwrap();
        assert_eq!(e.priority, LogPriority::Error);
        assert_eq!(e.pid, Some(1234));
    }

    #[test]
    fn test_parse_threadtime() {
        let line = "01-15 12:34:56.789  1234  5678 I MyTag: hello world";
        let e = LogcatParser::parse_threadtime(line).unwrap();
        assert_eq!(e.priority, LogPriority::Info);
        assert_eq!(e.pid, Some(1234));
        assert_eq!(e.tid, Some(5678));
        assert_eq!(e.tag, "MyTag");
        assert_eq!(e.message, "hello world");
        assert!(e.timestamp.contains("12:34:56"));
    }

    #[test]
    fn test_parse_line_separator() {
        assert!(LogcatParser::parse_line("--------- beginning of main").is_none());
    }

    #[test]
    fn test_parse_line_empty() {
        assert!(LogcatParser::parse_line("").is_none());
    }

    #[test]
    fn test_parse_batch() {
        let text = "I/Tag1(100): msg1\nE/Tag2(200): msg2\n";
        let entries = LogcatParser::parse(text);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_with_buffers() {
        let text = "--------- beginning of main\nI/Tag(1): hello\n";
        let entries = LogcatParser::parse_with_buffers(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].buffer.as_deref(), Some("main"));
    }

    #[test]
    fn test_filter_by_priority() {
        let entries = vec![
            make_entry(LogPriority::Debug, "T", 1),
            make_entry(LogPriority::Error, "T", 2),
        ];
        let mut f = LogEntryFilter::new();
        f.min_priority = Some(LogPriority::Error);
        let result = f.apply(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].priority, LogPriority::Error);
    }

    #[test]
    fn test_filter_by_tag() {
        let e1 = make_entry(LogPriority::Info, "ActivityManager", 1);
        let e2 = make_entry(LogPriority::Info, "BatteryService", 2);
        let entries = vec![e1, e2];
        let mut f = LogEntryFilter::new();
        f.tag_contains = Some("activity".to_string());
        let result = f.apply(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].tag, "ActivityManager");
    }

    #[test]
    fn test_filter_by_pid() {
        let entries = vec![
            make_entry_pid(LogPriority::Info, "T", 100),
            make_entry_pid(LogPriority::Info, "T", 200),
        ];
        let mut f = LogEntryFilter::new();
        f.pid = Some(100);
        let result = f.apply(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, Some(100));
    }

    #[test]
    fn test_crash_detector_java_crash() {
        let entries = vec![
            make_crash_entry("FATAL EXCEPTION: main", 1234),
            make_crash_entry("Process: com.example, PID: 1234", 1234),
            make_crash_entry("java.lang.NullPointerException: attempt to invoke", 1234),
            make_crash_entry("\tat com.example.MainActivity.onCreate(MainActivity.java:42)", 1234),
        ];
        let crashes = CrashDetector::detect(&entries);
        assert_eq!(crashes.len(), 1);
        assert!(!crashes[0].is_native);
        assert!(!crashes[0].stack_frames.is_empty());
    }

    #[test]
    fn test_crash_detector_no_crash() {
        let entries = vec![
            make_entry(LogPriority::Info, "Tag", 1),
            make_entry(LogPriority::Debug, "Tag2", 2),
        ];
        let crashes = CrashDetector::detect(&entries);
        assert!(crashes.is_empty());
    }

    #[test]
    fn test_logcat_stats() {
        let entries = vec![
            make_entry(LogPriority::Info, "Tag", 1),
            make_entry(LogPriority::Error, "Tag", 2),
            make_entry(LogPriority::Error, "Other", 3),
        ];
        let stats = LogcatStats::compute(&entries);
        assert_eq!(stats.total, 3);
        assert_eq!(stats.error_count, 2);
        assert!(!stats.top_tags.is_empty());
    }

    #[test]
    fn test_priority_at_least() {
        assert!(LogPriority::Error.at_least(LogPriority::Warn));
        assert!(!LogPriority::Info.at_least(LogPriority::Error));
    }

    #[test]
    fn test_priority_from_char() {
        assert_eq!(LogPriority::from_char('V'), LogPriority::Verbose);
        assert_eq!(LogPriority::from_char('E'), LogPriority::Error);
        assert_eq!(LogPriority::from_char('?'), LogPriority::Unknown);
    }

    #[test]
    fn test_log_entry_is_error() {
        let e = make_entry(LogPriority::Fatal, "T", 1);
        assert!(e.is_error());
        let e2 = make_entry(LogPriority::Info, "T", 2);
        assert!(!e2.is_error());
    }

    #[test]
    fn test_log_entry_is_stack_frame() {
        let mut e = make_entry(LogPriority::Error, "AndroidRuntime", 1);
        e.message = "\tat com.example.Foo.bar(Foo.java:10)".to_string();
        assert!(e.is_stack_frame());
    }

    // ─── helpers ─────────────────────────────────────────────────────────────

    fn make_entry(priority: LogPriority, tag: &str, pid: u32) -> LogEntry {
        LogEntry {
            timestamp: String::new(),
            pid: Some(pid),
            tid: None,
            priority,
            tag: tag.to_string(),
            message: "test message".to_string(),
            buffer: None,
        }
    }

    fn make_entry_pid(priority: LogPriority, tag: &str, pid: u32) -> LogEntry {
        make_entry(priority, tag, pid)
    }

    fn make_crash_entry(message: &str, pid: u32) -> LogEntry {
        LogEntry {
            timestamp: String::new(),
            pid: Some(pid),
            tid: None,
            priority: LogPriority::Error,
            tag: "AndroidRuntime".to_string(),
            message: message.to_string(),
            buffer: None,
        }
    }
}
