//! # logcat.rs — Android Logcat Reader
//!
//! Provides structured parsing of Android logcat output in both text formats
//! (brief, threadtime, long, process, tag, time) and the binary logcat format.
//!
//! ## Text formats
//!
//! ### Brief
//! ```text
//! I/ActivityManager(  432): Starting: Intent { ... }
//! ```
//!
//! ### Threadtime
//! ```text
//! 01-15 12:00:00.123  1234  5678 I SomeTag: the message
//! ```
//!
//! ### Time
//! ```text
//! 01-15 12:00:00.123 I/SomeTag(1234): message
//! ```
//!
//! ### Process
//! ```text
//! I(  432) message (SomeTag)
//! ```
//!
//! ### Long
//! Multi-line block starting with `[ MM-DD HH:MM:SS.mmm PID:TID prio/tag ]`

use std::collections::HashMap;
pub use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use crate::{AdbError, Result};

use crate::{LogEntry, LogLevel};

// ─── LogcatFormat ─────────────────────────────────────────────────────────────

/// The text output format selected with `logcat -v <format>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LogcatFormat {
    Brief,
    Process,
    Tag,
    Raw,
    Time,
    #[default]
    Threadtime,
    Long,
}

impl LogcatFormat {
    /// The `-v` argument value for `logcat`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Brief => "brief",
            Self::Process => "process",
            Self::Tag => "tag",
            Self::Raw => "raw",
            Self::Time => "time",
            Self::Threadtime => "threadtime",
            Self::Long => "long",
        }
    }
}

// ─── LogcatPriority (raw binary values) ──────────────────────────────────────

/// Logcat priority as stored in the binary log format.
///
/// Values match Android's `android_LogPriority` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum Priority {
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

impl Priority {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Default,
            2 => Self::Verbose,
            3 => Self::Debug,
            4 => Self::Info,
            5 => Self::Warn,
            6 => Self::Error,
            7 => Self::Fatal,
            8 => Self::Silent,
            _ => Self::Unknown,
        }
    }

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
            _ => '?',
        }
    }

    #[must_use]
    pub const fn to_log_level(self) -> LogLevel {
        match self {
            Self::Verbose => LogLevel::Verbose,
            Self::Debug => LogLevel::Debug,
            Self::Warn => LogLevel::Warning,
            Self::Error => LogLevel::Error,
            Self::Fatal => LogLevel::Fatal,
            Self::Silent => LogLevel::Silent,
            _ => LogLevel::Info,
        }
    }
}

impl From<Priority> for LogLevel {
    fn from(p: Priority) -> Self {
        p.to_log_level()
    }
}

// ─── LogcatEntry — enriched entry ─────────────────────────────────────────────

/// A fully-parsed logcat entry with all available metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogcatEntry {
    /// Formatted timestamp string (e.g. `"01-15 12:00:00.123"`).
    pub timestamp: String,
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Priority / severity level.
    pub priority: Priority,
    /// Log tag.
    pub tag: String,
    /// The log message body.
    pub message: String,
    /// Which buffer this entry came from (`main`, `system`, `crash`, `radio`).
    pub buffer: LogBuffer,
}

impl LogcatEntry {
    /// Convert to the simpler `LogEntry` type.
    #[must_use]
    pub fn to_log_entry(&self) -> LogEntry {
        LogEntry {
            tag: self.tag.clone(),
            pid: self.pid,
            tid: self.tid,
            level: self.priority.to_log_level(),
            message: self.message.clone(),
            timestamp: self.timestamp.clone(),
        }
    }

    /// Return `true` if the entry matches the given filter.
    #[must_use]
    pub fn matches(&self, filter: &LogcatFilter) -> bool {
        filter.matches(self)
    }

    /// Format as a threadtime-style line.
    #[must_use]
    pub fn format_threadtime(&self) -> String {
        format!(
            "{} {:5} {:5} {} {}: {}",
            self.timestamp,
            self.pid,
            self.tid,
            self.priority.as_char(),
            self.tag,
            self.message
        )
    }

    /// Format as a brief-style line.
    #[must_use]
    pub fn format_brief(&self) -> String {
        format!(
            "{}/{} ({}): {}",
            self.priority.as_char(),
            self.tag,
            self.pid,
            self.message
        )
    }
}

// ─── LogBuffer ────────────────────────────────────────────────────────────────

/// Android logcat buffer identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LogBuffer {
    #[default]
    Main,
    System,
    Radio,
    Events,
    Crash,
    Kernel,
    Unknown,
}

impl LogBuffer {
    #[must_use]
    pub fn from_name(s: &str) -> Self {
        match s {
            "main" => Self::Main,
            "system" => Self::System,
            "radio" => Self::Radio,
            "events" => Self::Events,
            "crash" => Self::Crash,
            "kernel" => Self::Kernel,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::System => "system",
            Self::Radio => "radio",
            Self::Events => "events",
            Self::Crash => "crash",
            Self::Kernel => "kernel",
            Self::Unknown => "unknown",
        }
    }
}

// ─── LogcatFilter ─────────────────────────────────────────────────────────────

/// A set of conditions used to filter logcat entries.
#[derive(Debug, Clone, Default)]
pub struct LogcatFilter {
    /// Minimum priority level.  `None` means accept all.
    pub min_priority: Option<Priority>,
    /// Include only entries whose tag is in this set (empty = all tags).
    pub tags: Vec<String>,
    /// Exclude entries whose tag is in this set.
    pub excluded_tags: Vec<String>,
    /// Include only entries from these PIDs (empty = all PIDs).
    pub pids: Vec<u32>,
    /// Only include entries whose message contains this substring (case-insensitive).
    pub message_contains: Option<String>,
    /// Only include entries from this buffer.
    pub buffer: Option<LogBuffer>,
}

impl LogcatFilter {
    /// Create an empty filter (accepts everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept entries at or above this priority.
    #[must_use]
    pub const fn min_priority(mut self, p: Priority) -> Self {
        self.min_priority = Some(p);
        self
    }

    /// Accept only entries with these tags.
    #[must_use]
    pub fn tags<I: IntoIterator<Item = S>, S: Into<String>>(mut self, tags: I) -> Self {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// Exclude entries with these tags.
    #[must_use]
    pub fn exclude_tags<I: IntoIterator<Item = S>, S: Into<String>>(mut self, tags: I) -> Self {
        self.excluded_tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// Accept only entries from these PIDs.
    #[must_use]
    pub fn pids(mut self, pids: Vec<u32>) -> Self {
        self.pids = pids;
        self
    }

    /// Accept only entries whose message contains `s` (case-insensitive).
    #[must_use]
    pub fn message_contains(mut self, s: impl Into<String>) -> Self {
        self.message_contains = Some(s.into().to_lowercase());
        self
    }

    /// Accept only entries from this buffer.
    #[must_use]
    pub const fn buffer(mut self, b: LogBuffer) -> Self {
        self.buffer = Some(b);
        self
    }

    /// Return `true` if `entry` passes all filter conditions.
    #[must_use]
    pub fn matches(&self, entry: &LogcatEntry) -> bool {
        if let Some(min_p) = self.min_priority
            && entry.priority < min_p
        {
            return false;
        }
        if !self.tags.is_empty() {
            let tag_lower = entry.tag.to_lowercase();
            if !self.tags.iter().any(|t| t.to_lowercase() == tag_lower) {
                return false;
            }
        }
        if !self.excluded_tags.is_empty() {
            let tag_lower = entry.tag.to_lowercase();
            if self
                .excluded_tags
                .iter()
                .any(|t| t.to_lowercase() == tag_lower)
            {
                return false;
            }
        }
        if !self.pids.is_empty() && !self.pids.contains(&entry.pid) {
            return false;
        }
        if let Some(ref needle) = self.message_contains
            && !entry.message.to_lowercase().contains(needle.as_str())
        {
            return false;
        }
        if let Some(buf) = self.buffer
            && entry.buffer != buf
        {
            return false;
        }
        true
    }

    /// Build an `adb logcat` filter expression from the tag list and priority.
    ///
    /// Returns a string like `"ActivityManager:I *:S"`.
    #[must_use]
    pub fn to_logcat_args(&self) -> Vec<String> {
        let prio = self.min_priority.map_or('V', Priority::as_char);
        let extra = usize::from(!self.tags.is_empty());
        let mut args = Vec::with_capacity(self.tags.len() + extra);
        for tag in &self.tags {
            args.push(format!("{tag}:{prio}"));
        }
        if !self.tags.is_empty() {
            args.push("*:S".to_owned()); // silence everything else
        }
        args
    }
}

// ─── Text parsers ─────────────────────────────────────────────────────────────

/// Parse a single logcat line in **threadtime** format:
/// `MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG: message`
#[must_use]
pub fn parse_threadtime_line(line: &str) -> Option<LogcatEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('-') {
        return None;
    }
    // Split on whitespace at most 6 parts:
    // [0]=date [1]=time [2]=pid [3]=tid [4]=level [5]=rest
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }
    let date = parts[0].to_owned();
    let time = parts[1].to_owned();
    let pid: u32 = parts[2].parse().ok()?;
    let tid: u32 = parts[3].parse().ok()?;
    let level_str = parts[4];
    // Reconstruct the rest of the line after the level token.
    let level_pos = {
        // Find the byte offset of parts[5] in the original line.
        let p5 = parts[5];
        let p5_ptr = p5.as_ptr() as usize;
        let line_ptr = line.as_ptr() as usize;
        p5_ptr - line_ptr
    };
    let rest = line[level_pos..].trim();

    let priority = {
        let ch = level_str.chars().next()?;
        match ch {
            'V' => Priority::Verbose,
            'D' => Priority::Debug,
            // 'I' was missing and only reached `Info` through the catch-all.
            'I' => Priority::Info,
            'W' => Priority::Warn,
            'E' => Priority::Error,
            'F' => Priority::Fatal,
            'S' => Priority::Silent,
            // The priority alphabet is closed. `parse_brief_line` and
            // `parse_tag_line` both reject an unknown character; mapping it to
            // `Info` instead invented a real level for malformed input, so a
            // corrupt line surfaced as a genuine informational message.
            _ => return None,
        }
    };

    // rest = "TAG: message" or "TAG : message"
    let colon = rest.find(':')?;
    let tag = rest[..colon].trim().to_owned();
    let message = rest[colon + 1..].trim().to_owned();

    Some(LogcatEntry {
        timestamp: format!("{date} {time}"),
        pid,
        tid,
        priority,
        tag,
        message,
        buffer: LogBuffer::Main,
    })
}

/// Parse a single logcat line in **brief** format:
/// `L/TAG(PID): message`
#[must_use]
pub fn parse_brief_line(line: &str) -> Option<LogcatEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('-') {
        return None;
    }
    let level_char = line.chars().next()?;
    let priority = match level_char {
        'V' => Priority::Verbose,
        'D' => Priority::Debug,
        'I' => Priority::Info,
        'W' => Priority::Warn,
        'E' => Priority::Error,
        'F' => Priority::Fatal,
        'S' => Priority::Silent,
        _ => return None,
    };
    // Expect "L/TAG(PID): msg"
    let rest = line.get(2..)?; // skip "L/"
    if rest.is_empty() {
        return None;
    }
    let slash = line.find('/')?;
    let rest = &line[slash + 1..];
    let paren = rest.find('(')?;
    let tag = rest[..paren].trim().to_owned();
    let rest2 = &rest[paren + 1..];
    let close = rest2.find(')')?;
    let pid: u32 = rest2[..close].trim().parse().ok()?;
    let message = rest2[close + 1..].trim_start_matches(':').trim().to_owned();
    Some(LogcatEntry {
        timestamp: String::new(),
        pid,
        tid: 0,
        priority,
        tag,
        message,
        buffer: LogBuffer::Main,
    })
}

/// Parse a single logcat line in **tag** format: `L/TAG: message`
#[must_use]
pub fn parse_tag_line(line: &str) -> Option<LogcatEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('-') {
        return None;
    }
    let level_char = line.chars().next()?;
    let priority = match level_char {
        'V' => Priority::Verbose,
        'D' => Priority::Debug,
        'I' => Priority::Info,
        'W' => Priority::Warn,
        'E' => Priority::Error,
        'F' => Priority::Fatal,
        'S' => Priority::Silent,
        _ => return None,
    };
    let slash = line.find('/')?;
    let rest = &line[slash + 1..];
    let colon = rest.find(':')?;
    let tag = rest[..colon].trim().to_owned();
    let message = rest[colon + 1..].trim().to_owned();
    Some(LogcatEntry {
        timestamp: String::new(),
        pid: 0,
        tid: 0,
        priority,
        tag,
        message,
        buffer: LogBuffer::Main,
    })
}

/// Try all text parsers in order (threadtime, brief, tag).
#[must_use]
pub fn parse_any_line(line: &str) -> Option<LogcatEntry> {
    parse_threadtime_line(line)
        .or_else(|| parse_brief_line(line))
        .or_else(|| parse_tag_line(line))
}

/// Parse a complete block of logcat text output.
pub fn parse_text_output(output: &str) -> Vec<LogcatEntry> {
    output.lines().filter_map(parse_any_line).collect()
}

/// Parse threadtime output — the most common programmatic format.
pub fn parse_threadtime_output(output: &str) -> Vec<LogcatEntry> {
    output.lines().filter_map(parse_threadtime_line).collect()
}

// ─── Binary logcat format parser ──────────────────────────────────────────────

/// A single binary logcat record as read from `/dev/log/main`.
///
/// Binary format (v1):
/// ```text
/// ┌─────────┬─────────┬─────────┬──────────────────────────────┐
/// │  len u16│  hdr u16│  pid i32│  tid i32 │ sec i32 │ nsec i32│
/// └─────────┴─────────┴─────────┴──────────────────────────────┘
/// followed by:  priority(u8)  tag(\0-terminated)  message(\0-terminated)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryLogEntry {
    pub pid: i32,
    pub tid: i32,
    pub seconds: i32,
    pub nanosecs: i32,
    pub priority: Priority,
    pub tag: String,
    pub message: String,
}

impl BinaryLogEntry {
    /// Parse the variable-length payload part (priority + tag\0 + message\0).
    #[must_use]
    pub fn parse_payload(payload: &[u8]) -> Option<(Priority, String, String)> {
        if payload.is_empty() {
            return None;
        }
        let priority = Priority::from_u8(payload[0]);
        let rest = &payload[1..];
        // Find first NUL (end of tag)
        let tag_end = rest.iter().position(|&b| b == 0)?;
        let tag = String::from_utf8_lossy(&rest[..tag_end]).into_owned();
        let msg_start = tag_end + 1;
        if msg_start >= rest.len() {
            return None;
        }
        let msg_end = rest[msg_start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(rest.len(), |p| msg_start + p);
        let message = String::from_utf8_lossy(&rest[msg_start..msg_end]).into_owned();
        Some((priority, tag, message))
    }

    /// Parse a complete binary log record from a byte slice.
    ///
    /// Returns the record and the number of bytes consumed.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 20 {
            return None;
        }
        let payload_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let _hdr_size = u16::from_le_bytes([data[2], data[3]]) as usize;
        let pid = i32::from_le_bytes(data[4..8].try_into().ok()?);
        let tid = i32::from_le_bytes(data[8..12].try_into().ok()?);
        let seconds = i32::from_le_bytes(data[12..16].try_into().ok()?);
        let nanosecs = i32::from_le_bytes(data[16..20].try_into().ok()?);

        if data.len() < 20 + payload_len {
            return None;
        }
        let payload = &data[20..20 + payload_len];
        let (priority, tag, message) = Self::parse_payload(payload)?;

        let total = 20 + payload_len;
        Some((
            Self {
                pid,
                tid,
                seconds,
                nanosecs,
                priority,
                tag,
                message,
            },
            total,
        ))
    }

    /// Convert to a `LogcatEntry`.
    #[must_use]
    pub fn to_entry(&self) -> LogcatEntry {
        let ts = format_unix_timestamp(
            u64::try_from(self.seconds).unwrap_or(0),
            self.nanosecs.cast_unsigned(),
        );
        LogcatEntry {
            timestamp: ts,
            pid: self.pid.cast_unsigned(),
            tid: self.tid.cast_unsigned(),
            priority: self.priority,
            tag: self.tag.clone(),
            message: self.message.clone(),
            buffer: LogBuffer::Main,
        }
    }
}

/// Parse a byte buffer containing multiple binary log records.
#[must_use]
pub fn parse_binary_log(data: &[u8]) -> Vec<LogcatEntry> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        match BinaryLogEntry::parse(&data[pos..]) {
            Some((rec, consumed)) => {
                entries.push(rec.to_entry());
                pos += consumed;
            }
            None => break,
        }
    }
    entries
}

// ─── Statistics ───────────────────────────────────────────────────────────────

/// Summary statistics for a collection of logcat entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogcatStats {
    pub total: usize,
    pub verbose: usize,
    pub debug: usize,
    pub info: usize,
    pub warn: usize,
    pub error: usize,
    pub fatal: usize,
    /// Number of unique tags.
    pub tag_count: usize,
    /// Number of unique PIDs.
    pub pid_count: usize,
}

impl LogcatStats {
    /// Compute statistics from a slice of entries.
    #[must_use]
    pub fn from_entries(entries: &[LogcatEntry]) -> Self {
        let mut stats = Self::default();
        let mut tags: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut pids: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for e in entries {
            stats.total += 1;
            match e.priority {
                Priority::Verbose => stats.verbose += 1,
                Priority::Debug => stats.debug += 1,
                Priority::Info => stats.info += 1,
                Priority::Warn => stats.warn += 1,
                Priority::Error => stats.error += 1,
                Priority::Fatal => stats.fatal += 1,
                _ => {}
            }
            tags.insert(&e.tag);
            pids.insert(e.pid);
        }
        stats.tag_count = tags.len();
        stats.pid_count = pids.len();
        stats
    }

    /// Return the most severe entry count (fatal + error).
    #[must_use]
    pub const fn severe_count(&self) -> usize {
        self.fatal + self.error
    }
}

// ─── LogcatReader ─────────────────────────────────────────────────────────────

/// Streaming reader that processes logcat text line by line.
pub struct LogcatReader {
    buffer: String,
    entries: Vec<LogcatEntry>,
    filter: Option<LogcatFilter>,
    format: LogcatFormat,
}

impl LogcatReader {
    #[must_use]
    pub const fn new(format: LogcatFormat) -> Self {
        Self {
            buffer: String::new(),
            entries: Vec::new(),
            filter: None,
            format,
        }
    }

    #[must_use]
    pub fn with_filter(mut self, filter: LogcatFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Feed a chunk of text into the reader.  Parses complete lines.
    pub fn feed(&mut self, data: &str) {
        self.buffer.push_str(data);
        let mut start = 0;
        while let Some(newline) = self.buffer[start..].find('\n') {
            let line = &self.buffer[start..start + newline];
            if let Some(entry) = self.parse_line(line) {
                let keep = self.filter.as_ref().is_none_or(|f| f.matches(&entry));
                if keep {
                    self.entries.push(entry);
                }
            }
            start += newline + 1;
        }
        self.buffer = self.buffer[start..].to_owned();
    }

    /// Drain all accumulated entries.
    pub fn drain(&mut self) -> Vec<LogcatEntry> {
        std::mem::take(&mut self.entries)
    }

    fn parse_line(&self, line: &str) -> Option<LogcatEntry> {
        match self.format {
            LogcatFormat::Threadtime => parse_threadtime_line(line),
            LogcatFormat::Brief => parse_brief_line(line),
            LogcatFormat::Tag => parse_tag_line(line),
            _ => parse_any_line(line),
        }
    }
}

// ─── Utility ─────────────────────────────────────────────────────────────────

/// Format a Unix timestamp + nanosecond offset as `MM-DD HH:MM:SS.mmm`.
#[must_use]
pub fn format_unix_timestamp(secs: u64, nanos: u32) -> String {
    // Minimal formatting without chrono: we compute year/month/day from epoch.
    // For accuracy this uses a very simplified calculation; replace with
    // `chrono` in production.
    let millis = nanos / 1_000_000;
    // This is approximate — not handling leap years / months accurately.
    let s_in_day = secs % 86_400;
    let hh = s_in_day / 3600;
    let mm = (s_in_day % 3600) / 60;
    let ss = s_in_day % 60;
    // Day of year (very rough for demo purposes)
    let days = secs / 86_400;
    let month = ((days % 365) / 30 + 1).min(12);
    let day = (days % 30 + 1).min(31);
    format!("{month:02}-{day:02} {hh:02}:{mm:02}:{ss:02}.{millis:03}")
}

/// Group entries by PID.
#[must_use]
pub fn group_by_pid(entries: &[LogcatEntry]) -> HashMap<u32, Vec<&LogcatEntry>> {
    let mut map: HashMap<u32, Vec<&LogcatEntry>> = HashMap::new();
    for e in entries {
        map.entry(e.pid).or_default().push(e);
    }
    map
}

/// Group entries by tag.
#[must_use]
pub fn group_by_tag(entries: &[LogcatEntry]) -> HashMap<String, Vec<&LogcatEntry>> {
    let mut map: HashMap<String, Vec<&LogcatEntry>> = HashMap::new();
    for e in entries {
        map.entry(e.tag.clone()).or_default().push(e);
    }
    map
}

/// Filter entries at or above `min_priority`.
#[must_use]
pub fn filter_by_priority(entries: &[LogcatEntry], min: Priority) -> Vec<&LogcatEntry> {
    entries.iter().filter(|e| e.priority >= min).collect()
}

/// Filter entries whose tag matches `tag` exactly (case-insensitive).
#[must_use]
pub fn filter_by_tag<'a>(entries: &'a [LogcatEntry], tag: &str) -> Vec<&'a LogcatEntry> {
    let lower = tag.to_lowercase();
    entries
        .iter()
        .filter(|e| e.tag.to_lowercase() == lower)
        .collect()
}

/// Keep only entries from the given PID.
#[must_use]
pub fn filter_by_pid(entries: &[LogcatEntry], pid: u32) -> Vec<&LogcatEntry> {
    entries.iter().filter(|e| e.pid == pid).collect()
}

/// Sort entries by timestamp string (lexicographic, assumes consistent format).
pub fn sort_by_timestamp(entries: &mut [LogcatEntry]) {
    entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Priority ──────────────────────────────────────────────────────────────

    #[test]
    fn test_priority_from_u8_roundtrip() {
        for (n, p) in [
            (2, Priority::Verbose),
            (3, Priority::Debug),
            (4, Priority::Info),
            (5, Priority::Warn),
            (6, Priority::Error),
            (7, Priority::Fatal),
            (8, Priority::Silent),
        ] {
            assert_eq!(Priority::from_u8(n), p);
        }
    }

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Fatal > Priority::Error);
        assert!(Priority::Error > Priority::Warn);
        assert!(Priority::Warn > Priority::Info);
        assert!(Priority::Info > Priority::Debug);
        assert!(Priority::Debug > Priority::Verbose);
    }

    #[test]
    fn test_priority_as_char() {
        assert_eq!(Priority::Info.as_char(), 'I');
        assert_eq!(Priority::Error.as_char(), 'E');
        assert_eq!(Priority::Verbose.as_char(), 'V');
    }

    #[test]
    fn test_priority_to_log_level() {
        assert_eq!(Priority::Error.to_log_level(), LogLevel::Error);
        assert_eq!(Priority::Warn.to_log_level(), LogLevel::Warning);
    }

    // ── parse_threadtime_line ─────────────────────────────────────────────────

    #[test]
    fn test_parse_threadtime_basic() {
        let line = "01-15 12:00:00.123  1234  5678 I MyTag: hello world";
        let entry = parse_threadtime_line(line).unwrap();
        assert_eq!(entry.pid, 1234);
        assert_eq!(entry.tid, 5678);
        assert_eq!(entry.priority, Priority::Info);
        assert_eq!(entry.tag, "MyTag");
        assert_eq!(entry.message, "hello world");
        assert!(entry.timestamp.contains("01-15"));
    }

    #[test]
    fn test_parse_threadtime_error_level() {
        let line = "06-01 08:30:00.000   999   888 E AndroidRuntime: FATAL EXCEPTION: main";
        let entry = parse_threadtime_line(line).unwrap();
        assert_eq!(entry.priority, Priority::Error);
        assert_eq!(entry.tag, "AndroidRuntime");
        assert!(entry.message.contains("FATAL"));
    }

    #[test]
    fn test_parse_threadtime_rejects_unknown_priority() {
        // The logcat priority alphabet is closed (V D I W E F S). An unknown
        // character must be rejected, exactly as `parse_brief_line` and
        // `parse_tag_line` do — mapping it to `Info` would surface a corrupt
        // line as a genuine informational message to anyone filtering by level.
        for bad in ['X', 'Q', '0', 'i', 'e'] {
            let line = format!("01-15 12:00:00.123  1234  5678 {bad} MyTag: hello");
            assert!(
                parse_threadtime_line(&line).is_none(),
                "priority '{bad}' is not a logcat level and must be rejected"
            );
        }
        // Every real level still parses, including 'I' — which used to reach
        // `Info` only through the catch-all.
        for (ch, expected) in [
            ('V', Priority::Verbose),
            ('D', Priority::Debug),
            ('I', Priority::Info),
            ('W', Priority::Warn),
            ('E', Priority::Error),
            ('F', Priority::Fatal),
            ('S', Priority::Silent),
        ] {
            let line = format!("01-15 12:00:00.123  1234  5678 {ch} MyTag: hello");
            let entry = parse_threadtime_line(&line)
                .unwrap_or_else(|| panic!("level '{ch}' must parse"));
            assert_eq!(entry.priority, expected);
        }
    }

    #[test]
    fn test_parse_threadtime_separator_line() {
        assert!(parse_threadtime_line("--------- beginning of /dev/log/main").is_none());
    }

    #[test]
    fn test_parse_threadtime_empty_line() {
        assert!(parse_threadtime_line("").is_none());
    }

    // ── parse_brief_line ──────────────────────────────────────────────────────

    #[test]
    fn test_parse_brief_info() {
        let line = "I/ActivityManager(  432): Starting activity";
        let entry = parse_brief_line(line).unwrap();
        assert_eq!(entry.pid, 432);
        assert_eq!(entry.priority, Priority::Info);
        assert_eq!(entry.tag, "ActivityManager");
        assert!(entry.message.contains("Starting"));
    }

    #[test]
    fn test_parse_brief_error() {
        let line = "E/System(1000): NullPointerException";
        let entry = parse_brief_line(line).unwrap();
        assert_eq!(entry.priority, Priority::Error);
        assert_eq!(entry.tag, "System");
    }

    #[test]
    fn test_parse_brief_warning() {
        let line = "W/GC(555): Long pause detected";
        let entry = parse_brief_line(line).unwrap();
        assert_eq!(entry.priority, Priority::Warn);
    }

    // ── parse_tag_line ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_tag_line_ok() {
        let line = "D/MyTag: debug message here";
        let entry = parse_tag_line(line).unwrap();
        assert_eq!(entry.priority, Priority::Debug);
        assert_eq!(entry.tag, "MyTag");
        assert_eq!(entry.message, "debug message here");
    }

    // ── parse_any_line ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_any_prefers_threadtime() {
        let line = "01-15 10:00:00.000  100  200 W Tag: msg";
        let entry = parse_any_line(line).unwrap();
        assert_eq!(entry.pid, 100);
    }

    #[test]
    fn test_parse_any_falls_back_to_brief() {
        let line = "W/SomeTag(9999): warning msg";
        let entry = parse_any_line(line).unwrap();
        assert_eq!(entry.priority, Priority::Warn);
    }

    // ── LogcatFilter ──────────────────────────────────────────────────────────

    fn make_entry(priority: Priority, tag: &str, pid: u32, msg: &str) -> LogcatEntry {
        LogcatEntry {
            timestamp: "01-01 00:00:00.000".into(),
            pid,
            tid: 0,
            priority,
            tag: tag.into(),
            message: msg.into(),
            buffer: LogBuffer::Main,
        }
    }

    #[test]
    fn test_filter_min_priority_passes() {
        let f = LogcatFilter::new().min_priority(Priority::Warn);
        let e = make_entry(Priority::Error, "T", 1, "msg");
        assert!(f.matches(&e));
    }

    #[test]
    fn test_filter_min_priority_fails() {
        let f = LogcatFilter::new().min_priority(Priority::Warn);
        let e = make_entry(Priority::Debug, "T", 1, "msg");
        assert!(!f.matches(&e));
    }

    #[test]
    fn test_filter_tag_include() {
        let f = LogcatFilter::new().tags(["ActivityManager"]);
        let e1 = make_entry(Priority::Info, "ActivityManager", 1, "");
        let e2 = make_entry(Priority::Info, "BatteryService", 1, "");
        assert!(f.matches(&e1));
        assert!(!f.matches(&e2));
    }

    #[test]
    fn test_filter_tag_exclude() {
        let f = LogcatFilter::new().exclude_tags(["Spam"]);
        let e_ok = make_entry(Priority::Info, "GoodTag", 1, "");
        let e_spam = make_entry(Priority::Info, "Spam", 1, "");
        assert!(f.matches(&e_ok));
        assert!(!f.matches(&e_spam));
    }

    #[test]
    fn test_filter_pid() {
        let f = LogcatFilter::new().pids(vec![1234]);
        let e1 = make_entry(Priority::Info, "T", 1234, "");
        let e2 = make_entry(Priority::Info, "T", 9999, "");
        assert!(f.matches(&e1));
        assert!(!f.matches(&e2));
    }

    #[test]
    fn test_filter_message_contains() {
        let f = LogcatFilter::new().message_contains("crash");
        let e_match = make_entry(Priority::Fatal, "T", 1, "app CRASH occurred");
        let e_no = make_entry(Priority::Info, "T", 1, "all good");
        assert!(f.matches(&e_match));
        assert!(!f.matches(&e_no));
    }

    #[test]
    fn test_filter_empty_accepts_all() {
        let f = LogcatFilter::new();
        let e = make_entry(Priority::Verbose, "T", 999, "any message");
        assert!(f.matches(&e));
    }

    #[test]
    fn test_filter_to_logcat_args_no_tags() {
        let f = LogcatFilter::new().min_priority(Priority::Info);
        let args = f.to_logcat_args();
        assert!(args.is_empty()); // no tags means no args
    }

    #[test]
    fn test_filter_to_logcat_args_with_tags() {
        let f = LogcatFilter::new()
            .min_priority(Priority::Warn)
            .tags(["ActivityManager"]);
        let args = f.to_logcat_args();
        assert!(args.iter().any(|a| a.contains("ActivityManager:W")));
        assert!(args.iter().any(|a| a == "*:S"));
    }

    // ── LogcatStats ───────────────────────────────────────────────────────────

    #[test]
    fn test_logcat_stats_basic() {
        let entries = vec![
            make_entry(Priority::Info, "T", 1, ""),
            make_entry(Priority::Error, "T", 2, ""),
            make_entry(Priority::Fatal, "X", 1, ""),
        ];
        let stats = LogcatStats::from_entries(&entries);
        assert_eq!(stats.total, 3);
        assert_eq!(stats.info, 1);
        assert_eq!(stats.error, 1);
        assert_eq!(stats.fatal, 1);
        assert_eq!(stats.severe_count(), 2);
        assert_eq!(stats.tag_count, 2);
        assert_eq!(stats.pid_count, 2);
    }

    #[test]
    fn test_logcat_stats_empty() {
        let stats = LogcatStats::from_entries(&[]);
        assert_eq!(stats.total, 0);
        assert_eq!(stats.severe_count(), 0);
    }

    // ── group_by_pid / group_by_tag ───────────────────────────────────────────

    #[test]
    fn test_group_by_pid() {
        let entries = vec![
            make_entry(Priority::Info, "T", 1, ""),
            make_entry(Priority::Info, "T", 2, ""),
            make_entry(Priority::Info, "T", 1, ""),
        ];
        let groups = group_by_pid(&entries);
        assert_eq!(groups[&1].len(), 2);
        assert_eq!(groups[&2].len(), 1);
    }

    #[test]
    fn test_group_by_tag() {
        let entries = vec![
            make_entry(Priority::Info, "A", 1, ""),
            make_entry(Priority::Info, "B", 2, ""),
            make_entry(Priority::Info, "A", 3, ""),
        ];
        let groups = group_by_tag(&entries);
        assert_eq!(groups["A"].len(), 2);
        assert_eq!(groups["B"].len(), 1);
    }

    // ── filter_by_priority ────────────────────────────────────────────────────

    #[test]
    fn test_filter_by_priority_fn() {
        let entries = vec![
            make_entry(Priority::Debug, "T", 1, ""),
            make_entry(Priority::Error, "T", 2, ""),
        ];
        let filtered = filter_by_priority(&entries, Priority::Warn);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].priority, Priority::Error);
    }

    // ── LogcatReader streaming ────────────────────────────────────────────────

    #[test]
    fn test_logcat_reader_feed_and_drain() {
        let mut reader = LogcatReader::new(LogcatFormat::Brief);
        reader.feed("I/Tag(100): msg1\n");
        reader.feed("E/Err(200): msg2\n");
        let entries = reader.drain();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].priority, Priority::Info);
        assert_eq!(entries[1].priority, Priority::Error);
    }

    #[test]
    fn test_logcat_reader_partial_line() {
        let mut reader = LogcatReader::new(LogcatFormat::Brief);
        reader.feed("I/Tag(1): par");
        reader.feed("tial message\n");
        let entries = reader.drain();
        // The line was assembled across two feeds
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_logcat_reader_with_filter() {
        let filter = LogcatFilter::new().min_priority(Priority::Error);
        let mut reader = LogcatReader::new(LogcatFormat::Brief).with_filter(filter);
        reader.feed("I/Tag(1): info msg\n");
        reader.feed("E/Tag(2): error msg\n");
        let entries = reader.drain();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].priority, Priority::Error);
    }

    // ── BinaryLogEntry ────────────────────────────────────────────────────────

    #[test]
    fn test_binary_log_entry_parse_payload() {
        // priority=4(Info) + "MyTag\0" + "hello\0"
        let mut payload = vec![4u8];
        payload.extend_from_slice(b"MyTag\0hello\0");
        let (pri, tag, msg) = BinaryLogEntry::parse_payload(&payload).unwrap();
        assert_eq!(pri, Priority::Info);
        assert_eq!(tag, "MyTag");
        assert_eq!(msg, "hello");
    }

    #[test]
    fn test_binary_log_entry_parse_empty_payload() {
        assert!(BinaryLogEntry::parse_payload(&[]).is_none());
    }

    fn make_binary_record(
        pid: i32,
        tid: i32,
        sec: i32,
        nsec: i32,
        priority: u8,
        tag: &str,
        msg: &str,
    ) -> Vec<u8> {
        let mut payload = vec![priority];
        payload.extend_from_slice(tag.as_bytes());
        payload.push(0);
        payload.extend_from_slice(msg.as_bytes());
        payload.push(0);

        let mut buf = Vec::new();
        buf.extend_from_slice(
            &u16::try_from(payload.len())
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        ); // len
        buf.extend_from_slice(&20u16.to_le_bytes()); // hdr_size
        buf.extend_from_slice(&pid.to_le_bytes());
        buf.extend_from_slice(&tid.to_le_bytes());
        buf.extend_from_slice(&sec.to_le_bytes());
        buf.extend_from_slice(&nsec.to_le_bytes());
        buf.extend_from_slice(&payload);
        buf
    }

    #[test]
    fn test_binary_log_entry_full_parse() {
        let rec = make_binary_record(1234, 5678, 1000, 500_000_000, 4, "TestTag", "test message");
        let (entry, consumed) = BinaryLogEntry::parse(&rec).unwrap();
        assert_eq!(entry.pid, 1234);
        assert_eq!(entry.tid, 5678);
        assert_eq!(entry.priority, Priority::Info);
        assert_eq!(entry.tag, "TestTag");
        assert_eq!(entry.message, "test message");
        assert_eq!(consumed, rec.len());
    }

    #[test]
    fn test_parse_binary_log_multiple() {
        let r1 = make_binary_record(1, 1, 0, 0, 4, "A", "msg1");
        let r2 = make_binary_record(2, 2, 1, 0, 6, "B", "msg2");
        let mut data = r1;
        data.extend(r2);
        let entries = parse_binary_log(&data);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].tag, "A");
        assert_eq!(entries[1].tag, "B");
        assert_eq!(entries[1].priority, Priority::Error);
    }

    // ── format helpers ────────────────────────────────────────────────────────

    #[test]
    fn test_format_unix_timestamp_zero() {
        let s = format_unix_timestamp(0, 0);
        assert!(s.contains("00:00:00.000"));
    }

    #[test]
    fn test_logcat_entry_format_threadtime() {
        let e = make_entry(Priority::Info, "MyTag", 100, "hello");
        let s = e.format_threadtime();
        assert!(s.contains("MyTag"));
        assert!(s.contains("hello"));
    }

    #[test]
    fn test_logcat_entry_format_brief() {
        let e = make_entry(Priority::Warn, "WarnTag", 200, "warning!");
        let s = e.format_brief();
        assert!(s.starts_with("W/"));
        assert!(s.contains("WarnTag"));
    }

    #[test]
    fn test_logcat_format_as_str() {
        assert_eq!(LogcatFormat::Threadtime.as_str(), "threadtime");
        assert_eq!(LogcatFormat::Brief.as_str(), "brief");
    }

    #[test]
    fn test_log_buffer_roundtrip() {
        for (s, b) in [("main", LogBuffer::Main), ("crash", LogBuffer::Crash)] {
            assert_eq!(LogBuffer::from_name(s), b);
            assert_eq!(b.as_str(), s);
        }
    }

    #[test]
    fn test_sort_by_timestamp() {
        let mut entries = vec![
            make_entry(Priority::Info, "T", 1, ""),
            make_entry(Priority::Info, "T", 2, ""),
        ];
        // Manually set timestamps out of order
        entries[0].timestamp = "01-02 00:00:00.000".into();
        entries[1].timestamp = "01-01 00:00:00.000".into();
        sort_by_timestamp(&mut entries);
        assert_eq!(entries[0].timestamp, "01-01 00:00:00.000");
    }
}
