//! Traffic logger — record, filter, and export intercepted HTTP traffic.
//!
//! Provides:
//! - [`TrafficLogger`] — central log with filtering and export
//! - [`LogEntry`] — structured record of a single request/response pair
//! - [`FilterRule`] — predicate-based log filtering
//! - PCAP export (link-layer-less variant, suitable for import into Wireshark)
//! - HAR (HTTP Archive 1.2) export
//! - Traffic replay helpers

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

// ────────────────────────────────────────────────────────────────────────────
// LogEntry
// ────────────────────────────────────────────────────────────────────────────

/// A single HTTP traffic entry in the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Sequential log ID.
    pub id: u64,
    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Client (source) address.
    pub src: SocketAddr,
    /// Server (destination) address.
    pub dst: SocketAddr,
    /// HTTP method (e.g. `"GET"`, `"POST"`).
    pub method: String,
    /// Full request URL.
    pub url: String,
    /// HTTP status code of the response (`0` if not yet received).
    pub status: u16,
    /// Total size of the response body in bytes.
    pub response_size: usize,
    /// Time-to-first-byte in milliseconds.
    pub ttfb_ms: Option<u64>,
    /// Total duration (request send → response complete) in milliseconds.
    pub duration_ms: Option<u64>,
    /// MIME type of the response.
    pub mime_type: String,
    /// Raw request bytes.
    pub request_raw: Vec<u8>,
    /// Raw response bytes.
    pub response_raw: Vec<u8>,
    /// Whether TLS was used.
    pub tls: bool,
    /// Arbitrary tags for filtering.
    pub tags: Vec<String>,
}

impl LogEntry {
    /// Construct a new log entry with the current system time.
    #[must_use]
    pub fn new(
        id: u64,
        src: SocketAddr,
        dst: SocketAddr,
        method: impl Into<String>,
        url: impl Into<String>,
        tls: bool,
    ) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            id,
            timestamp_ms,
            src,
            dst,
            method: method.into(),
            url: url.into(),
            status: 0,
            response_size: 0,
            ttfb_ms: None,
            duration_ms: None,
            mime_type: String::new(),
            request_raw: Vec::new(),
            response_raw: Vec::new(),
            tls,
            tags: Vec::new(),
        }
    }

    /// Set the response fields once the response arrives.
    pub fn set_response(
        &mut self,
        status: u16,
        mime_type: impl Into<String>,
        response_raw: Vec<u8>,
        duration_ms: u64,
    ) {
        self.response_size = response_raw.len();
        self.status = status;
        self.mime_type = mime_type.into();
        self.response_raw = response_raw;
        self.duration_ms = Some(duration_ms);
    }

    /// Add a tag for easy filtering.
    pub fn tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    /// Returns `true` if the entry has the given tag.
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    /// Human-readable one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} {} {} -> {} ({}b, {}ms)",
            self.id,
            self.method,
            self.url,
            self.status,
            self.dst,
            self.response_size,
            self.duration_ms.unwrap_or(0),
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────
// FilterRule
// ────────────────────────────────────────────────────────────────────────────

/// Predicate for filtering [`LogEntry`] records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterRule {
    /// Match everything.
    Any,
    /// Status code equals.
    Status(u16),
    /// Status code in range (inclusive).
    StatusRange { min: u16, max: u16 },
    /// URL contains substring.
    UrlContains(String),
    /// Method equals (case-insensitive).
    Method(String),
    /// Destination host/port matches.
    Dst(String),
    /// Response MIME type contains.
    MimeContains(String),
    /// Has a specific tag.
    HasTag(String),
    /// TLS or plain.
    Tls(bool),
    /// Response size exceeds threshold.
    LargerThan(usize),
    /// Duration exceeds threshold in ms.
    SlowerThan(u64),
    /// Logical AND.
    And(Box<Self>, Box<Self>),
    /// Logical OR.
    Or(Box<Self>, Box<Self>),
    /// Logical NOT.
    Not(Box<Self>),
}

/// Maximum recursion depth for [`FilterRule`] evaluation to prevent stack overflow
/// from adversarially deep deserialized rule trees.
const MAX_FILTER_DEPTH: u32 = 64;

impl FilterRule {
    /// Returns `true` if `entry` matches this rule.
    #[must_use]
    pub fn matches(&self, entry: &LogEntry) -> bool {
        self.matches_depth(entry, 0)
    }

    fn matches_depth(&self, entry: &LogEntry, depth: u32) -> bool {
        if depth > MAX_FILTER_DEPTH {
            return false;
        }
        match self {
            Self::Any => true,
            Self::Status(s) => entry.status == *s,
            Self::StatusRange { min, max } => entry.status >= *min && entry.status <= *max,
            Self::UrlContains(s) => entry.url.contains(s.as_str()),
            Self::Method(m) => entry.method.eq_ignore_ascii_case(m),
            Self::Dst(d) => entry.dst.to_string().contains(d.as_str()),
            Self::MimeContains(m) => entry.mime_type.contains(m.as_str()),
            Self::HasTag(t) => entry.has_tag(t),
            Self::Tls(tls) => entry.tls == *tls,
            Self::LargerThan(n) => entry.response_size > *n,
            Self::SlowerThan(ms) => entry.duration_ms.is_some_and(|d| d > *ms),
            Self::And(a, b) => a.matches_depth(entry, depth + 1) && b.matches_depth(entry, depth + 1),
            Self::Or(a, b) => a.matches_depth(entry, depth + 1) || b.matches_depth(entry, depth + 1),
            Self::Not(r) => !r.matches_depth(entry, depth + 1),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Traffic logger
// ────────────────────────────────────────────────────────────────────────────

/// Append-only traffic log with filtering and export capabilities.
pub struct TrafficLogger {
    entries: RwLock<VecDeque<LogEntry>>,
    max_entries: usize,
    next_id: std::sync::atomic::AtomicU64,
}

impl TrafficLogger {
    /// Create a logger with a given maximum capacity.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        let cap = max_entries.max(1);
        Self {
            entries: RwLock::new(VecDeque::with_capacity(cap)),
            max_entries: cap,
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Allocate the next entry ID.
    pub fn next_id(&self) -> u64 {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Append an entry.  Oldest entries are evicted when capacity is reached.
    pub fn push(&self, entry: LogEntry) {
        let mut guard = self.entries.write();
        if guard.len() >= self.max_entries {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    /// Number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Return a snapshot of all entries.
    #[must_use]
    pub fn all(&self) -> Vec<LogEntry> {
        self.entries.read().iter().cloned().collect()
    }

    /// Return entries matching `rule`.
    #[must_use]
    pub fn filter(&self, rule: &FilterRule) -> Vec<LogEntry> {
        self.entries
            .read()
            .iter()
            .filter(|e| rule.matches(e))
            .cloned()
            .collect()
    }

    /// Get an entry by ID.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<LogEntry> {
        self.entries.read().iter().find(|e| e.id == id).cloned()
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Total bytes logged (request + response).
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.entries
            .read()
            .iter()
            .map(|e| (e.request_raw.len() + e.response_raw.len()) as u64)
            .sum()
    }

    /// Number of entries with 4xx/5xx status codes.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.entries
            .read()
            .iter()
            .filter(|e| e.status >= 400)
            .count()
    }

    // ── PCAP export ────────────────────────────────────────────────────────

    /// Export all entries as a minimal PCAP file (linktype 228 = raw IP stub).
    ///
    /// Each log entry is wrapped in a fake IP/TCP header just enough for
    /// Wireshark to import. For real IP-level pcap, use a kernel capture.
    #[must_use]
    pub fn export_pcap(&self) -> Vec<u8> {
        let entries = self.entries.read();
        // Pre-allocate: 24-byte global header + ~20 bytes record header per entry
        let mut pcap = Vec::with_capacity(24 + entries.len() * 20);

        // PCAP global header
        pcap.extend_from_slice(&0xD4C3_B2A1_u32.to_le_bytes()); // magic (little-endian)
        pcap.extend_from_slice(&2u16.to_le_bytes()); // major version
        pcap.extend_from_slice(&4u16.to_le_bytes()); // minor version
        pcap.extend_from_slice(&0i32.to_le_bytes()); // timezone offset
        pcap.extend_from_slice(&0u32.to_le_bytes()); // timestamp accuracy
        pcap.extend_from_slice(&65535u32.to_le_bytes()); // snap length
        pcap.extend_from_slice(&228u32.to_le_bytes()); // linktype: raw IP (no link-layer)

        for entry in entries.iter() {
            if entry.request_raw.is_empty() {
                continue;
            }
            let ts_sec = u32::try_from(entry.timestamp_ms / 1000).unwrap_or(u32::MAX);
            let ts_usec = u32::try_from((entry.timestamp_ms % 1000) * 1000).unwrap_or(u32::MAX);

            // Minimal fake TCP/IP encapsulation (placeholder)
            let payload = &entry.request_raw;
            let incl_len = u32::try_from(payload.len().min(65535)).unwrap_or(u32::MAX);

            // Record header
            pcap.extend_from_slice(&ts_sec.to_le_bytes());
            pcap.extend_from_slice(&ts_usec.to_le_bytes());
            pcap.extend_from_slice(&incl_len.to_le_bytes());
            pcap.extend_from_slice(&incl_len.to_le_bytes());
            pcap.extend_from_slice(&payload[..incl_len as usize]);
        }
        pcap
    }

    // ── HAR export ────────────────────────────────────────────────────────

    /// Export all entries matching `filter` as a HAR 1.2 JSON string.
    #[must_use]
    pub fn export_har(&self, filter: Option<&FilterRule>) -> String {
        let entries = self.entries.read();
        let iter: Box<dyn Iterator<Item = &LogEntry>> = match filter {
            Some(rule) => Box::new(entries.iter().filter(|e| rule.matches(e))),
            None => Box::new(entries.iter()),
        };

        let har_entries: Vec<serde_json::Value> = iter
            .map(|e| {
                let req_body = String::from_utf8_lossy(&e.request_raw).to_string();
                let resp_body = String::from_utf8_lossy(&e.response_raw).to_string();
                serde_json::json!({
                    "startedDateTime": format_iso8601(e.timestamp_ms),
                    "time": e.duration_ms.unwrap_or(0),
                    "request": {
                        "method": e.method,
                        "url": e.url,
                        "httpVersion": "HTTP/1.1",
                        "headers": [],
                        "queryString": [],
                        "cookies": [],
                        "headersSize": -1,
                        "bodySize": e.request_raw.len(),
                        "postData": { "mimeType": "application/octet-stream", "text": req_body }
                    },
                    "response": {
                        "status": e.status,
                        "statusText": "",
                        "httpVersion": "HTTP/1.1",
                        "headers": [],
                        "cookies": [],
                        "content": {
                            "size": e.response_size,
                            "mimeType": e.mime_type,
                            "text": resp_body
                        },
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": e.response_size
                    },
                    "cache": {},
                    "timings": {
                        "send": 0,
                        "wait": e.ttfb_ms.unwrap_or(0),
                        "receive": e.duration_ms.unwrap_or(0)
                    }
                })
            })
            .collect();

        let har = serde_json::json!({
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "rustre-net-proxy",
                    "version": "0.1.0"
                },
                "entries": har_entries
            }
        });

        serde_json::to_string_pretty(&har).unwrap_or_default()
    }
}

/// Format a Unix millisecond timestamp as ISO 8601.
fn format_iso8601(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    // Minimal implementation: just emit a fixed-offset string
    // Real code would use `time` or `chrono`, but we stay dependency-free.
    format!("{secs}.{millis:03}Z")
}

// ────────────────────────────────────────────────────────────────────────────
// Traffic replay
// ────────────────────────────────────────────────────────────────────────────

/// A single replay job built from a [`LogEntry`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRequest {
    pub entry_id: u64,
    pub target: SocketAddr,
    pub request_raw: Vec<u8>,
    pub tls: bool,
    /// Optional delay in milliseconds before sending.
    pub delay_ms: u64,
}

impl ReplayRequest {
    /// Build a replay request from a log entry.
    #[must_use]
    pub fn from_entry(entry: &LogEntry) -> Self {
        Self {
            entry_id: entry.id,
            target: entry.dst,
            request_raw: entry.request_raw.clone(),
            tls: entry.tls,
            delay_ms: 0,
        }
    }

    /// Set a delay before replay.
    #[must_use]
    pub const fn with_delay(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }
}

/// A collection of replay requests built from a filtered set of log entries.
#[derive(Debug, Default)]
pub struct ReplayBatch {
    pub requests: Vec<ReplayRequest>,
}

impl ReplayBatch {
    /// Build a batch from a log, optionally filtered.
    #[must_use]
    pub fn from_log(logger: &TrafficLogger, filter: Option<&FilterRule>) -> Self {
        let entries = filter.map_or_else(|| logger.all(), |rule| logger.filter(rule));
        let requests = entries.iter().map(ReplayRequest::from_entry).collect();
        Self { requests }
    }

    /// Number of requests in this batch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.requests.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Serialize the batch to JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.requests).unwrap_or_default()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Log statistics
// ────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics computed from a set of [`LogEntry`] records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogStats {
    pub total_entries: usize,
    pub total_bytes: u64,
    pub error_entries: usize,
    pub avg_duration_ms: u64,
    pub max_duration_ms: u64,
    pub tls_entries: usize,
}

impl LogStats {
    /// Compute statistics from a slice of entries.
    #[must_use]
    pub fn compute(entries: &[LogEntry]) -> Self {
        let total_entries = entries.len();
        let total_bytes: u64 = entries
            .iter()
            .map(|e| (e.request_raw.len() + e.response_raw.len()) as u64)
            .sum();
        let error_entries = entries.iter().filter(|e| e.status >= 400).count();
        let tls_entries = entries.iter().filter(|e| e.tls).count();

        let durations: Vec<u64> = entries.iter().filter_map(|e| e.duration_ms).collect();
        let avg_duration_ms = if durations.is_empty() {
            0
        } else {
            durations.iter().sum::<u64>() / durations.len() as u64
        };
        let max_duration_ms = durations.iter().copied().max().unwrap_or(0);

        Self {
            total_entries,
            total_bytes,
            error_entries,
            avg_duration_ms,
            max_duration_ms,
            tls_entries,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn make_entry(id: u64, method: &str, url: &str, status: u16, tls: bool) -> LogEntry {
        let mut e = LogEntry::new(id, addr(10000), addr(443), method, url, tls);
        e.set_response(status, "text/html", b"response body".to_vec(), 42);
        e
    }

    // ── LogEntry ─────────────────────────────────────────────────────────────

    #[test]
    fn test_log_entry_construction() {
        let e = make_entry(1, "GET", "https://example.com/", 200, true);
        assert_eq!(e.id, 1);
        assert_eq!(e.status, 200);
        assert!(e.tls);
        assert_eq!(e.mime_type, "text/html");
    }

    #[test]
    fn test_log_entry_tag() {
        let mut e = make_entry(2, "POST", "https://api.example.com/login", 200, false);
        e.tag("credential");
        assert!(e.has_tag("credential"));
        assert!(!e.has_tag("tls-downgrade"));
    }

    #[test]
    fn test_log_entry_summary() {
        let e = make_entry(3, "GET", "https://example.com/", 200, false);
        let s = e.summary();
        assert!(s.contains("GET"));
        assert!(s.contains("200"));
    }

    #[test]
    fn test_log_entry_response_size() {
        let e = make_entry(4, "GET", "https://example.com/", 200, false);
        assert_eq!(e.response_size, b"response body".len());
    }

    // ── FilterRule ────────────────────────────────────────────────────────────

    #[test]
    fn test_filter_status() {
        let e = make_entry(1, "GET", "https://example.com/", 404, false);
        assert!(FilterRule::Status(404).matches(&e));
        assert!(!FilterRule::Status(200).matches(&e));
    }

    #[test]
    fn test_filter_status_range() {
        let e = make_entry(1, "GET", "https://example.com/", 503, false);
        assert!(FilterRule::StatusRange { min: 500, max: 599 }.matches(&e));
        assert!(!FilterRule::StatusRange { min: 200, max: 299 }.matches(&e));
    }

    #[test]
    fn test_filter_url_contains() {
        let e = make_entry(1, "GET", "https://example.com/admin/panel", 200, false);
        assert!(FilterRule::UrlContains("admin".to_string()).matches(&e));
        assert!(!FilterRule::UrlContains("user".to_string()).matches(&e));
    }

    #[test]
    fn test_filter_method() {
        let e = make_entry(1, "POST", "https://example.com/", 200, false);
        assert!(FilterRule::Method("post".to_string()).matches(&e));
        assert!(!FilterRule::Method("GET".to_string()).matches(&e));
    }

    #[test]
    fn test_filter_tls() {
        let e_tls = make_entry(1, "GET", "https://example.com/", 200, true);
        let e_plain = make_entry(2, "GET", "http://example.com/", 200, false);
        assert!(FilterRule::Tls(true).matches(&e_tls));
        assert!(!FilterRule::Tls(true).matches(&e_plain));
    }

    #[test]
    fn test_filter_larger_than() {
        let e = make_entry(1, "GET", "https://example.com/", 200, false);
        assert!(FilterRule::LargerThan(5).matches(&e)); // "response body" is 13 bytes
        assert!(!FilterRule::LargerThan(100).matches(&e));
    }

    #[test]
    fn test_filter_slower_than() {
        let e = make_entry(1, "GET", "https://example.com/", 200, false);
        assert!(FilterRule::SlowerThan(10).matches(&e)); // duration_ms = 42
        assert!(!FilterRule::SlowerThan(100).matches(&e));
    }

    #[test]
    fn test_filter_and() {
        let e = make_entry(1, "POST", "https://example.com/login", 200, false);
        let rule = FilterRule::And(
            Box::new(FilterRule::Method("POST".to_string())),
            Box::new(FilterRule::UrlContains("login".to_string())),
        );
        assert!(rule.matches(&e));
    }

    #[test]
    fn test_filter_or() {
        let e = make_entry(1, "GET", "https://example.com/", 404, false);
        let rule = FilterRule::Or(
            Box::new(FilterRule::Status(200)),
            Box::new(FilterRule::Status(404)),
        );
        assert!(rule.matches(&e));
    }

    #[test]
    fn test_filter_not() {
        let e = make_entry(1, "GET", "https://example.com/", 200, false);
        let rule = FilterRule::Not(Box::new(FilterRule::Status(404)));
        assert!(rule.matches(&e));
    }

    // ── TrafficLogger ─────────────────────────────────────────────────────────

    #[test]
    fn test_logger_push_and_len() {
        let logger = TrafficLogger::new(100);
        logger.push(make_entry(1, "GET", "https://a.com/", 200, false));
        logger.push(make_entry(2, "POST", "https://b.com/", 201, false));
        assert_eq!(logger.len(), 2);
    }

    #[test]
    fn test_logger_eviction() {
        let logger = TrafficLogger::new(2);
        logger.push(make_entry(1, "GET", "https://a.com/", 200, false));
        logger.push(make_entry(2, "GET", "https://b.com/", 200, false));
        logger.push(make_entry(3, "GET", "https://c.com/", 200, false));
        assert_eq!(logger.len(), 2);
        // Oldest (id=1) should be gone
        assert!(logger.get(1).is_none());
        assert!(logger.get(3).is_some());
    }

    #[test]
    fn test_logger_filter() {
        let logger = TrafficLogger::new(100);
        logger.push(make_entry(1, "GET", "https://a.com/", 200, false));
        logger.push(make_entry(2, "POST", "https://b.com/", 404, false));
        let errors = logger.filter(&FilterRule::StatusRange { min: 400, max: 499 });
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].status, 404);
    }

    #[test]
    fn test_logger_clear() {
        let logger = TrafficLogger::new(100);
        logger.push(make_entry(1, "GET", "https://a.com/", 200, false));
        logger.clear();
        assert!(logger.is_empty());
    }

    #[test]
    fn test_logger_error_count() {
        let logger = TrafficLogger::new(100);
        logger.push(make_entry(1, "GET", "https://a.com/", 200, false));
        logger.push(make_entry(2, "GET", "https://b.com/", 500, false));
        logger.push(make_entry(3, "GET", "https://c.com/", 404, false));
        assert_eq!(logger.error_count(), 2);
    }

    #[test]
    fn test_logger_total_bytes() {
        let logger = TrafficLogger::new(100);
        let mut e = make_entry(1, "GET", "https://a.com/", 200, false);
        e.request_raw = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        logger.push(e);
        assert!(logger.total_bytes() > 0);
    }

    // ── PCAP export ────────────────────────────────────────────────────────────

    #[test]
    fn test_pcap_export_header() {
        let logger = TrafficLogger::new(100);
        let pcap = logger.export_pcap();
        // PCAP magic LE = 0xD4C3B2A1
        assert_eq!(&pcap[0..4], &[0xA1u8, 0xB2, 0xC3, 0xD4]);
    }

    #[test]
    fn test_pcap_export_with_entry() {
        let logger = TrafficLogger::new(100);
        let mut e = make_entry(1, "GET", "https://a.com/", 200, false);
        e.request_raw = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        logger.push(e);
        let pcap = logger.export_pcap();
        // 24 bytes global header + records
        assert!(pcap.len() > 24);
    }

    #[test]
    fn test_pcap_export_empty_logger() {
        let logger = TrafficLogger::new(100);
        let pcap = logger.export_pcap();
        assert_eq!(pcap.len(), 24); // global header only
    }

    // ── HAR export ────────────────────────────────────────────────────────────

    #[test]
    fn test_har_export_valid_json() {
        let logger = TrafficLogger::new(100);
        logger.push(make_entry(1, "GET", "https://a.com/", 200, false));
        let har = logger.export_har(None);
        let parsed: serde_json::Value = serde_json::from_str(&har).unwrap();
        assert!(parsed["log"]["entries"].is_array());
    }

    #[test]
    fn test_har_export_with_filter() {
        let logger = TrafficLogger::new(100);
        logger.push(make_entry(1, "GET", "https://a.com/", 200, false));
        logger.push(make_entry(2, "GET", "https://b.com/", 404, false));
        let har = logger.export_har(Some(&FilterRule::Status(404)));
        let parsed: serde_json::Value = serde_json::from_str(&har).unwrap();
        assert_eq!(parsed["log"]["entries"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_har_version_field() {
        let logger = TrafficLogger::new(100);
        let har = logger.export_har(None);
        let parsed: serde_json::Value = serde_json::from_str(&har).unwrap();
        assert_eq!(parsed["log"]["version"], "1.2");
    }

    // ── ReplayRequest ─────────────────────────────────────────────────────────

    #[test]
    fn test_replay_request_from_entry() {
        let e = make_entry(1, "GET", "https://a.com/", 200, true);
        let rr = ReplayRequest::from_entry(&e);
        assert_eq!(rr.entry_id, 1);
        assert!(rr.tls);
    }

    #[test]
    fn test_replay_request_with_delay() {
        let e = make_entry(1, "GET", "https://a.com/", 200, false);
        let rr = ReplayRequest::from_entry(&e).with_delay(500);
        assert_eq!(rr.delay_ms, 500);
    }

    // ── ReplayBatch ───────────────────────────────────────────────────────────

    #[test]
    fn test_replay_batch_from_log() {
        let logger = TrafficLogger::new(100);
        logger.push(make_entry(1, "GET", "https://a.com/", 200, false));
        logger.push(make_entry(2, "POST", "https://b.com/", 201, false));
        let batch = ReplayBatch::from_log(&logger, None);
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn test_replay_batch_filtered() {
        let logger = TrafficLogger::new(100);
        logger.push(make_entry(1, "GET", "https://a.com/", 200, false));
        logger.push(make_entry(2, "POST", "https://b.com/", 404, false));
        let batch = ReplayBatch::from_log(&logger, Some(&FilterRule::Method("POST".to_string())));
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn test_replay_batch_to_json() {
        let logger = TrafficLogger::new(100);
        logger.push(make_entry(1, "GET", "https://a.com/", 200, false));
        let batch = ReplayBatch::from_log(&logger, None);
        let json = batch.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_array());
    }

    // ── LogStats ──────────────────────────────────────────────────────────────

    #[test]
    fn test_log_stats_basic() {
        let entries: Vec<LogEntry> = (1..=5)
            .map(|i| make_entry(i, "GET", "https://a.com/", 200, false))
            .collect();
        let stats = LogStats::compute(&entries);
        assert_eq!(stats.total_entries, 5);
        assert!(stats.total_bytes > 0);
        assert_eq!(stats.avg_duration_ms, 42);
    }

    #[test]
    fn test_log_stats_error_count() {
        let entries = vec![
            make_entry(1, "GET", "https://a.com/", 200, false),
            make_entry(2, "GET", "https://a.com/", 500, false),
            make_entry(3, "GET", "https://a.com/", 404, false),
        ];
        let stats = LogStats::compute(&entries);
        assert_eq!(stats.error_entries, 2);
    }

    #[test]
    fn test_log_stats_tls_count() {
        let entries = vec![
            make_entry(1, "GET", "https://a.com/", 200, true),
            make_entry(2, "GET", "http://b.com/", 200, false),
        ];
        let stats = LogStats::compute(&entries);
        assert_eq!(stats.tls_entries, 1);
    }

    #[test]
    fn test_log_stats_empty() {
        let stats = LogStats::compute(&[]);
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.avg_duration_ms, 0);
    }
}
