//! `event_recorder.rs` — Record and replay analysis events to/from a binary stream.
//!
//! Format (little-endian):
//!   File header : magic[8] + version[4] + reserved[4]
//!   Records     : (length[4] + `timestamp_ns`[8] + `topic_len`[2] + topic[..] + `payload_len`[4] + payload[..])*
//!
//! All integers are little-endian u32/u64 unless noted.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Cursor, Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Cast helpers: deliberate precision-loss boundaries.
#[inline]
const fn cast_usize_to_f64(v: usize) -> f64 { v as f64 }
#[inline]
const fn cast_u64_to_f64(v: u64) -> f64 { v as f64 }
#[inline]
const fn cast_f64_to_u64_sat(v: f64) -> u64 { v as u64 }
#[inline]
const fn cast_f64_to_usize_sat(v: f64) -> usize { v as usize }

// ─── constants ────────────────────────────────────────────────────────────────

const FILE_MAGIC: &[u8; 8] = b"RUSTRE\x01\x00";
const FORMAT_VERSION: u32 = 1;
const MAX_TOPIC_LEN: usize = 512;
const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024; // 16 MiB

// ─── EventRecord ──────────────────────────────────────────────────────────────

/// A single captured event with nanosecond timestamp.
#[derive(Debug, Clone)]
pub struct EventRecord {
    /// Nanoseconds since UNIX epoch when the event was captured.
    pub timestamp_ns: u64,
    /// Topic string (UTF-8).
    pub topic: String,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
}

impl EventRecord {
    /// Create a new record stamped right now.
    pub fn new(topic: impl Into<String>, payload: Vec<u8>) -> Self {
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX);
        Self { timestamp_ns, topic: topic.into(), payload }
    }

    /// Payload interpreted as UTF-8 text (lossy).
    #[must_use] 
    pub fn payload_text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.payload)
    }

    /// Serialize to wire bytes: length-prefixed frame.
    ///
    /// # Errors
    /// Returns `RecorderError::TopicTooLong` or `RecorderError::PayloadTooLarge`
    /// when the corresponding limits are exceeded.
    pub fn encode(&self) -> Result<Vec<u8>, RecorderError> {
        let topic_bytes = self.topic.as_bytes();
        if topic_bytes.len() > MAX_TOPIC_LEN {
            return Err(RecorderError::TopicTooLong(topic_bytes.len()));
        }
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(RecorderError::PayloadTooLarge(self.payload.len()));
        }
        // inner = ts[8] + topic_len[2] + topic + payload_len[4] + payload
        let inner_len: usize = 8 + 2 + topic_bytes.len() + 4 + self.payload.len();
        let mut buf = Vec::with_capacity(4 + inner_len);
        buf.extend_from_slice(&u32::try_from(inner_len).unwrap_or(u32::MAX).to_le_bytes());
        buf.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        buf.extend_from_slice(&u16::try_from(topic_bytes.len()).unwrap_or(u16::MAX).to_le_bytes());
        buf.extend_from_slice(topic_bytes);
        buf.extend_from_slice(&u32::try_from(self.payload.len()).unwrap_or(u32::MAX).to_le_bytes());
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }

    /// Deserialize from a reader.
    ///
    /// # Errors
    /// Returns `RecorderError::Io` on read failure, or `RecorderError::Corrupt`
    /// when frame size fields are out of bounds.
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, RecorderError> {
        // Guard against adversarially large allocations: cap at 2× MAX_PAYLOAD_LEN
        // plus the fixed-size header fields (8 + 2 + 4 = 14 bytes).
        const MAX_INNER_LEN: usize = 14 + MAX_TOPIC_LEN + MAX_PAYLOAD_LEN;
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).map_err(RecorderError::Io)?;
        let inner_len = u32::from_le_bytes(len_buf) as usize;
        if inner_len < 14 {
            return Err(RecorderError::Corrupt("inner_len too small".into()));
        }
        if inner_len > MAX_INNER_LEN {
            return Err(RecorderError::Corrupt(format!(
                "inner_len {inner_len} exceeds maximum {MAX_INNER_LEN}"
            )));
        }
        let mut inner = vec![0u8; inner_len];
        reader.read_exact(&mut inner).map_err(RecorderError::Io)?;
        let mut cur = Cursor::new(&inner);

        let mut ts_buf = [0u8; 8];
        cur.read_exact(&mut ts_buf).map_err(RecorderError::Io)?;
        let timestamp_ns = u64::from_le_bytes(ts_buf);

        let mut topic_len_buf = [0u8; 2];
        cur.read_exact(&mut topic_len_buf).map_err(RecorderError::Io)?;
        let topic_len = u16::from_le_bytes(topic_len_buf) as usize;

        let mut topic_bytes = vec![0u8; topic_len];
        cur.read_exact(&mut topic_bytes).map_err(RecorderError::Io)?;
        let topic = String::from_utf8(topic_bytes)
            .map_err(|_| RecorderError::Corrupt("topic not UTF-8".into()))?;

        let mut pl_buf = [0u8; 4];
        cur.read_exact(&mut pl_buf).map_err(RecorderError::Io)?;
        let payload_len = u32::from_le_bytes(pl_buf) as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(RecorderError::Corrupt(format!(
                "payload_len {payload_len} exceeds maximum {MAX_PAYLOAD_LEN}"
            )));
        }

        let mut payload = vec![0u8; payload_len];
        cur.read_exact(&mut payload).map_err(RecorderError::Io)?;

        Ok(Self { timestamp_ns, topic, payload })
    }
}

// ─── RecorderError ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum RecorderError {
    Io(io::Error),
    BadMagic,
    UnsupportedVersion(u32),
    Corrupt(String),
    TopicTooLong(usize),
    PayloadTooLarge(usize),
    NotOpen,
}

impl fmt::Display for RecorderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::BadMagic => write!(f, "bad file magic — not a rustre event log"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported format version {v}"),
            Self::Corrupt(s) => write!(f, "corrupt data: {s}"),
            Self::TopicTooLong(n) => write!(f, "topic too long ({n} bytes)"),
            Self::PayloadTooLarge(n) => write!(f, "payload too large ({n} bytes)"),
            Self::NotOpen => write!(f, "recorder not open"),
        }
    }
}

impl std::error::Error for RecorderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Io(e) = self { Some(e) } else { None }
    }
}

// ─── EventRecorder ────────────────────────────────────────────────────────────

/// Writes events to an in-memory or external byte sink.
///
/// # Usage
/// ```
/// use rustre_events::event_recorder::EventRecorder;
///
/// let mut rec = EventRecorder::new();
/// rec.record("analysis.start", b"hello".to_vec()).unwrap();
/// let bytes = rec.into_bytes().unwrap();
/// ```
pub struct EventRecorder {
    buffer: Vec<u8>,
    count: u64,
    first_ts: Option<u64>,
    last_ts: Option<u64>,
    opened: bool,
}

impl EventRecorder {
    /// Create a recorder and write the file header immediately.
    #[must_use] 
    pub fn new() -> Self {
        let mut rec = Self {
            buffer: Vec::with_capacity(4096),
            count: 0,
            first_ts: None,
            last_ts: None,
            opened: true,
        };
        rec.write_header();
        rec
    }

    fn write_header(&mut self) {
        self.buffer.extend_from_slice(FILE_MAGIC);
        self.buffer.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        self.buffer.extend_from_slice(&0u32.to_le_bytes()); // reserved
    }

    /// Record an event.
    ///
    /// # Errors
    /// Returns `RecorderError::NotOpen` if the recorder has not been opened,
    /// or the underlying error from `EventRecord::encode`.
    pub fn record(&mut self, topic: &str, payload: Vec<u8>) -> Result<(), RecorderError> {
        if !self.opened {
            return Err(RecorderError::NotOpen);
        }
        let ev = EventRecord::new(topic, payload);
        let ts = ev.timestamp_ns;
        let encoded = ev.encode()?;
        self.buffer.extend_from_slice(&encoded);
        self.count += 1;
        if self.first_ts.is_none() {
            self.first_ts = Some(ts);
        }
        self.last_ts = Some(ts);
        Ok(())
    }

    /// Record with an explicit timestamp (useful in tests or deterministic replay).
    ///
    /// # Errors
    /// Returns `RecorderError::NotOpen` if the recorder has not been opened,
    /// or the underlying error from `EventRecord::encode`.
    pub fn record_at(
        &mut self,
        timestamp_ns: u64,
        topic: &str,
        payload: Vec<u8>,
    ) -> Result<(), RecorderError> {
        if !self.opened {
            return Err(RecorderError::NotOpen);
        }
        let ev = EventRecord { timestamp_ns, topic: topic.to_owned(), payload };
        let encoded = ev.encode()?;
        self.buffer.extend_from_slice(&encoded);
        self.count += 1;
        if self.first_ts.is_none() {
            self.first_ts = Some(timestamp_ns);
        }
        self.last_ts = Some(timestamp_ns);
        Ok(())
    }

    /// Number of events recorded so far.
    #[must_use] 
    pub const fn event_count(&self) -> u64 {
        self.count
    }

    /// Current buffer size in bytes.
    #[must_use] 
    pub const fn byte_len(&self) -> usize {
        self.buffer.len()
    }

    /// Finish and return the raw bytes suitable for writing to a file.
    ///
    /// # Errors
    /// Returns `RecorderError::NotOpen` if the recorder was never opened.
    pub fn into_bytes(self) -> Result<Vec<u8>, RecorderError> {
        if !self.opened {
            return Err(RecorderError::NotOpen);
        }
        Ok(self.buffer)
    }

    /// Write the buffer to a `Write` sink.
    ///
    /// # Errors
    /// Returns `RecorderError::Io` if the underlying writer fails.
    pub fn flush_to<W: Write>(&self, w: &mut W) -> Result<(), RecorderError> {
        w.write_all(&self.buffer).map_err(RecorderError::Io)
    }

    /// Duration spanned by recorded events (None if fewer than 2 events).
    #[must_use] 
    pub const fn duration(&self) -> Option<Duration> {
        match (self.first_ts, self.last_ts) {
            (Some(a), Some(b)) if b >= a => Some(Duration::from_nanos(b - a)),
            _ => None,
        }
    }

    /// Average events per second (None if duration is zero).
    #[must_use] 
    pub fn events_per_second(&self) -> Option<f64> {
        let dur = self.duration()?;
        let secs = dur.as_secs_f64();
        if secs == 0.0 || self.count < 2 {
            return None;
        }
        Some(cast_u64_to_f64(self.count) / secs)
    }
}

impl Default for EventRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EventRecorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventRecorder")
            .field("count", &self.count)
            .field("byte_len", &self.buffer.len())
            .field("first_ts", &self.first_ts)
            .field("last_ts", &self.last_ts)
            .field("opened", &self.opened)
            .finish()
    }
}

// ─── ReplayConfig ─────────────────────────────────────────────────────────────

/// Configuration for replaying a recorded event log.
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// If Some, only replay events whose topic contains this substring.
    pub topic_filter: Option<String>,
    /// If Some, skip events before this nanosecond timestamp.
    pub start_ns: Option<u64>,
    /// If Some, stop replaying after this nanosecond timestamp.
    pub end_ns: Option<u64>,
    /// Replay speed multiplier (1.0 = real-time, 2.0 = double speed, 0.0 = instant).
    pub speed: f64,
    /// Maximum events to replay (0 = unlimited).
    pub limit: usize,
}

impl ReplayConfig {
    #[must_use] 
    pub const fn instant() -> Self {
        Self {
            topic_filter: None,
            start_ns: None,
            end_ns: None,
            speed: 0.0,
            limit: 0,
        }
    }

    #[must_use] 
    pub fn real_time() -> Self {
        Self { speed: 1.0, ..Self::instant() }
    }

    #[must_use]
    pub fn with_topic(mut self, topic: impl Into<String>) -> Self {
        self.topic_filter = Some(topic.into());
        self
    }

    #[must_use] 
    pub const fn with_limit(mut self, n: usize) -> Self {
        self.limit = n;
        self
    }

    #[must_use] 
    pub const fn with_speed(mut self, s: f64) -> Self {
        self.speed = s;
        self
    }

    fn matches(&self, ev: &EventRecord) -> bool {
        if let Some(tf) = &self.topic_filter
            && !ev.topic.contains(tf.as_str()) {
                return false;
            }
        if let Some(s) = self.start_ns
            && ev.timestamp_ns < s {
                return false;
            }
        if let Some(e) = self.end_ns
            && ev.timestamp_ns > e {
                return false;
            }
        true
    }
}

// ─── ReplayStats ──────────────────────────────────────────────────────────────

/// Statistics collected during a replay run.
#[derive(Debug, Clone, Default)]
pub struct ReplayStats {
    pub total_read: u64,
    pub total_delivered: u64,
    pub total_skipped: u64,
    pub elapsed_wall: Duration,
    pub first_event_ns: Option<u64>,
    pub last_event_ns: Option<u64>,
}

impl ReplayStats {
    #[must_use] 
    pub fn events_per_second(&self) -> f64 {
        let secs = self.elapsed_wall.as_secs_f64();
        if secs == 0.0 { 0.0 } else { self.total_delivered as f64 / secs }
    }

    #[must_use] 
    pub const fn span_duration(&self) -> Option<Duration> {
        match (self.first_event_ns, self.last_event_ns) {
            (Some(a), Some(b)) if b >= a => Some(Duration::from_nanos(b - a)),
            _ => None,
        }
    }
}

impl fmt::Display for ReplayStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReplayStats {{ read={}, delivered={}, skipped={}, wall={:.3}s, eps={:.1} }}",
            self.total_read,
            self.total_delivered,
            self.total_skipped,
            self.elapsed_wall.as_secs_f64(),
            self.events_per_second()
        )
    }
}

// ─── EventReplayer ────────────────────────────────────────────────────────────

/// Reads a binary event log and replays events to a callback.
pub struct EventReplayer {
    data: Vec<u8>,
}

impl EventReplayer {
    /// Load from raw bytes (e.g. from `EventRecorder::into_bytes()`).
    ///
    /// # Errors
    /// Returns `RecorderError::Corrupt` if the buffer is too short or contains
    /// an unexpected magic / version, or `RecorderError::Io` if record decoding
    /// fails.
    ///
    /// # Panics
    /// Panics if the internal end-of-stream check observes inconsistent state.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, RecorderError> {
        if data.len() < 16 {
            return Err(RecorderError::Corrupt("too short for header".into()));
        }
        if &data[0..8] != FILE_MAGIC {
            return Err(RecorderError::BadMagic);
        }
        let ver = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if ver != FORMAT_VERSION {
            return Err(RecorderError::UnsupportedVersion(ver));
        }
        Ok(Self { data })
    }

    /// Iterate over all records in log order. Returns (record, `decode_error`).
    #[must_use] 
    pub const fn records(&self) -> RecordIterator<'_> {
        RecordIterator {
            cursor: Cursor::new(&self.data),
            done: false,
        }
    }

    /// Replay events with a config, calling `cb` for each delivered event.
    /// Returns statistics about the run.
    pub fn replay<F>(&self, config: &ReplayConfig, mut cb: F) -> ReplayStats
    where
        F: FnMut(&EventRecord),
    {
        let mut stats = ReplayStats::default();
        let start_wall = Instant::now();

        // Collect first to allow time-aware delivery.
        let records: Vec<EventRecord> = self
            .records()
            .filter_map(std::result::Result::ok)
            .collect();

        let mut prev_ts: Option<u64> = None;
        let mut delivered = 0usize;

        for ev in &records {
            stats.total_read += 1;

            if !config.matches(ev) {
                stats.total_skipped += 1;
                continue;
            }

            // Timing: simulate original gaps when speed > 0.
            if config.speed > 0.0
                && let Some(prev) = prev_ts
                    && ev.timestamp_ns > prev {
                        let gap_ns = ev.timestamp_ns - prev;
                        let real_ns = cast_f64_to_u64_sat(cast_u64_to_f64(gap_ns) / config.speed);
                        if real_ns > 0 {
                            std::thread::sleep(Duration::from_nanos(real_ns));
                        }
                    }
            prev_ts = Some(ev.timestamp_ns);

            if stats.first_event_ns.is_none() {
                stats.first_event_ns = Some(ev.timestamp_ns);
            }
            stats.last_event_ns = Some(ev.timestamp_ns);

            cb(ev);
            stats.total_delivered += 1;
            delivered += 1;

            if config.limit > 0 && delivered >= config.limit {
                break;
            }
        }

        stats.elapsed_wall = start_wall.elapsed();
        stats
    }

    /// Count events matching a filter without a callback.
    #[must_use] 
    pub fn count_matching(&self, config: &ReplayConfig) -> u64 {
        self.records()
            .filter_map(std::result::Result::ok)
            .filter(|ev| config.matches(ev))
            .count() as u64
    }
}

// ─── RecordIterator ───────────────────────────────────────────────────────────

pub struct RecordIterator<'a> {
    cursor: Cursor<&'a Vec<u8>>,
    done: bool,
}

impl RecordIterator<'_> {
    const fn skip_header(&mut self) {
        // Already positioned at 0; skip 16-byte header.
        let pos = self.cursor.position();
        if pos == 0 {
            self.cursor.set_position(16);
        }
    }
}

impl Iterator for RecordIterator<'_> {
    type Item = Result<EventRecord, RecorderError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        self.skip_header();
        let pos = usize::try_from(self.cursor.position()).unwrap_or(usize::MAX);
        if pos >= self.cursor.get_ref().len() {
            self.done = true;
            return None;
        }
        match EventRecord::decode(&mut self.cursor) {
            Ok(ev) => Some(Ok(ev)),
            Err(RecorderError::Io(_)) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

// ─── EventTimeline ────────────────────────────────────────────────────────────

/// Text-based timeline visualization of recorded events.
pub struct EventTimeline {
    records: Vec<EventRecord>,
    width: usize,
}

impl EventTimeline {
    /// Build a timeline from a replayer (loads all records).
    #[must_use] 
    pub fn from_replayer(replayer: &EventReplayer) -> Self {
        let records: Vec<EventRecord> = replayer
            .records()
            .filter_map(std::result::Result::ok)
            .collect();
        Self { records, width: 60 }
    }

    #[must_use] 
    pub fn with_width(mut self, w: usize) -> Self {
        self.width = w.max(20);
        self
    }

    /// Render a histogram: time is divided into `bins` buckets across the width.
    ///
    /// # Panics
    /// Panics if `self.records` is non-empty but its first/last elements cannot
    /// be accessed (should not happen given the empty-records early return).
    #[must_use]
    pub fn render_histogram(&self, bins: usize) -> String {
        use std::fmt::Write as _;
        if self.records.is_empty() {
            return "(no events)\n".to_owned();
        }
        let bins = bins.clamp(1, self.width);
        let first = self.records.first().unwrap().timestamp_ns;
        let last = self.records.last().unwrap().timestamp_ns;
        let span = if last > first { last - first } else { 1 };

        let mut counts = vec![0usize; bins];
        for ev in &self.records {
            let offset = ev.timestamp_ns.saturating_sub(first);
            let idx = ((cast_u64_to_f64(offset) / cast_u64_to_f64(span)) * cast_usize_to_f64(bins - 1)) as usize;
            counts[idx.min(bins - 1)] += 1;
        }
        let max_count = *counts.iter().max().unwrap_or(&1).max(&1);
        let bar_height = 8usize;

        let mut out = String::new();
        // Top axis
        let _ = writeln!(out, "Events over time ({} total)", self.records.len());
        let _ = writeln!(out, "  [{:.3}s span]", cast_u64_to_f64(span) / 1e9);

        for row in (0..bar_height).rev() {
            let threshold = (cast_usize_to_f64(row) / cast_usize_to_f64(bar_height)) * cast_usize_to_f64(max_count);
            let line: String = counts
                .iter()
                .map(|&c| if cast_usize_to_f64(c) > threshold { '█' } else { ' ' })
                .collect();
            let _ = writeln!(out, "{:>4} |{}|", if row == bar_height - 1 { max_count } else { 0 }, line);
        }
        let _ = writeln!(out, "     +{}+", "-".repeat(bins));
        let _ = writeln!(out, "     {:^width$}", "time →", width = bins);
        out
    }

    /// Render a per-topic event count summary.
    #[must_use]
    pub fn render_topic_summary(&self) -> String {
        use std::fmt::Write as _;
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for ev in &self.records {
            *counts.entry(ev.topic.as_str()).or_insert(0) += 1;
        }
        let mut pairs: Vec<(&str, usize)> = counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        let total: usize = pairs.iter().map(|(_, c)| c).sum();
        let max_c = pairs.first().map_or(1, |(_, c)| *c).max(1);

        let mut out = format!("Topic breakdown ({total} events):\n");
        for (topic, count) in &pairs {
            let bar_len = cast_f64_to_usize_sat((cast_usize_to_f64(*count) / cast_usize_to_f64(max_c)) * 40.0);
            let _ = writeln!(
                out,
                "  {:<35} {:>5}  {}",
                topic,
                count,
                "▪".repeat(bar_len)
            );
        }
        out
    }

    /// Render a compact event list (first N events).
    #[must_use]
    pub fn render_list(&self, max_events: usize) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let show = self.records.len().min(max_events);
        let first_ts = self.records.first().map_or(0, |r| r.timestamp_ns);
        for (i, ev) in self.records[..show].iter().enumerate() {
            let rel_ms = ev.timestamp_ns.saturating_sub(first_ts) / 1_000_000;
            let preview = if ev.payload.len() <= 40 {
                String::from_utf8_lossy(&ev.payload).into_owned()
            } else {
                format!("{}…", String::from_utf8_lossy(&ev.payload[..40]))
            };
            let _ = writeln!(
                out,
                "[{:>5}] +{:>8}ms  {:<35}  {}",
                i, rel_ms, ev.topic, preview
            );
        }
        if self.records.len() > max_events {
            let _ = writeln!(out, "  ... and {} more events", self.records.len() - max_events);
        }
        out
    }
}

impl fmt::Display for EventTimeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render_topic_summary())
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log(events: &[(&str, &str)]) -> Vec<u8> {
        let mut rec = EventRecorder::new();
        let base: u64 = 1_000_000_000;
        for (i, (topic, payload)) in events.iter().enumerate() {
            rec.record_at(base + i as u64 * 100_000_000, topic, payload.as_bytes().to_vec())
                .unwrap();
        }
        rec.into_bytes().unwrap()
    }

    #[test]
    fn round_trip_single() {
        let ev = EventRecord { timestamp_ns: 999, topic: "test.topic".into(), payload: b"hello".to_vec() };
        let enc = ev.encode().unwrap();
        let mut cur = Cursor::new(&enc);
        let dec = EventRecord::decode(&mut cur).unwrap();
        assert_eq!(dec.timestamp_ns, 999);
        assert_eq!(dec.topic, "test.topic");
        assert_eq!(dec.payload, b"hello");
    }

    #[test]
    fn recorder_counts() {
        let mut rec = EventRecorder::new();
        rec.record("a.b", b"1".to_vec()).unwrap();
        rec.record("a.c", b"2".to_vec()).unwrap();
        assert_eq!(rec.event_count(), 2);
        assert!(rec.byte_len() > 16);
    }

    #[test]
    fn replayer_basic() {
        let bytes = make_log(&[
            ("analysis.start", "begin"),
            ("analysis.fn",    "func1"),
            ("analysis.end",   "done"),
        ]);
        let rp = EventReplayer::from_bytes(bytes).unwrap();
        let records: Vec<_> = rp.records().filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].topic, "analysis.start");
        assert_eq!(records[2].payload_text(), "done");
    }

    #[test]
    fn replay_with_filter() {
        let bytes = make_log(&[
            ("fn.entry", "a"), ("fn.exit", "b"), ("string.found", "c"), ("fn.entry", "d"),
        ]);
        let rp = EventReplayer::from_bytes(bytes).unwrap();
        let cfg = ReplayConfig::instant().with_topic("fn.");
        let mut received = Vec::new();
        let stats = rp.replay(&cfg, |ev| received.push(ev.topic.clone()));
        assert_eq!(received.len(), 3); // fn.entry x2 + fn.exit x1
        assert_eq!(stats.total_delivered, 3);
        assert_eq!(stats.total_skipped, 1);
    }

    #[test]
    fn replay_with_limit() {
        let bytes = make_log(&[("t","1"),("t","2"),("t","3"),("t","4"),("t","5")]);
        let rp = EventReplayer::from_bytes(bytes).unwrap();
        let cfg = ReplayConfig::instant().with_limit(3);
        let mut count = 0;
        rp.replay(&cfg, |_| count += 1);
        assert_eq!(count, 3);
    }

    #[test]
    fn replay_time_range() {
        let mut rec = EventRecorder::new();
        rec.record_at(100, "a", b"1".to_vec()).unwrap();
        rec.record_at(200, "a", b"2".to_vec()).unwrap();
        rec.record_at(300, "a", b"3".to_vec()).unwrap();
        rec.record_at(400, "a", b"4".to_vec()).unwrap();
        let bytes = rec.into_bytes().unwrap();
        let rp = EventReplayer::from_bytes(bytes).unwrap();
        let cfg = ReplayConfig { start_ns: Some(200), end_ns: Some(300), ..ReplayConfig::instant() };
        assert_eq!(rp.count_matching(&cfg), 2);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut data = vec![0u8; 32];
        data[0..8].copy_from_slice(b"BADMAGIC");
        assert!(matches!(EventReplayer::from_bytes(data), Err(RecorderError::BadMagic)));
    }

    #[test]
    fn events_per_second() {
        let mut rec = EventRecorder::new();
        rec.record_at(0,          "x", b"a".to_vec()).unwrap();
        rec.record_at(1_000_000_000, "x", b"b".to_vec()).unwrap(); // 1 second later
        // 2 events over 1 second = 2 eps
        let eps = rec.events_per_second().unwrap();
        assert!((eps - 2.0).abs() < 0.01, "expected ~2 eps, got {}", eps);
    }

    #[test]
    fn timeline_histogram() {
        let bytes = make_log(&[("a","1"),("a","2"),("b","3")]);
        let rp = EventReplayer::from_bytes(bytes).unwrap();
        let tl = EventTimeline::from_replayer(&rp);
        let h = tl.render_histogram(10);
        assert!(h.contains("Events over time"));
    }

    #[test]
    fn timeline_topic_summary() {
        let bytes = make_log(&[("fn.entry","1"),("fn.entry","2"),("fn.exit","3")]);
        let rp = EventReplayer::from_bytes(bytes).unwrap();
        let tl = EventTimeline::from_replayer(&rp);
        let s = tl.render_topic_summary();
        assert!(s.contains("fn.entry"));
        assert!(s.contains("fn.exit"));
    }

    #[test]
    fn timeline_list() {
        let bytes = make_log(&[("t","hello"),("t","world")]);
        let rp = EventReplayer::from_bytes(bytes).unwrap();
        let tl = EventTimeline::from_replayer(&rp);
        let l = tl.render_list(10);
        assert!(l.contains("hello"));
        assert!(l.contains("world"));
    }

    #[test]
    fn payload_text_lossy() {
        let ev = EventRecord { timestamp_ns: 0, topic: "t".into(), payload: b"abc\xff".to_vec() };
        let t = ev.payload_text();
        assert!(t.contains("abc"));
    }

    #[test]
    fn replay_config_builder() {
        let cfg = ReplayConfig::real_time().with_topic("foo").with_limit(5).with_speed(2.0);
        assert_eq!(cfg.topic_filter.as_deref(), Some("foo"));
        assert_eq!(cfg.limit, 5);
        assert!((cfg.speed - 2.0).abs() < f64::EPSILON);
    }
}
