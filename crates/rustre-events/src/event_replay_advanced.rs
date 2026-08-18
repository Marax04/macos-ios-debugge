//! `event_replay_advanced.rs` — Binary recording, integrity-checked replay,
//! and speed-controlled event stream reconstruction for `RustRE`.
//!
//! Complements the existing `event_replay` module with richer types:
//! [`EventRecorder`], [`EventReplayer`], [`EventFilter`], [`ReplayConfig`],
//! and [`EventRecord`].

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Cursor, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Isolate usize→f64 precision-loss cast.
#[inline]
const fn cast_usize_f64(v: usize) -> f64 { v as f64 }
/// Isolate u64→f64 precision-loss cast.
#[inline]
const fn cast_u64_f64(v: u64) -> f64 { v as f64 }
/// Saturating f64→u64 cast.
#[inline]
const fn cast_f64_u64_sat(v: f64) -> u64 { v.max(0.0).min(u64::MAX as f64) as u64 }

use crate::event_types::{AnalysisEvent, EventPayload, EventPriority};

// ---------------------------------------------------------------------------
// CRC-32 (IEEE polynomial, no external crate)
// ---------------------------------------------------------------------------

/// Compute CRC-32 (IEEE) over `data`.
#[must_use]
pub fn adv_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// EventRecord
// ---------------------------------------------------------------------------

/// A single recorded event envelope persisted by [`EventRecorder`].
#[derive(Debug, Clone)]
pub struct EventRecord {
    /// Monotonic sequence number assigned at publish time.
    pub sequence: u64,
    /// Microseconds since UNIX epoch.
    pub timestamp_us: u64,
    /// CRC-32 of the `json` field.
    pub checksum: u32,
    /// Short event class name (`variant_name`), stored for fast filtering.
    pub variant_name: String,
    /// View this event belongs to (0 encodes None).
    pub view_id: Option<u64>,
    /// Priority at time of recording.
    pub priority: EventPriority,
    /// Compact JSON representation of the envelope.
    pub json: String,
}

impl EventRecord {
    /// Build a record from a live [`EventPayload`].
    #[must_use]
    pub fn from_payload(p: &EventPayload) -> Self {
        let view_part = p.view_id().map_or_else(String::new, |v| format!(r#","view_id":{v}"#));
        let json = format!(
            r#"{{"v":"{v}","seq":{s},"pri":{pr}{vp}}}"#,
            v = p.variant_name(),
            s = p.sequence,
            pr = p.priority as u8,
            vp = view_part,
        );
        let checksum = adv_crc32(json.as_bytes());
        let timestamp_us = p
            .timestamp
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d: std::time::Duration| u64::try_from(d.as_micros().min(u128::from(u64::MAX))).unwrap_or(u64::MAX));
        Self {
            sequence: p.sequence,
            timestamp_us,
            checksum,
            variant_name: p.variant_name().to_owned(),
            view_id: p.view_id(),
            priority: p.priority,
            json,
        }
    }

    /// Verify that stored checksum matches actual JSON content.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        adv_crc32(self.json.as_bytes()) == self.checksum
    }

    /// Reconstruct a placeholder [`EventPayload`] from this record.
    #[must_use]
    pub fn to_payload(&self) -> EventPayload {
        use crate::event_types::ProgressUpdatePayload;
        let event = AnalysisEvent::ProgressUpdate(ProgressUpdatePayload {
            view_id: self.view_id.unwrap_or(0),
            task_name: format!("replay:{}", self.variant_name),
            percent: 0,
            items_done: self.sequence,
            items_total: 0,
            eta_secs: None,
            message: format!("replayed seq={}", self.sequence),
        });
        EventPayload::new(event, self.priority, self.sequence)
    }
}

// ---------------------------------------------------------------------------
// Binary serialisation helpers
// ---------------------------------------------------------------------------

/// Magic bytes at the start of a recording file.
pub const MAGIC: &[u8; 8] = b"RREC2025";

fn write_u8<W: Write>(w: &mut W, v: u8) -> io::Result<()> {
    w.write_all(&[v])
}
fn write_u16_le<W: Write>(w: &mut W, v: u16) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn write_u32_le<W: Write>(w: &mut W, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn write_u64_le<W: Write>(w: &mut W, v: u64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn write_bytes<W: Write>(w: &mut W, b: &[u8]) -> io::Result<()> {
    w.write_all(b)
}

fn read_u8<R: Read>(r: &mut R) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}
fn read_u16_le<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}
fn read_u32_le<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64_le<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
fn read_string<R: Read>(r: &mut R, len: usize) -> io::Result<String> {
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utf8"))
}

// ---------------------------------------------------------------------------
// EventRecorder
// ---------------------------------------------------------------------------

/// Records [`EventPayload`]s into an in-memory log that can be serialised to
/// binary for later replay.
#[derive(Debug, Default)]
pub struct EventRecorder {
    records: Vec<EventRecord>,
    /// Capacity limit (0 = unlimited).
    capacity: usize,
    /// Whether recording is active.
    pub active: bool,
    /// Deduplicate by checksum (skip if same as previous).
    pub deduplicate: bool,
    /// Running statistics.
    pub stats: RecorderStats,
}

/// Statistics tracked by [`EventRecorder`].
#[derive(Debug, Default, Clone)]
pub struct RecorderStats {
    pub total_recorded: u64,
    pub total_evicted: u64,
    pub duplicates_skipped: u64,
    pub by_variant: HashMap<String, u64>,
}

impl EventRecorder {
    /// Create a recorder with a bounded history.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self { capacity, active: true, ..Self::default() }
    }

    /// Create an unbounded recorder (keeps all events).
    #[must_use]
    pub fn unbounded() -> Self {
        Self::new(0)
    }

    /// Record one [`EventPayload`].
    pub fn record(&mut self, payload: &EventPayload) {
        if !self.active {
            return;
        }
        let rec = EventRecord::from_payload(payload);

        if self.deduplicate
            && self.records.last().is_some_and(|l| l.checksum == rec.checksum) {
                self.stats.duplicates_skipped += 1;
                return;
            }

        if self.capacity > 0 && self.records.len() >= self.capacity {
            self.records.remove(0);
            self.stats.total_evicted += 1;
        }

        *self.stats.by_variant.entry(rec.variant_name.clone()).or_insert(0) += 1;
        self.stats.total_recorded += 1;
        self.records.push(rec);
    }

    /// Immutable slice of all stored records.
    #[must_use]
    pub fn records(&self) -> &[EventRecord] {
        &self.records
    }

    /// Number of records in memory.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// True when no records are stored.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Discard all stored records.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Verify integrity of every record; returns `(ok_count, corrupt_count)`.
    #[must_use]
    pub fn verify_all(&self) -> (usize, usize) {
        let ok = self.records.iter().filter(|r| r.is_intact()).count();
        (ok, self.records.len() - ok)
    }

    /// Serialise all records to `w`.
    ///
    /// # Errors
    /// Returns `io::Error` on write failure.
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_bytes(w, MAGIC)?;
        write_u64_le(w, self.records.len() as u64)?;
        for rec in &self.records {
            write_u64_le(w, rec.sequence)?;
            write_u64_le(w, rec.timestamp_us)?;
            write_u32_le(w, rec.checksum)?;
            let vn = rec.variant_name.as_bytes();
            write_u16_le(w, u16::try_from(vn.len()).unwrap_or(u16::MAX))?;
            write_bytes(w, vn)?;
            write_u64_le(w, rec.view_id.unwrap_or(0))?;
            write_u8(w, rec.priority as u8)?;
            let jb = rec.json.as_bytes();
            write_u32_le(w, u32::try_from(jb.len()).unwrap_or(u32::MAX))?;
            write_bytes(w, jb)?;
        }
        Ok(())
    }

    /// Serialise to a `Vec<u8>`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let _ = self.write_to(&mut buf);
        buf
    }

    /// Deserialise from a reader.
    ///
    /// # Errors
    /// Returns `io::Error` on malformed data.
    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        const MAX_RECORDS: usize = 10_000_000;
        const MAX_JSON_LEN: usize = 4 * 1024 * 1024; // 4 MiB
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid magic"));
        }
        let count_raw = read_u64_le(r)?;
        if count_raw > MAX_RECORDS as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("record count {count_raw} exceeds maximum {MAX_RECORDS}"),
            ));
        }
        let count = usize::try_from(count_raw).unwrap_or(usize::MAX);
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let sequence = read_u64_le(r)?;
            let timestamp_us = read_u64_le(r)?;
            let checksum = read_u32_le(r)?;
            let vn_len = read_u16_le(r)? as usize;
            let variant_name = read_string(r, vn_len)?;
            let vid_raw = read_u64_le(r)?;
            let view_id = if vid_raw == 0 { None } else { Some(vid_raw) };
            let prio_byte = read_u8(r)?;
            let priority = match prio_byte {
                0 => EventPriority::Low,
                1 => EventPriority::Normal,
                2 => EventPriority::High,
                _ => EventPriority::Critical,
            };
            let jlen = read_u32_le(r)? as usize;
            if jlen > MAX_JSON_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("json field length {jlen} exceeds maximum {MAX_JSON_LEN}"),
                ));
            }
            let json = read_string(r, jlen)?;
            records.push(EventRecord { sequence, timestamp_us, checksum, variant_name, view_id, priority, json });
        }
        Ok(Self { records, capacity: 0, active: false, deduplicate: false, stats: RecorderStats::default() })
    }

    /// Deserialise from a byte slice.
    ///
    /// # Errors
    /// Returns `io::Error` on malformed data.
    pub fn from_bytes(data: &[u8]) -> io::Result<Self> {
        Self::read_from(&mut Cursor::new(data))
    }

    /// Return records whose `view_id` matches `vid`.
    #[must_use]
    pub fn records_for_view(&self, vid: u64) -> Vec<&EventRecord> {
        self.records.iter().filter(|r| r.view_id == Some(vid)).collect()
    }

    /// Return per-variant counts.
    #[must_use]
    pub fn variant_counts(&self) -> HashMap<&str, usize> {
        let mut m: HashMap<&str, usize> = HashMap::new();
        for r in &self.records {
            *m.entry(r.variant_name.as_str()).or_insert(0) += 1;
        }
        m
    }
}

// ---------------------------------------------------------------------------
// ReplayConfig
// ---------------------------------------------------------------------------

/// Controls how [`EventReplayer`] replays a recording.
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Speed multiplier (1.0 = real-time, 0.0 = instant).
    pub speed: f64,
    /// Skip records that fail integrity check.
    pub skip_corrupt: bool,
    /// Only replay events at or above this priority.
    pub min_priority: EventPriority,
    /// Restrict replay to a single view (None = all views).
    pub view_id_filter: Option<u64>,
    /// Restrict to these variant names (None = all).
    pub variant_filter: Option<Vec<String>>,
    /// Sequence range filter.
    pub seq_range: Option<(u64, u64)>,
    /// Maximum events to replay (0 = unlimited).
    pub max_events: usize,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            speed: 1.0,
            skip_corrupt: true,
            min_priority: EventPriority::Low,
            view_id_filter: None,
            variant_filter: None,
            seq_range: None,
            max_events: 0,
        }
    }
}

impl ReplayConfig {
    /// Instant replay, no filtering.
    #[must_use]
    pub fn instant() -> Self {
        Self { speed: 0.0, ..Self::default() }
    }

    /// True when `record` passes all configured filters.
    #[must_use]
    pub fn accepts(&self, record: &EventRecord) -> bool {
        if record.priority < self.min_priority {
            return false;
        }
        if let Some(vid) = self.view_id_filter
            && record.view_id.is_some_and(|v| v != vid) {
                return false;
            }
        if let Some(ref variants) = self.variant_filter
            && !variants.iter().any(|v| v == &record.variant_name) {
                return false;
            }
        if let Some((lo, hi)) = self.seq_range
            && (record.sequence < lo || record.sequence > hi) {
                return false;
            }
        true
    }

    /// Compute inter-event delay for real-time replay.
    #[must_use]
    pub fn delay_between(&self, ts_a: u64, ts_b: u64) -> Duration {
        if ts_b <= ts_a || self.speed <= 0.0 {
            return Duration::ZERO;
        }
        let delta = ts_b - ts_a;
        Duration::from_micros(cast_f64_u64_sat(cast_u64_f64(delta) / self.speed))
    }
}

// ---------------------------------------------------------------------------
// EventFilter — replay-time predicate
// ---------------------------------------------------------------------------

/// A filtering predicate applied during replay.
///
/// Differs from [`AnalysisEventFilter`] in that it operates on [`EventRecord`]
/// values directly, without reconstructing full payloads.
pub struct EventFilter {
    inner: Box<dyn Fn(&EventRecord) -> bool + Send + Sync>,
    pub description: String,
}

impl fmt::Debug for EventFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventFilter({})", self.description)
    }
}

impl EventFilter {
    /// Create from any predicate.
    pub fn new(desc: impl Into<String>, f: impl Fn(&EventRecord) -> bool + Send + Sync + 'static) -> Self {
        Self { inner: Box::new(f), description: desc.into() }
    }

    /// Accept records whose variant name matches.
    #[must_use]
    pub fn by_variant(name: impl Into<String>) -> Self {
        let n: String = name.into();
        Self::new(format!("variant={n}"), move |r| r.variant_name == n)
    }

    /// Accept records for a given view.
    #[must_use]
    pub fn by_view(vid: u64) -> Self {
        Self::new(format!("view={vid}"), move |r| r.view_id == Some(vid))
    }

    /// Accept records with priority >= min.
    #[must_use]
    pub fn min_priority(min: EventPriority) -> Self {
        Self::new(format!("pri>={min}"), move |r| r.priority >= min)
    }

    /// Accept records in a sequence range.
    #[must_use]
    pub fn seq_range(lo: u64, hi: u64) -> Self {
        Self::new(format!("seq=[{lo},{hi}]"), move |r| r.sequence >= lo && r.sequence <= hi)
    }

    /// Logical AND of two filters.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        let desc = format!("({}) AND ({})", self.description, other.description);
        Self::new(desc, move |r| (self.inner)(r) && (other.inner)(r))
    }

    /// Logical OR of two filters.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        let desc = format!("({}) OR ({})", self.description, other.description);
        Self::new(desc, move |r| (self.inner)(r) || (other.inner)(r))
    }

    /// Logical NOT.
    #[must_use]
    pub fn negate(self) -> Self {
        let desc = format!("NOT ({})", self.description);
        Self::new(desc, move |r| !(self.inner)(r))
    }

    /// Test a record.
    #[must_use]
    pub fn matches(&self, record: &EventRecord) -> bool {
        (self.inner)(record)
    }
}

// ---------------------------------------------------------------------------
// ReplayStats
// ---------------------------------------------------------------------------

/// Statistics accumulated during a replay run.
#[derive(Debug, Default, Clone)]
pub struct ReplayStats {
    pub total_replayed: u64,
    pub total_skipped_by_filter: u64,
    pub total_skipped_corrupt: u64,
    pub by_variant: HashMap<String, u64>,
    pub by_view: HashMap<u64, u64>,
    pub elapsed_ms: u64,
}

// ---------------------------------------------------------------------------
// EventReplayer
// ---------------------------------------------------------------------------

/// Replays a sequence of [`EventRecord`]s as [`EventPayload`]s with
/// configurable speed, filtering, and integrity validation.
pub struct EventReplayer {
    records: Vec<EventRecord>,
    pub config: ReplayConfig,
    position: usize,
    pub stats: ReplayStats,
    extra_filter: Option<EventFilter>,
}

impl fmt::Debug for EventReplayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventReplayer")
            .field("records_len", &self.records.len())
            .field("position", &self.position)
            .field("config", &self.config)
            .field("stats", &self.stats)
            .field("extra_filter", &self.extra_filter.as_ref().map(|_| "<EventFilter>"))
            .finish()
    }
}

impl EventReplayer {
    /// Build from a recorder snapshot.
    #[must_use]
    pub fn from_recorder(recorder: &EventRecorder, config: ReplayConfig) -> Self {
        Self {
            records: recorder.records.clone(),
            config,
            position: 0,
            stats: ReplayStats::default(),
            extra_filter: None,
        }
    }

    /// Build from raw records.
    #[must_use]
    pub fn new(records: Vec<EventRecord>, config: ReplayConfig) -> Self {
        Self { records, config, position: 0, stats: ReplayStats::default(), extra_filter: None }
    }

    /// Attach an additional record-level filter applied after config filters.
    pub fn set_filter(&mut self, filter: EventFilter) {
        self.extra_filter = Some(filter);
    }

    /// True when no more records remain.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.position >= self.records.len()
            || (self.config.max_events > 0 && self.stats.total_replayed >= self.config.max_events as u64)
    }

    /// Advance and return the next matching payload, or `None` when done.
    pub fn next_payload(&mut self) -> Option<EventPayload> {
        let start = std::time::Instant::now();
        while self.position < self.records.len() {
            if self.config.max_events > 0 && self.stats.total_replayed >= self.config.max_events as u64 {
                break;
            }
            let rec = &self.records[self.position];
            self.position += 1;

            if !rec.is_intact() {
                self.stats.total_skipped_corrupt += 1;
                if self.config.skip_corrupt {
                    continue;
                }
            }

            if !self.config.accepts(rec) {
                self.stats.total_skipped_by_filter += 1;
                continue;
            }

            if let Some(ref ef) = self.extra_filter
                && !ef.matches(rec) {
                    self.stats.total_skipped_by_filter += 1;
                    continue;
                }

            let payload = rec.to_payload();
            *self.stats.by_variant.entry(rec.variant_name.clone()).or_insert(0) += 1;
            if let Some(vid) = rec.view_id {
                *self.stats.by_view.entry(vid).or_insert(0) += 1;
            }
            self.stats.total_replayed += 1;
            self.stats.elapsed_ms += u64::try_from(start.elapsed().as_millis()).unwrap_or(0);
            return Some(payload);
        }
        None
    }

    /// Collect all remaining matching payloads.
    pub fn collect_all(&mut self) -> Vec<EventPayload> {
        let mut out = Vec::new();
        while let Some(p) = self.next_payload() {
            out.push(p);
        }
        out
    }

    /// Call `callback` for every matching payload.
    pub fn replay_into<F: FnMut(EventPayload)>(&mut self, mut callback: F) {
        while let Some(p) = self.next_payload() {
            callback(p);
        }
    }

    /// Reset to the beginning.
    pub fn reset(&mut self) {
        self.position = 0;
        self.stats = ReplayStats::default();
    }

    /// Current position index.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Total record count.
    #[must_use]
    pub const fn total_records(&self) -> usize {
        self.records.len()
    }

    /// Replay progress as percentage [0, 100].
    #[must_use]
    pub fn progress_pct(&self) -> f64 {
        if self.records.is_empty() { return 100.0; }
        cast_usize_f64(self.position) / cast_usize_f64(self.records.len()) * 100.0
    }

    /// Compute the inter-event delay between record at `idx-1` and `idx`.
    #[must_use]
    pub fn delay_before(&self, idx: usize) -> Duration {
        if idx == 0 || idx >= self.records.len() {
            return Duration::ZERO;
        }
        self.config.delay_between(
            self.records[idx - 1].timestamp_us,
            self.records[idx].timestamp_us,
        )
    }

    /// Jump to position `idx`, clamped to record count.
    pub fn seek(&mut self, idx: usize) {
        self.position = idx.min(self.records.len());
    }

    /// Return records in the given sequence range.
    #[must_use]
    pub fn records_in_seq_range(&self, lo: u64, hi: u64) -> Vec<&EventRecord> {
        self.records.iter().filter(|r| r.sequence >= lo && r.sequence <= hi).collect()
    }

    /// Count how many records pass the current config without actually replaying.
    #[must_use]
    pub fn count_matching(&self) -> usize {
        self.records.iter()
            .filter(|r| {
                r.is_intact() && self.config.accepts(r)
                    && self.extra_filter.as_ref().is_none_or(|f| f.matches(r))
            })
            .count()
    }
}

// ---------------------------------------------------------------------------
// ReplaySession
// ---------------------------------------------------------------------------

/// Bundles a recorder and replay configuration into one session object.
#[derive(Debug)]
pub struct ReplaySession {
    pub recorder: EventRecorder,
    pub config: ReplayConfig,
    pub id: String,
    pub created_at: SystemTime,
}

impl ReplaySession {
    /// Create a new session.
    #[must_use]
    pub fn new(id: impl Into<String>, capacity: usize, config: ReplayConfig) -> Self {
        Self {
            recorder: EventRecorder::new(capacity),
            config,
            id: id.into(),
            created_at: SystemTime::now(),
        }
    }

    /// Record one payload.
    pub fn record(&mut self, p: &EventPayload) {
        self.recorder.record(p);
    }

    /// Create a replayer from the current recording.
    #[must_use]
    pub fn make_replayer(&self) -> EventReplayer {
        EventReplayer::from_recorder(&self.recorder, self.config.clone())
    }

    /// Replay everything into `callback`.
    pub fn replay_all<F: FnMut(EventPayload)>(&self, callback: F) {
        self.make_replayer().replay_into(callback);
    }

    /// Verify integrity of all recorded events.
    #[must_use]
    pub fn verify_integrity(&self) -> (usize, usize) {
        self.recorder.verify_all()
    }

    /// Serialise to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.recorder.to_bytes()
    }

    /// Event count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.recorder.len()
    }

    /// True when nothing recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.recorder.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_types::{make_function_found, AnalysisEvent};

    fn make_payload(seq: u64, view_id: u64) -> EventPayload {
        let e = AnalysisEvent::FunctionFound(make_function_found(view_id, seq * 0x100, "f"));
        EventPayload::with_default_priority(e, seq)
    }

    #[test]
    fn adv_crc32_deterministic() {
        let v = adv_crc32(b"hello world");
        assert_eq!(v, adv_crc32(b"hello world"));
    }

    #[test]
    fn adv_crc32_sensitivity() {
        assert_ne!(adv_crc32(b"hello"), adv_crc32(b"hellx"));
    }

    #[test]
    fn record_checksum_valid_on_creation() {
        let p = make_payload(1, 1);
        let rec = EventRecord::from_payload(&p);
        assert!(rec.is_intact());
    }

    #[test]
    fn record_checksum_detects_mutation() {
        let p = make_payload(1, 1);
        let mut rec = EventRecord::from_payload(&p);
        rec.json.push_str("__CORRUPT");
        assert!(!rec.is_intact());
    }

    #[test]
    fn recorder_records_and_len() {
        let mut r = EventRecorder::new(100);
        r.record(&make_payload(1, 1));
        r.record(&make_payload(2, 1));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn recorder_eviction_at_capacity() {
        let mut r = EventRecorder::new(3);
        for i in 0..6u64 { r.record(&make_payload(i, 1)); }
        assert_eq!(r.len(), 3);
        assert_eq!(r.stats.total_evicted, 3);
    }

    #[test]
    fn recorder_dedup() {
        let mut r = EventRecorder::new(100);
        r.deduplicate = true;
        let p = make_payload(1, 1);
        r.record(&p);
        r.record(&p);
        assert_eq!(r.len(), 1);
        assert_eq!(r.stats.duplicates_skipped, 1);
    }

    #[test]
    fn recorder_inactive_ignores_records() {
        let mut r = EventRecorder::new(100);
        r.active = false;
        r.record(&make_payload(1, 1));
        assert!(r.is_empty());
    }

    #[test]
    fn binary_round_trip() {
        let mut r = EventRecorder::new(100);
        for i in 0..5u64 { r.record(&make_payload(i, 1)); }
        let bytes = r.to_bytes();
        let loaded = EventRecorder::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.len(), 5);
        assert_eq!(loaded.records()[2].sequence, 2);
    }

    #[test]
    fn binary_bad_magic_returns_error() {
        let bytes = b"BADMAGIC11111111111";
        assert!(EventRecorder::from_bytes(bytes).is_err());
    }

    #[test]
    fn verify_all_clean() {
        let mut r = EventRecorder::new(100);
        for i in 0..4u64 { r.record(&make_payload(i, 1)); }
        let (ok, bad) = r.verify_all();
        assert_eq!(ok, 4);
        assert_eq!(bad, 0);
    }

    #[test]
    fn replayer_collects_all() {
        let mut r = EventRecorder::new(100);
        for i in 0..8u64 { r.record(&make_payload(i, 1)); }
        let mut replay = EventReplayer::from_recorder(&r, ReplayConfig::instant());
        assert_eq!(replay.collect_all().len(), 8);
    }

    #[test]
    fn replayer_max_events_limit() {
        let mut r = EventRecorder::new(100);
        for i in 0..10u64 { r.record(&make_payload(i, 1)); }
        let cfg = ReplayConfig { max_events: 3, ..ReplayConfig::instant() };
        let mut replay = EventReplayer::from_recorder(&r, cfg);
        assert_eq!(replay.collect_all().len(), 3);
    }

    #[test]
    fn replayer_view_filter() {
        let mut r = EventRecorder::new(100);
        for i in 0..4u64 { r.record(&make_payload(i, 1)); }
        for i in 4..8u64 { r.record(&make_payload(i, 2)); }
        let cfg = ReplayConfig { view_id_filter: Some(1), ..ReplayConfig::instant() };
        let mut replay = EventReplayer::from_recorder(&r, cfg);
        assert_eq!(replay.collect_all().len(), 4);
    }

    #[test]
    fn replayer_skips_corrupt() {
        let mut r = EventRecorder::new(100);
        r.record(&make_payload(1, 1));
        let mut records = r.records.clone();
        records[0].json.push_str("BAD");
        let cfg = ReplayConfig { skip_corrupt: true, ..ReplayConfig::instant() };
        let mut replay = EventReplayer::new(records, cfg);
        assert_eq!(replay.collect_all().len(), 0);
        assert_eq!(replay.stats.total_skipped_corrupt, 1);
    }

    #[test]
    fn replayer_seq_range_filter() {
        let mut r = EventRecorder::new(100);
        for i in 0..10u64 { r.record(&make_payload(i, 1)); }
        let cfg = ReplayConfig { seq_range: Some((3, 6)), ..ReplayConfig::instant() };
        let mut replay = EventReplayer::from_recorder(&r, cfg);
        let events = replay.collect_all();
        for e in &events {
            assert!(e.sequence >= 3 && e.sequence <= 6);
        }
    }

    #[test]
    fn replayer_seek_and_progress() {
        let mut r = EventRecorder::new(100);
        for i in 0..10u64 { r.record(&make_payload(i, 1)); }
        let mut replay = EventReplayer::from_recorder(&r, ReplayConfig::instant());
        replay.seek(5);
        assert!((replay.progress_pct() - 50.0).abs() < 1.0);
    }

    #[test]
    fn replayer_reset_clears_stats() {
        let mut r = EventRecorder::new(100);
        for i in 0..5u64 { r.record(&make_payload(i, 1)); }
        let mut replay = EventReplayer::from_recorder(&r, ReplayConfig::instant());
        replay.collect_all();
        replay.reset();
        assert_eq!(replay.position(), 0);
        assert_eq!(replay.stats.total_replayed, 0);
    }

    #[test]
    fn event_filter_by_variant() {
        let mut r = EventRecorder::new(100);
        for i in 0..5u64 { r.record(&make_payload(i, 1)); }
        let mut replay = EventReplayer::from_recorder(&r, ReplayConfig::instant());
        replay.set_filter(EventFilter::by_variant("FunctionFound"));
        assert_eq!(replay.collect_all().len(), 5);
    }

    #[test]
    fn event_filter_not_excludes_all() {
        let mut r = EventRecorder::new(100);
        r.record(&make_payload(1, 1));
        let mut replay = EventReplayer::from_recorder(&r, ReplayConfig::instant());
        replay.set_filter(EventFilter::by_variant("FunctionFound").negate());
        assert_eq!(replay.collect_all().len(), 0);
    }

    #[test]
    fn replay_session_integrity() {
        let mut sess = ReplaySession::new("s1", 100, ReplayConfig::instant());
        for i in 0..5u64 { sess.record(&make_payload(i, 1)); }
        let (ok, bad) = sess.verify_integrity();
        assert_eq!(ok, 5);
        assert_eq!(bad, 0);
    }

    #[test]
    fn delay_between_at_double_speed() {
        let cfg = ReplayConfig { speed: 2.0, ..ReplayConfig::instant() };
        let delay = cfg.delay_between(0, 1_000_000); // 1 second
        assert_eq!(delay, Duration::from_micros(500_000));
    }

    #[test]
    fn delay_between_instant_is_zero() {
        let cfg = ReplayConfig::instant();
        assert_eq!(cfg.delay_between(0, 1_000_000), Duration::ZERO);
    }

    #[test]
    fn count_matching_respects_config() {
        let mut r = EventRecorder::new(100);
        for i in 0..10u64 { r.record(&make_payload(i, 1)); }
        let cfg = ReplayConfig { max_events: 0, seq_range: Some((2, 5)), ..ReplayConfig::instant() };
        let replay = EventReplayer::from_recorder(&r, cfg);
        assert_eq!(replay.count_matching(), 4); // seq 2,3,4,5
    }
}
