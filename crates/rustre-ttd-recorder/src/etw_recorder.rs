//! ETW-based trace capture for the TTD recorder.
//!
//! Models a Windows ETW (Event Tracing for Windows) recording session that
//! captures trace data into in-memory buffers with optional background
//! compression.  Actual ETW kernel calls are abstracted behind the trait
//! boundary so the module compiles and tests on all platforms.

pub use std::collections::VecDeque;
pub use std::sync::{Arc, Mutex};
pub use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::CompressionLevel;
pub use crate::TtdRecordError;

const fn usize_to_f64_lossy(v: usize) -> f64 {
    v as f64
}

const fn u64_to_f64_lossy(v: u64) -> f64 {
    v as f64
}

// ─── EtwProviderGuid ─────────────────────────────────────────────────────────

/// 128-bit GUID for an ETW provider (stored as four u32 words).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EtwProviderGuid {
    pub data: [u32; 4],
}

impl EtwProviderGuid {
    #[must_use]
    pub const fn new(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self { data: [a, b, c, d] }
    }

    /// NT Kernel Logger provider GUID.
    #[must_use]
    pub const fn nt_kernel_logger() -> Self {
        Self::new(0x9e81_4aad, 0x3204_11d2, 0x8a88_0014, 0x22_d0_53_88)
    }
}

impl std::fmt::Display for EtwProviderGuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{{:08x}-{:08x}-{:08x}-{:08x}}}",
            self.data[0], self.data[1], self.data[2], self.data[3]
        )
    }
}

// ─── EtwProvider ─────────────────────────────────────────────────────────────

/// An ETW provider to be enabled in the recording session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwProvider {
    /// Provider GUID.
    pub guid: EtwProviderGuid,
    /// Human-readable name.
    pub name: String,
    /// Verbosity level (0 = silent, 5 = verbose).
    pub level: u8,
    /// Keywords bitmask.
    pub keywords: u64,
    /// Whether this provider is enabled.
    pub enabled: bool,
}

impl EtwProvider {
    #[must_use]
    pub fn new(guid: EtwProviderGuid, name: impl Into<String>, level: u8, keywords: u64) -> Self {
        Self {
            guid,
            name: name.into(),
            level,
            keywords,
            enabled: true,
        }
    }
}

// ─── TraceBuffer ─────────────────────────────────────────────────────────────

/// A fixed-size in-memory trace buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBuffer {
    /// Maximum byte capacity.
    pub capacity: usize,
    /// Current contents.
    data: Vec<u8>,
    /// Whether this buffer has been flushed.
    pub flushed: bool,
    /// Buffer sequence number.
    pub seq: u64,
}

impl TraceBuffer {
    #[must_use]
    pub fn new(capacity: usize, seq: u64) -> Self {
        Self {
            capacity,
            data: Vec::with_capacity(capacity),
            flushed: false,
            seq,
        }
    }

    /// Append bytes to the buffer.  Returns `false` if the buffer would overflow.
    pub fn append(&mut self, bytes: &[u8]) -> bool {
        if self.data.len() + bytes.len() > self.capacity {
            return false;
        }
        self.data.extend_from_slice(bytes);
        true
    }

    /// Current used bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Fraction of capacity used.
    #[must_use]
    pub fn fill_ratio(&self) -> f64 {
        if self.capacity == 0 {
            0.0
        } else {
            usize_to_f64_lossy(self.data.len()) / usize_to_f64_lossy(self.capacity)
        }
    }

    /// Raw contents.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.data.clear();
        self.flushed = false;
    }
}

// ─── BufferFlush ─────────────────────────────────────────────────────────────

/// A record of a single buffer flush operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferFlush {
    /// Sequence number of the flushed buffer.
    pub buffer_seq: u64,
    /// Bytes flushed.
    pub bytes: usize,
    /// Timestamp (nanoseconds from session start).
    pub timestamp_ns: u64,
    /// Whether the flush was triggered automatically (threshold) or manually.
    pub automatic: bool,
}

// ─── CompressionWorker ────────────────────────────────────────────────────────

/// Simulates a background compression worker that drains a queue of raw buffers
/// and produces compressed output.
#[derive(Debug, Default)]
pub struct CompressionWorker {
    level: CompressionLevel,
    /// Total bytes accepted.
    total_input_bytes: u64,
    /// Total bytes produced after (simulated) compression.
    total_output_bytes: u64,
    /// Number of buffers processed.
    buffers_processed: u64,
}

impl CompressionWorker {
    #[must_use]
    pub fn new(level: CompressionLevel) -> Self {
        Self {
            level,
            ..Default::default()
        }
    }

    /// Submit a raw buffer for compression.  Returns the compressed size.
    pub fn submit(&mut self, data: &[u8]) -> usize {
        self.total_input_bytes += u64::try_from(data.len()).unwrap_or(u64::MAX);
        self.buffers_processed += 1;
        // Simulate compression ratios.
        let ratio: f64 = match self.level {
            CompressionLevel::None => 1.0,
            CompressionLevel::Fast => 0.75,
            CompressionLevel::Default => 0.60,
            CompressionLevel::Best => 0.45,
        };
        let out = (usize_to_f64_lossy(data.len()) * ratio).ceil() as usize;
        self.total_output_bytes += u64::try_from(out).unwrap_or(u64::MAX);
        out
    }

    /// Compression ratio achieved so far.
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.total_input_bytes == 0 {
            1.0
        } else {
            u64_to_f64_lossy(self.total_output_bytes) / u64_to_f64_lossy(self.total_input_bytes)
        }
    }

    /// Buffers processed.
    #[must_use]
    pub const fn buffers_processed(&self) -> u64 {
        self.buffers_processed
    }

    /// Total input bytes.
    #[must_use]
    pub const fn total_input_bytes(&self) -> u64 {
        self.total_input_bytes
    }
}

// ─── EtwSessionConfig ─────────────────────────────────────────────────────────

/// Configuration for an [`EtwSession`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwSessionConfig {
    /// Session name.
    pub name: String,
    /// Buffer size in KB.
    pub buffer_size_kb: u32,
    /// Minimum number of buffers to pre-allocate.
    pub min_buffers: u32,
    /// Maximum number of buffers.
    pub max_buffers: u32,
    /// Compression level for output.
    pub compression: CompressionLevel,
    /// Flush threshold (bytes) — triggers automatic flush.
    pub flush_threshold_bytes: usize,
}

impl Default for EtwSessionConfig {
    fn default() -> Self {
        Self {
            name: "RustRE-ETW".into(),
            buffer_size_kb: 64,
            min_buffers: 4,
            max_buffers: 64,
            compression: CompressionLevel::Default,
            flush_threshold_bytes: 48 * 1024,
        }
    }
}

// ─── EtwSession ──────────────────────────────────────────────────────────────

/// An active ETW recording session.
#[derive(Debug)]
pub struct EtwSession {
    pub config: EtwSessionConfig,
    providers: Vec<EtwProvider>,
    /// Active buffer.
    buffer: TraceBuffer,
    /// Flush log.
    flush_log: Vec<BufferFlush>,
    /// Compression worker.
    compression: CompressionWorker,
    next_buffer_seq: u64,
    next_flush_ts: u64,
    /// Whether the session is running.
    pub running: bool,
}

impl EtwSession {
    #[must_use]
    pub fn new(config: EtwSessionConfig) -> Self {
        let cap = usize::try_from(config.buffer_size_kb).unwrap_or(usize::MAX) * 1024;
        let comp = CompressionWorker::new(config.compression);
        Self {
            buffer: TraceBuffer::new(cap, 0),
            config,
            providers: Vec::new(),
            flush_log: Vec::new(),
            compression: comp,
            next_buffer_seq: 1,
            next_flush_ts: 0,
            running: false,
        }
    }

    /// Start the session.
    pub const fn start(&mut self) {
        self.running = true;
    }

    /// Stop the session.
    pub fn stop(&mut self) {
        if self.running {
            self.flush_internal(false);
        }
        self.running = false;
    }

    /// Add an ETW provider.
    pub fn add_provider(&mut self, p: EtwProvider) {
        self.providers.push(p);
    }

    /// Remove a provider by GUID.
    pub fn remove_provider(&mut self, guid: &EtwProviderGuid) {
        self.providers.retain(|p| &p.guid != guid);
    }

    /// Ingest raw trace bytes.  Returns `true` if the bytes were accepted.
    pub fn ingest(&mut self, bytes: &[u8]) -> bool {
        if !self.running {
            return false;
        }
        if !self.buffer.append(bytes) {
            self.flush_internal(true);
            if !self.buffer.append(bytes) {
                return false;
            }
        }
        if self.buffer.len() >= self.config.flush_threshold_bytes {
            self.flush_internal(true);
        }
        true
    }

    fn flush_internal(&mut self, automatic: bool) {
        let ts = self.next_flush_ts;
        self.next_flush_ts += 1;
        let flush = BufferFlush {
            buffer_seq: self.buffer.seq,
            bytes: self.buffer.len(),
            timestamp_ns: ts,
            automatic,
        };
        self.compression.submit(self.buffer.data());
        self.buffer.clear();
        self.buffer.seq = self.next_buffer_seq;
        self.next_buffer_seq += 1;
        self.buffer.flushed = false;
        self.flush_log.push(flush);
    }

    /// Manually flush the current buffer.
    pub fn flush(&mut self) {
        self.flush_internal(false);
    }

    /// Number of flush operations.
    #[must_use]
    pub const fn flush_count(&self) -> usize {
        self.flush_log.len()
    }

    /// Compression statistics.
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        self.compression.ratio()
    }

    /// Number of providers registered.
    #[must_use]
    pub const fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Flush log.
    #[must_use]
    pub fn flush_log(&self) -> &[BufferFlush] {
        &self.flush_log
    }
}

// ─── EtwRecorder ─────────────────────────────────────────────────────────────

/// High-level ETW recorder that owns one or more sessions.
#[derive(Debug, Default)]
pub struct EtwRecorder {
    sessions: std::collections::HashMap<String, EtwSession>,
}

impl EtwRecorder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create and start a new named session.
    ///
    /// # Panics
    ///
    /// Panics if the session name key cannot be found immediately after insertion
    /// (should never happen in practice).
    pub fn create_session(&mut self, config: EtwSessionConfig) -> &str {
        let name = config.name.clone();
        let mut sess = EtwSession::new(config);
        sess.start();
        self.sessions.insert(name.clone(), sess);
        // Return a str slice — stable across insert because we own the map.
        self.sessions
            .keys()
            .find(|k| *k == &name)
            .map_or("", String::as_str)
    }

    /// Stop and remove a session.
    #[must_use]
    pub fn stop_session(&mut self, name: &str) -> bool {
        if let Some(sess) = self.sessions.get_mut(name) {
            sess.stop();
            true
        } else {
            false
        }
    }

    /// Get an immutable reference to a session.
    #[must_use]
    pub fn session(&self, name: &str) -> Option<&EtwSession> {
        self.sessions.get(name)
    }

    /// Number of sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Ingest bytes into a named session.
    pub fn ingest(&mut self, session_name: &str, bytes: &[u8]) -> bool {
        self.sessions
            .get_mut(session_name)
            .is_some_and(|s| s.ingest(bytes))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- EtwProviderGuid ---

    #[test]
    fn guid_display() {
        let g = EtwProviderGuid::nt_kernel_logger();
        let s = g.to_string();
        assert!(s.starts_with('{'));
    }

    #[test]
    fn guid_equality() {
        assert_eq!(
            EtwProviderGuid::nt_kernel_logger(),
            EtwProviderGuid::nt_kernel_logger()
        );
    }

    // --- TraceBuffer ---

    #[test]
    fn trace_buffer_append_within_capacity() {
        let mut buf = TraceBuffer::new(100, 0);
        assert!(buf.append(b"hello"));
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn trace_buffer_overflow_rejected() {
        let mut buf = TraceBuffer::new(4, 0);
        assert!(!buf.append(b"toolong"));
    }

    #[test]
    fn trace_buffer_fill_ratio() {
        let mut buf = TraceBuffer::new(100, 0);
        buf.append(b"12345");
        assert!((buf.fill_ratio() - 0.05).abs() < 1e-9);
    }

    #[test]
    fn trace_buffer_clear() {
        let mut buf = TraceBuffer::new(100, 0);
        buf.append(b"data");
        buf.clear();
        assert!(buf.is_empty());
    }

    // --- CompressionWorker ---

    #[test]
    fn compression_worker_none_ratio_one() {
        let mut w = CompressionWorker::new(CompressionLevel::None);
        w.submit(b"1234567890");
        assert!((w.ratio() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn compression_worker_best_ratio_below_half() {
        let mut w = CompressionWorker::new(CompressionLevel::Best);
        w.submit(&vec![0u8; 1000]);
        assert!(w.ratio() < 0.5);
    }

    #[test]
    fn compression_worker_buffers_processed() {
        let mut w = CompressionWorker::new(CompressionLevel::Default);
        w.submit(b"a");
        w.submit(b"b");
        assert_eq!(w.buffers_processed(), 2);
    }

    // --- EtwSession ---

    #[test]
    fn session_start_stop() {
        let mut sess = EtwSession::new(EtwSessionConfig::default());
        assert!(!sess.running);
        sess.start();
        assert!(sess.running);
        sess.stop();
        assert!(!sess.running);
    }

    #[test]
    fn session_ingest_not_started_rejected() {
        let mut sess = EtwSession::new(EtwSessionConfig::default());
        assert!(!sess.ingest(b"data"));
    }

    #[test]
    fn session_ingest_accepted() {
        let mut sess = EtwSession::new(EtwSessionConfig::default());
        sess.start();
        assert!(sess.ingest(b"data"));
    }

    #[test]
    fn session_auto_flush_on_threshold() {
        let cfg = EtwSessionConfig {
            buffer_size_kb: 1, // 1 KB buffer
            flush_threshold_bytes: 512,
            ..EtwSessionConfig::default()
        };
        let mut sess = EtwSession::new(cfg);
        sess.start();
        // Fill past the threshold
        sess.ingest(&vec![0u8; 600]);
        assert!(sess.flush_count() >= 1);
    }

    #[test]
    fn session_manual_flush() {
        let mut sess = EtwSession::new(EtwSessionConfig::default());
        sess.start();
        sess.ingest(b"hello");
        sess.flush();
        assert_eq!(sess.flush_count(), 1);
    }

    #[test]
    fn session_add_remove_provider() {
        let mut sess = EtwSession::new(EtwSessionConfig::default());
        let guid = EtwProviderGuid::nt_kernel_logger();
        sess.add_provider(EtwProvider::new(guid, "NtKernel", 4, 0xFF));
        assert_eq!(sess.provider_count(), 1);
        sess.remove_provider(&guid);
        assert_eq!(sess.provider_count(), 0);
    }

    #[test]
    fn session_compression_ratio_default_below_one() {
        let mut sess = EtwSession::new(EtwSessionConfig::default());
        sess.start();
        sess.ingest(&vec![1u8; 512]);
        sess.flush();
        assert!(sess.compression_ratio() <= 1.0);
    }

    // --- EtwRecorder ---

    #[test]
    fn recorder_create_session() {
        let mut rec = EtwRecorder::new();
        let cfg = EtwSessionConfig {
            name: "test".into(),
            ..EtwSessionConfig::default()
        };
        rec.create_session(cfg);
        assert_eq!(rec.session_count(), 1);
        assert!(rec.session("test").is_some());
    }

    #[test]
    fn recorder_stop_session() {
        let mut rec = EtwRecorder::new();
        let cfg = EtwSessionConfig {
            name: "s1".into(),
            ..EtwSessionConfig::default()
        };
        rec.create_session(cfg);
        assert!(rec.stop_session("s1"));
        assert!(!rec.session("s1").unwrap().running);
    }

    #[test]
    fn recorder_ingest_into_session() {
        let mut rec = EtwRecorder::new();
        let cfg = EtwSessionConfig {
            name: "s1".into(),
            ..EtwSessionConfig::default()
        };
        rec.create_session(cfg);
        assert!(rec.ingest("s1", b"trace_data"));
    }

    #[test]
    fn recorder_ingest_unknown_session_false() {
        let mut rec = EtwRecorder::new();
        assert!(!rec.ingest("missing", b"data"));
    }

    #[test]
    fn recorder_stop_unknown_session_false() {
        let mut rec = EtwRecorder::new();
        assert!(!rec.stop_session("does_not_exist"));
    }

    #[test]
    fn etw_provider_enabled_by_default() {
        let p = EtwProvider::new(EtwProviderGuid::nt_kernel_logger(), "NTK", 4, 0);
        assert!(p.enabled);
    }
}
