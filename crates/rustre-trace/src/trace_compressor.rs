//! Trace compression: delta-encoding, run-length encoding, and dictionary
//! compression for execution traces.
//!
//! Provides [`TraceCompressor`], [`CompressedTrace`], and [`CompressionStats`].

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{TraceEvent, TraceRecord, TraceSession};

// ─── CompressionMethod ────────────────────────────────────────────────────────

/// Algorithm used to compress a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derive(Default)]
pub enum CompressionMethod {
    /// No compression; events stored verbatim.
    #[default]
    None,
    /// Run-length encoding: consecutive identical events are collapsed.
    RunLength,
    /// Delta encoding: only address *deltas* are stored for instruction events.
    Delta,
    /// Dictionary encoding: recurring event patterns are replaced with integer codes.
    Dictionary,
    /// Combined RLE + delta for instruction streams.
    RleDelta,
}


impl std::fmt::Display for CompressionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::RunLength => write!(f, "rle"),
            Self::Delta => write!(f, "delta"),
            Self::Dictionary => write!(f, "dictionary"),
            Self::RleDelta => write!(f, "rle+delta"),
        }
    }
}

// ─── CompressionStats ─────────────────────────────────────────────────────────

/// Statistics from a compression run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompressionStats {
    /// Original number of events.
    pub original_event_count: usize,
    /// Number of events (or blocks) after compression.
    pub compressed_event_count: usize,
    /// Estimated bytes before compression (using a fixed per-event size estimate).
    pub original_bytes_estimate: u64,
    /// Estimated bytes after compression.
    pub compressed_bytes_estimate: u64,
    /// Number of distinct event patterns in the dictionary (dictionary method).
    pub dictionary_entries: usize,
    /// Number of RLE runs created.
    pub rle_runs: usize,
    /// Compression method used.
    pub method: CompressionMethod,
    /// Wall-clock time spent compressing, in microseconds.
    pub elapsed_us: u64,
}

impl CompressionStats {
    /// Compression ratio: original / compressed event count.
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.compressed_event_count == 0 {
            return 0.0;
        }
        self.original_event_count as f64 / self.compressed_event_count as f64
    }

    /// Byte-level compression ratio.
    #[must_use]
    pub fn byte_ratio(&self) -> f64 {
        if self.compressed_bytes_estimate == 0 {
            return 0.0;
        }
        self.original_bytes_estimate as f64 / self.compressed_bytes_estimate as f64
    }

    /// Space saved as a percentage.
    #[must_use]
    pub fn space_saved_pct(&self) -> f64 {
        if self.original_bytes_estimate == 0 {
            return 0.0;
        }
        let saved = self
            .original_bytes_estimate
            .saturating_sub(self.compressed_bytes_estimate);
        (saved as f64 / self.original_bytes_estimate as f64) * 100.0
    }
}

impl std::fmt::Display for CompressionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "method={} ratio={:.2}x space_saved={:.1}%",
            self.method,
            self.compression_ratio(),
            self.space_saved_pct()
        )
    }
}

// ─── RleBlock ─────────────────────────────────────────────────────────────────

/// A run-length-encoded block of identical events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RleBlock {
    /// The representative event (all occurrences in this run are identical).
    pub event: TraceEvent,
    /// Number of consecutive occurrences.
    pub count: u64,
    /// Thread ID of the run.
    pub thread_id: u32,
    /// Sequence number of the first occurrence.
    pub start_seq: u64,
    /// Timestamp (nanoseconds) of the first occurrence.
    pub first_timestamp_ns: u64,
}

impl RleBlock {
    /// Return the average byte cost of this block.
    #[must_use]
    pub const fn cost_bytes(&self) -> u64 {
        // Fixed overhead: seq(8) + thread(4) + ts(8) + count(8) + event_tag(1) + addr(8) = 37
        37
    }

    /// Return the total events represented by this block.
    #[must_use]
    pub const fn event_count(&self) -> u64 {
        self.count
    }
}

// ─── DeltaBlock ───────────────────────────────────────────────────────────────

/// A delta-encoded instruction event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaBlock {
    /// Address delta from the previous instruction (signed).
    pub addr_delta: i64,
    /// Instruction size in bytes.
    pub size: u8,
    /// Thread ID.
    pub thread_id: u32,
    /// Timestamp delta from the previous event (nanoseconds).
    pub time_delta_ns: u64,
    /// Sequence number (absolute).
    pub seq: u64,
}

// ─── DictionaryEntry ──────────────────────────────────────────────────────────

/// An entry in the trace dictionary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DictionaryEntry {
    /// Integer code assigned to this pattern.
    pub code: u32,
    /// The event pattern.
    pub event: TraceEvent,
    /// Number of times this pattern appeared.
    pub frequency: u64,
}

// ─── CompressedTrace ──────────────────────────────────────────────────────────

/// A compressed execution trace, agnostic to the encoding method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedTrace {
    /// Name of the original session.
    pub session_name: String,
    /// Architecture string.
    pub arch: String,
    /// Compression method used.
    pub method: CompressionMethod,
    /// RLE blocks (populated when method includes RLE).
    pub rle_blocks: Vec<RleBlock>,
    /// Delta-encoded instruction blocks (populated when method includes delta).
    pub delta_blocks: Vec<DeltaBlock>,
    /// Dictionary used (populated when method is `Dictionary`).
    pub dictionary: Vec<DictionaryEntry>,
    /// Dictionary-encoded event stream (event code per record).
    pub dict_stream: Vec<u32>,
    /// Non-instruction events stored verbatim (for delta method).
    pub verbatim_events: Vec<TraceRecord>,
    /// Statistics from the compression run.
    pub stats: CompressionStats,
}

impl CompressedTrace {
    /// Return the compression ratio reported in the stats.
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        self.stats.compression_ratio()
    }

    /// Return the method used.
    #[must_use]
    pub const fn method(&self) -> CompressionMethod {
        self.method
    }

    /// Serialize to JSON bytes.
    ///
    /// # Errors
    /// Returns `serde_json::Error` on serialization failure.
    pub fn to_json(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Deserialize from JSON bytes.
    ///
    /// # Errors
    /// Returns `serde_json::Error` on deserialization failure.
    pub fn from_json(data: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(data)
    }
}

// ─── TraceCompressor ──────────────────────────────────────────────────────────

/// Compresses execution traces using configurable algorithms.
///
/// # Example
/// ```
/// # use rustre_trace::trace_compressor::{TraceCompressor, CompressionMethod};
/// # use rustre_trace::TraceSession;
/// let session = TraceSession::new("test", "x86_64");
/// let compressed = TraceCompressor::compress(&session, CompressionMethod::RunLength);
/// println!("{}", compressed.stats);
/// ```
pub struct TraceCompressor;

impl TraceCompressor {
    /// Bytes-per-event cost estimate for uncompressed storage.
    const BYTES_PER_EVENT: u64 = 64;

    /// Compress `session` using the given `method`.
    #[must_use]
    pub fn compress(session: &TraceSession, method: CompressionMethod) -> CompressedTrace {
        let start = std::time::Instant::now();
        let original_count = session.records.len();

        let compressed = match method {
            CompressionMethod::None => Self::compress_none(session),
            CompressionMethod::RunLength => Self::compress_rle(session),
            CompressionMethod::Delta => Self::compress_delta(session),
            CompressionMethod::Dictionary => Self::compress_dictionary(session),
            CompressionMethod::RleDelta => Self::compress_rle_delta(session),
        };

        let elapsed_us = start.elapsed().as_micros() as u64;

        let compressed_count = match method {
            CompressionMethod::None => original_count,
            CompressionMethod::RunLength | CompressionMethod::RleDelta => compressed.rle_blocks.len(),
            CompressionMethod::Delta => {
                compressed.delta_blocks.len() + compressed.verbatim_events.len()
            }
            CompressionMethod::Dictionary => compressed.dict_stream.len(),
            };

        let original_bytes = original_count as u64 * Self::BYTES_PER_EVENT;
        let compressed_bytes = Self::estimate_compressed_bytes(&compressed, method);

        let mut result = compressed;
        result.stats = CompressionStats {
            original_event_count: original_count,
            compressed_event_count: compressed_count,
            original_bytes_estimate: original_bytes,
            compressed_bytes_estimate: compressed_bytes,
            dictionary_entries: result.dictionary.len(),
            rle_runs: result.rle_blocks.len(),
            method,
            elapsed_us,
        };

        result
    }

    /// Estimate the byte cost of the compressed representation.
    fn estimate_compressed_bytes(ct: &CompressedTrace, method: CompressionMethod) -> u64 {
        match method {
            CompressionMethod::None => {
                ct.verbatim_events.len() as u64 * Self::BYTES_PER_EVENT
            }
            CompressionMethod::RunLength => ct.rle_blocks.iter().map(RleBlock::cost_bytes).sum(),
            CompressionMethod::Delta => {
                // Each delta block costs ~17 bytes; verbatim events cost full price.
                ct.delta_blocks.len() as u64 * 17
                    + ct.verbatim_events.len() as u64 * Self::BYTES_PER_EVENT
            }
            CompressionMethod::Dictionary => {
                // Dictionary header + 4 bytes per code.
                ct.dictionary.len() as u64 * Self::BYTES_PER_EVENT
                    + ct.dict_stream.len() as u64 * 4
            }
            CompressionMethod::RleDelta => {
                ct.rle_blocks.iter().map(RleBlock::cost_bytes).sum::<u64>()
                    + ct.delta_blocks.len() as u64 * 17
            }
        }
    }

    /// Identity compression — stores events verbatim in `verbatim_events`.
    fn compress_none(session: &TraceSession) -> CompressedTrace {
        CompressedTrace {
            session_name: session.name.clone(),
            arch: session.arch.clone(),
            method: CompressionMethod::None,
            rle_blocks: Vec::new(),
            delta_blocks: Vec::new(),
            dictionary: Vec::new(),
            dict_stream: Vec::new(),
            verbatim_events: session.records.clone(),
            stats: CompressionStats::default(),
        }
    }

    /// Run-length encoding: collapses consecutive identical events.
    fn compress_rle(session: &TraceSession) -> CompressedTrace {
        let mut blocks: Vec<RleBlock> = Vec::new();

        for rec in &session.records {
            if let Some(last) = blocks.last_mut()
                && last.event == rec.event && last.thread_id == rec.thread_id {
                    last.count += 1;
                    continue;
                }
            blocks.push(RleBlock {
                event: rec.event.clone(),
                count: 1,
                thread_id: rec.thread_id,
                start_seq: rec.seq,
                first_timestamp_ns: rec.timestamp_ns,
            });
        }

        CompressedTrace {
            session_name: session.name.clone(),
            arch: session.arch.clone(),
            method: CompressionMethod::RunLength,
            rle_blocks: blocks,
            delta_blocks: Vec::new(),
            dictionary: Vec::new(),
            dict_stream: Vec::new(),
            verbatim_events: Vec::new(),
            stats: CompressionStats::default(),
        }
    }

    /// Delta encoding for instruction events; other events stored verbatim.
    fn compress_delta(session: &TraceSession) -> CompressedTrace {
        let mut delta_blocks: Vec<DeltaBlock> = Vec::new();
        let mut verbatim: Vec<TraceRecord> = Vec::new();
        let mut prev_addr: u64 = 0;
        let mut prev_ts: u64 = 0;

        for rec in &session.records {
            match rec.event {
                TraceEvent::Instruction { addr, size } => {
                    let addr_delta = addr as i64 - prev_addr as i64;
                    let time_delta = rec.timestamp_ns.saturating_sub(prev_ts);
                    delta_blocks.push(DeltaBlock {
                        addr_delta,
                        size,
                        thread_id: rec.thread_id,
                        time_delta_ns: time_delta,
                        seq: rec.seq,
                    });
                    prev_addr = addr;
                    prev_ts = rec.timestamp_ns;
                }
                _ => {
                    verbatim.push(rec.clone());
                }
            }
        }

        CompressedTrace {
            session_name: session.name.clone(),
            arch: session.arch.clone(),
            method: CompressionMethod::Delta,
            rle_blocks: Vec::new(),
            delta_blocks,
            dictionary: Vec::new(),
            dict_stream: Vec::new(),
            verbatim_events: verbatim,
            stats: CompressionStats::default(),
        }
    }

    /// Dictionary encoding: build a frequency table, assign integer codes, encode stream.
    fn compress_dictionary(session: &TraceSession) -> CompressedTrace {
        // Build frequency map using the event type name + primary address as key.
        let mut freq_map: HashMap<(String, u64), (TraceEvent, u64)> = HashMap::new();

        for rec in &session.records {
            let key_addr = crate::event_primary_addr(&rec.event);
            let key_type = crate::event_type_name(&rec.event).to_string();
            let entry = freq_map
                .entry((key_type, key_addr))
                .or_insert_with(|| (rec.event.clone(), 0));
            entry.1 += 1;
        }

        // Sort by frequency descending, assign codes.
        let mut sorted: Vec<((String, u64), (TraceEvent, u64))> = freq_map.into_iter().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1.1));

        let mut code_map: HashMap<(String, u64), u32> = HashMap::new();
        let mut dictionary: Vec<DictionaryEntry> = Vec::with_capacity(sorted.len());

        for (i, ((type_name, addr), (event, freq))) in sorted.into_iter().enumerate() {
            let code = i as u32;
            code_map.insert((type_name, addr), code);
            dictionary.push(DictionaryEntry {
                code,
                event,
                frequency: freq,
            });
        }

        // Encode stream.
        let dict_stream: Vec<u32> = session
            .records
            .iter()
            .map(|rec| {
                let key_addr =
                    crate::event_primary_addr(&rec.event);
                let key_type =
                    crate::event_type_name(&rec.event).to_string();
                *code_map.get(&(key_type, key_addr)).unwrap_or(&u32::MAX)
            })
            .collect();

        CompressedTrace {
            session_name: session.name.clone(),
            arch: session.arch.clone(),
            method: CompressionMethod::Dictionary,
            rle_blocks: Vec::new(),
            delta_blocks: Vec::new(),
            dictionary,
            dict_stream,
            verbatim_events: Vec::new(),
            stats: CompressionStats::default(),
        }
    }

    /// Combined RLE + delta: instruction runs are delta-encoded; other events are RLE-compressed.
    fn compress_rle_delta(session: &TraceSession) -> CompressedTrace {
        let delta_ct = Self::compress_delta(session);
        // RLE-compress the delta blocks' address deltas by grouping same-delta runs.
        let mut rle_blocks: Vec<RleBlock> = Vec::new();
        for db in &delta_ct.delta_blocks {
            // Use the Instruction event with the reconstructed address as a proxy.
            let proxy_event = TraceEvent::Instruction {
                addr: db.addr_delta.unsigned_abs(),
                size: db.size,
            };
            if let Some(last) = rle_blocks.last_mut()
                && last.event == proxy_event && last.thread_id == db.thread_id {
                    last.count += 1;
                    continue;
                }
            rle_blocks.push(RleBlock {
                event: proxy_event,
                count: 1,
                thread_id: db.thread_id,
                start_seq: db.seq,
                first_timestamp_ns: db.time_delta_ns,
            });
        }

        CompressedTrace {
            session_name: session.name.clone(),
            arch: session.arch.clone(),
            method: CompressionMethod::RleDelta,
            rle_blocks,
            delta_blocks: delta_ct.delta_blocks,
            dictionary: Vec::new(),
            dict_stream: Vec::new(),
            verbatim_events: delta_ct.verbatim_events,
            stats: CompressionStats::default(),
        }
    }

    /// Decompress a [`CompressedTrace`] back to a [`TraceSession`].
    ///
    /// Only `RunLength` and `None` decompression are fully reversible with the
    /// current encoding.  `Delta` and `Dictionary` produce best-effort sessions.
    #[must_use]
    pub fn decompress(ct: &CompressedTrace) -> TraceSession {
        let mut session = TraceSession::new(&ct.session_name, &ct.arch);

        match ct.method {
            CompressionMethod::None => {
                for rec in &ct.verbatim_events {
                    session.push(rec.event.clone(), rec.thread_id, rec.timestamp_ns);
                }
            }
            CompressionMethod::RunLength => {
                // Cap the per-block repeat count to defend against a malformed
                // or adversarial CompressedTrace (e.g. loaded from untrusted
                // JSON) that encodes an astronomical count.
                const MAX_BLOCK_COUNT: u64 = 100_000_000;
                for block in &ct.rle_blocks {
                    let count = block.count.min(MAX_BLOCK_COUNT);
                    for i in 0..count {
                        let ts = block.first_timestamp_ns + i * 100;
                        session.push(block.event.clone(), block.thread_id, ts);
                    }
                }
            }
            CompressionMethod::Delta => {
                let mut addr: u64 = 0;
                let mut ts: u64 = 0;
                for db in &ct.delta_blocks {
                    addr = (addr as i64).wrapping_add(db.addr_delta) as u64;
                    ts = ts.wrapping_add(db.time_delta_ns);
                    session.push(
                        TraceEvent::Instruction {
                            addr,
                            size: db.size,
                        },
                        db.thread_id,
                        ts,
                    );
                }
                for rec in &ct.verbatim_events {
                    session.push(rec.event.clone(), rec.thread_id, rec.timestamp_ns);
                }
            }
            CompressionMethod::Dictionary => {
                // Reconstruct events from dictionary codes.
                for &code in &ct.dict_stream {
                    if let Some(entry) = ct.dictionary.iter().find(|e| e.code == code) {
                        session.push(entry.event.clone(), 0, 0);
                    }
                }
            }
            CompressionMethod::RleDelta => {
                // Restore from delta blocks (verbatim).
                let mut addr: u64 = 0;
                let mut ts: u64 = 0;
                for db in &ct.delta_blocks {
                    addr = (addr as i64).wrapping_add(db.addr_delta) as u64;
                    ts = ts.wrapping_add(db.time_delta_ns);
                    session.push(
                        TraceEvent::Instruction {
                            addr,
                            size: db.size,
                        },
                        db.thread_id,
                        ts,
                    );
                }
                for rec in &ct.verbatim_events {
                    session.push(rec.event.clone(), rec.thread_id, rec.timestamp_ns);
                }
            }
        }

        session
    }

    /// Choose the best compression method by trying all and picking the smallest.
    #[must_use]
    pub fn compress_best(session: &TraceSession) -> CompressedTrace {
        let methods = [
            CompressionMethod::RunLength,
            CompressionMethod::Delta,
            CompressionMethod::Dictionary,
            CompressionMethod::RleDelta,
        ];

        let mut best: Option<CompressedTrace> = None;
        let mut best_bytes = u64::MAX;

        for method in methods {
            let ct = Self::compress(session, method);
            if ct.stats.compressed_bytes_estimate < best_bytes {
                best_bytes = ct.stats.compressed_bytes_estimate;
                best = Some(ct);
            }
        }

        best.unwrap_or_else(|| Self::compress(session, CompressionMethod::None))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TraceEvent, TraceSession};

    fn make_session(n: usize) -> TraceSession {
        let mut s = TraceSession::new("test", "x86_64");
        for i in 0..n {
            s.push(
                TraceEvent::Instruction {
                    addr: 0x1000 + (i as u64 * 4),
                    size: 4,
                },
                1,
                i as u64 * 100,
            );
        }
        s
    }

    fn make_repetitive_session(n: usize) -> TraceSession {
        let mut s = TraceSession::new("rep", "x86_64");
        for _ in 0..n {
            s.push(
                TraceEvent::Instruction {
                    addr: 0x1000,
                    size: 4,
                },
                1,
                0,
            );
        }
        s
    }

    #[test]
    fn test_rle_compression_ratio() {
        let session = make_repetitive_session(1000);
        let ct = TraceCompressor::compress(&session, CompressionMethod::RunLength);
        assert_eq!(ct.rle_blocks.len(), 1);
        assert_eq!(ct.rle_blocks[0].count, 1000);
        assert!(ct.compression_ratio() > 100.0);
    }

    #[test]
    fn test_rle_roundtrip() {
        let session = make_repetitive_session(50);
        let ct = TraceCompressor::compress(&session, CompressionMethod::RunLength);
        let restored = TraceCompressor::decompress(&ct);
        assert_eq!(restored.record_count(), 50);
    }

    #[test]
    fn test_delta_compression_instruction_only() {
        let session = make_session(100);
        let ct = TraceCompressor::compress(&session, CompressionMethod::Delta);
        assert_eq!(ct.delta_blocks.len(), 100);
        assert!(ct.verbatim_events.is_empty());
    }

    #[test]
    fn test_delta_addr_deltas() {
        let session = make_session(4);
        let ct = TraceCompressor::compress(&session, CompressionMethod::Delta);
        // First delta = 0x1000 - 0 = 0x1000
        assert_eq!(ct.delta_blocks[0].addr_delta, 0x1000);
        // Subsequent deltas = 4
        assert_eq!(ct.delta_blocks[1].addr_delta, 4);
    }

    #[test]
    fn test_dictionary_compression_unique_events() {
        let session = make_session(20);
        let ct = TraceCompressor::compress(&session, CompressionMethod::Dictionary);
        assert_eq!(ct.dict_stream.len(), 20);
        assert!(!ct.dictionary.is_empty());
    }

    #[test]
    fn test_none_compression_identity() {
        let session = make_session(10);
        let ct = TraceCompressor::compress(&session, CompressionMethod::None);
        assert_eq!(ct.verbatim_events.len(), 10);
        let restored = TraceCompressor::decompress(&ct);
        assert_eq!(restored.record_count(), 10);
    }

    #[test]
    fn test_compress_best_returns_result() {
        let session = make_repetitive_session(200);
        let ct = TraceCompressor::compress_best(&session);
        assert!(ct.stats.compressed_event_count > 0);
    }

    #[test]
    fn test_stats_space_saved() {
        let session = make_repetitive_session(500);
        let ct = TraceCompressor::compress(&session, CompressionMethod::RunLength);
        assert!(ct.stats.space_saved_pct() > 90.0);
    }

    #[test]
    fn test_stats_display() {
        let session = make_session(10);
        let ct = TraceCompressor::compress(&session, CompressionMethod::Delta);
        let s = ct.stats.to_string();
        assert!(s.contains("delta"));
    }

    #[test]
    fn test_delta_roundtrip_addresses() {
        let session = make_session(8);
        let ct = TraceCompressor::compress(&session, CompressionMethod::Delta);
        let restored = TraceCompressor::decompress(&ct);
        for (i, rec) in restored.records.iter().enumerate() {
            if let TraceEvent::Instruction { addr, .. } = rec.event {
                assert_eq!(addr, 0x1000 + i as u64 * 4);
            }
        }
    }

    #[test]
    fn test_rle_delta_contains_both() {
        let session = make_session(20);
        let ct = TraceCompressor::compress(&session, CompressionMethod::RleDelta);
        // delta_blocks are always produced from the delta phase
        assert!(!ct.delta_blocks.is_empty());
    }

    #[test]
    fn test_json_roundtrip() {
        let session = make_session(5);
        let ct = TraceCompressor::compress(&session, CompressionMethod::RunLength);
        let json = ct.to_json().unwrap();
        let restored = CompressedTrace::from_json(&json).unwrap();
        assert_eq!(restored.method, CompressionMethod::RunLength);
        assert_eq!(restored.rle_blocks.len(), ct.rle_blocks.len());
    }
}
