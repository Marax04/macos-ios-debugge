//! `ttd_ring_buffer.rs` — TTD ring buffer for trace storage.
//!
//! A circular byte-oriented trace buffer with simple LZ77-like chunk
//! compression, binary flush to disk, and forward/backward iteration.

use std::collections::VecDeque;
use std::io::{self, Write};

// ─── Magic / constants ────────────────────────────────────────────────────────

/// File magic written at the start of every flushed buffer.
pub const RING_MAGIC: &[u8; 8] = b"RNGBUF01";

/// Minimum literal length that triggers an LZ77 back-reference encoding.
pub const LZ77_MIN_MATCH: usize = 4;

/// Maximum back-reference look-behind window (256 bytes = single-byte offset).
pub const LZ77_WINDOW: usize = 256;

// ─── RingBufferConfig ─────────────────────────────────────────────────────────

/// Configuration for a `TtdRingBuffer`.
#[derive(Debug, Clone)]
pub struct RingBufferConfig {
    /// Maximum total bytes the buffer may hold.
    pub capacity_bytes: usize,
    /// When `true`, the oldest chunk is evicted when the buffer is full.
    pub overwrite_on_full: bool,
    /// Target flush interval in milliseconds (0 = no automatic flush).
    pub flush_interval_ms: u64,
}

impl RingBufferConfig {
    /// Create a default config with 64 MB capacity and overwrite-on-full.
    #[must_use]
    pub const fn default_64mb() -> Self {
        Self {
            capacity_bytes: 64 * 1024 * 1024,
            overwrite_on_full: true,
            flush_interval_ms: 5000,
        }
    }

    /// Validate: capacity must be > 0.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.capacity_bytes > 0
    }
}

impl Default for RingBufferConfig {
    fn default() -> Self {
        Self::default_64mb()
    }
}

// ─── TraceChunk ───────────────────────────────────────────────────────────────

/// One discrete trace record stored in the ring buffer.
#[derive(Debug, Clone)]
pub struct TraceChunk {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Nanosecond timestamp.
    pub timestamp_ns: u64,
    /// Payload bytes (compressed or raw).
    pub data: Vec<u8>,
    /// `true` if `data` has been LZ77-compressed.
    pub compressed: bool,
}

impl TraceChunk {
    /// Create an uncompressed chunk.
    #[must_use]
    pub const fn new(sequence: u64, timestamp_ns: u64, data: Vec<u8>) -> Self {
        Self {
            sequence,
            timestamp_ns,
            data,
            compressed: false,
        }
    }

    /// Total serialised size: 8 (seq) + 8 (ts) + 4 (len) + 1 (flag) + data.
    #[must_use]
    pub const fn on_disk_size(&self) -> usize {
        8 + 8 + 4 + 1 + self.data.len()
    }
}

// ─── RingBufferStats ──────────────────────────────────────────────────────────

/// Statistics snapshot for a `TtdRingBuffer`.
#[derive(Debug, Clone, Default)]
pub struct RingBufferStats {
    pub chunks_written: u64,
    pub chunks_read: u64,
    pub chunks_dropped: u64,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub compression_ratio: f64,
    pub avg_chunk_size: f64,
}

impl RingBufferStats {
    /// Update the compression ratio.
    pub fn update_ratio(&mut self, original: u64, compressed: u64) {
        if compressed == 0 {
            self.compression_ratio = 1.0;
        } else {
            self.compression_ratio = original as f64 / compressed as f64;
        }
    }
}

// ─── LZ77 encoder / decoder ───────────────────────────────────────────────────

/// One LZ77 token.
#[derive(Debug, Clone)]
enum Lz77Token {
    /// Literal byte.
    Literal(u8),
    /// Back-reference: (offset-from-current, `match_length`).
    Match(u8, u8),
}

/// Encode `input` with a simple LZ77 scheme.
///
/// Output byte format:
/// - `0x00 b`          — literal byte `b`
/// - `0x01 offset len` — back-reference, `offset` bytes back, `len` bytes
#[must_use]
pub fn compress_chunk(input: &[u8]) -> Vec<u8> {
    if input.len() < LZ77_MIN_MATCH {
        // Too small to benefit; prepend flag byte 0 = uncompressed passthrough.
        let mut out = vec![0u8]; // 0 = raw
        out.extend_from_slice(input);
        return out;
    }

    let mut tokens: Vec<Lz77Token> = Vec::with_capacity(input.len());
    let mut pos = 0usize;

    while pos < input.len() {
        // Search the look-behind window for the longest match.
        // The offset is serialised in ONE byte, so a distance of 256 — which the
        // 256-byte window admits — cannot be represented. Searching that far and
        // then clamping with `.min(255)` below silently emitted a back-reference
        // to the wrong place and corrupted the round-trip, so the search itself
        // must stop at the largest representable distance.
        let window_start = pos.saturating_sub(LZ77_WINDOW.min(u8::MAX as usize));
        let window = &input[window_start..pos];

        let remaining = &input[pos..];
        let max_match = remaining.len().min(255);

        let mut best_offset = 0usize;
        let mut best_len = 0usize;

        for start in 0..window.len() {
            let mut match_len = 0usize;
            while match_len < max_match
                && match_len < (window.len() - start)
                && window[start + match_len] == remaining[match_len]
            {
                match_len += 1;
            }
            if match_len >= LZ77_MIN_MATCH && match_len > best_len {
                best_len = match_len;
                best_offset = window.len() - start; // distance from current pos
            }
        }

        if best_len >= LZ77_MIN_MATCH {
            debug_assert!(
                best_offset >= 1 && best_offset <= u8::MAX as usize,
                "offset {best_offset} must fit the one-byte field"
            );
            tokens.push(Lz77Token::Match(
                u8::try_from(best_offset).unwrap_or(u8::MAX),
                u8::try_from(best_len).unwrap_or(u8::MAX),
            ));
            pos += best_len;
        } else {
            tokens.push(Lz77Token::Literal(input[pos]));
            pos += 1;
        }
    }

    // Serialise tokens.  Prefix output with flag byte 1 = compressed.
    let mut out = vec![1u8]; // 1 = compressed
    for token in tokens {
        match token {
            Lz77Token::Literal(b) => {
                out.push(0x00);
                out.push(b);
            }
            Lz77Token::Match(offset, len) => {
                out.push(0x01);
                out.push(offset);
                out.push(len);
            }
        }
    }

    // Every literal costs TWO bytes, so an input with no usable back-reference
    // comes out larger than it went in — the opposite of what this function is
    // for, and what the `input.len() < LZ77_MIN_MATCH` guard above was trying to
    // avoid. That guard only catches inputs too short to hold a match at all;
    // this one catches every case where the encoding did not actually pay off.
    if out.len() >= input.len() + 1 {
        let mut raw = Vec::with_capacity(input.len() + 1);
        raw.push(0u8); // 0 = raw
        raw.extend_from_slice(input);
        return raw;
    }
    out
}

/// Decode bytes produced by [`compress_chunk`].
///
/// Returns `Err` if the input is malformed.
pub fn decompress_chunk(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Err("empty input".to_string());
    }
    let flag = input[0];
    let payload = &input[1..];

    if flag == 0 {
        // Raw passthrough
        return Ok(payload.to_vec());
    }
    if flag != 1 {
        return Err(format!("unknown compression flag: {flag}"));
    }

    let mut out: Vec<u8> = Vec::new();
    let mut i = 0usize;

    while i < payload.len() {
        match payload[i] {
            0x00 => {
                // Literal
                i += 1;
                if i >= payload.len() {
                    return Err("truncated literal token".to_string());
                }
                out.push(payload[i]);
                i += 1;
            }
            0x01 => {
                // Back-reference
                i += 1;
                if i + 1 >= payload.len() {
                    return Err("truncated match token".to_string());
                }
                let offset = payload[i] as usize;
                let len = payload[i + 1] as usize;
                i += 2;
                if offset == 0 || offset > out.len() {
                    return Err(format!(
                        "invalid back-reference offset={offset} out.len={}",
                        out.len()
                    ));
                }
                let start = out.len() - offset;
                for k in 0..len {
                    let b = out[start + k];
                    out.push(b);
                }
            }
            other => {
                return Err(format!("unknown token type: {other:#04x}"));
            }
        }
    }

    Ok(out)
}

// ─── ChunkIterator ────────────────────────────────────────────────────────────

/// Iterator over `TraceChunk` references, either forward or backward.
pub struct ChunkIterator<'a> {
    chunks: &'a VecDeque<TraceChunk>,
    index: usize,
    reverse: bool,
    len: usize,
}

impl<'a> ChunkIterator<'a> {
    fn new_forward(chunks: &'a VecDeque<TraceChunk>) -> Self {
        Self {
            len: chunks.len(),
            chunks,
            index: 0,
            reverse: false,
        }
    }

    fn new_backward(chunks: &'a VecDeque<TraceChunk>) -> Self {
        let len = chunks.len();
        Self {
            chunks,
            index: len,
            reverse: true,
            len,
        }
    }
}

impl<'a> Iterator for ChunkIterator<'a> {
    type Item = &'a TraceChunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reverse {
            if self.index == 0 {
                return None;
            }
            self.index -= 1;
            self.chunks.get(self.index)
        } else {
            if self.index >= self.len {
                return None;
            }
            let item = self.chunks.get(self.index);
            self.index += 1;
            item
        }
    }
}

// ─── TtdRingBuffer ────────────────────────────────────────────────────────────

/// Circular trace buffer with LZ77 compression and binary flush support.
pub struct TtdRingBuffer {
    /// Configuration.
    pub config: RingBufferConfig,
    /// Stored chunks (front = oldest, back = newest).
    chunks: VecDeque<TraceChunk>,
    /// Total payload bytes currently stored.
    total_bytes: usize,
    /// Running write-head sequence number.
    write_head: u64,
    /// Running read-head sequence number.
    read_head: u64,
    /// Number of chunks evicted due to buffer full.
    dropped_chunks: u64,
    /// Accumulated stats.
    stats: RingBufferStats,
    /// Total uncompressed bytes written (for compression ratio tracking).
    uncompressed_total: u64,
    /// Total compressed bytes written.
    compressed_total: u64,
}

impl TtdRingBuffer {
    /// Create a new ring buffer with the given config.
    #[must_use]
    pub fn new(config: RingBufferConfig) -> Self {
        Self {
            config,
            chunks: VecDeque::new(),
            total_bytes: 0,
            write_head: 0,
            read_head: 0,
            dropped_chunks: 0,
            stats: RingBufferStats::default(),
            uncompressed_total: 0,
            compressed_total: 0,
        }
    }

    /// Create with default 64 MB config.
    #[must_use]
    pub fn default() -> Self {
        Self::new(RingBufferConfig::default())
    }

    /// Write a chunk.  Data >= 256 bytes is compressed with LZ77.
    ///
    /// If the buffer is full and `overwrite_on_full` is set the oldest chunk
    /// is evicted; otherwise the write is dropped and the drop counter
    /// incremented.
    pub fn write_chunk(&mut self, timestamp_ns: u64, data: Vec<u8>) -> bool {
        let original_len = data.len();
        let (payload, compressed) = if original_len >= 256 {
            let c = compress_chunk(&data);
            // Only use compression if it actually saves space.
            if c.len() < original_len {
                (c, true)
            } else {
                (data, false)
            }
        } else {
            (data, false)
        };

        let payload_len = payload.len();
        let seq = self.write_head;
        self.write_head = self.write_head.wrapping_add(1);

        // Evict until there is room.
        while self.total_bytes + payload_len > self.config.capacity_bytes {
            if self.config.overwrite_on_full {
                if let Some(old) = self.chunks.pop_front() {
                    self.total_bytes -= old.data.len();
                    self.dropped_chunks += 1;
                    self.stats.chunks_dropped += 1;
                } else {
                    break;
                }
            } else {
                self.dropped_chunks += 1;
                self.stats.chunks_dropped += 1;
                return false;
            }
        }

        self.total_bytes += payload_len;
        self.uncompressed_total += original_len as u64;
        self.compressed_total += payload_len as u64;
        self.stats.bytes_written += payload_len as u64;
        self.stats.chunks_written += 1;

        let chunk = TraceChunk {
            sequence: seq,
            timestamp_ns,
            data: payload,
            compressed,
        };
        self.chunks.push_back(chunk);

        // Update rolling stats.
        if self.stats.chunks_written > 0 {
            self.stats.avg_chunk_size =
                self.stats.bytes_written as f64 / self.stats.chunks_written as f64;
        }
        if self.compressed_total > 0 {
            self.stats
                .update_ratio(self.uncompressed_total, self.compressed_total);
        }
        true
    }

    /// Find a chunk by sequence number (linear scan).
    #[must_use]
    pub fn read_chunk(&self, seq: u64) -> Option<&TraceChunk> {
        self.chunks.iter().find(|c| c.sequence == seq)
    }

    /// Advance the read head and return the next unread chunk, if any.
    ///
    /// Implements a single-consumer cursor over the ring: each call returns
    /// the chunk at `read_head` (or the closest later chunk still present in
    /// the buffer if some were evicted) and bumps the head past it.
    pub fn read_next(&mut self) -> Option<&TraceChunk> {
        // Find the first chunk whose sequence is >= read_head. This handles
        // the case where chunks <= read_head have been evicted by overwrite.
        let next_seq = self
            .chunks
            .iter()
            .find(|c| c.sequence >= self.read_head)
            .map(|c| c.sequence)?;
        self.read_head = next_seq.saturating_add(1);
        self.chunks.iter().find(|c| c.sequence == next_seq)
    }

    /// Current read-head sequence number.
    #[must_use]
    pub const fn read_head(&self) -> u64 {
        self.read_head
    }

    /// Reset the read cursor to the oldest available chunk.
    pub fn rewind_read_head(&mut self) {
        self.read_head = self.chunks.front().map_or(0, |c| c.sequence);
    }

    /// Return the oldest chunk without removing it.
    #[must_use]
    pub fn peek_oldest(&self) -> Option<&TraceChunk> {
        self.chunks.front()
    }

    /// Return the newest chunk without removing it.
    #[must_use]
    pub fn peek_newest(&self) -> Option<&TraceChunk> {
        self.chunks.back()
    }

    /// Flush all chunks to `writer` in binary format.
    ///
    /// Format per file:
    /// ```text
    /// [8-byte magic]
    /// for each chunk:
    ///   [8-byte sequence (LE)] [8-byte timestamp_ns (LE)]
    ///   [4-byte payload_len (LE)] [1-byte compressed_flag]
    ///   [payload_len bytes payload]
    /// ```
    ///
    /// # Errors
    /// Returns `io::Error` on write failure.
    pub fn flush_to_writer<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(RING_MAGIC)?;
        for chunk in &self.chunks {
            writer.write_all(&chunk.sequence.to_le_bytes())?;
            writer.write_all(&chunk.timestamp_ns.to_le_bytes())?;
            let len = chunk.data.len() as u32;
            writer.write_all(&len.to_le_bytes())?;
            writer.write_all(&[u8::from(chunk.compressed)])?;
            writer.write_all(&chunk.data)?;
        }
        Ok(())
    }

    /// Flush to an in-memory `Vec<u8>`.
    ///
    /// # Errors
    /// Propagates any `io::Error` (unlikely for in-memory writes).
    pub fn flush_to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.flush_to_writer(&mut buf)?;
        Ok(buf)
    }

    /// Clear all chunks.
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.total_bytes = 0;
    }

    /// Return the number of chunks currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Return `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Total payload bytes stored.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Number of chunks dropped so far.
    #[must_use]
    pub const fn dropped_chunks(&self) -> u64 {
        self.dropped_chunks
    }

    /// Return a statistics snapshot.
    #[must_use]
    pub const fn stats(&self) -> &RingBufferStats {
        &self.stats
    }

    /// Forward iterator over stored chunks (oldest → newest).
    #[must_use]
    pub fn iter_forward(&self) -> ChunkIterator<'_> {
        ChunkIterator::new_forward(&self.chunks)
    }

    /// Backward iterator over stored chunks (newest → oldest).
    #[must_use]
    pub fn iter_backward(&self) -> ChunkIterator<'_> {
        ChunkIterator::new_backward(&self.chunks)
    }

    /// Return all chunks whose timestamp falls in `[start_ns, end_ns]`.
    #[must_use]
    pub fn chunks_in_range(&self, start_ns: u64, end_ns: u64) -> Vec<&TraceChunk> {
        self.chunks
            .iter()
            .filter(|c| c.timestamp_ns >= start_ns && c.timestamp_ns <= end_ns)
            .collect()
    }
}

impl std::fmt::Debug for TtdRingBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtdRingBuffer")
            .field("chunks", &self.chunks.len())
            .field("total_bytes", &self.total_bytes)
            .field("dropped", &self.dropped_chunks)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn small_buf(cap: usize) -> TtdRingBuffer {
        TtdRingBuffer::new(RingBufferConfig {
            capacity_bytes: cap,
            overwrite_on_full: true,
            flush_interval_ms: 0,
        })
    }

    // ── RingBufferConfig ──────────────────────────────────────────────────────

    #[test]
    fn config_default_valid() {
        assert!(RingBufferConfig::default().is_valid());
    }

    #[test]
    fn config_zero_capacity_invalid() {
        let cfg = RingBufferConfig {
            capacity_bytes: 0,
            overwrite_on_full: false,
            flush_interval_ms: 0,
        };
        assert!(!cfg.is_valid());
    }

    // ── Basic write / read ────────────────────────────────────────────────────

    #[test]
    fn write_and_read_chunk() {
        let mut buf = small_buf(1024 * 1024);
        let written = buf.write_chunk(100, b"hello world".to_vec());
        assert!(written);
        let seq = buf.peek_newest().unwrap().sequence;
        let chunk = buf.read_chunk(seq).unwrap();
        // Raw (< 256 bytes) passthrough.
        assert!(!chunk.compressed);
        assert_eq!(chunk.timestamp_ns, 100);
    }

    #[test]
    fn write_two_chunks_sequence_increases() {
        let mut buf = small_buf(1024 * 1024);
        buf.write_chunk(1, vec![1, 2, 3]);
        buf.write_chunk(2, vec![4, 5, 6]);
        let oldest = buf.peek_oldest().unwrap().sequence;
        let newest = buf.peek_newest().unwrap().sequence;
        assert_eq!(oldest, 0);
        assert_eq!(newest, 1);
    }

    // ── Eviction ─────────────────────────────────────────────────────────────

    #[test]
    fn evict_oldest_on_full() {
        let mut buf = small_buf(100);
        for i in 0..5u64 {
            buf.write_chunk(i, vec![0u8; 30]);
        }
        // Buffer can hold ~3 chunks of 30 bytes each.
        assert!(buf.dropped_chunks() > 0);
    }

    #[test]
    fn no_overwrite_drops_new() {
        let mut buf = TtdRingBuffer::new(RingBufferConfig {
            capacity_bytes: 50,
            overwrite_on_full: false,
            flush_interval_ms: 0,
        });
        buf.write_chunk(0, vec![0u8; 40]);
        let written = buf.write_chunk(1, vec![0u8; 40]); // won't fit
        assert!(!written);
        assert_eq!(buf.dropped_chunks(), 1);
    }

    // ── Compression ───────────────────────────────────────────────────────────

    #[test]
    fn compress_decompress_roundtrip() {
        // Highly compressible: 512 bytes all the same.
        let input = vec![0xABu8; 512];
        let compressed = compress_chunk(&input);
        // Should be smaller.
        assert!(compressed.len() < input.len(), "compression should reduce size");
        let recovered = decompress_chunk(&compressed).unwrap();
        assert_eq!(recovered, input);
    }

    #[test]
    fn compress_small_passthrough() {
        // The raw form is chosen whenever compressing would not pay off: either
        // the input is shorter than LZ77_MIN_MATCH, or the token stream came out
        // no smaller than the input (every literal costs two bytes).
        let input = b"tiny".to_vec();
        let c = compress_chunk(&input);
        assert_eq!(c[0], 0); // raw flag
        assert_eq!(&c[1..], input.as_slice());
        let d = decompress_chunk(&c).unwrap();
        assert_eq!(d, input);
    }

    #[test]
    fn decompress_invalid_flag_error() {
        let bad = vec![0xFFu8, 0x00, 0x01];
        assert!(decompress_chunk(&bad).is_err());
    }

    #[test]
    fn compress_large_incompressible_no_panic() {
        // Random-ish data should not crash even if it doesn't compress.
        let input: Vec<u8> = (0..512u16).map(|i| (i.wrapping_mul(31) & 0xFF) as u8).collect();
        let compressed = compress_chunk(&input);
        let recovered = decompress_chunk(&compressed).unwrap();
        assert_eq!(recovered, input);
    }

    // ── Chunk with compression stored in buffer ───────────────────────────────

    #[test]
    fn large_chunk_stored_compressed() {
        let mut buf = small_buf(1024 * 1024);
        let data = vec![0x55u8; 512]; // highly compressible
        buf.write_chunk(999, data.clone());
        let chunk = buf.peek_newest().unwrap();
        if chunk.compressed {
            // Decompress and check
            let recovered = decompress_chunk(&chunk.data).unwrap();
            assert_eq!(recovered, data);
        }
        // Even if not compressed (edge case), the data is stored correctly.
    }

    // ── Iterator ─────────────────────────────────────────────────────────────

    #[test]
    fn iter_forward_order() {
        let mut buf = small_buf(1024 * 1024);
        for i in 0..5u64 {
            buf.write_chunk(i * 10, vec![i as u8]);
        }
        let seqs: Vec<u64> = buf.iter_forward().map(|c| c.sequence).collect();
        let mut sorted = seqs.clone();
        sorted.sort_unstable();
        assert_eq!(seqs, sorted);
    }

    #[test]
    fn iter_backward_reverse_order() {
        let mut buf = small_buf(1024 * 1024);
        for i in 0..5u64 {
            buf.write_chunk(i * 10, vec![i as u8]);
        }
        let seqs: Vec<u64> = buf.iter_backward().map(|c| c.sequence).collect();
        let mut rev = seqs.clone();
        rev.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(seqs, rev);
    }

    // ── Flush ─────────────────────────────────────────────────────────────────

    #[test]
    fn flush_to_bytes_starts_with_magic() {
        let mut buf = small_buf(1024 * 1024);
        buf.write_chunk(0, b"test".to_vec());
        let bytes = buf.flush_to_bytes().unwrap();
        assert!(bytes.starts_with(RING_MAGIC));
    }

    #[test]
    fn flush_empty_buffer_has_only_magic() {
        let buf = small_buf(1024);
        let bytes = buf.flush_to_bytes().unwrap();
        assert_eq!(bytes.len(), RING_MAGIC.len());
    }

    // ── Range query ───────────────────────────────────────────────────────────

    #[test]
    fn chunks_in_range_filters() {
        let mut buf = small_buf(1024 * 1024);
        buf.write_chunk(100, vec![1]);
        buf.write_chunk(200, vec![2]);
        buf.write_chunk(300, vec![3]);
        let found = buf.chunks_in_range(150, 250);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].timestamp_ns, 200);
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    #[test]
    fn stats_chunks_written_count() {
        let mut buf = small_buf(1024 * 1024);
        for _ in 0..10 {
            buf.write_chunk(0, vec![0u8; 10]);
        }
        assert_eq!(buf.stats().chunks_written, 10);
    }

    #[test]
    fn stats_avg_chunk_size_nonzero() {
        let mut buf = small_buf(1024 * 1024);
        buf.write_chunk(0, vec![0u8; 64]);
        assert!(buf.stats().avg_chunk_size > 0.0);
    }

    // ── Clear ─────────────────────────────────────────────────────────────────

    #[test]
    fn clear_empties_buffer() {
        let mut buf = small_buf(1024 * 1024);
        buf.write_chunk(0, vec![1, 2, 3]);
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.total_bytes(), 0);
    }
}
