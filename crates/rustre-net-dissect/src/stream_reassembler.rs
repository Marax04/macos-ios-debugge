//! TCP stream reassembler.
//!
//! Provides:
//! - [`StreamReassembler`] — manages per-stream reassembly state
//! - [`TCPSegment`] — a single received TCP segment
//! - [`ReassemblyBuffer`] — orders and stores out-of-sequence segments
//! - [`OutOfOrderQueue`] — priority queue of segments waiting for gaps
//! - [`GapDetector`] — tracks missing byte ranges
//! - [`ReassembledStream`] — fully ordered, gap-free byte sequence
//! - [`Pdu`] — an extracted Protocol Data Unit from a stream

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::DissectError;

// ────────────────────────────────────────────────────────────────────────────
// TCP flags
// ────────────────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// TCP control flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct TcpFlags: u8 {
        const FIN = 0x01;
        const SYN = 0x02;
        const RST = 0x04;
        const PSH = 0x08;
        const ACK = 0x10;
        const URG = 0x20;
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TCPSegment
// ────────────────────────────────────────────────────────────────────────────

/// A single TCP segment with its sequence metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TCPSegment {
    /// Sequence number of the first byte of `payload`.
    pub seq: u32,
    /// Acknowledgment number.
    pub ack: u32,
    /// TCP control flags.
    pub flags: TcpFlags,
    /// Payload bytes (may be empty for pure ACKs, SYN, FIN).
    pub payload: Vec<u8>,
    /// Timestamp when the segment was captured (Unix ms).
    pub timestamp_ms: u64,
    /// Stream ID this segment belongs to.
    pub stream_id: u64,
}

impl TCPSegment {
    /// Create a new segment.
    #[must_use] 
    pub const fn new(stream_id: u64, seq: u32, ack: u32, flags: TcpFlags, payload: Vec<u8>) -> Self {
        Self {
            seq,
            ack,
            flags,
            payload,
            timestamp_ms: 0,
            stream_id,
        }
    }

    /// The sequence number *after* this segment's payload.
    #[must_use]
    pub fn next_seq(&self) -> u32 {
        let len = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        let syn_fin = u32::from(self.flags.intersects(TcpFlags::SYN | TcpFlags::FIN));
        self.seq.wrapping_add(len).wrapping_add(syn_fin)
    }

    /// Whether this segment carries actual data.
    #[must_use]
    pub const fn has_payload(&self) -> bool {
        !self.payload.is_empty()
    }

    /// Compare two segments by sequence number using TCP-style modular
    /// arithmetic (RFC 1982): the smaller difference wins.  Returns
    /// [`Ordering::Equal`] when the sequence numbers are identical.
    #[must_use]
    pub const fn seq_cmp(&self, other: &Self) -> Ordering {
        let diff = self.seq.wrapping_sub(other.seq).cast_signed();
        match diff {
            0 => Ordering::Equal,
            d if d > 0 => Ordering::Greater,
            _ => Ordering::Less,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Gap detector
// ────────────────────────────────────────────────────────────────────────────

/// Tracks byte ranges that have been received, and reports gaps.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GapDetector {
    /// Sorted list of (start, `end_exclusive`) received ranges.
    received: Vec<(u32, u32)>,
}

impl GapDetector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the receipt of bytes `[start, start + len)`.
    /// Automatically merges overlapping/adjacent ranges.
    pub fn record(&mut self, start: u32, len: usize) {
        if len == 0 {
            return;
        }
        // Clamp to u32::MAX to avoid silent truncation on 64-bit targets.
        let len32 = u32::try_from(len.min(u32::MAX as usize)).unwrap_or(u32::MAX);
        let end = start.wrapping_add(len32);
        self.received.push((start, end));
        // Merge: sort and coalesce
        self.received.sort_by_key(|&(s, _)| s);
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(self.received.len());
        for &(s, e) in &self.received {
            if let Some(last) = merged.last_mut() {
                // Overlap or adjacent (no wrap-around check for simplicity)
                if s <= last.1 {
                    last.1 = last.1.max(e);
                    continue;
                }
            }
            merged.push((s, e));
        }
        self.received = merged;
    }

    /// Returns `true` if all bytes from `start` through `start + len - 1`
    /// have been received.
    #[must_use]
    pub fn is_contiguous(&self, start: u32, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let len32 = u32::try_from(len.min(u32::MAX as usize)).unwrap_or(u32::MAX);
        let end = start.wrapping_add(len32);
        self.received
            .iter()
            .any(|&(rs, re)| rs <= start && re >= end)
    }

    /// Number of distinct received ranges.
    #[must_use]
    pub const fn range_count(&self) -> usize {
        self.received.len()
    }

    /// Total received bytes (sum of ranges).
    #[must_use]
    pub fn total_received(&self) -> u64 {
        self.received
            .iter()
            .map(|&(s, e)| u64::from(e.wrapping_sub(s)))
            .sum()
    }

    /// Check if there's a gap between `start` and `end` in received data.
    #[must_use]
    pub fn has_gap(&self, start: u32, end: u32) -> bool {
        !self.is_contiguous(start, end.wrapping_sub(start) as usize)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// OutOfOrderQueue
// ────────────────────────────────────────────────────────────────────────────

/// Holds TCP segments that arrived before their sequence number is expected.
#[derive(Debug, Default)]
pub struct OutOfOrderQueue {
    /// Keyed by sequence number.
    segments: BTreeMap<u32, TCPSegment>,
    total_bytes: usize,
}

impl OutOfOrderQueue {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a segment.
    pub fn insert(&mut self, seg: TCPSegment) {
        self.total_bytes += seg.payload.len();
        self.segments.insert(seg.seq, seg);
    }

    /// Remove and return the segment with the lowest sequence number if it
    /// equals `expected_seq`.
    pub fn pop_if_expected(&mut self, expected_seq: u32) -> Option<TCPSegment> {
        if self.segments.contains_key(&expected_seq) {
            let seg = self.segments.remove(&expected_seq)?;
            self.total_bytes -= seg.payload.len();
            Some(seg)
        } else {
            None
        }
    }

    /// Peek at the lowest sequence number in the queue.
    #[must_use]
    pub fn lowest_seq(&self) -> Option<u32> {
        self.segments.keys().next().copied()
    }

    /// Number of queued segments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Total buffered payload bytes.
    #[must_use]
    pub const fn buffered_bytes(&self) -> usize {
        self.total_bytes
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ReassemblyBuffer
// ────────────────────────────────────────────────────────────────────────────

/// Accumulates reassembled bytes in order, tracking the next expected sequence
/// number.
#[derive(Debug, Default)]
pub struct ReassemblyBuffer {
    pub data: Vec<u8>,
    /// Next expected sequence number.
    pub next_seq: u32,
    /// Whether the stream has been initialised with a SYN sequence number.
    pub initialised: bool,
}

impl ReassemblyBuffer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialise with the ISN from a SYN segment.
    pub const fn init_with_syn(&mut self, syn_seq: u32) {
        // After the SYN, the first data byte has seq = syn_seq + 1
        self.next_seq = syn_seq.wrapping_add(1);
        self.initialised = true;
    }

    /// Attempt to append an in-order segment. Returns `true` if consumed.
    pub fn try_append(&mut self, seg: &TCPSegment) -> bool {
        if !self.initialised {
            // Accept without initialisation (mid-stream capture)
            self.next_seq = seg.seq;
            self.initialised = true;
        }
        if seg.seq != self.next_seq {
            return false;
        }
        self.data.extend_from_slice(&seg.payload);
        self.next_seq = seg.next_seq();
        true
    }

    /// Number of reassembled bytes so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Drain and return all accumulated bytes.
    pub fn drain_all(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }

    /// Drain up to `n` bytes from the front.
    pub fn drain(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(self.data.len());
        self.data.drain(..n).collect()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ReassembledStream
// ────────────────────────────────────────────────────────────────────────────

/// The fully ordered, gap-free byte sequence for one direction of a TCP stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReassembledStream {
    pub stream_id: u64,
    /// Accumulated reassembled data.
    pub data: Vec<u8>,
    /// Whether the stream has received a FIN.
    pub fin: bool,
    /// Whether the stream was reset (RST).
    pub rst: bool,
    /// Total segments processed.
    pub segments_processed: u64,
    /// Out-of-order segments seen.
    pub ooo_count: u64,
    /// Duplicate segments dropped.
    pub dup_count: u64,
}

impl ReassembledStream {
    #[must_use] 
    pub const fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            data: Vec::new(),
            fin: false,
            rst: false,
            segments_processed: 0,
            ooo_count: 0,
            dup_count: 0,
        }
    }

    /// Returns `true` if the stream is closed (FIN or RST).
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.fin || self.rst
    }
}

// ────────────────────────────────────────────────────────────────────────────
// PDU
// ────────────────────────────────────────────────────────────────────────────

/// A complete Protocol Data Unit extracted from a reassembled stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pdu {
    pub stream_id: u64,
    /// Sequence offset within the stream where this PDU starts.
    pub stream_offset: usize,
    /// Raw bytes of the PDU.
    pub data: Vec<u8>,
    /// Heuristic protocol name, if identified.
    pub protocol_hint: Option<String>,
}

impl Pdu {
    #[must_use] 
    pub const fn new(stream_id: u64, stream_offset: usize, data: Vec<u8>) -> Self {
        Self {
            stream_id,
            stream_offset,
            data,
            protocol_hint: None,
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// PDU extractor
// ────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `a` is strictly before `b` in TCP sequence space
/// (RFC 1982 serial number arithmetic, window ≤ 2^31).
#[inline]
const fn seq_before(a: u32, b: u32) -> bool {
    a.wrapping_sub(b).cast_signed() < 0
}

/// Heuristic to extract HTTP/1.x PDUs from a reassembled byte stream.
#[must_use] 
pub fn extract_http_pdus(stream_id: u64, data: &[u8]) -> Vec<Pdu> {
    let mut pdus = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        // Look for end of HTTP headers (\r\n\r\n)
        if let Some(end_pos) = find_bytes(&data[offset..], b"\r\n\r\n") {
            let headers_end = offset + end_pos + 4;
            // Try to find Content-Length
            let header_text = std::str::from_utf8(&data[offset..headers_end]).unwrap_or("");
            let body_len = extract_content_length(header_text).unwrap_or(0);
            // Guard against wrapping addition: if headers_end + body_len
            // overflows usize we must treat the PDU as incomplete.
            let Some(pdu_end) = headers_end.checked_add(body_len) else { break }; // arithmetic overflow — treat as incomplete
            if pdu_end <= data.len() {
                let mut pdu = Pdu::new(stream_id, offset, data[offset..pdu_end].to_vec());
                pdu.protocol_hint = Some("HTTP/1.1".to_string());
                pdus.push(pdu);
                offset = pdu_end;
            } else {
                break; // incomplete PDU — wait for more data
            }
        } else {
            break;
        }
    }
    pdus
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn extract_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

// ────────────────────────────────────────────────────────────────────────────
// StreamReassembler
// ────────────────────────────────────────────────────────────────────────────

/// Per-stream reassembly state (one direction).
struct StreamState {
    buffer: ReassemblyBuffer,
    ooo: OutOfOrderQueue,
    gap_detector: GapDetector,
    reassembled: ReassembledStream,
    /// Maximum bytes buffered in OOO queue before dropping.
    max_ooo_bytes: usize,
}

impl StreamState {
    fn new(stream_id: u64, max_ooo_bytes: usize) -> Self {
        Self {
            buffer: ReassemblyBuffer::new(),
            ooo: OutOfOrderQueue::new(),
            gap_detector: GapDetector::new(),
            reassembled: ReassembledStream::new(stream_id),
            max_ooo_bytes,
        }
    }
}

/// Manages reassembly for multiple concurrent TCP streams.
pub struct StreamReassembler {
    streams: HashMap<u64, StreamState>,
    /// Maximum OOO buffer bytes per stream.
    max_ooo_bytes: usize,
    /// Maximum number of concurrent streams.
    max_streams: usize,
}

impl StreamReassembler {
    /// Create a new reassembler.
    #[must_use]
    pub fn new(max_streams: usize, max_ooo_bytes: usize) -> Self {
        Self {
            streams: HashMap::new(),
            max_ooo_bytes: max_ooo_bytes.max(1),
            max_streams: max_streams.max(1),
        }
    }

    /// Register a new stream (called when a SYN is seen).
    pub fn new_stream(&mut self, stream_id: u64, syn_seq: u32) {
        if self.streams.len() >= self.max_streams {
            // Evict oldest stream
            if let Some(&oldest_id) = self.streams.keys().next() {
                self.streams.remove(&oldest_id);
            }
        }
        let mut state = StreamState::new(stream_id, self.max_ooo_bytes);
        state.buffer.init_with_syn(syn_seq);
        self.streams.insert(stream_id, state);
    }

    /// # Panics
    /// Panics if invariants are violated.
    /// Feed a TCP segment into the reassembler.
    ///
    /// Returns the number of new bytes added to the reassembled stream.
    ///
    /// # Errors
    /// Returns [`DissectError::Failed`] if the stream is unknown.
    pub fn feed(&mut self, seg: TCPSegment) -> Result<usize, DissectError> {
        let stream_id = seg.stream_id;

        // Auto-create stream if not seen (mid-stream capture)
        if !self.streams.contains_key(&stream_id) {
            let mut state = StreamState::new(stream_id, self.max_ooo_bytes);
            state.buffer.init_with_syn(seg.seq.wrapping_sub(1));
            self.streams.insert(stream_id, state);
        }

        let state = self.streams.get_mut(&stream_id).unwrap();
        state.reassembled.segments_processed += 1;

        // Handle control flags
        if seg.flags.contains(TcpFlags::RST) {
            state.reassembled.rst = true;
            return Ok(0);
        }
        if seg.flags.contains(TcpFlags::SYN) {
            state.buffer.init_with_syn(seg.seq);
            return Ok(0);
        }
        if seg.flags.contains(TcpFlags::FIN) {
            state.reassembled.fin = true;
        }
        if seg.payload.is_empty() {
            return Ok(0);
        }

        let before = state.buffer.len();

        // Record in gap detector
        state.gap_detector.record(seg.seq, seg.payload.len());

        // In-order?
        if state.buffer.try_append(&seg) {
            // Drain any queued segments that are now in order
            loop {
                let expected = state.buffer.next_seq;
                if let Some(ooo_seg) = state.ooo.pop_if_expected(expected) {
                    state
                        .gap_detector
                        .record(ooo_seg.seq, ooo_seg.payload.len());
                    state.buffer.try_append(&ooo_seg);
                } else {
                    break;
                }
            }
        } else if seq_before(seg.seq, state.buffer.next_seq) {
            // Duplicate / already-consumed (wrapping-safe comparison)
            state.reassembled.dup_count += 1;
        } else {
            // Out-of-order
            state.reassembled.ooo_count += 1;
            if state.ooo.buffered_bytes() < state.max_ooo_bytes {
                state.ooo.insert(seg);
            }
            // If OOO buffer is full, drop silently
        }

        let added = state.buffer.len() - before;
        // Copy new bytes to reassembled
        let already = state.reassembled.data.len();
        state.reassembled.data.extend_from_slice(&state.buffer.data[already..]);
        Ok(added)
    }

    /// Get a snapshot of the reassembled stream.
    #[must_use]
    pub fn stream(&self, stream_id: u64) -> Option<&ReassembledStream> {
        self.streams.get(&stream_id).map(|s| &s.reassembled)
    }

    /// Drain all reassembled bytes for a stream.
    pub fn drain(&mut self, stream_id: u64) -> Vec<u8> {
        self.streams
            .get_mut(&stream_id)
            .map(|s| std::mem::take(&mut s.reassembled.data))
            .unwrap_or_default()
    }

    /// Remove a stream and return its final reassembled data.
    pub fn close_stream(&mut self, stream_id: u64) -> Option<ReassembledStream> {
        self.streams.remove(&stream_id).map(|s| s.reassembled)
    }

    /// Number of active streams.
    #[must_use]
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Extract HTTP PDUs from the reassembled stream data.
    #[must_use]
    pub fn extract_pdus(&self, stream_id: u64) -> Vec<Pdu> {
        self.streams
            .get(&stream_id)
            .map(|s| extract_http_pdus(stream_id, &s.reassembled.data))
            .unwrap_or_default()
    }

    /// Gap detector for a stream.
    #[must_use]
    pub fn gap_detector(&self, stream_id: u64) -> Option<&GapDetector> {
        self.streams.get(&stream_id).map(|s| &s.gap_detector)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_seg(stream_id: u64, seq: u32, payload: &[u8]) -> TCPSegment {
        TCPSegment::new(
            stream_id,
            seq,
            0,
            TcpFlags::ACK | TcpFlags::PSH,
            payload.to_vec(),
        )
    }

    fn make_syn(stream_id: u64, seq: u32) -> TCPSegment {
        TCPSegment::new(stream_id, seq, 0, TcpFlags::SYN, vec![])
    }

    fn make_fin(stream_id: u64, seq: u32) -> TCPSegment {
        TCPSegment::new(stream_id, seq, 0, TcpFlags::FIN | TcpFlags::ACK, vec![])
    }

    fn make_rst(stream_id: u64, seq: u32) -> TCPSegment {
        TCPSegment::new(stream_id, seq, 0, TcpFlags::RST, vec![])
    }

    // ── TCPSegment ─────────────────────────────────────────────────────────────

    #[test]
    fn test_segment_next_seq_data() {
        let seg = make_seg(1, 100, b"hello");
        assert_eq!(seg.next_seq(), 105);
    }

    #[test]
    fn test_segment_next_seq_syn() {
        let seg = make_syn(1, 999);
        assert_eq!(seg.next_seq(), 1000); // SYN consumes 1 seq number
    }

    #[test]
    fn test_segment_has_payload() {
        let seg = make_seg(1, 0, b"data");
        assert!(seg.has_payload());
        let empty = TCPSegment::new(1, 0, 0, TcpFlags::ACK, vec![]);
        assert!(!empty.has_payload());
    }

    #[test]
    fn test_segment_seq_wrap() {
        let seg = TCPSegment::new(1, u32::MAX - 2, 0, TcpFlags::PSH, vec![0; 5]);
        let next = seg.next_seq();
        assert_eq!(next, 2); // wraps around
    }

    // ── GapDetector ────────────────────────────────────────────────────────────

    #[test]
    fn test_gap_record_single() {
        let mut gd = GapDetector::new();
        gd.record(100, 50);
        assert!(gd.is_contiguous(100, 50));
        assert!(!gd.is_contiguous(90, 20));
    }

    #[test]
    fn test_gap_merge_adjacent() {
        let mut gd = GapDetector::new();
        gd.record(0, 100);
        gd.record(100, 50);
        assert_eq!(gd.range_count(), 1);
        assert!(gd.is_contiguous(0, 150));
    }

    #[test]
    fn test_gap_merge_overlapping() {
        let mut gd = GapDetector::new();
        gd.record(0, 100);
        gd.record(50, 100);
        assert_eq!(gd.range_count(), 1);
        assert!(gd.is_contiguous(0, 150));
    }

    #[test]
    fn test_gap_two_ranges() {
        let mut gd = GapDetector::new();
        gd.record(0, 100);
        gd.record(200, 100);
        assert_eq!(gd.range_count(), 2);
        assert!(!gd.is_contiguous(0, 300));
    }

    #[test]
    fn test_gap_total_received() {
        let mut gd = GapDetector::new();
        gd.record(0, 100);
        gd.record(200, 50);
        assert_eq!(gd.total_received(), 150);
    }

    #[test]
    fn test_gap_has_gap() {
        let mut gd = GapDetector::new();
        gd.record(0, 100);
        assert!(gd.has_gap(0, 200));
        gd.record(100, 100);
        assert!(!gd.has_gap(0, 200));
    }

    // ── OutOfOrderQueue ────────────────────────────────────────────────────────

    #[test]
    fn test_ooo_insert_and_pop() {
        let mut q = OutOfOrderQueue::new();
        let seg = make_seg(1, 200, b"world");
        q.insert(seg);
        assert_eq!(q.len(), 1);
        let popped = q.pop_if_expected(200);
        assert!(popped.is_some());
        assert!(q.is_empty());
    }

    #[test]
    fn test_ooo_pop_wrong_seq() {
        let mut q = OutOfOrderQueue::new();
        q.insert(make_seg(1, 300, b"data"));
        assert!(q.pop_if_expected(200).is_none());
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_ooo_lowest_seq() {
        let mut q = OutOfOrderQueue::new();
        q.insert(make_seg(1, 500, b"c"));
        q.insert(make_seg(1, 100, b"a"));
        q.insert(make_seg(1, 300, b"b"));
        assert_eq!(q.lowest_seq(), Some(100));
    }

    #[test]
    fn test_ooo_buffered_bytes() {
        let mut q = OutOfOrderQueue::new();
        q.insert(make_seg(1, 0, b"hello"));
        q.insert(make_seg(1, 5, b"world"));
        assert_eq!(q.buffered_bytes(), 10);
    }

    // ── ReassemblyBuffer ──────────────────────────────────────────────────────

    #[test]
    fn test_buffer_in_order() {
        let mut buf = ReassemblyBuffer::new();
        buf.init_with_syn(99);
        let seg = make_seg(1, 100, b"hello");
        assert!(buf.try_append(&seg));
        assert_eq!(&buf.data, b"hello");
        assert_eq!(buf.next_seq, 105);
    }

    #[test]
    fn test_buffer_out_of_order_rejected() {
        let mut buf = ReassemblyBuffer::new();
        buf.init_with_syn(99);
        let seg = make_seg(1, 110, b"world");
        assert!(!buf.try_append(&seg));
        assert!(buf.is_empty());
    }

    #[test]
    fn test_buffer_drain_all() {
        let mut buf = ReassemblyBuffer::new();
        buf.init_with_syn(0);
        buf.try_append(&make_seg(1, 1, b"data"));
        let drained = buf.drain_all();
        assert_eq!(drained, b"data");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_buffer_drain_partial() {
        let mut buf = ReassemblyBuffer::new();
        buf.init_with_syn(0);
        buf.try_append(&make_seg(1, 1, b"hello world"));
        let part = buf.drain(5);
        assert_eq!(part, b"hello");
        assert_eq!(buf.data, b" world");
    }

    // ── StreamReassembler ─────────────────────────────────────────────────────

    #[test]
    fn test_reassembler_in_order() {
        let mut r = StreamReassembler::new(10, 65536);
        r.new_stream(1, 99);
        r.feed(make_seg(1, 100, b"hello")).unwrap();
        r.feed(make_seg(1, 105, b" world")).unwrap();
        let stream = r.stream(1).unwrap();
        assert_eq!(&stream.data, b"hello world");
    }

    #[test]
    fn test_reassembler_out_of_order() {
        let mut r = StreamReassembler::new(10, 65536);
        r.new_stream(1, 99);
        r.feed(make_seg(1, 105, b" world")).unwrap(); // OOO
        r.feed(make_seg(1, 100, b"hello")).unwrap(); // triggers drain of OOO
        let stream = r.stream(1).unwrap();
        assert_eq!(&stream.data, b"hello world");
    }

    #[test]
    fn test_reassembler_ooo_count() {
        let mut r = StreamReassembler::new(10, 65536);
        r.new_stream(1, 99);
        r.feed(make_seg(1, 110, b"c")).unwrap();
        r.feed(make_seg(1, 105, b"b")).unwrap();
        let stream = r.stream(1).unwrap();
        assert_eq!(stream.ooo_count, 2);
    }

    #[test]
    fn test_reassembler_fin_flag() {
        let mut r = StreamReassembler::new(10, 65536);
        r.new_stream(1, 99);
        r.feed(make_seg(1, 100, b"hello")).unwrap();
        r.feed(make_fin(1, 105)).unwrap();
        assert!(r.stream(1).unwrap().fin);
    }

    #[test]
    fn test_reassembler_rst_flag() {
        let mut r = StreamReassembler::new(10, 65536);
        r.new_stream(1, 99);
        r.feed(make_rst(1, 100)).unwrap();
        assert!(r.stream(1).unwrap().rst);
    }

    #[test]
    fn test_reassembler_drain() {
        let mut r = StreamReassembler::new(10, 65536);
        r.new_stream(1, 0);
        r.feed(make_seg(1, 1, b"abc")).unwrap();
        let drained = r.drain(1);
        assert_eq!(drained, b"abc");
        let stream = r.stream(1).unwrap();
        assert!(stream.data.is_empty());
    }

    #[test]
    fn test_reassembler_close_stream() {
        let mut r = StreamReassembler::new(10, 65536);
        r.new_stream(1, 99);
        r.feed(make_seg(1, 100, b"data")).unwrap();
        let final_stream = r.close_stream(1).unwrap();
        assert_eq!(&final_stream.data, b"data");
        assert_eq!(r.stream_count(), 0);
    }

    #[test]
    fn test_reassembler_auto_create() {
        let mut r = StreamReassembler::new(10, 65536);
        // Feed without calling new_stream first
        r.feed(make_seg(42, 1000, b"mid-stream")).unwrap();
        let stream = r.stream(42).unwrap();
        assert_eq!(&stream.data, b"mid-stream");
    }

    // ── PDU extraction ────────────────────────────────────────────────────────

    #[test]
    fn test_extract_http_pdu_get() {
        let data = b"GET / HTTP/1.1\r\nHost: a.com\r\nContent-Length: 0\r\n\r\n";
        let pdus = extract_http_pdus(1, data);
        assert_eq!(pdus.len(), 1);
        assert_eq!(pdus[0].protocol_hint.as_deref(), Some("HTTP/1.1"));
    }

    #[test]
    fn test_extract_http_pdu_with_body() {
        let data = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let pdus = extract_http_pdus(1, data);
        assert_eq!(pdus.len(), 1);
        assert_eq!(pdus[0].data.len(), data.len());
    }

    #[test]
    fn test_extract_http_pdu_incomplete() {
        // Content-Length says 100 but only 3 bytes of body
        let data = b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabc";
        let pdus = extract_http_pdus(1, data);
        assert!(pdus.is_empty()); // incomplete — wait for more
    }

    #[test]
    fn test_pdu_struct() {
        let pdu = Pdu::new(1, 42, b"hello".to_vec());
        assert_eq!(pdu.len(), 5);
        assert_eq!(pdu.stream_offset, 42);
    }

    // ── ReassembledStream ─────────────────────────────────────────────────────

    #[test]
    fn test_reassembled_stream_closed() {
        let mut s = ReassembledStream::new(1);
        assert!(!s.is_closed());
        s.fin = true;
        assert!(s.is_closed());
    }

    #[test]
    fn test_reassembled_stream_rst_closed() {
        let mut s = ReassembledStream::new(1);
        s.rst = true;
        assert!(s.is_closed());
    }
}
