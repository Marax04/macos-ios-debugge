//! TCP stream reassembly with sequence-number tracking, out-of-order buffering,
//! and gap detection.
//!
//! This module provides [`TcpReassembler`] — a bidirectional TCP reassembly
//! engine that accepts raw TCP segments and produces ordered byte streams for
//! each direction.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{FlowKey, NetError, TcpFlags, TcpSegment};

// ─────────────────────────────────────────────────────────────────────────────
// SegmentMap — ordered map of pending out-of-order segments
// ─────────────────────────────────────────────────────────────────────────────

/// An entry inside the out-of-order buffer, keyed by sequence number.
#[derive(Debug, Clone)]
pub struct PendingSegment {
    /// Absolute sequence number of the first byte.
    pub seq: u32,
    /// Raw payload bytes of this segment.
    pub data: Vec<u8>,
}

impl PendingSegment {
    /// First sequence number past the end of this segment.
    #[must_use]
    pub fn end_seq(&self) -> u32 {
        let len = u32::try_from(self.data.len()).unwrap_or(u32::MAX);
        self.seq.wrapping_add(len)
    }
}

/// Maximum number of out-of-order segments buffered per direction.
///
/// Prevents unbounded memory growth when an attacker floods a stream with
/// out-of-order segments while withholding the in-order segment.
pub const SEGMENT_MAP_MAX_ENTRIES: usize = 1024;

/// Out-of-order segment buffer ordered by sequence number.
///
/// Maintains segments in a `BTreeMap<seq, PendingSegment>` and merges
/// overlapping entries on insertion.  Capped at [`SEGMENT_MAP_MAX_ENTRIES`]
/// entries to bound memory usage.
#[derive(Debug, Default, Clone)]
pub struct SegmentMap {
    inner: BTreeMap<u32, PendingSegment>,
}

impl SegmentMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a segment, merging with any overlapping entries.
    pub fn insert(&mut self, seq: u32, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let end = seq.wrapping_add(len);

        // Merge any existing segment that starts inside this one.
        let overlapping_keys: Vec<u32> = self
            .inner
            .range(seq..)
            .take_while(|&(&k, _)| {
                // k is within [seq, end)
                let dist = k.wrapping_sub(seq);
                dist < len
            })
            .map(|(&k, _)| k)
            .collect();

        let mut merged_data = data;
        for k in overlapping_keys {
            if let Some(existing) = self.inner.remove(&k) {
                let existing_end = existing.end_seq();
                let existing_end_dist = existing_end.wrapping_sub(seq);
                if existing_end_dist > u32::try_from(merged_data.len()).unwrap_or(u32::MAX) {
                    // Existing segment extends past our merged data — append the tail.
                    let tail_start = merged_data.len();
                    let extra =
                        (existing_end_dist as usize).saturating_sub(tail_start);
                    if extra > 0 {
                        let src_off =
                            existing.data.len().saturating_sub(extra);
                        merged_data.extend_from_slice(&existing.data[src_off..]);
                    }
                }
            }
        }

        // Also check if there is a segment that starts before seq but extends into it.
        if let Some((&prev_seq, prev_seg)) = self.inner.range(..seq).next_back() {
            let prev_end = prev_seg.end_seq();
            let overlaps = prev_end.wrapping_sub(seq) <= u32::MAX / 2
                && prev_end.wrapping_sub(seq) > 0;
            if overlaps {
                let overlap_bytes = prev_end.wrapping_sub(seq) as usize;
                let tail_start = prev_seg.data.len().saturating_sub(overlap_bytes);
                let mut combined = prev_seg.data[..tail_start].to_vec();
                combined.extend_from_slice(&merged_data);
                let _ = end;
                let key = prev_seq;
                self.inner.remove(&key);
                self.inner.insert(
                    key,
                    PendingSegment {
                        seq: key,
                        data: combined,
                    },
                );
                return;
            }
        }

        // Enforce cap: if already at the limit, drop the new segment rather than
        // growing without bound.
        if self.inner.len() >= SEGMENT_MAP_MAX_ENTRIES {
            return;
        }
        self.inner.insert(seq, PendingSegment { seq, data: merged_data });
    }

    /// Remove and return the first segment whose seq matches `expected`.
    pub fn pop_at(&mut self, expected: u32) -> Option<PendingSegment> {
        self.inner.remove(&expected)
    }

    /// Peek at the first (lowest-seq) segment.
    #[must_use]
    pub fn first(&self) -> Option<&PendingSegment> {
        self.inner.values().next()
    }

    /// Number of buffered segments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if no segments are buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Total bytes buffered (sum of all segment lengths).
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.inner.values().map(|s| s.data.len()).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReassemblyBuffer — one-directional reassembly
// ─────────────────────────────────────────────────────────────────────────────

/// State of a one-directional TCP reassembly buffer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum ReassemblyState {
    #[default]
    Idle,
    /// SYN seen; waiting for SYN-ACK or data.
    SynSeen { isn: u32 },
    /// Actively reassembling data.
    Active,
    /// FIN received; stream is half-closed.
    FinReceived,
    /// RST received; stream is reset.
    Reset,
}

/// Detected gap in the reassembled stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamGap {
    /// Expected sequence number at the start of the gap.
    pub expected_seq: u32,
    /// Sequence number of the first segment received after the gap.
    pub received_seq: u32,
    /// Estimated number of bytes missing.
    pub missing_bytes: u32,
}

impl fmt::Display for StreamGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "gap @ seq={:#x} missing={} bytes",
            self.expected_seq, self.missing_bytes
        )
    }
}

/// A one-directional reassembly buffer tracking in-order bytes and
/// out-of-order buffering.
#[derive(Debug, Default)]
pub struct ReassemblyBuffer {
    /// Next expected sequence number.
    pub next_seq: u32,
    /// Reassembled in-order byte stream.
    pub stream: Vec<u8>,
    /// Out-of-order segments awaiting delivery.
    out_of_order: SegmentMap,
    /// Current reassembly state.
    pub state: ReassemblyState,
    /// Gaps that have been detected (filled when gap is later resolved).
    pub gaps: Vec<StreamGap>,
    /// Total bytes consumed into the stream.
    pub bytes_consumed: u64,
    /// Total bytes dropped (duplicates).
    pub bytes_dropped: u64,
}

impl ReassemblyBuffer {
    /// Create a new buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialise the buffer with the given initial sequence number (ISN).
    ///
    /// After a SYN/SYN-ACK exchange the ISN is incremented by 1 to produce
    /// the first data-carrying sequence number.
    pub const fn init(&mut self, isn: u32) {
        self.next_seq = isn.wrapping_add(1);
        self.state = ReassemblyState::Active;
    }

    /// Feed a TCP segment into the buffer.
    ///
    /// Returns the number of bytes newly appended to [`Self::stream`].
    pub fn feed(&mut self, seg: &TcpSegment) -> usize {
        let seq = seg.seq;
        let data = &seg.payload;

        if seg.flags.contains(TcpFlags::SYN) {
            self.state = ReassemblyState::SynSeen { isn: seq };
            self.next_seq = seq.wrapping_add(1);
            return 0;
        }

        if seg.flags.contains(TcpFlags::RST) {
            self.state = ReassemblyState::Reset;
            return 0;
        }

        if seg.flags.contains(TcpFlags::FIN) {
            self.state = ReassemblyState::FinReceived;
        }

        if data.is_empty() {
            return 0;
        }

        self.deliver(seq, data)
    }

    /// Deliver raw bytes at `seq` into the reassembly buffer.
    ///
    /// Returns the number of bytes newly added to [`Self::stream`].
    pub fn deliver(&mut self, seq: u32, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        let data_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let seg_end = seq.wrapping_add(data_len);

        // Fully duplicate — segment ends at or before next expected.
        let dist_to_end = seg_end.wrapping_sub(self.next_seq);
        if dist_to_end > 0x8000_0000 {
            self.bytes_dropped += data.len() as u64;
            return 0;
        }

        if seq == self.next_seq {
            // In-order: append directly.
            self.stream.extend_from_slice(data);
            self.next_seq = seg_end;
            self.bytes_consumed += data.len() as u64;
            let mut added = data.len();
            added += self.drain_ooo();
            return added;
        }

        let dist_to_seq = seq.wrapping_sub(self.next_seq);
        if dist_to_seq < 0x8000_0000 {
            // Out-of-order: record a gap and buffer the segment.
            let gap = StreamGap {
                expected_seq: self.next_seq,
                received_seq: seq,
                missing_bytes: dist_to_seq,
            };
            // Avoid duplicate gap entries.
            if !self.gaps.iter().any(|g| g.expected_seq == gap.expected_seq) {
                self.gaps.push(gap);
            }
            self.out_of_order.insert(seq, data.to_vec());
            return 0;
        }

        // Partial overlap from behind: segment starts before next_seq.
        let seen = self.next_seq.wrapping_sub(seq) as usize;
        if seen < data.len() {
            let trimmed = &data[seen..];
            self.stream.extend_from_slice(trimmed);
            self.next_seq = self.next_seq.wrapping_add(
                u32::try_from(trimmed.len()).unwrap_or(u32::MAX),
            );
            self.bytes_consumed += trimmed.len() as u64;
            let mut added = trimmed.len();
            added += self.drain_ooo();
            return added;
        }

        self.bytes_dropped += data.len() as u64;
        0
    }

    /// Drain buffered out-of-order segments now that `next_seq` has advanced.
    fn drain_ooo(&mut self) -> usize {
        let mut added = 0;
        loop {
            // Check if the first OOO segment can now be delivered.
            let first_seq = match self.out_of_order.first() {
                None => break,
                Some(s) => s.seq,
            };

            let dist = first_seq.wrapping_sub(self.next_seq);
            if dist > 0x8000_0000 {
                // Still ahead — nothing to deliver.
                break;
            }

            if let Some(seg) = self.out_of_order.pop_at(first_seq) {
                let seen = self.next_seq.wrapping_sub(seg.seq) as usize;
                if seen >= seg.data.len() {
                    // Fully covered — discard.
                    continue;
                }
                let trimmed = &seg.data[seen..];
                self.stream.extend_from_slice(trimmed);
                self.next_seq = self.next_seq.wrapping_add(
                    u32::try_from(trimmed.len()).unwrap_or(u32::MAX),
                );
                self.bytes_consumed += trimmed.len() as u64;
                added += trimmed.len();
            } else {
                break;
            }
        }
        self.gaps.retain(|g| {
            let dist = g.received_seq.wrapping_sub(self.next_seq);
            dist > 0 && dist < 0x8000_0000
        });
        added
    }

    /// Number of out-of-order segments pending delivery.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.out_of_order.len()
    }

    /// Total bytes buffered out-of-order.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.out_of_order.buffered_bytes()
    }

    /// True if the stream has been reset.
    #[must_use]
    pub const fn is_reset(&self) -> bool {
        matches!(self.state, ReassemblyState::Reset)
    }

    /// True if the stream has received a FIN.
    #[must_use]
    pub const fn is_fin(&self) -> bool {
        matches!(self.state, ReassemblyState::FinReceived)
    }

    /// Drain all reassembled bytes and return them, clearing the internal buffer.
    pub fn drain_stream(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stream)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TcpStream — bidirectional TCP stream
// ─────────────────────────────────────────────────────────────────────────────

/// Direction relative to the TCP session initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientToServer => write!(f, "c2s"),
            Self::ServerToClient => write!(f, "s2c"),
        }
    }
}

/// A fully bidirectional TCP stream with separate reassembly for each direction.
#[derive(Debug, Default)]
pub struct TcpStream {
    /// 5-tuple key (protocol implicit as TCP).
    pub key: Option<FlowKey>,
    /// Client-to-server reassembly buffer.
    pub c2s: ReassemblyBuffer,
    /// Server-to-client reassembly buffer.
    pub s2c: ReassemblyBuffer,
    /// Timestamp of first packet (nanoseconds since epoch).
    pub first_seen: u64,
    /// Timestamp of most recent packet.
    pub last_seen: u64,
    /// Total segments processed.
    pub segment_count: u64,
}

impl TcpStream {
    /// Create a new bidirectional TCP stream.
    #[must_use]
    pub fn new(key: FlowKey, now: u64) -> Self {
        Self {
            key: Some(key),
            c2s: ReassemblyBuffer::new(),
            s2c: ReassemblyBuffer::new(),
            first_seen: now,
            last_seen: now,
            segment_count: 0,
        }
    }

    /// Feed a TCP segment in the given direction.
    ///
    /// Returns the number of bytes newly added to the in-order stream for that
    /// direction.
    pub fn feed(&mut self, dir: Direction, seg: &TcpSegment, now: u64) -> usize {
        self.last_seen = now;
        self.segment_count += 1;
        match dir {
            Direction::ClientToServer => self.c2s.feed(seg),
            Direction::ServerToClient => self.s2c.feed(seg),
        }
    }

    /// Initialise one direction with its ISN.
    pub const fn init_direction(&mut self, dir: Direction, isn: u32) {
        match dir {
            Direction::ClientToServer => self.c2s.init(isn),
            Direction::ServerToClient => self.s2c.init(isn),
        }
    }

    /// Return a reference to the in-order data for the given direction.
    #[must_use]
    pub fn data(&self, dir: Direction) -> &[u8] {
        match dir {
            Direction::ClientToServer => &self.c2s.stream,
            Direction::ServerToClient => &self.s2c.stream,
        }
    }

    /// Drain in-order data for the given direction.
    pub fn drain(&mut self, dir: Direction) -> Vec<u8> {
        match dir {
            Direction::ClientToServer => self.c2s.drain_stream(),
            Direction::ServerToClient => self.s2c.drain_stream(),
        }
    }

    /// True if both directions have received a FIN or RST.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        (self.c2s.is_fin() || self.c2s.is_reset())
            && (self.s2c.is_fin() || self.s2c.is_reset())
    }

    /// All gaps detected across both directions.
    #[must_use]
    pub fn all_gaps(&self) -> Vec<&StreamGap> {
        self.c2s.gaps.iter().chain(self.s2c.gaps.iter()).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TcpReassembler — session table
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the reassembler.
#[derive(Debug, Clone)]
pub struct ReassemblerConfig {
    /// Maximum number of concurrent TCP sessions to track.
    pub max_sessions: usize,
    /// Maximum bytes to buffer per direction (OOO + stream).
    pub max_buffer_bytes: usize,
    /// Session idle timeout in nanoseconds.
    pub idle_timeout_ns: u64,
    /// If `true`, sessions are closed and evicted once both FINs are seen.
    pub close_on_fin: bool,
}

impl Default for ReassemblerConfig {
    fn default() -> Self {
        Self {
            max_sessions: 65536,
            max_buffer_bytes: 4 * 1024 * 1024, // 4 MiB
            idle_timeout_ns: 60_000_000_000,   // 60 s
            close_on_fin: true,
        }
    }
}

/// Statistics maintained by the [`TcpReassembler`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReassemblerStats {
    /// Total TCP segments processed.
    pub segments_processed: u64,
    /// Total sessions created.
    pub sessions_created: u64,
    /// Sessions currently open.
    pub sessions_open: usize,
    /// Sessions evicted due to timeout or capacity limit.
    pub sessions_evicted: u64,
    /// Total bytes reassembled across all sessions.
    pub bytes_reassembled: u64,
    /// Total gaps detected.
    pub gaps_detected: u64,
    /// Total segments dropped (duplicate or out of window).
    pub segments_dropped: u64,
}

/// Errors specific to the reassembler.
#[derive(Debug, thiserror::Error)]
pub enum ReassemblyError {
    #[error("session table full ({0} sessions)")]
    TableFull(usize),
    #[error("buffer limit exceeded for session {0}")]
    BufferLimitExceeded(String),
    #[error("parse error: {0}")]
    Parse(#[from] NetError),
}

/// A TCP stream reassembler that tracks multiple concurrent sessions.
///
/// For each new 4-tuple flow it creates a [`TcpStream`] and routes subsequent
/// segments to the correct session and direction.
#[derive(Debug)]
pub struct TcpReassembler {
    /// Session table keyed by canonical flow key.
    sessions: HashMap<FlowKey, TcpStream>,
    /// Configuration.
    pub config: ReassemblerConfig,
    /// Accumulated statistics.
    pub stats: ReassemblerStats,
}

impl TcpReassembler {
    /// Create a new reassembler with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            config: ReassemblerConfig::default(),
            stats: ReassemblerStats::default(),
        }
    }

    /// Create a reassembler with custom configuration.
    #[must_use]
    pub fn with_config(config: ReassemblerConfig) -> Self {
        Self {
            sessions: HashMap::new(),
            config,
            stats: ReassemblerStats::default(),
        }
    }

    /// Process a raw TCP segment given the enclosing IP flow.
    ///
    /// `src_ip`, `dst_ip`, `seg` must already be parsed.
    /// `now_ns` is the packet timestamp in nanoseconds.
    ///
    /// Returns the number of bytes newly reassembled for the matching stream
    /// direction.
    ///
    /// # Errors
    /// Returns [`ReassemblyError::TableFull`] when the session limit is reached
    /// and no eviction was possible.
    ///
    /// # Panics
    /// Panics only if the session entry vanishes between insert and lookup,
    /// which is impossible while holding `&mut self`.
    pub fn process(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        seg: &TcpSegment,
        now_ns: u64,
    ) -> Result<usize, ReassemblyError> {
        let key = FlowKey::new(src_ip, seg.src_port, dst_ip, seg.dst_port);
        let canon = key.canonical();
        let dir = if key == canon {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };

        self.stats.segments_processed += 1;

        // Create session if needed.
        if !self.sessions.contains_key(&canon) {
            if self.sessions.len() >= self.config.max_sessions {
                // Attempt to evict the oldest idle session.
                if !self.evict_one(now_ns) {
                    return Err(ReassemblyError::TableFull(self.sessions.len()));
                }
            }
            let stream = TcpStream::new(canon.clone(), now_ns);
            self.sessions.insert(canon.clone(), stream);
            self.stats.sessions_created += 1;
        }

        let session = self.sessions.get_mut(&canon).expect("just inserted");

        // Buffer limit check.
        let c2s_buf = session.c2s.stream.len() + session.c2s.pending_bytes();
        let s2c_buf = session.s2c.stream.len() + session.s2c.pending_bytes();
        if c2s_buf + s2c_buf > self.config.max_buffer_bytes {
            self.stats.segments_dropped += 1;
            return Err(ReassemblyError::BufferLimitExceeded(canon.to_string()));
        }

        // Snapshot gap counts before feeding so we can compute the delta.
        let gaps_before = session.c2s.gaps.len() + session.s2c.gaps.len();

        let added = session.feed(dir, seg, now_ns);
        self.stats.bytes_reassembled += added as u64;

        // Gap accounting: only count newly discovered gaps this call.
        let gaps_after = session.c2s.gaps.len() + session.s2c.gaps.len();
        let delta = gaps_after.saturating_sub(gaps_before);
        self.stats.gaps_detected = self.stats.gaps_detected.saturating_add(delta as u64);

        // Auto-close on FIN.
        if self.config.close_on_fin && session.is_closed() {
            self.sessions.remove(&canon);
            self.stats.sessions_evicted += 1;
        } else {
            self.stats.sessions_open = self.sessions.len();
        }

        Ok(added)
    }

    /// Look up a session by canonical flow key.
    #[must_use]
    pub fn get_session(&self, key: &FlowKey) -> Option<&TcpStream> {
        let canon = key.canonical();
        self.sessions.get(&canon)
    }

    /// Drain the reassembled data for a specific session and direction.
    ///
    /// Returns the drained bytes, or `None` if no such session exists.
    pub fn drain(&mut self, key: &FlowKey, dir: Direction) -> Option<Vec<u8>> {
        let canon = key.canonical();
        self.sessions.get_mut(&canon).map(|s| s.drain(dir))
    }

    /// Remove timed-out sessions.
    ///
    /// Returns the number of sessions removed.
    pub fn expire(&mut self, now_ns: u64) -> usize {
        let timeout = self.config.idle_timeout_ns;
        let mut expired = Vec::new();
        for (key, session) in &self.sessions {
            if now_ns.saturating_sub(session.last_seen) >= timeout {
                expired.push(key.clone());
            }
        }
        let count = expired.len();
        for key in expired {
            self.sessions.remove(&key);
        }
        self.stats.sessions_evicted += count as u64;
        self.stats.sessions_open = self.sessions.len();
        count
    }

    /// Forcibly remove a session.
    pub fn remove(&mut self, key: &FlowKey) -> Option<TcpStream> {
        let canon = key.canonical();
        let r = self.sessions.remove(&canon);
        self.stats.sessions_open = self.sessions.len();
        r
    }

    /// Return all currently tracked flow keys.
    #[must_use]
    pub fn flow_keys(&self) -> Vec<&FlowKey> {
        self.sessions.keys().collect()
    }

    /// Current number of tracked sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Evict the session with the oldest `last_seen` timestamp.
    ///
    /// Returns `true` if a session was evicted.
    fn evict_one(&mut self, _now_ns: u64) -> bool {
        let oldest_key = self
            .sessions
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest_key {
            self.sessions.remove(&k);
            self.stats.sessions_evicted += 1;
            self.stats.sessions_open = self.sessions.len();
            return true;
        }
        false
    }
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn seg(seq: u32, data: &[u8], flags: TcpFlags) -> TcpSegment {
        TcpSegment {
            src_port: 1234,
            dst_port: 80,
            seq,
            ack: 0,
            flags,
            window: 65535,
            payload: data.to_vec(),
        }
    }

    fn addrs() -> (IpAddr, IpAddr) {
        (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        )
    }

    #[test]
    fn in_order_delivery() {
        let mut buf = ReassemblyBuffer::new();
        buf.init(99);
        let s = seg(100, b"hello", TcpFlags::empty());
        buf.feed(&s);
        assert_eq!(&buf.stream, b"hello");
        assert_eq!(buf.next_seq, 105);
    }

    #[test]
    fn out_of_order_then_gap_fill() {
        let mut buf = ReassemblyBuffer::new();
        buf.init(99);
        // Deliver segment at 106 before 100.
        buf.deliver(106, b"world");
        assert_eq!(buf.stream.len(), 0);
        assert_eq!(buf.gaps.len(), 1);
        // Now deliver in-order.
        buf.deliver(100, b"hello ");
        assert_eq!(&buf.stream, b"hello world");
        assert_eq!(buf.gaps.len(), 0);
    }

    #[test]
    fn duplicate_segment_dropped() {
        let mut buf = ReassemblyBuffer::new();
        buf.init(0);
        buf.deliver(1, b"abc");
        let dropped_before = buf.bytes_dropped;
        buf.deliver(1, b"abc"); // duplicate
        assert!(buf.bytes_dropped > dropped_before);
        assert_eq!(&buf.stream, b"abc");
    }

    #[test]
    fn reassembler_basic() {
        let mut r = TcpReassembler::new();
        let (src, dst) = addrs();
        let syn_seg = seg(0, &[], TcpFlags::SYN);
        r.process(src, dst, &syn_seg, 1000).unwrap();
        // Deliver data
        let data_seg = seg(1, b"GET / HTTP/1.0\r\n", TcpFlags::empty());
        let added = r.process(src, dst, &data_seg, 2000).unwrap();
        assert_eq!(added, 16);
        let key = FlowKey::new(src, 1234, dst, 80);
        let bytes = r.drain(&key, Direction::ClientToServer).unwrap();
        assert_eq!(&bytes, b"GET / HTTP/1.0\r\n");
    }

    #[test]
    fn reassembler_expire() {
        let mut r = TcpReassembler::new();
        r.config.idle_timeout_ns = 1000;
        let (src, dst) = addrs();
        let s = seg(1, b"x", TcpFlags::empty());
        r.process(src, dst, &s, 0).unwrap();
        assert_eq!(r.session_count(), 1);
        let evicted = r.expire(2000);
        assert_eq!(evicted, 1);
        assert_eq!(r.session_count(), 0);
    }

    #[test]
    fn segment_map_insert_and_pop() {
        let mut map = SegmentMap::new();
        map.insert(10, b"hello".to_vec());
        map.insert(20, b"world".to_vec());
        let s = map.pop_at(10).unwrap();
        assert_eq!(&s.data, b"hello");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn stream_gap_display() {
        let g = StreamGap {
            expected_seq: 100,
            received_seq: 200,
            missing_bytes: 100,
        };
        let s = g.to_string();
        assert!(s.contains("gap"));
        assert!(s.contains("100"));
    }

    #[test]
    fn tcp_stream_bidirectional() {
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            9000,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            443,
        );
        let mut stream = TcpStream::new(key, 0);
        stream.init_direction(Direction::ClientToServer, 0);
        stream.init_direction(Direction::ServerToClient, 1000);
        let s = seg(1, b"request", TcpFlags::empty());
        stream.feed(Direction::ClientToServer, &s, 100);
        assert_eq!(stream.data(Direction::ClientToServer), b"request");
        assert_eq!(stream.data(Direction::ServerToClient).len(), 0);
    }
}
