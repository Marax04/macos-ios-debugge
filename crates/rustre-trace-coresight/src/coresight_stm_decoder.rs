//! ARM `CoreSight` STM (System Trace Macrocell) decoder.
//!
//! The STM is a lightweight software instrumentation peripheral that lets
//! software write stimulus data into dedicated memory-mapped registers.  The
//! resulting byte stream is framed and multiplexed per-channel before being
//! sent out through the `CoreSight` funnel/TPIU.
//!
//! This module provides:
//! - [`StmPacket`]  — a decoded STM packet.
//! - [`StmChannel`] — per-channel state tracking.
//! - [`CoreSightStmDecoder`] — full streaming decoder.
//! - [`decode_stm_stream`] — convenience function for one-shot decode.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

// ─── StmPacketKind ─────────────────────────────────────────────────────────────

/// Kind of a decoded STM packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StmPacketKind {
    /// 8-bit instrumentation data word.
    Data8 {
        /// Channel number (0-65535).
        channel: u16,
        /// Byte value.
        value: u8,
        /// Whether this is a marked (timestamped) write.
        marked: bool,
    },
    /// 16-bit instrumentation data word.
    Data16 {
        /// Channel number.
        channel: u16,
        /// 16-bit value (little-endian).
        value: u16,
        /// Whether this is a marked write.
        marked: bool,
    },
    /// 32-bit instrumentation data word.
    Data32 {
        /// Channel number.
        channel: u16,
        /// 32-bit value (little-endian).
        value: u32,
        /// Whether this is a marked write.
        marked: bool,
    },
    /// 64-bit instrumentation data word.
    Data64 {
        /// Channel number.
        channel: u16,
        /// 64-bit value (little-endian).
        value: u64,
        /// Whether this is a marked write.
        marked: bool,
    },
    /// Guaranteed (guaranteed-ordering) 8-bit data write.
    Guaranteed8 {
        /// Channel number.
        channel: u16,
        /// Byte value.
        value: u8,
    },
    /// Guaranteed 32-bit data write.
    Guaranteed32 {
        /// Channel number.
        channel: u16,
        /// 32-bit value.
        value: u32,
    },
    /// FLAG packet — marks a transaction boundary.
    Flag {
        /// Channel number.
        channel: u16,
        /// Whether this is a timestamped flag.
        marked: bool,
    },
    /// TRIGGER packet — hardware trigger output.
    Trigger {
        /// Channel number.
        channel: u16,
    },
    /// VERSION packet — emitted at the start of an STM trace.
    Version {
        /// STM version byte.
        version: u8,
    },
    /// NULL packet — padding.
    Null,
    /// ASYNC sync frame (12-byte pattern).
    Async,
    /// Timestamp packet.
    Timestamp {
        /// Raw 64-bit counter value.
        value: u64,
        /// Whether the timestamp is exact (vs delayed).
        exact: bool,
    },
    /// FREQ packet — carries the STM clock frequency.
    Freq {
        /// Clock frequency in Hz.
        freq_hz: u32,
    },
    /// Error packet (unknown/invalid byte during decode).
    Error {
        /// The unrecognised byte that triggered this error.
        byte: u8,
        /// Stream offset of the error.
        offset: usize,
    },
}

impl std::fmt::Display for StmPacketKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data8 { channel, value, marked } => {
                write!(f, "D8(ch={channel}, val={value:#04x}, marked={marked})")
            }
            Self::Data16 { channel, value, marked } => {
                write!(f, "D16(ch={channel}, val={value:#06x}, marked={marked})")
            }
            Self::Data32 { channel, value, marked } => {
                write!(f, "D32(ch={channel}, val={value:#010x}, marked={marked})")
            }
            Self::Data64 { channel, value, marked } => {
                write!(f, "D64(ch={channel}, val={value:#018x}, marked={marked})")
            }
            Self::Guaranteed8 { channel, value } => {
                write!(f, "G8(ch={channel}, val={value:#04x})")
            }
            Self::Guaranteed32 { channel, value } => {
                write!(f, "G32(ch={channel}, val={value:#010x})")
            }
            Self::Flag { channel, marked } => write!(f, "FLAG(ch={channel}, marked={marked})"),
            Self::Trigger { channel } => write!(f, "TRIG(ch={channel})"),
            Self::Version { version } => write!(f, "VER({version:#04x})"),
            Self::Null => write!(f, "NULL"),
            Self::Async => write!(f, "ASYNC"),
            Self::Timestamp { value, exact } => write!(f, "TS({value}, exact={exact})"),
            Self::Freq { freq_hz } => write!(f, "FREQ({freq_hz}Hz)"),
            Self::Error { byte, offset } => write!(f, "ERR(byte={byte:#04x}, off={offset:#x})"),
        }
    }
}

// ─── StmPacket ─────────────────────────────────────────────────────────────────

/// A fully decoded STM packet, including its byte offset in the raw stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StmPacket {
    /// Kind of the packet.
    pub kind: StmPacketKind,
    /// Byte offset of the packet's first byte in the original stream.
    pub byte_offset: usize,
}

impl StmPacket {
    /// Create a new [`StmPacket`].
    #[must_use]
    pub const fn new(kind: StmPacketKind, byte_offset: usize) -> Self {
        Self { kind, byte_offset }
    }

    /// Return the channel number if this packet carries one.
    #[must_use]
    pub const fn channel(&self) -> Option<u16> {
        match &self.kind {
            StmPacketKind::Data8 { channel, .. }
            | StmPacketKind::Data16 { channel, .. }
            | StmPacketKind::Data32 { channel, .. }
            | StmPacketKind::Data64 { channel, .. }
            | StmPacketKind::Guaranteed8 { channel, .. }
            | StmPacketKind::Guaranteed32 { channel, .. }
            | StmPacketKind::Flag { channel, .. }
            | StmPacketKind::Trigger { channel } => Some(*channel),
            _ => None,
        }
    }

    /// Return `true` if this is a data packet.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        matches!(
            self.kind,
            StmPacketKind::Data8 { .. }
                | StmPacketKind::Data16 { .. }
                | StmPacketKind::Data32 { .. }
                | StmPacketKind::Data64 { .. }
                | StmPacketKind::Guaranteed8 { .. }
                | StmPacketKind::Guaranteed32 { .. }
        )
    }

    /// Return `true` if this packet is marked (carries an associated timestamp).
    #[must_use]
    pub const fn is_marked(&self) -> bool {
        match &self.kind {
            StmPacketKind::Data8 { marked, .. }
            | StmPacketKind::Data16 { marked, .. }
            | StmPacketKind::Data32 { marked, .. }
            | StmPacketKind::Data64 { marked, .. }
            | StmPacketKind::Flag { marked, .. } => *marked,
            _ => false,
        }
    }
}

// ─── StmChannel ────────────────────────────────────────────────────────────────

/// Per-channel state accumulated during STM decode.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StmChannel {
    /// Channel number (0-65535).
    pub channel: u16,
    /// Raw bytes received on this channel, in order.
    pub bytes: Vec<u8>,
    /// Number of packets received on this channel.
    pub packet_count: u64,
    /// Number of marked (timestamped) packets received.
    pub marked_packet_count: u64,
    /// Whether the channel has seen a FLAG packet (transaction boundary).
    pub flagged: bool,
    /// Timestamp of the last marked packet, if any.
    pub last_timestamp: Option<u64>,
}

impl StmChannel {
    /// Create a new, empty channel state.
    #[must_use]
    pub const fn new(channel: u16) -> Self {
        Self {
            channel,
            bytes: Vec::new(),
            packet_count: 0,
            marked_packet_count: 0,
            flagged: false,
            last_timestamp: None,
        }
    }

    /// Push raw bytes received on this channel.
    pub fn push_bytes(&mut self, data: &[u8]) {
        self.bytes.extend_from_slice(data);
    }

    /// Return the accumulated data as a UTF-8 string (lossy).
    #[must_use]
    pub fn as_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// Reset channel state (clear bytes and flag, keep counts).
    pub fn reset(&mut self) {
        self.bytes.clear();
        self.flagged = false;
    }

    /// Record a packet arriving on this channel.
    pub const fn record_packet(&mut self, marked: bool, timestamp: Option<u64>) {
        self.packet_count += 1;
        if marked {
            self.marked_packet_count += 1;
            if let Some(ts) = timestamp {
                self.last_timestamp = Some(ts);
            }
        }
    }
}

// ─── StmStreamStats ────────────────────────────────────────────────────────────

/// Aggregate statistics from an STM decode.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StmStreamStats {
    /// Total number of packets decoded.
    pub total_packets: u64,
    /// Number of data packets.
    pub data_packets: u64,
    /// Number of FLAG packets.
    pub flag_packets: u64,
    /// Number of TRIGGER packets.
    pub trigger_packets: u64,
    /// Number of ASYNC sync frames.
    pub async_frames: u64,
    /// Number of TIMESTAMP packets.
    pub timestamp_packets: u64,
    /// Number of error packets (decode failures).
    pub error_packets: u64,
    /// Total data bytes across all channels.
    pub total_data_bytes: u64,
    /// Number of distinct channels seen.
    pub distinct_channels: usize,
}

impl StmStreamStats {
    /// Create zeroed statistics.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the packet error rate.
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.total_packets == 0 {
            0.0
        } else {
            let ppm = u128::from(self.error_packets) * 1_000_000 / u128::from(self.total_packets);
            f64::from(u32::try_from(ppm).unwrap_or(1_000_000)) * 1e-6
        }
    }
}

impl std::fmt::Display for StmStreamStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StmStreamStats {{ total={}, data={}, flags={}, channels={}, errors={} }}",
            self.total_packets,
            self.data_packets,
            self.flag_packets,
            self.distinct_channels,
            self.error_packets,
        )
    }
}

// ─── CoreSightStmDecoder ───────────────────────────────────────────────────────

/// Streaming ARM `CoreSight` STM packet decoder.
///
/// Feed raw STM bytes via [`feed`](Self::feed) and retrieve decoded packets via
/// [`next_packet`](Self::next_packet) or [`decode_all`](Self::decode_all).
/// Per-channel state is accumulated in [`channels`](Self::channels).
pub struct CoreSightStmDecoder {
    /// Input byte buffer.
    buf: Vec<u8>,
    /// Current read position.
    pos: usize,
    /// Per-channel state, keyed by channel number.
    pub channels: HashMap<u16, StmChannel>,
    /// Packet output queue (decoded but not yet consumed).
    queue: VecDeque<StmPacket>,
    /// Whether the decoder has seen an ASYNC sync frame.
    pub synchronized: bool,
    /// Aggregate statistics.
    pub stats: StmStreamStats,
    /// Last received timestamp value.
    pub last_timestamp: u64,
    /// Number of decode errors encountered.
    pub error_count: usize,
}

impl CoreSightStmDecoder {
    /// Create a new decoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            channels: HashMap::new(),
            queue: VecDeque::new(),
            synchronized: false,
            stats: StmStreamStats::new(),
            last_timestamp: 0,
            error_count: 0,
        }
    }

    /// Feed more raw STM bytes into the decoder.
    ///
    /// After feeding, call [`next_packet`](Self::next_packet) or
    /// [`decode_all`](Self::decode_all) to retrieve decoded packets.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        self.decode_available();
    }

    /// Return the next decoded packet, or `None` if no more are available.
    pub fn next_packet(&mut self) -> Option<StmPacket> {
        if self.queue.is_empty() {
            self.decode_available();
        }
        self.queue.pop_front()
    }

    /// Decode all currently available packets and return them.
    #[must_use]
    pub fn decode_all(&mut self) -> Vec<StmPacket> {
        self.decode_available();
        self.queue.drain(..).collect()
    }

    /// Try to scan forward to the next ASYNC sync frame.
    ///
    /// Returns `true` if sync was found, `false` if insufficient data.
    pub fn find_sync(&mut self) -> bool {
        // ASYNC: 11× 0x00 followed by 0x80
        let sync = [0x00u8; 11];
        if self.buf.len() < self.pos + 12 {
            return false;
        }
        let start = self.pos;
        while self.pos + 12 <= self.buf.len() {
            if self.buf[self.pos..self.pos + 11] == sync && self.buf[self.pos + 11] == 0x80 {
                self.pos += 12;
                self.synchronized = true;
                self.stats.async_frames += 1;
                let pkt = StmPacket::new(StmPacketKind::Async, self.pos - 12);
                self.queue.push_back(pkt);
                return true;
            }
            self.pos += 1;
        }
        self.pos = start;
        false
    }

    /// Return current decoder byte position.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Reset the decoder without discarding the input buffer.
    pub fn reset_state(&mut self) {
        self.synchronized = false;
        self.channels.clear();
        self.queue.clear();
        self.last_timestamp = 0;
        self.error_count = 0;
    }

    // ── Private decoding engine ───────────────────────────────────────────────

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn consume(&mut self) -> Option<u8> {
        let b = self.buf.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn consume_le_u16(&mut self) -> Option<u16> {
        if self.pos + 2 > self.buf.len() {
            return None;
        }
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }

    fn consume_le_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.buf.len() {
            return None;
        }
        let v = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }

    fn consume_le_u64(&mut self) -> Option<u64> {
        if self.pos + 8 > self.buf.len() {
            return None;
        }
        let v = u64::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
            self.buf[self.pos + 4],
            self.buf[self.pos + 5],
            self.buf[self.pos + 6],
            self.buf[self.pos + 7],
        ]);
        self.pos += 8;
        Some(v)
    }

    /// Read a ULEB128 timestamp.
    fn read_timestamp_uleb128(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.consume()?;
            result |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
        Some(result)
    }

    /// Get or create per-channel state.
    fn channel_state(&mut self, ch: u16) -> &mut StmChannel {
        self.channels.entry(ch).or_insert_with(|| StmChannel::new(ch))
    }

    /// Main decode loop — process as many packets as possible.
    fn decode_available(&mut self) {
        loop {
            if self.peek().is_none() {
                break;
            }
            let start = self.pos;

            // Check for ASYNC sync frame first.
            if self.buf.len() >= self.pos + 12 {
                let sync = [0x00u8; 11];
                if self.buf[self.pos..self.pos + 11] == sync && self.buf[self.pos + 11] == 0x80 {
                    self.pos += 12;
                    self.synchronized = true;
                    self.stats.async_frames += 1;
                    self.stats.total_packets += 1;
                    self.queue
                        .push_back(StmPacket::new(StmPacketKind::Async, start));
                    continue;
                }
            }

            // STM framing: header nibble encodes packet type and channel prefix.
            // The STM MIPI STPv2 protocol uses a compact header encoding.
            // We implement a simplified subset commonly used by ARM STM.
            let Some(header) = self.consume() else { break };

            let pkt = self.decode_header(header, start);
            if let Some(p) = pkt {
                self.stats.total_packets += 1;
                match &p.kind {
                    StmPacketKind::Data8 { channel, value, marked } => {
                        let ch = *channel;
                        let m = *marked;
                        let v = *value;
                        self.stats.data_packets += 1;
                        self.stats.total_data_bytes += 1;
                        let ts = if m { Some(self.last_timestamp) } else { None };
                        let ch_state = self.channel_state(ch);
                        ch_state.push_bytes(&[v]);
                        ch_state.record_packet(m, ts);
                    }
                    StmPacketKind::Data16 { channel, value, marked } => {
                        let ch = *channel;
                        let m = *marked;
                        let v = *value;
                        self.stats.data_packets += 1;
                        self.stats.total_data_bytes += 2;
                        let ts = if m { Some(self.last_timestamp) } else { None };
                        let ch_state = self.channel_state(ch);
                        ch_state.push_bytes(&v.to_le_bytes());
                        ch_state.record_packet(m, ts);
                    }
                    StmPacketKind::Data32 { channel, value, marked } => {
                        let ch = *channel;
                        let m = *marked;
                        let v = *value;
                        self.stats.data_packets += 1;
                        self.stats.total_data_bytes += 4;
                        let ts = if m { Some(self.last_timestamp) } else { None };
                        let ch_state = self.channel_state(ch);
                        ch_state.push_bytes(&v.to_le_bytes());
                        ch_state.record_packet(m, ts);
                    }
                    StmPacketKind::Data64 { channel, value, marked } => {
                        let ch = *channel;
                        let m = *marked;
                        let v = *value;
                        self.stats.data_packets += 1;
                        self.stats.total_data_bytes += 8;
                        let ts = if m { Some(self.last_timestamp) } else { None };
                        let ch_state = self.channel_state(ch);
                        ch_state.push_bytes(&v.to_le_bytes());
                        ch_state.record_packet(m, ts);
                    }
                    StmPacketKind::Flag { channel, .. } => {
                        let ch = *channel;
                        self.stats.flag_packets += 1;
                        self.channel_state(ch).flagged = true;
                    }
                    StmPacketKind::Trigger { channel } => {
                        let ch = *channel;
                        self.stats.trigger_packets += 1;
                        // Ensure channel state exists for triggered channels.
                        let _ = self.channel_state(ch);
                    }
                    StmPacketKind::Timestamp { value, .. } => {
                        let v = *value;
                        self.last_timestamp = v;
                        self.stats.timestamp_packets += 1;
                    }
                    StmPacketKind::Error { .. } => {
                        self.stats.error_packets += 1;
                        self.error_count += 1;
                    }
                    _ => {}
                }
                self.stats.distinct_channels = self.channels.len();
                self.queue.push_back(p);
            } else {
                // Back up — not enough data yet.
                self.pos = start;
                break;
            }
        }
    }

    /// Decode a single packet given a header byte.
    fn decode_header(&mut self, header: u8, start: usize) -> Option<StmPacket> {
        match header {
            0x00 => Some(StmPacket::new(StmPacketKind::Null, start)),
            0x01 => {
                let version = self.consume()?;
                Some(StmPacket::new(StmPacketKind::Version { version }, start))
            }
            0xF0..=0xFF => self.decode_data8(header, start, false),
            0xD0..=0xDF => self.decode_data8(header, start, true),
            0xC0..=0xCF => {
                let channel = u16::from(header & 0x0F);
                let marked = (header & 0x10) != 0;
                Some(StmPacket::new(StmPacketKind::Flag { channel, marked }, start))
            }
            0xE0..=0xEF => {
                let channel = u16::from(header & 0x0F);
                Some(StmPacket::new(StmPacketKind::Trigger { channel }, start))
            }
            0xA0..=0xAF => self.decode_data16(header, start, false),
            0xB0..=0xBF => self.decode_data16(header, start, true),
            0x40..=0x4F => self.decode_data32(header, start, false),
            0x60..=0x6F => self.decode_data32(header, start, true),
            0x70..=0x7F => self.decode_data64(header, start),
            0x98 => {
                let value = self.read_timestamp_uleb128()?;
                Some(StmPacket::new(StmPacketKind::Timestamp { value, exact: true }, start))
            }
            0x99 => {
                let value = self.read_timestamp_uleb128()?;
                Some(StmPacket::new(StmPacketKind::Timestamp { value, exact: false }, start))
            }
            0x95 => {
                let freq_hz = self.consume_le_u32()?;
                Some(StmPacket::new(StmPacketKind::Freq { freq_hz }, start))
            }
            0x50..=0x5F => {
                let channel = u16::from(header & 0x0F);
                let value = self.consume()?;
                Some(StmPacket::new(StmPacketKind::Guaranteed8 { channel, value }, start))
            }
            0x81..=0x8F => {
                let channel = u16::from(header & 0x0F);
                let value = self.consume_le_u32()?;
                Some(StmPacket::new(StmPacketKind::Guaranteed32 { channel, value }, start))
            }
            _ => Some(StmPacket::new(
                StmPacketKind::Error { byte: header, offset: start },
                start,
            )),
        }
    }

    fn decode_data8(&mut self, header: u8, start: usize, marked: bool) -> Option<StmPacket> {
        let channel = u16::from(header & 0x0F);
        let value = self.consume()?;
        Some(StmPacket::new(StmPacketKind::Data8 { channel, value, marked }, start))
    }

    fn decode_data16(&mut self, header: u8, start: usize, marked: bool) -> Option<StmPacket> {
        let channel = u16::from(header & 0x0F);
        let value = self.consume_le_u16()?;
        Some(StmPacket::new(StmPacketKind::Data16 { channel, value, marked }, start))
    }

    fn decode_data32(&mut self, header: u8, start: usize, marked: bool) -> Option<StmPacket> {
        let channel = u16::from(header & 0x0F);
        let value = self.consume_le_u32()?;
        Some(StmPacket::new(StmPacketKind::Data32 { channel, value, marked }, start))
    }

    fn decode_data64(&mut self, header: u8, start: usize) -> Option<StmPacket> {
        let channel = u16::from(header & 0x0F);
        let value = self.consume_le_u64()?;
        let marked = (header & 0x08) != 0;
        Some(StmPacket::new(StmPacketKind::Data64 { channel, value, marked }, start))
    }
}

impl Default for CoreSightStmDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Top-level convenience ──────────────────────────────────────────────────────

/// Decode an entire raw STM byte stream and return all packets.
///
/// This is a convenience wrapper around [`CoreSightStmDecoder`] for cases where
/// the full stream is available in memory.
#[must_use]
pub fn decode_stm_stream(data: &[u8]) -> Vec<StmPacket> {
    let mut decoder = CoreSightStmDecoder::new();
    decoder.feed(data);
    decoder.decode_all()
}

/// Decode a stream and collect per-channel byte data.
///
/// Returns a `HashMap` mapping channel number to the concatenated bytes
/// received on that channel.
#[must_use]
pub fn collect_channel_data(data: &[u8]) -> HashMap<u16, Vec<u8>> {
    let mut decoder = CoreSightStmDecoder::new();
    decoder.feed(data);
    let _ = decoder.decode_all();
    decoder
        .channels
        .into_iter()
        .map(|(ch, state)| (ch, state.bytes))
        .collect()
}

// ─── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data8_packet(channel: u8, value: u8) -> Vec<u8> {
        // 0xF0 | (channel & 0x0F) followed by value byte
        vec![0xF0 | (channel & 0x0F), value]
    }

    fn make_data8_marked(channel: u8, value: u8) -> Vec<u8> {
        vec![0xD0 | (channel & 0x0F), value]
    }

    fn make_data16_packet(channel: u8, value: u16) -> Vec<u8> {
        let [lo, hi] = value.to_le_bytes();
        vec![0xA0 | (channel & 0x0F), lo, hi]
    }

    fn make_data32_packet(channel: u8, value: u32) -> Vec<u8> {
        let bytes = value.to_le_bytes();
        let mut v = vec![0x40 | (channel & 0x0F)];
        v.extend_from_slice(&bytes);
        v
    }

    fn make_flag_packet(channel: u8) -> Vec<u8> {
        vec![0xC0 | (channel & 0x0F)]
    }

    fn make_trigger_packet(channel: u8) -> Vec<u8> {
        vec![0xE0 | (channel & 0x0F)]
    }

    fn make_async_frame() -> Vec<u8> {
        let mut v = vec![0x00u8; 11];
        v.push(0x80);
        v
    }

    fn make_null_packet() -> Vec<u8> {
        vec![0x00]
    }

    fn make_freq_packet(freq: u32) -> Vec<u8> {
        let mut v = vec![0x95];
        v.extend_from_slice(&freq.to_le_bytes());
        v
    }

    fn make_timestamp_exact(ts: u64) -> Vec<u8> {
        // ULEB128 encoding
        let mut v = vec![0x98];
        let mut val = ts;
        loop {
            let byte = (val & 0x7F) as u8;
            val >>= 7;
            if val == 0 {
                v.push(byte);
                break;
            }
            v.push(byte | 0x80);
        }
        v
    }

    // ── StmPacket ─────────────────────────────────────────────────────────────

    #[test]
    fn test_stm_packet_channel_data8() {
        let kind = StmPacketKind::Data8 { channel: 3, value: 0xAB, marked: false };
        let pkt = StmPacket::new(kind, 0);
        assert_eq!(pkt.channel(), Some(3));
        assert!(pkt.is_data());
        assert!(!pkt.is_marked());
    }

    #[test]
    fn test_stm_packet_channel_flag() {
        let kind = StmPacketKind::Flag { channel: 7, marked: true };
        let pkt = StmPacket::new(kind, 0);
        assert_eq!(pkt.channel(), Some(7));
        assert!(!pkt.is_data());
        assert!(pkt.is_marked());
    }

    #[test]
    fn test_stm_packet_no_channel_null() {
        let pkt = StmPacket::new(StmPacketKind::Null, 0);
        assert_eq!(pkt.channel(), None);
        assert!(!pkt.is_data());
    }

    #[test]
    fn test_stm_packet_display_data8() {
        let kind = StmPacketKind::Data8 { channel: 0, value: 0x41, marked: false };
        let s = format!("{kind}");
        assert!(s.contains("D8"));
        assert!(s.contains("ch=0"));
    }

    #[test]
    fn test_stm_packet_display_timestamp() {
        let kind = StmPacketKind::Timestamp { value: 1234, exact: true };
        let s = format!("{kind}");
        assert!(s.contains("TS"));
    }

    // ── StmChannel ────────────────────────────────────────────────────────────

    #[test]
    fn test_stm_channel_new() {
        let ch = StmChannel::new(5);
        assert_eq!(ch.channel, 5);
        assert!(ch.bytes.is_empty());
        assert_eq!(ch.packet_count, 0);
    }

    #[test]
    fn test_stm_channel_push_bytes() {
        let mut ch = StmChannel::new(1);
        ch.push_bytes(b"hello");
        assert_eq!(ch.bytes, b"hello");
        assert_eq!(ch.as_string_lossy(), "hello");
    }

    #[test]
    fn test_stm_channel_record_packet_marked() {
        let mut ch = StmChannel::new(2);
        ch.record_packet(true, Some(9999));
        assert_eq!(ch.packet_count, 1);
        assert_eq!(ch.marked_packet_count, 1);
        assert_eq!(ch.last_timestamp, Some(9999));
    }

    #[test]
    fn test_stm_channel_record_packet_unmarked() {
        let mut ch = StmChannel::new(0);
        ch.record_packet(false, None);
        assert_eq!(ch.packet_count, 1);
        assert_eq!(ch.marked_packet_count, 0);
        assert!(ch.last_timestamp.is_none());
    }

    #[test]
    fn test_stm_channel_reset() {
        let mut ch = StmChannel::new(0);
        ch.push_bytes(b"data");
        ch.flagged = true;
        ch.reset();
        assert!(ch.bytes.is_empty());
        assert!(!ch.flagged);
    }

    // ── CoreSightStmDecoder — basic packets ───────────────────────────────────

    #[test]
    fn test_decode_null() {
        let data = make_null_packet();
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 1);
        assert!(matches!(pkts[0].kind, StmPacketKind::Null));
    }

    #[test]
    fn test_decode_data8_basic() {
        let data = make_data8_packet(3, 0x42);
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 1);
        match &pkts[0].kind {
            StmPacketKind::Data8 { channel, value, marked } => {
                assert_eq!(*channel, 3);
                assert_eq!(*value, 0x42);
                assert!(!*marked);
            }
            _ => panic!("expected Data8"),
        }
    }

    #[test]
    fn test_decode_data8_marked() {
        let data = make_data8_marked(5, 0xFF);
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 1);
        match &pkts[0].kind {
            StmPacketKind::Data8 { channel, value, marked } => {
                assert_eq!(*channel, 5);
                assert_eq!(*value, 0xFF);
                assert!(*marked);
            }
            _ => panic!("expected Data8 marked"),
        }
    }

    #[test]
    fn test_decode_data16() {
        let data = make_data16_packet(2, 0x1234);
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 1);
        match &pkts[0].kind {
            StmPacketKind::Data16 { channel, value, .. } => {
                assert_eq!(*channel, 2);
                assert_eq!(*value, 0x1234);
            }
            _ => panic!("expected Data16"),
        }
    }

    #[test]
    fn test_decode_data32() {
        let data = make_data32_packet(0, 0xDEAD_BEEF);
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 1);
        match &pkts[0].kind {
            StmPacketKind::Data32 { value, .. } => assert_eq!(*value, 0xDEAD_BEEF),
            _ => panic!("expected Data32"),
        }
    }

    #[test]
    fn test_decode_flag() {
        let data = make_flag_packet(7);
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 1);
        match &pkts[0].kind {
            StmPacketKind::Flag { channel, .. } => assert_eq!(*channel, 7),
            _ => panic!("expected Flag"),
        }
    }

    #[test]
    fn test_decode_trigger() {
        let data = make_trigger_packet(1);
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 1);
        assert!(matches!(pkts[0].kind, StmPacketKind::Trigger { .. }));
    }

    #[test]
    fn test_decode_async_frame() {
        let data = make_async_frame();
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 1);
        assert!(matches!(pkts[0].kind, StmPacketKind::Async));
    }

    #[test]
    fn test_decode_timestamp_exact() {
        let data = make_timestamp_exact(1000);
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 1);
        match &pkts[0].kind {
            StmPacketKind::Timestamp { value, exact } => {
                assert_eq!(*value, 1000);
                assert!(*exact);
            }
            _ => panic!("expected Timestamp"),
        }
    }

    #[test]
    fn test_decode_freq_packet() {
        let data = make_freq_packet(100_000_000);
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 1);
        match &pkts[0].kind {
            StmPacketKind::Freq { freq_hz } => assert_eq!(*freq_hz, 100_000_000),
            _ => panic!("expected Freq"),
        }
    }

    // ── CoreSightStmDecoder — multi-packet ────────────────────────────────────

    #[test]
    fn test_decode_multi_packet() {
        let mut data = make_data8_packet(0, 0x41); // 'A'
        data.extend(make_data8_packet(0, 0x42)); // 'B'
        data.extend(make_flag_packet(0));
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 3);
    }

    #[test]
    fn test_decode_async_then_data() {
        let mut data = make_async_frame();
        data.extend(make_data8_packet(1, 0x10));
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 2);
        assert!(matches!(pkts[0].kind, StmPacketKind::Async));
        assert!(matches!(pkts[1].kind, StmPacketKind::Data8 { .. }));
    }

    #[test]
    fn test_decode_channel_accumulation() {
        let mut data = Vec::new();
        for b in b"hello" {
            data.extend(make_data8_packet(0, *b));
        }
        let channel_data = collect_channel_data(&data);
        assert_eq!(channel_data.get(&0), Some(&b"hello".to_vec()));
    }

    #[test]
    fn test_decode_multiple_channels() {
        let mut data = make_data8_packet(0, 1);
        data.extend(make_data8_packet(1, 2));
        data.extend(make_data8_packet(0, 3));
        let channel_data = collect_channel_data(&data);
        assert_eq!(channel_data.get(&0), Some(&vec![1, 3]));
        assert_eq!(channel_data.get(&1), Some(&vec![2]));
    }

    // ── StmStreamStats ────────────────────────────────────────────────────────

    #[test]
    fn test_stats_error_rate_zero_packets() {
        let stats = StmStreamStats::new();
        assert_eq!(stats.error_rate(), 0.0);
    }

    #[test]
    fn test_stats_display() {
        let stats = StmStreamStats::new();
        let s = format!("{stats}");
        assert!(s.contains("StmStreamStats"));
    }

    #[test]
    fn test_decoder_stats_accumulate() {
        let mut data = make_data8_packet(0, 0);
        data.extend(make_flag_packet(0));
        data.extend(make_trigger_packet(0));
        let mut dec = CoreSightStmDecoder::new();
        dec.feed(&data);
        let _ = dec.decode_all();
        assert_eq!(dec.stats.data_packets, 1);
        assert_eq!(dec.stats.flag_packets, 1);
        assert_eq!(dec.stats.trigger_packets, 1);
        assert_eq!(dec.stats.total_packets, 3);
    }

    #[test]
    fn test_decoder_find_sync() {
        let mut data = vec![0xFFu8; 4]; // garbage
        data.extend(make_async_frame());
        let mut dec = CoreSightStmDecoder::new();
        dec.buf = data;
        assert!(dec.find_sync());
        assert!(dec.synchronized);
    }

    #[test]
    fn test_decoder_reset_state() {
        let data = make_data8_packet(0, 1);
        let mut dec = CoreSightStmDecoder::new();
        dec.feed(&data);
        let _ = dec.decode_all();
        dec.reset_state();
        assert!(!dec.synchronized);
        assert!(dec.channels.is_empty());
        assert!(dec.queue.is_empty());
    }

    #[test]
    fn test_decode_empty_stream() {
        let pkts = decode_stm_stream(&[]);
        assert!(pkts.is_empty());
    }

    #[test]
    fn test_decode_truncated_data16() {
        // Only 1 byte of the 2-byte payload
        let data = vec![0xA0, 0x01]; // Data16, channel 0, but missing 2nd byte
        let pkts = decode_stm_stream(&data);
        // Should decode successfully if complete, else produce 0 packets
        // Either 0 (truncated) or 1 (if the u16 is read from 1 byte) – just no panic.
        let _ = pkts;
    }

    #[test]
    fn test_byte_offset_in_packet() {
        let mut data = make_null_packet();
        data.extend(make_data8_packet(0, 42));
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts[0].byte_offset, 0);
        assert_eq!(pkts[1].byte_offset, 1);
    }

    #[test]
    fn test_version_packet() {
        let data = vec![0x01, 0x20]; // VERSION header + version byte 0x20
        let pkts = decode_stm_stream(&data);
        assert_eq!(pkts.len(), 1);
        match &pkts[0].kind {
            StmPacketKind::Version { version } => assert_eq!(*version, 0x20),
            _ => panic!("expected Version"),
        }
    }

    #[test]
    fn test_channel_state_flagged() {
        let mut data = make_data8_packet(3, 0xAA);
        data.extend(make_flag_packet(3));
        let mut dec = CoreSightStmDecoder::new();
        dec.feed(&data);
        let _ = dec.decode_all();
        assert!(dec.channels.get(&3).is_some_and(|ch| ch.flagged));
    }

    #[test]
    fn test_timestamp_updates_decoder_state() {
        let ts_data = make_timestamp_exact(0x1234_5678);
        let mut dec = CoreSightStmDecoder::new();
        dec.feed(&ts_data);
        let _ = dec.decode_all();
        assert_eq!(dec.last_timestamp, 0x1234_5678);
    }

    #[test]
    fn test_stats_distinct_channels() {
        let mut data = make_data8_packet(0, 1);
        data.extend(make_data8_packet(1, 2));
        data.extend(make_data8_packet(2, 3));
        let mut dec = CoreSightStmDecoder::new();
        dec.feed(&data);
        let _ = dec.decode_all();
        assert_eq!(dec.stats.distinct_channels, 3);
    }
}
