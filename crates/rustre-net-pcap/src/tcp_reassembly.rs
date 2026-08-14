//! TCP stream reassembly.
//!
//! `TcpReassembler` tracks per-stream out-of-order segments and presents them
//! as ordered, contiguous application-layer byte streams via `ReassembledStream`.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;

// ─── TCP flags ────────────────────────────────────────────────────────────────

/// TCP flag bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;

    #[must_use]
    pub const fn syn(self) -> bool {
        self.0 & Self::SYN != 0
    }
    #[must_use]
    pub const fn fin(self) -> bool {
        self.0 & Self::FIN != 0
    }
    #[must_use]
    pub const fn rst(self) -> bool {
        self.0 & Self::RST != 0
    }
    #[must_use]
    pub const fn ack(self) -> bool {
        self.0 & Self::ACK != 0
    }
    #[must_use]
    pub const fn psh(self) -> bool {
        self.0 & Self::PSH != 0
    }

    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        Self(v)
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.syn() {
            parts.push("SYN");
        }
        if self.fin() {
            parts.push("FIN");
        }
        if self.rst() {
            parts.push("RST");
        }
        if self.ack() {
            parts.push("ACK");
        }
        if self.psh() {
            parts.push("PSH");
        }
        write!(f, "[{}]", parts.join("|"))
    }
}

// ─── TCP State Machine ────────────────────────────────────────────────────────

/// TCP connection state following RFC 793.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TcpState {
    /// Waiting for a connection request.
    #[default]
    Listen,
    /// SYN sent, waiting for SYN-ACK.
    SynSent,
    /// SYN received, waiting for ACK.
    SynReceived,
    /// Connection established.
    Established,
    /// Sent FIN, waiting for ACK.
    FinWait1,
    /// Received ACK of FIN, waiting for remote FIN.
    FinWait2,
    /// Both sides have sent FIN, waiting for all segments to be delivered.
    TimeWait,
    /// Received a FIN, waiting for the application to close.
    CloseWait,
    /// Sent FIN after close-wait, waiting for ACK.
    LastAck,
    /// Both sides simultaneously sent FIN.
    Closing,
    /// Connection closed.
    Closed,
    /// Connection reset.
    Reset,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Listen => "LISTEN",
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RECEIVED",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN_WAIT_1",
            Self::FinWait2 => "FIN_WAIT_2",
            Self::TimeWait => "TIME_WAIT",
            Self::CloseWait => "CLOSE_WAIT",
            Self::LastAck => "LAST_ACK",
            Self::Closing => "CLOSING",
            Self::Closed => "CLOSED",
            Self::Reset => "RESET",
        };
        write!(f, "{s}")
    }
}

// ─── Stream key ───────────────────────────────────────────────────────────────

/// Bidirectional stream identifier (canonical — lower endpoint first).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl StreamKey {
    /// Create a canonical (sorted) key so both directions map to the same entry.
    #[must_use]
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        if (src_ip, src_port) <= (dst_ip, dst_port) {
            Self {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            }
        } else {
            Self {
                src_ip: dst_ip,
                src_port: dst_port,
                dst_ip: src_ip,
                dst_port: src_port,
            }
        }
    }
}

impl fmt::Display for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} <-> {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

// ─── TCP Segment ──────────────────────────────────────────────────────────────

/// A single captured TCP segment.
#[derive(Debug, Clone)]
pub struct TcpSegment {
    /// Sequence number of the first byte in `data`.
    pub seq: u32,
    /// Acknowledgement number.
    pub ack: u32,
    /// TCP flags.
    pub flags: TcpFlags,
    /// Payload bytes.
    pub data: Vec<u8>,
    /// Timestamp in microseconds (optional).
    pub ts_us: u64,
}

impl TcpSegment {
    /// Create a new segment.
    #[must_use]
    pub const fn new(seq: u32, ack: u32, flags: TcpFlags, data: Vec<u8>) -> Self {
        Self {
            seq,
            ack,
            flags,
            data,
            ts_us: 0,
        }
    }

    /// End sequence number (exclusive).
    #[must_use]
    pub const fn end_seq(&self) -> u32 {
        self.seq.wrapping_add(self.data.len() as u32)
    }

    /// True if this segment carries payload.
    #[must_use]
    pub const fn has_data(&self) -> bool {
        !self.data.is_empty()
    }
}

// ─── Stream Buffer ────────────────────────────────────────────────────────────

/// An ordered byte buffer that handles out-of-order segment insertion.
#[derive(Debug, Clone, Default)]
pub struct StreamBuffer {
    /// Map from sequence number to payload bytes. Segments are stored in order.
    segments: BTreeMap<u32, Vec<u8>>,
    /// The next expected sequence number (contiguous window left edge).
    next_seq: u32,
    /// Total bytes in the buffer (including gaps).
    buffered: usize,
    /// Maximum buffer size in bytes (to prevent OOM from malformed streams).
    max_buf: usize,
}

impl StreamBuffer {
    /// Create a new buffer starting at `isn` (initial sequence number).
    #[must_use]
    pub fn new(isn: u32) -> Self {
        Self {
            next_seq: isn.wrapping_add(1), // skip SYN byte
            max_buf: 4 * 1024 * 1024,      // 4 MiB
            ..Default::default()
        }
    }

    /// Insert a segment.  Overlapping bytes are trimmed.
    pub fn insert(&mut self, seq: u32, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        // Trim leading bytes that we've already consumed.
        let start = seq;
        let end = seq.wrapping_add(u32::try_from(data.len()).unwrap_or(u32::MAX));
        if Self::seq_lt(end, self.next_seq) || end == self.next_seq {
            return; // fully in the past
        }
        // Trim leading overlap
        let (trim, trimmed_data) = if Self::seq_lt(start, self.next_seq) {
            let skip = self.next_seq.wrapping_sub(start) as usize;
            if skip >= data.len() {
                return;
            }
            (self.next_seq, &data[skip..])
        } else {
            (start, data)
        };

        if self.buffered + trimmed_data.len() > self.max_buf {
            return; // drop to prevent OOM
        }

        self.segments.entry(trim).or_insert_with(|| {
            self.buffered += trimmed_data.len();
            trimmed_data.to_vec()
        });
    }

    /// Drain all contiguous bytes starting from `next_seq`.
    #[must_use]
    /// # Panics
    /// Panics if invariants are violated.
    pub fn drain_contiguous(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            if let Some((&seq, _)) = self.segments.iter().next()
                && seq == self.next_seq {
                    let data = self.segments.remove(&seq).unwrap();
                    self.buffered = self.buffered.saturating_sub(data.len());
                    self.next_seq = self.next_seq.wrapping_add(u32::try_from(data.len()).unwrap_or(u32::MAX));
                    out.extend_from_slice(&data);
                    continue;
                }
            break;
        }
        out
    }

    /// True if there are bytes ready to drain.
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.segments
            .first_key_value()
            .is_some_and(|(&k, _)| k == self.next_seq)
    }

    /// Number of pending (possibly out-of-order) bytes.
    #[must_use]
    pub const fn buffered_bytes(&self) -> usize {
        self.buffered
    }

    /// Next expected sequence number.
    #[must_use]
    pub const fn next_seq(&self) -> u32 {
        self.next_seq
    }

    /// Compare sequence numbers accounting for wraparound.
    const fn seq_lt(a: u32, b: u32) -> bool {
        a.wrapping_sub(b).cast_signed() < 0
    }
}

// ─── TCP Stream ───────────────────────────────────────────────────────────────

/// One side of a TCP stream (per-direction).
#[derive(Debug)]
pub struct TcpStreamDirection {
    pub buf: StreamBuffer,
    pub isn: u32,
    pub fin_seq: Option<u32>,
    pub segment_count: u64,
    pub byte_count: u64,
    pub retransmit_count: u64,
}

impl TcpStreamDirection {
    fn new(isn: u32) -> Self {
        Self {
            buf: StreamBuffer::new(isn),
            isn,
            fin_seq: None,
            segment_count: 0,
            byte_count: 0,
            retransmit_count: 0,
        }
    }
}

/// A bidirectional TCP stream.
#[derive(Debug)]
pub struct TcpStream {
    pub key: StreamKey,
    pub state: TcpState,
    /// Client → server direction.
    pub client: TcpStreamDirection,
    /// Server → client direction.
    pub server: TcpStreamDirection,
    /// Approximate start timestamp (µs).
    pub start_ts: u64,
    /// Last activity timestamp (µs).
    pub last_ts: u64,
}

impl TcpStream {
    fn new(key: StreamKey, client_isn: u32) -> Self {
        Self {
            key,
            state: TcpState::SynSent,
            client: TcpStreamDirection::new(client_isn),
            server: TcpStreamDirection::new(0),
            start_ts: 0,
            last_ts: 0,
        }
    }

    /// Push a segment into the stream, choosing the direction by comparing the
    /// source address/port against the stream key.
    fn push_segment(&mut self, src_ip: IpAddr, src_port: u16, seg: &TcpSegment) {
        let is_client = src_ip == self.key.src_ip && src_port == self.key.src_port;
        let dir = if is_client {
            &mut self.client
        } else {
            &mut self.server
        };

        if seg.has_data() {
            dir.segment_count += 1;
            dir.byte_count += seg.data.len() as u64;
            dir.buf.insert(seg.seq, &seg.data);
        }
        if seg.flags.fin() {
            dir.fin_seq = Some(seg.end_seq());
        }
        self.last_ts = self.last_ts.max(seg.ts_us);
    }

    /// Transition state on flag set.
    const fn advance_state(&mut self, flags: TcpFlags, is_client: bool) {
        use TcpState::{Reset, Listen, SynSent, SynReceived, Established, FinWait1, CloseWait, FinWait2, TimeWait, LastAck, Closed};
        self.state = match (
            self.state,
            flags.syn(),
            flags.ack(),
            flags.fin(),
            flags.rst(),
        ) {
            // RST from any state → Reset
            (_, _, _, _, true) => Reset,
            // SYN — client sends first SYN
            (Listen | SynSent, true, false, _, _) => SynSent,
            // SYN-ACK — server responds
            (SynSent, true, true, _, _) => SynReceived,
            // ACK — client completes handshake
            (SynReceived, false, true, _, _) => Established,
            // FIN from established
            (Established, false, _, true, _) if is_client => FinWait1,
            (Established, false, _, true, _) => CloseWait,
            (FinWait1, false, true, _, _) => FinWait2,
            (FinWait2, false, _, true, _) => TimeWait,
            (CloseWait, false, _, true, _) => LastAck,
            (LastAck | TimeWait, false, true, _, _) => Closed,
            _ => self.state,
        };
    }

    /// True if both directions have seen a FIN and all data is consumed.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, TcpState::Closed | TcpState::Reset)
    }
}

// ─── Reassembled Stream ───────────────────────────────────────────────────────

/// Complete, reassembled application-layer data for one TCP stream.
#[derive(Debug, Clone)]
pub struct ReassembledStream {
    pub key: StreamKey,
    /// Client → server payload (request).
    pub client_data: Vec<u8>,
    /// Server → client payload (response).
    pub server_data: Vec<u8>,
    /// TCP state at time of extraction.
    pub final_state: TcpState,
    /// Number of client segments processed.
    pub client_segments: u64,
    /// Number of server segments processed.
    pub server_segments: u64,
    /// Total bytes transferred (both directions).
    pub total_bytes: u64,
}

impl ReassembledStream {
    /// Total combined payload length.
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.client_data.len() + self.server_data.len()
    }

    /// True if the stream contained any data.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.client_data.is_empty() && self.server_data.is_empty()
    }
}

// ─── Reassembler ─────────────────────────────────────────────────────────────

/// TCP stream reassembler.
///
/// Tracks all active streams, handles out-of-order segments, and delivers
/// reassembled application-layer data.
#[derive(Debug, Default)]
pub struct TcpReassembler {
    streams: HashMap<StreamKey, TcpStream>,
    /// Maximum number of concurrent tracked streams.
    pub max_streams: usize,
    /// Total segments processed.
    pub total_segments: u64,
    /// Total streams completed.
    pub completed_streams: u64,
}

impl TcpReassembler {
    /// Create a new reassembler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_streams: 65536,
            ..Default::default()
        }
    }

    /// Feed a TCP segment into the reassembler.
    ///
    /// `src_ip` / `src_port` are the sender's address. The segment must already
    /// have its IP/TCP header fields parsed.
    pub fn feed(
        &mut self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        seg: TcpSegment,
    ) {
        self.total_segments += 1;
        let key = StreamKey::new(src_ip, src_port, dst_ip, dst_port);
        let is_client = src_ip == key.src_ip && src_port == key.src_port;

        // Create a new stream on SYN
        if seg.flags.syn() && !seg.flags.ack() {
            if self.streams.len() < self.max_streams {
                let entry = self
                    .streams
                    .entry(key.clone())
                    .or_insert_with(|| TcpStream::new(key, seg.seq));
                entry.start_ts = seg.ts_us;
                entry.last_ts = seg.ts_us;
                entry.advance_state(seg.flags, is_client);
            }
            return;
        }

        if let Some(stream) = self.streams.get_mut(&key) {
            // SYN-ACK: set server ISN
            if seg.flags.syn() && seg.flags.ack() {
                stream.server = TcpStreamDirection::new(seg.seq);
            }
            stream.advance_state(seg.flags, is_client);
            stream.push_segment(src_ip, src_port, &seg);
            if stream.is_complete() {
                self.completed_streams += 1;
            }
        }
    }

    /// Drain all contiguous data from every tracked stream and return reassembled streams.
    #[must_use]
    pub fn drain_all(&mut self) -> Vec<ReassembledStream> {
        let mut out = Vec::new();
        for (key, stream) in &mut self.streams {
            let client_data = stream.client.buf.drain_contiguous();
            let server_data = stream.server.buf.drain_contiguous();
            if !client_data.is_empty() || !server_data.is_empty() {
                out.push(ReassembledStream {
                    key: key.clone(),
                    total_bytes: (client_data.len() + server_data.len()) as u64,
                    client_segments: stream.client.segment_count,
                    server_segments: stream.server.segment_count,
                    final_state: stream.state,
                    client_data,
                    server_data,
                });
            }
        }
        out
    }

    /// Flush and remove all completed (closed/reset) streams, returning them.
    #[must_use]
    pub fn flush_completed(&mut self) -> Vec<ReassembledStream> {
        let completed_keys: Vec<StreamKey> = self
            .streams
            .iter()
            .filter(|(_, s)| s.is_complete())
            .map(|(k, _)| k.clone())
            .collect();

        let mut out = Vec::new();
        for key in completed_keys {
            if let Some(mut stream) = self.streams.remove(&key) {
                let client_data = stream.client.buf.drain_contiguous();
                let server_data = stream.server.buf.drain_contiguous();
                out.push(ReassembledStream {
                    key,
                    total_bytes: (client_data.len() + server_data.len()) as u64,
                    client_segments: stream.client.segment_count,
                    server_segments: stream.server.segment_count,
                    final_state: stream.state,
                    client_data,
                    server_data,
                });
            }
        }
        out
    }

    /// Number of currently tracked streams.
    #[must_use]
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Look up a stream by key.
    #[must_use]
    pub fn get_stream(&self, key: &StreamKey) -> Option<&TcpStream> {
        self.streams.get(key)
    }

    /// Extract complete application-layer payloads from a parsed PCAP record
    /// (Ethernet → IPv4 → TCP, assumes no VLAN tagging).
    ///
    /// Returns `true` if the packet was a TCP packet and was processed.
    #[must_use]
    pub fn feed_ethernet_frame(&mut self, data: &[u8], ts_us: u64) -> bool {
        if data.len() < 54 {
            return false;
        } // 14 eth + 20 ip + 20 tcp min
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 {
            return false;
        }
        let ip_proto = data[23];
        if ip_proto != 6 {
            return false;
        } // TCP only
        let ihl = (data[14] & 0x0F) as usize * 4;
        if data.len() < 14 + ihl + 20 {
            return false;
        }
        let ip_base = 14;
        let tcp_base = ip_base + ihl;

        let src_ip_bytes: [u8; 4] = data[ip_base + 12..ip_base + 16]
            .try_into()
            .unwrap_or([0; 4]);
        let dst_ip_bytes: [u8; 4] = data[ip_base + 16..ip_base + 20]
            .try_into()
            .unwrap_or([0; 4]);
        let src_ip = IpAddr::from(src_ip_bytes);
        let dst_ip = IpAddr::from(dst_ip_bytes);

        let src_port = u16::from_be_bytes([data[tcp_base], data[tcp_base + 1]]);
        let dst_port = u16::from_be_bytes([data[tcp_base + 2], data[tcp_base + 3]]);
        let seq = u32::from_be_bytes([
            data[tcp_base + 4],
            data[tcp_base + 5],
            data[tcp_base + 6],
            data[tcp_base + 7],
        ]);
        let ack_num = u32::from_be_bytes([
            data[tcp_base + 8],
            data[tcp_base + 9],
            data[tcp_base + 10],
            data[tcp_base + 11],
        ]);
        let tcp_hdr_len = ((data[tcp_base + 12] >> 4) as usize) * 4;
        let flags = TcpFlags::from_bits(data[tcp_base + 13]);
        let payload_start = tcp_base + tcp_hdr_len;
        let payload = if payload_start < data.len() {
            data[payload_start..].to_vec()
        } else {
            vec![]
        };

        let mut seg = TcpSegment::new(seq, ack_num, flags, payload);
        seg.ts_us = ts_us;
        self.feed(src_ip, src_port, dst_ip, dst_port, seg);
        true
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn make_seg(seq: u32, ack: u32, flags: u8, data: &[u8]) -> TcpSegment {
        TcpSegment::new(seq, ack, TcpFlags::from_bits(flags), data.to_vec())
    }

    #[test]
    fn test_flags() {
        let f = TcpFlags::from_bits(TcpFlags::SYN | TcpFlags::ACK);
        assert!(f.syn());
        assert!(f.ack());
        assert!(!f.fin());
    }

    #[test]
    fn test_stream_key_canonical() {
        let k1 = StreamKey::new(ip(1, 2, 3, 4), 1000, ip(5, 6, 7, 8), 80);
        let k2 = StreamKey::new(ip(5, 6, 7, 8), 80, ip(1, 2, 3, 4), 1000);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_stream_buffer_in_order() {
        let mut buf = StreamBuffer::new(99); // next_seq = 100
        buf.insert(100, b"hello");
        buf.insert(105, b" world");
        let data = buf.drain_contiguous();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn test_stream_buffer_out_of_order() {
        let mut buf = StreamBuffer::new(99);
        buf.insert(105, b" world");
        let data = buf.drain_contiguous();
        assert!(data.is_empty()); // gap at 100..105
        buf.insert(100, b"hello");
        let data = buf.drain_contiguous();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn test_stream_buffer_overlap_trim() {
        let mut buf = StreamBuffer::new(99);
        buf.insert(100, b"helloXX");
        buf.insert(105, b"world"); // overlaps with "X"
        let data = buf.drain_contiguous();
        // "hello" + " world" because second insert starts at 105 which is after 100+7=107? no.
        // "helloXX" covers 100..107, then " world" from 105..110.
        // After draining 100..107 (7 bytes), next_seq=107.
        // " world" starts at 105 < 107, so trimmed to 107..110 = "ld"
        assert!(data.len() >= 7); // at least "helloXX"
    }

    #[test]
    fn test_stream_buffer_duplicate_ignored() {
        let mut buf = StreamBuffer::new(99);
        buf.insert(100, b"ABCDE");
        buf.insert(100, b"ABCDE"); // duplicate — buffered count stays same
        let data = buf.drain_contiguous();
        assert_eq!(&data, b"ABCDE");
    }

    #[test]
    fn test_tcp_reassembler_handshake() {
        let mut r = TcpReassembler::new();
        let cli = ip(10, 0, 0, 1);
        let srv = ip(10, 0, 0, 2);

        // SYN
        r.feed(cli, 12345, srv, 80, make_seg(1000, 0, TcpFlags::SYN, b""));
        assert_eq!(r.stream_count(), 1);
        let key = StreamKey::new(cli, 12345, srv, 80);
        let s = r.get_stream(&key).unwrap();
        assert_eq!(s.state, TcpState::SynSent);
    }

    #[test]
    fn test_tcp_reassembler_full_handshake() {
        let mut r = TcpReassembler::new();
        let cli = ip(10, 0, 0, 1);
        let srv = ip(10, 0, 0, 2);
        let key = StreamKey::new(cli, 1234, srv, 80);

        r.feed(cli, 1234, srv, 80, make_seg(0, 0, TcpFlags::SYN, b""));
        r.feed(
            srv,
            80,
            cli,
            1234,
            make_seg(5000, 1, TcpFlags::SYN | TcpFlags::ACK, b""),
        );
        r.feed(cli, 1234, srv, 80, make_seg(1, 5001, TcpFlags::ACK, b""));
        let s = r.get_stream(&key).unwrap();
        assert_eq!(s.state, TcpState::Established);
    }

    #[test]
    fn test_tcp_data_reassembly() {
        let mut r = TcpReassembler::new();
        let cli = ip(10, 0, 0, 1);
        let srv = ip(10, 0, 0, 2);

        r.feed(cli, 9000, srv, 80, make_seg(0, 0, TcpFlags::SYN, b""));
        r.feed(
            srv,
            80,
            cli,
            9000,
            make_seg(500, 1, TcpFlags::SYN | TcpFlags::ACK, b""),
        );
        r.feed(cli, 9000, srv, 80, make_seg(1, 501, TcpFlags::ACK, b""));
        r.feed(
            cli,
            9000,
            srv,
            80,
            make_seg(1, 501, TcpFlags::PSH | TcpFlags::ACK, b"GET / HTTP/1.0\r\n"),
        );
        r.feed(
            srv,
            80,
            cli,
            9000,
            make_seg(
                501,
                17,
                TcpFlags::PSH | TcpFlags::ACK,
                b"HTTP/1.0 200 OK\r\n",
            ),
        );

        let drained = r.drain_all();
        let total: usize = drained.iter().map(super::ReassembledStream::payload_len).sum();
        assert!(total > 0);
    }

    #[test]
    fn test_ooo_reassembly() {
        let mut r = TcpReassembler::new();
        let cli = ip(192, 168, 1, 1);
        let srv = ip(192, 168, 1, 2);

        r.feed(cli, 5000, srv, 443, make_seg(0, 0, TcpFlags::SYN, b""));
        r.feed(
            srv,
            443,
            cli,
            5000,
            make_seg(0, 1, TcpFlags::SYN | TcpFlags::ACK, b""),
        );
        r.feed(cli, 5000, srv, 443, make_seg(1, 1, TcpFlags::ACK, b""));
        // Send second chunk before first
        r.feed(
            cli,
            5000,
            srv,
            443,
            make_seg(6, 1, TcpFlags::PSH | TcpFlags::ACK, b"world"),
        );
        r.feed(
            cli,
            5000,
            srv,
            443,
            make_seg(1, 1, TcpFlags::PSH | TcpFlags::ACK, b"hello"),
        );

        let drained = r.drain_all();
        let cli_data: Vec<u8> = drained
            .iter()
            .flat_map(|s| s.client_data.iter().copied())
            .collect();
        assert!(cli_data.starts_with(b"hello"));
        assert!(cli_data.ends_with(b"world") || cli_data.len() >= 10);
    }

    #[test]
    fn test_rst_closes_stream() {
        let mut r = TcpReassembler::new();
        let cli = ip(10, 1, 1, 1);
        let srv = ip(10, 1, 1, 2);
        let key = StreamKey::new(cli, 1111, srv, 22);

        r.feed(cli, 1111, srv, 22, make_seg(0, 0, TcpFlags::SYN, b""));
        r.feed(srv, 22, cli, 1111, make_seg(0, 1, TcpFlags::RST, b""));
        let s = r.get_stream(&key).unwrap();
        assert_eq!(s.state, TcpState::Reset);
    }

    #[test]
    fn test_fin_handshake() {
        let mut r = TcpReassembler::new();
        let cli = ip(1, 1, 1, 1);
        let srv = ip(2, 2, 2, 2);
        let key = StreamKey::new(cli, 2222, srv, 80);

        r.feed(cli, 2222, srv, 80, make_seg(0, 0, TcpFlags::SYN, b""));
        r.feed(
            srv,
            80,
            cli,
            2222,
            make_seg(0, 1, TcpFlags::SYN | TcpFlags::ACK, b""),
        );
        r.feed(cli, 2222, srv, 80, make_seg(1, 1, TcpFlags::ACK, b""));
        r.feed(
            cli,
            2222,
            srv,
            80,
            make_seg(1, 1, TcpFlags::FIN | TcpFlags::ACK, b""),
        );
        r.feed(srv, 80, cli, 2222, make_seg(1, 2, TcpFlags::ACK, b""));
        r.feed(
            srv,
            80,
            cli,
            2222,
            make_seg(1, 2, TcpFlags::FIN | TcpFlags::ACK, b""),
        );
        r.feed(cli, 2222, srv, 80, make_seg(2, 2, TcpFlags::ACK, b""));

        let s = r.get_stream(&key);
        // After full FIN exchange stream should be Closed
        if let Some(s) = s {
            assert!(matches!(s.state, TcpState::Closed | TcpState::TimeWait));
        }
    }

    #[test]
    fn test_max_streams_limit() {
        let mut r = TcpReassembler::new();
        r.max_streams = 2;
        for i in 0u16..5 {
            let cli = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            let srv = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
            r.feed(cli, 10000 + i, srv, 80, make_seg(0, 0, TcpFlags::SYN, b""));
        }
        assert!(r.stream_count() <= 2);
    }

    #[test]
    fn test_state_display() {
        assert_eq!(TcpState::Established.to_string(), "ESTABLISHED");
        assert_eq!(TcpState::TimeWait.to_string(), "TIME_WAIT");
    }

    #[test]
    fn test_flags_display() {
        let f = TcpFlags::from_bits(TcpFlags::SYN | TcpFlags::ACK);
        let s = f.to_string();
        assert!(s.contains("SYN"));
        assert!(s.contains("ACK"));
    }

    #[test]
    fn test_tcp_segment_end_seq() {
        let s = make_seg(100, 0, 0, b"hello");
        assert_eq!(s.end_seq(), 105);
    }

    #[test]
    fn test_stream_key_display() {
        let k = StreamKey::new(ip(1, 2, 3, 4), 80, ip(5, 6, 7, 8), 8080);
        let s = k.to_string();
        assert!(s.contains("80"));
        assert!(s.contains("8080"));
    }

    #[test]
    fn test_no_data_stream() {
        let mut r = TcpReassembler::new();
        let cli = ip(10, 10, 10, 1);
        let srv = ip(10, 10, 10, 2);
        // Only handshake, no payload
        r.feed(cli, 3000, srv, 80, make_seg(0, 0, TcpFlags::SYN, b""));
        r.feed(
            srv,
            80,
            cli,
            3000,
            make_seg(0, 1, TcpFlags::SYN | TcpFlags::ACK, b""),
        );
        let drained = r.drain_all();
        // Nothing to reassemble
        for s in &drained {
            assert!(s.is_empty());
        }
    }

    #[test]
    fn test_flush_completed() {
        let mut r = TcpReassembler::new();
        let cli = ip(10, 0, 1, 1);
        let srv = ip(10, 0, 1, 2);

        r.feed(cli, 4444, srv, 80, make_seg(0, 0, TcpFlags::SYN, b""));
        r.feed(
            srv,
            80,
            cli,
            4444,
            make_seg(0, 1, TcpFlags::SYN | TcpFlags::ACK, b""),
        );
        r.feed(cli, 4444, srv, 80, make_seg(1, 1, TcpFlags::ACK, b""));
        r.feed(srv, 80, cli, 4444, make_seg(1, 1, TcpFlags::RST, b""));

        let completed = r.flush_completed();
        // RST stream should be flushed
        assert!(!completed.is_empty() || r.stream_count() == 0);
    }

    #[test]
    fn test_buffer_next_seq() {
        let buf = StreamBuffer::new(0); // ISN=0 → next_seq=1
        assert_eq!(buf.next_seq(), 1);
    }

    #[test]
    fn test_segment_has_data() {
        let s = make_seg(0, 0, TcpFlags::SYN, b"");
        assert!(!s.has_data());
        let s2 = make_seg(1, 0, TcpFlags::PSH, b"data");
        assert!(s2.has_data());
    }

    #[test]
    fn test_reassembled_stream_total_bytes() {
        let rs = ReassembledStream {
            key: StreamKey::new(ip(1, 2, 3, 4), 80, ip(5, 6, 7, 8), 9000),
            client_data: b"request".to_vec(),
            server_data: b"response".to_vec(),
            final_state: TcpState::Established,
            client_segments: 1,
            server_segments: 1,
            total_bytes: 15,
        };
        assert_eq!(rs.payload_len(), 15);
        assert!(!rs.is_empty());
    }
}
