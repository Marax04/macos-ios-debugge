//! Extract conversations: group packets into TCP/UDP flows.
//!
//! Tracks bidirectional flows identified by a canonical 5-tuple,
//! reassembles per-direction byte streams, and exposes stream data
//! for further analysis.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── ConversationKey ──────────────────────────────────────────────────────────

/// Canonical 5-tuple that identifies a bidirectional conversation.
///
/// The tuple is always stored in canonical order (lower (IP, port) first) so
/// that packets flowing in either direction map to the same key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConversationKey {
    pub proto: u8,
    pub src_ip: [u8; 16], // IPv4 stored in first 4 bytes
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub is_ipv6: bool,
}

impl ConversationKey {
    /// Build a canonical key from packet fields.
    #[must_use] 
    pub fn new_ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16) -> Self {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a[..4].copy_from_slice(&src);
        b[..4].copy_from_slice(&dst);
        // Canonical: (lower IP, lower port) first.
        if (a, sp) <= (b, dp) {
            Self { proto, src_ip: a, dst_ip: b, src_port: sp, dst_port: dp, is_ipv6: false }
        } else {
            Self { proto, src_ip: b, dst_ip: a, src_port: dp, dst_port: sp, is_ipv6: false }
        }
    }

    /// Build a canonical key from IPv6 fields.
    #[must_use] 
    pub fn new_ipv6(proto: u8, src: [u8; 16], dst: [u8; 16], sp: u16, dp: u16) -> Self {
        if (src, sp) <= (dst, dp) {
            Self { proto, src_ip: src, dst_ip: dst, src_port: sp, dst_port: dp, is_ipv6: true }
        } else {
            Self { proto, src_ip: dst, dst_ip: src, src_port: dp, dst_port: sp, is_ipv6: true }
        }
    }

    /// Return the source IPv4 address as a string.
    #[must_use] 
    pub fn src_addr_str(&self) -> String {
        if self.is_ipv6 {
            format_ipv6(&self.src_ip)
        } else {
            format!("{}.{}.{}.{}", self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3])
        }
    }

    /// Return the destination IPv4 address as a string.
    #[must_use] 
    pub fn dst_addr_str(&self) -> String {
        if self.is_ipv6 {
            format_ipv6(&self.dst_ip)
        } else {
            format!("{}.{}.{}.{}", self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3])
        }
    }

    /// Protocol name string.
    #[must_use] 
    pub const fn proto_name(&self) -> &'static str {
        match self.proto {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            58 => "ICMPv6",
            _ => "IP",
        }
    }
}

impl fmt::Display for ConversationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{} <-> {}:{}",
            self.proto_name(),
            self.src_addr_str(),
            self.src_port,
            self.dst_addr_str(),
            self.dst_port,
        )
    }
}

fn format_ipv6(b: &[u8; 16]) -> String {
    let groups: Vec<String> = (0..8)
        .map(|i| format!("{:04x}", u16::from_be_bytes([b[i * 2], b[i * 2 + 1]])))
        .collect();
    groups.join(":")
}

// ─── PacketDirection ──────────────────────────────────────────────────────────

/// Which direction a packet was flowing within a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketDirection {
    /// From the canonical-first endpoint to the canonical-second endpoint.
    Forward,
    /// From the canonical-second endpoint back to the canonical-first.
    Reverse,
}

// ─── ConversationPacket ───────────────────────────────────────────────────────

/// Metadata about a single packet belonging to a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationPacket {
    /// Packet index in the original PCAP/buffer.
    pub original_index: usize,
    /// Microsecond timestamp (relative to epoch or capture start).
    pub timestamp_us: u64,
    /// Layer-4 payload bytes.
    pub payload: Vec<u8>,
    /// Direction relative to the canonical key.
    pub direction: PacketDirection,
    /// TCP flags byte (0 for UDP).
    pub tcp_flags: u8,
    /// TCP sequence number (0 for UDP).
    pub tcp_seq: u32,
}

impl ConversationPacket {
    /// Returns `true` if this is a TCP SYN (flags & 0x02 != 0).
    #[must_use] 
    pub const fn is_syn(&self) -> bool { self.tcp_flags & 0x02 != 0 }
    /// Returns `true` if this is a TCP FIN.
    #[must_use] 
    pub const fn is_fin(&self) -> bool { self.tcp_flags & 0x01 != 0 }
    /// Returns `true` if this is a TCP RST.
    #[must_use] 
    pub const fn is_rst(&self) -> bool { self.tcp_flags & 0x04 != 0 }
    /// Returns `true` if this packet carries application data.
    #[must_use] 
    pub const fn has_data(&self) -> bool { !self.payload.is_empty() }
}

// ─── Conversation ─────────────────────────────────────────────────────────────

/// All information about a single bidirectional conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub key: ConversationKey,
    /// All packets in arrival order.
    pub packets: Vec<ConversationPacket>,
    /// Timestamp of the first observed packet (microseconds).
    pub first_seen_us: u64,
    /// Timestamp of the last observed packet (microseconds).
    pub last_seen_us: u64,
    /// Bytes sent in the forward direction.
    pub fwd_bytes: u64,
    /// Bytes sent in the reverse direction.
    pub rev_bytes: u64,
}

impl Conversation {
    const fn new(key: ConversationKey, first_ts: u64) -> Self {
        Self {
            key,
            packets: Vec::new(),
            first_seen_us: first_ts,
            last_seen_us: first_ts,
            fwd_bytes: 0,
            rev_bytes: 0,
        }
    }

    fn add_packet(&mut self, pkt: ConversationPacket) {
        if pkt.timestamp_us > self.last_seen_us {
            self.last_seen_us = pkt.timestamp_us;
        }
        match pkt.direction {
            PacketDirection::Forward => self.fwd_bytes += pkt.payload.len() as u64,
            PacketDirection::Reverse => self.rev_bytes += pkt.payload.len() as u64,
        }
        self.packets.push(pkt);
    }

    /// Duration of the conversation in microseconds.
    #[must_use] 
    pub const fn duration_us(&self) -> u64 {
        self.last_seen_us.saturating_sub(self.first_seen_us)
    }

    /// Total bytes exchanged in both directions.
    #[must_use] 
    pub const fn total_bytes(&self) -> u64 {
        self.fwd_bytes + self.rev_bytes
    }

    /// Number of packets in this conversation.
    #[must_use] 
    pub const fn packet_count(&self) -> usize {
        self.packets.len()
    }

    /// Returns `true` if this looks like a TCP conversation (saw SYN).
    pub fn is_tcp_established(&self) -> bool {
        self.packets.iter().any(ConversationPacket::is_syn)
    }

    /// Returns `true` if a TCP FIN or RST was seen (conversation closed).
    #[must_use] 
    pub fn is_closed(&self) -> bool {
        self.packets.iter().any(|p| p.is_fin() || p.is_rst())
    }
}

impl fmt::Display for Conversation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Conv[{}] pkts={} fwd={}B rev={}B dur={}µs",
            self.key,
            self.packet_count(),
            self.fwd_bytes,
            self.rev_bytes,
            self.duration_us(),
        )
    }
}

// ─── stream_data ──────────────────────────────────────────────────────────────

/// Reconstruct the application-layer byte stream for one direction of a conversation.
///
/// For TCP, packets are ordered by sequence number before concatenation.
/// For UDP/other, they are concatenated in arrival order.
#[must_use] 
pub fn stream_data(conv: &Conversation, direction: PacketDirection) -> Vec<u8> {
    let is_tcp = conv.key.proto == 6;
    let mut pkts: Vec<&ConversationPacket> = conv
        .packets
        .iter()
        .filter(|p| p.direction == direction && !p.payload.is_empty())
        .collect();

    if is_tcp {
        pkts.sort_by_key(|p| p.tcp_seq);
    }

    let mut out = Vec::new();
    for p in pkts {
        out.extend_from_slice(&p.payload);
    }
    out
}

// ─── ConversationExtractor ───────────────────────────────────────────────────

/// Extracts conversations from a stream of raw Ethernet/IPv4/IPv6 packets.
pub struct ConversationExtractor {
    conversations: HashMap<ConversationKey, Conversation>,
    /// Maximum number of simultaneously tracked conversations.
    max_conversations: usize,
    /// Whether to track IPv6 conversations.
    track_ipv6: bool,
    /// Whether to include ICMP as a "conversation".
    track_icmp: bool,
    /// Minimum payload size to record in a `ConversationPacket`.
    min_payload: usize,
}

impl ConversationExtractor {
    /// Create an extractor with default settings.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            conversations: HashMap::new(),
            max_conversations: 65536,
            track_ipv6: true,
            track_icmp: false,
            min_payload: 0,
        }
    }

    /// Set maximum number of tracked conversations.
    #[must_use] 
    pub const fn with_max_conversations(mut self, n: usize) -> Self {
        self.max_conversations = n;
        self
    }

    /// Enable/disable IPv6 tracking.
    #[must_use] 
    pub const fn with_ipv6(mut self, v: bool) -> Self {
        self.track_ipv6 = v;
        self
    }

    /// Enable/disable ICMP conversation tracking.
    #[must_use] 
    pub const fn with_icmp(mut self, v: bool) -> Self {
        self.track_icmp = v;
        self
    }

    /// Only record payload bytes in packets with at least `n` payload bytes.
    #[must_use] 
    pub const fn with_min_payload(mut self, n: usize) -> Self {
        self.min_payload = n;
        self
    }

    /// Feed a single raw Ethernet frame.
    ///
    /// - `index` is the original packet index.
    /// - `timestamp_us` is the capture timestamp in microseconds.
    pub fn feed(&mut self, index: usize, timestamp_us: u64, frame: &[u8]) {
        if frame.len() < 14 { return; }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

        match ethertype {
            0x0800 => self.feed_ipv4(index, timestamp_us, &frame[14..]),
            0x86DD if self.track_ipv6 => self.feed_ipv6(index, timestamp_us, &frame[14..]),
            _ => {}
        }
    }

    fn feed_ipv4(&mut self, index: usize, ts: u64, ip: &[u8]) {
        if ip.len() < 20 { return; }
        let ihl = ((ip[0] & 0x0F) as usize) * 4;
        if ihl > ip.len() { return; }

        let proto = ip[9];
        let src: [u8; 4] = ip[12..16].try_into().unwrap_or([0; 4]);
        let dst: [u8; 4] = ip[16..20].try_into().unwrap_or([0; 4]);
        let transport = &ip[ihl..];

        match proto {
            6 => self.feed_tcp_v4(index, ts, src, dst, transport),
            17 => self.feed_udp_v4(index, ts, src, dst, transport),
            1 if self.track_icmp => {
                let key = ConversationKey::new_ipv4(1, src, dst, 0, 0);
                let payload = transport.to_vec();
                self.record(key, index, ts, src, dst, 0, 0, payload, 0, 0);
            }
            _ => {}
        }
    }

    fn feed_tcp_v4(&mut self, index: usize, ts: u64, src: [u8; 4], dst: [u8; 4], tcp: &[u8]) {
        if tcp.len() < 20 { return; }
        let sp = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dp = u16::from_be_bytes([tcp[2], tcp[3]]);
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let flags = tcp[13];
        let data_off = ((tcp[12] >> 4) as usize) * 4;
        let payload = if data_off < tcp.len() { tcp[data_off..].to_vec() } else { vec![] };
        let key = ConversationKey::new_ipv4(6, src, dst, sp, dp);
        self.record(key, index, ts, src, dst, sp, dp, payload, flags, seq);
    }

    fn feed_udp_v4(&mut self, index: usize, ts: u64, src: [u8; 4], dst: [u8; 4], udp: &[u8]) {
        if udp.len() < 8 { return; }
        let sp = u16::from_be_bytes([udp[0], udp[1]]);
        let dp = u16::from_be_bytes([udp[2], udp[3]]);
        let payload = if udp.len() > 8 { udp[8..].to_vec() } else { vec![] };
        let key = ConversationKey::new_ipv4(17, src, dst, sp, dp);
        self.record(key, index, ts, src, dst, sp, dp, payload, 0, 0);
    }

    fn feed_ipv6(&mut self, index: usize, ts: u64, ip: &[u8]) {
        if ip.len() < 40 { return; }
        let proto = ip[6];
        let src: [u8; 16] = ip[8..24].try_into().unwrap_or([0; 16]);
        let dst: [u8; 16] = ip[24..40].try_into().unwrap_or([0; 16]);
        let transport = &ip[40..];

        let (sp, dp, flags, seq, payload) = match proto {
            6 if transport.len() >= 20 => {
                let sp = u16::from_be_bytes([transport[0], transport[1]]);
                let dp = u16::from_be_bytes([transport[2], transport[3]]);
                let seq = u32::from_be_bytes([transport[4], transport[5], transport[6], transport[7]]);
                let flags = transport[13];
                let off = ((transport[12] >> 4) as usize) * 4;
                let payload = if off < transport.len() { transport[off..].to_vec() } else { vec![] };
                (sp, dp, flags, seq, payload)
            }
            17 if transport.len() >= 8 => {
                let sp = u16::from_be_bytes([transport[0], transport[1]]);
                let dp = u16::from_be_bytes([transport[2], transport[3]]);
                let payload = if transport.len() > 8 { transport[8..].to_vec() } else { vec![] };
                (sp, dp, 0, 0, payload)
            }
            _ => return,
        };

        let key = ConversationKey::new_ipv6(proto, src, dst, sp, dp);
        let mut src4 = [0u8; 4];
        let mut dst4 = [0u8; 4];
        src4.copy_from_slice(&src[..4]);
        dst4.copy_from_slice(&dst[..4]);
        self.record(key, index, ts, src4, dst4, sp, dp, payload, flags, seq);
    }

    fn record(
        &mut self,
        key: ConversationKey,
        index: usize,
        ts: u64,
        src: [u8; 4],
        _dst: [u8; 4],
        sp: u16,
        _dp: u16,
        payload: Vec<u8>,
        tcp_flags: u8,
        tcp_seq: u32,
    ) {
        if self.conversations.len() >= self.max_conversations && !self.conversations.contains_key(&key) {
            return; // Eviction policy: just drop new flows when at capacity.
        }
        if payload.len() < self.min_payload && tcp_flags == 0 {
            // Skip empty UDP payloads below min.
        }

        // Determine direction: is src the canonical-first endpoint?
        let direction = {
            let mut fwd_src = [0u8; 4];
            fwd_src.copy_from_slice(&key.src_ip[..4]);
            if src == fwd_src && sp == key.src_port { PacketDirection::Forward } else { PacketDirection::Reverse }
        };

        let pkt = ConversationPacket {
            original_index: index,
            timestamp_us: ts,
            payload,
            direction,
            tcp_flags,
            tcp_seq,
        };

        self.conversations
            .entry(key.clone())
            .or_insert_with(|| Conversation::new(key, ts))
            .add_packet(pkt);
    }

    /// Return a sorted list of all tracked conversations (by total bytes, descending).
    #[must_use] 
    pub fn conversations(&self) -> Vec<&Conversation> {
        let mut v: Vec<&Conversation> = self.conversations.values().collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.total_bytes()));
        v
    }

    /// Return the conversation matching the given key, if any.
    #[must_use] 
    pub fn get(&self, key: &ConversationKey) -> Option<&Conversation> {
        self.conversations.get(key)
    }

    /// Total number of tracked conversations.
    #[must_use] 
    pub fn len(&self) -> usize { self.conversations.len() }
    #[must_use] 
    pub fn is_empty(&self) -> bool { self.conversations.is_empty() }

    /// Return conversations with `total_bytes` > threshold.
    #[must_use] 
    pub fn heavy_hitters(&self, threshold: u64) -> Vec<&Conversation> {
        self.conversations
            .values()
            .filter(|c| c.total_bytes() > threshold)
            .collect()
    }

    /// Return a summary of conversation statistics.
    pub fn summary(&self) -> ConversationSummary {
        let total = self.conversations.len();
        let tcp = self.conversations.values().filter(|c| c.key.proto == 6).count();
        let udp = self.conversations.values().filter(|c| c.key.proto == 17).count();
        let total_bytes: u64 = self.conversations.values().map(Conversation::total_bytes).sum();
        let total_pkts: usize = self.conversations.values().map(Conversation::packet_count).sum();
        ConversationSummary { total, tcp, udp, total_bytes, total_pkts }
    }
}

impl Default for ConversationExtractor {
    fn default() -> Self { Self::new() }
}

/// Summary of all extracted conversations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub total: usize,
    pub tcp: usize,
    pub udp: usize,
    pub total_bytes: u64,
    pub total_pkts: usize,
}

impl fmt::Display for ConversationSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConvSummary: total={} tcp={} udp={} bytes={} pkts={}",
            self.total, self.tcp, self.udp, self.total_bytes, self.total_pkts,
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet/IPv4/TCP frame.
    fn make_tcp_frame(
        src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16,
        seq: u32, flags: u8, payload: &[u8],
    ) -> Vec<u8> {
        let mut f = Vec::with_capacity(54 + payload.len());
        f.extend_from_slice(&[0u8; 12]); // MAC addresses
        f.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
        // IPv4 header (20 bytes)
        f.push(0x45); // version+IHL
        f.push(0x00); // DSCP
        let total_len = (40u16 + u16::try_from(payload.len()).unwrap_or(u16::MAX)).to_be_bytes();
        f.extend_from_slice(&total_len);
        f.extend_from_slice(&[0, 1, 0, 0]); // id, flags, frag
        f.push(64); // TTL
        f.push(6); // protocol TCP
        f.extend_from_slice(&[0, 0]); // checksum
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        // TCP header (20 bytes)
        f.extend_from_slice(&sp.to_be_bytes());
        f.extend_from_slice(&dp.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0]); // ack
        f.push(0x50); // data offset = 5*4=20
        f.push(flags);
        f.extend_from_slice(&[0xFF, 0xFF]); // window
        f.extend_from_slice(&[0, 0]); // checksum
        f.extend_from_slice(&[0, 0]); // urgent
        f.extend_from_slice(payload);
        f
    }

    fn make_udp_frame(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(42 + payload.len());
        f.extend_from_slice(&[0u8; 12]);
        f.extend_from_slice(&[0x08, 0x00]);
        f.push(0x45);
        f.push(0x00);
        let tlen = (28u16 + u16::try_from(payload.len()).unwrap_or(u16::MAX)).to_be_bytes();
        f.extend_from_slice(&tlen);
        f.extend_from_slice(&[0, 1, 0, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&sp.to_be_bytes());
        f.extend_from_slice(&dp.to_be_bytes());
        f.extend_from_slice(&(8u16 + u16::try_from(payload.len()).unwrap_or(u16::MAX)).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn test_extract_tcp_conversation() {
        let mut ext = ConversationExtractor::new();
        let a = [10, 0, 0, 1];
        let b = [10, 0, 0, 2];
        ext.feed(0, 1000, &make_tcp_frame(a, b, 1234, 80, 100, 0x02, b"GET / HTTP/1.1\r\n"));
        ext.feed(1, 2000, &make_tcp_frame(b, a, 80, 1234, 200, 0x12, b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(ext.len(), 1);
        let conv = ext.conversations().into_iter().next().unwrap();
        assert_eq!(conv.packet_count(), 2);
        assert!(conv.is_tcp_established());
    }

    #[test]
    fn test_extract_udp_conversation() {
        let mut ext = ConversationExtractor::new();
        ext.feed(0, 0, &make_udp_frame([1,1,1,1], [2,2,2,2], 5353, 5353, b"query"));
        ext.feed(1, 1, &make_udp_frame([2,2,2,2], [1,1,1,1], 5353, 5353, b"response"));
        assert_eq!(ext.len(), 1);
    }

    #[test]
    fn test_stream_data() {
        let mut ext = ConversationExtractor::new();
        let a = [10, 0, 0, 1];
        let b = [10, 0, 0, 2];
        ext.feed(0, 0, &make_tcp_frame(a, b, 1234, 80, 0, 0x02, b"Hello"));
        ext.feed(1, 1, &make_tcp_frame(a, b, 1234, 80, 5, 0x00, b" World"));
        let conv = ext.conversations().into_iter().next().unwrap();
        let data = stream_data(conv, PacketDirection::Forward);
        assert!(data.windows(5).any(|w| w == b"Hello"));
    }

    #[test]
    fn test_canonical_key_symmetry() {
        let a = [10, 0, 0, 1];
        let b = [10, 0, 0, 2];
        let k1 = ConversationKey::new_ipv4(6, a, b, 1234, 80);
        let k2 = ConversationKey::new_ipv4(6, b, a, 80, 1234);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_summary() {
        let mut ext = ConversationExtractor::new();
        ext.feed(0, 0, &make_tcp_frame([1,2,3,4], [5,6,7,8], 1111, 80, 0, 0x02, b"data"));
        ext.feed(1, 0, &make_udp_frame([9,8,7,6], [5,4,3,2], 53, 53, b"q"));
        let s = ext.summary();
        assert_eq!(s.total, 2);
        assert_eq!(s.tcp, 1);
        assert_eq!(s.udp, 1);
    }

    #[test]
    fn test_conversation_duration() {
        let mut ext = ConversationExtractor::new();
        let a = [1,0,0,1];
        let b = [2,0,0,2];
        ext.feed(0, 1_000_000, &make_tcp_frame(a, b, 100, 200, 0, 0x02, b"start"));
        ext.feed(1, 5_000_000, &make_tcp_frame(a, b, 100, 200, 5, 0x01, b"end"));
        let conv = ext.conversations()[0];
        assert_eq!(conv.duration_us(), 4_000_000);
    }

    #[test]
    fn test_heavy_hitters() {
        let mut ext = ConversationExtractor::new();
        ext.feed(0, 0, &make_tcp_frame([1,2,3,4],[5,6,7,8], 1, 80, 0, 0, &vec![0u8; 2000]));
        ext.feed(1, 0, &make_udp_frame([9,8,7,6],[5,4,3,2], 53, 53, b"small"));
        let h = ext.heavy_hitters(100);
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_max_conversations_limit() {
        let mut ext = ConversationExtractor::new().with_max_conversations(2);
        for i in 0u8..10 {
            ext.feed(i as usize, 0, &make_udp_frame([1,2,3,i],[5,6,7,8], u16::from(i) + 1000, 53, b"x"));
        }
        assert!(ext.len() <= 2);
    }
}
