//! `pcap_analyzer.rs` — high-level PCAP traffic analysis.
//!
//! Analyses a stream of [`Packet`]s (typically loaded from a PCAP/PCAPNG file)
//! and produces structured statistics and extracted metadata.
//!
//! # Types
//! * [`PcapAnalyzer`] — drives the analysis; owns all sub-analysers.
//! * [`ConversationTracker`] — tracks per-flow byte/packet counts.
//! * [`ProtocolDistribution`] — counts packets per L3/L4 protocol.
//! * [`IOGraph`] — bytes-per-second time series.
//! * [`TopTalkers`] — IP addresses with the most traffic.
//! * [`DnsAnalysis`] — DNS question/answer extraction.
//! * [`TlsHandshake`] — TLS `ClientHello` / `ServerHello` extraction.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

// ─── Packet ───────────────────────────────────────────────────────────────────

/// A single packet with timestamp and raw bytes.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Timestamp in microseconds since epoch.
    pub ts_us: u64,
    pub data: Vec<u8>,
}

impl Packet {
    #[must_use]
    pub const fn new(ts_us: u64, data: Vec<u8>) -> Self {
        Self { ts_us, data }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Timestamp as [`Duration`] from epoch.
    #[must_use]
    pub const fn timestamp(&self) -> Duration {
        Duration::from_micros(self.ts_us)
    }
}

// ─── FlowKey ──────────────────────────────────────────────────────────────────

/// 5-tuple identifying a TCP/UDP flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl FlowKey {
    #[must_use] 
    pub const fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, proto: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        }
    }

    /// Return a canonical (bi-directional) key where `src < dst`.
    #[must_use]
    pub fn canonical(&self) -> Self {
        let (s, sp, d, dp) = if self.src_ip < self.dst_ip
            || (self.src_ip == self.dst_ip && self.src_port <= self.dst_port)
        {
            (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        } else {
            (self.dst_ip, self.dst_port, self.src_ip, self.src_port)
        };
        Self {
            src_ip: s,
            dst_ip: d,
            src_port: sp,
            dst_port: dp,
            proto: self.proto,
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} → {}:{} (proto {})",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.proto
        )
    }
}

// ─── FlowStats ────────────────────────────────────────────────────────────────

/// Accumulated statistics for one flow.
#[derive(Debug, Clone, Default)]
pub struct FlowStats {
    pub packets: u64,
    pub bytes: u64,
    pub first_ts_us: Option<u64>,
    pub last_ts_us: Option<u64>,
}

impl FlowStats {
    pub fn record(&mut self, pkt_len: usize, ts_us: u64) {
        self.packets += 1;
        self.bytes += pkt_len as u64;
        self.first_ts_us = Some(self.first_ts_us.map_or(ts_us, |t| t.min(ts_us)));
        self.last_ts_us = Some(self.last_ts_us.map_or(ts_us, |t| t.max(ts_us)));
    }

    /// Flow duration in microseconds (0 when only one packet).
    #[must_use]
    pub const fn duration_us(&self) -> u64 {
        match (self.first_ts_us, self.last_ts_us) {
            (Some(f), Some(l)) => l.saturating_sub(f),
            _ => 0,
        }
    }

    /// Average packet size in bytes.
    #[must_use]
    pub fn avg_pkt_bytes(&self) -> f64 {
        if self.packets == 0 {
            return 0.0;
        }
        self.bytes as f64 / self.packets as f64
    }
}

// ─── ConversationTracker ─────────────────────────────────────────────────────

/// Tracks per-flow (conversation) statistics.
#[derive(Debug, Default)]
pub struct ConversationTracker {
    pub flows: HashMap<FlowKey, FlowStats>,
}

impl ConversationTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a packet belonging to `key`.
    pub fn record(&mut self, key: FlowKey, pkt_len: usize, ts_us: u64) {
        self.flows.entry(key).or_default().record(pkt_len, ts_us);
    }

    /// Number of tracked flows.
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Total bytes across all flows.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.flows.values().map(|s| s.bytes).sum()
    }

    /// Top-N flows by byte count.
    #[must_use]
    pub fn top_n_by_bytes(&self, n: usize) -> Vec<(&FlowKey, &FlowStats)> {
        let mut flows: Vec<_> = self.flows.iter().collect();
        flows.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));
        flows.into_iter().take(n).collect()
    }

    /// Find a flow by key, if tracked.
    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<&FlowStats> {
        self.flows.get(key)
    }
}

// ─── ProtocolDistribution ────────────────────────────────────────────────────

/// Packet and byte counts per protocol number.
#[derive(Debug, Default)]
pub struct ProtocolDistribution {
    /// Maps protocol number (L4) → (`packet_count`, `byte_count`).
    pub proto_counts: HashMap<u8, (u64, u64)>,
    /// Maps `EtherType` (u16) → (`packet_count`, `byte_count`).
    pub ethertype_counts: HashMap<u16, (u64, u64)>,
}

impl ProtocolDistribution {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an L4 protocol packet.
    pub fn record_proto(&mut self, proto: u8, pkt_len: usize) {
        let e = self.proto_counts.entry(proto).or_default();
        e.0 += 1;
        e.1 += pkt_len as u64;
    }

    /// Record an `EtherType`.
    pub fn record_ethertype(&mut self, etype: u16, pkt_len: usize) {
        let e = self.ethertype_counts.entry(etype).or_default();
        e.0 += 1;
        e.1 += pkt_len as u64;
    }

    /// Return the percentage of bytes for `proto`.
    #[must_use]
    pub fn proto_byte_pct(&self, proto: u8) -> f64 {
        let total: u64 = self.proto_counts.values().map(|(_, b)| b).sum();
        if total == 0 {
            return 0.0;
        }
        let proto_bytes = self.proto_counts.get(&proto).map_or(0, |(_, b)| *b);
        proto_bytes as f64 / total as f64 * 100.0
    }

    /// Return the most common L4 protocol number.
    #[must_use]
    pub fn dominant_proto(&self) -> Option<u8> {
        self.proto_counts
            .iter()
            .max_by_key(|(_, (c, _))| c)
            .map(|(p, _)| *p)
    }

    /// Sorted list of (proto, `packet_count`).
    #[must_use]
    pub fn sorted_by_packets(&self) -> Vec<(u8, u64)> {
        let mut v: Vec<(u8, u64)> = self
            .proto_counts
            .iter()
            .map(|(&p, &(c, _))| (p, c))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

// ─── IOGraph ──────────────────────────────────────────────────────────────────

/// Bytes-over-time IO graph with configurable bucket width.
#[derive(Debug)]
pub struct IOGraph {
    /// Bucket width in microseconds.
    pub bucket_us: u64,
    /// Maps `bucket_index` → byte count.
    pub buckets: HashMap<u64, u64>,
}

impl IOGraph {
    #[must_use]
    pub fn new(bucket_us: u64) -> Self {
        Self {
            bucket_us,
            buckets: HashMap::new(),
        }
    }

    /// Default 1-second buckets.
    #[must_use]
    pub fn one_second() -> Self {
        Self::new(1_000_000)
    }

    pub fn record(&mut self, ts_us: u64, bytes: usize) {
        let idx = ts_us / self.bucket_us;
        *self.buckets.entry(idx).or_default() += bytes as u64;
    }

    /// Maximum bytes in any single bucket.
    #[must_use]
    pub fn peak_bytes(&self) -> u64 {
        self.buckets.values().copied().max().unwrap_or(0)
    }

    /// Average bytes per bucket (over non-empty buckets).
    #[must_use]
    pub fn avg_bytes_per_bucket(&self) -> f64 {
        if self.buckets.is_empty() {
            return 0.0;
        }
        let total: u64 = self.buckets.values().sum();
        total as f64 / self.buckets.len() as f64
    }

    /// Sorted bucket entries `(bucket_idx, byte_count)`.
    #[must_use]
    pub fn sorted_buckets(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<_> = self.buckets.iter().map(|(&k, &v)| (k, v)).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }

    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }
}

// ─── TopTalkers ──────────────────────────────────────────────────────────────

/// Tracks per-IP byte and packet counts.
#[derive(Debug, Default)]
pub struct TopTalkers {
    /// Maps IP address → (`packet_count`, `byte_count`).
    pub counts: HashMap<IpAddr, (u64, u64)>,
}

impl TopTalkers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, ip: IpAddr, pkt_len: usize) {
        let e = self.counts.entry(ip).or_default();
        e.0 += 1;
        e.1 += pkt_len as u64;
    }

    /// Top-N talkers by byte count.
    #[must_use]
    pub fn top_n_by_bytes(&self, n: usize) -> Vec<(IpAddr, u64, u64)> {
        let mut v: Vec<_> = self
            .counts
            .iter()
            .map(|(&ip, &(p, b))| (ip, p, b))
            .collect();
        v.sort_by(|a, b| b.2.cmp(&a.2));
        v.into_iter().take(n).collect()
    }

    /// Total unique IPs seen.
    #[must_use]
    pub fn unique_ips(&self) -> usize {
        self.counts.len()
    }

    /// Total bytes across all IPs.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.counts.values().map(|(_, b)| b).sum()
    }
}

// ─── DnsAnalysis ─────────────────────────────────────────────────────────────

/// Minimal DNS question/answer extraction from UDP payloads.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rdata: String,
    pub is_query: bool,
}

impl DnsRecord {
    #[must_use]
    pub const fn type_str(&self) -> &'static str {
        match self.rtype {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            15 => "MX",
            28 => "AA",
            _ => "?",
        }
    }
}

#[derive(Debug, Default)]
pub struct DnsAnalysis {
    pub records: Vec<DnsRecord>,
    /// Maps queried names → number of queries.
    pub query_counts: HashMap<String, u64>,
}

impl DnsAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to parse a UDP payload as DNS.
    ///
    /// This is a stub that recognises the DNS header but only extracts the
    /// QD count and ANCOUNT.  A full implementation would parse the wire format.
    pub fn ingest_udp_payload(&mut self, payload: &[u8]) {
        if payload.len() < 12 {
            return;
        }
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let is_query = (flags >> 15) == 0;
        let qd_count = u16::from_be_bytes([payload[4], payload[5]]);
        let an_count = u16::from_be_bytes([payload[6], payload[7]]);

        // Stub: emit synthetic records based on header counts.
        let name = format!("q{qd_count}_{an_count}");
        if is_query {
            *self.query_counts.entry(name.clone()).or_default() += 1;
        }
        self.records.push(DnsRecord {
            name,
            rtype: 1,
            rdata: "0.0.0.0".to_string(),
            is_query,
        });
    }

    /// Most frequently queried names (top-N).
    #[must_use]
    pub fn top_queried(&self, n: usize) -> Vec<(&str, u64)> {
        let mut v: Vec<_> = self
            .query_counts
            .iter()
            .map(|(k, &v)| (k.as_str(), v))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.into_iter().take(n).collect()
    }

    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn query_count(&self) -> usize {
        self.records.iter().filter(|r| r.is_query).count()
    }
}

// ─── TlsHandshake ────────────────────────────────────────────────────────────

/// Extracted TLS `ClientHello` / `ServerHello` metadata.
#[derive(Debug, Clone)]
pub struct TlsHandshake {
    pub is_client_hello: bool,
    pub tls_version: u16,
    /// SNI from `ClientHello`, if present.
    pub sni: Option<String>,
    /// Cipher suites offered (`ClientHello`) or selected (`ServerHello`).
    pub cipher_suites: Vec<u16>,
    /// Session ID length.
    pub session_id_len: u8,
}

impl TlsHandshake {
    /// Attempt to parse a TLS record from `data`.
    ///
    /// Recognises the TLS record header (0x16 = Handshake) and handshake
    /// type (0x01 = `ClientHello`, 0x02 = `ServerHello`).
    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 9 {
            return None;
        }
        if data[0] != 0x16 {
            return None;
        } // not a Handshake record
        let tls_version = u16::from_be_bytes([data[1], data[2]]);
        let hs_type = data[5];
        if hs_type != 0x01 && hs_type != 0x02 {
            return None;
        }
        let is_client = hs_type == 0x01;
        let session_id_len = if data.len() > 43 { data[43] } else { 0 };
        Some(Self {
            is_client_hello: is_client,
            tls_version,
            sni: None, // full SNI extraction would parse extensions
            cipher_suites: Vec::new(),
            session_id_len,
        })
    }

    #[must_use]
    pub const fn version_str(&self) -> &'static str {
        match self.tls_version {
            0x0301 => "TLS 1.0",
            0x0302 => "TLS 1.1",
            0x0303 => "TLS 1.2",
            0x0304 => "TLS 1.3",
            _ => "Unknown",
        }
    }

    #[must_use]
    pub const fn handshake_type_str(&self) -> &'static str {
        if self.is_client_hello {
            "ClientHello"
        } else {
            "ServerHello"
        }
    }
}

#[derive(Debug, Default)]
pub struct TlsHandshakeExtractor {
    pub handshakes: Vec<TlsHandshake>,
}

impl TlsHandshakeExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest(&mut self, data: &[u8]) {
        if let Some(hs) = TlsHandshake::parse(data) {
            self.handshakes.push(hs);
        }
    }

    #[must_use]
    pub fn client_hellos(&self) -> Vec<&TlsHandshake> {
        self.handshakes
            .iter()
            .filter(|h| h.is_client_hello)
            .collect()
    }

    #[must_use]
    pub fn server_hellos(&self) -> Vec<&TlsHandshake> {
        self.handshakes
            .iter()
            .filter(|h| !h.is_client_hello)
            .collect()
    }

    #[must_use]
    pub const fn total(&self) -> usize {
        self.handshakes.len()
    }
}

// ─── PcapAnalyzer ─────────────────────────────────────────────────────────────

/// Top-level PCAP analyser.
///
/// Ingest packets one by one via [`PcapAnalyzer::ingest`]; then query the
/// sub-analysers for results.
#[derive(Debug, Default)]
pub struct PcapAnalyzer {
    pub conversations: ConversationTracker,
    pub protocols: ProtocolDistribution,
    pub io_graph: Option<IOGraph>,
    pub top_talkers: TopTalkers,
    pub dns: DnsAnalysis,
    pub tls: TlsHandshakeExtractor,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub first_ts_us: Option<u64>,
    pub last_ts_us: Option<u64>,
}

impl PcapAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_io_graph(bucket_us: u64) -> Self {
        Self {
            io_graph: Some(IOGraph::new(bucket_us)),
            ..Default::default()
        }
    }

    /// Ingest a raw Ethernet packet.
    pub fn ingest(&mut self, pkt: &Packet) {
        self.total_packets += 1;
        self.total_bytes += pkt.data.len() as u64;
        self.first_ts_us = Some(self.first_ts_us.map_or(pkt.ts_us, |t| t.min(pkt.ts_us)));
        self.last_ts_us = Some(self.last_ts_us.map_or(pkt.ts_us, |t| t.max(pkt.ts_us)));

        if let Some(graph) = &mut self.io_graph {
            graph.record(pkt.ts_us, pkt.data.len());
        }

        // Parse Ethernet header.
        if pkt.data.len() < 14 {
            return;
        }
        let etype = u16::from_be_bytes([pkt.data[12], pkt.data[13]]);
        self.protocols.record_ethertype(etype, pkt.data.len());

        match etype {
            0x0800 => self.ingest_ipv4(pkt),
            0x86DD => self.ingest_ipv6(pkt),
            _ => {}
        }
    }

    fn ingest_ipv4(&mut self, pkt: &Packet) {
        let eth_payload = &pkt.data[14..];
        if eth_payload.len() < 20 {
            return;
        }
        let ihl = (eth_payload[0] & 0xF) as usize * 4;
        let proto = eth_payload[9];
        let src = Ipv4Addr::new(
            eth_payload[12],
            eth_payload[13],
            eth_payload[14],
            eth_payload[15],
        );
        let dst = Ipv4Addr::new(
            eth_payload[16],
            eth_payload[17],
            eth_payload[18],
            eth_payload[19],
        );
        self.protocols.record_proto(proto, pkt.data.len());
        self.top_talkers.record(IpAddr::V4(src), pkt.data.len());
        self.top_talkers.record(IpAddr::V4(dst), pkt.data.len());

        if eth_payload.len() > ihl {
            let transport = &eth_payload[ihl..];
            match proto {
                6 => self.ingest_tcp(src, dst, transport, pkt.ts_us, pkt.data.len()),
                17 => self.ingest_udp(src, dst, transport, pkt.ts_us, pkt.data.len()),
                _ => {}
            }
        }
    }

    fn ingest_ipv6(&mut self, pkt: &Packet) {
        let eth_payload = &pkt.data[14..];
        if eth_payload.len() < 40 {
            return;
        }
        let next_hdr = eth_payload[6];
        let src_bytes: [u8; 16] = eth_payload[8..24].try_into().unwrap_or([0u8; 16]);
        let dst_bytes: [u8; 16] = eth_payload[24..40].try_into().unwrap_or([0u8; 16]);
        let src = IpAddr::V6(Ipv6Addr::from(src_bytes));
        let dst = IpAddr::V6(Ipv6Addr::from(dst_bytes));
        self.protocols.record_proto(next_hdr, pkt.data.len());
        self.top_talkers.record(src, pkt.data.len());
        self.top_talkers.record(dst, pkt.data.len());
    }

    fn ingest_tcp(&mut self, src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8], ts: u64, pkt_len: usize) {
        if tcp.len() < 20 {
            return;
        }
        let sp = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dp = u16::from_be_bytes([tcp[2], tcp[3]]);
        let key = FlowKey::new(IpAddr::V4(src), IpAddr::V4(dst), sp, dp, 6);
        self.conversations.record(key.canonical(), pkt_len, ts);
        // TLS detection: dst/src port 443.
        if dp == 443 || sp == 443 {
            let doff = ((tcp[12] >> 4) as usize) * 4;
            if tcp.len() > doff {
                self.tls.ingest(&tcp[doff..]);
            }
        }
    }

    fn ingest_udp(&mut self, src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8], ts: u64, pkt_len: usize) {
        if udp.len() < 8 {
            return;
        }
        let sp = u16::from_be_bytes([udp[0], udp[1]]);
        let dp = u16::from_be_bytes([udp[2], udp[3]]);
        let key = FlowKey::new(IpAddr::V4(src), IpAddr::V4(dst), sp, dp, 17);
        self.conversations.record(key.canonical(), pkt_len, ts);
        // DNS detection: dst/src port 53.
        if dp == 53 || sp == 53 {
            self.dns.ingest_udp_payload(&udp[8..]);
        }
    }

    /// Capture duration in microseconds.
    #[must_use]
    pub const fn duration_us(&self) -> u64 {
        match (self.first_ts_us, self.last_ts_us) {
            (Some(f), Some(l)) => l.saturating_sub(f),
            _ => 0,
        }
    }

    /// Average packet size.
    #[must_use]
    pub fn avg_pkt_bytes(&self) -> f64 {
        if self.total_packets == 0 {
            return 0.0;
        }
        self.total_bytes as f64 / self.total_packets as f64
    }

    /// Packets per second (0.0 when duration is zero).
    #[must_use]
    pub fn pps(&self) -> f64 {
        let secs = self.duration_us() as f64 / 1_000_000.0;
        if secs == 0.0 {
            return 0.0;
        }
        self.total_packets as f64 / secs
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_udp_packet(
        ts: u64,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sp: u16,
        dp: u16,
        payload: &[u8],
    ) -> Packet {
        let mut data = Vec::new();
        // Ethernet header (14 bytes, EtherType 0x0800)
        data.extend_from_slice(&[0u8; 6]); // dst mac
        data.extend_from_slice(&[0u8; 6]); // src mac
        data.extend_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4 header (20 bytes)
        let ip_total = 20u16 + 8 + u16::try_from(payload.len()).unwrap_or(u16::MAX);
        data.push(0x45); // ver + IHL
        data.push(0);
        data.extend_from_slice(&ip_total.to_be_bytes());
        data.extend_from_slice(&[0u8; 4]); // id, flags, frag
        data.push(64); // TTL
        data.push(17); // UDP
        data.extend_from_slice(&[0u8; 2]); // checksum (unchecked)
        data.extend_from_slice(&src.octets());
        data.extend_from_slice(&dst.octets());
        // UDP header (8 bytes)
        data.extend_from_slice(&sp.to_be_bytes());
        data.extend_from_slice(&dp.to_be_bytes());
        data.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap_or(u16::MAX).to_be_bytes());
        data.extend_from_slice(&[0u8; 2]); // checksum
        data.extend_from_slice(payload);
        Packet::new(ts, data)
    }

    // FlowKey tests ─────────────────────────────────────────────────────────

    #[test]
    fn flow_key_canonical_idempotent() {
        let k = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
            80,
            6,
        );
        let c1 = k.canonical();
        let c2 = c1.canonical();
        assert_eq!(c1, c2);
    }

    #[test]
    fn flow_key_canonical_swaps_when_greater() {
        let k = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(200, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            9999,
            80,
            6,
        );
        let c = k.canonical();
        assert!(c.src_ip <= c.dst_ip);
    }

    #[test]
    fn flow_key_display() {
        let k = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            80,
            443,
            6,
        );
        assert!(k.to_string().contains("80"));
        assert!(k.to_string().contains("443"));
    }

    // FlowStats tests ───────────────────────────────────────────────────────

    #[test]
    fn flow_stats_accumulate() {
        let mut s = FlowStats::default();
        s.record(100, 1000);
        s.record(200, 2000);
        assert_eq!(s.packets, 2);
        assert_eq!(s.bytes, 300);
    }

    #[test]
    fn flow_stats_duration() {
        let mut s = FlowStats::default();
        s.record(10, 0);
        s.record(10, 1_000_000);
        assert_eq!(s.duration_us(), 1_000_000);
    }

    #[test]
    fn flow_stats_avg_bytes() {
        let mut s = FlowStats::default();
        s.record(100, 0);
        s.record(200, 0);
        assert!((s.avg_pkt_bytes() - 150.0).abs() < 0.001);
    }

    // ConversationTracker tests ─────────────────────────────────────────────

    #[test]
    fn conversation_tracker_records_flows() {
        let mut ct = ConversationTracker::new();
        let k = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            80,
            443,
            6,
        );
        ct.record(k.clone(), 100, 0);
        ct.record(k, 200, 0);
        assert_eq!(ct.flow_count(), 1);
        assert_eq!(ct.total_bytes(), 300);
    }

    #[test]
    fn conversation_top_n() {
        let mut ct = ConversationTracker::new();
        for i in 0u16..5 {
            let k = FlowKey::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::BROADCAST),
                i,
                80,
                6,
            );
            ct.record(k, (i as usize + 1) * 100, 0);
        }
        let top = ct.top_n_by_bytes(3);
        assert_eq!(top.len(), 3);
    }

    // ProtocolDistribution tests ────────────────────────────────────────────

    #[test]
    fn proto_distribution_records() {
        let mut pd = ProtocolDistribution::new();
        pd.record_proto(6, 100); // TCP
        pd.record_proto(17, 50); // UDP
        pd.record_proto(6, 200);
        assert_eq!(pd.proto_counts[&6].0, 2);
    }

    #[test]
    fn proto_distribution_dominant() {
        let mut pd = ProtocolDistribution::new();
        pd.record_proto(6, 100);
        pd.record_proto(6, 100);
        pd.record_proto(17, 50);
        assert_eq!(pd.dominant_proto(), Some(6));
    }

    #[test]
    fn proto_byte_pct() {
        let mut pd = ProtocolDistribution::new();
        pd.record_proto(6, 80);
        pd.record_proto(17, 20);
        assert!((pd.proto_byte_pct(6) - 80.0).abs() < 0.1);
    }

    // IOGraph tests ─────────────────────────────────────────────────────────

    #[test]
    fn io_graph_buckets() {
        let mut g = IOGraph::one_second();
        g.record(0, 100);
        g.record(500_000, 200);
        g.record(1_000_000, 50); // second bucket
        assert_eq!(g.bucket_count(), 2);
    }

    #[test]
    fn io_graph_peak() {
        let mut g = IOGraph::one_second();
        g.record(0, 100);
        g.record(0, 400); // same bucket = 500
        g.record(2_000_000, 10);
        assert_eq!(g.peak_bytes(), 500);
    }

    #[test]
    fn io_graph_sorted_buckets() {
        let mut g = IOGraph::one_second();
        g.record(3_000_000, 1);
        g.record(1_000_000, 2);
        g.record(2_000_000, 3);
        let sorted = g.sorted_buckets();
        assert_eq!(sorted[0].0, 1);
        assert_eq!(sorted[2].0, 3);
    }

    // TopTalkers tests ──────────────────────────────────────────────────────

    #[test]
    fn top_talkers_unique_ips() {
        let mut t = TopTalkers::new();
        t.record(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 100);
        t.record(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 200);
        assert_eq!(t.unique_ips(), 2);
    }

    #[test]
    fn top_talkers_top_n() {
        let mut t = TopTalkers::new();
        t.record(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 500);
        t.record(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 100);
        let top = t.top_n_by_bytes(1);
        assert_eq!(top[0].0, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    // DnsAnalysis tests ─────────────────────────────────────────────────────

    #[test]
    fn dns_ingest_stub() {
        let mut dns = DnsAnalysis::new();
        // Minimal DNS query header (QD=1, AN=0, NS=0, AR=0)
        let payload = b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        dns.ingest_udp_payload(payload);
        assert_eq!(dns.record_count(), 1);
        assert_eq!(dns.query_count(), 1);
    }

    #[test]
    fn dns_too_short_ignored() {
        let mut dns = DnsAnalysis::new();
        dns.ingest_udp_payload(b"\x00\x01");
        assert_eq!(dns.record_count(), 0);
    }

    // TlsHandshake tests ────────────────────────────────────────────────────

    #[test]
    fn tls_parse_client_hello() {
        // TLS record: type=22, version=0x0303, ClientHello=1
        let mut data = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // record header
            0x01, // ClientHello
        ];
        data.resize(50, 0);
        let hs = TlsHandshake::parse(&data).unwrap();
        assert!(hs.is_client_hello);
        assert_eq!(hs.version_str(), "TLS 1.2");
    }

    #[test]
    fn tls_parse_server_hello() {
        let mut data = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, 0x02, // ServerHello
        ];
        data.resize(50, 0);
        let hs = TlsHandshake::parse(&data).unwrap();
        assert!(!hs.is_client_hello);
        assert_eq!(hs.handshake_type_str(), "ServerHello");
    }

    #[test]
    fn tls_parse_non_handshake_returns_none() {
        let data = vec![0x17u8; 50]; // Application data
        assert!(TlsHandshake::parse(&data).is_none());
    }

    #[test]
    fn tls_extractor_client_hellos() {
        let mut ext = TlsHandshakeExtractor::new();
        let mut ch = vec![0x16, 0x03, 0x03, 0x00, 0x00, 0x01];
        ch.resize(50, 0);
        ext.ingest(&ch);
        assert_eq!(ext.client_hellos().len(), 1);
        assert_eq!(ext.server_hellos().len(), 0);
    }

    // PcapAnalyzer tests ────────────────────────────────────────────────────

    #[test]
    fn analyzer_ingest_single_packet() {
        let mut az = PcapAnalyzer::new();
        let pkt = make_udp_packet(
            1_000_000,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            5000,
            80,
            b"hello",
        );
        az.ingest(&pkt);
        assert_eq!(az.total_packets, 1);
        assert!(az.total_bytes > 0);
    }

    #[test]
    fn analyzer_conversation_tracked() {
        let mut az = PcapAnalyzer::new();
        let pkt = make_udp_packet(
            0,
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            1111,
            2222,
            b"data",
        );
        az.ingest(&pkt);
        assert_eq!(az.conversations.flow_count(), 1);
    }

    #[test]
    fn analyzer_top_talkers_counted() {
        let mut az = PcapAnalyzer::new();
        let pkt = make_udp_packet(
            0,
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(2, 2, 2, 2),
            1234,
            5678,
            b"x",
        );
        az.ingest(&pkt);
        assert!(az.top_talkers.unique_ips() >= 2);
    }

    #[test]
    fn analyzer_duration_us() {
        let mut az = PcapAnalyzer::new();
        az.ingest(&make_udp_packet(
            1_000,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            1,
            2,
            b"a",
        ));
        az.ingest(&make_udp_packet(
            3_000,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            1,
            2,
            b"b",
        ));
        assert_eq!(az.duration_us(), 2_000);
    }

    #[test]
    fn analyzer_avg_pkt_bytes() {
        let mut az = PcapAnalyzer::new();
        az.ingest(&make_udp_packet(
            0,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            1,
            2,
            b"ab",
        ));
        assert!(az.avg_pkt_bytes() > 0.0);
    }

    #[test]
    fn analyzer_with_io_graph() {
        let mut az = PcapAnalyzer::with_io_graph(1_000_000);
        az.ingest(&make_udp_packet(
            0,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            1,
            2,
            b"x",
        ));
        assert!(az.io_graph.as_ref().unwrap().bucket_count() > 0);
    }

    #[test]
    fn packet_len_and_timestamp() {
        let pkt = Packet::new(5_000_000, vec![0u8; 100]);
        assert_eq!(pkt.len(), 100);
        assert_eq!(pkt.timestamp().as_secs(), 5);
        assert!(!pkt.is_empty());
    }

    #[test]
    fn io_graph_avg_bytes() {
        let mut g = IOGraph::one_second();
        g.record(0, 1000);
        g.record(1_000_000, 500);
        let avg = g.avg_bytes_per_bucket();
        assert!((avg - 750.0).abs() < 0.001);
    }

    #[test]
    fn top_talkers_total_bytes() {
        let mut t = TopTalkers::new();
        t.record(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 300);
        t.record(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 200);
        assert_eq!(t.total_bytes(), 500);
    }

    #[test]
    fn dns_response_record_not_counted_as_query() {
        let mut dns = DnsAnalysis::new();
        // DNS response: flags bit 15 = 1
        let payload = b"\x00\x01\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00";
        dns.ingest_udp_payload(payload);
        assert_eq!(dns.query_count(), 0);
        assert_eq!(dns.record_count(), 1);
    }

    #[test]
    fn tls_handshake_type_str_client() {
        let hs = TlsHandshake {
            is_client_hello: true,
            tls_version: 0x0303,
            sni: None,
            cipher_suites: vec![],
            session_id_len: 0,
        };
        assert_eq!(hs.handshake_type_str(), "ClientHello");
    }

    #[test]
    fn tls_version_str_tls13() {
        let hs = TlsHandshake {
            is_client_hello: false,
            tls_version: 0x0304,
            sni: None,
            cipher_suites: vec![],
            session_id_len: 0,
        };
        assert_eq!(hs.version_str(), "TLS 1.3");
    }

    #[test]
    fn conversation_tracker_get_known_flow() {
        let mut ct = ConversationTracker::new();
        let k = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            80,
            443,
            6,
        )
        .canonical();
        ct.record(k.clone(), 50, 1000);
        assert!(ct.get(&k).is_some());
        assert_eq!(ct.get(&k).unwrap().bytes, 50);
    }

    #[test]
    fn protocol_distribution_sorted() {
        let mut pd = ProtocolDistribution::new();
        pd.record_proto(17, 10);
        pd.record_proto(6, 100);
        pd.record_proto(6, 100);
        let sorted = pd.sorted_by_packets();
        assert_eq!(sorted[0].0, 6);
    }
}
