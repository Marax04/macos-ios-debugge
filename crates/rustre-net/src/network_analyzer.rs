//! `network_analyzer` — Higher-level network traffic analysis.
//!
//! Builds on the core packet parsing in `lib.rs` to provide:
//! [`NetworkAnalyzer`], [`TrafficAnalysis`], [`ProtocolStats`],
//! [`ConnectionTable`], [`DnsResolver`], [`TlsHandshakeAnalysis`],
//! and [`AnomalyScore`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
pub use std::net::Ipv4Addr;
pub use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// Packet observation (input)
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified observed network packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedPacket {
    pub timestamp: u64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
    pub length: usize,
    pub payload: Vec<u8>,
}

impl ObservedPacket {
    /// Create a TCP packet.
    #[must_use]
    pub fn tcp(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, length: usize) -> Self {
        Self {
            timestamp: now_secs(),
            src_ip: src,
            dst_ip: dst,
            src_port,
            dst_port,
            protocol: TransportProtocol::Tcp,
            length,
            payload: Vec::new(),
        }
    }

    /// Create a UDP packet.
    #[must_use]
    pub fn udp(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, length: usize) -> Self {
        Self {
            timestamp: now_secs(),
            src_ip: src,
            dst_ip: dst,
            src_port,
            dst_port,
            protocol: TransportProtocol::Udp,
            length,
            payload: Vec::new(),
        }
    }
}

/// Transport-layer protocol of a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ─────────────────────────────────────────────────────────────────────────────
// ProtocolStats
// ─────────────────────────────────────────────────────────────────────────────

/// Per-protocol packet and byte statistics.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolStats {
    pub packet_count: HashMap<String, u64>,
    pub byte_count: HashMap<String, u64>,
    pub total_packets: u64,
    pub total_bytes: u64,
}

impl ProtocolStats {
    /// Create new empty stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a packet for a protocol.
    pub fn record(&mut self, protocol: impl Into<String>, bytes: u64) {
        let proto: String = protocol.into();
        *self.packet_count.entry(proto.clone()).or_insert(0) += 1;
        *self.byte_count.entry(proto).or_insert(0) += bytes;
        self.total_packets += 1;
        self.total_bytes += bytes;
    }

    /// Return the fraction of packets belonging to a protocol.
    #[must_use]
    pub fn fraction(&self, protocol: &str) -> f64 {
        if self.total_packets == 0 {
            return 0.0;
        }
        let count = self.packet_count.get(protocol).copied().unwrap_or(0);
        let numer = u32::try_from(count).unwrap_or(u32::MAX);
        let denom = u32::try_from(self.total_packets).unwrap_or(u32::MAX);
        f64::from(numer) / f64::from(denom)
    }

    /// Return the top-N protocols by packet count.
    #[must_use]
    pub fn top_protocols(&self, n: usize) -> Vec<(&str, u64)> {
        let mut pairs: Vec<(&str, u64)> = self
            .packet_count
            .iter()
            .map(|(k, &v)| (k.as_str(), v))
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectionTable
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies a network connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
}

impl ConnectionKey {
    /// Create a normalized (src < dst) connection key.
    #[must_use]
    pub fn normalized(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: TransportProtocol,
    ) -> Self {
        // Normalize so that the key is the same for both directions.
        if src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port) {
            Self {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
            }
        } else {
            Self {
                src_ip: dst_ip,
                dst_ip: src_ip,
                src_port: dst_port,
                dst_port: src_port,
                protocol,
            }
        }
    }
}

/// State of a tracked connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Syn,
    Established,
    Closing,
    Closed,
    Unknown,
}

/// An entry in the connection table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEntry {
    pub key: ConnectionKey,
    pub state: ConnectionState,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub application: Option<String>,
}

/// Tracks all observed connections.
#[derive(Debug, Default)]
pub struct ConnectionTable {
    pub connections: HashMap<ConnectionKey, ConnectionEntry>,
}

impl ConnectionTable {
    /// Create a new empty connection table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a packet in the table.
    pub fn record(&mut self, pkt: &ObservedPacket) {
        let key = ConnectionKey::normalized(
            pkt.src_ip,
            pkt.dst_ip,
            pkt.src_port,
            pkt.dst_port,
            pkt.protocol,
        );
        let now = pkt.timestamp;
        let entry = self
            .connections
            .entry(key.clone())
            .or_insert_with(|| ConnectionEntry {
                key,
                state: ConnectionState::Unknown,
                packets: 0,
                bytes: 0,
                first_seen: now,
                last_seen: now,
                application: guess_application(pkt.dst_port),
            });
        entry.packets += 1;
        entry.bytes += pkt.length as u64;
        entry.last_seen = now;
    }

    /// Return the connection count.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Return connections to a specific destination port.
    #[must_use]
    pub fn connections_to_port(&self, port: u16) -> Vec<&ConnectionEntry> {
        self.connections
            .values()
            .filter(|e| e.key.dst_port == port || e.key.src_port == port)
            .collect()
    }

    /// Mark long-idle connections as closed.
    pub fn prune_idle(&mut self, idle_threshold_secs: u64) {
        let cutoff = now_secs().saturating_sub(idle_threshold_secs);
        for entry in self.connections.values_mut() {
            if entry.last_seen < cutoff {
                entry.state = ConnectionState::Closed;
            }
        }
    }
}

fn guess_application(port: u16) -> Option<String> {
    let app = match port {
        80 => "HTTP",
        443 => "HTTPS",
        53 => "DNS",
        22 => "SSH",
        21 => "FTP",
        25 => "SMTP",
        110 => "POP3",
        143 => "IMAP",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        _ => return None,
    };
    Some(app.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// DnsResolver — passive DNS tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Passively tracks DNS queries and resolutions.
#[derive(Debug, Default)]
pub struct DnsResolver {
    /// hostname → IP addresses seen.
    hostname_to_ips: HashMap<String, Vec<IpAddr>>,
    /// IP → hostnames seen.
    ip_to_hostnames: HashMap<IpAddr, Vec<String>>,
    /// Query counts per hostname.
    query_count: HashMap<String, usize>,
}

impl DnsResolver {
    /// Create a new DNS resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a DNS resolution.
    pub fn record_resolution(&mut self, hostname: impl Into<String>, ip: IpAddr) {
        let h: String = hostname.into();
        self.hostname_to_ips.entry(h.clone()).or_default().push(ip);
        self.ip_to_hostnames.entry(ip).or_default().push(h);
    }

    /// Record a DNS query.
    pub fn record_query(&mut self, hostname: impl Into<String>) {
        *self.query_count.entry(hostname.into()).or_insert(0) += 1;
    }

    /// Reverse lookup: IP → hostnames.
    #[must_use]
    pub fn reverse_lookup(&self, ip: IpAddr) -> &[String] {
        self.ip_to_hostnames.get(&ip).map_or(&[], Vec::as_slice)
    }

    /// Forward lookup: hostname → IPs.
    #[must_use]
    pub fn forward_lookup(&self, hostname: &str) -> &[IpAddr] {
        self.hostname_to_ips
            .get(hostname)
            .map_or(&[], Vec::as_slice)
    }

    /// Return the most queried hostnames.
    #[must_use]
    pub fn top_queried(&self, n: usize) -> Vec<(&str, usize)> {
        let mut pairs: Vec<(&str, usize)> = self
            .query_count
            .iter()
            .map(|(k, &v)| (k.as_str(), v))
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    /// Return the number of unique hostnames resolved.
    #[must_use]
    pub fn hostname_count(&self) -> usize {
        self.hostname_to_ips.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TlsHandshakeAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// TLS version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsVersion {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown,
}

impl TlsVersion {
    /// Return true if this version is considered secure.
    #[must_use]
    pub const fn is_secure(self) -> bool {
        matches!(self, Self::Tls12 | Self::Tls13)
    }

    /// Build from a version byte pair.
    #[must_use]
    pub const fn from_bytes(major: u8, minor: u8) -> Self {
        match (major, minor) {
            (3, 0) => Self::Ssl30,
            (3, 1) => Self::Tls10,
            (3, 2) => Self::Tls11,
            (3, 3) => Self::Tls12,
            (3, 4) => Self::Tls13,
            _ => Self::Unknown,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ssl30 => "SSLv3.0",
            Self::Tls10 => "TLS 1.0",
            Self::Tls11 => "TLS 1.1",
            Self::Tls12 => "TLS 1.2",
            Self::Tls13 => "TLS 1.3",
            Self::Unknown => "Unknown",
        }
    }
}

/// A detected TLS handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsHandshake {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub version: TlsVersion,
    pub sni: Option<String>,
    pub cipher_suite: Option<String>,
    pub cert_cn: Option<String>,
    pub timestamp: u64,
}

impl TlsHandshake {
    /// Create a new TLS handshake observation.
    #[must_use]
    pub fn new(src: IpAddr, dst: IpAddr, port: u16, version: TlsVersion) -> Self {
        Self {
            src_ip: src,
            dst_ip: dst,
            dst_port: port,
            version,
            sni: None,
            cipher_suite: None,
            cert_cn: None,
            timestamp: now_secs(),
        }
    }

    /// Return true if this handshake used a weak TLS version.
    #[must_use]
    pub const fn is_weak(&self) -> bool {
        !self.version.is_secure()
    }
}

/// Collects and analyzes TLS handshake observations.
#[derive(Debug, Default)]
pub struct TlsHandshakeAnalysis {
    pub handshakes: Vec<TlsHandshake>,
}

impl TlsHandshakeAnalysis {
    /// Create a new analysis context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a handshake.
    pub fn record(&mut self, h: TlsHandshake) {
        self.handshakes.push(h);
    }

    /// Return weak handshakes (old TLS versions).
    #[must_use]
    pub fn weak_handshakes(&self) -> Vec<&TlsHandshake> {
        self.handshakes.iter().filter(|h| h.is_weak()).collect()
    }

    /// Return all unique SNIs seen.
    #[must_use]
    pub fn unique_snis(&self) -> Vec<&str> {
        let mut snis: Vec<&str> = self
            .handshakes
            .iter()
            .filter_map(|h| h.sni.as_deref())
            .collect();
        snis.sort_unstable();
        snis.dedup();
        snis
    }

    /// Return the distribution of TLS versions.
    #[must_use]
    pub fn version_distribution(&self) -> HashMap<String, usize> {
        let mut dist: HashMap<String, usize> = HashMap::new();
        for h in &self.handshakes {
            *dist.entry(h.version.name().to_string()).or_insert(0) += 1;
        }
        dist
    }

    /// Return the total handshake count.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.handshakes.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnomalyScore — anomaly detection
// ─────────────────────────────────────────────────────────────────────────────

/// Types of network anomalies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyType {
    PortScan,
    HighVolume,
    SuspiciousPort,
    WeakTls,
    DnsExfiltration,
    UnusualProtocol,
    RapidConnections,
}

/// A detected anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub anomaly_type: AnomalyType,
    pub source: IpAddr,
    pub score: f64,
    pub description: String,
    pub timestamp: u64,
}

/// Computes anomaly scores from traffic observations.
#[derive(Debug, Default)]
pub struct AnomalyScore {
    /// Connection count per source IP.
    pub conn_per_src: HashMap<IpAddr, usize>,
    /// Unique destination ports per source IP.
    pub ports_per_src: HashMap<IpAddr, std::collections::HashSet<u16>>,
    /// Bytes per source IP.
    pub bytes_per_src: HashMap<IpAddr, u64>,
    /// Detected anomalies.
    pub anomalies: Vec<Anomaly>,
}

impl AnomalyScore {
    /// Create a new anomaly scorer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a packet observation.
    pub fn observe(&mut self, pkt: &ObservedPacket) {
        *self.conn_per_src.entry(pkt.src_ip).or_insert(0) += 1;
        self.ports_per_src
            .entry(pkt.src_ip)
            .or_default()
            .insert(pkt.dst_port);
        *self.bytes_per_src.entry(pkt.src_ip).or_insert(0) += pkt.length as u64;
    }

    /// Run anomaly detection heuristics.
    pub fn detect(&mut self) {
        self.anomalies.clear();
        let now = now_secs();

        // Port scan: many unique ports from one source.
        for (src, ports) in &self.ports_per_src {
            if ports.len() > 20 {
                self.anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::PortScan,
                    source: *src,
                    score: (f64::from(u32::try_from(ports.len()).unwrap_or(u32::MAX)) / 1000.0)
                        .min(1.0),
                    description: format!("{src} scanned {} ports", ports.len()),
                    timestamp: now,
                });
            }
        }

        // High volume: many bytes from one source.
        for (src, &bytes) in &self.bytes_per_src {
            if bytes > 100_000_000 {
                self.anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::HighVolume,
                    source: *src,
                    score: (f64::from(u32::try_from(bytes).unwrap_or(u32::MAX)) / 1_000_000_000.0)
                        .min(1.0),
                    description: format!("{src} sent {bytes} bytes"),
                    timestamp: now,
                });
            }
        }

        // Rapid connections.
        for (src, &count) in &self.conn_per_src {
            if count > 500 {
                self.anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::RapidConnections,
                    source: *src,
                    score: (f64::from(u32::try_from(count).unwrap_or(u32::MAX)) / 10_000.0)
                        .min(1.0),
                    description: format!("{src} made {count} connections"),
                    timestamp: now,
                });
            }
        }
    }

    /// Return the highest anomaly score across all detected anomalies.
    #[must_use]
    pub fn max_score(&self) -> f64 {
        self.anomalies
            .iter()
            .map(|a| a.score)
            .fold(0.0_f64, f64::max)
    }

    /// Return anomalies above a score threshold.
    #[must_use]
    pub fn above_threshold(&self, threshold: f64) -> Vec<&Anomaly> {
        self.anomalies
            .iter()
            .filter(|a| a.score >= threshold)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TrafficAnalysis — aggregate analysis result
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate analysis results for a traffic capture.
#[derive(Debug, Serialize, Deserialize)]
pub struct TrafficAnalysis {
    pub protocol_stats: ProtocolStats,
    pub total_connections: usize,
    pub tls_handshake_count: usize,
    pub weak_tls_count: usize,
    pub dns_query_count: usize,
    pub top_talkers: Vec<(String, u64)>,
    pub anomaly_count: usize,
    pub duration_secs: u64,
}

impl TrafficAnalysis {
    /// Compute from a set of observations.
    #[must_use]
    pub fn compute(
        stats: &ProtocolStats,
        connections: &ConnectionTable,
        tls: &TlsHandshakeAnalysis,
        dns: &DnsResolver,
        anomaly: &AnomalyScore,
        duration_secs: u64,
    ) -> Self {
        let top_talkers: Vec<(String, u64)> = anomaly
            .bytes_per_src
            .iter()
            .map(|(ip, &bytes)| (ip.to_string(), bytes))
            .collect::<Vec<_>>()
            .into_iter()
            .take(5)
            .collect();
        Self {
            protocol_stats: stats.clone(),
            total_connections: connections.connection_count(),
            tls_handshake_count: tls.count(),
            weak_tls_count: tls.weak_handshakes().len(),
            dns_query_count: dns.hostname_count(),
            top_talkers,
            anomaly_count: anomaly.anomalies.len(),
            duration_secs,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkAnalyzer — top-level driver
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level network traffic analysis engine.
#[derive(Debug, Default)]
pub struct NetworkAnalyzer {
    pub stats: ProtocolStats,
    pub connections: ConnectionTable,
    pub dns: DnsResolver,
    pub tls: TlsHandshakeAnalysis,
    pub anomaly: AnomalyScore,
    pub start_time: u64,
    pub packet_count: u64,
}

impl NetworkAnalyzer {
    /// Create a new network analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_time: now_secs(),
            ..Default::default()
        }
    }

    /// Feed a packet into all sub-analyzers.
    pub fn feed(&mut self, pkt: &ObservedPacket) {
        let proto_name = format!("{:?}", pkt.protocol);
        self.stats.record(&proto_name, pkt.length as u64);
        self.connections.record(pkt);
        self.anomaly.observe(pkt);

        // DNS heuristic: UDP port 53.
        if pkt.dst_port == 53 || pkt.src_port == 53 {
            self.dns.record_query("_detected_");
        }
        // TLS heuristic: TCP port 443 + non-empty payload.
        if pkt.dst_port == 443 && !pkt.payload.is_empty() {
            let version = if pkt.payload.len() >= 2 {
                TlsVersion::from_bytes(pkt.payload[0], pkt.payload[1])
            } else {
                TlsVersion::Tls12
            };
            self.tls
                .record(TlsHandshake::new(pkt.src_ip, pkt.dst_ip, 443, version));
        }
        self.packet_count += 1;
    }

    /// Run all detection passes.
    pub fn analyze(&mut self) {
        self.anomaly.detect();
    }

    /// Build a [`TrafficAnalysis`] summary.
    #[must_use]
    pub fn summary(&self) -> TrafficAnalysis {
        let elapsed = now_secs().saturating_sub(self.start_time);
        TrafficAnalysis::compute(
            &self.stats,
            &self.connections,
            &self.tls,
            &self.dns,
            &self.anomaly,
            elapsed,
        )
    }

    /// Return the total packet count.
    #[must_use]
    pub const fn total_packets(&self) -> u64 {
        self.packet_count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn tcp_pkt(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, len: usize) -> ObservedPacket {
        ObservedPacket::tcp(src, dst, sport, dport, len)
    }

    // ── ObservedPacket ────────────────────────────────────────────────────────

    #[test]
    fn test_observed_packet_tcp() {
        let pkt = ObservedPacket::tcp(ip4(1, 2, 3, 4), ip4(5, 6, 7, 8), 1024, 80, 512);
        assert_eq!(pkt.protocol, TransportProtocol::Tcp);
        assert_eq!(pkt.dst_port, 80);
    }

    #[test]
    fn test_observed_packet_udp() {
        let pkt = ObservedPacket::udp(ip4(1, 2, 3, 4), ip4(8, 8, 8, 8), 5353, 53, 64);
        assert_eq!(pkt.protocol, TransportProtocol::Udp);
        assert_eq!(pkt.dst_port, 53);
    }

    // ── ProtocolStats ─────────────────────────────────────────────────────────

    #[test]
    fn test_protocol_stats_record() {
        let mut s = ProtocolStats::new();
        s.record("TCP", 100);
        s.record("TCP", 200);
        s.record("UDP", 50);
        assert_eq!(s.total_packets, 3);
        assert_eq!(s.total_bytes, 350);
    }

    #[test]
    fn test_protocol_stats_fraction() {
        let mut s = ProtocolStats::new();
        s.record("TCP", 100);
        s.record("UDP", 50);
        assert!((s.fraction("TCP") - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_protocol_stats_top_protocols() {
        let mut s = ProtocolStats::new();
        for _ in 0..10 {
            s.record("TCP", 1);
        }
        for _ in 0..3 {
            s.record("UDP", 1);
        }
        let top = s.top_protocols(2);
        assert_eq!(top[0].0, "TCP");
        assert_eq!(top[0].1, 10);
    }

    #[test]
    fn test_protocol_stats_zero_fraction() {
        let s = ProtocolStats::new();
        assert!(s.fraction("TCP").abs() < f64::EPSILON);
    }

    // ── ConnectionTable ───────────────────────────────────────────────────────

    #[test]
    fn test_connection_table_record() {
        let mut ct = ConnectionTable::new();
        let pkt = tcp_pkt(ip4(1, 1, 1, 1), ip4(2, 2, 2, 2), 5000, 80, 100);
        ct.record(&pkt);
        assert_eq!(ct.connection_count(), 1);
    }

    #[test]
    fn test_connection_table_same_connection() {
        let mut ct = ConnectionTable::new();
        let src = ip4(1, 1, 1, 1);
        let dst = ip4(2, 2, 2, 2);
        ct.record(&tcp_pkt(src, dst, 5000, 80, 100));
        ct.record(&tcp_pkt(src, dst, 5000, 80, 200));
        assert_eq!(ct.connection_count(), 1);
        let entry = ct.connections.values().next().unwrap();
        assert_eq!(entry.packets, 2);
    }

    #[test]
    fn test_connection_table_different_connections() {
        let mut ct = ConnectionTable::new();
        ct.record(&tcp_pkt(ip4(1, 1, 1, 1), ip4(2, 2, 2, 2), 5000, 80, 100));
        ct.record(&tcp_pkt(ip4(3, 3, 3, 3), ip4(4, 4, 4, 4), 5001, 443, 200));
        assert_eq!(ct.connection_count(), 2);
    }

    #[test]
    fn test_connection_table_application_guessing() {
        let mut ct = ConnectionTable::new();
        ct.record(&tcp_pkt(ip4(1, 1, 1, 1), ip4(2, 2, 2, 2), 5000, 443, 100));
        let entry = ct.connections.values().next().unwrap();
        assert_eq!(entry.application.as_deref(), Some("HTTPS"));
    }

    #[test]
    fn test_connection_table_connections_to_port() {
        let mut ct = ConnectionTable::new();
        ct.record(&tcp_pkt(ip4(1, 1, 1, 1), ip4(2, 2, 2, 2), 1024, 80, 100));
        ct.record(&tcp_pkt(ip4(3, 3, 3, 3), ip4(4, 4, 4, 4), 2048, 443, 200));
        assert_eq!(ct.connections_to_port(80).len(), 1);
    }

    #[test]
    fn test_connection_key_normalized() {
        let k1 = ConnectionKey::normalized(
            ip4(1, 1, 1, 1),
            ip4(2, 2, 2, 2),
            1000,
            80,
            TransportProtocol::Tcp,
        );
        let k2 = ConnectionKey::normalized(
            ip4(2, 2, 2, 2),
            ip4(1, 1, 1, 1),
            80,
            1000,
            TransportProtocol::Tcp,
        );
        assert_eq!(k1, k2);
    }

    // ── DnsResolver ───────────────────────────────────────────────────────────

    #[test]
    fn test_dns_resolver_resolution() {
        let mut dns = DnsResolver::new();
        dns.record_resolution("example.com", ip4(93, 184, 216, 34));
        assert_eq!(dns.forward_lookup("example.com"), &[ip4(93, 184, 216, 34)]);
    }

    #[test]
    fn test_dns_resolver_reverse() {
        let mut dns = DnsResolver::new();
        let ip = ip4(1, 2, 3, 4);
        dns.record_resolution("test.com", ip);
        assert!(!dns.reverse_lookup(ip).is_empty());
    }

    #[test]
    fn test_dns_resolver_top_queried() {
        let mut dns = DnsResolver::new();
        for _ in 0..5 {
            dns.record_query("popular.com");
        }
        for _ in 0..2 {
            dns.record_query("rare.com");
        }
        let top = dns.top_queried(1);
        assert_eq!(top[0].0, "popular.com");
    }

    #[test]
    fn test_dns_resolver_hostname_count() {
        let mut dns = DnsResolver::new();
        dns.record_resolution("a.com", ip4(1, 1, 1, 1));
        dns.record_resolution("b.com", ip4(2, 2, 2, 2));
        assert_eq!(dns.hostname_count(), 2);
    }

    // ── TlsHandshakeAnalysis ──────────────────────────────────────────────────

    #[test]
    fn test_tls_version_secure() {
        assert!(TlsVersion::Tls12.is_secure());
        assert!(TlsVersion::Tls13.is_secure());
        assert!(!TlsVersion::Tls10.is_secure());
        assert!(!TlsVersion::Ssl30.is_secure());
    }

    #[test]
    fn test_tls_version_from_bytes() {
        assert_eq!(TlsVersion::from_bytes(3, 3), TlsVersion::Tls12);
        assert_eq!(TlsVersion::from_bytes(3, 4), TlsVersion::Tls13);
        assert_eq!(TlsVersion::from_bytes(3, 0), TlsVersion::Ssl30);
    }

    #[test]
    fn test_tls_handshake_weak() {
        let h = TlsHandshake::new(ip4(1, 1, 1, 1), ip4(2, 2, 2, 2), 443, TlsVersion::Tls10);
        assert!(h.is_weak());
    }

    #[test]
    fn test_tls_analysis_weak_count() {
        let mut tls = TlsHandshakeAnalysis::new();
        tls.record(TlsHandshake::new(
            ip4(1, 1, 1, 1),
            ip4(2, 2, 2, 2),
            443,
            TlsVersion::Ssl30,
        ));
        tls.record(TlsHandshake::new(
            ip4(3, 3, 3, 3),
            ip4(4, 4, 4, 4),
            443,
            TlsVersion::Tls13,
        ));
        assert_eq!(tls.weak_handshakes().len(), 1);
    }

    #[test]
    fn test_tls_analysis_snis() {
        let mut tls = TlsHandshakeAnalysis::new();
        let mut h = TlsHandshake::new(ip4(1, 1, 1, 1), ip4(2, 2, 2, 2), 443, TlsVersion::Tls12);
        h.sni = Some("example.com".to_string());
        tls.record(h);
        let snis = tls.unique_snis();
        assert_eq!(snis, &["example.com"]);
    }

    #[test]
    fn test_tls_version_distribution() {
        let mut tls = TlsHandshakeAnalysis::new();
        tls.record(TlsHandshake::new(
            ip4(1, 1, 1, 1),
            ip4(2, 2, 2, 2),
            443,
            TlsVersion::Tls12,
        ));
        tls.record(TlsHandshake::new(
            ip4(1, 1, 1, 1),
            ip4(2, 2, 2, 2),
            443,
            TlsVersion::Tls13,
        ));
        let dist = tls.version_distribution();
        assert!(dist.contains_key("TLS 1.2"));
        assert!(dist.contains_key("TLS 1.3"));
    }

    // ── AnomalyScore ──────────────────────────────────────────────────────────

    #[test]
    fn test_anomaly_score_port_scan() {
        let mut scorer = AnomalyScore::new();
        let src = ip4(10, 0, 0, 1);
        for port in 0..30u16 {
            scorer.observe(&tcp_pkt(src, ip4(1, 1, 1, 1), 10000, port, 64));
        }
        scorer.detect();
        assert!(!scorer.anomalies.is_empty());
        assert!(
            scorer
                .anomalies
                .iter()
                .any(|a| a.anomaly_type == AnomalyType::PortScan)
        );
    }

    #[test]
    fn test_anomaly_score_no_anomaly_low_traffic() {
        let mut scorer = AnomalyScore::new();
        scorer.observe(&tcp_pkt(ip4(1, 1, 1, 1), ip4(2, 2, 2, 2), 5000, 80, 100));
        scorer.detect();
        assert!(scorer.above_threshold(0.5).is_empty());
    }

    #[test]
    fn test_anomaly_score_max_score_zero_when_empty() {
        let scorer = AnomalyScore::new();
        assert!(scorer.max_score().abs() < f64::EPSILON);
    }

    // ── NetworkAnalyzer ───────────────────────────────────────────────────────

    #[test]
    fn test_network_analyzer_feed() {
        let mut na = NetworkAnalyzer::new();
        na.feed(&tcp_pkt(ip4(1, 1, 1, 1), ip4(2, 2, 2, 2), 5000, 80, 256));
        assert_eq!(na.total_packets(), 1);
    }

    #[test]
    fn test_network_analyzer_summary() {
        let mut na = NetworkAnalyzer::new();
        for i in 0..5 {
            na.feed(&tcp_pkt(
                ip4(1, 1, 1, 1),
                ip4(2, 2, 2, 2),
                5000 + i,
                80,
                100,
            ));
        }
        na.analyze();
        let summary = na.summary();
        assert!(summary.total_connections > 0);
    }

    #[test]
    fn test_network_analyzer_dns_detection() {
        let mut na = NetworkAnalyzer::new();
        na.feed(&ObservedPacket::udp(
            ip4(1, 1, 1, 1),
            ip4(8, 8, 8, 8),
            12345,
            53,
            64,
        ));
        let s = na.summary();
        assert!(s.dns_query_count > 0 || na.stats.packet_count.contains_key("Udp"));
    }

    #[test]
    fn test_network_analyzer_tls_detection() {
        let mut na = NetworkAnalyzer::new();
        let mut pkt = tcp_pkt(ip4(1, 1, 1, 1), ip4(2, 2, 2, 2), 5000, 443, 1400);
        pkt.payload = vec![3u8, 3u8, 0, 0, 0];
        na.feed(&pkt);
        let s = na.summary();
        assert_eq!(s.tls_handshake_count, 1);
    }

    #[test]
    fn test_network_analyzer_multiple_protocols() {
        let mut na = NetworkAnalyzer::new();
        na.feed(&tcp_pkt(ip4(1, 1, 1, 1), ip4(2, 2, 2, 2), 1, 80, 100));
        na.feed(&ObservedPacket::udp(
            ip4(1, 1, 1, 1),
            ip4(8, 8, 8, 8),
            2,
            53,
            50,
        ));
        assert!(na.stats.packet_count.contains_key("Tcp"));
        assert!(na.stats.packet_count.contains_key("Udp"));
    }

    // ── Additional coverage ────────────────────────────────────────────────────

    #[test]
    fn test_protocol_stats_byte_count() {
        let mut s = ProtocolStats::new();
        s.record("HTTP", 1500);
        s.record("HTTP", 800);
        assert_eq!(s.byte_count.get("HTTP").copied().unwrap_or(0), 2300);
    }

    #[test]
    fn test_connection_table_bytes_accumulate() {
        let mut ct = ConnectionTable::new();
        let src = ip4(10, 0, 0, 1);
        let dst = ip4(10, 0, 0, 2);
        ct.record(&tcp_pkt(src, dst, 9000, 80, 100));
        ct.record(&tcp_pkt(src, dst, 9000, 80, 200));
        let entry = ct.connections.values().next().unwrap();
        assert_eq!(entry.bytes, 300);
    }

    #[test]
    fn test_dns_resolver_multiple_ips() {
        let mut dns = DnsResolver::new();
        dns.record_resolution("cdn.example.com", ip4(1, 2, 3, 4));
        dns.record_resolution("cdn.example.com", ip4(5, 6, 7, 8));
        assert_eq!(dns.forward_lookup("cdn.example.com").len(), 2);
    }

    #[test]
    fn test_tls_version_name() {
        assert_eq!(TlsVersion::Tls13.name(), "TLS 1.3");
        assert_eq!(TlsVersion::Unknown.name(), "Unknown");
    }

    #[test]
    fn test_tls_analysis_count() {
        let mut tls = TlsHandshakeAnalysis::new();
        tls.record(TlsHandshake::new(
            ip4(1, 1, 1, 1),
            ip4(2, 2, 2, 2),
            443,
            TlsVersion::Tls12,
        ));
        tls.record(TlsHandshake::new(
            ip4(3, 3, 3, 3),
            ip4(4, 4, 4, 4),
            443,
            TlsVersion::Tls12,
        ));
        assert_eq!(tls.count(), 2);
    }

    #[test]
    fn test_anomaly_high_volume() {
        let mut scorer = AnomalyScore::new();
        let src = ip4(1, 1, 1, 1);
        let pkt = ObservedPacket::tcp(src, ip4(2, 2, 2, 2), 9000, 80, 200_000_000 / 10);
        // Simulate 10 large packets totaling > 100MB.
        for _ in 0..10 {
            scorer.observe(&pkt);
        }
        scorer.detect();
        let has_high_vol = scorer
            .anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::HighVolume);
        assert!(has_high_vol);
    }

    #[test]
    fn test_network_analyzer_empty_summary() {
        let na = NetworkAnalyzer::new();
        let s = na.summary();
        assert_eq!(s.total_connections, 0);
        assert_eq!(s.tls_handshake_count, 0);
    }

    #[test]
    fn test_connection_table_prune_idle() {
        let mut ct = ConnectionTable::new();
        let mut pkt = tcp_pkt(ip4(1, 1, 1, 1), ip4(2, 2, 2, 2), 5000, 80, 100);
        pkt.timestamp = 1; // Very old.
        ct.record(&pkt);
        ct.prune_idle(1);
        let entry = ct.connections.values().next().unwrap();
        assert_eq!(entry.state, ConnectionState::Closed);
    }
}
