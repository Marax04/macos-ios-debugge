//! Apply a compiled rule set to raw packets.
//!
//! Parses TCP/UDP/ICMP/IPv4 headers, extracts payload, runs the Aho-Corasick
//! automaton and per-rule PCRE checks, and returns match results with metadata.

use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::rule_compiler::{CompiledRule, CompiledRuleId, CompiledRuleSet};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("packet too short: need {needed} bytes, have {have}")]
    TooShort { needed: usize, have: usize },
    #[error("unsupported IP version: {0}")]
    UnsupportedIpVersion(u8),
    #[error("unsupported protocol: {0}")]
    UnsupportedProto(u8),
    #[error("malformed header: {0}")]
    MalformedHeader(String),
    #[error("fragment: not reassembled")]
    Fragment,
}

pub type PacketResult<T> = Result<T, PacketError>;

// ─── IP Protocol Constants ────────────────────────────────────────────────────

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_IPV6: u8 = 41;

// ─── Truncation helpers (deliberate cast boundaries) ─────────────────────────

#[inline]
fn usize_to_u8_trunc(n: usize) -> u8 { u8::try_from(n & 0xFF).unwrap_or(0) }
#[inline]
fn usize_to_u16_trunc(n: usize) -> u16 { u16::try_from(n & 0xFFFF).unwrap_or(0) }
#[inline]
const fn u128_to_u64_trunc(n: u128) -> u64 {
    // Deliberate truncation boundary.
    (n & 0xFFFF_FFFF_FFFF_FFFF) as u64
}
#[inline]
fn u64_to_f64_lossy(n: u64) -> f64 {
    // Deliberate lossy conversion: stats reporting only.
    let lo = u32::try_from(n & 0xFFFF_FFFF).unwrap_or(0);
    let hi = u32::try_from(n >> 32).unwrap_or(0);
    (f64::from(hi) * f64::from(1u32 << 16)).mul_add(f64::from(1u32 << 16), f64::from(lo))
}

// ─── Parsed Packet ────────────────────────────────────────────────────────────

/// Layer-3 header fields extracted from an IPv4 packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_len: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

impl Ipv4Header {
    #[must_use]
    pub const fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.src[0], self.src[1], self.src[2], self.src[3])
    }
    #[must_use]
    pub const fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.dst[0], self.dst[1], self.dst[2], self.dst[3])
    }
    /// True if the MF (more fragments) bit is set or the fragment offset is nonzero.
    #[must_use]
    pub const fn is_fragment(&self) -> bool {
        (self.flags & 0x01 != 0) || self.fragment_offset != 0
    }
}

/// Layer-4 TCP header fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    #[must_use]
    pub const fn has_syn(&self) -> bool { self.flags & 0x02 != 0 }
    #[must_use]
    pub const fn has_ack(&self) -> bool { self.flags & 0x10 != 0 }
    #[must_use]
    pub const fn has_fin(&self) -> bool { self.flags & 0x01 != 0 }
    #[must_use]
    pub const fn has_rst(&self) -> bool { self.flags & 0x04 != 0 }
    #[must_use]
    pub const fn has_psh(&self) -> bool { self.flags & 0x08 != 0 }
    #[must_use]
    pub const fn header_len(&self) -> usize { (self.data_offset as usize) * 4 }
}

/// Layer-4 UDP header fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// Layer-4 ICMP header fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: u32,
}

/// Transport layer variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportHeader {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp(IcmpHeader),
    Other(u8),
}

impl TransportHeader {
    #[must_use]
    pub const fn src_port(&self) -> Option<u16> {
        match self {
            Self::Tcp(h) => Some(h.src_port),
            Self::Udp(h) => Some(h.src_port),
            _ => None,
        }
    }
    #[must_use]
    pub const fn dst_port(&self) -> Option<u16> {
        match self {
            Self::Tcp(h) => Some(h.dst_port),
            Self::Udp(h) => Some(h.dst_port),
            _ => None,
        }
    }
    #[must_use]
    pub const fn proto_name(&self) -> &'static str {
        match self {
            Self::Tcp(_) => "tcp",
            Self::Udp(_) => "udp",
            Self::Icmp(_) => "icmp",
            Self::Other(_) => "ip",
        }
    }
}

/// A fully parsed packet (IP + transport + payload).
#[derive(Debug, Clone)]
pub struct ParsedPacket<'a> {
    pub ip: Ipv4Header,
    pub transport: TransportHeader,
    pub payload: &'a [u8],
    pub raw: &'a [u8],
}

impl ParsedPacket<'_> {
    #[must_use]
    pub const fn src_port(&self) -> u16 {
        match self.transport.src_port() {
            Some(p) => p,
            None => 0,
        }
    }
    #[must_use]
    pub const fn dst_port(&self) -> u16 {
        match self.transport.dst_port() {
            Some(p) => p,
            None => 0,
        }
    }
}

// ─── Parser ───────────────────────────────────────────────────────────────────

/// Parse a raw IPv4 packet buffer into a `ParsedPacket`.
///
/// # Errors
/// Returns `PacketError` when the buffer is too short, the IP version is not 4,
/// the header is malformed, or the packet is a fragment.
pub fn parse_ipv4(raw: &[u8]) -> PacketResult<ParsedPacket<'_>> {
    if raw.len() < 20 {
        return Err(PacketError::TooShort { needed: 20, have: raw.len() });
    }
    let version = raw[0] >> 4;
    if version != 4 {
        return Err(PacketError::UnsupportedIpVersion(version));
    }
    let ihl = (raw[0] & 0x0F) as usize;
    if ihl < 5 {
        return Err(PacketError::MalformedHeader(format!("IHL={ihl} < 5")));
    }
    let ip_header_len = ihl * 4;
    if raw.len() < ip_header_len {
        return Err(PacketError::TooShort { needed: ip_header_len, have: raw.len() });
    }
    let total_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    let flags_frag = u16::from_be_bytes([raw[6], raw[7]]);
    let flags = (flags_frag >> 13) as u8 & 0x07;
    let fragment_offset = flags_frag & 0x1FFF;

    let ip = Ipv4Header {
        version,
        ihl: usize_to_u8_trunc(ihl),
        dscp: (raw[1] >> 2) & 0x3F,
        ecn: raw[1] & 0x03,
        total_len: usize_to_u16_trunc(total_len),
        identification: u16::from_be_bytes([raw[4], raw[5]]),
        flags,
        fragment_offset,
        ttl: raw[8],
        protocol: raw[9],
        checksum: u16::from_be_bytes([raw[10], raw[11]]),
        src: [raw[12], raw[13], raw[14], raw[15]],
        dst: [raw[16], raw[17], raw[18], raw[19]],
    };

    if ip.is_fragment() {
        return Err(PacketError::Fragment);
    }

    // Total Length counts the IP header too, so anything below IHL*4 is a
    // malformed header — and clamping only the END (`min(raw.len())`) leaves the
    // start past it, which panics instead of erroring.
    if total_len < ip_header_len {
        return Err(PacketError::MalformedHeader(format!(
            "total_len={total_len} < header {ip_header_len}"
        )));
    }
    let effective_len = total_len.min(raw.len());
    let l4_data = &raw[ip_header_len..effective_len];

    let (transport, payload_offset) = parse_transport(ip.protocol, l4_data)?;
    let payload = &l4_data[payload_offset..];

    Ok(ParsedPacket { ip, transport, payload, raw })
}

fn parse_transport(proto: u8, data: &[u8]) -> PacketResult<(TransportHeader, usize)> {
    match proto {
        IPPROTO_TCP => {
            if data.len() < 20 {
                return Err(PacketError::TooShort { needed: 20, have: data.len() });
            }
            let data_offset = (data[12] >> 4) as usize;
            let header_len = data_offset * 4;
            if header_len < 20 || header_len > data.len() {
                return Err(PacketError::MalformedHeader(format!("TCP offset {data_offset} out of range")));
            }
            let hdr = TcpHeader {
                src_port: u16::from_be_bytes([data[0], data[1]]),
                dst_port: u16::from_be_bytes([data[2], data[3]]),
                seq: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                ack: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
                data_offset: usize_to_u8_trunc(data_offset),
                flags: data[13],
                window: u16::from_be_bytes([data[14], data[15]]),
                checksum: u16::from_be_bytes([data[16], data[17]]),
                urgent_ptr: u16::from_be_bytes([data[18], data[19]]),
            };
            Ok((TransportHeader::Tcp(hdr), header_len))
        }
        IPPROTO_UDP => {
            if data.len() < 8 {
                return Err(PacketError::TooShort { needed: 8, have: data.len() });
            }
            let hdr = UdpHeader {
                src_port: u16::from_be_bytes([data[0], data[1]]),
                dst_port: u16::from_be_bytes([data[2], data[3]]),
                length: u16::from_be_bytes([data[4], data[5]]),
                checksum: u16::from_be_bytes([data[6], data[7]]),
            };
            Ok((TransportHeader::Udp(hdr), 8))
        }
        IPPROTO_ICMP => {
            if data.len() < 8 {
                return Err(PacketError::TooShort { needed: 8, have: data.len() });
            }
            let hdr = IcmpHeader {
                icmp_type: data[0],
                code: data[1],
                checksum: u16::from_be_bytes([data[2], data[3]]),
                rest: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            };
            Ok((TransportHeader::Icmp(hdr), 8))
        }
        other => Ok((TransportHeader::Other(other), 0)),
    }
}

// ─── Match Result ─────────────────────────────────────────────────────────────

/// The result of matching one rule against a packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub rule_id: CompiledRuleId,
    pub sid: u64,
    pub msg: String,
    pub action_drop: bool,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub payload_offset: usize,
    pub matched_patterns: Vec<u32>,
}

impl fmt::Display for MatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let src = Ipv4Addr::from(self.src_ip);
        let dst = Ipv4Addr::from(self.dst_ip);
        write!(
            f,
            "[SID:{}] {} {}:{} -> {}:{} ({})",
            self.sid, self.msg, src, self.src_port, dst, self.dst_port, self.protocol
        )
    }
}

// ─── Packet Matcher ──────────────────────────────────────────────────────────

/// Statistics accumulated across many `match_packet` calls.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MatcherStats {
    pub packets_inspected: u64,
    pub packets_matched: u64,
    pub packets_dropped: u64,
    pub packets_errored: u64,
    pub total_matches: u64,
    pub total_elapsed_us: u64,
}

impl MatcherStats {
    #[must_use]
    pub fn packets_per_second(&self, elapsed: Duration) -> f64 {
        let secs = elapsed.as_secs_f64();
        if secs == 0.0 { 0.0 } else { u64_to_f64_lossy(self.packets_inspected) / secs }
    }
}

/// Context for a packet presentation.
#[derive(Debug, Clone)]
pub struct PacketContext {
    pub timestamp_us: u64,
    pub interface: String,
    pub direction: PacketDirection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketDirection {
    Inbound,
    Outbound,
    Internal,
}

impl Default for PacketContext {
    fn default() -> Self {
        Self {
            timestamp_us: 0,
            interface: String::new(),
            direction: PacketDirection::Inbound,
        }
    }
}

/// Stateless packet matcher — apply a `CompiledRuleSet` to raw packets.
pub struct PacketMatcher<'a> {
    rules: &'a CompiledRuleSet,
    stats: MatcherStats,
    /// Maximum payload bytes to inspect (0 = unlimited).
    pub snap_len: usize,
}

impl<'a> PacketMatcher<'a> {
    #[must_use]
    pub fn new(rules: &'a CompiledRuleSet) -> Self {
        Self { rules, stats: MatcherStats::default(), snap_len: 0 }
    }

    #[must_use]
    pub const fn with_snap_len(mut self, n: usize) -> Self {
        self.snap_len = n;
        self
    }

    /// Match `raw_packet` against the rule set. Returns all matching results.
    pub fn match_packet(
        &mut self,
        raw_packet: &[u8],
        ctx: &PacketContext,
    ) -> Vec<MatchResult> {
        let t0 = Instant::now();
        self.stats.packets_inspected += 1;

        let parsed = match parse_ipv4(raw_packet) {
            Ok(p) => p,
            Err(PacketError::Fragment) => {
                // Fragments: count but don't inspect.
                self.stats.packets_errored += 1;
                return Vec::new();
            }
            Err(_) => {
                self.stats.packets_errored += 1;
                return Vec::new();
            }
        };

        let payload = if self.snap_len > 0 && parsed.payload.len() > self.snap_len {
            &parsed.payload[..self.snap_len]
        } else {
            parsed.payload
        };

        let results = self.eval_rules(&parsed, payload, ctx);

        let elapsed = u128_to_u64_trunc(t0.elapsed().as_micros());
        self.stats.total_elapsed_us += elapsed;

        if !results.is_empty() {
            self.stats.packets_matched += 1;
            self.stats.total_matches += results.len() as u64;
            if results.iter().any(|r| r.action_drop) {
                self.stats.packets_dropped += 1;
            }
        }
        results
    }

    fn eval_rules(
        &self,
        pkt: &ParsedPacket<'_>,
        payload: &[u8],
        _ctx: &PacketContext,
    ) -> Vec<MatchResult> {
        // Phase 1: AC search for candidate rules.
        let ac_hits: std::collections::HashMap<_, _> = self
            .rules
            .ac_search(payload)
            .into_iter()
            .map(|(off, pid)| (pid, off))
            .collect();

        let mut results = Vec::new();

        for rule in self.rules.rules() {
            if !Self::proto_matches(rule, pkt) {
                continue;
            }
            if !Self::addr_port_matches(rule, pkt) {
                continue;
            }

            // Content pattern check.
            if !rule.required_patterns.is_empty() {
                let all_match = rule.required_patterns.iter().all(|pid| ac_hits.contains_key(pid));
                if !all_match {
                    continue;
                }
            }

            // PCRE check.
            let pcre_ok = rule.required_pcre.iter().all(|&idx| {
                self.rules.pcre_patterns.get(idx).is_some_and(|pat| pat.test(payload))
            });
            if !pcre_ok {
                continue;
            }

            let matched_patterns: Vec<u32> = rule.required_patterns.iter().map(|p| p.0).collect();

            results.push(MatchResult {
                rule_id: rule.id,
                sid: rule.sid,
                msg: rule.msg.clone(),
                action_drop: rule.action_drop,
                src_ip: pkt.ip.src,
                dst_ip: pkt.ip.dst,
                src_port: pkt.src_port(),
                dst_port: pkt.dst_port(),
                protocol: pkt.transport.proto_name().to_string(),
                payload_offset: (pkt.payload.as_ptr() as usize)
                    .saturating_sub(pkt.raw.as_ptr() as usize),
                matched_patterns,
            });
        }
        results
    }

    const fn proto_matches(rule: &CompiledRule, pkt: &ParsedPacket<'_>) -> bool {
        use crate::suricata_rules::SuricataProto;
        match &rule.proto {
            SuricataProto::Tcp
            | SuricataProto::Http
            | SuricataProto::Ftp
            | SuricataProto::Smtp
            | SuricataProto::Imap
            | SuricataProto::Ssh
            | SuricataProto::Tls => matches!(pkt.transport, TransportHeader::Tcp(_)),
            SuricataProto::Udp => matches!(pkt.transport, TransportHeader::Udp(_)),
            SuricataProto::Icmp => matches!(pkt.transport, TransportHeader::Icmp(_)),
            SuricataProto::Dns => matches!(pkt.transport, TransportHeader::Udp(_) | TransportHeader::Tcp(_)),
            _ => true,
        }
    }

    fn addr_port_matches(rule: &CompiledRule, pkt: &ParsedPacket<'_>) -> bool {
        rule.src_addr.matches(&pkt.ip.src)
            && rule.dst_addr.matches(&pkt.ip.dst)
            && rule.src_port.matches(pkt.src_port())
            && rule.dst_port.matches(pkt.dst_port())
    }

    #[must_use]
    pub const fn stats(&self) -> &MatcherStats {
        &self.stats
    }

    pub fn reset_stats(&mut self) {
        self.stats = MatcherStats::default();
    }
}

// ─── Batch Matcher ───────────────────────────────────────────────────────────

/// Batch-match a slice of raw packets and collect all results.
pub fn match_batch<'a>(
    matcher: &mut PacketMatcher<'_>,
    packets: &'a [&'a [u8]],
    ctx: &PacketContext,
) -> Vec<(usize, Vec<MatchResult>)> {
    packets
        .iter()
        .enumerate()
        .filter_map(|(i, pkt)| {
            let results = matcher.match_packet(pkt, ctx);
            if results.is_empty() { None } else { Some((i, results)) }
        })
        .collect()
}

// ─── Packet Builder (for tests) ──────────────────────────────────────────────

/// Construct a minimal IPv4/TCP packet for testing.
#[must_use]
pub fn build_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_header_len = 20usize;
    let total_len = 20 + tcp_header_len + payload.len();
    let mut pkt = vec![0u8; total_len];

    // IPv4 header.
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[2] = usize_to_u8_trunc(total_len >> 8);
    pkt[3] = usize_to_u8_trunc(total_len & 0xFF);
    pkt[8] = 64; // TTL
    pkt[9] = IPPROTO_TCP;
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);

    // TCP header.
    pkt[20] = (src_port >> 8) as u8;
    pkt[21] = (src_port & 0xFF) as u8;
    pkt[22] = (dst_port >> 8) as u8;
    pkt[23] = (dst_port & 0xFF) as u8;
    pkt[32] = 0x50; // data offset = 5 (20 bytes), no flags
    pkt[33] = 0x18; // PSH | ACK

    // Payload.
    pkt[40..40 + payload.len()].copy_from_slice(payload);
    pkt
}

/// Construct a minimal IPv4/UDP packet for testing.
#[must_use]
pub fn build_udp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2] = usize_to_u8_trunc(total_len >> 8);
    pkt[3] = usize_to_u8_trunc(total_len & 0xFF);
    pkt[8] = 64;
    pkt[9] = IPPROTO_UDP;
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);
    pkt[20] = (src_port >> 8) as u8;
    pkt[21] = (src_port & 0xFF) as u8;
    pkt[22] = (dst_port >> 8) as u8;
    pkt[23] = (dst_port & 0xFF) as u8;
    let udp_len = 8 + payload.len();
    pkt[24] = usize_to_u8_trunc(udp_len >> 8);
    pkt[25] = usize_to_u8_trunc(udp_len & 0xFF);
    pkt[28..28 + payload.len()].copy_from_slice(payload);
    pkt
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_compiler::RuleCompiler;
    use crate::suricata_rules::{SuricataParser, SuricataRuleSet};

    fn make_compiled() -> crate::rule_compiler::CompiledRuleSet {
        let mut set = SuricataRuleSet::new();
        let rules = [
            r#"alert tcp any any -> any 80 (msg:"HTTP evil"; content:"evil.exe"; sid:1; rev:1;)"#,
            r#"alert udp any any -> any 53 (msg:"DNS C2"; content:"badguys"; sid:2; rev:1;)"#,
        ];
        for r in &rules {
            set.add(SuricataParser::parse_rule(r).unwrap());
        }
        RuleCompiler::new().compile(&set).unwrap()
    }

    #[test]
    fn test_parse_tcp_packet() {
        let pkt = build_tcp_packet(
            [192, 168, 1, 100], [1, 2, 3, 4], 54321, 80,
            b"GET /evil.exe HTTP/1.1\r\n",
        );
        let parsed = parse_ipv4(&pkt).unwrap();
        assert!(matches!(parsed.transport, TransportHeader::Tcp(_)));
        assert_eq!(parsed.src_port(), 54321);
        assert_eq!(parsed.dst_port(), 80);
        assert_eq!(&parsed.payload[..3], b"GET");
    }

    #[test]
    fn test_parse_udp_packet() {
        let pkt = build_udp_packet(
            [10, 0, 0, 1], [8, 8, 8, 8], 12345, 53,
            b"badguys.net",
        );
        let parsed = parse_ipv4(&pkt).unwrap();
        assert!(matches!(parsed.transport, TransportHeader::Udp(_)));
        assert_eq!(parsed.dst_port(), 53);
    }

    #[test]
    fn test_matcher_tcp_match() {
        let compiled = make_compiled();
        let mut matcher = PacketMatcher::new(&compiled);
        let pkt = build_tcp_packet(
            [192, 168, 1, 1], [1, 2, 3, 4], 54321, 80,
            b"GET /evil.exe HTTP/1.1\r\n\r\n",
        );
        let results = matcher.match_packet(&pkt, &PacketContext::default());
        assert!(!results.is_empty(), "expected at least one match");
        assert_eq!(results[0].sid, 1);
    }

    #[test]
    fn test_matcher_udp_match() {
        let compiled = make_compiled();
        let mut matcher = PacketMatcher::new(&compiled);
        let pkt = build_udp_packet(
            [10, 0, 0, 1], [8, 8, 8, 8], 11111, 53,
            b"query badguys.net A",
        );
        let results = matcher.match_packet(&pkt, &PacketContext::default());
        assert!(!results.is_empty());
        assert_eq!(results[0].sid, 2);
    }

    #[test]
    fn test_matcher_no_match() {
        let compiled = make_compiled();
        let mut matcher = PacketMatcher::new(&compiled);
        let pkt = build_tcp_packet(
            [192, 168, 1, 1], [1, 2, 3, 4], 54321, 80,
            b"GET /benign.html HTTP/1.1\r\n",
        );
        let results = matcher.match_packet(&pkt, &PacketContext::default());
        assert!(results.is_empty());
    }

    #[test]
    fn test_stats_accumulate() {
        let compiled = make_compiled();
        let mut matcher = PacketMatcher::new(&compiled);
        let ctx = PacketContext::default();
        let pkt = build_tcp_packet(
            [1, 2, 3, 4], [5, 6, 7, 8], 1234, 80, b"benign",
        );
        for _ in 0..10 {
            matcher.match_packet(&pkt, &ctx);
        }
        assert_eq!(matcher.stats().packets_inspected, 10);
    }

    #[test]
    fn test_match_display() {
        let mr = MatchResult {
            rule_id: CompiledRuleId(0),
            sid: 42,
            msg: "Test rule".to_string(),
            action_drop: false,
            src_ip: [192, 168, 1, 1],
            dst_ip: [10, 0, 0, 1],
            src_port: 54321,
            dst_port: 80,
            protocol: "tcp".to_string(),
            payload_offset: 40,
            matched_patterns: vec![0],
        };
        let s = format!("{mr}");
        assert!(s.contains("42"));
        assert!(s.contains("192.168.1.1"));
    }

    #[test]
    fn test_batch_match() {
        let compiled = make_compiled();
        let mut matcher = PacketMatcher::new(&compiled);
        let ctx = PacketContext::default();
        let p1 = build_tcp_packet([1,2,3,4],[5,6,7,8],1234,80,b"evil.exe data");
        let p2 = build_tcp_packet([1,2,3,4],[5,6,7,8],1234,80,b"benign");
        let pkts: Vec<&[u8]> = vec![p1.as_slice(), p2.as_slice()];
        let results = match_batch(&mut matcher, &pkts, &ctx);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 0);
    }

    #[test]
    fn test_short_packet_error() {
        let compiled = make_compiled();
        let mut matcher = PacketMatcher::new(&compiled);
        let pkt = vec![0u8; 10];
        let results = matcher.match_packet(&pkt, &PacketContext::default());
        assert!(results.is_empty());
        assert_eq!(matcher.stats().packets_errored, 1);
    }

    #[test]
    fn test_total_len_below_ip_header_is_rejected() {
        // A valid TCP packet, then its Total Length field (bytes 2..4) rewritten
        // to values a peer can legally put on the wire but that are smaller than
        // the 20-byte header they are supposed to include.
        let base = build_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1111, 80, b"x");
        for declared in [0u16, 1, 19] {
            let mut pkt = base.clone();
            pkt[2..4].copy_from_slice(&declared.to_be_bytes());
            assert!(
                matches!(parse_ipv4(&pkt), Err(PacketError::MalformedHeader(_))),
                "total_len={declared} must be reported malformed, not panic"
            );
        }
        // The boundary value — header only, no L4 — is still a parse attempt,
        // and the untouched packet keeps parsing.
        let mut pkt = base.clone();
        pkt[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert!(!matches!(parse_ipv4(&pkt), Err(PacketError::MalformedHeader(_))));
        assert!(parse_ipv4(&base).is_ok());
    }
}
