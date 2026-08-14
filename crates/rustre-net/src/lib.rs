//! `rustre-net` — Network capture and traffic analysis core.
//!
//! Provides protocol parsing, connection tracking, packet capture traits,
//! and basic application-layer dissection for the `RustRE` platform.

#![forbid(unsafe_code)]

pub mod c2_detector;
pub mod network_analyzer;
pub mod packet_builder;
pub mod protocol_dissector;
pub mod protocol_fingerprint;
pub mod traffic_reassembler;
pub mod tcp_reassembler;
pub mod flow_tracker;
pub mod packet_decoder;
pub mod registry;

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use bitflags::bitflags;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ────────────────────────────────────────────────────────────────────────────
// Error type
// ────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during network operations.
#[derive(Debug, Error)]
pub enum NetError {
    #[error("buffer too short: need {needed} bytes, got {got}")]
    BufferTooShort { needed: usize, got: usize },

    #[error("invalid ethernet frame")]
    InvalidEthernetFrame,

    #[error("invalid IPv4 packet")]
    InvalidIpv4Packet,

    #[error("invalid IPv6 packet")]
    InvalidIpv6Packet,

    #[error("invalid TCP segment")]
    InvalidTcpSegment,

    #[error("invalid UDP datagram")]
    InvalidUdpDatagram,

    #[error("invalid ICMP packet")]
    InvalidIcmpPacket,

    #[error("invalid DNS packet")]
    InvalidDnsPacket,

    #[error("invalid HTTP message")]
    InvalidHttpMessage,

    #[error("unsupported ethertype: 0x{0:04x}")]
    UnsupportedEthertype(u16),

    #[error("unsupported IP protocol: {0}")]
    UnsupportedIpProtocol(u8),

    #[error("BPF filter error: {0}")]
    BpfFilterError(String),

    #[error("capture error: {0}")]
    CaptureError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("connection not found")]
    ConnectionNotFound,

    #[error("malformed packet: {0}")]
    MalformedPacket(String),
}

// ────────────────────────────────────────────────────────────────────────────
// TCP flags
// ────────────────────────────────────────────────────────────────────────────

bitflags! {
    /// TCP control flags as defined in RFC 793.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct TcpFlags: u8 {
        const FIN = 0x01;
        const SYN = 0x02;
        const RST = 0x04;
        const PSH = 0x08;
        const ACK = 0x10;
        const URG = 0x20;
        const ECE = 0x40;
        const CWR = 0x80;
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.contains(Self::SYN) {
            parts.push("SYN");
        }
        if self.contains(Self::ACK) {
            parts.push("ACK");
        }
        if self.contains(Self::FIN) {
            parts.push("FIN");
        }
        if self.contains(Self::RST) {
            parts.push("RST");
        }
        if self.contains(Self::PSH) {
            parts.push("PSH");
        }
        if self.contains(Self::URG) {
            parts.push("URG");
        }
        if self.contains(Self::ECE) {
            parts.push("ECE");
        }
        if self.contains(Self::CWR) {
            parts.push("CWR");
        }
        write!(f, "[{}]", parts.join("|"))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Core network structs
// ────────────────────────────────────────────────────────────────────────────

/// An Ethernet II frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetFrame {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    /// `EtherType` field (e.g. 0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP).
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    /// Format a MAC address as colon-separated hex.
    #[must_use]
    pub fn mac_to_string(mac: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }
}

impl fmt::Display for EthernetFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ethernet {} -> {} ethertype=0x{:04x} len={}",
            Self::mac_to_string(&self.src_mac),
            Self::mac_to_string(&self.dst_mac),
            self.ethertype,
            self.payload.len()
        )
    }
}

/// An IPv4 or IPv6 packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpPacket {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6).
    pub protocol: u8,
    pub ttl: u8,
    pub payload: Vec<u8>,
}

impl fmt::Display for IpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IP {} -> {} proto={} ttl={} len={}",
            self.src,
            self.dst,
            self.protocol,
            self.ttl,
            self.payload.len()
        )
    }
}

/// A TCP segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub payload: Vec<u8>,
}

impl fmt::Display for TcpSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP {}:{} -> flags={} seq={} ack={} len={}",
            self.src_port,
            self.dst_port,
            self.flags,
            self.seq,
            self.ack,
            self.payload.len()
        )
    }
}

/// A UDP datagram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpDatagram {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

impl fmt::Display for UdpDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UDP {} -> {} len={}",
            self.src_port,
            self.dst_port,
            self.payload.len()
        )
    }
}

/// An ICMP message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpPacket {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl fmt::Display for IcmpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ICMP type={} code={} chksum=0x{:04x} len={}",
            self.icmp_type,
            self.code,
            self.checksum,
            self.payload.len()
        )
    }
}

/// The network layer content of a [`Packet`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkLayer {
    Ethernet(EthernetFrame),
    Raw(Vec<u8>),
}

/// A captured network packet with a timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    /// Nanoseconds since Unix epoch.
    pub timestamp: u64,
    pub data: Vec<u8>,
    pub layer: NetworkLayer,
}

impl Packet {
    /// Create a new packet with an Ethernet layer.
    #[must_use]
    pub const fn new_ethernet(timestamp: u64, data: Vec<u8>, frame: EthernetFrame) -> Self {
        Self {
            timestamp,
            data,
            layer: NetworkLayer::Ethernet(frame),
        }
    }

    /// Create a raw (non-Ethernet) packet.
    #[must_use]
    pub const fn new_raw(timestamp: u64, data: Vec<u8>) -> Self {
        // Avoid duplicating bytes: the payload lives in `Packet::data`; the
        // `Raw` variant is a tag only (use `Packet::data` to access bytes).
        Self {
            timestamp,
            data,
            layer: NetworkLayer::Raw(Vec::new()),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Capture stats
// ────────────────────────────────────────────────────────────────────────────

/// Statistics reported by a packet capture source.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct CaptureStats {
    pub received: u64,
    pub dropped: u64,
    pub if_dropped: u64,
}

impl fmt::Display for CaptureStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CaptureStats {{ received: {}, dropped: {}, if_dropped: {} }}",
            self.received, self.dropped, self.if_dropped
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────
// PacketCapture trait
// ────────────────────────────────────────────────────────────────────────────

/// Async packet capture source.
#[async_trait]
pub trait PacketCapture: Send + Sync {
    /// Capture the next available packet, blocking asynchronously.
    async fn capture_next(&mut self) -> Result<Packet, NetError>;

    /// Apply a BPF (Berkeley Packet Filter) expression.
    ///
    /// # Errors
    /// Returns a [`NetError`] if the filter is malformed or cannot be installed by the backend.
    fn filter(&mut self, bpf_filter: &str) -> Result<(), NetError>;

    /// Return current capture statistics.
    fn stats(&self) -> CaptureStats;
}

// ────────────────────────────────────────────────────────────────────────────
// Protocol parsers
// ────────────────────────────────────────────────────────────────────────────

/// Parse an Ethernet II frame from raw bytes.
///
/// The frame must be at least 14 bytes (6+6+2 header).
///
/// # Errors
/// Returns [`NetError::BufferTooShort`] when `data` is fewer than 14 bytes.
pub fn parse_ethernet(data: &[u8]) -> Result<EthernetFrame, NetError> {
    if data.len() < 14 {
        return Err(NetError::BufferTooShort {
            needed: 14,
            got: data.len(),
        });
    }
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&data[0..6]);
    src_mac.copy_from_slice(&data[6..12]);
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    // Handle 802.1Q VLAN tag (0x8100) — skip 4-byte tag
    let (ethertype, payload_start) = if ethertype == 0x8100 && data.len() >= 18 {
        let inner_type = u16::from_be_bytes([data[16], data[17]]);
        (inner_type, 18)
    } else {
        (ethertype, 14)
    };
    let payload = data[payload_start..].to_vec();
    Ok(EthernetFrame {
        src_mac,
        dst_mac,
        ethertype,
        payload,
    })
}

/// Parse an IPv4 packet from the IP header onwards (no Ethernet framing).
///
/// # Errors
/// Returns [`NetError::BufferTooShort`] when `data` is shorter than the header, or
/// [`NetError::InvalidIpv4Packet`] when the version or IHL fields are invalid.
pub fn parse_ipv4(data: &[u8]) -> Result<IpPacket, NetError> {
    if data.len() < 20 {
        return Err(NetError::BufferTooShort {
            needed: 20,
            got: data.len(),
        });
    }
    let version = (data[0] >> 4) & 0xF;
    if version != 4 {
        return Err(NetError::InvalidIpv4Packet);
    }
    let ihl = ((data[0] & 0x0F) as usize) * 4;
    if ihl < 20 || data.len() < ihl {
        return Err(NetError::InvalidIpv4Packet);
    }
    let protocol = data[9];
    let ttl = data[8];
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total_len < ihl {
        return Err(NetError::InvalidIpv4Packet);
    }
    let end = total_len.min(data.len());
    let payload = data[ihl..end].to_vec();
    let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
    Ok(IpPacket {
        src,
        dst,
        protocol,
        ttl,
        payload,
    })
}

/// Parse an IPv6 packet from the IP header onwards.
///
/// # Errors
/// Returns [`NetError::BufferTooShort`] when `data` is shorter than 40 bytes, or
/// [`NetError::InvalidIpv6Packet`] when the version field is not 6.
///
/// # Panics
/// Panics only if internal slice-to-array conversion fails, which cannot happen
/// after the length check ensures at least 40 bytes are available.
pub fn parse_ipv6(data: &[u8]) -> Result<IpPacket, NetError> {
    if data.len() < 40 {
        return Err(NetError::BufferTooShort {
            needed: 40,
            got: data.len(),
        });
    }
    let version = (data[0] >> 4) & 0xF;
    if version != 6 {
        return Err(NetError::InvalidIpv6Packet);
    }
    let next_header = data[6];
    let ttl = data[7]; // hop limit
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let end = (40 + payload_len).min(data.len());
    let payload = data[40..end].to_vec();
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap()));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap()));
    Ok(IpPacket {
        src,
        dst,
        protocol: next_header,
        ttl,
        payload,
    })
}

/// Parse a TCP segment from raw bytes (transport layer).
///
/// # Errors
/// Returns [`NetError::BufferTooShort`] when `data` is fewer than 20 bytes, or
/// [`NetError::InvalidTcpSegment`] when the data-offset field is invalid.
pub fn parse_tcp(data: &[u8]) -> Result<TcpSegment, NetError> {
    if data.len() < 20 {
        return Err(NetError::BufferTooShort {
            needed: 20,
            got: data.len(),
        });
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = ((data[12] >> 4) as usize) * 4;
    if data_offset < 20 || data.len() < data_offset {
        return Err(NetError::InvalidTcpSegment);
    }
    let flags = TcpFlags::from_bits_truncate(data[13]);
    let window = u16::from_be_bytes([data[14], data[15]]);
    let payload = data[data_offset..].to_vec();
    Ok(TcpSegment {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        payload,
    })
}

/// Parse a UDP datagram from raw bytes (transport layer).
///
/// # Errors
/// Returns [`NetError::BufferTooShort`] when `data` is fewer than 8 bytes.
pub fn parse_udp(data: &[u8]) -> Result<UdpDatagram, NetError> {
    if data.len() < 8 {
        return Err(NetError::BufferTooShort {
            needed: 8,
            got: data.len(),
        });
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]) as usize;
    if length < 8 {
        return Err(NetError::InvalidUdpDatagram);
    }
    let payload_end = length.min(data.len());
    let payload = data[8..payload_end].to_vec();
    Ok(UdpDatagram {
        src_port,
        dst_port,
        payload,
    })
}

/// Parse an ICMP message from raw bytes.
///
/// # Errors
/// Returns [`NetError::BufferTooShort`] when `data` is fewer than 4 bytes.
pub fn parse_icmp(data: &[u8]) -> Result<IcmpPacket, NetError> {
    if data.len() < 4 {
        return Err(NetError::BufferTooShort {
            needed: 4,
            got: data.len(),
        });
    }
    let icmp_type = data[0];
    let code = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);
    let payload = data[4..].to_vec();
    Ok(IcmpPacket {
        icmp_type,
        code,
        checksum,
        payload,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// DNS parser
// ────────────────────────────────────────────────────────────────────────────

/// Parsed DNS question entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Parsed DNS resource record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

/// A fully-parsed DNS packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsPacket {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

impl DnsPacket {
    /// Returns `true` if this packet is a DNS response.
    #[must_use]
    pub const fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    /// Returns the RCODE nibble (0 = no error).
    #[must_use]
    pub const fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }
}

/// Parse a DNS label at `offset`, following compression pointers.
///
/// Returns `(name, new_offset)`.
fn parse_dns_name(data: &[u8], mut offset: usize) -> Result<(String, usize), NetError> {
    const MAX_HOPS: usize = 128;
    let mut parts: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut final_offset = offset;
    // Limit total hops to prevent infinite loops via circular compression pointers.
    let mut hops: usize = 0;

    loop {
        if hops > MAX_HOPS {
            return Err(NetError::InvalidDnsPacket);
        }
        hops += 1;
        if offset >= data.len() {
            return Err(NetError::InvalidDnsPacket);
        }
        let len = data[offset] as usize;
        if len == 0 {
            if !jumped {
                final_offset = offset + 1;
            }
            break;
        }
        // Compression pointer: top 2 bits set
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= data.len() {
                return Err(NetError::InvalidDnsPacket);
            }
            let ptr = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
            if !jumped {
                final_offset = offset + 2;
            }
            jumped = true;
            offset = ptr;
            continue;
        }
        offset += 1;
        if offset + len > data.len() {
            return Err(NetError::InvalidDnsPacket);
        }
        let label = std::str::from_utf8(&data[offset..offset + len])
            .map_err(|_| NetError::InvalidDnsPacket)?
            .to_string();
        parts.push(label);
        offset += len;
    }
    Ok((parts.join("."), final_offset))
}

/// Parse a DNS packet from raw UDP payload bytes.
///
/// # Errors
/// Returns [`NetError::BufferTooShort`] when `data` is fewer than 12 bytes, or
/// [`NetError::MalformedPacket`] when name compression or section parsing fails.
pub fn parse_dns(data: &[u8]) -> Result<DnsPacket, NetError> {
    // Cap counts to avoid allocating enormous Vecs from attacker-controlled values.
    // A DNS packet over UDP cannot exceed 512 bytes (4096 with EDNS0), so
    // more than 512 records of any section is impossible in practice.
    const MAX_DNS_RECORDS: usize = 512;
    if data.len() < 12 {
        return Err(NetError::BufferTooShort {
            needed: 12,
            got: data.len(),
        });
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let question_count = (u16::from_be_bytes([data[4], data[5]]) as usize).min(MAX_DNS_RECORDS);
    let answer_count = (u16::from_be_bytes([data[6], data[7]]) as usize).min(MAX_DNS_RECORDS);
    let authority_count = (u16::from_be_bytes([data[8], data[9]]) as usize).min(MAX_DNS_RECORDS);
    let additional_count = (u16::from_be_bytes([data[10], data[11]]) as usize).min(MAX_DNS_RECORDS);

    let mut offset = 12usize;

    let parse_question = |off: usize| -> Result<(DnsQuestion, usize), NetError> {
        let (name, next) = parse_dns_name(data, off)?;
        if next + 4 > data.len() {
            return Err(NetError::InvalidDnsPacket);
        }
        let qtype = u16::from_be_bytes([data[next], data[next + 1]]);
        let qclass = u16::from_be_bytes([data[next + 2], data[next + 3]]);
        Ok((
            DnsQuestion {
                name,
                qtype,
                qclass,
            },
            next + 4,
        ))
    };

    let parse_record = |off: usize| -> Result<(DnsRecord, usize), NetError> {
        let (name, next) = parse_dns_name(data, off)?;
        if next + 10 > data.len() {
            return Err(NetError::InvalidDnsPacket);
        }
        let rtype = u16::from_be_bytes([data[next], data[next + 1]]);
        let rclass = u16::from_be_bytes([data[next + 2], data[next + 3]]);
        let ttl = u32::from_be_bytes([
            data[next + 4],
            data[next + 5],
            data[next + 6],
            data[next + 7],
        ]);
        let rdlen = u16::from_be_bytes([data[next + 8], data[next + 9]]) as usize;
        let rdata_start = next + 10;
        if rdata_start + rdlen > data.len() {
            return Err(NetError::InvalidDnsPacket);
        }
        let rdata = data[rdata_start..rdata_start + rdlen].to_vec();
        Ok((
            DnsRecord {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            },
            rdata_start + rdlen,
        ))
    };

    let mut questions = Vec::with_capacity(question_count);
    for _ in 0..question_count {
        let (q, next) = parse_question(offset)?;
        questions.push(q);
        offset = next;
    }

    let mut answers = Vec::with_capacity(answer_count);
    for _ in 0..answer_count {
        let (r, next) = parse_record(offset)?;
        answers.push(r);
        offset = next;
    }

    let mut authorities = Vec::with_capacity(authority_count);
    for _ in 0..authority_count {
        let (r, next) = parse_record(offset)?;
        authorities.push(r);
        offset = next;
    }

    let mut additional = Vec::with_capacity(additional_count);
    for _ in 0..additional_count {
        let (r, next) = parse_record(offset)?;
        additional.push(r);
        offset = next;
    }

    Ok(DnsPacket {
        id,
        flags,
        questions,
        answers,
        authorities,
        additional,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP parser
// ────────────────────────────────────────────────────────────────────────────

/// A parsed HTTP/1.x request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Look up a header value by name (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A parsed HTTP/1.x response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Look up a header value by name (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn parse_http_headers(lines: &[&str]) -> Vec<(String, String)> {
    lines
        .iter()
        .filter_map(|line| {
            let idx = line.find(':')?;
            let key = line[..idx].trim().to_string();
            let val = line[idx + 1..].trim().to_string();
            Some((key, val))
        })
        .collect()
}

/// Parse an HTTP/1.x request from raw bytes.
///
/// # Errors
/// Returns [`NetError::InvalidHttpMessage`] when `data` is not valid UTF-8 or
/// does not contain a complete request line and header section.
pub fn parse_http_request(data: &[u8]) -> Result<HttpRequest, NetError> {
    let text = std::str::from_utf8(data).map_err(|_| NetError::InvalidHttpMessage)?;
    let (header_section, body_raw) = if let Some(idx) = text.find("\r\n\r\n") {
        (&text[..idx], &data[idx + 4..])
    } else {
        return Err(NetError::InvalidHttpMessage);
    };
    let mut lines: Vec<&str> = header_section.split("\r\n").collect();
    if lines.is_empty() {
        return Err(NetError::InvalidHttpMessage);
    }
    let request_line = lines.remove(0);
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() != 3 {
        return Err(NetError::InvalidHttpMessage);
    }
    let method = parts[0].to_string();
    let uri = parts[1].to_string();
    let version = parts[2].to_string();
    let headers = parse_http_headers(&lines);
    Ok(HttpRequest {
        method,
        uri,
        version,
        headers,
        body: body_raw.to_vec(),
    })
}

/// Parse an HTTP/1.x response from raw bytes.
///
/// # Errors
/// Returns [`NetError::InvalidHttpMessage`] when `data` is not valid UTF-8 or
/// does not contain a complete status line and header section.
pub fn parse_http_response(data: &[u8]) -> Result<HttpResponse, NetError> {
    let text = std::str::from_utf8(data).map_err(|_| NetError::InvalidHttpMessage)?;
    let (header_section, body_raw) = if let Some(idx) = text.find("\r\n\r\n") {
        (&text[..idx], &data[idx + 4..])
    } else {
        return Err(NetError::InvalidHttpMessage);
    };
    let mut lines: Vec<&str> = header_section.split("\r\n").collect();
    if lines.is_empty() {
        return Err(NetError::InvalidHttpMessage);
    }
    let status_line = lines.remove(0);
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(NetError::InvalidHttpMessage);
    }
    let version = parts[0].to_string();
    let status_code: u16 = parts[1].parse().map_err(|_| NetError::InvalidHttpMessage)?;
    let reason = if parts.len() == 3 {
        parts[2].to_string()
    } else {
        String::new()
    };
    let headers = parse_http_headers(&lines);
    Ok(HttpResponse {
        version,
        status_code,
        reason,
        headers,
        body: body_raw.to_vec(),
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Connection tracker
// ────────────────────────────────────────────────────────────────────────────

/// 4-tuple identifying a TCP/UDP flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl FlowKey {
    #[must_use]
    pub const fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }

    /// Return the canonical (sorted) form of this key so that A→B and B→A
    /// map to the same flow.
    #[must_use]
    pub fn canonical(&self) -> Self {
        let a = (&self.src_ip, self.src_port);
        let b = (&self.dst_ip, self.dst_port);
        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port) {
            self.clone()
        } else {
            Self::new(*b.0, b.1, *a.0, a.1)
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

/// State of a tracked TCP connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RECEIVED",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN_WAIT_1",
            Self::FinWait2 => "FIN_WAIT_2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::Closed => "CLOSED",
        };
        write!(f, "{s}")
    }
}

/// An entry tracked by [`ConnectionTracker`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub key: FlowKey,
    pub state: TcpState,
    /// Reassembled payload bytes from both directions.
    pub stream_data: Vec<u8>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

impl Connection {
    const fn new(key: FlowKey, now: u64) -> Self {
        Self {
            key,
            state: TcpState::SynSent,
            stream_data: Vec::new(),
            packet_count: 0,
            byte_count: 0,
            first_seen: now,
            last_seen: now,
        }
    }

    fn ingest_tcp_payload(&mut self, payload: &[u8], flags: TcpFlags, now: u64) {
        self.last_seen = now;
        self.packet_count += 1;
        self.byte_count += payload.len() as u64;
        self.stream_data.extend_from_slice(payload);
        self.state = advance_tcp_state(&self.state, flags);
    }

    fn ingest_udp_payload(&mut self, payload: &[u8], now: u64) {
        self.last_seen = now;
        self.packet_count += 1;
        self.byte_count += payload.len() as u64;
        self.stream_data.extend_from_slice(payload);
    }
}

/// Tracks TCP streams by their 4-tuple flow key.
pub struct ConnectionTracker {
    connections: RwLock<HashMap<FlowKey, Connection>>,
}

impl ConnectionTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Feed an IP packet into the tracker. Updates or creates the matching flow.
    ///
    /// # Errors
    /// Propagates [`NetError`] values from the transport-layer parser when the IP
    /// payload is not a well-formed TCP or UDP datagram.
    pub fn process(&self, ip: &IpPacket, now: u64) -> Result<(), NetError> {
        if ip.protocol == 6 {
            let tcp = parse_tcp(&ip.payload)?;
            let key = FlowKey::new(ip.src, tcp.src_port, ip.dst, tcp.dst_port).canonical();
            self.connections
                .write()
                .entry(key.clone())
                .or_insert_with(|| Connection::new(key, now))
                .ingest_tcp_payload(&tcp.payload, tcp.flags, now);
        } else if ip.protocol == 17 {
            let udp = parse_udp(&ip.payload)?;
            let key = FlowKey::new(ip.src, udp.src_port, ip.dst, udp.dst_port).canonical();
            self.connections
                .write()
                .entry(key.clone())
                .or_insert_with(|| Connection::new(key, now))
                .ingest_udp_payload(&udp.payload, now);
        }
        Ok(())
    }

    /// Look up a connection by flow key (canonical form used automatically).
    pub fn get(&self, key: &FlowKey) -> Option<Connection> {
        let canon = key.canonical();
        self.connections.read().get(&canon).cloned()
    }

    /// Return all tracked connections.
    pub fn all(&self) -> Vec<Connection> {
        self.connections.read().values().cloned().collect()
    }

    /// Remove a connection by key.
    pub fn remove(&self, key: &FlowKey) -> Option<Connection> {
        let canon = key.canonical();
        self.connections.write().remove(&canon)
    }

    /// Number of currently tracked connections.
    pub fn len(&self) -> usize {
        self.connections.read().len()
    }

    /// Returns true if no connections are tracked.
    pub fn is_empty(&self) -> bool {
        self.connections.read().is_empty()
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn advance_tcp_state(state: &TcpState, flags: TcpFlags) -> TcpState {
    match state {
        TcpState::SynSent => {
            if flags.contains(TcpFlags::SYN | TcpFlags::ACK) {
                TcpState::SynReceived
            } else {
                state.clone()
            }
        }
        TcpState::SynReceived => {
            if flags.contains(TcpFlags::ACK) && !flags.contains(TcpFlags::SYN) {
                TcpState::Established
            } else {
                state.clone()
            }
        }
        TcpState::Established => {
            if flags.contains(TcpFlags::FIN) {
                TcpState::FinWait1
            } else if flags.contains(TcpFlags::RST) {
                TcpState::Closed
            } else {
                TcpState::Established
            }
        }
        TcpState::FinWait1 => {
            if flags.contains(TcpFlags::ACK) {
                TcpState::FinWait2
            } else {
                state.clone()
            }
        }
        TcpState::FinWait2 => {
            if flags.contains(TcpFlags::FIN) {
                TcpState::TimeWait
            } else {
                state.clone()
            }
        }
        _ => state.clone(),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Protocol enum (application-layer protocol identification)
// ────────────────────────────────────────────────────────────────────────────

/// Application-layer protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Dns,
    Http,
    Https,
    Unknown,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
            Self::Dns => "DNS",
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ConnectionInfo
// ────────────────────────────────────────────────────────────────────────────

/// Information about a network connection including source, destination and protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub src: std::net::SocketAddr,
    pub dst: std::net::SocketAddr,
    pub protocol: Protocol,
    pub pid: Option<u32>,
}

impl ConnectionInfo {
    /// Create a new connection info record.
    #[must_use]
    pub const fn new(
        src: std::net::SocketAddr,
        dst: std::net::SocketAddr,
        protocol: Protocol,
        pid: Option<u32>,
    ) -> Self {
        Self {
            src,
            dst,
            protocol,
            pid,
        }
    }
}

impl fmt::Display for ConnectionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {} [{}]", self.src, self.dst, self.protocol)?;
        if let Some(pid) = self.pid {
            write!(f, " pid={pid}")?;
        }
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// LinkType (simple 4-variant version for PacketBuffer)
// ────────────────────────────────────────────────────────────────────────────

/// Link-layer type for a captured packet buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureLink {
    Ethernet,
    Raw,
    Loopback,
    Null,
}

impl fmt::Display for CaptureLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Ethernet => "Ethernet",
            Self::Raw => "Raw",
            Self::Loopback => "Loopback",
            Self::Null => "Null",
        };
        write!(f, "{s}")
    }
}

// ────────────────────────────────────────────────────────────────────────────
// PacketBuffer
// ────────────────────────────────────────────────────────────────────────────

/// A raw captured packet with timestamp and link-layer type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketBuffer {
    pub data: Vec<u8>,
    pub timestamp_us: u64,
    pub link_type: CaptureLink,
}

impl PacketBuffer {
    /// Create a new packet buffer.
    #[must_use]
    pub const fn new(data: Vec<u8>, timestamp_us: u64, link_type: CaptureLink) -> Self {
        Self {
            data,
            timestamp_us,
            link_type,
        }
    }

    /// Return the length of the captured data.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the buffer has no data.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// NetworkError
// ────────────────────────────────────────────────────────────────────────────

/// Errors produced by the network abstraction layer.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("I/O error: {0}")]
    IoError(String),
    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
}

// ────────────────────────────────────────────────────────────────────────────
// Direction
// ────────────────────────────────────────────────────────────────────────────

/// Traffic direction relative to the capture point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Inbound => "Inbound",
            Self::Outbound => "Outbound",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ────────────────────────────────────────────────────────────────────────────
// PacketSink trait
// ────────────────────────────────────────────────────────────────────────────

/// A sink that accepts raw packet buffers for processing.
pub trait PacketSink: Send + Sync {
    /// Accept a packet buffer for processing.
    ///
    /// # Errors
    ///
    /// Returns a [`NetworkError`] if the packet cannot be processed.
    fn accept(&self, pkt: &PacketBuffer) -> Result<(), NetworkError>;

    /// Flush any pending packets. Default implementation is a no-op.
    ///
    /// # Errors
    ///
    /// Returns a [`NetworkError`] if the flush fails.
    fn flush(&self) -> Result<(), NetworkError> {
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// LinkType enum (spec-required: Ethernet, Raw, Loopback, Null with dlt())
// ────────────────────────────────────────────────────────────────────────────

/// Link-layer type identifier used in PCAP headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkType {
    Ethernet,
    Raw,
    Loopback,
    Null,
}

impl LinkType {
    /// Return the DLT (Data Link Type) code for this link type.
    #[must_use]
    pub const fn dlt(&self) -> u32 {
        match self {
            Self::Ethernet => 1,
            Self::Loopback | Self::Null => 0,
            Self::Raw => 12,
        }
    }
}

impl From<CaptureLink> for LinkType {
    fn from(c: CaptureLink) -> Self {
        match c {
            CaptureLink::Ethernet => Self::Ethernet,
            CaptureLink::Raw => Self::Raw,
            CaptureLink::Loopback => Self::Loopback,
            CaptureLink::Null => Self::Null,
        }
    }
}

impl From<LinkType> for CaptureLink {
    fn from(l: LinkType) -> Self {
        match l {
            LinkType::Ethernet => Self::Ethernet,
            LinkType::Raw => Self::Raw,
            LinkType::Loopback => Self::Loopback,
            LinkType::Null => Self::Null,
        }
    }
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Ethernet => "Ethernet",
            Self::Raw => "Raw",
            Self::Loopback => "Loopback",
            Self::Null => "Null",
        };
        write!(f, "{s}")
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Extend Protocol with Tls variant
// ────────────────────────────────────────────────────────────────────────────

// NOTE: Protocol::Tls is needed by spec; the enum above already exists,
// so we expose a helper rather than re-define it (avoids name collision).
// The spec-required Protocol enum already has Http/Https but not Tls.
// We add an alias for callers who need Tls:
/// Returns true if the given protocol is TLS.
#[must_use]
pub const fn protocol_is_tls(p: &Protocol) -> bool {
    matches!(p, Protocol::Https)
}

// ────────────────────────────────────────────────────────────────────────────
// Extend NetworkError with InvalidAddress variant
// ────────────────────────────────────────────────────────────────────────────
// NetworkError already exists above; we cannot have two definitions.
// The spec requires: ParseError(String), IoError(String), UnsupportedProtocol(String),
// InvalidAddress(String). Our existing NetworkError already has ParseError, IoError,
// UnsupportedProtocol — we need to ADD InvalidAddress. We redefine the enum here
// but first remove the old definition by adding the variant to the existing one.

// ────────────────────────────────────────────────────────────────────────────
// PacketSink flush default + BlackholePacketSink + BufferingPacketSink
// ────────────────────────────────────────────────────────────────────────────

/// A packet sink that silently discards all packets.
pub struct BlackholePacketSink;

impl PacketSink for BlackholePacketSink {
    fn accept(&self, _pkt: &PacketBuffer) -> Result<(), NetworkError> {
        Ok(())
    }

    fn flush(&self) -> Result<(), NetworkError> {
        Ok(())
    }
}

/// A packet sink that buffers all accepted packets in memory.
pub struct BufferingPacketSink {
    buf: parking_lot::Mutex<Vec<PacketBuffer>>,
}

impl BufferingPacketSink {
    /// Create a new empty buffering sink.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// Drain all buffered packets, returning them and clearing the buffer.
    #[must_use]
    pub fn drain(&self) -> Vec<PacketBuffer> {
        let mut guard = self.buf.lock();
        std::mem::take(&mut *guard)
    }
}

impl Default for BufferingPacketSink {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketSink for BufferingPacketSink {
    fn accept(&self, pkt: &PacketBuffer) -> Result<(), NetworkError> {
        self.buf.lock().push(pkt.clone());
        Ok(())
    }

    fn flush(&self) -> Result<(), NetworkError> {
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ConnectionInfo::is_local  (spec-required method)
// ────────────────────────────────────────────────────────────────────────────
impl ConnectionInfo {
    /// Returns `true` if the source IP is a loopback address.
    #[must_use]
    pub const fn is_local(&self) -> bool {
        self.src.ip().is_loopback()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ARP packet
// ────────────────────────────────────────────────────────────────────────────

/// ARP hardware type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArpHwType {
    Ethernet,
    Other(u16),
}

/// ARP operation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArpOp {
    Request,
    Reply,
    Other(u16),
}

impl fmt::Display for ArpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request => write!(f, "Request"),
            Self::Reply => write!(f, "Reply"),
            Self::Other(n) => write!(f, "Other({n})"),
        }
    }
}

/// A parsed ARP packet (RFC 826).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpPacket {
    pub htype: ArpHwType,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub op: ArpOp,
    pub sha: [u8; 6],
    pub spa: [u8; 4],
    pub tha: [u8; 6],
    pub tpa: [u8; 4],
}

impl ArpPacket {
    /// Sender hardware address as colon-separated hex.
    #[must_use]
    pub fn sha_str(&self) -> String {
        let m = &self.sha;
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }

    /// Sender protocol address as dotted decimal.
    #[must_use]
    pub fn spa_str(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.spa[0], self.spa[1], self.spa[2], self.spa[3]
        )
    }

    /// Target protocol address as dotted decimal.
    #[must_use]
    pub fn tpa_str(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.tpa[0], self.tpa[1], self.tpa[2], self.tpa[3]
        )
    }
}

impl fmt::Display for ArpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ARP {} {} -> {}",
            self.op,
            self.spa_str(),
            self.tpa_str()
        )
    }
}

/// Parse an ARP packet from raw bytes (after the Ethernet header).
///
/// # Errors
///
/// Returns [`NetError::BufferTooShort`] if fewer than 28 bytes are provided,
/// or [`NetError::MalformedPacket`] if the hardware/protocol lengths are unexpected.
pub fn parse_arp(data: &[u8]) -> Result<ArpPacket, NetError> {
    if data.len() < 28 {
        return Err(NetError::BufferTooShort {
            needed: 28,
            got: data.len(),
        });
    }
    let htype_raw = u16::from_be_bytes([data[0], data[1]]);
    let htype = if htype_raw == 1 {
        ArpHwType::Ethernet
    } else {
        ArpHwType::Other(htype_raw)
    };
    let ptype = u16::from_be_bytes([data[2], data[3]]);
    let hlen = data[4];
    let plen = data[5];
    if hlen != 6 || plen != 4 {
        return Err(NetError::MalformedPacket(format!(
            "ARP hlen={hlen} plen={plen}, expected 6/4"
        )));
    }
    let op_raw = u16::from_be_bytes([data[6], data[7]]);
    let op = match op_raw {
        1 => ArpOp::Request,
        2 => ArpOp::Reply,
        n => ArpOp::Other(n),
    };
    let mut sha = [0u8; 6];
    sha.copy_from_slice(&data[8..14]);
    let mut spa = [0u8; 4];
    spa.copy_from_slice(&data[14..18]);
    let mut tha = [0u8; 6];
    tha.copy_from_slice(&data[18..24]);
    let mut tpa = [0u8; 4];
    tpa.copy_from_slice(&data[24..28]);
    Ok(ArpPacket {
        htype,
        ptype,
        hlen,
        plen,
        op,
        sha,
        spa,
        tha,
        tpa,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// TLS record layer parser
// ────────────────────────────────────────────────────────────────────────────

/// TLS content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TlsContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
    Unknown(u8),
}

impl TlsContentType {
    /// Parse a content type byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            24 => Self::Heartbeat,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for TlsContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ChangeCipherSpec => "ChangeCipherSpec",
            Self::Alert => "Alert",
            Self::Handshake => "Handshake",
            Self::ApplicationData => "ApplicationData",
            Self::Heartbeat => "Heartbeat",
            Self::Unknown(n) => return write!(f, "Unknown({n})"),
        };
        write!(f, "{s}")
    }
}

/// A single TLS record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRecord {
    pub content_type: TlsContentType,
    /// Legacy record version (e.g. 0x0303 = TLS 1.2).
    pub version: u16,
    pub payload: Vec<u8>,
}

impl fmt::Display for TlsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TLS {} v=0x{:04x} len={}",
            self.content_type,
            self.version,
            self.payload.len()
        )
    }
}

/// Parse TLS records from a raw byte slice. Returns all complete records found.
///
/// Partial trailing records are silently ignored.
///
/// # Errors
///
/// Returns [`NetError::BufferTooShort`] if the very first record header is truncated.
pub fn parse_tls_records(data: &[u8]) -> Result<Vec<TlsRecord>, NetError> {
    if data.len() < 5 {
        return Err(NetError::BufferTooShort {
            needed: 5,
            got: data.len(),
        });
    }
    let mut records = Vec::new();
    let mut off = 0usize;
    while off + 5 <= data.len() {
        let content_type = TlsContentType::from_u8(data[off]);
        let version = u16::from_be_bytes([data[off + 1], data[off + 2]]);
        let length = u16::from_be_bytes([data[off + 3], data[off + 4]]) as usize;
        off += 5;
        if off + length > data.len() {
            break; // partial record
        }
        let payload = data[off..off + length].to_vec();
        off += length;
        records.push(TlsRecord {
            content_type,
            version,
            payload,
        });
    }
    Ok(records)
}

/// TLS handshake type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsHandshakeType {
    HelloRequest,
    ClientHello,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
    Unknown(u8),
}

impl TlsHandshakeType {
    /// Decode a handshake type byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::HelloRequest,
            1 => Self::ClientHello,
            2 => Self::ServerHello,
            11 => Self::Certificate,
            12 => Self::ServerKeyExchange,
            13 => Self::CertificateRequest,
            14 => Self::ServerHelloDone,
            15 => Self::CertificateVerify,
            16 => Self::ClientKeyExchange,
            20 => Self::Finished,
            other => Self::Unknown(other),
        }
    }
}

/// A parsed TLS handshake message header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsHandshakeMessage {
    pub msg_type: TlsHandshakeType,
    pub length: u32,
    pub body: Vec<u8>,
}

/// Parse TLS handshake messages from a Handshake record payload.
///
/// # Errors
///
/// Returns [`NetError::BufferTooShort`] if the buffer is too short for even one header.
pub fn parse_tls_handshake_messages(data: &[u8]) -> Result<Vec<TlsHandshakeMessage>, NetError> {
    if data.len() < 4 {
        return Err(NetError::BufferTooShort {
            needed: 4,
            got: data.len(),
        });
    }
    let mut messages = Vec::new();
    let mut off = 0usize;
    while off + 4 <= data.len() {
        let msg_type = TlsHandshakeType::from_u8(data[off]);
        let length = u32::from_be_bytes([0, data[off + 1], data[off + 2], data[off + 3]]);
        off += 4;
        // Use checked_add to prevent overflow on 32-bit targets.
        let Some(end) = off.checked_add(length as usize) else { break };
        if end > data.len() {
            break;
        }
        let body = data[off..end].to_vec();
        off = end;
        messages.push(TlsHandshakeMessage {
            msg_type,
            length,
            body,
        });
    }
    Ok(messages)
}

// ────────────────────────────────────────────────────────────────────────────
// TCP stream reassembly
// ────────────────────────────────────────────────────────────────────────────

/// Direction of a TCP segment relative to the session initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamDir {
    /// Initiator (SYN sender) to responder.
    ClientToServer,
    /// Responder to initiator.
    ServerToClient,
}

/// A segment pending reassembly into the TCP stream.
#[derive(Debug, Clone)]
struct PendingSegment {
    seq: u32,
    data: Vec<u8>,
}

/// One-directional TCP stream with reassembly.
#[derive(Debug)]
pub struct TcpStream {
    /// Next expected sequence number.
    pub next_seq: u32,
    /// Reassembled byte stream (in-order).
    pub stream: Vec<u8>,
    /// Out-of-order segments awaiting in-order delivery.
    pending: Vec<PendingSegment>,
    /// Total bytes received (including retransmits).
    pub total_bytes: u64,
}

impl TcpStream {
    /// Create a new stream beginning at the given ISN+1 (post-SYN).
    #[must_use]
    pub const fn new(isn_plus_one: u32) -> Self {
        Self {
            next_seq: isn_plus_one,
            stream: Vec::new(),
            pending: Vec::new(),
            total_bytes: 0,
        }
    }

    /// Feed a TCP segment into the stream.
    ///
    /// Returns the number of newly in-order bytes appended to [`Self::stream`].
    pub fn feed(&mut self, seq: u32, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        self.total_bytes += data.len() as u64;

        let data_len_u32 = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let seg_end = seq.wrapping_add(data_len_u32);

        // Fully duplicate / retransmit — segment ends at or before next expected
        if seg_end == self.next_seq || seg_end.wrapping_sub(self.next_seq) > 0x8000_0000 {
            return 0;
        }

        // In-order delivery (seq == next_seq) or partial overlap from behind
        if seq == self.next_seq {
            self.stream.extend_from_slice(data);
            self.next_seq = seg_end;
            let drained = self.drain_pending();
            return data.len() + drained;
        }

        // Segment starts before next_seq but has new data beyond it (partial overlap)
        if self.next_seq.wrapping_sub(seq) < data_len_u32
            && seq.wrapping_sub(self.next_seq) > 0x8000_0000
        {
            let seen = self.next_seq.wrapping_sub(seq) as usize;
            let trimmed = &data[seen..];
            self.stream.extend_from_slice(trimmed);
            self.next_seq = self
                .next_seq
                .wrapping_add(u32::try_from(trimmed.len()).unwrap_or(u32::MAX));
            let drained = self.drain_pending();
            return trimmed.len() + drained;
        }

        // Out of order — buffer it
        self.pending.push(PendingSegment {
            seq,
            data: data.to_vec(),
        });
        self.pending.sort_by_key(|s| s.seq);
        0
    }

    /// Drain as many pending segments as can now be delivered in order.
    fn drain_pending(&mut self) -> usize {
        let mut added = 0usize;
        loop {
            let pos = self.pending.iter().position(|s| s.seq <= self.next_seq);
            match pos {
                None => break,
                Some(i) => {
                    let seg = self.pending.remove(i);
                    let seen = self.next_seq.wrapping_sub(seg.seq) as usize;
                    if seen >= seg.data.len() {
                        continue; // fully duplicate
                    }
                    let trimmed = &seg.data[seen..];
                    self.stream.extend_from_slice(trimmed);
                    self.next_seq = self
                        .next_seq
                        .wrapping_add(u32::try_from(trimmed.len()).unwrap_or(u32::MAX));
                    added += trimmed.len();
                }
            }
        }
        added
    }

    /// Number of bytes buffered out-of-order.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.pending.iter().map(|s| s.data.len()).sum()
    }
}

/// A bidirectional TCP session with per-direction stream reassembly.
pub struct TcpSession {
    pub key: FlowKey,
    pub client_to_server: TcpStream,
    pub server_to_client: TcpStream,
    pub state: TcpState,
    pub first_seen: u64,
    pub last_seen: u64,
}

impl TcpSession {
    /// Create a new session. `client_isn` and `server_isn` are the initial
    /// sequence numbers of the SYN and SYN-ACK respectively.
    #[must_use]
    pub const fn new(key: FlowKey, client_isn: u32, server_isn: u32, now: u64) -> Self {
        Self {
            key,
            client_to_server: TcpStream::new(client_isn.wrapping_add(1)),
            server_to_client: TcpStream::new(server_isn.wrapping_add(1)),
            state: TcpState::Established,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Feed a segment from the client side.
    pub fn feed_client(&mut self, seq: u32, data: &[u8], now: u64) -> usize {
        self.last_seen = now;
        self.client_to_server.feed(seq, data)
    }

    /// Feed a segment from the server side.
    pub fn feed_server(&mut self, seq: u32, data: &[u8], now: u64) -> usize {
        self.last_seen = now;
        self.server_to_client.feed(seq, data)
    }

    /// Reassembled bytes for the client-to-server direction.
    #[must_use]
    pub fn c2s_data(&self) -> &[u8] {
        &self.client_to_server.stream
    }

    /// Reassembled bytes for the server-to-client direction.
    #[must_use]
    pub fn s2c_data(&self) -> &[u8] {
        &self.server_to_client.stream
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Flow statistics
// ────────────────────────────────────────────────────────────────────────────

/// Per-flow traffic statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub retransmits: u64,
    pub out_of_order: u64,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
}

impl FlowStats {
    /// Create a new zeroed stats record with a given start time.
    #[must_use]
    pub fn new(now_us: u64) -> Self {
        Self {
            first_seen_us: now_us,
            last_seen_us: now_us,
            ..Default::default()
        }
    }

    /// Record an inbound packet.
    pub const fn record_in(&mut self, bytes: u64, now_us: u64) {
        self.packets_in += 1;
        self.bytes_in += bytes;
        self.last_seen_us = now_us;
    }

    /// Record an outbound packet.
    pub const fn record_out(&mut self, bytes: u64, now_us: u64) {
        self.packets_out += 1;
        self.bytes_out += bytes;
        self.last_seen_us = now_us;
    }

    /// Record a packet with the given direction (Unknown is treated as inbound).
    pub const fn record_direction(&mut self, direction: Direction, bytes: u64, now_us: u64) {
        match direction {
            Direction::Inbound | Direction::Unknown => self.record_in(bytes, now_us),
            Direction::Outbound => self.record_out(bytes, now_us),
        }
    }

    /// Duration of the flow in microseconds.
    #[must_use]
    pub const fn duration_us(&self) -> u64 {
        self.last_seen_us.saturating_sub(self.first_seen_us)
    }

    /// Total packets (in + out).
    #[must_use]
    pub const fn total_packets(&self) -> u64 {
        self.packets_in + self.packets_out
    }

    /// Total bytes (in + out).
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.bytes_in + self.bytes_out
    }
}

impl fmt::Display for FlowStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FlowStats pkts={}/{} bytes={}/{} dur={}us",
            self.packets_in,
            self.packets_out,
            self.bytes_in,
            self.bytes_out,
            self.duration_us()
        )
    }
}

/// A flow statistics tracker keyed by [`FlowKey`].
pub struct FlowStatsTracker {
    stats: parking_lot::Mutex<HashMap<FlowKey, FlowStats>>,
}

impl FlowStatsTracker {
    /// Create a new empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stats: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Record a packet for the given flow.
    pub fn record(&self, key: &FlowKey, direction: Direction, bytes: u64, now_us: u64) {
        let canon = key.canonical();
        self.stats
            .lock()
            .entry(canon)
            .or_insert_with(|| FlowStats::new(now_us))
            .record_direction(direction, bytes, now_us);
    }

    /// Get a copy of the stats for the given flow.
    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<FlowStats> {
        let canon = key.canonical();
        self.stats.lock().get(&canon).cloned()
    }

    /// Return all flow statistics.
    #[must_use]
    pub fn all(&self) -> Vec<(FlowKey, FlowStats)> {
        self.stats
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Number of tracked flows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.stats.lock().len()
    }

    /// Returns `true` if no flows are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stats.lock().is_empty()
    }
}

impl Default for FlowStatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Packet builder
// ────────────────────────────────────────────────────────────────────────────

/// Builder for constructing raw network packets.
pub struct PacketBuilder {
    buf: Vec<u8>,
}

impl PacketBuilder {
    /// Create a new empty builder.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append an Ethernet II header.
    #[must_use]
    pub fn ethernet(mut self, src: [u8; 6], dst: [u8; 6], ethertype: u16) -> Self {
        self.buf.extend_from_slice(&dst);
        self.buf.extend_from_slice(&src);
        self.buf.extend_from_slice(&ethertype.to_be_bytes());
        self
    }

    /// Append an IPv4 header with the given parameters. Computes total length.
    ///
    /// # Panics
    ///
    /// Panics if the combined payload + IPv4 header exceeds 65535 bytes.
    #[must_use]
    pub fn ipv4(
        mut self,
        src: [u8; 4],
        dst: [u8; 4],
        proto: u8,
        ttl: u8,
        payload_len: u16,
    ) -> Self {
        let total_len: u16 = 20u16
            .checked_add(payload_len)
            .expect("IPv4 packet too large");
        self.buf.push(0x45); // version + IHL
        self.buf.push(0x00); // DSCP / ECN
        self.buf.extend_from_slice(&total_len.to_be_bytes());
        self.buf.extend_from_slice(&[0x00, 0x00]); // ID
        self.buf.extend_from_slice(&[0x40, 0x00]); // flags + frag offset (DF)
        self.buf.push(ttl);
        self.buf.push(proto);
        self.buf.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        self.buf.extend_from_slice(&src);
        self.buf.extend_from_slice(&dst);
        // Compute checksum over the 20-byte header we just wrote
        let hdr_start = self.buf.len() - 20;
        let cksum = ip_checksum(&self.buf[hdr_start..]);
        let cs_pos = hdr_start + 10;
        self.buf[cs_pos] = (cksum >> 8) as u8;
        self.buf[cs_pos + 1] = (cksum & 0xFF) as u8;
        self
    }

    /// Append a TCP header. Flags is a raw byte.
    #[must_use]
    pub fn tcp(
        mut self,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
    ) -> Self {
        self.buf.extend_from_slice(&src_port.to_be_bytes());
        self.buf.extend_from_slice(&dst_port.to_be_bytes());
        self.buf.extend_from_slice(&seq.to_be_bytes());
        self.buf.extend_from_slice(&ack.to_be_bytes());
        self.buf.push(0x50); // data offset = 5
        self.buf.push(flags);
        self.buf.extend_from_slice(&window.to_be_bytes());
        self.buf.extend_from_slice(&[0x00, 0x00]); // checksum
        self.buf.extend_from_slice(&[0x00, 0x00]); // urgent pointer
        self
    }

    /// Append a UDP header.
    #[must_use]
    pub fn udp(mut self, src_port: u16, dst_port: u16, payload_len: u16) -> Self {
        let length = 8u16.saturating_add(payload_len);
        self.buf.extend_from_slice(&src_port.to_be_bytes());
        self.buf.extend_from_slice(&dst_port.to_be_bytes());
        self.buf.extend_from_slice(&length.to_be_bytes());
        self.buf.extend_from_slice(&[0x00, 0x00]); // checksum
        self
    }

    /// Append a raw payload.
    #[must_use]
    pub fn payload(mut self, data: &[u8]) -> Self {
        self.buf.extend_from_slice(data);
        self
    }

    /// Consume the builder and return the raw packet bytes.
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        self.buf
    }

    /// Current length of the accumulated buffer.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if no bytes have been added.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Default for PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the Internet checksum (RFC 1071) over a byte slice.
///
/// Returns the one's complement sum in host byte order.
#[must_use]
pub fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !u16::try_from(sum & 0xFFFF).unwrap_or(0)
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP/1.1 chunked transfer decoding
// ────────────────────────────────────────────────────────────────────────────

/// Decode an HTTP/1.1 chunked-encoded body.
///
/// # Errors
///
/// Returns [`NetError::InvalidHttpMessage`] if the chunk framing is malformed.
pub fn decode_chunked(data: &[u8]) -> Result<Vec<u8>, NetError> {
    let text = std::str::from_utf8(data).map_err(|_| NetError::InvalidHttpMessage)?;
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        // Find end of chunk-size line
        let line_end = text[pos..]
            .find("\r\n")
            .ok_or(NetError::InvalidHttpMessage)?;
        let size_str = text[pos..pos + line_end].trim();
        // Strip chunk extensions
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size =
            usize::from_str_radix(size_str, 16).map_err(|_| NetError::InvalidHttpMessage)?;
        pos += line_end + 2; // skip CRLF
        if chunk_size == 0 {
            break;
        }
        if pos + chunk_size > text.len() {
            return Err(NetError::InvalidHttpMessage);
        }
        out.extend_from_slice(&data[pos..pos + chunk_size]);
        pos += chunk_size + 2; // skip trailing CRLF
    }
    Ok(out)
}

// ────────────────────────────────────────────────────────────────────────────
// Protocol detection heuristics
// ────────────────────────────────────────────────────────────────────────────

/// Identify the application-layer protocol from port numbers and payload.
///
/// Returns a static string such as `"HTTP"`, `"DNS"`, `"TLS"`, `"SSH"`, etc.
#[must_use]
pub fn detect_protocol(src_port: u16, dst_port: u16, payload: &[u8]) -> &'static str {
    let server_port = src_port.min(dst_port);
    match server_port {
        22 => return "SSH",
        25 | 587 => return "SMTP",
        53 => return "DNS",
        80 | 8080 | 8000 => return "HTTP",
        110 => return "POP3",
        143 => return "IMAP",
        443 | 8443 => return "TLS",
        445 | 139 => return "SMB",
        21 | 20 => return "FTP",
        3306 => return "MySQL",
        5432 => return "PostgreSQL",
        6379 => return "Redis",
        27017 => return "MongoDB",
        _ => {}
    }
    // Magic-byte heuristics
    if payload.starts_with(b"HTTP/") {
        return "HTTP";
    }
    for method in [
        b"GET " as &[u8],
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
    ] {
        if payload.starts_with(method) {
            return "HTTP";
        }
    }
    if payload.first().copied() == Some(22) && payload.len() >= 5 {
        return "TLS";
    }
    if payload.starts_with(b"SSH-") {
        return "SSH";
    }
    if payload.starts_with(b"\xFFSMB") || payload.starts_with(b"\xFESMB") {
        return "SMB";
    }
    if payload.starts_with(b"220 ") || payload.starts_with(b"250 ") {
        return "SMTP";
    }
    if payload.starts_with(b"+OK") || payload.starts_with(b"-ERR") {
        return "POP3";
    }
    if payload.starts_with(b"* OK") || payload.starts_with(b"* BYE") {
        return "IMAP";
    }
    "Unknown"
}

// ────────────────────────────────────────────────────────────────────────────
// ICMP type helpers
// ────────────────────────────────────────────────────────────────────────────

/// Well-known ICMP type values.
pub mod icmp_types {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACHABLE: u8 = 3;
    pub const REDIRECT: u8 = 5;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const PARAM_PROBLEM: u8 = 12;
    pub const TIMESTAMP: u8 = 13;
    pub const TIMESTAMP_REPLY: u8 = 14;
}

/// Return a human-readable name for a standard ICMP type.
#[must_use]
pub const fn icmp_type_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        icmp_types::ECHO_REPLY => "Echo Reply",
        icmp_types::DEST_UNREACHABLE => "Destination Unreachable",
        icmp_types::REDIRECT => "Redirect",
        icmp_types::ECHO_REQUEST => "Echo Request",
        icmp_types::TIME_EXCEEDED => "Time Exceeded",
        icmp_types::PARAM_PROBLEM => "Parameter Problem",
        icmp_types::TIMESTAMP => "Timestamp",
        icmp_types::TIMESTAMP_REPLY => "Timestamp Reply",
        _ => "Unknown",
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DNS record type helpers
// ────────────────────────────────────────────────────────────────────────────

/// Well-known DNS record types.
pub mod dns_types {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const ANY: u16 = 255;
}

/// Return a human-readable name for a DNS record type.
#[must_use]
pub const fn dns_type_name(rtype: u16) -> &'static str {
    match rtype {
        dns_types::A => "A",
        dns_types::NS => "NS",
        dns_types::CNAME => "CNAME",
        dns_types::SOA => "SOA",
        dns_types::PTR => "PTR",
        dns_types::MX => "MX",
        dns_types::TXT => "TXT",
        dns_types::AAAA => "AAAA",
        dns_types::SRV => "SRV",
        dns_types::ANY => "ANY",
        _ => "Unknown",
    }
}

/// Decode an A record rdata (4 bytes) as an IPv4 address string.
///
/// # Errors
///
/// Returns [`NetError::BufferTooShort`] if `rdata` is less than 4 bytes.
pub fn dns_decode_a(rdata: &[u8]) -> Result<std::net::Ipv4Addr, NetError> {
    if rdata.len() < 4 {
        return Err(NetError::BufferTooShort {
            needed: 4,
            got: rdata.len(),
        });
    }
    Ok(std::net::Ipv4Addr::new(
        rdata[0], rdata[1], rdata[2], rdata[3],
    ))
}

/// Decode an AAAA record rdata (16 bytes) as an IPv6 address.
///
/// # Errors
///
/// Returns [`NetError::BufferTooShort`] if `rdata` is less than 16 bytes.
///
/// # Panics
///
/// Panics only if internal slice-to-array conversion fails, which cannot happen
/// after the length check ensures at least 16 bytes are available.
pub fn dns_decode_aaaa(rdata: &[u8]) -> Result<std::net::Ipv6Addr, NetError> {
    if rdata.len() < 16 {
        return Err(NetError::BufferTooShort {
            needed: 16,
            got: rdata.len(),
        });
    }
    Ok(std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(&rdata[..16]).unwrap(),
    ))
}

// ────────────────────────────────────────────────────────────────────────────
// Packet serialization helpers
// ────────────────────────────────────────────────────────────────────────────

/// Serialize an [`EthernetFrame`] to raw bytes.
#[must_use]
pub fn serialize_ethernet(frame: &EthernetFrame) -> Vec<u8> {
    let mut buf = Vec::with_capacity(14 + frame.payload.len());
    buf.extend_from_slice(&frame.dst_mac);
    buf.extend_from_slice(&frame.src_mac);
    buf.extend_from_slice(&frame.ethertype.to_be_bytes());
    buf.extend_from_slice(&frame.payload);
    buf
}

/// Serialize an [`IpPacket`] (IPv4 only) to raw bytes with a minimal header.
///
/// # Panics
///
/// Panics if the source or destination address is not IPv4.
#[must_use]
pub fn serialize_ipv4(pkt: &IpPacket) -> Vec<u8> {
    let IpAddr::V4(src) = pkt.src else {
        panic!("expected IPv4 src")
    };
    let IpAddr::V4(dst) = pkt.dst else {
        panic!("expected IPv4 dst")
    };
    let total: u16 = u16::try_from(20 + pkt.payload.len()).unwrap_or(u16::MAX);
    let mut buf = Vec::with_capacity(total as usize);
    buf.push(0x45); // version + IHL
    buf.push(0); // DSCP
    buf.extend_from_slice(&total.to_be_bytes());
    buf.extend_from_slice(&[0, 0]); // id
    buf.extend_from_slice(&[0x40, 0]); // DF, no fragment
    buf.push(pkt.ttl);
    buf.push(pkt.protocol);
    buf.extend_from_slice(&[0, 0]); // checksum placeholder
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    let cksum = ip_checksum(&buf);
    buf[10] = (cksum >> 8) as u8;
    buf[11] = (cksum & 0xFF) as u8;
    buf.extend_from_slice(&pkt.payload);
    buf
}

/// Serialize a [`TcpSegment`] to raw bytes (no pseudo-header checksum).
#[must_use]
pub fn serialize_tcp(seg: &TcpSegment) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20 + seg.payload.len());
    buf.extend_from_slice(&seg.src_port.to_be_bytes());
    buf.extend_from_slice(&seg.dst_port.to_be_bytes());
    buf.extend_from_slice(&seg.seq.to_be_bytes());
    buf.extend_from_slice(&seg.ack.to_be_bytes());
    buf.push(0x50); // data offset = 5 words
    buf.push(seg.flags.bits());
    buf.extend_from_slice(&seg.window.to_be_bytes());
    buf.extend_from_slice(&[0, 0]); // checksum
    buf.extend_from_slice(&[0, 0]); // urgent pointer
    buf.extend_from_slice(&seg.payload);
    buf
}

/// Serialize a [`UdpDatagram`] to raw bytes (checksum left as zero).
#[must_use]
pub fn serialize_udp(dg: &UdpDatagram) -> Vec<u8> {
    let length: u16 = u16::try_from(8 + dg.payload.len()).unwrap_or(u16::MAX);
    let mut buf = Vec::with_capacity(length as usize);
    buf.extend_from_slice(&dg.src_port.to_be_bytes());
    buf.extend_from_slice(&dg.dst_port.to_be_bytes());
    buf.extend_from_slice(&length.to_be_bytes());
    buf.extend_from_slice(&[0, 0]); // checksum
    buf.extend_from_slice(&dg.payload);
    buf
}

// ────────────────────────────────────────────────────────────────────────────
// Session reconstruction
// ────────────────────────────────────────────────────────────────────────────

/// Metadata about a reconstructed application-layer session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedSession {
    pub key: FlowKey,
    /// Application-layer protocol guess.
    pub protocol: &'static str,
    /// Reassembled client-to-server payload.
    pub client_payload: Vec<u8>,
    /// Reassembled server-to-client payload.
    pub server_payload: Vec<u8>,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
}

impl ReconstructedSession {
    /// Attempt to decode the client payload as a UTF-8 string.
    #[must_use]
    pub fn client_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.client_payload).ok()
    }

    /// Attempt to decode the server payload as a UTF-8 string.
    #[must_use]
    pub fn server_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.server_payload).ok()
    }

    /// Combined payload size in bytes.
    #[must_use]
    pub const fn total_size(&self) -> usize {
        self.client_payload.len() + self.server_payload.len()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Extended connection tracker with flow statistics integration
// ────────────────────────────────────────────────────────────────────────────

/// Extended tracker combining connection state with per-flow statistics.
pub struct ExtConnectionTracker {
    tracker: ConnectionTracker,
    stats: FlowStatsTracker,
}

impl ExtConnectionTracker {
    /// Create a new empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tracker: ConnectionTracker::new(),
            stats: FlowStatsTracker::new(),
        }
    }

    /// Process an IPv4 packet, updating both state and statistics.
    ///
    /// # Errors
    ///
    /// Returns [`NetError`] if the packet is malformed.
    pub fn process(
        &self,
        ip: &IpPacket,
        direction: Direction,
        now_us: u64,
    ) -> Result<(), NetError> {
        self.tracker.process(ip, now_us)?;
        let (src_port, dst_port) = if ip.protocol == 6 {
            let tcp = parse_tcp(&ip.payload)?;
            (tcp.src_port, tcp.dst_port)
        } else if ip.protocol == 17 {
            let udp = parse_udp(&ip.payload)?;
            (udp.src_port, udp.dst_port)
        } else {
            (0, 0)
        };
        let key = FlowKey::new(ip.src, src_port, ip.dst, dst_port);
        self.stats
            .record(&key, direction, ip.payload.len() as u64, now_us);
        Ok(())
    }

    /// Return state for a flow.
    #[must_use]
    pub fn connection(&self, key: &FlowKey) -> Option<Connection> {
        self.tracker.get(key)
    }

    /// Return statistics for a flow.
    #[must_use]
    pub fn flow_stats(&self, key: &FlowKey) -> Option<FlowStats> {
        self.stats.get(key)
    }

    /// Number of tracked flows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tracker.len()
    }

    /// Returns `true` if no flows are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tracker.is_empty()
    }
}

impl Default for ExtConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// IPv4/IPv6 address utilities
// ────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `addr` is a private (RFC 1918 / RFC 4193) address.
#[must_use]
pub fn is_private_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(v6) => {
            // fc00::/7
            let bytes = v6.octets();
            (bytes[0] & 0xFE) == 0xFC
        }
    }
}

/// Returns `true` if `addr` is a multicast address.
#[must_use]
pub const fn is_multicast_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_multicast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

/// Returns `true` if `addr` is the limited broadcast address (255.255.255.255).
#[must_use]
pub fn is_broadcast_addr(addr: IpAddr) -> bool {
    addr == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TcpFlags ──────────────────────────────────────────────────────────

    #[test]
    fn tcp_flags_roundtrip() {
        let f = TcpFlags::SYN | TcpFlags::ACK;
        assert!(f.contains(TcpFlags::SYN));
        assert!(f.contains(TcpFlags::ACK));
        assert!(!f.contains(TcpFlags::FIN));
    }

    #[test]
    fn tcp_flags_display() {
        let f = TcpFlags::SYN | TcpFlags::ACK;
        let s = f.to_string();
        assert!(s.contains("SYN"));
        assert!(s.contains("ACK"));
    }

    #[test]
    fn tcp_flags_from_bits() {
        let f = TcpFlags::from_bits_truncate(0x12); // SYN | ACK
        assert!(f.contains(TcpFlags::SYN));
        assert!(f.contains(TcpFlags::ACK));
    }

    // ── Ethernet ─────────────────────────────────────────────────────────

    #[test]
    fn parse_ethernet_basic() {
        let mut frame = vec![0u8; 14];
        // dst mac
        frame[0..6].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        // src mac
        frame[6..12].copy_from_slice(&[0xCA, 0xFE, 0x00, 0x00, 0x00, 0x02]);
        // ethertype IPv4
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame.extend_from_slice(&[0x45, 0x00]); // minimal IPv4 header start

        let eth = parse_ethernet(&frame).unwrap();
        assert_eq!(eth.ethertype, 0x0800);
        assert_eq!(eth.dst_mac, [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        assert_eq!(eth.src_mac, [0xCA, 0xFE, 0x00, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn parse_ethernet_too_short() {
        let data = [0u8; 10];
        assert!(matches!(
            parse_ethernet(&data),
            Err(NetError::BufferTooShort {
                needed: 14,
                got: 10
            })
        ));
    }

    #[test]
    fn ethernet_mac_to_string() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(EthernetFrame::mac_to_string(&mac), "00:11:22:33:44:55");
    }

    // ── IPv4 ─────────────────────────────────────────────────────────────

    fn minimal_ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut buf = vec![0u8; total];
        buf[0] = 0x45; // version=4, ihl=5
        buf[2] = u8::try_from((total >> 8) & 0xFF).unwrap_or(0);
        buf[3] = u8::try_from(total & 0xFF).unwrap_or(0);
        buf[8] = 64; // ttl
        buf[9] = proto;
        buf[12..16].copy_from_slice(&src);
        buf[16..20].copy_from_slice(&dst);
        buf[20..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn parse_ipv4_basic() {
        let buf = minimal_ipv4([1, 2, 3, 4], [5, 6, 7, 8], 6, &[0u8; 8]);
        let pkt = parse_ipv4(&buf).unwrap();
        assert_eq!(pkt.src, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(pkt.dst, IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!(pkt.protocol, 6);
        assert_eq!(pkt.ttl, 64);
    }

    #[test]
    fn parse_ipv4_wrong_version() {
        let mut buf = minimal_ipv4([1, 2, 3, 4], [5, 6, 7, 8], 6, &[]);
        buf[0] = 0x65; // version=6
        assert!(matches!(parse_ipv4(&buf), Err(NetError::InvalidIpv4Packet)));
    }

    // ── IPv6 ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_ipv6_basic() {
        let mut buf = vec![0u8; 40];
        buf[0] = 0x60; // version=6
        buf[6] = 17; // next header = UDP
        buf[7] = 64; // hop limit
        // src = ::1
        buf[15] = 1;
        // dst = ::2
        buf[31] = 2;
        let pkt = parse_ipv6(&buf).unwrap();
        assert_eq!(pkt.protocol, 17);
        assert_eq!(pkt.ttl, 64);
    }

    #[test]
    fn parse_ipv6_wrong_version() {
        let mut buf = vec![0u8; 40];
        buf[0] = 0x40;
        assert!(matches!(parse_ipv6(&buf), Err(NetError::InvalidIpv6Packet)));
    }

    // ── TCP ──────────────────────────────────────────────────────────────

    fn minimal_tcp(src: u16, dst: u16, flags: TcpFlags, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 20 + payload.len()];
        buf[0] = (src >> 8) as u8;
        buf[1] = (src & 0xFF) as u8;
        buf[2] = (dst >> 8) as u8;
        buf[3] = (dst & 0xFF) as u8;
        buf[12] = 0x50; // data offset = 5
        buf[13] = flags.bits();
        buf[14] = 0xFF;
        buf[15] = 0xFF; // window
        buf[20..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn parse_tcp_basic() {
        let buf = minimal_tcp(1234, 80, TcpFlags::SYN, &[]);
        let seg = parse_tcp(&buf).unwrap();
        assert_eq!(seg.src_port, 1234);
        assert_eq!(seg.dst_port, 80);
        assert!(seg.flags.contains(TcpFlags::SYN));
    }

    #[test]
    fn parse_tcp_with_payload() {
        let payload = b"GET / HTTP/1.1\r\n";
        let buf = minimal_tcp(54321, 80, TcpFlags::PSH | TcpFlags::ACK, payload);
        let seg = parse_tcp(&buf).unwrap();
        assert_eq!(seg.payload, payload);
    }

    // ── UDP ──────────────────────────────────────────────────────────────

    #[test]
    fn parse_udp_basic() {
        let payload = b"hello dns";
        let mut buf = vec![0u8; 8 + payload.len()];
        buf[0] = 0x00;
        buf[1] = 53; // src port 53
        buf[2] = 0xC0;
        buf[3] = 0x00; // dst port 49152
        let len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
        buf[4] = u8::try_from((len >> 8) & 0xFF).unwrap_or(0);
        buf[5] = u8::try_from(len & 0xFF).unwrap_or(0);
        buf[8..].copy_from_slice(payload);
        let dg = parse_udp(&buf).unwrap();
        assert_eq!(dg.src_port, 53);
        assert_eq!(dg.payload, payload);
    }

    // ── ICMP ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_icmp_echo_request() {
        let buf = [8u8, 0, 0xF7, 0xFF, 0x00, 0x01, 0x00, 0x01];
        let pkt = parse_icmp(&buf).unwrap();
        assert_eq!(pkt.icmp_type, 8);
        assert_eq!(pkt.code, 0);
    }

    // ── DNS ──────────────────────────────────────────────────────────────

    #[test]
    fn parse_dns_query() {
        // A query for "example.com" type A
        let data: &[u8] = &[
            0xAB, 0xCD, // id
            0x01, 0x00, // flags (query, RD)
            0x00, 0x01, // qdcount=1
            0x00, 0x00, // ancount=0
            0x00, 0x00, // nscount=0
            0x00, 0x00, // arcount=0
            // question: example.com A IN
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // end of name
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ];
        let dns = parse_dns(data).unwrap();
        assert_eq!(dns.id, 0xABCD);
        assert!(!dns.is_response());
        assert_eq!(dns.questions.len(), 1);
        assert_eq!(dns.questions[0].name, "example.com");
        assert_eq!(dns.questions[0].qtype, 1);
    }

    // ── HTTP ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_http_request_get() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let req = parse_http_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.uri, "/index.html");
        assert_eq!(req.header("Host"), Some("example.com"));
    }

    #[test]
    fn parse_http_response_200() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.body, b"hello");
    }

    // ── ConnectionTracker ────────────────────────────────────────────────

    #[test]
    fn connection_tracker_tcp_flow() {
        let tracker = ConnectionTracker::new();
        let src = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

        let ip_data = minimal_ipv4(
            [1, 1, 1, 1],
            [2, 2, 2, 2],
            6,
            &minimal_tcp(1234, 80, TcpFlags::SYN, &[]),
        );
        let ip = parse_ipv4(&ip_data).unwrap();
        tracker.process(&ip, 1000).unwrap();

        let key = FlowKey::new(src, 1234, dst, 80);
        let conn = tracker.get(&key).unwrap();
        assert_eq!(conn.packet_count, 1);
    }

    #[test]
    fn connection_tracker_bidirectional_same_flow() {
        let tracker = ConnectionTracker::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let ip1 = minimal_ipv4(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            6,
            &minimal_tcp(5000, 80, TcpFlags::SYN, &[]),
        );
        let ip2 = minimal_ipv4(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            6,
            &minimal_tcp(80, 5000, TcpFlags::SYN | TcpFlags::ACK, &[]),
        );

        tracker.process(&parse_ipv4(&ip1).unwrap(), 1).unwrap();
        tracker.process(&parse_ipv4(&ip2).unwrap(), 2).unwrap();

        // Both directions should map to the same canonical flow
        assert_eq!(tracker.len(), 1);
        let key = FlowKey::new(src, 5000, dst, 80);
        let conn = tracker.get(&key).unwrap();
        assert_eq!(conn.packet_count, 2);
    }

    #[test]
    fn connection_tracker_remove() {
        let tracker = ConnectionTracker::new();
        let ip_data = minimal_ipv4(
            [1, 1, 1, 1],
            [2, 2, 2, 2],
            6,
            &minimal_tcp(9000, 443, TcpFlags::SYN, &[]),
        );
        let ip = parse_ipv4(&ip_data).unwrap();
        tracker.process(&ip, 0).unwrap();
        assert_eq!(tracker.len(), 1);

        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            9000,
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            443,
        );
        assert!(tracker.remove(&key).is_some());
        assert!(tracker.is_empty());
    }

    #[test]
    fn capture_stats_display() {
        let s = CaptureStats {
            received: 100,
            dropped: 5,
            if_dropped: 1,
        };
        let t = s.to_string();
        assert!(t.contains("100"));
    }

    #[test]
    fn flow_key_display() {
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            1234,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            80,
        );
        assert!(key.to_string().contains("80"));
    }

    #[test]
    fn tcp_state_display() {
        assert_eq!(TcpState::Established.to_string(), "ESTABLISHED");
        assert_eq!(TcpState::SynSent.to_string(), "SYN_SENT");
    }

    #[test]
    fn ip_packet_display() {
        let pkt = IpPacket {
            src: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            protocol: 6,
            ttl: 64,
            payload: vec![],
        };
        let s = pkt.to_string();
        assert!(s.contains("proto=6"));
    }

    #[test]
    fn udp_display() {
        let dg = UdpDatagram {
            src_port: 53,
            dst_port: 1024,
            payload: vec![1, 2, 3],
        };
        assert!(dg.to_string().contains("53"));
    }

    // ── New types (Protocol, ConnectionInfo, PacketBuffer, etc.) ─────────

    #[test]
    fn protocol_display_all_variants() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp.to_string(), "UDP");
        assert_eq!(Protocol::Icmp.to_string(), "ICMP");
        assert_eq!(Protocol::Dns.to_string(), "DNS");
        assert_eq!(Protocol::Http.to_string(), "HTTP");
        assert_eq!(Protocol::Https.to_string(), "HTTPS");
        assert_eq!(Protocol::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn connection_info_new_and_display() {
        let src = "127.0.0.1:1234".parse().unwrap();
        let dst = "192.168.1.1:80".parse().unwrap();
        let ci = ConnectionInfo::new(src, dst, Protocol::Http, Some(1234));
        assert_eq!(ci.src, src);
        assert_eq!(ci.dst, dst);
        assert_eq!(ci.protocol, Protocol::Http);
        assert_eq!(ci.pid, Some(1234));
        let s = ci.to_string();
        assert!(s.contains("HTTP"));
        assert!(s.contains("pid=1234"));
    }

    #[test]
    fn connection_info_no_pid() {
        let src = "10.0.0.1:5000".parse().unwrap();
        let dst = "10.0.0.2:443".parse().unwrap();
        let ci = ConnectionInfo::new(src, dst, Protocol::Https, None);
        assert!(ci.pid.is_none());
        let s = ci.to_string();
        assert!(s.contains("HTTPS"));
    }

    #[test]
    fn packet_buffer_new_and_len() {
        let buf = PacketBuffer::new(vec![1, 2, 3, 4], 1_000_000, CaptureLink::Ethernet);
        assert_eq!(buf.len(), 4);
        assert!(!buf.is_empty());
        assert_eq!(buf.link_type, CaptureLink::Ethernet);
        assert_eq!(buf.timestamp_us, 1_000_000);
    }

    #[test]
    fn packet_buffer_empty() {
        let buf = PacketBuffer::new(vec![], 0, CaptureLink::Raw);
        assert!(buf.is_empty());
    }

    #[test]
    fn capture_link_display_all() {
        assert_eq!(CaptureLink::Ethernet.to_string(), "Ethernet");
        assert_eq!(CaptureLink::Raw.to_string(), "Raw");
        assert_eq!(CaptureLink::Loopback.to_string(), "Loopback");
        assert_eq!(CaptureLink::Null.to_string(), "Null");
    }

    #[test]
    fn direction_display_all() {
        assert_eq!(Direction::Inbound.to_string(), "Inbound");
        assert_eq!(Direction::Outbound.to_string(), "Outbound");
        assert_eq!(Direction::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn network_error_display() {
        let e = NetworkError::ParseError("bad data".to_string());
        assert!(e.to_string().contains("bad data"));
        let e2 = NetworkError::IoError("connection reset".to_string());
        assert!(e2.to_string().contains("connection reset"));
        let e3 = NetworkError::UnsupportedProtocol("QUIC".to_string());
        assert!(e3.to_string().contains("QUIC"));
    }

    #[test]
    fn packet_sink_impl() {
        struct LogSink {
            count: std::sync::atomic::AtomicU64,
        }
        impl PacketSink for LogSink {
            fn accept(&self, pkt: &PacketBuffer) -> Result<(), NetworkError> {
                if pkt.is_empty() {
                    return Err(NetworkError::ParseError("empty packet".to_string()));
                }
                self.count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
        }
        let sink = LogSink {
            count: std::sync::atomic::AtomicU64::new(0),
        };
        let pkt = PacketBuffer::new(vec![0xDE, 0xAD], 100, CaptureLink::Ethernet);
        assert!(sink.accept(&pkt).is_ok());
        assert_eq!(sink.count.load(std::sync::atomic::Ordering::Relaxed), 1);
        let empty = PacketBuffer::new(vec![], 200, CaptureLink::Raw);
        assert!(sink.accept(&empty).is_err());
    }

    // ── Spec-required LinkType tests ──────────────────────────────────────

    #[test]
    fn link_type_display_all() {
        assert_eq!(LinkType::Ethernet.to_string(), "Ethernet");
        assert_eq!(LinkType::Raw.to_string(), "Raw");
        assert_eq!(LinkType::Loopback.to_string(), "Loopback");
        assert_eq!(LinkType::Null.to_string(), "Null");
    }

    #[test]
    fn link_type_dlt_ethernet() {
        assert_eq!(LinkType::Ethernet.dlt(), 1);
    }

    #[test]
    fn link_type_dlt_loopback() {
        assert_eq!(LinkType::Loopback.dlt(), 0);
    }

    #[test]
    fn link_type_dlt_null() {
        assert_eq!(LinkType::Null.dlt(), 0);
    }

    #[test]
    fn link_type_dlt_raw() {
        assert_eq!(LinkType::Raw.dlt(), 12);
    }

    // ── BlackholePacketSink ───────────────────────────────────────────────

    #[test]
    fn blackhole_sink_accepts_anything() {
        let sink = BlackholePacketSink;
        let pkt = PacketBuffer::new(vec![1, 2, 3], 0, CaptureLink::Ethernet);
        assert!(sink.accept(&pkt).is_ok());
        let empty = PacketBuffer::new(vec![], 0, CaptureLink::Raw);
        assert!(sink.accept(&empty).is_ok());
        assert!(sink.flush().is_ok());
    }

    // ── BufferingPacketSink ───────────────────────────────────────────────

    #[test]
    fn buffering_sink_collects_packets() {
        let sink = BufferingPacketSink::new();
        let p1 = PacketBuffer::new(vec![1], 10, CaptureLink::Ethernet);
        let p2 = PacketBuffer::new(vec![2, 3], 20, CaptureLink::Raw);
        sink.accept(&p1).unwrap();
        sink.accept(&p2).unwrap();
        let drained = sink.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].data, vec![1]);
        assert_eq!(drained[1].data, vec![2, 3]);
    }

    #[test]
    fn buffering_sink_drain_clears() {
        let sink = BufferingPacketSink::new();
        let p = PacketBuffer::new(vec![0xFF], 0, CaptureLink::Null);
        sink.accept(&p).unwrap();
        let _ = sink.drain();
        assert!(sink.drain().is_empty());
    }

    #[test]
    fn buffering_sink_flush_ok() {
        let sink = BufferingPacketSink::default();
        assert!(sink.flush().is_ok());
    }

    // ── ConnectionInfo::is_local ──────────────────────────────────────────

    #[test]
    fn connection_info_is_local_loopback() {
        let src = "127.0.0.1:1234".parse().unwrap();
        let dst = "8.8.8.8:53".parse().unwrap();
        let ci = ConnectionInfo::new(src, dst, Protocol::Dns, None);
        assert!(ci.is_local());
    }

    #[test]
    fn connection_info_is_local_remote() {
        let src = "192.168.1.1:5000".parse().unwrap();
        let dst = "1.1.1.1:443".parse().unwrap();
        let ci = ConnectionInfo::new(src, dst, Protocol::Https, None);
        assert!(!ci.is_local());
    }

    // ── NetworkError::InvalidAddress ─────────────────────────────────────

    #[test]
    fn network_error_invalid_address() {
        let e = NetworkError::InvalidAddress("not an ip".to_string());
        assert!(e.to_string().contains("not an ip"));
    }

    // ── PacketSink flush default ──────────────────────────────────────────

    #[test]
    fn packet_sink_flush_default() {
        struct MinimalSink;
        impl PacketSink for MinimalSink {
            fn accept(&self, _pkt: &PacketBuffer) -> Result<(), NetworkError> {
                Ok(())
            }
        }
        let s = MinimalSink;
        // flush() uses the default impl
        assert!(s.flush().is_ok());
    }

    // ── ARP ──────────────────────────────────────────────────────────────

    #[test]
    fn parse_arp_request() {
        let mut buf = vec![0u8; 28];
        buf[0] = 0x00;
        buf[1] = 0x01; // htype=Ethernet
        buf[2] = 0x08;
        buf[3] = 0x00; // ptype=IPv4
        buf[4] = 6;
        buf[5] = 4; // hlen=6, plen=4
        buf[6] = 0x00;
        buf[7] = 0x01; // op=Request
        buf[8..14].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]); // sha
        buf[14..18].copy_from_slice(&[192, 168, 1, 1]); // spa
        buf[18..24].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // tha
        buf[24..28].copy_from_slice(&[192, 168, 1, 2]); // tpa
        let arp = parse_arp(&buf).unwrap();
        assert_eq!(arp.op, ArpOp::Request);
        assert_eq!(arp.spa_str(), "192.168.1.1");
        assert_eq!(arp.tpa_str(), "192.168.1.2");
        assert_eq!(arp.sha_str(), "de:ad:be:ef:00:01");
    }

    #[test]
    fn parse_arp_too_short() {
        let buf = vec![0u8; 10];
        assert!(matches!(
            parse_arp(&buf),
            Err(NetError::BufferTooShort { needed: 28, .. })
        ));
    }

    #[test]
    fn parse_arp_reply() {
        let mut buf = vec![0u8; 28];
        buf[0] = 0;
        buf[1] = 1;
        buf[2] = 0x08;
        buf[3] = 0x00;
        buf[4] = 6;
        buf[5] = 4;
        buf[6] = 0;
        buf[7] = 2; // op=Reply
        let arp = parse_arp(&buf).unwrap();
        assert_eq!(arp.op, ArpOp::Reply);
    }

    #[test]
    fn arp_malformed_hlen() {
        let mut buf = vec![0u8; 28];
        buf[0] = 0;
        buf[1] = 1;
        buf[2] = 0x08;
        buf[3] = 0x00;
        buf[4] = 8;
        buf[5] = 4; // hlen=8 (wrong)
        buf[6] = 0;
        buf[7] = 1;
        assert!(parse_arp(&buf).is_err());
    }

    // ── TLS record layer ─────────────────────────────────────────────────

    #[test]
    fn parse_tls_records_handshake() {
        let payload = b"hello world";
        let mut data = vec![22u8, 0x03, 0x03];
        let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(payload);
        let records = parse_tls_records(&data).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_type, TlsContentType::Handshake);
        assert_eq!(records[0].version, 0x0303);
        assert_eq!(records[0].payload, payload);
    }

    #[test]
    fn parse_tls_records_multiple() {
        let mut data = Vec::new();
        for ct in [22u8, 23u8] {
            data.push(ct);
            data.extend_from_slice(&[0x03, 0x03]);
            data.extend_from_slice(&4u16.to_be_bytes());
            data.extend_from_slice(&[1, 2, 3, 4]);
        }
        let records = parse_tls_records(&data).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].content_type, TlsContentType::ApplicationData);
    }

    #[test]
    fn tls_content_type_display() {
        assert_eq!(TlsContentType::Handshake.to_string(), "Handshake");
        assert_eq!(
            TlsContentType::ApplicationData.to_string(),
            "ApplicationData"
        );
        assert_eq!(TlsContentType::Alert.to_string(), "Alert");
    }

    // ── TLS handshake messages ────────────────────────────────────────────

    #[test]
    fn parse_tls_handshake_client_hello() {
        let body = vec![0u8; 10];
        let mut data = vec![1u8]; // ClientHello
        let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
        data.push(u8::try_from((len >> 16) & 0xFF).unwrap_or(0));
        data.push(u8::try_from((len >> 8) & 0xFF).unwrap_or(0));
        data.push(u8::try_from(len & 0xFF).unwrap_or(0));
        data.extend_from_slice(&body);
        let msgs = parse_tls_handshake_messages(&data).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].msg_type, TlsHandshakeType::ClientHello);
        assert_eq!(msgs[0].length, 10);
    }

    // ── TCP stream reassembly ─────────────────────────────────────────────

    #[test]
    fn tcp_stream_in_order() {
        let mut stream = TcpStream::new(1000);
        stream.feed(1000, b"hello ");
        stream.feed(1006, b"world");
        assert_eq!(stream.stream, b"hello world");
        assert_eq!(stream.next_seq, 1011);
    }

    #[test]
    fn tcp_stream_out_of_order() {
        let mut stream = TcpStream::new(1);
        stream.feed(7, b"world"); // out of order: seq=7, covers bytes 7..12
        assert!(stream.stream.is_empty());
        stream.feed(1, b"hello "); // in-order: seq=1, covers bytes 1..7, fills gap
        // After delivering "hello ", next_seq=7; drain_pending delivers "world"
        assert_eq!(stream.stream, b"hello world");
    }

    #[test]
    fn tcp_stream_pending_bytes() {
        let mut stream = TcpStream::new(1);
        stream.feed(10, b"late");
        assert_eq!(stream.pending_bytes(), 4);
    }

    #[test]
    fn tcp_session_bidirectional() {
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            1234,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            80,
        );
        let mut session = TcpSession::new(key, 0, 0, 0);
        session.feed_client(1, b"GET / HTTP/1.1\r\n", 1);
        session.feed_server(1, b"HTTP/1.1 200 OK\r\n", 2);
        assert_eq!(session.c2s_data(), b"GET / HTTP/1.1\r\n");
        assert_eq!(session.s2c_data(), b"HTTP/1.1 200 OK\r\n");
    }

    // ── Flow statistics ───────────────────────────────────────────────────

    #[test]
    fn flow_stats_record_and_duration() {
        let mut stats = FlowStats::new(1000);
        stats.record_in(100, 2000);
        stats.record_out(200, 3000);
        assert_eq!(stats.total_packets(), 2);
        assert_eq!(stats.total_bytes(), 300);
        assert_eq!(stats.duration_us(), 2000);
    }

    #[test]
    fn flow_stats_display() {
        let stats = FlowStats {
            packets_in: 5,
            packets_out: 3,
            bytes_in: 500,
            bytes_out: 300,
            ..Default::default()
        };
        let s = stats.to_string();
        assert!(s.contains("5/3"));
        assert!(s.contains("500/300"));
    }

    #[test]
    fn flow_stats_tracker() {
        let tracker = FlowStatsTracker::new();
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            5000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
        );
        tracker.record(&key, Direction::Outbound, 100, 1000);
        tracker.record(&key, Direction::Inbound, 200, 2000);
        let stats = tracker.get(&key).unwrap();
        assert_eq!(stats.bytes_out, 100);
        assert_eq!(stats.bytes_in, 200);
        assert_eq!(tracker.len(), 1);
    }

    // ── Packet builder ────────────────────────────────────────────────────

    #[test]
    fn packet_builder_eth_ipv4_tcp() {
        let payload = b"test";
        let raw = PacketBuilder::new()
            .ethernet([0xCA, 0xFE, 0, 0, 0, 1], [0xDE, 0xAD, 0, 0, 0, 2], 0x0800)
            .ipv4(
                [1, 2, 3, 4],
                [5, 6, 7, 8],
                6,
                64,
                20 + u16::try_from(payload.len()).unwrap_or(u16::MAX),
            )
            .tcp(1234, 80, 0, 0, 0x02, 65535)
            .payload(payload)
            .build();
        // At minimum: 14 (eth) + 20 (ip) + 20 (tcp) + 4 (payload) = 58
        assert!(raw.len() >= 58);
        // Check ethertype
        assert_eq!(raw[12], 0x08);
        assert_eq!(raw[13], 0x00);
    }

    #[test]
    fn packet_builder_udp() {
        let payload = b"dns";
        let raw = PacketBuilder::new()
            .udp(12345, 53, u16::try_from(payload.len()).unwrap_or(u16::MAX))
            .payload(payload)
            .build();
        assert_eq!(raw.len(), 8 + payload.len());
        let dg = parse_udp(&raw).unwrap();
        assert_eq!(dg.src_port, 12345);
        assert_eq!(dg.dst_port, 53);
        assert_eq!(dg.payload, payload);
    }

    #[test]
    fn packet_builder_empty() {
        let b = PacketBuilder::new();
        assert!(b.is_empty());
        assert_eq!(b.build(), Vec::<u8>::new());
    }

    // ── IP checksum ───────────────────────────────────────────────────────

    #[test]
    fn ip_checksum_known_header() {
        // Standard 20-byte IPv4 header for 192.168.1.1 -> 8.8.8.8 (ICMP)
        // with zeroed checksum; result should be non-zero
        let hdr = [
            0x45u8, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 192, 168, 1,
            1, 8, 8, 8, 8,
        ];
        let ck = ip_checksum(&hdr);
        assert_ne!(ck, 0);
        // Verify: inserting the checksum back and recomputing gives 0
        // (RFC 1071: sum of all words in a valid header including the checksum word = 0xFFFF,
        //  and ip_checksum returns !sum, so ip_checksum(valid_hdr) = !(0xFFFF) = 0x0000)
        let mut hdr2 = hdr;
        hdr2[10] = (ck >> 8) as u8;
        hdr2[11] = (ck & 0xFF) as u8;
        assert_eq!(ip_checksum(&hdr2), 0x0000);
    }

    // ── HTTP chunked decoding ─────────────────────────────────────────────

    #[test]
    fn decode_chunked_basic() {
        let encoded = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let decoded = decode_chunked(encoded).unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn decode_chunked_empty_body() {
        let encoded = b"0\r\n\r\n";
        let decoded = decode_chunked(encoded).unwrap();
        assert!(decoded.is_empty());
    }

    // ── Protocol detection ────────────────────────────────────────────────

    #[test]
    fn detect_protocol_by_port() {
        assert_eq!(detect_protocol(12345, 80, b""), "HTTP");
        assert_eq!(detect_protocol(53, 12345, b""), "DNS");
        assert_eq!(detect_protocol(22, 12345, b""), "SSH");
        assert_eq!(detect_protocol(12345, 443, b""), "TLS");
    }

    #[test]
    fn detect_protocol_by_payload() {
        assert_eq!(detect_protocol(10000, 10001, b"GET / HTTP/1.1\r\n"), "HTTP");
        assert_eq!(
            detect_protocol(10000, 10001, b"HTTP/1.1 200 OK\r\n"),
            "HTTP"
        );
        assert_eq!(detect_protocol(10000, 10001, b"SSH-2.0-OpenSSH"), "SSH");
        let tls = [22u8, 3, 3, 0, 5];
        assert_eq!(detect_protocol(10000, 10001, &tls), "TLS");
    }

    // ── ICMP type names ───────────────────────────────────────────────────

    #[test]
    fn icmp_type_names() {
        assert_eq!(icmp_type_name(8), "Echo Request");
        assert_eq!(icmp_type_name(0), "Echo Reply");
        assert_eq!(icmp_type_name(11), "Time Exceeded");
        assert_eq!(icmp_type_name(255), "Unknown");
    }

    // ── DNS type names ────────────────────────────────────────────────────

    #[test]
    fn dns_type_names() {
        assert_eq!(dns_type_name(1), "A");
        assert_eq!(dns_type_name(28), "AAAA");
        assert_eq!(dns_type_name(15), "MX");
        assert_eq!(dns_type_name(999), "Unknown");
    }

    #[test]
    fn dns_decode_a_and_aaaa() {
        let a = dns_decode_a(&[8, 8, 8, 8]).unwrap();
        assert_eq!(a.to_string(), "8.8.8.8");
        let aaaa_bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let aaaa = dns_decode_aaaa(&aaaa_bytes).unwrap();
        assert!(aaaa.to_string().starts_with("2001"));
    }

    // ── Serialization ─────────────────────────────────────────────────────

    #[test]
    fn serialize_ethernet_roundtrip() {
        let frame = EthernetFrame {
            dst_mac: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
            src_mac: [0xCA, 0xFE, 0x00, 0x00, 0x00, 0x02],
            ethertype: 0x0800,
            payload: vec![1, 2, 3, 4],
        };
        let bytes = serialize_ethernet(&frame);
        let parsed = parse_ethernet(&bytes).unwrap();
        assert_eq!(parsed.ethertype, 0x0800);
        assert_eq!(parsed.dst_mac, frame.dst_mac);
        assert_eq!(parsed.src_mac, frame.src_mac);
        assert_eq!(parsed.payload, frame.payload);
    }

    #[test]
    fn serialize_ipv4_roundtrip() {
        let pkt = IpPacket {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            protocol: 17,
            ttl: 128,
            payload: vec![0u8; 8],
        };
        let bytes = serialize_ipv4(&pkt);
        let parsed = parse_ipv4(&bytes).unwrap();
        assert_eq!(parsed.src, pkt.src);
        assert_eq!(parsed.dst, pkt.dst);
        assert_eq!(parsed.protocol, 17);
        assert_eq!(parsed.ttl, 128);
    }

    #[test]
    fn serialize_tcp_roundtrip() {
        let seg = TcpSegment {
            src_port: 1234,
            dst_port: 80,
            seq: 100,
            ack: 200,
            flags: TcpFlags::SYN | TcpFlags::ACK,
            window: 65535,
            payload: b"hello".to_vec(),
        };
        let bytes = serialize_tcp(&seg);
        let parsed = parse_tcp(&bytes).unwrap();
        assert_eq!(parsed.src_port, 1234);
        assert_eq!(parsed.dst_port, 80);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn serialize_udp_roundtrip() {
        let dg = UdpDatagram {
            src_port: 5353,
            dst_port: 5353,
            payload: b"mdns".to_vec(),
        };
        let bytes = serialize_udp(&dg);
        let parsed = parse_udp(&bytes).unwrap();
        assert_eq!(parsed.src_port, 5353);
        assert_eq!(parsed.payload, b"mdns");
    }

    // ── Address utilities ─────────────────────────────────────────────────

    #[test]
    fn private_addr_detection() {
        assert!(is_private_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(is_private_addr(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!is_private_addr(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn multicast_and_broadcast() {
        assert!(is_multicast_addr(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
        assert!(!is_multicast_addr(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
        assert!(is_broadcast_addr(IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(!is_broadcast_addr(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 255
        ))));
    }

    // ── ExtConnectionTracker ─────────────────────────────────────────────

    #[test]
    fn ext_tracker_tracks_stats() {
        let tracker = ExtConnectionTracker::new();
        let ip_data = minimal_ipv4(
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            6,
            &minimal_tcp(1234, 80, TcpFlags::SYN, &[1, 2, 3]),
        );
        let ip = parse_ipv4(&ip_data).unwrap();
        tracker.process(&ip, Direction::Outbound, 0).unwrap();
        assert_eq!(tracker.len(), 1);
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            1234,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            80,
        );
        let stats = tracker.flow_stats(&key).unwrap();
        assert_eq!(stats.bytes_out, ip.payload.len() as u64);
    }

    // ── ReconstructedSession ─────────────────────────────────────────────

    #[test]
    fn reconstructed_session_text() {
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            1234,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            80,
        );
        let sess = ReconstructedSession {
            key,
            protocol: "HTTP",
            client_payload: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            server_payload: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            first_seen_us: 0,
            last_seen_us: 1000,
        };
        assert_eq!(sess.protocol, "HTTP");
        assert!(sess.client_text().unwrap().starts_with("GET"));
        assert!(sess.server_text().unwrap().starts_with("HTTP"));
        assert_eq!(
            sess.total_size(),
            sess.client_payload.len() + sess.server_payload.len()
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Extended protocol headers — IPv4 options, IPv6 extension headers,
// TCP options, IGMP, ICMPv6, DNS extended types, EDNS0, TLS extensions
// ════════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────────
// IPv4 options
// ────────────────────────────────────────────────────────────────────────────

/// IPv4 option copied/class/number fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ipv4Option {
    /// End of options list (type 0).
    Eool,
    /// No operation (type 1).
    Nop,
    /// Security (type 130).
    Security { data: Vec<u8> },
    /// Loose source routing (type 131).
    LooseSourceRoute {
        pointer: u8,
        routes: Vec<std::net::Ipv4Addr>,
    },
    /// Strict source routing (type 137).
    StrictSourceRoute {
        pointer: u8,
        routes: Vec<std::net::Ipv4Addr>,
    },
    /// Record route (type 7).
    RecordRoute {
        pointer: u8,
        routes: Vec<std::net::Ipv4Addr>,
    },
    /// Internet timestamp (type 68).
    InternetTimestamp { data: Vec<u8> },
    /// Router alert (type 148).
    RouterAlert { value: u16 },
    /// Unknown option.
    Unknown { option_type: u8, data: Vec<u8> },
}

/// Parse IPv4 options from the options field of an IPv4 header.
///
/// `options_data` should be the bytes between the end of the fixed 20-byte
/// header and the start of the payload (i.e. `data[20..ihl*4]`).
///
/// # Errors
///
/// Returns [`NetError::MalformedPacket`] if an option length is invalid.
pub fn parse_ipv4_options(options_data: &[u8]) -> Result<Vec<Ipv4Option>, NetError> {
    let mut opts = Vec::new();
    let mut pos = 0usize;
    while pos < options_data.len() {
        let opt_type = options_data[pos];
        match opt_type {
            0 => {
                opts.push(Ipv4Option::Eool);
                break; // end of option list
            }
            1 => {
                opts.push(Ipv4Option::Nop);
                pos += 1;
            }
            _ => {
                if pos + 1 >= options_data.len() {
                    return Err(NetError::MalformedPacket(
                        "IPv4 option truncated before length byte".to_string(),
                    ));
                }
                let opt_len = options_data[pos + 1] as usize;
                if opt_len < 2 {
                    return Err(NetError::MalformedPacket(format!(
                        "IPv4 option type={opt_type} has len={opt_len} < 2"
                    )));
                }
                if pos + opt_len > options_data.len() {
                    return Err(NetError::MalformedPacket(format!(
                        "IPv4 option type={opt_type} len={opt_len} extends past buffer"
                    )));
                }
                let data = options_data[pos + 2..pos + opt_len].to_vec();
                let opt = match opt_type {
                    130 => Ipv4Option::Security { data },
                    131 => {
                        let pointer = if data.is_empty() { 4 } else { data[0] };
                        let routes = data[1..]
                            .chunks_exact(4)
                            .map(|c| std::net::Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                            .collect();
                        Ipv4Option::LooseSourceRoute { pointer, routes }
                    }
                    137 => {
                        let pointer = if data.is_empty() { 4 } else { data[0] };
                        let routes = data[1..]
                            .chunks_exact(4)
                            .map(|c| std::net::Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                            .collect();
                        Ipv4Option::StrictSourceRoute { pointer, routes }
                    }
                    7 => {
                        let pointer = if data.is_empty() { 4 } else { data[0] };
                        let routes = data[1..]
                            .chunks_exact(4)
                            .map(|c| std::net::Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                            .collect();
                        Ipv4Option::RecordRoute { pointer, routes }
                    }
                    68 => Ipv4Option::InternetTimestamp { data },
                    148 => {
                        let value = if data.len() >= 2 {
                            u16::from_be_bytes([data[0], data[1]])
                        } else {
                            0
                        };
                        Ipv4Option::RouterAlert { value }
                    }
                    _ => Ipv4Option::Unknown {
                        option_type: opt_type,
                        data,
                    },
                };
                opts.push(opt);
                pos += opt_len;
            }
        }
    }
    Ok(opts)
}

// ────────────────────────────────────────────────────────────────────────────
// IPv6 extension headers
// ────────────────────────────────────────────────────────────────────────────

/// IPv6 extension header type codes (next-header values).
pub mod ipv6_next_hdr {
    pub const HOP_BY_HOP: u8 = 0;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const IPV6: u8 = 41;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const AH: u8 = 51;
    pub const ESP: u8 = 50;
    pub const ICMPV6: u8 = 58;
    pub const NO_NEXT: u8 = 59;
    pub const DEST_OPTIONS: u8 = 60;
}

/// A single option inside a Hop-by-Hop or Destination Options extension header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6ExtOption {
    pub opt_type: u8,
    pub data: Vec<u8>,
}

/// IPv6 Hop-by-Hop Options or Destination Options extension header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6HopByHopHeader {
    pub next_header: u8,
    /// Header length in 8-octet units, not including the first 8 octets.
    pub hdr_ext_len: u8,
    pub options: Vec<Ipv6ExtOption>,
}

/// IPv6 Routing extension header (type 0 / type 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6RoutingHeader {
    pub next_header: u8,
    pub hdr_ext_len: u8,
    pub routing_type: u8,
    pub segments_left: u8,
    pub data: Vec<u8>,
}

/// IPv6 Fragment extension header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6FragmentHeader {
    pub next_header: u8,
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub identification: u32,
}

/// IPv6 Authentication Header (AH, RFC 4302).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6AuthHeader {
    pub next_header: u8,
    pub payload_len: u8,
    pub spi: u32,
    pub sequence_number: u32,
    pub icv: Vec<u8>,
}

/// An IPv6 extension header variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ipv6ExtHeader {
    HopByHop(Ipv6HopByHopHeader),
    Routing(Ipv6RoutingHeader),
    Fragment(Ipv6FragmentHeader),
    DestOptions(Ipv6HopByHopHeader),
    Auth(Ipv6AuthHeader),
    /// ESP is opaque; we only record the SPI.
    Esp {
        spi: u32,
    },
}

/// Result of parsing an IPv6 packet with all extension headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Packet {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    /// Traffic class (DSCP + ECN).
    pub traffic_class: u8,
    /// Flow label.
    pub flow_label: u32,
    /// Hop limit.
    pub hop_limit: u8,
    /// Chain of extension headers.
    pub ext_headers: Vec<Ipv6ExtHeader>,
    /// Final next-header protocol number (after all extension headers).
    pub final_protocol: u8,
    /// Payload after all extension headers.
    pub payload: Vec<u8>,
}

/// Parse an IPv6 packet including all extension headers.
///
/// # Errors
///
/// Returns [`NetError::InvalidIpv6Packet`] for version mismatch,
/// [`NetError::BufferTooShort`] if data is too short.
///
/// # Panics
///
/// Panics only if internal slice-to-array conversion fails, which cannot happen
/// after the length check ensures at least 40 bytes are available.
pub fn parse_ipv6_full(data: &[u8]) -> Result<Ipv6Packet, NetError> {
    if data.len() < 40 {
        return Err(NetError::BufferTooShort {
            needed: 40,
            got: data.len(),
        });
    }
    let version = (data[0] >> 4) & 0xF;
    if version != 6 {
        return Err(NetError::InvalidIpv6Packet);
    }
    let traffic_class = ((data[0] & 0x0F) << 4) | (data[1] >> 4);
    let flow_label = u32::from_be_bytes([0, data[1] & 0x0F, data[2], data[3]]);
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let next_hdr = data[6];
    let hop_limit = data[7];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());

    let body_end = (40 + payload_len).min(data.len());
    let body = &data[40..body_end];
    let (ext_headers, body, next_hdr) = parse_ipv6_ext_chain(body, next_hdr);

    Ok(Ipv6Packet {
        src,
        dst,
        traffic_class,
        flow_label,
        hop_limit,
        ext_headers,
        final_protocol: next_hdr,
        payload: body.to_vec(),
    })
}

fn parse_ipv6_ext_chain(mut body: &[u8], mut next_hdr: u8) -> (Vec<Ipv6ExtHeader>, &[u8], u8) {
    let mut ext_headers = Vec::new();
    loop {
        match next_hdr {
            ipv6_next_hdr::HOP_BY_HOP | ipv6_next_hdr::DEST_OPTIONS => {
                if body.len() < 2 {
                    break;
                }
                let nh = body[0];
                let hel = body[1] as usize;
                let total = (hel + 1) * 8;
                if body.len() < total {
                    break;
                }
                let opts_data = &body[2..total];
                let options = parse_ipv6_ext_options(opts_data);
                let hdr = Ipv6HopByHopHeader {
                    next_header: nh,
                    hdr_ext_len: body[1],
                    options,
                };
                if next_hdr == ipv6_next_hdr::HOP_BY_HOP {
                    ext_headers.push(Ipv6ExtHeader::HopByHop(hdr));
                } else {
                    ext_headers.push(Ipv6ExtHeader::DestOptions(hdr));
                }
                next_hdr = nh;
                body = &body[total..];
            }
            ipv6_next_hdr::ROUTING => {
                if body.len() < 4 {
                    break;
                }
                let nh = body[0];
                let hel = body[1] as usize;
                let total = (hel + 1) * 8;
                if body.len() < total {
                    break;
                }
                let hdr = Ipv6RoutingHeader {
                    next_header: nh,
                    hdr_ext_len: body[1],
                    routing_type: body[2],
                    segments_left: body[3],
                    data: body[4..total].to_vec(),
                };
                ext_headers.push(Ipv6ExtHeader::Routing(hdr));
                next_hdr = nh;
                body = &body[total..];
            }
            ipv6_next_hdr::FRAGMENT => {
                if body.len() < 8 {
                    break;
                }
                let nh = body[0];
                let fo_raw = u16::from_be_bytes([body[2], body[3]]);
                let fragment_offset = fo_raw >> 3;
                let more_fragments = (fo_raw & 0x1) != 0;
                let identification = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                ext_headers.push(Ipv6ExtHeader::Fragment(Ipv6FragmentHeader {
                    next_header: nh,
                    fragment_offset,
                    more_fragments,
                    identification,
                }));
                next_hdr = nh;
                body = &body[8..];
            }
            ipv6_next_hdr::AH => {
                if let Some((hdr, skip)) = parse_ipv6_ah_header(body) {
                    next_hdr = hdr.next_header;
                    ext_headers.push(Ipv6ExtHeader::Auth(hdr));
                    body = &body[skip..];
                } else {
                    break;
                }
            }
            ipv6_next_hdr::ESP => {
                if body.len() < 4 {
                    break;
                }
                let spi = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                ext_headers.push(Ipv6ExtHeader::Esp { spi });
                // ESP is opaque; can't continue parsing
                break;
            }
            _ => break,
        }
    }
    (ext_headers, body, next_hdr)
}

fn parse_ipv6_ah_header(body: &[u8]) -> Option<(Ipv6AuthHeader, usize)> {
    if body.len() < 12 {
        return None;
    }
    let nh = body[0];
    let payload_len_ah = body[1];
    let spi = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let sequence_number = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
    let ah_len = ((payload_len_ah as usize) + 2) * 4;
    let icv_start = 12;
    let icv_end = ah_len.max(icv_start);
    let icv = if icv_end <= body.len() {
        body[icv_start..icv_end].to_vec()
    } else {
        Vec::new()
    };
    let hdr = Ipv6AuthHeader {
        next_header: nh,
        payload_len: payload_len_ah,
        spi,
        sequence_number,
        icv,
    };
    let skip = ah_len.min(body.len());
    Some((hdr, skip))
}

fn parse_ipv6_ext_options(data: &[u8]) -> Vec<Ipv6ExtOption> {
    let mut opts = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let t = data[pos];
        if t == 0 {
            // Pad1
            opts.push(Ipv6ExtOption {
                opt_type: 0,
                data: Vec::new(),
            });
            pos += 1;
            continue;
        }
        if pos + 1 >= data.len() {
            break;
        }
        let l = data[pos + 1] as usize;
        if pos + 2 + l > data.len() {
            break;
        }
        opts.push(Ipv6ExtOption {
            opt_type: t,
            data: data[pos + 2..pos + 2 + l].to_vec(),
        });
        pos += 2 + l;
    }
    opts
}

// ────────────────────────────────────────────────────────────────────────────
// TCP options
// ────────────────────────────────────────────────────────────────────────────

/// A parsed TCP option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpOption {
    /// End of option list (kind 0).
    Eol,
    /// No operation (kind 1).
    Nop,
    /// Maximum Segment Size (kind 2).
    Mss(u16),
    /// Window Scale (kind 3).
    WindowScale(u8),
    /// SACK Permitted (kind 4).
    SackPermitted,
    /// SACK (kind 5): list of (`left_edge`, `right_edge`) pairs.
    Sack(Vec<(u32, u32)>),
    /// Timestamps (kind 8): `TSval`, `TSecr`.
    Timestamps { tsval: u32, tsecr: u32 },
    /// Unknown option.
    Unknown { kind: u8, data: Vec<u8> },
}

impl fmt::Display for TcpOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eol => write!(f, "EOL"),
            Self::Nop => write!(f, "NOP"),
            Self::Mss(v) => write!(f, "MSS={v}"),
            Self::WindowScale(s) => write!(f, "WScale={s}"),
            Self::SackPermitted => write!(f, "SACK-Permitted"),
            Self::Sack(blocks) => write!(f, "SACK({} blocks)", blocks.len()),
            Self::Timestamps { tsval, tsecr } => {
                write!(f, "TS(val={tsval},ecr={tsecr})")
            }
            Self::Unknown { kind, .. } => write!(f, "Unknown(kind={kind})"),
        }
    }
}

/// Parse TCP options from the options field of a TCP header.
///
/// `options_data` is the bytes between offset 20 and the data offset
/// (i.e. `data[20..data_offset]`).
///
/// # Errors
///
/// Returns [`NetError::MalformedPacket`] if an option length field is
/// inconsistent with the buffer.
pub fn parse_tcp_options(options_data: &[u8]) -> Result<Vec<TcpOption>, NetError> {
    let mut opts = Vec::new();
    let mut pos = 0usize;
    while pos < options_data.len() {
        let kind = options_data[pos];
        match kind {
            0 => {
                opts.push(TcpOption::Eol);
                break;
            }
            1 => {
                opts.push(TcpOption::Nop);
                pos += 1;
            }
            _ => {
                if pos + 1 >= options_data.len() {
                    return Err(NetError::MalformedPacket(
                        "TCP option truncated before length".to_string(),
                    ));
                }
                let opt_len = options_data[pos + 1] as usize;
                if opt_len < 2 {
                    return Err(NetError::MalformedPacket(format!(
                        "TCP option kind={kind} len={opt_len} < 2"
                    )));
                }
                if pos + opt_len > options_data.len() {
                    return Err(NetError::MalformedPacket(format!(
                        "TCP option kind={kind} extends past buffer"
                    )));
                }
                let data = &options_data[pos + 2..pos + opt_len];
                let opt = match kind {
                    2 => {
                        if data.len() < 2 {
                            return Err(NetError::MalformedPacket(
                                "MSS option too short".to_string(),
                            ));
                        }
                        TcpOption::Mss(u16::from_be_bytes([data[0], data[1]]))
                    }
                    3 => {
                        if data.is_empty() {
                            return Err(NetError::MalformedPacket(
                                "WScale option too short".to_string(),
                            ));
                        }
                        TcpOption::WindowScale(data[0])
                    }
                    4 => TcpOption::SackPermitted,
                    5 => {
                        let mut blocks = Vec::new();
                        let mut i = 0usize;
                        while i + 8 <= data.len() {
                            let l = u32::from_be_bytes([
                                data[i],
                                data[i + 1],
                                data[i + 2],
                                data[i + 3],
                            ]);
                            let r = u32::from_be_bytes([
                                data[i + 4],
                                data[i + 5],
                                data[i + 6],
                                data[i + 7],
                            ]);
                            blocks.push((l, r));
                            i += 8;
                        }
                        TcpOption::Sack(blocks)
                    }
                    8 => {
                        if data.len() < 8 {
                            return Err(NetError::MalformedPacket(
                                "Timestamps option too short".to_string(),
                            ));
                        }
                        let tsval = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                        let tsecr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                        TcpOption::Timestamps { tsval, tsecr }
                    }
                    _ => TcpOption::Unknown {
                        kind,
                        data: data.to_vec(),
                    },
                };
                opts.push(opt);
                pos += opt_len;
            }
        }
    }
    Ok(opts)
}

/// A TCP segment with parsed options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSegmentFull {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: Vec<TcpOption>,
    pub payload: Vec<u8>,
}

/// Parse a TCP segment with options.
///
/// # Errors
///
/// Returns [`NetError::InvalidTcpSegment`] for structural errors,
/// [`NetError::BufferTooShort`] if the buffer is too short.
pub fn parse_tcp_full(data: &[u8]) -> Result<TcpSegmentFull, NetError> {
    if data.len() < 20 {
        return Err(NetError::BufferTooShort {
            needed: 20,
            got: data.len(),
        });
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset_raw = (data[12] >> 4) as usize;
    let data_offset_bytes = data_offset_raw * 4;
    if data_offset_bytes < 20 || data.len() < data_offset_bytes {
        return Err(NetError::InvalidTcpSegment);
    }
    let flags = TcpFlags::from_bits_truncate(data[13]);
    let window = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);
    let options_data = &data[20..data_offset_bytes];
    let options = parse_tcp_options(options_data)?;
    let payload = data[data_offset_bytes..].to_vec();
    Ok(TcpSegmentFull {
        src_port,
        dst_port,
        seq,
        ack,
        data_offset: u8::try_from(data_offset_raw).unwrap_or(u8::MAX),
        flags,
        window,
        checksum,
        urgent_ptr,
        options,
        payload,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// IGMP
// ────────────────────────────────────────────────────────────────────────────

/// IGMP message type codes.
pub mod igmp_types {
    pub const MEMBERSHIP_QUERY: u8 = 0x11;
    pub const V1_MEMBERSHIP_REPORT: u8 = 0x12;
    pub const V2_MEMBERSHIP_REPORT: u8 = 0x16;
    pub const V2_LEAVE_GROUP: u8 = 0x17;
    pub const V3_MEMBERSHIP_REPORT: u8 = 0x22;
}

/// A parsed IGMP message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgmpMessage {
    pub msg_type: u8,
    pub max_resp_time: u8,
    pub checksum: u16,
    pub group_address: std::net::Ipv4Addr,
}

impl fmt::Display for IgmpMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IGMP type=0x{:02x} group={} chksum=0x{:04x}",
            self.msg_type, self.group_address, self.checksum
        )
    }
}

/// Parse an IGMP message from raw bytes.
///
/// # Errors
///
/// Returns [`NetError::BufferTooShort`] if fewer than 8 bytes are provided.
pub fn parse_igmp(data: &[u8]) -> Result<IgmpMessage, NetError> {
    if data.len() < 8 {
        return Err(NetError::BufferTooShort {
            needed: 8,
            got: data.len(),
        });
    }
    let msg_type = data[0];
    let max_resp_time = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);
    let group_address = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
    Ok(IgmpMessage {
        msg_type,
        max_resp_time,
        checksum,
        group_address,
    })
}

/// Return a human-readable name for an IGMP message type.
#[must_use]
pub const fn igmp_type_name(msg_type: u8) -> &'static str {
    match msg_type {
        igmp_types::MEMBERSHIP_QUERY => "Membership Query",
        igmp_types::V1_MEMBERSHIP_REPORT => "V1 Membership Report",
        igmp_types::V2_MEMBERSHIP_REPORT => "V2 Membership Report",
        igmp_types::V2_LEAVE_GROUP => "V2 Leave Group",
        igmp_types::V3_MEMBERSHIP_REPORT => "V3 Membership Report",
        _ => "Unknown",
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ICMPv6
// ────────────────────────────────────────────────────────────────────────────

/// `ICMPv6` message type codes (RFC 4443 and NDP RFC 4861).
pub mod icmpv6_types {
    pub const DEST_UNREACHABLE: u8 = 1;
    pub const PACKET_TOO_BIG: u8 = 2;
    pub const TIME_EXCEEDED: u8 = 3;
    pub const PARAM_PROBLEM: u8 = 4;
    pub const ECHO_REQUEST: u8 = 128;
    pub const ECHO_REPLY: u8 = 129;
    pub const ROUTER_SOLICIT: u8 = 133;
    pub const ROUTER_ADVERT: u8 = 134;
    pub const NEIGHBOR_SOLICIT: u8 = 135;
    pub const NEIGHBOR_ADVERT: u8 = 136;
    pub const REDIRECT: u8 = 137;
    pub const MLD_QUERY: u8 = 130;
    pub const MLD_REPORT: u8 = 131;
    pub const MLD_DONE: u8 = 132;
}

/// `ICMPv6` destination-unreachable codes.
pub mod icmpv6_dest_unreachable {
    pub const NO_ROUTE: u8 = 0;
    pub const ADMIN_PROHIBITED: u8 = 1;
    pub const BEYOND_SCOPE: u8 = 2;
    pub const ADDRESS_UNREACHABLE: u8 = 3;
    pub const PORT_UNREACHABLE: u8 = 4;
    pub const FAILED_POLICY: u8 = 5;
    pub const REJECT_ROUTE: u8 = 6;
}

/// A parsed `ICMPv6` packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Icmpv6Packet {
    pub icmpv6_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub body: Vec<u8>,
}

impl fmt::Display for Icmpv6Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ICMPv6 type={} code={} chksum=0x{:04x} len={}",
            icmpv6_type_name(self.icmpv6_type),
            self.code,
            self.checksum,
            self.body.len()
        )
    }
}

/// Parse an `ICMPv6` packet from raw bytes.
///
/// # Errors
///
/// Returns [`NetError::BufferTooShort`] if fewer than 4 bytes are provided.
pub fn parse_icmpv6(data: &[u8]) -> Result<Icmpv6Packet, NetError> {
    if data.len() < 4 {
        return Err(NetError::BufferTooShort {
            needed: 4,
            got: data.len(),
        });
    }
    let icmpv6_type = data[0];
    let code = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);
    let body = data[4..].to_vec();
    Ok(Icmpv6Packet {
        icmpv6_type,
        code,
        checksum,
        body,
    })
}

/// Return a human-readable name for an `ICMPv6` type code.
#[must_use]
pub const fn icmpv6_type_name(t: u8) -> &'static str {
    match t {
        icmpv6_types::DEST_UNREACHABLE => "Destination Unreachable",
        icmpv6_types::PACKET_TOO_BIG => "Packet Too Big",
        icmpv6_types::TIME_EXCEEDED => "Time Exceeded",
        icmpv6_types::PARAM_PROBLEM => "Parameter Problem",
        icmpv6_types::ECHO_REQUEST => "Echo Request",
        icmpv6_types::ECHO_REPLY => "Echo Reply",
        icmpv6_types::ROUTER_SOLICIT => "Router Solicitation",
        icmpv6_types::ROUTER_ADVERT => "Router Advertisement",
        icmpv6_types::NEIGHBOR_SOLICIT => "Neighbor Solicitation",
        icmpv6_types::NEIGHBOR_ADVERT => "Neighbor Advertisement",
        icmpv6_types::REDIRECT => "Redirect",
        icmpv6_types::MLD_QUERY => "MLD Query",
        icmpv6_types::MLD_REPORT => "MLD Report",
        icmpv6_types::MLD_DONE => "MLD Done",
        _ => "Unknown",
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Extended DNS record types
// ────────────────────────────────────────────────────────────────────────────

/// Extended DNS record type constants beyond the basic set.
pub mod dns_types_ext {
    pub const CAA: u16 = 257;
    pub const HTTPS: u16 = 65;
    pub const SVCB: u16 = 64;
    pub const DNSKEY: u16 = 48;
    pub const DS: u16 = 43;
    pub const RRSIG: u16 = 46;
    pub const NSEC: u16 = 47;
    pub const NSEC3: u16 = 50;
    pub const TLSA: u16 = 52;
    pub const NAPTR: u16 = 35;
    pub const CERT: u16 = 37;
    pub const SSHFP: u16 = 44;
    pub const LOC: u16 = 29;
    pub const HINFO: u16 = 13;
    pub const OPT: u16 = 41; // EDNS0
    pub const TKEY: u16 = 249;
    pub const TSIG: u16 = 250;
    pub const IXFR: u16 = 251;
    pub const AXFR: u16 = 252;
    pub const MAILB: u16 = 253;
    pub const MAILA: u16 = 254;
}

/// Extended DNS record type name mapping (supplements `dns_type_name`).
#[must_use]
pub fn dns_type_name_full(rtype: u16) -> &'static str {
    // First check the basic types
    let basic = dns_type_name(rtype);
    if basic != "Unknown" {
        return basic;
    }
    match rtype {
        dns_types_ext::CAA => "CAA",
        dns_types_ext::HTTPS => "HTTPS",
        dns_types_ext::SVCB => "SVCB",
        dns_types_ext::DNSKEY => "DNSKEY",
        dns_types_ext::DS => "DS",
        dns_types_ext::RRSIG => "RRSIG",
        dns_types_ext::NSEC => "NSEC",
        dns_types_ext::NSEC3 => "NSEC3",
        dns_types_ext::TLSA => "TLSA",
        dns_types_ext::NAPTR => "NAPTR",
        dns_types_ext::CERT => "CERT",
        dns_types_ext::SSHFP => "SSHFP",
        dns_types_ext::LOC => "LOC",
        dns_types_ext::HINFO => "HINFO",
        dns_types_ext::OPT => "OPT",
        dns_types_ext::TKEY => "TKEY",
        dns_types_ext::TSIG => "TSIG",
        _ => "Unknown",
    }
}

// ────────────────────────────────────────────────────────────────────────────
// EDNS0 (RFC 6891)
// ────────────────────────────────────────────────────────────────────────────

/// An EDNS0 option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edns0Option {
    pub option_code: u16,
    pub data: Vec<u8>,
}

/// An EDNS0 OPT pseudo-RR (appears in the additional section of a DNS message).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edns0Record {
    /// UDP payload size the sender can handle.
    pub udp_payload_size: u16,
    /// Extended RCODE (upper 8 bits).
    pub extended_rcode: u8,
    /// EDNS version (should be 0).
    pub version: u8,
    /// DNSSEC OK bit.
    pub dnssec_ok: bool,
    /// List of EDNS0 options.
    pub options: Vec<Edns0Option>,
}

/// Parse an EDNS0 OPT RR from its RDATA bytes plus the TTL field.
///
/// `ttl_field` is the 4-byte TTL field of the OPT RR (reinterpreted as
/// extended RCODE + version + flags).  `rdata` is the RDATA section.
///
/// # Errors
///
/// Returns [`NetError::MalformedPacket`] if options are malformed.
pub fn parse_edns0(ttl_field: u32, rdata: &[u8]) -> Result<Edns0Record, NetError> {
    let extended_rcode = ((ttl_field >> 24) & 0xFF) as u8;
    let version = ((ttl_field >> 16) & 0xFF) as u8;
    let flags = (ttl_field & 0xFFFF) as u16;
    let dnssec_ok = (flags & 0x8000) != 0;

    let mut options = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= rdata.len() {
        let option_code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let option_len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + option_len > rdata.len() {
            return Err(NetError::MalformedPacket(format!(
                "EDNS0 option code={option_code} extends past RDATA"
            )));
        }
        options.push(Edns0Option {
            option_code,
            data: rdata[pos..pos + option_len].to_vec(),
        });
        pos += option_len;
    }

    Ok(Edns0Record {
        udp_payload_size: 0, // caller sets from class field of OPT RR
        extended_rcode,
        version,
        dnssec_ok,
        options,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// TLS extensions (ClientHello / ServerHello)
// ────────────────────────────────────────────────────────────────────────────

/// Well-known TLS extension type codes.
pub mod tls_ext_types {
    pub const SNI: u16 = 0;
    pub const MAX_FRAGMENT_LENGTH: u16 = 1;
    pub const STATUS_REQUEST: u16 = 5;
    pub const SUPPORTED_GROUPS: u16 = 10;
    pub const EC_POINT_FORMATS: u16 = 11;
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    pub const USE_SRTP: u16 = 14;
    pub const HEARTBEAT: u16 = 15;
    pub const ALPN: u16 = 16;
    pub const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 18;
    pub const CLIENT_CERTIFICATE_TYPE: u16 = 19;
    pub const SERVER_CERTIFICATE_TYPE: u16 = 20;
    pub const PADDING: u16 = 21;
    pub const ENCRYPT_THEN_MAC: u16 = 22;
    pub const EXTENDED_MASTER_SECRET: u16 = 23;
    pub const SESSION_TICKET: u16 = 35;
    pub const PRE_SHARED_KEY: u16 = 41;
    pub const EARLY_DATA: u16 = 42;
    pub const SUPPORTED_VERSIONS: u16 = 43;
    pub const COOKIE: u16 = 44;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    pub const CERTIFICATE_AUTHORITIES: u16 = 47;
    pub const OID_FILTERS: u16 = 48;
    pub const POST_HANDSHAKE_AUTH: u16 = 49;
    pub const SIGNATURE_ALGORITHMS_CERT: u16 = 50;
    pub const KEY_SHARE: u16 = 51;
    pub const RENEGOTIATION_INFO: u16 = 0xFF01;
}

/// Return a human-readable name for a TLS extension type.
#[must_use]
pub const fn tls_ext_name(ext_type: u16) -> &'static str {
    match ext_type {
        tls_ext_types::SNI => "server_name",
        tls_ext_types::MAX_FRAGMENT_LENGTH => "max_fragment_length",
        tls_ext_types::STATUS_REQUEST => "status_request",
        tls_ext_types::SUPPORTED_GROUPS => "supported_groups",
        tls_ext_types::EC_POINT_FORMATS => "ec_point_formats",
        tls_ext_types::SIGNATURE_ALGORITHMS => "signature_algorithms",
        tls_ext_types::USE_SRTP => "use_srtp",
        tls_ext_types::HEARTBEAT => "heartbeat",
        tls_ext_types::ALPN => "application_layer_protocol_negotiation",
        tls_ext_types::SIGNED_CERTIFICATE_TIMESTAMP => "signed_certificate_timestamp",
        tls_ext_types::PADDING => "padding",
        tls_ext_types::ENCRYPT_THEN_MAC => "encrypt_then_mac",
        tls_ext_types::EXTENDED_MASTER_SECRET => "extended_master_secret",
        tls_ext_types::SESSION_TICKET => "session_ticket",
        tls_ext_types::PRE_SHARED_KEY => "pre_shared_key",
        tls_ext_types::EARLY_DATA => "early_data",
        tls_ext_types::SUPPORTED_VERSIONS => "supported_versions",
        tls_ext_types::COOKIE => "cookie",
        tls_ext_types::PSK_KEY_EXCHANGE_MODES => "psk_key_exchange_modes",
        tls_ext_types::KEY_SHARE => "key_share",
        tls_ext_types::RENEGOTIATION_INFO => "renegotiation_info",
        _ => "unknown",
    }
}

/// A single TLS extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsExtension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

impl TlsExtension {
    /// Return the human-readable name for this extension type.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        tls_ext_name(self.ext_type)
    }
}

/// Parsed content of a TLS `ClientHello` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsClientHello {
    /// Legacy version (typically 0x0303).
    pub legacy_version: u16,
    /// 32-byte client random.
    pub random: [u8; 32],
    /// Session ID bytes.
    pub session_id: Vec<u8>,
    /// List of cipher suite codes.
    pub cipher_suites: Vec<u16>,
    /// Compression methods.
    pub compression_methods: Vec<u8>,
    /// Parsed extensions.
    pub extensions: Vec<TlsExtension>,
    /// SNI extracted from extensions (convenience field).
    pub sni: Option<String>,
    /// ALPN protocols from extensions.
    pub alpn: Vec<String>,
    /// Supported groups (named curves).
    pub supported_groups: Vec<u16>,
}

/// Parse a TLS `ClientHello` handshake message body.
///
/// `data` should be the body bytes of the `ClientHello` (after the 4-byte
/// handshake header type+length).
///
/// # Errors
///
/// Returns [`NetError::BufferTooShort`] or [`NetError::MalformedPacket`]
/// for structural problems.
pub fn parse_tls_client_hello(data: &[u8]) -> Result<TlsClientHello, NetError> {
    if data.len() < 34 {
        return Err(NetError::BufferTooShort {
            needed: 34,
            got: data.len(),
        });
    }
    let legacy_version = u16::from_be_bytes([data[0], data[1]]);
    let mut random = [0u8; 32];
    random.copy_from_slice(&data[2..34]);
    let mut pos = 34usize;

    // Session ID
    if pos >= data.len() {
        return Err(NetError::MalformedPacket(
            "ClientHello truncated at session_id_len".to_string(),
        ));
    }
    let sid_len = data[pos] as usize;
    pos += 1;
    if pos + sid_len > data.len() {
        return Err(NetError::BufferTooShort {
            needed: pos + sid_len,
            got: data.len(),
        });
    }
    let session_id = data[pos..pos + sid_len].to_vec();
    pos += sid_len;

    // Cipher suites
    if pos + 2 > data.len() {
        return Err(NetError::MalformedPacket(
            "ClientHello truncated at cipher_suites_len".to_string(),
        ));
    }
    let cipher_suite_bytes = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_suite_bytes > data.len() {
        return Err(NetError::BufferTooShort {
            needed: pos + cipher_suite_bytes,
            got: data.len(),
        });
    }
    let cipher_suites: Vec<u16> = data[pos..pos + cipher_suite_bytes]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    pos += cipher_suite_bytes;

    // Compression methods
    if pos >= data.len() {
        return Err(NetError::MalformedPacket(
            "ClientHello truncated at comp_methods_len".to_string(),
        ));
    }
    let compression_bytes = data[pos] as usize;
    pos += 1;
    if pos + compression_bytes > data.len() {
        return Err(NetError::BufferTooShort {
            needed: pos + compression_bytes,
            got: data.len(),
        });
    }
    let compression_methods = data[pos..pos + compression_bytes].to_vec();
    pos += compression_bytes;

    let parsed = parse_tls_extensions(data, pos);
    let TlsParsedExtensions {
        extensions,
        sni,
        alpn,
        supported_groups,
    } = parsed;

    Ok(TlsClientHello {
        legacy_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions,
        sni,
        alpn,
        supported_groups,
    })
}

struct TlsParsedExtensions {
    extensions: Vec<TlsExtension>,
    sni: Option<String>,
    alpn: Vec<String>,
    supported_groups: Vec<u16>,
}

fn parse_tls_extensions(data: &[u8], mut pos: usize) -> TlsParsedExtensions {
    let mut extensions = Vec::new();
    let mut sni = None;
    let mut alpn = Vec::new();
    let mut supported_groups = Vec::new();

    if pos + 2 <= data.len() {
        let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total).min(data.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > ext_end {
                break;
            }
            let ext_data = data[pos..pos + ext_len].to_vec();

            match ext_type {
                tls_ext_types::SNI => {
                    sni = decode_tls_sni_ext(&ext_data);
                }
                tls_ext_types::ALPN => {
                    alpn = decode_tls_alpn_ext(&ext_data);
                }
                tls_ext_types::SUPPORTED_GROUPS => {
                    supported_groups = decode_tls_supported_groups(&ext_data);
                }
                _ => {}
            }

            extensions.push(TlsExtension {
                ext_type,
                data: ext_data,
            });
            pos += ext_len;
        }
    }
    TlsParsedExtensions {
        extensions,
        sni,
        alpn,
        supported_groups,
    }
}

fn decode_tls_sni_ext(data: &[u8]) -> Option<String> {
    // ServerNameList: list_len(2) + name_type(1) + name_len(2) + name
    if data.len() < 5 {
        return None;
    }
    let _list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let name_type = data[2];
    if name_type != 0 {
        return None; // only host_name supported
    }
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if 5 + name_len > data.len() {
        return None;
    }
    std::str::from_utf8(&data[5..5 + name_len])
        .ok()
        .map(std::string::ToString::to_string)
}

fn decode_tls_alpn_ext(data: &[u8]) -> Vec<String> {
    let mut protocols = Vec::new();
    if data.len() < 2 {
        return protocols;
    }
    let total = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2usize;
    let end = (2 + total).min(data.len());
    while pos < end {
        if pos >= data.len() {
            break;
        }
        let len = data[pos] as usize;
        pos += 1;
        if pos + len > data.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&data[pos..pos + len]) {
            protocols.push(s.to_string());
        }
        pos += len;
    }
    protocols
}

fn decode_tls_supported_groups(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = (2 + list_len).min(data.len());
    data[2..end]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// Parsed content of a TLS `ServerHello` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsServerHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<TlsExtension>,
    /// Negotiated ALPN protocol (if present).
    pub alpn: Option<String>,
    /// Selected TLS version from `supported_versions` extension.
    pub negotiated_version: Option<u16>,
}

/// Parse a TLS `ServerHello` handshake message body.
///
/// # Errors
///
/// Returns [`NetError::BufferTooShort`] or [`NetError::MalformedPacket`]
/// for structural problems.
pub fn parse_tls_server_hello(data: &[u8]) -> Result<TlsServerHello, NetError> {
    if data.len() < 35 {
        return Err(NetError::BufferTooShort {
            needed: 35,
            got: data.len(),
        });
    }
    let legacy_version = u16::from_be_bytes([data[0], data[1]]);
    let mut random = [0u8; 32];
    random.copy_from_slice(&data[2..34]);
    let mut pos = 34usize;

    let sid_len = data[pos] as usize;
    pos += 1;
    if pos + sid_len + 3 > data.len() {
        return Err(NetError::BufferTooShort {
            needed: pos + sid_len + 3,
            got: data.len(),
        });
    }
    let session_id = data[pos..pos + sid_len].to_vec();
    pos += sid_len;

    let cipher_suite = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let compression_method = data[pos + 2];
    pos += 3;

    let mut extensions = Vec::new();
    let mut alpn = None;
    let mut negotiated_version = None;

    if pos + 2 <= data.len() {
        let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total).min(data.len());
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > ext_end {
                break;
            }
            let ext_data = data[pos..pos + ext_len].to_vec();
            match ext_type {
                tls_ext_types::ALPN => {
                    if ext_data.len() >= 3 {
                        let proto_len = ext_data[2] as usize;
                        if 3 + proto_len <= ext_data.len() {
                            alpn = std::str::from_utf8(&ext_data[3..3 + proto_len])
                                .ok()
                                .map(std::string::ToString::to_string);
                        }
                    }
                }
                tls_ext_types::SUPPORTED_VERSIONS
                    if ext_data.len() >= 2 => {
                        negotiated_version = Some(u16::from_be_bytes([ext_data[0], ext_data[1]]));
                    }
                _ => {}
            }
            extensions.push(TlsExtension {
                ext_type,
                data: ext_data,
            });
            pos += ext_len;
        }
    }

    Ok(TlsServerHello {
        legacy_version,
        random,
        session_id,
        cipher_suite,
        compression_method,
        extensions,
        alpn,
        negotiated_version,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// 802.1Q VLAN tag
// ────────────────────────────────────────────────────────────────────────────

/// An 802.1Q VLAN tag extracted from an Ethernet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlanTag {
    /// Priority Code Point (3 bits).
    pub pcp: u8,
    /// Drop Eligible Indicator (1 bit).
    pub dei: bool,
    /// VLAN ID (12 bits).
    pub vid: u16,
    /// Inner `EtherType`.
    pub ethertype: u16,
}

impl fmt::Display for VlanTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VLAN pcp={} dei={} vid={} ethertype=0x{:04x}",
            self.pcp, self.dei, self.vid, self.ethertype
        )
    }
}

/// An Ethernet II frame with optional 802.1Q VLAN tag(s).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetFrameExt {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    /// Outer VLAN tag (present if the frame had a 0x8100 tag).
    pub outer_vlan: Option<VlanTag>,
    /// Inner VLAN tag (present for Q-in-Q frames with 0x8100 + 0x8100).
    pub inner_vlan: Option<VlanTag>,
    /// Final `EtherType` after stripping all VLAN tags.
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

/// Parse an Ethernet frame with full 802.1Q/Q-in-Q VLAN tag support.
///
/// # Errors
///
/// Returns [`NetError::BufferTooShort`] if the frame is too short.
pub fn parse_ethernet_ext(data: &[u8]) -> Result<EthernetFrameExt, NetError> {
    if data.len() < 14 {
        return Err(NetError::BufferTooShort {
            needed: 14,
            got: data.len(),
        });
    }
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&data[0..6]);
    src_mac.copy_from_slice(&data[6..12]);
    let mut etype = u16::from_be_bytes([data[12], data[13]]);
    let mut pos = 14usize;
    let mut outer_vlan = None;
    let mut inner_vlan = None;

    if etype == 0x8100 || etype == 0x88A8 {
        // Outer VLAN tag
        if pos + 4 > data.len() {
            return Err(NetError::BufferTooShort {
                needed: pos + 4,
                got: data.len(),
            });
        }
        let tci = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let inner_etype = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        outer_vlan = Some(VlanTag {
            pcp: ((tci >> 13) & 0x7) as u8,
            dei: ((tci >> 12) & 0x1) != 0,
            vid: tci & 0x0FFF,
            ethertype: inner_etype,
        });
        pos += 4;
        etype = inner_etype;

        // Inner VLAN tag (Q-in-Q)
        if etype == 0x8100 {
            if pos + 4 > data.len() {
                return Err(NetError::BufferTooShort {
                    needed: pos + 4,
                    got: data.len(),
                });
            }
            let tci2 = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let inner_etype2 = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            inner_vlan = Some(VlanTag {
                pcp: ((tci2 >> 13) & 0x7) as u8,
                dei: ((tci2 >> 12) & 0x1) != 0,
                vid: tci2 & 0x0FFF,
                ethertype: inner_etype2,
            });
            pos += 4;
            etype = inner_etype2;
        }
    }

    let payload = data[pos..].to_vec();
    Ok(EthernetFrameExt {
        src_mac,
        dst_mac,
        outer_vlan,
        inner_vlan,
        ethertype: etype,
        payload,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// ICMP all types and codes
// ────────────────────────────────────────────────────────────────────────────

/// ICMP destination-unreachable codes.
pub mod icmp_dest_unreachable {
    pub const NET_UNREACHABLE: u8 = 0;
    pub const HOST_UNREACHABLE: u8 = 1;
    pub const PROTOCOL_UNREACHABLE: u8 = 2;
    pub const PORT_UNREACHABLE: u8 = 3;
    pub const FRAGMENTATION_NEEDED: u8 = 4;
    pub const SOURCE_ROUTE_FAILED: u8 = 5;
    pub const DEST_NET_UNKNOWN: u8 = 6;
    pub const DEST_HOST_UNKNOWN: u8 = 7;
    pub const SOURCE_HOST_ISOLATED: u8 = 8;
    pub const NET_ADMIN_PROHIBITED: u8 = 9;
    pub const HOST_ADMIN_PROHIBITED: u8 = 10;
    pub const NET_UNREACHABLE_TOS: u8 = 11;
    pub const HOST_UNREACHABLE_TOS: u8 = 12;
    pub const COMM_ADMIN_PROHIBITED: u8 = 13;
    pub const HOST_PRECEDENCE_VIOLATION: u8 = 14;
    pub const PRECEDENCE_CUTOFF: u8 = 15;
}

/// ICMP redirect codes.
pub mod icmp_redirect {
    pub const FOR_NETWORK: u8 = 0;
    pub const FOR_HOST: u8 = 1;
    pub const FOR_TOS_AND_NETWORK: u8 = 2;
    pub const FOR_TOS_AND_HOST: u8 = 3;
}

/// ICMP time-exceeded codes.
pub mod icmp_time_exceeded {
    pub const TTL_EXCEEDED: u8 = 0;
    pub const FRAGMENT_REASSEMBLY: u8 = 1;
}

/// Return a human-readable string for an ICMP type+code pair.
#[must_use]
pub const fn icmp_code_name(icmp_type: u8, code: u8) -> &'static str {
    match icmp_type {
        3 => match code {
            icmp_dest_unreachable::NET_UNREACHABLE => "Net Unreachable",
            icmp_dest_unreachable::HOST_UNREACHABLE => "Host Unreachable",
            icmp_dest_unreachable::PROTOCOL_UNREACHABLE => "Protocol Unreachable",
            icmp_dest_unreachable::PORT_UNREACHABLE => "Port Unreachable",
            icmp_dest_unreachable::FRAGMENTATION_NEEDED => "Fragmentation Needed",
            icmp_dest_unreachable::SOURCE_ROUTE_FAILED => "Source Route Failed",
            icmp_dest_unreachable::COMM_ADMIN_PROHIBITED => "Comm Admin Prohibited",
            _ => "Destination Unreachable",
        },
        5 => match code {
            icmp_redirect::FOR_NETWORK => "Redirect for Network",
            icmp_redirect::FOR_HOST => "Redirect for Host",
            icmp_redirect::FOR_TOS_AND_NETWORK => "Redirect for TOS+Network",
            icmp_redirect::FOR_TOS_AND_HOST => "Redirect for TOS+Host",
            _ => "Redirect",
        },
        11 => match code {
            icmp_time_exceeded::TTL_EXCEEDED => "TTL Exceeded in Transit",
            icmp_time_exceeded::FRAGMENT_REASSEMBLY => "Fragment Reassembly Time Exceeded",
            _ => "Time Exceeded",
        },
        _ => icmp_type_name(icmp_type),
    }
}

/// Extended ICMP packet with ID and sequence number (for echo request/reply).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpEcho {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence: u16,
    pub data: Vec<u8>,
}

impl fmt::Display for IcmpEcho {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ICMP Echo type={} id={} seq={} len={}",
            self.icmp_type,
            self.identifier,
            self.sequence,
            self.data.len()
        )
    }
}

/// Parse an ICMP Echo Request or Reply from raw bytes.
///
/// # Errors
///
/// Returns [`NetError::BufferTooShort`] if fewer than 8 bytes are provided.
pub fn parse_icmp_echo(data: &[u8]) -> Result<IcmpEcho, NetError> {
    if data.len() < 8 {
        return Err(NetError::BufferTooShort {
            needed: 8,
            got: data.len(),
        });
    }
    let icmp_type = data[0];
    let code = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);
    let identifier = u16::from_be_bytes([data[4], data[5]]);
    let sequence = u16::from_be_bytes([data[6], data[7]]);
    let echo_data = data[8..].to_vec();
    Ok(IcmpEcho {
        icmp_type,
        code,
        checksum,
        identifier,
        sequence,
        data: echo_data,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// 5-tuple flow key (protocol-aware)
// ────────────────────────────────────────────────────────────────────────────

/// A 5-tuple flow key including IP protocol number.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey5 {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey5 {
    /// Create a new 5-tuple flow key.
    #[must_use]
    pub const fn new(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
        }
    }

    /// Return the canonical (bidirectional) form of this key.
    #[must_use]
    pub fn canonical(&self) -> Self {
        let a = (self.src_ip, self.src_port);
        let b = (self.dst_ip, self.dst_port);
        if a <= b {
            self.clone()
        } else {
            Self {
                src_ip: b.0,
                src_port: b.1,
                dst_ip: a.0,
                dst_port: a.1,
                protocol: self.protocol,
            }
        }
    }
}

impl fmt::Display for FlowKey5 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} proto={}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Segment queue for TCP reassembly (enhanced)
// ────────────────────────────────────────────────────────────────────────────

/// A gap in the TCP stream (missing data between two received segments).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpGap {
    pub start: u32,
    pub end: u32,
}

impl TcpGap {
    /// Length of this gap in bytes.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.end.wrapping_sub(self.start)
    }

    /// Returns `true` if the gap has zero length.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Extended TCP stream with gap tracking and FIN/RST handling.
#[derive(Debug)]
pub struct TcpStreamExt {
    /// Next expected sequence number.
    pub next_seq: u32,
    /// Reassembled in-order bytes.
    pub data: Vec<u8>,
    /// Gaps in the stream (segments we know are missing).
    pub gaps: Vec<TcpGap>,
    /// Whether FIN has been observed.
    pub fin_seen: bool,
    /// Whether RST has been observed.
    pub rst_seen: bool,
    /// Total number of bytes received (including retransmits).
    pub total_received: u64,
    /// Out-of-order segment buffer.
    ooo_buf: Vec<(u32, Vec<u8>)>,
}

impl TcpStreamExt {
    /// Create a new stream starting at `isn_plus_one`.
    #[must_use]
    pub const fn new(isn_plus_one: u32) -> Self {
        Self {
            next_seq: isn_plus_one,
            data: Vec::new(),
            gaps: Vec::new(),
            fin_seen: false,
            rst_seen: false,
            total_received: 0,
            ooo_buf: Vec::new(),
        }
    }

    /// Feed a segment into the stream. Returns bytes added in-order.
    pub fn feed_segment(&mut self, seq: u32, payload: &[u8], flags: TcpFlags) -> usize {
        if flags.contains(TcpFlags::RST) {
            self.rst_seen = true;
            return 0;
        }
        if flags.contains(TcpFlags::FIN) {
            self.fin_seen = true;
        }
        if payload.is_empty() {
            return 0;
        }
        self.total_received += payload.len() as u64;
        let seg_end = seq.wrapping_add(u32::try_from(payload.len()).unwrap_or(u32::MAX));

        // Fully below next_seq → retransmit, discard
        if Self::seq_before_or_eq(seg_end, self.next_seq) {
            return 0;
        }

        if seq == self.next_seq {
            // In-order delivery
            self.data.extend_from_slice(payload);
            self.next_seq = seg_end;
            return payload.len() + self.drain_ooo();
        }

        if Self::seq_before(seq, self.next_seq) {
            // Partial overlap from behind
            let overlap = self.next_seq.wrapping_sub(seq) as usize;
            if overlap < payload.len() {
                let new_data = &payload[overlap..];
                self.data.extend_from_slice(new_data);
                self.next_seq = self
                    .next_seq
                    .wrapping_add(u32::try_from(new_data.len()).unwrap_or(u32::MAX));
                let added = new_data.len();
                return added + self.drain_ooo();
            }
            return 0;
        }

        // Out-of-order: record a gap
        let gap = TcpGap {
            start: self.next_seq,
            end: seq,
        };
        if !gap.is_empty() {
            // Only push if this gap isn't already tracked
            if !self.gaps.iter().any(|g| g.start == gap.start) {
                self.gaps.push(gap);
            }
        }

        self.ooo_buf.push((seq, payload.to_vec()));
        self.ooo_buf.sort_by_key(|(s, _)| *s);
        0
    }

    fn drain_ooo(&mut self) -> usize {
        let mut added = 0usize;
        loop {
            let pos = self.ooo_buf.iter().position(|(s, d)| {
                let end = s.wrapping_add(u32::try_from(d.len()).unwrap_or(u32::MAX));
                *s <= self.next_seq && Self::seq_before_or_eq(self.next_seq, end)
            });
            match pos {
                None => break,
                Some(i) => {
                    let (seg_seq, seg_data) = self.ooo_buf.remove(i);
                    let seen = self.next_seq.wrapping_sub(seg_seq) as usize;
                    if seen >= seg_data.len() {
                        continue;
                    }
                    let trimmed = &seg_data[seen..];
                    self.data.extend_from_slice(trimmed);
                    self.next_seq = self
                        .next_seq
                        .wrapping_add(u32::try_from(trimmed.len()).unwrap_or(u32::MAX));
                    added += trimmed.len();

                    // Remove gap that was just filled
                    let ns = self.next_seq;
                    self.gaps.retain(|g| !Self::seq_before_or_eq(g.end, ns));
                }
            }
        }
        added
    }

    /// Returns true if `a` is strictly before `b` in sequence space.
    const fn seq_before(a: u32, b: u32) -> bool {
        a.wrapping_sub(b) > 0x8000_0000
    }

    /// Returns true if `a` is before or equal to `b` in sequence space.
    const fn seq_before_or_eq(a: u32, b: u32) -> bool {
        a == b || Self::seq_before(a, b)
    }

    /// Number of buffered out-of-order bytes.
    #[must_use]
    pub fn ooo_bytes(&self) -> usize {
        self.ooo_buf.iter().map(|(_, d)| d.len()).sum()
    }

    /// Returns true if the stream has observed a FIN.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.fin_seen || self.rst_seen
    }
}

// ────────────────────────────────────────────────────────────────────────────
// NetworkSessionTracker
// ────────────────────────────────────────────────────────────────────────────

/// TCP connection-state machine (simplified RFC 793).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpSessionState {
    /// SYN seen, waiting for SYN-ACK.
    SynSent,
    /// Handshake complete; data transfer in progress.
    Established,
    /// At least one FIN has been observed.
    Closing,
    /// RST seen or both FINs exchanged.
    Closed,
}

/// 5-tuple key that uniquely identifies one flow direction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    /// IP protocol number (6 = TCP, 17 = UDP, …).
    pub proto: u8,
}

impl SessionKey {
    /// Build a key for TCP.
    #[must_use]
    pub const fn tcp(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto: 6,
        }
    }

    /// Build a key for UDP.
    #[must_use]
    pub const fn udp(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto: 17,
        }
    }

    /// Return the canonical (lower-IP-first) version so that both directions
    /// of a bidirectional flow map to the same key.
    #[must_use]
    pub fn canonical(&self) -> Self {
        let (s_ip, s_port, d_ip, d_port) =
            if (self.src_ip, self.src_port) < (self.dst_ip, self.dst_port) {
                (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
            } else {
                (self.dst_ip, self.dst_port, self.src_ip, self.src_port)
            };
        Self {
            src_ip: s_ip,
            src_port: s_port,
            dst_ip: d_ip,
            dst_port: d_port,
            proto: self.proto,
        }
    }
}

/// Internal mutable state for one tracked session.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionState {
    tcp_state: TcpSessionState,
    bytes_in: u64,
    bytes_out: u64,
    pkt_count: u64,
    /// Nanosecond timestamp of the first packet.
    first_seen_ns: u64,
    /// Nanosecond timestamp of the most recent packet.
    last_seen_ns: u64,
    /// Whether at least one payload byte was observed.
    has_payload: bool,
}

/// Read-only summary returned by [`NetworkSessionTracker::sessions_with_payload`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub key: SessionKey,
    pub tcp_state: TcpSessionState,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub pkt_count: u64,
    /// Duration in nanoseconds (`last_seen - first_seen`).
    pub duration_ns: u64,
}

/// Source/destination address+port tuple used when ingesting packets.
#[derive(Debug, Clone, Copy)]
pub struct SessionEndpoints {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

/// Parameters for [`NetworkSessionTracker::ingest_tcp_segment`].
#[derive(Debug, Clone, Copy)]
pub struct TcpSegmentIngest {
    pub endpoints: SessionEndpoints,
    pub tcp_flags: u8,
    pub payload_len: u64,
    pub timestamp_ns: u64,
    pub is_inbound: u8,
}

/// Parameters for [`NetworkSessionTracker::ingest_udp_datagram`].
#[derive(Debug, Clone, Copy)]
pub struct UdpDatagramIngest {
    pub endpoints: SessionEndpoints,
    pub payload_len: u64,
    pub timestamp_ns: u64,
    pub is_inbound: u8,
}

/// Groups packets into five-tuple sessions and maintains per-session statistics.
///
/// ```no_run
/// use rustre_net::{NetworkSessionTracker, SessionEndpoints, SessionKey};
/// use std::net::{IpAddr, Ipv4Addr};
///
/// let mut tracker = NetworkSessionTracker::new();
/// let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
/// let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
/// let endpoints = SessionEndpoints { src_ip, src_port: 54321, dst_ip, dst_port: 80 };
/// tracker.ingest_tcp(endpoints, 0x02 /* SYN */, 60, 0, 0);
/// ```
pub struct NetworkSessionTracker {
    sessions: HashMap<SessionKey, SessionState>,
}

impl NetworkSessionTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Feed a TCP segment into the tracker.
    ///
    /// * `tcp_flags` — raw TCP flags byte.
    /// * `payload_len` — application-layer payload bytes (0 for header-only segments).
    /// * `timestamp_ns` — nanoseconds since epoch (0 is acceptable during tests).
    /// * `is_inbound` — `true` if the packet travels toward `dst_ip:dst_port` (i.e. normal
    ///   ingress); `false` for the reverse path.
    pub fn ingest_tcp(
        &mut self,
        endpoints: SessionEndpoints,
        tcp_flags: u8,
        payload_len: u64,
        timestamp_ns: u64,
        is_inbound: u8,
    ) {
        self.ingest_tcp_segment(TcpSegmentIngest {
            endpoints,
            tcp_flags,
            payload_len,
            timestamp_ns,
            is_inbound,
        });
    }

    /// Feed a TCP segment into the tracker (struct form to avoid long argument lists).
    pub fn ingest_tcp_segment(&mut self, ingest: TcpSegmentIngest) {
        let TcpSegmentIngest {
            endpoints,
            tcp_flags,
            payload_len,
            timestamp_ns,
            is_inbound,
        } = ingest;
        let SessionEndpoints {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        } = endpoints;
        let key = SessionKey::tcp(src_ip, src_port, dst_ip, dst_port).canonical();
        let syn = tcp_flags & 0x02 != 0;
        let ack = tcp_flags & 0x10 != 0;
        let fin = tcp_flags & 0x01 != 0;
        let rst = tcp_flags & 0x04 != 0;

        let entry = self.sessions.entry(key).or_insert_with(|| SessionState {
            tcp_state: TcpSessionState::SynSent,
            bytes_in: 0,
            bytes_out: 0,
            pkt_count: 0,
            first_seen_ns: timestamp_ns,
            last_seen_ns: timestamp_ns,
            has_payload: false,
        });

        entry.pkt_count += 1;
        entry.last_seen_ns = entry.last_seen_ns.max(timestamp_ns);
        if payload_len > 0 {
            entry.has_payload = true;
        }
        if is_inbound != 0 {
            entry.bytes_in += payload_len;
        } else {
            entry.bytes_out += payload_len;
        }

        // State machine transitions.
        entry.tcp_state = match entry.tcp_state {
            TcpSessionState::SynSent if syn && ack => TcpSessionState::Established,
            TcpSessionState::SynSent if ack => TcpSessionState::Established,
            TcpSessionState::Established if fin => TcpSessionState::Closing,
            TcpSessionState::Established if rst => TcpSessionState::Closed,
            TcpSessionState::Closing if fin || rst => TcpSessionState::Closed,
            other => other,
        };
        // Absorb: a bare RST always closes.
        if rst {
            entry.tcp_state = TcpSessionState::Closed;
        }
        // First packet is a plain SYN — keep SynSent; if it already has ACK handled above.
        let _ = syn;
    }

    /// Feed a UDP datagram into the tracker.
    pub fn ingest_udp(
        &mut self,
        endpoints: SessionEndpoints,
        payload_len: u64,
        timestamp_ns: u64,
        is_inbound: u8,
    ) {
        self.ingest_udp_datagram(UdpDatagramIngest {
            endpoints,
            payload_len,
            timestamp_ns,
            is_inbound,
        });
    }

    /// Feed a UDP datagram into the tracker (struct form to avoid long argument lists).
    pub fn ingest_udp_datagram(&mut self, ingest: UdpDatagramIngest) {
        let UdpDatagramIngest {
            endpoints,
            payload_len,
            timestamp_ns,
            is_inbound,
        } = ingest;
        let SessionEndpoints {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        } = endpoints;
        let key = SessionKey::udp(src_ip, src_port, dst_ip, dst_port).canonical();
        let entry = self.sessions.entry(key).or_insert_with(|| SessionState {
            tcp_state: TcpSessionState::Established, // UDP is always "established"
            bytes_in: 0,
            bytes_out: 0,
            pkt_count: 0,
            first_seen_ns: timestamp_ns,
            last_seen_ns: timestamp_ns,
            has_payload: false,
        });
        entry.pkt_count += 1;
        entry.last_seen_ns = entry.last_seen_ns.max(timestamp_ns);
        if payload_len > 0 {
            entry.has_payload = true;
        }
        if is_inbound != 0 {
            entry.bytes_in += payload_len;
        } else {
            entry.bytes_out += payload_len;
        }
    }

    /// Return summaries for all sessions that carried at least one payload byte.
    #[must_use]
    pub fn sessions_with_payload(&self) -> Vec<SessionSummary> {
        self.sessions
            .iter()
            .filter(|(_, s)| s.has_payload)
            .map(|(key, s)| SessionSummary {
                key: key.clone(),
                tcp_state: s.tcp_state,
                bytes_in: s.bytes_in,
                bytes_out: s.bytes_out,
                pkt_count: s.pkt_count,
                duration_ns: s.last_seen_ns.saturating_sub(s.first_seen_ns),
            })
            .collect()
    }

    /// Return summaries for all tracked sessions regardless of payload.
    #[must_use]
    pub fn all_sessions(&self) -> Vec<SessionSummary> {
        self.sessions
            .iter()
            .map(|(key, s)| SessionSummary {
                key: key.clone(),
                tcp_state: s.tcp_state,
                bytes_in: s.bytes_in,
                bytes_out: s.bytes_out,
                pkt_count: s.pkt_count,
                duration_ns: s.last_seen_ns.saturating_sub(s.first_seen_ns),
            })
            .collect()
    }

    /// Total number of tracked sessions (with and without payload).
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for NetworkSessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// PortKnockingDetector
// ────────────────────────────────────────────────────────────────────────────

/// Watches a stream of `(src_ip, dst_port)` observations and fires a callback
/// when the configured knock sequence is seen **from the same source IP** in order.
///
/// # Example
/// ```
/// use rustre_net::PortKnockingDetector;
/// use std::net::{IpAddr, Ipv4Addr};
/// use std::sync::{Arc, Mutex};
///
/// let fired = Arc::new(Mutex::new(false));
/// let fired_clone = fired.clone();
/// let mut detector = PortKnockingDetector::new(
///     vec![1234, 5678, 9012],
///     move |ip| { *fired_clone.lock().unwrap() = true; },
/// );
/// let src = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
/// detector.observe(src, 1234);
/// detector.observe(src, 5678);
/// detector.observe(src, 9012);
/// assert!(*fired.lock().unwrap());
/// ```
pub struct PortKnockingDetector<F: Fn(IpAddr)> {
    /// The required knock sequence.
    sequence: Vec<u16>,
    /// Per-source progress index: how many consecutive matching ports have been seen.
    progress: HashMap<IpAddr, usize>,
    callback: F,
}

impl<F: Fn(IpAddr)> PortKnockingDetector<F> {
    /// Create a detector for `sequence` that calls `callback` with the source IP
    /// when the full sequence is matched.
    ///
    /// # Panics
    /// Panics if `sequence` is empty.
    #[must_use]
    pub fn new(sequence: Vec<u16>, callback: F) -> Self {
        assert!(!sequence.is_empty(), "knock sequence must not be empty");
        Self {
            sequence,
            progress: HashMap::new(),
            callback,
        }
    }

    /// Feed one port-access observation.
    ///
    /// If this observation completes the knock sequence for `src`, the callback
    /// fires and the progress for `src` is reset.
    pub fn observe(&mut self, src: IpAddr, dst_port: u16) {
        let idx = self.progress.entry(src).or_insert(0);
        if self.sequence[*idx] == dst_port {
            *idx += 1;
            if *idx == self.sequence.len() {
                // Full sequence matched.
                *idx = 0;
                (self.callback)(src);
            }
        } else {
            // Wrong port — restart from 0, but check if this port starts a new sequence.
            *idx = usize::from(self.sequence[0] == dst_port);
        }
    }

    /// Reset progress tracking for all sources.
    pub fn reset_all(&mut self) {
        self.progress.clear();
    }

    /// Reset progress for a specific source IP.
    pub fn reset_source(&mut self, src: IpAddr) {
        self.progress.remove(&src);
    }

    /// Current progress (number of correctly knocked ports so far) for `src`.
    #[must_use]
    pub fn progress_for(&self, src: IpAddr) -> usize {
        self.progress.get(&src).copied().unwrap_or(0)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DnsQueryExtractor
// ────────────────────────────────────────────────────────────────────────────

/// A single DNS question extracted from a DNS message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuery {
    /// Fully qualified domain name (without trailing dot).
    pub name: String,
    /// QTYPE field (e.g. 1 = A, 28 = AAAA, 15 = MX, 255 = ANY).
    pub qtype: u16,
    /// QCLASS field (e.g. 1 = IN).
    pub qclass: u16,
}

/// Parses raw DNS wire-format bytes and extracts the question section.
///
/// Handles standard label encoding and pointer compression (RFC 1035 §4.1.4).
/// Returns [`NetError::InvalidDnsPacket`] for malformed input.
pub struct DnsQueryExtractor;

impl DnsQueryExtractor {
    /// Parse `buf` as a DNS message and return all questions it contains.
    ///
    /// # Errors
    /// Returns [`NetError::InvalidDnsPacket`] if the buffer is too short,
    /// the header is malformed, or any label / pointer is invalid.
    pub fn extract(buf: &[u8]) -> Result<Vec<DnsQuery>, NetError> {
        // DNS header is 12 bytes.
        if buf.len() < 12 {
            return Err(NetError::InvalidDnsPacket);
        }

        let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let mut offset = 12usize;
        let mut queries = Vec::with_capacity(qdcount);

        for _ in 0..qdcount {
            let (name, new_offset) = Self::parse_name(buf, offset)?;
            offset = new_offset;

            if offset + 4 > buf.len() {
                return Err(NetError::InvalidDnsPacket);
            }
            let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            offset += 4;

            queries.push(DnsQuery {
                name,
                qtype,
                qclass,
            });
        }

        Ok(queries)
    }

    /// Parse a DNS domain name starting at `offset` in `buf`.
    ///
    /// Returns `(name, next_offset)` where `next_offset` is the position
    /// immediately after the name's terminating zero (or pointer) in the
    /// *original* message (not in the followed pointer chain).
    fn parse_name(buf: &[u8], start: usize) -> Result<(String, usize), NetError> {
        const MAX_HOPS: usize = 128;
        let mut labels: Vec<String> = Vec::new();
        let mut offset = start;
        // `jumped` tracks the offset to return after following a pointer.
        let mut return_offset: Option<usize> = None;
        // Guard against infinite pointer loops.
        let mut hops = 0usize;

        loop {
            if offset >= buf.len() {
                return Err(NetError::InvalidDnsPacket);
            }
            let byte = buf[offset];

            if byte == 0 {
                // Terminating zero label.
                if return_offset.is_none() {
                    return_offset = Some(offset + 1);
                }
                break;
            }

            // Check for pointer (top two bits set: 0xC0).
            if byte & 0xC0 == 0xC0 {
                if offset + 1 >= buf.len() {
                    return Err(NetError::InvalidDnsPacket);
                }
                let ptr = (((byte & 0x3F) as usize) << 8) | (buf[offset + 1] as usize);
                if return_offset.is_none() {
                    return_offset = Some(offset + 2);
                }
                offset = ptr;
                hops += 1;
                if hops > MAX_HOPS {
                    return Err(NetError::InvalidDnsPacket);
                }
                continue;
            }

            // Regular label: next `byte` octets are the label text.
            let len = byte as usize;
            offset += 1;
            if offset + len > buf.len() {
                return Err(NetError::InvalidDnsPacket);
            }
            let label = std::str::from_utf8(&buf[offset..offset + len])
                .map_err(|_| NetError::InvalidDnsPacket)?;
            labels.push(label.to_owned());
            offset += len;
        }

        let name = labels.join(".");
        Ok((name, return_offset.unwrap_or(offset + 1)))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Additional tests for new functionality
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // ── IPv4 options ──────────────────────────────────────────────────────

    #[test]
    fn parse_ipv4_options_eool() {
        let opts = parse_ipv4_options(&[0x00]).unwrap();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0], Ipv4Option::Eool);
    }

    #[test]
    fn parse_ipv4_options_nop() {
        let opts = parse_ipv4_options(&[0x01, 0x01, 0x01]).unwrap();
        assert_eq!(opts.len(), 3);
        assert!(matches!(opts[0], Ipv4Option::Nop));
    }

    #[test]
    fn parse_ipv4_options_router_alert() {
        // Type=148, Len=4, Value=0
        let data = [148u8, 4, 0, 0];
        let opts = parse_ipv4_options(&data).unwrap();
        assert_eq!(opts.len(), 1);
        assert!(matches!(opts[0], Ipv4Option::RouterAlert { value: 0 }));
    }

    #[test]
    fn parse_ipv4_options_record_route() {
        // RR: type=7, len=11, pointer=4, then 2 IPs (data[3..] = pointer byte + 2x4 bytes = 9 bytes, but len=11 means 9 opt bytes)
        // Actually: type(1) + len(1) + pointer(1) + routes = 3 + routes
        // opt_len=11 means the opt is 11 bytes total; data starts at pos+2, so data = options_data[2..11] = 9 bytes
        // routes = data[1..] (skipping pointer) = 8 bytes = 2 routes
        let mut data = vec![7u8, 11, 4]; // type, len, pointer
        data.extend_from_slice(&[1, 2, 3, 4]);
        data.extend_from_slice(&[5, 6, 7, 8]);
        data.extend_from_slice(&[0, 0, 0, 0]); // total len so far = 15, but opt_len=11, so we only have 9 bytes in `data` field
        // The parse reads options_data[2..11] = bytes at positions 2..11 from start of option
        // data slice = options_data[pos+2..pos+opt_len], so 9 bytes: [4, 1,2,3,4, 5,6,7,8]
        // pointer=4 (data[0]), routes = data[1..] chunks_exact(4) = [1,2,3,4] and [5,6,7,8] = 2 routes
        let opts = parse_ipv4_options(&data[..11]).unwrap();
        assert_eq!(opts.len(), 1);
        if let Ipv4Option::RecordRoute { pointer, routes } = &opts[0] {
            assert_eq!(*pointer, 4);
            assert_eq!(routes.len(), 2);
        } else {
            panic!("expected RecordRoute");
        }
    }

    #[test]
    fn parse_ipv4_options_unknown() {
        // Type=200, Len=4, 2 bytes data
        let data = [200u8, 4, 0xAA, 0xBB];
        let opts = parse_ipv4_options(&data).unwrap();
        assert_eq!(opts.len(), 1);
        if let Ipv4Option::Unknown {
            option_type,
            data: d,
        } = &opts[0]
        {
            assert_eq!(*option_type, 200);
            assert_eq!(d, &[0xAA, 0xBB]);
        } else {
            panic!("expected Unknown");
        }
    }

    // ── TCP options ───────────────────────────────────────────────────────

    #[test]
    fn parse_tcp_options_mss_and_nop() {
        // NOP, NOP, MSS=1460
        let data = [1u8, 1, 2, 4, 0x05, 0xB4];
        let opts = parse_tcp_options(&data).unwrap();
        assert!(opts.contains(&TcpOption::Nop));
        assert!(opts.contains(&TcpOption::Mss(1460)));
    }

    #[test]
    fn parse_tcp_options_window_scale() {
        let data = [3u8, 3, 7]; // kind=3, len=3, shift=7
        let opts = parse_tcp_options(&data).unwrap();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0], TcpOption::WindowScale(7));
    }

    #[test]
    fn parse_tcp_options_timestamps() {
        // kind=8, len=10, tsval, tsecr
        let mut data = vec![8u8, 10];
        data.extend_from_slice(&12345u32.to_be_bytes());
        data.extend_from_slice(&67890u32.to_be_bytes());
        let opts = parse_tcp_options(&data).unwrap();
        assert_eq!(opts.len(), 1);
        assert_eq!(
            opts[0],
            TcpOption::Timestamps {
                tsval: 12345,
                tsecr: 67890
            }
        );
    }

    #[test]
    fn parse_tcp_options_sack_permitted() {
        let data = [4u8, 2]; // kind=4, len=2, no data
        let opts = parse_tcp_options(&data).unwrap();
        assert_eq!(opts[0], TcpOption::SackPermitted);
    }

    #[test]
    fn parse_tcp_options_sack_blocks() {
        // kind=5, len=18, 2 SACK blocks
        let mut data = vec![5u8, 18];
        data.extend_from_slice(&100u32.to_be_bytes());
        data.extend_from_slice(&200u32.to_be_bytes());
        data.extend_from_slice(&300u32.to_be_bytes());
        data.extend_from_slice(&400u32.to_be_bytes());
        let opts = parse_tcp_options(&data).unwrap();
        if let TcpOption::Sack(blocks) = &opts[0] {
            assert_eq!(blocks.len(), 2);
            assert_eq!(blocks[0], (100, 200));
            assert_eq!(blocks[1], (300, 400));
        } else {
            panic!("expected SACK");
        }
    }

    #[test]
    fn parse_tcp_full_with_options() {
        // Build a TCP header with MSS option
        let mut hdr = vec![0u8; 24]; // 20 fixed + 4 option
        hdr[0] = 0x00;
        hdr[1] = 0x50; // src_port=80
        hdr[2] = 0x1F;
        hdr[3] = 0x40; // dst_port=8000
        hdr[12] = 0x60; // data_offset=6 (24 bytes)
        hdr[13] = 0x12; // SYN+ACK
        hdr[14] = 0xFF;
        hdr[15] = 0xFF; // window
        // MSS option at offset 20
        hdr[20] = 2;
        hdr[21] = 4;
        hdr[22] = 0x05;
        hdr[23] = 0xB4; // MSS=1460
        let seg = parse_tcp_full(&hdr).unwrap();
        assert_eq!(seg.src_port, 80);
        assert_eq!(seg.dst_port, 8000);
        assert!(seg.options.contains(&TcpOption::Mss(1460)));
    }

    // ── IGMP ──────────────────────────────────────────────────────────────

    #[test]
    fn parse_igmp_query() {
        let mut data = vec![0u8; 8];
        data[0] = igmp_types::MEMBERSHIP_QUERY;
        data[1] = 100; // max resp time
        data[4..8].copy_from_slice(&[224, 0, 0, 1]);
        let msg = parse_igmp(&data).unwrap();
        assert_eq!(msg.msg_type, igmp_types::MEMBERSHIP_QUERY);
        assert_eq!(msg.max_resp_time, 100);
        assert_eq!(msg.group_address, std::net::Ipv4Addr::new(224, 0, 0, 1));
    }

    #[test]
    fn igmp_type_names() {
        assert_eq!(
            igmp_type_name(igmp_types::MEMBERSHIP_QUERY),
            "Membership Query"
        );
        assert_eq!(igmp_type_name(igmp_types::V2_LEAVE_GROUP), "V2 Leave Group");
        assert_eq!(igmp_type_name(0xFF), "Unknown");
    }

    // ── ICMPv6 ───────────────────────────────────────────────────────────

    #[test]
    fn parse_icmpv6_echo_request() {
        let data = [128u8, 0, 0xFF, 0xFF, 0, 1, 0, 1, 0xDE, 0xAD];
        let pkt = parse_icmpv6(&data).unwrap();
        assert_eq!(pkt.icmpv6_type, icmpv6_types::ECHO_REQUEST);
        assert_eq!(pkt.code, 0);
        assert_eq!(pkt.body.len(), 6);
    }

    #[test]
    fn icmpv6_type_names() {
        assert_eq!(icmpv6_type_name(icmpv6_types::ECHO_REQUEST), "Echo Request");
        assert_eq!(
            icmpv6_type_name(icmpv6_types::NEIGHBOR_SOLICIT),
            "Neighbor Solicitation"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_types::ROUTER_ADVERT),
            "Router Advertisement"
        );
        assert_eq!(icmpv6_type_name(0xFF), "Unknown");
    }

    // ── DNS extended types ────────────────────────────────────────────────

    #[test]
    fn dns_type_name_full_basic() {
        assert_eq!(dns_type_name_full(1), "A");
        assert_eq!(dns_type_name_full(28), "AAAA");
        assert_eq!(dns_type_name_full(dns_types_ext::CAA), "CAA");
        assert_eq!(dns_type_name_full(dns_types_ext::HTTPS), "HTTPS");
        assert_eq!(dns_type_name_full(dns_types_ext::TLSA), "TLSA");
        assert_eq!(dns_type_name_full(0xFFFF), "Unknown");
    }

    // ── EDNS0 ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_edns0_dnssec_ok() {
        // TTL field: ext_rcode=0, version=0, flags=0x8000 (DO bit)
        let ttl = 0x0000_8000u32;
        let rdata: &[u8] = &[]; // no options
        let rec = parse_edns0(ttl, rdata).unwrap();
        assert!(rec.dnssec_ok);
        assert_eq!(rec.extended_rcode, 0);
        assert_eq!(rec.version, 0);
        assert!(rec.options.is_empty());
    }

    #[test]
    fn parse_edns0_with_option() {
        let ttl = 0u32;
        // One EDNS0 option: code=8 (LLQ), length=2, data=0x0001
        let rdata = [0x00u8, 8, 0x00, 2, 0x00, 0x01];
        let rec = parse_edns0(ttl, &rdata).unwrap();
        assert_eq!(rec.options.len(), 1);
        assert_eq!(rec.options[0].option_code, 8);
    }

    // ── TLS extensions ────────────────────────────────────────────────────

    #[test]
    fn tls_ext_names() {
        assert_eq!(tls_ext_name(tls_ext_types::SNI), "server_name");
        assert_eq!(
            tls_ext_name(tls_ext_types::ALPN),
            "application_layer_protocol_negotiation"
        );
        assert_eq!(tls_ext_name(tls_ext_types::KEY_SHARE), "key_share");
        assert_eq!(tls_ext_name(0x9999), "unknown");
    }

    #[test]
    fn tls_ext_display_name() {
        let ext = TlsExtension {
            ext_type: tls_ext_types::SNI,
            data: vec![],
        };
        assert_eq!(ext.name(), "server_name");
    }

    // ── 802.1Q VLAN ───────────────────────────────────────────────────────

    #[test]
    fn parse_ethernet_ext_no_vlan() {
        let mut frame = vec![0u8; 14];
        frame[6..12].copy_from_slice(&[0xCA, 0xFE, 0, 0, 0, 1]);
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame.extend_from_slice(&[0; 4]);
        let eth = parse_ethernet_ext(&frame).unwrap();
        assert!(eth.outer_vlan.is_none());
        assert_eq!(eth.ethertype, 0x0800);
    }

    #[test]
    fn parse_ethernet_ext_single_vlan() {
        let mut frame = vec![0u8; 14];
        frame[12] = 0x81;
        frame[13] = 0x00; // 802.1Q tag
        // TCI: PCP=5, DEI=0, VID=100
        let tci: u16 = (5 << 13) | 100;
        frame.extend_from_slice(&tci.to_be_bytes());
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // inner ethertype
        frame.extend_from_slice(&[0xDE, 0xAD]); // payload
        let eth = parse_ethernet_ext(&frame).unwrap();
        let vlan = eth.outer_vlan.unwrap();
        assert_eq!(vlan.vid, 100);
        assert_eq!(vlan.pcp, 5);
        assert!(!vlan.dei);
        assert_eq!(eth.ethertype, 0x0800);
    }

    // ── ICMP echo ─────────────────────────────────────────────────────────

    #[test]
    fn parse_icmp_echo_roundtrip() {
        let mut data = vec![8u8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        data.extend_from_slice(b"ping payload");
        let echo = parse_icmp_echo(&data).unwrap();
        assert_eq!(echo.icmp_type, 8);
        assert_eq!(echo.identifier, 0x1234);
        assert_eq!(echo.sequence, 1);
        assert_eq!(echo.data, b"ping payload");
    }

    #[test]
    fn icmp_code_names() {
        assert_eq!(icmp_code_name(3, 2), "Protocol Unreachable");
        assert_eq!(icmp_code_name(3, 4), "Fragmentation Needed");
        assert_eq!(icmp_code_name(11, 0), "TTL Exceeded in Transit");
        assert_eq!(icmp_code_name(5, 1), "Redirect for Host");
    }

    // ── FlowKey5 ─────────────────────────────────────────────────────────

    #[test]
    fn flow_key5_canonical() {
        let k1 = FlowKey5::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            1234,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            80,
            6,
        );
        let k2 = FlowKey5::new(
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            80,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            1234,
            6,
        );
        assert_eq!(k1.canonical(), k2.canonical());
    }

    #[test]
    fn flow_key5_display() {
        let k = FlowKey5::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            17,
        );
        assert!(k.to_string().contains("proto=17"));
    }

    // ── TcpStreamExt ─────────────────────────────────────────────────────

    #[test]
    fn tcp_stream_ext_in_order() {
        let mut s = TcpStreamExt::new(1);
        let added = s.feed_segment(1, b"hello ", TcpFlags::PSH);
        assert_eq!(added, 6);
        s.feed_segment(7, b"world", TcpFlags::PSH);
        assert_eq!(s.data, b"hello world");
    }

    #[test]
    fn tcp_stream_ext_out_of_order() {
        let mut s = TcpStreamExt::new(1);
        // "world" starts at seq=7 (after "hello "), feed it out of order
        s.feed_segment(7, b"world", TcpFlags::PSH);
        assert!(s.data.is_empty());
        assert_eq!(s.gaps.len(), 1);
        // Now deliver "hello " in-order, which fills next_seq from 1 to 7, then OOO drains
        s.feed_segment(1, b"hello ", TcpFlags::PSH);
        assert_eq!(s.data, b"hello world");
        assert!(s.gaps.is_empty());
    }

    #[test]
    fn tcp_stream_ext_rst() {
        let mut s = TcpStreamExt::new(1);
        s.feed_segment(1, b"data", TcpFlags::RST);
        assert!(s.rst_seen);
        assert!(s.data.is_empty());
    }

    #[test]
    fn tcp_stream_ext_fin() {
        let mut s = TcpStreamExt::new(1);
        s.feed_segment(1, b"last", TcpFlags::FIN | TcpFlags::PSH);
        assert!(s.fin_seen);
    }

    // ── IPv6 full parsing ─────────────────────────────────────────────────

    #[test]
    fn parse_ipv6_full_no_ext() {
        let mut buf = vec![0u8; 48]; // 40 hdr + 8 UDP payload
        buf[0] = 0x60; // version=6, tc=0, fl=0
        buf[4] = 0;
        buf[5] = 8; // payload_len=8
        buf[6] = 17; // next_hdr=UDP
        buf[7] = 64; // hop_limit
        // src = ::1
        buf[15] = 1;
        // dst = ::2
        buf[31] = 2;
        // UDP header
        buf[40] = 0;
        buf[41] = 53; // src_port=53
        buf[42] = 0x04;
        buf[43] = 0x00; // dst_port=1024
        let pkt = parse_ipv6_full(&buf).unwrap();
        assert_eq!(pkt.final_protocol, 17);
        assert_eq!(pkt.hop_limit, 64);
        assert!(pkt.ext_headers.is_empty());
    }

    #[test]
    fn parse_ipv6_full_wrong_version() {
        let mut buf = vec![0u8; 40];
        buf[0] = 0x40; // version=4
        assert!(parse_ipv6_full(&buf).is_err());
    }

    // ── TLS ClientHello parsing ───────────────────────────────────────────

    #[test]
    fn parse_tls_client_hello_minimal() {
        // Minimal ClientHello: version(2) + random(32) + sid_len(1) + cs_len(2)+2cs + cm_len(1)+1cm
        let mut data = vec![0x03u8, 0x03]; // legacy_version TLS 1.2
        data.extend_from_slice(&[0u8; 32]); // random
        data.push(0); // sid_len=0
        data.extend_from_slice(&4u16.to_be_bytes()); // cs_len=4
        data.extend_from_slice(&0x002Fu16.to_be_bytes()); // TLS_RSA_WITH_AES_128_CBC_SHA
        data.extend_from_slice(&0x00FFu16.to_be_bytes()); // empty renegotiation info SCSV
        data.push(1); // comp_methods_len=1
        data.push(0); // null compression
        // No extensions
        let ch = parse_tls_client_hello(&data).unwrap();
        assert_eq!(ch.legacy_version, 0x0303);
        assert_eq!(ch.cipher_suites.len(), 2);
        assert!(ch.sni.is_none());
    }

    // ── VlanTag display ───────────────────────────────────────────────────

    #[test]
    fn vlan_tag_display() {
        let vt = VlanTag {
            pcp: 0,
            dei: false,
            vid: 100,
            ethertype: 0x0800,
        };
        let s = vt.to_string();
        assert!(s.contains("vid=100"));
        assert!(s.contains("0x0800"));
    }

    // ── IPv6 next-header constants ────────────────────────────────────────

    #[test]
    fn ipv6_next_hdr_constants() {
        assert_eq!(ipv6_next_hdr::TCP, 6);
        assert_eq!(ipv6_next_hdr::UDP, 17);
        assert_eq!(ipv6_next_hdr::ICMPV6, 58);
        assert_eq!(ipv6_next_hdr::FRAGMENT, 44);
    }

    // ── TcpOption display ─────────────────────────────────────────────────

    #[test]
    fn tcp_option_display() {
        assert_eq!(TcpOption::Mss(1460).to_string(), "MSS=1460");
        assert_eq!(TcpOption::WindowScale(7).to_string(), "WScale=7");
        assert_eq!(TcpOption::SackPermitted.to_string(), "SACK-Permitted");
        assert_eq!(TcpOption::Nop.to_string(), "NOP");
        assert_eq!(TcpOption::Eol.to_string(), "EOL");
        assert_eq!(
            TcpOption::Timestamps {
                tsval: 100,
                tsecr: 50
            }
            .to_string(),
            "TS(val=100,ecr=50)"
        );
    }
}
