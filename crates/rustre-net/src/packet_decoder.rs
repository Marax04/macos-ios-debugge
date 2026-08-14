//! Multi-layer packet decoding: Ethernet → IP → TCP/UDP → payload.
//!
//! This module provides [`PacketDecoder`] that walks the protocol stack of a
//! raw captured buffer and produces a [`DecodedPacket`] containing every
//! parsed layer.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::NetError;

// ─────────────────────────────────────────────────────────────────────────────
// EtherFrame — Layer 2
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed Ethernet II frame header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherFrame {
    /// Destination MAC address.
    pub dst_mac: [u8; 6],
    /// Source MAC address.
    pub src_mac: [u8; 6],
    /// `EtherType` field (after 802.1Q VLAN stripping if present).
    pub ethertype: u16,
    /// VLAN tag (outer), if present.
    pub vlan: Option<u16>,
    /// Byte offset in the original buffer where the payload starts.
    pub payload_offset: usize,
}

impl EtherFrame {
    /// Format `mac` as a colon-separated hex string.
    #[must_use]
    pub fn mac_str(mac: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }

    /// Source MAC as a formatted string.
    #[must_use]
    pub fn src_str(&self) -> String {
        Self::mac_str(&self.src_mac)
    }

    /// Destination MAC as a formatted string.
    #[must_use]
    pub fn dst_str(&self) -> String {
        Self::mac_str(&self.dst_mac)
    }

    /// True if the destination MAC is the broadcast address.
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        self.dst_mac == [0xFF; 6]
    }

    /// True if the destination MAC is a multicast address.
    #[must_use]
    pub fn is_multicast(&self) -> bool {
        self.dst_mac[0] & 0x01 != 0 && !self.is_broadcast()
    }
}

impl fmt::Display for EtherFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ethernet {} → {} etype=0x{:04x}",
            self.src_str(),
            self.dst_str(),
            self.ethertype
        )
    }
}

/// Parse an Ethernet II frame header from `data`.
///
/// # Errors
/// Returns [`NetError::BufferTooShort`] when `data` is fewer than 14 bytes.
pub fn parse_ether_frame(data: &[u8]) -> Result<EtherFrame, NetError> {
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
    let raw_etype = u16::from_be_bytes([data[12], data[13]]);

    // Handle 802.1Q VLAN tag (0x8100).
    let (ethertype, vlan, payload_offset) = if raw_etype == 0x8100 {
        if data.len() < 18 {
            return Err(NetError::BufferTooShort {
                needed: 18,
                got: data.len(),
            });
        }
        let tci = u16::from_be_bytes([data[14], data[15]]);
        let inner = u16::from_be_bytes([data[16], data[17]]);
        (inner, Some(tci), 18usize)
    } else {
        (raw_etype, None, 14usize)
    };

    Ok(EtherFrame {
        dst_mac,
        src_mac,
        ethertype,
        vlan,
        payload_offset,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// IpHeader — Layer 3
// ─────────────────────────────────────────────────────────────────────────────

/// IP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpVersion {
    V4,
    V6,
}

impl fmt::Display for IpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 => write!(f, "IPv4"),
            Self::V6 => write!(f, "IPv6"),
        }
    }
}

/// Parsed IP (v4 or v6) header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpHeader {
    pub version: IpVersion,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// IP protocol number (6 = TCP, 17 = UDP, etc.).
    pub protocol: u8,
    /// Hop limit / TTL.
    pub ttl: u8,
    /// Total packet length in bytes as reported by the IP header.
    pub total_len: u16,
    /// IP header length in bytes.
    pub header_len: usize,
    /// DSCP/ECN traffic class byte.
    pub traffic_class: u8,
    /// IPv4 identification field (0 for IPv6).
    pub id: u16,
    /// IPv4 fragment flags (0 for IPv6).
    pub flags: u8,
    /// IPv4 fragment offset (0 for IPv6).
    pub frag_offset: u16,
}

impl IpHeader {
    /// True if this IPv4 packet is a fragment (not the first fragment or
    /// more-fragments bit is set).
    #[must_use]
    pub const fn is_fragment(&self) -> bool {
        self.frag_offset != 0 || (self.flags & 0x20) != 0
    }
}

impl fmt::Display for IpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} → {} proto={} ttl={}",
            self.version, self.src, self.dst, self.protocol, self.ttl
        )
    }
}

/// Parse an IPv4 header from `data` (no Ethernet framing).
///
/// # Errors
/// Returns [`NetError::BufferTooShort`] or [`NetError::InvalidIpv4Packet`].
pub fn parse_ipv4_header(data: &[u8]) -> Result<IpHeader, NetError> {
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
    let traffic_class = data[1]; // DSCP + ECN
    let total_len = u16::from_be_bytes([data[2], data[3]]);
    let id = u16::from_be_bytes([data[4], data[5]]);
    let flags = (data[6] >> 5) & 0x07;
    let frag_offset =
        u16::from_be_bytes([data[6] & 0x1F, data[7]]);
    let ttl = data[8];
    let protocol = data[9];
    let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
    Ok(IpHeader {
        version: IpVersion::V4,
        src,
        dst,
        protocol,
        ttl,
        total_len,
        header_len: ihl,
        traffic_class,
        id,
        flags,
        frag_offset,
    })
}

/// Parse an IPv6 header from `data`.
///
/// # Errors
/// Returns [`NetError::BufferTooShort`] or [`NetError::InvalidIpv6Packet`].
pub fn parse_ipv6_header(data: &[u8]) -> Result<IpHeader, NetError> {
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
    let traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
    let payload_len = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];
    let src_bytes: [u8; 16] = data[8..24].try_into().map_err(|_| NetError::InvalidIpv6Packet)?;
    let dst_bytes: [u8; 16] = data[24..40].try_into().map_err(|_| NetError::InvalidIpv6Packet)?;
    let src = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst = IpAddr::V6(Ipv6Addr::from(dst_bytes));
    Ok(IpHeader {
        version: IpVersion::V6,
        src,
        dst,
        protocol: next_header,
        ttl: hop_limit,
        total_len: payload_len,
        header_len: 40,
        traffic_class,
        id: 0,
        flags: 0,
        frag_offset: 0,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// TcpHeader — Layer 4 TCP
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed TCP segment header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    /// Data offset (header length) in bytes.
    pub header_len: usize,
    /// Raw flags byte.
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    /// Parsed TCP options (raw bytes).
    pub options: Vec<u8>,
}

impl TcpHeader {
    pub const FLAG_FIN: u8 = 0x01;
    pub const FLAG_SYN: u8 = 0x02;
    pub const FLAG_RST: u8 = 0x04;
    pub const FLAG_PSH: u8 = 0x08;
    pub const FLAG_ACK: u8 = 0x10;
    pub const FLAG_URG: u8 = 0x20;

    #[must_use] pub const fn is_syn(&self) -> bool { self.flags & Self::FLAG_SYN != 0 }
    #[must_use] pub const fn is_fin(&self) -> bool { self.flags & Self::FLAG_FIN != 0 }
    #[must_use] pub const fn is_rst(&self) -> bool { self.flags & Self::FLAG_RST != 0 }
    #[must_use] pub const fn is_ack(&self) -> bool { self.flags & Self::FLAG_ACK != 0 }
    #[must_use] pub const fn is_psh(&self) -> bool { self.flags & Self::FLAG_PSH != 0 }

    /// Format flags as a human-readable string.
    #[must_use]
    pub fn flags_str(&self) -> String {
        let mut parts = Vec::new();
        if self.is_syn() { parts.push("SYN"); }
        if self.is_ack() { parts.push("ACK"); }
        if self.is_fin() { parts.push("FIN"); }
        if self.is_rst() { parts.push("RST"); }
        if self.is_psh() { parts.push("PSH"); }
        if parts.is_empty() { "<none>".to_string() } else { parts.join("|") }
    }
}

impl fmt::Display for TcpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP {}:{} flags=[{}] seq={} ack={}",
            self.src_port, self.dst_port, self.flags_str(), self.seq, self.ack
        )
    }
}

/// Parse a TCP header from `data` (transport layer onwards).
///
/// # Errors
/// Returns [`NetError::BufferTooShort`] or [`NetError::InvalidTcpSegment`].
pub fn parse_tcp_header(data: &[u8]) -> Result<TcpHeader, NetError> {
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
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);
    let options = if data_offset > 20 {
        data[20..data_offset].to_vec()
    } else {
        Vec::new()
    };
    Ok(TcpHeader {
        src_port,
        dst_port,
        seq,
        ack,
        header_len: data_offset,
        flags,
        window,
        checksum,
        urgent_ptr,
        options,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// UdpHeader — Layer 4 UDP
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed UDP datagram header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    /// Length field from the UDP header (header + payload).
    pub length: u16,
    pub checksum: u16,
}

impl fmt::Display for UdpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UDP {}:{} len={}", self.src_port, self.dst_port, self.length)
    }
}

/// Parse a UDP header from `data`.
///
/// # Errors
/// Returns [`NetError::BufferTooShort`] when fewer than 8 bytes are available.
pub fn parse_udp_header(data: &[u8]) -> Result<UdpHeader, NetError> {
    if data.len() < 8 {
        return Err(NetError::BufferTooShort {
            needed: 8,
            got: data.len(),
        });
    }
    Ok(UdpHeader {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        length: u16::from_be_bytes([data[4], data[5]]),
        checksum: u16::from_be_bytes([data[6], data[7]]),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Transport layer result
// ─────────────────────────────────────────────────────────────────────────────

/// The transport-layer (L4) component of a decoded packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportLayer {
    Tcp {
        header: TcpHeader,
        payload: Vec<u8>,
    },
    Udp {
        header: UdpHeader,
        payload: Vec<u8>,
    },
    Icmp {
        icmp_type: u8,
        code: u8,
        checksum: u16,
        payload: Vec<u8>,
    },
    Raw {
        protocol: u8,
        payload: Vec<u8>,
    },
}

impl TransportLayer {
    /// Source port (TCP/UDP only).
    #[must_use]
    pub const fn src_port(&self) -> Option<u16> {
        match self {
            Self::Tcp { header, .. } => Some(header.src_port),
            Self::Udp { header, .. } => Some(header.src_port),
            _ => None,
        }
    }

    /// Destination port (TCP/UDP only).
    #[must_use]
    pub const fn dst_port(&self) -> Option<u16> {
        match self {
            Self::Tcp { header, .. } => Some(header.dst_port),
            Self::Udp { header, .. } => Some(header.dst_port),
            _ => None,
        }
    }

    /// Payload bytes.
    #[must_use]
    pub const fn payload(&self) -> &[u8] {
        match self {
            Self::Tcp { payload, .. }
            | Self::Udp { payload, .. }
            | Self::Icmp { payload, .. }
            | Self::Raw { payload, .. } => payload.as_slice(),
        }
    }

    /// Protocol label.
    #[must_use]
    pub const fn protocol_name(&self) -> &'static str {
        match self {
            Self::Tcp { .. } => "TCP",
            Self::Udp { .. } => "UDP",
            Self::Icmp { .. } => "ICMP",
            Self::Raw { .. } => "RAW",
        }
    }
}

impl fmt::Display for TransportLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp { header, payload } => {
                write!(f, "{} payload={} bytes", header, payload.len())
            }
            Self::Udp { header, payload } => {
                write!(f, "{} payload={} bytes", header, payload.len())
            }
            Self::Icmp { icmp_type, code, .. } => {
                write!(f, "ICMP type={icmp_type} code={code}")
            }
            Self::Raw { protocol, payload } => {
                write!(f, "RAW proto={protocol} len={}", payload.len())
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DecodedPacket — fully parsed multi-layer packet
// ─────────────────────────────────────────────────────────────────────────────

/// Fully decoded multi-layer packet.
#[derive(Debug, Clone)]
pub struct DecodedPacket {
    /// Timestamp (nanoseconds since epoch) from the capture layer.
    pub timestamp_ns: u64,
    /// Ethernet layer (absent for raw-IP captures).
    pub ether: Option<EtherFrame>,
    /// IP layer (absent for non-IP frames).
    pub ip: Option<IpHeader>,
    /// Transport layer.
    pub transport: Option<TransportLayer>,
    /// Capture-level raw bytes.
    pub raw: Vec<u8>,
}

impl DecodedPacket {
    /// Source IP address (if an IP layer is present).
    #[must_use]
    pub fn src_ip(&self) -> Option<IpAddr> {
        self.ip.as_ref().map(|h| h.src)
    }

    /// Destination IP address (if an IP layer is present).
    #[must_use]
    pub fn dst_ip(&self) -> Option<IpAddr> {
        self.ip.as_ref().map(|h| h.dst)
    }

    /// Source port (if a TCP/UDP transport layer is present).
    #[must_use]
    pub fn src_port(&self) -> Option<u16> {
        self.transport.as_ref().and_then(TransportLayer::src_port)
    }

    /// Destination port.
    #[must_use]
    pub fn dst_port(&self) -> Option<u16> {
        self.transport.as_ref().and_then(TransportLayer::dst_port)
    }

    /// Application payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.transport.as_ref().map_or(&[], TransportLayer::payload)
    }

    /// Protocol name string (TCP, UDP, ICMP, …).
    #[must_use]
    pub fn protocol_name(&self) -> &str {
        self.transport
            .as_ref()
            .map_or("UNKNOWN", TransportLayer::protocol_name)
    }
}

impl fmt::Display for DecodedPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ip) = &self.ip {
            write!(f, "{ip}")?;
        } else {
            write!(f, "<no IP>")?;
        }
        if let Some(t) = &self.transport {
            write!(f, " / {t}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PacketDecoder — the main decoder
// ─────────────────────────────────────────────────────────────────────────────

/// Decoding mode — determines which layer the raw bytes start at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecodeMode {
    /// Bytes start at Ethernet II frame header.
    #[default]
    Ethernet,
    /// Bytes start at the IPv4 header (no Ethernet framing).
    RawIpv4,
    /// Bytes start at the IPv6 header.
    RawIpv6,
    /// Try to auto-detect the start layer.
    Auto,
}

/// Decode statistics accumulated by a [`PacketDecoder`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecoderStats {
    /// Total packets fed into the decoder.
    pub total: u64,
    /// Packets successfully decoded at L2.
    pub l2_ok: u64,
    /// Packets with a successfully decoded IP header.
    pub l3_ok: u64,
    /// Packets with a successfully decoded transport header.
    pub l4_ok: u64,
    /// Packets that failed at some layer.
    pub errors: u64,
    /// Packets that were not IP (ARP, etc.).
    pub non_ip: u64,
}

/// Multi-layer packet decoder.
///
/// Accepts raw byte slices and walks the Ethernet → IP → TCP/UDP stack,
/// returning a [`DecodedPacket`] with every parsed layer.  Parse errors at
/// any layer are soft: the successfully decoded layers up to the failure point
/// are still returned.
#[derive(Debug, Default)]
pub struct PacketDecoder {
    /// Decoding mode.
    pub mode: DecodeMode,
    /// Accumulated statistics.
    pub stats: DecoderStats,
}

impl PacketDecoder {
    /// Create a new decoder in Ethernet mode.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a decoder with the given mode.
    #[must_use]
    pub fn with_mode(mode: DecodeMode) -> Self {
        Self {
            mode,
            ..Default::default()
        }
    }

    /// Decode a raw packet buffer captured at timestamp `ts_ns`.
    ///
    /// This method never fails: parse errors at any layer result in `None`
    /// for that layer in the returned [`DecodedPacket`].
    pub fn decode(&mut self, data: &[u8], ts_ns: u64) -> DecodedPacket {
        self.stats.total += 1;

        let mut pkt = DecodedPacket {
            timestamp_ns: ts_ns,
            ether: None,
            ip: None,
            transport: None,
            raw: data.to_vec(),
        };

        match self.mode {
            DecodeMode::Ethernet => self.decode_ether(&mut pkt, data),
            DecodeMode::RawIpv4 => {
                self.stats.l2_ok += 1;
                self.decode_ip(&mut pkt, data, 0x0800);
            }
            DecodeMode::RawIpv6 => {
                self.stats.l2_ok += 1;
                self.decode_ip(&mut pkt, data, 0x86DD);
            }
            DecodeMode::Auto => self.decode_auto(&mut pkt, data),
        }

        pkt
    }

    fn decode_ether(&mut self, pkt: &mut DecodedPacket, data: &[u8]) {
        match parse_ether_frame(data) {
            Ok(frame) => {
                self.stats.l2_ok += 1;
                let ethertype = frame.ethertype;
                let payload_offset = frame.payload_offset;
                pkt.ether = Some(frame);
                if payload_offset < data.len() {
                    self.decode_ip(pkt, &data[payload_offset..], ethertype);
                }
            }
            Err(_) => {
                self.stats.errors += 1;
            }
        }
    }

    fn decode_auto(&mut self, pkt: &mut DecodedPacket, data: &[u8]) {
        if data.len() >= 14 {
            // Check if it looks like Ethernet by inspecting the ethertype.
            let et = u16::from_be_bytes([data[12], data[13]]);
            if matches!(et, 0x0800 | 0x86DD | 0x0806 | 0x8100) {
                self.decode_ether(pkt, data);
                return;
            }
        }
        if !data.is_empty() {
            let version = (data[0] >> 4) & 0xF;
            if version == 4 {
                self.stats.l2_ok += 1;
                self.decode_ip(pkt, data, 0x0800);
                return;
            }
            if version == 6 {
                self.stats.l2_ok += 1;
                self.decode_ip(pkt, data, 0x86DD);
                return;
            }
        }
        self.stats.errors += 1;
    }

    fn decode_ip(&mut self, pkt: &mut DecodedPacket, data: &[u8], ethertype: u16) {
        match ethertype {
            0x0800 => match parse_ipv4_header(data) {
                Ok(hdr) => {
                    self.stats.l3_ok += 1;
                    let header_len = hdr.header_len;
                    let proto = hdr.protocol;
                    pkt.ip = Some(hdr);
                    if header_len <= data.len() {
                        self.decode_transport(pkt, &data[header_len..], proto);
                    }
                }
                Err(_) => {
                    self.stats.errors += 1;
                }
            },
            0x86DD => match parse_ipv6_header(data) {
                Ok(hdr) => {
                    self.stats.l3_ok += 1;
                    let header_len = hdr.header_len;
                    let proto = hdr.protocol;
                    pkt.ip = Some(hdr);
                    if header_len <= data.len() {
                        self.decode_transport(pkt, &data[header_len..], proto);
                    }
                }
                Err(_) => {
                    self.stats.errors += 1;
                }
            },
            _ => {
                self.stats.non_ip += 1;
            }
        }
    }

    fn decode_transport(&mut self, pkt: &mut DecodedPacket, data: &[u8], proto: u8) {
        match proto {
            6 => match parse_tcp_header(data) {
                Ok(hdr) => {
                    self.stats.l4_ok += 1;
                    let payload = data[hdr.header_len..].to_vec();
                    pkt.transport = Some(TransportLayer::Tcp { header: hdr, payload });
                }
                Err(_) => {
                    self.stats.errors += 1;
                }
            },
            17 => match parse_udp_header(data) {
                Ok(hdr) => {
                    self.stats.l4_ok += 1;
                    let payload_len = (hdr.length as usize).saturating_sub(8);
                    let payload = if data.len() >= 8 {
                        data[8..8 + payload_len.min(data.len() - 8)].to_vec()
                    } else {
                        Vec::new()
                    };
                    pkt.transport = Some(TransportLayer::Udp { header: hdr, payload });
                }
                Err(_) => {
                    self.stats.errors += 1;
                }
            },
            1 | 58 => {
                // ICMP / ICMPv6
                if data.len() >= 4 {
                    self.stats.l4_ok += 1;
                    pkt.transport = Some(TransportLayer::Icmp {
                        icmp_type: data[0],
                        code: data[1],
                        checksum: u16::from_be_bytes([data[2], data[3]]),
                        payload: data[4..].to_vec(),
                    });
                } else {
                    self.stats.errors += 1;
                }
            }
            other => {
                self.stats.l4_ok += 1; // Raw counts as decoded.
                pkt.transport = Some(TransportLayer::Raw {
                    protocol: other,
                    payload: data.to_vec(),
                });
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_eth_ipv4_tcp() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header
        pkt.extend_from_slice(&[0xFF; 6]); // dst MAC
        pkt.extend_from_slice(&[0xAA; 6]); // src MAC
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4 header (20 bytes)
        pkt.push(0x45); // version=4, ihl=5
        pkt.push(0x00); // DSCP/ECN
        pkt.extend_from_slice(&[0x00, 0x28]); // total len = 40
        pkt.extend_from_slice(&[0x00, 0x01]); // ID
        pkt.extend_from_slice(&[0x40, 0x00]); // flags / frag offset
        pkt.push(64); // TTL
        pkt.push(6); // TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum (fake)
        pkt.extend_from_slice(&[10, 0, 0, 1]); // src
        pkt.extend_from_slice(&[10, 0, 0, 2]); // dst
        // TCP header (20 bytes)
        pkt.extend_from_slice(&[0x04, 0xD2]); // src port 1234
        pkt.extend_from_slice(&[0x00, 0x50]); // dst port 80
        pkt.extend_from_slice(&[0, 0, 0, 1]); // seq
        pkt.extend_from_slice(&[0, 0, 0, 0]); // ack
        pkt.push(0x50); // data offset = 5*4 = 20
        pkt.push(0x02); // SYN
        pkt.extend_from_slice(&[0xFF, 0xFF]); // window
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent
        pkt
    }

    #[test]
    fn decode_ethernet_ipv4_tcp() {
        let raw = make_eth_ipv4_tcp();
        let mut dec = PacketDecoder::new();
        let pkt = dec.decode(&raw, 12345);
        assert!(pkt.ether.is_some());
        assert!(pkt.ip.is_some());
        assert!(matches!(pkt.transport, Some(TransportLayer::Tcp { .. })));
        assert_eq!(pkt.src_port(), Some(1234));
        assert_eq!(pkt.dst_port(), Some(80));
        let ip = pkt.ip.as_ref().unwrap();
        assert_eq!(ip.protocol, 6);
        assert_eq!(ip.ttl, 64);
    }

    #[test]
    fn decode_stats_updated() {
        let raw = make_eth_ipv4_tcp();
        let mut dec = PacketDecoder::new();
        dec.decode(&raw, 0);
        assert_eq!(dec.stats.total, 1);
        assert_eq!(dec.stats.l2_ok, 1);
        assert_eq!(dec.stats.l3_ok, 1);
        assert_eq!(dec.stats.l4_ok, 1);
    }

    #[test]
    fn ether_frame_vlan() {
        let mut data = vec![0u8; 18];
        data[12] = 0x81;
        data[13] = 0x00; // VLAN
        data[14] = 0x00;
        data[15] = 0x0A;
        data[16] = 0x08;
        data[17] = 0x00; // IPv4
        let frame = parse_ether_frame(&data).unwrap();
        assert!(frame.vlan.is_some());
        assert_eq!(frame.ethertype, 0x0800);
        assert_eq!(frame.payload_offset, 18);
    }

    #[test]
    fn ether_frame_broadcast() {
        let mut data = vec![0u8; 14];
        data[0..6].copy_from_slice(&[0xFF; 6]);
        data[6..12].copy_from_slice(&[0xAA; 6]);
        data[12] = 0x08;
        data[13] = 0x00;
        let frame = parse_ether_frame(&data).unwrap();
        assert!(frame.is_broadcast());
        assert!(!frame.is_multicast());
    }

    #[test]
    fn tcp_header_flags() {
        let mut data = vec![0u8; 20];
        data[0] = 0x04;
        data[1] = 0xD2; // src port 1234
        data[2] = 0x00;
        data[3] = 0x50; // dst port 80
        data[12] = 0x50; // data offset
        data[13] = TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK;
        let hdr = parse_tcp_header(&data).unwrap();
        assert!(hdr.is_syn());
        assert!(hdr.is_ack());
        assert!(!hdr.is_fin());
        assert!(hdr.flags_str().contains("SYN"));
    }

    #[test]
    fn udp_header_parse() {
        let data = [0x13, 0x88, 0x00, 0x35, 0x00, 0x1C, 0x00, 0x00u8]; // 5000 → 53
        let hdr = parse_udp_header(&data).unwrap();
        assert_eq!(hdr.src_port, 5000);
        assert_eq!(hdr.dst_port, 53);
        assert_eq!(hdr.length, 28);
    }

    #[test]
    fn decode_too_short() {
        let raw = vec![0u8; 4];
        let mut dec = PacketDecoder::new();
        let pkt = dec.decode(&raw, 0);
        assert!(pkt.ether.is_none());
        assert_eq!(dec.stats.errors, 1);
    }

    #[test]
    fn decode_auto_mode_ipv4() {
        let mut raw = vec![0u8; 40];
        // IPv4 header magic
        raw[0] = 0x45;
        raw[9] = 17; // UDP
        let mut dec = PacketDecoder::with_mode(DecodeMode::Auto);
        let _pkt = dec.decode(&raw, 0);
        // Should at least not panic; l3 may succeed or fail based on valid fields.
        assert_eq!(dec.stats.total, 1);
    }
}
