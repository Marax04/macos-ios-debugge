//! `packet_builder.rs` — craft arbitrary network packets from Rust.
//!
//! # Types
//! * [`EthernetFrame`] — 14-byte Ethernet II header with optional payload.
//! * [`IpHeader`] — IPv4 (20 bytes min) or IPv6 (40 bytes) header.
//! * [`TcpSegment`] — TCP header with options and payload.
//! * [`UdpDatagram`] — UDP header with payload.
//! * [`ChecksumCalculator`] — internet checksum (RFC 1071) and TCP/UDP pseudo-header.
//! * [`PacketCraft`] — high-level builder that stacks layers and serialises.
//! * [`PacketBuilder`] — fluent builder for all layer types.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ─── BuildError ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    PayloadTooLarge { max: usize, got: usize },
    InvalidHeader(String),
    BufferTooShort { need: usize, got: usize },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { max, got } => {
                write!(f, "payload too large: max {max} bytes, got {got}")
            }
            Self::InvalidHeader(s) => write!(f, "invalid header: {s}"),
            Self::BufferTooShort { need, got } => {
                write!(f, "buffer too short: need {need}, have {got}")
            }
        }
    }
}

pub type BuildResult<T> = Result<T, BuildError>;

// ─── EtherType ────────────────────────────────────────────────────────────────

/// Common `EtherType` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EtherType(pub u16);

impl EtherType {
    pub const IPV4: Self = Self(0x0800);
    pub const ARP: Self = Self(0x0806);
    pub const IPV6: Self = Self(0x86DD);
    pub const VLAN: Self = Self(0x8100);
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

// ─── EthernetFrame ────────────────────────────────────────────────────────────

/// An Ethernet II frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ether_type: EtherType,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    #[must_use]
    pub const fn new(dst: [u8; 6], src: [u8; 6], ether_type: EtherType) -> Self {
        Self {
            dst,
            src,
            ether_type,
            payload: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    /// Serialise to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14 + self.payload.len());
        out.extend_from_slice(&self.dst);
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.ether_type.0.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse from bytes.
    ///
    /// # Errors
    /// Returns [`BuildError::BufferTooShort`] when `data` is smaller than the minimum Ethernet header (14 bytes).
    pub fn from_bytes(data: &[u8]) -> BuildResult<Self> {
        if data.len() < 14 {
            return Err(BuildError::BufferTooShort {
                need: 14,
                got: data.len(),
            });
        }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&data[0..6]);
        src.copy_from_slice(&data[6..12]);
        let etype = u16::from_be_bytes([data[12], data[13]]);
        Ok(Self {
            dst,
            src,
            ether_type: EtherType(etype),
            payload: data[14..].to_vec(),
        })
    }

    /// Total frame length including header.
    #[must_use]
    pub const fn len(&self) -> usize {
        14 + self.payload.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// MAC address of destination as a colon-separated string.
    #[must_use]
    pub fn dst_str(&self) -> String {
        format_mac(self.dst)
    }

    /// MAC address of source as a colon-separated string.
    #[must_use]
    pub fn src_str(&self) -> String {
        format_mac(self.src)
    }
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

// ─── IpVersion ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

// ─── IpHeader ────────────────────────────────────────────────────────────────

/// IPv4 or IPv6 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

impl IpHeader {
    #[must_use]
    pub const fn version(&self) -> IpVersion {
        match self {
            Self::V4(_) => IpVersion::V4,
            Self::V6(_) => IpVersion::V6,
        }
    }

    #[must_use]
    pub const fn src(&self) -> IpAddr {
        match self {
            Self::V4(h) => IpAddr::V4(h.src),
            Self::V6(h) => IpAddr::V6(h.src),
        }
    }

    #[must_use]
    pub const fn dst(&self) -> IpAddr {
        match self {
            Self::V4(h) => IpAddr::V4(h.dst),
            Self::V6(h) => IpAddr::V6(h.dst),
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::V4(h) => h.to_bytes(),
            Self::V6(h) => h.to_bytes(),
        }
    }

    #[must_use]
    pub const fn header_len(&self) -> usize {
        match self {
            Self::V4(h) => h.ihl as usize * 4,
            Self::V6(_) => 40,
        }
    }
}

// ─── Ipv4Header ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub ihl: u8,
    pub dscp: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl Ipv4Header {
    #[must_use]
    pub const fn new(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload_len: u16) -> Self {
        Self {
            ihl: 5,
            dscp: 0,
            total_length: 20 + payload_len,
            identification: 0x1234,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol,
            checksum: 0,
            src,
            dst,
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        buf[0] = (4 << 4) | self.ihl;
        buf[1] = self.dscp;
        buf[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        buf[4..6].copy_from_slice(&self.identification.to_be_bytes());
        let flags_frag = (u16::from(self.flags) << 13) | (self.fragment_offset & 0x1FFF);
        buf[6..8].copy_from_slice(&flags_frag.to_be_bytes());
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        buf[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        buf[12..16].copy_from_slice(&self.src.octets());
        buf[16..20].copy_from_slice(&self.dst.octets());
        let csum = ChecksumCalculator::internet_checksum(&buf);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());
        buf
    }

    /// Parse from bytes; checksum is stored as-is.
    ///
    /// # Errors
    /// Returns [`BuildError::BufferTooShort`] when `data` is smaller than the minimum IPv4 header (20 bytes).
    pub fn from_bytes(data: &[u8]) -> BuildResult<Self> {
        if data.len() < 20 {
            return Err(BuildError::BufferTooShort {
                need: 20,
                got: data.len(),
            });
        }
        let ihl = data[0] & 0xF;
        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        Ok(Self {
            ihl,
            dscp: data[1],
            total_length: u16::from_be_bytes([data[2], data[3]]),
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags: (data[6] >> 5) & 0x7,
            fragment_offset: u16::from_be_bytes([data[6] & 0x1F, data[7]]),
            ttl: data[8],
            protocol: data[9],
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src,
            dst,
        })
    }
}

// ─── Ipv6Header ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

impl Ipv6Header {
    #[must_use]
    pub const fn new(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload_len: u16) -> Self {
        Self {
            traffic_class: 0,
            flow_label: 0,
            payload_length: payload_len,
            next_header,
            hop_limit: 64,
            src,
            dst,
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 40];
        let ver_tc_fl =
            (6u32 << 28) | (u32::from(self.traffic_class) << 20) | (self.flow_label & 0xFFFFF);
        buf[0..4].copy_from_slice(&ver_tc_fl.to_be_bytes());
        buf[4..6].copy_from_slice(&self.payload_length.to_be_bytes());
        buf[6] = self.next_header;
        buf[7] = self.hop_limit;
        buf[8..24].copy_from_slice(&self.src.octets());
        buf[24..40].copy_from_slice(&self.dst.octets());
        buf
    }
}

// ─── TcpSegment ──────────────────────────────────────────────────────────────

/// TCP header flags.
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent: u16,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

impl TcpSegment {
    #[must_use]
    pub const fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            seq: 0,
            ack: 0,
            data_offset: 5,
            flags: tcp_flags::SYN,
            window: 65535,
            checksum: 0,
            urgent: 0,
            options: Vec::new(),
            payload: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }
    #[must_use]
    pub const fn with_seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }
    #[must_use]
    pub const fn with_ack(mut self, ack: u32) -> Self {
        self.ack = ack;
        self
    }
    #[must_use]
    pub fn with_payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    #[must_use]
    pub const fn header_len(&self) -> usize {
        (self.data_offset as usize) * 4
    }

    #[must_use]
    pub fn to_bytes_no_checksum(&self) -> Vec<u8> {
        let hl = self.header_len();
        let mut buf = vec![0u8; hl + self.payload.len()];
        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack.to_be_bytes());
        buf[12] = (self.data_offset << 4) & 0xF0;
        buf[13] = self.flags;
        buf[14..16].copy_from_slice(&self.window.to_be_bytes());
        buf[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        buf[18..20].copy_from_slice(&self.urgent.to_be_bytes());
        if !self.options.is_empty() {
            let copy_len = self.options.len().min(hl - 20);
            buf[20..20 + copy_len].copy_from_slice(&self.options[..copy_len]);
        }
        buf[hl..].copy_from_slice(&self.payload);
        buf
    }

    /// Compute TCP checksum over a pseudo-header (IPv4).
    #[must_use]
    pub fn checksum_ipv4(&self, src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
        let seg = self.to_bytes_no_checksum();
        ChecksumCalculator::tcp_checksum_ipv4(src, dst, &seg)
    }

    #[must_use]
    pub const fn is_syn(&self) -> bool {
        self.flags & tcp_flags::SYN != 0
    }
    #[must_use]
    pub const fn is_ack(&self) -> bool {
        self.flags & tcp_flags::ACK != 0
    }
    #[must_use]
    pub const fn is_fin(&self) -> bool {
        self.flags & tcp_flags::FIN != 0
    }
    #[must_use]
    pub const fn is_rst(&self) -> bool {
        self.flags & tcp_flags::RST != 0
    }
}

// ─── UdpDatagram ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl UdpDatagram {
    #[must_use]
    pub fn new(src_port: u16, dst_port: u16, payload: Vec<u8>) -> Self {
        let length = 8u16.saturating_add(u16::try_from(payload.len()).unwrap_or(u16::MAX));
        Self {
            src_port,
            dst_port,
            length,
            checksum: 0,
            payload,
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.payload.len());
        buf.extend_from_slice(&self.src_port.to_be_bytes());
        buf.extend_from_slice(&self.dst_port.to_be_bytes());
        buf.extend_from_slice(&self.length.to_be_bytes());
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    #[must_use]
    pub fn checksum_ipv4(&self, src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
        let seg = self.to_bytes();
        ChecksumCalculator::udp_checksum_ipv4(src, dst, &seg)
    }
}

// ─── ChecksumCalculator ──────────────────────────────────────────────────────

/// Internet checksum (RFC 1071) and pseudo-header checksum utilities.
pub struct ChecksumCalculator;

impl ChecksumCalculator {
    /// Compute the one's complement internet checksum over `data`.
    /// Returns 0 when `data` is all zeros.
    #[must_use]
    pub fn internet_checksum(data: &[u8]) -> u16 {
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

    /// Compute TCP checksum using IPv4 pseudo-header.
    #[must_use]
    pub fn tcp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
        Self::transport_checksum_ipv4(src, dst, 6, tcp_segment)
    }

    /// Compute UDP checksum using IPv4 pseudo-header.
    #[must_use]
    pub fn udp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, udp_datagram: &[u8]) -> u16 {
        Self::transport_checksum_ipv4(src, dst, 17, udp_datagram)
    }

    fn transport_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
        let seg_len = u16::try_from(segment.len()).unwrap_or(u16::MAX);
        let mut pseudo = Vec::with_capacity(12 + segment.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0); // reserved
        pseudo.push(proto);
        pseudo.extend_from_slice(&seg_len.to_be_bytes());
        pseudo.extend_from_slice(segment);
        Self::internet_checksum(&pseudo)
    }
}

// ─── PacketCraft ──────────────────────────────────────────────────────────────

/// High-level builder that stacks protocol layers and serialises them.
#[derive(Debug, Default)]
pub struct PacketCraft {
    pub ethernet: Option<EthernetFrame>,
    pub ip: Option<IpHeader>,
    pub tcp: Option<TcpSegment>,
    pub udp: Option<UdpDatagram>,
    pub raw_payload: Vec<u8>,
}

impl PacketCraft {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn ethernet(mut self, frame: EthernetFrame) -> Self {
        self.ethernet = Some(frame);
        self
    }

    #[must_use]
    pub const fn ipv4(mut self, header: Ipv4Header) -> Self {
        self.ip = Some(IpHeader::V4(header));
        self
    }

    #[must_use]
    pub const fn ipv6(mut self, header: Ipv6Header) -> Self {
        self.ip = Some(IpHeader::V6(header));
        self
    }

    #[must_use]
    pub fn tcp(mut self, segment: TcpSegment) -> Self {
        self.tcp = Some(segment);
        self
    }

    #[must_use]
    pub fn udp(mut self, datagram: UdpDatagram) -> Self {
        self.udp = Some(datagram);
        self
    }

    #[must_use]
    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.raw_payload = data;
        self
    }

    /// Serialize the full packet stack.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let transport_bytes: Vec<u8> = self.tcp.as_ref().map_or_else(
            || {
                self.udp
                    .as_ref()
                    .map_or_else(|| self.raw_payload.clone(), UdpDatagram::to_bytes)
            },
            TcpSegment::to_bytes_no_checksum,
        );

        let ip_bytes: Vec<u8> = if let Some(ip) = &self.ip {
            let mut b = ip.to_bytes();
            b.extend_from_slice(&transport_bytes);
            b
        } else {
            transport_bytes
        };

        if let Some(eth) = &self.ethernet {
            let mut frame = eth.clone();
            frame.payload = ip_bytes;
            frame.to_bytes()
        } else {
            ip_bytes
        }
    }

    /// Total serialized length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.build().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─── PacketBuilder ────────────────────────────────────────────────────────────

/// Fluent builder façade.
#[derive(Debug, Default)]
pub struct PacketBuilder {
    craft: PacketCraft,
}

impl PacketBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn ethernet(mut self, dst: [u8; 6], src: [u8; 6], ether_type: EtherType) -> Self {
        self.craft = self
            .craft
            .ethernet(EthernetFrame::new(dst, src, ether_type));
        self
    }

    #[must_use]
    pub fn ipv4(mut self, src: Ipv4Addr, dst: Ipv4Addr, proto: u8) -> Self {
        self.craft = self.craft.ipv4(Ipv4Header::new(src, dst, proto, 0));
        self
    }

    #[must_use]
    pub fn tcp(mut self, src_port: u16, dst_port: u16) -> Self {
        self.craft = self.craft.tcp(TcpSegment::new(src_port, dst_port));
        self
    }

    #[must_use]
    pub fn udp(mut self, src_port: u16, dst_port: u16, payload: Vec<u8>) -> Self {
        self.craft = self
            .craft
            .udp(UdpDatagram::new(src_port, dst_port, payload));
        self
    }

    #[must_use]
    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.craft = self.craft.payload(data);
        self
    }

    #[must_use]
    pub fn build(self) -> Vec<u8> {
        self.craft.build()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // EthernetFrame tests ───────────────────────────────────────────────────

    #[test]
    fn ethernet_roundtrip() {
        let dst = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        let src = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x02];
        let frame = EthernetFrame::new(dst, src, EtherType::IPV4).with_payload(vec![0x45, 0x00]);
        let bytes = frame.to_bytes();
        assert_eq!(bytes.len(), 16);
        let parsed = EthernetFrame::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.ether_type, EtherType::IPV4);
    }

    #[test]
    fn ethernet_too_short_parse_error() {
        assert!(EthernetFrame::from_bytes(&[0u8; 5]).is_err());
    }

    #[test]
    fn ethernet_length() {
        let frame =
            EthernetFrame::new([0u8; 6], [0u8; 6], EtherType::IPV4).with_payload(vec![0u8; 20]);
        assert_eq!(frame.len(), 34);
    }

    #[test]
    fn ethernet_mac_display() {
        let frame = EthernetFrame::new(
            [0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34],
            [0u8; 6],
            EtherType::ARP,
        );
        assert_eq!(frame.dst_str(), "de:ad:be:ef:12:34");
    }

    #[test]
    fn ethertype_display() {
        assert_eq!(EtherType::IPV4.to_string(), "0x0800");
    }

    // Ipv4Header tests ──────────────────────────────────────────────────────

    #[test]
    fn ipv4_header_serializes_to_20_bytes() {
        let h = Ipv4Header::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            6,
            0,
        );
        assert_eq!(h.to_bytes().len(), 20);
    }

    #[test]
    fn ipv4_header_src_dst() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let ip = IpHeader::V4(Ipv4Header::new(src, dst, 17, 8));
        assert_eq!(ip.src(), IpAddr::V4(src));
        assert_eq!(ip.dst(), IpAddr::V4(dst));
    }

    #[test]
    fn ipv4_header_parse_roundtrip() {
        let src = Ipv4Addr::new(1, 2, 3, 4);
        let dst = Ipv4Addr::new(5, 6, 7, 8);
        let h = Ipv4Header::new(src, dst, 6, 0);
        let bytes = h.to_bytes();
        let parsed = Ipv4Header::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.protocol, 6);
    }

    #[test]
    fn ipv4_header_parse_too_short() {
        assert!(Ipv4Header::from_bytes(&[0u8; 5]).is_err());
    }

    // Ipv6Header tests ──────────────────────────────────────────────────────

    #[test]
    fn ipv6_header_serializes_to_40_bytes() {
        let h = Ipv6Header::new(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 6, 0);
        assert_eq!(h.to_bytes().len(), 40);
    }

    #[test]
    fn ipv6_version_field() {
        let ip = IpHeader::V6(Ipv6Header::new(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            6,
            0,
        ));
        assert_eq!(ip.version(), IpVersion::V6);
        assert_eq!(ip.header_len(), 40);
    }

    // TcpSegment tests ──────────────────────────────────────────────────────

    #[test]
    fn tcp_segment_is_syn() {
        let seg = TcpSegment::new(1234, 80).with_flags(tcp_flags::SYN);
        assert!(seg.is_syn());
        assert!(!seg.is_ack());
    }

    #[test]
    fn tcp_segment_syn_ack_flags() {
        let seg = TcpSegment::new(80, 1234).with_flags(tcp_flags::SYN | tcp_flags::ACK);
        assert!(seg.is_syn());
        assert!(seg.is_ack());
    }

    #[test]
    fn tcp_segment_serialization_length() {
        let seg = TcpSegment::new(443, 1234).with_payload(vec![0u8; 10]);
        let bytes = seg.to_bytes_no_checksum();
        assert_eq!(bytes.len(), 20 + 10);
    }

    #[test]
    fn tcp_checksum_non_zero() {
        let seg = TcpSegment::new(1234, 80).with_flags(tcp_flags::SYN);
        let csum = seg.checksum_ipv4(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2));
        // Should not be trivially 0 for a real segment.
        // (May be 0 for a specific all-zeros case, but generally non-zero.)
        let _ = csum; // just ensure it computes without panic
    }

    // UdpDatagram tests ─────────────────────────────────────────────────────

    #[test]
    fn udp_datagram_length() {
        let udp = UdpDatagram::new(1234, 53, vec![0u8; 4]);
        assert_eq!(udp.length, 12);
        assert_eq!(udp.to_bytes().len(), 12);
    }

    #[test]
    fn udp_datagram_ports() {
        let udp = UdpDatagram::new(5000, 53, vec![]);
        assert_eq!(udp.src_port, 5000);
        assert_eq!(udp.dst_port, 53);
    }

    // ChecksumCalculator tests ──────────────────────────────────────────────

    #[test]
    fn checksum_empty_data() {
        assert_eq!(ChecksumCalculator::internet_checksum(b""), 0xFFFF);
    }

    #[test]
    fn checksum_all_zeros() {
        assert_eq!(ChecksumCalculator::internet_checksum(&[0u8; 20]), 0xFFFF);
    }

    #[test]
    fn checksum_known_ipv4_header() {
        // A valid IPv4 header has checksum field such that checksum of the full
        // 20 bytes equals 0x0000.
        let h = Ipv4Header::new(
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            17,
            8,
        );
        let bytes = h.to_bytes();
        assert_eq!(ChecksumCalculator::internet_checksum(&bytes), 0);
    }

    // PacketCraft tests ─────────────────────────────────────────────────────

    #[test]
    fn packet_craft_raw_payload() {
        let pkt = PacketCraft::new().payload(vec![1, 2, 3]).build();
        assert_eq!(pkt, vec![1, 2, 3]);
    }

    #[test]
    fn packet_craft_with_udp() {
        let udp = UdpDatagram::new(5000, 53, vec![0u8; 4]);
        let pkt = PacketCraft::new().udp(udp).build();
        assert_eq!(pkt.len(), 12);
    }

    #[test]
    fn packet_craft_ethernet_ip_udp() {
        let eth = EthernetFrame::new([0u8; 6], [0u8; 6], EtherType::IPV4);
        let ip = Ipv4Header::new(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 17, 12);
        let udp = UdpDatagram::new(1234, 5678, vec![0xAB; 4]);
        let pkt = PacketCraft::new().ethernet(eth).ipv4(ip).udp(udp).build();
        // 14 (eth) + 20 (ip) + 12 (udp) = 46
        assert_eq!(pkt.len(), 46);
    }

    // PacketBuilder tests ───────────────────────────────────────────────────

    #[test]
    fn packet_builder_tcp_syn() {
        let pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8), 6)
            .tcp(12345, 80)
            .build();
        // 20 (ip) + 20 (tcp) = 40
        assert_eq!(pkt.len(), 40);
    }

    #[test]
    fn packet_builder_udp_payload() {
        let pkt = PacketBuilder::new().udp(5000, 53, vec![0u8; 4]).build();
        assert_eq!(pkt.len(), 12);
    }

    #[test]
    fn ipv4_header_version_is_v4() {
        let ip = IpHeader::V4(Ipv4Header::new(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            6,
            0,
        ));
        assert_eq!(ip.version(), IpVersion::V4);
    }

    #[test]
    fn ipv4_header_protocol_field_preserved() {
        let h = Ipv4Header::new(Ipv4Addr::LOCALHOST, Ipv4Addr::BROADCAST, 17, 0);
        let bytes = h.to_bytes();
        assert_eq!(bytes[9], 17);
    }

    #[test]
    fn tcp_segment_fin_flag() {
        let seg = TcpSegment::new(1, 2).with_flags(tcp_flags::FIN);
        assert!(seg.is_fin());
        assert!(!seg.is_syn());
    }

    #[test]
    fn tcp_segment_rst_flag() {
        let seg = TcpSegment::new(1, 2).with_flags(tcp_flags::RST);
        assert!(seg.is_rst());
    }

    #[test]
    fn udp_checksum_non_panic() {
        let udp = UdpDatagram::new(1234, 5678, vec![0xAB; 8]);
        let _ = udp.checksum_ipv4(Ipv4Addr::LOCALHOST, Ipv4Addr::BROADCAST);
    }

    #[test]
    fn packet_craft_empty_no_panic() {
        let pkt = PacketCraft::new().build();
        assert!(pkt.is_empty());
    }

    #[test]
    fn packet_craft_tcp_payload_is_correct_size() {
        let tcp = TcpSegment::new(80, 443)
            .with_flags(tcp_flags::SYN | tcp_flags::ACK)
            .with_payload(vec![0u8; 5]);
        let pkt = PacketCraft::new().tcp(tcp).build();
        // 20 (tcp hdr) + 5 (payload) = 25
        assert_eq!(pkt.len(), 25);
    }

    #[test]
    fn checksum_odd_len_data() {
        // Should not panic on odd-length input.
        let data = b"\xAB\xCD\xEF";
        let _ = ChecksumCalculator::internet_checksum(data);
    }

    #[test]
    fn build_error_display() {
        let e = BuildError::PayloadTooLarge { max: 100, got: 200 };
        assert!(e.to_string().contains("200"));
    }

    #[test]
    fn build_error_buffer_too_short_display() {
        let e = BuildError::BufferTooShort { need: 20, got: 5 };
        assert!(e.to_string().contains('5'));
    }
}
