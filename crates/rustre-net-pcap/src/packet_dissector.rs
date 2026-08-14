//! Full protocol-stack packet dissector.
//!
//! Dissects raw packet bytes from the link layer up to application-layer
//! protocols.  The dissection is purely zero-copy where possible (slices into
//! the original buffer) and never panics.
//!
//! Supported protocol stack:
//!   Link  : Ethernet I, 802.1Q VLAN, 802.1ad `QinQ`, Linux cooked (SLL)
//!   L3    : IPv4, IPv6 (with extension header chaining)
//!   L4    : TCP, UDP, `ICMPv4`, `ICMPv6`
//!   App   : DNS (UDP/53), HTTP (TCP/80, heuristic), TLS Client Hello (TCP/443)

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DissectError {
    TooShort { layer: &'static str, need: usize, got: usize },
    UnknownEthertype(u16),
    BadIpVersion(u8),
    BadIpHeaderLen(u8),
    UnknownProtocol(u8),
    BadChecksum { layer: &'static str },
    Truncated,
}

impl std::fmt::Display for DissectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { layer, need, got } => {
                write!(f, "{layer}: need {need} bytes, got {got}")
            }
            Self::UnknownEthertype(e) => write!(f, "unknown ethertype 0x{e:04x}"),
            Self::BadIpVersion(v) => write!(f, "bad IP version {v}"),
            Self::BadIpHeaderLen(l) => write!(f, "bad IP IHL {l}"),
            Self::UnknownProtocol(p) => write!(f, "unknown protocol {p}"),
            Self::BadChecksum { layer } => write!(f, "bad {layer} checksum"),
            Self::Truncated => write!(f, "packet truncated"),
        }
    }
}

impl std::error::Error for DissectError {}

// ─── Common types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl std::fmt::Display for IpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(a) => write!(f, "{a}"),
            Self::V6(a) => write!(f, "{a}"),
        }
    }
}

// ─── Ethernet ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub vlan_tags: Vec<VlanTag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanTag {
    pub tpid: u16, // 0x8100 or 0x88a8
    pub pcp: u8,   // 3-bit priority
    pub dei: bool, // drop eligible indicator
    pub vid: u16,  // 12-bit VLAN ID
}

impl EthernetHeader {
    #[must_use] 
    pub fn src_mac_str(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.src_mac[0],
            self.src_mac[1],
            self.src_mac[2],
            self.src_mac[3],
            self.src_mac[4],
            self.src_mac[5]
        )
    }
    #[must_use] 
    pub fn dst_mac_str(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.dst_mac[0],
            self.dst_mac[1],
            self.dst_mac[2],
            self.dst_mac[3],
            self.dst_mac[4],
            self.dst_mac[5]
        )
    }
    #[must_use] 
    pub fn is_broadcast(&self) -> bool {
        self.dst_mac == [0xff; 6]
    }
    #[must_use] 
    pub fn is_multicast(&self) -> bool {
        self.dst_mac[0] & 0x01 != 0 && !self.is_broadcast()
    }
}

// ─── IPv4 ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub options: Vec<u8>,
}

impl Ipv4Header {
    #[must_use] 
    pub const fn header_len(&self) -> usize {
        self.ihl as usize * 4
    }
    #[must_use] 
    pub const fn is_fragmented(&self) -> bool {
        self.flags & 0x01 != 0 || self.fragment_offset != 0
    }
    #[must_use] 
    pub const fn dont_fragment(&self) -> bool {
        self.flags & 0x02 != 0
    }
}

// ─── IPv6 ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub extension_headers: Vec<Ipv6ExtensionHeader>,
    /// Next-header value after all extensions have been consumed.
    pub final_next_header: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6ExtensionHeader {
    pub next_header: u8,
    pub header_type: u8,
    pub data: Vec<u8>,
}

// ─── TCP ──────────────────────────────────────────────────────────────────────

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
    pub options: Vec<TcpOption>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TcpOption {
    Nop,
    Eol,
    MaxSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(Vec<(u32, u32)>),
    Timestamp { val: u32, ecr: u32 },
    Unknown { kind: u8, data: Vec<u8> },
}

impl TcpHeader {
    #[must_use] 
    pub const fn header_len(&self) -> usize {
        self.data_offset as usize * 4
    }
    #[must_use] 
    pub const fn is_syn(&self) -> bool { self.flags & 0x02 != 0 }
    #[must_use] 
    pub const fn is_ack(&self) -> bool { self.flags & 0x10 != 0 }
    #[must_use] 
    pub const fn is_fin(&self) -> bool { self.flags & 0x01 != 0 }
    #[must_use] 
    pub const fn is_rst(&self) -> bool { self.flags & 0x04 != 0 }
    #[must_use] 
    pub const fn is_psh(&self) -> bool { self.flags & 0x08 != 0 }
    #[must_use] 
    pub const fn is_urg(&self) -> bool { self.flags & 0x20 != 0 }
}

// ─── UDP ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

// ─── ICMP ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest_of_header: [u8; 4],
}

impl IcmpHeader {
    #[must_use] 
    pub const fn type_name(&self) -> &'static str {
        match self.icmp_type {
            0 => "EchoReply",
            3 => "DestinationUnreachable",
            5 => "Redirect",
            8 => "EchoRequest",
            11 => "TimeExceeded",
            12 => "ParameterProblem",
            _ => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Icmpv6Header {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest_of_header: [u8; 4],
}

// ─── Application layer ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMessage {
    pub id: u16,
    pub flags: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

impl DnsMessage {
    #[must_use] 
    pub const fn is_nx_domain(&self) -> bool {
        self.is_response && (self.flags & 0x000f) == 3
    }
    #[must_use] 
    pub const fn rcode(&self) -> u8 {
        (self.flags & 0x000f) as u8
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppLayer {
    Dns(DnsMessage),
    HttpRequest(HttpRequest),
    HttpResponse(HttpResponse),
    TlsClientHello(TlsClientHello),
    RawPayload(Vec<u8>),
    Empty,
}

// ─── Dissected packet ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissectedPacket {
    pub ethernet: Option<EthernetHeader>,
    pub ip4: Option<Ipv4Header>,
    pub ip6: Option<Ipv6Header>,
    pub tcp: Option<TcpHeader>,
    pub udp: Option<UdpHeader>,
    pub icmp: Option<IcmpHeader>,
    pub icmp6: Option<Icmpv6Header>,
    pub app: AppLayer,
    pub payload: Vec<u8>,
    pub errors: Vec<String>,
}

impl DissectedPacket {
    #[must_use] 
    pub const fn src_ip(&self) -> Option<IpAddr> {
        if let Some(ref h) = self.ip4 {
            return Some(IpAddr::V4(h.src));
        }
        if let Some(ref h) = self.ip6 {
            return Some(IpAddr::V6(h.src));
        }
        None
    }
    #[must_use] 
    pub const fn dst_ip(&self) -> Option<IpAddr> {
        if let Some(ref h) = self.ip4 {
            return Some(IpAddr::V4(h.dst));
        }
        if let Some(ref h) = self.ip6 {
            return Some(IpAddr::V6(h.dst));
        }
        None
    }
    #[must_use] 
    pub const fn src_port(&self) -> Option<u16> {
        if let Some(ref t) = self.tcp { return Some(t.src_port); }
        if let Some(ref u) = self.udp { return Some(u.src_port); }
        None
    }
    #[must_use] 
    pub const fn dst_port(&self) -> Option<u16> {
        if let Some(ref t) = self.tcp { return Some(t.dst_port); }
        if let Some(ref u) = self.udp { return Some(u.dst_port); }
        None
    }
    #[must_use] 
    pub const fn protocol_name(&self) -> &'static str {
        if self.tcp.is_some() { "TCP" }
        else if self.udp.is_some() { "UDP" }
        else if self.icmp.is_some() { "ICMP" }
        else if self.icmp6.is_some() { "ICMPv6" }
        else { "Unknown" }
    }
}

// ─── Dissector ────────────────────────────────────────────────────────────────

pub struct PacketDissector {
    pub validate_checksums: bool,
    pub max_dns_labels: usize,
    pub decode_app_layer: bool,
}

impl Default for PacketDissector {
    fn default() -> Self {
        Self { validate_checksums: false, max_dns_labels: 128, decode_app_layer: true }
    }
}

impl PacketDissector {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn dissect(&self, data: &[u8]) -> DissectedPacket {
        self.dissect_ethernet(data)
    }

    #[must_use] 
    pub fn dissect_raw_ip(&self, data: &[u8]) -> DissectedPacket {
        let mut pkt = DissectedPacket {
            ethernet: None,
            ip4: None, ip6: None, tcp: None, udp: None,
            icmp: None, icmp6: None,
            app: AppLayer::Empty,
            payload: Vec::new(),
            errors: Vec::new(),
        };
        if data.is_empty() { return pkt; }
        let version = (data[0] >> 4) & 0xf;
        match version {
            4 => self.dissect_ipv4(data, &mut pkt),
            6 => self.dissect_ipv6(data, &mut pkt),
            _ => pkt.errors.push(format!("unknown IP version {version}")),
        }
        pkt
    }

    fn dissect_ethernet(&self, data: &[u8]) -> DissectedPacket {
        let mut pkt = DissectedPacket {
            ethernet: None, ip4: None, ip6: None, tcp: None, udp: None,
            icmp: None, icmp6: None,
            app: AppLayer::Empty,
            payload: Vec::new(),
            errors: Vec::new(),
        };
        if data.len() < 14 {
            pkt.errors.push(format!("ethernet: too short ({} bytes)", data.len()));
            return pkt;
        }
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&data[0..6]);
        src_mac.copy_from_slice(&data[6..12]);
        let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
        let mut offset = 14usize;
        let mut vlan_tags = Vec::new();

        // Strip 802.1Q / 802.1ad VLAN tags
        while ethertype == 0x8100 || ethertype == 0x88a8 {
            if offset + 4 > data.len() {
                pkt.errors.push("vlan tag truncated".to_string());
                break;
            }
            let tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let next_type = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            vlan_tags.push(VlanTag {
                tpid: ethertype,
                pcp: (tci >> 13) as u8,
                dei: (tci >> 12 & 1) != 0,
                vid: tci & 0x0fff,
            });
            ethertype = next_type;
            offset += 4;
        }

        pkt.ethernet = Some(EthernetHeader { dst_mac, src_mac, ethertype, vlan_tags });

        let payload = &data[offset..];
        match ethertype {
            0x0800 => self.dissect_ipv4(payload, &mut pkt),
            0x86dd => self.dissect_ipv6(payload, &mut pkt),
            0x0806 => {} // ARP — no further dissection
            _ => pkt.errors.push(format!("unknown ethertype 0x{ethertype:04x}")),
        }
        pkt
    }

    fn dissect_ipv4(&self, data: &[u8], pkt: &mut DissectedPacket) {
        if data.len() < 20 {
            pkt.errors.push(format!("ipv4: too short ({} bytes)", data.len()));
            return;
        }
        let version = (data[0] >> 4) & 0xf;
        let ihl = data[0] & 0xf;
        if version != 4 {
            pkt.errors.push(format!("ipv4: bad version {version}"));
            return;
        }
        if ihl < 5 {
            pkt.errors.push(format!("ipv4: bad IHL {ihl}"));
            return;
        }
        let hdr_len = ihl as usize * 4;
        if data.len() < hdr_len {
            pkt.errors.push(format!("ipv4: header truncated (need {hdr_len})"));
            return;
        }
        let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let id = u16::from_be_bytes([data[4], data[5]]);
        let flags_frag = u16::from_be_bytes([data[6], data[7]]);
        let flags = (flags_frag >> 13) as u8;
        let frag_off = flags_frag & 0x1fff;
        let ttl = data[8];
        let proto = data[9];
        let checksum = u16::from_be_bytes([data[10], data[11]]);
        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let options = if hdr_len > 20 { data[20..hdr_len].to_vec() } else { Vec::new() };

        if self.validate_checksums {
            let computed = ipv4_checksum(&data[..hdr_len]);
            if computed != 0 {
                pkt.errors.push("ipv4: bad checksum".to_string());
            }
        }

        pkt.ip4 = Some(Ipv4Header {
            version, ihl, dscp: data[1] >> 2, ecn: data[1] & 0x03,
            total_len: u16::try_from(total_len).unwrap_or(u16::MAX), id, flags, fragment_offset: frag_off,
            ttl, protocol: proto, checksum, src, dst, options,
        });

        // Restrict payload to total_len
        let payload_start = hdr_len;
        let payload_end = total_len.min(data.len());
        if payload_end <= payload_start {
            return;
        }
        let payload = &data[payload_start..payload_end];
        match proto {
            6  => self.dissect_tcp(payload, pkt),
            17 => self.dissect_udp(payload, pkt),
            1  => self.dissect_icmp(payload, pkt),
            _  => { pkt.payload = payload.to_vec(); }
        }
    }

    fn dissect_ipv6(&self, data: &[u8], pkt: &mut DissectedPacket) {
        if data.len() < 40 {
            pkt.errors.push(format!("ipv6: too short ({} bytes)", data.len()));
            return;
        }
        let version = (data[0] >> 4) & 0xf;
        if version != 6 {
            pkt.errors.push(format!("ipv6: bad version {version}"));
            return;
        }
        let tc = (u16::from_be_bytes([data[0], data[1]]) >> 4 & 0xff) as u8;
        let flow_label = (u32::from_be_bytes([data[0], data[1], data[2], data[3]])) & 0x000f_ffff;
        let payload_len = u16::from_be_bytes([data[4], data[5]]);
        let mut next_hdr = data[6];
        let hop_limit = data[7];
        let mut src_bytes = [0u8; 16];
        let mut dst_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&data[8..24]);
        dst_bytes.copy_from_slice(&data[24..40]);
        let src = Ipv6Addr::from(src_bytes);
        let dst = Ipv6Addr::from(dst_bytes);

        let mut ext_hdrs = Vec::new();
        let mut offset = 40usize;

        // Walk extension headers
        loop {
            let ext_type = next_hdr;
            match ext_type {
                0 | 43 | 44 | 60 | 135 | 139 | 140 => {
                    // Hop-by-hop, routing, fragment, destination, mobility, HIP, shim6
                    if offset + 8 > data.len() { break; }
                    let len_field = data[offset + 1] as usize;
                    let hdr_len = (len_field + 1) * 8;
                    if offset + hdr_len > data.len() { break; }
                    let ext_next = data[offset];
                    ext_hdrs.push(Ipv6ExtensionHeader {
                        next_header: ext_next,
                        header_type: ext_type,
                        data: data[offset..offset + hdr_len].to_vec(),
                    });
                    next_hdr = ext_next;
                    offset += hdr_len;
                }
                _ => break,
            }
        }

        pkt.ip6 = Some(Ipv6Header {
            version, traffic_class: tc, flow_label, payload_len,
            next_header: data[6], hop_limit, src, dst,
            extension_headers: ext_hdrs,
            final_next_header: next_hdr,
        });

        let payload = &data[offset..];
        match next_hdr {
            6  => self.dissect_tcp(payload, pkt),
            17 => self.dissect_udp(payload, pkt),
            58 => self.dissect_icmpv6(payload, pkt),
            _  => { pkt.payload = payload.to_vec(); }
        }
    }

    fn dissect_tcp(&self, data: &[u8], pkt: &mut DissectedPacket) {
        if data.len() < 20 {
            pkt.errors.push(format!("tcp: too short ({} bytes)", data.len()));
            return;
        }
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = (data[12] >> 4) & 0xf;
        let flags = data[13];
        let window = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);
        let hdr_len = data_offset as usize * 4;
        if hdr_len < 20 || hdr_len > data.len() {
            pkt.errors.push(format!("tcp: bad data_offset {data_offset}"));
            return;
        }
        let options = parse_tcp_options(&data[20..hdr_len]);
        pkt.tcp = Some(TcpHeader {
            src_port, dst_port, seq, ack, data_offset, flags, window, checksum, urgent_ptr, options,
        });
        let payload = &data[hdr_len..];
        pkt.payload = payload.to_vec();
        if self.decode_app_layer && !payload.is_empty() {
            self.dissect_tcp_app(payload, src_port, dst_port, pkt);
        }
    }

    fn dissect_udp(&self, data: &[u8], pkt: &mut DissectedPacket) {
        if data.len() < 8 {
            pkt.errors.push(format!("udp: too short ({} bytes)", data.len()));
            return;
        }
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);
        pkt.udp = Some(UdpHeader { src_port, dst_port, length, checksum });
        let payload = &data[8..];
        pkt.payload = payload.to_vec();
        if self.decode_app_layer && !payload.is_empty() {
            self.dissect_udp_app(payload, src_port, dst_port, pkt);
        }
    }

    fn dissect_icmp(&self, data: &[u8], pkt: &mut DissectedPacket) {
        if data.len() < 8 {
            pkt.errors.push(format!("icmp: too short ({} bytes)", data.len()));
            return;
        }
        let mut rest = [0u8; 4];
        rest.copy_from_slice(&data[4..8]);
        pkt.icmp = Some(IcmpHeader {
            icmp_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            rest_of_header: rest,
        });
        pkt.payload = data[8..].to_vec();
    }

    fn dissect_icmpv6(&self, data: &[u8], pkt: &mut DissectedPacket) {
        if data.len() < 8 {
            pkt.errors.push(format!("icmpv6: too short ({} bytes)", data.len()));
            return;
        }
        let mut rest = [0u8; 4];
        rest.copy_from_slice(&data[4..8]);
        pkt.icmp6 = Some(Icmpv6Header {
            icmp_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            rest_of_header: rest,
        });
        pkt.payload = data[8..].to_vec();
    }

    fn dissect_tcp_app(&self, payload: &[u8], src: u16, dst: u16, pkt: &mut DissectedPacket) {
        if (src == 443 || dst == 443)
            && let Some(ch) = try_parse_tls_client_hello(payload) {
                pkt.app = AppLayer::TlsClientHello(ch);
                return;
            }
        if src == 80 || dst == 80 || src == 8080 || dst == 8080 {
            if let Some(req) = try_parse_http_request(payload) {
                pkt.app = AppLayer::HttpRequest(req);
                return;
            }
            if let Some(resp) = try_parse_http_response(payload) {
                pkt.app = AppLayer::HttpResponse(resp);
            }
        }
    }

    fn dissect_udp_app(&self, payload: &[u8], src: u16, dst: u16, pkt: &mut DissectedPacket) {
        if (src == 53 || dst == 53)
            && let Some(dns) = try_parse_dns(payload, self.max_dns_labels) {
                pkt.app = AppLayer::Dns(dns);
            }
    }
}

// ─── TCP option parser ────────────────────────────────────────────────────────

fn parse_tcp_options(data: &[u8]) -> Vec<TcpOption> {
    let mut opts = Vec::new();
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            0 => { opts.push(TcpOption::Eol); break; }
            1 => { opts.push(TcpOption::Nop); i += 1; }
            2 if i + 4 <= data.len() => {
                let mss = u16::from_be_bytes([data[i + 2], data[i + 3]]);
                opts.push(TcpOption::MaxSegmentSize(mss));
                i += 4;
            }
            3 if i + 3 <= data.len() => {
                opts.push(TcpOption::WindowScale(data[i + 2]));
                i += 3;
            }
            4 if i + 2 <= data.len() => {
                opts.push(TcpOption::SackPermitted);
                i += 2;
            }
            5 if i + 2 <= data.len() => {
                let len = data[i + 1] as usize;
                if i + len > data.len() { break; }
                let sack_data = &data[i + 2..i + len];
                let mut blocks = Vec::new();
                let mut j = 0;
                while j + 8 <= sack_data.len() {
                    let l = u32::from_be_bytes(sack_data[j..j + 4].try_into().unwrap_or([0; 4]));
                    let r = u32::from_be_bytes(sack_data[j + 4..j + 8].try_into().unwrap_or([0; 4]));
                    blocks.push((l, r));
                    j += 8;
                }
                opts.push(TcpOption::Sack(blocks));
                i += len;
            }
            8 if i + 10 <= data.len() => {
                let val = u32::from_be_bytes([data[i+2], data[i+3], data[i+4], data[i+5]]);
                let ecr = u32::from_be_bytes([data[i+6], data[i+7], data[i+8], data[i+9]]);
                opts.push(TcpOption::Timestamp { val, ecr });
                i += 10;
            }
            kind => {
                if i + 2 > data.len() { break; }
                let len = data[i + 1] as usize;
                if len < 2 || i + len > data.len() { break; }
                opts.push(TcpOption::Unknown { kind, data: data[i + 2..i + len].to_vec() });
                i += len;
            }
        }
    }
    opts
}

// ─── IPv4 checksum ────────────────────────────────────────────────────────────

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        i += 2;
    }
    if i < header.len() {
        sum += u32::from(header[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

// ─── DNS parser ───────────────────────────────────────────────────────────────

fn parse_dns_name(data: &[u8], mut offset: usize, max_labels: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumps = 0;
    let mut end_offset: Option<usize> = None;
    loop {
        if offset >= data.len() { return None; }
        let len = data[offset];
        if len == 0 {
            if end_offset.is_none() { end_offset = Some(offset + 1); }
            break;
        }
        if len & 0xc0 == 0xc0 {
            // Pointer
            if offset + 2 > data.len() { return None; }
            if end_offset.is_none() { end_offset = Some(offset + 2); }
            let ptr = ((len as usize & 0x3f) << 8) | data[offset + 1] as usize;
            offset = ptr;
            jumps += 1;
            if jumps > 20 { return None; } // loop guard
        } else {
            let label_len = len as usize;
            offset += 1;
            if offset + label_len > data.len() { return None; }
            labels.push(String::from_utf8_lossy(&data[offset..offset + label_len]).into_owned());
            offset += label_len;
            if labels.len() > max_labels { return None; }
        }
    }
    let name = if labels.is_empty() { ".".to_string() } else { labels.join(".") };
    Some((name, end_offset.unwrap_or(offset)))
}

fn parse_dns_record(data: &[u8], offset: usize, max_labels: usize) -> Option<(DnsRecord, usize)> {
    let (name, after_name) = parse_dns_name(data, offset, max_labels)?;
    if after_name + 10 > data.len() { return None; }
    let rtype = u16::from_be_bytes([data[after_name], data[after_name + 1]]);
    let class = u16::from_be_bytes([data[after_name + 2], data[after_name + 3]]);
    let ttl   = u32::from_be_bytes([data[after_name + 4], data[after_name + 5], data[after_name + 6], data[after_name + 7]]);
    let rdlen = u16::from_be_bytes([data[after_name + 8], data[after_name + 9]]) as usize;
    let rdata_start = after_name + 10;
    if rdata_start + rdlen > data.len() { return None; }
    let rdata = data[rdata_start..rdata_start + rdlen].to_vec();
    Some((DnsRecord { name, rtype, class, ttl, rdata }, rdata_start + rdlen))
}

fn try_parse_dns(data: &[u8], max_labels: usize) -> Option<DnsMessage> {
    if data.len() < 12 { return None; }
    let id    = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcnt = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancnt = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscnt = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcnt = u16::from_be_bytes([data[10], data[11]]) as usize;
    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0xf) as u8;
    let mut offset = 12;
    let mut questions = Vec::new();
    let mut answers = Vec::new();
    let mut authority = Vec::new();
    let mut additional = Vec::new();

    for _ in 0..qdcnt.min(64) {
        let (qname, after) = parse_dns_name(data, offset, max_labels)?;
        if after + 4 > data.len() { return None; }
        let qtype  = u16::from_be_bytes([data[after], data[after + 1]]);
        let qclass = u16::from_be_bytes([data[after + 2], data[after + 3]]);
        questions.push(DnsQuestion { qname, qtype, qclass });
        offset = after + 4;
    }
    for _ in 0..ancnt.min(64) {
        let (rec, after) = parse_dns_record(data, offset, max_labels)?;
        answers.push(rec);
        offset = after;
    }
    for _ in 0..nscnt.min(32) {
        let (rec, after) = parse_dns_record(data, offset, max_labels)?;
        authority.push(rec);
        offset = after;
    }
    for _ in 0..arcnt.min(32) {
        let (rec, after) = parse_dns_record(data, offset, max_labels)?;
        additional.push(rec);
        offset = after;
    }
    Some(DnsMessage { id, flags, is_response, opcode, questions, answers, authority, additional })
}

// ─── HTTP parser ──────────────────────────────────────────────────────────────

fn try_parse_http_request(data: &[u8]) -> Option<HttpRequest> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.splitn(3, ' ');
    let method  = parts.next()?.to_string();
    let uri     = parts.next()?.to_string();
    let version = parts.next()?.to_string();
    if !version.starts_with("HTTP/") { return None; }
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() { break; }
        if let Some((k, v)) = line.split_once(": ") {
            headers.insert(k.to_lowercase(), v.to_string());
        }
    }
    Some(HttpRequest { method, uri, version, headers })
}

fn try_parse_http_response(data: &[u8]) -> Option<HttpResponse> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?;
    if !status_line.starts_with("HTTP/") { return None; }
    let mut parts = status_line.splitn(3, ' ');
    let version     = parts.next()?.to_string();
    let status_str  = parts.next()?;
    let reason      = parts.next().unwrap_or("").to_string();
    let status_code = status_str.parse().ok()?;
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() { break; }
        if let Some((k, v)) = line.split_once(": ") {
            headers.insert(k.to_lowercase(), v.to_string());
        }
    }
    Some(HttpResponse { version, status_code, reason, headers })
}

// ─── TLS Client Hello parser ──────────────────────────────────────────────────

fn try_parse_tls_client_hello(data: &[u8]) -> Option<TlsClientHello> {
    if data.len() < 5 { return None; }
    if data[0] != 0x16 { return None; } // content type: handshake
    let _ver = u16::from_be_bytes([data[1], data[2]]);
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len { return None; }
    let hs = &data[5..5 + record_len];
    if hs.len() < 4 { return None; }
    if hs[0] != 0x01 { return None; } // ClientHello
    let hs_len = (hs[1] as usize) << 16 | (hs[2] as usize) << 8 | hs[3] as usize;
    if hs.len() < 4 + hs_len { return None; }
    let body = &hs[4..4 + hs_len];
    if body.len() < 34 { return None; }
    let legacy_version = u16::from_be_bytes([body[0], body[1]]);
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[2..34]);
    let mut off = 34usize;
    // Session ID
    if off >= body.len() { return None; }
    let sid_len = body[off] as usize;
    off += 1;
    if off + sid_len > body.len() { return None; }
    let session_id = body[off..off + sid_len].to_vec();
    off += sid_len;
    // Cipher suites
    if off + 2 > body.len() { return None; }
    let cs_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if off + cs_len > body.len() { return None; }
    let mut cipher_suites = Vec::new();
    let mut i = 0;
    while i + 1 < cs_len {
        cipher_suites.push(u16::from_be_bytes([body[off + i], body[off + i + 1]]));
        i += 2;
    }
    off += cs_len;
    // Compression methods
    if off >= body.len() { return None; }
    let comp_len = body[off] as usize;
    off += 1;
    if off + comp_len > body.len() { return None; }
    let compression_methods = body[off..off + comp_len].to_vec();
    off += comp_len;
    // Extensions
    let mut server_name: Option<String> = None;
    let mut alpn: Vec<String> = Vec::new();
    let mut supported_versions: Vec<u16> = Vec::new();
    if off + 2 <= body.len() {
        let ext_total = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
        off += 2;
        let ext_end = off + ext_total;
        while off + 4 <= ext_end && off + 4 <= body.len() {
            let ext_type = u16::from_be_bytes([body[off], body[off + 1]]);
            let ext_len  = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
            off += 4;
            if off + ext_len > body.len() { break; }
            let ext_data = &body[off..off + ext_len];
            match ext_type {
                0 => { // SNI
                    if ext_data.len() > 5 {
                        let nm_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                        if nm_len + 5 <= ext_data.len() {
                            server_name = Some(
                                String::from_utf8_lossy(&ext_data[5..5 + nm_len]).into_owned()
                            );
                        }
                    }
                }
                16 => { // ALPN
                    let mut j = 2usize;
                    while j + 1 < ext_data.len() {
                        let plen = ext_data[j] as usize;
                        j += 1;
                        if j + plen > ext_data.len() { break; }
                        alpn.push(String::from_utf8_lossy(&ext_data[j..j + plen]).into_owned());
                        j += plen;
                    }
                }
                43 => { // supported_versions
                    if !ext_data.is_empty() {
                        let vlen = ext_data[0] as usize;
                        let mut j = 1;
                        while j + 1 < vlen + 1 && j + 1 < ext_data.len() {
                            supported_versions.push(u16::from_be_bytes([ext_data[j], ext_data[j + 1]]));
                            j += 2;
                        }
                    }
                }
                _ => {}
            }
            off += ext_len;
        }
    }
    Some(TlsClientHello {
        legacy_version, random, session_id, cipher_suites, compression_methods,
        server_name, alpn, supported_versions,
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ethernet_ipv4_udp(src_ip: [u8;4], dst_ip: [u8;4], payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet
        pkt.extend_from_slice(&[0xff; 6]); // dst mac
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4
        let ip_payload_len = 8 + payload.len();
        let ip_total = 20 + ip_payload_len;
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0); // DSCP/ECN
        pkt.extend_from_slice(&u16::try_from(ip_total).unwrap_or(u16::MAX).to_be_bytes());
        pkt.extend_from_slice(&[0, 1, 0x40, 0]); // id, flags+frag_off
        pkt.push(64); // TTL
        pkt.push(17); // UDP
        pkt.extend_from_slice(&[0, 0]); // checksum placeholder
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        // UDP
        pkt.extend_from_slice(&5000u16.to_be_bytes()); // src port
        pkt.extend_from_slice(&53u16.to_be_bytes());   // dst port (DNS)
        pkt.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap_or(u16::MAX).to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn test_dissect_ethernet_ipv4_udp() {
        let raw = make_ethernet_ipv4_udp([1,2,3,4], [8,8,8,8], &[0u8; 12]);
        let d = PacketDissector::new();
        let pkt = d.dissect(&raw);
        assert!(pkt.ethernet.is_some());
        assert!(pkt.ip4.is_some());
        assert!(pkt.udp.is_some());
        assert_eq!(pkt.udp.as_ref().unwrap().dst_port, 53);
        assert_eq!(pkt.src_ip(), Some(IpAddr::V4(Ipv4Addr::new(1,2,3,4))));
    }

    #[test]
    fn test_icmp_type_name() {
        let icmp = IcmpHeader { icmp_type: 8, code: 0, checksum: 0, rest_of_header: [0;4] };
        assert_eq!(icmp.type_name(), "EchoRequest");
    }

    #[test]
    fn test_dns_parse_query() {
        // Craft a minimal DNS query for "example.com"
        let mut dns = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR
        ];
        // QNAME: example.com
        dns.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        dns.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        dns.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        let msg = try_parse_dns(&dns, 128).unwrap();
        assert_eq!(msg.id, 0x1234);
        assert!(!msg.is_response);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].qname, "example.com");
    }

    #[test]
    fn test_http_request_parse() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let req = try_parse_http_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.uri, "/index.html");
        assert_eq!(req.headers.get("host").map(std::string::String::as_str), Some("example.com"));
    }

    #[test]
    fn test_http_response_parse() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
        let resp = try_parse_http_response(raw).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
    }

    #[test]
    fn test_broadcast_mac() {
        let eth = EthernetHeader {
            dst_mac: [0xff; 6],
            src_mac: [0x00; 6],
            ethertype: 0x0800,
            vlan_tags: vec![],
        };
        assert!(eth.is_broadcast());
        assert!(!eth.is_multicast());
    }

    #[test]
    fn test_multicast_mac() {
        let eth = EthernetHeader {
            dst_mac: [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01],
            src_mac: [0x00; 6],
            ethertype: 0x0800,
            vlan_tags: vec![],
        };
        assert!(eth.is_multicast());
        assert!(!eth.is_broadcast());
    }

    #[test]
    fn test_tcp_flags() {
        let tcp = TcpHeader {
            src_port: 1234, dst_port: 80, seq: 1, ack: 0,
            data_offset: 5, flags: 0x12, // SYN + ACK
            window: 65535, checksum: 0, urgent_ptr: 0, options: vec![],
        };
        assert!(tcp.is_syn());
        assert!(tcp.is_ack());
        assert!(!tcp.is_fin());
        assert!(!tcp.is_rst());
    }

    #[test]
    fn test_ipv4_checksum_valid() {
        // Known valid IPv4 header
        let hdr: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x3c,
            0x1c, 0x46, 0x40, 0x00,
            0x40, 0x06, 0xb1, 0xe6,
            0xac, 0x10, 0x0a, 0x63,
            0xac, 0x10, 0x0a, 0x0c,
        ];
        // Checksum of a valid header should fold to 0
        let cs = ipv4_checksum(&hdr);
        assert_eq!(cs, 0); // valid checksum
    }

    #[test]
    fn test_dissect_too_short() {
        let d = PacketDissector::new();
        let pkt = d.dissect(&[0u8; 5]);
        assert!(!pkt.errors.is_empty());
    }

    #[test]
    fn test_vlan_tagged_frame() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&[0xff; 6]); // dst
        raw.extend_from_slice(&[0x00; 6]); // src
        raw.extend_from_slice(&[0x81, 0x00]); // 802.1Q
        raw.extend_from_slice(&[0x00, 0x64]); // TCI: VID=100
        raw.extend_from_slice(&[0x08, 0x00]); // IPv4 after VLAN
        raw.extend_from_slice(&[0u8; 20]); // minimal IPv4 (will fail, but parse proceeds)
        let d = PacketDissector::new();
        let pkt = d.dissect(&raw);
        let eth = pkt.ethernet.as_ref().unwrap();
        assert_eq!(eth.vlan_tags.len(), 1);
        assert_eq!(eth.vlan_tags[0].vid, 100);
    }

    #[test]
    fn test_dns_nx_domain() {
        let flags: u16 = 0x8003; // response, NXDOMAIN
        let mut dns = vec![0x00, 0x01];
        dns.extend_from_slice(&flags.to_be_bytes());
        dns.extend_from_slice(&[0,0, 0,0, 0,0, 0,0]);
        let msg = DnsMessage {
            id: 1, flags, is_response: true, opcode: 0,
            questions: vec![], answers: vec![], authority: vec![], additional: vec![],
        };
        assert!(msg.is_nx_domain());
        assert_eq!(msg.rcode(), 3);
    }
}
