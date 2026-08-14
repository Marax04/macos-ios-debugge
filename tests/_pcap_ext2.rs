
// ─── HTTP/2 frame types ───────────────────────────────────────────────────────

/// HTTP/2 frame type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Http2FrameType {
    Data         = 0x0,
    Headers      = 0x1,
    Priority     = 0x2,
    RstStream    = 0x3,
    Settings     = 0x4,
    PushPromise  = 0x5,
    Ping         = 0x6,
    Goaway       = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
    Unknown(u8),
}

impl Http2FrameType {
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x0 => Self::Data,
            0x1 => Self::Headers,
            0x2 => Self::Priority,
            0x3 => Self::RstStream,
            0x4 => Self::Settings,
            0x5 => Self::PushPromise,
            0x6 => Self::Ping,
            0x7 => Self::Goaway,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Continuation,
            n   => Self::Unknown(n),
        }
    }
}

impl std::fmt::Display for Http2FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data         => write!(f, "DATA"),
            Self::Headers      => write!(f, "HEADERS"),
            Self::Priority     => write!(f, "PRIORITY"),
            Self::RstStream    => write!(f, "RST_STREAM"),
            Self::Settings     => write!(f, "SETTINGS"),
            Self::PushPromise  => write!(f, "PUSH_PROMISE"),
            Self::Ping         => write!(f, "PING"),
            Self::Goaway       => write!(f, "GOAWAY"),
            Self::WindowUpdate => write!(f, "WINDOW_UPDATE"),
            Self::Continuation => write!(f, "CONTINUATION"),
            Self::Unknown(n)   => write!(f, "UNKNOWN(0x{n:02x})"),
        }
    }
}

/// A parsed HTTP/2 frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Frame {
    pub length: u32,
    pub frame_type: Http2FrameType,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

/// Parse HTTP/2 frames from a byte slice.
///
/// Assumes the connection preface has been consumed.
#[must_use]
pub fn parse_http2_frames(data: &[u8]) -> Vec<Http2Frame> {
    let mut frames = Vec::new();
    let mut off = 0usize;
    while off + 9 <= data.len() {
        let length = (u32::from(data[off]) << 16) | (u32::from(data[off+1]) << 8) | u32::from(data[off+2]);
        let frame_type = Http2FrameType::from_u8(data[off+3]);
        let flags = data[off+4];
        let stream_id = u32::from_be_bytes([data[off+5] & 0x7F, data[off+6], data[off+7], data[off+8]]);
        off += 9;
        let payload_len = length as usize;
        if off + payload_len > data.len() { break; }
        let payload = data[off..off + payload_len].to_vec();
        off += payload_len;
        frames.push(Http2Frame { length, frame_type, flags, stream_id, payload });
    }
    frames
}

// ─── HPACK static table ───────────────────────────────────────────────────────

/// HPACK static header table (RFC 7541 Appendix A).
pub static HPACK_STATIC_TABLE: &[(&str, &str)] = &[
    (":authority",                   ""),
    (":method",                      "GET"),
    (":method",                      "POST"),
    (":path",                        "/"),
    (":path",                        "/index.html"),
    (":scheme",                      "http"),
    (":scheme",                      "https"),
    (":status",                      "200"),
    (":status",                      "204"),
    (":status",                      "206"),
    (":status",                      "304"),
    (":status",                      "400"),
    (":status",                      "404"),
    (":status",                      "500"),
    ("accept-charset",               ""),
    ("accept-encoding",              "gzip, deflate"),
    ("accept-language",              ""),
    ("accept-ranges",                ""),
    ("accept",                       ""),
    ("access-control-allow-origin",  ""),
    ("age",                          ""),
    ("allow",                        ""),
    ("authorization",                ""),
    ("cache-control",                ""),
    ("content-disposition",          ""),
    ("content-encoding",             ""),
    ("content-language",             ""),
    ("content-length",               ""),
    ("content-location",             ""),
    ("content-range",                ""),
    ("content-type",                 ""),
    ("cookie",                       ""),
    ("date",                         ""),
    ("etag",                         ""),
    ("expect",                       ""),
    ("expires",                      ""),
    ("from",                         ""),
    ("host",                         ""),
    ("if-match",                     ""),
    ("if-modified-since",            ""),
    ("if-none-match",                ""),
    ("if-range",                     ""),
    ("if-unmodified-since",          ""),
    ("last-modified",                ""),
    ("link",                         ""),
    ("location",                     ""),
    ("max-forwards",                 ""),
    ("proxy-authenticate",           ""),
    ("proxy-authorization",          ""),
    ("range",                        ""),
    ("referer",                      ""),
    ("refresh",                      ""),
    ("retry-after",                  ""),
    ("server",                       ""),
    ("set-cookie",                   ""),
    ("strict-transport-security",    ""),
    ("transfer-encoding",            ""),
    ("user-agent",                   ""),
    ("vary",                         ""),
    ("via",                          ""),
    ("www-authenticate",             ""),
];

/// Look up a name+value pair from the HPACK static table by 1-based index.
#[must_use]
pub fn hpack_static_lookup(idx: usize) -> Option<(&'static str, &'static str)> {
    if idx == 0 || idx > HPACK_STATIC_TABLE.len() {
        return None;
    }
    Some(HPACK_STATIC_TABLE[idx - 1])
}

// ─── Link-type extended set ────────────────────────────────────────────────────

/// Extended link types (including ones not in the original enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtLinkType {
    Ethernet      = 1,
    Raw           = 101,
    LinuxSll      = 113,
    LinuxSll2     = 276,
    Ieee80211     = 105,
    Usb           = 189,
    BluetoothHci  = 187,
    Ppp           = 9,
    Null          = 0,
}

impl ExtLinkType {
    #[must_use]
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1   => Some(Self::Ethernet),
            101 => Some(Self::Raw),
            113 => Some(Self::LinuxSll),
            276 => Some(Self::LinuxSll2),
            105 => Some(Self::Ieee80211),
            189 => Some(Self::Usb),
            187 => Some(Self::BluetoothHci),
            9   => Some(Self::Ppp),
            0   => Some(Self::Null),
            _   => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ethernet     => "LINKTYPE_ETHERNET",
            Self::Raw          => "LINKTYPE_RAW",
            Self::LinuxSll     => "LINKTYPE_LINUX_SLL",
            Self::LinuxSll2    => "LINKTYPE_LINUX_SLL2",
            Self::Ieee80211    => "LINKTYPE_IEEE802_11",
            Self::Usb          => "LINKTYPE_USB",
            Self::BluetoothHci => "LINKTYPE_BLUETOOTH_HCI_H4",
            Self::Ppp          => "LINKTYPE_PPP",
            Self::Null         => "LINKTYPE_NULL",
        }
    }
}

// ─── ICMP type/code decoder ────────────────────────────────────────────────────

/// Decode an ICMPv4 type + code to a description.
#[must_use]
pub fn icmp_type_name(icmp_type: u8, code: u8) -> &'static str {
    match (icmp_type, code) {
        (0, 0)  => "Echo Reply",
        (3, 0)  => "Destination Network Unreachable",
        (3, 1)  => "Destination Host Unreachable",
        (3, 2)  => "Destination Protocol Unreachable",
        (3, 3)  => "Destination Port Unreachable",
        (3, 4)  => "Fragmentation Required",
        (3, 5)  => "Source Route Failed",
        (3, 6)  => "Destination Network Unknown",
        (3, 7)  => "Destination Host Unknown",
        (3, 9)  => "Network Administratively Prohibited",
        (3, 10) => "Host Administratively Prohibited",
        (3, 13) => "Communication Administratively Prohibited",
        (4, 0)  => "Source Quench",
        (5, 0)  => "Redirect for Network",
        (5, 1)  => "Redirect for Host",
        (8, 0)  => "Echo Request",
        (9, 0)  => "Router Advertisement",
        (10, 0) => "Router Solicitation",
        (11, 0) => "TTL Exceeded in Transit",
        (11, 1) => "Fragment Reassembly Time Exceeded",
        (12, 0) => "Pointer indicates the error",
        (13, 0) => "Timestamp Request",
        (14, 0) => "Timestamp Reply",
        (17, 0) => "Address Mask Request",
        (18, 0) => "Address Mask Reply",
        _       => "Unknown ICMP",
    }
}

/// Decode an ICMPv6 type to a name.
#[must_use]
pub fn icmpv6_type_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        1   => "Destination Unreachable",
        2   => "Packet Too Big",
        3   => "Time Exceeded",
        4   => "Parameter Problem",
        128 => "Echo Request",
        129 => "Echo Reply",
        130 => "Multicast Listener Query",
        131 => "Multicast Listener Report",
        132 => "Multicast Listener Done",
        133 => "Router Solicitation",
        134 => "Router Advertisement",
        135 => "Neighbor Solicitation",
        136 => "Neighbor Advertisement",
        137 => "Redirect Message",
        143 => "Multicast Listener Report v2",
        148 => "Certification Path Solicitation",
        149 => "Certification Path Advertisement",
        _   => "Unknown ICMPv6",
    }
}

// ─── Ethernet frame parsing ───────────────────────────────────────────────────

/// A parsed Ethernet frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub vlan_id: Option<u16>,
    pub payload: Vec<u8>,
}

impl EtherFrame {
    /// Parse an Ethernet II frame.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 14 { return None; }
        let dst_mac = [data[0], data[1], data[2], data[3], data[4], data[5]];
        let src_mac = [data[6], data[7], data[8], data[9], data[10], data[11]];
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        // 802.1Q VLAN tag
        if ethertype == 0x8100 {
            if data.len() < 18 { return None; }
            let vlan_id = u16::from_be_bytes([data[14], data[15]]) & 0x0FFF;
            let inner_ethertype = u16::from_be_bytes([data[16], data[17]]);
            let payload = data[18..].to_vec();
            return Some(Self { dst_mac, src_mac, ethertype: inner_ethertype, vlan_id: Some(vlan_id), payload });
        }
        let payload = data[14..].to_vec();
        Some(Self { dst_mac, src_mac, ethertype, vlan_id: None, payload })
    }

    #[must_use]
    pub fn src_mac_str(&self) -> String {
        self.src_mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
    }

    #[must_use]
    pub fn dst_mac_str(&self) -> String {
        self.dst_mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
    }

    #[must_use]
    pub fn is_broadcast(&self) -> bool { self.dst_mac == [0xFF; 6] }
    #[must_use]
    pub fn is_multicast(&self) -> bool { self.dst_mac[0] & 0x01 != 0 }
}

// ─── IPv4 header parser ───────────────────────────────────────────────────────

/// A parsed IPv4 header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

impl Ipv4Header {
    /// Parse an IPv4 header from raw bytes (does not validate checksum).
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 { return None; }
        let version = data[0] >> 4;
        if version != 4 { return None; }
        let ihl = data[0] & 0x0F;
        let dscp = data[1] >> 2;
        let ecn = data[1] & 0x03;
        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags = data[6] >> 5;
        let fragment_offset = u16::from_be_bytes([data[6] & 0x1F, data[7]]);
        let ttl = data[8];
        let protocol = data[9];
        let header_checksum = u16::from_be_bytes([data[10], data[11]]);
        let src = [data[12], data[13], data[14], data[15]];
        let dst = [data[16], data[17], data[18], data[19]];
        Some(Self { version, ihl, dscp, ecn, total_length, identification, flags, fragment_offset, ttl, protocol, header_checksum, src, dst })
    }

    #[must_use]
    pub fn header_len(&self) -> usize { (self.ihl as usize) * 4 }
    #[must_use]
    pub fn src_str(&self) -> String { format!("{}.{}.{}.{}", self.src[0], self.src[1], self.src[2], self.src[3]) }
    #[must_use]
    pub fn dst_str(&self) -> String { format!("{}.{}.{}.{}", self.dst[0], self.dst[1], self.dst[2], self.dst[3]) }
    #[must_use]
    pub fn is_fragmented(&self) -> bool { self.fragment_offset > 0 || self.flags & 0x1 != 0 }
    #[must_use]
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            1  => "ICMP", 2  => "IGMP", 6  => "TCP", 17 => "UDP",
            41 => "IPv6", 47 => "GRE", 50 => "ESP", 51 => "AH",
            58 => "ICMPv6", 89 => "OSPF", 132 => "SCTP",
            _  => "Unknown",
        }
    }
}

// ─── TCP header parser ────────────────────────────────────────────────────────

/// A parsed TCP header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

impl TcpHeader {
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 { return None; }
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = data[12] >> 4;
        let flags = data[13];
        let window_size = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);
        Some(Self { src_port, dst_port, seq, ack, data_offset, flags, window_size, checksum, urgent_pointer })
    }

    #[must_use] pub fn is_syn(&self)    -> bool { self.flags & 0x02 != 0 }
    #[must_use] pub fn is_ack(&self)    -> bool { self.flags & 0x10 != 0 }
    #[must_use] pub fn is_fin(&self)    -> bool { self.flags & 0x01 != 0 }
    #[must_use] pub fn is_rst(&self)    -> bool { self.flags & 0x04 != 0 }
    #[must_use] pub fn is_psh(&self)    -> bool { self.flags & 0x08 != 0 }
    #[must_use] pub fn is_urg(&self)    -> bool { self.flags & 0x20 != 0 }
    #[must_use] pub fn header_len(&self) -> usize { (self.data_offset as usize) * 4 }
    #[must_use]
    pub fn flags_str(&self) -> String {
        let mut f = String::new();
        if self.is_syn() { f.push_str("SYN "); }
        if self.is_ack() { f.push_str("ACK "); }
        if self.is_fin() { f.push_str("FIN "); }
        if self.is_rst() { f.push_str("RST "); }
        if self.is_psh() { f.push_str("PSH "); }
        if self.is_urg() { f.push_str("URG "); }
        f.trim().to_string()
    }
}

// ─── UDP header parser ────────────────────────────────────────────────────────

/// A parsed UDP header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 { return None; }
        Some(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length:   u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
        })
    }
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.length.saturating_sub(8) as usize
    }
}

// ─── ISB / DSB block types ────────────────────────────────────────────────────

const BLOCK_TYPE_ISB: u32 = 0x0000_0005;
const BLOCK_TYPE_DSB: u32 = 0x0000_000A;

/// A PCAPNG interface statistics block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStatisticsBlock {
    pub interface_id: u32,
    pub timestamp_high: u32,
    pub timestamp_low: u32,
    pub options: Vec<(u16, Vec<u8>)>,
}

/// A PCAPNG decryption secrets block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionSecretsBlock {
    pub secrets_type: u32,
    pub secrets_data: Vec<u8>,
}

/// All PCAPNG block variants (extended).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PcapNgBlockExt {
    SectionHeader(SectionHeaderBlock),
    InterfaceDescription(InterfaceDescriptionBlock),
    EnhancedPacket(EnhancedPacketBlock),
    SimplePacket(SimplePacketBlock),
    NameResolution(NameResolutionBlock),
    InterfaceStatistics(InterfaceStatisticsBlock),
    DecryptionSecrets(DecryptionSecretsBlock),
    Unknown { block_type: u32, data: Vec<u8> },
}

// ─── Packet dissector (top-level) ─────────────────────────────────────────────

/// A fully dissected network packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissectedPacket {
    pub ts_us: u64,
    pub frame_len: usize,
    pub ether: Option<EtherFrame>,
    pub ipv4: Option<Ipv4Header>,
    pub tcp: Option<TcpHeader>,
    pub udp: Option<UdpHeader>,
    pub dns: Option<DnsMessage>,
    pub http_request: Option<HttpRequest>,
    pub http_response: Option<HttpResponse>,
    pub tls_hello: Option<TlsClientHello>,
}

impl DissectedPacket {
    /// Dissect a raw Ethernet frame.
    #[must_use]
    pub fn from_ethernet(data: &[u8], ts_us: u64) -> Self {
        let mut pkt = Self {
            ts_us, frame_len: data.len(),
            ether: None, ipv4: None, tcp: None, udp: None,
            dns: None, http_request: None, http_response: None, tls_hello: None,
        };
        let ether = match EtherFrame::parse(data) {
            Some(e) => e,
            None => return pkt,
        };
        let ip_data = ether.payload.clone();
        pkt.ether = Some(ether.clone());
        if ether.ethertype != 0x0800 { return pkt; }

        let ipv4 = match Ipv4Header::parse(&ip_data) {
            Some(h) => h,
            None    => return pkt,
        };
        let transport_off = ipv4.header_len();
        if transport_off > ip_data.len() { return pkt; }
        let transport_data = &ip_data[transport_off..];
        let proto = ipv4.protocol;
        pkt.ipv4 = Some(ipv4);

        match proto {
            6 => {
                if let Some(tcp) = TcpHeader::parse(transport_data) {
                    let payload_off = tcp.header_len();
                    let payload = transport_data.get(payload_off..).unwrap_or(&[]);
                    pkt.tcp = Some(tcp);
                    if !payload.is_empty() {
                        pkt.http_request = HttpRequest::parse(payload);
                        if pkt.http_request.is_none() {
                            pkt.http_response = HttpResponse::parse(payload);
                        }
                        if pkt.http_request.is_none() && pkt.http_response.is_none() {
                            pkt.tls_hello = parse_tls_client_hello(payload);
                        }
                    }
                }
            }
            17 => {
                if let Some(udp) = UdpHeader::parse(transport_data) {
                    let payload = transport_data.get(8..).unwrap_or(&[]);
                    let is_dns_port = udp.src_port == 53 || udp.dst_port == 53;
                    pkt.udp = Some(udp);
                    if is_dns_port {
                        pkt.dns = parse_dns(payload);
                    }
                }
            }
            _ => {}
        }
        pkt
    }

    /// Return a brief one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let src = self.ipv4.as_ref().map(|h| h.src_str()).unwrap_or_default();
        let dst = self.ipv4.as_ref().map(|h| h.dst_str()).unwrap_or_default();
        if let Some(tcp) = &self.tcp {
            if let Some(req) = &self.http_request {
                return format!("HTTP {} {}", req.method, req.url());
            }
            if let Some(resp) = &self.http_response {
                return format!("HTTP {} {}", resp.status_code, resp.reason);
            }
            if self.tls_hello.is_some() {
                return format!("TLS ClientHello {src} -> {dst}");
            }
            return format!("TCP {src}:{} -> {dst}:{} [{}]", tcp.src_port, tcp.dst_port, tcp.flags_str());
        }
        if let Some(udp) = &self.udp {
            if let Some(dns) = &self.dns {
                let q = dns.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
                let dir = if dns.is_response { "response" } else { "query" };
                return format!("DNS {dir} {q}");
            }
            return format!("UDP {src}:{} -> {dst}:{}", udp.src_port, udp.dst_port);
        }
        format!("IPv4 {src} -> {dst}")
    }
}

// ─── pcap-level statistics (extended) ─────────────────────────────────────────

/// Extended protocol distribution statistics from a PCAP.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolStats {
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub other_ip_packets: u64,
    pub non_ip_packets: u64,
    pub http_requests: u64,
    pub http_responses: u64,
    pub dns_queries: u64,
    pub dns_responses: u64,
    pub tls_hellos: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
}

impl ProtocolStats {
    #[must_use]
    pub fn compute(packets: &[DissectedPacket]) -> Self {
        let mut s = Self::default();
        for p in packets {
            s.total_packets += 1;
            s.total_bytes += p.frame_len as u64;
            if let Some(ipv4) = &p.ipv4 {
                match ipv4.protocol {
                    6  => s.tcp_packets += 1,
                    17 => s.udp_packets += 1,
                    1  => s.icmp_packets += 1,
                    _  => s.other_ip_packets += 1,
                }
            } else {
                s.non_ip_packets += 1;
            }
            if p.http_request.is_some()  { s.http_requests += 1; }
            if p.http_response.is_some() { s.http_responses += 1; }
            if let Some(dns) = &p.dns {
                if dns.is_response { s.dns_responses += 1; } else { s.dns_queries += 1; }
            }
            if p.tls_hello.is_some() { s.tls_hellos += 1; }
        }
        s
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod pcap_ext2_tests {
    use super::*;

    #[test]
    fn test_http2_frame_type_display() {
        assert_eq!(Http2FrameType::Data.to_string(), "DATA");
        assert_eq!(Http2FrameType::Settings.to_string(), "SETTINGS");
        assert_eq!(Http2FrameType::Goaway.to_string(), "GOAWAY");
    }

    #[test]
    fn test_http2_frame_type_from_u8() {
        assert_eq!(Http2FrameType::from_u8(0), Http2FrameType::Data);
        assert_eq!(Http2FrameType::from_u8(1), Http2FrameType::Headers);
        assert_eq!(Http2FrameType::from_u8(4), Http2FrameType::Settings);
    }

    #[test]
    fn test_parse_http2_frames_empty() {
        let frames = parse_http2_frames(&[]);
        assert!(frames.is_empty());
    }

    #[test]
    fn test_parse_http2_frames_single() {
        // Build a minimal SETTINGS frame: 9-byte header + 0 payload
        let data = [0, 0, 0, 4, 0, 0, 0, 0, 0u8];
        let frames = parse_http2_frames(&data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_type, Http2FrameType::Settings);
        assert_eq!(frames[0].length, 0);
        assert_eq!(frames[0].stream_id, 0);
    }

    #[test]
    fn test_hpack_static_lookup_idx1() {
        let (name, val) = hpack_static_lookup(1).unwrap();
        assert_eq!(name, ":authority");
        assert_eq!(val, "");
    }

    #[test]
    fn test_hpack_static_lookup_idx2() {
        let (name, val) = hpack_static_lookup(2).unwrap();
        assert_eq!(name, ":method");
        assert_eq!(val, "GET");
    }

    #[test]
    fn test_hpack_static_lookup_out_of_range() {
        assert!(hpack_static_lookup(0).is_none());
        assert!(hpack_static_lookup(9999).is_none());
    }

    #[test]
    fn test_hpack_static_table_size() {
        assert_eq!(HPACK_STATIC_TABLE.len(), 61);
    }

    #[test]
    fn test_ext_link_type_from_u32_ethernet() {
        assert_eq!(ExtLinkType::from_u32(1), Some(ExtLinkType::Ethernet));
    }

    #[test]
    fn test_ext_link_type_from_u32_linux_sll() {
        assert_eq!(ExtLinkType::from_u32(113), Some(ExtLinkType::LinuxSll));
    }

    #[test]
    fn test_ext_link_type_unknown() {
        assert!(ExtLinkType::from_u32(9999).is_none());
    }

    #[test]
    fn test_icmp_type_echo_request() {
        assert_eq!(icmp_type_name(8, 0), "Echo Request");
    }

    #[test]
    fn test_icmp_type_port_unreachable() {
        assert_eq!(icmp_type_name(3, 3), "Destination Port Unreachable");
    }

    #[test]
    fn test_icmpv6_type_echo_request() {
        assert_eq!(icmpv6_type_name(128), "Echo Request");
    }

    #[test]
    fn test_icmpv6_type_neighbor_solicitation() {
        assert_eq!(icmpv6_type_name(135), "Neighbor Solicitation");
    }

    #[test]
    fn test_ether_frame_parse_basic() {
        let mut data = vec![0u8; 14];
        data[0..6].copy_from_slice(&[0xFF; 6]); // dst = broadcast
        data[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src
        data[12..14].copy_from_slice(&[0x08, 0x00]); // ethertype = IPv4
        let frame = EtherFrame::parse(&data).unwrap();
        assert!(frame.is_broadcast());
        assert_eq!(frame.ethertype, 0x0800);
        assert_eq!(frame.src_mac_str(), "11:22:33:44:55:66");
    }

    #[test]
    fn test_ether_frame_too_short() {
        assert!(EtherFrame::parse(&[0u8; 5]).is_none());
    }

    #[test]
    fn test_ipv4_header_parse_basic() {
        let mut data = vec![0u8; 20];
        data[0] = 0x45; // version=4, IHL=5
        data[9] = 6;   // TCP
        data[12..16].copy_from_slice(&[192, 168, 1, 1]);
        data[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let h = Ipv4Header::parse(&data).unwrap();
        assert_eq!(h.version, 4);
        assert_eq!(h.protocol, 6);
        assert_eq!(h.protocol_name(), "TCP");
        assert_eq!(h.src_str(), "192.168.1.1");
        assert_eq!(h.dst_str(), "10.0.0.1");
        assert_eq!(h.header_len(), 20);
    }

    #[test]
    fn test_tcp_header_parse_syn() {
        let mut data = vec![0u8; 20];
        data[0..2].copy_from_slice(&[0x00, 0x50]); // src = 80
        data[2..4].copy_from_slice(&[0xC0, 0x00]); // dst = 49152
        data[12] = 0x50; // data offset = 5
        data[13] = 0x02; // SYN flag
        let h = TcpHeader::parse(&data).unwrap();
        assert_eq!(h.src_port, 80);
        assert!(h.is_syn());
        assert!(!h.is_ack());
        assert_eq!(h.flags_str(), "SYN");
    }

    #[test]
    fn test_udp_header_parse() {
        let data = [0x00, 0x35, 0xC0, 0x00, 0x00, 0x1C, 0x00, 0x00u8];
        let h = UdpHeader::parse(&data).unwrap();
        assert_eq!(h.src_port, 53);
        assert_eq!(h.dst_port, 0xC000);
        assert_eq!(h.length, 28);
        assert_eq!(h.payload_len(), 20);
    }

    #[test]
    fn test_protocol_stats_empty() {
        let s = ProtocolStats::compute(&[]);
        assert_eq!(s.total_packets, 0);
    }

    #[test]
    fn test_dissected_packet_summary_no_ip() {
        let pkt = DissectedPacket {
            ts_us: 0, frame_len: 14,
            ether: None, ipv4: None, tcp: None, udp: None,
            dns: None, http_request: None, http_response: None, tls_hello: None,
        };
        assert!(pkt.summary().len() > 0);
    }

    #[test]
    fn test_tcp_flags_str_syn_ack() {
        let mut h = TcpHeader::parse(&vec![0u8; 20]).unwrap();
        h.data_offset = 5;
        h.flags = 0x12; // SYN | ACK
        assert!(h.flags_str().contains("SYN"));
        assert!(h.flags_str().contains("ACK"));
    }
}
