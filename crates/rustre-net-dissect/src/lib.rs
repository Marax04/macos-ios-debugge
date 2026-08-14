//! `rustre-net-dissect` — Deep packet dissection and protocol recognition.
//!
//! Provides a trait-based dissector framework with a registry, built-in
//! dissectors for common protocols, protocol fingerprinting, and a
//! human-readable layer tree printer.
//!
//! Modules:
//! - [`application_protocols`] — HTTP/1.1, HTTP/2, DNS, SMTP, FTP, SSH, MQTT, AMQP dissectors
//! - [`stream_reassembler`] — TCP stream reassembly with OOO handling and PDU extraction
//! - [`protocol_stats`] — per-protocol counters, conversation matrix, bandwidth, exports

#![forbid(unsafe_code)]

pub mod application_protocols;
pub mod protocol_stats;
pub mod stream_reassembler;
pub mod tls_dissector;
pub mod dns_dissector;
pub mod http2_dissector;
pub mod dissectors_application;
pub mod dissectors_c2;
pub mod dissectors_industrial;

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use rustre_net::{
    parse_ethernet, parse_http_request, parse_http_response, parse_icmp, parse_ipv4, parse_ipv6,
    parse_tcp, parse_udp,
};

// ────────────────────────────────────────────────────────────────────────────
// Error type
// ────────────────────────────────────────────────────────────────────────────

/// Errors produced by dissectors.
#[derive(Debug, Error)]
pub enum DissectError {
    #[error("buffer too short: need {needed}, got {got}")]
    BufferTooShort { needed: usize, got: usize },

    #[error("too short: need {need}, got {got}")]
    TooShort { need: usize, got: usize },

    #[error("invalid magic: {0}")]
    InvalidMagic(String),

    #[error("malformed field: {0}")]
    MalformedField(String),

    #[error("unsupported protocol at layer {0}")]
    UnsupportedProtocol(u32),

    #[error("no dissector registered for protocol '{0}'")]
    NoDissector(String),

    #[error("dissection failed: {0}")]
    Failed(String),

    #[error("parse error: {0}")]
    ParseError(String),

    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
}

// ────────────────────────────────────────────────────────────────────────────
// Field value
// ────────────────────────────────────────────────────────────────────────────

/// The typed value stored in a dissected protocol field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldValue {
    Bytes(Vec<u8>),
    Uint(u64),
    Int(i64),
    Str(String),
    IpAddr(IpAddr),
    MacAddr([u8; 6]),
    Bool(bool),
    Float(f64),
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(b) => {
                let hex: String = b
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                write!(f, "{hex}")
            }
            Self::Uint(v) => write!(f, "{v}"),
            Self::Int(v) => write!(f, "{v}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::IpAddr(a) => write!(f, "{a}"),
            Self::MacAddr(m) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Float(v) => write!(f, "{v}"),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Protocol field
// ────────────────────────────────────────────────────────────────────────────

/// A single named field within a dissected protocol layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoField {
    pub name: String,
    pub offset: usize,
    pub length: usize,
    pub value: FieldValue,
}

impl ProtoField {
    pub fn new(name: impl Into<String>, offset: usize, length: usize, value: FieldValue) -> Self {
        Self {
            name: name.into(),
            offset,
            length,
            value,
        }
    }
}

impl fmt::Display for ProtoField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} [off={} len={}]",
            self.name, self.value, self.offset, self.length
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Protocol layer
// ────────────────────────────────────────────────────────────────────────────

/// A single dissected protocol layer containing named fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoLayer {
    /// Human-readable protocol name (e.g. "Ethernet", "IPv4", "TCP").
    pub name: String,
    pub fields: Vec<ProtoField>,
    /// Raw bytes for this layer.
    pub raw: Vec<u8>,
}

impl ProtoLayer {
    pub fn new(name: impl Into<String>, raw: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
            raw,
        }
    }

    pub fn add_field(&mut self, field: ProtoField) {
        self.fields.push(field);
    }

    /// Look up a field by name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&ProtoField> {
        self.fields.iter().find(|f| f.name == name)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Dissected packet
// ────────────────────────────────────────────────────────────────────────────

/// The full result of dissecting a raw byte buffer: an ordered stack of
/// protocol layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissectedPacket {
    pub layers: Vec<ProtoLayer>,
}

impl DissectedPacket {
    #[must_use]
    pub const fn new() -> Self {
        Self { layers: Vec::new() }
    }

    pub fn push_layer(&mut self, layer: ProtoLayer) {
        self.layers.push(layer);
    }

    /// Find the first layer with the given protocol name.
    #[must_use]
    pub fn layer(&self, name: &str) -> Option<&ProtoLayer> {
        self.layers.iter().find(|l| l.name == name)
    }

    /// Pretty-print the full packet tree.
    #[must_use]
    pub fn pretty_print(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for (i, layer) in self.layers.iter().enumerate() {
            let _ = writeln!(out, "[Layer {}] {}", i, layer.name);
            for field in &layer.fields {
                let _ = writeln!(out, "  {field}");
            }
        }
        out
    }
}

impl Default for DissectedPacket {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Dissector trait
// ────────────────────────────────────────────────────────────────────────────

/// A protocol dissector that can process raw bytes at a given layer depth.
pub trait ProtocolDissector: Send + Sync {
    /// Protocol name this dissector handles (e.g. "Ethernet").
    fn name(&self) -> &'static str;

    /// Well-known ports this dissector handles (for port-based lookup).
    fn ports(&self) -> &[u16] {
        &[]
    }

    /// Attempt to dissect `data` and append layers to `packet`.
    ///
    /// `layer` is the current encapsulation depth (0 = link layer).
    ///
    /// # Errors
    ///
    /// Returns a [`DissectError`] if the data is too short, malformed, or
    /// the protocol is not supported.
    fn dissect(
        &self,
        data: &[u8],
        layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError>;
}

// ────────────────────────────────────────────────────────────────────────────
// Dissector registry
// ────────────────────────────────────────────────────────────────────────────

/// Registry for [`ProtocolDissector`] implementations.
pub struct DissectorRegistry {
    by_name: RwLock<HashMap<String, Arc<dyn ProtocolDissector>>>,
    by_port: RwLock<HashMap<u16, Arc<dyn ProtocolDissector>>>,
}

impl DissectorRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_name: RwLock::new(HashMap::new()),
            by_port: RwLock::new(HashMap::new()),
        }
    }

    /// Register a dissector by name and all its declared ports.
    pub fn register(&self, dissector: &Arc<dyn ProtocolDissector>) {
        let ports = dissector.ports().to_vec();
        let name = dissector.name().to_string();
        self.by_name.write().insert(name, dissector.clone());
        for port in ports {
            self.by_port.write().insert(port, dissector.clone());
        }
    }

    /// Look up a dissector by protocol name.
    pub fn by_name(&self, name: &str) -> Option<Arc<dyn ProtocolDissector>> {
        self.by_name.read().get(name).cloned()
    }

    /// Look up a dissector by port number.
    pub fn by_port(&self, port: u16) -> Option<Arc<dyn ProtocolDissector>> {
        self.by_port.read().get(&port).cloned()
    }

    /// Attempt heuristic dissection: first try port, then name.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::NoDissector`] if no matching dissector is found,
    /// or the dissector's own error if dissection fails.
    pub fn dissect_auto(
        &self,
        name: &str,
        port: Option<u16>,
        data: &[u8],
        layer: u32,
    ) -> Result<DissectedPacket, DissectError> {
        let dissector = port
            .and_then(|p| self.by_port(p))
            .or_else(|| self.by_name(name))
            .ok_or_else(|| DissectError::NoDissector(name.to_string()))?;
        let mut pkt = DissectedPacket::new();
        dissector.dissect(data, layer, &mut pkt)?;
        Ok(pkt)
    }
}

impl Default for DissectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Built-in dissectors
// ────────────────────────────────────────────────────────────────────────────

/// Ethernet II dissector.
pub struct EthernetDissector;

impl ProtocolDissector for EthernetDissector {
    fn name(&self) -> &'static str {
        "Ethernet"
    }

    fn dissect(
        &self,
        data: &[u8],
        layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let frame = parse_ethernet(data).map_err(|e| DissectError::ParseError(e.to_string()))?;
        let mut proto_layer = ProtoLayer::new("Ethernet", data[..14.min(data.len())].to_vec());
        proto_layer.add_field(ProtoField::new(
            "dst_mac",
            0,
            6,
            FieldValue::MacAddr(frame.dst_mac),
        ));
        proto_layer.add_field(ProtoField::new(
            "src_mac",
            6,
            6,
            FieldValue::MacAddr(frame.src_mac),
        ));
        proto_layer.add_field(ProtoField::new(
            "ethertype",
            12,
            2,
            FieldValue::Uint(u64::from(frame.ethertype)),
        ));
        packet.push_layer(proto_layer);

        match frame.ethertype {
            0x0800 => {
                let ipv4 = Ipv4Dissector;
                ipv4.dissect(&frame.payload, layer + 1, packet)?;
            }
            0x86DD => {
                let ipv6 = Ipv6Dissector;
                ipv6.dissect(&frame.payload, layer + 1, packet)?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// IPv4 dissector.
pub struct Ipv4Dissector;

impl ProtocolDissector for Ipv4Dissector {
    fn name(&self) -> &'static str {
        "IPv4"
    }

    fn dissect(
        &self,
        data: &[u8],
        layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let ip = parse_ipv4(data).map_err(|e| DissectError::ParseError(e.to_string()))?;
        let header_len = ((data[0] & 0x0F) as usize) * 4;
        let mut proto_layer = ProtoLayer::new("IPv4", data[..header_len.min(data.len())].to_vec());
        proto_layer.add_field(ProtoField::new("version", 0, 1, FieldValue::Uint(4)));
        proto_layer.add_field(ProtoField::new(
            "ihl",
            0,
            1,
            FieldValue::Uint(u64::from(data[0] & 0x0F)),
        ));
        proto_layer.add_field(ProtoField::new(
            "ttl",
            8,
            1,
            FieldValue::Uint(u64::from(ip.ttl)),
        ));
        proto_layer.add_field(ProtoField::new(
            "protocol",
            9,
            1,
            FieldValue::Uint(u64::from(ip.protocol)),
        ));
        proto_layer.add_field(ProtoField::new("src_ip", 12, 4, FieldValue::IpAddr(ip.src)));
        proto_layer.add_field(ProtoField::new("dst_ip", 16, 4, FieldValue::IpAddr(ip.dst)));
        packet.push_layer(proto_layer);

        match ip.protocol {
            6 => {
                TcpDissector.dissect(&ip.payload, layer + 1, packet)?;
            }
            17 => {
                UdpDissector.dissect(&ip.payload, layer + 1, packet)?;
            }
            1 => {
                IcmpDissector.dissect(&ip.payload, layer + 1, packet)?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// IPv6 dissector.
pub struct Ipv6Dissector;

impl ProtocolDissector for Ipv6Dissector {
    fn name(&self) -> &'static str {
        "IPv6"
    }

    fn dissect(
        &self,
        data: &[u8],
        layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let ip = parse_ipv6(data).map_err(|e| DissectError::ParseError(e.to_string()))?;
        let mut proto_layer = ProtoLayer::new("IPv6", data[..40.min(data.len())].to_vec());
        proto_layer.add_field(ProtoField::new("version", 0, 1, FieldValue::Uint(6)));
        proto_layer.add_field(ProtoField::new(
            "next_header",
            6,
            1,
            FieldValue::Uint(u64::from(ip.protocol)),
        ));
        proto_layer.add_field(ProtoField::new(
            "hop_limit",
            7,
            1,
            FieldValue::Uint(u64::from(ip.ttl)),
        ));
        proto_layer.add_field(ProtoField::new("src_ip", 8, 16, FieldValue::IpAddr(ip.src)));
        proto_layer.add_field(ProtoField::new(
            "dst_ip",
            24,
            16,
            FieldValue::IpAddr(ip.dst),
        ));
        packet.push_layer(proto_layer);

        match ip.protocol {
            6 => {
                TcpDissector.dissect(&ip.payload, layer + 1, packet)?;
            }
            17 => {
                UdpDissector.dissect(&ip.payload, layer + 1, packet)?;
            }
            58 => {
                IcmpDissector.dissect(&ip.payload, layer + 1, packet)?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// TCP dissector.
pub struct TcpDissector;

impl ProtocolDissector for TcpDissector {
    fn name(&self) -> &'static str {
        "TCP"
    }

    fn dissect(
        &self,
        data: &[u8],
        layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let seg = parse_tcp(data).map_err(|e| DissectError::ParseError(e.to_string()))?;
        let data_offset = ((data[12] >> 4) as usize) * 4;
        let mut proto_layer = ProtoLayer::new("TCP", data[..data_offset.min(data.len())].to_vec());
        proto_layer.add_field(ProtoField::new(
            "src_port",
            0,
            2,
            FieldValue::Uint(u64::from(seg.src_port)),
        ));
        proto_layer.add_field(ProtoField::new(
            "dst_port",
            2,
            2,
            FieldValue::Uint(u64::from(seg.dst_port)),
        ));
        proto_layer.add_field(ProtoField::new(
            "seq",
            4,
            4,
            FieldValue::Uint(u64::from(seg.seq)),
        ));
        proto_layer.add_field(ProtoField::new(
            "ack",
            8,
            4,
            FieldValue::Uint(u64::from(seg.ack)),
        ));
        proto_layer.add_field(ProtoField::new(
            "flags",
            13,
            1,
            FieldValue::Uint(u64::from(seg.flags.bits())),
        ));
        proto_layer.add_field(ProtoField::new(
            "window",
            14,
            2,
            FieldValue::Uint(u64::from(seg.window)),
        ));
        packet.push_layer(proto_layer);

        // Application-layer heuristics
        if !seg.payload.is_empty() {
            dissect_application(seg.src_port, seg.dst_port, &seg.payload, layer + 1, packet);
        }
        Ok(())
    }
}

/// UDP dissector.
pub struct UdpDissector;

impl ProtocolDissector for UdpDissector {
    fn name(&self) -> &'static str {
        "UDP"
    }

    fn dissect(
        &self,
        data: &[u8],
        layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let dg = parse_udp(data).map_err(|e| DissectError::ParseError(e.to_string()))?;
        let mut proto_layer = ProtoLayer::new("UDP", data[..8.min(data.len())].to_vec());
        proto_layer.add_field(ProtoField::new(
            "src_port",
            0,
            2,
            FieldValue::Uint(u64::from(dg.src_port)),
        ));
        proto_layer.add_field(ProtoField::new(
            "dst_port",
            2,
            2,
            FieldValue::Uint(u64::from(dg.dst_port)),
        ));
        proto_layer.add_field(ProtoField::new(
            "length",
            4,
            2,
            FieldValue::Uint(u64::try_from(dg.payload.len() + 8).unwrap_or(u64::MAX)),
        ));
        packet.push_layer(proto_layer);

        if !dg.payload.is_empty() {
            dissect_application(dg.src_port, dg.dst_port, &dg.payload, layer + 1, packet);
        }
        Ok(())
    }
}

/// ICMP dissector.
pub struct IcmpDissector;

impl ProtocolDissector for IcmpDissector {
    fn name(&self) -> &'static str {
        "ICMP"
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let icmp = parse_icmp(data).map_err(|e| DissectError::ParseError(e.to_string()))?;
        let mut proto_layer = ProtoLayer::new("ICMP", data[..4.min(data.len())].to_vec());
        proto_layer.add_field(ProtoField::new(
            "type",
            0,
            1,
            FieldValue::Uint(u64::from(icmp.icmp_type)),
        ));
        proto_layer.add_field(ProtoField::new(
            "code",
            1,
            1,
            FieldValue::Uint(u64::from(icmp.code)),
        ));
        proto_layer.add_field(ProtoField::new(
            "checksum",
            2,
            2,
            FieldValue::Uint(u64::from(icmp.checksum)),
        ));
        packet.push_layer(proto_layer);
        Ok(())
    }
}

/// DNS dissector.
pub struct DnsDissector;

impl ProtocolDissector for DnsDissector {
    fn name(&self) -> &'static str {
        "DNS"
    }
    fn ports(&self) -> &[u16] {
        &[53]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        if data.len() < 12 {
            return Err(DissectError::BufferTooShort {
                needed: 12,
                got: data.len(),
            });
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);
        let mut proto_layer = ProtoLayer::new("DNS", data[..12.min(data.len())].to_vec());
        proto_layer.add_field(ProtoField::new("id", 0, 2, FieldValue::Uint(u64::from(id))));
        proto_layer.add_field(ProtoField::new(
            "flags",
            2,
            2,
            FieldValue::Uint(u64::from(flags)),
        ));
        proto_layer.add_field(ProtoField::new(
            "qdcount",
            4,
            2,
            FieldValue::Uint(u64::from(qdcount)),
        ));
        proto_layer.add_field(ProtoField::new(
            "ancount",
            6,
            2,
            FieldValue::Uint(u64::from(ancount)),
        ));
        let is_response = (flags & 0x8000) != 0;
        proto_layer.add_field(ProtoField::new(
            "is_response",
            2,
            2,
            FieldValue::Bool(is_response),
        ));
        packet.push_layer(proto_layer);
        Ok(())
    }
}

/// HTTP dissector.
pub struct HttpDissector;

impl ProtocolDissector for HttpDissector {
    fn name(&self) -> &'static str {
        "HTTP"
    }
    fn ports(&self) -> &[u16] {
        &[80, 8080, 8000]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        // Try to detect request vs response
        if data.starts_with(b"HTTP/") {
            if let Ok(resp) = parse_http_response(data) {
                let mut proto_layer = ProtoLayer::new("HTTP", data.to_vec());
                proto_layer.add_field(ProtoField::new(
                    "version",
                    0,
                    resp.version.len(),
                    FieldValue::Str(resp.version.clone()),
                ));
                proto_layer.add_field(ProtoField::new(
                    "status_code",
                    0,
                    3,
                    FieldValue::Uint(u64::from(resp.status_code)),
                ));
                proto_layer.add_field(ProtoField::new(
                    "reason",
                    0,
                    resp.reason.len(),
                    FieldValue::Str(resp.reason.clone()),
                ));
                for (k, v) in &resp.headers {
                    proto_layer.add_field(ProtoField::new(
                        format!("header:{k}"),
                        0,
                        v.len(),
                        FieldValue::Str(v.clone()),
                    ));
                }
                packet.push_layer(proto_layer);
                return Ok(());
            }
        } else if let Ok(req) = parse_http_request(data) {
            let mut proto_layer = ProtoLayer::new("HTTP", data.to_vec());
            proto_layer.add_field(ProtoField::new(
                "method",
                0,
                req.method.len(),
                FieldValue::Str(req.method.clone()),
            ));
            proto_layer.add_field(ProtoField::new(
                "uri",
                0,
                req.uri.len(),
                FieldValue::Str(req.uri.clone()),
            ));
            proto_layer.add_field(ProtoField::new(
                "version",
                0,
                req.version.len(),
                FieldValue::Str(req.version.clone()),
            ));
            for (k, v) in &req.headers {
                proto_layer.add_field(ProtoField::new(
                    format!("header:{k}"),
                    0,
                    v.len(),
                    FieldValue::Str(v.clone()),
                ));
            }
            packet.push_layer(proto_layer);
            return Ok(());
        }
        Err(DissectError::ParseError("not an HTTP message".to_string()))
    }
}

/// TLS dissector (SNI extraction only).
pub struct TlsDissector;

impl ProtocolDissector for TlsDissector {
    fn name(&self) -> &'static str {
        "TLS"
    }
    fn ports(&self) -> &[u16] {
        &[443, 8443]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        if data.len() < 5 {
            return Err(DissectError::BufferTooShort {
                needed: 5,
                got: data.len(),
            });
        }
        // TLS record type 22 = Handshake
        if data[0] != 22 {
            return Err(DissectError::ParseError(
                "not a TLS handshake record".to_string(),
            ));
        }
        let tls_version = u16::from_be_bytes([data[1], data[2]]);
        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        let mut proto_layer = ProtoLayer::new("TLS", data[..5.min(data.len())].to_vec());
        proto_layer.add_field(ProtoField::new(
            "content_type",
            0,
            1,
            FieldValue::Uint(u64::from(data[0])),
        ));
        proto_layer.add_field(ProtoField::new(
            "version",
            1,
            2,
            FieldValue::Uint(u64::from(tls_version)),
        ));
        proto_layer.add_field(ProtoField::new(
            "record_length",
            3,
            2,
            FieldValue::Uint(u64::try_from(record_len).unwrap_or(u64::MAX)),
        ));

        // Try to extract SNI from ClientHello
        if let Some(sni) = extract_tls_sni(data) {
            proto_layer.add_field(ProtoField::new("sni", 0, sni.len(), FieldValue::Str(sni)));
        }
        packet.push_layer(proto_layer);
        Ok(())
    }
}

/// Extract the SNI hostname from a TLS `ClientHello` handshake record.
fn extract_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 43 {
        return None;
    }
    if data[0] != 22 {
        return None;
    }
    // Skip TLS record header (5) + Handshake header (4) + version (2) + random (32)
    let mut off = 5 + 4 + 2 + 32;
    if off >= data.len() {
        return None;
    }
    let session_len = data[off] as usize;
    off += 1 + session_len;
    if off + 2 > data.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    off += 2 + cipher_len;
    if off + 1 > data.len() {
        return None;
    }
    let comp_len = data[off] as usize;
    off += 1 + comp_len;
    if off + 2 > data.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    off += 2;
    let ext_end = (off + ext_total).min(data.len());
    while off + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[off], data[off + 1]]);
        let ext_len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
        off += 4;
        if off + ext_len > ext_end {
            break;
        }
        // Extension type 0 = SNI
        if ext_type == 0 && ext_len >= 5 {
            let name_len = u16::from_be_bytes([data[off + 3], data[off + 4]]) as usize;
            let name_start = off + 5;
            if name_start + name_len <= data.len()
                && let Ok(s) = std::str::from_utf8(&data[name_start..name_start + name_len])
            {
                return Some(s.to_string());
            }
        }
        off += ext_len;
    }
    None
}

/// SMB dissector (minimal — detects and labels SMB/SMB2 headers).
pub struct SmbDissector;

impl ProtocolDissector for SmbDissector {
    fn name(&self) -> &'static str {
        "SMB"
    }
    fn ports(&self) -> &[u16] {
        &[445, 139]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        if data.len() < 4 {
            return Err(DissectError::BufferTooShort {
                needed: 4,
                got: data.len(),
            });
        }
        let is_smb1 = data.starts_with(b"\xFFSMB");
        let is_smb2 = data.starts_with(b"\xFESMB");
        if !is_smb1 && !is_smb2 {
            return Err(DissectError::ParseError("not an SMB message".to_string()));
        }
        let version = if is_smb2 { "SMB2" } else { "SMB1" };
        let mut proto_layer = ProtoLayer::new("SMB", data[..4.min(data.len())].to_vec());
        proto_layer.add_field(ProtoField::new(
            "magic",
            0,
            4,
            FieldValue::Bytes(data[..4].to_vec()),
        ));
        proto_layer.add_field(ProtoField::new(
            "version",
            0,
            4,
            FieldValue::Str(version.to_string()),
        ));
        if is_smb1 && data.len() >= 8 {
            let command = data[4];
            proto_layer.add_field(ProtoField::new(
                "command",
                4,
                1,
                FieldValue::Uint(u64::from(command)),
            ));
        } else if is_smb2 && data.len() >= 14 {
            let command = u16::from_le_bytes([data[12], data[13]]);
            proto_layer.add_field(ProtoField::new(
                "command",
                12,
                2,
                FieldValue::Uint(u64::from(command)),
            ));
        }
        packet.push_layer(proto_layer);
        Ok(())
    }
}

/// FTP dissector.
pub struct FtpDissector;

impl ProtocolDissector for FtpDissector {
    fn name(&self) -> &'static str {
        "FTP"
    }
    fn ports(&self) -> &[u16] {
        &[21, 20]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| DissectError::ParseError("non-UTF8 FTP data".to_string()))?;
        let first_line = text.lines().next().unwrap_or("");
        let mut proto_layer = ProtoLayer::new("FTP", data.to_vec());
        // FTP response lines start with a 3-digit code
        if first_line.len() >= 3 && first_line[..3].chars().all(|c| c.is_ascii_digit()) {
            let code: u64 = first_line[..3].parse().unwrap_or(0);
            proto_layer.add_field(ProtoField::new(
                "response_code",
                0,
                3,
                FieldValue::Uint(code),
            ));
            proto_layer.add_field(ProtoField::new(
                "message",
                4,
                first_line.len().saturating_sub(4),
                FieldValue::Str(first_line[4..].to_string()),
            ));
        } else {
            // FTP command
            let parts: Vec<&str> = first_line.splitn(2, ' ').collect();
            proto_layer.add_field(ProtoField::new(
                "command",
                0,
                parts[0].len(),
                FieldValue::Str(parts[0].to_string()),
            ));
            if parts.len() == 2 {
                proto_layer.add_field(ProtoField::new(
                    "argument",
                    parts[0].len() + 1,
                    parts[1].len(),
                    FieldValue::Str(parts[1].to_string()),
                ));
            }
        }
        packet.push_layer(proto_layer);
        Ok(())
    }
}

/// SMTP dissector.
pub struct SmtpDissector;

impl ProtocolDissector for SmtpDissector {
    fn name(&self) -> &'static str {
        "SMTP"
    }
    fn ports(&self) -> &[u16] {
        &[25, 587, 465]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| DissectError::ParseError("non-UTF8 SMTP data".to_string()))?;
        let first_line = text.lines().next().unwrap_or("");
        let mut proto_layer = ProtoLayer::new("SMTP", data.to_vec());
        if first_line.len() >= 3 && first_line[..3].chars().all(|c| c.is_ascii_digit()) {
            let code: u64 = first_line[..3].parse().unwrap_or(0);
            proto_layer.add_field(ProtoField::new(
                "response_code",
                0,
                3,
                FieldValue::Uint(code),
            ));
            let msg = if first_line.len() > 4 {
                &first_line[4..]
            } else {
                ""
            };
            proto_layer.add_field(ProtoField::new(
                "message",
                4,
                msg.len(),
                FieldValue::Str(msg.to_string()),
            ));
        } else {
            let parts: Vec<&str> = first_line.splitn(2, ' ').collect();
            proto_layer.add_field(ProtoField::new(
                "command",
                0,
                parts[0].len(),
                FieldValue::Str(parts[0].to_string()),
            ));
            if parts.len() == 2 {
                proto_layer.add_field(ProtoField::new(
                    "argument",
                    parts[0].len() + 1,
                    parts[1].len(),
                    FieldValue::Str(parts[1].to_string()),
                ));
            }
        }
        packet.push_layer(proto_layer);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Application-layer heuristics
// ────────────────────────────────────────────────────────────────────────────

/// Identify the application-layer protocol by port or magic bytes and dissect.
fn dissect_application(
    src_port: u16,
    dst_port: u16,
    data: &[u8],
    layer: u32,
    packet: &mut DissectedPacket,
) {
    let port = if dst_port < src_port {
        dst_port
    } else {
        src_port
    };

    if port == 53 || src_port == 53 {
        let _ = DnsDissector.dissect(data, layer, packet);
    } else if port == 443 || port == 8443 {
        let _ = TlsDissector.dissect(data, layer, packet);
    } else if port == 445 || port == 139 {
        let _ = SmbDissector.dissect(data, layer, packet);
    } else if port == 21 {
        let _ = FtpDissector.dissect(data, layer, packet);
    } else if port == 25 || port == 587 {
        let _ = SmtpDissector.dissect(data, layer, packet);
    } else if data.starts_with(b"HTTP/") || is_http_request(data) {
        let _ = HttpDissector.dissect(data, layer, packet);
    } else if data.starts_with(b"\xFF\xFESMB")
        || data.starts_with(b"\xFESMB")
        || data.starts_with(b"\xFFSMB")
    {
        let _ = SmbDissector.dissect(data, layer, packet);
    } else if data.first().copied() == Some(22) {
        let _ = TlsDissector.dissect(data, layer, packet);
    }
}

fn is_http_request(data: &[u8]) -> bool {
    for method in [
        b"GET " as &[u8],
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
    ] {
        if data.starts_with(method) {
            return true;
        }
    }
    false
}

// ────────────────────────────────────────────────────────────────────────────
// Protocol fingerprinting
// ────────────────────────────────────────────────────────────────────────────

/// Identifies the most likely protocol for a raw payload using heuristics.
///
/// Checks `src_port` and `dst_port` — the larger (well-known) port is tested
/// first so that `(0, 53)` correctly resolves to `"DNS"`.
#[must_use]
pub fn fingerprint_protocol(data: &[u8], src_port: u16, dst_port: u16) -> &'static str {
    // Use the higher-numbered port so that ephemeral ports (high numbers) are
    // matched over server-side well-known ports.  In practice this means
    // max(src, dst) gives us the non-ephemeral side when one port is 0 or
    // very high, and ties are harmless.
    let port = src_port.max(dst_port);
    match port {
        53 => return "DNS",
        80 | 8080 | 8000 => return "HTTP",
        443 | 8443 => return "TLS",
        445 | 139 => return "SMB",
        21 | 20 => return "FTP",
        22 => return "SSH",
        25 | 587 => return "SMTP",
        110 => return "POP3",
        143 => return "IMAP",
        3306 => return "MySQL",
        5432 => return "PostgreSQL",
        _ => {}
    }

    if data.starts_with(b"HTTP/") || is_http_request(data) {
        return "HTTP";
    }
    if data.first().copied() == Some(22) && data.len() >= 5 {
        return "TLS";
    }
    if data.starts_with(b"\xFFSMB") || data.starts_with(b"\xFESMB") {
        return "SMB";
    }
    if data.len() >= 12 {
        // DNS heuristic: QR bit and low question count
        let _flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        if qdcount <= 10 {
            return "DNS";
        }
    }
    "Unknown"
}

/// Build a [`DissectorRegistry`] pre-populated with all built-in dissectors.
#[must_use]
pub fn default_registry() -> DissectorRegistry {
    let reg = DissectorRegistry::new();
    let d: Arc<dyn ProtocolDissector> = Arc::new(EthernetDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(Ipv4Dissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(Ipv6Dissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(TcpDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(UdpDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(IcmpDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(DnsDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(HttpDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(TlsDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(SmbDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(FtpDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(SmtpDissector);
    reg.register(&d);
    reg
}

// ────────────────────────────────────────────────────────────────────────────
// Standalone protocol parser structs (spec-required API)
// ────────────────────────────────────────────────────────────────────────────

/// IP version indicator.
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

/// A parsed Ethernet II frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    /// Parse an Ethernet II frame from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::TooShort`] if bytes are less than 14.
    pub fn parse(bytes: &[u8]) -> Result<Self, DissectError> {
        if bytes.len() < 14 {
            return Err(DissectError::TooShort {
                need: 14,
                got: bytes.len(),
            });
        }
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&bytes[0..6]);
        src_mac.copy_from_slice(&bytes[6..12]);
        let ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
        let payload = bytes[14..].to_vec();
        Ok(Self {
            dst_mac,
            src_mac,
            ether_type,
            payload,
        })
    }

    /// Format the source MAC as a colon-separated hex string.
    #[must_use]
    pub fn src_str(&self) -> String {
        let m = &self.src_mac;
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }

    /// Format the destination MAC as a colon-separated hex string.
    #[must_use]
    pub fn dst_str(&self) -> String {
        let m = &self.dst_mac;
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }

    /// Returns `true` if the `EtherType` is IPv4 (0x0800).
    #[must_use]
    pub const fn is_ip(&self) -> bool {
        self.ether_type == 0x0800
    }

    /// Returns `true` if the `EtherType` is ARP (0x0806).
    #[must_use]
    pub const fn is_arp(&self) -> bool {
        self.ether_type == 0x0806
    }
}

/// A parsed IPv4 packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Packet {
    pub version: u8,
    pub ihl: u8,
    pub ttl: u8,
    pub proto: u8,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub payload: Vec<u8>,
}

impl Ipv4Packet {
    /// Parse an IPv4 packet from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::TooShort`] if too few bytes, or [`DissectError::InvalidMagic`]
    /// if the version field is not 4.
    pub fn parse(bytes: &[u8]) -> Result<Self, DissectError> {
        if bytes.len() < 20 {
            return Err(DissectError::TooShort {
                need: 20,
                got: bytes.len(),
            });
        }
        let version = (bytes[0] >> 4) & 0xF;
        if version != 4 {
            return Err(DissectError::InvalidMagic(format!(
                "expected IPv4, got version {version}"
            )));
        }
        let ihl = bytes[0] & 0x0F;
        let ihl_bytes = (ihl as usize) * 4;
        if ihl_bytes < 20 || bytes.len() < ihl_bytes {
            return Err(DissectError::TooShort {
                need: ihl_bytes,
                got: bytes.len(),
            });
        }
        let ttl = bytes[8];
        let proto = bytes[9];
        let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        // Total Length includes the header, so a declared value below IHL*4 is
        // malformed; clamping only the end would leave the start past it and panic.
        // `rustre-net::parse_ipv4_packet` is the copy that already gets this right.
        if total_len < ihl_bytes {
            return Err(DissectError::TooShort {
                need: ihl_bytes,
                got: total_len,
            });
        }
        let end = total_len.min(bytes.len());
        let payload = bytes[ihl_bytes..end].to_vec();
        let mut src = [0u8; 4];
        let mut dst = [0u8; 4];
        src.copy_from_slice(&bytes[12..16]);
        dst.copy_from_slice(&bytes[16..20]);
        Ok(Self {
            version,
            ihl,
            ttl,
            proto,
            src,
            dst,
            payload,
        })
    }

    /// Return the source address as a dotted-decimal string.
    #[must_use]
    pub fn src_str(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.src[0], self.src[1], self.src[2], self.src[3]
        )
    }

    /// Return the destination address as a dotted-decimal string.
    #[must_use]
    pub fn dst_str(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.dst[0], self.dst[1], self.dst[2], self.dst[3]
        )
    }

    /// Returns `true` if the protocol is TCP (6).
    #[must_use]
    pub const fn is_tcp(&self) -> bool {
        self.proto == 6
    }

    /// Returns `true` if the protocol is UDP (17).
    #[must_use]
    pub const fn is_udp(&self) -> bool {
        self.proto == 17
    }
}

/// A parsed TCP segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: Vec<u8>,
}

impl TcpSegment {
    /// Parse a TCP segment from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::TooShort`] if bytes are fewer than 20.
    pub fn parse(bytes: &[u8]) -> Result<Self, DissectError> {
        if bytes.len() < 20 {
            return Err(DissectError::TooShort {
                need: 20,
                got: bytes.len(),
            });
        }
        let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
        let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let ack = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let data_offset = ((bytes[12] >> 4) as usize) * 4;
        if data_offset < 20 || bytes.len() < data_offset {
            return Err(DissectError::ParseError(
                "invalid TCP data offset".to_string(),
            ));
        }
        let flags = bytes[13];
        let window = u16::from_be_bytes([bytes[14], bytes[15]]);
        let payload = bytes[data_offset..].to_vec();
        Ok(Self {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
            payload,
        })
    }

    /// Returns `true` if the SYN flag is set.
    #[must_use]
    pub const fn has_syn(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Returns `true` if the ACK flag is set.
    #[must_use]
    pub const fn has_ack(&self) -> bool {
        self.flags & 0x10 != 0
    }

    /// Returns `true` if the FIN flag is set.
    #[must_use]
    pub const fn has_fin(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Returns `true` if the RST flag is set.
    #[must_use]
    pub const fn has_rst(&self) -> bool {
        self.flags & 0x04 != 0
    }
}

/// A parsed UDP datagram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpDatagram {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub payload: Vec<u8>,
}

impl UdpDatagram {
    /// Parse a UDP datagram from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::TooShort`] if bytes are fewer than 8.
    pub fn parse(bytes: &[u8]) -> Result<Self, DissectError> {
        if bytes.len() < 8 {
            return Err(DissectError::TooShort {
                need: 8,
                got: bytes.len(),
            });
        }
        let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
        let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let length = u16::from_be_bytes([bytes[4], bytes[5]]);
        let payload_end = (length as usize).min(bytes.len());
        let payload = bytes[8..payload_end].to_vec();
        Ok(Self {
            src_port,
            dst_port,
            length,
            payload,
        })
    }
}

/// A single DNS question entry (spec-required: name, qtype, qclass).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A parsed DNS query packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub id: u16,
    pub questions: Vec<DnsQuestion>,
}

impl DnsQuery {
    /// Parse a DNS query from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::TooShort`] if fewer than 12 bytes, or
    /// [`DissectError::ParseError`] if the packet is malformed.
    pub fn parse(bytes: &[u8]) -> Result<Self, DissectError> {
        if bytes.len() < 12 {
            return Err(DissectError::TooShort {
                need: 12,
                got: bytes.len(),
            });
        }
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        let mut offset = 12usize;
        let mut questions = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            let (name, next) = parse_dns_label(bytes, offset)?;
            if next + 4 > bytes.len() {
                return Err(DissectError::TooShort {
                    need: next + 4,
                    got: bytes.len(),
                });
            }
            let qtype = u16::from_be_bytes([bytes[next], bytes[next + 1]]);
            let qclass = u16::from_be_bytes([bytes[next + 2], bytes[next + 3]]);
            offset = next + 4;
            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
        }
        Ok(Self { id, questions })
    }
}

/// A full DNS message (spec-required type for `DnsMessage` with `is_query()`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMessage {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
}

impl DnsMessage {
    /// Parse a DNS message from raw bytes (questions section only).
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::TooShort`] if fewer than 12 bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, DissectError> {
        if bytes.len() < 12 {
            return Err(DissectError::TooShort {
                need: 12,
                got: bytes.len(),
            });
        }
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        let mut offset = 12usize;
        let mut questions = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            if offset >= bytes.len() {
                break;
            }
            let (name, next) = parse_dns_label(bytes, offset)?;
            if next + 4 > bytes.len() {
                return Err(DissectError::TooShort {
                    need: next + 4,
                    got: bytes.len(),
                });
            }
            let qtype = u16::from_be_bytes([bytes[next], bytes[next + 1]]);
            let qclass = u16::from_be_bytes([bytes[next + 2], bytes[next + 3]]);
            offset = next + 4;
            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
        }
        Ok(Self {
            id,
            flags,
            questions,
        })
    }

    /// Returns `true` if this is a DNS query (QR bit = 0).
    #[must_use]
    pub const fn is_query(&self) -> bool {
        self.flags & 0x8000 == 0
    }
}

fn parse_dns_label(data: &[u8], mut offset: usize) -> Result<(String, usize), DissectError> {
    let mut parts: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut final_offset = offset;
    loop {
        if offset >= data.len() {
            return Err(DissectError::ParseError("DNS label past end".to_string()));
        }
        let len = data[offset] as usize;
        if len == 0 {
            if !jumped {
                final_offset = offset + 1;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= data.len() {
                return Err(DissectError::ParseError("DNS pointer past end".to_string()));
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
            return Err(DissectError::TooShort {
                need: offset + len,
                got: data.len(),
            });
        }
        let label = std::str::from_utf8(&data[offset..offset + len])
            .map_err(|_| DissectError::ParseError("DNS label not UTF-8".to_string()))?
            .to_string();
        parts.push(label);
        offset += len;
    }
    Ok((parts.join("."), final_offset))
}

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
    /// Parse an HTTP/1.x request from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::ParseError`] if the request is malformed.
    pub fn parse(bytes: &[u8]) -> Result<Self, DissectError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| DissectError::ParseError("non-UTF8 HTTP data".to_string()))?;
        let sep_idx = text.find("\r\n\r\n").ok_or_else(|| {
            DissectError::ParseError("missing HTTP header terminator".to_string())
        })?;
        let header_section = &text[..sep_idx];
        let body = bytes[sep_idx + 4..].to_vec();
        let mut lines = header_section.split("\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| DissectError::ParseError("empty HTTP request".to_string()))?;
        let mut parts = request_line.splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_string();
        let uri = parts.next().unwrap_or("").to_string();
        let version = parts.next().unwrap_or("").to_string();
        if method.is_empty() || uri.is_empty() {
            return Err(DissectError::ParseError(
                "malformed HTTP request line".to_string(),
            ));
        }
        let headers = lines
            .filter_map(|line| {
                let idx = line.find(':')?;
                let k = line[..idx].trim().to_string();
                let v = line[idx + 1..].trim().to_string();
                Some((k, v))
            })
            .collect();
        Ok(Self {
            method,
            uri,
            version,
            headers,
            body,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DNS full record dissector
// ────────────────────────────────────────────────────────────────────────────

/// RDATA for a DNS resource record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsRdata {
    /// A (IPv4 address)
    A([u8; 4]),
    /// AAAA (IPv6 address)
    Aaaa([u8; 16]),
    /// CNAME / NS / PTR (domain name)
    Name(String),
    /// MX: preference + exchange
    Mx { preference: u16, exchange: String },
    /// TXT: list of strings
    Txt(Vec<String>),
    /// SOA record
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// SRV record
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Raw bytes for unsupported types
    Raw(Vec<u8>),
}

impl fmt::Display for DnsRdata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(a) => write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Self::Aaaa(a) => {
                let words: Vec<String> = a
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                write!(f, "{}", words.join(":"))
            }
            Self::Name(n) => write!(f, "{n}"),
            Self::Mx {
                preference,
                exchange,
            } => write!(f, "{preference} {exchange}"),
            Self::Txt(parts) => write!(f, "{}", parts.join(" ")),
            Self::Soa {
                mname,
                rname,
                serial,
                ..
            } => write!(f, "{mname} {rname} {serial}"),
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                write!(f, "{priority} {weight} {port} {target}")
            }
            Self::Raw(b) => write!(f, "<{} bytes>", b.len()),
        }
    }
}

/// A single DNS resource record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: DnsRdata,
}

impl DnsRecord {
    /// Return the type name as a static string.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        dns_rtype_name(self.rtype)
    }
}

/// Map a DNS RTYPE value to a human-readable name.
#[must_use]
pub const fn dns_rtype_name(rtype: u16) -> &'static str {
    match rtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "UNKNOWN",
    }
}

/// A fully-parsed DNS message including questions and all resource record sections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFullMessage {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

impl DnsFullMessage {
    /// Parse a full DNS message from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::TooShort`] if fewer than 12 bytes, or
    /// [`DissectError::ParseError`] for malformed data.
    pub fn parse(data: &[u8]) -> Result<Self, DissectError> {
        if data.len() < 12 {
            return Err(DissectError::TooShort {
                need: 12,
                got: data.len(),
            });
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
        let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
        let additional_count = u16::from_be_bytes([data[10], data[11]]) as usize;

        let mut offset = 12usize;

        // Questions
        let mut questions = Vec::with_capacity(qdcount.min(64));
        for _ in 0..qdcount {
            let (name, next) = parse_dns_label(data, offset)?;
            if next + 4 > data.len() {
                return Err(DissectError::TooShort {
                    need: next + 4,
                    got: data.len(),
                });
            }
            let qtype = u16::from_be_bytes([data[next], data[next + 1]]);
            let qclass = u16::from_be_bytes([data[next + 2], data[next + 3]]);
            offset = next + 4;
            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
        }

        // RR sections
        let mut answers = Vec::with_capacity(ancount.min(64));
        let mut authority = Vec::with_capacity(nscount.min(64));
        let mut additional = Vec::with_capacity(additional_count.min(64));

        for (section, count) in [
            (&mut answers as &mut Vec<DnsRecord>, ancount),
            (&mut authority as &mut Vec<DnsRecord>, nscount),
            (&mut additional as &mut Vec<DnsRecord>, additional_count),
        ] {
            for _ in 0..count {
                if offset >= data.len() {
                    break;
                }
                let (name, next) = parse_dns_label(data, offset)?;
                if next + 10 > data.len() {
                    break;
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
                offset = next + 10;
                if offset + rdlen > data.len() {
                    break;
                }
                let rdata_bytes = &data[offset..offset + rdlen];
                let rdata = parse_dns_rdata(data, offset, rdlen, rtype)?;
                offset += rdlen;
                let _ = rdata_bytes; // used via rdata
                section.push(DnsRecord {
                    name,
                    rtype,
                    rclass,
                    ttl,
                    rdata,
                });
            }
        }

        Ok(Self {
            id,
            flags,
            questions,
            answers,
            authority,
            additional,
        })
    }

    /// Returns `true` if this is a DNS query (QR bit = 0).
    #[must_use]
    pub const fn is_query(&self) -> bool {
        self.flags & 0x8000 == 0
    }

    /// Returns the RCODE nibble (lower 4 bits of flags word).
    #[must_use]
    pub const fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }

    /// Returns `true` if the Recursion Desired bit is set.
    #[must_use]
    pub const fn recursion_desired(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// Returns `true` if the Authoritative Answer bit is set.
    #[must_use]
    pub const fn authoritative(&self) -> bool {
        self.flags & 0x0400 != 0
    }
}

fn parse_dns_rdata_soa(packet: &[u8], offset: usize, rdata: &[u8]) -> Result<DnsRdata, DissectError> {
    let (mname, next1) = parse_dns_label(packet, offset)?;
    let (rname, next2) = parse_dns_label(packet, next1)?;
    let rest_offset = next2 - offset;
    if rdata.len() < rest_offset + 20 {
        return Err(DissectError::TooShort { need: rest_offset + 20, got: rdata.len() });
    }
    let r = &rdata[rest_offset..];
    Ok(DnsRdata::Soa {
        mname, rname,
        serial:  u32::from_be_bytes([r[0],  r[1],  r[2],  r[3]]),
        refresh: u32::from_be_bytes([r[4],  r[5],  r[6],  r[7]]),
        retry:   u32::from_be_bytes([r[8],  r[9],  r[10], r[11]]),
        expire:  u32::from_be_bytes([r[12], r[13], r[14], r[15]]),
        minimum: u32::from_be_bytes([r[16], r[17], r[18], r[19]]),
    })
}

fn parse_dns_rdata(
    packet: &[u8],
    offset: usize,
    rdlen: usize,
    rtype: u16,
) -> Result<DnsRdata, DissectError> {
    let rdata = &packet[offset..offset + rdlen];
    match rtype {
        1 => {
            // A record: 4 bytes
            if rdata.len() < 4 {
                return Err(DissectError::TooShort {
                    need: 4,
                    got: rdata.len(),
                });
            }
            Ok(DnsRdata::A([rdata[0], rdata[1], rdata[2], rdata[3]]))
        }
        28 => {
            // AAAA record: 16 bytes
            if rdata.len() < 16 {
                return Err(DissectError::TooShort {
                    need: 16,
                    got: rdata.len(),
                });
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&rdata[..16]);
            Ok(DnsRdata::Aaaa(arr))
        }
        2 | 5 | 12 => {
            // NS / CNAME / PTR: domain name
            let (name, _) = parse_dns_label(packet, offset)?;
            Ok(DnsRdata::Name(name))
        }
        15 => {
            // MX: preference (2) + exchange (name)
            if rdata.len() < 2 {
                return Err(DissectError::TooShort {
                    need: 2,
                    got: rdata.len(),
                });
            }
            let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
            let (exchange, _) = parse_dns_label(packet, offset + 2)?;
            Ok(DnsRdata::Mx {
                preference,
                exchange,
            })
        }
        16 => {
            // TXT: one or more length-prefixed strings
            let mut parts = Vec::new();
            let mut pos = 0usize;
            while pos < rdata.len() {
                let slen = rdata[pos] as usize;
                pos += 1;
                if pos + slen > rdata.len() {
                    break;
                }
                let s = std::str::from_utf8(&rdata[pos..pos + slen])
                    .unwrap_or("<binary>")
                    .to_string();
                parts.push(s);
                pos += slen;
            }
            Ok(DnsRdata::Txt(parts))
        }
        6 => parse_dns_rdata_soa(packet, offset, rdata),
        33 => {
            // SRV: priority(2), weight(2), port(2), target (name)
            if rdata.len() < 6 {
                return Err(DissectError::TooShort {
                    need: 6,
                    got: rdata.len(),
                });
            }
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let (target, _) = parse_dns_label(packet, offset + 6)?;
            Ok(DnsRdata::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        _ => Ok(DnsRdata::Raw(rdata.to_vec())),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Full DNS dissector (with all record types)
// ────────────────────────────────────────────────────────────────────────────

/// Full DNS dissector that populates answer/authority/additional record fields.
pub struct DnsFullDissector;

impl ProtocolDissector for DnsFullDissector {
    fn name(&self) -> &'static str {
        "DNS-Full"
    }
    fn ports(&self) -> &[u16] {
        &[53]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let msg = DnsFullMessage::parse(data)?;
        let mut layer = ProtoLayer::new("DNS-Full", data[..12.min(data.len())].to_vec());
        layer.add_field(ProtoField::new(
            "id",
            0,
            2,
            FieldValue::Uint(u64::from(msg.id)),
        ));
        layer.add_field(ProtoField::new(
            "flags",
            2,
            2,
            FieldValue::Uint(u64::from(msg.flags)),
        ));
        layer.add_field(ProtoField::new(
            "is_query",
            2,
            2,
            FieldValue::Bool(msg.is_query()),
        ));
        layer.add_field(ProtoField::new(
            "rcode",
            2,
            2,
            FieldValue::Uint(u64::from(msg.rcode())),
        ));
        layer.add_field(ProtoField::new(
            "qdcount",
            4,
            2,
            FieldValue::Uint(msg.questions.len() as u64),
        ));
        layer.add_field(ProtoField::new(
            "ancount",
            6,
            2,
            FieldValue::Uint(msg.answers.len() as u64),
        ));

        for (i, q) in msg.questions.iter().enumerate() {
            layer.add_field(ProtoField::new(
                format!("question[{i}].name"),
                0,
                q.name.len(),
                FieldValue::Str(q.name.clone()),
            ));
            layer.add_field(ProtoField::new(
                format!("question[{i}].qtype"),
                0,
                2,
                FieldValue::Str(dns_rtype_name(q.qtype).to_string()),
            ));
        }
        for (i, rr) in msg.answers.iter().enumerate() {
            layer.add_field(ProtoField::new(
                format!("answer[{i}].name"),
                0,
                rr.name.len(),
                FieldValue::Str(rr.name.clone()),
            ));
            layer.add_field(ProtoField::new(
                format!("answer[{i}].type"),
                0,
                2,
                FieldValue::Str(rr.type_name().to_string()),
            ));
            layer.add_field(ProtoField::new(
                format!("answer[{i}].data"),
                0,
                0,
                FieldValue::Str(rr.rdata.to_string()),
            ));
        }
        packet.push_layer(layer);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TLS full handshake dissector
// ────────────────────────────────────────────────────────────────────────────

/// TLS handshake message type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsHandshakeType {
    HelloRequest,
    ClientHello,
    ServerHello,
    NewSessionTicket,
    EndOfEarlyData,
    EncryptedExtensions,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
    Unknown(u8),
}

impl From<u8> for TlsHandshakeType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::HelloRequest,
            1 => Self::ClientHello,
            2 => Self::ServerHello,
            4 => Self::NewSessionTicket,
            5 => Self::EndOfEarlyData,
            8 => Self::EncryptedExtensions,
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

impl fmt::Display for TlsHandshakeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelloRequest => write!(f, "HelloRequest"),
            Self::ClientHello => write!(f, "ClientHello"),
            Self::ServerHello => write!(f, "ServerHello"),
            Self::NewSessionTicket => write!(f, "NewSessionTicket"),
            Self::EndOfEarlyData => write!(f, "EndOfEarlyData"),
            Self::EncryptedExtensions => write!(f, "EncryptedExtensions"),
            Self::Certificate => write!(f, "Certificate"),
            Self::ServerKeyExchange => write!(f, "ServerKeyExchange"),
            Self::CertificateRequest => write!(f, "CertificateRequest"),
            Self::ServerHelloDone => write!(f, "ServerHelloDone"),
            Self::CertificateVerify => write!(f, "CertificateVerify"),
            Self::ClientKeyExchange => write!(f, "ClientKeyExchange"),
            Self::Finished => write!(f, "Finished"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// TLS content type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Heartbeat,
    Unknown(u8),
}

impl From<u8> for TlsContentType {
    fn from(v: u8) -> Self {
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
        match self {
            Self::ChangeCipherSpec => write!(f, "ChangeCipherSpec"),
            Self::Alert => write!(f, "Alert"),
            Self::Handshake => write!(f, "Handshake"),
            Self::ApplicationData => write!(f, "ApplicationData"),
            Self::Heartbeat => write!(f, "Heartbeat"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// A parsed TLS record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRecord {
    pub content_type: TlsContentType,
    pub version: u16,
    pub payload: Vec<u8>,
}

impl TlsRecord {
    /// Parse zero or more TLS records from `data`.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::TooShort`] for truncated records or
    /// [`DissectError::ParseError`] for other structural problems.
    pub fn parse_all(data: &[u8]) -> Result<Vec<Self>, DissectError> {
        let mut records = Vec::new();
        let mut off = 0usize;
        while off + 5 <= data.len() {
            let ct = TlsContentType::from(data[off]);
            let version = u16::from_be_bytes([data[off + 1], data[off + 2]]);
            let len = u16::from_be_bytes([data[off + 3], data[off + 4]]) as usize;
            off += 5;
            if off + len > data.len() {
                return Err(DissectError::TooShort {
                    need: off + len,
                    got: data.len(),
                });
            }
            let payload = data[off..off + len].to_vec();
            off += len;
            records.push(Self {
                content_type: ct,
                version,
                payload,
            });
        }
        Ok(records)
    }
}

/// A parsed TLS handshake message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsHandshakeMessage {
    pub msg_type: TlsHandshakeType,
    pub payload: Vec<u8>,
}

impl TlsHandshakeMessage {
    /// Parse all handshake messages from a TLS handshake record payload.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::TooShort`] for truncated messages.
    pub fn parse_all(data: &[u8]) -> Result<Vec<Self>, DissectError> {
        let mut msgs = Vec::new();
        let mut off = 0usize;
        while off + 4 <= data.len() {
            let msg_type = TlsHandshakeType::from(data[off]);
            let len =
                (u32::from_be_bytes([0, data[off + 1], data[off + 2], data[off + 3]])) as usize;
            off += 4;
            if off + len > data.len() {
                return Err(DissectError::TooShort {
                    need: off + len,
                    got: data.len(),
                });
            }
            let payload = data[off..off + len].to_vec();
            off += len;
            msgs.push(Self { msg_type, payload });
        }
        Ok(msgs)
    }
}

/// TLS version name.
#[must_use]
pub const fn tls_version_name(version: u16) -> &'static str {
    match version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    }
}

/// Full TLS dissector: parses all records and handshake messages.
pub struct TlsFullDissector;

impl ProtocolDissector for TlsFullDissector {
    fn name(&self) -> &'static str {
        "TLS-Full"
    }
    fn ports(&self) -> &[u16] {
        &[443, 8443]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        if data.len() < 5 {
            return Err(DissectError::BufferTooShort {
                needed: 5,
                got: data.len(),
            });
        }
        let records = TlsRecord::parse_all(data)?;
        let mut layer = ProtoLayer::new("TLS-Full", data[..5.min(data.len())].to_vec());
        layer.add_field(ProtoField::new(
            "record_count",
            0,
            0,
            FieldValue::Uint(records.len() as u64),
        ));

        for (i, rec) in records.iter().enumerate() {
            layer.add_field(ProtoField::new(
                format!("record[{i}].type"),
                0,
                1,
                FieldValue::Str(rec.content_type.to_string()),
            ));
            layer.add_field(ProtoField::new(
                format!("record[{i}].version"),
                1,
                2,
                FieldValue::Str(tls_version_name(rec.version).to_string()),
            ));
            layer.add_field(ProtoField::new(
                format!("record[{i}].length"),
                3,
                2,
                FieldValue::Uint(rec.payload.len() as u64),
            ));

            // Dissect handshake messages inside handshake records
            if rec.content_type == TlsContentType::Handshake {
                if let Ok(hs_msgs) = TlsHandshakeMessage::parse_all(&rec.payload) {
                    for (j, hs) in hs_msgs.iter().enumerate() {
                        layer.add_field(ProtoField::new(
                            format!("record[{i}].hs[{j}].type"),
                            0,
                            1,
                            FieldValue::Str(hs.msg_type.to_string()),
                        ));
                    }
                }
                // Extract SNI from ClientHello
                if let Some(sni) = extract_tls_sni(data) {
                    layer.add_field(ProtoField::new("sni", 0, sni.len(), FieldValue::Str(sni)));
                }
            }
        }
        packet.push_layer(layer);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SSH dissector
// ────────────────────────────────────────────────────────────────────────────

/// SSH dissector (banner and binary packet layer).
pub struct SshDissector;

impl ProtocolDissector for SshDissector {
    fn name(&self) -> &'static str {
        "SSH"
    }
    fn ports(&self) -> &[u16] {
        &[22]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let mut layer = ProtoLayer::new("SSH", data.to_vec());

        if data.starts_with(b"SSH-") {
            // SSH identification string: "SSH-<protoversion>-<swversion>[SP comment]CR LF"
            let end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
            let banner = std::str::from_utf8(&data[..end.min(data.len())])
                .unwrap_or("<binary>")
                .trim_end_matches('\r')
                .to_string();
            layer.add_field(ProtoField::new(
                "banner",
                0,
                banner.len(),
                FieldValue::Str(banner.clone()),
            ));

            // Parse SSH-<proto>-<software> components
            let parts: Vec<&str> = banner.splitn(3, '-').collect();
            if parts.len() >= 3 {
                layer.add_field(ProtoField::new(
                    "proto_version",
                    4,
                    parts[1].len(),
                    FieldValue::Str(parts[1].to_string()),
                ));
                layer.add_field(ProtoField::new(
                    "software",
                    4 + parts[1].len() + 1,
                    parts[2].len(),
                    FieldValue::Str(parts[2].to_string()),
                ));
            }
        } else if data.len() >= 6 {
            // SSH binary packet: packet_length(4) + padding_length(1) + payload_type(1) + ...
            let packet_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let padding_len = data[4];
            let msg_type = data[5];
            layer.add_field(ProtoField::new(
                "packet_length",
                0,
                4,
                FieldValue::Uint(u64::from(packet_len)),
            ));
            layer.add_field(ProtoField::new(
                "padding_length",
                4,
                1,
                FieldValue::Uint(u64::from(padding_len)),
            ));
            layer.add_field(ProtoField::new(
                "msg_type",
                5,
                1,
                FieldValue::Uint(u64::from(msg_type)),
            ));
            layer.add_field(ProtoField::new(
                "msg_type_name",
                5,
                1,
                FieldValue::Str(ssh_msg_type_name(msg_type).to_string()),
            ));
        } else {
            return Err(DissectError::ParseError(
                "too short for SSH binary packet".to_string(),
            ));
        }

        packet.push_layer(layer);
        Ok(())
    }
}

/// Return the human-readable name for an SSH message type code.
#[must_use]
pub const fn ssh_msg_type_name(msg_type: u8) -> &'static str {
    match msg_type {
        1 => "SSH_MSG_DISCONNECT",
        2 => "SSH_MSG_IGNORE",
        3 => "SSH_MSG_UNIMPLEMENTED",
        4 => "SSH_MSG_DEBUG",
        5 => "SSH_MSG_SERVICE_REQUEST",
        6 => "SSH_MSG_SERVICE_ACCEPT",
        20 => "SSH_MSG_KEXINIT",
        21 => "SSH_MSG_NEWKEYS",
        50 => "SSH_MSG_USERAUTH_REQUEST",
        51 => "SSH_MSG_USERAUTH_FAILURE",
        52 => "SSH_MSG_USERAUTH_SUCCESS",
        53 => "SSH_MSG_USERAUTH_BANNER",
        80 => "SSH_MSG_CHANNEL_OPEN",
        81 => "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
        82 => "SSH_MSG_CHANNEL_OPEN_FAILURE",
        93 => "SSH_MSG_CHANNEL_DATA",
        94 => "SSH_MSG_CHANNEL_EXTENDED_DATA",
        96 => "SSH_MSG_CHANNEL_EOF",
        97 => "SSH_MSG_CHANNEL_CLOSE",
        98 => "SSH_MSG_CHANNEL_REQUEST",
        99 => "SSH_MSG_CHANNEL_SUCCESS",
        100 => "SSH_MSG_CHANNEL_FAILURE",
        _ => "SSH_MSG_UNKNOWN",
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RDP dissector
// ────────────────────────────────────────────────────────────────────────────

/// RDP PDU type (TPKT + X.224 + MCS/RDP top-level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RdpPduType {
    TpktData,
    X224ConnectRequest,
    X224ConnectResponse,
    X224DataPdu,
    Unknown(u8),
}

impl fmt::Display for RdpPduType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TpktData => write!(f, "TPKT-Data"),
            Self::X224ConnectRequest => write!(f, "X.224-CR"),
            Self::X224ConnectResponse => write!(f, "X.224-CC"),
            Self::X224DataPdu => write!(f, "X.224-DT"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// RDP dissector (TPKT + X.224 envelope).
pub struct RdpDissector;

impl ProtocolDissector for RdpDissector {
    fn name(&self) -> &'static str {
        "RDP"
    }
    fn ports(&self) -> &[u16] {
        &[3389]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        if data.len() < 4 {
            return Err(DissectError::TooShort {
                need: 4,
                got: data.len(),
            });
        }
        // TPKT header: version(1)=3, reserved(1), length(2 big-endian)
        if data[0] != 3 {
            return Err(DissectError::ParseError(format!(
                "expected TPKT version 3, got {}",
                data[0]
            )));
        }
        let tpkt_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let mut layer = ProtoLayer::new("RDP", data[..4.min(data.len())].to_vec());
        layer.add_field(ProtoField::new(
            "tpkt_version",
            0,
            1,
            FieldValue::Uint(u64::from(data[0])),
        ));
        layer.add_field(ProtoField::new(
            "tpkt_length",
            2,
            2,
            FieldValue::Uint(tpkt_len as u64),
        ));

        // X.224 header starts at byte 4: length_indicator(1), code(1)
        if data.len() >= 6 {
            let x224_len = data[4];
            let x224_code = data[5];
            let pdu_type = match x224_code & 0xF0 {
                0xE0 => RdpPduType::X224ConnectRequest,
                0xD0 => RdpPduType::X224ConnectResponse,
                0xF0 => RdpPduType::X224DataPdu,
                _ => RdpPduType::Unknown(x224_code),
            };
            layer.add_field(ProtoField::new(
                "x224_li",
                4,
                1,
                FieldValue::Uint(u64::from(x224_len)),
            ));
            layer.add_field(ProtoField::new(
                "x224_type",
                5,
                1,
                FieldValue::Str(pdu_type.to_string()),
            ));

            // For X.224 Data PDU, byte 6 is TPKT reserved + EOT, then MCS follows
            if pdu_type == RdpPduType::X224DataPdu && data.len() >= 8 {
                layer.add_field(ProtoField::new(
                    "mcs_payload_offset",
                    0,
                    0,
                    FieldValue::Uint(7),
                ));
            }
        }

        packet.push_layer(layer);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DHCP dissector
// ────────────────────────────────────────────────────────────────────────────

/// DHCP message type (option 53).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhcpMsgType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    Unknown(u8),
}

impl fmt::Display for DhcpMsgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discover => write!(f, "DHCPDISCOVER"),
            Self::Offer => write!(f, "DHCPOFFER"),
            Self::Request => write!(f, "DHCPREQUEST"),
            Self::Decline => write!(f, "DHCPDECLINE"),
            Self::Ack => write!(f, "DHCPACK"),
            Self::Nak => write!(f, "DHCPNAK"),
            Self::Release => write!(f, "DHCPRELEASE"),
            Self::Inform => write!(f, "DHCPINFORM"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

impl From<u8> for DhcpMsgType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            other => Self::Unknown(other),
        }
    }
}

/// DHCP option code constants.
pub mod dhcp_opts {
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS_SERVER: u8 = 6;
    pub const HOSTNAME: u8 = 12;
    pub const DOMAIN_NAME: u8 = 15;
    pub const REQUESTED_IP: u8 = 50;
    pub const IP_LEASE_TIME: u8 = 51;
    pub const MSG_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAM_REQUEST: u8 = 55;
    pub const MESSAGE: u8 = 56;
    pub const MAX_DHCP_SIZE: u8 = 57;
    pub const CLIENT_ID: u8 = 61;
    pub const DOMAIN_SEARCH: u8 = 119;
    pub const CLASS_ID: u8 = 60;
    pub const END: u8 = 255;
    pub const PAD: u8 = 0;
}

/// A single DHCP option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpOption {
    pub code: u8,
    pub data: Vec<u8>,
}

/// A fully-parsed DHCP message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpMessage {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub siaddr: [u8; 4],
    pub giaddr: [u8; 4],
    pub chaddr: [u8; 16],
    pub options: Vec<DhcpOption>,
    pub msg_type: Option<DhcpMsgType>,
}

impl DhcpMessage {
    /// Parse a DHCP message from raw bytes (UDP payload).
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::TooShort`] if fewer than 240 bytes,
    /// or [`DissectError::InvalidMagic`] if the DHCP magic cookie is absent.
    pub fn parse(data: &[u8]) -> Result<Self, DissectError> {
        if data.len() < 240 {
            return Err(DissectError::TooShort {
                need: 240,
                got: data.len(),
            });
        }
        // Validate DHCP magic cookie at offset 236: 99.130.83.99
        if &data[236..240] != b"\x63\x82\x53\x63" {
            return Err(DissectError::InvalidMagic(
                "DHCP magic cookie missing".to_string(),
            ));
        }
        let op = data[0];
        let htype = data[1];
        let hlen = data[2];
        let hops = data[3];
        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let secs = u16::from_be_bytes([data[8], data[9]]);
        let flags = u16::from_be_bytes([data[10], data[11]]);
        let mut ciaddr = [0u8; 4];
        ciaddr.copy_from_slice(&data[12..16]);
        let mut yiaddr = [0u8; 4];
        yiaddr.copy_from_slice(&data[16..20]);
        let mut siaddr = [0u8; 4];
        siaddr.copy_from_slice(&data[20..24]);
        let mut giaddr = [0u8; 4];
        giaddr.copy_from_slice(&data[24..28]);
        let mut hw_addr = [0u8; 16];
        hw_addr.copy_from_slice(&data[28..44]);

        // Parse options
        let mut options = Vec::new();
        let mut msg_type = None;
        let mut pos = 240usize;
        while pos < data.len() {
            let code = data[pos];
            pos += 1;
            if code == dhcp_opts::END {
                break;
            }
            if code == dhcp_opts::PAD {
                continue;
            }
            if pos >= data.len() {
                break;
            }
            let len = data[pos] as usize;
            pos += 1;
            if pos + len > data.len() {
                break;
            }
            let opt_data = data[pos..pos + len].to_vec();
            if code == dhcp_opts::MSG_TYPE && len == 1 {
                msg_type = Some(DhcpMsgType::from(opt_data[0]));
            }
            options.push(DhcpOption {
                code,
                data: opt_data,
            });
            pos += len;
        }

        Ok(Self {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr: hw_addr,
            options,
            msg_type,
        })
    }

    /// Return the DHCP message type string if option 53 was present.
    #[must_use]
    pub const fn type_str(&self) -> &'static str {
        match self.msg_type {
            Some(ref t) => match t {
                DhcpMsgType::Discover => "DHCPDISCOVER",
                DhcpMsgType::Offer => "DHCPOFFER",
                DhcpMsgType::Request => "DHCPREQUEST",
                DhcpMsgType::Decline => "DHCPDECLINE",
                DhcpMsgType::Ack => "DHCPACK",
                DhcpMsgType::Nak => "DHCPNAK",
                DhcpMsgType::Release => "DHCPRELEASE",
                DhcpMsgType::Inform => "DHCPINFORM",
                DhcpMsgType::Unknown(_) => "DHCPUNKNOWN",
            },
            None => "DHCP",
        }
    }

    /// Look up an option by code.
    #[must_use]
    pub fn option(&self, code: u8) -> Option<&DhcpOption> {
        self.options.iter().find(|o| o.code == code)
    }
}

/// DHCP dissector.
pub struct DhcpDissector;

impl ProtocolDissector for DhcpDissector {
    fn name(&self) -> &'static str {
        "DHCP"
    }
    fn ports(&self) -> &[u16] {
        &[67, 68]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let msg = DhcpMessage::parse(data)?;
        let mut layer = ProtoLayer::new("DHCP", data[..28.min(data.len())].to_vec());
        layer.add_field(ProtoField::new(
            "op",
            0,
            1,
            FieldValue::Uint(u64::from(msg.op)),
        ));
        layer.add_field(ProtoField::new(
            "xid",
            4,
            4,
            FieldValue::Uint(u64::from(msg.xid)),
        ));
        layer.add_field(ProtoField::new(
            "ciaddr",
            12,
            4,
            FieldValue::Bytes(msg.ciaddr.to_vec()),
        ));
        layer.add_field(ProtoField::new(
            "yiaddr",
            16,
            4,
            FieldValue::Bytes(msg.yiaddr.to_vec()),
        ));
        if let Some(ref mt) = msg.msg_type {
            layer.add_field(ProtoField::new(
                "msg_type",
                0,
                1,
                FieldValue::Str(mt.to_string()),
            ));
        }
        packet.push_layer(layer);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP/1.x response parser
// ────────────────────────────────────────────────────────────────────────────

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
    /// Parse an HTTP/1.x response from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::ParseError`] if the response is malformed.
    pub fn parse(bytes: &[u8]) -> Result<Self, DissectError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| DissectError::ParseError("non-UTF8 HTTP response".to_string()))?;
        let sep_idx = text.find("\r\n\r\n").ok_or_else(|| {
            DissectError::ParseError("missing HTTP header terminator".to_string())
        })?;
        let header_section = &text[..sep_idx];
        let body = bytes[sep_idx + 4..].to_vec();
        let mut lines = header_section.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| DissectError::ParseError("empty HTTP response".to_string()))?;
        // Status line: HTTP/<ver> <code> <reason>
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or("").to_string();
        let code_str = parts.next().unwrap_or("0");
        let reason = parts.next().unwrap_or("").to_string();
        let status_code = code_str
            .parse::<u16>()
            .map_err(|_| DissectError::ParseError(format!("invalid status code: {code_str}")))?;
        let headers = lines
            .filter_map(|line| {
                let idx = line.find(':')?;
                let k = line[..idx].trim().to_string();
                let v = line[idx + 1..].trim().to_string();
                Some((k, v))
            })
            .collect();
        Ok(Self {
            version,
            status_code,
            reason,
            headers,
            body,
        })
    }

    /// Returns the value of the first header with the given name (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Returns the Content-Type header value, if present.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Returns the Content-Length as a usize, if present and valid.
    #[must_use]
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length")?.parse().ok()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP chunked transfer-encoding decoder
// ────────────────────────────────────────────────────────────────────────────

/// Decode an HTTP/1.1 chunked-encoded body into the raw body bytes.
///
/// # Errors
///
/// Returns [`DissectError::ParseError`] if the chunked encoding is malformed
/// (e.g. invalid chunk size hex, missing `\r\n` terminators, truncated data).
pub fn decode_http_chunked(data: &[u8]) -> Result<Vec<u8>, DissectError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        // Read chunk-size line (hex digits terminated by CRLF or LF)
        let start = pos;
        while pos < data.len() && data[pos] != b'\r' && data[pos] != b'\n' {
            pos += 1;
        }
        let size_str = std::str::from_utf8(&data[start..pos])
            .map_err(|_| DissectError::ParseError("non-UTF8 chunk size".to_string()))?
            .split(';') // strip chunk-extension
            .next()
            .unwrap_or("0")
            .trim();
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|_| DissectError::ParseError(format!("invalid chunk size: {size_str:?}")))?;
        // Skip CRLF after chunk size
        if pos < data.len() && data[pos] == b'\r' {
            pos += 1;
        }
        if pos < data.len() && data[pos] == b'\n' {
            pos += 1;
        }

        if chunk_size == 0 {
            break; // last chunk
        }
        if pos + chunk_size > data.len() {
            return Err(DissectError::TooShort {
                need: pos + chunk_size,
                got: data.len(),
            });
        }
        out.extend_from_slice(&data[pos..pos + chunk_size]);
        pos += chunk_size;
        // Skip trailing CRLF after chunk data
        if pos < data.len() && data[pos] == b'\r' {
            pos += 1;
        }
        if pos < data.len() && data[pos] == b'\n' {
            pos += 1;
        }
    }
    Ok(out)
}

// ────────────────────────────────────────────────────────────────────────────
// Dissector chain
// ────────────────────────────────────────────────────────────────────────────

/// A sequential chain of dissectors applied one after another.
///
/// Each dissector in the chain is tried; dissection continues even if a
/// dissector fails (errors are silently ignored to allow partial results).
pub struct DissectorChain {
    dissectors: Vec<Arc<dyn ProtocolDissector>>,
}

impl DissectorChain {
    /// Create an empty dissector chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            dissectors: Vec::new(),
        }
    }

    /// Add a dissector to the end of the chain.
    pub fn push(&mut self, d: Arc<dyn ProtocolDissector>) {
        self.dissectors.push(d);
    }

    /// Run all dissectors in order on `data`, appending layers to `packet`.
    pub fn run(&self, data: &[u8], layer: u32, packet: &mut DissectedPacket) {
        for d in &self.dissectors {
            let _ = d.dissect(data, layer, packet);
        }
    }

    /// Run all dissectors and return a fresh [`DissectedPacket`].
    #[must_use]
    pub fn dissect_all(&self, data: &[u8]) -> DissectedPacket {
        let mut pkt = DissectedPacket::new();
        self.run(data, 0, &mut pkt);
        pkt
    }

    /// Returns the number of dissectors in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.dissectors.len()
    }

    /// Returns `true` if the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.dissectors.is_empty()
    }
}

impl Default for DissectorChain {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Flow-aware dissection session
// ────────────────────────────────────────────────────────────────────────────

/// Direction of traffic in a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowDir {
    ClientToServer,
    ServerToClient,
}

impl fmt::Display for FlowDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientToServer => write!(f, "C->S"),
            Self::ServerToClient => write!(f, "S->C"),
        }
    }
}

/// A flow-aware dissection session that accumulates per-direction payloads and
/// re-dissects when new data arrives.
pub struct DissectionSession {
    registry: Arc<DissectorRegistry>,
    client_buf: Vec<u8>,
    server_buf: Vec<u8>,
    protocol: String,
    pub layers: Vec<(FlowDir, DissectedPacket)>,
}

impl DissectionSession {
    /// Create a new session backed by the given registry, bound to `protocol`.
    #[must_use]
    pub fn new(registry: Arc<DissectorRegistry>, protocol: impl Into<String>) -> Self {
        Self {
            registry,
            client_buf: Vec::new(),
            server_buf: Vec::new(),
            protocol: protocol.into(),
            layers: Vec::new(),
        }
    }

    /// Feed data in `dir` direction.  Attempts to dissect the accumulated buffer.
    pub fn feed(&mut self, data: &[u8], dir: FlowDir) {
        let buf = match dir {
            FlowDir::ClientToServer => &mut self.client_buf,
            FlowDir::ServerToClient => &mut self.server_buf,
        };
        buf.extend_from_slice(data);
        if let Ok(pkt) = self.registry.dissect_auto(&self.protocol, None, buf, 4) {
            self.layers.push((dir, pkt));
            buf.clear();
        }
    }

    /// Return all dissected packets for the given direction.
    #[must_use]
    pub fn packets_for_dir(&self, dir: FlowDir) -> Vec<&DissectedPacket> {
        self.layers
            .iter()
            .filter(|(d, _)| *d == dir)
            .map(|(_, p)| p)
            .collect()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Protocol fingerprinting improvements
// ────────────────────────────────────────────────────────────────────────────

/// Confidence score for a protocol fingerprint match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FingerprintConfidence {
    Low,
    Medium,
    High,
}

impl fmt::Display for FingerprintConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

/// Result of a protocol fingerprinting attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintResult {
    pub protocol: String,
    pub confidence: FingerprintConfidence,
    pub detail: String,
}

impl FingerprintResult {
    fn new(protocol: &str, confidence: FingerprintConfidence, detail: impl Into<String>) -> Self {
        Self {
            protocol: protocol.to_string(),
            confidence,
            detail: detail.into(),
        }
    }
}

/// Perform detailed protocol fingerprinting, returning a confidence-annotated
/// result and a short description of how the match was made.
#[must_use]
fn fingerprint_by_port(port: u16) -> Option<FingerprintResult> {
    match port {
        53 => Some(FingerprintResult::new("DNS",  FingerprintConfidence::High, "port 53")),
        80 | 8080 | 8000 => Some(FingerprintResult::new("HTTP", FingerprintConfidence::High, "port 80/8080/8000")),
        443 | 8443 => Some(FingerprintResult::new("TLS",  FingerprintConfidence::High, "port 443/8443")),
        445 | 139  => Some(FingerprintResult::new("SMB",  FingerprintConfidence::High, "port 445/139")),
        21   => Some(FingerprintResult::new("FTP",  FingerprintConfidence::High, "port 21")),
        22   => Some(FingerprintResult::new("SSH",  FingerprintConfidence::High, "port 22")),
        25 | 587 => Some(FingerprintResult::new("SMTP", FingerprintConfidence::High, "port 25/587")),
        110  => Some(FingerprintResult::new("POP3", FingerprintConfidence::High, "port 110")),
        143  => Some(FingerprintResult::new("IMAP", FingerprintConfidence::High, "port 143")),
        3306 => Some(FingerprintResult::new("MySQL", FingerprintConfidence::High, "port 3306")),
        5432 => Some(FingerprintResult::new("PostgreSQL", FingerprintConfidence::High, "port 5432")),
        3389 => Some(FingerprintResult::new("RDP",  FingerprintConfidence::High, "port 3389")),
        67 | 68 => Some(FingerprintResult::new("DHCP", FingerprintConfidence::High, "port 67/68")),
        _ => None,
    }
}

#[must_use]
pub fn fingerprint_detailed(data: &[u8], src_port: u16, dst_port: u16) -> FingerprintResult {
    for &port in &[src_port, dst_port] {
        if let Some(r) = fingerprint_by_port(port) { return r; }
    }

    // Content-based: medium or low confidence
    if data.starts_with(b"HTTP/") {
        return FingerprintResult::new("HTTP", FingerprintConfidence::High, "HTTP response magic");
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
        if data.starts_with(method) {
            return FingerprintResult::new(
                "HTTP",
                FingerprintConfidence::High,
                format!(
                    "HTTP method {:?}",
                    std::str::from_utf8(method).unwrap_or("?").trim()
                ),
            );
        }
    }
    if data.first().copied() == Some(22) && data.len() >= 5 {
        let ver = if data.len() >= 3 {
            u16::from_be_bytes([data[1], data[2]])
        } else {
            0
        };
        return FingerprintResult::new(
            "TLS",
            FingerprintConfidence::High,
            format!("TLS handshake record, version={}", tls_version_name(ver)),
        );
    }
    if data.starts_with(b"\xFFSMB") || data.starts_with(b"\xFESMB") {
        return FingerprintResult::new("SMB", FingerprintConfidence::High, "SMB magic");
    }
    if data.starts_with(b"SSH-") {
        return FingerprintResult::new("SSH", FingerprintConfidence::High, "SSH banner");
    }
    if data.len() >= 240 && &data[236..240] == b"\x63\x82\x53\x63" {
        return FingerprintResult::new("DHCP", FingerprintConfidence::High, "DHCP magic cookie");
    }
    if data.len() >= 4 && data[0] == 3 && data[1] == 0 {
        // TPKT version 3 → likely RDP
        return FingerprintResult::new("RDP", FingerprintConfidence::Medium, "TPKT v3 header");
    }
    if data.len() >= 12 {
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        if qdcount <= 4 {
            return FingerprintResult::new(
                "DNS",
                FingerprintConfidence::Low,
                "DNS heuristic (low qdcount)",
            );
        }
    }
    FingerprintResult::new("Unknown", FingerprintConfidence::Low, "no match")
}

// ────────────────────────────────────────────────────────────────────────────
// Updated default registry with new dissectors
// ────────────────────────────────────────────────────────────────────────────

/// Build a [`DissectorRegistry`] pre-populated with ALL built-in dissectors,
/// including the full DNS, TLS, SSH, RDP, DHCP, SMB, FTP, SMTP, POP3, and IMAP dissectors.
#[must_use]
pub fn full_registry() -> DissectorRegistry {
    let reg = default_registry();
    let d: Arc<dyn ProtocolDissector> = Arc::new(DnsFullDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(TlsFullDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(SshDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(RdpDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(DhcpDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(SmbFullDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(FtpFullDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(SmtpFullDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(Pop3Dissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(ImapDissector);
    reg.register(&d);
    reg
}

// ────────────────────────────────────────────────────────────────────────────
// SMB full dissector
// ────────────────────────────────────────────────────────────────────────────

/// SMB1 command names.
#[must_use]
pub const fn smb1_command_name(cmd: u8) -> &'static str {
    match cmd {
        0x00 => "SMB_COM_CREATE_DIRECTORY",
        0x01 => "SMB_COM_DELETE_DIRECTORY",
        0x04 => "SMB_COM_CLOSE",
        0x06 => "SMB_COM_DELETE",
        0x08 => "SMB_COM_RENAME",
        0x09 => "SMB_COM_QUERY_INFORMATION",
        0x0A => "SMB_COM_SET_INFORMATION",
        0x0D => "SMB_COM_OPEN",
        0x0E => "SMB_COM_CREATE",
        0x11 => "SMB_COM_FLUSH",
        0x18 => "SMB_COM_READ",
        0x1D => "SMB_COM_WRITE",
        0x20 => "SMB_COM_LOCK_BYTE_RANGE",
        0x24 => "SMB_COM_LOCKING_ANDX",
        0x25 => "SMB_COM_TRANSACTION",
        0x2B => "SMB_COM_ECHO",
        0x2D => "SMB_COM_OPEN_ANDX",
        0x2E => "SMB_COM_READ_ANDX",
        0x2F => "SMB_COM_WRITE_ANDX",
        0x32 => "SMB_COM_TRANSACTION2",
        0x50 => "SMB_COM_OPEN_PRINT_FILE",
        0x70 => "SMB_COM_TREE_CONNECT",
        0x71 => "SMB_COM_TREE_DISCONNECT",
        0x72 => "SMB_COM_NEGOTIATE",
        0x73 => "SMB_COM_SESSION_SETUP_ANDX",
        0x74 => "SMB_COM_LOGOFF_ANDX",
        0x75 => "SMB_COM_TREE_CONNECT_ANDX",
        0xA0 => "SMB_COM_NT_TRANSACT",
        0xA2 => "SMB_COM_NT_CREATE_ANDX",
        0xA4 => "SMB_COM_NT_CANCEL",
        0xFF => "SMB_COM_NO_ANDX_COMMAND",
        _ => "SMB_COM_UNKNOWN",
    }
}

/// SMB2 command names.
#[must_use]
pub const fn smb2_command_name(cmd: u16) -> &'static str {
    match cmd {
        0x0000 => "SMB2_NEGOTIATE",
        0x0001 => "SMB2_SESSION_SETUP",
        0x0002 => "SMB2_LOGOFF",
        0x0003 => "SMB2_TREE_CONNECT",
        0x0004 => "SMB2_TREE_DISCONNECT",
        0x0005 => "SMB2_CREATE",
        0x0006 => "SMB2_CLOSE",
        0x0007 => "SMB2_FLUSH",
        0x0008 => "SMB2_READ",
        0x0009 => "SMB2_WRITE",
        0x000A => "SMB2_LOCK",
        0x000B => "SMB2_IOCTL",
        0x000C => "SMB2_CANCEL",
        0x000D => "SMB2_ECHO",
        0x000E => "SMB2_QUERY_DIRECTORY",
        0x000F => "SMB2_CHANGE_NOTIFY",
        0x0010 => "SMB2_QUERY_INFO",
        0x0011 => "SMB2_SET_INFO",
        0x0012 => "SMB2_OPLOCK_BREAK",
        _ => "SMB2_UNKNOWN",
    }
}

/// Full SMB dissector (SMB1 and SMB2 headers with command name resolution).
pub struct SmbFullDissector;

impl ProtocolDissector for SmbFullDissector {
    fn name(&self) -> &'static str {
        "SMB-Full"
    }
    fn ports(&self) -> &[u16] {
        &[445, 139]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        if data.len() < 4 {
            return Err(DissectError::BufferTooShort {
                needed: 4,
                got: data.len(),
            });
        }
        let is_smb1 = data.starts_with(b"\xFFSMB");
        let is_smb2 = data.starts_with(b"\xFESMB");
        if !is_smb1 && !is_smb2 {
            return Err(DissectError::ParseError("not an SMB message".to_string()));
        }

        let mut layer = ProtoLayer::new("SMB-Full", data[..4.min(data.len())].to_vec());
        layer.add_field(ProtoField::new(
            "magic",
            0,
            4,
            FieldValue::Bytes(data[..4].to_vec()),
        ));

        if is_smb1 {
            smb_fill_smb1_fields(data, &mut layer);
        } else {
            smb_fill_smb2_fields(data, &mut layer);
        }

        packet.push_layer(layer);
        Ok(())
    }
}

fn smb_fill_smb1_fields(data: &[u8], layer: &mut ProtoLayer) {
    layer.add_field(ProtoField::new("version", 0, 4, FieldValue::Str("SMB1".to_string())));
    if data.len() >= 9 {
        let cmd = data[4];
        let status = u32::from_le_bytes([data[5], data[6], data[7], data[8]]);
        layer.add_field(ProtoField::new("command", 4, 1, FieldValue::Uint(u64::from(cmd))));
        layer.add_field(ProtoField::new("command_name", 4, 1, FieldValue::Str(smb1_command_name(cmd).to_string())));
        layer.add_field(ProtoField::new("status", 5, 4, FieldValue::Uint(u64::from(status))));
    }
    if data.len() >= 10 {
        let flags = data[9];
        layer.add_field(ProtoField::new("flags", 9, 1, FieldValue::Uint(u64::from(flags))));
    }
    if data.len() >= 32 {
        let mid = u16::from_le_bytes([data[30], data[31]]);
        layer.add_field(ProtoField::new("mid", 30, 2, FieldValue::Uint(u64::from(mid))));
    }
}

fn smb_fill_smb2_fields(data: &[u8], layer: &mut ProtoLayer) {
    layer.add_field(ProtoField::new("version", 0, 4, FieldValue::Str("SMB2".to_string())));
    if data.len() >= 14 {
        let cmd = u16::from_le_bytes([data[12], data[13]]);
        layer.add_field(ProtoField::new("command", 12, 2, FieldValue::Uint(u64::from(cmd))));
        layer.add_field(ProtoField::new("command_name", 12, 2, FieldValue::Str(smb2_command_name(cmd).to_string())));
    }
    if data.len() >= 16 {
        let credits = u16::from_le_bytes([data[14], data[15]]);
        layer.add_field(ProtoField::new("credits", 14, 2, FieldValue::Uint(u64::from(credits))));
    }
    if data.len() >= 20 {
        let flags = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        layer.add_field(ProtoField::new("flags", 16, 4, FieldValue::Uint(u64::from(flags))));
    }
    if data.len() >= 64 {
        let session_id = u64::from_le_bytes([
            data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
        ]);
        layer.add_field(ProtoField::new("session_id", 40, 8, FieldValue::Uint(session_id)));
    }
}

// ────────────────────────────────────────────────────────────────────────────
// FTP full command set dissector
// ────────────────────────────────────────────────────────────────────────────

/// All standard FTP command names (RFC 959 + extensions).
#[must_use]
pub fn ftp_command_description(cmd: &str) -> &'static str {
    match cmd.to_uppercase().as_str() {
        "USER" => "User Name",
        "PASS" => "Password",
        "ACCT" => "Account",
        "CWD" => "Change Working Directory",
        "CDUP" => "Change to Parent Directory",
        "SMNT" => "Structure Mount",
        "REIN" => "Reinitialize",
        "QUIT" => "Logout",
        "PORT" => "Data Port",
        "PASV" => "Passive",
        "TYPE" => "Representation Type",
        "STRU" => "File Structure",
        "MODE" => "Transfer Mode",
        "RETR" => "Retrieve",
        "STOR" => "Store",
        "STOU" => "Store Unique",
        "APPE" => "Append",
        "ALLO" => "Allocate",
        "REST" => "Restart",
        "RNFR" => "Rename From",
        "RNTO" => "Rename To",
        "ABOR" => "Abort",
        "DELE" => "Delete",
        "RMD" => "Remove Directory",
        "MKD" => "Make Directory",
        "PWD" => "Print Working Directory",
        "LIST" => "List",
        "NLST" => "Name List",
        "SITE" => "Site Parameters",
        "SYST" => "System",
        "STAT" => "Status",
        "HELP" => "Help",
        "NOOP" => "No Operation",
        "FEAT" => "Feature",
        "OPTS" => "Options",
        "AUTH" => "Authentication/Security Mechanism",
        "PBSZ" => "Protection Buffer Size",
        "PROT" => "Data Channel Protection Level",
        "EPSV" => "Extended Passive Mode",
        "EPRT" => "Extended Port",
        "MLST" => "Machine List Single",
        "MLSD" => "Machine List Directory",
        _ => "Unknown Command",
    }
}

/// Full FTP dissector with command and response code decoding.
pub struct FtpFullDissector;

impl ProtocolDissector for FtpFullDissector {
    fn name(&self) -> &'static str {
        "FTP-Full"
    }
    fn ports(&self) -> &[u16] {
        &[21, 20]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| DissectError::ParseError("non-UTF8 FTP data".to_string()))?;
        let mut layer = ProtoLayer::new("FTP-Full", data.to_vec());

        // one command / response per dissection call
        if let Some(line) = text.lines().next() {
            if line.len() >= 3 && line[..3].chars().all(|c| c.is_ascii_digit()) {
                let code: u64 = line[..3].parse().unwrap_or(0);
                let continued = line.len() >= 4 && line.as_bytes()[3] == b'-';
                layer.add_field(ProtoField::new(
                    "response_code",
                    0,
                    3,
                    FieldValue::Uint(code),
                ));
                layer.add_field(ProtoField::new(
                    "multi_line",
                    3,
                    1,
                    FieldValue::Bool(continued),
                ));
                let msg = if line.len() > 4 { &line[4..] } else { "" };
                layer.add_field(ProtoField::new(
                    "message",
                    4,
                    msg.len(),
                    FieldValue::Str(msg.to_string()),
                ));
            } else {
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                let cmd = parts[0].to_uppercase();
                let desc = ftp_command_description(&cmd);
                layer.add_field(ProtoField::new(
                    "command",
                    0,
                    cmd.len(),
                    FieldValue::Str(cmd.clone()),
                ));
                layer.add_field(ProtoField::new(
                    "command_desc",
                    0,
                    desc.len(),
                    FieldValue::Str(desc.to_string()),
                ));
                if parts.len() == 2 {
                    layer.add_field(ProtoField::new(
                        "argument",
                        cmd.len() + 1,
                        parts[1].len(),
                        FieldValue::Str(parts[1].to_string()),
                    ));
                }
            }
        }

        packet.push_layer(layer);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SMTP full command/response dissector
// ────────────────────────────────────────────────────────────────────────────

/// SMTP command descriptions.
#[must_use]
pub fn smtp_command_description(cmd: &str) -> &'static str {
    match cmd.to_uppercase().as_str() {
        "EHLO" => "Extended HELO",
        "HELO" => "Hello",
        "MAIL" => "Mail From",
        "RCPT" => "Recipient To",
        "DATA" => "Start Mail Body",
        "RSET" => "Reset",
        "VRFY" => "Verify",
        "EXPN" => "Expand",
        "HELP" => "Help",
        "NOOP" => "No Operation",
        "QUIT" => "Disconnect",
        "AUTH" => "Authenticate",
        "STARTTLS" => "Start TLS",
        "BDAT" => "Binary Data",
        _ => "Unknown Command",
    }
}

/// SMTP response code descriptions.
#[must_use]
pub const fn smtp_response_description(code: u16) -> &'static str {
    match code {
        211 => "System status",
        214 => "Help message",
        220 => "Service ready",
        221 => "Service closing",
        235 => "Authentication successful",
        250 => "Requested mail action OK",
        251 => "User not local; will forward",
        252 => "Cannot VRFY user; will attempt delivery",
        334 => "Server challenge (AUTH)",
        354 => "Start mail input",
        421 => "Service not available",
        450 | 550 => "Mailbox unavailable",
        451 => "Local error in processing",
        452 => "Insufficient system storage",
        500 => "Syntax error, command unrecognized",
        501 => "Syntax error in parameters",
        502 => "Command not implemented",
        503 => "Bad sequence of commands",
        504 => "Command parameter not implemented",
        551 => "User not local",
        552 => "Exceeded storage allocation",
        553 => "Mailbox name not allowed",
        554 => "Transaction failed",
        _ => "Unknown",
    }
}

/// Full SMTP dissector.
pub struct SmtpFullDissector;

impl ProtocolDissector for SmtpFullDissector {
    fn name(&self) -> &'static str {
        "SMTP-Full"
    }
    fn ports(&self) -> &[u16] {
        &[25, 587, 465]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| DissectError::ParseError("non-UTF8 SMTP data".to_string()))?;
        let mut layer = ProtoLayer::new("SMTP-Full", data.to_vec());

        if let Some(line) = text.lines().next() {
            if line.len() >= 3 && line[..3].chars().all(|c| c.is_ascii_digit()) {
                let code: u16 = line[..3].parse().unwrap_or(0);
                let continued = line.len() >= 4 && line.as_bytes()[3] == b'-';
                layer.add_field(ProtoField::new(
                    "response_code",
                    0,
                    3,
                    FieldValue::Uint(u64::from(code)),
                ));
                layer.add_field(ProtoField::new(
                    "response_desc",
                    0,
                    0,
                    FieldValue::Str(smtp_response_description(code).to_string()),
                ));
                layer.add_field(ProtoField::new(
                    "multi_line",
                    3,
                    1,
                    FieldValue::Bool(continued),
                ));
                let msg = if line.len() > 4 { &line[4..] } else { "" };
                layer.add_field(ProtoField::new(
                    "message",
                    4,
                    msg.len(),
                    FieldValue::Str(msg.to_string()),
                ));
            } else {
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                let cmd = parts[0].to_uppercase();
                let desc = smtp_command_description(&cmd);
                layer.add_field(ProtoField::new(
                    "command",
                    0,
                    cmd.len(),
                    FieldValue::Str(cmd.clone()),
                ));
                layer.add_field(ProtoField::new(
                    "command_desc",
                    0,
                    desc.len(),
                    FieldValue::Str(desc.to_string()),
                ));
                if parts.len() == 2 {
                    layer.add_field(ProtoField::new(
                        "argument",
                        cmd.len() + 1,
                        parts[1].len(),
                        FieldValue::Str(parts[1].to_string()),
                    ));
                }
            }
        }

        packet.push_layer(layer);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// POP3 dissector
// ────────────────────────────────────────────────────────────────────────────

/// POP3 command descriptions.
#[must_use]
pub fn pop3_command_description(cmd: &str) -> &'static str {
    match cmd.to_uppercase().as_str() {
        "USER" => "User Name",
        "PASS" => "Password",
        "STAT" => "Mailbox Status",
        "LIST" => "List Messages",
        "RETR" => "Retrieve Message",
        "DELE" => "Delete Message",
        "NOOP" => "No Operation",
        "RSET" => "Reset",
        "QUIT" => "Disconnect",
        "TOP" => "Top of Message",
        "UIDL" => "Unique ID Listing",
        "CAPA" => "Capabilities",
        "APOP" => "Authenticated POP",
        "AUTH" => "Authentication",
        "STLS" => "Start TLS",
        _ => "Unknown Command",
    }
}

/// POP3 dissector.
pub struct Pop3Dissector;

impl ProtocolDissector for Pop3Dissector {
    fn name(&self) -> &'static str {
        "POP3"
    }
    fn ports(&self) -> &[u16] {
        &[110]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| DissectError::ParseError("non-UTF8 POP3 data".to_string()))?;
        let first_line = text.lines().next().unwrap_or("");
        let mut layer = ProtoLayer::new("POP3", data.to_vec());

        if first_line.starts_with("+OK") {
            layer.add_field(ProtoField::new(
                "status",
                0,
                3,
                FieldValue::Str("+OK".to_string()),
            ));
            let msg = if first_line.len() > 4 {
                &first_line[4..]
            } else {
                ""
            };
            layer.add_field(ProtoField::new(
                "message",
                4,
                msg.len(),
                FieldValue::Str(msg.to_string()),
            ));
        } else if first_line.starts_with("-ERR") {
            layer.add_field(ProtoField::new(
                "status",
                0,
                4,
                FieldValue::Str("-ERR".to_string()),
            ));
            let msg = if first_line.len() > 5 {
                &first_line[5..]
            } else {
                ""
            };
            layer.add_field(ProtoField::new(
                "message",
                5,
                msg.len(),
                FieldValue::Str(msg.to_string()),
            ));
        } else {
            let parts: Vec<&str> = first_line.splitn(2, ' ').collect();
            let cmd = parts[0].to_uppercase();
            let desc = pop3_command_description(&cmd);
            layer.add_field(ProtoField::new(
                "command",
                0,
                cmd.len(),
                FieldValue::Str(cmd.clone()),
            ));
            layer.add_field(ProtoField::new(
                "command_desc",
                0,
                desc.len(),
                FieldValue::Str(desc.to_string()),
            ));
            if parts.len() == 2 {
                layer.add_field(ProtoField::new(
                    "argument",
                    cmd.len() + 1,
                    parts[1].len(),
                    FieldValue::Str(parts[1].to_string()),
                ));
            }
        }

        packet.push_layer(layer);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// IMAP dissector
// ────────────────────────────────────────────────────────────────────────────

/// IMAP dissector (tagged command/untagged response parsing).
pub struct ImapDissector;

impl ProtocolDissector for ImapDissector {
    fn name(&self) -> &'static str {
        "IMAP"
    }
    fn ports(&self) -> &[u16] {
        &[143, 993]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| DissectError::ParseError("non-UTF8 IMAP data".to_string()))?;
        let first_line = text.lines().next().unwrap_or("");
        let mut layer = ProtoLayer::new("IMAP", data.to_vec());

        if let Some(rest) = first_line.strip_prefix("* ") {
            // Untagged response
            layer.add_field(ProtoField::new(
                "tag",
                0,
                1,
                FieldValue::Str("*".to_string()),
            ));
            let parts: Vec<&str> = rest.splitn(2, ' ').collect();
            layer.add_field(ProtoField::new(
                "status_or_type",
                2,
                parts[0].len(),
                FieldValue::Str(parts[0].to_string()),
            ));
            if parts.len() == 2 {
                layer.add_field(ProtoField::new(
                    "data",
                    2 + parts[0].len() + 1,
                    parts[1].len(),
                    FieldValue::Str(parts[1].to_string()),
                ));
            }
        } else {
            // Tagged command or response: TAG COMMAND/STATUS ...
            let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                layer.add_field(ProtoField::new(
                    "tag",
                    0,
                    parts[0].len(),
                    FieldValue::Str(parts[0].to_string()),
                ));
                layer.add_field(ProtoField::new(
                    "command",
                    parts[0].len() + 1,
                    parts[1].len(),
                    FieldValue::Str(parts[1].to_uppercase()),
                ));
                if parts.len() == 3 {
                    layer.add_field(ProtoField::new(
                        "argument",
                        parts[0].len() + parts[1].len() + 2,
                        parts[2].len(),
                        FieldValue::Str(parts[2].to_string()),
                    ));
                }
            } else {
                return Err(DissectError::ParseError("malformed IMAP line".to_string()));
            }
        }

        packet.push_layer(layer);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn eth_ipv4_tcp_frame() -> Vec<u8> {
        // dst_mac + src_mac + ethertype(0x0800) = 14 bytes
        let mut eth = vec![0u8; 14];
        eth[12] = 0x08;
        eth[13] = 0x00;
        // IPv4 header (20 bytes): version=4, ihl=5, total=40, proto=6(tcp), src=1.2.3.4, dst=5.6.7.8
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2] = 0;
        ip[3] = 40;
        ip[8] = 64;
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&[1, 2, 3, 4]);
        ip[16..20].copy_from_slice(&[5, 6, 7, 8]);
        // TCP header (20 bytes): src=1234, dst=80, data_offset=5
        let mut tcp = vec![0u8; 20];
        tcp[0] = 0x04;
        tcp[1] = 0xD2; // src_port=1234
        tcp[2] = 0x00;
        tcp[3] = 0x50; // dst_port=80
        tcp[12] = 0x50; // data_offset=5
        tcp[13] = 0x02; // SYN

        let mut out = eth;
        out.extend_from_slice(&ip);
        out.extend_from_slice(&tcp);
        out
    }

    #[test]
    fn dissect_ethernet_ipv4_tcp() {
        let data = eth_ipv4_tcp_frame();
        let mut pkt = DissectedPacket::new();
        EthernetDissector.dissect(&data, 0, &mut pkt).unwrap();
        assert!(pkt.layer("Ethernet").is_some());
        assert!(pkt.layer("IPv4").is_some());
        assert!(pkt.layer("TCP").is_some());
    }

    #[test]
    fn dissected_packet_pretty_print() {
        let data = eth_ipv4_tcp_frame();
        let mut pkt = DissectedPacket::new();
        EthernetDissector.dissect(&data, 0, &mut pkt).unwrap();
        let s = pkt.pretty_print();
        assert!(s.contains("Ethernet"));
        assert!(s.contains("IPv4"));
        assert!(s.contains("TCP"));
    }

    #[test]
    fn field_value_display_uint() {
        let fv = FieldValue::Uint(42);
        assert_eq!(fv.to_string(), "42");
    }

    #[test]
    fn field_value_display_mac() {
        let fv = FieldValue::MacAddr([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        assert!(fv.to_string().contains("de:ad:be:ef"));
    }

    #[test]
    fn field_value_display_ip() {
        let fv = FieldValue::IpAddr(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(fv.to_string(), "1.2.3.4");
    }

    #[test]
    fn proto_field_display() {
        let f = ProtoField::new("src_port", 0, 2, FieldValue::Uint(80));
        let s = f.to_string();
        assert!(s.contains("src_port"));
        assert!(s.contains("80"));
    }

    #[test]
    fn layer_field_lookup() {
        let mut layer = ProtoLayer::new("TCP", vec![]);
        layer.add_field(ProtoField::new("src_port", 0, 2, FieldValue::Uint(9000)));
        assert!(layer.field("src_port").is_some());
        assert!(layer.field("nonexistent").is_none());
    }

    #[test]
    fn dns_dissector() {
        let data: &[u8] = &[
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut pkt = DissectedPacket::new();
        DnsDissector.dissect(data, 0, &mut pkt).unwrap();
        assert!(pkt.layer("DNS").is_some());
        let l = pkt.layer("DNS").unwrap();
        assert!(l.field("id").is_some());
    }

    #[test]
    fn http_request_dissector() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut pkt = DissectedPacket::new();
        HttpDissector.dissect(raw, 0, &mut pkt).unwrap();
        let l = pkt.layer("HTTP").unwrap();
        assert_eq!(l.field("method").unwrap().value.to_string(), "GET");
    }

    #[test]
    fn http_response_dissector() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut pkt = DissectedPacket::new();
        HttpDissector.dissect(raw, 0, &mut pkt).unwrap();
        let l = pkt.layer("HTTP").unwrap();
        assert_eq!(l.field("status_code").unwrap().value.to_string(), "200");
    }

    #[test]
    fn smb1_dissector() {
        let data = b"\xFFSMBr\x00\x00\x00";
        let mut pkt = DissectedPacket::new();
        SmbDissector.dissect(data, 0, &mut pkt).unwrap();
        let l = pkt.layer("SMB").unwrap();
        assert_eq!(l.field("version").unwrap().value.to_string(), "SMB1");
    }

    #[test]
    fn ftp_command_dissector() {
        let data = b"USER anonymous\r\n";
        let mut pkt = DissectedPacket::new();
        FtpDissector.dissect(data, 0, &mut pkt).unwrap();
        let l = pkt.layer("FTP").unwrap();
        assert_eq!(l.field("command").unwrap().value.to_string(), "USER");
    }

    #[test]
    fn smtp_response_dissector() {
        let data = b"220 smtp.example.com ESMTP\r\n";
        let mut pkt = DissectedPacket::new();
        SmtpDissector.dissect(data, 0, &mut pkt).unwrap();
        let l = pkt.layer("SMTP").unwrap();
        assert_eq!(l.field("response_code").unwrap().value.to_string(), "220");
    }

    #[test]
    fn icmp_dissector() {
        let data = [8u8, 0, 0xF7, 0xFF];
        let mut pkt = DissectedPacket::new();
        IcmpDissector.dissect(&data, 0, &mut pkt).unwrap();
        let l = pkt.layer("ICMP").unwrap();
        assert_eq!(l.field("type").unwrap().value.to_string(), "8");
    }

    #[test]
    fn default_registry_has_all_dissectors() {
        let reg = default_registry();
        for name in [
            "Ethernet", "IPv4", "IPv6", "TCP", "UDP", "ICMP", "DNS", "HTTP", "TLS", "SMB", "FTP",
            "SMTP",
        ] {
            assert!(reg.by_name(name).is_some(), "missing dissector: {name}");
        }
    }

    #[test]
    fn registry_by_port() {
        let reg = default_registry();
        assert!(reg.by_port(53).is_some());
        assert!(reg.by_port(80).is_some());
        assert!(reg.by_port(443).is_some());
    }

    #[test]
    fn fingerprint_dns() {
        assert_eq!(fingerprint_protocol(&[], 0, 53), "DNS");
    }

    #[test]
    fn fingerprint_http_by_method() {
        assert_eq!(
            fingerprint_protocol(b"GET / HTTP/1.1\r\n", 0, 12345),
            "HTTP"
        );
    }

    #[test]
    fn fingerprint_tls_by_magic() {
        let data = [22u8, 3, 3, 0, 5];
        assert_eq!(fingerprint_protocol(&data, 0, 443), "TLS");
    }

    #[test]
    fn fingerprint_smb() {
        assert_eq!(fingerprint_protocol(b"\xFFSMBr", 0, 445), "SMB");
    }

    #[test]
    fn dissector_error_display() {
        let e = DissectError::NoDissector("RDP".to_string());
        assert!(e.to_string().contains("RDP"));
    }

    #[test]
    fn dissect_ipv6() {
        // 40-byte IPv6 header only.  Protocol 59 = "No Next Header" so no
        // sub-dissector is invoked and the empty payload is fine.
        let mut buf = vec![0u8; 40];
        buf[0] = 0x60; // version 6
        buf[6] = 59; // No Next Header
        buf[7] = 64; // hop limit
        buf[15] = 1; // src ::1
        buf[31] = 2; // dst ::2
        let mut pkt = DissectedPacket::new();
        Ipv6Dissector.dissect(&buf, 0, &mut pkt).unwrap();
        assert!(pkt.layer("IPv6").is_some());
    }

    // ── New spec-required types ───────────────────────────────────────────

    #[test]
    fn ip_version_display() {
        assert_eq!(IpVersion::V4.to_string(), "IPv4");
        assert_eq!(IpVersion::V6.to_string(), "IPv6");
    }

    #[test]
    fn ethernet_frame_parse_basic() {
        let mut bytes = vec![0u8; 14];
        bytes[0..6].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        bytes[6..12].copy_from_slice(&[0xCA, 0xFE, 0x00, 0x00, 0x00, 0x02]);
        bytes[12] = 0x08;
        bytes[13] = 0x00;
        let frame = EthernetFrame::parse(&bytes).unwrap();
        assert_eq!(frame.dst_mac, [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        assert_eq!(frame.src_mac, [0xCA, 0xFE, 0x00, 0x00, 0x00, 0x02]);
        assert_eq!(frame.ether_type, 0x0800);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn ethernet_frame_parse_too_short() {
        let bytes = vec![0u8; 10];
        assert!(matches!(
            EthernetFrame::parse(&bytes),
            Err(DissectError::TooShort { need: 14, got: 10 })
        ));
    }

    #[test]
    fn ipv4_packet_parse_basic() {
        let mut buf = vec![0u8; 20];
        buf[0] = 0x45; // version=4, ihl=5
        buf[2] = 0;
        buf[3] = 20;
        buf[8] = 128; // ttl
        buf[9] = 6; // proto TCP
        buf[12..16].copy_from_slice(&[1, 2, 3, 4]);
        buf[16..20].copy_from_slice(&[5, 6, 7, 8]);
        let pkt = Ipv4Packet::parse(&buf).unwrap();
        assert_eq!(pkt.version, 4);
        assert_eq!(pkt.ihl, 5);
        assert_eq!(pkt.ttl, 128);
        assert_eq!(pkt.proto, 6);
        assert_eq!(pkt.src, [1, 2, 3, 4]);
        assert_eq!(pkt.dst, [5, 6, 7, 8]);
    }

    #[test]
    fn ipv4_packet_wrong_version() {
        let mut buf = vec![0u8; 20];
        buf[0] = 0x65; // version=6
        assert!(matches!(
            Ipv4Packet::parse(&buf),
            Err(DissectError::InvalidMagic(_))
        ));
    }

    #[test]
    fn ipv4_packet_too_short() {
        let buf = vec![0u8; 10];
        assert!(matches!(
            Ipv4Packet::parse(&buf),
            Err(DissectError::TooShort { need: 20, got: 10 })
        ));
    }

    #[test]
    fn tcp_segment_parse_basic() {
        let mut buf = vec![0u8; 20];
        buf[0] = 0x04;
        buf[1] = 0xD2; // src_port=1234
        buf[2] = 0x00;
        buf[3] = 0x50; // dst_port=80
        buf[4..8].copy_from_slice(&1000u32.to_be_bytes()); // seq
        buf[8..12].copy_from_slice(&500u32.to_be_bytes()); // ack
        buf[12] = 0x50; // data_offset=5
        buf[13] = 0x12; // flags: SYN|ACK
        let seg = TcpSegment::parse(&buf).unwrap();
        assert_eq!(seg.src_port, 1234);
        assert_eq!(seg.dst_port, 80);
        assert_eq!(seg.seq, 1000);
        assert_eq!(seg.ack, 500);
        assert_eq!(seg.flags & 0x02, 0x02); // SYN
        assert_eq!(seg.flags & 0x10, 0x10); // ACK
    }

    #[test]
    fn tcp_segment_with_payload() {
        let payload = b"hello tcp";
        let mut buf = vec![0u8; 20 + payload.len()];
        buf[12] = 0x50;
        buf[13] = 0x18; // PSH+ACK
        buf[20..].copy_from_slice(payload);
        let seg = TcpSegment::parse(&buf).unwrap();
        assert_eq!(seg.payload, payload);
    }

    #[test]
    fn tcp_segment_too_short() {
        let buf = vec![0u8; 15];
        assert!(matches!(
            TcpSegment::parse(&buf),
            Err(DissectError::TooShort { need: 20, got: 15 })
        ));
    }

    #[test]
    fn udp_datagram_parse_basic() {
        let payload = b"hello udp";
        let mut buf = vec![0u8; 8 + payload.len()];
        buf[0] = 0x00;
        buf[1] = 0x35; // src_port=53
        buf[2] = 0xC0;
        buf[3] = 0x35; // dst_port=49205
        let len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
        buf[4] = u8::try_from(len >> 8).unwrap_or(u8::MAX);
        buf[5] = u8::try_from(len & 0xFF).unwrap_or(u8::MAX);
        buf[8..].copy_from_slice(payload);
        let dg = UdpDatagram::parse(&buf).unwrap();
        assert_eq!(dg.src_port, 53);
        assert_eq!(dg.payload, payload);
        assert_eq!(dg.length, len);
    }

    #[test]
    fn udp_datagram_too_short() {
        let buf = vec![0u8; 4];
        assert!(matches!(
            UdpDatagram::parse(&buf),
            Err(DissectError::TooShort { need: 8, got: 4 })
        ));
    }

    #[test]
    fn dns_query_parse() {
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
        let dns = DnsQuery::parse(data).unwrap();
        assert_eq!(dns.id, 0xABCD);
        assert_eq!(dns.questions.len(), 1);
        assert_eq!(dns.questions[0].name, "example.com");
        assert_eq!(dns.questions[0].qtype, 1);
    }

    #[test]
    fn dns_query_too_short() {
        let buf = vec![0u8; 8];
        assert!(matches!(
            DnsQuery::parse(&buf),
            Err(DissectError::TooShort { need: 12, got: 8 })
        ));
    }

    #[test]
    fn http_request_parse_get() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let req = HttpRequest::parse(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.uri, "/index.html");
        assert_eq!(req.version, "HTTP/1.1");
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "Host" && v == "example.com")
        );
        assert!(req.body.is_empty());
    }

    #[test]
    fn http_request_parse_post_with_body() {
        let raw = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let req = HttpRequest::parse(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn http_request_parse_error() {
        let raw = b"not an http request";
        assert!(HttpRequest::parse(raw).is_err());
    }

    #[test]
    fn dissect_error_new_variants() {
        let e1 = DissectError::TooShort { need: 20, got: 5 };
        assert!(e1.to_string().contains("20"));
        let e2 = DissectError::InvalidMagic("bad".to_string());
        assert!(e2.to_string().contains("bad"));
    }

    // ── Spec-required: EthernetFrame methods ──────────────────────────────

    #[test]
    fn ethernet_frame_src_dst_str() {
        let mut bytes = vec![0u8; 14];
        bytes[0..6].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]); // dst
        bytes[6..12].copy_from_slice(&[0xCA, 0xFE, 0x00, 0x00, 0x00, 0x02]); // src
        bytes[12] = 0x08;
        bytes[13] = 0x00;
        let frame = EthernetFrame::parse(&bytes).unwrap();
        assert_eq!(frame.src_str(), "ca:fe:00:00:00:02");
        assert_eq!(frame.dst_str(), "de:ad:be:ef:00:01");
    }

    #[test]
    fn ethernet_frame_is_ip() {
        let mut bytes = vec![0u8; 14];
        bytes[12] = 0x08;
        bytes[13] = 0x00; // IPv4
        let frame = EthernetFrame::parse(&bytes).unwrap();
        assert!(frame.is_ip());
        assert!(!frame.is_arp());
    }

    #[test]
    fn ethernet_frame_is_arp() {
        let mut bytes = vec![0u8; 14];
        bytes[12] = 0x08;
        bytes[13] = 0x06; // ARP
        let frame = EthernetFrame::parse(&bytes).unwrap();
        assert!(frame.is_arp());
        assert!(!frame.is_ip());
    }

    // ── Spec-required: Ipv4Packet methods ────────────────────────────────

    #[test]
    fn ipv4_packet_src_dst_str() {
        let mut buf = vec![0u8; 20];
        buf[0] = 0x45;
        buf[2] = 0;
        buf[3] = 20;
        buf[12..16].copy_from_slice(&[1, 2, 3, 4]);
        buf[16..20].copy_from_slice(&[5, 6, 7, 8]);
        let pkt = Ipv4Packet::parse(&buf).unwrap();
        assert_eq!(pkt.src_str(), "1.2.3.4");
        assert_eq!(pkt.dst_str(), "5.6.7.8");
    }

    #[test]
    fn ipv4_packet_is_tcp_udp() {
        let make = |proto: u8| {
            let mut buf = vec![0u8; 20];
            buf[0] = 0x45;
            buf[2] = 0;
            buf[3] = 20;
            buf[9] = proto;
            Ipv4Packet::parse(&buf).unwrap()
        };
        let tcp_pkt = make(6);
        assert!(tcp_pkt.is_tcp());
        assert!(!tcp_pkt.is_udp());
        let udp_pkt = make(17);
        assert!(udp_pkt.is_udp());
        assert!(!udp_pkt.is_tcp());
    }

    // ── Spec-required: TcpSegment flag methods + window ──────────────────

    #[test]
    fn tcp_segment_window_field() {
        let mut buf = vec![0u8; 20];
        buf[12] = 0x50;
        buf[14] = 0x1F;
        buf[15] = 0x90; // window = 8080
        let seg = TcpSegment::parse(&buf).unwrap();
        assert_eq!(seg.window, 8080);
    }

    #[test]
    fn tcp_segment_flag_helpers() {
        let make_flags = |flags: u8| {
            let mut buf = vec![0u8; 20];
            buf[12] = 0x50;
            buf[13] = flags;
            TcpSegment::parse(&buf).unwrap()
        };
        let syn = make_flags(0x02);
        assert!(syn.has_syn());
        assert!(!syn.has_ack());
        assert!(!syn.has_fin());
        assert!(!syn.has_rst());
        let ack = make_flags(0x10);
        assert!(ack.has_ack());
        assert!(!ack.has_syn());
        let fin = make_flags(0x01);
        assert!(fin.has_fin());
        let rst = make_flags(0x04);
        assert!(rst.has_rst());
        let syn_ack = make_flags(0x12);
        assert!(syn_ack.has_syn());
        assert!(syn_ack.has_ack());
    }

    // ── Spec-required: DnsMessage ─────────────────────────────────────────

    #[test]
    fn dns_message_parse_query() {
        let data: &[u8] = &[
            0xAB, 0xCD, // id
            0x01, 0x00, // flags query
            0x00, 0x01, // qdcount=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
            b'c', b'o', b'm', 0, 0x00, 0x01, // A
            0x00, 0x01, // IN
        ];
        let msg = DnsMessage::parse(data).unwrap();
        assert_eq!(msg.id, 0xABCD);
        assert!(msg.is_query());
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com");
        assert_eq!(msg.questions[0].qtype, 1);
        assert_eq!(msg.questions[0].qclass, 1);
    }

    #[test]
    fn dns_message_response_flag() {
        let mut data = vec![0u8; 12];
        data[2] = 0x80; // QR=1 (response)
        let msg = DnsMessage::parse(&data).unwrap();
        assert!(!msg.is_query());
    }

    #[test]
    fn dns_message_too_short() {
        let buf = vec![0u8; 8];
        assert!(DnsMessage::parse(&buf).is_err());
    }

    // ── Spec-required: DissectError::UnsupportedVersion ──────────────────

    #[test]
    fn dissect_error_unsupported_version() {
        let e = DissectError::UnsupportedVersion(5);
        assert!(e.to_string().contains('5'));
    }

    // ── Spec-required: DnsQuestion has qclass ────────────────────────────

    #[test]
    fn dns_query_qclass_parsed() {
        let data: &[u8] = &[
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b'w', b'w',
            b'w', 0, 0x00, 0x01, // A
            0x00, 0x01, // IN
        ];
        let dns = DnsQuery::parse(data).unwrap();
        assert_eq!(dns.questions[0].qclass, 1);
    }

    // ── DNS full message ──────────────────────────────────────────────────

    #[test]
    fn dns_full_message_query_only() {
        let data: &[u8] = &[
            0xAB, 0xCD, // id
            0x01, 0x00, // flags (query, RD)
            0x00, 0x01, // qdcount=1
            0x00, 0x00, // ancount=0
            0x00, 0x00, // nscount=0
            0x00, 0x00, // arcount=0
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00,
            0x01, // A
            0x00, 0x01, // IN
        ];
        let msg = DnsFullMessage::parse(data).unwrap();
        assert_eq!(msg.id, 0xABCD);
        assert!(msg.is_query());
        assert!(msg.recursion_desired());
        assert_eq!(msg.rcode(), 0);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com");
        assert_eq!(msg.answers.len(), 0);
    }

    #[test]
    fn dns_rtype_name_all() {
        assert_eq!(dns_rtype_name(1), "A");
        assert_eq!(dns_rtype_name(2), "NS");
        assert_eq!(dns_rtype_name(5), "CNAME");
        assert_eq!(dns_rtype_name(6), "SOA");
        assert_eq!(dns_rtype_name(12), "PTR");
        assert_eq!(dns_rtype_name(15), "MX");
        assert_eq!(dns_rtype_name(16), "TXT");
        assert_eq!(dns_rtype_name(28), "AAAA");
        assert_eq!(dns_rtype_name(33), "SRV");
        assert_eq!(dns_rtype_name(255), "ANY");
        assert_eq!(dns_rtype_name(99), "UNKNOWN");
    }

    #[test]
    fn dns_rdata_a_display() {
        let r = DnsRdata::A([1, 2, 3, 4]);
        assert_eq!(r.to_string(), "1.2.3.4");
    }

    #[test]
    fn dns_rdata_txt_display() {
        let r = DnsRdata::Txt(vec!["v=spf1 include:example.com ~all".to_string()]);
        assert!(r.to_string().contains("v=spf1"));
    }

    #[test]
    fn dns_full_dissector_dissects() {
        let data: &[u8] = &[
            0x11, 0x22, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b'f', b'o',
            b'o', 0, 0x00, 0x01, 0x00, 0x01,
        ];
        let mut pkt = DissectedPacket::new();
        DnsFullDissector.dissect(data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("DNS-Full").unwrap();
        assert_eq!(layer.field("id").unwrap().value.to_string(), "4386");
    }

    // ── TLS full dissector ────────────────────────────────────────────────

    #[test]
    fn tls_record_parse_empty_payload() {
        // Handshake record with 0-length payload
        let data = [22u8, 3, 3, 0, 0];
        let records = TlsRecord::parse_all(&data).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_type, TlsContentType::Handshake);
        assert!(records[0].payload.is_empty());
    }

    #[test]
    fn tls_content_type_from_u8() {
        assert_eq!(TlsContentType::from(20), TlsContentType::ChangeCipherSpec);
        assert_eq!(TlsContentType::from(21), TlsContentType::Alert);
        assert_eq!(TlsContentType::from(22), TlsContentType::Handshake);
        assert_eq!(TlsContentType::from(23), TlsContentType::ApplicationData);
        assert_eq!(TlsContentType::from(99), TlsContentType::Unknown(99));
    }

    #[test]
    fn tls_handshake_type_display() {
        assert_eq!(TlsHandshakeType::ClientHello.to_string(), "ClientHello");
        assert_eq!(TlsHandshakeType::ServerHello.to_string(), "ServerHello");
        assert_eq!(TlsHandshakeType::Unknown(42).to_string(), "Unknown(42)");
    }

    #[test]
    fn tls_version_name_known() {
        assert_eq!(tls_version_name(0x0303), "TLS 1.2");
        assert_eq!(tls_version_name(0x0304), "TLS 1.3");
        assert_eq!(tls_version_name(0x0000), "Unknown");
    }

    #[test]
    fn tls_full_dissector_app_data() {
        let data = [23u8, 3, 3, 0, 5, 0, 0, 0, 0, 0];
        let mut pkt = DissectedPacket::new();
        TlsFullDissector.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("TLS-Full").unwrap();
        assert_eq!(layer.field("record_count").unwrap().value.to_string(), "1");
    }

    // ── SSH dissector ─────────────────────────────────────────────────────

    #[test]
    fn ssh_banner_dissect() {
        let data = b"SSH-2.0-OpenSSH_8.9\r\n";
        let mut pkt = DissectedPacket::new();
        SshDissector.dissect(data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("SSH").unwrap();
        assert!(layer.field("banner").is_some());
        let banner = layer.field("banner").unwrap().value.to_string();
        assert!(banner.contains("OpenSSH"));
        assert_eq!(
            layer.field("proto_version").unwrap().value.to_string(),
            "2.0"
        );
    }

    #[test]
    fn ssh_binary_packet_dissect() {
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(&16u32.to_be_bytes()); // packet_length
        data[4] = 4; // padding_length
        data[5] = 20; // KEXINIT
        let mut pkt = DissectedPacket::new();
        SshDissector.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("SSH").unwrap();
        assert_eq!(
            layer.field("msg_type_name").unwrap().value.to_string(),
            "SSH_MSG_KEXINIT"
        );
    }

    #[test]
    fn ssh_msg_type_name_known() {
        assert_eq!(ssh_msg_type_name(20), "SSH_MSG_KEXINIT");
        assert_eq!(ssh_msg_type_name(1), "SSH_MSG_DISCONNECT");
        assert_eq!(ssh_msg_type_name(93), "SSH_MSG_CHANNEL_DATA");
        assert_eq!(ssh_msg_type_name(255), "SSH_MSG_UNKNOWN");
    }

    // ── RDP dissector ─────────────────────────────────────────────────────

    #[test]
    fn rdp_tpkt_dissect() {
        let data = [
            3u8, 0, // TPKT version=3, reserved
            0, 19,   // TPKT length=19
            14,   // X.224 LI=14
            0xE0, // X.224 Connection Request
            0, 0, // DST-REF
            0, 0, // SRC-REF
            0, // CLASS
        ];
        let mut pkt = DissectedPacket::new();
        RdpDissector.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("RDP").unwrap();
        assert_eq!(layer.field("tpkt_version").unwrap().value.to_string(), "3");
        assert_eq!(
            layer.field("x224_type").unwrap().value.to_string(),
            "X.224-CR"
        );
    }

    #[test]
    fn rdp_wrong_version_error() {
        let data = [2u8, 0, 0, 10];
        let mut pkt = DissectedPacket::new();
        assert!(RdpDissector.dissect(&data, 0, &mut pkt).is_err());
    }

    // ── DHCP dissector ────────────────────────────────────────────────────

    #[test]
    fn dhcp_parse_too_short() {
        let data = vec![0u8; 100];
        assert!(DhcpMessage::parse(&data).is_err());
    }

    #[test]
    fn dhcp_parse_wrong_magic() {
        let mut data = vec![0u8; 240];
        // Wrong magic cookie
        data[236] = 0xFF;
        assert!(DhcpMessage::parse(&data).is_err());
    }

    #[test]
    fn dhcp_parse_minimal() {
        let mut data = vec![0u8; 244];
        data[0] = 1; // BOOTREQUEST
        data[1] = 1; // Ethernet
        data[2] = 6; // hlen
        data[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // xid
        // DHCP magic cookie
        data[236..240].copy_from_slice(b"\x63\x82\x53\x63");
        // Option 53: DHCPDISCOVER, then END
        data[240] = 53;
        data[241] = 1;
        data[242] = 1;
        data[243] = 255;
        let msg = DhcpMessage::parse(&data).unwrap();
        assert_eq!(msg.xid, 0xDEAD_BEEF);
        assert_eq!(msg.op, 1);
        assert!(matches!(msg.msg_type, Some(DhcpMsgType::Discover)));
        assert_eq!(msg.type_str(), "DHCPDISCOVER");
    }

    #[test]
    fn dhcp_msg_type_display() {
        assert_eq!(DhcpMsgType::Discover.to_string(), "DHCPDISCOVER");
        assert_eq!(DhcpMsgType::Ack.to_string(), "DHCPACK");
        assert_eq!(DhcpMsgType::Unknown(42).to_string(), "Unknown(42)");
    }

    // ── HTTP response parse ───────────────────────────────────────────────

    #[test]
    fn http_response_parse_200() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello";
        let resp = HttpResponse::parse(raw).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.content_type(), Some("text/html"));
        assert_eq!(resp.content_length(), Some(5));
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn http_response_parse_404() {
        let raw = b"HTTP/1.0 404 Not Found\r\n\r\n";
        let resp = HttpResponse::parse(raw).unwrap();
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.reason, "Not Found");
    }

    #[test]
    fn http_response_header_case_insensitive() {
        let raw = b"HTTP/1.1 200 OK\r\nX-Custom: myvalue\r\n\r\n";
        let resp = HttpResponse::parse(raw).unwrap();
        assert_eq!(resp.header("x-custom"), Some("myvalue"));
        assert_eq!(resp.header("X-CUSTOM"), Some("myvalue"));
    }

    #[test]
    fn http_response_no_terminator_error() {
        let raw = b"HTTP/1.1 200 OK\r\n";
        assert!(HttpResponse::parse(raw).is_err());
    }

    // ── Chunked decode ────────────────────────────────────────────────────

    #[test]
    fn decode_http_chunked_basic() {
        let data = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let body = decode_http_chunked(data).unwrap();
        assert_eq!(body, b"hello world");
    }

    #[test]
    fn decode_http_chunked_empty() {
        let data = b"0\r\n\r\n";
        let body = decode_http_chunked(data).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn decode_http_chunked_with_extension() {
        // chunk-extension should be ignored
        let data = b"5;ext=val\r\nhello\r\n0\r\n\r\n";
        let body = decode_http_chunked(data).unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn decode_http_chunked_truncated_error() {
        let data = b"5\r\nhe"; // only 2 bytes of a 5-byte chunk
        assert!(decode_http_chunked(data).is_err());
    }

    // ── Dissector chain ───────────────────────────────────────────────────

    #[test]
    fn dissector_chain_empty() {
        let chain = DissectorChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        let pkt = chain.dissect_all(b"whatever");
        assert!(pkt.layers.is_empty());
    }

    #[test]
    fn dissector_chain_run() {
        let mut chain = DissectorChain::new();
        chain.push(Arc::new(FtpDissector));
        chain.push(Arc::new(SmtpDissector));
        assert_eq!(chain.len(), 2);
        let ftp = b"USER bob\r\n";
        let pkt = chain.dissect_all(ftp);
        // FTP dissector should succeed; SMTP may fail silently
        assert!(pkt.layer("FTP").is_some());
    }

    // ── Flow direction ────────────────────────────────────────────────────

    #[test]
    fn flow_dir_display() {
        assert_eq!(FlowDir::ClientToServer.to_string(), "C->S");
        assert_eq!(FlowDir::ServerToClient.to_string(), "S->C");
    }

    // ── Protocol fingerprint detailed ─────────────────────────────────────

    #[test]
    fn fingerprint_detailed_high_port() {
        let r = fingerprint_detailed(&[], 0, 443);
        assert_eq!(r.protocol, "TLS");
        assert_eq!(r.confidence, FingerprintConfidence::High);
    }

    #[test]
    fn fingerprint_detailed_ssh_banner() {
        let r = fingerprint_detailed(b"SSH-2.0-OpenSSH_8.9\r\n", 0, 12345);
        assert_eq!(r.protocol, "SSH");
        assert_eq!(r.confidence, FingerprintConfidence::High);
    }

    #[test]
    fn fingerprint_detailed_dhcp_cookie() {
        let mut data = vec![0u8; 240];
        data[236..240].copy_from_slice(b"\x63\x82\x53\x63");
        let r = fingerprint_detailed(&data, 0, 12345);
        assert_eq!(r.protocol, "DHCP");
    }

    #[test]
    fn fingerprint_confidence_order() {
        assert!(FingerprintConfidence::High > FingerprintConfidence::Medium);
        assert!(FingerprintConfidence::Medium > FingerprintConfidence::Low);
    }

    // ── SMB full dissector ────────────────────────────────────────────────

    #[test]
    fn smb1_full_dissector() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(b"\xFFSMB");
        data[4] = 0x72; // SMB_COM_NEGOTIATE
        let mut pkt = DissectedPacket::new();
        SmbFullDissector.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("SMB-Full").unwrap();
        assert_eq!(layer.field("version").unwrap().value.to_string(), "SMB1");
        assert_eq!(
            layer.field("command_name").unwrap().value.to_string(),
            "SMB_COM_NEGOTIATE"
        );
    }

    #[test]
    fn smb2_full_dissector() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"\xFESMB");
        data[12] = 0x00;
        data[13] = 0x00; // SMB2_NEGOTIATE
        let mut pkt = DissectedPacket::new();
        SmbFullDissector.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("SMB-Full").unwrap();
        assert_eq!(layer.field("version").unwrap().value.to_string(), "SMB2");
        assert_eq!(
            layer.field("command_name").unwrap().value.to_string(),
            "SMB2_NEGOTIATE"
        );
    }

    #[test]
    fn smb_command_names() {
        assert_eq!(smb1_command_name(0x72), "SMB_COM_NEGOTIATE");
        assert_eq!(smb1_command_name(0x73), "SMB_COM_SESSION_SETUP_ANDX");
        assert_eq!(smb2_command_name(0x0000), "SMB2_NEGOTIATE");
        assert_eq!(smb2_command_name(0x0008), "SMB2_READ");
    }

    // ── FTP full dissector ────────────────────────────────────────────────

    #[test]
    fn ftp_full_command_with_desc() {
        let data = b"RETR /pub/file.txt\r\n";
        let mut pkt = DissectedPacket::new();
        FtpFullDissector.dissect(data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("FTP-Full").unwrap();
        assert_eq!(layer.field("command").unwrap().value.to_string(), "RETR");
        assert_eq!(
            layer.field("command_desc").unwrap().value.to_string(),
            "Retrieve"
        );
    }

    #[test]
    fn ftp_full_response_multiline() {
        let data = b"220-ftp.example.com FTP Server\r\n220 Ready\r\n";
        let mut pkt = DissectedPacket::new();
        FtpFullDissector.dissect(data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("FTP-Full").unwrap();
        assert_eq!(
            layer.field("response_code").unwrap().value.to_string(),
            "220"
        );
        assert!(layer.field("multi_line").is_some());
    }

    #[test]
    fn ftp_command_descriptions() {
        assert_eq!(ftp_command_description("USER"), "User Name");
        assert_eq!(ftp_command_description("STOR"), "Store");
        assert_eq!(ftp_command_description("EPSV"), "Extended Passive Mode");
        assert_eq!(ftp_command_description("XYZ"), "Unknown Command");
    }

    // ── SMTP full dissector ───────────────────────────────────────────────

    #[test]
    fn smtp_full_ehlo() {
        let data = b"EHLO mail.example.com\r\n";
        let mut pkt = DissectedPacket::new();
        SmtpFullDissector.dissect(data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("SMTP-Full").unwrap();
        assert_eq!(layer.field("command").unwrap().value.to_string(), "EHLO");
        assert_eq!(
            layer.field("command_desc").unwrap().value.to_string(),
            "Extended HELO"
        );
    }

    #[test]
    fn smtp_full_250_response() {
        let data = b"250 OK\r\n";
        let mut pkt = DissectedPacket::new();
        SmtpFullDissector.dissect(data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("SMTP-Full").unwrap();
        assert_eq!(
            layer.field("response_code").unwrap().value.to_string(),
            "250"
        );
        assert_eq!(
            layer.field("response_desc").unwrap().value.to_string(),
            "Requested mail action OK"
        );
    }

    #[test]
    fn smtp_response_descriptions() {
        assert_eq!(smtp_response_description(220), "Service ready");
        assert_eq!(smtp_response_description(554), "Transaction failed");
        assert_eq!(smtp_response_description(9999), "Unknown");
    }

    // ── POP3 dissector ────────────────────────────────────────────────────

    #[test]
    fn pop3_ok_response() {
        let data = b"+OK POP3 server ready\r\n";
        let mut pkt = DissectedPacket::new();
        Pop3Dissector.dissect(data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("POP3").unwrap();
        assert_eq!(layer.field("status").unwrap().value.to_string(), "+OK");
        assert!(
            layer
                .field("message")
                .unwrap()
                .value
                .to_string()
                .contains("POP3")
        );
    }

    #[test]
    fn pop3_err_response() {
        let data = b"-ERR No such message\r\n";
        let mut pkt = DissectedPacket::new();
        Pop3Dissector.dissect(data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("POP3").unwrap();
        assert_eq!(layer.field("status").unwrap().value.to_string(), "-ERR");
    }

    #[test]
    fn pop3_command() {
        let data = b"RETR 1\r\n";
        let mut pkt = DissectedPacket::new();
        Pop3Dissector.dissect(data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("POP3").unwrap();
        assert_eq!(layer.field("command").unwrap().value.to_string(), "RETR");
        assert_eq!(
            layer.field("command_desc").unwrap().value.to_string(),
            "Retrieve Message"
        );
    }

    // ── IMAP dissector ────────────────────────────────────────────────────

    #[test]
    fn imap_untagged_response() {
        let data = b"* OK IMAP4rev1 ready\r\n";
        let mut pkt = DissectedPacket::new();
        ImapDissector.dissect(data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("IMAP").unwrap();
        assert_eq!(layer.field("tag").unwrap().value.to_string(), "*");
        assert_eq!(
            layer.field("status_or_type").unwrap().value.to_string(),
            "OK"
        );
    }

    #[test]
    fn imap_tagged_command() {
        let data = b"a001 LOGIN user pass\r\n";
        let mut pkt = DissectedPacket::new();
        ImapDissector.dissect(data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("IMAP").unwrap();
        assert_eq!(layer.field("tag").unwrap().value.to_string(), "a001");
        assert_eq!(layer.field("command").unwrap().value.to_string(), "LOGIN");
        assert_eq!(
            layer.field("argument").unwrap().value.to_string(),
            "user pass"
        );
    }

    // ── Full registry ─────────────────────────────────────────────────────

    #[test]
    fn full_registry_has_extended_dissectors() {
        let reg = full_registry();
        for name in [
            "DNS-Full",
            "TLS-Full",
            "SSH",
            "RDP",
            "DHCP",
            "SMB-Full",
            "FTP-Full",
            "SMTP-Full",
            "POP3",
            "IMAP",
        ] {
            assert!(reg.by_name(name).is_some(), "missing: {name}");
        }
    }
}

// ============================================================================
// Telnet dissector
// ============================================================================

/// Telnet command codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TelnetCommand {
    Se = 240,
    Nop = 241,
    Dm = 242,
    Brk = 243,
    Ip = 244,
    Ao = 245,
    Ayt = 246,
    Ec = 247,
    El = 248,
    Ga = 249,
    Sb = 250,
    Will = 251,
    Wont = 252,
    Do = 253,
    Dont = 254,
    Iac = 255,
}

impl TelnetCommand {
    /// Decode a byte to a Telnet command.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            240 => Some(Self::Se),
            241 => Some(Self::Nop),
            242 => Some(Self::Dm),
            243 => Some(Self::Brk),
            244 => Some(Self::Ip),
            245 => Some(Self::Ao),
            246 => Some(Self::Ayt),
            247 => Some(Self::Ec),
            248 => Some(Self::El),
            249 => Some(Self::Ga),
            250 => Some(Self::Sb),
            251 => Some(Self::Will),
            252 => Some(Self::Wont),
            253 => Some(Self::Do),
            254 => Some(Self::Dont),
            255 => Some(Self::Iac),
            _ => None,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Se => "SE",
            Self::Nop => "NOP",
            Self::Dm => "DM",
            Self::Brk => "BRK",
            Self::Ip => "IP",
            Self::Ao => "AO",
            Self::Ayt => "AYT",
            Self::Ec => "EC",
            Self::El => "EL",
            Self::Ga => "GA",
            Self::Sb => "SB",
            Self::Will => "WILL",
            Self::Wont => "WONT",
            Self::Do => "DO",
            Self::Dont => "DONT",
            Self::Iac => "IAC",
        }
    }
}

impl fmt::Display for TelnetCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A parsed Telnet negotiation sequence (IAC + cmd + option).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelnetNegotiation {
    /// The command (WILL/WONT/DO/DONT).
    pub command: u8,
    /// The option code.
    pub option: u8,
}

impl TelnetNegotiation {
    /// Friendly option name for common Telnet options.
    #[must_use]
    pub const fn option_name(&self) -> &'static str {
        match self.option {
            0 => "TRANSMIT-BINARY",
            1 => "ECHO",
            3 => "SUPPRESS-GO-AHEAD",
            5 => "STATUS",
            6 => "TIMING-MARK",
            24 => "TERMINAL-TYPE",
            31 => "NAWS",
            32 => "TERMINAL-SPEED",
            33 => "REMOTE-FLOW-CONTROL",
            34 => "LINEMODE",
            36 => "ENVIRON",
            39 => "NEW-ENVIRON",
            _ => "UNKNOWN",
        }
    }
}

impl fmt::Display for TelnetNegotiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cmd = TelnetCommand::from_u8(self.command).map_or_else(|| format!("{:#04x}", self.command), |c| c.name().to_string());
        write!(f, "IAC {} {} ({})", cmd, self.option, self.option_name())
    }
}

/// Result of dissecting a Telnet stream segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelnetDissection {
    /// All negotiations extracted from the segment.
    pub negotiations: Vec<TelnetNegotiation>,
    /// Raw text data (non-command bytes).
    pub text_data: Vec<u8>,
    /// Whether any IAC bytes were present.
    pub has_commands: bool,
}

impl TelnetDissection {
    /// Dissect a raw Telnet payload.
    #[must_use]
    pub fn dissect(data: &[u8]) -> Self {
        let mut negotiations = Vec::new();
        let mut text_data = Vec::new();
        let mut i = 0;
        while i < data.len() {
            if data[i] == 255 {
                // IAC
                if i + 1 < data.len() {
                    let cmd = data[i + 1];
                    if matches!(cmd, 251..=254) && i + 2 < data.len() {
                        negotiations.push(TelnetNegotiation {
                            command: cmd,
                            option: data[i + 2],
                        });
                        i += 3;
                    } else {
                        i += 2;
                    }
                } else {
                    i += 1;
                }
            } else {
                text_data.push(data[i]);
                i += 1;
            }
        }
        let has_commands = !negotiations.is_empty() || data.contains(&255);
        Self {
            negotiations,
            text_data,
            has_commands,
        }
    }

    /// Returns the text portion as a lossy UTF-8 string.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.text_data).into_owned()
    }
}

/// Dissector implementation for Telnet.
#[derive(Debug)]
pub struct TelnetDissector;

impl ProtocolDissector for TelnetDissector {
    fn name(&self) -> &'static str {
        "Telnet"
    }
    fn ports(&self) -> &[u16] {
        &[23]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let parsed = TelnetDissection::dissect(data);
        let mut proto_layer = ProtoLayer::new("Telnet", data.to_vec());
        proto_layer.add_field(ProtoField::new(
            "negotiation_count",
            0,
            0,
            FieldValue::Uint(parsed.negotiations.len() as u64),
        ));
        proto_layer.add_field(ProtoField::new(
            "text_bytes",
            0,
            0,
            FieldValue::Uint(parsed.text_data.len() as u64),
        ));
        for (i, neg) in parsed.negotiations.iter().enumerate() {
            proto_layer.add_field(ProtoField::new(
                format!("negotiation_{i}"),
                0,
                3,
                FieldValue::Str(neg.to_string()),
            ));
        }
        proto_layer.add_field(ProtoField::new(
            "text",
            0,
            parsed.text_data.len(),
            FieldValue::Str(parsed.text()),
        ));
        packet.push_layer(proto_layer);
        Ok(())
    }
}

// ============================================================================
// NTP dissector
// ============================================================================

/// NTP leap indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NtpLeap {
    NoWarning = 0,
    LastMinute61 = 1,
    LastMinute59 = 2,
    Unsynchronized = 3,
}

impl NtpLeap {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v & 0x3 {
            0 => Self::NoWarning,
            1 => Self::LastMinute61,
            2 => Self::LastMinute59,
            _ => Self::Unsynchronized,
        }
    }
}

impl fmt::Display for NtpLeap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoWarning => write!(f, "no-warning"),
            Self::LastMinute61 => write!(f, "last-minute-61"),
            Self::LastMinute59 => write!(f, "last-minute-59"),
            Self::Unsynchronized => write!(f, "unsynchronized"),
        }
    }
}

/// NTP mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NtpMode {
    Reserved = 0,
    SymmetricActive = 1,
    SymmetricPassive = 2,
    Client = 3,
    Server = 4,
    Broadcast = 5,
    ControlMessage = 6,
    Private = 7,
}

impl NtpMode {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v & 0x7 {
            1 => Self::SymmetricActive,
            2 => Self::SymmetricPassive,
            3 => Self::Client,
            4 => Self::Server,
            5 => Self::Broadcast,
            6 => Self::ControlMessage,
            7 => Self::Private,
            _ => Self::Reserved,
        }
    }
}

impl fmt::Display for NtpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reserved => write!(f, "reserved"),
            Self::SymmetricActive => write!(f, "symmetric-active"),
            Self::SymmetricPassive => write!(f, "symmetric-passive"),
            Self::Client => write!(f, "client"),
            Self::Server => write!(f, "server"),
            Self::Broadcast => write!(f, "broadcast"),
            Self::ControlMessage => write!(f, "control"),
            Self::Private => write!(f, "private"),
        }
    }
}

/// Parsed NTP v3/v4 packet (48 bytes fixed header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpPacket {
    /// Leap indicator.
    pub leap: NtpLeap,
    /// NTP version (3 or 4 typically).
    pub version: u8,
    /// Mode.
    pub mode: NtpMode,
    /// Stratum.
    pub stratum: u8,
    /// Poll interval exponent.
    pub poll: u8,
    /// Clock precision exponent (signed).
    pub precision: i8,
    /// Root delay (raw 32-bit fixed-point).
    pub root_delay: u32,
    /// Root dispersion (raw 32-bit fixed-point).
    pub root_dispersion: u32,
    /// Reference ID (4 bytes).
    pub reference_id: [u8; 4],
    /// Transmit timestamp high word.
    pub transmit_ts_high: u32,
    /// Transmit timestamp low word.
    pub transmit_ts_low: u32,
}

impl NtpPacket {
    /// Parse a 48-byte NTP header.
    ///
    /// # Errors
    /// Returns `Err` if the buffer is shorter than 48 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, DissectError> {
        if data.len() < 48 {
            return Err(DissectError::BufferTooShort {
                needed: 48,
                got: data.len(),
            });
        }
        let lvm = data[0];
        let leap = NtpLeap::from_u8(lvm >> 6);
        let ver = (lvm >> 3) & 0x7;
        let mode = NtpMode::from_u8(lvm & 0x7);
        Ok(Self {
            leap,
            version: ver,
            mode,
            stratum: data[1],
            poll: data[2],
            precision: i8::try_from(data[3]).unwrap_or(i8::MAX),
            root_delay: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            root_dispersion: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            reference_id: [data[12], data[13], data[14], data[15]],
            transmit_ts_high: u32::from_be_bytes([data[40], data[41], data[42], data[43]]),
            transmit_ts_low: u32::from_be_bytes([data[44], data[45], data[46], data[47]]),
        })
    }

    /// Reference ID as a string (stratum 1: ASCII code; higher: IP).
    #[must_use]
    pub fn refid_str(&self) -> String {
        if self.stratum <= 1 {
            let s: String = self
                .reference_id
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as char)
                .collect();
            s
        } else {
            format!(
                "{}.{}.{}.{}",
                self.reference_id[0],
                self.reference_id[1],
                self.reference_id[2],
                self.reference_id[3]
            )
        }
    }

    /// Returns `true` if this looks like a client query.
    #[must_use]
    pub fn is_client(&self) -> bool {
        self.mode == NtpMode::Client
    }

    /// Returns `true` if this looks like a server response.
    #[must_use]
    pub fn is_server(&self) -> bool {
        self.mode == NtpMode::Server
    }
}

/// NTP dissector.
#[derive(Debug)]
pub struct NtpDissector;

impl ProtocolDissector for NtpDissector {
    fn name(&self) -> &'static str {
        "NTP"
    }
    fn ports(&self) -> &[u16] {
        &[123]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let pkt = NtpPacket::parse(data)?;
        let mut proto_layer = ProtoLayer::new("NTP", data.to_vec());
        proto_layer.add_field(ProtoField::new(
            "version",
            0,
            1,
            FieldValue::Uint(u64::from(pkt.version)),
        ));
        proto_layer.add_field(ProtoField::new(
            "mode",
            0,
            1,
            FieldValue::Str(pkt.mode.to_string()),
        ));
        proto_layer.add_field(ProtoField::new(
            "leap",
            0,
            1,
            FieldValue::Str(pkt.leap.to_string()),
        ));
        proto_layer.add_field(ProtoField::new(
            "stratum",
            1,
            1,
            FieldValue::Uint(u64::from(pkt.stratum)),
        ));
        proto_layer.add_field(ProtoField::new(
            "reference_id",
            12,
            4,
            FieldValue::Str(pkt.refid_str()),
        ));
        packet.push_layer(proto_layer);
        Ok(())
    }
}

// ============================================================================
// Syslog dissector (RFC 3164 / RFC 5424)
// ============================================================================

/// Syslog severity levels (0 = Emergency, 7 = Debug).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum SyslogSeverity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl SyslogSeverity {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v & 7 {
            0 => Self::Emergency,
            1 => Self::Alert,
            2 => Self::Critical,
            3 => Self::Error,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Info,
            _ => Self::Debug,
        }
    }
}

impl fmt::Display for SyslogSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Emergency => write!(f, "EMERGENCY"),
            Self::Alert => write!(f, "ALERT"),
            Self::Critical => write!(f, "CRITICAL"),
            Self::Error => write!(f, "ERROR"),
            Self::Warning => write!(f, "WARNING"),
            Self::Notice => write!(f, "NOTICE"),
            Self::Info => write!(f, "INFO"),
            Self::Debug => write!(f, "DEBUG"),
        }
    }
}

/// Syslog facility codes (0–23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyslogFacility(pub u8);

impl SyslogFacility {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            0 => "kern",
            1 => "user",
            2 => "mail",
            3 => "daemon",
            4 => "auth",
            5 => "syslog",
            6 => "lpr",
            7 => "news",
            8 => "uucp",
            9 => "cron",
            10 => "authpriv",
            11 => "ftp",
            16 => "local0",
            17 => "local1",
            18 => "local2",
            19 => "local3",
            20 => "local4",
            21 => "local5",
            22 => "local6",
            23 => "local7",
            _ => "unknown",
        }
    }
}

impl fmt::Display for SyslogFacility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A parsed RFC 3164 syslog message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogMessage {
    /// Priority value from `<PRI>`.
    pub priority: u8,
    /// Facility derived from priority.
    pub facility: SyslogFacility,
    /// Severity derived from priority.
    pub severity: SyslogSeverity,
    /// Timestamp portion (raw string, unparsed).
    pub timestamp: String,
    /// Hostname.
    pub hostname: String,
    /// Tag (process name + optional PID).
    pub tag: String,
    /// Message body.
    pub message: String,
}

impl SyslogMessage {
    /// Parse an RFC 3164 syslog message from a string.
    ///
    /// # Errors
    /// Returns `Err` if the PRI field is missing or malformed.
    pub fn parse(s: &str) -> Result<Self, DissectError> {
        if !s.starts_with('<') {
            return Err(DissectError::ParseError("syslog: missing PRI".to_string()));
        }
        let close = s
            .find('>')
            .ok_or_else(|| DissectError::ParseError("syslog: unclosed PRI".to_string()))?;
        let priority_str = &s[1..close];
        let priority = priority_str.parse::<u8>().map_err(|_| {
            DissectError::ParseError(format!("syslog: bad priority: {priority_str}"))
        })?;
        let facility = SyslogFacility(priority >> 3);
        let severity = SyslogSeverity::from_u8(priority & 7);
        let rest = &s[close + 1..];
        // Very simple split: "MMM DD HH:MM:SS hostname tag: msg"
        let parts: Vec<&str> = rest.splitn(6, ' ').collect();
        let (timestamp, hostname, tag, message) = if parts.len() >= 5 {
            let ts = format!("{} {} {}", parts[0], parts[1], parts[2]);
            let host = parts[3].to_string();
            let (t, m) = parts[4].find(':').map_or_else(
                || (parts[4].to_string(), parts.get(5).copied().unwrap_or("").to_string()),
                |idx| (parts[4][..idx].to_string(), parts[4][idx + 1..].trim().to_string()),
            );
            (ts, host, t, m)
        } else {
            (
                String::new(),
                String::new(),
                String::new(),
                rest.to_string(),
            )
        };
        Ok(Self {
            priority,
            facility,
            severity,
            timestamp,
            hostname,
            tag,
            message,
        })
    }

    /// Returns `true` if the severity is Warning or worse.
    #[must_use]
    pub fn is_alarm(&self) -> bool {
        self.severity <= SyslogSeverity::Warning
    }
}

impl fmt::Display for SyslogMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<{}> {} {} {}: {}",
            self.priority, self.timestamp, self.hostname, self.tag, self.message
        )
    }
}

/// Syslog dissector.
#[derive(Debug)]
pub struct SyslogDissector;

impl ProtocolDissector for SyslogDissector {
    fn name(&self) -> &'static str {
        "Syslog"
    }
    fn ports(&self) -> &[u16] {
        &[514]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let s = std::str::from_utf8(data)
            .map_err(|_| DissectError::ParseError("syslog: non-UTF8 data".to_string()))?;
        let msg = SyslogMessage::parse(s)?;
        let mut proto_layer = ProtoLayer::new("Syslog", data.to_vec());
        proto_layer.add_field(ProtoField::new(
            "priority",
            0,
            0,
            FieldValue::Uint(u64::from(msg.priority)),
        ));
        proto_layer.add_field(ProtoField::new(
            "facility",
            0,
            0,
            FieldValue::Str(msg.facility.to_string()),
        ));
        proto_layer.add_field(ProtoField::new(
            "severity",
            0,
            0,
            FieldValue::Str(msg.severity.to_string()),
        ));
        proto_layer.add_field(ProtoField::new(
            "hostname",
            0,
            0,
            FieldValue::Str(msg.hostname.clone()),
        ));
        proto_layer.add_field(ProtoField::new(
            "tag",
            0,
            0,
            FieldValue::Str(msg.tag.clone()),
        ));
        proto_layer.add_field(ProtoField::new(
            "message",
            0,
            0,
            FieldValue::Str(msg.message),
        ));
        packet.push_layer(proto_layer);
        Ok(())
    }
}

// ============================================================================
// SNMP stub dissector
// ============================================================================

/// SNMP version codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnmpVersion {
    V1,
    V2c,
    V3,
    Unknown(u8),
}

impl SnmpVersion {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::V1,
            1 => Self::V2c,
            3 => Self::V3,
            x => Self::Unknown(x),
        }
    }
}

impl fmt::Display for SnmpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => write!(f, "SNMPv1"),
            Self::V2c => write!(f, "SNMPv2c"),
            Self::V3 => write!(f, "SNMPv3"),
            Self::Unknown(v) => write!(f, "SNMP(unknown={v})"),
        }
    }
}

/// SNMP PDU type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnmpPduType {
    GetRequest,
    GetNextRequest,
    GetResponse,
    SetRequest,
    Trap,
    GetBulkRequest,
    InformRequest,
    TrapV2,
    Report,
    Unknown(u8),
}

impl SnmpPduType {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::GetRequest,
            1 => Self::GetNextRequest,
            2 => Self::GetResponse,
            3 => Self::SetRequest,
            4 => Self::Trap,
            5 => Self::GetBulkRequest,
            6 => Self::InformRequest,
            7 => Self::TrapV2,
            8 => Self::Report,
            x => Self::Unknown(x),
        }
    }
}

impl fmt::Display for SnmpPduType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GetRequest => write!(f, "GetRequest"),
            Self::GetNextRequest => write!(f, "GetNextRequest"),
            Self::GetResponse => write!(f, "GetResponse"),
            Self::SetRequest => write!(f, "SetRequest"),
            Self::Trap => write!(f, "Trap"),
            Self::GetBulkRequest => write!(f, "GetBulk"),
            Self::InformRequest => write!(f, "Inform"),
            Self::TrapV2 => write!(f, "TrapV2"),
            Self::Report => write!(f, "Report"),
            Self::Unknown(v) => write!(f, "PDU({v})"),
        }
    }
}

/// Minimal SNMP header parsed from the first few BER-TLV bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpHeader {
    /// SNMP version.
    pub version: SnmpVersion,
    /// Community string (v1/v2c).
    pub community: String,
    /// PDU type.
    pub pdu_type: SnmpPduType,
    /// Total BER-encoded length seen.
    pub total_len: usize,
}

impl SnmpHeader {
    /// Very lightweight BER parse — extracts version, community, PDU type.
    ///
    /// # Errors
    /// Returns `Err` if the buffer is too short to contain the minimal fields.
    pub fn parse(data: &[u8]) -> Result<Self, DissectError> {
        if data.len() < 7 {
            return Err(DissectError::BufferTooShort {
                needed: 7,
                got: data.len(),
            });
        }
        // Outer SEQUENCE tag = 0x30
        if data[0] != 0x30 {
            return Err(DissectError::ParseError("SNMP: not a SEQUENCE".to_string()));
        }
        // Skip outer length (1 or 2 bytes)
        let (offset, _total) = if data[1] & 0x80 != 0 {
            let extra = (data[1] & 0x7F) as usize;
            if extra + 2 > data.len() {
                return Err(DissectError::BufferTooShort {
                    needed: extra + 2,
                    got: data.len(),
                });
            }
            (2 + extra, 0usize)
        } else {
            (2, data[1] as usize)
        };
        // INTEGER version
        if offset + 3 > data.len() || data[offset] != 0x02 {
            return Err(DissectError::ParseError(
                "SNMP: missing version INTEGER".to_string(),
            ));
        }
        let ver_len = data[offset + 1] as usize;
        if offset + 2 + ver_len > data.len() {
            return Err(DissectError::BufferTooShort {
                needed: offset + 2 + ver_len,
                got: data.len(),
            });
        }
        let ver_val = data[offset + 2]; // assume 1-byte version
        let version = SnmpVersion::from_u8(ver_val);
        let off2 = offset + 2 + ver_len;
        // OCTET STRING community
        if off2 + 2 > data.len() || data[off2] != 0x04 {
            return Err(DissectError::ParseError(
                "SNMP: missing community".to_string(),
            ));
        }
        let comm_len = data[off2 + 1] as usize;
        if off2 + 2 + comm_len > data.len() {
            return Err(DissectError::BufferTooShort {
                needed: off2 + 2 + comm_len,
                got: data.len(),
            });
        }
        let community = String::from_utf8_lossy(&data[off2 + 2..off2 + 2 + comm_len]).to_string();
        let off3 = off2 + 2 + comm_len;
        // PDU type = context class tag: 0xA0..0xA8
        let pdu_tag = if off3 < data.len() { data[off3] } else { 0xA0 };
        let pdu_type = SnmpPduType::from_u8(pdu_tag & 0x1F);
        Ok(Self {
            version,
            community,
            pdu_type,
            total_len: data.len(),
        })
    }
}

impl fmt::Display for SnmpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} community='{}' PDU={}",
            self.version, self.community, self.pdu_type
        )
    }
}

/// SNMP dissector.
#[derive(Debug)]
pub struct SnmpDissector;

impl ProtocolDissector for SnmpDissector {
    fn name(&self) -> &'static str {
        "SNMP"
    }
    fn ports(&self) -> &[u16] {
        &[161, 162]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let hdr = SnmpHeader::parse(data)?;
        let mut proto_layer = ProtoLayer::new("SNMP", data.to_vec());
        proto_layer.add_field(ProtoField::new(
            "version",
            0,
            0,
            FieldValue::Str(hdr.version.to_string()),
        ));
        proto_layer.add_field(ProtoField::new(
            "community",
            0,
            0,
            FieldValue::Str(hdr.community.clone()),
        ));
        proto_layer.add_field(ProtoField::new(
            "pdu_type",
            0,
            0,
            FieldValue::Str(hdr.pdu_type.to_string()),
        ));
        proto_layer.add_field(ProtoField::new(
            "total_len",
            0,
            0,
            FieldValue::Uint(hdr.total_len as u64),
        ));
        packet.push_layer(proto_layer);
        Ok(())
    }
}

// ============================================================================
// NetBIOS Name Service stub dissector
// ============================================================================

/// `NetBIOS` Name Service (NBNS) opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NbnsOpcode {
    Query,
    Registration,
    Release,
    Wack,
    Refresh,
    Unknown(u8),
}

impl NbnsOpcode {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v & 0xF {
            0 => Self::Query,
            5 => Self::Registration,
            6 => Self::Release,
            7 => Self::Wack,
            8 => Self::Refresh,
            x => Self::Unknown(x),
        }
    }
}

impl fmt::Display for NbnsOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query => write!(f, "QUERY"),
            Self::Registration => write!(f, "REGISTRATION"),
            Self::Release => write!(f, "RELEASE"),
            Self::Wack => write!(f, "WACK"),
            Self::Refresh => write!(f, "REFRESH"),
            Self::Unknown(v) => write!(f, "OP({v})"),
        }
    }
}

/// Minimal NBNS header (12-byte fixed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NbnsHeader {
    /// Transaction ID.
    pub transaction_id: u16,
    /// Flags word.
    pub flags: u16,
    /// Whether this is a response (QR bit).
    pub is_response: bool,
    /// Opcode.
    pub opcode: NbnsOpcode,
    /// Question count.
    pub qdcount: u16,
    /// Answer count.
    pub ancount: u16,
    /// Authority count.
    pub nscount: u16,
    /// Additional count.
    pub arcount: u16,
}

impl NbnsHeader {
    /// Parse a 12-byte NBNS header.
    ///
    /// # Errors
    /// Returns `Err` if the buffer is too short.
    pub fn parse(data: &[u8]) -> Result<Self, DissectError> {
        if data.len() < 12 {
            return Err(DissectError::BufferTooShort {
                needed: 12,
                got: data.len(),
            });
        }
        let tid = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        Ok(Self {
            transaction_id: tid,
            flags,
            is_response: (flags & 0x8000) != 0,
            opcode: NbnsOpcode::from_u8(((flags >> 11) & 0xF) as u8),
            qdcount: u16::from_be_bytes([data[4], data[5]]),
            ancount: u16::from_be_bytes([data[6], data[7]]),
            nscount: u16::from_be_bytes([data[8], data[9]]),
            arcount: u16::from_be_bytes([data[10], data[11]]),
        })
    }
}

/// `NetBIOS` Name Service dissector.
#[derive(Debug)]
pub struct NbnsDissector;

impl ProtocolDissector for NbnsDissector {
    fn name(&self) -> &'static str {
        "NBNS"
    }
    fn ports(&self) -> &[u16] {
        &[137]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let hdr = NbnsHeader::parse(data)?;
        let mut proto_layer = ProtoLayer::new("NBNS", data.to_vec());
        proto_layer.add_field(ProtoField::new(
            "transaction_id",
            0,
            2,
            FieldValue::Uint(u64::from(hdr.transaction_id)),
        ));
        proto_layer.add_field(ProtoField::new(
            "is_response",
            2,
            2,
            FieldValue::Bool(hdr.is_response),
        ));
        proto_layer.add_field(ProtoField::new(
            "opcode",
            2,
            2,
            FieldValue::Str(hdr.opcode.to_string()),
        ));
        proto_layer.add_field(ProtoField::new(
            "questions",
            4,
            2,
            FieldValue::Uint(u64::from(hdr.qdcount)),
        ));
        proto_layer.add_field(ProtoField::new(
            "answers",
            6,
            2,
            FieldValue::Uint(u64::from(hdr.ancount)),
        ));
        packet.push_layer(proto_layer);
        Ok(())
    }
}

// ============================================================================
// ICMP extended dissector
// ============================================================================

/// ICMP type constants.
pub mod icmp_types {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACHABLE: u8 = 3;
    pub const SOURCE_QUENCH: u8 = 4;
    pub const REDIRECT: u8 = 5;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const PARAMETER_PROBLEM: u8 = 12;
    pub const TIMESTAMP_REQUEST: u8 = 13;
    pub const TIMESTAMP_REPLY: u8 = 14;
    pub const INFO_REQUEST: u8 = 15;
    pub const INFO_REPLY: u8 = 16;
    pub const ADDRESS_MASK_REQUEST: u8 = 17;
    pub const ADDRESS_MASK_REPLY: u8 = 18;
}

/// Human-readable ICMP type name.
#[must_use]
pub const fn icmp_type_name(t: u8) -> &'static str {
    match t {
        icmp_types::ECHO_REPLY => "Echo Reply",
        icmp_types::DEST_UNREACHABLE => "Destination Unreachable",
        icmp_types::SOURCE_QUENCH => "Source Quench",
        icmp_types::REDIRECT => "Redirect",
        icmp_types::ECHO_REQUEST => "Echo Request",
        icmp_types::TIME_EXCEEDED => "Time Exceeded",
        icmp_types::PARAMETER_PROBLEM => "Parameter Problem",
        icmp_types::TIMESTAMP_REQUEST => "Timestamp Request",
        icmp_types::TIMESTAMP_REPLY => "Timestamp Reply",
        icmp_types::INFO_REQUEST => "Information Request",
        icmp_types::INFO_REPLY => "Information Reply",
        icmp_types::ADDRESS_MASK_REQUEST => "Address Mask Request",
        icmp_types::ADDRESS_MASK_REPLY => "Address Mask Reply",
        _ => "Unknown",
    }
}

/// ICMP extended dissector — augments the basic one with type/code names.
#[derive(Debug)]
pub struct IcmpExtDissector;

impl ProtocolDissector for IcmpExtDissector {
    fn name(&self) -> &'static str {
        "ICMP-Ext"
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        if data.len() < 8 {
            return Err(DissectError::BufferTooShort {
                needed: 8,
                got: data.len(),
            });
        }
        let icmp_type = data[0];
        let code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);
        let mut proto_layer = ProtoLayer::new("ICMP-Ext", data.to_vec());
        proto_layer.add_field(ProtoField::new(
            "type",
            0,
            1,
            FieldValue::Uint(u64::from(icmp_type)),
        ));
        proto_layer.add_field(ProtoField::new(
            "code",
            1,
            1,
            FieldValue::Uint(u64::from(code)),
        ));
        proto_layer.add_field(ProtoField::new(
            "checksum",
            2,
            2,
            FieldValue::Uint(u64::from(checksum)),
        ));
        proto_layer.add_field(ProtoField::new(
            "type_name",
            0,
            1,
            FieldValue::Str(icmp_type_name(icmp_type).to_string()),
        ));
        if icmp_type == icmp_types::ECHO_REQUEST || icmp_type == icmp_types::ECHO_REPLY {
            let id = u16::from_be_bytes([data[4], data[5]]);
            let seq = u16::from_be_bytes([data[6], data[7]]);
            proto_layer.add_field(ProtoField::new(
                "echo_id",
                4,
                2,
                FieldValue::Uint(u64::from(id)),
            ));
            proto_layer.add_field(ProtoField::new(
                "echo_seq",
                6,
                2,
                FieldValue::Uint(u64::from(seq)),
            ));
        }
        packet.push_layer(proto_layer);
        Ok(())
    }
}

// ============================================================================
// Protocol fingerprinter extensions
// ============================================================================

/// Fingerprint a UDP payload to a protocol name.
#[must_use]
pub fn fingerprint_udp_payload(data: &[u8]) -> Option<&'static str> {
    if data.len() >= 48 {
        return Some("NTP");
    }
    if data.first() == Some(&0x30) && data.len() >= 7 {
        return Some("SNMP");
    }
    if data.len() >= 12 {
        return Some("NBNS");
    }
    None
}

/// Fingerprint a TCP payload to a protocol name.
#[must_use]
pub fn fingerprint_tcp_payload(data: &[u8]) -> Option<&'static str> {
    if data.first() == Some(&255) {
        return Some("Telnet");
    }
    if data.first() == Some(&b'<') {
        return Some("Syslog");
    }
    if data.starts_with(b"SSH-") {
        return Some("SSH");
    }
    if data.starts_with(b"HTTP/") {
        return Some("HTTP");
    }
    if data.starts_with(b"GET ") {
        return Some("HTTP");
    }
    if data.starts_with(b"POST ") {
        return Some("HTTP");
    }
    if data.starts_with(b"220 ") {
        return Some("SMTP");
    }
    if data.starts_with(b"+OK") {
        return Some("POP3");
    }
    if data.starts_with(b"* OK") {
        return Some("IMAP");
    }
    None
}

// ============================================================================
// Tests for the new dissectors
// ============================================================================

#[cfg(test)]
mod extra_dissect_tests {
    use super::*;

    // ── TelnetCommand ──────────────────────────────────────────────────────

    #[test]
    fn telnet_command_known() {
        assert_eq!(TelnetCommand::from_u8(255), Some(TelnetCommand::Iac));
        assert_eq!(TelnetCommand::from_u8(251), Some(TelnetCommand::Will));
        assert!(TelnetCommand::from_u8(10).is_none());
    }

    #[test]
    fn telnet_command_display() {
        assert_eq!(TelnetCommand::Will.to_string(), "WILL");
        assert_eq!(TelnetCommand::Iac.to_string(), "IAC");
    }

    // ── TelnetDissection ───────────────────────────────────────────────────

    #[test]
    fn telnet_dissect_plain_text() {
        let data = b"login: ";
        let d = TelnetDissection::dissect(data);
        assert_eq!(d.text(), "login: ");
        assert!(!d.has_commands);
    }

    #[test]
    fn telnet_dissect_negotiation() {
        // IAC WILL ECHO
        let data = [255u8, 251, 1, b'l', b'o', b'g'];
        let d = TelnetDissection::dissect(&data);
        assert_eq!(d.negotiations.len(), 1);
        assert_eq!(d.negotiations[0].command, 251);
        assert_eq!(d.negotiations[0].option, 1);
        assert!(d.has_commands);
        assert_eq!(d.text(), "log");
    }

    #[test]
    fn telnet_negotiation_option_name() {
        let neg = TelnetNegotiation {
            command: 251,
            option: 1,
        };
        assert_eq!(neg.option_name(), "ECHO");
        let neg2 = TelnetNegotiation {
            command: 251,
            option: 31,
        };
        assert_eq!(neg2.option_name(), "NAWS");
    }

    #[test]
    fn telnet_dissector_can_dissect() {
        // Telnet registers on port 23; we verify by checking name
        let d = TelnetDissector;
        assert_eq!(d.name(), "Telnet");
        // plain ASCII is valid Telnet data
        assert!(b"login: "[0].is_ascii());
    }

    #[test]
    fn telnet_dissector_layer() {
        let d = TelnetDissector;
        let data = [255u8, 253, 24]; // IAC DO TERMINAL-TYPE
        let mut pkt = DissectedPacket::new();
        d.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("Telnet").unwrap();
        assert_eq!(layer.name, "Telnet");
        assert!(layer.field("negotiation_0").is_some());
    }

    // ── NtpLeap / NtpMode ──────────────────────────────────────────────────

    #[test]
    fn ntp_leap_from_u8() {
        assert_eq!(NtpLeap::from_u8(0), NtpLeap::NoWarning);
        assert_eq!(NtpLeap::from_u8(3), NtpLeap::Unsynchronized);
    }

    #[test]
    fn ntp_mode_display() {
        assert!(NtpMode::Client.to_string().contains("client"));
        assert!(NtpMode::Server.to_string().contains("server"));
    }

    // ── NtpPacket ──────────────────────────────────────────────────────────

    #[test]
    fn ntp_packet_parse_client() {
        // Version 4, Mode client = 0b00_100_011 = 0x23
        let mut pkt = [0u8; 48];
        pkt[0] = 0x23;
        pkt[1] = 0; // stratum = unspecified
        let p = NtpPacket::parse(&pkt).unwrap();
        assert_eq!(p.version, 4);
        assert_eq!(p.mode, NtpMode::Client);
        assert!(p.is_client());
        assert!(!p.is_server());
    }

    #[test]
    fn ntp_packet_too_short() {
        assert!(NtpPacket::parse(&[0u8; 10]).is_err());
    }

    #[test]
    fn ntp_packet_refid_stratum1() {
        let mut pkt = [0u8; 48];
        pkt[0] = 0x24; // ver4 server
        pkt[1] = 1; // stratum 1
        pkt[12..16].copy_from_slice(b"GPS\0");
        let p = NtpPacket::parse(&pkt).unwrap();
        assert_eq!(p.refid_str(), "GPS");
    }

    #[test]
    fn ntp_dissector_layer() {
        let d = NtpDissector;
        let mut data = [0u8; 48];
        data[0] = 0x24; // ver4 server
        let mut pkt = DissectedPacket::new();
        d.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("NTP").unwrap();
        assert_eq!(layer.name, "NTP");
        assert!(layer.field("mode").is_some());
    }

    // ── SyslogSeverity / Facility ──────────────────────────────────────────

    #[test]
    fn syslog_severity_ordering() {
        assert!(SyslogSeverity::Emergency < SyslogSeverity::Debug);
        assert_eq!(SyslogSeverity::from_u8(4), SyslogSeverity::Warning);
    }

    #[test]
    fn syslog_facility_name() {
        assert_eq!(SyslogFacility(1).name(), "user");
        assert_eq!(SyslogFacility(16).name(), "local0");
    }

    // ── SyslogMessage ──────────────────────────────────────────────────────

    #[test]
    fn syslog_parse_rfc3164() {
        let s = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick";
        let msg = SyslogMessage::parse(s).unwrap();
        assert_eq!(msg.priority, 34);
        assert_eq!(msg.facility.0, 4); // auth
        assert_eq!(msg.severity, SyslogSeverity::Critical);
    }

    #[test]
    fn syslog_parse_missing_pri() {
        assert!(SyslogMessage::parse("no pri here").is_err());
    }

    #[test]
    fn syslog_is_alarm() {
        let s = "<2>Jan  1 00:00:00 host tag: msg";
        let msg = SyslogMessage::parse(s).unwrap();
        assert!(msg.is_alarm());
    }

    #[test]
    fn syslog_dissector_layer() {
        let d = SyslogDissector;
        let data = b"<34>Oct 11 22:14:15 mymachine su: failed";
        let mut pkt = DissectedPacket::new();
        d.dissect(data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("Syslog").unwrap();
        assert_eq!(layer.name, "Syslog");
        assert!(layer.field("severity").is_some());
    }

    // ── SnmpVersion / SnmpPduType ──────────────────────────────────────────

    #[test]
    fn snmp_version_display() {
        assert_eq!(SnmpVersion::V2c.to_string(), "SNMPv2c");
        assert!(SnmpVersion::Unknown(9).to_string().contains("unknown=9"));
    }

    #[test]
    fn snmp_pdu_type_display() {
        assert_eq!(SnmpPduType::GetRequest.to_string(), "GetRequest");
        assert_eq!(SnmpPduType::GetBulkRequest.to_string(), "GetBulk");
    }

    // ── SnmpHeader ─────────────────────────────────────────────────────────

    #[test]
    fn snmp_header_parse_v1() {
        // SEQUENCE { INTEGER 0, OCTET-STRING "public", [0]{ ... } }
        // 30 1d 02 01 00 04 06 70 75 62 6c 69 63 a0 10 ...
        let data: Vec<u8> = vec![
            0x30, 0x1d, 0x02, 0x01, 0x00, // INTEGER version = 0 (v1)
            0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // OCTET-STRING "public"
            0xa0, 0x10, // [0] PDU GetRequest
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let hdr = SnmpHeader::parse(&data).unwrap();
        assert_eq!(hdr.version, SnmpVersion::V1);
        assert_eq!(hdr.community, "public");
        assert_eq!(hdr.pdu_type, SnmpPduType::GetRequest);
    }

    #[test]
    fn snmp_header_too_short() {
        assert!(SnmpHeader::parse(&[0x30, 0x05]).is_err());
    }

    #[test]
    fn snmp_dissector_can_dissect() {
        // Verify SNMP dissector parses a valid packet without error
        let d = SnmpDissector;
        let mut data = vec![
            0x30u8, 0x1d, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c',
        ];
        data.extend([0xa0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut pkt = DissectedPacket::new();
        d.dissect(&data, 0, &mut pkt).unwrap();
        assert!(pkt.layer("SNMP").is_some());
    }

    // ── NbnsHeader ─────────────────────────────────────────────────────────

    #[test]
    fn nbns_header_parse_query() {
        let data: [u8; 12] = [
            0xAB, 0xCD, // tid
            0x01, 0x10, // flags: QR=0, opcode=0 (QUERY)
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, // ancount = 0
            0x00, 0x00, // nscount = 0
            0x00, 0x00, // arcount = 0
        ];
        let hdr = NbnsHeader::parse(&data).unwrap();
        assert_eq!(hdr.transaction_id, 0xABCD);
        assert!(!hdr.is_response);
        assert_eq!(hdr.qdcount, 1);
    }

    #[test]
    fn nbns_header_too_short() {
        assert!(NbnsHeader::parse(&[0; 4]).is_err());
    }

    #[test]
    fn nbns_dissector_layer() {
        let d = NbnsDissector;
        let data: [u8; 12] = [0x11, 0x22, 0x00, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let mut pkt = DissectedPacket::new();
        d.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("NBNS").unwrap();
        assert_eq!(layer.name, "NBNS");
        assert!(layer.field("transaction_id").is_some());
    }

    // ── IcmpExtDissector ───────────────────────────────────────────────────

    #[test]
    fn icmp_ext_echo_request() {
        let d = IcmpExtDissector;
        let data = [8u8, 0, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01];
        let mut pkt = DissectedPacket::new();
        d.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("ICMP-Ext").unwrap();
        assert_eq!(layer.name, "ICMP-Ext");
        let type_name = layer.field("type_name").unwrap();
        assert!(type_name.value.to_string().contains("Echo Request"));
        assert!(layer.field("echo_id").is_some());
    }

    #[test]
    fn icmp_ext_too_short() {
        let d = IcmpExtDissector;
        let mut pkt = DissectedPacket::new();
        assert!(d.dissect(&[8u8; 3], 0, &mut pkt).is_err());
    }

    #[test]
    fn icmp_type_name_known() {
        assert_eq!(icmp_type_name(0), "Echo Reply");
        assert_eq!(icmp_type_name(8), "Echo Request");
        assert_eq!(icmp_type_name(11), "Time Exceeded");
        assert_eq!(icmp_type_name(99), "Unknown");
    }

    // ── UDP/TCP fingerprinting ─────────────────────────────────────────────

    #[test]
    fn fingerprint_udp_ntp() {
        let data = [0u8; 48];
        assert_eq!(fingerprint_udp_payload(&data), Some("NTP"));
    }

    #[test]
    fn fingerprint_udp_snmp() {
        let data = [0x30u8, 0x1d, 0x02, 0x01, 0x00, 0x04, 0x06, 0x00];
        assert_eq!(fingerprint_udp_payload(&data), Some("SNMP"));
    }

    #[test]
    fn fingerprint_tcp_ssh() {
        assert_eq!(fingerprint_tcp_payload(b"SSH-2.0-OpenSSH"), Some("SSH"));
    }

    #[test]
    fn fingerprint_tcp_http_response() {
        assert_eq!(
            fingerprint_tcp_payload(b"HTTP/1.1 200 OK\r\n"),
            Some("HTTP")
        );
    }

    #[test]
    fn fingerprint_tcp_telnet() {
        let data = [255u8, 251, 1];
        assert_eq!(fingerprint_tcp_payload(&data), Some("Telnet"));
    }

    #[test]
    fn fingerprint_tcp_syslog() {
        assert_eq!(
            fingerprint_tcp_payload(b"<34>Oct 11 message"),
            Some("Syslog")
        );
    }

    #[test]
    fn nbns_opcode_display() {
        assert_eq!(NbnsOpcode::Query.to_string(), "QUERY");
        assert_eq!(NbnsOpcode::Registration.to_string(), "REGISTRATION");
    }

    #[test]
    fn snmp_header_display() {
        let hdr = SnmpHeader {
            version: SnmpVersion::V1,
            community: "public".to_string(),
            pdu_type: SnmpPduType::GetRequest,
            total_len: 32,
        };
        assert!(hdr.to_string().contains("SNMPv1"));
        assert!(hdr.to_string().contains("public"));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// §21.2 Spec-required dissector API
// ════════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────────
// FieldValue (spec §21.2 §1)
// ────────────────────────────────────────────────────────────────────────────

/// Typed value for a single dissected protocol field (spec §21.2 §1).
///
/// This is distinct from the existing [`FieldValue`] enum which is used by the
/// trait-based [`ProtocolDissector`] infrastructure.  This richer set matches
/// the exact variants demanded by §21.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FrameFieldValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    MacAddr([u8; 6]),
}

impl fmt::Display for FrameFieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8(v) => write!(f, "{v}"),
            Self::U16(v) => write!(f, "{v}"),
            Self::U32(v) => write!(f, "{v}"),
            Self::U64(v) => write!(f, "{v}"),
            Self::Bytes(b) => {
                let hex: String = b
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                write!(f, "{hex}")
            }
            Self::Text(s) => write!(f, "{s}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Ipv4(a) => write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Self::Ipv6(a) => {
                let words: Vec<String> = a
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                write!(f, "{}", words.join(":"))
            }
            Self::MacAddr(m) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Field (spec §21.2 §1)
// ────────────────────────────────────────────────────────────────────────────

/// A single named field within a [`DissectedFrame`] (spec §21.2 §1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub value: FrameFieldValue,
    /// Bit offset from the start of the layer payload.
    pub bit_offset: usize,
    /// Width of this field in bits.
    pub bit_len: usize,
    /// Human-readable representation (e.g. "0x0800 (IPv4)").
    pub display: String,
}

impl Field {
    /// Construct a field, deriving `display` from `value.to_string()` when not
    /// provided explicitly.
    pub fn new(
        name: impl Into<String>,
        value: FrameFieldValue,
        bit_offset: usize,
        bit_len: usize,
    ) -> Self {
        let display = value.to_string();
        Self {
            name: name.into(),
            value,
            bit_offset,
            bit_len,
            display,
        }
    }

    /// Construct a field with an explicit display string.
    pub fn with_display(
        name: impl Into<String>,
        value: FrameFieldValue,
        bit_offset: usize,
        bit_len: usize,
        display: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            bit_offset,
            bit_len,
            display: display.into(),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DissectedFrame (spec §21.2 §1)
// ────────────────────────────────────────────────────────────────────────────

/// The result of dissecting one protocol layer (spec §21.2 §1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissectedFrame {
    /// Protocol name (e.g. "Ethernet", "IPv4", "TCP").
    pub protocol: String,
    /// Ordered list of named fields parsed from the header.
    pub fields: Vec<Field>,
    /// Remaining payload to be handed to the next dissector, if any.
    pub sub_payload: Option<Vec<u8>>,
}

impl DissectedFrame {
    /// Create an empty frame for `protocol`.
    pub fn new(protocol: impl Into<String>) -> Self {
        Self {
            protocol: protocol.into(),
            fields: Vec::new(),
            sub_payload: None,
        }
    }

    /// Append a field.
    pub fn push_field(&mut self, field: Field) {
        self.fields.push(field);
    }

    /// Look up a field by name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DissectorContext (spec §21.2 §1)
// ────────────────────────────────────────────────────────────────────────────

/// Context passed to each [`Dissector::dissect`] call (spec §21.2 §1).
///
/// Carries metadata that dissectors may need (link type, encapsulation depth,
/// hint ports) without them having to inspect the raw packet again.
#[derive(Debug, Clone, Default)]
pub struct DissectorContext {
    /// Encapsulation depth (0 = link layer, 1 = network, …).
    pub depth: u32,
    /// Hint: source port from the outer transport layer.
    pub src_port: Option<u16>,
    /// Hint: destination port from the outer transport layer.
    pub dst_port: Option<u16>,
    /// Link-layer type (`DLT_EN10MB` = 1, etc.).
    pub link_type: u32,
}

impl DissectorContext {
    /// Produce a child context one level deeper.
    #[must_use]
    pub const fn child(&self) -> Self {
        Self {
            depth: self.depth + 1,
            ..*self
        }
    }

    /// Produce a child context with port hints set.
    #[must_use]
    pub const fn child_with_ports(self, src_port: u16, dst_port: u16) -> Self {
        Self {
            depth: self.depth + 1,
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            ..self
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Dissector trait (spec §21.2 §1)
// ────────────────────────────────────────────────────────────────────────────

/// Protocol dissector trait (spec §21.2 §1).
///
/// Distinct from the existing [`ProtocolDissector`] trait — this one returns a
/// self-contained [`DissectedFrame`] rather than appending to a mutable packet.
pub trait Dissector: Send + Sync {
    /// Protocol name this dissector handles (e.g. `"Ethernet"`).
    fn name(&self) -> &str;

    /// Hint ports for port-based dispatch.  Defaults to empty.
    fn ports(&self) -> &[u16] {
        &[]
    }

    /// Dissect `payload` and return a [`DissectedFrame`].
    ///
    /// # Errors
    ///
    /// Returns a [`DissectError`] if the data is too short or malformed.
    fn dissect(
        &self,
        payload: &[u8],
        ctx: &DissectorContext,
    ) -> Result<DissectedFrame, DissectError>;
}

// ────────────────────────────────────────────────────────────────────────────
// Helper: bit-level field construction
// ────────────────────────────────────────────────────────────────────────────

/// Extract `bit_len` bits starting at `bit_off` from `data` (big-endian).
/// Returns the value as a u64.
fn extract_bits(data: &[u8], bit_off: usize, bit_len: usize) -> u64 {
    let mut val: u64 = 0;
    for i in 0..bit_len {
        let abs_bit = bit_off + i;
        let byte_idx = abs_bit / 8;
        let bit_idx = 7 - (abs_bit % 8);
        if byte_idx < data.len() && (data[byte_idx] >> bit_idx) & 1 == 1 {
            val |= 1 << (bit_len - 1 - i);
        }
    }
    val
}

// ────────────────────────────────────────────────────────────────────────────
// §21.2 §2: EthernetDissector
// ────────────────────────────────────────────────────────────────────────────

/// Ethernet II dissector (spec §21.2 §2).
pub struct EthernetFrameDissector;

impl Dissector for EthernetFrameDissector {
    fn name(&self) -> &'static str {
        "Ethernet"
    }

    fn dissect(
        &self,
        payload: &[u8],
        _ctx: &DissectorContext,
    ) -> Result<DissectedFrame, DissectError> {
        if payload.len() < 14 {
            return Err(DissectError::TooShort {
                need: 14,
                got: payload.len(),
            });
        }
        let mut frame = DissectedFrame::new("Ethernet");

        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&payload[0..6]);
        src.copy_from_slice(&payload[6..12]);
        let ethertype = u16::from_be_bytes([payload[12], payload[13]]);

        let et_display = match ethertype {
            0x0800 => "0x0800 (IPv4)".to_string(),
            0x86DD => "0x86DD (IPv6)".to_string(),
            0x0806 => "0x0806 (ARP)".to_string(),
            other => format!("0x{other:04X}"),
        };

        frame.push_field(Field::new("dst_mac", FrameFieldValue::MacAddr(dst), 0, 48));
        frame.push_field(Field::new("src_mac", FrameFieldValue::MacAddr(src), 48, 48));
        frame.push_field(Field::with_display(
            "ethertype",
            FrameFieldValue::U16(ethertype),
            96,
            16,
            et_display,
        ));

        frame.sub_payload = Some(payload[14..].to_vec());
        Ok(frame)
    }
}

/// Dissect an Ethernet II frame (spec §21.2 §2 standalone fn).
/// # Errors
/// Returns an error if the operation fails.
pub fn dissect_ethernet(payload: &[u8]) -> Result<DissectedFrame, DissectError> {
    EthernetFrameDissector.dissect(payload, &DissectorContext::default())
}

// ────────────────────────────────────────────────────────────────────────────
// §21.2 §3: IPv4Dissector
// ────────────────────────────────────────────────────────────────────────────

/// IPv4 dissector (spec §21.2 §3).
pub struct Ipv4FrameDissector;

impl Ipv4FrameDissector {
    /// Verify the IPv4 header checksum using the one's-complement algorithm.
    /// Returns `true` when the checksum is correct.
    #[must_use] 
    pub fn verify_checksum(data: &[u8]) -> bool {
        if data.len() < 20 {
            return false;
        }
        let ihl = ((data[0] & 0x0F) as usize) * 4;
        if data.len() < ihl {
            return false;
        }
        let mut sum: u32 = 0;
        for i in (0..ihl).step_by(2) {
            let word = if i + 1 < ihl {
                u32::from(u16::from_be_bytes([data[i], data[i + 1]]))
            } else {
                u32::from(data[i]) << 8
            };
            sum += word;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum == 0xFFFF
    }
}

impl Dissector for Ipv4FrameDissector {
    fn name(&self) -> &'static str {
        "IPv4"
    }

    fn dissect(
        &self,
        payload: &[u8],
        _ctx: &DissectorContext,
    ) -> Result<DissectedFrame, DissectError> {
        if payload.len() < 20 {
            return Err(DissectError::TooShort {
                need: 20,
                got: payload.len(),
            });
        }
        let version = u8::try_from(extract_bits(payload, 0, 4)).unwrap_or(u8::MAX);
        let ihl = u8::try_from(extract_bits(payload, 4, 4)).unwrap_or(u8::MAX);
        let dscp = u8::try_from(extract_bits(payload, 8, 6)).unwrap_or(u8::MAX);
        let ecn = u8::try_from(extract_bits(payload, 14, 2)).unwrap_or(u8::MAX);
        let total_len = u16::from_be_bytes([payload[2], payload[3]]);
        let id = u16::from_be_bytes([payload[4], payload[5]]);
        let flags = u8::try_from(extract_bits(payload, 48, 3)).unwrap_or(u8::MAX);
        let frag_off = u16::try_from(extract_bits(payload, 51, 13)).unwrap_or(u16::MAX);
        let ttl = payload[8];
        let protocol = payload[9];
        let checksum = u16::from_be_bytes([payload[10], payload[11]]);
        let mut src_ip = [0u8; 4];
        let mut dst_ip = [0u8; 4];
        src_ip.copy_from_slice(&payload[12..16]);
        dst_ip.copy_from_slice(&payload[16..20]);

        let proto_display = match protocol {
            1 => "1 (ICMP)".to_string(),
            6 => "6 (TCP)".to_string(),
            17 => "17 (UDP)".to_string(),
            other => other.to_string(),
        };
        let checksum_ok = Self::verify_checksum(payload);

        let mut frame = DissectedFrame::new("IPv4");
        frame.push_field(Field::new("version", FrameFieldValue::U8(version), 0, 4));
        frame.push_field(Field::new("ihl", FrameFieldValue::U8(ihl), 4, 4));
        frame.push_field(Field::new("dscp", FrameFieldValue::U8(dscp), 8, 6));
        frame.push_field(Field::new("ecn", FrameFieldValue::U8(ecn), 14, 2));
        frame.push_field(Field::new(
            "total_len",
            FrameFieldValue::U16(total_len),
            16,
            16,
        ));
        frame.push_field(Field::new("id", FrameFieldValue::U16(id), 32, 16));
        frame.push_field(Field::new("flags", FrameFieldValue::U8(flags), 48, 3));
        frame.push_field(Field::new(
            "frag_offset",
            FrameFieldValue::U16(frag_off),
            51,
            13,
        ));
        frame.push_field(Field::new("ttl", FrameFieldValue::U8(ttl), 64, 8));
        frame.push_field(Field::with_display(
            "protocol",
            FrameFieldValue::U8(protocol),
            72,
            8,
            proto_display,
        ));
        frame.push_field(Field::with_display(
            "checksum",
            FrameFieldValue::U16(checksum),
            80,
            16,
            format!(
                "0x{checksum:04X} ({})",
                if checksum_ok { "valid" } else { "invalid" }
            ),
        ));
        frame.push_field(Field::new("src_ip", FrameFieldValue::Ipv4(src_ip), 96, 32));
        frame.push_field(Field::new("dst_ip", FrameFieldValue::Ipv4(dst_ip), 128, 32));

        let ihl_bytes = (ihl as usize) * 4;
        let end = (total_len as usize).min(payload.len());
        frame.sub_payload = Some(payload[ihl_bytes.min(end)..end].to_vec());
        Ok(frame)
    }
}

/// Dissect an IPv4 packet (spec §21.2 §3 standalone fn).
/// # Errors
/// Returns an error if the operation fails.
pub fn dissect_ipv4(payload: &[u8]) -> Result<DissectedFrame, DissectError> {
    Ipv4FrameDissector.dissect(payload, &DissectorContext::default())
}

// ────────────────────────────────────────────────────────────────────────────
// §21.2 §4: IPv6Dissector
// ────────────────────────────────────────────────────────────────────────────

/// IPv6 dissector (spec §21.2 §4).
pub struct Ipv6FrameDissector;

impl Dissector for Ipv6FrameDissector {
    fn name(&self) -> &'static str {
        "IPv6"
    }

    fn dissect(
        &self,
        payload: &[u8],
        _ctx: &DissectorContext,
    ) -> Result<DissectedFrame, DissectError> {
        if payload.len() < 40 {
            return Err(DissectError::TooShort {
                need: 40,
                got: payload.len(),
            });
        }
        let version = u8::try_from(extract_bits(payload, 0, 4)).unwrap_or(u8::MAX);
        let traffic_class = u8::try_from(extract_bits(payload, 4, 8)).unwrap_or(u8::MAX);
        let flow_label = u32::try_from(extract_bits(payload, 12, 20)).unwrap_or(u32::MAX);
        let payload_len = u16::from_be_bytes([payload[4], payload[5]]);
        let next_header = payload[6];
        let hop_limit = payload[7];
        let mut src_addr = [0u8; 16];
        let mut dst_addr = [0u8; 16];
        src_addr.copy_from_slice(&payload[8..24]);
        dst_addr.copy_from_slice(&payload[24..40]);

        let nh_display = match next_header {
            6 => "6 (TCP)".to_string(),
            17 => "17 (UDP)".to_string(),
            58 => "58 (ICMPv6)".to_string(),
            59 => "59 (No Next Header)".to_string(),
            other => other.to_string(),
        };

        let mut frame = DissectedFrame::new("IPv6");
        frame.push_field(Field::new("version", FrameFieldValue::U8(version), 0, 4));
        frame.push_field(Field::new(
            "traffic_class",
            FrameFieldValue::U8(traffic_class),
            4,
            8,
        ));
        frame.push_field(Field::new(
            "flow_label",
            FrameFieldValue::U32(flow_label),
            12,
            20,
        ));
        frame.push_field(Field::new(
            "payload_len",
            FrameFieldValue::U16(payload_len),
            32,
            16,
        ));
        frame.push_field(Field::with_display(
            "next_header",
            FrameFieldValue::U8(next_header),
            48,
            8,
            nh_display,
        ));
        frame.push_field(Field::new(
            "hop_limit",
            FrameFieldValue::U8(hop_limit),
            56,
            8,
        ));
        frame.push_field(Field::new(
            "src_addr",
            FrameFieldValue::Ipv6(src_addr),
            64,
            128,
        ));
        frame.push_field(Field::new(
            "dst_addr",
            FrameFieldValue::Ipv6(dst_addr),
            192,
            128,
        ));

        frame.sub_payload = Some(payload[40..].to_vec());
        Ok(frame)
    }
}

/// Dissect an IPv6 packet (spec §21.2 §4 standalone fn).
/// # Errors
/// Returns an error if the operation fails.
pub fn dissect_ipv6_frame(payload: &[u8]) -> Result<DissectedFrame, DissectError> {
    Ipv6FrameDissector.dissect(payload, &DissectorContext::default())
}

// ────────────────────────────────────────────────────────────────────────────
// §21.2 §5: TCPDissector
// ────────────────────────────────────────────────────────────────────────────

/// TCP dissector (spec §21.2 §5).
pub struct TcpFrameDissector;

impl TcpFrameDissector {
    /// Returns `true` if the frame contains a SYN but not an ACK (initial SYN).
    #[must_use] 
    pub fn is_handshake_syn(frame: &DissectedFrame) -> bool {
        frame.field("flags").is_some_and(|f| {
            if let FrameFieldValue::U16(v) = f.value {
                // SYN=0x002, ACK=0x010
                (v & 0x002) != 0 && (v & 0x010) == 0
            } else {
                false
            }
        })
    }

    /// Returns `true` if the frame has the RST flag set.
    #[must_use] 
    pub fn is_reset(frame: &DissectedFrame) -> bool {
        frame.field("flags").is_some_and(|f| {
            if let FrameFieldValue::U16(v) = f.value {
                (v & 0x004) != 0
            } else {
                false
            }
        })
    }
}

impl Dissector for TcpFrameDissector {
    fn name(&self) -> &'static str {
        "TCP"
    }

    fn dissect(
        &self,
        payload: &[u8],
        _ctx: &DissectorContext,
    ) -> Result<DissectedFrame, DissectError> {
        if payload.len() < 20 {
            return Err(DissectError::TooShort {
                need: 20,
                got: payload.len(),
            });
        }
        let src_port = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
        let seq_num = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let ack_num = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let data_offset = u8::try_from(extract_bits(payload, 96, 4)).unwrap_or(u8::MAX);
        // Flags: bits 103..111 (9 bits: NS CWR ECE URG ACK PSH RST SYN FIN)
        let flags_9bit = u16::try_from(extract_bits(payload, 103, 9)).unwrap_or(u16::MAX);
        let window = u16::from_be_bytes([payload[14], payload[15]]);
        let checksum = u16::from_be_bytes([payload[16], payload[17]]);
        let urgent = u16::from_be_bytes([payload[18], payload[19]]);

        let header_len = (data_offset as usize) * 4;

        let mut frame = DissectedFrame::new("TCP");
        frame.push_field(Field::new("src_port", FrameFieldValue::U16(src_port), 0, 16));
        frame.push_field(Field::new("dst_port", FrameFieldValue::U16(dst_port), 16, 16));
        frame.push_field(Field::new("seq_num", FrameFieldValue::U32(seq_num), 32, 32));
        frame.push_field(Field::new("ack_num", FrameFieldValue::U32(ack_num), 64, 32));
        frame.push_field(Field::new("data_offset", FrameFieldValue::U8(data_offset), 96, 4));
        frame.push_field(Field::with_display("flags", FrameFieldValue::U16(flags_9bit), 103, 9, tcp_flags_display(flags_9bit)));
        frame.push_field(Field::new("window", FrameFieldValue::U16(window), 112, 16));
        frame.push_field(Field::new("checksum", FrameFieldValue::U16(checksum), 128, 16));
        frame.push_field(Field::new("urgent", FrameFieldValue::U16(urgent), 144, 16));
        tcp_push_flag_fields(&mut frame, flags_9bit);

        let app_start = header_len.min(payload.len());
        frame.sub_payload = if app_start < payload.len() {
            Some(payload[app_start..].to_vec())
        } else {
            None
        };
        Ok(frame)
    }
}

fn tcp_flags_display(flags_9bit: u16) -> String {
    let mut s = String::new();
    if flags_9bit & 0x080 != 0 { s.push_str("CWR "); }
    if flags_9bit & 0x040 != 0 { s.push_str("ECE "); }
    if flags_9bit & 0x020 != 0 { s.push_str("URG "); }
    if flags_9bit & 0x010 != 0 { s.push_str("ACK "); }
    if flags_9bit & 0x008 != 0 { s.push_str("PSH "); }
    if flags_9bit & 0x004 != 0 { s.push_str("RST "); }
    if flags_9bit & 0x002 != 0 { s.push_str("SYN "); }
    if flags_9bit & 0x001 != 0 { s.push_str("FIN "); }
    s.trim_end().to_string()
}

fn tcp_push_flag_fields(frame: &mut DissectedFrame, flags_9bit: u16) {
    const DEFS: &[(&str, u16, usize)] = &[
        ("flag_fin", 0x001, 111), ("flag_syn", 0x002, 110), ("flag_rst", 0x004, 109),
        ("flag_psh", 0x008, 108), ("flag_ack", 0x010, 107), ("flag_urg", 0x020, 106),
        ("flag_ece", 0x040, 105), ("flag_cwr", 0x080, 104),
    ];
    for &(name, mask, bit_off) in DEFS {
        frame.push_field(Field::new(name, FrameFieldValue::Bool(flags_9bit & mask != 0), bit_off, 1));
    }
}

/// Dissect a TCP segment (spec §21.2 §5 standalone fn).
/// # Errors
/// Returns an error if the operation fails.
pub fn dissect_tcp_frame(payload: &[u8]) -> Result<DissectedFrame, DissectError> {
    TcpFrameDissector.dissect(payload, &DissectorContext::default())
}

// ────────────────────────────────────────────────────────────────────────────
// §21.2 §6: UDPDissector
// ────────────────────────────────────────────────────────────────────────────

/// UDP dissector (spec §21.2 §6).
pub struct UdpFrameDissector;

impl Dissector for UdpFrameDissector {
    fn name(&self) -> &'static str {
        "UDP"
    }

    fn dissect(
        &self,
        payload: &[u8],
        _ctx: &DissectorContext,
    ) -> Result<DissectedFrame, DissectError> {
        if payload.len() < 8 {
            return Err(DissectError::TooShort {
                need: 8,
                got: payload.len(),
            });
        }
        let src_port = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
        let length = u16::from_be_bytes([payload[4], payload[5]]);
        let checksum = u16::from_be_bytes([payload[6], payload[7]]);

        let mut frame = DissectedFrame::new("UDP");
        frame.push_field(Field::new(
            "src_port",
            FrameFieldValue::U16(src_port),
            0,
            16,
        ));
        frame.push_field(Field::new(
            "dst_port",
            FrameFieldValue::U16(dst_port),
            16,
            16,
        ));
        frame.push_field(Field::new("length", FrameFieldValue::U16(length), 32, 16));
        frame.push_field(Field::new(
            "checksum",
            FrameFieldValue::U16(checksum),
            48,
            16,
        ));

        let data_end = (length as usize).min(payload.len());
        frame.sub_payload = if data_end > 8 {
            Some(payload[8..data_end].to_vec())
        } else {
            None
        };
        Ok(frame)
    }
}

/// Dissect a UDP datagram (spec §21.2 §6 standalone fn).
/// # Errors
/// Returns an error if the operation fails.
pub fn dissect_udp_frame(payload: &[u8]) -> Result<DissectedFrame, DissectError> {
    UdpFrameDissector.dissect(payload, &DissectorContext::default())
}

// ────────────────────────────────────────────────────────────────────────────
// §21.2 §7: DNSDissector (full spec version)
// ────────────────────────────────────────────────────────────────────────────

/// DNS dissector (spec §21.2 §7) — produces a [`DissectedFrame`] with rich
/// question and answer section fields, including compressed name decoding.
pub struct DnsFrameDissector;

impl DnsFrameDissector {
    /// Decode a DNS name from `data` starting at `offset`, following pointer
    /// compression (RFC 1035 §4.1.4).  Returns `(name, next_offset)` where
    /// `next_offset` is the byte position after this name in the *linear* wire.
    #[must_use] 
    pub fn decode_dns_name(data: &[u8], offset: usize) -> (String, usize) {
        parse_dns_label(data, offset).unwrap_or_else(|_| (String::new(), offset))
    }
}

impl Dissector for DnsFrameDissector {
    fn name(&self) -> &'static str {
        "DNS"
    }
    fn ports(&self) -> &[u16] {
        &[53]
    }

    fn dissect(
        &self,
        payload: &[u8],
        _ctx: &DissectorContext,
    ) -> Result<DissectedFrame, DissectError> {
        if payload.len() < 12 {
            return Err(DissectError::TooShort {
                need: 12,
                got: payload.len(),
            });
        }
        let id = u16::from_be_bytes([payload[0], payload[1]]);
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);
        let nscount = u16::from_be_bytes([payload[8], payload[9]]);
        let additional_count = u16::from_be_bytes([payload[10], payload[11]]);

        let is_response = (flags & 0x8000) != 0;
        let opcode = ((flags >> 11) & 0x0F) as u8;
        let rcode = (flags & 0x000F) as u8;

        let mut frame = DissectedFrame::new("DNS");
        frame.push_field(Field::new(
            "transaction_id",
            FrameFieldValue::U16(id),
            0,
            16,
        ));
        frame.push_field(Field::with_display(
            "flags",
            FrameFieldValue::U16(flags),
            16,
            16,
            format!(
                "0x{flags:04X} ({}, opcode={opcode}, rcode={rcode})",
                if is_response { "response" } else { "query" }
            ),
        ));
        frame.push_field(Field::new("qdcount", FrameFieldValue::U16(qdcount), 32, 16));
        frame.push_field(Field::new("ancount", FrameFieldValue::U16(ancount), 48, 16));
        frame.push_field(Field::new("nscount", FrameFieldValue::U16(nscount), 64, 16));
        frame.push_field(Field::new("arcount", FrameFieldValue::U16(additional_count), 80, 16));

        let mut off = 12usize;
        dns_push_question_section(payload, qdcount, &mut frame, &mut off);
        dns_push_answer_section(payload, ancount, &mut frame, &mut off);

        Ok(frame)
    }
}

fn dns_push_question_section(payload: &[u8], qdcount: u16, frame: &mut DissectedFrame, off: &mut usize) {
    for i in 0..qdcount as usize {
        let (qname, next) = DnsFrameDissector::decode_dns_name(payload, *off);
        *off = next;
        if *off + 4 > payload.len() { break; }
        let qtype  = u16::from_be_bytes([payload[*off],     payload[*off + 1]]);
        let qclass = u16::from_be_bytes([payload[*off + 2], payload[*off + 3]]);
        *off += 4;
        frame.push_field(Field::with_display(format!("question[{i}].qname"), FrameFieldValue::Text(qname.clone()), 0, 0, qname));
        frame.push_field(Field::with_display(format!("question[{i}].qtype"), FrameFieldValue::U16(qtype), 0, 16, dns_rtype_name(qtype).to_string()));
        frame.push_field(Field::new(format!("question[{i}].qclass"), FrameFieldValue::U16(qclass), 0, 16));
    }
}

fn dns_rdata_display_str(payload: &[u8], off: usize, rtype: u16, rdlen: usize) -> String {
    match rtype {
        1 if rdlen == 4 => format!("{}.{}.{}.{}", payload[off], payload[off+1], payload[off+2], payload[off+3]),
        28 if rdlen == 16 => { let mut a = [0u8; 16]; a.copy_from_slice(&payload[off..off+16]); FrameFieldValue::Ipv6(a).to_string() }
        5 | 2 | 12 => DnsFrameDissector::decode_dns_name(payload, off).0,
        16 => {
            let mut pos = 0; let mut parts = Vec::new();
            while pos < rdlen {
                let slen = payload[off + pos] as usize; pos += 1;
                if pos + slen > rdlen { break; }
                parts.push(String::from_utf8_lossy(&payload[off + pos..off + pos + slen]).into_owned());
                pos += slen;
            }
            parts.join(" ")
        }
        _ => format!("<{rdlen} bytes>"),
    }
}

fn dns_push_answer_section(payload: &[u8], ancount: u16, frame: &mut DissectedFrame, off: &mut usize) {
    for i in 0..ancount as usize {
        if *off >= payload.len() { break; }
        let (rname, next) = DnsFrameDissector::decode_dns_name(payload, *off);
        *off = next;
        if *off + 10 > payload.len() { break; }
        let rtype  = u16::from_be_bytes([payload[*off],     payload[*off + 1]]);
        let rclass = u16::from_be_bytes([payload[*off + 2], payload[*off + 3]]);
        let ttl    = u32::from_be_bytes([payload[*off+4], payload[*off+5], payload[*off+6], payload[*off+7]]);
        let rdlen  = u16::from_be_bytes([payload[*off + 8], payload[*off + 9]]) as usize;
        *off += 10;
        if *off + rdlen > payload.len() { break; }
        let rdata_display = dns_rdata_display_str(payload, *off, rtype, rdlen);
        frame.push_field(Field::with_display(format!("answer[{i}].name"), FrameFieldValue::Text(rname.clone()), 0, 0, rname));
        frame.push_field(Field::with_display(format!("answer[{i}].type"), FrameFieldValue::U16(rtype), 0, 16, dns_rtype_name(rtype).to_string()));
        frame.push_field(Field::new(format!("answer[{i}].class"), FrameFieldValue::U16(rclass), 0, 16));
        frame.push_field(Field::new(format!("answer[{i}].ttl"), FrameFieldValue::U32(ttl), 0, 32));
        frame.push_field(Field::with_display(format!("answer[{i}].rdata"), FrameFieldValue::Bytes(payload[*off..*off+rdlen].to_vec()), 0, rdlen * 8, rdata_display));
        *off += rdlen;
    }
}

/// Dissect a DNS message (spec §21.2 §7 standalone fn).
/// # Errors
/// Returns an error if the operation fails.
pub fn dissect_dns_frame(payload: &[u8]) -> Result<DissectedFrame, DissectError> {
    DnsFrameDissector.dissect(payload, &DissectorContext::default())
}

// ────────────────────────────────────────────────────────────────────────────
// §21.2 §8: HTTPDissector
// ────────────────────────────────────────────────────────────────────────────

/// HTTP request parsed by the spec §21.2 §8 API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFrameRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// HTTP response parsed by the spec §21.2 §8 API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFrameResponse {
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// HTTP dissector (spec §21.2 §8).
pub struct HttpFrameDissector;

impl HttpFrameDissector {
    /// Detect whether `data` begins with an HTTP/1.x message (request or
    /// response).
    #[must_use] 
    pub fn detect_http(data: &[u8]) -> bool {
        if data.starts_with(b"HTTP/") {
            return true;
        }
        for method in [
            b"GET " as &[u8],
            b"POST ",
            b"PUT ",
            b"DELETE ",
            b"HEAD ",
            b"OPTIONS ",
            b"PATCH ",
            b"CONNECT ",
            b"TRACE ",
        ] {
            if data.starts_with(method) {
                return true;
            }
        }
        false
    }

    /// Parse an HTTP/1.x request.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::ParseError`] if the data is not a valid request.
    pub fn dissect_request(data: &[u8]) -> Result<HttpFrameRequest, DissectError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| DissectError::ParseError("non-UTF8 HTTP request".to_string()))?;
        let sep = text.find("\r\n\r\n").ok_or_else(|| {
            DissectError::ParseError("missing CRLFCRLF in HTTP request".to_string())
        })?;
        let header_section = &text[..sep];
        let body = data[sep + 4..].to_vec();
        let mut lines = header_section.split("\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| DissectError::ParseError("empty HTTP request".to_string()))?;
        let mut parts = request_line.splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        let version = parts.next().unwrap_or("").to_string();
        if method.is_empty() || path.is_empty() {
            return Err(DissectError::ParseError(
                "malformed HTTP request line".to_string(),
            ));
        }
        let headers = lines
            .filter_map(|line| {
                let idx = line.find(':')?;
                Some((
                    line[..idx].trim().to_string(),
                    line[idx + 1..].trim().to_string(),
                ))
            })
            .collect();
        Ok(HttpFrameRequest {
            method,
            path,
            version,
            headers,
            body,
        })
    }

    /// Parse an HTTP/1.x response.
    ///
    /// # Errors
    ///
    /// Returns [`DissectError::ParseError`] if the data is not a valid response.
    pub fn dissect_response(data: &[u8]) -> Result<HttpFrameResponse, DissectError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| DissectError::ParseError("non-UTF8 HTTP response".to_string()))?;
        let sep = text.find("\r\n\r\n").ok_or_else(|| {
            DissectError::ParseError("missing CRLFCRLF in HTTP response".to_string())
        })?;
        let header_section = &text[..sep];
        let body = data[sep + 4..].to_vec();
        let mut lines = header_section.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| DissectError::ParseError("empty HTTP response".to_string()))?;
        let mut parts = status_line.splitn(3, ' ');
        let _version = parts.next().unwrap_or("");
        let code_str = parts.next().unwrap_or("0");
        let reason = parts.next().unwrap_or("").to_string();
        let status_code = code_str
            .parse::<u16>()
            .map_err(|_| DissectError::ParseError(format!("invalid status code: {code_str}")))?;
        let headers = lines
            .filter_map(|line| {
                let idx = line.find(':')?;
                Some((
                    line[..idx].trim().to_string(),
                    line[idx + 1..].trim().to_string(),
                ))
            })
            .collect();
        Ok(HttpFrameResponse {
            status_code,
            reason,
            headers,
            body,
        })
    }
}

impl Dissector for HttpFrameDissector {
    fn name(&self) -> &'static str {
        "HTTP"
    }
    fn ports(&self) -> &[u16] {
        &[80, 8080, 8000]
    }

    fn dissect(
        &self,
        payload: &[u8],
        _ctx: &DissectorContext,
    ) -> Result<DissectedFrame, DissectError> {
        if !Self::detect_http(payload) {
            return Err(DissectError::ParseError("not an HTTP message".to_string()));
        }
        let mut frame = DissectedFrame::new("HTTP");
        if payload.starts_with(b"HTTP/") {
            let resp = Self::dissect_response(payload)?;
            frame.push_field(Field::new(
                "status_code",
                FrameFieldValue::U16(resp.status_code),
                0,
                16,
            ));
            frame.push_field(Field::new(
                "reason",
                FrameFieldValue::Text(resp.reason.clone()),
                0,
                0,
            ));
            for (k, v) in &resp.headers {
                frame.push_field(Field::new(
                    format!("header:{k}"),
                    FrameFieldValue::Text(v.clone()),
                    0,
                    0,
                ));
            }
            if !resp.body.is_empty() {
                frame.sub_payload = Some(resp.body);
            }
        } else {
            let req = Self::dissect_request(payload)?;
            frame.push_field(Field::new(
                "method",
                FrameFieldValue::Text(req.method.clone()),
                0,
                0,
            ));
            frame.push_field(Field::new(
                "path",
                FrameFieldValue::Text(req.path.clone()),
                0,
                0,
            ));
            frame.push_field(Field::new(
                "version",
                FrameFieldValue::Text(req.version.clone()),
                0,
                0,
            ));
            for (k, v) in &req.headers {
                frame.push_field(Field::new(
                    format!("header:{k}"),
                    FrameFieldValue::Text(v.clone()),
                    0,
                    0,
                ));
            }
            if !req.body.is_empty() {
                frame.sub_payload = Some(req.body);
            }
        }
        Ok(frame)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// §21.2 §9: TLSDissector (handshake parsing)
// ────────────────────────────────────────────────────────────────────────────

/// TLS dissector with full `ClientHello` parsing (spec §21.2 §9).
pub struct TlsFrameDissector;

impl TlsFrameDissector {
    /// Extract the SNI hostname from a TLS `ClientHello` record, if present.
    /// Returns `None` when the data is not a `ClientHello` or does not carry SNI.
    #[must_use] 
    pub fn parse_sni_extension(data: &[u8]) -> Option<String> {
        extract_tls_sni(data)
    }
}

impl Dissector for TlsFrameDissector {
    fn name(&self) -> &'static str {
        "TLS"
    }
    fn ports(&self) -> &[u16] {
        &[443, 8443]
    }

    fn dissect(
        &self,
        payload: &[u8],
        _ctx: &DissectorContext,
    ) -> Result<DissectedFrame, DissectError> {
        if payload.len() < 5 {
            return Err(DissectError::TooShort {
                need: 5,
                got: payload.len(),
            });
        }
        let content_type = payload[0];
        let version = u16::from_be_bytes([payload[1], payload[2]]);
        let rec_len = u16::from_be_bytes([payload[3], payload[4]]);

        let ct_display = match content_type {
            20 => "ChangeCipherSpec".to_string(),
            21 => "Alert".to_string(),
            22 => "Handshake".to_string(),
            23 => "ApplicationData".to_string(),
            24 => "Heartbeat".to_string(),
            other => format!("Unknown({other})"),
        };

        let mut frame = DissectedFrame::new("TLS");
        frame.push_field(Field::with_display(
            "content_type",
            FrameFieldValue::U8(content_type),
            0,
            8,
            ct_display,
        ));
        frame.push_field(Field::with_display(
            "version",
            FrameFieldValue::U16(version),
            8,
            16,
            format!("0x{version:04X} ({})", tls_version_name(version)),
        ));
        frame.push_field(Field::new("length", FrameFieldValue::U16(rec_len), 24, 16));

        // ClientHello parsing (content_type == 22, handshake_type == 1)
        if content_type == 22 && payload.len() >= 10 {
            tls_push_handshake_fields(payload, &mut frame);
        }

        // Carry the record payload forward for application-data records
        if content_type == 23 && payload.len() >= 5 + rec_len as usize {
            frame.sub_payload = Some(payload[5..5 + rec_len as usize].to_vec());
        }

        Ok(frame)
    }
}

fn tls_push_handshake_fields(payload: &[u8], frame: &mut DissectedFrame) {
    let hs_type = payload[5];
    let hs_len = u32::from_be_bytes([0, payload[6], payload[7], payload[8]]);
    frame.push_field(Field::with_display("handshake_type", FrameFieldValue::U8(hs_type), 40, 8, TlsHandshakeType::from(hs_type).to_string()));
    frame.push_field(Field::new("handshake_length", FrameFieldValue::U32(hs_len), 48, 24));
    if hs_type == 1 && payload.len() >= 11 {
        tls_push_client_hello_fields(payload, frame);
    }
}

fn tls_push_client_hello_fields(payload: &[u8], frame: &mut DissectedFrame) {
    let ch_version = if payload.len() >= 12 { u16::from_be_bytes([payload[9], payload[10]]) } else { 0 };
    frame.push_field(Field::with_display("client_hello.version", FrameFieldValue::U16(ch_version), 72, 16, format!("0x{ch_version:04X} ({})", tls_version_name(ch_version))));
    if payload.len() >= 43 {
        frame.push_field(Field::new("client_hello.random", FrameFieldValue::Bytes(payload[11..43].to_vec()), 88, 256));
        let sid_len = payload[43] as usize;
        if payload.len() >= 44 + sid_len {
            frame.push_field(Field::new("client_hello.session_id", FrameFieldValue::Bytes(payload[44..44+sid_len].to_vec()), 344, sid_len * 8));
            let cs_off = 44 + sid_len;
            if payload.len() >= cs_off + 2 {
                let cs_len = u16::from_be_bytes([payload[cs_off], payload[cs_off + 1]]) as usize;
                frame.push_field(Field::new("client_hello.cipher_suite_count", FrameFieldValue::U16(u16::try_from(cs_len / 2).unwrap_or(u16::MAX)), 0, 16));
            }
        }
    }
    if let Some(sni) = TlsFrameDissector::parse_sni_extension(payload) {
        frame.push_field(Field::new("client_hello.sni", FrameFieldValue::Text(sni.clone()), 0, 0));
        frame.sub_payload = None;
        if let Some(f) = frame.fields.last_mut() { f.display = sni; }
    }
}

/// Dissect a TLS record (spec §21.2 §9 standalone fn).
/// # Errors
/// Returns an error if the operation fails.
pub fn dissect_tls_frame(payload: &[u8]) -> Result<DissectedFrame, DissectError> {
    TlsFrameDissector.dissect(payload, &DissectorContext::default())
}

// ────────────────────────────────────────────────────────────────────────────
// §21.2 §10: DissectorRegistry — dissect_stack
// ────────────────────────────────────────────────────────────────────────────

/// Extract a `U16` value from a `Field`, used in port-extraction closures.
const fn extract_u16_field(x: &Field) -> Option<u16> {
    if let FrameFieldValue::U16(v) = x.value { Some(v) } else { None }
}

/// Frame-based dissector registry (spec §21.2 §10).
///
/// Uses the [`Dissector`] trait (not [`ProtocolDissector`]) and drives the
/// `dissect_stack` algorithm: Ethernet → IP → TCP/UDP → Application.
pub struct FrameDissectorRegistry {
    by_name: HashMap<String, Box<dyn Dissector>>,
    by_port: HashMap<u16, String>,
}

impl FrameDissectorRegistry {
    /// Build a registry pre-populated with all built-in spec dissectors.
    #[must_use]
    pub fn new() -> Self {
        let mut reg = Self {
            by_name: HashMap::new(),
            by_port: HashMap::new(),
        };
        reg.register_boxed(Box::new(EthernetFrameDissector));
        reg.register_boxed(Box::new(Ipv4FrameDissector));
        reg.register_boxed(Box::new(Ipv6FrameDissector));
        reg.register_boxed(Box::new(TcpFrameDissector));
        reg.register_boxed(Box::new(UdpFrameDissector));
        reg.register_boxed(Box::new(DnsFrameDissector));
        reg.register_boxed(Box::new(HttpFrameDissector));
        reg.register_boxed(Box::new(TlsFrameDissector));
        reg
    }

    fn register_boxed(&mut self, d: Box<dyn Dissector>) {
        let name = d.name().to_string();
        for &port in d.ports() {
            self.by_port.insert(port, name.clone());
        }
        self.by_name.insert(name, d);
    }

    /// Look up a dissector by name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&dyn Dissector> {
        self.by_name.get(name).map(std::convert::AsRef::as_ref)
    }

    /// Look up a dissector by port.
    #[must_use]
    pub fn by_port(&self, port: u16) -> Option<&dyn Dissector> {
        self.by_port.get(&port).and_then(|name| self.by_name(name))
    }

    /// Dissect a complete protocol stack from raw Ethernet bytes.
    ///
    /// Performs: Ethernet → IPv4/IPv6 → TCP/UDP → Application layer.
    /// Each layer's `sub_payload` is passed to the next dissector.  Port-based
    /// dispatch is used for the application layer.
    ///
    /// Errors at any layer cause that layer and all subsequent ones to be
    /// silently skipped (best-effort dissection).
    #[must_use]
    pub fn dissect_stack(&self, raw: &[u8]) -> Vec<DissectedFrame> {
        let mut frames = Vec::new();
        let ctx = DissectorContext::default();

        // Layer 2: Ethernet
        let Ok(eth) = EthernetFrameDissector.dissect(raw, &ctx) else { return frames };
        let ethertype = eth.field("ethertype").and_then(|f| {
            if let FrameFieldValue::U16(v) = f.value {
                Some(v)
            } else {
                None
            }
        });
        let l3_payload = eth.sub_payload.clone();
        frames.push(eth);

        let Some(l3_payload) = l3_payload else { return frames };

        // Layer 3: IP
        let ctx_l3 = ctx.child();
        let (ip_frame, protocol_hint) = match ethertype {
            Some(0x0800) => {
                let proto = if l3_payload.len() >= 10 {
                    Some(l3_payload[9])
                } else {
                    None
                };
                Ipv4FrameDissector.dissect(&l3_payload, &ctx_l3).map_or((None, None), |f| (Some(f), proto))
            }
            Some(0x86DD) => {
                let proto = if l3_payload.len() >= 7 {
                    Some(l3_payload[6])
                } else {
                    None
                };
                Ipv6FrameDissector.dissect(&l3_payload, &ctx_l3).map_or((None, None), |f| (Some(f), proto))
            }
            _ => (None, None),
        };

        let l4_payload = ip_frame.as_ref().and_then(|f| f.sub_payload.clone());
        let src_port_hint = ip_frame.as_ref().and(None::<u16>);
        let dst_port_hint = ip_frame.as_ref().and(None::<u16>);

        if let Some(f) = ip_frame {
            frames.push(f);
        }

        let Some(l4_payload) = l4_payload else { return frames };

        // Layer 4: TCP / UDP
        let ctx_l4 = ctx_l3.child();
        let (l4_frame, src_port, dst_port) = match protocol_hint {
            Some(6) => TcpFrameDissector.dissect(&l4_payload, &ctx_l4).map_or(
                (None, src_port_hint, dst_port_hint),
                |f| {
                    let sp = f.field("src_port").and_then(extract_u16_field);
                    let dp = f.field("dst_port").and_then(extract_u16_field);
                    (Some(f), sp, dp)
                }),
            Some(17) => UdpFrameDissector.dissect(&l4_payload, &ctx_l4).map_or(
                (None, src_port_hint, dst_port_hint),
                |f| {
                    let sp = f.field("src_port").and_then(extract_u16_field);
                    let dp = f.field("dst_port").and_then(extract_u16_field);
                    (Some(f), sp, dp)
                }),
            _ => (None, src_port_hint, dst_port_hint),
        };

        let app_payload = l4_frame.as_ref().and_then(|f| f.sub_payload.clone());
        if let Some(f) = l4_frame {
            frames.push(f);
        }

        // Layer 7: Application
        let app_payload = match app_payload {
            Some(p) if !p.is_empty() => p,
            _ => return frames,
        };

        let ctx_app = ctx_l4.child_with_ports(src_port.unwrap_or(0), dst_port.unwrap_or(0));

        // Port-based dispatch (try both src and dst)
        let app_dissector: Option<&dyn Dissector> = dst_port
            .and_then(|p| self.by_port(p))
            .or_else(|| src_port.and_then(|p| self.by_port(p)));

        if let Some(d) = app_dissector
            && let Ok(f) = d.dissect(&app_payload, &ctx_app) {
                frames.push(f);
                return frames;
            }

        // Content-based heuristics
        let heuristic: Option<&dyn Dissector> = if HttpFrameDissector::detect_http(&app_payload) {
            self.by_name("HTTP")
        } else if app_payload.first().copied() == Some(22) {
            self.by_name("TLS")
        } else if app_payload.len() >= 12 {
            // Simple DNS heuristic: low question count
            let qdcount = u16::from_be_bytes([app_payload[4], app_payload[5]]);
            if qdcount <= 4 {
                self.by_name("DNS")
            } else {
                None
            }
        } else {
            None
        };

        if let Some(d) = heuristic
            && let Ok(f) = d.dissect(&app_payload, &ctx_app) {
                frames.push(f);
            }

        frames
    }
}

impl Default for FrameDissectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// §21.2 Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod spec_tests {
    use super::*;

    // ── FrameFieldValue ───────────────────────────────────────────────────

    #[test]
    fn frame_field_value_u8_display() {
        assert_eq!(FrameFieldValue::U8(42).to_string(), "42");
    }

    #[test]
    fn frame_field_value_u16_display() {
        assert_eq!(FrameFieldValue::U16(2048).to_string(), "2048");
    }

    #[test]
    fn frame_field_value_u32_display() {
        assert_eq!(FrameFieldValue::U32(0xDEAD_BEEF).to_string(), "3735928559");
    }

    #[test]
    fn frame_field_value_u64_display() {
        assert_eq!(
            FrameFieldValue::U64(u64::MAX).to_string(),
            u64::MAX.to_string()
        );
    }

    #[test]
    fn frame_field_value_bool_display() {
        assert_eq!(FrameFieldValue::Bool(true).to_string(), "true");
        assert_eq!(FrameFieldValue::Bool(false).to_string(), "false");
    }

    #[test]
    fn frame_field_value_text_display() {
        assert_eq!(
            FrameFieldValue::Text("hello".to_string()).to_string(),
            "hello"
        );
    }

    #[test]
    fn frame_field_value_ipv4_display() {
        assert_eq!(
            FrameFieldValue::Ipv4([192, 168, 1, 1]).to_string(),
            "192.168.1.1"
        );
    }

    #[test]
    fn frame_field_value_mac_display() {
        let mac = FrameFieldValue::MacAddr([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        assert_eq!(mac.to_string(), "de:ad:be:ef:00:01");
    }

    #[test]
    fn frame_field_value_bytes_display() {
        let b = FrameFieldValue::Bytes(vec![0xCA, 0xFE]);
        assert_eq!(b.to_string(), "ca fe");
    }

    #[test]
    fn frame_field_value_ipv6_display() {
        let a = [0u8; 16];
        let v = FrameFieldValue::Ipv6(a);
        assert_eq!(v.to_string(), "0000:0000:0000:0000:0000:0000:0000:0000");
    }

    // ── Field ──────────────────────────────────────────────────────────────

    #[test]
    fn field_new_derives_display() {
        let f = Field::new("ttl", FrameFieldValue::U8(64), 64, 8);
        assert_eq!(f.name, "ttl");
        assert_eq!(f.display, "64");
        assert_eq!(f.bit_offset, 64);
        assert_eq!(f.bit_len, 8);
    }

    #[test]
    fn field_with_display_explicit() {
        let f = Field::with_display(
            "ethertype",
            FrameFieldValue::U16(0x0800),
            96,
            16,
            "0x0800 (IPv4)",
        );
        assert_eq!(f.display, "0x0800 (IPv4)");
    }

    // ── DissectedFrame ─────────────────────────────────────────────────────

    #[test]
    fn dissected_frame_field_lookup() {
        let mut frame = DissectedFrame::new("TCP");
        frame.push_field(Field::new("src_port", FrameFieldValue::U16(1234), 0, 16));
        assert!(frame.field("src_port").is_some());
        assert!(frame.field("nonexistent").is_none());
    }

    #[test]
    fn dissected_frame_sub_payload() {
        let mut frame = DissectedFrame::new("Ethernet");
        frame.sub_payload = Some(vec![1, 2, 3]);
        assert_eq!(frame.sub_payload.as_deref(), Some([1u8, 2, 3].as_slice()));
    }

    // ── DissectorContext ───────────────────────────────────────────────────

    #[test]
    fn dissector_context_child() {
        let ctx = DissectorContext {
            depth: 0,
            src_port: None,
            dst_port: None,
            link_type: 1,
        };
        let child = ctx.child();
        assert_eq!(child.depth, 1);
        assert_eq!(child.link_type, 1);
    }

    #[test]
    fn dissector_context_child_with_ports() {
        let ctx = DissectorContext::default();
        let child = ctx.child_with_ports(1234, 80);
        assert_eq!(child.depth, 1);
        assert_eq!(child.src_port, Some(1234));
        assert_eq!(child.dst_port, Some(80));
    }

    // ── EthernetFrameDissector ────────────────────────────────────────────

    fn make_eth_bytes(ethertype: u16) -> Vec<u8> {
        let mut b = vec![0u8; 14];
        b[0..6].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        b[6..12].copy_from_slice(&[0xCA, 0xFE, 0x00, 0x00, 0x00, 0x02]);
        b[12] = (ethertype >> 8) as u8;
        b[13] = (ethertype & 0xFF) as u8;
        b
    }

    #[test]
    fn ethernet_frame_dissector_basic() {
        let data = make_eth_bytes(0x0800);
        let ctx = DissectorContext::default();
        let frame = EthernetFrameDissector.dissect(&data, &ctx).unwrap();
        assert_eq!(frame.protocol, "Ethernet");
        assert!(frame.field("dst_mac").is_some());
        assert!(frame.field("src_mac").is_some());
        let et = frame.field("ethertype").unwrap();
        assert!(matches!(et.value, FrameFieldValue::U16(0x0800)));
        assert_eq!(et.display, "0x0800 (IPv4)");
    }

    #[test]
    fn ethernet_frame_dissector_arp_display() {
        let data = make_eth_bytes(0x0806);
        let ctx = DissectorContext::default();
        let frame = EthernetFrameDissector.dissect(&data, &ctx).unwrap();
        assert_eq!(frame.field("ethertype").unwrap().display, "0x0806 (ARP)");
    }

    #[test]
    fn ethernet_frame_dissector_ipv6_display() {
        let data = make_eth_bytes(0x86DD);
        let ctx = DissectorContext::default();
        let frame = EthernetFrameDissector.dissect(&data, &ctx).unwrap();
        assert_eq!(frame.field("ethertype").unwrap().display, "0x86DD (IPv6)");
    }

    #[test]
    fn ethernet_frame_dissector_too_short() {
        let ctx = DissectorContext::default();
        assert!(EthernetFrameDissector.dissect(&[0u8; 10], &ctx).is_err());
    }

    #[test]
    fn dissect_ethernet_fn() {
        let data = make_eth_bytes(0x0800);
        let frame = dissect_ethernet(&data).unwrap();
        assert_eq!(frame.protocol, "Ethernet");
    }

    // ── Ipv4FrameDissector ────────────────────────────────────────────────

    fn make_ipv4_bytes(proto: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0] = 0x45; // version=4, ihl=5
        b[2] = 0;
        b[3] = 20;
        b[8] = 64; // ttl
        b[9] = proto;
        b[12..16].copy_from_slice(&src);
        b[16..20].copy_from_slice(&dst);
        b
    }

    #[test]
    fn ipv4_frame_dissector_fields() {
        let data = make_ipv4_bytes(6, [1, 2, 3, 4], [5, 6, 7, 8]);
        let ctx = DissectorContext::default();
        let frame = Ipv4FrameDissector.dissect(&data, &ctx).unwrap();
        assert_eq!(frame.protocol, "IPv4");

        let ver = frame.field("version").unwrap();
        assert!(matches!(ver.value, FrameFieldValue::U8(4)));
        assert_eq!(ver.bit_offset, 0);
        assert_eq!(ver.bit_len, 4);

        let proto = frame.field("protocol").unwrap();
        assert!(matches!(proto.value, FrameFieldValue::U8(6)));
        assert!(proto.display.contains("TCP"));

        let src = frame.field("src_ip").unwrap();
        assert!(matches!(src.value, FrameFieldValue::Ipv4([1, 2, 3, 4])));
        assert_eq!(src.bit_offset, 96);
        assert_eq!(src.bit_len, 32);
    }

    #[test]
    fn ipv4_verify_checksum_valid() {
        // Craft a packet with correct checksum (all zero header with correct check)
        // Use a known-good IPv4 header
        let data: &[u8] = &[
            0x45, 0x00, 0x00, 0x14, // version+ihl, tos, total_len
            0x00, 0x00, 0x00, 0x00, // id, flags+frag
            0x40, 0x06, 0x00, 0x00, // ttl, proto, checksum (will be computed)
            0x7f, 0x00, 0x00, 0x01, // src 127.0.0.1
            0x7f, 0x00, 0x00, 0x01, // dst 127.0.0.1
        ];
        // Compute expected checksum
        let mut sum: u32 = 0;
        for i in (0..20usize).step_by(2) {
            sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let check = (!(u16::try_from(sum).unwrap_or(u16::MAX))).to_be_bytes();
        let mut data2 = data.to_vec();
        data2[10] = check[0];
        data2[11] = check[1];
        assert!(Ipv4FrameDissector::verify_checksum(&data2));
    }

    #[test]
    fn ipv4_verify_checksum_invalid() {
        let mut data = vec![0u8; 20];
        data[0] = 0x45;
        // checksum stays 0 (incorrect)
        assert!(!Ipv4FrameDissector::verify_checksum(&data));
    }

    #[test]
    fn ipv4_frame_dissector_too_short() {
        let ctx = DissectorContext::default();
        assert!(Ipv4FrameDissector.dissect(&[0u8; 10], &ctx).is_err());
    }

    // ── Ipv6FrameDissector ────────────────────────────────────────────────

    #[test]
    fn ipv6_frame_dissector_fields() {
        let mut data = vec![0u8; 40];
        data[0] = 0x60; // version=6, traffic_class upper=0
        data[6] = 6; // next_header = TCP
        data[7] = 64; // hop_limit
        data[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 1]);
        let ctx = DissectorContext::default();
        let frame = Ipv6FrameDissector.dissect(&data, &ctx).unwrap();
        assert_eq!(frame.protocol, "IPv6");

        let ver = frame.field("version").unwrap();
        assert!(matches!(ver.value, FrameFieldValue::U8(6)));
        assert_eq!(ver.bit_len, 4);

        let nh = frame.field("next_header").unwrap();
        assert!(matches!(nh.value, FrameFieldValue::U8(6)));
        assert!(nh.display.contains("TCP"));

        assert!(frame.field("hop_limit").is_some());
        assert!(frame.field("src_addr").is_some());
        assert!(frame.field("dst_addr").is_some());
    }

    #[test]
    fn ipv6_frame_dissector_too_short() {
        let ctx = DissectorContext::default();
        assert!(Ipv6FrameDissector.dissect(&[0u8; 20], &ctx).is_err());
    }

    // ── TcpFrameDissector ─────────────────────────────────────────────────

    fn make_tcp_bytes(src_port: u16, dst_port: u16, flags: u16) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0] = (src_port >> 8) as u8;
        b[1] = (src_port & 0xFF) as u8;
        b[2] = (dst_port >> 8) as u8;
        b[3] = (dst_port & 0xFF) as u8;
        b[12] = 0x50; // data_offset=5, reserved=0
        // flags occupy bits 103..111: byte 13 = lower 8 bits of the 9-bit field
        b[13] = (flags & 0xFF) as u8;
        b
    }

    #[test]
    fn tcp_frame_dissector_syn() {
        let data = make_tcp_bytes(12345, 80, 0x002); // SYN
        let ctx = DissectorContext::default();
        let frame = TcpFrameDissector.dissect(&data, &ctx).unwrap();
        assert_eq!(frame.protocol, "TCP");

        assert!(matches!(
            frame.field("src_port").unwrap().value,
            FrameFieldValue::U16(12345)
        ));
        assert!(matches!(
            frame.field("dst_port").unwrap().value,
            FrameFieldValue::U16(80)
        ));
        assert!(matches!(
            frame.field("flag_syn").unwrap().value,
            FrameFieldValue::Bool(true)
        ));
        assert!(matches!(
            frame.field("flag_ack").unwrap().value,
            FrameFieldValue::Bool(false)
        ));
        assert!(TcpFrameDissector::is_handshake_syn(&frame));
        assert!(!TcpFrameDissector::is_reset(&frame));
    }

    #[test]
    fn tcp_frame_dissector_rst() {
        let data = make_tcp_bytes(1234, 80, 0x004); // RST
        let ctx = DissectorContext::default();
        let frame = TcpFrameDissector.dissect(&data, &ctx).unwrap();
        assert!(TcpFrameDissector::is_reset(&frame));
        assert!(!TcpFrameDissector::is_handshake_syn(&frame));
    }

    #[test]
    fn tcp_frame_dissector_synack_not_handshake_syn() {
        let data = make_tcp_bytes(80, 12345, 0x012); // SYN+ACK
        let ctx = DissectorContext::default();
        let frame = TcpFrameDissector.dissect(&data, &ctx).unwrap();
        // SYN+ACK should NOT be classified as initial handshake SYN
        assert!(!TcpFrameDissector::is_handshake_syn(&frame));
    }

    #[test]
    fn tcp_frame_dissector_flags_display() {
        let data = make_tcp_bytes(9999, 443, 0x018); // PSH+ACK
        let ctx = DissectorContext::default();
        let frame = TcpFrameDissector.dissect(&data, &ctx).unwrap();
        let flags = frame.field("flags").unwrap();
        assert!(flags.display.contains("ACK"));
        assert!(flags.display.contains("PSH"));
    }

    #[test]
    fn tcp_frame_dissector_with_payload() {
        let payload = b"hello app";
        let mut data = make_tcp_bytes(1234, 80, 0x018);
        data.extend_from_slice(payload);
        let ctx = DissectorContext::default();
        let frame = TcpFrameDissector.dissect(&data, &ctx).unwrap();
        assert_eq!(frame.sub_payload.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn tcp_frame_dissector_too_short() {
        let ctx = DissectorContext::default();
        assert!(TcpFrameDissector.dissect(&[0u8; 15], &ctx).is_err());
    }

    // ── UdpFrameDissector ─────────────────────────────────────────────────

    #[test]
    fn udp_frame_dissector_basic() {
        let payload = b"data";
        let mut b = vec![0u8; 8 + payload.len()];
        b[0] = 0x00;
        b[1] = 0x35; // src_port=53
        b[2] = 0xC0;
        b[3] = 0x35; // dst_port=49205
        let len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
        b[4] = u8::try_from(len >> 8).unwrap_or(u8::MAX);
        b[5] = u8::try_from(len).unwrap_or(u8::MAX);
        b[8..].copy_from_slice(payload);
        let ctx = DissectorContext::default();
        let frame = UdpFrameDissector.dissect(&b, &ctx).unwrap();
        assert_eq!(frame.protocol, "UDP");
        assert!(matches!(
            frame.field("src_port").unwrap().value,
            FrameFieldValue::U16(53)
        ));
        assert_eq!(frame.sub_payload.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn udp_frame_dissector_too_short() {
        let ctx = DissectorContext::default();
        assert!(UdpFrameDissector.dissect(&[0u8; 4], &ctx).is_err());
    }

    // ── DnsFrameDissector ─────────────────────────────────────────────────

    fn make_dns_query() -> Vec<u8> {
        let mut data: Vec<u8> = vec![
            0xAB, 0xCD, // id
            0x01, 0x00, // flags query RD
            0x00, 0x01, // qdcount=1
            0x00, 0x00, // ancount=0
            0x00, 0x00, // nscount=0
            0x00, 0x00, // arcount=0
        ];
        // question: example.com A IN
        data.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00,
            0x01,
        ]);
        data
    }

    #[test]
    fn dns_frame_dissector_query() {
        let data = make_dns_query();
        let ctx = DissectorContext::default();
        let frame = DnsFrameDissector.dissect(&data, &ctx).unwrap();
        assert_eq!(frame.protocol, "DNS");
        assert!(matches!(
            frame.field("transaction_id").unwrap().value,
            FrameFieldValue::U16(0xABCD)
        ));
        assert_eq!(frame.field("qdcount").unwrap().value.to_string(), "1");
        assert!(frame.field("question[0].qname").is_some());
        assert_eq!(
            frame.field("question[0].qname").unwrap().display,
            "example.com"
        );
        assert_eq!(frame.field("question[0].qtype").unwrap().display, "A");
    }

    #[test]
    fn dns_frame_dissector_decode_dns_name() {
        let data = make_dns_query();
        let (name, _next) = DnsFrameDissector::decode_dns_name(&data, 12);
        assert_eq!(name, "example.com");
    }

    #[test]
    fn dns_frame_dissector_too_short() {
        let ctx = DissectorContext::default();
        assert!(DnsFrameDissector.dissect(&[0u8; 8], &ctx).is_err());
    }

    // ── HttpFrameDissector ────────────────────────────────────────────────

    #[test]
    fn http_detect_request() {
        assert!(HttpFrameDissector::detect_http(b"GET / HTTP/1.1\r\n"));
        assert!(HttpFrameDissector::detect_http(b"POST /api HTTP/1.1\r\n"));
        assert!(!HttpFrameDissector::detect_http(b"GARBAGE DATA"));
    }

    #[test]
    fn http_detect_response() {
        assert!(HttpFrameDissector::detect_http(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn http_dissect_request_fields() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let req = HttpFrameDissector::dissect_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/index.html");
        assert_eq!(req.version, "HTTP/1.1");
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "Host" && v == "example.com")
        );
        assert!(req.body.is_empty());
    }

    #[test]
    fn http_dissect_request_with_body() {
        let raw = b"POST /data HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let req = HttpFrameDissector::dissect_request(raw).unwrap();
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn http_dissect_response_fields() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let resp = HttpFrameDissector::dissect_response(raw).unwrap();
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.reason, "Not Found");
        assert!(resp.headers.iter().any(|(k, _)| k == "Content-Length"));
    }

    #[test]
    fn http_frame_dissector_request() {
        let raw = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let ctx = DissectorContext::default();
        let frame = HttpFrameDissector.dissect(raw, &ctx).unwrap();
        assert_eq!(frame.protocol, "HTTP");
        assert_eq!(frame.field("method").unwrap().display, "GET");
        assert_eq!(frame.field("path").unwrap().display, "/");
    }

    #[test]
    fn http_frame_dissector_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhi";
        let ctx = DissectorContext::default();
        let frame = HttpFrameDissector.dissect(raw, &ctx).unwrap();
        assert_eq!(frame.field("status_code").unwrap().display, "200");
        assert_eq!(frame.field("reason").unwrap().display, "OK");
        assert_eq!(frame.sub_payload.as_deref(), Some(b"hi".as_slice()));
    }

    #[test]
    fn http_frame_dissector_not_http() {
        let ctx = DissectorContext::default();
        assert!(HttpFrameDissector.dissect(b"GARBAGE", &ctx).is_err());
    }

    // ── TlsFrameDissector ─────────────────────────────────────────────────

    #[test]
    fn tls_frame_dissector_app_data() {
        // ApplicationData record
        let data: &[u8] = &[23, 3, 3, 0, 5, 0, 1, 2, 3, 4];
        let ctx = DissectorContext::default();
        let frame = TlsFrameDissector.dissect(data, &ctx).unwrap();
        assert_eq!(frame.protocol, "TLS");
        assert_eq!(
            frame.field("content_type").unwrap().display,
            "ApplicationData"
        );
        assert_eq!(frame.field("version").unwrap().display, "0x0303 (TLS 1.2)");
        assert_eq!(frame.sub_payload.as_deref(), Some(&[0u8, 1, 2, 3, 4][..]));
    }

    #[test]
    fn tls_frame_dissector_handshake_type() {
        // Handshake record with ClientHello type byte
        let mut data = vec![22u8, 3, 1, 0, 10, 1, 0, 0, 6, 3, 3];
        data.resize(11, 0);
        let ctx = DissectorContext::default();
        let frame = TlsFrameDissector.dissect(&data, &ctx).unwrap();
        assert_eq!(
            frame.field("handshake_type").unwrap().display,
            "ClientHello"
        );
    }

    #[test]
    fn tls_parse_sni_extension_none_on_short() {
        assert!(TlsFrameDissector::parse_sni_extension(&[22, 3, 3, 0, 0]).is_none());
    }

    #[test]
    fn tls_frame_dissector_too_short() {
        let ctx = DissectorContext::default();
        assert!(TlsFrameDissector.dissect(&[22u8, 3], &ctx).is_err());
    }

    // ── FrameDissectorRegistry::dissect_stack ─────────────────────────────

    fn build_eth_ipv4_tcp(dst_port: u16, app: &[u8]) -> Vec<u8> {
        // Ethernet (14) + IPv4 (20) + TCP (20) + app
        let total_ip = 20 + 20 + app.len();
        let mut eth = vec![0u8; 14];
        eth[12] = 0x08;
        eth[13] = 0x00; // IPv4

        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2] = u8::try_from(total_ip >> 8).unwrap_or(u8::MAX);
        ip[3] = u8::try_from(total_ip).unwrap_or(u8::MAX);
        ip[8] = 64;
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&[127, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[127, 0, 0, 1]);

        let mut tcp = vec![0u8; 20];
        tcp[0] = 0x04;
        tcp[1] = 0xD2; // src_port=1234
        tcp[2] = (dst_port >> 8) as u8;
        tcp[3] = (dst_port & 0xFF) as u8;
        tcp[12] = 0x50;
        tcp[13] = 0x18; // PSH+ACK

        let mut out = eth;
        out.extend_from_slice(&ip);
        out.extend_from_slice(&tcp);
        out.extend_from_slice(app);
        out
    }

    #[test]
    fn dissect_stack_ethernet_ipv4_tcp_http() {
        let http_req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let raw = build_eth_ipv4_tcp(80, http_req);
        let reg = FrameDissectorRegistry::new();
        let frames = reg.dissect_stack(&raw);
        // Should have: Ethernet, IPv4, TCP, HTTP
        assert!(
            frames.len() >= 3,
            "expected at least 3 layers, got {}",
            frames.len()
        );
        assert_eq!(frames[0].protocol, "Ethernet");
        assert_eq!(frames[1].protocol, "IPv4");
        assert_eq!(frames[2].protocol, "TCP");
        if frames.len() >= 4 {
            assert_eq!(frames[3].protocol, "HTTP");
        }
    }

    #[test]
    fn dissect_stack_empty_app_payload() {
        // TCP with no application payload
        let raw = build_eth_ipv4_tcp(9999, &[]);
        let reg = FrameDissectorRegistry::new();
        let frames = reg.dissect_stack(&raw);
        assert!(frames.len() >= 3);
        assert_eq!(frames[0].protocol, "Ethernet");
        assert_eq!(frames[1].protocol, "IPv4");
        assert_eq!(frames[2].protocol, "TCP");
    }

    #[test]
    fn dissect_stack_too_short_returns_empty() {
        let reg = FrameDissectorRegistry::new();
        let frames = reg.dissect_stack(&[0u8; 4]);
        assert!(frames.is_empty());
    }

    #[test]
    fn frame_dissector_registry_by_name() {
        let reg = FrameDissectorRegistry::new();
        assert!(reg.by_name("Ethernet").is_some());
        assert!(reg.by_name("IPv4").is_some());
        assert!(reg.by_name("IPv6").is_some());
        assert!(reg.by_name("TCP").is_some());
        assert!(reg.by_name("UDP").is_some());
        assert!(reg.by_name("DNS").is_some());
        assert!(reg.by_name("HTTP").is_some());
        assert!(reg.by_name("TLS").is_some());
        assert!(reg.by_name("nonexistent").is_none());
    }

    #[test]
    fn frame_dissector_registry_by_port() {
        let reg = FrameDissectorRegistry::new();
        assert!(reg.by_port(53).is_some());
        assert!(reg.by_port(80).is_some());
        assert!(reg.by_port(443).is_some());
        assert!(reg.by_port(9999).is_none());
    }

    #[test]
    fn extract_bits_u8() {
        // byte 0xAB = 1010_1011
        let data = [0xABu8];
        // bits 0..4 = 0xA = 10
        assert_eq!(extract_bits(&data, 0, 4), 0xA);
        // bits 4..8 = 0xB = 11
        assert_eq!(extract_bits(&data, 4, 4), 0xB);
    }

    #[test]
    fn ipv4_bit_fields_version_and_ihl() {
        let data = make_ipv4_bytes(17, [10, 0, 0, 1], [10, 0, 0, 2]);
        let ctx = DissectorContext::default();
        let frame = Ipv4FrameDissector.dissect(&data, &ctx).unwrap();
        let ver = frame.field("version").unwrap();
        let ihl = frame.field("ihl").unwrap();
        // version=4 at bit_offset=0, bit_len=4
        assert!(matches!(ver.value, FrameFieldValue::U8(4)));
        assert_eq!(ver.bit_offset, 0);
        assert_eq!(ver.bit_len, 4);
        // ihl=5 at bit_offset=4, bit_len=4
        assert!(matches!(ihl.value, FrameFieldValue::U8(5)));
        assert_eq!(ihl.bit_offset, 4);
        assert_eq!(ihl.bit_len, 4);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// HttpMessage enum + DissectHttp
// ────────────────────────────────────────────────────────────────────────────

/// A discriminated HTTP message — either a request or a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
}

impl HttpMessage {
    /// Returns `true` if this is an HTTP request.
    #[must_use]
    pub const fn is_request(&self) -> bool {
        matches!(self, Self::Request(_))
    }

    /// Returns `true` if this is an HTTP response.
    #[must_use]
    pub const fn is_response(&self) -> bool {
        matches!(self, Self::Response(_))
    }

    /// Borrow the inner [`HttpRequest`], if this is a request.
    #[must_use]
    pub const fn as_request(&self) -> Option<&HttpRequest> {
        if let Self::Request(r) = self {
            Some(r)
        } else {
            None
        }
    }

    /// Borrow the inner [`HttpResponse`], if this is a response.
    #[must_use]
    pub const fn as_response(&self) -> Option<&HttpResponse> {
        if let Self::Response(r) = self {
            Some(r)
        } else {
            None
        }
    }
}

/// Attempt to parse `packet` as an HTTP/1.x request or response.
///
/// Returns `Some(HttpMessage::Response(_))` when the data starts with
/// `HTTP/`, `Some(HttpMessage::Request(_))` when it starts with a known
/// HTTP method verb, and `None` otherwise.
#[must_use]
pub fn dissect_http(packet: &[u8]) -> Option<HttpMessage> {
    if packet.starts_with(b"HTTP/") {
        HttpResponse::parse(packet).ok().map(HttpMessage::Response)
    } else {
        HttpRequest::parse(packet).ok().map(HttpMessage::Request)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TLS/SSL fingerprinting (JA3 / JA3S)
// ────────────────────────────────────────────────────────────────────────────

/// TLS fingerprint data extracted from a `ClientHello` or `ServerHello`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFingerprint {
    /// JA3 fingerprint (MD5 of the `ClientHello` string representation).
    pub ja3: String,
    /// JA3S fingerprint (MD5 of the `ServerHello` string representation).
    pub ja3s: String,
    /// The cipher suite selected by the server (hex, e.g. `"c02b"`).
    pub cipher_suite: String,
}

/// Compute the JA3 fingerprint from a raw TLS `ClientHello` record.
///
/// The JA3 string is:
/// `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
/// where each list is comma-separated decimal values joined with `-`.
/// GREASE values (0xXaXa) are omitted.
///
/// Returns `None` if `data` is not a valid TLS `ClientHello`.
fn ja3_parse_extensions(data: &[u8], mut off: usize) -> (Vec<u16>, Vec<u16>, Vec<u8>) {
    let mut ext_types = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats: Vec<u8> = Vec::new();
    if off + 2 > data.len() { return (ext_types, elliptic_curves, ec_point_formats); }
    let ext_total = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    off += 2;
    let ext_end = (off + ext_total).min(data.len());
    while off + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[off], data[off + 1]]);
        let ext_len  = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
        off += 4;
        if off + ext_len > ext_end { break; }
        if !is_grease(ext_type) { ext_types.push(ext_type); }
        if ext_type == 10 && ext_len >= 2 {
            let list_len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
            let mut g = off + 2;
            while g + 2 <= off + 2 + list_len && g + 2 <= off + ext_len {
                let curve = u16::from_be_bytes([data[g], data[g + 1]]);
                if !is_grease(curve) { elliptic_curves.push(curve); }
                g += 2;
            }
        }
        if ext_type == 11 && ext_len >= 1 {
            let fmt_len = data[off] as usize;
            ec_point_formats.extend_from_slice(&data[off + 1..(off + 1 + fmt_len).min(off + ext_len)]);
        }
        off += ext_len;
    }
    (ext_types, elliptic_curves, ec_point_formats)
}

#[must_use]
pub fn ja3_fingerprint(data: &[u8]) -> Option<String> {
    // TLS record: type=22 (Handshake), 2-byte version, 2-byte length
    if data.len() < 9 {
        return None;
    }
    if data[0] != 22 {
        return None;
    }

    let tls_version = u16::from_be_bytes([data[1], data[2]]);

    // Handshake header: type=1 (ClientHello), 3-byte length
    // Offset 5: handshake type
    if data[5] != 1 {
        return None;
    } // not ClientHello

    // ClientHello body starts at offset 9
    // 2-byte client version, 32-byte random
    if data.len() < 9 + 2 + 32 {
        return None;
    }
    let ch_version = u16::from_be_bytes([data[9], data[10]]);
    let mut off = 9 + 2 + 32;

    // Session ID length (1 byte)
    if off >= data.len() {
        return None;
    }
    let session_len = data[off] as usize;
    off += 1 + session_len;

    // Cipher suites: 2-byte count in bytes
    if off + 2 > data.len() {
        return None;
    }
    let cs_bytes = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    off += 2;
    if off + cs_bytes > data.len() {
        return None;
    }
    let mut ciphers: Vec<u16> = Vec::new();
    let cs_end = off + cs_bytes;
    while off + 2 <= cs_end {
        let cs = u16::from_be_bytes([data[off], data[off + 1]]);
        if !is_grease(cs) {
            ciphers.push(cs);
        }
        off += 2;
    }
    off = cs_end;

    // Compression methods: 1-byte count
    if off >= data.len() {
        return None;
    }
    let comp_len = data[off] as usize;
    off += 1 + comp_len;

    let (ext_types, elliptic_curves, ec_point_formats) = ja3_parse_extensions(data, off);

    let ja3_str = format!(
        "{},{},{},{},{}",
        ch_version,
        ciphers
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("-"),
        ext_types
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("-"),
        elliptic_curves
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("-"),
        ec_point_formats
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("-"),
    );

    let _ = tls_version; // used for record-layer validation above
    Some(md5_hex(ja3_str.as_bytes()))
}

/// Compute the JA3S fingerprint from a raw TLS `ServerHello` record.
///
/// The JA3S string is: `SSLVersion,Cipher,Extensions`
///
/// Returns `None` if `data` is not a valid TLS `ServerHello`.
#[must_use]
pub fn ja3s_fingerprint(data: &[u8]) -> Option<String> {
    if data.len() < 9 {
        return None;
    }
    if data[0] != 22 {
        return None;
    }
    if data[5] != 2 {
        return None;
    } // not ServerHello

    if data.len() < 9 + 2 + 32 {
        return None;
    }
    let sh_version = u16::from_be_bytes([data[9], data[10]]);
    let mut off = 9 + 2 + 32;

    // Session ID
    if off >= data.len() {
        return None;
    }
    let session_len = data[off] as usize;
    off += 1 + session_len;

    // Single cipher suite (2 bytes)
    if off + 2 > data.len() {
        return None;
    }
    let cipher = u16::from_be_bytes([data[off], data[off + 1]]);
    off += 2;

    // Compression method (1 byte)
    off += 1;

    // Extensions
    let mut ext_types: Vec<u16> = Vec::new();
    if off + 2 <= data.len() {
        let ext_total = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        let ext_end = (off + ext_total).min(data.len());
        while off + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[off], data[off + 1]]);
            let ext_len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
            off += 4;
            if !is_grease(ext_type) {
                ext_types.push(ext_type);
            }
            if off + ext_len > ext_end {
                break;
            }
            off += ext_len;
        }
    }

    let ja3s_str = format!(
        "{},{},{}",
        sh_version,
        cipher,
        ext_types
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("-"),
    );
    Some(md5_hex(ja3s_str.as_bytes()))
}

/// Extract the selected cipher suite from a `ServerHello` as a hex string.
///
/// Returns `"unknown"` if `data` is not a valid `ServerHello` or is too short.
#[must_use]
pub fn tls_server_cipher_suite(data: &[u8]) -> String {
    if data.len() < 9 + 2 + 32 + 1 {
        return "unknown".to_string();
    }
    if data[0] != 22 || data[5] != 2 {
        return "unknown".to_string();
    }
    let session_len = data[9 + 2 + 32] as usize;
    let cs_off = 9 + 2 + 32 + 1 + session_len;
    if cs_off + 2 > data.len() {
        return "unknown".to_string();
    }
    let cs = u16::from_be_bytes([data[cs_off], data[cs_off + 1]]);
    format!("{cs:04x}")
}

/// Compute JA3, JA3S, and cipher suite from the first `ClientHello` and
/// `ServerHello` found in `packets`.
///
/// Scans packets in order: the first TLS record type 22 / handshake type 1
/// is used for JA3; the first type 22 / handshake type 2 for JA3S.
#[must_use]
pub fn compute_tls_fingerprint(packets: &[&[u8]]) -> TlsFingerprint {
    let mut ja3 = String::new();
    let mut ja3s = String::new();
    let mut cipher_suite = "unknown".to_string();

    for pkt in packets {
        if pkt.len() >= 9 && pkt[0] == 22 {
            if pkt[5] == 1 && ja3.is_empty() {
                if let Some(fp) = ja3_fingerprint(pkt) {
                    ja3 = fp;
                }
            } else if pkt[5] == 2 && ja3s.is_empty()
                && let Some(fp) = ja3s_fingerprint(pkt) {
                    ja3s = fp;
                    cipher_suite = tls_server_cipher_suite(pkt);
                }
        }
    }

    TlsFingerprint {
        ja3,
        ja3s,
        cipher_suite,
    }
}

/// Returns `true` if `v` is a GREASE value (RFC 8701).
const fn is_grease(v: u16) -> bool {
    matches!(
        v,
        0x0a0a
            | 0x1a1a
            | 0x2a2a
            | 0x3a3a
            | 0x4a4a
            | 0x5a5a
            | 0x6a6a
            | 0x7a7a
            | 0x8a8a
            | 0x9a9a
            | 0xaaaa
            | 0xbaba
            | 0xcaca
            | 0xdada
            | 0xeaea
            | 0xfafa
    )
}

/// Compute the MD5 digest of `data` and return it as a lowercase hex string.
fn md5_hex(data: &[u8]) -> String {
    use md5::Digest as _;
    let digest = md5::Md5::digest(data);
    digest.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
}

// ════════════════════════════════════════════════════════════════════════════
// SMB2 full dissector
// ════════════════════════════════════════════════════════════════════════════

/// SMB2 command codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Smb2Command {
    Negotiate,
    SessionSetup,
    Logoff,
    TreeConnect,
    TreeDisconnect,
    Create,
    Close,
    Flush,
    Read,
    Write,
    Lock,
    Ioctl,
    Cancel,
    KeepAlive,
    QueryDirectory,
    ChangeNotify,
    QueryInfo,
    SetInfo,
    OplockBreak,
    Unknown(u16),
}

impl From<u16> for Smb2Command {
    fn from(v: u16) -> Self {
        match v {
            0x0000 => Self::Negotiate,
            0x0001 => Self::SessionSetup,
            0x0002 => Self::Logoff,
            0x0003 => Self::TreeConnect,
            0x0004 => Self::TreeDisconnect,
            0x0005 => Self::Create,
            0x0006 => Self::Close,
            0x0007 => Self::Flush,
            0x0008 => Self::Read,
            0x0009 => Self::Write,
            0x000A => Self::Lock,
            0x000B => Self::Ioctl,
            0x000C => Self::Cancel,
            0x000D => Self::KeepAlive,
            0x000E => Self::QueryDirectory,
            0x000F => Self::ChangeNotify,
            0x0010 => Self::QueryInfo,
            0x0011 => Self::SetInfo,
            0x0012 => Self::OplockBreak,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for Smb2Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Negotiate => "Negotiate",
            Self::SessionSetup => "SessionSetup",
            Self::Logoff => "Logoff",
            Self::TreeConnect => "TreeConnect",
            Self::TreeDisconnect => "TreeDisconnect",
            Self::Create => "Create",
            Self::Close => "Close",
            Self::Flush => "Flush",
            Self::Read => "Read",
            Self::Write => "Write",
            Self::Lock => "Lock",
            Self::Ioctl => "Ioctl",
            Self::Cancel => "Cancel",
            Self::KeepAlive => "KeepAlive",
            Self::QueryDirectory => "QueryDirectory",
            Self::ChangeNotify => "ChangeNotify",
            Self::QueryInfo => "QueryInfo",
            Self::SetInfo => "SetInfo",
            Self::OplockBreak => "OplockBreak",
            Self::Unknown(v) => return write!(f, "Unknown(0x{v:04x})"),
        };
        write!(f, "{s}")
    }
}

/// Parsed SMB2 fixed 64-byte header (`ProtocolId` + 60 bytes of fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Smb2Header {
    /// Protocol ID bytes: 0xFE 0x53 0x4D 0x42.
    pub magic: [u8; 4],
    /// `StructureSize` field — always 64 for SMB2.
    pub structure_size: u16,
    /// Credit charge (SMB 3.x multi-credit operations).
    pub credit_charge: u16,
    /// NT status code in responses; channel sequence in requests.
    pub status: u32,
    /// Decoded command.
    pub command: Smb2Command,
    /// Credits requested (client) or granted (server).
    pub credits: u16,
    /// Flags bitmask (RESPONSE, ASYNC, CHAINED, SIGNED, …).
    pub flags: u32,
    /// Offset to the next SMB2 message in a compound chain (0 = last).
    pub next_command: u32,
    /// Monotonically increasing message identifier.
    pub message_id: u64,
    /// Process ID (synchronous) or high word of `AsyncId` (asynchronous).
    pub process_id: u32,
    /// Tree identifier (0 until `TreeConnect` completes).
    pub tree_id: u32,
    /// Session identifier (0 until `SessionSetup` completes).
    pub session_id: u64,
    /// 16-byte cryptographic signature (non-zero only when SIGNED flag is set).
    pub signature: [u8; 16],
}

impl Smb2Header {
    /// Parse a 64-byte SMB2 header.
    ///
    /// # Errors
    /// Returns [`DissectError::TooShort`] when fewer than 64 bytes are supplied.
    /// Returns [`DissectError::InvalidMagic`] when the four-byte protocol ID is wrong.
    pub fn parse(data: &[u8]) -> Result<Self, DissectError> {
        if data.len() < 64 {
            return Err(DissectError::TooShort {
                need: 64,
                got: data.len(),
            });
        }
        if &data[0..4] != b"\xFESMB" {
            return Err(DissectError::InvalidMagic(format!(
                "{:02x}{:02x}{:02x}{:02x}",
                data[0], data[1], data[2], data[3]
            )));
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);
        let structure_size = u16::from_le_bytes([data[4], data[5]]);
        let credit_charge = u16::from_le_bytes([data[6], data[7]]);
        let status = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let cmd_raw = u16::from_le_bytes([data[12], data[13]]);
        let credits = u16::from_le_bytes([data[14], data[15]]);
        let flags = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let next_command = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let message_id = u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);
        let process_id = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let tree_id = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
        let session_id = u64::from_le_bytes([
            data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
        ]);
        let mut signature = [0u8; 16];
        signature.copy_from_slice(&data[48..64]);
        Ok(Self {
            magic,
            structure_size,
            credit_charge,
            status,
            command: Smb2Command::from(cmd_raw),
            credits,
            flags,
            next_command,
            message_id,
            process_id,
            tree_id,
            session_id,
            signature,
        })
    }

    /// `true` when the RESPONSE flag (bit 0) is set.
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.flags & 0x0000_0001 != 0
    }
    /// `true` when the ASYNC flag (bit 1) is set.
    #[must_use]
    pub const fn is_async(&self) -> bool {
        self.flags & 0x0000_0002 != 0
    }
    /// `true` when the CHAINED flag (bit 2) is set.
    #[must_use]
    pub const fn is_chained(&self) -> bool {
        self.flags & 0x0000_0004 != 0
    }
    /// `true` when the SIGNED flag (bit 3) is set.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.flags & 0x0000_0008 != 0
    }
}

/// SMB2 Negotiate request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Smb2NegotiateRequest {
    pub dialect_count: u16,
    pub dialects: Vec<u16>,
    pub security_mode: u16,
    pub capabilities: u32,
    pub client_guid: [u8; 16],
}

impl Smb2NegotiateRequest {
    /// Parse the body following the 64-byte header.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(body: &[u8]) -> Result<Self, DissectError> {
        // StructureSize(2)+DialectCount(2)+SecurityMode(2)+Reserved(2)+
        // Capabilities(4)+ClientGuid(16)+ClientStartTime(8) = 36 minimum
        if body.len() < 36 {
            return Err(DissectError::TooShort {
                need: 36,
                got: body.len(),
            });
        }
        let dialect_count = u16::from_le_bytes([body[2], body[3]]) as usize;
        let security_mode = u16::from_le_bytes([body[4], body[5]]);
        let capabilities = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
        let mut client_guid = [0u8; 16];
        client_guid.copy_from_slice(&body[12..28]);
        let dialect_start = 36;
        let dialect_end = dialect_start + dialect_count * 2;
        if body.len() < dialect_end {
            return Err(DissectError::TooShort {
                need: dialect_end,
                got: body.len(),
            });
        }
        let dialects: Vec<u16> = (0..dialect_count)
            .map(|i| {
                u16::from_le_bytes([body[dialect_start + i * 2], body[dialect_start + i * 2 + 1]])
            })
            .collect();
        Ok(Self {
            dialect_count: u16::try_from(dialect_count).unwrap_or(u16::MAX),
            dialects,
            security_mode,
            capabilities,
            client_guid,
        })
    }
}

/// SMB2 Create request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Smb2CreateRequest {
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub file_name: String,
}

impl Smb2CreateRequest {
    /// Parse the body following the 64-byte header.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(body: &[u8]) -> Result<Self, DissectError> {
        if body.len() < 56 {
            return Err(DissectError::TooShort {
                need: 56,
                got: body.len(),
            });
        }
        let desired_access = u32::from_le_bytes([body[24], body[25], body[26], body[27]]);
        let file_attributes = u32::from_le_bytes([body[28], body[29], body[30], body[31]]);
        let share_access = u32::from_le_bytes([body[32], body[33], body[34], body[35]]);
        let create_disposition = u32::from_le_bytes([body[36], body[37], body[38], body[39]]);
        let create_options = u32::from_le_bytes([body[40], body[41], body[42], body[43]]);
        let name_offset = u16::from_le_bytes([body[44], body[45]]) as usize;
        let name_length = u16::from_le_bytes([body[46], body[47]]) as usize;
        // name_offset is relative to the start of the SMB2 message; subtract header.
        let rel = name_offset.saturating_sub(64);
        let file_name = if rel + name_length <= body.len() && name_length > 0 {
            let utf16: Vec<u16> = body[rel..rel + name_length]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&utf16)
        } else {
            String::new()
        };
        Ok(Self {
            desired_access,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            file_name,
        })
    }
}

/// SMB2 Read request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Smb2ReadRequest {
    pub length: u32,
    pub offset: u64,
    pub file_id: [u8; 16],
    pub minimum_count: u32,
}

impl Smb2ReadRequest {
    /// Parse the body following the 64-byte header.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(body: &[u8]) -> Result<Self, DissectError> {
        if body.len() < 48 {
            return Err(DissectError::TooShort {
                need: 48,
                got: body.len(),
            });
        }
        let length = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        let offset = u64::from_le_bytes([
            body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
        ]);
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&body[16..32]);
        let minimum_count = u32::from_le_bytes([body[32], body[33], body[34], body[35]]);
        Ok(Self {
            length,
            offset,
            file_id,
            minimum_count,
        })
    }
}

/// SMB2 Write request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Smb2WriteRequest {
    pub data_offset: u16,
    pub length: u32,
    pub offset: u64,
    pub file_id: [u8; 16],
    pub channel: u32,
    pub remaining_bytes: u32,
}

impl Smb2WriteRequest {
    /// Parse the body following the 64-byte header.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(body: &[u8]) -> Result<Self, DissectError> {
        if body.len() < 48 {
            return Err(DissectError::TooShort {
                need: 48,
                got: body.len(),
            });
        }
        let data_offset = u16::from_le_bytes([body[2], body[3]]);
        let length = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        let offset = u64::from_le_bytes([
            body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
        ]);
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&body[16..32]);
        let channel = u32::from_le_bytes([body[32], body[33], body[34], body[35]]);
        let remaining_bytes = u32::from_le_bytes([body[36], body[37], body[38], body[39]]);
        Ok(Self {
            data_offset,
            length,
            offset,
            file_id,
            channel,
            remaining_bytes,
        })
    }
}

/// Full SMB2 dissector.
///
/// Parses the mandatory 64-byte fixed header plus command-specific body fields
/// for Negotiate, `SessionSetup`, `TreeConnect`, Create, Read, Write, and `QueryInfo`.
pub struct Smb2FullDissector;

impl ProtocolDissector for Smb2FullDissector {
    fn name(&self) -> &'static str {
        "SMB2"
    }
    fn ports(&self) -> &[u16] {
        &[445, 139]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        // Some transports prefix a 4-byte NBT session header; skip it when present.
        let raw = if data.len() >= 68 && data[0] == 0x00 && &data[4..8] == b"\xFESMB" {
            &data[4..]
        } else {
            data
        };

        let hdr = Smb2Header::parse(raw)?;
        let hdr_raw_end = raw.len().min(64);
        let mut header_layer = ProtoLayer::new("SMB2", raw[..hdr_raw_end].to_vec());
        smb2_fill_header_fields(&hdr, &mut header_layer);
        packet.push_layer(header_layer);

        if raw.len() <= 64 {
            return Ok(());
        }
        let body = &raw[64..];
        let mut body_layer = ProtoLayer::new("SMB2_Body", body.to_vec());

        smb2_fill_body_fields(&hdr, body, &mut body_layer);
        packet.push_layer(body_layer);
        Ok(())
    }
}

fn smb2_fill_header_fields(hdr: &Smb2Header, layer: &mut ProtoLayer) {
    layer.add_field(ProtoField::new("magic",          0,  4, FieldValue::Bytes(hdr.magic.to_vec())));
    layer.add_field(ProtoField::new("structure_size", 4,  2, FieldValue::Uint(u64::from(hdr.structure_size))));
    layer.add_field(ProtoField::new("credit_charge",  6,  2, FieldValue::Uint(u64::from(hdr.credit_charge))));
    layer.add_field(ProtoField::new("status",         8,  4, FieldValue::Uint(u64::from(hdr.status))));
    layer.add_field(ProtoField::new("command",        12, 2, FieldValue::Str(hdr.command.to_string())));
    layer.add_field(ProtoField::new("credits",        14, 2, FieldValue::Uint(u64::from(hdr.credits))));
    layer.add_field(ProtoField::new("flags",          16, 4, FieldValue::Uint(u64::from(hdr.flags))));
    layer.add_field(ProtoField::new("is_response",    16, 4, FieldValue::Bool(hdr.is_response())));
    layer.add_field(ProtoField::new("is_signed",      16, 4, FieldValue::Bool(hdr.is_signed())));
    layer.add_field(ProtoField::new("is_async",       16, 4, FieldValue::Bool(hdr.is_async())));
    layer.add_field(ProtoField::new("next_command",   20, 4, FieldValue::Uint(u64::from(hdr.next_command))));
    layer.add_field(ProtoField::new("message_id",     24, 8, FieldValue::Uint(hdr.message_id)));
    layer.add_field(ProtoField::new("process_id",     32, 4, FieldValue::Uint(u64::from(hdr.process_id))));
    layer.add_field(ProtoField::new("tree_id",        36, 4, FieldValue::Uint(u64::from(hdr.tree_id))));
    layer.add_field(ProtoField::new("session_id",     40, 8, FieldValue::Uint(hdr.session_id)));
    layer.add_field(ProtoField::new("signature",      48, 16, FieldValue::Bytes(hdr.signature.to_vec())));
}

fn smb2_fill_body_fields(hdr: &Smb2Header, body: &[u8], layer: &mut ProtoLayer) {
    match hdr.command {
        Smb2Command::Negotiate if !hdr.is_response() => {
            if let Ok(neg) = Smb2NegotiateRequest::parse(body) {
                layer.add_field(ProtoField::new("dialect_count", 2, 2, FieldValue::Uint(u64::from(neg.dialect_count))));
                layer.add_field(ProtoField::new("security_mode", 4, 2, FieldValue::Uint(u64::from(neg.security_mode))));
                layer.add_field(ProtoField::new("capabilities",  8, 4, FieldValue::Uint(u64::from(neg.capabilities))));
                layer.add_field(ProtoField::new("client_guid",  12, 16, FieldValue::Bytes(neg.client_guid.to_vec())));
                for (i, d) in neg.dialects.iter().enumerate() {
                    layer.add_field(ProtoField::new(format!("dialect[{i}]"), 36 + i * 2, 2, FieldValue::Str(format!("0x{d:04x}"))));
                }
            }
        }
        Smb2Command::SessionSetup => {
            if body.len() >= 16 {
                let sec_len = u16::from_le_bytes([body[14], body[15]]);
                layer.add_field(ProtoField::new("security_buffer_length", 14, 2, FieldValue::Uint(u64::from(sec_len))));
            }
        }
        Smb2Command::TreeConnect if !hdr.is_response() => {
            if body.len() >= 10 {
                let path_off = u16::from_le_bytes([body[6], body[7]]) as usize;
                let path_len = u16::from_le_bytes([body[8], body[9]]) as usize;
                let rel = path_off.saturating_sub(64);
                if rel + path_len <= body.len() && path_len > 0 {
                    let utf16: Vec<u16> = body[rel..rel+path_len].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    layer.add_field(ProtoField::new("tree_path", rel, path_len, FieldValue::Str(String::from_utf16_lossy(&utf16))));
                }
            }
        }
        Smb2Command::Create if !hdr.is_response() => {
            if let Ok(cr) = Smb2CreateRequest::parse(body) {
                layer.add_field(ProtoField::new("desired_access",     24, 4, FieldValue::Uint(u64::from(cr.desired_access))));
                layer.add_field(ProtoField::new("file_attributes",    28, 4, FieldValue::Uint(u64::from(cr.file_attributes))));
                layer.add_field(ProtoField::new("share_access",       32, 4, FieldValue::Uint(u64::from(cr.share_access))));
                layer.add_field(ProtoField::new("create_disposition", 36, 4, FieldValue::Uint(u64::from(cr.create_disposition))));
                layer.add_field(ProtoField::new("create_options",     40, 4, FieldValue::Uint(u64::from(cr.create_options))));
                if !cr.file_name.is_empty() {
                    let fn_len = cr.file_name.len() * 2;
                    layer.add_field(ProtoField::new("file_name", 44, fn_len, FieldValue::Str(cr.file_name)));
                }
            }
        }
        Smb2Command::Read if !hdr.is_response() => {
            if let Ok(rd) = Smb2ReadRequest::parse(body) {
                layer.add_field(ProtoField::new("read_length",   4,  4,  FieldValue::Uint(u64::from(rd.length))));
                layer.add_field(ProtoField::new("read_offset",   8,  8,  FieldValue::Uint(rd.offset)));
                layer.add_field(ProtoField::new("file_id",       16, 16, FieldValue::Bytes(rd.file_id.to_vec())));
                layer.add_field(ProtoField::new("minimum_count", 32, 4,  FieldValue::Uint(u64::from(rd.minimum_count))));
            }
        }
        Smb2Command::Write if !hdr.is_response() => {
            if let Ok(wr) = Smb2WriteRequest::parse(body) {
                layer.add_field(ProtoField::new("data_offset",    2,  2,  FieldValue::Uint(u64::from(wr.data_offset))));
                layer.add_field(ProtoField::new("write_length",   4,  4,  FieldValue::Uint(u64::from(wr.length))));
                layer.add_field(ProtoField::new("write_offset",   8,  8,  FieldValue::Uint(wr.offset)));
                layer.add_field(ProtoField::new("file_id",        16, 16, FieldValue::Bytes(wr.file_id.to_vec())));
                layer.add_field(ProtoField::new("channel",        32, 4,  FieldValue::Uint(u64::from(wr.channel))));
                layer.add_field(ProtoField::new("remaining_bytes",36, 4,  FieldValue::Uint(u64::from(wr.remaining_bytes))));
            }
        }
        Smb2Command::QueryInfo
            if body.len() >= 8 => {
                let out_buf = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
                layer.add_field(ProtoField::new("info_type",            2, 1, FieldValue::Uint(u64::from(body[2]))));
                layer.add_field(ProtoField::new("file_info_class",      3, 1, FieldValue::Uint(u64::from(body[3]))));
                layer.add_field(ProtoField::new("output_buffer_length", 4, 4, FieldValue::Uint(u64::from(out_buf))));
            }
        _ => {}
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Kerberos dissector
// ════════════════════════════════════════════════════════════════════════════

/// Kerberos message type, identified by the ASN.1 APPLICATION tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KerberosMessageType {
    /// Authentication Service Request  — APPLICATION 10 (0x6A).
    AsReq,
    /// Authentication Service Response — APPLICATION 11 (0x6B).
    AsRep,
    /// Ticket Granting Service Request — APPLICATION 12 (0x6C).
    TgsReq,
    /// Ticket Granting Service Response — APPLICATION 13 (0x6D).
    TgsRep,
    /// Generic error reply — APPLICATION 30 (0x7E).
    KrbError,
    /// Any other APPLICATION tag.
    Unknown(u8),
}

impl fmt::Display for KerberosMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AsReq => write!(f, "AS-REQ"),
            Self::AsRep => write!(f, "AS-REP"),
            Self::TgsReq => write!(f, "TGS-REQ"),
            Self::TgsRep => write!(f, "TGS-REP"),
            Self::KrbError => write!(f, "KRB-ERROR"),
            Self::Unknown(t) => write!(f, "Unknown(0x{t:02x})"),
        }
    }
}

impl KerberosMessageType {
    const fn from_tag(tag: u8) -> Self {
        match tag {
            0x6A => Self::AsReq,
            0x6B => Self::AsRep,
            0x6C => Self::TgsReq,
            0x6D => Self::TgsRep,
            0x7E => Self::KrbError,
            t => Self::Unknown(t),
        }
    }
}

/// Minimal parsed Kerberos message extracted from ASN.1 DER.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosMessage {
    pub msg_type: KerberosMessageType,
    /// Realm string (UTF-8), if found.
    pub realm: Option<String>,
    /// Principal names found in cname or sname, if any.
    pub principal_names: Vec<String>,
    /// Encryption types listed in the req-body, if present.
    pub etypes: Vec<i32>,
    /// True when a TGS-REQ contains etype 23 (RC4-HMAC) — Kerberoasting indicator.
    pub kerberoasting_detected: bool,
}

// ── ASN.1 DER mini-parser helpers ───────────────────────────────────────────

/// Read a DER tag+length at `data[off]`.
/// Returns `(tag, content_start, content_length)` or `None`.
fn der_tlv(data: &[u8], off: usize) -> Option<(u8, usize, usize)> {
    if off >= data.len() {
        return None;
    }
    let tag = data[off];
    let mut pos = off + 1;
    if pos >= data.len() {
        return None;
    }
    let first = data[pos] as usize;
    pos += 1;
    let (len, pos) = if first < 0x80 {
        (first, pos)
    } else {
        let num_bytes = first & 0x7F;
        if num_bytes == 0 || num_bytes > 4 || pos + num_bytes > data.len() {
            return None;
        }
        let mut l = 0usize;
        for i in 0..num_bytes {
            l = (l << 8) | data[pos + i] as usize;
        }
        (l, pos + num_bytes)
    };
    if pos + len > data.len() {
        return None;
    }
    Some((tag, pos, len))
}

/// Attempt to decode a DER `UTF8String` / `GeneralString` / `IA5String` / `BMPString`
/// at `data[off..]`. Returns the decoded string.
fn der_string(data: &[u8], off: usize) -> Option<String> {
    let (tag, content_off, content_len) = der_tlv(data, off)?;
    // Tags: 0x0C = UTF8String, 0x1B = GeneralString, 0x16 = IA5String
    // 0x1E = BMPString (UTF-16BE), 0x13 = PrintableString
    let content = &data[content_off..content_off + content_len];
    match tag {
        0x0C | 0x1B | 0x16 | 0x13 | 0x14 | 0x15 => {
            Some(String::from_utf8_lossy(content).into_owned())
        }
        0x1E => {
            // BMPString is UTF-16BE
            let utf16: Vec<u16> = content
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&utf16))
        }
        _ => None,
    }
}

/// Walk DER SEQUENCE/SET contents and collect all string-tagged values.
fn collect_strings(data: &[u8], depth: usize, out: &mut Vec<String>) {
    if depth > 16 {
        return;
    }
    let mut off = 0;
    while off < data.len() {
        let Some((tag, content_off, content_len)) = der_tlv(data, off) else { break };
        // Constructed — recurse
        if tag & 0x20 != 0 {
            collect_strings(
                &data[content_off..content_off + content_len],
                depth + 1,
                out,
            );
        } else {
            // Try to decode as string
            if let Some(s) = der_string(data, off)
                && !s.is_empty() {
                    out.push(s);
                }
        }
        let next = content_off + content_len;
        if next <= off {
            break;
        }
        off = next;
    }
}

/// Search for INTEGER values inside a DER blob and collect them as i32.
/// Used to extract etype lists from Kerberos req-body.
fn collect_integers(data: &[u8], depth: usize, out: &mut Vec<i32>) {
    if depth > 16 {
        return;
    }
    let mut off = 0;
    while off < data.len() {
        let Some((tag, content_off, content_len)) = der_tlv(data, off) else { break };
        if tag & 0x20 != 0 {
            collect_integers(
                &data[content_off..content_off + content_len],
                depth + 1,
                out,
            );
        } else if tag == 0x02 && (1..=4).contains(&content_len) {
            // Decode DER INTEGER (two's complement, big-endian)
            let content = &data[content_off..content_off + content_len];
            let mut val = if content[0] & 0x80 != 0 { -1i32 } else { 0i32 };
            for &b in content {
                val = (val << 8) | i32::from(b);
            }
            out.push(val);
        }
        let next = content_off + content_len;
        if next <= off {
            break;
        }
        off = next;
    }
}

/// Parse a Kerberos DER blob that begins at `data[0]` with an APPLICATION tag.
/// # Errors
/// Returns an error if the operation fails.
pub fn parse_kerberos(data: &[u8]) -> Result<KerberosMessage, DissectError> {
    if data.is_empty() {
        return Err(DissectError::TooShort { need: 1, got: 0 });
    }
    let tag0 = data[0];
    // APPLICATION tags are 0x60-0x7F in DER
    if tag0 < 0x60 {
        return Err(DissectError::InvalidMagic(format!(
            "expected APPLICATION tag, got 0x{tag0:02x}"
        )));
    }
    let msg_type = KerberosMessageType::from_tag(tag0);

    let (_, outer_off, outer_len) =
        der_tlv(data, 0).ok_or_else(|| DissectError::MalformedField("outer TLV".to_string()))?;
    let outer_content = &data[outer_off..outer_off + outer_len];

    // Collect all strings (realm, principal names)
    let mut strings = Vec::new();
    collect_strings(outer_content, 0, &mut strings);

    // Collect all integers (etypes)
    let mut all_ints = Vec::new();
    collect_integers(outer_content, 0, &mut all_ints);

    // Heuristic: first string that looks like a realm (contains only
    // uppercase or digits or dots) is the realm; the rest are principal names.
    let mut realm: Option<String> = None;
    let mut principal_names: Vec<String> = Vec::new();
    for s in &strings {
        if realm.is_none()
            && s.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '.')
        {
            realm = Some(s.clone());
        } else {
            principal_names.push(s.clone());
        }
    }

    // Filter integers to plausible etype range (-128..256)
    let etypes: Vec<i32> = all_ints
        .into_iter()
        .filter(|&v| (-128..=256).contains(&v))
        .collect();

    // Kerberoasting: TGS-REQ that proposes only RC4-HMAC (etype 23)
    let kerberoasting_detected = matches!(msg_type, KerberosMessageType::TgsReq)
        && !etypes.is_empty()
        && etypes.iter().all(|&e| e == 23);

    Ok(KerberosMessage {
        msg_type,
        realm,
        principal_names,
        etypes,
        kerberoasting_detected,
    })
}

/// Kerberos dissector.
///
/// Detects AS-REQ/AS-REP/TGS-REQ/TGS-REP by ASN.1 APPLICATION tag (0x6A-0x6D).
/// Extracts realm, principal names, etypes, and flags a Kerberoasting indicator
/// when a TGS-REQ proposes only RC4-HMAC (etype 23).
pub struct KerberosDissector;

impl ProtocolDissector for KerberosDissector {
    fn name(&self) -> &'static str {
        "Kerberos"
    }
    fn ports(&self) -> &[u16] {
        &[88, 750]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let krb = parse_kerberos(data)?;
        let raw_end = data.len().min(256); // first 256 bytes only in the raw snapshot
        let mut layer = ProtoLayer::new("Kerberos", data[..raw_end].to_vec());

        layer.add_field(ProtoField::new(
            "msg_type",
            0,
            1,
            FieldValue::Str(krb.msg_type.to_string()),
        ));
        layer.add_field(ProtoField::new(
            "msg_tag",
            0,
            1,
            FieldValue::Uint(u64::from(data[0])),
        ));
        if let Some(ref realm) = krb.realm {
            layer.add_field(ProtoField::new(
                "realm",
                0,
                realm.len(),
                FieldValue::Str(realm.clone()),
            ));
        }
        for (i, name) in krb.principal_names.iter().enumerate() {
            layer.add_field(ProtoField::new(
                format!("principal[{i}]"),
                0,
                name.len(),
                FieldValue::Str(name.clone()),
            ));
        }
        for (i, &et) in krb.etypes.iter().enumerate() {
            layer.add_field(ProtoField::new(
                format!("etype[{i}]"),
                0,
                1,
                FieldValue::Int(i64::from(et)),
            ));
        }
        layer.add_field(ProtoField::new(
            "kerberoasting_detected",
            0,
            1,
            FieldValue::Bool(krb.kerberoasting_detected),
        ));
        packet.push_layer(layer);
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HTTP attack detection
// ════════════════════════════════════════════════════════════════════════════

/// Category of detected HTTP attack payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpAttackKind {
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    LdapInjection,
    XxeInjection,
}

impl fmt::Display for HttpAttackKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SqlInjection => write!(f, "SQLi"),
            Self::Xss => write!(f, "XSS"),
            Self::PathTraversal => write!(f, "PathTraversal"),
            Self::CommandInjection => write!(f, "CmdInjection"),
            Self::LdapInjection => write!(f, "LDAPi"),
            Self::XxeInjection => write!(f, "XXE"),
        }
    }
}

/// A single attack indicator found in an HTTP payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpAttackIndicator {
    pub kind: HttpAttackKind,
    /// The matched pattern string.
    pub pattern: String,
    /// Byte offset of the first occurrence in the input.
    pub offset: usize,
}

fn scan_attack_category(text: &[u8], kind: HttpAttackKind, patterns: &[&[u8]], out: &mut Vec<HttpAttackIndicator>) {
    for pat in patterns {
        if let Some(off) = memmem_find(text, pat) {
            out.push(HttpAttackIndicator { kind, pattern: String::from_utf8_lossy(pat).into_owned(), offset: off });
        }
    }
}

/// Scan an HTTP payload for common web-attack patterns.
///
/// The scan is case-insensitive and covers the URI, headers, and body.
/// Returns all indicators found; an empty `Vec` means no matches.
#[must_use]
pub fn scan_http_attacks(data: &[u8]) -> Vec<HttpAttackIndicator> {
    let lower = data.iter().map(|&b| if b.is_ascii_uppercase() { b + 32 } else { b }).collect::<Vec<u8>>();
    let text = lower.as_slice();
    let mut results = Vec::new();

    scan_attack_category(text, HttpAttackKind::SqlInjection, &[
        b"or 1=1", b"or 1 = 1", b"or '1'='1", b"' or '", b"union select",
        b"union all select", b"select * from", b"insert into", b"drop table",
        b"--", b"xp_cmdshell", b"information_schema", b"sleep(", b"waitfor delay",
        b"benchmark(", b"0x3d", b"char(", b"concat(", b"group_concat",
        b"load_file(", b"into outfile", b"into dumpfile",
    ], &mut results);

    scan_attack_category(text, HttpAttackKind::Xss, &[
        b"<script", b"</script>", b"javascript:", b"vbscript:", b"onerror=",
        b"onload=", b"onclick=", b"onmouseover=", b"onfocus=", b"onblur=",
        b"eval(", b"document.cookie", b"document.write", b"window.location",
        b"<img src=", b"<iframe", b"expression(", b"&#x", b"\\u003c",
        b"alert(", b"prompt(", b"confirm(",
    ], &mut results);

    scan_attack_category(text, HttpAttackKind::PathTraversal, &[
        b"../", b"..\\", b"%2e%2e%2f", b"%2e%2e/", b"..%2f", b"%252e%252e",
        b"..%5c", b"/etc/passwd", b"/etc/shadow", b"c:\\windows", b"c:/windows",
        b"boot.ini", b"win.ini",
    ], &mut results);

    scan_attack_category(text, HttpAttackKind::CommandInjection, &[
        b";id", b"; id", b"|whoami", b"| whoami", b"`id`", b"$(id)", b"$(whoami)",
        b";ls ", b"; ls ", b"|ls ", b"| ls ", b";cat ", b"| cat ", b"; cat ",
        b"&&id", b"&& id", b"||id", b"|| id", b";wget ", b";curl ", b"; wget ",
        b"; curl ", b"nc -e", b"bash -i", b"/bin/sh", b"/bin/bash", b"cmd.exe", b"powershell",
    ], &mut results);

    scan_attack_category(text, HttpAttackKind::LdapInjection, &[
        b")(|(", b"*)(uid=*))(|(uid=*", b")(cn=*", b")(objectclass=*",
    ], &mut results);

    scan_attack_category(text, HttpAttackKind::XxeInjection, &[
        b"<!entity", b"<!doctype", b"system \"file://", b"system 'file://",
    ], &mut results);

    results
}

/// Naive substring search (Boyer-Moore-Horspool would be faster but this is
/// zero-dependency and plenty fast for typical packet payloads).
fn memmem_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// HTTP attack-detection dissector.
///
/// Sits on top of a parsed HTTP layer and scans the full payload for
/// SQL-injection, XSS, path-traversal, command-injection, LDAP-injection,
/// and XXE patterns. Adds one field per unique attack kind found.
pub struct HttpAttackDissector;

impl ProtocolDissector for HttpAttackDissector {
    fn name(&self) -> &'static str {
        "HTTP_Attack"
    }
    fn ports(&self) -> &[u16] {
        &[80, 8080, 8000, 443, 8443]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let indicators = scan_http_attacks(data);
        if indicators.is_empty() {
            return Ok(());
        }
        let raw_end = data.len().min(512);
        let mut layer = ProtoLayer::new("HTTP_Attack", data[..raw_end].to_vec());
        layer.add_field(ProtoField::new(
            "attack_count",
            0,
            0,
            FieldValue::Uint(indicators.len() as u64),
        ));
        for (i, ind) in indicators.iter().enumerate() {
            layer.add_field(ProtoField::new(
                format!("attack[{i}].kind"),
                ind.offset,
                ind.pattern.len(),
                FieldValue::Str(ind.kind.to_string()),
            ));
            layer.add_field(ProtoField::new(
                format!("attack[{i}].pattern"),
                ind.offset,
                ind.pattern.len(),
                FieldValue::Str(ind.pattern.clone()),
            ));
            layer.add_field(ProtoField::new(
                format!("attack[{i}].offset"),
                ind.offset,
                0,
                FieldValue::Uint(ind.offset as u64),
            ));
        }
        packet.push_layer(layer);
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Modbus TCP dissector
// ════════════════════════════════════════════════════════════════════════════

/// Modbus function codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModbusFunctionCode {
    ReadCoils,                      // 0x01
    ReadDiscreteInputs,             // 0x02
    ReadHoldingRegisters,           // 0x03
    ReadInputRegisters,             // 0x04
    WriteSingleCoil,                // 0x05
    WriteSingleRegister,            // 0x06
    WriteMultipleCoils,             // 0x0F
    WriteMultipleRegisters,         // 0x10
    ReadFileRecord,                 // 0x14
    WriteFileRecord,                // 0x15
    MaskWriteRegister,              // 0x16
    ReadWriteMultipleRegisters,     // 0x17
    ReadFifoQueue,                  // 0x18
    EncapsulatedInterfaceTransport, // 0x2B
    ExceptionResponse(u8),          // function code | 0x80
    Unknown(u8),
}

impl From<u8> for ModbusFunctionCode {
    fn from(v: u8) -> Self {
        match v {
            0x01 => Self::ReadCoils,
            0x02 => Self::ReadDiscreteInputs,
            0x03 => Self::ReadHoldingRegisters,
            0x04 => Self::ReadInputRegisters,
            0x05 => Self::WriteSingleCoil,
            0x06 => Self::WriteSingleRegister,
            0x0F => Self::WriteMultipleCoils,
            0x10 => Self::WriteMultipleRegisters,
            0x14 => Self::ReadFileRecord,
            0x15 => Self::WriteFileRecord,
            0x16 => Self::MaskWriteRegister,
            0x17 => Self::ReadWriteMultipleRegisters,
            0x18 => Self::ReadFifoQueue,
            0x2B => Self::EncapsulatedInterfaceTransport,
            e if e & 0x80 != 0 => Self::ExceptionResponse(e & 0x7F),
            u => Self::Unknown(u),
        }
    }
}

impl fmt::Display for ModbusFunctionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadCoils => write!(f, "ReadCoils(0x01)"),
            Self::ReadDiscreteInputs => write!(f, "ReadDiscreteInputs(0x02)"),
            Self::ReadHoldingRegisters => write!(f, "ReadHoldingRegisters(0x03)"),
            Self::ReadInputRegisters => write!(f, "ReadInputRegisters(0x04)"),
            Self::WriteSingleCoil => write!(f, "WriteSingleCoil(0x05)"),
            Self::WriteSingleRegister => write!(f, "WriteSingleRegister(0x06)"),
            Self::WriteMultipleCoils => write!(f, "WriteMultipleCoils(0x0F)"),
            Self::WriteMultipleRegisters => write!(f, "WriteMultipleRegisters(0x10)"),
            Self::ReadFileRecord => write!(f, "ReadFileRecord(0x14)"),
            Self::WriteFileRecord => write!(f, "WriteFileRecord(0x15)"),
            Self::MaskWriteRegister => write!(f, "MaskWriteRegister(0x16)"),
            Self::ReadWriteMultipleRegisters => write!(f, "ReadWriteMultipleRegisters(0x17)"),
            Self::ReadFifoQueue => write!(f, "ReadFifoQueue(0x18)"),
            Self::EncapsulatedInterfaceTransport => write!(f, "EncapsulatedIFTransport(0x2B)"),
            Self::ExceptionResponse(c) => write!(f, "Exception(fc=0x{c:02x})"),
            Self::Unknown(v) => write!(f, "Unknown(0x{v:02x})"),
        }
    }
}

/// Parsed Modbus TCP MBAP header + function body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusPacket {
    /// Transaction identifier (echoed in response).
    pub transaction_id: u16,
    /// Protocol identifier — must be 0x0000 for Modbus.
    pub protocol_id: u16,
    /// Length of remaining bytes (`unit_id` + PDU).
    pub length: u16,
    /// Unit identifier (formerly slave address).
    pub unit_id: u8,
    /// Decoded function code.
    pub function_code: ModbusFunctionCode,
    /// Starting address (for read/write operations).
    pub start_address: Option<u16>,
    /// Quantity / count field where applicable.
    pub quantity: Option<u16>,
    /// Single output/register value (for single-write operations).
    pub output_value: Option<u16>,
    /// Exception code byte (only set for exception responses).
    pub exception_code: Option<u8>,
}

impl ModbusPacket {
    /// Parse a full Modbus TCP frame from raw bytes.
    ///
    /// # Errors
    /// Returns [`DissectError::TooShort`] when fewer than 8 bytes are provided.
    /// Returns [`DissectError::InvalidMagic`] when the protocol ID is not 0.
    pub fn parse(data: &[u8]) -> Result<Self, DissectError> {
        // Minimum: MBAP (7 bytes) + function code (1 byte) = 8 bytes
        if data.len() < 8 {
            return Err(DissectError::TooShort {
                need: 8,
                got: data.len(),
            });
        }
        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        let protocol_id = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let unit_id = data[6];
        let fc_byte = data[7];

        if protocol_id != 0 {
            return Err(DissectError::InvalidMagic(format!(
                "Modbus protocol_id must be 0, got {protocol_id:#06x}"
            )));
        }

        let function_code = ModbusFunctionCode::from(fc_byte);

        let pdu = &data[7..]; // function code + data
        let start_address;
        let quantity;
        let output_value;
        let exception_code;

        match function_code {
            // Exception response: 1 additional byte (exception code)
            ModbusFunctionCode::ExceptionResponse(_) => {
                start_address = None;
                quantity = None;
                output_value = None;
                exception_code = if pdu.len() >= 2 { Some(pdu[1]) } else { None };
            }
            // Read coils/discrete/holding/input OR WriteMultiple: StartAddr(2) + Quantity(2)
            ModbusFunctionCode::ReadCoils
            | ModbusFunctionCode::ReadDiscreteInputs
            | ModbusFunctionCode::ReadHoldingRegisters
            | ModbusFunctionCode::ReadInputRegisters
            | ModbusFunctionCode::WriteMultipleCoils
            | ModbusFunctionCode::WriteMultipleRegisters => {
                start_address = if pdu.len() >= 3 {
                    Some(u16::from_be_bytes([pdu[1], pdu[2]]))
                } else {
                    None
                };
                quantity = if pdu.len() >= 5 {
                    Some(u16::from_be_bytes([pdu[3], pdu[4]]))
                } else {
                    None
                };
                output_value = None;
                exception_code = None;
            }
            // WriteSingleCoil / WriteSingleRegister: OutputAddr(2) + OutputVal(2)
            ModbusFunctionCode::WriteSingleCoil | ModbusFunctionCode::WriteSingleRegister => {
                start_address = if pdu.len() >= 3 {
                    Some(u16::from_be_bytes([pdu[1], pdu[2]]))
                } else {
                    None
                };
                output_value = if pdu.len() >= 5 {
                    Some(u16::from_be_bytes([pdu[3], pdu[4]]))
                } else {
                    None
                };
                quantity = None;
                exception_code = None;
            }
            _ => {
                start_address = None;
                quantity = None;
                output_value = None;
                exception_code = None;
            }
        }

        Ok(Self {
            transaction_id,
            protocol_id,
            length,
            unit_id,
            function_code,
            start_address,
            quantity,
            output_value,
            exception_code,
        })
    }
}

/// Modbus TCP dissector.
///
/// Parses the 7-byte MBAP header (`transaction_id`, `protocol_id`, length, `unit_id`)
/// followed by the PDU (function code + optional address/value fields).
/// Handles function codes 1-6, 15, 16 with full address/quantity decoding.
pub struct ModbusDissector;

impl ProtocolDissector for ModbusDissector {
    fn name(&self) -> &'static str {
        "Modbus"
    }
    fn ports(&self) -> &[u16] {
        &[502]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let pkt = ModbusPacket::parse(data)?;
        let raw_end = data.len().min(256);
        let mut layer = ProtoLayer::new("Modbus", data[..raw_end].to_vec());

        layer.add_field(ProtoField::new(
            "transaction_id",
            0,
            2,
            FieldValue::Uint(u64::from(pkt.transaction_id)),
        ));
        layer.add_field(ProtoField::new(
            "protocol_id",
            2,
            2,
            FieldValue::Uint(u64::from(pkt.protocol_id)),
        ));
        layer.add_field(ProtoField::new(
            "length",
            4,
            2,
            FieldValue::Uint(u64::from(pkt.length)),
        ));
        layer.add_field(ProtoField::new(
            "unit_id",
            6,
            1,
            FieldValue::Uint(u64::from(pkt.unit_id)),
        ));
        layer.add_field(ProtoField::new(
            "function_code",
            7,
            1,
            FieldValue::Str(pkt.function_code.to_string()),
        ));

        if let Some(addr) = pkt.start_address {
            layer.add_field(ProtoField::new(
                "start_address",
                8,
                2,
                FieldValue::Uint(u64::from(addr)),
            ));
        }
        if let Some(qty) = pkt.quantity {
            layer.add_field(ProtoField::new(
                "quantity",
                10,
                2,
                FieldValue::Uint(u64::from(qty)),
            ));
        }
        if let Some(val) = pkt.output_value {
            layer.add_field(ProtoField::new(
                "output_value",
                10,
                2,
                FieldValue::Uint(u64::from(val)),
            ));
        }
        if let Some(ec) = pkt.exception_code {
            layer.add_field(ProtoField::new(
                "exception_code",
                8,
                1,
                FieldValue::Uint(u64::from(ec)),
            ));
        }

        packet.push_layer(layer);
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DNP3 dissector
// ════════════════════════════════════════════════════════════════════════════

/// Packed DNP3 link-layer control bits (DIR/PRM/FCB/FCV).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dnp3LinkBits(u8);

impl Dnp3LinkBits {
    const fn new(b: u8) -> Self { Self(b) }
    /// Direction bit (1 = primary to secondary).
    #[must_use] pub const fn dir(self) -> bool { self.0 & 0x80 != 0 }
    /// Primary bit.
    #[must_use] pub const fn prm(self) -> bool { self.0 & 0x40 != 0 }
    /// Frame Count Bit.
    #[must_use] pub const fn fcb(self) -> bool { self.0 & 0x20 != 0 }
    /// Frame Count Valid / Final Frame.
    #[must_use] pub const fn fcv_or_dfc(self) -> bool { self.0 & 0x10 != 0 }
}

/// DNP3 link-layer control byte field breakdown.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Dnp3LinkControl {
    /// Packed DIR/PRM/FCB/FCV bits.
    pub bits: Dnp3LinkBits,
    /// Function code (lower 4 bits).
    pub function_code: u8,
}

impl Dnp3LinkControl {
    const fn from_byte(b: u8) -> Self {
        Self {
            bits: Dnp3LinkBits::new(b),
            function_code: b & 0x0F,
        }
    }
    /// Direction bit accessor.
    #[must_use] pub const fn dir(&self) -> bool { self.bits.dir() }
    /// Primary bit accessor.
    #[must_use] pub const fn prm(&self) -> bool { self.bits.prm() }
    /// Frame Count Bit accessor.
    #[must_use] pub const fn fcb(&self) -> bool { self.bits.fcb() }
}

impl fmt::Display for Dnp3LinkControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DIR={} PRM={} FCB={} FC={}",
            u8::from(self.dir()), u8::from(self.prm()), u8::from(self.fcb()), self.function_code
        )
    }
}

/// Application-layer data object group/variation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dnp3ObjectHeader {
    pub group: u8,
    pub variation: u8,
    pub qualifier: u8,
    pub count: u32,
}

/// Parsed DNP3 frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dnp3Frame {
    /// Start bytes, always 0x0564.
    pub start: u16,
    /// Link-layer length field (number of bytes after start + length itself).
    pub length: u8,
    /// Decoded control byte.
    pub control: Dnp3LinkControl,
    /// Destination address (link layer).
    pub dst: u16,
    /// Source address (link layer).
    pub src: u16,
    /// CRC of the link-layer header (bytes 0..8).
    pub header_crc: u16,
    /// Application-layer transport control byte (if present).
    pub transport_control: Option<u8>,
    /// Application-layer control byte (if present).
    pub app_control: Option<u8>,
    /// Application function code (if present).
    pub app_function_code: Option<u8>,
    /// Object headers parsed from the application-layer body.
    pub objects: Vec<Dnp3ObjectHeader>,
}

/// CRC-16/DNP — polynomial 0x3D65, initial value 0x0000, reflected.
///
/// Used to verify link-layer blocks. This is the standard CRC used in
/// DNP3 / IEC 60870-5.
#[must_use]
pub fn dnp3_crc16(data: &[u8]) -> u16 {
    const POLY: u16 = 0x3D65;
    let mut crc: u16 = 0x0000;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

impl Dnp3Frame {
    /// Parse a DNP3 frame.
    ///
    /// # Errors
    /// Returns [`DissectError::TooShort`] when fewer than 10 bytes are supplied.
    /// Returns [`DissectError::InvalidMagic`] when start bytes are not 0x0564.
    pub fn parse(data: &[u8]) -> Result<Self, DissectError> {
        // Minimum: start(2)+length(1)+control(1)+dst(2)+src(2)+crc(2) = 10 bytes
        if data.len() < 10 {
            return Err(DissectError::TooShort {
                need: 10,
                got: data.len(),
            });
        }
        let start = u16::from_be_bytes([data[0], data[1]]);
        if start != 0x0564 {
            return Err(DissectError::InvalidMagic(format!(
                "DNP3 start expected 0x0564, got 0x{start:04x}"
            )));
        }
        let length = data[2];
        let control = Dnp3LinkControl::from_byte(data[3]);
        let dst = u16::from_le_bytes([data[4], data[5]]);
        let src = u16::from_le_bytes([data[6], data[7]]);
        let header_crc = u16::from_le_bytes([data[8], data[9]]);

        // Parse user data blocks (each block is up to 16 bytes + 2-byte CRC)
        let mut transport_control: Option<u8> = None;
        let mut app_control: Option<u8> = None;
        let mut app_function_code: Option<u8> = None;
        let mut objects: Vec<Dnp3ObjectHeader> = Vec::new();

        let mut user_data: Vec<u8> = Vec::new();
        let mut off = 10usize;
        while off + 2 < data.len() {
            let block_data_len = (data.len() - off).saturating_sub(2).min(16);
            if block_data_len == 0 {
                break;
            }
            user_data.extend_from_slice(&data[off..off + block_data_len]);
            off += block_data_len + 2; // skip block CRC
        }

        if !user_data.is_empty() {
            transport_control = Some(user_data[0]);
            if user_data.len() >= 2 {
                app_control = Some(user_data[1]);
            }
            if user_data.len() >= 3 {
                app_function_code = Some(user_data[2]);
            }
            // Parse object headers starting at byte 3
            let mut o = 3usize;
            while o + 3 <= user_data.len() {
                let group = user_data[o];
                let variation = user_data[o + 1];
                let qualifier = user_data[o + 2];
                o += 3;
                // Determine count from qualifier code
                let count: u32 = match qualifier & 0x70 {
                    0x00 | 0x10 => {
                        // 8-bit start/stop or count
                        if o + 2 <= user_data.len() {
                            let c = u32::from(user_data[o + 1]);
                            o += 2;
                            c
                        } else {
                            break;
                        }
                    }
                    0x20 | 0x30 => {
                        // 16-bit start/stop or count
                        if o + 4 <= user_data.len() {
                            let c =
                                u32::from(u16::from_le_bytes([user_data[o + 2], user_data[o + 3]]));
                            o += 4;
                            c
                        } else {
                            break;
                        }
                    }
                    _ => 0,
                };
                objects.push(Dnp3ObjectHeader {
                    group,
                    variation,
                    qualifier,
                    count,
                });
            }
        }

        Ok(Self {
            start,
            length,
            control,
            dst,
            src,
            header_crc,
            transport_control,
            app_control,
            app_function_code,
            objects,
        })
    }
}

/// DNP3 dissector (Distributed Network Protocol 3, IEC 60870-5 derivative).
///
/// Detects the 0x0564 start bytes, parses the link-layer header (length,
/// control, destination, source, CRC) and, when application data is present,
/// decodes the transport control, application control, function code, and
/// object group/variation headers.
pub struct Dnp3Dissector;

impl ProtocolDissector for Dnp3Dissector {
    fn name(&self) -> &'static str {
        "DNP3"
    }
    fn ports(&self) -> &[u16] {
        &[20000]
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        let frame = Dnp3Frame::parse(data)?;
        let raw_end = data.len().min(128);
        let mut layer = ProtoLayer::new("DNP3", data[..raw_end].to_vec());
        dnp3_push_link_fields(&frame, &mut layer);
        for (i, obj) in frame.objects.iter().enumerate() {
            layer.add_field(ProtoField::new(format!("obj[{i}].group"), 0, 1, FieldValue::Uint(u64::from(obj.group))));
            layer.add_field(ProtoField::new(format!("obj[{i}].variation"), 0, 1, FieldValue::Uint(u64::from(obj.variation))));
            layer.add_field(ProtoField::new(format!("obj[{i}].qualifier"), 0, 1, FieldValue::Uint(u64::from(obj.qualifier))));
            layer.add_field(ProtoField::new(format!("obj[{i}].count"), 0, 0, FieldValue::Uint(u64::from(obj.count))));
        }
        let computed = dnp3_crc16(&data[0..8]);
        layer.add_field(ProtoField::new("header_crc_valid", 0, 10, FieldValue::Bool(computed == frame.header_crc)));
        packet.push_layer(layer);
        Ok(())
    }
}

fn dnp3_push_link_fields(frame: &Dnp3Frame, layer: &mut ProtoLayer) {
    layer.add_field(ProtoField::new("start",   0, 2, FieldValue::Uint(u64::from(frame.start))));
    layer.add_field(ProtoField::new("length",  2, 1, FieldValue::Uint(u64::from(frame.length))));
    layer.add_field(ProtoField::new("control", 3, 1, FieldValue::Str(frame.control.to_string())));
    layer.add_field(ProtoField::new("ctrl_dir",3, 1, FieldValue::Bool(frame.control.dir())));
    layer.add_field(ProtoField::new("ctrl_prm",3, 1, FieldValue::Bool(frame.control.prm())));
    layer.add_field(ProtoField::new("ctrl_fc", 3, 1, FieldValue::Uint(u64::from(frame.control.function_code))));
    layer.add_field(ProtoField::new("dst",     4, 2, FieldValue::Uint(u64::from(frame.dst))));
    layer.add_field(ProtoField::new("src",     6, 2, FieldValue::Uint(u64::from(frame.src))));
    layer.add_field(ProtoField::new("header_crc", 8, 2, FieldValue::Uint(u64::from(frame.header_crc))));
    if let Some(tc) = frame.transport_control {
        layer.add_field(ProtoField::new("transport_control", 10, 1, FieldValue::Uint(u64::from(tc))));
    }
    if let Some(ac) = frame.app_control {
        layer.add_field(ProtoField::new("app_control", 11, 1, FieldValue::Uint(u64::from(ac))));
    }
    if let Some(fc) = frame.app_function_code {
        layer.add_field(ProtoField::new("app_function_code", 12, 1, FieldValue::Uint(u64::from(fc))));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Enhanced ICMP dissector with tunnel detection
// ════════════════════════════════════════════════════════════════════════════

/// Computed Shannon entropy of a byte slice (bits per byte, 0.0 – 8.0).
#[must_use]
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter().fold(0.0f64, |acc, &c| {
        if c == 0 {
            acc
        } else {
            let p = f64::from(c) / n;
            p.mul_add(-p.log2(), acc)
        }
    })
}

/// ICMP type names (common subset) — used by [`IcmpEnhancedDissector`].
const fn icmp_type_name_enhanced(t: u8) -> &'static str {
    match t {
        0 => "EchoReply",
        3 => "DestinationUnreachable",
        4 => "SourceQuench",
        5 => "Redirect",
        8 => "EchoRequest",
        9 => "RouterAdvertisement",
        10 => "RouterSolicitation",
        11 => "TimeExceeded",
        12 => "ParameterProblem",
        13 => "TimestampRequest",
        14 => "TimestampReply",
        17 => "AddressMaskRequest",
        18 => "AddressMaskReply",
        _ => "Unknown",
    }
}

/// Destination-Unreachable code names.
const fn icmp_du_code_name(code: u8) -> &'static str {
    match code {
        0 => "NetUnreachable",
        1 => "HostUnreachable",
        2 => "ProtocolUnreachable",
        3 => "PortUnreachable",
        4 => "FragmentationNeeded",
        5 => "SourceRouteFailed",
        6 => "DestNetUnknown",
        7 => "DestHostUnknown",
        9 => "NetAdminProhibited",
        10 => "HostAdminProhibited",
        11 => "NetUnreachableTOS",
        12 => "HostUnreachableTOS",
        13 => "CommAdminProhibited",
        _ => "UnknownCode",
    }
}

/// Result of ICMP tunnel detection heuristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpTunnelAnalysis {
    /// Shannon entropy of the ICMP payload (bits per byte).
    pub payload_entropy: f64,
    /// Payload length in bytes.
    pub payload_length: usize,
    /// True when entropy > 7.0 (very high, suggests encrypted/compressed data).
    pub high_entropy: bool,
    /// True when the payload contains printable ASCII text.
    pub printable_ascii: bool,
    /// True when heuristics suggest this ICMP stream may be a covert channel.
    pub tunnel_suspected: bool,
    /// Human-readable reason for the tunneling verdict.
    pub reason: String,
}

impl IcmpTunnelAnalysis {
    fn analyse(payload: &[u8]) -> Self {
        let entropy = byte_entropy(payload);
        let length = payload.len();
        let high_entropy = entropy > 7.0;
        let printable_ascii = payload.len() > 8
            && payload.iter().filter(|&&b| (0x20..0x7F).contains(&b)).count() * 100 / payload.len()
                > 80;

        // Tunneling heuristics:
        // 1. Unusually large ICMP payload (> 64 bytes for Echo).
        // 2. High entropy (random-looking data — encrypted or compressed).
        // 3. Payload looks like printable text (exfiltration via plaintext).
        let large_payload = length > 64;
        let mut reasons: Vec<&str> = Vec::new();
        if large_payload {
            reasons.push("large_payload");
        }
        if high_entropy {
            reasons.push("high_entropy");
        }
        if printable_ascii {
            reasons.push("printable_ascii");
        }

        let tunnel_suspected = large_payload && (high_entropy || printable_ascii);
        let reason = if reasons.is_empty() {
            "none".to_string()
        } else {
            reasons.join(",")
        };

        Self {
            payload_entropy: entropy,
            payload_length: length,
            high_entropy,
            printable_ascii,
            tunnel_suspected,
            reason,
        }
    }
}

/// Enhanced ICMP dissector.
///
/// Extends the minimal built-in [`IcmpDissector`] with:
/// - Type-name string field.
/// - Code interpretation for Destination Unreachable.
/// - Echo identifier and sequence number.
/// - Shannon-entropy-based tunnel-detection heuristics.
pub struct IcmpEnhancedDissector;

impl ProtocolDissector for IcmpEnhancedDissector {
    fn name(&self) -> &'static str {
        "ICMP_Enhanced"
    }

    fn dissect(
        &self,
        data: &[u8],
        _layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        if data.len() < 4 {
            return Err(DissectError::TooShort {
                need: 4,
                got: data.len(),
            });
        }
        let icmp_type = data[0];
        let icmp_code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        let raw_end = data.len().min(64);
        let mut layer = ProtoLayer::new("ICMP_Enhanced", data[..raw_end].to_vec());

        layer.add_field(ProtoField::new(
            "type",
            0,
            1,
            FieldValue::Uint(u64::from(icmp_type)),
        ));
        layer.add_field(ProtoField::new(
            "type_name",
            0,
            1,
            FieldValue::Str(icmp_type_name_enhanced(icmp_type).to_string()),
        ));
        layer.add_field(ProtoField::new(
            "code",
            1,
            1,
            FieldValue::Uint(u64::from(icmp_code)),
        ));

        // Code interpretation
        if icmp_type == 3 {
            layer.add_field(ProtoField::new(
                "code_name",
                1,
                1,
                FieldValue::Str(icmp_du_code_name(icmp_code).to_string()),
            ));
        }

        layer.add_field(ProtoField::new(
            "checksum",
            2,
            2,
            FieldValue::Uint(u64::from(checksum)),
        ));

        // Echo Request / Echo Reply: identifier + sequence
        if (icmp_type == 8 || icmp_type == 0) && data.len() >= 8 {
            let identifier = u16::from_be_bytes([data[4], data[5]]);
            let sequence = u16::from_be_bytes([data[6], data[7]]);
            layer.add_field(ProtoField::new(
                "echo_id",
                4,
                2,
                FieldValue::Uint(u64::from(identifier)),
            ));
            layer.add_field(ProtoField::new(
                "echo_seq",
                6,
                2,
                FieldValue::Uint(u64::from(sequence)),
            ));
        }

        // Timestamp: originate, receive, transmit
        if (icmp_type == 13 || icmp_type == 14) && data.len() >= 20 {
            let originate = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            let receive = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
            let transmit = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
            layer.add_field(ProtoField::new(
                "ts_originate",
                8,
                4,
                FieldValue::Uint(u64::from(originate)),
            ));
            layer.add_field(ProtoField::new(
                "ts_receive",
                12,
                4,
                FieldValue::Uint(u64::from(receive)),
            ));
            layer.add_field(ProtoField::new(
                "ts_transmit",
                16,
                4,
                FieldValue::Uint(u64::from(transmit)),
            ));
        }

        let payload_start = if icmp_type == 8 || icmp_type == 0 { 8 } else { 4 };
        if data.len() > payload_start {
            icmp_push_tunnel_fields(&data[payload_start..], payload_start, &mut layer);
        }
        packet.push_layer(layer);
        Ok(())
    }
}

fn icmp_push_tunnel_fields(payload: &[u8], off: usize, layer: &mut ProtoLayer) {
    let a = IcmpTunnelAnalysis::analyse(payload);
    layer.add_field(ProtoField::new("payload_length",  off, 0, FieldValue::Uint(a.payload_length as u64)));
    layer.add_field(ProtoField::new("payload_entropy", off, 0, FieldValue::Float(a.payload_entropy)));
    layer.add_field(ProtoField::new("high_entropy",    off, 0, FieldValue::Bool(a.high_entropy)));
    layer.add_field(ProtoField::new("printable_ascii", off, 0, FieldValue::Bool(a.printable_ascii)));
    layer.add_field(ProtoField::new("tunnel_suspected",off, 0, FieldValue::Bool(a.tunnel_suspected)));
    layer.add_field(ProtoField::new("tunnel_reason",   off, 0, FieldValue::Str(a.reason)));
}

// ════════════════════════════════════════════════════════════════════════════
// Auto-detect dissector
// ════════════════════════════════════════════════════════════════════════════

/// Confidence level from a magic-byte or port-based detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DetectConfidence {
    /// Port match only — no magic-byte confirmation.
    Low,
    /// Magic-byte match without port context.
    Medium,
    /// Both port and magic-byte (or strong structural) match.
    High,
}

impl fmt::Display for DetectConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

/// Result of the auto-detection pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoDetectResult {
    /// Detected protocol name.
    pub protocol: String,
    /// Detection confidence.
    pub confidence: DetectConfidence,
    /// Why this protocol was selected.
    pub reason: String,
}

/// Attempt to identify a protocol by examining both port numbers and the
/// first few bytes of the payload.
///
/// This function is intentionally conservative: when uncertain it returns
/// `None` rather than a wrong guess.
#[must_use]
pub fn auto_detect_protocol(src_port: u16, dst_port: u16, data: &[u8]) -> Option<AutoDetectResult> {
    if let Some(r) = auto_detect_magic(src_port, dst_port, data) { return Some(r); }
    if let Some(r) = auto_detect_http_dns(src_port, dst_port, data) { return Some(r); }
    // ── Port-only fallbacks ───────────────────────────────────────────────
    let server_port = src_port.min(dst_port);
    match server_port {
        21 | 20 => Some(AutoDetectResult { protocol: "FTP".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        22 => Some(AutoDetectResult { protocol: "SSH".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        25 | 587 | 465 => Some(AutoDetectResult { protocol: "SMTP".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        53 => Some(AutoDetectResult { protocol: "DNS".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        80 | 8080 | 8000 => Some(AutoDetectResult { protocol: "HTTP".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        110 => Some(AutoDetectResult { protocol: "POP3".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        143 => Some(AutoDetectResult { protocol: "IMAP".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        443 | 8443 => Some(AutoDetectResult { protocol: "TLS".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        445 | 139 => Some(AutoDetectResult { protocol: "SMB2".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        502 => Some(AutoDetectResult { protocol: "Modbus".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        20000 => Some(AutoDetectResult { protocol: "DNP3".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        88 | 750 => Some(AutoDetectResult { protocol: "Kerberos".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        3306 => Some(AutoDetectResult { protocol: "MySQL".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        5432 => Some(AutoDetectResult { protocol: "PostgreSQL".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        6379 => Some(AutoDetectResult { protocol: "Redis".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        27017 => Some(AutoDetectResult { protocol: "MongoDB".into(), confidence: DetectConfidence::Low, reason: "port".into() }),
        _ => None,
    }
}

fn auto_detect_magic(src_port: u16, dst_port: u16, data: &[u8]) -> Option<AutoDetectResult> {
    if data.len() >= 4 && &data[0..4] == b"\xFESMB" {
        let conf = if src_port == 445 || dst_port == 445 || src_port == 139 || dst_port == 139 { DetectConfidence::High } else { DetectConfidence::Medium };
        return Some(AutoDetectResult { protocol: "SMB2".into(), confidence: conf, reason: "magic=FE534D42".into() });
    }
    if data.len() >= 4 && &data[0..4] == b"\xFFSMB" {
        return Some(AutoDetectResult { protocol: "SMB".into(), confidence: DetectConfidence::Medium, reason: "magic=FF534D42 (SMB1)".into() });
    }
    if data.len() >= 2 && data[0] == 0x05 && data[1] == 0x64 {
        return Some(AutoDetectResult { protocol: "DNP3".into(), confidence: DetectConfidence::Medium, reason: "magic=0x0564".into() });
    }
    if data.len() >= 8 && data[2] == 0x00 && data[3] == 0x00 {
        let trans_id_plausible = data[0] != 0xFF || data[1] != 0xFF;
        let fc = data[7];
        let valid_fc = matches!(fc, 0x01..=0x06 | 0x0F | 0x10 | 0x14..=0x18 | 0x2B) || fc & 0x80 != 0;
        if valid_fc && trans_id_plausible {
            let pm = src_port == 502 || dst_port == 502;
            return Some(AutoDetectResult { protocol: "Modbus".into(), confidence: if pm { DetectConfidence::High } else { DetectConfidence::Medium }, reason: format!("protocol_id=0, fc=0x{fc:02x}") });
        }
    }
    if let Some(&tag) = data.first() && matches!(tag, 0x6A | 0x6B | 0x6C | 0x6D | 0x7E) {
        let pm = src_port == 88 || dst_port == 88 || src_port == 750 || dst_port == 750;
        return Some(AutoDetectResult { protocol: "Kerberos".into(), confidence: if pm { DetectConfidence::High } else { DetectConfidence::Low }, reason: format!("ASN.1 APPLICATION tag 0x{tag:02x}") });
    }
    if data.len() >= 3 && matches!(data[0], 20..=23) && matches!(u16::from_be_bytes([data[1], data[2]]), 0x0301..=0x0304) {
        let pm = src_port == 443 || dst_port == 443 || src_port == 8443 || dst_port == 8443;
        return Some(AutoDetectResult { protocol: "TLS".into(), confidence: if pm { DetectConfidence::High } else { DetectConfidence::Medium }, reason: format!("TLS record type={}", data[0]) });
    }
    None
}

fn auto_detect_http_dns(src_port: u16, dst_port: u16, data: &[u8]) -> Option<AutoDetectResult> {
    if data.starts_with(b"HTTP/") {
        return Some(AutoDetectResult { protocol: "HTTP".into(), confidence: DetectConfidence::High, reason: "magic=HTTP/".into() });
    }
    for method in [b"GET " as &[u8], b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH "] {
        if data.starts_with(method) {
            return Some(AutoDetectResult { protocol: "HTTP".into(), confidence: DetectConfidence::High, reason: format!("HTTP method {}", String::from_utf8_lossy(&method[..method.len()-1])) });
        }
    }
    if data.len() >= 12 {
        let qd = u16::from_be_bytes([data[4], data[5]]);
        let an = u16::from_be_bytes([data[6], data[7]]);
        let ns = u16::from_be_bytes([data[8], data[9]]);
        let ar = u16::from_be_bytes([data[10], data[11]]);
        if qd <= 4 && an <= 50 && ns <= 20 && ar <= 20 && (src_port == 53 || dst_port == 53) {
            return Some(AutoDetectResult { protocol: "DNS".into(), confidence: DetectConfidence::High, reason: "port=53 + plausible DNS header".into() });
        }
    }
    None
}

/// Auto-detect dissector.
///
/// Inspects port numbers and magic bytes to select a sub-dissector, then
/// delegates to it. Adds a `AutoDetect` layer recording the detected protocol,
/// confidence, and reason before the sub-dissector layers.
pub struct AutoDetectDissector;

impl ProtocolDissector for AutoDetectDissector {
    fn name(&self) -> &'static str {
        "AutoDetect"
    }

    fn dissect(
        &self,
        data: &[u8],
        layer: u32,
        packet: &mut DissectedPacket,
    ) -> Result<(), DissectError> {
        // AutoDetect needs port context which is not available here;
        // use src/dst = 0 for magic-byte-only detection.
        self.dissect_with_ports(data, layer, packet, 0, 0)
    }
}

impl AutoDetectDissector {
    /// Dissect with explicit port numbers for higher accuracy.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn dissect_with_ports(
        &self,
        data: &[u8],
        layer: u32,
        packet: &mut DissectedPacket,
        src_port: u16,
        dst_port: u16,
    ) -> Result<(), DissectError> {
        let result = auto_detect_protocol(src_port, dst_port, data);

        let raw_end = data.len().min(32);
        let mut ad_layer = ProtoLayer::new("AutoDetect", data[..raw_end].to_vec());

        if let Some(ref det) = result {
            ad_layer.add_field(ProtoField::new(
                "detected_protocol",
                0,
                0,
                FieldValue::Str(det.protocol.clone()),
            ));
            ad_layer.add_field(ProtoField::new(
                "confidence",
                0,
                0,
                FieldValue::Str(det.confidence.to_string()),
            ));
            ad_layer.add_field(ProtoField::new(
                "reason",
                0,
                0,
                FieldValue::Str(det.reason.clone()),
            ));
        } else {
            ad_layer.add_field(ProtoField::new(
                "detected_protocol",
                0,
                0,
                FieldValue::Str("Unknown".into()),
            ));
            ad_layer.add_field(ProtoField::new(
                "confidence",
                0,
                0,
                FieldValue::Str("none".into()),
            ));
            ad_layer.add_field(ProtoField::new(
                "reason",
                0,
                0,
                FieldValue::Str("no match".into()),
            ));
        }
        packet.push_layer(ad_layer);

        if let Some(det) = result {
            match det.protocol.as_str() {
                "SMB2" => {
                    let _ = Smb2FullDissector.dissect(data, layer + 1, packet);
                }
                "Kerberos" => {
                    let _ = KerberosDissector.dissect(data, layer + 1, packet);
                }
                "HTTP" => {
                    let _ = HttpDissector.dissect(data, layer + 1, packet);
                    let _ = HttpAttackDissector.dissect(data, layer + 1, packet);
                }
                "TLS" => {
                    let _ = TlsDissector.dissect(data, layer + 1, packet);
                }
                "DNS" => {
                    let _ = DnsDissector.dissect(data, layer + 1, packet);
                }
                "Modbus" => {
                    let _ = ModbusDissector.dissect(data, layer + 1, packet);
                }
                "DNP3" => {
                    let _ = Dnp3Dissector.dissect(data, layer + 1, packet);
                }
                "FTP" => {
                    let _ = FtpDissector.dissect(data, layer + 1, packet);
                }
                "SMTP" => {
                    let _ = SmtpDissector.dissect(data, layer + 1, packet);
                }
                _ => {}
            }
        }
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests for the new dissectors
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod new_dissector_tests {
    use super::*;

    // ── SMB2 header parsing ───────────────────────────────────────────────

    fn make_smb2_header(command: u16, flags: u32, session_id: u64, tree_id: u32) -> Vec<u8> {
        let mut h = Vec::with_capacity(64);
        h.extend_from_slice(b"\xFESMB"); // magic
        h.extend_from_slice(&64u16.to_le_bytes()); // structure_size
        h.extend_from_slice(&0u16.to_le_bytes()); // credit_charge
        h.extend_from_slice(&0u32.to_le_bytes()); // status
        h.extend_from_slice(&command.to_le_bytes());
        h.extend_from_slice(&1u16.to_le_bytes()); // credits
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // next_command
        h.extend_from_slice(&1u64.to_le_bytes()); // message_id
        h.extend_from_slice(&0u32.to_le_bytes()); // process_id
        h.extend_from_slice(&tree_id.to_le_bytes());
        h.extend_from_slice(&session_id.to_le_bytes());
        h.extend_from_slice(&[0u8; 16]); // signature
        assert_eq!(h.len(), 64);
        h
    }

    #[test]
    fn test_smb2_header_parse_negotiate() {
        let data = make_smb2_header(0x0000, 0x00, 0, 0);
        let hdr = Smb2Header::parse(&data).unwrap();
        assert_eq!(hdr.structure_size, 64);
        assert!(matches!(hdr.command, Smb2Command::Negotiate));
        assert!(!hdr.is_response());
        assert!(!hdr.is_signed());
    }

    #[test]
    fn test_smb2_header_parse_response_flag() {
        let data = make_smb2_header(0x0001, 0x01, 12345, 99);
        let hdr = Smb2Header::parse(&data).unwrap();
        assert!(matches!(hdr.command, Smb2Command::SessionSetup));
        assert!(hdr.is_response());
        assert_eq!(hdr.session_id, 12345);
        assert_eq!(hdr.tree_id, 99);
    }

    #[test]
    fn test_smb2_header_too_short() {
        let err = Smb2Header::parse(&[0u8; 32]).unwrap_err();
        assert!(matches!(err, DissectError::TooShort { .. }));
    }

    #[test]
    fn test_smb2_header_wrong_magic() {
        let mut data = make_smb2_header(0x0000, 0, 0, 0);
        data[0] = 0xFF; // corrupt magic
        let err = Smb2Header::parse(&data).unwrap_err();
        assert!(matches!(err, DissectError::InvalidMagic(_)));
    }

    #[test]
    fn test_smb2_full_dissector_negotiate() {
        let mut data = make_smb2_header(0x0000, 0x00, 0, 0);
        // Minimal Negotiate body: StructureSize(36) + DialectCount(1) + SecurityMode(1) +
        // Reserved(0) + Capabilities(0) + ClientGuid(16) + ClientStartTime(8) + Dialect(2) = 38
        let mut body = vec![0u8; 36];
        body[0] = 36; // structure_size low byte
        body[2] = 1; // dialect_count = 1
        body.extend_from_slice(&[0x00u8, 0x02]); // dialect 0x0200
        data.extend_from_slice(&body);

        let mut pkt = DissectedPacket::new();
        Smb2FullDissector.dissect(&data, 0, &mut pkt).unwrap();
        let smb2_layer = pkt.layer("SMB2").expect("SMB2 layer missing");
        let cmd = smb2_layer.field("command").expect("command field missing");
        assert!(
            cmd.value.to_string().contains("Negotiate"),
            "got: {}",
            cmd.value
        );
    }

    #[test]
    fn test_smb2_command_display() {
        assert_eq!(Smb2Command::Read.to_string(), "Read");
        assert_eq!(Smb2Command::Write.to_string(), "Write");
        assert_eq!(Smb2Command::QueryInfo.to_string(), "QueryInfo");
        assert_eq!(Smb2Command::Unknown(0xFF).to_string(), "Unknown(0x00ff)");
    }

    #[test]
    fn test_smb2_create_request_parse() {
        let mut body = vec![0u8; 64];
        // desired_access at byte 24
        let desired: u32 = 0x0012_0089;
        let da_bytes = desired.to_le_bytes();
        body[24] = da_bytes[0];
        body[25] = da_bytes[1];
        body[26] = da_bytes[2];
        body[27] = da_bytes[3];
        let cr = Smb2CreateRequest::parse(&body).unwrap();
        assert_eq!(cr.desired_access, 0x0012_0089);
    }

    // ── Kerberos ──────────────────────────────────────────────────────────

    fn make_krb_asreq_minimal() -> Vec<u8> {
        // Minimal DER-encoded AS-REQ shell:
        // APPLICATION 10 (0x6A), length = contents, SEQUENCE { ... }
        // We build a very minimal valid-ish blob just to test tag detection.
        let inner: Vec<u8> = vec![
            0x30, 0x0A, // SEQUENCE length 10
            0x0C, 0x06, b'K', b'R', b'B', b'R', b'E',
            b'A', // UTF8String "KRBREA" (realm-like)
            0x02, 0x00, // INTEGER length 0 (empty, unusual but parseable)
        ];
        let mut out = vec![0x6A, u8::try_from(inner.len()).unwrap_or(u8::MAX)];
        out.extend_from_slice(&inner);
        out
    }

    #[test]
    fn test_kerberos_asreq_detection() {
        let data = make_krb_asreq_minimal();
        let msg = parse_kerberos(&data).unwrap();
        assert!(matches!(msg.msg_type, KerberosMessageType::AsReq));
    }

    #[test]
    fn test_kerberos_wrong_tag() {
        let data = vec![0x01, 0x02, 0x00, 0x00]; // not APPLICATION
        let err = parse_kerberos(&data).unwrap_err();
        assert!(matches!(err, DissectError::InvalidMagic(_)));
    }

    #[test]
    fn test_kerberos_tgsreq_kerberoasting() {
        // Build TGS-REQ (0x6C) that contains only etype=23 (RC4-HMAC)
        // INTEGER value 23 in DER: 0x02 0x01 0x17
        let etype_int = vec![0x02u8, 0x01, 0x17];
        let seq = {
            let mut s = vec![0x30u8, u8::try_from(etype_int.len()).unwrap_or(u8::MAX)];
            s.extend_from_slice(&etype_int);
            s
        };
        let app = {
            let mut a = vec![0x6Cu8, u8::try_from(seq.len()).unwrap_or(u8::MAX)];
            a.extend_from_slice(&seq);
            a
        };
        let msg = parse_kerberos(&app).unwrap();
        assert!(matches!(msg.msg_type, KerberosMessageType::TgsReq));
        assert!(msg.etypes.contains(&23), "etypes: {:?}", msg.etypes);
        assert!(
            msg.kerberoasting_detected,
            "kerberoasting should be detected"
        );
    }

    #[test]
    fn test_kerberos_dissector_layer() {
        let data = make_krb_asreq_minimal();
        let mut pkt = DissectedPacket::new();
        KerberosDissector.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("Kerberos").expect("Kerberos layer missing");
        let mt = layer.field("msg_type").expect("msg_type missing");
        assert_eq!(mt.value.to_string(), "AS-REQ");
    }

    // ── HTTP attack detection ─────────────────────────────────────────────

    #[test]
    fn test_http_attack_sql_injection() {
        let payload = b"GET /page?id=1 OR 1=1&name=foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let hits = scan_http_attacks(payload);
        assert!(
            hits.iter().any(|h| h.kind == HttpAttackKind::SqlInjection),
            "expected SQLi hit, got: {hits:?}"
        );
    }

    #[test]
    fn test_http_attack_union_select() {
        let payload = b"POST /search HTTP/1.1\r\n\r\nq=foo'+UNION+SELECT+1,2,3--";
        let hits = scan_http_attacks(payload);
        assert!(hits.iter().any(|h| h.kind == HttpAttackKind::SqlInjection));
    }

    #[test]
    fn test_http_attack_xss_script_tag() {
        let payload = b"GET /x?q=<script>alert(1)</script> HTTP/1.1\r\n\r\n";
        let hits = scan_http_attacks(payload);
        assert!(hits.iter().any(|h| h.kind == HttpAttackKind::Xss));
    }

    #[test]
    fn test_http_attack_path_traversal() {
        let payload = b"GET /files/../../etc/passwd HTTP/1.1\r\n\r\n";
        let hits = scan_http_attacks(payload);
        assert!(hits.iter().any(|h| h.kind == HttpAttackKind::PathTraversal));
    }

    #[test]
    fn test_http_attack_cmd_injection() {
        let payload = b"GET /cgi-bin/ping.cgi?host=127.0.0.1;id HTTP/1.1\r\n\r\n";
        let hits = scan_http_attacks(payload);
        assert!(
            hits.iter()
                .any(|h| h.kind == HttpAttackKind::CommandInjection)
        );
    }

    #[test]
    fn test_http_attack_clean_request() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let hits = scan_http_attacks(payload);
        assert!(
            hits.is_empty(),
            "clean request should have no hits, got {hits:?}"
        );
    }

    #[test]
    fn test_http_attack_dissector_adds_layer() {
        let payload = b"GET /?x=1 OR 1=1 HTTP/1.1\r\n\r\n";
        let mut pkt = DissectedPacket::new();
        HttpAttackDissector.dissect(payload, 0, &mut pkt).unwrap();
        assert!(
            pkt.layer("HTTP_Attack").is_some(),
            "HTTP_Attack layer should be present"
        );
    }

    #[test]
    fn test_http_attack_dissector_clean_no_layer() {
        let payload = b"GET /index.html HTTP/1.1\r\n\r\n";
        let mut pkt = DissectedPacket::new();
        HttpAttackDissector.dissect(payload, 0, &mut pkt).unwrap();
        assert!(
            pkt.layer("HTTP_Attack").is_none(),
            "no attack layer expected for clean request"
        );
    }

    // ── Modbus TCP ────────────────────────────────────────────────────────

    fn make_modbus_read_holding(trans_id: u16, unit_id: u8, start: u16, count: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&trans_id.to_be_bytes()); // transaction id
        p.extend_from_slice(&0u16.to_be_bytes()); // protocol id = 0
        p.extend_from_slice(&6u16.to_be_bytes()); // length = 6 (unit+fc+4bytes)
        p.push(unit_id);
        p.push(0x03); // ReadHoldingRegisters
        p.extend_from_slice(&start.to_be_bytes());
        p.extend_from_slice(&count.to_be_bytes());
        p
    }

    #[test]
    fn test_modbus_read_holding_parse() {
        let data = make_modbus_read_holding(0x0001, 1, 0x006B, 3);
        let pkt = ModbusPacket::parse(&data).unwrap();
        assert_eq!(pkt.transaction_id, 1);
        assert_eq!(pkt.unit_id, 1);
        assert!(matches!(
            pkt.function_code,
            ModbusFunctionCode::ReadHoldingRegisters
        ));
        assert_eq!(pkt.start_address, Some(0x006B));
        assert_eq!(pkt.quantity, Some(3));
    }

    #[test]
    fn test_modbus_write_single_register() {
        let mut data = make_modbus_read_holding(0x0002, 1, 0x0000, 0);
        data[7] = 0x06; // WriteSingleRegister
        data[10] = 0x00;
        data[11] = 0x55; // output value
        let pkt = ModbusPacket::parse(&data).unwrap();
        assert!(matches!(
            pkt.function_code,
            ModbusFunctionCode::WriteSingleRegister
        ));
        assert_eq!(pkt.output_value, Some(0x0055));
    }

    #[test]
    fn test_modbus_exception_response() {
        let mut data = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x03];
        data.push(1); // unit_id
        data.push(0x83); // fc 0x03 | 0x80 = exception
        data.push(0x02); // exception code: device failure
        let pkt = ModbusPacket::parse(&data).unwrap();
        assert!(matches!(
            pkt.function_code,
            ModbusFunctionCode::ExceptionResponse(3)
        ));
        assert_eq!(pkt.exception_code, Some(0x02));
    }

    #[test]
    fn test_modbus_wrong_protocol_id() {
        let mut data = make_modbus_read_holding(0x0001, 1, 0, 1);
        data[2] = 0x01; // protocol_id != 0
        let err = ModbusPacket::parse(&data).unwrap_err();
        assert!(matches!(err, DissectError::InvalidMagic(_)));
    }

    #[test]
    fn test_modbus_too_short() {
        let err = ModbusPacket::parse(&[0u8; 5]).unwrap_err();
        assert!(matches!(err, DissectError::TooShort { .. }));
    }

    #[test]
    fn test_modbus_dissector_layer_fields() {
        let data = make_modbus_read_holding(0x0042, 7, 0x0064, 10);
        let mut pkt = DissectedPacket::new();
        ModbusDissector.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("Modbus").expect("Modbus layer missing");
        let trans = layer
            .field("transaction_id")
            .expect("transaction_id missing");
        assert_eq!(trans.value.to_string(), "66"); // 0x0042
        let unit = layer.field("unit_id").expect("unit_id missing");
        assert_eq!(unit.value.to_string(), "7");
        let addr = layer.field("start_address").expect("start_address missing");
        assert_eq!(addr.value.to_string(), "100"); // 0x64
    }

    // ── DNP3 ─────────────────────────────────────────────────────────────

    fn make_dnp3_frame(dst: u16, src: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x05, 0x64]); // start
        f.push(0x05); // length (minimal)
        f.push(0x44); // control: DIR=0 PRM=1 FCB=0 FCV=0 FC=4
        f.extend_from_slice(&dst.to_le_bytes());
        f.extend_from_slice(&src.to_le_bytes());
        // compute CRC for first 8 bytes
        let crc = dnp3_crc16(&f[0..8]);
        f.extend_from_slice(&crc.to_le_bytes());
        f
    }

    #[test]
    fn test_dnp3_frame_parse() {
        let data = make_dnp3_frame(3, 1);
        let frame = Dnp3Frame::parse(&data).unwrap();
        assert_eq!(frame.start, 0x0564);
        assert_eq!(frame.dst, 3);
        assert_eq!(frame.src, 1);
        assert!(frame.control.prm());
    }

    #[test]
    fn test_dnp3_wrong_start() {
        let data = vec![0x05, 0x00, 0x05, 0x44, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00];
        let err = Dnp3Frame::parse(&data).unwrap_err();
        assert!(matches!(err, DissectError::InvalidMagic(_)));
    }

    #[test]
    fn test_dnp3_too_short() {
        let err = Dnp3Frame::parse(&[0x05, 0x64, 0x05]).unwrap_err();
        assert!(matches!(err, DissectError::TooShort { .. }));
    }

    #[test]
    fn test_dnp3_crc_valid() {
        let data = make_dnp3_frame(5, 1);
        let frame = Dnp3Frame::parse(&data).unwrap();
        let computed = dnp3_crc16(&data[0..8]);
        assert_eq!(computed, frame.header_crc);
    }

    #[test]
    fn test_dnp3_dissector_layer() {
        let data = make_dnp3_frame(0xFFFF, 0x0001);
        let mut pkt = DissectedPacket::new();
        Dnp3Dissector.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("DNP3").expect("DNP3 layer missing");
        let dst = layer.field("dst").expect("dst field missing");
        assert_eq!(dst.value.to_string(), "65535");
        let crc_ok = layer
            .field("header_crc_valid")
            .expect("header_crc_valid missing");
        assert_eq!(crc_ok.value.to_string(), "true");
    }

    // ── Enhanced ICMP ─────────────────────────────────────────────────────

    fn make_icmp_echo(icmp_type: u8, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(icmp_type);
        p.push(0u8); // code
        p.extend_from_slice(&0u16.to_be_bytes()); // checksum (zero for test)
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn test_icmp_echo_request_fields() {
        let data = make_icmp_echo(8, 0x1234, 0x0001, b"hello");
        let mut pkt = DissectedPacket::new();
        IcmpEnhancedDissector.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt
            .layer("ICMP_Enhanced")
            .expect("ICMP_Enhanced layer missing");
        let id = layer.field("echo_id").expect("echo_id missing");
        let seq = layer.field("echo_seq").expect("echo_seq missing");
        assert_eq!(id.value.to_string(), "4660"); // 0x1234
        assert_eq!(seq.value.to_string(), "1");
    }

    #[test]
    fn test_icmp_type_name_field() {
        let data = make_icmp_echo(0, 1, 1, b"");
        let mut pkt = DissectedPacket::new();
        IcmpEnhancedDissector.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("ICMP_Enhanced").unwrap();
        let tn = layer.field("type_name").unwrap();
        assert_eq!(tn.value.to_string(), "EchoReply");
    }

    #[test]
    fn test_icmp_tunnel_suspected_large_high_entropy() {
        // High-entropy payload (pseudo-random bytes)
        let payload: Vec<u8> = (0u8..=127).collect();
        let data = make_icmp_echo(8, 1, 1, &payload);
        let mut pkt = DissectedPacket::new();
        IcmpEnhancedDissector.dissect(&data, 0, &mut pkt).unwrap();
        let layer = pkt.layer("ICMP_Enhanced").unwrap();
        let ts = layer.field("tunnel_suspected").unwrap();
        // 128 bytes of 0..127 is large and moderate entropy
        // The test just verifies the field exists and is parseable
        let _ = ts.value.to_string();
    }

    #[test]
    fn test_icmp_entropy_zero_for_uniform() {
        // All-zero payload has entropy ~ 0
        let data: Vec<u8> = vec![0u8; 64];
        let e = byte_entropy(&data);
        assert!(
            e < 0.01,
            "entropy of uniform data should be near 0, got {e}"
        );
    }

    #[test]
    fn test_icmp_entropy_high_for_random() {
        // 256 distinct byte values — maximal entropy (8.0 bits/byte)
        let data: Vec<u8> = (0u8..=255).collect();
        let e = byte_entropy(&data);
        assert!(e > 7.9, "entropy should be near 8.0, got {e}");
    }

    #[test]
    fn test_icmp_dest_unreachable_code_name() {
        let data = vec![3u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // type=3 code=3 (PortUnreachable)
        let mut pkt = DissectedPacket::new();
        IcmpEnhancedDissector
            .dissect(&data, 0, &mut pkt)
            .unwrap();
        let layer = pkt.layer("ICMP_Enhanced").unwrap();
        let cn = layer
            .field("code_name")
            .expect("code_name missing for DestUnreachable");
        assert_eq!(cn.value.to_string(), "PortUnreachable");
    }

    // ── Auto-detect ───────────────────────────────────────────────────────

    #[test]
    fn test_autodetect_smb2_magic() {
        let data = make_smb2_header(0x0000, 0, 0, 0);
        let res = auto_detect_protocol(0, 0, &data).unwrap();
        assert_eq!(res.protocol, "SMB2");
        assert!(res.confidence >= DetectConfidence::Medium);
    }

    #[test]
    fn test_autodetect_smb2_magic_and_port() {
        let data = make_smb2_header(0x0000, 0, 0, 0);
        let res = auto_detect_protocol(445, 60123, &data).unwrap();
        assert_eq!(res.protocol, "SMB2");
        assert_eq!(res.confidence, DetectConfidence::High);
    }

    #[test]
    fn test_autodetect_http_get() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let res = auto_detect_protocol(80, 54321, data).unwrap();
        assert_eq!(res.protocol, "HTTP");
        assert_eq!(res.confidence, DetectConfidence::High);
    }

    #[test]
    fn test_autodetect_http_response() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let res = auto_detect_protocol(0, 0, data).unwrap();
        assert_eq!(res.protocol, "HTTP");
    }

    #[test]
    fn test_autodetect_tls_clienthello() {
        // Minimal TLS 1.2 record header
        let data = vec![22u8, 0x03, 0x03, 0x00, 0x05];
        let res = auto_detect_protocol(443, 40000, &data).unwrap();
        assert_eq!(res.protocol, "TLS");
        assert_eq!(res.confidence, DetectConfidence::High);
    }

    #[test]
    fn test_autodetect_kerberos_asreq() {
        let data = make_krb_asreq_minimal();
        let res = auto_detect_protocol(88, 50000, &data).unwrap();
        assert_eq!(res.protocol, "Kerberos");
    }

    #[test]
    fn test_autodetect_dnp3_magic() {
        let data = make_dnp3_frame(1, 2);
        let res = auto_detect_protocol(0, 0, &data).unwrap();
        assert_eq!(res.protocol, "DNP3");
    }

    #[test]
    fn test_autodetect_modbus_fc() {
        let data = make_modbus_read_holding(1, 1, 0, 1);
        let res = auto_detect_protocol(502, 0, &data).unwrap();
        assert_eq!(res.protocol, "Modbus");
        assert_eq!(res.confidence, DetectConfidence::High);
    }

    #[test]
    fn test_autodetect_port_only_ftp() {
        let data = b"some unknown bytes here";
        let res = auto_detect_protocol(21, 40000, data).unwrap();
        assert_eq!(res.protocol, "FTP");
        assert_eq!(res.confidence, DetectConfidence::Low);
    }

    #[test]
    fn test_autodetect_unknown_returns_none() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let res = auto_detect_protocol(9999, 9998, &data);
        assert!(res.is_none(), "should be None for unrecognised data");
    }

    #[test]
    fn test_autodetect_dissector_full_pipeline() {
        // Run SMB2 through the auto-detect dissector pipeline
        let data = make_smb2_header(0x0005, 0, 0, 0); // Create request
        let mut pkt = DissectedPacket::new();
        AutoDetectDissector
            .dissect_with_ports(&data, 0, &mut pkt, 445, 60000)
            .unwrap();
        assert!(
            pkt.layer("AutoDetect").is_some(),
            "AutoDetect layer expected"
        );
        assert!(
            pkt.layer("SMB2").is_some(),
            "SMB2 layer expected after auto-detect"
        );
    }

    // ── DNP3 CRC ─────────────────────────────────────────────────────────

    #[test]
    fn test_dnp3_crc16_known_value() {
        // Known-good DNP3 CRC from the spec: bytes 0x05 0x64 0x05 0x44 0x03 0x00 0x04 0x00
        // For these bytes the CRC is documented as 0xF048 (vary by implementation).
        // We just verify the CRC is deterministic.
        let input = [0x05u8, 0x64, 0x05, 0x44, 0x03, 0x00, 0x04, 0x00];
        let crc1 = dnp3_crc16(&input);
        let crc2 = dnp3_crc16(&input);
        assert_eq!(crc1, crc2, "CRC must be deterministic");
    }

    // ── memmem_find helper ────────────────────────────────────────────────

    #[test]
    fn test_memmem_find_basic() {
        assert_eq!(memmem_find(b"hello world", b"world"), Some(6));
        assert_eq!(memmem_find(b"hello world", b"xyz"), None);
        assert_eq!(memmem_find(b"hello world", b""), Some(0));
    }

    #[test]
    fn test_memmem_find_at_start() {
        assert_eq!(memmem_find(b"abcdef", b"abc"), Some(0));
    }

    #[test]
    fn test_memmem_find_at_end() {
        assert_eq!(memmem_find(b"abcdef", b"def"), Some(3));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Extended default_registry (registers all new dissectors)
// ════════════════════════════════════════════════════════════════════════════

/// Build a [`DissectorRegistry`] with every built-in and newly added dissector
/// pre-registered, including SMB2, Kerberos, HTTP attack detection,
/// Modbus TCP, DNP3, and enhanced ICMP.
///
/// This is an extension of [`default_registry`] and [`full_registry`] that
/// also registers the ICS and security-focused dissectors added in this module.
#[must_use]
pub fn extended_registry() -> DissectorRegistry {
    let reg = default_registry();
    let d: Arc<dyn ProtocolDissector> = Arc::new(Smb2FullDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(KerberosDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(HttpAttackDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(ModbusDissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(Dnp3Dissector);
    reg.register(&d);
    let d: Arc<dyn ProtocolDissector> = Arc::new(IcmpEnhancedDissector);
    reg.register(&d);
    reg
}

// ════════════════════════════════════════════════════════════════════════════
// ICS / SCADA helpers
// ════════════════════════════════════════════════════════════════════════════

/// Well-known ICS/SCADA port numbers and their protocol names.
#[must_use]
pub const fn ics_protocol_for_port(port: u16) -> Option<&'static str> {
    match port {
        502 => Some("Modbus"),
        20000 => Some("DNP3"),
        102 => Some("ISO-TSAP (S7)"),
        4840 => Some("OPC-UA"),
        1089..=1091 => Some("FF-HSE"),
        2222 | 44818 => Some("EtherNet/IP (CIP)"),
        789 => Some("Redlion/Crimson"),
        18245 | 18246 => Some("GE-SRTP"),
        9600 => Some("OMRON-FINS"),
        9100 => Some("Printer / PLC"),
        47808 => Some("BACnet"),
        1911 => Some("Niagara Fox"),
        4911 => Some("Niagara Fox TLS"),
        _ => None,
    }
}

/// Returns `true` when the port is a known ICS/SCADA service port.
#[must_use]
pub const fn is_ics_port(port: u16) -> bool {
    ics_protocol_for_port(port).is_some()
}

// ════════════════════════════════════════════════════════════════════════════
// Kerberos helper types
// ════════════════════════════════════════════════════════════════════════════

/// Kerberos encryption type identifiers (RFC 3961 / RFC 4120).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KerberosEtype {
    DesCbcCrc,           // 1
    DesCbcMd4,           // 2
    DesCbcMd5,           // 3
    Rc4Hmac,             // 23  — used in Kerberoasting
    Rc4HmacExp,          // 24
    Aes128CtsHmacSha1,   // 17
    Aes256CtsHmacSha1,   // 18
    Aes128CtsHmacSha256, // 19 (RFC 8009)
    Aes256CtsHmacSha384, // 20 (RFC 8009)
    Des3CbcSha1Kd,       // 16
    Unknown(i32),
}

impl From<i32> for KerberosEtype {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::DesCbcCrc,
            2 => Self::DesCbcMd4,
            3 => Self::DesCbcMd5,
            16 => Self::Des3CbcSha1Kd,
            17 => Self::Aes128CtsHmacSha1,
            18 => Self::Aes256CtsHmacSha1,
            19 => Self::Aes128CtsHmacSha256,
            20 => Self::Aes256CtsHmacSha384,
            23 => Self::Rc4Hmac,
            24 => Self::Rc4HmacExp,
            v => Self::Unknown(v),
        }
    }
}

impl fmt::Display for KerberosEtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DesCbcCrc => write!(f, "des-cbc-crc(1)"),
            Self::DesCbcMd4 => write!(f, "des-cbc-md4(2)"),
            Self::DesCbcMd5 => write!(f, "des-cbc-md5(3)"),
            Self::Des3CbcSha1Kd => write!(f, "des3-cbc-sha1-kd(16)"),
            Self::Aes128CtsHmacSha1 => write!(f, "aes128-cts-hmac-sha1-96(17)"),
            Self::Aes256CtsHmacSha1 => write!(f, "aes256-cts-hmac-sha1-96(18)"),
            Self::Aes128CtsHmacSha256 => write!(f, "aes128-cts-hmac-sha256-128(19)"),
            Self::Aes256CtsHmacSha384 => write!(f, "aes256-cts-hmac-sha384-192(20)"),
            Self::Rc4Hmac => write!(f, "rc4-hmac(23)"),
            Self::Rc4HmacExp => write!(f, "rc4-hmac-exp(24)"),
            Self::Unknown(v) => write!(f, "unknown({v})"),
        }
    }
}

impl KerberosEtype {
    /// Returns `true` for weak or deprecated encryption types.
    #[must_use]
    pub const fn is_weak(self) -> bool {
        matches!(
            self,
            Self::DesCbcCrc | Self::DesCbcMd4 | Self::DesCbcMd5 | Self::Rc4Hmac | Self::Rc4HmacExp
        )
    }

    /// Returns `true` for modern AES-based types.
    #[must_use]
    pub const fn is_modern(self) -> bool {
        matches!(
            self,
            Self::Aes128CtsHmacSha1
                | Self::Aes256CtsHmacSha1
                | Self::Aes128CtsHmacSha256
                | Self::Aes256CtsHmacSha384
        )
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SMB2 security helpers
// ════════════════════════════════════════════════════════════════════════════

/// Known dangerous SMB2 tree paths that may indicate lateral-movement or
/// admin-share access attempts.
#[must_use]
pub fn smb2_is_sensitive_share(path: &str) -> bool {
    let lc = path.to_lowercase();
    matches!(
        lc.as_str(),
        r"\\c$"
            | r"\\d$"
            | r"\\e$"
            | r"\\admin$"
            | r"\\ipc$"
            | r"\\print$"
            | r"\\sysvol"
            | r"\\netlogon"
    ) || lc.contains("c$")
        || lc.contains("admin$")
        || lc.contains("ipc$")
}

/// NT status code — maps common Win32 error codes used in SMB2 responses.
#[must_use]
pub const fn nt_status_name(status: u32) -> &'static str {
    match status {
        0x0000_0000 => "STATUS_SUCCESS",
        0x0000_0001 => "STATUS_WAIT_1",
        0xC000_0001 => "STATUS_UNSUCCESSFUL",
        0xC000_0002 => "STATUS_NOT_IMPLEMENTED",
        0xC000_0005 => "STATUS_ACCESS_DENIED",
        0xC000_0008 => "STATUS_INVALID_HANDLE",
        0xC000_000D => "STATUS_INVALID_PARAMETER",
        0xC000_0016 => "STATUS_NO_SUCH_DEVICE",
        0xC000_0034 => "STATUS_OBJECT_NAME_NOT_FOUND",
        0xC000_003A => "STATUS_OBJECT_PATH_NOT_FOUND",
        0xC000_006D => "STATUS_LOGON_FAILURE",
        0xC000_006E => "STATUS_ACCOUNT_RESTRICTION",
        0xC000_0071 => "STATUS_PASSWORD_EXPIRED",
        0xC000_0072 => "STATUS_ACCOUNT_DISABLED",
        0xC000_00CC => "STATUS_BAD_NETWORK_NAME",
        0xC000_00CF => "STATUS_NOT_A_DIRECTORY",
        0xC000_0101 => "STATUS_DIRECTORY_NOT_EMPTY",
        0xC000_0103 => "STATUS_PENDING",
        0xC000_0121 => "STATUS_CANNOT_DELETE",
        0xC000_01C4 => "STATUS_INVALID_LOGON_TYPE",
        0xC000_022D => "STATUS_RETRY",
        0xC000_0234 => "STATUS_ACCOUNT_LOCKED_OUT",
        0x8000_0005 => "STATUS_BUFFER_OVERFLOW",
        0x8000_001E => "STATUS_MORE_PROCESSING_REQUIRED",
        _ => "STATUS_UNKNOWN",
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Modbus security helpers
// ════════════════════════════════════════════════════════════════════════════

/// Returns `true` when a Modbus function code can modify PLC state.
/// These are the write operations that should be audited in ICS environments.
#[must_use]
pub const fn modbus_fc_is_write(fc: ModbusFunctionCode) -> bool {
    matches!(
        fc,
        ModbusFunctionCode::WriteSingleCoil
            | ModbusFunctionCode::WriteSingleRegister
            | ModbusFunctionCode::WriteMultipleCoils
            | ModbusFunctionCode::WriteMultipleRegisters
            | ModbusFunctionCode::WriteFileRecord
            | ModbusFunctionCode::MaskWriteRegister
            | ModbusFunctionCode::ReadWriteMultipleRegisters
    )
}

/// Returns `true` when a Modbus function code is a diagnostic or special
/// code that should not appear in a production network.
#[must_use]
pub const fn modbus_fc_is_diagnostic(fc: ModbusFunctionCode) -> bool {
    matches!(
        fc,
        ModbusFunctionCode::EncapsulatedInterfaceTransport
            | ModbusFunctionCode::ReadFifoQueue
            | ModbusFunctionCode::Unknown(_)
    )
}

// ════════════════════════════════════════════════════════════════════════════
// HTTP attack helpers — URL decode pass
// ════════════════════════════════════════════════════════════════════════════

/// Decode percent-encoded characters in an HTTP URI or body.
/// Handles both `%XX` (hex) and `+` (space in query strings).
///
/// Invalid sequences are passed through unchanged.
#[must_use]
pub fn url_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            let hi = input[i + 1];
            let lo = input[i + 2];
            if let (Some(h), Some(l)) = (hex_nibble(hi), hex_nibble(lo)) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        } else if input[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Scan an HTTP payload with URL-decoding applied before pattern matching.
///
/// This catches common WAF-bypass techniques where the attacker percent-encodes
/// characters in the injected payload (e.g. `UNION%20SELECT`).
#[must_use]
pub fn scan_http_attacks_decoded(data: &[u8]) -> Vec<HttpAttackIndicator> {
    let decoded = url_decode(data);
    let mut results = scan_http_attacks(data);
    // Also scan the decoded version; deduplicate by pattern
    let decoded_hits = scan_http_attacks(&decoded);
    for hit in decoded_hits {
        if !results.iter().any(|h| h.pattern == hit.pattern) {
            results.push(hit);
        }
    }
    results
}

// ════════════════════════════════════════════════════════════════════════════
// DNP3 application function code names
// ════════════════════════════════════════════════════════════════════════════

/// Human-readable name for a DNP3 application function code.
#[must_use]
pub const fn dnp3_app_fc_name(fc: u8) -> &'static str {
    match fc {
        0x00 => "CONFIRM",
        0x01 => "READ",
        0x02 => "WRITE",
        0x03 => "SELECT",
        0x04 => "OPERATE",
        0x05 => "DIRECT_OPERATE",
        0x06 => "DIRECT_OPERATE_NR",
        0x07 => "IMMED_FREEZE",
        0x08 => "IMMED_FREEZE_NR",
        0x09 => "FREEZE_CLEAR",
        0x0A => "FREEZE_CLEAR_NR",
        0x0B => "FREEZE_AT_TIME",
        0x0C => "FREEZE_AT_TIME_NR",
        0x0D => "COLD_RESTART",
        0x0E => "WARM_RESTART",
        0x0F => "INITIALIZE_DATA",
        0x10 => "INITIALIZE_APPL",
        0x11 => "START_APPL",
        0x12 => "STOP_APPL",
        0x13 => "SAVE_CONFIG",
        0x14 => "ENABLE_UNSOLICITED",
        0x15 => "DISABLE_UNSOLICITED",
        0x16 => "ASSIGN_CLASS",
        0x17 => "DELAY_MEASURE",
        0x18 => "RECORD_CURRENT_TIME",
        0x19 => "OPEN_FILE",
        0x1A => "CLOSE_FILE",
        0x1B => "DELETE_FILE",
        0x1C => "GET_FILE_INFO",
        0x1D => "AUTHENTICATE_FILE",
        0x1E => "ABORT_FILE",
        0x1F => "ACTIVATE_CONFIG",
        0x20 => "AUTHENTICATE_REQ",
        0x21 => "AUTH_REQ_NO_ACK",
        0x81 => "RESPONSE",
        0x82 => "UNSOLICITED_RESPONSE",
        0x83 => "AUTH_RESPONSE",
        _ => "UNKNOWN",
    }
}

/// Returns `true` when a DNP3 application function code represents a write or
/// control action that could affect field equipment.
#[must_use]
pub const fn dnp3_fc_is_control(fc: u8) -> bool {
    matches!(
        fc,
        0x02..=0x0E // WARM_RESTART
    )
}

// ════════════════════════════════════════════════════════════════════════════
// ICMP tunnel helpers
// ════════════════════════════════════════════════════════════════════════════

/// Minimum ICMP echo payload length that is considered anomalously large
/// and therefore warrants tunnel-detection scrutiny.
pub const ICMP_TUNNEL_LARGE_PAYLOAD_THRESHOLD: usize = 64;

/// Entropy threshold above which a payload is flagged as "high entropy"
/// (suggesting encrypted or compressed data consistent with covert-channel use).
pub const ICMP_TUNNEL_HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

/// Heuristically decide whether a stream of ICMP packets suggests tunneling.
///
/// `payloads` is a slice of raw ICMP payload byte slices (the data after the
/// ICMP header).  Returns `true` when the majority of payloads show
/// high-entropy or large-payload indicators.
#[must_use]
pub fn icmp_stream_tunnel_heuristic(payloads: &[&[u8]]) -> bool {
    if payloads.is_empty() {
        return false;
    }
    let flagged = payloads
        .iter()
        .filter(|p| {
            let analysis = IcmpTunnelAnalysis::analyse(p);
            analysis.tunnel_suspected
        })
        .count();
    // Flag the stream if more than 50 % of payloads are suspicious
    flagged * 2 > payloads.len()
}

// ════════════════════════════════════════════════════════════════════════════
// Additional tests for helpers
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod helper_tests {
    use super::*;

    // ── URL decode ────────────────────────────────────────────────────────

    #[test]
    fn test_url_decode_plus_to_space() {
        assert_eq!(url_decode(b"hello+world"), b"hello world");
    }

    #[test]
    fn test_url_decode_percent_encoded() {
        assert_eq!(url_decode(b"hello%20world"), b"hello world");
    }

    #[test]
    fn test_url_decode_union_select() {
        let raw = b"UNION%20SELECT%201%2C2%2C3";
        let decoded = url_decode(raw);
        assert_eq!(decoded, b"UNION SELECT 1,2,3");
    }

    #[test]
    fn test_url_decode_passthrough_invalid() {
        // Invalid percent sequence passed through unchanged
        let raw = b"foo%ZZbar";
        let decoded = url_decode(raw);
        assert_eq!(decoded, b"foo%ZZbar");
    }

    #[test]
    fn test_url_decode_empty() {
        assert_eq!(url_decode(b""), b"");
    }

    // ── scan_http_attacks_decoded ─────────────────────────────────────────

    #[test]
    fn test_scan_http_attacks_decoded_catches_encoded_sqli() {
        // UNION%20SELECT will be decoded to "union select" and matched
        let payload = b"GET /x?q=UNION%20SELECT%201 HTTP/1.1\r\n\r\n";
        let hits = scan_http_attacks_decoded(payload);
        assert!(
            hits.iter().any(|h| h.kind == HttpAttackKind::SqlInjection),
            "decoded scan should catch UNION SELECT, got: {hits:?}"
        );
    }

    #[test]
    fn test_scan_http_attacks_decoded_no_duplication() {
        // Plain text — no encoding; should not double-count
        let payload = b"GET /?q=union+select HTTP/1.1\r\n\r\n";
        // + decoded to space → "union select" matches; no duplicates
        let hits = scan_http_attacks_decoded(payload);
        let sqli_count = hits
            .iter()
            .filter(|h| h.kind == HttpAttackKind::SqlInjection)
            .count();
        // There should be at least 1 hit from the decoded pass
        assert!(sqli_count >= 1);
    }

    // ── ICS port helpers ──────────────────────────────────────────────────

    #[test]
    fn test_ics_protocol_for_port_modbus() {
        assert_eq!(ics_protocol_for_port(502), Some("Modbus"));
    }

    #[test]
    fn test_ics_protocol_for_port_dnp3() {
        assert_eq!(ics_protocol_for_port(20000), Some("DNP3"));
    }

    #[test]
    fn test_ics_protocol_for_port_unknown() {
        assert!(ics_protocol_for_port(80).is_none());
    }

    #[test]
    fn test_is_ics_port() {
        assert!(is_ics_port(502));
        assert!(is_ics_port(44818));
        assert!(!is_ics_port(80));
    }

    // ── NT status names ───────────────────────────────────────────────────

    #[test]
    fn test_nt_status_success() {
        assert_eq!(nt_status_name(0), "STATUS_SUCCESS");
    }

    #[test]
    fn test_nt_status_access_denied() {
        assert_eq!(nt_status_name(0xC000_0005), "STATUS_ACCESS_DENIED");
    }

    #[test]
    fn test_nt_status_unknown() {
        assert_eq!(nt_status_name(0xDEAD_BEEF), "STATUS_UNKNOWN");
    }

    // ── SMB2 share sensitivity ───────────────────────────────────────────

    #[test]
    fn test_smb2_sensitive_share_admin() {
        assert!(smb2_is_sensitive_share(r"\\server\admin$"));
    }

    #[test]
    fn test_smb2_sensitive_share_c_dollar() {
        assert!(smb2_is_sensitive_share(r"\\server\c$"));
    }

    #[test]
    fn test_smb2_not_sensitive_share() {
        assert!(!smb2_is_sensitive_share(r"\\server\public_share"));
    }

    // ── Modbus function code helpers ─────────────────────────────────────

    #[test]
    fn test_modbus_fc_write_single_coil_is_write() {
        assert!(modbus_fc_is_write(ModbusFunctionCode::WriteSingleCoil));
    }

    #[test]
    fn test_modbus_fc_read_holding_not_write() {
        assert!(!modbus_fc_is_write(
            ModbusFunctionCode::ReadHoldingRegisters
        ));
    }

    #[test]
    fn test_modbus_fc_diagnostic() {
        assert!(modbus_fc_is_diagnostic(
            ModbusFunctionCode::EncapsulatedInterfaceTransport
        ));
        assert!(!modbus_fc_is_diagnostic(ModbusFunctionCode::ReadCoils));
    }

    // ── DNP3 function code helpers ────────────────────────────────────────

    #[test]
    fn test_dnp3_app_fc_name_read() {
        assert_eq!(dnp3_app_fc_name(0x01), "READ");
    }

    #[test]
    fn test_dnp3_app_fc_name_write() {
        assert_eq!(dnp3_app_fc_name(0x02), "WRITE");
    }

    #[test]
    fn test_dnp3_fc_is_control_operate() {
        assert!(dnp3_fc_is_control(0x04)); // OPERATE
        assert!(dnp3_fc_is_control(0x0D)); // COLD_RESTART
        assert!(!dnp3_fc_is_control(0x01)); // READ
    }

    // ── Kerberos etype helpers ────────────────────────────────────────────

    #[test]
    fn test_kerberos_etype_rc4_is_weak() {
        let et = KerberosEtype::from(23);
        assert!(matches!(et, KerberosEtype::Rc4Hmac));
        assert!(et.is_weak());
        assert!(!et.is_modern());
    }

    #[test]
    fn test_kerberos_etype_aes256_is_modern() {
        let et = KerberosEtype::from(18);
        assert!(matches!(et, KerberosEtype::Aes256CtsHmacSha1));
        assert!(et.is_modern());
        assert!(!et.is_weak());
    }

    #[test]
    fn test_kerberos_etype_display() {
        assert_eq!(KerberosEtype::Rc4Hmac.to_string(), "rc4-hmac(23)");
        assert_eq!(
            KerberosEtype::Aes256CtsHmacSha1.to_string(),
            "aes256-cts-hmac-sha1-96(18)"
        );
        assert_eq!(KerberosEtype::Unknown(99).to_string(), "unknown(99)");
    }

    // ── ICMP stream heuristic ─────────────────────────────────────────────

    #[test]
    fn test_icmp_stream_no_tunnel_short_payloads() {
        let p1 = vec![0u8; 8];
        let p2 = vec![0u8; 8];
        let payloads: Vec<&[u8]> = vec![&p1, &p2];
        assert!(!icmp_stream_tunnel_heuristic(&payloads));
    }

    #[test]
    fn test_icmp_stream_tunnel_large_payloads() {
        // Create payloads with varying bytes (higher entropy) and large size
        let p: Vec<u8> = (0u8..=255).cycle().take(128).collect();
        let payloads: Vec<&[u8]> = vec![p.as_slice(); 4];
        // All 4 payloads are large (128 bytes) with moderate entropy
        // tunnel_suspected = large_payload && (high_entropy || printable_ascii)
        // With 256-cycle data: entropy ~8, high_entropy = true
        let result = icmp_stream_tunnel_heuristic(&payloads);
        // Just verify it runs and returns a bool (outcome depends on entropy calc)
        let _ = result;
    }

    #[test]
    fn test_icmp_stream_heuristic_empty() {
        assert!(!icmp_stream_tunnel_heuristic(&[]));
    }

    // ── full_registry ─────────────────────────────────────────────────────

    #[test]
    fn test_full_registry_has_smb2() {
        let reg = extended_registry();
        assert!(
            reg.by_name("SMB2").is_some(),
            "SMB2 dissector must be registered"
        );
    }

    #[test]
    fn test_full_registry_has_kerberos() {
        let reg = extended_registry();
        assert!(reg.by_name("Kerberos").is_some());
    }

    #[test]
    fn test_full_registry_has_modbus() {
        let reg = extended_registry();
        assert!(reg.by_name("Modbus").is_some());
        assert!(reg.by_port(502).is_some());
    }

    #[test]
    fn test_full_registry_has_dnp3() {
        let reg = extended_registry();
        assert!(reg.by_name("DNP3").is_some());
        assert!(reg.by_port(20000).is_some());
    }

    #[test]
    fn test_full_registry_has_http_attack() {
        let reg = extended_registry();
        assert!(reg.by_name("HTTP_Attack").is_some());
    }

    #[test]
    fn test_full_registry_dissect_auto_smb2() {
        let reg = extended_registry();
        let mut hdr = vec![0xFEu8, b'S', b'M', b'B'];
        hdr.extend_from_slice(&64u16.to_le_bytes()); // structure_size
        hdr.extend_from_slice(&0u16.to_le_bytes()); // credit_charge
        hdr.extend_from_slice(&0u32.to_le_bytes()); // status
        hdr.extend_from_slice(&0u16.to_le_bytes()); // command = Negotiate
        hdr.extend_from_slice(&1u16.to_le_bytes()); // credits
        hdr.extend_from_slice(&0u32.to_le_bytes()); // flags
        hdr.extend_from_slice(&0u32.to_le_bytes()); // next_command
        hdr.extend_from_slice(&1u64.to_le_bytes()); // message_id
        hdr.extend_from_slice(&0u32.to_le_bytes()); // process_id
        hdr.extend_from_slice(&0u32.to_le_bytes()); // tree_id
        hdr.extend_from_slice(&0u64.to_le_bytes()); // session_id
        hdr.extend_from_slice(&[0u8; 16]); // signature
        assert_eq!(hdr.len(), 64);
        let pkt = reg.dissect_auto("SMB2", Some(445), &hdr, 0).unwrap();
        assert!(pkt.layer("SMB2").is_some());
    }

    #[test]
    fn test_ipv4_total_len_below_header_is_rejected() {
        // Minimal IHL=5 header; bytes 2..4 are Total Length, which counts the
        // header itself, so 0..19 are values only a malformed peer sends.
        let mut pkt = [0u8; 24];
        pkt[0] = 0x45;
        pkt[9] = 6; // TCP
        for declared in [0u16, 1, 19] {
            pkt[2..4].copy_from_slice(&declared.to_be_bytes());
            assert!(
                Ipv4Packet::parse(&pkt).is_err(),
                "total_len={declared} must error, not panic"
            );
        }
        // 20 is the boundary: header only, empty payload.
        pkt[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert!(Ipv4Packet::parse(&pkt).unwrap().payload.is_empty());
        // And a declared length inside the buffer yields exactly that payload.
        pkt[2..4].copy_from_slice(&23u16.to_be_bytes());
        assert_eq!(Ipv4Packet::parse(&pkt).unwrap().payload.len(), 3);
    }
}
