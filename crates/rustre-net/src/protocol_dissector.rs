//! `protocol_dissector` — Protocol dissector framework.
//!
//! Provides `Dissector` trait, `DissectionResult`, `ProtocolStack`,
//! `FieldDef`, `DissectionTree`, `WiresharkCompatOutput`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from dissection.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DissectionError {
    #[error("buffer too short: need {need}, got {got}")]
    TooShort { need: usize, got: usize },
    #[error("invalid checksum")]
    InvalidChecksum,
    #[error("unknown protocol: 0x{0:04x}")]
    UnknownProtocol(u16),
    #[error("field '{0}' not found")]
    FieldNotFound(String),
    #[error("dissector not registered: '{0}'")]
    NotRegistered(String),
    #[error("recursion limit exceeded")]
    RecursionLimit,
    #[error("parse error: {0}")]
    Parse(String),
}

// ─── FieldType ────────────────────────────────────────────────────────────────

/// Type of a dissected field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    U8, U16Be, U16Le, U32Be, U32Le, U64Be, U64Le,
    I8, I16Be, I32Be, I64Be,
    Bytes, Ipv4, Ipv6, MacAddr, Bool, Flags, Ascii, Utf16,
    Enum8, Enum16, Enum32,
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::U8 => "uint8", Self::U16Be => "uint16be", Self::U16Le => "uint16le",
            Self::U32Be => "uint32be", Self::U32Le => "uint32le",
            Self::U64Be => "uint64be", Self::U64Le => "uint64le",
            Self::I8 => "int8", Self::I16Be => "int16be", Self::I32Be => "int32be", Self::I64Be => "int64be",
            Self::Bytes => "bytes", Self::Ipv4 => "ipv4", Self::Ipv6 => "ipv6",
            Self::MacAddr => "mac_addr", Self::Bool => "bool",
            Self::Flags => "flags", Self::Ascii => "ascii", Self::Utf16 => "utf16",
            Self::Enum8 => "enum8", Self::Enum16 => "enum16", Self::Enum32 => "enum32",
        };
        f.write_str(s)
    }
}

// ─── FieldValue ───────────────────────────────────────────────────────────────

/// The decoded value of a field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldValue {
    Uint(u64),
    Int(i64),
    Bytes(Vec<u8>),
    String(String),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    MacAddr([u8; 6]),
    Bool(bool),
    Null,
}

impl FieldValue {
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        if let Self::Uint(v) = self { Some(*v) } else { None }
    }
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self { Some(s.as_str()) } else { None }
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uint(v) => write!(f, "{v}"),
            Self::Int(v) => write!(f, "{v}"),
            Self::Bytes(b) => write!(f, "{} bytes", b.len()),
            Self::String(s) => write!(f, "{s}"),
            Self::Ipv4(a) => write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Self::Ipv6(a) => {
                let words: Vec<String> = a.chunks(2)
                    .map(|w| format!("{:02x}{:02x}", w[0], w[1]))
                    .collect();
                write!(f, "{}", words.join(":"))
            }
            Self::MacAddr(m) => write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5]),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Null => write!(f, "null"),
        }
    }
}

// ─── FieldDef ─────────────────────────────────────────────────────────────────

/// Definition of a protocol field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    /// Machine-readable field name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Byte offset from the start of the protocol header.
    pub offset: usize,
    /// Size in bytes.
    pub size: usize,
    /// Field type.
    pub field_type: FieldType,
    /// Optional decoded value.
    pub value: Option<FieldValue>,
    /// Bitfield mask (0 = not a bitfield).
    pub bitmask: u64,
}

impl FieldDef {
    /// Create a new field definition.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        offset: usize,
        size: usize,
        field_type: FieldType,
    ) -> Self {
        Self {
            name: name.into(), description: description.into(),
            offset, size, field_type, value: None, bitmask: 0,
        }
    }

    /// Builder: set value.
    #[must_use]
    pub fn with_value(mut self, v: FieldValue) -> Self { self.value = Some(v); self }

    /// Builder: set bitmask.
    #[must_use]
    pub const fn with_bitmask(mut self, mask: u64) -> Self { self.bitmask = mask; self }

    /// Return `true` if this is a bitfield.
    #[must_use]
    pub const fn is_bitfield(&self) -> bool { self.bitmask != 0 }

    /// Decode the field from `data` (starting at `offset`).
    ///
    /// # Errors
    /// Returns `DissectionError::TooShort` if the buffer is too short.
    pub fn decode(&self, data: &[u8]) -> Result<FieldValue, DissectionError> {
        let end = self.offset + self.size;
        if end > data.len() {
            return Err(DissectionError::TooShort { need: end, got: data.len() });
        }
        let slice = &data[self.offset..end];
        let value = match self.field_type {
            FieldType::U8 | FieldType::Enum8 => FieldValue::Uint(u64::from(slice[0])),
            FieldType::U16Be | FieldType::Enum16 => FieldValue::Uint(u64::from(u16::from_be_bytes([slice[0], slice[1]]))),
            FieldType::U16Le => FieldValue::Uint(u64::from(u16::from_le_bytes([slice[0], slice[1]]))),
            FieldType::U32Be | FieldType::Enum32 => FieldValue::Uint(u64::from(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))),
            FieldType::U32Le => FieldValue::Uint(u64::from(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))),
            FieldType::U64Be => FieldValue::Uint(u64::from_be_bytes(slice.try_into().unwrap_or([0; 8]))),
            FieldType::U64Le => FieldValue::Uint(u64::from_le_bytes(slice.try_into().unwrap_or([0; 8]))),
            FieldType::I8 => FieldValue::Int(i64::from(i8::from_ne_bytes([slice[0]]))),
            FieldType::I16Be => FieldValue::Int(i64::from(i16::from_be_bytes([slice[0], slice[1]]))),
            FieldType::I32Be => FieldValue::Int(i64::from(i32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))),
            FieldType::I64Be => FieldValue::Int(i64::from_be_bytes(slice.try_into().unwrap_or([0; 8]))),
            FieldType::Bool => FieldValue::Bool(slice[0] != 0),
            FieldType::Ipv4 => FieldValue::Ipv4([slice[0], slice[1], slice[2], slice[3]]),
            FieldType::Ipv6 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&slice[..16]);
                FieldValue::Ipv6(a)
            }
            FieldType::MacAddr => {
                FieldValue::MacAddr([slice[0], slice[1], slice[2], slice[3], slice[4], slice[5]])
            }
            FieldType::Ascii | FieldType::Utf16 => {
                let s = String::from_utf8_lossy(slice).into_owned();
                FieldValue::String(s.trim_end_matches('\0').to_string())
            }
            FieldType::Flags => {
                let v = match self.size {
                    1 => u64::from(slice[0]),
                    2 => u64::from(u16::from_be_bytes([slice[0], slice[1]])),
                    4 => u64::from(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])),
                    8 => u64::from_be_bytes(slice.try_into().unwrap_or([0; 8])),
                    _ => 0,
                };
                FieldValue::Uint(v)
            }
            FieldType::Bytes => FieldValue::Bytes(slice.to_vec()),
        };
        // Apply bitmask if set
        if self.bitmask != 0
            && let FieldValue::Uint(v) = value {
                return Ok(FieldValue::Uint(v & self.bitmask));
            }
        Ok(value)
    }
}

impl fmt::Display for FieldDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(v) = &self.value {
            write!(f, "{}: {v} ({})", self.name, self.field_type)
        } else {
            write!(f, "{}: <not decoded> ({})", self.name, self.field_type)
        }
    }
}

// ─── DissectionResult ─────────────────────────────────────────────────────────

/// Result of dissecting one protocol layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissectionResult {
    /// Protocol name (e.g. `"Ethernet"`, `"IPv4"`).
    pub protocol: String,
    /// Decoded fields.
    pub fields: Vec<FieldDef>,
    /// The protocol type of the encapsulated payload (0 = none).
    pub next_protocol: u16,
    /// The payload bytes (after the header).
    pub payload: Vec<u8>,
    /// Total header size consumed.
    pub header_size: usize,
    /// Whether the dissection was complete.
    pub complete: bool,
    /// Optional human-readable summary.
    pub summary: String,
}

impl DissectionResult {
    /// Create an empty dissection result.
    #[must_use]
    pub fn new(protocol: impl Into<String>) -> Self {
        Self {
            protocol: protocol.into(), fields: vec![], next_protocol: 0,
            payload: vec![], header_size: 0, complete: false, summary: String::new(),
        }
    }

    /// Add a decoded field.
    pub fn add_field(&mut self, field: FieldDef) { self.fields.push(field); }

    /// Look up a field by name.
    #[must_use]
    pub fn get_field(&self, name: &str) -> Option<&FieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Get the value of a named field.
    #[must_use]
    pub fn get_value(&self, name: &str) -> Option<&FieldValue> {
        self.get_field(name).and_then(|f| f.value.as_ref())
    }

    /// Get a u64 field value.
    #[must_use]
    pub fn get_u64(&self, name: &str) -> Option<u64> {
        self.get_value(name).and_then(FieldValue::as_u64)
    }

    /// Return `true` if the protocol has a payload.
    #[must_use]
    pub const fn has_payload(&self) -> bool { !self.payload.is_empty() }
}

impl fmt::Display for DissectionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} fields, payload={}, next=0x{:04x}",
               self.protocol, self.fields.len(), self.payload.len(), self.next_protocol)
    }
}

// ─── Dissector trait ──────────────────────────────────────────────────────────

/// A protocol dissector.
pub trait Dissector: Send + Sync {
    /// Protocol name.
    fn name(&self) -> &'static str;

    /// `EtherType` / protocol number this dissector handles (0 = any / unspecified).
    fn proto_id(&self) -> u16 { 0 }

    /// Dissect `data` into fields and return the result.
    ///
    /// # Errors
    /// Returns `DissectionError` on parse failure.
    fn dissect(&self, data: &[u8]) -> Result<DissectionResult, DissectionError>;
}

// ─── Built-in dissectors ──────────────────────────────────────────────────────

/// Ethernet II dissector.
pub struct EthernetDissector;

impl Dissector for EthernetDissector {
    fn name(&self) -> &'static str { "Ethernet" }
    fn proto_id(&self) -> u16 { 1 } // DLT_EN10MB
    fn dissect(&self, data: &[u8]) -> Result<DissectionResult, DissectionError> {
        if data.len() < 14 {
            return Err(DissectionError::TooShort { need: 14, got: data.len() });
        }
        let mut r = DissectionResult::new("Ethernet");
        r.add_field(
            FieldDef::new("dst_mac", "Destination MAC", 0, 6, FieldType::MacAddr)
                .with_value(FieldValue::MacAddr([data[0], data[1], data[2], data[3], data[4], data[5]])),
        );
        r.add_field(
            FieldDef::new("src_mac", "Source MAC", 6, 6, FieldType::MacAddr)
                .with_value(FieldValue::MacAddr([data[6], data[7], data[8], data[9], data[10], data[11]])),
        );
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        r.add_field(
            FieldDef::new("ethertype", "EtherType", 12, 2, FieldType::U16Be)
                .with_value(FieldValue::Uint(u64::from(ethertype))),
        );
        r.next_protocol = ethertype;
        r.header_size = 14;
        r.payload = data[14..].to_vec();
        r.complete = true;
        r.summary = format!("Ethernet ethertype=0x{ethertype:04x}");
        Ok(r)
    }
}

/// IPv4 dissector.
pub struct Ipv4Dissector;

impl Dissector for Ipv4Dissector {
    fn name(&self) -> &'static str { "IPv4" }
    fn proto_id(&self) -> u16 { 0x0800 }
    fn dissect(&self, data: &[u8]) -> Result<DissectionResult, DissectionError> {
        if data.len() < 20 {
            return Err(DissectionError::TooShort { need: 20, got: data.len() });
        }
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if ihl < 20 || ihl > data.len() {
            return Err(DissectionError::TooShort { need: ihl, got: data.len() });
        }
        let mut r = DissectionResult::new("IPv4");
        r.add_field(FieldDef::new("version", "IP Version", 0, 1, FieldType::U8).with_value(FieldValue::Uint(u64::from(data[0] >> 4))));
        r.add_field(FieldDef::new("ihl", "Header Length", 0, 1, FieldType::U8).with_value(FieldValue::Uint(ihl as u64)));
        r.add_field(FieldDef::new("dscp", "DSCP", 1, 1, FieldType::U8).with_value(FieldValue::Uint(u64::from(data[1] >> 2))));
        r.add_field(FieldDef::new("total_length", "Total Length", 2, 2, FieldType::U16Be).with_value(FieldValue::Uint(u64::from(u16::from_be_bytes([data[2], data[3]])))));
        r.add_field(FieldDef::new("identification", "Identification", 4, 2, FieldType::U16Be).with_value(FieldValue::Uint(u64::from(u16::from_be_bytes([data[4], data[5]])))));
        r.add_field(FieldDef::new("ttl", "TTL", 8, 1, FieldType::U8).with_value(FieldValue::Uint(u64::from(data[8]))));
        r.add_field(FieldDef::new("protocol", "Protocol", 9, 1, FieldType::U8).with_value(FieldValue::Uint(u64::from(data[9]))));
        r.add_field(FieldDef::new("checksum", "Header Checksum", 10, 2, FieldType::U16Be).with_value(FieldValue::Uint(u64::from(u16::from_be_bytes([data[10], data[11]])))));
        r.add_field(FieldDef::new("src_ip", "Source IP", 12, 4, FieldType::Ipv4).with_value(FieldValue::Ipv4([data[12], data[13], data[14], data[15]])));
        r.add_field(FieldDef::new("dst_ip", "Destination IP", 16, 4, FieldType::Ipv4).with_value(FieldValue::Ipv4([data[16], data[17], data[18], data[19]])));
        r.next_protocol = u16::from(data[9]);
        r.header_size = ihl;
        r.payload = data[ihl..].to_vec();
        r.complete = true;
        r.summary = format!("IPv4 proto={} src={}.{}.{}.{} dst={}.{}.{}.{}", data[9], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19]);
        Ok(r)
    }
}

/// TCP dissector.
pub struct TcpDissector;

impl Dissector for TcpDissector {
    fn name(&self) -> &'static str { "TCP" }
    fn proto_id(&self) -> u16 { 6 }
    fn dissect(&self, data: &[u8]) -> Result<DissectionResult, DissectionError> {
        if data.len() < 20 {
            return Err(DissectionError::TooShort { need: 20, got: data.len() });
        }
        let data_offset = ((data[12] >> 4) as usize) * 4;
        let mut r = DissectionResult::new("TCP");
        r.add_field(FieldDef::new("src_port", "Source Port", 0, 2, FieldType::U16Be).with_value(FieldValue::Uint(u64::from(u16::from_be_bytes([data[0], data[1]])))));
        r.add_field(FieldDef::new("dst_port", "Destination Port", 2, 2, FieldType::U16Be).with_value(FieldValue::Uint(u64::from(u16::from_be_bytes([data[2], data[3]])))));
        r.add_field(FieldDef::new("seq_num", "Sequence Number", 4, 4, FieldType::U32Be).with_value(FieldValue::Uint(u64::from(u32::from_be_bytes([data[4], data[5], data[6], data[7]])))));
        r.add_field(FieldDef::new("ack_num", "Acknowledgement Number", 8, 4, FieldType::U32Be).with_value(FieldValue::Uint(u64::from(u32::from_be_bytes([data[8], data[9], data[10], data[11]])))));
        r.add_field(FieldDef::new("flags", "Flags", 13, 1, FieldType::Flags).with_value(FieldValue::Uint(u64::from(data[13]))));
        r.add_field(FieldDef::new("window", "Window Size", 14, 2, FieldType::U16Be).with_value(FieldValue::Uint(u64::from(u16::from_be_bytes([data[14], data[15]])))));
        r.next_protocol = u16::from_be_bytes([data[2], data[3]]); // dst port as next
        r.header_size = data_offset;
        r.payload = if data_offset < data.len() { data[data_offset..].to_vec() } else { vec![] };
        r.complete = true;
        let flags = data[13];
        let flag_str: Vec<&str> = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
            .iter().enumerate()
            .filter(|(i, _)| (flags >> i) & 1 == 1)
            .map(|(_, n)| *n)
            .collect();
        r.summary = format!("TCP {}->{} [{}]", u16::from_be_bytes([data[0], data[1]]), u16::from_be_bytes([data[2], data[3]]), flag_str.join(","));
        Ok(r)
    }
}

/// UDP dissector.
pub struct UdpDissector;

impl Dissector for UdpDissector {
    fn name(&self) -> &'static str { "UDP" }
    fn proto_id(&self) -> u16 { 17 }
    fn dissect(&self, data: &[u8]) -> Result<DissectionResult, DissectionError> {
        if data.len() < 8 {
            return Err(DissectionError::TooShort { need: 8, got: data.len() });
        }
        let mut r = DissectionResult::new("UDP");
        r.add_field(FieldDef::new("src_port", "Source Port", 0, 2, FieldType::U16Be).with_value(FieldValue::Uint(u64::from(u16::from_be_bytes([data[0], data[1]])))));
        r.add_field(FieldDef::new("dst_port", "Destination Port", 2, 2, FieldType::U16Be).with_value(FieldValue::Uint(u64::from(u16::from_be_bytes([data[2], data[3]])))));
        r.add_field(FieldDef::new("length", "Length", 4, 2, FieldType::U16Be).with_value(FieldValue::Uint(u64::from(u16::from_be_bytes([data[4], data[5]])))));
        r.add_field(FieldDef::new("checksum", "Checksum", 6, 2, FieldType::U16Be).with_value(FieldValue::Uint(u64::from(u16::from_be_bytes([data[6], data[7]])))));
        r.next_protocol = u16::from_be_bytes([data[2], data[3]]);
        r.header_size = 8;
        r.payload = data[8..].to_vec();
        r.complete = true;
        r.summary = format!("UDP {}→{}", u16::from_be_bytes([data[0], data[1]]), u16::from_be_bytes([data[2], data[3]]));
        Ok(r)
    }
}

/// HTTP (request) dissector — simple heuristic.
pub struct HttpDissector;

impl Dissector for HttpDissector {
    fn name(&self) -> &'static str { "HTTP" }
    fn proto_id(&self) -> u16 { 80 }
    fn dissect(&self, data: &[u8]) -> Result<DissectionResult, DissectionError> {
        let text = std::str::from_utf8(data).map_err(|_| DissectionError::Parse("not UTF-8".into()))?;
        let mut r = DissectionResult::new("HTTP");
        let header_end = text.find("\r\n\r\n").map_or(data.len(), |pos| pos + 4);
        let header_text = &text[..header_end.min(text.len())];
        let mut lines = header_text.lines();
        if let Some(request_line) = lines.next() {
            r.add_field(FieldDef::new("request_line", "Request Line", 0, request_line.len(), FieldType::Ascii).with_value(FieldValue::String(request_line.to_string())));
            r.summary = request_line.to_string();
        }
        for line in lines {
            if line.is_empty() { break; }
            if let Some(colon) = line.find(':') {
                let key = line[..colon].trim();
                let val = line[colon + 1..].trim();
                r.add_field(FieldDef::new(key, key, 0, val.len(), FieldType::Ascii).with_value(FieldValue::String(val.to_string())));
            }
        }
        r.header_size = header_end;
        r.payload = data[header_end..].to_vec();
        r.complete = true;
        Ok(r)
    }
}

// ─── ProtocolStack ────────────────────────────────────────────────────────────

/// Ordered stack of protocol layers (e.g. Ethernet→IPv4→TCP→HTTP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStack {
    pub layers: Vec<DissectionResult>,
}

impl ProtocolStack {
    /// Create an empty stack.
    #[must_use]
    pub const fn new() -> Self { Self { layers: vec![] } }

    /// Push a layer.
    pub fn push(&mut self, result: DissectionResult) { self.layers.push(result); }

    /// Number of layers.
    #[must_use]
    pub const fn depth(&self) -> usize { self.layers.len() }

    /// Return `true` if the stack is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.layers.is_empty() }

    /// Get a layer by protocol name.
    #[must_use]
    pub fn get_layer(&self, protocol: &str) -> Option<&DissectionResult> {
        self.layers.iter().find(|l| l.protocol == protocol)
    }

    /// Return the innermost payload bytes.
    #[must_use]
    pub fn innermost_payload(&self) -> &[u8] {
        self.layers.last().map_or(&[], |l| l.payload.as_slice())
    }

    /// Collect all field values across all layers as a flat map.
    #[must_use]
    pub fn all_fields(&self) -> HashMap<String, &FieldValue> {
        let mut m = HashMap::new();
        for layer in &self.layers {
            for field in &layer.fields {
                if let Some(v) = &field.value {
                    m.insert(format!("{}.{}", layer.protocol, field.name), v);
                }
            }
        }
        m
    }

    /// Return a one-line summary of the full stack.
    #[must_use]
    pub fn summary(&self) -> String {
        self.layers.iter().map(|l| l.summary.as_str()).filter(|s| !s.is_empty())
            .collect::<Vec<_>>().join(" | ")
    }
}

impl Default for ProtocolStack { fn default() -> Self { Self::new() } }

// ─── DissectionTree ───────────────────────────────────────────────────────────

/// Hierarchical tree of dissected layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissectionTree {
    pub root_protocol: String,
    pub layers: Vec<DissectionResult>,
    pub total_bytes: usize,
}

impl DissectionTree {
    /// Build a tree by running the protocol stack dissector.
    #[must_use]
    pub fn build(stack: &ProtocolStack, total_bytes: usize) -> Self {
        Self {
            root_protocol: stack.layers.first().map(|l| l.protocol.clone()).unwrap_or_default(),
            layers: stack.layers.clone(),
            total_bytes,
        }
    }

    /// Serialise the stack to a JSON string.
    ///
    /// # Errors
    /// Returns the underlying serde error as a `String` on failure.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| e.to_string())
    }

    /// Return the number of protocol layers.
    #[must_use]
    pub const fn layer_count(&self) -> usize { self.layers.len() }
}

// ─── WiresharkCompatOutput ────────────────────────────────────────────────────

/// Produces Wireshark-compatible summary text.
pub struct WiresharkCompatOutput;

impl WiresharkCompatOutput {
    /// Generate a one-line Wireshark-style frame summary.
    #[must_use]
    pub fn frame_summary(frame_num: u64, timestamp: f64, stack: &ProtocolStack, len: usize) -> String {
        let proto = stack.layers.last().map_or("Unknown", |l| l.protocol.as_str());
        let summary = stack.summary();
        format!("{frame_num:<5} {timestamp:<12.6} {proto:<8} {len:<6} {summary}")
    }

    /// Generate a full packet detail view.
    #[must_use]
    pub fn packet_detail(stack: &ProtocolStack) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for layer in &stack.layers {
            let _ = writeln!(out, "=== {} ===", layer.protocol);
            for field in &layer.fields {
                let value = field
                    .value
                    .as_ref()
                    .map_or_else(|| "<not decoded>".to_string(), ToString::to_string);
                let _ = writeln!(out, "  {:30} = {value}", field.name);
            }
        }
        out
    }

    /// Generate a hex dump line.
    #[must_use]
    pub fn hex_dump(offset: usize, data: &[u8]) -> String {
        let hex: Vec<String> = data.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = data.iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }).collect();
        format!("{offset:04x}  {:<48}  {ascii}", hex.join(" "))
    }
}

// ─── DissectorRegistry ────────────────────────────────────────────────────────

/// Registry of all dissectors, dispatched by protocol ID.
pub struct DissectorRegistry {
    dissectors: HashMap<u16, Arc<dyn Dissector>>,
    name_index: HashMap<String, u16>,
}

impl DissectorRegistry {
    /// Create a registry with all built-in dissectors registered.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut r = Self { dissectors: HashMap::new(), name_index: HashMap::new() };
        r.register(Arc::new(EthernetDissector));
        r.register(Arc::new(Ipv4Dissector));
        r.register(Arc::new(TcpDissector));
        r.register(Arc::new(UdpDissector));
        r.register(Arc::new(HttpDissector));
        r
    }

    /// Register a dissector.
    pub fn register(&mut self, d: Arc<dyn Dissector>) {
        let id = d.proto_id();
        self.name_index.insert(d.name().to_string(), id);
        self.dissectors.insert(id, d);
    }

    /// Find by protocol ID.
    #[must_use]
    pub fn find_by_id(&self, id: u16) -> Option<Arc<dyn Dissector>> {
        self.dissectors.get(&id).cloned()
    }

    /// Find by name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<Arc<dyn Dissector>> {
        self.name_index.get(name).and_then(|id| self.dissectors.get(id)).cloned()
    }

    /// Dissect a full frame starting from the given DLT link layer.
    ///
    /// `link_type`: 1 = Ethernet, 12 = raw IPv4, etc.
    ///
    /// # Errors
    /// Returns `DissectionError` if the initial dissector is not found.
    pub fn dissect_frame(&self, data: &[u8], link_type: u16, max_depth: usize) -> Result<ProtocolStack, DissectionError> {
        let mut stack = ProtocolStack::new();
        let mut current_data = data.to_vec();
        let mut proto_id = link_type;
        let mut depth = 0;

        while depth < max_depth && !current_data.is_empty() {
            let Some(dissector) = self.find_by_id(proto_id) else { break };
            let result = dissector.dissect(&current_data)?;
            let next_proto = result.next_protocol;
            current_data.clone_from(&result.payload);
            stack.push(result);
            proto_id = next_proto;
            depth += 1;
        }
        Ok(stack)
    }

    /// Number of registered dissectors.
    #[must_use]
    pub fn count(&self) -> usize { self.dissectors.len() }
}

impl fmt::Debug for DissectorRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DissectorRegistry({} dissectors)", self.dissectors.len())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_frame() -> Vec<u8> {
        let mut frame = vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst mac
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, // src mac
            0x08, 0x00,                          // ethertype IPv4
        ];
        // Minimal IPv4 header
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, // version+ihl, dscp, total_len=40
            0x00, 0x01, 0x40, 0x00, // id, flags+frag
            0x40, 0x06, 0x00, 0x00, // ttl=64, proto=6(TCP), checksum=0
            0x7f, 0x00, 0x00, 0x01, // src 127.0.0.1
            0x7f, 0x00, 0x00, 0x01, // dst 127.0.0.1
        ]);
        // Minimal TCP header (20 bytes)
        frame.extend_from_slice(&[
            0x1F, 0x90, 0x00, 0x50, // src=8080, dst=80
            0x00, 0x00, 0x00, 0x01, // seq=1
            0x00, 0x00, 0x00, 0x00, // ack=0
            0x50, 0x02, 0xFF, 0xFF, // data_offset=5, SYN, window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent
        ]);
        frame
    }

    // ── FieldType ─────────────────────────────────────────────────────────────

    #[test]
    fn test_field_type_display() {
        assert_eq!(FieldType::U8.to_string(), "uint8");
        assert_eq!(FieldType::Ipv4.to_string(), "ipv4");
    }

    // ── FieldDef ──────────────────────────────────────────────────────────────

    #[test]
    fn test_field_def_decode_u8() {
        let f = FieldDef::new("byte", "A byte", 0, 1, FieldType::U8);
        let v = f.decode(&[0x42, 0x00]).unwrap();
        assert_eq!(v.as_u64(), Some(0x42));
    }

    #[test]
    fn test_field_def_decode_u16be() {
        let f = FieldDef::new("port", "Port", 0, 2, FieldType::U16Be);
        let v = f.decode(&[0x00, 0x50]).unwrap();
        assert_eq!(v.as_u64(), Some(80));
    }

    #[test]
    fn test_field_def_decode_ipv4() {
        let f = FieldDef::new("src", "Src IP", 0, 4, FieldType::Ipv4);
        let v = f.decode(&[127, 0, 0, 1]).unwrap();
        assert_eq!(v.to_string(), "127.0.0.1");
    }

    #[test]
    fn test_field_def_decode_too_short() {
        let f = FieldDef::new("x", "X", 0, 4, FieldType::U32Be);
        assert!(matches!(f.decode(&[0, 1]), Err(DissectionError::TooShort { .. })));
    }

    #[test]
    fn test_field_def_bitmask() {
        let f = FieldDef::new("flags", "Flags", 0, 1, FieldType::Flags).with_bitmask(0x3f);
        let v = f.decode(&[0xFF]).unwrap();
        assert_eq!(v.as_u64(), Some(0x3f));
    }

    #[test]
    fn test_field_def_display() {
        let f = FieldDef::new("x", "X", 0, 1, FieldType::U8).with_value(FieldValue::Uint(42));
        assert!(f.to_string().contains("42"));
    }

    // ── DissectionResult ──────────────────────────────────────────────────────

    #[test]
    fn test_dissection_result_get_field() {
        let mut r = DissectionResult::new("TestProto");
        r.add_field(FieldDef::new("x", "X", 0, 1, FieldType::U8).with_value(FieldValue::Uint(5)));
        assert!(r.get_field("x").is_some());
        assert!(r.get_field("y").is_none());
    }

    #[test]
    fn test_dissection_result_get_u64() {
        let mut r = DissectionResult::new("TestProto");
        r.add_field(FieldDef::new("port", "Port", 0, 2, FieldType::U16Be).with_value(FieldValue::Uint(443)));
        assert_eq!(r.get_u64("port"), Some(443));
    }

    #[test]
    fn test_dissection_result_display() {
        let r = DissectionResult::new("IPv4");
        assert!(r.to_string().contains("IPv4"));
    }

    // ── EthernetDissector ─────────────────────────────────────────────────────

    #[test]
    fn test_ethernet_dissect() {
        let frame = eth_frame();
        let d = EthernetDissector;
        let r = d.dissect(&frame).unwrap();
        assert_eq!(r.protocol, "Ethernet");
        assert_eq!(r.get_u64("ethertype"), Some(0x0800));
        assert_eq!(r.next_protocol, 0x0800);
    }

    #[test]
    fn test_ethernet_too_short() {
        let d = EthernetDissector;
        assert!(matches!(d.dissect(&[0; 5]), Err(DissectionError::TooShort { .. })));
    }

    // ── Ipv4Dissector ─────────────────────────────────────────────────────────

    #[test]
    fn test_ipv4_dissect() {
        let ipv4 = &eth_frame()[14..]; // strip Ethernet header
        let d = Ipv4Dissector;
        let r = d.dissect(ipv4).unwrap();
        assert_eq!(r.protocol, "IPv4");
        assert_eq!(r.get_u64("ttl"), Some(64));
        assert_eq!(r.next_protocol, 6); // TCP
    }

    #[test]
    fn test_ipv4_src_ip() {
        let ipv4 = &eth_frame()[14..];
        let d = Ipv4Dissector;
        let r = d.dissect(ipv4).unwrap();
        let src = r.get_field("src_ip").unwrap();
        assert_eq!(src.value.as_ref().unwrap().to_string(), "127.0.0.1");
    }

    // ── TcpDissector ─────────────────────────────────────────────────────────

    #[test]
    fn test_tcp_dissect() {
        let tcp = &eth_frame()[34..]; // skip Ethernet+IPv4
        let d = TcpDissector;
        let r = d.dissect(tcp).unwrap();
        assert_eq!(r.protocol, "TCP");
        assert_eq!(r.get_u64("src_port"), Some(8080));
        assert_eq!(r.get_u64("dst_port"), Some(80));
    }

    // ── UdpDissector ─────────────────────────────────────────────────────────

    #[test]
    fn test_udp_dissect() {
        let udp = &[0x00, 0x35, 0x00, 0x50, 0x00, 0x08, 0xab, 0xcd]; // src=53 dst=80
        let d = UdpDissector;
        let r = d.dissect(udp).unwrap();
        assert_eq!(r.get_u64("src_port"), Some(53));
        assert_eq!(r.get_u64("dst_port"), Some(80));
    }

    // ── HttpDissector ─────────────────────────────────────────────────────────

    #[test]
    fn test_http_dissect() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        let d = HttpDissector;
        let r = d.dissect(req).unwrap();
        assert_eq!(r.protocol, "HTTP");
        assert!(!r.fields.is_empty());
    }

    // ── ProtocolStack ─────────────────────────────────────────────────────────

    #[test]
    fn test_stack_push_and_depth() {
        let mut s = ProtocolStack::new();
        s.push(DissectionResult::new("L1"));
        s.push(DissectionResult::new("L2"));
        assert_eq!(s.depth(), 2);
    }

    #[test]
    fn test_stack_get_layer() {
        let mut s = ProtocolStack::new();
        s.push(DissectionResult::new("IPv4"));
        assert!(s.get_layer("IPv4").is_some());
        assert!(s.get_layer("TCP").is_none());
    }

    #[test]
    fn test_stack_all_fields() {
        let mut s = ProtocolStack::new();
        let mut r = DissectionResult::new("IPv4");
        r.add_field(FieldDef::new("ttl", "TTL", 8, 1, FieldType::U8).with_value(FieldValue::Uint(64)));
        s.push(r);
        let fields = s.all_fields();
        assert!(fields.contains_key("IPv4.ttl"));
    }

    // ── DissectionTree ────────────────────────────────────────────────────────

    #[test]
    fn test_tree_build() {
        let mut s = ProtocolStack::new();
        s.push(DissectionResult::new("Ethernet"));
        s.push(DissectionResult::new("IPv4"));
        let tree = DissectionTree::build(&s, 1500);
        assert_eq!(tree.root_protocol, "Ethernet");
        assert_eq!(tree.layer_count(), 2);
    }

    #[test]
    fn test_tree_to_json() {
        let s = ProtocolStack::new();
        let tree = DissectionTree::build(&s, 0);
        assert!(tree.to_json().is_ok());
    }

    // ── WiresharkCompatOutput ─────────────────────────────────────────────────

    #[test]
    fn test_frame_summary() {
        let s = ProtocolStack::new();
        let line = WiresharkCompatOutput::frame_summary(1, 0.001, &s, 60);
        assert!(line.contains('1'));
    }

    #[test]
    fn test_hex_dump() {
        let line = WiresharkCompatOutput::hex_dump(0, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(line.contains("de ad"));
    }

    // ── DissectorRegistry ─────────────────────────────────────────────────────

    #[test]
    fn test_registry_builtins() {
        let r = DissectorRegistry::with_builtins();
        assert!(r.count() >= 4);
        assert!(r.find_by_name("TCP").is_some());
        assert!(r.find_by_name("UDP").is_some());
    }

    #[test]
    fn test_registry_dissect_ethernet_frame() {
        let r = DissectorRegistry::with_builtins();
        let frame = eth_frame();
        let stack = r.dissect_frame(&frame, 1, 5).unwrap();
        assert!(stack.depth() >= 2);
        assert!(stack.get_layer("Ethernet").is_some());
        assert!(stack.get_layer("IPv4").is_some());
    }

    #[test]
    fn test_registry_unknown_protocol_stops() {
        let r = DissectorRegistry::with_builtins();
        // Fake Ethernet with unknown EtherType 0xFFFF
        let mut frame = vec![0u8; 14];
        frame[12] = 0xFF; frame[13] = 0xFF;
        let stack = r.dissect_frame(&frame, 1, 5).unwrap();
        // Only Ethernet layer parsed
        assert_eq!(stack.depth(), 1);
    }

    #[test]
    fn test_field_value_display_mac() {
        let v = FieldValue::MacAddr([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        assert_eq!(v.to_string(), "de:ad:be:ef:00:01");
    }

    #[test]
    fn test_field_value_bool() {
        assert_eq!(FieldValue::Bool(true).to_string(), "true");
    }

    #[test]
    fn test_dissection_error_display() {
        let e = DissectionError::TooShort { need: 20, got: 5 };
        assert!(e.to_string().contains("20"));
    }
}
