//! Application-layer protocol dissectors.
//!
//! Provides:
//! - [`ApplicationDissector`] trait and registry
//! - Built-in dissectors: HTTP/1.1, HTTP/2, DNS, SMTP, FTP, SSH, MQTT, AMQP
//! - [`ProtocolIdentifier`] — port-based and content-based fingerprinting
//! - [`DissectedApplication`] — structured output from dissection

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::DissectError;

// ────────────────────────────────────────────────────────────────────────────
// DissectedApplication
// ────────────────────────────────────────────────────────────────────────────

/// A protocol field extracted from application-layer data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppField {
    pub name: String,
    pub value: String,
}

impl AppField {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// The fully dissected representation of an application-layer payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissectedApplication {
    /// Protocol name (e.g. `"HTTP/1.1"`, `"DNS"`, `"MQTT"`).
    pub protocol: String,
    /// Extracted structured fields.
    pub fields: Vec<AppField>,
    /// Any nested payload that could be further dissected.
    pub payload: Vec<u8>,
}

impl DissectedApplication {
    pub fn new(protocol: impl Into<String>) -> Self {
        Self {
            protocol: protocol.into(),
            fields: Vec::new(),
            payload: Vec::new(),
        }
    }

    pub fn add_field(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.fields.push(AppField::new(name, value));
    }

    /// Look up a field by name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.value.as_str())
    }

    /// Pretty-print the dissected application layer.
    #[must_use]
    pub fn pretty_print(&self) -> String {
        use std::fmt::Write as _;
        let mut out = format!("[{}]\n", self.protocol);
        for f in &self.fields {
            let _ = writeln!(out, "  {}: {}", f.name, f.value);
        }
        out
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ApplicationDissector trait
// ────────────────────────────────────────────────────────────────────────────

/// Dissect a raw application-layer payload into a [`DissectedApplication`].
pub trait ApplicationDissector: Send + Sync {
    /// Protocol name.
    fn name(&self) -> &'static str;
    /// Well-known TCP/UDP ports.
    fn ports(&self) -> &[u16] {
        &[]
    }
    /// Confidence heuristic: returns 0–100 for how confident this dissector is
    /// that `data` belongs to this protocol (content-based detection).
    fn confidence(&self, data: &[u8]) -> u8;
    /// Perform dissection.
    ///
    /// # Errors
    /// Returns [`DissectError`] when `data` does not conform to the protocol
    /// or is too short to parse.
    fn dissect(&self, data: &[u8]) -> Result<DissectedApplication, DissectError>;
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP/1.1 dissector
// ────────────────────────────────────────────────────────────────────────────

pub struct Http11Dissector;

impl ApplicationDissector for Http11Dissector {
    fn name(&self) -> &'static str {
        "HTTP/1.1"
    }
    fn ports(&self) -> &[u16] {
        &[80, 8080, 8000, 3000]
    }

    fn confidence(&self, data: &[u8]) -> u8 {
        if data.len() < 4 {
            return 0;
        }
        let s = &data[..data.len().min(16)];
        let methods = [
            b"GET " as &[u8],
            b"POST",
            b"PUT ",
            b"DELE",
            b"HEAD",
            b"OPTI",
            b"HTTP",
            b"PATC",
            b"CONN",
            b"TRAC",
        ];
        if methods.iter().any(|m| s.starts_with(m)) {
            90
        } else {
            0
        }
    }

    fn dissect(&self, data: &[u8]) -> Result<DissectedApplication, DissectError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| DissectError::MalformedField("non-UTF-8 HTTP".into()))?;
        let mut app = DissectedApplication::new("HTTP/1.1");

        let first_line = text.lines().next().unwrap_or("");
        // Request line
        if first_line.starts_with("GET")
            || first_line.starts_with("POST")
            || first_line.starts_with("PUT")
            || first_line.starts_with("DELETE")
            || first_line.starts_with("HEAD")
            || first_line.starts_with("OPTIONS")
            || first_line.starts_with("PATCH")
            || first_line.starts_with("CONNECT")
        {
            let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                app.add_field("method", parts[0]);
                app.add_field("uri", parts[1]);
            }
            if parts.len() == 3 {
                app.add_field("version", parts[2]);
            }
            app.add_field("direction", "request");
        } else if first_line.starts_with("HTTP/") {
            // Status line
            let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                app.add_field("version", parts[0]);
                app.add_field("status_code", parts[1]);
            }
            if parts.len() == 3 {
                app.add_field("reason", parts[2]);
            }
            app.add_field("direction", "response");
        }

        // Parse a few headers
        for line in text.lines().skip(1) {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(": ") {
                let name = k.to_ascii_lowercase();
                if matches!(
                    name.as_str(),
                    "host"
                        | "content-type"
                        | "content-length"
                        | "user-agent"
                        | "authorization"
                        | "cookie"
                ) {
                    app.add_field(k, v);
                }
            }
        }

        // Body
        if let Some(body_start) = text.find("\r\n\r\n") {
            app.payload = data[body_start + 4..].to_vec();
        }

        Ok(app)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP/2 dissector (frame-level)
// ────────────────────────────────────────────────────────────────────────────

/// HTTP/2 frame types (RFC 7540 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Http2FrameType {
    Data = 0,
    Headers = 1,
    Priority = 2,
    RstStream = 3,
    Settings = 4,
    PushPromise = 5,
    Ping = 6,
    GoAway = 7,
    WindowUpdate = 8,
    Continuation = 9,
    Unknown,
}

impl From<u8> for Http2FrameType {
    fn from(b: u8) -> Self {
        match b {
            0 => Self::Data,
            1 => Self::Headers,
            2 => Self::Priority,
            3 => Self::RstStream,
            4 => Self::Settings,
            5 => Self::PushPromise,
            6 => Self::Ping,
            7 => Self::GoAway,
            8 => Self::WindowUpdate,
            9 => Self::Continuation,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for Http2FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Data => "DATA",
            Self::Headers => "HEADERS",
            Self::Priority => "PRIORITY",
            Self::RstStream => "RST_STREAM",
            Self::Settings => "SETTINGS",
            Self::PushPromise => "PUSH_PROMISE",
            Self::Ping => "PING",
            Self::GoAway => "GOAWAY",
            Self::WindowUpdate => "WINDOW_UPDATE",
            Self::Continuation => "CONTINUATION",
            Self::Unknown => "UNKNOWN",
        };
        write!(f, "{s}")
    }
}

/// HTTP/2 connection preface magic.
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub struct Http2Dissector;

impl ApplicationDissector for Http2Dissector {
    fn name(&self) -> &'static str {
        "HTTP/2"
    }
    fn ports(&self) -> &[u16] {
        &[443, 8443]
    }

    fn confidence(&self, data: &[u8]) -> u8 {
        if data.starts_with(HTTP2_PREFACE) {
            95
        } else if data.len() >= 9 {
            30
        }
        // might be a frame
        else {
            0
        }
    }

    fn dissect(&self, data: &[u8]) -> Result<DissectedApplication, DissectError> {
        let mut app = DissectedApplication::new("HTTP/2");
        let offset = if data.starts_with(HTTP2_PREFACE) {
            app.add_field("preface", "present");
            HTTP2_PREFACE.len()
        } else {
            0
        };

        // Parse first frame
        if offset + 9 <= data.len() {
            let length = (u32::from(data[offset]) << 16)
                | (u32::from(data[offset + 1]) << 8)
                | u32::from(data[offset + 2]);
            let frame_type = Http2FrameType::from(data[offset + 3]);
            let flags = data[offset + 4];
            let stream_id = u32::from_be_bytes([
                data[offset + 5] & 0x7F,
                data[offset + 6],
                data[offset + 7],
                data[offset + 8],
            ]);
            app.add_field("frame_type", frame_type.to_string());
            app.add_field("frame_length", length.to_string());
            app.add_field("flags", format!("0x{flags:02X}"));
            app.add_field("stream_id", stream_id.to_string());

            let payload_start = offset + 9;
            let payload_end = (payload_start + length as usize).min(data.len());
            app.payload = data[payload_start..payload_end].to_vec();
        }
        Ok(app)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DNS dissector
// ────────────────────────────────────────────────────────────────────────────

pub struct DnsDissector;

impl ApplicationDissector for DnsDissector {
    fn name(&self) -> &'static str {
        "DNS"
    }
    fn ports(&self) -> &[u16] {
        &[53, 5353]
    }

    fn confidence(&self, data: &[u8]) -> u8 {
        if data.len() < 12 {
            return 0;
        }
        // Heuristic: opcode in bits 11-14 of flags byte should be 0-5
        let opcode = (data[2] >> 3) & 0x0F;
        if opcode <= 5 { 70 } else { 0 }
    }

    fn dissect(&self, data: &[u8]) -> Result<DissectedApplication, DissectError> {
        if data.len() < 12 {
            return Err(DissectError::BufferTooShort {
                needed: 12,
                got: data.len(),
            });
        }
        let mut app = DissectedApplication::new("DNS");
        let txid = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qr = (flags >> 15) & 1;
        let opcode = (flags >> 11) & 0xF;
        let rcode = flags & 0xF;
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);

        app.add_field("transaction_id", format!("0x{txid:04X}"));
        app.add_field("qr", if qr == 0 { "query" } else { "response" });
        app.add_field("opcode", opcode.to_string());
        app.add_field("rcode", rcode.to_string());
        app.add_field("questions", qdcount.to_string());
        app.add_field("answers", ancount.to_string());

        // Parse first question name
        if data.len() > 12 {
            let name = parse_dns_name(data, 12);
            app.add_field("query_name", name);
        }

        Ok(app)
    }
}

/// Parse a DNS compressed name starting at `offset`.
fn parse_dns_name(data: &[u8], mut offset: usize) -> String {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut safety = 0usize;
    loop {
        safety += 1;
        if safety > 64 || offset >= data.len() {
            break;
        }
        let len = data[offset] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Pointer
            if offset + 1 >= data.len() {
                break;
            }
            let ptr = ((len & 0x3F) << 8) | data[offset + 1] as usize;
            
            offset = ptr;
            jumped = true;
            continue;
        }
        offset += 1;
        if offset + len > data.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&data[offset..offset + len]).to_string());
        offset += len;
        if !jumped {}
    }
    labels.join(".")
}

// ────────────────────────────────────────────────────────────────────────────
// SMTP dissector
// ────────────────────────────────────────────────────────────────────────────

pub struct SmtpDissector;

impl ApplicationDissector for SmtpDissector {
    fn name(&self) -> &'static str {
        "SMTP"
    }
    fn ports(&self) -> &[u16] {
        &[25, 587, 465]
    }

    fn confidence(&self, data: &[u8]) -> u8 {
        if data.len() < 4 {
            return 0;
        }
        let s = &data[..data.len().min(20)];
        if s.starts_with(b"220 ")
            || s.starts_with(b"EHLO")
            || s.starts_with(b"HELO")
            || s.starts_with(b"MAIL")
            || s.starts_with(b"RCPT")
            || s.starts_with(b"DATA")
        {
            85
        } else {
            0
        }
    }

    fn dissect(&self, data: &[u8]) -> Result<DissectedApplication, DissectError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| DissectError::MalformedField("non-UTF-8 SMTP".into()))?;
        let mut app = DissectedApplication::new("SMTP");
        for line in text.lines().take(10) {
            if line.len() >= 4 {
                if let Ok(code) = line[..3].parse::<u16>() {
                    app.add_field(format!("reply_{code}"), &line[4..]);
                } else if line.starts_with("EHLO") || line.starts_with("HELO") {
                    app.add_field("command", &line[..4]);
                    app.add_field("domain", line[5..].trim());
                } else if let Some(__stripped) = line.strip_prefix("MAIL FROM:") {
                    app.add_field("mail_from", __stripped.trim());
                } else if let Some(__stripped) = line.strip_prefix("RCPT TO:") {
                    app.add_field("rcpt_to", __stripped.trim());
                } else if line.starts_with("DATA") {
                    app.add_field("command", "DATA");
                } else if line.starts_with("QUIT") {
                    app.add_field("command", "QUIT");
                }
            }
        }
        Ok(app)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// FTP dissector
// ────────────────────────────────────────────────────────────────────────────

pub struct FtpDissector;

impl ApplicationDissector for FtpDissector {
    fn name(&self) -> &'static str {
        "FTP"
    }
    fn ports(&self) -> &[u16] {
        &[21, 20]
    }

    fn confidence(&self, data: &[u8]) -> u8 {
        if data.len() < 4 {
            return 0;
        }
        let s = &data[..data.len().min(16)];
        if s.starts_with(b"220 ")
            || s.starts_with(b"USER")
            || s.starts_with(b"PASS")
            || s.starts_with(b"RETR")
            || s.starts_with(b"STOR")
            || s.starts_with(b"LIST")
        {
            80
        } else {
            0
        }
    }

    fn dissect(&self, data: &[u8]) -> Result<DissectedApplication, DissectError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| DissectError::MalformedField("non-UTF-8 FTP".into()))?;
        let mut app = DissectedApplication::new("FTP");
        let line = text.lines().next().unwrap_or("").trim();
        // Server reply
        if line.len() >= 3
            && let Ok(code) = line[..3].parse::<u16>() {
                app.add_field("reply_code", code.to_string());
                app.add_field("reply_text", if line.len() > 4 { &line[4..] } else { "" });
                return Ok(app);
            }
        // Client command
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        app.add_field("command", parts[0].to_ascii_uppercase());
        if parts.len() > 1 {
            app.add_field("argument", parts[1]);
        }
        Ok(app)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SSH handshake dissector
// ────────────────────────────────────────────────────────────────────────────

pub struct SshDissector;

impl ApplicationDissector for SshDissector {
    fn name(&self) -> &'static str {
        "SSH"
    }
    fn ports(&self) -> &[u16] {
        &[22]
    }

    fn confidence(&self, data: &[u8]) -> u8 {
        if data.starts_with(b"SSH-") { 95 } else { 0 }
    }

    fn dissect(&self, data: &[u8]) -> Result<DissectedApplication, DissectError> {
        let mut app = DissectedApplication::new("SSH");
        if let Ok(text) = std::str::from_utf8(data) {
            let banner = text.lines().next().unwrap_or("").trim();
            app.add_field("banner", banner);
            // SSH-<proto>-<software> [<comment>]
            let parts: Vec<&str> = banner.splitn(3, '-').collect();
            if parts.len() >= 3 {
                app.add_field("proto_version", parts[1]);
                let sw_comment: Vec<&str> = parts[2].splitn(2, ' ').collect();
                app.add_field("software", sw_comment[0]);
                if sw_comment.len() > 1 {
                    app.add_field("comment", sw_comment[1]);
                }
            }
        } else {
            // Binary SSH packet after handshake
            if data.len() >= 5 {
                let pkt_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let msg_code = if data.len() > 5 { data[5] } else { 0 };
                app.add_field("packet_length", pkt_len.to_string());
                app.add_field("message_code", msg_code.to_string());
            }
        }
        Ok(app)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// MQTT dissector
// ────────────────────────────────────────────────────────────────────────────

/// MQTT control packet types (OASIS MQTT 3.1.1 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MqttPacketType {
    Connect = 1,
    ConnAck = 2,
    Publish = 3,
    PubAck = 4,
    PubRec = 5,
    PubRel = 6,
    PubComp = 7,
    Subscribe = 8,
    SubAck = 9,
    Unsubscribe = 10,
    UnsubAck = 11,
    PingReq = 12,
    PingResp = 13,
    Disconnect = 14,
    Unknown,
}

impl MqttPacketType {
    const fn from_nibble(n: u8) -> Self {
        match n {
            1 => Self::Connect,
            2 => Self::ConnAck,
            3 => Self::Publish,
            4 => Self::PubAck,
            5 => Self::PubRec,
            6 => Self::PubRel,
            7 => Self::PubComp,
            8 => Self::Subscribe,
            9 => Self::SubAck,
            10 => Self::Unsubscribe,
            11 => Self::UnsubAck,
            12 => Self::PingReq,
            13 => Self::PingResp,
            14 => Self::Disconnect,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for MqttPacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

pub struct MqttDissector;

impl ApplicationDissector for MqttDissector {
    fn name(&self) -> &'static str {
        "MQTT"
    }
    fn ports(&self) -> &[u16] {
        &[1883, 8883]
    }

    fn confidence(&self, data: &[u8]) -> u8 {
        if data.len() < 2 {
            return 0;
        }
        let ptype = (data[0] >> 4) & 0xF;
        if (1..=14).contains(&ptype) { 70 } else { 0 }
    }

    fn dissect(&self, data: &[u8]) -> Result<DissectedApplication, DissectError> {
        if data.len() < 2 {
            return Err(DissectError::BufferTooShort {
                needed: 2,
                got: data.len(),
            });
        }
        let mut app = DissectedApplication::new("MQTT");
        let packet_type = MqttPacketType::from_nibble((data[0] >> 4) & 0xF);
        let flags = data[0] & 0xF;
        // Variable-length remaining length (up to 4 bytes)
        let (remaining_len, var_len_size) = decode_mqtt_varint(data, 1);
        app.add_field("packet_type", packet_type.to_string());
        app.add_field("flags", format!("0x{flags:01X}"));
        app.add_field("remaining_length", remaining_len.to_string());

        let payload_start = 1 + var_len_size;
        if packet_type == MqttPacketType::Connect && payload_start + 4 <= data.len() {
            // Protocol name length
            let proto_name_len =
                u16::from_be_bytes([data[payload_start], data[payload_start + 1]]) as usize;
            if payload_start + 2 + proto_name_len <= data.len() {
                let name = String::from_utf8_lossy(
                    &data[payload_start + 2..payload_start + 2 + proto_name_len],
                )
                .to_string();
                app.add_field("protocol_name", name);
            }
        } else if packet_type == MqttPacketType::Publish && payload_start + 2 <= data.len() {
            let topic_len =
                u16::from_be_bytes([data[payload_start], data[payload_start + 1]]) as usize;
            if payload_start + 2 + topic_len <= data.len() {
                let topic = String::from_utf8_lossy(
                    &data[payload_start + 2..payload_start + 2 + topic_len],
                )
                .to_string();
                app.add_field("topic", topic);
                app.payload = data[payload_start + 2 + topic_len..].to_vec();
            }
        }
        Ok(app)
    }
}

/// Decode MQTT variable-length integer starting at `offset`.
/// Returns (value, `bytes_consumed`).
fn decode_mqtt_varint(data: &[u8], mut offset: usize) -> (u32, usize) {
    let mut value: u32 = 0;
    let mut shift = 0u32;
    let mut consumed = 0usize;
    while offset < data.len() && consumed < 4 {
        let byte = data[offset];
        offset += 1;
        consumed += 1;
        value |= u32::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    (value, consumed)
}

// ────────────────────────────────────────────────────────────────────────────
// AMQP dissector (0-9-1)
// ────────────────────────────────────────────────────────────────────────────

const AMQP_PROTOCOL_HEADER: &[u8] = b"AMQP\x00\x00\x09\x01";

pub struct AmqpDissector;

impl ApplicationDissector for AmqpDissector {
    fn name(&self) -> &'static str {
        "AMQP"
    }
    fn ports(&self) -> &[u16] {
        &[5672, 5671]
    }

    fn confidence(&self, data: &[u8]) -> u8 {
        if data.starts_with(b"AMQP") { 95 } else { 20 }
    }

    fn dissect(&self, data: &[u8]) -> Result<DissectedApplication, DissectError> {
        let mut app = DissectedApplication::new("AMQP");
        if data.starts_with(AMQP_PROTOCOL_HEADER) {
            app.add_field("frame_type", "protocol_header");
            app.add_field("version", "0-9-1");
            return Ok(app);
        }
        if data.len() < 7 {
            return Err(DissectError::BufferTooShort {
                needed: 7,
                got: data.len(),
            });
        }
        let frame_type = data[0];
        let channel = u16::from_be_bytes([data[1], data[2]]);
        let payload_size = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
        let frame_type_name = match frame_type {
            1 => "Method",
            2 => "Header",
            3 => "Body",
            8 => "Heartbeat",
            _ => "Unknown",
        };
        app.add_field("frame_type", frame_type_name);
        app.add_field("channel", channel.to_string());
        app.add_field("payload_size", payload_size.to_string());
        let payload_start = 7;
        let payload_end = (payload_start + payload_size as usize).min(data.len());
        app.payload = data[payload_start..payload_end].to_vec();
        Ok(app)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ProtocolIdentifier
// ────────────────────────────────────────────────────────────────────────────

/// Identify application-layer protocols by port and/or content.
pub struct ProtocolIdentifier {
    dissectors: Vec<Box<dyn ApplicationDissector>>,
    port_map: HashMap<u16, usize>,
}

impl ProtocolIdentifier {
    /// Build an identifier with the standard set of dissectors.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut id = Self {
            dissectors: Vec::new(),
            port_map: HashMap::new(),
        };
        id.register(Box::new(Http11Dissector));
        id.register(Box::new(Http2Dissector));
        id.register(Box::new(DnsDissector));
        id.register(Box::new(SmtpDissector));
        id.register(Box::new(FtpDissector));
        id.register(Box::new(SshDissector));
        id.register(Box::new(MqttDissector));
        id.register(Box::new(AmqpDissector));
        id
    }

    /// Register a dissector.
    pub fn register(&mut self, d: Box<dyn ApplicationDissector>) {
        let idx = self.dissectors.len();
        for &port in d.ports() {
            self.port_map.insert(port, idx);
        }
        self.dissectors.push(d);
    }

    /// Identify the most likely protocol by port and content confidence.
    #[must_use]
    pub fn identify(&self, src_port: u16, dst_port: u16, data: &[u8]) -> Option<&str> {
        // Try port-based first
        for port in [dst_port, src_port] {
            if let Some(&idx) = self.port_map.get(&port) {
                return Some(self.dissectors[idx].name());
            }
        }
        // Content-based fallback
        let best = self
            .dissectors
            .iter()
            .map(|d| (d.name(), d.confidence(data)))
            .filter(|&(_, c)| c >= 50)
            .max_by_key(|&(_, c)| c);
        best.map(|(name, _)| name)
    }

    /// Dissect using the best matching dissector.
    ///
    /// # Errors
    /// Returns [`DissectError`] when no dissector matches the port or the
    /// content-based fallback selection fails to dissect the payload.
    pub fn dissect_best(
        &self,
        src_port: u16,
        dst_port: u16,
        data: &[u8],
    ) -> Result<DissectedApplication, DissectError> {
        for port in [dst_port, src_port] {
            if let Some(&idx) = self.port_map.get(&port) {
                return self.dissectors[idx].dissect(data);
            }
        }
        // Fallback: highest confidence
        let best_idx = self
            .dissectors
            .iter()
            .enumerate()
            .map(|(i, d)| (i, d.confidence(data)))
            .filter(|&(_, c)| c >= 50)
            .max_by_key(|&(_, c)| c)
            .map(|(i, _)| i);
        best_idx.map_or_else(|| Err(DissectError::NoDissector("unknown".into())), |idx| self.dissectors[idx].dissect(data))
    }

    /// Number of registered dissectors.
    #[must_use]
    pub fn dissector_count(&self) -> usize {
        self.dissectors.len()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Http11Dissector ───────────────────────────────────────────────────────

    #[test]
    fn test_http11_confidence_get() {
        let d = Http11Dissector;
        assert!(d.confidence(b"GET / HTTP/1.1\r\n") >= 90);
    }

    #[test]
    fn test_http11_confidence_response() {
        let d = Http11Dissector;
        assert!(d.confidence(b"HTTP/1.1 200 OK\r\n") >= 90);
    }

    #[test]
    fn test_http11_confidence_unknown() {
        let d = Http11Dissector;
        assert_eq!(d.confidence(b"\x00\x01\x02\x03"), 0);
    }

    #[test]
    fn test_http11_dissect_get() {
        let d = Http11Dissector;
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let app = d.dissect(data).unwrap();
        assert_eq!(app.protocol, "HTTP/1.1");
        assert_eq!(app.field("method"), Some("GET"));
        assert_eq!(app.field("uri"), Some("/index.html"));
        assert_eq!(app.field("Host"), Some("example.com"));
    }

    #[test]
    fn test_http11_dissect_response() {
        let d = Http11Dissector;
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>";
        let app = d.dissect(data).unwrap();
        assert_eq!(app.field("status_code"), Some("200"));
        assert_eq!(app.field("direction"), Some("response"));
    }

    #[test]
    fn test_http11_ports() {
        let d = Http11Dissector;
        assert!(d.ports().contains(&80));
    }

    // ── Http2Dissector ────────────────────────────────────────────────────────

    #[test]
    fn test_http2_confidence_preface() {
        let d = Http2Dissector;
        assert!(d.confidence(HTTP2_PREFACE) >= 95);
    }

    #[test]
    fn test_http2_dissect_preface() {
        let d = Http2Dissector;
        // Preface followed by a SETTINGS frame (type=4, length=0, stream_id=0)
        let mut data = HTTP2_PREFACE.to_vec();
        data.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]); // SETTINGS frame
        let app = d.dissect(&data).unwrap();
        assert!(app.field("preface").is_some());
        assert_eq!(app.field("frame_type"), Some("SETTINGS"));
    }

    #[test]
    fn test_http2_frame_type_display() {
        assert_eq!(Http2FrameType::Headers.to_string(), "HEADERS");
        assert_eq!(Http2FrameType::GoAway.to_string(), "GOAWAY");
    }

    // ── DnsDissector ──────────────────────────────────────────────────────────

    #[test]
    fn test_dns_dissect_query() {
        let d = DnsDissector;
        // Minimal DNS query: txid=0xABCD, flags=0x0100 (standard query), 1 question
        let mut data = vec![
            0xAB, 0xCD, // transaction ID
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        // Query name: "example.com"
        data.extend_from_slice(&[7]);
        data.extend_from_slice(b"example");
        data.extend_from_slice(&[3]);
        data.extend_from_slice(b"com");
        data.push(0); // end
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        let app = d.dissect(&data).unwrap();
        assert_eq!(app.field("qr"), Some("query"));
        assert_eq!(app.field("questions"), Some("1"));
    }

    #[test]
    fn test_dns_too_short() {
        let d = DnsDissector;
        assert!(d.dissect(&[1, 2, 3]).is_err());
    }

    #[test]
    fn test_dns_ports() {
        let d = DnsDissector;
        assert!(d.ports().contains(&53));
    }

    // ── SmtpDissector ─────────────────────────────────────────────────────────

    #[test]
    fn test_smtp_confidence_banner() {
        let d = SmtpDissector;
        assert!(d.confidence(b"220 mail.example.com ESMTP") >= 85);
    }

    #[test]
    fn test_smtp_dissect_ehlo() {
        let d = SmtpDissector;
        let data = b"EHLO client.example.com\r\n";
        let app = d.dissect(data).unwrap();
        assert_eq!(app.field("command"), Some("EHLO"));
        assert_eq!(app.field("domain"), Some("client.example.com"));
    }

    #[test]
    fn test_smtp_dissect_mail_from() {
        let d = SmtpDissector;
        let data = b"MAIL FROM:<sender@example.com>\r\n";
        let app = d.dissect(data).unwrap();
        assert_eq!(app.field("mail_from"), Some("<sender@example.com>"));
    }

    // ── FtpDissector ──────────────────────────────────────────────────────────

    #[test]
    fn test_ftp_confidence_banner() {
        let d = FtpDissector;
        assert!(d.confidence(b"220 FTP server ready") >= 80);
    }

    #[test]
    fn test_ftp_dissect_reply() {
        let d = FtpDissector;
        let data = b"220 Welcome to FTP\r\n";
        let app = d.dissect(data).unwrap();
        assert_eq!(app.field("reply_code"), Some("220"));
    }

    #[test]
    fn test_ftp_dissect_command() {
        let d = FtpDissector;
        let data = b"RETR /pub/file.txt\r\n";
        let app = d.dissect(data).unwrap();
        assert_eq!(app.field("command"), Some("RETR"));
        assert_eq!(app.field("argument"), Some("/pub/file.txt"));
    }

    // ── SshDissector ──────────────────────────────────────────────────────────

    #[test]
    fn test_ssh_confidence_banner() {
        let d = SshDissector;
        assert!(d.confidence(b"SSH-2.0-OpenSSH_8.9") >= 95);
    }

    #[test]
    fn test_ssh_dissect_banner() {
        let d = SshDissector;
        let data = b"SSH-2.0-OpenSSH_8.9 Debian\r\n";
        let app = d.dissect(data).unwrap();
        assert_eq!(app.field("proto_version"), Some("2.0"));
        assert_eq!(app.field("software"), Some("OpenSSH_8.9"));
    }

    #[test]
    fn test_ssh_ports() {
        let d = SshDissector;
        assert!(d.ports().contains(&22));
    }

    // ── MqttDissector ─────────────────────────────────────────────────────────

    #[test]
    fn test_mqtt_confidence_connect() {
        let d = MqttDissector;
        // CONNECT packet type = 1, flags = 0 → first nibble = 0x10
        assert!(d.confidence(&[0x10, 0x00]) > 0);
    }

    #[test]
    fn test_mqtt_dissect_ping() {
        let d = MqttDissector;
        // PINGREQ = type 12 (0xC0), remaining = 0
        let data = &[0xC0u8, 0x00];
        let app = d.dissect(data).unwrap();
        assert_eq!(app.field("packet_type"), Some("PingReq"));
    }

    #[test]
    fn test_mqtt_dissect_too_short() {
        let d = MqttDissector;
        assert!(d.dissect(&[]).is_err());
    }

    // ── AmqpDissector ─────────────────────────────────────────────────────────

    #[test]
    fn test_amqp_confidence_header() {
        let d = AmqpDissector;
        assert!(d.confidence(AMQP_PROTOCOL_HEADER) >= 95);
    }

    #[test]
    fn test_amqp_dissect_protocol_header() {
        let d = AmqpDissector;
        let app = d.dissect(AMQP_PROTOCOL_HEADER).unwrap();
        assert_eq!(app.field("version"), Some("0-9-1"));
    }

    #[test]
    fn test_amqp_dissect_frame() {
        let d = AmqpDissector;
        // Method frame (type=1), channel=1, payload=4 bytes
        let data = &[1u8, 0, 1, 0, 0, 0, 4, 0, 10, 0, 11, 0xCE]; // 0xCE = frame-end
        let app = d.dissect(data).unwrap();
        assert_eq!(app.field("frame_type"), Some("Method"));
        assert_eq!(app.field("channel"), Some("1"));
    }

    // ── ProtocolIdentifier ────────────────────────────────────────────────────

    #[test]
    fn test_identifier_defaults() {
        let id = ProtocolIdentifier::with_defaults();
        assert!(id.dissector_count() >= 8);
    }

    #[test]
    fn test_identify_by_dst_port() {
        let id = ProtocolIdentifier::with_defaults();
        assert_eq!(
            id.identify(54321, 80, b"GET / HTTP/1.1\r\n"),
            Some("HTTP/1.1")
        );
    }

    #[test]
    fn test_identify_dns_by_port() {
        let id = ProtocolIdentifier::with_defaults();
        assert_eq!(id.identify(12345, 53, &[0u8; 12]), Some("DNS"));
    }

    #[test]
    fn test_identify_ssh_by_content() {
        let id = ProtocolIdentifier::with_defaults();
        // No matching port, but content is SSH banner
        let name = id.identify(54321, 65001, b"SSH-2.0-OpenSSH_8.9\r\n");
        assert_eq!(name, Some("SSH"));
    }

    #[test]
    fn test_identify_unknown() {
        let id = ProtocolIdentifier::with_defaults();
        let name = id.identify(12345, 9999, b"\x00\x01\x02\x03\x04");
        assert!(name.is_none());
    }

    #[test]
    fn test_dissect_best_http() {
        let id = ProtocolIdentifier::with_defaults();
        let data = b"GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let app = id.dissect_best(54321, 80, data).unwrap();
        assert_eq!(app.protocol, "HTTP/1.1");
    }

    // ── DissectedApplication ──────────────────────────────────────────────────

    #[test]
    fn test_app_field_lookup() {
        let mut app = DissectedApplication::new("TEST");
        app.add_field("key", "value");
        assert_eq!(app.field("key"), Some("value"));
        assert!(app.field("missing").is_none());
    }

    #[test]
    fn test_app_pretty_print() {
        let mut app = DissectedApplication::new("TEST");
        app.add_field("a", "1");
        let s = app.pretty_print();
        assert!(s.contains("[TEST]"));
        assert!(s.contains("a: 1"));
    }
}
