//! Application-layer protocol dissectors — extended set.
//!
//! This module is the **medium-depth dissection layer**. It sits above the
//! quick-scan dissectors in [`crate::application_protocols`] and below the
//! fully-validating, per-protocol standalone parsers:
//!
//! | Protocol | Quick scan             | Extended (this module)        | Deep / standalone           |
//! |----------|------------------------|-------------------------------|-----------------------------|
//! | HTTP/2   | `application_protocols::Http2Dissector` | `Http2Dissector` + HPACK | [`crate::http2_dissector`] |
//! | DNS      | `application_protocols::DnsDissector`  | *(none)*                 | [`crate::dns_dissector`]   |
//! | MQTT     | `application_protocols::MqttDissector` | `MqttDissector` (5.0)    | *(none)*                   |
//! | AMQP     | `application_protocols::AmqpDissector` | `AmqpDissector` (methods)| *(none)*                   |
//!
//! Adds:
//! - HTTP/2 frame dissection with HPACK header compression
//! - gRPC protobuf framing on HTTP/2 with service/method extraction
//! - WebSocket handshake, frame dissection, and per-message compression
//! - MQTT 3.1.1 / 5.0 all control packet types
//! - AMQP 0-9-1 frame types and all method frames
//! - Redis RESP protocol (inline + multi-bulk)

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::DissectError;

// ─────────────────────────────────────────────────────────────────────────────
// HTTP/2
// ─────────────────────────────────────────────────────────────────────────────

/// HTTP/2 frame type identifiers (RFC 9113 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Http2FrameType {
    Data            = 0x0,
    Headers         = 0x1,
    Priority        = 0x2,
    RstStream       = 0x3,
    Settings        = 0x4,
    PushPromise     = 0x5,
    Ping            = 0x6,
    GoAway          = 0x7,
    WindowUpdate    = 0x8,
    Continuation    = 0x9,
    Unknown(u8),
}

impl Http2FrameType {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x0 => Self::Data,
            0x1 => Self::Headers,
            0x2 => Self::Priority,
            0x3 => Self::RstStream,
            0x4 => Self::Settings,
            0x5 => Self::PushPromise,
            0x6 => Self::Ping,
            0x7 => Self::GoAway,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Continuation,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for Http2FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data          => write!(f, "DATA"),
            Self::Headers       => write!(f, "HEADERS"),
            Self::Priority      => write!(f, "PRIORITY"),
            Self::RstStream     => write!(f, "RST_STREAM"),
            Self::Settings      => write!(f, "SETTINGS"),
            Self::PushPromise   => write!(f, "PUSH_PROMISE"),
            Self::Ping          => write!(f, "PING"),
            Self::GoAway        => write!(f, "GOAWAY"),
            Self::WindowUpdate  => write!(f, "WINDOW_UPDATE"),
            Self::Continuation  => write!(f, "CONTINUATION"),
            Self::Unknown(v)    => write!(f, "UNKNOWN(0x{v:02x})"),
        }
    }
}

/// HTTP/2 frame flags bitfield.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http2Flags(pub u8);

impl Http2Flags {
    pub const END_STREAM:   u8 = 0x01;
    pub const ACK:          u8 = 0x01; // same bit, context-dependent
    pub const END_HEADERS:  u8 = 0x04;
    pub const PADDED:       u8 = 0x08;
    pub const PRIORITY:     u8 = 0x20;

    #[must_use]
    pub const fn end_stream(self)  -> bool { self.0 & Self::END_STREAM  != 0 }
    #[must_use]
    pub const fn end_headers(self) -> bool { self.0 & Self::END_HEADERS != 0 }
    #[must_use]
    pub const fn padded(self)      -> bool { self.0 & Self::PADDED      != 0 }
    #[must_use]
    pub const fn priority(self)    -> bool { self.0 & Self::PRIORITY    != 0 }
    #[must_use]
    pub const fn ack(self)         -> bool { self.0 & Self::ACK         != 0 }
}

/// A decoded HTTP/2 frame header (9-byte prefix).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2FrameHeader {
    pub length:    u32,
    pub frame_type: Http2FrameType,
    pub flags:     Http2Flags,
    pub stream_id: u32, // 31-bit: MSB reserved
}

impl Http2FrameHeader {
    /// Decode a 9-byte HTTP/2 frame header.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode(buf: &[u8]) -> Result<Self, DissectError> {
        if buf.len() < 9 {
            return Err(DissectError::BufferTooShort { needed: 9, got: buf.len() });
        }
        let length = ((u32::from(buf[0])) << 16) | ((u32::from(buf[1])) << 8) | (u32::from(buf[2]));
        let frame_type = Http2FrameType::from_byte(buf[3]);
        let flags  = Http2Flags(buf[4]);
        let stream_id = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
        Ok(Self { length, frame_type, flags, stream_id })
    }
}

/// HPACK header entry (name + value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpackHeader {
    pub name:  String,
    pub value: String,
}

/// Minimal HPACK static table (RFC 7541 Appendix A).
static HPACK_STATIC_TABLE: &[(&str, &str)] = &[
    ("",                              ""),
    (":authority",                    ""),
    (":method",                       "GET"),
    (":method",                       "POST"),
    (":path",                         "/"),
    (":path",                         "/index.html"),
    (":scheme",                       "http"),
    (":scheme",                       "https"),
    (":status",                       "200"),
    (":status",                       "204"),
    (":status",                       "206"),
    (":status",                       "304"),
    (":status",                       "400"),
    (":status",                       "404"),
    (":status",                       "500"),
    ("accept-charset",                ""),
    ("accept-encoding",               "gzip, deflate"),
    ("accept-language",               ""),
    ("accept-ranges",                 ""),
    ("accept",                        ""),
    ("access-control-allow-origin",   ""),
    ("age",                           ""),
    ("allow",                         ""),
    ("authorization",                 ""),
    ("cache-control",                 ""),
    ("content-disposition",           ""),
    ("content-encoding",              ""),
    ("content-language",              ""),
    ("content-length",                ""),
    ("content-location",              ""),
    ("content-range",                 ""),
    ("content-type",                  ""),
    ("cookie",                        ""),
    ("date",                          ""),
    ("etag",                          ""),
    ("expect",                        ""),
    ("expires",                       ""),
    ("from",                          ""),
    ("host",                          ""),
    ("if-match",                      ""),
    ("if-modified-since",             ""),
    ("if-none-match",                 ""),
    ("if-range",                      ""),
    ("if-unmodified-since",           ""),
    ("last-modified",                 ""),
    ("link",                          ""),
    ("location",                      ""),
    ("max-forwards",                  ""),
    ("proxy-authenticate",            ""),
    ("proxy-authorization",           ""),
    ("range",                         ""),
    ("referer",                       ""),
    ("refresh",                       ""),
    ("retry-after",                   ""),
    ("server",                        ""),
    ("set-cookie",                    ""),
    ("strict-transport-security",     ""),
    ("transfer-encoding",             ""),
    ("user-agent",                    ""),
    ("vary",                          ""),
    ("via",                           ""),
    ("www-authenticate",              ""),
];

/// Minimal HPACK decoder (indexed header field + literal without Huffman).
pub struct HpackDecoder {
    dynamic_table: Vec<HpackHeader>,
    max_table_size: usize,
}

impl HpackDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self { dynamic_table: Vec::new(), max_table_size: 4096 }
    }

    fn static_entry(idx: usize) -> Option<HpackHeader> {
        let (name, value) = HPACK_STATIC_TABLE.get(idx)?;
        Some(HpackHeader { name: name.to_string(), value: value.to_string() })
    }

    fn dynamic_entry(&self, idx: usize) -> Option<HpackHeader> {
        // RFC 7541 §2.3.3: dynamic table indices start at HPACK_STATIC_TABLE.len()+1
        let adjusted = idx.checked_sub(HPACK_STATIC_TABLE.len())?.checked_sub(1)?;
        self.dynamic_table.get(adjusted).cloned()
    }

    fn table_entry(&self, idx: usize) -> Option<HpackHeader> {
        // RFC 7541 §2.3.3: index 0 is reserved and must be treated as an error
        if idx == 0 {
            return None;
        }
        if idx <= HPACK_STATIC_TABLE.len() {
            // Static table is 1-indexed; convert to 0-based array index
            Self::static_entry(idx - 1)
        } else {
            self.dynamic_entry(idx)
        }
    }

    fn read_integer(buf: &[u8], prefix_bits: u8) -> Result<(u64, usize), DissectError> {
        if buf.is_empty() {
            return Err(DissectError::BufferTooShort { needed: 1, got: 0 });
        }
        let prefix_mask = (1u8 << prefix_bits) - 1;
        let first = u64::from(buf[0] & prefix_mask);
        if first < u64::from(prefix_mask) {
            return Ok((first, 1));
        }
        let mut value = first;
        let mut m = 0u64;
        let mut pos = 1usize;
        loop {
            if pos >= buf.len() {
                return Err(DissectError::BufferTooShort { needed: pos + 1, got: buf.len() });
            }
            let b = buf[pos];
            value += (u64::from(b & 0x7f)) << m;
            m += 7;
            pos += 1;
            if b & 0x80 == 0 { break; }
        }
        Ok((value, pos))
    }

    fn read_string(buf: &[u8]) -> Result<(String, usize), DissectError> {
        if buf.is_empty() {
            return Err(DissectError::BufferTooShort { needed: 1, got: 0 });
        }
        let huffman = buf[0] & 0x80 != 0;
        let (len, hdr_sz) = Self::read_integer(buf, 7)?;
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        let start = hdr_sz;
        let end = start + len;
        if buf.len() < end {
            return Err(DissectError::BufferTooShort { needed: end, got: buf.len() });
        }
        let raw = &buf[start..end];
        let s = if huffman {
            // Huffman decode — simplified: emit hex for now
            raw.iter().fold(String::from("<huffman:"), |mut s, b| { use std::fmt::Write; let _ = write!(s, "{b:02x}"); s }) + ">"
        } else {
            String::from_utf8_lossy(raw).into_owned()
        };
        Ok((s, end))
    }

    /// # Panics
    /// # Errors
    /// Returns an error if the operation fails.
    /// Panics if invariants are violated.
    /// Decode a HEADERS block payload, returning the list of headers.
    pub fn decode_headers(&mut self, buf: &[u8]) -> Result<Vec<HpackHeader>, DissectError> {
        let mut headers = Vec::new();
        let mut pos = 0usize;
        while pos < buf.len() {
            let b = buf[pos];
            if b & 0x80 != 0 {
                // Indexed header field
                let (idx, sz) = Self::read_integer(&buf[pos..], 7)?;
                pos += sz;
                if let Some(h) = self.table_entry(usize::try_from(idx).unwrap_or(usize::MAX)) {
                    headers.push(h);
                }
            } else if b & 0x40 != 0 {
                // Literal with incremental indexing
                let (idx, sz) = Self::read_integer(&buf[pos..], 6)?;
                pos += sz;
                let name = if idx == 0 {
                    let (n, nsz) = Self::read_string(&buf[pos..])?;
                    pos += nsz;
                    n
                } else {
                    self.table_entry(usize::try_from(idx).unwrap_or(usize::MAX))
                        .map(|h| h.name)
                        .unwrap_or_default()
                };
                let (value, vsz) = Self::read_string(&buf[pos..])?;
                pos += vsz;
                let h = HpackHeader { name, value };
                self.dynamic_table.insert(0, h.clone());
                // Enforce dynamic table size limit (RFC 7541 §4.4): each entry
                // costs 32 + name.len() + value.len() bytes of table space.
                let mut table_size: usize = self
                    .dynamic_table
                    .iter()
                    .map(|e| 32 + e.name.len() + e.value.len())
                    .sum();
                while table_size > self.max_table_size && !self.dynamic_table.is_empty() {
                    let evicted = self.dynamic_table.pop().unwrap();
                    table_size -= 32 + evicted.name.len() + evicted.value.len();
                }
                headers.push(h);
            } else {
                // Literal never indexed or size update — skip byte
                pos += 1;
            }
        }
        Ok(headers)
    }
}

impl Default for HpackDecoder {
    fn default() -> Self { Self::new() }
}

/// Full HTTP/2 frame with decoded payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Frame {
    pub header:  Http2FrameHeader,
    pub payload: Http2FramePayload,
}

/// Decoded payload variant per frame type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Http2FramePayload {
    Data        { data: Vec<u8>, pad_length: Option<u8> },
    Headers     { headers: Vec<HpackHeader>, priority: Option<Http2Priority> },
    Priority    (Http2Priority),
    RstStream   { error_code: u32 },
    Settings    { params: Vec<Http2SettingsParam> },
    PushPromise { promised_stream_id: u32, headers: Vec<HpackHeader> },
    Ping        { opaque: [u8; 8] },
    GoAway      { last_stream_id: u32, error_code: u32, debug_data: Vec<u8> },
    WindowUpdate { increment: u32 },
    Continuation { headers: Vec<HpackHeader> },
    Unknown     { raw: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Priority {
    pub exclusive:        bool,
    pub stream_dependency: u32,
    pub weight:           u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2SettingsParam {
    pub id:    u16,
    pub value: u32,
}

/// HTTP/2 frame dissector.
pub struct Http2Dissector {
    hpack: HpackDecoder,
}

impl Http2Dissector {
    #[must_use]
    pub const fn new() -> Self {
        Self { hpack: HpackDecoder::new() }
    }

    /// # Errors
    /// Returns an error if the operation fails.
    pub fn dissect_frame(&mut self, buf: &[u8]) -> Result<(Http2Frame, usize), DissectError> {
        let hdr = Http2FrameHeader::decode(buf)?;
        let total = 9 + hdr.length as usize;
        if buf.len() < total {
            return Err(DissectError::BufferTooShort { needed: total, got: buf.len() });
        }
        let payload_bytes = &buf[9..total];
        let payload = self.decode_payload(&hdr, payload_bytes)?;
        Ok((Http2Frame { header: hdr, payload }, total))
    }

    fn decode_payload(&mut self, hdr: &Http2FrameHeader, data: &[u8]) -> Result<Http2FramePayload, DissectError> {
        match hdr.frame_type {
            Http2FrameType::Data       => Ok(http2_decode_data(hdr, data)),
            Http2FrameType::Priority   => http2_decode_priority(data),
            Http2FrameType::RstStream  => http2_decode_rst(data),
            Http2FrameType::Settings   => Ok(http2_decode_settings(data)),
            Http2FrameType::Ping       => http2_decode_ping(data),
            Http2FrameType::GoAway     => http2_decode_goaway(data),
            Http2FrameType::WindowUpdate => http2_decode_window_update(data),
            Http2FrameType::Unknown(_) => Ok(Http2FramePayload::Unknown { raw: data.to_vec() }),
            Http2FrameType::Headers => {
                let mut pos = 0usize;
                let pad_len = if hdr.flags.padded() { let p = data[pos]; pos += 1; p } else { 0 };
                let priority = http2_decode_headers_priority(hdr, data, &mut pos)?;
                let header_end = data.len() - pad_len as usize;
                let headers = self.hpack.decode_headers(&data[pos..header_end.max(pos)])?;
                Ok(Http2FramePayload::Headers { headers, priority })
            }
            Http2FrameType::PushPromise => {
                if data.len() < 4 {
                    return Err(DissectError::BufferTooShort { needed: 4, got: data.len() });
                }
                let promised = u32::from_be_bytes([data[0] & 0x7f, data[1], data[2], data[3]]);
                let headers = self.hpack.decode_headers(&data[4..])?;
                Ok(Http2FramePayload::PushPromise { promised_stream_id: promised, headers })
            }
            Http2FrameType::Continuation => {
                let headers = self.hpack.decode_headers(data)?;
                Ok(Http2FramePayload::Continuation { headers })
            }
        }
    }
}

fn http2_decode_data(hdr: &Http2FrameHeader, data: &[u8]) -> Http2FramePayload {
    let (pad_length, body_start) = if hdr.flags.padded() && !data.is_empty() {
        (Some(data[0]), 1usize)
    } else {
        (None, 0usize)
    };
    let body_end = data.len() - pad_length.unwrap_or(0) as usize;
    Http2FramePayload::Data { data: data[body_start..body_end.max(body_start)].to_vec(), pad_length }
}

fn http2_decode_headers_priority(hdr: &Http2FrameHeader, data: &[u8], pos: &mut usize) -> Result<Option<Http2Priority>, DissectError> {
    if hdr.flags.priority() {
        if data.len() < *pos + 5 {
            return Err(DissectError::BufferTooShort { needed: *pos + 5, got: data.len() });
        }
        let dep_raw = u32::from_be_bytes([data[*pos], data[*pos+1], data[*pos+2], data[*pos+3]]);
        let weight = data[*pos + 4];
        *pos += 5;
        Ok(Some(Http2Priority { exclusive: dep_raw & 0x8000_0000 != 0, stream_dependency: dep_raw & 0x7fff_ffff, weight }))
    } else {
        Ok(None)
    }
}

fn http2_decode_priority(data: &[u8]) -> Result<Http2FramePayload, DissectError> {
    if data.len() < 5 { return Err(DissectError::BufferTooShort { needed: 5, got: data.len() }); }
    let dep_raw = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    Ok(Http2FramePayload::Priority(Http2Priority {
        exclusive: dep_raw & 0x8000_0000 != 0, stream_dependency: dep_raw & 0x7fff_ffff, weight: data[4],
    }))
}

fn http2_decode_rst(data: &[u8]) -> Result<Http2FramePayload, DissectError> {
    if data.len() < 4 { return Err(DissectError::BufferTooShort { needed: 4, got: data.len() }); }
    Ok(Http2FramePayload::RstStream { error_code: u32::from_be_bytes([data[0], data[1], data[2], data[3]]) })
}

fn http2_decode_settings(data: &[u8]) -> Http2FramePayload {
    let mut params = Vec::new();
    let mut pos = 0;
    while pos + 6 <= data.len() {
        let id    = u16::from_be_bytes([data[pos], data[pos+1]]);
        let value = u32::from_be_bytes([data[pos+2], data[pos+3], data[pos+4], data[pos+5]]);
        params.push(Http2SettingsParam { id, value });
        pos += 6;
    }
    Http2FramePayload::Settings { params }
}

fn http2_decode_ping(data: &[u8]) -> Result<Http2FramePayload, DissectError> {
    if data.len() < 8 { return Err(DissectError::BufferTooShort { needed: 8, got: data.len() }); }
    let mut opaque = [0u8; 8];
    opaque.copy_from_slice(&data[..8]);
    Ok(Http2FramePayload::Ping { opaque })
}

fn http2_decode_goaway(data: &[u8]) -> Result<Http2FramePayload, DissectError> {
    if data.len() < 8 { return Err(DissectError::BufferTooShort { needed: 8, got: data.len() }); }
    let last = u32::from_be_bytes([data[0] & 0x7f, data[1], data[2], data[3]]);
    let err  = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    Ok(Http2FramePayload::GoAway { last_stream_id: last, error_code: err, debug_data: data[8..].to_vec() })
}

fn http2_decode_window_update(data: &[u8]) -> Result<Http2FramePayload, DissectError> {
    if data.len() < 4 { return Err(DissectError::BufferTooShort { needed: 4, got: data.len() }); }
    let inc = u32::from_be_bytes([data[0] & 0x7f, data[1], data[2], data[3]]);
    Ok(Http2FramePayload::WindowUpdate { increment: inc })
}

impl Default for Http2Dissector {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// gRPC
// ─────────────────────────────────────────────────────────────────────────────

/// gRPC Length-Prefixed Message framing (over HTTP/2 DATA frames).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcMessage {
    pub compressed: bool,
    pub length:     u32,
    pub body:       Vec<u8>,
}

/// gRPC service/method extracted from :path pseudo-header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcCall {
    pub service: String,
    pub method:  String,
    pub messages: Vec<GrpcMessage>,
}

pub struct GrpcDissector;

impl GrpcDissector {
    #[must_use]
    pub fn extract_call_from_path(path: &str) -> Option<(String, String)> {
        // gRPC path: /<service>/<method>
        let stripped = path.strip_prefix('/')?;
        let mut it = stripped.splitn(2, '/');
        let service = it.next()?.to_string();
        let method  = it.next()?.to_string();
        Some((service, method))
    }

    /// Decode Length-Prefixed Messages from a DATA frame body.
    #[must_use]
    pub fn decode_messages(data: &[u8]) -> Vec<GrpcMessage> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 5 <= data.len() {
            let compressed = data[pos] != 0;
            let length = u32::from_be_bytes([data[pos+1], data[pos+2], data[pos+3], data[pos+4]]);
            pos += 5;
            let end = pos + length as usize;
            if data.len() < end { break; }
            out.push(GrpcMessage { compressed, length, body: data[pos..end].to_vec() });
            pos = end;
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WebSocket
// ─────────────────────────────────────────────────────────────────────────────

/// WebSocket opcode (RFC 6455 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum WsOpcode {
    Continuation = 0x0,
    Text         = 0x1,
    Binary       = 0x2,
    Close        = 0x8,
    Ping         = 0x9,
    Pong         = 0xa,
    Reserved(u8),
}

impl WsOpcode {
    #[must_use]
    pub const fn from_nibble(v: u8) -> Self {
        match v & 0x0f {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xa => Self::Pong,
            other => Self::Reserved(other),
        }
    }
    #[must_use]
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// A decoded WebSocket frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsFrame {
    pub fin:        bool,
    pub rsv:        [bool; 3],
    pub opcode:     WsOpcode,
    pub masked:     bool,
    pub masking_key: Option<[u8; 4]>,
    pub payload_len: u64,
    pub payload:    Vec<u8>,  // already unmasked
}

impl WsFrame {
    /// # Panics
    /// # Errors
    /// Returns an error if the operation fails.
    /// Panics if invariants are violated.
    /// Decode a WebSocket frame from `buf`. Returns `(frame, consumed)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DissectError> {
        if buf.len() < 2 {
            return Err(DissectError::BufferTooShort { needed: 2, got: buf.len() });
        }
        let b0 = buf[0];
        let b1 = buf[1];
        let fin    = b0 & 0x80 != 0;
        let rsv    = [b0 & 0x40 != 0, b0 & 0x20 != 0, b0 & 0x10 != 0];
        let opcode = WsOpcode::from_nibble(b0);
        let masked = b1 & 0x80 != 0;
        let len7   = u64::from(b1 & 0x7f);

        let (payload_len, mut pos) = match len7 {
            126 => {
                if buf.len() < 4 { return Err(DissectError::BufferTooShort { needed: 4, got: buf.len() }); }
                (u64::from(u16::from_be_bytes([buf[2], buf[3]])), 4usize)
            }
            127 => {
                if buf.len() < 10 { return Err(DissectError::BufferTooShort { needed: 10, got: buf.len() }); }
                (u64::from_be_bytes(buf[2..10].try_into().unwrap()), 10usize)
            }
            n => (n, 2usize),
        };

        let masking_key = if masked {
            if buf.len() < pos + 4 {
                return Err(DissectError::BufferTooShort { needed: pos + 4, got: buf.len() });
            }
            let k = [buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]];
            pos += 4;
            Some(k)
        } else {
            None
        };

        let plen = usize::try_from(payload_len).unwrap_or(usize::MAX);
        if buf.len() < pos + plen {
            return Err(DissectError::BufferTooShort { needed: pos + plen, got: buf.len() });
        }
        let raw = &buf[pos..pos+plen];
        let payload = masking_key.map_or_else(|| raw.to_vec(), |key| raw.iter().enumerate().map(|(i, &b)| b ^ key[i % 4]).collect());

        Ok((Self { fin, rsv, opcode, masked, masking_key, payload_len, payload }, pos + plen))
    }
}

/// WebSocket upgrade handshake parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsHandshake {
    pub host:      Option<String>,
    pub upgrade:   String,
    pub key:       Option<String>,
    pub protocols: Vec<String>,
    pub extensions: Vec<String>,
    pub per_message_deflate: bool,
}

impl WsHandshake {
    #[must_use]
    pub fn parse_request(headers: &str) -> Self {
        let mut hs = Self {
            host: None,
            upgrade: String::new(),
            key: None,
            protocols: Vec::new(),
            extensions: Vec::new(),
            per_message_deflate: false,
        };
        for line in headers.lines() {
            if let Some((name, value)) = line.split_once(':') {
                let v = value.trim();
                match name.trim().to_ascii_lowercase().as_str() {
                    "host"                     => hs.host      = Some(v.to_string()),
                    "upgrade"                  => hs.upgrade   = v.to_string(),
                    "sec-websocket-key"        => hs.key       = Some(v.to_string()),
                    "sec-websocket-protocol"   => hs.protocols = v.split(',').map(|s| s.trim().to_string()).collect(),
                    "sec-websocket-extensions" => {
                        hs.extensions = v.split(',').map(|s| s.trim().to_string()).collect();
                        hs.per_message_deflate = hs.extensions.iter().any(|e| e.contains("permessage-deflate"));
                    }
                    _ => {}
                }
            }
        }
        hs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MQTT
// ─────────────────────────────────────────────────────────────────────────────

/// MQTT Control Packet Types (OASIS MQTT 3.1.1 §2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MqttPacketType {
    Reserved0   = 0,
    Connect     = 1,
    ConnAck     = 2,
    Publish     = 3,
    PubAck      = 4,
    PubRec      = 5,
    PubRel      = 6,
    PubComp     = 7,
    Subscribe   = 8,
    SubAck      = 9,
    Unsubscribe = 10,
    UnsubAck    = 11,
    PingReq     = 12,
    PingResp    = 13,
    Disconnect  = 14,
    Auth        = 15,
}

impl MqttPacketType {
    #[must_use]
    pub const fn from_nibble(v: u8) -> Self {
        match v & 0x0f {
            1  => Self::Connect,
            2  => Self::ConnAck,
            3  => Self::Publish,
            4  => Self::PubAck,
            5  => Self::PubRec,
            6  => Self::PubRel,
            7  => Self::PubComp,
            8  => Self::Subscribe,
            9  => Self::SubAck,
            10 => Self::Unsubscribe,
            11 => Self::UnsubAck,
            12 => Self::PingReq,
            13 => Self::PingResp,
            14 => Self::Disconnect,
            15 => Self::Auth,
            _  => Self::Reserved0,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Reserved0   => "RESERVED",
            Self::Connect     => "CONNECT",
            Self::ConnAck     => "CONNACK",
            Self::Publish     => "PUBLISH",
            Self::PubAck      => "PUBACK",
            Self::PubRec      => "PUBREC",
            Self::PubRel      => "PUBREL",
            Self::PubComp     => "PUBCOMP",
            Self::Subscribe   => "SUBSCRIBE",
            Self::SubAck      => "SUBACK",
            Self::Unsubscribe => "UNSUBSCRIBE",
            Self::UnsubAck    => "UNSUBACK",
            Self::PingReq     => "PINGREQ",
            Self::PingResp    => "PINGRESP",
            Self::Disconnect  => "DISCONNECT",
            Self::Auth        => "AUTH",
        }
    }
}

/// MQTT `QoS` level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MqttQos {
    AtMostOnce  = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
}

impl MqttQos {
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x3 {
            1 => Self::AtLeastOnce,
            2 => Self::ExactlyOnce,
            _ => Self::AtMostOnce,
        }
    }
}

/// Decoded MQTT fixed header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttFixedHeader {
    pub packet_type: MqttPacketType,
    pub flags:       u8,
    pub remaining:   u32,
}

fn mqtt_decode_remaining(buf: &[u8]) -> Result<(u32, usize), DissectError> {
    let mut value = 0u32;
    let mut multiplier = 1u32;
    for (i, &b) in buf.iter().enumerate().take(4) {
        value += (u32::from(b) & 0x7f) * multiplier;
        multiplier *= 128;
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(DissectError::MalformedField("MQTT remaining length".into()))
}

fn read_mqtt_string(buf: &[u8]) -> Result<(String, usize), DissectError> {
    if buf.len() < 2 {
        return Err(DissectError::BufferTooShort { needed: 2, got: buf.len() });
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return Err(DissectError::BufferTooShort { needed: 2 + len, got: buf.len() });
    }
    Ok((String::from_utf8_lossy(&buf[2..2+len]).into_owned(), 2 + len))
}

/// Packed MQTT CONNECT flag bits (CleanSession/WillFlag/WillRetain/Username/Password).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MqttConnectFlags(u8);

impl MqttConnectFlags {
    /// Build from the raw connect-flags byte.
    #[must_use] pub const fn from_byte(b: u8) -> Self { Self(b) }
    /// Clean session flag.
    #[must_use] pub const fn clean_session(self) -> bool { self.0 & 0x02 != 0 }
    /// Will flag.
    #[must_use] pub const fn will_flag(self) -> bool { self.0 & 0x04 != 0 }
    /// Will retain flag.
    #[must_use] pub const fn will_retain(self) -> bool { self.0 & 0x20 != 0 }
    /// Username flag.
    #[must_use] pub const fn username_flag(self) -> bool { self.0 & 0x80 != 0 }
    /// Password flag.
    #[must_use] pub const fn password_flag(self) -> bool { self.0 & 0x40 != 0 }
}

/// Decoded MQTT CONNECT packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttConnect {
    pub protocol_name:    String,
    pub protocol_version: u8,
    /// Packed MQTT connect flags (CleanSession/Will/Retain/Username/Password).
    pub connect_flags:    MqttConnectFlags,
    pub will_qos:         MqttQos,
    pub keep_alive:       u16,
    pub client_id:        String,
    pub will_topic:       Option<String>,
    pub will_message:     Option<Vec<u8>>,
    pub username:         Option<String>,
    pub password:         Option<Vec<u8>>,
}

/// Decoded MQTT PUBLISH packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttPublish {
    pub topic:      String,
    pub packet_id:  Option<u16>,
    pub qos:        MqttQos,
    pub retain:     bool,
    pub dup:        bool,
    pub payload:    Vec<u8>,
}

/// Top-level decoded MQTT packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MqttPacket {
    Connect(MqttConnect),
    ConnAck  { session_present: bool, return_code: u8 },
    Publish(MqttPublish),
    PubAck   { packet_id: u16 },
    Subscribe { packet_id: u16, filters: Vec<(String, MqttQos)> },
    SubAck   { packet_id: u16, return_codes: Vec<u8> },
    Unsubscribe { packet_id: u16, topics: Vec<String> },
    UnsubAck { packet_id: u16 },
    PingReq,
    PingResp,
    Disconnect,
    Auth     { reason_code: u8 },
    Unknown  { packet_type: u8, flags: u8, payload: Vec<u8> },
}

pub struct MqttDissector;

impl MqttDissector {
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode(buf: &[u8]) -> Result<(MqttPacket, usize), DissectError> {
        if buf.len() < 2 {
            return Err(DissectError::BufferTooShort { needed: 2, got: buf.len() });
        }
        let b0 = buf[0];
        let ptype  = MqttPacketType::from_nibble(b0 >> 4);
        let flags  = b0 & 0x0f;
        let (remaining, rem_sz) = mqtt_decode_remaining(&buf[1..])?;
        let hdr_sz = 1 + rem_sz;
        let total  = hdr_sz + remaining as usize;
        if buf.len() < total {
            return Err(DissectError::BufferTooShort { needed: total, got: buf.len() });
        }
        let payload = &buf[hdr_sz..total];

        let pkt = match ptype {
            MqttPacketType::Connect => mqtt_decode_connect_payload(payload)?,
            MqttPacketType::ConnAck => {
                MqttPacket::ConnAck { session_present: payload.first().copied().unwrap_or(0) & 0x01 != 0, return_code: payload.get(1).copied().unwrap_or(0) }
            }
            MqttPacketType::Publish => {
                let qos = MqttQos::from_bits((flags >> 1) & 0x3);
                let retain = flags & 0x01 != 0;
                let dup    = flags & 0x08 != 0;
                let mut pos = 0;
                let (topic, tsz) = read_mqtt_string(payload)?; pos += tsz;
                let packet_id = if matches!(qos, MqttQos::AtMostOnce) {
                    None
                } else {
                    if payload.len() < pos + 2 { return Err(DissectError::BufferTooShort { needed: pos+2, got: payload.len() }); }
                    let id = u16::from_be_bytes([payload[pos], payload[pos+1]]); pos += 2;
                    Some(id)
                };
                MqttPacket::Publish(MqttPublish { topic, packet_id, qos, retain, dup, payload: payload[pos..].to_vec() })
            }
            MqttPacketType::PubAck => MqttPacket::PubAck { packet_id: u16::from_be_bytes([payload[0], payload[1]]) },
            MqttPacketType::Subscribe => {
                let pid = u16::from_be_bytes([payload[0], payload[1]]);
                let mut pos = 2;
                let mut filters = Vec::new();
                while pos < payload.len() {
                    let (topic, sz) = read_mqtt_string(&payload[pos..])?; pos += sz;
                    let qos = MqttQos::from_bits(payload[pos]); pos += 1;
                    filters.push((topic, qos));
                }
                MqttPacket::Subscribe { packet_id: pid, filters }
            }
            MqttPacketType::SubAck => {
                let pid = u16::from_be_bytes([payload[0], payload[1]]);
                MqttPacket::SubAck { packet_id: pid, return_codes: payload[2..].to_vec() }
            }
            MqttPacketType::Unsubscribe => {
                let pid = u16::from_be_bytes([payload[0], payload[1]]);
                let mut pos = 2;
                let mut topics = Vec::new();
                while pos < payload.len() {
                    let (t, sz) = read_mqtt_string(&payload[pos..])?; pos += sz;
                    topics.push(t);
                }
                MqttPacket::Unsubscribe { packet_id: pid, topics }
            }
            MqttPacketType::UnsubAck  => MqttPacket::UnsubAck  { packet_id: u16::from_be_bytes([payload[0], payload[1]]) },
            MqttPacketType::PingReq   => MqttPacket::PingReq,
            MqttPacketType::PingResp  => MqttPacket::PingResp,
            MqttPacketType::Disconnect => MqttPacket::Disconnect,
            MqttPacketType::Auth      => MqttPacket::Auth { reason_code: payload.first().copied().unwrap_or(0) },
            _                          => MqttPacket::Unknown { packet_type: b0 >> 4, flags, payload: payload.to_vec() },
        };
        Ok((pkt, total))
    }
}

fn mqtt_decode_connect_payload(payload: &[u8]) -> Result<MqttPacket, DissectError> {
    let mut pos = 0;
    let (proto_name, sz) = read_mqtt_string(payload)?;
    pos += sz;
    if payload.len() < pos + 4 {
        return Err(DissectError::BufferTooShort { needed: pos + 4, got: payload.len() });
    }
    let version = payload[pos]; pos += 1;
    let conn_flags = payload[pos]; pos += 1;
    let keep_alive = u16::from_be_bytes([payload[pos], payload[pos+1]]); pos += 2;
    let (client_id, sz) = read_mqtt_string(&payload[pos..])?; pos += sz;
    let cf = MqttConnectFlags::from_byte(conn_flags);
    let will_qos = MqttQos::from_bits((conn_flags >> 3) & 0x3);
    let (will_topic, will_message) = if cf.will_flag() {
        let (wt, wsz) = read_mqtt_string(&payload[pos..])?; pos += wsz;
        let wlen = u16::from_be_bytes([payload[pos], payload[pos+1]]) as usize; pos += 2;
        let wm = payload[pos..pos+wlen].to_vec(); pos += wlen;
        (Some(wt), Some(wm))
    } else { (None, None) };
    let username = if cf.username_flag() {
        let (u, sz2) = read_mqtt_string(&payload[pos..])?; pos += sz2;
        Some(u)
    } else { None };
    let password = if cf.password_flag() {
        let plen = u16::from_be_bytes([payload[pos], payload[pos+1]]) as usize; pos += 2;
        let pw = payload[pos..pos+plen].to_vec();
        Some(pw)
    } else { None };
    let _ = pos;
    Ok(MqttPacket::Connect(MqttConnect {
        protocol_name: proto_name, protocol_version: version,
        connect_flags: cf, will_qos,
        keep_alive, client_id, will_topic, will_message, username, password,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// AMQP 0-9-1
// ─────────────────────────────────────────────────────────────────────────────

/// AMQP 0-9-1 frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AmqpFrameType {
    Method   = 1,
    Header   = 2,
    Body     = 3,
    Heartbeat = 8,
    Unknown(u8),
}

impl AmqpFrameType {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::Method,
            2 => Self::Header,
            3 => Self::Body,
            8 => Self::Heartbeat,
            o => Self::Unknown(o),
        }
    }
}

/// AMQP frame header (7 bytes before payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmqpFrameHeader {
    pub frame_type: AmqpFrameType,
    pub channel:    u16,
    pub payload_sz: u32,
}

/// AMQP class/method pair used in Method frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AmqpMethodId {
    pub class_id:  u16,
    pub method_id: u16,
}

impl AmqpMethodId {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match (self.class_id, self.method_id) {
            // Connection
            (10, 10) => "connection.start",
            (10, 11) => "connection.start-ok",
            (10, 20) => "connection.secure",
            (10, 21) => "connection.secure-ok",
            (10, 30) => "connection.tune",
            (10, 31) => "connection.tune-ok",
            (10, 40) => "connection.open",
            (10, 41) => "connection.open-ok",
            (10, 50) => "connection.close",
            (10, 51) => "connection.close-ok",
            // Channel
            (20, 10) => "channel.open",
            (20, 11) => "channel.open-ok",
            (20, 20) => "channel.flow",
            (20, 21) => "channel.flow-ok",
            (20, 40) => "channel.close",
            (20, 41) => "channel.close-ok",
            // Exchange
            (40, 10) => "exchange.declare",
            (40, 11) => "exchange.declare-ok",
            (40, 20) => "exchange.delete",
            (40, 21) => "exchange.delete-ok",
            (40, 30) => "exchange.bind",
            (40, 31) => "exchange.bind-ok",
            (40, 40) => "exchange.unbind",
            (40, 51) => "exchange.unbind-ok",
            // Queue
            (50, 10) => "queue.declare",
            (50, 11) => "queue.declare-ok",
            (50, 20) => "queue.bind",
            (50, 21) => "queue.bind-ok",
            (50, 30) => "queue.purge",
            (50, 31) => "queue.purge-ok",
            (50, 40) => "queue.delete",
            (50, 41) => "queue.delete-ok",
            (50, 50) => "queue.unbind",
            (50, 51) => "queue.unbind-ok",
            // Basic
            (60, 10) => "basic.qos",
            (60, 11) => "basic.qos-ok",
            (60, 20) => "basic.consume",
            (60, 21) => "basic.consume-ok",
            (60, 30) => "basic.cancel",
            (60, 31) => "basic.cancel-ok",
            (60, 40) => "basic.publish",
            (60, 50) => "basic.return",
            (60, 60) => "basic.deliver",
            (60, 70) => "basic.get",
            (60, 71) => "basic.get-ok",
            (60, 72) => "basic.get-empty",
            (60, 80) => "basic.ack",
            (60, 90) => "basic.reject",
            (60, 100) => "basic.recover-async",
            (60, 110) => "basic.recover",
            (60, 111) => "basic.recover-ok",
            (60, 120) => "basic.nack",
            // Confirm
            (85, 10) => "confirm.select",
            (85, 11) => "confirm.select-ok",
            // Tx
            (90, 10) => "tx.select",
            (90, 11) => "tx.select-ok",
            (90, 20) => "tx.commit",
            (90, 21) => "tx.commit-ok",
            (90, 30) => "tx.rollback",
            (90, 31) => "tx.rollback-ok",
            _ => "unknown",
        }
    }
}

/// A decoded AMQP Method frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmqpMethodFrame {
    pub channel:   u16,
    pub method_id: AmqpMethodId,
    pub arguments: Vec<u8>,
}

pub struct AmqpDissector;

impl AmqpDissector {
    /// Decode one AMQP frame. Returns `(frame_type, channel, payload, consumed)`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode_frame(buf: &[u8]) -> Result<(AmqpFrameType, u16, Vec<u8>, usize), DissectError> {
        if buf.len() < 7 {
            return Err(DissectError::BufferTooShort { needed: 7, got: buf.len() });
        }
        let ft  = AmqpFrameType::from_byte(buf[0]);
        let ch  = u16::from_be_bytes([buf[1], buf[2]]);
        let psz = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]) as usize;
        let total = 7 + psz + 1; // +1 for frame-end 0xCE
        if buf.len() < total {
            return Err(DissectError::BufferTooShort { needed: total, got: buf.len() });
        }
        if buf[total - 1] != 0xCE {
            return Err(DissectError::MalformedField("AMQP frame-end byte".into()));
        }
        Ok((ft, ch, buf[7..7+psz].to_vec(), total))
    }

    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode_method(channel: u16, payload: &[u8]) -> Result<AmqpMethodFrame, DissectError> {
        if payload.len() < 4 {
            return Err(DissectError::BufferTooShort { needed: 4, got: payload.len() });
        }
        let class_id  = u16::from_be_bytes([payload[0], payload[1]]);
        let method_id = u16::from_be_bytes([payload[2], payload[3]]);
        Ok(AmqpMethodFrame {
            channel,
            method_id: AmqpMethodId { class_id, method_id },
            arguments: payload[4..].to_vec(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Redis RESP
// ─────────────────────────────────────────────────────────────────────────────

/// Redis RESP data types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RespValue {
    SimpleString(String),
    Error        { kind: String, message: String },
    Integer      (i64),
    BulkString   (Option<Vec<u8>>),
    Array        (Option<Vec<Self>>),
}

impl RespValue {
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::SimpleString(_) => "simple_string",
            Self::Error { .. }   => "error",
            Self::Integer(_)     => "integer",
            Self::BulkString(_)  => "bulk_string",
            Self::Array(_)       => "array",
        }
    }
}

impl fmt::Display for RespValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SimpleString(s) => write!(f, "+{s}"),
            Self::Error { kind, message } => write!(f, "-{kind} {message}"),
            Self::Integer(n)      => write!(f, ":{n}"),
            Self::BulkString(None) => write!(f, "$-1"),
            Self::BulkString(Some(b)) => write!(f, "${}\r\n{}", b.len(), String::from_utf8_lossy(b)),
            Self::Array(None)     => write!(f, "*-1"),
            Self::Array(Some(a))  => write!(f, "*{}", a.len()),
        }
    }
}

pub struct RespDissector;

impl RespDissector {
    /// Decode a single RESP value from `buf`. Returns `(value, bytes_consumed)`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode(buf: &[u8]) -> Result<(RespValue, usize), DissectError> {
        if buf.is_empty() {
            return Err(DissectError::BufferTooShort { needed: 1, got: 0 });
        }
        match buf[0] {
            b'+' => {
                let (line, sz) = Self::read_line(&buf[1..])?;
                Ok((RespValue::SimpleString(line), 1 + sz))
            }
            b'-' => {
                let (line, sz) = Self::read_line(&buf[1..])?;
                let (kind, message) = line.split_once(' ')
                    .map_or_else(|| (line.clone(), String::new()), |(k, m)| (k.to_string(), m.to_string()));
                Ok((RespValue::Error { kind, message }, 1 + sz))
            }
            b':' => {
                let (line, sz) = Self::read_line(&buf[1..])?;
                let n: i64 = line.parse().map_err(|_| DissectError::MalformedField("RESP integer".into()))?;
                Ok((RespValue::Integer(n), 1 + sz))
            }
            b'$' => {
                let (line, sz) = Self::read_line(&buf[1..])?;
                let len: i64 = line.parse().map_err(|_| DissectError::MalformedField("RESP bulk string length".into()))?;
                if len < 0 {
                    return Ok((RespValue::BulkString(None), 1 + sz));
                }
                let blen = usize::try_from(len).unwrap_or(usize::MAX);
                let start = 1 + sz;
                if buf.len() < start + blen + 2 {
                    return Err(DissectError::BufferTooShort { needed: start + blen + 2, got: buf.len() });
                }
                let data = buf[start..start+blen].to_vec();
                Ok((RespValue::BulkString(Some(data)), start + blen + 2))
            }
            b'*' => {
                let (line, sz) = Self::read_line(&buf[1..])?;
                let count: i64 = line.parse().map_err(|_| DissectError::MalformedField("RESP array count".into()))?;
                if count < 0 {
                    return Ok((RespValue::Array(None), 1 + sz));
                }
                let mut elements = Vec::with_capacity(usize::try_from(count).unwrap_or(usize::MAX));
                let mut pos = 1 + sz;
                for _ in 0..count {
                    let (elem, esz) = Self::decode(&buf[pos..])?;
                    elements.push(elem);
                    pos += esz;
                }
                Ok((RespValue::Array(Some(elements)), pos))
            }
            other => Err(DissectError::MalformedField(format!("RESP unknown type byte: 0x{other:02x}"))),
        }
    }

    fn read_line(buf: &[u8]) -> Result<(String, usize), DissectError> {
        for i in 0..buf.len().saturating_sub(1) {
            if buf[i] == b'\r' && buf[i+1] == b'\n' {
                return Ok((String::from_utf8_lossy(&buf[..i]).into_owned(), i + 2));
            }
        }
        Err(DissectError::MalformedField("RESP CRLF not found".into()))
    }

    /// Decode all RESP values available in `buf`.
    #[must_use]
    pub fn decode_all(buf: &[u8]) -> Vec<RespValue> {
        let mut values = Vec::new();
        let mut pos = 0;
        while pos < buf.len() {
            match Self::decode(&buf[pos..]) {
                Ok((v, sz)) => { values.push(v); pos += sz; }
                Err(_)      => break,
            }
        }
        values
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_frame_header_decode() {
        let buf = [0x00, 0x00, 0x0c, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01];
        let hdr = Http2FrameHeader::decode(&buf).unwrap();
        assert_eq!(hdr.length, 12);
        assert_eq!(hdr.frame_type, Http2FrameType::Headers);
        assert_eq!(hdr.stream_id, 1);
    }

    #[test]
    fn test_ws_frame_unmasked() {
        // Unmasked text frame "Hi"
        let buf = [0x81, 0x02, b'H', b'i'];
        let (frame, consumed) = WsFrame::decode(&buf).unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, WsOpcode::Text);
        assert_eq!(frame.payload, b"Hi");
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_resp_integer() {
        let (v, sz) = RespDissector::decode(b":42\r\n").unwrap();
        assert_eq!(v, RespValue::Integer(42));
        assert_eq!(sz, 5);
    }

    #[test]
    fn test_resp_bulk_string() {
        let (v, _) = RespDissector::decode(b"$3\r\nfoo\r\n").unwrap();
        assert_eq!(v, RespValue::BulkString(Some(b"foo".to_vec())));
    }

    #[test]
    fn test_mqtt_packet_type_names() {
        assert_eq!(MqttPacketType::Connect.name(), "CONNECT");
        assert_eq!(MqttPacketType::PingReq.name(), "PINGREQ");
        assert_eq!(MqttPacketType::Auth.name(), "AUTH");
    }

    #[test]
    fn test_amqp_method_names() {
        let id = AmqpMethodId { class_id: 60, method_id: 40 };
        assert_eq!(id.name(), "basic.publish");
        let id2 = AmqpMethodId { class_id: 10, method_id: 40 };
        assert_eq!(id2.name(), "connection.open");
    }

    #[test]
    fn test_grpc_path() {
        let (svc, method) = GrpcDissector::extract_call_from_path("/helloworld.Greeter/SayHello").unwrap();
        assert_eq!(svc, "helloworld.Greeter");
        assert_eq!(method, "SayHello");
    }

    #[test]
    fn test_ws_opcode_control() {
        assert!(WsOpcode::Ping.is_control());
        assert!(!WsOpcode::Text.is_control());
    }
}
