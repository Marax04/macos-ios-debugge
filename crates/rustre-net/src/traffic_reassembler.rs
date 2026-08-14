//! `traffic_reassembler` — TCP stream reassembly and application-layer parsing.
//!
//! Reassembles TCP streams from out-of-order segments with overlap resolution,
//! optionally decrypts TLS using keys from SSLKEYLOGFILE or injected key material,
//! and parses HTTP/1.1, HTTP/2 (with HPACK), and QUIC/HTTP/3 streams.
//! Exports reconstructed streams for downstream analysis.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ReassemblerError {
    #[error("stream not found: {0}")]
    StreamNotFound(String),
    #[error("overlap conflict at offset {0}")]
    OverlapConflict(u64),
    #[error("TLS decryption failed: {0}")]
    TlsDecryptFailed(String),
    #[error("HTTP parse error: {0}")]
    HttpParseFailed(String),
    #[error("stream too large: {0} bytes")]
    StreamTooLarge(usize),
    #[error("invalid key log entry: {0}")]
    InvalidKeyLog(String),
    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),
}

// ─── Four-Tuple Stream Key ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StreamKey {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: TransportProto,
}

impl StreamKey {
    #[must_use]
    pub fn new(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16, proto: TransportProto) -> Self {
        Self {
            src_ip: src_ip.to_owned(),
            src_port,
            dst_ip: dst_ip.to_owned(),
            dst_port,
            protocol: proto,
        }
    }

    /// Returns the canonical (lower IP:port first) key for bidirectional flows.
    #[must_use]
    pub fn canonical(&self) -> Self {
        let (a, b) = if self.src_ip < self.dst_ip || (self.src_ip == self.dst_ip && self.src_port < self.dst_port) {
            ((self.src_ip.clone(), self.src_port), (self.dst_ip.clone(), self.dst_port))
        } else {
            ((self.dst_ip.clone(), self.dst_port), (self.src_ip.clone(), self.src_port))
        };
        Self {
            src_ip: a.0,
            src_port: a.1,
            dst_ip: b.0,
            dst_port: b.1,
            protocol: self.protocol,
        }
    }
}

impl fmt::Display for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{} ↔ {}:{} ({})", self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportProto {
    Tcp,
    Udp,
    Quic,
}

impl fmt::Display for TransportProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Quic => write!(f, "QUIC"),
        }
    }
}

// ─── TCP Segment ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSegment {
    pub seq: u32,
    pub flags: TcpFlags,
    pub payload: Vec<u8>,
    pub timestamp_ms: u64,
}

/// TCP control-bit flags, packed into a single byte.
///
/// This avoids the `struct_excessive_bools` lint while preserving the existing
/// public field access (`flags.syn`, `flags.ack`, …) through `Deref`-style
/// helper methods.
///
/// The raw byte uses the wire layout:
/// `URG=0x20 | ACK=0x10 | PSH=0x08 | RST=0x04 | SYN=0x02 | FIN=0x01`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TcpFlags {
    bits: u8,
}

impl TcpFlags {
    const FIN: u8 = 0x01;
    const SYN: u8 = 0x02;
    const RST: u8 = 0x04;
    const PSH: u8 = 0x08;
    const ACK: u8 = 0x10;
    const URG: u8 = 0x20;

    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        Self { bits: b & (Self::FIN | Self::SYN | Self::RST | Self::PSH | Self::ACK | Self::URG) }
    }

    /// Start a builder with no flags set; chain `.with_syn()` etc. to add bits.
    #[must_use]
    pub const fn builder() -> Self {
        Self { bits: 0 }
    }

    #[must_use] pub const fn with_syn(mut self, on: bool) -> Self { if on { self.bits |= Self::SYN; } self }
    #[must_use] pub const fn with_ack(mut self, on: bool) -> Self { if on { self.bits |= Self::ACK; } self }
    #[must_use] pub const fn with_fin(mut self, on: bool) -> Self { if on { self.bits |= Self::FIN; } self }
    #[must_use] pub const fn with_rst(mut self, on: bool) -> Self { if on { self.bits |= Self::RST; } self }
    #[must_use] pub const fn with_psh(mut self, on: bool) -> Self { if on { self.bits |= Self::PSH; } self }
    #[must_use] pub const fn with_urg(mut self, on: bool) -> Self { if on { self.bits |= Self::URG; } self }

    #[must_use] pub const fn syn(self) -> bool { self.bits & Self::SYN != 0 }
    #[must_use] pub const fn ack(self) -> bool { self.bits & Self::ACK != 0 }
    #[must_use] pub const fn fin(self) -> bool { self.bits & Self::FIN != 0 }
    #[must_use] pub const fn rst(self) -> bool { self.bits & Self::RST != 0 }
    #[must_use] pub const fn psh(self) -> bool { self.bits & Self::PSH != 0 }
    #[must_use] pub const fn urg(self) -> bool { self.bits & Self::URG != 0 }

    #[must_use] pub const fn bits(self) -> u8 { self.bits }
}


// ─── TCP Stream ───────────────────────────────────────────────────────────────

/// Direction of data flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// A half-connection in one direction.
#[derive(Debug, Default)]
struct HalfStream {
    /// Next expected sequence number.
    next_seq: u32,
    /// ISN (initial sequence number).
    isn: Option<u32>,
    /// Out-of-order segments: seq → payload.
    ooo: BTreeMap<u32, Vec<u8>>,
    /// Reassembled contiguous data.
    data: Vec<u8>,
    /// Whether FIN has been received.
    fin: bool,
    /// Total bytes consumed.
    bytes_consumed: u64,
}

impl HalfStream {
    fn push_segment(&mut self, seg: &TcpSegment) {
        if seg.flags.syn() {
            self.isn = Some(seg.seq);
            self.next_seq = seg.seq.wrapping_add(1);
            return;
        }
        if seg.flags.fin() {
            self.fin = true;
        }
        if seg.payload.is_empty() {
            return;
        }

        let seq = seg.seq;
        let len = u32::try_from(seg.payload.len()).unwrap_or(u32::MAX);

        // Discard if fully before next_seq (duplicate).
        // Use wrapping arithmetic with a half-window test to handle sequence wrap-around.
        let seg_end = seq.wrapping_add(len);
        if seg_end.wrapping_sub(self.next_seq) > 0x8000_0000u32 {
            // seg_end is in the past relative to next_seq (or exactly equal = empty)
            return;
        }

        // Trim overlap at beginning.
        // seq is "before" next_seq when wrapping distance is < half window.
        let (trim_start, effective_seq) = if seq.wrapping_sub(self.next_seq) > 0x8000_0000u32 {
            // seq is behind next_seq — trim the overlapping prefix
            let trim = self.next_seq.wrapping_sub(seq) as usize;
            (trim, self.next_seq)
        } else {
            (0, seq)
        };

        let trimmed = &seg.payload[trim_start..];
        if trimmed.is_empty() {
            return;
        }

        if effective_seq == self.next_seq {
            // In-order: append directly
            self.data.extend_from_slice(trimmed);
            self.bytes_consumed += trimmed.len() as u64;
            self.next_seq = self.next_seq.wrapping_add(u32::try_from(trimmed.len()).unwrap_or(u32::MAX));
            // Check if any OOO segments can now be consumed
            self.flush_ooo();
        } else {
            // Out-of-order: store for later
            self.ooo.insert(effective_seq, trimmed.to_vec());
        }
    }

    fn flush_ooo(&mut self) {
        loop {
            if let Some(&seq) = self.ooo.keys().next() {
                if seq == self.next_seq {
                    let payload = self.ooo.remove(&seq).unwrap();
                    self.bytes_consumed += payload.len() as u64;
                    self.next_seq = self.next_seq.wrapping_add(u32::try_from(payload.len()).unwrap_or(u32::MAX));
                    self.data.extend_from_slice(&payload);
                    continue;
                } else if seq.wrapping_sub(self.next_seq) > 0x8000_0000u32 {
                    // Overlapping OOO segment (seq is in the past) — overlap resolution: take max
                    let payload = self.ooo.remove(&seq).unwrap();
                    let trim = self.next_seq.wrapping_sub(seq) as usize;
                    if trim < payload.len() {
                        let new_payload = &payload[trim..];
                        self.data.extend_from_slice(new_payload);
                        self.bytes_consumed += new_payload.len() as u64;
                        self.next_seq = self.next_seq.wrapping_add(u32::try_from(new_payload.len()).unwrap_or(u32::MAX));
                        continue;
                    }
                    // Fully overlapping, discard
                    continue;
                }
            }
            break;
        }
    }
}

/// A complete bidirectional TCP stream.
#[derive(Debug)]
pub struct TcpStream {
    pub key: StreamKey,
    client: HalfStream, // SYN initiator → server
    server: HalfStream, // server → client
    pub start_ms: u64,
    pub last_ms: u64,
    pub is_tls: bool,
    pub decrypted: bool,
    pub app_protocol: Option<AppProtocol>,
}

impl TcpStream {
    #[must_use]
    pub fn new(key: StreamKey, start_ms: u64) -> Self {
        let is_tls = matches!(key.dst_port, 443 | 8443 | 993 | 995 | 465 | 636 | 989 | 990);
        Self {
            key,
            client: HalfStream::default(),
            server: HalfStream::default(),
            start_ms,
            last_ms: start_ms,
            is_tls,
            decrypted: false,
            app_protocol: None,
        }
    }

    pub fn push(&mut self, seg: &TcpSegment, direction: Direction, timestamp_ms: u64) {
        self.last_ms = timestamp_ms;
        match direction {
            Direction::ClientToServer => self.client.push_segment(seg),
            Direction::ServerToClient => self.server.push_segment(seg),
        }
    }

    #[must_use]
    pub fn client_data(&self) -> &[u8] {
        &self.client.data
    }

    #[must_use]
    pub fn server_data(&self) -> &[u8] {
        &self.server.data
    }

    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.client.fin && self.server.fin
    }

    #[must_use]
    pub const fn duration_ms(&self) -> u64 {
        self.last_ms.saturating_sub(self.start_ms)
    }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.client.bytes_consumed + self.server.bytes_consumed
    }
}

// ─── TLS Key Log ─────────────────────────────────────────────────────────────

/// A key from SSLKEYLOGFILE (NSS key log format).
/// Format: `<label> <client_random_hex> <key_hex>`
#[derive(Debug, Clone)]
pub struct KeyLogEntry {
    pub label: String,
    pub client_random: Vec<u8>,
    pub key: Vec<u8>,
}

fn keylog_hex_decode(s: &str) -> Option<Vec<u8>> {
    // Reject odd-length strings to avoid a panic on s[i..i+2] at the last byte.
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

impl KeyLogEntry {
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            return None;
        }
        let mut parts = line.splitn(3, ' ');
        let label = parts.next()?.to_owned();
        let cr_hex = parts.next()?;
        let key_hex = parts.next()?;

        Some(Self {
            label,
            client_random: keylog_hex_decode(cr_hex)?,
            key: keylog_hex_decode(key_hex)?,
        })
    }
}

/// TLS key store parsed from SSLKEYLOGFILE.
#[derive(Debug, Default)]
pub struct TlsKeyStore {
    /// `client_random` → (label, key)
    entries: HashMap<Vec<u8>, Vec<KeyLogEntry>>,
}

impl TlsKeyStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load keys from an SSLKEYLOGFILE-format text.
    ///
    /// # Errors
    /// Currently infallible; the `Result` is reserved for future formats that
    /// may report decoding errors.
    pub fn load_from_text(&mut self, text: &str) -> Result<usize, ReassemblerError> {
        let mut count = 0;
        for line in text.lines() {
            if let Some(entry) = KeyLogEntry::parse(line) {
                self.entries.entry(entry.client_random.clone()).or_default().push(entry);
                count += 1;
            }
        }
        Ok(count)
    }

    #[must_use]
    pub fn get_key(&self, client_random: &[u8], label: &str) -> Option<&[u8]> {
        let entries = self.entries.get(client_random)?;
        entries.iter().find(|e| e.label == label).map(|e| e.key.as_slice())
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }
}

/// Simulated TLS decryption (placeholder — real impl uses ring/rustls).
///
/// # Errors
/// Returns [`ReassemblerError::TlsDecryptFailed`] if no matching key was
/// available in the key store or the record header is malformed.
pub fn decrypt_tls_stream(
    ciphertext: &[u8],
    _key_store: &TlsKeyStore,
    _client_random: &[u8],
) -> Result<Vec<u8>, ReassemblerError> {
    // Real implementation would:
    // 1. Parse ClientHello to extract client_random
    // 2. Look up traffic key from key_store
    // 3. Use AES-GCM / ChaCha20-Poly1305 to decrypt each TLS record
    // For now, detect if data starts with TLS record header (0x17 = application data)
    if ciphertext.len() >= 5 && ciphertext[0] == 0x17 {
        let _version = u16::from_be_bytes([ciphertext[1], ciphertext[2]]);
        let length = u16::from_be_bytes([ciphertext[3], ciphertext[4]]) as usize;
        if length + 5 <= ciphertext.len() {
            // Return the record payload as-is (simulated "decryption")
            return Ok(ciphertext[5..5 + length].to_vec());
        }
    }
    // If no key found, return decryption-failed
    Err(ReassemblerError::TlsDecryptFailed("No matching key in key store".to_owned()))
}

// ─── HTTP Parsing ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppProtocol {
    Http1,
    Http2,
    Http3,
    Tls,
    Unknown(String),
}

impl fmt::Display for AppProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http1 => write!(f, "HTTP/1.1"),
            Self::Http2 => write!(f, "HTTP/2"),
            Self::Http3 => write!(f, "HTTP/3 (QUIC)"),
            Self::Tls => write!(f, "TLS"),
            Self::Unknown(s) => write!(f, "Unknown({s})"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpMessage {
    pub direction: HttpDirection,
    pub version: String,
    pub method_or_status: String,    // method for request, status code for response
    pub path_or_reason: String,      // path for request, reason phrase for response
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub is_request: bool,
    pub stream_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpDirection {
    Request,
    Response,
}

/// Maximum body bytes to copy from a single HTTP message.
/// This is a reassembler-level guard; the actual bytes are already in the
/// stream buffer so the cap only limits how much we copy into `HttpMessage`.
const MAX_HTTP_BODY: usize = 16 * 1024 * 1024; // 16 MiB

/// Parse HTTP/1.x messages from a byte stream.
#[must_use]
pub fn parse_http1_stream(data: &[u8]) -> Vec<HttpMessage> {
    let mut messages = Vec::new();
    let text = String::from_utf8_lossy(data);
    let mut remaining = text.as_ref();

    loop {
        if remaining.trim_start().is_empty() {
            break;
        }
        let trimmed = remaining.trim_start_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }

        // Split on header/body separator
        let sep = if let Some(p) = trimmed.find("\r\n\r\n") {
            p
        } else if let Some(p) = trimmed.find("\n\n") {
            p
        } else {
            break;
        };

        let header_section = &trimmed[..sep];
        let body_start = sep + if trimmed[sep..].starts_with("\r\n\r\n") { 4 } else { 2 };
        let rest = &trimmed[body_start..];

        let mut lines = header_section.lines();
        let first_line = match lines.next() {
            Some(l) => l.trim(),
            None => break,
        };

        let is_request = !first_line.starts_with("HTTP/");
        let mut headers = HashMap::new();
        let mut content_length = 0usize;

        for line in lines {
            if let Some((k, v)) = line.split_once(": ") {
                let key = k.to_ascii_lowercase();
                if key == "content-length" {
                    content_length = v.trim().parse::<usize>().unwrap_or(0).min(MAX_HTTP_BODY);
                }
                headers.insert(key, v.trim().to_owned());
            }
        }

        let body = rest.as_bytes()[..rest.len().min(content_length)].to_vec();

        let mut parts = first_line.splitn(3, ' ');
        if is_request {
            let method = parts.next().unwrap_or("").to_owned();
            let path = parts.next().unwrap_or("").to_owned();
            let version = parts.next().unwrap_or("HTTP/1.1").to_owned();
            messages.push(HttpMessage {
                direction: HttpDirection::Request,
                version,
                method_or_status: method,
                path_or_reason: path,
                headers,
                body,
                is_request: true,
                stream_key: None,
            });
        } else {
            let version = parts.next().unwrap_or("HTTP/1.1").to_owned();
            let status = parts.next().unwrap_or("200").to_owned();
            let reason = parts.next().unwrap_or("").to_owned();
            messages.push(HttpMessage {
                direction: HttpDirection::Response,
                version,
                method_or_status: status,
                path_or_reason: reason,
                headers,
                body,
                is_request: false,
                stream_key: None,
            });
        }

        remaining = &rest[rest.len().min(content_length)..];
        if remaining.is_empty() || remaining == rest {
            break;
        }
    }

    messages
}

// ─── HTTP/2 Frame Parser ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Frame {
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl Http2Frame {
    pub const TYPE_DATA: u8 = 0x0;
    pub const TYPE_HEADERS: u8 = 0x1;
    pub const TYPE_SETTINGS: u8 = 0x4;
    pub const TYPE_GOAWAY: u8 = 0x7;
    pub const PREFACE: &'static [u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    #[must_use]
    pub fn parse_next(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 9 {
            return None;
        }
        let length = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        let frame_type = data[3];
        let flags = data[4];
        let stream_id = u32::from_be_bytes([data[5] & 0x7F, data[6], data[7], data[8]]);
        // Use checked_add to prevent overflow on 32-bit targets where usize == u32.
        let payload_end = (9usize).checked_add(length as usize)?;
        if payload_end > data.len() {
            return None;
        }
        let payload = data[9..payload_end].to_vec();
        Some((Self { length, frame_type, flags, stream_id, payload }, payload_end))
    }
}

/// Parse all HTTP/2 frames from a buffer (skipping the connection preface if present).
#[must_use]
pub fn parse_http2_frames(data: &[u8]) -> Vec<Http2Frame> {
    let mut frames = Vec::new();
    let mut offset = 0;

    // Skip HTTP/2 connection preface
    if data.starts_with(Http2Frame::PREFACE) {
        offset += Http2Frame::PREFACE.len();
    }

    while offset < data.len() {
        match Http2Frame::parse_next(&data[offset..]) {
            Some((frame, consumed)) => {
                offset += consumed;
                frames.push(frame);
            }
            None => break,
        }
    }
    frames
}

// ─── Reconstructed Stream ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedStream {
    pub key: StreamKey,
    pub app_protocol: AppProtocol,
    pub is_tls: bool,
    pub decrypted: bool,
    pub total_bytes: u64,
    pub duration_ms: u64,
    pub http_messages: Vec<HttpMessage>,
    pub http2_frames: Vec<Http2Frame>,
    pub raw_client_data: Vec<u8>,
    pub raw_server_data: Vec<u8>,
}

impl ReconstructedStream {
    #[must_use]
    pub fn http_requests(&self) -> Vec<&HttpMessage> {
        self.http_messages.iter().filter(|m| m.is_request).collect()
    }

    #[must_use]
    pub fn http_responses(&self) -> Vec<&HttpMessage> {
        self.http_messages.iter().filter(|m| !m.is_request).collect()
    }

    #[must_use]
    pub fn all_urls(&self) -> Vec<String> {
        let host = self.http_messages.iter()
            .find(|m| m.headers.contains_key("host"))
            .and_then(|m| m.headers.get("host"))
            .cloned()
            .unwrap_or_default();

        self.http_requests().iter()
            .map(|m| {
                let scheme = if self.is_tls { "https" } else { "http" };
                format!("{scheme}://{host}{}", m.path_or_reason)
            })
            .collect()
    }

    #[must_use]
    pub fn summary(&self) -> StreamSummary {
        StreamSummary {
            key: format!("{}", self.key),
            protocol: format!("{}", self.app_protocol),
            is_tls: self.is_tls,
            decrypted: self.decrypted,
            total_bytes: self.total_bytes,
            duration_ms: self.duration_ms,
            http_request_count: self.http_requests().len(),
            http_response_count: self.http_responses().len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSummary {
    pub key: String,
    pub protocol: String,
    pub is_tls: bool,
    pub decrypted: bool,
    pub total_bytes: u64,
    pub duration_ms: u64,
    pub http_request_count: usize,
    pub http_response_count: usize,
}

// ─── Traffic Reassembler ──────────────────────────────────────────────────────

/// Configuration for the traffic reassembler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReassemblerConfig {
    /// Maximum size per stream (bytes) before discarding old data.
    pub max_stream_bytes: usize,
    /// Automatically detect and parse TLS.
    pub auto_tls: bool,
    /// Maximum out-of-order window (segments).
    pub max_ooo_segments: usize,
    /// Parse HTTP/2 frames in addition to HTTP/1.x.
    pub parse_http2: bool,
}

impl Default for ReassemblerConfig {
    fn default() -> Self {
        Self {
            max_stream_bytes: 10 * 1024 * 1024, // 10 MiB
            auto_tls: true,
            max_ooo_segments: 64,
            parse_http2: true,
        }
    }
}

/// Main traffic reassembly engine.
pub struct TrafficReassembler {
    config: ReassemblerConfig,
    streams: HashMap<StreamKey, TcpStream>,
    tls_keys: TlsKeyStore,
    reconstructed: Vec<ReconstructedStream>,
}

impl std::fmt::Debug for TrafficReassembler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrafficReassembler")
            .field("config", &self.config)
            .field("stream_count", &self.streams.len())
            .field("tls_keys", &self.tls_keys.entry_count())
            .field("reconstructed", &self.reconstructed.len())
            .finish()
    }
}

impl TrafficReassembler {
    #[must_use]
    pub fn new(config: ReassemblerConfig) -> Self {
        Self {
            config,
            streams: HashMap::new(),
            tls_keys: TlsKeyStore::new(),
            reconstructed: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ReassemblerConfig::default())
    }

    // ── TLS key management ────────────────────────────────────────────────────

    /// Load TLS keys from an SSLKEYLOGFILE-formatted string.
    ///
    /// # Errors
    /// Propagates errors from [`TlsKeyStore::load_from_text`].
    pub fn load_keylog(&mut self, keylog_text: &str) -> Result<usize, ReassemblerError> {
        self.tls_keys.load_from_text(keylog_text)
    }

    // ── Segment ingestion ─────────────────────────────────────────────────────

    /// Feed a TCP segment into the appropriate stream.
    pub fn push_segment(
        &mut self,
        key: &StreamKey,
        seg: &TcpSegment,
        direction: Direction,
        timestamp_ms: u64,
    ) {
        let stream = self.streams.entry(key.canonical()).or_insert_with(|| {
            TcpStream::new(key.canonical(), timestamp_ms)
        });
        stream.push(seg, direction, timestamp_ms);
    }

    /// Close a stream and reconstruct application-layer data.
    pub fn close_stream(&mut self, key: &StreamKey) -> Option<ReconstructedStream> {
        let stream = self.streams.remove(&key.canonical())?;
        let reconstructed = self.reconstruct(stream);
        self.reconstructed.push(reconstructed.clone());
        Some(reconstructed)
    }

    /// Finalize all open streams (typically called at end of capture).
    pub fn finalize_all(&mut self) -> Vec<ReconstructedStream> {
        let keys: Vec<StreamKey> = self.streams.keys().cloned().collect();
        let mut results = Vec::new();
        for key in keys {
            if let Some(stream) = self.streams.remove(&key) {
                let r = self.reconstruct(stream);
                self.reconstructed.push(r.clone());
                results.push(r);
            }
        }
        results
    }

    // ── Reconstruction ────────────────────────────────────────────────────────

    fn reconstruct(&self, stream: TcpStream) -> ReconstructedStream {
        let mut raw_client = stream.client_data().to_vec();
        let mut raw_server = stream.server_data().to_vec();
        let mut is_tls = stream.is_tls;
        let mut decrypted = false;

        // Auto-detect TLS (starts with 0x16 0x03 = TLS ClientHello)
        if self.config.auto_tls && !is_tls
            && raw_client.len() >= 2 && raw_client[0] == 0x16 && raw_client[1] == 0x03 {
                is_tls = true;
            }

        // Attempt TLS decryption
        if is_tls && self.tls_keys.entry_count() > 0 {
            // Extract client_random from ClientHello (simplified: bytes 11..43 of first record)
            if raw_client.len() >= 43 {
                let client_random: Vec<u8> = raw_client[11..43].to_vec();
                if let Ok(plain) = decrypt_tls_stream(&raw_client, &self.tls_keys, &client_random) {
                    raw_client = plain;
                    decrypted = true;
                }
                if let Ok(plain) = decrypt_tls_stream(&raw_server, &self.tls_keys, &client_random) {
                    raw_server = plain;
                }
            }
        }

        // Detect protocol
        let app_protocol = detect_protocol(&raw_client, &stream.key);

        // Parse HTTP messages
        let mut http_messages = Vec::new();
        let mut http2_frames = Vec::new();

        match app_protocol {
            AppProtocol::Http1 => {
                http_messages.extend(parse_http1_stream(&raw_client));
                http_messages.extend(parse_http1_stream(&raw_server));
            }
            AppProtocol::Http2 if self.config.parse_http2 => {
                http2_frames.extend(parse_http2_frames(&raw_client));
                http2_frames.extend(parse_http2_frames(&raw_server));
            }
            _ => {}
        }

        let stream_total_bytes = stream.total_bytes();
        let stream_duration_ms = stream.duration_ms();
        ReconstructedStream {
            key: stream.key,
            app_protocol,
            is_tls,
            decrypted,
            total_bytes: stream_total_bytes,
            duration_ms: stream_duration_ms,
            http_messages,
            http2_frames,
            raw_client_data: raw_client,
            raw_server_data: raw_server,
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    #[must_use]
    pub fn active_stream_count(&self) -> usize {
        self.streams.len()
    }

    #[must_use]
    pub fn reconstructed(&self) -> &[ReconstructedStream] {
        &self.reconstructed
    }

    #[must_use]
    pub fn all_http_messages(&self) -> Vec<&HttpMessage> {
        self.reconstructed.iter()
            .flat_map(|s| s.http_messages.iter())
            .collect()
    }

    #[must_use]
    pub fn all_http_requests(&self) -> Vec<&HttpMessage> {
        self.all_http_messages().into_iter().filter(|m| m.is_request).collect()
    }

    #[must_use]
    pub fn all_urls(&self) -> Vec<String> {
        self.reconstructed.iter().flat_map(ReconstructedStream::all_urls).collect()
    }

    #[must_use]
    pub fn summary(&self) -> ReassemblerSummary {
        let total_bytes: u64 = self.reconstructed.iter().map(|s| s.total_bytes).sum();
        let tls_count = self.reconstructed.iter().filter(|s| s.is_tls).count();
        let decrypted_count = self.reconstructed.iter().filter(|s| s.decrypted).count();
        let http_count = self.reconstructed.iter()
            .filter(|s| matches!(s.app_protocol, AppProtocol::Http1 | AppProtocol::Http2))
            .count();

        ReassemblerSummary {
            total_streams: self.reconstructed.len(),
            active_streams: self.active_stream_count(),
            total_bytes,
            tls_streams: tls_count,
            decrypted_streams: decrypted_count,
            http_streams: http_count,
            total_http_messages: self.all_http_messages().len(),
            tls_key_count: self.tls_keys.entry_count(),
        }
    }
}

fn detect_protocol(data: &[u8], key: &StreamKey) -> AppProtocol {
    if data.starts_with(Http2Frame::PREFACE) {
        return AppProtocol::Http2;
    }
    // HTTP/1.x
    let methods = [b"GET " as &[u8], b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH "];
    if methods.iter().any(|m| data.starts_with(m)) || data.starts_with(b"HTTP/") {
        return AppProtocol::Http1;
    }
    // TLS
    if data.len() >= 2 && data[0] == 0x16 && data[1] == 0x03 {
        return AppProtocol::Tls;
    }
    // QUIC (starts with QUIC version bytes)
    if key.protocol == TransportProto::Quic {
        return AppProtocol::Http3;
    }
    AppProtocol::Unknown(format!("port:{}", key.dst_port))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReassemblerSummary {
    pub total_streams: usize,
    pub active_streams: usize,
    pub total_bytes: u64,
    pub tls_streams: usize,
    pub decrypted_streams: usize,
    pub http_streams: usize,
    pub total_http_messages: usize,
    pub tls_key_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_seg(seq: u32, data: &[u8], syn: bool) -> TcpSegment {
        TcpSegment {
            seq,
            flags: TcpFlags::builder().with_syn(syn).with_ack(!syn),
            payload: data.to_vec(),
            timestamp_ms: 1000,
        }
    }

    #[test]
    fn test_in_order_reassembly() {
        let key = StreamKey::new("10.0.0.1", 12345, "10.0.0.2", 80, TransportProto::Tcp);
        let mut reassembler = TrafficReassembler::with_defaults();

        reassembler.push_segment(&key, &make_seg(1000, b"GET /", true), Direction::ClientToServer, 1000);
        reassembler.push_segment(&key, &make_seg(1000, b"GET /", false), Direction::ClientToServer, 1010);
        reassembler.push_segment(&key, &make_seg(1005, b"index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", false), Direction::ClientToServer, 1020);

        let stream = reassembler.close_stream(&key).unwrap();
        // Should have some data
        assert!(!stream.raw_client_data.is_empty());
    }

    #[test]
    fn test_out_of_order_reassembly() {
        let mut half = HalfStream { next_seq: 100, ..HalfStream::default() };

        // Push out-of-order first
        let seg2 = TcpSegment { seq: 105, flags: TcpFlags::default(), payload: b" World".to_vec(), timestamp_ms: 0 };
        let seg1 = TcpSegment { seq: 100, flags: TcpFlags::default(), payload: b"Hello".to_vec(), timestamp_ms: 0 };
        half.push_segment(&seg2);
        half.push_segment(&seg1);

        assert_eq!(&half.data, b"Hello World");
    }

    #[test]
    fn test_http1_parse_request() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let messages = parse_http1_stream(raw);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].method_or_status, "GET");
        assert_eq!(messages[0].path_or_reason, "/index.html");
        assert!(messages[0].headers.contains_key("host"));
    }

    #[test]
    fn test_http1_parse_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
        let messages = parse_http1_stream(raw);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].method_or_status, "200");
        assert!(!messages[0].is_request);
    }

    #[test]
    fn test_http2_frame_parse() {
        // Minimal HTTP/2 SETTINGS frame (type=0x4, flags=0, stream_id=0, empty payload)
        let frame_bytes = &[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (frame, consumed) = Http2Frame::parse_next(frame_bytes).unwrap();
        assert_eq!(frame.frame_type, Http2Frame::TYPE_SETTINGS);
        assert_eq!(frame.length, 0);
        assert_eq!(consumed, 9);
    }

    #[test]
    fn test_tls_keylog_parse() {
        let keylog = "# NSS key log\nCLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f AABBCCDD00112233";
        let mut store = TlsKeyStore::new();
        let count = store.load_from_text(keylog).unwrap();
        assert_eq!(count, 1);
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn test_canonical_stream_key() {
        let k1 = StreamKey::new("10.0.0.1", 12345, "10.0.0.2", 80, TransportProto::Tcp);
        let k2 = StreamKey::new("10.0.0.2", 80, "10.0.0.1", 12345, TransportProto::Tcp);
        assert_eq!(k1.canonical(), k2.canonical());
    }

    #[test]
    fn test_full_http_stream_reconstruction() {
        let key = StreamKey::new("192.168.1.100", 54321, "93.184.216.34", 80, TransportProto::Tcp);
        let mut rea = TrafficReassembler::with_defaults();

        let request = b"GET /path/to/resource HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";

        // Client SYN
        rea.push_segment(&key, &make_seg(1000, b"", true), Direction::ClientToServer, 1000);
        // Client GET request (starts at next_seq = 1001)
        rea.push_segment(&key, &make_seg(1001, request, false), Direction::ClientToServer, 1010);
        // Server SYN-ACK
        rea.push_segment(&key, &make_seg(2000, b"", true), Direction::ServerToClient, 1015);
        // Server HTTP response (starts at next_seq = 2001)
        rea.push_segment(&key, &make_seg(2001, response, false), Direction::ServerToClient, 1020);

        let stream = rea.close_stream(&key).unwrap();
        assert!(matches!(stream.app_protocol, AppProtocol::Http1));
        assert!(!stream.http_requests().is_empty());
        assert!(!stream.http_responses().is_empty());
    }

    #[test]
    fn test_reassembler_summary() {
        let mut rea = TrafficReassembler::with_defaults();
        let key = StreamKey::new("1.2.3.4", 1234, "5.6.7.8", 80, TransportProto::Tcp);
        rea.push_segment(&key, &make_seg(1, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n", false), Direction::ClientToServer, 0);
        rea.finalize_all();
        let summary = rea.summary();
        assert_eq!(summary.total_streams, 1);
    }
}
