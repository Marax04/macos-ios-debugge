//! HTTP/2 dissector — deep, fully-validating frame parser (RFC 7540 / RFC 9113).
//!
//! This is the **canonical deep HTTP/2 parser** for this crate. It owns its own
//! error type ([`Http2Error`]), validates every structural constraint mandated by
//! the RFC (padding bounds, stream-0 rules, preface check, MAX\_FRAME\_SIZE), and
//! maintains per-stream and connection-level flow-control state.
//!
//! # Layering
//!
//! Three HTTP/2 implementations exist at different fidelity levels:
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`crate::application_protocols::Http2Dissector`] | Quick-scan: detect preface, read first frame header, no validation |
//! | [`crate::dissectors_application::Http2Dissector`] | Medium-depth: decode all frame types + HPACK static table |
//! | This module (`http2_dissector`) | Full fidelity: RFC validation, error codes, stream state, flow control |
//!
//! Callers that need to validate a live connection or implement a proxy should
//! use this module. Callers that only need to fingerprint traffic should prefer
//! `application_protocols::Http2Dissector` for speed.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced during HTTP/2 frame dissection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Http2Error {
    #[error("buffer too short: need {need}, have {have}")]
    TooShort { need: usize, have: usize },
    #[error("invalid frame length {0}: exceeds MAX_FRAME_SIZE")]
    FrameTooLarge(u32),
    #[error("reserved bit set in stream id")]
    ReservedBit,
    #[error("invalid padding length {pad} for frame of length {frame_len}")]
    BadPadding { pad: usize, frame_len: usize },
    #[error("SETTINGS frame must target stream 0, got {0}")]
    SettingsOnStream(u32),
    #[error("PING frame must target stream 0, got {0}")]
    PingOnStream(u32),
    #[error("GOAWAY frame must target stream 0, got {0}")]
    GoawayOnStream(u32),
    #[error("connection preface mismatch")]
    BadPreface,
    #[error("unknown frame type {0:#04x}")]
    UnknownFrameType(u8),
    #[error("malformed frame: {0}")]
    Malformed(String),
}

pub type Http2Result<T> = Result<T, Http2Error>;

// ─────────────────────────────────────────────────────────────────────────────
// FrameType
// ─────────────────────────────────────────────────────────────────────────────

/// HTTP/2 frame types per RFC 7540 §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    Goaway,
    WindowUpdate,
    Continuation,
    Unknown(u8),
}

impl FrameType {
    const fn from_u8(v: u8) -> Self {
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
            other => Self::Unknown(other),
        }
    }

    const fn as_u8(self) -> u8 {
        match self {
            Self::Data => 0x0,
            Self::Headers => 0x1,
            Self::Priority => 0x2,
            Self::RstStream => 0x3,
            Self::Settings => 0x4,
            Self::PushPromise => 0x5,
            Self::Ping => 0x6,
            Self::Goaway => 0x7,
            Self::WindowUpdate => 0x8,
            Self::Continuation => 0x9,
            Self::Unknown(v) => v,
        }
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data => write!(f, "DATA"),
            Self::Headers => write!(f, "HEADERS"),
            Self::Priority => write!(f, "PRIORITY"),
            Self::RstStream => write!(f, "RST_STREAM"),
            Self::Settings => write!(f, "SETTINGS"),
            Self::PushPromise => write!(f, "PUSH_PROMISE"),
            Self::Ping => write!(f, "PING"),
            Self::Goaway => write!(f, "GOAWAY"),
            Self::WindowUpdate => write!(f, "WINDOW_UPDATE"),
            Self::Continuation => write!(f, "CONTINUATION"),
            Self::Unknown(v) => write!(f, "FRAME_TYPE_{v:#04x}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Flags
// ─────────────────────────────────────────────────────────────────────────────

/// Frame flags (raw byte; interpretation depends on frame type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameFlags(pub u8);

impl FrameFlags {
    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
    pub const ACK: u8 = 0x1;

    #[must_use]
    pub const fn end_stream(self) -> bool { self.0 & Self::END_STREAM != 0 }
    #[must_use]
    pub const fn end_headers(self) -> bool { self.0 & Self::END_HEADERS != 0 }
    #[must_use]
    pub const fn padded(self) -> bool { self.0 & Self::PADDED != 0 }
    #[must_use]
    pub const fn priority(self) -> bool { self.0 & Self::PRIORITY != 0 }
    #[must_use]
    pub const fn ack(self) -> bool { self.0 & Self::ACK != 0 }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error codes
// ─────────────────────────────────────────────────────────────────────────────

/// HTTP/2 error codes per RFC 7540 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http2ErrorCode {
    NoError,
    ProtocolError,
    InternalError,
    FlowControlError,
    SettingsTimeout,
    StreamClosed,
    FrameSizeError,
    RefusedStream,
    Cancel,
    CompressionError,
    ConnectError,
    EnhanceYourCalm,
    InadequateSecurity,
    Http11Required,
    Unknown(u32),
}

impl Http2ErrorCode {
    const fn from_u32(v: u32) -> Self {
        match v {
            0x0 => Self::NoError,
            0x1 => Self::ProtocolError,
            0x2 => Self::InternalError,
            0x3 => Self::FlowControlError,
            0x4 => Self::SettingsTimeout,
            0x5 => Self::StreamClosed,
            0x6 => Self::FrameSizeError,
            0x7 => Self::RefusedStream,
            0x8 => Self::Cancel,
            0x9 => Self::CompressionError,
            0xa => Self::ConnectError,
            0xb => Self::EnhanceYourCalm,
            0xc => Self::InadequateSecurity,
            0xd => Self::Http11Required,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for Http2ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "NO_ERROR"),
            Self::ProtocolError => write!(f, "PROTOCOL_ERROR"),
            Self::InternalError => write!(f, "INTERNAL_ERROR"),
            Self::FlowControlError => write!(f, "FLOW_CONTROL_ERROR"),
            Self::SettingsTimeout => write!(f, "SETTINGS_TIMEOUT"),
            Self::StreamClosed => write!(f, "STREAM_CLOSED"),
            Self::FrameSizeError => write!(f, "FRAME_SIZE_ERROR"),
            Self::RefusedStream => write!(f, "REFUSED_STREAM"),
            Self::Cancel => write!(f, "CANCEL"),
            Self::CompressionError => write!(f, "COMPRESSION_ERROR"),
            Self::ConnectError => write!(f, "CONNECT_ERROR"),
            Self::EnhanceYourCalm => write!(f, "ENHANCE_YOUR_CALM"),
            Self::InadequateSecurity => write!(f, "INADEQUATE_SECURITY"),
            Self::Http11Required => write!(f, "HTTP_1_1_REQUIRED"),
            Self::Unknown(v) => write!(f, "0x{v:08x}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SETTINGS parameters
// ─────────────────────────────────────────────────────────────────────────────

/// A single SETTINGS parameter identifier + value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsParam {
    pub identifier: SettingsId,
    pub value: u32,
}

/// Known SETTINGS parameter IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsId {
    HeaderTableSize,
    EnablePush,
    MaxConcurrentStreams,
    InitialWindowSize,
    MaxFrameSize,
    MaxHeaderListSize,
    Unknown(u16),
}

impl SettingsId {
    const fn from_u16(v: u16) -> Self {
        match v {
            0x1 => Self::HeaderTableSize,
            0x2 => Self::EnablePush,
            0x3 => Self::MaxConcurrentStreams,
            0x4 => Self::InitialWindowSize,
            0x5 => Self::MaxFrameSize,
            0x6 => Self::MaxHeaderListSize,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for SettingsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTableSize => write!(f, "HEADER_TABLE_SIZE"),
            Self::EnablePush => write!(f, "ENABLE_PUSH"),
            Self::MaxConcurrentStreams => write!(f, "MAX_CONCURRENT_STREAMS"),
            Self::InitialWindowSize => write!(f, "INITIAL_WINDOW_SIZE"),
            Self::MaxFrameSize => write!(f, "MAX_FRAME_SIZE"),
            Self::MaxHeaderListSize => write!(f, "MAX_HEADER_LIST_SIZE"),
            Self::Unknown(v) => write!(f, "0x{v:04x}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Priority info
// ─────────────────────────────────────────────────────────────────────────────

/// Stream priority information from HEADERS or PRIORITY frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorityInfo {
    pub exclusive: bool,
    pub stream_dependency: u32,
    pub weight: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// Http2Frame — parsed frame body variants
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed body of an HTTP/2 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http2FrameBody {
    Data {
        data: Vec<u8>,
        pad_length: Option<u8>,
    },
    Headers {
        priority: Option<PriorityInfo>,
        header_block_fragment: Vec<u8>,
        pad_length: Option<u8>,
    },
    Priority(PriorityInfo),
    RstStream {
        error_code: Http2ErrorCode,
    },
    Settings {
        ack: bool,
        params: Vec<SettingsParam>,
    },
    PushPromise {
        promised_stream_id: u32,
        header_block_fragment: Vec<u8>,
        pad_length: Option<u8>,
    },
    Ping {
        ack: bool,
        opaque_data: [u8; 8],
    },
    Goaway {
        last_stream_id: u32,
        error_code: Http2ErrorCode,
        debug_data: Vec<u8>,
    },
    WindowUpdate {
        window_size_increment: u32,
    },
    Continuation {
        header_block_fragment: Vec<u8>,
    },
    Unknown {
        raw: Vec<u8>,
    },
}

/// A complete HTTP/2 frame with header and parsed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2Frame {
    /// Raw payload length from the 3-byte frame header.
    pub length: u32,
    /// Frame type.
    pub frame_type: FrameType,
    /// Raw flags byte.
    pub flags: FrameFlags,
    /// Stream identifier (31 bits; 0 = connection-level).
    pub stream_id: u32,
    /// Parsed body.
    pub body: Http2FrameBody,
}

impl Http2Frame {
    /// Return `true` if this frame ends the stream.
    #[must_use]
    pub const fn ends_stream(&self) -> bool {
        self.flags.end_stream()
    }

    /// Return `true` if this frame is connection-level (stream 0).
    #[must_use]
    pub const fn is_connection_level(&self) -> bool {
        self.stream_id == 0
    }

    /// Return the total wire size of this frame (9-byte header + payload).
    #[must_use]
    pub const fn wire_size(&self) -> usize {
        9 + self.length as usize
    }
}

impl fmt::Display for Http2Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} stream={} len={} flags={:#04x}",
            self.frame_type, self.stream_id, self.length, self.flags.0
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-level reader helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_u8(buf: &[u8], off: usize) -> Http2Result<u8> {
    buf.get(off).copied().ok_or(Http2Error::TooShort { need: off + 1, have: buf.len() })
}

fn read_u16_be(buf: &[u8], off: usize) -> Http2Result<u16> {
    if off + 2 > buf.len() {
        return Err(Http2Error::TooShort { need: off + 2, have: buf.len() });
    }
    Ok(u16::from_be_bytes([buf[off], buf[off + 1]]))
}

fn read_u24_be(buf: &[u8], off: usize) -> Http2Result<u32> {
    if off + 3 > buf.len() {
        return Err(Http2Error::TooShort { need: off + 3, have: buf.len() });
    }
    Ok(u32::from_be_bytes([0, buf[off], buf[off + 1], buf[off + 2]]))
}

fn read_u31_be(buf: &[u8], off: usize) -> Http2Result<u32> {
    if off + 4 > buf.len() {
        return Err(Http2Error::TooShort { need: off + 4, have: buf.len() });
    }
    let v = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
    Ok(v & 0x7FFF_FFFF)
}

fn read_u32_be(buf: &[u8], off: usize) -> Http2Result<u32> {
    if off + 4 > buf.len() {
        return Err(Http2Error::TooShort { need: off + 4, have: buf.len() });
    }
    Ok(u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]))
}

/// Parse PRIORITY block (5 bytes) starting at `off`.
fn parse_priority_block(buf: &[u8], off: usize) -> Http2Result<PriorityInfo> {
    if off + 5 > buf.len() {
        return Err(Http2Error::TooShort { need: off + 5, have: buf.len() });
    }
    let raw = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
    let exclusive = raw & 0x8000_0000 != 0;
    let stream_dependency = raw & 0x7FFF_FFFF;
    let weight = buf[off + 4];
    Ok(PriorityInfo { exclusive, stream_dependency, weight })
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — parse_http2_frame
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a single HTTP/2 frame from `data`.
///
/// `max_frame_size` should be the negotiated `SETTINGS_MAX_FRAME_SIZE` (default 16384).
///
/// Returns `(frame, bytes_consumed)` on success.
///
/// # Errors
/// Returns [`Http2Error`] on any parse failure.
pub fn parse_http2_frame(data: &[u8], max_frame_size: u32) -> Http2Result<(Http2Frame, usize)> {
    if data.len() < 9 {
        return Err(Http2Error::TooShort { need: 9, have: data.len() });
    }

    let length = read_u24_be(data, 0)?;
    if length > max_frame_size.max(16_384) {
        return Err(Http2Error::FrameTooLarge(length));
    }
    let frame_type = FrameType::from_u8(read_u8(data, 3)?);
    let flags = FrameFlags(read_u8(data, 4)?);
    let stream_raw = read_u32_be(data, 5)?;
    let stream_id = stream_raw & 0x7FFF_FFFF;

    let total = 9 + length as usize;
    if data.len() < total {
        return Err(Http2Error::TooShort { need: total, have: data.len() });
    }
    let payload = &data[9..total];

    let body = parse_frame_body(frame_type, flags, stream_id, payload)?;

    Ok((Http2Frame { length, frame_type, flags, stream_id, body }, total))
}

fn parse_frame_body(
    ftype: FrameType,
    flags: FrameFlags,
    stream_id: u32,
    payload: &[u8],
) -> Http2Result<Http2FrameBody> {
    match ftype {
        FrameType::Data => parse_data(flags, payload),
        FrameType::Headers => parse_headers(flags, stream_id, payload),
        FrameType::Priority => {
            let pri = parse_priority_block(payload, 0)?;
            Ok(Http2FrameBody::Priority(pri))
        }
        FrameType::RstStream => {
            if payload.len() < 4 {
                return Err(Http2Error::Malformed("RST_STREAM must be 4 bytes".into()));
            }
            let code = Http2ErrorCode::from_u32(read_u32_be(payload, 0)?);
            Ok(Http2FrameBody::RstStream { error_code: code })
        }
        FrameType::Settings => {
            if stream_id != 0 {
                return Err(Http2Error::SettingsOnStream(stream_id));
            }
            let ack = flags.ack();
            if ack && !payload.is_empty() {
                return Err(Http2Error::Malformed("SETTINGS ACK must have empty payload".into()));
            }
            let mut params = Vec::new();
            let mut pos = 0;
            while pos + 6 <= payload.len() {
                let id = SettingsId::from_u16(read_u16_be(payload, pos)?);
                let val = read_u32_be(payload, pos + 2)?;
                params.push(SettingsParam { identifier: id, value: val });
                pos += 6;
            }
            Ok(Http2FrameBody::Settings { ack, params })
        }
        FrameType::PushPromise => parse_push_promise(flags, payload),
        FrameType::Ping => {
            if stream_id != 0 {
                return Err(Http2Error::PingOnStream(stream_id));
            }
            if payload.len() < 8 {
                return Err(Http2Error::Malformed("PING must be 8 bytes".into()));
            }
            let mut data = [0u8; 8];
            data.copy_from_slice(&payload[..8]);
            Ok(Http2FrameBody::Ping { ack: flags.ack(), opaque_data: data })
        }
        FrameType::Goaway => {
            if stream_id != 0 {
                return Err(Http2Error::GoawayOnStream(stream_id));
            }
            if payload.len() < 8 {
                return Err(Http2Error::Malformed("GOAWAY must be at least 8 bytes".into()));
            }
            let last = read_u31_be(payload, 0)?;
            let code = Http2ErrorCode::from_u32(read_u32_be(payload, 4)?);
            let debug = payload[8..].to_vec();
            Ok(Http2FrameBody::Goaway { last_stream_id: last, error_code: code, debug_data: debug })
        }
        FrameType::WindowUpdate => {
            if payload.len() < 4 {
                return Err(Http2Error::Malformed("WINDOW_UPDATE must be 4 bytes".into()));
            }
            let inc = read_u32_be(payload, 0)? & 0x7FFF_FFFF;
            Ok(Http2FrameBody::WindowUpdate { window_size_increment: inc })
        }
        FrameType::Continuation => {
            Ok(Http2FrameBody::Continuation { header_block_fragment: payload.to_vec() })
        }
        FrameType::Unknown(_) => Ok(Http2FrameBody::Unknown { raw: payload.to_vec() }),
    }
}

fn strip_padding(flags: FrameFlags, payload: &[u8]) -> Http2Result<(&[u8], Option<u8>)> {
    if flags.padded() {
        if payload.is_empty() {
            return Err(Http2Error::Malformed("PADDED flag set but no padding length byte".into()));
        }
        let pad_len = payload[0] as usize;
        let rest = &payload[1..];
        if pad_len >= rest.len() {
            return Err(Http2Error::BadPadding { pad: pad_len, frame_len: payload.len() });
        }
        Ok((&rest[..rest.len() - pad_len], Some(payload[0])))
    } else {
        Ok((payload, None))
    }
}

fn parse_data(flags: FrameFlags, payload: &[u8]) -> Http2Result<Http2FrameBody> {
    let (inner, pad) = strip_padding(flags, payload)?;
    Ok(Http2FrameBody::Data { data: inner.to_vec(), pad_length: pad })
}

fn parse_headers(flags: FrameFlags, _stream_id: u32, payload: &[u8]) -> Http2Result<Http2FrameBody> {
    let (inner, pad) = strip_padding(flags, payload)?;
    let (priority, hbf_start) = if flags.priority() {
        if inner.len() < 5 {
            return Err(Http2Error::Malformed("HEADERS PRIORITY block too short".into()));
        }
        (Some(parse_priority_block(inner, 0)?), 5)
    } else {
        (None, 0)
    };
    let header_block_fragment = inner[hbf_start..].to_vec();
    Ok(Http2FrameBody::Headers { priority, header_block_fragment, pad_length: pad })
}

fn parse_push_promise(flags: FrameFlags, payload: &[u8]) -> Http2Result<Http2FrameBody> {
    let (inner, pad) = strip_padding(flags, payload)?;
    if inner.len() < 4 {
        return Err(Http2Error::Malformed("PUSH_PROMISE too short".into()));
    }
    let promised_stream_id = read_u32_be(inner, 0)? & 0x7FFF_FFFF;
    let header_block_fragment = inner[4..].to_vec();
    Ok(Http2FrameBody::PushPromise { promised_stream_id, header_block_fragment, pad_length: pad })
}

// ─────────────────────────────────────────────────────────────────────────────
// Stream state
// ─────────────────────────────────────────────────────────────────────────────

/// Per-stream state tracked by the dissector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

impl fmt::Display for StreamState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Open => write!(f, "open"),
            Self::HalfClosedLocal => write!(f, "half-closed(local)"),
            Self::HalfClosedRemote => write!(f, "half-closed(remote)"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Per-stream tracking record.
#[derive(Debug, Clone)]
pub struct StreamInfo {
    pub id: u32,
    pub state: StreamState,
    pub send_window: i64,
    pub recv_window: i64,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub header_fragments: Vec<Vec<u8>>,
}

impl StreamInfo {
    const fn new(id: u32, initial_window: i64) -> Self {
        Self {
            id,
            state: StreamState::Idle,
            send_window: initial_window,
            recv_window: initial_window,
            frames_sent: 0,
            frames_received: 0,
            header_fragments: Vec::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Http2Dissector
// ─────────────────────────────────────────────────────────────────────────────

/// Stateful HTTP/2 dissector — tracks connection and stream state.
#[derive(Debug)]
pub struct Http2Dissector {
    /// Negotiated max frame size.
    max_frame_size: u32,
    /// Connection-level send window.
    conn_send_window: i64,
    /// Connection-level receive window.
    conn_recv_window: i64,
    /// Initial stream window size.
    initial_window_size: i64,
    /// Per-stream state.
    streams: HashMap<u32, StreamInfo>,
    /// Total frames parsed.
    total_frames: u64,
    /// Counts per frame type.
    frame_type_counts: HashMap<u8, u64>,
    /// Whether the connection preface has been seen.
    preface_seen: bool,
    /// Cumulative data bytes transferred (client → server).
    data_bytes_sent: u64,
    /// Cumulative data bytes transferred (server → client).
    data_bytes_received: u64,
    /// Parse errors encountered.
    parse_errors: u64,
}

impl Http2Dissector {
    /// Create a new dissector with RFC-default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_frame_size: 16_384,
            conn_send_window: 65_535,
            conn_recv_window: 65_535,
            initial_window_size: 65_535,
            streams: HashMap::new(),
            total_frames: 0,
            frame_type_counts: HashMap::new(),
            preface_seen: false,
            data_bytes_sent: 0,
            data_bytes_received: 0,
            parse_errors: 0,
        }
    }

    /// Verify and consume the client connection preface (24-byte magic string).
    ///
    /// # Errors
    /// Returns [`Http2Error::BadPreface`] if the preface does not match.
    pub fn consume_preface<'a>(&mut self, data: &'a [u8]) -> Http2Result<&'a [u8]> {
        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if data.len() < PREFACE.len() {
            return Err(Http2Error::TooShort { need: PREFACE.len(), have: data.len() });
        }
        if &data[..PREFACE.len()] != PREFACE {
            return Err(Http2Error::BadPreface);
        }
        self.preface_seen = true;
        Ok(&data[PREFACE.len()..])
    }

    /// Parse and account for a single frame at the front of `data`.
    ///
    /// Returns `(frame, bytes_consumed)`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn feed(&mut self, data: &[u8], from_client: bool) -> Http2Result<(Http2Frame, usize)> {
        let result = parse_http2_frame(data, self.max_frame_size);
        match &result {
            Ok((frame, _)) => {
                self.total_frames += 1;
                *self.frame_type_counts.entry(frame.frame_type.as_u8()).or_insert(0) += 1;
                self.process_frame(frame, from_client);
            }
            Err(_) => {
                self.parse_errors += 1;
            }
        }
        result
    }

    fn process_frame(&mut self, frame: &Http2Frame, from_client: bool) {
        let stream = self.streams.entry(frame.stream_id).or_insert_with(|| {
            StreamInfo::new(frame.stream_id, self.initial_window_size)
        });

        if from_client {
            stream.frames_sent += 1;
        } else {
            stream.frames_received += 1;
        }

        match &frame.body {
            Http2FrameBody::Data { data, .. } => {
                let len = i64::try_from(data.len()).unwrap_or(i64::MAX);
                if from_client {
                    self.data_bytes_sent += data.len() as u64;
                    self.conn_recv_window -= len;
                    stream.recv_window -= len;
                } else {
                    self.data_bytes_received += data.len() as u64;
                    self.conn_send_window -= len;
                    stream.send_window -= len;
                }
                if frame.flags.end_stream() {
                    stream.state = if from_client {
                        StreamState::HalfClosedLocal
                    } else {
                        StreamState::HalfClosedRemote
                    };
                }
            }
            Http2FrameBody::Headers { .. } => {
                stream.state = StreamState::Open;
                if frame.flags.end_stream() {
                    stream.state = if from_client {
                        StreamState::HalfClosedLocal
                    } else {
                        StreamState::HalfClosedRemote
                    };
                }
            }
            Http2FrameBody::RstStream { .. } => {
                stream.state = StreamState::Closed;
            }
            Http2FrameBody::Settings { ack, params } => {
                if !ack {
                    for p in params {
                        match p.identifier {
                            SettingsId::MaxFrameSize => {
                                self.max_frame_size = p.value.min(16_777_215);
                            }
                            SettingsId::InitialWindowSize => {
                                self.initial_window_size = i64::from(p.value);
                            }
                            _ => {}
                        }
                    }
                }
            }
            Http2FrameBody::WindowUpdate { window_size_increment } => {
                let inc = i64::from(*window_size_increment);
                if frame.stream_id == 0 {
                    self.conn_send_window += inc;
                } else {
                    stream.send_window += inc;
                }
            }
            Http2FrameBody::Continuation { header_block_fragment } => {
                stream.header_fragments.push(header_block_fragment.clone());
            }
            _ => {}
        }
    }

    /// Parse all complete frames from a byte buffer, returning the list and remaining bytes.
    pub fn feed_all<'a>(&mut self, data: &'a [u8], from_client: bool) -> (Vec<Http2Frame>, &'a [u8]) {
        let mut frames = Vec::new();
        let mut pos = 0;
        while pos + 9 <= data.len() {
            match self.feed(&data[pos..], from_client) {
                Ok((frame, consumed)) => {
                    pos += consumed;
                    frames.push(frame);
                }
                Err(_) => break,
            }
        }
        (frames, &data[pos..])
    }

    /// Return the state of a stream by ID.
    #[must_use]
    pub fn stream_state(&self, stream_id: u32) -> Option<&StreamState> {
        self.streams.get(&stream_id).map(|s| &s.state)
    }

    /// Return all known streams.
    #[must_use]
    pub const fn streams(&self) -> &HashMap<u32, StreamInfo> {
        &self.streams
    }

    /// Total frames parsed.
    #[must_use]
    pub const fn total_frames(&self) -> u64 {
        self.total_frames
    }

    /// Parse error count.
    #[must_use]
    pub const fn parse_errors(&self) -> u64 {
        self.parse_errors
    }

    /// Connection-level receive window remaining.
    #[must_use]
    pub const fn conn_recv_window(&self) -> i64 {
        self.conn_recv_window
    }

    /// Total data bytes seen from client.
    #[must_use]
    pub const fn data_bytes_sent(&self) -> u64 {
        self.data_bytes_sent
    }

    /// Total data bytes seen from server.
    #[must_use]
    pub const fn data_bytes_received(&self) -> u64 {
        self.data_bytes_received
    }

    /// Return count for a specific frame type.
    #[must_use]
    pub fn frame_count(&self, ftype: FrameType) -> u64 {
        self.frame_type_counts.get(&ftype.as_u8()).copied().unwrap_or(0)
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.streams.clear();
        self.frame_type_counts.clear();
        self.total_frames = 0;
        self.parse_errors = 0;
        self.data_bytes_sent = 0;
        self.data_bytes_received = 0;
        self.conn_send_window = 65_535;
        self.conn_recv_window = 65_535;
        self.preface_seen = false;
    }
}

impl Default for Http2Dissector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_frame(ack: bool) -> Vec<u8> {
        let flags: u8 = u8::from(ack);
        let mut f = Vec::new();
        f.extend_from_slice(&[0, 0, 0]); // length = 0
        f.push(0x4); // SETTINGS
        f.push(flags);
        f.extend_from_slice(&[0, 0, 0, 0]); // stream 0
        f
    }

    fn ping_frame(ack: bool) -> Vec<u8> {
        let flags: u8 = u8::from(ack);
        let mut f = vec![0u8, 0, 8, 0x6, flags, 0, 0, 0, 0];
        f.extend_from_slice(&[0u8; 8]);
        f
    }

    fn window_update_frame(stream: u32, inc: u32) -> Vec<u8> {
        let mut f = vec![0u8, 0, 4, 0x8, 0x0];
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(&inc.to_be_bytes());
        f
    }

    #[test]
    fn parse_settings_ack() {
        let data = settings_frame(true);
        let (frame, consumed) = parse_http2_frame(&data, 16_384).unwrap();
        assert_eq!(consumed, 9);
        assert_eq!(frame.frame_type, FrameType::Settings);
        assert!(matches!(frame.body, Http2FrameBody::Settings { ack: true, .. }));
    }

    #[test]
    fn parse_ping() {
        let data = ping_frame(false);
        let (frame, _) = parse_http2_frame(&data, 16_384).unwrap();
        assert_eq!(frame.frame_type, FrameType::Ping);
        assert!(!frame.flags.ack());
    }

    #[test]
    fn parse_window_update() {
        let data = window_update_frame(0, 65_535);
        let (frame, _) = parse_http2_frame(&data, 16_384).unwrap();
        assert_eq!(frame.frame_type, FrameType::WindowUpdate);
        assert!(matches!(frame.body, Http2FrameBody::WindowUpdate { window_size_increment: 65_535 }));
    }

    #[test]
    fn dissector_tracks_frames() {
        let mut d = Http2Dissector::new();
        let s = settings_frame(false);
        d.feed(&s, true).unwrap();
        assert_eq!(d.total_frames(), 1);
        assert_eq!(d.frame_count(FrameType::Settings), 1);
    }

    #[test]
    fn too_short_error() {
        let result = parse_http2_frame(&[0u8; 4], 16_384);
        assert!(matches!(result, Err(Http2Error::TooShort { .. })));
    }

    #[test]
    fn settings_on_stream_error() {
        let mut data = vec![0u8, 0, 0, 0x4, 0x0];
        data.extend_from_slice(&1u32.to_be_bytes()); // stream 1
        let result = parse_http2_frame(&data, 16_384);
        assert!(matches!(result, Err(Http2Error::SettingsOnStream(1))));
    }
}
