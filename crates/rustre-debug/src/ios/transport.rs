//! Real transports to an Apple debug target.
//!
//! Two shapes are implemented here:
//!
//! * [`TcpRspTransport`] — plain TCP to a `debugserver` that is already
//!   listening on a reachable address (a Mac on the LAN, or a port already
//!   forwarded by some other tool).
//! * [`UsbmuxClient`] — a client for **usbmuxd**, the daemon that multiplexes
//!   TCP connections to an iOS device over USB. On Windows it is reached
//!   through the named pipe `\\.\pipe\iTunes` installed by Apple Mobile Device
//!   Support; on Unix hosts through the socket `/var/run/usbmuxd`. Once a
//!   `Connect` succeeds the very same socket becomes a byte-for-byte tunnel to
//!   the requested TCP port on the device, so wrapping it in
//!   [`UsbmuxRspTransport`] yields an [`RspTransport`] to `debugserver`
//!   running on the phone.
//!
//! The usbmuxd wire format is a 16-byte little-endian header
//! (`length`, `version`, `message`, `tag`) followed by an XML property list.
//! Everything about that framing — including the plist encoder/decoder — is
//! pure byte math and is unit-tested on Windows against [`MockMuxd`], a real
//! in-process usbmuxd that speaks the same protocol over a loopback socket.
//!
//! Nothing here is gated on `cfg(target_os = "macos")`. The only host gate is
//! [`connect_usbmuxd`], which must open a platform-specific socket type; the
//! protocol itself is generic over `Read + Write`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::ios::rsp::{RspInterrupter, RspTransport, TcpInterrupter};

/// Header size of every usbmuxd message: four little-endian `u32`s.
pub const MUX_HEADER_LEN: usize = 16;

/// Refuse to allocate for absurd payload sizes claimed by the daemon.
///
/// The target side of this connection is not trusted: a hostile or broken
/// daemon must not be able to make us allocate gigabytes.
pub const MUX_MAX_PAYLOAD: u32 = 8 * 1024 * 1024;

/// Protocol version field. `0` is the legacy binary protocol; `1` is plist.
pub const MUX_VERSION_PLIST: u32 = 1;

/// Message field for a plist-carrying packet.
pub const MUX_MESSAGE_PLIST: u32 = 8;

/// Default TCP fallback port for usbmuxd on Windows when the named pipe is
/// unavailable (some iTunes/AMDS builds expose this instead).
pub const USBMUXD_TCP_FALLBACK: &str = "127.0.0.1:27015";

/// Windows named pipe published by Apple Mobile Device Support.
pub const USBMUXD_PIPE_WINDOWS: &str = r"\\.\pipe\iTunes";

/// Unix domain socket path used by usbmuxd.
pub const USBMUXD_SOCKET_UNIX: &str = "/var/run/usbmuxd";

/// Errors raised by the usbmuxd client.
#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    /// Underlying socket/pipe failure.
    #[error("usbmuxd I/O error: {0}")]
    Io(#[from] io::Error),
    /// Header or payload did not conform to the protocol.
    #[error("usbmuxd protocol error: {0}")]
    Protocol(String),
    /// A plist could not be parsed, or lacked a required key.
    #[error("usbmuxd plist error: {0}")]
    Plist(String),
    /// The daemon answered `Result` with a non-zero code.
    #[error("usbmuxd refused request: {reason} (code {code})")]
    Refused {
        /// Numeric `Number` field from the daemon.
        code: u64,
        /// Decoded meaning of `code`.
        reason: &'static str,
    },
    /// The requested feature genuinely is not implementable here.
    #[error("usbmuxd transport unsupported on this host: {0}")]
    Unsupported(String),
}

/// Decode the `Number` field of a usbmuxd `Result` message.
#[must_use]
pub const fn mux_result_reason(code: u64) -> &'static str {
    match code {
        0 => "ok",
        2 => "device not connected",
        3 => "port not available / connection refused",
        5 => "bad command",
        6 => "bad device",
        7 => "connection refused by device",
        _ => "unknown error",
    }
}

// ---------------------------------------------------------------------------
// Minimal XML property list
// ---------------------------------------------------------------------------

/// The subset of property-list values usbmuxd actually exchanges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlistValue {
    /// `<string>`
    String(String),
    /// `<integer>`
    Integer(i64),
    /// `<true/>` / `<false/>`
    Boolean(bool),
    /// `<data>` (base64 in the XML form)
    Data(Vec<u8>),
    /// `<array>`
    Array(Vec<Self>),
    /// `<dict>`; ordered so serialisation is deterministic and testable.
    Dict(BTreeMap<String, Self>),
}

impl PlistValue {
    /// Borrow a dict entry, if this is a dict containing `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Dict(map) => map.get(key),
            _ => None,
        }
    }

    /// Interpret as a string.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Interpret as an integer (booleans do NOT coerce).
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(v) => Some(*v),
            _ => None,
        }
    }

    /// Interpret as raw data.
    #[must_use]
    pub const fn as_data(&self) -> Option<&[u8]> {
        match self {
            Self::Data(d) => Some(d.as_slice()),
            _ => None,
        }
    }

    /// Interpret as an array.
    #[must_use]
    pub const fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    /// Build a dict from key/value pairs.
    #[must_use]
    pub fn dict<I: IntoIterator<Item = (String, Self)>>(entries: I) -> Self {
        Self::Dict(entries.into_iter().collect())
    }

    /// Serialise to an XML property list document.
    #[must_use]
    pub fn to_xml(&self) -> String {
        let mut out = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n",
        );
        self.write_xml(&mut out, 1);
        out.push_str("</plist>\n");
        out
    }

    fn write_xml(&self, out: &mut String, depth: usize) {
        let pad = "\t".repeat(depth);
        match self {
            Self::String(s) => {
                let _ = writeln!(out, "{pad}<string>{}</string>", xml_escape(s));
            }
            Self::Integer(v) => {
                let _ = writeln!(out, "{pad}<integer>{v}</integer>");
            }
            Self::Boolean(true) => {
                let _ = writeln!(out, "{pad}<true/>");
            }
            Self::Boolean(false) => {
                let _ = writeln!(out, "{pad}<false/>");
            }
            Self::Data(d) => {
                let _ = writeln!(out, "{pad}<data>{}</data>", base64_encode(d));
            }
            Self::Array(items) => {
                let _ = writeln!(out, "{pad}<array>");
                for item in items {
                    item.write_xml(out, depth + 1);
                }
                let _ = writeln!(out, "{pad}</array>");
            }
            Self::Dict(map) => {
                let _ = writeln!(out, "{pad}<dict>");
                for (k, v) in map {
                    let _ = writeln!(out, "{pad}\t<key>{}</key>", xml_escape(k));
                    v.write_xml(out, depth + 1);
                }
                let _ = writeln!(out, "{pad}</dict>");
            }
        }
    }

    /// Parse an XML property list document.
    ///
    /// This is a deliberately small, allocation-bounded parser: it handles the
    /// element set above and nothing else. Input arrives from a daemon we do
    /// not control, so every step is fallible and no index is unchecked.
    ///
    /// # Errors
    /// Returns [`MuxError::Plist`] on malformed or unsupported markup.
    pub fn parse_xml(text: &str) -> Result<Self, MuxError> {
        let mut p = XmlParser {
            src: text.as_bytes(),
            pos: 0,
            depth: 0,
        };
        p.skip_prologue();
        let value = p.parse_value()?;
        Ok(value)
    }
}

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn xml_unescape(input: &str) -> String {
    input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

struct XmlParser<'a> {
    src: &'a [u8],
    pos: usize,
    depth: usize,
}

/// Nesting cap: a hostile plist must not be able to blow the stack.
const PLIST_MAX_DEPTH: usize = 32;

impl XmlParser<'_> {
    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    /// Skip `<?xml …?>`, `<!DOCTYPE …>` and the opening `<plist …>` tag.
    fn skip_prologue(&mut self) {
        loop {
            self.skip_ws();
            let rest = &self.src[self.pos.min(self.src.len())..];
            if rest.starts_with(b"<?") {
                if let Some(end) = find(rest, b"?>") {
                    self.pos += end + 2;
                    continue;
                }
                self.pos = self.src.len();
                return;
            }
            if rest.starts_with(b"<!") {
                if let Some(end) = find(rest, b">") {
                    self.pos += end + 1;
                    continue;
                }
                self.pos = self.src.len();
                return;
            }
            if rest.starts_with(b"<plist") {
                if let Some(end) = find(rest, b">") {
                    self.pos += end + 1;
                    continue;
                }
                self.pos = self.src.len();
                return;
            }
            return;
        }
    }

    /// Read the next tag name, e.g. `dict`, `/dict`, `true/`.
    fn peek_tag(&mut self) -> Result<String, MuxError> {
        self.skip_ws();
        if self.pos >= self.src.len() || self.src[self.pos] != b'<' {
            return Err(MuxError::Plist(format!(
                "expected '<' at byte {}",
                self.pos
            )));
        }
        let rest = &self.src[self.pos..];
        let end = find(rest, b">")
            .ok_or_else(|| MuxError::Plist("unterminated tag".to_string()))?;
        let raw = std::str::from_utf8(&rest[1..end])
            .map_err(|_| MuxError::Plist("non-UTF-8 tag".to_string()))?;
        Ok(raw.trim().to_string())
    }

    fn consume_tag(&mut self) -> Result<String, MuxError> {
        let tag = self.peek_tag()?;
        let rest = &self.src[self.pos..];
        let end = find(rest, b">")
            .ok_or_else(|| MuxError::Plist("unterminated tag".to_string()))?;
        self.pos += end + 1;
        Ok(tag)
    }

    /// Read character data up to the next `<`.
    fn read_text(&mut self) -> Result<String, MuxError> {
        let start = self.pos;
        while self.pos < self.src.len() && self.src[self.pos] != b'<' {
            self.pos += 1;
        }
        let raw = std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| MuxError::Plist("non-UTF-8 text node".to_string()))?;
        Ok(xml_unescape(raw))
    }

    fn expect_close(&mut self, name: &str) -> Result<(), MuxError> {
        let tag = self.consume_tag()?;
        if tag.trim_start_matches('/').trim() == name {
            Ok(())
        } else {
            Err(MuxError::Plist(format!("expected </{name}>, saw <{tag}>")))
        }
    }

    fn parse_value(&mut self) -> Result<PlistValue, MuxError> {
        if self.depth >= PLIST_MAX_DEPTH {
            return Err(MuxError::Plist("plist nesting too deep".to_string()));
        }
        let tag = self.consume_tag()?;
        let name = tag.trim_end_matches('/').trim().to_string();
        let self_closing = tag.ends_with('/');
        match name.as_str() {
            "true" => Ok(PlistValue::Boolean(true)),
            "false" => Ok(PlistValue::Boolean(false)),
            "string" => {
                if self_closing {
                    return Ok(PlistValue::String(String::new()));
                }
                let text = self.read_text()?;
                self.expect_close("string")?;
                Ok(PlistValue::String(text))
            }
            "integer" => {
                if self_closing {
                    return Ok(PlistValue::Integer(0));
                }
                let text = self.read_text()?;
                self.expect_close("integer")?;
                text.trim()
                    .parse::<i64>()
                    .map(PlistValue::Integer)
                    .map_err(|e| MuxError::Plist(format!("bad integer {text:?}: {e}")))
            }
            "data" => {
                if self_closing {
                    return Ok(PlistValue::Data(Vec::new()));
                }
                let text = self.read_text()?;
                self.expect_close("data")?;
                base64_decode(&text).map(PlistValue::Data)
            }
            "array" => {
                if self_closing {
                    return Ok(PlistValue::Array(Vec::new()));
                }
                self.depth += 1;
                let mut items = Vec::new();
                loop {
                    let next = self.peek_tag()?;
                    if next.starts_with('/') {
                        self.expect_close("array")?;
                        break;
                    }
                    items.push(self.parse_value()?);
                }
                self.depth -= 1;
                Ok(PlistValue::Array(items))
            }
            "dict" => {
                if self_closing {
                    return Ok(PlistValue::Dict(BTreeMap::new()));
                }
                self.depth += 1;
                let mut map = BTreeMap::new();
                loop {
                    let next = self.peek_tag()?;
                    if next.starts_with('/') {
                        self.expect_close("dict")?;
                        break;
                    }
                    if next.trim_end_matches('/').trim() != "key" {
                        return Err(MuxError::Plist(format!("expected <key>, saw <{next}>")));
                    }
                    let key_tag = self.consume_tag()?;
                    let key = if key_tag.ends_with('/') {
                        String::new()
                    } else {
                        let k = self.read_text()?;
                        self.expect_close("key")?;
                        k
                    };
                    let value = self.parse_value()?;
                    map.insert(key, value);
                }
                self.depth -= 1;
                Ok(PlistValue::Dict(map))
            }
            other => Err(MuxError::Plist(format!("unsupported element <{other}>"))),
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64-encode `data` (no line wrapping).
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Base64-decode, ignoring ASCII whitespace (XML `<data>` is usually wrapped).
///
/// # Errors
/// Returns [`MuxError::Plist`] if a non-alphabet character is present, if a
/// symbol follows the padding, or if the trailing quantum is not one the
/// encoding can produce: the padding must be exactly the amount the final
/// group of symbols calls for (0, 1 or 2 `=`), and a final group of a single
/// symbol carries only 6 bits, so it is never a whole byte and is rejected.
pub fn base64_decode(text: &str) -> Result<Vec<u8>, MuxError> {
    let mut symbols: Vec<u8> = Vec::with_capacity(text.len());
    let mut pad = 0usize;
    for c in text.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            pad += 1;
            continue;
        }
        if pad > 0 {
            return Err(MuxError::Plist("base64 data after padding".to_string()));
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => {
                return Err(MuxError::Plist(format!(
                    "invalid base64 character {:?}",
                    c as char
                )));
            }
        };
        symbols.push(v);
    }
    // The trailing group decides how much padding is legal. A group of one
    // symbol is 6 bits and can never round out to a byte, so it is rejected
    // outright instead of silently decoding as `symbol << 2`.
    let quantum = symbols.len() % 4;
    if quantum == 1 {
        return Err(MuxError::Plist(
            "base64 final quantum has a single symbol".to_string(),
        ));
    }
    let expected_pad = if quantum == 0 { 0 } else { 4 - quantum };
    if pad != expected_pad {
        return Err(MuxError::Plist(format!(
            "base64 has {pad} padding characters, expected {expected_pad}"
        )));
    }
    let mut out = Vec::with_capacity(symbols.len() * 3 / 4);
    for chunk in symbols.chunks(4) {
        let mut n: u32 = 0;
        for (i, s) in chunk.iter().enumerate() {
            n |= u32::from(*s) << (18 - 6 * i);
        }
        out.push(((n >> 16) & 0xff) as u8);
        if chunk.len() > 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if chunk.len() > 3 {
            out.push((n & 0xff) as u8);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// usbmuxd framing
// ---------------------------------------------------------------------------

/// The 16-byte usbmuxd packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxHeader {
    /// Total packet length *including* these 16 bytes.
    pub length: u32,
    /// Protocol version (`1` for plist).
    pub version: u32,
    /// Message type (`8` for plist).
    pub message: u32,
    /// Request tag, echoed by the daemon in its reply.
    pub tag: u32,
}

impl MuxHeader {
    /// Encode to the wire form (little-endian).
    #[must_use]
    pub fn to_bytes(self) -> [u8; MUX_HEADER_LEN] {
        let mut out = [0u8; MUX_HEADER_LEN];
        out[0..4].copy_from_slice(&self.length.to_le_bytes());
        out[4..8].copy_from_slice(&self.version.to_le_bytes());
        out[8..12].copy_from_slice(&self.message.to_le_bytes());
        out[12..16].copy_from_slice(&self.tag.to_le_bytes());
        out
    }

    /// Decode from the wire form.
    ///
    /// # Errors
    /// Returns [`MuxError::Protocol`] when `bytes` is short, when `length` is
    /// smaller than the header itself, or when the claimed payload exceeds
    /// [`MUX_MAX_PAYLOAD`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MuxError> {
        if bytes.len() < MUX_HEADER_LEN {
            return Err(MuxError::Protocol(format!(
                "header too short: {} bytes",
                bytes.len()
            )));
        }
        let rd = |o: usize| -> u32 {
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[o..o + 4]);
            u32::from_le_bytes(b)
        };
        let header = Self {
            length: rd(0),
            version: rd(4),
            message: rd(8),
            tag: rd(12),
        };
        let header_len = u32::try_from(MUX_HEADER_LEN).unwrap_or(u32::MAX);
        if header.length < header_len {
            return Err(MuxError::Protocol(format!(
                "header length {} below minimum {header_len}",
                header.length
            )));
        }
        if header.length - header_len > MUX_MAX_PAYLOAD {
            return Err(MuxError::Protocol(format!(
                "payload {} exceeds cap {MUX_MAX_PAYLOAD}",
                header.length - header_len
            )));
        }
        Ok(header)
    }

    /// Payload length implied by `length`.
    #[must_use]
    pub const fn payload_len(self) -> usize {
        (self.length as usize).saturating_sub(MUX_HEADER_LEN)
    }
}

/// Frame a plist payload into a complete usbmuxd packet.
#[must_use]
pub fn encode_mux_packet(tag: u32, plist_xml: &str) -> Vec<u8> {
    let body = plist_xml.as_bytes();
    let length = u32::try_from(MUX_HEADER_LEN + body.len()).unwrap_or(u32::MAX);
    let header = MuxHeader {
        length,
        version: MUX_VERSION_PLIST,
        message: MUX_MESSAGE_PLIST,
        tag,
    };
    let mut out = Vec::with_capacity(length as usize);
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(body);
    out
}

/// Read exactly one usbmuxd packet from `stream`, returning header + payload.
///
/// # Errors
/// I/O failures, malformed headers, and oversized payloads.
pub fn read_mux_packet<S: Read>(stream: &mut S) -> Result<(MuxHeader, Vec<u8>), MuxError> {
    let mut hdr = [0u8; MUX_HEADER_LEN];
    stream.read_exact(&mut hdr)?;
    let header = MuxHeader::from_bytes(&hdr)?;
    let mut payload = vec![0u8; header.payload_len()];
    if !payload.is_empty() {
        stream.read_exact(&mut payload)?;
    }
    Ok((header, payload))
}

// ---------------------------------------------------------------------------
// Device records
// ---------------------------------------------------------------------------

/// How a device is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Attached over USB.
    Usb,
    /// Reachable over the network (wireless debugging).
    Network,
    /// The daemon reported something we do not model.
    Unknown,
}

/// One entry of a `ListDevices` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxDevice {
    /// usbmuxd's handle for the device; the value `Connect` takes.
    pub device_id: u32,
    /// 40-character UDID (`SerialNumber` in the plist).
    pub udid: String,
    /// USB product id, when reported.
    pub product_id: Option<u32>,
    /// Attachment kind.
    pub connection_type: ConnectionType,
}

impl MuxDevice {
    /// Build from the `Properties` dict of a device entry.
    ///
    /// # Errors
    /// Returns [`MuxError::Plist`] when required keys are missing.
    pub fn from_plist(entry: &PlistValue) -> Result<Self, MuxError> {
        let props = entry
            .get("Properties")
            .ok_or_else(|| MuxError::Plist("device entry lacks Properties".to_string()))?;
        let device_id = entry
            .get("DeviceID")
            .or_else(|| props.get("DeviceID"))
            .and_then(PlistValue::as_i64)
            .ok_or_else(|| MuxError::Plist("device entry lacks DeviceID".to_string()))?;
        let udid = props
            .get("SerialNumber")
            .and_then(PlistValue::as_str)
            .ok_or_else(|| MuxError::Plist("device entry lacks SerialNumber".to_string()))?
            .to_string();
        let product_id = props
            .get("ProductID")
            .and_then(PlistValue::as_i64)
            .and_then(|v| u32::try_from(v).ok());
        let connection_type = match props.get("ConnectionType").and_then(PlistValue::as_str) {
            Some("USB") => ConnectionType::Usb,
            Some("Network") => ConnectionType::Network,
            _ => ConnectionType::Unknown,
        };
        Ok(Self {
            device_id: u32::try_from(device_id)
                .map_err(|_| MuxError::Plist(format!("DeviceID {device_id} out of range")))?,
            udid,
            product_id,
            connection_type,
        })
    }
}

/// A pairing record as stored by usbmuxd (`ReadPairRecord`).
///
/// The certificates are opaque DER blobs here; this crate never parses them,
/// it only needs to know that a pairing exists and to be able to hand the
/// record to a TLS layer later.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PairRecord {
    /// `HostID` GUID string.
    pub host_id: Option<String>,
    /// `SystemBUID` GUID string.
    pub system_buid: Option<String>,
    /// `HostCertificate` DER.
    pub host_certificate: Option<Vec<u8>>,
    /// `HostPrivateKey` PEM/DER.
    pub host_private_key: Option<Vec<u8>>,
    /// `DeviceCertificate` DER.
    pub device_certificate: Option<Vec<u8>>,
    /// `EscrowBag`, present once the device has been unlocked while paired.
    pub escrow_bag: Option<Vec<u8>>,
}

impl PairRecord {
    /// Decode from the inner plist of `PairRecordData`.
    #[must_use]
    pub fn from_plist(value: &PlistValue) -> Self {
        let s = |k: &str| {
            value
                .get(k)
                .and_then(PlistValue::as_str)
                .map(ToString::to_string)
        };
        let d = |k: &str| {
            value
                .get(k)
                .and_then(PlistValue::as_data)
                .map(<[u8]>::to_vec)
        };
        Self {
            host_id: s("HostID"),
            system_buid: s("SystemBUID"),
            host_certificate: d("HostCertificate"),
            host_private_key: d("HostPrivateKey"),
            device_certificate: d("DeviceCertificate"),
            escrow_bag: d("EscrowBag"),
        }
    }

    /// True when the record carries enough material to be usable for TLS.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.host_certificate.is_some() && self.host_private_key.is_some()
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Convenience alias for an owned bidirectional stream.
pub trait MuxStream: Read + Write + Send {}
impl<T: Read + Write + Send> MuxStream for T {}

/// Out-of-band writer over a *duplicate* of any writable handle.
///
/// The usbmux analogue of [`TcpInterrupter`]. Once `Connect` succeeds the
/// daemon socket is a byte-for-byte tunnel to the device port, so a second,
/// independently owned handle on that same socket (a `TcpStream::try_clone`,
/// a `UnixStream::try_clone`, a `File::try_clone` on the Windows named pipe)
/// is a legitimate path for the single unframed `\x03` — it lands in the
/// tunnel exactly like a byte written through `send`, without disturbing the
/// reader that owns the original handle.
///
/// The `Mutex` only serialises concurrent interrupters against each other; the
/// reader never touches it.
pub struct StreamInterrupter<T: Write + Send> {
    stream: Mutex<T>,
    description: String,
}

impl<T: Write + Send> std::fmt::Debug for StreamInterrupter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamInterrupter")
            .field("description", &self.description)
            .finish()
    }
}

impl<T: Write + Send> StreamInterrupter<T> {
    /// Wrap an already-duplicated write handle.
    pub fn new(stream: T, description: impl Into<String>) -> Self {
        Self {
            stream: Mutex::new(stream),
            description: description.into(),
        }
    }
}

impl<T: Write + Send> RspInterrupter for StreamInterrupter<T> {
    fn send_out_of_band(&self, data: &[u8]) -> io::Result<()> {
        let mut guard = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("usbmux interrupt handle mutex poisoned"))?;
        guard.write_all(data)?;
        guard.flush()
    }

    fn description(&self) -> String {
        self.description.clone()
    }
}

/// Client identification sent with every usbmuxd request.
const CLIENT_PROG: &str = "rustre-debug-apple";
const CLIENT_VERSION: &str = "1.0";

/// A usbmuxd client over any byte stream.
///
/// After a successful [`UsbmuxClient::connect_device`] the object is consumed
/// and the stream becomes a raw tunnel — no further usbmuxd messages may be
/// sent on it. That is enforced by the type: `connect_device` takes `self`.
pub struct UsbmuxClient<S: MuxStream> {
    stream: S,
    tag: u32,
    description: String,
    /// Second, independently owned write end of the *same* daemon socket, kept
    /// so that the tunnel this client becomes can be written to out of band.
    /// `None` means the host handle could not be duplicated, which stays
    /// visible all the way up to `pause()`.
    interrupter: Option<Arc<dyn RspInterrupter>>,
}

impl<S: MuxStream> std::fmt::Debug for UsbmuxClient<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsbmuxClient")
            .field("description", &self.description)
            .field("tag", &self.tag)
            .field("can_interrupt", &self.interrupter.is_some())
            .finish()
    }
}

impl<S: MuxStream> UsbmuxClient<S> {
    /// Wrap an already-open connection to the daemon.
    pub fn new(stream: S, description: impl Into<String>) -> Self {
        Self {
            stream,
            tag: 0,
            description: description.into(),
            interrupter: None,
        }
    }

    /// Attach a duplicated write end of the same socket (see
    /// [`StreamInterrupter`]). It is carried through `Connect` and becomes the
    /// tunnel's [`RspTransport::interrupter`].
    #[must_use]
    pub fn with_interrupter(mut self, interrupter: Arc<dyn RspInterrupter>) -> Self {
        self.interrupter = Some(interrupter);
        self
    }

    /// The out-of-band write handle, if the host could duplicate one.
    #[must_use]
    pub fn interrupter(&self) -> Option<Arc<dyn RspInterrupter>> {
        self.interrupter.clone()
    }

    /// Human-readable description of the underlying socket.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    const fn next_tag(&mut self) -> u32 {
        self.tag = self.tag.wrapping_add(1);
        self.tag
    }

    fn base_request(message_type: &str) -> BTreeMap<String, PlistValue> {
        let mut map = BTreeMap::new();
        map.insert(
            "MessageType".to_string(),
            PlistValue::String(message_type.to_string()),
        );
        map.insert(
            "ClientVersionString".to_string(),
            PlistValue::String(CLIENT_VERSION.to_string()),
        );
        map.insert(
            "ProgName".to_string(),
            PlistValue::String(CLIENT_PROG.to_string()),
        );
        map.insert("kLibUSBMuxVersion".to_string(), PlistValue::Integer(3));
        map
    }

    /// Send a plist request and read the plist reply.
    ///
    /// # Errors
    /// I/O, framing, or plist decoding failures; also a tag mismatch, which
    /// means the daemon's reply stream has desynchronised.
    pub fn request(&mut self, body: &PlistValue) -> Result<PlistValue, MuxError> {
        let tag = self.next_tag();
        let packet = encode_mux_packet(tag, &body.to_xml());
        self.stream.write_all(&packet)?;
        self.stream.flush()?;
        let (header, payload) = read_mux_packet(&mut self.stream)?;
        if header.tag != tag {
            return Err(MuxError::Protocol(format!(
                "reply tag {} does not match request tag {tag}",
                header.tag
            )));
        }
        if header.message != MUX_MESSAGE_PLIST || header.version != MUX_VERSION_PLIST {
            return Err(MuxError::Protocol(format!(
                "unexpected reply version/message {}/{}",
                header.version, header.message
            )));
        }
        let text = std::str::from_utf8(&payload)
            .map_err(|_| MuxError::Plist("reply payload is not UTF-8".to_string()))?;
        PlistValue::parse_xml(text)
    }

    /// Check a `Result` reply and map a non-zero `Number` to an error.
    fn check_result(reply: &PlistValue) -> Result<(), MuxError> {
        let msg = reply.get("MessageType").and_then(PlistValue::as_str);
        if msg != Some("Result") {
            return Err(MuxError::Protocol(format!(
                "expected Result message, got {msg:?}"
            )));
        }
        let code = reply
            .get("Number")
            .and_then(PlistValue::as_i64)
            .ok_or_else(|| MuxError::Plist("Result lacks Number".to_string()))?;
        let code = u64::try_from(code).unwrap_or(u64::MAX);
        if code == 0 {
            Ok(())
        } else {
            Err(MuxError::Refused {
                code,
                reason: mux_result_reason(code),
            })
        }
    }

    /// `ListDevices`: enumerate everything the daemon currently knows about.
    ///
    /// # Errors
    /// Transport failures, or a reply that is not a `DeviceList`.
    pub fn list_devices(&mut self) -> Result<Vec<MuxDevice>, MuxError> {
        let reply = self.request(&PlistValue::Dict(Self::base_request("ListDevices")))?;
        let list = reply
            .get("DeviceList")
            .and_then(PlistValue::as_array)
            .ok_or_else(|| MuxError::Plist("reply lacks DeviceList".to_string()))?;
        let mut out = Vec::with_capacity(list.len());
        for entry in list {
            out.push(MuxDevice::from_plist(entry)?);
        }
        Ok(out)
    }

    /// `ReadPairRecord`: fetch the stored pairing for `udid`.
    ///
    /// # Errors
    /// [`MuxError::Refused`] when the device is not paired; plist errors when
    /// the record cannot be decoded.
    pub fn read_pair_record(&mut self, udid: &str) -> Result<PairRecord, MuxError> {
        let mut body = Self::base_request("ReadPairRecord");
        body.insert(
            "PairRecordID".to_string(),
            PlistValue::String(udid.to_string()),
        );
        let reply = self.request(&PlistValue::Dict(body))?;
        if reply.get("MessageType").and_then(PlistValue::as_str) == Some("Result") {
            // A bare Result here is always a failure path; success carries data.
            Self::check_result(&reply)?;
            return Err(MuxError::Plist(
                "ReadPairRecord returned Result(0) without PairRecordData".to_string(),
            ));
        }
        let data = reply
            .get("PairRecordData")
            .and_then(PlistValue::as_data)
            .ok_or_else(|| MuxError::Plist("reply lacks PairRecordData".to_string()))?;
        let text = std::str::from_utf8(data)
            .map_err(|_| MuxError::Plist("PairRecordData is not UTF-8 plist".to_string()))?;
        let inner = PlistValue::parse_xml(text)?;
        Ok(PairRecord::from_plist(&inner))
    }

    /// `Connect`: forward `port` on `device_id` onto this stream.
    ///
    /// On success the stream is no longer a usbmuxd control channel; it is a
    /// transparent tunnel to the device port, which is why `self` is consumed
    /// and a plain stream comes back.
    ///
    /// # Errors
    /// [`MuxError::Refused`] when the device or port is unavailable.
    pub fn connect_device(mut self, device_id: u32, port: u16) -> Result<S, MuxError> {
        let mut body = Self::base_request("Connect");
        body.insert(
            "DeviceID".to_string(),
            PlistValue::Integer(i64::from(device_id)),
        );
        // usbmuxd wants the port in network byte order inside a host-order field.
        body.insert(
            "PortNumber".to_string(),
            PlistValue::Integer(i64::from(port.to_be())),
        );
        let reply = self.request(&PlistValue::Dict(body))?;
        Self::check_result(&reply)?;
        Ok(self.stream)
    }
}

// ---------------------------------------------------------------------------
// RSP transports
// ---------------------------------------------------------------------------

/// TCP transport to a `debugserver` reachable by address.
#[derive(Debug)]
pub struct TcpRspTransport {
    stream: TcpStream,
    peer: String,
    /// Duplicated write end for asynchronous `\x03` (see
    /// [`RspTransport::interrupter`]).
    interrupter: Option<Arc<TcpInterrupter>>,
}

impl TcpRspTransport {
    /// Connect to `addr` with an optional read/write timeout.
    ///
    /// # Errors
    /// Propagates connect and socket-option failures.
    pub fn connect<A: ToSocketAddrs>(addr: A, timeout: Option<Duration>) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        let peer = stream
            .peer_addr()
            .map_or_else(|_| "<unknown>".to_string(), |a| a.to_string());
        let interrupter = TcpInterrupter::from_stream(&stream, peer.clone()).ok().map(Arc::new);
        Ok(Self { stream, peer, interrupter })
    }

    /// Peer address as a string.
    #[must_use]
    pub fn peer(&self) -> &str {
        &self.peer
    }
}

impl RspTransport for TcpRspTransport {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(data)?;
        self.stream.flush()
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }

    fn description(&self) -> String {
        format!("tcp:{}", self.peer)
    }

    fn interrupter(&self) -> Option<Arc<dyn RspInterrupter>> {
        self.interrupter
            .clone()
            .map(|i| i as Arc<dyn RspInterrupter>)
    }
}

/// An RSP transport riding a usbmuxd tunnel to a device port.
///
/// # Out-of-band writes
///
/// The `MuxStream` bound alone cannot duplicate the tunnel — it is one
/// `Read + Write` owned by this struct. So the duplicate is made *earlier*,
/// where the concrete host handle is still known ([`connect_usbmuxd`] does a
/// `try_clone` on the TCP socket / Unix socket / Windows pipe handle), carried
/// through `Connect` by [`UsbmuxClient::with_interrupter`], and surfaced here
/// as [`RspTransport::interrupter`]. Since the tunnel is byte-transparent
/// after `Connect`, a `\x03` written on that second handle arrives at
/// `debugserver` on the device exactly as one written through `send`.
///
/// When the host handle cannot be duplicated the interrupter stays `None`, and
/// `AppleDebugger::pause()` refuses with a reason naming the transport rather
/// than reporting a delivery that never happened.
pub struct UsbmuxRspTransport<S: MuxStream> {
    stream: S,
    description: String,
    interrupter: Option<Arc<dyn RspInterrupter>>,
}

impl<S: MuxStream> std::fmt::Debug for UsbmuxRspTransport<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsbmuxRspTransport")
            .field("description", &self.description)
            .finish()
    }
}

impl<S: MuxStream> UsbmuxRspTransport<S> {
    /// Wrap an already-tunnelled stream.
    pub fn new(stream: S, description: impl Into<String>) -> Self {
        Self {
            stream,
            description: description.into(),
            interrupter: None,
        }
    }

    /// Attach the duplicated write end used for asynchronous `\x03`.
    #[must_use]
    pub fn with_interrupter(mut self, interrupter: Arc<dyn RspInterrupter>) -> Self {
        self.interrupter = Some(interrupter);
        self
    }

    /// Perform `Connect` on `client` and wrap the resulting tunnel.
    ///
    /// The client's out-of-band handle, if it has one, becomes the tunnel's.
    ///
    /// # Errors
    /// Any usbmuxd failure while establishing the tunnel.
    pub fn connect(client: UsbmuxClient<S>, device_id: u32, port: u16) -> Result<Self, MuxError> {
        let description = format!("usbmux:{}/device{device_id}:{port}", client.description());
        let interrupter = client.interrupter();
        let stream = client.connect_device(device_id, port)?;
        let transport = Self::new(stream, description);
        Ok(match interrupter {
            Some(i) => transport.with_interrupter(i),
            None => transport,
        })
    }
}

impl<S: MuxStream> RspTransport for UsbmuxRspTransport<S> {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(data)?;
        self.stream.flush()
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }

    fn description(&self) -> String {
        self.description.clone()
    }

    fn interrupter(&self) -> Option<Arc<dyn RspInterrupter>> {
        self.interrupter.clone()
    }
}

// ---------------------------------------------------------------------------
// Host socket
// ---------------------------------------------------------------------------

/// Open a connection to the local usbmuxd daemon.
///
/// * Windows: the named pipe `\\.\pipe\iTunes`, falling back to
///   `127.0.0.1:27015` when the pipe is absent.
/// * Unix: the socket `/var/run/usbmuxd`, falling back to the same TCP port
///   (the shape `usbmuxd -t` / `usbfluxd` expose).
///
/// # Errors
/// Returns [`MuxError::Unsupported`] with both underlying failures attached
/// when neither path is reachable — never a silent fallback to a stub.
pub fn connect_usbmuxd() -> Result<UsbmuxClient<Box<dyn MuxStream>>, MuxError> {
    let native = open_native_usbmuxd();
    match native {
        Ok((stream, desc, interrupter)) => Ok(attach_interrupter(
            UsbmuxClient::new(stream, desc),
            interrupter,
        )),
        Err(primary) => match TcpStream::connect(USBMUXD_TCP_FALLBACK) {
            Ok(tcp) => {
                tcp.set_nodelay(true)?;
                let interrupter = tcp_interrupter(&tcp, USBMUXD_TCP_FALLBACK);
                let boxed: Box<dyn MuxStream> = Box::new(tcp);
                Ok(attach_interrupter(
                    UsbmuxClient::new(boxed, format!("tcp:{USBMUXD_TCP_FALLBACK}")),
                    interrupter,
                ))
            }
            Err(secondary) => Err(MuxError::Unsupported(format!(
                "no usbmuxd endpoint: native ({primary}); tcp {USBMUXD_TCP_FALLBACK} ({secondary})"
            ))),
        },
    }
}

/// Duplicate a TCP socket for out-of-band `\x03`; `None` when the host refuses.
fn tcp_interrupter(stream: &TcpStream, label: &str) -> Option<Arc<dyn RspInterrupter>> {
    stream.try_clone().ok().map(|dup| {
        Arc::new(StreamInterrupter::new(
            dup,
            format!("usbmux-interrupt:tcp:{label}"),
        )) as Arc<dyn RspInterrupter>
    })
}

/// Apply an optional interrupter without shadowing the `None` case.
fn attach_interrupter<S: MuxStream>(
    client: UsbmuxClient<S>,
    interrupter: Option<Arc<dyn RspInterrupter>>,
) -> UsbmuxClient<S> {
    match interrupter {
        Some(i) => client.with_interrupter(i),
        None => client,
    }
}

#[cfg(windows)]
fn open_native_usbmuxd() -> io::Result<(Box<dyn MuxStream>, String, Option<Arc<dyn RspInterrupter>>)>
{
    // A Windows named pipe opened in duplex mode is a normal file handle;
    // `std::fs::File` implements both `Read` and `Write` over it, so no
    // `unsafe` and no extra dependency is needed for the byte-stream role.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(USBMUXD_PIPE_WINDOWS)?;
    // A duplicated pipe handle is what makes `pause()` possible over USB on
    // Windows: `File::try_clone` is `DuplicateHandle` underneath, and both
    // handles write into the same pipe instance.
    let interrupter = file.try_clone().ok().map(|dup| {
        Arc::new(StreamInterrupter::new(
            dup,
            format!("usbmux-interrupt:pipe:{USBMUXD_PIPE_WINDOWS}"),
        )) as Arc<dyn RspInterrupter>
    });
    Ok((
        Box::new(file) as Box<dyn MuxStream>,
        format!("pipe:{USBMUXD_PIPE_WINDOWS}"),
        interrupter,
    ))
}

#[cfg(unix)]
fn open_native_usbmuxd() -> io::Result<(Box<dyn MuxStream>, String, Option<Arc<dyn RspInterrupter>>)>
{
    let sock = std::os::unix::net::UnixStream::connect(USBMUXD_SOCKET_UNIX)?;
    let interrupter = sock.try_clone().ok().map(|dup| {
        Arc::new(StreamInterrupter::new(
            dup,
            format!("usbmux-interrupt:unix:{USBMUXD_SOCKET_UNIX}"),
        )) as Arc<dyn RspInterrupter>
    });
    Ok((
        Box::new(sock) as Box<dyn MuxStream>,
        format!("unix:{USBMUXD_SOCKET_UNIX}"),
        interrupter,
    ))
}

#[cfg(not(any(windows, unix)))]
fn open_native_usbmuxd() -> io::Result<(Box<dyn MuxStream>, String, Option<Arc<dyn RspInterrupter>>)>
{
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no native usbmuxd endpoint on this platform",
    ))
}

/// End-to-end helper: find a device by UDID (or take the first one), open a
/// tunnel to `port`, and return an [`RspTransport`] for it.
///
/// # Errors
/// Any usbmuxd failure, or [`MuxError::Refused`] with code 6 when no device
/// matches `udid`.
pub fn open_device_port(
    udid: Option<&str>,
    port: u16,
) -> Result<UsbmuxRspTransport<Box<dyn MuxStream>>, MuxError> {
    open_device_port_with(connect_usbmuxd()?, udid, port)
}

/// Same as [`open_device_port`] but against a daemon reachable over TCP
/// (`usbmuxd -t`, `usbfluxd`, an SSH forward — and [`MockMuxd`] in tests).
///
/// # Errors
/// Connect failures, plus everything [`open_device_port`] can return.
pub fn open_device_port_at(
    daemon_addr: &str,
    udid: Option<&str>,
    port: u16,
) -> Result<UsbmuxRspTransport<Box<dyn MuxStream>>, MuxError> {
    let tcp = TcpStream::connect(daemon_addr)?;
    tcp.set_nodelay(true)?;
    let interrupter = tcp_interrupter(&tcp, daemon_addr);
    let boxed: Box<dyn MuxStream> = Box::new(tcp);
    let client = attach_interrupter(
        UsbmuxClient::new(boxed, format!("tcp:{daemon_addr}")),
        interrupter,
    );
    open_device_port_with(client, udid, port)
}

/// Pick the device and open the tunnel on an already-connected daemon client.
///
/// # Errors
/// Any usbmuxd failure, or [`MuxError::Refused`] with code 6 when no device
/// matches `udid`.
pub fn open_device_port_with(
    mut client: UsbmuxClient<Box<dyn MuxStream>>,
    udid: Option<&str>,
    port: u16,
) -> Result<UsbmuxRspTransport<Box<dyn MuxStream>>, MuxError> {
    let devices = client.list_devices()?;
    let device = match udid {
        Some(want) => devices.into_iter().find(|d| d.udid == want),
        None => devices.into_iter().next(),
    }
    .ok_or(MuxError::Refused {
        code: 6,
        reason: mux_result_reason(6),
    })?;
    UsbmuxRspTransport::connect(client, device.device_id, port)
}

// ---------------------------------------------------------------------------
// Mock daemon
// ---------------------------------------------------------------------------

/// An in-process usbmuxd that speaks the real protocol.
///
/// This is what makes the client testable on Windows: it frames and parses the
/// exact same headers and plists a real daemon would.
#[derive(Debug, Clone)]
pub struct MockMuxd {
    /// Devices reported by `ListDevices`.
    pub devices: Vec<MuxDevice>,
    /// Pair records keyed by UDID, as inner plists.
    pub pair_records: BTreeMap<String, PlistValue>,
    /// Ports the mock will accept `Connect` for.
    pub open_ports: Vec<u16>,
    /// Bytes handed to the client once a tunnel is established.
    pub tunnel_greeting: Vec<u8>,
}

impl Default for MockMuxd {
    fn default() -> Self {
        Self {
            devices: vec![MuxDevice {
                device_id: 7,
                udid: "00008030-000A1B2C3D4E5F60".to_string(),
                product_id: Some(0x12a8),
                connection_type: ConnectionType::Usb,
            }],
            pair_records: BTreeMap::new(),
            open_ports: vec![6666],
            tunnel_greeting: Vec::new(),
        }
    }
}

impl MockMuxd {
    /// Build a mock with the default single USB device.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pair record for `udid`.
    #[must_use]
    pub fn with_pair_record(mut self, udid: &str, record: PlistValue) -> Self {
        self.pair_records.insert(udid.to_string(), record);
        self
    }

    /// Bytes to emit on the tunnel after a successful `Connect`.
    #[must_use]
    pub fn with_tunnel_greeting(mut self, bytes: &[u8]) -> Self {
        self.tunnel_greeting = bytes.to_vec();
        self
    }

    fn device_list_plist(&self) -> PlistValue {
        let entries: Vec<PlistValue> = self
            .devices
            .iter()
            .map(|d| {
                let mut props = BTreeMap::new();
                props.insert(
                    "SerialNumber".to_string(),
                    PlistValue::String(d.udid.clone()),
                );
                props.insert(
                    "ConnectionType".to_string(),
                    PlistValue::String(
                        match d.connection_type {
                            ConnectionType::Usb => "USB",
                            ConnectionType::Network => "Network",
                            ConnectionType::Unknown => "Other",
                        }
                        .to_string(),
                    ),
                );
                if let Some(pid) = d.product_id {
                    props.insert("ProductID".to_string(), PlistValue::Integer(i64::from(pid)));
                }
                props.insert(
                    "DeviceID".to_string(),
                    PlistValue::Integer(i64::from(d.device_id)),
                );
                PlistValue::dict([
                    ("MessageType".to_string(), PlistValue::String("Attached".to_string())),
                    (
                        "DeviceID".to_string(),
                        PlistValue::Integer(i64::from(d.device_id)),
                    ),
                    ("Properties".to_string(), PlistValue::Dict(props)),
                ])
            })
            .collect();
        PlistValue::dict([("DeviceList".to_string(), PlistValue::Array(entries))])
    }

    fn result(code: i64) -> PlistValue {
        PlistValue::dict([
            (
                "MessageType".to_string(),
                PlistValue::String("Result".to_string()),
            ),
            ("Number".to_string(), PlistValue::Integer(code)),
        ])
    }

    /// Answer one request. `Ok(None)` means "the tunnel is now open".
    ///
    /// # Errors
    /// Plist decoding failures on the request.
    pub fn handle(&self, request: &PlistValue) -> Result<(PlistValue, bool), MuxError> {
        let msg = request
            .get("MessageType")
            .and_then(PlistValue::as_str)
            .ok_or_else(|| MuxError::Plist("request lacks MessageType".to_string()))?;
        match msg {
            "ListDevices" => Ok((self.device_list_plist(), false)),
            "ReadPairRecord" => {
                let udid = request
                    .get("PairRecordID")
                    .and_then(PlistValue::as_str)
                    .ok_or_else(|| MuxError::Plist("ReadPairRecord lacks PairRecordID".into()))?;
                self.pair_records.get(udid).map_or_else(
                    || Ok((Self::result(6), false)),
                    |record| {
                        Ok((
                            PlistValue::dict([(
                                "PairRecordData".to_string(),
                                PlistValue::Data(record.to_xml().into_bytes()),
                            )]),
                            false,
                        ))
                    },
                )
            }
            "Connect" => {
                let device_id = request
                    .get("DeviceID")
                    .and_then(PlistValue::as_i64)
                    .ok_or_else(|| MuxError::Plist("Connect lacks DeviceID".to_string()))?;
                let raw_port = request
                    .get("PortNumber")
                    .and_then(PlistValue::as_i64)
                    .ok_or_else(|| MuxError::Plist("Connect lacks PortNumber".to_string()))?;
                let port = u16::try_from(raw_port & 0xffff)
                    .map(u16::to_be)
                    .map_err(|_| MuxError::Plist("PortNumber out of range".to_string()))?;
                let known = self
                    .devices
                    .iter()
                    .any(|d| i64::from(d.device_id) == device_id);
                if !known {
                    return Ok((Self::result(2), false));
                }
                if !self.open_ports.contains(&port) {
                    return Ok((Self::result(3), false));
                }
                Ok((Self::result(0), true))
            }
            other => Err(MuxError::Protocol(format!("unhandled request {other}"))),
        }
    }

    /// Serve requests on `stream` until the client disconnects or a tunnel is
    /// opened; after a tunnel opens, the greeting is written and the stream is
    /// echoed back to the caller.
    ///
    /// # Errors
    /// I/O and protocol failures.
    pub fn serve<S: Read + Write>(&self, stream: &mut S) -> Result<(), MuxError> {
        loop {
            let (header, payload) = match read_mux_packet(stream) {
                Ok(v) => v,
                Err(MuxError::Io(e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let text = std::str::from_utf8(&payload)
                .map_err(|_| MuxError::Plist("request payload not UTF-8".to_string()))?;
            let request = PlistValue::parse_xml(text)?;
            let (reply, tunnel) = self.handle(&request)?;
            stream.write_all(&encode_mux_packet(header.tag, &reply.to_xml()))?;
            stream.flush()?;
            if tunnel {
                if !self.tunnel_greeting.is_empty() {
                    stream.write_all(&self.tunnel_greeting)?;
                    stream.flush()?;
                }
                // Echo mode: whatever the debugger writes comes straight back,
                // which is enough to prove the tunnel is byte-transparent.
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => return Ok(()),
                        Ok(n) => {
                            stream.write_all(&buf[..n])?;
                            stream.flush()?;
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionAborted
                            ) =>
                        {
                            return Ok(());
                        }
                        Err(e) => return Err(MuxError::Io(e)),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn sample_pair_record() -> PlistValue {
        PlistValue::dict([
            (
                "HostID".to_string(),
                PlistValue::String("11111111-2222-3333-4444-555555555555".to_string()),
            ),
            (
                "SystemBUID".to_string(),
                PlistValue::String("AABBCCDD-EEFF".to_string()),
            ),
            (
                "HostCertificate".to_string(),
                PlistValue::Data(vec![0x30, 0x82, 0x01, 0x0a]),
            ),
            (
                "HostPrivateKey".to_string(),
                PlistValue::Data(b"-----BEGIN RSA PRIVATE KEY-----".to_vec()),
            ),
        ])
    }

    /// Start a `MockMuxd` on loopback; returns the address and the join handle.
    fn spawn_mock(mock: MockMuxd) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("addr").to_string();
        let handle = thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = mock.serve(&mut sock);
            }
        });
        (addr, handle)
    }

    fn client_to(addr: &str) -> UsbmuxClient<TcpStream> {
        let s = TcpStream::connect(addr).expect("connect mock");
        s.set_nodelay(true).expect("nodelay");
        UsbmuxClient::new(s, format!("tcp:{addr}"))
    }

    #[test]
    fn header_roundtrip() {
        let h = MuxHeader {
            length: 100,
            version: MUX_VERSION_PLIST,
            message: MUX_MESSAGE_PLIST,
            tag: 42,
        };
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), MUX_HEADER_LEN);
        assert_eq!(&bytes[0..4], &100u32.to_le_bytes());
        assert_eq!(MuxHeader::from_bytes(&bytes).expect("decode"), h);
        assert_eq!(h.payload_len(), 84);
    }

    #[test]
    fn header_rejects_hostile_values() {
        let mut bytes = MuxHeader {
            length: 4,
            version: 1,
            message: 8,
            tag: 1,
        }
        .to_bytes();
        assert!(MuxHeader::from_bytes(&bytes).is_err(), "length below header");
        bytes[0..4].copy_from_slice(&(MUX_MAX_PAYLOAD + 64).to_le_bytes());
        assert!(MuxHeader::from_bytes(&bytes).is_err(), "payload cap");
        assert!(MuxHeader::from_bytes(&bytes[..8]).is_err(), "short header");
    }

    #[test]
    fn base64_roundtrips_all_lengths() {
        for len in 0..64usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let enc = base64_encode(&data);
            assert_eq!(base64_decode(&enc).expect("decode"), data, "len {len}");
        }
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"M"), "TQ==");
        assert!(base64_decode("!!!!").is_err());
        assert!(base64_decode("TWF").is_err());
    }

    #[test]
    fn base64_rejects_impossible_final_quantum() {
        // A final quantum of a single symbol carries 6 bits: it can never be a
        // whole byte, so no encoder produces it and it must not decode.
        assert!(base64_decode("A===").is_err(), "1-symbol quantum, 3 pads");
        assert!(base64_decode("TWFuA===").is_err(), "trailing 1-symbol quantum");
        assert!(
            base64_decode("TWFu\n A===").is_err(),
            "whitespace must not hide a 1-symbol quantum"
        );
        // More than two pad characters is likewise unrepresentable.
        assert!(base64_decode("TWFu====").is_err(), "4 pad characters");
        assert!(base64_decode("===").is_err(), "padding only");
        // Every legal shape still decodes.
        assert_eq!(base64_decode("").expect("empty"), Vec::<u8>::new());
        assert_eq!(base64_decode("TWFu").expect("no pad"), b"Man".to_vec());
        assert_eq!(base64_decode("TWE=").expect("one pad"), b"Ma".to_vec());
        assert_eq!(base64_decode("TQ==").expect("two pads"), b"M".to_vec());
    }

    #[test]
    fn plist_roundtrip() {
        let v = PlistValue::dict([
            ("MessageType".to_string(), PlistValue::String("Connect".to_string())),
            ("DeviceID".to_string(), PlistValue::Integer(7)),
            ("Flag".to_string(), PlistValue::Boolean(true)),
            ("Blob".to_string(), PlistValue::Data(vec![1, 2, 3, 255])),
            (
                "List".to_string(),
                PlistValue::Array(vec![
                    PlistValue::Integer(1),
                    PlistValue::String("a<b&c".to_string()),
                ]),
            ),
        ]);
        let xml = v.to_xml();
        let back = PlistValue::parse_xml(&xml).expect("parse");
        assert_eq!(back, v);
    }

    #[test]
    fn plist_rejects_garbage_and_deep_nesting() {
        assert!(PlistValue::parse_xml("not xml at all").is_err());
        assert!(PlistValue::parse_xml("<dict><key>a</key></dict>").is_err());
        assert!(PlistValue::parse_xml("<unsupported/>").is_err());
        let deep = "<array>".repeat(64) + &"</array>".repeat(64);
        assert!(PlistValue::parse_xml(&deep).is_err(), "depth cap");
    }

    #[test]
    fn packet_framing_matches_header() {
        let pkt = encode_mux_packet(9, "<plist/>");
        let hdr = MuxHeader::from_bytes(&pkt).expect("hdr");
        assert_eq!(hdr.tag, 9);
        assert_eq!(hdr.length as usize, pkt.len());
        assert_eq!(hdr.payload_len(), "<plist/>".len());
        let mut cursor = std::io::Cursor::new(pkt);
        let (h2, body) = read_mux_packet(&mut cursor).expect("read");
        assert_eq!(h2, hdr);
        assert_eq!(body, b"<plist/>");
    }

    #[test]
    fn list_devices_against_mock() {
        let (addr, handle) = spawn_mock(MockMuxd::new());
        let mut client = client_to(&addr);
        let devices = client.list_devices().expect("list");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, 7);
        assert_eq!(devices[0].udid, "00008030-000A1B2C3D4E5F60");
        assert_eq!(devices[0].connection_type, ConnectionType::Usb);
        drop(client);
        handle.join().expect("join");
    }

    #[test]
    fn read_pair_record_against_mock() {
        let mock = MockMuxd::new()
            .with_pair_record("00008030-000A1B2C3D4E5F60", sample_pair_record());
        let (addr, handle) = spawn_mock(mock);
        let mut client = client_to(&addr);
        let record = client
            .read_pair_record("00008030-000A1B2C3D4E5F60")
            .expect("pair record");
        assert_eq!(
            record.host_id.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert!(record.is_usable());
        assert_eq!(record.host_certificate.as_deref(), Some(&[0x30u8, 0x82, 0x01, 0x0a][..]));
        drop(client);
        handle.join().expect("join");
    }

    #[test]
    fn read_pair_record_unpaired_is_explicit_error() {
        let (addr, handle) = spawn_mock(MockMuxd::new());
        let mut client = client_to(&addr);
        let err = client.read_pair_record("nope").expect_err("must fail");
        match err {
            MuxError::Refused { code, .. } => assert_eq!(code, 6),
            other => panic!("unexpected error: {other}"),
        }
        drop(client);
        handle.join().expect("join");
    }

    #[test]
    fn connect_opens_transparent_tunnel() {
        let mock = MockMuxd::new().with_tunnel_greeting(b"$OK#9a");
        let (addr, handle) = spawn_mock(mock);
        let client = client_to(&addr);
        let mut transport =
            UsbmuxRspTransport::connect(client, 7, 6666).expect("tunnel");
        assert!(transport.description().contains("device7:6666"));
        let mut buf = [0u8; 6];
        let mut got = 0;
        while got < buf.len() {
            let n = transport.recv(&mut buf[got..]).expect("greeting");
            assert!(n > 0, "unexpected EOF");
            got += n;
        }
        assert_eq!(&buf, b"$OK#9a");
        transport.send(b"$qHostInfo#9b").expect("send");
        let mut echo = [0u8; 13];
        let mut got = 0;
        while got < echo.len() {
            let n = transport.recv(&mut echo[got..]).expect("echo");
            assert!(n > 0, "unexpected EOF");
            got += n;
        }
        assert_eq!(&echo, b"$qHostInfo#9b");
        drop(transport);
        handle.join().expect("join");
    }

    #[test]
    fn connect_to_closed_port_is_refused() {
        let (addr, handle) = spawn_mock(MockMuxd::new());
        let client = client_to(&addr);
        let err = UsbmuxRspTransport::connect(client, 7, 9999).expect_err("must fail");
        match err {
            MuxError::Refused { code, reason } => {
                assert_eq!(code, 3);
                assert_eq!(reason, mux_result_reason(3));
            }
            other => panic!("unexpected error: {other}"),
        }
        handle.join().expect("join");
    }

    #[test]
    fn connect_to_unknown_device_is_refused() {
        let (addr, handle) = spawn_mock(MockMuxd::new());
        let client = client_to(&addr);
        let err = UsbmuxRspTransport::connect(client, 123, 6666).expect_err("must fail");
        assert!(matches!(err, MuxError::Refused { code: 2, .. }));
        handle.join().expect("join");
    }

    #[test]
    fn connect_port_is_byte_swapped_on_the_wire() {
        // The mock swaps back, so a round trip proves both directions agree
        // with usbmuxd's htons-in-a-host-field convention.
        let mut body = BTreeMap::new();
        body.insert(
            "MessageType".to_string(),
            PlistValue::String("Connect".to_string()),
        );
        body.insert("DeviceID".to_string(), PlistValue::Integer(7));
        body.insert(
            "PortNumber".to_string(),
            PlistValue::Integer(i64::from(6666u16.to_be())),
        );
        let request = PlistValue::Dict(body);
        assert_eq!(
            request.get("PortNumber").and_then(PlistValue::as_i64),
            Some(i64::from(6666u16.to_be()))
        );
        let (reply, tunnel) = MockMuxd::new().handle(&request).expect("handle");
        assert!(tunnel);
        assert_eq!(reply.get("Number").and_then(PlistValue::as_i64), Some(0));
    }

    #[test]
    fn tag_mismatch_is_detected() {
        // Server that always replies with tag 0xdead, regardless of request.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let handle = thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept()
                && read_mux_packet(&mut sock).is_ok() {
                    let reply = MockMuxd::result(0);
                    let _ = sock.write_all(&encode_mux_packet(0xdead, &reply.to_xml()));
                }
        });
        let mut client = client_to(&addr);
        let err = client.list_devices().expect_err("must fail");
        assert!(matches!(err, MuxError::Protocol(_)), "got {err}");
        drop(client);
        handle.join().expect("join");
    }

    #[test]
    fn tcp_rsp_transport_talks_to_a_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 5];
                if sock.read_exact(&mut buf).is_ok() {
                    let _ = sock.write_all(b"+");
                }
            }
        });
        let mut t = TcpRspTransport::connect(addr, Some(Duration::from_secs(5))).expect("connect");
        assert!(t.description().starts_with("tcp:"));
        t.send(b"$g#67").expect("send");
        let mut buf = [0u8; 1];
        assert_eq!(t.recv(&mut buf).expect("recv"), 1);
        assert_eq!(&buf, b"+");
        handle.join().expect("join");
    }

    #[test]
    fn connect_usbmuxd_failure_is_explicit_not_a_stub() {
        // On a developer box with no iOS tooling this must be a loud error.
        match connect_usbmuxd() {
            Ok(client) => assert!(!client.description().is_empty()),
            Err(MuxError::Unsupported(msg)) => {
                assert!(msg.contains("no usbmuxd endpoint"), "{msg}");
            }
            Err(other) => panic!("unexpected error shape: {other}"),
        }
    }

    /// A session built over the **USB** factory must be interruptible, and the
    /// `\x03` must actually reach the mux framing layer.
    ///
    /// Both halves matter and both were missing:
    ///
    /// * no `TransportFactory` wrapped the usbmux transport, so an
    ///   `AppleDebugger` could not be constructed over a cable at all — the
    ///   factory call below would not have compiled;
    /// * `UsbmuxRspTransport` implemented `send`/`recv`/`description` but not
    ///   `interrupter()`, so `interrupter()` fell through to the trait default
    ///   `None` and `pause()` was structurally impossible over USB.
    ///
    /// Delivery is proven, not assumed: the reader is parked in `recv` on the
    /// tunnel (exactly the window `pause` exists for) while another thread
    /// writes the byte through the second handle, and `MockMuxd`'s post-Connect
    /// echo returns whatever crossed the tunnel. Getting `0x03` back means the
    /// byte went through the real framed `Connect` and out the far side.
    ///
    /// What this does NOT prove: there is no iPhone here. `MockMuxd` speaks the
    /// usbmuxd protocol over loopback TCP, so the duplicated handle is a
    /// `TcpStream::try_clone`. On a real host the daemon handle is a Windows
    /// named pipe or a Unix socket; those `try_clone` calls are exercised only
    /// on hardware. Nor does it prove a `debugserver` on the far side answers
    /// the interrupt with a SIGINT stop reply — the mock echoes, it does not
    /// debug. It proves the transport-level capability that was absent.
    #[test]
    fn a_usb_session_can_be_interrupted_and_the_byte_crosses_the_tunnel() {
        use crate::ios::apple_debugger::{
            ConnectRequest, TransportFactory, UsbmuxDebugserverFactory,
        };
        use crate::ios::rsp::RSP_INTERRUPT_BYTE;
        use crate::ProcessId;

        let (addr, handle) = spawn_mock(MockMuxd::new());

        let factory = UsbmuxDebugserverFactory::at_daemon(&addr, None, 6666);
        assert!(
            factory.description().contains("usbmux"),
            "the factory must identify itself as the USB path, got {}",
            factory.description()
        );
        let mut transport = factory
            .connect(&ConnectRequest::Attach(ProcessId(4242)))
            .expect("the USB factory must open a tunnel through the mock daemon");

        let interrupter = transport
            .interrupter()
            .expect("a usbmux transport must expose an out-of-band write handle");

        // Park a reader on the tunnel, as a resume does.
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = thread::spawn(move || {
            let mut buf = [0u8; 8];
            let n = transport.recv(&mut buf).expect("tunnel read");
            let _ = tx.send(buf[..n].to_vec());
            transport
        });

        interrupter
            .interrupt()
            .expect("writing \\x03 on the duplicated handle must succeed");

        let echoed = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the interrupt byte never came back through the tunnel");
        assert_eq!(
            echoed,
            vec![RSP_INTERRUPT_BYTE],
            "the byte that crossed the mux tunnel must be exactly \\x03"
        );
        assert!(
            interrupter.description().contains("usbmux-interrupt"),
            "diagnostics must name the usbmux path, got {}",
            interrupter.description()
        );

        // Both ends of the duplicated socket must go before the mock can see
        // EOF and wind down: the transport half AND the interrupt half.
        drop(reader.join().expect("reader thread"));
        drop(interrupter);
        let _ = handle.join();
    }

    /// The debugger itself must be constructible over USB, and say so.
    #[test]
    fn apple_debugger_can_be_built_over_the_usb_factory() {
        let dbg = crate::ios::apple_debugger::AppleDebugger::usbmux_at(
            "127.0.0.1:27015",
            Some("00008030-000A1B2C3D4E5F60".to_string()),
            6666,
        );
        let rendered = format!("{dbg:?}");
        assert!(
            rendered.contains("usbmux"),
            "a USB-backed debugger must name its transport, got {rendered}"
        );
    }
}
