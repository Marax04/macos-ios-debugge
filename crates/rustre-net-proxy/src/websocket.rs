//! `websocket` — WebSocket frame parsing, reassembly, and upgrade detection.
//!
//! Provides:
//! - [`WsOpcode`] / [`WebSocketFrame`] — RFC 6455 §5.2 frame model with
//!   masking-aware parse/serialise.
//! - [`detect_websocket_upgrade`] — recognise WS upgrade handshakes on an
//!   [`HttpRequest`].
//! - [`parse_websocket_stream`] — greedy parse of as many frames as a buffer
//!   contains.
//! - [`reassemble_ws_messages`] — collapse Continuation chains into whole
//!   messages, leaving control frames interleaved.

use crate::HttpRequest;

/// WebSocket opcode as defined in RFC 6455 §5.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsOpcode {
    /// UTF-8 text data frame.
    Text,
    /// Binary data frame.
    Binary,
    /// Connection close control frame.
    Close,
    /// Ping control frame.
    Ping,
    /// Pong control frame.
    Pong,
    /// Continuation frame for a fragmented message.
    Continuation,
    /// An opcode value not enumerated above.
    Unknown(u8),
}

impl WsOpcode {
    /// Decode the raw 4-bit opcode from a WebSocket frame byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b & 0x0F {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            n => Self::Unknown(n),
        }
    }

    /// Return the raw opcode nibble.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
            Self::Unknown(n) => n,
        }
    }
}

/// A parsed WebSocket frame (RFC 6455 §5.2).
#[derive(Debug, Clone)]
pub struct WebSocketFrame {
    /// Whether the FIN bit is set (last fragment or unfragmented message).
    pub fin: bool,
    /// The RSV1/RSV2/RSV3 extension bits.
    pub rsv: u8,
    /// Frame opcode.
    pub opcode: WsOpcode,
    /// Whether the payload is masked (always `true` for client→server frames).
    pub masked: bool,
    /// Unmasked payload bytes.
    pub payload: Vec<u8>,
}

impl WebSocketFrame {
    /// Attempt to parse one WebSocket frame from the front of `data`.
    ///
    /// Returns `(frame, bytes_consumed)` on success, or `None` if `data`
    /// contains fewer bytes than required by the frame header/payload.
    ///
    /// This parser correctly handles the 7-bit, 16-bit, and 64-bit payload
    /// length encodings and the optional 4-byte masking key.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 2 {
            return None;
        }
        let b0 = data[0];
        let b1 = data[1];

        let fin = (b0 & 0x80) != 0;
        let rsv = (b0 >> 4) & 0x07;
        let opcode = WsOpcode::from_byte(b0);
        let masked = (b1 & 0x80) != 0;

        let (payload_len, mut offset): (u64, usize) = match b1 & 0x7F {
            126 => {
                if data.len() < 4 {
                    return None;
                }
                let len = u64::from(u16::from_be_bytes([data[2], data[3]]));
                (len, 4)
            }
            127 => {
                if data.len() < 10 {
                    return None;
                }
                let len = u64::from_be_bytes([
                    data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
                ]);
                (len, 10)
            }
            n => (u64::from(n), 2),
        };

        let mask_key: Option<[u8; 4]> = if masked {
            if data.len() < offset + 4 {
                return None;
            }
            let k = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            offset += 4;
            Some(k)
        } else {
            None
        };

        // Guard against payload_len values that would overflow usize addition.
        let payload_len_usize = usize::try_from(payload_len).ok()?;
        let payload_end = offset.checked_add(payload_len_usize)?;
        if data.len() < payload_end {
            return None;
        }

        let mut payload = data[offset..payload_end].to_vec();
        if let Some(key) = mask_key {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[i % 4];
            }
        }

        Some((
            Self {
                fin,
                rsv,
                opcode,
                masked,
                payload,
            },
            payload_end,
        ))
    }

    /// Serialise this frame to bytes ready to be sent over the wire.
    ///
    /// Client-to-server frames should have `masked = true`; a random masking
    /// key is generated.  Server-to-client frames have `masked = false`.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + 14);

        let b0 = (u8::from(self.fin) << 7) | ((self.rsv & 0x07) << 4) | self.opcode.to_byte();
        out.push(b0);

        // Choose a simple deterministic "random" mask key derived from payload
        // length so this implementation stays dependency-free and unsafe-free.
        let mask_key: [u8; 4] = if self.masked {
            let seed = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
            [
                (seed.wrapping_mul(0x9E37_79B9) >> 24) as u8,
                (seed.wrapping_mul(0x6C62_272E) >> 24) as u8,
                (seed.wrapping_mul(0x811C_9DC5) >> 24) as u8,
                (seed.wrapping_mul(0xB391_6A29) >> 24) as u8,
            ]
        } else {
            [0u8; 4]
        };

        let mask_bit: u8 = if self.masked { 0x80 } else { 0x00 };
        let len = self.payload.len();
        if len < 126 {
            out.push(mask_bit | u8::try_from(len).unwrap_or(u8::MAX));
        } else if len <= 0xFFFF {
            out.push(mask_bit | 126);
            out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
        } else {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }

        if self.masked {
            out.extend_from_slice(&mask_key);
            for (i, &b) in self.payload.iter().enumerate() {
                out.push(b ^ mask_key[i % 4]);
            }
        } else {
            out.extend_from_slice(&self.payload);
        }
        out
    }

    /// Returns `true` if this is a control frame (Close, Ping, or Pong).
    ///
    /// Control frames are identified by opcodes 0x8–0xF (RFC 6455 §5.5).
    #[must_use]
    pub const fn is_control(&self) -> bool {
        matches!(
            self.opcode,
            WsOpcode::Close | WsOpcode::Ping | WsOpcode::Pong
        )
    }

    /// Returns `true` if the FIN bit is set.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        self.fin
    }

    /// Return the payload as a UTF-8 string (lossy).
    #[must_use]
    pub fn payload_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.payload)
    }

    /// Create a text frame with the given UTF-8 string payload.
    #[must_use]
    pub fn text(payload: impl Into<String>) -> Self {
        Self {
            fin: true,
            rsv: 0,
            opcode: WsOpcode::Text,
            masked: false,
            payload: payload.into().into_bytes(),
        }
    }

    /// Create a binary frame.
    #[must_use]
    pub const fn binary(payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            rsv: 0,
            opcode: WsOpcode::Binary,
            masked: false,
            payload,
        }
    }

    /// Create a Ping frame.
    #[must_use]
    pub const fn ping(data: Vec<u8>) -> Self {
        Self {
            fin: true,
            rsv: 0,
            opcode: WsOpcode::Ping,
            masked: false,
            payload: data,
        }
    }

    /// Create a Pong frame echoing the given ping data.
    #[must_use]
    pub const fn pong(data: Vec<u8>) -> Self {
        Self {
            fin: true,
            rsv: 0,
            opcode: WsOpcode::Pong,
            masked: false,
            payload: data,
        }
    }

    /// Create a Close frame, optionally carrying a status code + reason.
    #[must_use]
    pub fn close(code: u16, reason: &str) -> Self {
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        Self {
            fin: true,
            rsv: 0,
            opcode: WsOpcode::Close,
            masked: false,
            payload,
        }
    }
}

/// Return `true` when the HTTP request carries the headers required to
/// initiate a WebSocket upgrade (RFC 6455 §4.1).
///
/// Specifically it checks:
/// - `Upgrade: websocket` (case-insensitive value)
/// - `Connection: Upgrade` (case-insensitive value, allows multi-value)
#[must_use]
pub fn detect_websocket_upgrade(req: &HttpRequest) -> bool {
    let has_upgrade = req.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("upgrade") && v.to_ascii_lowercase().contains("websocket")
    });
    let has_connection = req.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("connection") && v.to_ascii_lowercase().contains("upgrade")
    });
    has_upgrade && has_connection
}

/// Parse as many WebSocket frames as possible from the given byte slice.
///
/// Frames that cannot be parsed (e.g. because the slice is truncated) are
/// silently ignored; any trailing incomplete frame is dropped.
#[must_use]
pub fn parse_websocket_stream(data: &[u8]) -> Vec<WebSocketFrame> {
    let mut frames = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        match WebSocketFrame::parse(&data[pos..]) {
            Some((frame, consumed)) => {
                frames.push(frame);
                pos += consumed;
            }
            None => break,
        }
    }
    frames
}

/// Reassemble fragmented WebSocket messages from a sequence of frames.
///
/// Fragmentation uses a Continuation opcode chain:
/// - First fragment: data opcode (Text/Binary) with `fin = false`.
/// - Middle fragments: Continuation opcode with `fin = false`.
/// - Last fragment: Continuation opcode with `fin = true`.
///
/// Control frames (Close/Ping/Pong) are never fragmented and are interleaved
/// in the output as-is.
///
/// Returns a `Vec<WebSocketFrame>` where each element is a complete,
/// reassembled message or a control frame.
#[must_use]
pub fn reassemble_ws_messages(frames: &[WebSocketFrame]) -> Vec<WebSocketFrame> {
    let mut messages: Vec<WebSocketFrame> = Vec::new();
    let mut fragment_buf: Option<(WsOpcode, Vec<u8>)> = None;

    for frame in frames {
        if frame.is_control() {
            // Control frames are never fragmented.
            messages.push(frame.clone());
            continue;
        }
        match frame.opcode {
            WsOpcode::Continuation => {
                if let Some((_, ref mut buf)) = fragment_buf {
                    buf.extend_from_slice(&frame.payload);
                }
                if frame.fin
                    && let Some((opcode, payload)) = fragment_buf.take() {
                        messages.push(WebSocketFrame {
                            fin: true,
                            rsv: 0,
                            opcode,
                            masked: false,
                            payload,
                        });
                    }
            }
            opcode => {
                if frame.fin {
                    // Unfragmented message.
                    messages.push(frame.clone());
                } else {
                    // Start of fragmented sequence.
                    fragment_buf = Some((opcode, frame.payload.clone()));
                }
            }
        }
    }
    messages
}
