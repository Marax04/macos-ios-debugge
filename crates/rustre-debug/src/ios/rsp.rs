//! GDB Remote Serial Protocol (RSP) client, wire layer.
//!
//! This module is deliberately byte-in / byte-out and free of any
//! `cfg(target_os)`: the whole Apple debugging story (debugserver on
//! macOS/iOS speaks RSP with lldb extensions) has to be exercised from a
//! Windows development host, so the protocol is separated from the socket by
//! the [`RspTransport`] trait and every test drives an in-memory transport.
//!
//! Why the framing lives in a [`RspFramer`] instead of a single `read()`:
//! debugserver replies are routinely split across TCP segments (a `g` packet
//! for ARM64 is >1 KiB, `qXfer` responses are paginated), and it also emits
//! *asynchronous notifications* (`%Stop:…#xx`) interleaved with command
//! replies. A one-shot read cannot express either, and silently truncates.
//!
//! Layering of a packet on the wire, outermost first:
//!
//! ```text
//! $ <run-length-encoded( escaped( payload ) )> # <checksum-hex>
//! ```
//!
//! so decoding is: verify checksum over the raw body → RLE-expand → unescape.
//! The checksum is computed over the *encoded* body, which is why it must be
//! validated before any transformation.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Bytes that must never appear literally inside a packet body.
const ESCAPE_BYTE: u8 = b'}';
const ESCAPE_XOR: u8 = 0x20;

/// Errors produced by the wire layer.
///
/// Every variant is explicit: a corrupt packet is never silently downgraded to
/// an empty reply, because "the target answered nothing" and "we failed to
/// understand the target" lead to opposite debugging decisions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RspError {
    /// Checksum in the trailer did not match the body.
    #[error("RSP checksum mismatch: expected {expected:#04x}, computed {computed:#04x}")]
    BadChecksum { expected: u8, computed: u8 },
    /// Packet did not start with `$`/`%`, or the trailer was malformed.
    #[error("RSP framing error: {0}")]
    Framing(String),
    /// The buffer ended before a complete packet was available.
    #[error("RSP packet truncated")]
    Truncated,
    /// A `}` escape or `*` run-length prefix was not followed by a byte.
    #[error("RSP encoding error: {0}")]
    Encoding(String),
    /// Non-hexadecimal input where hex was required.
    #[error("invalid hex in RSP payload: {0}")]
    Hex(String),
    /// Transport failure (socket closed, timeout, …).
    #[error("RSP transport error: {0}")]
    Transport(String),
    /// The remote replied `Exx` to a command.
    #[error("remote returned error code {0:#04x}")]
    Remote(u8),
    /// The remote replied with an empty packet, i.e. "command unsupported".
    #[error("remote does not support command {0}")]
    Unsupported(String),
    /// `m` returned fewer bytes than were asked for.
    ///
    /// The protocol permits this — a stub that can only read part of a region
    /// answers with what it got — but every caller in this crate assumes the
    /// full length, so the shortfall has to be visible rather than silently
    /// handed back as if it were the whole read. The concrete damage: the
    /// software-breakpoint fallback saves the original word before patching
    /// `BRK #0`, and a short save means the restore writes back fewer bytes
    /// than it overwrote, leaving part of the `BRK` in the target's code.
    /// A data command was answered with a `W`/`X` stop reply.
    ///
    /// The stub is allowed to answer whatever command is in flight with an
    /// exit notification when the inferior dies mid-request. Those bytes are
    /// not hex payload, so decoding them yields a framing/encoding complaint
    /// and the caller retries or reports corruption — while the honest fact,
    /// already representable as [`StopReply::is_exit`], is that the process
    /// is gone and no retry can succeed.
    #[error("process is gone (reply {reply} to command {cmd})")]
    ProcessGone { cmd: String, reply: String },
    #[error("short read at {addr:#x}: asked for {requested} bytes, got {returned}")]
    ShortRead {
        addr: u64,
        requested: usize,
        returned: usize,
    },
}

impl RspError {
    /// `true` when the failure means "we could not trust what came back",
    /// as opposed to "the target said no".
    ///
    /// Retransmission is the protocol's own answer to a garbled packet, and a
    /// garbled packet can surface as a bad checksum, a non-hex checksum digit,
    /// or a broken escape/run-length sequence — all of them the same event on
    /// the wire, so all of them must retry. Treating only `BadChecksum` as
    /// retryable made a single flipped bit fatal.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::BadChecksum { .. }
                | Self::Encoding(_)
                | Self::Hex(_)
                | Self::Framing(_)
                | Self::Truncated
        )
    }
}

impl From<io::Error> for RspError {
    fn from(e: io::Error) -> Self {
        Self::Transport(e.to_string())
    }
}

/// Result alias for this module.
pub type RspResult<T> = Result<T, RspError>;

// ---------------------------------------------------------------------------
// checksum / hex
// ---------------------------------------------------------------------------

/// Modulo-256 sum of the packet body, exactly as the GDB protocol defines it.
#[must_use]
pub fn checksum(body: &[u8]) -> u8 {
    body.iter().fold(0u8, |acc, b| acc.wrapping_add(*b))
}

/// Lowercase hex digit for a nibble. Panics never: input is masked by callers.
const fn nibble_to_hex(n: u8) -> u8 {
    match n & 0x0f {
        d @ 0..=9 => b'0' + d,
        d => b'a' + (d - 10),
    }
}

const fn hex_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Encode bytes as lowercase hex, the representation used by `m`/`M`/`g`/`G`.
#[must_use]
pub fn hex_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 2);
    for b in data {
        out.push(nibble_to_hex(b >> 4));
        out.push(nibble_to_hex(*b));
    }
    out
}

/// Decode a hex string into bytes.
///
/// # Errors
/// Returns [`RspError::Hex`] on odd length or non-hex digits.
pub fn hex_decode(data: &[u8]) -> RspResult<Vec<u8>> {
    if data.len() % 2 != 0 {
        return Err(RspError::Hex(format!("odd length {}", data.len())));
    }
    let mut out = Vec::with_capacity(data.len() / 2);
    for pair in data.chunks_exact(2) {
        let (hi, lo) = (hex_to_nibble(pair[0]), hex_to_nibble(pair[1]));
        match (hi, lo) {
            (Some(h), Some(l)) => out.push((h << 4) | l),
            _ => {
                return Err(RspError::Hex(String::from_utf8_lossy(pair).into_owned()));
            }
        }
    }
    Ok(out)
}

/// Is this packet payload an `O<hex>` console-output packet?
///
/// `OK` is deliberately excluded: `K` is not a hex digit, and no hex payload
/// can begin with `O` either, so the two can never be confused.
#[must_use]
pub fn is_console_output(data: &[u8]) -> bool {
    data.first() == Some(&b'O')
        && data.len() >= 3
        && data.len() % 2 == 1
        && data[1..].iter().all(|b| hex_to_nibble(*b).is_some())
}

/// Parse an unsigned hex integer (as used for addresses/lengths).
///
/// # Errors
/// Returns [`RspError::Hex`] if empty, non-hex, or wider than 64 bits.
pub fn parse_hex_u64(s: &[u8]) -> RspResult<u64> {
    if s.is_empty() {
        return Err(RspError::Hex("empty".to_string()));
    }
    let mut v: u64 = 0;
    for c in s {
        let n = hex_to_nibble(*c).ok_or_else(|| RspError::Hex((*c as char).to_string()))?;
        v = v
            .checked_mul(16)
            .and_then(|x| x.checked_add(u64::from(n)))
            .ok_or_else(|| RspError::Hex("overflow".to_string()))?;
    }
    Ok(v)
}

/// Format an unsigned integer as bare lowercase hex, no `0x`, no padding.
#[must_use]
pub fn fmt_hex_u64(v: u64) -> String {
    format!("{v:x}")
}

// ---------------------------------------------------------------------------
// escaping and run-length encoding
// ---------------------------------------------------------------------------

/// Escape the four reserved bytes as `}` followed by `byte ^ 0x20`.
#[must_use]
pub fn escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for b in data {
        if matches!(*b, b'#' | b'$' | b'}' | b'*') {
            out.push(ESCAPE_BYTE);
            out.push(*b ^ ESCAPE_XOR);
        } else {
            out.push(*b);
        }
    }
    out
}

/// Reverse [`escape`].
///
/// # Errors
/// Returns [`RspError::Encoding`] on a trailing `}` with no following byte.
pub fn unescape(data: &[u8]) -> RspResult<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    let mut it = data.iter().copied();
    while let Some(b) = it.next() {
        if b == ESCAPE_BYTE {
            let n = it
                .next()
                .ok_or_else(|| RspError::Encoding("dangling '}' escape".to_string()))?;
            out.push(n ^ ESCAPE_XOR);
        } else {
            out.push(b);
        }
    }
    Ok(out)
}

/// Expand GDB run-length encoding: `X*<n>` repeats `X` an extra `n - 29` times.
///
/// The repeat count is a printable character biased by 29; counts of 6 and 7
/// are impossible on the wire because they would encode `#` and `$`.
///
/// # Errors
/// Returns [`RspError::Encoding`] for a leading `*`, a dangling `*`, or a
/// count character outside the printable range.
pub fn rle_decode(data: &[u8]) -> RspResult<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        if b == b'*' {
            let last = *out
                .last()
                .ok_or_else(|| RspError::Encoding("run-length prefix with no data".to_string()))?;
            let count_ch = *data
                .get(i + 1)
                .ok_or_else(|| RspError::Encoding("dangling run-length prefix".to_string()))?;
            if !(29..=126).contains(&count_ch) {
                return Err(RspError::Encoding(format!(
                    "run-length count {count_ch:#04x} out of range"
                )));
            }
            let repeat = usize::from(count_ch - 29);
            out.extend(std::iter::repeat_n(last, repeat));
            i += 2;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Ok(out)
}

/// Compress runs of an identical byte using GDB run-length encoding.
///
/// Only runs long enough to actually shrink the stream are encoded, and the
/// count is clamped so it never lands on `#` or `$` — emitting either would
/// desynchronise the receiver's framer.
#[must_use]
pub fn rle_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        let mut run = 1usize;
        while i + run < data.len() && data[i + run] == b && run < 97 {
            run += 1;
        }
        out.push(b);
        // `run - 1` further copies remain; encoding is only a win at >= 4.
        let mut extra = run - 1;
        if extra >= 3 {
            // 6 and 7 map to '#'/'$'; back off to 5 so the count stays legal.
            if extra == 6 || extra == 7 {
                extra = 5;
            }
            let count_ch = u8::try_from(extra + 29).unwrap_or(126);
            out.push(b'*');
            out.push(count_ch);
            i += 1 + extra;
        } else {
            i += 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// packets
// ---------------------------------------------------------------------------

/// A decoded packet payload (escaping and RLE already removed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RspPacket {
    pub data: Vec<u8>,
}

impl RspPacket {
    /// Build a packet from a logical payload.
    #[must_use]
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self { data: data.into() }
    }

    /// Payload as a lossy string, for logs and matching on textual replies.
    #[must_use]
    pub fn as_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.data)
    }

    /// `true` for the `OK` reply.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.data == b"OK"
    }

    /// `true` for the empty reply, which means "command not supported".
    #[must_use]
    pub fn is_empty_reply(&self) -> bool {
        self.data.is_empty()
    }

    /// Error code of an `Exx` reply, if this is one.
    #[must_use]
    pub fn error_code(&self) -> Option<u8> {
        if self.data.len() == 3 && self.data[0] == b'E' {
            hex_decode(&self.data[1..]).ok().and_then(|v| v.first().copied())
        } else {
            None
        }
    }

    /// Turn `Exx` / empty replies into typed errors; pass anything else through.
    ///
    /// # Errors
    /// [`RspError::Remote`] for `Exx`, [`RspError::Unsupported`] for empty.
    pub fn ok_or_err(self, cmd: &str) -> RspResult<Self> {
        if let Some(code) = self.error_code() {
            return Err(RspError::Remote(code));
        }
        if self.data.is_empty() {
            return Err(RspError::Unsupported(cmd.to_string()));
        }
        Ok(self)
    }

    /// Turn a `W`/`X` exit notification into [`RspError::ProcessGone`].
    ///
    /// Applied to commands whose reply is payload rather than a stop reply
    /// (`m`/`M`/`g`/`G`): a stub may answer the in-flight command with an exit
    /// notification when the inferior dies, and `W`/`X` are not hex, so the
    /// alternative is a misleading decoding error. Only leading `W`/`X` is
    /// considered, so a hex payload can never be mistaken for a stop reply.
    ///
    /// # Errors
    /// [`RspError::ProcessGone`] when the reply parses as an exit stop reply.
    pub fn err_if_exit(self, cmd: &str) -> RspResult<Self> {
        if matches!(self.data.first(), Some(b'W' | b'X')) {
            if let Ok(stop) = StopReply::parse(&self.data) {
                if stop.is_exit() {
                    return Err(RspError::ProcessGone {
                        cmd: cmd.to_string(),
                        reply: self.as_str().into_owned(),
                    });
                }
            }
        }
        Ok(self)
    }

    /// Encode as a full on-the-wire packet, `$…#xx`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.encode_inner(b'$', false)
    }

    /// Encode with run-length compression applied to the escaped body.
    #[must_use]
    pub fn encode_compressed(&self) -> Vec<u8> {
        self.encode_inner(b'$', true)
    }

    fn encode_inner(&self, lead: u8, compress: bool) -> Vec<u8> {
        let escaped = escape(&self.data);
        let body = if compress { rle_encode(&escaped) } else { escaped };
        let sum = checksum(&body);
        let mut out = Vec::with_capacity(body.len() + 4);
        out.push(lead);
        out.extend_from_slice(&body);
        out.push(b'#');
        out.push(nibble_to_hex(sum >> 4));
        out.push(nibble_to_hex(sum));
        out
    }

    /// Decode one complete packet, verifying the checksum.
    ///
    /// Accepts both command packets (`$…`) and asynchronous notifications
    /// (`%…`). Leading `+`/`-` acknowledgements are skipped.
    ///
    /// # Errors
    /// See [`RspError`]; a bad checksum is always reported, never ignored.
    pub fn decode(raw: &[u8]) -> RspResult<Self> {
        let start = raw
            .iter()
            .position(|b| *b == b'$' || *b == b'%')
            .ok_or_else(|| RspError::Framing("no packet start marker".to_string()))?;
        let rest = &raw[start + 1..];
        let hash = rest
            .iter()
            .position(|b| *b == b'#')
            .ok_or(RspError::Truncated)?;
        let body = &rest[..hash];
        let sum_hex = rest.get(hash + 1..hash + 3).ok_or(RspError::Truncated)?;
        let expected = hex_decode(sum_hex)?[0];
        let computed = checksum(body);
        if expected != computed {
            return Err(RspError::BadChecksum { expected, computed });
        }
        let expanded = rle_decode(body)?;
        Ok(Self {
            data: unescape(&expanded)?,
        })
    }
}

// ---------------------------------------------------------------------------
// incremental framer
// ---------------------------------------------------------------------------

/// One item pulled out of the byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RspIncoming {
    /// `+` — the peer accepted our last packet.
    Ack,
    /// `-` — the peer wants a retransmission.
    Nack,
    /// A normal `$…#xx` reply.
    Packet(RspPacket),
    /// An asynchronous `%…#xx` notification (debugserver stop events).
    Notification(RspPacket),
}

/// Largest partial packet the framer will hold before giving up.
///
/// The peer is not trusted: a stub that streams bytes and never sends the
/// terminating `#` would otherwise grow this buffer without bound, because
/// [`RspClient::read_reply`] keeps reading until a complete item appears.
/// 8 MiB is far above any real reply (`m` reads are chunked well below the
/// stub's advertised `PacketSize`) and far below anything that could exhaust
/// the debugger.
pub const RSP_MAX_BUFFERED: usize = 8 * 1024 * 1024;

/// Incremental, restartable packet reassembler.
///
/// Feed it whatever arrived from the socket with [`RspFramer::push`] and pull
/// complete items with [`RspFramer::next_item`]. Partial packets stay buffered
/// across calls, which is the entire reason this type exists.
#[derive(Debug, Default)]
pub struct RspFramer {
    buf: VecDeque<u8>,
}

impl RspFramer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append freshly read bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes.iter().copied());
    }

    /// Bytes currently buffered but not yet forming a complete item.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Drop everything buffered (used after a reconnect).
    pub fn reset(&mut self) {
        self.buf.clear();
    }

    /// Pull the next complete item.
    ///
    /// Returns `None` when more bytes are needed. A malformed packet yields
    /// `Some(Err(..))` **and is consumed**, so a caller looping on this can
    /// never spin forever on the same garbage.
    pub fn next_item(&mut self) -> Option<RspResult<RspIncoming>> {
        loop {
            let first = *self.buf.front()?;
            match first {
                b'+' => {
                    self.buf.pop_front();
                    return Some(Ok(RspIncoming::Ack));
                }
                b'-' => {
                    self.buf.pop_front();
                    return Some(Ok(RspIncoming::Nack));
                }
                b'$' | b'%' => break,
                // Anything else is noise between packets (e.g. a stray 0x03
                // interrupt echo); drop one byte and re-examine.
                _ => {
                    self.buf.pop_front();
                }
            }
        }

        let lead = *self.buf.front()?;
        // Find '#' and make sure two checksum digits follow it.
        let Some(hash) = self.buf.iter().position(|b| *b == b'#') else {
            // No terminator yet. Wait for more bytes, but only up to a cap:
            // the peer is untrusted and could otherwise stream forever.
            if self.buf.len() > RSP_MAX_BUFFERED {
                let n = self.buf.len();
                self.buf.clear();
                return Some(Err(RspError::Framing(format!(
                    "no packet terminator within {n} buffered bytes (cap {RSP_MAX_BUFFERED})"
                ))));
            }
            return None;
        };
        if self.buf.len() < hash + 3 {
            return None;
        }
        let raw: Vec<u8> = self.buf.iter().copied().take(hash + 3).collect();
        self.buf.drain(..hash + 3);
        let decoded = RspPacket::decode(&raw);
        Some(decoded.map(|p| {
            if lead == b'%' {
                RspIncoming::Notification(p)
            } else {
                RspIncoming::Packet(p)
            }
        }))
    }
}

// ---------------------------------------------------------------------------
// command builders
// ---------------------------------------------------------------------------

/// Typed constructors for the packets this client sends.
///
/// These return the *logical* payload; escaping, checksum and framing are
/// added by [`RspPacket::encode`].
pub mod commands {
    use super::{fmt_hex_u64, hex_encode};

    /// `?` — why did the target stop?
    #[must_use]
    pub fn halt_reason() -> Vec<u8> {
        b"?".to_vec()
    }

    /// `g` — read all registers.
    #[must_use]
    pub fn read_registers() -> Vec<u8> {
        b"g".to_vec()
    }

    /// `G<hex>` — write all registers.
    #[must_use]
    pub fn write_registers(raw: &[u8]) -> Vec<u8> {
        let mut v = vec![b'G'];
        v.extend_from_slice(&hex_encode(raw));
        v
    }

    /// `p<n>` — read one register.
    #[must_use]
    pub fn read_register(n: u32) -> Vec<u8> {
        format!("p{n:x}").into_bytes()
    }

    /// `P<n>=<hex>` — write one register.
    #[must_use]
    pub fn write_register(n: u32, raw: &[u8]) -> Vec<u8> {
        let mut v = format!("P{n:x}=").into_bytes();
        v.extend_from_slice(&hex_encode(raw));
        v
    }

    /// `m<addr>,<len>` — read memory.
    #[must_use]
    pub fn read_memory(addr: u64, len: usize) -> Vec<u8> {
        format!("m{},{:x}", fmt_hex_u64(addr), len).into_bytes()
    }

    /// `M<addr>,<len>:<hex>` — write memory (hex form, always safe).
    #[must_use]
    pub fn write_memory(addr: u64, data: &[u8]) -> Vec<u8> {
        let mut v = format!("M{},{:x}:", fmt_hex_u64(addr), data.len()).into_bytes();
        v.extend_from_slice(&hex_encode(data));
        v
    }

    /// `X<addr>,<len>:<binary>` — write memory in binary form.
    ///
    /// The payload is left raw here; [`super::escape`] handles the reserved
    /// bytes when the packet is encoded.
    #[must_use]
    pub fn write_memory_binary(addr: u64, data: &[u8]) -> Vec<u8> {
        let mut v = format!("X{},{:x}:", fmt_hex_u64(addr), data.len()).into_bytes();
        v.extend_from_slice(data);
        v
    }

    /// `c` / `c<addr>` — continue.
    #[must_use]
    pub fn cont(addr: Option<u64>) -> Vec<u8> {
        addr.map_or_else(|| b"c".to_vec(), |a| format!("c{}", fmt_hex_u64(a)).into_bytes())
    }

    /// `s` / `s<addr>` — single step.
    #[must_use]
    pub fn step(addr: Option<u64>) -> Vec<u8> {
        addr.map_or_else(|| b"s".to_vec(), |a| format!("s{}", fmt_hex_u64(a)).into_bytes())
    }

    /// `vCont?` — which resume actions does the stub support?
    #[must_use]
    pub fn vcont_query() -> Vec<u8> {
        b"vCont?".to_vec()
    }

    /// `vCont;<action>[:<tid>]…`
    ///
    /// Actions are given as `("c" | "s" | "C05" | "S05", Some(tid))`. A thread
    /// id of `None` applies the action to all threads.
    #[must_use]
    pub fn vcont(actions: &[(&str, Option<u64>)]) -> Vec<u8> {
        let mut s = String::from("vCont");
        for (action, tid) in actions {
            s.push(';');
            s.push_str(action);
            if let Some(t) = tid {
                s.push(':');
                s.push_str(&fmt_hex_u64(*t));
            }
        }
        s.into_bytes()
    }

    /// Breakpoint kinds understood by `Z`/`z`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ZKind {
        /// `Z0` — software breakpoint (stub patches the instruction).
        Software,
        /// `Z1` — hardware breakpoint (debug register / `DBGBVR`).
        Hardware,
        /// `Z2` — write watchpoint.
        WriteWatch,
        /// `Z3` — read watchpoint.
        ReadWatch,
        /// `Z4` — access watchpoint.
        AccessWatch,
    }

    impl ZKind {
        /// Numeric type code used in the packet.
        #[must_use]
        pub const fn code(self) -> u8 {
            match self {
                Self::Software => 0,
                Self::Hardware => 1,
                Self::WriteWatch => 2,
                Self::ReadWatch => 3,
                Self::AccessWatch => 4,
            }
        }
    }

    /// `Z<t>,<addr>,<kind>` — insert breakpoint/watchpoint.
    ///
    /// `kind` is the instruction length in bytes on ARM64/x86 (4 for A64) or
    /// the watched region size for watchpoints.
    #[must_use]
    pub fn insert_breakpoint(kind: ZKind, addr: u64, size: u32) -> Vec<u8> {
        format!("Z{},{},{:x}", kind.code(), fmt_hex_u64(addr), size).into_bytes()
    }

    /// `z<t>,<addr>,<kind>` — remove breakpoint/watchpoint.
    #[must_use]
    pub fn remove_breakpoint(kind: ZKind, addr: u64, size: u32) -> Vec<u8> {
        format!("z{},{},{:x}", kind.code(), fmt_hex_u64(addr), size).into_bytes()
    }

    /// `qSupported:<features>` — feature negotiation.
    #[must_use]
    pub fn q_supported(features: &[&str]) -> Vec<u8> {
        if features.is_empty() {
            b"qSupported".to_vec()
        } else {
            format!("qSupported:{}", features.join(";")).into_bytes()
        }
    }

    /// `QStartNoAckMode` — stop exchanging `+`/`-` after this is acknowledged.
    #[must_use]
    pub fn start_no_ack_mode() -> Vec<u8> {
        b"QStartNoAckMode".to_vec()
    }

    /// Which class of operation a `H` packet selects a thread for.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum HOp {
        /// `Hg` — subsequent register/memory operations.
        General,
        /// `Hc` — subsequent step/continue (legacy; superseded by `vCont`).
        Continue,
    }

    /// `H<op><tid>` — select the thread for following operations.
    ///
    /// `tid` of `None` encodes `-1`, i.e. "all threads"; `Some(0)` means
    /// "any thread", which is what most stubs want at handshake time.
    #[must_use]
    pub fn set_thread(op: HOp, tid: Option<u64>) -> Vec<u8> {
        let c = match op {
            HOp::General => 'g',
            HOp::Continue => 'c',
        };
        match tid {
            Some(t) => format!("H{c}{}", fmt_hex_u64(t)).into_bytes(),
            None => format!("H{c}-1").into_bytes(),
        }
    }

    /// `qfThreadInfo` — start enumerating threads.
    #[must_use]
    pub fn q_first_thread_info() -> Vec<u8> {
        b"qfThreadInfo".to_vec()
    }

    /// `qsThreadInfo` — continue enumerating threads.
    #[must_use]
    pub fn q_next_thread_info() -> Vec<u8> {
        b"qsThreadInfo".to_vec()
    }

    /// `D` — detach, leaving the process running.
    #[must_use]
    pub fn detach() -> Vec<u8> {
        b"D".to_vec()
    }

    /// `k` — kill the target.
    #[must_use]
    pub fn kill() -> Vec<u8> {
        b"k".to_vec()
    }
}

// ---------------------------------------------------------------------------
// stop replies
// ---------------------------------------------------------------------------

/// Parsed `S`/`T`/`W`/`X` stop reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReply {
    /// `Snn` — stopped with signal `nn`, no extra detail.
    Signal { signal: u8 },
    /// `Tnn key:value;…` — stopped with signal and register/thread detail.
    SignalWithInfo {
        signal: u8,
        thread: Option<u64>,
        pairs: Vec<(String, String)>,
    },
    /// `Wnn` — process exited with status `nn`.
    Exited { status: u8 },
    /// `Xnn` — process terminated by signal `nn`.
    Terminated { signal: u8 },
}

impl StopReply {
    /// Parse a stop reply payload.
    ///
    /// # Errors
    /// [`RspError::Framing`] if the leading character is not one of `S T W X`
    /// or the signal byte is not two hex digits.
    pub fn parse(data: &[u8]) -> RspResult<Self> {
        let kind = *data
            .first()
            .ok_or_else(|| RspError::Framing("empty stop reply".to_string()))?;
        let sig_hex = data
            .get(1..3)
            .ok_or_else(|| RspError::Framing("stop reply too short".to_string()))?;
        let sig = hex_decode(sig_hex)?[0];
        match kind {
            b'S' => Ok(Self::Signal { signal: sig }),
            b'W' => Ok(Self::Exited { status: sig }),
            b'X' => Ok(Self::Terminated { signal: sig }),
            b'T' => {
                let mut pairs = Vec::new();
                let mut thread = None;
                for field in data[3..].split(|b| *b == b';') {
                    if field.is_empty() {
                        continue;
                    }
                    let Some(colon) = field.iter().position(|b| *b == b':') else {
                        continue;
                    };
                    let key = String::from_utf8_lossy(&field[..colon]).into_owned();
                    let val = String::from_utf8_lossy(&field[colon + 1..]).into_owned();
                    if key == "thread" {
                        // debugserver may use `p<pid>.<tid>`; the tid is what matters.
                        let tid_part = val.rsplit('.').next().unwrap_or(&val);
                        thread = parse_hex_u64(tid_part.trim_start_matches('p').as_bytes()).ok();
                    }
                    pairs.push((key, val));
                }
                Ok(Self::SignalWithInfo {
                    signal: sig,
                    thread,
                    pairs,
                })
            }
            other => Err(RspError::Framing(format!(
                "unknown stop reply kind {:?}",
                other as char
            ))),
        }
    }

    /// `true` if the process is gone.
    #[must_use]
    pub const fn is_exit(&self) -> bool {
        matches!(self, Self::Exited { .. } | Self::Terminated { .. })
    }
}

// ---------------------------------------------------------------------------
// transport
// ---------------------------------------------------------------------------

/// Byte pipe to a remote stub.
///
/// Synchronous by design: RSP framing is stateful, and interleaving two
/// requests on one connection corrupts it. Async lives one layer up, in the
/// adapter that implements `crate::Debugger`.
pub trait RspTransport: Send {
    /// Write all bytes.
    ///
    /// # Errors
    /// Propagates the underlying I/O failure.
    fn send(&mut self, data: &[u8]) -> io::Result<()>;

    /// Read at most `buf.len()` bytes; `Ok(0)` means the peer closed.
    ///
    /// # Errors
    /// Propagates the underlying I/O failure.
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Human-readable description, for diagnostics.
    fn description(&self) -> String {
        "rsp-transport".to_string()
    }

    /// A clonable send-only handle usable **while this transport is borrowed
    /// mutably by a blocked reader**.
    ///
    /// This is the whole reason [`RspInterrupter`] exists: `send`/`recv` take
    /// `&mut self`, so the thread parked in [`RspClient::read_reply`] owns the
    /// transport for the entire duration of a `vCont` — and an asynchronous
    /// `\x03` has to reach the stub during exactly that window. A transport
    /// that can hand out a second, independently owned write end (a
    /// `TcpStream::try_clone`, a duplicated pipe handle) returns it here.
    ///
    /// `None` — the default — means "this transport cannot be written to
    /// out of band", and callers must surface that as an explicit
    /// unsupported-operation error rather than pretending the interrupt was
    /// delivered.
    fn interrupter(&self) -> Option<Arc<dyn RspInterrupter>> {
        None
    }
}

/// The byte the GDB protocol reserves for "stop the target now".
pub const RSP_INTERRUPT_BYTE: u8 = 0x03;

/// A send-only, shareable half of a transport, for out-of-band writes.
///
/// Deliberately tiny: an interrupt is one unframed byte with no reply of its
/// own (the stub answers it with a stop reply on the *main* stream, which the
/// blocked reader consumes), so nothing here needs to read.
pub trait RspInterrupter: Send + Sync {
    /// Write raw bytes to the peer without disturbing the reader.
    ///
    /// # Errors
    /// Propagates the underlying I/O failure.
    fn send_out_of_band(&self, data: &[u8]) -> io::Result<()>;

    /// Description used in diagnostics.
    fn description(&self) -> String {
        "rsp-interrupter".to_string()
    }

    /// Send the single [`RSP_INTERRUPT_BYTE`].
    ///
    /// # Errors
    /// Propagates the underlying I/O failure.
    fn interrupt(&self) -> io::Result<()> {
        self.send_out_of_band(&[RSP_INTERRUPT_BYTE])
    }
}

/// Out-of-band writer over a duplicated [`TcpStream`].
///
/// The `Mutex` serialises concurrent `pause()` callers against each other; it
/// is *not* shared with the reader, which is the point — the reader holds the
/// original socket and never waits on this lock.
#[derive(Debug)]
pub struct TcpInterrupter {
    stream: Mutex<TcpStream>,
    peer: String,
}

impl TcpInterrupter {
    /// Duplicate `stream`'s handle for out-of-band writes.
    ///
    /// # Errors
    /// Propagates a `try_clone` failure; on a host that cannot duplicate the
    /// descriptor there is no out-of-band path and the caller must say so.
    pub fn from_stream(stream: &TcpStream, peer: impl Into<String>) -> io::Result<Self> {
        Ok(Self {
            stream: Mutex::new(stream.try_clone()?),
            peer: peer.into(),
        })
    }
}

impl RspInterrupter for TcpInterrupter {
    fn send_out_of_band(&self, data: &[u8]) -> io::Result<()> {
        let mut guard = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("interrupt socket mutex poisoned"))?;
        guard.write_all(data)?;
        guard.flush()
    }

    fn description(&self) -> String {
        format!("tcp-interrupt:{}", self.peer)
    }
}

/// Out-of-band writer for [`MockTransport`]: records bytes in a shared buffer.
///
/// Records rather than delivers, on purpose. `MockTransport` replies from a
/// script, so there is no peer to interrupt; what a test needs to know is
/// whether the byte was written on the *second* handle at all, and that is
/// exactly what this makes observable.
#[derive(Debug, Default)]
pub struct MockInterrupter {
    oob: Arc<Mutex<Vec<u8>>>,
    sends: Arc<AtomicUsize>,
}

impl RspInterrupter for MockInterrupter {
    fn send_out_of_band(&self, data: &[u8]) -> io::Result<()> {
        self.oob
            .lock()
            .map_err(|_| io::Error::other("mock oob mutex poisoned"))?
            .extend_from_slice(data);
        self.sends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn description(&self) -> String {
        "mock-interrupt".to_string()
    }
}

/// TCP transport, the shape debugserver is normally reached through.
#[derive(Debug)]
pub struct TcpTransport {
    stream: TcpStream,
    peer: String,
    /// Duplicated write end, so `\x03` can be injected while a reader is
    /// parked on `stream`. Built at connect time because `try_clone` can fail
    /// and a failure there must not be discovered mid-interrupt.
    interrupter: Option<Arc<TcpInterrupter>>,
}

impl TcpTransport {
    /// Connect to `addr`, applying a read/write timeout.
    ///
    /// # Errors
    /// Propagates connect/setsockopt failures.
    pub fn connect<A: ToSocketAddrs>(addr: A, timeout: Option<Duration>) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        let peer = stream
            .peer_addr()
            .map_or_else(|_| "<unknown>".to_string(), |a| a.to_string());
        // A duplicate that cannot be made leaves `interrupter()` at `None`,
        // which turns `pause()` into an explicit Unsupported rather than a
        // silent no-op.
        let interrupter = TcpInterrupter::from_stream(&stream, peer.clone()).ok().map(Arc::new);
        Ok(Self { stream, peer, interrupter })
    }
}

impl RspTransport for TcpTransport {
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

/// Deterministic fault injection for the in-memory transport.
#[derive(Debug, Clone, Copy, Default)]
pub struct MockFaults {
    /// Deliver at most this many bytes per `recv` (0 = unlimited). Simulates
    /// TCP segmentation, which is what breaks single-`read()` clients.
    pub chunk_size: usize,
    /// Corrupt the checksum digits of the Nth queued response (0-based).
    pub corrupt_checksum_at: Option<usize>,
    /// Close the connection after N responses have been delivered.
    pub close_after: Option<usize>,
}

/// In-memory transport: scripted responses in, sent bytes recorded.
///
/// This is what makes the Apple protocol testable on a Windows host — no
/// socket, no debugserver, no `cfg(target_os)`.
#[derive(Debug, Default)]
pub struct MockTransport {
    outgoing: Vec<u8>,
    incoming: VecDeque<u8>,
    responses_delivered: usize,
    queued: usize,
    faults: MockFaults,
    closed: bool,
    /// Bytes written through [`Self::interrupter`], kept apart from `outgoing`
    /// so a test can tell the two paths apart.
    oob: Arc<Mutex<Vec<u8>>>,
    oob_sends: Arc<AtomicUsize>,
}

impl MockTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes written out of band so far.
    #[must_use]
    pub fn out_of_band(&self) -> Vec<u8> {
        self.oob.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// How many out-of-band writes were performed.
    #[must_use]
    pub fn out_of_band_sends(&self) -> usize {
        self.oob_sends.load(Ordering::SeqCst)
    }

    /// Configure fault injection.
    #[must_use]
    pub const fn with_faults(mut self, faults: MockFaults) -> Self {
        self.faults = faults;
        self
    }

    /// Queue raw bytes to be handed back by `recv`.
    pub fn push_raw(&mut self, bytes: &[u8]) {
        self.incoming.extend(bytes.iter().copied());
    }

    /// Queue a properly framed reply (plus a leading `+` ack).
    pub fn push_reply(&mut self, payload: &[u8]) {
        let mut encoded = RspPacket::new(payload.to_vec()).encode();
        if self.faults.corrupt_checksum_at == Some(self.queued) {
            let n = encoded.len();
            // Flip to a *different but still valid* hex digit as well as an
            // outright invalid one across runs; here we keep it hex so the
            // failure is specifically a checksum mismatch.
            encoded[n - 1] = if encoded[n - 1] == b'0' { b'1' } else { b'0' };
        }
        self.queued += 1;
        self.incoming.push_back(b'+');
        self.incoming.extend(encoded);
    }

    /// Queue an asynchronous notification.
    pub fn push_notification(&mut self, payload: &[u8]) {
        let p = RspPacket::new(payload.to_vec());
        let mut wire = p.encode();
        wire[0] = b'%';
        // The checksum covers only the body, so re-leading with '%' is safe.
        self.incoming.extend(wire);
    }

    /// Everything the client has written so far.
    #[must_use]
    pub fn sent(&self) -> &[u8] {
        &self.outgoing
    }

    /// Sent bytes as a string, for assertions.
    #[must_use]
    pub fn sent_str(&self) -> String {
        String::from_utf8_lossy(&self.outgoing).into_owned()
    }

    /// Forget recorded traffic (keeps queued responses).
    pub fn clear_sent(&mut self) {
        self.outgoing.clear();
    }
}

impl RspTransport for MockTransport {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mock transport closed",
            ));
        }
        self.outgoing.extend_from_slice(data);
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed || buf.is_empty() {
            return Ok(0);
        }
        if let Some(limit) = self.faults.close_after
            && self.responses_delivered >= limit
        {
            self.closed = true;
            return Ok(0);
        }
        let mut cap = buf.len();
        if self.faults.chunk_size > 0 {
            cap = cap.min(self.faults.chunk_size);
        }
        let n = cap.min(self.incoming.len());
        if n == 0 {
            return Ok(0);
        }
        for (i, slot) in buf.iter_mut().enumerate().take(n) {
            *slot = self.incoming.pop_front().unwrap_or(0);
            let _ = i;
        }
        // Count a delivered response each time a trailing checksum leaves the
        // queue; approximate but enough for `close_after` scenarios.
        self.responses_delivered += 1;
        Ok(n)
    }

    fn description(&self) -> String {
        "mock".to_string()
    }

    fn interrupter(&self) -> Option<Arc<dyn RspInterrupter>> {
        Some(Arc::new(MockInterrupter {
            oob: Arc::clone(&self.oob),
            sends: Arc::clone(&self.oob_sends),
        }))
    }
}

// ---------------------------------------------------------------------------
// client
// ---------------------------------------------------------------------------

/// Request/response client over any [`RspTransport`].
#[derive(Debug)]
pub struct RspClient<T: RspTransport> {
    transport: T,
    framer: RspFramer,
    /// While `true` we send `+` after each received packet and expect one back.
    ack_mode: bool,
    /// Notifications received while waiting for a command reply.
    notifications: VecDeque<RspPacket>,
    /// `O<hex>` console output emitted by the inferior while we waited for a
    /// command reply. Kept apart from replies: it is target stdout, not an
    /// answer to anything we asked.
    console_output: VecDeque<Vec<u8>>,
    max_retries: u32,
    /// The stub's advertised `PacketSize` from `qSupported`, in payload bytes.
    ///
    /// `None` until [`RspClient::handshake`] parses it. It is the size of the
    /// stub's RECEIVE buffer: a longer packet is dropped or truncated by real
    /// debugserver, so writes must be split to fit rather than sent whole.
    packet_size: Option<usize>,
}

/// Largest `M` payload we will emit when the stub advertised no `PacketSize`.
///
/// The gdb protocol's documented floor before any negotiation.
const RSP_DEFAULT_PACKET_SIZE: usize = 400;

/// Worst-case length of the `M<addr>,<len>:` header, with both fields at the
/// full 16 hex digits a 64-bit value can need.
const M_HEADER_MAX: usize = 1 + 16 + 1 + 16 + 1;

/// Extract `PacketSize=<hex>` from a `qSupported` reply.
///
/// The value is hex per the protocol. Returns `None` when absent or malformed,
/// which leaves the caller on the conservative default rather than on a size
/// invented from a garbled reply.
#[must_use]
pub fn parse_packet_size(features: &str) -> Option<usize> {
    features.split(';').find_map(|f| {
        let v = f.trim().strip_prefix("PacketSize=")?;
        usize::from_str_radix(v, 16).ok().filter(|n| *n > 0)
    })
}

impl<T: RspTransport> RspClient<T> {
    /// Wrap a transport. Ack mode starts enabled, as the protocol requires.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            framer: RspFramer::new(),
            ack_mode: true,
            notifications: VecDeque::new(),
            console_output: VecDeque::new(),
            max_retries: 3,
            packet_size: None,
        }
    }

    /// The stub's advertised `PacketSize`, once the handshake has run.
    #[must_use]
    /// Override the negotiated `PacketSize`.
    ///
    /// For tests that need a stub small enough to force chunking without
    /// standing up a whole `qSupported` exchange.
    #[cfg(test)]
    pub const fn set_packet_size_for_test(&mut self, n: usize) {
        self.packet_size = Some(n);
    }

    pub const fn packet_size(&self) -> Option<usize> {
        self.packet_size
    }

    /// Payload budget for one packet: what the stub advertised, or the
    /// protocol's pre-negotiation floor.
    const fn packet_budget(&self) -> usize {
        match self.packet_size {
            Some(n) => n,
            None => RSP_DEFAULT_PACKET_SIZE,
        }
    }

    /// Borrow the transport (tests inspect the mock through this).
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Mutably borrow the transport.
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// The transport's out-of-band write handle, if it has one.
    ///
    /// Taken *before* a resume parks this client in `read_reply`, because from
    /// that moment on `&mut self` is unavailable — which is exactly the
    /// constraint that made `pause()` unimplementable.
    #[must_use]
    pub fn interrupter(&self) -> Option<Arc<dyn RspInterrupter>> {
        self.transport.interrupter()
    }

    /// Whether `+`/`-` acknowledgements are still in use.
    #[must_use]
    pub const fn ack_mode(&self) -> bool {
        self.ack_mode
    }

    /// Pop an asynchronous notification observed so far, if any.
    pub fn take_notification(&mut self) -> Option<RspPacket> {
        self.notifications.pop_front()
    }

    /// Pop one chunk of decoded target console output (`O<hex>`), if any.
    pub fn take_console_output(&mut self) -> Option<Vec<u8>> {
        self.console_output.pop_front()
    }

    /// Send a payload and wait for the matching reply.
    ///
    /// Retries on `-` (nack) up to a fixed bound; notifications arriving in
    /// between are queued rather than mistaken for the reply.
    ///
    /// # Errors
    /// See [`RspError`].
    pub fn request(&mut self, payload: &[u8]) -> RspResult<RspPacket> {
        let wire = RspPacket::new(payload.to_vec()).encode();
        let mut attempt = 0u32;
        // Sent ONCE, outside the loop. Which failure happened decides whether
        // it may be sent again — see the two arms below.
        self.transport.send(&wire)?;
        loop {
            match self.read_reply() {
                Ok(Some(pkt)) => {
                    if self.ack_mode {
                        self.transport.send(b"+")?;
                    }
                    return Ok(pkt);
                }
                Ok(None) => {
                    // The peer nacked: it did NOT accept our packet, so it
                    // never ran the command. Re-sending is the repair, and
                    // answering with a `-` of our own would instead ask the
                    // stub to retransmit a reply it has not produced.
                    self.bump_attempt(&mut attempt)?;
                    self.transport.send(&wire)?;
                }
                Err(e) if e.is_retryable() => {
                    // The REPLY was damaged. The stub accepted the command and
                    // has already executed it — re-sending would execute it a
                    // SECOND time: two `M` writes, a `Z0` refcount incremented
                    // twice that one `z0` can never undo, two instructions
                    // stepped for one `vCont;s`. In RSP the repair is `-`
                    // alone: the stub retransmits its last reply.
                    self.bump_attempt(&mut attempt)?;
                    if self.ack_mode {
                        self.transport.send(b"-")?;
                    }
                    // With acks disabled there is no way to ask for a
                    // retransmission, so we simply read again and let the
                    // attempt budget end it. Re-issuing the command to "make
                    // progress" would trade a failed request for a corrupted
                    // target, which is not a trade a debugger may make.
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Count one failed attempt, or give up. Sends nothing: what to send —
    /// and whether the command may be re-issued at all — depends on which
    /// failure occurred, so it is decided by the caller.
    fn bump_attempt(&mut self, attempt: &mut u32) -> RspResult<()> {
        *attempt += 1;
        if *attempt > self.max_retries {
            return Err(RspError::Transport(format!(
                "no valid reply after {} attempts on {}",
                attempt,
                self.transport.description()
            )));
        }
        Ok(())
    }

    /// `Ok(None)` means "the peer nacked, resend".
    fn read_reply(&mut self) -> RspResult<Option<RspPacket>> {
        let mut buf = [0u8; 4096];
        loop {
            while let Some(item) = self.framer.next_item() {
                match item? {
                    RspIncoming::Ack => {}
                    RspIncoming::Nack => return Ok(None),
                    RspIncoming::Notification(p) => self.notifications.push_back(p),
                    // `O<hex>` is the inferior writing to its stdout. It is a
                    // `$`-framed packet like any reply, but it answers no
                    // command: returning it would hand the caller somebody
                    // else's data and shift every later reply by one.
                    RspIncoming::Packet(p) if is_console_output(&p.data) => {
                        if self.ack_mode {
                            self.transport.send(b"+")?;
                        }
                        // The hex is validated by `is_console_output`, so this
                        // cannot fail; keep the raw bytes if it somehow does.
                        let bytes = hex_decode(&p.data[1..]).unwrap_or_else(|_| p.data[1..].to_vec());
                        self.console_output.push_back(bytes);
                    }
                    RspIncoming::Packet(p) => return Ok(Some(p)),
                }
            }
            let n = self.transport.recv(&mut buf)?;
            if n == 0 {
                return Err(RspError::Transport(format!(
                    "connection closed by {}",
                    self.transport.description()
                )));
            }
            self.framer.push(&buf[..n]);
        }
    }

    /// Perform the standard handshake: `qSupported`, then disable ack mode if
    /// the stub agrees. Returns the raw feature string.
    ///
    /// # Errors
    /// See [`RspError`].
    pub fn handshake(&mut self, features: &[&str]) -> RspResult<String> {
        let reply = self.request(&commands::q_supported(features))?;
        let supported = reply.as_str().into_owned();
        self.packet_size = parse_packet_size(&supported);
        if supported.contains("QStartNoAckMode+") {
            let r = self.request(&commands::start_no_ack_mode())?;
            if r.is_ok() {
                self.ack_mode = false;
            }
        }
        Ok(supported)
    }

    /// `m` — read `len` bytes at `addr`.
    ///
    /// # Errors
    /// See [`RspError`]; `Exx` from the stub becomes [`RspError::Remote`].
    pub fn read_memory(&mut self, addr: u64, len: usize) -> RspResult<Vec<u8>> {
        // SPLIT by the stub's `PacketSize`, exactly as `write_memory` below
        // does — and for the same reason, mirrored: `PacketSize` bounds the
        // stub's reply too, and an `m` reply is HEX, so every byte asked for
        // costs two in the buffer. Asking for more than fits does not produce a
        // large read; it produces a truncated one, which this function then
        // (correctly) reports as `ShortRead` — so a perfectly ordinary request
        // like "dump 4 KiB" simply FAILED against a stub advertising 1 KiB,
        // while the same call on the three native backends works. The write path
        // has chunked since it was written; the read path never did.
        let per_packet = (self.packet_budget() / 2).max(1);
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let want = per_packet.min(len - out.len());
            let at = addr.wrapping_add(out.len() as u64);
            let reply = self
                .request(&commands::read_memory(at, want))?
                .ok_or_err("m")?
                .err_if_exit("m")?;
            let bytes = hex_decode(&reply.data)?;
            // A shortfall is data loss, not data — see `RspError::ShortRead`.
            // Reported against the ORIGINAL request, so the caller learns how
            // much of what it asked for exists rather than how much of an
            // internal chunk did.
            if bytes.len() != want {
                return Err(RspError::ShortRead {
                    addr,
                    requested: len,
                    returned: out.len() + bytes.len(),
                });
            }
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }

    /// `M` — write memory, returning the number of bytes accepted.
    ///
    /// The buffer is split into packets that fit the stub's advertised
    /// `PacketSize`. Sending more than that is not a large write, it is a
    /// dropped or truncated one: `PacketSize` is the size of the stub's
    /// RECEIVE buffer, and hex encoding doubles every byte we put in it.
    ///
    /// # Errors
    /// See [`RspError`]. A budget too small to carry even one byte is an
    /// error, not a silent no-op.
    pub fn write_memory(&mut self, addr: u64, data: &[u8]) -> RspResult<usize> {
        let budget = self.packet_budget();
        let per_packet = budget.saturating_sub(M_HEADER_MAX) / 2;
        if per_packet == 0 {
            return Err(RspError::Framing(format!(
                "stub PacketSize {budget} is too small to carry an M write"
            )));
        }
        if data.is_empty() {
            return self.write_memory_chunk(addr, data);
        }
        let mut written = 0usize;
        for chunk in data.chunks(per_packet) {
            let at = addr.wrapping_add(written as u64);
            written += self.write_memory_chunk(at, chunk)?;
        }
        Ok(written)
    }

    /// One `M` packet, already known to fit the budget.
    fn write_memory_chunk(&mut self, addr: u64, data: &[u8]) -> RspResult<usize> {
        let reply = self
            .request(&commands::write_memory(addr, data))?
            .ok_or_err("M")?
            .err_if_exit("M")?;
        if reply.is_ok() {
            Ok(data.len())
        } else {
            Err(RspError::Framing(format!(
                "unexpected reply to M: {}",
                reply.as_str()
            )))
        }
    }

    /// `g` — read the raw register block.
    ///
    /// # Errors
    /// See [`RspError`].
    pub fn read_registers(&mut self) -> RspResult<Vec<u8>> {
        let reply = self
            .request(&commands::read_registers())?
            .ok_or_err("g")?
            .err_if_exit("g")?;
        hex_decode(&reply.data)
    }

    /// `G` — write the raw register block.
    ///
    /// # Errors
    /// See [`RspError`].
    pub fn write_registers(&mut self, raw: &[u8]) -> RspResult<()> {
        // REFUSE a `G` the stub cannot receive, rather than send it and hope.
        //
        // `PacketSize` is the size of the stub's receive buffer and hex doubles
        // every byte, so an AArch64 register block — thirty-odd integer
        // registers plus a 32x128-bit vector file — is well over a kilobyte on
        // the wire. Sent to a stub that advertised less, it is dropped or
        // TRUNCATED, and a truncated `G` is the bad case: the stub may apply the
        // prefix, leaving the target with half its registers overwritten and
        // half not, from an operation that reported success.
        //
        // Unlike a memory write there is no splitting it: `G` is all-or-nothing
        // by definition. So this refuses and names the way out, which already
        // exists — `P` writes one register at a time and is what
        // `set_register` uses.
        let needed = 1 + raw.len() * 2;
        let budget = self.packet_budget();
        if needed > budget {
            return Err(RspError::Framing(format!(
                "a G packet of {needed} bytes does not fit the stub's PacketSize of {budget}; \
                 write the registers individually with P instead"
            )));
        }
        let reply = self
            .request(&commands::write_registers(raw))?
            .ok_or_err("G")?
            .err_if_exit("G")?;
        if reply.is_ok() {
            Ok(())
        } else {
            Err(RspError::Framing(format!(
                "unexpected reply to G: {}",
                reply.as_str()
            )))
        }
    }

    /// `?` — current stop reason.
    ///
    /// # Errors
    /// See [`RspError`].
    pub fn halt_reason(&mut self) -> RspResult<StopReply> {
        let reply = self.request(&commands::halt_reason())?.ok_or_err("?")?;
        StopReply::parse(&reply.data)
    }

    /// Insert a breakpoint via `Z`.
    ///
    /// # Errors
    /// See [`RspError`].
    pub fn insert_breakpoint(
        &mut self,
        kind: commands::ZKind,
        addr: u64,
        size: u32,
    ) -> RspResult<()> {
        let reply = self
            .request(&commands::insert_breakpoint(kind, addr, size))?
            .ok_or_err("Z")?;
        if reply.is_ok() {
            Ok(())
        } else {
            Err(RspError::Framing(format!(
                "unexpected reply to Z: {}",
                reply.as_str()
            )))
        }
    }

    /// Remove a breakpoint via `z`.
    ///
    /// # Errors
    /// See [`RspError`].
    pub fn remove_breakpoint(
        &mut self,
        kind: commands::ZKind,
        addr: u64,
        size: u32,
    ) -> RspResult<()> {
        let reply = self
            .request(&commands::remove_breakpoint(kind, addr, size))?
            .ok_or_err("z")?;
        if reply.is_ok() {
            Ok(())
        } else {
            Err(RspError::Framing(format!(
                "unexpected reply to z: {}",
                reply.as_str()
            )))
        }
    }

    /// Resume with `vCont` and parse the resulting stop reply.
    ///
    /// # Errors
    /// See [`RspError`].
    pub fn vcont(&mut self, actions: &[(&str, Option<u64>)]) -> RspResult<StopReply> {
        let reply = self.request(&commands::vcont(actions))?.ok_or_err("vCont")?;
        StopReply::parse(&reply.data)
    }

    /// `H` — select the thread for subsequent operations.
    ///
    /// # Errors
    /// See [`RspError`].
    pub fn set_thread(&mut self, op: commands::HOp, tid: Option<u64>) -> RspResult<()> {
        let reply = self
            .request(&commands::set_thread(op, tid))?
            .ok_or_err("H")?;
        if reply.is_ok() {
            Ok(())
        } else {
            Err(RspError::Framing(format!(
                "unexpected reply to H: {}",
                reply.as_str()
            )))
        }
    }

    /// Enumerate thread ids via `qfThreadInfo`/`qsThreadInfo`.
    ///
    /// # Errors
    /// See [`RspError`].
    pub fn thread_ids(&mut self) -> RspResult<Vec<u64>> {
        let mut out = Vec::new();
        let mut payload = commands::q_first_thread_info();
        loop {
            let reply = self.request(&payload)?;
            let s = reply.as_str().into_owned();
            if s.is_empty() || s.starts_with('l') {
                break;
            }
            let list = s.strip_prefix('m').unwrap_or(&s);
            for tid in list.split(',').filter(|t| !t.is_empty()) {
                let bare = tid.rsplit('.').next().unwrap_or(tid);
                if let Ok(v) = parse_hex_u64(bare.trim_start_matches('p').as_bytes()) {
                    out.push(v);
                }
            }
            payload = commands::q_next_thread_info();
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {

    /// Truncation + mutation sweep over every parser that touches bytes from
    /// the target.
    ///
    /// This is the most exposed surface in the whole iOS backend: a
    /// `debugserver` is a REMOTE process on a device we do not control, and
    /// every byte it sends reaches `RspPacket::decode` first. The crate's
    /// parsers for local formats (minidump, PE, MSF) were swept this way in
    /// iters 235-236; these never were.
    ///
    /// The bar is simply: malformed input must produce `Err`, never a panic.
    #[test]
    fn rsp_parsers_never_panic_on_truncated_or_mutated_input() {
        // A realistic, well-formed stop reply as the seed.
        let seed = RspPacket::new(b"T05thread:1a2b;name:main;reason:breakpoint;".to_vec()).encode();

        for len in 0..=seed.len() {
            let _ = RspPacket::decode(&seed[..len]);
        }
        for i in 0..seed.len() {
            for probe in [0x00u8, b'#', b'$', b'*', b'}', b'+', 0x7F, 0xFF] {
                let mut m = seed.clone();
                m[i] = probe;
                let _ = RspPacket::decode(&m);
            }
        }

        // The payload parsers, reached once a packet has been framed.
        let payload = b"T05thread:1a2b;name:main;reason:breakpoint;";
        for len in 0..=payload.len() {
            let slice = &payload[..len];
            let _ = StopReply::parse(slice);
            let _ = hex_decode(slice);
            let _ = rle_decode(slice);
            let _ = parse_hex_u64(slice);
        }
        for i in 0..payload.len() {
            for probe in [0x00u8, b'*', b'}', b':', b';', b'x', 0xFF] {
                let mut m = payload.to_vec();
                m[i] = probe;
                let _ = StopReply::parse(&m);
                let _ = hex_decode(&m);
                let _ = rle_decode(&m);
                let _ = parse_hex_u64(&m);
            }
        }

        // Run-length encoding is the one construct that can EXPAND input, so
        // it gets its own adversarial shapes: a repeat with nothing to
        // repeat, and the largest count the encoding can express.
        for hostile in [
            b"*".to_vec(),
            b"*~".to_vec(),
            vec![b'}'],                        // escape with nothing after it
            vec![b'A', b'*', 0xFF],            // maximal repeat count
            vec![b'A', b'*', b' '],            // count that decodes to zero
            vec![b'}', 0x00],
        ] {
            let _ = rle_decode(&hostile);
            let _ = hex_decode(&hostile);
        }
    }
    use super::commands::{HOp, ZKind};
    use super::*;

    // ---- checksum / hex -------------------------------------------------

    #[test]
    fn checksum_matches_gdb_definition() {
        assert_eq!(checksum(b"OK"), 0x9a);
        assert_eq!(checksum(b""), 0);
        // Wrapping is modulo 256, never a panic.
        assert_eq!(checksum(&[0xff, 0xff]), 0xfe);
    }

    #[test]
    fn hex_roundtrip() {
        let data = [0x00u8, 0x7f, 0x80, 0xff, 0x10];
        let enc = hex_encode(&data);
        assert_eq!(enc, b"007f80ff10");
        assert_eq!(hex_decode(&enc).unwrap(), data);
    }

    #[test]
    fn hex_decode_rejects_malformed() {
        assert!(matches!(hex_decode(b"abc"), Err(RspError::Hex(_))));
        assert!(matches!(hex_decode(b"zz"), Err(RspError::Hex(_))));
        assert!(hex_decode(b"").unwrap().is_empty());
    }

    #[test]
    fn parse_hex_u64_bounds() {
        assert_eq!(parse_hex_u64(b"ffffffffffffffff").unwrap(), u64::MAX);
        assert!(parse_hex_u64(b"1ffffffffffffffff").is_err());
        assert!(parse_hex_u64(b"").is_err());
        assert!(parse_hex_u64(b"xyz").is_err());
    }

    // ---- escaping / RLE -------------------------------------------------

    #[test]
    fn escape_roundtrip_covers_all_reserved_bytes() {
        let raw = b"a#b$c}d*e";
        let esc = escape(raw);
        assert!(!esc[1..].contains(&b'#'));
        assert_eq!(unescape(&esc).unwrap(), raw);
    }

    #[test]
    fn unescape_rejects_dangling_escape() {
        assert!(matches!(unescape(b"abc}"), Err(RspError::Encoding(_))));
    }

    #[test]
    fn rle_decode_expands() {
        // '0' followed by *" (0x22 = 34 -> 5 extra copies)
        assert_eq!(rle_decode(b"0*\"").unwrap(), b"000000");
        assert_eq!(rle_decode(b"abc").unwrap(), b"abc");
    }

    #[test]
    fn rle_decode_rejects_malformed_without_panicking() {
        assert!(matches!(rle_decode(b"*a"), Err(RspError::Encoding(_))));
        assert!(matches!(rle_decode(b"a*"), Err(RspError::Encoding(_))));
        assert!(matches!(rle_decode(b"a*\x01"), Err(RspError::Encoding(_))));
    }

    #[test]
    fn rle_encode_roundtrips_and_avoids_illegal_counts() {
        for len in 1usize..200 {
            let data = vec![b'x'; len];
            let enc = rle_encode(&data);
            assert!(!enc.contains(&b'#'), "len {len} produced '#'");
            assert!(!enc.contains(&b'$'), "len {len} produced '$'");
            assert_eq!(rle_decode(&enc).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn rle_encode_roundtrips_mixed_data() {
        let data = b"aaaaaaaabbbcdddddddddddddddddddde".to_vec();
        assert_eq!(rle_decode(&rle_encode(&data)).unwrap(), data);
    }

    // ---- packets --------------------------------------------------------

    #[test]
    fn packet_encode_shape() {
        assert_eq!(RspPacket::new(b"OK".to_vec()).encode(), b"$OK#9a");
        assert_eq!(RspPacket::new(Vec::new()).encode(), b"$#00");
    }

    #[test]
    fn packet_decode_verifies_checksum() {
        assert_eq!(RspPacket::decode(b"$OK#9a").unwrap().data, b"OK");
        assert!(matches!(
            RspPacket::decode(b"$OK#9b"),
            Err(RspError::BadChecksum {
                expected: 0x9b,
                computed: 0x9a
            })
        ));
    }

    #[test]
    fn packet_decode_skips_leading_acks() {
        assert_eq!(RspPacket::decode(b"++-$OK#9a").unwrap().data, b"OK");
    }

    #[test]
    fn packet_decode_handles_truncated_and_garbage_without_panicking() {
        for bad in [
            &b""[..],
            b"$",
            b"$OK",
            b"$OK#",
            b"$OK#9",
            b"garbage",
            b"#9a",
            b"$}",
            b"$*a#00",
        ] {
            let _ = RspPacket::decode(bad);
        }
    }

    #[test]
    fn packet_roundtrip_with_reserved_bytes_and_rle() {
        let payload: Vec<u8> = (0u8..=255).collect();
        for wire in [
            RspPacket::new(payload.clone()).encode(),
            RspPacket::new(payload.clone()).encode_compressed(),
        ] {
            assert_eq!(RspPacket::decode(&wire).unwrap().data, payload);
        }
    }

    #[test]
    fn packet_classification_helpers() {
        assert!(RspPacket::new(b"OK".to_vec()).is_ok());
        assert!(RspPacket::new(Vec::new()).is_empty_reply());
        assert_eq!(RspPacket::new(b"E01".to_vec()).error_code(), Some(1));
        assert_eq!(RspPacket::new(b"Exx".to_vec()).error_code(), None);
        assert!(matches!(
            RspPacket::new(b"E05".to_vec()).ok_or_err("m"),
            Err(RspError::Remote(5))
        ));
        assert!(matches!(
            RspPacket::new(Vec::new()).ok_or_err("qFoo"),
            Err(RspError::Unsupported(_))
        ));
    }

    // ---- framer ---------------------------------------------------------

    #[test]
    fn framer_reassembles_across_byte_sized_chunks() {
        let wire = RspPacket::new(b"T05thread:1;".to_vec()).encode();
        let mut f = RspFramer::new();
        let mut got = None;
        for b in &wire {
            f.push(&[*b]);
            while let Some(item) = f.next_item() {
                if let RspIncoming::Packet(p) = item.unwrap() {
                    got = Some(p);
                }
            }
        }
        assert_eq!(got.unwrap().data, b"T05thread:1;");
        assert_eq!(f.buffered(), 0);
    }

    #[test]
    fn framer_yields_acks_and_notifications() {
        let mut f = RspFramer::new();
        let mut wire = RspPacket::new(b"Stop:T05".to_vec()).encode();
        wire[0] = b'%';
        f.push(b"+-");
        f.push(&wire);
        f.push(&RspPacket::new(b"OK".to_vec()).encode());
        assert_eq!(f.next_item().unwrap().unwrap(), RspIncoming::Ack);
        assert_eq!(f.next_item().unwrap().unwrap(), RspIncoming::Nack);
        assert!(matches!(
            f.next_item().unwrap().unwrap(),
            RspIncoming::Notification(_)
        ));
        assert!(matches!(
            f.next_item().unwrap().unwrap(),
            RspIncoming::Packet(_)
        ));
        assert!(f.next_item().is_none());
    }

    #[test]
    fn framer_consumes_corrupt_packet_so_the_loop_terminates() {
        let mut f = RspFramer::new();
        f.push(b"$OK#00$OK#9a");
        assert!(matches!(
            f.next_item().unwrap(),
            Err(RspError::BadChecksum { .. })
        ));
        // The good packet behind the bad one is still recoverable.
        assert!(matches!(
            f.next_item().unwrap().unwrap(),
            RspIncoming::Packet(_)
        ));
    }

    #[test]
    fn framer_caps_a_packet_that_never_terminates() {
        let mut f = RspFramer::new();
        // A peer that opens a packet and streams payload forever.
        f.push(b"$");
        let chunk = vec![b'A'; 64 * 1024];
        let mut errored = false;
        for _ in 0..(RSP_MAX_BUFFERED / chunk.len() + 2) {
            f.push(&chunk);
            match f.next_item() {
                None => {}
                Some(Err(RspError::Framing(_))) => {
                    errored = true;
                    break;
                }
                other => panic!("unexpected item {other:?}"),
            }
            assert!(
                f.buffered() <= RSP_MAX_BUFFERED + chunk.len(),
                "buffer grew past the cap: {}",
                f.buffered()
            );
        }
        assert!(errored, "framer never reported the overlong packet");
        // The buffer is released, not retained, so a resync starts clean.
        assert_eq!(f.buffered(), 0);
    }

    #[test]
    fn framer_never_panics_on_arbitrary_input() {
        let inputs: [&[u8]; 7] = [
            b"$$$$",
            b"####",
            b"$}#",
            b"%",
            b"$*\x00#00",
            b"\x00\x01\x02$OK#9a",
            b"$OK#zz",
        ];
        for inp in inputs {
            let mut f = RspFramer::new();
            f.push(inp);
            let mut guard = 0;
            while let Some(_item) = f.next_item() {
                guard += 1;
                assert!(guard < 64, "framer failed to make progress on {inp:?}");
            }
        }
    }

    // ---- commands -------------------------------------------------------

    #[test]
    fn command_shapes() {
        assert_eq!(commands::halt_reason(), b"?");
        assert_eq!(commands::read_memory(0x1000, 16), b"m1000,10");
        assert_eq!(commands::write_memory(0x20, &[0xde, 0xad]), b"M20,2:dead");
        assert_eq!(commands::read_register(31), b"p1f");
        assert_eq!(commands::write_register(0, &[0x01]), b"P0=01");
        assert_eq!(commands::cont(None), b"c");
        assert_eq!(commands::cont(Some(0x40)), b"c40");
        assert_eq!(commands::step(None), b"s");
        assert_eq!(
            commands::vcont(&[("s", Some(2)), ("c", None)]),
            b"vCont;s:2;c"
        );
        assert_eq!(
            commands::insert_breakpoint(ZKind::Software, 0x1000, 4),
            b"Z0,1000,4"
        );
        assert_eq!(
            commands::remove_breakpoint(ZKind::Hardware, 0x1000, 4),
            b"z1,1000,4"
        );
        assert_eq!(
            commands::q_supported(&["multiprocess+", "swbreak+"]),
            b"qSupported:multiprocess+;swbreak+"
        );
        assert_eq!(commands::q_supported(&[]), b"qSupported");
        assert_eq!(commands::set_thread(HOp::General, Some(0)), b"Hg0");
        assert_eq!(commands::set_thread(HOp::Continue, None), b"Hc-1");
        assert_eq!(commands::detach(), b"D");
        assert_eq!(commands::kill(), b"k");
    }

    #[test]
    fn binary_write_is_escaped_at_encode_time() {
        let payload = commands::write_memory_binary(0, &[b'$', b'#', b'}', b'*']);
        let wire = RspPacket::new(payload.clone()).encode();
        assert_eq!(RspPacket::decode(&wire).unwrap().data, payload);
    }

    // ---- stop replies ---------------------------------------------------

    #[test]
    fn stop_reply_parsing() {
        assert_eq!(
            StopReply::parse(b"S05").unwrap(),
            StopReply::Signal { signal: 5 }
        );
        assert_eq!(
            StopReply::parse(b"W00").unwrap(),
            StopReply::Exited { status: 0 }
        );
        assert!(StopReply::parse(b"W00").unwrap().is_exit());
        let t = StopReply::parse(b"T05thread:1a3;metype:6;medata:1;").unwrap();
        match t {
            StopReply::SignalWithInfo {
                signal,
                thread,
                pairs,
            } => {
                assert_eq!(signal, 5);
                assert_eq!(thread, Some(0x1a3));
                assert!(pairs.iter().any(|(k, v)| k == "metype" && v == "6"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn stop_reply_rejects_garbage_without_panicking() {
        for bad in [&b""[..], b"Q", b"T", b"T0", b"Tzz", b"S"] {
            assert!(StopReply::parse(bad).is_err());
        }
    }

    // ---- client over the mock transport ---------------------------------

    fn client_with(replies: &[&[u8]]) -> RspClient<MockTransport> {
        let mut t = MockTransport::new();
        for r in replies {
            t.push_reply(r);
        }
        RspClient::new(t)
    }

    /// A `G` that does not fit the stub's buffer must be REFUSED, not sent.
    ///
    /// The dual of the read-splitting test below, and the case where splitting
    /// is not available: `G` writes the whole register block or nothing. An
    /// AArch64 block — thirty-odd integer registers plus a 32x128-bit vector
    /// file — is over a kilobyte once hex-encoded, so a stub that advertised
    /// less either drops it or, worse, applies the PREFIX: half the target's
    /// registers overwritten and half not, from a call that reported success.
    ///
    /// Refusing names the way out, which already exists: `P` writes one
    /// register at a time, and is what `set_register` uses.
    #[test]
    fn a_register_block_too_big_for_the_stub_is_refused_instead_of_truncated() {
        let mut t = MockTransport::new();
        t.push_reply(b"OK"); // the stub would happily answer, if we sent it
        let mut c = RspClient::new(t);
        let () = c.set_packet_size_for_test(64);

        // 64 bytes of registers = 129 bytes on the wire, over a 64-byte budget.
        let err = c.write_registers(&[0xAAu8; 64]).expect_err(
            "a register block twice the stub's buffer was accepted: it is dropped or truncated on the far side, and a truncated G can leave the target with half its registers overwritten",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("PacketSize"),
            "the refusal must say what the limit is, so the caller can act on it: {msg}"
        );
        assert!(
            c.transport().sent_str().is_empty(),
            "the oversized packet was put on the wire anyway: {}",
            c.transport().sent_str()
        );

        // And a block that DOES fit still goes through, so the guard is a limit
        // and not a wall.
        let () = c.set_packet_size_for_test(4096);
        c.write_registers(&[0xAAu8; 64]).expect("a block within budget must still be written");
    }

    /// A read bigger than the stub's buffer must be SPLIT, not refused.
    ///
    /// `PacketSize` bounds the stub's reply as well as its receive buffer, and
    /// an `m` reply is hex — two buffer bytes per byte asked for. A single `m`
    /// for more than that comes back truncated, which `read_memory` then
    /// (correctly) calls a short read: so an ordinary "dump 4 KiB" simply FAILED
    /// against a small stub, while the same call on the three native backends
    /// works. `write_memory` has chunked since it was written; the read path
    /// never did, and the asymmetry sat in the same file.
    #[test]
    fn a_read_larger_than_the_packet_size_is_split_into_several_m_packets() {
        // Budget 16 => 8 bytes per `m`. Four replies of 8 bytes each cover 32.
        let mut t = MockTransport::new();
        for _ in 0..4 {
            t.push_reply(b"aabbccddeeff0011"); // 8 bytes, hex-encoded
        }
        let mut c = RspClient::new(t);
        let () = c.set_packet_size_for_test(16);

        let got = c.read_memory(0x1000, 32).expect("a 32-byte read must succeed");
        assert_eq!(got.len(), 32, "the read came back short instead of being split");

        let sent = c.transport().sent_str();
        assert_eq!(
            sent.matches("$m").count(),
            4,
            "expected four `m` packets of eight bytes each; the wire was {sent}"
        );
        assert!(
            sent.contains("$m1000,8#"),
            "the first chunk must ask for the budget, not the whole request: {sent}"
        );
        assert!(
            sent.contains("$m1008,8#"),
            "each chunk must continue where the last one ended: {sent}"
        );
    }

    #[test]
    fn request_response_and_ack_traffic() {
        let mut c = client_with(&[b"OK"]);
        let reply = c.request(b"?").unwrap();
        assert!(reply.is_ok());
        let sent = c.transport().sent_str();
        assert!(sent.starts_with("$?#3f"), "sent: {sent}");
        assert!(sent.ends_with('+'), "ack not sent: {sent}");
    }

    #[test]
    fn exit_reply_to_data_command_is_reported_as_process_gone() {
        // A stub that loses the inferior mid-request answers the *pending*
        // command with a stop reply. The honest diagnosis is "the process is
        // gone", not a complaint about the encoding of the bytes.
        for (reply, cmd) in [
            (&b"W00"[..], "m"),
            (&b"X09"[..], "m"),
            (&b"W00"[..], "M"),
            (&b"W00"[..], "g"),
            (&b"X09"[..], "G"),
        ] {
            let mut c = client_with(&[reply]);
            let err = match cmd {
                "m" => c.read_memory(0x1000, 4).unwrap_err(),
                "M" => c.write_memory(0x1000, &[0u8; 4]).unwrap_err(),
                "g" => c.read_registers().unwrap_err(),
                "G" => c.write_registers(&[0u8; 4]).unwrap_err(),
                _ => unreachable!(),
            };
            assert!(
                matches!(err, RspError::ProcessGone { .. }),
                "reply {} to {cmd} reported as {err:?}, not process exit",
                String::from_utf8_lossy(reply)
            );
        }
    }

    #[test]
    fn memory_read_write_roundtrip() {
        let mut c = client_with(&[b"cafe", b"OK"]);
        assert_eq!(c.read_memory(0x1000, 2).unwrap(), vec![0xca, 0xfe]);
        assert_eq!(c.write_memory(0x1000, &[0x01, 0x02]).unwrap(), 2);
        assert!(c.transport().sent_str().contains("M1000,2:0102"));
    }

    #[test]
    fn remote_error_is_typed_not_swallowed() {
        let mut c = client_with(&[b"E05"]);
        assert!(matches!(
            c.read_memory(0x1000, 4),
            Err(RspError::Remote(0x05))
        ));
    }

    #[test]
    fn empty_reply_means_unsupported() {
        let mut c = client_with(&[b""]);
        assert!(matches!(
            c.read_registers(),
            Err(RspError::Unsupported(ref s)) if s == "g"
        ));
    }

    #[test]
    fn handshake_disables_ack_mode_when_offered() {
        let mut c = client_with(&[b"PacketSize=1000;QStartNoAckMode+", b"OK"]);
        let feats = c.handshake(&["multiprocess+"]).unwrap();
        assert!(feats.contains("QStartNoAckMode+"));
        assert!(!c.ack_mode());
    }

    #[test]
    fn handshake_keeps_ack_mode_when_not_offered() {
        let mut c = client_with(&[b"PacketSize=1000"]);
        c.handshake(&[]).unwrap();
        assert!(c.ack_mode());
    }

    #[test]
    fn fragmented_delivery_is_reassembled() {
        let mut t = MockTransport::new().with_faults(MockFaults {
            chunk_size: 1,
            ..MockFaults::default()
        });
        t.push_reply(&hex_encode(&[0xaa; 64]));
        let mut c = RspClient::new(t);
        assert_eq!(c.read_memory(0, 64).unwrap(), vec![0xaa; 64]);
    }

    /// A nack from the peer must be answered with the COMMAND, never with `-`.
    ///
    /// The mirror image of the corrupted-reply case, and the second half of
    /// the same confusion. `-` from the stub means "your packet was garbled,
    /// send it again". Answering it with a `-` of our own says the opposite —
    /// "your last reply was garbled, send IT again" — and a spec-conformant
    /// stub duly retransmits its previous reply. That extra, unrequested
    /// packet stays in the stream and is consumed as the answer to the NEXT
    /// command, so from then on every reply is one packet behind, for the life
    /// of the connection. RSP has no sequence numbers, so nothing downstream
    /// can notice the skew: `read_registers` would simply return the previous
    /// command's data as though it were registers.
    ///
    /// The window is narrow — `QStartNoAckMode` closes it as soon as the stub
    /// advertises it, which Apple's debugserver does — but the handshake
    /// itself happens inside that window.
    #[test]
    fn a_nack_resends_the_command_and_does_not_nack_back() {
        let mut t = MockTransport::new();
        t.push_raw(b"-"); // the stub rejected our packet
        t.push_reply(b"OK"); // ...and accepts the retransmission
        let mut c = RspClient::new(t);

        assert!(c.request(b"qC").unwrap().is_ok());

        let sent = c.transport().sent_str();
        assert_eq!(
            sent.matches("qC").count(),
            2,
            "a nacked command must be retransmitted exactly once more; sent: {sent:?}"
        );
        assert!(
            !sent.contains('-'),
            "we answered the stub's nack with a nack of our own, asking it to retransmit a reply it \
             never sent; a conformant stub then emits an extra packet and every later reply is one \
             behind. Sent: {sent:?}"
        );
    }

    /// A damaged REPLY must not make us run the command a second time.
    ///
    /// RSP repairs a corrupted reply with `-` alone: the stub retransmits its
    /// last reply. The command itself must never be re-issued, because the stub
    /// accepted it and has already executed it. Re-sending turns one flipped
    /// bit on the inbound path into a duplicated side effect — two `M` writes,
    /// a `Z0` refcount incremented twice that a single `z0` can never undo,
    /// two instructions stepped for one `vCont;s`.
    ///
    /// No existing test could see this: the mock is a reply queue with no
    /// target state, so a command arriving twice changes nothing it can
    /// observe. Counting the transmissions is what makes it visible, and it is
    /// the only assertion here that fails on the old code.
    #[test]
    fn a_corrupt_reply_is_nacked_without_re_executing_the_command() {
        let mut t = MockTransport::new().with_faults(MockFaults {
            corrupt_checksum_at: Some(0),
            ..MockFaults::default()
        });
        t.push_reply(b"OK"); // damaged in transit
        t.push_reply(b"OK"); // the stub's retransmission
        let mut c = RspClient::new(t);

        // A command with a side effect, so the duplication is not academic:
        // this writes four bytes into the target.
        let cmd = b"M1000,4:deadbeef";
        assert!(c.request(cmd).unwrap().is_ok());

        let sent = c.transport().sent_str();
        let times = sent.matches("M1000,4:deadbeef").count();
        assert_eq!(
            times, 1,
            "the command was transmitted {times} times after its reply was corrupted; a real \
             debugserver would perform the write once per transmission, so the target ends up \
             with the command applied twice. Sent: {sent:?}"
        );
        assert!(
            sent.contains('-'),
            "the corrupted reply must still be nacked so the stub retransmits it"
        );
    }

    #[test]
    fn corrupt_checksum_triggers_retry_then_succeeds() {
        let mut t = MockTransport::new().with_faults(MockFaults {
            corrupt_checksum_at: Some(0),
            ..MockFaults::default()
        });
        t.push_reply(b"OK"); // corrupted
        t.push_reply(b"OK"); // clean retransmission
        let mut c = RspClient::new(t);
        assert!(c.request(b"?").unwrap().is_ok());
        assert!(c.transport().sent_str().contains('-'), "no nack was sent");
    }

    #[test]
    fn non_hex_checksum_digit_is_retried_not_fatal() {
        // A flipped bit can land on the checksum digit itself, producing a
        // non-hex character rather than a checksum mismatch. Both are the same
        // wire event and both must retransmit.
        let mut t = MockTransport::new();
        t.push_raw(b"+$OK#9`");
        t.push_reply(b"OK");
        let mut c = RspClient::new(t);
        assert!(c.request(b"?").unwrap().is_ok());
    }

    #[test]
    fn retryable_classification_is_explicit() {
        assert!(RspError::Truncated.is_retryable());
        assert!(RspError::Hex("x".into()).is_retryable());
        assert!(!RspError::Remote(5).is_retryable());
        assert!(!RspError::Unsupported("g".into()).is_retryable());
        assert!(!RspError::Transport("closed".into()).is_retryable());
    }

    #[test]
    fn persistent_corruption_gives_up_with_an_explicit_error() {
        let mut t = MockTransport::new();
        // Four corrupt replies: more than max_retries.
        for _ in 0..4 {
            t.push_raw(b"+$OK#00");
        }
        let mut c = RspClient::new(t);
        assert!(matches!(c.request(b"?"), Err(RspError::Transport(_))));
    }

    #[test]
    fn closed_connection_is_reported_not_hung() {
        let mut c = RspClient::new(MockTransport::new());
        assert!(matches!(c.request(b"?"), Err(RspError::Transport(_))));
    }

    #[test]
    fn notifications_do_not_get_mistaken_for_replies() {
        let mut t = MockTransport::new();
        t.push_notification(b"Stop:T05thread:1;");
        t.push_reply(b"OK");
        let mut c = RspClient::new(t);
        assert!(c.request(b"?").unwrap().is_ok());
        let n = c.take_notification().expect("notification was dropped");
        assert_eq!(n.data, b"Stop:T05thread:1;");
        assert!(c.take_notification().is_none());
    }

    /// An `O` packet arriving where a reply is expected must not be consumed
    /// as that reply. If it is, `m` decodes console text as memory AND every
    /// later command reads the previous command's answer — the desync is
    /// permanent, so the second assertion is the load-bearing one.
    ///
    /// Not vacuous: both assertions run unconditionally on a fixed script.
    /// Mutating `is_console_output` to `false` (or deleting the new arm in
    /// `read_reply`) turns the first assertion red.
    #[test]
    fn console_output_is_not_consumed_as_a_reply() {
        let mut t = MockTransport::new();
        t.push_reply(b"O48656c6c6f"); // "Hello" on the inferior's stdout
        t.push_reply(b"41414141"); // the real answer to `m`
        t.push_reply(b"OK"); // the real answer to `qC`
        let mut c = RspClient::new(t);

        assert_eq!(
            c.read_memory(0x1000, 4).expect("O packet eaten the m reply"),
            vec![0x41, 0x41, 0x41, 0x41]
        );
        // The connection must still be in step: `qC` gets `qC`'s answer.
        assert_eq!(c.request(b"qC").unwrap().as_str(), "OK");
        assert_eq!(c.take_console_output().as_deref(), Some(&b"Hello"[..]));
        assert!(c.take_console_output().is_none());
    }

    /// `OK` starts with `O` too. It must stay a reply.
    #[test]
    fn ok_is_not_mistaken_for_console_output() {
        assert!(!is_console_output(b"OK"));
        assert!(is_console_output(b"O48"));
        let mut c = client_with(&[b"OK"]);
        assert!(c.request(b"?").unwrap().is_ok());
    }

    #[test]
    fn breakpoint_and_vcont_flow() {
        let mut c = client_with(&[b"OK", b"T05thread:2;", b"OK"]);
        c.insert_breakpoint(ZKind::Software, 0x1_0000, 4).unwrap();
        let stop = c.vcont(&[("c", None)]).unwrap();
        assert!(matches!(
            stop,
            StopReply::SignalWithInfo {
                signal: 5,
                thread: Some(2),
                ..
            }
        ));
        c.remove_breakpoint(ZKind::Software, 0x1_0000, 4).unwrap();
        let sent = c.transport().sent_str();
        assert!(sent.contains("Z0,10000,4"));
        assert!(sent.contains("z0,10000,4"));
    }

    #[test]
    fn thread_enumeration_paginates() {
        let mut c = client_with(&[b"m1,2", b"m3", b"l"]);
        assert_eq!(c.thread_ids().unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn register_block_roundtrip() {
        let mut c = client_with(&[&hex_encode(&[0x11; 8]), b"OK"]);
        assert_eq!(c.read_registers().unwrap(), vec![0x11; 8]);
        c.write_registers(&[0x22; 8]).unwrap();
        assert!(c.transport().sent_str().contains("G2222222222222222"));
    }

    // ---- out-of-band interrupt -----------------------------------------

    #[test]
    fn a_transport_without_a_second_handle_reports_no_interrupter() {
        /// The default impl is the whole point: a transport that cannot be
        /// written to concurrently must not pretend it can.
        struct OneWay;
        impl RspTransport for OneWay {
            fn send(&mut self, _d: &[u8]) -> io::Result<()> {
                Ok(())
            }
            fn recv(&mut self, _b: &mut [u8]) -> io::Result<usize> {
                Ok(0)
            }
        }
        assert!(OneWay.interrupter().is_none());
        assert!(RspClient::new(OneWay).interrupter().is_none());
    }

    #[test]
    fn mock_interrupter_records_the_single_interrupt_byte() {
        let client = RspClient::new(MockTransport::new());
        let oob = client.interrupter().expect("mock exposes an interrupter");
        assert_eq!(oob.description(), "mock-interrupt");
        oob.interrupt().unwrap();
        oob.interrupt().unwrap();
        assert_eq!(client.transport().out_of_band(), vec![RSP_INTERRUPT_BYTE; 2]);
        assert_eq!(client.transport().out_of_band_sends(), 2);
        // The interrupt must NOT go through the framed request path, or the
        // stub would see `$#..` and answer nothing.
        assert!(client.transport().sent().is_empty());
    }

    /// The handle must be usable from another thread while the reader is
    /// parked in `recv` on the ORIGINAL socket — the exact situation `pause`
    /// faces, and the reason `send`/`recv` taking `&mut self` was a blocker.
    #[test]
    fn tcp_interrupter_writes_while_the_reader_is_blocked() {
        use std::io::Read as _;
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut got = [0u8; 1];
            // Blocks until the out-of-band write lands.
            sock.read_exact(&mut got).expect("read interrupt");
            tx.send(got[0]).expect("report");
            // Answer as debugserver would: a SIGINT stop reply.
            let _ = sock.write_all(&RspPacket::new(b"T02thread:1;".to_vec()).encode());
            let mut sink = Vec::new();
            let _ = sock.read_to_end(&mut sink);
        });

        let mut transport = TcpTransport::connect(addr, Some(Duration::from_secs(10)))
            .expect("connect");
        let oob = transport.interrupter().expect("tcp exposes an interrupter");
        assert!(oob.description().starts_with("tcp-interrupt:"));

        // Nothing has been sent in band; the byte can only arrive through the
        // duplicated handle.
        oob.interrupt().expect("out-of-band write");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)).expect("server saw the byte"),
            RSP_INTERRUPT_BYTE
        );

        // And the main handle still frames correctly afterwards: the stop reply
        // is readable as a packet, not as noise.
        let mut framer = RspFramer::new();
        let mut buf = [0u8; 64];
        let mut packet = None;
        for _ in 0..16 {
            if let Some(item) = framer.next_item() {
                if let RspIncoming::Packet(p) = item.expect("well-formed") {
                    packet = Some(p);
                    break;
                }
                continue;
            }
            let n = transport.recv(&mut buf).expect("recv");
            assert!(n > 0, "socket closed before the stop reply arrived");
            framer.push(&buf[..n]);
        }
        assert_eq!(
            packet.expect("stop reply").as_str(),
            "T02thread:1;",
            "the interrupt's stop reply must arrive on the main stream"
        );
        // BOTH handles on the socket have to go before the peer can see EOF.
        // `TcpInterrupter::from_stream` DUPLICATES the descriptor, so an
        // interrupter that outlives its transport holds the connection open:
        // dropping only the transport left the server's `read_to_end` blocked
        // forever and this test hung — on Linux it never returned, which is why
        // the whole WSL suite could not finish (it stopped here, at test ~850,
        // for two consecutive days). Windows happens not to reproduce it.
        //
        // Keeping the drop explicit is the point: it also states the production
        // invariant — an interrupter is a second owner of the socket, and a
        // caller that parks one somewhere long-lived keeps the debugserver
        // connection alive after the debugger believes it has detached.
        drop(oob);
        drop(transport);
        server.join().expect("server thread");
    }

    /// The interrupt round-trip against the real mock stub, at the TRANSPORT
    /// level: send a resume the stub answers with silence, inject `\x03`
    /// through the duplicated handle, and read the SIGINT stop reply back on
    /// the main stream.
    ///
    /// Written to place blame. `pause_interrupts_a_running_target_over_a_real_socket`
    /// fails identically on Windows and Linux with a read timeout on the parked
    /// `vCont`, and that test drives the whole `AppleDebugger` session. This one
    /// exercises the same wire conversation with no session, no async runtime
    /// and no locks — so if it passes, the transport, the interrupter and the
    /// stub are all sound and the defect is above them.
    #[test]
    fn the_interrupt_round_trip_works_at_the_transport_level() {
        use crate::ios::mock_debugserver::MockDebugserver;

        // A64 `nop` sled: the program is irrelevant here, only the wire is.
        let mut srv = MockDebugserver::with_program(4242, 0x1_0000, &[0xD503_201Fu32; 4]);
        srv.run_until_interrupt = true;
        let (addr, server) = srv.spawn_tcp().expect("spawn tcp mock");

        let mut transport =
            TcpTransport::connect(addr.as_str(), Some(Duration::from_secs(5))).expect("connect");
        let oob = transport.interrupter().expect("tcp exposes an interrupter");

        // A resume the stub deliberately does not answer.
        transport
            .send(&RspPacket::new(b"vCont;c".to_vec()).encode())
            .expect("send vCont");

        // Now the only thing that can produce a reply is the out-of-band byte.
        oob.interrupt().expect("out-of-band write");

        let mut framer = RspFramer::new();
        let mut buf = [0u8; 256];
        let mut stop = None;
        for _ in 0..64 {
            while let Some(item) = framer.next_item() {
                if let RspIncoming::Packet(p) = item.expect("well-formed") {
                    stop = Some(p);
                    break;
                }
            }
            if stop.is_some() {
                break;
            }
            let n = transport.recv(&mut buf).expect("recv must not time out");
            assert!(n > 0, "stub closed before answering the interrupt");
            framer.push(&buf[..n]);
        }
        let stop = stop.expect("the interrupt must produce a stop reply");
        assert!(
            stop.as_str().starts_with("T02"),
            "expected a SIGINT stop, got {:?}",
            stop.as_str()
        );

        drop(oob);
        drop(transport);
        let _ = server.join();
    }

    /// The interrupt round trip one layer up: through `RspClient::request`,
    /// with the real handshake, instead of raw `send`/`recv`.
    ///
    /// `request` is where a parked resume actually lives in production —
    /// `Session::text` is a thin wrapper over it — and it does things the raw
    /// transport does not: it retransmits on retryable errors, it tracks
    /// ack mode, and it buffers notifications. Any of those could swallow the
    /// stop reply that `pause()` is waiting for.
    ///
    /// Third and last layer this session can isolate: transport (ok), wire
    /// ordering (ok), client. Whatever this says, the remaining suspect list
    /// shrinks to one.
    #[test]
    fn the_interrupt_round_trip_works_through_the_client_after_a_handshake() {
        use crate::ios::mock_debugserver::MockDebugserver;
        use std::sync::mpsc;

        let mut srv = MockDebugserver::with_program(4242, 0x1_0000, &[0xD503_201Fu32; 4]);
        srv.run_until_interrupt = true;
        let (addr, server) = srv.spawn_tcp().expect("spawn tcp mock");

        let mut transport =
            TcpTransport::connect(addr.as_str(), Some(Duration::from_secs(5))).expect("connect");
        let oob = transport.interrupter().expect("tcp exposes an interrupter");
        let mut client = RspClient::new(transport);
        // The same negotiation `attach` performs, so ack mode matches
        // production rather than the raw-socket default.
        let _ = client.handshake(&[]);

        let (tx, rx) = mpsc::channel();
        let runner = std::thread::spawn(move || {
            let reply = client.request(b"vCont;c");
            tx.send(reply.map(|p| p.as_str().into_owned())).expect("report");
            client
        });

        // Give the resume time to be genuinely outstanding, then interrupt.
        std::thread::sleep(Duration::from_millis(100));
        oob.interrupt().expect("out-of-band write");

        let reply = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the parked request must return once the interrupt lands")
            .expect("the interrupt's stop reply must come back as the request's reply");
        assert!(
            reply.starts_with("T02"),
            "expected a SIGINT stop, got {reply:?}"
        );

        drop(oob);
        drop(runner.join().expect("runner thread"));
        let _ = server.join();
    }

    /// The SAME round trip with the two writes in the other order: `\x03`
    /// first, then the resume.
    ///
    /// This is not a hypothetical ordering. `AppleDebugger::resume` raises
    /// `resume_in_flight` and only afterwards writes the `vCont`, so a caller
    /// that waits for that flag and then calls `pause()` — the documented way
    /// to interrupt a running target — can put the interrupt on the wire first.
    ///
    /// What the stub does with an early interrupt decides whether that race is
    /// survivable: if the stop reply it emits is still waiting in the socket
    /// when the resume arrives, the resume consumes it and the caller is fine;
    /// if the interrupt is instead "used up" and the later resume is answered
    /// with silence, the caller blocks until its read timeout — which is
    /// exactly how `pause_interrupts_a_running_target_over_a_real_socket`
    /// fails, on both platforms.
    #[test]
    fn an_interrupt_that_beats_the_resume_onto_the_wire_still_stops_the_target() {
        use crate::ios::mock_debugserver::MockDebugserver;

        let mut srv = MockDebugserver::with_program(4242, 0x1_0000, &[0xD503_201Fu32; 4]);
        srv.run_until_interrupt = true;
        let (addr, server) = srv.spawn_tcp().expect("spawn tcp mock");

        let mut transport =
            TcpTransport::connect(addr.as_str(), Some(Duration::from_secs(5))).expect("connect");
        let oob = transport.interrupter().expect("tcp exposes an interrupter");

        // Reversed on purpose: the interrupt goes out BEFORE the resume.
        oob.interrupt().expect("out-of-band write");
        std::thread::sleep(Duration::from_millis(50)); // let the stub see it first
        transport
            .send(&RspPacket::new(b"vCont;c".to_vec()).encode())
            .expect("send vCont");

        let mut framer = RspFramer::new();
        let mut buf = [0u8; 256];
        let mut stop = None;
        for _ in 0..64 {
            while let Some(item) = framer.next_item() {
                if let RspIncoming::Packet(p) = item.expect("well-formed") {
                    stop = Some(p);
                    break;
                }
            }
            if stop.is_some() {
                break;
            }
            let n = transport
                .recv(&mut buf)
                .expect("an interrupt that arrived early must not strand the resume");
            assert!(n > 0, "stub closed instead of answering");
            framer.push(&buf[..n]);
        }
        let stop = stop.expect("a stop reply must reach the caller in either order");
        assert!(
            stop.as_str().starts_with("T02"),
            "expected a SIGINT stop, got {:?}",
            stop.as_str()
        );

        drop(oob);
        drop(transport);
        let _ = server.join();
    }
}

#[cfg(test)]
mod packet_size_tests {
    use super::{parse_packet_size, RspClient, TcpTransport};
    use crate::ios::mock_debugserver::MockDebugserver;
    use std::time::Duration;

    #[test]
    fn packet_size_is_parsed_from_qsupported() {
        assert_eq!(
            parse_packet_size("PacketSize=fa0;QStartNoAckMode+"),
            Some(4000)
        );
        assert_eq!(parse_packet_size("QStartNoAckMode+"), None);
        assert_eq!(parse_packet_size("PacketSize=zz"), None);
    }

    /// The stub declares the size of its receive buffer; a client that ignores
    /// it corrupts or loses a large patch against a real debugserver while
    /// passing against every permissive mock. Observed through the mock's
    /// `packet_log`, which records exactly what went on the wire.
    #[test]
    fn large_write_is_split_to_fit_the_advertised_packet_size() {
        const STACK_BASE: u64 = 0x1_6f00_0000;
        let srv = MockDebugserver::with_program(1, 0x4000, &[0xd503_201f]);
        let (addr, handle) = srv.spawn_tcp().expect("spawn tcp mock");

        let transport =
            TcpTransport::connect(&addr, Some(Duration::from_secs(5))).expect("connect");
        let mut client = RspClient::new(transport);
        let features = client.handshake(&[]).expect("handshake");
        let advertised = parse_packet_size(&features).expect("mock advertises PacketSize");
        assert_eq!(client.packet_size(), Some(advertised));

        // 64 KiB: hex encoding doubles it to 128 KiB on the wire, eight times
        // the 0x4000 bytes the stub declared it can receive.
        let payload = vec![0xAAu8; 64 * 1024];
        let n = client.write_memory(STACK_BASE, &payload).expect("write");
        assert_eq!(n, payload.len(), "every byte must be written");
        // Chunk addressing: the tail must be at the tail, not re-written over
        // the head.
        let tail = client
            .read_memory(STACK_BASE + 64 * 1024 - 16, 16)
            .expect("read back tail");
        assert_eq!(tail, vec![0xAAu8; 16], "last chunk landed at the wrong address");
        drop(client);

        let srv = handle.join().expect("server thread");
        let longest = srv
            .packet_log
            .iter()
            .filter(|p| p.starts_with('M'))
            .map(String::len)
            .max()
            .expect("at least one M packet");
        assert!(
            longest <= advertised,
            "longest M packet is {longest} bytes but the stub advertised \
             PacketSize={advertised}"
        );
    }
}
