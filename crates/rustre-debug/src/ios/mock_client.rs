//! A real RSP client, sufficient to drive [`crate::ios::mock_debugserver::MockDebugserver`] end to end.
//!
//! This is the other half of the "testable on Windows" story: the mock is only
//! worth having if something actually *speaks* to it, and a test that drives the
//! mock through a hand-rolled string in each test function proves nothing about
//! a client. So this module implements the client side properly — checksum
//! verification (which `rr_backend.rs` skips), acknowledgement handling,
//! escaping, run-length expansion, reassembly across arbitrary transport
//! fragmentation, and a register map built at *runtime* from `qRegisterInfo`
//! rather than hardcoded offsets.
//!
//! It is transport-generic ([`AppleTransport`]), so the same client code will
//! drive a real `debugserver` over TCP once that transport exists.

use std::collections::HashMap;
use std::io;

use crate::ios::mock_debugserver::{
    Arm64Registers, MockDebugserver, MockError, checksum, decode_hex, encode_packet, hex_encode,
    unescape,
};

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// A byte pipe to a debugserver. Synchronous on purpose: RSP framing is
/// stateful, and an async boundary belongs at the `Debugger` trait, not here.
pub trait AppleTransport: Send {
    /// Write all of `data`.
    fn send(&mut self, data: &[u8]) -> io::Result<()>;
    /// Read up to `buf.len()` bytes; `Ok(0)` means the peer closed.
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

/// In-process transport wrapping a [`crate::ios::mock_debugserver::MockDebugserver`].
///
/// `chunk` deliberately caps how many bytes each `recv` hands back, so the
/// client is forced to reassemble — the single-`read()` bug is unrepresentable
/// in a test that uses this.
#[derive(Debug)]
pub struct LoopbackTransport {
    server: MockDebugserver,
    pending: Vec<u8>,
    /// Maximum bytes returned per `recv` call. `0` means "no limit".
    pub chunk: usize,
    closed: bool,
}

impl LoopbackTransport {
    #[must_use]
    pub const fn new(server: MockDebugserver) -> Self {
        Self { server, pending: Vec::new(), chunk: 0, closed: false }
    }

    /// Force the transport to dribble bytes out `n` at a time.
    #[must_use]
    pub const fn with_chunk(mut self, n: usize) -> Self {
        self.chunk = n;
        self
    }

    #[must_use]
    pub const fn server(&self) -> &MockDebugserver {
        &self.server
    }

    #[must_use]
    pub const fn server_mut(&mut self) -> &mut MockDebugserver {
        &mut self.server
    }

    /// Consume the transport and hand the server back, so a test can inspect
    /// the final simulated process state.
    #[must_use]
    pub fn into_server(self) -> MockDebugserver {
        self.server
    }
}

impl AppleTransport for LoopbackTransport {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        if self.closed {
            // A write to a half-closed socket usually succeeds locally; the
            // peer's disappearance is discovered on the *read*. Reporting it
            // here instead would give the client a misleading error class.
            return Ok(());
        }
        match self.server.feed(data) {
            Ok(reply) => {
                self.pending.extend_from_slice(&reply);
                Ok(())
            }
            Err(MockError::ConnectionClosed) => {
                self.closed = true;
                // Bytes already queued stay readable, exactly as a real socket
                // would deliver what was in flight before the FIN.
                Ok(())
            }
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pending.is_empty() {
            return if self.closed { Ok(0) } else { Ok(0) };
        }
        let mut n = self.pending.len().min(buf.len());
        if self.chunk > 0 {
            n = n.min(self.chunk);
        }
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// Client errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("transport error: {0}")]
    Io(#[from] io::Error),
    #[error("connection closed while awaiting a reply")]
    Closed,
    #[error("bad checksum in server reply: expected {expected:02x}, got {got:02x}")]
    BadChecksum { expected: u8, got: u8 },
    #[error("server returned error {0}")]
    Remote(String),
    #[error("malformed reply: {0}")]
    Malformed(String),
    #[error("unsupported by this server: {0}")]
    Unsupported(String),
    #[error("short read at {addr:#x}: asked for {requested} bytes, got {returned}")]
    ShortRead { addr: u64, requested: usize, returned: usize },
}

// ---------------------------------------------------------------------------
// Stop replies
// ---------------------------------------------------------------------------

/// A parsed `T`/`S`/`W`/`X` stop reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReply {
    /// Thread stopped with `signal`; `values` holds the expedited registers
    /// keyed by their `qRegisterInfo` index, plus named keys such as `reason`.
    Stopped { signal: u8, tid: Option<u32>, keys: HashMap<String, String> },
    /// Process exited normally.
    Exited { code: u8 },
    /// Process terminated by a signal.
    Terminated { signal: u8 },
}

impl StopReply {
    /// Parse a stop-reply payload.
    pub fn parse(payload: &str) -> Result<Self, ClientError> {
        let mut chars = payload.chars();
        let kind = chars
            .next()
            .ok_or_else(|| ClientError::Malformed("empty stop reply".into()))?;
        let rest = &payload[1..];
        let sig_hex: String = rest.chars().take(2).collect();
        // A stop reply always carries exactly two hex digits of signal/exit
        // code. Anything shorter is a truncated payload, not a one-digit
        // signal: accepting it would also make the `rest[2..]` slice below
        // index past the end of the string.
        if sig_hex.len() != 2 {
            return Err(ClientError::Malformed(format!("truncated stop reply: {payload:?}")));
        }
        let sig = u8::from_str_radix(&sig_hex, 16)
            .map_err(|_| ClientError::Malformed(format!("bad signal in {payload:?}")))?;
        match kind {
            'W' => Ok(Self::Exited { code: sig }),
            'X' => Ok(Self::Terminated { signal: sig }),
            'S' => Ok(Self::Stopped { signal: sig, tid: None, keys: HashMap::new() }),
            'T' => {
                // Annotated because the `medata` branch below calls
                // `keys.keys()` before any `insert` has pinned the key type,
                // so inference has nothing to work from at that point.
                let mut keys: HashMap<String, String> = HashMap::new();
                let mut tid = None;
                for field in rest[2..].split(';').filter(|s| !s.is_empty()) {
                    if let Some((k, v)) = field.split_once(':') {
                        if k == "thread" {
                            tid = u32::from_str_radix(v, 16).ok();
                        }
                        // `medata` legitimately repeats; keep them distinguishable.
                        if k == "medata" {
                            let n = keys.keys().filter(|k| k.starts_with("medata")).count();
                            keys.insert(format!("medata{n}"), v.to_string());
                        } else {
                            keys.insert(k.to_string(), v.to_string());
                        }
                    }
                }
                Ok(Self::Stopped { signal: sig, tid, keys })
            }
            _ => Err(ClientError::Malformed(format!("not a stop reply: {payload:?}"))),
        }
    }

    /// `true` when the process is gone.
    #[must_use]
    pub const fn is_exit(&self) -> bool {
        matches!(self, Self::Exited { .. } | Self::Terminated { .. })
    }

    /// Expedited PC, if the server sent one (register index 32 = `0x20`).
    #[must_use]
    pub fn pc(&self) -> Option<u64> {
        match self {
            Self::Stopped { keys, .. } => keys.get("20").and_then(|h| le_hex_to_u64(h)),
            _ => None,
        }
    }
}

fn le_hex_to_u64(hex: &str) -> Option<u64> {
    let bytes = decode_hex(hex)?;
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    buf[..n].copy_from_slice(&bytes[..n]);
    Some(u64::from_le_bytes(buf))
}

// ---------------------------------------------------------------------------
// Register map (built at runtime, never hardcoded)
// ---------------------------------------------------------------------------

/// One register as the *server* described it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRegister {
    pub index: usize,
    pub name: String,
    pub bitsize: u32,
    pub offset: usize,
    pub generic: Option<String>,
}

/// The register layout discovered via `qRegisterInfo`.
#[derive(Debug, Default, Clone)]
pub struct RegisterMap {
    pub regs: Vec<RemoteRegister>,
}

impl RegisterMap {
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&RemoteRegister> {
        self.regs.iter().find(|r| r.name == name)
    }

    /// Look up by the architecture-neutral `generic` tag (`pc`, `sp`, `fp`,
    /// `ra`). This is the whole point of the runtime map: `RegisterSet.fp`/`lr`
    /// can be filled correctly on ARM64 without an `if arch == ...`.
    #[must_use]
    pub fn by_generic(&self, generic: &str) -> Option<&RemoteRegister> {
        self.regs.iter().find(|r| r.generic.as_deref() == Some(generic))
    }

    /// Total byte size implied by the map (the expected `g` payload length).
    #[must_use]
    pub fn g_packet_bytes(&self) -> usize {
        self.regs.iter().map(|r| r.offset + (r.bitsize as usize) / 8).max().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// A synchronous RSP client for Apple's debugserver dialect.
pub struct RspClient<T: AppleTransport> {
    transport: T,
    rx: Vec<u8>,
    no_ack_mode: bool,
    /// Features advertised by `qSupported`.
    pub features: Vec<String>,
    pub register_map: RegisterMap,
}

impl<T: AppleTransport> RspClient<T> {
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            rx: Vec::new(),
            no_ack_mode: false,
            features: Vec::new(),
            register_map: RegisterMap { regs: Vec::new() },
        }
    }

    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn into_transport(self) -> T {
        self.transport
    }

    // -- wire ---------------------------------------------------------------

    /// Send one packet and return the (unescaped, RLE-expanded) reply payload
    /// as raw BYTES. Binary objects (`qXfer` on a non-XML annex, for one) are
    /// not text, so anything that needs a byte count must use this and never
    /// the length of a lossily-decoded `String`.
    pub fn command_bytes(&mut self, payload: &str) -> Result<Vec<u8>, ClientError> {
        self.transport.send(&encode_packet(payload))?;
        self.read_reply_bytes()
    }

    /// Send one packet and return the (unescaped, RLE-expanded) reply payload.
    pub fn command(&mut self, payload: &str) -> Result<String, ClientError> {
        Ok(String::from_utf8_lossy(&self.command_bytes(payload)?).to_string())
    }

    /// Like [`Self::command`] but maps an `Exx` payload to
    /// [`ClientError::Remote`] and an empty payload to
    /// [`ClientError::Unsupported`] — so a caller cannot mistake "unsupported"
    /// for "succeeded with no data", which is a real class of client bug.
    pub fn command_checked(&mut self, payload: &str) -> Result<String, ClientError> {
        let reply = self.command(payload)?;
        if reply.is_empty() {
            return Err(ClientError::Unsupported(payload.to_string()));
        }
        // Two error shapes exist on the wire: `Exx` and `E.errtext`. Only
        // checking the first let a textual rejection through as a payload.
        if reply.len() == 3
            && reply.starts_with('E')
            && reply[1..].chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(ClientError::Remote(reply));
        }
        if reply.starts_with("E.") {
            return Err(ClientError::Remote(reply));
        }
        Ok(reply)
    }

    fn read_reply_bytes(&mut self) -> Result<Vec<u8>, ClientError> {
        loop {
            if let Some(payload) = self.take_packet()? {
                return Ok(payload);
            }
            let mut buf = [0u8; 4096];
            let n = self.transport.recv(&mut buf)?;
            if n == 0 {
                // No new bytes and no complete packet buffered.
                if self.rx.is_empty() {
                    return Err(ClientError::Closed);
                }
                return Err(ClientError::Malformed(format!(
                    "truncated reply: {:?}",
                    String::from_utf8_lossy(&self.rx)
                )));
            }
            self.rx.extend_from_slice(&buf[..n]);
        }
    }

    /// Extract one packet from the receive buffer, consuming acks along the way.
    fn take_packet(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        loop {
            match self.rx.first() {
                None => return Ok(None),
                Some(b'+' | b'-') => {
                    self.rx.remove(0);
                }
                Some(b'$') => break,
                Some(_) => {
                    self.rx.remove(0);
                }
            }
        }
        let Some(hash) = self.rx.iter().position(|&b| b == b'#') else {
            return Ok(None);
        };
        if self.rx.len() < hash + 3 {
            return Ok(None);
        }
        let body = self.rx[1..hash].to_vec();
        let csum_hex = String::from_utf8_lossy(&self.rx[hash + 1..hash + 3]).to_string();
        self.rx.drain(..hash + 3);
        let got = u8::from_str_radix(&csum_hex, 16)
            .map_err(|_| ClientError::Malformed(format!("non-hex checksum {csum_hex:?}")))?;
        let expected = checksum(&body);
        if expected != got {
            // The reason `rr_backend.rs`'s omission matters: without this the
            // corrupted payload would be parsed as if it were fine.
            if !self.no_ack_mode {
                self.transport.send(b"-")?;
            }
            return Err(ClientError::BadChecksum { expected, got });
        }
        if !self.no_ack_mode {
            self.transport.send(b"+")?;
        }
        Ok(Some(unescape(&body)))
    }

    // -- session ------------------------------------------------------------

    /// Full startup: negotiate features, drop acknowledgements, enable thread
    /// suffixes, and build the register map from `qRegisterInfo`.
    pub fn handshake(&mut self) -> Result<(), ClientError> {
        let supported = self.command("qSupported:xmlRegisters=aarch64")?;
        self.features = supported.split(';').map(str::to_string).collect();
        if self.features.iter().any(|f| f == "QStartNoAckMode+") {
            if self.command("QStartNoAckMode")? == "OK" {
                self.no_ack_mode = true;
            }
        }
        if self.features.iter().any(|f| f == "QThreadSuffixSupported+") {
            let _ = self.command("QThreadSuffixSupported")?;
        }
        self.register_map = self.query_register_map()?;
        Ok(())
    }

    /// Enumerate `qRegisterInfo0..` until the server answers `E45`.
    pub fn query_register_map(&mut self) -> Result<RegisterMap, ClientError> {
        let mut regs = Vec::new();
        for idx in 0..1024usize {
            let reply = self.command(&format!("qRegisterInfo{idx:x}"))?;
            if reply.is_empty() || reply.starts_with('E') {
                break;
            }
            let mut name = String::new();
            let mut bitsize = 0u32;
            let mut offset = 0usize;
            let mut generic = None;
            for field in reply.split(';').filter(|s| !s.is_empty()) {
                let Some((k, v)) = field.split_once(':') else { continue };
                match k {
                    "name" => name = v.to_string(),
                    "bitsize" => bitsize = v.parse().unwrap_or(0),
                    "offset" => offset = v.parse().unwrap_or(0),
                    "generic" => generic = Some(v.to_string()),
                    _ => {}
                }
            }
            regs.push(RemoteRegister { index: idx, name, bitsize, offset, generic });
        }
        Ok(RegisterMap { regs })
    }

    /// `qfThreadInfo`/`qsThreadInfo`, fully paginated.
    pub fn threads(&mut self) -> Result<Vec<u32>, ClientError> {
        let mut out = Vec::new();
        let mut reply = self.command("qfThreadInfo")?;
        loop {
            match reply.chars().next() {
                Some('m') => {
                    for id in reply[1..].split(',').filter(|s| !s.is_empty()) {
                        if let Ok(t) = u32::from_str_radix(id, 16) {
                            out.push(t);
                        }
                    }
                    reply = self.command("qsThreadInfo")?;
                }
                Some('l') => {
                    for id in reply[1..].split(',').filter(|s| !s.is_empty()) {
                        if let Ok(t) = u32::from_str_radix(id, 16) {
                            out.push(t);
                        }
                    }
                    return Ok(out);
                }
                _ => return Ok(out),
            }
        }
    }

    /// Read the whole register file for `tid` using the thread suffix.
    pub fn read_registers(&mut self, tid: u32) -> Result<Arm64Registers, ClientError> {
        let reply = self.command_checked(&format!("g;thread:{tid:x};"))?;
        Arm64Registers::decode_g(&reply)
            .ok_or_else(|| ClientError::Malformed(format!("short g packet ({} chars)", reply.len())))
    }

    pub fn write_registers(&mut self, tid: u32, regs: &Arm64Registers) -> Result<(), ClientError> {
        let reply = self.command_checked(&format!("G{};thread:{tid:x};", regs.encode_g()))?;
        expect_ok(&reply)
    }

    /// Read one register by *name*, resolved through the runtime register map.
    ///
    /// The `p` reply must be EXACTLY as wide as `qRegisterInfo` said the
    /// register is. A short reply was never sent in full, and zero-filling its
    /// high bytes hands back a plausible wrong value as success (`pc` =
    /// `0x00000000deadbeef`); a longer one is not the register we asked for.
    /// Both are "unknown", and an unknown may not be degraded to a default.
    pub fn read_register(&mut self, tid: u32, name: &str) -> Result<u64, ClientError> {
        let reg = self
            .register_map
            .by_name(name)
            .or_else(|| self.register_map.by_generic(name))
            .ok_or_else(|| ClientError::Unsupported(format!("register {name}")))?;
        let (idx, bitsize) = (reg.index, reg.bitsize);
        if bitsize == 0 || bitsize % 8 != 0 {
            return Err(ClientError::Malformed(format!(
                "register {name} has an unusable bitsize {bitsize}"
            )));
        }
        if bitsize > 64 {
            return Err(ClientError::Unsupported(format!(
                "register {name} is {bitsize} bits wide and does not fit a u64"
            )));
        }
        let size = bitsize as usize / 8;
        let reply = self.command_checked(&format!("p{idx:x};thread:{tid:x};"))?;
        let bytes = decode_hex(&reply)
            .ok_or_else(|| ClientError::Malformed(format!("bad register value {reply:?}")))?;
        if bytes.len() != size {
            return Err(ClientError::Malformed(format!(
                "p{idx:x} ({name}) returned {} bytes but qRegisterInfo describes {size} ({bitsize} bits)",
                bytes.len()
            )));
        }
        let mut buf = [0u8; 8];
        buf[..size].copy_from_slice(&bytes);
        Ok(u64::from_le_bytes(buf))
    }

    pub fn write_register(&mut self, tid: u32, name: &str, value: u64) -> Result<(), ClientError> {
        let idx = self
            .register_map
            .by_name(name)
            .ok_or_else(|| ClientError::Unsupported(format!("register {name}")))?
            .index;
        let reply = self.command_checked(&format!(
            "P{idx:x}={};thread:{tid:x};",
            hex_encode(&value.to_le_bytes())
        ))?;
        expect_ok(&reply)
    }

    pub fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, ClientError> {
        let reply = self.command_checked(&format!("m{addr:x},{len:x}"))?;
        let bytes = decode_hex(&reply)
            .ok_or_else(|| ClientError::Malformed(format!("bad hex {reply:?}")))?;
        // A shortfall is data loss, not data: `m` may legally answer with fewer
        // bytes for a partially readable range, and handing that back as `Ok`
        // gives the caller a buffer smaller than the object it must hold.
        if bytes.len() != len {
            return Err(ClientError::ShortRead { addr, requested: len, returned: bytes.len() });
        }
        Ok(bytes)
    }

    pub fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), ClientError> {
        let reply = self.command_checked(&format!(
            "M{addr:x},{:x}:{}",
            data.len(),
            hex_encode(data)
        ))?;
        expect_ok(&reply)
    }

    pub fn set_breakpoint(&mut self, addr: u64) -> Result<(), ClientError> {
        expect_ok(&self.command_checked(&format!("Z0,{addr:x},4"))?)
    }

    pub fn remove_breakpoint(&mut self, addr: u64) -> Result<(), ClientError> {
        expect_ok(&self.command_checked(&format!("z0,{addr:x},4"))?)
    }

    pub fn set_watchpoint(&mut self, addr: u64, len: u64, write: bool) -> Result<(), ClientError> {
        let code = if write { 2 } else { 3 };
        expect_ok(&self.command_checked(&format!("Z{code},{addr:x},{len:x}"))?)
    }

    pub fn cont(&mut self) -> Result<StopReply, ClientError> {
        StopReply::parse(&self.command_checked("vCont;c")?)
    }

    pub fn step(&mut self, tid: u32) -> Result<StopReply, ClientError> {
        StopReply::parse(&self.command_checked(&format!("vCont;s:{tid:x}"))?)
    }

    pub fn stop_reason(&mut self) -> Result<StopReply, ClientError> {
        StopReply::parse(&self.command_checked("?")?)
    }

    /// Read a `qXfer` object, reassembling every `m`-chunk until the `l`-chunk.
    ///
    /// Works on BYTES throughout: `off` is a byte offset into the remote
    /// object, and a chunk boundary is free to fall in the middle of a
    /// multi-byte UTF-8 sequence (or the object may not be text at all). A
    /// per-chunk lossy decode would substitute a 3-byte U+FFFD for every byte
    /// it could not decode, so the next request would start PAST data that was
    /// never delivered — and the `l` chunk would still make the result look
    /// complete.
    pub fn read_qxfer_bytes(&mut self, object: &str, annex: &str) -> Result<Vec<u8>, ClientError> {
        let mut out: Vec<u8> = Vec::new();
        let mut off = 0usize;
        loop {
            let reply = self.command_bytes(&format!("qXfer:{object}:read:{annex}:{off:x},200"))?;
            let Some(&first) = reply.first() else {
                return Err(ClientError::Unsupported(format!("qXfer:{object}")));
            };
            let body = &reply[1..];
            out.extend_from_slice(body);
            off += body.len();
            match first {
                b'l' => return Ok(out),
                b'm' => {
                    if body.is_empty() {
                        // An empty `m` chunk advances nothing: continuing would
                        // loop forever asking for the same offset.
                        return Err(ClientError::Malformed(format!(
                            "empty qXfer:{object} `m` chunk at offset {off:#x}"
                        )));
                    }
                }
                _ => {
                    return Err(ClientError::Malformed(format!(
                        "bad qXfer chunk {:?}",
                        String::from_utf8_lossy(&reply)
                    )));
                }
            }
        }
    }

    /// Read a `qXfer` object as text.
    ///
    /// Refuses an object that is not valid UTF-8 rather than handing back
    /// replacement characters: a caller asking for a document must not be given
    /// a silently substituted one.
    pub fn read_qxfer(&mut self, object: &str, annex: &str) -> Result<String, ClientError> {
        let bytes = self.read_qxfer_bytes(object, annex)?;
        String::from_utf8(bytes).map_err(|e| {
            ClientError::Malformed(format!(
                "qXfer:{object}:{annex} is not valid UTF-8 at byte {}",
                e.utf8_error().valid_up_to()
            ))
        })
    }

    /// Walk the ARM64 frame-pointer chain. Returns `(pc, fp)` per frame,
    /// innermost first.
    ///
    /// This is the frame-pointer *fallback* an unwinder uses when neither
    /// compact-unwind nor `eh_frame` covers the PC; keeping it here lets the
    /// mock validate the memory/register plumbing that the real unwinder will
    /// sit on top of.
    pub fn frame_pointer_backtrace(
        &mut self,
        tid: u32,
        max_depth: usize,
    ) -> Result<Vec<(u64, u64)>, ClientError> {
        let regs = self.read_registers(tid)?;
        let mut frames = vec![(regs.pc, regs.fp())];
        let mut fp = regs.fp();
        for _ in 1..max_depth {
            if fp == 0 {
                break;
            }
            let Ok(saved) = self.read_memory(fp, 16) else { break };
            // A stub may legally answer a stack read short. A partial frame is
            // not data: stop the walk rather than slicing past the end or
            // degrading an unknown return address to zero.
            let (Ok(next_bytes), Ok(ret_bytes)) = (
                <[u8; 8]>::try_from(&saved[..saved.len().min(8)]),
                <[u8; 8]>::try_from(&saved[saved.len().min(8)..]),
            ) else {
                break;
            };
            let next_fp = u64::from_le_bytes(next_bytes);
            let ret = u64::from_le_bytes(ret_bytes);
            if ret == 0 {
                break;
            }
            frames.push((ret, next_fp));
            // Termination rule: a non-increasing frame pointer means the chain
            // is corrupt (or we walked into unrelated memory).
            if next_fp <= fp {
                break;
            }
            fp = next_fp;
        }
        Ok(frames)
    }
}

fn expect_ok(reply: &str) -> Result<(), ClientError> {
    if reply == "OK" { Ok(()) } else { Err(ClientError::Remote(reply.to_string())) }
}

// ---------------------------------------------------------------------------
// Tests: client + mock, driven together
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ios::mock_debugserver::{
        Arm64Interp, FaultInjection, LoadedImage, MemoryRegion, MockThread, Perms, escape,
    };

    /// main -> a -> b, where b traps on `brk`. Three real frames.
    fn three_frame_program() -> (u64, Vec<u32>) {
        let base = 0x1_0000_1000u64;
        let code = vec![
            // 0x…1000 main
            Arm64Interp::STP_FP_LR_PRE,
            Arm64Interp::MOV_FP_SP,
            Arm64Interp::bl(0x20 - 8),
            Arm64Interp::LDP_FP_LR_POST,
            Arm64Interp::RET,
            Arm64Interp::NOP,
            Arm64Interp::NOP,
            Arm64Interp::NOP,
            // 0x…1020 a
            Arm64Interp::STP_FP_LR_PRE,
            Arm64Interp::MOV_FP_SP,
            Arm64Interp::bl(0x40 - 0x28),
            Arm64Interp::LDP_FP_LR_POST,
            Arm64Interp::RET,
            Arm64Interp::NOP,
            Arm64Interp::NOP,
            Arm64Interp::NOP,
            // 0x…1040 b — has a real prologue, so it owns a frame of its own;
            // without one the fp chain would legitimately show only 2 frames.
            Arm64Interp::STP_FP_LR_PRE,
            Arm64Interp::MOV_FP_SP,
            Arm64Interp::brk(0x8000),
        ];
        (base, code)
    }

    fn connected() -> RspClient<LoopbackTransport> {
        let (base, code) = three_frame_program();
        let srv = MockDebugserver::with_program(0x1234, base, &code);
        // 7-byte chunks: every reply crosses several `recv` boundaries.
        let mut client = RspClient::new(LoopbackTransport::new(srv).with_chunk(7));
        client.handshake().expect("handshake");
        client
    }

    fn connected_with<F: FnOnce(&mut MockDebugserver)>(f: F) -> RspClient<LoopbackTransport> {
        let (base, code) = three_frame_program();
        let mut srv = MockDebugserver::with_program(0x1234, base, &code);
        f(&mut srv);
        let mut client = RspClient::new(LoopbackTransport::new(srv).with_chunk(7));
        client.handshake().expect("handshake");
        client
    }

    /// A `p` reply shorter than the register's `bitsize` must be an error, not a
    /// zero-extended value: 4 bytes of a 64-bit `pc` would otherwise read back
    /// as a plausible-looking `0x00000000deadbeef`.
    #[test]
    fn short_p_reply_is_refused_not_zero_filled() {
        let mut c = connected_with(|s| s.faults_mut().truncate_p_to_bytes = Some(4));
        let err = c.read_register(1, "pc").unwrap_err();
        match err {
            ClientError::Malformed(ref m) => {
                assert!(m.contains("4 bytes"), "{m}");
                assert!(m.contains("64"), "{m}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    /// A 128-bit `v0` does not fit in a `u64`; silently returning the low half
    /// is worse than refusing.
    #[test]
    fn oversize_p_reply_is_refused_not_halved() {
        let mut c = connected();
        let err = c.read_register(1, "v0").unwrap_err();
        assert!(
            matches!(err, ClientError::Unsupported(ref m) if m.contains("128")),
            "{err:?}"
        );
    }

    #[test]
    fn handshake_negotiates_and_builds_the_register_map() {
        let client = connected();
        assert!(client.features.iter().any(|f| f == "QStartNoAckMode+"));
        assert_eq!(client.register_map.regs.len(), 68);
        // The whole point: pc/sp/fp/lr found by tag, not by hardcoded index.
        assert_eq!(client.register_map.by_generic("pc").unwrap().name, "pc");
        assert_eq!(client.register_map.by_generic("sp").unwrap().name, "sp");
        assert_eq!(client.register_map.by_generic("fp").unwrap().name, "fp");
        assert_eq!(client.register_map.by_generic("ra").unwrap().name, "lr");
        assert_eq!(
            client.register_map.g_packet_bytes(),
            crate::ios::mock_debugserver::G_PACKET_BYTES
        );
    }

    #[test]
    fn registers_read_write_roundtrip_through_the_wire() {
        let mut c = connected();
        let regs = c.read_registers(1).expect("g");
        assert_eq!(regs.pc, 0x1_0000_1000);
        assert_ne!(regs.sp, 0);

        c.write_register(1, "x0", 0xFEED_FACE).expect("P x0");
        assert_eq!(c.read_register(1, "x0").unwrap(), 0xFEED_FACE);

        let mut new_regs = regs.clone();
        new_regs.x[5] = 0x5555;
        c.write_registers(1, &new_regs).expect("G");
        assert_eq!(c.read_registers(1).unwrap().x[5], 0x5555);
        // x0 was overwritten by the full G packet — proves G really applied.
        assert_eq!(c.read_register(1, "x0").unwrap(), 0);
    }

    #[test]
    fn memory_read_write_roundtrip() {
        let mut c = connected();
        let sp = c.read_register(1, "sp").unwrap();
        let scratch = sp - 64;
        c.write_memory(scratch, b"\xde\xad\xbe\xef").expect("M");
        assert_eq!(c.read_memory(scratch, 4).unwrap(), b"\xde\xad\xbe\xef");
        // An unmapped read must surface as a typed remote error.
        let err = c.read_memory(0xDEAD_0000, 4).unwrap_err();
        assert!(matches!(err, ClientError::Remote(ref e) if e == "E09"), "{err:?}");
    }

    #[test]
    fn breakpoint_hit_reported_with_matching_pc() {
        let mut c = connected();
        let bp = 0x1_0000_1040; // entry of `b`
        c.set_breakpoint(bp).expect("Z0");
        let stop = c.cont().expect("continue");
        match &stop {
            StopReply::Stopped { signal, tid, keys } => {
                assert_eq!(*signal, 5, "SIGTRAP");
                assert_eq!(*tid, Some(1));
                assert_eq!(keys.get("reason").map(String::as_str), Some("breakpoint"));
                assert_eq!(keys.get("metype").map(String::as_str), Some("6"));
            }
            other => panic!("expected a stop, got {other:?}"),
        }
        assert_eq!(stop.pc(), Some(bp));
        assert_eq!(c.read_register(1, "pc").unwrap(), bp);
    }

    #[test]
    fn end_to_end_three_frame_backtrace_over_the_wire() {
        let mut c = connected();
        let stop = c.cont().expect("run to brk");
        assert!(!stop.is_exit());
        assert_eq!(stop.pc(), Some(0x1_0000_1048), "stopped on the brk");

        let frames = c.frame_pointer_backtrace(1, 8).expect("backtrace");
        assert_eq!(frames.len(), 3, "main -> a -> b, got {frames:?}");
        assert_eq!(frames[0].0, 0x1_0000_1048, "innermost is the brk");
        assert_eq!(frames[1].0, 0x1_0000_1020 + 12, "return address inside `a`");
        assert_eq!(frames[2].0, 0x1_0000_1000 + 12, "return address inside `main`");
        // Frame pointers must strictly increase towards the stack base.
        assert!(frames[0].1 < frames[1].1, "{frames:?}");
    }

    /// A stub that answers a stack read one byte short must fail the unwind,
    /// not panic and not invent a zero return address.
    #[test]
    fn short_stack_read_stops_the_backtrace_without_panicking() {
        let mut c = connected();
        let stop = c.cont().expect("run to brk");
        assert_eq!(stop.pc(), Some(0x1_0000_1048));
        c.transport_mut().server_mut().short_read_memory();

        let frames = c.frame_pointer_backtrace(1, 4).expect("backtrace must not fail");
        assert_eq!(
            frames.len(),
            1,
            "a short frame read is not data: only the innermost frame is known, got {frames:?}"
        );
        assert_eq!(frames[0].0, 0x1_0000_1048);
    }

    #[test]
    fn single_step_then_continue_to_exit() {
        let (base, _) = three_frame_program();
        // A short program: movz x0,#3 ; ret  (with lr == 0 -> exit 3)
        let srv = MockDebugserver::with_program(9, base, &[Arm64Interp::movz(0, 3), Arm64Interp::RET]);
        let mut c = RspClient::new(LoopbackTransport::new(srv));
        c.handshake().unwrap();

        let stop = c.step(1).expect("step");
        assert_eq!(stop.pc(), Some(base + 4));
        match stop {
            StopReply::Stopped { keys, .. } => {
                assert_eq!(keys.get("reason").map(String::as_str), Some("trace"));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(c.cont().unwrap(), StopReply::Exited { code: 3 });
    }

    #[test]
    fn thread_enumeration_and_per_thread_registers() {
        let (base, code) = three_frame_program();
        let mut srv = MockDebugserver::with_program(1, base, &code);
        let mut t2 = MockThread::new(0x2a, "worker");
        t2.regs.pc = 0xCAFE_0000;
        srv.add_thread(t2);
        let mut c = RspClient::new(LoopbackTransport::new(srv).with_chunk(3));
        c.handshake().unwrap();

        assert_eq!(c.threads().unwrap(), vec![1, 0x2a]);
        assert_eq!(c.read_registers(1).unwrap().pc, base);
        assert_eq!(c.read_registers(0x2a).unwrap().pc, 0xCAFE_0000);
        // Reading thread 2 must not have disturbed thread 1.
        assert_eq!(c.read_registers(1).unwrap().pc, base);
    }

    #[test]
    fn qxfer_target_xml_is_reassembled_across_chunks() {
        let mut c = connected();
        let xml = c.read_qxfer("features", "target.xml").expect("target.xml");
        assert!(xml.starts_with("<?xml"), "{}", &xml[..40.min(xml.len())]);
        assert!(xml.contains("aarch64"));
        assert!(xml.contains("name=\"pc\""));
        assert!(xml.ends_with("</target>"), "must reach the final chunk");
    }

    #[test]
    fn qxfer_libraries_lists_the_loaded_image() {
        let (base, code) = three_frame_program();
        let mut srv = MockDebugserver::with_program(1, base, &code);
        srv.add_image(LoadedImage {
            path: "/usr/lib/libextra.dylib".into(),
            load_address: 0x2_0000_0000,
            slide: 0x8000,
            uuid: [0x22; 16],
        });
        let mut c = RspClient::new(LoopbackTransport::new(srv).with_chunk(11));
        c.handshake().unwrap();
        let libs = c.read_qxfer("libraries", "").expect("libraries");
        assert!(libs.contains("libextra.dylib"), "{libs}");
        let json = c.command("jGetLoadedDynamicLibrariesInfos:{}").unwrap();
        assert!(json.contains("\"slide\":32768"), "{json}");
    }

    #[test]
    fn rle_compressed_replies_are_expanded_by_the_client() {
        let (base, code) = three_frame_program();
        let mut srv = MockDebugserver::with_program(1, base, &code);
        srv.set_faults(FaultInjection { use_rle: true, ..FaultInjection::default() });
        let mut c = RspClient::new(LoopbackTransport::new(srv).with_chunk(5));
        c.handshake().unwrap();
        // The `g` packet is mostly zeros, so RLE definitely kicked in; the
        // decoded register file must still be exact.
        let regs = c.read_registers(1).expect("g under RLE");
        assert_eq!(regs.pc, base);
        assert_eq!(regs.x[29], 0);
    }

    #[test]
    fn corrupted_checksum_is_detected_not_swallowed() {
        let (base, code) = three_frame_program();
        let mut srv = MockDebugserver::with_program(1, base, &code);
        srv.faults_mut().corrupt_checksum = true;
        let mut c = RspClient::new(LoopbackTransport::new(srv));
        let err = c.command("qC").unwrap_err();
        assert!(matches!(err, ClientError::BadChecksum { .. }), "{err:?}");
    }

    #[test]
    fn truncated_reply_is_an_error_not_a_short_read() {
        let (base, code) = three_frame_program();
        let mut srv = MockDebugserver::with_program(1, base, &code);
        srv.faults_mut().drop_bytes = 3;
        let mut c = RspClient::new(LoopbackTransport::new(srv));
        let err = c.command("qHostInfo").unwrap_err();
        assert!(
            matches!(err, ClientError::Malformed(_) | ClientError::Closed),
            "{err:?}"
        );
    }

    #[test]
    fn connection_close_mid_session_surfaces() {
        let (base, code) = three_frame_program();
        let mut srv = MockDebugserver::with_program(1, base, &code);
        srv.faults_mut().close_after_n = Some(1);
        let mut c = RspClient::new(LoopbackTransport::new(srv));
        assert!(c.command("qC").is_ok(), "first packet still answered");
        let err = c.command("qC").unwrap_err();
        assert!(matches!(err, ClientError::Closed), "{err:?}");
    }

    #[test]
    fn watchpoint_registration_is_accepted() {
        let mut c = connected();
        c.set_watchpoint(0x1_6f00_0000, 8, true).expect("Z2");
        let srv = c.into_transport().into_server();
        assert_eq!(srv.breakpoints().len(), 1);
        assert!(srv.breakpoints()[0].kind.is_watchpoint());
    }

    #[test]
    fn unsupported_packet_is_distinguished_from_success() {
        let mut c = connected();
        assert_eq!(c.command("qNoSuchThing").unwrap(), "");
        let err = c.command_checked("qNoSuchThing").unwrap_err();
        assert!(matches!(err, ClientError::Unsupported(_)), "{err:?}");
    }

    #[test]
    fn client_written_memory_is_visible_to_the_interpreter() {
        // Patch a `brk` over the second instruction of `main` and continue: the
        // stop must be a BRK, proving the client's write reached executable
        // memory the interpreter actually fetches from.
        let mut c = connected();
        let addr = 0x1_0000_1000 + 4;
        c.write_memory(addr, &Arm64Interp::brk(1).to_le_bytes()).expect("patch");
        let stop = c.cont().expect("continue");
        assert_eq!(stop.pc(), Some(addr));
        match stop {
            StopReply::Stopped { keys, .. } => {
                assert_eq!(keys.get("reason").map(String::as_str), Some("breakpoint"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn memory_region_info_matches_the_mapped_layout() {
        let mut c = connected();
        let text = c.command_checked("qMemoryRegionInfo:100001000").unwrap();
        assert!(text.contains("permissions:rx"), "{text}");
        let unmapped = c.command("qMemoryRegionInfo:dead0000").unwrap();
        assert!(unmapped.starts_with("error:"), "{unmapped}");
    }

    #[test]
    fn stop_reply_parser_handles_every_shape() {
        assert_eq!(StopReply::parse("W00").unwrap(), StopReply::Exited { code: 0 });
        assert_eq!(StopReply::parse("X0b").unwrap(), StopReply::Terminated { signal: 11 });
        let s = StopReply::parse("T05thread:1;reason:breakpoint;medata:1;medata:2;").unwrap();
        match s {
            StopReply::Stopped { signal, tid, keys } => {
                assert_eq!(signal, 5);
                assert_eq!(tid, Some(1));
                assert_eq!(keys.get("medata0").map(String::as_str), Some("1"));
                assert_eq!(keys.get("medata1").map(String::as_str), Some("2"));
            }
            other => panic!("{other:?}"),
        }
        assert!(StopReply::parse("").is_err());
        assert!(StopReply::parse("Zzz").is_err());
        // A truncated payload carries fewer than the two mandatory hex digits
        // of signal/exit code. Every kind must surface that as an error: `T`
        // used to index `rest[2..]` and panic, while `W`/`X`/`S` used to
        // silently accept the single digit as a whole signal.
        assert!(matches!(StopReply::parse("W"), Err(ClientError::Malformed(_))));
        assert!(matches!(StopReply::parse("W5"), Err(ClientError::Malformed(_))));
        assert!(matches!(StopReply::parse("X5"), Err(ClientError::Malformed(_))));
        assert!(matches!(StopReply::parse("S5"), Err(ClientError::Malformed(_))));
        assert!(matches!(StopReply::parse("T5"), Err(ClientError::Malformed(_))));
    }

    #[test]
    fn stop_reply_truncated_t_is_malformed_not_a_panic() {
        assert!(matches!(StopReply::parse("T5"), Err(ClientError::Malformed(_))));
    }

    #[test]
    fn short_memory_read_is_an_error_not_data() {
        let (base, code) = three_frame_program();
        let mut srv = MockDebugserver::with_program(0x1234, base, &code);
        srv.short_read_memory();
        let mut c = RspClient::new(LoopbackTransport::new(srv));
        c.handshake().expect("handshake");
        let sp = c.read_register(1, "sp").unwrap();
        let err = c.read_memory(sp - 64, 16).unwrap_err();
        assert!(
            matches!(err, ClientError::ShortRead { requested: 16, returned: 15, .. }),
            "a 15-of-16 `m` reply must be an error, not data: {err:?}"
        );
    }

    #[test]
    fn extra_mapped_region_is_reachable_from_the_client() {
        let (base, code) = three_frame_program();
        let mut srv = MockDebugserver::with_program(1, base, &code);
        assert!(srv.memory.map(MemoryRegion::new(
            0x5_0000_0000,
            b"apple".to_vec(),
            Perms::rw(),
            "__DATA",
        )));
        let mut c = RspClient::new(LoopbackTransport::new(srv));
        c.handshake().unwrap();
        assert_eq!(c.read_memory(0x5_0000_0000, 5).unwrap(), b"apple");
    }

    /// A `qXfer` object served in chunks whose boundaries fall in the middle of
    /// a multi-byte UTF-8 sequence. Each individual chunk is therefore NOT
    /// valid UTF-8, even though the whole object is.
    struct SplitXferTransport {
        data: Vec<u8>,
        chunk: usize,
        pending: Vec<u8>,
    }

    impl SplitXferTransport {
        fn new(data: Vec<u8>, chunk: usize) -> Self {
            Self { data, chunk, pending: Vec::new() }
        }
    }

    impl AppleTransport for SplitXferTransport {
        fn send(&mut self, data: &[u8]) -> io::Result<()> {
            let text = String::from_utf8_lossy(data).to_string();
            let Some(start) = text.find('$') else { return Ok(()) };
            let Some(end) = text.find('#') else { return Ok(()) };
            let req = &text[start + 1..end];
            let Some(rest) = req.strip_prefix("qXfer:blob:read::") else {
                // Anything else is answered as unsupported.
                self.pending.extend_from_slice(b"+$#00");
                return Ok(());
            };
            let off = usize::from_str_radix(rest.split(',').next().unwrap_or("0"), 16).unwrap_or(0);
            let off = off.min(self.data.len());
            let take = self.chunk.min(self.data.len() - off);
            let mut body = Vec::new();
            body.push(if off + take == self.data.len() { b'l' } else { b'm' });
            body.extend_from_slice(&self.data[off..off + take]);
            let escaped = escape(&body);
            self.pending.push(b'+');
            self.pending.push(b'$');
            self.pending.extend_from_slice(&escaped);
            self.pending.push(b'#');
            // The checksum covers the ESCAPED wire bytes, which is what the
            // client sees and sums.
            self.pending
                .extend_from_slice(format!("{:02x}", checksum(&escaped)).as_bytes());
            Ok(())
        }

        fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            Ok(n)
        }
    }

    /// `off` is a byte offset into the remote object, so it must advance by the
    /// number of BYTES received — not by the length of a lossily-decoded
    /// string, which substitutes 3-byte U+FFFD for every invalid byte and so
    /// makes the next request start past data that was never delivered.
    #[test]
    fn qxfer_chunk_split_inside_a_utf8_sequence_is_reassembled_exactly() {
        let want: String = "é".repeat(100); // 200 bytes, 2 bytes per char
        let data = want.as_bytes().to_vec();
        // 63 is odd, so every chunk boundary lands mid-character.
        let mut c = RspClient::new(SplitXferTransport::new(data.clone(), 63));
        assert_eq!(c.read_qxfer_bytes("blob", "").expect("blob bytes"), data);
        assert_eq!(c.read_qxfer("blob", "").expect("blob"), want);
    }

    /// A binary object must come back byte-exact, and the text accessor must
    /// REFUSE it instead of returning U+FFFD in place of the bytes it dropped.
    #[test]
    fn non_utf8_qxfer_object_is_exact_in_bytes_and_refused_as_text() {
        let data: Vec<u8> = (0u16..300).map(|i| (i % 256) as u8).collect();
        let mut c = RspClient::new(SplitXferTransport::new(data.clone(), 37));
        assert_eq!(c.read_qxfer_bytes("blob", "").expect("blob bytes"), data);
        match c.read_qxfer("blob", "") {
            Err(ClientError::Malformed(m)) => assert!(m.contains("not valid UTF-8"), "{m}"),
            other => panic!("a non-UTF-8 object must not decode: {other:?}"),
        }
    }
}
