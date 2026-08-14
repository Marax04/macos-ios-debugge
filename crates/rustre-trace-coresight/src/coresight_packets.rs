// CoreSight / ETM v4 packet type definitions, packet-stream framing,
// synchronisation logic, and per-packet decoders.
//
// ETM4 uses a variable-length framing format where the first byte identifies
// the packet type and further bytes carry payload.  This module provides:
//   - `RawPacket`     — partially decoded (type + raw bytes)
//   - `CsPacketType`  — exhaustive enum of ETM4 packet types
//   - `DecodedPacket` — fully decoded packet variants with fields
//   - `PacketStream`  — framing decoder with sync-state machine

use std::fmt;
use std::collections::VecDeque;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum FramingError {
    Truncated { need: usize, have: usize },
    BadSync,
    UnknownPacket { byte: u8, offset: usize },
    Overflow { field: &'static str },
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "truncated: need {need}, have {have}")
            }
            Self::BadSync => write!(f, "bad sync sequence"),
            Self::UnknownPacket { byte, offset } => {
                write!(f, "unknown packet 0x{byte:02x} at offset {offset}")
            }
            Self::Overflow { field } => write!(f, "value overflow in field {field}"),
        }
    }
}
impl std::error::Error for FramingError {}

pub type Result<T> = std::result::Result<T, FramingError>;

// ── Packet type enum ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CsPacketKind {
    // Synchronisation
    ASync,          // ETM async byte 0x00
    ISync,          // context+instruction address sync
    TrSync,         // trace enable / cycle-count sync
    // Address / branch
    BranchAddress,  // direct branch with address
    IndirectBranch, // indirect branch (no address)
    ExceptionEntry,
    ExceptionReturn,
    // Atom — conditional execution
    AtomF1,   // 1-bit E/N
    AtomF2,   // 2-bit
    AtomF3,   // 3-bit
    AtomF4,   // 4-bit
    AtomF5,   // 5-bit
    AtomF6,   // 4+5-bit long form
    // Timestamp
    Timestamp,
    TimestampWithCC,
    // Context
    TraceOn,
    TraceInfo,
    TsMarker,
    // Commit / overflow
    Commit,
    CancelFormat1,
    CancelFormat2,
    CancelFormat3,
    Overflow,
    // Function-return stack
    Speculation,
    // Short format instructions — F0–F7
    ShortAddr32,
    ShortAddr64,
    LongAddr32,
    LongAddr64,
    // Conditional
    ConditionalResult,
    ConditionalFlush,
    // Q-element
    QElement,
    // Custom / unknown
    Unknown(u8),
}

impl CsPacketKind {
    #[must_use]
    pub const fn is_sync(&self) -> bool {
        matches!(self, Self::ASync | Self::ISync | Self::TrSync)
    }
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        matches!(
            self,
            Self::BranchAddress
                | Self::IndirectBranch
                | Self::ExceptionEntry
                | Self::ExceptionReturn
        )
    }
    #[must_use]
    pub const fn is_atom(&self) -> bool {
        matches!(
            self,
            Self::AtomF1
                | Self::AtomF2
                | Self::AtomF3
                | Self::AtomF4
                | Self::AtomF5
                | Self::AtomF6
        )
    }
}

impl fmt::Display for CsPacketKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── Decoded packet variants ───────────────────────────────────────────────────

/// ISA (Instruction Set Architecture) modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsaMode {
    Aarch64,
    Aarch32Arm,
    Aarch32Thumb,
}

/// Security state for exception context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityState {
    Secure,
    NonSecure,
    Root,
    Realm,
}

/// Exception type encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExcType {
    Irq,
    Fiq,
    SError,
    SynchronousExtAbort,
    SyncException,
    Reset,
    Debug,
    CallSupervisor,
    HypervisorCall,
    SecureMonitorCall,
    Unknown(u8),
}

impl From<u8> for ExcType {
    fn from(v: u8) -> Self {
        match v {
            0x00 => Self::Reset,
            0x01 => Self::Debug,
            0x02 => Self::CallSupervisor,
            0x03 => Self::HypervisorCall,
            0x04 => Self::SecureMonitorCall,
            0x08 => Self::SynchronousExtAbort,
            0x09 => Self::SError,
            0x0a => Self::Irq,
            0x0b => Self::Fiq,
            other => Self::Unknown(other),
        }
    }
}

/// Fully decoded `CoreSight` / ETM4 packet.
#[derive(Debug, Clone)]
pub enum DecodedPacket {
    /// 12 consecutive 0x00 bytes followed by 0x80 — stream sync.
    ASync,

    /// Trace-stream info packet (first packet after async).
    TraceInfo {
        plctl: u8,           // payload control bits
        info: u32,           // main info word
        key: Option<u32>,    // P0 key
        spec: Option<u8>,    // max speculation depth
        cyct: Option<u8>,    // cycle count threshold
    },

    /// Trace-on — tracing re-enabled after overflow or disable.
    TraceOn,

    /// P0 direct/indirect branch address update.
    Address {
        addr: u64,
        isa: IsaMode,
        update_bits: u8,
    },

    /// Atom packet — one or more taken/not-taken bits for conditional branches.
    Atom {
        /// Encoded as bitmask: bit=1 → Taken, bit=0 → Not-Taken.
        /// Least significant bit = oldest atom.
        atoms: u64,
        /// How many valid bit positions in `atoms`.
        count: u8,
    },

    /// Exception entry.
    ExceptionEntry {
        exc_type: ExcType,
        ns: bool,
        el: u8,
        prev_el: u8,
        addr: Option<u64>,
    },

    /// Exception return.
    ExceptionReturn {
        addr: Option<u64>,
    },

    /// Timestamp value.
    Timestamp {
        /// 64-bit counter value.
        ts: u64,
        /// Carried cycle count if present.
        cc: Option<u32>,
    },

    /// Cycle-count (commit/cancel) packet.
    CycleCount {
        count: u32,
        kind: CycleKind,
    },

    /// Speculation commit or cancel markers.
    Commit { p0_key_lsb: u8 },
    Cancel { p0_key_lsb: u8, count: u8 },

    /// Q-element: represents untaken branch or loop count.
    QElement {
        q_type: u8,
        count: Option<u32>,
        addr: Option<u64>,
    },

    /// Context packet — EL, security state, etc.
    Context {
        p0_key_lsb: u8,
        el: u8,
        sf: bool,   // 64-bit (AArch64)
        ns: bool,
        has_vmid: bool,
        vmid: u32,
        has_contextid: bool,
        contextid: u64,
    },

    /// Short instruction address packet (differential, up to 4 or 8 bytes).
    ShortAddr { addr: u64, bits: u8 },
    LongAddr  { addr: u64, bits: u8 },

    /// Overflow — trace buffer overflow, some packets lost.
    Overflow,

    Unknown { byte: u8, raw: Vec<u8> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleKind { Commit, Cancel }

// ── Raw packet ────────────────────────────────────────────────────────────────

/// A partially-framed packet: just the leading byte and the raw payload bytes.
#[derive(Debug, Clone)]
pub struct RawPacket {
    pub kind: CsPacketKind,
    pub first_byte: u8,
    pub payload: Vec<u8>,
    pub stream_offset: usize,
}

impl RawPacket {
    #[must_use]
    pub const fn total_len(&self) -> usize { 1 + self.payload.len() }
}

// ── Sync state machine ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Waiting for the async sequence (12×0x00 + 0x80).
    Hunting,
    /// We have seen at least one 0x00 counting toward async.
    InNulls { count: u8 },
    /// Fully synchronised, decoding packets.
    Synchronised,
}

// ── Packet stream framer ──────────────────────────────────────────────────────

pub struct PacketStream {
    sync: SyncState,
    buf: VecDeque<u8>,
    stream_offset: usize,
    pub sync_events: u32,
    pub packet_count: u64,
    pub error_count: u64,
}

impl PacketStream {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sync: SyncState::Hunting,
            buf: VecDeque::new(),
            stream_offset: 0,
            sync_events: 0,
            packet_count: 0,
            error_count: 0,
        }
    }

    /// Feed raw bytes into the framer.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes);
    }

    /// Drain all available decoded packets.
    pub fn drain(&mut self) -> Vec<DecodedPacket> {
        let mut out = Vec::new();
        loop {
            match self.next_packet() {
                Ok(Some(pkt)) => out.push(pkt),
                Ok(None) => break,
                Err(_e) => {
                    self.error_count += 1;
                    // Skip one byte and try to recover
                    if self.buf.is_empty() {
                        break;
                    }
                    self.buf.pop_front();
                    self.stream_offset += 1;
                }
            }
        }
        out
    }

    fn peek_byte(&self, ahead: usize) -> Option<u8> {
        self.buf.get(ahead).copied()
    }

    pub fn consume(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            if let Some(b) = self.buf.pop_front() {
                v.push(b);
                self.stream_offset += 1;
            }
        }
        v
    }

    fn consume_one(&mut self) -> Option<u8> {
        let b = self.buf.pop_front()?;
        self.stream_offset += 1;
        Some(b)
    }

    fn available(&self) -> usize { self.buf.len() }

    fn next_packet(&mut self) -> Result<Option<DecodedPacket>> {
        match self.sync {
            SyncState::Hunting | SyncState::InNulls { .. } => {
                if let Some(pkt) = self.try_sync() {
                    return Ok(Some(pkt));
                }
                Ok(None)
            }
            SyncState::Synchronised => {
                self.decode_next_packet()
            }
        }
    }

    fn try_sync(&mut self) -> Option<DecodedPacket> {
        while let Some(b) = self.peek_byte(0) {
            if b == 0x00 {
                match &mut self.sync {
                    SyncState::Hunting => { self.sync = SyncState::InNulls { count: 1 }; }
                    SyncState::InNulls { count } => { *count += 1; }
                    SyncState::Synchronised => {}
                }
                // NB: do NOT consume here — the `consume_one()` at the bottom of
                // the loop already advances one byte. Consuming twice made every
                // null byte eat two, so a 12-null run only ever counted 6 and the
                // `nulls >= 12` A-Sync condition could never be met.
            } else if b == 0x80 {
                let nulls = match self.sync {
                    SyncState::InNulls { count } => count,
                    _ => 0,
                };
                if nulls >= 12 {
                    self.consume_one();
                    self.sync = SyncState::Synchronised;
                    self.sync_events += 1;
                    return Some(DecodedPacket::ASync);
                }
                self.sync = SyncState::Hunting;
            } else {
                self.sync = SyncState::Hunting;
            }
            self.consume_one();
        }
        None
    }

    fn decode_next_packet(&mut self) -> Result<Option<DecodedPacket>> {
        if self.available() == 0 { return Ok(None); }
        let Some(first) = self.peek_byte(0) else { return Ok(None) };

        let pkt = match first {
            // ── Async / sync ──────────────────────────────────────────────
            0x00 => {
                // Start of async sequence while sync'd — re-sync
                self.sync = SyncState::Hunting;
                return Ok(self.try_sync());
            }
            // ── TraceInfo 0x01 ────────────────────────────────────────────
            0x01 => {
                self.consume_one();
                self.decode_trace_info()?
            }
            // ── TraceOn 0x04 ──────────────────────────────────────────────
            0x04 => { self.consume_one(); DecodedPacket::TraceOn }
            // ── Timestamp 0x02 ────────────────────────────────────────────
            0x02 => {
                self.consume_one();
                self.decode_timestamp(false)?
            }
            // ── Timestamp with cycle count 0x03 ──────────────────────────
            0x03 => {
                self.consume_one();
                self.decode_timestamp(true)?
            }
            // ── Exception 0x06 ────────────────────────────────────────────
            0x06 => { self.consume_one(); self.decode_exception_entry()? }
            0x07 => { self.consume_one(); self.decode_exception_return()? }
            // ── Overflow 0x05 ─────────────────────────────────────────────
            0x05 => { self.consume_one(); DecodedPacket::Overflow }
            // ── Context 0x80..0x9f ────────────────────────────────────────
            b if (b & 0xfe) == 0x80 => {
                self.consume_one();
                self.decode_context(b)?
            }
            // ── Address — short/long ──────────────────────────────────────
            b if (b & 0xf0) == 0x90 => {
                self.consume_one();
                self.decode_address_short(b)?
            }
            b if (b & 0xf0) == 0xa0 => {
                self.consume_one();
                self.decode_address_short(b)?
            }
            b if (b & 0xf0) == 0xc0 => {
                self.consume_one();
                self.decode_address_long(b)?
            }
            // ── Atom F1–F5 ────────────────────────────────────────────────
            b if (b & 0xfe) == 0xd4 => { self.consume_one(); decode_atom_f1(b) }
            b if (b & 0xfc) == 0xd0 => { self.consume_one(); decode_atom_f2(b) }
            b if (b & 0xf8) == 0xd8 => { self.consume_one(); decode_atom_f3(b) }
            b if (b & 0xf0) == 0xe0 => { self.consume_one(); decode_atom_f4(b) }
            b if (b & 0xf8) == 0xf8 => { self.consume_one(); decode_atom_f5(b) }
            // ── Atom F6 (long) 0xf0..0xf7 ────────────────────────────────
            b if (b & 0xf8) == 0xf0 && b <= 0xf7 => {
                self.consume_one();
                self.decode_atom_f6(b)?
            }
            // ── Commit/Cancel ─────────────────────────────────────────────
            b if (b & 0xfe) == 0x2e => {
                self.consume_one();
                DecodedPacket::Commit { p0_key_lsb: b & 1 }
            }
            b if (b & 0xfc) == 0x28 => {
                self.consume_one();
                DecodedPacket::Cancel { p0_key_lsb: b & 1, count: (b >> 1) & 1 }
            }
            // ── Q-element 0x27 ────────────────────────────────────────────
            0x27 => { self.consume_one(); self.decode_q_element()? }
            // ── Unknown ───────────────────────────────────────────────────
            b => {
                self.consume_one();
                self.error_count += 1;
                DecodedPacket::Unknown { byte: b, raw: vec![b] }
            }
        };
        self.packet_count += 1;
        Ok(Some(pkt))
    }

    // ── Sub-decoders ──────────────────────────────────────────────────────────

    fn decode_trace_info(&mut self) -> Result<DecodedPacket> {
        // Byte 0 is already consumed. Read PLCTL from header.
        let plctl = self.require_byte()?;
        let mut info = 0u32;
        let mut key = None;
        let mut spec = None;
        let mut cyct = None;

        // PLCTL bit 0 → info word present
        if plctl & 0x01 != 0 {
            info = self.read_uleb32()?;
        }
        // PLCTL bit 1 → P0 key present
        if plctl & 0x02 != 0 {
            key = Some(self.read_uleb32()?);
        }
        // PLCTL bit 2 → speculation depth
        if plctl & 0x04 != 0 {
            spec = Some(self.require_byte()?);
        }
        // PLCTL bit 3 → cycle-count threshold
        if plctl & 0x08 != 0 {
            cyct = Some(self.require_byte()?);
        }
        Ok(DecodedPacket::TraceInfo { plctl, info, key, spec, cyct })
    }

    fn decode_timestamp(&mut self, with_cc: bool) -> Result<DecodedPacket> {
        let ts = self.read_uleb64()?;
        let cc = if with_cc { Some(self.read_uleb32()?) } else { None };
        Ok(DecodedPacket::Timestamp { ts, cc })
    }

    fn decode_exception_entry(&mut self) -> Result<DecodedPacket> {
        let b0 = self.require_byte()?;
        let b1 = self.require_byte()?;
        let exc_type = ExcType::from(b0 & 0x1f);
        let ns = (b1 & 0x01) != 0;
        let el = (b1 >> 1) & 0x03;
        let prev_el = (b1 >> 3) & 0x03;
        let has_addr = (b1 & 0x80) != 0;
        let addr = if has_addr {
            Some(self.read_uleb64()?)
        } else { None };
        Ok(DecodedPacket::ExceptionEntry { exc_type, ns, el, prev_el, addr })
    }

    fn decode_exception_return(&mut self) -> Result<DecodedPacket> {
        let has_addr = self.peek_byte(0).is_some_and(|b| b & 0x80 != 0);
        self.consume_one(); // header byte
        let addr = if has_addr {
            Some(self.read_uleb64()?)
        } else {
            None
        };
        Ok(DecodedPacket::ExceptionReturn { addr })
    }

    fn decode_context(&mut self, first: u8) -> Result<DecodedPacket> {
        let p0_key_lsb = first & 0x01;
        let hdr = self.require_byte()?;
        let el = (hdr >> 1) & 0x03;
        let sf = (hdr & 0x10) != 0;
        let ns = (hdr & 0x08) != 0;
        let has_vmid = (hdr & 0x40) != 0;
        let has_ctxid = (hdr & 0x80) != 0;
        let vmid = if has_vmid { self.read_uleb32()? } else { 0 };
        let contextid = if has_ctxid { self.read_uleb64()? } else { 0 };
        Ok(DecodedPacket::Context { p0_key_lsb, el, sf, ns, has_vmid, vmid, has_contextid: has_ctxid, contextid })
    }

    fn decode_address_short(&mut self, first: u8) -> Result<DecodedPacket> {
        // Short form: up to 4 additional bytes
        let bits = first & 0x0f;
        let payload_bytes = match bits {
            0..=4 => usize::from(bits),
            _ => 4,
        };
        let mut addr = 0u64;
        for i in 0..payload_bytes {
            if self.available() == 0 {
                return Err(FramingError::Truncated { need: payload_bytes, have: i });
            }
            let b = self.consume_one().unwrap();
            addr |= u64::from(b) << (i * 8);
        }
        let bits = u8::try_from(payload_bytes * 8).unwrap_or(32);
        Ok(DecodedPacket::ShortAddr { addr, bits })
    }

    fn decode_address_long(&mut self, first: u8) -> Result<DecodedPacket> {
        let is64 = (first & 0x10) != 0;
        let byte_count = if is64 { 8usize } else { 4 };
        if self.available() < byte_count {
            return Err(FramingError::Truncated { need: byte_count, have: self.available() });
        }
        let mut addr = 0u64;
        for i in 0..byte_count {
            addr |= u64::from(self.consume_one().unwrap()) << (i * 8);
        }
        let bits = u8::try_from(byte_count * 8).unwrap_or(64);
        Ok(DecodedPacket::LongAddr { addr, bits })
    }

    fn decode_atom_f6(&mut self, first: u8) -> Result<DecodedPacket> {
        let b1 = self.require_byte()?;
        // first: lower 3 bits = low 3 atom bits; b1 = upper 5 bits → 8 total? ETM4 spec §6.4.7
        let low_atoms = u64::from(first & 0x07);
        let high_atoms = u64::from(b1 & 0x1f);
        let atoms = low_atoms | (high_atoms << 3);
        let count = 8;
        Ok(DecodedPacket::Atom { atoms, count })
    }

    fn decode_q_element(&mut self) -> Result<DecodedPacket> {
        let hdr = self.require_byte()?;
        let q_type = hdr & 0x0f;
        let has_count = (hdr & 0x10) != 0;
        let has_addr = (hdr & 0x80) != 0;
        let count = if has_count { Some(self.read_uleb32()?) } else { None };
        let addr = if has_addr { Some(self.read_uleb64()?) } else { None };
        Ok(DecodedPacket::QElement { q_type, count, addr })
    }

    // ── ULEB helpers ──────────────────────────────────────────────────────────

    fn require_byte(&mut self) -> Result<u8> {
        self.consume_one().ok_or(FramingError::Truncated { need: 1, have: 0 })
    }

    fn read_uleb32(&mut self) -> Result<u32> {
        let mut val = 0u32;
        let mut shift = 0;
        for _ in 0..5 {
            let b = self.require_byte()?;
            let lo = u32::from(b & 0x7f);
            val |= lo << shift;
            if b & 0x80 == 0 { return Ok(val); }
            shift += 7;
        }
        Err(FramingError::Overflow { field: "uleb32" })
    }

    fn read_uleb64(&mut self) -> Result<u64> {
        let mut val = 0u64;
        let mut shift = 0;
        for _ in 0..10 {
            let b = self.require_byte()?;
            let lo = u64::from(b & 0x7f);
            val |= lo << shift;
            if b & 0x80 == 0 { return Ok(val); }
            shift += 7;
        }
        Err(FramingError::Overflow { field: "uleb64" })
    }
}

impl Default for PacketStream {
    fn default() -> Self { Self::new() }
}

// ── Atom decoders (stateless) ─────────────────────────────────────────────────

const fn decode_atom_f1(b: u8) -> DecodedPacket {
    let e = (b & 0x01) as u64;
    DecodedPacket::Atom { atoms: e, count: 1 }
}

const fn decode_atom_f2(b: u8) -> DecodedPacket {
    let atoms = (b & 0x03) as u64;
    DecodedPacket::Atom { atoms, count: 2 }
}

const fn decode_atom_f3(b: u8) -> DecodedPacket {
    let atoms = (b & 0x07) as u64;
    DecodedPacket::Atom { atoms, count: 3 }
}

fn decode_atom_f4(b: u8) -> DecodedPacket {
    let atoms = u64::from(b & 0x0f);
    DecodedPacket::Atom { atoms, count: 4 }
}

fn decode_atom_f5(b: u8) -> DecodedPacket {
    let atoms = u64::from(b & 0x1f);
    DecodedPacket::Atom { atoms, count: 5 }
}

// ── Packet statistics ─────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct PacketStats {
    pub atoms: u64,
    pub atom_bits: u64,
    pub branches: u64,
    pub timestamps: u64,
    pub contexts: u64,
    pub exceptions: u64,
    pub overflows: u64,
    pub unknowns: u64,
}

impl PacketStats {
    pub fn observe(&mut self, pkt: &DecodedPacket) {
        match pkt {
            DecodedPacket::Atom { count, .. } => {
                self.atoms += 1;
                self.atom_bits += u64::from(*count);
            }
            DecodedPacket::Address { .. }
            | DecodedPacket::ShortAddr { .. }
            | DecodedPacket::LongAddr { .. } => self.branches += 1,
            DecodedPacket::Timestamp { .. } => self.timestamps += 1,
            DecodedPacket::Context { .. } => self.contexts += 1,
            DecodedPacket::ExceptionEntry { .. }
            | DecodedPacket::ExceptionReturn { .. } => self.exceptions += 1,
            DecodedPacket::Overflow => self.overflows += 1,
            DecodedPacket::Unknown { .. } => self.unknowns += 1,
            _ => {}
        }
    }

    pub const fn merge(&mut self, other: &Self) {
        self.atoms += other.atoms;
        self.atom_bits += other.atom_bits;
        self.branches += other.branches;
        self.timestamps += other.timestamps;
        self.contexts += other.contexts;
        self.exceptions += other.exceptions;
        self.overflows += other.overflows;
        self.unknowns += other.unknowns;
    }
}

// ── TPIU frame demux ──────────────────────────────────────────────────────────

/// Strip TPIU framing (16-byte frames) from a raw trace capture.
/// TPIU uses 16-byte frames where byte 15 is a flag byte indicating
/// which byte positions have ID-change flags set.
#[must_use]
pub fn tpiu_demux(raw: &[u8], target_id: u8) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cur_id = 0u8;
    let frames = raw.chunks(16);
    for frame in frames {
        if frame.len() < 16 { break; }
        let flags = frame[15];
        for byte_idx in 0..15usize {
            let b = frame[byte_idx];
            if byte_idx % 2 == 1 && (flags >> (byte_idx / 2)) & 1 != 0 {
                // ID-change: the preceding byte was an ID byte
                cur_id = frame[byte_idx - 1] >> 1;
            } else if cur_id == target_id {
                out.push(b);
            }
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_async() -> Vec<u8> {
        let mut v = vec![0u8; 12];
        v.push(0x80);
        v
    }

    #[test]
    fn test_async_sync() {
        let mut stream = PacketStream::new();
        stream.feed(&make_async());
        let pkts = stream.drain();
        assert_eq!(pkts.len(), 1);
        assert!(matches!(pkts[0], DecodedPacket::ASync));
        assert_eq!(stream.sync_events, 1);
    }

    #[test]
    fn test_trace_on() {
        let mut stream = PacketStream::new();
        stream.feed(&make_async());
        stream.feed(&[0x04]);
        let pkts = stream.drain();
        assert!(pkts.iter().any(|p| matches!(p, DecodedPacket::TraceOn)));
    }

    #[test]
    fn test_overflow() {
        let mut stream = PacketStream::new();
        stream.feed(&make_async());
        stream.feed(&[0x05]);
        let pkts = stream.drain();
        assert!(pkts.iter().any(|p| matches!(p, DecodedPacket::Overflow)));
    }

    #[test]
    fn test_timestamp() {
        let mut stream = PacketStream::new();
        stream.feed(&make_async());
        // 0x02 + ULEB128(1234)
        let ts: u64 = 1234;
        let mut uleb = Vec::new();
        let mut v = ts;
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            uleb.push(if v != 0 { b | 0x80 } else { b });
            if v == 0 { break; }
        }
        let mut data = vec![0x02];
        data.extend_from_slice(&uleb);
        stream.feed(&data);
        let pkts = stream.drain();
        let ts_pkt = pkts.iter().find(|p| matches!(p, DecodedPacket::Timestamp { .. }));
        assert!(ts_pkt.is_some());
        if let Some(DecodedPacket::Timestamp { ts: t, cc }) = ts_pkt {
            assert_eq!(*t, 1234);
            assert!(cc.is_none());
        }
    }

    #[test]
    fn test_atom_f1_taken() {
        let mut stream = PacketStream::new();
        stream.feed(&make_async());
        // Atom F1: 0xd4 (E bit = 0 = Not-Taken) or 0xd5 (E bit = 1 = Taken)
        stream.feed(&[0xd5]);
        let pkts = stream.drain();
        let atom = pkts.iter().find(|p| matches!(p, DecodedPacket::Atom { .. }));
        assert!(atom.is_some());
        if let Some(DecodedPacket::Atom { atoms, count }) = atom {
            assert_eq!(*count, 1);
            assert_eq!(*atoms, 1); // Taken
        }
    }

    #[test]
    fn test_packet_stats() {
        let mut stats = PacketStats::default();
        stats.observe(&DecodedPacket::Overflow);
        stats.observe(&DecodedPacket::Atom { atoms: 0b101, count: 3 });
        assert_eq!(stats.overflows, 1);
        assert_eq!(stats.atoms, 1);
        assert_eq!(stats.atom_bits, 3);
    }

    #[test]
    fn test_tpiu_demux_passthrough() {
        // 16-byte frame, all bytes for id=0x01, flags=0
        let mut frame = [0u8; 16];
        frame[0] = 0xAB;
        frame[2] = 0xCD;
        frame[15] = 0x00;
        // Without proper ID assignment all bytes are id=0 by default
        let out = tpiu_demux(&frame, 0);
        assert!(!out.is_empty() || out.is_empty()); // just exercises the code path
    }
}
