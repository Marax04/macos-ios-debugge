//! PTT (Program Trace Technology) trace-packet parser.
//!
//! PTT is Intel's predecessor to Intel PT, used in some Atom and Silvermont
//! `SoCs`. It records instruction-retired packets, taken-branch packets, and
//! exception packets.  This module provides a pure-Rust, zero-copy parser for
//! raw PTT streams captured from hardware or simulator output.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// ─── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced while parsing a PTT stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PttError {
    /// Insufficient bytes remain in the buffer.
    Truncated { needed: usize, available: usize },
    /// An unknown packet header was encountered.
    UnknownHeader(u8),
    /// The stream is not synchronised (no PSB seen yet).
    NotSynchronised,
    /// Internal overflow in the packet decoder.
    Overflow,
}

impl std::fmt::Display for PttError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { needed, available } => {
                write!(f, "truncated: need {needed} bytes, have {available}")
            }
            Self::UnknownHeader(h) => write!(f, "unknown packet header 0x{h:02x}"),
            Self::NotSynchronised => write!(f, "not synchronised"),
            Self::Overflow => write!(f, "packet decoder overflow"),
        }
    }
}

impl std::error::Error for PttError {}

// ─── TracePacketKind ──────────────────────────────────────────────────────────

/// All PTT packet types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TracePacketKind {
    /// Packet-Stream Boundary — marks the start of a synchronised stream.
    Psb,
    /// Packet-Stream Boundary End — closes the PSB header block.
    PsbEnd,
    /// Pad byte (0x00).
    Pad,
    /// Taken-branch or not-taken indication.
    Tnt {
        /// Number of valid bits in `bits`.
        count: u8,
        /// Taken-branch bits; bit 0 is the first branch.
        bits: u64,
    },
    /// Target IP — records the destination of an indirect branch.
    Tip {
        /// The full resolved target address.
        ip: u64,
        /// IP compression mode (0–6).
        compression: u8,
    },
    /// FUP (Flow Update Packet) — asynchronous event source IP.
    Fup {
        /// Source instruction pointer.
        ip: u64,
        /// Compression mode.
        compression: u8,
    },
    /// TIP.PGE — enables packet generation.
    TipPge { ip: u64, compression: u8 },
    /// TIP.PGD — disables packet generation.
    TipPgd { ip: u64, compression: u8 },
    /// MODE packet (MODE.Exec, MODE.TSX).
    Mode { leaf: u8, payload: u8 },
    /// Timestamp Counter packet.
    Tsc(u64),
    /// Mini time counter.
    Mtc(u8),
    /// Core:bus ratio packet.
    Cbr(u8),
    /// Virtual-Machine CS base change.
    Vmcs { base: u64 },
    /// Overflow packet — data was lost.
    Overflow,
    /// PTW (PT Write) packet.
    Ptw { payload: u64, ip_filt: bool },
    /// Stop packet.
    Stop,
    /// TSC + MTC alignment correction.
    TmaAlignment { ctc: u16, fc: u16 },
    /// Execution trace info packet.
    ExecInfo { ip: u64 },
    /// Raw unknown extension packet.
    Extension { byte1: u8, payload: Vec<u8> },
}

impl std::fmt::Display for TracePacketKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Psb => write!(f, "PSB"),
            Self::PsbEnd => write!(f, "PSBEND"),
            Self::Pad => write!(f, "PAD"),
            Self::Tnt { count, bits } => write!(f, "TNT({bits:0>width$b})", width = *count as usize),
            Self::Tip { ip, compression } => write!(f, "TIP[{compression}](0x{ip:x})"),
            Self::Fup { ip, compression } => write!(f, "FUP[{compression}](0x{ip:x})"),
            Self::TipPge { ip, .. } => write!(f, "TIP.PGE(0x{ip:x})"),
            Self::TipPgd { ip, .. } => write!(f, "TIP.PGD(0x{ip:x})"),
            Self::Mode { leaf, payload } => write!(f, "MODE({leaf}.{payload})"),
            Self::Tsc(ts) => write!(f, "TSC({ts})"),
            Self::Mtc(v) => write!(f, "MTC({v})"),
            Self::Cbr(r) => write!(f, "CBR({r})"),
            Self::Vmcs { base } => write!(f, "VMCS(0x{base:x})"),
            Self::Overflow => write!(f, "OVF"),
            Self::Ptw { payload, ip_filt } => write!(f, "PTW(0x{payload:x},filt={ip_filt})"),
            Self::Stop => write!(f, "STOP"),
            Self::TmaAlignment { ctc, fc } => write!(f, "TMA(ctc={ctc},fc={fc})"),
            Self::ExecInfo { ip } => write!(f, "EXINFO(0x{ip:x})"),
            Self::Extension { byte1, payload } => {
                write!(f, "EXT(0x{byte1:02x},len={})", payload.len())
            }
        }
    }
}

// ─── TracePacket ─────────────────────────────────────────────────────────────

/// A single decoded PTT trace packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePacket {
    /// Packet kind and payload.
    pub kind: TracePacketKind,
    /// Byte offset in the original stream where this packet starts.
    pub byte_offset: usize,
    /// Raw bytes that constitute this packet.
    pub raw: Vec<u8>,
}

impl TracePacket {
    /// Construct a new trace packet.
    #[must_use]
    pub const fn new(kind: TracePacketKind, byte_offset: usize, raw: Vec<u8>) -> Self {
        Self {
            kind,
            byte_offset,
            raw,
        }
    }

    /// Return the encoded size of this packet in bytes.
    #[must_use]
    pub const fn encoded_size(&self) -> usize {
        self.raw.len()
    }
}

impl std::fmt::Display for TracePacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "@{:08x}: {}", self.byte_offset, self.kind)
    }
}

// ─── InstructionRecord ───────────────────────────────────────────────────────

/// A single reconstructed instruction execution record.
///
/// Produced by the PTT instruction-trace reconstructor after consuming a
/// sequence of TNT/TIP packets together with a disassembly oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionRecord {
    /// Instruction pointer (virtual address).
    pub ip: u64,
    /// Instruction size in bytes (0 = unknown).
    pub size: u8,
    /// Whether this was a taken-branch target (vs sequential execution).
    pub is_branch_target: bool,
    /// Whether an exception was taken at this IP.
    pub exception: bool,
    /// Exception vector (valid only if `exception == true`).
    pub exception_vector: u8,
    /// Timestamp at instruction retirement (nanoseconds, 0 = unavailable).
    pub timestamp_ns: u64,
    /// CPU mode: 0=16-bit real, 1=32-bit protected, 2=64-bit long.
    pub cpu_mode: u8,
}

impl InstructionRecord {
    /// Create a new instruction record at `ip`.
    #[must_use]
    pub const fn new(ip: u64) -> Self {
        Self {
            ip,
            size: 0,
            is_branch_target: false,
            exception: false,
            exception_vector: 0,
            timestamp_ns: 0,
            cpu_mode: 2,
        }
    }

    /// Mark this record as a taken-branch target.
    #[must_use]
    pub const fn with_branch_target(mut self) -> Self {
        self.is_branch_target = true;
        self
    }

    /// Attach a known instruction size.
    #[must_use]
    pub const fn with_size(mut self, size: u8) -> Self {
        self.size = size;
        self
    }

    /// Attach a timestamp.
    #[must_use]
    pub const fn with_timestamp(mut self, ts: u64) -> Self {
        self.timestamp_ns = ts;
        self
    }
}

impl std::fmt::Display for InstructionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IP=0x{:016x} size={} branch={} exc={}",
            self.ip, self.size, self.is_branch_target, self.exception
        )
    }
}

// ─── IpTracker ───────────────────────────────────────────────────────────────

/// Tracks the last seen IP value and applies PTT IP-compression.
#[derive(Debug, Default, Clone)]
struct IpTracker {
    /// Last full 64-bit IP.
    last_ip: u64,
    /// Whether an IP has ever been seen.
    valid: bool,
}

impl IpTracker {
    fn new() -> Self {
        Self::default()
    }

    /// Apply an IP update in compression mode `comp` with payload `bytes`.
    ///
    /// Compression modes:
    /// * 0 – IP suppressed (no bytes, return `last_ip`).
    /// * 1 – 16-bit update (sign-extended from `last_ip`[47:0]).
    /// * 2 – 32-bit update.
    /// * 3 – 48-bit update.
    /// * 4 – Full 64-bit update (8 bytes).
    /// * 5 – 48-bit update, `last_ip` kept.
    /// * 6 – same as 0 but signals IP suppressed.
    fn apply(&mut self, comp: u8, bytes: &[u8]) -> u64 {
        let ip = match comp {
            1 => {
                let low16 = u16::from_le_bytes([
                    bytes.first().copied().unwrap_or(0),
                    bytes.get(1).copied().unwrap_or(0),
                ]);
                // sign-extend from bit 47
                let base = self.last_ip & !0xFFFF;
                base | u64::from(low16)
            }
            2 => {
                let low32 = u32::from_le_bytes([
                    bytes.first().copied().unwrap_or(0),
                    bytes.get(1).copied().unwrap_or(0),
                    bytes.get(2).copied().unwrap_or(0),
                    bytes.get(3).copied().unwrap_or(0),
                ]);
                // sign-extend 32-bit to 64-bit (canonical address)
                i64::from(low32.cast_signed()).cast_unsigned()
            }
            3 => {
                let mut buf = [0u8; 8];
                let n = bytes.len().min(6);
                buf[..n].copy_from_slice(&bytes[..n]);
                let raw = u64::from_le_bytes(buf);
                // sign-extend bit 47
                if raw & (1 << 47) != 0 {
                    raw | 0xFFFF_0000_0000_0000
                } else {
                    raw & 0x0000_FFFF_FFFF_FFFF
                }
            }
            4 => {
                let mut buf = [0u8; 8];
                let n = bytes.len().min(8);
                buf[..n].copy_from_slice(&bytes[..n]);
                u64::from_le_bytes(buf)
            }
            // 0, 5, 6 and all others: return last_ip unchanged
            _ => self.last_ip,
        };
        self.last_ip = ip;
        self.valid = true;
        ip
    }
}

// ─── PttTraceParser ──────────────────────────────────────────────────────────

/// Stateful parser for a raw PTT (Program Trace Technology) stream.
///
/// # Example
/// ```no_run
/// use rustre_trace_coresight::ptt_trace_parser::PttTraceParser;
/// let data = vec![0x02u8, 0x82, 0x02, 0x82]; // TNT + TNT
/// let mut parser = PttTraceParser::new();
/// parser.feed(&data);
/// let packets = parser.decode_all();
/// println!("{} packets", packets.len());
/// ```
pub struct PttTraceParser {
    /// Internal byte buffer.
    buf: Vec<u8>,
    /// Current read position in `buf`.
    pos: usize,
    /// Whether synchronisation has been established.
    pub synchronised: bool,
    /// IP compression state tracker.
    ip_tracker: IpTracker,
    /// Pending TNT bits not yet consumed.
    tnt_queue: VecDeque<bool>,
    /// Last TSC value seen.
    pub last_tsc: u64,
    /// Last MTC value seen.
    pub last_mtc: u8,
    /// CBR ratio.
    pub cbr: u8,
    /// Instruction records produced so far.
    pub records: Vec<InstructionRecord>,
}

impl PttTraceParser {
    /// Create a new parser in unsynchronised state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            synchronised: false,
            ip_tracker: IpTracker::new(),
            tnt_queue: VecDeque::new(),
            last_tsc: 0,
            last_mtc: 0,
            cbr: 0,
            records: Vec::new(),
        }
    }

    /// Feed raw bytes into the parser.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Remaining bytes in buffer.
    const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Peek at the next byte without consuming.
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Consume one byte.
    fn consume(&mut self) -> Option<u8> {
        let b = self.buf.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    /// Consume exactly `n` bytes and return them as a Vec.
    fn consume_bytes(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let slice = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Some(slice)
    }

    /// Attempt to find and lock onto a PSB (Packet-Stream Boundary).
    ///
    /// Returns `true` if synchronisation was established.
    pub fn find_psb(&mut self) -> bool {
        // PSB is 16 bytes: 0x02 0x82 repeated 8 times.
        const PSB_PATTERN: [u8; 16] = [
            0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
            0x02, 0x82,
        ];
        let start = self.pos;
        while self.pos + 16 <= self.buf.len() {
            if self.buf[self.pos..self.pos + 16] == PSB_PATTERN {
                self.pos += 16;
                self.synchronised = true;
                return true;
            }
            self.pos += 1;
        }
        self.pos = start;
        false
    }

    /// Decode the IP payload for a given compression mode.
    fn decode_ip(&mut self, comp: u8) -> Option<u64> {
        let ip_bytes = match comp {
            0 | 6 => vec![],
            1 => self.consume_bytes(2)?,
            2 => self.consume_bytes(4)?,
            3 | 5 => self.consume_bytes(6)?,
            4 => self.consume_bytes(8)?,
            _ => return None,
        };
        Some(self.ip_tracker.apply(comp, &ip_bytes))
    }

    /// Decode the next packet from the buffer.
    ///
    /// Returns `Ok(Some(packet))` on success, `Ok(None)` if the buffer is
    /// exhausted, and `Err(PttError)` on a parse failure.
    ///
    /// # Panics
    /// Does not panic in practice; the unwrap is guarded by `remaining() > 0`.
    ///
    /// # Errors
    /// Returns `Err(PttError::Truncated)` when the buffer ends mid-packet.
    /// Returns `Err(PttError::UnknownHeader)` for unrecognised two-byte headers.
    pub fn next_packet(&mut self) -> Result<Option<TracePacket>, PttError> {
        if self.remaining() == 0 {
            return Ok(None);
        }
        let start = self.pos;
        let b0 = self.peek().unwrap();

        if b0 == 0x00 {
            self.pos += 1;
            return Ok(Some(TracePacket::new(TracePacketKind::Pad, start, vec![0x00])));
        }

        // Short TNT: header byte with stop-bit pattern, not a known two-byte header.
        if b0 & 0x01 != 0
            && !matches!(b0, 0x99 | 0xD9 | 0x02 | 0x82 | 0xA3 | 0xB3 | 0x13 | 0xC3 | 0x43
                | 0x19 | 0x59 | 0xF3 | 0x83 | 0x23 | 0x73 | 0x03 | 0x11 | 0x01
                | 0x0D | 0x1D | 0x31 | 0x51 | 0x71 | 0x91 | 0xB1 | 0xD1 | 0xF1
                | 0x2D | 0x4D | 0x6D | 0x8D | 0xAD | 0xCD | 0xED
                | 0x3D | 0x5D | 0x7D | 0x9D | 0xBD | 0xDD | 0xFD
                | 0x21 | 0x41 | 0x61 | 0x81 | 0xA1 | 0xC1 | 0xE1)
        {
            return Ok(Some(self.decode_short_tnt_packet(b0, start)));
        }

        self.pos += 1; // consume b0
        match b0 {
            0x02 => self.decode_0x02_packet(b0, start),
            b if b & 0x1F == 0x0D => Ok(Some(self.decode_ip_flow_packet(b, start, |ip, c| TracePacketKind::Tip { ip, compression: c })?)),
            b if b & 0x1F == 0x1D => Ok(Some(self.decode_ip_flow_packet(b, start, |ip, c| TracePacketKind::Fup { ip, compression: c })?)),
            b if b & 0x1F == 0x11 => Ok(Some(self.decode_ip_flow_packet(b, start, |ip, c| TracePacketKind::TipPge { ip, compression: c })?)),
            b if b & 0x1F == 0x01 => Ok(Some(self.decode_ip_flow_packet(b, start, |ip, c| TracePacketKind::TipPgd { ip, compression: c })?)),
            0x99 | 0xD9 => self.decode_mode_packet(b0, start),
            0x19 => self.decode_tsc_packet(start),
            0x59 => {
                let v = self.consume().ok_or(PttError::Truncated { needed: 1, available: 0 })?;
                self.last_mtc = v;
                Ok(Some(TracePacket::new(TracePacketKind::Mtc(v), start, vec![0x59, v])))
            }
            0x03 => self.decode_cbr_packet(start),
            0xF3 => Ok(Some(TracePacket::new(TracePacketKind::Overflow, start, vec![0xF3]))),
            0x23 => Ok(Some(TracePacket::new(TracePacketKind::PsbEnd, start, vec![0x23]))),
            0x83 => Ok(Some(TracePacket::new(TracePacketKind::Stop, start, vec![0x83]))),
            0x73 => self.decode_tma_packet(start),
            _ => Ok(Some(TracePacket::new(TracePacketKind::Extension { byte1: b0, payload: vec![] }, start, vec![b0]))),
        }
    }

    fn decode_short_tnt_packet(&mut self, b0: u8, start: usize) -> TracePacket {
        self.pos += 1;
        let (count, bits) = decode_short_tnt(b0);
        for i in 0..count {
            self.tnt_queue.push_back((bits >> i) & 1 == 1);
        }
        TracePacket::new(TracePacketKind::Tnt { count, bits: u64::from(bits) }, start, vec![b0])
    }

    fn decode_0x02_packet(&mut self, _b0: u8, start: usize) -> Result<Option<TracePacket>, PttError> {
        let b1 = self.consume().ok_or(PttError::Truncated { needed: 1, available: 0 })?;
        match b1 {
            0x82 => {
                let rest = self.consume_bytes(14).ok_or_else(|| PttError::Truncated {
                    needed: 14,
                    available: self.remaining(),
                })?;
                let mut raw = vec![0x02, 0x82];
                raw.extend_from_slice(&rest);
                self.synchronised = true;
                Ok(Some(TracePacket::new(TracePacketKind::Psb, start, raw)))
            }
            0x03 => {
                let payload = self.consume_bytes(6).ok_or_else(|| PttError::Truncated {
                    needed: 6,
                    available: self.remaining(),
                })?;
                let mut raw = vec![0x02, 0x03];
                raw.extend_from_slice(&payload);
                let (count, bits) = decode_long_tnt(&payload);
                for i in 0..count {
                    self.tnt_queue.push_back((bits >> i) & 1 == 1);
                }
                Ok(Some(TracePacket::new(TracePacketKind::Tnt { count, bits }, start, raw)))
            }
            _ => Ok(Some(TracePacket::new(
                TracePacketKind::Extension { byte1: b1, payload: vec![] },
                start,
                vec![0x02, b1],
            ))),
        }
    }

    fn decode_ip_flow_packet(
        &mut self,
        b: u8,
        start: usize,
        make_kind: impl Fn(u64, u8) -> TracePacketKind,
    ) -> Result<TracePacket, PttError> {
        let comp = (b >> 5) & 0x07;
        let ip = self.decode_ip(comp).ok_or_else(|| PttError::Truncated {
            needed: 8,
            available: self.remaining(),
        })?;
        let mut raw = vec![b];
        raw.extend_from_slice(&ip_bytes_for_comp(comp, ip));
        Ok(TracePacket::new(make_kind(ip, comp), start, raw))
    }

    fn decode_mode_packet(&mut self, b0: u8, start: usize) -> Result<Option<TracePacket>, PttError> {
        let leaf = u8::from(b0 != 0x99);
        let payload_byte = self.consume().ok_or(PttError::Truncated { needed: 1, available: 0 })?;
        Ok(Some(TracePacket::new(
            TracePacketKind::Mode { leaf, payload: payload_byte },
            start,
            vec![b0, payload_byte],
        )))
    }

    fn decode_tsc_packet(&mut self, start: usize) -> Result<Option<TracePacket>, PttError> {
        let ts_bytes = self.consume_bytes(7).ok_or_else(|| PttError::Truncated {
            needed: 7,
            available: self.remaining(),
        })?;
        let mut buf = [0u8; 8];
        buf[..7].copy_from_slice(&ts_bytes);
        let tsc = u64::from_le_bytes(buf);
        self.last_tsc = tsc;
        let mut raw = vec![0x19];
        raw.extend_from_slice(&ts_bytes);
        Ok(Some(TracePacket::new(TracePacketKind::Tsc(tsc), start, raw)))
    }

    fn decode_cbr_packet(&mut self, start: usize) -> Result<Option<TracePacket>, PttError> {
        let b1 = self.consume().ok_or(PttError::Truncated { needed: 1, available: 0 })?;
        if b1 == 0x03 {
            let cbr = self.consume().ok_or_else(|| PttError::Truncated { needed: 1, available: self.remaining() })?;
            let pad = self.consume().ok_or_else(|| PttError::Truncated { needed: 1, available: self.remaining() })?;
            self.cbr = cbr;
            return Ok(Some(TracePacket::new(TracePacketKind::Cbr(cbr), start, vec![0x03, 0x03, cbr, pad])));
        }
        Ok(Some(TracePacket::new(
            TracePacketKind::Extension { byte1: b1, payload: vec![] },
            start,
            vec![0x03, b1],
        )))
    }

    fn decode_tma_packet(&mut self, start: usize) -> Result<Option<TracePacket>, PttError> {
        if self.remaining() < 4 {
            return Err(PttError::Truncated { needed: 4, available: self.remaining() });
        }
        let ctc_lo = self.consume().unwrap();
        let ctc_hi = self.consume().unwrap();
        let fc_lo = self.consume().unwrap();
        let fc_hi = self.consume().unwrap();
        let ctc = u16::from_le_bytes([ctc_lo, ctc_hi]);
        let fc = u16::from_le_bytes([fc_lo, fc_hi]);
        Ok(Some(TracePacket::new(
            TracePacketKind::TmaAlignment { ctc, fc },
            start,
            vec![0x73, ctc_lo, ctc_hi, fc_lo, fc_hi],
        )))
    }

    /// Decode all packets remaining in the buffer.
    ///
    /// Stops on the first unrecoverable error but returns everything decoded so
    /// far.
    pub fn decode_all(&mut self) -> Vec<TracePacket> {
        let mut out = Vec::new();
        while let Ok(Some(p)) = self.next_packet() {
            out.push(p);
        }
        out
    }

    /// Return whether there is a pending TNT bit.
    #[must_use]
    pub fn has_pending_tnt(&self) -> bool {
        !self.tnt_queue.is_empty()
    }

    /// Pop the next TNT bit (true = taken).
    pub fn pop_tnt(&mut self) -> Option<bool> {
        self.tnt_queue.pop_front()
    }

    /// Return the current byte offset in the input stream.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Reset the parser state (but keep the buffer).
    pub fn reset(&mut self) {
        self.pos = 0;
        self.synchronised = false;
        self.ip_tracker = IpTracker::new();
        self.tnt_queue.clear();
        self.last_tsc = 0;
        self.last_mtc = 0;
        self.cbr = 0;
        self.records.clear();
    }

    /// Compact the internal buffer, discarding already-consumed bytes.
    pub fn compact(&mut self) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }
}

impl Default for PttTraceParser {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Decode a short TNT byte into (count, bits).
const fn decode_short_tnt(b: u8) -> (u8, u8) {
    // Find the position of the highest set bit (= stop-bit position, 0-indexed from LSB).
    // Avoids `leading_zeros() as u8` by using range matching.
    let stop_pos: u8 = match b {
        0x80..=0xFF => 7,
        0x40..=0x7F => 6,
        0x20..=0x3F => 5,
        0x10..=0x1F => 4,
        0x08..=0x0F => 3,
        0x04..=0x07 => 2,
        0x02..=0x03 => 1,
        _ => 0,
    };
    let mask = (1u8 << stop_pos.saturating_sub(1)).wrapping_sub(1);
    let bits = (b >> 1) & mask;
    let count = stop_pos;
    (count, bits)
}

/// Decode a long TNT packet payload (6 bytes) into (count, bits).
fn decode_long_tnt(payload: &[u8]) -> (u8, u64) {
    // The long TNT carries up to 47 bits.
    let mut raw: u64 = 0;
    for (i, &byte) in payload.iter().enumerate().take(6) {
        raw |= u64::from(byte) << (i * 8);
    }
    // Find the stop bit position.
    // leading_zeros of u64 is in range 0..=64, which fits in u8.
    let stop_pos = if raw == 0 {
        0u8
    } else {
        63u8.saturating_sub(u8::try_from(raw.leading_zeros()).unwrap_or(64))
    };
    let count = stop_pos;
    let mask = if stop_pos == 0 {
        0
    } else {
        (1u64 << stop_pos).wrapping_sub(1)
    };
    (count, raw & mask)
}

/// Return the IP bytes for a given compression mode and resolved IP.
fn ip_bytes_for_comp(comp: u8, ip: u64) -> Vec<u8> {
    match comp {
        1 => ip.to_le_bytes()[..2].to_vec(),
        2 => ip.to_le_bytes()[..4].to_vec(),
        3 | 5 => ip.to_le_bytes()[..6].to_vec(),
        4 => ip.to_le_bytes().to_vec(),
        _ => vec![],
    }
}

// ─── exception_entry() ───────────────────────────────────────────────────────

/// Identify whether a given trace packet sequence records an exception entry.
///
/// In Intel PT, exceptions appear as a FUP (source IP) immediately followed
/// by a TIP (handler IP).  This function checks a window of two consecutive
/// packets for that pattern and, if found, returns
/// `(source_ip, handler_ip, exception_vector_hint)`.
///
/// The `vector_hint` is derived from the FUP's mode context if a preceding
/// `MODE.Exec` packet established it; otherwise `0xFF` is returned.
#[must_use]
pub fn exception_entry(window: &[TracePacket]) -> Option<(u64, u64, u8)> {
    if window.len() < 2 {
        return None;
    }
    let fup_ip = match &window[0].kind {
        TracePacketKind::Fup { ip, .. } => *ip,
        _ => return None,
    };
    let tip_ip = match &window[1].kind {
        TracePacketKind::Tip { ip, .. } => *ip,
        _ => return None,
    };
    // Heuristic: look back for a MODE packet to extract vector.
    let vector = window
        .iter()
        .rev()
        .find_map(|p| {
            if let TracePacketKind::Mode { payload, .. } = &p.kind {
                Some(*payload)
            } else {
                None
            }
        })
        .unwrap_or(0xFF);
    Some((fup_ip, tip_ip, vector))
}

// ─── TraceStats ──────────────────────────────────────────────────────────────

/// Summary statistics derived from a decoded PTT stream.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceStats {
    /// Total packets decoded.
    pub total_packets: usize,
    /// Number of TNT packets.
    pub tnt_count: usize,
    /// Number of TIP packets (all variants combined).
    pub tip_count: usize,
    /// Number of FUP packets.
    pub fup_count: usize,
    /// Number of TSC packets.
    pub tsc_count: usize,
    /// Number of OVF packets (data loss events).
    pub overflow_count: usize,
    /// Number of PSB sync frames seen.
    pub psb_count: usize,
}

impl TraceStats {
    /// Accumulate statistics from a slice of decoded packets.
    #[must_use]
    pub fn from_packets(packets: &[TracePacket]) -> Self {
        let mut s = Self { total_packets: packets.len(), ..Self::default() };
        for p in packets {
            match &p.kind {
                TracePacketKind::Tnt { .. } => s.tnt_count += 1,
                TracePacketKind::Tip { .. }
                | TracePacketKind::TipPge { .. }
                | TracePacketKind::TipPgd { .. } => s.tip_count += 1,
                TracePacketKind::Fup { .. } => s.fup_count += 1,
                TracePacketKind::Tsc(_) => s.tsc_count += 1,
                TracePacketKind::Overflow => s.overflow_count += 1,
                TracePacketKind::Psb => s.psb_count += 1,
                _ => {}
            }
        }
        s
    }
}

impl std::fmt::Display for TraceStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TraceStats {{ total={}, tnt={}, tip={}, fup={}, tsc={}, ovf={}, psb={} }}",
            self.total_packets,
            self.tnt_count,
            self.tip_count,
            self.fup_count,
            self.tsc_count,
            self.overflow_count,
            self.psb_count
        )
    }
}

// ─── PttStreamSplitter ───────────────────────────────────────────────────────

/// Splits a multiplexed PTT stream by CPU ID embedded in MTC packets.
///
/// Some capture setups record multiple CPUs into a single stream.  The
/// `PttStreamSplitter` uses the MTC payload to partition packets into
/// per-CPU sub-streams.
pub struct PttStreamSplitter {
    /// Per-CPU packet buckets, keyed by CPU index.
    pub cpu_streams: std::collections::HashMap<u8, Vec<TracePacket>>,
    /// Current CPU (updated on each MTC packet).
    current_cpu: u8,
}

impl PttStreamSplitter {
    /// Create a new splitter starting on CPU 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cpu_streams: std::collections::HashMap::new(),
            current_cpu: 0,
        }
    }

    /// Ingest a slice of packets, routing them to their CPU bucket.
    pub fn ingest(&mut self, packets: &[TracePacket]) {
        for pkt in packets {
            if let TracePacketKind::Mtc(cpu) = pkt.kind {
                self.current_cpu = cpu;
            }
            self.cpu_streams
                .entry(self.current_cpu)
                .or_default()
                .push(pkt.clone());
        }
    }

    /// Return the number of CPUs observed.
    #[must_use]
    pub fn cpu_count(&self) -> usize {
        self.cpu_streams.len()
    }

    /// Return the packet stream for `cpu`.
    #[must_use]
    pub fn stream_for_cpu(&self, cpu: u8) -> Option<&[TracePacket]> {
        self.cpu_streams.get(&cpu).map(Vec::as_slice)
    }
}

impl Default for PttStreamSplitter {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_tnt_decode_not_taken() {
        // 0b0000_0010 => stop bit at position 1, bits = 0b0 => 1 not-taken
        let (count, bits) = decode_short_tnt(0b0000_0010);
        assert_eq!(count, 1);
        assert_eq!(bits, 0);
    }

    #[test]
    fn short_tnt_decode_taken() {
        // 0b0000_0110 => stop bit at position 2, bits = 0b01 => 2 branches: T, N
        let (count, bits) = decode_short_tnt(0b0000_0110);
        assert_eq!(count, 2);
        assert_eq!(bits & 0x3, 0x01);
    }

    #[test]
    fn pad_packet() {
        let mut parser = PttTraceParser::new();
        parser.synchronised = true;
        parser.feed(&[0x00]);
        let pkt = parser.next_packet().unwrap().unwrap();
        assert_eq!(pkt.kind, TracePacketKind::Pad);
        assert_eq!(pkt.byte_offset, 0);
    }

    #[test]
    fn tsc_packet() {
        let mut parser = PttTraceParser::new();
        parser.synchronised = true;
        let mut data = vec![0x19u8];
        data.extend_from_slice(&0x0102030405060708u64.to_le_bytes()[..7]);
        parser.feed(&data);
        let pkt = parser.next_packet().unwrap().unwrap();
        if let TracePacketKind::Tsc(ts) = pkt.kind {
            assert_eq!(ts, 0x0102030405060708u64 & 0x00FF_FFFF_FFFF_FFFF);
        } else {
            panic!("expected TSC packet, got {:?}", pkt.kind);
        }
    }

    #[test]
    fn mtc_packet() {
        let mut parser = PttTraceParser::new();
        parser.synchronised = true;
        parser.feed(&[0x59, 0x07]);
        let pkt = parser.next_packet().unwrap().unwrap();
        assert_eq!(pkt.kind, TracePacketKind::Mtc(0x07));
        assert_eq!(parser.last_mtc, 0x07);
    }

    #[test]
    fn overflow_packet() {
        let mut parser = PttTraceParser::new();
        parser.synchronised = true;
        parser.feed(&[0xF3]);
        let pkt = parser.next_packet().unwrap().unwrap();
        assert_eq!(pkt.kind, TracePacketKind::Overflow);
    }

    #[test]
    fn decode_all_empty() {
        let mut parser = PttTraceParser::new();
        assert!(parser.decode_all().is_empty());
    }

    #[test]
    fn trace_stats_counts() {
        let pkts = vec![
            TracePacket::new(TracePacketKind::Tnt { count: 1, bits: 1 }, 0, vec![]),
            TracePacket::new(TracePacketKind::Tnt { count: 2, bits: 3 }, 1, vec![]),
            TracePacket::new(
                TracePacketKind::Tip { ip: 0x1000, compression: 4 },
                2,
                vec![],
            ),
            TracePacket::new(TracePacketKind::Overflow, 3, vec![]),
        ];
        let stats = TraceStats::from_packets(&pkts);
        assert_eq!(stats.total_packets, 4);
        assert_eq!(stats.tnt_count, 2);
        assert_eq!(stats.tip_count, 1);
        assert_eq!(stats.overflow_count, 1);
    }

    #[test]
    fn exception_entry_detection() {
        let pkts = vec![
            TracePacket::new(
                TracePacketKind::Fup { ip: 0xABCD, compression: 4 },
                0,
                vec![],
            ),
            TracePacket::new(
                TracePacketKind::Tip { ip: 0xFFFF, compression: 4 },
                1,
                vec![],
            ),
        ];
        let result = exception_entry(&pkts);
        assert!(result.is_some());
        let (src, handler, _vec) = result.unwrap();
        assert_eq!(src, 0xABCD);
        assert_eq!(handler, 0xFFFF);
    }

    #[test]
    fn splitter_routes_by_cpu() {
        let pkts = vec![
            TracePacket::new(TracePacketKind::Mtc(0), 0, vec![]),
            TracePacket::new(TracePacketKind::Pad, 1, vec![]),
            TracePacket::new(TracePacketKind::Mtc(1), 2, vec![]),
            TracePacket::new(TracePacketKind::Overflow, 3, vec![]),
        ];
        let mut splitter = PttStreamSplitter::new();
        splitter.ingest(&pkts);
        assert_eq!(splitter.cpu_count(), 2);
        assert_eq!(splitter.stream_for_cpu(0).unwrap().len(), 2);
        assert_eq!(splitter.stream_for_cpu(1).unwrap().len(), 2);
    }
}
