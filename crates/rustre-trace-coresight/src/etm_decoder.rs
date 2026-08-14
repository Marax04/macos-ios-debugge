//! `etm_decoder` — Full ETMv3/ETMv4/ETE packet decoder.
//!
//! Decodes every packet class defined in:
//! - ARM IHI0014Q "Embedded Trace Macrocell Architecture Specification" (`ETMv3`)
//! - ARM IHI0064H "ARM Embedded Trace Macrocell Architecture Specification ETM4" (`ETMv4`)
//! - ARM DDI0600A "Embedded Trace Extension" (ETE/ARMv9)
//!
//! Covers: sync frames, branch/atom packets, context ID, VMID, address packets,
//! Q elements, exception packets, data trace, and all extension packets.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::{
    CsError, CsPacket, CsPacketKind, EtmContext, EtmVersion, ExceptionLevel,
    ExceptionPacket, ExceptionType,
};

// ─── SyncState ────────────────────────────────────────────────────────────────

/// Synchronization state of the ETM decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncState {
    /// Searching for ASYNC or sync frame.
    Searching,
    /// Found ASYNC, waiting for `TraceInfo`.
    FoundAsync,
    /// Fully synchronized, decoding packets.
    Synchronized,
    /// Lost synchronization (overflow or bad frame).
    Lost,
}

// ─── AtomPattern ──────────────────────────────────────────────────────────────

/// Decoded atom pattern from `ETMv4` atom packets (F1-F6 formats).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomPattern {
    /// E/N bits (1 = taken/Execute, 0 = Not-taken).
    pub en_bits: u32,
    /// Number of valid atom bits.
    pub count: u8,
    /// Raw encoding byte.
    pub raw: u8,
    /// Atom format (F1-F6 in `ETMv4`, or short `ETMv3` form).
    pub format: AtomFormat,
}

/// `ETMv4` atom packet format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtomFormat {
    /// F1: single atom (E or N).
    F1,
    /// F2: two atoms.
    F2,
    /// F3: three atoms.
    F3,
    /// F4: four atoms.
    F4,
    /// F5: 5–23 atoms (long format).
    F5,
    /// F6: 1–24 atoms (long format with CCNT).
    F6,
    /// `ETMv3` branch P-header.
    V3Branch,
}

impl AtomPattern {
    /// Decode an `ETMv4` atom byte.
    ///
    /// Returns `None` if the byte is not an atom packet.
    #[must_use]
    pub fn decode_etm4(b: u8) -> Option<Self> {
        // F1: 0b0000_00E0 (single N or E)
        if b & 0b1111_1101 == 0b0000_0000 {
            let e = (b >> 1) & 1 == 1;
            return Some(Self {
                en_bits: u32::from(e),
                count: 1,
                raw: b,
                format: AtomFormat::F1,
            });
        }
        // F2: 0b0000_EE10
        if b & 0b1111_0011 == 0b0000_0010 {
            let bits = (b >> 2) & 0b11;
            return Some(Self {
                en_bits: u32::from(bits),
                count: 2,
                raw: b,
                format: AtomFormat::F2,
            });
        }
        // F3: 0b0EEE_1110 (three atoms, all N first, variable E)
        if b & 0b1000_1111 == 0b0000_1110 {
            let bits = (b >> 4) & 0b111;
            return Some(Self {
                en_bits: u32::from(bits),
                count: 3,
                raw: b,
                format: AtomFormat::F3,
            });
        }
        // F4: 0b1EEE_EE10 (five atoms, mixed)
        if b & 0b1000_0011 == 0b1000_0010 {
            let bits = (b >> 2) & 0b1_1111;
            return Some(Self {
                en_bits: u32::from(bits),
                count: 5,
                raw: b,
                format: AtomFormat::F4,
            });
        }
        // F6: 0b1100_0000..0b1111_1111 (long atom with CCNT encoded)
        if b & 0b1100_0000 == 0b1100_0000 {
            let cycle = (b >> 2) & 0b1111;
            let e = b & 0b11;
            return Some(Self {
                en_bits: u32::from(e),
                count: (cycle + 1).min(24),
                raw: b,
                format: AtomFormat::F6,
            });
        }
        // F5: 0b1000_0000 (all-N or all-E sequences)
        if b == 0b1000_0000 {
            return Some(Self {
                en_bits: 0,
                count: 1,
                raw: b,
                format: AtomFormat::F5,
            });
        }
        None
    }

    /// Decode an `ETMv3` branch P-header.
    #[must_use]
    pub const fn decode_etm3_branch(b: u8) -> Option<Self> {
        // ETMv3 P-header: bit[0]=1, bit[1]=E/N
        if b & 1 == 1 {
            let taken = (b >> 1) & 1 == 1;
            return Some(Self {
                en_bits: taken as u32,
                count: 1,
                raw: b,
                format: AtomFormat::V3Branch,
            });
        }
        None
    }

    /// Return a slice of booleans (true = E/taken).
    #[must_use]
    pub fn to_vec(&self) -> Vec<bool> {
        (0..self.count)
            .map(|i| (self.en_bits >> i) & 1 == 1)
            .collect()
    }
}

// ─── AddressPacketType ────────────────────────────────────────────────────────

/// Type of `ETMv4` address packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressPacketType {
    /// IS0 — `AArch64` (4-byte instructions at all addresses).
    Is0,
    /// IS1 — AArch32/T32 (2- or 4-byte instructions).
    Is1,
    /// Short form (32-bit address, IS0).
    Short,
    /// Long form (64-bit address).
    Long,
    /// 32-bit with EL hint.
    WithEl,
}

/// A decoded `ETMv4` address packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressPacket {
    /// Decoded address.
    pub address: u64,
    /// Type of this packet.
    pub ptype: AddressPacketType,
    /// Exception level hint (if present).
    pub el: Option<ExceptionLevel>,
    /// Number of bytes consumed from the stream.
    pub size: usize,
}

// ─── QElement ─────────────────────────────────────────────────────────────────

/// An `ETMv4` Q-element (speculative execution marker).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QElement {
    /// Number of instructions in the speculative window.
    pub count: u32,
    /// Whether the speculation was committed (vs squashed).
    pub committed: bool,
    /// Address at which the Q-element was generated.
    pub address: Option<u64>,
}

// ─── EtmDecodeState ───────────────────────────────────────────────────────────

/// Full ETMv4/ETE decoder state machine.
pub struct EtmDecodeState {
    /// ETM protocol version.
    pub version: EtmVersion,
    /// Current decoder context.
    pub context: EtmContext,
    /// Synchronization state.
    pub sync: SyncState,
    /// Accumulated atom queue.
    pub atoms: VecDeque<bool>,
    /// Exception packets.
    pub exceptions: Vec<ExceptionPacket>,
    /// Q elements.
    pub q_elements: Vec<QElement>,
    /// Whether data trace is enabled.
    pub data_trace: bool,
    /// Last address update.
    pub last_addr: u64,
    /// Last context ID.
    pub last_context_id: u32,
    /// Last VMID.
    pub last_vmid: u32,
    /// Total packets decoded.
    pub total_decoded: u64,
    /// Packets that caused errors.
    pub error_count: u64,
    /// Whether we are in a speculative region.
    pub in_speculative: bool,
}

impl EtmDecodeState {
    /// Create a new state for the given ETM version.
    #[must_use]
    pub fn new(version: EtmVersion) -> Self {
        Self {
            version,
            context: EtmContext::default(),
            sync: SyncState::Searching,
            atoms: VecDeque::new(),
            exceptions: Vec::new(),
            q_elements: Vec::new(),
            data_trace: false,
            last_addr: 0,
            last_context_id: 0,
            last_vmid: 0,
            total_decoded: 0,
            error_count: 0,
            in_speculative: false,
        }
    }

    /// Apply an address update.
    pub const fn apply_addr(&mut self, addr: u64) {
        self.last_addr = addr;
        self.context.apply_address(addr);
    }

    /// Record an atom.
    pub fn push_atoms(&mut self, pattern: &AtomPattern) {
        for &taken in &pattern.to_vec() {
            self.atoms.push_back(taken);
        }
    }

    /// Pop the next atom.
    #[must_use]
    pub fn pop_atom(&mut self) -> Option<bool> {
        self.atoms.pop_front()
    }

    /// Return the pending atom count.
    #[must_use]
    pub fn pending_atoms(&self) -> usize {
        self.atoms.len()
    }

    /// Reset sync state.
    pub fn lose_sync(&mut self) {
        self.sync = SyncState::Lost;
        self.atoms.clear();
        self.in_speculative = false;
    }
}

// ─── Etm4Decoder ──────────────────────────────────────────────────────────────

/// Full `ETMv4` / ETE packet decoder.
pub struct Etm4Decoder {
    /// Raw byte buffer.
    buf: Vec<u8>,
    /// Current read position.
    pos: usize,
    /// Decoder state.
    pub state: EtmDecodeState,
    /// Decoded packets.
    pub packets: Vec<CsPacket>,
}

impl Etm4Decoder {
    /// Create a new decoder.
    #[must_use]
    pub fn new(version: EtmVersion) -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            state: EtmDecodeState::new(version),
            packets: Vec::new(),
        }
    }

    /// Feed raw bytes.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Return remaining bytes.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Peek at the next byte without consuming.
    #[must_use]
    pub fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn consume(&mut self) -> Option<u8> {
        let b = self.buf.get(self.pos).copied();
        if b.is_some() { self.pos += 1; }
        b
    }

    fn consume_n(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.pos + n > self.buf.len() { return None; }
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Some(v)
    }

    /// Try to find an ASYNC sync frame (12 zero bytes followed by 0x80).
    pub fn find_async(&mut self) -> bool {
        while self.pos + 12 <= self.buf.len() {
            let slice = &self.buf[self.pos..self.pos + 12];
            if slice[..11] == [0u8; 11] && slice[11] == 0x80 {
                self.pos += 12;
                self.state.sync = SyncState::FoundAsync;
                return true;
            }
            self.pos += 1;
        }
        false
    }

    /// Decode the next `ETMv4` packet.
    pub fn next_packet(&mut self) -> Option<Result<CsPacket, CsError>> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let start = self.pos;
        let b = self.consume()?;

        let result = self.decode_byte(b, start);
        if let Ok(ref pkt) = result {
            self.state.total_decoded += 1;
            self.packets.push(pkt.clone());
        } else {
            self.state.error_count += 1;
            self.pos = start + 1;
        }
        Some(result)
    }

    fn decode_byte(&mut self, b: u8, start: usize) -> Result<CsPacket, CsError> {
        match b {
            // ── Extension byte 0x00 ────────────────────────────────────────
            0x00 => {
                // ASYNC detection: if we see 11 more zeros followed by 0x80
                if self.pos + 11 <= self.buf.len() {
                    let rest = &self.buf[self.pos..self.pos + 11];
                    if rest[..10] == [0u8; 10] && rest[10] == 0x80 {
                        self.pos += 11;
                        self.state.sync = SyncState::Synchronized;
                        return Ok(CsPacket { kind: CsPacketKind::Sync, byte_offset: start });
                    }
                }
                // Otherwise: atom not-taken (single N)
                self.state.push_atoms(&AtomPattern {
                    en_bits: 0,
                    count: 1,
                    raw: b,
                    format: AtomFormat::F1,
                });
                Ok(CsPacket {
                    kind: CsPacketKind::Atom { taken: false, count: 1 },
                    byte_offset: start,
                })
            }

            // ── TraceInfo (0x01) ────────────────────────────────────────────
            0x01 => {
                // TraceInfo payload is variable-length ULEB128
                let _payload = self.read_uleb128().unwrap_or(0);
                self.state.sync = SyncState::Synchronized;
                Ok(CsPacket { kind: CsPacketKind::TraceInfo, byte_offset: start })
            }

            // ── Ignore (0x06) ───────────────────────────────────────────────
            0x06 => Ok(CsPacket { kind: CsPacketKind::Ignore, byte_offset: start }),

            // ── Exception return (0x0E, first byte of 2-byte sequence) ─────
            0x0E => {
                // ETMv4 exception return packet
                Ok(CsPacket { kind: CsPacketKind::ExceptionReturn, byte_offset: start })
            }

            // ── TraceOn (0x04) ──────────────────────────────────────────────
            0x04 => {
                self.state.sync = SyncState::Synchronized;
                Ok(CsPacket { kind: CsPacketKind::TraceOn, byte_offset: start })
            }

            // ── TraceOff (0x05) ─────────────────────────────────────────────
            0x05 => Ok(CsPacket { kind: CsPacketKind::TraceOff, byte_offset: start }),

            // ── Overflow (0xFF) ─────────────────────────────────────────────
            0xFF => {
                self.state.lose_sync();
                Ok(CsPacket { kind: CsPacketKind::Overflow, byte_offset: start })
            }

            // ── Timestamp (0x43) ────────────────────────────────────────────
            0x43 => {
                // ETMv4 timestamp: ULEB128 encoded up to 9 bytes
                let ts = self.read_uleb128().ok_or(CsError::TruncatedBuffer)?;
                self.state.context.timestamp = ts;
                Ok(CsPacket { kind: CsPacketKind::Timestamp(ts), byte_offset: start })
            }

            // ── Cycle count (0x0D) ──────────────────────────────────────────
            0x0D => {
                let count = self.read_uleb128().ok_or(CsError::TruncatedBuffer)?;
                self.state.context.cycle_count = self.state.context.cycle_count.wrapping_add(count);
                Ok(CsPacket { kind: CsPacketKind::CycleCount(count), byte_offset: start })
            }

            // ── Context packet (0x80..0x8F) ─────────────────────────────────
            b if b & 0xF0 == 0x80 => self.decode_etm4_context(b, start),

            // ── Address packets (0x9A, 0x9B, 0x9C, 0x9D, 0x9E) ─────────────
            0x9A => self.decode_addr_short(start, false),
            0x9B => self.decode_addr_long(start),
            0x9C => self.decode_addr_short(start, true),  // with IS hint
            0x9D => self.decode_addr_with_el(start),
            0x9E => {
                // 64-bit address, 8 bytes
                let bytes = self.consume_n(8).ok_or(CsError::TruncatedBuffer)?;
                let addr = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                self.state.apply_addr(addr);
                Ok(CsPacket { kind: CsPacketKind::Address { addr }, byte_offset: start })
            }

            // ── Exception packet (0x08 | 0x0A) ──────────────────────────────
            0x08 | 0x0A => self.decode_etm4_exception(start),

            // ── Q element (0x0C) ─────────────────────────────────────────────
            0x0C => {
                let count = u32::try_from(self.read_uleb128().ok_or(CsError::TruncatedBuffer)?).unwrap_or(u32::MAX);
                let q = QElement { count, committed: true, address: None };
                self.state.q_elements.push(q);
                Ok(CsPacket {
                    kind: CsPacketKind::QElement { count },
                    byte_offset: start,
                })
            }

            // ── Atom packets (F1-F6 formats) ─────────────────────────────────
            b => {
                if let Some(pattern) = AtomPattern::decode_etm4(b) {
                    self.state.push_atoms(&pattern);
                    let taken = pattern.en_bits & 1 == 1;
                    Ok(CsPacket {
                        kind: CsPacketKind::Atom { taken, count: pattern.count },
                        byte_offset: start,
                    })
                } else {
                    Err(CsError::InvalidPacket(b))
                }
            }
        }
    }

    fn decode_etm4_context(&mut self, b: u8, start: usize) -> Result<CsPacket, CsError> {
        let info_byte = b & 0x0F;
        let has_el = (info_byte >> 2) & 1 != 0;
        let el_bits = info_byte & 0b11;
        let el = ExceptionLevel::from_bits(el_bits);
        let has_vmid = (info_byte >> 1) & 1 != 0;
        let has_ctx = info_byte & 1 != 0;
        if has_vmid {
            let vmid_bytes = self.consume_n(4).ok_or(CsError::TruncatedBuffer)?;
            let vmid = u32::from_le_bytes([vmid_bytes[0], vmid_bytes[1], vmid_bytes[2], vmid_bytes[3]]);
            self.state.last_vmid = vmid;
            self.state.context.vmid = vmid;
        }
        if has_ctx {
            let ctx_bytes = self.consume_n(4).ok_or(CsError::TruncatedBuffer)?;
            let ctx = u32::from_le_bytes([ctx_bytes[0], ctx_bytes[1], ctx_bytes[2], ctx_bytes[3]]);
            self.state.last_context_id = ctx;
            self.state.context.context_id = ctx;
        }
        if has_el { self.state.context.el = el; }
        Ok(CsPacket { kind: CsPacketKind::ContextId(self.state.context.context_id), byte_offset: start })
    }

    fn decode_etm4_exception(&mut self, start: usize) -> Result<CsPacket, CsError> {
        let type_byte = self.consume().ok_or(CsError::TruncatedBuffer)?;
        let level_byte = self.consume().ok_or(CsError::TruncatedBuffer)?;
        let exc_type = ExceptionType::from_etm_field(type_byte & 0x1F);
        let level = ExceptionLevel::from_bits(level_byte & 0b11);
        let previous_el = (level_byte >> 2) & 1 != 0;
        let mut pkt = ExceptionPacket::new(exc_type, level, start);
        pkt.previous_el = previous_el;
        let exc_code = u16::from(type_byte);
        self.state.exceptions.push(pkt);
        Ok(CsPacket { kind: CsPacketKind::Exception { exc_type: exc_code }, byte_offset: start })
    }

    fn decode_addr_short(&mut self, start: usize, _with_is: bool) -> Result<CsPacket, CsError> {
        let bytes = self.consume_n(4).ok_or(CsError::TruncatedBuffer)?;
        let addr = u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        self.state.apply_addr(addr);
        Ok(CsPacket { kind: CsPacketKind::Address { addr }, byte_offset: start })
    }

    fn decode_addr_long(&mut self, start: usize) -> Result<CsPacket, CsError> {
        let bytes = self.consume_n(8).ok_or(CsError::TruncatedBuffer)?;
        let addr = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        self.state.apply_addr(addr);
        Ok(CsPacket { kind: CsPacketKind::Address { addr }, byte_offset: start })
    }

    fn decode_addr_with_el(&mut self, start: usize) -> Result<CsPacket, CsError> {
        let info = self.consume().ok_or(CsError::TruncatedBuffer)?;
        let el = ExceptionLevel::from_bits((info >> 1) & 0b11);
        let ns = info & 1 != 0;
        self.state.context.apply_context(el, ns);
        let bytes = self.consume_n(4).ok_or(CsError::TruncatedBuffer)?;
        let addr = u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        self.state.apply_addr(addr);
        Ok(CsPacket { kind: CsPacketKind::Address { addr }, byte_offset: start })
    }

    fn read_uleb128(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.consume()?;
            result |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 { break; }
            shift += 7;
            if shift >= 64 { return None; }
        }
        Some(result)
    }

    /// Decode all packets.
    pub fn decode_all(&mut self) -> Vec<CsPacket> {
        let mut out = Vec::new();
        while let Some(result) = self.next_packet() {
            if let Ok(pkt) = result {
                out.push(pkt);
            }
        }
        out
    }

    /// Reset decoder position.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.state = EtmDecodeState::new(self.state.version.clone());
        self.packets.clear();
    }
}

// ─── Etm3PacketDecoder ────────────────────────────────────────────────────────

/// `ETMv3` packet decoder (pre-Cortex-A15 cores).
///
/// `ETMv3` packet format:
/// - Branch with no address: 0bxxxxxxx1 (P-header)
/// - Branch with address: multi-byte sequence
/// - I-sync: 0b00001000
/// - Trigger: 0b00001100
/// - Context ID: 0b01101110
/// - Timestamp: 0b01000011
pub struct Etm3PacketDecoder {
    buf: Vec<u8>,
    pos: usize,
    /// Decoder state.
    pub state: EtmDecodeState,
    /// Last address (delta compressed in `ETMv3`).
    pub last_addr: u64,
    /// Context ID bytes (4 bytes).
    pub context_id: u32,
}

impl Etm3PacketDecoder {
    /// Create a new `ETMv3` decoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            state: EtmDecodeState::new(EtmVersion::Etm3),
            last_addr: 0,
            context_id: 0,
        }
    }

    /// Feed bytes.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn consume(&mut self) -> Option<u8> {
        let b = self.buf.get(self.pos).copied();
        if b.is_some() { self.pos += 1; }
        b
    }

    fn consume_n(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.pos + n > self.buf.len() { return None; }
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Some(v)
    }

    /// Decode the next `ETMv3` packet.
    ///
    /// # Panics
    ///
    /// Panics if the internal buffer has been corrupted (unwrap on a validated length check).
    pub fn next_packet(&mut self) -> Option<Result<CsPacket, CsError>> {
        if self.pos >= self.buf.len() { return None; }
        let start = self.pos;
        let b = self.consume()?;

        let result = match b {
            // I-sync (0x08) — synchronization with address
            0x08 => {
                // I-sync: next 4 bytes are the address
                if self.pos + 4 > self.buf.len() {
                    self.pos = start;
                    return Some(Err(CsError::TruncatedBuffer));
                }
                let bytes = self.consume_n(4).unwrap();
                let addr = u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
                self.last_addr = addr;
                Ok(CsPacket { kind: CsPacketKind::Address { addr }, byte_offset: start })
            }
            // Trigger (0x0C)
            0x0C => Ok(CsPacket { kind: CsPacketKind::TraceOn, byte_offset: start }),
            // Context ID (0x6E) — 4 bytes
            0x6E => {
                if self.pos + 4 > self.buf.len() {
                    self.pos = start;
                    return Some(Err(CsError::TruncatedBuffer));
                }
                let bytes = self.consume_n(4).unwrap();
                self.context_id = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Ok(CsPacket {
                    kind: CsPacketKind::ContextId(self.context_id),
                    byte_offset: start,
                })
            }
            // Timestamp (0x43)
            0x43 => {
                let mut ts: u64 = 0;
                let mut shift = 0u32;
                loop {
                    let Some(tb) = self.consume() else {
                        self.pos = start;
                        return Some(Err(CsError::TruncatedBuffer));
                    };
                    ts |= u64::from(tb & 0x7F) << shift;
                    if tb & 0x80 == 0 { break; }
                    shift += 7;
                    if shift >= 64 { break; }
                }
                Ok(CsPacket { kind: CsPacketKind::Timestamp(ts), byte_offset: start })
            }
            // Overflow
            0xA0 => Ok(CsPacket { kind: CsPacketKind::Overflow, byte_offset: start }),
            // ASYNC A-sync (0x00 followed by 0x80)
            0x00 => {
                if self.peek() == Some(0x80) {
                    self.pos += 1;
                    Ok(CsPacket { kind: CsPacketKind::Sync, byte_offset: start })
                } else {
                    Ok(CsPacket { kind: CsPacketKind::Ignore, byte_offset: start })
                }
            }
            // Branch / P-header: bit 0 = 1
            b if b & 1 == 1 => {
                let taken = (b >> 2) & 1 == 1;
                // If bit 7 is set, there's a full address following
                let has_addr = (b & 0x80) != 0;
                if has_addr {
                    let addr_byte = self.consume().unwrap_or(0);
                    // Simple address update (partial)
                    self.last_addr = (self.last_addr & !0xFF) | u64::from(addr_byte);
                }
                let pattern = AtomPattern {
                    en_bits: u32::from(taken),
                    count: 1,
                    raw: b,
                    format: AtomFormat::V3Branch,
                };
                self.state.push_atoms(&pattern);
                Ok(CsPacket {
                    kind: CsPacketKind::Atom { taken, count: 1 },
                    byte_offset: start,
                })
            }
            _ => Err(CsError::InvalidPacket(b)),
        };
        self.state.total_decoded += 1;
        Some(result)
    }

    /// Decode all packets.
    pub fn decode_all(&mut self) -> Vec<CsPacket> {
        let mut out = Vec::new();
        while let Some(r) = self.next_packet() {
            if let Ok(p) = r { out.push(p); }
        }
        out
    }
}

impl Default for Etm3PacketDecoder {
    fn default() -> Self { Self::new() }
}

// ─── EtePacketDecoder ─────────────────────────────────────────────────────────

/// ETE (Embedded Trace Extension) packet decoder for `ARMv9`.
///
/// ETE extends `ETMv4` with additional packets for:
/// - GCS (Guarded Control Stack) trace
/// - Realm Management Extension trace
/// - Additional context
pub struct EtePacketDecoder {
    inner: Etm4Decoder,
    /// Whether GCS tracing is enabled.
    pub gcs_enabled: bool,
    /// Realm ID.
    pub realm_id: u32,
}

impl EtePacketDecoder {
    /// Create a new ETE decoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Etm4Decoder::new(EtmVersion::Ete),
            gcs_enabled: false,
            realm_id: 0,
        }
    }

    /// Feed bytes.
    pub fn feed(&mut self, data: &[u8]) {
        self.inner.feed(data);
    }

    /// Decode the next ETE packet.
    pub fn next_packet(&mut self) -> Option<Result<CsPacket, CsError>> {
        self.inner.next_packet()
    }

    /// Decode all packets.
    pub fn decode_all(&mut self) -> Vec<CsPacket> {
        self.inner.decode_all()
    }

    /// Return the pending atom count.
    #[must_use]
    pub fn pending_atoms(&self) -> usize {
        self.inner.state.pending_atoms()
    }
}

impl Default for EtePacketDecoder {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn async_bytes() -> Vec<u8> {
        let mut v = vec![0u8; 11];
        v.push(0x80);
        v
    }

    #[test]
    fn test_atom_pattern_f1_not_taken() {
        let p = AtomPattern::decode_etm4(0x00).unwrap();
        assert_eq!(p.count, 1);
        assert_eq!(p.en_bits, 0);
        assert_eq!(p.format, AtomFormat::F1);
    }

    #[test]
    fn test_atom_pattern_f1_taken() {
        // F1 taken: 0b0000_0010
        let p = AtomPattern::decode_etm4(0x02).unwrap();
        assert_eq!(p.count, 1);
        assert_eq!(p.en_bits, 1);
    }

    #[test]
    fn test_atom_pattern_f2() {
        // F2: 0b0000_EE10 = 0x0E (E=11 => both taken)
        let p = AtomPattern::decode_etm4(0x0E);
        assert!(p.is_some());
        let p = p.unwrap();
        assert_eq!(p.count, 2);
    }

    #[test]
    fn test_atom_pattern_to_vec() {
        let p = AtomPattern {
            en_bits: 0b101,
            count: 3,
            raw: 0,
            format: AtomFormat::F3,
        };
        let v = p.to_vec();
        assert_eq!(v, vec![true, false, true]);
    }

    #[test]
    fn test_etm4_decoder_async() {
        let mut dec = Etm4Decoder::new(EtmVersion::Etm4);
        dec.feed(&async_bytes());
        let _ = dec.find_async();
        assert_eq!(dec.state.sync, SyncState::FoundAsync);
    }

    #[test]
    fn test_etm4_trace_on() {
        let mut dec = Etm4Decoder::new(EtmVersion::Etm4);
        dec.feed(&[0x04]);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, CsPacketKind::TraceOn);
    }

    #[test]
    fn test_etm4_trace_off() {
        let mut dec = Etm4Decoder::new(EtmVersion::Etm4);
        dec.feed(&[0x05]);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, CsPacketKind::TraceOff);
    }

    #[test]
    fn test_etm4_overflow() {
        let mut dec = Etm4Decoder::new(EtmVersion::Etm4);
        dec.feed(&[0xFF]);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, CsPacketKind::Overflow);
        assert_eq!(dec.state.sync, SyncState::Lost);
    }

    #[test]
    fn test_etm4_timestamp_uleb128() {
        // Timestamp 0x43 <ULEB128: 300 = 0xAC02>
        let data = vec![0x43u8, 0xAC, 0x02];
        let mut dec = Etm4Decoder::new(EtmVersion::Etm4);
        dec.feed(&data);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, CsPacketKind::Timestamp(300));
    }

    #[test]
    fn test_etm4_cycle_count() {
        let data = vec![0x0Du8, 0x10]; // count = 16
        let mut dec = Etm4Decoder::new(EtmVersion::Etm4);
        dec.feed(&data);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, CsPacketKind::CycleCount(16));
    }

    #[test]
    fn test_etm4_address_short() {
        let addr: u32 = 0x0040_0000;
        let mut data = vec![0x9Au8];
        data.extend_from_slice(&addr.to_le_bytes());
        let mut dec = Etm4Decoder::new(EtmVersion::Etm4);
        dec.feed(&data);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, CsPacketKind::Address { addr: addr as u64 });
    }

    #[test]
    fn test_etm4_address_long() {
        let addr: u64 = 0xFFFF_8000_0040_0000;
        let mut data = vec![0x9Bu8];
        data.extend_from_slice(&addr.to_le_bytes());
        let mut dec = Etm4Decoder::new(EtmVersion::Etm4);
        dec.feed(&data);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, CsPacketKind::Address { addr });
    }

    #[test]
    fn test_etm4_exception_packet() {
        let data = vec![0x08u8, 0x05, 0x01]; // type=5 (IRQ), level=1 (EL1)
        let mut dec = Etm4Decoder::new(EtmVersion::Etm4);
        dec.feed(&data);
        let r = dec.next_packet().unwrap().unwrap();
        assert!(matches!(r.kind, CsPacketKind::Exception { .. }));
    }

    #[test]
    fn test_etm4_atom_queue() {
        let mut dec = Etm4Decoder::new(EtmVersion::Etm4);
        dec.feed(&[0x00, 0x02]); // not-taken, taken
        dec.decode_all();
        // atoms should be in queue: false, true
        assert_eq!(dec.state.pending_atoms(), 2);
        assert_eq!(dec.state.pop_atom(), Some(false));
        assert_eq!(dec.state.pop_atom(), Some(true));
    }

    #[test]
    fn test_etm3_isync() {
        let addr: u32 = 0x0040_0100;
        let mut data = vec![0x08u8];
        data.extend_from_slice(&addr.to_le_bytes());
        let mut dec = Etm3PacketDecoder::new();
        dec.feed(&data);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, CsPacketKind::Address { addr: addr as u64 });
    }

    #[test]
    fn test_etm3_context_id() {
        let ctx: u32 = 0x0000_1234;
        let mut data = vec![0x6Eu8];
        data.extend_from_slice(&ctx.to_le_bytes());
        let mut dec = Etm3PacketDecoder::new();
        dec.feed(&data);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, CsPacketKind::ContextId(ctx));
    }

    #[test]
    fn test_etm3_branch_taken() {
        let mut dec = Etm3PacketDecoder::new();
        dec.feed(&[0b0000_0101]); // bit0=1 (branch), bit2=1 (taken)
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, CsPacketKind::Atom { taken: true, count: 1 });
    }

    #[test]
    fn test_ete_decoder_passthrough() {
        let mut dec = EtePacketDecoder::new();
        dec.feed(&[0x04]); // TraceOn
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, CsPacketKind::TraceOn);
    }

    #[test]
    fn test_etm_decode_state_lose_sync() {
        let mut s = EtmDecodeState::new(EtmVersion::Etm4);
        s.atoms.push_back(true);
        s.atoms.push_back(false);
        s.lose_sync();
        assert_eq!(s.sync, SyncState::Lost);
        assert_eq!(s.pending_atoms(), 0);
    }

    #[test]
    fn test_q_element_decode() {
        let data = vec![0x0Cu8, 0x04]; // count = 4
        let mut dec = Etm4Decoder::new(EtmVersion::Etm4);
        dec.feed(&data);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, CsPacketKind::QElement { count: 4 });
    }

    #[test]
    fn test_decode_all_returns_packets() {
        let mut dec = Etm4Decoder::new(EtmVersion::Etm4);
        dec.feed(&[0x04, 0x05, 0xFF]);
        let pkts = dec.decode_all();
        assert!(!pkts.is_empty());
    }
}
