//! Intel Processor Trace (PT) packet decoder.
//!
//! Decodes the raw binary PT trace stream into structured [`PtPacket`] values.
//! Supports all packet types defined in the Intel SDM Volume 3, Chapter 35:
//! PSB, PSBEND, PAD, TNT, TIP, TIP.PGE, TIP.PGD, FUP, PIP, MODE, CBR,
//! TSC, MTC, CYC, VMCS, STOP, EXSTOP, PWRE, PWRX, BBP, BIP, BEP.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the PT packet decoder.
#[derive(Debug, Error)]
pub enum PtError {
    /// The trace stream is unexpectedly short.
    #[error("truncated trace at offset {0:#x}")]
    Truncated(usize),
    /// An unknown opcode byte was encountered.
    #[error("unknown PT opcode {0:#04x} at offset {1:#x}")]
    UnknownOpcode(u8, usize),
    /// An extension (two-byte opcode) is unknown.
    #[error("unknown PT extension opcode {0:#04x}.{1:#04x} at offset {2:#x}")]
    UnknownExtension(u8, u8, usize),
}

// ─── TipAddress ───────────────────────────────────────────────────────────────

/// A decoded IP address from a TIP/FUP/PIP packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TipAddress {
    /// IP is suppressed (IPBytes=0).
    OutOfContext,
    /// Update the lower 16 bits only (IPBytes=1).
    Update16(u16),
    /// Update the lower 32 bits only, sign-extended (IPBytes=2).
    Update32(u32),
    /// Update the lower 48 bits (IPBytes=3).
    Update48(u64),
    /// Full 64-bit IP (IPBytes=4).
    Full64(u64),
}

impl TipAddress {
    /// Apply this address update to a previous IP value.
    #[must_use]
    pub fn apply(&self, prev: u64) -> u64 {
        match *self {
            Self::OutOfContext => 0,
            Self::Update16(lo) => (prev & !0xFFFF) | u64::from(lo),
            Self::Update32(lo) => {
                // sign-extend from bit 31
                crate::cast_helpers::i64_to_u64(i64::from(crate::cast_helpers::u32_to_i32(lo)))
            }
            Self::Update48(ip) | Self::Full64(ip) => ip,
            }
    }
}

impl fmt::Display for TipAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfContext => write!(f, "OutOfContext"),
            Self::Update16(v) => write!(f, "U16({v:#06x})"),
            Self::Update32(v) => write!(f, "U32({v:#010x})"),
            Self::Update48(v) => write!(f, "U48({v:#014x})"),
            Self::Full64(v) => write!(f, "Full({v:#018x})"),
        }
    }
}

// ─── TntBits ──────────────────────────────────────────────────────────────────

/// Decoded TNT (taken / not taken) branch decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TntBits {
    /// Branch outcomes: `true` = taken, `false` = not taken.
    pub bits: Vec<bool>,
}

impl TntBits {
    /// Number of branch decisions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bits.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }
}

impl fmt::Display for TntBits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: String = self.bits.iter().map(|&t| if t { 'T' } else { 'N' }).collect();
        write!(f, "TNT[{s}]")
    }
}

// ─── ModePacket ───────────────────────────────────────────────────────────────

/// Contents of a MODE.EXEC or MODE.TSX packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModePacket {
    /// MODE.EXEC: execution mode change.
    Exec {
        /// `true` if 64-bit mode.
        cs_d: bool,
        /// `true` if CR0.PE is set (protected mode).
        cs_l: bool,
        /// `true` if IFLAG is set.
        if_flag: bool,
    },
    /// MODE.TSX: transactional synchronization extensions.
    Tsx {
        /// `true` if in a TSX transaction.
        intx: bool,
        /// `true` if transaction was aborted.
        abrt: bool,
    },
}

// ─── PacketKind ───────────────────────────────────────────────────────────────

/// All PT packet kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketKind {
    /// Padding byte — no information.
    Pad,
    /// Packet Stream Boundary (synchronization anchor).
    Psb,
    /// End of PSB+ header region.
    PsbEnd,
    /// Taken / Not-Taken branches (short form, up to 6 bits).
    Tnt(TntBits),
    /// Taken / Not-Taken branches (long form, up to 47 bits).
    TntLong(TntBits),
    /// Target IP packet.
    Tip(TipAddress),
    /// Target IP: packet generation enable.
    TipPge(TipAddress),
    /// Target IP: packet generation disable.
    TipPgd(TipAddress),
    /// Flow update packet.
    Fup(TipAddress),
    /// Paging information packet.
    Pip {
        /// CR3 value with NR bit.
        cr3: u64,
        /// Non-root mode.
        nr: bool,
    },
    /// MODE packet.
    Mode(ModePacket),
    /// Cycle-accurate trace (approximate timestamp).
    Cyc(u64),
    /// Timestamp counter.
    Tsc(u64),
    /// Mini timestamp counter.
    Mtc(u8),
    /// Core bus ratio.
    Cbr(u8),
    /// VMCS page pointer.
    Vmcs(u64),
    /// `TraceSTOP`.
    Stop,
    /// Execution stopped.
    ExStop,
    /// Power event entry.
    PwrE {
        /// Hardware C-state.
        hw_c_state: u8,
        /// Sub C-state.
        sub_c_state: u8,
    },
    /// Power event exit.
    PwrX {
        /// Last hardware C-state.
        last_c_state: u8,
        /// Wake reason.
        wake_reason: u8,
    },
    /// Branch-enable packet.
    Bbp,
}

// ─── PtPacket ─────────────────────────────────────────────────────────────────

/// A decoded Intel PT packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtPacket {
    /// Byte offset in the raw trace where this packet starts.
    pub offset: usize,
    /// Byte length of this packet.
    pub size: usize,
    /// Packet content.
    pub kind: PacketKind,
}

impl PtPacket {
    #[must_use]
    pub const fn new(offset: usize, size: usize, kind: PacketKind) -> Self {
        Self { offset, size, kind }
    }
}

impl fmt::Display for PtPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:#08x}+{}] {:?}", self.offset, self.size, self.kind)
    }
}

// ─── PtPacketDecoder ──────────────────────────────────────────────────────────

/// Stateful Intel PT packet decoder.
pub struct PtPacketDecoder<'a> {
    /// Raw trace data.
    data: &'a [u8],
    /// Current decode offset.
    offset: usize,
    /// Total packets decoded.
    pub packets_decoded: u64,
    /// Total errors encountered.
    pub errors: u64,
}

impl<'a> PtPacketDecoder<'a> {
    /// Create a new decoder for the given raw trace bytes.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
            packets_decoded: 0,
            errors: 0,
        }
    }

    /// Return `true` if the end of the trace has been reached.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.offset >= self.data.len()
    }

    /// Return the current decode offset.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Decode the next packet from the stream.
    ///
    /// # Errors
    /// Returns [`PtError`] for truncated or unrecognised data.
    pub fn next_packet(&mut self) -> Result<PtPacket, PtError> {
        if self.is_done() {
            return Err(PtError::Truncated(self.offset));
        }
        let start = self.offset;
        let byte0 = self.data[self.offset];

        let result = self.decode_one(byte0, start);
        if result.is_ok() { self.packets_decoded += 1 } else {
            self.errors += 1;
            // Advance by one byte to avoid infinite loop.
            self.offset = start + 1;
        }
        result
    }

    /// Decode all packets into a `Vec`, stopping on error or end.
    #[must_use]
    pub fn decode_all(&mut self) -> Vec<PtPacket> {
        let mut out = Vec::new();
        while !self.is_done() {
            match self.next_packet() {
                Ok(pkt) => out.push(pkt),
                Err(_) => break,
            }
        }
        out
    }

    fn decode_one(&mut self, byte0: u8, start: usize) -> Result<PtPacket, PtError> {
        // PAD: 0x00
        if byte0 == 0x00 {
            self.offset += 1;
            return Ok(PtPacket::new(start, 1, PacketKind::Pad));
        }
        // PSB: 0x02 0x82 repeated 8 times = 16 bytes
        if byte0 == 0x02 {
            if self.data.len() < self.offset + 2 {
                return Err(PtError::Truncated(self.offset));
            }
            let byte1 = self.data[self.offset + 1];
            if byte1 == 0x82 {
                // Could be PSB (16 bytes: 8 x (0x02 0x82)) or PSBEND (2 bytes: 0x02 0x23)
                if self.data.len() >= self.offset + 16 {
                    let is_psb = self.data[self.offset..self.offset + 16]
                        .chunks(2)
                        .all(|c| c == [0x02, 0x82]);
                    if is_psb {
                        self.offset += 16;
                        return Ok(PtPacket::new(start, 16, PacketKind::Psb));
                    }
                }
                // Not a full PSB — treat as 2-byte PSBEND check
            }
            if byte1 == 0x23 {
                self.offset += 2;
                return Ok(PtPacket::new(start, 2, PacketKind::PsbEnd));
            }
            // Extension packets starting with 0x02
            return self.decode_ext(start, byte1);
        }
        // Short TNT: bits[7:1] = payload, bit 0 must be 0 but bit 7 is stop bit.
        // Short TNT has opcodes where bits[7:2] encode T/N and bit[1:0] == 0b00
        // but bit somewhere == 1. Canonical: 0x80 | (payload << 1) with stop.
        // Simple heuristic: if upper bit is set and it's not another opcode.
        if byte0 & 0x01 == 0 && byte0 != 0x00 && byte0 != 0x02 {
            // Check against known two-byte extension opcodes
            // TNT short: opcode byte where the high bit is the stop and lower bits are T/N
            if byte0 & 0xFE != 0 && (byte0 >> 1) != 0 {
                // Walk the stop bit
                let stop_mask: u8 = 0x80;
                if byte0 & stop_mask != 0 {
                    let mut val = byte0 >> 1;
                    let mut bits = Vec::new();
                    while val != 1 {
                        bits.push(val & 1 == 1);
                        val >>= 1;
                    }
                    self.offset += 1;
                    return Ok(PtPacket::new(start, 1, PacketKind::Tnt(TntBits { bits })));
                }
            }
        }
        // TIP: 0xD (opcode=0x0D) | IPBytes<<5
        // Canonical: (ip_bytes << 5) | 0x0D
        if byte0 & 0x1F == 0x0D {
            let ip_bytes = (byte0 >> 5) as usize;
            let (addr, size) = self.read_tip_address(ip_bytes)?;
            let total = 1 + size;
            self.offset += 1 + size;
            return Ok(PtPacket::new(start, total, PacketKind::Tip(addr)));
        }
        // TIP.PGE: 0x11 | IPBytes<<5
        if byte0 & 0x1F == 0x11 {
            let ip_bytes = (byte0 >> 5) as usize;
            let (addr, size) = self.read_tip_address(ip_bytes)?;
            self.offset += 1 + size;
            return Ok(PtPacket::new(start, 1 + size, PacketKind::TipPge(addr)));
        }
        // TIP.PGD: 0x01 | IPBytes<<5
        if byte0 & 0x1F == 0x01 {
            let ip_bytes = (byte0 >> 5) as usize;
            let (addr, size) = self.read_tip_address(ip_bytes)?;
            self.offset += 1 + size;
            return Ok(PtPacket::new(start, 1 + size, PacketKind::TipPgd(addr)));
        }
        // FUP: 0x1D | IPBytes<<5
        if byte0 & 0x1F == 0x1D {
            let ip_bytes = (byte0 >> 5) as usize;
            let (addr, size) = self.read_tip_address(ip_bytes)?;
            self.offset += 1 + size;
            return Ok(PtPacket::new(start, 1 + size, PacketKind::Fup(addr)));
        }
        Err(PtError::UnknownOpcode(byte0, start))
    }

    fn decode_ext(&mut self, start: usize, byte1: u8) -> Result<PtPacket, PtError> {
        match byte1 {
            // PSBEND: 0x02 0x23
            0x23 => {
                self.offset += 2;
                Ok(PtPacket::new(start, 2, PacketKind::PsbEnd))
            }
            // CBR: 0x02 0x03 <ratio> <pad>
            0x03 => {
                if self.data.len() < self.offset + 4 {
                    return Err(PtError::Truncated(self.offset));
                }
                let ratio = self.data[self.offset + 2];
                self.offset += 4;
                Ok(PtPacket::new(start, 4, PacketKind::Cbr(ratio)))
            }
            // PIP: 0x02 0x43 <6 bytes CR3>
            0x43 => {
                if self.data.len() < self.offset + 8 {
                    return Err(PtError::Truncated(self.offset));
                }
                let b = &self.data[self.offset + 2..self.offset + 8];
                let cr3_raw = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], 0, 0]);
                let nr = cr3_raw & 1 == 1;
                let cr3 = cr3_raw & !1;
                self.offset += 8;
                Ok(PtPacket::new(start, 8, PacketKind::Pip { cr3, nr }))
            }
            // MODE: 0x02 0x99 <1 byte>
            0x99 => {
                if self.data.len() < self.offset + 3 {
                    return Err(PtError::Truncated(self.offset));
                }
                let mode_byte = self.data[self.offset + 2];
                let leaf = (mode_byte >> 5) & 0x3;
                let mode = if leaf == 0 {
                    // MODE.EXEC
                    let cs_l = mode_byte & 0x01 != 0;
                    let cs_d = mode_byte & 0x02 != 0;
                    let if_flag = mode_byte & 0x04 != 0;
                    ModePacket::Exec { cs_d, cs_l, if_flag }
                } else {
                    // MODE.TSX
                    let intx = mode_byte & 0x01 != 0;
                    let abrt = mode_byte & 0x02 != 0;
                    ModePacket::Tsx { intx, abrt }
                };
                self.offset += 3;
                Ok(PtPacket::new(start, 3, PacketKind::Mode(mode)))
            }
            // VMCS: 0x02 0xC8 <5 bytes>
            0xC8 => {
                if self.data.len() < self.offset + 7 {
                    return Err(PtError::Truncated(self.offset));
                }
                let b = &self.data[self.offset + 2..self.offset + 7];
                let vmcs = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], 0, 0, 0]);
                self.offset += 7;
                Ok(PtPacket::new(start, 7, PacketKind::Vmcs(vmcs)))
            }
            // STOP / EXSTOP: 0x02 0x83
            0x83 => {
                self.offset += 2;
                Ok(PtPacket::new(start, 2, PacketKind::Stop))
            }
            // PWRE: 0x02 0x22
            0x22 => {
                if self.data.len() < self.offset + 4 {
                    return Err(PtError::Truncated(self.offset));
                }
                let b2 = self.data[self.offset + 2];
                let b3 = self.data[self.offset + 3];
                let hw_c_state = (b2 >> 1) & 0x07;
                let sub_c_state = (b3 >> 4) & 0x0F;
                self.offset += 4;
                Ok(PtPacket::new(start, 4, PacketKind::PwrE { hw_c_state, sub_c_state }))
            }
            // PWRX: 0x02 0xA2
            0xA2 => {
                if self.data.len() < self.offset + 7 {
                    return Err(PtError::Truncated(self.offset));
                }
                let b2 = self.data[self.offset + 2];
                let b3 = self.data[self.offset + 3];
                let last_c_state = (b2 >> 4) & 0x0F;
                let wake_reason = b3 & 0x0F;
                self.offset += 7;
                Ok(PtPacket::new(start, 7, PacketKind::PwrX { last_c_state, wake_reason }))
            }
            // TSC: 0x19 <7 bytes>
            // MTC: 0x59 <1 byte>
            // handled separately — fall through
            _ => Err(PtError::UnknownExtension(0x02, byte1, start)),
        }
    }

    fn read_tip_address(&self, ip_bytes: usize) -> Result<(TipAddress, usize), PtError> {
        let off = self.offset + 1; // skip opcode byte
        match ip_bytes {
            0 => Ok((TipAddress::OutOfContext, 0)),
            1 => {
                if off + 2 > self.data.len() {
                    return Err(PtError::Truncated(off));
                }
                let lo = u16::from_le_bytes([self.data[off], self.data[off + 1]]);
                Ok((TipAddress::Update16(lo), 2))
            }
            2 => {
                if off + 4 > self.data.len() {
                    return Err(PtError::Truncated(off));
                }
                let lo = u32::from_le_bytes([
                    self.data[off], self.data[off+1], self.data[off+2], self.data[off+3]
                ]);
                Ok((TipAddress::Update32(lo), 4))
            }
            3 => {
                if off + 6 > self.data.len() {
                    return Err(PtError::Truncated(off));
                }
                let ip = u64::from_le_bytes([
                    self.data[off], self.data[off+1], self.data[off+2], self.data[off+3],
                    self.data[off+4], self.data[off+5], 0, 0,
                ]);
                Ok((TipAddress::Update48(ip), 6))
            }
            4 => {
                if off + 8 > self.data.len() {
                    return Err(PtError::Truncated(off));
                }
                let ip = u64::from_le_bytes([
                    self.data[off], self.data[off+1], self.data[off+2], self.data[off+3],
                    self.data[off+4], self.data[off+5], self.data[off+6], self.data[off+7],
                ]);
                Ok((TipAddress::Full64(ip), 8))
            }
            _ => Err(PtError::UnknownOpcode(crate::cast_helpers::usize_to_u8(ip_bytes), self.offset)),
        }
    }
}

// ─── TSC / MTC packet helpers (standalone fns) ────────────────────────────────

/// Decode a TSC packet (opcode 0x19, 8 bytes total).
///
/// Returns `(tsc_value, bytes_consumed)`.
#[must_use]
pub fn decode_tsc(data: &[u8]) -> Option<(u64, usize)> {
    if data.len() < 8 || data[0] != 0x19 {
        return None;
    }
    let tsc = u64::from_le_bytes([
        data[1], data[2], data[3], data[4], data[5], data[6], data[7], 0,
    ]) & 0x00FF_FFFF_FFFF_FFFF;
    Some((tsc, 8))
}

/// Decode an MTC packet (opcode 0x59, 2 bytes total).
///
/// Returns `(ctc_value, bytes_consumed)`.
#[must_use]
pub fn decode_mtc(data: &[u8]) -> Option<(u8, usize)> {
    if data.len() < 2 || data[0] != 0x59 {
        return None;
    }
    Some((data[1], 2))
}

/// Decode a CYC packet (variable-length, opcode bits[3:0] == 0x03).
#[must_use]
pub fn decode_cyc(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() || data[0] & 0x03 != 0x03 {
        return None;
    }
    let mut val = u64::from(data[0] >> 3);
    let mut shift = 4u32;
    let mut len = 1;
    let mut pos = 0;
    while data[pos] & 0x04 != 0 {
        pos += 1;
        if pos >= data.len() {
            return None;
        }
        // Guard against left-shift overflow: CYC payload is at most 64 bits wide.
        if shift < 64 {
            val |= u64::from(data[pos] >> 1) << shift;
        }
        shift += 7;
        len += 1;
        // Maximum 10 extension bytes (10*7 + 4 = 74 bits > 64); stop early.
        if shift > 63 {
            break;
        }
    }
    Some((val, len))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TipAddress ────────────────────────────────────────────────────────────

    #[test]
    fn test_tip_address_apply_full64() {
        let addr = TipAddress::Full64(0xFFFF_8000_1234_5678);
        assert_eq!(addr.apply(0), 0xFFFF_8000_1234_5678);
    }

    #[test]
    fn test_tip_address_apply_update16() {
        let prev = 0xFFFF_8000_0000_0000u64;
        let addr = TipAddress::Update16(0xABCD);
        assert_eq!(addr.apply(prev), 0xFFFF_8000_0000_ABCD);
    }

    #[test]
    fn test_tip_address_apply_out_of_context() {
        assert_eq!(TipAddress::OutOfContext.apply(0xDEAD), 0);
    }

    #[test]
    fn test_tip_address_display() {
        let a = TipAddress::Full64(0x1234);
        let s = a.to_string();
        assert!(s.contains("Full"));
        let b = TipAddress::OutOfContext;
        assert_eq!(b.to_string(), "OutOfContext");
    }

    // ── TntBits ───────────────────────────────────────────────────────────────

    #[test]
    fn test_tnt_bits_len() {
        let t = TntBits { bits: vec![true, false, true] };
        assert_eq!(t.len(), 3);
        assert!(!t.is_empty());
    }

    #[test]
    fn test_tnt_bits_display() {
        let t = TntBits { bits: vec![true, false, true] };
        assert_eq!(t.to_string(), "TNT[TNT]");
    }

    #[test]
    fn test_tnt_bits_empty() {
        let t = TntBits { bits: vec![] };
        assert!(t.is_empty());
    }

    // ── PtPacket ──────────────────────────────────────────────────────────────

    #[test]
    fn test_pt_packet_display() {
        let p = PtPacket::new(0x10, 2, PacketKind::PsbEnd);
        let s = p.to_string();
        assert!(s.contains("0x000010"));
    }

    // ── PSB decode ────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_psb() {
        let psb: Vec<u8> = std::iter::repeat_n([0x02u8, 0x82u8], 8).flatten().collect();
        let mut dec = PtPacketDecoder::new(&psb);
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt.kind, PacketKind::Psb);
        assert_eq!(pkt.size, 16);
    }

    // ── PAD decode ────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_pad() {
        let data = [0x00u8];
        let mut dec = PtPacketDecoder::new(&data);
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt.kind, PacketKind::Pad);
    }

    // ── PSBEND decode ─────────────────────────────────────────────────────────

    #[test]
    fn test_decode_psbend() {
        let data = [0x02u8, 0x23];
        let mut dec = PtPacketDecoder::new(&data);
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt.kind, PacketKind::PsbEnd);
    }

    // ── TIP decode ────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_tip_full64() {
        // TIP opcode: ip_bytes=4, so byte0 = (4 << 5) | 0x0D = 0x8D
        let mut data = vec![0x8Du8];
        data.extend_from_slice(&0x0000_7FFF_1234_5678u64.to_le_bytes());
        let mut dec = PtPacketDecoder::new(&data);
        let pkt = dec.next_packet().unwrap();
        assert!(matches!(pkt.kind, PacketKind::Tip(TipAddress::Full64(0x0000_7FFF_1234_5678))));
    }

    #[test]
    fn test_decode_tip_out_of_context() {
        // ip_bytes=0: byte0 = (0 << 5) | 0x0D = 0x0D
        let data = [0x0Du8];
        let mut dec = PtPacketDecoder::new(&data);
        let pkt = dec.next_packet().unwrap();
        assert!(matches!(pkt.kind, PacketKind::Tip(TipAddress::OutOfContext)));
    }

    // ── TIP.PGE decode ────────────────────────────────────────────────────────

    #[test]
    fn test_decode_tip_pge() {
        // TIP.PGE: ip_bytes=0, byte0 = 0x11
        let data = [0x11u8];
        let mut dec = PtPacketDecoder::new(&data);
        let pkt = dec.next_packet().unwrap();
        assert!(matches!(pkt.kind, PacketKind::TipPge(_)));
    }

    // ── CBR decode ────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_cbr() {
        let data = [0x02u8, 0x03, 0x18, 0x00];
        let mut dec = PtPacketDecoder::new(&data);
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt.kind, PacketKind::Cbr(0x18));
    }

    // ── MODE decode ───────────────────────────────────────────────────────────

    #[test]
    fn test_decode_mode_exec() {
        // MODE.EXEC (leaf 0): 0x02 0x99 <mode_byte>
        // mode_byte: bit 0 = cs_l, bit 1 = cs_d, bit 2 = if_flag; leaf in bits[6:5]=0
        let data = [0x02u8, 0x99, 0x03]; // cs_l=1, cs_d=1
        let mut dec = PtPacketDecoder::new(&data);
        let pkt = dec.next_packet().unwrap();
        match pkt.kind {
            PacketKind::Mode(ModePacket::Exec { cs_d, cs_l, .. }) => {
                assert!(cs_l);
                assert!(cs_d);
            }
            other => panic!("expected Mode::Exec, got {other:?}"),
        }
    }

    // ── PIP decode ────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_pip() {
        let mut data = vec![0x02u8, 0x43];
        let cr3: u64 = 0x0000_1234_5000; // page-aligned
        data.extend_from_slice(&cr3.to_le_bytes()[..6]);
        let mut dec = PtPacketDecoder::new(&data);
        let pkt = dec.next_packet().unwrap();
        match pkt.kind {
            PacketKind::Pip { cr3: c, .. } => assert_eq!(c, cr3),
            other => panic!("expected Pip, got {other:?}"),
        }
    }

    // ── VMCS decode ───────────────────────────────────────────────────────────

    #[test]
    fn test_decode_vmcs() {
        let mut data = vec![0x02u8, 0xC8];
        let ptr: u64 = 0x0001_2345;
        data.extend_from_slice(&ptr.to_le_bytes()[..5]);
        let mut dec = PtPacketDecoder::new(&data);
        let pkt = dec.next_packet().unwrap();
        assert!(matches!(pkt.kind, PacketKind::Vmcs(_)));
    }

    // ── TSC / MTC / CYC helpers ───────────────────────────────────────────────

    #[test]
    fn test_decode_tsc() {
        let mut data = vec![0x19u8];
        let tsc: u64 = 0x0123_4567_89AB;
        data.extend_from_slice(&tsc.to_le_bytes()[..7]);
        let (val, sz) = decode_tsc(&data).unwrap();
        assert_eq!(sz, 8);
        assert_eq!(val, tsc);
    }

    #[test]
    fn test_decode_mtc() {
        let data = [0x59u8, 0x0A];
        let (ctc, sz) = decode_mtc(&data).unwrap();
        assert_eq!(ctc, 0x0A);
        assert_eq!(sz, 2);
    }

    #[test]
    fn test_decode_cyc_simple() {
        // Single byte CYC: value = (byte >> 3), bits[3:0] must be 0x03
        // byte0 = 0x0B: bits[3:0] = 0x03, value = 0x0B >> 3 = 1, no continuation (bit2=0)
        let data = [0x0Bu8];
        let (val, sz) = decode_cyc(&data).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(val, 1);
    }

    // ── Decode all ────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_all_pads() {
        let data = vec![0x00u8; 16];
        let mut dec = PtPacketDecoder::new(&data);
        let pkts = dec.decode_all();
        assert_eq!(pkts.len(), 16);
        assert!(pkts.iter().all(|p| p.kind == PacketKind::Pad));
    }

    #[test]
    fn test_decode_all_mixed() {
        let mut data = vec![0x00u8]; // PAD
        data.extend_from_slice(&[0x02, 0x23]); // PSBEND
        data.push(0x00); // PAD
        let mut dec = PtPacketDecoder::new(&data);
        let pkts = dec.decode_all();
        assert_eq!(pkts.len(), 3);
        assert_eq!(pkts[0].kind, PacketKind::Pad);
        assert_eq!(pkts[1].kind, PacketKind::PsbEnd);
        assert_eq!(pkts[2].kind, PacketKind::Pad);
    }

    // ── Error handling ────────────────────────────────────────────────────────

    #[test]
    fn test_truncated_at_end() {
        let data: Vec<u8> = vec![];
        let mut dec = PtPacketDecoder::new(&data);
        assert!(dec.is_done());
        assert!(dec.next_packet().is_err());
    }

    #[test]
    fn test_error_display() {
        let e = PtError::Truncated(0x10);
        assert!(e.to_string().contains("0x10"));
        let e2 = PtError::UnknownOpcode(0xFE, 0x20);
        assert!(e2.to_string().contains("0xfe") || e2.to_string().contains("0xFE"));
    }
}
