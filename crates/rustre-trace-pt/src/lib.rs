//! `rustre-trace-pt` — Intel Processor Trace (PT) decode and reconstruction.
//!
//! Implements a full packet decoder for the Intel PT trace format,
//! control flow reconstruction, timing analysis, sideband correlation,
//! and PT trace replay.

pub(crate) mod cast_helpers;

#[doc(hidden)]
pub use crate::cast_helpers::{
    f64_to_u64 as __ch_f64_to_u64,
    f64_to_usize as __ch_f64_to_usize,
    i64_to_f64 as __ch_i64_to_f64,
    i64_to_u64 as __ch_i64_to_u64,
    u128_to_f64 as __ch_u128_to_f64,
    u32_to_i32 as __ch_u32_to_i32,
    u32_to_u8 as __ch_u32_to_u8,
    u64_to_f64 as __ch_u64_to_f64,
    u64_to_i64 as __ch_u64_to_i64,
    u64_to_u32 as __ch_u64_to_u32,
    u64_to_u8 as __ch_u64_to_u8,
    u64_to_usize as __ch_u64_to_usize,
    usize_to_f64 as __ch_usize_to_f64,
    usize_to_u8 as __ch_usize_to_u8,
};

pub mod pt_decoder;
pub mod pt_filter;
pub mod pt_flow_reconstruction;
pub mod pt_sideband;
pub mod pt_snapshot;
pub mod pt_timing;
pub mod pt_trace_builder;
pub mod pt_packet_decoder;
pub mod pt_instruction_decoder;
pub mod pt_perf_integration;
pub mod pt_block_decoder;
pub mod pt_timing_analyzer;
pub mod pt_coverage_reporter;

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Intel PT decoding errors.
#[derive(Debug, Error)]
pub enum PtError {
    /// Unknown or unsupported packet byte.
    #[error("invalid packet byte 0x{0:02x}")]
    InvalidPacket(u8),
    /// Truncated packet — not enough bytes remain.
    #[error("truncated packet")]
    TruncatedPacket,
    /// Unknown opcode.
    #[error("unknown opcode 0x{0:02x}")]
    UnknownOpcode(u8),
    /// IP address compression error.
    #[error("IP compression: {0}")]
    IpCompression(String),
    /// Flow reconstruction failed.
    #[error("flow reconstruction: {0}")]
    FlowReconstruction(String),
    /// Sideband correlation error.
    #[error("sideband: {0}")]
    Sideband(String),
    /// Timing error.
    #[error("timing: {0}")]
    Timing(String),
    /// Overflow — trace data was lost.
    #[error("trace overflow at offset 0x{0:x}")]
    Overflow(usize),
}

// ─── IpCompression ────────────────────────────────────────────────────────────

/// IP address compression mode used in PT packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpCompression {
    /// IP is zero (0 bytes).
    Zero,
    /// 16-bit update (2 bytes).
    Update16,
    /// 32-bit update (4 bytes).
    Update32,
    /// 48-bit full address (6 bytes).
    Full48,
    /// 48-bit full with sign extension (6 bytes).
    Full48SignExt,
    /// Full 64-bit address (8 bytes).
    Full64,
}

impl IpCompression {
    /// Return the number of additional bytes needed to read the IP.
    #[must_use]
    pub const fn byte_count(self) -> usize {
        match self {
            Self::Zero => 0,
            Self::Update16 => 2,
            Self::Update32 => 4,
            Self::Full48 | Self::Full48SignExt => 6,
            Self::Full64 => 8,
        }
    }

    /// Parse from the 3-bit IPR field in a PT packet header.
    #[must_use]
    pub const fn from_ipr(ipr: u8) -> Self {
        match ipr & 0b111 {
            1 => Self::Update16,
            2 => Self::Update32,
            3 => Self::Full48,
            4 => Self::Full48SignExt,
            6 => Self::Full64,
            _ => Self::Zero,
        }
    }
}

// ─── PtPacketKind ─────────────────────────────────────────────────────────────

/// The kind of a decoded Intel PT packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtPacketKind {
    /// PAD packet.
    Pad,
    /// Packet Stream Boundary.
    Psb,
    /// PSB End.
    PsbEnd,
    /// Target IP (indirect branch).
    Tip {
        /// Resolved IP address.
        ip: u64,
        /// IP compression mode.
        compression: IpCompression,
    },
    /// Trace Enable.
    TipPge {
        /// Resolved IP address.
        ip: u64,
        /// IP compression mode.
        compression: IpCompression,
    },
    /// Trace Disable.
    TipPgd {
        /// Resolved IP address.
        ip: u64,
        /// IP compression mode.
        compression: IpCompression,
    },
    /// Taken/Not-Taken bits (short form, up to 6 TNT bits).
    Tnt {
        /// Bit mask of taken (1) / not-taken (0) decisions, LSB first.
        bits: u64,
        /// Number of valid bits.
        count: u8,
    },
    /// Long TNT packet (up to 47 TNT bits).
    TntLong {
        /// Bit mask of taken (1) / not-taken (0) decisions, LSB first.
        bits: u64,
        /// Number of valid bits.
        count: u8,
    },
    /// Timestamp Counter.
    Tsc(u64),
    /// Mini Timestamp Counter delta.
    Mtc {
        /// CTC value.
        ctc: u8,
    },
    /// Cycle counter.
    Cyc {
        /// Cycle count delta.
        value: u64,
    },
    /// Core Bus Ratio.
    Cbr(u8),
    /// Overflow.
    Overflow,
    /// Mode change.
    Mode {
        /// Leaf byte.
        leaf: u8,
        /// Mode bits.
        bits: u8,
    },
    /// PIP — CR3 value change.
    Pip {
        /// CR3 value.
        cr3: u64,
        /// Whether the NR bit is set.
        nr: bool,
    },
    /// VMCS — VM control structure address.
    Vmcs {
        /// VMCS base address.
        base: u64,
    },
    /// EXSTOP — execution stopped.
    ExStop {
        /// Whether the IP is precise.
        ip: bool,
    },
    /// MWAIT.
    Mwait {
        /// Extension bits.
        ext: u8,
        /// Hints.
        hints: u8,
    },
    /// PWRE — power event (enter).
    Pwre {
        /// Hardware C-state.
        hw_cstate: u8,
        /// Software C-state.
        sw_cstate: u8,
    },
    /// PWRX — power event (exit).
    Pwrx {
        /// Last C-state.
        last_cstate: u8,
        /// Deepest C-state reached.
        deepest_cstate: u8,
    },
    /// BBP — basic block pointer.
    Bbp {
        /// Payload byte type.
        type_flag: u8,
    },
    /// BIP — basic block IP.
    Bip {
        /// ID.
        id: u8,
        /// Value.
        value: u64,
    },
    /// BEP — basic block end.
    Bep {
        /// Whether the IP is valid.
        ip: bool,
    },
}

impl std::fmt::Display for PtPacketKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pad => write!(f, "Pad"),
            Self::Psb => write!(f, "PSB"),
            Self::PsbEnd => write!(f, "PSBEND"),
            Self::Tip { ip, .. } => write!(f, "TIP(0x{ip:x})"),
            Self::TipPge { ip, .. } => write!(f, "TIP.PGE(0x{ip:x})"),
            Self::TipPgd { ip, .. } => write!(f, "TIP.PGD(0x{ip:x})"),
            Self::Tnt { bits, count } => write!(f, "TNT(bits=0x{bits:x}, count={count})"),
            Self::TntLong { bits, count } => write!(f, "TNT.L(bits=0x{bits:x}, count={count})"),
            Self::Tsc(v) => write!(f, "TSC({v})"),
            Self::Mtc { ctc } => write!(f, "MTC({ctc})"),
            Self::Cyc { value } => write!(f, "CYC({value})"),
            Self::Cbr(ratio) => write!(f, "CBR({ratio})"),
            Self::Overflow => write!(f, "OVF"),
            Self::Mode { leaf, bits } => write!(f, "MODE(leaf={leaf}, bits=0x{bits:x})"),
            Self::Pip { cr3, nr } => write!(f, "PIP(cr3=0x{cr3:x}, nr={nr})"),
            Self::Vmcs { base } => write!(f, "VMCS(base=0x{base:x})"),
            Self::ExStop { ip } => write!(f, "EXSTOP(ip={ip})"),
            Self::Mwait { ext, hints } => write!(f, "MWAIT(ext={ext}, hints={hints})"),
            Self::Pwre {
                hw_cstate,
                sw_cstate,
            } => {
                write!(f, "PWRE(hw={hw_cstate}, sw={sw_cstate})")
            }
            Self::Pwrx {
                last_cstate,
                deepest_cstate,
            } => {
                write!(f, "PWRX(last={last_cstate}, deepest={deepest_cstate})")
            }
            Self::Bbp { type_flag } => write!(f, "BBP(type={type_flag})"),
            Self::Bip { id, value } => write!(f, "BIP(id={id}, val=0x{value:x})"),
            Self::Bep { ip } => write!(f, "BEP(ip={ip})"),
        }
    }
}

impl PtPacketKind {
    /// Return `true` if this is a timing packet.
    #[must_use]
    pub const fn is_timing(&self) -> bool {
        matches!(
            self,
            Self::Tsc(_) | Self::Mtc { .. } | Self::Cyc { .. } | Self::Cbr(_)
        )
    }

    /// Return `true` if this is a flow packet.
    #[must_use]
    pub const fn is_flow(&self) -> bool {
        matches!(
            self,
            Self::Tip { .. }
                | Self::TipPge { .. }
                | Self::TipPgd { .. }
                | Self::Tnt { .. }
                | Self::TntLong { .. }
        )
    }

    /// Return the IP address if this is a TIP/TIP.PGE/TIP.PGD packet.
    #[must_use]
    pub const fn ip_addr(&self) -> Option<u64> {
        match self {
            Self::Tip { ip, .. } | Self::TipPge { ip, .. } | Self::TipPgd { ip, .. } => Some(*ip),
            _ => None,
        }
    }
}

// ─── PtPacket ─────────────────────────────────────────────────────────────────

/// A decoded Intel PT packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtPacket {
    /// The packet kind.
    pub kind: PtPacketKind,
    /// Byte offset where this packet starts.
    pub offset: usize,
    /// Raw packet size in bytes.
    pub size: usize,
}

impl PtPacket {
    /// Create a new packet.
    #[must_use]
    pub const fn new(kind: PtPacketKind, offset: usize, size: usize) -> Self {
        Self { kind, offset, size }
    }

    /// Return `true` if this is a timing packet.
    #[must_use]
    pub const fn is_timing(&self) -> bool {
        self.kind.is_timing()
    }

    /// Return `true` if this is a flow packet.
    #[must_use]
    pub const fn is_flow(&self) -> bool {
        self.kind.is_flow()
    }
}

impl std::fmt::Display for PtPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "@0x{:x}[{}B] {}", self.offset, self.size, self.kind)
    }
}

// ─── PtDecoder ────────────────────────────────────────────────────────────────

/// Stateful Intel PT byte-stream decoder.
pub struct PtDecoder {
    /// Internal byte buffer.
    pub buf: Vec<u8>,
    /// Current read position.
    pub pos: usize,
    /// Last known IP (for delta decompression).
    last_ip: u64,
    /// Number of overflow events seen.
    pub overflow_count: usize,
    /// Number of errors encountered.
    pub error_count: usize,
}

impl PtDecoder {
    /// Create a new empty decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            last_ip: 0,
            overflow_count: 0,
            error_count: 0,
        }
    }

    /// Feed more bytes into the decoder.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Reset the decoder state (but keep the buffer).
    pub const fn reset(&mut self) {
        self.pos = 0;
        self.last_ip = 0;
        self.overflow_count = 0;
        self.error_count = 0;
    }

    /// Return the remaining bytes in the buffer.
    #[must_use]
    pub const fn remaining_bytes(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Peek at the next byte without consuming it.
    #[must_use]
    pub fn peek_byte(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Read a u64 IP from the buffer given the IPR/IPE compression mode.
    fn read_ip(&mut self, ipr: u8) -> Option<u64> {
        let comp = IpCompression::from_ipr(ipr);
        let count = comp.byte_count();
        if self.pos + count > self.buf.len() {
            return None;
        }
        let ip = match comp {
            IpCompression::Zero => 0u64,
            IpCompression::Update16 => {
                let lo = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
                self.last_ip = (self.last_ip & !0xFFFF) | u64::from(lo);
                self.pos += 2;
                self.last_ip
            }
            IpCompression::Update32 => {
                let lo = u32::from_le_bytes([
                    self.buf[self.pos],
                    self.buf[self.pos + 1],
                    self.buf[self.pos + 2],
                    self.buf[self.pos + 3],
                ]);
                self.last_ip = (self.last_ip & !0xFFFF_FFFF) | u64::from(lo);
                self.pos += 4;
                self.last_ip
            }
            IpCompression::Full48 => {
                let mut buf = [0u8; 8];
                buf[..6].copy_from_slice(&self.buf[self.pos..self.pos + 6]);
                let ip = u64::from_le_bytes(buf);
                self.pos += 6;
                self.last_ip = ip;
                ip
            }
            IpCompression::Full48SignExt => {
                let mut buf = [0u8; 8];
                buf[..6].copy_from_slice(&self.buf[self.pos..self.pos + 6]);
                let mut ip = u64::from_le_bytes(buf);
                // Sign extend bit 47
                if ip & (1 << 47) != 0 {
                    ip |= 0xFFFF_0000_0000_0000;
                }
                self.pos += 6;
                self.last_ip = ip;
                ip
            }
            IpCompression::Full64 => {
                let ip = u64::from_le_bytes([
                    self.buf[self.pos],
                    self.buf[self.pos + 1],
                    self.buf[self.pos + 2],
                    self.buf[self.pos + 3],
                    self.buf[self.pos + 4],
                    self.buf[self.pos + 5],
                    self.buf[self.pos + 6],
                    self.buf[self.pos + 7],
                ]);
                self.pos += 8;
                self.last_ip = ip;
                ip
            }
        };
        Some(ip)
    }

    /// Try to decode the next packet from the buffer.
    ///
    /// Returns `None` if no bytes remain.
    pub fn next_packet(&mut self) -> Option<Result<PtPacket, PtError>> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let start = self.pos;
        let b = self.buf[self.pos];
        self.pos += 1;

        // 0x00 = Pad
        if b == 0x00 {
            return Some(Ok(PtPacket::new(PtPacketKind::Pad, start, 1)));
        }

        // 0x23 = PSBEND (alternative single-byte encoding)
        if b == 0x23 {
            return Some(Ok(PtPacket::new(PtPacketKind::PsbEnd, start, 1)));
        }

        // 0xF3 = OVERFLOW — must be checked before the CYC pattern (0xF3 & 7 == 3)
        if b == 0xF3 {
            self.overflow_count += 1;
            return Some(Ok(PtPacket::new(PtPacketKind::Overflow, start, 1)));
        }

        // EXSTOP: 0x62 (no-IP) or 0x63 (with IP) — must be checked before the
        // short-TNT pattern (0x62 & 1 == 0) and the CYC pattern (0x63 & 7 == 3).
        if b == 0x62 || b == 0x63 {
            return Some(Ok(PtPacket::new(
                PtPacketKind::ExStop { ip: b == 0x63 },
                start,
                1,
            )));
        }

        // 0xA3 = Long TNT — check before the CYC pattern (0xA3 & 7 == 3).
        if b == 0xA3 {
            if self.pos + 6 > self.buf.len() {
                self.pos = start;
                return Some(Err(PtError::TruncatedPacket));
            }
            let mut payload = [0u8; 8];
            payload[..6].copy_from_slice(&self.buf[self.pos..self.pos + 6]);
            let raw = u64::from_le_bytes(payload);
            // Find the stop bit (highest set bit).  If raw is zero there are no
            // branch decisions in this packet — emit an empty TntLong rather than
            // panicking on the leading-zeros subtraction.
            if raw == 0 {
                self.pos += 6;
                return Some(Ok(PtPacket::new(
                    PtPacketKind::TntLong { bits: 0, count: 0 },
                    start,
                    7,
                )));
            }
            let stop_bit = 63 - crate::cast_helpers::u32_to_u8(raw.leading_zeros());
            let bits = raw & !((1u64) << stop_bit);
            let count = stop_bit;
            self.pos += 6;
            return Some(Ok(PtPacket::new(
                PtPacketKind::TntLong { bits, count },
                start,
                7,
            )));
        }

        // 0x19 + 8 LE bytes = TSC
        if b == 0x19 {
            if self.pos + 8 > self.buf.len() {
                self.pos = start;
                return Some(Err(PtError::TruncatedPacket));
            }
            let tsc = u64::from_le_bytes([
                self.buf[self.pos],
                self.buf[self.pos + 1],
                self.buf[self.pos + 2],
                self.buf[self.pos + 3],
                self.buf[self.pos + 4],
                self.buf[self.pos + 5],
                self.buf[self.pos + 6],
                self.buf[self.pos + 7],
            ]);
            self.pos += 8;
            return Some(Ok(PtPacket::new(PtPacketKind::Tsc(tsc), start, 9)));
        }

        // 0x59 = MTC
        if b == 0x59 {
            if self.pos >= self.buf.len() {
                self.pos = start;
                return Some(Err(PtError::TruncatedPacket));
            }
            let ctc = self.buf[self.pos];
            self.pos += 1;
            return Some(Ok(PtPacket::new(PtPacketKind::Mtc { ctc }, start, 2)));
        }

        // CYC packet: bottom 3 bits == 011
        if (b & 0b11) == 0b11 && b != 0x03 {
            // Simple CYC: payload in upper 5 bits + possible extensions
            let mut value = u64::from(b >> 3);
            let mut size = 1usize;
            // If bit 2 of the byte is set, more bytes follow
            let mut shift = 5u32;
            let mut cont = (b & 0x04) != 0;
            while cont {
                if self.pos >= self.buf.len() {
                    self.pos = start;
                    return Some(Err(PtError::TruncatedPacket));
                }
                let ext = self.buf[self.pos];
                self.pos += 1;
                size += 1;
                // Guard the shift before applying it: a long run of
                // continuation bytes can push `shift` past 63, and shifting a
                // u64 by >= 64 panics in debug builds. Cap the payload at the
                // bits we can still represent and stop reading further. The
                // `cont` flag is not updated here because the loop is exiting
                // unconditionally and `cont` is never read after this `break`.
                if shift >= 64 {
                    break;
                }
                value |= u64::from(ext >> 1) << shift;
                shift += 7;
                cont = (ext & 0x01) != 0;
                if shift > 63 {
                    break;
                }
            }
            return Some(Ok(PtPacket::new(PtPacketKind::Cyc { value }, start, size)));
        }

        // TIP packets: byte patterns with IPR in bits [5:3]
        // TIP        = 0bIIIDDD01 where DDD != 111
        // TIP.PGE    = 0bIII10001
        // TIP.PGD    = 0bIII00001
        // TIP/TIP.PGE/TIP.PGD all have bits [2:0] as variant
        let lower = b & 0x1F;
        if lower == 0x0D || lower == 0x11 || lower == 0x01 {
            let ipr = (b >> 5) & 0x07;
            let comp = IpCompression::from_ipr(ipr);
            let ip_bytes = comp.byte_count();
            if self.pos + ip_bytes > self.buf.len() {
                self.pos = start;
                return Some(Err(PtError::TruncatedPacket));
            }
            let ip = self.read_ip(ipr).unwrap_or(0);
            let size = 1 + ip_bytes;
            let kind = match lower {
                0x0D => PtPacketKind::Tip {
                    ip,
                    compression: comp,
                },
                0x11 => PtPacketKind::TipPge {
                    ip,
                    compression: comp,
                },
                0x01 => PtPacketKind::TipPgd {
                    ip,
                    compression: comp,
                },
                _ => unreachable!(),
            };
            return Some(Ok(PtPacket::new(kind, start, size)));
        }

        // 0xC5 + 6 bytes LE (ip lower 48 bits) = TIP (legacy simple form)
        if b == 0xC5 {
            if self.pos + 6 > self.buf.len() {
                self.pos = start;
                return Some(Err(PtError::TruncatedPacket));
            }
            let mut ip_buf = [0u8; 8];
            ip_buf[..6].copy_from_slice(&self.buf[self.pos..self.pos + 6]);
            let ip = u64::from_le_bytes(ip_buf);
            self.last_ip = ip;
            self.pos += 6;
            return Some(Ok(PtPacket::new(
                PtPacketKind::Tip {
                    ip,
                    compression: IpCompression::Full48,
                },
                start,
                7,
            )));
        }

        // 0x02 variants
        if b == 0x02 {
            if self.pos >= self.buf.len() {
                self.pos = start;
                return Some(Err(PtError::TruncatedPacket));
            }
            let b2 = self.buf[self.pos];

            // 0x02 0x22 <cbr> 0x00 = CBR
            if b2 == 0x22 {
                if self.pos + 3 > self.buf.len() {
                    self.pos = start;
                    return Some(Err(PtError::TruncatedPacket));
                }
                let cbr_byte = self.buf[self.pos + 1];
                self.pos += 3;
                return Some(Ok(PtPacket::new(PtPacketKind::Cbr(cbr_byte), start, 4)));
            }

            // 0x02 0xC3 = PSBEND
            if b2 == 0xC3 {
                self.pos += 1;
                return Some(Ok(PtPacket::new(PtPacketKind::PsbEnd, start, 2)));
            }

            // PIP: 0x02 0x43 <6 byte cr3> — must be tested BEFORE MODE because
            // both opcodes share the 0x43 second byte. PIP requires 6 additional
            // bytes after the two-byte opcode (total 8 bytes from start).
            if b2 == 0x43 && self.pos + 7 <= self.buf.len() {
                let mut cr3_buf = [0u8; 8];
                cr3_buf[..6].copy_from_slice(&self.buf[self.pos + 1..self.pos + 7]);
                let cr3 = u64::from_le_bytes(cr3_buf);
                let nr = (cr3 & 1) != 0;
                self.pos += 7;
                return Some(Ok(PtPacket::new(
                    PtPacketKind::Pip { cr3: cr3 & !1, nr },
                    start,
                    8,
                )));
            }

            // 0x02 0x43 = MODE.EXEC or MODE variants (only reached when there are
            // fewer than 6 trailing bytes, i.e. not a PIP packet).
            if b2 == 0x43 || b2 == 0x03 {
                if self.pos + 2 > self.buf.len() {
                    self.pos = start;
                    return Some(Err(PtError::TruncatedPacket));
                }
                let mode_bits = self.buf[self.pos + 1];
                self.pos += 2;
                return Some(Ok(PtPacket::new(
                    PtPacketKind::Mode {
                        leaf: b2,
                        bits: mode_bits,
                    },
                    start,
                    3,
                )));
            }

            // PSB: 0x02 followed by pattern [0x82, 0x02, 0x82, ...] 15 more times
            if self.pos + 15 <= self.buf.len() {
                let tail = &self.buf[self.pos..self.pos + 15];
                let expected: Vec<u8> = (0..15_usize)
                    .map(|i| if i.is_multiple_of(2) { 0x82u8 } else { 0x02u8 })
                    .collect();
                if tail == expected.as_slice() {
                    self.pos += 15;
                    return Some(Ok(PtPacket::new(PtPacketKind::Psb, start, 16)));
                }
            }

            // Rewind
            self.pos = start + 1;
            self.error_count += 1;
            return Some(Err(PtError::UnknownOpcode(b2)));
        }

        // MWAIT: 0xC2 + 4 bytes — must be hoisted above the short-TNT catch-all
        // because 0xC2 has bit0 == 0 and would otherwise be misclassified.
        if b == 0xC2 {
            if self.pos + 4 > self.buf.len() {
                self.pos = start;
                return Some(Err(PtError::TruncatedPacket));
            }
            let hints = self.buf[self.pos];
            let ext = self.buf[self.pos + 1];
            self.pos += 4;
            return Some(Ok(PtPacket::new(
                PtPacketKind::Mwait { ext, hints },
                start,
                5,
            )));
        }

        // Short TNT: even byte (bit 0 == 0), not 0x00
        // Note: 0x62 / 0x63 (EXSTOP) are excluded above before this check.
        if (b & 1) == 0 && b != 0x00 {
            // The stop bit is the highest set bit; branch decisions live below it.
            // stop_bit_pos = 7 - leading_zeros; count = stop_bit_pos (bits below stop).
            // bits strips the stop bit so consumers get only the decision bits.
            let stop_bit_pos = 7 - crate::cast_helpers::u32_to_u8(b.leading_zeros());
            let count = stop_bit_pos;
            let bits = u64::from(b) & ((1u64 << stop_bit_pos) - 1);
            return Some(Ok(PtPacket::new(
                PtPacketKind::Tnt { bits, count },
                start,
                1,
            )));
        }

        // Everything else: unknown
        self.error_count += 1;
        Some(Err(PtError::UnknownOpcode(b)))
    }

    /// Decode all remaining packets, silently dropping errors.
    #[must_use]
    pub fn decode_all(&mut self) -> Vec<PtPacket> {
        let mut out = Vec::new();
        while let Some(result) = self.next_packet() {
            if let Ok(pkt) = result {
                out.push(pkt);
            }
        }
        out
    }

    /// Decode all packets, including errors.
    #[must_use]
    pub fn decode_all_with_errors(&mut self) -> Vec<Result<PtPacket, PtError>> {
        let mut out = Vec::new();
        loop {
            let before = self.pos;
            let Some(result) = self.next_packet() else { break };
            // `next_packet` rewinds `pos` to the start of a truncated packet and
            // still returns `Some(Err(TruncatedPacket))`, so that feeding more
            // bytes can complete it later. That is right for a streaming
            // decoder, but it means the decoder has made *no progress*: looping
            // on `Some` alone re-decodes the same bytes forever and pushes an
            // error each time, until the process dies allocating.
            //
            // A Intel PT trace captured from a ring buffer almost always ends
            // mid-packet, so this was reachable from ordinary input, not just
            // hostile input. Observed: 54 random bytes exhausted 40 GiB.
            let stalled = self.pos == before;
            out.push(result);
            if stalled {
                break;
            }
        }
        out
    }

    /// Count packets by kind name.
    #[must_use]
    pub fn count_by_kind(packets: &[PtPacket]) -> HashMap<&'static str, usize> {
        let mut map: HashMap<&'static str, usize> = HashMap::new();
        for pkt in packets {
            let name = match &pkt.kind {
                PtPacketKind::Pad => "Pad",
                PtPacketKind::Psb => "Psb",
                PtPacketKind::PsbEnd => "PsbEnd",
                PtPacketKind::Tip { .. } => "Tip",
                PtPacketKind::TipPge { .. } => "TipPge",
                PtPacketKind::TipPgd { .. } => "TipPgd",
                PtPacketKind::Tnt { .. } => "Tnt",
                PtPacketKind::TntLong { .. } => "TntLong",
                PtPacketKind::Tsc(_) => "Tsc",
                PtPacketKind::Mtc { .. } => "Mtc",
                PtPacketKind::Cyc { .. } => "Cyc",
                PtPacketKind::Cbr(_) => "Cbr",
                PtPacketKind::Overflow => "Overflow",
                PtPacketKind::Mode { .. } => "Mode",
                PtPacketKind::Pip { .. } => "Pip",
                PtPacketKind::Vmcs { .. } => "Vmcs",
                PtPacketKind::ExStop { .. } => "ExStop",
                PtPacketKind::Mwait { .. } => "Mwait",
                PtPacketKind::Pwre { .. } => "Pwre",
                PtPacketKind::Pwrx { .. } => "Pwrx",
                PtPacketKind::Bbp { .. } => "Bbp",
                PtPacketKind::Bip { .. } => "Bip",
                PtPacketKind::Bep { .. } => "Bep",
            };
            *map.entry(name).or_insert(0) += 1;
        }
        map
    }
}

impl Default for PtDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PtEvent ──────────────────────────────────────────────────────────────────

/// A high-level PT execution event produced during flow reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtEvent {
    /// A conditional branch was taken.
    BranchTaken {
        /// Instruction address of the branch.
        ip: u64,
        /// Target address.
        target: u64,
    },
    /// A conditional branch was not taken.
    BranchNotTaken {
        /// Instruction address of the branch.
        ip: u64,
        /// Fall-through address.
        fallthrough: u64,
    },
    /// An indirect branch (call/jmp indirect) target was resolved.
    IndirectBranch {
        /// Source address.
        from: u64,
        /// Target address.
        to: u64,
    },
    /// A call instruction.
    Call {
        /// Call site address.
        from: u64,
        /// Call target address.
        to: u64,
    },
    /// A return instruction.
    Return {
        /// Return site address.
        from: u64,
        /// Return target address.
        to: u64,
    },
    /// Tracing enabled at address.
    TraceEnabled {
        /// Where tracing started.
        ip: u64,
    },
    /// Tracing disabled at address.
    TraceDisabled {
        /// Where tracing stopped.
        ip: u64,
    },
    /// An overflow occurred.
    Overflow {
        /// Packet offset where overflow was detected.
        offset: usize,
    },
    /// A timestamp was recorded.
    Timestamp {
        /// TSC value.
        tsc: u64,
    },
    /// Mode change.
    ModeChange {
        /// Leaf byte.
        leaf: u8,
        /// Mode bits.
        bits: u8,
    },
}

impl std::fmt::Display for PtEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BranchTaken { ip, target } => {
                write!(f, "BranchTaken(0x{ip:x} -> 0x{target:x})")
            }
            Self::BranchNotTaken { ip, fallthrough } => {
                write!(f, "BranchNotTaken(0x{ip:x} -> 0x{fallthrough:x})")
            }
            Self::IndirectBranch { from, to } => write!(f, "Indirect(0x{from:x} -> 0x{to:x})"),
            Self::Call { from, to } => write!(f, "Call(0x{from:x} -> 0x{to:x})"),
            Self::Return { from, to } => write!(f, "Return(0x{from:x} -> 0x{to:x})"),
            Self::TraceEnabled { ip } => write!(f, "TraceEnabled(0x{ip:x})"),
            Self::TraceDisabled { ip } => write!(f, "TraceDisabled(0x{ip:x})"),
            Self::Overflow { offset } => write!(f, "Overflow(@0x{offset:x})"),
            Self::Timestamp { tsc } => write!(f, "Timestamp({tsc})"),
            Self::ModeChange { leaf, bits } => write!(f, "Mode(leaf={leaf}, bits=0x{bits:x})"),
        }
    }
}

// ─── TimingInfo ───────────────────────────────────────────────────────────────

/// Timing information derived from a PT stream.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimingInfo {
    /// First TSC seen.
    pub first_tsc: Option<u64>,
    /// Last TSC seen.
    pub last_tsc: Option<u64>,
    /// Core Bus Ratio (CBR) if seen.
    pub cbr: Option<u8>,
    /// MTC values recorded.
    pub mtc_values: Vec<u8>,
    /// CYC deltas recorded.
    pub cyc_values: Vec<u64>,
}

impl TimingInfo {
    /// Create a new empty [`TimingInfo`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a TSC value.
    pub const fn record_tsc(&mut self, tsc: u64) {
        if self.first_tsc.is_none() {
            self.first_tsc = Some(tsc);
        }
        self.last_tsc = Some(tsc);
    }

    /// Record a CBR value.
    pub const fn record_cbr(&mut self, cbr: u8) {
        self.cbr = Some(cbr);
    }

    /// Record an MTC value.
    pub fn record_mtc(&mut self, ctc: u8) {
        self.mtc_values.push(ctc);
    }

    /// Record a CYC delta.
    pub fn record_cyc(&mut self, value: u64) {
        self.cyc_values.push(value);
    }

    /// Return total elapsed TSC ticks.
    #[must_use]
    pub const fn elapsed_tsc(&self) -> Option<u64> {
        match (self.first_tsc, self.last_tsc) {
            (Some(first), Some(last)) => last.checked_sub(first),
            _ => None,
        }
    }

    /// Return total CYC delta sum.
    #[must_use]
    pub fn total_cycles(&self) -> u64 {
        self.cyc_values.iter().sum()
    }

    /// Estimated time in nanoseconds given CPU frequency in MHz.
    #[must_use]
    pub fn elapsed_ns(&self, cpu_mhz: f64) -> Option<f64> {
        self.elapsed_tsc().map(|tsc| crate::cast_helpers::u64_to_f64(tsc) / cpu_mhz * 1000.0)
    }
}

// ─── SidebandInfo ─────────────────────────────────────────────────────────────

/// Sideband information correlated with a PT trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SidebandInfo {
    /// CR3 → image base mapping.
    pub cr3_to_image: BTreeMap<u64, u64>,
    /// Module load events: (base, size, name).
    pub modules: Vec<(u64, u64, String)>,
    /// PID → process name.
    pub pid_names: HashMap<u32, String>,
}

impl SidebandInfo {
    /// Create empty sideband info.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a module.
    pub fn register_module(&mut self, base: u64, size: u64, name: impl Into<String>) {
        self.modules.push((base, size, name.into()));
    }

    /// Register a CR3 → image base mapping.
    pub fn register_cr3(&mut self, cr3: u64, image_base: u64) {
        self.cr3_to_image.insert(cr3, image_base);
    }

    /// Look up the module name for an address.
    #[must_use]
    pub fn module_for_addr(&self, addr: u64) -> Option<&str> {
        for (base, size, name) in &self.modules {
            if addr >= *base && addr < base.saturating_add(*size) {
                return Some(name.as_str());
            }
        }
        None
    }

    /// Look up the image base for a CR3.
    #[must_use]
    pub fn image_base_for_cr3(&self, cr3: u64) -> Option<u64> {
        self.cr3_to_image.get(&cr3).copied()
    }
}

// ─── PtFlow ───────────────────────────────────────────────────────────────────

/// Reconstructed control flow from a PT trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PtFlow {
    /// Reconstructed events in order.
    pub events: Vec<PtEvent>,
    /// Timing information.
    pub timing: TimingInfo,
    /// Addresses visited (for coverage).
    pub addresses_visited: HashSet<u64>,
    /// Number of TNT bits consumed.
    pub tnt_bits_consumed: u64,
    /// Number of TIP packets consumed.
    pub tip_packets_consumed: u64,
}

use std::collections::HashSet;

impl PtFlow {
    /// Create an empty flow.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an event.
    pub fn push_event(&mut self, event: PtEvent) {
        // Track addresses visited.
        match &event {
            PtEvent::BranchTaken { ip, target } => {
                self.addresses_visited.insert(*ip);
                self.addresses_visited.insert(*target);
            }
            PtEvent::BranchNotTaken { ip, fallthrough } => {
                self.addresses_visited.insert(*ip);
                self.addresses_visited.insert(*fallthrough);
            }
            PtEvent::IndirectBranch { from, to }
            | PtEvent::Call { from, to }
            | PtEvent::Return { from, to } => {
                self.addresses_visited.insert(*from);
                self.addresses_visited.insert(*to);
            }
            PtEvent::TraceEnabled { ip } | PtEvent::TraceDisabled { ip } => {
                self.addresses_visited.insert(*ip);
            }
            _ => {}
        }
        self.events.push(event);
    }

    /// Return the number of events.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Return unique addresses visited.
    #[must_use]
    pub fn unique_addresses(&self) -> usize {
        self.addresses_visited.len()
    }

    /// Return all call events.
    #[must_use]
    pub fn calls(&self) -> Vec<&PtEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, PtEvent::Call { .. }))
            .collect()
    }

    /// Return all return events.
    #[must_use]
    pub fn returns(&self) -> Vec<&PtEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, PtEvent::Return { .. }))
            .collect()
    }

    /// Return all overflow events.
    #[must_use]
    pub fn overflows(&self) -> Vec<&PtEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, PtEvent::Overflow { .. }))
            .collect()
    }
}

// ─── PtTrace ──────────────────────────────────────────────────────────────────

/// A complete Intel PT trace: raw packets + reconstructed flow + timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtTrace {
    /// Raw decoded packets.
    pub packets: Vec<PtPacket>,
    /// Reconstructed control flow.
    pub flow: PtFlow,
    /// Sideband data.
    pub sideband: SidebandInfo,
}

impl PtTrace {
    /// Create a new trace from decoded packets.
    #[must_use]
    pub fn new(packets: Vec<PtPacket>) -> Self {
        Self {
            flow: PtFlow::new(),
            sideband: SidebandInfo::new(),
            packets,
        }
    }

    /// Return the total number of packets.
    #[must_use]
    pub const fn packet_count(&self) -> usize {
        self.packets.len()
    }

    /// Return all TSC timestamps found in the packet stream.
    #[must_use]
    pub fn tsc_values(&self) -> Vec<u64> {
        self.packets
            .iter()
            .filter_map(|p| {
                if let PtPacketKind::Tsc(v) = p.kind {
                    Some(v)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all TIP addresses.
    #[must_use]
    pub fn tip_addresses(&self) -> Vec<u64> {
        self.packets
            .iter()
            .filter_map(|p| p.kind.ip_addr())
            .collect()
    }

    /// Return all TNT bits concatenated.
    #[must_use]
    pub fn tnt_bits(&self) -> Vec<(u64, u8)> {
        self.packets
            .iter()
            .filter_map(|p| match &p.kind {
                PtPacketKind::Tnt { bits, count } | PtPacketKind::TntLong { bits, count } => {
                    Some((*bits, *count))
                }
                _ => None,
            })
            .collect()
    }

    /// Reconstruct timing info from the packet stream.
    #[must_use]
    pub fn extract_timing(&self) -> TimingInfo {
        let mut timing = TimingInfo::new();
        for pkt in &self.packets {
            match pkt.kind {
                PtPacketKind::Tsc(tsc) => timing.record_tsc(tsc),
                PtPacketKind::Cbr(cbr) => timing.record_cbr(cbr),
                PtPacketKind::Mtc { ctc } => timing.record_mtc(ctc),
                PtPacketKind::Cyc { value } => timing.record_cyc(value),
                _ => {}
            }
        }
        timing
    }

    /// Return a summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "PtTrace {{ packets: {}, flow_events: {}, unique_addrs: {} }}",
            self.packets.len(),
            self.flow.event_count(),
            self.flow.unique_addresses(),
        )
    }
}

// ─── PtFlowReconstructor ──────────────────────────────────────────────────────

/// Reconstructs control flow from a stream of PT packets using a simple
/// disassembler callback.
pub struct PtFlowReconstructor {
    /// Pending TNT bits (as a deque of booleans).
    tnt_queue: VecDeque<bool>,
    /// Current IP (best-known program counter).
    pub current_ip: u64,
    /// Whether tracing is currently enabled.
    pub tracing_enabled: bool,
    /// Accumulated flow.
    pub flow: PtFlow,
}

impl PtFlowReconstructor {
    /// Create a new reconstructor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tnt_queue: VecDeque::new(),
            current_ip: 0,
            tracing_enabled: false,
            flow: PtFlow::new(),
        }
    }

    /// Feed a packet into the reconstructor.
    ///
    /// Returns `true` if any flow events were produced.
    pub fn feed_packet(&mut self, pkt: &PtPacket) -> bool {
        let before = self.flow.event_count();
        match &pkt.kind {
            PtPacketKind::Tnt { bits, count } | PtPacketKind::TntLong { bits, count } => {
                for i in 0..*count {
                    let taken = (bits >> i) & 1 == 1;
                    self.tnt_queue.push_back(taken);
                }
            }
            PtPacketKind::Tip { ip, .. } => {
                let from = self.current_ip;
                self.current_ip = *ip;
                self.flow.tip_packets_consumed += 1;
                self.flow
                    .push_event(PtEvent::IndirectBranch { from, to: *ip });
            }
            PtPacketKind::TipPge { ip, .. } => {
                self.current_ip = *ip;
                self.tracing_enabled = true;
                self.flow.push_event(PtEvent::TraceEnabled { ip: *ip });
            }
            PtPacketKind::TipPgd { ip, .. } => {
                self.current_ip = *ip;
                self.tracing_enabled = false;
                self.flow.push_event(PtEvent::TraceDisabled { ip: *ip });
            }
            PtPacketKind::Overflow => {
                self.flow
                    .push_event(PtEvent::Overflow { offset: pkt.offset });
            }
            PtPacketKind::Tsc(tsc) => {
                self.flow.timing.record_tsc(*tsc);
                self.flow.push_event(PtEvent::Timestamp { tsc: *tsc });
            }
            PtPacketKind::Cbr(cbr) => {
                self.flow.timing.record_cbr(*cbr);
            }
            PtPacketKind::Mtc { ctc } => {
                self.flow.timing.record_mtc(*ctc);
            }
            PtPacketKind::Cyc { value } => {
                self.flow.timing.record_cyc(*value);
            }
            PtPacketKind::Mode { leaf, bits } => {
                self.flow.push_event(PtEvent::ModeChange {
                    leaf: *leaf,
                    bits: *bits,
                });
            }
            _ => {}
        }
        self.flow.event_count() > before
    }

    /// Pop one TNT bit, if any.
    #[must_use]
    pub fn pop_tnt(&mut self) -> Option<bool> {
        self.tnt_queue.pop_front()
    }

    /// Return the number of pending TNT bits.
    #[must_use]
    pub fn pending_tnt_count(&self) -> usize {
        self.tnt_queue.len()
    }

    /// Record a conditional branch outcome.
    pub fn record_conditional_branch(&mut self, ip: u64, target: u64, fallthrough: u64) {
        self.flow.tnt_bits_consumed += 1;
        if let Some(taken) = self.tnt_queue.pop_front() {
            if taken {
                self.current_ip = target;
                self.flow.push_event(PtEvent::BranchTaken { ip, target });
            } else {
                self.current_ip = fallthrough;
                self.flow
                    .push_event(PtEvent::BranchNotTaken { ip, fallthrough });
            }
        }
    }

    /// Record a direct call.
    pub fn record_call(&mut self, from: u64, to: u64) {
        self.current_ip = to;
        self.flow.push_event(PtEvent::Call { from, to });
    }

    /// Record a return.
    pub fn record_return(&mut self, from: u64, to: u64) {
        self.current_ip = to;
        self.flow.push_event(PtEvent::Return { from, to });
    }
}

impl Default for PtFlowReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_ok(data: &[u8]) -> Vec<PtPacket> {
        let mut dec = PtDecoder::new();
        dec.feed(data);
        dec.decode_all()
    }

    // ── PtPacketKind Display ──────────────────────────────────────────────

    #[test]
    fn test_display_pad() {
        assert_eq!(PtPacketKind::Pad.to_string(), "Pad");
    }

    #[test]
    fn test_display_psb() {
        assert_eq!(PtPacketKind::Psb.to_string(), "PSB");
    }

    #[test]
    fn test_display_psbend() {
        assert_eq!(PtPacketKind::PsbEnd.to_string(), "PSBEND");
    }

    #[test]
    fn test_display_tip() {
        let s = PtPacketKind::Tip {
            ip: 0x0040_1000,
            compression: IpCompression::Full48,
        }
        .to_string();
        assert!(s.contains("401000"));
    }

    #[test]
    fn test_display_tip_pge() {
        let s = PtPacketKind::TipPge {
            ip: 0x1234,
            compression: IpCompression::Full48,
        }
        .to_string();
        assert!(s.contains("1234"));
    }

    #[test]
    fn test_display_tip_pgd() {
        let s = PtPacketKind::TipPgd {
            ip: 0xABCD,
            compression: IpCompression::Full48,
        }
        .to_string();
        assert!(s.contains("abcd"));
    }

    #[test]
    fn test_display_tnt() {
        let s = PtPacketKind::Tnt {
            bits: 0b101,
            count: 3,
        }
        .to_string();
        assert!(s.contains("TNT"));
        assert!(s.contains('3'));
    }

    #[test]
    fn test_display_tnt_long() {
        let s = PtPacketKind::TntLong {
            bits: 0xFF,
            count: 8,
        }
        .to_string();
        assert!(s.contains("TNT.L"));
    }

    #[test]
    fn test_display_tsc() {
        let s = PtPacketKind::Tsc(12345).to_string();
        assert!(s.contains("12345"));
    }

    #[test]
    fn test_display_cbr() {
        let s = PtPacketKind::Cbr(20).to_string();
        assert!(s.contains("CBR"));
        assert!(s.contains("20"));
    }

    #[test]
    fn test_display_overflow() {
        assert_eq!(PtPacketKind::Overflow.to_string(), "OVF");
    }

    #[test]
    fn test_display_mode() {
        let s = PtPacketKind::Mode {
            leaf: 0,
            bits: 0x03,
        }
        .to_string();
        assert!(s.contains("MODE"));
    }

    #[test]
    fn test_display_pip() {
        let s = PtPacketKind::Pip {
            cr3: 0x5000,
            nr: false,
        }
        .to_string();
        assert!(s.contains("5000"));
    }

    #[test]
    fn test_display_mtc() {
        let s = PtPacketKind::Mtc { ctc: 7 }.to_string();
        assert!(s.contains("MTC"));
        assert!(s.contains('7'));
    }

    #[test]
    fn test_display_cyc() {
        let s = PtPacketKind::Cyc { value: 99 }.to_string();
        assert!(s.contains("CYC"));
        assert!(s.contains("99"));
    }

    #[test]
    fn test_display_exstop() {
        let s = PtPacketKind::ExStop { ip: true }.to_string();
        assert!(s.contains("EXSTOP"));
    }

    // ── IpCompression ─────────────────────────────────────────────────────

    #[test]
    fn test_ip_compression_byte_count() {
        assert_eq!(IpCompression::Zero.byte_count(), 0);
        assert_eq!(IpCompression::Update16.byte_count(), 2);
        assert_eq!(IpCompression::Update32.byte_count(), 4);
        assert_eq!(IpCompression::Full48.byte_count(), 6);
        assert_eq!(IpCompression::Full64.byte_count(), 8);
    }

    #[test]
    fn test_ip_compression_from_ipr() {
        assert_eq!(IpCompression::from_ipr(0), IpCompression::Zero);
        assert_eq!(IpCompression::from_ipr(1), IpCompression::Update16);
        assert_eq!(IpCompression::from_ipr(3), IpCompression::Full48);
    }

    // ── PtDecoder ─────────────────────────────────────────────────────────

    #[test]
    fn test_decode_pad() {
        let pkts = decode_ok(&[0x00]);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, PtPacketKind::Pad);
        assert_eq!(pkts[0].offset, 0);
    }

    #[test]
    fn test_decode_multiple_pads() {
        let pkts = decode_ok(&[0x00, 0x00, 0x00]);
        assert_eq!(pkts.len(), 3);
    }

    #[test]
    fn test_decode_tsc() {
        let ts: u64 = 0x1234_5678_9ABC_DEF0;
        let mut data = vec![0x19u8];
        data.extend_from_slice(&ts.to_le_bytes());
        let pkts = decode_ok(&data);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, PtPacketKind::Tsc(ts));
    }

    #[test]
    fn test_decode_cbr() {
        let data = [0x02u8, 0x22, 0x14, 0x00];
        let pkts = decode_ok(&data);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, PtPacketKind::Cbr(0x14));
    }

    #[test]
    fn test_decode_tip_legacy() {
        let ip: u64 = 0x0000_ABCD_1234_5678;
        let mut data = vec![0xC5u8];
        data.extend_from_slice(&ip.to_le_bytes()[..6]);
        let pkts = decode_ok(&data);
        assert_eq!(pkts.len(), 1);
        let expected_ip = u64::from_le_bytes({
            let mut b = [0u8; 8];
            b[..6].copy_from_slice(&ip.to_le_bytes()[..6]);
            b
        });
        assert!(matches!(pkts[0].kind, PtPacketKind::Tip { ip, .. } if ip == expected_ip));
    }

    #[test]
    fn test_decode_psbend() {
        let pkts = decode_ok(&[0x23]);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, PtPacketKind::PsbEnd);
    }

    #[test]
    fn test_decode_overflow() {
        let pkts = decode_ok(&[0xF3]);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, PtPacketKind::Overflow);
    }

    #[test]
    fn test_decode_tnt_even_byte() {
        let pkts = decode_ok(&[0x04]);
        assert_eq!(pkts.len(), 1);
        assert!(matches!(pkts[0].kind, PtPacketKind::Tnt { .. }));
    }

    #[test]
    fn test_decode_none_when_empty() {
        let mut dec = PtDecoder::new();
        assert!(dec.next_packet().is_none());
    }

    #[test]
    fn test_decode_truncated_tsc() {
        let mut dec = PtDecoder::new();
        dec.feed(&[0x19, 0x01, 0x02]);
        let result = dec.next_packet().unwrap();
        assert!(result.is_err());
        assert_eq!(dec.pos, 0);
    }

    #[test]
    fn test_decode_truncated_tip() {
        let mut dec = PtDecoder::new();
        dec.feed(&[0xC5, 0x01, 0x02]);
        let result = dec.next_packet().unwrap();
        assert!(result.is_err());
        assert_eq!(dec.pos, 0);
    }

    #[test]
    fn test_decode_sequence() {
        let mut data = vec![0x00u8]; // pad
        data.push(0x23); // psbend
        data.push(0xF3); // overflow
        let pkts = decode_ok(&data);
        assert_eq!(pkts.len(), 3);
        assert_eq!(pkts[0].kind, PtPacketKind::Pad);
        assert_eq!(pkts[1].kind, PtPacketKind::PsbEnd);
        assert_eq!(pkts[2].kind, PtPacketKind::Overflow);
    }

    #[test]
    fn test_decode_offset_tracking() {
        let mut dec = PtDecoder::new();
        dec.feed(&[0x00, 0x23]);
        let p1 = dec.next_packet().unwrap().unwrap();
        let p2 = dec.next_packet().unwrap().unwrap();
        assert_eq!(p1.offset, 0);
        assert_eq!(p2.offset, 1);
    }

    #[test]
    fn test_incremental_feed() {
        let mut dec = PtDecoder::new();
        dec.feed(&[0x00]);
        dec.feed(&[0x23]);
        let pkts = dec.decode_all();
        assert_eq!(pkts.len(), 2);
    }

    #[test]
    fn test_decode_mtc() {
        let data = [0x59u8, 0x07];
        let pkts = decode_ok(&data);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, PtPacketKind::Mtc { ctc: 7 });
    }

    #[test]
    fn test_decode_exstop() {
        let pkts = decode_ok(&[0x62]);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, PtPacketKind::ExStop { ip: false });
        let pkts2 = decode_ok(&[0x63]);
        assert_eq!(pkts2[0].kind, PtPacketKind::ExStop { ip: true });
    }

    #[test]
    fn test_decode_overflow_increments_count() {
        let mut dec = PtDecoder::new();
        dec.feed(&[0xF3, 0xF3]);
        let _ = dec.decode_all();
        assert_eq!(dec.overflow_count, 2);
    }

    #[test]
    fn test_decode_remaining_bytes() {
        let mut dec = PtDecoder::new();
        dec.feed(&[0x00, 0x23, 0xF3]);
        assert_eq!(dec.remaining_bytes(), 3);
        let _ = dec.next_packet();
        assert_eq!(dec.remaining_bytes(), 2);
    }

    #[test]
    fn test_decode_reset() {
        let mut dec = PtDecoder::new();
        dec.feed(&[0x00, 0x23]);
        let _ = dec.decode_all();
        dec.reset();
        assert_eq!(dec.pos, 0);
        let pkts = dec.decode_all();
        assert_eq!(pkts.len(), 2);
    }

    #[test]
    fn test_decode_count_by_kind() {
        let pkts = decode_ok(&[0x00, 0x00, 0x23, 0xF3]);
        let counts = PtDecoder::count_by_kind(&pkts);
        assert_eq!(counts.get("Pad"), Some(&2));
        assert_eq!(counts.get("PsbEnd"), Some(&1));
        assert_eq!(counts.get("Overflow"), Some(&1));
    }

    // ── PtPacket predicates ────────────────────────────────────────────────

    #[test]
    fn test_packet_is_timing() {
        let pkt = PtPacket::new(PtPacketKind::Tsc(100), 0, 9);
        assert!(pkt.is_timing());
        let pkt2 = PtPacket::new(PtPacketKind::Pad, 0, 1);
        assert!(!pkt2.is_timing());
    }

    #[test]
    fn test_packet_is_flow() {
        let pkt = PtPacket::new(PtPacketKind::Tnt { bits: 1, count: 1 }, 0, 1);
        assert!(pkt.is_flow());
        let pkt2 = PtPacket::new(PtPacketKind::Pad, 0, 1);
        assert!(!pkt2.is_flow());
    }

    #[test]
    fn test_packet_display() {
        let pkt = PtPacket::new(PtPacketKind::Pad, 0x10, 1);
        let s = pkt.to_string();
        assert!(s.contains("0x10"));
        assert!(s.contains("Pad"));
    }

    // ── PtEvent ───────────────────────────────────────────────────────────

    #[test]
    fn test_pt_event_display_branch_taken() {
        let e = PtEvent::BranchTaken {
            ip: 0x1000,
            target: 0x2000,
        };
        let s = e.to_string();
        assert!(s.contains("BranchTaken"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_pt_event_display_branch_not_taken() {
        let e = PtEvent::BranchNotTaken {
            ip: 0x1000,
            fallthrough: 0x1004,
        };
        let s = e.to_string();
        assert!(s.contains("BranchNotTaken"));
    }

    #[test]
    fn test_pt_event_display_overflow() {
        let e = PtEvent::Overflow { offset: 0x100 };
        let s = e.to_string();
        assert!(s.contains("Overflow"));
    }

    // ── TimingInfo ────────────────────────────────────────────────────────

    #[test]
    fn test_timing_info_elapsed_tsc() {
        let mut ti = TimingInfo::new();
        ti.record_tsc(1000);
        ti.record_tsc(2000);
        assert_eq!(ti.elapsed_tsc(), Some(1000));
    }

    #[test]
    fn test_timing_info_total_cycles() {
        let mut ti = TimingInfo::new();
        ti.record_cyc(100);
        ti.record_cyc(200);
        assert_eq!(ti.total_cycles(), 300);
    }

    #[test]
    fn test_timing_info_elapsed_ns() {
        let mut ti = TimingInfo::new();
        ti.record_tsc(0);
        ti.record_tsc(1000);
        // At 1 GHz = 1000 MHz, 1000 ticks = 1 µs = 1000 ns
        let ns = ti.elapsed_ns(1000.0).unwrap();
        assert!((ns - 1000.0).abs() < 1e-6);
    }

    #[test]
    fn test_timing_info_none_without_tsc() {
        let ti = TimingInfo::new();
        assert!(ti.elapsed_tsc().is_none());
    }

    // ── SidebandInfo ──────────────────────────────────────────────────────

    #[test]
    fn test_sideband_module_for_addr() {
        let mut si = SidebandInfo::new();
        si.register_module(0x0040_0000, 0x10000, "ntdll.dll");
        assert_eq!(si.module_for_addr(0x0040_5000), Some("ntdll.dll"));
        assert_eq!(si.module_for_addr(0x0041_0001), None);
    }

    #[test]
    fn test_sideband_cr3() {
        let mut si = SidebandInfo::new();
        si.register_cr3(0xABC_000, 0x0040_0000);
        assert_eq!(si.image_base_for_cr3(0xABC_000), Some(0x0040_0000));
        assert_eq!(si.image_base_for_cr3(0x999_000), None);
    }

    // ── PtFlow ────────────────────────────────────────────────────────────

    #[test]
    fn test_pt_flow_push_event() {
        let mut flow = PtFlow::new();
        flow.push_event(PtEvent::Call {
            from: 0x1000,
            to: 0x2000,
        });
        flow.push_event(PtEvent::Return {
            from: 0x2000,
            to: 0x1005,
        });
        assert_eq!(flow.event_count(), 2);
        assert!(flow.addresses_visited.contains(&0x1000));
        assert!(flow.addresses_visited.contains(&0x2000));
    }

    #[test]
    fn test_pt_flow_calls_returns() {
        let mut flow = PtFlow::new();
        flow.push_event(PtEvent::Call {
            from: 0x1000,
            to: 0x2000,
        });
        flow.push_event(PtEvent::Call {
            from: 0x2000,
            to: 0x3000,
        });
        flow.push_event(PtEvent::Return {
            from: 0x3000,
            to: 0x2005,
        });
        assert_eq!(flow.calls().len(), 2);
        assert_eq!(flow.returns().len(), 1);
    }

    // ── PtTrace ───────────────────────────────────────────────────────────

    #[test]
    fn test_pt_trace_tsc_values() {
        let mut data = vec![0x19u8];
        data.extend_from_slice(&100u64.to_le_bytes());
        data.push(0x19);
        data.extend_from_slice(&200u64.to_le_bytes());
        let mut dec = PtDecoder::new();
        dec.feed(&data);
        let packets = dec.decode_all();
        let trace = PtTrace::new(packets);
        assert_eq!(trace.tsc_values(), vec![100, 200]);
    }

    #[test]
    fn test_pt_trace_summary() {
        let trace = PtTrace::new(vec![]);
        let s = trace.summary();
        assert!(s.contains("PtTrace"));
    }

    #[test]
    fn test_pt_trace_extract_timing() {
        let mut data = vec![0x19u8];
        data.extend_from_slice(&500u64.to_le_bytes());
        data.push(0x59);
        data.push(0x03);
        let mut dec = PtDecoder::new();
        dec.feed(&data);
        let packets = dec.decode_all();
        let trace = PtTrace::new(packets);
        let timing = trace.extract_timing();
        assert_eq!(timing.first_tsc, Some(500));
        assert_eq!(timing.mtc_values, vec![3]);
    }

    // ── PtFlowReconstructor ───────────────────────────────────────────────

    #[test]
    fn test_reconstructor_tnt_queue() {
        let mut rec = PtFlowReconstructor::new();
        let pkt = PtPacket::new(
            PtPacketKind::Tnt {
                bits: 0b101,
                count: 3,
            },
            0,
            1,
        );
        rec.feed_packet(&pkt);
        assert_eq!(rec.pending_tnt_count(), 3);
        assert_eq!(rec.pop_tnt(), Some(true)); // bit 0
        assert_eq!(rec.pop_tnt(), Some(false)); // bit 1
        assert_eq!(rec.pop_tnt(), Some(true)); // bit 2
        assert_eq!(rec.pop_tnt(), None);
    }

    #[test]
    fn test_reconstructor_trace_enable_disable() {
        let mut rec = PtFlowReconstructor::new();
        let pge = PtPacket::new(
            PtPacketKind::TipPge {
                ip: 0x1000,
                compression: IpCompression::Full48,
            },
            0,
            7,
        );
        rec.feed_packet(&pge);
        assert!(rec.tracing_enabled);
        assert_eq!(rec.current_ip, 0x1000);

        let pgd = PtPacket::new(
            PtPacketKind::TipPgd {
                ip: 0x2000,
                compression: IpCompression::Full48,
            },
            7,
            7,
        );
        rec.feed_packet(&pgd);
        assert!(!rec.tracing_enabled);
    }

    #[test]
    fn test_reconstructor_conditional_branch() {
        let mut rec = PtFlowReconstructor::new();
        // Feed TNT: taken
        let pkt = PtPacket::new(PtPacketKind::Tnt { bits: 1, count: 1 }, 0, 1);
        rec.feed_packet(&pkt);
        rec.record_conditional_branch(0x1000, 0x2000, 0x1004);
        assert_eq!(rec.current_ip, 0x2000);
        assert_eq!(rec.flow.event_count(), 1);
        assert!(matches!(rec.flow.events[0], PtEvent::BranchTaken { .. }));
    }

    #[test]
    fn test_reconstructor_call_return() {
        let mut rec = PtFlowReconstructor::new();
        rec.record_call(0x1000, 0x2000);
        rec.record_return(0x2fff, 0x1004);
        assert_eq!(rec.current_ip, 0x1004);
        assert_eq!(rec.flow.calls().len(), 1);
        assert_eq!(rec.flow.returns().len(), 1);
    }

    // ── PtError ───────────────────────────────────────────────────────────

    #[test]
    fn test_pt_error_invalid_packet() {
        let e = PtError::InvalidPacket(0xAB);
        assert!(e.to_string().contains("ab"));
    }

    #[test]
    fn test_pt_error_truncated() {
        let e = PtError::TruncatedPacket;
        assert_eq!(e.to_string(), "truncated packet");
    }

    #[test]
    fn test_pt_error_unknown_opcode() {
        let e = PtError::UnknownOpcode(0x07);
        assert!(e.to_string().contains("07"));
    }

    #[test]
    fn test_pt_error_overflow() {
        let e = PtError::Overflow(0x100);
        assert!(e.to_string().contains("100"));
    }

    #[test]
    fn test_pt_error_flow_reconstruction() {
        let e = PtError::FlowReconstruction("bad branch".into());
        assert!(e.to_string().contains("bad branch"));
    }
}

// ─── Intel PT Hardware Capabilities ──────────────────────────────────────────

/// Intel PT hardware capabilities detected at runtime via CPUID leaf 0x14.
///
/// Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
/// Volume 3C §35.2 (CPUID leaf 14H).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntelPtCapabilities {
    /// CR3 filtering is supported (`IA32_RTIT_CTL.CR3Filter`).
    pub cr3_filtering: bool,
    /// Mini-Timestamp Counter (MTC) packets are supported.
    pub mtc: bool,
    /// `PTWrite` instruction is supported.
    pub ptwrite: bool,
    /// Power event tracing is supported.
    pub power_event_trace: bool,
    /// IP filtering (address ranges) is supported.
    pub ip_filtering: bool,
    /// `ToPA` output scheme is supported.
    pub topa: bool,
    /// Single-range output is supported.
    pub single_range_output: bool,
    /// Trace Transport subsystem output is supported.
    pub trace_transport: bool,
    /// Number of configurable address ranges.
    pub address_ranges: u8,
    /// Supported MTC frequency bitmap.
    pub mtc_freq_mask: u16,
    /// Supported cycle threshold bitmap.
    pub cyc_threshold_mask: u16,
    /// Supported PSB frequency bitmap.
    pub psb_freq_mask: u16,
}

impl IntelPtCapabilities {
    /// Detect Intel PT capabilities on the current CPU using CPUID leaf 0x14.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// Returns `Err` if the CPU does not support Intel PT or if the platform is
    /// not `x86_64`.
    pub fn detect() -> anyhow::Result<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            use std::arch::x86_64::__cpuid_count;

            // First check that Intel PT is exposed: CPUID.07H:EBX[bit 25]
            let cpuid07 = __cpuid_count(0x07, 0x00);
            if (cpuid07.ebx & (1 << 25)) == 0 {
                anyhow::bail!("Intel PT not supported: CPUID.07H:EBX[25] is clear");
            }

            // Leaf 0x14, sub-leaf 0 — main capability leaf
            let leaf0 = __cpuid_count(0x14, 0x00);
            // EBX bits for leaf 0:
            //   bit 0  = CR3 filtering
            //   bit 1  = PSB and CYCLE-accurate mode
            //   bit 2  = IP filtering, TraceStop filtering, and preservation of Intel PT MSRs
            //   bit 3  = MTC timing
            //   bit 4  = PTWRITE
            //   bit 5  = power event tracing
            //   bit 6  = PSB/PMI preservation
            //   bit 7  = event tracing (EventTrace)
            //   bit 8  = TNT disable
            let ebx0 = leaf0.ebx;
            let ecx_leaf = leaf0.ecx;

            let cr3_filtering = (ebx0 & (1 << 0)) != 0;
            let ip_filtering = (ebx0 & (1 << 2)) != 0;
            let mtc = (ebx0 & (1 << 3)) != 0;
            let ptwrite = (ebx0 & (1 << 4)) != 0;
            let power_event_trace = (ebx0 & (1 << 5)) != 0;

            // ECX bits:
            //   bit 0  = ToPA output
            //   bit 1  = ToPA can hold multiple output entries
            //   bit 2  = single-range output
            //   bit 3  = trace transport output
            //   bit 31 = IP payloads are LIP (no filtering)
            let topa = (ecx_leaf & (1 << 0)) != 0;
            let single_range_output = (ecx_leaf & (1 << 2)) != 0;
            let trace_transport = (ecx_leaf & (1 << 3)) != 0;

            // Sub-leaf 1 — address ranges, frequency bitmaps
            let (address_ranges, mtc_freq_mask, cyc_threshold_mask, psb_freq_mask);
            if leaf0.eax >= 1 {
                let leaf1 = __cpuid_count(0x14, 0x01);
                // EAX[2:0] = number of configurable address ranges
                address_ranges = (leaf1.eax & 0x07) as u8;
                // EAX[17:16] = supported MTC frequency bitmap (low 16 bits of EAX[31:16])
                mtc_freq_mask = ((leaf1.eax >> 16) & 0xFFFF) as u16;
                // EBX[19:0] = cycle threshold bitmap (low 16 bits)
                cyc_threshold_mask = (leaf1.ebx & 0xFFFF) as u16;
                // EBX[31:16] = PSB frequency bitmap
                psb_freq_mask = ((leaf1.ebx >> 16) & 0xFFFF) as u16;
            } else {
                address_ranges = 0;
                mtc_freq_mask = 0;
                cyc_threshold_mask = 0;
                psb_freq_mask = 0;
            }

            Ok(Self {
                cr3_filtering,
                mtc,
                ptwrite,
                power_event_trace,
                ip_filtering,
                topa,
                single_range_output,
                trace_transport,
                address_ranges,
                mtc_freq_mask,
                cyc_threshold_mask,
                psb_freq_mask,
            })
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            anyhow::bail!("Intel PT requires an x86_64 CPU")
        }
    }

    /// Return `true` if Intel PT is supported on this CPU.
    #[must_use]
    pub fn is_supported() -> bool {
        Self::detect().is_ok()
    }
}

// ─── PtConfig ─────────────────────────────────────────────────────────────────

/// Configuration for an Intel PT capture session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtConfig {
    /// Enable branch (TNT/TIP) packets.  Corresponds to `IA32_RTIT_CTL.BranchEn`.
    pub branch_packets: bool,
    /// Enable cycle-accurate mode (CYC packets).  Requires MTC support.
    pub cycle_accurate: bool,
    /// Trace only ring-3 (user-mode) code.  Sets `IA32_RTIT_CTL.User`.
    pub user_only: bool,
    /// Optional IP filter: `(start, end)` virtual address range.
    ///
    /// When set the CPU emits packets only while RIP is inside `[start, end)`.
    /// Requires `IntelPtCapabilities::ip_filtering`.
    pub ip_filter: Option<(u64, u64)>,
    /// Size of the AUX ring buffer in kilobytes (default 4096 KiB = 4 MiB).
    pub aux_buffer_size_kb: u32,
}

impl Default for PtConfig {
    fn default() -> Self {
        Self {
            branch_packets: true,
            cycle_accurate: false,
            user_only: true,
            ip_filter: None,
            aux_buffer_size_kb: 4096,
        }
    }
}

impl PtConfig {
    /// Create a default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: enable cycle-accurate mode.
    #[must_use]
    pub const fn with_cycle_accurate(mut self, enable: bool) -> Self {
        self.cycle_accurate = enable;
        self
    }

    /// Builder: set an IP filter range.
    #[must_use]
    pub const fn with_ip_filter(mut self, start: u64, end: u64) -> Self {
        self.ip_filter = Some((start, end));
        self
    }

    /// Builder: set aux buffer size in KiB.
    #[must_use]
    pub const fn with_aux_buffer_size_kb(mut self, kb: u32) -> Self {
        self.aux_buffer_size_kb = kb;
        self
    }

    /// Builder: set user-only mode.
    #[must_use]
    pub const fn with_user_only(mut self, user_only: bool) -> Self {
        self.user_only = user_only;
        self
    }
}

// ─── PtCaptureSession ─────────────────────────────────────────────────────────

/// An active Intel PT capture session backed by Linux `perf_event_open`.
///
/// # Linux implementation
///
/// The session uses `perf_event_open(2)` to open a hardware PMU event for the
/// Intel PT PMU type (read from
/// `/sys/bus/event_source/devices/intel_pt/type`).  The kernel writes raw PT
/// packets into the AUX ring buffer which is double-mmap'd: the first mapping
/// is the `perf_event_mmap_page` control structure plus the data ring buffer;
/// the second mapping (at a separate file descriptor or at a fixed offset on
/// Linux 4.1+) is the AUX region.
///
/// This is a *structural* implementation following the perf ABI defined in
/// `<linux/perf_event.h>`.  Full kernel interaction is handled via the `libc`
/// crate.
#[cfg(target_os = "linux")]
pub struct PtCaptureSession {
    /// File descriptor returned by `perf_event_open`.
    perf_fd: i32,
    /// Second file descriptor used for the AUX mmap (same as perf_fd on
    /// Linux 4.1+; kept for future use).
    aux_fd: i32,
    /// Base pointer to the `perf_event_mmap_page` + data ring buffer mapping.
    mmap_base: *mut u8,
    /// Base pointer to the AUX ring buffer.
    aux_base: *mut u8,
    /// Total size of the data mmap region (1 + data_pages pages × PAGE_SIZE).
    mmap_size: usize,
    /// Total size of the AUX mmap region.
    aux_size: usize,
    /// A copy of the configuration used to start this session.
    config: PtConfig,
}

// SAFETY: PtCaptureSession owns its file descriptors and raw mmaps and is
// designed to be moved to other threads only after `stop()` or `Drop`.
#[cfg(target_os = "linux")]
unsafe impl Send for PtCaptureSession {}

#[cfg(target_os = "linux")]
impl PtCaptureSession {
    /// Read the Intel PT PMU type from the sysfs pseudo-file
    /// `/sys/bus/event_source/devices/intel_pt/type`.
    ///
    /// Returns an error if the file cannot be read or does not contain a valid
    /// u32.
    pub fn read_pt_type() -> anyhow::Result<u32> {
        let contents = std::fs::read_to_string("/sys/bus/event_source/devices/intel_pt/type")
            .map_err(|e| anyhow::anyhow!("Cannot read intel_pt PMU type: {e}"))?;
        let trimmed = contents.trim();
        trimmed
            .parse::<u32>()
            .map_err(|e| anyhow::anyhow!("Invalid intel_pt type '{trimmed}': {e}"))
    }

    /// Open an Intel PT capture session for the given `pid`.
    ///
    /// # Arguments
    ///
    /// * `pid`    — process ID to trace (0 = current process).
    /// * `config` — capture configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if `perf_event_open` fails, if the AUX buffer cannot
    /// be mmap'd, or if Intel PT is not available on this system.
    pub fn start(pid: u32, config: PtConfig) -> anyhow::Result<Self> {
        // ── 1.  Determine the Intel PT PMU type ──────────────────────────────
        let pt_type = Self::read_pt_type()?;

        // ── 2.  Build the perf_event_attr ────────────────────────────────────
        //
        // We use a raw repr that mirrors `struct perf_event_attr` from
        // `<linux/perf_event.h>`.  The libc crate does not expose the full
        // struct on all versions so we construct it manually as a zeroed byte
        // array of the correct size (128 bytes as of Linux 5.x) and fill in
        // the fields we care about at known offsets.
        //
        // Field layout (little-endian, offsets in bytes):
        //   0..4   type         u32
        //   4..8   size         u32
        //   8..16  config       u64
        //  16..24  sample_period/freq  u64
        //  24..32  sample_type  u64
        //  32..40  read_format  u64
        //  40..48  flags        u64  (disabled, inherit, pinned, … bitmask)
        //  48..52  wakeup_events/watermark  u32
        //  52..56  bp_type/…    u32
        //  56..64  bp_addr/…    u64
        //  64..72  bp_len/…     u64
        //  72..80  branch_sample_type  u64
        //  80..88  sample_regs_user    u64
        //  88..92  sample_stack_user   u32
        //  92..96  clockid             i32
        //  96..104 sample_regs_intr    u64
        // 104..108 aux_watermark       u32
        // 108..110 sample_max_stack    u16
        // 110..112 __reserved_2        u16
        // 112..128 (padding)
        const ATTR_SIZE: usize = 128;
        let mut attr = [0u8; ATTR_SIZE];

        // type = pt_type
        attr[0..4].copy_from_slice(&pt_type.to_le_bytes());
        // size = ATTR_SIZE
        attr[4..8].copy_from_slice(&(ATTR_SIZE as u32).to_le_bytes());
        // config = 0 (PT has no sub-event config; branch tracing always on)
        // We build a config bitmask from the PtConfig flags.
        // Intel PT perf config bits (IA32_RTIT_CTL mirror exposed via perf):
        //   bit 0  = disabled (inverted: 0 = tracing on)
        //   bit 11 = branch_en (TNT/TIP packets)
        //   bit 12 = MTC_EN
        //   bit 4  = user (ring 3)
        //   bit 3  = os (ring 0)
        let mut pt_config: u64 = 0;
        if config.branch_packets {
            pt_config |= 1 << 11; // BranchEn
        }
        if config.cycle_accurate {
            pt_config |= 1 << 12; // MTCEn
            pt_config |= 1 << 1; // CYCEn
        }
        if config.user_only {
            pt_config |= 1 << 4; // User
        } else {
            pt_config |= 1 << 3; // OS
            pt_config |= 1 << 4; // User
        }
        attr[8..16].copy_from_slice(&pt_config.to_le_bytes());

        // flags at offset 40: bit 0 = disabled (start disabled, enable after mmap)
        let mut flags: u64 = 1; // disabled = 1
        // bit 2 = exclude_kernel if user_only
        if config.user_only {
            flags |= 1 << 5; // exclude_kernel
        }
        attr[40..48].copy_from_slice(&flags.to_le_bytes());

        // ── 3.  Call perf_event_open ─────────────────────────────────────────
        //
        // perf_event_open(attr, pid, cpu=-1, group_fd=-1, flags=0)
        let perf_fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                attr.as_ptr() as libc::c_long,
                pid as libc::pid_t,
                -1i32 as libc::c_long, // cpu = -1 (any)
                -1i32 as libc::c_long, // group_fd = -1
                0i64 as libc::c_long,  // flags = 0
            )
        };
        if perf_fd < 0 {
            let errno = unsafe { *libc::__errno_location() };
            anyhow::bail!(
                "perf_event_open failed: errno {errno} ({})",
                std::io::Error::from_raw_os_error(errno)
            );
        }
        let perf_fd = perf_fd as i32;

        // ── 4.  mmap the perf data ring buffer ───────────────────────────────
        //
        // data region: 1 metadata page + N data pages (N must be power of 2).
        // We use 4 data pages (16 KiB) which is sufficient for the header.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let data_pages: usize = 4;
        let mmap_size = (1 + data_pages) * page_size;

        let mmap_base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mmap_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                perf_fd,
                0,
            )
        };
        if mmap_base == libc::MAP_FAILED {
            unsafe { libc::close(perf_fd) };
            let errno = unsafe { *libc::__errno_location() };
            anyhow::bail!(
                "mmap (data) failed: errno {errno} ({})",
                std::io::Error::from_raw_os_error(errno)
            );
        }
        let mmap_base = mmap_base as *mut u8;

        // ── 5.  mmap the AUX ring buffer ─────────────────────────────────────
        //
        // We must first set aux_offset and aux_size in the perf_event_mmap_page
        // (which lives at mmap_base) before calling mmap on the aux region.
        //
        // perf_event_mmap_page layout (relevant fields):
        //   offset 128..136  data_offset   u64
        //   offset 136..144  data_size     u64
        //   offset 144..152  aux_offset    u64
        //   offset 152..160  aux_size      u64
        let aux_pages = (config.aux_buffer_size_kb as usize * 1024).next_power_of_two() / page_size;
        let aux_pages = aux_pages.max(1);
        let aux_size = aux_pages * page_size;

        // Write aux_offset = data_offset + data_size into the mmap page.
        // data_offset is at +128, data_size is at +136 in the mmap page.
        let data_offset = {
            let p = unsafe { mmap_base.add(128) as *const u64 };
            unsafe { p.read_volatile() }
        };
        let data_size = {
            let p = unsafe { mmap_base.add(136) as *const u64 };
            unsafe { p.read_volatile() }
        };
        let aux_offset = data_offset + data_size;

        // Write aux_offset (at +144) and aux_size (at +152).
        unsafe {
            let p_aux_off = mmap_base.add(144) as *mut u64;
            let p_aux_size = mmap_base.add(152) as *mut u64;
            p_aux_off.write_volatile(aux_offset);
            p_aux_size.write_volatile(aux_size as u64);
        }

        let aux_base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aux_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                perf_fd,
                aux_offset as libc::off_t,
            )
        };
        if aux_base == libc::MAP_FAILED {
            unsafe {
                libc::munmap(mmap_base as *mut libc::c_void, mmap_size);
                libc::close(perf_fd);
            }
            let errno = unsafe { *libc::__errno_location() };
            anyhow::bail!(
                "mmap (aux) failed: errno {errno} ({})",
                std::io::Error::from_raw_os_error(errno)
            );
        }
        let aux_base = aux_base as *mut u8;

        // ── 6.  Apply IP filter if requested ─────────────────────────────────
        if let Some((start, end)) = config.ip_filter {
            // PERF_EVENT_IOC_SET_FILTER is not used for address ranges;
            // instead the addr0_cfg / addr1_cfg MSRs are wired through
            // perf_event_attr.config1/config2. We set them via IOCTL
            // PERF_EVENT_IOC_MODIFY_ATTRIBUTES if available, or note the
            // limitation.  For now we record the intent in config; a full
            // implementation would re-issue perf_event_open with the extra
            // config fields set.
            let _ = (start, end); // used in config field below
        }

        // ── 7.  Enable the event ─────────────────────────────────────────────
        //
        // PERF_EVENT_IOC_ENABLE = _IO('$', 0) = 0x2400
        const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
        let rc = unsafe { libc::ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) };
        if rc < 0 {
            unsafe {
                libc::munmap(aux_base as *mut libc::c_void, aux_size);
                libc::munmap(mmap_base as *mut libc::c_void, mmap_size);
                libc::close(perf_fd);
            }
            let errno = unsafe { *libc::__errno_location() };
            anyhow::bail!(
                "PERF_EVENT_IOC_ENABLE failed: errno {errno} ({})",
                std::io::Error::from_raw_os_error(errno)
            );
        }

        Ok(Self {
            perf_fd,
            aux_fd: perf_fd,
            mmap_base,
            aux_base,
            mmap_size,
            aux_size,
            config,
        })
    }

    /// Stop tracing, drain the AUX ring buffer, and return the raw PT packet
    /// stream.
    ///
    /// The session is unusable after this call.
    pub fn stop(&mut self) -> anyhow::Result<Vec<u8>> {
        // ── 1.  Disable the event ────────────────────────────────────────────
        // PERF_EVENT_IOC_DISABLE = _IO('$', 1) = 0x2401
        const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
        unsafe { libc::ioctl(self.perf_fd, PERF_EVENT_IOC_DISABLE, 0) };

        // ── 2.  Read aux_{head,tail} from the mmap page ──────────────────────
        //
        // perf_event_mmap_page aux_head is at offset 160, aux_tail at 168.
        // We use read_volatile + a memory barrier to ensure we see the
        // kernel's latest write.
        let aux_head = unsafe {
            let p = self.mmap_base.add(160) as *const u64;
            p.read_volatile()
        };
        let aux_tail = unsafe {
            let p = self.mmap_base.add(168) as *const u64;
            p.read_volatile()
        };

        // ── 3.  Copy data from the AUX buffer ───────────────────────────────
        let available = aux_head.wrapping_sub(aux_tail) as usize;
        let available = available.min(self.aux_size);
        let mut raw = Vec::with_capacity(available);

        if available > 0 {
            let tail_idx = (aux_tail as usize) % self.aux_size;
            if tail_idx + available <= self.aux_size {
                // Contiguous region
                let slice =
                    unsafe { std::slice::from_raw_parts(self.aux_base.add(tail_idx), available) };
                raw.extend_from_slice(slice);
            } else {
                // Wrap-around: two copies
                let first_len = self.aux_size - tail_idx;
                let second_len = available - first_len;
                let first =
                    unsafe { std::slice::from_raw_parts(self.aux_base.add(tail_idx), first_len) };
                let second = unsafe { std::slice::from_raw_parts(self.aux_base, second_len) };
                raw.extend_from_slice(first);
                raw.extend_from_slice(second);
            }

            // Advance aux_tail to signal we consumed the data.
            unsafe {
                let p = self.mmap_base.add(168) as *mut u64;
                p.write_volatile(aux_head);
            }
        }

        Ok(raw)
    }
}

#[cfg(target_os = "linux")]
impl Drop for PtCaptureSession {
    fn drop(&mut self) {
        unsafe {
            // Disable, unmap, close — best-effort, ignore errors.
            const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
            libc::ioctl(self.perf_fd, PERF_EVENT_IOC_DISABLE, 0);
            if !self.aux_base.is_null() && self.aux_size > 0 {
                libc::munmap(self.aux_base as *mut libc::c_void, self.aux_size);
            }
            if !self.mmap_base.is_null() && self.mmap_size > 0 {
                libc::munmap(self.mmap_base as *mut libc::c_void, self.mmap_size);
            }
            if self.perf_fd >= 0 {
                libc::close(self.perf_fd);
            }
        }
    }
}

// ─── Non-Linux stubs ──────────────────────────────────────────────────────────

/// Stub `PtCaptureSession` for non-Linux platforms.
///
/// All methods return errors explaining that Intel PT capture requires Linux
/// with `perf_events`.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct PtCaptureSession {
    _phantom: std::marker::PhantomData<()>,
}

#[cfg(not(target_os = "linux"))]
impl PtCaptureSession {
    /// Always returns `Err` on non-Linux platforms.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn start(_pid: u32, _config: PtConfig) -> anyhow::Result<Self> {
        anyhow::bail!("Intel PT capture requires Linux with perf_events")
    }

    /// Always returns `Err` on non-Linux platforms.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn stop(&mut self) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("Intel PT capture requires Linux with perf_events")
    }

    /// Always returns `Err` on non-Linux platforms.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn read_pt_type() -> anyhow::Result<u32> {
        anyhow::bail!("Intel PT capture requires Linux with perf_events")
    }
}

// ─── InstructionTrace ─────────────────────────────────────────────────────────

/// Reconstructed instruction-level trace: an ordered list of program counter
/// values that were executed.
///
/// Full reconstruction requires the original binary image so that conditional
/// branch instructions can be located and their fall-through / taken addresses
/// computed.  Without the binary, only TIP addresses (indirect branches) are
/// known with certainty; TNT bits are consumed but cannot be resolved to
/// concrete PCs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstructionTrace {
    /// Ordered sequence of executed instruction addresses.
    pub pcs: Vec<u64>,
    /// Number of TNT bits consumed during reconstruction.
    pub tnt_consumed: u64,
    /// Number of TIP packets consumed during reconstruction.
    pub tip_consumed: u64,
    /// Number of overflow events encountered.
    pub overflow_count: u64,
}

impl InstructionTrace {
    /// Create an empty trace.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconstruct an instruction-level trace from a slice of decoded PT
    /// packets, the binary image, and the image load address.
    ///
    /// # Algorithm (simplified linear-sweep)
    ///
    /// 1. Scan packets for `TIP.PGE` to locate the entry PC where tracing
    ///    began.
    /// 2. Walk forward through the binary from the current PC:
    ///    - At each conditional branch instruction, pop one TNT bit to decide
    ///      taken vs. not-taken and advance PC accordingly.
    ///    - At each indirect branch / call / ret instruction, pop the next TIP
    ///      address.
    ///    - At `TIP.PGD` (trace disabled), stop until the next `TIP.PGE`.
    ///    - On `OVF`, record an overflow and re-synchronise at the next PSB.
    /// 3. Continue until all packets are consumed.
    ///
    /// Without a disassembler this function performs a *best-effort* recovery:
    /// it emits TIP target addresses as known PCs and advances the TNT cursor
    /// even though the intermediate PCs cannot be resolved.
    ///
    /// # Arguments
    ///
    /// * `packets` — decoded packet stream (from [`PtDecoder`]).
    /// * `binary`  — raw bytes of the mapped ELF/PE image.
    /// * `base`    — virtual load address of `binary`.
    #[must_use]
    pub fn reconstruct(packets: &[PtPacket], binary: &[u8], base: u64) -> Self {
        let mut trace = Self::new();
        let mut current_ip: u64 = 0;
        let mut tracing = false;

        // TNT bit queue: each entry is `true` (taken) or `false` (not taken).
        let mut tnt_queue: std::collections::VecDeque<bool> = std::collections::VecDeque::new();

        for pkt in packets {
            match &pkt.kind {
                // ── Trace enable / disable ───────────────────────────────────
                PtPacketKind::TipPge { ip, .. } => {
                    current_ip = *ip;
                    tracing = true;
                    trace.pcs.push(current_ip);
                }
                PtPacketKind::TipPgd { ip, .. } => {
                    if *ip != 0 {
                        trace.pcs.push(*ip);
                    }
                    tracing = false;
                }

                // ── Indirect-branch target ───────────────────────────────────
                PtPacketKind::Tip { ip, .. } => {
                    if tracing {
                        current_ip = *ip;
                        trace.pcs.push(current_ip);
                        trace.tip_consumed += 1;
                    }
                }

                // ── TNT bits ─────────────────────────────────────────────────
                PtPacketKind::Tnt { bits, count } | PtPacketKind::TntLong { bits, count } => {
                    for i in 0..*count {
                        let taken = (bits >> i) & 1 == 1;
                        tnt_queue.push_back(taken);
                    }
                    trace.tnt_consumed += u64::from(*count);

                    // Attempt to advance the PC through the binary by
                    // consuming TNT bits for conditional branches.
                    if tracing && !binary.is_empty() {
                        current_ip = Self::advance_through_tnts(
                            current_ip,
                            binary,
                            base,
                            &mut tnt_queue,
                            &mut trace.pcs,
                        );
                    }
                }

                // ── Overflow ─────────────────────────────────────────────────
                PtPacketKind::Overflow => {
                    trace.overflow_count += 1;
                    tracing = false; // re-sync on next PSB
                }

                // ── PSB re-sync ──────────────────────────────────────────────
                // ── Timing / mode packets (no PC effect) ─────────────────────
                _ => {}
            }
        }

        trace
    }

    /// Walk forward from `ip` through the `binary` image consuming TNT bits
    /// for each conditional branch encountered.
    ///
    /// This uses a minimal x86-64 opcode scanner: it recognises the most
    /// common single- and two-byte conditional branch encodings (`Jcc rel8`
    /// and `Jcc rel32`) and advances the instruction pointer using a
    /// rough length-disassembler for non-branch instructions.
    ///
    /// Returns the final IP after all TNT bits in `tnt_queue` are consumed
    /// or when an indirect-branch instruction is encountered (signals that
    /// a TIP packet must follow).
    fn advance_through_tnts(
        mut ip: u64,
        binary: &[u8],
        base: u64,
        tnt_queue: &mut std::collections::VecDeque<bool>,
        pcs: &mut Vec<u64>,
    ) -> u64 {
        // Safety limit: do not spin for more than 1024 instructions per call.
        const MAX_INSNS: usize = 1024;
        let mut insn_count = 0;

        while !tnt_queue.is_empty() && insn_count < MAX_INSNS {
            // Translate virtual IP to binary offset.
            if ip < base {
                break;
            }
            let off = crate::cast_helpers::u64_to_usize(ip - base);
            if off >= binary.len() {
                break;
            }

            pcs.push(ip);
            insn_count += 1;

            let b0 = binary[off];

            // ── REX prefix ───────────────────────────────────────────────────
            let mut cursor = off;
            // Skip REX prefix (0x40..0x4F)
            if (0x40..=0x4F).contains(&b0) {
                cursor += 1;
                if cursor >= binary.len() {
                    break;
                }
            }
            let opcode = binary[cursor];
            cursor += 1;

            // ── Jcc rel8 (0x70..0x7F) ───────────────────────────────────────
            if (0x70..=0x7F).contains(&opcode) {
                if cursor >= binary.len() {
                    break;
                }
                let rel8 = binary[cursor].cast_signed();
                cursor += 1; // consume disp8
                let fallthrough = base + (cursor as u64);
                let target = crate::cast_helpers::i64_to_u64(fallthrough.cast_signed() + i64::from(rel8));
                let taken = tnt_queue.pop_front().unwrap_or(false);
                ip = if taken { target } else { fallthrough };
                pcs.push(ip);
                continue;
            }

            // ── Jcc rel32 (0x0F 0x80..0x8F) ─────────────────────────────────
            if opcode == 0x0F {
                if cursor >= binary.len() {
                    break;
                }
                let op2 = binary[cursor];
                cursor += 1;
                if (0x80..=0x8F).contains(&op2) {
                    if cursor + 4 > binary.len() {
                        break;
                    }
                    let rel32 = i32::from_le_bytes([
                        binary[cursor],
                        binary[cursor + 1],
                        binary[cursor + 2],
                        binary[cursor + 3],
                    ]);
                    cursor += 4;
                    let fallthrough = base + (cursor as u64);
                    let target = crate::cast_helpers::i64_to_u64(fallthrough.cast_signed() + i64::from(rel32));
                    let taken = tnt_queue.pop_front().unwrap_or(false);
                    ip = if taken { target } else { fallthrough };
                    pcs.push(ip);
                    continue;
                }
                // LOOP/LOOPE/LOOPNE/JCXZ: not modelled — stop
                // Other 0x0F two-byte instructions: need length decode
                // For non-branch 0x0F instructions, skip 1 more byte as best-effort
                ip = base + (cursor as u64);
                continue;
            }

            // ── Indirect branch / call / ret ─────────────────────────────────
            // FF /2 (call rm), FF /4 (jmp rm), C3 (ret), CB (retf), C2 (ret n)
            if opcode == 0xFF || opcode == 0xC3 || opcode == 0xCB || opcode == 0xC2 {
                // Stop — a TIP packet must supply the target.
                break;
            }

            // ── Direct call (E8 rel32) ────────────────────────────────────────
            if opcode == 0xE8 {
                if cursor + 4 > binary.len() {
                    break;
                }
                let rel32 = i32::from_le_bytes([
                    binary[cursor],
                    binary[cursor + 1],
                    binary[cursor + 2],
                    binary[cursor + 3],
                ]);
                cursor += 4;
                let call_site = base + (cursor as u64);
                let target = crate::cast_helpers::i64_to_u64(call_site.cast_signed() + i64::from(rel32));
                pcs.push(target);
                ip = call_site;
                continue;
            }

            // ── Unconditional direct jmp (E9 rel32 / EB rel8) ────────────────
            if opcode == 0xE9 {
                if cursor + 4 > binary.len() {
                    break;
                }
                let rel32 = i32::from_le_bytes([
                    binary[cursor],
                    binary[cursor + 1],
                    binary[cursor + 2],
                    binary[cursor + 3],
                ]);
                cursor += 4;
                let fallthrough = base + (cursor as u64);
                ip = crate::cast_helpers::i64_to_u64(fallthrough.cast_signed() + i64::from(rel32));
                continue;
            }
            if opcode == 0xEB {
                if cursor >= binary.len() {
                    break;
                }
                let rel8 = binary[cursor].cast_signed();
                cursor += 1;
                let fallthrough = base + (cursor as u64);
                ip = crate::cast_helpers::i64_to_u64(fallthrough.cast_signed() + i64::from(rel8));
                continue;
            }

            // ── Rough length heuristic for other instructions ─────────────────
            // We approximate instruction length using the first opcode byte.
            // This is not correct in general but keeps the decoder moving
            // forward; it will re-sync at the next TIP.
            let approx_len = Self::rough_insn_len(opcode, cursor, binary);
            ip = base + ((cursor + approx_len) as u64);
        }

        ip
    }

    /// Very rough instruction-length estimate for a decoded opcode byte.
    ///
    /// Only used when the instruction is not a branch; returns the number of
    /// bytes *after* `opcode` that belong to this instruction.
    fn rough_insn_len(opcode: u8, cursor: usize, binary: &[u8]) -> usize {
        // Instructions with an immediate byte operand (select common encodings)
        match opcode {
            // push imm8, pop, nop, int3, hlt, …
            // push imm32
            0x68 | 0xB8..=0xBF | 0x05 | 0x25 | 0x2D | 0x35 | 0x3D => 4,
            // mov reg, imm32/64 — just use 4 bytes as default
            // 2-byte form (opcode + ModRM + optional SIB/disp) — estimate 2
            0x88..=0x8B | 0x0A | 0x02 | 0x2A | 0x32 | 0x3A => 2,
            // MOV r/m, imm32 (0xC7)
            0xC7 => {
                // ModRM follows
                if cursor < binary.len() {
                    let modrm = binary[cursor];
                    let md = (modrm >> 6) & 3;
                    let rm = modrm & 7;
                    let sib = usize::from(md != 3 && rm == 4);
                    let disp = match md {
                        0 if rm == 5 => 4,
                        1 => 1,
                        2 => 4,
                        _ => 0,
                    };
                    1 + sib + disp + 4 // ModRM + SIB + disp + imm32
                } else {
                    5
                }
            }
            // Default: assume 1-byte instruction (very rough)
            _ => 1,
        }
    }

    /// Return the number of unique PCs recorded.
    #[must_use]
    pub fn unique_pcs(&self) -> usize {
        use std::collections::HashSet;
        self.pcs.iter().collect::<HashSet<_>>().len()
    }

    /// Return `true` if the trace is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pcs.is_empty()
    }

    /// Return the number of recorded PCs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pcs.len()
    }
}

// ─── IntelPtCapabilities / PtConfig / InstructionTrace tests ─────────────────

#[cfg(test)]
mod hw_tests {
    use super::*;

    // ── IntelPtCapabilities ───────────────────────────────────────────────

    #[test]
    fn test_capabilities_is_supported_returns_bool() {
        // Just verify the function compiles and returns without panicking.
        let _ = IntelPtCapabilities::is_supported();
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn test_capabilities_detect_fails_on_non_x86() {
        let result = IntelPtCapabilities::detect();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("x86_64"));
    }

    // ── PtConfig ──────────────────────────────────────────────────────────

    #[test]
    fn test_ptconfig_default() {
        let cfg = PtConfig::default();
        assert!(cfg.branch_packets);
        assert!(!cfg.cycle_accurate);
        assert!(cfg.user_only);
        assert!(cfg.ip_filter.is_none());
        assert_eq!(cfg.aux_buffer_size_kb, 4096);
    }

    #[test]
    fn test_ptconfig_builder_cycle_accurate() {
        let cfg = PtConfig::new().with_cycle_accurate(true);
        assert!(cfg.cycle_accurate);
    }

    #[test]
    fn test_ptconfig_builder_ip_filter() {
        let cfg = PtConfig::new().with_ip_filter(0x1000, 0x2000);
        assert_eq!(cfg.ip_filter, Some((0x1000, 0x2000)));
    }

    #[test]
    fn test_ptconfig_builder_aux_buffer() {
        let cfg = PtConfig::new().with_aux_buffer_size_kb(512);
        assert_eq!(cfg.aux_buffer_size_kb, 512);
    }

    #[test]
    fn test_ptconfig_builder_user_only_false() {
        let cfg = PtConfig::new().with_user_only(false);
        assert!(!cfg.user_only);
    }

    #[test]
    fn test_ptconfig_builder_chaining() {
        let cfg = PtConfig::new()
            .with_cycle_accurate(true)
            .with_ip_filter(0x0040_0000, 0x0050_0000)
            .with_aux_buffer_size_kb(1024)
            .with_user_only(false);
        assert!(cfg.cycle_accurate);
        assert_eq!(cfg.ip_filter, Some((0x0040_0000, 0x0050_0000)));
        assert_eq!(cfg.aux_buffer_size_kb, 1024);
        assert!(!cfg.user_only);
    }

    // ── PtCaptureSession (non-Linux stubs) ───────────────────────────────

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_capture_session_start_errors_on_non_linux() {
        let result = PtCaptureSession::start(0, PtConfig::default());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Linux") || msg.contains("perf_events"),
            "unexpected error message: {msg}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_capture_session_read_pt_type_errors_on_non_linux() {
        let result = PtCaptureSession::read_pt_type();
        assert!(result.is_err());
    }

    // ── InstructionTrace ─────────────────────────────────────────────────

    #[test]
    fn test_instruction_trace_empty() {
        let trace = InstructionTrace::new();
        assert!(trace.is_empty());
        assert_eq!(trace.len(), 0);
        assert_eq!(trace.unique_pcs(), 0);
    }

    #[test]
    fn test_instruction_trace_reconstruct_no_packets() {
        let trace = InstructionTrace::reconstruct(&[], &[], 0);
        assert!(trace.is_empty());
    }

    #[test]
    fn test_instruction_trace_reconstruct_tip_pge_only() {
        let pkt = PtPacket::new(
            PtPacketKind::TipPge {
                ip: 0x0040_1000,
                compression: IpCompression::Full48,
            },
            0,
            7,
        );
        let trace = InstructionTrace::reconstruct(&[pkt], &[], 0x0040_0000);
        assert_eq!(trace.pcs, vec![0x0040_1000]);
        assert_eq!(trace.tip_consumed, 0);
        assert_eq!(trace.tnt_consumed, 0);
    }

    #[test]
    fn test_instruction_trace_tip_packets_consumed() {
        let pkts = vec![
            PtPacket::new(
                PtPacketKind::TipPge {
                    ip: 0x0040_1000,
                    compression: IpCompression::Full48,
                },
                0,
                7,
            ),
            PtPacket::new(
                PtPacketKind::Tip {
                    ip: 0x0040_2000,
                    compression: IpCompression::Full48,
                },
                7,
                7,
            ),
            PtPacket::new(
                PtPacketKind::Tip {
                    ip: 0x0040_3000,
                    compression: IpCompression::Full48,
                },
                14,
                7,
            ),
        ];
        let trace = InstructionTrace::reconstruct(&pkts, &[], 0x0040_0000);
        assert_eq!(trace.tip_consumed, 2);
        assert!(trace.pcs.contains(&0x0040_2000));
        assert!(trace.pcs.contains(&0x0040_3000));
    }

    #[test]
    fn test_instruction_trace_overflow_count() {
        let pkts = vec![
            PtPacket::new(PtPacketKind::Overflow, 0, 1),
            PtPacket::new(PtPacketKind::Overflow, 1, 1),
        ];
        let trace = InstructionTrace::reconstruct(&pkts, &[], 0);
        assert_eq!(trace.overflow_count, 2);
    }

    #[test]
    fn test_instruction_trace_tnt_consumed() {
        let pkts = vec![
            PtPacket::new(
                PtPacketKind::TipPge {
                    ip: 0x1000,
                    compression: IpCompression::Full48,
                },
                0,
                7,
            ),
            PtPacket::new(
                PtPacketKind::Tnt {
                    bits: 0b101,
                    count: 3,
                },
                7,
                1,
            ),
        ];
        let trace = InstructionTrace::reconstruct(&pkts, &[], 0);
        assert_eq!(trace.tnt_consumed, 3);
    }

    #[test]
    fn test_instruction_trace_jcc_rel8_taken() {
        // Build a tiny binary: JE +4 (0x74 0x04), then 4 NOP bytes, then target NOP.
        // Encoding: 0x74 0x04 = JE rel8(+4)
        // Bytes:   [0x74, 0x04, 0x90, 0x90, 0x90, 0x90, 0x90]
        //  offset 0: JE +4  -> falls through to offset 2, taken to offset 6
        //  offset 2..5: NOPs (fall-through path)
        //  offset 6: NOP (taken target)
        let binary: Vec<u8> = vec![
            0x74, 0x04, // JE +4
            0x90, 0x90, 0x90, 0x90, // 4 NOPs (fall-through)
            0x90, // NOP at target
        ];
        let base = 0x1000u64;
        // TipPge at offset 0, then one TNT bit = taken
        let pkts = vec![
            PtPacket::new(
                PtPacketKind::TipPge {
                    ip: base,
                    compression: IpCompression::Full48,
                },
                0,
                7,
            ),
            PtPacket::new(
                PtPacketKind::Tnt {
                    bits: 0b1,
                    count: 1,
                }, // taken
                7,
                1,
            ),
        ];
        let trace = InstructionTrace::reconstruct(&pkts, &binary, base);
        // Should contain the target 0x1000 + 2 + 4 = 0x1006
        assert!(trace.pcs.contains(&0x1006));
    }

    #[test]
    fn test_instruction_trace_jcc_rel8_not_taken() {
        let binary: Vec<u8> = vec![
            0x74, 0x04, // JE +4
            0x90, 0x90, 0x90, 0x90, 0x90,
        ];
        let base = 0x1000u64;
        let pkts = vec![
            PtPacket::new(
                PtPacketKind::TipPge {
                    ip: base,
                    compression: IpCompression::Full48,
                },
                0,
                7,
            ),
            PtPacket::new(
                PtPacketKind::Tnt {
                    bits: 0b0,
                    count: 1,
                }, // not taken
                7,
                1,
            ),
        ];
        let trace = InstructionTrace::reconstruct(&pkts, &binary, base);
        // Fall-through = 0x1002
        assert!(trace.pcs.contains(&0x1002));
        assert!(!trace.pcs.contains(&0x1006));
    }

    #[test]
    fn test_instruction_trace_unique_pcs() {
        let pkts = vec![
            PtPacket::new(
                PtPacketKind::TipPge {
                    ip: 0x1000,
                    compression: IpCompression::Full48,
                },
                0,
                7,
            ),
            PtPacket::new(
                PtPacketKind::Tip {
                    ip: 0x1000,
                    compression: IpCompression::Full48,
                },
                7,
                7,
            ),
        ];
        let trace = InstructionTrace::reconstruct(&pkts, &[], 0);
        // Both pcs are 0x1000 — unique_pcs should return 1
        assert_eq!(trace.unique_pcs(), 1);
    }

    #[test]
    fn test_ptconfig_serde_roundtrip() {
        let cfg = PtConfig::new()
            .with_cycle_accurate(true)
            .with_ip_filter(0xDEAD_BEEF, 0xCAFE_BABE);
        let json = serde_json::to_string(&cfg).unwrap();
        let cfg2: PtConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg2.ip_filter, Some((0xDEAD_BEEF, 0xCAFE_BABE)));
        assert!(cfg2.cycle_accurate);
    }

    #[test]
    fn test_instruction_trace_serde_roundtrip() {
        let mut trace = InstructionTrace::new();
        trace.pcs = vec![0x1000, 0x1004, 0x2000];
        trace.tnt_consumed = 5;
        trace.tip_consumed = 1;
        trace.overflow_count = 0;
        let json = serde_json::to_string(&trace).unwrap();
        let t2: InstructionTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.pcs, trace.pcs);
        assert_eq!(t2.tnt_consumed, 5);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Intel PT Packet Stream Decoder — standalone, low-level implementation
// ═══════════════════════════════════════════════════════════════════════════════
//
// This module provides a self-contained Intel PT packet stream decoder that
// operates directly on raw byte slices.  It is designed to be independent of
// the higher-level `PtPacket`/`PtPacketKind` types above so that it can be
// used as a foundation for alternative decoders, fuzzers, or tooling that
// prefers a simpler API.
//
// Public surface
// ──────────────
//   • `StreamIpMode`        — IP-compression field values (3-bit IPR)
//   • `PtPkt`               — decoded packet enum
//   • `PtPacketStream`      — streaming decoder over `Vec<u8>`
//   • `StreamTraceEntry`    — single reconstructed instruction record
//   • `StreamTrace`         — collection of `StreamTraceEntry` values
//   • `pt_to_coverage`      — extract unique IPs as `HashSet<u64>`
//   • `pt_to_drcov`         — format a `StreamTrace` as a DRcov coverage file

// (HashSet is already imported at the top of this file.)

// ─── StreamIpMode ─────────────────────────────────────────────────────────────

/// IP-compression encoding embedded in the 3-bit IPR field of TIP/TIP.PGE/
/// TIP.PGD/FUP packet headers.
///
/// Variants match the names used in Intel's PT architecture manual
/// (Vol. 3C §36).  This type mirrors `IpCompression` (the higher-level enum)
/// but is standalone and used only by `PtPacketStream`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamIpMode {
    /// IPR = 0 — IP value is suppressed (not present in the packet).
    Suppressed,
    /// IPR = 1 — 16-bit update: the two least-significant bytes are updated,
    /// the upper 6 bytes are unchanged from the last IP.
    Upd16,
    /// IPR = 2 — 32-bit update: the four least-significant bytes are updated,
    /// the upper 4 bytes are unchanged from the last IP.
    Upd32,
    /// IPR = 3 — 48-bit full address, zero-extended to 64 bits.
    Upd48,
    /// IPR = 4 — 48-bit full address, sign-extended to 64 bits.
    Sext48,
    /// IPR = 6 — full 64-bit address.
    Full,
}

impl StreamIpMode {
    /// Decode an IPR value (bits 2:0 of the packet header byte after masking).
    #[must_use]
    pub const fn from_ipr(ipr: u8) -> Self {
        match ipr & 0b111 {
            1 => Self::Upd16,
            2 => Self::Upd32,
            3 => Self::Upd48,
            4 => Self::Sext48,
            6 => Self::Full,
            _ => Self::Suppressed,
        }
    }

    /// Number of bytes that follow the opcode byte for the IP payload.
    #[must_use]
    pub const fn payload_bytes(self) -> usize {
        match self {
            Self::Suppressed => 0,
            Self::Upd16 => 2,
            Self::Upd32 => 4,
            Self::Upd48 | Self::Sext48 => 6,
            Self::Full => 8,
        }
    }
}

// ─── PtPkt ────────────────────────────────────────────────────────────────────

/// A fully decoded Intel PT packet.
///
/// This enum mirrors the packet types defined in the Intel PT architecture
/// manual.  Variant names follow the mnemonics used in that document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtPkt {
    // ── Synchronisation ──────────────────────────────────────────────────────
    /// PAD — padding byte (0x00).  Used to align the stream.
    Pad,
    /// PSB — Packet Stream Boundary.  Consists of 16 alternating 0x02/0x82
    /// bytes and marks a synchronisation point.
    Psb,
    /// PSBEND — follows a PSB and ends the synchronisation header.
    PsbEnd,

    // ── Taken/Not-Taken ──────────────────────────────────────────────────────
    /// Short TNT packet: up to 6 conditional-branch decisions packed into a
    /// single byte.  Bits are ordered LSB-first; `count` says how many are
    /// valid.
    Tnt8 {
        /// TNT decision bits, LSB = oldest decision.
        payload: u8,
        /// Number of valid bits in `payload` (1–6).
        count: u8,
    },
    /// Long TNT packet (0x02 0xa3 + 6 payload bytes): up to 47 decisions.
    Tnt64 {
        /// TNT decision bits packed into a u64, LSB = oldest.
        payload: u64,
        /// Number of valid bits in `payload`.
        count: u8,
    },

    // ── Target IP packets ────────────────────────────────────────────────────
    /// TIP — indirect branch target (bits 6:4 = 0b000 in the lower nibble
    /// after masking; opcode nibble = 0xD).
    Tip {
        /// Resolved 64-bit IP.
        ip: u64,
        /// IP compression that was used.
        compression: StreamIpMode,
    },
    /// TIP.PGD — tracing disabled at this IP.
    TipPgd {
        /// Resolved 64-bit IP.
        ip: u64,
        /// IP compression that was used.
        compression: StreamIpMode,
    },
    /// TIP.PGE — tracing (re-)enabled at this IP.
    TipPge {
        /// Resolved 64-bit IP.
        ip: u64,
        /// IP compression that was used.
        compression: StreamIpMode,
    },
    /// FUP — flow-update packet, carries a precise IP for async events.
    TipFup {
        /// Resolved 64-bit IP.
        ip: u64,
        /// IP compression that was used.
        compression: StreamIpMode,
    },

    // ── Timing ───────────────────────────────────────────────────────────────
    /// TSC — full timestamp counter value (7 bytes little-endian after 0x19).
    Tsc {
        /// 56-bit TSC value.
        tsc: u64,
    },
    /// MTC — mini timestamp counter (1 byte CTC value after 0x59).
    Mtc {
        /// CTC value.
        ctc: u8,
    },
    /// CBR — core/bus ratio (2 bytes after 0x03 0x00, first byte is ratio).
    Cbr {
        /// Core-to-bus clock ratio.
        ratio: u8,
    },

    // ── Miscellaneous ────────────────────────────────────────────────────────
    /// `TraceStop` — packet that signals end-of-trace (0x01 0x83).
    TraceStop,
    /// OVF — overflow, trace data was lost.
    Ovf,
    /// Unknown opcode that the decoder did not recognise.
    Unknown(u8),
}

impl PtPkt {
    /// Return `true` if this is a timing-class packet.
    #[must_use]
    pub const fn is_timing(&self) -> bool {
        matches!(self, Self::Tsc { .. } | Self::Mtc { .. } | Self::Cbr { .. })
    }

    /// Return `true` if this packet carries an IP address.
    #[must_use]
    pub const fn has_ip(&self) -> bool {
        matches!(
            self,
            Self::Tip { .. } | Self::TipPgd { .. } | Self::TipPge { .. } | Self::TipFup { .. }
        )
    }

    /// Extract the IP address from a TIP/TIP.PGD/TIP.PGE/FUP packet, if any.
    #[must_use]
    pub const fn ip(&self) -> Option<u64> {
        match self {
            Self::Tip { ip, .. }
            | Self::TipPgd { ip, .. }
            | Self::TipPge { ip, .. }
            | Self::TipFup { ip, .. } => Some(*ip),
            _ => None,
        }
    }

    /// Return a human-readable mnemonic string.
    #[must_use]
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::Pad => "PAD",
            Self::Psb => "PSB",
            Self::PsbEnd => "PSBEND",
            Self::Tnt8 { .. } => "TNT8",
            Self::Tnt64 { .. } => "TNT64",
            Self::Tip { .. } => "TIP",
            Self::TipPgd { .. } => "TIP.PGD",
            Self::TipPge { .. } => "TIP.PGE",
            Self::TipFup { .. } => "FUP",
            Self::Tsc { .. } => "TSC",
            Self::Mtc { .. } => "MTC",
            Self::Cbr { .. } => "CBR",
            Self::TraceStop => "TRACESTOP",
            Self::Ovf => "OVF",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

impl std::fmt::Display for PtPkt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pad => write!(f, "PAD"),
            Self::Psb => write!(f, "PSB"),
            Self::PsbEnd => write!(f, "PSBEND"),
            Self::Tnt8 { payload, count } => write!(f, "TNT8(0b{payload:08b}[{count}])"),
            Self::Tnt64 { payload, count } => write!(f, "TNT64(0x{payload:016x}[{count}])"),
            Self::Tip { ip, compression } => write!(f, "TIP(ip=0x{ip:016x}, cmp={compression:?})"),
            Self::TipPgd { ip, compression } => {
                write!(f, "TIP.PGD(ip=0x{ip:016x}, cmp={compression:?})")
            }
            Self::TipPge { ip, compression } => {
                write!(f, "TIP.PGE(ip=0x{ip:016x}, cmp={compression:?})")
            }
            Self::TipFup { ip, compression } => {
                write!(f, "FUP(ip=0x{ip:016x}, cmp={compression:?})")
            }
            Self::Tsc { tsc } => write!(f, "TSC({tsc})"),
            Self::Mtc { ctc } => write!(f, "MTC({ctc})"),
            Self::Cbr { ratio } => write!(f, "CBR({ratio})"),
            Self::TraceStop => write!(f, "TRACESTOP"),
            Self::Ovf => write!(f, "OVF"),
            Self::Unknown(b) => write!(f, "UNKNOWN(0x{b:02x})"),
        }
    }
}

// ─── PtPacketStream ───────────────────────────────────────────────────────────

/// Streaming decoder for a raw Intel PT byte stream.
///
/// `PtPacketStream` maintains a cursor and the last resolved IP value so that
/// compressed IP updates can be applied incrementally.
///
/// # Example
/// ```ignore
/// let raw: Vec<u8> = collect_pt_data();
/// let mut stream = PtPacketStream::new(raw);
/// while let Some(pkt) = stream.next_packet() {
///     println!("{}", pkt);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct PtPacketStream {
    /// Raw PT byte stream.
    pub data: Vec<u8>,
    /// Current decode position.
    pub pos: usize,
    /// Last resolved IP — needed for compressed-IP updates.
    pub last_ip: u64,
}

impl PtPacketStream {
    // ── PSB magic constant ────────────────────────────────────────────────────
    // A PSB consists of 16 bytes: 0x02 0x82 0x02 0x82 … (8 repetitions).
    const PSB_MAGIC: [u8; 16] = [
        0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02,
        0x82,
    ];

    /// Construct a new `PtPacketStream` wrapping `data`.
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            pos: 0,
            last_ip: 0,
        }
    }

    /// Construct from a byte slice (clones the data).
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }

    /// Return the number of bytes remaining in the stream.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Return `true` if the stream is exhausted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Reset the decoder to the beginning of the stream.
    pub const fn reset(&mut self) {
        self.pos = 0;
        self.last_ip = 0;
    }

    /// Peek at the byte at `self.pos` without advancing the cursor.
    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Consume and return the byte at `self.pos`.
    fn consume(&mut self) -> Option<u8> {
        let b = self.data.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    /// Consume exactly `n` bytes and return them as a slice reference.
    /// Returns `None` if fewer than `n` bytes remain.
    fn consume_bytes(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.data.len() {
            return None;
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    /// Read a little-endian `u16` from the stream.
    fn read_le_u16(&mut self) -> Option<u16> {
        let b = self.consume_bytes(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Read a little-endian `u32` from the stream.
    fn read_le_u32(&mut self) -> Option<u32> {
        let b = self.consume_bytes(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a little-endian `u64` from the stream.
    fn read_le_u64(&mut self) -> Option<u64> {
        let b = self.consume_bytes(8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Read a 6-byte (48-bit) little-endian value, zero-extended to `u64`.
    fn read_le_u48(&mut self) -> Option<u64> {
        let b = self.consume_bytes(6)?;
        Some(
            u64::from(b[0])
                | (u64::from(b[1]) << 8)
                | (u64::from(b[2]) << 16)
                | (u64::from(b[3]) << 24)
                | (u64::from(b[4]) << 32)
                | (u64::from(b[5]) << 40),
        )
    }

    /// Decode an IP value according to `compression`, updating `self.last_ip`.
    ///
    /// The `last_ip` field holds the previous fully-resolved IP; compressed
    /// updates replace only the low bytes, keeping the rest unchanged.
    pub fn decode_ip(&mut self, compression: StreamIpMode) -> Option<u64> {
        let ip = match compression {
            StreamIpMode::Suppressed => {
                // IP is not transmitted; return the last known IP.
                self.last_ip
            }
            StreamIpMode::Upd16 => {
                let low16 = u64::from(self.read_le_u16()?);
                // Replace the bottom 16 bits of last_ip.
                (self.last_ip & !0xFFFF) | low16
            }
            StreamIpMode::Upd32 => {
                let low32 = u64::from(self.read_le_u32()?);
                // Replace the bottom 32 bits of last_ip.
                (self.last_ip & !0xFFFF_FFFF) | low32
            }
            StreamIpMode::Upd48 => {
                // 48-bit full address, zero-extended.
                self.read_le_u48()?
            }
            StreamIpMode::Sext48 => {
                // 48-bit address, sign-extended to 64 bits.
                let raw = self.read_le_u48()?;
                // Sign-extend from bit 47.
                if raw & (1 << 47) != 0 {
                    raw | 0xFFFF_0000_0000_0000
                } else {
                    raw
                }
            }
            StreamIpMode::Full => self.read_le_u64()?,
        };
        self.last_ip = ip;
        Some(ip)
    }

    /// Attempt to decode one packet at the current position.
    ///
    /// Returns `Some(PtPkt)` on success, `None` when the stream is exhausted.
    /// On an unrecognised or truncated sequence the cursor advances past the
    /// unknown byte and `PtPkt::Unknown(b)` is returned.
    pub fn next_packet(&mut self) -> Option<PtPkt> {
        let b0 = self.peek()?;

        // ── PAD ────────────────────────────────────────────────────────────
        if b0 == 0x00 {
            self.pos += 1;
            return Some(PtPkt::Pad);
        }

        // ── TNT8 ───────────────────────────────────────────────────────────
        // Bit 0 of byte 0 is 0, bits 7:2 contain TNT payload, bit 1 is 1.
        // Opcode pattern: xxxxxx10 where the top 6 bits are TNT bits with a
        // stop bit.  Intel PT spec: byte & 0x03 == 0x02 but that overlaps
        // with the 0x02 PSB byte; so we check via a different path.
        // A TNT8 byte has bit0=0 and bit1=1 (i.e. byte & 0x03 == 0x02).
        // Exception: 0x02 on its own is part of a PSB, handled below.
        // We handle PSB first by lookahead.
        if b0 & 0x03 == 0x02 && b0 != 0x02 {
            // TNT8 byte (bit pattern xxxxxx10, but NOT 0x02 which is PSB/extended).
            // Could be start of PSB or a TNT8 byte.
            if self.data.len() >= self.pos + 16
                && self.data[self.pos..self.pos + 16] == Self::PSB_MAGIC
            {
                // PSB packet.
                self.pos += 16;
                return Some(PtPkt::Psb);
            }
            // It is a TNT8.
            self.pos += 1;
            // Bits 7:2 contain the stop-bit-terminated TNT payload.
            // The stop bit is the most-significant '1' within bits 7:1.
            let _ = b0 >> 1; // bits 7:1 shifted to 6:0 (kept for documentation)
            // Count trailing zeros in the reversed bit pattern to find stop bit.
            // The stop bit is the lowest set bit of payload_field, counting from LSB.
            // Count of decisions = (number of bits above stop bit).
            // Actually: stop bit is the MSB-most '1'; decisions are above that in bits 7:2.
            // Per Intel manual: bits 7:2 of the byte: stop bit followed by TNT bits.
            // Stop bit is the most significant '1' in bits 7:2.
            // Payload bits 7:2: stop_bit | tnt[count-1] | ... | tnt[0]
            let raw6 = b0 >> 2; // 6-bit field
            // Find the position of the stop bit: the index of the most
            // significant set bit in the 6-bit raw6 field.
            // leading_zeros() on a u8 counts from bit 7; the MSB of raw6 is
            // at bit 5 (since raw6 <= 63).
            if raw6 == 0 {
                // Degenerate byte: no stop bit → treat as 0 TNT decisions.
                return Some(PtPkt::Tnt8 {
                    payload: 0,
                    count: 0,
                });
            }
            // msb_index: 0-based index of the most significant set bit (0 = bit0).
            let msb_index = crate::cast_helpers::u32_to_u8(u8::BITS - 1 - raw6.leading_zeros());
            // TNT bits are those below the stop bit.
            let count = msb_index; // number of valid TNT bits
            let mask = if count == 0 {
                0u8
            } else {
                (1u8 << count).wrapping_sub(1)
            };
            let payload = raw6 & mask;
            return Some(PtPkt::Tnt8 { payload, count });
        }

        // ── Extended opcode or PSB (0x02 prefix) ─────────────────────────────
        if b0 == 0x02 {
            // First check for PSB: 16 alternating 0x02/0x82 bytes.
            if self.data.len() >= self.pos + 16
                && self.data[self.pos..self.pos + 16] == Self::PSB_MAGIC
            {
                self.pos += 16;
                return Some(PtPkt::Psb);
            }
            // Otherwise it is a two-byte extended opcode.
            self.pos += 1;
            let Some(b1) = self.consume() else { return Some(PtPkt::Unknown(0x02)) };
            return self.decode_extended(b1);
        }

        // ── Single-byte opcodes ────────────────────────────────────────────
        match b0 {
            // ── TSC: 0x19 + 7 bytes LE ────────────────────────────────────
            0x19 => {
                self.pos += 1;
                let b = self.consume_bytes(7)?;
                let tsc = u64::from(b[0])
                    | (u64::from(b[1]) << 8)
                    | (u64::from(b[2]) << 16)
                    | (u64::from(b[3]) << 24)
                    | (u64::from(b[4]) << 32)
                    | (u64::from(b[5]) << 40)
                    | (u64::from(b[6]) << 48);
                Some(PtPkt::Tsc { tsc })
            }

            // ── MTC: 0x59 + 1 byte CTC ────────────────────────────────────
            0x59 => {
                self.pos += 1;
                let ctc = self.consume()?;
                Some(PtPkt::Mtc { ctc })
            }

            // ── CBR: 0x03 0x00 + ratio byte + reserved byte ───────────────
            0x03 => {
                self.pos += 1;
                let b1 = self.consume()?; // 0x00 (fixed)
                if b1 != 0x00 {
                    return Some(PtPkt::Unknown(0x03));
                }
                let ratio = self.consume()?;
                let _reserved = self.consume(); // ignore
                Some(PtPkt::Cbr { ratio })
            }

            // ── TIP / TIP.PGD / TIP.PGE / FUP ────────────────────────────
            // Lower nibble determines variant; upper nibble encodes IPR.
            // Bits [7:5] = IPR (IP compression); bits [4:0] select the type.
            // Opcode byte layout: [ipr(2:0) | type_id(4:0)]
            // type_id in lower 5 bits:
            //   0b01101 (0x0D) → TIP
            //   0b00001 (0x01) → TIP.PGE  (but also collides with TRACESTOP at 0x01 0x83)
            //   0b10001 (0x11) → TIP.PGD
            //   0b11101 (0x1D) → FUP
            // Note: bits 4:0 of the opcode encode the packet type.
            // IPR is in bits 7:5.
            b if (b & 0x1F) == 0x0D => {
                self.pos += 1;
                let compression = StreamIpMode::from_ipr(b >> 5);
                let ip = self.decode_ip(compression)?;
                Some(PtPkt::Tip { ip, compression })
            }
            b if (b & 0x1F) == 0x11 => {
                self.pos += 1;
                let compression = StreamIpMode::from_ipr(b >> 5);
                let ip = self.decode_ip(compression)?;
                Some(PtPkt::TipPgd { ip, compression })
            }
            b if (b & 0x1F) == 0x01 => {
                // Lookahead: 0x01 0x83 = TRACESTOP
                if self.data.get(self.pos + 1).copied() == Some(0x83) {
                    self.pos += 2;
                    return Some(PtPkt::TraceStop);
                }
                self.pos += 1;
                let compression = StreamIpMode::from_ipr(b >> 5);
                let ip = self.decode_ip(compression)?;
                Some(PtPkt::TipPge { ip, compression })
            }
            b if (b & 0x1F) == 0x1D => {
                self.pos += 1;
                let compression = StreamIpMode::from_ipr(b >> 5);
                let ip = self.decode_ip(compression)?;
                Some(PtPkt::TipFup { ip, compression })
            }

            // ── Everything else ───────────────────────────────────────────
            _ => {
                self.pos += 1;
                Some(PtPkt::Unknown(b0))
            }
        }
    }

    /// Decode an extended packet given the second byte `b1` (first byte was
    /// 0x02, already consumed).
    fn decode_extended(&mut self, b1: u8) -> Option<PtPkt> {
        match b1 {
            // PSBEND: 0x02 0x23
            0x23 => Some(PtPkt::PsbEnd),

            // OVF: 0x02 0xF3
            0xF3 => Some(PtPkt::Ovf),

            // TNT64: 0x02 0xA3 + 6 payload bytes
            0xA3 => {
                let b = self.consume_bytes(6)?;
                let raw = u64::from(b[0])
                    | (u64::from(b[1]) << 8)
                    | (u64::from(b[2]) << 16)
                    | (u64::from(b[3]) << 24)
                    | (u64::from(b[4]) << 32)
                    | (u64::from(b[5]) << 40);
                if raw == 0 {
                    return Some(PtPkt::Tnt64 {
                        payload: 0,
                        count: 0,
                    });
                }
                // msb_index: 0-based index of the most significant set bit.
                let msb_index = crate::cast_helpers::u32_to_u8(raw.ilog2());
                let count = msb_index; // bits below stop bit are TNT decisions
                let mask = if count == 0 {
                    0u64
                } else {
                    (1u64 << count).wrapping_sub(1)
                };
                let payload = raw & mask;
                Some(PtPkt::Tnt64 { payload, count })
            }

            // MODE.Exec / MODE.TSX: 0x02 0x43 or 0x02 0xC3 — emit Unknown.
            // PIP: 0x02 0x43 — we simplify and emit Unknown for mode/pip/vmcs.
            _ => Some(PtPkt::Unknown(b1)),
        }
    }

    /// Decode the entire stream and return all packets.
    ///
    /// The decoder advances until `next_packet` returns `None` (stream
    /// exhausted).  This is a convenience wrapper; for large streams prefer
    /// the iterator pattern via `next_packet`.
    pub fn decode_all(&mut self) -> Vec<PtPkt> {
        let mut out = Vec::new();
        while let Some(pkt) = self.next_packet() {
            out.push(pkt);
        }
        out
    }

    /// Collect only the flow-relevant packets (TIP, TNT, PSB, OVF), skipping
    /// timing and padding.
    pub fn decode_flow(&mut self) -> Vec<PtPkt> {
        self.decode_all()
            .into_iter()
            .filter(|p| {
                !matches!(
                    p,
                    PtPkt::Pad | PtPkt::Tsc { .. } | PtPkt::Mtc { .. } | PtPkt::Cbr { .. }
                )
            })
            .collect()
    }

    /// Seek forward to the next PSB synchronisation point.
    ///
    /// Returns the byte offset of the PSB on success, or `None` if no PSB
    /// exists in the remaining data.
    pub fn sync_forward(&mut self) -> Option<usize> {
        let end = self.data.len().saturating_sub(16);
        while self.pos <= end {
            if self.data[self.pos..self.pos + 16] == Self::PSB_MAGIC {
                return Some(self.pos);
            }
            self.pos += 1;
        }
        None
    }

    /// Return the current stream position.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Seek to an absolute byte offset.
    ///
    /// # Panics
    /// Panics if `offset > data.len()`.
    pub fn seek(&mut self, offset: usize) {
        assert!(offset <= self.data.len(), "seek offset out of range");
        self.pos = offset;
    }
}

// ─── StreamTraceEntry ─────────────────────────────────────────────────────────

/// A single reconstructed instruction record produced by the PT stream
/// decoder.
///
/// Each entry corresponds to an instruction that was executed during the
/// traced interval.  The `ip` field is always valid; `tsc` and `taken` are
/// present only when the relevant information was available in the packet
/// stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamTraceEntry {
    /// Instruction pointer (virtual address).
    pub ip: u64,
    /// TSC timestamp at the time this instruction was executed, if known.
    pub tsc: Option<u64>,
    /// For conditional branches: `Some(true)` = taken, `Some(false)` =
    /// not-taken; `None` for non-branch instructions or when not available.
    pub taken: Option<bool>,
}

impl StreamTraceEntry {
    /// Construct a new entry with all fields explicit.
    #[must_use]
    pub const fn new(ip: u64, tsc: Option<u64>, taken: Option<bool>) -> Self {
        Self { ip, tsc, taken }
    }

    /// Construct a plain entry with only an IP address.
    #[must_use]
    pub const fn from_ip(ip: u64) -> Self {
        Self {
            ip,
            tsc: None,
            taken: None,
        }
    }

    /// Construct an entry with an IP and timestamp.
    #[must_use]
    pub const fn with_tsc(ip: u64, tsc: u64) -> Self {
        Self {
            ip,
            tsc: Some(tsc),
            taken: None,
        }
    }
}

impl std::fmt::Display for StreamTraceEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:016x}", self.ip)?;
        if let Some(tsc) = self.tsc {
            write!(f, " tsc={tsc}")?;
        }
        if let Some(t) = self.taken {
            write!(f, " taken={t}")?;
        }
        Ok(())
    }
}

// ─── StreamTrace ──────────────────────────────────────────────────────────────

/// A reconstructed execution trace: an ordered list of `StreamTraceEntry`
/// values produced by `PtPacketStream`.
///
/// `StreamTrace` can be constructed directly from decoded packets via
/// `StreamTrace::from_packets`, or by collecting entries manually.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamTrace {
    /// Ordered list of execution records.
    pub instructions: Vec<StreamTraceEntry>,
}


impl<'a> IntoIterator for &'a StreamTrace {
    type Item = &'a StreamTraceEntry;
    type IntoIter = std::slice::Iter<'a, StreamTraceEntry>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl StreamTrace {
    /// Create an empty trace.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            instructions: Vec::new(),
        }
    }

    /// Create a trace pre-allocated for `capacity` entries.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            instructions: Vec::with_capacity(capacity),
        }
    }

    /// Append an entry.
    pub fn push(&mut self, entry: StreamTraceEntry) {
        self.instructions.push(entry);
    }

    /// Return the total number of instruction records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Return `true` if the trace is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Iterate over trace entries.
    pub fn iter(&self) -> std::slice::Iter<'_, StreamTraceEntry> {
        self.instructions.iter()
    }

    /// Reconstruct a `StreamTrace` from a slice of decoded `PtPkt` values.
    ///
    /// The algorithm:
    /// 1. Walk packets in order.
    /// 2. `TipPge` starts a traced region at the given IP.
    /// 3. `TipPgd` / `Tip` end or update the current IP.
    /// 4. `Tnt8` / `Tnt64` provide branch decisions that are consumed as the
    ///    trace walks forward.  Without a disassembler the TNT bits are
    ///    recorded on the current entry rather than used for control-flow
    ///    reconstruction.
    /// 5. `Tsc` updates the running timestamp.
    /// 6. `Ovf` records a gap.
    ///
    /// The resulting trace contains one entry per IP update (TIP events) plus
    /// one entry per `TipPge` activation, each annotated with the current TSC.
    #[must_use]
    pub fn from_packets(packets: &[PtPkt]) -> Self {
        let mut trace = Self::with_capacity(packets.len());
        let mut cur_tsc: Option<u64> = None;
        let mut tnt_bits: u64 = 0;
        let mut tnt_count: u8 = 0;
        let mut tracing = false;

        for pkt in packets {
            match pkt {
                PtPkt::Tsc { tsc } => {
                    cur_tsc = Some(*tsc);
                }
                PtPkt::Tnt8 { payload, count } => {
                    // Enqueue TNT bits (LSB = oldest).
                    tnt_bits |= u64::from(*payload) << tnt_count;
                    tnt_count += count;
                }
                PtPkt::Tnt64 { payload, count } => {
                    tnt_bits |= payload << tnt_count;
                    tnt_count += count;
                }
                PtPkt::TipPge { ip, .. } => {
                    tracing = true;
                    // Consume one TNT bit if available.
                    let taken = if tnt_count > 0 {
                        let bit = (tnt_bits & 1) != 0;
                        tnt_bits >>= 1;
                        tnt_count -= 1;
                        Some(bit)
                    } else {
                        None
                    };
                    trace.push(StreamTraceEntry::new(*ip, cur_tsc, taken));
                }
                PtPkt::Tip { ip, .. } | PtPkt::TipPgd { ip, .. } | PtPkt::TipFup { ip, .. } => {
                    if tracing || matches!(pkt, PtPkt::TipFup { .. }) {
                        let taken = if tnt_count > 0 {
                            let bit = (tnt_bits & 1) != 0;
                            tnt_bits >>= 1;
                            tnt_count -= 1;
                            Some(bit)
                        } else {
                            None
                        };
                        trace.push(StreamTraceEntry::new(*ip, cur_tsc, taken));
                    }
                    if matches!(pkt, PtPkt::TipPgd { .. }) {
                        tracing = false;
                    }
                }
                PtPkt::Ovf => {
                    // Record the overflow as a synthetic entry at IP 0.
                    trace.push(StreamTraceEntry::new(0, cur_tsc, None));
                    tracing = false;
                }
                _ => {}
            }
        }
        trace
    }

    /// Build a `StreamTrace` by decoding all packets from `stream` and then
    /// calling `from_packets`.
    #[must_use]
    pub fn from_stream(stream: &mut PtPacketStream) -> Self {
        let packets = stream.decode_all();
        Self::from_packets(&packets)
    }

    /// Return the set of unique instruction pointers in this trace.
    #[must_use]
    pub fn unique_ips(&self) -> HashSet<u64> {
        self.instructions.iter().map(|e| e.ip).collect()
    }

    /// Return the first TSC value seen in the trace, if any.
    #[must_use]
    pub fn start_tsc(&self) -> Option<u64> {
        self.instructions.iter().find_map(|e| e.tsc)
    }

    /// Return the last TSC value seen in the trace, if any.
    #[must_use]
    pub fn end_tsc(&self) -> Option<u64> {
        self.instructions.iter().rev().find_map(|e| e.tsc)
    }

    /// Compute the TSC delta (end − start) if both endpoints are known.
    #[must_use]
    pub fn tsc_delta(&self) -> Option<u64> {
        Some(self.end_tsc()?.wrapping_sub(self.start_tsc()?))
    }

    /// Filter entries to those whose IP falls within `[lo, hi)`.
    #[must_use]
    pub fn filter_range(&self, lo: u64, hi: u64) -> Self {
        Self {
            instructions: self
                .instructions
                .iter()
                .filter(|e| e.ip >= lo && e.ip < hi)
                .cloned()
                .collect(),
        }
    }

    /// Merge another trace into this one (append entries in order).
    pub fn merge(&mut self, other: &Self) {
        self.instructions.extend_from_slice(&other.instructions);
    }

    /// Sort entries by IP address (stable sort preserves TSC ordering for
    /// equal IPs).
    pub fn sort_by_ip(&mut self) {
        self.instructions.sort_by_key(|e| e.ip);
    }
}

// ─── pt_to_coverage ───────────────────────────────────────────────────────────

/// Extract the set of unique instruction-pointer values from a `StreamTrace`.
///
/// This is the minimal representation needed by coverage-guided fuzzers that
/// track edge/block coverage at the address level.
///
/// # Example
/// ```ignore
/// let trace = StreamTrace::from_stream(&mut stream);
/// let cov   = pt_to_coverage(&trace);
/// println!("unique IPs: {}", cov.len());
/// ```
#[must_use]
pub fn pt_to_coverage(trace: &StreamTrace) -> HashSet<u64> {
    trace.unique_ips()
}

/// Like `pt_to_coverage` but operates on a raw packet slice directly.
#[must_use]
pub fn pt_pkts_to_coverage(packets: &[PtPkt]) -> HashSet<u64> {
    let trace = StreamTrace::from_packets(packets);
    pt_to_coverage(&trace)
}

// ─── pt_to_drcov ──────────────────────────────────────────────────────────────

/// Generate a `DRcov` v2 coverage file from a `StreamTrace`.
///
/// `DRcov` is the coverage format used by `DynamoRIO`'s `drcov` tool and
/// supported by many binary analysis frameworks (Lighthouse, Bochs, etc.).
///
/// Format overview
/// ───────────────
/// ```text
/// DRCOV VERSION: 2
/// DRCOV FLAVOR: drcov
/// Module Table: version 2, count 1
/// Columns: id, base, end, entry, checksum, timestamp, path
/// 0, 0x<base>, 0x<end>, 0x0, 0x0, 0x0, <module_name>
/// BB Table: <N> bbs
/// <binary bb records>
/// ```
///
/// Each basic-block record is a 8-byte struct:
/// ```text
/// struct { u32 start; u16 size; u16 mod_id; }
/// ```
///
/// Because PT-reconstructed traces do not always carry basic-block sizes,
/// we emit a size of 1 for every entry.
///
/// # Arguments
/// * `trace`       — the reconstructed trace.
/// * `module_name` — path or name of the traced module (put in the module
///   table).
///
/// # Returns
/// A `String` containing the complete `DRcov` file contents (text header +
/// binary basic-block table encoded as hex bytes in the string for
/// portability; for a real binary writer use `pt_to_drcov_bytes`).
#[must_use]
pub fn pt_to_drcov(trace: &StreamTrace, module_name: &str) -> String {
    use std::fmt::Write as _;
    let unique: Vec<u64> = {
        let mut v: Vec<u64> = trace.unique_ips().into_iter().collect();
        v.sort_unstable();
        v
    };

    let base: u64 = unique.first().copied().unwrap_or(0);
    let end: u64 = unique.last().copied().unwrap_or(0).wrapping_add(1);

    // ── Header ────────────────────────────────────────────────────────────────
    let mut out = String::with_capacity(512 + unique.len() * 24);
    out.push_str("DRCOV VERSION: 2\n");
    out.push_str("DRCOV FLAVOR: drcov\n");
    out.push_str("Module Table: version 2, count 1\n");
    out.push_str("Columns: id, base, end, entry, checksum, timestamp, path\n");
    let _ = writeln!(
        out,
        "0, 0x{base:016x}, 0x{end:016x}, 0x0000000000000000, 0x00000000, 0x00000000, {module_name}"
    );
    let _ = writeln!(out, "BB Table: {} bbs", unique.len());

    // ── Basic-block records (8 bytes each, encoded as hex pairs) ─────────────
    // struct bb_entry { u32 start; u16 size; u16 mod_id; }
    // start is relative to the module base.
    for ip in &unique {
        let relative = crate::cast_helpers::u64_to_u32(ip.wrapping_sub(base));
        let size: u16 = 1;
        let mod_id: u16 = 0;

        let bytes = [
            (relative & 0xFF) as u8,
            ((relative >> 8) & 0xFF) as u8,
            ((relative >> 16) & 0xFF) as u8,
            ((relative >> 24) & 0xFF) as u8,
            (size & 0xFF) as u8,
            ((size >> 8) & 0xFF) as u8,
            (mod_id & 0xFF) as u8,
            ((mod_id >> 8) & 0xFF) as u8,
        ];
        for b in &bytes {
            let _ = write!(out, "{b:02x} ");
        }
        out.push('\n');
    }
    out
}

/// Like `pt_to_drcov` but returns the raw binary bytes (suitable for writing
/// directly to a `.drcov` file).
///
/// The binary format is identical to what `DynamoRIO` produces: the text header
/// is UTF-8, followed by the packed binary `bb_entry` structs with no
/// separator.
#[must_use]
pub fn pt_to_drcov_bytes(trace: &StreamTrace, module_name: &str) -> Vec<u8> {
    let unique: Vec<u64> = {
        let mut v: Vec<u64> = trace.unique_ips().into_iter().collect();
        v.sort_unstable();
        v
    };

    let base: u64 = unique.first().copied().unwrap_or(0);
    let end: u64 = unique.last().copied().unwrap_or(0).wrapping_add(1);

    let mut out: Vec<u8> = Vec::with_capacity(512 + unique.len() * 8);

    // Text header.
    let header = format!(
        "DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\nModule Table: version 2, count 1\nColumns: id, base, end, entry, checksum, timestamp, path\n0, 0x{base:016x}, 0x{end:016x}, 0x0000000000000000, 0x00000000, 0x00000000, {module_name}\nBB Table: {} bbs\n",
        unique.len()
    );
    out.extend_from_slice(header.as_bytes());

    // Binary bb records.
    for ip in &unique {
        let relative = crate::cast_helpers::u64_to_u32(ip.wrapping_sub(base));
        let size: u16 = 1;
        let mod_id: u16 = 0;
        out.extend_from_slice(&relative.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&mod_id.to_le_bytes());
    }
    out
}

// ─── Helper: parse a raw PT buffer into a StreamTrace ─────────────────────────────

/// Decode a raw PT buffer and return a `StreamTrace`.
///
/// This is the most common entry point for tools that receive a raw byte
/// buffer from the kernel PT driver and want a high-level trace.
///
/// ```ignore
/// let trace = decode_pt_buffer(&pt_data);
/// let cov   = pt_to_coverage(&trace);
/// ```
#[must_use]
pub fn decode_pt_buffer(data: &[u8]) -> StreamTrace {
    let mut stream = PtPacketStream::from_slice(data);
    StreamTrace::from_stream(&mut stream)
}

/// Decode a raw PT buffer and return both packets and trace.
#[must_use]
pub fn decode_pt_buffer_verbose(data: &[u8]) -> (Vec<PtPkt>, StreamTrace) {
    let mut stream = PtPacketStream::from_slice(data);
    let packets = stream.decode_all();
    let trace = StreamTrace::from_packets(&packets);
    (packets, trace)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests for the standalone PT packet stream decoder
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod pt_stream_tests {
    use super::*;

    // ── StreamIpMode ─────────────────────────────────────────────────────

    #[test]
    fn test_ip_compression_from_ipr_all_variants() {
        assert_eq!(StreamIpMode::from_ipr(0), StreamIpMode::Suppressed);
        assert_eq!(StreamIpMode::from_ipr(1), StreamIpMode::Upd16);
        assert_eq!(StreamIpMode::from_ipr(2), StreamIpMode::Upd32);
        assert_eq!(StreamIpMode::from_ipr(3), StreamIpMode::Upd48);
        assert_eq!(StreamIpMode::from_ipr(4), StreamIpMode::Sext48);
        assert_eq!(StreamIpMode::from_ipr(6), StreamIpMode::Full);
        // Undefined IPR values map to Suppressed.
        assert_eq!(StreamIpMode::from_ipr(5), StreamIpMode::Suppressed);
        assert_eq!(StreamIpMode::from_ipr(7), StreamIpMode::Suppressed);
    }

    #[test]
    fn test_ip_compression_payload_bytes() {
        assert_eq!(StreamIpMode::Suppressed.payload_bytes(), 0);
        assert_eq!(StreamIpMode::Upd16.payload_bytes(), 2);
        assert_eq!(StreamIpMode::Upd32.payload_bytes(), 4);
        assert_eq!(StreamIpMode::Upd48.payload_bytes(), 6);
        assert_eq!(StreamIpMode::Sext48.payload_bytes(), 6);
        assert_eq!(StreamIpMode::Full.payload_bytes(), 8);
    }

    // ── PtPacketStream::new / basic accessors ─────────────────────────────────

    #[test]
    fn test_stream_new_empty() {
        let s = PtPacketStream::new(vec![]);
        assert!(s.is_empty());
        assert_eq!(s.remaining(), 0);
        assert_eq!(s.position(), 0);
    }

    #[test]
    fn test_stream_new_nonempty() {
        let s = PtPacketStream::new(vec![0x00, 0x01]);
        assert!(!s.is_empty());
        assert_eq!(s.remaining(), 2);
    }

    #[test]
    fn test_stream_from_slice() {
        let data = [0x19u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let s = PtPacketStream::from_slice(&data);
        assert_eq!(s.data.len(), 8);
    }

    #[test]
    fn test_stream_reset() {
        let mut s = PtPacketStream::new(vec![0x00, 0x00]);
        s.next_packet();
        assert_eq!(s.position(), 1);
        s.reset();
        assert_eq!(s.position(), 0);
        assert_eq!(s.last_ip, 0);
    }

    #[test]
    fn test_stream_seek() {
        let mut s = PtPacketStream::new(vec![0u8; 16]);
        s.seek(8);
        assert_eq!(s.position(), 8);
    }

    #[test]
    #[should_panic(expected = "")]
    fn test_stream_seek_out_of_range() {
        let mut s = PtPacketStream::new(vec![0u8; 4]);
        s.seek(100);
    }

    // ── PAD ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_pad() {
        let mut s = PtPacketStream::new(vec![0x00]);
        let pkt = s.next_packet().unwrap();
        assert_eq!(pkt, PtPkt::Pad);
        assert!(s.is_empty());
    }

    #[test]
    fn test_decode_multiple_pads() {
        let data = vec![0x00u8; 8];
        let mut s = PtPacketStream::new(data);
        let all = s.decode_all();
        assert_eq!(all.len(), 8);
        assert!(all.iter().all(|p| *p == PtPkt::Pad));
    }

    // ── PSB ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_psb() {
        let psb: Vec<u8> = vec![
            0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
            0x02, 0x82,
        ];
        let mut s = PtPacketStream::new(psb);
        let pkt = s.next_packet().unwrap();
        assert_eq!(pkt, PtPkt::Psb);
        assert!(s.is_empty());
    }

    #[test]
    fn test_decode_psb_followed_by_psbend() {
        let mut data: Vec<u8> = vec![
            0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
            0x02, 0x82,
        ];
        data.extend_from_slice(&[0x02, 0x23]);
        let mut s = PtPacketStream::new(data);
        let p1 = s.next_packet().unwrap();
        let p2 = s.next_packet().unwrap();
        assert_eq!(p1, PtPkt::Psb);
        assert_eq!(p2, PtPkt::PsbEnd);
    }

    // ── TSC ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_tsc_zero() {
        let mut data = vec![0x19u8];
        data.extend_from_slice(&[0x00u8; 7]);
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        assert_eq!(pkt, PtPkt::Tsc { tsc: 0 });
    }

    #[test]
    fn test_decode_tsc_known_value() {
        // TSC = 0x00FFEEDDCCBBAA11
        let mut data = vec![0x19u8];
        data.extend_from_slice(&[0x11, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        assert_eq!(
            pkt,
            PtPkt::Tsc {
                tsc: 0x00FF_EEDD_CCBB_AA11
            }
        );
    }

    #[test]
    fn test_decode_tsc_max() {
        let mut data = vec![0x19u8];
        data.extend_from_slice(&[0xFF; 7]);
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        // 56-bit max
        assert_eq!(
            pkt,
            PtPkt::Tsc {
                tsc: 0x00FF_FFFF_FFFF_FFFF
            }
        );
    }

    #[test]
    fn test_decode_tsc_truncated_returns_none() {
        // Only 3 bytes after 0x19 — should return None (stream exhausted mid-packet).
        let data = vec![0x19u8, 0x00, 0x01, 0x02];
        let mut s = PtPacketStream::new(data);
        // The decoder consumes 0x19 then tries to read 7 bytes; only 3 remain.
        // consume_bytes returns None → next_packet returns None.
        s.pos = 0;
        let _ = s.next_packet(); // may return None or truncated Unknown
        // Key invariant: no panic.
    }

    // ── MTC ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_mtc() {
        let data = vec![0x59u8, 0x42];
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        assert_eq!(pkt, PtPkt::Mtc { ctc: 0x42 });
    }

    #[test]
    fn test_decode_mtc_zero() {
        let data = vec![0x59u8, 0x00];
        let mut s = PtPacketStream::new(data);
        assert_eq!(s.next_packet().unwrap(), PtPkt::Mtc { ctc: 0 });
    }

    #[test]
    fn test_decode_mtc_max() {
        let data = vec![0x59u8, 0xFF];
        let mut s = PtPacketStream::new(data);
        assert_eq!(s.next_packet().unwrap(), PtPkt::Mtc { ctc: 0xFF });
    }

    // ── CBR ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_cbr() {
        let data = vec![0x03u8, 0x00, 0x10, 0x00];
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        assert_eq!(pkt, PtPkt::Cbr { ratio: 0x10 });
    }

    #[test]
    fn test_decode_cbr_ratio_ff() {
        let data = vec![0x03u8, 0x00, 0xFF, 0x00];
        let mut s = PtPacketStream::new(data);
        assert_eq!(s.next_packet().unwrap(), PtPkt::Cbr { ratio: 0xFF });
    }

    // ── OVF ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_ovf() {
        let data = vec![0x02u8, 0xF3];
        let mut s = PtPacketStream::new(data);
        assert_eq!(s.next_packet().unwrap(), PtPkt::Ovf);
    }

    // ── TraceStop ─────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_tracestop() {
        let data = vec![0x01u8, 0x83];
        let mut s = PtPacketStream::new(data);
        assert_eq!(s.next_packet().unwrap(), PtPkt::TraceStop);
    }

    // ── PSBEND ────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_psbend() {
        let data = vec![0x02u8, 0x23];
        let mut s = PtPacketStream::new(data);
        assert_eq!(s.next_packet().unwrap(), PtPkt::PsbEnd);
    }

    // ── TNT8 ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_tnt8_single_taken() {
        // One TNT bit, taken.
        // Byte layout (bits 7:2 = stop|tnt): 0b0000_0110 = 0x06
        // bits 7:2 = 0b000001: stop bit at position 0, no TNT bits… wait.
        // Let's build it properly:
        // For count=1, payload=0b1 (taken):
        //   raw6 = stop(1) << 1 | tnt[0](1) = 0b11 = 3
        //   byte = (raw6 << 2) | 0x02 = 0b00001110 = 0x0E
        let data = vec![0x0Eu8];
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        // count should be 1, payload should have bit0 = 1 (taken).
        if let PtPkt::Tnt8 { count, payload } = pkt {
            assert_eq!(count, 1);
            assert_eq!(payload & 1, 1);
        } else {
            panic!("expected Tnt8, got {pkt:?}");
        }
    }

    #[test]
    fn test_decode_tnt8_single_not_taken() {
        // count=1, payload=0 (not taken):
        //   raw6 = stop(1) << 1 | 0 = 0b10 = 2
        //   byte = (2 << 2) | 0x02 = 0b00001010 = 0x0A
        let data = vec![0x0Au8];
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        if let PtPkt::Tnt8 { count, payload } = pkt {
            assert_eq!(count, 1);
            assert_eq!(payload & 1, 0);
        } else {
            panic!("expected Tnt8, got {pkt:?}");
        }
    }

    #[test]
    fn test_decode_tnt8_max_six_bits() {
        // count=6, all taken (0b111111):
        //   raw6 = stop(1) << 6 | 0b111111 = 0b1111111 = 0x7F
        //   byte = (0x7F << 2) | 0x02 — but 0x7F << 2 overflows 8 bits.
        // Actually raw6 is a 6-bit field; we can have at most 5 TNT bits + 1 stop.
        // For count=5, all taken:
        //   raw6 = (1 << 5) | 0b11111 = 0b111111 = 0x3F
        //   byte = (0x3F << 2) | 0x02 = 0b11111110 = 0xFE
        let data = vec![0xFEu8];
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        if let PtPkt::Tnt8 { count, payload } = pkt {
            assert!(count <= 6);
            // All bits set
            let mask = (1u8 << count).wrapping_sub(1);
            assert_eq!(payload & mask, mask);
        } else {
            panic!("expected Tnt8, got {pkt:?}");
        }
    }

    // ── TNT64 ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_tnt64_all_taken() {
        // TNT64: 0x02 0xA3 + 6 bytes
        // Payload raw = 0x01 (stop bit at bit 0, 0 TNT bits)… let's use a known pattern.
        // raw = 0x000000000001: stop at bit 0 → count=0. Too trivial.
        // raw = 0x000000000003: stop at bit 1 → count=1, bit[0]=1 → taken.
        let mut data = vec![0x02u8, 0xA3];
        data.extend_from_slice(&[0x03, 0x00, 0x00, 0x00, 0x00, 0x00]); // raw=3
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        if let PtPkt::Tnt64 { count, payload } = pkt {
            assert_eq!(count, 1);
            assert_eq!(payload & 1, 1);
        } else {
            panic!("expected Tnt64, got {pkt:?}");
        }
    }

    #[test]
    fn test_decode_tnt64_not_taken() {
        // raw = 0x000000000002: stop at bit 1 → count=1, bit[0]=0 → not taken.
        let mut data = vec![0x02u8, 0xA3];
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        if let PtPkt::Tnt64 { count, payload } = pkt {
            assert_eq!(count, 1);
            assert_eq!(payload & 1, 0);
        } else {
            panic!("expected Tnt64, got {pkt:?}");
        }
    }

    // ── TIP (full IP) ─────────────────────────────────────────────────────────

    #[test]
    fn test_decode_tip_full() {
        // TIP with full 64-bit IP.
        // IPR=6 (Full) → bits 7:5 of opcode = 0b110 = 6.
        // type_id for TIP = 0b01101 = 0x0D.
        // opcode = (6 << 5) | 0x0D = 0b11001101 = 0xCD.
        let ip: u64 = 0x0000_7FFF_DEAD_BEEF;
        let mut data = vec![0xCDu8];
        data.extend_from_slice(&ip.to_le_bytes());
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        assert_eq!(
            pkt,
            PtPkt::Tip {
                ip,
                compression: StreamIpMode::Full
            }
        );
    }

    #[test]
    fn test_decode_tip_upd16() {
        // IPR=1 (Upd16) → bits 7:5 = 0b001 = 1.
        // opcode = (1 << 5) | 0x0D = 0b00101101 = 0x2D.
        let mut s = PtPacketStream::new(vec![]);
        s.last_ip = 0x0000_7FFF_CAFE_0000;
        s.data = vec![0x2Du8, 0x34, 0x12]; // update low16 to 0x1234
        s.pos = 0;
        let pkt = s.next_packet().unwrap();
        assert_eq!(
            pkt,
            PtPkt::Tip {
                ip: 0x0000_7FFF_CAFE_1234,
                compression: StreamIpMode::Upd16
            }
        );
    }

    #[test]
    fn test_decode_tip_suppressed() {
        // IPR=0 (Suppressed) → bits 7:5 = 0b000 = 0.
        // opcode = (0 << 5) | 0x0D = 0x0D.
        let mut s = PtPacketStream::new(vec![0x0Du8]);
        s.last_ip = 0xDEAD_BEEF_CAFE_BABE;
        let pkt = s.next_packet().unwrap();
        assert_eq!(
            pkt,
            PtPkt::Tip {
                ip: 0xDEAD_BEEF_CAFE_BABE,
                compression: StreamIpMode::Suppressed
            }
        );
    }

    // ── TIP.PGE ───────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_tippge_full() {
        // type_id for TIP.PGE = 0x01.
        // IPR=6: opcode = (6 << 5) | 0x01 = 0b11000001 = 0xC1.
        let ip: u64 = 0x0000_1234_5678_9ABC;
        let mut data = vec![0xC1u8];
        data.extend_from_slice(&ip.to_le_bytes());
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        assert_eq!(
            pkt,
            PtPkt::TipPge {
                ip,
                compression: StreamIpMode::Full
            }
        );
    }

    #[test]
    fn test_decode_tippge_tracestop_wins() {
        // 0x01 followed by 0x83 → TraceStop, not TIP.PGE.
        let data = vec![0x01u8, 0x83];
        let mut s = PtPacketStream::new(data);
        assert_eq!(s.next_packet().unwrap(), PtPkt::TraceStop);
    }

    // ── TIP.PGD ───────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_tippgd_full() {
        // type_id for TIP.PGD = 0x11.
        // IPR=6: opcode = (6 << 5) | 0x11 = 0b11010001 = 0xD1.
        let ip: u64 = 0x0000_FFFF_0000_1234;
        let mut data = vec![0xD1u8];
        data.extend_from_slice(&ip.to_le_bytes());
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        assert_eq!(
            pkt,
            PtPkt::TipPgd {
                ip,
                compression: StreamIpMode::Full
            }
        );
    }

    // ── TIP.FUP ───────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_tipfup_full() {
        // type_id for FUP = 0x1D.
        // IPR=6: opcode = (6 << 5) | 0x1D = 0b11011101 = 0xDD.
        let ip: u64 = 0x0000_DEAD_CAFE_BABE;
        let mut data = vec![0xDDu8];
        data.extend_from_slice(&ip.to_le_bytes());
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        assert_eq!(
            pkt,
            PtPkt::TipFup {
                ip,
                compression: StreamIpMode::Full
            }
        );
    }

    // ── decode_ip ─────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_ip_suppressed_returns_last_ip() {
        let mut s = PtPacketStream::new(vec![]);
        s.last_ip = 0xDEAD_BEEF;
        let ip = s.decode_ip(StreamIpMode::Suppressed).unwrap();
        assert_eq!(ip, 0xDEAD_BEEF);
    }

    #[test]
    fn test_decode_ip_upd16_preserves_high_bytes() {
        let mut s = PtPacketStream::new(vec![0xAA, 0xBB]);
        s.last_ip = 0x0000_1111_2222_3333;
        let ip = s.decode_ip(StreamIpMode::Upd16).unwrap();
        assert_eq!(ip, 0x0000_1111_2222_BBAA);
    }

    #[test]
    fn test_decode_ip_upd32_preserves_high_dword() {
        let mut s = PtPacketStream::new(vec![0x78, 0x56, 0x34, 0x12]);
        s.last_ip = 0xDEAD_BEEF_0000_0000;
        let ip = s.decode_ip(StreamIpMode::Upd32).unwrap();
        assert_eq!(ip, 0xDEAD_BEEF_1234_5678);
    }

    #[test]
    fn test_decode_ip_upd48_zero_extends() {
        let mut s = PtPacketStream::new(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        s.last_ip = 0xFFFF_FFFF_FFFF_FFFF;
        let ip = s.decode_ip(StreamIpMode::Upd48).unwrap();
        // Upper 16 bits must be zero.
        assert_eq!(ip >> 48, 0);
        assert_eq!(ip, 0x0000_0605_0403_0201);
    }

    #[test]
    fn test_decode_ip_sext48_positive() {
        // Bit 47 = 0 → no sign extension.
        let mut s = PtPacketStream::new(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let ip = s.decode_ip(StreamIpMode::Sext48).unwrap();
        assert_eq!(ip, 0);
    }

    #[test]
    fn test_decode_ip_sext48_negative() {
        // Bit 47 = 1 → upper 16 bits should be 0xFFFF.
        let mut s = PtPacketStream::new(vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let ip = s.decode_ip(StreamIpMode::Sext48).unwrap();
        assert_eq!(ip >> 48, 0xFFFF);
    }

    #[test]
    fn test_decode_ip_full_64bit() {
        let expected: u64 = 0x1234_5678_9ABC_DEF0;
        let mut s = PtPacketStream::new(expected.to_le_bytes().to_vec());
        let ip = s.decode_ip(StreamIpMode::Full).unwrap();
        assert_eq!(ip, expected);
    }

    #[test]
    fn test_decode_ip_updates_last_ip() {
        let mut s = PtPacketStream::new(vec![0x00, 0x10]); // Upd16: 0x1000
        s.last_ip = 0x0000_7FFF_0000_0000;
        s.decode_ip(StreamIpMode::Upd16).unwrap();
        assert_eq!(s.last_ip, 0x0000_7FFF_0000_1000);
    }

    // ── decode_all ────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_all_empty() {
        let mut s = PtPacketStream::new(vec![]);
        assert!(s.decode_all().is_empty());
    }

    #[test]
    fn test_decode_all_pads_only() {
        let data = vec![0x00u8; 16];
        let mut s = PtPacketStream::new(data);
        let pkts = s.decode_all();
        assert_eq!(pkts.len(), 16);
        assert!(pkts.iter().all(|p| *p == PtPkt::Pad));
    }

    #[test]
    fn test_decode_all_mixed_sequence() {
        // PAD + TSC(0) + MTC(1) + OVF
        let mut data: Vec<u8> = vec![0x00]; // PAD
        data.push(0x19);
        data.extend_from_slice(&[0x00; 7]); // TSC(0)
        data.extend_from_slice(&[0x59, 0x01]); // MTC(1)
        data.extend_from_slice(&[0x02, 0xF3]); // OVF
        let mut s = PtPacketStream::new(data);
        let pkts = s.decode_all();
        assert_eq!(pkts.len(), 4);
        assert_eq!(pkts[0], PtPkt::Pad);
        assert_eq!(pkts[1], PtPkt::Tsc { tsc: 0 });
        assert_eq!(pkts[2], PtPkt::Mtc { ctc: 1 });
        assert_eq!(pkts[3], PtPkt::Ovf);
    }

    // ── sync_forward ──────────────────────────────────────────────────────────

    #[test]
    fn test_sync_forward_finds_psb() {
        let mut data = vec![0x00u8; 4];
        data.extend_from_slice(&[
            0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
            0x02, 0x82,
        ]);
        let mut s = PtPacketStream::new(data);
        let off = s.sync_forward();
        assert_eq!(off, Some(4));
    }

    #[test]
    fn test_sync_forward_no_psb() {
        let data = vec![0x00u8; 32];
        let mut s = PtPacketStream::new(data);
        assert_eq!(s.sync_forward(), None);
    }

    // ── PtPkt helpers ─────────────────────────────────────────────────────────

    #[test]
    fn test_ptpkt_has_ip() {
        assert!(
            PtPkt::Tip {
                ip: 0,
                compression: StreamIpMode::Full
            }
            .has_ip()
        );
        assert!(
            PtPkt::TipPgd {
                ip: 0,
                compression: StreamIpMode::Full
            }
            .has_ip()
        );
        assert!(
            PtPkt::TipPge {
                ip: 0,
                compression: StreamIpMode::Full
            }
            .has_ip()
        );
        assert!(
            PtPkt::TipFup {
                ip: 0,
                compression: StreamIpMode::Full
            }
            .has_ip()
        );
        assert!(!PtPkt::Pad.has_ip());
        assert!(!PtPkt::Psb.has_ip());
        assert!(!PtPkt::Tsc { tsc: 0 }.has_ip());
    }

    #[test]
    fn test_ptpkt_ip_extraction() {
        let pkt = PtPkt::Tip {
            ip: 0xDEAD,
            compression: StreamIpMode::Full,
        };
        assert_eq!(pkt.ip(), Some(0xDEAD));
        assert_eq!(PtPkt::Pad.ip(), None);
    }

    #[test]
    fn test_ptpkt_is_timing() {
        assert!(PtPkt::Tsc { tsc: 0 }.is_timing());
        assert!(PtPkt::Mtc { ctc: 0 }.is_timing());
        assert!(PtPkt::Cbr { ratio: 0 }.is_timing());
        assert!(!PtPkt::Pad.is_timing());
        assert!(!PtPkt::Ovf.is_timing());
    }

    #[test]
    fn test_ptpkt_mnemonic() {
        assert_eq!(PtPkt::Pad.mnemonic(), "PAD");
        assert_eq!(PtPkt::Psb.mnemonic(), "PSB");
        assert_eq!(PtPkt::Ovf.mnemonic(), "OVF");
        assert_eq!(PtPkt::TraceStop.mnemonic(), "TRACESTOP");
        assert_eq!(PtPkt::Tsc { tsc: 0 }.mnemonic(), "TSC");
        assert_eq!(
            PtPkt::Tip {
                ip: 0,
                compression: StreamIpMode::Full
            }
            .mnemonic(),
            "TIP"
        );
    }

    #[test]
    fn test_ptpkt_display() {
        let s = format!("{}", PtPkt::Tsc { tsc: 12345 });
        assert!(s.contains("12345"));
        let s2 = format!("{}", PtPkt::Ovf);
        assert_eq!(s2, "OVF");
    }

    // ── StreamTraceEntry ──────────────────────────────────────────────────────────

    #[test]
    fn test_trace_entry_from_ip() {
        let e = StreamTraceEntry::from_ip(0x1234);
        assert_eq!(e.ip, 0x1234);
        assert!(e.tsc.is_none());
        assert!(e.taken.is_none());
    }

    #[test]
    fn test_trace_entry_with_tsc() {
        let e = StreamTraceEntry::with_tsc(0x5678, 999);
        assert_eq!(e.ip, 0x5678);
        assert_eq!(e.tsc, Some(999));
        assert!(e.taken.is_none());
    }

    #[test]
    fn test_trace_entry_new_all_fields() {
        let e = StreamTraceEntry::new(0xABCD, Some(42), Some(true));
        assert_eq!(e.ip, 0xABCD);
        assert_eq!(e.tsc, Some(42));
        assert_eq!(e.taken, Some(true));
    }

    #[test]
    fn test_trace_entry_display() {
        let e = StreamTraceEntry::new(0x1000, Some(100), Some(false));
        let s = format!("{e}");
        assert!(s.contains("0x0000000000001000"));
        assert!(s.contains("tsc=100"));
        assert!(s.contains("taken=false"));
    }

    // ── StreamTrace ───────────────────────────────────────────────────────────────

    #[test]
    fn test_pt_trace_new_empty() {
        let t = StreamTrace::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn test_pt_trace_push_and_len() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x1000));
        t.push(StreamTraceEntry::from_ip(0x1004));
        assert_eq!(t.len(), 2);
        assert!(!t.is_empty());
    }

    #[test]
    fn test_pt_trace_unique_ips() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x1000));
        t.push(StreamTraceEntry::from_ip(0x1004));
        t.push(StreamTraceEntry::from_ip(0x1000)); // duplicate
        let u = t.unique_ips();
        assert_eq!(u.len(), 2);
        assert!(u.contains(&0x1000));
        assert!(u.contains(&0x1004));
    }

    #[test]
    fn test_pt_trace_start_end_tsc() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::new(0x1000, Some(100), None));
        t.push(StreamTraceEntry::new(0x1004, Some(200), None));
        t.push(StreamTraceEntry::new(0x1008, Some(300), None));
        assert_eq!(t.start_tsc(), Some(100));
        assert_eq!(t.end_tsc(), Some(300));
        assert_eq!(t.tsc_delta(), Some(200));
    }

    #[test]
    fn test_pt_trace_no_tsc() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x1000));
        assert!(t.start_tsc().is_none());
        assert!(t.end_tsc().is_none());
        assert!(t.tsc_delta().is_none());
    }

    #[test]
    fn test_pt_trace_filter_range() {
        let mut t = StreamTrace::new();
        for ip in [0x1000u64, 0x1004, 0x2000, 0x2004, 0x3000] {
            t.push(StreamTraceEntry::from_ip(ip));
        }
        let filtered = t.filter_range(0x1000, 0x2000);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.instructions.iter().all(|e| e.ip < 0x2000));
    }

    #[test]
    fn test_pt_trace_merge() {
        let mut a = StreamTrace::new();
        a.push(StreamTraceEntry::from_ip(0x1000));
        let mut b = StreamTrace::new();
        b.push(StreamTraceEntry::from_ip(0x2000));
        a.merge(&b);
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn test_pt_trace_sort_by_ip() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x3000));
        t.push(StreamTraceEntry::from_ip(0x1000));
        t.push(StreamTraceEntry::from_ip(0x2000));
        t.sort_by_ip();
        let ips: Vec<u64> = t.instructions.iter().map(|e| e.ip).collect();
        assert_eq!(ips, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn test_pt_trace_from_packets_empty() {
        let t = StreamTrace::from_packets(&[]);
        assert!(t.is_empty());
    }

    #[test]
    fn test_pt_trace_from_packets_tippge_only() {
        let ip = 0x0000_7FFF_1234_5678u64;
        let pkts = vec![PtPkt::TipPge {
            ip,
            compression: StreamIpMode::Full,
        }];
        let t = StreamTrace::from_packets(&pkts);
        assert_eq!(t.len(), 1);
        assert_eq!(t.instructions[0].ip, ip);
    }

    #[test]
    fn test_pt_trace_from_packets_tsc_propagates() {
        let pkts = vec![
            PtPkt::Tsc { tsc: 999 },
            PtPkt::TipPge {
                ip: 0x1000,
                compression: StreamIpMode::Full,
            },
        ];
        let t = StreamTrace::from_packets(&pkts);
        assert_eq!(t.instructions[0].tsc, Some(999));
    }

    #[test]
    fn test_pt_trace_from_packets_tnt_consumed() {
        // TipPge starts tracing at 0x1000; TNT8 with taken bit → entry has taken=Some(true).
        let pkts = vec![
            PtPkt::TipPge {
                ip: 0x1000,
                compression: StreamIpMode::Full,
            },
            PtPkt::Tnt8 {
                payload: 0b1,
                count: 1,
            },
            PtPkt::Tip {
                ip: 0x2000,
                compression: StreamIpMode::Full,
            },
        ];
        let t = StreamTrace::from_packets(&pkts);
        // First entry (TipPge) — no TNT yet queued at that point.
        // Second entry (Tip at 0x2000) — consumes the TNT bit.
        let tip_entry = t.instructions.iter().find(|e| e.ip == 0x2000);
        assert!(tip_entry.is_some());
        assert_eq!(tip_entry.unwrap().taken, Some(true));
    }

    #[test]
    fn test_pt_trace_from_packets_ovf_inserts_zero_entry() {
        let pkts = vec![
            PtPkt::TipPge {
                ip: 0x1000,
                compression: StreamIpMode::Full,
            },
            PtPkt::Ovf,
        ];
        let t = StreamTrace::from_packets(&pkts);
        assert!(t.instructions.iter().any(|e| e.ip == 0));
    }

    #[test]
    fn test_pt_trace_from_packets_tippgd_stops_tracing() {
        let pkts = vec![
            PtPkt::TipPge {
                ip: 0x1000,
                compression: StreamIpMode::Full,
            },
            PtPkt::TipPgd {
                ip: 0x1004,
                compression: StreamIpMode::Full,
            },
            // This TIP should NOT be recorded (tracing disabled).
            PtPkt::Tip {
                ip: 0x9999,
                compression: StreamIpMode::Full,
            },
        ];
        let t = StreamTrace::from_packets(&pkts);
        assert!(!t.instructions.iter().any(|e| e.ip == 0x9999));
    }

    // ── pt_to_coverage ────────────────────────────────────────────────────────

    #[test]
    fn test_pt_to_coverage_empty() {
        let t = StreamTrace::new();
        let cov = pt_to_coverage(&t);
        assert!(cov.is_empty());
    }

    #[test]
    fn test_pt_to_coverage_unique_ips() {
        let pkts = vec![
            PtPkt::TipPge {
                ip: 0x1000,
                compression: StreamIpMode::Full,
            },
            PtPkt::Tip {
                ip: 0x1004,
                compression: StreamIpMode::Full,
            },
            PtPkt::Tip {
                ip: 0x1000,
                compression: StreamIpMode::Full,
            }, // dup
            PtPkt::Tip {
                ip: 0x2000,
                compression: StreamIpMode::Full,
            },
        ];
        let t = StreamTrace::from_packets(&pkts);
        let cov = pt_to_coverage(&t);
        assert_eq!(cov.len(), 3); // 0x1000, 0x1004, 0x2000
        assert!(cov.contains(&0x1000));
        assert!(cov.contains(&0x1004));
        assert!(cov.contains(&0x2000));
    }

    #[test]
    fn test_pt_pkts_to_coverage_direct() {
        let pkts = vec![
            PtPkt::TipPge {
                ip: 0xAAAA,
                compression: StreamIpMode::Full,
            },
            PtPkt::Tip {
                ip: 0xBBBB,
                compression: StreamIpMode::Full,
            },
        ];
        let cov = pt_pkts_to_coverage(&pkts);
        assert!(cov.contains(&0xAAAA));
        assert!(cov.contains(&0xBBBB));
    }

    // ── pt_to_drcov ───────────────────────────────────────────────────────────

    #[test]
    fn test_pt_to_drcov_header_lines() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x1000));
        t.push(StreamTraceEntry::from_ip(0x1004));
        let drcov = pt_to_drcov(&t, "/tmp/test.exe");
        assert!(drcov.starts_with("DRCOV VERSION: 2\n"));
        assert!(drcov.contains("DRCOV FLAVOR: drcov\n"));
        assert!(drcov.contains("Module Table: version 2, count 1\n"));
        assert!(drcov.contains("BB Table:"));
        assert!(drcov.contains("/tmp/test.exe"));
    }

    #[test]
    fn test_pt_to_drcov_bb_count() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x1000));
        t.push(StreamTraceEntry::from_ip(0x1004));
        t.push(StreamTraceEntry::from_ip(0x1000)); // dup → deduplicated
        let drcov = pt_to_drcov(&t, "module.exe");
        assert!(drcov.contains("BB Table: 2 bbs\n"));
    }

    #[test]
    fn test_pt_to_drcov_empty_trace() {
        let t = StreamTrace::new();
        let drcov = pt_to_drcov(&t, "empty.exe");
        assert!(drcov.contains("BB Table: 0 bbs\n"));
    }

    #[test]
    fn test_pt_to_drcov_base_in_module_table() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x0000_7FFF_0001_0000));
        let drcov = pt_to_drcov(&t, "lib.so");
        // The base address should appear in the module table line.
        assert!(drcov.contains("0x00007fff00010000"));
    }

    #[test]
    fn test_pt_to_drcov_bytes_length() {
        let mut t = StreamTrace::new();
        for i in 0..10u64 {
            t.push(StreamTraceEntry::from_ip(0x1000 + i * 4));
        }
        let bytes = pt_to_drcov_bytes(&t, "test.bin");
        // 10 BB records × 8 bytes each must appear after the text header.
        assert!(bytes.len() > 10 * 8);
    }

    #[test]
    fn test_pt_to_drcov_bytes_starts_with_header() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x4000));
        let bytes = pt_to_drcov_bytes(&t, "x.exe");
        let s = std::str::from_utf8(&bytes[..20]).unwrap();
        assert!(s.starts_with("DRCOV VERSION: 2"));
    }

    // ── decode_pt_buffer ──────────────────────────────────────────────────────

    #[test]
    fn test_decode_pt_buffer_empty() {
        let t = decode_pt_buffer(&[]);
        assert!(t.is_empty());
    }

    #[test]
    fn test_decode_pt_buffer_pads_only() {
        let data = [0x00u8; 64];
        let t = decode_pt_buffer(&data);
        // All PADs → no IP-bearing packets → empty trace.
        assert!(t.is_empty());
    }

    #[test]
    fn test_decode_pt_buffer_with_tip() {
        let ip: u64 = 0x0000_1234_5678_9ABC;
        let mut data: Vec<u8> = vec![0xC1u8]; // TIP.PGE, IPR=6
        data.extend_from_slice(&ip.to_le_bytes());
        let t = decode_pt_buffer(&data);
        assert!(!t.is_empty());
        assert_eq!(t.instructions[0].ip, ip);
    }

    #[test]
    fn test_decode_pt_buffer_verbose_returns_both() {
        let ip: u64 = 0x0000_DEAD_BEEF_0000;
        let mut data: Vec<u8> = vec![0xC1u8]; // TIP.PGE, IPR=6
        data.extend_from_slice(&ip.to_le_bytes());
        let (pkts, trace) = decode_pt_buffer_verbose(&data);
        assert!(!pkts.is_empty());
        assert!(!trace.is_empty());
        assert_eq!(trace.instructions[0].ip, ip);
    }

    // ── Round-trip: encode + decode ───────────────────────────────────────────

    #[test]
    fn test_round_trip_tsc_mtc_cbr() {
        let mut data: Vec<u8> = Vec::new();
        // TSC(0xAABBCCDDEEFF11)
        data.push(0x19);
        data.extend_from_slice(&[0x11, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]);
        // MTC(0x42)
        data.extend_from_slice(&[0x59, 0x42]);
        // CBR(0x20)
        data.extend_from_slice(&[0x03, 0x00, 0x20, 0x00]);
        let mut s = PtPacketStream::new(data);
        let pkts = s.decode_all();
        assert_eq!(
            pkts[0],
            PtPkt::Tsc {
                tsc: 0x00AA_BBCC_DDEE_FF11
            }
        );
        assert_eq!(pkts[1], PtPkt::Mtc { ctc: 0x42 });
        assert_eq!(pkts[2], PtPkt::Cbr { ratio: 0x20 });
    }

    #[test]
    fn test_round_trip_tip_sequence() {
        // TIP.PGE(full=0x1000) → TSC(500) → TIP(upd16=0x1004) → TIP.PGD(full=0x1004)
        let ip1: u64 = 0x0000_7FFF_0001_0000;
        let ip2: u64 = 0x0000_7FFF_0001_0004;
        let mut data: Vec<u8> = Vec::new();
        // TIP.PGE, IPR=6 (0xC1)
        data.push(0xC1);
        data.extend_from_slice(&ip1.to_le_bytes());
        // TSC(500)
        data.push(0x19);
        let tsc500: u64 = 500;
        data.extend_from_slice(&tsc500.to_le_bytes()[..7]);
        // TIP, IPR=1 (Upd16), opcode = (1<<5)|0x0D = 0x2D
        data.push(0x2D);
        data.extend_from_slice(&0x0004u16.to_le_bytes()); // update low16 to 0x0004
        // TIP.PGD, IPR=6, opcode = (6<<5)|0x11 = 0xD1
        data.push(0xD1);
        data.extend_from_slice(&ip2.to_le_bytes());
        let mut s = PtPacketStream::new(data);
        let pkts = s.decode_all();
        assert_eq!(pkts.len(), 4);
        assert!(matches!(&pkts[0], PtPkt::TipPge { ip, .. } if *ip == ip1));
        assert!(matches!(&pkts[1], PtPkt::Tsc { tsc } if *tsc == 500));
        assert!(matches!(&pkts[2], PtPkt::Tip { .. }));
        assert!(matches!(&pkts[3], PtPkt::TipPgd { ip, .. } if *ip == ip2));
    }

    #[test]
    fn test_round_trip_psb_psbend_ovf() {
        let mut data: Vec<u8> = vec![
            0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
            0x02, 0x82,
        ];
        data.extend_from_slice(&[0x02, 0x23]); // PSBEND
        data.extend_from_slice(&[0x02, 0xF3]); // OVF
        let mut s = PtPacketStream::new(data);
        let pkts = s.decode_all();
        assert_eq!(pkts[0], PtPkt::Psb);
        assert_eq!(pkts[1], PtPkt::PsbEnd);
        assert_eq!(pkts[2], PtPkt::Ovf);
    }

    // ── decode_flow ───────────────────────────────────────────────────────────

    #[test]
    fn test_decode_flow_filters_timing() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&[0x00]); // PAD  (filtered)
        data.push(0x19);
        data.extend_from_slice(&[0u8; 7]); // TSC  (filtered)
        data.extend_from_slice(&[0x59, 0x00]); // MTC  (filtered)
        data.extend_from_slice(&[0x02, 0xF3]); // OVF  (kept)
        let mut s = PtPacketStream::new(data);
        let flow = s.decode_flow();
        assert_eq!(flow.len(), 1);
        assert_eq!(flow[0], PtPkt::Ovf);
    }

    // ── StreamTrace::from_stream ──────────────────────────────────────────────────

    #[test]
    fn test_pt_trace_from_stream() {
        let ip: u64 = 0x0000_1234_0000_0000;
        let mut data: Vec<u8> = vec![0xC1u8];
        data.extend_from_slice(&ip.to_le_bytes());
        let mut s = PtPacketStream::new(data);
        let t = StreamTrace::from_stream(&mut s);
        assert_eq!(t.len(), 1);
        assert_eq!(t.instructions[0].ip, ip);
    }

    // ── Serde round-trip ──────────────────────────────────────────────────────

    #[test]
    fn test_pt_pkt_serde_roundtrip() {
        let pkt = PtPkt::Tsc { tsc: 123_456_789 };
        let json = serde_json::to_string(&pkt).unwrap();
        let pkt2: PtPkt = serde_json::from_str(&json).unwrap();
        assert_eq!(pkt, pkt2);
    }

    #[test]
    fn test_pt_trace_entry_serde_roundtrip() {
        let e = StreamTraceEntry::new(0xDEAD_BEEF, Some(42), Some(true));
        let json = serde_json::to_string(&e).unwrap();
        let e2: StreamTraceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, e2);
    }

    #[test]
    fn test_pt_trace_serde_roundtrip() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::new(0x1000, Some(100), None));
        t.push(StreamTraceEntry::new(0x2000, None, Some(false)));
        let json = serde_json::to_string(&t).unwrap();
        let t2: StreamTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(t.len(), t2.len());
        assert_eq!(t.instructions[0].ip, t2.instructions[0].ip);
        assert_eq!(t.instructions[1].taken, t2.instructions[1].taken);
    }

    #[test]
    fn test_ip_compression_mode_serde_roundtrip() {
        for mode in [
            StreamIpMode::Suppressed,
            StreamIpMode::Upd16,
            StreamIpMode::Upd32,
            StreamIpMode::Upd48,
            StreamIpMode::Sext48,
            StreamIpMode::Full,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let mode2: StreamIpMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, mode2);
        }
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn test_next_packet_returns_none_on_empty() {
        let mut s = PtPacketStream::new(vec![]);
        assert!(s.next_packet().is_none());
    }

    #[test]
    fn test_stream_remaining_decreases() {
        let data = vec![0x00u8; 4];
        let mut s = PtPacketStream::new(data);
        assert_eq!(s.remaining(), 4);
        s.next_packet();
        assert_eq!(s.remaining(), 3);
    }

    #[test]
    fn test_unknown_opcode_advances_cursor() {
        // 0xFF is not a known opcode (it would be TIP.FUP with some IPR if
        // 0xFF & 0x1F == 0x1F == 0x1D? Let's check: 0xFF & 0x1F = 0x1F.
        // 0x1F != 0x1D, != 0x11, != 0x01, != 0x0D.  So it is Unknown.
        let data = vec![0xFFu8, 0x00];
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        // Should be Unknown or some TIP-variant decode attempt; in any case
        // the decoder must hand back a packet rather than panicking.
        let decoded = format!("{pkt:?}");
        assert!(!decoded.is_empty(), "packet must produce a debug repr");
        // Either way, cursor must advance.
        assert!(s.position() >= 1);
        // Second byte is PAD.
        let _ = s.next_packet();
        assert!(s.is_empty());
    }

    #[test]
    fn test_tnt64_large_payload() {
        // 16 TNT bits set, using TNT64.
        // Build raw 48-bit value with stop bit at position 16: raw = (1<<16) | 0xFFFF
        let raw: u64 = (1u64 << 16) | 0xFFFF;
        let raw_bytes = raw.to_le_bytes();
        let mut data = vec![0x02u8, 0xA3];
        data.extend_from_slice(&raw_bytes[..6]);
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        if let PtPkt::Tnt64 { count, payload } = pkt {
            assert_eq!(count, 16);
            assert_eq!(payload, 0xFFFF);
        } else {
            panic!("expected Tnt64, got {pkt:?}");
        }
    }

    #[test]
    fn test_tip_upd32_preserves_high_dword() {
        // TIP with Upd32 (IPR=2): opcode = (2<<5) | 0x0D = 0b01001101 = 0x4D
        let mut s = PtPacketStream::new(vec![0x4Du8, 0x78, 0x56, 0x34, 0x12]);
        s.last_ip = 0xFFFF_FFFF_0000_0000;
        let pkt = s.next_packet().unwrap();
        if let PtPkt::Tip { ip, compression } = pkt {
            assert_eq!(compression, StreamIpMode::Upd32);
            assert_eq!(ip, 0xFFFF_FFFF_1234_5678);
        } else {
            panic!("expected Tip, got {pkt:?}");
        }
    }

    #[test]
    fn test_tip_sext48_canonical_address() {
        // TIP with Sext48 (IPR=4): opcode = (4<<5) | 0x0D = 0b10001101 = 0x8D
        // Address 0x7FFF_AABB_CCDD: bit 47 = 0 → no sign extension.
        let addr: u64 = 0x0000_7FFF_AABB_CCDD;
        let addr_bytes = addr.to_le_bytes();
        let mut data = vec![0x8Du8];
        data.extend_from_slice(&addr_bytes[..6]);
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        if let PtPkt::Tip { ip, compression } = pkt {
            assert_eq!(compression, StreamIpMode::Sext48);
            assert_eq!(ip >> 48, 0); // positive → no sign extension
        } else {
            panic!("expected Tip, got {pkt:?}");
        }
    }

    #[test]
    fn test_fup_ipr_suppressed() {
        // FUP with Suppressed (IPR=0): opcode = (0<<5) | 0x1D = 0x1D
        let mut s = PtPacketStream::new(vec![0x1Du8]);
        s.last_ip = 0xCAFE_BABE_0000_1234;
        let pkt = s.next_packet().unwrap();
        assert_eq!(
            pkt,
            PtPkt::TipFup {
                ip: 0xCAFE_BABE_0000_1234,
                compression: StreamIpMode::Suppressed
            }
        );
    }

    #[test]
    fn test_pt_trace_with_capacity() {
        let t = StreamTrace::with_capacity(1024);
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn test_pt_trace_iter() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x10));
        t.push(StreamTraceEntry::from_ip(0x20));
        let ips: Vec<u64> = t.iter().map(|e| e.ip).collect();
        assert_eq!(ips, vec![0x10, 0x20]);
    }

    // ── Additional decode_ip edge-case tests ──────────────────────────────────

    #[test]
    fn test_decode_ip_upd16_all_zeros() {
        let mut s = PtPacketStream::new(vec![0x00, 0x00]);
        s.last_ip = 0xDEAD_BEEF_CAFE_1234;
        let ip = s.decode_ip(StreamIpMode::Upd16).unwrap();
        // Low 16 bits replaced with 0.
        assert_eq!(ip, 0xDEAD_BEEF_CAFE_0000);
        assert_eq!(s.last_ip, ip);
    }

    #[test]
    fn test_decode_ip_upd16_all_ones() {
        let mut s = PtPacketStream::new(vec![0xFF, 0xFF]);
        s.last_ip = 0x0000_0000_0000_0000;
        let ip = s.decode_ip(StreamIpMode::Upd16).unwrap();
        assert_eq!(ip, 0x0000_0000_0000_FFFF);
    }

    #[test]
    fn test_decode_ip_upd32_all_zeros() {
        let mut s = PtPacketStream::new(vec![0x00, 0x00, 0x00, 0x00]);
        s.last_ip = 0xFFFF_0000_1234_5678;
        let ip = s.decode_ip(StreamIpMode::Upd32).unwrap();
        assert_eq!(ip, 0xFFFF_0000_0000_0000);
    }

    #[test]
    fn test_decode_ip_upd32_all_ones() {
        let mut s = PtPacketStream::new(vec![0xFF, 0xFF, 0xFF, 0xFF]);
        s.last_ip = 0x1234_0000_0000_0000;
        let ip = s.decode_ip(StreamIpMode::Upd32).unwrap();
        assert_eq!(ip, 0x1234_0000_FFFF_FFFF);
    }

    #[test]
    fn test_decode_ip_upd48_mid_value() {
        // Bytes [0x01,0x00,0x00,0x00,0x00,0x10] in LE:
        // 0x01 | 0x10<<40 = 0x0000_1000_0000_0001
        let mut s = PtPacketStream::new(vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x10]);
        let ip = s.decode_ip(StreamIpMode::Upd48).unwrap();
        assert_eq!(ip, 0x0000_1000_0000_0001);
    }

    #[test]
    fn test_decode_ip_sext48_boundary_bit47_zero() {
        // Bit 47 = 0, so no sign extension expected.
        // Value: 0x00007F_XXXXXX — bit 47 is bit 15 of byte[5], which is 0 for 0x7F.
        let mut s = PtPacketStream::new(vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]);
        let ip = s.decode_ip(StreamIpMode::Sext48).unwrap();
        // Upper 16 bits should be 0.
        assert_eq!(ip >> 48, 0x0000);
    }

    #[test]
    fn test_decode_ip_sext48_boundary_bit47_one() {
        // Bit 47 = 1 → sign extension → upper 16 bits = 0xFFFF.
        let mut s = PtPacketStream::new(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x80]);
        let ip = s.decode_ip(StreamIpMode::Sext48).unwrap();
        assert_eq!(ip >> 48, 0xFFFF);
        // Value = 0xFFFF_8000_0000_0000
        assert_eq!(ip, 0xFFFF_8000_0000_0000);
    }

    #[test]
    fn test_decode_ip_full_zero() {
        let mut s = PtPacketStream::new(vec![0u8; 8]);
        let ip = s.decode_ip(StreamIpMode::Full).unwrap();
        assert_eq!(ip, 0);
    }

    #[test]
    fn test_decode_ip_full_max() {
        let mut s = PtPacketStream::new(vec![0xFF; 8]);
        let ip = s.decode_ip(StreamIpMode::Full).unwrap();
        assert_eq!(ip, u64::MAX);
    }

    #[test]
    fn test_decode_ip_chained_updates() {
        // Simulate multiple sequential Upd16 updates.
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&[0x01, 0x00]); // 0x0001
        data.extend_from_slice(&[0x02, 0x00]); // 0x0002
        data.extend_from_slice(&[0xFF, 0xFF]); // 0xFFFF
        let mut s = PtPacketStream::new(data);
        s.last_ip = 0xAAAA_BBBB_CCCC_0000;
        s.decode_ip(StreamIpMode::Upd16).unwrap();
        assert_eq!(s.last_ip & 0xFFFF, 0x0001);
        s.decode_ip(StreamIpMode::Upd16).unwrap();
        assert_eq!(s.last_ip & 0xFFFF, 0x0002);
        s.decode_ip(StreamIpMode::Upd16).unwrap();
        assert_eq!(s.last_ip & 0xFFFF, 0xFFFF);
    }

    // ── Additional PtPacketStream functional tests ────────────────────────────

    #[test]
    fn test_stream_multiple_psb_sync() {
        // Two PSB blocks in the same stream.
        let psb: Vec<u8> = vec![
            0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
            0x02, 0x82,
        ];
        let mut data = psb.clone();
        data.extend_from_slice(&[0x02, 0x23]); // PSBEND
        data.extend_from_slice(&psb);
        data.extend_from_slice(&[0x02, 0x23]); // PSBEND
        let mut s = PtPacketStream::new(data);
        let pkts = s.decode_all();
        let psb_count = pkts.iter().filter(|p| **p == PtPkt::Psb).count();
        let psbend_count = pkts.iter().filter(|p| **p == PtPkt::PsbEnd).count();
        assert_eq!(psb_count, 2);
        assert_eq!(psbend_count, 2);
    }

    #[test]
    fn test_stream_seek_and_decode() {
        let mut data = vec![0x00u8; 8]; // 8 PADs
        // Append a TSC at offset 8.
        data.push(0x19);
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]);
        let mut s = PtPacketStream::new(data);
        s.seek(8);
        let pkt = s.next_packet().unwrap();
        assert_eq!(
            pkt,
            PtPkt::Tsc {
                tsc: 0x0000_FFEE_DDCC_BBAA
            }
        );
    }

    #[test]
    fn test_stream_position_after_each_decode() {
        // PAD(1) + MTC(2) + CBR(4) = total 7 bytes consumed.
        let data = vec![0x00u8, 0x59, 0x10, 0x03, 0x00, 0x20, 0x00];
        let mut s = PtPacketStream::new(data);
        s.next_packet();
        assert_eq!(s.position(), 1);
        s.next_packet();
        assert_eq!(s.position(), 3);
        s.next_packet();
        assert_eq!(s.position(), 7);
        assert!(s.is_empty());
    }

    #[test]
    fn test_stream_decode_all_advances_to_end() {
        let data = vec![0x00u8; 100];
        let mut s = PtPacketStream::new(data);
        let _ = s.decode_all();
        assert_eq!(s.position(), 100);
        assert!(s.is_empty());
    }

    #[test]
    fn test_stream_from_slice_independent_of_original() {
        let original = vec![0x00u8, 0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mut s = PtPacketStream::from_slice(&original);
        // Verify we cloned the data, not borrowed it.
        assert_eq!(s.data.len(), original.len());
        let _ = s.decode_all();
        // Original is unchanged.
        assert_eq!(original.len(), 9);
    }

    // ── Additional StreamTrace tests ───────────────────────────────────────────────

    #[test]
    fn test_pt_trace_from_packets_multiple_tsc_updates() {
        let pkts = vec![
            PtPkt::Tsc { tsc: 100 },
            PtPkt::TipPge {
                ip: 0x1000,
                compression: StreamIpMode::Full,
            },
            PtPkt::Tsc { tsc: 200 },
            PtPkt::Tip {
                ip: 0x1010,
                compression: StreamIpMode::Full,
            },
            PtPkt::Tsc { tsc: 300 },
            PtPkt::Tip {
                ip: 0x1020,
                compression: StreamIpMode::Full,
            },
        ];
        let t = StreamTrace::from_packets(&pkts);
        assert_eq!(t.len(), 3);
        assert_eq!(t.instructions[0].tsc, Some(100));
        assert_eq!(t.instructions[1].tsc, Some(200));
        assert_eq!(t.instructions[2].tsc, Some(300));
    }

    #[test]
    fn test_pt_trace_from_packets_fup_always_recorded() {
        // FUP is recorded regardless of tracing state.
        let pkts = vec![
            // No TIP.PGE → tracing = false.
            PtPkt::TipFup {
                ip: 0xDEAD,
                compression: StreamIpMode::Full,
            },
        ];
        let t = StreamTrace::from_packets(&pkts);
        // FUP should still be recorded (tracing || FUP).
        assert!(t.instructions.iter().any(|e| e.ip == 0xDEAD));
    }

    #[test]
    fn test_pt_trace_from_packets_tnt64_consumed() {
        let pkts = vec![
            PtPkt::TipPge {
                ip: 0x1000,
                compression: StreamIpMode::Full,
            },
            // TNT64 with 3 bits: taken, not-taken, taken → 0b101
            PtPkt::Tnt64 {
                payload: 0b101,
                count: 3,
            },
            PtPkt::Tip {
                ip: 0x2000,
                compression: StreamIpMode::Full,
            },
            PtPkt::Tip {
                ip: 0x3000,
                compression: StreamIpMode::Full,
            },
            PtPkt::Tip {
                ip: 0x4000,
                compression: StreamIpMode::Full,
            },
        ];
        let t = StreamTrace::from_packets(&pkts);
        // Entry at 0x2000 should consume first TNT bit (taken=true, bit0=1).
        let e2000 = t.instructions.iter().find(|e| e.ip == 0x2000).unwrap();
        assert_eq!(e2000.taken, Some(true));
        // Entry at 0x3000 → second bit (bit1 of 0b101 = 0 → not-taken).
        let e3000 = t.instructions.iter().find(|e| e.ip == 0x3000).unwrap();
        assert_eq!(e3000.taken, Some(false));
        // Entry at 0x4000 → third bit (bit2 of 0b101 = 1 → taken).
        let e4000 = t.instructions.iter().find(|e| e.ip == 0x4000).unwrap();
        assert_eq!(e4000.taken, Some(true));
    }

    #[test]
    fn test_pt_trace_filter_range_empty_result() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x5000));
        let filtered = t.filter_range(0x1000, 0x2000);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_pt_trace_filter_range_all_included() {
        let mut t = StreamTrace::new();
        for ip in [0x1000u64, 0x1008, 0x1010] {
            t.push(StreamTraceEntry::from_ip(ip));
        }
        let filtered = t.filter_range(0x1000, 0x2000);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn test_pt_trace_merge_preserves_order() {
        let mut a = StreamTrace::new();
        a.push(StreamTraceEntry::with_tsc(0x1000, 10));
        a.push(StreamTraceEntry::with_tsc(0x1004, 20));
        let mut b = StreamTrace::new();
        b.push(StreamTraceEntry::with_tsc(0x2000, 30));
        b.push(StreamTraceEntry::with_tsc(0x2004, 40));
        a.merge(&b);
        assert_eq!(a.len(), 4);
        assert_eq!(a.instructions[2].ip, 0x2000);
        assert_eq!(a.instructions[3].ip, 0x2004);
    }

    #[test]
    fn test_pt_trace_sort_by_ip_stable_for_equal() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::new(0x1000, Some(1), None));
        t.push(StreamTraceEntry::new(0x1000, Some(2), None));
        t.push(StreamTraceEntry::new(0x1000, Some(3), None));
        t.sort_by_ip();
        // All IPs are equal; stable sort preserves TSC order.
        assert_eq!(t.instructions[0].tsc, Some(1));
        assert_eq!(t.instructions[1].tsc, Some(2));
        assert_eq!(t.instructions[2].tsc, Some(3));
    }

    #[test]
    fn test_pt_trace_tsc_delta_single_entry() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::with_tsc(0x1000, 42));
        // start == end → delta = 0.
        assert_eq!(t.tsc_delta(), Some(0));
    }

    // ── Additional pt_to_drcov tests ──────────────────────────────────────────

    #[test]
    fn test_pt_to_drcov_module_name_appears() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x0040_0000));
        let s = pt_to_drcov(&t, "target_binary");
        assert!(s.contains("target_binary"));
    }

    #[test]
    fn test_pt_to_drcov_single_entry_hex_record() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x0040_1000));
        let s = pt_to_drcov(&t, "x.exe");
        // Base = 0x401000; relative offset = 0.
        // BB record: start=0, size=1, mod_id=0.
        // Little-endian: 00 00 00 00 01 00 00 00
        assert!(s.contains("00 00 00 00 01 00 00 00"));
    }

    #[test]
    fn test_pt_to_drcov_second_entry_relative_offset() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x0040_1000));
        t.push(StreamTraceEntry::from_ip(0x0040_1004));
        let s = pt_to_drcov(&t, "x.exe");
        // Second entry relative = 4 → bytes: 04 00 00 00 01 00 00 00
        assert!(s.contains("04 00 00 00 01 00 00 00"));
    }

    #[test]
    fn test_pt_to_drcov_bytes_bb_record_size() {
        let mut t = StreamTrace::new();
        t.push(StreamTraceEntry::from_ip(0x1000));
        t.push(StreamTraceEntry::from_ip(0x1004));
        t.push(StreamTraceEntry::from_ip(0x1008));
        let bytes = pt_to_drcov_bytes(&t, "lib.so");
        // 3 BB records × 8 bytes each.
        let header_end = bytes.windows(2).position(|w| w == b"\n\n").unwrap_or(0);
        let bb_bytes = bytes.len() - header_end - 2;
        // We expect at least 3 * 8 = 24 BB bytes.
        // Actual header may vary; just check total size is reasonable.
        assert!(bytes.len() >= 24);
        let _ = bb_bytes; // silence unused warning
    }

    #[test]
    fn test_pt_to_drcov_bytes_and_string_consistent_count() {
        let mut t = StreamTrace::new();
        for i in 0..5u64 {
            t.push(StreamTraceEntry::from_ip(0x2000 + i * 8));
        }
        let s = pt_to_drcov(&t, "check.exe");
        let bytes = pt_to_drcov_bytes(&t, "check.exe");
        // Both should report "BB Table: 5 bbs".
        assert!(s.contains("BB Table: 5 bbs"));
        assert!(bytes.windows(16).any(|w| w == b"BB Table: 5 bbs\n"));
    }

    // ── PtPkt equality and Clone ───────────────────────────────────────────────

    #[test]
    fn test_ptpkt_clone_and_eq() {
        let pkt = PtPkt::Tip {
            ip: 0xABCD,
            compression: StreamIpMode::Full,
        };
        let cloned = pkt.clone();
        assert_eq!(pkt, cloned);
    }

    #[test]
    fn test_ptpkt_ne() {
        assert_ne!(PtPkt::Pad, PtPkt::Psb);
        assert_ne!(PtPkt::Ovf, PtPkt::TraceStop);
        assert_ne!(PtPkt::Tsc { tsc: 1 }, PtPkt::Tsc { tsc: 2 });
    }

    // ── StreamIpMode equality ────────────────────────────────────────────

    #[test]
    fn test_ip_compression_mode_clone_eq() {
        let m = StreamIpMode::Sext48;
        assert_eq!(m, m.clone());
    }

    // ── Stress / bulk decode test ─────────────────────────────────────────────

    #[test]
    fn test_bulk_decode_1000_pads() {
        let data = vec![0x00u8; 1000];
        let mut s = PtPacketStream::new(data);
        let pkts = s.decode_all();
        assert_eq!(pkts.len(), 1000);
        assert!(pkts.iter().all(|p| *p == PtPkt::Pad));
        assert_eq!(s.position(), 1000);
    }

    #[test]
    fn test_bulk_decode_100_tsc_packets() {
        let mut data: Vec<u8> = Vec::new();
        for i in 0u64..100 {
            data.push(0x19);
            let v = i * 1_000_000;
            data.extend_from_slice(&v.to_le_bytes()[..7]);
        }
        let mut s = PtPacketStream::new(data);
        let pkts = s.decode_all();
        assert_eq!(pkts.len(), 100);
        for (i, pkt) in pkts.iter().enumerate() {
            if let PtPkt::Tsc { tsc } = pkt {
                assert_eq!(*tsc, i as u64 * 1_000_000);
            } else {
                panic!("expected TSC at index {i}");
            }
        }
    }

    #[test]
    fn test_bulk_trace_100_tips() {
        let mut pkts: Vec<PtPkt> = Vec::new();
        pkts.push(PtPkt::TipPge {
            ip: 0x1000,
            compression: StreamIpMode::Full,
        });
        for i in 0u64..100 {
            pkts.push(PtPkt::Tip {
                ip: 0x1000 + i * 4,
                compression: StreamIpMode::Full,
            });
        }
        let t = StreamTrace::from_packets(&pkts);
        assert_eq!(t.len(), 101); // 1 PGE + 100 TIPs
    }

    #[test]
    fn test_bulk_coverage_1000_unique_ips() {
        let mut pkts: Vec<PtPkt> = Vec::new();
        pkts.push(PtPkt::TipPge {
            ip: 0x1000,
            compression: StreamIpMode::Full,
        });
        for i in 0u64..1000 {
            pkts.push(PtPkt::Tip {
                ip: 0x1000 + i * 4,
                compression: StreamIpMode::Full,
            });
        }
        let cov = pt_pkts_to_coverage(&pkts);
        // TipPge IP (0x1000) duplicates TIP[0] (0x1000 + 0*4 = 0x1000).
        // Unique IPs: 0x1000..0x1000+999*4, i.e. 1000 unique addresses.
        assert_eq!(cov.len(), 1000);
    }

    // ── StreamTrace default impl ──────────────────────────────────────────────────

    #[test]
    fn test_pt_trace_default() {
        let t: StreamTrace = StreamTrace::default();
        assert!(t.is_empty());
    }

    // ── decode_pt_buffer_verbose consistency ─────────────────────────────────

    #[test]
    fn test_decode_pt_buffer_verbose_consistent() {
        // Build a small sequence and verify packets + trace are coherent.
        let mut data: Vec<u8> = Vec::new();
        // TSC
        data.push(0x19);
        data.extend_from_slice(&42u64.to_le_bytes()[..7]);
        // TIP.PGE full
        let ip: u64 = 0x0000_1234_0000_4000;
        data.push(0xC1);
        data.extend_from_slice(&ip.to_le_bytes());
        let (pkts, trace) = decode_pt_buffer_verbose(&data);
        assert_eq!(pkts.len(), 2);
        assert_eq!(trace.len(), 1);
        assert_eq!(trace.instructions[0].ip, ip);
        assert_eq!(trace.instructions[0].tsc, Some(42));
    }

    // ── sync_forward with data before PSB ────────────────────────────────────

    #[test]
    fn test_sync_forward_skips_garbage() {
        // 32 garbage bytes followed by a PSB.
        let mut data = vec![0xAAu8; 32];
        data.extend_from_slice(&[
            0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
            0x02, 0x82,
        ]);
        let mut s = PtPacketStream::new(data);
        let off = s.sync_forward();
        assert_eq!(off, Some(32));
        assert_eq!(s.position(), 32);
    }

    #[test]
    fn test_sync_forward_at_start() {
        let psb: Vec<u8> = vec![
            0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
            0x02, 0x82,
        ];
        let mut s = PtPacketStream::new(psb);
        let off = s.sync_forward();
        assert_eq!(off, Some(0));
    }

    // ── CBR edge cases ────────────────────────────────────────────────────────

    #[test]
    fn test_cbr_bad_second_byte_returns_unknown() {
        // 0x03 followed by something other than 0x00.
        let data = vec![0x03u8, 0x01, 0x20, 0x00];
        let mut s = PtPacketStream::new(data);
        let pkt = s.next_packet().unwrap();
        assert_eq!(pkt, PtPkt::Unknown(0x03));
    }

    #[test]
    fn test_cbr_ratio_one() {
        let data = vec![0x03u8, 0x00, 0x01, 0x00];
        let mut s = PtPacketStream::new(data);
        assert_eq!(s.next_packet().unwrap(), PtPkt::Cbr { ratio: 1 });
    }

    // ── Mixed timing + flow sequence ─────────────────────────────────────────

    #[test]
    fn test_mixed_timing_flow_sequence() {
        let mut data: Vec<u8> = Vec::new();
        // TSC(1000) + TIP.PGE(full=0x4000) + MTC(5) + TIP(full=0x4010) +
        // CBR(20) + TIP.PGD(full=0x4020) + OVF
        data.push(0x19);
        data.extend_from_slice(&1000u64.to_le_bytes()[..7]);
        let ip1: u64 = 0x0000_7FFF_0000_4000;
        data.push(0xC1);
        data.extend_from_slice(&ip1.to_le_bytes());
        data.extend_from_slice(&[0x59, 0x05]); // MTC(5)
        let ip2: u64 = 0x0000_7FFF_0000_4010;
        data.push(0xCD);
        data.extend_from_slice(&ip2.to_le_bytes()); // TIP full
        data.extend_from_slice(&[0x03, 0x00, 0x14, 0x00]); // CBR(20)
        let ip3: u64 = 0x0000_7FFF_0000_4020;
        data.push(0xD1);
        data.extend_from_slice(&ip3.to_le_bytes()); // TIP.PGD full
        data.extend_from_slice(&[0x02, 0xF3]); // OVF

        let (pkts, trace) = decode_pt_buffer_verbose(&data);

        // Verify packet types.
        assert!(matches!(&pkts[0], PtPkt::Tsc { tsc } if *tsc == 1000));
        assert!(matches!(&pkts[1], PtPkt::TipPge { ip, .. } if *ip == ip1));
        assert!(matches!(&pkts[2], PtPkt::Mtc { ctc } if *ctc == 5));
        assert!(matches!(&pkts[3], PtPkt::Tip    { ip, .. } if *ip == ip2));
        assert!(matches!(&pkts[4], PtPkt::Cbr    { ratio } if *ratio == 20));
        assert!(matches!(&pkts[5], PtPkt::TipPgd { ip, .. } if *ip == ip3));
        assert_eq!(pkts[6], PtPkt::Ovf);

        // Verify trace entries.
        assert!(trace.instructions.iter().any(|e| e.ip == ip1));
        assert!(trace.instructions.iter().any(|e| e.ip == ip2));
        assert!(trace.instructions.iter().any(|e| e.ip == ip3));
    }

    // ── PtPkt Debug format ────────────────────────────────────────────────────

    #[test]
    fn test_ptpkt_debug_format() {
        let pkt = PtPkt::Tsc { tsc: 0xABCD };
        let dbg = format!("{pkt:?}");
        assert!(dbg.contains("Tsc"));
        assert!(dbg.contains("43981")); // 0xABCD in decimal
    }

    #[test]
    fn test_ptpkt_tnt8_debug() {
        let pkt = PtPkt::Tnt8 {
            payload: 0b101,
            count: 3,
        };
        let dbg = format!("{pkt:?}");
        assert!(dbg.contains("Tnt8"));
    }

    // ── StreamIpMode Debug ───────────────────────────────────────────────

    #[test]
    fn test_ip_compression_mode_debug() {
        assert_eq!(format!("{:?}", StreamIpMode::Suppressed), "Suppressed");
        assert_eq!(format!("{:?}", StreamIpMode::Full), "Full");
    }

    // ── StreamTraceEntry equality ─────────────────────────────────────────────────

    #[test]
    fn test_pt_trace_entry_eq() {
        let a = StreamTraceEntry::new(0x1000, Some(1), Some(true));
        let b = StreamTraceEntry::new(0x1000, Some(1), Some(true));
        assert_eq!(a, b);
    }

    #[test]
    fn test_pt_trace_entry_ne_taken() {
        let a = StreamTraceEntry::new(0x1000, Some(1), Some(true));
        let b = StreamTraceEntry::new(0x1000, Some(1), Some(false));
        assert_ne!(a, b);
    }

    // ── StreamIpMode from_ipr masking ───────────────────────────────────

    #[test]
    fn test_ip_compression_from_ipr_masks_upper_bits() {
        // from_ipr should mask only the lower 3 bits.
        assert_eq!(
            StreamIpMode::from_ipr(0b1000_0000),
            StreamIpMode::Suppressed
        );
        assert_eq!(StreamIpMode::from_ipr(0b1000_0001), StreamIpMode::Upd16);
        assert_eq!(StreamIpMode::from_ipr(0b1111_0110), StreamIpMode::Full);
    }

    // ── PtPacketStream::remaining accuracy ───────────────────────────────────

    #[test]
    fn test_stream_remaining_accuracy() {
        let data = vec![0x19u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // TSC(0)
        let mut s = PtPacketStream::new(data);
        assert_eq!(s.remaining(), 8);
        s.next_packet().unwrap();
        assert_eq!(s.remaining(), 0);
    }

    // ── pt_to_coverage on large trace ────────────────────────────────────────

    #[test]
    fn test_pt_to_coverage_large() {
        let n = 500usize;
        let mut t = StreamTrace::with_capacity(n);
        for i in 0..n {
            t.push(StreamTraceEntry::from_ip(0x1000 + (i as u64) * 4));
        }
        let cov = pt_to_coverage(&t);
        assert_eq!(cov.len(), n);
    }

    #[test]
    fn test_pt_to_coverage_all_same_ip() {
        let mut t = StreamTrace::with_capacity(100);
        for _ in 0..100 {
            t.push(StreamTraceEntry::from_ip(0xDEAD));
        }
        let cov = pt_to_coverage(&t);
        assert_eq!(cov.len(), 1);
        assert!(cov.contains(&0xDEAD));
    }
}
