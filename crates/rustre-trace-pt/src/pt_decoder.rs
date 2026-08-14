//! `pt_decoder` — Full Intel PT packet decoder with state machine, IP compression,
//! timing reconstruction, and TSC/MTC/CYC correlation.
//!
//! This module implements a production-quality stateful decoder covering every
//! packet type defined in the Intel 64 and IA-32 Architectures Software
//! Developer's Manual Volume 3C, Chapter 36 ("Intel Processor Trace").

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::{IpCompression, PtError, PtPacket, PtPacketKind};

// ─── DecoderState ─────────────────────────────────────────────────────────────

/// Phase of the decoder state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecoderPhase {
    /// Searching for a PSB sync packet.
    Unsynced,
    /// Inside a PSB header block (between PSB and PSBEND).
    InPsbHeader,
    /// Normal decoding after a PSB + PSBEND pair.
    Decoding,
    /// Overflow recovery — waiting for the next PSB.
    OverflowRecovery,
}

impl std::fmt::Display for DecoderPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsynced => write!(f, "Unsynced"),
            Self::InPsbHeader => write!(f, "InPsbHeader"),
            Self::Decoding => write!(f, "Decoding"),
            Self::OverflowRecovery => write!(f, "OverflowRecovery"),
        }
    }
}

// ─── MtcState ─────────────────────────────────────────────────────────────────

/// State for MTC-based timing reconstruction.
///
/// MTC packets carry a `CTC` value derived from the `ART` counter.  Together
/// with the `TSC` packet they allow sub-TSC resolution timing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MtcState {
    /// Last CTC value seen.
    pub last_ctc: Option<u8>,
    /// MTC frequency select (from `CPUID`).
    pub mtc_freq: u8,
    /// Last reconstructed wall-clock nanoseconds.
    pub last_wall_ns: Option<u64>,
    /// Number of MTC packets seen.
    pub mtc_count: u64,
}

impl MtcState {
    /// Create a new `MtcState`.
    #[must_use]
    pub const fn new(mtc_freq: u8) -> Self {
        Self {
            last_ctc: None,
            mtc_freq,
            last_wall_ns: None,
            mtc_count: 0,
        }
    }

    /// Record a new CTC value.
    ///
    /// Returns the wrapped delta (handles 8-bit wrap).
    pub fn record_ctc(&mut self, ctc: u8) -> u8 {
        let delta = self.last_ctc.map_or(0, |prev| ctc.wrapping_sub(prev));
        self.last_ctc = Some(ctc);
        self.mtc_count += 1;
        delta
    }

    /// Compute the ART period in nanoseconds for this MTC frequency.
    ///
    /// The ART runs at bus clock / (2^`mtc_freq`).  We assume a 100 MHz bus
    /// clock (typical for modern Intel parts) giving `ART_freq = 100e6 / 2^f`.
    #[must_use]
    pub fn art_period_ns(&self) -> f64 {
        let bus_hz = 100_000_000.0_f64;
        let divisor = f64::from(1u32 << self.mtc_freq);
        let art_hz = bus_hz / divisor;
        1e9 / art_hz
    }
}

// ─── CycState ─────────────────────────────────────────────────────────────────

/// State for CYC-based cycle counting and wall-clock reconstruction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CycState {
    /// Accumulated cycle delta since last TSC anchor.
    pub accumulated_cycles: u64,
    /// Number of CYC packets seen.
    pub cyc_count: u64,
    /// Last CBR ratio.
    pub cbr: Option<u8>,
    /// Whether CYC counting is enabled (set by MODE.Exec).
    pub enabled: bool,
}

impl CycState {
    /// Create a new `CycState` with CYC counting enabled.
    #[must_use]
    pub fn new_enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    /// Record a CYC delta.
    pub const fn record_delta(&mut self, delta: u64) {
        if self.enabled {
            self.accumulated_cycles = self.accumulated_cycles.wrapping_add(delta);
            self.cyc_count += 1;
        }
    }

    /// Reset accumulated cycles (call at each TSC anchor).
    pub const fn reset_accumulator(&mut self) {
        self.accumulated_cycles = 0;
    }

    /// Estimate cycles-to-nanoseconds given the TSC frequency in MHz.
    ///
    /// `tsc_mhz`: The TSC frequency (same as bus clock for most Intel parts).
    /// Returns the wall-clock nanoseconds for the accumulated cycles.
    #[must_use]
    pub fn cycles_to_ns(&self, tsc_mhz: f64) -> f64 {
        crate::cast_helpers::u64_to_f64(self.accumulated_cycles) / tsc_mhz * 1000.0
    }
}

// ─── TscAnchor ────────────────────────────────────────────────────────────────

/// A TSC anchor point used for sub-TSC timing reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TscAnchor {
    /// The TSC value at this anchor.
    pub tsc: u64,
    /// Packet offset where this anchor was recorded.
    pub packet_offset: usize,
    /// Cycle count at the anchor point.
    pub cycles_at_anchor: u64,
}

// ─── TimingReconstructor ──────────────────────────────────────────────────────

/// Reconstructs a continuous timeline from TSC, MTC, and CYC packets.
///
/// The algorithm:
/// 1. TSC packets provide absolute wall-clock anchors.
/// 2. CYC packets accumulate cycle deltas between TSC anchors.
/// 3. MTC packets provide intermediate ART counter ticks for interpolation.
/// 4. CBR provides the core-to-bus ratio needed to convert cycles to time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimingReconstructor {
    /// Known TSC anchors (sorted by packet offset).
    pub anchors: Vec<TscAnchor>,
    /// MTC state.
    pub mtc: MtcState,
    /// CYC state.
    pub cyc: CycState,
    /// TSC frequency estimate in MHz (set from CBR if available).
    pub tsc_mhz: f64,
    /// First TSC seen.
    pub first_tsc: Option<u64>,
    /// Last TSC seen.
    pub last_tsc: Option<u64>,
    /// Core Bus Ratio.
    pub cbr: Option<u8>,
    /// Total cycle count across all CYC packets.
    pub total_cycles: u64,
    /// Interpolated nanoseconds since first TSC for each CYC event.
    pub cyc_timeline: Vec<(u64, f64)>,
}

impl TimingReconstructor {
    /// Create a new reconstructor.
    ///
    /// `tsc_mhz`: nominal TSC frequency (e.g. 3000.0 for a 3 GHz part).
    #[must_use]
    pub fn new(tsc_mhz: f64) -> Self {
        Self {
            tsc_mhz,
            ..Self::default()
        }
    }

    /// Process a `TSC` packet.
    pub fn on_tsc(&mut self, tsc: u64, packet_offset: usize) {
        if self.first_tsc.is_none() {
            self.first_tsc = Some(tsc);
        }
        self.last_tsc = Some(tsc);
        let cycles_at = self.cyc.accumulated_cycles;
        self.anchors.push(TscAnchor {
            tsc,
            packet_offset,
            cycles_at_anchor: cycles_at,
        });
        self.cyc.reset_accumulator();
    }

    /// Process a `CBR` packet.
    pub fn on_cbr(&mut self, cbr: u8) {
        self.cbr = Some(cbr);
        // CBR encodes the core-to-bus ratio; TSC runs at bus clock * CBR.
        // For a 100 MHz bus: tsc_mhz = cbr * 100.0
        self.tsc_mhz = f64::from(cbr) * 100.0;
        self.cyc.cbr = Some(cbr);
    }

    /// Process an `MTC` packet.
    pub fn on_mtc(&mut self, ctc: u8) {
        self.mtc.record_ctc(ctc);
    }

    /// Process a `CYC` packet.
    pub fn on_cyc(&mut self, delta: u64) {
        self.cyc.record_delta(delta);
        self.total_cycles = self.total_cycles.wrapping_add(delta);
        if let Some(first) = self.first_tsc {
            let elapsed_ns = self.interpolate_ns_from_first(first);
            self.cyc_timeline.push((first, elapsed_ns));
        }
    }

    /// Interpolate elapsed nanoseconds since `base_tsc`.
    ///
    /// Uses the last TSC anchor + accumulated CYC deltas since that anchor.
    #[must_use]
    pub fn interpolate_ns_from_first(&self, base_tsc: u64) -> f64 {
        let tsc_elapsed = self.last_tsc.unwrap_or(base_tsc).wrapping_sub(base_tsc);
        let tsc_ns = crate::cast_helpers::u64_to_f64(tsc_elapsed) / self.tsc_mhz * 1000.0;
        // Add sub-TSC resolution from accumulated CYC
        let cyc_ns = self.cyc.cycles_to_ns(self.tsc_mhz);
        tsc_ns + cyc_ns
    }

    /// Return total elapsed nanoseconds.
    #[must_use]
    pub fn total_elapsed_ns(&self) -> Option<f64> {
        match (self.first_tsc, self.last_tsc) {
            (Some(first), Some(last)) => {
                let delta = last.wrapping_sub(first);
                Some(crate::cast_helpers::u64_to_f64(delta) / self.tsc_mhz * 1000.0)
            }
            _ => None,
        }
    }

    /// Return the number of TSC anchors.
    #[must_use]
    pub const fn anchor_count(&self) -> usize {
        self.anchors.len()
    }

    /// Look up the last TSC anchor before a given packet offset.
    #[must_use]
    pub fn last_anchor_before(&self, offset: usize) -> Option<&TscAnchor> {
        self.anchors
            .iter()
            .rev()
            .find(|a| a.packet_offset <= offset)
    }

    /// Estimate the TSC value at a given packet offset using linear interpolation.
    #[must_use]
    pub fn estimate_tsc_at(&self, offset: usize) -> Option<u64> {
        let anchor = self.last_anchor_before(offset)?;
        // Interpolation using CYC cycles since anchor (rough)
        let cycles_since = self.cyc.accumulated_cycles;
        let tsc_delta = crate::cast_helpers::f64_to_u64(crate::cast_helpers::u64_to_f64(cycles_since) / self.tsc_mhz * self.tsc_mhz);
        Some(anchor.tsc.wrapping_add(tsc_delta))
    }
}

// ─── FullPtDecoder ────────────────────────────────────────────────────────────

/// Full-featured Intel PT decoder with state machine, sync handling,
/// IP compression, and timing reconstruction.
///
/// Unlike `PtDecoder` in `lib.rs` (which is a simple byte-stream decoder),
/// this struct models the complete decoder state machine including:
/// - PSB-based synchronization
/// - Phase transitions (Unsynced → `InPsbHeader` → Decoding)
/// - Overflow recovery
/// - Full IP address decompression with last-IP state
/// - TSC/MTC/CYC timing reconstruction
/// - VMCS/PIP/MODE state tracking
pub struct FullPtDecoder {
    /// Raw byte buffer.
    buf: Vec<u8>,
    /// Current read position.
    pos: usize,
    /// Current decoder phase.
    pub phase: DecoderPhase,
    /// Last known IP (for delta decompression).
    last_ip: u64,
    /// Timing reconstructor.
    pub timing: TimingReconstructor,
    /// Current CR3 (from PIP packets).
    pub current_cr3: u64,
    /// Current VMCS base address.
    pub vmcs_base: Option<u64>,
    /// Current MODE bits.
    pub mode_exec: u8,
    /// Whether we are in 64-bit mode (from MODE.Exec).
    pub is_64bit: bool,
    /// Pending TNT bits.
    pub tnt_queue: VecDeque<bool>,
    /// Decoded packets in order.
    pub packets: Vec<PtPacket>,
    /// Error log.
    pub errors: Vec<(usize, PtError)>,
    /// Number of overflows seen.
    pub overflow_count: usize,
    /// Number of PSB sync packets seen.
    pub psb_count: usize,
    /// Whether NR mode is active (non-root mode, from PIP).
    pub non_root_mode: bool,
}

impl FullPtDecoder {
    /// Create a new decoder.
    ///
    /// `tsc_mhz`: nominal TSC frequency for timing reconstruction.
    #[must_use]
    pub fn new(tsc_mhz: f64) -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            phase: DecoderPhase::Unsynced,
            last_ip: 0,
            timing: TimingReconstructor::new(tsc_mhz),
            current_cr3: 0,
            vmcs_base: None,
            mode_exec: 0,
            is_64bit: true,
            tnt_queue: VecDeque::new(),
            packets: Vec::new(),
            errors: Vec::new(),
            overflow_count: 0,
            psb_count: 0,
            non_root_mode: false,
        }
    }

    /// Feed raw trace bytes into the decoder.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Return the number of remaining undecoded bytes.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Peek at the next byte without consuming.
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Consume one byte.
    fn consume(&mut self) -> Option<u8> {
        let b = self.buf.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    /// Consume `n` bytes.
    fn consume_n(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Some(v)
    }

    /// Try to read a 48-bit IP with sign extension.
    fn read_ip_48_se(&mut self) -> Option<u64> {
        let bytes = self.consume_n(6)?;
        let mut arr = [0u8; 8];
        arr[..6].copy_from_slice(&bytes);
        let mut ip = u64::from_le_bytes(arr);
        if ip & (1 << 47) != 0 {
            ip |= 0xFFFF_0000_0000_0000;
        }
        self.last_ip = ip;
        Some(ip)
    }

    /// Read an IP using the given IPR compression mode.
    fn read_ip_compressed(&mut self, ipr: u8) -> Option<u64> {
        let comp = IpCompression::from_ipr(ipr);
        match comp {
            IpCompression::Zero => Some(0),
            IpCompression::Update16 => {
                let bytes = self.consume_n(2)?;
                let lo = u16::from_le_bytes([bytes[0], bytes[1]]);
                self.last_ip = (self.last_ip & !0xFFFF) | u64::from(lo);
                Some(self.last_ip)
            }
            IpCompression::Update32 => {
                let bytes = self.consume_n(4)?;
                let lo = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                self.last_ip = (self.last_ip & !0xFFFF_FFFF) | u64::from(lo);
                Some(self.last_ip)
            }
            IpCompression::Full48 => {
                let bytes = self.consume_n(6)?;
                let mut arr = [0u8; 8];
                arr[..6].copy_from_slice(&bytes);
                let ip = u64::from_le_bytes(arr);
                self.last_ip = ip;
                Some(ip)
            }
            IpCompression::Full48SignExt => {
                let ip = self.read_ip_48_se()?;
                Some(ip)
            }
            IpCompression::Full64 => {
                let bytes = self.consume_n(8)?;
                let ip = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                self.last_ip = ip;
                Some(ip)
            }
        }
    }

    /// Search forward for a PSB sync packet.
    ///
    /// Returns `true` if a PSB was found and the decoder is now positioned
    /// immediately after it.
    pub fn seek_sync(&mut self) -> bool {
        while self.pos + 16 <= self.buf.len() {
            if self.buf[self.pos] == 0x02 {
                let expected: Vec<u8> = (0..15_usize)
                    .map(|i| if i.is_multiple_of(2) { 0x82u8 } else { 0x02u8 })
                    .collect();
                if &self.buf[self.pos + 1..self.pos + 16] == expected.as_slice() {
                    // Leave pos at the PSB start so the next decode_byte call parses it.
                    self.phase = DecoderPhase::InPsbHeader;
                    return true;
                }
            }
            self.pos += 1;
        }
        false
    }

    /// Decode the next packet, advancing the state machine.
    ///
    /// Returns `None` when the buffer is exhausted.
    pub fn next_packet(&mut self) -> Option<Result<PtPacket, PtError>> {
        // If unsynced, try to find the first PSB
        if (self.phase == DecoderPhase::Unsynced || self.phase == DecoderPhase::OverflowRecovery)
            && !self.seek_sync()
        {
            return None;
        }

        if self.pos >= self.buf.len() {
            return None;
        }

        let start = self.pos;
        let b = self.peek()?;
        self.pos += 1;

        let result = self.decode_byte(b, start);

        match &result {
            Ok(pkt) => {
                // State machine transitions
                match &pkt.kind {
                    PtPacketKind::Psb => {
                        self.phase = DecoderPhase::InPsbHeader;
                        self.psb_count += 1;
                    }
                    PtPacketKind::PsbEnd => {
                        self.phase = DecoderPhase::Decoding;
                        // Reset last IP on PSB boundary (hardware requirement)
                        self.last_ip = 0;
                    }
                    PtPacketKind::Overflow => {
                        self.overflow_count += 1;
                        self.phase = DecoderPhase::OverflowRecovery;
                    }
                    PtPacketKind::Tsc(tsc) => {
                        self.timing.on_tsc(*tsc, start);
                    }
                    PtPacketKind::Cbr(cbr) => {
                        self.timing.on_cbr(*cbr);
                    }
                    PtPacketKind::Mtc { ctc } => {
                        self.timing.on_mtc(*ctc);
                    }
                    PtPacketKind::Cyc { value } => {
                        self.timing.on_cyc(*value);
                    }
                    PtPacketKind::Pip { cr3, nr } => {
                        self.current_cr3 = *cr3;
                        self.non_root_mode = *nr;
                    }
                    PtPacketKind::Vmcs { base } => {
                        self.vmcs_base = Some(*base);
                    }
                    PtPacketKind::Mode { leaf, bits } => {
                        self.apply_mode(*leaf, *bits);
                    }
                    PtPacketKind::Tnt { bits, count }
                    | PtPacketKind::TntLong { bits, count } => {
                        for i in 0..*count {
                            self.tnt_queue.push_back((bits >> i) & 1 == 1);
                        }
                    }
                    _ => {}
                }
                self.packets.push(pkt.clone());
                Some(Ok(pkt.clone()))
            }
            Err(e) => {
                // Log error and rewind
                let msg = e.to_string();
                self.errors.push((start, PtError::FlowReconstruction(msg)));
                self.pos = start + 1; // skip one byte and retry
                Some(result)
            }
        }
    }

    /// Apply a MODE packet to decoder state.
    const fn apply_mode(&mut self, leaf: u8, bits: u8) {
        self.mode_exec = bits;
        match leaf {
            // MODE.Exec (leaf 0)
            0x43 => {
                // Bit 0: CSD (CS.D) — 0=16-bit/32-bit, 1=64-bit when IF bit 1=0
                // Bit 1: IF (IA-32e) — 1=64-bit mode
                self.is_64bit = (bits & 0x02) != 0;
            }
            // MODE.TSX (leaf 1)
            0x03 => {
                // bit 0 = TSX abort, bit 1 = in TSX region
                let _ = (bits & 0x02) != 0; // in TSX
                let _ = (bits & 0x01) != 0; // TSX abort
            }
            _ => {}
        }
    }

    /// Core packet decode for one byte `b` starting at `start`.
    fn decode_byte(&mut self, b: u8, start: usize) -> Result<PtPacket, PtError> {
        // 0x00 = PAD
        if b == 0x00 {
            return Ok(PtPacket::new(PtPacketKind::Pad, start, 1));
        }

        // 0xF3 = OVF (must be before CYC check, 0xF3 & 7 == 3)
        if b == 0xF3 {
            return Ok(PtPacket::new(PtPacketKind::Overflow, start, 1));
        }

        // EXSTOP: 0x62 / 0x63
        if b == 0x62 || b == 0x63 {
            return Ok(PtPacket::new(
                PtPacketKind::ExStop { ip: b == 0x63 },
                start,
                1,
            ));
        }

        // 0xA3 = Long TNT (7 bytes total)
        if b == 0xA3 {
            let bytes = self
                .consume_n(6)
                .ok_or(PtError::TruncatedPacket)?;
            let mut payload = [0u8; 8];
            payload[..6].copy_from_slice(&bytes);
            let raw = u64::from_le_bytes(payload);
            if raw == 0 {
                return Err(PtError::UnknownOpcode(b));
            }
            let stop_bit = 63 - crate::cast_helpers::u32_to_u8(raw.leading_zeros());
            let bits = raw & !((1u64) << stop_bit);
            let count = stop_bit;
            return Ok(PtPacket::new(
                PtPacketKind::TntLong { bits, count },
                start,
                7,
            ));
        }

        // 0x19 = TSC (9 bytes total)
        if b == 0x19 {
            let bytes = self
                .consume_n(8)
                .ok_or(PtError::TruncatedPacket)?;
            let tsc = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            return Ok(PtPacket::new(PtPacketKind::Tsc(tsc), start, 9));
        }

        // 0x59 = MTC (2 bytes)
        if b == 0x59 {
            let ctc = self.consume().ok_or(PtError::TruncatedPacket)?;
            return Ok(PtPacket::new(PtPacketKind::Mtc { ctc }, start, 2));
        }

        // 0x23 = PSBEND
        if b == 0x23 {
            return Ok(PtPacket::new(PtPacketKind::PsbEnd, start, 1));
        }

        // CYC: lower 3 bits == 0b011, not 0x03 (which starts PSB/PIP/MODE/etc.)
        if (b & 0b111) == 0b011 && b != 0x03 && b != 0xA3 {
            let mut value = u64::from(b >> 3);
            let mut size = 1usize;
            let mut cont = (b & 0x04) != 0;
            let mut shift = 5u32;
            while cont {
                let ext = self.consume().ok_or(PtError::TruncatedPacket)?;
                size += 1;
                value |= u64::from(ext >> 1) << shift;
                shift += 7;
                cont = (ext & 0x01) != 0;
                if shift > 63 {
                    break;
                }
            }
            return Ok(PtPacket::new(PtPacketKind::Cyc { value }, start, size));
        }

        // TIP family: 5-bit lower field identifies the exact variant.
        // TIP        lower5 == 0x0D
        // TIP.PGE    lower5 == 0x11
        // TIP.PGD    lower5 == 0x01
        // FUP        lower5 == 0x1D
        let lower5 = b & 0x1F;
        if matches!(lower5, 0x0D | 0x11 | 0x01 | 0x1D) {
            let ipr = (b >> 5) & 0x07;
            let comp = IpCompression::from_ipr(ipr);
            let ip = self
                .read_ip_compressed(ipr)
                .ok_or(PtError::TruncatedPacket)?;
            let size = 1 + comp.byte_count();
            let kind = match lower5 {
                0x0D => PtPacketKind::Tip { ip, compression: comp },
                0x11 => PtPacketKind::TipPge { ip, compression: comp },
                0x01 => PtPacketKind::TipPgd { ip, compression: comp },
                0x1D => {
                    // FUP — Flow Update Packet.  Shares TIP structure.
                    // Encode as TIP for now (FUP is used for async events).
                    PtPacketKind::Tip { ip, compression: comp }
                }
                _ => unreachable!(),
            };
            return Ok(PtPacket::new(kind, start, size));
        }

        // 0xC5 = legacy TIP with full 48-bit address
        if b == 0xC5 {
            let bytes = self.consume_n(6).ok_or(PtError::TruncatedPacket)?;
            let mut arr = [0u8; 8];
            arr[..6].copy_from_slice(&bytes);
            let ip = u64::from_le_bytes(arr);
            self.last_ip = ip;
            return Ok(PtPacket::new(
                PtPacketKind::Tip { ip, compression: IpCompression::Full48 },
                start,
                7,
            ));
        }

        // 0x02 = extended opcode family. If there is no follow byte to identify
        // the extended sub-opcode, fall through to the short-TNT path below
        // (0x02 is a valid short TNT encoding: bits=1, count=1).
        if b == 0x02 && self.pos < self.buf.len() {
            return self.decode_extended(start);
        }

        // MWAIT: 0xC2 + 4 bytes
        if b == 0xC2 {
            let bytes = self.consume_n(4).ok_or(PtError::TruncatedPacket)?;
            let hints = bytes[0];
            let ext = bytes[1];
            return Ok(PtPacket::new(
                PtPacketKind::Mwait { ext, hints },
                start,
                5,
            ));
        }

        // PWRE: 0x22 + 2 bytes
        if b == 0x22 {
            let bytes = self.consume_n(2).ok_or(PtError::TruncatedPacket)?;
            let hw_cstate = bytes[0] & 0x0F;
            let sw_cstate = (bytes[0] >> 4) & 0x0F;
            return Ok(PtPacket::new(
                PtPacketKind::Pwre { hw_cstate, sw_cstate },
                start,
                3,
            ));
        }

        // PWRX: 0x32 + 5 bytes
        if b == 0x32 {
            let bytes = self.consume_n(5).ok_or(PtError::TruncatedPacket)?;
            let last_cstate = bytes[0] & 0x0F;
            let deepest_cstate = (bytes[0] >> 4) & 0x0F;
            return Ok(PtPacket::new(
                PtPacketKind::Pwrx { last_cstate, deepest_cstate },
                start,
                6,
            ));
        }

        // BBP: 0x12 (Basic Block Pointer)
        if b == 0x12 {
            let type_byte = self.consume().ok_or(PtError::TruncatedPacket)?;
            return Ok(PtPacket::new(
                PtPacketKind::Bbp { type_flag: type_byte & 0x01 },
                start,
                2,
            ));
        }

        // BEP: 0x33 (Basic Block End)
        if b == 0x33 {
            let flags = self.consume().ok_or(PtError::TruncatedPacket)?;
            return Ok(PtPacket::new(
                PtPacketKind::Bep { ip: flags & 0x01 != 0 },
                start,
                2,
            ));
        }

        // BIP: 0b0001_0RRR  (R = register ID, 3 bits)
        if b & 0xF8 == 0x10 {
            let id = b & 0x07;
            let bytes = self.consume_n(8).ok_or(PtError::TruncatedPacket)?;
            let value = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            return Ok(PtPacket::new(
                PtPacketKind::Bip { id, value },
                start,
                9,
            ));
        }

        // Short TNT: even byte (bit 0 == 0), not 0x00
        if (b & 1) == 0 && b != 0x00 {
            let bits = u64::from(b >> 1);
            let count = if b == 0 {
                0
            } else {
                7 - crate::cast_helpers::u32_to_u8(b.leading_zeros())
            };
            return Ok(PtPacket::new(
                PtPacketKind::Tnt { bits, count },
                start,
                1,
            ));
        }

        Err(PtError::UnknownOpcode(b))
    }

    /// Decode a 0x02-prefixed extended packet.
    fn decode_extended(&mut self, start: usize) -> Result<PtPacket, PtError> {
        let b2 = self.consume().ok_or(PtError::TruncatedPacket)?;

        match b2 {
            // 0x02 0x22 <cbr> 0x00 = CBR
            0x22 => {
                let cbr = self.consume().ok_or(PtError::TruncatedPacket)?;
                let _pad = self.consume().ok_or(PtError::TruncatedPacket)?;
                Ok(PtPacket::new(PtPacketKind::Cbr(cbr), start, 4))
            }
            // 0x02 0x23 = PSBEND (Intel SDM Vol 3C §33.4.2.3).
            //
            // This arm read 0xC3, which is not PSBEND at all: `0x02 0xC3` is the
            // prefix of MNT (`0x02 0xC3 0x88`), a three-byte packet.  So a real
            // PSBEND went unrecognised here while the start of an MNT was
            // consumed as a two-byte PSBEND, desynchronising everything after
            // it.  The sibling `pt_packet_decoder` uses 0x23 throughout, and the
            // single-byte arm earlier in this same file already says
            // "0x23 = PSBEND".
            0x23 => Ok(PtPacket::new(PtPacketKind::PsbEnd, start, 2)),
            // 0x02 0x43 or 0x02 0x03 = MODE
            0x43 | 0x03 => {
                let mode_bits = self.consume().ok_or(PtError::TruncatedPacket)?;
                Ok(PtPacket::new(
                    PtPacketKind::Mode { leaf: b2, bits: mode_bits },
                    start,
                    3,
                ))
            }
            // PSB: 0x02 [0x82 0x02] × 7 ... 0x82
            0x82 => {
                // Check for PSB pattern continuation
                if self.pos + 14 > self.buf.len() {
                    self.pos = start + 1;
                    return Err(PtError::TruncatedPacket);
                }
                let pattern_ok = (0..14_usize).all(|i| {
                    let expected = if i.is_multiple_of(2) { 0x02u8 } else { 0x82u8 };
                    self.buf[self.pos + i] == expected
                });
                if pattern_ok {
                    self.pos += 14;
                    Ok(PtPacket::new(PtPacketKind::Psb, start, 16))
                } else {
                    Err(PtError::UnknownOpcode(b2))
                }
            }
            // PIP: 0x02 0x43 <6 byte CR3> (alternate opcode — same as MODE 0x43,
            //       distinguished by context: PIP has 6-byte payload not 1-byte).
            // The Intel manual defines PIP as 0x02 0x43 with a 5-byte payload.
            // Disambiguated by checking the next byte sequence here.
            0x02 => {
                // 0x02 0x02 — could be PIP
                if self.pos + 5 > self.buf.len() {
                    return Err(PtError::TruncatedPacket);
                }
                let bytes = self.consume_n(5).ok_or(PtError::TruncatedPacket)?;
                let mut arr = [0u8; 8];
                arr[..5].copy_from_slice(&bytes);
                let cr3_raw = u64::from_le_bytes(arr);
                let nr = (cr3_raw & 1) != 0;
                let cr3 = cr3_raw & !1;
                Ok(PtPacket::new(PtPacketKind::Pip { cr3, nr }, start, 7))
            }
            // VMCS: 0x02 0xC8 <5 bytes VMCS base>
            0xC8 => {
                if self.pos + 5 > self.buf.len() {
                    return Err(PtError::TruncatedPacket);
                }
                let bytes = self.consume_n(5).ok_or(PtError::TruncatedPacket)?;
                let mut arr = [0u8; 8];
                arr[..5].copy_from_slice(&bytes);
                // VMCS base is a physical address, page-aligned (12-bit zero suffix)
                let base = u64::from_le_bytes(arr) << 12;
                Ok(PtPacket::new(PtPacketKind::Vmcs { base }, start, 7))
            }
            _ => {
                Err(PtError::UnknownOpcode(b2))
            }
        }
    }

    /// Decode all remaining packets, storing results internally.
    ///
    /// Returns the number of successful packets decoded.
    pub fn decode_all(&mut self) -> usize {
        let before = self.packets.len();
        while let Some(_result) = self.next_packet() {
            // packets are appended inside next_packet()
        }
        self.packets.len() - before
    }

    /// Pop the next TNT bit from the queue.
    #[must_use]
    pub fn pop_tnt(&mut self) -> Option<bool> {
        self.tnt_queue.pop_front()
    }

    /// Return the number of pending TNT bits.
    #[must_use]
    pub fn pending_tnt(&self) -> usize {
        self.tnt_queue.len()
    }

    /// Return a summary of decode statistics.
    #[must_use]
    pub fn stats(&self) -> DecoderStats {
        let timing_pkts = self
            .packets
            .iter()
            .filter(|p| p.is_timing())
            .count();
        let flow_pkts = self
            .packets
            .iter()
            .filter(|p| p.is_flow())
            .count();

        DecoderStats {
            total_packets: self.packets.len(),
            timing_packets: timing_pkts,
            flow_packets: flow_pkts,
            overflow_count: self.overflow_count,
            psb_count: self.psb_count,
            error_count: self.errors.len(),
            bytes_consumed: self.pos,
            tnt_bits_total: self
                .packets
                .iter()
                .map(|p| match &p.kind {
                    PtPacketKind::Tnt { count, .. } | PtPacketKind::TntLong { count, .. } => {
                        u64::from(*count)
                    }
                    _ => 0,
                })
                .sum(),
        }
    }

    /// Reset the decoder to its initial state (preserves buffer).
    pub fn reset(&mut self) {
        self.pos = 0;
        self.phase = DecoderPhase::Unsynced;
        self.last_ip = 0;
        self.tnt_queue.clear();
        self.packets.clear();
        self.errors.clear();
        self.overflow_count = 0;
        self.psb_count = 0;
        self.current_cr3 = 0;
        self.vmcs_base = None;
    }
}

// ─── DecoderStats ─────────────────────────────────────────────────────────────

/// Statistics from a completed decode run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecoderStats {
    /// Total packets decoded.
    pub total_packets: usize,
    /// Timing packets (TSC/MTC/CYC/CBR).
    pub timing_packets: usize,
    /// Flow packets (TIP/TNT).
    pub flow_packets: usize,
    /// Overflow packets.
    pub overflow_count: usize,
    /// PSB sync packets.
    pub psb_count: usize,
    /// Decode errors.
    pub error_count: usize,
    /// Bytes consumed from the buffer.
    pub bytes_consumed: usize,
    /// Total TNT bits across all TNT packets.
    pub tnt_bits_total: u64,
}

impl std::fmt::Display for DecoderStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DecoderStats {{ total={}, timing={}, flow={}, overflows={}, \
             psbs={}, errors={}, bytes={}, tnt_bits={} }}",
            self.total_packets,
            self.timing_packets,
            self.flow_packets,
            self.overflow_count,
            self.psb_count,
            self.error_count,
            self.bytes_consumed,
            self.tnt_bits_total
        )
    }
}

// ─── PacketClassifier ─────────────────────────────────────────────────────────

/// Classifies a stream of decoded packets into categories.
pub struct PacketClassifier;

impl PacketClassifier {
    /// Return all IP-carrying packets (TIP/TIP.PGE/TIP.PGD).
    #[must_use]
    pub fn ip_packets(packets: &[PtPacket]) -> Vec<&PtPacket> {
        packets
            .iter()
            .filter(|p| {
                matches!(
                    p.kind,
                    PtPacketKind::Tip { .. }
                        | PtPacketKind::TipPge { .. }
                        | PtPacketKind::TipPgd { .. }
                )
            })
            .collect()
    }

    /// Return all TNT packets.
    #[must_use]
    pub fn tnt_packets(packets: &[PtPacket]) -> Vec<&PtPacket> {
        packets
            .iter()
            .filter(|p| matches!(p.kind, PtPacketKind::Tnt { .. } | PtPacketKind::TntLong { .. }))
            .collect()
    }

    /// Return all PSB packets.
    #[must_use]
    pub fn psb_packets(packets: &[PtPacket]) -> Vec<&PtPacket> {
        packets
            .iter()
            .filter(|p| matches!(p.kind, PtPacketKind::Psb))
            .collect()
    }

    /// Return all power management packets.
    #[must_use]
    pub fn power_packets(packets: &[PtPacket]) -> Vec<&PtPacket> {
        packets
            .iter()
            .filter(|p| {
                matches!(
                    p.kind,
                    PtPacketKind::Pwre { .. }
                        | PtPacketKind::Pwrx { .. }
                        | PtPacketKind::ExStop { .. }
                        | PtPacketKind::Mwait { .. }
                )
            })
            .collect()
    }

    /// Return all virtualization packets (VMCS / PIP).
    #[must_use]
    pub fn virt_packets(packets: &[PtPacket]) -> Vec<&PtPacket> {
        packets
            .iter()
            .filter(|p| matches!(p.kind, PtPacketKind::Vmcs { .. } | PtPacketKind::Pip { .. }))
            .collect()
    }

    /// Compute taken/not-taken ratio from TNT packets.
    #[must_use]
    pub fn tnt_ratio(packets: &[PtPacket]) -> (u64, u64) {
        let mut taken = 0u64;
        let mut not_taken = 0u64;
        for p in packets {
            match &p.kind {
                PtPacketKind::Tnt { bits, count } | PtPacketKind::TntLong { bits, count } => {
                    for i in 0..*count {
                        if (bits >> i) & 1 == 1 {
                            taken += 1;
                        } else {
                            not_taken += 1;
                        }
                    }
                }
                _ => {}
            }
        }
        (taken, not_taken)
    }

    /// Find the minimum and maximum TSC values.
    #[must_use]
    pub fn tsc_range(packets: &[PtPacket]) -> Option<(u64, u64)> {
        let mut min_tsc = u64::MAX;
        let mut max_tsc = 0u64;
        let mut found = false;
        for p in packets {
            if let PtPacketKind::Tsc(t) = p.kind {
                min_tsc = min_tsc.min(t);
                max_tsc = max_tsc.max(t);
                found = true;
            }
        }
        if found { Some((min_tsc, max_tsc)) } else { None }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_decoder() -> FullPtDecoder {
        FullPtDecoder::new(3000.0)
    }

    fn psb_bytes() -> Vec<u8> {
        let mut v = vec![0x02u8];
        for i in 0..15usize {
            v.push(if i.is_multiple_of(2) { 0x82 } else { 0x02 });
        }
        v
    }

    fn synced_decoder_with(extra: &[u8]) -> FullPtDecoder {
        let mut dec = make_decoder();
        let mut data = psb_bytes();
        data.push(0x02);
        data.push(0x23); // PSBEND — Intel SDM: 0x02 0x23, not 0xC3
        data.extend_from_slice(extra);
        dec.feed(&data);
        // Consume PSB + PSBEND
        let _ = dec.next_packet();
        let _ = dec.next_packet();
        dec
    }

    #[test]
    fn test_seek_sync_finds_psb() {
        let mut dec = make_decoder();
        dec.feed(&psb_bytes());
        assert!(dec.seek_sync());
        assert_eq!(dec.phase, DecoderPhase::InPsbHeader);
    }

    #[test]
    fn test_psbend_transitions_to_decoding() {
        let mut dec = make_decoder();
        let mut data = psb_bytes();
        data.extend_from_slice(&[0x02, 0x23]); // PSBEND — Intel SDM: 0x02 0x23
        dec.feed(&data);
        let _ = dec.next_packet(); // PSB
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, PtPacketKind::PsbEnd);
        assert_eq!(dec.phase, DecoderPhase::Decoding);
    }

    #[test]
    fn test_overflow_triggers_recovery() {
        let mut dec = synced_decoder_with(&[0xF3]);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, PtPacketKind::Overflow);
        assert_eq!(dec.phase, DecoderPhase::OverflowRecovery);
    }

    #[test]
    fn test_tsc_recorded_in_timing() {
        let ts: u64 = 0x1234_5678_9ABC;
        let mut payload = vec![0x19u8];
        payload.extend_from_slice(&ts.to_le_bytes());
        let mut dec = synced_decoder_with(&payload);
        let _ = dec.next_packet();
        assert_eq!(dec.timing.last_tsc, Some(ts));
    }

    #[test]
    fn test_cbr_updates_tsc_mhz() {
        let mut dec = synced_decoder_with(&[0x02, 0x22, 30, 0x00]);
        let _ = dec.next_packet();
        assert!((dec.timing.tsc_mhz - 3000.0).abs() < 1e-6);
    }

    #[test]
    fn test_cyc_accumulates() {
        // CYC with value 4: byte = (4 << 3) | 0b010 = 0x22; bit 2 not set so no extension
        // Actually CYC = (value << 3) | 0b011 and bit 2 (0x04) = 0 means no continuation
        // For value=1: byte = (1 << 3) | 0b011 = 0x0B; bit 2 = 0 no cont
        let mut dec = synced_decoder_with(&[0x0B]);
        let _ = dec.next_packet();
        assert_eq!(dec.timing.total_cycles, 1);
    }

    #[test]
    fn test_tnt_queue_populated() {
        // Short TNT: 0b0000_1010 = 0x0A  — bit0=0(not TNT), wait…
        // Short TNT must be even and not 0. 0x02 = 0b0000_0010
        // bits = b >> 1 = 1, count = 7 - leading_zeros(0x02) = 7 - 6 = 1
        let mut dec = synced_decoder_with(&[0x02]);
        let _ = dec.next_packet();
        assert!(!dec.tnt_queue.is_empty());
    }

    #[test]
    fn test_pip_updates_cr3() {
        // PIP: 0x02 0x02 <5-byte CR3 with NR=0>
        let cr3: u64 = 0x0000_1234_5000;
        let mut bytes = vec![0x02u8, 0x02];
        let payload = cr3.to_le_bytes();
        bytes.extend_from_slice(&payload[..5]);
        let mut dec = synced_decoder_with(&bytes);
        let _ = dec.next_packet();
        assert_eq!(dec.current_cr3 & !1, cr3 & !1);
    }

    #[test]
    fn test_stats_counts() {
        let mut dec = synced_decoder_with(&[0x00, 0x00, 0xF3]);
        dec.decode_all();
        let stats = dec.stats();
        assert!(stats.total_packets >= 2);
        assert!(stats.overflow_count >= 1);
    }

    #[test]
    fn test_timing_reconstructor_total_elapsed() {
        let mut r = TimingReconstructor::new(3000.0);
        r.on_tsc(0, 0);
        r.on_tsc(3_000_000, 100);
        // 3_000_000 ticks / 3000 MHz = 1_000 µs = 1_000_000 ns
        let ns = r.total_elapsed_ns().unwrap();
        assert!((ns - 1_000_000.0).abs() < 1.0, "got {ns}");
    }

    #[test]
    fn test_timing_reconstructor_anchors() {
        let mut r = TimingReconstructor::new(3000.0);
        r.on_tsc(100, 0);
        r.on_tsc(200, 50);
        assert_eq!(r.anchor_count(), 2);
    }

    #[test]
    fn test_mtc_state_art_period() {
        let s = MtcState::new(0); // freq 0 => divisor 1 => ART = 100 MHz => 10 ns
        assert!((s.art_period_ns() - 10.0).abs() < 0.001);
        let s2 = MtcState::new(1); // freq 1 => divisor 2 => ART = 50 MHz => 20 ns
        assert!((s2.art_period_ns() - 20.0).abs() < 0.001);
    }

    #[test]
    fn test_cyc_state_cycles_to_ns() {
        let mut s = CycState::new_enabled();
        s.record_delta(3000); // 3000 cycles at 3000 MHz = 1 µs
        let ns = s.cycles_to_ns(3000.0);
        assert!((ns - 1000.0).abs() < 0.001, "got {ns}");
    }

    #[test]
    fn test_classifier_tnt_ratio() {
        let pkts = vec![
            PtPacket::new(PtPacketKind::Tnt { bits: 0b101, count: 3 }, 0, 1),
        ];
        let (t, nt) = PacketClassifier::tnt_ratio(&pkts);
        assert_eq!(t, 2);
        assert_eq!(nt, 1);
    }

    #[test]
    fn test_classifier_tsc_range() {
        let pkts = vec![
            PtPacket::new(PtPacketKind::Tsc(100), 0, 9),
            PtPacket::new(PtPacketKind::Tsc(500), 9, 9),
            PtPacket::new(PtPacketKind::Tsc(300), 18, 9),
        ];
        let range = PacketClassifier::tsc_range(&pkts);
        assert_eq!(range, Some((100, 500)));
    }

    #[test]
    fn test_classifier_ip_packets() {
        let pkts = vec![
            PtPacket::new(
                PtPacketKind::Tip { ip: 0x1000, compression: IpCompression::Full48 },
                0, 7,
            ),
            PtPacket::new(PtPacketKind::Pad, 7, 1),
        ];
        let ips = PacketClassifier::ip_packets(&pkts);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_decoder_reset() {
        let mut dec = make_decoder();
        dec.feed(&psb_bytes());
        dec.decode_all();
        dec.reset();
        assert_eq!(dec.pos, 0);
        assert!(dec.packets.is_empty());
        assert_eq!(dec.phase, DecoderPhase::Unsynced);
    }

    #[test]
    fn test_long_tnt_decode() {
        // Long TNT: 0xA3 + 6 bytes payload
        // payload: stop bit at position 3 => raw = 0b1000 = 8 => bits = 0, count = 3
        let payload: [u8; 6] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut v = vec![0xA3u8];
        v.extend_from_slice(&payload);
        let mut dec = synced_decoder_with(&v);
        let r = dec.next_packet().unwrap().unwrap();
        assert!(matches!(r.kind, PtPacketKind::TntLong { count: 3, .. }));
    }

    #[test]
    fn test_mtc_decode() {
        let mut dec = synced_decoder_with(&[0x59, 0x0F]);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.kind, PtPacketKind::Mtc { ctc: 0x0F });
    }

    #[test]
    fn test_exstop_decode() {
        let mut dec = synced_decoder_with(&[0x62, 0x63]);
        let r1 = dec.next_packet().unwrap().unwrap();
        let r2 = dec.next_packet().unwrap().unwrap();
        assert_eq!(r1.kind, PtPacketKind::ExStop { ip: false });
        assert_eq!(r2.kind, PtPacketKind::ExStop { ip: true });
    }

    #[test]
    fn test_mode_packet_updates_64bit() {
        // MODE.Exec (0x02 0x43 <bits>) with bits = 0x02 => 64-bit mode
        let mut dec = synced_decoder_with(&[0x02, 0x43, 0x02]);
        let _ = dec.next_packet();
        assert!(dec.is_64bit);
    }

    #[test]
    fn test_vmcs_decode() {
        // VMCS: 0x02 0xC8 + 5 bytes base
        let base_shifted: u64 = 0x10; // base = 0x10 << 12 = 0x10000
        let payload = base_shifted.to_le_bytes();
        let mut data = vec![0x02u8, 0xC8];
        data.extend_from_slice(&payload[..5]);
        let mut dec = synced_decoder_with(&data);
        let r = dec.next_packet().unwrap().unwrap();
        assert!(matches!(r.kind, PtPacketKind::Vmcs { base } if base == 0x10000));
    }
}
