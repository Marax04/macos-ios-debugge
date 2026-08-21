//! `coresight_etm_decoder` — ETM4/ETE trace stream decoder.
//!
//! Provides [`CoreSightEtmDecoder`], [`EtmPacket`], and the free function
//! [`decode_stream`] for decoding raw ETM4 binary trace streams into structured
//! packet sequences.

use std::collections::VecDeque;
use std::fmt;
use serde::{Deserialize, Serialize};

// ─── EtmContext ───────────────────────────────────────────────────────────────

/// Boolean state flags grouped to avoid `struct_excessive_bools`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EtmFlags {
    /// Whether the CPU is in Secure state.
    pub secure: bool,
    /// Whether trace is currently enabled (`TraceOn` seen).
    pub trace_enabled: bool,
}

/// Decoder execution context maintained across packet boundaries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EtmContext {
    /// Current traced instruction address.
    pub address: u64,
    /// Whether the address is valid (we have seen at least one address packet).
    pub address_valid: bool,
    /// Current exception level (0–3).
    pub exception_level: u8,
    /// Current timestamp counter.
    pub timestamp: u64,
    /// Current cycle count.
    pub cycle_count: u64,
    /// Context ID.
    pub context_id: u32,
    /// Virtual machine ID.
    pub vm_id: u32,
    /// Whether we are synchronised (ASYNC seen).
    pub synchronised: bool,
    /// Number of atoms decoded.
    pub atom_count: u64,
    /// Number of taken atoms.
    pub taken_count: u64,
    /// Boolean state flags.
    pub flags: EtmFlags,
}

impl EtmContext {
    /// Apply a 32-bit address update (zero-extends to 64-bit).
    pub fn apply_addr32(&mut self, addr: u32) {
        self.address = u64::from(addr);
        self.address_valid = true;
    }

    /// Apply a 64-bit address update.
    pub const fn apply_addr64(&mut self, addr: u64) {
        self.address = addr;
        self.address_valid = true;
    }

    /// Apply a partial address update, updating only the low `bytes` bytes.
    pub const fn apply_addr_partial(&mut self, value: u64, bytes: u8) {
        let mask = if bytes >= 8 { u64::MAX } else { (1u64 << (bytes * 8)) - 1 };
        self.address = (self.address & !mask) | (value & mask);
        self.address_valid = true;
    }

    /// Advance the instruction pointer by `n` bytes.
    pub const fn advance(&mut self, n: u64) {
        if self.address_valid {
            self.address = self.address.wrapping_add(n);
        }
    }

    /// Record a branch atom.
    pub const fn record_atom(&mut self, taken: bool) {
        self.atom_count += 1;
        if taken { self.taken_count += 1; }
    }

    /// Return the taken/total atom ratio.
    #[must_use]
    pub fn taken_ratio(&self) -> f64 {
        if self.atom_count == 0 {
            0.0
        } else {
            let ppm = u128::from(self.taken_count) * 1_000_000 / u128::from(self.atom_count);
            f64::from(u32::try_from(ppm).unwrap_or(1_000_000)) * 1e-6
        }
    }
}

// ─── EtmPacket ────────────────────────────────────────────────────────────────

/// A single decoded ETM4 packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EtmPacket {
    /// ASYNC synchronisation frame (11× 0x00 + 0x80).
    Async,
    /// `TraceInfo` — payload byte(s) describe configuration.
    TraceInfo { payload: Vec<u8> },
    /// `TraceOn` — tracing enabled.
    TraceOn,
    /// `TraceOff` — tracing disabled.
    TraceOff,
    /// Address update (32-bit).
    Address32 { addr: u32 },
    /// Address update (64-bit).
    Address64 { addr: u64 },
    /// Partial address update.
    AddressPartial { value: u64, bytes: u8 },
    /// Atom packet with taken/not-taken bits.
    Atom {
        /// E/N bits (1 = taken).
        en_bits: u32,
        /// Number of valid atoms in `en_bits`.
        count: u8,
    },
    /// Context packet with exception level and security state.
    Context {
        /// Exception level (0–3).
        el: u8,
        /// Non-secure flag (true = non-secure).
        ns: bool,
    },
    /// Timestamp packet.
    Timestamp { value: u64 },
    /// Cycle count packet.
    CycleCount { count: u64 },
    /// Context ID.
    ContextId { id: u32 },
    /// Virtual Machine ID.
    VmId { id: u32 },
    /// Exception packet.
    Exception { exc_type: u16, el: u8 },
    /// Exception return.
    ExceptionReturn,
    /// Q element (speculative execution).
    QElement { count: u32 },
    /// Overflow — trace data was lost.
    Overflow,
    /// Ignore / pad byte.
    Ignore,
    /// Indirect branch target.
    IndirectBranch { target: u64 },
}

impl EtmPacket {
    /// Return the byte offset category string for logging.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Async => "ASYNC",
            Self::TraceInfo { .. } => "TraceInfo",
            Self::TraceOn => "TraceOn",
            Self::TraceOff => "TraceOff",
            Self::Address32 { .. } => "Address32",
            Self::Address64 { .. } => "Address64",
            Self::AddressPartial { .. } => "AddressPartial",
            Self::Atom { .. } => "Atom",
            Self::Context { .. } => "Context",
            Self::Timestamp { .. } => "Timestamp",
            Self::CycleCount { .. } => "CycleCount",
            Self::ContextId { .. } => "ContextId",
            Self::VmId { .. } => "VmId",
            Self::Exception { .. } => "Exception",
            Self::ExceptionReturn => "ExceptionReturn",
            Self::QElement { .. } => "QElement",
            Self::Overflow => "Overflow",
            Self::Ignore => "Ignore",
            Self::IndirectBranch { .. } => "IndirectBranch",
        }
    }

    /// Return `true` if this packet is a branch/atom.
    #[must_use]
    pub const fn is_atom(&self) -> bool { matches!(self, Self::Atom { .. }) }

    /// Return `true` if this packet updates the program counter.
    #[must_use]
    pub const fn is_address(&self) -> bool {
        matches!(self, Self::Address32 { .. } | Self::Address64 { .. } | Self::AddressPartial { .. })
    }
}

impl fmt::Display for EtmPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address32 { addr } => write!(f, "Address32(0x{addr:08x})"),
            Self::Address64 { addr } => write!(f, "Address64(0x{addr:016x})"),
            Self::Atom { en_bits, count } => write!(f, "Atom(en={en_bits:b}, n={count})"),
            Self::Timestamp { value } => write!(f, "Timestamp({value})"),
            Self::Exception { exc_type, el } => write!(f, "Exception(type={exc_type:#x}, el={el})"),
            _ => write!(f, "{}", self.kind_name()),
        }
    }
}

// ─── DecodedPacket ────────────────────────────────────────────────────────────

/// An [`EtmPacket`] paired with its position in the raw byte stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedPacket {
    /// Byte offset in the input stream.
    pub offset: usize,
    /// The decoded packet.
    pub packet: EtmPacket,
}

// ─── CoreSightEtmDecoder ──────────────────────────────────────────────────────

/// ETM4/ETE trace stream decoder.
///
/// Accepts raw bytes via [`Self::feed`], then pulls packets via
/// [`Self::next_packet`] or collects them all via [`Self::decode_all`].
pub struct CoreSightEtmDecoder {
    buf: Vec<u8>,
    pos: usize,
    /// Live execution context updated as packets are decoded.
    pub context: EtmContext,
    /// Whether to require synchronisation before decoding atoms.
    pub require_sync: bool,
    /// Decoded packet queue.
    queue: VecDeque<DecodedPacket>,
    /// Running error count.
    pub error_count: usize,
}

impl CoreSightEtmDecoder {
    /// Create a new decoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            context: EtmContext::default(),
            require_sync: false,
            queue: VecDeque::new(),
            error_count: 0,
        }
    }

    /// Feed raw bytes into the decoder.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Reset the decoder state.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.pos = 0;
        self.context = EtmContext::default();
        self.queue.clear();
        self.error_count = 0;
    }

    /// Return the current buffer position.
    #[must_use]
    pub const fn position(&self) -> usize { self.pos }

    /// Return whether the decoder is synchronised.
    #[must_use]
    pub const fn is_synchronised(&self) -> bool { self.context.synchronised }

    fn peek(&self) -> Option<u8> { self.buf.get(self.pos).copied() }

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

    fn read_uleb128(&mut self) -> Option<u64> {
        let mut val: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.consume()?;
            val |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 { break; }
            shift += 7;
            if shift >= 64 { return None; }
        }
        Some(val)
    }

    /// Attempt to locate the next ASYNC frame and synchronise.
    pub fn find_sync(&mut self) -> bool {
        let start = self.pos;
        while self.pos + 12 <= self.buf.len() {
            if self.buf[self.pos..self.pos + 11] == [0u8; 11]
                && self.buf[self.pos + 11] == 0x80
            {
                self.pos += 12;
                self.context.synchronised = true;
                return true;
            }
            self.pos += 1;
        }
        self.pos = start;
        false
    }

    /// Decode one packet from the buffer, updating `self.context`.
    ///
    /// # Panics
    ///
    /// Panics if internal byte slice conversion fails (should not occur given length checks).
    pub fn next_packet(&mut self) -> Option<DecodedPacket> {
        // Drain pre-decoded packets first
        if let Some(p) = self.queue.pop_front() { return Some(p); }

        let b = self.peek()?;
        let start = self.pos;
        self.pos += 1;

        let packet = match b {
            // ASYNC marker
            0x00 => {
                // Check for ASYNC sequence
                if self.pos + 10 <= self.buf.len()
                    && self.buf[self.pos..self.pos + 10] == [0u8; 10]
                    && self.buf.get(self.pos + 10) == Some(&0x80)
                {
                    self.pos += 11;
                    self.context.synchronised = true;
                    EtmPacket::Async
                } else {
                    EtmPacket::Ignore
                }
            }
            // TraceInfo
            0x01 => {
                let payload = self.consume_n(1).unwrap_or_default();
                EtmPacket::TraceInfo { payload }
            }
            // TraceOn
            0x04 => { self.context.flags.trace_enabled = true; EtmPacket::TraceOn }
            // TraceOff
            0x05 => { self.context.flags.trace_enabled = false; EtmPacket::TraceOff }
            // Atom F1 — single not-taken
            0x06 => { self.context.record_atom(false); EtmPacket::Atom { en_bits: 0, count: 1 } }
            // ExceptionReturn
            0x0E => EtmPacket::ExceptionReturn,
            // Exception
            0x08 => {
                if self.pos + 2 > self.buf.len() { self.pos = start; return None; }
                let t = self.buf[self.pos]; self.pos += 1;
                let l = self.buf[self.pos]; self.pos += 1;
                EtmPacket::Exception { exc_type: u16::from(t), el: l & 0b11 }
            }
            // CycleCount
            0x0D => {
                let count = self.read_uleb128().unwrap_or(0);
                self.context.cycle_count = self.context.cycle_count.wrapping_add(count);
                EtmPacket::CycleCount { count }
            }
            // Context
            0x0C => {
                if self.pos >= self.buf.len() { self.pos = start; return None; }
                let c = self.buf[self.pos]; self.pos += 1;
                let el = (c >> 1) & 0b11;
                let ns = c & 1 != 0;
                self.context.exception_level = el;
                self.context.flags.secure = !ns;
                EtmPacket::Context { el, ns }
            }
            // Atom taken (0x9E encodes single taken)
            0x9E => { self.context.record_atom(true); EtmPacket::Atom { en_bits: 1, count: 1 } }
            // Atom F3 — 2 atoms (0xA0..0xA3)
            0xA0..=0xA3 => {
                let en_bits = u32::from(b & 0x03);
                self.context.record_atom(en_bits & 1 != 0);
                self.context.record_atom(en_bits & 2 != 0);
                EtmPacket::Atom { en_bits, count: 2 }
            }
            // Timestamp: 0x43 + 8 bytes LE
            0x43 => {
                let Some(bytes) = self.consume_n(8) else { self.pos = start; return None; };
                let ts = u64::from_le_bytes(bytes.try_into().unwrap());
                self.context.timestamp = ts;
                EtmPacket::Timestamp { value: ts }
            }
            // ContextId: 0x50 + 4 bytes LE
            0x50 => {
                let Some(bytes) = self.consume_n(4) else { self.pos = start; return None; };
                let id = u32::from_le_bytes(bytes.try_into().unwrap());
                self.context.context_id = id;
                EtmPacket::ContextId { id }
            }
            // VmId: 0x51 + 4 bytes LE
            0x51 => {
                let Some(bytes) = self.consume_n(4) else { self.pos = start; return None; };
                let id = u32::from_le_bytes(bytes.try_into().unwrap());
                self.context.vm_id = id;
                EtmPacket::VmId { id }
            }
            // Address32: 0x9A + 4 bytes LE
            0x9A => {
                let Some(bytes) = self.consume_n(4) else { self.pos = start; return None; };
                let addr = u32::from_le_bytes(bytes.try_into().unwrap());
                self.context.apply_addr32(addr);
                EtmPacket::Address32 { addr }
            }
            // Address64: 0x9B + 8 bytes LE
            0x9B => {
                let Some(bytes) = self.consume_n(8) else { self.pos = start; return None; };
                let addr = u64::from_le_bytes(bytes.try_into().unwrap());
                self.context.apply_addr64(addr);
                EtmPacket::Address64 { addr }
            }
            // IndirectBranch: 0xAA + 8 bytes
            0xAA => {
                let Some(bytes) = self.consume_n(8) else { self.pos = start; return None; };
                let target = u64::from_le_bytes(bytes.try_into().unwrap());
                EtmPacket::IndirectBranch { target }
            }
            // Overflow / sync marker
            0x80 => { self.context.synchronised = true; EtmPacket::Async }
            0xFF => EtmPacket::Overflow,
            // Ignore all others
            _ => EtmPacket::Ignore,
        };

        Some(DecodedPacket { offset: start, packet })
    }

    /// Decode all remaining packets.
    #[must_use]
    pub fn decode_all(&mut self) -> Vec<DecodedPacket> {
        let mut out = Vec::new();
        while let Some(pkt) = self.next_packet() { out.push(pkt); }
        out
    }

    /// Collect all [`EtmPacket::Address64`] addresses.
    #[must_use]
    pub fn collect_addresses(&self, packets: &[DecodedPacket]) -> Vec<u64> {
        packets.iter().filter_map(|p| {
            match p.packet {
                EtmPacket::Address32 { addr } => Some(u64::from(addr)),
                EtmPacket::Address64 { addr } => Some(addr),
                _ => None,
            }
        }).collect()
    }
}

impl Default for CoreSightEtmDecoder {
    fn default() -> Self { Self::new() }
}

// ─── decode_stream ────────────────────────────────────────────────────────────

/// Decode an entire ETM4 byte stream and return all decoded packets.
///
/// This convenience function constructs a [`CoreSightEtmDecoder`], feeds all
/// `data` into it, and collects all packets.  The final decoder context is
/// discarded.
#[must_use]
pub fn decode_stream(data: &[u8]) -> Vec<DecodedPacket> {
    let mut dec = CoreSightEtmDecoder::new();
    dec.feed(data);
    dec.decode_all()
}

// ─── EtmStreamStats ───────────────────────────────────────────────────────────

/// Aggregate statistics computed over a decoded ETM packet stream.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EtmStreamStats {
    /// Total number of decoded packets.
    pub total_packets: usize,
    /// Number of address packets.
    pub address_packets: usize,
    /// Total atoms decoded.
    pub total_atoms: usize,
    /// Number of taken atoms.
    pub taken_atoms: usize,
    /// Number of exception packets.
    pub exception_packets: usize,
    /// Number of timestamp packets.
    pub timestamp_packets: usize,
    /// Number of overflow packets.
    pub overflow_packets: usize,
}

impl EtmStreamStats {
    /// Compute statistics from a slice of [`DecodedPacket`]s.
    #[must_use]
    pub fn compute(packets: &[DecodedPacket]) -> Self {
        let mut s = Self::default();
        for dp in packets {
            s.total_packets += 1;
            match &dp.packet {
                EtmPacket::Address32 { .. } | EtmPacket::Address64 { .. } => s.address_packets += 1,
                EtmPacket::Atom { en_bits, count } => {
                    let n = *count as usize;
                    s.total_atoms += n;
                    s.taken_atoms += (0..n).filter(|&i| (en_bits >> i) & 1 == 1).count();
                }
                EtmPacket::Exception { .. } => s.exception_packets += 1,
                EtmPacket::Timestamp { .. } => s.timestamp_packets += 1,
                EtmPacket::Overflow => s.overflow_packets += 1,
                _ => {}
            }
        }
        s
    }

    /// Return the taken-atom ratio in `[0.0, 1.0]`.
    #[must_use]
    pub fn taken_ratio(&self) -> f64 {
        if self.total_atoms == 0 {
            0.0
        } else {
            let ppm = (self.taken_atoms as u128) * 1_000_000 / (self.total_atoms as u128);
            f64::from(u32::try_from(ppm).unwrap_or(1_000_000)) * 1e-6
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_trace_on_off() {
        let mut dec = CoreSightEtmDecoder::new();
        dec.feed(&[0x04, 0x05]);
        let pkts = dec.decode_all();
        assert!(pkts.iter().any(|p| p.packet == EtmPacket::TraceOn));
        assert!(pkts.iter().any(|p| p.packet == EtmPacket::TraceOff));
    }

    #[test]
    fn decode_address32() {
        let mut dec = CoreSightEtmDecoder::new();
        let mut data = vec![0x9Au8];
        data.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        dec.feed(&data);
        let pkts = dec.decode_all();
        assert!(pkts.iter().any(|p| matches!(p.packet, EtmPacket::Address32 { addr: 0xDEAD_BEEF })));
    }

    #[test]
    fn decode_address64() {
        let mut dec = CoreSightEtmDecoder::new();
        let mut data = vec![0x9Bu8];
        data.extend_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
        dec.feed(&data);
        let pkts = dec.decode_all();
        assert!(pkts.iter().any(|p| matches!(p.packet, EtmPacket::Address64 { addr: 0xDEAD_BEEF_CAFE_BABE })));
    }

    #[test]
    fn decode_timestamp() {
        let mut dec = CoreSightEtmDecoder::new();
        let mut data = vec![0x43u8];
        data.extend_from_slice(&12_345_678_u64.to_le_bytes());
        dec.feed(&data);
        let pkts = dec.decode_all();
        assert!(pkts.iter().any(|p| matches!(p.packet, EtmPacket::Timestamp { value: 12_345_678 })));
        assert_eq!(dec.context.timestamp, 12_345_678);
    }

    #[test]
    fn decode_atom_single_not_taken() {
        let mut dec = CoreSightEtmDecoder::new();
        dec.feed(&[0x06]);
        let pkts = dec.decode_all();
        assert!(pkts.iter().any(|p| matches!(p.packet, EtmPacket::Atom { count: 1, en_bits: 0 })));
    }

    #[test]
    fn decode_context_id() {
        let mut dec = CoreSightEtmDecoder::new();
        let mut data = vec![0x50u8];
        data.extend_from_slice(&0xABCD_1234_u32.to_le_bytes());
        dec.feed(&data);
        let pkts = dec.decode_all();
        assert!(pkts.iter().any(|p| matches!(p.packet, EtmPacket::ContextId { id: 0xABCD_1234 })));
    }

    #[test]
    fn decode_stream_fn() {
        let mut data = vec![0x04u8]; // TraceOn
        data.push(0x9A);
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        let pkts = decode_stream(&data);
        assert!(!pkts.is_empty());
    }

    #[test]
    fn context_advance() {
        let mut ctx = EtmContext::default();
        ctx.apply_addr32(0x1000);
        ctx.advance(4);
        assert_eq!(ctx.address, 0x1004);
    }

    #[test]
    fn context_atom_ratio() {
        let mut ctx = EtmContext::default();
        ctx.record_atom(true);
        ctx.record_atom(false);
        ctx.record_atom(true);
        assert!((ctx.taken_ratio() - 2.0 / 3.0).abs() < 1e-6);
    }

    #[test]
    fn stream_stats_compute() {
        let data: Vec<u8> = {
            let mut v = vec![0x04u8]; // TraceOn
            v.push(0x9A); v.extend_from_slice(&0u32.to_le_bytes()); // Address32
            v.push(0xA0); // Atom 2-bit
            v
        };
        let pkts = decode_stream(&data);
        let stats = EtmStreamStats::compute(&pkts);
        assert_eq!(stats.address_packets, 1);
        assert_eq!(stats.total_atoms, 2);
    }

    #[test]
    fn decoder_find_sync() {
        let mut dec = CoreSightEtmDecoder::new();
        let mut data = vec![0x99u8, 0xAA]; // junk
        data.extend_from_slice(&[0u8; 11]);
        data.push(0x80);
        dec.feed(&data);
        assert!(dec.find_sync());
        assert!(dec.is_synchronised());
    }

    #[test]
    fn decoder_reset() {
        let mut dec = CoreSightEtmDecoder::new();
        dec.feed(&[0x04, 0x05]);
        let _ = dec.decode_all();
        dec.reset();
        assert_eq!(dec.position(), 0);
        assert!(!dec.is_synchronised());
    }

    #[test]
    fn decode_overflow() {
        let pkts = decode_stream(&[0xFF]);
        assert!(pkts.iter().any(|p| p.packet == EtmPacket::Overflow));
    }

    #[test]
    fn collect_addresses() {
        let dec = CoreSightEtmDecoder::new();
        let pkts = decode_stream(&{
            let mut v = vec![0x9Au8]; v.extend_from_slice(&0x1000u32.to_le_bytes());
            v.push(0x9A); v.extend_from_slice(&0x2000u32.to_le_bytes());
            v
        });
        let addrs = dec.collect_addresses(&pkts);
        assert_eq!(addrs, vec![0x1000, 0x2000]);
    }

    #[test]
    fn etm_packet_display() {
        let p = EtmPacket::Address32 { addr: 0x1000 };
        let s = p.to_string();
        assert!(s.contains("1000"));
    }

    #[test]
    fn stats_taken_ratio_zero_atoms() {
        let stats = EtmStreamStats::default();
        assert_eq!(stats.taken_ratio(), 0.0);
    }
}
