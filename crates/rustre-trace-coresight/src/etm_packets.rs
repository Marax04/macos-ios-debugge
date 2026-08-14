//! ARM ETM (Embedded Trace Macrocell) packet decoder.
//!
//! Supports ETM3 (Cortex-A/R) and ETM4 (Cortex-A/R v8) trace packet formats.
//! The decoder is a state machine that consumes raw byte streams and emits
//! decoded trace elements.

use std::collections::VecDeque;
use std::fmt;

pub use crate::CsError;

// ─── EtmVersion ───────────────────────────────────────────────────────────────

/// ETM architecture version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EtmArchVersion {
    /// ETM v3 (Cortex-A8/A9/A15/R4/R5 etc.).
    Etm3,
    /// ETM v4 (Cortex-A53/A55/A72/A78 etc.).
    Etm4,
    /// PTM (Program Trace Macrocell, a variant of ETM3).
    Ptm,
    /// ETE (Embedded Trace Extension, ARMv8.x).
    Ete,
}

impl fmt::Display for EtmArchVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Etm3 => write!(f, "ETM3"),
            Self::Etm4 => write!(f, "ETM4"),
            Self::Ptm => write!(f, "PTM"),
            Self::Ete => write!(f, "ETE"),
        }
    }
}

// ─── ETM3 packet types ────────────────────────────────────────────────────────

/// Decoded ETM3 packet type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Etm3Packet {
    /// A-Sync: synchronisation frame (21-byte sequence of 0x00).
    ASync,
    /// I-Sync: instruction packet with address and CPSR.
    ISync {
        /// Traced instruction address.
        address: u32,
        /// Current Program Status Register.
        cpsr: u32,
    },
    /// Trigger packet.
    Trigger,
    /// Branch packet.
    Branch {
        /// Branch target address.
        address: u32,
        /// Indirect branch (true = register, false = immediate).
        indirect: bool,
    },
    /// Context ID packet.
    ContextId {
        /// The context ID value.
        context_id: u32,
    },
    /// VMID packet.
    Vmid {
        /// Virtual machine ID.
        vmid: u8,
    },
    /// Timestamp packet.
    Timestamp {
        /// 64-bit trace timestamp.
        ts: u64,
    },
    /// Trace enabled.
    TraceOn,
    /// Trace disabled (branch tracing suppressed).
    TraceOff,
    /// Ignore / filler packet.
    Ignore,
    /// Atom packet (N taken/not-taken outcomes).
    Atom {
        /// Atom bits: bit 0 = first outcome, 1 = taken, 0 = not-taken.
        atoms: u8,
        /// Number of valid atom bits.
        count: u8,
    },
    /// Exception entry.
    ExceptionEntry {
        /// Exception type code.
        exception_type: u8,
    },
    /// Exception exit (return from exception).
    ExceptionExit,
}

impl fmt::Display for Etm3Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ASync => write!(f, "A-Sync"),
            Self::ISync { address, cpsr } => {
                write!(f, "I-Sync addr={address:#010x} cpsr={cpsr:#010x}")
            }
            Self::Trigger => write!(f, "Trigger"),
            Self::Branch { address, indirect } => {
                write!(f, "Branch addr={address:#010x} indirect={indirect}")
            }
            Self::ContextId { context_id } => write!(f, "ContextId {context_id:#010x}"),
            Self::Vmid { vmid } => write!(f, "VMID {vmid:#04x}"),
            Self::Timestamp { ts } => write!(f, "Timestamp {ts}"),
            Self::TraceOn => write!(f, "TraceOn"),
            Self::TraceOff => write!(f, "TraceOff"),
            Self::Ignore => write!(f, "Ignore"),
            Self::Atom { atoms, count } => write!(f, "Atom bits={atoms:08b} count={count}"),
            Self::ExceptionEntry { exception_type } => {
                write!(f, "ExceptionEntry type={exception_type:#04x}")
            }
            Self::ExceptionExit => write!(f, "ExceptionExit"),
        }
    }
}

// ─── ETM4 packet types ────────────────────────────────────────────────────────

/// ETM4 atom type (E = executed/taken, N = not-executed/not-taken).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Etm4Atom {
    /// Atom E (executed branch).
    E,
    /// Atom N (not-executed branch).
    N,
}

impl fmt::Display for Etm4Atom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::E => write!(f, "E"),
            Self::N => write!(f, "N"),
        }
    }
}

/// Decoded ETM4 trace element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Etm4Packet {
    /// Trace-On element (tracing started / resumed).
    TraceOn,
    /// Address element with IS-bit.
    Address {
        /// Target address.
        addr: u64,
        /// Instruction set bit (0 = A64/A32, 1 = T32).
        is_bit: u8,
    },
    /// Atom element: sequence of E/N outcomes.
    Atom {
        /// Up to 6 E/N outcomes.
        outcomes: Vec<Etm4Atom>,
    },
    /// Exception element.
    Exception {
        /// Exception type (ETM4 encoding).
        exception_type: u16,
        /// Exception level at entry.
        el: u8,
    },
    /// Timestamp element.
    Timestamp {
        /// Trace timestamp value.
        ts: u64,
        /// Whether a cycle count is embedded.
        has_cc: bool,
    },
    /// Cycle count element.
    CycleCount {
        /// Number of cycles.
        count: u64,
    },
    /// Context element (VMID + `ContextID`).
    Context {
        /// VMID value (if valid).
        vmid: Option<u64>,
        /// Context ID (if valid).
        context_id: Option<u64>,
    },
    /// Discard element — previous data discarded.
    Discard,
    /// Overflow element — ETM FIFO overflow detected.
    Overflow,
    /// Event element (custom event trigger).
    Event {
        /// Event number (0-3).
        event_num: u8,
    },
}

impl fmt::Display for Etm4Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TraceOn => write!(f, "ETM4:TraceOn"),
            Self::Address { addr, is_bit } => {
                write!(f, "ETM4:Address {addr:#018x} IS={is_bit}")
            }
            Self::Atom { outcomes } => {
                let s: String = outcomes.iter().map(std::string::ToString::to_string).collect();
                write!(f, "ETM4:Atom [{s}]")
            }
            Self::Exception { exception_type, el } => {
                write!(f, "ETM4:Exception type={exception_type:#06x} EL={el}")
            }
            Self::Timestamp { ts, has_cc } => {
                write!(f, "ETM4:Timestamp {ts} has_cc={has_cc}")
            }
            Self::CycleCount { count } => write!(f, "ETM4:CycleCount {count}"),
            Self::Context { vmid, context_id } => {
                write!(f, "ETM4:Context vmid={vmid:?} ctx={context_id:?}")
            }
            Self::Discard => write!(f, "ETM4:Discard"),
            Self::Overflow => write!(f, "ETM4:Overflow"),
            Self::Event { event_num } => write!(f, "ETM4:Event {event_num}"),
        }
    }
}

// ─── EtmDecoder ───────────────────────────────────────────────────────────────

/// State machine for decoding an ETM3 byte stream.
#[derive(Debug, Default)]
pub struct EtmDecoder {
    /// Unprocessed input bytes.
    buf: VecDeque<u8>,
    /// Number of A-Sync zero bytes seen consecutively.
    async_zeros: usize,
    /// Accumulated decoded packets.
    packets: VecDeque<Etm3Packet>,
    /// Whether we have synchronised to the stream.
    synced: bool,
}

impl EtmDecoder {
    /// Create a new decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes into the decoder.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend(data);
        self.process();
    }

    /// Take the next decoded packet, if any.
    pub fn next_packet(&mut self) -> Option<Etm3Packet> {
        self.packets.pop_front()
    }

    /// Take all currently available packets.
    pub fn drain_packets(&mut self) -> Vec<Etm3Packet> {
        self.packets.drain(..).collect()
    }

    /// Number of buffered (not yet consumed) packets.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.packets.len()
    }

    fn process(&mut self) {
        while let Some(&byte) = self.buf.front() {
            if !self.synced {
                // Look for A-Sync: 21 x 0x00 followed by 0x80
                if byte == 0x00 {
                    self.async_zeros += 1;
                    self.buf.pop_front();
                    continue;
                } else if byte == 0x80 && self.async_zeros >= 21 {
                    self.synced = true;
                    self.async_zeros = 0;
                    self.buf.pop_front();
                    self.packets.push_back(Etm3Packet::ASync);
                    continue;
                }
                self.async_zeros = 0;
                self.buf.pop_front();
                continue;
            }

            // Decode packet header
            match byte {
                0x00 => {
                    // Could be start of A-Sync or Ignore
                    self.buf.pop_front();
                    self.packets.push_back(Etm3Packet::Ignore);
                }
                0x08 => {
                    // Trigger
                    self.buf.pop_front();
                    self.packets.push_back(Etm3Packet::Trigger);
                }
                0x06 => {
                    // TraceOff
                    self.buf.pop_front();
                    self.packets.push_back(Etm3Packet::TraceOff);
                }
                0x04 => {
                    // TraceOn
                    self.buf.pop_front();
                    self.packets.push_back(Etm3Packet::TraceOn);
                }
                b if b & 0xFE == 0x6E => {
                    // ExceptionExit (0x6E or 0x6F)
                    self.buf.pop_front();
                    self.packets.push_back(Etm3Packet::ExceptionExit);
                }
                b if b & 0x80 == 0 && b & 0x01 == 0 => {
                    // Atom packet: bits 7:1 encode atoms, bit 0 = 0
                    self.buf.pop_front();
                    let atoms = (b >> 1) & 0x3F;
                    let count = 6u8;
                    self.packets.push_back(Etm3Packet::Atom { atoms, count });
                }
                b if b & 0x7F == 0x01 => {
                    // I-Sync: 5 bytes (byte + 4 bytes address)
                    if self.buf.len() < 9 {
                        break; // wait for more data
                    }
                    self.buf.pop_front();
                    let cpsr = self.read_u32_le();
                    let addr = self.read_u32_le();
                    self.packets.push_back(Etm3Packet::ISync {
                        address: addr,
                        cpsr,
                    });
                }
                b if b & 0x01 == 0x01 && b & 0xFE != 0 => {
                    // Branch packet: variable length (continuation bit in LSB)
                    self.buf.pop_front();
                    let mut addr_bytes = vec![b];
                    // Collect continuation bytes
                    let mut full = false;
                    for _ in 0..3 {
                        if let Some(&next) = self.buf.front() {
                            if next & 0x80 != 0 {
                                addr_bytes.push(next);
                                self.buf.pop_front();
                            } else {
                                full = true;
                                break;
                            }
                        }
                    }
                    let _ = full;
                    // Build address from 7-bit chunks
                    let mut address = 0u32;
                    for (i, &ab) in addr_bytes.iter().enumerate() {
                        address |= u32::from(ab & 0x7F) << (i * 7);
                    }
                    address <<= 1; // bit 0 = continuation, addresses are 2-byte aligned
                    let indirect = (b & 0x40) != 0;
                    self.packets
                        .push_back(Etm3Packet::Branch { address, indirect });
                }
                _ => {
                    self.buf.pop_front();
                    self.packets.push_back(Etm3Packet::Ignore);
                }
            }
        }
    }

    fn read_u32_le(&mut self) -> u32 {
        let b0 = u32::from(self.buf.pop_front().unwrap_or(0));
        let b1 = u32::from(self.buf.pop_front().unwrap_or(0));
        let b2 = u32::from(self.buf.pop_front().unwrap_or(0));
        let b3 = u32::from(self.buf.pop_front().unwrap_or(0));
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }
}

// ─── Etm4Decoder ──────────────────────────────────────────────────────────────

/// State machine for decoding an ETM4 byte stream.
#[derive(Debug, Default)]
pub struct Etm4Decoder {
    buf: VecDeque<u8>,
    packets: VecDeque<Etm4Packet>,
    synced: bool,
    async_zeros: usize,
}

impl Etm4Decoder {
    /// Create a new ETM4 decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend(data);
        self.process();
    }

    /// Take the next packet.
    pub fn next_packet(&mut self) -> Option<Etm4Packet> {
        self.packets.pop_front()
    }

    /// Drain all pending packets.
    pub fn drain_packets(&mut self) -> Vec<Etm4Packet> {
        self.packets.drain(..).collect()
    }

    fn process(&mut self) {
        while let Some(&byte) = self.buf.front() {
            if !self.synced {
                if byte == 0x00 {
                    self.async_zeros += 1;
                    self.buf.pop_front();
                } else if byte == 0x80 && self.async_zeros >= 11 {
                    // ETM4 A-Sync: 12 x 0x00 + 0x80
                    self.synced = true;
                    self.async_zeros = 0;
                    self.buf.pop_front();
                    self.packets.push_back(Etm4Packet::TraceOn);
                } else {
                    self.async_zeros = 0;
                    self.buf.pop_front();
                }
                continue;
            }

            match byte {
                0x00 => {
                    // Extension header byte — peek at next
                    if self.buf.len() < 2 {
                        break;
                    }
                    self.buf.pop_front();
                    let sub = *self.buf.front().unwrap_or(&0);
                    self.buf.pop_front();
                    match sub {
                        0x00 => self.packets.push_back(Etm4Packet::Overflow),
                        0x01 => self.packets.push_back(Etm4Packet::Discard),
                        _ => {} // reserved
                    }
                }
                0x01 => {
                    // TraceOn
                    self.buf.pop_front();
                    self.packets.push_back(Etm4Packet::TraceOn);
                }
                b if (0x95..=0x9B).contains(&b) => {
                    // Address packet: header encodes IS and address size
                    let header = b;
                    self.buf.pop_front();
                    let addr_bytes = (header & 0x06) as usize + 2;
                    if self.buf.len() < addr_bytes {
                        // Push header back conceptually — we can't un-consume,
                        // so we just stop and wait.
                        break;
                    }
                    let mut addr = 0u64;
                    for i in 0..addr_bytes {
                        addr |= u64::from(self.buf.pop_front().unwrap_or(0)) << (i * 8);
                    }
                    let is_bit = (header >> 3) & 0x01;
                    self.packets.push_back(Etm4Packet::Address { addr, is_bit });
                }
                b if (0xD0..=0xDF).contains(&b) => {
                    // Atom F1..F6 packets
                    let header = b;
                    self.buf.pop_front();
                    let outcomes = decode_atom_f(header);
                    self.packets.push_back(Etm4Packet::Atom { outcomes });
                }
                b if b >= 0xF0 => {
                    // Atom F6 long form
                    let header = b;
                    self.buf.pop_front();
                    let outcomes = decode_atom_long(header);
                    self.packets.push_back(Etm4Packet::Atom { outcomes });
                }
                0x02 => {
                    // Timestamp: variable-length ULEB128
                    self.buf.pop_front();
                    let ts = self.read_uleb128();
                    self.packets
                        .push_back(Etm4Packet::Timestamp { ts, has_cc: false });
                }
                0x03 => {
                    // Cycle count
                    self.buf.pop_front();
                    let count = self.read_uleb128();
                    self.packets.push_back(Etm4Packet::CycleCount { count });
                }
                0x80..=0x8F => {
                    // Exception
                    let header = byte;
                    self.buf.pop_front();
                    if self.buf.is_empty() {
                        break;
                    }
                    let ext = self.buf.pop_front().unwrap_or(0);
                    let exception_type = ((u16::from(header) & 0x0F) << 4) | ((u16::from(ext) >> 3) & 0x0F);
                    let el = ext & 0x03;
                    self.packets
                        .push_back(Etm4Packet::Exception { exception_type, el });
                }
                _ => {
                    self.buf.pop_front(); // skip unknown
                }
            }
        }
    }

    fn read_uleb128(&mut self) -> u64 {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let byte = self.buf.pop_front().unwrap_or(0);
            result |= u64::from(byte & 0x7F) << shift;
            shift += 7;
            if byte & 0x80 == 0 || shift >= 64 {
                break;
            }
        }
        result
    }
}

// ─── Atom decoders ────────────────────────────────────────────────────────────

fn decode_atom_f(header: u8) -> Vec<Etm4Atom> {
    // F1..F3: header encodes E/N pattern in bits [3:0]
    let count = ((header & 0x0F) >> 1).min(6) as usize;
    let pattern = header & 0x01;
    (0..count.max(1))
        .map(|i| {
            if (pattern >> i) & 1 == 1 {
                Etm4Atom::E
            } else {
                Etm4Atom::N
            }
        })
        .collect()
}

fn decode_atom_long(header: u8) -> Vec<Etm4Atom> {
    let e_count = (header & 0x1F) as usize;
    let n_count = ((header >> 5) & 0x03) as usize;
    let mut out: Vec<Etm4Atom> = (0..e_count).map(|_| Etm4Atom::E).collect();
    out.extend((0..n_count).map(|_| Etm4Atom::N));
    out
}

// ─── EtmTrace ─────────────────────────────────────────────────────────────────

/// A decoded instruction trace from ETM3 data.
#[derive(Debug, Clone, Default)]
pub struct EtmTrace {
    /// Decoded packets in order.
    pub packets: Vec<Etm3Packet>,
    /// Reconstructed instruction addresses in order (partial — requires
    /// disassembly for full reconstruction).
    pub addresses: Vec<u64>,
}

impl EtmTrace {
    /// Create an empty trace.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a packet.
    pub fn push(&mut self, pkt: Etm3Packet) {
        // Extract branch address if applicable
        if let Etm3Packet::Branch { address, .. } = &pkt {
            self.addresses.push(u64::from(*address));
        }
        if let Etm3Packet::ISync { address, .. } = &pkt {
            self.addresses.push(u64::from(*address));
        }
        self.packets.push(pkt);
    }

    /// Number of packets.
    #[must_use]
    pub const fn packet_count(&self) -> usize {
        self.packets.len()
    }

    /// Number of reconstructed addresses.
    #[must_use]
    pub const fn address_count(&self) -> usize {
        self.addresses.len()
    }

    /// Count of specific packet types.
    #[must_use]
    pub fn count_branches(&self) -> usize {
        self.packets
            .iter()
            .filter(|p| matches!(p, Etm3Packet::Branch { .. }))
            .count()
    }

    /// Count atom packets.
    #[must_use]
    pub fn count_atoms(&self) -> usize {
        self.packets
            .iter()
            .filter(|p| matches!(p, Etm3Packet::Atom { .. }))
            .count()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EtmArchVersion ───────────────────────────────────────────────────────

    #[test]
    fn arch_version_display() {
        assert_eq!(EtmArchVersion::Etm3.to_string(), "ETM3");
        assert_eq!(EtmArchVersion::Etm4.to_string(), "ETM4");
        assert_eq!(EtmArchVersion::Ptm.to_string(), "PTM");
        assert_eq!(EtmArchVersion::Ete.to_string(), "ETE");
    }

    // ── Etm3Packet display ───────────────────────────────────────────────────

    #[test]
    fn etm3_async_display() {
        let p = Etm3Packet::ASync;
        assert_eq!(p.to_string(), "A-Sync");
    }

    #[test]
    fn etm3_trigger_display() {
        let p = Etm3Packet::Trigger;
        assert_eq!(p.to_string(), "Trigger");
    }

    #[test]
    fn etm3_traceon_display() {
        assert_eq!(Etm3Packet::TraceOn.to_string(), "TraceOn");
    }

    #[test]
    fn etm3_traceoff_display() {
        assert_eq!(Etm3Packet::TraceOff.to_string(), "TraceOff");
    }

    #[test]
    fn etm3_ignore_display() {
        assert_eq!(Etm3Packet::Ignore.to_string(), "Ignore");
    }

    #[test]
    fn etm3_branch_display() {
        let p = Etm3Packet::Branch {
            address: 0x1234,
            indirect: false,
        };
        let s = p.to_string();
        assert!(s.contains("Branch"));
        assert!(s.contains("0x00001234"));
    }

    #[test]
    fn etm3_context_id_display() {
        let p = Etm3Packet::ContextId {
            context_id: 0xABCD_EF01,
        };
        let s = p.to_string();
        assert!(s.contains("ContextId"));
    }

    #[test]
    fn etm3_vmid_display() {
        let p = Etm3Packet::Vmid { vmid: 0x12 };
        let s = p.to_string();
        assert!(s.contains("VMID"));
    }

    #[test]
    fn etm3_timestamp_display() {
        let p = Etm3Packet::Timestamp { ts: 12345 };
        let s = p.to_string();
        assert!(s.contains("12345"));
    }

    #[test]
    fn etm3_atom_display() {
        let p = Etm3Packet::Atom {
            atoms: 0b1010_1010,
            count: 8,
        };
        let s = p.to_string();
        assert!(s.contains("Atom"));
    }

    #[test]
    fn etm3_exception_entry_display() {
        let p = Etm3Packet::ExceptionEntry {
            exception_type: 0x02,
        };
        let s = p.to_string();
        assert!(s.contains("ExceptionEntry"));
    }

    #[test]
    fn etm3_exception_exit_display() {
        assert_eq!(Etm3Packet::ExceptionExit.to_string(), "ExceptionExit");
    }

    // ── Etm4Packet display ───────────────────────────────────────────────────

    #[test]
    fn etm4_trace_on_display() {
        assert!(Etm4Packet::TraceOn.to_string().contains("TraceOn"));
    }

    #[test]
    fn etm4_address_display() {
        let p = Etm4Packet::Address {
            addr: 0xFFFF_8000_1234_5678,
            is_bit: 0,
        };
        let s = p.to_string();
        assert!(s.contains("Address"));
    }

    #[test]
    fn etm4_overflow_display() {
        assert!(Etm4Packet::Overflow.to_string().contains("Overflow"));
    }

    #[test]
    fn etm4_discard_display() {
        assert!(Etm4Packet::Discard.to_string().contains("Discard"));
    }

    #[test]
    fn etm4_atom_en_display() {
        let p = Etm4Packet::Atom {
            outcomes: vec![Etm4Atom::E, Etm4Atom::N],
        };
        let s = p.to_string();
        assert!(s.contains("EN") || s.contains('E') && s.contains('N'));
    }

    // ── EtmDecoder ───────────────────────────────────────────────────────────

    fn make_async() -> Vec<u8> {
        let mut v = vec![0x00u8; 21];
        v.push(0x80);
        v
    }

    #[test]
    fn etm_decoder_async_sync() {
        let mut dec = EtmDecoder::new();
        dec.feed(&make_async());
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt, Etm3Packet::ASync);
    }

    #[test]
    fn etm_decoder_trigger_after_sync() {
        let mut dec = EtmDecoder::new();
        let mut data = make_async();
        data.push(0x08);
        dec.feed(&data);
        dec.next_packet(); // consume A-Sync
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt, Etm3Packet::Trigger);
    }

    #[test]
    fn etm_decoder_trace_on_after_sync() {
        let mut dec = EtmDecoder::new();
        let mut data = make_async();
        data.push(0x04);
        dec.feed(&data);
        dec.next_packet(); // A-Sync
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt, Etm3Packet::TraceOn);
    }

    #[test]
    fn etm_decoder_trace_off() {
        let mut dec = EtmDecoder::new();
        let mut data = make_async();
        data.push(0x06);
        dec.feed(&data);
        dec.next_packet();
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt, Etm3Packet::TraceOff);
    }

    #[test]
    fn etm_decoder_drain_packets() {
        let mut dec = EtmDecoder::new();
        dec.feed(&make_async());
        let all = dec.drain_packets();
        assert!(!all.is_empty());
    }

    #[test]
    fn etm_decoder_pending_count() {
        let mut dec = EtmDecoder::new();
        dec.feed(&make_async());
        assert_eq!(dec.pending_count(), 1);
    }

    // ── Etm4Decoder ──────────────────────────────────────────────────────────

    fn make_etm4_async() -> Vec<u8> {
        let mut v = vec![0x00u8; 12];
        v.push(0x80);
        v
    }

    #[test]
    fn etm4_decoder_sync() {
        let mut dec = Etm4Decoder::new();
        dec.feed(&make_etm4_async());
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt, Etm4Packet::TraceOn);
    }

    #[test]
    fn etm4_decoder_trace_on_byte() {
        let mut dec = Etm4Decoder::new();
        let mut data = make_etm4_async();
        data.push(0x01);
        dec.feed(&data);
        dec.next_packet(); // sync TraceOn
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt, Etm4Packet::TraceOn);
    }

    #[test]
    fn etm4_decoder_overflow() {
        let mut dec = Etm4Decoder::new();
        let mut data = make_etm4_async();
        data.extend_from_slice(&[0x00, 0x00]);
        dec.feed(&data);
        dec.next_packet(); // sync
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt, Etm4Packet::Overflow);
    }

    // ── Etm4Atom ─────────────────────────────────────────────────────────────

    #[test]
    fn etm4_atom_display_e() {
        assert_eq!(Etm4Atom::E.to_string(), "E");
    }

    #[test]
    fn etm4_atom_display_n() {
        assert_eq!(Etm4Atom::N.to_string(), "N");
    }

    // ── EtmTrace ─────────────────────────────────────────────────────────────

    #[test]
    fn etm_trace_push_and_count() {
        let mut trace = EtmTrace::new();
        trace.push(Etm3Packet::Branch {
            address: 0x1000,
            indirect: false,
        });
        assert_eq!(trace.packet_count(), 1);
        assert_eq!(trace.address_count(), 1);
    }

    #[test]
    fn etm_trace_count_branches() {
        let mut trace = EtmTrace::new();
        trace.push(Etm3Packet::Branch {
            address: 0x1000,
            indirect: false,
        });
        trace.push(Etm3Packet::Branch {
            address: 0x2000,
            indirect: true,
        });
        trace.push(Etm3Packet::Trigger);
        assert_eq!(trace.count_branches(), 2);
    }

    #[test]
    fn etm_trace_count_atoms() {
        let mut trace = EtmTrace::new();
        trace.push(Etm3Packet::Atom {
            atoms: 0b1111,
            count: 4,
        });
        assert_eq!(trace.count_atoms(), 1);
    }

    #[test]
    fn etm_trace_isync_address() {
        let mut trace = EtmTrace::new();
        trace.push(Etm3Packet::ISync {
            address: 0xABCD_1234,
            cpsr: 0,
        });
        assert_eq!(trace.address_count(), 1);
        assert_eq!(trace.addresses[0], 0xABCD_1234);
    }
}
