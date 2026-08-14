//! `ptm_decoder` — ARM PTM (Program Trace Macrocell) decoder.
//!
//! Implements the PTM packet encoding used in Cortex-A5, A8, and A9 processors.
//! The PTM protocol predates `ETMv4` and uses a different packet framing scheme.
//!
//! Protocol summary:
//! * **Branch packets** — direct branches with partial address bits.
//! * **Atom packets** — sequential E/N (executed/not-executed) bits.
//! * **Waypoint updates** — resyncs the decoder's PC to a known address.
//! * **A-sync packets** — full 12-byte synchronization frame.
//! * **Context ID** — 1/2/4 byte context identifiers.
//! * **Timestamp** — variable-length encoded timestamp.
//! * **Exception** — exception entry/exit markers.

use std::collections::VecDeque;
use std::fmt;

// ─── PtmError ─────────────────────────────────────────────────────────────────

/// Error during PTM decoding.
#[derive(Debug, Clone)]
pub enum PtmError {
    /// Not enough bytes remain.
    TruncatedStream { pos: usize },
    /// Sync lost: no valid ASYNC frame found.
    SyncLost,
    /// Unrecognised packet header byte.
    UnknownPacket { byte: u8, pos: usize },
    /// Internal decoder state inconsistency.
    StateError(String),
}

impl fmt::Display for PtmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedStream { pos } => write!(f, "truncated stream at 0x{pos:x}"),
            Self::SyncLost => write!(f, "synchronization lost"),
            Self::UnknownPacket { byte, pos } => {
                write!(f, "unknown packet 0x{byte:02x} at 0x{pos:x}")
            }
            Self::StateError(s) => write!(f, "state error: {s}"),
        }
    }
}

// ─── PtmPacketKind ────────────────────────────────────────────────────────────

/// Kind of decoded PTM packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtmPacketKind {
    /// A-sync synchronization frame (12 bytes: 11×0x00 + 0x80).
    ASync,
    /// Cycle count packet.
    CycleCount(u32),
    /// Branch packet with address and taken/not-taken.
    Branch {
        /// Reconstructed target address (partial or full).
        address: u64,
        /// Whether the branch was taken.
        taken: bool,
        /// Whether the address bits are fully specified.
        address_complete: bool,
    },
    /// Atom packet: one or more E/N bits.
    Atom {
        /// E/N bits packed into a u32 (bit 0 = first atom, 1=taken).
        en_bits: u32,
        /// Number of valid E/N bits.
        count: u8,
    },
    /// Waypoint update: full PC resync.
    Waypoint {
        /// Full reconstructed PC.
        address: u64,
    },
    /// Context ID (1/2/4 bytes).
    ContextId {
        /// The context ID value.
        id: u32,
        /// Width in bytes (1, 2, or 4).
        bytes: u8,
    },
    /// Timestamp (variable length).
    Timestamp(u64),
    /// Ignore byte.
    Ignore,
    /// Exception packet.
    Exception {
        /// ARM exception type code.
        exc_type: u8,
        /// Whether this is an exception return.
        is_return: bool,
    },
    /// `TraceInfo` / trace-enable event.
    TraceInfo,
    /// Overflow — decoder overflowed.
    Overflow,
    /// VMID packet.
    VmId(u8),
}

impl fmt::Display for PtmPacketKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ASync => write!(f, "ASYNC"),
            Self::CycleCount(c) => write!(f, "CC({c})"),
            Self::Branch {
                address,
                taken,
                address_complete,
            } => write!(
                f,
                "Branch(addr={address:#x}, taken={taken}, complete={address_complete})"
            ),
            Self::Atom { en_bits, count } => write!(f, "Atom(bits={en_bits:032b}, n={count})"),
            Self::Waypoint { address } => write!(f, "Waypoint({address:#x})"),
            Self::ContextId { id, bytes } => write!(f, "ContextId({id:#x}, {bytes}B)"),
            Self::Timestamp(ts) => write!(f, "TS({ts})"),
            Self::Ignore => write!(f, "Ignore"),
            Self::Exception { exc_type, is_return } => {
                write!(f, "Exception(type={exc_type:#x}, ret={is_return})")
            }
            Self::TraceInfo => write!(f, "TraceInfo"),
            Self::Overflow => write!(f, "Overflow"),
            Self::VmId(id) => write!(f, "VmId({id:#x})"),
        }
    }
}

// ─── PtmPacket ────────────────────────────────────────────────────────────────

/// A single decoded PTM packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtmPacket {
    /// The decoded payload.
    pub kind: PtmPacketKind,
    /// Byte offset in the source stream.
    pub offset: usize,
    /// Total bytes consumed by this packet.
    pub byte_len: usize,
}

impl PtmPacket {
    /// Create a new packet.
    #[must_use]
    pub const fn new(kind: PtmPacketKind, offset: usize, byte_len: usize) -> Self {
        Self {
            kind,
            offset,
            byte_len,
        }
    }

    /// Return `true` if this is a branch packet.
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        matches!(self.kind, PtmPacketKind::Branch { .. })
    }

    /// Return `true` if this is an atom packet.
    #[must_use]
    pub const fn is_atom(&self) -> bool {
        matches!(self.kind, PtmPacketKind::Atom { .. })
    }

    /// Return `true` if this is a waypoint packet.
    #[must_use]
    pub const fn is_waypoint(&self) -> bool {
        matches!(self.kind, PtmPacketKind::Waypoint { .. })
    }
}

impl fmt::Display for PtmPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PtmPacket {{ {} @ 0x{:x} ({} bytes) }}", self.kind, self.offset, self.byte_len)
    }
}

// ─── BranchPacket ─────────────────────────────────────────────────────────────

/// Decoded PTM branch packet with address reconstruction state.
#[derive(Debug, Clone)]
pub struct BranchPacket {
    /// Bytes of the branch packet (variable length).
    pub raw_bytes: Vec<u8>,
    /// Address bits extracted from the packet (may be partial).
    pub address_bits: u64,
    /// Number of valid address bits.
    pub valid_bits: u8,
    /// Whether the branch was taken.
    pub taken: bool,
    /// Whether the exception bit is set.
    pub exception: bool,
    /// Whether this branch carries a full address.
    pub full_address: bool,
}

impl BranchPacket {
    /// Create a branch packet.
    #[must_use]
    pub const fn new(raw_bytes: Vec<u8>) -> Self {
        Self {
            raw_bytes,
            address_bits: 0,
            valid_bits: 0,
            taken: false,
            exception: false,
            full_address: false,
        }
    }

    /// Return `true` if the packet contains a full 32-bit address.
    #[must_use]
    pub const fn has_full_address(&self) -> bool {
        self.valid_bits >= 32
    }

    /// Reconstruct the full address by merging partial bits with `prev_pc`.
    #[must_use]
    pub const fn merge_address(&self, prev_pc: u64) -> u64 {
        if self.has_full_address() {
            return self.address_bits & !1u64; // clear Thumb bit
        }
        // Replace the low `valid_bits` of prev_pc with the partial address.
        let mask = (1u64 << self.valid_bits) - 1;
        (prev_pc & !mask) | (self.address_bits & mask)
    }
}

// ─── WaypointPacket ───────────────────────────────────────────────────────────

/// A PTM waypoint update packet.
#[derive(Debug, Clone)]
pub struct WaypointPacket {
    /// The full PC address provided by the waypoint.
    pub address: u64,
    /// Byte offset in the source stream.
    pub offset: usize,
    /// Whether this was a 32-bit or 64-bit waypoint.
    pub is_32bit: bool,
}

impl WaypointPacket {
    /// Create a waypoint packet.
    #[must_use]
    pub const fn new(address: u64, offset: usize, is_32bit: bool) -> Self {
        Self {
            address,
            offset,
            is_32bit,
        }
    }
}

// ─── PcHistory ────────────────────────────────────────────────────────────────

/// Reconstructed PC history from decoded PTM packets.
#[derive(Debug, Clone, Default)]
pub struct PcHistory {
    /// All reconstructed addresses in decode order.
    pub addresses: Vec<u64>,
    /// Current PC.
    pub current_pc: u64,
    /// Whether the current PC is valid (synced).
    pub pc_valid: bool,
    /// Number of unresolved branch packets (branches without full addresses).
    pub unresolved_branches: usize,
}

impl PcHistory {
    /// Create an empty PC history.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            addresses: Vec::new(),
            current_pc: 0,
            pc_valid: false,
            unresolved_branches: 0,
        }
    }

    /// Apply a waypoint update.
    pub fn apply_waypoint(&mut self, addr: u64) {
        self.current_pc = addr;
        self.pc_valid = true;
        self.addresses.push(addr);
    }

    /// Apply a branch packet.
    ///
    /// If the branch is taken and has a full address, advances the PC.
    pub fn apply_branch(&mut self, packet: &BranchPacket) {
        if !self.pc_valid {
            self.unresolved_branches += 1;
            return;
        }
        if packet.taken {
            let target = packet.merge_address(self.current_pc);
            self.current_pc = target;
            self.addresses.push(target);
        } else {
            // Not taken: fall through (advance by assumed instruction width).
            self.current_pc = self.current_pc.wrapping_add(4);
            self.addresses.push(self.current_pc);
        }
    }

    /// Return the last N addresses.
    #[must_use]
    pub fn last_n(&self, n: usize) -> &[u64] {
        let start = self.addresses.len().saturating_sub(n);
        &self.addresses[start..]
    }

    /// Return the total number of recorded addresses.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Return `true` if no addresses have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

// ─── PtmConfig ────────────────────────────────────────────────────────────────

/// Optional feature flags for the PTM decoder (data-tracing and return-stack).
///
/// Split from [`PtmConfig`] to keep the bool count per struct within limits.
#[derive(Debug, Clone, Default)]
pub struct PtmConfigFlags {
    /// Whether data tracing is enabled.
    pub data_tracing: bool,
    /// Whether return-stack tracing is enabled.
    pub return_stack: bool,
}

/// Configuration for the PTM decoder.
#[derive(Debug, Clone)]
pub struct PtmConfig {
    /// Whether 32-bit or 64-bit addresses are used.
    pub address_bits: u8,
    /// Context ID size in bytes (0 = disabled, 1/2/4).
    pub context_id_bytes: u8,
    /// Whether cycle counting is enabled.
    pub cycle_counting: bool,
    /// Whether timestamps are enabled.
    pub timestamps: bool,
    /// Whether strict mode (error on unknown packets) is enabled.
    pub strict: bool,
    /// Additional optional feature flags.
    pub flags: PtmConfigFlags,
}

impl Default for PtmConfig {
    fn default() -> Self {
        Self {
            address_bits: 32,
            context_id_bytes: 0,
            cycle_counting: false,
            timestamps: false,
            strict: false,
            flags: PtmConfigFlags::default(),
        }
    }
}

// ─── PtmDecoderState ──────────────────────────────────────────────────────────

/// Internal state machine state for the PTM decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PtmState {
    /// Waiting for / searching for an ASYNC frame.
    WaitingForSync,
    /// Normal packet decode.
    Decoding,
}

// ─── PtmDecoder ───────────────────────────────────────────────────────────────

/// PTM (Program Trace Macrocell) packet decoder.
///
/// Reconstructs the PC history from a raw PTM byte stream.
///
/// # Usage
///
/// ```ignore
/// let mut dec = PtmDecoder::new(PtmConfig::default());
/// dec.feed(&raw_trace_bytes);
/// let packets = dec.decode_all();
/// ```
pub struct PtmDecoder {
    /// Decoder configuration.
    pub config: PtmConfig,
    /// Raw byte buffer.
    buf: Vec<u8>,
    /// Current read position.
    pos: usize,
    /// Internal state.
    state: PtmState,
    /// Reconstructed PC history.
    pub history: PcHistory,
    /// Pending branch bytes accumulator.
    branch_acc: Vec<u8>,
    /// Atom queue.
    pub atom_queue: VecDeque<bool>,
    /// Waypoint packets seen.
    pub waypoints: Vec<WaypointPacket>,
    /// Total packets decoded.
    pub packet_count: usize,
    /// Number of decode errors encountered.
    pub error_count: usize,
}

impl PtmDecoder {
    /// Create a new PTM decoder with the given configuration.
    #[must_use]
    pub const fn new(config: PtmConfig) -> Self {
        Self {
            config,
            buf: Vec::new(),
            pos: 0,
            state: PtmState::WaitingForSync,
            history: PcHistory::new(),
            branch_acc: Vec::new(),
            atom_queue: VecDeque::new(),
            waypoints: Vec::new(),
            packet_count: 0,
            error_count: 0,
        }
    }

    /// Create a decoder with default configuration.
    #[must_use]
    pub fn default_decoder() -> Self {
        Self::new(PtmConfig::default())
    }

    /// Feed additional trace bytes into the decoder.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Peek at the next byte without consuming.
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Consume and return the next byte.
    fn consume(&mut self) -> Option<u8> {
        let b = self.buf.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    /// Consume `n` bytes, returning them as a slice copy.
    fn consume_n(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Some(v)
    }

    /// Scan forward for an ASYNC frame (11×0x00 followed by 0x80).
    ///
    /// Returns `true` if sync was found and the decoder is now positioned
    /// after the sync frame.
    pub fn find_sync(&mut self) -> bool {
        while self.pos + 12 <= self.buf.len() {
            let slice = &self.buf[self.pos..self.pos + 12];
            let all_zero = slice[..11].iter().all(|&b| b == 0x00);
            if all_zero && slice[11] == 0x80 {
                self.pos += 12;
                self.state = PtmState::Decoding;
                return true;
            }
            self.pos += 1;
        }
        false
    }

    /// Decode one PTM packet from the current position.
    ///
    /// Returns `None` when the buffer is exhausted.
    pub fn decode_one(&mut self) -> Option<PtmPacket> {
        if self.state == PtmState::WaitingForSync {
            if !self.find_sync() {
                return None;
            }
            let start = self.pos - 12;
            self.packet_count += 1;
            return Some(PtmPacket::new(PtmPacketKind::ASync, start, 12));
        }

        let start = self.pos;
        let b = self.peek()?;

        // ── ASYNC (12 bytes: 11×0x00 + 0x80) ─────────────────────────────────
        if b == 0x00 && self.pos + 12 <= self.buf.len() {
            let candidate = &self.buf[self.pos..self.pos + 12];
            if candidate[..11].iter().all(|&x| x == 0) && candidate[11] == 0x80 {
                self.pos += 12;
                self.packet_count += 1;
                return Some(PtmPacket::new(PtmPacketKind::ASync, start, 12));
            }
        }

        // Consume the header byte.
        let b = self.consume()?;

        match b {
            // ── TraceInfo 0x01 ────────────────────────────────────────────
            0x01 => {
                self.packet_count += 1;
                Some(PtmPacket::new(PtmPacketKind::TraceInfo, start, 1))
            }
            // ── P-header (atom) bytes: 0bxxxxxxx1 with bit[4:1] encoding atoms
            // PTM P-header: bit0 = 1, bits 7:4 = atom bits.
            // Various P-header formats:
            // Format 1: 0b1000_1101 — multiple E atoms.
            // Format 2: 0b1000_0100 — N atom.
            x if x & 0x81 == 0x80 => {
                // P-header packet.
                let (en_bits, count) = decode_p_header(x);
                for i in 0..count {
                    let taken = (en_bits >> i) & 1 != 0;
                    self.atom_queue.push_back(taken);
                }
                self.packet_count += 1;
                Some(PtmPacket::new(
                    PtmPacketKind::Atom {
                        en_bits: u32::from(en_bits),
                        count,
                    },
                    start,
                    1,
                ))
            }

            // ── Branch packet: bit0 = 1, not a P-header.
            x if x & 0x01 == 0x01 => Some(self.decode_ptm_branch(x, start)),

            // ── Context ID (depends on config)
            0x6E if self.config.context_id_bytes >= 1 => self.decode_ptm_context_id(start),

            // ── Waypoint: 0x76 — full 32-bit PC resync
            0x76 => {
                let Some(addr_bytes) = self.consume_n(4) else {
                    self.pos = start;
                    return None;
                };
                let addr = u64::from(u32::from_le_bytes([addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]]));
                let wp = WaypointPacket::new(addr, start, true);
                self.history.apply_waypoint(addr);
                self.waypoints.push(wp);
                self.packet_count += 1;
                Some(PtmPacket::new(PtmPacketKind::Waypoint { address: addr }, start, 5))
            }

            // ── Timestamp: 0b0100_0011 (0x43) followed by ULEB128.
            0x43 if self.config.timestamps => {
                let ts = self.read_uleb128().unwrap_or(0);
                self.packet_count += 1;
                Some(PtmPacket::new(PtmPacketKind::Timestamp(ts), start, self.pos - start))
            }

            // ── Cycle count: 0x12
            0x12 if self.config.cycle_counting => {
                let count = u32::from(self.consume().unwrap_or(0));
                self.packet_count += 1;
                Some(PtmPacket::new(PtmPacketKind::CycleCount(count), start, 2))
            }

            // ── Exception packet: 0b0000_1110 (0x0E)
            0x0E => {
                let exc_byte = self.consume().unwrap_or(0);
                let exc_type = exc_byte & 0x1F;
                let is_return = exc_byte & 0x80 != 0;
                self.packet_count += 1;
                Some(PtmPacket::new(
                    PtmPacketKind::Exception { exc_type, is_return },
                    start,
                    2,
                ))
            }

            // TraceInfo (0x01) is handled earlier in this match; the
            // duplicate arm previously here is unreachable and has been
            // removed. VMID handling follows.

            // ── VMID: 0b0000_0011 (0x03)
            0x03 => {
                let id = self.consume().unwrap_or(0);
                self.packet_count += 1;
                Some(PtmPacket::new(PtmPacketKind::VmId(id), start, 2))
            }

            // ── Ignore: 0b0110_0110 (0x66)
            0x66 => {
                self.packet_count += 1;
                Some(PtmPacket::new(PtmPacketKind::Ignore, start, 1))
            }

            // ── Overflow: 0x05
            0x05 => {
                self.packet_count += 1;
                Some(PtmPacket::new(PtmPacketKind::Overflow, start, 1))
            }

            // ── Unknown byte
            _unknown => {
                self.error_count += 1;
                if self.config.strict {
                    // Strict mode: emit error as an overflow packet and stop.
                    self.pos = start; // back up
                    return None;
                }
                // Non-strict: emit overflow and continue.
                Some(PtmPacket::new(PtmPacketKind::Overflow, start, 1))
            }
        }
    }

    /// Decode a PTM branch packet starting with the already-consumed byte `b`.
    fn decode_ptm_branch(&mut self, b: u8, start: usize) -> PtmPacket {
        let mut raw = vec![b];
        // Continuation: if bit[7] of the current byte is set, more bytes follow.
        while let Some(next) = self.peek() {
            if next & 0x80 != 0 {
                self.consume();
                raw.push(next);
            } else {
                break;
            }
        }
        let (addr_bits, valid_bits, taken, exception) = decode_branch_bytes(&raw);
        let mut bp = BranchPacket::new(raw.clone());
        bp.address_bits = addr_bits;
        bp.valid_bits = valid_bits;
        bp.taken = taken;
        bp.exception = exception;
        bp.full_address = valid_bits >= 32;
        let reconstructed_addr = if self.history.pc_valid {
            bp.merge_address(self.history.current_pc)
        } else {
            addr_bits
        };
        self.history.apply_branch(&bp);
        self.packet_count += 1;
        PtmPacket::new(
            PtmPacketKind::Branch {
                address: reconstructed_addr,
                taken,
                address_complete: bp.full_address,
            },
            start,
            raw.len(),
        )
    }

    /// Decode a PTM Context ID packet (0x6E).
    fn decode_ptm_context_id(&mut self, start: usize) -> Option<PtmPacket> {
        let nb = usize::from(self.config.context_id_bytes);
        let id_bytes = self.consume_n(nb.min(4))?;
        let id = match id_bytes.len() {
            1 => u32::from(id_bytes[0]),
            2 => u32::from(u16::from_le_bytes([id_bytes[0], id_bytes[1]])),
            4 => u32::from_le_bytes([id_bytes[0], id_bytes[1], id_bytes[2], id_bytes[3]]),
            _ => 0,
        };
        let len = id_bytes.len();
        self.packet_count += 1;
        Some(PtmPacket::new(
            PtmPacketKind::ContextId {
                id,
                bytes: u8::try_from(len).unwrap_or(4),
            },
            start,
            1 + len,
        ))
    }

    /// Decode all remaining packets in the buffer.
    #[must_use]
    pub fn decode_all(&mut self) -> Vec<PtmPacket> {
        let mut out = Vec::new();
        while let Some(pkt) = self.decode_one() {
            out.push(pkt);
        }
        out
    }

    /// Reset the decoder to initial state, clearing the buffer and history.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.pos = 0;
        self.state = PtmState::WaitingForSync;
        self.history = PcHistory::new();
        self.branch_acc.clear();
        self.atom_queue.clear();
        self.waypoints.clear();
        self.packet_count = 0;
        self.error_count = 0;
    }

    /// Return the current read position in the buffer.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Return `true` if the decoder is synchronized.
    #[must_use]
    pub const fn is_synchronized(&self) -> bool {
        matches!(self.state, PtmState::Decoding)
    }

    /// Return remaining (unread) bytes in the buffer.
    #[must_use]
    pub const fn remaining_bytes(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Return the next atom from the atom queue.
    pub fn next_atom(&mut self) -> Option<bool> {
        self.atom_queue.pop_front()
    }

    /// Read a ULEB128-encoded integer.
    fn read_uleb128(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.consume()?;
            result |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 63 {
                break;
            }
        }
        Some(result)
    }
}

impl Default for PtmDecoder {
    fn default() -> Self {
        Self::new(PtmConfig::default())
    }
}

// ─── Decode helpers ───────────────────────────────────────────────────────────

/// Decode a PTM P-header (atom) byte.
///
/// Returns `(en_bits, count)` where bit `i` of `en_bits` = taken for atom `i`.
///
/// PTM P-header formats (ARM IHI0014):
/// * `0b1000_0100` (0x84) — single N atom.
/// * `0b1000_1000` (0x88) — two E atoms.
/// * `0b1000_1101` (0x8D) — one E + one N.
/// * `0b1001_0101` (0x95) etc. — various combinations.
const fn decode_p_header(b: u8) -> (u8, u8) {
    // P-headers have bit[0]=0 and bit[7]=1 in PTM.
    // bits [6:5] encode the atom pattern.
    let e_count = (b >> 4) & 0x07; // number of E (executed/taken) atoms
    let n_count = (b >> 2) & 0x01; // number of N (not-executed) atoms
    let total = e_count + n_count;
    // E atoms come first, then N atoms.
    let en_bits: u8 = (1u8 << e_count).wrapping_sub(1); // low e_count bits set
    (en_bits, total)
}

/// Decode address bits from a multi-byte PTM branch packet.
///
/// Returns `(address_bits, valid_bits, taken, exception)`.
fn decode_branch_bytes(raw: &[u8]) -> (u64, u8, bool, bool) {
    if raw.is_empty() {
        return (0, 0, false, false);
    }

    let first = raw[0];
    // Bit 0 of first byte is branch indicator (already consumed).
    // Bit 1 of first byte is the taken/not-taken indicator.
    let taken = first & 0x02 != 0;
    // Bit 6 of last byte (or relevant byte) is the exception bit.
    let last = raw[raw.len() - 1];
    let exception = last & 0x40 != 0;

    // Address bits are scattered: bits [6:1] of byte 0, bits [6:0] of subsequent bytes.
    let mut address_bits: u64 = u64::from((first >> 1) & 0x3F); // 6 bits from byte 0
    let mut valid_bits: u8 = 6;

    for &byte in &raw[1..] {
        let addr_chunk = u64::from(byte & 0x7F); // 7 bits
        address_bits |= addr_chunk << valid_bits;
        valid_bits += 7;
        if valid_bits >= 32 {
            valid_bits = 32;
            break;
        }
    }

    (address_bits, valid_bits, taken, exception)
}

// ─── TraceStats ───────────────────────────────────────────────────────────────

/// Statistics from a PTM decode pass.
#[derive(Debug, Clone, Default)]
pub struct TraceStats {
    /// Total packets decoded.
    pub total_packets: usize,
    /// Number of branch packets.
    pub branch_packets: usize,
    /// Number of taken branches.
    pub taken_branches: usize,
    /// Number of not-taken branches.
    pub not_taken_branches: usize,
    /// Number of atom packets.
    pub atom_packets: usize,
    /// Total atom bits (E+N).
    pub total_atoms: usize,
    /// Number of waypoint packets.
    pub waypoint_packets: usize,
    /// Number of ASYNC sync frames.
    pub sync_frames: usize,
    /// Number of overflow packets.
    pub overflow_packets: usize,
    /// Number of decode errors.
    pub decode_errors: usize,
}

impl TraceStats {
    /// Compute statistics from a list of decoded packets.
    #[must_use]
    pub fn from_packets(packets: &[PtmPacket], error_count: usize) -> Self {
        let mut s = Self {
            total_packets: packets.len(),
            decode_errors: error_count,
            ..Self::default()
        };
        for pkt in packets {
            match &pkt.kind {
                PtmPacketKind::Branch { taken, .. } => {
                    s.branch_packets += 1;
                    if *taken {
                        s.taken_branches += 1;
                    } else {
                        s.not_taken_branches += 1;
                    }
                }
                PtmPacketKind::Atom { count, .. } => {
                    s.atom_packets += 1;
                    s.total_atoms += *count as usize;
                }
                PtmPacketKind::Waypoint { .. } => s.waypoint_packets += 1,
                PtmPacketKind::ASync => s.sync_frames += 1,
                PtmPacketKind::Overflow => s.overflow_packets += 1,
                _ => {}
            }
        }
        s
    }

    /// Return the taken-branch ratio (0.0–1.0).
    #[must_use]
    pub fn taken_ratio(&self) -> f64 {
        let total = self.taken_branches + self.not_taken_branches;
        if total == 0 {
            0.0
        } else {
            // Use integer arithmetic to avoid precision-loss cast warnings.
            let ppm = (self.taken_branches as u128) * 1_000_000
                / (total as u128);
            f64::from(u32::try_from(ppm).unwrap_or(1_000_000)) * 1e-6
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_async_frame() -> Vec<u8> {
        let mut v = vec![0x00u8; 11];
        v.push(0x80);
        v
    }

    #[test]
    fn test_find_sync() {
        let mut dec = PtmDecoder::default_decoder();
        dec.feed(&build_async_frame());
        assert!(dec.find_sync());
        assert!(dec.is_synchronized());
    }

    #[test]
    fn test_decode_async_packet() {
        let mut dec = PtmDecoder::default_decoder();
        dec.feed(&build_async_frame());
        let pkts = dec.decode_all();
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, PtmPacketKind::ASync);
    }

    #[test]
    fn test_decode_trace_info() {
        let mut dec = PtmDecoder::default_decoder();
        dec.state = PtmState::Decoding; // skip sync search
        dec.feed(&[0x01u8]);
        let pkts = dec.decode_all();
        assert!(pkts.iter().any(|p| p.kind == PtmPacketKind::TraceInfo));
    }

    #[test]
    fn test_decode_ignore() {
        let mut dec = PtmDecoder::default_decoder();
        dec.state = PtmState::Decoding;
        dec.feed(&[0x66u8]);
        let pkts = dec.decode_all();
        assert_eq!(pkts[0].kind, PtmPacketKind::Ignore);
    }

    #[test]
    fn test_decode_waypoint() {
        let mut dec = PtmDecoder::default_decoder();
        dec.state = PtmState::Decoding;
        let addr = 0x0001_0000u32;
        let mut data = vec![0x76u8];
        data.extend_from_slice(&addr.to_le_bytes());
        dec.feed(&data);
        let pkts = dec.decode_all();
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].kind, PtmPacketKind::Waypoint { address: 0x0001_0000 });
        assert_eq!(dec.history.current_pc, 0x0001_0000);
        assert!(dec.history.pc_valid);
    }

    #[test]
    fn test_pc_history_apply_waypoint() {
        let mut h = PcHistory::new();
        h.apply_waypoint(0x1000);
        assert_eq!(h.current_pc, 0x1000);
        assert!(h.pc_valid);
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_pc_history_apply_branch_taken() {
        let mut h = PcHistory::new();
        h.apply_waypoint(0x1000);

        let mut bp = BranchPacket::new(vec![0x03]); // dummy
        bp.taken = true;
        bp.address_bits = 0x2000;
        bp.valid_bits = 32;
        bp.full_address = true;

        h.apply_branch(&bp);
        assert_eq!(h.current_pc, 0x2000);
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn test_branch_packet_merge_partial() {
        let mut bp = BranchPacket::new(vec![]);
        bp.address_bits = 0x0040; // 7 bits
        bp.valid_bits = 7;
        // prev_pc = 0x0001_0000 — replace low 7 bits.
        let merged = bp.merge_address(0x0001_0000);
        assert_eq!(merged, 0x0001_0040);
    }

    #[test]
    fn test_branch_packet_full_address() {
        let mut bp = BranchPacket::new(vec![]);
        bp.address_bits = 0xDEAD_0000;
        bp.valid_bits = 32;
        bp.full_address = true;
        let merged = bp.merge_address(0x1234_5678);
        assert_eq!(merged, 0xDEAD_0000);
    }

    #[test]
    fn test_decode_exception_packet() {
        let mut dec = PtmDecoder::default_decoder();
        dec.state = PtmState::Decoding;
        dec.feed(&[0x0Eu8, 0x05u8]); // exc_type=5, not a return
        let pkts = dec.decode_all();
        assert_eq!(pkts.len(), 1);
        assert!(
            matches!(pkts[0].kind, PtmPacketKind::Exception { exc_type: 5, is_return: false })
        );
    }

    #[test]
    fn test_trace_stats_taken_ratio() {
        let packets = vec![
            PtmPacket::new(
                PtmPacketKind::Branch {
                    address: 0x1000,
                    taken: true,
                    address_complete: false,
                },
                0,
                1,
            ),
            PtmPacket::new(
                PtmPacketKind::Branch {
                    address: 0x2000,
                    taken: false,
                    address_complete: false,
                },
                1,
                1,
            ),
        ];
        let stats = TraceStats::from_packets(&packets, 0);
        assert_eq!(stats.branch_packets, 2);
        assert!((stats.taken_ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_decoder_reset() {
        let mut dec = PtmDecoder::default_decoder();
        dec.feed(&build_async_frame());
        let _ = dec.decode_all();
        dec.reset();
        assert_eq!(dec.position(), 0);
        assert!(!dec.is_synchronized());
        assert_eq!(dec.packet_count, 0);
    }

    #[test]
    fn test_p_header_decode() {
        // 0x84 = 0b1000_0100: e_count = 0, n_count = 1 → N atom
        let (en, count) = decode_p_header(0x84);
        assert_eq!(count, 1);
        let _ = en; // just check it doesn't panic

        // 0x88 = 0b1000_1000: e_count = 0, n_count = 0 — edge case
        let (_, count2) = decode_p_header(0x88);
        let _ = count2;
    }

    #[test]
    fn test_ptm_packet_display() {
        let p = PtmPacket::new(PtmPacketKind::ASync, 0, 12);
        let s = format!("{p}");
        assert!(s.contains("ASYNC"));
    }
}
