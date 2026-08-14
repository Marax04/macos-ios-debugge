//! `rustre-trace-coresight` — ARM `CoreSight` ETM trace decode engine.
//!
//! Full ETM4/ETE trace decode, PTM/ETM3 support, `CoreSight` topology
//! discovery via ROM tables, data trace, and trace filtering.

pub mod coresight_packets;
pub mod coresight_topology;
pub mod ptm_decoder;
pub mod cs_analysis;
pub mod etm_decoder;
pub mod etm_packets;
pub mod stm_decoder;
pub mod timestamp_decoder;
pub mod tpiu_sink;
pub mod trace_reconstructor;
pub mod ptt_trace_parser;
pub mod coresight_etm_decoder;
pub mod coresight_stm_decoder;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors from the `CoreSight` decoding subsystem.
#[derive(Debug, Error)]
pub enum CsError {
    /// Unknown or unsupported packet byte.
    #[error("invalid packet byte 0x{0:02x}")]
    InvalidPacket(u8),
    /// Truncated buffer — not enough bytes remain.
    #[error("truncated buffer")]
    TruncatedBuffer,
    /// Unknown format string.
    #[error("unknown format: {0}")]
    UnknownFormat(String),
    /// Synchronization lost.
    #[error("sync lost at offset 0x{0:x}")]
    SyncLost(usize),
    /// Unsupported ISA.
    #[error("unsupported ISA: {0}")]
    UnsupportedIsa(String),
    /// ROM table parse error.
    #[error("ROM table error: {0}")]
    RomTable(String),
    /// Data trace error.
    #[error("data trace error: {0}")]
    DataTrace(String),
}

// ─── ExceptionType ────────────────────────────────────────────────────────────

/// ARM exception types for ETM exception packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ExceptionType {
    /// Reset vector.
    Reset = 0,
    /// Undefined instruction.
    Undefined = 1,
    /// Supervisor call (SVC).
    Svc = 2,
    /// Prefetch abort.
    PrefetchAbort = 3,
    /// Data abort.
    DataAbort = 4,
    /// IRQ interrupt.
    Irq = 5,
    /// FIQ interrupt.
    Fiq = 6,
    /// Hypervisor call (HVC).
    Hvc = 7,
    /// Monitor call (SMC).
    Smc = 8,
    /// `SError`.
    SError = 9,
    /// Debug exception.
    Debug = 10,
    /// Unknown exception type.
    Unknown = 0xFF,
}

impl ExceptionType {
    /// Parse from the ETM exception type field.
    #[must_use]
    pub const fn from_etm_field(v: u8) -> Self {
        match v {
            0 => Self::Reset,
            1 => Self::Undefined,
            2 => Self::Svc,
            3 => Self::PrefetchAbort,
            4 => Self::DataAbort,
            5 => Self::Irq,
            6 => Self::Fiq,
            7 => Self::Hvc,
            8 => Self::Smc,
            9 => Self::SError,
            10 => Self::Debug,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for ExceptionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Reset => "Reset",
            Self::Undefined => "Undefined",
            Self::Svc => "SVC",
            Self::PrefetchAbort => "PrefetchAbort",
            Self::DataAbort => "DataAbort",
            Self::Irq => "IRQ",
            Self::Fiq => "FIQ",
            Self::Hvc => "HVC",
            Self::Smc => "SMC",
            Self::SError => "SError",
            Self::Debug => "Debug",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ─── ExceptionLevel ───────────────────────────────────────────────────────────

/// ARM exception level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ExceptionLevel {
    /// EL0 — unprivileged user mode.
    El0 = 0,
    /// EL1 — kernel mode.
    El1 = 1,
    /// EL2 — hypervisor mode.
    El2 = 2,
    /// EL3 — secure monitor mode.
    El3 = 3,
}

impl ExceptionLevel {
    /// Parse from a 2-bit field.
    #[must_use]
    pub fn from_bits(b: u8) -> Self {
        match b & 0b11 {
            0 => Self::El0,
            1 => Self::El1,
            2 => Self::El2,
            3 => Self::El3,
            _ => unreachable!(),
        }
    }

    /// Return the numeric level.
    #[must_use]
    pub const fn level(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for ExceptionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EL{}", self.level())
    }
}

// ─── IsaMode ──────────────────────────────────────────────────────────────────

/// ARM ISA mode tracked by the ETM decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IsaMode {
    /// `AArch64` A64 instructions.
    Aarch64,
    /// `AArch32` A32 (ARM) instructions.
    Arm,
    /// `AArch32` T32 (Thumb/Thumb-2) instructions.
    Thumb,
    /// `AArch32` T16 (16-bit Thumb) instructions.
    Thumb16,
    /// Jazelle/ThumbEE.
    Jazelle,
}

impl std::fmt::Display for IsaMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aarch64 => write!(f, "A64"),
            Self::Arm => write!(f, "A32"),
            Self::Thumb => write!(f, "T32"),
            Self::Thumb16 => write!(f, "T16"),
            Self::Jazelle => write!(f, "Jazelle"),
        }
    }
}

// ─── SecurityState ────────────────────────────────────────────────────────────

/// ARM security state (`TrustZone`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityState {
    /// Non-secure world.
    NonSecure,
    /// Secure world.
    Secure,
}

impl std::fmt::Display for SecurityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonSecure => write!(f, "NS"),
            Self::Secure => write!(f, "S"),
        }
    }
}

// ─── CsPacketKind ─────────────────────────────────────────────────────────────

/// The kind of a decoded `CoreSight` packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsPacketKind {
    /// Trace Info packet.
    TraceInfo,
    /// Trace On — tracing restarted.
    TraceOn,
    /// Trace Off — tracing suspended.
    TraceOff,
    /// Address packet.
    Address {
        /// The resolved address.
        addr: u64,
    },
    /// Atom packet — branch decisions.
    Atom {
        /// Whether the branch was taken.
        taken: bool,
        /// Number of valid atoms.
        count: u8,
    },
    /// Exception entry.
    Exception {
        /// Exception type code.
        exc_type: u16,
    },
    /// Timestamp.
    Timestamp(u64),
    /// Context ID.
    ContextId(u32),
    /// Virtual Machine ID.
    VmId(u32),
    /// Overflow packet.
    Overflow,
    /// Cycle count packet.
    CycleCount(u64),
    /// Synchronization packet (ASYNC).
    Sync,
    /// Ignore/pad packet.
    Ignore,
    /// Data trace address.
    DataAddress {
        /// Data address.
        addr: u64,
        /// Whether this is a write.
        is_write: bool,
    },
    /// Data trace value.
    DataValue {
        /// The value.
        value: u64,
        /// Size in bytes.
        size: u8,
    },
    /// Exception return.
    ExceptionReturn,
    /// Context packet — EL/NS fields from an `ETMv4` context update.
    Context {
        /// Exception level at the time of the context packet.
        el: Option<ExceptionLevel>,
        /// Non-secure bit.
        ns: bool,
    },
    /// Q element — speculative execution marker.
    QElement {
        /// Number of instructions in speculative window.
        count: u32,
    },
    /// Branch future packet.
    BranchFuture {
        /// Target address.
        target: u64,
    },
    /// Indirect branch packet.
    IndirectBranch {
        /// Target address.
        target: u64,
    },
}

impl std::fmt::Display for CsPacketKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TraceInfo => write!(f, "TraceInfo"),
            Self::TraceOn => write!(f, "TraceOn"),
            Self::TraceOff => write!(f, "TraceOff"),
            Self::Address { addr } => write!(f, "Address(0x{addr:x})"),
            Self::Atom { taken, count } => write!(f, "Atom(taken={taken}, count={count})"),
            Self::Exception { exc_type } => write!(f, "Exception(type=0x{exc_type:x})"),
            Self::Timestamp(ts) => write!(f, "Timestamp({ts})"),
            Self::ContextId(id) => write!(f, "ContextId(0x{id:x})"),
            Self::VmId(id) => write!(f, "VmId(0x{id:x})"),
            Self::Overflow => write!(f, "Overflow"),
            Self::CycleCount(c) => write!(f, "CycleCount({c})"),
            Self::Sync => write!(f, "Sync"),
            Self::Ignore => write!(f, "Ignore"),
            Self::DataAddress { addr, is_write } => {
                write!(f, "DataAddr(0x{addr:x}, write={is_write})")
            }
            Self::DataValue { value, size } => write!(f, "DataValue(0x{value:x}, {size}B)"),
            Self::ExceptionReturn => write!(f, "ExceptionReturn"),
            Self::Context { el, ns } => write!(f, "Context(el={el:?}, ns={ns})"),
            Self::QElement { count } => write!(f, "QElement({count})"),
            Self::BranchFuture { target } => write!(f, "BranchFuture(0x{target:x})"),
            Self::IndirectBranch { target } => write!(f, "IndirectBranch(0x{target:x})"),
        }
    }
}

// ─── CsPacket ─────────────────────────────────────────────────────────────────

/// A decoded `CoreSight` packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsPacket {
    /// The packet kind.
    pub kind: CsPacketKind,
    /// Byte offset in the stream where this packet starts.
    pub byte_offset: usize,
}

// ─── EtmVersion ───────────────────────────────────────────────────────────────

/// ETM protocol version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EtmVersion {
    /// ETM version 3.
    Etm3,
    /// ETM version 4.
    Etm4,
    /// ETM version 4.1.
    EtmV4p1,
    /// PTM (Program Trace Macrocell) used in Cortex-A5/A8/A9.
    Ptm,
    /// ETE (Embedded Trace Extension) for `ARMv9`.
    Ete,
}

impl std::fmt::Display for EtmVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Etm3 => write!(f, "ETMv3"),
            Self::Etm4 => write!(f, "ETMv4"),
            Self::EtmV4p1 => write!(f, "ETMv4.1"),
            Self::Ptm => write!(f, "PTM"),
            Self::Ete => write!(f, "ETE"),
        }
    }
}

// ─── EtmConfig ────────────────────────────────────────────────────────────────

/// Configuration for an ETM trace decoder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtmConfig {
    /// ETM protocol version.
    pub version: EtmVersion,
    /// Architecture string (e.g. `"arm64"`, `"arm"`).
    pub arch: String,
    /// Number of address comparators.
    pub addr_comparators: u8,
    /// Number of context ID comparators.
    pub context_id_comparators: u8,
    /// Whether data tracing is enabled.
    pub data_trace_enabled: bool,
    /// Whether cycle counting is enabled.
    pub cycle_counting: bool,
    /// Whether timestamp is enabled.
    pub timestamps: bool,
    /// Trace ID assigned to this ETM.
    pub trace_id: u8,
}

impl EtmConfig {
    /// Create a new [`EtmConfig`] with defaults.
    #[must_use]
    pub fn new(version: EtmVersion, arch: impl Into<String>) -> Self {
        Self {
            version,
            arch: arch.into(),
            addr_comparators: 4,
            context_id_comparators: 1,
            data_trace_enabled: false,
            cycle_counting: false,
            timestamps: true,
            trace_id: 0x10,
        }
    }

    /// Enable data tracing.
    #[must_use]
    pub const fn with_data_trace(mut self) -> Self {
        self.data_trace_enabled = true;
        self
    }

    /// Enable cycle counting.
    #[must_use]
    pub const fn with_cycle_count(mut self) -> Self {
        self.cycle_counting = true;
        self
    }
}

// ─── EtmContext ───────────────────────────────────────────────────────────────

/// Decoder state context for ETM4/ETE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtmContext {
    /// Current ISA mode.
    pub isa: IsaMode,
    /// Current security state.
    pub security: SecurityState,
    /// Current exception level.
    pub el: ExceptionLevel,
    /// Current traced address.
    pub current_addr: u64,
    /// Current context ID.
    pub context_id: u32,
    /// Current VMID.
    pub vmid: u32,
    /// Whether we are in a speculative region.
    pub speculative: bool,
    /// Whether the address is valid (we have a known address).
    pub addr_valid: bool,
    /// Last timestamp value.
    pub timestamp: u64,
    /// Last cycle count.
    pub cycle_count: u64,
}

impl Default for EtmContext {
    fn default() -> Self {
        Self {
            isa: IsaMode::Aarch64,
            security: SecurityState::NonSecure,
            el: ExceptionLevel::El0,
            current_addr: 0,
            context_id: 0,
            vmid: 0,
            speculative: false,
            addr_valid: false,
            timestamp: 0,
            cycle_count: 0,
        }
    }
}

impl EtmContext {
    /// Create a default context for `AArch64`.
    #[must_use]
    pub fn new_aarch64() -> Self {
        Self {
            isa: IsaMode::Aarch64,
            ..Self::default()
        }
    }

    /// Apply an address update.
    pub const fn apply_address(&mut self, addr: u64) {
        self.current_addr = addr;
        self.addr_valid = true;
    }

    /// Apply a context packet.
    pub const fn apply_context(&mut self, el: ExceptionLevel, ns: bool) {
        self.el = el;
        self.security = if ns {
            SecurityState::NonSecure
        } else {
            SecurityState::Secure
        };
    }

    /// Advance address by `n` bytes (instruction width).
    pub const fn advance(&mut self, n: u64) {
        if self.addr_valid {
            self.current_addr = self.current_addr.wrapping_add(n);
        }
    }
}

// ─── EtmAddressUpdate ─────────────────────────────────────────────────────────

/// An ETM address update packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtmAddressUpdate {
    /// The new address.
    pub address: u64,
    /// Whether this is a full address or a partial update.
    pub is_full: bool,
    /// Number of bytes of the update that are valid (1-8).
    pub bytes_valid: u8,
    /// Exception level hint (if present).
    pub el_hint: Option<ExceptionLevel>,
}

impl EtmAddressUpdate {
    /// Create a full 64-bit address update.
    #[must_use]
    pub const fn full(address: u64) -> Self {
        Self {
            address,
            is_full: true,
            bytes_valid: 8,
            el_hint: None,
        }
    }

    /// Create a partial address update.
    #[must_use]
    pub const fn partial(address: u64, bytes: u8) -> Self {
        Self {
            address,
            is_full: false,
            bytes_valid: bytes,
            el_hint: None,
        }
    }
}

// ─── EtmTimestamp ─────────────────────────────────────────────────────────────

/// An ETM timestamp counter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EtmTimestamp {
    /// Raw 64-bit counter value.
    pub value: u64,
}

impl EtmTimestamp {
    /// Create a new timestamp.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self { value }
    }

    /// Return the delta from another timestamp.
    #[must_use]
    pub const fn delta_from(self, other: Self) -> u64 {
        self.value.wrapping_sub(other.value)
    }
}

impl std::fmt::Display for EtmTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ts:{}", self.value)
    }
}

// ─── AtomPacket ───────────────────────────────────────────────────────────────

/// Low-level atom packet carrying E/N (Executed/Not-taken) bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomPacket {
    /// The raw E/N bits (bit N = 1 means taken).
    pub en_bits: u32,
    /// Number of valid bits in `en_bits`.
    pub count: u8,
    /// Byte offset in original stream.
    pub byte_offset: usize,
}

impl AtomPacket {
    /// Create a new atom packet.
    #[must_use]
    pub const fn new(en_bits: u32, count: u8, byte_offset: usize) -> Self {
        Self {
            en_bits,
            count,
            byte_offset,
        }
    }

    /// Return whether branch `idx` was taken.
    #[must_use]
    pub const fn is_taken(&self, idx: u8) -> bool {
        if idx >= self.count {
            return false;
        }
        (self.en_bits >> idx) & 1 == 1
    }

    /// Return a vector of booleans for each atom.
    #[must_use]
    pub fn to_vec(&self) -> Vec<bool> {
        (0..self.count).map(|i| self.is_taken(i)).collect()
    }
}

// ─── ExceptionPacket ──────────────────────────────────────────────────────────

/// ETM exception packet carrying type and level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionPacket {
    /// Exception type.
    pub exc_type: ExceptionType,
    /// Exception level.
    pub level: ExceptionLevel,
    /// Whether this is a previous EL exception.
    pub previous_el: bool,
    /// Exception address (target of the exception handler).
    pub target_addr: Option<u64>,
    /// Byte offset in original stream.
    pub byte_offset: usize,
}

impl ExceptionPacket {
    /// Create an exception packet.
    #[must_use]
    pub const fn new(exc_type: ExceptionType, level: ExceptionLevel, byte_offset: usize) -> Self {
        Self {
            exc_type,
            level,
            previous_el: false,
            target_addr: None,
            byte_offset,
        }
    }
}

// ─── DataTracePacket ──────────────────────────────────────────────────────────

/// Data trace packet carrying address and value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTracePacket {
    /// Data address accessed.
    pub address: u64,
    /// Data value (if available).
    pub value: Option<u64>,
    /// Size of access in bytes.
    pub size: u8,
    /// Whether this is a write (vs read).
    pub is_write: bool,
    /// Byte offset in original stream.
    pub byte_offset: usize,
}

impl DataTracePacket {
    /// Create a new data trace packet.
    #[must_use]
    pub const fn new(address: u64, size: u8, is_write: bool, byte_offset: usize) -> Self {
        Self {
            address,
            value: None,
            size,
            is_write,
            byte_offset,
        }
    }

    /// Attach a data value.
    #[must_use]
    pub const fn with_value(mut self, value: u64) -> Self {
        self.value = Some(value);
        self
    }
}

// ─── CoreSightDecoder ─────────────────────────────────────────────────────────

/// Full ETM4/ETE trace decode engine.
pub struct CoreSightDecoder {
    /// Decoder configuration.
    pub config: EtmConfig,
    /// Internal byte buffer.
    buf: Vec<u8>,
    /// Current read position.
    pos: usize,
    /// Decoder context state.
    pub context: EtmContext,
    /// Accumulated atom packets.
    pub atoms: Vec<AtomPacket>,
    /// Exception packets.
    pub exceptions: Vec<ExceptionPacket>,
    /// Data trace packets.
    pub data_trace: Vec<DataTracePacket>,
    /// Whether we are synchronized.
    synchronized: bool,
}

impl CoreSightDecoder {
    /// Create a new decoder with the given config.
    #[must_use]
    pub fn new(config: EtmConfig) -> Self {
        Self {
            config,
            buf: Vec::new(),
            pos: 0,
            context: EtmContext::default(),
            atoms: Vec::new(),
            exceptions: Vec::new(),
            data_trace: Vec::new(),
            synchronized: false,
        }
    }

    /// Feed more bytes into the decoder.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Peek at the next byte without consuming.
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Consume the next byte.
    fn consume(&mut self) -> Option<u8> {
        let b = self.buf.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    /// Consume `n` bytes.
    fn consume_bytes(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let slice = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Some(slice)
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
            if shift >= 64 {
                return None;
            }
        }
        Some(result)
    }

    /// Try to find the next ASYNC sync packet.
    pub fn find_sync(&mut self) -> bool {
        let sync_pattern = [0x00u8; 11];
        // Look for 11 zero bytes followed by 0x80
        let start_pos = self.pos;
        while self.pos + 12 <= self.buf.len() {
            if self.buf[self.pos..self.pos + 11] == sync_pattern && self.buf[self.pos + 11] == 0x80
            {
                self.pos += 12;
                self.synchronized = true;
                return true;
            }
            self.pos += 1;
        }
        self.pos = start_pos;
        false
    }

    /// Try to decode the next packet from the buffer.
    pub fn next_packet(&mut self) -> Option<CsPacket> {
        // Look ahead at the header byte without consuming, so we can bail out
        // cleanly when the buffer is exhausted.
        let b = self.peek()?;
        let start = self.pos;
        self.pos += 1;

        match b {
            0x00 => Some(self.decode_atom_packet(false, start)),
            0x01 => Some(CsPacket { kind: CsPacketKind::TraceInfo, byte_offset: start }),
            0x04 => Some(self.decode_atom_packet(true, start)),
            0x05 => { self.synchronized = true; Some(CsPacket { kind: CsPacketKind::TraceOn, byte_offset: start }) }
            0x06 => Some(CsPacket { kind: CsPacketKind::TraceOff, byte_offset: start }),
            0x07 => Some(CsPacket { kind: CsPacketKind::ExceptionReturn, byte_offset: start }),
            0x08 => self.decode_exception_packet(start),
            0x0D => {
                let count = self.read_uleb128().unwrap_or(0);
                self.context.cycle_count = self.context.cycle_count.wrapping_add(count);
                Some(CsPacket { kind: CsPacketKind::CycleCount(count), byte_offset: start })
            }
            0x0E => self.decode_context_packet(start),
            0x43 => self.decode_timestamp_packet(start),
            0x50 => self.decode_context_id_packet(start),
            0x51 => self.decode_vmid_packet(start),
            0x80 => { self.synchronized = true; Some(CsPacket { kind: CsPacketKind::Sync, byte_offset: start }) }
            0x9A => self.decode_addr32_packet(start),
            0x9B => self.decode_addr64_packet(start),
            0xAA => self.decode_indirect_branch_packet(start),
            _ => Some(CsPacket { kind: CsPacketKind::Overflow, byte_offset: start }),
        }
    }

    fn decode_atom_packet(&mut self, taken: bool, start: usize) -> CsPacket {
        let pattern = u32::from(taken);
        let pkt = AtomPacket::new(pattern, 1, start);
        self.atoms.push(pkt);
        CsPacket { kind: CsPacketKind::Atom { taken, count: 1 }, byte_offset: start }
    }

    fn decode_exception_packet(&mut self, start: usize) -> Option<CsPacket> {
        if self.pos + 2 > self.buf.len() {
            self.pos = start;
            return None;
        }
        let type_byte = self.buf[self.pos];
        self.pos += 1;
        let level_byte = self.buf[self.pos];
        self.pos += 1;
        let exc_type_val = type_byte & 0x1F;
        let level = ExceptionLevel::from_bits(level_byte & 0b11);
        let exc_type = ExceptionType::from_etm_field(exc_type_val);
        let pkt = ExceptionPacket::new(exc_type, level, start);
        let exc_code = u16::from(type_byte);
        self.exceptions.push(pkt);
        Some(CsPacket { kind: CsPacketKind::Exception { exc_type: exc_code }, byte_offset: start })
    }

    fn decode_context_packet(&mut self, start: usize) -> Option<CsPacket> {
        if self.pos >= self.buf.len() {
            self.pos = start;
            return None;
        }
        let ctx_byte = self.buf[self.pos];
        self.pos += 1;
        let el = ExceptionLevel::from_bits((ctx_byte >> 1) & 0b11);
        let ns = ctx_byte & 1 != 0;
        self.context.apply_context(el, ns);
        Some(CsPacket { kind: CsPacketKind::Context { el: Some(el), ns }, byte_offset: start })
    }

    fn decode_timestamp_packet(&mut self, start: usize) -> Option<CsPacket> {
        let Some(bytes) = self.consume_bytes(8) else {
            self.pos = start;
            return None;
        };
        let ts = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        self.context.timestamp = ts;
        Some(CsPacket { kind: CsPacketKind::Timestamp(ts), byte_offset: start })
    }

    fn decode_context_id_packet(&mut self, start: usize) -> Option<CsPacket> {
        if self.pos + 4 > self.buf.len() {
            self.pos = start;
            return None;
        }
        let id = u32::from_le_bytes([
            self.buf[self.pos], self.buf[self.pos + 1],
            self.buf[self.pos + 2], self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        self.context.context_id = id;
        Some(CsPacket { kind: CsPacketKind::ContextId(id), byte_offset: start })
    }

    fn decode_vmid_packet(&mut self, start: usize) -> Option<CsPacket> {
        if self.pos + 4 > self.buf.len() {
            self.pos = start;
            return None;
        }
        let id = u32::from_le_bytes([
            self.buf[self.pos], self.buf[self.pos + 1],
            self.buf[self.pos + 2], self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        self.context.vmid = id;
        Some(CsPacket { kind: CsPacketKind::VmId(id), byte_offset: start })
    }

    fn decode_addr32_packet(&mut self, start: usize) -> Option<CsPacket> {
        if self.pos + 4 > self.buf.len() {
            self.pos = start;
            return None;
        }
        let addr = u64::from(u32::from_le_bytes([
            self.buf[self.pos], self.buf[self.pos + 1],
            self.buf[self.pos + 2], self.buf[self.pos + 3],
        ]));
        self.pos += 4;
        self.context.apply_address(addr);
        Some(CsPacket { kind: CsPacketKind::Address { addr }, byte_offset: start })
    }

    fn decode_addr64_packet(&mut self, start: usize) -> Option<CsPacket> {
        if self.pos + 8 > self.buf.len() {
            self.pos = start;
            return None;
        }
        let addr = u64::from_le_bytes([
            self.buf[self.pos], self.buf[self.pos + 1], self.buf[self.pos + 2], self.buf[self.pos + 3],
            self.buf[self.pos + 4], self.buf[self.pos + 5], self.buf[self.pos + 6], self.buf[self.pos + 7],
        ]);
        self.pos += 8;
        self.context.apply_address(addr);
        Some(CsPacket { kind: CsPacketKind::Address { addr }, byte_offset: start })
    }

    fn decode_indirect_branch_packet(&mut self, start: usize) -> Option<CsPacket> {
        if self.pos + 8 > self.buf.len() {
            self.pos = start;
            return None;
        }
        let target = u64::from_le_bytes([
            self.buf[self.pos], self.buf[self.pos + 1], self.buf[self.pos + 2], self.buf[self.pos + 3],
            self.buf[self.pos + 4], self.buf[self.pos + 5], self.buf[self.pos + 6], self.buf[self.pos + 7],
        ]);
        self.pos += 8;
        Some(CsPacket { kind: CsPacketKind::IndirectBranch { target }, byte_offset: start })
    }

    /// Decode all remaining packets.
    #[must_use]
    pub fn decode_all(&mut self) -> Vec<CsPacket> {
        let mut out = Vec::new();
        while let Some(pkt) = self.next_packet() {
            out.push(pkt);
        }
        out
    }

    /// Return the current decoder position.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Reset the decoder position.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.context = EtmContext::default();
        self.synchronized = false;
    }

    /// Return whether the decoder is synchronized.
    #[must_use]
    pub const fn is_synchronized(&self) -> bool {
        self.synchronized
    }
}

// ─── CsDecoder (legacy compat) ────────────────────────────────────────────────

/// Stateful `CoreSight` ETM packet decoder (legacy compatibility wrapper).
pub struct CsDecoder {
    /// Internal byte buffer.
    pub buf: Vec<u8>,
    /// Current read position.
    pub pos: usize,
    /// Decoder configuration.
    pub config: EtmConfig,
}

impl CsDecoder {
    /// Create a new decoder with the given config.
    #[must_use]
    pub const fn new(config: EtmConfig) -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            config,
        }
    }

    /// Feed more bytes into the decoder.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Try to decode the next packet from the buffer.
    pub fn next_packet(&mut self) -> Option<CsPacket> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let start = self.pos;
        let b = self.buf[self.pos];
        self.pos += 1;

        match b {
            0x00 => Some(CsPacket {
                kind: CsPacketKind::Atom {
                    taken: false,
                    count: 1,
                },
                byte_offset: start,
            }),
            0x01 => Some(CsPacket {
                kind: CsPacketKind::TraceInfo,
                byte_offset: start,
            }),
            0x04 => Some(CsPacket {
                kind: CsPacketKind::Atom {
                    taken: true,
                    count: 1,
                },
                byte_offset: start,
            }),
            0x05 => Some(CsPacket {
                kind: CsPacketKind::TraceOn,
                byte_offset: start,
            }),
            0x06 => Some(CsPacket {
                kind: CsPacketKind::TraceOff,
                byte_offset: start,
            }),
            0x43 => {
                if self.pos + 8 > self.buf.len() {
                    self.pos = start;
                    return None;
                }
                let ts = u64::from_le_bytes([
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
                Some(CsPacket {
                    kind: CsPacketKind::Timestamp(ts),
                    byte_offset: start,
                })
            }
            0x9A => {
                if self.pos + 4 > self.buf.len() {
                    self.pos = start;
                    return None;
                }
                let addr = u64::from(u32::from_le_bytes([
                    self.buf[self.pos],
                    self.buf[self.pos + 1],
                    self.buf[self.pos + 2],
                    self.buf[self.pos + 3],
                ]));
                self.pos += 4;
                Some(CsPacket {
                    kind: CsPacketKind::Address { addr },
                    byte_offset: start,
                })
            }
            _ => Some(CsPacket {
                kind: CsPacketKind::Overflow,
                byte_offset: start,
            }),
        }
    }

    /// Decode all remaining packets.
    #[must_use]
    pub fn decode_all(&mut self) -> Vec<CsPacket> {
        let mut out = Vec::new();
        while let Some(pkt) = self.next_packet() {
            out.push(pkt);
        }
        out
    }
}

// ─── EtmTrace ─────────────────────────────────────────────────────────────────

/// A decoded ETM trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtmTrace {
    /// All decoded packets.
    pub packets: Vec<CsPacket>,
    /// Configuration used for decoding.
    pub config: EtmConfig,
}

impl EtmTrace {
    /// Return all instruction addresses from `Address` packets.
    #[must_use]
    pub fn instruction_addresses(&self) -> Vec<u64> {
        self.packets
            .iter()
            .filter_map(|p| {
                if let CsPacketKind::Address { addr } = p.kind {
                    Some(addr)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return the number of `Atom` packets.
    #[must_use]
    pub fn atom_count(&self) -> usize {
        self.packets
            .iter()
            .filter(|p| matches!(p.kind, CsPacketKind::Atom { .. }))
            .count()
    }

    /// Return the number of taken atoms.
    #[must_use]
    pub fn taken_atoms(&self) -> usize {
        self.packets
            .iter()
            .filter(|p| matches!(p.kind, CsPacketKind::Atom { taken: true, .. }))
            .count()
    }

    /// Return the number of not-taken atoms.
    #[must_use]
    pub fn not_taken_atoms(&self) -> usize {
        self.packets
            .iter()
            .filter(|p| matches!(p.kind, CsPacketKind::Atom { taken: false, .. }))
            .count()
    }

    /// Return the number of exception packets.
    #[must_use]
    pub fn exception_count(&self) -> usize {
        self.packets
            .iter()
            .filter(|p| matches!(p.kind, CsPacketKind::Exception { .. }))
            .count()
    }

    /// Return the most recent timestamp.
    #[must_use]
    pub fn last_timestamp(&self) -> Option<u64> {
        self.packets.iter().rev().find_map(|p| {
            if let CsPacketKind::Timestamp(ts) = p.kind {
                Some(ts)
            } else {
                None
            }
        })
    }
}

// ─── PtmDecoder ───────────────────────────────────────────────────────────────

/// PTM (Program Trace Macrocell) decoder for Cortex-A5/A8/A9.
pub struct PtmDecoder {
    /// Decoder config (must be PTM version).
    pub config: EtmConfig,
    buf: Vec<u8>,
    pos: usize,
    /// Last decoded address.
    pub last_addr: u64,
    /// Atom queue.
    pub atom_queue: VecDeque<bool>,
}

impl PtmDecoder {
    /// Create a new PTM decoder.
    #[must_use]
    pub fn new() -> Self {
        let config = EtmConfig::new(EtmVersion::Ptm, "arm");
        Self {
            config,
            buf: Vec::new(),
            pos: 0,
            last_addr: 0,
            atom_queue: VecDeque::new(),
        }
    }

    /// Feed bytes into the decoder.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Decode the next PTM packet.
    pub fn next_packet(&mut self) -> Option<CsPacket> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let start = self.pos;
        let b = self.buf[self.pos];
        self.pos += 1;

        // PTM packet formats
        match b {
            // Branch with address
            x if x & 0x01 == 1 => {
                // Branch packet with embedded address bits
                let taken = x & 0x02 != 0;
                self.atom_queue.push_back(taken);
                Some(CsPacket {
                    kind: CsPacketKind::Atom { taken, count: 1 },
                    byte_offset: start,
                })
            }
            // A-sync
            0x00 => {
                // Look for ASYNC
                Some(CsPacket {
                    kind: CsPacketKind::Sync,
                    byte_offset: start,
                })
            }
            // CycleCount
            0x12 => Some(CsPacket {
                kind: CsPacketKind::CycleCount(1),
                byte_offset: start,
            }),
            _ => Some(CsPacket {
                kind: CsPacketKind::Overflow,
                byte_offset: start,
            }),
        }
    }

    /// Return the next atom from the queue.
    pub fn next_atom(&mut self) -> Option<bool> {
        self.atom_queue.pop_front()
    }
}

impl Default for PtmDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Etm3Decoder ──────────────────────────────────────────────────────────────

/// ETM3 decoder for older ARM cores (pre-Cortex-A15).
pub struct Etm3Decoder {
    /// Decoder config.
    pub config: EtmConfig,
    buf: Vec<u8>,
    pos: usize,
    /// Context ID bits.
    pub context_id: u32,
    /// Last address.
    pub last_addr: u64,
}

impl Etm3Decoder {
    /// Create a new ETM3 decoder.
    #[must_use]
    pub fn new() -> Self {
        let config = EtmConfig::new(EtmVersion::Etm3, "arm");
        Self {
            config,
            buf: Vec::new(),
            pos: 0,
            context_id: 0,
            last_addr: 0,
        }
    }

    /// Feed bytes into the decoder.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Decode the next ETM3 packet.
    pub fn next_packet(&mut self) -> Option<CsPacket> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let start = self.pos;
        let b = self.buf[self.pos];
        self.pos += 1;

        // ETM3 packet encoding
        match b {
            // Trace Out of Order / Trace On
            0x05 | 0x08 => Some(CsPacket {
                kind: CsPacketKind::TraceOn,
                byte_offset: start,
            }),
            // Branch
            x if x & 0x01 == 1 => {
                let taken = x & 0x04 != 0;
                Some(CsPacket {
                    kind: CsPacketKind::Atom { taken, count: 1 },
                    byte_offset: start,
                })
            }
            // Atom
            0x10..=0x1F => {
                // ETM3 P-header encoding
                let taken = (b & 0x04) != 0;
                Some(CsPacket {
                    kind: CsPacketKind::Atom { taken, count: 1 },
                    byte_offset: start,
                })
            }
            _ => Some(CsPacket {
                kind: CsPacketKind::Overflow,
                byte_offset: start,
            }),
        }
    }
}

impl Default for Etm3Decoder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── EteDecoder ───────────────────────────────────────────────────────────────

/// ETE (Embedded Trace Extension) decoder for `ARMv9`.
pub struct EteDecoder {
    /// Configuration.
    pub config: EtmConfig,
    inner: CoreSightDecoder,
    /// ETE-specific: whether we're in a branch table context.
    pub in_branch_table: bool,
}

impl EteDecoder {
    /// Create a new ETE decoder.
    #[must_use]
    pub fn new() -> Self {
        let config = EtmConfig::new(EtmVersion::Ete, "arm64");
        let inner = CoreSightDecoder::new(config.clone());
        Self {
            config,
            inner,
            in_branch_table: false,
        }
    }

    /// Feed bytes.
    pub fn feed(&mut self, data: &[u8]) {
        self.inner.feed(data);
    }

    /// Decode next packet.
    pub fn next_packet(&mut self) -> Option<CsPacket> {
        self.inner.next_packet()
    }

    /// Decode all packets.
    #[must_use]
    pub fn decode_all(&mut self) -> Vec<CsPacket> {
        self.inner.decode_all()
    }
}

impl Default for EteDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CoreSightSynchronization ─────────────────────────────────────────────────

/// Finds synchronization packets in a raw `CoreSight` stream.
pub struct CoreSightSynchronization;

impl CoreSightSynchronization {
    /// Scan `data` and return offsets of ASYNC sync frames.
    #[must_use]
    pub fn find_sync_offsets(data: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        let sync_pattern = [0x00u8; 11];
        if data.len() < 12 {
            return offsets;
        }
        for i in 0..data.len() - 11 {
            if data[i..i + 11] == sync_pattern && data[i + 11] == 0x80 {
                offsets.push(i);
            }
        }
        offsets
    }

    /// Return `true` if the stream appears to be a valid `CoreSight` trace.
    #[must_use]
    pub fn is_valid_stream(data: &[u8]) -> bool {
        // Avoid allocating the full offsets Vec; short-circuit on first match.
        if data.len() < 12 {
            return false;
        }
        let sync_pattern = [0x00u8; 11];
        (0..data.len() - 11)
            .any(|i| data[i..i + 11] == sync_pattern && data[i + 11] == 0x80)
    }
}

// ─── CoreSightTracePort ───────────────────────────────────────────────────────

/// Trace port configuration for `CoreSight`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreSightTracePort {
    /// Port width in bits (4, 8, 16, 32).
    pub width: u8,
    /// Port frequency in Hz.
    pub frequency_hz: u64,
    /// Port mode: TPIU/ETF/ETB.
    pub mode: TracePortMode,
    /// Whether DDR (double data rate) is enabled.
    pub ddr: bool,
}

/// Trace port operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TracePortMode {
    /// Trace Port Interface Unit — external trace capture.
    Tpiu,
    /// Embedded Trace FIFO — internal buffering.
    Etf,
    /// Embedded Trace Buffer — circular buffer.
    Etb,
    /// System Memory (ETF streaming to DDR).
    SysMemory,
}

impl CoreSightTracePort {
    /// Create a default TPIU configuration.
    #[must_use]
    pub const fn new_tpiu(width: u8, frequency_hz: u64) -> Self {
        Self {
            width,
            frequency_hz,
            mode: TracePortMode::Tpiu,
            ddr: false,
        }
    }

    /// Create an ETB configuration.
    #[must_use]
    pub const fn new_etb() -> Self {
        Self {
            width: 32,
            frequency_hz: 0,
            mode: TracePortMode::Etb,
            ddr: false,
        }
    }
}

// ─── EmbeddedTraceBuffer ──────────────────────────────────────────────────────

/// ETB — on-chip trace buffer.
pub struct EmbeddedTraceBuffer {
    /// Buffer capacity in bytes.
    pub capacity: usize,
    /// Stored trace data.
    data: Vec<u8>,
    /// Read pointer.
    read_ptr: usize,
    /// Whether the buffer has wrapped around.
    pub wrapped: bool,
}

impl EmbeddedTraceBuffer {
    /// Create a new ETB with given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            data: Vec::with_capacity(capacity),
            read_ptr: 0,
            wrapped: false,
        }
    }

    /// Write trace data into the ETB (simulating hardware DMA).
    pub fn write(&mut self, bytes: &[u8]) {
        if self.data.len() + bytes.len() > self.capacity {
            // Simulate wrap-around: keep last `capacity` bytes
            self.data.extend_from_slice(bytes);
            let overflow = self.data.len().saturating_sub(self.capacity);
            if overflow > 0 {
                self.data.drain(..overflow);
                self.wrapped = true;
            }
        } else {
            self.data.extend_from_slice(bytes);
        }
    }

    /// Read all available trace data.
    #[must_use]
    pub fn read_all(&self) -> &[u8] {
        &self.data
    }

    /// Return amount of data stored.
    #[must_use]
    pub const fn stored_bytes(&self) -> usize {
        self.data.len()
    }

    /// Return whether the buffer is full.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.data.len() >= self.capacity
    }

    /// Reset the buffer.
    pub fn reset(&mut self) {
        self.data.clear();
        self.read_ptr = 0;
        self.wrapped = false;
    }

    /// Step the read pointer forward.
    pub fn advance_read(&mut self, n: usize) {
        self.read_ptr = (self.read_ptr + n).min(self.data.len());
    }

    /// Read `n` bytes from the read pointer.
    #[must_use]
    pub fn read_bytes(&self, n: usize) -> &[u8] {
        let end = (self.read_ptr + n).min(self.data.len());
        &self.data[self.read_ptr..end]
    }
}

// ─── TraceMemoryInterface ─────────────────────────────────────────────────────

/// TMI — interface for capturing trace data from memory.
pub struct TraceMemoryInterface {
    /// Base address of the TMI buffer in physical memory.
    pub base_addr: u64,
    /// Buffer size.
    pub size: usize,
    /// Current write pointer.
    pub write_ptr: u64,
    /// Current read pointer.
    pub read_ptr: u64,
    /// Captured trace bytes.
    pub data: Vec<u8>,
}

impl TraceMemoryInterface {
    /// Create a new TMI at the given physical base.
    #[must_use]
    pub const fn new(base_addr: u64, size: usize) -> Self {
        Self {
            base_addr,
            size,
            write_ptr: base_addr,
            read_ptr: base_addr,
            data: Vec::new(),
        }
    }

    /// Simulate receiving trace data into the TMI buffer.
    ///
    /// Note: `write_ptr` is tracked as a `u64`; on 32-bit hosts where
    /// `data.len()` could theoretically exceed 4 GiB, a saturating add
    /// prevents silent pointer wrap-around that would corrupt `has_data()`.
    pub fn receive(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
        self.write_ptr = self.base_addr.saturating_add(self.data.len() as u64);
    }

    /// Return whether there is unread data.
    #[must_use]
    pub const fn has_data(&self) -> bool {
        self.read_ptr < self.write_ptr
    }

    /// Drain all available trace data.
    #[must_use]
    pub fn drain(&mut self) -> Vec<u8> {
        let data = self.data.clone();
        self.data.clear();
        self.read_ptr = self.write_ptr;
        data
    }
}

// ─── RomTableEntry ────────────────────────────────────────────────────────────

/// A single entry in a `CoreSight` ROM table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RomTableEntry {
    /// Component base address.
    pub base_addr: u64,
    /// Component class.
    pub component_class: u8,
    /// Part number.
    pub part_number: u16,
    /// Component description.
    pub description: String,
    /// Whether this entry is present.
    pub present: bool,
}

impl RomTableEntry {
    /// Create a ROM table entry.
    #[must_use]
    pub fn new(base_addr: u64, component_class: u8, part_number: u16) -> Self {
        Self {
            base_addr,
            component_class,
            part_number,
            description: format!("0x{part_number:04x}"),
            present: true,
        }
    }

    /// Return `true` if this is an ETM component.
    #[must_use]
    pub const fn is_etm(&self) -> bool {
        // ETM part numbers: 0x9A0 (Cortex-A5 ETM), 0x9D0 (Cortex-A7 ETM), etc.
        matches!(
            self.part_number,
            0x9A0 | 0x9D0 | 0x950 | 0x955 | 0x95A | 0x95B | 0x95D | 0x95F
        )
    }

    /// Return `true` if this is a CTI component.
    #[must_use]
    pub const fn is_cti(&self) -> bool {
        matches!(self.part_number, 0x906 | 0x9EE)
    }
}

// ─── RomTable ─────────────────────────────────────────────────────────────────

/// `CoreSight` ROM table parser.
pub struct RomTable {
    /// All discovered entries.
    pub entries: Vec<RomTableEntry>,
    /// Base address of this ROM table.
    pub base_addr: u64,
}

impl RomTable {
    /// Create an empty ROM table at `base_addr`.
    #[must_use]
    pub const fn new(base_addr: u64) -> Self {
        Self {
            entries: Vec::new(),
            base_addr,
        }
    }

    /// Parse a ROM table from raw 32-bit register data.
    ///
    /// `regs` contains the ROM table entries (each 32-bit word, one per
    /// component slot).  `pidr_regs` is a parallel slice of the same length:
    /// each element holds the raw PIDR0/PIDR1 bytes for that component,
    /// packed as `(PIDR1 & 0x0F) << 8 | PIDR0` — i.e. the 12-bit part
    /// number from the `CoreSight` PIDR0 (bits[7:0]) and PIDR1 (bits[3:0])
    /// registers at offsets 0xFE0/0xFE4 from the component base address.
    /// If `pidr_regs` is shorter than `regs` the missing entries are treated
    /// as part number 0.
    pub fn parse_entries(&mut self, base_addr: u64, regs: &[u32], pidr_regs: &[u16]) {
        for (i, &reg) in regs.iter().enumerate() {
            if reg == 0 {
                break;
            } // End of table
            let present = reg & 1 != 0;
            if present {
                let offset = (reg & 0xFFFF_F000).cast_signed();
                let component_addr = (base_addr.cast_signed() + i64::from(offset)).cast_unsigned();
                // Read the real 12-bit part number from the PIDR registers
                // provided by the caller (read at offsets 0xFE0 and 0xFE4
                // from the component base).  Fall back to 0 when not supplied.
                let part_number = pidr_regs.get(i).copied().unwrap_or(0);
                let entry = RomTableEntry {
                    base_addr: component_addr,
                    component_class: ((reg >> 4) & 0xF) as u8,
                    part_number,
                    description: format!(
                        "Component at 0x{component_addr:x} (part 0x{part_number:03x})"
                    ),
                    present,
                };
                self.entries.push(entry);
            }
        }
    }

    /// Find all ETM entries.
    #[must_use]
    pub fn etm_entries(&self) -> Vec<&RomTableEntry> {
        self.entries.iter().filter(|e| e.is_etm()).collect()
    }

    /// Return the total number of entries.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ─── CoreSightTopology ────────────────────────────────────────────────────────

/// Discovered `CoreSight` topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreSightTopology {
    /// ROM table entries (component list).
    pub components: Vec<RomTableEntry>,
    /// Number of ETM sources detected.
    pub etm_count: usize,
    /// Number of CTI components detected.
    pub cti_count: usize,
    /// Whether a funnel is present.
    pub has_funnel: bool,
    /// Whether an ETF/ETB is present.
    pub has_etf: bool,
}

impl CoreSightTopology {
    /// Create an empty topology.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            components: Vec::new(),
            etm_count: 0,
            cti_count: 0,
            has_funnel: false,
            has_etf: false,
        }
    }

    /// Add a component.
    pub fn add_component(&mut self, entry: RomTableEntry) {
        if entry.is_etm() {
            self.etm_count += 1;
        }
        if entry.is_cti() {
            self.cti_count += 1;
        }
        self.components.push(entry);
    }

    /// Return all component base addresses.
    #[must_use]
    pub fn component_addresses(&self) -> Vec<u64> {
        self.components.iter().map(|e| e.base_addr).collect()
    }
}

impl Default for CoreSightTopology {
    fn default() -> Self {
        Self::new()
    }
}

// ─── EtmConfiguration ─────────────────────────────────────────────────────────

/// Security-world filter flags for [`EtmConfiguration`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EtmFilterFlags {
    /// Whether to trace only secure world.
    pub secure_only: bool,
    /// Whether to trace only non-secure world.
    pub non_secure_only: bool,
}

/// ETM configuration registers and filtering options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtmConfiguration {
    /// Address range filters (start, end).
    pub address_ranges: Vec<(u64, u64)>,
    /// Security-world filter flags.
    pub filters: EtmFilterFlags,
    /// Exception level filter (if set, only trace this level).
    pub el_filter: Option<ExceptionLevel>,
    /// Context ID filter.
    pub context_id_filter: Option<u32>,
    /// Trigger address (start tracing at this address).
    pub trigger_addr: Option<u64>,
    /// Whether to enable cycle counting.
    pub cycle_count_enabled: bool,
    /// Whether timestamps are enabled.
    pub timestamp_enabled: bool,
    /// Return stack mode.
    pub return_stack: bool,
}

impl EtmConfiguration {
    /// Create a default configuration (trace everything).
    #[must_use]
    pub const fn default_all() -> Self {
        Self {
            address_ranges: Vec::new(),
            filters: EtmFilterFlags { secure_only: false, non_secure_only: false },
            el_filter: None,
            context_id_filter: None,
            trigger_addr: None,
            cycle_count_enabled: false,
            timestamp_enabled: true,
            return_stack: true,
        }
    }

    /// Add an address range filter.
    pub fn add_range(&mut self, start: u64, end: u64) {
        self.address_ranges.push((start, end));
    }

    /// Return `true` if tracing at `addr` passes all filters.
    #[must_use]
    pub fn passes(&self, addr: u64, el: ExceptionLevel, secure: bool) -> bool {
        if self.filters.secure_only && !secure {
            return false;
        }
        if self.filters.non_secure_only && secure {
            return false;
        }
        if let Some(el_filter) = self.el_filter
            && el_filter != el {
                return false;
            }
        if !self.address_ranges.is_empty() {
            return self
                .address_ranges
                .iter()
                .any(|(s, e)| addr >= *s && addr < *e);
        }
        true
    }
}

// ─── TraceFilter ──────────────────────────────────────────────────────────────

/// Filtering criteria for `CoreSight` trace streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFilter {
    /// Only pass packets from secure world.
    pub secure_only: bool,
    /// Only pass packets from non-secure world.
    pub non_secure_only: bool,
    /// Only pass packets from this exception level.
    pub el_filter: Option<ExceptionLevel>,
    /// Only pass addresses in this range.
    pub addr_range: Option<(u64, u64)>,
    /// Trace ID filter (match against `CoreSight` trace ID).
    pub trace_id: Option<u8>,
}

impl TraceFilter {
    /// Create a permissive filter (pass everything).
    #[must_use]
    pub const fn pass_all() -> Self {
        Self {
            secure_only: false,
            non_secure_only: false,
            el_filter: None,
            addr_range: None,
            trace_id: None,
        }
    }

    /// Filter for EL0 only.
    #[must_use]
    pub const fn el0_only() -> Self {
        Self {
            el_filter: Some(ExceptionLevel::El0),
            ..Self::pass_all()
        }
    }

    /// Filter for non-secure world.
    #[must_use]
    pub const fn non_secure() -> Self {
        Self {
            non_secure_only: true,
            ..Self::pass_all()
        }
    }

    /// Check if a packet passes the filter.
    #[must_use]
    pub const fn passes_addr(&self, addr: u64) -> bool {
        if let Some((start, end)) = self.addr_range {
            return addr >= start && addr < end;
        }
        true
    }
}

// ─── IsochronousBranchTrace ───────────────────────────────────────────────────

/// Branch trace reconstruction from isochronous trace.
pub struct IsochronousBranchTrace {
    /// Reconstructed branch records.
    pub branches: Vec<BranchRecord>,
    /// Last known address.
    pub last_addr: u64,
}

/// A single reconstructed branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchRecord {
    /// Source address.
    pub from: u64,
    /// Target address.
    pub to: u64,
    /// Whether branch was taken.
    pub taken: bool,
    /// Cycle count at branch time.
    pub cycle: u64,
}

impl IsochronousBranchTrace {
    /// Create a new branch tracer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            branches: Vec::new(),
            last_addr: 0,
        }
    }

    /// Record a branch.
    pub fn record(&mut self, from: u64, to: u64, taken: bool, cycle: u64) {
        self.branches.push(BranchRecord {
            from,
            to,
            taken,
            cycle,
        });
        self.last_addr = to;
    }

    /// Return all taken branches.
    #[must_use]
    pub fn taken_branches(&self) -> Vec<&BranchRecord> {
        self.branches.iter().filter(|b| b.taken).collect()
    }

    /// Return all unique branch source addresses.
    #[must_use]
    pub fn unique_sources(&self) -> Vec<u64> {
        let mut seen = std::collections::HashSet::new();
        self.branches
            .iter()
            .filter(|b| seen.insert(b.from))
            .map(|b| b.from)
            .collect()
    }
}

impl Default for IsochronousBranchTrace {
    fn default() -> Self {
        Self::new()
    }
}

// ─── FullExecutionTrace ───────────────────────────────────────────────────────

/// Full instruction-level execution trace replay.
pub struct FullExecutionTrace {
    /// Sequence of executed instruction addresses.
    pub instructions: Vec<u64>,
    /// Call events (from, to).
    pub calls: Vec<(u64, u64)>,
    /// Return events (from, to).
    pub returns: Vec<(u64, u64)>,
    /// Exception events.
    pub exceptions: Vec<(u64, ExceptionType)>,
    /// Current position in the replay.
    pub cursor: usize,
}

impl FullExecutionTrace {
    /// Create an empty execution trace.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            instructions: Vec::new(),
            calls: Vec::new(),
            returns: Vec::new(),
            exceptions: Vec::new(),
            cursor: 0,
        }
    }

    /// Record an instruction execution.
    pub fn record_instruction(&mut self, addr: u64) {
        self.instructions.push(addr);
    }

    /// Record a call.
    pub fn record_call(&mut self, from: u64, to: u64) {
        self.calls.push((from, to));
    }

    /// Record a return.
    pub fn record_return(&mut self, from: u64, to: u64) {
        self.returns.push((from, to));
    }

    /// Record an exception.
    pub fn record_exception(&mut self, addr: u64, exc: ExceptionType) {
        self.exceptions.push((addr, exc));
    }

    /// Return the total instruction count.
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Step forward in the replay.
    pub fn step_forward(&mut self) -> Option<u64> {
        let addr = self.instructions.get(self.cursor).copied();
        if addr.is_some() {
            self.cursor += 1;
        }
        addr
    }

    /// Step backward in the replay.
    pub fn step_backward(&mut self) -> Option<u64> {
        if self.cursor == 0 {
            return None;
        }
        self.cursor -= 1;
        self.instructions.get(self.cursor).copied()
    }

    /// Seek to a specific position.
    pub const fn seek(&mut self, pos: usize) -> bool {
        if pos <= self.instructions.len() {
            self.cursor = pos;
            true
        } else {
            false
        }
    }

    /// Return coverage: unique addresses executed.
    #[must_use]
    pub fn coverage(&self) -> std::collections::HashSet<u64> {
        self.instructions.iter().copied().collect()
    }
}

impl Default for FullExecutionTrace {
    fn default() -> Self {
        Self::new()
    }
}

// ─── TraceHeatmap ─────────────────────────────────────────────────────────────

/// Execution frequency per address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceHeatmap {
    /// Hit count per address.
    pub counts: BTreeMap<u64, u64>,
}

impl TraceHeatmap {
    /// Create an empty heatmap.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            counts: BTreeMap::new(),
        }
    }

    /// Record a hit at address `addr`.
    pub fn hit(&mut self, addr: u64) {
        *self.counts.entry(addr).or_insert(0) += 1;
    }

    /// Return the hot spot (highest execution count).
    #[must_use]
    pub fn hotspot(&self) -> Option<(u64, u64)> {
        self.counts
            .iter()
            .max_by_key(|(_, v)| **v)
            .map(|(k, v)| (*k, *v))
    }

    /// Return the top `n` hottest addresses.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(u64, u64)> {
        let mut pairs: Vec<(u64, u64)> = self.counts.iter().map(|(&k, &v)| (k, v)).collect();
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    /// Return total hit count.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Return the number of unique addresses.
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.counts.len()
    }
}

// ─── SharedTraceIndex ───────────────────────────────────────────────────────

/// Thread-safe, shareable index that maps trace addresses to resolved symbol
/// names and memoizes packet-decode results across concurrent decode workers.
///
/// `CoreSight` trace decode is frequently fanned out across multiple trace sink
/// buffers (one per core), and all workers benefit from a shared address →
/// symbol map plus a shared decode-result cache. The index keeps the read-mostly
/// symbol map behind an [`RwLock`] and the mutable decode cache behind a
/// [`Mutex`], both wrapped in [`Arc`] so the same index can be cloned cheaply
/// into each worker.
#[derive(Clone, Default)]
pub struct SharedTraceIndex {
    /// Read-mostly address → symbol name map (many readers, rare writers).
    symbols: std::sync::Arc<RwLock<BTreeMap<u64, String>>>,
    /// Decode memoization: raw packet byte → decoded packet kind name.
    decode_cache: std::sync::Arc<Mutex<HashMap<u8, String>>>,
}

impl SharedTraceIndex {
    /// Create an empty shared index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a resolved symbol name for `addr`. Returns the previous name,
    /// if any.
    pub fn set_symbol(&self, addr: u64, name: impl Into<String>) -> Option<String> {
        self.symbols.write().insert(addr, name.into())
    }

    /// Resolve the symbol name for `addr`, returning the nearest preceding
    /// symbol (function-start semantics) when no exact match exists.
    #[must_use]
    pub fn resolve(&self, addr: u64) -> Option<String> {
        let map = self.symbols.read();
        if let Some(name) = map.get(&addr) {
            return Some(name.clone());
        }
        map.range(..=addr).next_back().map(|(_, name)| name.clone())
    }

    /// Number of symbols currently registered.
    #[must_use]
    pub fn symbol_count(&self) -> usize {
        self.symbols.read().len()
    }

    /// Memoize (or fetch) the human-readable kind name for a packet header
    /// byte. The closure is only invoked on a cache miss.
    pub fn cached_kind<F>(&self, header: u8, compute: F) -> String
    where
        F: FnOnce() -> String,
    {
        let mut cache = self.decode_cache.lock();
        cache.entry(header).or_insert_with(compute).clone()
    }

    /// Number of distinct packet headers currently memoized.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.decode_cache.lock().len()
    }

    /// Clear the decode cache (e.g. when switching trace protocols), leaving
    /// the symbol map intact.
    pub fn clear_cache(&self) {
        self.decode_cache.lock().clear();
    }
}

// ─── CoreSightCapabilities ────────────────────────────────────────────────────

/// Describes the ARM `CoreSight` / ETM hardware capabilities present on the
/// current system, as discovered via sysfs and /dev node probing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreSightCapabilities {
    /// Number of ETM sources found under /sys/bus/coresight/devices/.
    pub etm_device_count: usize,
    /// Names of the ETM sysfs entries (e.g. "etm0", "etm1").
    pub etm_device_names: Vec<String>,
    /// Whether a /`dev/cs_etm`* sink node is present.
    pub has_cs_etm_sink: bool,
    /// Path to the first usable trace sink, if any.
    pub sink_path: Option<String>,
    /// `perf_event` type number for the ETM PMU (read from sysfs type file).
    pub perf_event_type: Option<u32>,
}

impl CoreSightCapabilities {
    /// Probe the system for ARM `CoreSight` / ETM hardware.
    ///
    /// On Linux `AArch64`, reads `/sys/bus/coresight/devices/` and looks for
    /// `etm*` entries, then checks for a `/dev/cs_etm*` sink.  On all other
    /// platforms this always returns `None`.
    #[must_use]
    pub const fn detect() -> Option<Self> {
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            Self::detect_linux()
        }
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        {
            None
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    fn detect_linux() -> Option<Self> {
        use std::fs;
        use std::path::Path;

        let cs_bus = Path::new("/sys/bus/coresight/devices");
        if !cs_bus.exists() {
            return None;
        }

        let mut etm_names: Vec<String> = Vec::new();
        let mut perf_type: Option<u32> = None;

        if let Ok(entries) = fs::read_dir(cs_bus) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("etm") {
                    // Try to read the perf_event type for the first ETM we find.
                    if perf_type.is_none() {
                        let type_path = entry.path().join("type");
                        if let Ok(content) = fs::read_to_string(&type_path) {
                            perf_type = content.trim().parse::<u32>().ok();
                        }
                    }
                    etm_names.push(name);
                }
            }
        }

        if etm_names.is_empty() {
            return None;
        }

        // Sort for deterministic ordering.
        etm_names.sort();

        // Check for /dev/cs_etm* sink.
        let sink_path = Self::find_cs_etm_sink();
        let has_sink = sink_path.is_some();

        Some(Self {
            etm_device_count: etm_names.len(),
            etm_device_names: etm_names,
            has_cs_etm_sink: has_sink,
            sink_path,
            perf_event_type: perf_type,
        })
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    fn find_cs_etm_sink() -> Option<String> {
        use std::fs;
        use std::path::Path;

        let dev_dir = Path::new("/dev");
        if let Ok(entries) = fs::read_dir(dev_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("cs_etm") {
                    return Some(entry.path().to_string_lossy().into_owned());
                }
            }
        }
        None
    }

    /// Return `true` when ARM `CoreSight` ETM tracing is available on this system.
    #[must_use]
    pub fn is_supported() -> bool {
        Self::detect().is_some()
    }
}

// ─── EtmCaptureConfig ─────────────────────────────────────────────────────────

/// Optional feature flags for [`EtmCaptureConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtmCaptureFlags {
    /// Enable cycle-accurate tracing (higher overhead, more detail).
    pub cycle_accurate: bool,
    /// Embed context IDs (PID) in the trace stream.
    pub context_ids: bool,
}

impl Default for EtmCaptureFlags {
    fn default() -> Self {
        Self { cycle_accurate: false, context_ids: true }
    }
}

/// Runtime capture configuration passed to [`PerfEtmCapture`].
///
/// This is separate from [`EtmConfig`] (which is a *decode* configuration) and
/// controls what the hardware traces rather than how the trace stream is parsed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtmCaptureConfig {
    /// Optional feature flags.
    pub flags: EtmCaptureFlags,
    /// Enable the hardware return-address stack.
    pub return_stack: bool,
    /// Embed timestamps in the trace stream.
    pub timestamp: bool,
    /// Optional address filter `(start, end)` — only trace within this range.
    pub addr_filter: Option<(u64, u64)>,
}

impl Default for EtmCaptureConfig {
    fn default() -> Self {
        Self {
            flags: EtmCaptureFlags::default(),
            return_stack: true,
            timestamp: true,
            addr_filter: None,
        }
    }
}

impl EtmCaptureConfig {
    /// Create a configuration that traces the given address range only.
    #[must_use]
    pub fn with_addr_filter(start: u64, end: u64) -> Self {
        Self {
            addr_filter: Some((start, end)),
            ..Self::default()
        }
    }
}

// ─── CoreSightTrace ───────────────────────────────────────────────────────────

/// Raw `CoreSight` trace data, as captured from the hardware or read from a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreSightTrace {
    /// Raw packet bytes from the trace sink.
    pub raw_packets: Vec<u8>,
    /// Source path, if loaded from a file.
    pub source_path: Option<String>,
}

impl CoreSightTrace {
    /// Create a [`CoreSightTrace`] from a raw byte slice.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            raw_packets: bytes.to_vec(),
            source_path: None,
        }
    }

    /// Load a [`CoreSightTrace`] from a binary file (e.g. a perf aux dump).
    ///
    /// # Errors
    /// Returns an error if the file cannot be read.
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read trace file {}: {}", path.display(), e))?;
        Ok(Self {
            raw_packets: raw,
            source_path: Some(path.to_string_lossy().into_owned()),
        })
    }

    /// Return the number of raw bytes in the trace.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.raw_packets.len()
    }

    /// Return `true` when the trace contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.raw_packets.is_empty()
    }
}

// ─── IsaType ──────────────────────────────────────────────────────────────────

/// ISA classification carried by `ETMv4` / ETE address packets.
///
/// Mirrors the `IS` field in the `ETMv4` spec (IHI0064).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IsaType {
    /// `AArch32` ARM (A32) instructions.
    ARM,
    /// `AArch32` Thumb / Thumb-2 (T32) instructions.
    Thumb,
    /// `AArch64` (A64) instructions.
    AArch64,
    /// Jazelle / `ThumbEE` (legacy, uncommon).
    Jazelle,
    /// `ThumbEE` (deprecated in `ARMv7`, removed in `ARMv8`).
    ThumbEE,
}

impl std::fmt::Display for IsaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ARM => write!(f, "ARM"),
            Self::Thumb => write!(f, "Thumb"),
            Self::AArch64 => write!(f, "AArch64"),
            Self::Jazelle => write!(f, "Jazelle"),
            Self::ThumbEE => write!(f, "ThumbEE"),
        }
    }
}

impl IsaType {
    /// Parse from the 2-bit `IS` field of an `ETMv4` address packet.
    ///
    /// `is_aarch64_context` disambiguates between Thumb/ARM when the `IS` bits
    /// are `0b00`.
    #[must_use]
    pub fn from_etm_is_field(bits: u8, is_aarch64_context: bool) -> Self {
        match bits & 0b11 {
            0b00 => {
                if is_aarch64_context {
                    Self::AArch64
                } else {
                    Self::ARM
                }
            }
            0b01 => Self::Thumb,
            0b10 => Self::Jazelle,
            0b11 => Self::ThumbEE,
            _ => unreachable!(),
        }
    }

    /// Return the instruction width in bytes for this ISA.
    ///
    /// For variable-width ISAs (Thumb) this returns the minimum width.
    #[must_use]
    pub const fn min_insn_bytes(self) -> u64 {
        match self {
            Self::ARM | Self::AArch64 => 4,
            Self::Thumb | Self::ThumbEE => 2,
            Self::Jazelle => 1,
        }
    }
}

// ─── EtmPacket ────────────────────────────────────────────────────────────────

/// A single decoded `ETMv4` / ETE packet.
///
/// `ETMv4` packets are the ARM equivalent of Intel PT packets.  The key
/// correspondences are:
///
/// | ETM packet  | Intel PT packet |
/// |-------------|----------------|
/// | `Atom`      | `TNT` (taken/not-taken) |
/// | `Address`   | `TIP` (target IP) |
/// | `Exception` | `TIP.PGE` + exception info |
/// | `Timestamp` | `TSC` |
/// | `Cycle`     | `CYC` |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EtmPacket {
    /// Atom packet — a burst of taken/not-taken branch decisions.
    ///
    /// `pattern` is a bitmask where bit N = 1 means the N-th branch was taken.
    /// `count` is the number of valid bits in `pattern` (1..=6 for `ETMv4` F1-F6
    /// atoms, up to 32 for extended formats).
    Atom {
        /// Number of valid branch decisions in `pattern`.
        count: u32,
        /// Taken/not-taken bitmask (bit 0 = first decision).
        pattern: u32,
    },

    /// Address packet — sets the current PC (like Intel PT `TIP`).
    Address {
        /// The absolute target address.
        addr: u64,
        /// ISA state at this address.
        isa: IsaType,
    },

    /// Exception entry — records the exception type and handler PC.
    Exception {
        /// ARM exception type (IRQ, FIQ, SVC, etc.).
        type_: u16,
        /// Exception handler program counter.
        pc: u64,
    },

    /// Timestamp packet — free-running counter value.
    Timestamp {
        /// Raw counter value.
        value: u64,
    },

    /// Cycle count packet — number of CPU cycles since the last cycle packet.
    Cycle {
        /// Cycle delta.
        count: u32,
    },

    /// Trace Info — marks the start of a new trace session with a type word.
    TraceInfo {
        /// Encoded info type word.
        info_type: u32,
    },

    /// Trace On — tracing has been enabled (after a gap).
    TraceOn,

    /// Trace Off — tracing has been disabled.
    TraceOff,
}

impl std::fmt::Display for EtmPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Atom { count, pattern } => write!(
                f,
                "Atom(count={count}, pattern=0b{pattern:0>count$b}",
                count = *count as usize
            ),
            Self::Address { addr, isa } => write!(f, "Address(0x{addr:x}, {isa})"),
            Self::Exception { type_, pc } => {
                write!(f, "Exception(type=0x{type_:04x}, pc=0x{pc:x})")
            }
            Self::Timestamp { value } => write!(f, "Timestamp({value})"),
            Self::Cycle { count } => write!(f, "Cycle({count})"),
            Self::TraceInfo { info_type } => write!(f, "TraceInfo(0x{info_type:08x})"),
            Self::TraceOn => write!(f, "TraceOn"),
            Self::TraceOff => write!(f, "TraceOff"),
        }
    }
}

// ─── EtmDecoder ───────────────────────────────────────────────────────────────

/// `ETMv4` / ETE packet stream decoder.
///
/// Processes a raw byte slice and emits [`EtmPacket`]s.  The decoder handles:
///
/// * ASYNC synchronisation (8 × 0xFF followed by 0x00)
/// * Atom packets F1–F6 (short taken/not-taken bursts)
/// * Address packets (1-byte through 8-byte forms)
/// * Exception, Timestamp, Cycle, `TraceInfo`, TraceOn/Off packets
///
/// The implementation is intentionally conservative: when a packet is
/// malformed or truncated it is silently skipped so the decoder stays
/// as resilient as possible against corrupted capture data.
pub struct EtmDecoder {
    /// Whether the decoder has seen an ASYNC sync marker.
    pub synchronized: bool,
    /// Current ISA state (updated by Address packets).
    pub current_isa: IsaType,
    /// Whether we are in an `AArch64` context (affects ISA resolution).
    pub aarch64_context: bool,
    /// Current PC (updated by Address packets).
    pub current_pc: u64,
}

impl EtmDecoder {
    /// Create a new decoder in `AArch64` mode.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            synchronized: false,
            current_isa: IsaType::AArch64,
            aarch64_context: true,
            current_pc: 0,
        }
    }

    /// Create a new decoder in `AArch32` (ARM/Thumb) mode.
    #[must_use]
    pub const fn new_aarch32() -> Self {
        Self {
            synchronized: false,
            current_isa: IsaType::ARM,
            aarch64_context: false,
            current_pc: 0,
        }
    }

    /// Attempt to find the `ETMv4` ASYNC synchronisation marker.
    ///
    /// The `ETMv4` ASYNC packet is 8 consecutive 0xFF bytes followed by a
    /// single 0x00 byte (9 bytes total).  This is analogous to the Intel PT
    /// PSB (Packet Stream Boundary).
    fn try_sync(raw: &[u8], pos: &mut usize) -> bool {
        let sync: [u8; 9] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        while *pos + 9 <= raw.len() {
            if raw[*pos..*pos + 9] == sync {
                *pos += 9;
                return true;
            }
            *pos += 1;
        }
        false
    }

    /// Read a ULEB128-encoded integer from `raw` starting at `*pos`.
    fn read_uleb128(raw: &[u8], pos: &mut usize) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            if *pos >= raw.len() {
                return None;
            }
            let byte = raw[*pos];
            *pos += 1;
            result |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
        Some(result)
    }

    /// Decode the address continuation bytes that follow an `ETMv4` address
    /// packet header.  Returns `(address, isa_bits)` or `None` on truncation.
    ///
    /// `ETMv4` address packets use a variable-length continuation encoding where
    /// each byte carries 7 bits of address and a "more" flag in bit 7.
    fn decode_address_bytes(raw: &[u8], pos: &mut usize) -> Option<(u64, u8)> {
        // First byte already consumed (the header byte).
        // Following bytes: up to 9 address bytes with continuation bits.
        let mut addr: u64 = 0;
        let mut shift: u32 = 0;
        let isa_bits: u8;
        let mut byte_count = 0usize;

        loop {
            if *pos >= raw.len() {
                return None;
            }
            let byte = raw[*pos];
            *pos += 1;
            byte_count += 1;

            // Last address byte (continuation bit clear) encodes 2 ISA bits
            // in bits [1:0] of the final 7-bit payload.
            let is_last = byte & 0x80 == 0;
            let payload = u64::from(byte & 0x7F);

            if is_last {
                // Bottom 2 bits of the final payload are the IS field.
                isa_bits = (payload & 0b11) as u8;
                addr |= (payload >> 2) << shift;
                break;
            }
            addr |= payload << shift;

            shift += 7;
            if byte_count > 9 || shift >= 64 {
                return None;
            }
        }

        Some((addr, isa_bits))
    }

    /// Decode an `ETMv4` / ETE packet stream from `raw`.
    ///
    /// The decoder first attempts to find an ASYNC sync packet; if none is
    /// found it falls back to decoding from offset 0 (useful for pre-sliced
    /// buffers that have already been aligned).
    #[must_use]
    pub fn decode_packets(raw: &[u8]) -> Vec<EtmPacket> {
        let mut decoder = Self::new();
        decoder.decode_all(raw)
    }

    /// Decode the full packet stream, returning all recognised packets.
    #[must_use]
    pub fn decode_all(&mut self, raw: &[u8]) -> Vec<EtmPacket> {
        let mut packets = Vec::with_capacity(raw.len() / 2);
        let mut pos = 0usize;
        let sync_pos = pos;
        if Self::try_sync(raw, &mut pos) {
            self.synchronized = true;
        } else {
            pos = sync_pos;
        }
        while pos < raw.len() {
            let header = raw[pos];
            pos += 1;
            if header == 0xFF {
                self.decode_async_sync(raw, &mut pos);
                continue;
            }
            match header {
                0x01 => {
                    let info = Self::read_uleb128(raw, &mut pos).unwrap_or(0);
                    packets.push(EtmPacket::TraceInfo { info_type: u32::try_from(info).unwrap_or(u32::MAX) });
                }
                0x04 => packets.push(EtmPacket::TraceOn),
                0x05 => packets.push(EtmPacket::TraceOff),
                0x02 => {
                    let value = Self::read_uleb128(raw, &mut pos).unwrap_or(0);
                    packets.push(EtmPacket::Timestamp { value });
                }
                0x03 => {
                    let count = u32::try_from(Self::read_uleb128(raw, &mut pos).unwrap_or(0)).unwrap_or(u32::MAX);
                    packets.push(EtmPacket::Cycle { count });
                }
                0x06 => {
                    if !self.decode_exception_etm(raw, &mut pos, &mut packets) { break; }
                }
                h if Self::is_atom_header(h) => {
                    Self::decode_atom_header(raw, &mut pos, h, &mut packets);
                }
                h if h & 0xF0 == 0x90 => {
                    self.decode_address_header(raw, &mut pos, h, &mut packets);
                }
                _ => {}
            }
        }
        packets
    }

    fn decode_async_sync(&mut self, raw: &[u8], pos: &mut usize) {
        let mut ff_count = 1usize;
        while *pos < raw.len() && raw[*pos] == 0xFF && ff_count < 8 {
            ff_count += 1;
            *pos += 1;
        }
        if ff_count >= 8 && *pos < raw.len() && raw[*pos] == 0x00 {
            *pos += 1;
            self.synchronized = true;
        }
    }

    fn decode_exception_etm(&mut self, raw: &[u8], pos: &mut usize, packets: &mut Vec<EtmPacket>) -> bool {
        if *pos + 2 > raw.len() {
            return false;
        }
        let b0 = u16::from(raw[*pos]);
        let b1 = u16::from(raw[*pos + 1]);
        *pos += 2;
        let exc_type = b0 | (b1 << 8);
        let pc = Self::read_uleb128(raw, pos).unwrap_or(0);
        self.current_pc = pc;
        packets.push(EtmPacket::Exception { type_: exc_type, pc });
        true
    }

    const fn is_atom_header(h: u8) -> bool {
        h == 0xF5 || h == 0xF6 || h == 0xF4
            || h & 0b1111_1100 == 0b1111_1000
            || h & 0b1111_1000 == 0b1101_0000
            || (h & 0b1100_0000 == 0b1100_0000 && h & 0b1111_1100 != 0b1111_1100)
    }

    fn decode_atom_header(raw: &[u8], pos: &mut usize, header: u8, packets: &mut Vec<EtmPacket>) {
        // ETMv4 atom formats F1–F6 (IHI0064 §6.4.3)
        if header == 0xF5 { packets.push(EtmPacket::Atom { count: 1, pattern: 1 }); return; }
        if header == 0xF6 { packets.push(EtmPacket::Atom { count: 1, pattern: 0 }); return; }
        if header & 0b1111_1100 == 0b1111_1000 {
            packets.push(EtmPacket::Atom { count: 2, pattern: u32::from(header & 0b11) }); return;
        }
        if header & 0b1111_1000 == 0b1101_0000 {
            packets.push(EtmPacket::Atom { count: 3, pattern: u32::from(header & 0b0111) }); return;
        }
        if header == 0xF4 {
            if *pos < raw.len() {
                let pattern = u32::from(raw[*pos] & 0x0F);
                *pos += 1;
                packets.push(EtmPacket::Atom { count: 4, pattern });
            }
            return;
        }
        // F6: six atoms in bits [5:0]
        packets.push(EtmPacket::Atom { count: 6, pattern: u32::from(header & 0b0011_1111) });
    }

    fn decode_address_header(&mut self, raw: &[u8], pos: &mut usize, header: u8, packets: &mut Vec<EtmPacket>) {
        let base_bits = u64::from(header & 0x0F);
        if let Some((addr_high, isa_bits)) = Self::decode_address_bytes(raw, pos) {
            let addr = base_bits | (addr_high << 4);
            let isa = IsaType::from_etm_is_field(isa_bits, self.aarch64_context);
            self.current_isa = isa;
            self.current_pc = addr;
            packets.push(EtmPacket::Address { addr, isa });
        }
    }
}

impl Default for EtmDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── TraceReconstructor ───────────────────────────────────────────────────────

/// Reconstructs a linear sequence of executed PCs from an [`EtmPacket`] stream.
///
/// The algorithm mirrors the Intel PT reconstruction loop:
///
/// 1. `Address` packets anchor the current PC.
/// 2. `Atom` packets drive forward simulation by consuming taken/not-taken bits.
///    * Taken → the next PC comes from the next `Address` packet in the stream.
///    * Not-taken → advance the PC by the minimum instruction width for the
///      current ISA and continue linear execution.
/// 3. `Exception` packets set the PC to the exception handler entry.
pub struct TraceReconstructor;

impl TraceReconstructor {
    /// Reconstruct a list of executed program counters from the packet stream.
    ///
    /// `binary` is the mapped binary image (used in future extensions for
    /// disassembly-guided reconstruction).  `base` is the load address of the
    /// binary within the traced address space.
    #[must_use]
    pub fn reconstruct_pcs(packets: &[EtmPacket], _binary: &[u8], _base: u64) -> Vec<u64> {
        let mut pcs: Vec<u64> = Vec::with_capacity(packets.len());
        let mut current_pc: Option<u64> = None;
        let mut current_isa = IsaType::AArch64;

        // Single-pass simulation: process packets in order.
        // For taken atoms we look ahead for the *next* Address packet after the
        // current position rather than pre-collecting all addresses up front.
        // Pre-collecting caused double-use: Address packets both set current_pc
        // during the sequential scan AND were popped from a pre-built queue,
        // yielding addresses that were far ahead in the stream.
        let mut pos = 0usize;
        while pos < packets.len() {
            let pkt = &packets[pos];
            pos += 1;
            match pkt {
                EtmPacket::Address { addr, isa } => {
                    current_pc = Some(*addr);
                    current_isa = *isa;
                    pcs.push(*addr);
                }

                EtmPacket::Atom { count, pattern } => {
                    for bit in 0..*count {
                        let taken = (pattern >> bit) & 1 == 1;
                        if taken {
                            // Lookahead: find the next Address packet from pos onwards.
                            let mut found = false;
                            let mut lookahead = pos;
                            while lookahead < packets.len() {
                                if let EtmPacket::Address { addr, isa } = &packets[lookahead] {
                                    current_pc = Some(*addr);
                                    current_isa = *isa;
                                    pcs.push(*addr);
                                    // Advance pos past this consumed Address packet.
                                    pos = lookahead + 1;
                                    found = true;
                                    break;
                                }
                                lookahead += 1;
                            }
                            if !found {
                                // No address packet available; stall.
                                break;
                            }
                        } else {
                            // Not-taken: advance linearly.
                            if let Some(pc) = current_pc {
                                let step = current_isa.min_insn_bytes();
                                let next = pc.wrapping_add(step);
                                current_pc = Some(next);
                                pcs.push(next);
                            }
                        }
                    }
                }

                EtmPacket::Exception { pc, .. } => {
                    current_pc = Some(*pc);
                    pcs.push(*pc);
                }

                _ => {}
            }
        }

        pcs
    }

    /// Compute the set of unique PCs that were executed (the coverage set).
    #[must_use]
    pub fn compute_coverage(pcs: &[u64]) -> std::collections::HashSet<u64> {
        pcs.iter().copied().collect()
    }

    /// Return a sorted, deduplicated list of executed PCs.
    #[must_use]
    pub fn sorted_unique_pcs(pcs: &[u64]) -> Vec<u64> {
        let mut unique: Vec<u64> = Self::compute_coverage(pcs).into_iter().collect();
        unique.sort_unstable();
        unique
    }

    /// Count how many times each PC was executed.
    #[must_use]
    pub fn execution_frequencies(pcs: &[u64]) -> BTreeMap<u64, u64> {
        let mut counts = BTreeMap::new();
        for &pc in pcs {
            *counts.entry(pc).or_insert(0u64) += 1;
        }
        counts
    }
}

// ─── PerfEtmCapture ───────────────────────────────────────────────────────────

/// Captures an ETM trace using the Linux `perf_event_open` system call.
///
/// On non-Linux-AArch64 platforms every method immediately returns an error
/// explaining that `CoreSight` requires Linux on `AArch64`.
///
/// # Linux `AArch64` usage
///
/// ```ignore
/// use rustre_trace_coresight::{PerfEtmCapture, EtmCaptureConfig};
///
/// let config = EtmCaptureConfig::default();
/// let mut cap = PerfEtmCapture::start(std::process::id(), config)?;
/// // ... run workload ...
/// let trace = cap.stop()?;
/// println!("captured {} bytes", trace.len());
/// ```
#[derive(Debug)]
pub struct PerfEtmCapture {
    /// The target PID being traced.
    pub pid: u32,
    /// The capture configuration in use.
    pub config: EtmCaptureConfig,
    /// Internal OS handle (fd on Linux, -1 on unsupported platforms).
    pub fd: i64,
    /// Whether the capture is currently active.
    pub active: bool,
    /// Accumulated raw trace bytes (filled on [`stop`]).
    raw: Vec<u8>,
}

impl PerfEtmCapture {
    /// Start an ETM trace capture for the given `pid`.
    ///
    /// On Linux `AArch64`, this calls `perf_event_open(2)` with the ETM PMU
    /// type read from `/sys/bus/coresight/devices/etm0/type`.
    ///
    /// On all other platforms this returns an error.
    ///
    /// # Errors
    /// Returns an error on non-Linux-AArch64 platforms, or if the ETM PMU type
    /// cannot be read or `perf_event_open` fails.
    pub fn start(pid: u32, config: EtmCaptureConfig) -> anyhow::Result<Self> {
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            Self::start_linux(pid, config)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        {
            let _ = (pid, config);
            anyhow::bail!("ARM CoreSight ETM capture requires Linux on AArch64")
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    fn start_linux(pid: u32, config: EtmCaptureConfig) -> anyhow::Result<Self> {
        use std::fs;

        // Read the PMU type for the CoreSight ETM.
        let pmu_type_path = "/sys/bus/coresight/devices/etm0/type";
        let pmu_type_str = fs::read_to_string(pmu_type_path)
            .map_err(|e| anyhow::anyhow!("cannot read ETM PMU type from {pmu_type_path}: {e}"))?;
        let pmu_type: u32 = pmu_type_str
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("cannot parse ETM PMU type: {e}"))?;

        // Build a perf_event_attr.  We use a minimal structure layout that
        // matches the kernel ABI; the remaining fields default to zero.
        //
        // SAFETY: the struct is initialised to zeroes, which is a valid
        // initial state for `perf_event_attr` per the kernel docs.
        let mut attr = unsafe { std::mem::zeroed::<libc::perf_event_attr>() };
        attr.type_ = pmu_type;
        attr.size = std::mem::size_of::<libc::perf_event_attr>() as u32;

        // Build the config word from our EtmCaptureConfig.
        let mut cfg: u64 = 0;
        if config.flags.cycle_accurate {
            cfg |= 1 << 0;
        }
        if config.return_stack {
            cfg |= 1 << 1;
        }
        if config.flags.context_ids {
            cfg |= 1 << 2;
        }
        if config.timestamp {
            cfg |= 1 << 3;
        }
        attr.config = cfg;

        // Open the perf event.
        //
        // SAFETY: FFI call with a valid perf_event_attr pointer.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const libc::perf_event_attr,
                pid as libc::pid_t,
                -1i32, // cpu = -1 (any)
                -1i32, // group_fd = -1 (new group)
                0u64,  // flags
            )
        };

        if fd < 0 {
            let errno = unsafe { *libc::__errno_location() };
            anyhow::bail!("perf_event_open failed: errno {errno}");
        }

        Ok(Self {
            pid,
            config,
            fd,
            active: true,
            raw: Vec::new(),
        })
    }

    /// Stop the capture and return the accumulated [`CoreSightTrace`].
    ///
    /// On non-Linux-AArch64 platforms this always returns an error.
    ///
    /// # Errors
    /// Returns an error on non-Linux-AArch64 platforms or if the capture fails to stop.
    pub fn stop(&mut self) -> anyhow::Result<CoreSightTrace> {
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            self.stop_linux()
        }
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        {
            anyhow::bail!("ARM CoreSight ETM capture requires Linux on AArch64")
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    fn stop_linux(&mut self) -> anyhow::Result<CoreSightTrace> {
        if !self.active {
            anyhow::bail!("capture already stopped");
        }
        self.active = false;

        // PERF_EVENT_IOC_DISABLE = _IO('$', 0) = 0x2400 on all Linux architectures
        // (the direction/size bits of _IO are 0 for no argument).
        // Using the kernel-correct encoding avoids fragility from magic literals.
        const PERF_EVENT_IOC_DISABLE: u64 = libc::_IO(b'$' as u32, 0);

        // Disable the perf event.
        // SAFETY: FFI ioctl call on our own fd with a known-safe request number.
        let rc = unsafe { libc::ioctl(self.fd as libc::c_int, PERF_EVENT_IOC_DISABLE, 0) };
        if rc < 0 {
            let errno = unsafe { *libc::__errno_location() };
            anyhow::bail!("ioctl(PERF_EVENT_IOC_DISABLE) failed: errno {errno}");
        }

        // ETM trace data is placed in the AUX region of the perf mmap ring
        // buffer (PERF_RECORD_AUX events), not in the normal data ring and not
        // returned by read(2).  We must:
        //   1. mmap the ring buffer (data page + N data pages).
        //   2. mmap the AUX sub-buffer at the offset stored in the
        //      perf_event_mmap_page header.
        //   3. Drain bytes between aux_tail and aux_head.
        //
        // Ring sizes: 1 metadata page + 2^n data pages (we use 16 = 64 KiB).
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let data_pages: usize = 16; // must be a power of two
        let ring_size = page_size + data_pages * page_size;

        // SAFETY: mmap of a perf fd with PROT_READ | PROT_WRITE and MAP_SHARED
        // is the documented way to access the perf ring buffer.
        let ring_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.fd as libc::c_int,
                0,
            )
        };
        if ring_ptr == libc::MAP_FAILED {
            let errno = unsafe { *libc::__errno_location() };
            // Close fd before returning the error.
            unsafe { libc::close(self.fd as libc::c_int) };
            self.fd = -1;
            anyhow::bail!("mmap(perf ring) failed: errno {errno}");
        }

        // The first page is a perf_event_mmap_page header.
        // SAFETY: the kernel guarantees this layout; we just read atomic fields.
        let hdr = ring_ptr as *const libc::perf_event_mmap_page;
        let aux_offset = unsafe { std::ptr::read_volatile(std::ptr::addr_of!((*hdr).aux_offset)) };
        let aux_size = unsafe { std::ptr::read_volatile(std::ptr::addr_of!((*hdr).aux_size)) };

        let mut trace_bytes: Vec<u8> = Vec::new();

        if aux_size > 0 {
            // mmap the AUX sub-buffer at aux_offset.
            // SAFETY: aux_offset and aux_size come from the kernel-owned header.
            let aux_ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    aux_size as usize,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    self.fd as libc::c_int,
                    aux_offset as libc::off_t,
                )
            };
            if aux_ptr != libc::MAP_FAILED {
                let aux_head = unsafe {
                    std::ptr::read_volatile(std::ptr::addr_of!((*hdr).aux_head))
                };
                let aux_tail = unsafe {
                    std::ptr::read_volatile(std::ptr::addr_of!((*hdr).aux_tail))
                };
                // Copy all available bytes from [aux_tail, aux_head).
                // The AUX buffer is a power-of-two ring; use modular indexing.
                let available = (aux_head.wrapping_sub(aux_tail)) as usize;
                let buf_len = aux_size as usize;
                trace_bytes.reserve(available);
                let base = aux_ptr as *const u8;
                for i in 0..available {
                    let idx = ((aux_tail as usize).wrapping_add(i)) & (buf_len - 1);
                    // SAFETY: idx is within [0, buf_len).
                    trace_bytes.push(unsafe { *base.add(idx) });
                }
                // Advance aux_tail to signal that we consumed the data.
                unsafe {
                    std::ptr::write_volatile(
                        std::ptr::addr_of_mut!((*hdr).aux_tail),
                        aux_head,
                    );
                }
                unsafe { libc::munmap(aux_ptr, aux_size as usize) };
            }
        }

        // Unmap the ring buffer and close the fd.
        unsafe { libc::munmap(ring_ptr, ring_size) };
        unsafe { libc::close(self.fd as libc::c_int) };
        self.fd = -1;

        self.raw = trace_bytes;
        Ok(CoreSightTrace::from_bytes(&self.raw))
    }

    /// Return a reference to the raw bytes accumulated so far.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Return the traced PID.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }
}

impl Drop for PerfEtmCapture {
    fn drop(&mut self) {
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd as libc::c_int);
            }
        }
    }
}

// ─── Platform guard (non-AArch64 Linux) ──────────────────────────────────────

/// Return an error on platforms that are not Linux `AArch64`.
///
/// This function is the central platform gate: call it at the start of any
/// function that can only operate on the target platform.
///
/// # Errors
/// Returns an error on platforms other than Linux `AArch64`.
pub fn require_linux_aarch64() -> anyhow::Result<()> {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        Ok(())
    }
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    {
        anyhow::bail!("ARM CoreSight requires Linux on AArch64")
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_decoder() -> CsDecoder {
        CsDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"))
    }

    fn make_full_decoder() -> CoreSightDecoder {
        CoreSightDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"))
    }

    #[test]
    fn test_display_trace_info() {
        assert_eq!(CsPacketKind::TraceInfo.to_string(), "TraceInfo");
    }

    #[test]
    fn test_display_trace_on() {
        assert_eq!(CsPacketKind::TraceOn.to_string(), "TraceOn");
    }

    #[test]
    fn test_display_trace_off() {
        assert_eq!(CsPacketKind::TraceOff.to_string(), "TraceOff");
    }

    #[test]
    fn test_display_address() {
        let s = CsPacketKind::Address { addr: 0x401000 }.to_string();
        assert!(s.contains("401000"));
    }

    #[test]
    fn test_display_atom_taken() {
        let s = CsPacketKind::Atom {
            taken: true,
            count: 1,
        }
        .to_string();
        assert!(s.contains("Atom"));
        assert!(s.contains("true"));
    }

    #[test]
    fn test_display_atom_not_taken() {
        let s = CsPacketKind::Atom {
            taken: false,
            count: 1,
        }
        .to_string();
        assert!(s.contains("false"));
    }

    #[test]
    fn test_display_exception() {
        let s = CsPacketKind::Exception { exc_type: 0x0A }.to_string();
        assert!(s.contains("Exception"));
    }

    #[test]
    fn test_display_timestamp() {
        let s = CsPacketKind::Timestamp(999).to_string();
        assert!(s.contains("999"));
    }

    #[test]
    fn test_display_context_id() {
        let s = CsPacketKind::ContextId(0x1234).to_string();
        assert!(s.contains("ContextId"));
    }

    #[test]
    fn test_display_vmid() {
        let s = CsPacketKind::VmId(42).to_string();
        assert!(s.contains("VmId"));
    }

    #[test]
    fn test_display_overflow() {
        assert_eq!(CsPacketKind::Overflow.to_string(), "Overflow");
    }

    #[test]
    fn test_etm_version_display() {
        assert_eq!(EtmVersion::Etm3.to_string(), "ETMv3");
        assert_eq!(EtmVersion::Etm4.to_string(), "ETMv4");
        assert_eq!(EtmVersion::EtmV4p1.to_string(), "ETMv4.1");
    }

    #[test]
    fn test_etm_config_new() {
        let cfg = EtmConfig::new(EtmVersion::Etm4, "arm64");
        assert_eq!(cfg.arch, "arm64");
        assert_eq!(cfg.version, EtmVersion::Etm4);
    }

    #[test]
    fn test_decode_atom_not_taken() {
        let mut dec = make_decoder();
        dec.feed(&[0x00]);
        let pkt = dec.next_packet().unwrap();
        assert_eq!(
            pkt.kind,
            CsPacketKind::Atom {
                taken: false,
                count: 1
            }
        );
        assert_eq!(pkt.byte_offset, 0);
    }

    #[test]
    fn test_decode_trace_info() {
        let mut dec = make_decoder();
        dec.feed(&[0x01]);
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt.kind, CsPacketKind::TraceInfo);
    }

    #[test]
    fn test_decode_atom_taken() {
        let mut dec = make_decoder();
        dec.feed(&[0x04]);
        let pkt = dec.next_packet().unwrap();
        assert_eq!(
            pkt.kind,
            CsPacketKind::Atom {
                taken: true,
                count: 1
            }
        );
    }

    #[test]
    fn test_decode_trace_on() {
        let mut dec = make_decoder();
        dec.feed(&[0x05]);
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt.kind, CsPacketKind::TraceOn);
    }

    #[test]
    fn test_decode_trace_off() {
        let mut dec = make_decoder();
        dec.feed(&[0x06]);
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt.kind, CsPacketKind::TraceOff);
    }

    #[test]
    fn test_decode_timestamp() {
        let mut dec = make_decoder();
        let ts: u64 = 0x1234_5678_9ABC_DEF0;
        let mut data = vec![0x43u8];
        data.extend_from_slice(&ts.to_le_bytes());
        dec.feed(&data);
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt.kind, CsPacketKind::Timestamp(ts));
    }

    #[test]
    fn test_decode_address() {
        let mut dec = make_decoder();
        let addr: u32 = 0x0040_1000;
        let mut data = vec![0x9Au8];
        data.extend_from_slice(&addr.to_le_bytes());
        dec.feed(&data);
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt.kind, CsPacketKind::Address { addr: u64::from(addr) });
    }

    #[test]
    fn test_decode_overflow_unknown_byte() {
        let mut dec = make_decoder();
        dec.feed(&[0xFF]);
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt.kind, CsPacketKind::Overflow);
    }

    #[test]
    fn test_decode_none_when_empty() {
        let mut dec = make_decoder();
        assert!(dec.next_packet().is_none());
    }

    #[test]
    fn test_decode_truncated_timestamp_rewinds() {
        let mut dec = make_decoder();
        dec.feed(&[0x43, 0x01, 0x02]);
        let result = dec.next_packet();
        assert!(result.is_none());
        assert_eq!(dec.pos, 0);
    }

    #[test]
    fn test_decode_truncated_address_rewinds() {
        let mut dec = make_decoder();
        dec.feed(&[0x9A, 0x01, 0x02]);
        let result = dec.next_packet();
        assert!(result.is_none());
        assert_eq!(dec.pos, 0);
    }

    #[test]
    fn test_decode_all_sequence() {
        let mut dec = make_decoder();
        dec.feed(&[0x01, 0x05, 0x04, 0x00]);
        let pkts = dec.decode_all();
        assert_eq!(pkts.len(), 4);
        assert_eq!(pkts[0].kind, CsPacketKind::TraceInfo);
        assert_eq!(pkts[1].kind, CsPacketKind::TraceOn);
        assert_eq!(
            pkts[2].kind,
            CsPacketKind::Atom {
                taken: true,
                count: 1
            }
        );
        assert_eq!(
            pkts[3].kind,
            CsPacketKind::Atom {
                taken: false,
                count: 1
            }
        );
    }

    #[test]
    fn test_decode_byte_offset() {
        let mut dec = make_decoder();
        dec.feed(&[0x01, 0x05]);
        let _ = dec.next_packet();
        let pkt = dec.next_packet().unwrap();
        assert_eq!(pkt.byte_offset, 1);
    }

    #[test]
    fn test_etm_trace_instruction_addresses() {
        let pkts = vec![
            CsPacket {
                kind: CsPacketKind::Address { addr: 0x1000 },
                byte_offset: 0,
            },
            CsPacket {
                kind: CsPacketKind::Atom {
                    taken: true,
                    count: 1,
                },
                byte_offset: 5,
            },
            CsPacket {
                kind: CsPacketKind::Address { addr: 0x2000 },
                byte_offset: 6,
            },
        ];
        let cfg = EtmConfig::new(EtmVersion::Etm4, "arm64");
        let trace = EtmTrace {
            packets: pkts,
            config: cfg,
        };
        let addrs = trace.instruction_addresses();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], 0x1000);
        assert_eq!(addrs[1], 0x2000);
    }

    #[test]
    fn test_etm_trace_atom_count() {
        let pkts = vec![
            CsPacket {
                kind: CsPacketKind::TraceInfo,
                byte_offset: 0,
            },
            CsPacket {
                kind: CsPacketKind::Atom {
                    taken: true,
                    count: 1,
                },
                byte_offset: 1,
            },
            CsPacket {
                kind: CsPacketKind::Atom {
                    taken: false,
                    count: 1,
                },
                byte_offset: 2,
            },
        ];
        let cfg = EtmConfig::new(EtmVersion::Etm4, "arm64");
        let trace = EtmTrace {
            packets: pkts,
            config: cfg,
        };
        assert_eq!(trace.atom_count(), 2);
    }

    #[test]
    fn test_etm_trace_empty() {
        let cfg = EtmConfig::new(EtmVersion::Etm3, "arm");
        let trace = EtmTrace {
            packets: vec![],
            config: cfg,
        };
        assert_eq!(trace.instruction_addresses().len(), 0);
        assert_eq!(trace.atom_count(), 0);
    }

    #[test]
    fn test_cs_error_display_invalid_packet() {
        let e = CsError::InvalidPacket(0xFF);
        assert!(e.to_string().contains("ff"));
    }

    #[test]
    fn test_cs_error_display_truncated() {
        let e = CsError::TruncatedBuffer;
        assert_eq!(e.to_string(), "truncated buffer");
    }

    #[test]
    fn test_cs_error_display_unknown_format() {
        let e = CsError::UnknownFormat("ETMv5".to_string());
        assert!(e.to_string().contains("ETMv5"));
    }

    #[test]
    fn test_incremental_feed() {
        let mut dec = make_decoder();
        dec.feed(&[0x01]);
        dec.feed(&[0x05]);
        let pkts = dec.decode_all();
        assert_eq!(pkts.len(), 2);
    }

    #[test]
    fn test_decode_all_empty() {
        let mut dec = make_decoder();
        assert_eq!(dec.decode_all().len(), 0);
    }

    // — New tests for expanded types —

    #[test]
    fn test_exception_type_from_etm_field() {
        assert_eq!(ExceptionType::from_etm_field(5), ExceptionType::Irq);
        assert_eq!(ExceptionType::from_etm_field(6), ExceptionType::Fiq);
        assert_eq!(ExceptionType::from_etm_field(2), ExceptionType::Svc);
        assert_eq!(ExceptionType::from_etm_field(0xFF), ExceptionType::Unknown);
    }

    #[test]
    fn test_exception_level_from_bits() {
        assert_eq!(ExceptionLevel::from_bits(0), ExceptionLevel::El0);
        assert_eq!(ExceptionLevel::from_bits(3), ExceptionLevel::El3);
    }

    #[test]
    fn test_exception_level_display() {
        assert_eq!(ExceptionLevel::El0.to_string(), "EL0");
        assert_eq!(ExceptionLevel::El3.to_string(), "EL3");
    }

    #[test]
    fn test_isa_mode_display() {
        assert_eq!(IsaMode::Aarch64.to_string(), "A64");
        assert_eq!(IsaMode::Thumb.to_string(), "T32");
    }

    #[test]
    fn test_security_state_display() {
        assert_eq!(SecurityState::NonSecure.to_string(), "NS");
        assert_eq!(SecurityState::Secure.to_string(), "S");
    }

    #[test]
    fn test_etm_context_default() {
        let ctx = EtmContext::default();
        assert!(!ctx.addr_valid);
        assert_eq!(ctx.timestamp, 0);
    }

    #[test]
    fn test_etm_context_apply_address() {
        let mut ctx = EtmContext::default();
        ctx.apply_address(0x1234_5678);
        assert_eq!(ctx.current_addr, 0x1234_5678);
        assert!(ctx.addr_valid);
    }

    #[test]
    fn test_etm_timestamp() {
        let ts1 = EtmTimestamp::new(1000);
        let ts2 = EtmTimestamp::new(1100);
        assert_eq!(ts2.delta_from(ts1), 100);
    }

    #[test]
    fn test_atom_packet_is_taken() {
        let pkt = AtomPacket::new(0b1010, 4, 0);
        assert!(!pkt.is_taken(0));
        assert!(pkt.is_taken(1));
        assert!(!pkt.is_taken(2));
        assert!(pkt.is_taken(3));
    }

    #[test]
    fn test_atom_packet_to_vec() {
        let pkt = AtomPacket::new(0b0101, 4, 0);
        let v = pkt.to_vec();
        assert_eq!(v, vec![true, false, true, false]);
    }

    #[test]
    fn test_exception_packet_new() {
        let pkt = ExceptionPacket::new(ExceptionType::Irq, ExceptionLevel::El1, 5);
        assert_eq!(pkt.exc_type, ExceptionType::Irq);
        assert_eq!(pkt.level, ExceptionLevel::El1);
        assert_eq!(pkt.byte_offset, 5);
        assert!(pkt.target_addr.is_none());
    }

    #[test]
    fn test_data_trace_packet_with_value() {
        let pkt = DataTracePacket::new(0xDEAD_BEEF, 4, true, 10).with_value(0x1234);
        assert_eq!(pkt.address, 0xDEAD_BEEF);
        assert_eq!(pkt.value, Some(0x1234));
        assert!(pkt.is_write);
    }

    #[test]
    fn test_core_sight_decoder_full() {
        let mut dec = make_full_decoder();
        let addr: u32 = 0x1000;
        let mut data = vec![0x9Au8];
        data.extend_from_slice(&addr.to_le_bytes());
        dec.feed(&data);
        let pkt = dec.next_packet().unwrap();
        assert!(matches!(pkt.kind, CsPacketKind::Address { addr: 0x1000 }));
        assert!(dec.context.addr_valid);
        assert_eq!(dec.context.current_addr, 0x1000);
    }

    #[test]
    fn test_core_sight_decoder_sync() {
        let mut dec = make_full_decoder();
        let mut data = vec![0x00u8; 11];
        data.push(0x80);
        dec.feed(&data);
        let pkt = dec.next_packet();
        assert!(pkt.is_some());
    }

    #[test]
    fn test_core_sight_synchronization_find() {
        let mut data = vec![0xAA, 0xBB];
        data.extend_from_slice(&[0x00u8; 11]);
        data.push(0x80);
        let offsets = CoreSightSynchronization::find_sync_offsets(&data);
        assert_eq!(offsets, vec![2]);
    }

    #[test]
    fn test_core_sight_synchronization_invalid() {
        let offsets = CoreSightSynchronization::find_sync_offsets(&[0x01, 0x02, 0x03]);
        assert!(offsets.is_empty());
    }

    #[test]
    fn test_rom_table_entry_is_etm() {
        let entry = RomTableEntry::new(0x8000_0000, 9, 0x9A0);
        assert!(entry.is_etm());
    }

    #[test]
    fn test_rom_table_entry_is_cti() {
        let entry = RomTableEntry::new(0x8000_1000, 9, 0x906);
        assert!(entry.is_cti());
    }

    #[test]
    fn test_rom_table_entry_not_etm() {
        let entry = RomTableEntry::new(0x8000_2000, 9, 0x1234);
        assert!(!entry.is_etm());
    }

    #[test]
    fn test_coresight_topology_add() {
        let mut topo = CoreSightTopology::new();
        topo.add_component(RomTableEntry::new(0xE00_0000, 9, 0x9A0));
        assert_eq!(topo.etm_count, 1);
    }

    #[test]
    fn test_etm_configuration_passes() {
        let mut cfg = EtmConfiguration::default_all();
        cfg.add_range(0x1000, 0x2000);
        assert!(cfg.passes(0x1500, ExceptionLevel::El0, false));
        assert!(!cfg.passes(0x500, ExceptionLevel::El0, false));
    }

    #[test]
    fn test_trace_filter_passes_addr() {
        let f = TraceFilter {
            secure_only: false,
            non_secure_only: false,
            el_filter: None,
            addr_range: Some((0x1000, 0x2000)),
            trace_id: None,
        };
        assert!(f.passes_addr(0x1500));
        assert!(!f.passes_addr(0x500));
    }

    #[test]
    fn test_embedded_trace_buffer_write_wrap() {
        let mut etb = EmbeddedTraceBuffer::new(8);
        etb.write(&[0u8; 10]);
        assert!(etb.wrapped);
        assert_eq!(etb.stored_bytes(), 8);
    }

    #[test]
    fn test_embedded_trace_buffer_reset() {
        let mut etb = EmbeddedTraceBuffer::new(100);
        etb.write(&[1, 2, 3]);
        etb.reset();
        assert_eq!(etb.stored_bytes(), 0);
        assert!(!etb.wrapped);
    }

    #[test]
    fn test_full_execution_trace() {
        let mut fet = FullExecutionTrace::new();
        fet.record_instruction(0x1000);
        fet.record_instruction(0x1004);
        fet.record_call(0x1004, 0x2000);
        assert_eq!(fet.instruction_count(), 2);
        assert_eq!(fet.calls.len(), 1);
        let a = fet.step_forward();
        assert_eq!(a, Some(0x1000));
        let b = fet.step_forward();
        assert_eq!(b, Some(0x1004));
        let back = fet.step_backward();
        assert_eq!(back, Some(0x1004));
    }

    #[test]
    fn test_trace_heatmap() {
        let mut hm = TraceHeatmap::new();
        hm.hit(0x1000);
        hm.hit(0x1000);
        hm.hit(0x2000);
        assert_eq!(hm.total_hits(), 3);
        let hot = hm.hotspot().unwrap();
        assert_eq!(hot.0, 0x1000);
        assert_eq!(hot.1, 2);
    }

    #[test]
    fn test_isochron_branch_trace() {
        let mut bt = IsochronousBranchTrace::new();
        bt.record(0x1000, 0x1010, true, 100);
        bt.record(0x1010, 0x1020, false, 200);
        assert_eq!(bt.taken_branches().len(), 1);
        assert_eq!(bt.unique_sources().len(), 2);
    }

    #[test]
    fn test_ptm_decoder_atom() {
        let mut ptm = PtmDecoder::new();
        ptm.feed(&[0x03]); // bit0=1 → branch, bit1=1 → taken
        let pkt = ptm.next_packet().unwrap();
        assert!(matches!(pkt.kind, CsPacketKind::Atom { .. }));
    }

    #[test]
    fn test_etm3_decoder_basic() {
        let mut dec = Etm3Decoder::new();
        dec.feed(&[0x08]);
        let pkt = dec.next_packet().unwrap();
        assert!(matches!(pkt.kind, CsPacketKind::TraceOn));
    }

    #[test]
    fn test_ete_decoder_basic() {
        let mut dec = EteDecoder::new();
        dec.feed(&[0x01]);
        let pkt = dec.next_packet().unwrap();
        assert!(matches!(pkt.kind, CsPacketKind::TraceInfo));
    }

    #[test]
    fn test_etm_version_ptm_ete_display() {
        assert_eq!(EtmVersion::Ptm.to_string(), "PTM");
        assert_eq!(EtmVersion::Ete.to_string(), "ETE");
    }

    #[test]
    fn test_tmi_receive_drain() {
        let mut tmi = TraceMemoryInterface::new(0xF000_0000, 0x1000);
        tmi.receive(&[1, 2, 3, 4]);
        assert!(tmi.has_data());
        let data = tmi.drain();
        assert_eq!(data.len(), 4);
        assert!(!tmi.has_data());
    }

    #[test]
    fn test_etm_address_update_full() {
        let upd = EtmAddressUpdate::full(0xFFFF_FFFF_0000_0000);
        assert!(upd.is_full);
        assert_eq!(upd.bytes_valid, 8);
    }

    #[test]
    fn test_trace_port_etb() {
        let port = CoreSightTracePort::new_etb();
        assert!(matches!(port.mode, TracePortMode::Etb));
    }

    #[test]
    fn test_core_sight_decoder_8byte_address() {
        let mut dec = make_full_decoder();
        let addr: u64 = 0xFFFF_FFFF_8080_1234;
        let mut data = vec![0x9Bu8];
        data.extend_from_slice(&addr.to_le_bytes());
        dec.feed(&data);
        let pkt = dec.next_packet().unwrap();
        assert!(matches!(pkt.kind, CsPacketKind::Address { addr: _ }));
        if let CsPacketKind::Address { addr: a } = pkt.kind {
            assert_eq!(a, addr);
        }
    }

    // ─── SharedTraceIndex ────────────────────────────────────────────────────

    #[test]
    fn test_shared_index_exact_resolve() {
        let idx = SharedTraceIndex::new();
        idx.set_symbol(0x1000, "main");
        assert_eq!(idx.resolve(0x1000).as_deref(), Some("main"));
        assert_eq!(idx.symbol_count(), 1);
    }

    #[test]
    fn test_shared_index_nearest_preceding() {
        let idx = SharedTraceIndex::new();
        idx.set_symbol(0x1000, "func_a");
        idx.set_symbol(0x2000, "func_b");
        // Address inside func_a resolves to func_a (nearest preceding).
        assert_eq!(idx.resolve(0x1500).as_deref(), Some("func_a"));
        assert_eq!(idx.resolve(0x2008).as_deref(), Some("func_b"));
        // Below all symbols → None.
        assert_eq!(idx.resolve(0x500), None);
    }

    #[test]
    fn test_shared_index_decode_cache() {
        let idx = SharedTraceIndex::new();
        let mut calls = 0;
        let k1 = idx.cached_kind(0x06, || {
            calls += 1;
            "TraceOff".to_string()
        });
        assert_eq!(k1, "TraceOff");
        // Second lookup hits the cache; closure not invoked again.
        let k2 = idx.cached_kind(0x06, || {
            calls += 1;
            "WRONG".to_string()
        });
        assert_eq!(k2, "TraceOff");
        assert_eq!(calls, 1);
        assert_eq!(idx.cache_len(), 1);
        idx.clear_cache();
        assert_eq!(idx.cache_len(), 0);
    }

    #[test]
    fn test_shared_index_clone_shares_state() {
        let idx = SharedTraceIndex::new();
        let clone = idx.clone();
        clone.set_symbol(0x4000, "shared");
        // Mutation through the clone is visible via the original (shared Arc).
        assert_eq!(idx.resolve(0x4000).as_deref(), Some("shared"));
    }

    // ─── CoreSightCapabilities ───────────────────────────────────────────────

    #[test]
    fn test_coresight_capabilities_not_supported_on_non_aarch64() {
        // On non-AArch64 / non-Linux platforms detect() must return None.
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        assert!(CoreSightCapabilities::detect().is_none());
    }

    #[test]
    fn test_coresight_capabilities_is_supported_false_on_non_aarch64() {
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        assert!(!CoreSightCapabilities::is_supported());
    }

    // ─── EtmCaptureConfig ─────────────────────────────────────────────────────

    #[test]
    fn test_etm_capture_config_default() {
        let cfg = EtmCaptureConfig::default();
        assert!(!cfg.flags.cycle_accurate);
        assert!(cfg.return_stack);
        assert!(cfg.flags.context_ids);
        assert!(cfg.timestamp);
        assert!(cfg.addr_filter.is_none());
    }

    #[test]
    fn test_etm_capture_config_with_addr_filter() {
        let cfg = EtmCaptureConfig::with_addr_filter(0x1000, 0x2000);
        assert_eq!(cfg.addr_filter, Some((0x1000, 0x2000)));
        // Other fields retain their defaults.
        assert!(cfg.return_stack);
    }

    // ─── CoreSightTrace ───────────────────────────────────────────────────────

    #[test]
    fn test_coresight_trace_from_bytes() {
        let raw = vec![0xFF, 0x00, 0x01, 0x02];
        let trace = CoreSightTrace::from_bytes(&raw);
        assert_eq!(trace.raw_packets, raw);
        assert_eq!(trace.len(), 4);
        assert!(!trace.is_empty());
        assert!(trace.source_path.is_none());
    }

    #[test]
    fn test_coresight_trace_empty() {
        let trace = CoreSightTrace::from_bytes(&[]);
        assert!(trace.is_empty());
        assert_eq!(trace.len(), 0);
    }

    #[test]
    fn test_coresight_trace_from_file_missing() {
        let result = CoreSightTrace::from_file(std::path::Path::new("/nonexistent/trace.bin"));
        assert!(result.is_err());
    }

    // ─── IsaType ──────────────────────────────────────────────────────────────

    #[test]
    fn test_isa_type_display() {
        assert_eq!(IsaType::ARM.to_string(), "ARM");
        assert_eq!(IsaType::Thumb.to_string(), "Thumb");
        assert_eq!(IsaType::AArch64.to_string(), "AArch64");
        assert_eq!(IsaType::Jazelle.to_string(), "Jazelle");
        assert_eq!(IsaType::ThumbEE.to_string(), "ThumbEE");
    }

    #[test]
    fn test_isa_type_from_etm_is_field_aarch64() {
        // IS = 0b00 in AArch64 context → AArch64
        assert_eq!(IsaType::from_etm_is_field(0b00, true), IsaType::AArch64);
    }

    #[test]
    fn test_isa_type_from_etm_is_field_arm() {
        // IS = 0b00 in AArch32 context → ARM
        assert_eq!(IsaType::from_etm_is_field(0b00, false), IsaType::ARM);
    }

    #[test]
    fn test_isa_type_from_etm_is_field_thumb() {
        assert_eq!(IsaType::from_etm_is_field(0b01, false), IsaType::Thumb);
        assert_eq!(IsaType::from_etm_is_field(0b01, true), IsaType::Thumb);
    }

    #[test]
    fn test_isa_type_from_etm_is_field_jazelle() {
        assert_eq!(IsaType::from_etm_is_field(0b10, false), IsaType::Jazelle);
    }

    #[test]
    fn test_isa_type_from_etm_is_field_thumbee() {
        assert_eq!(IsaType::from_etm_is_field(0b11, false), IsaType::ThumbEE);
    }

    #[test]
    fn test_isa_type_min_insn_bytes() {
        assert_eq!(IsaType::AArch64.min_insn_bytes(), 4);
        assert_eq!(IsaType::ARM.min_insn_bytes(), 4);
        assert_eq!(IsaType::Thumb.min_insn_bytes(), 2);
        assert_eq!(IsaType::ThumbEE.min_insn_bytes(), 2);
        assert_eq!(IsaType::Jazelle.min_insn_bytes(), 1);
    }

    // ─── EtmPacket ────────────────────────────────────────────────────────────

    #[test]
    fn test_etm_packet_display_trace_on() {
        assert_eq!(EtmPacket::TraceOn.to_string(), "TraceOn");
    }

    #[test]
    fn test_etm_packet_display_trace_off() {
        assert_eq!(EtmPacket::TraceOff.to_string(), "TraceOff");
    }

    #[test]
    fn test_etm_packet_display_timestamp() {
        let p = EtmPacket::Timestamp { value: 12345 };
        assert!(p.to_string().contains("12345"));
    }

    #[test]
    fn test_etm_packet_display_cycle() {
        let p = EtmPacket::Cycle { count: 42 };
        assert!(p.to_string().contains("42"));
    }

    #[test]
    fn test_etm_packet_display_address() {
        let p = EtmPacket::Address {
            addr: 0xDEAD_BEEF,
            isa: IsaType::AArch64,
        };
        let s = p.to_string();
        assert!(s.contains("deadbeef"));
        assert!(s.contains("AArch64"));
    }

    #[test]
    fn test_etm_packet_display_exception() {
        let p = EtmPacket::Exception {
            type_: 0x0005,
            pc: 0x8000,
        };
        let s = p.to_string();
        assert!(s.contains("Exception"));
        assert!(s.contains("8000"));
    }

    #[test]
    fn test_etm_packet_display_trace_info() {
        let p = EtmPacket::TraceInfo { info_type: 0xDEAD };
        let s = p.to_string();
        assert!(s.contains("TraceInfo"));
    }

    // ─── EtmDecoder ───────────────────────────────────────────────────────────

    #[test]
    fn test_etm_decoder_default_is_aarch64() {
        let dec = EtmDecoder::new();
        assert_eq!(dec.current_isa, IsaType::AArch64);
        assert!(dec.aarch64_context);
        assert!(!dec.synchronized);
    }

    #[test]
    fn test_etm_decoder_aarch32() {
        let dec = EtmDecoder::new_aarch32();
        assert_eq!(dec.current_isa, IsaType::ARM);
        assert!(!dec.aarch64_context);
    }

    #[test]
    fn test_etm_decoder_trace_on() {
        let raw = [0x04u8];
        let pkts = EtmDecoder::decode_packets(&raw);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0], EtmPacket::TraceOn);
    }

    #[test]
    fn test_etm_decoder_trace_off() {
        let pkts = EtmDecoder::decode_packets(&[0x05]);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0], EtmPacket::TraceOff);
    }

    #[test]
    fn test_etm_decoder_timestamp() {
        // 0x02 followed by ULEB128 for 300 (0xAC 0x02)
        let raw = [0x02u8, 0xAC, 0x02];
        let pkts = EtmDecoder::decode_packets(&raw);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0], EtmPacket::Timestamp { value: 300 });
    }

    #[test]
    fn test_etm_decoder_cycle() {
        // 0x03 followed by ULEB128 for 5 (0x05)
        let raw = [0x03u8, 0x05];
        let pkts = EtmDecoder::decode_packets(&raw);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0], EtmPacket::Cycle { count: 5 });
    }

    #[test]
    fn test_etm_decoder_trace_info() {
        // 0x01 followed by ULEB128 for 0 (0x00)
        let raw = [0x01u8, 0x00];
        let pkts = EtmDecoder::decode_packets(&raw);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0], EtmPacket::TraceInfo { info_type: 0 });
    }

    #[test]
    fn test_etm_decoder_atom_f1_taken() {
        let pkts = EtmDecoder::decode_packets(&[0xF5]);
        assert_eq!(pkts.len(), 1);
        assert_eq!(
            pkts[0],
            EtmPacket::Atom {
                count: 1,
                pattern: 1
            }
        );
    }

    #[test]
    fn test_etm_decoder_atom_f1_not_taken() {
        let pkts = EtmDecoder::decode_packets(&[0xF6]);
        assert_eq!(pkts.len(), 1);
        assert_eq!(
            pkts[0],
            EtmPacket::Atom {
                count: 1,
                pattern: 0
            }
        );
    }

    #[test]
    fn test_etm_decoder_atom_f4() {
        // 0xF4 followed by nibble byte: pattern = 0b1010 → 4 atoms
        let pkts = EtmDecoder::decode_packets(&[0xF4, 0b0000_1010]);
        assert_eq!(pkts.len(), 1);
        assert_eq!(
            pkts[0],
            EtmPacket::Atom {
                count: 4,
                pattern: 0b1010
            }
        );
    }

    #[test]
    fn test_etm_decoder_async_sync() {
        // 8 × 0xFF followed by 0x00 = ASYNC sync packet, then TraceOn.
        let mut raw = vec![0xFFu8; 8];
        raw.push(0x00);
        raw.push(0x04); // TraceOn
        let pkts = EtmDecoder::decode_packets(&raw);
        // Only TraceOn should appear; sync does not produce a packet.
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0], EtmPacket::TraceOn);
    }

    #[test]
    fn test_etm_decoder_empty_input() {
        let pkts = EtmDecoder::decode_packets(&[]);
        assert!(pkts.is_empty());
    }

    #[test]
    fn test_etm_decoder_multiple_packets() {
        let raw = [
            0x04u8, // TraceOn
            0xF5,   // Atom taken
            0xF6,   // Atom not-taken
            0x02, 0x64, // Timestamp = 100
        ];
        let pkts = EtmDecoder::decode_packets(&raw);
        assert_eq!(pkts.len(), 4);
        assert_eq!(pkts[0], EtmPacket::TraceOn);
        assert_eq!(
            pkts[1],
            EtmPacket::Atom {
                count: 1,
                pattern: 1
            }
        );
        assert_eq!(
            pkts[2],
            EtmPacket::Atom {
                count: 1,
                pattern: 0
            }
        );
        assert_eq!(pkts[3], EtmPacket::Timestamp { value: 100 });
    }

    // ─── TraceReconstructor ───────────────────────────────────────────────────

    #[test]
    fn test_trace_reconstructor_empty() {
        let pcs = TraceReconstructor::reconstruct_pcs(&[], &[], 0);
        assert!(pcs.is_empty());
    }

    #[test]
    fn test_trace_reconstructor_address_only() {
        let packets = vec![
            EtmPacket::Address {
                addr: 0x1000,
                isa: IsaType::AArch64,
            },
            EtmPacket::Address {
                addr: 0x2000,
                isa: IsaType::AArch64,
            },
        ];
        let pcs = TraceReconstructor::reconstruct_pcs(&packets, &[], 0);
        assert_eq!(pcs, vec![0x1000, 0x2000]);
    }

    #[test]
    fn test_trace_reconstructor_not_taken_advances_linearly() {
        let packets = vec![
            EtmPacket::Address {
                addr: 0x1000,
                isa: IsaType::AArch64,
            },
            EtmPacket::Atom {
                count: 1,
                pattern: 0,
            }, // not-taken
        ];
        let pcs = TraceReconstructor::reconstruct_pcs(&packets, &[], 0);
        // Address at 0x1000, then linear advance by 4 (AArch64).
        assert_eq!(pcs, vec![0x1000, 0x1004]);
    }

    #[test]
    fn test_trace_reconstructor_taken_uses_next_address() {
        let packets = vec![
            EtmPacket::Address {
                addr: 0x1000,
                isa: IsaType::AArch64,
            },
            EtmPacket::Address {
                addr: 0x3000,
                isa: IsaType::AArch64,
            },
            EtmPacket::Atom {
                count: 1,
                pattern: 1,
            }, // taken
        ];
        let pcs = TraceReconstructor::reconstruct_pcs(&packets, &[], 0);
        // First two Address packets appear directly; the taken atom consumes
        // the second address from the queue and emits 0x3000 again.
        assert!(pcs.contains(&0x1000));
        assert!(pcs.contains(&0x3000));
    }

    #[test]
    fn test_trace_reconstructor_exception() {
        let packets = vec![
            EtmPacket::Address {
                addr: 0x1000,
                isa: IsaType::AArch64,
            },
            EtmPacket::Exception {
                type_: 5,
                pc: 0xFFFF_0000,
            },
        ];
        let pcs = TraceReconstructor::reconstruct_pcs(&packets, &[], 0);
        assert!(pcs.contains(&0xFFFF_0000));
    }

    #[test]
    fn test_compute_coverage() {
        let pcs = vec![0x1000, 0x1004, 0x1000, 0x2000, 0x1004];
        let cov = TraceReconstructor::compute_coverage(&pcs);
        assert_eq!(cov.len(), 3);
        assert!(cov.contains(&0x1000));
        assert!(cov.contains(&0x1004));
        assert!(cov.contains(&0x2000));
    }

    #[test]
    fn test_sorted_unique_pcs() {
        let pcs = vec![0x3000, 0x1000, 0x2000, 0x1000];
        let sorted = TraceReconstructor::sorted_unique_pcs(&pcs);
        assert_eq!(sorted, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn test_execution_frequencies() {
        let pcs = vec![0x1000, 0x1000, 0x2000, 0x1000];
        let freq = TraceReconstructor::execution_frequencies(&pcs);
        assert_eq!(freq[&0x1000], 3);
        assert_eq!(freq[&0x2000], 1);
    }

    // ─── require_linux_aarch64 ────────────────────────────────────────────────

    #[test]
    fn test_require_linux_aarch64_non_aarch64() {
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        assert!(require_linux_aarch64().is_err());
    }

    // ─── PerfEtmCapture platform guard ───────────────────────────────────────

    #[test]
    fn test_perf_etm_capture_start_fails_on_non_aarch64() {
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        {
            let result = PerfEtmCapture::start(1234, EtmCaptureConfig::default());
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("AArch64"));
        }
    }
}
