//! `rustre-trace` — Core execution tracing abstraction.
//!
//! Provides unified trace recording, replay, diff, slicing, coverage,
//! merging, filtering, index, and visualization data types.

pub mod trace_analysis;
pub mod trace_annotation;
pub mod trace_database;
pub mod trace_export;
pub mod trace_filter;
pub mod trace_indexer;
pub mod trace_format;
pub mod trace_statistics;
pub mod trace_index;
pub mod trace_hot_spots;
pub mod trace_serializer;
pub mod trace_compressor;
pub mod trace_importer;
pub mod trace_annotator;

/// Registry of trace sub-crate engines wired into the `rustre-trace` hub.
///
/// Each entry re-exports the primary engine type from a sub-crate and exposes
/// a constructor through [`registry::all_engines`], giving callers a single
/// dispatcher over every available tracing backend.
pub mod registry {
    pub use rustre_trace_coresight::CoreSightDecoder;
    pub use rustre_trace_coverage::CoverageSession;
    pub use rustre_trace_navigate::TraceNavigator;
    pub use rustre_trace_pt::{
        IpCompression, PtDecoder, PtError, PtEvent, PtFlow, PtFlowReconstructor, PtPacket,
        PtPacketKind, PtTrace, SidebandInfo, TimingInfo,
    };
    // Submodule re-exports so downstream consumers can reach the full Intel PT
    // toolkit (packet/instruction/block decoders, flow reconstruction, sideband
    // correlation, snapshotting, perf integration, timing analysis, coverage
    // reporting, filtering, trace builder) through the `rustre-trace` hub
    // instead of taking a direct path-dependency on `rustre-trace-pt`.
    pub use rustre_trace_pt::{
        pt_block_decoder, pt_coverage_reporter, pt_decoder, pt_filter,
        pt_flow_reconstruction, pt_instruction_decoder, pt_packet_decoder,
        pt_perf_integration, pt_sideband, pt_snapshot, pt_timing,
        pt_timing_analyzer, pt_trace_builder,
    };

    /// A handle to one of the registered trace engines.
    pub enum TraceEngine {
        /// ARM `CoreSight` ETM decoder.
        CoreSight(CoreSightDecoder),
        /// Lighthouse-style coverage session.
        Coverage(CoverageSession),
        /// Tenet-style trace navigator.
        Navigate(Box<TraceNavigator>),
        /// Intel Processor Trace decoder.
        Pt(PtDecoder),
    }

    impl TraceEngine {
        /// Static name of this engine.
        #[must_use]
        pub const fn name(&self) -> &'static str {
            match self {
                Self::CoreSight(_) => "coresight",
                Self::Coverage(_) => "coverage",
                Self::Navigate(_) => "navigate",
                Self::Pt(_) => "pt",
            }
        }
    }

    /// Construct one instance of every registered trace engine that can be
    /// created without external inputs.
    #[must_use]
    pub fn all_engines() -> Vec<TraceEngine> {
        vec![
            TraceEngine::CoreSight(CoreSightDecoder::new(
                rustre_trace_coresight::EtmConfig::new(
                    rustre_trace_coresight::EtmVersion::Etm4,
                    "arm64",
                ),
            )),
            TraceEngine::Coverage(CoverageSession::new("default")),
            TraceEngine::Navigate(Box::new(TraceNavigator::new(
                rustre_trace_navigate::ExecutionTrace::new(Vec::new(), "default"),
            ))),
            TraceEngine::Pt(PtDecoder::new()),
        ]
    }

    /// Return the static names of all registered engines.
    #[must_use]
    pub fn engine_names() -> Vec<&'static str> {
        vec!["coresight", "coverage", "navigate", "pt"]
    }
}

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use parking_lot::Mutex;
use rustre_core::address::Address as CoreAddress;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the trace subsystem.
#[derive(Debug, Error)]
pub enum TraceError {
    /// The trace provider is already running.
    #[error("trace provider already running")]
    AlreadyRunning,
    /// The trace provider is not running.
    #[error("trace provider not running")]
    NotRunning,
    /// An I/O or backing-store error.
    #[error("I/O error: {0}")]
    Io(String),
    /// Unsupported operation.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The requested trace record does not exist.
    #[error("trace record {0} not found")]
    NotFound(u64),
    /// A backing-store SQL error.
    #[error("store error: {0}")]
    Store(#[from] rusqlite::Error),
    /// Slice range is out of bounds.
    #[error("slice out of bounds: start={start}, end={end}, len={len}")]
    SliceOutOfBounds {
        /// Requested start.
        start: u64,
        /// Requested end.
        end: u64,
        /// Actual length.
        len: u64,
    },
    /// Merge target format mismatch.
    #[error("merge mismatch: {0}")]
    MergeMismatch(String),
    /// Serialization error.
    #[error("serialization: {0}")]
    Serialization(String),
    /// Deserialization error.
    #[error("deserialization: {0}")]
    Deserialization(String),
    /// Generic wrapped error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// ─── TraceEvent ───────────────────────────────────────────────────────────────

/// A single event in an execution trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceEvent {
    /// An executed instruction.
    Instruction {
        /// Address of the instruction.
        addr: u64,
        /// Size in bytes.
        size: u8,
    },
    /// A memory read.
    MemRead {
        /// Address read from.
        addr: u64,
        /// Width of the read in bytes.
        size: u8,
        /// Value read.
        value: u64,
    },
    /// A memory write.
    MemWrite {
        /// Address written to.
        addr: u64,
        /// Width of the write in bytes.
        size: u8,
        /// Value written.
        value: u64,
    },
    /// A function call.
    Call {
        /// Address of the call instruction.
        from: u64,
        /// Target address.
        to: u64,
    },
    /// A function return.
    Return {
        /// Address of the return instruction.
        from: u64,
        /// Return address.
        to: u64,
    },
    /// An exception/fault.
    Exception {
        /// Exception code.
        code: u32,
        /// Address where the exception occurred.
        addr: u64,
    },
    /// A system call.
    Syscall {
        /// Syscall number.
        number: u64,
        /// Arguments.
        args: Vec<u64>,
    },
    /// A branch (conditional).
    Branch {
        /// Branch instruction address.
        from: u64,
        /// Taken target.
        to: u64,
        /// Whether the branch was taken.
        taken: bool,
    },
    /// A module load.
    ModuleLoad {
        /// Module base address.
        base: u64,
        /// Module size in bytes.
        size: u64,
        /// Module name.
        name: String,
    },
    /// A register change snapshot.
    RegisterChange {
        /// Register name.
        name: String,
        /// Old value.
        old_value: u64,
        /// New value.
        new_value: u64,
    },
}

impl TraceEvent {
    /// Return the primary address associated with this event.
    #[must_use]
    pub const fn primary_addr(&self) -> u64 {
        event_primary_addr(self)
    }

    /// Return the event type name as a static string.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        event_type_name(self)
    }

    /// Return `true` if this is an `Instruction` event.
    #[must_use]
    pub const fn is_instruction(&self) -> bool {
        matches!(self, Self::Instruction { .. })
    }

    /// Return `true` if this is a memory access event.
    #[must_use]
    pub const fn is_memory_access(&self) -> bool {
        matches!(self, Self::MemRead { .. } | Self::MemWrite { .. })
    }

    /// Return `true` if this is a control-flow event.
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(
            self,
            Self::Call { .. } | Self::Return { .. } | Self::Branch { .. }
        )
    }

    /// Return `true` if this is a syscall event.
    #[must_use]
    pub const fn is_syscall(&self) -> bool {
        matches!(self, Self::Syscall { .. })
    }

    /// Return `true` if this is an exception event.
    #[must_use]
    pub const fn is_exception(&self) -> bool {
        matches!(self, Self::Exception { .. })
    }
}

impl std::fmt::Display for TraceEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Instruction { addr, size } => {
                write!(f, "Instruction(addr=0x{addr:x}, size={size})")
            }
            Self::MemRead { addr, size, value } => {
                write!(
                    f,
                    "MemRead(addr=0x{addr:x}, size={size}, value=0x{value:x})"
                )
            }
            Self::MemWrite { addr, size, value } => {
                write!(
                    f,
                    "MemWrite(addr=0x{addr:x}, size={size}, value=0x{value:x})"
                )
            }
            Self::Call { from, to } => {
                write!(f, "Call(from=0x{from:x}, to=0x{to:x})")
            }
            Self::Return { from, to } => {
                write!(f, "Return(from=0x{from:x}, to=0x{to:x})")
            }
            Self::Exception { code, addr } => {
                write!(f, "Exception(code=0x{code:x}, addr=0x{addr:x})")
            }
            Self::Syscall { number, args } => {
                write!(f, "Syscall(number={number}, args={args:?})")
            }
            Self::Branch { from, to, taken } => {
                write!(f, "Branch(from=0x{from:x}, to=0x{to:x}, taken={taken})")
            }
            Self::ModuleLoad { base, size, name } => {
                write!(f, "ModuleLoad(base=0x{base:x}, size={size}, name={name})")
            }
            Self::RegisterChange {
                name,
                old_value,
                new_value,
            } => {
                write!(f, "RegChange({name}: 0x{old_value:x}->0x{new_value:x})")
            }
        }
    }
}

// ─── TraceRecord ──────────────────────────────────────────────────────────────

/// A single record in an execution trace session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// The event at this step.
    pub event: TraceEvent,
    /// Thread identifier.
    pub thread_id: u32,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

impl TraceRecord {
    /// Construct a [`TraceRecord`].
    #[must_use]
    pub const fn new(seq: u64, event: TraceEvent, thread_id: u32, timestamp_ns: u64) -> Self {
        Self {
            seq,
            event,
            thread_id,
            timestamp_ns,
        }
    }
}

impl std::fmt::Display for TraceRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] tid={} t={}ns {}",
            self.seq, self.thread_id, self.timestamp_ns, self.event
        )
    }
}

// ─── TraceFrame ───────────────────────────────────────────────────────────────

/// A richer trace frame including register state alongside an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFrame {
    /// Underlying record.
    pub record: TraceRecord,
    /// CPU register state at this point.
    pub registers: HashMap<String, u64>,
    /// Call depth at this point.
    pub call_depth: u32,
}

impl TraceFrame {
    /// Create a new [`TraceFrame`].
    #[must_use]
    pub fn new(record: TraceRecord) -> Self {
        Self {
            record,
            registers: HashMap::new(),
            call_depth: 0,
        }
    }

    /// Return the sequence number.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.record.seq
    }

    /// Return the thread ID.
    #[must_use]
    pub const fn thread_id(&self) -> u32 {
        self.record.thread_id
    }

    /// Return the timestamp in nanoseconds.
    #[must_use]
    pub const fn timestamp_ns(&self) -> u64 {
        self.record.timestamp_ns
    }

    /// Return the instruction pointer if this is an `Instruction` event.
    #[must_use]
    pub const fn instruction_pointer(&self) -> Option<u64> {
        if let TraceEvent::Instruction { addr, .. } = self.record.event {
            Some(addr)
        } else {
            None
        }
    }

    /// Set a register value.
    pub fn set_register(&mut self, name: impl Into<String>, value: u64) {
        self.registers.insert(name.into(), value);
    }

    /// Get a register value by name.
    #[must_use]
    pub fn get_register(&self, name: &str) -> Option<u64> {
        self.registers.get(name).copied()
    }
}

// ─── TraceFilter ──────────────────────────────────────────────────────────────

/// Criteria for filtering trace records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceFilter {
    /// Only include records at or after this address.
    pub min_addr: Option<u64>,
    /// Only include records before this address.
    pub max_addr: Option<u64>,
    /// Only include records from this thread.
    pub thread_id: Option<u32>,
    /// Only include events whose type name is in this list.
    pub event_types: Vec<String>,
    /// Alias for `event_types` — only include events whose kind name is in this list.
    pub kinds: Vec<String>,
    /// Only include records at or after this timestamp (nanoseconds).
    pub min_timestamp_ns: Option<u64>,
    /// Only include records at or before this timestamp (nanoseconds).
    pub max_timestamp_ns: Option<u64>,
    /// Only include records whose sequence number is in `[min_seq, max_seq)`.
    pub seq_range: Option<(u64, u64)>,
}

impl TraceFilter {
    /// Create a new empty [`TraceFilter`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a filter that only passes instructions.
    #[must_use]
    pub fn instructions_only() -> Self {
        Self {
            event_types: vec!["Instruction".to_string()],
            ..Default::default()
        }
    }

    /// Return a filter restricted to a single thread.
    #[must_use]
    pub fn for_thread(tid: u32) -> Self {
        Self {
            thread_id: Some(tid),
            ..Default::default()
        }
    }

    /// Return a filter restricted to an address range.
    #[must_use]
    pub fn address_range(min: u64, max: u64) -> Self {
        Self {
            min_addr: Some(min),
            max_addr: Some(max),
            ..Default::default()
        }
    }

    /// Return a filter restricted to an address range expressed as
    /// [`rustre_core::address::Address`] values.
    ///
    /// This bridges the canonical core address type to the trace filter,
    /// allowing callers that work with `rustre-core` types to avoid manual
    /// `.as_u64()` conversions.
    #[must_use]
    pub fn core_address_range(min: CoreAddress, max: CoreAddress) -> Self {
        Self::address_range(min.as_u64(), max.as_u64())
    }

    /// Return a filter restricted to a time range.
    #[must_use]
    pub fn time_range(min_ns: u64, max_ns: u64) -> Self {
        Self {
            min_timestamp_ns: Some(min_ns),
            max_timestamp_ns: Some(max_ns),
            ..Default::default()
        }
    }

    /// Returns `true` if `rec` satisfies all active criteria.
    #[must_use]
    pub fn matches(&self, rec: &TraceRecord) -> bool {
        // Address filtering (uses the primary address of the event).
        let addr = event_primary_addr(&rec.event);
        if let Some(min) = self.min_addr
            && addr < min
        {
            return false;
        }
        if let Some(max) = self.max_addr
            && addr >= max
        {
            return false;
        }
        // Thread filter.
        if let Some(tid) = self.thread_id
            && rec.thread_id != tid
        {
            return false;
        }
        // Timestamp filter.
        if let Some(min_ts) = self.min_timestamp_ns
            && rec.timestamp_ns < min_ts
        {
            return false;
        }
        if let Some(max_ts) = self.max_timestamp_ns
            && rec.timestamp_ns > max_ts
        {
            return false;
        }
        // Sequence number filter.
        if let Some((start, end)) = self.seq_range
            && (rec.seq < start || rec.seq >= end)
        {
            return false;
        }
        // Event type filter (event_types takes priority, then kinds).
        let active_kinds = if self.event_types.is_empty() {
            &self.kinds
        } else {
            &self.event_types
        };
        if !active_kinds.is_empty() {
            let kind = event_type_name(&rec.event);
            if !active_kinds.iter().any(|t| t == kind) {
                return false;
            }
        }
        true
    }

    /// Apply the filter to a slice of records.
    #[must_use]
    pub fn apply<'a>(&self, records: &'a [TraceRecord]) -> Vec<&'a TraceRecord> {
        records.iter().filter(|r| self.matches(r)).collect()
    }

    /// Return whether the filter is empty (passes everything).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.min_addr.is_none()
            && self.max_addr.is_none()
            && self.thread_id.is_none()
            && self.event_types.is_empty()
            && self.kinds.is_empty()
            && self.min_timestamp_ns.is_none()
            && self.max_timestamp_ns.is_none()
            && self.seq_range.is_none()
    }

    /// Validate that `event_types` and `kinds` are not both set simultaneously.
    ///
    /// When both fields are non-empty `event_types` takes priority and `kinds`
    /// is silently ignored, which is almost certainly a caller bug.  Call this
    /// after constructing a filter from external input to catch the mistake
    /// early.
    ///
    /// # Errors
    ///
    /// Returns an error string if both `event_types` and `kinds` are non-empty.
    pub fn validate(&self) -> Result<(), String> {
        if !self.event_types.is_empty() && !self.kinds.is_empty() {
            return Err(
                "TraceFilter: both `event_types` and `kinds` are set; \
                 use only one — `event_types` takes priority and `kinds` \
                 would be silently ignored"
                    .to_string(),
            );
        }
        Ok(())
    }
}

pub(crate) const fn event_primary_addr(event: &TraceEvent) -> u64 {
    match event {
        TraceEvent::Instruction { addr, .. }
        | TraceEvent::MemRead { addr, .. }
        | TraceEvent::MemWrite { addr, .. }
        | TraceEvent::Call { from: addr, .. }
        | TraceEvent::Return { from: addr, .. }
        | TraceEvent::Exception { addr, .. }
        | TraceEvent::Branch { from: addr, .. }
        | TraceEvent::ModuleLoad { base: addr, .. } => *addr,
        TraceEvent::Syscall { number, .. } => *number,
        TraceEvent::RegisterChange { .. } => 0,
    }
}

pub(crate) const fn event_type_name(event: &TraceEvent) -> &'static str {
    match event {
        TraceEvent::Instruction { .. } => "Instruction",
        TraceEvent::MemRead { .. } => "MemRead",
        TraceEvent::MemWrite { .. } => "MemWrite",
        TraceEvent::Call { .. } => "Call",
        TraceEvent::Return { .. } => "Return",
        TraceEvent::Exception { .. } => "Exception",
        TraceEvent::Syscall { .. } => "Syscall",
        TraceEvent::Branch { .. } => "Branch",
        TraceEvent::ModuleLoad { .. } => "ModuleLoad",
        TraceEvent::RegisterChange { .. } => "RegisterChange",
    }
}

// ─── TraceSession ─────────────────────────────────────────────────────────────

/// An in-memory trace session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSession {
    /// All recorded events.
    pub records: Vec<TraceRecord>,
    /// Name of the trace session.
    pub name: String,
    /// Architecture string (e.g. `"x86_64"`, `"arm64"`).
    pub arch: String,
    next_seq: u64,
}

impl TraceSession {
    /// Create a new empty [`TraceSession`].
    #[must_use]
    pub fn new(name: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            records: Vec::new(),
            name: name.into(),
            arch: arch.into(),
            next_seq: 0,
        }
    }

    /// Append a new event.
    pub fn push(&mut self, event: TraceEvent, thread_id: u32, timestamp_ns: u64) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.records.push(TraceRecord {
            seq,
            event,
            thread_id,
            timestamp_ns,
        });
    }

    /// Append a new event (alias for `push`).
    pub fn push_event(&mut self, event: TraceEvent, thread_id: u32, ts_ns: u64) {
        self.push(event, thread_id, ts_ns);
    }

    /// Return all records that match the filter.
    #[must_use]
    pub fn filter(&self, f: &TraceFilter) -> Vec<&TraceRecord> {
        self.records.iter().filter(|r| f.matches(r)).collect()
    }

    /// Count the number of `Instruction` events.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| matches!(r.event, TraceEvent::Instruction { .. }))
            .count()
    }

    /// Return the set of unique program-counter addresses from all `Instruction` events.
    #[must_use]
    pub fn unique_pcs(&self) -> HashSet<u64> {
        self.records
            .iter()
            .filter_map(|r| {
                if let TraceEvent::Instruction { addr, .. } = r.event {
                    Some(addr)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return the set of unique addresses from all `Instruction` events.
    #[must_use]
    pub fn unique_addresses(&self) -> HashSet<u64> {
        self.unique_pcs()
    }

    /// Return the total number of records in this session.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Slice: return records in the inclusive sequence number range `[start, end]`.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::SliceOutOfBounds`] if `start > end` or either is
    /// greater than the last sequence number.
    pub fn slice(&self, start: u64, end: u64) -> Result<Vec<&TraceRecord>, TraceError> {
        let max_seq = self.records.last().map_or(0, |r| r.seq);
        if start > end {
            return Err(TraceError::SliceOutOfBounds {
                start,
                end,
                len: max_seq,
            });
        }
        Ok(self
            .records
            .iter()
            .filter(|r| r.seq >= start && r.seq <= end)
            .collect())
    }

    /// Merge another session's records into this one, re-sequencing.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::MergeMismatch`] if the architectures differ.
    pub fn merge(&mut self, other: &Self) -> Result<(), TraceError> {
        if self.arch != other.arch {
            return Err(TraceError::MergeMismatch(format!(
                "arch mismatch: {} vs {}",
                self.arch, other.arch
            )));
        }
        for rec in &other.records {
            let seq = self.next_seq;
            self.next_seq += 1;
            self.records.push(TraceRecord {
                seq,
                event: rec.event.clone(),
                thread_id: rec.thread_id,
                timestamp_ns: rec.timestamp_ns,
            });
        }
        Ok(())
    }

    /// Return all unique thread IDs seen in this session.
    #[must_use]
    pub fn thread_ids(&self) -> HashSet<u32> {
        self.records.iter().map(|r| r.thread_id).collect()
    }

    /// Count events by type name.
    #[must_use]
    pub fn event_type_counts(&self) -> HashMap<&'static str, usize> {
        let mut map: HashMap<&'static str, usize> = HashMap::new();
        for rec in &self.records {
            *map.entry(event_type_name(&rec.event)).or_insert(0) += 1;
        }
        map
    }

    /// Return the time duration of this session in nanoseconds.
    #[must_use]
    pub fn duration_ns(&self) -> u64 {
        let first = self.records.first().map_or(0, |r| r.timestamp_ns);
        let last = self.records.last().map_or(0, |r| r.timestamp_ns);
        last.saturating_sub(first)
    }

    /// Build a [`HeatMap`] from instruction records.
    #[must_use]
    pub fn build_heat_map(&self) -> HeatMap {
        let mut hm = HeatMap::new();
        for rec in &self.records {
            if let TraceEvent::Instruction { addr, .. } = rec.event {
                hm.record(addr);
            }
        }
        hm
    }

    /// Build a [`TraceIndex`] from this session.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] if the index cannot be created.
    pub fn build_index(&self) -> Result<TraceIndex, TraceError> {
        let mut idx = TraceIndex::new();
        idx.seq_to_idx.reserve(self.records.len());
        for (i, rec) in self.records.iter().enumerate() {
            idx.insert_record(rec);
            idx.seq_to_idx.insert(rec.seq, i);
        }
        Ok(idx)
    }

    /// Return records for a given thread, sorted by sequence number.
    #[must_use]
    pub fn records_for_thread(&self, tid: u32) -> Vec<&TraceRecord> {
        self.records.iter().filter(|r| r.thread_id == tid).collect()
    }

    /// Compute coverage: set of unique (addr) pairs from Instruction events.
    #[must_use]
    pub fn coverage_set(&self) -> HashSet<u64> {
        self.unique_pcs()
    }

    /// Return the first record, if any.
    #[must_use]
    pub fn first_record(&self) -> Option<&TraceRecord> {
        self.records.first()
    }

    /// Return the last record, if any.
    #[must_use]
    pub fn last_record(&self) -> Option<&TraceRecord> {
        self.records.last()
    }
}

// ─── TraceRecorder ────────────────────────────────────────────────────────────

/// Records events into a [`TraceSession`] with configurable buffering.
pub struct TraceRecorder {
    session: TraceSession,
    /// Current event count.
    pub event_count: u64,
    /// Maximum events before auto-flush (0 = unlimited).
    pub max_events: u64,
    flushed_count: u64,
}

impl TraceRecorder {
    /// Create a new recorder.
    #[must_use]
    pub fn new(name: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            session: TraceSession::new(name, arch),
            event_count: 0,
            max_events: 0,
            flushed_count: 0,
        }
    }

    /// Create a recorder with a maximum event limit.
    #[must_use]
    pub fn with_max_events(name: impl Into<String>, arch: impl Into<String>, max: u64) -> Self {
        let mut rec = Self::new(name, arch);
        rec.max_events = max;
        rec
    }

    /// Record an event.
    pub fn record(&mut self, event: TraceEvent, thread_id: u32, timestamp_ns: u64) {
        if self.max_events > 0 && self.event_count >= self.max_events {
            return;
        }
        self.session.push(event, thread_id, timestamp_ns);
        self.event_count += 1;
    }

    /// Record an instruction.
    pub fn record_instruction(&mut self, addr: u64, size: u8, thread_id: u32, ts_ns: u64) {
        self.record(TraceEvent::Instruction { addr, size }, thread_id, ts_ns);
    }

    /// Record a memory read.
    pub fn record_mem_read(&mut self, addr: u64, size: u8, value: u64, thread_id: u32, ts_ns: u64) {
        self.record(TraceEvent::MemRead { addr, size, value }, thread_id, ts_ns);
    }

    /// Record a memory write.
    pub fn record_mem_write(
        &mut self,
        addr: u64,
        size: u8,
        value: u64,
        thread_id: u32,
        ts_ns: u64,
    ) {
        self.record(TraceEvent::MemWrite { addr, size, value }, thread_id, ts_ns);
    }

    /// Record a function call.
    pub fn record_call(&mut self, from: u64, to: u64, thread_id: u32, ts_ns: u64) {
        self.record(TraceEvent::Call { from, to }, thread_id, ts_ns);
    }

    /// Record a return.
    pub fn record_return(&mut self, from: u64, to: u64, thread_id: u32, ts_ns: u64) {
        self.record(TraceEvent::Return { from, to }, thread_id, ts_ns);
    }

    /// Record an exception.
    pub fn record_exception(&mut self, code: u32, addr: u64, thread_id: u32, ts_ns: u64) {
        self.record(TraceEvent::Exception { code, addr }, thread_id, ts_ns);
    }

    /// Record a syscall.
    pub fn record_syscall(&mut self, number: u64, args: Vec<u64>, thread_id: u32, ts_ns: u64) {
        self.record(TraceEvent::Syscall { number, args }, thread_id, ts_ns);
    }

    /// Finalise and return the completed session.
    #[must_use]
    pub fn finish(self) -> TraceSession {
        self.session
    }

    /// Return the number of events flushed so far.
    #[must_use]
    pub const fn flushed_count(&self) -> u64 {
        self.flushed_count
    }

    /// Return whether the maximum event limit has been reached.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.max_events > 0 && self.event_count >= self.max_events
    }

    /// Borrow the current session without consuming the recorder.
    #[must_use]
    pub const fn session(&self) -> &TraceSession {
        &self.session
    }
}

// ─── TracePlayer ──────────────────────────────────────────────────────────────

/// Plays back a recorded trace session event by event.
pub struct TracePlayer {
    session: TraceSession,
    /// Current position.
    pub cursor: usize,
    /// Playback speed multiplier.
    pub speed: f64,
}

impl TracePlayer {
    /// Create a player from a session.
    #[must_use]
    pub const fn new(session: TraceSession) -> Self {
        Self {
            session,
            cursor: 0,
            speed: 1.0,
        }
    }

    /// Return the next record, advancing the cursor.
    #[must_use]
    pub fn next(&mut self) -> Option<&TraceRecord> {
        let rec = self.session.records.get(self.cursor);
        if rec.is_some() {
            self.cursor += 1;
        }
        rec
    }

    /// Peek at the current record without advancing.
    #[must_use]
    pub fn peek(&self) -> Option<&TraceRecord> {
        self.session.records.get(self.cursor)
    }

    /// Reset the player to the beginning.
    pub const fn reset(&mut self) {
        self.cursor = 0;
    }

    /// Seek to a specific sequence number.
    ///
    /// Returns `true` if the sequence number was found.
    pub fn seek_to_seq(&mut self, seq: u64) -> bool {
        if let Some(idx) = self.session.records.iter().position(|r| r.seq == seq) {
            self.cursor = idx;
            true
        } else {
            false
        }
    }

    /// Return `true` if there are no more records.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.cursor >= self.session.records.len()
    }

    /// Return the number of remaining records.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.session.records.len().saturating_sub(self.cursor)
    }

    /// Return all remaining records without advancing.
    #[must_use]
    pub fn peek_all_remaining(&self) -> &[TraceRecord] {
        &self.session.records[self.cursor..]
    }

    /// Step backward by one record.
    ///
    /// Returns `false` if already at the beginning.
    pub const fn step_back(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }
        self.cursor -= 1;
        true
    }

    /// Return the total number of records.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.session.records.len()
    }

    /// Return the progress as a fraction `[0.0, 1.0]`.
    #[must_use]
    pub fn progress(&self) -> f64 {
        let total = self.session.records.len();
        if total == 0 {
            return 1.0;
        }
        self.cursor as f64 / total as f64
    }
}

// ─── TraceDiff ────────────────────────────────────────────────────────────────

/// Difference between two trace sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDiff {
    /// Events only in the left trace.
    pub only_in_left: Vec<TraceRecord>,
    /// Events only in the right trace.
    pub only_in_right: Vec<TraceRecord>,
    /// Events present in both (by seq and event type).
    pub common_count: usize,
}

impl TraceDiff {
    /// Compute a diff between two sessions.
    #[must_use]
    pub fn compute(left: &TraceSession, right: &TraceSession) -> Self {
        let left_types: HashSet<(&'static str, u64)> = left
            .records
            .iter()
            .map(|r| (event_type_name(&r.event), event_primary_addr(&r.event)))
            .collect();
        let right_types: HashSet<(&'static str, u64)> = right
            .records
            .iter()
            .map(|r| (event_type_name(&r.event), event_primary_addr(&r.event)))
            .collect();

        let common_count = left_types.intersection(&right_types).count();

        let only_in_left: Vec<TraceRecord> = left
            .records
            .iter()
            .filter(|r| {
                !right_types.contains(&(event_type_name(&r.event), event_primary_addr(&r.event)))
            })
            .cloned()
            .collect();

        let only_in_right: Vec<TraceRecord> = right
            .records
            .iter()
            .filter(|r| {
                !left_types.contains(&(event_type_name(&r.event), event_primary_addr(&r.event)))
            })
            .cloned()
            .collect();

        Self {
            only_in_left,
            only_in_right,
            common_count,
        }
    }

    /// Return `true` if the two sessions are identical.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.only_in_left.is_empty() && self.only_in_right.is_empty()
    }

    /// Return the total number of unique events across both sessions.
    #[must_use]
    pub const fn total_unique(&self) -> usize {
        self.only_in_left.len() + self.only_in_right.len() + self.common_count
    }

    /// Similarity ratio in `[0.0, 1.0]`.
    #[must_use]
    pub fn similarity(&self) -> f64 {
        let total = self.total_unique();
        if total == 0 {
            return 1.0;
        }
        self.common_count as f64 / total as f64
    }
}

// ─── CoverageMap ──────────────────────────────────────────────────────────────

/// Maps addresses to hit counts for coverage measurement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageMap {
    /// Hit count per address.
    pub counts: BTreeMap<u64, u64>,
    /// Total address space (for computing coverage ratio).
    pub total_addresses: u64,
}

impl CoverageMap {
    /// Create an empty [`CoverageMap`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a [`CoverageMap`] with a known total address space.
    #[must_use]
    pub const fn with_total(total_addresses: u64) -> Self {
        Self {
            counts: BTreeMap::new(),
            total_addresses,
        }
    }

    /// Record a hit at `addr`.
    pub fn record_hit(&mut self, addr: u64) {
        *self.counts.entry(addr).or_insert(0) += 1;
    }

    /// Record `n` hits at `addr`.
    pub fn record_hits(&mut self, addr: u64, n: u64) {
        *self.counts.entry(addr).or_insert(0) += n;
    }

    /// Return the hit count for `addr`.
    #[must_use]
    pub fn hit_count(&self, addr: u64) -> u64 {
        self.counts.get(&addr).copied().unwrap_or(0)
    }

    /// Return the number of unique addresses that were hit.
    #[must_use]
    pub fn unique_addresses_hit(&self) -> usize {
        self.counts.len()
    }

    /// Return total hits across all addresses.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Coverage ratio: unique addresses hit / total addresses.
    #[must_use]
    pub fn coverage_ratio(&self) -> f64 {
        if self.total_addresses == 0 {
            return if self.counts.is_empty() { 1.0 } else { 0.0 };
        }
        self.counts.len() as f64 / self.total_addresses as f64
    }

    /// Merge another coverage map into this one.
    pub fn merge(&mut self, other: &Self) {
        for (&addr, &count) in &other.counts {
            *self.counts.entry(addr).or_insert(0) += count;
        }
        self.total_addresses = self.total_addresses.max(other.total_addresses);
    }

    /// Return addresses sorted by hit count, descending.
    #[must_use]
    pub fn hottest_addresses(&self, n: usize) -> Vec<(u64, u64)> {
        let mut pairs: Vec<(u64, u64)> = self.counts.iter().map(|(&a, &c)| (a, c)).collect();
        if n < pairs.len() {
            // Partial selection: find the top-n without fully sorting the tail.
            pairs.select_nth_unstable_by(n, |a, b| b.1.cmp(&a.1));
            pairs.truncate(n);
        }
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        pairs
    }

    /// Return addresses that have never been hit (relative to a known range).
    #[must_use]
    pub fn uncovered_in_range(&self, start: u64, end: u64, step: u64) -> Vec<u64> {
        let step = if step == 0 { 1 } else { step };
        let mut uncovered = Vec::new();
        let mut addr = start;
        while addr < end {
            if !self.counts.contains_key(&addr) {
                uncovered.push(addr);
            }
            addr = addr.saturating_add(step);
        }
        uncovered
    }

    /// Build a coverage map from a session.
    #[must_use]
    pub fn from_session(session: &TraceSession) -> Self {
        let mut map = Self::new();
        for rec in &session.records {
            if let TraceEvent::Instruction { addr, .. } = rec.event {
                map.record_hit(addr);
            }
        }
        map
    }
}

// ─── TraceIndex ───────────────────────────────────────────────────────────────

/// In-memory index for fast lookups over a [`TraceSession`].
#[derive(Debug, Clone, Default)]
pub struct TraceIndex {
    /// Address → list of sequence numbers.
    addr_to_seqs: HashMap<u64, Vec<u64>>,
    /// Thread ID → list of sequence numbers.
    tid_to_seqs: HashMap<u32, Vec<u64>>,
    /// Event type → list of sequence numbers.
    type_to_seqs: HashMap<&'static str, Vec<u64>>,
    /// Sequence number → index in the parent session.
    seq_to_idx: HashMap<u64, usize>,
}

impl TraceIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a record into the index.
    pub fn insert_record(&mut self, rec: &TraceRecord) {
        let addr = event_primary_addr(&rec.event);
        self.addr_to_seqs.entry(addr).or_default().push(rec.seq);
        self.tid_to_seqs
            .entry(rec.thread_id)
            .or_default()
            .push(rec.seq);
        self.type_to_seqs
            .entry(event_type_name(&rec.event))
            .or_default()
            .push(rec.seq);
    }

    /// Look up sequence numbers by address.
    #[must_use]
    pub fn seqs_at_addr(&self, addr: u64) -> &[u64] {
        self.addr_to_seqs.get(&addr).map_or(&[], |v| v.as_slice())
    }

    /// Look up sequence numbers by thread ID.
    #[must_use]
    pub fn seqs_for_thread(&self, tid: u32) -> &[u64] {
        self.tid_to_seqs.get(&tid).map_or(&[], |v| v.as_slice())
    }

    /// Look up sequence numbers by event type name.
    #[must_use]
    pub fn seqs_by_type(&self, type_name: &str) -> &[u64] {
        self.type_to_seqs
            .get(type_name)
            .map_or(&[], |v| v.as_slice())
    }

    /// Return all indexed addresses.
    #[must_use]
    pub fn all_addresses(&self) -> Vec<u64> {
        self.addr_to_seqs.keys().copied().collect()
    }

    /// Return all thread IDs in the index.
    #[must_use]
    pub fn all_thread_ids(&self) -> Vec<u32> {
        self.tid_to_seqs.keys().copied().collect()
    }

    /// Return all event type names in the index.
    #[must_use]
    pub fn all_event_types(&self) -> Vec<&'static str> {
        self.type_to_seqs.keys().copied().collect()
    }

    /// Return the total number of indexed entries.
    #[must_use]
    pub fn total_indexed(&self) -> usize {
        self.seq_to_idx.len()
    }
}

// ─── TraceProvider ────────────────────────────────────────────────────────────

/// Abstract provider that can capture a live trace session.
pub trait TraceProvider: Send + Sync {
    /// Name of this provider.
    fn name(&self) -> &str;

    /// Start capturing.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::AlreadyRunning`] if already started.
    fn start(&mut self) -> Result<(), TraceError>;

    /// Stop capturing and return the recorded session.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::NotRunning`] if not started.
    fn stop(&mut self) -> Result<TraceSession, TraceError>;
}

// ─── InMemoryTraceProvider ────────────────────────────────────────────────────

/// A [`TraceProvider`] that replays pre-recorded events.
pub struct InMemoryTraceProvider {
    /// Name of this provider.
    pub name: String,
    session: TraceSession,
    /// Whether the provider is currently "running".
    pub running: bool,
    pre_recorded: Vec<TraceEvent>,
}

impl InMemoryTraceProvider {
    /// Create a provider that will replay `records` when started.
    #[must_use]
    pub fn with_pre_recorded(
        name: impl Into<String>,
        arch: impl Into<String>,
        records: Vec<TraceEvent>,
    ) -> Self {
        let name_str = name.into();
        Self {
            session: TraceSession::new(name_str.clone(), arch),
            name: name_str,
            running: false,
            pre_recorded: records,
        }
    }

    /// Create a provider with pre-loaded events (alias for `with_pre_recorded`).
    #[must_use]
    pub fn with_events(
        name: impl Into<String>,
        arch: impl Into<String>,
        events: Vec<TraceEvent>,
    ) -> Self {
        Self::with_pre_recorded(name, arch, events)
    }
}

impl TraceProvider for InMemoryTraceProvider {
    fn name(&self) -> &str {
        &self.name
    }

    /// # Errors
    ///
    /// Returns [`TraceError::AlreadyRunning`] if already running.
    fn start(&mut self) -> Result<(), TraceError> {
        if self.running {
            return Err(TraceError::AlreadyRunning);
        }
        self.running = true;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns [`TraceError::NotRunning`] if not running.
    fn stop(&mut self) -> Result<TraceSession, TraceError> {
        if !self.running {
            return Err(TraceError::NotRunning);
        }
        self.running = false;
        // Replay pre-recorded events into the session.
        // Cloning (not draining) preserves the list so the provider can be reused
        // across multiple start()+stop() cycles.
        self.session.records.reserve(self.pre_recorded.len());
        for (i, ev) in self.pre_recorded.iter().cloned().enumerate() {
            self.session.push(ev, 1, i.saturating_mul(100) as u64);
        }
        Ok(self.session.clone())
    }
}

// ─── Trace (high-level facade) ────────────────────────────────────────────────

/// High-level trace object that wraps a session and provides rich analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    /// Underlying session.
    pub session: TraceSession,
    /// Optional human-readable description.
    pub description: String,
}

impl Trace {
    /// Create a new [`Trace`] from a session.
    #[must_use]
    pub const fn new(session: TraceSession) -> Self {
        Self {
            session,
            description: String::new(),
        }
    }

    /// Create a new [`Trace`] with a description.
    #[must_use]
    pub fn with_description(session: TraceSession, description: impl Into<String>) -> Self {
        Self {
            session,
            description: description.into(),
        }
    }

    /// Return the number of records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.session.records.len()
    }

    /// Return `true` if there are no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.session.records.is_empty()
    }

    /// Return a reference to all records.
    #[must_use]
    pub fn records(&self) -> &[TraceRecord] {
        &self.session.records
    }

    /// Return the name of the trace.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.session.name
    }

    /// Return the architecture.
    #[must_use]
    pub fn arch(&self) -> &str {
        &self.session.arch
    }

    /// Compute a coverage map.
    #[must_use]
    pub fn coverage_map(&self) -> CoverageMap {
        CoverageMap::from_session(&self.session)
    }

    /// Compute a diff against another trace.
    #[must_use]
    pub fn diff(&self, other: &Self) -> TraceDiff {
        TraceDiff::compute(&self.session, &other.session)
    }

    /// Serialize to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::Serialization`] if serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, TraceError> {
        serde_json::to_vec(self).map_err(|e| TraceError::Serialization(e.to_string()))
    }

    /// Serialize to a pretty JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::Serialization`] if serialization fails.
    pub fn to_json_pretty(&self) -> Result<String, TraceError> {
        serde_json::to_string_pretty(self).map_err(|e| TraceError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::Deserialization`] if deserialization fails.
    pub fn from_json(data: &[u8]) -> Result<Self, TraceError> {
        serde_json::from_slice(data).map_err(|e| TraceError::Deserialization(e.to_string()))
    }

    /// Serialize to binary (bincode-style using `serde_json` with compact format).
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::Serialization`] if serialization fails.
    pub fn to_binary(&self) -> Result<Vec<u8>, TraceError> {
        // Use JSON with a compact header for "binary" compatibility.
        let json =
            serde_json::to_vec(self).map_err(|e| TraceError::Serialization(e.to_string()))?;
        let mut out = Vec::with_capacity(4 + json.len());
        let len: u32 = json.len().try_into().map_err(|_| {
            TraceError::Serialization(format!(
                "serialized trace is too large ({} bytes, max {})",
                json.len(),
                u32::MAX
            ))
        })?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&json);
        Ok(out)
    }

    /// Deserialize from binary format.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::Deserialization`] if deserialization fails.
    pub fn from_binary(data: &[u8]) -> Result<Self, TraceError> {
        if data.len() < 4 {
            return Err(TraceError::Deserialization("too short".into()));
        }
        let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return Err(TraceError::Deserialization("truncated".into()));
        }
        serde_json::from_slice(&data[4..4 + len])
            .map_err(|e| TraceError::Deserialization(e.to_string()))
    }

    /// Return visualization data for this trace.
    #[must_use]
    pub fn visualization_data(&self) -> TraceVisualizationData {
        TraceVisualizationData::from_trace(self)
    }

    /// Build a player for this trace.
    #[must_use]
    pub fn player(&self) -> TracePlayer {
        TracePlayer::new(self.session.clone())
    }

    /// Filter this trace and return a new [`Trace`] with only matching records.
    #[must_use]
    pub fn filtered(&self, filter: &TraceFilter) -> Self {
        let mut new_session = TraceSession::new(
            format!("{}-filtered", self.session.name),
            self.session.arch.clone(),
        );
        for rec in self.session.records.iter().filter(|r| filter.matches(r)) {
            new_session.push(rec.event.clone(), rec.thread_id, rec.timestamp_ns);
        }
        Self::with_description(new_session, format!("filtered({})", self.description))
    }
}

// ─── TraceVisualizationData ───────────────────────────────────────────────────

/// Data suitable for rendering a trace in a UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceVisualizationData {
    /// Total number of events.
    pub total_events: usize,
    /// Unique addresses hit.
    pub unique_addresses: usize,
    /// Event type counts.
    pub event_type_counts: HashMap<String, usize>,
    /// Thread activity: thread ID → event count.
    pub thread_activity: HashMap<u32, usize>,
    /// Top 20 hottest addresses.
    pub hot_addresses: Vec<(u64, u64)>,
    /// Time range (`first_ns`, `last_ns` {).
    pub time_range: (u64, u64),
    /// Number of unique threads.
    pub thread_count: usize,
}

impl TraceVisualizationData {
    /// Build visualization data from a [`Trace`].
    #[must_use]
    pub fn from_trace(trace: &Trace) -> Self {
        let session = &trace.session;
        let total_events = session.records.len();
        let unique_addresses = session.unique_pcs().len();

        let event_type_counts: HashMap<String, usize> = {
            let mut map: HashMap<&'static str, usize> = HashMap::new();
            for rec in &session.records {
                *map.entry(event_type_name(&rec.event)).or_insert(0) += 1;
            }
            map.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
        };

        let thread_activity: HashMap<u32, usize> = {
            let mut map: HashMap<u32, usize> = HashMap::new();
            for rec in &session.records {
                *map.entry(rec.thread_id).or_insert(0) += 1;
            }
            map
        };

        let thread_count = thread_activity.len();

        let cov = CoverageMap::from_session(session);
        let hot_addresses = cov.hottest_addresses(20);

        let first_ns = session.records.first().map_or(0, |r| r.timestamp_ns);
        let last_ns = session.records.last().map_or(0, |r| r.timestamp_ns);

        Self {
            total_events,
            unique_addresses,
            event_type_counts,
            thread_activity,
            hot_addresses,
            time_range: (first_ns, last_ns),
            thread_count,
        }
    }
}

// ─── TraceCompressor / TraceDecompressor ──────────────────────────────────────

/// Run-length compressor for sequences of identical trace events.
pub struct TraceCompressor;

/// A run-length-compressed block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedBlock {
    /// First sequence number in this block.
    pub start_seq: u64,
    /// The event (shared among all runs in this block).
    pub event: TraceEvent,
    /// Number of repetitions.
    pub count: u64,
    /// Thread ID.
    pub thread_id: u32,
    /// Timestamp of the first occurrence.
    pub first_timestamp_ns: u64,
}

impl TraceCompressor {
    /// Compress a session into run-length-encoded blocks.
    #[must_use]
    pub fn compress(session: &TraceSession) -> Vec<CompressedBlock> {
        let mut blocks: Vec<CompressedBlock> = Vec::new();
        for rec in &session.records {
            if let Some(last) = blocks.last_mut()
                && last.event == rec.event
                && last.thread_id == rec.thread_id
            {
                last.count += 1;
                continue;
            }
            blocks.push(CompressedBlock {
                start_seq: rec.seq,
                event: rec.event.clone(),
                count: 1,
                thread_id: rec.thread_id,
                first_timestamp_ns: rec.timestamp_ns,
            });
        }
        blocks
    }

    /// Decompress blocks back into a session.
    #[must_use]
    pub fn decompress(blocks: &[CompressedBlock], name: &str, arch: &str) -> TraceSession {
        let total: u64 = blocks.iter().map(|b| b.count).sum();
        let mut session = TraceSession::new(name, arch);
        session.records.reserve(total as usize);
        for block in blocks {
            for i in 0..block.count {
                session.push(
                    block.event.clone(),
                    block.thread_id,
                    block.first_timestamp_ns + i * 100,
                );
            }
        }
        session
    }

    /// Compute the compression ratio (original / compressed blocks count).
    #[must_use]
    pub fn compression_ratio(original_count: usize, block_count: usize) -> f64 {
        if block_count == 0 {
            return 0.0;
        }
        original_count as f64 / block_count as f64
    }
}

// ─── Legacy types (kept for downstream crates) ────────────────────────────────

/// A single memory access observed during execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemAccess {
    /// Linear address accessed.
    pub address: u64,
    /// Width of the access in bytes.
    pub size: usize,
    /// Value read or written.
    pub value: u64,
}

/// Information about a syscall captured in a trace record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallRecord {
    /// Numeric syscall number.
    pub number: u64,
    /// Symbolic name.
    pub name: String,
    /// Up to six arguments, in ABI order.
    pub args: Vec<u64>,
    /// Return value.
    pub ret: i64,
}

/// One recorded instruction step — legacy type kept for downstream crates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyTraceRecord {
    /// Monotonically increasing trace-step identifier.
    pub id: u64,
    /// Instruction pointer.
    pub address: u64,
    /// OS thread identifier.
    pub thread_id: u32,
    /// Timestamp.
    pub timestamp: u64,
    /// Register file snapshot.
    pub registers: HashMap<String, u64>,
    /// Memory reads.
    pub mem_reads: Vec<MemAccess>,
    /// Memory writes.
    pub mem_writes: Vec<MemAccess>,
    /// Syscall information.
    pub syscall: Option<SyscallRecord>,
}

impl LegacyTraceRecord {
    /// Construct a minimal [`LegacyTraceRecord`].
    #[must_use]
    pub fn new(id: u64, address: u64, thread_id: u32, timestamp: u64) -> Self {
        Self {
            id,
            address,
            thread_id,
            timestamp,
            registers: HashMap::new(),
            mem_reads: Vec::new(),
            mem_writes: Vec::new(),
            syscall: None,
        }
    }

    /// Return `true` if this record has any memory accesses.
    #[must_use]
    pub const fn has_memory_access(&self) -> bool {
        !self.mem_reads.is_empty() || !self.mem_writes.is_empty()
    }

    /// Return `true` if this record has a syscall.
    #[must_use]
    pub const fn has_syscall(&self) -> bool {
        self.syscall.is_some()
    }

    /// Add a memory read.
    pub fn add_mem_read(&mut self, address: u64, size: usize, value: u64) {
        self.mem_reads.push(MemAccess {
            address,
            size,
            value,
        });
    }

    /// Add a memory write.
    pub fn add_mem_write(&mut self, address: u64, size: usize, value: u64) {
        self.mem_writes.push(MemAccess {
            address,
            size,
            value,
        });
    }

    /// Set a register value.
    pub fn set_register(&mut self, name: impl Into<String>, value: u64) {
        self.registers.insert(name.into(), value);
    }
}

// ─── TraceStore (SQLite) ──────────────────────────────────────────────────────

/// SQLite-backed persistent store for execution traces.
pub struct TraceStore {
    conn: Arc<Mutex<Connection>>,
}

impl TraceStore {
    /// Open (or create) a trace database at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on `SQLite` open/schema errors.
    pub fn open(path: &str) -> Result<Self, TraceError> {
        let conn = Connection::open(path)?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Convenience {ructor for an in-memory database.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on schema init failure.
    pub fn open_memory() -> Result<Self, TraceError> {
        Self::open(":memory:")
    }

    fn init_schema(&self) -> Result<(), TraceError> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS trace_records (
                id        INTEGER PRIMARY KEY,
                address   INTEGER NOT NULL,
                thread_id INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                registers TEXT    NOT NULL,
                mem_reads TEXT    NOT NULL,
                mem_writes TEXT   NOT NULL,
                syscall   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_address   ON trace_records(address);
            CREATE INDEX IF NOT EXISTS idx_thread_id ON trace_records(thread_id);
            CREATE INDEX IF NOT EXISTS idx_ts        ON trace_records(timestamp);",
        )?;
        Ok(())
    }

    /// Insert a single [`LegacyTraceRecord`].
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on serialisation or SQL errors.
    pub fn insert(&self, rec: &LegacyTraceRecord) -> Result<(), TraceError> {
        let regs = serde_json::to_string(&rec.registers).map_err(|e| anyhow::anyhow!(e))?;
        let reads = serde_json::to_string(&rec.mem_reads).map_err(|e| anyhow::anyhow!(e))?;
        let writes = serde_json::to_string(&rec.mem_writes).map_err(|e| anyhow::anyhow!(e))?;
        let syscall = rec
            .syscall
            .as_ref()
            .map(|s| serde_json::to_string(s).map_err(|e| anyhow::anyhow!(e)))
            .transpose()?;

        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO trace_records
             (id, address, thread_id, timestamp, registers, mem_reads, mem_writes, syscall)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rec.id,
                rec.address,
                rec.thread_id,
                rec.timestamp,
                regs,
                reads,
                writes,
                syscall
            ],
        )?;
        Ok(())
    }

    /// Insert a batch of records in a single transaction.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on any failure.
    pub fn insert_batch(&self, records: &[LegacyTraceRecord]) -> Result<(), TraceError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        for rec in records {
            let regs = serde_json::to_string(&rec.registers).map_err(|e| anyhow::anyhow!(e))?;
            let reads = serde_json::to_string(&rec.mem_reads).map_err(|e| anyhow::anyhow!(e))?;
            let writes = serde_json::to_string(&rec.mem_writes).map_err(|e| anyhow::anyhow!(e))?;
            let syscall = rec
                .syscall
                .as_ref()
                .map(|s| serde_json::to_string(s).map_err(|e| anyhow::anyhow!(e)))
                .transpose()?;
            tx.execute(
                "INSERT OR REPLACE INTO trace_records
                 (id, address, thread_id, timestamp, registers, mem_reads, mem_writes, syscall)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    rec.id,
                    rec.address,
                    rec.thread_id,
                    rec.timestamp,
                    regs,
                    reads,
                    writes,
                    syscall
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Retrieve a record by its unique id.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] if not found or on SQL error.
    pub fn get(&self, id: u64) -> Result<LegacyTraceRecord, TraceError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, address, thread_id, timestamp, registers, mem_reads, mem_writes, syscall
             FROM trace_records WHERE id = ?1",
        )?;
        let rec = stmt.query_row(params![id], Self::row_to_record)?;
        Ok(rec)
    }

    /// Return up to `limit` records starting at `offset`, ordered by id.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on SQL error.
    pub fn get_range(&self, offset: u64, limit: u64) -> Result<Vec<LegacyTraceRecord>, TraceError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, address, thread_id, timestamp, registers, mem_reads, mem_writes, syscall
             FROM trace_records ORDER BY id LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit, offset], Self::row_to_record)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Total number of records in the store.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on SQL error.
    pub fn count(&self) -> Result<u64, TraceError> {
        let conn = self.conn.lock();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM trace_records", [], |row| row.get(0))?;
        Ok(n as u64)
    }

    /// All distinct addresses executed.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on SQL error.
    pub fn distinct_addresses(&self) -> Result<Vec<u64>, TraceError> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare("SELECT DISTINCT address FROM trace_records ORDER BY address")?;
        let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r? as u64);
        }
        Ok(out)
    }

    /// Records for a specific thread.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on SQL error.
    pub fn by_thread(&self, thread_id: u32) -> Result<Vec<LegacyTraceRecord>, TraceError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, address, thread_id, timestamp, registers, mem_reads, mem_writes, syscall
             FROM trace_records WHERE thread_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![thread_id], Self::row_to_record)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Records whose address falls within `[start, end)`.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on SQL error.
    pub fn by_address_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<LegacyTraceRecord>, TraceError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, address, thread_id, timestamp, registers, mem_reads, mem_writes, syscall
             FROM trace_records WHERE address >= ?1 AND address < ?2 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![start, end], Self::row_to_record)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<LegacyTraceRecord> {
        let id: i64 = row.get(0)?;
        let address: i64 = row.get(1)?;
        let thread_id: i64 = row.get(2)?;
        let timestamp: i64 = row.get(3)?;
        let regs_str: String = row.get(4)?;
        let reads_str: String = row.get(5)?;
        let writes_str: String = row.get(6)?;
        let syscall_str: Option<String> = row.get(7)?;

        let registers: HashMap<String, u64> = serde_json::from_str(&regs_str).map_err(|e| {
            rusqlite::Error::InvalidColumnType(
                4,
                format!("registers JSON invalid: {e}"),
                rusqlite::types::Type::Text,
            )
        })?;
        let mem_reads: Vec<MemAccess> = serde_json::from_str(&reads_str).map_err(|e| {
            rusqlite::Error::InvalidColumnType(
                5,
                format!("mem_reads JSON invalid: {e}"),
                rusqlite::types::Type::Text,
            )
        })?;
        let mem_writes: Vec<MemAccess> = serde_json::from_str(&writes_str).map_err(|e| {
            rusqlite::Error::InvalidColumnType(
                6,
                format!("mem_writes JSON invalid: {e}"),
                rusqlite::types::Type::Text,
            )
        })?;
        let syscall: Option<SyscallRecord> = syscall_str
            .map(|s| {
                serde_json::from_str(&s).map_err(|e| {
                    rusqlite::Error::InvalidColumnType(
                        7,
                        format!("syscall JSON invalid: {e}"),
                        rusqlite::types::Type::Text,
                    )
                })
            })
            .transpose()?;

        Ok(LegacyTraceRecord {
            id: id as u64,
            address: address as u64,
            thread_id: thread_id as u32,
            timestamp: timestamp as u64,
            registers,
            mem_reads,
            mem_writes,
            syscall,
        })
    }
}

// ─── LegacyTraceFilter ────────────────────────────────────────────────────────

/// Criteria for filtering legacy trace records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LegacyTraceFilter {
    /// Keep only records whose `address` is in `[start, end)`.
    pub address_range: Option<(u64, u64)>,
    /// Keep only records from this thread.
    pub thread_id: Option<u32>,
    /// Maximum number of records to return.
    pub instruction_limit: Option<u64>,
    /// Keep only records whose `timestamp` is in `[start, end]`.
    pub time_range: Option<(u64, u64)>,
}

impl LegacyTraceFilter {
    /// Returns `true` if `rec` satisfies every active criterion.
    #[must_use]
    pub const fn matches(&self, rec: &LegacyTraceRecord) -> bool {
        if let Some((lo, hi)) = self.address_range
            && (rec.address < lo || rec.address >= hi)
        {
            return false;
        }
        if let Some(tid) = self.thread_id
            && rec.thread_id != tid
        {
            return false;
        }
        if let Some((t0, t1)) = self.time_range
            && (rec.timestamp < t0 || rec.timestamp > t1)
        {
            return false;
        }
        true
    }

    /// Apply the filter to a slice, respecting `instruction_limit`.
    #[must_use]
    pub fn apply<'a>(&self, records: &'a [LegacyTraceRecord]) -> Vec<&'a LegacyTraceRecord> {
        let filtered = records.iter().filter(|r| self.matches(r));
        if let Some(lim) = self.instruction_limit {
            filtered.take(lim as usize).collect()
        } else {
            filtered.collect()
        }
    }
}

// ─── HeatMap ──────────────────────────────────────────────────────────────────

/// Counts how many times each address was executed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeatMap {
    counts: HashMap<u64, u64>,
}

impl HeatMap {
    /// Create an empty heat-map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one execution of `address`.
    pub fn record(&mut self, address: u64) {
        *self.counts.entry(address).or_insert(0) += 1;
    }

    /// Return the hit count for `address` (0 if never executed).
    #[must_use]
    pub fn count(&self, address: u64) -> u64 {
        self.counts.get(&address).copied().unwrap_or(0)
    }

    /// Return all (address, count) pairs sorted by address.
    #[must_use]
    pub fn sorted_entries(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<_> = self.counts.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_unstable_by_key(|(a, _)| *a);
        v
    }

    /// Return the `n` hottest addresses (by execution count), descending.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<_> = self.counts.iter().map(|(&a, &c)| (a, c)).collect();
        if n < v.len() {
            v.select_nth_unstable_by(n, |a, b| b.1.cmp(&a.1));
            v.truncate(n);
        }
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        v
    }

    /// Total number of recorded executions across all addresses.
    #[must_use]
    pub fn total_executions(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Number of unique addresses in the map.
    #[must_use]
    pub fn unique_addresses(&self) -> usize {
        self.counts.len()
    }

    /// Merge another heat-map into this one.
    pub fn merge(&mut self, other: &Self) {
        for (&addr, &count) in &other.counts {
            *self.counts.entry(addr).or_insert(0) += count;
        }
    }

    /// Return addresses sorted by count descending.
    #[must_use]
    pub fn sorted_by_heat(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<_> = self.counts.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    /// Return the maximum hit count.
    #[must_use]
    pub fn max_count(&self) -> u64 {
        self.counts.values().copied().max().unwrap_or(0)
    }

    /// Return the minimum non-zero hit count.
    #[must_use]
    pub fn min_count(&self) -> u64 {
        self.counts.values().copied().min().unwrap_or(0)
    }
}

// ─── Utility ──────────────────────────────────────────────────────────────────

/// Open a [`TraceStore`] from a file path.
///
/// # Errors
///
/// Returns [`TraceError`] if the path is invalid or the store fails to open.
pub fn open_trace_file(path: &Path) -> Result<TraceStore, TraceError> {
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid path"))?;
    TraceStore::open(path_str)
}

/// Merge a list of sessions into a single session.
///
/// # Errors
///
/// Returns [`TraceError`] if any two sessions have mismatched architectures.
pub fn merge_sessions(sessions: &[TraceSession]) -> Result<TraceSession, TraceError> {
    if sessions.is_empty() {
        return Ok(TraceSession::new("merged", "unknown"));
    }
    let mut merged = TraceSession::new("merged", sessions[0].arch.as_str());
    let total: usize = sessions.iter().map(|s| s.records.len()).sum();
    merged.records.reserve(total);
    for sess in sessions {
        merged.merge(sess)?;
    }
    Ok(merged)
}

/// Compute coverage percentage given a set of hit addresses and total.
#[must_use]
pub fn coverage_percent(hit: usize, total: usize) -> f64 {
    if total == 0 {
        return 100.0;
    }
    (hit as f64 / total as f64) * 100.0
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TraceEvent Display ─────────────────────────────────────────────────

    #[test]
    fn test_event_display_instruction() {
        let e = TraceEvent::Instruction {
            addr: 0x1000,
            size: 4,
        };
        let s = e.to_string();
        assert!(s.contains("1000"));
    }

    #[test]
    fn test_event_display_memread() {
        let e = TraceEvent::MemRead {
            addr: 0x2000,
            size: 8,
            value: 0xdead_beef,
        };
        let s = e.to_string();
        assert!(s.contains("MemRead"));
        assert!(s.contains("2000"));
    }

    #[test]
    fn test_event_display_memwrite() {
        let e = TraceEvent::MemWrite {
            addr: 0x3000,
            size: 4,
            value: 0x1234,
        };
        let s = e.to_string();
        assert!(s.contains("MemWrite"));
    }

    #[test]
    fn test_event_display_call() {
        let e = TraceEvent::Call {
            from: 0x100,
            to: 0x200,
        };
        let s = e.to_string();
        assert!(s.contains("Call"));
        assert!(s.contains("100"));
    }

    #[test]
    fn test_event_display_return() {
        let e = TraceEvent::Return {
            from: 0x200,
            to: 0x105,
        };
        let s = e.to_string();
        assert!(s.contains("Return"));
    }

    #[test]
    fn test_event_display_exception() {
        let e = TraceEvent::Exception {
            code: 0xC000_0005,
            addr: 0x0040_1000,
        };
        let s = e.to_string();
        assert!(s.contains("Exception"));
    }

    #[test]
    fn test_event_display_syscall() {
        let e = TraceEvent::Syscall {
            number: 60,
            args: vec![0, 1, 2],
        };
        let s = e.to_string();
        assert!(s.contains("Syscall"));
        assert!(s.contains("60"));
    }

    #[test]
    fn test_event_display_branch() {
        let e = TraceEvent::Branch {
            from: 0x100,
            to: 0x200,
            taken: true,
        };
        let s = e.to_string();
        assert!(s.contains("Branch"));
        assert!(s.contains("true"));
    }

    #[test]
    fn test_event_display_module_load() {
        let e = TraceEvent::ModuleLoad {
            base: 0x0040_0000,
            size: 0x0001_0000,
            name: "test.dll".into(),
        };
        let s = e.to_string();
        assert!(s.contains("ModuleLoad"));
        assert!(s.contains("test.dll"));
    }

    #[test]
    fn test_event_display_register_change() {
        let e = TraceEvent::RegisterChange {
            name: "rax".into(),
            old_value: 0,
            new_value: 0x1234,
        };
        let s = e.to_string();
        assert!(s.contains("RegChange"));
        assert!(s.contains("rax"));
    }

    // ── TraceEvent predicates ─────────────────────────────────────────────

    #[test]
    fn test_event_is_instruction() {
        assert!(TraceEvent::Instruction { addr: 0, size: 1 }.is_instruction());
        assert!(
            !TraceEvent::MemRead {
                addr: 0,
                size: 1,
                value: 0
            }
            .is_instruction()
        );
    }

    #[test]
    fn test_event_is_memory_access() {
        assert!(
            TraceEvent::MemRead {
                addr: 0,
                size: 1,
                value: 0
            }
            .is_memory_access()
        );
        assert!(
            TraceEvent::MemWrite {
                addr: 0,
                size: 1,
                value: 0
            }
            .is_memory_access()
        );
        assert!(!TraceEvent::Instruction { addr: 0, size: 1 }.is_memory_access());
    }

    #[test]
    fn test_event_is_control_flow() {
        assert!(TraceEvent::Call { from: 0, to: 1 }.is_control_flow());
        assert!(TraceEvent::Return { from: 1, to: 0 }.is_control_flow());
        assert!(
            TraceEvent::Branch {
                from: 0,
                to: 1,
                taken: true
            }
            .is_control_flow()
        );
        assert!(
            !TraceEvent::MemRead {
                addr: 0,
                size: 1,
                value: 0
            }
            .is_control_flow()
        );
    }

    #[test]
    fn test_event_is_syscall() {
        assert!(
            TraceEvent::Syscall {
                number: 1,
                args: vec![]
            }
            .is_syscall()
        );
        assert!(!TraceEvent::Instruction { addr: 0, size: 1 }.is_syscall());
    }

    #[test]
    fn test_event_is_exception() {
        assert!(TraceEvent::Exception { code: 1, addr: 0 }.is_exception());
        assert!(!TraceEvent::Instruction { addr: 0, size: 1 }.is_exception());
    }

    // ── TraceSession ───────────────────────────────────────────────────────

    #[test]
    fn test_session_new() {
        let s = TraceSession::new("test", "x86_64");
        assert_eq!(s.name, "test");
        assert_eq!(s.arch, "x86_64");
        assert!(s.records.is_empty());
    }

    #[test]
    fn test_session_push_instruction() {
        let mut s = TraceSession::new("t", "arm64");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            100,
        );
        assert_eq!(s.records.len(), 1);
        assert_eq!(s.records[0].seq, 0);
        assert_eq!(s.records[0].thread_id, 1);
        assert_eq!(s.records[0].timestamp_ns, 100);
    }

    #[test]
    fn test_session_instruction_count() {
        let mut s = TraceSession::new("t", "x86");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::MemRead {
                addr: 0x2000,
                size: 8,
                value: 0,
            },
            1,
            10,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 3,
            },
            1,
            20,
        );
        assert_eq!(s.instruction_count(), 2);
    }

    #[test]
    fn test_session_unique_addresses() {
        let mut s = TraceSession::new("t", "x86");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
            1,
            10,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            20,
        );
        let addrs = s.unique_addresses();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&0x1000));
        assert!(addrs.contains(&0x1004));
    }

    #[test]
    fn test_session_filter_by_thread() {
        let mut s = TraceSession::new("t", "x86");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x2000,
                size: 4,
            },
            2,
            10,
        );
        let f = TraceFilter {
            thread_id: Some(1),
            ..Default::default()
        };
        let results = s.filter(&f);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].thread_id, 1);
    }

    #[test]
    fn test_session_filter_by_min_addr() {
        let mut s = TraceSession::new("t", "x86");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x2000,
                size: 4,
            },
            1,
            10,
        );
        let f = TraceFilter {
            min_addr: Some(0x1500),
            ..Default::default()
        };
        let results = s.filter(&f);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_session_filter_by_max_addr() {
        let mut s = TraceSession::new("t", "x86");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x2000,
                size: 4,
            },
            1,
            10,
        );
        let f = TraceFilter {
            max_addr: Some(0x1500),
            ..Default::default()
        };
        let results = s.filter(&f);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_session_filter_by_event_type() {
        let mut s = TraceSession::new("t", "x86");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::MemRead {
                addr: 0x2000,
                size: 8,
                value: 0,
            },
            1,
            10,
        );
        s.push(
            TraceEvent::Call {
                from: 0x1008,
                to: 0x2000,
            },
            1,
            20,
        );
        let f = TraceFilter {
            event_types: vec!["Instruction".to_string()],
            ..Default::default()
        };
        let results = s.filter(&f);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_session_all_event_variants() {
        let mut s = TraceSession::new("t", "x86_64");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::MemRead {
                addr: 0x2000,
                size: 8,
                value: 42,
            },
            1,
            10,
        );
        s.push(
            TraceEvent::MemWrite {
                addr: 0x3000,
                size: 4,
                value: 99,
            },
            1,
            20,
        );
        s.push(
            TraceEvent::Call {
                from: 0x1000,
                to: 0x4000,
            },
            1,
            30,
        );
        s.push(
            TraceEvent::Return {
                from: 0x4fff,
                to: 0x1005,
            },
            1,
            40,
        );
        s.push(
            TraceEvent::Exception {
                code: 0xAB,
                addr: 0x5000,
            },
            1,
            50,
        );
        s.push(
            TraceEvent::Syscall {
                number: 1,
                args: vec![0, 1],
            },
            1,
            60,
        );
        assert_eq!(s.records.len(), 7);
    }

    #[test]
    fn test_session_thread_ids() {
        let mut s = TraceSession::new("t", "x86");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x2000,
                size: 4,
            },
            2,
            10,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x3000,
                size: 4,
            },
            3,
            20,
        );
        let tids = s.thread_ids();
        assert_eq!(tids.len(), 3);
        assert!(tids.contains(&1));
        assert!(tids.contains(&2));
        assert!(tids.contains(&3));
    }

    #[test]
    fn test_session_duration_ns() {
        let mut s = TraceSession::new("t", "x86");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            100,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
            1,
            500,
        );
        assert_eq!(s.duration_ns(), 400);
    }

    #[test]
    fn test_session_merge_ok() {
        let mut a = TraceSession::new("a", "x86_64");
        let mut b = TraceSession::new("b", "x86_64");
        a.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        b.push(
            TraceEvent::Instruction {
                addr: 0x2000,
                size: 4,
            },
            1,
            10,
        );
        a.merge(&b).unwrap();
        assert_eq!(a.records.len(), 2);
    }

    #[test]
    fn test_session_merge_arch_mismatch() {
        let mut a = TraceSession::new("a", "x86_64");
        let b = TraceSession::new("b", "arm64");
        assert!(a.merge(&b).is_err());
    }

    #[test]
    fn test_session_slice_ok() {
        let mut s = TraceSession::new("t", "x86");
        for i in 0..5u64 {
            s.push(
                TraceEvent::Instruction {
                    addr: 0x1000 + i * 4,
                    size: 4,
                },
                1,
                i * 10,
            );
        }
        let slice = s.slice(1, 3).unwrap();
        assert_eq!(slice.len(), 3); // seqs 1, 2, 3
    }

    #[test]
    fn test_session_slice_invalid() {
        let s = TraceSession::new("t", "x86");
        assert!(s.slice(5, 3).is_err());
    }

    #[test]
    fn test_session_event_type_counts() {
        let mut s = TraceSession::new("t", "x86");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
            1,
            10,
        );
        s.push(
            TraceEvent::MemRead {
                addr: 0x2000,
                size: 8,
                value: 0,
            },
            1,
            20,
        );
        let counts = s.event_type_counts();
        assert_eq!(counts.get("Instruction").copied(), Some(2));
        assert_eq!(counts.get("MemRead").copied(), Some(1));
    }

    #[test]
    fn test_session_build_heat_map() {
        let mut s = TraceSession::new("t", "x86");
        for _ in 0..3 {
            s.push(
                TraceEvent::Instruction {
                    addr: 0x1000,
                    size: 4,
                },
                1,
                0,
            );
        }
        s.push(
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
            1,
            10,
        );
        let hm = s.build_heat_map();
        assert_eq!(hm.count(0x1000), 3);
        assert_eq!(hm.count(0x1004), 1);
    }

    // ── TraceFilter ────────────────────────────────────────────────────────

    #[test]
    fn test_filter_matches_all_default() {
        let f = TraceFilter::default();
        let r = TraceRecord::new(
            0,
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            100,
        );
        assert!(f.matches(&r));
    }

    #[test]
    fn test_filter_thread_no_match() {
        let f = TraceFilter {
            thread_id: Some(99),
            ..Default::default()
        };
        let r = TraceRecord::new(
            0,
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            100,
        );
        assert!(!f.matches(&r));
    }

    #[test]
    fn test_filter_is_empty() {
        assert!(TraceFilter::new().is_empty());
        let f = TraceFilter {
            thread_id: Some(1),
            ..Default::default()
        };
        assert!(!f.is_empty());
    }

    #[test]
    fn test_filter_instructions_only() {
        let f = TraceFilter::instructions_only();
        let instr = TraceRecord::new(
            0,
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        let mem = TraceRecord::new(
            1,
            TraceEvent::MemRead {
                addr: 0x2000,
                size: 8,
                value: 0,
            },
            1,
            0,
        );
        assert!(f.matches(&instr));
        assert!(!f.matches(&mem));
    }

    #[test]
    fn test_filter_time_range() {
        let f = TraceFilter::time_range(100, 200);
        let r1 = TraceRecord::new(0, TraceEvent::Instruction { addr: 0, size: 1 }, 1, 50);
        let r2 = TraceRecord::new(1, TraceEvent::Instruction { addr: 0, size: 1 }, 1, 150);
        let r3 = TraceRecord::new(2, TraceEvent::Instruction { addr: 0, size: 1 }, 1, 250);
        assert!(!f.matches(&r1));
        assert!(f.matches(&r2));
        assert!(!f.matches(&r3));
    }

    // ── InMemoryTraceProvider ──────────────────────────────────────────────

    #[test]
    fn test_provider_start_stop() {
        let events = vec![
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
        ];
        let mut p = InMemoryTraceProvider::with_pre_recorded("p", "x86_64", events);
        assert!(!p.running);
        p.start().unwrap();
        assert!(p.running);
        let session = p.stop().unwrap();
        assert!(!p.running);
        assert_eq!(session.records.len(), 2);
    }

    #[test]
    fn test_provider_already_running_error() {
        let mut p = InMemoryTraceProvider::with_pre_recorded("p", "x86", vec![]);
        p.start().unwrap();
        let err = p.start().unwrap_err();
        assert!(matches!(err, TraceError::AlreadyRunning));
    }

    #[test]
    fn test_provider_not_running_error() {
        let mut p = InMemoryTraceProvider::with_pre_recorded("p", "x86", vec![]);
        let err = p.stop().unwrap_err();
        assert!(matches!(err, TraceError::NotRunning));
    }

    #[test]
    fn test_provider_name() {
        let p = InMemoryTraceProvider::with_pre_recorded("my-provider", "arm64", vec![]);
        assert_eq!(p.name(), "my-provider");
    }

    // ── HeatMap ────────────────────────────────────────────────────────────

    #[test]
    fn test_heat_map_basic() {
        let mut hm = HeatMap::new();
        hm.record(0x1000);
        hm.record(0x1000);
        hm.record(0x1004);
        assert_eq!(hm.count(0x1000), 2);
        assert_eq!(hm.count(0x1004), 1);
        assert_eq!(hm.count(0x9999), 0);
    }

    #[test]
    fn test_heat_map_top_n() {
        let mut hm = HeatMap::new();
        for _ in 0..5 {
            hm.record(0xaaa);
        }
        for _ in 0..3 {
            hm.record(0xbbb);
        }
        hm.record(0xccc);
        let top = hm.top_n(1);
        assert_eq!(top[0].0, 0xaaa);
    }

    #[test]
    fn test_heat_map_total() {
        let mut hm = HeatMap::new();
        hm.record(0x100);
        hm.record(0x100);
        hm.record(0x104);
        assert_eq!(hm.total_executions(), 3);
        assert_eq!(hm.unique_addresses(), 2);
    }

    #[test]
    fn test_heat_map_merge() {
        let mut a = HeatMap::new();
        let mut b = HeatMap::new();
        a.record(0x100);
        b.record(0x100);
        b.record(0x200);
        a.merge(&b);
        assert_eq!(a.count(0x100), 2);
        assert_eq!(a.count(0x200), 1);
    }

    #[test]
    fn test_heat_map_max_min_count() {
        let mut hm = HeatMap::new();
        for _ in 0..5 {
            hm.record(0x100);
        }
        hm.record(0x200);
        assert_eq!(hm.max_count(), 5);
        assert_eq!(hm.min_count(), 1);
    }

    // ── TraceStore ─────────────────────────────────────────────────────────

    #[test]
    fn test_store_insert_get() {
        let store = TraceStore::open_memory().unwrap();
        let rec = LegacyTraceRecord::new(1, 0x1000, 1, 100);
        store.insert(&rec).unwrap();
        let fetched = store.get(1).unwrap();
        assert_eq!(fetched.address, 0x1000);
    }

    #[test]
    fn test_store_count() {
        let store = TraceStore::open_memory().unwrap();
        assert_eq!(store.count().unwrap(), 0);
        store
            .insert(&LegacyTraceRecord::new(1, 0x100, 1, 10))
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);
    }

    // ── CoverageMap ────────────────────────────────────────────────────────

    #[test]
    fn test_coverage_map_record_hit() {
        let mut cm = CoverageMap::new();
        cm.record_hit(0x1000);
        cm.record_hit(0x1000);
        cm.record_hit(0x2000);
        assert_eq!(cm.hit_count(0x1000), 2);
        assert_eq!(cm.hit_count(0x2000), 1);
        assert_eq!(cm.total_hits(), 3);
        assert_eq!(cm.unique_addresses_hit(), 2);
    }

    #[test]
    fn test_coverage_map_coverage_ratio() {
        let mut cm = CoverageMap::with_total(4);
        cm.record_hit(0x1000);
        cm.record_hit(0x2000);
        assert!((cm.coverage_ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_coverage_map_merge() {
        let mut a = CoverageMap::new();
        let mut b = CoverageMap::new();
        a.record_hit(0x100);
        b.record_hit(0x100);
        b.record_hit(0x200);
        a.merge(&b);
        assert_eq!(a.hit_count(0x100), 2);
        assert_eq!(a.hit_count(0x200), 1);
    }

    #[test]
    fn test_coverage_map_from_session() {
        let mut s = TraceSession::new("t", "x86");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
            1,
            10,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            20,
        );
        let cm = CoverageMap::from_session(&s);
        assert_eq!(cm.hit_count(0x1000), 2);
        assert_eq!(cm.hit_count(0x1004), 1);
    }

    // ── TraceRecorder ──────────────────────────────────────────────────────

    #[test]
    fn test_recorder_basic() {
        let mut rec = TraceRecorder::new("test", "x86_64");
        rec.record_instruction(0x1000, 4, 1, 0);
        rec.record_instruction(0x1004, 4, 1, 10);
        rec.record_mem_read(0x2000, 8, 0xdead_beef, 1, 20);
        assert_eq!(rec.event_count, 3);
        let sess = rec.finish();
        assert_eq!(sess.records.len(), 3);
    }

    #[test]
    fn test_recorder_max_events() {
        let mut rec = TraceRecorder::with_max_events("test", "x86_64", 2);
        rec.record_instruction(0x1000, 4, 1, 0);
        rec.record_instruction(0x1004, 4, 1, 10);
        rec.record_instruction(0x1008, 4, 1, 20); // should be dropped
        assert!(rec.is_full());
        let sess = rec.finish();
        assert_eq!(sess.records.len(), 2);
    }

    #[test]
    fn test_recorder_all_types() {
        let mut rec = TraceRecorder::new("test", "x86_64");
        rec.record_instruction(0x1000, 4, 1, 0);
        rec.record_mem_read(0x2000, 8, 0, 1, 10);
        rec.record_mem_write(0x3000, 4, 0xff, 1, 20);
        rec.record_call(0x1000, 0x2000, 1, 30);
        rec.record_return(0x2000, 0x1005, 1, 40);
        rec.record_exception(0xC000_0005, 0x5000, 1, 50);
        rec.record_syscall(60, vec![0], 1, 60);
        assert_eq!(rec.event_count, 7);
    }

    // ── TracePlayer ────────────────────────────────────────────────────────

    #[test]
    fn test_player_basic() {
        let mut s = TraceSession::new("t", "x86");
        for i in 0..5u64 {
            s.push(
                TraceEvent::Instruction {
                    addr: 0x1000 + i * 4,
                    size: 4,
                },
                1,
                i * 10,
            );
        }
        let mut player = TracePlayer::new(s);
        assert_eq!(player.total(), 5);
        assert!(!player.is_done());
        let first = player.next().unwrap();
        assert_eq!(first.seq, 0);
        assert_eq!(player.remaining(), 4);
    }

    #[test]
    fn test_player_seek_to_seq() {
        let mut s = TraceSession::new("t", "x86");
        for i in 0..5u64 {
            s.push(
                TraceEvent::Instruction {
                    addr: 0x1000 + i * 4,
                    size: 4,
                },
                1,
                i * 10,
            );
        }
        let mut player = TracePlayer::new(s);
        assert!(player.seek_to_seq(3));
        let rec = player.next().unwrap();
        assert_eq!(rec.seq, 3);
    }

    #[test]
    fn test_player_progress() {
        let mut s = TraceSession::new("t", "x86");
        for i in 0..4u64 {
            s.push(
                TraceEvent::Instruction {
                    addr: 0x1000 + i * 4,
                    size: 4,
                },
                1,
                i * 10,
            );
        }
        let mut player = TracePlayer::new(s);
        let _ = player.next();
        let _ = player.next();
        assert!((player.progress() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_player_step_back() {
        let mut s = TraceSession::new("t", "x86");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
            1,
            10,
        );
        let mut player = TracePlayer::new(s);
        let _ = player.next();
        let _ = player.next();
        assert!(player.step_back());
        let rec = player.next().unwrap();
        assert_eq!(rec.seq, 1);
    }

    // ── TraceDiff ──────────────────────────────────────────────────────────

    #[test]
    fn test_diff_identical() {
        let mut s = TraceSession::new("t", "x86_64");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        let diff = TraceDiff::compute(&s, &s);
        assert!(diff.is_identical());
        assert!((diff.similarity() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_diff_completely_different() {
        let mut a = TraceSession::new("a", "x86_64");
        let mut b = TraceSession::new("b", "x86_64");
        a.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        b.push(
            TraceEvent::Instruction {
                addr: 0x9999,
                size: 4,
            },
            1,
            0,
        );
        let diff = TraceDiff::compute(&a, &b);
        assert!(!diff.is_identical());
        assert!((diff.similarity() - 0.0).abs() < 1e-9);
    }

    // ── TraceCompressor ────────────────────────────────────────────────────

    #[test]
    fn test_compressor_compress_decompress() {
        let mut s = TraceSession::new("t", "x86");
        for _ in 0..4 {
            s.push(
                TraceEvent::Instruction {
                    addr: 0x1000,
                    size: 4,
                },
                1,
                0,
            );
        }
        s.push(
            TraceEvent::MemRead {
                addr: 0x2000,
                size: 8,
                value: 0,
            },
            1,
            40,
        );
        let blocks = TraceCompressor::compress(&s);
        assert_eq!(blocks.len(), 2); // 4 identical instructions + 1 different
        let restored = TraceCompressor::decompress(&blocks, "t", "x86");
        assert_eq!(restored.records.len(), 5);
    }

    #[test]
    fn test_compressor_ratio() {
        let ratio = TraceCompressor::compression_ratio(100, 10);
        assert!((ratio - 10.0).abs() < 1e-9);
    }

    // ── Trace facade ───────────────────────────────────────────────────────

    #[test]
    fn test_trace_json_roundtrip() {
        let mut s = TraceSession::new("t", "x86_64");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        let trace = Trace::new(s);
        let json = trace.to_json().unwrap();
        let restored = Trace::from_json(&json).unwrap();
        assert_eq!(restored.len(), 1);
    }

    #[test]
    fn test_trace_binary_roundtrip() {
        let mut s = TraceSession::new("t", "x86_64");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::MemRead {
                addr: 0x2000,
                size: 4,
                value: 0,
            },
            1,
            10,
        );
        let trace = Trace::new(s);
        let bin = trace.to_binary().unwrap();
        let restored = Trace::from_binary(&bin).unwrap();
        assert_eq!(restored.len(), 2);
    }

    #[test]
    fn test_trace_filtered() {
        let mut s = TraceSession::new("t", "x86");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        s.push(
            TraceEvent::MemRead {
                addr: 0x2000,
                size: 8,
                value: 0,
            },
            1,
            10,
        );
        let trace = Trace::new(s);
        let f = TraceFilter::instructions_only();
        let filtered = trace.filtered(&f);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_trace_visualization_data() {
        let mut s = TraceSession::new("t", "x86");
        for i in 0..10u64 {
            s.push(
                TraceEvent::Instruction {
                    addr: 0x1000 + i * 4,
                    size: 4,
                },
                1,
                i * 10,
            );
        }
        let trace = Trace::new(s);
        let viz = trace.visualization_data();
        assert_eq!(viz.total_events, 10);
        assert_eq!(viz.unique_addresses, 10);
    }

    // ── LegacyTraceRecord ─────────────────────────────────────────────────

    #[test]
    fn test_legacy_record_mem_access() {
        let mut r = LegacyTraceRecord::new(1, 0x1000, 1, 0);
        r.add_mem_read(0x2000, 8, 0xdead_beef);
        r.add_mem_write(0x3000, 4, 0xff);
        assert!(r.has_memory_access());
        assert_eq!(r.mem_reads.len(), 1);
        assert_eq!(r.mem_writes.len(), 1);
    }

    #[test]
    fn test_legacy_record_register() {
        let mut r = LegacyTraceRecord::new(1, 0x1000, 1, 0);
        r.set_register("rax", 0x42);
        assert_eq!(r.registers.get("rax").copied(), Some(0x42));
    }

    #[test]
    fn test_legacy_record_has_syscall() {
        let mut r = LegacyTraceRecord::new(1, 0x1000, 1, 0);
        assert!(!r.has_syscall());
        r.syscall = Some(SyscallRecord {
            number: 1,
            name: "write".into(),
            args: vec![1, 2],
            ret: 0,
        });
        assert!(r.has_syscall());
    }

    // ── TraceFrame ─────────────────────────────────────────────────────────

    #[test]
    fn test_trace_frame_registers() {
        let rec = TraceRecord::new(
            0,
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        let mut frame = TraceFrame::new(rec);
        frame.set_register("rax", 0x42);
        assert_eq!(frame.get_register("rax"), Some(0x42));
        assert_eq!(frame.get_register("rbx"), None);
    }

    #[test]
    fn test_trace_frame_instruction_pointer() {
        let rec = TraceRecord::new(
            0,
            TraceEvent::Instruction {
                addr: 0x1234,
                size: 4,
            },
            1,
            0,
        );
        let frame = TraceFrame::new(rec);
        assert_eq!(frame.instruction_pointer(), Some(0x1234));

        let rec2 = TraceRecord::new(
            1,
            TraceEvent::MemRead {
                addr: 0,
                size: 1,
                value: 0,
            },
            1,
            0,
        );
        let frame2 = TraceFrame::new(rec2);
        assert_eq!(frame2.instruction_pointer(), None);
    }

    // ── merge_sessions ─────────────────────────────────────────────────────

    #[test]
    fn test_merge_sessions_empty() {
        let merged = merge_sessions(&[]).unwrap();
        assert_eq!(merged.records.len(), 0);
    }

    #[test]
    fn test_merge_sessions_multiple() {
        let mut a = TraceSession::new("a", "x86_64");
        let mut b = TraceSession::new("b", "x86_64");
        a.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        b.push(
            TraceEvent::Instruction {
                addr: 0x2000,
                size: 4,
            },
            1,
            10,
        );
        let merged = merge_sessions(&[a, b]).unwrap();
        assert_eq!(merged.records.len(), 2);
    }

    // ── coverage_percent ───────────────────────────────────────────────────

    #[test]
    fn test_coverage_percent() {
        assert!((coverage_percent(50, 100) - 50.0).abs() < 1e-9);
        assert!((coverage_percent(0, 0) - 100.0).abs() < 1e-9);
        assert!((coverage_percent(1, 4) - 25.0).abs() < 1e-9);
    }
}

// ─── TraceSink ────────────────────────────────────────────────────────────────

/// Trait for consuming trace events as they are produced.
pub trait TraceSink: Send + Sync {
    /// Called for each new record.
    fn on_record(&mut self, record: &TraceRecord);
    /// Called when the trace stream ends.
    fn on_end(&mut self) {}
    /// Called when tracing starts.
    fn on_start(&mut self) {}
}

/// A sink that collects all records into a vector.
pub struct VecSink {
    /// Collected records.
    pub records: Vec<TraceRecord>,
}

impl VecSink {
    /// Create a new empty sink.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }
}

impl Default for VecSink {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceSink for VecSink {
    fn on_record(&mut self, record: &TraceRecord) {
        self.records.push(record.clone());
    }
}

/// A sink that counts records by type.
pub struct CountingSink {
    /// Total records received.
    pub total: u64,
    /// Counts by event type name.
    pub by_type: HashMap<&'static str, u64>,
}

impl CountingSink {
    /// Create a new counting sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            total: 0,
            by_type: HashMap::new(),
        }
    }
}

impl Default for CountingSink {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceSink for CountingSink {
    fn on_record(&mut self, record: &TraceRecord) {
        self.total += 1;
        *self
            .by_type
            .entry(event_type_name(&record.event))
            .or_insert(0) += 1;
    }
}

/// A sink that forwards events to multiple sinks.
pub struct MultiSink {
    sinks: Vec<Box<dyn TraceSink>>,
}

impl MultiSink {
    /// Create a new multi-sink.
    #[must_use]
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    /// Add a sink.
    pub fn add(&mut self, sink: Box<dyn TraceSink>) {
        self.sinks.push(sink);
    }
}

impl Default for MultiSink {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceSink for MultiSink {
    fn on_record(&mut self, record: &TraceRecord) {
        for s in &mut self.sinks {
            s.on_record(record);
        }
    }

    fn on_start(&mut self) {
        for s in &mut self.sinks {
            s.on_start();
        }
    }

    fn on_end(&mut self) {
        for s in &mut self.sinks {
            s.on_end();
        }
    }
}

// ─── TraceDb ──────────────────────────────────────────────────────────────────

/// `SQLite` + metadata storage for trace sessions.
pub struct TraceDb {
    store: TraceStore,
    /// Name of this database.
    pub name: String,
}

impl TraceDb {
    /// Open or create a trace database at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on SQL errors.
    pub fn open(path: &str, name: &str) -> Result<Self, TraceError> {
        let store = TraceStore::open(path)?;
        Ok(Self {
            store,
            name: name.to_string(),
        })
    }

    /// Open an in-memory database.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on SQL errors.
    pub fn open_memory(name: &str) -> Result<Self, TraceError> {
        Self::open(":memory:", name)
    }

    /// Insert a legacy record.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on SQL errors.
    pub fn insert(&self, rec: &LegacyTraceRecord) -> Result<(), TraceError> {
        self.store.insert(rec)
    }

    /// Insert a batch of records.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on SQL errors.
    pub fn insert_batch(&self, records: &[LegacyTraceRecord]) -> Result<(), TraceError> {
        self.store.insert_batch(records)
    }

    /// Retrieve a record by id.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] if not found.
    pub fn get(&self, id: u64) -> Result<LegacyTraceRecord, TraceError> {
        self.store.get(id)
    }

    /// Count total records.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on SQL errors.
    pub fn count(&self) -> Result<u64, TraceError> {
        self.store.count()
    }

    /// Import a `TraceSession` into the database.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] on SQL errors.
    pub fn import_session(&self, session: &TraceSession) -> Result<(), TraceError> {
        let mut records = Vec::new();
        for rec in &session.records {
            let addr = event_primary_addr(&rec.event);
            records.push(LegacyTraceRecord::new(
                rec.seq,
                addr,
                rec.thread_id,
                rec.timestamp_ns,
            ));
        }
        self.store.insert_batch(&records)
    }
}

// ─── TraceReplay ──────────────────────────────────────────────────────────────

/// Replays a trace session, optionally driving a `TraceSink`.
pub struct TraceReplay {
    session: TraceSession,
    cursor: usize,
    /// Whether replay is paused.
    pub paused: bool,
    /// Breakpoints: set of sequence numbers to pause at.
    pub breakpoints: HashSet<u64>,
}

impl TraceReplay {
    /// Create a new replay from a session.
    #[must_use]
    pub fn new(session: TraceSession) -> Self {
        Self {
            session,
            cursor: 0,
            paused: false,
            breakpoints: HashSet::new(),
        }
    }

    /// Add a breakpoint at sequence number `seq`.
    pub fn add_breakpoint(&mut self, seq: u64) {
        self.breakpoints.insert(seq);
    }

    /// Remove a breakpoint.
    pub fn remove_breakpoint(&mut self, seq: u64) {
        self.breakpoints.remove(&seq);
    }

    /// Step one record forward, returning it if available.
    pub fn step(&mut self) -> Option<&TraceRecord> {
        let rec = self.session.records.get(self.cursor);
        if let Some(r) = rec {
            if self.breakpoints.contains(&r.seq) {
                self.paused = true;
            }
            self.cursor += 1;
        }
        rec
    }

    /// Run until end or a breakpoint, passing each record to `sink`.
    pub fn run(&mut self, sink: &mut dyn TraceSink) {
        self.paused = false;
        while !self.paused {
            if let Some(rec) = self.session.records.get(self.cursor) {
                if self.breakpoints.contains(&rec.seq) {
                    self.paused = true;
                    break;
                }
                sink.on_record(rec);
                self.cursor += 1;
            } else {
                sink.on_end();
                break;
            }
        }
    }

    /// Run all records through `sink`.
    pub fn run_all(&mut self, sink: &mut dyn TraceSink) {
        sink.on_start();
        for rec in &self.session.records {
            sink.on_record(rec);
        }
        sink.on_end();
    }

    /// Seek to sequence number `seq`.
    pub fn seek_to(&mut self, seq: u64) -> bool {
        if let Some(idx) = self.session.records.iter().position(|r| r.seq == seq) {
            self.cursor = idx;
            true
        } else {
            false
        }
    }

    /// Return current cursor position.
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Return whether replay is complete.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.cursor >= self.session.records.len()
    }

    /// Reset to beginning.
    pub const fn reset(&mut self) {
        self.cursor = 0;
        self.paused = false;
    }
}

// ─── TraceBackwardSearch ──────────────────────────────────────────────────────

/// Searches backwards from a position in a trace.
pub struct TraceBackwardSearch<'a> {
    session: &'a TraceSession,
    /// Starting position (inclusive).
    pub start_seq: u64,
}

impl<'a> TraceBackwardSearch<'a> {
    /// Create a new backward search from `start_seq`.
    #[must_use]
    pub const fn new(session: &'a TraceSession, start_seq: u64) -> Self {
        Self { session, start_seq }
    }

    /// Find the last record before `start_seq` where `predicate` is true.
    #[must_use]
    pub fn find_last<F>(&self, predicate: F) -> Option<&TraceRecord>
    where
        F: Fn(&TraceRecord) -> bool,
    {
        self.session
            .records
            .iter()
            .rev()
            .find(|r| r.seq <= self.start_seq && predicate(r))
    }

    /// Find all records before `start_seq` where `predicate` is true.
    #[must_use]
    pub fn find_all<F>(&self, predicate: F) -> Vec<&TraceRecord>
    where
        F: Fn(&TraceRecord) -> bool,
    {
        self.session
            .records
            .iter()
            .filter(|r| r.seq <= self.start_seq && predicate(r))
            .collect()
    }

    /// Find the previous `Call` event before `start_seq`.
    #[must_use]
    pub fn find_prev_call(&self) -> Option<&TraceRecord> {
        self.find_last(|r| matches!(r.event, TraceEvent::Call { .. }))
    }

    /// Find the previous instruction at `addr`.
    #[must_use]
    pub fn find_prev_instruction_at(&self, addr: u64) -> Option<&TraceRecord> {
        self.find_last(|r| matches!(r.event, TraceEvent::Instruction { addr: a, .. } if a == addr))
    }
}

// ─── TraceDivergenceDetector ──────────────────────────────────────────────────

/// Detects where two execution traces diverge.
pub struct TraceDivergenceDetector;

/// Divergence point between two traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergencePoint {
    /// Sequence number at the divergence.
    pub seq: u64,
    /// Event in the left trace.
    pub left_event: TraceEvent,
    /// Event in the right trace.
    pub right_event: TraceEvent,
}

impl TraceDivergenceDetector {
    /// Find the first point where `left` and `right` diverge.
    #[must_use]
    pub fn find_first_divergence(
        left: &TraceSession,
        right: &TraceSession,
    ) -> Option<DivergencePoint> {
        let min_len = left.records.len().min(right.records.len());
        for i in 0..min_len {
            let lr = &left.records[i];
            let rr = &right.records[i];
            if lr.event != rr.event || lr.thread_id != rr.thread_id {
                return Some(DivergencePoint {
                    seq: lr.seq,
                    left_event: lr.event.clone(),
                    right_event: rr.event.clone(),
                });
            }
        }
        None
    }

    /// Return the number of matching records at the start of both traces.
    #[must_use]
    pub fn common_prefix_length(left: &TraceSession, right: &TraceSession) -> usize {
        let min_len = left.records.len().min(right.records.len());
        let mut count = 0;
        for i in 0..min_len {
            if left.records[i].event == right.records[i].event {
                count += 1;
            } else {
                break;
            }
        }
        count
    }
}

// ─── TraceSymbolResolver ──────────────────────────────────────────────────────

/// Resolves addresses to symbols during trace replay.
pub struct TraceSymbolResolver {
    /// Symbol map: address → name.
    symbols: BTreeMap<u64, String>,
    /// Module ranges: (start, end, name).
    modules: Vec<(u64, u64, String)>,
}

impl TraceSymbolResolver {
    /// Create a new empty symbol resolver.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            symbols: BTreeMap::new(),
            modules: Vec::new(),
        }
    }

    /// Add a symbol.
    pub fn add_symbol(&mut self, addr: u64, name: impl Into<String>) {
        self.symbols.insert(addr, name.into());
    }

    /// Add a module range.
    pub fn add_module(&mut self, start: u64, end: u64, name: impl Into<String>) {
        self.modules.push((start, end, name.into()));
    }

    /// Resolve an address to a symbol name.
    #[must_use]
    pub fn resolve(&self, addr: u64) -> Option<&str> {
        self.symbols.get(&addr).map(std::string::String::as_str)
    }

    /// Return the module name containing `, addr`.
    #[must_use]
    pub fn module_for(&self, addr: u64) -> Option<&str> {
        self.modules.iter().find_map(|(s, e, n)| {
            if addr >= *s && addr < *e {
                Some(n.as_str())
            } else {
                None
            }
        })
    }

    /// Format an address with symbol if known.
    #[must_use]
    pub fn format_addr(&self, addr: u64) -> String {
        if let Some(sym) = self.resolve(addr) {
            format!("{sym} (0x{addr:x})")
        } else if let Some(module) = self.module_for(addr) {
            format!("{module}+0x{addr:x}")
        } else {
            format!("0x{addr:x}")
        }
    }
}

impl Default for TraceSymbolResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── TraceFunctionCallTree ────────────────────────────────────────────────────

/// Node in the function call tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTreeNode {
    /// Function address.
    pub addr: u64,
    /// Optional symbol name.
    pub name: Option<String>,
    /// Sequence number when called.
    pub called_at: u64,
    /// Sequence number when returned (if known).
    pub returned_at: Option<u64>,
    /// Children (callees).
    pub children: Vec<Self>,
    /// Number of instructions executed in this frame.
    pub instruction_count: u64,
}

impl CallTreeNode {
    /// Create a new call tree node.
    #[must_use]
    pub const fn new(addr: u64, called_at: u64) -> Self {
        Self {
            addr,
            name: None,
            called_at,
            returned_at: None,
            children: Vec::new(),
            instruction_count: 0,
        }
    }

    /// Total number of nodes in the subtree (inclusive).
    #[must_use]
    pub fn subtree_size(&self) -> usize {
        1 + self.children.iter().map(Self::subtree_size).sum::<usize>()
    }

    /// Maximum depth of the subtree.
    #[must_use]
    pub fn depth(&self) -> usize {
        if self.children.is_empty() {
            1
        } else {
            1 + self.children.iter().map(Self::depth).max().unwrap_or(0)
        }
    }
}

/// Reconstructs a function call tree from a trace session.
pub struct TraceFunctionCallTree;

impl TraceFunctionCallTree {
    /// Build a call tree from a session.
    #[must_use]
    pub fn build(session: &TraceSession) -> Vec<CallTreeNode> {
        let mut roots: Vec<CallTreeNode> = Vec::new();
        let mut stack: Vec<CallTreeNode> = Vec::new();

        for rec in &session.records {
            match &rec.event {
                TraceEvent::Call { to, .. } => {
                    let node = CallTreeNode::new(*to, rec.seq);
                    stack.push(node);
                }
                TraceEvent::Return { .. } => {
                    if let Some(mut node) = stack.pop() {
                        node.returned_at = Some(rec.seq);
                        if let Some(parent) = stack.last_mut() {
                            parent.children.push(node);
                        } else {
                            roots.push(node);
                        }
                    }
                }
                TraceEvent::Instruction { .. } => {
                    if let Some(top) = stack.last_mut() {
                        top.instruction_count += 1;
                    }
                }
                _ => {}
            }
        }

        // Drain remaining frames
        while let Some(node) = stack.pop() {
            if let Some(parent) = stack.last_mut() {
                parent.children.push(node);
            } else {
                roots.push(node);
            }
        }

        roots
    }
}

// ─── TraceLoopDetector ────────────────────────────────────────────────────────

/// Identifies loops in a trace.
pub struct TraceLoopDetector;

/// A detected loop in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedLoop {
    /// Loop entry address.
    pub entry_addr: u64,
    /// Number of iterations detected.
    pub iteration_count: u64,
    /// First occurrence (seq number).
    pub first_seq: u64,
    /// Last occurrence (seq number).
    pub last_seq: u64,
}

impl TraceLoopDetector {
    /// Detect loops in a session by finding repeated address visits.
    #[must_use]
    pub fn detect(session: &TraceSession, min_iterations: u64) -> Vec<DetectedLoop> {
        let mut addr_seqs: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for rec in &session.records {
            if let TraceEvent::Instruction { addr, .. } = rec.event {
                addr_seqs.entry(addr).or_default().push(rec.seq);
            }
        }

        let mut loops = Vec::new();
        for (addr, seqs) in addr_seqs {
            let count = seqs.len() as u64;
            if count >= min_iterations {
                loops.push(DetectedLoop {
                    entry_addr: addr,
                    iteration_count: count,
                    first_seq: seqs[0],
                    last_seq: *seqs.last().unwrap(),
                });
            }
        }
        loops.sort_unstable_by(|a, b| b.iteration_count.cmp(&a.iteration_count));
        loops
    }
}

// ─── TraceAnomalyDetector ─────────────────────────────────────────────────────

/// Detects unusual patterns in a trace.
pub struct TraceAnomalyDetector;

/// A detected anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceAnomaly {
    /// Sequence number where the anomaly was detected.
    pub seq: u64,
    /// Description of the anomaly.
    pub description: String,
    /// Severity: 0 = info, 1 = warning, 2 = error.
    pub severity: u8,
}

impl TraceAnomalyDetector {
    /// Run anomaly detection on a session.
    #[must_use]
    pub fn detect(session: &TraceSession) -> Vec<TraceAnomaly> {
        let mut anomalies = Vec::new();
        let mut prev_addr: Option<u64> = None;
        let mut call_depth: i64 = 0;

        for rec in &session.records {
            match &rec.event {
                TraceEvent::Exception { code, addr } => {
                    anomalies.push(TraceAnomaly {
                        seq: rec.seq,
                        description: format!("Exception 0x{code:x} at 0x{addr:x}"),
                        severity: 2,
                    });
                }
                TraceEvent::Call { .. } => {
                    call_depth += 1;
                }
                TraceEvent::Return { .. } => {
                    call_depth -= 1;
                    if call_depth < 0 {
                        anomalies.push(TraceAnomaly {
                            seq: rec.seq,
                            description: "Return with no matching call".to_string(),
                            severity: 1,
                        });
                        call_depth = 0;
                    }
                }
                TraceEvent::Instruction { addr, .. } => {
                    if let Some(prev) = prev_addr {
                        // Detect large jumps (> 4MB) that are not calls/returns
                        let delta = addr.abs_diff(prev);
                        if delta > 0x40_0000 {
                            anomalies.push(TraceAnomaly {
                                seq: rec.seq,
                                description: format!(
                                    "Large jump of 0x{delta:x} bytes at 0x{addr:x}"
                                ),
                                severity: 1,
                            });
                        }
                    }
                    prev_addr = Some(*addr);
                }
                _ => {}
            }
        }
        anomalies
    }
}

// ─── TraceStatistics ─────────────────────────────────────────────────────────

/// Statistics about a trace session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStatistics {
    /// Total records.
    pub total_records: u64,
    /// Instruction count.
    pub instruction_count: u64,
    /// Memory read count.
    pub mem_read_count: u64,
    /// Memory write count.
    pub mem_write_count: u64,
    /// Call count.
    pub call_count: u64,
    /// Return count.
    pub return_count: u64,
    /// Exception count.
    pub exception_count: u64,
    /// Syscall count.
    pub syscall_count: u64,
    /// Branch count.
    pub branch_count: u64,
    /// Taken branch count.
    pub taken_branch_count: u64,
    /// Unique addresses.
    pub unique_addresses: u64,
    /// Unique threads.
    pub unique_threads: u64,
    /// Duration in nanoseconds.
    pub duration_ns: u64,
    /// Average instructions per call.
    pub avg_instr_per_call: f64,
}

impl TraceStatistics {
    /// Compute statistics from a session.
    #[must_use]
    pub fn compute(session: &TraceSession) -> Self {
        let mut stats = Self {
            total_records: session.records.len() as u64,
            instruction_count: 0,
            mem_read_count: 0,
            mem_write_count: 0,
            call_count: 0,
            return_count: 0,
            exception_count: 0,
            syscall_count: 0,
            branch_count: 0,
            taken_branch_count: 0,
            unique_addresses: 0,
            unique_threads: 0,
            duration_ns: session.duration_ns(),
            avg_instr_per_call: 0.0,
        };

        for rec in &session.records {
            match &rec.event {
                TraceEvent::Instruction { .. } => stats.instruction_count += 1,
                TraceEvent::MemRead { .. } => stats.mem_read_count += 1,
                TraceEvent::MemWrite { .. } => stats.mem_write_count += 1,
                TraceEvent::Call { .. } => stats.call_count += 1,
                TraceEvent::Return { .. } => stats.return_count += 1,
                TraceEvent::Exception { .. } => stats.exception_count += 1,
                TraceEvent::Syscall { .. } => stats.syscall_count += 1,
                TraceEvent::Branch { taken, .. } => {
                    stats.branch_count += 1;
                    if *taken {
                        stats.taken_branch_count += 1;
                    }
                }
                _ => {}
            }
        }

        stats.unique_addresses = session.unique_pcs().len() as u64;
        stats.unique_threads = session.thread_ids().len() as u64;
        if stats.call_count > 0 {
            stats.avg_instr_per_call = stats.instruction_count as f64 / stats.call_count as f64;
        }
        stats
    }

    /// Return the branch taken ratio (taken / total branches).
    #[must_use]
    pub fn branch_taken_ratio(&self) -> f64 {
        if self.branch_count == 0 {
            return 0.0;
        }
        self.taken_branch_count as f64 / self.branch_count as f64
    }
}

// ─── TraceHeatmap ─────────────────────────────────────────────────────────────

/// Execution frequency per address (alias for `HeatMap` with extra methods).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceHeatmap {
    inner: HeatMap,
}

impl TraceHeatmap {
    /// Create an empty heatmap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: HeatMap::new(),
        }
    }

    /// Build from a session.
    #[must_use]
    pub fn from_session(session: &TraceSession) -> Self {
        let mut hm = Self::new();
        for rec in &session.records {
            if let TraceEvent::Instruction { addr, .. } = rec.event {
                hm.inner.record(addr);
            }
        }
        hm
    }

    /// Hit count for an address.
    #[must_use]
    pub fn count(&self, addr: u64) -> u64 {
        self.inner.count(addr)
    }

    /// Top N hottest addresses.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(u64, u64)> {
        self.inner.top_n(n)
    }

    /// Hottest address.
    #[must_use]
    pub fn hottest(&self) -> Option<(u64, u64)> {
        self.inner.top_n(1).into_iter().next()
    }

    /// Total hits.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.inner.total_executions()
    }

    /// Number of unique addresses.
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.inner.unique_addresses()
    }

    /// Generate an ASCII heat bar for `addr` (relative to max).
    #[must_use]
    pub fn heat_bar(&self, addr: u64, width: usize) -> String {
        let max = self.inner.max_count();
        if max == 0 {
            return " ".repeat(width);
        }
        let count = self.inner.count(addr);
        let filled = (count * width as u64 / max) as usize;
        format!(
            "{}{}",
            "#".repeat(filled),
            " ".repeat(width.saturating_sub(filled))
        )
    }
}

// ─── IntelPtIntegration ───────────────────────────────────────────────────────

/// Type alias: Intel PT trace session.
pub type IntelPtSession = TraceSession;

/// Type alias: Intel PT trace record.
pub type IntelPtRecord = TraceRecord;

/// Type alias: Intel PT trace event.
pub type IntelPtEvent = TraceEvent;

// ─── CoreSightIntegration ─────────────────────────────────────────────────────

/// Type alias: `CoreSight` trace session.
pub type CoreSightSession = TraceSession;

/// Type alias: `CoreSight` trace record.
pub type CoreSightRecord = TraceRecord;

// ─── TraceIndex extensions ────────────────────────────────────────────────────

impl TraceIndex {
    /// Build the index from a full session (builds `seq_to_idx` mapping).
    pub fn build_from_session(&mut self, session: &TraceSession) {
        for (idx, rec) in session.records.iter().enumerate() {
            self.insert_record(rec);
            self.seq_to_idx.insert(rec.seq, idx);
        }
    }

    /// Return the session index for a sequence number.
    #[must_use]
    pub fn index_of_seq(&self, seq: u64) -> Option<usize> {
        self.seq_to_idx.get(&seq).copied()
    }
}

// ─── TraceFilter builder methods ─────────────────────────────────────────────

/// A view of a [`Trace`] produced by applying a [`TraceFilter`].
///
/// Holds references to the records that matched the filter criteria so that
/// callers can inspect or iterate them without cloning the entire session.
#[derive(Debug)]
pub struct FilteredTrace<'a> {
    /// Matching records, in original order.
    pub records: Vec<&'a TraceRecord>,
    /// The filter that produced this view.
    pub filter: TraceFilter,
}

impl<'a> FilteredTrace<'a> {
    /// Return the number of matching records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Return `true` if no records matched.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterate over the matching records.
    pub fn iter(&self) -> impl Iterator<Item = &&'a TraceRecord> {
        self.records.iter()
    }
}

impl TraceFilter {
    /// Return a new filter restricted to address range `[start, end)`.
    ///
    /// This is a builder method that merges with any existing address bounds,
    /// so multiple calls narrow the range further.
    #[must_use]
    pub fn by_address_range(mut self, start: u64, end: u64) -> Self {
        self.min_addr = Some(match self.min_addr {
            Some(existing) => existing.max(start),
            None => start,
        });
        self.max_addr = Some(match self.max_addr {
            Some(existing) => existing.min(end),
            None => end,
        });
        self
    }

    /// Return a new filter that only passes events belonging to `module_name`.
    ///
    /// Module membership is inferred from [`TraceEvent::ModuleLoad`] records
    /// that precede each event: an event at address `addr` is considered to
    /// belong to a module if `addr` falls within the range
    /// `[module.base, module.base + module.size)`.  Because this check requires
    /// layout context that the filter criteria alone do not carry, this method
    /// stores the module name in the `kinds` list as a sentinel so that
    /// [`TraceFilter::matches`] can be extended.  For practical filtering of a
    /// full session use [`TraceFilter::apply_by_module`].
    #[must_use]
    pub fn by_module(mut self, module_name: &str) -> Self {
        self.kinds.push(format!("module:{module_name}"));
        self
    }

    /// Return a new filter restricted to thread `tid`.
    #[must_use]
    pub const fn by_thread(mut self, tid: u32) -> Self {
        self.thread_id = Some(tid);
        self
    }

    /// Return a new filter that only passes events whose type name matches
    /// the discriminant of the given [`TraceEvent`] variant.
    ///
    /// `event_type` should be one of the `event_type_name` strings such as
    /// `"Instruction"`, `"MemRead"`, `"Call"`, etc.  Internally this appends
    /// to `event_types` so calling this method multiple times ORs the types.
    #[must_use]
    pub fn by_event_type(mut self, event_type: &str) -> Self {
        self.event_types.push(event_type.to_string());
        self
    }

    /// Chain `other` onto this filter, merging both sets of criteria.
    ///
    /// Address ranges are intersected; thread IDs and timestamps are taken
    /// from `other` when `self` is unset, otherwise `other` wins only when it
    /// is more restrictive.  Event-type lists are unioned.
    #[must_use]
    pub fn and_then(mut self, other: Self) -> Self {
        // Intersect address bounds.
        if let Some(o_min) = other.min_addr {
            self.min_addr = Some(match self.min_addr {
                Some(s_min) => s_min.max(o_min),
                None => o_min,
            });
        }
        if let Some(o_max) = other.max_addr {
            self.max_addr = Some(match self.max_addr {
                Some(s_max) => s_max.min(o_max),
                None => o_max,
            });
        }
        // Thread: other overrides.
        if other.thread_id.is_some() {
            self.thread_id = other.thread_id;
        }
        // Timestamps: take the more restrictive bound.
        if let Some(o_min_ts) = other.min_timestamp_ns {
            self.min_timestamp_ns = Some(match self.min_timestamp_ns {
                Some(s) => s.max(o_min_ts),
                None => o_min_ts,
            });
        }
        if let Some(o_max_ts) = other.max_timestamp_ns {
            self.max_timestamp_ns = Some(match self.max_timestamp_ns {
                Some(s) => s.min(o_max_ts),
                None => o_max_ts,
            });
        }
        // Seq range: take the intersection.
        if let Some((o_start, o_end)) = other.seq_range {
            self.seq_range = Some(match self.seq_range {
                Some((s_start, s_end)) => (s_start.max(o_start), s_end.min(o_end)),
                None => (o_start, o_end),
            });
        }
        // Event types: union.
        self.event_types.extend(other.event_types);
        self.kinds.extend(other.kinds);
        self
    }

    /// Apply this filter to `trace`, returning a [`FilteredTrace`] view.
    #[must_use]
    pub fn apply_to<'a>(&self, trace: &'a Trace) -> FilteredTrace<'a> {
        let records = trace
            .session
            .records
            .iter()
            .filter(|r| self.matches(r))
            .collect();
        FilteredTrace {
            records,
            filter: self.clone(),
        }
    }

    /// Apply module-based filtering to `trace`.
    ///
    /// Builds a module layout map from [`TraceEvent::ModuleLoad`] records,
    /// then returns all records whose primary address falls within the named
    /// module's address range.
    #[must_use]
    pub fn apply_by_module<'a>(trace: &'a Trace, module_name: &str) -> FilteredTrace<'a> {
        // Walk records once to build the module map.
        let mut modules: Vec<(u64, u64, String)> = Vec::new(); // (base, end, name)
        for rec in &trace.session.records {
            if let TraceEvent::ModuleLoad { base, size, name } = &rec.event {
                modules.push((*base, base.saturating_add(*size), name.clone()));
            }
        }
        let records: Vec<&TraceRecord> = trace
            .session
            .records
            .iter()
            .filter(|r| {
                let addr = event_primary_addr(&r.event);
                modules.iter().any(|(base, end, name)| {
                    name.as_str() == module_name && addr >= *base && addr < *end
                })
            })
            .collect();
        FilteredTrace {
            records,
            filter: Self::new().by_module(module_name),
        }
    }
}

// ─── TraceSummary ─────────────────────────────────────────────────────────────

/// Compact statistics computed from a [`Trace`].
///
/// Provides the fields required by the task specification with names that
/// match exactly.  The existing [`TraceStatistics`] type (which operates on
/// [`TraceSession`]) continues to exist unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSummary {
    /// Total number of events in the trace.
    pub total_events: u64,
    /// Number of unique instruction addresses seen.
    pub unique_addresses: u64,
    /// Number of [`TraceEvent::MemRead`] events.
    pub memory_reads: u64,
    /// Number of [`TraceEvent::MemWrite`] events.
    pub memory_writes: u64,
    /// Number of [`TraceEvent::Call`] events.
    pub calls: u64,
    /// Number of [`TraceEvent::Return`] events.
    pub returns: u64,
    /// Top-20 hottest addresses by hit count: `(address, hit_count)`.
    pub hot_addresses: Vec<(u64, u64)>,
}

impl TraceSummary {
    /// Compute a [`TraceSummary`] from the given trace.
    #[must_use]
    pub fn compute(trace: &Trace) -> Self {
        let session = &trace.session;
        let total_events = session.records.len() as u64;
        let mut memory_reads = 0u64;
        let mut memory_writes = 0u64;
        let mut calls = 0u64;
        let mut returns = 0u64;
        let mut addr_counts: HashMap<u64, u64> = HashMap::new();

        for rec in &session.records {
            match &rec.event {
                TraceEvent::MemRead { .. } => memory_reads += 1,
                TraceEvent::MemWrite { .. } => memory_writes += 1,
                TraceEvent::Call { .. } => calls += 1,
                TraceEvent::Return { .. } => returns += 1,
                TraceEvent::Instruction { addr, .. } => {
                    *addr_counts.entry(*addr).or_insert(0) += 1;
                }
                _ => {}
            }
        }

        let unique_addresses = addr_counts.len() as u64;

        // Build top-20 hot addresses.
        let mut hot: Vec<(u64, u64)> = addr_counts.into_iter().collect();
        hot.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        hot.truncate(20);

        Self {
            total_events,
            unique_addresses,
            memory_reads,
            memory_writes,
            calls,
            returns,
            hot_addresses: hot,
        }
    }

    /// Return the address with the highest hit count, if any.
    #[must_use]
    pub fn hottest_address(&self) -> Option<(u64, u64)> {
        self.hot_addresses.first().copied()
    }

    /// Return the memory-access ratio (reads + writes) / `total_events`.
    #[must_use]
    pub fn memory_access_ratio(&self) -> f64 {
        if self.total_events == 0 {
            return 0.0;
        }
        (self.memory_reads + self.memory_writes) as f64 / self.total_events as f64
    }
}

// ─── TraceDiffResult ──────────────────────────────────────────────────────────

/// The result of diffing two [`Trace`] instances.
///
/// Identifies which instruction addresses appear exclusively in one trace,
/// and where the two traces first diverge in their sequential event stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDiffResult {
    /// Unique instruction addresses found only in trace `a`.
    pub addresses_only_in_a: Vec<u64>,
    /// Unique instruction addresses found only in trace `b`.
    pub addresses_only_in_b: Vec<u64>,
    /// Primary address of the first event where the two traces differ
    /// (comparing event by event in sequence-number order).  `None` if the
    /// traces are identical up to the length of the shorter one.
    pub divergence_point: Option<u64>,
}

impl TraceDiffResult {
    /// Return `true` if the two traces are structurally identical.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.addresses_only_in_a.is_empty()
            && self.addresses_only_in_b.is_empty()
            && self.divergence_point.is_none()
    }
}

/// Diff two traces and return a [`TraceDiffResult`].
///
/// Address sets are derived from [`TraceEvent::Instruction`] events only.
/// Divergence is found by walking both event sequences in lock-step and
/// comparing `(event_type_name, primary_addr)` pairs.
#[must_use]
pub fn diff_traces(a: &Trace, b: &Trace) -> TraceDiffResult {
    // Build instruction-address sets.
    let addrs_a: HashSet<u64> = a
        .session
        .records
        .iter()
        .filter_map(|r| {
            if let TraceEvent::Instruction { addr, .. } = r.event {
                Some(addr)
            } else {
                None
            }
        })
        .collect();

    let addrs_b: HashSet<u64> = b
        .session
        .records
        .iter()
        .filter_map(|r| {
            if let TraceEvent::Instruction { addr, .. } = r.event {
                Some(addr)
            } else {
                None
            }
        })
        .collect();

    let mut addresses_only_in_a: Vec<u64> = addrs_a.difference(&addrs_b).copied().collect();
    addresses_only_in_a.sort_unstable();

    let mut addresses_only_in_b: Vec<u64> = addrs_b.difference(&addrs_a).copied().collect();
    addresses_only_in_b.sort_unstable();

    // Find the first divergence point by walking both sequences.
    let divergence_point = a
        .session
        .records
        .iter()
        .zip(b.session.records.iter())
        .find(|(ra, rb)| {
            event_type_name(&ra.event) != event_type_name(&rb.event)
                || event_primary_addr(&ra.event) != event_primary_addr(&rb.event)
        })
        .map(|(ra, _rb)| event_primary_addr(&ra.event));

    TraceDiffResult {
        addresses_only_in_a,
        addresses_only_in_b,
        divergence_point,
    }
}

// ─── TraceSink tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    #[test]
    fn test_vec_sink() {
        let mut sink = VecSink::new();
        let rec = TraceRecord::new(
            0,
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        sink.on_record(&rec);
        assert_eq!(sink.records.len(), 1);
    }

    #[test]
    fn test_counting_sink() {
        let mut sink = CountingSink::new();
        let r1 = TraceRecord::new(
            0,
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        let r2 = TraceRecord::new(
            1,
            TraceEvent::MemRead {
                addr: 0x2000,
                size: 8,
                value: 0,
            },
            1,
            10,
        );
        let r3 = TraceRecord::new(
            2,
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
            1,
            20,
        );
        sink.on_record(&r1);
        sink.on_record(&r2);
        sink.on_record(&r3);
        assert_eq!(sink.total, 3);
        assert_eq!(sink.by_type.get("Instruction").copied(), Some(2));
        assert_eq!(sink.by_type.get("MemRead").copied(), Some(1));
    }

    #[test]
    fn test_trace_db_memory() {
        let db = TraceDb::open_memory("test_db").unwrap();
        let mut rec = LegacyTraceRecord::new(1, 0x1000, 1, 100);
        rec.add_mem_read(0x2000, 4, 0xDEAD);
        db.insert(&rec).unwrap();
        let got = db.get(1).unwrap();
        assert_eq!(got.address, 0x1000);
    }

    #[test]
    fn test_trace_db_import_session() {
        let db = TraceDb::open_memory("import_test").unwrap();
        let mut session = TraceSession::new("t", "x86_64");
        session.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        session.push(
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
            1,
            100,
        );
        db.import_session(&session).unwrap();
        assert_eq!(db.count().unwrap(), 2);
    }

    #[test]
    fn test_trace_replay_basic() {
        let mut session = TraceSession::new("t", "x86");
        session.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        session.push(
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
            1,
            10,
        );
        let mut replay = TraceReplay::new(session);
        let r1 = replay.step();
        assert!(r1.is_some());
        let r2 = replay.step();
        assert!(r2.is_some());
        let r3 = replay.step();
        assert!(r3.is_none());
    }

    #[test]
    fn test_trace_replay_breakpoint() {
        let mut session = TraceSession::new("t", "x86");
        for i in 0..5u64 {
            session.push(
                TraceEvent::Instruction {
                    addr: 0x1000 + i * 4,
                    size: 4,
                },
                1,
                i * 10,
            );
        }
        let mut replay = TraceReplay::new(session);
        replay.add_breakpoint(3);
        let mut sink = CountingSink::new();
        replay.run(&mut sink);
        // Should have stopped at seq=3
        assert_eq!(sink.total, 3);
        assert!(replay.paused);
    }

    #[test]
    fn test_trace_replay_seek() {
        let mut session = TraceSession::new("t", "x86");
        for i in 0..5u64 {
            session.push(
                TraceEvent::Instruction {
                    addr: 0x1000 + i * 4,
                    size: 4,
                },
                1,
                i * 10,
            );
        }
        let mut replay = TraceReplay::new(session);
        assert!(replay.seek_to(3));
        let r = replay.step().unwrap();
        assert_eq!(r.seq, 3);
    }

    #[test]
    fn test_trace_backward_search() {
        let mut session = TraceSession::new("t", "x86");
        session.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        session.push(
            TraceEvent::Call {
                from: 0x1004,
                to: 0x2000,
            },
            1,
            10,
        );
        session.push(
            TraceEvent::Instruction {
                addr: 0x2000,
                size: 4,
            },
            1,
            20,
        );
        let search = TraceBackwardSearch::new(&session, 2);
        let call = search.find_prev_call();
        assert!(call.is_some());
        assert!(matches!(call.unwrap().event, TraceEvent::Call { .. }));
    }

    #[test]
    fn test_divergence_detector_identical() {
        let mut a = TraceSession::new("a", "x86");
        let mut b = TraceSession::new("b", "x86");
        a.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        b.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        assert!(TraceDivergenceDetector::find_first_divergence(&a, &b).is_none());
        assert_eq!(TraceDivergenceDetector::common_prefix_length(&a, &b), 1);
    }

    #[test]
    fn test_divergence_detector_differs() {
        let mut a = TraceSession::new("a", "x86");
        let mut b = TraceSession::new("b", "x86");
        a.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        b.push(
            TraceEvent::Instruction {
                addr: 0x2000,
                size: 4,
            },
            1,
            0,
        );
        let dp = TraceDivergenceDetector::find_first_divergence(&a, &b);
        assert!(dp.is_some());
    }

    #[test]
    fn test_symbol_resolver() {
        let mut resolver = TraceSymbolResolver::new();
        resolver.add_symbol(0x1000, "main");
        resolver.add_module(0x0040_0000, 0x0050_0000, "libc.so");
        assert_eq!(resolver.resolve(0x1000), Some("main"));
        assert!(resolver.resolve(0x2000).is_none());
        assert_eq!(resolver.module_for(0x0045_0000), Some("libc.so"));
        let fmt = resolver.format_addr(0x1000);
        assert!(fmt.contains("main"));
    }

    #[test]
    fn test_call_tree_build() {
        let mut session = TraceSession::new("t", "x86");
        session.push(
            TraceEvent::Call {
                from: 0x1000,
                to: 0x2000,
            },
            1,
            0,
        );
        session.push(
            TraceEvent::Instruction {
                addr: 0x2000,
                size: 4,
            },
            1,
            10,
        );
        session.push(
            TraceEvent::Return {
                from: 0x2010,
                to: 0x1005,
            },
            1,
            20,
        );
        let roots = TraceFunctionCallTree::build(&session);
        assert!(!roots.is_empty());
        assert_eq!(roots[0].addr, 0x2000);
        assert_eq!(roots[0].instruction_count, 1);
    }

    #[test]
    fn test_loop_detector() {
        let mut session = TraceSession::new("t", "x86");
        for _ in 0..5 {
            session.push(
                TraceEvent::Instruction {
                    addr: 0x1000,
                    size: 4,
                },
                1,
                0,
            );
        }
        session.push(
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
            1,
            0,
        );
        let loops = TraceLoopDetector::detect(&session, 3);
        assert!(!loops.is_empty());
        assert_eq!(loops[0].entry_addr, 0x1000);
        assert_eq!(loops[0].iteration_count, 5);
    }

    #[test]
    fn test_anomaly_detector_exception() {
        let mut session = TraceSession::new("t", "x86");
        session.push(
            TraceEvent::Exception {
                code: 0xC000_0005,
                addr: 0x1234,
            },
            1,
            0,
        );
        let anomalies = TraceAnomalyDetector::detect(&session);
        assert!(!anomalies.is_empty());
        assert_eq!(anomalies[0].severity, 2);
    }

    #[test]
    fn test_anomaly_detector_unmatched_return() {
        let mut session = TraceSession::new("t", "x86");
        session.push(
            TraceEvent::Return {
                from: 0x1004,
                to: 0x1000,
            },
            1,
            0,
        );
        let anomalies = TraceAnomalyDetector::detect(&session);
        assert!(!anomalies.is_empty());
    }

    #[test]
    fn test_statistics_compute() {
        let mut session = TraceSession::new("t", "x86");
        session.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        session.push(
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
            1,
            10,
        );
        session.push(
            TraceEvent::Call {
                from: 0x1004,
                to: 0x2000,
            },
            1,
            20,
        );
        session.push(
            TraceEvent::Branch {
                from: 0x1000,
                to: 0x1100,
                taken: true,
            },
            1,
            30,
        );
        session.push(
            TraceEvent::Branch {
                from: 0x1100,
                to: 0x1200,
                taken: false,
            },
            1,
            40,
        );
        let stats = TraceStatistics::compute(&session);
        assert_eq!(stats.instruction_count, 2);
        assert_eq!(stats.call_count, 1);
        assert_eq!(stats.branch_count, 2);
        assert_eq!(stats.taken_branch_count, 1);
        assert!((stats.branch_taken_ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_trace_heatmap_from_session() {
        let mut session = TraceSession::new("t", "x86");
        for _ in 0..3 {
            session.push(
                TraceEvent::Instruction {
                    addr: 0x1000,
                    size: 4,
                },
                1,
                0,
            );
        }
        session.push(
            TraceEvent::Instruction {
                addr: 0x1004,
                size: 4,
            },
            1,
            10,
        );
        let hm = TraceHeatmap::from_session(&session);
        assert_eq!(hm.count(0x1000), 3);
        assert_eq!(hm.count(0x1004), 1);
        let top = hm.top_n(1);
        assert_eq!(top[0].0, 0x1000);
    }

    #[test]
    fn test_trace_heatmap_heat_bar() {
        let mut hm = TraceHeatmap::new();
        hm.inner.record(0x1000);
        hm.inner.record(0x1000);
        hm.inner.record(0x1004);
        let bar = hm.heat_bar(0x1000, 10);
        assert_eq!(bar.len(), 10);
    }

    #[test]
    fn test_intel_pt_type_aliases() {
        let mut session: IntelPtSession = TraceSession::new("pt", "x86_64");
        session.push(
            IntelPtEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        assert_eq!(session.instruction_count(), 1);
    }

    #[test]
    fn test_trace_index_build_from_session() {
        let mut session = TraceSession::new("t", "x86");
        session.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        session.push(
            TraceEvent::Instruction {
                addr: 0x2000,
                size: 4,
            },
            2,
            10,
        );
        let mut idx = TraceIndex::new();
        idx.build_from_session(&session);
        let seqs = idx.seqs_at_addr(0x1000);
        assert!(!seqs.is_empty());
        assert_eq!(idx.index_of_seq(1), Some(1));
    }

    #[test]
    fn test_multi_sink() {
        let mut multi = MultiSink::new();
        multi.add(Box::new(VecSink::new()));
        multi.add(Box::new(CountingSink::new()));
        let rec = TraceRecord::new(
            0,
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        multi.on_start();
        multi.on_record(&rec);
        multi.on_end();
        // Just verifying no panics
    }

    #[test]
    fn test_trace_replay_run_all() {
        let mut session = TraceSession::new("t", "x86");
        for i in 0..5u64 {
            session.push(
                TraceEvent::Instruction {
                    addr: 0x1000 + i * 4,
                    size: 4,
                },
                1,
                i,
            );
        }
        let mut replay = TraceReplay::new(session);
        let mut sink = VecSink::new();
        replay.run_all(&mut sink);
        assert_eq!(sink.records.len(), 5);
    }

    #[test]
    fn test_trace_statistics_branch_ratio_zero() {
        let session = TraceSession::new("t", "x86");
        let stats = TraceStatistics::compute(&session);
        assert!((stats.branch_taken_ratio()).abs() < 1e-9);
    }

    #[test]
    fn test_divergence_common_prefix_different_lengths() {
        let mut a = TraceSession::new("a", "x86");
        let b = TraceSession::new("b", "x86");
        a.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 4,
            },
            1,
            0,
        );
        assert_eq!(TraceDivergenceDetector::common_prefix_length(&a, &b), 0);
    }

    #[test]
    fn test_call_tree_node_depth() {
        let mut node = CallTreeNode::new(0x1000, 0);
        let child = CallTreeNode::new(0x2000, 5);
        node.children.push(child);
        assert_eq!(node.depth(), 2);
        assert_eq!(node.subtree_size(), 2);
    }
}
