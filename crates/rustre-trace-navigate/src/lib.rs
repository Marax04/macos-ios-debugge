//! `rustre-trace-navigate` — Full Tenet-style execution trace navigation.
//!
//! Provides bidirectional navigation over execution trace entries with:
//! - `TraceNavigator`: full time-travel navigation (step forward/backward, jump,
//!   run to breakpoint, reverse run to breakpoint, step-over, step-out)
//! - Memory timeline: all writes/reads to an address, value reconstruction
//! - Call stack reconstruction: replay CALL/RET events, find callers
//! - Register timeline: history per register, find specific values
//! - Coverage and statistics: visited blocks, hot blocks, function call counts
//! - Playback: tick-to-wall-clock mapping via TSC deltas

pub mod address_timeline;
pub mod backward_nav;
pub mod bookmark_manager;
pub mod call_tree_navigator;
pub mod step_navigator;
pub mod trace_index;
pub mod tenet_navigation;
pub mod time_travel_search;
pub mod execution_graph_builder;
pub mod time_travel_navigator;
pub mod trace_search_engine;
pub mod trace_diff_engine;
pub mod trace_replay_controller;
pub mod trace_slice_extractor;
pub mod function_call_navigator;
pub mod memory_access_navigator;
pub mod trace_bookmark_manager;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::ops::Range;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Type Aliases ────────────────────────────────────────────────────────────

/// Address type used throughout the trace navigation API.
pub type Address = u64;

/// Register identifier.
pub type RegId = u32;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors from the navigation subsystem.
#[derive(Debug, Error)]
pub enum NavError {
    /// Requested index is out of bounds.
    #[error("out of bounds: idx={idx}, max={max}")]
    OutOfBounds {
        /// The requested index.
        idx: usize,
        /// The maximum valid index.
        max: usize,
    },
    /// The trace is empty.
    #[error("trace is empty")]
    Empty,
    /// No bookmark with the given name.
    #[error("bookmark not found: {0}")]
    BookmarkNotFound(String),
    /// Query produced no results.
    #[error("query returned no results")]
    NoResults,
    /// A navigation limit was exceeded.
    #[error("navigation limit exceeded: {0}")]
    LimitExceeded(String),
    /// Register ID has no recorded history.
    #[error("no history for register id {0}")]
    UnknownRegister(RegId),
    /// Memory address has no recorded history.
    #[error("no memory history at address 0x{0:x}")]
    NoMemoryHistory(Address),
    /// Call stack reconstruction failed.
    #[error("call stack reconstruction failed: {0}")]
    CallStackError(String),
    /// Invalid time range.
    #[error("invalid time range: start={start}, end={end}")]
    InvalidRange {
        /// Start of the range.
        start: usize,
        /// End of the range.
        end: usize,
    },
}

// ─── Safe float-to-integer helpers ───────────────────────────────────────────

/// Convert an `f64` to `u64`, saturating at the bounds (0 for negative/NaN, `u64::MAX` for
/// values that exceed the representable range).  Avoids both unsafe code and clippy cast lints.
fn f64_to_u64_saturating(val: f64) -> u64 {
    // 2^64 as f64 — the next power of 2 above u64::MAX.  Any f64 ≥ this value
    // cannot be represented as a u64 without overflow.
    const TWO_POW_64: f64 = 18_446_744_073_709_551_616.0_f64; // 2^64 exact in f64
    if val.is_nan() || val <= 0.0 {
        0u64
    } else if val >= TWO_POW_64 {
        u64::MAX
    } else {
        // val ∈ (0, 2^64) — non-negative and in-range; bounds verified above.
        #[expect(clippy::cast_sign_loss, clippy::cast_possible_truncation,
                 reason = "bounds verified: val > 0.0 and val < 2^64")]
        { val as u64 }
    }
}

/// Convert an `f64` to `usize`, saturating at the bounds.
fn f64_to_usize_saturating(val: f64) -> usize {
    // On 64-bit targets usize == u64; on 32-bit targets usize == u32.
    #[cfg(target_pointer_width = "64")]
    {
        // On 64-bit targets usize == u64; safe.
        #[expect(clippy::cast_possible_truncation, reason = "usize == u64 on 64-bit targets")]
        { f64_to_u64_saturating(val) as usize }
    }
    #[cfg(not(target_pointer_width = "64"))]
    {
        const TWO_POW_32: f64 = 4_294_967_296.0_f64;
        if val.is_nan() || val <= 0.0 {
            0usize
        } else if val >= TWO_POW_32 {
            usize::MAX
        } else {
            #[expect(clippy::cast_sign_loss, clippy::cast_possible_truncation,
                     reason = "bounds verified: val > 0.0 and val < 2^32")]
            { val as usize }
        }
    }
}

// ─── AccessKind ───────────────────────────────────────────────────────────────

/// Whether a memory access is a read or write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessKind {
    /// Memory was read.
    Read,
    /// Memory was written.
    Write,
}

impl std::fmt::Display for AccessKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
        }
    }
}

// ─── TraceEntry ───────────────────────────────────────────────────────────────

/// A single entry in a navigable execution trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    /// Monotonically increasing index (0-based).
    pub idx: usize,
    /// Program counter (instruction address).
    pub pc: Address,
    /// Thread identifier.
    pub tid: u32,
    /// Register snapshot at this point: list of `(reg_id, value)` pairs.
    pub reg_snapshot: Vec<(RegId, u64)>,
    /// Memory writes performed at this instruction: `(addr, bytes)`.
    pub mem_writes: Vec<(Address, Vec<u8>)>,
    /// Memory reads performed at this instruction: `(addr, size)`.
    pub mem_reads: Vec<(Address, u8)>,
    /// Optional TSC (time-stamp counter) value for wall-clock mapping.
    pub tsc: Option<u64>,
    /// Kind of instruction.
    pub kind: EntryKind,
    /// Human-readable disassembly or description.
    pub disasm: String,
}

/// The kind of instruction in a trace entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    /// Ordinary instruction.
    Insn,
    /// Function call; target is the callee address.
    Call {
        /// Callee address.
        target: Address,
        /// Return address (typically pc + `call_insn_len`).
        ret_addr: Address,
    },
    /// Return instruction.
    Ret {
        /// Target address (return destination).
        target: Address,
    },
    /// Conditional or unconditional branch.
    Branch {
        /// Branch target.
        target: Address,
        /// Whether the branch was taken.
        taken: bool,
    },
    /// System call.
    Syscall {
        /// Syscall number.
        number: u64,
    },
    /// Hardware exception / fault.
    Exception {
        /// Exception code.
        code: u32,
    },
}

impl TraceEntry {
    /// Create a basic instruction entry.
    #[must_use]
    pub fn insn(idx: usize, pc: Address, tid: u32, disasm: impl Into<String>) -> Self {
        Self {
            idx,
            pc,
            tid,
            reg_snapshot: Vec::new(),
            mem_writes: Vec::new(),
            mem_reads: Vec::new(),
            tsc: None,
            kind: EntryKind::Insn,
            disasm: disasm.into(),
        }
    }

    /// Create a CALL entry.
    #[must_use]
    pub fn call(idx: usize, pc: Address, tid: u32, target: Address, ret_addr: Address) -> Self {
        Self {
            idx,
            pc,
            tid,
            reg_snapshot: Vec::new(),
            mem_writes: Vec::new(),
            mem_reads: Vec::new(),
            tsc: None,
            kind: EntryKind::Call { target, ret_addr },
            disasm: format!("call 0x{target:x}"),
        }
    }

    /// Create a RET entry.
    #[must_use]
    pub fn ret(idx: usize, pc: Address, tid: u32, target: Address) -> Self {
        Self {
            idx,
            pc,
            tid,
            reg_snapshot: Vec::new(),
            mem_writes: Vec::new(),
            mem_reads: Vec::new(),
            tsc: None,
            kind: EntryKind::Ret { target },
            disasm: format!("ret -> 0x{target:x}"),
        }
    }

    /// Attach a register snapshot.
    #[must_use]
    pub fn with_regs(mut self, regs: Vec<(RegId, u64)>) -> Self {
        self.reg_snapshot = regs;
        self
    }

    /// Attach a TSC value.
    #[must_use]
    pub const fn with_tsc(mut self, tsc: u64) -> Self {
        self.tsc = Some(tsc);
        self
    }

    /// Add a memory write record.
    pub fn add_mem_write(&mut self, addr: Address, bytes: Vec<u8>) {
        self.mem_writes.push((addr, bytes));
    }

    /// Add a memory read record.
    pub fn add_mem_read(&mut self, addr: Address, size: u8) {
        self.mem_reads.push((addr, size));
    }

    /// Return `true` if this entry is a CALL.
    #[must_use]
    pub const fn is_call(&self) -> bool {
        matches!(self.kind, EntryKind::Call { .. })
    }

    /// Return `true` if this entry is a RET.
    #[must_use]
    pub const fn is_ret(&self) -> bool {
        matches!(self.kind, EntryKind::Ret { .. })
    }

    /// Return the call target if this is a CALL entry.
    #[must_use]
    pub const fn call_target(&self) -> Option<Address> {
        match self.kind {
            EntryKind::Call { target, .. } => Some(target),
            _ => None,
        }
    }

    /// Return the return address if this is a CALL entry.
    #[must_use]
    pub const fn ret_addr(&self) -> Option<Address> {
        match self.kind {
            EntryKind::Call { ret_addr, .. } => Some(ret_addr),
            _ => None,
        }
    }

    /// Return the return destination if this is a RET entry.
    #[must_use]
    pub const fn ret_target(&self) -> Option<Address> {
        match self.kind {
            EntryKind::Ret { target } => Some(target),
            _ => None,
        }
    }

    /// Get the value of a register from the snapshot, if present.
    #[must_use]
    pub fn reg_value(&self, reg: RegId) -> Option<u64> {
        self.reg_snapshot
            .iter()
            .find(|(r, _)| *r == reg)
            .map(|(_, v)| *v)
    }
}

impl std::fmt::Display for TraceEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] pc=0x{:x} tid={} {}",
            self.idx, self.pc, self.tid, self.disasm
        )
    }
}

// ─── StackFrame ───────────────────────────────────────────────────────────────

/// One frame in a reconstructed call stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrame {
    /// Entry address of the called function.
    pub fn_addr: Address,
    /// Address the function will return to.
    pub ret_addr: Address,
    /// Depth (0 = outermost / bottom of stack).
    pub depth: u32,
    /// Optional symbol name.
    pub name: Option<String>,
    /// Trace index when the CALL was made.
    pub called_at_idx: usize,
}

impl StackFrame {
    /// Create a new stack frame.
    #[must_use]
    pub const fn new(fn_addr: Address, ret_addr: Address, depth: u32, called_at_idx: usize) -> Self {
        Self {
            fn_addr,
            ret_addr,
            depth,
            name: None,
            called_at_idx,
        }
    }

    /// Attach a symbol name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Human-readable identifier: symbol name or hex address.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("0x{:x}", self.fn_addr))
    }
}

impl std::fmt::Display for StackFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} -> ret:0x{:x} (called at idx {})",
            self.depth,
            self.display_name(),
            self.ret_addr,
            self.called_at_idx,
        )
    }
}

// ─── ExecutionTrace ───────────────────────────────────────────────────────────

/// An ordered, immutable sequence of trace entries forming the execution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// Ordered trace entries.
    pub entries: Vec<TraceEntry>,
    /// Metadata: binary name.
    pub binary_name: String,
    /// Metadata: optional architecture string.
    pub arch: String,
    /// Metadata: total TSC ticks if available.
    pub total_tsc: Option<u64>,
    /// First TSC value (for relative timing).
    pub tsc_base: Option<u64>,
    /// TSC frequency in Hz (if known, for wall-clock conversion).
    pub tsc_freq_hz: Option<u64>,
}

impl ExecutionTrace {
    /// Create a new trace from a list of entries.
    #[must_use]
    pub fn new(entries: Vec<TraceEntry>, binary_name: impl Into<String>) -> Self {
        let tsc_base = entries.first().and_then(|e| e.tsc);
        let total_tsc = match (tsc_base, entries.last().and_then(|e| e.tsc)) {
            (Some(first), Some(last)) => Some(last.saturating_sub(first)),
            _ => None,
        };
        Self {
            entries,
            binary_name: binary_name.into(),
            arch: "x86_64".to_string(),
            total_tsc,
            tsc_base,
            tsc_freq_hz: None,
        }
    }

    /// Set the TSC frequency for wall-clock mapping.
    #[must_use]
    pub const fn with_tsc_freq(mut self, hz: u64) -> Self {
        self.tsc_freq_hz = Some(hz);
        self
    }

    /// Set the architecture string.
    #[must_use]
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.arch = arch.into();
        self
    }

    /// Return the number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the trace is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up an entry by index.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&TraceEntry> {
        self.entries.get(idx)
    }

    /// Convert a TSC value to a trace index via binary search.
    #[must_use]
    pub fn idx_for_tsc(&self, tsc: u64) -> Option<usize> {
        if self.entries.is_empty() {
            return None;
        }
        let pos = self.entries.partition_point(|e| e.tsc.unwrap_or(0) < tsc);
        Some(pos.min(self.entries.len() - 1))
    }

    /// Convert a wall-clock millisecond offset to a trace index.
    /// Requires `tsc_freq_hz` and `tsc_base` to be set.
    #[must_use]
    pub fn idx_for_ms(&self, ms: f64) -> Option<usize> {
        let freq = self.tsc_freq_hz?;
        let base = self.tsc_base?;
        let freq_f = f64::from(u32::try_from(freq).unwrap_or(u32::MAX));
        let tsc_offset_f = ms * freq_f / 1000.0;
        let tsc_offset = if tsc_offset_f <= 0.0 {
            0u64
        } else if tsc_offset_f >= f64::from(u32::MAX) * f64::from(u32::MAX) {
            u64::MAX
        } else {
            // tsc_offset_f is checked > 0 and < u64::MAX boundary above — cast is safe.
            // We round first to avoid fractional values and ensure the result is non-negative.
            f64_to_u64_saturating(tsc_offset_f)
        };
        let target_tsc = base.saturating_add(tsc_offset);
        self.idx_for_tsc(target_tsc)
    }
}

// ─── MemoryAccessIndex ────────────────────────────────────────────────────────

/// Index mapping each address to all trace entries that accessed it.
/// Per address: sorted list of `(idx, kind, value_written_or_zero)`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemAccessIndex {
    inner: BTreeMap<Address, Vec<(usize, AccessKind, u64)>>,
}

impl MemAccessIndex {
    /// Create a new empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the index from a trace.
    #[must_use]
    pub fn build(trace: &ExecutionTrace) -> Self {
        let mut idx = Self::new();
        for entry in &trace.entries {
            for (addr, bytes) in &entry.mem_writes {
                let val = bytes_to_u64(bytes);
                idx.inner
                    .entry(*addr)
                    .or_default()
                    .push((entry.idx, AccessKind::Write, val));
            }
            for (addr, _size) in &entry.mem_reads {
                idx.inner
                    .entry(*addr)
                    .or_default()
                    .push((entry.idx, AccessKind::Read, 0));
            }
        }
        idx
    }

    /// All accesses to `addr`, sorted by trace index.
    #[must_use]
    pub fn accesses(&self, addr: Address) -> &[(usize, AccessKind, u64)] {
        self.inner.get(&addr).map_or(&[], std::vec::Vec::as_slice)
    }

    /// All write accesses to `addr`.
    #[must_use]
    pub fn writes(&self, addr: Address) -> Vec<(usize, u64)> {
        self.accesses(addr)
            .iter()
            .filter(|(_, k, _)| *k == AccessKind::Write)
            .map(|(i, _, v)| (*i, *v))
            .collect()
    }

    /// All read accesses to `addr` (returns trace indices).
    #[must_use]
    pub fn reads(&self, addr: Address) -> Vec<usize> {
        self.accesses(addr)
            .iter()
            .filter(|(_, k, _)| *k == AccessKind::Read)
            .map(|(i, _, _)| *i)
            .collect()
    }

    /// Reconstruct the value at `addr` just before trace index `at_idx`.
    /// Returns the value from the most recent write before `at_idx`.
    #[must_use]
    pub fn value_at_idx(&self, addr: Address, at_idx: usize) -> Option<u64> {
        self.writes(addr)
            .into_iter()
            .rev()
            .find(|(i, _)| *i < at_idx)
            .map(|(_, v)| v)
    }

    /// Find the first trace index where `addr` was written with `value`.
    #[must_use]
    pub fn first_write_of_value(&self, addr: Address, value: u64) -> Option<usize> {
        self.writes(addr)
            .into_iter()
            .find(|(_, v)| *v == value)
            .map(|(i, _)| i)
    }

    /// Find the last trace index where `addr` was written with `value`.
    #[must_use]
    pub fn last_write_of_value(&self, addr: Address, value: u64) -> Option<usize> {
        self.writes(addr)
            .into_iter()
            .rev()
            .find(|(_, v)| *v == value)
            .map(|(i, _)| i)
    }

    /// All addresses that were ever written to.
    #[must_use]
    pub fn written_addresses(&self) -> Vec<Address> {
        self.inner
            .iter()
            .filter(|(_, v)| v.iter().any(|(_, k, _)| *k == AccessKind::Write))
            .map(|(a, _)| *a)
            .collect()
    }

    /// All addresses that were ever read from.
    #[must_use]
    pub fn read_addresses(&self) -> Vec<Address> {
        self.inner
            .iter()
            .filter(|(_, v)| v.iter().any(|(_, k, _)| *k == AccessKind::Read))
            .map(|(a, _)| *a)
            .collect()
    }

    /// Number of distinct addresses tracked.
    #[must_use]
    pub fn address_count(&self) -> usize {
        self.inner.len()
    }
}

/// Convert a byte slice (little-endian) to a u64, reading up to 8 bytes.
#[must_use]
pub fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut val = 0u64;
    for (i, &b) in bytes.iter().take(8).enumerate() {
        val |= u64::from(b) << (i * 8);
    }
    val
}

// ─── CallIndex ────────────────────────────────────────────────────────────────

/// Index mapping function addresses to all trace indices where they were called.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallIndex {
    /// function address -> list of (`trace_idx`, `call_site_addr`)
    inner: HashMap<Address, Vec<(usize, Address)>>,
}

impl CallIndex {
    /// Create a new empty call index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a call index from a trace.
    #[must_use]
    pub fn build(trace: &ExecutionTrace) -> Self {
        let mut idx = Self::new();
        for entry in &trace.entries {
            if let EntryKind::Call { target, .. } = entry.kind {
                idx.inner
                    .entry(target)
                    .or_default()
                    .push((entry.idx, entry.pc));
            }
        }
        idx
    }

    /// All (`trace_idx`, `call_site`) pairs for `func_addr`.
    #[must_use]
    pub fn callers_of(&self, func_addr: Address) -> &[(usize, Address)] {
        self.inner
            .get(&func_addr)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    /// Number of unique functions tracked.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.inner.len()
    }

    /// Call counts per function address.
    #[must_use]
    pub fn call_counts(&self) -> HashMap<Address, usize> {
        self.inner
            .iter()
            .map(|(addr, calls)| (*addr, calls.len()))
            .collect()
    }

    /// All tracked function addresses.
    #[must_use]
    pub fn functions(&self) -> Vec<Address> {
        self.inner.keys().copied().collect()
    }
}

// ─── RegTimeline ─────────────────────────────────────────────────────────────

/// Per-register history extracted from trace entry snapshots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegTimeline {
    /// `reg_id` -> sorted vec of (`trace_idx`, value)
    inner: HashMap<RegId, Vec<(usize, u64)>>,
}

impl RegTimeline {
    /// Create an empty timeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the register timeline from a trace.
    #[must_use]
    pub fn build(trace: &ExecutionTrace) -> Self {
        let mut tl = Self::new();
        for entry in &trace.entries {
            for (reg, val) in &entry.reg_snapshot {
                tl.inner.entry(*reg).or_default().push((entry.idx, *val));
            }
        }
        tl
    }

    /// All `(idx, value)` pairs for `reg` in the given index range.
    #[must_use]
    pub fn history(&self, reg: RegId, range: Range<usize>) -> Vec<(usize, u64)> {
        self.inner
            .get(&reg)
            .map(|v| {
                v.iter()
                    .filter(|(i, _)| range.contains(i))
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// All trace indices where `reg` held exactly `value`.
    #[must_use]
    pub fn find_value(&self, reg: RegId, value: u64) -> Vec<usize> {
        self.inner
            .get(&reg)
            .map(|v| {
                v.iter()
                    .filter(|(_, val)| *val == value)
                    .map(|(i, _)| *i)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Value of `reg` at the given trace index (most recent write <= idx).
    #[must_use]
    pub fn value_at(&self, reg: RegId, idx: usize) -> Option<u64> {
        self.inner
            .get(&reg)?
            .iter()
            .rev()
            .find(|(i, _)| *i <= idx)
            .map(|(_, v)| *v)
    }

    /// All tracked register IDs.
    #[must_use]
    pub fn tracked_regs(&self) -> Vec<RegId> {
        self.inner.keys().copied().collect()
    }

    /// Snapshot of all registers at index `at_idx`.
    #[must_use]
    pub fn snapshot_at(&self, at_idx: usize) -> HashMap<RegId, u64> {
        self.inner
            .iter()
            .filter_map(|(reg, hist)| {
                hist.iter()
                    .rev()
                    .find(|(i, _)| *i <= at_idx)
                    .map(|(_, v)| (*reg, *v))
            })
            .collect()
    }

    /// All registers that changed between `from_idx` (exclusive) and `to_idx` (inclusive).
    #[must_use]
    pub fn changed_between(&self, from_idx: usize, to_idx: usize) -> Vec<(RegId, usize, u64)> {
        let mut out = Vec::new();
        for (reg, hist) in &self.inner {
            for (i, v) in hist {
                if *i > from_idx && *i <= to_idx {
                    out.push((*reg, *i, *v));
                }
            }
        }
        out.sort_by_key(|(_, i, _)| *i);
        out
    }
}

// ─── CallStackReconstructor ───────────────────────────────────────────────────

/// Reconstructs call stacks by replaying CALL/RET events.
#[derive(Debug, Clone, Default)]
pub struct CallStackReconstructor {
    /// Current stack.
    stack: Vec<StackFrame>,
    /// Max depth to track.
    max_depth: usize,
    /// Symbol table for name resolution.
    symbols: HashMap<Address, String>,
    /// Overflow count.
    overflow: u64,
}

impl CallStackReconstructor {
    /// Create a new reconstructor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            max_depth: 512,
            symbols: HashMap::new(),
            overflow: 0,
        }
    }

    /// Set the max depth.
    #[must_use]
    pub const fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Register a symbol.
    pub fn add_symbol(&mut self, addr: Address, name: impl Into<String>) {
        self.symbols.insert(addr, name.into());
    }

    /// Process one trace entry.
    pub fn process(&mut self, entry: &TraceEntry) {
        match entry.kind {
            EntryKind::Call { target, ret_addr } => {
                if self.stack.len() >= self.max_depth {
                    self.overflow += 1;
                    return;
                }
                let depth = u32::try_from(self.stack.len()).unwrap_or(u32::MAX);
                let name = self.symbols.get(&target).cloned();
                let mut frame = StackFrame::new(target, ret_addr, depth, entry.idx);
                frame.name = name;
                self.stack.push(frame);
            }
            EntryKind::Ret { .. } => {
                self.stack.pop();
            }
            _ => {}
        }
    }

    /// Reset to empty state.
    pub fn reset(&mut self) {
        self.stack.clear();
        self.overflow = 0;
    }

    /// Replay entries from the beginning up to (and including) `at_idx`.
    #[must_use]
    pub fn rebuild_to(&mut self, trace: &ExecutionTrace, at_idx: usize) -> Vec<StackFrame> {
        self.reset();
        for entry in &trace.entries {
            if entry.idx > at_idx {
                break;
            }
            self.process(entry);
        }
        self.stack.clone()
    }

    /// Current stack frames (most recent last).
    #[must_use]
    pub fn frames(&self) -> &[StackFrame] {
        &self.stack
    }

    /// Current depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.stack.len()
    }

    /// Number of overflowed frames.
    #[must_use]
    pub const fn overflow_count(&self) -> u64 {
        self.overflow
    }
}

// ─── Bookmark ─────────────────────────────────────────────────────────────────

/// A named position bookmark in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    /// Unique name.
    pub name: String,
    /// Trace index of the bookmark.
    pub idx: usize,
    /// PC at the bookmark.
    pub pc: Address,
    /// Optional user note.
    pub note: Option<String>,
}

impl Bookmark {
    /// Create a new bookmark.
    #[must_use]
    pub fn new(name: impl Into<String>, idx: usize, pc: Address) -> Self {
        Self {
            name: name.into(),
            idx,
            pc,
            note: None,
        }
    }

    /// Attach a note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

impl std::fmt::Display for Bookmark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Bookmark({}, idx={}, pc=0x{:x})",
            self.name, self.idx, self.pc
        )
    }
}

// ─── BookmarkStore ────────────────────────────────────────────────────────────

/// A named bookmark store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BookmarkStore {
    inner: HashMap<String, Bookmark>,
}

impl BookmarkStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a bookmark.
    pub fn insert(&mut self, bm: Bookmark) {
        self.inner.insert(bm.name.clone(), bm);
    }

    /// Get a bookmark by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Bookmark> {
        self.inner.get(name)
    }

    /// Remove a bookmark.
    ///
    /// # Errors
    /// [`NavError::BookmarkNotFound`] if the bookmark does not exist.
    pub fn remove(&mut self, name: &str) -> Result<Bookmark, NavError> {
        self.inner
            .remove(name)
            .ok_or_else(|| NavError::BookmarkNotFound(name.to_owned()))
    }

    /// All bookmarks sorted by trace index.
    #[must_use]
    pub fn sorted_by_idx(&self) -> Vec<&Bookmark> {
        let mut v: Vec<&Bookmark> = self.inner.values().collect();
        v.sort_by_key(|b| b.idx);
        v
    }

    /// Number of bookmarks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if there are no bookmarks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// All bookmark names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.inner.keys().map(std::string::String::as_str).collect()
    }
}

// ─── CoverageStats ────────────────────────────────────────────────────────────

/// Coverage and execution statistics derived from a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageStats {
    /// Set of basic-block start addresses visited.
    pub visited_blocks: HashSet<Address>,
    /// Number of times each address was executed.
    pub block_counts: HashMap<Address, usize>,
    /// Number of times each function was called.
    pub function_call_counts: HashMap<Address, usize>,
}

impl CoverageStats {
    /// Build coverage stats from a trace.
    #[must_use]
    pub fn build(trace: &ExecutionTrace) -> Self {
        let mut block_counts: HashMap<Address, usize> = HashMap::new();
        let mut function_call_counts: HashMap<Address, usize> = HashMap::new();
        let mut visited_blocks = HashSet::new();

        for entry in &trace.entries {
            *block_counts.entry(entry.pc).or_insert(0) += 1;
            visited_blocks.insert(entry.pc);
            if let EntryKind::Call { target, .. } = entry.kind {
                *function_call_counts.entry(target).or_insert(0) += 1;
            }
        }

        Self {
            visited_blocks,
            block_counts,
            function_call_counts,
        }
    }

    /// Top-N most-executed basic block addresses.
    #[must_use]
    pub fn hot_blocks(&self, top_n: usize) -> Vec<(Address, usize)> {
        let mut pairs: Vec<(Address, usize)> =
            self.block_counts.iter().map(|(&a, &c)| (a, c)).collect();
        pairs.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        pairs.truncate(top_n);
        pairs
    }

    /// All visited basic block addresses.
    #[must_use]
    pub const fn visited_basic_blocks(&self) -> &HashSet<Address> {
        &self.visited_blocks
    }

    /// Number of unique blocks visited.
    #[must_use]
    pub fn unique_block_count(&self) -> usize {
        self.visited_blocks.len()
    }

    /// Hit count for a specific address.
    #[must_use]
    pub fn hit_count(&self, addr: Address) -> usize {
        self.block_counts.get(&addr).copied().unwrap_or(0)
    }

    /// Total number of instructions executed.
    #[must_use]
    pub fn total_instructions(&self) -> usize {
        self.block_counts.values().sum()
    }

    /// Coverage density: fraction of total instructions in top-N hottest blocks.
    #[must_use]
    pub fn hot_fraction(&self, top_n: usize) -> f64 {
        let total: usize = self.total_instructions();
        if total == 0 {
            return 0.0;
        }
        let hot: usize = self.hot_blocks(top_n).iter().map(|(_, c)| c).sum();
        f64::from(u32::try_from(hot).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }
}

// ─── NavigationHistory ────────────────────────────────────────────────────────

/// Undo/redo navigation history.
#[derive(Debug, Clone, Default)]
pub struct NavigationHistory {
    past: VecDeque<usize>,
    future: Vec<usize>,
    max_size: usize,
}

impl NavigationHistory {
    /// Create with default capacity.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            past: VecDeque::new(),
            future: Vec::new(),
            max_size: 2048,
        }
    }

    /// Push a new position (clears future).
    pub fn push(&mut self, idx: usize) {
        self.future.clear();
        if self.past.len() >= self.max_size {
            self.past.pop_front();
        }
        self.past.push_back(idx);
    }

    /// Undo: return previous position, keeping current as redo.
    pub fn undo(&mut self) -> Option<usize> {
        let cur = self.past.pop_back()?;
        self.future.push(cur);
        self.past.back().copied()
    }

    /// Redo: return the next position in the future stack.
    pub fn redo(&mut self) -> Option<usize> {
        let idx = self.future.pop()?;
        self.past.push_back(idx);
        Some(idx)
    }

    /// Number of undo steps available.
    #[must_use]
    pub fn undo_depth(&self) -> usize {
        self.past.len().saturating_sub(1)
    }

    /// Number of redo steps available.
    #[must_use]
    pub const fn redo_depth(&self) -> usize {
        self.future.len()
    }

    /// Current position (most recent push).
    #[must_use]
    pub fn current(&self) -> Option<usize> {
        self.past.back().copied()
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.past.clear();
        self.future.clear();
    }
}

// ─── StepWindow ───────────────────────────────────────────────────────────────

/// Sliding window of recent navigation events.
#[derive(Debug, Clone, Default)]
pub struct StepWindow {
    buf: VecDeque<NavEvent>,
    cap: usize,
}

impl StepWindow {
    /// Create a step window with given capacity.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            buf: VecDeque::with_capacity(cap),
            cap,
        }
    }

    /// Push a new event, evicting the oldest if full.
    pub fn push(&mut self, ev: NavEvent) {
        if self.buf.len() >= self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(ev);
    }

    /// Most recent event.
    #[must_use]
    pub fn latest(&self) -> Option<&NavEvent> {
        self.buf.back()
    }

    /// Number of events in the window.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the window is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Drain all events.
    pub fn drain(&mut self) -> Vec<NavEvent> {
        self.buf.drain(..).collect()
    }

    /// View events as a deque reference.
    #[must_use]
    pub const fn as_deque(&self) -> &VecDeque<NavEvent> {
        &self.buf
    }
}

// ─── NavEvent ─────────────────────────────────────────────────────────────────

/// An event emitted during navigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NavEvent {
    /// Cursor moved from one index to another.
    Moved { from: usize, to: usize },
    /// Hit a breakpoint address.
    BreakpointHit { idx: usize, pc: Address },
    /// Reached the end of the trace.
    End,
    /// Reached the beginning of the trace during reverse navigation.
    Beginning,
    /// Navigation was cancelled (step limit, etc.).
    Cancelled { reason: String },
    /// Hit a bookmark.
    BookmarkHit {
        name: String,
        idx: usize,
        pc: Address,
    },
}

impl std::fmt::Display for NavEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Moved { from, to } => write!(f, "Moved({from} -> {to})"),
            Self::BreakpointHit { idx, pc } => write!(f, "BreakpointHit(idx={idx}, pc=0x{pc:x})"),
            Self::End => write!(f, "End"),
            Self::Beginning => write!(f, "Beginning"),
            Self::Cancelled { reason } => write!(f, "Cancelled({reason})"),
            Self::BookmarkHit { name, idx, pc } => {
                write!(f, "BookmarkHit({name}, idx={idx}, pc=0x{pc:x})")
            }
        }
    }
}

// ─── TraceNavigator ───────────────────────────────────────────────────────────

/// Full Tenet-style execution trace navigator.
///
/// Supports:
/// - Forward/backward single-step
/// - Jump to arbitrary index
/// - Run to breakpoint (forward) / reverse run to breakpoint
/// - Step over (skip called functions) / step out
/// - Run to cursor (address)
/// - Memory timeline queries (writes, reads, value reconstruction)
/// - Call stack reconstruction at any index
/// - Find callers of a function
/// - Register timeline queries
/// - Coverage and statistics
/// - Wall-clock playback via TSC deltas
pub struct TraceNavigator {
    /// The underlying trace.
    pub trace: ExecutionTrace,
    /// Current cursor position (index into `trace.entries`).
    pub current_idx: usize,
    /// Memory access index: address -> [(idx, kind, value)].
    pub mem_access_index: MemAccessIndex,
    /// Call index: function address -> [(idx, `call_site`)].
    pub call_index: CallIndex,
    /// Register timeline.
    pub reg_timeline: RegTimeline,
    /// Coverage/statistics cache.
    pub coverage: CoverageStats,
    /// Named bookmarks.
    pub bookmarks: BookmarkStore,
    /// Navigation history.
    pub history: NavigationHistory,
    /// Call stack reconstructor.
    reconstructor: CallStackReconstructor,
    /// Incrementally-maintained call depth at `current_idx`.
    /// Avoids O(n²) `rebuild_to` calls in `step_over_forward` / `step_out`.
    current_call_depth: usize,
    /// Step limit (guards against infinite loops).
    pub step_limit: usize,
    /// Address -> list of entry indices (for fast PC lookup).
    pc_index: HashMap<Address, Vec<usize>>,
    /// Accumulated navigation events.
    pub event_window: StepWindow,
}

impl TraceNavigator {
    /// Create a navigator from a complete execution trace.
    ///
    /// Builds all internal indices in O(n).
    #[must_use]
    pub fn new(trace: ExecutionTrace) -> Self {
        let mem_access_index = MemAccessIndex::build(&trace);
        let call_index = CallIndex::build(&trace);
        let reg_timeline = RegTimeline::build(&trace);
        let coverage = CoverageStats::build(&trace);

        // Build PC index.
        let mut pc_index: HashMap<Address, Vec<usize>> = HashMap::new();
        for entry in &trace.entries {
            pc_index.entry(entry.pc).or_default().push(entry.idx);
        }

        Self {
            trace,
            current_idx: 0,
            mem_access_index,
            call_index,
            reg_timeline,
            coverage,
            bookmarks: BookmarkStore::new(),
            history: NavigationHistory::new(),
            reconstructor: CallStackReconstructor::new(),
            current_call_depth: 0,
            step_limit: 10_000_000,
            pc_index,
            event_window: StepWindow::new(256),
        }
    }

    /// Add a symbol for call-stack display.
    pub fn add_symbol(&mut self, addr: Address, name: impl Into<String>) {
        self.reconstructor.add_symbol(addr, name);
    }

    /// Update the incremental call depth by applying the entry at `new_idx`
    /// relative to the direction of movement.
    ///
    /// - Moving **forward** to `new_idx`: apply the entry at `new_idx`.
    /// - Moving **backward** to `new_idx`: undo the entry at `new_idx + 1`
    ///   (reverse a CALL = decrement, reverse a RET = increment).
    fn update_depth_forward(&mut self, new_idx: usize) {
        if let Some(entry) = self.trace.get(new_idx) {
            match entry.kind {
                EntryKind::Call { .. } => {
                    self.current_call_depth = self.current_call_depth.saturating_add(1);
                }
                EntryKind::Ret { .. } => {
                    self.current_call_depth = self.current_call_depth.saturating_sub(1);
                }
                _ => {}
            }
        }
    }

    fn update_depth_backward(&mut self, old_idx: usize) {
        // We are moving from old_idx to old_idx-1.  Undo the effect of old_idx's entry.
        if let Some(entry) = self.trace.get(old_idx) {
            match entry.kind {
                EntryKind::Call { .. } => {
                    self.current_call_depth = self.current_call_depth.saturating_sub(1);
                }
                EntryKind::Ret { .. } => {
                    self.current_call_depth = self.current_call_depth.saturating_add(1);
                }
                _ => {}
            }
        }
    }

    /// Rebuild the incremental depth by replaying from scratch.
    /// Called after arbitrary jumps.
    fn rebuild_depth(&mut self) {
        let depth = self.reconstructor.rebuild_to(&self.trace, self.current_idx).len();
        self.current_call_depth = depth;
    }

    // ── Basic Navigation ─────────────────────────────────────────────────

    /// Current trace entry.
    #[must_use]
    pub fn current_entry(&self) -> Option<&TraceEntry> {
        self.trace.get(self.current_idx)
    }

    /// Step forward by one instruction.
    /// Returns `false` at end of trace.
    pub fn step_forward(&mut self) -> bool {
        if self.current_idx + 1 >= self.trace.len() {
            let ev = NavEvent::End;
            self.event_window.push(ev);
            return false;
        }
        let from = self.current_idx;
        self.current_idx += 1;
        self.update_depth_forward(self.current_idx);
        self.history.push(self.current_idx);
        let ev = NavEvent::Moved {
            from,
            to: self.current_idx,
        };
        self.event_window.push(ev);
        true
    }

    /// Step backward by one instruction.
    /// Returns `false` at beginning of trace.
    pub fn step_backward(&mut self) -> bool {
        if self.current_idx == 0 {
            let ev = NavEvent::Beginning;
            self.event_window.push(ev);
            return false;
        }
        let from = self.current_idx;
        self.update_depth_backward(self.current_idx);
        self.current_idx -= 1;
        self.history.push(self.current_idx);
        let ev = NavEvent::Moved {
            from,
            to: self.current_idx,
        };
        self.event_window.push(ev);
        true
    }

    /// Jump directly to index `idx`.
    ///
    /// # Errors
    /// [`NavError::OutOfBounds`] if `idx` is out of range.
    /// [`NavError::Empty`] if the trace is empty.
    pub fn jump_to(&mut self, idx: usize) -> Result<NavEvent, NavError> {
        if self.trace.is_empty() {
            return Err(NavError::Empty);
        }
        let max = self.trace.len() - 1;
        if idx > max {
            return Err(NavError::OutOfBounds { idx, max });
        }
        let from = self.current_idx;
        self.current_idx = idx;
        // Arbitrary jump: must rebuild depth from scratch (O(n) once, not in a loop).
        self.rebuild_depth();
        self.history.push(idx);
        let pc = self.trace.get(idx).map_or(0, |e| e.pc);
        let ev = NavEvent::Moved { from, to: idx };
        self.event_window.push(ev);
        Ok(NavEvent::BreakpointHit { idx, pc })
    }

    // ── Breakpoint Navigation ─────────────────────────────────────────────

    /// Run forward until the PC equals `addr`.
    /// Returns the `NavEvent` when the address is hit.
    ///
    /// # Errors
    /// [`NavError::NoResults`] if the address is never reached going forward.
    pub fn run_to_breakpoint(&mut self, addr: Address) -> Result<NavEvent, NavError> {
        let start = self.current_idx + 1;
        for i in start..self.trace.len() {
            if self.trace.entries[i].pc == addr {
                let from = self.current_idx;
                self.current_idx = i;
                self.history.push(i);
                self.event_window.push(NavEvent::Moved { from, to: i });
                return Ok(NavEvent::BreakpointHit { idx: i, pc: addr });
            }
        }
        Err(NavError::NoResults)
    }

    /// Run backward until the PC equals `addr`.
    ///
    /// # Errors
    /// [`NavError::NoResults`] if the address is never reached going backward.
    pub fn reverse_run_to_breakpoint(&mut self, addr: Address) -> Result<NavEvent, NavError> {
        if self.current_idx == 0 {
            return Err(NavError::NoResults);
        }
        let end = self.current_idx - 1;
        for i in (0..=end).rev() {
            if self.trace.entries[i].pc == addr {
                let from = self.current_idx;
                self.current_idx = i;
                self.history.push(i);
                self.event_window.push(NavEvent::Moved { from, to: i });
                return Ok(NavEvent::BreakpointHit { idx: i, pc: addr });
            }
        }
        Err(NavError::NoResults)
    }

    /// Run forward to the cursor address (same semantics as `run_to_breakpoint`).
    ///
    /// # Errors
    /// See `run_to_breakpoint`.
    pub fn run_to_cursor(&mut self, target_addr: Address) -> Result<NavEvent, NavError> {
        self.run_to_breakpoint(target_addr)
    }

    /// Run backward to the cursor address.
    ///
    /// # Errors
    /// See `reverse_run_to_breakpoint`.
    pub fn run_backward_to_cursor(&mut self, addr: Address) -> Result<NavEvent, NavError> {
        self.reverse_run_to_breakpoint(addr)
    }

    // ── Step Over / Step Out ──────────────────────────────────────────────

    /// Step over: advance until we return to the same call depth.
    /// Skips over any called functions at deeper depths.
    ///
    /// Uses the incrementally-maintained `current_call_depth` — O(1) per step,
    /// O(k) total where k is the number of instructions skipped.
    pub fn step_over_forward(&mut self) -> NavEvent {
        let initial_depth = self.current_call_depth;
        let mut steps = 0usize;
        let from = self.current_idx;

        loop {
            if steps >= self.step_limit {
                let ev = NavEvent::Cancelled {
                    reason: format!(
                        "step limit {} exceeded in step_over_forward",
                        self.step_limit
                    ),
                };
                self.event_window.push(ev.clone());
                return ev;
            }
            if self.current_idx + 1 >= self.trace.len() {
                let ev = NavEvent::End;
                self.event_window.push(ev.clone());
                return ev;
            }
            self.current_idx += 1;
            steps += 1;
            // Incrementally update depth: O(1).
            self.update_depth_forward(self.current_idx);
            if self.current_call_depth <= initial_depth {
                self.history.push(self.current_idx);
                let ev = NavEvent::Moved {
                    from,
                    to: self.current_idx,
                };
                self.event_window.push(ev.clone());
                return ev;
            }
        }
    }

    /// Step out: advance until the current function returns (depth decreases by one).
    ///
    /// Uses the incrementally-maintained `current_call_depth` — O(1) per step.
    pub fn step_out(&mut self) -> NavEvent {
        // Rebuild depth from scratch in case `current_idx` was set directly
        // (e.g. via `jump_to` or external mutation) without updating the cached depth.
        self.rebuild_depth();
        let initial_depth = self.current_call_depth;

        if initial_depth == 0 {
            return NavEvent::Cancelled {
                reason: "already at outermost frame, cannot step out".to_owned(),
            };
        }
        let target_depth = initial_depth - 1;
        let from = self.current_idx;
        let mut steps = 0usize;

        loop {
            if steps >= self.step_limit {
                let ev = NavEvent::Cancelled {
                    reason: format!("step limit {} exceeded in step_out", self.step_limit),
                };
                self.event_window.push(ev.clone());
                return ev;
            }
            if self.current_idx + 1 >= self.trace.len() {
                let ev = NavEvent::End;
                self.event_window.push(ev.clone());
                return ev;
            }
            self.current_idx += 1;
            steps += 1;
            // Incrementally update depth: O(1).
            self.update_depth_forward(self.current_idx);
            if self.current_call_depth <= target_depth {
                self.history.push(self.current_idx);
                let ev = NavEvent::Moved {
                    from,
                    to: self.current_idx,
                };
                self.event_window.push(ev.clone());
                return ev;
            }
        }
    }

    // ── Memory Timeline ───────────────────────────────────────────────────

    /// All writes to `addr`: returns `(trace_idx, value_written)` pairs.
    #[must_use]
    pub fn get_writes_to(&self, addr: Address) -> Vec<(usize, u64)> {
        self.mem_access_index.writes(addr)
    }

    /// All trace indices where `addr` was read.
    #[must_use]
    pub fn get_reads_from(&self, addr: Address) -> Vec<usize> {
        self.mem_access_index.reads(addr)
    }

    /// Reconstruct the value at `addr` at trace index `tick`.
    ///
    /// # Errors
    /// [`NavError::NoMemoryHistory`] if `addr` was never written before `tick`.
    pub fn get_value_at_tick(&self, addr: Address, tick: usize) -> Result<u64, NavError> {
        let writes = self.get_writes_to(addr);
        if writes.is_empty() {
            return Err(NavError::NoMemoryHistory(addr));
        }
        writes
            .into_iter()
            .rev()
            .find(|(i, _)| *i < tick)
            .map(|(_, v)| v)
            .ok_or(NavError::NoMemoryHistory(addr))
    }

    /// Find the first tick when `addr` was written with `value`.
    #[must_use]
    pub fn find_first_write(&self, addr: Address, value: u64) -> Option<usize> {
        self.mem_access_index.first_write_of_value(addr, value)
    }

    /// Find the last tick when `addr` was written with `value`.
    #[must_use]
    pub fn find_last_write(&self, addr: Address, value: u64) -> Option<usize> {
        self.mem_access_index.last_write_of_value(addr, value)
    }

    // ── Call Stack Reconstruction ─────────────────────────────────────────

    /// Reconstruct the call stack at `idx` by replaying from the beginning.
    #[must_use]
    pub fn call_stack_at(&mut self, idx: usize) -> Vec<StackFrame> {
        self.reconstructor.rebuild_to(&self.trace, idx)
    }

    /// Call stack at the current cursor position.
    #[must_use]
    pub fn current_call_stack(&mut self) -> Vec<StackFrame> {
        let idx = self.current_idx;
        self.call_stack_at(idx)
    }

    /// Find all (`trace_idx`, `call_site_addr`) pairs that called `func_addr`.
    #[must_use]
    pub fn find_callers_of(&self, func_addr: Address) -> Vec<(usize, Address)> {
        self.call_index.callers_of(func_addr).to_vec()
    }

    // ── Register Timeline ─────────────────────────────────────────────────

    /// Get the value history of `reg` in the given index range.
    #[must_use]
    pub fn register_history(&self, reg: RegId, range: Range<usize>) -> Vec<(usize, u64)> {
        self.reg_timeline.history(reg, range)
    }

    /// Find all trace indices where `reg` had exactly `value`.
    #[must_use]
    pub fn find_reg_value(&self, reg: RegId, value: u64) -> Vec<usize> {
        self.reg_timeline.find_value(reg, value)
    }

    /// Value of `reg` at the current cursor position.
    #[must_use]
    pub fn current_reg_value(&self, reg: RegId) -> Option<u64> {
        self.reg_timeline.value_at(reg, self.current_idx)
    }

    /// Full register snapshot at `idx`.
    #[must_use]
    pub fn reg_snapshot_at(&self, idx: usize) -> HashMap<RegId, u64> {
        self.reg_timeline.snapshot_at(idx)
    }

    // ── Coverage and Statistics ───────────────────────────────────────────

    /// All basic-block addresses visited in the trace.
    #[must_use]
    pub const fn visited_basic_blocks(&self) -> &HashSet<Address> {
        self.coverage.visited_basic_blocks()
    }

    /// Top-N most-executed basic blocks.
    #[must_use]
    pub fn hot_blocks(&self, top_n: usize) -> Vec<(Address, usize)> {
        self.coverage.hot_blocks(top_n)
    }

    /// Per-function call counts (keyed by callee address).
    #[must_use]
    pub const fn function_call_counts(&self) -> &HashMap<Address, usize> {
        &self.coverage.function_call_counts
    }

    /// Unique number of PCs visited.
    #[must_use]
    pub fn unique_pc_count(&self) -> usize {
        self.coverage.unique_block_count()
    }

    /// Total number of instructions in the trace.
    #[must_use]
    pub const fn total_instructions(&self) -> usize {
        self.trace.len()
    }

    // ── Playback / Timing ─────────────────────────────────────────────────

    /// Convert wall-clock milliseconds to a trace index.
    /// Requires TSC frequency to be set on the trace.
    #[must_use]
    pub fn tick_at_time(&self, ms: f64) -> usize {
        self.trace.idx_for_ms(ms).unwrap_or(0)
    }

    /// Convert a trace index to approximate wall-clock milliseconds.
    #[must_use]
    pub fn time_at_tick(&self, idx: usize) -> Option<f64> {
        let entry = self.trace.get(idx)?;
        let tsc = entry.tsc?;
        let base = self.trace.tsc_base?;
        let freq = self.trace.tsc_freq_hz?;
        let delta_tsc = tsc.saturating_sub(base);
        Some(f64::from(u32::try_from(delta_tsc).unwrap_or(u32::MAX)) / f64::from(u32::try_from(freq).unwrap_or(u32::MAX)) * 1000.0)
    }

    // ── Bookmark API ──────────────────────────────────────────────────────

    /// Set a bookmark at the current position.
    pub fn set_bookmark(&mut self, name: impl Into<String>, note: Option<String>) {
        let Some(entry) = self.trace.get(self.current_idx) else { return };
        let idx = entry.idx;
        let pc = entry.pc;
        let mut bm = Bookmark::new(name, idx, pc);
        if let Some(n) = note {
            bm = bm.with_note(n);
        }
        self.bookmarks.insert(bm);
    }

    /// Jump to a named bookmark.
    ///
    /// # Errors
    /// [`NavError::BookmarkNotFound`] if the bookmark does not exist.
    pub fn goto_bookmark(&mut self, name: &str) -> Result<NavEvent, NavError> {
        let (idx, pc) = {
            let bm = self
                .bookmarks
                .get(name)
                .ok_or_else(|| NavError::BookmarkNotFound(name.to_owned()))?;
            (bm.idx, bm.pc)
        };
        let from = self.current_idx;
        self.current_idx = idx;
        self.history.push(idx);
        self.event_window.push(NavEvent::Moved { from, to: idx });
        Ok(NavEvent::BookmarkHit {
            name: name.to_owned(),
            idx,
            pc,
        })
    }

    // ── Undo / Redo ───────────────────────────────────────────────────────

    /// Undo the last navigation action.
    pub fn undo(&mut self) -> Option<usize> {
        let prev = self.history.undo()?;
        self.current_idx = prev;
        Some(prev)
    }

    /// Redo the last undone navigation action.
    pub fn redo(&mut self) -> Option<usize> {
        let next = self.history.redo()?;
        self.current_idx = next;
        Some(next)
    }

    // ── Query / Search ────────────────────────────────────────────────────

    /// All entries with the given PC address, in trace order.
    #[must_use]
    pub fn entries_at_pc(&self, pc: Address) -> Vec<&TraceEntry> {
        self.pc_index
            .get(&pc)
            .map(|idxs| idxs.iter().filter_map(|&i| self.trace.get(i)).collect())
            .unwrap_or_default()
    }

    /// All entries in the given index range.
    #[must_use]
    pub fn entries_in_range(&self, range: Range<usize>) -> Vec<&TraceEntry> {
        // Clamping both ends independently bounds the length but not the ORDER:
        // a reversed range survives both `.min` calls and panics on the slice.
        // `rustre-events::event_replay::EventReplay::window` is the copy that
        // gets this right — clamp the end, then the start against the end.
        let end = range.end.min(self.trace.len());
        let start = range.start.min(end);
        self.trace.entries[start..end].iter().collect()
    }

    /// All CALL entries in the trace.
    #[must_use]
    pub fn all_calls(&self) -> Vec<&TraceEntry> {
        self.trace.entries.iter().filter(|e| e.is_call()).collect()
    }

    /// All RET entries in the trace.
    #[must_use]
    pub fn all_rets(&self) -> Vec<&TraceEntry> {
        self.trace.entries.iter().filter(|e| e.is_ret()).collect()
    }

    /// Number of times `pc` was visited.
    #[must_use]
    pub fn visit_count(&self, pc: Address) -> usize {
        self.coverage.hit_count(pc)
    }

    /// Peek forward `n` entries from the current position.
    #[must_use]
    pub fn peek_forward(&self, n: usize) -> Vec<&TraceEntry> {
        let start = (self.current_idx + 1).min(self.trace.len());
        let end = (start + n).min(self.trace.len());
        self.trace.entries[start..end].iter().collect()
    }

    /// Peek backward `n` entries from the current position.
    #[must_use]
    pub fn peek_backward(&self, n: usize) -> Vec<&TraceEntry> {
        let end = self.current_idx;
        let start = end.saturating_sub(n);
        self.trace.entries[start..end].iter().rev().collect()
    }

    // ── Progress / State ──────────────────────────────────────────────────

    /// Whether at the end of the trace.
    #[must_use]
    pub const fn at_end(&self) -> bool {
        self.trace.is_empty() || self.current_idx + 1 >= self.trace.len()
    }

    /// Whether at the beginning of the trace.
    #[must_use]
    pub const fn at_beginning(&self) -> bool {
        self.current_idx == 0
    }

    /// Cursor progress as a fraction `[0.0, 1.0]`.
    #[must_use]
    pub fn progress(&self) -> f64 {
        if self.trace.len() <= 1 {
            return 1.0;
        }
        f64::from(u32::try_from(self.current_idx).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.trace.len() - 1).unwrap_or(u32::MAX))
    }

    /// Return a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> NavigatorSummary {
        let entry = self.current_entry();
        NavigatorSummary {
            total_entries: self.trace.len(),
            current_idx: self.current_idx,
            current_pc: entry.map_or(0, |e| e.pc),
            current_tid: entry.map_or(0, |e| e.tid),
            unique_pcs: self.unique_pc_count(),
            total_calls: self.all_calls().len(),
            total_rets: self.all_rets().len(),
            binary_name: self.trace.binary_name.clone(),
        }
    }
}

// ─── NavigatorSummary ─────────────────────────────────────────────────────────

/// Summary of the navigator state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigatorSummary {
    pub total_entries: usize,
    pub current_idx: usize,
    pub current_pc: Address,
    pub current_tid: u32,
    pub unique_pcs: usize,
    pub total_calls: usize,
    pub total_rets: usize,
    pub binary_name: String,
}

impl std::fmt::Display for NavigatorSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TraceNavigator({}) idx={}/{} pc=0x{:x} tid={} unique_pcs={} calls={} rets={}",
            self.binary_name,
            self.current_idx,
            self.total_entries,
            self.current_pc,
            self.current_tid,
            self.unique_pcs,
            self.total_calls,
            self.total_rets,
        )
    }
}

// ─── TraceBuilder ─────────────────────────────────────────────────────────────

/// Convenience builder for constructing an `ExecutionTrace` programmatically.
#[derive(Debug, Default)]
pub struct TraceBuilder {
    pub entries: Vec<TraceEntry>,
    next_idx: usize,
    binary_name: String,
    tsc_freq_hz: Option<u64>,
    tsc: u64,
    tsc_per_insn: u64,
}

impl TraceBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new(binary_name: impl Into<String>) -> Self {
        Self {
            entries: Vec::new(),
            next_idx: 0,
            binary_name: binary_name.into(),
            tsc_freq_hz: None,
            tsc: 0,
            tsc_per_insn: 100,
        }
    }

    /// Set the TSC frequency.
    #[must_use]
    pub const fn tsc_freq(mut self, hz: u64) -> Self {
        self.tsc_freq_hz = Some(hz);
        self
    }

    /// Set the simulated TSC increment per instruction.
    #[must_use]
    pub const fn tsc_per_insn(mut self, n: u64) -> Self {
        self.tsc_per_insn = n;
        self
    }

    /// Add an instruction entry.
    pub fn insn(&mut self, pc: Address, tid: u32, disasm: impl Into<String>) -> usize {
        let idx = self.next_idx;
        let mut e = TraceEntry::insn(idx, pc, tid, disasm);
        e.tsc = Some(self.tsc);
        self.tsc += self.tsc_per_insn;
        self.entries.push(e);
        self.next_idx += 1;
        idx
    }

    /// Add a CALL entry.
    pub fn call(&mut self, pc: Address, tid: u32, target: Address, ret_addr: Address) -> usize {
        let idx = self.next_idx;
        let mut e = TraceEntry::call(idx, pc, tid, target, ret_addr);
        e.tsc = Some(self.tsc);
        self.tsc += self.tsc_per_insn;
        self.entries.push(e);
        self.next_idx += 1;
        idx
    }

    /// Add a RET entry.
    pub fn ret(&mut self, pc: Address, tid: u32, target: Address) -> usize {
        let idx = self.next_idx;
        let mut e = TraceEntry::ret(idx, pc, tid, target);
        e.tsc = Some(self.tsc);
        self.tsc += self.tsc_per_insn;
        self.entries.push(e);
        self.next_idx += 1;
        idx
    }

    /// Add a memory write to the last entry.
    pub fn mem_write(&mut self, addr: Address, bytes: Vec<u8>) {
        if let Some(e) = self.entries.last_mut() {
            e.add_mem_write(addr, bytes);
        }
    }

    /// Add a register snapshot to the last entry.
    pub fn regs(&mut self, regs: Vec<(RegId, u64)>) {
        if let Some(e) = self.entries.last_mut() {
            e.reg_snapshot = regs;
        }
    }

    /// Consume the builder and produce a `TraceNavigator`.
    #[must_use]
    pub fn build_navigator(self) -> TraceNavigator {
        let mut trace = ExecutionTrace::new(self.entries, self.binary_name);
        if let Some(hz) = self.tsc_freq_hz {
            trace = trace.with_tsc_freq(hz);
        }
        TraceNavigator::new(trace)
    }

    /// Consume the builder and produce an `ExecutionTrace`.
    #[must_use]
    pub fn build(self) -> ExecutionTrace {
        let mut trace = ExecutionTrace::new(self.entries, self.binary_name);
        if let Some(hz) = self.tsc_freq_hz {
            trace = trace.with_tsc_freq(hz);
        }
        trace
    }

    /// Number of entries added so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no entries have been added.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── TraceDiff ────────────────────────────────────────────────────────────────

/// Difference between two execution traces in terms of PC coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDiff {
    /// PCs in trace A but not B.
    pub only_in_a: HashSet<Address>,
    /// PCs in trace B but not A.
    pub only_in_b: HashSet<Address>,
    /// PCs present in both.
    pub common: HashSet<Address>,
    /// Jaccard similarity.
    pub jaccard: f64,
}

impl TraceDiff {
    /// Compute the diff between two traces.
    #[must_use]
    pub fn compute(a: &ExecutionTrace, b: &ExecutionTrace) -> Self {
        let set_a: HashSet<Address> = a.entries.iter().map(|e| e.pc).collect();
        let set_b: HashSet<Address> = b.entries.iter().map(|e| e.pc).collect();
        let only_in_a: HashSet<Address> = set_a.difference(&set_b).copied().collect();
        let only_in_b: HashSet<Address> = set_b.difference(&set_a).copied().collect();
        let common: HashSet<Address> = set_a.intersection(&set_b).copied().collect();
        let union_count = set_a.union(&set_b).count();
        let jaccard = if union_count == 0 {
            1.0
        } else {
            f64::from(u32::try_from(common.len()).unwrap_or(u32::MAX)) / f64::from(u32::try_from(union_count).unwrap_or(u32::MAX))
        };
        Self {
            only_in_a,
            only_in_b,
            common,
            jaccard,
        }
    }

    /// Coverage overlap percentage (0-100).
    #[must_use]
    pub fn overlap_pct(&self) -> f64 {
        self.jaccard * 100.0
    }
}

// ─── FunctionSlice ────────────────────────────────────────────────────────────

/// A slice of a trace corresponding to one invocation of a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSlice {
    /// Function entry address.
    pub fn_addr: Address,
    /// Start index in the trace.
    pub start_idx: usize,
    /// End index in the trace (inclusive).
    pub end_idx: usize,
    /// Number of instructions in this invocation.
    pub instruction_count: usize,
}

impl FunctionSlice {
    /// Extract all function slices from a trace.
    #[must_use]
    pub fn extract_all(trace: &ExecutionTrace) -> Vec<Self> {
        let mut slices = Vec::new();
        let mut call_stack: Vec<(Address, usize)> = Vec::new();

        for entry in &trace.entries {
            match entry.kind {
                EntryKind::Call { target, .. } => {
                    call_stack.push((target, entry.idx));
                }
                EntryKind::Ret { .. } => {
                    if let Some((fn_addr, start_idx)) = call_stack.pop() {
                        let count = entry.idx.saturating_sub(start_idx);
                        slices.push(Self {
                            fn_addr,
                            start_idx,
                            end_idx: entry.idx,
                            instruction_count: count,
                        });
                    }
                }
                _ => {}
            }
        }
        slices
    }

    /// Filter slices by function address.
    #[must_use]
    pub fn for_function(slices: &[Self], fn_addr: Address) -> Vec<&Self> {
        slices.iter().filter(|s| s.fn_addr == fn_addr).collect()
    }
}

// ─── Thread-filtered View ─────────────────────────────────────────────────────

/// A read-only view of the trace filtered to a specific thread.
#[derive(Debug, Clone)]
pub struct ThreadView<'a> {
    pub tid: u32,
    pub entries: Vec<&'a TraceEntry>,
}

impl<'a> ThreadView<'a> {
    /// Build a thread view from a trace.
    #[must_use]
    pub fn build(trace: &'a ExecutionTrace, tid: u32) -> Self {
        let entries = trace.entries.iter().filter(|e| e.tid == tid).collect();
        Self { tid, entries }
    }

    /// Number of entries in this thread view.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the thread produced no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All distinct PC values for this thread.
    #[must_use]
    pub fn unique_pcs(&self) -> HashSet<Address> {
        self.entries.iter().map(|e| e.pc).collect()
    }
}

// ─── LoopDetector ────────────────────────────────────────────────────────────

/// Detects tight loops in the trace by finding repeated PC sequences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopDetector {
    /// (`loop_head_pc`, `iteration_count`) pairs.
    pub loops: Vec<(Address, usize)>,
}

impl LoopDetector {
    /// Detect loops in a trace using a simple back-edge heuristic.
    #[must_use]
    pub fn detect(trace: &ExecutionTrace, min_iterations: usize) -> Self {
        let mut pc_first_seen: HashMap<Address, usize> = HashMap::new();
        let mut loop_counts: HashMap<Address, usize> = HashMap::new();
        let mut prev_pc = 0u64;

        for entry in &trace.entries {
            let pc = entry.pc;
            // Back-edge heuristic: if this PC was previously seen and is less
            // than the previous PC, it might be a loop head.
            if pc < prev_pc
                && let Some(&first_idx) = pc_first_seen.get(&pc)
                    && first_idx + 2 < entry.idx {
                        *loop_counts.entry(pc).or_insert(0) += 1;
                    }
            pc_first_seen.entry(pc).or_insert(entry.idx);
            prev_pc = pc;
        }

        let loops = loop_counts
            .into_iter()
            .filter(|(_, c)| *c >= min_iterations)
            .collect::<Vec<_>>();

        Self { loops }
    }

    /// Return the top-N tightest loops.
    #[must_use]
    pub fn top_loops(&self, n: usize) -> Vec<(Address, usize)> {
        let mut sorted = self.loops.clone();
        sorted.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        sorted.truncate(n);
        sorted
    }
}

// ─── ExecutionHeatmap ────────────────────────────────────────────────────────

/// Address heatmap suitable for display as a gradient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionHeatmap {
    /// (address, `normalised_heat`) where heat is in `[0.0, 1.0]`.
    pub entries: Vec<(Address, f64)>,
    /// Maximum raw hit count across all addresses.
    pub max_count: usize,
}

impl ExecutionHeatmap {
    /// Build a heatmap from coverage stats.
    #[must_use]
    pub fn build(coverage: &CoverageStats) -> Self {
        let max_count = coverage.block_counts.values().copied().max().unwrap_or(1);
        let mut entries: Vec<(Address, f64)> = coverage
            .block_counts
            .iter()
            .map(|(&addr, &count)| (addr, f64::from(u32::try_from(count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(max_count).unwrap_or(u32::MAX))))
            .collect();
        entries.sort_unstable_by_key(|a| a.0);
        Self { entries, max_count }
    }

    /// Return the heat for a specific address (0.0 if not visited).
    #[must_use]
    pub fn heat_at(&self, addr: Address) -> f64 {
        self.entries
            .iter()
            .find(|(a, _)| *a == addr)
            .map_or(0.0, |(_, h)| *h)
    }

    /// Return addresses sorted by descending heat.
    #[must_use]
    pub fn hottest(&self, n: usize) -> Vec<(Address, f64)> {
        let mut sorted = self.entries.clone();
        sorted.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        sorted.truncate(n);
        sorted
    }
}

// ─── DrcovRecord ─────────────────────────────────────────────────────────────

/// One module entry from a `DRcov` coverage file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrcovModule {
    pub id: u32,
    pub base: Address,
    pub end: Address,
    pub name: String,
}

/// A basic block entry from a `DRcov` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrcovBB {
    pub start: u32,
    pub size: u16,
    pub mod_id: u16,
}

/// Parsed `DRcov` coverage file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrcovData {
    pub modules: Vec<DrcovModule>,
    pub basic_blocks: Vec<DrcovBB>,
}

impl DrcovData {
    /// Parse a `DRcov` text-format coverage file.
    ///
    /// Understands the `DRCOV VERSION:`, `DRCOV FLAVOR:`, `Module Table:`,
    /// `BB Table:` header structure.
    #[must_use]
    pub fn parse(input: &str) -> Self {
        let mut modules = Vec::new();
        let mut basic_blocks = Vec::new();
        let mut in_modules = false;
        let mut in_bbs = false;

        for line in input.lines() {
            let line = line.trim();
            if line.starts_with("DRCOV VERSION:") || line.starts_with("DRCOV FLAVOR:") {
                continue;
            }
            if line.starts_with("Module Table:") {
                in_modules = true;
                in_bbs = false;
                continue;
            }
            if line.starts_with("BB Table:") {
                in_bbs = true;
                in_modules = false;
                continue;
            }
            if line.starts_with("Columns:") || line.is_empty() {
                continue;
            }
            if in_modules {
                // Format: id, base, end, entry, checksum, timestamp, path
                let parts: Vec<&str> = line.splitn(7, ',').map(str::trim).collect();
                if parts.len() >= 7 {
                    let id = parts[0].parse::<u32>().unwrap_or(0);
                    let base =
                        u64::from_str_radix(parts[1].trim_start_matches("0x"), 16).unwrap_or(0);
                    let end =
                        u64::from_str_radix(parts[2].trim_start_matches("0x"), 16).unwrap_or(0);
                    let name = parts[6]
                        .rsplit('/')
                        .next()
                        .or_else(|| parts[6].rsplit('\\').next())
                        .unwrap_or(parts[6])
                        .to_string();
                    modules.push(DrcovModule {
                        id,
                        base,
                        end,
                        name,
                    });
                }
            } else if in_bbs {
                // Binary-format BBs are typically not text; text format:
                // start, size, mod_id
                let parts: Vec<&str> = line.splitn(3, ',').map(str::trim).collect();
                if parts.len() >= 3 {
                    let start =
                        u32::from_str_radix(parts[0].trim_start_matches("0x"), 16).unwrap_or(0);
                    let size = parts[1].parse::<u16>().unwrap_or(0);
                    let mod_id = parts[2].parse::<u16>().unwrap_or(0);
                    basic_blocks.push(DrcovBB {
                        start,
                        size,
                        mod_id,
                    });
                }
            }
        }

        Self {
            modules,
            basic_blocks,
        }
    }

    /// Resolve all basic block absolute addresses.
    #[must_use]
    pub fn resolve_addresses(&self) -> Vec<Address> {
        let mod_map: HashMap<u16, Address> =
            self.modules.iter().map(|m| (u16::try_from(m.id).unwrap_or(u16::MAX), m.base)).collect();

        self.basic_blocks
            .iter()
            .filter_map(|bb| mod_map.get(&bb.mod_id).map(|base| base + u64::from(bb.start)))
            .collect()
    }

    /// Convert to a `CoverageStats`-compatible block hit map.
    #[must_use]
    pub fn to_block_hits(&self) -> HashMap<Address, usize> {
        let mut hits = HashMap::new();
        for addr in self.resolve_addresses() {
            *hits.entry(addr).or_insert(0) += 1;
        }
        hits
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────

    fn simple_trace() -> ExecutionTrace {
        let mut b = TraceBuilder::new("test.exe");
        b.insn(0x1000, 1, "nop");
        b.call(0x1004, 1, 0x2000, 0x1008);
        b.insn(0x2000, 1, "push rbp");
        b.insn(0x2001, 1, "add rax, 1");
        b.ret(0x2005, 1, 0x1008);
        b.insn(0x1008, 1, "xor eax, eax");
        b.build()
    }

    fn simple_nav() -> TraceNavigator {
        TraceNavigator::new(simple_trace())
    }

    // ── TraceEntry ────────────────────────────────────────────────────────

    #[test]
    fn test_entry_insn_fields() {
        let e = TraceEntry::insn(3, 0x1000, 1, "nop");
        assert_eq!(e.idx, 3);
        assert_eq!(e.pc, 0x1000);
        assert_eq!(e.tid, 1);
        assert!(!e.is_call());
        assert!(!e.is_ret());
    }

    #[test]
    fn test_entry_call_fields() {
        let e = TraceEntry::call(0, 0x1000, 1, 0x2000, 0x1005);
        assert!(e.is_call());
        assert_eq!(e.call_target(), Some(0x2000));
        assert_eq!(e.ret_addr(), Some(0x1005));
    }

    #[test]
    fn test_entry_ret_fields() {
        let e = TraceEntry::ret(0, 0x2010, 1, 0x1005);
        assert!(e.is_ret());
        assert_eq!(e.ret_target(), Some(0x1005));
    }

    #[test]
    fn test_entry_reg_value() {
        let e = TraceEntry::insn(0, 0x1000, 1, "mov rax, 42").with_regs(vec![(0, 42)]);
        assert_eq!(e.reg_value(0), Some(42));
        assert_eq!(e.reg_value(99), None);
    }

    #[test]
    fn test_entry_mem_write_read() {
        let mut e = TraceEntry::insn(0, 0x1000, 1, "store");
        e.add_mem_write(0xDEAD, vec![0xAA, 0xBB]);
        e.add_mem_read(0xBEEF, 8);
        assert_eq!(e.mem_writes.len(), 1);
        assert_eq!(e.mem_reads.len(), 1);
    }

    #[test]
    fn test_entry_display() {
        let e = TraceEntry::insn(7, 0x1000, 2, "nop");
        let s = e.to_string();
        assert!(s.contains('7'));
        assert!(s.contains("1000"));
        assert!(s.contains("nop"));
    }

    // ── bytes_to_u64 ──────────────────────────────────────────────────────

    #[test]
    fn test_bytes_to_u64_little_endian() {
        let val = bytes_to_u64(&[0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0]);
        assert_eq!(val, 0x0403_0201);
    }

    #[test]
    fn test_bytes_to_u64_short() {
        assert_eq!(bytes_to_u64(&[0xFF]), 0xFF);
    }

    #[test]
    fn test_bytes_to_u64_empty() {
        assert_eq!(bytes_to_u64(&[]), 0);
    }

    // ── MemAccessIndex ────────────────────────────────────────────────────

    #[test]
    fn test_mem_access_index_writes() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "store");
        b.mem_write(0xDEAD_BEEF, vec![0x42]);
        b.insn(0x1004, 1, "store2");
        b.mem_write(0xDEAD_BEEF, vec![0x99]);
        let nav = b.build_navigator();
        let writes = nav.get_writes_to(0xDEAD_BEEF);
        assert_eq!(writes.len(), 2);
    }

    #[test]
    fn test_mem_access_index_value_at_tick() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "nop");
        b.mem_write(0xABCD, vec![0x10]);
        b.insn(0x1004, 1, "nop");
        b.mem_write(0xABCD, vec![0x20]);
        b.insn(0x1008, 1, "nop");
        let nav = b.build_navigator();
        // Before any write (tick 0 → no write before it)
        assert!(nav.get_value_at_tick(0xABCD, 0).is_err());
        // After first write (idx 0, value 0x10), before second write (idx 1)
        let v_after_first = nav.get_value_at_tick(0xABCD, 1).unwrap();
        assert_eq!(v_after_first, 0x10);
        // After second write (idx 1, value 0x20)
        let v = nav.get_value_at_tick(0xABCD, 2).unwrap();
        assert_eq!(v, 0x20);
    }

    #[test]
    fn test_find_first_last_write() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "a");
        b.mem_write(0x500, vec![0x42]);
        b.insn(0x1004, 1, "b");
        b.mem_write(0x500, vec![0x99]);
        b.insn(0x1008, 1, "c");
        b.mem_write(0x500, vec![0x42]);
        let nav = b.build_navigator();
        assert_eq!(nav.find_first_write(0x500, 0x42), Some(0));
        assert_eq!(nav.find_last_write(0x500, 0x42), Some(2));
        assert_eq!(nav.find_first_write(0x500, 0x99), Some(1));
    }

    // ── CallIndex ─────────────────────────────────────────────────────────

    #[test]
    fn test_call_index_build() {
        let trace = simple_trace();
        let idx = CallIndex::build(&trace);
        assert_eq!(idx.function_count(), 1);
        let callers = idx.callers_of(0x2000);
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].1, 0x1004);
    }

    #[test]
    fn test_call_counts() {
        let trace = simple_trace();
        let idx = CallIndex::build(&trace);
        let counts = idx.call_counts();
        assert_eq!(counts.get(&0x2000), Some(&1));
    }

    // ── RegTimeline ───────────────────────────────────────────────────────

    #[test]
    fn test_reg_timeline_history() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "a");
        b.regs(vec![(0, 100)]);
        b.insn(0x1004, 1, "b");
        b.regs(vec![(0, 200)]);
        b.insn(0x1008, 1, "c");
        b.regs(vec![(0, 300)]);
        let nav = b.build_navigator();
        let hist = nav.register_history(0, 0..3);
        assert_eq!(hist.len(), 3);
        assert_eq!(hist[0].1, 100);
        assert_eq!(hist[2].1, 300);
    }

    #[test]
    fn test_reg_timeline_find_value() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "a");
        b.regs(vec![(1, 0xDEAD)]);
        b.insn(0x1004, 1, "b");
        b.regs(vec![(1, 0xBEEF)]);
        b.insn(0x1008, 1, "c");
        b.regs(vec![(1, 0xDEAD)]);
        let nav = b.build_navigator();
        let hits = nav.find_reg_value(1, 0xDEAD);
        assert_eq!(hits.len(), 2);
    }

    // ── Navigation ────────────────────────────────────────────────────────

    #[test]
    fn test_step_forward_basic() {
        let mut nav = simple_nav();
        assert_eq!(nav.current_idx, 0);
        assert!(nav.step_forward());
        assert_eq!(nav.current_idx, 1);
    }

    #[test]
    fn test_step_backward_basic() {
        let mut nav = simple_nav();
        nav.current_idx = 3;
        assert!(nav.step_backward());
        assert_eq!(nav.current_idx, 2);
    }

    #[test]
    fn test_step_forward_at_end_returns_false() {
        let mut nav = simple_nav();
        nav.current_idx = nav.trace.len() - 1;
        assert!(!nav.step_forward());
    }

    #[test]
    fn test_step_backward_at_beginning_returns_false() {
        let mut nav = simple_nav();
        assert!(!nav.step_backward());
        assert_eq!(nav.current_idx, 0);
    }

    #[test]
    fn test_jump_to_valid() {
        let mut nav = simple_nav();
        nav.jump_to(3).unwrap();
        assert_eq!(nav.current_idx, 3);
    }

    #[test]
    fn test_jump_to_out_of_bounds() {
        let mut nav = simple_nav();
        assert!(matches!(
            nav.jump_to(9999),
            Err(NavError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn test_run_to_breakpoint() {
        let mut nav = simple_nav();
        let ev = nav.run_to_breakpoint(0x2000).unwrap();
        assert_eq!(nav.current_idx, 2);
        assert!(matches!(ev, NavEvent::BreakpointHit { pc: 0x2000, .. }));
    }

    #[test]
    fn test_run_to_breakpoint_not_found() {
        let mut nav = simple_nav();
        assert!(matches!(
            nav.run_to_breakpoint(0xDEAD_BEEF),
            Err(NavError::NoResults)
        ));
    }

    #[test]
    fn test_reverse_run_to_breakpoint() {
        let mut nav = simple_nav();
        nav.current_idx = 5;
        let ev = nav.reverse_run_to_breakpoint(0x1000).unwrap();
        assert_eq!(nav.current_idx, 0);
        assert!(matches!(ev, NavEvent::BreakpointHit { pc: 0x1000, .. }));
    }

    #[test]
    fn test_step_over_forward() {
        let mut nav = simple_nav();
        nav.current_idx = 1; // At CALL
        let ev = nav.step_over_forward();
        assert!(matches!(ev, NavEvent::Moved { .. }));
        assert!(nav.current_idx > 1);
    }

    #[test]
    fn test_step_out() {
        let mut nav = simple_nav();
        nav.current_idx = 2; // Inside callee
        let ev = nav.step_out();
        assert!(matches!(ev, NavEvent::Moved { .. } | NavEvent::End));
    }

    // ── Call Stack ────────────────────────────────────────────────────────

    #[test]
    fn test_call_stack_at_inside_callee() {
        let mut nav = simple_nav();
        let stack = nav.call_stack_at(3);
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].fn_addr, 0x2000);
    }

    #[test]
    fn test_call_stack_at_before_call() {
        let mut nav = simple_nav();
        let stack = nav.call_stack_at(0);
        assert_eq!(stack.len(), 0);
    }

    #[test]
    fn test_find_callers_of() {
        let nav = simple_nav();
        let callers = nav.find_callers_of(0x2000);
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].1, 0x1004);
    }

    // ── Coverage ──────────────────────────────────────────────────────────

    #[test]
    fn test_visited_basic_blocks() {
        let nav = simple_nav();
        let vb = nav.visited_basic_blocks();
        assert!(vb.contains(&0x1000));
        assert!(vb.contains(&0x2000));
    }

    #[test]
    fn test_hot_blocks() {
        let mut b = TraceBuilder::new("t");
        for _ in 0..5 {
            b.insn(0x1000, 1, "hot");
        }
        b.insn(0x2000, 1, "cold");
        let nav = b.build_navigator();
        let hot = nav.hot_blocks(1);
        assert_eq!(hot[0].0, 0x1000);
        assert_eq!(hot[0].1, 5);
    }

    #[test]
    fn test_function_call_counts() {
        let nav = simple_nav();
        let counts = nav.function_call_counts();
        assert_eq!(counts.get(&0x2000), Some(&1));
    }

    // ── Bookmark ──────────────────────────────────────────────────────────

    #[test]
    fn test_bookmark_set_goto() {
        let mut nav = simple_nav();
        nav.current_idx = 2;
        nav.set_bookmark("callee_start", None);
        nav.current_idx = 0;
        let ev = nav.goto_bookmark("callee_start").unwrap();
        assert_eq!(nav.current_idx, 2);
        assert!(matches!(ev, NavEvent::BookmarkHit { .. }));
    }

    #[test]
    fn test_bookmark_not_found() {
        let mut nav = simple_nav();
        assert!(matches!(
            nav.goto_bookmark("nonexistent"),
            Err(NavError::BookmarkNotFound(_))
        ));
    }

    // ── Undo/Redo ─────────────────────────────────────────────────────────

    #[test]
    fn test_undo_redo() {
        let mut nav = simple_nav();
        nav.step_forward();
        nav.step_forward();
        assert_eq!(nav.current_idx, 2);
        nav.undo();
        assert_eq!(nav.current_idx, 1);
        nav.redo();
        assert_eq!(nav.current_idx, 2);
    }

    // ── Timing ────────────────────────────────────────────────────────────

    #[test]
    fn test_tick_at_time() {
        let mut b = TraceBuilder::new("t")
            .tsc_freq(1_000_000_000)
            .tsc_per_insn(1_000_000);
        b.insn(0x1000, 1, "a");
        b.insn(0x1001, 1, "b");
        b.insn(0x1002, 1, "c");
        let nav = b.build_navigator();
        let idx = nav.tick_at_time(2.0);
        assert!(idx <= 2);
    }

    // ── TraceDiff ─────────────────────────────────────────────────────────

    #[test]
    fn test_trace_diff_identical() {
        let trace = simple_trace();
        let diff = TraceDiff::compute(&trace, &trace);
        assert!(diff.only_in_a.is_empty());
        assert!((diff.jaccard - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_trace_diff_disjoint() {
        let mut b1 = TraceBuilder::new("t1");
        b1.insn(0x1000, 1, "a");
        let t1 = b1.build();
        let mut b2 = TraceBuilder::new("t2");
        b2.insn(0x9000, 1, "b");
        let t2 = b2.build();
        let diff = TraceDiff::compute(&t1, &t2);
        assert!((diff.jaccard - 0.0).abs() < 1e-9);
    }

    // ── FunctionSlice ─────────────────────────────────────────────────────

    #[test]
    fn test_function_slice_extract() {
        let trace = simple_trace();
        let slices = FunctionSlice::extract_all(&trace);
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0].fn_addr, 0x2000);
    }

    // ── ThreadView ────────────────────────────────────────────────────────

    #[test]
    fn test_thread_view_build() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "t1");
        b.insn(0x1001, 2, "t2");
        b.insn(0x1002, 1, "t1b");
        let trace = b.build();
        let view = ThreadView::build(&trace, 1);
        assert_eq!(view.len(), 2);
    }

    // ── LoopDetector ──────────────────────────────────────────────────────

    #[test]
    fn test_loop_detector_detect() {
        let mut b = TraceBuilder::new("t");
        for i in 0..10u64 {
            b.insn(0x1000, 1, "loop_head");
            b.insn(0x1000 + (i + 1) * 4, 1, "loop_body");
        }
        let trace = b.build();
        let detector = LoopDetector::detect(&trace, 3);
        assert!(!detector.loops.is_empty());
    }

    // ── ExecutionHeatmap ──────────────────────────────────────────────────

    #[test]
    fn test_heatmap_build() {
        let mut b = TraceBuilder::new("t");
        for _ in 0..10 {
            b.insn(0x1000, 1, "hot");
        }
        b.insn(0x2000, 1, "cold");
        let trace = b.build();
        let stats = CoverageStats::build(&trace);
        let heatmap = ExecutionHeatmap::build(&stats);
        let hot = heatmap.heat_at(0x1000);
        let cold = heatmap.heat_at(0x2000);
        assert!(hot > cold);
        assert!((hot - 1.0).abs() < 1e-9);
    }

    // ── NavigatorSummary ──────────────────────────────────────────────────

    #[test]
    fn test_summary_display() {
        let nav = simple_nav();
        let s = nav.summary().to_string();
        assert!(s.contains("test.exe"));
        assert!(s.contains("calls=1"));
    }

    // ── Progress ──────────────────────────────────────────────────────────

    #[test]
    fn test_progress_at_start() {
        let nav = simple_nav();
        assert!((nav.progress() - 0.0).abs() < 1e-6);
    }

    #[test]
    fn test_progress_at_end() {
        let mut nav = simple_nav();
        nav.current_idx = nav.trace.len() - 1;
        assert!((nav.progress() - 1.0).abs() < 1e-6);
    }

    // ── CoverageStats ─────────────────────────────────────────────────────

    #[test]
    fn test_coverage_stats_total_instructions() {
        let mut b = TraceBuilder::new("t");
        for _ in 0..20 {
            b.insn(0x1000, 1, "nop");
        }
        let trace = b.build();
        let stats = CoverageStats::build(&trace);
        assert_eq!(stats.total_instructions(), 20);
    }

    // ── StackFrame ────────────────────────────────────────────────────────

    #[test]
    fn test_stack_frame_display_name_with_symbol() {
        let f = StackFrame::new(0x1000, 0x2000, 0, 5).with_name("main");
        assert_eq!(f.display_name(), "main");
    }

    #[test]
    fn test_stack_frame_display_name_no_symbol() {
        let f = StackFrame::new(0x1000, 0x2000, 0, 5);
        assert!(f.display_name().contains("1000"));
    }

    // ── BookmarkStore ─────────────────────────────────────────────────────

    #[test]
    fn test_bookmark_store_insert_get_remove() {
        let mut store = BookmarkStore::new();
        let bm = Bookmark::new("start", 0, 0x1000);
        store.insert(bm);
        assert!(store.get("start").is_some());
        assert!(store.remove("start").is_ok());
        assert!(store.get("start").is_none());
    }

    #[test]
    fn test_bookmark_store_sorted_by_idx() {
        let mut store = BookmarkStore::new();
        store.insert(Bookmark::new("b", 10, 0x1000));
        store.insert(Bookmark::new("a", 2, 0x1004));
        let sorted = store.sorted_by_idx();
        assert_eq!(sorted[0].name, "a");
    }

    // ── NavigationHistory ─────────────────────────────────────────────────

    #[test]
    fn test_nav_history_undo_redo() {
        let mut h = NavigationHistory::new();
        h.push(1);
        h.push(2);
        h.push(3);
        assert_eq!(h.undo(), Some(2));
        assert_eq!(h.redo(), Some(3));
    }

    // ── StepWindow ────────────────────────────────────────────────────────

    #[test]
    fn test_step_window_evicts_oldest() {
        let mut w = StepWindow::new(2);
        w.push(NavEvent::End);
        w.push(NavEvent::Beginning);
        w.push(NavEvent::End);
        assert_eq!(w.len(), 2);
    }

    // ── DrcovData ─────────────────────────────────────────────────────────

    #[test]
    fn test_drcov_parse_empty() {
        let d = DrcovData::parse("");
        assert!(d.modules.is_empty());
        assert!(d.basic_blocks.is_empty());
    }

    #[test]
    fn test_drcov_resolve_addresses_empty() {
        let d = DrcovData {
            modules: vec![],
            basic_blocks: vec![],
        };
        assert!(d.resolve_addresses().is_empty());
    }

    // ── peek_forward / peek_backward ──────────────────────────────────────

    #[test]
    fn test_peek_forward() {
        let mut nav = simple_nav();
        nav.current_idx = 0;
        let peeked = nav.peek_forward(3);
        assert_eq!(peeked.len(), 3);
        assert_eq!(peeked[0].idx, 1);
    }

    #[test]
    fn test_peek_backward() {
        let mut nav = simple_nav();
        nav.current_idx = 4;
        let peeked = nav.peek_backward(2);
        assert_eq!(peeked.len(), 2);
    }

    // ── run_to_cursor / run_backward_to_cursor ─────────────────────────────

    #[test]
    fn test_run_to_cursor_alias() {
        let mut nav = simple_nav();
        let ev = nav.run_to_cursor(0x2000).unwrap();
        assert!(matches!(ev, NavEvent::BreakpointHit { pc: 0x2000, .. }));
    }

    #[test]
    fn test_run_backward_to_cursor_alias() {
        let mut nav = simple_nav();
        nav.current_idx = 5;
        let ev = nav.run_backward_to_cursor(0x1004).unwrap();
        assert!(matches!(ev, NavEvent::BreakpointHit { pc: 0x1004, .. }));
    }
}

// ─── DataFlowTracker ─────────────────────────────────────────────────────────

/// Tracks how a value flows through registers and memory over time.
///
/// Starting from a source (register or memory address at a given tick),
/// this tracker follows writes that use the current value of the tracked
/// location, approximating lightweight data-flow analysis over the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowTracker {
    /// Chain of (tick, kind, `location_description`, value) events.
    pub flow: Vec<DataFlowEvent>,
    /// Origin description.
    pub origin: String,
}

/// One step in a data-flow chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowEvent {
    /// Trace index.
    pub idx: usize,
    /// Program counter at this event.
    pub pc: Address,
    /// Human-readable location (e.g., "rax", "mem[0x1000]").
    pub location: String,
    /// Value at this point.
    pub value: u64,
    /// How the value was obtained.
    pub source: DataFlowSource,
}

/// How a data-flow value was observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataFlowSource {
    /// Value was loaded from a register snapshot.
    Register(RegId),
    /// Value was written to memory.
    MemoryWrite(Address),
    /// Value was read from memory.
    MemoryRead(Address),
    /// Initial/seed value.
    Origin,
}

impl DataFlowTracker {
    /// Seed a tracker from a register value at a specific tick.
    #[must_use]
    pub fn from_register(nav: &TraceNavigator, reg: RegId, start_idx: usize) -> Self {
        let mut flow = Vec::new();
        let entry = nav.trace.get(start_idx);
        let pc = entry.map_or(0, |e| e.pc);

        let seed_value = nav.reg_timeline.value_at(reg, start_idx).unwrap_or(0);
        flow.push(DataFlowEvent {
            idx: start_idx,
            pc,
            location: format!("reg[{reg}]"),
            value: seed_value,
            source: DataFlowSource::Origin,
        });

        // Follow subsequent ticks where the same register changes.
        for tick in (start_idx + 1)..nav.trace.len() {
            let Some(e) = nav.trace.get(tick) else { break };
            for (r, v) in &e.reg_snapshot {
                if *r == reg {
                    flow.push(DataFlowEvent {
                        idx: tick,
                        pc: e.pc,
                        location: format!("reg[{reg}]"),
                        value: *v,
                        source: DataFlowSource::Register(*r),
                    });
                }
            }
        }

        Self {
            flow,
            origin: format!("reg[{reg}]@{start_idx}"),
        }
    }

    /// Seed a tracker from a memory address, following all subsequent writes.
    #[must_use]
    pub fn from_memory(nav: &TraceNavigator, addr: Address, start_idx: usize) -> Self {
        let mut flow = Vec::new();
        let seed_value = nav
            .mem_access_index
            .value_at_idx(addr, start_idx)
            .unwrap_or(0);
        let pc = nav.trace.get(start_idx).map_or(0, |e| e.pc);

        flow.push(DataFlowEvent {
            idx: start_idx,
            pc,
            location: format!("mem[0x{addr:x}]"),
            value: seed_value,
            source: DataFlowSource::Origin,
        });

        for (tick, value) in nav.mem_access_index.writes(addr) {
            if tick >= start_idx {
                let ep = nav.trace.get(tick).map_or(0, |e| e.pc);
                flow.push(DataFlowEvent {
                    idx: tick,
                    pc: ep,
                    location: format!("mem[0x{addr:x}]"),
                    value,
                    source: DataFlowSource::MemoryWrite(addr),
                });
            }
        }

        Self {
            flow,
            origin: format!("mem[0x{addr:x}]@{start_idx}"),
        }
    }

    /// Return the final value in the flow chain.
    #[must_use]
    pub fn final_value(&self) -> Option<u64> {
        self.flow.last().map(|e| e.value)
    }

    /// Return the number of events in the flow chain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.flow.len()
    }

    /// Returns `true` if the flow chain is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.flow.is_empty()
    }

    /// Return all unique values observed.
    #[must_use]
    pub fn unique_values(&self) -> HashSet<u64> {
        self.flow.iter().map(|e| e.value).collect()
    }

    /// Return all trace indices in this flow chain.
    #[must_use]
    pub fn ticks(&self) -> Vec<usize> {
        self.flow.iter().map(|e| e.idx).collect()
    }

    /// Return events where the value changed from the previous event.
    #[must_use]
    pub fn value_changes(&self) -> Vec<&DataFlowEvent> {
        self.flow
            .windows(2)
            .filter(|w| w[0].value != w[1].value)
            .map(|w| &w[1])
            .collect()
    }
}

// ─── TraceAnnotation ─────────────────────────────────────────────────────────

/// A user-defined annotation attached to a range of trace entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceAnnotation {
    /// Start index (inclusive).
    pub start_idx: usize,
    /// End index (inclusive).
    pub end_idx: usize,
    /// Annotation text.
    pub text: String,
    /// Optional tag (e.g., "suspicious", "interesting", "crypto").
    pub tag: Option<String>,
    /// Color hint for the UI (e.g., "#ff0000").
    pub color: Option<String>,
}

impl TraceAnnotation {
    /// Create a new annotation.
    #[must_use]
    pub fn new(start_idx: usize, end_idx: usize, text: impl Into<String>) -> Self {
        Self {
            start_idx,
            end_idx,
            text: text.into(),
            tag: None,
            color: None,
        }
    }

    /// Attach a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Attach a color hint.
    #[must_use]
    pub fn with_color(mut self, color: impl Into<String>) -> Self {
        self.color = Some(color.into());
        self
    }

    /// Returns `true` if the given index falls within the annotated range.
    #[must_use]
    pub const fn covers(&self, idx: usize) -> bool {
        idx >= self.start_idx && idx <= self.end_idx
    }

    /// Returns the span (number of entries covered).
    #[must_use]
    pub const fn span(&self) -> usize {
        self.end_idx.saturating_sub(self.start_idx) + 1
    }
}

impl std::fmt::Display for TraceAnnotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}..{}] {}{}",
            self.start_idx,
            self.end_idx,
            self.text,
            self.tag
                .as_deref()
                .map(|t| format!(" #{t}"))
                .unwrap_or_default(),
        )
    }
}

/// A collection of trace annotations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnnotationStore {
    annotations: Vec<TraceAnnotation>,
}

impl AnnotationStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an annotation.
    pub fn add(&mut self, ann: TraceAnnotation) {
        self.annotations.push(ann);
    }

    /// All annotations that cover the given index.
    #[must_use]
    pub fn at_idx(&self, idx: usize) -> Vec<&TraceAnnotation> {
        self.annotations.iter().filter(|a| a.covers(idx)).collect()
    }

    /// All annotations with a given tag.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<&TraceAnnotation> {
        self.annotations
            .iter()
            .filter(|a| a.tag.as_deref() == Some(tag))
            .collect()
    }

    /// Number of annotations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.annotations.len()
    }

    /// Returns `true` if there are no annotations.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.annotations.is_empty()
    }

    /// Remove all annotations that overlap with the given range.
    pub fn remove_in_range(&mut self, start: usize, end: usize) {
        self.annotations
            .retain(|a| a.end_idx < start || a.start_idx > end);
    }
}

// ─── TraceFilter ─────────────────────────────────────────────────────────────

/// A composable filter for trace entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFilter {
    /// Require PC in this set (empty = no filter).
    pub pc_whitelist: HashSet<Address>,
    /// Exclude entries with these PCs.
    pub pc_blacklist: HashSet<Address>,
    /// Only include entries from this thread ID (None = all).
    pub tid: Option<u32>,
    /// Only include entries after this index (inclusive).
    pub from_idx: Option<usize>,
    /// Only include entries before this index (inclusive).
    pub to_idx: Option<usize>,
    /// Only include entries with at least one memory write.
    pub only_mem_writes: bool,
    /// Only include CALL entries.
    pub only_calls: bool,
    /// Only include RET entries.
    pub only_rets: bool,
}

impl TraceFilter {
    /// Create an empty filter that matches everything.
    #[must_use]
    pub fn any() -> Self {
        Self {
            pc_whitelist: HashSet::new(),
            pc_blacklist: HashSet::new(),
            tid: None,
            from_idx: None,
            to_idx: None,
            only_mem_writes: false,
            only_calls: false,
            only_rets: false,
        }
    }

    /// Filter to a specific thread.
    #[must_use]
    pub const fn for_tid(mut self, tid: u32) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Filter to an index range.
    #[must_use]
    pub const fn in_range(mut self, from: usize, to: usize) -> Self {
        self.from_idx = Some(from);
        self.to_idx = Some(to);
        self
    }

    /// Only include entries whose PC is in the given list.
    #[must_use]
    pub fn at_pcs(mut self, pcs: impl IntoIterator<Item = Address>) -> Self {
        self.pc_whitelist.extend(pcs);
        self
    }

    /// Only include memory write entries.
    #[must_use]
    pub const fn with_mem_writes(mut self) -> Self {
        self.only_mem_writes = true;
        self
    }

    /// Only include CALL entries.
    #[must_use]
    pub const fn calls_only(mut self) -> Self {
        self.only_calls = true;
        self
    }

    /// Test whether an entry matches this filter.
    #[must_use]
    pub fn matches(&self, entry: &TraceEntry) -> bool {
        if let Some(tid) = self.tid
            && entry.tid != tid {
                return false;
            }
        if let Some(from) = self.from_idx
            && entry.idx < from {
                return false;
            }
        if let Some(to) = self.to_idx
            && entry.idx > to {
                return false;
            }
        if !self.pc_whitelist.is_empty() && !self.pc_whitelist.contains(&entry.pc) {
            return false;
        }
        if self.pc_blacklist.contains(&entry.pc) {
            return false;
        }
        if self.only_mem_writes && entry.mem_writes.is_empty() {
            return false;
        }
        if self.only_calls && !entry.is_call() {
            return false;
        }
        if self.only_rets && !entry.is_ret() {
            return false;
        }
        true
    }

    /// Apply this filter to a trace, returning matching entries.
    #[must_use]
    pub fn apply<'a>(&self, trace: &'a ExecutionTrace) -> Vec<&'a TraceEntry> {
        trace.entries.iter().filter(|e| self.matches(e)).collect()
    }
}

// ─── TraceSearcher ───────────────────────────────────────────────────────────

/// Text-based search over trace disassembly strings.
#[derive(Debug, Clone, Default)]
pub struct TraceSearcher {
    /// Disassembly substring to search for (case-insensitive).
    pattern: String,
}

impl TraceSearcher {
    /// Create a new searcher with the given pattern.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into().to_lowercase(),
        }
    }

    /// Find all entries in `trace` whose disassembly contains the pattern.
    #[must_use]
    pub fn find_all<'a>(&self, trace: &'a ExecutionTrace) -> Vec<&'a TraceEntry> {
        let pat = &self.pattern;
        trace
            .entries
            .iter()
            .filter(|e| e.disasm.to_lowercase().contains(pat.as_str()))
            .collect()
    }

    /// Find the next matching entry after `from_idx`.
    #[must_use]
    pub fn find_next<'a>(
        &self,
        trace: &'a ExecutionTrace,
        from_idx: usize,
    ) -> Option<&'a TraceEntry> {
        let pat = &self.pattern;
        trace.entries[from_idx + 1..]
            .iter()
            .find(|e| e.disasm.to_lowercase().contains(pat.as_str()))
    }

    /// Find the previous matching entry before `from_idx`.
    #[must_use]
    pub fn find_prev<'a>(
        &self,
        trace: &'a ExecutionTrace,
        from_idx: usize,
    ) -> Option<&'a TraceEntry> {
        let pat = &self.pattern;
        trace.entries[..from_idx]
            .iter()
            .rev()
            .find(|e| e.disasm.to_lowercase().contains(pat.as_str()))
    }
}

// ─── TraceStatistics ─────────────────────────────────────────────────────────

/// Extended statistics about an execution trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStatistics {
    pub total_entries: usize,
    pub unique_pcs: usize,
    pub total_calls: usize,
    pub total_rets: usize,
    pub total_branches: usize,
    pub total_syscalls: usize,
    pub total_exceptions: usize,
    pub total_mem_writes: usize,
    pub total_mem_reads: usize,
    pub thread_count: usize,
    pub unique_thread_ids: HashSet<u32>,
    pub tsc_duration: Option<u64>,
    pub call_ret_balance: i64,
}

impl TraceStatistics {
    /// Compute statistics from a trace.
    #[must_use]
    pub fn compute(trace: &ExecutionTrace) -> Self {
        let mut unique_pcs: HashSet<u64> = HashSet::new();
        let mut calls = 0usize;
        let mut rets = 0usize;
        let mut branches = 0usize;
        let mut syscalls = 0usize;
        let mut exceptions = 0usize;
        let mut mem_writes = 0usize;
        let mut mem_reads = 0usize;
        let mut tids: HashSet<u32> = HashSet::new();

        for e in &trace.entries {
            unique_pcs.insert(e.pc);
            tids.insert(e.tid);
            mem_writes += e.mem_writes.len();
            mem_reads += e.mem_reads.len();
            match e.kind {
                EntryKind::Call { .. } => calls += 1,
                EntryKind::Ret { .. } => rets += 1,
                EntryKind::Branch { .. } => branches += 1,
                EntryKind::Syscall { .. } => syscalls += 1,
                EntryKind::Exception { .. } => exceptions += 1,
                EntryKind::Insn => {}
            }
        }

        let tsc_duration = match (
            trace.entries.first().and_then(|e| e.tsc),
            trace.entries.last().and_then(|e| e.tsc),
        ) {
            (Some(first), Some(last)) => Some(last.saturating_sub(first)),
            _ => None,
        };

        let call_ret_balance = i64::try_from(calls).unwrap_or(i64::MAX) - i64::try_from(rets).unwrap_or(i64::MAX);

        Self {
            total_entries: trace.len(),
            unique_pcs: unique_pcs.len(),
            total_calls: calls,
            total_rets: rets,
            total_branches: branches,
            total_syscalls: syscalls,
            total_exceptions: exceptions,
            total_mem_writes: mem_writes,
            total_mem_reads: mem_reads,
            thread_count: tids.len(),
            unique_thread_ids: tids,
            tsc_duration,
            call_ret_balance,
        }
    }

    /// Whether calls and rets are balanced (good indicator of clean trace).
    #[must_use]
    pub const fn is_balanced(&self) -> bool {
        self.call_ret_balance == 0
    }

    /// Instructions per unique PC (ILP approximation).
    #[must_use]
    pub fn insn_per_unique_pc(&self) -> f64 {
        if self.unique_pcs == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.total_entries).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.unique_pcs).unwrap_or(u32::MAX))
    }
}

impl std::fmt::Display for TraceStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Stats(entries={} pcs={} calls={} rets={} branches={} syscalls={} \
             mem_w={} mem_r={} threads={} balance={})",
            self.total_entries,
            self.unique_pcs,
            self.total_calls,
            self.total_rets,
            self.total_branches,
            self.total_syscalls,
            self.total_mem_writes,
            self.total_mem_reads,
            self.thread_count,
            self.call_ret_balance,
        )
    }
}

// ─── TraceSlice ───────────────────────────────────────────────────────────────

/// An immutable sub-sequence of a trace between two indices.
#[derive(Debug, Clone)]
pub struct TraceSlice<'a> {
    pub entries: &'a [TraceEntry],
    pub start_idx: usize,
    pub end_idx: usize,
}

impl<'a> TraceSlice<'a> {
    /// Create a slice from a trace.
    ///
    /// Clamps `start` and `end` to valid range.
    #[must_use]
    pub fn new(trace: &'a ExecutionTrace, start: usize, end: usize) -> Self {
        let lo = start.min(trace.len());
        let hi = (end.saturating_add(1)).min(trace.len()).max(lo);
        Self {
            entries: &trace.entries[lo..hi],
            start_idx: lo,
            end_idx: hi.saturating_sub(1),
        }
    }

    /// Number of entries in the slice.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the slice is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All PC addresses in the slice.
    #[must_use]
    pub fn pcs(&self) -> HashSet<Address> {
        self.entries.iter().map(|e| e.pc).collect()
    }

    /// Count entries matching a predicate.
    #[must_use]
    pub fn count_matching(&self, pred: impl Fn(&TraceEntry) -> bool) -> usize {
        self.entries.iter().filter(|e| pred(e)).count()
    }

    /// Compute statistics for this slice.
    #[must_use]
    pub fn statistics(&self) -> SliceStats {
        let calls = self.entries.iter().filter(|e| e.is_call()).count();
        let rets = self.entries.iter().filter(|e| e.is_ret()).count();
        let unique: HashSet<Address> = self.entries.iter().map(|e| e.pc).collect();
        SliceStats {
            len: self.entries.len(),
            unique_pcs: unique.len(),
            calls,
            rets,
        }
    }
}

/// Statistics for a trace slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceStats {
    pub len: usize,
    pub unique_pcs: usize,
    pub calls: usize,
    pub rets: usize,
}

// ─── Extended Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    fn simple_nav() -> TraceNavigator {
        let mut b = TraceBuilder::new("test.exe");
        b.insn(0x1000, 1, "nop");
        b.call(0x1004, 1, 0x2000, 0x1008);
        b.insn(0x2000, 1, "push rbp");
        b.insn(0x2001, 1, "add rax, 1");
        b.ret(0x2005, 1, 0x1008);
        b.insn(0x1008, 1, "xor eax, eax");
        b.build_navigator()
    }

    // ── DataFlowTracker ───────────────────────────────────────────────────

    #[test]
    fn test_data_flow_from_register() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "mov rax, 1");
        b.regs(vec![(0, 1)]);
        b.insn(0x1004, 1, "add rax, 1");
        b.regs(vec![(0, 2)]);
        b.insn(0x1008, 1, "add rax, 1");
        b.regs(vec![(0, 3)]);
        let nav = b.build_navigator();
        let dft = DataFlowTracker::from_register(&nav, 0, 0);
        // seed (idx 0) + changes at idx 1 and idx 2 = 3 total
        assert_eq!(dft.len(), 3);
        assert_eq!(dft.final_value(), Some(3));
    }

    #[test]
    fn test_data_flow_unique_values() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "a");
        b.regs(vec![(1, 10)]);
        b.insn(0x1004, 1, "b");
        b.regs(vec![(1, 20)]);
        b.insn(0x1008, 1, "c");
        b.regs(vec![(1, 10)]); // revisit 10
        let nav = b.build_navigator();
        let dft = DataFlowTracker::from_register(&nav, 1, 0);
        let unique = dft.unique_values();
        // Unique values: 0 (seed from no snapshot at 0), 10, 20
        assert!(unique.contains(&10));
        assert!(unique.contains(&20));
    }

    #[test]
    fn test_data_flow_from_memory() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "store");
        b.mem_write(0xABCD, vec![0x42]);
        b.insn(0x1004, 1, "store2");
        b.mem_write(0xABCD, vec![0xFF]);
        let nav = b.build_navigator();
        let dft = DataFlowTracker::from_memory(&nav, 0xABCD, 0);
        assert!(dft.len() >= 2);
        assert_eq!(dft.final_value(), Some(0xFF));
    }

    #[test]
    fn test_data_flow_value_changes() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "a");
        b.regs(vec![(2, 5)]);
        b.insn(0x1004, 1, "b");
        b.regs(vec![(2, 5)]); // no change
        b.insn(0x1008, 1, "c");
        b.regs(vec![(2, 7)]); // change
        let nav = b.build_navigator();
        let dft = DataFlowTracker::from_register(&nav, 2, 0);
        let changes = dft.value_changes();
        // Should detect the change from 5 to 7
        assert!(!changes.is_empty());
    }

    // ── TraceAnnotation ───────────────────────────────────────────────────

    #[test]
    fn test_annotation_covers() {
        let ann = TraceAnnotation::new(5, 10, "test");
        assert!(ann.covers(5));
        assert!(ann.covers(7));
        assert!(ann.covers(10));
        assert!(!ann.covers(4));
        assert!(!ann.covers(11));
    }

    #[test]
    fn test_annotation_span() {
        let ann = TraceAnnotation::new(3, 7, "test");
        assert_eq!(ann.span(), 5);
    }

    #[test]
    fn test_annotation_display() {
        let ann = TraceAnnotation::new(0, 5, "crypto loop").with_tag("suspicious");
        let s = ann.to_string();
        assert!(s.contains("crypto loop"));
        assert!(s.contains("suspicious"));
    }

    // ── AnnotationStore ───────────────────────────────────────────────────

    #[test]
    fn test_annotation_store_at_idx() {
        let mut store = AnnotationStore::new();
        store.add(TraceAnnotation::new(0, 5, "a").with_tag("t1"));
        store.add(TraceAnnotation::new(3, 8, "b").with_tag("t2"));
        let at_3 = store.at_idx(3);
        assert_eq!(at_3.len(), 2);
    }

    #[test]
    fn test_annotation_store_by_tag() {
        let mut store = AnnotationStore::new();
        store.add(TraceAnnotation::new(0, 5, "a").with_tag("suspicious"));
        store.add(TraceAnnotation::new(6, 10, "b").with_tag("crypto"));
        let suspicious = store.by_tag("suspicious");
        assert_eq!(suspicious.len(), 1);
    }

    #[test]
    fn test_annotation_store_remove_in_range() {
        let mut store = AnnotationStore::new();
        store.add(TraceAnnotation::new(0, 5, "a"));
        store.add(TraceAnnotation::new(10, 15, "b"));
        store.remove_in_range(0, 7);
        assert_eq!(store.len(), 1);
    }

    // ── TraceFilter ───────────────────────────────────────────────────────

    #[test]
    fn test_trace_filter_any() {
        let nav = simple_nav();
        let filter = TraceFilter::any();
        let matches = filter.apply(&nav.trace);
        assert_eq!(matches.len(), nav.trace.len());
    }

    #[test]
    fn test_trace_filter_for_tid() {
        let nav = simple_nav();
        let filter = TraceFilter::any().for_tid(1);
        let matches = filter.apply(&nav.trace);
        assert!(!matches.is_empty());
        assert!(matches.iter().all(|e| e.tid == 1));
    }

    #[test]
    fn test_trace_filter_calls_only() {
        let nav = simple_nav();
        let filter = TraceFilter::any().calls_only();
        let matches = filter.apply(&nav.trace);
        assert!(!matches.is_empty());
        assert!(matches.iter().all(|e| e.is_call()));
    }

    #[test]
    fn test_trace_filter_in_range() {
        let nav = simple_nav();
        let filter = TraceFilter::any().in_range(2, 4);
        let matches = filter.apply(&nav.trace);
        assert!(matches.iter().all(|e| e.idx >= 2 && e.idx <= 4));
    }

    // ── TraceSearcher ─────────────────────────────────────────────────────

    #[test]
    fn test_searcher_find_all() {
        let nav = simple_nav();
        let searcher = TraceSearcher::new("push");
        let found = searcher.find_all(&nav.trace);
        assert!(!found.is_empty());
        assert!(
            found
                .iter()
                .all(|e| e.disasm.to_lowercase().contains("push"))
        );
    }

    #[test]
    fn test_searcher_find_next() {
        let nav = simple_nav();
        let searcher = TraceSearcher::new("nop");
        // "nop" is at idx 0; searching from 0 should look in [1..]
        let result = searcher.find_next(&nav.trace, 0);
        // No second "nop" in simple trace
        assert!(result.is_none());
    }

    #[test]
    fn test_searcher_find_prev() {
        let nav = simple_nav();
        let searcher = TraceSearcher::new("nop");
        // "nop" is at idx 0; searching before idx 5 should find it
        let result = searcher.find_prev(&nav.trace, 5);
        assert!(result.is_some());
    }

    // ── TraceStatistics ───────────────────────────────────────────────────

    #[test]
    fn test_trace_statistics_compute() {
        let nav = simple_nav();
        let stats = TraceStatistics::compute(&nav.trace);
        assert_eq!(stats.total_entries, nav.trace.len());
        assert_eq!(stats.total_calls, 1);
        assert_eq!(stats.total_rets, 1);
        assert!(stats.is_balanced());
    }

    #[test]
    fn test_trace_statistics_multi_thread() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "a");
        b.insn(0x1001, 2, "b");
        b.insn(0x1002, 3, "c");
        let trace = b.build();
        let stats = TraceStatistics::compute(&trace);
        assert_eq!(stats.thread_count, 3);
    }

    #[test]
    fn test_trace_statistics_display() {
        let nav = simple_nav();
        let stats = TraceStatistics::compute(&nav.trace);
        let s = stats.to_string();
        assert!(s.contains("Stats("));
        assert!(s.contains("calls=1"));
    }

    #[test]
    fn test_trace_statistics_insn_per_unique_pc() {
        let mut b = TraceBuilder::new("t");
        for _ in 0..10 {
            b.insn(0x1000, 1, "loop");
        }
        b.insn(0x2000, 1, "once");
        let trace = b.build();
        let stats = TraceStatistics::compute(&trace);
        // 11 entries, 2 unique PCs -> 5.5
        assert!((stats.insn_per_unique_pc() - 5.5).abs() < 1e-9);
    }

    // ── TraceSlice ────────────────────────────────────────────────────────

    #[test]
    fn test_trace_slice_basic() {
        let nav = simple_nav();
        let slice = TraceSlice::new(&nav.trace, 1, 3);
        assert_eq!(slice.len(), 3);
    }

    #[test]
    fn test_trace_slice_statistics() {
        let nav = simple_nav();
        let slice = TraceSlice::new(&nav.trace, 0, 5);
        let stats = slice.statistics();
        assert_eq!(stats.calls, 1);
        assert_eq!(stats.rets, 1);
    }

    #[test]
    fn test_trace_slice_pcs() {
        let nav = simple_nav();
        let slice = TraceSlice::new(&nav.trace, 0, 0);
        let pcs = slice.pcs();
        assert_eq!(pcs.len(), 1);
        assert!(pcs.contains(&0x1000));
    }

    #[test]
    fn test_trace_slice_clamps_range() {
        let nav = simple_nav();
        let slice = TraceSlice::new(&nav.trace, 0, 9999);
        assert_eq!(slice.len(), nav.trace.len());
    }
}

// ─── TimedRegion ─────────────────────────────────────────────────────────────

/// A named region of the trace with timing information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimedRegion {
    /// Region name.
    pub name: String,
    /// Start index.
    pub start_idx: usize,
    /// End index.
    pub end_idx: usize,
    /// Start TSC (if available).
    pub start_tsc: Option<u64>,
    /// End TSC (if available).
    pub end_tsc: Option<u64>,
    /// TSC frequency used for conversion.
    pub tsc_freq_hz: Option<u64>,
}

impl TimedRegion {
    /// Create a timed region from a trace slice.
    #[must_use]
    pub fn from_trace(
        trace: &ExecutionTrace,
        name: impl Into<String>,
        start_idx: usize,
        end_idx: usize,
    ) -> Self {
        let start_tsc = trace.get(start_idx).and_then(|e| e.tsc);
        let end_tsc = trace.get(end_idx).and_then(|e| e.tsc);
        Self {
            name: name.into(),
            start_idx,
            end_idx,
            start_tsc,
            end_tsc,
            tsc_freq_hz: trace.tsc_freq_hz,
        }
    }

    /// Duration in TSC ticks.
    #[must_use]
    pub const fn tsc_duration(&self) -> Option<u64> {
        match (self.start_tsc, self.end_tsc) {
            (Some(s), Some(e)) => Some(e.saturating_sub(s)),
            _ => None,
        }
    }

    /// Duration in milliseconds.
    #[must_use]
    pub fn duration_ms(&self) -> Option<f64> {
        let ticks = self.tsc_duration()?;
        let freq = self.tsc_freq_hz?;
        Some(f64::from(u32::try_from(ticks).unwrap_or(u32::MAX)) / f64::from(u32::try_from(freq).unwrap_or(u32::MAX)) * 1000.0)
    }

    /// Number of entries in this region.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.end_idx.saturating_sub(self.start_idx) + 1
    }
}

impl std::fmt::Display for TimedRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ms) = self.duration_ms() {
            write!(
                f,
                "Region({}, idx={}..{}, {:.3}ms)",
                self.name, self.start_idx, self.end_idx, ms
            )
        } else {
            write!(
                f,
                "Region({}, idx={}..{})",
                self.name, self.start_idx, self.end_idx
            )
        }
    }
}

// ─── TraceIndex ───────────────────────────────────────────────────────────────

/// A pre-built, comprehensive set of indices over a trace for fast queries.
///
/// Building this once up front avoids repeated scans.
#[derive(Debug)]
pub struct TraceIndex {
    /// PC -> sorted list of entry indices.
    pub by_pc: HashMap<Address, Vec<usize>>,
    /// Thread ID -> sorted list of entry indices.
    pub by_tid: HashMap<u32, Vec<usize>>,
    /// Memory write address -> sorted list of entry indices.
    pub by_mem_write: BTreeMap<Address, Vec<usize>>,
    /// Memory read address -> sorted list of entry indices.
    pub by_mem_read: BTreeMap<Address, Vec<usize>>,
    /// Call target address -> sorted list of entry indices.
    pub by_call_target: HashMap<Address, Vec<usize>>,
    /// Return target address -> sorted list of entry indices.
    pub by_ret_target: HashMap<Address, Vec<usize>>,
    /// Total entries indexed.
    pub total: usize,
}

impl TraceIndex {
    /// Build all indices from a trace in a single O(n) pass.
    #[must_use]
    pub fn build(trace: &ExecutionTrace) -> Self {
        let mut by_pc: HashMap<Address, Vec<usize>> = HashMap::new();
        let mut by_tid: HashMap<u32, Vec<usize>> = HashMap::new();
        let mut by_mem_write: BTreeMap<Address, Vec<usize>> = BTreeMap::new();
        let mut by_mem_read: BTreeMap<Address, Vec<usize>> = BTreeMap::new();
        let mut by_call_target: HashMap<Address, Vec<usize>> = HashMap::new();
        let mut by_ret_target: HashMap<Address, Vec<usize>> = HashMap::new();

        for entry in &trace.entries {
            by_pc.entry(entry.pc).or_default().push(entry.idx);
            by_tid.entry(entry.tid).or_default().push(entry.idx);
            for (addr, _) in &entry.mem_writes {
                by_mem_write.entry(*addr).or_default().push(entry.idx);
            }
            for (addr, _) in &entry.mem_reads {
                by_mem_read.entry(*addr).or_default().push(entry.idx);
            }
            match entry.kind {
                EntryKind::Call { target, .. } => {
                    by_call_target.entry(target).or_default().push(entry.idx);
                }
                EntryKind::Ret { target } => {
                    by_ret_target.entry(target).or_default().push(entry.idx);
                }
                _ => {}
            }
        }

        Self {
            by_pc,
            by_tid,
            by_mem_write,
            by_mem_read,
            by_call_target,
            by_ret_target,
            total: trace.len(),
        }
    }

    /// All entry indices for a given PC.
    #[must_use]
    pub fn indices_for_pc(&self, pc: Address) -> &[usize] {
        self.by_pc.get(&pc).map_or(&[], std::vec::Vec::as_slice)
    }

    /// All entry indices for a given thread.
    #[must_use]
    pub fn indices_for_tid(&self, tid: u32) -> &[usize] {
        self.by_tid.get(&tid).map_or(&[], std::vec::Vec::as_slice)
    }

    /// Number of unique PCs.
    #[must_use]
    pub fn unique_pc_count(&self) -> usize {
        self.by_pc.len()
    }

    /// Number of unique threads.
    #[must_use]
    pub fn unique_thread_count(&self) -> usize {
        self.by_tid.len()
    }

    /// All unique PCs in sorted order.
    #[must_use]
    pub fn sorted_pcs(&self) -> Vec<Address> {
        let mut pcs: Vec<Address> = self.by_pc.keys().copied().collect();
        pcs.sort_unstable();
        pcs
    }

    /// All unique thread IDs.
    #[must_use]
    pub fn thread_ids(&self) -> Vec<u32> {
        self.by_tid.keys().copied().collect()
    }

    /// Find the next index >= `from` where PC == `pc`.
    #[must_use]
    pub fn next_pc_after(&self, pc: Address, from: usize) -> Option<usize> {
        self.indices_for_pc(pc).iter().copied().find(|&i| i > from)
    }

    /// Find the previous index <= `before` where PC == `pc`.
    #[must_use]
    pub fn prev_pc_before(&self, pc: Address, before: usize) -> Option<usize> {
        self.indices_for_pc(pc)
            .iter()
            .rev()
            .copied()
            .find(|&i| i < before)
    }

    /// Hit count for a given PC.
    #[must_use]
    pub fn hit_count(&self, pc: Address) -> usize {
        self.by_pc.get(&pc).map_or(0, std::vec::Vec::len)
    }

    /// Top-N hottest PCs by hit count.
    #[must_use]
    pub fn hot_pcs(&self, n: usize) -> Vec<(Address, usize)> {
        let mut pairs: Vec<(Address, usize)> =
            self.by_pc.iter().map(|(&pc, v)| (pc, v.len())).collect();
        pairs.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        pairs.truncate(n);
        pairs
    }
}

// ─── CallGraphNode ────────────────────────────────────────────────────────────

/// A node in a call graph extracted from the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    /// Function entry address.
    pub addr: Address,
    /// Optional symbol name.
    pub name: Option<String>,
    /// Addresses of functions called by this function.
    pub callees: HashSet<Address>,
    /// Addresses of functions that call this function.
    pub callers: HashSet<Address>,
    /// Total number of times this function was called.
    pub call_count: usize,
    /// Total number of instructions attributed to this function.
    pub insn_count: usize,
}

impl CallGraphNode {
    /// Create a new call graph node.
    #[must_use]
    pub fn new(addr: Address) -> Self {
        Self {
            addr,
            name: None,
            callees: HashSet::new(),
            callers: HashSet::new(),
            call_count: 0,
            insn_count: 0,
        }
    }

    /// Human-readable identifier.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("0x{:x}", self.addr))
    }

    /// Returns `true` if this function is a leaf (calls nothing).
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.callees.is_empty()
    }

    /// Returns `true` if this function is a root (called by nothing in the trace).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.callers.is_empty()
    }
}

impl std::fmt::Display for CallGraphNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}(calls={}, insns={}, callees={}, callers={})",
            self.display_name(),
            self.call_count,
            self.insn_count,
            self.callees.len(),
            self.callers.len(),
        )
    }
}

/// A call graph extracted from a trace.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CallGraph {
    pub nodes: HashMap<Address, CallGraphNode>,
}

impl CallGraph {
    /// Create an empty call graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a call graph from a trace.
    #[must_use]
    pub fn build(trace: &ExecutionTrace) -> Self {
        let mut cg = Self::new();
        let mut current_fn: HashMap<u32, Address> = HashMap::new(); // tid -> current fn

        for entry in &trace.entries {
            // Ensure the current PC's function is in the graph.
            // We approximate function boundaries by CALL targets.
            match entry.kind {
                EntryKind::Call { target, .. } => {
                    // Caller node: the function containing the CALL instruction.
                    if let Some(&caller_fn) = current_fn.get(&entry.tid) {
                        let caller = cg
                            .nodes
                            .entry(caller_fn)
                            .or_insert_with(|| CallGraphNode::new(caller_fn));
                        caller.callees.insert(target);
                    }
                    // Callee node.
                    let callee = cg
                        .nodes
                        .entry(target)
                        .or_insert_with(|| CallGraphNode::new(target));
                    if let Some(&caller_fn) = current_fn.get(&entry.tid) {
                        callee.callers.insert(caller_fn);
                    }
                    callee.call_count += 1;
                    // Track that this thread is now inside `target`.
                    current_fn.insert(entry.tid, target);
                }
                EntryKind::Ret { .. } => {
                    // On ret, we lose track of exact return address — this is an approximation.
                    current_fn.remove(&entry.tid);
                }
                _ => {
                    // Count instructions for the current function.
                    if let Some(&fn_addr) = current_fn.get(&entry.tid) {
                        cg.nodes
                            .entry(fn_addr)
                            .or_insert_with(|| CallGraphNode::new(fn_addr))
                            .insn_count += 1;
                    }
                }
            }
        }

        cg
    }

    /// Add a symbol name to a node.
    pub fn add_symbol(&mut self, addr: Address, name: impl Into<String>) {
        if let Some(node) = self.nodes.get_mut(&addr) {
            node.name = Some(name.into());
        }
    }

    /// All leaf functions.
    #[must_use]
    pub fn leaves(&self) -> Vec<&CallGraphNode> {
        self.nodes.values().filter(|n| n.is_leaf()).collect()
    }

    /// All root functions (not called by any known function).
    #[must_use]
    pub fn roots(&self) -> Vec<&CallGraphNode> {
        self.nodes.values().filter(|n| n.is_root()).collect()
    }

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total number of unique edges (caller -> callee pairs).
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.nodes.values().map(|n| n.callees.len()).sum()
    }

    /// Depth-first ordering from `start`.
    #[must_use]
    pub fn dfs_order(&self, start: Address) -> Vec<Address> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        let mut stack = vec![start];
        while let Some(addr) = stack.pop() {
            if visited.contains(&addr) {
                continue;
            }
            visited.insert(addr);
            order.push(addr);
            if let Some(node) = self.nodes.get(&addr) {
                for &callee in &node.callees {
                    if !visited.contains(&callee) {
                        stack.push(callee);
                    }
                }
            }
        }
        order
    }
}

// ─── TraceExport ─────────────────────────────────────────────────────────────

/// Exports traces to various text formats.
pub struct TraceExport;

impl TraceExport {
    /// Export a trace as a simple TSV (idx, `pc_hex`, tid, disasm).
    #[must_use]
    pub fn to_tsv(trace: &ExecutionTrace) -> String {
        let mut lines = vec!["idx\tpc\ttid\tdisasm".to_string()];
        for e in &trace.entries {
            lines.push(format!("{}\t0x{:x}\t{}\t{}", e.idx, e.pc, e.tid, e.disasm));
        }
        lines.join("\n")
    }

    /// Export a trace as JSON (pretty-printed).
    ///
    /// # Errors
    /// Returns an error string if serialization fails.
    pub fn to_json(trace: &ExecutionTrace) -> Result<String, String> {
        serde_json::to_string_pretty(trace).map_err(|e| e.to_string())
    }

    /// Export only the PC sequence (one hex per line).
    #[must_use]
    pub fn pc_sequence(trace: &ExecutionTrace) -> String {
        trace
            .entries
            .iter()
            .map(|e| format!("0x{:x}", e.pc))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Export call graph edges as DOT format.
    #[must_use]
    pub fn call_graph_dot(cg: &CallGraph) -> String {
        let mut lines = vec!["digraph callgraph {".to_string()];
        for node in cg.nodes.values() {
            let label = node.display_name();
            lines.push(format!("  \"0x{:x}\" [label=\"{}\"];", node.addr, label));
            for callee in &node.callees {
                lines.push(format!("  \"0x{:x}\" -> \"0x{callee:x}\";", node.addr));
            }
        }
        lines.push("}".to_string());
        lines.join("\n")
    }
}

// ─── FinalExtended Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod final_extended_tests {
    use super::*;

    fn simple_trace() -> ExecutionTrace {
        let mut b = TraceBuilder::new("test.exe");
        b.insn(0x1000, 1, "nop");
        b.call(0x1004, 1, 0x2000, 0x1008);
        b.insn(0x2000, 1, "push rbp");
        b.insn(0x2001, 1, "add rax, 1");
        b.ret(0x2005, 1, 0x1008);
        b.insn(0x1008, 1, "xor eax, eax");
        b.build()
    }

    // ── TimedRegion ───────────────────────────────────────────────────────

    #[test]
    fn test_timed_region_entry_count() {
        let trace = simple_trace();
        let region = TimedRegion::from_trace(&trace, "main", 0, 3);
        assert_eq!(region.entry_count(), 4);
    }

    #[test]
    fn test_timed_region_display_without_tsc() {
        let trace = simple_trace();
        let region = TimedRegion::from_trace(&trace, "r", 0, 2);
        let s = region.to_string();
        assert!(s.contains("Region(r"));
        assert!(s.contains("0..2"));
    }

    #[test]
    fn test_timed_region_with_tsc() {
        let mut b = TraceBuilder::new("t")
            .tsc_freq(1_000_000_000)
            .tsc_per_insn(1_000_000);
        b.insn(0x1000, 1, "a");
        b.insn(0x1004, 1, "b");
        let trace = b.build();
        let region = TimedRegion::from_trace(&trace, "r", 0, 1);
        let ms = region.duration_ms().unwrap();
        assert!(ms > 0.0);
    }

    // ── TraceIndex ────────────────────────────────────────────────────────

    #[test]
    fn test_trace_index_build() {
        let trace = simple_trace();
        let idx = TraceIndex::build(&trace);
        assert_eq!(idx.total, trace.len());
        assert!(!idx.indices_for_pc(0x1000).is_empty());
    }

    #[test]
    fn test_trace_index_unique_pcs() {
        let trace = simple_trace();
        // simple_trace: 0x1000, 0x1004, 0x2000, 0x2001, 0x2005, 0x1008 = 6 unique PCs
        let idx = TraceIndex::build(&trace);
        assert_eq!(idx.unique_pc_count(), 6);
    }

    #[test]
    fn test_trace_index_hot_pcs() {
        let mut b = TraceBuilder::new("t");
        for _ in 0..5 {
            b.insn(0x1000, 1, "hot");
        }
        b.insn(0x2000, 1, "cold");
        let trace = b.build();
        let idx = TraceIndex::build(&trace);
        let hot = idx.hot_pcs(1);
        assert_eq!(hot[0].0, 0x1000);
        assert_eq!(hot[0].1, 5);
    }

    #[test]
    fn test_trace_index_next_pc_after() {
        let trace = simple_trace();
        let idx = TraceIndex::build(&trace);
        // 0x1000 is at index 0; next 0x1000 after 0 doesn't exist in simple trace
        assert!(idx.next_pc_after(0x1000, 0).is_none());
        // 0x2000 is at index 2; find it starting from 0
        let n = idx.next_pc_after(0x2000, 0);
        assert!(n.is_some());
    }

    #[test]
    fn test_trace_index_prev_pc_before() {
        let trace = simple_trace();
        let idx = TraceIndex::build(&trace);
        let p = idx.prev_pc_before(0x1000, 5);
        assert_eq!(p, Some(0));
    }

    #[test]
    fn test_trace_index_mem_write_index() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "store");
        b.mem_write(0xDEAD, vec![0x42]);
        let trace = b.build();
        let idx = TraceIndex::build(&trace);
        assert!(!idx.by_mem_write.get(&0xDEAD).unwrap_or(&vec![]).is_empty());
    }

    // ── CallGraphNode ─────────────────────────────────────────────────────

    #[test]
    fn test_call_graph_node_leaf() {
        let node = CallGraphNode::new(0x1000);
        assert!(node.is_leaf());
    }

    #[test]
    fn test_call_graph_node_display() {
        let mut node = CallGraphNode::new(0x1000);
        node.name = Some("foo".to_string());
        let s = node.to_string();
        assert!(s.contains("foo"));
    }

    // ── CallGraph ─────────────────────────────────────────────────────────

    #[test]
    fn test_call_graph_build() {
        let trace = simple_trace();
        let cg = CallGraph::build(&trace);
        // Should have at least one node for the callee 0x2000.
        assert!(!cg.nodes.is_empty());
    }

    #[test]
    fn test_call_graph_edge_count() {
        let trace = simple_trace();
        let cg = CallGraph::build(&trace);
        let _ = cg.edge_count();
    }

    #[test]
    fn test_call_graph_dfs_order() {
        let trace = simple_trace();
        let cg = CallGraph::build(&trace);
        // DFS from a node that exists
        if let Some(&addr) = cg.nodes.keys().next() {
            let order = cg.dfs_order(addr);
            assert!(!order.is_empty());
            assert_eq!(order[0], addr);
        }
    }

    // ── TraceExport ───────────────────────────────────────────────────────

    #[test]
    fn test_export_to_tsv() {
        let trace = simple_trace();
        let tsv = TraceExport::to_tsv(&trace);
        assert!(tsv.contains("idx\tpc\ttid\tdisasm"));
        assert!(tsv.contains("0x1000"));
    }

    #[test]
    fn test_export_to_json() {
        let trace = simple_trace();
        let json = TraceExport::to_json(&trace).unwrap();
        assert!(json.contains("test.exe"));
    }

    #[test]
    fn test_export_pc_sequence() {
        let trace = simple_trace();
        let seq = TraceExport::pc_sequence(&trace);
        assert!(seq.contains("0x1000"));
        assert!(seq.contains("0x2000"));
    }

    #[test]
    fn test_export_call_graph_dot() {
        let trace = simple_trace();
        let cg = CallGraph::build(&trace);
        let dot = TraceExport::call_graph_dot(&cg);
        assert!(dot.starts_with("digraph callgraph {"));
        assert!(dot.ends_with('}'));
    }

    // ── TraceIndex hit_count ───────────────────────────────────────────────

    #[test]
    fn test_trace_index_hit_count() {
        let trace = simple_trace();
        let idx = TraceIndex::build(&trace);
        assert_eq!(idx.hit_count(0x1000), 1);
        assert_eq!(idx.hit_count(0xDEAD_BEEF), 0);
    }

    #[test]
    fn test_trace_index_sorted_pcs() {
        let trace = simple_trace();
        let idx = TraceIndex::build(&trace);
        let pcs = idx.sorted_pcs();
        assert!(pcs.windows(2).all(|w| w[0] <= w[1]));
    }
}

// ─── SyscallTrace ─────────────────────────────────────────────────────────────

/// A syscall event extracted from a trace entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// Trace index.
    pub idx: usize,
    /// PC of the syscall instruction.
    pub pc: Address,
    /// Thread ID.
    pub tid: u32,
    /// Syscall number (from the Syscall variant's number field).
    pub number: u64,
}

impl SyscallEvent {
    /// Extract all syscall events from a trace.
    #[must_use]
    pub fn extract_all(trace: &ExecutionTrace) -> Vec<Self> {
        trace
            .entries
            .iter()
            .filter_map(|e| {
                if let EntryKind::Syscall { number } = e.kind {
                    Some(Self {
                        idx: e.idx,
                        pc: e.pc,
                        tid: e.tid,
                        number,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Group syscall events by syscall number.
    #[must_use]
    pub fn grouped_by_number(events: &[Self]) -> HashMap<u64, Vec<&Self>> {
        let mut map: HashMap<u64, Vec<&Self>> = HashMap::new();
        for ev in events {
            map.entry(ev.number).or_default().push(ev);
        }
        map
    }

    /// Return unique syscall numbers seen.
    #[must_use]
    pub fn unique_numbers(events: &[Self]) -> HashSet<u64> {
        events.iter().map(|e| e.number).collect()
    }
}

// ─── ExceptionEvent ───────────────────────────────────────────────────────────

/// An exception/fault event extracted from a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionEvent {
    /// Trace index.
    pub idx: usize,
    /// PC where the exception occurred.
    pub pc: Address,
    /// Thread ID.
    pub tid: u32,
    /// Exception code.
    pub code: u32,
}

impl ExceptionEvent {
    /// Extract all exception events from a trace.
    #[must_use]
    pub fn extract_all(trace: &ExecutionTrace) -> Vec<Self> {
        trace
            .entries
            .iter()
            .filter_map(|e| {
                if let EntryKind::Exception { code } = e.kind {
                    Some(Self {
                        idx: e.idx,
                        pc: e.pc,
                        tid: e.tid,
                        code,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Whether this is a crash (access violation = 0xC0000005 on Windows).
    #[must_use]
    pub const fn is_crash(&self) -> bool {
        self.code == 0xC000_0005 || self.code == 0xC000_0096
    }
}

// ─── TraceCompressor ─────────────────────────────────────────────────────────

/// Run-length compresses a trace by collapsing repeated identical PCs.
///
/// Useful for reducing storage/display of tight loops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedTrace {
    /// (pc, `run_length`) pairs.
    pub runs: Vec<(Address, usize)>,
    /// Original trace length.
    pub original_len: usize,
}

impl CompressedTrace {
    /// Compress a trace.
    #[must_use]
    pub fn compress(trace: &ExecutionTrace) -> Self {
        let original_len = trace.len();
        let mut runs: Vec<(Address, usize)> = Vec::new();
        for entry in &trace.entries {
            match runs.last_mut() {
                Some(last) if last.0 == entry.pc => last.1 += 1,
                _ => runs.push((entry.pc, 1)),
            }
        }
        Self { runs, original_len }
    }

    /// Number of compressed runs.
    #[must_use]
    pub const fn run_count(&self) -> usize {
        self.runs.len()
    }

    /// Compression ratio (original / compressed).
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.runs.is_empty() {
            return 1.0;
        }
        f64::from(u32::try_from(self.original_len).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.runs.len()).unwrap_or(u32::MAX))
    }

    /// Sum of all run lengths (should equal `original_len`).
    #[must_use]
    pub fn total_runs_len(&self) -> usize {
        self.runs.iter().map(|(_, n)| n).sum()
    }
}

// ─── TraceNavigator convenience wrappers ─────────────────────────────────────

impl TraceNavigator {
    // These are additional convenience methods that enrich the navigation API.

    /// Compress the trace and return a `CompressedTrace`.
    #[must_use]
    pub fn compressed(&self) -> CompressedTrace {
        CompressedTrace::compress(&self.trace)
    }

    /// Extract all syscall events.
    #[must_use]
    pub fn syscall_events(&self) -> Vec<SyscallEvent> {
        SyscallEvent::extract_all(&self.trace)
    }

    /// Extract all exception events.
    #[must_use]
    pub fn exception_events(&self) -> Vec<ExceptionEvent> {
        ExceptionEvent::extract_all(&self.trace)
    }

    /// Build a full `TraceIndex` over the trace.
    #[must_use]
    pub fn build_index(&self) -> TraceIndex {
        TraceIndex::build(&self.trace)
    }

    /// Build a `CallGraph` from the trace.
    #[must_use]
    pub fn call_graph(&self) -> CallGraph {
        CallGraph::build(&self.trace)
    }

    /// Compute `TraceStatistics`.
    #[must_use]
    pub fn statistics(&self) -> TraceStatistics {
        TraceStatistics::compute(&self.trace)
    }

    /// Build an `ExecutionHeatmap`.
    #[must_use]
    pub fn heatmap(&self) -> ExecutionHeatmap {
        ExecutionHeatmap::build(&self.coverage)
    }

    /// Apply a `TraceFilter` to the trace.
    #[must_use]
    pub fn filter(&self, filter: &TraceFilter) -> Vec<&TraceEntry> {
        filter.apply(&self.trace)
    }

    /// Search for entries containing a disassembly substring.
    #[must_use]
    pub fn search_disasm(&self, pattern: &str) -> Vec<&TraceEntry> {
        let searcher = TraceSearcher::new(pattern);
        searcher.find_all(&self.trace)
    }

    /// Get a `TraceSlice` between two indices.
    #[must_use]
    pub fn slice(&self, start: usize, end: usize) -> TraceSlice<'_> {
        TraceSlice::new(&self.trace, start, end)
    }

    /// Detect loops using `LoopDetector`.
    #[must_use]
    pub fn detect_loops(&self, min_iterations: usize) -> LoopDetector {
        LoopDetector::detect(&self.trace, min_iterations)
    }

    /// Compute a diff against another trace.
    #[must_use]
    pub fn diff_with(&self, other: &ExecutionTrace) -> TraceDiff {
        TraceDiff::compute(&self.trace, other)
    }

    /// Extract all function slices.
    #[must_use]
    pub fn function_slices(&self) -> Vec<FunctionSlice> {
        FunctionSlice::extract_all(&self.trace)
    }

    /// Build a thread view for a specific thread.
    #[must_use]
    pub fn thread_view(&self, tid: u32) -> ThreadView<'_> {
        ThreadView::build(&self.trace, tid)
    }

    /// Export the trace as a TSV string.
    #[must_use]
    pub fn export_tsv(&self) -> String {
        TraceExport::to_tsv(&self.trace)
    }

    /// Export the call graph as DOT format.
    #[must_use]
    pub fn export_call_graph_dot(&self) -> String {
        let cg = self.call_graph();
        TraceExport::call_graph_dot(&cg)
    }
}

// ─── DrcovData additional methods ────────────────────────────────────────────

impl DrcovData {
    /// Module count.
    #[must_use]
    pub const fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Basic-block count.
    #[must_use]
    pub const fn bb_count(&self) -> usize {
        self.basic_blocks.len()
    }

    /// Coverage percentage given total known BBs.
    #[must_use]
    pub fn coverage_pct(&self, total_bbs: usize) -> f64 {
        if total_bbs == 0 {
            return 100.0;
        }
        f64::from(u32::try_from(self.basic_blocks.len()).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total_bbs).unwrap_or(u32::MAX)) * 100.0
    }
}

// ─── TraceEventIterator ───────────────────────────────────────────────────────

/// An iterator over trace entries with filtering.
pub struct TraceEventIter<'a> {
    entries: &'a [TraceEntry],
    pos: usize,
    filter: Option<&'a TraceFilter>,
}

impl<'a> TraceEventIter<'a> {
    /// Create an iterator over all entries.
    #[must_use]
    pub fn new(trace: &'a ExecutionTrace) -> Self {
        Self {
            entries: &trace.entries,
            pos: 0,
            filter: None,
        }
    }

    /// Apply a filter.
    #[must_use]
    pub const fn with_filter(mut self, filter: &'a TraceFilter) -> Self {
        self.filter = Some(filter);
        self
    }
}

impl<'a> Iterator for TraceEventIter<'a> {
    type Item = &'a TraceEntry;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.get(self.pos)?;
            self.pos += 1;
            if let Some(f) = self.filter
                && !f.matches(entry) {
                    continue;
                }
            return Some(entry);
        }
    }
}

// ─── Additional Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod additional_tests {
    use super::*;

    fn simple_trace() -> ExecutionTrace {
        let mut b = TraceBuilder::new("test.exe");
        b.insn(0x1000, 1, "nop");
        b.call(0x1004, 1, 0x2000, 0x1008);
        b.insn(0x2000, 1, "push rbp");
        b.ret(0x2005, 1, 0x1008);
        b.insn(0x1008, 1, "xor eax, eax");
        b.build()
    }

    // ── SyscallEvent ──────────────────────────────────────────────────────

    #[test]
    fn test_syscall_event_extract_none() {
        let trace = simple_trace();
        let events = SyscallEvent::extract_all(&trace);
        assert!(events.is_empty());
    }

    #[test]
    fn test_syscall_event_extract_some() {
        let mut b = TraceBuilder::new("t");
        let idx = b.insn(0x1000, 1, "syscall");
        if let Some(e) = b.entries.last_mut() {
            e.kind = EntryKind::Syscall { number: 60 };
        }
        let trace = b.build();
        let events = SyscallEvent::extract_all(&trace);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].number, 60);
        let _ = idx;
    }

    #[test]
    fn test_syscall_event_unique_numbers() {
        let events = vec![
            SyscallEvent {
                idx: 0,
                pc: 0x1000,
                tid: 1,
                number: 1,
            },
            SyscallEvent {
                idx: 1,
                pc: 0x1004,
                tid: 1,
                number: 2,
            },
            SyscallEvent {
                idx: 2,
                pc: 0x1008,
                tid: 1,
                number: 1,
            },
        ];
        let unique = SyscallEvent::unique_numbers(&events);
        assert_eq!(unique.len(), 2);
    }

    // ── ExceptionEvent ────────────────────────────────────────────────────

    #[test]
    fn test_exception_event_is_crash() {
        let ev = ExceptionEvent {
            idx: 0,
            pc: 0x1000,
            tid: 1,
            code: 0xC000_0005,
        };
        assert!(ev.is_crash());
        let ok = ExceptionEvent {
            idx: 1,
            pc: 0x1004,
            tid: 1,
            code: 0x0000_0001,
        };
        assert!(!ok.is_crash());
    }

    #[test]
    fn test_exception_event_extract_none() {
        let trace = simple_trace();
        let evs = ExceptionEvent::extract_all(&trace);
        assert!(evs.is_empty());
    }

    // ── CompressedTrace ───────────────────────────────────────────────────

    #[test]
    fn test_compressed_trace_no_repeats() {
        let trace = simple_trace();
        let ct = CompressedTrace::compress(&trace);
        assert_eq!(ct.run_count(), trace.len()); // each PC is unique
        assert_eq!(ct.total_runs_len(), trace.len());
    }

    #[test]
    fn test_compressed_trace_with_loop() {
        let mut b = TraceBuilder::new("t");
        for _ in 0..10 {
            b.insn(0x1000, 1, "loop");
        }
        let trace = b.build();
        let ct = CompressedTrace::compress(&trace);
        assert_eq!(ct.run_count(), 1);
        assert_eq!(ct.runs[0].1, 10);
        assert!(ct.compression_ratio() > 1.0);
    }

    #[test]
    fn test_compressed_trace_total_len() {
        let trace = simple_trace();
        let ct = CompressedTrace::compress(&trace);
        assert_eq!(ct.total_runs_len(), ct.original_len);
    }

    // ── TraceNavigator convenience wrappers ────────────────────────────────

    #[test]
    fn test_nav_compressed() {
        let nav = TraceNavigator::new(simple_trace());
        let ct = nav.compressed();
        assert_eq!(ct.original_len, nav.trace.len());
    }

    #[test]
    fn test_nav_statistics() {
        let nav = TraceNavigator::new(simple_trace());
        let stats = nav.statistics();
        assert_eq!(stats.total_entries, nav.trace.len());
    }

    #[test]
    fn test_nav_search_disasm() {
        let nav = TraceNavigator::new(simple_trace());
        let results = nav.search_disasm("nop");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_nav_slice() {
        let nav = TraceNavigator::new(simple_trace());
        let slice = nav.slice(0, 2);
        assert_eq!(slice.len(), 3);
    }

    #[test]
    fn test_nav_export_tsv() {
        let nav = TraceNavigator::new(simple_trace());
        let tsv = nav.export_tsv();
        assert!(tsv.contains("idx\tpc\ttid\tdisasm"));
    }

    #[test]
    fn test_nav_call_graph() {
        let nav = TraceNavigator::new(simple_trace());
        let cg = nav.call_graph();
        // Should have at least the callee.
        let _ = cg;
    }

    #[test]
    fn test_nav_filter() {
        let nav = TraceNavigator::new(simple_trace());
        let filter = TraceFilter::any().calls_only();
        let results = nav.filter(&filter);
        assert!(!results.is_empty());
        assert!(results.iter().all(|e| e.is_call()));
    }

    #[test]
    fn test_nav_function_slices() {
        let nav = TraceNavigator::new(simple_trace());
        let slices = nav.function_slices();
        assert_eq!(slices.len(), 1);
    }

    #[test]
    fn test_nav_detect_loops() {
        let nav = TraceNavigator::new(simple_trace());
        let loops = nav.detect_loops(2);
        // Simple trace has no loops.
        assert!(loops.loops.is_empty());
    }

    #[test]
    fn test_nav_heatmap() {
        let nav = TraceNavigator::new(simple_trace());
        let hm = nav.heatmap();
        assert!(!hm.entries.is_empty());
    }

    // ── TraceEventIter ────────────────────────────────────────────────────

    #[test]
    fn test_trace_event_iter_all() {
        let trace = simple_trace();
        let count = TraceEventIter::new(&trace).count();
        assert_eq!(count, trace.len());
    }

    #[test]
    fn test_trace_event_iter_filtered() {
        let trace = simple_trace();
        let filter = TraceFilter::any().calls_only();
        let count = TraceEventIter::new(&trace).with_filter(&filter).count();
        assert_eq!(count, 1);
    }

    // ── DrcovData coverage_pct ────────────────────────────────────────────

    #[test]
    fn test_drcov_coverage_pct_zero_total() {
        let d = DrcovData {
            modules: vec![],
            basic_blocks: vec![],
        };
        assert!((d.coverage_pct(0) - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_drcov_coverage_pct_some() {
        let d = DrcovData {
            modules: vec![],
            basic_blocks: vec![
                DrcovBB {
                    start: 0,
                    size: 4,
                    mod_id: 0,
                },
                DrcovBB {
                    start: 4,
                    size: 4,
                    mod_id: 0,
                },
            ],
        };
        assert!((d.coverage_pct(4) - 50.0).abs() < 1e-9);
    }

    // ── RegTimeline changed_between ────────────────────────────────────────

    #[test]
    fn test_reg_timeline_changed_between() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "a");
        b.regs(vec![(0, 10)]);
        b.insn(0x1004, 1, "b");
        b.regs(vec![(0, 20)]);
        b.insn(0x1008, 1, "c");
        b.regs(vec![(0, 30)]);
        let nav = b.build_navigator();
        let changed = nav.reg_timeline.changed_between(0, 2);
        // idx 1 and idx 2 both write reg 0
        assert!(!changed.is_empty());
    }

    // ── MemAccessIndex address listing ─────────────────────────────────────

    #[test]
    fn test_mem_access_written_addresses() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "s");
        b.mem_write(0xABCD, vec![0x01]);
        b.mem_write(0xEF01, vec![0x02]);
        let nav = b.build_navigator();
        let waddrs = nav.mem_access_index.written_addresses();
        assert!(waddrs.contains(&0xABCD));
        assert!(waddrs.contains(&0xEF01));
    }

    // ── ExecutionTrace idx_for_tsc edge case ──────────────────────────────

    #[test]
    fn test_idx_for_tsc_empty_trace() {
        let trace = ExecutionTrace::new(vec![], "empty");
        assert!(trace.idx_for_tsc(1000).is_none());
    }

    #[test]
    fn test_idx_for_tsc_before_all() {
        let mut b = TraceBuilder::new("t").tsc_per_insn(1000);
        b.insn(0x1000, 1, "a"); // tsc=0
        b.insn(0x1004, 1, "b"); // tsc=1000
        let trace = b.build();
        // tsc 500 is between 0 and 1000
        let idx = trace.idx_for_tsc(500);
        assert!(idx.is_some());
    }
}

// ─── PatternMatcher ───────────────────────────────────────────────────────────

/// Matches sequences of instruction PCs (gadget-style patterns) in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatcher {
    /// The sequence of PCs to match (in order, consecutive).
    pub pattern: Vec<Address>,
}

impl PatternMatcher {
    /// Create a new pattern matcher.
    #[must_use]
    pub const fn new(pattern: Vec<Address>) -> Self {
        Self { pattern }
    }

    /// Find all starting indices where the pattern occurs in the trace.
    #[must_use]
    pub fn find_all(&self, trace: &ExecutionTrace) -> Vec<usize> {
        if self.pattern.is_empty() || trace.len() < self.pattern.len() {
            return Vec::new();
        }
        let len = self.pattern.len();
        (0..=trace.len().saturating_sub(len))
            .filter(|&i| {
                self.pattern
                    .iter()
                    .enumerate()
                    .all(|(j, &p)| trace.entries.get(i + j).is_some_and(|e| e.pc == p))
            })
            .collect()
    }

    /// Find the first occurrence.
    #[must_use]
    pub fn find_first(&self, trace: &ExecutionTrace) -> Option<usize> {
        self.find_all(trace).into_iter().next()
    }

    /// Find the last occurrence.
    #[must_use]
    pub fn find_last(&self, trace: &ExecutionTrace) -> Option<usize> {
        self.find_all(trace).into_iter().last()
    }

    /// Count occurrences.
    #[must_use]
    pub fn count(&self, trace: &ExecutionTrace) -> usize {
        self.find_all(trace).len()
    }
}

// ─── TraceResampler ───────────────────────────────────────────────────────────

/// Resamples a trace at regular intervals for lightweight display.
pub struct TraceResampler;

impl TraceResampler {
    /// Take every Nth entry from the trace.
    #[must_use]
    pub fn sample_every_n(trace: &ExecutionTrace, n: usize) -> Vec<&TraceEntry> {
        if n == 0 {
            return Vec::new();
        }
        trace.entries.iter().step_by(n).collect()
    }

    /// Sample the trace at `max_samples` evenly spaced positions.
    #[must_use]
    pub fn sample_n(trace: &ExecutionTrace, max_samples: usize) -> Vec<&TraceEntry> {
        let len = trace.len();
        if len == 0 || max_samples == 0 {
            return Vec::new();
        }
        if max_samples >= len {
            return trace.entries.iter().collect();
        }
        let step = f64::from(u32::try_from(len).unwrap_or(u32::MAX)) / f64::from(u32::try_from(max_samples).unwrap_or(u32::MAX));
        (0..max_samples)
            .filter_map(|i| {
                // f64::from(i_u32) * step ≥ 0 and product ≤ len ≤ usize::MAX; cast is safe.
                let idx = f64_to_usize_saturating(f64::from(u32::try_from(i).unwrap_or(u32::MAX)) * step);
                trace.get(idx)
            })
            .collect()
    }
}

// ─── TraceNavigatorSnapshot ───────────────────────────────────────────────────

/// A serializable snapshot of the navigator's current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigatorSnapshot {
    /// Current cursor index.
    pub current_idx: usize,
    /// Current PC.
    pub current_pc: Address,
    /// Current thread ID.
    pub current_tid: u32,
    /// Call stack at this point.
    pub call_stack: Vec<StackFrame>,
    /// All bookmarks.
    pub bookmarks: Vec<Bookmark>,
}

impl NavigatorSnapshot {
    /// Capture a snapshot from the navigator.
    pub fn capture(nav: &mut TraceNavigator) -> Self {
        let idx = nav.current_idx;
        let (pc, tid) = nav.current_entry().map_or((0, 0), |e| (e.pc, e.tid));
        let call_stack = nav.call_stack_at(idx);
        let bookmarks: Vec<Bookmark> = nav.bookmarks.sorted_by_idx().into_iter().cloned().collect();
        Self {
            current_idx: idx,
            current_pc: pc,
            current_tid: tid,
            call_stack,
            bookmarks,
        }
    }

    /// Restore the cursor from a snapshot.
    ///
    /// # Errors
    /// Returns `NavError::OutOfBounds` if the snapshot's index is invalid.
    pub fn restore(&self, nav: &mut TraceNavigator) -> Result<(), NavError> {
        nav.jump_to(self.current_idx)?;
        // Restore bookmarks.
        for bm in &self.bookmarks {
            nav.bookmarks.insert(bm.clone());
        }
        Ok(())
    }
}

// ─── TraceNavigator batch operations ─────────────────────────────────────────

impl TraceNavigator {
    /// Run to the next CALL instruction.
    pub fn run_to_next_call(&mut self) -> NavEvent {
        let start = self.current_idx + 1;
        for i in start..self.trace.len() {
            if self.trace.entries[i].is_call() {
                let from = self.current_idx;
                self.current_idx = i;
                let ev = NavEvent::Moved { from, to: i };
                self.event_window.push(ev.clone());
                return ev;
            }
        }
        NavEvent::End
    }

    /// Run backward to the previous CALL instruction.
    pub fn run_backward_to_prev_call(&mut self) -> NavEvent {
        if self.current_idx == 0 {
            return NavEvent::Beginning;
        }
        for i in (0..self.current_idx).rev() {
            if self.trace.entries[i].is_call() {
                let from = self.current_idx;
                self.current_idx = i;
                let ev = NavEvent::Moved { from, to: i };
                self.event_window.push(ev.clone());
                return ev;
            }
        }
        NavEvent::Beginning
    }

    /// Run to the next RET instruction.
    pub fn run_to_next_ret(&mut self) -> NavEvent {
        let start = self.current_idx + 1;
        for i in start..self.trace.len() {
            if self.trace.entries[i].is_ret() {
                let from = self.current_idx;
                self.current_idx = i;
                let ev = NavEvent::Moved { from, to: i };
                self.event_window.push(ev.clone());
                return ev;
            }
        }
        NavEvent::End
    }

    /// Advance N steps forward (stops at end).
    pub fn step_forward_n(&mut self, n: usize) -> usize {
        let mut stepped = 0;
        for _ in 0..n {
            if !self.step_forward() {
                break;
            }
            stepped += 1;
        }
        stepped
    }

    /// Retreat N steps backward (stops at beginning).
    pub fn step_backward_n(&mut self, n: usize) -> usize {
        let mut stepped = 0;
        for _ in 0..n {
            if !self.step_backward() {
                break;
            }
            stepped += 1;
        }
        stepped
    }

    /// Jump to the first entry.
    pub fn jump_to_beginning(&mut self) {
        self.current_idx = 0;
        self.history.push(0);
    }

    /// Jump to the last entry.
    pub fn jump_to_end(&mut self) {
        if !self.trace.is_empty() {
            let last = self.trace.len() - 1;
            self.current_idx = last;
            self.history.push(last);
        }
    }

    /// All calls to a specific target address.
    #[must_use]
    pub fn calls_to(&self, target: Address) -> Vec<&TraceEntry> {
        self.trace
            .entries
            .iter()
            .filter(|e| matches!(e.kind, EntryKind::Call { target: t, .. } if t == target))
            .collect()
    }

    /// Return the indices of all entries where a specific register had a specific value.
    #[must_use]
    pub fn entries_where_reg_eq(&self, reg: RegId, value: u64) -> Vec<usize> {
        self.find_reg_value(reg, value)
    }

    /// Compute a snapshot of all registers at the current position.
    #[must_use]
    pub fn current_reg_snapshot(&self) -> HashMap<RegId, u64> {
        self.reg_snapshot_at(self.current_idx)
    }

    /// Return the most recent memory write to `addr` before the current position.
    #[must_use]
    pub fn last_write_before_cursor(&self, addr: Address) -> Option<u64> {
        self.get_value_at_tick(addr, self.current_idx).ok()
    }
}

// ─── BatchNavigation tests ─────────────────────────────────────────────────

#[cfg(test)]
mod batch_nav_tests {
    use super::*;

    fn nav_with_calls() -> TraceNavigator {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "nop");
        b.call(0x1004, 1, 0x2000, 0x1008);
        b.insn(0x2000, 1, "push rbp");
        b.ret(0x2005, 1, 0x1008);
        b.insn(0x1008, 1, "xor");
        b.call(0x100C, 1, 0x3000, 0x1010);
        b.insn(0x3000, 1, "mov");
        b.ret(0x3010, 1, 0x1010);
        b.insn(0x1010, 1, "ret_after");
        b.build_navigator()
    }

    #[test]
    fn test_run_to_next_call() {
        let mut nav = nav_with_calls();
        let ev = nav.run_to_next_call();
        assert!(matches!(ev, NavEvent::Moved { to: 1, .. }));
    }

    #[test]
    fn test_run_backward_to_prev_call() {
        let mut nav = nav_with_calls();
        nav.current_idx = 8;
        let ev = nav.run_backward_to_prev_call();
        assert!(matches!(ev, NavEvent::Moved { .. }));
        assert!(nav.current_entry().is_some_and(super::TraceEntry::is_call));
    }

    #[test]
    fn test_run_to_next_ret() {
        let mut nav = nav_with_calls();
        let ev = nav.run_to_next_ret();
        assert!(matches!(ev, NavEvent::Moved { .. }));
        assert!(nav.current_entry().is_some_and(super::TraceEntry::is_ret));
    }

    #[test]
    fn test_step_forward_n() {
        let mut nav = nav_with_calls();
        let stepped = nav.step_forward_n(3);
        assert_eq!(stepped, 3);
        assert_eq!(nav.current_idx, 3);
    }

    #[test]
    fn test_step_forward_n_clamped() {
        let mut nav = nav_with_calls();
        let len = nav.trace.len();
        let stepped = nav.step_forward_n(1000);
        assert_eq!(stepped, len - 1);
        assert!(nav.at_end());
    }

    #[test]
    fn test_step_backward_n() {
        let mut nav = nav_with_calls();
        nav.current_idx = 5;
        let stepped = nav.step_backward_n(3);
        assert_eq!(stepped, 3);
        assert_eq!(nav.current_idx, 2);
    }

    #[test]
    fn test_jump_to_beginning() {
        let mut nav = nav_with_calls();
        nav.current_idx = 7;
        nav.jump_to_beginning();
        assert_eq!(nav.current_idx, 0);
    }

    #[test]
    fn test_jump_to_end() {
        let mut nav = nav_with_calls();
        nav.jump_to_end();
        assert_eq!(nav.current_idx, nav.trace.len() - 1);
    }

    #[test]
    fn test_calls_to() {
        let nav = nav_with_calls();
        let calls = nav.calls_to(0x2000);
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn test_entries_where_reg_eq() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "a");
        b.regs(vec![(0, 42)]);
        b.insn(0x1004, 1, "b");
        b.regs(vec![(0, 99)]);
        b.insn(0x1008, 1, "c");
        b.regs(vec![(0, 42)]);
        let nav = b.build_navigator();
        let idxs = nav.entries_where_reg_eq(0, 42);
        assert_eq!(idxs.len(), 2);
    }

    // ── PatternMatcher ────────────────────────────────────────────────────

    #[test]
    fn test_pattern_matcher_find_all() {
        let nav = nav_with_calls();
        let pm = PatternMatcher::new(vec![0x1000, 0x1004]);
        let found = pm.find_all(&nav.trace);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], 0);
    }

    #[test]
    fn test_pattern_matcher_not_found() {
        let nav = nav_with_calls();
        let pm = PatternMatcher::new(vec![0xDEAD, 0xBEEF]);
        assert!(pm.find_first(&nav.trace).is_none());
    }

    #[test]
    fn test_pattern_matcher_single_pc() {
        let nav = nav_with_calls();
        let pm = PatternMatcher::new(vec![0x2000]);
        assert_eq!(pm.count(&nav.trace), 1);
    }

    #[test]
    fn test_pattern_matcher_empty_pattern() {
        let nav = nav_with_calls();
        let pm = PatternMatcher::new(vec![]);
        assert!(pm.find_first(&nav.trace).is_none());
    }

    // ── TraceResampler ────────────────────────────────────────────────────

    #[test]
    fn test_resampler_every_n() {
        let nav = nav_with_calls();
        let sampled = TraceResampler::sample_every_n(&nav.trace, 2);
        assert_eq!(sampled.len(), nav.trace.len().div_ceil(2));
    }

    #[test]
    fn test_resampler_n_samples() {
        let nav = nav_with_calls();
        let sampled = TraceResampler::sample_n(&nav.trace, 3);
        assert_eq!(sampled.len(), 3);
    }

    #[test]
    fn test_resampler_n_larger_than_trace() {
        let nav = nav_with_calls();
        let sampled = TraceResampler::sample_n(&nav.trace, 9999);
        assert_eq!(sampled.len(), nav.trace.len());
    }

    #[test]
    fn test_resampler_zero_n() {
        let nav = nav_with_calls();
        let sampled = TraceResampler::sample_every_n(&nav.trace, 0);
        assert!(sampled.is_empty());
    }

    // ── NavigatorSnapshot ─────────────────────────────────────────────────

    #[test]
    fn test_snapshot_capture_restore() {
        let mut nav = nav_with_calls();
        nav.current_idx = 3;
        nav.set_bookmark("b1", None);
        let snap = NavigatorSnapshot::capture(&mut nav);
        assert_eq!(snap.current_idx, 3);
        nav.jump_to_beginning();
        snap.restore(&mut nav).unwrap();
        assert_eq!(nav.current_idx, 3);
    }

    #[test]
    fn test_snapshot_preserves_bookmarks() {
        let mut nav = nav_with_calls();
        nav.current_idx = 2;
        nav.set_bookmark("mymark", Some("note".to_string()));
        let snap = NavigatorSnapshot::capture(&mut nav);
        assert!(!snap.bookmarks.is_empty());
        assert!(snap.bookmarks.iter().any(|b| b.name == "mymark"));
    }

    // ── current_reg_snapshot ──────────────────────────────────────────────

    #[test]
    fn test_current_reg_snapshot() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "a");
        b.regs(vec![(0, 1), (1, 2)]);
        let nav = b.build_navigator();
        let snap = nav.current_reg_snapshot();
        assert_eq!(snap.get(&0), Some(&1));
        assert_eq!(snap.get(&1), Some(&2));
    }

    // ── last_write_before_cursor ──────────────────────────────────────────

    #[test]
    fn test_last_write_before_cursor() {
        let mut b = TraceBuilder::new("t");
        b.insn(0x1000, 1, "store");
        b.mem_write(0xABCD, vec![0x42]);
        b.insn(0x1004, 1, "nop");
        let mut nav = b.build_navigator();
        nav.current_idx = 1;
        let val = nav.last_write_before_cursor(0xABCD);
        assert_eq!(val, Some(0x42));
    }

    #[test]
    fn test_entries_in_range_reversed_range_is_empty_not_panic() {
        let entries: Vec<TraceEntry> = (0..8usize)
            .map(|i| TraceEntry::insn(i, 0x1000 + i as u64, 0, "nop"))
            .collect();
        let nav = TraceNavigator::new(ExecutionTrace::new(entries, "t"));
        // Reversed, both ends inside the trace.
        assert!(nav.entries_in_range(6..2).is_empty());
        // Reversed with the start past the end of the trace.
        assert!(nav.entries_in_range(1000..2).is_empty());
        // Well-formed ranges are unchanged, including the clamping one.
        assert_eq!(nav.entries_in_range(2..5).len(), 3);
        assert_eq!(nav.entries_in_range(6..100).len(), 2);
    }
}
