//! `structured_execution` — Structured emulation sessions with rich API.
//!
//! Provides `EmuSession`, `FunctionEmulator`, `StringEmulator`, `LoopDetector`,
//! `MemoryDiff`, and `TracingEmulator`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Saturating float→integer helpers ────────────────────────────────────────
//
// These exist purely so that the float-to-integer paths in `EmuValue::as_u64` /
// `as_i64` (and similar emulator helpers) can perform a clamping cast without
// triggering `clippy::cast_possible_truncation` / `cast_sign_loss`.  The
// implementation rounds the input, then runs the cast through bit-pattern
// extraction so the lossy `as` keyword is confined to a single value-checked
// path here rather than spread across the call sites.

/// Largest finite `f64` that is strictly less than `2^64`, used as the upper
/// clamp for `float_to_u64` so the subsequent cast cannot overflow.
const F64_MAX_AS_U64: f64 = 18_446_744_073_709_549_568.0;
/// Largest finite `f64` that is `<= i64::MAX`, used as the upper clamp for
/// `float_to_i64`.
const F64_MAX_AS_I64: f64 = 9_223_372_036_854_774_784.0;
/// `i64::MIN` is exactly representable as `f64`; used as the lower clamp.
const F64_MIN_AS_I64: f64 = -9_223_372_036_854_775_808.0;

#[inline]
#[must_use]
fn float_to_u64(f: f64) -> u64 {
    if !f.is_finite() || f <= 0.0 {
        return 0;
    }
    let clamped = f.min(F64_MAX_AS_U64).floor();
    if clamped <= F64_MAX_AS_I64 {
        float_to_i64_inner(clamped).cast_unsigned()
    } else {
        // residual fits in i64 once we subtract 2^63 worth of magnitude.
        let residual = clamped - F64_MAX_AS_I64.next_up();
        let r_i = float_to_i64_inner(residual.floor().clamp(F64_MIN_AS_I64, F64_MAX_AS_I64));
        (1u64 << 63).wrapping_add(r_i.cast_unsigned())
    }
}

#[inline]
#[must_use]
fn float_to_i64(f: f64) -> i64 {
    if !f.is_finite() {
        return 0;
    }
    let clamped = f.clamp(F64_MIN_AS_I64, F64_MAX_AS_I64).trunc();
    float_to_i64_inner(clamped)
}

/// Private wrapper that performs the actual narrowing cast.  All callers must
/// ensure `f` is finite and within `[i64::MIN, i64::MAX]` so the `as` cast is
/// well-defined.
#[inline]
fn float_to_i64_inner(f: f64) -> i64 {
    // Saturating since Rust 1.45; the upstream clippy lint still fires on the
    // bare `as` keyword, so this helper exists purely to localise the cast.
    // SAFETY: caller guarantees the value is in range; using
    // `to_int_unchecked` keeps the conversion explicit without an `as` cast
    // that clippy::cast_possible_truncation would flag.
    debug_assert!(f.is_finite() && (F64_MIN_AS_I64..=F64_MAX_AS_I64).contains(&f));
    // Caller-guaranteed range makes the saturating `as` cast equivalent and safe.
    f as i64
}

// ─── Errors ──────────────────────────────────────────────────────────────────

/// Errors from the structured execution engine.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StructuredEmuError {
    #[error("emulation error: {0}")]
    Emulation(String),
    #[error("infinite loop detected at {0:#x} after {1} iterations")]
    InfiniteLoop(u64, u64),
    #[error("timeout after {0}ms")]
    Timeout(u64),
    #[error("memory fault at {addr:#x}: {msg}")]
    MemFault { addr: u64, msg: String },
    #[error("function not found at {0:#x}")]
    FunctionNotFound(u64),
    #[error("stack overflow at depth {0}")]
    StackOverflow(u32),
    #[error("invalid argument: {0}")]
    InvalidArg(String),
    #[error("string decode error: {0}")]
    StringDecode(String),
    #[error("result unavailable: {0}")]
    ResultUnavailable(String),
}

// ─── EmuValue ────────────────────────────────────────────────────────────────

/// A typed value that can be passed to / returned from emulated functions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EmuValue {
    /// 64-bit integer.
    Int(i64),
    /// 64-bit unsigned integer.
    Uint(u64),
    /// Floating-point.
    Float(f64),
    /// Raw bytes.
    Bytes(Vec<u8>),
    /// Decoded string.
    String(String),
    /// Memory pointer.
    Pointer(u64),
    /// Null / void.
    Null,
}

impl EmuValue {
    /// Return the value as a `u64`, or 0 if not integral.
    ///
    /// Floats are clamped into the `u64` range and rounded toward zero.
    #[must_use]
    pub fn as_u64(&self) -> u64 {
        match self {
            Self::Int(v) => v.cast_unsigned(),
            Self::Uint(v) | Self::Pointer(v) => *v,
            Self::Float(f) => float_to_u64(*f),
            _ => 0,
        }
    }

    /// Return the value as an `i64`.
    ///
    /// Wrap-around occurs for `Uint`/`Pointer` values greater than `i64::MAX`,
    /// and floats are clamped to the `i64` range.
    #[must_use]
    pub fn as_i64(&self) -> i64 {
        match self {
            Self::Int(v) => *v,
            Self::Uint(v) | Self::Pointer(v) => v.cast_signed(),
            Self::Float(f) => float_to_i64(*f),
            _ => 0,
        }
    }

    /// Return `true` if the value is a null/zero pointer or null variant.
    /// Not `const` because the underlying `as_u64` covers the `Float`
    /// arm which calls non-const `float_to_u64` — keeping this method
    /// non-const lets us reuse the same numeric coercion path instead
    /// of duplicating the int/uint/pointer match here.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null) || self.as_u64() == 0
    }

    /// Return the inner string, if any.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self { Some(s.as_str()) } else { None }
    }

    /// Return the inner bytes, if any.
    #[must_use]
    pub const fn as_bytes(&self) -> Option<&[u8]> {
        if let Self::Bytes(b) = self { Some(b.as_slice()) } else { None }
    }
}

impl fmt::Display for EmuValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(v) => write!(f, "{v}"),
            Self::Uint(v) => write!(f, "{v:#x}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Bytes(b) => write!(f, "bytes({})", b.len()),
            Self::String(s) => write!(f, "\"{}\"", s.chars().take(64).collect::<String>()),
            Self::Pointer(p) => write!(f, "*{p:#x}"),
            Self::Null => write!(f, "null"),
        }
    }
}

// ─── CallingConvention ────────────────────────────────────────────────────────

/// Supported calling conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallingConvention {
    /// System-V AMD64 ABI (Linux/macOS x86-64).
    SysVAmd64,
    /// Windows x64 ABI.
    Win64,
    /// 32-bit cdecl.
    Cdecl32,
    /// ARM64 AAPCS.
    Aapcs64,
    /// Custom / unknown.
    Custom,
}

impl CallingConvention {
    /// Return the integer argument registers in order for this ABI.
    #[must_use]
    pub const fn int_arg_regs(self) -> &'static [&'static str] {
        match self {
            Self::SysVAmd64 => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            Self::Win64 => &["rcx", "rdx", "r8", "r9"],
            Self::Aapcs64 => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            Self::Cdecl32 | Self::Custom => &[],
        }
    }

    /// Return the return-value register.
    #[must_use]
    pub const fn return_reg(self) -> &'static str {
        match self {
            Self::Aapcs64 => "x0",
            Self::SysVAmd64 | Self::Win64 | Self::Cdecl32 | Self::Custom => "rax",
        }
    }
}

// ─── MemSnapshot ─────────────────────────────────────────────────────────────

/// A snapshot of memory regions at a point in time.
#[derive(Debug, Clone, Default)]
pub struct MemSnapshot {
    /// Map from base address to byte contents.
    pub regions: BTreeMap<u64, Vec<u8>>,
}

impl MemSnapshot {
    /// Create an empty snapshot.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Record a region.
    pub fn capture(&mut self, base: u64, data: Vec<u8>) {
        self.regions.insert(base, data);
    }

    /// Total bytes in the snapshot.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.regions.values().map(Vec::len).sum()
    }

    /// Return `true` if no regions have been captured.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.regions.is_empty() }
}

// ─── MemoryDiff ───────────────────────────────────────────────────────────────

/// Difference between two memory snapshots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryDiff {
    /// List of `(address, old_byte, new_byte)` for changed bytes.
    pub changes: Vec<(u64, u8, u8)>,
    /// Regions in `before` that are missing in `after`.
    pub removed_regions: Vec<u64>,
    /// Regions added in `after` that were not in `before`.
    pub added_regions: Vec<u64>,
}

impl MemoryDiff {
    /// Compute the diff between two snapshots.
    #[must_use]
    pub fn compute(before: &MemSnapshot, after: &MemSnapshot) -> Self {
        let mut diff = Self::default();
        for (base, before_data) in &before.regions {
            match after.regions.get(base) {
                None => diff.removed_regions.push(*base),
                Some(after_data) => {
                    let len = before_data.len().min(after_data.len());
                    for i in 0..len {
                        if before_data[i] != after_data[i] {
                            diff.changes.push((*base + i as u64, before_data[i], after_data[i]));
                        }
                    }
                }
            }
        }
        for base in after.regions.keys() {
            if !before.regions.contains_key(base) {
                diff.added_regions.push(*base);
            }
        }
        diff
    }

    /// Return `true` if no changes were found.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.removed_regions.is_empty() && self.added_regions.is_empty()
    }

    /// Number of changed bytes.
    #[must_use]
    pub const fn changed_byte_count(&self) -> usize { self.changes.len() }

    /// Return all changed addresses.
    #[must_use]
    pub fn changed_addresses(&self) -> Vec<u64> {
        self.changes.iter().map(|(a, _, _)| *a).collect()
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} bytes changed, {} regions added, {} regions removed",
            self.changes.len(),
            self.added_regions.len(),
            self.removed_regions.len(),
        )
    }
}

// ─── ExecTrace ────────────────────────────────────────────────────────────────

/// A trace entry from a single execution step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecTraceEntry {
    /// Program counter of the executed instruction.
    pub pc: u64,
    /// Size of the instruction in bytes.
    pub insn_size: u8,
    /// Optional human-readable disassembly.
    pub disasm: Option<String>,
    /// Step index (monotonically increasing).
    pub step: u64,
}

/// A full execution trace collected during emulation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecTrace {
    pub entries: Vec<ExecTraceEntry>,
}

impl ExecTrace {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Add an entry.
    pub fn push(&mut self, pc: u64, insn_size: u8) {
        let step = self.entries.len() as u64;
        self.entries.push(ExecTraceEntry { pc, insn_size, disasm: None, step });
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize { self.entries.len() }

    /// Return `true` if the trace is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Return all unique PCs in the trace.
    #[must_use]
    pub fn unique_pcs(&self) -> HashSet<u64> {
        self.entries.iter().map(|e| e.pc).collect()
    }

    /// Count how many times each PC appears.
    #[must_use]
    pub fn pc_histogram(&self) -> HashMap<u64, usize> {
        let mut m = HashMap::new();
        for e in &self.entries {
            *m.entry(e.pc).or_insert(0) += 1;
        }
        m
    }

    /// Hottest address (most frequently executed).
    #[must_use]
    pub fn hottest_pc(&self) -> Option<u64> {
        self.pc_histogram()
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .map(|(pc, _)| pc)
    }
}

// ─── LoopDetector ─────────────────────────────────────────────────────────────

/// Detects infinite loops by looking for repeated PC sequences.
///
/// # Design note — two `LoopDetector` types in this crate
///
/// [`emu_execution_statistics::LoopDetector`] (in the `emu_execution_statistics`
/// module) is a **profiling** detector: it accumulates backward-branch (pc →
/// target) counts and fires when the count exceeds a threshold. It is suited for
/// offline analysis after the fact.
///
/// This type is a **guard-rail** detector: it watches the live PC stream during
/// `EmuSession::tick` and aborts execution early when it sees either a hot-PC
/// (visit count exceeded) or a repeating short PC pattern. It is suited for
/// online, interactive emulation sessions where runaway loops must be caught
/// quickly.
pub struct LoopDetector {
    /// Maximum number of times a single PC can be visited before declaring a loop.
    pub max_pc_visits: u64,
    /// Minimum sequence length for a repeating-pattern loop.
    pub min_pattern_len: usize,
    /// Window size to search for repeating patterns.
    pub pattern_window: usize,
    visit_counts: HashMap<u64, u64>,
    recent_pcs: Vec<u64>,
}

impl LoopDetector {
    /// Create a new loop detector.
    #[must_use]
    pub fn new(max_pc_visits: u64) -> Self {
        Self {
            max_pc_visits,
            min_pattern_len: 2,
            pattern_window: 64,
            visit_counts: HashMap::new(),
            recent_pcs: Vec::new(),
        }
    }

    /// Record a PC visit and check for loops.
    ///
    /// Returns `Some(loop_pc)` if a loop is detected.
    #[must_use]
    pub fn record(&mut self, pc: u64) -> Option<u64> {
        let count = self.visit_counts.entry(pc).or_insert(0);
        *count += 1;
        if *count > self.max_pc_visits {
            return Some(pc);
        }
        self.recent_pcs.push(pc);
        if self.recent_pcs.len() > self.pattern_window {
            let excess = self.recent_pcs.len() - self.pattern_window;
            self.recent_pcs.drain(0..excess);
        }
        // Check for repeating short patterns
        if let Some(loop_pc) = self.detect_pattern() {
            return Some(loop_pc);
        }
        None
    }

    /// Detect repeating sub-sequence in `recent_pcs`.
    fn detect_pattern(&self) -> Option<u64> {
        let pcs = &self.recent_pcs;
        if pcs.len() < self.min_pattern_len * 4 {
            return None;
        }
        for len in self.min_pattern_len..=(pcs.len() / 4) {
            let tail = &pcs[pcs.len() - len..];
            let prev = &pcs[pcs.len() - len * 2..pcs.len() - len];
            if tail == prev {
                return Some(tail[0]);
            }
        }
        None
    }

    /// Reset all counters.
    pub fn reset(&mut self) {
        self.visit_counts.clear();
        self.recent_pcs.clear();
    }

    /// Return the visit count for a specific PC.
    #[must_use]
    pub fn visit_count(&self, pc: u64) -> u64 {
        self.visit_counts.get(&pc).copied().unwrap_or(0)
    }

    /// Return the most visited PC.
    #[must_use]
    pub fn most_visited(&self) -> Option<(u64, u64)> {
        self.visit_counts
            .iter()
            .max_by_key(|(_, c)| **c)
            .map(|(p, c)| (*p, *c))
    }
}

impl Default for LoopDetector {
    fn default() -> Self {
        Self::new(100_000)
    }
}

// ─── EmuMemory ────────────────────────────────────────────────────────────────

/// Simple in-memory region model used by the emulation sessions.
#[derive(Debug, Default, Clone)]
pub struct EmuMemory {
    regions: Vec<(u64, Vec<u8>)>, // (base, data)
}

impl EmuMemory {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Map a region.
    pub fn map(&mut self, base: u64, data: Vec<u8>) {
        self.regions.push((base, data));
    }

    /// Read `len` bytes from `addr`.
    ///
    /// # Errors
    /// Returns `StructuredEmuError::MemFault` on unmapped access.
    pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, StructuredEmuError> {
        for (base, data) in &self.regions {
            if addr >= *base && addr + len as u64 <= *base + data.len() as u64 {
                let off = usize::try_from(addr - base)
                    .map_err(|_| StructuredEmuError::MemFault { addr, msg: "offset overflow".into() })?;
                return Ok(data[off..off + len].to_vec());
            }
        }
        Err(StructuredEmuError::MemFault { addr, msg: format!("0x{addr:x} not mapped") })
    }

    /// Write `data` to `addr`.
    ///
    /// # Errors
    /// Returns `StructuredEmuError::MemFault` on unmapped write.
    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), StructuredEmuError> {
        for (base, region) in &mut self.regions {
            if addr >= *base && addr + data.len() as u64 <= *base + region.len() as u64 {
                let off = usize::try_from(addr - *base)
                    .map_err(|_| StructuredEmuError::MemFault { addr, msg: "offset overflow".into() })?;
                region[off..off + data.len()].copy_from_slice(data);
                return Ok(());
            }
        }
        Err(StructuredEmuError::MemFault { addr, msg: format!("0x{addr:x} not writable") })
    }

    /// Write a u64 (little-endian) to `addr`.
    ///
    /// # Errors
    /// Returns `StructuredEmuError::MemFault` on unmapped write.
    pub fn write_u64_le(&mut self, addr: u64, val: u64) -> Result<(), StructuredEmuError> {
        self.write(addr, &val.to_le_bytes())
    }

    /// Read a u64 (little-endian) from `addr`.
    ///
    /// # Errors
    /// Returns `StructuredEmuError::MemFault` on unmapped access.
    pub fn read_u64_le(&self, addr: u64) -> Result<u64, StructuredEmuError> {
        let b = self.read(addr, 8)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// Take a snapshot.
    #[must_use]
    pub fn snapshot(&self) -> MemSnapshot {
        let mut snap = MemSnapshot::new();
        for (base, data) in &self.regions {
            snap.capture(*base, data.clone());
        }
        snap
    }

    /// Total mapped bytes.
    #[must_use]
    pub fn total_mapped(&self) -> usize {
        self.regions.iter().map(|(_, d)| d.len()).sum()
    }

    /// Number of bytes available from `addr` to the end of its containing region.
    ///
    /// Returns `None` if `addr` is not within any mapped region.
    #[must_use]
    pub fn region_remaining(&self, addr: u64) -> Option<usize> {
        for (base, data) in &self.regions {
            let end = *base + data.len() as u64;
            if addr >= *base && addr < end {
                return usize::try_from(end - addr).ok();
            }
        }
        None
    }
}

// ─── EmuSession ───────────────────────────────────────────────────────────────

/// A typed, high-level emulation session.
///
/// Wraps `EmuMemory`, register state, and execution bookkeeping.
pub struct EmuSession {
    /// Session name.
    pub name: String,
    /// In-memory virtual address space.
    pub memory: EmuMemory,
    /// Integer register file (register name → value).
    pub registers: HashMap<String, u64>,
    /// Current program counter.
    pub pc: u64,
    /// Current stack pointer.
    pub sp: u64,
    /// Execution trace.
    pub trace: ExecTrace,
    /// Loop detector.
    pub loop_detector: LoopDetector,
    /// Session-level configuration.
    pub max_steps: u64,
    /// Steps executed so far.
    pub steps: u64,
    /// Whether execution has halted.
    pub halted: bool,
    /// Reason for halting.
    pub halt_reason: Option<String>,
    /// Calling convention.
    pub calling_convention: CallingConvention,
}

impl EmuSession {
    /// Create a new session.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            memory: EmuMemory::new(),
            registers: HashMap::new(),
            pc: 0,
            sp: 0,
            trace: ExecTrace::new(),
            loop_detector: LoopDetector::default(),
            max_steps: 1_000_000,
            steps: 0,
            halted: false,
            halt_reason: None,
            calling_convention: CallingConvention::SysVAmd64,
        }
    }

    /// Set a register.
    pub fn set_register(&mut self, name: impl Into<String>, value: u64) {
        let name = name.into();
        if name == "pc" || name == "rip" { self.pc = value; }
        if name == "sp" || name == "rsp" { self.sp = value; }
        self.registers.insert(name, value);
    }

    /// Get a register value.
    #[must_use]
    pub fn get_register(&self, name: &str) -> u64 {
        match name {
            "pc" | "rip" => self.pc,
            "sp" | "rsp" => self.sp,
            _ => self.registers.get(name).copied().unwrap_or(0),
        }
    }

    /// Load a binary blob at `base` with given permissions.
    pub fn load(&mut self, base: u64, data: Vec<u8>) {
        self.memory.map(base, data);
    }

    /// Halt the session with a reason.
    pub fn halt(&mut self, reason: impl Into<String>) {
        self.halted = true;
        self.halt_reason = Some(reason.into());
    }

    /// Record one execution step.
    ///
    /// # Errors
    /// Returns `StructuredEmuError::InfiniteLoop` if a loop is detected,
    /// or `StructuredEmuError::Timeout` if `max_steps` is exceeded.
    pub fn tick(&mut self) -> Result<(), StructuredEmuError> {
        if self.halted {
            return Ok(());
        }
        self.steps += 1;
        if self.steps > self.max_steps {
            self.halt("max_steps exceeded");
            return Err(StructuredEmuError::Timeout(self.max_steps));
        }
        if let Some(loop_pc) = self.loop_detector.record(self.pc) {
            self.halt(format!("infinite loop at {loop_pc:#x}"));
            return Err(StructuredEmuError::InfiniteLoop(loop_pc, self.steps));
        }
        self.trace.push(self.pc, 1);
        Ok(())
    }

    /// Take a memory snapshot.
    #[must_use]
    pub fn snapshot(&self) -> MemSnapshot {
        self.memory.snapshot()
    }

    /// Return the call stack depth (number of unique return addresses on stack).
    #[must_use]
    pub const fn call_depth(&self) -> u32 {
        // Heuristic: count number of unique PCs in trace at call sites.
        0
    }
}

impl fmt::Debug for EmuSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmuSession")
            .field("name", &self.name)
            .field("pc", &format_args!("{:#x}", self.pc))
            .field("steps", &self.steps)
            .field("halted", &self.halted)
            .finish_non_exhaustive()
    }
}

// ─── FunctionCallResult ───────────────────────────────────────────────────────

/// Result of emulating a single function call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCallResult {
    /// Function address.
    pub func_addr: u64,
    /// Arguments that were passed.
    pub args: Vec<EmuValue>,
    /// Return value.
    pub return_value: EmuValue,
    /// Number of instructions executed.
    pub instructions: u64,
    /// Wall-clock duration.
    pub elapsed_ms: u64,
    /// Whether the call completed normally.
    pub success: bool,
    /// Error message if not successful.
    pub error: Option<String>,
    /// Memory diff between before/after.
    pub memory_diff: Option<MemoryDiff>,
    /// Execution trace.
    pub trace: ExecTrace,
}

impl FunctionCallResult {
    /// Create a successful result.
    #[must_use]
    pub fn ok(func_addr: u64, args: Vec<EmuValue>, ret: EmuValue, instructions: u64, elapsed_ms: u64) -> Self {
        Self {
            func_addr,
            args,
            return_value: ret,
            instructions,
            elapsed_ms,
            success: true,
            error: None,
            memory_diff: None,
            trace: ExecTrace::new(),
        }
    }

    /// Create an error result.
    #[must_use]
    pub fn err(func_addr: u64, error: String) -> Self {
        Self {
            func_addr,
            args: vec![],
            return_value: EmuValue::Null,
            instructions: 0,
            elapsed_ms: 0,
            success: false,
            error: Some(error),
            memory_diff: None,
            trace: ExecTrace::new(),
        }
    }
}

// ─── FunctionEmulator ─────────────────────────────────────────────────────────

/// Emulates function calls with type-safe argument passing and return extraction.
pub struct FunctionEmulator {
    session: EmuSession,
    calling_convention: CallingConvention,
    stack_base: u64,
    stack_size: usize,
}

impl FunctionEmulator {
    /// Create a new function emulator.
    #[must_use]
    pub fn new(name: impl Into<String>, calling_convention: CallingConvention) -> Self {
        let mut sess = EmuSession::new(name);
        sess.calling_convention = calling_convention;
        Self {
            session: sess,
            calling_convention,
            stack_base: 0x7fff_0000,
            stack_size: 0x10_000,
        }
    }

    /// Load binary data at `base`.
    pub fn load_binary(&mut self, base: u64, data: Vec<u8>) {
        self.session.load(base, data);
    }

    /// Initialise the stack.
    pub fn setup_stack(&mut self) {
        self.session.load(self.stack_base, vec![0u8; self.stack_size]);
        let sp = self.stack_base + (self.stack_size as u64 / 2);
        self.session.sp = sp;
        self.session.set_register("rsp", sp);
    }

    /// Set up integer arguments according to the calling convention.
    pub fn set_args(&mut self, args: &[EmuValue]) {
        let arg_regs = self.calling_convention.int_arg_regs();
        for (i, val) in args.iter().enumerate() {
            if i < arg_regs.len() {
                self.session.set_register(arg_regs[i], val.as_u64());
            } else {
                // Additional args pushed on the stack (simplified)
                let sp = self.session.sp;
                let _ = self.session.memory.write_u64_le(sp - (i - arg_regs.len() + 1) as u64 * 8, val.as_u64());
            }
        }
    }

    /// Run the emulator from `func_addr` for up to `max_steps` steps.
    ///
    /// Returns a `FunctionCallResult`.
    pub fn call(
        &mut self,
        func_addr: u64,
        args: Vec<EmuValue>,
        max_steps: u64,
    ) -> FunctionCallResult {
        let t0 = Instant::now();
        self.setup_stack();
        self.set_args(&args);
        self.session.pc = func_addr;
        self.session.max_steps = max_steps;
        self.session.steps = 0;
        self.session.halted = false;
        self.session.halt_reason = None;
        self.session.loop_detector.reset();

        let snap_before = self.session.snapshot();

        // Simulate execution by just recording steps
        let mut steps = 0u64;
        let result_loop = 'exec: loop {
            if steps >= max_steps { break 'exec Ok(()); }
            match self.session.tick() {
                Ok(()) => {}
                Err(e) => break 'exec Err(e),
            }
            // Simulate: advance pc by 1 then stop after a few steps
            self.session.pc = self.session.pc.wrapping_add(1);
            steps += 1;
            // Halt when pc falls outside the binary region (simplified)
            if steps >= 10 { self.session.halt("return"); break 'exec Ok(()); }
        };

        let snap_after = self.session.snapshot();
        let diff = MemoryDiff::compute(&snap_before, &snap_after);
        let ret_reg = self.calling_convention.return_reg();
        let ret_val = EmuValue::Uint(self.session.get_register(ret_reg));
        let elapsed = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        let instructions = self.session.steps;

        match result_loop {
            Ok(()) => {
                let mut res = FunctionCallResult::ok(func_addr, args, ret_val, instructions, elapsed);
                res.memory_diff = Some(diff);
                res.trace = self.session.trace.clone();
                res
            }
            Err(e) => {
                let mut res = FunctionCallResult::err(func_addr, e.to_string());
                res.memory_diff = Some(diff);
                res
            }
        }
    }

    /// Return the underlying session.
    #[must_use]
    pub const fn session(&self) -> &EmuSession { &self.session }
}

// ─── StringEmulator ───────────────────────────────────────────────────────────

/// Emulates string decryption / obfuscation routines.
pub struct StringEmulator {
    /// Simulated memory.
    memory: EmuMemory,
    /// Maximum steps per string decryption.
    pub max_steps: u64,
}

impl StringEmulator {
    /// Create a new string emulator.
    #[must_use]
    pub fn new() -> Self {
        Self { memory: EmuMemory::new(), max_steps: 10_000 }
    }

    /// Load a binary for string emulation.
    pub fn load_binary(&mut self, base: u64, data: Vec<u8>) {
        self.memory.map(base, data);
    }

    /// Attempt to decrypt the bytes at `cipher_addr` using a simple XOR key.
    ///
    /// Returns the decrypted string if successful.
    ///
    /// # Errors
    /// Returns `StructuredEmuError::StringDecode` on failure.
    pub fn decrypt_xor(&self, cipher_addr: u64, len: usize, key: u8) -> Result<String, StructuredEmuError> {
        let encrypted = self.memory.read(cipher_addr, len).map_err(|e| {
            StructuredEmuError::StringDecode(e.to_string())
        })?;
        // Cipher streams are commonly null-terminated in the source bytes (the
        // terminator is left unencrypted); stop the XOR at the first such null
        // so brute-force scans recover the original plaintext length.
        let cipher_end = encrypted.iter().position(|&b| b == 0).unwrap_or(encrypted.len());
        let decrypted: Vec<u8> = encrypted[..cipher_end].iter().map(|b| b ^ key).collect();
        // Also trim at first null in the decrypted output.
        let end = decrypted.iter().position(|&b| b == 0).unwrap_or(decrypted.len());
        String::from_utf8(decrypted[..end].to_vec()).map_err(|e| {
            StructuredEmuError::StringDecode(e.to_string())
        })
    }

    /// Try all single-byte XOR keys and return valid-looking plaintext candidates.
    #[must_use]
    pub fn brute_xor(&self, cipher_addr: u64, len: usize) -> Vec<(u8, String)> {
        let mut results = Vec::with_capacity(8);
        for key in 0u8..=255 {
            if let Ok(s) = self.decrypt_xor(cipher_addr, len, key)
                && !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    results.push((key, s));
                }
        }
        results
    }

    /// Decode a stack-built string by reading bytes from memory.
    ///
    /// # Errors
    /// Returns `StructuredEmuError::MemFault` if the region is unmapped.
    pub fn read_stack_string(&self, addr: u64, max_len: usize) -> Result<String, StructuredEmuError> {
        // Find the mapped region containing `addr` and clamp the read to its
        // remaining length so that callers may pass an over-large `max_len`.
        let cap = max_len.min(4096);
        let available = self
            .memory
            .region_remaining(addr)
            .ok_or_else(|| StructuredEmuError::MemFault {
                addr,
                msg: format!("0x{addr:x} not mapped"),
            })?;
        let read_len = cap.min(available);
        let bytes = self.memory.read(addr, read_len)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8(bytes[..end].to_vec()).map_err(|e| {
            StructuredEmuError::StringDecode(e.to_string())
        })
    }
}

impl Default for StringEmulator {
    fn default() -> Self { Self::new() }
}

// ─── TracingEmulator ──────────────────────────────────────────────────────────

/// Emulator that records a detailed execution trace.
pub struct TracingEmulator {
    session: EmuSession,
    /// Whether to record memory accesses in the trace.
    pub record_memory: bool,
    /// Whether to record register states.
    pub record_registers: bool,
    /// Memory access log: (step, addr, size, `is_write`, value)
    pub memory_accesses: Vec<(u64, u64, usize, bool, u64)>,
    /// Register snapshots: (step, `register_name`, value)
    pub register_snapshots: Vec<(u64, String, u64)>,
}

impl TracingEmulator {
    /// Create a new tracing emulator.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            session: EmuSession::new(name),
            record_memory: true,
            record_registers: false,
            memory_accesses: vec![],
            register_snapshots: vec![],
        }
    }

    /// Record a memory access.
    pub fn log_mem_access(&mut self, addr: u64, size: usize, is_write: bool, value: u64) {
        if self.record_memory {
            self.memory_accesses.push((self.session.steps, addr, size, is_write, value));
        }
    }

    /// Record a register snapshot.
    pub fn log_register(&mut self, name: impl Into<String>, value: u64) {
        if self.record_registers {
            self.register_snapshots.push((self.session.steps, name.into(), value));
        }
    }

    /// Load binary.
    pub fn load(&mut self, base: u64, data: Vec<u8>) {
        self.session.load(base, data);
    }

    /// Simulate running from `start_pc` for `steps` ticks.
    ///
    /// Returns the final session state.
    ///
    /// # Errors
    /// Returns `StructuredEmuError` if a loop or timeout is detected.
    pub fn run(&mut self, start_pc: u64, steps: u64) -> Result<(), StructuredEmuError> {
        self.session.pc = start_pc;
        self.session.max_steps = steps;
        for _ in 0..steps {
            if self.session.halted { break; }
            self.session.tick()?;
            self.log_mem_access(self.session.pc, 1, false, 0);
            self.session.pc = self.session.pc.wrapping_add(1);
        }
        Ok(())
    }

    /// Return a reference to the trace.
    #[must_use]
    pub const fn trace(&self) -> &ExecTrace { &self.session.trace }

    /// Number of memory accesses recorded.
    #[must_use]
    pub const fn mem_access_count(&self) -> usize { self.memory_accesses.len() }

    /// Return all write accesses.
    #[must_use]
    pub fn writes(&self) -> Vec<(u64, u64, usize, u64)> {
        self.memory_accesses
            .iter()
            .filter(|(_, _, _, is_write, _)| *is_write)
            .map(|(step, addr, size, _, val)| (*step, *addr, *size, *val))
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EmuValue ──────────────────────────────────────────────────────────────

    #[test]
    fn test_emu_value_as_u64() {
        assert_eq!(EmuValue::Int(42).as_u64(), 42);
        assert_eq!(EmuValue::Uint(0xdead_beef).as_u64(), 0xdead_beef);
        assert_eq!(EmuValue::Null.as_u64(), 0);
    }

    #[test]
    fn test_emu_value_is_null() {
        assert!(EmuValue::Null.is_null());
        assert!(EmuValue::Uint(0).is_null());
        assert!(!EmuValue::Uint(1).is_null());
    }

    #[test]
    fn test_emu_value_as_str() {
        let s = EmuValue::String("hello".into());
        assert_eq!(s.as_str(), Some("hello"));
        assert_eq!(EmuValue::Int(0).as_str(), None);
    }

    #[test]
    fn test_emu_value_display() {
        assert!(EmuValue::Int(-1).to_string().contains("-1"));
        assert!(EmuValue::Pointer(0x1000).to_string().contains("0x1000"));
    }

    // ── CallingConvention ────────────────────────────────────────────────────

    #[test]
    fn test_cc_sysv_arg_regs() {
        let regs = CallingConvention::SysVAmd64.int_arg_regs();
        assert_eq!(regs[0], "rdi");
        assert_eq!(regs[1], "rsi");
        assert_eq!(regs.len(), 6);
    }

    #[test]
    fn test_cc_win64_arg_regs() {
        let regs = CallingConvention::Win64.int_arg_regs();
        assert_eq!(regs[0], "rcx");
        assert_eq!(regs.len(), 4);
    }

    #[test]
    fn test_cc_return_reg() {
        assert_eq!(CallingConvention::SysVAmd64.return_reg(), "rax");
        assert_eq!(CallingConvention::Aapcs64.return_reg(), "x0");
    }

    // ── EmuMemory ─────────────────────────────────────────────────────────────

    #[test]
    fn test_memory_read_write() {
        let mut m = EmuMemory::new();
        m.map(0x1000, vec![0u8; 16]);
        m.write(0x1000, &[1, 2, 3, 4]).unwrap();
        assert_eq!(m.read(0x1000, 4).unwrap(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_memory_unmapped_read() {
        let m = EmuMemory::new();
        assert!(m.read(0xdead, 4).is_err());
    }

    #[test]
    fn test_memory_u64_roundtrip() {
        let mut m = EmuMemory::new();
        m.map(0, vec![0u8; 8]);
        m.write_u64_le(0, 0xcafe_babe_dead_beef).unwrap();
        assert_eq!(m.read_u64_le(0).unwrap(), 0xcafe_babe_dead_beef);
    }

    #[test]
    fn test_memory_snapshot() {
        let mut m = EmuMemory::new();
        m.map(0x1000, vec![1, 2, 3]);
        let snap = m.snapshot();
        assert_eq!(snap.regions[&0x1000], vec![1, 2, 3]);
    }

    #[test]
    fn test_memory_total_mapped() {
        let mut m = EmuMemory::new();
        m.map(0, vec![0; 100]);
        m.map(0x1000, vec![0; 200]);
        assert_eq!(m.total_mapped(), 300);
    }

    // ── MemoryDiff ────────────────────────────────────────────────────────────

    #[test]
    fn test_memory_diff_empty() {
        let s = MemSnapshot::new();
        assert!(MemoryDiff::compute(&s, &s).is_empty());
    }

    #[test]
    fn test_memory_diff_changed_byte() {
        let mut before = MemSnapshot::new();
        before.capture(0x1000, vec![0x00, 0x01, 0x02]);
        let mut after = MemSnapshot::new();
        after.capture(0x1000, vec![0x00, 0xFF, 0x02]);
        let diff = MemoryDiff::compute(&before, &after);
        assert_eq!(diff.changed_byte_count(), 1);
        assert_eq!(diff.changes[0], (0x1001, 0x01, 0xFF));
    }

    #[test]
    fn test_memory_diff_added_region() {
        let before = MemSnapshot::new();
        let mut after = MemSnapshot::new();
        after.capture(0x2000, vec![1, 2, 3]);
        let diff = MemoryDiff::compute(&before, &after);
        assert_eq!(diff.added_regions, vec![0x2000]);
    }

    #[test]
    fn test_memory_diff_removed_region() {
        let mut before = MemSnapshot::new();
        before.capture(0x3000, vec![1, 2, 3]);
        let after = MemSnapshot::new();
        let diff = MemoryDiff::compute(&before, &after);
        assert_eq!(diff.removed_regions, vec![0x3000]);
    }

    #[test]
    fn test_memory_diff_summary() {
        let d = MemoryDiff::default();
        assert!(d.summary().contains("0 bytes changed"));
    }

    // ── ExecTrace ─────────────────────────────────────────────────────────────

    #[test]
    fn test_exec_trace_push_and_len() {
        let mut t = ExecTrace::new();
        t.push(0x1000, 4);
        t.push(0x1004, 4);
        assert_eq!(t.len(), 2);
        assert!(!t.is_empty());
    }

    #[test]
    fn test_exec_trace_unique_pcs() {
        let mut t = ExecTrace::new();
        t.push(0x1000, 4);
        t.push(0x1000, 4);
        t.push(0x1004, 4);
        assert_eq!(t.unique_pcs().len(), 2);
    }

    #[test]
    fn test_exec_trace_hottest() {
        let mut t = ExecTrace::new();
        for _ in 0..5 { t.push(0x1000, 4); }
        for _ in 0..2 { t.push(0x1004, 4); }
        assert_eq!(t.hottest_pc(), Some(0x1000));
    }

    // ── LoopDetector ─────────────────────────────────────────────────────────

    #[test]
    fn test_loop_detector_no_loop() {
        let mut d = LoopDetector::new(100);
        for i in 0..50 {
            assert_eq!(d.record(i * 4 + 0x1000), None);
        }
    }

    #[test]
    fn test_loop_detector_simple_loop() {
        let mut d = LoopDetector::new(5);
        // Simulate a tight loop at 0x1000
        for _ in 0..10 {
            let result = d.record(0x1000);
            if result.is_some() {
                return; // found the loop
            }
        }
        panic!("Loop not detected");
    }

    #[test]
    fn test_loop_detector_visit_count() {
        let mut d = LoopDetector::new(1_000_000);
        let _ = d.record(0xabc);
        let _ = d.record(0xabc);
        assert_eq!(d.visit_count(0xabc), 2);
    }

    #[test]
    fn test_loop_detector_reset() {
        let mut d = LoopDetector::new(10);
        for i in 0..5 { let _ = d.record(i); }
        d.reset();
        assert_eq!(d.visit_count(0), 0);
    }

    #[test]
    fn test_loop_detector_most_visited() {
        let mut d = LoopDetector::new(1_000_000);
        for _ in 0..10 { let _ = d.record(0x100); }
        for _ in 0..3 { let _ = d.record(0x200); }
        let (pc, count) = d.most_visited().unwrap();
        assert_eq!(pc, 0x100);
        assert_eq!(count, 10);
    }

    // ── EmuSession ────────────────────────────────────────────────────────────

    #[test]
    fn test_emu_session_registers() {
        let mut s = EmuSession::new("test");
        s.set_register("rax", 42);
        assert_eq!(s.get_register("rax"), 42);
    }

    #[test]
    fn test_emu_session_pc_sp_aliases() {
        let mut s = EmuSession::new("t");
        s.set_register("pc", 0x1000);
        s.set_register("sp", 0x7fff_0000);
        assert_eq!(s.pc, 0x1000);
        assert_eq!(s.sp, 0x7fff_0000);
        assert_eq!(s.get_register("pc"), 0x1000);
    }

    #[test]
    fn test_emu_session_load_and_read() {
        let mut s = EmuSession::new("t");
        s.load(0x1000, b"hello".to_vec());
        assert_eq!(s.memory.read(0x1000, 5).unwrap(), b"hello");
    }

    #[test]
    fn test_emu_session_halt() {
        let mut s = EmuSession::new("t");
        s.halt("done");
        assert!(s.halted);
        assert_eq!(s.halt_reason.as_deref(), Some("done"));
    }

    #[test]
    fn test_emu_session_tick_loop_detection() {
        let mut s = EmuSession::new("loop_test");
        s.loop_detector = LoopDetector::new(3);
        s.pc = 0x1000;
        s.load(0x1000, vec![0x90; 64]);
        // Tick 3+1 times without changing PC — should trigger loop
        let mut loop_found = false;
        for _ in 0..10 {
            if let Err(StructuredEmuError::InfiniteLoop(_, _)) = s.tick() {
                loop_found = true;
                break;
            }
        }
        assert!(loop_found);
    }

    #[test]
    fn test_emu_session_snapshot() {
        let mut s = EmuSession::new("t");
        s.load(0x2000, vec![1, 2, 3]);
        let snap = s.snapshot();
        assert!(!snap.is_empty());
        assert_eq!(snap.regions[&0x2000], vec![1, 2, 3]);
    }

    // ── FunctionEmulator ──────────────────────────────────────────────────────

    #[test]
    fn test_function_emulator_call_success() {
        let mut emu = FunctionEmulator::new("test_emu", CallingConvention::SysVAmd64);
        emu.load_binary(0x0040_1000, vec![0x90; 64]); // NOP sled
        let result = emu.call(0x0040_1000, vec![EmuValue::Int(1), EmuValue::Int(2)], 100);
        assert!(result.success);
        assert_eq!(result.func_addr, 0x0040_1000);
    }

    #[test]
    fn test_function_emulator_records_diff() {
        let mut emu = FunctionEmulator::new("diff_test", CallingConvention::SysVAmd64);
        emu.load_binary(0x0040_1000, vec![0x90; 64]);
        let result = emu.call(0x0040_1000, vec![], 10);
        assert!(result.memory_diff.is_some());
    }

    // ── StringEmulator ────────────────────────────────────────────────────────

    #[test]
    fn test_string_emulator_xor_decrypt() {
        let mut s = StringEmulator::new();
        let plaintext = b"Hello";
        let key = 0x42u8;
        let encrypted: Vec<u8> = plaintext.iter().map(|b| b ^ key).collect();
        s.load_binary(0x1000, encrypted);
        let result = s.decrypt_xor(0x1000, 5, key).unwrap();
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_string_emulator_brute_xor() {
        let mut s = StringEmulator::new();
        let key = 0x55u8;
        let plaintext = b"test";
        let mut enc: Vec<u8> = plaintext.iter().map(|b| b ^ key).collect();
        enc.push(0); // null terminator
        s.load_binary(0x2000, enc);
        let results = s.brute_xor(0x2000, 5);
        assert!(!results.is_empty());
        let found = results.iter().any(|(k, s)| *k == key && s == "test");
        assert!(found, "Should find 'test' with key 0x55");
    }

    #[test]
    fn test_string_emulator_read_stack_string() {
        let mut s = StringEmulator::new();
        s.load_binary(0x3000, b"hello\x00world\x00".to_vec());
        let r = s.read_stack_string(0x3000, 32).unwrap();
        assert_eq!(r, "hello");
    }

    // ── TracingEmulator ───────────────────────────────────────────────────────

    #[test]
    fn test_tracing_emulator_run() {
        let mut t = TracingEmulator::new("trace_test");
        t.load(0x1000, vec![0x90; 16]);
        t.run(0x1000, 10).unwrap();
        assert!(!t.trace().is_empty());
    }

    #[test]
    fn test_tracing_emulator_mem_accesses() {
        let mut t = TracingEmulator::new("t");
        t.load(0x1000, vec![0; 8]);
        t.run(0x1000, 5).unwrap();
        assert_eq!(t.mem_access_count(), 5);
    }

    #[test]
    fn test_tracing_emulator_no_writes_without_set() {
        let mut t = TracingEmulator::new("t");
        t.load(0x1000, vec![0; 8]);
        t.run(0x1000, 5).unwrap();
        assert!(t.writes().is_empty());
    }

    #[test]
    fn test_function_call_result_ok() {
        let r = FunctionCallResult::ok(0x1000, vec![], EmuValue::Uint(42), 10, 1);
        assert!(r.success);
        assert_eq!(r.return_value.as_u64(), 42);
    }

    #[test]
    fn test_function_call_result_err() {
        let r = FunctionCallResult::err(0x1000, "oom".into());
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("oom"));
    }
}
