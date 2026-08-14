//! `rustre-arch`
//!
//! Architecture orchestration layer for the `RustRE` Suite.
//!
//! Re-exports the core [`Architecture`] trait and companion types from
//! `rustre-core`, and adds:
//!
//! * [`ArchRegistry`] —" thread-safe registry of pluggable arch backends.
//! * [`LinearDisassembler`] / [`RecursiveDisassembler`] —" sweep and
//!   branch-following disassembly algorithms.
//! * [`InstrStream`] —" lazy iterator over disassembled instructions.
//! * [`RegisterFile`] —" mutable snapshot of register state.
//! * [`InstrStats`] —" aggregated instruction-type counters.
//! * [`LiftContext`] —" shared context passed to IL-lifting passes.
//! * [`ArchMetadata`] —" extra metadata stored alongside an arch.
//! * [`DecodeError`], [`EncodeError`], [`LiftError`] —" typed errors.
//! * [`register_set`] —" per-architecture register descriptors and registry.
//! * [`calling_conv`] —" architecture-specific calling convention abstractions.

pub mod arch_features;
pub mod arch_meta;
pub mod arch_registry_full;
pub mod calling_conv;
pub mod calling_conventions;
pub mod instr_analysis;
pub mod instruction_semantics;
pub mod register_alias_map;
pub mod register_set;
pub mod arch_registry;
pub mod arch_feature_flags;
pub mod cross_arch_normalizer;
// NOTE: `sub_arch_registry` lives in the sibling crate `rustre-arch-registry`,
// not here. The wiring depends on every `rustre-arch-*` sub-crate, and
// each sub-crate already depends on this hub crate, so hosting the
// registry here would create a workspace path-dep cycle. `rustre-arch-registry`
// is the cycle-free aggregator and is the canonical entry point for
// installing all built-in architectures into `global_registry`.

pub use rustre_core::address::Address;
pub use rustre_core::arch::{
    ArchMode, Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
pub use rustre_core::endian::Endian;
pub use rustre_core::errors::CoreError;

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Error types
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors that can occur while decoding machine instructions.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// The byte sequence does not encode a valid instruction.
    #[error("invalid instruction bytes")]
    Invalid,
    /// Not enough bytes remain to decode a complete instruction.
    #[error("truncated instruction")]
    Truncated,
    /// Any other decode-time failure.
    #[error("other decode error: {0}")]
    Other(String),
}

/// Errors that can occur while encoding an instruction back to bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodeError {
    /// An operand value is out of range or otherwise invalid.
    #[error("invalid operand")]
    InvalidOperand,
    /// The requested instruction is not supported by this arch backend.
    #[error("unsupported instruction")]
    Unsupported,
    /// Any other encode-time failure.
    #[error("other encode error: {0}")]
    Other(String),
}

/// Errors that can occur while lifting machine code to an intermediate
/// representation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LiftError {
    /// The instruction has no lift implementation for this arch.
    #[error("unsupported instruction for lifting")]
    Unsupported,
    /// The `LiftContext` stack overflowed.
    #[error("lift stack overflow")]
    StackOverflow,
    /// Any other lift-time failure.
    #[error("other lift error: {0}")]
    Other(String),
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LiftContext
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Shared mutable context threaded through all IL-lifting passes.
///
/// Holds a lightweight temporary stack and a variable map that lifting passes
/// can use to communicate across instruction boundaries.
#[derive(Debug, Default, Clone)]
pub struct LiftContext {
    /// Depth counter, incremented on function entry and decremented on exit.
    pub depth: usize,
    /// Temporary variable pool indexed by name.
    pub temps: HashMap<String, u64>,
    /// Captured lift-time warnings (non-fatal anomalies).
    pub warnings: Vec<String>,
    /// Maximum stack depth seen so far.
    pub max_depth: usize,
}

impl LiftContext {
    /// Create an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push one frame on to the virtual call stack.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError::StackOverflow`] when `depth` exceeds 4096.
    pub const fn push(&mut self) -> Result<(), LiftError> {
        if self.depth >= 4096 {
            return Err(LiftError::StackOverflow);
        }
        self.depth += 1;
        if self.depth > self.max_depth {
            self.max_depth = self.depth;
        }
        Ok(())
    }

    /// Pop one frame from the virtual call stack.
    ///
    /// # Panics
    ///
    /// Does not panic —" silently clamps at zero.
    pub const fn pop(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Store a temporary value.
    pub fn set_temp(&mut self, name: impl Into<String>, value: u64) {
        self.temps.insert(name.into(), value);
    }

    /// Retrieve a temporary value, if present.
    #[must_use]
    pub fn get_temp(&self, name: &str) -> Option<u64> {
        self.temps.get(name).copied()
    }

    /// Record a non-fatal lift warning.
    ///
    /// At most 4096 warnings are retained to prevent unbounded memory growth
    /// when processing attacker-controlled instruction streams.
    pub fn warn(&mut self, msg: impl Into<String>) {
        const MAX_WARNINGS: usize = 4096;
        if self.warnings.len() < MAX_WARNINGS {
            self.warnings.push(msg.into());
        }
    }

    /// Return `true` if any warnings were emitted.
    #[must_use]
    pub const fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ArchMetadata
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Extra metadata stored alongside an [`Architecture`] in the [`ArchRegistry`].
#[derive(Debug, Clone)]
pub struct ArchMetadata {
    /// Human-readable description of the architecture.
    pub description: String,
    /// Typical minimum instruction size in bytes.
    pub min_instr_size: usize,
    /// Typical maximum instruction size in bytes.
    pub max_instr_size: usize,
    /// Whether the ISA supports variable-length instructions.
    pub variable_length: bool,
    /// Canonical NOP byte sequence for this architecture.
    pub nop_bytes: Vec<u8>,
}

impl ArchMetadata {
    /// Build metadata for a simple fixed-width RISC architecture.
    #[must_use]
    pub fn fixed_width(instr_size: usize, nop: &[u8], description: &str) -> Self {
        Self {
            description: description.to_string(),
            min_instr_size: instr_size,
            max_instr_size: instr_size,
            variable_length: false,
            nop_bytes: nop.to_vec(),
        }
    }

    /// Build metadata for a variable-length CISC architecture.
    #[must_use]
    pub fn variable_width(min: usize, max: usize, nop: &[u8], description: &str) -> Self {
        Self {
            description: description.to_string(),
            min_instr_size: min,
            max_instr_size: max,
            variable_length: true,
            nop_bytes: nop.to_vec(),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ArchRegistry
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

struct ArchEntry {
    arch: Arc<dyn Architecture>,
    meta: Option<ArchMetadata>,
}

/// Thread-safe registry of [`Architecture`] backends.
///
/// Wraps a `RwLock`-protected `Vec` so registrations and lookups can happen
/// concurrently from multiple threads.
#[derive(Default)]
pub struct ArchRegistry {
    entries: RwLock<Vec<ArchEntry>>,
}

impl fmt::Debug for ArchRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchRegistry")
            .field("count", &self.entries.read().len())
            .finish_non_exhaustive()
    }
}

impl ArchRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an arch backend (no metadata).
    pub fn register(&self, arch: Arc<dyn Architecture>) {
        self.entries.write().push(ArchEntry { arch, meta: None });
    }

    /// Register an arch backend together with [`ArchMetadata`].
    pub fn register_with_meta(&self, arch: Arc<dyn Architecture>, meta: ArchMetadata) {
        self.entries.write().push(ArchEntry {
            arch,
            meta: Some(meta),
        });
    }

    /// Look up a registered architecture by name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<Arc<dyn Architecture>> {
        self.entries
            .read()
            .iter()
            .find(|e| e.arch.name() == name)
            .map(|e| Arc::clone(&e.arch))
    }

    /// Return metadata for the named architecture, if available.
    #[must_use]
    pub fn metadata(&self, name: &str) -> Option<ArchMetadata> {
        self.entries
            .read()
            .iter()
            .find(|e| e.arch.name() == name)
            .and_then(|e| e.meta.clone())
    }

    /// Return the names of all registered architectures.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.entries
            .read()
            .iter()
            .map(|e| e.arch.name().to_owned())
            .collect()
    }

    /// Deregister an architecture by name. Returns `true` if it was present.
    pub fn remove(&self, name: &str) -> bool {
        let mut entries = self.entries.write();
        let before = entries.len();
        entries.retain(|e| e.arch.name() != name);
        entries.len() < before
    }

    /// Return the number of registered architectures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Return `true` if no architectures are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// InstrStats
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Aggregated statistics over a set of disassembled instructions.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InstrStats {
    /// Total number of instructions.
    pub total: usize,
    /// Instructions with the [`InstrFlags::BRANCH`] flag.
    pub branches: usize,
    /// Instructions with the [`InstrFlags::CALL`] flag.
    pub calls: usize,
    /// Instructions with the [`InstrFlags::RET`] flag.
    pub returns: usize,
    /// Instructions with the [`InstrFlags::CONDITIONAL`] flag.
    pub conditionals: usize,
    /// Instructions that access memory (read or write).
    pub memory_ops: usize,
}

impl InstrStats {
    /// Accumulate a single instruction into the counters.
    pub const fn feed(&mut self, instr: &Instruction) {
        self.total += 1;
        if instr.flags.contains(InstrFlags::BRANCH) {
            self.branches += 1;
        }
        if instr.flags.contains(InstrFlags::CALL) {
            self.calls += 1;
        }
        if instr.flags.contains(InstrFlags::RET) {
            self.returns += 1;
        }
        if instr.flags.contains(InstrFlags::CONDITIONAL) {
            self.conditionals += 1;
        }
        if instr.flags.contains(InstrFlags::READ_MEM) || instr.flags.contains(InstrFlags::WRITE_MEM)
        {
            self.memory_ops += 1;
        }
    }

    /// Compute statistics from a slice of instructions.
    #[must_use]
    pub fn from_slice(instrs: &[Instruction]) -> Self {
        let mut s = Self::default();
        for i in instrs {
            s.feed(i);
        }
        s
    }

    /// Return the fraction of instructions that are branches (0.0—"1.0).
    #[must_use]
    pub fn branch_density(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.branches).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.total).unwrap_or(u32::MAX))
        }
    }
}

impl fmt::Display for InstrStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InstrStats {{ total={}, branches={}, calls={}, returns={}, conditionals={}, memory_ops={} }}",
            self.total, self.branches, self.calls, self.returns, self.conditionals, self.memory_ops
        )
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// RegisterFile
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Mutable snapshot of architectural register state.
///
/// Stores up to 256 64-bit register values indexed by the register's [`RegisterInfo::id`].
#[derive(Debug, Default, Clone)]
pub struct RegisterFile {
    values: HashMap<u32, u64>,
    arch_name: String,
}

impl RegisterFile {
    /// Create an empty register file for the named architecture.
    #[must_use]
    pub fn new(arch_name: &str) -> Self {
        Self {
            values: HashMap::new(),
            arch_name: arch_name.to_owned(),
        }
    }

    /// Initialise all registers described by an [`Architecture`] to zero.
    #[must_use]
    pub fn zeroed(arch: &dyn Architecture) -> Self {
        let mut rf = Self::new(arch.name());
        for reg in arch.registers() {
            rf.values.insert(reg.id, 0);
        }
        rf
    }

    /// Write a register value.
    pub fn write(&mut self, id: u32, value: u64) {
        self.values.insert(id, value);
    }

    /// Read a register value, returning 0 for unknown registers.
    #[must_use]
    pub fn read(&self, id: u32) -> u64 {
        self.values.get(&id).copied().unwrap_or(0)
    }

    /// Return `true` if the given register ID has a recorded value.
    #[must_use]
    pub fn has(&self, id: u32) -> bool {
        self.values.contains_key(&id)
    }

    /// Reset all registers to zero.
    pub fn zero_all(&mut self) {
        for v in self.values.values_mut() {
            *v = 0;
        }
    }

    /// Return the architecture name this register file belongs to.
    #[must_use]
    pub fn arch_name(&self) -> &str {
        &self.arch_name
    }

    /// Number of registers tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Return `true` if no registers are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// InstrStream
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Collected result of a disassembly run.
#[derive(Debug, Clone)]
pub struct InstrStream {
    /// The decoded instructions in address order.
    pub instructions: Vec<Instruction>,
    /// Any addresses that could not be decoded (decode errors).
    pub errors: Vec<(Address, String)>,
}

impl InstrStream {
    /// Create an empty stream.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            instructions: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Return aggregate statistics over all decoded instructions.
    #[must_use]
    pub fn stats(&self) -> InstrStats {
        InstrStats::from_slice(&self.instructions)
    }

    /// Return `true` if no instructions were decoded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Total number of decoded instructions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }
}

impl Default for InstrStream {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LinearDisassembler
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Linear sweep disassembler: decodes every byte range in sequence, making no
/// assumptions about control flow.
pub struct LinearDisassembler {
    arch: Arc<dyn Architecture>,
    /// If `true`, stop at the first decode error; otherwise skip and continue.
    pub strict: bool,
}

impl fmt::Debug for LinearDisassembler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinearDisassembler")
            .field("arch", &self.arch.name())
            .field("strict", &self.strict)
            .finish_non_exhaustive()
    }
}

impl LinearDisassembler {
    /// Create a new linear disassembler backed by the given arch.
    #[must_use]
    pub fn new(arch: Arc<dyn Architecture>) -> Self {
        Self {
            arch,
            strict: false,
        }
    }

    /// Run linear disassembly over `bytes` starting at `base_address`.
    ///
    /// Returns an [`InstrStream`] containing all decoded instructions and any
    /// addresses that failed to decode.
    #[must_use]
    pub fn disassemble(&self, base_address: Address, bytes: &[u8]) -> InstrStream {
        let mut stream = InstrStream::new();
        let mut offset = 0usize;

        while offset < bytes.len() {
            let addr = Address::new(base_address.0.wrapping_add(offset as u64));
            match self.arch.disassemble(addr, &bytes[offset..]) {
                Ok(instr) => {
                    let step = instr.size.max(1);
                    stream.instructions.push(instr);
                    offset += step;
                }
                Err(e) => {
                    stream.errors.push((addr, e.to_string()));
                    if self.strict {
                        break;
                    }
                    offset += 1; // skip bad byte
                }
            }
        }

        stream
    }

    /// Disassemble exactly `count` instructions starting at `base_address`.
    ///
    /// Returns the [`InstrStream`] once `count` instructions have been decoded
    /// or the byte buffer is exhausted.
    #[must_use]
    pub fn disassemble_count(
        &self,
        base_address: Address,
        bytes: &[u8],
        count: usize,
    ) -> InstrStream {
        let mut stream = InstrStream::new();
        let mut offset = 0usize;

        while offset < bytes.len() && stream.len() < count {
            let addr = Address::new(base_address.0.wrapping_add(offset as u64));
            match self.arch.disassemble(addr, &bytes[offset..]) {
                Ok(instr) => {
                    let step = instr.size.max(1);
                    stream.instructions.push(instr);
                    offset += step;
                }
                Err(e) => {
                    stream.errors.push((addr, e.to_string()));
                    if self.strict {
                        break;
                    }
                    offset += 1;
                }
            }
        }

        stream
    }

    /// Return the underlying architecture name.
    #[must_use]
    pub fn arch_name(&self) -> &str {
        self.arch.name()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// RecursiveDisassembler
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Recursive-descent (branch-following) disassembler.
///
/// Starts from one or more entry points and follows unconditional and
/// conditional branches, deduplicating already-visited addresses.
pub struct RecursiveDisassembler {
    arch: Arc<dyn Architecture>,
    /// Maximum number of instructions to decode in one pass.
    pub max_instrs: usize,
}

impl fmt::Debug for RecursiveDisassembler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecursiveDisassembler")
            .field("arch", &self.arch.name())
            .field("max_instrs", &self.max_instrs)
            .finish_non_exhaustive()
    }
}

impl RecursiveDisassembler {
    /// Create a new recursive disassembler (limit = 100 000 instructions).
    #[must_use]
    pub fn new(arch: Arc<dyn Architecture>) -> Self {
        Self {
            arch,
            max_instrs: 100_000,
        }
    }

    /// Run recursive-descent disassembly over `bytes` from `entry`.
    ///
    /// `base` is the load address of the first byte in `bytes`.
    #[must_use]
    pub fn disassemble(&self, base: Address, bytes: &[u8], entry: Address) -> InstrStream {
        let mut stream = InstrStream::new();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut worklist: Vec<Address> = vec![entry];

        while let Some(addr) = worklist.pop() {
            if stream.len() >= self.max_instrs {
                break;
            }
            if visited.contains(&addr.0) {
                continue;
            }
            visited.insert(addr.0);

            // Bounds check: addr must fall inside [base, base + len).
            let rel = usize::try_from(addr.0.wrapping_sub(base.0)).unwrap_or(usize::MAX);
            if rel >= bytes.len() {
                stream
                    .errors
                    .push((addr, "address out of range".to_string()));
                continue;
            }

            match self.arch.disassemble(addr, &bytes[rel..]) {
                Ok(instr) => {
                    let is_return = instr.flags.contains(InstrFlags::RET);
                    let branches = self.arch.get_branches(&instr);

                    // Compute fall-through only for non-unconditional-branch instructions.
                    let fall_through_addr = Address::new(addr.0.wrapping_add(instr.size as u64));

                    let push_fall_through = !is_return
                        && !branches
                            .iter()
                            .any(|b| b.is_unconditional() && !b.kind.is_call());

                    stream.instructions.push(instr);

                    // Enqueue branch targets.
                    for b in branches {
                        if let Some(target_addr) = b.target
                            && !visited.contains(&target_addr)
                        {
                            worklist.push(Address::new(target_addr));
                        }
                    }

                    // Enqueue fall-through.
                    if push_fall_through
                        && !visited.contains(&fall_through_addr.0)
                        && fall_through_addr.0 >= base.0
                        && (fall_through_addr.0 - base.0) < bytes.len() as u64
                    {
                        worklist.push(fall_through_addr);
                    }
                }
                Err(e) => {
                    stream.errors.push((addr, e.to_string()));
                }
            }
        }

        // Sort instructions by address for reproducible output.
        stream.instructions.sort_unstable_by_key(|i| i.address.0);
        stream
    }

    /// Return the underlying architecture name.
    #[must_use]
    pub fn arch_name(&self) -> &str {
        self.arch.name()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// DisasmFilter
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A predicate applied to [`Instruction`]s to include/exclude them from an
/// [`InstrStream`].
#[derive(Debug, Clone, Default)]
pub struct DisasmFilter {
    /// If set, only include instructions containing this mnemonic substring.
    pub mnemonic_contains: Option<String>,
    /// If set, only include instructions with at least these flags set.
    pub required_flags: Option<InstrFlags>,
    /// If set, exclude instructions with any of these flags set.
    pub excluded_flags: Option<InstrFlags>,
}

impl DisasmFilter {
    /// Create a filter that accepts everything.
    #[must_use]
    pub fn accept_all() -> Self {
        Self::default()
    }

    /// Create a filter that only passes branch instructions.
    #[must_use]
    pub fn branches_only() -> Self {
        Self {
            required_flags: Some(InstrFlags::BRANCH),
            ..Default::default()
        }
    }

    /// Create a filter that only passes call instructions.
    #[must_use]
    pub fn calls_only() -> Self {
        Self {
            required_flags: Some(InstrFlags::CALL),
            ..Default::default()
        }
    }

    /// Return `true` if the instruction passes this filter.
    #[must_use]
    pub fn matches(&self, instr: &Instruction) -> bool {
        if let Some(ref sub) = self.mnemonic_contains
            && !instr.mnemonic.contains(sub.as_str())
        {
            return false;
        }
        if let Some(req) = self.required_flags
            && !instr.flags.contains(req)
        {
            return false;
        }
        if let Some(exc) = self.excluded_flags
            && instr.flags.intersects(exc)
        {
            return false;
        }
        true
    }

    /// Apply this filter to a stream, returning a new stream with only matching
    /// instructions.
    #[must_use]
    pub fn apply(&self, stream: &InstrStream) -> InstrStream {
        InstrStream {
            instructions: stream
                .instructions
                .iter()
                .filter(|i| self.matches(i))
                .cloned()
                .collect(),
            errors: stream.errors.clone(),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// DisasmCache
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Thread-safe, address-keyed cache for decoded instructions.
///
/// Useful when the same address range is disassembled multiple times (e.g.
/// during interactive analysis).
#[derive(Debug, Default)]
pub struct DisasmCache {
    inner: Mutex<HashMap<u64, Instruction>>,
}

impl DisasmCache {
    /// Create an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or overwrite an instruction.
    pub fn insert(&self, instr: Instruction) {
        self.inner.lock().insert(instr.address.0, instr);
    }

    /// Look up an instruction at `addr`.
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<Instruction> {
        self.inner.lock().get(&addr).cloned()
    }

    /// Return `true` if `addr` is present in the cache.
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        self.inner.lock().contains_key(&addr)
    }

    /// Invalidate all cached instructions.
    pub fn clear(&self) {
        self.inner.lock().clear();
    }

    /// Number of cached instructions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Return `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Global singleton registry (Â§4 central dispatcher)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Process-wide singleton `DashMap` keyed by architecture name.
///
/// Populated lazily on first access.  Individual arch crates may call
/// [`global_registry`] and insert their own [`Arc<dyn Architecture>`] at
/// static-init time.
static GLOBAL_REGISTRY: std::sync::LazyLock<DashMap<String, Arc<dyn Architecture>>> =
    std::sync::LazyLock::new(DashMap::new);

/// Return a reference to the process-wide global architecture registry.
///
/// The registry is backed by a [`dashmap::DashMap`] so concurrent read and
/// write access from multiple threads is safe without any additional locking.
///
/// # Example
/// ```ignore
/// let reg = global_registry();
/// if let Some(arch) = reg.get("x86_64") {
///     println!("found {}", arch.name());
/// }
/// ```
#[must_use]
pub fn global_registry() -> &'static DashMap<String, Arc<dyn Architecture>> {
    &GLOBAL_REGISTRY
}

/// Register all well-known builtin architecture names into the
/// [`global_registry`].
///
/// This function inserts *name-only placeholder entries* (represented by the
/// sentinel string `"<lazy>"` stored as a key).  Real implementations are
/// resolved when the corresponding `rustre-arch-*` crate is linked in and
/// calls [`global_registry().insert(...)`] itself.  After calling this
/// function, [`global_registry().contains_key(name)`] will return `true` for
/// every architecture name listed here, making it easy for loaders to check
/// whether a given ISA is theoretically supported before attempting to obtain a
/// concrete backend.
///
/// The following canonical names are pre-registered:
/// `"x86"`, `"x86_64"`, `"arm"`, `"arm64"`, `"mips"`, `"mips64"`,
/// `"ppc"`, `"ppc64"`, `"riscv32"`, `"riscv64"`, `"sparc"`, `"sparc64"`,
/// `"msp430"`, `"avr"`, `"6502"`, `"z80"`, `"68k"`, `"bpf"`, `"wasm"`,
/// `"jvm"`, `"cil"`, `"luajit"`, `"dex"`.
pub fn register_all_builtins() {
    let names: &[&str] = &[
        "x86", "x86_64", "arm", "arm64", "mips", "mips64", "ppc", "ppc64", "riscv32", "riscv64",
        "sparc", "sparc64", "msp430", "avr", "6502", "z80", "68k", "bpf", "wasm", "jvm", "cil",
        "luajit", "dex",
    ];
    // Only insert placeholder entries for names that have *not yet* been
    // populated by a concrete arch crate to avoid overwriting real backends.
    for name in names {
        GLOBAL_REGISTRY
            .entry((*name).to_owned())
            .or_insert_with(|| {
                // Sentinel: a stub arch that knows its name but cannot decode.
                Arc::new(PlaceholderArch {
                    name: (*name).to_owned(),
                })
            });
    }
}

// â"€â"€â"€ PlaceholderArch â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Internal sentinel used by [`register_all_builtins`] for not-yet-loaded arch
/// backends.  All methods return unsupported errors so callers can detect that
/// the real backend has not been linked in.
#[derive(Debug)]
struct PlaceholderArch {
    name: String,
}

impl Architecture for PlaceholderArch {
    fn name(&self) -> &str {
        &self.name
    }

    fn pointer_size(&self) -> usize {
        // Return a reasonable default; real value depends on the backend.
        8
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, _address: Address, _bytes: &[u8]) -> Result<Instruction, CoreError> {
        Err(CoreError::unsupported("PlaceholderArch: no backend linked"))
    }

    fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        vec![]
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![]
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Binary format / architecture detection
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Inspect the leading bytes of a binary image and return the canonical
/// architecture name (e.g. `"x86_64"`, `"arm"`) if a supported magic sequence
/// is recognised.
///
/// Detection priority:
/// 1. ELF (`\x7fELF` magic)
/// 2. PE  (`MZ` magic with optional `PE\0\0` search)
/// 3. Mach-O (four-byte magic: `0xFEEDFACE`, `0xFEEDFACF`, `0xCEFAEDFE`, `0xCFFAEDFE`)
///
/// Returns `None` when the format is not recognised or the machine field maps
/// to an unknown architecture.
#[must_use]
pub fn detect_arch_from_bytes(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    // ELF: \x7fELF
    if data.starts_with(b"\x7fELF") {
        return detect_from_elf(data);
    }
    // PE: MZ header
    if data.starts_with(b"MZ") {
        return detect_from_pe(data);
    }
    // Mach-O big-endian: FEEDFACE / FEEDFACF
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic == 0xFEED_FACE || magic == 0xFEED_FACF {
        return detect_from_macho(data);
    }
    // Mach-O little-endian: CEFAEDFE / CFFAEDFE
    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic_le == 0xFEED_FACE || magic_le == 0xFEED_FACF {
        return detect_from_macho(data);
    }
    None
}

/// Detect the architecture from an ELF header.
///
/// Reads `e_machine` from offset 18 (ELF32/ELF64 share the same offset for
/// `e_machine`).  Uses `EI_DATA` (offset 5) to determine endianness so the
/// field is always interpreted correctly.
///
/// Supported `e_machine` values:
///
/// | Value | Arch       |
/// |-------|------------|
/// |     3 | `x86`      |
/// |    62 | `x86_64`   |
/// |    40 | `arm`      |
/// |   183 | `arm64`    |
/// |     8 | `mips`     |
/// |    20 | `ppc`      |
/// |    21 | `ppc64`    |
/// |   243 | `riscv32` / `riscv64` (determined by ELF class) |
/// |     2 | `sparc`    |
/// |    18 | `sparc64`  |
/// |   220 | `msp430`   |
/// |    83 | `avr`      |
#[must_use]
pub fn detect_from_elf(data: &[u8]) -> Option<String> {
    // Minimum ELF header is 52 bytes (ELF32).
    if data.len() < 20 {
        return None;
    }
    // EI_CLASS: 1 = 32-bit, 2 = 64-bit
    let ei_class = data[4];
    // EI_DATA: 1 = LE, 2 = BE
    let ei_data = data[5];

    // e_machine is at byte offset 18 (2 bytes).
    let e_machine_raw = [data[18], data[19]];
    let e_machine: u16 = if ei_data == 2 {
        u16::from_be_bytes(e_machine_raw)
    } else {
        u16::from_le_bytes(e_machine_raw)
    };

    let arch = match e_machine {
        3 => "x86",
        62 => "x86_64",
        40 => "arm",
        183 => "arm64",
        8 => "mips",
        20 => "ppc",
        21 => "ppc64",
        243 => {
            // RISC-V: distinguish 32 vs 64 by ELF class.
            if ei_class == 2 { "riscv64" } else { "riscv32" }
        }
        2 => "sparc",
        18 => "sparc64",
        220 => "msp430",
        83 => "avr",
        _ => return None,
    };
    Some(arch.to_owned())
}

/// Detect the architecture from a PE (Portable Executable) header.
///
/// Reads the `Machine` field from the COFF header that follows the MZ stub.
/// The PE signature offset is stored at byte 0x3C of the MZ header as a
/// little-endian `u32`.
///
/// Supported `Machine` values:
///
/// | Value    | Arch     |
/// |----------|----------|
/// | `0x014c` | `x86`    |
/// | `0x8664` | `x86_64` |
/// | `0x01c0` | `arm`    |
/// | `0xaa64` | `arm64`  |
/// | `0x01f0` | `ppc`    |
/// | `0x0162` | `mips`   |
#[must_use]
pub fn detect_from_pe(data: &[u8]) -> Option<String> {
    if data.len() < 0x40 {
        return None;
    }
    // PE header offset is stored at 0x3C as LE u32.
    let pe_offset = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    // PE\0\0 signature (4 bytes) + COFF Machine field (2 bytes at offset +4).
    if pe_offset.saturating_add(6) > data.len() {
        return None;
    }
    // Verify "PE\0\0" signature.
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }
    let machine = u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);
    let arch = match machine {
        0x014c => "x86",
        0x8664 => "x86_64",
        0x01c0 => "arm",
        0xaa64 => "arm64",
        0x01f0 => "ppc",
        0x0162 => "mips",
        _ => return None,
    };
    Some(arch.to_owned())
}

/// Detect the architecture from a Mach-O header.
///
/// Handles both big-endian (`FEEDFACE`/`FEEDFACF`) and little-endian
/// (`CEFAEDFE`/`CFFAEDFE`) variants.  The `cputype` field is a 32-bit integer
/// at byte offset 4.
///
/// Supported `cputype` values:
///
/// | Value        | Arch     |
/// |-------------|----------|
/// | `7`          | `x86`    |
/// | `0x1000007`  | `x86_64` |
/// | `12`         | `arm`    |
/// | `0x100000c`  | `arm64`  |
/// | `18`         | `ppc`    |
/// | `0x1000012`  | `ppc64`  |
#[must_use]
pub fn detect_from_macho(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    // big-endian if magic is FEEDFACE/FEEDFACF; little-endian otherwise.
    let is_be = magic == 0xFEED_FACE || magic == 0xFEED_FACF;
    let cputype: u32 = if is_be {
        u32::from_be_bytes([data[4], data[5], data[6], data[7]])
    } else {
        u32::from_le_bytes([data[4], data[5], data[6], data[7]])
    };

    let arch = match cputype {
        7 => "x86",
        0x0100_0007 => "x86_64",
        12 => "arm",
        0x0100_000c => "arm64",
        18 => "ppc",
        0x0100_0012 => "ppc64",
        _ => return None,
    };
    Some(arch.to_owned())
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// DisassemblyResult
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// The result of a single disassembly pass.
///
/// Complements [`InstrStream`] with an explicit `total_bytes` counter so
/// callers know how far into a buffer the disassembler advanced.
#[derive(Debug, Clone, Default)]
pub struct DisassemblyResult {
    /// All successfully decoded instructions.
    pub instructions: Vec<Instruction>,
    /// Total number of bytes consumed by all decoded instructions.
    pub total_bytes: usize,
    /// Human-readable error messages for bytes that could not be decoded.
    pub errors: Vec<String>,
}

impl DisassemblyResult {
    /// Create an empty result.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return aggregate statistics over the decoded instructions.
    #[must_use]
    pub fn stats(&self) -> ExtendedInstrStats {
        ExtendedInstrStats::compute(&self.instructions)
    }

    /// Return the number of successfully decoded instructions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Return `true` if no instructions were decoded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

/// Perform a *linear sweep* disassembly of `data` starting at virtual address
/// `base`, decoding at most `max_instrs` instructions.
///
/// Every byte in `data` is processed in sequence: on a decode error the
/// offending bytes are skipped and the pass continues.  The result's
/// `total_bytes` reflects the total number of bytes consumed by successfully
/// decoded instructions (not the number of bytes scanned).
///
/// # Arguments
/// * `arch`        —" the architecture backend to use.
/// * `data`        —" raw binary bytes to disassemble.
/// * `base`        —" virtual load address of `data[0]`.
/// * `max_instrs`  —" maximum number of instructions to decode (0 = unlimited).
#[must_use]
pub fn disassemble_linear(
    arch: &dyn Architecture,
    data: &[u8],
    base: u64,
    max_instrs: usize,
) -> DisassemblyResult {
    let mut result = DisassemblyResult::new();
    let mut offset = 0usize;

    while offset < data.len() {
        if max_instrs > 0 && result.instructions.len() >= max_instrs {
            break;
        }
        let addr = Address::new(base.wrapping_add(offset as u64));
        match arch.disassemble(addr, &data[offset..]) {
            Ok(instr) => {
                let size = instr.size.max(1);
                result.total_bytes += size;
                result.instructions.push(instr);
                offset += size;
            }
            Err(e) => {
                result
                    .errors
                    .push(format!("{:#x}: {}", base.wrapping_add(offset as u64), e));
                offset += 1; // skip bad byte and continue
            }
        }
    }

    result
}

/// Perform a *recursive-descent* disassembly of `data`, starting from
/// `entry`.
///
/// Follows unconditional and conditional branch targets inside the buffer,
/// avoiding re-visiting already-decoded addresses.  Stops when there are no
/// more reachable addresses inside the buffer or a call limit is hit.
///
/// # Arguments
/// * `arch`   —" the architecture backend to use.
/// * `data`   —" raw binary bytes.
/// * `base`   —" virtual load address of `data[0]`.
/// * `entry`  —" virtual address of the first instruction to decode.
#[must_use]
pub fn disassemble_recursive(
    arch: &dyn Architecture,
    data: &[u8],
    base: u64,
    entry: u64,
) -> DisassemblyResult {
    const MAX_INSTRS: usize = 1_000_000;

    let mut result = DisassemblyResult::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut worklist: Vec<u64> = vec![entry];

    while let Some(addr) = worklist.pop() {
        if result.instructions.len() >= MAX_INSTRS {
            break;
        }
        if !visited.insert(addr) {
            continue; // already decoded
        }
        // bounds check
        let Some(rel) = addr.checked_sub(base).and_then(|r| usize::try_from(r).ok()) else {
            result
                .errors
                .push(format!("{addr:#x}: address below base {base:#x}"));
            continue;
        };
        if rel >= data.len() {
            result
                .errors
                .push(format!("{addr:#x}: address out of range"));
            continue;
        }

        match arch.disassemble(Address::new(addr), &data[rel..]) {
            Ok(instr) => {
                let size = instr.size.max(1);
                let is_ret = instr.flags.contains(InstrFlags::RET);
                let branches = arch.get_branches(&instr);
                let fall_through = addr.wrapping_add(size as u64);

                // Determine whether we should continue to fall-through address.
                let push_fall = !is_ret
                    && !branches
                        .iter()
                        .any(|b| b.is_unconditional() && !b.kind.is_call());

                result.total_bytes += size;
                result.instructions.push(instr);

                // Enqueue branch targets (only those inside the buffer).
                for b in branches {
                    if let Some(target) = b.target
                        && !visited.contains(&target)
                        && let Some(t_rel) = target
                            .checked_sub(base)
                            .and_then(|r| usize::try_from(r).ok())
                        && t_rel < data.len()
                    {
                        worklist.push(target);
                    }
                }

                // Enqueue fall-through.
                if push_fall
                    && !visited.contains(&fall_through)
                    && let Some(ft_rel) = fall_through
                        .checked_sub(base)
                        .and_then(|r| usize::try_from(r).ok())
                    && ft_rel < data.len()
                {
                    worklist.push(fall_through);
                }
            }
            Err(e) => {
                result.errors.push(format!("{addr:#x}: {e}"));
            }
        }
    }

    // Return instructions in address order.
    result.instructions.sort_unstable_by_key(|i| i.address.0);
    result
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ExtendedInstrStats  (replaces / supplements InstrStats)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Extended instruction-type statistics with f32 density helpers.
///
/// Unlike [`InstrStats`] (which uses `usize` counters), this struct uses `u32`
/// counters and provides `f32`-typed density methods to match the spec.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExtendedInstrStats {
    /// Total number of instructions.
    pub total: u32,
    /// Instructions with the [`InstrFlags::CALL`] flag.
    pub calls: u32,
    /// Instructions with the [`InstrFlags::BRANCH`] flag.
    pub branches: u32,
    /// Instructions with the [`InstrFlags::RET`] flag.
    pub returns: u32,
    /// Instructions with the [`InstrFlags::SYSCALL`] flag.
    pub syscalls: u32,
    /// Instructions with the [`InstrFlags::NOP`] flag.
    pub nops: u32,
    /// Instructions with the [`InstrFlags::READ_MEM`] flag.
    pub memory_reads: u32,
    /// Instructions with the [`InstrFlags::WRITE_MEM`] flag.
    pub memory_writes: u32,
    /// Instructions with the [`InstrFlags::PRIVILEGED`] flag.
    pub privileged: u32,
}

impl ExtendedInstrStats {
    /// Compute statistics from a slice of [`Instruction`]s.
    #[must_use]
    pub fn compute(instrs: &[Instruction]) -> Self {
        let mut s = Self::default();
        for i in instrs {
            s.total += 1;
            if i.flags.contains(InstrFlags::CALL) {
                s.calls += 1;
            }
            if i.flags.contains(InstrFlags::BRANCH) {
                s.branches += 1;
            }
            if i.flags.contains(InstrFlags::RET) {
                s.returns += 1;
            }
            if i.flags.contains(InstrFlags::SYSCALL) {
                s.syscalls += 1;
            }
            if i.flags.contains(InstrFlags::NOP) {
                s.nops += 1;
            }
            if i.flags.contains(InstrFlags::READ_MEM) {
                s.memory_reads += 1;
            }
            if i.flags.contains(InstrFlags::WRITE_MEM) {
                s.memory_writes += 1;
            }
            if i.flags.contains(InstrFlags::PRIVILEGED) {
                s.privileged += 1;
            }
        }
        s
    }

    /// Fraction of instructions that are calls: `calls / total` (0.0 if empty).
    #[must_use]
    pub fn call_density(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            f64::from(self.calls) / f64::from(self.total)
        }
    }

    /// Fraction of instructions that are branches: `branches / total` (0.0 if empty).
    #[must_use]
    pub fn branch_density(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            f64::from(self.branches) / f64::from(self.total)
        }
    }

    /// Fraction of instructions that are returns: `returns / total`.
    #[must_use]
    pub fn return_density(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            f64::from(self.returns) / f64::from(self.total)
        }
    }

    /// Fraction of instructions that are NOPs: `nops / total`.
    #[must_use]
    pub fn nop_density(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            f64::from(self.nops) / f64::from(self.total)
        }
    }

    /// Fraction of instructions that access memory (reads or writes).
    #[must_use]
    pub fn memory_density(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            // Sum directly as f64 to avoid both u32 overflow and precision-loss casts.
            // f64 can represent u32 values exactly (53-bit mantissa > 32 bits).
            let mem = f64::from(self.memory_reads) + f64::from(self.memory_writes);
            mem / f64::from(self.total)
        }
    }
}

impl fmt::Display for ExtendedInstrStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExtendedInstrStats {{ total={}, calls={}, branches={}, returns={}, \
             syscalls={}, nops={}, mem_reads={}, mem_writes={}, privileged={} }}",
            self.total,
            self.calls,
            self.branches,
            self.returns,
            self.syscalls,
            self.nops,
            self.memory_reads,
            self.memory_writes,
            self.privileged,
        )
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CallingConvention factory helpers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// The `calling_conventions` module is declared as an external file module
// at the top of this file (pub mod calling_conventions;).  The factory
// functions live in crates/rustre-arch/src/calling_conventions.rs.

// Inline module removed to avoid E0428 "defined multiple times".


// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ModeDetector
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Utilities for detecting the ARM execution mode (ARM / Thumb) at a given
/// address.
///
/// ARM ELF binaries use the Thumb-bit convention: a function whose symbol value
/// has bit 0 set is a Thumb function.  The actual code starts at the even
/// address (value & !1), but the symbol table stores the odd address so linkers
/// know to switch to Thumb mode.
pub struct ModeDetector;

impl ModeDetector {
    /// Determine the ARM execution mode active at `addr`.
    ///
    /// Rules (in priority order):
    ///
    /// 1. If `symbol_table` contains an entry whose value equals `addr | 1`
    ///    (i.e. an odd-addressed Thumb symbol whose code address is `addr`),
    ///    return [`ArchMode::Thumb`].
    /// 2. If `addr & 1 == 1`, return [`ArchMode::Thumb`] (the address itself
    ///    is a raw Thumb function pointer).
    /// 3. If `symbol_table` contains an entry whose value equals `addr` with
    ///    an even address, return [`ArchMode::Default`] (ARM mode).
    /// 4. Otherwise return [`ArchMode::Default`].
    ///
    /// # Arguments
    /// * `binary`       —" raw binary bytes (not used in the current heuristic,
    ///   reserved for future prologue-byte inspection).
    /// * `addr`         —" the virtual address to classify.
    /// * `symbol_table` —" slice of `(symbol_value, symbol_name)` pairs as
    ///   found in the ELF `.symtab` / `.dynsym` sections.
    #[must_use]
    pub fn detect_arm_mode(_binary: &[u8], addr: u64, symbol_table: &[(u64, String)]) -> ArchMode {
        // Rule 1: look for a Thumb symbol whose code address matches `addr`.
        // In ELF symbol tables, Thumb functions are stored with value = addr | 1.
        for (sym_value, _sym_name) in symbol_table {
            let is_thumb_sym = sym_value & 1 == 1;
            let code_addr = sym_value & !1u64;
            if is_thumb_sym && code_addr == addr {
                return ArchMode::Thumb;
            }
        }

        // Rule 2: raw Thumb pointer (lowest bit set in the address itself).
        if addr & 1 == 1 {
            return ArchMode::Thumb;
        }

        // Rule 3 / Rule 4: even address â†' ARM mode (default).
        ArchMode::Default
    }

    /// Return `true` if `addr` is a Thumb function address according to the
    /// symbol table or the Thumb-bit convention.
    #[must_use]
    pub fn is_thumb(addr: u64, symbol_table: &[(u64, String)]) -> bool {
        Self::detect_arm_mode(&[], addr, symbol_table) == ArchMode::Thumb
    }

    /// Strip the Thumb bit from an address, returning the actual code address.
    ///
    /// `thumb_ptr & !1`
    #[must_use]
    pub const fn code_addr(thumb_ptr: u64) -> u64 {
        thumb_ptr & !1u64
    }

    /// Return the canonical Thumb symbol value for a code address (sets bit 0).
    #[must_use]
    pub const fn thumb_symbol_value(code_addr: u64) -> u64 {
        code_addr | 1
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ArchRegistryExt —" convenience extension methods on ArchRegistry
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl ArchRegistry {
    /// Attempt to detect the architecture from binary `data` and look it up in
    /// this registry.
    ///
    /// Returns the matching [`Arc<dyn Architecture>`] if both detection and
    /// registry lookup succeed.
    #[must_use]
    pub fn find_for_binary(&self, data: &[u8]) -> Option<Arc<dyn Architecture>> {
        let name = detect_arch_from_bytes(data)?;
        self.find(&name)
    }

    /// Register an architecture into both this registry *and* the
    /// [`global_registry`] singleton.
    ///
    /// Useful for arch crates that want to be available globally without
    /// requiring callers to pass a registry around.
    pub fn register_global(&self, arch: Arc<dyn Architecture>) {
        let name = arch.name().to_owned();
        self.register(Arc::clone(&arch));
        global_registry().insert(name, arch);
    }

    /// Iterate over all registered architectures and collect their names.
    ///
    /// Equivalent to [`ArchRegistry::names`] but uses an iterator form
    /// compatible with method chaining.
    #[must_use]
    pub fn iter_names(&self) -> Vec<String> {
        self.names()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    // â"€â"€ Minimal stub arch for testing â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[derive(Debug)]
    struct StubArch {
        name: &'static str,
    }

    impl Architecture for StubArch {
        fn name(&self) -> &str {
            self.name
        }

        fn pointer_size(&self) -> usize {
            8
        }

        fn endian(&self) -> Endian {
            Endian::Little
        }

        /// Decodes a single 1-byte NOP or returns a decode error on `0xFF`.
        fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
            if bytes.is_empty() {
                return Err(CoreError::InvalidFormat {
                    message: "empty".into(),
                });
            }
            let byte = bytes[0];
            if byte == 0xFF {
                return Err(CoreError::InvalidFormat {
                    message: "bad byte".into(),
                });
            }
            let flags = match byte {
                0xE8 => InstrFlags::CALL,
                0xC3 => InstrFlags::RET,
                0xEB => InstrFlags::BRANCH,
                0x74 => InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                0x8B => InstrFlags::READ_MEM,
                _ => InstrFlags::NONE,
            };
            let mut i = Instruction::new(address, 1, format!("op_{byte:02x}"), vec![byte]);
            i.flags = flags;
            Ok(i)
        }

        fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
            use rustre_core::arch::{BranchCondition, BranchKind};
            if instr.flags.contains(InstrFlags::CALL) {
                vec![BranchInfo {
                    target: Some(instr.address.0.wrapping_add(0x20)),
                    kind: BranchKind::Call,
                    condition: BranchCondition::Always,
                }]
            } else if instr.flags.contains(InstrFlags::BRANCH) {
                // For testing: branch target is always address + 0x10.
                let kind = if instr.flags.contains(InstrFlags::CONDITIONAL) {
                    BranchKind::ConditionalJump
                } else {
                    BranchKind::UnconditionalJump
                };
                let condition = if instr.flags.contains(InstrFlags::CONDITIONAL) {
                    BranchCondition::Equal
                } else {
                    BranchCondition::Always
                };
                vec![BranchInfo {
                    target: Some(instr.address.0.wrapping_add(0x10)),
                    kind,
                    condition,
                }]
            } else {
                vec![]
            }
        }

        fn registers(&self) -> Vec<RegisterInfo> {
            use rustre_core::arch::RegisterKind;
            vec![
                RegisterInfo::new("r0", 0, 8, RegisterKind::General),
                RegisterInfo::new("r1", 1, 8, RegisterKind::General),
                RegisterInfo::new("r2", 2, 8, RegisterKind::General),
            ]
        }

        fn calling_conventions(&self) -> Vec<CallingConvention> {
            vec![
                CallingConvention::new("stub_cc")
                    .with_int_args(vec!["r0".into(), "r1".into()])
                    .with_return_regs(vec!["r0".into()]),
            ]
        }
    }

    fn stub_arch() -> Arc<StubArch> {
        Arc::new(StubArch { name: "stub" })
    }

    fn make_instr(addr: u64, flags: InstrFlags) -> Instruction {
        let mut i = Instruction::new(Address::new(addr), 1, "test", vec![0x00]);
        i.flags = flags;
        i
    }

    // â"€â"€ DecodeError â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_error_display_invalid() {
        assert_eq!(
            DecodeError::Invalid.to_string(),
            "invalid instruction bytes"
        );
    }

    #[test]
    fn test_decode_error_display_truncated() {
        assert_eq!(DecodeError::Truncated.to_string(), "truncated instruction");
    }

    #[test]
    fn test_decode_error_display_other() {
        let e = DecodeError::Other("oops".into());
        assert!(e.to_string().contains("oops"));
    }

    // â"€â"€ EncodeError â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_encode_error_variants() {
        assert!(
            EncodeError::InvalidOperand
                .to_string()
                .contains("invalid operand")
        );
        assert!(EncodeError::Unsupported.to_string().contains("unsupported"));
        assert!(EncodeError::Other("x".into()).to_string().contains('x'));
    }

    // â"€â"€ LiftError â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_error_variants() {
        assert!(LiftError::Unsupported.to_string().contains("unsupported"));
        assert!(LiftError::StackOverflow.to_string().contains("overflow"));
        assert!(LiftError::Other("y".into()).to_string().contains('y'));
    }

    // â"€â"€ LiftContext â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_context_push_pop() {
        let mut ctx = LiftContext::new();
        ctx.push().unwrap();
        ctx.push().unwrap();
        assert_eq!(ctx.depth, 2);
        assert_eq!(ctx.max_depth, 2);
        ctx.pop();
        assert_eq!(ctx.depth, 1);
        ctx.pop();
        ctx.pop(); // clamped at 0
        assert_eq!(ctx.depth, 0);
    }

    #[test]
    fn test_lift_context_temps() {
        let mut ctx = LiftContext::new();
        ctx.set_temp("t0", 42);
        assert_eq!(ctx.get_temp("t0"), Some(42));
        assert_eq!(ctx.get_temp("t1"), None);
    }

    #[test]
    fn test_lift_context_warnings() {
        let mut ctx = LiftContext::new();
        assert!(!ctx.has_warnings());
        ctx.warn("something odd");
        assert!(ctx.has_warnings());
        assert_eq!(ctx.warnings.len(), 1);
    }

    #[test]
    fn test_lift_context_stack_overflow() {
        let mut ctx = LiftContext::new();
        for _ in 0..4096 {
            ctx.push().unwrap();
        }
        assert!(ctx.push().is_err());
    }

    // â"€â"€ ArchMetadata â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_arch_metadata_fixed() {
        let m = ArchMetadata::fixed_width(4, &[0x00, 0x00, 0x00, 0x00], "Test RISC");
        assert_eq!(m.min_instr_size, 4);
        assert_eq!(m.max_instr_size, 4);
        assert!(!m.variable_length);
    }

    #[test]
    fn test_arch_metadata_variable() {
        let m = ArchMetadata::variable_width(1, 15, &[0x90], "Test CISC");
        assert_eq!(m.min_instr_size, 1);
        assert_eq!(m.max_instr_size, 15);
        assert!(m.variable_length);
        assert_eq!(m.nop_bytes, vec![0x90]);
    }

    // â"€â"€ ArchRegistry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_registry_register_and_find() {
        let reg = ArchRegistry::new();
        assert!(reg.is_empty());
        reg.register(stub_arch());
        assert!(!reg.is_empty());
        assert_eq!(reg.len(), 1);
        assert!(reg.find("stub").is_some());
        assert!(reg.find("nonexistent").is_none());
    }

    #[test]
    fn test_registry_names() {
        let reg = ArchRegistry::new();
        reg.register(stub_arch());
        let names = reg.names();
        assert!(names.contains(&"stub".to_string()));
    }

    #[test]
    fn test_registry_remove() {
        let reg = ArchRegistry::new();
        reg.register(stub_arch());
        assert!(reg.remove("stub"));
        assert!(!reg.remove("stub")); // already gone
        assert!(reg.is_empty());
    }

    #[test]
    fn test_registry_with_meta() {
        let reg = ArchRegistry::new();
        let meta = ArchMetadata::fixed_width(4, &[0x00], "Stub RISC");
        reg.register_with_meta(stub_arch(), meta);
        let m = reg.metadata("stub").unwrap();
        assert_eq!(m.min_instr_size, 4);
        assert!(reg.metadata("unknown").is_none());
    }

    #[test]
    fn test_registry_debug() {
        let reg = ArchRegistry::new();
        reg.register(stub_arch());
        let s = format!("{reg:?}");
        assert!(s.contains("ArchRegistry"));
    }

    // â"€â"€ InstrStats â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_instr_stats_feed() {
        let mut stats = InstrStats::default();
        stats.feed(&make_instr(0, InstrFlags::BRANCH | InstrFlags::CONDITIONAL));
        stats.feed(&make_instr(1, InstrFlags::CALL));
        stats.feed(&make_instr(2, InstrFlags::RET));
        stats.feed(&make_instr(3, InstrFlags::READ_MEM));
        assert_eq!(stats.total, 4);
        assert_eq!(stats.branches, 1);
        assert_eq!(stats.calls, 1);
        assert_eq!(stats.returns, 1);
        assert_eq!(stats.conditionals, 1);
        assert_eq!(stats.memory_ops, 1);
    }

    #[test]
    fn test_instr_stats_branch_density() {
        let instrs = vec![
            make_instr(0, InstrFlags::BRANCH),
            make_instr(1, InstrFlags::NONE),
            make_instr(2, InstrFlags::NONE),
            make_instr(3, InstrFlags::NONE),
        ];
        let stats = InstrStats::from_slice(&instrs);
        assert!((stats.branch_density() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn test_instr_stats_empty() {
        let stats = InstrStats::default();
        assert!(stats.branch_density().abs() < f64::EPSILON);
    }

    #[test]
    fn test_instr_stats_display() {
        let s = InstrStats::from_slice(&[make_instr(0, InstrFlags::CALL)]).to_string();
        assert!(s.contains("calls=1"));
    }

    // â"€â"€ RegisterFile â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_register_file_read_write() {
        let mut rf = RegisterFile::new("test");
        rf.write(0, 0xDEAD_BEEF);
        assert_eq!(rf.read(0), 0xDEAD_BEEF);
        assert_eq!(rf.read(99), 0); // unknown â†' 0
    }

    #[test]
    fn test_register_file_zeroed() {
        let arch = StubArch { name: "stub" };
        let rf = RegisterFile::zeroed(&arch);
        assert_eq!(rf.len(), 3);
        for reg in arch.registers() {
            assert_eq!(rf.read(reg.id), 0);
        }
    }

    #[test]
    fn test_register_file_has() {
        let mut rf = RegisterFile::new("test");
        rf.write(5, 100);
        assert!(rf.has(5));
        assert!(!rf.has(6));
    }

    #[test]
    fn test_register_file_zero_all() {
        let mut rf = RegisterFile::new("test");
        rf.write(0, 100);
        rf.write(1, 200);
        rf.zero_all();
        assert_eq!(rf.read(0), 0);
        assert_eq!(rf.read(1), 0);
    }

    #[test]
    fn test_register_file_arch_name() {
        let rf = RegisterFile::new("arm64");
        assert_eq!(rf.arch_name(), "arm64");
    }

    // â"€â"€ LinearDisassembler â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_linear_disasm_nops() {
        let dasm = LinearDisassembler::new(stub_arch());
        let bytes = vec![0x00u8; 8];
        let stream = dasm.disassemble(Address::new(0x1000), &bytes);
        assert_eq!(stream.len(), 8);
        assert!(stream.errors.is_empty());
    }

    #[test]
    fn test_linear_disasm_with_error_bytes() {
        let dasm = LinearDisassembler::new(stub_arch());
        // 0xFF causes a decode error in our stub.
        let bytes = vec![0x00, 0xFF, 0x00];
        let stream = dasm.disassemble(Address::new(0), &bytes);
        assert_eq!(stream.len(), 2); // 0x00, skip 0xFF, 0x00
        assert_eq!(stream.errors.len(), 1);
    }

    #[test]
    fn test_linear_disasm_strict_stops_on_error() {
        let mut dasm = LinearDisassembler::new(stub_arch());
        dasm.strict = true;
        let bytes = vec![0x00, 0xFF, 0x00];
        let stream = dasm.disassemble(Address::new(0), &bytes);
        assert_eq!(stream.len(), 1);
    }

    #[test]
    fn test_linear_disasm_count() {
        let dasm = LinearDisassembler::new(stub_arch());
        let bytes = vec![0x00u8; 100];
        let stream = dasm.disassemble_count(Address::new(0), &bytes, 10);
        assert_eq!(stream.len(), 10);
    }

    #[test]
    fn test_linear_disasm_arch_name() {
        let dasm = LinearDisassembler::new(stub_arch());
        assert_eq!(dasm.arch_name(), "stub");
    }

    // â"€â"€ RecursiveDisassembler â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_recursive_disasm_basic() {
        let dasm = RecursiveDisassembler::new(stub_arch());
        // 8 NOP bytes; no branches —" should decode linearly from entry.
        let bytes = vec![0x00u8; 8];
        let stream = dasm.disassemble(Address::new(0), &bytes, Address::new(0));
        assert!(!stream.is_empty());
    }

    #[test]
    fn test_recursive_disasm_out_of_range_entry() {
        let dasm = RecursiveDisassembler::new(stub_arch());
        let bytes = vec![0x00u8; 4];
        // Entry at 0x1000, but bytes start at 0 —" entry is out of range.
        let stream = dasm.disassemble(Address::new(0), &bytes, Address::new(0x1000));
        assert!(stream.is_empty());
        assert_eq!(stream.errors.len(), 1);
    }

    #[test]
    fn test_recursive_disasm_arch_name() {
        let dasm = RecursiveDisassembler::new(stub_arch());
        assert_eq!(dasm.arch_name(), "stub");
    }

    // â"€â"€ DisasmFilter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_disasm_filter_accept_all() {
        let filter = DisasmFilter::accept_all();
        let instr = make_instr(0, InstrFlags::NONE);
        assert!(filter.matches(&instr));
    }

    #[test]
    fn test_disasm_filter_branches_only() {
        let filter = DisasmFilter::branches_only();
        assert!(filter.matches(&make_instr(0, InstrFlags::BRANCH)));
        assert!(!filter.matches(&make_instr(0, InstrFlags::NONE)));
    }

    #[test]
    fn test_disasm_filter_calls_only() {
        let filter = DisasmFilter::calls_only();
        assert!(filter.matches(&make_instr(0, InstrFlags::CALL)));
        assert!(!filter.matches(&make_instr(0, InstrFlags::BRANCH)));
    }

    #[test]
    fn test_disasm_filter_mnemonic() {
        let filter = DisasmFilter {
            mnemonic_contains: Some("nop".into()),
            ..Default::default()
        };
        let mut instr = make_instr(0, InstrFlags::NONE);
        instr.mnemonic = "nop".into();
        assert!(filter.matches(&instr));
        instr.mnemonic = "add".into();
        assert!(!filter.matches(&instr));
    }

    #[test]
    fn test_disasm_filter_apply() {
        let dasm = LinearDisassembler::new(stub_arch());
        // Mix of NOP (0x00) and branch (0xEB) bytes.
        let bytes = vec![0x00, 0xEB, 0x00, 0xEB, 0x00];
        let stream = dasm.disassemble(Address::new(0), &bytes);
        let filter = DisasmFilter::branches_only();
        let filtered = filter.apply(&stream);
        assert_eq!(filtered.len(), 2);
    }

    // â"€â"€ DisasmCache â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_disasm_cache_insert_and_get() {
        let cache = DisasmCache::new();
        let instr = make_instr(0x1000, InstrFlags::NONE);
        cache.insert(instr);
        let got = cache.get(0x1000).unwrap();
        assert_eq!(got.address.0, 0x1000);
    }

    #[test]
    fn test_disasm_cache_contains() {
        let cache = DisasmCache::new();
        cache.insert(make_instr(0xABCD, InstrFlags::NONE));
        assert!(cache.contains(0xABCD));
        assert!(!cache.contains(0x0000));
    }

    #[test]
    fn test_disasm_cache_clear() {
        let cache = DisasmCache::new();
        cache.insert(make_instr(1, InstrFlags::NONE));
        cache.insert(make_instr(2, InstrFlags::NONE));
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
    }

    // â"€â"€ detect_from_elf â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_elf_header(e_machine_le: u16, ei_class: u8) -> Vec<u8> {
        // Minimal 20-byte ELF header stub (enough for our parser).
        let mut h = vec![0u8; 20];
        h[0] = 0x7f;
        h[1] = b'E';
        h[2] = b'L';
        h[3] = b'F';
        h[4] = ei_class; // EI_CLASS
        h[5] = 1; // EI_DATA = LE
        // e_machine at offset 18 (LE u16).
        let m = e_machine_le.to_le_bytes();
        h[18] = m[0];
        h[19] = m[1];
        h
    }

    #[test]
    fn test_detect_elf_x86() {
        let data = make_elf_header(3, 1);
        assert_eq!(detect_from_elf(&data), Some("x86".to_string()));
    }

    #[test]
    fn test_detect_elf_x86_64() {
        let data = make_elf_header(62, 2);
        assert_eq!(detect_from_elf(&data), Some("x86_64".to_string()));
    }

    #[test]
    fn test_detect_elf_arm() {
        let data = make_elf_header(40, 1);
        assert_eq!(detect_from_elf(&data), Some("arm".to_string()));
    }

    #[test]
    fn test_detect_elf_arm64() {
        let data = make_elf_header(183, 2);
        assert_eq!(detect_from_elf(&data), Some("arm64".to_string()));
    }

    #[test]
    fn test_detect_elf_mips() {
        let data = make_elf_header(8, 1);
        assert_eq!(detect_from_elf(&data), Some("mips".to_string()));
    }

    #[test]
    fn test_detect_elf_riscv32() {
        let data = make_elf_header(243, 1 /* EI_CLASS=1 = 32-bit */);
        assert_eq!(detect_from_elf(&data), Some("riscv32".to_string()));
    }

    #[test]
    fn test_detect_elf_riscv64() {
        let data = make_elf_header(243, 2 /* EI_CLASS=2 = 64-bit */);
        assert_eq!(detect_from_elf(&data), Some("riscv64".to_string()));
    }

    #[test]
    fn test_detect_elf_unknown() {
        let data = make_elf_header(0xFFFF, 2);
        assert_eq!(detect_from_elf(&data), None);
    }

    #[test]
    fn test_detect_elf_too_short() {
        assert_eq!(detect_from_elf(&[0x7f, b'E', b'L', b'F']), None);
    }

    // â"€â"€ detect_from_pe â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_pe_header(machine_le: u16) -> Vec<u8> {
        let mut data = vec![0u8; 0x100];
        data[0] = b'M';
        data[1] = b'Z';
        // PE header offset at 0x3c = 0x40 (64).
        let pe_off: u32 = 0x40;
        let pe_off_bytes = pe_off.to_le_bytes();
        data[0x3c] = pe_off_bytes[0];
        data[0x3d] = pe_off_bytes[1];
        data[0x3e] = pe_off_bytes[2];
        data[0x3f] = pe_off_bytes[3];
        // Write PE\0\0 signature at offset 0x40.
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;
        // Machine field at offset 0x44 (PE+4).
        let m = machine_le.to_le_bytes();
        data[0x44] = m[0];
        data[0x45] = m[1];
        data
    }

    #[test]
    fn test_detect_pe_x86() {
        let data = make_pe_header(0x014c);
        assert_eq!(detect_from_pe(&data), Some("x86".to_string()));
    }

    #[test]
    fn test_detect_pe_x86_64() {
        let data = make_pe_header(0x8664);
        assert_eq!(detect_from_pe(&data), Some("x86_64".to_string()));
    }

    #[test]
    fn test_detect_pe_arm() {
        let data = make_pe_header(0x01c0);
        assert_eq!(detect_from_pe(&data), Some("arm".to_string()));
    }

    #[test]
    fn test_detect_pe_arm64() {
        let data = make_pe_header(0xaa64);
        assert_eq!(detect_from_pe(&data), Some("arm64".to_string()));
    }

    #[test]
    fn test_detect_pe_unknown_machine() {
        let data = make_pe_header(0x1234);
        assert_eq!(detect_from_pe(&data), None);
    }

    #[test]
    fn test_detect_pe_too_short() {
        assert_eq!(detect_from_pe(b"MZ"), None);
    }

    // â"€â"€ detect_from_macho â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_macho_le(cputype: u32) -> Vec<u8> {
        // Little-endian Mach-O 64-bit: magic FEEDFACF as LE = CF FA ED FE.
        let magic: u32 = 0xFEED_FACF;
        let mut data = vec![0u8; 8];
        let mb = magic.to_le_bytes();
        data[..4].copy_from_slice(&mb);
        let cb = cputype.to_le_bytes();
        data[4..8].copy_from_slice(&cb);
        data
    }

    #[test]
    fn test_detect_macho_x86() {
        let data = make_macho_le(7);
        assert_eq!(detect_from_macho(&data), Some("x86".to_string()));
    }

    #[test]
    fn test_detect_macho_x86_64() {
        let data = make_macho_le(0x0100_0007);
        assert_eq!(detect_from_macho(&data), Some("x86_64".to_string()));
    }

    #[test]
    fn test_detect_macho_arm() {
        let data = make_macho_le(12);
        assert_eq!(detect_from_macho(&data), Some("arm".to_string()));
    }

    #[test]
    fn test_detect_macho_arm64() {
        let data = make_macho_le(0x0100_000c);
        assert_eq!(detect_from_macho(&data), Some("arm64".to_string()));
    }

    #[test]
    fn test_detect_macho_unknown() {
        let data = make_macho_le(0xDEAD_BEEF);
        assert_eq!(detect_from_macho(&data), None);
    }

    // â"€â"€ detect_arch_from_bytes â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_detect_arch_dispatch_elf() {
        let data = make_elf_header(62, 2);
        assert_eq!(detect_arch_from_bytes(&data), Some("x86_64".to_string()));
    }

    #[test]
    fn test_detect_arch_dispatch_pe() {
        let data = make_pe_header(0xaa64);
        assert_eq!(detect_arch_from_bytes(&data), Some("arm64".to_string()));
    }

    #[test]
    fn test_detect_arch_dispatch_unknown() {
        // Random bytes that don't match any magic.
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0u8, 0u8, 0u8, 0u8];
        assert_eq!(detect_arch_from_bytes(&data), None);
    }

    #[test]
    fn test_detect_arch_too_short() {
        assert_eq!(detect_arch_from_bytes(&[0x7f, b'E', b'L']), None);
    }

    // â"€â"€ DisassemblyResult / disassemble_linear â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_disassemble_linear_basic() {
        let arch = stub_arch();
        let data = vec![0x00u8; 8];
        let result = disassemble_linear(arch.as_ref(), &data, 0x1000, 0);
        assert_eq!(result.len(), 8);
        assert_eq!(result.total_bytes, 8);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_disassemble_linear_max_instrs() {
        let arch = stub_arch();
        let data = vec![0x00u8; 100];
        let result = disassemble_linear(arch.as_ref(), &data, 0, 5);
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_disassemble_linear_skips_bad_bytes() {
        let arch = stub_arch();
        // 0xFF triggers decode error in StubArch.
        let data = vec![0x00, 0xFF, 0x00];
        let result = disassemble_linear(arch.as_ref(), &data, 0, 0);
        assert_eq!(result.len(), 2);
        assert_eq!(result.errors.len(), 1);
    }

    // â"€â"€ disassemble_recursive â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_disassemble_recursive_basic() {
        let arch = stub_arch();
        let data = vec![0x00u8; 8];
        let result = disassemble_recursive(arch.as_ref(), &data, 0x0, 0x0);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_disassemble_recursive_out_of_range() {
        let arch = stub_arch();
        let data = vec![0x00u8; 4];
        // entry is beyond the buffer
        let result = disassemble_recursive(arch.as_ref(), &data, 0x0, 0x1000);
        assert!(result.is_empty());
        assert_eq!(result.errors.len(), 1);
    }

    // â"€â"€ ExtendedInstrStats â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_ext_instr(flags: InstrFlags) -> Instruction {
        let mut i = Instruction::new(Address::new(0), 1, "test", vec![0x00]);
        i.flags = flags;
        i
    }

    #[test]
    fn test_extended_stats_compute() {
        let instrs = vec![
            make_ext_instr(InstrFlags::CALL),
            make_ext_instr(InstrFlags::BRANCH),
            make_ext_instr(InstrFlags::RET),
            make_ext_instr(InstrFlags::SYSCALL),
            make_ext_instr(InstrFlags::NOP),
            make_ext_instr(InstrFlags::READ_MEM),
            make_ext_instr(InstrFlags::WRITE_MEM),
            make_ext_instr(InstrFlags::PRIVILEGED),
            make_ext_instr(InstrFlags::NONE),
            make_ext_instr(InstrFlags::NONE),
        ];
        let s = ExtendedInstrStats::compute(&instrs);
        assert_eq!(s.total, 10);
        assert_eq!(s.calls, 1);
        assert_eq!(s.branches, 1);
        assert_eq!(s.returns, 1);
        assert_eq!(s.syscalls, 1);
        assert_eq!(s.nops, 1);
        assert_eq!(s.memory_reads, 1);
        assert_eq!(s.memory_writes, 1);
        assert_eq!(s.privileged, 1);
    }

    #[test]
    fn test_extended_stats_call_density() {
        let instrs = vec![
            make_ext_instr(InstrFlags::CALL),
            make_ext_instr(InstrFlags::NONE),
            make_ext_instr(InstrFlags::NONE),
            make_ext_instr(InstrFlags::NONE),
        ];
        let s = ExtendedInstrStats::compute(&instrs);
        assert!((s.call_density() - 0.25).abs() < 1e-5);
        assert!((s.branch_density() - 0.0).abs() < 1e-5);
    }

    #[test]
    fn test_extended_stats_empty() {
        let s = ExtendedInstrStats::default();
        assert!(s.call_density().abs() < f64::EPSILON);
        assert!(s.branch_density().abs() < f64::EPSILON);
        assert!(s.return_density().abs() < f64::EPSILON);
        assert!(s.nop_density().abs() < f64::EPSILON);
        assert!(s.memory_density().abs() < f64::EPSILON);
    }

    #[test]
    fn test_extended_stats_display() {
        let s = ExtendedInstrStats {
            total: 5,
            calls: 2,
            ..Default::default()
        };
        let text = s.to_string();
        assert!(text.contains("total=5"));
        assert!(text.contains("calls=2"));
    }

    // â"€â"€ CallingConvention factories â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_cc_sysv_amd64() {
        let cc = calling_conventions::sysv_amd64();
        assert_eq!(cc.name, "sysv_amd64");
        assert_eq!(cc.int_arg_regs.len(), 6);
        assert_eq!(cc.int_arg_regs[0], "rdi");
        assert_eq!(cc.float_arg_regs.len(), 8);
        assert_eq!(format!("{}", cc.int_return), "pair:rax:rdx");
        assert!(cc.callee_saved.contains(&"rbx".to_string()));
        assert!(cc.callee_saved.contains(&"r15".to_string()));
    }

    #[test]
    fn test_cc_ms_x64() {
        let cc = calling_conventions::win64();
        assert_eq!(cc.name, "win64");
        assert_eq!(cc.int_arg_regs, vec!["rcx", "rdx", "r8", "r9"]);
        assert_eq!(format!("{}", cc.int_return), "reg:rax");
        assert_eq!(cc.shadow_space, 32);
    }

    #[test]
    fn test_cc_aapcs64() {
        let cc = calling_conventions::aapcs64();
        assert_eq!(cc.name, "aapcs64");
        assert_eq!(cc.int_arg_regs.len(), 8);
        assert_eq!(cc.int_arg_regs[0], "x0");
        assert_eq!(cc.int_arg_regs[7], "x7");
        assert_eq!(format!("{}", cc.int_return), "pair:x0:x1");
        assert!(cc.callee_saved.contains(&"x19".to_string()));
        assert!(cc.callee_saved.contains(&"x30".to_string()));
    }

    #[test]
    fn test_cc_aapcs32() {
        let cc = calling_conventions::aapcs32();
        assert_eq!(cc.int_arg_regs[0], "r0");
        assert_eq!(cc.int_arg_regs.len(), 4);
    }

    #[test]
    fn test_cc_cdecl() {
        let cc = calling_conventions::cdecl();
        assert!(cc.int_arg_regs.is_empty()); // stack-based
        assert!(cc.callee_saved.contains(&"ebx".to_string()));
    }

    // â"€â"€ ModeDetector â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_mode_detector_thumb_bit_in_address() {
        // Address with bit 0 set â†' Thumb.
        let mode = ModeDetector::detect_arm_mode(&[], 0x1001, &[]);
        assert_eq!(mode, ArchMode::Thumb);
    }

    #[test]
    fn test_mode_detector_arm_even_address() {
        // Even address, no symbol table â†' ARM (Default).
        let mode = ModeDetector::detect_arm_mode(&[], 0x1000, &[]);
        assert_eq!(mode, ArchMode::Default);
    }

    #[test]
    fn test_mode_detector_thumb_from_symtab() {
        // Symbol table has entry (0x1001, "foo") â†' code at 0x1000 is Thumb.
        let symtab = vec![(0x1001u64, "foo".to_string())];
        let mode = ModeDetector::detect_arm_mode(&[], 0x1000, &symtab);
        assert_eq!(mode, ArchMode::Thumb);
    }

    #[test]
    fn test_mode_detector_arm_from_symtab() {
        // Symbol table has even-addressed entry â†' ARM mode.
        let symtab = vec![(0x2000u64, "bar".to_string())];
        let mode = ModeDetector::detect_arm_mode(&[], 0x2000, &symtab);
        assert_eq!(mode, ArchMode::Default);
    }

    #[test]
    fn test_mode_detector_is_thumb() {
        let symtab = vec![(0x3001u64, "thumb_fn".to_string())];
        assert!(ModeDetector::is_thumb(0x3000, &symtab));
        assert!(!ModeDetector::is_thumb(0x4000, &symtab));
    }

    #[test]
    fn test_mode_detector_code_addr() {
        assert_eq!(ModeDetector::code_addr(0x1001), 0x1000);
        assert_eq!(ModeDetector::code_addr(0x1000), 0x1000);
    }

    #[test]
    fn test_mode_detector_thumb_symbol_value() {
        assert_eq!(ModeDetector::thumb_symbol_value(0x1000), 0x1001);
    }

    // â"€â"€ global_registry / register_all_builtins â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_register_all_builtins_populates_registry() {
        register_all_builtins();
        let reg = global_registry();
        assert!(reg.contains_key("x86"));
        assert!(reg.contains_key("x86_64"));
        assert!(reg.contains_key("arm"));
        assert!(reg.contains_key("arm64"));
        assert!(reg.contains_key("mips"));
        assert!(reg.contains_key("riscv32"));
        assert!(reg.contains_key("riscv64"));
    }

    #[test]
    fn test_global_registry_is_static() {
        // Calling global_registry() twice must return the same instance.
        let r1 = std::ptr::from_ref(global_registry());
        let r2 = std::ptr::from_ref(global_registry());
        assert_eq!(r1, r2);
    }

    // â"€â"€ ArchRegistryExt â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_arch_registry_ext_find_for_binary() {
        // Register stub as "x86_64" so detect_arch_from_bytes â†' find works.
        #[derive(Debug)]
        struct X86_64Stub;
        impl Architecture for X86_64Stub {
            fn name(&self) -> &'static str {
                "x86_64"
            }
            fn pointer_size(&self) -> usize {
                8
            }
            fn endian(&self) -> Endian {
                Endian::Little
            }
            fn disassemble(&self, a: Address, b: &[u8]) -> Result<Instruction, CoreError> {
                if b.is_empty() {
                    return Err(CoreError::InvalidFormat {
                        message: "empty".into(),
                    });
                }
                Ok(Instruction::new(a, 1, "nop", vec![b[0]]))
            }
            fn get_branches(&self, _: &Instruction) -> Vec<BranchInfo> {
                vec![]
            }
            fn registers(&self) -> Vec<RegisterInfo> {
                vec![]
            }
            fn calling_conventions(&self) -> Vec<CallingConvention> {
                vec![]
            }
        }
        let reg = ArchRegistry::new();
        reg.register(Arc::new(X86_64Stub));
        // Make an ELF x86_64 header.
        let data = make_elf_header(62, 2);
        let found = reg.find_for_binary(&data);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name(), "x86_64");
    }

    #[test]
    fn test_arch_registry_ext_find_for_binary_not_found() {
        let reg = ArchRegistry::new();
        let data = make_elf_header(62, 2); // x86_64 ELF but nothing registered
        assert!(reg.find_for_binary(&data).is_none());
    }
}
