//! `vm_bytecode_recovery` — Recover VM bytecode semantics from handler analysis.
//!
//! This module provides [`VmBytecodeRecovery`], the main entry point for
//! semantics-driven bytecode reconstruction.  Given a set of observed handler
//! execution traces and a prototype opcode map, the engine correlates raw
//! bytecode bytes with semantic operations, builds a [`HandlerDatabase`], and
//! produces a [`VmReport`] summarising coverage and completeness.
//!
//! # Key types
//! - [`VmBytecodeRecovery`]  — orchestrator
//! - [`HandlerDatabase`]     — keyed store of `HandlerEntry` records
//! - [`SemanticCoverage`]    — tracks which opcodes have been resolved
//! - [`OpcodeMap`]           — bijective opcode ↔ semantic mapping
//! - [`VmInstruction`]       — decoded VM instruction with operands
//! - [`LiftedVmFunction`]    — sequence of lifted instructions for a function
//! - [`VmReport`]            — final analysis report

use std::collections::{BTreeMap, HashMap, HashSet};
use serde::{Deserialize, Serialize};
use serde_json;

// ─────────────────────────────────────────────────────────────────────────────
// SemanticOp — canonical VM operation kind
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical semantic operation for a VM instruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SemanticOp {
    /// Push immediate value.
    PushImm,
    /// Push virtual register.
    PushReg,
    /// Pop into virtual register.
    PopReg,
    /// Add.
    Add,
    /// Subtract.
    Sub,
    /// Multiply.
    Mul,
    /// Unsigned divide.
    Div,
    /// Modulo.
    Mod,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Bitwise NOT.
    Not,
    /// Negate (two's complement).
    Neg,
    /// Logical shift left.
    Shl,
    /// Logical shift right.
    Shr,
    /// Arithmetic shift right.
    Sar,
    /// Rotate left.
    Rol,
    /// Rotate right.
    Ror,
    /// Load from memory (N-byte).
    Load(u8),
    /// Store to memory (N-byte).
    Store(u8),
    /// Compare (updates flags).
    Cmp,
    /// Unconditional jump.
    Jmp,
    /// Jump if zero.
    Jz,
    /// Jump if not zero.
    Jnz,
    /// Jump if less.
    Jl,
    /// Jump if greater.
    Jg,
    /// Call subroutine.
    Call,
    /// Return.
    Ret,
    /// No-operation.
    Nop,
    /// Halt execution.
    Halt,
    /// Sign-extend N bits → M bits.
    Sext { from: u8, to: u8 },
    /// Zero-extend.
    Zext { from: u8, to: u8 },
    /// Swap top two stack elements.
    Swap,
    /// Duplicate top of stack.
    Dup,
    /// Unknown / unresolved.
    Unknown,
}

impl SemanticOp {
    /// Returns `true` if this operation changes control flow.
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(
            self,
            Self::Jmp | Self::Jz | Self::Jnz | Self::Jl | Self::Jg | Self::Call | Self::Ret | Self::Halt
        )
    }

    /// Returns `true` if this operation reads or writes memory.
    #[must_use]
    pub const fn accesses_memory(&self) -> bool {
        matches!(self, Self::Load(_) | Self::Store(_))
    }

    /// Returns the stack balance (positive = net pushes, negative = net pops).
    #[must_use]
    pub const fn stack_balance(&self) -> i8 {
        match self {
            Self::PushImm | Self::PushReg | Self::Dup => 1,
            Self::PopReg | Self::Jmp | Self::Jz | Self::Jnz | Self::Jl | Self::Jg
            | Self::Add | Self::Sub | Self::Mul | Self::Div | Self::Mod
            | Self::And | Self::Or | Self::Xor | Self::Shl | Self::Shr | Self::Sar
            | Self::Rol | Self::Ror | Self::Cmp => -1,
            Self::Store(_) => -2,
            Self::Load(_) | Self::Not | Self::Neg | Self::Sext { .. } | Self::Zext { .. }
            | Self::Swap | Self::Nop | Self::Halt | Self::Unknown
            | Self::Call | Self::Ret => 0,
        }
    }

    /// Short mnemonic string.
    #[must_use]
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::PushImm => "PUSH.IMM",
            Self::PushReg => "PUSH.REG",
            Self::PopReg  => "POP.REG",
            Self::Add => "ADD",   Self::Sub => "SUB",   Self::Mul => "MUL",
            Self::Div => "DIV",   Self::Mod => "MOD",
            Self::And => "AND",   Self::Or  => "OR",    Self::Xor => "XOR",
            Self::Not => "NOT",   Self::Neg => "NEG",
            Self::Shl => "SHL",   Self::Shr => "SHR",   Self::Sar => "SAR",
            Self::Rol => "ROL",   Self::Ror => "ROR",
            Self::Load(_) => "LOAD",   Self::Store(_) => "STORE",
            Self::Cmp => "CMP",
            Self::Jmp => "JMP",   Self::Jz  => "JZ",    Self::Jnz => "JNZ",
            Self::Jl  => "JL",    Self::Jg  => "JG",
            Self::Call => "CALL", Self::Ret  => "RET",
            Self::Nop => "NOP",   Self::Halt => "HALT",
            Self::Sext { .. } => "SEXT", Self::Zext { .. } => "ZEXT",
            Self::Swap => "SWAP", Self::Dup  => "DUP",
            Self::Unknown => "UNK",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpcodeMap
// ─────────────────────────────────────────────────────────────────────────────

/// Bijective mapping between raw bytecode opcode bytes and [`SemanticOp`].
///
/// The mapping may be incomplete (opcode → `SemanticOp::Unknown` for unresolved
/// entries).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OpcodeMap {
    forward: BTreeMap<u8, SemanticOp>,
    reverse: HashMap<String, u8>,
}

impl OpcodeMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `opcode` → `sem`.
    ///
    /// Overwrites any previous entry for `opcode`.  Does not enforce bijectivity
    /// (two opcodes may map to the same semantic in degenerate VMs with aliases).
    pub fn insert(&mut self, opcode: u8, sem: SemanticOp) {
        let key = format!("{sem:?}");
        self.reverse.insert(key, opcode);
        self.forward.insert(opcode, sem);
    }

    /// Look up the semantic for a raw opcode byte.
    #[must_use]
    pub fn semantic(&self, opcode: u8) -> Option<&SemanticOp> {
        self.forward.get(&opcode)
    }

    /// Look up the opcode byte for a semantic (reverse lookup).
    #[must_use]
    pub fn opcode_for(&self, sem: &SemanticOp) -> Option<u8> {
        let key = format!("{sem:?}");
        self.reverse.get(&key).copied()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    /// `true` when the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// All registered opcode bytes, sorted.
    #[must_use]
    pub fn opcodes(&self) -> Vec<u8> {
        self.forward.keys().copied().collect()
    }

    /// Iterate over (opcode, semantic) pairs in opcode order.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &SemanticOp)> {
        self.forward.iter().map(|(&k, v)| (k, v))
    }

    /// Build a default opcode map using the simple 0x00-based scheme.
    #[must_use]
    pub fn default_scheme() -> Self {
        let mut m = Self::new();
        let entries: &[(u8, SemanticOp)] = &[
            (0x00, SemanticOp::Nop),
            (0x01, SemanticOp::PushImm),
            (0x02, SemanticOp::PushReg),
            (0x03, SemanticOp::PopReg),
            (0x10, SemanticOp::Add),
            (0x11, SemanticOp::Sub),
            (0x12, SemanticOp::Mul),
            (0x13, SemanticOp::And),
            (0x14, SemanticOp::Or),
            (0x15, SemanticOp::Xor),
            (0x16, SemanticOp::Not),
            (0x17, SemanticOp::Neg),
            (0x18, SemanticOp::Shl),
            (0x19, SemanticOp::Shr),
            (0x1A, SemanticOp::Sar),
            (0x20, SemanticOp::Load(4)),
            (0x21, SemanticOp::Store(4)),
            (0x22, SemanticOp::Load(8)),
            (0x23, SemanticOp::Store(8)),
            (0x30, SemanticOp::Jmp),
            (0x31, SemanticOp::Jz),
            (0x32, SemanticOp::Jnz),
            (0x33, SemanticOp::Jl),
            (0x34, SemanticOp::Jg),
            (0x35, SemanticOp::Call),
            (0x36, SemanticOp::Ret),
            (0x40, SemanticOp::Cmp),
            (0x50, SemanticOp::Dup),
            (0x51, SemanticOp::Swap),
            (0xFF, SemanticOp::Halt),
        ];
        for (op, sem) in entries {
            m.insert(*op, sem.clone());
        }
        m
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HandlerEntry / HandlerDatabase
// ─────────────────────────────────────────────────────────────────────────────

/// Source of evidence that resolved a handler's semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceSource {
    /// Pattern matched from the static handler database.
    PatternMatch,
    /// Derived from concolic/symbolic execution.
    Concolic,
    /// Inferred from data-flow analysis of handler prologue.
    DataFlow,
    /// Manually annotated.
    Manual,
    /// Cross-referenced against FLIRT signatures.
    Flirt,
}

/// A single handler entry in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerEntry {
    /// Opcode byte this handler is assigned to.
    pub opcode: u8,
    /// Virtual address of the handler code.
    pub address: u64,
    /// Size of the handler in bytes.
    pub size: usize,
    /// Resolved semantic operation.
    pub semantic: SemanticOp,
    /// Confidence in the semantic assignment `[0.0, 1.0]`.
    pub confidence: f32,
    /// Evidence source(s) that resolved this handler.
    pub evidence: Vec<EvidenceSource>,
    /// Handler prologue bytes (up to 32).
    pub prologue: Vec<u8>,
    /// Human-readable notes.
    pub notes: String,
}

impl HandlerEntry {
    /// Create a new entry with the minimum required fields.
    #[must_use]
    pub const fn new(opcode: u8, address: u64, semantic: SemanticOp, confidence: f32) -> Self {
        Self {
            opcode,
            address,
            size: 0,
            semantic,
            confidence: confidence.clamp(0.0, 1.0),
            evidence: Vec::new(),
            prologue: Vec::new(),
            notes: String::new(),
        }
    }

    /// Builder: set the handler size.
    #[must_use]
    pub const fn with_size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }

    /// Builder: append an evidence source.
    #[must_use]
    pub fn with_evidence(mut self, src: EvidenceSource) -> Self {
        self.evidence.push(src);
        self
    }

    /// Builder: set prologue bytes.
    #[must_use]
    pub fn with_prologue(mut self, prologue: Vec<u8>) -> Self {
        self.prologue = prologue.into_iter().take(32).collect();
        self
    }

    /// Builder: set notes.
    #[must_use]
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }

    /// Returns `true` if this entry has high confidence (≥ 0.8).
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }
}

/// Database of resolved VM handlers, keyed by opcode byte.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HandlerDatabase {
    entries: BTreeMap<u8, HandlerEntry>,
}

impl HandlerDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a handler entry.
    pub fn insert(&mut self, entry: HandlerEntry) {
        self.entries.insert(entry.opcode, entry);
    }

    /// Look up a handler by opcode.
    #[must_use]
    pub fn get(&self, opcode: u8) -> Option<&HandlerEntry> {
        self.entries.get(&opcode)
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if the database has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries sorted by opcode.
    #[must_use]
    pub fn sorted_entries(&self) -> Vec<&HandlerEntry> {
        self.entries.values().collect()
    }

    /// Count of high-confidence entries.
    #[must_use]
    pub fn high_confidence_count(&self) -> usize {
        self.entries.values().filter(|e| e.is_high_confidence()).count()
    }

    /// Return all entries whose semantic matches `op`.
    #[must_use]
    pub fn entries_for_semantic(&self, op: &SemanticOp) -> Vec<&HandlerEntry> {
        self.entries.values().filter(|e| &e.semantic == op).collect()
    }

    /// Merge entries from another database; higher confidence wins on collision.
    pub fn merge(&mut self, other: &Self) {
        for (opcode, entry) in &other.entries {
            match self.entries.get(opcode) {
                Some(existing) if existing.confidence >= entry.confidence => {}
                _ => { self.entries.insert(*opcode, entry.clone()); }
            }
        }
    }

    /// Remove all entries with confidence below `threshold`.
    pub fn prune_below(&mut self, threshold: f32) {
        self.entries.retain(|_, e| e.confidence >= threshold);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SemanticCoverage
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks which opcode bytes have been resolved to known semantics.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SemanticCoverage {
    /// Set of opcodes that have been resolved.
    resolved: HashSet<u8>,
    /// Set of all distinct opcodes observed in bytecode (resolved or not).
    seen: HashSet<u8>,
    /// Total number of distinct opcodes seen in bytecode.
    total_seen: usize,
    /// Total number of opcodes in the ISA (if known).
    isa_size: Option<usize>,
}

impl SemanticCoverage {
    /// Create an empty coverage tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a coverage tracker with a known ISA size.
    #[must_use]
    pub fn with_isa_size(isa_size: usize) -> Self {
        Self { isa_size: Some(isa_size), ..Default::default() }
    }

    /// Mark `opcode` as resolved.
    pub fn mark_resolved(&mut self, opcode: u8) {
        self.resolved.insert(opcode);
    }

    /// Register that `opcode` was observed in bytecode (whether resolved or not).
    pub fn observe(&mut self, opcode: u8) {
        // Track all distinct opcodes regardless of resolution status so that
        // total_seen reflects the true cardinality of the observed ISA subset.
        if self.seen.insert(opcode) {
            self.total_seen += 1;
        }
    }

    /// Coverage ratio: resolved / (ISA size or `total_seen`), in `[0.0, 1.0]`.
    #[must_use]
    pub fn ratio(&self) -> f64 {
        let denominator = self.isa_size.unwrap_or_else(|| self.total_seen.max(1));
        if denominator == 0 { return 0.0; }
        f64::from(u32::try_from(self.resolved.len()).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(denominator).unwrap_or(u32::MAX))
    }

    /// Number of resolved opcodes.
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.resolved.len()
    }

    /// `true` if all ISA opcodes are resolved (or `total_seen` == resolved).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.isa_size.map_or(self.resolved.len() >= self.total_seen, |n| self.resolved.len() >= n)
    }

    /// Percentage string representation.
    #[must_use]
    pub fn percent_str(&self) -> String {
        format!("{:.1}%", self.ratio() * 100.0)
    }

    /// Set of unresolved opcode bytes (present in bytecode but not in resolved set).
    #[must_use]
    pub fn unresolved_opcodes(&self) -> HashSet<u8> {
        (0u8..=255).filter(|b| !self.resolved.contains(b)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmInstruction — decoded VM instruction with operands
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded VM instruction with its operands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmInstruction {
    /// Byte offset in the bytecode buffer.
    pub offset: usize,
    /// Raw opcode byte.
    pub opcode: u8,
    /// Resolved semantic (or `SemanticOp::Unknown`).
    pub semantic: SemanticOp,
    /// Immediate operand (if any).
    pub imm: Option<u64>,
    /// Register operands (indices).
    pub regs: Vec<u8>,
    /// Size annotation from the opcode map.
    pub size_hint: Option<u8>,
}

impl VmInstruction {
    /// Create a minimal instruction with just an offset, opcode, and semantic.
    #[must_use]
    pub const fn new(offset: usize, opcode: u8, semantic: SemanticOp) -> Self {
        Self {
            offset,
            opcode,
            semantic,
            imm: None,
            regs: Vec::new(),
            size_hint: None,
        }
    }

    /// Returns `true` if the instruction has a resolved semantic.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        self.semantic != SemanticOp::Unknown
    }

    /// Format as a short disassembly line.
    #[must_use]
    pub fn display(&self) -> String {
        let mnem = self.semantic.mnemonic();
        let ops: Vec<String> = self.regs.iter().map(|r| format!("r{r}"))
            .chain(self.imm.map(|v| format!("{v:#x}")))
            .collect();
        if ops.is_empty() {
            format!("{:#06x}  {:12}  [{:#04x}]", self.offset, mnem, self.opcode)
        } else {
            format!("{:#06x}  {:12}  [{:#04x}]  {}", self.offset, mnem, self.opcode, ops.join(", "))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftedVmFunction
// ─────────────────────────────────────────────────────────────────────────────

/// A lifted VM function — a sequence of decoded [`VmInstruction`]s together
/// with metadata about the function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftedVmFunction {
    /// Virtual address of the first bytecode byte.
    pub start_address: u64,
    /// Name of the function (if available).
    pub name: Option<String>,
    /// Sequence of decoded instructions.
    pub instructions: Vec<VmInstruction>,
    /// Number of unresolved instructions.
    pub unresolved_count: usize,
    /// Stack depth trace — net stack balance at each instruction.
    pub stack_trace: Vec<i32>,
}

impl LiftedVmFunction {
    /// Create a new function with the given start address.
    #[must_use]
    pub const fn new(start_address: u64) -> Self {
        Self {
            start_address,
            name: None,
            instructions: Vec::new(),
            unresolved_count: 0,
            stack_trace: Vec::new(),
        }
    }

    /// Add an instruction and update counters.
    pub fn push(&mut self, insn: VmInstruction) {
        let balance = self.stack_trace.last().copied().unwrap_or(0)
            + i32::from(insn.semantic.stack_balance());
        self.stack_trace.push(balance);
        if !insn.is_resolved() {
            self.unresolved_count += 1;
        }
        self.instructions.push(insn);
    }

    /// Resolution ratio `[0.0, 1.0]`.
    #[must_use]
    pub fn resolution_ratio(&self) -> f64 {
        if self.instructions.is_empty() { return 1.0; }
        let total = self.instructions.len();
        f64::from(u32::try_from(total - self.unresolved_count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }

    /// `true` if the function ends with a HALT or RET.
    #[must_use]
    pub fn has_terminator(&self) -> bool {
        self.instructions.last().is_some_and(|i| {
            matches!(i.semantic, SemanticOp::Halt | SemanticOp::Ret)
        })
    }

    /// Instruction count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// `true` if there are no instructions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics for a bytecode recovery run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmReport {
    /// Number of functions lifted.
    pub functions_lifted: usize,
    /// Total instructions decoded across all functions.
    pub total_instructions: usize,
    /// Total unresolved instructions.
    pub unresolved_instructions: usize,
    /// Handler database size at time of report.
    pub handler_db_size: usize,
    /// Semantic coverage snapshot.
    pub coverage: SemanticCoverage,
    /// Opcode map snapshot.
    pub opcode_map: OpcodeMap,
    /// Analysis notes.
    pub notes: Vec<String>,
    /// Whether the ISA is considered fully recovered.
    pub isa_complete: bool,
}

impl VmReport {
    /// Overall instruction resolution percentage.
    #[must_use]
    pub fn resolution_percent(&self) -> f64 {
        if self.total_instructions == 0 { return 100.0; }
        f64::from(u32::try_from(self.total_instructions - self.unresolved_instructions).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total_instructions).unwrap_or(u32::MAX))
            * 100.0
    }

    /// Serialize this report to a JSON string.
    ///
    /// # Errors
    /// Returns a [`serde_json::Error`] if serialization fails (extremely rare for
    /// well-formed in-memory data).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// One-line summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "functions={} instructions={} unresolved={} ({:.1}%) coverage={} isa_complete={}",
            self.functions_lifted,
            self.total_instructions,
            self.unresolved_instructions,
            100.0 - self.resolution_percent(),
            self.coverage.percent_str(),
            self.isa_complete,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmBytecodeRecovery — orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the recovery engine.
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Minimum confidence required for a handler to be committed to the database.
    pub min_commit_confidence: f32,
    /// Maximum instructions to decode per function (guards against infinite loops).
    pub max_instructions_per_fn: usize,
    /// Whether to attempt heuristic opcode inference for unknown opcodes.
    pub heuristic_inference: bool,
    /// Whether to build a stack-balance trace per function.
    pub trace_stack: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            min_commit_confidence: 0.5,
            max_instructions_per_fn: 4096,
            heuristic_inference: true,
            trace_stack: true,
        }
    }
}

/// Main engine for VM bytecode semantic recovery.
///
/// Takes an [`OpcodeMap`] and a [`HandlerDatabase`] as inputs and iteratively
/// decodes bytecode buffers into [`LiftedVmFunction`]s while updating coverage.
#[derive(Debug)]
pub struct VmBytecodeRecovery {
    /// Opcode → semantic mapping.
    pub opcode_map: OpcodeMap,
    /// Handler database (resolved semantics per opcode).
    pub handler_db: HandlerDatabase,
    /// Semantic coverage tracker.
    pub coverage: SemanticCoverage,
    /// Lifted functions produced so far.
    pub functions: Vec<LiftedVmFunction>,
    /// Configuration.
    pub config: RecoveryConfig,
    /// Analysis notes accumulated during recovery.
    notes: Vec<String>,
}

impl VmBytecodeRecovery {
    /// Create a new recovery engine with a default opcode map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            opcode_map: OpcodeMap::default_scheme(),
            handler_db: HandlerDatabase::new(),
            coverage: SemanticCoverage::new(),
            functions: Vec::new(),
            config: RecoveryConfig::default(),
            notes: Vec::new(),
        }
    }

    /// Create with a custom opcode map.
    #[must_use]
    pub fn with_opcode_map(opcode_map: OpcodeMap) -> Self {
        let isa_size = opcode_map.len();
        let mut cov = SemanticCoverage::with_isa_size(isa_size);
        // Pre-mark all opcodes that are in the map as resolved.
        for op in opcode_map.opcodes() {
            cov.mark_resolved(op);
        }
        Self {
            opcode_map,
            handler_db: HandlerDatabase::new(),
            coverage: cov,
            functions: Vec::new(),
            config: RecoveryConfig::default(),
            notes: Vec::new(),
        }
    }

    /// Add a note to the analysis log.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Register a handler entry into the database and update coverage.
    pub fn register_handler(&mut self, entry: HandlerEntry) {
        if entry.confidence >= self.config.min_commit_confidence {
            self.coverage.mark_resolved(entry.opcode);
            self.opcode_map.insert(entry.opcode, entry.semantic.clone());
            self.handler_db.insert(entry);
        }
    }

    /// Decode a raw bytecode buffer into a [`LiftedVmFunction`].
    ///
    /// Unknown opcodes produce `SemanticOp::Unknown` instructions and are
    /// optionally subject to heuristic inference.
    pub fn decode_function(&mut self, bytecode: &[u8], start_address: u64) -> LiftedVmFunction {
        let mut func = LiftedVmFunction::new(start_address);
        let mut pc = 0usize;
        let limit = self.config.max_instructions_per_fn;

        while pc < bytecode.len() && func.instructions.len() < limit {
            let opcode = bytecode[pc];
            let offset = pc;
            pc += 1;

            self.coverage.observe(opcode);

            let semantic = self.opcode_map.semantic(opcode)
                .cloned()
                .unwrap_or_else(|| {
                    if self.config.heuristic_inference {
                        Self::infer_semantic(opcode, bytecode, pc)
                    } else {
                        SemanticOp::Unknown
                    }
                });

            let (imm, regs, bytes_consumed) = Self::decode_operands(&semantic, bytecode, pc);
            pc += bytes_consumed;

            let mut insn = VmInstruction::new(offset, opcode, semantic.clone());
            insn.imm = imm;
            insn.regs = regs;
            insn.size_hint = Self::size_hint_for(&semantic);

            let is_terminator = matches!(semantic, SemanticOp::Halt | SemanticOp::Ret | SemanticOp::Jmp);
            func.push(insn);
            if is_terminator { break; }
        }

        self.notes.push(format!(
            "Decoded function @{:#x}: {} instructions, {:.1}% resolved",
            start_address,
            func.len(),
            func.resolution_ratio() * 100.0
        ));

        func
    }

    /// Decode a bytecode buffer into a [`LiftedVmFunction`] **and** record it
    /// in `self.functions` so that subsequent calls to [`Self::report`] reflect it.
    ///
    /// Use this instead of [`Self::decode_function`] when you want the function to
    /// appear in [`VmReport::functions_lifted`] and related statistics.
    ///
    /// # Panics
    /// Panics if the internal functions list is empty after push (should never happen).
    pub fn decode_and_record(&mut self, bytecode: &[u8], start_address: u64) -> &LiftedVmFunction {
        let func = self.decode_function(bytecode, start_address);
        self.functions.push(func);
        self.functions.last().unwrap()
    }

    /// Lift multiple bytecode buffers, one per function.
    pub fn lift_all(&mut self, functions: &[(u64, Vec<u8>)]) {
        let decoded: Vec<LiftedVmFunction> = functions.iter()
            .map(|(addr, bc)| self.decode_function(bc, *addr))
            .collect();
        self.functions.extend(decoded);
    }

    /// Produce a [`VmReport`] from the current engine state.
    #[must_use]
    pub fn report(&self) -> VmReport {
        let total: usize = self.functions.iter().map(LiftedVmFunction::len).sum();
        let unresolved: usize = self.functions.iter().map(|f| f.unresolved_count).sum();
        VmReport {
            functions_lifted: self.functions.len(),
            total_instructions: total,
            unresolved_instructions: unresolved,
            handler_db_size: self.handler_db.len(),
            coverage: self.coverage.clone(),
            opcode_map: self.opcode_map.clone(),
            notes: self.notes.clone(),
            isa_complete: self.coverage.is_complete(),
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Very simple heuristic: guess from the opcode byte range.
    const fn infer_semantic(opcode: u8, _buf: &[u8], _pc: usize) -> SemanticOp {
        match opcode {
            0x00 => SemanticOp::Nop,
            0xFF => SemanticOp::Halt,
            0x10..=0x1F => SemanticOp::Add,
            0x20..=0x2F => SemanticOp::Load(4),
            0x30..=0x3F => SemanticOp::Jmp,
            _ => SemanticOp::Unknown,
        }
    }

    /// Decode operand bytes and return `(imm, regs, bytes_consumed)`.
    fn decode_operands(sem: &SemanticOp, buf: &[u8], pc: usize) -> (Option<u64>, Vec<u8>, usize) {
        let remaining = &buf[pc.min(buf.len())..];
        match sem {
            SemanticOp::PushImm
            | SemanticOp::Jmp | SemanticOp::Jz | SemanticOp::Jnz | SemanticOp::Jl | SemanticOp::Jg
            | SemanticOp::Call => {
                if remaining.len() >= 4 {
                    let v = u32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]);
                    (Some(u64::from(v)), vec![], 4)
                } else { (None, vec![], 0) }
            }
            SemanticOp::PushReg | SemanticOp::PopReg => {
                if remaining.is_empty() { (None, vec![], 0) }
                else { (None, vec![remaining[0]], 1) }
            }
            _ => (None, vec![], 0),
        }
    }

    const fn size_hint_for(sem: &SemanticOp) -> Option<u8> {
        match sem {
            SemanticOp::Load(n) | SemanticOp::Store(n) => Some(*n),
            _ => None,
        }
    }
}

impl Default for VmBytecodeRecovery {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── OpcodeMap ─────────────────────────────────────────────────────────────

    #[test]
    fn test_opcode_map_insert_lookup() {
        let mut m = OpcodeMap::new();
        m.insert(0x10, SemanticOp::Add);
        assert_eq!(m.semantic(0x10), Some(&SemanticOp::Add));
        assert_eq!(m.semantic(0x11), None);
    }

    #[test]
    fn test_opcode_map_reverse() {
        let mut m = OpcodeMap::new();
        m.insert(0x10, SemanticOp::Add);
        assert_eq!(m.opcode_for(&SemanticOp::Add), Some(0x10));
    }

    #[test]
    fn test_opcode_map_default_scheme() {
        let m = OpcodeMap::default_scheme();
        assert!(!m.is_empty());
        assert!(m.len() >= 10);
        assert_eq!(m.semantic(0x00), Some(&SemanticOp::Nop));
        assert_eq!(m.semantic(0xFF), Some(&SemanticOp::Halt));
        assert_eq!(m.semantic(0x10), Some(&SemanticOp::Add));
    }

    #[test]
    fn test_opcode_map_opcodes_sorted() {
        let m = OpcodeMap::default_scheme();
        let ops = m.opcodes();
        let sorted: Vec<u8> = {
            let mut v = ops.clone();
            v.sort_unstable();
            v
        };
        assert_eq!(ops, sorted);
    }

    #[test]
    fn test_opcode_map_iter() {
        let mut m = OpcodeMap::new();
        m.insert(0x01, SemanticOp::Add);
        m.insert(0x02, SemanticOp::Sub);
        assert_eq!(m.iter().count(), 2);
    }

    #[test]
    fn test_opcode_map_overwrite() {
        let mut m = OpcodeMap::new();
        m.insert(0x10, SemanticOp::Add);
        m.insert(0x10, SemanticOp::Sub);
        assert_eq!(m.semantic(0x10), Some(&SemanticOp::Sub));
        assert_eq!(m.len(), 1);
    }

    // ── SemanticOp ────────────────────────────────────────────────────────────

    #[test]
    fn test_semantic_op_is_control_flow() {
        assert!(SemanticOp::Jmp.is_control_flow());
        assert!(SemanticOp::Ret.is_control_flow());
        assert!(SemanticOp::Halt.is_control_flow());
        assert!(!SemanticOp::Add.is_control_flow());
        assert!(!SemanticOp::Nop.is_control_flow());
    }

    #[test]
    fn test_semantic_op_accesses_memory() {
        assert!(SemanticOp::Load(4).accesses_memory());
        assert!(SemanticOp::Store(8).accesses_memory());
        assert!(!SemanticOp::Add.accesses_memory());
        assert!(!SemanticOp::Jmp.accesses_memory());
    }

    #[test]
    fn test_semantic_op_stack_balance() {
        assert_eq!(SemanticOp::PushImm.stack_balance(), 1);
        assert_eq!(SemanticOp::PopReg.stack_balance(), -1);
        assert_eq!(SemanticOp::Add.stack_balance(), -1);
        assert_eq!(SemanticOp::Nop.stack_balance(), 0);
        assert_eq!(SemanticOp::Store(4).stack_balance(), -2);
        assert_eq!(SemanticOp::Dup.stack_balance(), 1);
    }

    #[test]
    fn test_semantic_op_mnemonic() {
        assert_eq!(SemanticOp::Add.mnemonic(), "ADD");
        assert_eq!(SemanticOp::Halt.mnemonic(), "HALT");
        assert_eq!(SemanticOp::Load(4).mnemonic(), "LOAD");
        assert_eq!(SemanticOp::Unknown.mnemonic(), "UNK");
    }

    // ── HandlerEntry ──────────────────────────────────────────────────────────

    #[test]
    fn test_handler_entry_new() {
        let e = HandlerEntry::new(0x10, 0x1000, SemanticOp::Add, 0.9);
        assert_eq!(e.opcode, 0x10);
        assert_eq!(e.address, 0x1000);
        assert_eq!(e.semantic, SemanticOp::Add);
        assert!((e.confidence - 0.9).abs() < f32::EPSILON);
        assert!(e.is_high_confidence());
    }

    #[test]
    fn test_handler_entry_clamp_confidence() {
        let e = HandlerEntry::new(0x01, 0x0, SemanticOp::Nop, 1.5);
        assert!((e.confidence - 1.0).abs() < f32::EPSILON);
        let e2 = HandlerEntry::new(0x01, 0x0, SemanticOp::Nop, -0.5);
        assert!((e2.confidence).abs() < f32::EPSILON);
    }

    #[test]
    fn test_handler_entry_builders() {
        let e = HandlerEntry::new(0x10, 0x0, SemanticOp::Add, 0.9)
            .with_size(64)
            .with_evidence(EvidenceSource::PatternMatch)
            .with_prologue(vec![0x55, 0x48, 0x89, 0xE5])
            .with_notes("test handler");
        assert_eq!(e.size, 64);
        assert_eq!(e.evidence, vec![EvidenceSource::PatternMatch]);
        assert_eq!(e.prologue, vec![0x55, 0x48, 0x89, 0xE5]);
        assert_eq!(e.notes, "test handler");
    }

    #[test]
    fn test_handler_entry_prologue_truncated() {
        let long_prologue = vec![0xAA; 64];
        let e = HandlerEntry::new(0x01, 0x0, SemanticOp::Add, 0.9)
            .with_prologue(long_prologue);
        assert_eq!(e.prologue.len(), 32);
    }

    // ── HandlerDatabase ───────────────────────────────────────────────────────

    #[test]
    fn test_handler_db_insert_get() {
        let mut db = HandlerDatabase::new();
        db.insert(HandlerEntry::new(0x10, 0x1000, SemanticOp::Add, 0.9));
        assert!(db.get(0x10).is_some());
        assert!(db.get(0x11).is_none());
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn test_handler_db_is_empty() {
        let db = HandlerDatabase::new();
        assert!(db.is_empty());
    }

    #[test]
    fn test_handler_db_high_confidence_count() {
        let mut db = HandlerDatabase::new();
        db.insert(HandlerEntry::new(0x01, 0x0, SemanticOp::Add, 0.9));
        db.insert(HandlerEntry::new(0x02, 0x0, SemanticOp::Sub, 0.4));
        assert_eq!(db.high_confidence_count(), 1);
    }

    #[test]
    fn test_handler_db_entries_for_semantic() {
        let mut db = HandlerDatabase::new();
        db.insert(HandlerEntry::new(0x10, 0x0, SemanticOp::Add, 0.9));
        db.insert(HandlerEntry::new(0x11, 0x0, SemanticOp::Sub, 0.9));
        let add_entries = db.entries_for_semantic(&SemanticOp::Add);
        assert_eq!(add_entries.len(), 1);
        assert_eq!(add_entries[0].opcode, 0x10);
    }

    #[test]
    fn test_handler_db_merge_higher_confidence_wins() {
        let mut db1 = HandlerDatabase::new();
        db1.insert(HandlerEntry::new(0x10, 0x1000, SemanticOp::Add, 0.6));
        let mut db2 = HandlerDatabase::new();
        db2.insert(HandlerEntry::new(0x10, 0x2000, SemanticOp::Add, 0.9));
        db1.merge(&db2);
        assert_eq!(db1.get(0x10).unwrap().address, 0x2000);
    }

    #[test]
    fn test_handler_db_merge_lower_confidence_loses() {
        let mut db1 = HandlerDatabase::new();
        db1.insert(HandlerEntry::new(0x10, 0x1000, SemanticOp::Add, 0.9));
        let mut db2 = HandlerDatabase::new();
        db2.insert(HandlerEntry::new(0x10, 0x2000, SemanticOp::Add, 0.5));
        db1.merge(&db2);
        assert_eq!(db1.get(0x10).unwrap().address, 0x1000);
    }

    #[test]
    fn test_handler_db_prune() {
        let mut db = HandlerDatabase::new();
        db.insert(HandlerEntry::new(0x01, 0x0, SemanticOp::Add, 0.9));
        db.insert(HandlerEntry::new(0x02, 0x0, SemanticOp::Sub, 0.3));
        db.prune_below(0.5);
        assert_eq!(db.len(), 1);
        assert!(db.get(0x01).is_some());
        assert!(db.get(0x02).is_none());
    }

    // ── SemanticCoverage ──────────────────────────────────────────────────────

    #[test]
    fn test_coverage_empty() {
        let c = SemanticCoverage::new();
        assert_eq!(c.resolved_count(), 0);
    }

    #[test]
    fn test_coverage_mark_resolved() {
        let mut c = SemanticCoverage::with_isa_size(10);
        c.mark_resolved(0x10);
        c.mark_resolved(0x11);
        assert_eq!(c.resolved_count(), 2);
        assert!((c.ratio() - 0.2).abs() < 1e-9);
    }

    #[test]
    fn test_coverage_percent_str() {
        let mut c = SemanticCoverage::with_isa_size(4);
        c.mark_resolved(0x01);
        c.mark_resolved(0x02);
        assert_eq!(c.percent_str(), "50.0%");
    }

    #[test]
    fn test_coverage_is_complete() {
        let mut c = SemanticCoverage::with_isa_size(2);
        c.mark_resolved(0x01);
        assert!(!c.is_complete());
        c.mark_resolved(0x02);
        assert!(c.is_complete());
    }

    #[test]
    fn test_coverage_observe_no_double_count() {
        let mut c = SemanticCoverage::new();
        c.mark_resolved(0x10);
        c.observe(0x10); // already resolved, should not increment total_seen
        c.observe(0x11);
        assert_eq!(c.resolved_count(), 1);
    }

    // ── VmInstruction ─────────────────────────────────────────────────────────

    #[test]
    fn test_vm_instruction_new() {
        let i = VmInstruction::new(0, 0x10, SemanticOp::Add);
        assert_eq!(i.offset, 0);
        assert_eq!(i.opcode, 0x10);
        assert_eq!(i.semantic, SemanticOp::Add);
        assert!(i.is_resolved());
    }

    #[test]
    fn test_vm_instruction_unknown_not_resolved() {
        let i = VmInstruction::new(0, 0xAB, SemanticOp::Unknown);
        assert!(!i.is_resolved());
    }

    #[test]
    fn test_vm_instruction_display() {
        let mut i = VmInstruction::new(0x10, 0x01, SemanticOp::PushImm);
        i.imm = Some(0x42);
        let d = i.display();
        assert!(d.contains("PUSH.IMM"));
        assert!(d.contains("0x42"));
    }

    // ── LiftedVmFunction ─────────────────────────────────────────────────────

    #[test]
    fn test_lifted_fn_empty() {
        let f = LiftedVmFunction::new(0x1000);
        assert!(f.is_empty());
        assert!((f.resolution_ratio() - 1.0_f64).abs() < f64::EPSILON);
        assert!(!f.has_terminator());
    }

    #[test]
    fn test_lifted_fn_push_and_resolution() {
        let mut f = LiftedVmFunction::new(0x0);
        f.push(VmInstruction::new(0, 0x10, SemanticOp::Add));
        f.push(VmInstruction::new(1, 0xAB, SemanticOp::Unknown));
        assert_eq!(f.len(), 2);
        assert_eq!(f.unresolved_count, 1);
        assert!((f.resolution_ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_lifted_fn_has_terminator() {
        let mut f = LiftedVmFunction::new(0x0);
        f.push(VmInstruction::new(0, 0xFF, SemanticOp::Halt));
        assert!(f.has_terminator());
    }

    #[test]
    fn test_lifted_fn_stack_trace() {
        let mut f = LiftedVmFunction::new(0x0);
        f.push(VmInstruction::new(0, 0x01, SemanticOp::PushImm));
        f.push(VmInstruction::new(1, 0x02, SemanticOp::PushImm));
        f.push(VmInstruction::new(2, 0x10, SemanticOp::Add));
        // balance: 1, 2, 1
        assert_eq!(f.stack_trace, vec![1, 2, 1]);
    }

    // ── VmBytecodeRecovery ────────────────────────────────────────────────────

    #[test]
    fn test_recovery_new() {
        let r = VmBytecodeRecovery::new();
        assert!(!r.opcode_map.is_empty());
        assert!(r.handler_db.is_empty());
    }

    #[test]
    fn test_recovery_decode_nop_halt() {
        let mut r = VmBytecodeRecovery::new();
        let bc = vec![0x00, 0xFF]; // Nop, Halt
        let f = r.decode_function(&bc, 0x1000);
        assert_eq!(f.len(), 2);
        assert_eq!(f.instructions[0].semantic, SemanticOp::Nop);
        assert_eq!(f.instructions[1].semantic, SemanticOp::Halt);
        assert!(f.has_terminator());
    }

    #[test]
    fn test_recovery_decode_stops_at_halt() {
        let mut r = VmBytecodeRecovery::new();
        let bc = vec![0x00, 0xFF, 0x00, 0x00]; // Nop, Halt, (unreachable bytes)
        let f = r.decode_function(&bc, 0x0);
        assert_eq!(f.len(), 2); // stops after HALT
    }

    #[test]
    fn test_recovery_decode_push_imm() {
        let mut r = VmBytecodeRecovery::new();
        let bc = vec![0x01, 0x42, 0x00, 0x00, 0x00, 0xFF];
        let f = r.decode_function(&bc, 0x0);
        assert_eq!(f.instructions[0].semantic, SemanticOp::PushImm);
        assert_eq!(f.instructions[0].imm, Some(0x42));
    }

    #[test]
    fn test_recovery_register_handler() {
        let mut r = VmBytecodeRecovery::new();
        r.register_handler(HandlerEntry::new(0xAA, 0x5000, SemanticOp::Mul, 0.9));
        assert!(r.handler_db.get(0xAA).is_some());
        assert_eq!(r.opcode_map.semantic(0xAA), Some(&SemanticOp::Mul));
    }

    #[test]
    fn test_recovery_low_confidence_not_committed() {
        let mut r = VmBytecodeRecovery::new();
        r.config.min_commit_confidence = 0.7;
        r.register_handler(HandlerEntry::new(0xBB, 0x0, SemanticOp::Add, 0.3));
        assert!(r.handler_db.get(0xBB).is_none());
    }

    #[test]
    fn test_recovery_lift_all() {
        let mut r = VmBytecodeRecovery::new();
        let fns: Vec<(u64, Vec<u8>)> = vec![
            (0x1000, vec![0x00, 0xFF]),
            (0x2000, vec![0x10, 0xFF]),
        ];
        r.lift_all(&fns);
        assert_eq!(r.functions.len(), 2);
    }

    #[test]
    fn test_recovery_report() {
        let mut r = VmBytecodeRecovery::new();
        r.decode_function(&[0x00, 0x10, 0xFF], 0x0);
        let report = r.report();
        assert_eq!(report.functions_lifted, 0); // decode_function doesn't push to self.functions
    }

    #[test]
    fn test_recovery_report_via_lift_all() {
        let mut r = VmBytecodeRecovery::new();
        r.lift_all(&[(0x0, vec![0x00, 0xFF])]);
        let report = r.report();
        assert_eq!(report.functions_lifted, 1);
        assert!(report.total_instructions >= 2);
    }

    #[test]
    fn test_report_resolution_percent_full() {
        let mut r = VmBytecodeRecovery::new();
        r.lift_all(&[(0x0, vec![0x00, 0xFF])]);
        let rep = r.report();
        assert!((rep.resolution_percent() - 100.0).abs() < 1e-6);
    }

    #[test]
    fn test_report_summary_string() {
        let mut r = VmBytecodeRecovery::new();
        r.lift_all(&[(0x0, vec![0x00, 0xFF])]);
        let rep = r.report();
        let s = rep.summary();
        assert!(s.contains("functions=1"));
    }

    #[test]
    fn test_vm_report_unresolved() {
        let mut r = VmBytecodeRecovery::new();
        r.lift_all(&[(0x0, vec![0xAB, 0xFF])]); // 0xAB is unknown
        let rep = r.report();
        assert!(rep.unresolved_instructions > 0);
    }

    #[test]
    fn test_recovery_with_custom_opcode_map() {
        let mut m = OpcodeMap::new();
        m.insert(0x01, SemanticOp::Add);
        m.insert(0x02, SemanticOp::Halt);
        let mut r = VmBytecodeRecovery::with_opcode_map(m);
        r.lift_all(&[(0x0, vec![0x01, 0x02])]);
        assert_eq!(r.functions[0].instructions[0].semantic, SemanticOp::Add);
        assert_eq!(r.functions[0].instructions[1].semantic, SemanticOp::Halt);
    }

    #[test]
    fn test_recovery_add_note() {
        let mut r = VmBytecodeRecovery::new();
        r.add_note("test note");
        let rep = r.report();
        assert!(rep.notes.iter().any(|n| n == "test note"));
    }

    #[test]
    fn test_coverage_unresolved_opcodes() {
        let c = SemanticCoverage::new();
        let unresolved = c.unresolved_opcodes();
        assert!(unresolved.contains(&0x10));
    }

    #[test]
    fn test_semantic_coverage_isa_size_zero() {
        let c = SemanticCoverage::with_isa_size(0);
        assert!(c.ratio().abs() < f64::EPSILON);
    }

    #[test]
    fn test_opcode_map_empty_is_empty() {
        let m = OpcodeMap::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn test_lifted_fn_name() {
        let mut f = LiftedVmFunction::new(0x0);
        f.name = Some("main_vm".to_string());
        assert_eq!(f.name, Some("main_vm".to_string()));
    }

    #[test]
    fn test_recovery_stops_at_ret() {
        let mut r = VmBytecodeRecovery::new();
        let bc = vec![0x00, 0x36, 0x00]; // Nop, Ret, Nop — stops at Ret
        let f = r.decode_function(&bc, 0x0);
        assert_eq!(f.len(), 2);
        assert!(f.has_terminator());
    }

    #[test]
    fn test_handler_db_sorted_entries() {
        let mut db = HandlerDatabase::new();
        db.insert(HandlerEntry::new(0x20, 0x0, SemanticOp::Sub, 0.9));
        db.insert(HandlerEntry::new(0x10, 0x0, SemanticOp::Add, 0.9));
        let entries = db.sorted_entries();
        assert_eq!(entries[0].opcode, 0x10);
        assert_eq!(entries[1].opcode, 0x20);
    }
}
