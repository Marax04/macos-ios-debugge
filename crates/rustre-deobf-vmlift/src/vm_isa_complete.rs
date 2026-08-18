//! `vm_isa_complete` — Complete VM ISA reconstruction from lifted handler data.
//!
//! # Relation to `vm_isa_recovery`
//! [`crate::vm_isa_recovery`] is the **low-level layer** that parses a raw
//! dispatch-table byte slice into an [`crate::vm_isa_recovery::IsaTable`].
//! This module is the **high-level layer** that further decodes bytecode
//! into typed [`VmBasicBlock`]s / [`VmCfg`]s and emits a [`VmIsaReport`].
//! The two modules form a deliberate pipeline; keep them separate.
//!
//! Reconstructs the full Instruction Set Architecture of a detected virtual
//! machine: opcodes, operand encodings, basic blocks, and a function-level
//! control-flow graph.
//!
//! # Key types
//! - [`VmIsaComplete`]   — primary reconstruction engine
//! - [`VmOpcode`]        — one instruction definition in the ISA
//! - [`VmOperand`]       — typed operand descriptor
//! - [`VmBasicBlock`]    — block of sequentially-executed VM instructions
//! - [`VmCfg`]           — control-flow graph over basic blocks
//! - [`VmFunctionList`]  — registry of lifted VM functions
//! - [`VmIsaReport`]     — final reconstruction report

use std::collections::{BTreeMap, HashMap, HashSet};
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// VmOperand
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of an operand within a VM instruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperandKind {
    /// An inline immediate constant.
    Immediate,
    /// A virtual register index.
    Register,
    /// A bytecode-relative branch target.
    BranchTarget,
    /// An absolute memory address.
    MemoryAddress,
    /// A type identifier (for type-tagged VMs).
    TypeId,
}

/// Width of an operand in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperandWidth {
    U8 = 1,
    U16 = 2,
    U32 = 4,
    U64 = 8,
}

impl OperandWidth {
    /// Number of bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self as usize
    }
}

/// A typed operand descriptor for one instruction in the VM ISA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmOperand {
    /// Operand name (e.g. "dst", "src", "imm", "target").
    pub name: String,
    /// Kind of value this operand carries.
    pub kind: OperandKind,
    /// Width of the operand encoding in the bytecode stream.
    pub width: OperandWidth,
    /// Whether this operand is optional (only present in some encodings).
    pub optional: bool,
}

impl VmOperand {
    /// Create a mandatory operand.
    #[must_use]
    pub fn new(name: impl Into<String>, kind: OperandKind, width: OperandWidth) -> Self {
        Self { name: name.into(), kind, width, optional: false }
    }

    /// Create an optional operand.
    #[must_use]
    pub fn optional(name: impl Into<String>, kind: OperandKind, width: OperandWidth) -> Self {
        Self { name: name.into(), kind, width, optional: true }
    }

    /// Total encoded bytes this operand occupies in the stream.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.width.bytes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmOpcode
// ─────────────────────────────────────────────────────────────────────────────

/// Execution category of a VM instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InsnCategory {
    Stack,
    Arithmetic,
    Logic,
    Memory,
    ControlFlow,
    Comparison,
    Conversion,
    System,
    Unknown,
}

impl InsnCategory {
    /// Short label string.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Stack       => "stack",
            Self::Arithmetic  => "arith",
            Self::Logic       => "logic",
            Self::Memory      => "mem",
            Self::ControlFlow => "cf",
            Self::Comparison  => "cmp",
            Self::Conversion  => "conv",
            Self::System      => "sys",
            Self::Unknown     => "unk",
        }
    }
}

/// One instruction definition in the reconstructed VM ISA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmOpcode {
    /// The opcode byte.
    pub byte: u8,
    /// Human-readable mnemonic.
    pub mnemonic: String,
    /// Execution category.
    pub category: InsnCategory,
    /// Ordered list of operands that follow the opcode in the bytecode stream.
    pub operands: Vec<VmOperand>,
    /// Total bytes consumed by this instruction (1 opcode + sum of operand widths).
    pub total_bytes: usize,
    /// Stack balance: positive = net pushes, negative = net pops.
    pub stack_balance: i8,
    /// `true` if this instruction may branch (jmp, jz, call, ret, halt).
    pub is_branch: bool,
    /// Confidence that the reconstruction is correct `[0.0, 1.0]`.
    pub confidence: f32,
}

impl VmOpcode {
    /// Construct from basic fields; computes `total_bytes` automatically.
    #[must_use]
    pub fn new(
        byte: u8,
        mnemonic: impl Into<String>,
        category: InsnCategory,
        operands: Vec<VmOperand>,
        stack_balance: i8,
        is_branch: bool,
        confidence: f32,
    ) -> Self {
        let total_bytes = 1 + operands.iter().filter(|o| !o.optional).map(VmOperand::encoded_bytes).sum::<usize>();
        Self {
            byte,
            mnemonic: mnemonic.into(),
            category,
            operands,
            total_bytes,
            stack_balance,
            is_branch,
            confidence: confidence.clamp(0.0, 1.0),
        }
    }

    /// Short description: `mnem [category] +/-n`.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{:12} [{}] stack{:+}  total={}B  conf={:.2}",
            self.mnemonic,
            self.category.label(),
            self.stack_balance,
            self.total_bytes,
            self.confidence,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmBasicBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded VM instruction (thin record for use inside basic blocks).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedInsn {
    /// Offset from the start of the bytecode buffer.
    pub offset: usize,
    /// Opcode byte.
    pub opcode: u8,
    /// Mnemonic (from the ISA or "UNK").
    pub mnemonic: String,
    /// Raw operand values decoded from the bytecode.
    pub operand_values: Vec<u64>,
}

impl DecodedInsn {
    /// Create a minimal decoded instruction.
    #[must_use]
    pub fn new(offset: usize, opcode: u8, mnemonic: impl Into<String>) -> Self {
        Self {
            offset,
            opcode,
            mnemonic: mnemonic.into(),
            operand_values: Vec::new(),
        }
    }

    /// Format as `offset  mnem  ops…`
    #[must_use]
    pub fn display(&self) -> String {
        let ops: Vec<String> = self.operand_values.iter().map(|v| format!("{v:#x}")).collect();
        if ops.is_empty() {
            format!("{:#06x}  {}", self.offset, self.mnemonic)
        } else {
            format!("{:#06x}  {}  {}", self.offset, self.mnemonic, ops.join(", "))
        }
    }
}

/// A basic block in the VM CFG: a maximal sequence of instructions with
/// no internal branches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmBasicBlock {
    /// Unique identifier for this block.
    pub id: u32,
    /// Bytecode offset of the first instruction.
    pub start_offset: usize,
    /// Bytecode offset just past the last instruction.
    pub end_offset: usize,
    /// Decoded instructions in this block.
    pub instructions: Vec<DecodedInsn>,
    /// Successor block IDs (0, 1, or 2 successors).
    pub successors: Vec<u32>,
    /// Predecessor block IDs.
    pub predecessors: Vec<u32>,
    /// `true` if the last instruction is a branch.
    pub ends_with_branch: bool,
}

impl VmBasicBlock {
    /// Create an empty block with the given ID and start offset.
    #[must_use]
    pub const fn new(id: u32, start_offset: usize) -> Self {
        Self {
            id,
            start_offset,
            end_offset: start_offset,
            instructions: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
            ends_with_branch: false,
        }
    }

    /// Append an instruction and update `end_offset`.
    pub fn push(&mut self, insn: DecodedInsn) {
        self.end_offset = insn.offset + 1; // will be corrected by caller with actual insn size
        self.instructions.push(insn);
    }

    /// Number of instructions in this block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// `true` if the block has no instructions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Size of the block in bytecode bytes.
    #[must_use]
    pub const fn byte_size(&self) -> usize {
        self.end_offset.saturating_sub(self.start_offset)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmCfg
// ─────────────────────────────────────────────────────────────────────────────

/// A control-flow graph over [`VmBasicBlock`]s.
///
/// Block data is stored in a `BTreeMap` keyed by block ID for ordered
/// traversal and serialisation. Edge topology is maintained in a
/// [`petgraph::graph::DiGraph`] so that standard graph algorithms
/// (reachability, dominators, etc.) can be applied directly.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VmCfg {
    /// All blocks in this CFG, keyed by block ID.
    pub blocks: BTreeMap<u32, VmBasicBlock>,
    /// Entry block ID.
    pub entry: Option<u32>,
    /// Next block ID counter.
    next_id: u32,
    /// Petgraph directed graph for edge queries and graph algorithms.
    /// Each node weight is the block ID it represents.
    #[serde(skip)]
    graph: DiGraph<u32, ()>,
    /// Map from block ID → petgraph `NodeIndex`, kept in sync with `graph`.
    #[serde(skip)]
    node_index: HashMap<u32, NodeIndex>,
}

impl VmCfg {
    /// Create an empty CFG.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new block with a fresh ID starting at `start_offset`.
    pub fn new_block(&mut self, start_offset: usize) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let block = VmBasicBlock::new(id, start_offset);
        self.blocks.insert(id, block);
        let ni = self.graph.add_node(id);
        self.node_index.insert(id, ni);
        id
    }

    /// Get a mutable reference to a block by ID.
    pub fn block_mut(&mut self, id: u32) -> Option<&mut VmBasicBlock> {
        self.blocks.get_mut(&id)
    }

    /// Get an immutable reference to a block by ID.
    #[must_use]
    pub fn block(&self, id: u32) -> Option<&VmBasicBlock> {
        self.blocks.get(&id)
    }

    /// Add a directed edge from block `from` to block `to`.
    ///
    /// The edge is recorded both in the petgraph [`DiGraph`] (for graph
    /// algorithms) and in the [`VmBasicBlock`] successor/predecessor lists
    /// (for quick serialisable access).
    pub fn add_edge(&mut self, from: u32, to: u32) {
        // Update petgraph graph.
        if let (Some(&ni_from), Some(&ni_to)) =
            (self.node_index.get(&from), self.node_index.get(&to))
        {
            // Avoid duplicate edges.
            if !self.graph.contains_edge(ni_from, ni_to) {
                self.graph.add_edge(ni_from, ni_to, ());
            }
        }
        // Mirror in block successor/predecessor lists for serialisation.
        if let Some(b) = self.blocks.get_mut(&from) {
            if !b.successors.contains(&to) {
                b.successors.push(to);
            }
        }
        if let Some(b) = self.blocks.get_mut(&to) {
            if !b.predecessors.contains(&from) {
                b.predecessors.push(from);
            }
        }
    }

    /// Number of blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Total instruction count across all blocks.
    #[must_use]
    pub fn total_instructions(&self) -> usize {
        self.blocks.values().map(VmBasicBlock::len).sum()
    }

    /// Return the IDs of all blocks that have no predecessors (entry candidates).
    ///
    /// Uses the petgraph graph for an O(V) in-degree check.
    #[must_use]
    pub fn entry_candidates(&self) -> Vec<u32> {
        self.graph
            .node_indices()
            .filter(|&ni| {
                self.graph
                    .neighbors_directed(ni, petgraph::Direction::Incoming)
                    .next()
                    .is_none()
            })
            .filter_map(|ni| self.graph.node_weight(ni).copied())
            .collect()
    }

    /// Expose a reference to the underlying petgraph [`DiGraph`] for callers
    /// that want to run graph algorithms (e.g. dominator tree computation).
    #[must_use]
    pub const fn digraph(&self) -> &DiGraph<u32, ()> {
        &self.graph
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmFunctionList
// ─────────────────────────────────────────────────────────────────────────────

/// A lifted VM function record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmFunction {
    /// Virtual address of the function's first bytecode byte.
    pub address: u64,
    /// Optional name.
    pub name: Option<String>,
    /// The function's CFG.
    pub cfg: VmCfg,
    /// Number of unique opcodes used in this function.
    pub opcode_variety: usize,
}

impl VmFunction {
    /// Create a new empty function.
    #[must_use]
    pub fn new(address: u64) -> Self {
        Self {
            address,
            name: None,
            cfg: VmCfg::new(),
            opcode_variety: 0,
        }
    }

    /// Total instruction count.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.cfg.total_instructions()
    }
}

/// Registry of all lifted VM functions.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VmFunctionList {
    functions: Vec<VmFunction>,
}

impl VmFunctionList {
    /// Create an empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function.
    pub fn push(&mut self, func: VmFunction) {
        self.functions.push(func);
    }

    /// Number of functions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.functions.len()
    }

    /// `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Total instructions across all functions.
    #[must_use]
    pub fn total_instructions(&self) -> usize {
        self.functions.iter().map(VmFunction::instruction_count).sum()
    }

    /// Look up a function by address.
    #[must_use]
    pub fn find_by_address(&self, addr: u64) -> Option<&VmFunction> {
        self.functions.iter().find(|f| f.address == addr)
    }

    /// Iterate over all functions.
    pub fn iter(&self) -> impl Iterator<Item = &VmFunction> {
        self.functions.iter()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmIsaReport
// ─────────────────────────────────────────────────────────────────────────────

/// Report produced by a complete ISA reconstruction pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmIsaReport {
    /// Number of opcode bytes that were successfully characterised.
    pub opcodes_characterised: usize,
    /// Total distinct opcode bytes observed in bytecode.
    pub opcodes_observed: usize,
    /// Number of functions lifted.
    pub functions_lifted: usize,
    /// Total basic blocks across all lifted functions.
    pub basic_blocks_total: usize,
    /// Total instructions across all lifted functions.
    pub instructions_total: usize,
    /// Coverage fraction `[0.0, 1.0]`.
    pub coverage_ratio: f64,
    /// ISA completeness flag.
    pub isa_complete: bool,
    /// Analysis notes.
    pub notes: Vec<String>,
}

impl VmIsaReport {
    /// Coverage as a percentage string.
    #[must_use]
    pub fn coverage_percent(&self) -> String {
        format!("{:.1}%", self.coverage_ratio * 100.0)
    }

    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "opcodes={}/{} fns={} blocks={} insns={} coverage={} complete={}",
            self.opcodes_characterised,
            self.opcodes_observed,
            self.functions_lifted,
            self.basic_blocks_total,
            self.instructions_total,
            self.coverage_percent(),
            self.isa_complete,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmIsaComplete — main reconstruction engine
// ─────────────────────────────────────────────────────────────────────────────

/// Complete VM ISA reconstruction engine.
///
/// 1. Accepts handler analysis data (opcode bytes + observed semantics).
/// 2. Builds a full [`VmOpcode`] table for the ISA.
/// 3. Decodes bytecode buffers into [`VmCfg`]s and populates a [`VmFunctionList`].
/// 4. Produces a [`VmIsaReport`] with completeness metrics.
#[derive(Debug)]
pub struct VmIsaComplete {
    /// The reconstructed ISA: opcode byte → definition.
    pub isa: BTreeMap<u8, VmOpcode>,
    /// Registry of lifted functions.
    pub functions: VmFunctionList,
    /// Notes accumulated during analysis.
    pub notes: Vec<String>,
    /// Set of opcode bytes observed in bytecode.
    observed_opcodes: HashSet<u8>,
}

impl VmIsaComplete {
    /// Create a new reconstruction engine with an empty ISA.
    #[must_use]
    pub fn new() -> Self {
        Self {
            isa: BTreeMap::new(),
            functions: VmFunctionList::new(),
            notes: Vec::new(),
            observed_opcodes: HashSet::new(),
        }
    }

    /// Register an opcode definition into the ISA.
    pub fn register_opcode(&mut self, opcode: VmOpcode) {
        self.isa.insert(opcode.byte, opcode);
    }

    /// Look up an opcode definition.
    #[must_use]
    pub fn lookup(&self, byte: u8) -> Option<&VmOpcode> {
        self.isa.get(&byte)
    }

    /// ISA size (number of defined opcodes).
    #[must_use]
    pub fn isa_size(&self) -> usize {
        self.isa.len()
    }

    /// Decode `bytecode` into a [`VmCfg`], lifting one function.
    ///
    /// Uses a linear sweep: each instruction starts a new basic block when it
    /// is a branch target, and ends the current block when it is a branch.
    pub fn decode_to_cfg(&mut self, bytecode: &[u8], start_address: u64) -> VmFunction {
        let mut func = VmFunction::new(start_address);
        let mut cfg = VmCfg::new();

        // Pass 1: collect all branch-target offsets so we know where blocks start.
        let targets = self.collect_branch_targets(bytecode);

        // Pass 2: linear sweep to build blocks.
        let mut current_block = cfg.new_block(0);
        cfg.entry = Some(current_block);
        let mut pc = 0usize;
        let mut opcodes_seen: HashSet<u8> = HashSet::new();

        while pc < bytecode.len() {
            let opcode_byte = bytecode[pc];
            self.observed_opcodes.insert(opcode_byte);
            opcodes_seen.insert(opcode_byte);
            let offset = pc;

            let (mnem, total, is_branch, ops) = self.decode_single(bytecode, pc);
            let mut insn = DecodedInsn::new(offset, opcode_byte, mnem);
            insn.operand_values = ops;

            // If this offset is a branch target, close current block and start new one.
            if targets.contains(&pc) && !cfg.block(current_block).is_none_or(VmBasicBlock::is_empty) {
                let new_id = cfg.new_block(pc);
                cfg.add_edge(current_block, new_id);
                current_block = new_id;
            }

            if let Some(b) = cfg.block_mut(current_block) {
                b.push(insn);
                b.end_offset = pc + total;
                if is_branch {
                    b.ends_with_branch = true;
                }
            }

            pc += total;

            // End block after branch.
            if is_branch && pc < bytecode.len() {
                let new_id = cfg.new_block(pc);
                cfg.add_edge(current_block, new_id);
                current_block = new_id;
            }
        }

        func.opcode_variety = opcodes_seen.len();
        func.cfg = cfg;
        func
    }

    /// Lift multiple functions and store them in the function list.
    pub fn lift_all(&mut self, functions: &[(u64, Vec<u8>)]) {
        let funcs: Vec<VmFunction> = functions.iter()
            .map(|(addr, bc)| self.decode_to_cfg(bc, *addr))
            .collect();
        for f in funcs {
            self.functions.push(f);
        }
    }

    /// Populate the ISA with a built-in default scheme matching the standard
    /// bytecode encoding.
    pub fn populate_default_isa(&mut self) {
        let entries: &[(u8, &str, InsnCategory, i8, bool)] = &[
            (0x00, "NOP",      InsnCategory::System,      0,  false),
            (0x01, "PUSH.IMM", InsnCategory::Stack,       1,  false),
            (0x02, "PUSH.REG", InsnCategory::Stack,       1,  false),
            (0x03, "POP.REG",  InsnCategory::Stack,      -1,  false),
            (0x10, "ADD",      InsnCategory::Arithmetic, -1,  false),
            (0x11, "SUB",      InsnCategory::Arithmetic, -1,  false),
            (0x12, "MUL",      InsnCategory::Arithmetic, -1,  false),
            (0x13, "AND",      InsnCategory::Logic,      -1,  false),
            (0x14, "OR",       InsnCategory::Logic,      -1,  false),
            (0x15, "XOR",      InsnCategory::Logic,      -1,  false),
            (0x16, "NOT",      InsnCategory::Logic,       0,  false),
            (0x17, "NEG",      InsnCategory::Arithmetic,  0,  false),
            (0x18, "SHL",      InsnCategory::Logic,      -1,  false),
            (0x19, "SHR",      InsnCategory::Logic,      -1,  false),
            (0x20, "LOAD32",   InsnCategory::Memory,      0,  false),
            (0x21, "STORE32",  InsnCategory::Memory,     -2,  false),
            (0x30, "JMP",      InsnCategory::ControlFlow,-1,  true),
            (0x31, "JZ",       InsnCategory::ControlFlow,-1,  true),
            (0x32, "JNZ",      InsnCategory::ControlFlow,-1,  true),
            (0x35, "CALL",     InsnCategory::ControlFlow,-1,  true),
            (0x36, "RET",      InsnCategory::ControlFlow, 0,  true),
            (0x40, "CMP",      InsnCategory::Comparison, -1,  false),
            (0x50, "DUP",      InsnCategory::Stack,       1,  false),
            (0x51, "SWAP",     InsnCategory::Stack,       0,  false),
            (0xFF, "HALT",     InsnCategory::System,      0,  true),
        ];

        for &(byte, mnem, cat, sb, branch) in entries {
            let operands = Self::default_operands_for(byte);
            let op = VmOpcode::new(byte, mnem, cat, operands, sb, branch, 1.0);
            self.register_opcode(op);
        }

        self.notes.push(format!("Populated default ISA with {} opcodes", self.isa.len()));
    }

    /// Generate a [`VmIsaReport`].
    #[must_use]
    pub fn report(&self) -> VmIsaReport {
        let total_blocks: usize = self.functions.iter()
            .map(|f| f.cfg.block_count())
            .sum();
        let opcodes_observed = self.observed_opcodes.len();
        let opcodes_characterised = self.isa.keys()
            .filter(|b| self.observed_opcodes.contains(*b))
            .count();
        let cov = if opcodes_observed == 0 { 1.0 }
            else { opcodes_characterised as f64 / opcodes_observed as f64 };

        VmIsaReport {
            opcodes_characterised,
            opcodes_observed,
            functions_lifted: self.functions.len(),
            basic_blocks_total: total_blocks,
            instructions_total: self.functions.total_instructions(),
            coverage_ratio: cov,
            isa_complete: cov >= 1.0,
            notes: self.notes.clone(),
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn collect_branch_targets(&self, bytecode: &[u8]) -> HashSet<usize> {
        let mut targets = HashSet::new();
        let mut pc = 0usize;
        while pc < bytecode.len() {
            let _opcode_byte = bytecode[pc];
            let (_, total, is_branch, ops) = self.decode_single(bytecode, pc);
            if is_branch {
                if let Some(&target) = ops.first() {
                    let t = target as usize;
                    if t < bytecode.len() {
                        targets.insert(t);
                    }
                }
            }
            pc += total;
        }
        targets
    }

    /// Decode a single instruction at `pc`, returning `(mnem, total_bytes, is_branch, operand_values)`.
    fn decode_single(&self, bytecode: &[u8], pc: usize) -> (String, usize, bool, Vec<u64>) {
        let opcode_byte = bytecode[pc];
        match self.isa.get(&opcode_byte) {
            Some(def) => {
                let mut ops = Vec::new();
                let mut consumed = 1usize;
                for op in &def.operands {
                    if op.optional { continue; }
                    let bytes = op.width.bytes();
                    if consumed + bytes <= bytecode.len() {
                        let val = Self::read_le(&bytecode[pc + consumed..], bytes);
                        ops.push(val);
                        consumed += bytes;
                    }
                }
                (def.mnemonic.clone(), consumed, def.is_branch, ops)
            }
            None => (format!("UNK_{opcode_byte:02X}"), 1, false, vec![]),
        }
    }

    fn read_le(buf: &[u8], bytes: usize) -> u64 {
        let mut val = 0u64;
        let n = bytes.min(buf.len()).min(8);
        for i in 0..n {
            val |= u64::from(buf[i]) << (i * 8);
        }
        val
    }

    fn default_operands_for(byte: u8) -> Vec<VmOperand> {
        match byte {
            0x01 => vec![VmOperand::new("imm", OperandKind::Immediate, OperandWidth::U32)],
            0x02 => vec![VmOperand::new("reg", OperandKind::Register, OperandWidth::U8)],
            0x03 => vec![VmOperand::new("reg", OperandKind::Register, OperandWidth::U8)],
            0x30 | 0x31 | 0x32 | 0x35 => {
                vec![VmOperand::new("target", OperandKind::BranchTarget, OperandWidth::U32)]
            }
            _ => vec![],
        }
    }
}

impl Default for VmIsaComplete {
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

    // ── VmOperand ─────────────────────────────────────────────────────────────

    #[test]
    fn test_vm_operand_new() {
        let o = VmOperand::new("imm", OperandKind::Immediate, OperandWidth::U32);
        assert_eq!(o.name, "imm");
        assert!(!o.optional);
        assert_eq!(o.encoded_bytes(), 4);
    }

    #[test]
    fn test_vm_operand_optional() {
        let o = VmOperand::optional("disp", OperandKind::Immediate, OperandWidth::U8);
        assert!(o.optional);
    }

    #[test]
    fn test_operand_width_bytes() {
        assert_eq!(OperandWidth::U8.bytes(), 1);
        assert_eq!(OperandWidth::U16.bytes(), 2);
        assert_eq!(OperandWidth::U32.bytes(), 4);
        assert_eq!(OperandWidth::U64.bytes(), 8);
    }

    // ── VmOpcode ──────────────────────────────────────────────────────────────

    #[test]
    fn test_vm_opcode_new_no_operands() {
        let op = VmOpcode::new(0x10, "ADD", InsnCategory::Arithmetic, vec![], -1, false, 0.9);
        assert_eq!(op.byte, 0x10);
        assert_eq!(op.mnemonic, "ADD");
        assert_eq!(op.total_bytes, 1); // 1 opcode + 0 operands
        assert_eq!(op.stack_balance, -1);
        assert!(!op.is_branch);
    }

    #[test]
    fn test_vm_opcode_with_operands() {
        let ops = vec![VmOperand::new("imm", OperandKind::Immediate, OperandWidth::U32)];
        let op = VmOpcode::new(0x01, "PUSH.IMM", InsnCategory::Stack, ops, 1, false, 0.95);
        assert_eq!(op.total_bytes, 5); // 1 + 4
    }

    #[test]
    fn test_vm_opcode_describe() {
        let op = VmOpcode::new(0x10, "ADD", InsnCategory::Arithmetic, vec![], -1, false, 0.9);
        let d = op.describe();
        assert!(d.contains("ADD"));
        assert!(d.contains("arith"));
    }

    #[test]
    fn test_vm_opcode_confidence_clamp() {
        let op = VmOpcode::new(0x00, "NOP", InsnCategory::System, vec![], 0, false, 1.5);
        assert!((op.confidence - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_insn_category_label() {
        assert_eq!(InsnCategory::Stack.label(), "stack");
        assert_eq!(InsnCategory::ControlFlow.label(), "cf");
        assert_eq!(InsnCategory::Unknown.label(), "unk");
    }

    // ── DecodedInsn ───────────────────────────────────────────────────────────

    #[test]
    fn test_decoded_insn_display_no_ops() {
        let i = DecodedInsn::new(0x10, 0x00, "NOP");
        assert!(i.display().contains("NOP"));
    }

    #[test]
    fn test_decoded_insn_display_with_ops() {
        let mut i = DecodedInsn::new(0x00, 0x01, "PUSH.IMM");
        i.operand_values.push(0x42);
        let d = i.display();
        assert!(d.contains("0x42"));
    }

    // ── VmBasicBlock ──────────────────────────────────────────────────────────

    #[test]
    fn test_basic_block_new() {
        let b = VmBasicBlock::new(0, 0x100);
        assert_eq!(b.id, 0);
        assert_eq!(b.start_offset, 0x100);
        assert!(b.is_empty());
    }

    #[test]
    fn test_basic_block_push() {
        let mut b = VmBasicBlock::new(0, 0);
        b.push(DecodedInsn::new(0, 0x00, "NOP"));
        assert_eq!(b.len(), 1);
        assert!(!b.is_empty());
    }

    #[test]
    fn test_basic_block_byte_size() {
        let mut b = VmBasicBlock::new(0, 0x100);
        b.end_offset = 0x110;
        assert_eq!(b.byte_size(), 0x10);
    }

    // ── VmCfg ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_cfg_new_block() {
        let mut cfg = VmCfg::new();
        let id = cfg.new_block(0);
        assert_eq!(id, 0);
        assert_eq!(cfg.block_count(), 1);
    }

    #[test]
    fn test_cfg_add_edge() {
        let mut cfg = VmCfg::new();
        let a = cfg.new_block(0);
        let b = cfg.new_block(10);
        cfg.add_edge(a, b);
        assert!(cfg.block(a).unwrap().successors.contains(&b));
        assert!(cfg.block(b).unwrap().predecessors.contains(&a));
    }

    #[test]
    fn test_cfg_entry_candidates() {
        let mut cfg = VmCfg::new();
        let a = cfg.new_block(0);
        let b = cfg.new_block(10);
        cfg.add_edge(a, b);
        let cands = cfg.entry_candidates();
        assert!(cands.contains(&a));
        assert!(!cands.contains(&b));
    }

    #[test]
    fn test_cfg_total_instructions() {
        let mut cfg = VmCfg::new();
        let id = cfg.new_block(0);
        cfg.block_mut(id).unwrap().push(DecodedInsn::new(0, 0x00, "NOP"));
        cfg.block_mut(id).unwrap().push(DecodedInsn::new(1, 0xFF, "HALT"));
        assert_eq!(cfg.total_instructions(), 2);
    }

    // ── VmFunctionList ────────────────────────────────────────────────────────

    #[test]
    fn test_function_list_empty() {
        let fl = VmFunctionList::new();
        assert!(fl.is_empty());
        assert_eq!(fl.len(), 0);
    }

    #[test]
    fn test_function_list_push() {
        let mut fl = VmFunctionList::new();
        fl.push(VmFunction::new(0x1000));
        assert_eq!(fl.len(), 1);
    }

    #[test]
    fn test_function_list_find_by_address() {
        let mut fl = VmFunctionList::new();
        fl.push(VmFunction::new(0x1000));
        fl.push(VmFunction::new(0x2000));
        assert!(fl.find_by_address(0x1000).is_some());
        assert!(fl.find_by_address(0x3000).is_none());
    }

    // ── VmIsaComplete ─────────────────────────────────────────────────────────

    #[test]
    fn test_isa_complete_new() {
        let e = VmIsaComplete::new();
        assert_eq!(e.isa_size(), 0);
        assert!(e.functions.is_empty());
    }

    #[test]
    fn test_populate_default_isa() {
        let mut e = VmIsaComplete::new();
        e.populate_default_isa();
        assert!(e.isa_size() >= 20);
        assert!(e.lookup(0x00).is_some()); // NOP
        assert!(e.lookup(0xFF).is_some()); // HALT
    }

    #[test]
    fn test_decode_single_known() {
        let mut e = VmIsaComplete::new();
        e.populate_default_isa();
        let bc = vec![0x00]; // NOP
        let (mnem, total, branch, _) = e.decode_single(&bc, 0);
        assert_eq!(mnem, "NOP");
        assert_eq!(total, 1);
        assert!(!branch);
    }

    #[test]
    fn test_decode_single_unknown() {
        let e = VmIsaComplete::new();
        let bc = vec![0xAB];
        let (mnem, total, _, _) = e.decode_single(&bc, 0);
        assert!(mnem.starts_with("UNK_"));
        assert_eq!(total, 1);
    }

    #[test]
    fn test_decode_to_cfg_nop_halt() {
        let mut e = VmIsaComplete::new();
        e.populate_default_isa();
        let bc = vec![0x00, 0xFF]; // NOP, HALT
        let f = e.decode_to_cfg(&bc, 0x1000);
        assert_eq!(f.address, 0x1000);
        assert!(f.cfg.total_instructions() >= 2);
    }

    #[test]
    fn test_lift_all() {
        let mut e = VmIsaComplete::new();
        e.populate_default_isa();
        let fns = vec![
            (0x1000u64, vec![0x00u8, 0xFF]),
            (0x2000u64, vec![0x10u8, 0xFF]),
        ];
        e.lift_all(&fns);
        assert_eq!(e.functions.len(), 2);
    }

    #[test]
    fn test_report_after_lift() {
        let mut e = VmIsaComplete::new();
        e.populate_default_isa();
        e.lift_all(&[(0x0, vec![0x00, 0x10, 0xFF])]);
        let rep = e.report();
        assert_eq!(rep.functions_lifted, 1);
        assert!(rep.instructions_total >= 3);
    }

    #[test]
    fn test_report_coverage_100_when_all_known() {
        let mut e = VmIsaComplete::new();
        e.populate_default_isa();
        e.lift_all(&[(0x0, vec![0x00, 0xFF])]); // only NOP and HALT — both in ISA
        let rep = e.report();
        assert!((rep.coverage_ratio - 1.0).abs() < 1e-9);
        assert!(rep.isa_complete);
    }

    #[test]
    fn test_report_coverage_partial_when_unknown_opcode() {
        let mut e = VmIsaComplete::new();
        e.populate_default_isa();
        e.lift_all(&[(0x0, vec![0xAB, 0xFF])]); // 0xAB unknown
        let rep = e.report();
        assert!(rep.coverage_ratio < 1.0);
        assert!(!rep.isa_complete);
    }

    #[test]
    fn test_report_summary_string() {
        let mut e = VmIsaComplete::new();
        e.populate_default_isa();
        e.lift_all(&[(0x0, vec![0x00, 0xFF])]);
        let rep = e.report();
        let s = rep.summary();
        assert!(s.contains("fns=1"));
    }

    #[test]
    fn test_vm_isa_report_coverage_percent() {
        let rep = VmIsaReport {
            opcodes_characterised: 1,
            opcodes_observed: 2,
            functions_lifted: 0,
            basic_blocks_total: 0,
            instructions_total: 0,
            coverage_ratio: 0.5,
            isa_complete: false,
            notes: vec![],
        };
        assert_eq!(rep.coverage_percent(), "50.0%");
    }

    #[test]
    fn test_read_le_u32() {
        let bytes = [0x01, 0x00, 0x00, 0x00];
        assert_eq!(VmIsaComplete::read_le(&bytes, 4), 1);
    }

    #[test]
    fn test_register_opcode_overwrite() {
        let mut e = VmIsaComplete::new();
        e.register_opcode(VmOpcode::new(0x10, "ADD", InsnCategory::Arithmetic, vec![], -1, false, 0.9));
        e.register_opcode(VmOpcode::new(0x10, "ADDX", InsnCategory::Arithmetic, vec![], -1, false, 0.8));
        assert_eq!(e.lookup(0x10).unwrap().mnemonic, "ADDX");
    }
}
