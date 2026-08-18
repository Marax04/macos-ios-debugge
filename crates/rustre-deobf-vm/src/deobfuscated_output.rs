//! Deobfuscated IL Output
//!
//! Produces the final deobfuscated output from VM lifting:
//! - [`DeobfuscatedFunction`] — a function with VM code replaced by lifted IL
//! - [`LiftedInstruction`] — a single lifted LLIL-equivalent instruction
//! - [`VmLiftResult`] — complete result of a VM lifting pass
//! - Metadata annotation and IR serialisation


use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::isa_reconstruction::{VirtualInstruction, VirtualIsa};
use crate::vm_cfg::VirtualCfg;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from deobfuscated output generation.
#[derive(Debug, Error)]
pub enum OutputError {
    #[error("function at {addr:#x} has no basic blocks")]
    EmptyFunction { addr: u64 },

    #[error("cannot emit output: no ISA has been loaded")]
    NoIsa,

    #[error("block {block_id:#x} references unknown opcode {opcode:#04x}")]
    UnknownOpcode { block_id: u64, opcode: u8 },

    #[error("serialisation failed: {reason}")]
    SerializationError { reason: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftedILOp — LLIL-equivalent opcodes
// ─────────────────────────────────────────────────────────────────────────────

/// LLIL-equivalent opcodes for the deobfuscated intermediate language.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LiftedILOp {
    // ── Memory ────────────────────────────────────────────────────────────────
    SetReg {
        dest: String,
        src: Box<LiftedExpr>,
    },
    Store {
        dest: Box<LiftedExpr>,
        src: Box<LiftedExpr>,
        size: u8,
    },
    // ── Control flow ─────────────────────────────────────────────────────────
    Jump {
        target: Box<LiftedExpr>,
    },
    JumpTo {
        targets: Vec<(u64, LiftedExpr)>,
    },
    Call {
        target: Box<LiftedExpr>,
    },
    Ret {
        value: Option<Box<LiftedExpr>>,
    },
    If {
        cond: Box<LiftedExpr>,
        true_target: u64,
        false_target: u64,
    },
    Goto {
        target: u64,
    },
    // ── No-op ────────────────────────────────────────────────────────────────
    Nop,
    // ── Trap / assert ────────────────────────────────────────────────────────
    Undef,
    Halt,
    // ── Intrinsics ───────────────────────────────────────────────────────────
    Intrinsic {
        name: String,
        outputs: Vec<LiftedExpr>,
        inputs: Vec<LiftedExpr>,
    },
}

/// An expression in the lifted IL (rvalue).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LiftedExpr {
    /// A concrete constant.
    Const { value: u64, size: u8 },
    /// A register or temporary value.
    Reg { name: String, size: u8 },
    /// Load from memory.
    Load { src: Box<Self>, size: u8 },
    /// Binary expression.
    BinOp {
        op: LiftedBinOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
        size: u8,
    },
    /// Unary expression.
    UnOp {
        op: LiftedUnOp,
        operand: Box<Self>,
        size: u8,
    },
    /// Sign-extend.
    SignExtend { src: Box<Self>, size: u8 },
    /// Zero-extend.
    ZeroExtend { src: Box<Self>, size: u8 },
}

impl LiftedExpr {
    /// Return a 64-bit register expression.
    pub fn reg64(name: impl Into<String>) -> Self {
        Self::Reg {
            name: name.into(),
            size: 8,
        }
    }
    /// Return a 32-bit constant expression.
    #[must_use]
    pub fn const32(value: u32) -> Self {
        Self::Const {
            value: u64::from(value),
            size: 4,
        }
    }
    /// Return a 64-bit constant expression.
    #[must_use]
    pub const fn const64(value: u64) -> Self {
        Self::Const { value, size: 8 }
    }

    /// Pretty-print the expression.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Const { value, size } => format!("{value:#x}:{size}"),
            Self::Reg { name, size } => format!("{name}:{size}"),
            Self::Load { src, size } => format!("*[{}]:{}", src.display(), size),
            Self::BinOp { op, lhs, rhs, .. } => {
                format!("({} {:?} {})", lhs.display(), op, rhs.display())
            }
            Self::UnOp { op, operand, .. } => format!("({:?} {})", op, operand.display()),
            Self::SignExtend { src, size } => format!("sext({}, {})", src.display(), size),
            Self::ZeroExtend { src, size } => format!("zext({}, {})", src.display(), size),
        }
    }
}

/// Binary operations in the lifted IL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LiftedBinOp {
    Add,
    Sub,
    Mul,
    DivU,
    DivS,
    And,
    Or,
    Xor,
    Shl,
    LshrU,
    AshrS,
    CmpEq,
    CmpNe,
    CmpLtU,
    CmpLeU,
    CmpLtS,
    CmpLeS,
    Rol,
    Ror,
}

/// Unary operations in the lifted IL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LiftedUnOp {
    Not,
    Neg,
    Bswap,
    Clz,
    Ctz,
    Popcnt,
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftedInstruction
// ─────────────────────────────────────────────────────────────────────────────

/// A single deobfuscated instruction in the output IL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftedInstruction {
    /// Original virtual instruction pointer.
    pub vip: u64,
    /// IL operation.
    pub op: LiftedILOp,
    /// Source virtual opcode.
    pub source_opcode: u8,
    /// IL instruction index within its basic block.
    pub index: usize,
    /// Human-readable textual representation.
    pub text: String,
    /// Any annotations (e.g. from pattern matching, confidence).
    pub annotations: HashMap<String, String>,
}

impl LiftedInstruction {
    /// Create a new lifted instruction.
    pub fn new(
        vip: u64,
        op: LiftedILOp,
        source_opcode: u8,
        index: usize,
        text: impl Into<String>,
    ) -> Self {
        Self {
            vip,
            op,
            source_opcode,
            index,
            text: text.into(),
            annotations: HashMap::new(),
        }
    }

    /// Add an annotation key-value pair.
    pub fn annotate(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.annotations.insert(key.into(), value.into());
    }

    /// Returns `true` if this instruction has any annotations.
    #[must_use]
    pub fn is_annotated(&self) -> bool {
        !self.annotations.is_empty()
    }

    /// Returns `true` if this is a control-flow IL instruction.
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(
            &self.op,
            LiftedILOp::Jump { .. }
                | LiftedILOp::JumpTo { .. }
                | LiftedILOp::Call { .. }
                | LiftedILOp::Ret { .. }
                | LiftedILOp::If { .. }
                | LiftedILOp::Goto { .. }
                | LiftedILOp::Halt
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftedBasicBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block in the deobfuscated IL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftedBasicBlock {
    /// Block ID (virtual entry VIP).
    pub id: u64,
    /// Lifted instructions in this block.
    pub instructions: Vec<LiftedInstruction>,
    /// Successor block IDs.
    pub successors: Vec<u64>,
    /// Predecessor block IDs.
    pub predecessors: Vec<u64>,
    /// Whether this block is the function entry.
    pub is_entry: bool,
    /// Whether this is a VM-exit block.
    pub is_vm_exit: bool,
    /// Whether this block is a loop header.
    pub is_loop_header: bool,
}

impl LiftedBasicBlock {
    /// Create a new empty lifted block.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self {
            id,
            instructions: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
            is_entry: false,
            is_vm_exit: false,
            is_loop_header: false,
        }
    }

    /// Number of IL instructions in this block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }
    /// Returns `true` if the block is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Append a lifted instruction.
    pub fn push(&mut self, insn: LiftedInstruction) {
        self.instructions.push(insn);
    }

    /// Return the terminator instruction of this block.
    #[must_use]
    pub fn terminator(&self) -> Option<&LiftedInstruction> {
        self.instructions.last().filter(|i| i.is_control_flow())
    }

    /// Pretty-print the block.
    #[must_use]
    pub fn display(&self) -> String {
        use std::fmt::Write as _;
        let mut s = format!("block_{:#x}:\n", self.id);
        for insn in &self.instructions {
            let _ = writeln!(s, "  [{:#06x}] {}", insn.vip, insn.text);
        }
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfuscatedFunction
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata annotations attached to a deobfuscated function.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionMetadata {
    /// Detected protector name.
    pub protector: Option<String>,
    /// Number of virtual instructions processed.
    pub virtual_instruction_count: usize,
    /// Number of lifted IL instructions produced.
    pub lifted_instruction_count: usize,
    /// Number of virtual basic blocks in the CFG.
    pub virtual_block_count: usize,
    /// Number of detected loops.
    pub loop_count: usize,
    /// Whether the function's CFG was reducible.
    pub cfg_reducible: bool,
    /// Confidence score from ISA reconstruction [0.0, 1.0].
    pub isa_confidence: f32,
    /// Human-readable analysis notes.
    pub notes: Vec<String>,
}

/// A function with its VM code replaced by the lifted intermediate language.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeobfuscatedFunction {
    /// Virtual address of the original function.
    pub address: u64,
    /// Name of the function (from symbols or synthesised).
    pub name: String,
    /// Lifted basic blocks in RPO order.
    pub blocks: Vec<LiftedBasicBlock>,
    /// Metadata / annotations.
    pub metadata: FunctionMetadata,
    /// Entry block ID.
    pub entry_block: u64,
    /// All exit block IDs (VM-exit or function return).
    pub exit_blocks: Vec<u64>,
}

impl DeobfuscatedFunction {
    /// Create a new function container.
    pub fn new(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
            blocks: Vec::new(),
            metadata: FunctionMetadata::default(),
            entry_block: address,
            exit_blocks: Vec::new(),
        }
    }

    /// Total number of IL instructions in the function.
    #[must_use]
    pub fn total_instructions(&self) -> usize {
        self.blocks.iter().map(LiftedBasicBlock::len).sum()
    }

    /// Total number of basic blocks.
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Find a block by ID.
    #[must_use]
    pub fn find_block(&self, id: u64) -> Option<&LiftedBasicBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Find the entry block.
    #[must_use]
    pub fn entry_block(&self) -> Option<&LiftedBasicBlock> {
        self.find_block(self.entry_block)
    }

    /// Emit the function as a plain-text listing.
    #[must_use]
    pub fn emit_text(&self) -> String {
        use std::fmt::Write as _;
        let mut s = format!(
            "; DeobfuscatedFunction: {} @ {:#x}\n",
            self.name, self.address
        );
        let _ = writeln!(
            s,
            "; {} blocks, {} IL insns, {} virtual insns, protector={:?}",
            self.block_count(),
            self.total_instructions(),
            self.metadata.virtual_instruction_count,
            self.metadata.protector,
        );
        s.push_str(";\n");
        for block in &self.blocks {
            s.push_str(&block.display());
        }
        s
    }

    /// Add a metadata note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.metadata.notes.push(note.into());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmLiftResult — complete result of a VM lifting run
// ─────────────────────────────────────────────────────────────────────────────

/// Status of a VM lifting operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiftStatus {
    /// Successfully lifted all virtual instructions.
    Success,
    /// Partially lifted; some opcodes were not recovered.
    Partial,
    /// Failed: no ISA could be recovered.
    Failed,
    /// Skipped: the input does not appear to be VM-protected.
    Skipped,
}

/// Complete result of a VM deobfuscation lifting pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmLiftResult {
    /// Status of the lift.
    pub status: LiftStatus,
    /// The deobfuscated function (if status is Success or Partial).
    pub function: Option<DeobfuscatedFunction>,
    /// The recovered virtual ISA.
    pub isa: Option<VirtualIsa>,
    /// Total time taken (microseconds) — 0 if not measured.
    pub elapsed_us: u64,
    /// Error message if status is Failed.
    pub error: Option<String>,
    /// Diagnostic warnings encountered during lifting.
    pub warnings: Vec<String>,
    /// Overall confidence in the lift quality [0.0, 1.0].
    pub overall_confidence: f32,
    /// Byte size of the original VM bytecode processed.
    pub bytecode_size: usize,
    /// Number of opcodes that were classified.
    pub classified_opcode_count: usize,
    /// Number of opcodes that remain unknown.
    pub unknown_opcode_count: usize,
}

impl VmLiftResult {
    /// Create a successful result.
    #[must_use]
    pub fn success(func: DeobfuscatedFunction, isa: VirtualIsa, confidence: f32) -> Self {
        let classified = isa
            .entries
            .values()
            .filter(|e| e.category != crate::isa_reconstruction::VirtualOpCategory::Unknown)
            .count();
        let unknown = isa.entries.len() - classified;
        Self {
            status: LiftStatus::Success,
            function: Some(func),
            isa: Some(isa),
            elapsed_us: 0,
            error: None,
            warnings: Vec::new(),
            overall_confidence: confidence,
            bytecode_size: 0,
            classified_opcode_count: classified,
            unknown_opcode_count: unknown,
        }
    }

    /// Create a failure result.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            status: LiftStatus::Failed,
            function: None,
            isa: None,
            elapsed_us: 0,
            error: Some(error.into()),
            warnings: Vec::new(),
            overall_confidence: 0.0,
            bytecode_size: 0,
            classified_opcode_count: 0,
            unknown_opcode_count: 0,
        }
    }

    /// Returns `true` if the lift was successful.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status == LiftStatus::Success
    }

    /// Returns `true` if there is a recovered function.
    #[must_use]
    pub const fn has_output(&self) -> bool {
        self.function.is_some()
    }

    /// Add a warning message.
    pub fn add_warning(&mut self, w: impl Into<String>) {
        self.warnings.push(w.into());
    }

    /// Percentage of opcodes classified.
    #[must_use]
    pub fn classification_rate(&self) -> f32 {
        let total = self.classified_opcode_count + self.unknown_opcode_count;
        if total == 0 {
            return 0.0;
        }
        f32::from(u16::try_from(self.classified_opcode_count).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(total).unwrap_or(u16::MAX))
    }

    /// Return a one-line summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        match self.status {
            LiftStatus::Success => format!(
                "Lifted successfully: {:.0}% confidence, {}/{} opcodes classified",
                self.overall_confidence * 100.0,
                self.classified_opcode_count,
                self.classified_opcode_count + self.unknown_opcode_count,
            ),
            LiftStatus::Partial => format!(
                "Partial lift: {:.0}% classified",
                self.classification_rate() * 100.0,
            ),
            LiftStatus::Failed => format!(
                "Lift failed: {}",
                self.error.as_deref().unwrap_or("unknown error"),
            ),
            LiftStatus::Skipped => "Not VM-protected; lift skipped.".to_owned(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ILEmitter — translate virtual instructions to lifted IL
// ─────────────────────────────────────────────────────────────────────────────

/// Translates decoded [`VirtualInstruction`]s into [`LiftedInstruction`]s
/// using the recovered [`VirtualIsa`].
#[derive(Debug, Clone, Default)]
pub struct ILEmitter {
    /// Stack depth tracking (for push/pop balance analysis).
    stack_depth: i32,
    /// Temporary register counter.
    tmp_counter: u32,
}

impl ILEmitter {
    /// Create a new emitter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new temporary register name.
    fn next_tmp(&mut self) -> String {
        let name = format!("t{}", self.tmp_counter);
        self.tmp_counter += 1;
        name
    }

    /// Emit a single lifted instruction from a virtual instruction.
    ///
    /// Uses the ISA entry to determine the correct IL operation.
    ///
    /// # Errors
    /// Currently infallible — always returns `Ok`. The `Result` return type is
    /// reserved for future error-propagation from ISA lookups.
    pub fn emit(
        &mut self,
        insn: &VirtualInstruction,
        isa: &VirtualIsa,
        index: usize,
    ) -> Result<LiftedInstruction, OutputError> {
        let entry = isa.lookup(insn.opcode);
        let category = entry.map_or(insn.category, |e| e.category);
        let mnemonic = entry.map_or(insn.mnemonic.as_str(), |e| e.mnemonic.as_str());
        let (op, text) = self.category_to_il(insn.vip, insn.opcode, category, mnemonic);
        Ok(LiftedInstruction::new(insn.vip, op, insn.opcode, index, text))
    }

    fn category_to_il(
        &mut self,
        vip: u64,
        opcode: u8,
        category: crate::isa_reconstruction::VirtualOpCategory,
        mnemonic: &str,
    ) -> (LiftedILOp, String) {
        use crate::isa_reconstruction::VirtualOpCategory;
        match category {
            VirtualOpCategory::Nop => (LiftedILOp::Nop, format!("{vip:#06x}: nop")),
            VirtualOpCategory::Halt => (LiftedILOp::Halt, format!("{vip:#06x}: halt")),
            VirtualOpCategory::Push => {
                self.stack_depth += 1;
                let dst = self.next_tmp();
                let text = format!("{vip:#06x}: {mnemonic} → {dst}");
                (LiftedILOp::SetReg { dest: dst, src: Box::new(LiftedExpr::const64(0)) }, text)
            }
            VirtualOpCategory::Pop => {
                self.stack_depth -= 1;
                let src = self.next_tmp();
                let text = format!("{vip:#06x}: {mnemonic} ← stack");
                (LiftedILOp::SetReg { dest: "vr0".to_owned(), src: Box::new(LiftedExpr::reg64(src)) }, text)
            }
            VirtualOpCategory::Arithmetic | VirtualOpCategory::Logic => {
                self.stack_depth -= 1;
                let tmp = self.next_tmp();
                let il_op = map_category_to_binop(category);
                let text = format!("{vip:#06x}: {mnemonic} tos, nos → {tmp}");
                (LiftedILOp::SetReg {
                    dest: tmp,
                    src: Box::new(LiftedExpr::BinOp {
                        op: il_op,
                        lhs: Box::new(LiftedExpr::reg64("tos")),
                        rhs: Box::new(LiftedExpr::reg64("nos")),
                        size: 8,
                    }),
                }, text)
            }
            VirtualOpCategory::Load => {
                let tmp = self.next_tmp();
                let text = format!("{vip:#06x}: {mnemonic} *[tos] → {tmp}");
                (LiftedILOp::SetReg {
                    dest: tmp,
                    src: Box::new(LiftedExpr::Load { src: Box::new(LiftedExpr::reg64("tos")), size: 8 }),
                }, text)
            }
            VirtualOpCategory::Store => {
                self.stack_depth -= 2;
                (LiftedILOp::Store {
                    dest: Box::new(LiftedExpr::reg64("tos")),
                    src: Box::new(LiftedExpr::reg64("nos")),
                    size: 8,
                }, format!("{vip:#06x}: {mnemonic} *[tos] = nos"))
            }
            VirtualOpCategory::Jump => (
                LiftedILOp::Jump { target: Box::new(LiftedExpr::reg64("tos")) },
                format!("{vip:#06x}: {mnemonic} tos"),
            ),
            VirtualOpCategory::CondBranch => (
                LiftedILOp::If { cond: Box::new(LiftedExpr::reg64("flags_zf")), true_target: 0, false_target: 0 },
                format!("{vip:#06x}: {mnemonic} <cond>"),
            ),
            VirtualOpCategory::Call => (
                LiftedILOp::Call { target: Box::new(LiftedExpr::reg64("tos")) },
                format!("{vip:#06x}: {mnemonic} tos"),
            ),
            VirtualOpCategory::Return => (LiftedILOp::Ret { value: None }, format!("{vip:#06x}: ret")),
            VirtualOpCategory::Compare => {
                let tmp = self.next_tmp();
                let text = format!("{vip:#06x}: {mnemonic} tos, nos");
                (LiftedILOp::SetReg {
                    dest: tmp,
                    src: Box::new(LiftedExpr::BinOp {
                        op: LiftedBinOp::CmpEq,
                        lhs: Box::new(LiftedExpr::reg64("tos")),
                        rhs: Box::new(LiftedExpr::reg64("nos")),
                        size: 1,
                    }),
                }, text)
            }
            VirtualOpCategory::Unknown => (
                LiftedILOp::Undef,
                format!("{vip:#06x}: ??? opcode={opcode:#04x}"),
            ),
        }
    }

    /// Emit all instructions in a virtual block and return a lifted block.
    ///
    /// # Errors
    /// Propagates any error returned by [`Self::emit`] for an individual instruction.
    pub fn emit_block(
        &mut self,
        block_id: u64,
        insns: &[VirtualInstruction],
        isa: &VirtualIsa,
    ) -> Result<LiftedBasicBlock, OutputError> {
        let mut lifted = LiftedBasicBlock::new(block_id);
        for (idx, insn) in insns.iter().enumerate() {
            let li = self.emit(insn, isa, idx)?;
            lifted.push(li);
        }
        Ok(lifted)
    }
}

const fn map_category_to_binop(cat: crate::isa_reconstruction::VirtualOpCategory) -> LiftedBinOp {
    use crate::isa_reconstruction::VirtualOpCategory;
    match cat {
        VirtualOpCategory::Logic => LiftedBinOp::Xor,
        _ => LiftedBinOp::Add,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmOutputPipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Combines the virtual CFG and ISA to produce a [`VmLiftResult`].
#[derive(Debug, Clone, Default)]
pub struct VmOutputPipeline;

impl VmOutputPipeline {
    /// Create a new pipeline.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Produce a [`VmLiftResult`] from a [`VirtualCfg`] and a [`VirtualIsa`].
    pub fn emit(
        &self,
        cfg: &VirtualCfg,
        isa: &VirtualIsa,
        function_addr: u64,
        function_name: impl Into<String>,
    ) -> VmLiftResult {
        let mut func = DeobfuscatedFunction::new(function_addr, function_name);
        func.entry_block = cfg.entry;
        func.metadata.virtual_block_count = cfg.block_count();
        func.metadata.loop_count = cfg.loops.len();
        func.metadata.cfg_reducible = cfg.is_reducible;
        func.metadata.isa_confidence = isa.average_confidence();
        func.metadata.virtual_instruction_count = cfg.total_instructions;

        let mut emitter = ILEmitter::new();
        let mut warnings = Vec::new();

        for block in cfg.blocks.values() {
            match emitter.emit_block(block.id, &block.instructions, isa) {
                Ok(mut lifted) => {
                    lifted.is_entry = block.is_entry;
                    lifted.is_vm_exit = block.is_vm_exit;
                    lifted.is_loop_header = block.is_loop_header;
                    lifted.successors.clone_from(&block.successors);
                    lifted.predecessors.clone_from(&block.predecessors);
                    if block.is_vm_exit {
                        func.exit_blocks.push(block.id);
                    }
                    func.metadata.lifted_instruction_count += lifted.len();
                    func.blocks.push(lifted);
                }
                Err(e) => {
                    warnings.push(format!("Block {:#x}: {}", block.id, e));
                }
            }
        }

        // Sort blocks by ID for deterministic output.
        func.blocks.sort_by_key(|b| b.id);

        let classified = isa
            .entries
            .values()
            .filter(|e| e.category != crate::isa_reconstruction::VirtualOpCategory::Unknown)
            .count();
        let unknown = isa.entries.len() - classified;
        let confidence = isa.average_confidence();

        let mut result = VmLiftResult::success(func, isa.clone(), confidence);
        result.warnings = warnings;
        result.classified_opcode_count = classified;
        result.unknown_opcode_count = unknown;
        result.bytecode_size = cfg.total_instructions;

        if !result.warnings.is_empty() {
            result.status = LiftStatus::Partial;
        }

        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa_reconstruction::{VirtualIsa, VirtualIsaEntry, VirtualOpCategory};

    fn make_isa() -> VirtualIsa {
        let mut isa = VirtualIsa::new(64, true);
        isa.register(VirtualIsaEntry::new(
            0x00,
            VirtualOpCategory::Nop,
            "NOP",
            0,
            1,
            0x1000,
            0.9,
        ))
        .unwrap();
        isa.register(VirtualIsaEntry::new(
            0x10,
            VirtualOpCategory::Arithmetic,
            "ADD",
            0,
            1,
            0x1100,
            0.85,
        ))
        .unwrap();
        isa.register(VirtualIsaEntry::new(
            0x30,
            VirtualOpCategory::Jump,
            "JMP",
            0,
            1,
            0x1200,
            0.95,
        ))
        .unwrap();
        isa.register(VirtualIsaEntry::new(
            0xFF,
            VirtualOpCategory::Halt,
            "HALT",
            0,
            1,
            0x1300,
            1.0,
        ))
        .unwrap();
        isa
    }

    fn make_insn(opcode: u8, cat: VirtualOpCategory, vip: u64) -> VirtualInstruction {
        VirtualInstruction::new(opcode, cat, vec![], vip, 1, 0x1000, "TEST")
    }

    #[test]
    fn test_lifted_expr_display() {
        let e = LiftedExpr::const32(42);
        assert!(e.display().contains("2a")); // 42 in hex
        let r = LiftedExpr::reg64("EAX");
        assert_eq!(r.display(), "EAX:8");
    }

    #[test]
    fn test_lifted_instruction_new_and_annotate() {
        let mut insn = LiftedInstruction::new(0x100, LiftedILOp::Nop, 0x00, 0, "nop");
        assert!(!insn.is_annotated());
        insn.annotate("confidence", "0.9");
        assert!(insn.is_annotated());
        assert_eq!(insn.annotations.get("confidence").unwrap(), "0.9");
    }

    #[test]
    fn test_lifted_instruction_is_control_flow() {
        let cf = LiftedInstruction::new(
            0,
            LiftedILOp::Jump {
                target: Box::new(LiftedExpr::const64(0)),
            },
            0,
            0,
            "",
        );
        assert!(cf.is_control_flow());
        let not_cf = LiftedInstruction::new(0, LiftedILOp::Nop, 0, 0, "");
        assert!(!not_cf.is_control_flow());
    }

    #[test]
    fn test_lifted_basic_block_empty() {
        let block = LiftedBasicBlock::new(0x1000);
        assert!(block.is_empty());
        assert_eq!(block.len(), 0);
        assert!(block.terminator().is_none());
    }

    #[test]
    fn test_lifted_basic_block_push_display() {
        let mut block = LiftedBasicBlock::new(0x100);
        block.push(LiftedInstruction::new(0x100, LiftedILOp::Nop, 0, 0, "nop"));
        assert_eq!(block.len(), 1);
        let d = block.display();
        assert!(d.contains("block_0x100"));
        assert!(d.contains("nop"));
    }

    #[test]
    fn test_il_emitter_nop() {
        let isa = make_isa();
        let mut emitter = ILEmitter::new();
        let insn = make_insn(0x00, VirtualOpCategory::Nop, 0x100);
        let li = emitter.emit(&insn, &isa, 0).unwrap();
        assert!(matches!(li.op, LiftedILOp::Nop));
        assert_eq!(li.vip, 0x100);
    }

    #[test]
    fn test_il_emitter_halt() {
        let isa = make_isa();
        let mut emitter = ILEmitter::new();
        let insn = make_insn(0xFF, VirtualOpCategory::Halt, 0x200);
        let li = emitter.emit(&insn, &isa, 0).unwrap();
        assert!(matches!(li.op, LiftedILOp::Halt));
    }

    #[test]
    fn test_il_emitter_push_stack_depth() {
        let isa = make_isa();
        let mut emitter = ILEmitter::new();
        // Use a custom push-category instruction not in ISA to test fallback.
        let insn = make_insn(0xAA, VirtualOpCategory::Push, 0x300);
        let li = emitter.emit(&insn, &isa, 0).unwrap();
        assert!(matches!(li.op, LiftedILOp::SetReg { .. }));
    }

    #[test]
    fn test_il_emitter_block() {
        let isa = make_isa();
        let mut emitter = ILEmitter::new();
        let insns = vec![
            make_insn(0x00, VirtualOpCategory::Nop, 0x100),
            make_insn(0xFF, VirtualOpCategory::Halt, 0x101),
        ];
        let block = emitter.emit_block(0x100, &insns, &isa).unwrap();
        assert_eq!(block.len(), 2);
    }

    #[test]
    fn test_deobfuscated_function_emit_text() {
        let func = DeobfuscatedFunction::new(0x4000, "vm_func_0");
        let text = func.emit_text();
        assert!(text.contains("vm_func_0"));
        assert!(text.contains("4000"));
    }

    #[test]
    fn test_vm_lift_result_success() {
        let isa = make_isa();
        let func = DeobfuscatedFunction::new(0x1000, "f");
        let result = VmLiftResult::success(func, isa, 0.85);
        assert!(result.is_ok());
        assert!(result.has_output());
        assert!(result.summary().contains("Lifted successfully"));
    }

    #[test]
    fn test_vm_lift_result_failure() {
        let result = VmLiftResult::failure("ISA not loaded");
        assert!(!result.is_ok());
        assert!(!result.has_output());
        assert!(result.summary().contains("failed"));
    }

    #[test]
    fn test_vm_lift_result_classification_rate() {
        let isa = make_isa();
        let func = DeobfuscatedFunction::new(0, "f");
        let mut result = VmLiftResult::success(func, isa, 0.9);
        result.classified_opcode_count = 8;
        result.unknown_opcode_count = 2;
        let rate = result.classification_rate();
        assert!((rate - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_function_metadata_defaults() {
        let md = FunctionMetadata::default();
        assert!(md.protector.is_none());
        assert_eq!(md.virtual_instruction_count, 0);
    }

    #[test]
    fn test_deobfuscated_function_find_block() {
        let mut func = DeobfuscatedFunction::new(0x1000, "f");
        let block = LiftedBasicBlock::new(0x1000);
        func.blocks.push(block);
        assert!(func.find_block(0x1000).is_some());
        assert!(func.find_block(0x2000).is_none());
    }
}
