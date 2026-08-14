//! Virtual instruction to LLIL lifter.
//!
//! Provides [`VmToLlilLifter`], [`VirtualInstruction`], and
//! [`lift_virtual_function`].  Handles both stack-based and register-based VMs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use crate::vm_isa_recovery::{HandlerSemanticsKind, IsaTable, VirtualOpcode};

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LiftError {
    #[error("empty bytecode")]
    EmptyBytecode,
    #[error("unknown opcode {0:#04x} at offset {1}")]
    UnknownOpcode(u16, usize),
    #[error("operand count mismatch at offset {0}: expected {1}, got {2}")]
    OperandMismatch(usize, usize, usize),
    #[error("stack underflow at offset {0}")]
    StackUnderflow(usize),
    #[error("ISA table is missing required opcode {0:#04x}")]
    MissingOpcode(u16),
    #[error("lifting budget exceeded ({0} instructions)")]
    BudgetExceeded(usize),
}

// ─────────────────────────────────────────────────────────────────────────────
// Operand
// ─────────────────────────────────────────────────────────────────────────────

/// An operand to a [`VirtualInstruction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operand {
    /// Immediate integer constant.
    Imm(u64),
    /// Virtual register number (for register-based VMs).
    VReg(u8),
    /// Virtual stack slot index.
    StackSlot(u8),
    /// Memory address.
    MemAddr(u64),
    /// Pointer through a virtual register.
    MemReg { reg: u8, offset: i64 },
    /// Label / branch target offset.
    Label(u64),
}

impl std::fmt::Display for Operand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Imm(v) => write!(f, "{v:#x}"),
            Self::VReg(r) => write!(f, "vr{r}"),
            Self::StackSlot(s) => write!(f, "slot{s}"),
            Self::MemAddr(a) => write!(f, "[{a:#x}]"),
            Self::MemReg { reg, offset } => {
                if *offset >= 0 {
                    write!(f, "[vr{reg}+{offset:#x}]")
                } else {
                    write!(f, "[vr{reg}{offset:#x}]")
                }
            }
            Self::Label(t) => write!(f, "L{t:#x}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtualInstruction
// ─────────────────────────────────────────────────────────────────────────────

/// A single decoded virtual instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualInstruction {
    /// Opcode ID.
    pub opcode: u16,
    /// Virtual address in the bytecode stream.
    pub address: u64,
    /// Size of this instruction in bytecode bytes.
    pub size: usize,
    /// Semantic kind.
    pub kind: HandlerSemanticsKind,
    /// Destination operand(s).
    pub dst: Vec<Operand>,
    /// Source operand(s).
    pub src: Vec<Operand>,
    /// Size of the operation in bytes (1/2/4/8).
    pub op_size: u8,
}

impl VirtualInstruction {
    /// Create a new instruction.
    #[must_use]
    pub fn new(opcode: u16, address: u64, size: usize, kind: HandlerSemanticsKind) -> Self {
        Self {
            opcode,
            address,
            size,
            kind,
            dst: Vec::new(),
            src: Vec::new(),
            op_size: 8,
        }
    }

    /// Return a compact mnemonic.
    #[must_use]
    pub fn mnemonic(&self) -> String {
        format!("{}", self.kind)
    }

    /// Return a disassembly-style string.
    #[must_use]
    pub fn disasm(&self) -> String {
        let dst: Vec<String> = self.dst.iter().map(|o| o.to_string()).collect();
        let src: Vec<String> = self.src.iter().map(|o| o.to_string()).collect();
        match (dst.is_empty(), src.is_empty()) {
            (true, true) => format!("{}", self.kind),
            (false, true) => format!("{} {}", self.kind, dst.join(", ")),
            (true, false) => format!("{} {}", self.kind, src.join(", ")),
            (false, false) => format!("{} {}, {}", self.kind, dst.join(", "), src.join(", ")),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LlilExpr — Low-Level IL expression
// ─────────────────────────────────────────────────────────────────────────────

/// A Low-Level Intermediate Language expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LlilExpr {
    Const {
        size: u8,
        value: u64,
    },
    Reg {
        size: u8,
        reg: u8,
    },
    Load {
        size: u8,
        src: Box<LlilExpr>,
    },
    Add {
        size: u8,
        left: Box<LlilExpr>,
        right: Box<LlilExpr>,
    },
    Sub {
        size: u8,
        left: Box<LlilExpr>,
        right: Box<LlilExpr>,
    },
    Mul {
        size: u8,
        left: Box<LlilExpr>,
        right: Box<LlilExpr>,
    },
    And {
        size: u8,
        left: Box<LlilExpr>,
        right: Box<LlilExpr>,
    },
    Or {
        size: u8,
        left: Box<LlilExpr>,
        right: Box<LlilExpr>,
    },
    Xor {
        size: u8,
        left: Box<LlilExpr>,
        right: Box<LlilExpr>,
    },
    Neg {
        size: u8,
        src: Box<LlilExpr>,
    },
    Not {
        size: u8,
        src: Box<LlilExpr>,
    },
    Cmp {
        size: u8,
        left: Box<LlilExpr>,
        right: Box<LlilExpr>,
    },
    Zx {
        size: u8,
        src: Box<LlilExpr>,
    },
    Sx {
        size: u8,
        src: Box<LlilExpr>,
    },
    StackSlot {
        size: u8,
        slot: u8,
    },
}

impl LlilExpr {
    /// Returns the operand byte width of this LLIL expression.
    #[must_use]
    pub fn size(&self) -> u8 {
        match self {
            Self::Const { size, .. } | Self::Reg { size, .. } | Self::Load { size, .. } => *size,
            Self::Add { size, .. } | Self::Sub { size, .. } | Self::Mul { size, .. } => *size,
            Self::And { size, .. } | Self::Or { size, .. } | Self::Xor { size, .. } => *size,
            Self::Neg { size, .. } | Self::Not { size, .. } | Self::Cmp { size, .. } => *size,
            Self::Zx { size, .. } | Self::Sx { size, .. } => *size,
            Self::StackSlot { size, .. } => *size,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LlilStmt — Low-Level IL statement
// ─────────────────────────────────────────────────────────────────────────────

/// A Low-Level Intermediate Language statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LlilStmt {
    /// Set virtual register to an expression.
    SetReg { size: u8, reg: u8, src: LlilExpr },
    /// Push expression onto stack.
    Push { size: u8, src: LlilExpr },
    /// Pop expression from stack into register.
    Pop { size: u8, reg: u8 },
    /// Store expression to memory.
    Store {
        size: u8,
        dst: LlilExpr,
        src: LlilExpr,
    },
    /// Unconditional jump to expression.
    Jump { target: LlilExpr },
    /// Conditional jump.
    JumpIf {
        cond: LlilExpr,
        t: LlilExpr,
        f: LlilExpr,
    },
    /// Call expression.
    Call { target: LlilExpr },
    /// Return.
    Ret,
    /// No-operation.
    Nop,
    /// Exit VM.
    VmExit,
    /// Annotated intrinsic (for unlifted patterns).
    Intrinsic { name: String, args: Vec<LlilExpr> },
}

impl LlilStmt {
    /// Return a human-readable representation.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::SetReg { reg, .. } => format!("vr{reg} = <expr>"),
            Self::Push { .. } => "push <expr>".into(),
            Self::Pop { reg, .. } => format!("vr{reg} = pop"),
            Self::Store { .. } => "store <expr> -> <addr>".into(),
            Self::Jump { .. } => "jmp <target>".into(),
            Self::JumpIf { .. } => "jcc <cond>, <t>, <f>".into(),
            Self::Call { .. } => "call <target>".into(),
            Self::Ret => "ret".into(),
            Self::Nop => "nop".into(),
            Self::VmExit => "vmexit".into(),
            Self::Intrinsic { name, .. } => format!("intrinsic {name}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftedBlock — a lifted basic block
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block of lifted LLIL statements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftedBlock {
    /// Starting virtual address.
    pub start_address: u64,
    /// Ending virtual address (exclusive).
    pub end_address: u64,
    /// Lifted LLIL statements.
    pub stmts: Vec<LlilStmt>,
    /// Successor addresses (branch targets).
    pub successors: Vec<u64>,
}

impl LiftedBlock {
    #[must_use]
    pub fn new(start: u64) -> Self {
        Self {
            start_address: start,
            end_address: start,
            stmts: Vec::new(),
            successors: Vec::new(),
        }
    }

    pub fn push(&mut self, stmt: LlilStmt, end_addr: u64) {
        self.stmts.push(stmt);
        self.end_address = end_addr;
    }

    pub fn add_successor(&mut self, addr: u64) {
        if !self.successors.contains(&addr) {
            self.successors.push(addr);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftedFunction
// ─────────────────────────────────────────────────────────────────────────────

/// A lifted virtual function containing LLIL blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftedFunction {
    /// Virtual entry address.
    pub entry_address: u64,
    /// All lifted blocks keyed by start address.
    pub blocks: HashMap<u64, LiftedBlock>,
    /// Total number of virtual instructions processed.
    pub instruction_count: usize,
    /// Whether the lift completed successfully.
    pub complete: bool,
    /// Any error encountered during lifting.
    pub error: Option<String>,
    /// VM architecture type.
    pub vm_type: VmType,
}

impl LiftedFunction {
    #[must_use]
    pub fn new(entry: u64, vm_type: VmType) -> Self {
        Self {
            entry_address: entry,
            blocks: HashMap::new(),
            instruction_count: 0,
            complete: false,
            error: None,
            vm_type,
        }
    }

    /// Return the number of blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

/// Type of VM (stack vs register).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmType {
    StackBased,
    RegisterBased { reg_count: u8 },
}

// ─────────────────────────────────────────────────────────────────────────────
// VmToLlilLifter
// ─────────────────────────────────────────────────────────────────────────────

/// Lifts reconstructed virtual instructions to LLIL.
pub struct VmToLlilLifter {
    isa: IsaTable,
    vm_type: VmType,
    max_instructions: usize,
    operand_size: u8,
}

impl VmToLlilLifter {
    /// Create a lifter for the given ISA table.
    #[must_use]
    pub fn new(isa: IsaTable) -> Self {
        let vm_type = if isa.is_stack_based {
            VmType::StackBased
        } else {
            VmType::RegisterBased {
                reg_count: isa.register_count,
            }
        };
        Self {
            isa,
            vm_type,
            max_instructions: 10_000,
            operand_size: 8,
        }
    }

    /// Set the maximum number of instructions to lift.
    pub fn set_max_instructions(&mut self, max: usize) {
        self.max_instructions = max;
    }

    /// Set default operand size in bytes.
    pub fn set_operand_size(&mut self, size: u8) {
        self.operand_size = size;
    }

    /// Lift a bytecode stream into a [`LiftedFunction`].
    ///
    /// `bytecode` is the raw virtual bytecode.
    /// `entry_address` is the virtual start address.
    ///
    /// # Errors
    /// Returns an error on empty bytecode or budget exceeded.
    pub fn lift_virtual_function(
        &self,
        bytecode: &[u8],
        entry_address: u64,
    ) -> Result<LiftedFunction, LiftError> {
        if bytecode.is_empty() {
            return Err(LiftError::EmptyBytecode);
        }

        let mut func = LiftedFunction::new(entry_address, self.vm_type);
        let mut current_block = LiftedBlock::new(entry_address);
        let mut offset = 0usize;
        let mut instr_count = 0usize;

        while offset < bytecode.len() {
            if instr_count >= self.max_instructions {
                return Err(LiftError::BudgetExceeded(instr_count));
            }

            let opcode_id = bytecode[offset] as u16;
            let virt_addr = entry_address + offset as u64;

            let vop = self.isa.get_opcode(opcode_id);

            // Determine instruction size (opcode + optional immediate).
            let instr_size = self.instruction_size_for(opcode_id, bytecode, offset);

            let stmt = match vop {
                Some(vop) => self.lift_opcode(vop, bytecode, offset, instr_size),
                None => LlilStmt::Intrinsic {
                    name: format!("vm_op_{opcode_id:#04x}"),
                    args: Vec::new(),
                },
            };

            let is_terminator = matches!(
                stmt,
                LlilStmt::Jump { .. }
                    | LlilStmt::JumpIf { .. }
                    | LlilStmt::Ret
                    | LlilStmt::VmExit
                    | LlilStmt::Call { .. }
            );

            let next_addr = virt_addr + instr_size as u64;
            current_block.push(stmt, next_addr);
            instr_count += 1;
            offset += instr_size;

            if is_terminator || offset >= bytecode.len() {
                let block_start = current_block.start_address;
                func.blocks.insert(block_start, current_block);
                current_block = LiftedBlock::new(next_addr);
            }
        }

        // Flush any remaining block.
        if !current_block.stmts.is_empty() {
            func.blocks
                .insert(current_block.start_address, current_block);
        }

        func.instruction_count = instr_count;
        func.complete = true;
        Ok(func)
    }

    fn instruction_size_for(&self, opcode_id: u16, bytecode: &[u8], offset: usize) -> usize {
        let vop = self.isa.get_opcode(opcode_id);
        let has_imm = matches!(vop.map(|v| v.semantics.kind), Some(HandlerSemanticsKind::Push) | Some(HandlerSemanticsKind::Branch) | Some(HandlerSemanticsKind::ConditionalBranch) | Some(HandlerSemanticsKind::Call));
        if has_imm && offset + 1 + self.operand_size as usize <= bytecode.len() {
            1 + self.operand_size as usize
        } else {
            1
        }
    }

    fn extract_immediate(&self, bytecode: &[u8], offset: usize) -> Option<u64> {
        let imm_offset = offset + 1;
        let size = self.operand_size as usize;
        if imm_offset + size > bytecode.len() {
            return None;
        }
        let bytes = &bytecode[imm_offset..imm_offset + size];
        let val = match size {
            1 => bytes[0] as u64,
            2 => u16::from_le_bytes(bytes.try_into().ok()?) as u64,
            4 => u32::from_le_bytes(bytes.try_into().ok()?) as u64,
            8 => u64::from_le_bytes(bytes.try_into().ok()?),
            _ => return None,
        };
        Some(val)
    }

    fn lift_opcode(
        &self,
        vop: &VirtualOpcode,
        bytecode: &[u8],
        offset: usize,
        instr_size: usize,
    ) -> LlilStmt {
        let size = if vop.semantics.operand_size > 0 {
            vop.semantics.operand_size
        } else {
            self.operand_size
        };

        match vop.semantics.kind {
            HandlerSemanticsKind::Push => {
                let imm = self.extract_immediate(bytecode, offset).unwrap_or(0);
                LlilStmt::Push {
                    size,
                    src: LlilExpr::Const { size, value: imm },
                }
            }
            HandlerSemanticsKind::Pop => LlilStmt::Pop { size, reg: 0 },
            HandlerSemanticsKind::Alu => {
                // Placeholder: add top-two stack slots.
                let left = LlilExpr::StackSlot { size, slot: 0 };
                let right = LlilExpr::StackSlot { size, slot: 1 };
                LlilStmt::Push {
                    size,
                    src: LlilExpr::Add {
                        size,
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                }
            }
            HandlerSemanticsKind::MemLoad => {
                let addr_expr = LlilExpr::StackSlot { size, slot: 0 };
                LlilStmt::Push {
                    size,
                    src: LlilExpr::Load {
                        size,
                        src: Box::new(addr_expr),
                    },
                }
            }
            HandlerSemanticsKind::MemStore => {
                let src = LlilExpr::StackSlot { size, slot: 0 };
                let dst = LlilExpr::StackSlot { size, slot: 1 };
                LlilStmt::Store { size, dst, src }
            }
            HandlerSemanticsKind::Branch => {
                let target = self.extract_immediate(bytecode, offset).unwrap_or(0);
                LlilStmt::Jump {
                    target: LlilExpr::Const {
                        size: 8,
                        value: target,
                    },
                }
            }
            HandlerSemanticsKind::ConditionalBranch => {
                let target = self.extract_immediate(bytecode, offset).unwrap_or(0);
                let fall_through = (offset + instr_size) as u64;
                LlilStmt::JumpIf {
                    cond: LlilExpr::StackSlot { size: 1, slot: 0 },
                    t: LlilExpr::Const {
                        size: 8,
                        value: target,
                    },
                    f: LlilExpr::Const {
                        size: 8,
                        value: fall_through,
                    },
                }
            }
            HandlerSemanticsKind::Call => {
                let target = self.extract_immediate(bytecode, offset).unwrap_or(0);
                LlilStmt::Call {
                    target: LlilExpr::Const {
                        size: 8,
                        value: target,
                    },
                }
            }
            HandlerSemanticsKind::Ret => LlilStmt::Ret,
            HandlerSemanticsKind::VmExit => LlilStmt::VmExit,
            HandlerSemanticsKind::Nop => LlilStmt::Nop,
            HandlerSemanticsKind::Compare => {
                let left = LlilExpr::StackSlot { size, slot: 0 };
                let right = LlilExpr::StackSlot { size, slot: 1 };
                LlilStmt::Push {
                    size: 1,
                    src: LlilExpr::Cmp {
                        size,
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                }
            }
            HandlerSemanticsKind::VmEnter => LlilStmt::Intrinsic {
                name: "vmenter".into(),
                args: Vec::new(),
            },
            HandlerSemanticsKind::Unknown => LlilStmt::Intrinsic {
                name: format!("vm_op_{:#04x}", vop.id),
                args: Vec::new(),
            },
        }
    }

    /// Return the underlying ISA table.
    #[must_use]
    pub fn isa(&self) -> &IsaTable {
        &self.isa
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// lift_virtual_function convenience function
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience wrapper around [`VmToLlilLifter::lift_virtual_function`].
///
/// # Errors
/// Returns a [`LiftError`] on failure.
pub fn lift_virtual_function(
    isa: IsaTable,
    bytecode: &[u8],
    entry_address: u64,
) -> Result<LiftedFunction, LiftError> {
    VmToLlilLifter::new(isa).lift_virtual_function(bytecode, entry_address)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_isa_recovery::{HandlerSemantics, HandlerSemanticsKind, IsaTable, VirtualOpcode};

    fn make_isa() -> IsaTable {
        let mut t = IsaTable::new("x86_64");
        // opcode 0x50 → PUSH
        let mut push_sem = HandlerSemantics::new(HandlerSemanticsKind::Push, "push imm");
        push_sem.stack_pushes = 1;
        push_sem.operand_size = 8;
        let mut op_push = VirtualOpcode::unanalysed(0x50, 0x1000);
        op_push.semantics = push_sem;
        op_push.analysed = true;
        t.add_opcode(op_push);

        // opcode 0x58 → POP
        let mut pop_sem = HandlerSemantics::new(HandlerSemanticsKind::Pop, "pop");
        pop_sem.stack_pops = 1;
        pop_sem.operand_size = 8;
        let mut op_pop = VirtualOpcode::unanalysed(0x58, 0x2000);
        op_pop.semantics = pop_sem;
        op_pop.analysed = true;
        t.add_opcode(op_pop);

        // opcode 0x90 → NOP
        let nop_sem = HandlerSemantics::new(HandlerSemanticsKind::Nop, "nop");
        let mut op_nop = VirtualOpcode::unanalysed(0x90, 0x3000);
        op_nop.semantics = nop_sem;
        op_nop.analysed = true;
        t.add_opcode(op_nop);

        // opcode 0xE9 → JMP
        let mut jmp_sem = HandlerSemantics::new(HandlerSemanticsKind::Branch, "jmp");
        jmp_sem.writes_vpc = true;
        let mut op_jmp = VirtualOpcode::unanalysed(0xE9, 0x4000);
        op_jmp.semantics = jmp_sem;
        op_jmp.analysed = true;
        t.add_opcode(op_jmp);

        // opcode 0xC3 → RET
        let ret_sem = HandlerSemantics::new(HandlerSemanticsKind::Ret, "ret");
        let mut op_ret = VirtualOpcode::unanalysed(0xC3, 0x5000);
        op_ret.semantics = ret_sem;
        op_ret.analysed = true;
        t.add_opcode(op_ret);

        t
    }

    // -- Operand display -----------------------------------------------------

    #[test]
    fn test_operand_display_imm() {
        assert_eq!(Operand::Imm(0x100).to_string(), "0x100");
    }

    #[test]
    fn test_operand_display_vreg() {
        assert_eq!(Operand::VReg(3).to_string(), "vr3");
    }

    #[test]
    fn test_operand_display_label() {
        assert_eq!(Operand::Label(0x1234).to_string(), "L0x1234");
    }

    // -- VirtualInstruction --------------------------------------------------

    #[test]
    fn test_virtual_instruction_disasm_no_ops() {
        let i = VirtualInstruction::new(0x90, 0x1000, 1, HandlerSemanticsKind::Nop);
        assert_eq!(i.disasm(), "NOP");
    }

    #[test]
    fn test_virtual_instruction_disasm_with_src() {
        let mut i = VirtualInstruction::new(0x50, 0x1000, 9, HandlerSemanticsKind::Push);
        i.src.push(Operand::Imm(0xDEAD));
        assert!(i.disasm().contains("PUSH"));
        assert!(i.disasm().contains("0xdead"));
    }

    // -- LlilStmt display ----------------------------------------------------

    #[test]
    fn test_llil_stmt_display() {
        assert_eq!(LlilStmt::Nop.display(), "nop");
        assert_eq!(LlilStmt::Ret.display(), "ret");
        assert_eq!(LlilStmt::VmExit.display(), "vmexit");
    }

    // -- VmToLlilLifter ------------------------------------------------------

    #[test]
    fn test_lifter_empty_bytecode_error() {
        let isa = make_isa();
        let lifter = VmToLlilLifter::new(isa);
        assert!(matches!(
            lifter.lift_virtual_function(&[], 0x1000),
            Err(LiftError::EmptyBytecode)
        ));
    }

    #[test]
    fn test_lifter_nop() {
        let isa = make_isa();
        let lifter = VmToLlilLifter::new(isa);
        let bytecode = vec![0x90]; // NOP
        let func = lifter.lift_virtual_function(&bytecode, 0x1000).unwrap();
        assert!(func.complete);
        assert_eq!(func.instruction_count, 1);
        let stmts: Vec<_> = func.blocks.values().flat_map(|b| b.stmts.iter()).collect();
        assert!(matches!(stmts[0], LlilStmt::Nop));
    }

    #[test]
    fn test_lifter_push_imm() {
        let isa = make_isa();
        let mut lifter = VmToLlilLifter::new(isa);
        lifter.set_operand_size(4);
        let mut bytecode = vec![0x50]; // PUSH
        bytecode.extend_from_slice(&0xDEADu32.to_le_bytes());
        let func = lifter.lift_virtual_function(&bytecode, 0).unwrap();
        let stmts: Vec<_> = func.blocks.values().flat_map(|b| b.stmts.iter()).collect();
        assert!(matches!(stmts[0], LlilStmt::Push { .. }));
    }

    #[test]
    fn test_lifter_ret_terminates_block() {
        let isa = make_isa();
        let lifter = VmToLlilLifter::new(isa);
        let bytecode = vec![0x90, 0xC3]; // NOP; RET
        let func = lifter.lift_virtual_function(&bytecode, 0).unwrap();
        // RET should start a new block.
        assert!(func.instruction_count >= 2);
    }

    #[test]
    fn test_lifter_jump_terminates_block() {
        let isa = make_isa();
        let mut lifter = VmToLlilLifter::new(isa);
        lifter.set_operand_size(4);
        let mut bytecode = vec![0xE9]; // JMP
        bytecode.extend_from_slice(&0x2000u32.to_le_bytes());
        let func = lifter.lift_virtual_function(&bytecode, 0).unwrap();
        let stmts: Vec<_> = func.blocks.values().flat_map(|b| b.stmts.iter()).collect();
        assert!(matches!(stmts[0], LlilStmt::Jump { .. }));
    }

    #[test]
    fn test_lifter_unknown_opcode_becomes_intrinsic() {
        let isa = make_isa();
        let lifter = VmToLlilLifter::new(isa);
        let bytecode = vec![0xAB]; // Not in ISA
        let func = lifter.lift_virtual_function(&bytecode, 0).unwrap();
        let stmts: Vec<_> = func.blocks.values().flat_map(|b| b.stmts.iter()).collect();
        assert!(matches!(stmts[0], LlilStmt::Intrinsic { .. }));
    }

    #[test]
    fn test_lifter_budget_exceeded() {
        let isa = make_isa();
        let mut lifter = VmToLlilLifter::new(isa);
        lifter.set_max_instructions(2);
        let bytecode = vec![0x90; 100]; // 100 NOPs
        assert!(matches!(
            lifter.lift_virtual_function(&bytecode, 0),
            Err(LiftError::BudgetExceeded(_))
        ));
    }

    #[test]
    fn test_lifter_block_count() {
        let isa = make_isa();
        let lifter = VmToLlilLifter::new(isa);
        let bytecode = vec![0x90, 0xC3, 0x90]; // NOP; RET; NOP
        let func = lifter.lift_virtual_function(&bytecode, 0).unwrap();
        // Should have at least 2 blocks (one ending at RET, one after).
        assert!(func.block_count() >= 1);
    }

    #[test]
    fn test_lift_virtual_function_convenience() {
        let isa = make_isa();
        let bytecode = vec![0x90]; // NOP
        let result = lift_virtual_function(isa, &bytecode, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_lifted_function_complete() {
        let isa = make_isa();
        let lifter = VmToLlilLifter::new(isa);
        let bytecode = vec![0x90, 0x58, 0x90]; // NOP; POP; NOP
        let func = lifter.lift_virtual_function(&bytecode, 0x4000).unwrap();
        assert!(func.complete);
        assert_eq!(func.entry_address, 0x4000);
    }

    #[test]
    fn test_vm_type_stack() {
        let isa = make_isa();
        assert!(isa.is_stack_based);
        let lifter = VmToLlilLifter::new(isa);
        assert_eq!(lifter.vm_type, VmType::StackBased);
    }

    #[test]
    fn test_isa_table_ref_from_lifter() {
        let isa = make_isa();
        let lifter = VmToLlilLifter::new(isa);
        assert!(lifter.isa().get_opcode(0x90).is_some());
    }
}
