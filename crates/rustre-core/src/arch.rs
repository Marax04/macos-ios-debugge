//! Architecture abstraction layer for the RustRE platform.
//!
//! This module defines the [`Architecture`] trait and all supporting types that
//! concrete architecture crates (e.g. `rustre-arch-x86`, `rustre-arch-arm`)
//! implement.
//!
//! Key types:
//! - [`Architecture`] — the central trait.
//! - [`Instruction`] — a fully decoded machine instruction.
//! - [`Operand`] — a single instruction operand (register, immediate, memory, …).
//! - [`InstrFlags`] — bitflags describing instruction properties.
//! - [`BranchInfo`], [`BranchKind`], [`BranchCondition`] — branch target details.
//! - [`RegisterInfo`], [`RegisterKind`] — register metadata.
//! - [`CallingConvention`] — ABI calling-convention descriptor.
//! - [`ArchitectureRegistry`] — global registry of registered architectures.
//! - [`DisassemblyContext`] — stateful context for architectures that require
//!   it (e.g. ARM Thumb IT-blocks).

use crate::address::Address;
use crate::endian::Endian;
use crate::errors::CoreError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// InstrFlags
// ─────────────────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Miscellaneous per-instruction flags.
    ///
    /// These are set by the disassembler and consumed by analysis passes to
    /// avoid re-inspecting instruction mnemonics.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct InstrFlags: u32 {
        /// No flags set (placeholder).
        const NONE        = 0;
        /// Unconditional or conditional branch.
        const BRANCH      = 1 << 0;
        /// Direct or indirect function call.
        const CALL        = 1 << 1;
        /// Function return.
        const RET         = 1 << 2;
        /// Software interrupt / syscall.
        const SYSCALL     = 1 << 3;
        /// Requires elevated privilege.
        const PRIVILEGED  = 1 << 4;
        /// Has lock / memory-order prefix.
        const ATOMIC      = 1 << 5;
        /// Floating-point operation.
        const FP          = 1 << 6;
        /// SIMD / vector operation.
        const SIMD        = 1 << 7;
        /// Terminates the basic block.
        const TERMINATOR  = 1 << 8;
        /// No-operation.
        const NOP         = 1 << 9;
        /// Could not be decoded.
        const INVALID     = 1 << 10;
        /// Reads from memory.
        const READ_MEM    = 1 << 11;
        /// Writes to memory.
        const WRITE_MEM   = 1 << 12;
        /// Memory barrier / fence.
        const BARRIER     = 1 << 13;
        /// Conditional branch (subset of BRANCH).
        const CONDITIONAL = 1 << 14;
        /// Indirect branch or call target.
        const INDIRECT    = 1 << 15;
    }
}

impl Serialize for InstrFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.bits())
    }
}

impl<'de> Deserialize<'de> for InstrFlags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bits = u32::deserialize(deserializer)?;
        Ok(Self::from_bits_truncate(bits))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterKind
// ─────────────────────────────────────────────────────────────────────────────

/// Semantic class of a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisterKind {
    /// General-purpose integer register.
    General,
    /// Stack pointer.
    Stack,
    /// Link register (return address).
    Link,
    /// Program counter / instruction pointer.
    ProgramCounter,
    /// Flags / status register.
    Flags,
    /// Segment register (x86).
    Segment,
    /// Floating-point register.
    Float,
    /// SIMD / vector register.
    Vector,
    /// Control register (CR0–CR15 on x86).
    Control,
    /// Debug register (DR0–DR7 on x86).
    Debug,
    /// System / special-purpose register (MSR, etc.).
    System,
}

impl std::fmt::Display for RegisterKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::General => write!(f, "general"),
            Self::Stack => write!(f, "stack"),
            Self::Link => write!(f, "link"),
            Self::ProgramCounter => write!(f, "pc"),
            Self::Flags => write!(f, "flags"),
            Self::Segment => write!(f, "segment"),
            Self::Float => write!(f, "float"),
            Self::Vector => write!(f, "vector"),
            Self::Control => write!(f, "control"),
            Self::Debug => write!(f, "debug"),
            Self::System => write!(f, "system"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata about a single architectural register.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterInfo {
    /// Primary name (e.g. `"rax"`, `"r0"`, `"sp"`).
    pub name: String,
    /// Architecture-specific opaque identifier.
    pub id: u32,
    /// Size in bytes of the *physical* register storage.
    pub size: usize,
    /// Semantic role.
    pub kind: RegisterKind,
    /// Alternate names (e.g. `"eax"` and `"ax"` for the x86 `rax` family).
    pub aliases: Vec<String>,
    /// ID of the full-width parent register, if this is a sub-register.
    pub full_register: Option<u32>,
    /// Bit offset within the parent register (0 for most sub-registers).
    pub bit_offset: u8,
    /// Width in bits of this register within its parent.
    pub bit_width: u8,
}

impl RegisterInfo {
    /// Create a basic register with no aliases and no parent.
    #[must_use]
    pub fn new(name: impl Into<String>, id: u32, size: usize, kind: RegisterKind) -> Self {
        Self {
            name: name.into(),
            id,
            size,
            kind,
            aliases: Vec::new(),
            full_register: None,
            bit_offset: 0,
            bit_width: u8::try_from(size.saturating_mul(8)).unwrap_or(u8::MAX),
        }
    }

    /// Attach alias names.
    #[must_use]
    pub fn with_aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = aliases;
        self
    }

    /// Mark this register as a sub-register of `parent`.
    #[must_use]
    pub const fn with_parent(mut self, parent: u32, bit_offset: u8, bit_width: u8) -> Self {
        self.full_register = Some(parent);
        self.bit_offset = bit_offset;
        self.bit_width = bit_width;
        self
    }

    /// Return `true` if this is the stack pointer.
    #[must_use]
    pub fn is_stack_pointer(&self) -> bool {
        self.kind == RegisterKind::Stack
    }

    /// Return `true` if this is a general-purpose register.
    #[must_use]
    pub fn is_general(&self) -> bool {
        self.kind == RegisterKind::General
    }

    /// Size in bits.
    #[must_use]
    pub const fn size_bits(&self) -> usize {
        self.size * 8
    }
}

impl std::fmt::Display for RegisterInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Operand
// ─────────────────────────────────────────────────────────────────────────────

/// A single instruction operand.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Operand {
    /// A named register.
    Register(RegisterInfo),
    /// A signed immediate value.
    Immediate(i64),
    /// An unsigned immediate (e.g. shift amounts, bit masks).
    UImmediate(u64),
    /// A memory reference: `[base + index * scale + disp]`.
    Memory {
        /// Optional base register.
        base: Option<RegisterInfo>,
        /// Optional index register.
        index: Option<RegisterInfo>,
        /// Scale factor for the index register (1, 2, 4, 8).
        scale: u8,
        /// Signed displacement.
        disp: i64,
        /// Width of the access in bytes.
        width: u8,
    },
    /// A code label / branch target.
    Label(u64),
    /// A floating-point register (index-based for brevity).
    FpReg(u8),
    /// A SIMD/vector register (index-based).
    VecReg(u8),
    /// A segment register override (segment ID + inner operand).
    Segment(u8, Box<Self>),
}

impl Operand {
    /// Return the immediate value as a `u64`, if this is an immediate operand.
    #[must_use]
    pub fn as_immediate(&self) -> Option<i64> {
        match self {
            Self::Immediate(v) => Some(*v),
            Self::UImmediate(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// Return the register info if this is a register operand.
    #[must_use]
    pub const fn as_register(&self) -> Option<&RegisterInfo> {
        match self {
            Self::Register(r) => Some(r),
            _ => None,
        }
    }

    /// Return the label address if this is a label operand.
    #[must_use]
    pub const fn as_label(&self) -> Option<u64> {
        match self {
            Self::Label(a) => Some(*a),
            _ => None,
        }
    }
}

impl std::fmt::Display for Operand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Register(r) => write!(f, "{}", r.name),
            Self::Immediate(v) => {
                if *v < 0 {
                    write!(f, "-{:#x}", v.unsigned_abs())
                } else {
                    write!(f, "{v:#x}")
                }
            }
            Self::UImmediate(v) => write!(f, "{v:#x}"),
            Self::Memory {
                base,
                index,
                scale,
                disp,
                ..
            } => {
                write!(f, "[")?;
                if let Some(b) = base {
                    write!(f, "{}", b.name)?;
                }
                if let Some(i) = index {
                    if *scale > 1 {
                        write!(f, "+{}*{scale}", i.name)?;
                    } else {
                        write!(f, "+{}", i.name)?;
                    }
                }
                if *disp != 0 {
                    if *disp < 0 {
                        write!(f, "-{:#x}", disp.unsigned_abs())?;
                    } else {
                        write!(f, "+{disp:#x}")?;
                    }
                }
                write!(f, "]")
            }
            Self::Label(a) => write!(f, "{a:#x}"),
            Self::FpReg(n) => write!(f, "fp{n}"),
            Self::VecReg(n) => write!(f, "v{n}"),
            Self::Segment(s, inner) => write!(f, "seg{s}:{inner}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BranchKind & BranchCondition & BranchInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Semantic classification of a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BranchKind {
    /// Unconditional direct jump.
    UnconditionalJump,
    /// Conditional direct jump.
    ConditionalJump,
    /// Direct function call.
    Call,
    /// Return from function.
    Return,
    /// System call / software interrupt.
    SystemCall,
    /// Trap / breakpoint.
    Trap,
    /// Indirect jump (target computed at runtime).
    IndirectJump,
    /// Indirect call.
    IndirectCall,
    /// Exception return (e.g. ARM `ERET`).
    ExceptionReturn,
}

impl BranchKind {
    /// Return `true` if this kind terminates the current function.
    #[must_use]
    pub const fn is_terminator(self) -> bool {
        matches!(self, Self::Return | Self::Trap | Self::ExceptionReturn)
    }

    /// Return `true` if this is any form of call.
    #[must_use]
    pub const fn is_call(self) -> bool {
        matches!(self, Self::Call | Self::IndirectCall | Self::SystemCall)
    }

    /// Return `true` if the branch target may be unknown statically.
    #[must_use]
    pub const fn is_indirect(self) -> bool {
        matches!(self, Self::IndirectJump | Self::IndirectCall)
    }
}

/// Condition code for a conditional branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BranchCondition {
    /// Branch always (unconditional).
    Always,
    /// Equal / zero.
    Equal,
    /// Not equal / not zero.
    NotEqual,
    /// Signed less than.
    LessThan,
    /// Signed less than or equal.
    LessEqual,
    /// Signed greater than.
    GreaterThan,
    /// Signed greater than or equal.
    GreaterEqual,
    /// Unsigned below (carry set).
    Below,
    /// Unsigned below or equal.
    BelowEqual,
    /// Unsigned above.
    Above,
    /// Unsigned above or equal.
    AboveEqual,
    /// Overflow set.
    Overflow,
    /// No overflow.
    NoOverflow,
    /// Sign / negative.
    Minus,
    /// No sign / positive.
    Plus,
    /// Parity even.
    ParityEven,
    /// Parity odd.
    ParityOdd,
    /// Architecture-specific condition not covered above.
    Custom(u16),
}

/// Information about a branch that an instruction may take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchInfo {
    /// Statically-known target address, or `None` for indirect branches.
    pub target: Option<u64>,
    /// Semantic branch kind.
    pub kind: BranchKind,
    /// Branch condition.
    pub condition: BranchCondition,
}

impl BranchInfo {
    /// Create an unconditional direct jump.
    #[must_use]
    pub const fn unconditional_jump(target: u64) -> Self {
        Self {
            target: Some(target),
            kind: BranchKind::UnconditionalJump,
            condition: BranchCondition::Always,
        }
    }

    /// Create a conditional jump.
    #[must_use]
    pub const fn conditional_jump(target: u64, cond: BranchCondition) -> Self {
        Self {
            target: Some(target),
            kind: BranchKind::ConditionalJump,
            condition: cond,
        }
    }

    /// Create a direct call.
    #[must_use]
    pub const fn call(target: u64) -> Self {
        Self {
            target: Some(target),
            kind: BranchKind::Call,
            condition: BranchCondition::Always,
        }
    }

    /// Create a function return.
    #[must_use]
    pub const fn ret() -> Self {
        Self {
            target: None,
            kind: BranchKind::Return,
            condition: BranchCondition::Always,
        }
    }

    /// Create an indirect jump with no statically-known target.
    #[must_use]
    pub const fn indirect_jump() -> Self {
        Self {
            target: None,
            kind: BranchKind::IndirectJump,
            condition: BranchCondition::Always,
        }
    }

    /// Return `true` if this branch is taken unconditionally.
    #[must_use]
    pub fn is_unconditional(&self) -> bool {
        self.condition == BranchCondition::Always
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction
// ─────────────────────────────────────────────────────────────────────────────

/// A fully decoded machine instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Instruction {
    /// Address of the first byte of this instruction.
    pub address: Address,
    /// Size of the instruction encoding in bytes.
    pub size: usize,
    /// Mnemonic string (e.g. `"mov"`, `"bl"`, `"ld.d"`).
    pub mnemonic: String,
    /// Raw operand text as rendered by the disassembler.
    pub operands: String,
    /// Structured operand list parsed from the raw text.
    pub operand_list: Vec<Operand>,
    /// Instruction property flags.
    pub flags: InstrFlags,
    /// Raw encoding bytes.
    pub bytes: Vec<u8>,
    /// Optional analyst comment attached by the disassembler.
    pub comment: Option<String>,
}

impl Instruction {
    /// Create a minimal instruction with no operands.
    #[must_use]
    pub fn new(address: Address, size: usize, mnemonic: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            address,
            size,
            mnemonic: mnemonic.into(),
            operands: String::new(),
            operand_list: Vec::new(),
            flags: InstrFlags::NONE,
            bytes,
            comment: None,
        }
    }

    /// Return `true` if this instruction is a branch.
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        self.flags.contains(InstrFlags::BRANCH)
    }

    /// Return `true` if this instruction is a call.
    #[must_use]
    pub const fn is_call(&self) -> bool {
        self.flags.contains(InstrFlags::CALL)
    }

    /// Return `true` if this instruction is a return.
    #[must_use]
    pub const fn is_return(&self) -> bool {
        self.flags.contains(InstrFlags::RET)
    }

    /// Return `true` if this instruction is a NOP.
    #[must_use]
    pub const fn is_nop(&self) -> bool {
        self.flags.contains(InstrFlags::NOP)
    }

    /// Return `true` if this instruction could not be decoded.
    #[must_use]
    pub const fn is_invalid(&self) -> bool {
        self.flags.contains(InstrFlags::INVALID)
    }

    /// Return `true` if this instruction terminates a basic block.
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        self.flags.contains(InstrFlags::TERMINATOR)
    }

    /// Address of the byte immediately following this instruction.
    #[must_use]
    pub fn next_address(&self) -> Address {
        self.address + self.size as u64
    }

    /// Attach a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}  {}", self.address.as_u64(), self.mnemonic)?;
        if !self.operands.is_empty() {
            write!(f, " {}", self.operands)?;
        }
        if let Some(c) = &self.comment {
            write!(f, "   ; {c}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallingConvention
// ─────────────────────────────────────────────────────────────────────────────

/// An ABI calling-convention descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallingConvention {
    /// Canonical name (e.g. `"System V AMD64 ABI"`, `"__cdecl"`, `"aapcs64"`).
    pub name: String,
    /// Registers used to pass integer/pointer arguments (in order).
    pub int_args: Vec<String>,
    /// Registers used to pass floating-point arguments (in order).
    pub float_args: Vec<String>,
    /// Registers used to return values.
    pub return_regs: Vec<String>,
    /// Registers the callee must preserve across a call.
    pub callee_saved: Vec<String>,
    /// Registers the caller must save before a call.
    pub caller_saved: Vec<String>,
    /// Red zone size in bytes (area below SP that the callee may use freely).
    pub red_zone_size: u32,
    /// Shadow space in bytes (Windows x64 "home" space).
    pub shadow_space_size: u32,
    /// `true` if the caller is responsible for cleaning up stack arguments.
    pub caller_cleans_stack: bool,
}

impl CallingConvention {
    /// Create a minimal calling convention.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            int_args: Vec::new(),
            float_args: Vec::new(),
            return_regs: Vec::new(),
            callee_saved: Vec::new(),
            caller_saved: Vec::new(),
            red_zone_size: 0,
            shadow_space_size: 0,
            caller_cleans_stack: true,
        }
    }

    /// Set integer argument registers.
    #[must_use]
    pub fn with_int_args(mut self, args: Vec<String>) -> Self {
        self.int_args = args;
        self
    }

    /// Set floating-point argument registers.
    #[must_use]
    pub fn with_float_args(mut self, args: Vec<String>) -> Self {
        self.float_args = args;
        self
    }

    /// Set return-value registers.
    #[must_use]
    pub fn with_return_regs(mut self, regs: Vec<String>) -> Self {
        self.return_regs = regs;
        self
    }

    /// Set callee-saved registers.
    #[must_use]
    pub fn with_callee_saved(mut self, regs: Vec<String>) -> Self {
        self.callee_saved = regs;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DisassemblyContext
// ─────────────────────────────────────────────────────────────────────────────

/// Stateful context passed to the disassembler to handle architectures that
/// require cross-instruction state (e.g. ARM Thumb IT-blocks, MIPS delay slots).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisassemblyContext {
    /// Number of instructions remaining in an ARM Thumb IT-block.
    pub it_block_remaining: u8,
    /// Condition for the current IT-block.
    pub it_condition: u8,
    /// Whether the disassembler is currently in Thumb mode.
    pub thumb_mode: bool,
    /// Whether the next instruction is in a MIPS delay slot.
    pub in_delay_slot: bool,
    /// Arbitrary opaque extra state for architecture-specific extensions.
    pub extra: std::collections::HashMap<String, u64>,
}

impl DisassemblyContext {
    /// Create an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter an ARM Thumb IT-block with `count` conditional instructions and
    /// `condition` as the base condition code.
    pub const fn enter_it_block(&mut self, count: u8, condition: u8) {
        self.it_block_remaining = count;
        self.it_condition = condition;
    }

    /// Consume one instruction from the IT-block.
    /// Returns `true` if we were in an IT-block.
    pub const fn advance_it_block(&mut self) -> bool {
        if self.it_block_remaining > 0 {
            self.it_block_remaining -= 1;
            true
        } else {
            false
        }
    }

    /// Return `true` if we are currently inside a Thumb IT-block.
    #[must_use]
    pub const fn in_it_block(&self) -> bool {
        self.it_block_remaining > 0
    }

    /// Set/get an opaque extra value by key.
    pub fn set_extra(&mut self, key: impl Into<String>, val: u64) {
        self.extra.insert(key.into(), val);
    }

    /// Get an extra value by key.
    #[must_use]
    pub fn get_extra(&self, key: &str) -> Option<u64> {
        self.extra.get(key).copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchMode
// ─────────────────────────────────────────────────────────────────────────────

/// Current execution mode of an architecture at a given address.
///
/// Used by architectures that can switch modes at runtime (e.g. ARM ↔ Thumb).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArchMode {
    /// Default / primary mode for this architecture.
    Default,
    /// ARM Thumb (16-bit) mode.
    Thumb,
    /// ARM Thumb-2 (mixed 16/32-bit) mode.
    Thumb2,
    /// 16-bit execution mode.
    Bit16,
    /// 32-bit execution mode.
    Bit32,
    /// 64-bit execution mode.
    Bit64,
}

// ─────────────────────────────────────────────────────────────────────────────
// LlilOp
// ─────────────────────────────────────────────────────────────────────────────

/// A Low-Level Intermediate Language operation.
///
/// This is a minimal stub used for lifting machine instructions to an IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LlilOp {
    /// Load a value from memory.
    Load,
    /// Store a value to memory.
    Store,
    /// Integer addition.
    Add,
    /// Integer subtraction.
    Sub,
    /// Integer multiplication.
    Mul,
    /// Integer division.
    Div,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Bitwise NOT.
    Not,
    /// Logical shift left.
    Lsl,
    /// Logical shift right.
    Lsr,
    /// Arithmetic (sign-preserving) shift right.
    Asr,
    /// No operation.
    Nop,
    /// A constant value.
    Const(i128),
    /// Read from a register (by architecture-specific register ID).
    GetReg(u32),
    /// Write to a register (by architecture-specific register ID).
    SetReg(u32),
    /// Unconditional jump to an address.
    Jump(u64),
    /// Call a function at an address.
    Call(u64),
    /// Return from the current function.
    Return,
    /// System call.
    Syscall,
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftContext
// ─────────────────────────────────────────────────────────────────────────────

/// Mutable context passed to [`Architecture::lift`] for accumulating LLIL ops.
#[derive(Debug, Clone)]
pub struct LiftContext {
    /// Address of the function being lifted.
    pub function_address: Address,
    /// Name of the architecture performing the lift.
    pub arch: String,
    /// Accumulated LLIL operations.
    pub results: Vec<LlilOp>,
    /// Map from target address to index in `results` (for label resolution).
    pub labels: HashMap<u64, usize>,
}

impl LiftContext {
    /// Create a new context for lifting at `function_address` with the given
    /// architecture name.
    #[must_use]
    pub fn new(addr: Address, arch: impl Into<String>) -> Self {
        Self {
            function_address: addr,
            arch: arch.into(),
            results: Vec::new(),
            labels: HashMap::new(),
        }
    }

    /// Append an LLIL operation to the result list.
    pub fn emit(&mut self, op: LlilOp) {
        self.results.push(op);
    }

    /// Record the current result index as a label for `addr`.
    pub fn emit_label(&mut self, addr: u64) {
        self.labels.insert(addr, self.results.len());
    }

    /// Consume the context and return the accumulated ops.
    #[must_use]
    pub fn build(self) -> Vec<LlilOp> {
        self.results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Architecture trait
// ─────────────────────────────────────────────────────────────────────────────

/// The core architecture abstraction.
///
/// Implementors live in crates like `rustre-arch-x86`, `rustre-arch-arm`, etc.
/// All methods must be re-entrant and safe to call from multiple threads.
pub trait Architecture: Send + Sync + std::fmt::Debug {
    /// Human-readable architecture name (e.g. `"x86_64"`, `"aarch64"`).
    fn name(&self) -> &str;

    /// Size of a pointer in bytes (4 for 32-bit, 8 for 64-bit).
    fn pointer_size(&self) -> usize;

    /// Default endianness of the architecture.
    fn endian(&self) -> Endian;

    /// Word size in bits (typically `pointer_size() * 8`).
    fn word_size(&self) -> usize {
        self.pointer_size() * 8
    }

    /// Decode one instruction starting at `address` from `bytes`.
    ///
    /// # Errors
    /// Returns [`CoreError::ArchitectureError`] if the bytes cannot be decoded.
    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError>;

    /// Decode a chunk of instructions until `max_count` are decoded or `bytes`
    /// is exhausted.
    ///
    /// Default implementation calls [`disassemble`](Self::disassemble) in a loop.
    ///
    /// # Errors
    /// Returns an error if the first instruction cannot be decoded.
    fn disassemble_chunk(
        &self,
        address: Address,
        bytes: &[u8],
        max_count: usize,
    ) -> Result<Vec<Instruction>, CoreError> {
        // Cap to avoid pre-allocating unbounded memory from a caller-supplied value.
        const MAX_DISASM_CAP: usize = 65_536;
        let capped = max_count.min(MAX_DISASM_CAP);
        let mut instrs = Vec::with_capacity(capped);
        let mut offset = 0usize;
        let mut addr = address;
        while offset < bytes.len() && instrs.len() < max_count {
            let instr = self.disassemble(addr, &bytes[offset..])?;
            offset += instr.size;
            addr += instr.size as u64;
            instrs.push(instr);
        }
        Ok(instrs)
    }

    /// Return branch information for an instruction.
    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo>;

    /// Return all registers defined by this architecture.
    fn registers(&self) -> Vec<RegisterInfo>;

    /// Return all supported calling conventions.
    fn calling_conventions(&self) -> Vec<CallingConvention>;

    /// Return the stack pointer register, if known.
    fn stack_pointer(&self) -> Option<RegisterInfo> {
        self.registers()
            .into_iter()
            .find(|r| r.kind == RegisterKind::Stack)
    }

    /// Return the frame pointer register, if defined.
    fn frame_pointer(&self) -> Option<RegisterInfo> {
        None
    }

    /// Return the instruction pointer / program counter register.
    fn instruction_pointer(&self) -> Option<RegisterInfo> {
        self.registers()
            .into_iter()
            .find(|r| r.kind == RegisterKind::ProgramCounter)
    }

    /// Return the primary integer return register.
    fn return_register(&self) -> Option<RegisterInfo> {
        self.calling_conventions()
            .into_iter()
            .next()
            .and_then(|cc| {
                cc.return_regs
                    .first()
                    .map(|n| self.registers().into_iter().find(|r| &r.name == n))
            })?
    }

    /// Return the system-call calling convention, if any.
    fn system_call_convention(&self) -> Option<CallingConvention> {
        None
    }

    /// Required alignment of instructions in bytes (1 for variable-length, 2
    /// for Thumb, 4 for most RISC architectures).
    fn instruction_alignment(&self) -> usize {
        1
    }

    /// Maximum possible instruction length in bytes.
    fn max_instruction_length(&self) -> usize {
        15 // x86-64 maximum
    }

    /// Re-encode an instruction back to its byte representation.
    ///
    /// This is the assembler direction: given a decoded [`Instruction`],
    /// produce the canonical byte encoding.  Architectures that implement an
    /// assembler should override this method.
    ///
    /// # Errors
    /// Returns [`CoreError::Unsupported`] by default.
    fn encode(&self, _instr: &Instruction) -> Result<Vec<u8>, CoreError> {
        Err(CoreError::unsupported("encode"))
    }

    /// Lift an instruction to a sequence of Low-Level IL operations.
    ///
    /// The caller supplies a mutable [`LiftContext`] so that label information
    /// can be accumulated across multiple instructions in one pass.
    ///
    /// # Errors
    /// Returns an error if lifting fails.  The default implementation succeeds
    /// with an empty operation list (i.e. the instruction is treated as a NOP
    /// at the LLIL level).
    fn lift(&self, _instr: &Instruction, _ctx: &mut LiftContext) -> Result<Vec<LlilOp>, CoreError> {
        Ok(vec![])
    }

    /// Return the execution mode that is in effect at `addr`.
    ///
    /// Architectures that can switch modes (e.g. ARM ↔ Thumb) should override
    /// this to consult their symbol / mapping-symbol tables.  The default
    /// implementation always returns [`ArchMode::Default`].
    fn mode_at(&self, _addr: Address) -> ArchMode {
        ArchMode::Default
    }

    /// Return the natural integer width in bits (16, 32, 64, or 128).
    ///
    /// The default implementation derives the value from [`pointer_size`](Self::pointer_size).
    fn bits(&self) -> u8 {
        u8::try_from(self.pointer_size().saturating_mul(8)).unwrap_or(u8::MAX)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchitectureRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Global registry of registered [`Architecture`] implementations.
#[derive(Default)]
pub struct ArchitectureRegistry {
    architectures: parking_lot::RwLock<Vec<std::sync::Arc<dyn Architecture>>>,
}

impl std::fmt::Debug for ArchitectureRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchitectureRegistry")
            .field("count", &self.architectures.read().len())
            .finish_non_exhaustive()
    }
}

impl ArchitectureRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an architecture implementation.
    pub fn register(&self, arch: std::sync::Arc<dyn Architecture>) {
        self.architectures.write().push(arch);
    }

    /// Find an architecture by name (case-sensitive).
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<std::sync::Arc<dyn Architecture>> {
        self.architectures
            .read()
            .iter()
            .find(|a| a.name() == name)
            .cloned()
    }

    /// Find all architectures with `pointer_size == size`.
    #[must_use]
    pub fn find_by_pointer_size(&self, size: usize) -> Vec<std::sync::Arc<dyn Architecture>> {
        self.architectures
            .read()
            .iter()
            .filter(|a| a.pointer_size() == size)
            .cloned()
            .collect()
    }

    /// Return all registered architecture names.
    #[must_use]
    pub fn list_names(&self) -> Vec<String> {
        self.architectures
            .read()
            .iter()
            .map(|a| a.name().to_owned())
            .collect()
    }

    /// Number of registered architectures.
    #[must_use]
    pub fn count(&self) -> usize {
        self.architectures.read().len()
    }

    /// Remove an architecture by name.  Returns `true` if it was present.
    pub fn unregister(&self, name: &str) -> bool {
        let mut guard = self.architectures.write();
        let before = guard.len();
        guard.retain(|a| a.name() != name);
        guard.len() < before
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Stub architecture for testing ─────────────────────────────────────────

    #[derive(Debug)]
    struct StubArch {
        name: &'static str,
        ptr_size: usize,
        endian: Endian,
    }

    impl StubArch {
        fn new(name: &'static str, ptr_size: usize, endian: Endian) -> Self {
            Self {
                name,
                ptr_size,
                endian,
            }
        }
    }

    impl Architecture for StubArch {
        fn name(&self) -> &str {
            self.name
        }
        fn pointer_size(&self) -> usize {
            self.ptr_size
        }
        fn endian(&self) -> Endian {
            self.endian
        }

        fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
            if bytes.is_empty() {
                return Err(CoreError::truncated(1, 0));
            }
            Ok(Instruction::new(address, 1, "nop", bytes[..1].to_vec()))
        }

        fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
            vec![]
        }

        fn registers(&self) -> Vec<RegisterInfo> {
            vec![
                RegisterInfo::new("sp", 0, self.ptr_size, RegisterKind::Stack),
                RegisterInfo::new("pc", 1, self.ptr_size, RegisterKind::ProgramCounter),
                RegisterInfo::new("r0", 2, self.ptr_size, RegisterKind::General),
            ]
        }

        fn calling_conventions(&self) -> Vec<CallingConvention> {
            vec![
                CallingConvention::new("default")
                    .with_int_args(vec!["r0".into()])
                    .with_return_regs(vec!["r0".into()]),
            ]
        }
    }

    fn make_arch() -> std::sync::Arc<StubArch> {
        std::sync::Arc::new(StubArch::new("stub32", 4, Endian::Little))
    }

    // ── InstrFlags ────────────────────────────────────────────────────────────

    #[test]
    fn instr_flags_combine() {
        let f = InstrFlags::BRANCH | InstrFlags::CONDITIONAL;
        assert!(f.contains(InstrFlags::BRANCH));
        assert!(f.contains(InstrFlags::CONDITIONAL));
        assert!(!f.contains(InstrFlags::CALL));
    }

    #[test]
    fn instr_flags_serde_round_trip() {
        let f = InstrFlags::CALL | InstrFlags::INDIRECT;
        let bits = f.bits();
        let recovered = InstrFlags::from_bits_truncate(bits);
        assert_eq!(f, recovered);
    }

    // ── RegisterKind display ──────────────────────────────────────────────────

    #[test]
    fn register_kind_display() {
        assert_eq!(RegisterKind::General.to_string(), "general");
        assert_eq!(RegisterKind::ProgramCounter.to_string(), "pc");
        assert_eq!(RegisterKind::Vector.to_string(), "vector");
    }

    // ── RegisterInfo ──────────────────────────────────────────────────────────

    #[test]
    fn register_info_basic() {
        let r = RegisterInfo::new("rax", 0, 8, RegisterKind::General);
        assert!(r.is_general());
        assert!(!r.is_stack_pointer());
        assert_eq!(r.size_bits(), 64);
        assert_eq!(r.to_string(), "rax");
    }

    #[test]
    fn register_info_sub_register() {
        let r = RegisterInfo::new("eax", 1, 4, RegisterKind::General).with_parent(0, 0, 32);
        assert_eq!(r.full_register, Some(0));
        assert_eq!(r.bit_width, 32);
    }

    #[test]
    fn register_info_with_aliases() {
        let r = RegisterInfo::new("rax", 0, 8, RegisterKind::General).with_aliases(vec![
            "eax".into(),
            "ax".into(),
            "al".into(),
        ]);
        assert_eq!(r.aliases.len(), 3);
    }

    // ── Operand ───────────────────────────────────────────────────────────────

    #[test]
    fn operand_immediate() {
        let op = Operand::Immediate(-16);
        assert_eq!(op.as_immediate(), Some(-16));
        assert!(op.as_register().is_none());
    }

    #[test]
    fn operand_label() {
        let op = Operand::Label(0x4000);
        assert_eq!(op.as_label(), Some(0x4000));
    }

    #[test]
    fn operand_display_memory() {
        let base = RegisterInfo::new("rbp", 5, 8, RegisterKind::General);
        let op = Operand::Memory {
            base: Some(base),
            index: None,
            scale: 1,
            disp: -8,
            width: 8,
        };
        let s = op.to_string();
        assert!(s.contains("rbp"));
        assert!(s.contains("-0x8"));
    }

    #[test]
    fn operand_display_register() {
        let r = RegisterInfo::new("rsp", 7, 8, RegisterKind::Stack);
        let op = Operand::Register(r);
        assert_eq!(op.to_string(), "rsp");
    }

    // ── BranchKind ────────────────────────────────────────────────────────────

    #[test]
    fn branch_kind_predicates() {
        assert!(BranchKind::Return.is_terminator());
        assert!(BranchKind::Trap.is_terminator());
        assert!(!BranchKind::ConditionalJump.is_terminator());
        assert!(BranchKind::Call.is_call());
        assert!(BranchKind::IndirectCall.is_call());
        assert!(!BranchKind::ConditionalJump.is_call());
        assert!(BranchKind::IndirectJump.is_indirect());
        assert!(!BranchKind::UnconditionalJump.is_indirect());
    }

    // ── BranchInfo ────────────────────────────────────────────────────────────

    #[test]
    fn branch_info_constructors() {
        let jmp = BranchInfo::unconditional_jump(0x1000);
        assert_eq!(jmp.target, Some(0x1000));
        assert!(jmp.is_unconditional());
        assert_eq!(jmp.kind, BranchKind::UnconditionalJump);

        let ret = BranchInfo::ret();
        assert_eq!(ret.target, None);
        assert_eq!(ret.kind, BranchKind::Return);

        let cjmp = BranchInfo::conditional_jump(0x2000, BranchCondition::Equal);
        assert_eq!(cjmp.condition, BranchCondition::Equal);
    }

    // ── Instruction ───────────────────────────────────────────────────────────

    #[test]
    fn instruction_next_address() {
        let instr = Instruction::new(Address::new(0x1000), 4, "add", vec![0; 4]);
        assert_eq!(instr.next_address(), Address::new(0x1004));
    }

    #[test]
    fn instruction_flags_predicates() {
        let mut instr = Instruction::new(Address::new(0), 1, "nop", vec![0x90]);
        instr.flags = InstrFlags::NOP;
        assert!(instr.is_nop());
        assert!(!instr.is_branch());
        assert!(!instr.is_invalid());
    }

    #[test]
    fn instruction_display() {
        let instr = Instruction::new(Address::new(0x4000), 2, "mov", vec![0x89, 0xC0])
            .with_comment("eax, eax");
        let s = instr.to_string();
        assert!(s.contains("4000"));
        assert!(s.contains("mov"));
        assert!(s.contains("eax, eax"));
    }

    // ── CallingConvention ─────────────────────────────────────────────────────

    #[test]
    fn calling_convention_builder() {
        let cc = CallingConvention::new("sysv64")
            .with_int_args(vec!["rdi".into(), "rsi".into()])
            .with_float_args(vec!["xmm0".into()])
            .with_return_regs(vec!["rax".into()])
            .with_callee_saved(vec!["rbx".into(), "rbp".into()]);
        assert_eq!(cc.int_args.len(), 2);
        assert_eq!(cc.float_args.len(), 1);
        assert_eq!(cc.return_regs[0], "rax");
        assert_eq!(cc.callee_saved.len(), 2);
    }

    // ── DisassemblyContext ────────────────────────────────────────────────────

    #[test]
    fn disassembly_context_it_block() {
        let mut ctx = DisassemblyContext::new();
        assert!(!ctx.in_it_block());
        ctx.enter_it_block(3, 0);
        assert!(ctx.in_it_block());
        assert_eq!(ctx.it_block_remaining, 3);

        assert!(ctx.advance_it_block());
        assert!(ctx.advance_it_block());
        assert!(ctx.advance_it_block());
        assert!(!ctx.in_it_block());
        assert!(!ctx.advance_it_block());
    }

    #[test]
    fn disassembly_context_extra() {
        let mut ctx = DisassemblyContext::new();
        ctx.set_extra("mips.delay_slot", 1);
        assert_eq!(ctx.get_extra("mips.delay_slot"), Some(1));
        assert_eq!(ctx.get_extra("nonexistent"), None);
    }

    // ── Architecture trait via StubArch ───────────────────────────────────────

    #[test]
    fn arch_word_size() {
        let arch = make_arch();
        assert_eq!(arch.word_size(), 32);
    }

    #[test]
    fn arch_stack_pointer() {
        let arch = make_arch();
        let sp = arch.stack_pointer().unwrap();
        assert_eq!(sp.name, "sp");
    }

    #[test]
    fn arch_instruction_pointer() {
        let arch = make_arch();
        let pc = arch.instruction_pointer().unwrap();
        assert_eq!(pc.name, "pc");
    }

    #[test]
    fn arch_disassemble_chunk() {
        let arch = make_arch();
        let data = vec![0x90u8; 5];
        let instrs = arch.disassemble_chunk(Address::new(0), &data, 3).unwrap();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[2].address, Address::new(2));
    }

    #[test]
    fn arch_disassemble_empty_errors() {
        let arch = make_arch();
        let result = arch.disassemble(Address::new(0), &[]);
        assert!(result.is_err());
    }

    // ── ArchitectureRegistry ──────────────────────────────────────────────────

    #[test]
    fn registry_register_and_find() {
        let reg = ArchitectureRegistry::new();
        let arch = make_arch();
        reg.register(arch);
        assert!(reg.find_by_name("stub32").is_some());
        assert!(reg.find_by_name("nonexistent").is_none());
    }

    #[test]
    fn registry_count() {
        let reg = ArchitectureRegistry::new();
        assert_eq!(reg.count(), 0);
        reg.register(std::sync::Arc::new(StubArch::new("a", 4, Endian::Little)));
        reg.register(std::sync::Arc::new(StubArch::new("b", 8, Endian::Big)));
        assert_eq!(reg.count(), 2);
    }

    #[test]
    fn registry_list_names() {
        let reg = ArchitectureRegistry::new();
        reg.register(std::sync::Arc::new(StubArch::new(
            "alpha",
            4,
            Endian::Little,
        )));
        reg.register(std::sync::Arc::new(StubArch::new("beta", 8, Endian::Big)));
        let names = reg.list_names();
        assert!(names.contains(&"alpha".to_string()));
        assert!(names.contains(&"beta".to_string()));
    }

    #[test]
    fn registry_find_by_pointer_size() {
        let reg = ArchitectureRegistry::new();
        reg.register(std::sync::Arc::new(StubArch::new("x32", 4, Endian::Little)));
        reg.register(std::sync::Arc::new(StubArch::new("x64", 8, Endian::Little)));
        let results = reg.find_by_pointer_size(4);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name(), "x32");
    }

    #[test]
    fn registry_unregister() {
        let reg = ArchitectureRegistry::new();
        reg.register(std::sync::Arc::new(StubArch::new("temp", 4, Endian::Big)));
        assert!(reg.find_by_name("temp").is_some());
        let removed = reg.unregister("temp");
        assert!(removed);
        assert!(reg.find_by_name("temp").is_none());
        assert!(!reg.unregister("temp")); // already gone
    }
}
