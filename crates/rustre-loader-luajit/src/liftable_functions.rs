//! `liftable_functions` â€” LLIL-equivalent lift for `LuaJIT` bytecode.
//!
//! This module translates `LuaJIT` bytecode instructions into a simple
//! Intermediate Language (IL) that abstracts away opcode details and expresses
//! the instruction's effect in terms of typed IL operations.
//!
//! # IL Operations
//! - **MOV**   â€” register-to-register copy
//! - **LOAD**  â€” load from a constant or upvalue
//! - **STORE** â€” store to an upvalue or table slot
//! - **ARITH** â€” binary arithmetic (add/sub/mul/div/mod/pow/concat)
//! - **UNARY** â€” unary operation (neg/not/len)
//! - **CALL**  â€” function call with argument/result count
//! - **RET**   â€” function return
//! - **JCC**   â€” conditional jump (comparison + branch target)
//! - **JMP**   â€” unconditional jump
//! - **PHI**   â€” SSA Ï†-node placeholder inserted at join points
//! - **NOP**   â€” no operation (loop hints, function headers, etc.)
//!
//! # Design notes
//! The lift is intentionally low-level and non-SSA â€” callers can apply an
//! SSA construction pass on top if needed.  Each `LjLiftedInsn` carries the
//! original PC and raw instruction for traceability.

use std::fmt;

use serde::{Deserialize, Serialize};

pub use crate::bytecode_format::LJ_OP_TABLE;
use crate::{KNumConst, LjProto};

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// IlArithOp
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Arithmetic operation kind in the lifted IL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IlArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Concat,
}

impl fmt::Display for IlArithOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
            Self::Pow => "^",
            Self::Concat => "..",
        };
        write!(f, "{s}")
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// IlUnaryOp
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Unary operation kind in the lifted IL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IlUnaryOp {
    Neg,
    Not,
    Len,
}

impl fmt::Display for IlUnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Neg => "-",
            Self::Not => "not ",
            Self::Len => "#",
        };
        write!(f, "{s}")
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// IlCmpOp
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Comparison predicate for a conditional-jump instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IlCmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    /// Test that a register holds a truthy value.
    IsTrue,
    /// Test that a register holds a falsy value.
    IsFalse,
    /// Type-check: `type(reg) == expected_type`.
    IsType,
    /// Numeric type-check.
    IsNum,
}

impl fmt::Display for IlCmpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Eq => "==",
            Self::Ne => "~=",
            Self::IsTrue => "istrue",
            Self::IsFalse => "isfalse",
            Self::IsType => "istype",
            Self::IsNum => "isnum",
        };
        write!(f, "{s}")
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// IlOperand â€” an IL operand
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// An operand in the lifted IL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IlOperand {
    /// Stack register (slot number).
    Reg(u8),
    /// Integer immediate.
    ImmInt(i32),
    /// Float immediate.
    ImmFloat(f64),
    /// String constant from KGC table.
    ConstStr(String),
    /// Upvalue index.
    Upval(u8),
    /// Primitive nil/false/true (0/1/2).
    Prim(u8),
    /// Child prototype index.
    ProtoRef(u16),
    /// `KNum` constant index (unresolved).
    KNumIdx(u16),
    /// KGC string constant index (unresolved).
    KGCIdx(u16),
    /// Absolute PC of a jump target.
    Label(usize),
    /// Nil / absent.
    None,
}

impl IlOperand {
    /// True if this operand is a register.
    #[must_use]
    pub const fn is_reg(&self) -> bool {
        matches!(self, Self::Reg(_))
    }
    /// True if this is a label (jump target PC).
    #[must_use]
    pub const fn is_label(&self) -> bool {
        matches!(self, Self::Label(_))
    }
}

impl fmt::Display for IlOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reg(r) => write!(f, "r{r}"),
            Self::ImmInt(v) => write!(f, "{v}"),
            Self::ImmFloat(v) => write!(f, "{v}"),
            Self::ConstStr(s) => write!(f, "\"{s}\""),
            Self::Upval(u) => write!(f, "uv[{u}]"),
            Self::Prim(0) => write!(f, "nil"),
            Self::Prim(1) => write!(f, "false"),
            Self::Prim(2) => write!(f, "true"),
            Self::Prim(v) => write!(f, "pri({v})"),
            Self::ProtoRef(p) => write!(f, "proto[{p}]"),
            Self::KNumIdx(i) => write!(f, "kn[{i}]"),
            Self::KGCIdx(i) => write!(f, "kgc[{i}]"),
            Self::Label(pc) => write!(f, "L{pc:04}"),
            Self::None => write!(f, "_"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// IlOp â€” IL operation variant
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// An IL operation â€” describes *what* a lifted instruction does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IlOp {
    /// `dst = src`
    Mov { dst: IlOperand, src: IlOperand },
    /// `dst = constant` (from KGC, KN, KPRI, KSHORT, or KNIL range)
    Load { dst: IlOperand, src: IlOperand },
    /// `dst = constant` (numeric from KN table, already resolved if possible)
    LoadNum { dst: IlOperand, src: IlOperand },
    /// Store to upvalue or table slot: `target[key] = value`
    Store {
        target: IlOperand,
        key: IlOperand,
        value: IlOperand,
    },
    /// Binary arithmetic: `dst = lhs op rhs`
    Arith {
        dst: IlOperand,
        op: IlArithOp,
        lhs: IlOperand,
        rhs: IlOperand,
    },
    /// Unary operation: `dst = op src`
    Unary {
        dst: IlOperand,
        op: IlUnaryOp,
        src: IlOperand,
    },
    /// Function call: `base(args) â†’ results`
    Call {
        base: IlOperand,
        num_args: u8,
        num_results: u8,
        is_tail: bool,
    },
    /// Return from function.
    Ret { base: IlOperand, count: u8 },
    /// Conditional jump: if `cmp(lhs, rhs)` goto `target`, else fall through.
    Jcc {
        cmp: IlCmpOp,
        lhs: IlOperand,
        rhs: IlOperand,
        target: IlOperand,
    },
    /// Unconditional jump.
    Jmp { target: IlOperand },
    /// Close upvalues up to slot `upto` and jump.
    CloseUv { upto: u8, target: IlOperand },
    /// New table: `dst = {}` with given array/hash hints.
    NewTable {
        dst: IlOperand,
        asize: u16,
        hsize: u16,
    },
    /// Table get: `dst = table[key]`
    TGet {
        dst: IlOperand,
        table: IlOperand,
        key: IlOperand,
    },
    /// Table set: `table[key] = value`
    TSet {
        table: IlOperand,
        key: IlOperand,
        value: IlOperand,
    },
    /// New closure: `dst = new closure(proto)`
    FNew { dst: IlOperand, proto: IlOperand },
    /// Load global: `dst = _ENV[name]`
    GGet { dst: IlOperand, name: IlOperand },
    /// Store global: `_ENV[name] = src`
    GSet { name: IlOperand, src: IlOperand },
    /// Iterator call placeholder.
    IterCall { base: IlOperand },
    /// Loop header / back-edge hint.
    LoopHint,
    /// Vararg: `dst..dst+count = vararg`
    Varg { base: u8, count: u8 },
    /// SSA Ï†-node: `dst = Ï†(operandsâ€¦)` â€” inserted at control-flow join points.
    Phi {
        dst: IlOperand,
        operands: Vec<IlOperand>,
    },
    /// No operation.
    Nop,
}

impl fmt::Display for IlOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mov { dst, src } => write!(f, "MOV {dst} = {src}"),
            Self::Load { dst, src } => write!(f, "LOAD {dst} = {src}"),
            Self::LoadNum { dst, src } => write!(f, "LOADN {dst} = {src}"),
            Self::Store { target, key, value } => write!(f, "STORE {target}[{key}] = {value}"),
            Self::Arith { dst, op, lhs, rhs } => write!(f, "ARITH {dst} = {lhs} {op} {rhs}"),
            Self::Unary { dst, op, src } => write!(f, "UNARY {dst} = {op}{src}"),
            Self::Call {
                base,
                num_args,
                num_results,
                is_tail,
            } => {
                let kind = if *is_tail { "CALLT" } else { "CALL" };
                write!(f, "{kind} {base}({num_args}) -> {num_results}")
            }
            Self::Ret { base, count } => write!(f, "RET {base} #{count}"),
            Self::Jcc {
                cmp,
                lhs,
                rhs,
                target,
            } => write!(f, "JCC if {lhs} {cmp} {rhs} -> {target}"),
            Self::Jmp { target } => write!(f, "JMP {target}"),
            Self::CloseUv { upto, target } => write!(f, "CLOSEUVS upto=r{upto} then {target}"),
            Self::NewTable { dst, asize, hsize } => {
                write!(f, "TNEW {dst} asize={asize} hsize={hsize}")
            }
            Self::TGet { dst, table, key } => write!(f, "TGET {dst} = {table}[{key}]"),
            Self::TSet { table, key, value } => write!(f, "TSET {table}[{key}] = {value}"),
            Self::FNew { dst, proto } => write!(f, "FNEW {dst} = {proto}"),
            Self::GGet { dst, name } => write!(f, "GGET {dst} = _ENV[{name}]"),
            Self::GSet { name, src } => write!(f, "GSET _ENV[{name}] = {src}"),
            Self::IterCall { base } => write!(f, "ITER_CALL {base}"),
            Self::LoopHint => write!(f, "LOOP_HINT"),
            Self::Varg { base, count } => write!(f, "VARG r{base} #{count}"),
            Self::Phi { dst, operands } => {
                write!(f, "PHI {dst} = Ï†(")?;
                for (i, op) in operands.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{op}")?;
                }
                write!(f, ")")
            }
            Self::Nop => write!(f, "NOP"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LjLiftedInsn â€” a single lifted instruction
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A single lifted instruction.
///
/// Each lifted instruction traces back to a bytecode PC and retains the
/// original raw word for debugging.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LjLiftedInsn {
    /// Bytecode program counter (instruction index).
    pub pc: usize,
    /// The lifted IL operation.
    pub op: IlOp,
    /// Raw 32-bit bytecode word.
    pub raw: u32,
    /// Source line, if debug info is present.
    pub source_line: Option<u32>,
}

impl LjLiftedInsn {
    const fn new(pc: usize, op: IlOp, raw: u32, source_line: Option<u32>) -> Self {
        Self {
            pc,
            op,
            raw,
            source_line,
        }
    }
}

impl fmt::Display for LjLiftedInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let line = self
            .source_line
            .map(|l| format!(" ; line:{l}"))
            .unwrap_or_default();
        write!(f, "{:04}  {}{}", self.pc, self.op, line)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftedFunction â€” all lifted instructions for one prototype
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A fully-lifted function prototype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftedFunction {
    /// Source name, if available.
    pub name: Option<String>,
    /// Number of parameters.
    pub num_params: u8,
    /// Maximum register count.
    pub frame_size: u8,
    /// Whether the function is vararg.
    pub is_vararg: bool,
    /// The lifted instruction stream.
    pub insns: Vec<LjLiftedInsn>,
}

impl LiftedFunction {
    /// Number of lifted instructions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.insns.len()
    }

    /// True if the function has no instructions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// Iterate over lifted instructions.
    pub fn iter(&self) -> impl Iterator<Item = &LjLiftedInsn> {
        self.insns.iter()
    }

    /// Count instructions with a given IL operation kind.
    #[must_use]
    pub fn count_op_kind(&self, pred: impl Fn(&IlOp) -> bool) -> usize {
        self.insns.iter().filter(|i| pred(&i.op)).count()
    }

    /// Return all call instructions.
    #[must_use]
    pub fn calls(&self) -> Vec<&LjLiftedInsn> {
        self.insns
            .iter()
            .filter(|i| matches!(i.op, IlOp::Call { .. }))
            .collect()
    }

    /// Return all return instructions.
    #[must_use]
    pub fn returns(&self) -> Vec<&LjLiftedInsn> {
        self.insns
            .iter()
            .filter(|i| matches!(i.op, IlOp::Ret { .. }))
            .collect()
    }

    /// Return all conditional jump instructions.
    #[must_use]
    pub fn branches(&self) -> Vec<&LjLiftedInsn> {
        self.insns
            .iter()
            .filter(|i| matches!(i.op, IlOp::Jcc { .. } | IlOp::Jmp { .. }))
            .collect()
    }
}

impl fmt::Display for LiftedFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("?");
        writeln!(
            f,
            "; LiftedFunction [{name}] params={} frame={} vararg={} insns={}",
            self.num_params,
            self.frame_size,
            self.is_vararg,
            self.insns.len()
        )?;
        for insn in &self.insns {
            writeln!(f, "  {insn}")?;
        }
        Ok(())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// emit_lifted_function â€” main lift entry point
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Lift a `LuaJIT` prototype into a `LiftedFunction`.
///
/// Each bytecode instruction is translated to one or more IL operations.  The
/// resulting stream preserves the original PC indices and source-line
/// annotations from the prototype's debug info.
#[must_use]
pub fn emit_lifted_function(proto: &LjProto) -> LiftedFunction {
    let count = proto.instructions.len();
    let mut insns = Vec::with_capacity(count);

    for (pc, raw_instr) in proto.instructions.iter().enumerate() {
        let raw = raw_instr.0;
        let op = (raw & 0xFF) as u8;
        let op_a = ((raw >> 8) & 0xFF) as u8;
        let op_b = ((raw >> 24) & 0xFF) as u8;
        let op_c = ((raw >> 16) & 0xFF) as u8;
        let op_d = ((raw >> 16) & 0xFFFF) as u16;
        let jmp = i32::from(op_d) - 0x8000;
        let line = proto.source_line(pc);

        let target_pc = (pc as i64 + 1 + i64::from(jmp)).max(0) as usize;
        let target_lbl = || IlOperand::Label(target_pc.min(count.saturating_sub(1)));

        let kgc_op = |idx: u16| -> IlOperand {
            proto
                .kgc
                .get(idx as usize)
                .and_then(|k| k.as_str())
                .map(|s| IlOperand::ConstStr(s.to_string()))
                .unwrap_or(IlOperand::KGCIdx(idx))
        };
        let kn_op = |idx: u16| -> IlOperand {
            match proto.kn.get(idx as usize) {
                Some(KNumConst::Int(v)) => IlOperand::ImmInt(*v),
                Some(KNumConst::Float(v)) => IlOperand::ImmFloat(*v),
                None => IlOperand::KNumIdx(idx),
            }
        };

        let il_op: IlOp = match op {
            // â”€â”€ Comparisons â†’ JCC (comparison + implicit JMP PC+2) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x00 => IlOp::Jcc {
                cmp: IlCmpOp::Lt,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::Reg(op_d as u8),
                target: target_lbl(),
            },
            0x01 => IlOp::Jcc {
                cmp: IlCmpOp::Ge,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::Reg(op_d as u8),
                target: target_lbl(),
            },
            0x02 => IlOp::Jcc {
                cmp: IlCmpOp::Le,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::Reg(op_d as u8),
                target: target_lbl(),
            },
            0x03 => IlOp::Jcc {
                cmp: IlCmpOp::Gt,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::Reg(op_d as u8),
                target: target_lbl(),
            },
            0x04 => IlOp::Jcc {
                cmp: IlCmpOp::Eq,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::Reg(op_d as u8),
                target: target_lbl(),
            },
            0x05 => IlOp::Jcc {
                cmp: IlCmpOp::Ne,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::Reg(op_d as u8),
                target: target_lbl(),
            },
            0x06 => IlOp::Jcc {
                cmp: IlCmpOp::Eq,
                lhs: IlOperand::Reg(op_a),
                rhs: kgc_op(op_d),
                target: target_lbl(),
            },
            0x07 => IlOp::Jcc {
                cmp: IlCmpOp::Ne,
                lhs: IlOperand::Reg(op_a),
                rhs: kgc_op(op_d),
                target: target_lbl(),
            },
            0x08 => IlOp::Jcc {
                cmp: IlCmpOp::Eq,
                lhs: IlOperand::Reg(op_a),
                rhs: kn_op(op_d),
                target: target_lbl(),
            },
            0x09 => IlOp::Jcc {
                cmp: IlCmpOp::Ne,
                lhs: IlOperand::Reg(op_a),
                rhs: kn_op(op_d),
                target: target_lbl(),
            },
            0x0A => IlOp::Jcc {
                cmp: IlCmpOp::Eq,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::Prim(op_d as u8),
                target: target_lbl(),
            },
            0x0B => IlOp::Jcc {
                cmp: IlCmpOp::Ne,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::Prim(op_d as u8),
                target: target_lbl(),
            },
            // â”€â”€ Test+copy â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x0C => {
                insns.push(LjLiftedInsn::new(
                    pc,
                    IlOp::Jcc {
                        cmp: IlCmpOp::IsTrue,
                        lhs: IlOperand::Reg(op_a),
                        rhs: IlOperand::None,
                        target: target_lbl(),
                    },
                    raw,
                    line,
                ));
                LjLiftedInsn::new(
                    pc,
                    IlOp::Mov {
                        dst: IlOperand::Reg(op_d as u8),
                        src: IlOperand::Reg(op_a),
                    },
                    raw,
                    line,
                );
                continue;
            }
            0x0D => {
                insns.push(LjLiftedInsn::new(
                    pc,
                    IlOp::Jcc {
                        cmp: IlCmpOp::IsFalse,
                        lhs: IlOperand::Reg(op_a),
                        rhs: IlOperand::None,
                        target: target_lbl(),
                    },
                    raw,
                    line,
                ));
                LjLiftedInsn::new(
                    pc,
                    IlOp::Mov {
                        dst: IlOperand::Reg(op_d as u8),
                        src: IlOperand::Reg(op_a),
                    },
                    raw,
                    line,
                );
                continue;
            }
            0x0E => IlOp::Jcc {
                cmp: IlCmpOp::IsTrue,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::None,
                target: target_lbl(),
            },
            0x0F => IlOp::Jcc {
                cmp: IlCmpOp::IsFalse,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::None,
                target: target_lbl(),
            },
            0x10 => IlOp::Jcc {
                cmp: IlCmpOp::IsType,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::ImmInt(i32::from(op_d)),
                target: target_lbl(),
            },
            0x11 => IlOp::Jcc {
                cmp: IlCmpOp::IsNum,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::None,
                target: target_lbl(),
            },
            // â”€â”€ Unary ops â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x12 => IlOp::Mov {
                dst: IlOperand::Reg(op_a),
                src: IlOperand::Reg(op_d as u8),
            },
            0x13 => IlOp::Unary {
                dst: IlOperand::Reg(op_a),
                op: IlUnaryOp::Not,
                src: IlOperand::Reg(op_d as u8),
            },
            0x14 => IlOp::Unary {
                dst: IlOperand::Reg(op_a),
                op: IlUnaryOp::Neg,
                src: IlOperand::Reg(op_d as u8),
            },
            0x15 => IlOp::Unary {
                dst: IlOperand::Reg(op_a),
                op: IlUnaryOp::Len,
                src: IlOperand::Reg(op_d as u8),
            },
            // â”€â”€ Binary arith: reg op numconst â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x16 => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Add,
                lhs: IlOperand::Reg(op_b),
                rhs: kn_op(u16::from(op_c)),
            },
            0x17 => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Sub,
                lhs: IlOperand::Reg(op_b),
                rhs: kn_op(u16::from(op_c)),
            },
            0x18 => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Mul,
                lhs: IlOperand::Reg(op_b),
                rhs: kn_op(u16::from(op_c)),
            },
            0x19 => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Div,
                lhs: IlOperand::Reg(op_b),
                rhs: kn_op(u16::from(op_c)),
            },
            0x1A => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Mod,
                lhs: IlOperand::Reg(op_b),
                rhs: kn_op(u16::from(op_c)),
            },
            // â”€â”€ Binary arith: numconst op reg â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x1B => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Add,
                lhs: kn_op(u16::from(op_c)),
                rhs: IlOperand::Reg(op_b),
            },
            0x1C => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Sub,
                lhs: kn_op(u16::from(op_c)),
                rhs: IlOperand::Reg(op_b),
            },
            0x1D => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Mul,
                lhs: kn_op(u16::from(op_c)),
                rhs: IlOperand::Reg(op_b),
            },
            0x1E => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Div,
                lhs: kn_op(u16::from(op_c)),
                rhs: IlOperand::Reg(op_b),
            },
            0x1F => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Mod,
                lhs: kn_op(u16::from(op_c)),
                rhs: IlOperand::Reg(op_b),
            },
            // â”€â”€ Binary arith: reg op reg â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x20 => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Add,
                lhs: IlOperand::Reg(op_b),
                rhs: IlOperand::Reg(op_c),
            },
            0x21 => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Sub,
                lhs: IlOperand::Reg(op_b),
                rhs: IlOperand::Reg(op_c),
            },
            0x22 => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Mul,
                lhs: IlOperand::Reg(op_b),
                rhs: IlOperand::Reg(op_c),
            },
            0x23 => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Div,
                lhs: IlOperand::Reg(op_b),
                rhs: IlOperand::Reg(op_c),
            },
            0x24 => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Mod,
                lhs: IlOperand::Reg(op_b),
                rhs: IlOperand::Reg(op_c),
            },
            0x25 => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Pow,
                lhs: IlOperand::Reg(op_b),
                rhs: IlOperand::Reg(op_c),
            },
            0x26 => IlOp::Arith {
                dst: IlOperand::Reg(op_a),
                op: IlArithOp::Concat,
                lhs: IlOperand::Reg(op_b),
                rhs: IlOperand::Reg(op_c),
            },
            // â”€â”€ Constant loads â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x27 => IlOp::Load {
                dst: IlOperand::Reg(op_a),
                src: kgc_op(op_d),
            },
            0x28 => IlOp::Load {
                dst: IlOperand::Reg(op_a),
                src: IlOperand::KGCIdx(op_d),
            },
            0x29 => IlOp::Load {
                dst: IlOperand::Reg(op_a),
                src: IlOperand::ImmInt(jmp),
            },
            0x2A => IlOp::LoadNum {
                dst: IlOperand::Reg(op_a),
                src: kn_op(op_d),
            },
            0x2B => IlOp::Load {
                dst: IlOperand::Reg(op_a),
                src: IlOperand::Prim(op_d as u8),
            },
            0x2C => IlOp::Load {
                dst: IlOperand::Reg(op_a),
                src: IlOperand::Prim(0),
            }, // KNIL range â†’ nil
            // â”€â”€ Upvalue ops â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x2D => IlOp::Load {
                dst: IlOperand::Reg(op_a),
                src: IlOperand::Upval(op_d as u8),
            },
            0x2E => IlOp::Store {
                target: IlOperand::Upval(op_a),
                key: IlOperand::None,
                value: IlOperand::Reg(op_d as u8),
            },
            0x2F => IlOp::Store {
                target: IlOperand::Upval(op_a),
                key: IlOperand::None,
                value: kgc_op(op_d),
            },
            0x30 => IlOp::Store {
                target: IlOperand::Upval(op_a),
                key: IlOperand::None,
                value: kn_op(op_d),
            },
            0x31 => IlOp::Store {
                target: IlOperand::Upval(op_a),
                key: IlOperand::None,
                value: IlOperand::Prim(op_d as u8),
            },
            0x32 => IlOp::CloseUv {
                upto: op_a,
                target: target_lbl(),
            },
            0x33 => IlOp::FNew {
                dst: IlOperand::Reg(op_a),
                proto: IlOperand::ProtoRef(op_d),
            },
            // â”€â”€ Table ops â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x34 => IlOp::NewTable {
                dst: IlOperand::Reg(op_a),
                asize: op_d & 0x7FF,
                hsize: op_d >> 11,
            },
            0x35 => IlOp::Load {
                dst: IlOperand::Reg(op_a),
                src: IlOperand::KGCIdx(op_d),
            }, // TDUP
            0x36 => IlOp::GGet {
                dst: IlOperand::Reg(op_a),
                name: kgc_op(op_d),
            },
            0x37 => IlOp::GSet {
                name: kgc_op(op_d),
                src: IlOperand::Reg(op_a),
            },
            0x38 => IlOp::TGet {
                dst: IlOperand::Reg(op_a),
                table: IlOperand::Reg(op_b),
                key: IlOperand::Reg(op_c),
            },
            0x39 => IlOp::TGet {
                dst: IlOperand::Reg(op_a),
                table: IlOperand::Reg(op_b),
                key: kgc_op(u16::from(op_c)),
            },
            0x3A => IlOp::TGet {
                dst: IlOperand::Reg(op_a),
                table: IlOperand::Reg(op_b),
                key: IlOperand::ImmInt(i32::from(op_c)),
            },
            0x3B => IlOp::TGet {
                dst: IlOperand::Reg(op_a),
                table: IlOperand::Reg(op_b),
                key: IlOperand::None,
            },
            0x3C => IlOp::TSet {
                table: IlOperand::Reg(op_b),
                key: IlOperand::Reg(op_c),
                value: IlOperand::Reg(op_a),
            },
            0x3D => IlOp::TSet {
                table: IlOperand::Reg(op_b),
                key: kgc_op(u16::from(op_c)),
                value: IlOperand::Reg(op_a),
            },
            0x3E => IlOp::TSet {
                table: IlOperand::Reg(op_b),
                key: IlOperand::ImmInt(i32::from(op_c)),
                value: IlOperand::Reg(op_a),
            },
            0x3F => IlOp::TSet {
                table: IlOperand::Reg(op_b),
                key: IlOperand::None,
                value: IlOperand::Reg(op_a),
            },
            0x40 => IlOp::TSet {
                table: IlOperand::Reg(op_b),
                key: IlOperand::Reg(op_c),
                value: IlOperand::Reg(op_a),
            }, // TSETR raw
            // â”€â”€ Calls â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x41 => IlOp::Call {
                base: IlOperand::Reg(op_a),
                num_args: op_c,
                num_results: op_b.saturating_sub(1),
                is_tail: false,
            },
            0x42 => IlOp::Call {
                base: IlOperand::Reg(op_a),
                num_args: op_c.saturating_sub(1),
                num_results: op_b.saturating_sub(1),
                is_tail: false,
            },
            0x43 => IlOp::Call {
                base: IlOperand::Reg(op_a),
                num_args: op_d as u8,
                num_results: 0xFF,
                is_tail: true,
            },
            0x44 => IlOp::Call {
                base: IlOperand::Reg(op_a),
                num_args: op_d.saturating_sub(1) as u8,
                num_results: 0xFF,
                is_tail: true,
            },
            0x45 | 0x46 => IlOp::IterCall {
                base: IlOperand::Reg(op_a),
            },
            0x47 => IlOp::Varg {
                base: op_a,
                count: op_b.saturating_sub(1),
            },
            0x48 => IlOp::Jcc {
                cmp: IlCmpOp::IsTrue,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::None,
                target: target_lbl(),
            },
            // â”€â”€ Returns â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x49 => IlOp::Ret {
                base: IlOperand::Reg(op_a),
                count: 0xFF,
            }, // multi-result
            0x4A => IlOp::Ret {
                base: IlOperand::Reg(op_a),
                count: op_d.saturating_sub(2) as u8,
            },
            0x4B => IlOp::Ret {
                base: IlOperand::None,
                count: 0,
            },
            0x4C => IlOp::Ret {
                base: IlOperand::Reg(op_a),
                count: 1,
            },
            // â”€â”€ Loops / branches â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x4D | 0x4E => IlOp::Jcc {
                cmp: IlCmpOp::Lt,
                lhs: IlOperand::Reg(op_a),
                rhs: IlOperand::Reg(op_a + 2),
                target: target_lbl(),
            },
            0x4F..=0x51 => IlOp::Jmp {
                target: target_lbl(),
            },
            0x52..=0x54 => IlOp::Jmp {
                target: target_lbl(),
            },
            0x55..=0x57 => IlOp::LoopHint,
            // â”€â”€ JMP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x58 => IlOp::Jmp {
                target: target_lbl(),
            },
            // â”€â”€ Function headers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            0x59..=0x60 => IlOp::Nop,
            // â”€â”€ Unknown â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            _ => IlOp::Nop,
        };

        insns.push(LjLiftedInsn::new(pc, il_op, raw, line));
    }

    LiftedFunction {
        name: proto.source_name.clone(),
        num_params: proto.num_params,
        frame_size: proto.frame_size,
        is_vararg: proto.is_vararg,
        insns,
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// insert_phi_nodes â€” simplified Ï†-node insertion at join points
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Insert `PHI` placeholder nodes at PCs that are targets of two or more
/// distinct branch instructions.
///
/// This is a simple structural approximation: a Ï†-node is inserted for each
/// register that is written before the join point in at least two predecessor
/// paths.  In practice this is used as a hint for later SSA construction.
pub fn insert_phi_nodes(func: &mut LiftedFunction) {
    // Gather all branch targets
    let mut target_counts: std::collections::HashMap<usize, usize> =
        std::collections::HashMap::new();
    for insn in &func.insns {
        match &insn.op {
            IlOp::Jmp {
                target: IlOperand::Label(t),
            } => {
                *target_counts.entry(*t).or_insert(0) += 1;
            }
            IlOp::Jcc {
                target: IlOperand::Label(t),
                ..
            } => {
                *target_counts.entry(*t).or_insert(0) += 1;
            }
            _ => {}
        }
    }

    // Identify join points (2+ predecessors)
    let join_points: std::collections::HashSet<usize> = target_counts
        .into_iter()
        .filter(|(_, count)| *count >= 2)
        .map(|(pc, _)| pc)
        .collect();

    if join_points.is_empty() {
        return;
    }

    // Insert a PHI placeholder at each join point
    // We insert them at the right positions without disturbing existing PCs
    let mut new_insns: Vec<LjLiftedInsn> = Vec::with_capacity(func.insns.len() + join_points.len());
    for insn in func.insns.drain(..) {
        if join_points.contains(&insn.pc) {
            // Insert a placeholder Ï†-node (empty operand list = to be filled by SSA pass)
            new_insns.push(LjLiftedInsn::new(
                insn.pc,
                IlOp::Phi {
                    dst: IlOperand::None,
                    operands: vec![],
                },
                0,
                insn.source_line,
            ));
        }
        new_insns.push(insn);
    }
    func.insns = new_insns;
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KGC, KNumConst, LjConst, LjInstr, LjProtoFlags, LjUpvalue};

    fn proto_from_words(words: &[u32]) -> LjProto {
        LjProto {
            flags: LjProtoFlags::empty(),
            num_params: 0,
            frame_size: 8,
            num_upvalues: 0,
            is_vararg: false,
            instructions: words.iter().map(|&w| LjInstr(w)).collect(),
            upvalues: vec![],
            kgc: vec![KGC::String("hello".to_string())],
            kn: vec![KNumConst::Int(42)],
            constants: vec![LjConst::Str("hello".to_string())],
            instruction_count: words.len() as u32,
            debug_info: None,
            source_name: Some("test.lua".to_string()),
            first_line: 0,
            num_lines: 0,
            line_info: vec![],
            local_vars: vec![],
            upvalue_names: vec![],
        }
    }

    fn proto_with_uv(words: &[u32]) -> LjProto {
        let mut p = proto_from_words(words);
        p.num_upvalues = 1;
        p.upvalues = vec![LjUpvalue {
            slot: 0,
            is_local: false,
            name: Some("_ENV".into()),
        }];
        p.upvalue_names = vec!["_ENV".to_string()];
        p
    }

    // â”€â”€ IlArithOp â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_il_arith_op_display() {
        assert_eq!(IlArithOp::Add.to_string(), "+");
        assert_eq!(IlArithOp::Concat.to_string(), "..");
        assert_eq!(IlArithOp::Pow.to_string(), "^");
    }

    // â”€â”€ IlUnaryOp â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_il_unary_op_display() {
        assert_eq!(IlUnaryOp::Neg.to_string(), "-");
        assert_eq!(IlUnaryOp::Not.to_string(), "not ");
        assert_eq!(IlUnaryOp::Len.to_string(), "#");
    }

    // â”€â”€ IlCmpOp â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_il_cmp_op_display() {
        assert_eq!(IlCmpOp::Lt.to_string(), "<");
        assert_eq!(IlCmpOp::Eq.to_string(), "==");
        assert_eq!(IlCmpOp::IsTrue.to_string(), "istrue");
    }

    // â”€â”€ IlOperand â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_il_operand_display_reg() {
        assert_eq!(IlOperand::Reg(3).to_string(), "r3");
    }
    #[test]
    fn test_il_operand_display_prim_nil() {
        assert_eq!(IlOperand::Prim(0).to_string(), "nil");
    }
    #[test]
    fn test_il_operand_display_prim_true() {
        assert_eq!(IlOperand::Prim(2).to_string(), "true");
    }
    #[test]
    fn test_il_operand_display_label() {
        assert_eq!(IlOperand::Label(5).to_string(), "L0005");
    }
    #[test]
    fn test_il_operand_is_reg() {
        assert!(IlOperand::Reg(0).is_reg());
        assert!(!IlOperand::Label(0).is_reg());
    }

    // â”€â”€ emit_lifted_function: RET0 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_ret0() {
        let proto = proto_from_words(&[0x0000_004B]);
        let f = emit_lifted_function(&proto);
        assert_eq!(f.len(), 1);
        assert!(matches!(f.insns[0].op, IlOp::Ret { .. }));
    }

    #[test]
    fn test_lift_ret0_count_zero() {
        let proto = proto_from_words(&[0x0000_004B]);
        let f = emit_lifted_function(&proto);
        if let IlOp::Ret { count, .. } = &f.insns[0].op {
            assert_eq!(*count, 0);
        } else {
            panic!("expected Ret");
        }
    }

    // â”€â”€ emit_lifted_function: MOV â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_mov() {
        // MOV A=1 D=2: r1 = r2
        let raw = 0x12u32 | (0x01u32 << 8) | (0x02u32 << 16);
        let proto = proto_from_words(&[raw]);
        let f = emit_lifted_function(&proto);
        assert!(matches!(
            f.insns[0].op,
            IlOp::Mov {
                dst: IlOperand::Reg(1),
                src: IlOperand::Reg(2)
            }
        ));
    }

    // â”€â”€ emit_lifted_function: KSTR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_kstr_resolves_string() {
        // KSTR A=0 D=0 â†’ Load "hello"
        let raw = 0x27u32;
        let proto = proto_from_words(&[raw]);
        let f = emit_lifted_function(&proto);
        if let IlOp::Load {
            dst: IlOperand::Reg(0),
            src: IlOperand::ConstStr(ref s),
        } = f.insns[0].op
        {
            assert_eq!(s, "hello");
        } else {
            panic!("expected Load with ConstStr, got {:?}", f.insns[0].op);
        }
    }

    // â”€â”€ emit_lifted_function: KSHORT â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_kshort() {
        // KSHORT A=2 D=0x8005 â†’ j=5
        let raw = 0x29u32 | (0x02u32 << 8) | (0x8005u32 << 16);
        let proto = proto_from_words(&[raw]);
        let f = emit_lifted_function(&proto);
        assert!(matches!(
            f.insns[0].op,
            IlOp::Load {
                dst: IlOperand::Reg(2),
                src: IlOperand::ImmInt(5)
            }
        ));
    }

    // â”€â”€ emit_lifted_function: arithmetic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_addvv() {
        // ADDVV A=0 B=1 C=2: r0 = r1 + r2
        let raw = 0x20u32 | (0x02u32 << 16) | (0x01u32 << 24);
        let proto = proto_from_words(&[raw]);
        let f = emit_lifted_function(&proto);
        assert!(matches!(
            f.insns[0].op,
            IlOp::Arith {
                op: IlArithOp::Add,
                lhs: IlOperand::Reg(1),
                rhs: IlOperand::Reg(2),
                ..
            }
        ));
    }

    #[test]
    fn test_lift_unm() {
        // UNM A=0 D=1: r0 = -r1
        let raw = 0x14u32 | (0x01u32 << 16);
        let proto = proto_from_words(&[raw]);
        let f = emit_lifted_function(&proto);
        assert!(matches!(
            f.insns[0].op,
            IlOp::Unary {
                op: IlUnaryOp::Neg,
                src: IlOperand::Reg(1),
                ..
            }
        ));
    }

    // â”€â”€ emit_lifted_function: CALL â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_call() {
        // CALL A=1 B=2 C=3: r1(r2..r3) â†’ 1 result
        let raw = 0x42u32 | (0x01u32 << 8) | (0x03u32 << 16) | (0x02u32 << 24);
        let proto = proto_from_words(&[raw]);
        let f = emit_lifted_function(&proto);
        assert!(matches!(f.insns[0].op, IlOp::Call { is_tail: false, .. }));
    }

    #[test]
    fn test_lift_callt() {
        // CALLT A=1 D=2
        let raw = 0x44u32 | (0x01u32 << 8) | (0x02u32 << 16);
        let proto = proto_from_words(&[raw]);
        let f = emit_lifted_function(&proto);
        assert!(matches!(f.insns[0].op, IlOp::Call { is_tail: true, .. }));
    }

    // â”€â”€ emit_lifted_function: JMP branch target â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_jmp_target() {
        // JMP at pc=0, D=0x8002 â†’ j=2 â†’ target=3
        let raw = 0x58u32 | (0x8002u32 << 16);
        let nop = 0x0000_004Bu32; // RET0
        let proto = proto_from_words(&[raw, nop, nop, nop]);
        let f = emit_lifted_function(&proto);
        assert!(matches!(
            f.insns[0].op,
            IlOp::Jmp {
                target: IlOperand::Label(3)
            }
        ));
    }

    // â”€â”€ emit_lifted_function: GGET/GSET â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_gget() {
        // GGET A=0 D=0 â†’ load _ENV["hello"]
        let raw = 0x36u32;
        let proto = proto_from_words(&[raw]);
        let f = emit_lifted_function(&proto);
        assert!(matches!(f.insns[0].op, IlOp::GGet { .. }));
    }

    // â”€â”€ emit_lifted_function: UGET â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_uget() {
        // UGET A=0 D=0 â†’ r0 = uv[0]
        let raw = 0x2Du32;
        let proto = proto_with_uv(&[raw]);
        let f = emit_lifted_function(&proto);
        assert!(matches!(
            f.insns[0].op,
            IlOp::Load {
                dst: IlOperand::Reg(0),
                src: IlOperand::Upval(0)
            }
        ));
    }

    // â”€â”€ LiftedFunction helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lifted_function_is_empty() {
        let proto = proto_from_words(&[]);
        let f = emit_lifted_function(&proto);
        assert!(f.is_empty());
    }

    #[test]
    fn test_lifted_function_len() {
        let proto = proto_from_words(&[0x0000_004B, 0x0000_004B]);
        let f = emit_lifted_function(&proto);
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn test_lifted_function_returns() {
        let proto = proto_from_words(&[0x0000_004B]);
        let f = emit_lifted_function(&proto);
        assert_eq!(f.returns().len(), 1);
    }

    #[test]
    fn test_lifted_function_calls_empty() {
        let proto = proto_from_words(&[0x0000_004B]);
        let f = emit_lifted_function(&proto);
        assert!(f.calls().is_empty());
    }

    #[test]
    fn test_lifted_function_display_contains_header() {
        let proto = proto_from_words(&[0x0000_004B]);
        let f = emit_lifted_function(&proto);
        let s = f.to_string();
        assert!(s.contains("LiftedFunction"), "got: {s}");
    }

    // â”€â”€ IlOp display â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_il_op_mov_display() {
        let op = IlOp::Mov {
            dst: IlOperand::Reg(0),
            src: IlOperand::Reg(1),
        };
        assert_eq!(op.to_string(), "MOV r0 = r1");
    }

    #[test]
    fn test_il_op_ret_display() {
        let op = IlOp::Ret {
            base: IlOperand::None,
            count: 0,
        };
        assert!(op.to_string().contains("RET"));
    }

    #[test]
    fn test_il_op_jmp_display() {
        let op = IlOp::Jmp {
            target: IlOperand::Label(5),
        };
        assert!(op.to_string().contains("JMP"));
        assert!(op.to_string().contains("L0005"));
    }

    #[test]
    fn test_il_op_phi_display() {
        let op = IlOp::Phi {
            dst: IlOperand::Reg(0),
            operands: vec![IlOperand::Reg(1), IlOperand::Reg(2)],
        };
        let s = op.to_string();
        assert!(s.contains("PHI"));
        assert!(s.contains("r1"));
        assert!(s.contains("r2"));
    }

    // â”€â”€ insert_phi_nodes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_insert_phi_nodes_with_join_point() {
        // pc=0: JMP â†’ pc=2
        // pc=1: JMP â†’ pc=2
        // pc=2: RET0   â† join point (2 predecessors)
        let jmp_to_2 = |pc_at: usize| -> u32 {
            // JMP offset such that target = pc+1+j = 2 â†’ j = 2 - (pc+1) = 1-pc
            let j = 2i32 - (pc_at as i32 + 1);
            let d = (j + 0x8000) as u32;
            0x58u32 | (d << 16)
        };
        let proto = proto_from_words(&[jmp_to_2(0), jmp_to_2(1), 0x0000_004B]);
        let mut f = emit_lifted_function(&proto);
        insert_phi_nodes(&mut f);
        // Should have a PHI node inserted at pc=2
        let phi_count = f
            .insns
            .iter()
            .filter(|i| matches!(i.op, IlOp::Phi { .. }))
            .count();
        assert!(
            phi_count >= 1,
            "expected at least one PHI node, got {phi_count}"
        );
    }

    #[test]
    fn test_insert_phi_nodes_no_branches() {
        let proto = proto_from_words(&[0x0000_004B, 0x0000_004B]);
        let mut f = emit_lifted_function(&proto);
        let original_len = f.len();
        insert_phi_nodes(&mut f);
        // No branches â†’ no PHI nodes added
        assert_eq!(f.len(), original_len);
    }
}
