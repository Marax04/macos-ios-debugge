//! `instruction_decoder` â€” Full `LuaJIT` instruction decoder and disassembler.
//!
//! Provides:
//! - `LjInstruction` â€” richly-decoded instruction with all fields named
//! - `OperandKind`   â€” semantic type annotation for each operand
//! - `DisasmLine`    â€” one line of disassembly output
//! - `decode_instruction()`   â€” decode one 32-bit word â†’ `LjInstruction`
//! - `disassemble_proto()`    â€” decode entire prototype â†’ `Vec<DisasmLine>`
//! - Branch-target resolution within a prototype
//! - Mnemonic strings for all 97 opcodes (delegates to `bytecode_format`)

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::bytecode_format::{InstrWord, LJ_OP_TABLE, OpMode};
use crate::{KNumConst, LjProto};

const fn default_mnemonic() -> &'static str {
    "???"
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// OperandKind â€” semantic annotation for instruction operands
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Semantic kind of an instruction operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperandKind {
    /// A register (stack slot) index.
    Reg,
    /// A primitive constant index (0=nil, 1=false, 2=true).
    Prim,
    /// A numeric constant index into the KN table.
    Num,
    /// A string constant index into the KGC table.
    Str,
    /// An upvalue index.
    Uv,
    /// A signed jump offset (PC-relative).
    Jump,
    /// An unsigned immediate integer.
    Imm,
    /// A child-prototype index.
    Proto,
    /// Not used for this operand position.
    Unused,
}

impl fmt::Display for OperandKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Reg => "REG",
            Self::Prim => "PRIM",
            Self::Num => "NUM",
            Self::Str => "STR",
            Self::Uv => "UV",
            Self::Jump => "JUMP",
            Self::Imm => "IMM",
            Self::Proto => "PROTO",
            Self::Unused => "_",
        };
        write!(f, "{s}")
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// OperandAnnotation â€” (kind, value) pair for a single operand slot
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A (kind, value) pair for a single decoded operand slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperandAnnotation {
    pub kind: OperandKind,
    /// Raw numeric value (register index, constant index, jump offset, etc.).
    pub value: i32,
    /// Optional resolved label string (e.g. a string constant or upvalue name).
    pub label: Option<String>,
}

impl OperandAnnotation {
    const fn reg(v: u8) -> Self {
        Self {
            kind: OperandKind::Reg,
            value: v as i32,
            label: None,
        }
    }
    fn prim(v: u8) -> Self {
        let label = match v {
            0 => "nil",
            1 => "false",
            2 => "true",
            _ => "?",
        };
        Self {
            kind: OperandKind::Prim,
            value: i32::from(v),
            label: Some(label.to_string()),
        }
    }
    const fn num(v: u16) -> Self {
        Self {
            kind: OperandKind::Num,
            value: v as i32,
            label: None,
        }
    }
    const fn str_idx(v: u16) -> Self {
        Self {
            kind: OperandKind::Str,
            value: v as i32,
            label: None,
        }
    }
    const fn uv(v: u16) -> Self {
        Self {
            kind: OperandKind::Uv,
            value: v as i32,
            label: None,
        }
    }
    fn jump(offset: i32, target: usize) -> Self {
        Self {
            kind: OperandKind::Jump,
            value: offset,
            label: Some(format!("{target:04}")),
        }
    }
    const fn imm(v: i32) -> Self {
        Self {
            kind: OperandKind::Imm,
            value: v,
            label: None,
        }
    }
    const fn proto_idx(v: u16) -> Self {
        Self {
            kind: OperandKind::Proto,
            value: v as i32,
            label: None,
        }
    }
    const fn unused() -> Self {
        Self {
            kind: OperandKind::Unused,
            value: 0,
            label: None,
        }
    }
}

impl fmt::Display for OperandAnnotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(lbl) = &self.label {
            write!(f, "{}({}={})", self.kind, self.value, lbl)
        } else {
            write!(f, "{}({})", self.kind, self.value)
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LjInstruction â€” richly decoded instruction
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A fully decoded `LuaJIT` bytecode instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LjInstruction {
    /// Program counter (instruction index within the prototype).
    pub pc: usize,
    /// Raw 32-bit word.
    pub raw: u32,
    /// Opcode byte.
    pub op: u8,
    /// Mnemonic string (static lifetime).
    #[serde(skip, default = "default_mnemonic")]
    pub mnemonic: &'static str,
    /// A operand (bits 15â€“8).
    pub a: u8,
    /// B operand (bits 31â€“24).
    pub b: u8,
    /// C operand (bits 23â€“16).
    pub c: u8,
    /// D operand, unsigned (bits 31â€“16).
    pub d: u16,
    /// J (signed jump offset) = D âˆ’ 0x8000.
    pub j: i32,
    /// Operand encoding mode.
    pub mode: OpMode,
    /// Semantic annotation for each of the A, B/D, C slots.
    pub ann_a: OperandAnnotation,
    pub ann_b: OperandAnnotation,
    pub ann_c: OperandAnnotation,
    /// Resolved absolute jump target PC (if this is a branch).  `None` for
    /// non-branch instructions or if the target is out of range.
    pub branch_target: Option<usize>,
    /// Source line number (from debug info), if available.
    pub source_line: Option<u32>,
}

impl LjInstruction {
    /// Is this instruction a function call variant?
    #[must_use]
    pub fn is_call(&self) -> bool {
        LJ_OP_TABLE
            .get(self.op as usize)
            .is_some_and(|i| i.is_call)
    }
    /// Is this instruction a return variant?
    #[must_use]
    pub fn is_return(&self) -> bool {
        LJ_OP_TABLE
            .get(self.op as usize)
            .is_some_and(|i| i.is_return)
    }
    /// Is this instruction a branch?
    #[must_use]
    pub fn is_branch(&self) -> bool {
        LJ_OP_TABLE
            .get(self.op as usize)
            .is_some_and(|i| i.is_branch)
    }
    /// Is this instruction a loop marker?
    #[must_use]
    pub fn is_loop(&self) -> bool {
        LJ_OP_TABLE
            .get(self.op as usize)
            .is_some_and(|i| i.is_loop)
    }
    /// Is this instruction a comparison?
    #[must_use]
    pub fn is_compare(&self) -> bool {
        LJ_OP_TABLE
            .get(self.op as usize)
            .is_some_and(|i| i.is_compare)
    }
}

impl fmt::Display for LjInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}  {:<8}  A={} B={} C={} D={}",
            self.pc, self.mnemonic, self.a, self.b, self.c, self.d
        )?;
        if let Some(t) = self.branch_target {
            write!(f, "  -> {t:04}")?;
        }
        if let Some(ln) = self.source_line {
            write!(f, "  line:{ln}")?;
        }
        Ok(())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// DisasmLine â€” one formatted line of disassembly
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A single formatted disassembly line with rich metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasmLine {
    /// Instruction index (PC).
    pub pc: usize,
    /// Formatted text for display.
    pub text: String,
    /// The underlying decoded instruction.
    pub instr: LjInstruction,
    /// True if this PC is a branch target from another instruction.
    pub is_target: bool,
}

impl fmt::Display for DisasmLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_target {
            write!(f, "> {}", self.text)
        } else {
            write!(f, "  {}", self.text)
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// decode_instruction â€” decode a single 32-bit word
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Decode a single 32-bit `LuaJIT` instruction word at position `pc`.
///
/// `proto_len` is used only for bounds-checking jump targets.
/// `source_line` is optional debug info.
#[must_use]
pub fn decode_instruction(
    raw: u32,
    pc: usize,
    proto_len: usize,
    source_line: Option<u32>,
) -> LjInstruction {
    let word = InstrWord(raw);
    let op = word.op();
    let op_a = word.a();
    let op_b = word.b();
    let op_c = word.c();
    let op_d = word.d();
    let jmp = word.j();
    let mode = word.mode();
    let mnemonic = word.mnemonic();

    // Annotate operands based on opcode semantics
    let (ann_a, ann_b, ann_c) = annotate_operands(op, op_a, op_b, op_c, op_d, jmp, pc);

    // Resolve branch target
    let branch_target = if matches!(mode, OpMode::AJ) || is_branch_op(op) {
        let target_signed = i64::try_from(pc).unwrap_or(i64::MAX) + 1 + i64::from(jmp);
        if target_signed >= 0 && (usize::try_from(target_signed).unwrap_or(usize::MAX)) < proto_len {
            Some(usize::try_from(target_signed).unwrap_or(usize::MAX))
        } else {
            None
        }
    } else {
        None
    };

    LjInstruction {
        pc,
        raw,
        op,
        mnemonic,
        a: op_a,
        b: op_b,
        c: op_c,
        d: op_d,
        j: jmp,
        mode,
        ann_a,
        ann_b,
        ann_c,
        branch_target,
        source_line,
    }
}

/// True for opcodes that perform an unconditional or conditional jump whose
/// D field encodes a signed jump offset.
#[must_use]
const fn is_branch_op(op: u8) -> bool {
    matches!(
        op,
        // JMP
        0x58 |
        // FORI/JFORI/FORL/IFORL/JFORL
        0x4D | 0x4E | 0x4F | 0x50 |
        // ITERL/IITERL
        0x52 | 0x53 |
        // LOOP/ILOOP
        0x55 | 0x56 |
        // ISNEXT / UCLO
        0x48 | 0x32
    )
}

/// Produce per-operand kind annotations for the given opcode.
///
/// This encodes the per-opcode operand semantics described in `lj_bc.h`.
fn annotate_operands(
    op: u8,
    op_a: u8,
    op_b: u8,
    op_c: u8,
    op_d: u16,
    jmp: i32,
    pc: usize,
) -> (OperandAnnotation, OperandAnnotation, OperandAnnotation) {
    let target = usize::try_from((i64::try_from(pc).unwrap_or(i64::MAX) + 1 + i64::from(jmp)).max(0)).unwrap_or(usize::MAX);
    match op {
        // ── Comparisons, eq/ne, unary test/copy, unary ops, MOVCOPY (AD: A=reg, D=low-byte-reg) ──
        0x00..=0x05 | 0x0C..=0x15 | 0x2C => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::reg(u8::try_from(op_d & 0xFF).unwrap_or(u8::MAX)),
            OperandAnnotation::unused(),
        ),
        // ── ISEQV/ISNEV vs string, KSTR, GGET ────────────────────────────────────────────────────
        0x06 | 0x07 | 0x27 | 0x36 => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::str_idx(op_d),
            OperandAnnotation::unused(),
        ),
        // ── ISEQN/ISNEN vs numconst, KNUM ────────────────────────────────────────────────────────
        0x08 | 0x09 | 0x2A => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::num(op_d),
            OperandAnnotation::unused(),
        ),
        // ── ISEQP/ISNEP vs prim, KPRI ────────────────────────────────────────────────────────────
        0x0A | 0x0B | 0x2B => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::prim(u8::try_from(op_d).unwrap_or(u8::MAX)),
            OperandAnnotation::unused(),
        ),
        // ── Binary arith reg-numconst and numconst-reg (ABC: A=reg, B=reg, C=numconst) ──────────
        0x16..=0x1F => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::reg(op_b),
            OperandAnnotation::num(u16::from(op_c)),
        ),
        // ── Binary arith reg-reg, table get/set/raw ───────────────────────────────────────────────
        0x20..=0x26 | 0x38 | 0x3C | 0x40 => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::reg(op_b),
            OperandAnnotation::reg(op_c),
        ),
        // ── KCDATA, TNEW, TDUP, TSETS, TSETM, CALLT, CALLMT, RETM, RET (imm D) ────────────────
        0x28 | 0x34 | 0x35 | 0x3B | 0x3F | 0x43 | 0x44 | 0x49 | 0x4A => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::imm(i32::from(op_d)),
            OperandAnnotation::unused(),
        ),
        // ── KSHORT (signed D via j field) ────────────────────────────────────────────────────────
        0x29 => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::imm(jmp),
            OperandAnnotation::unused(),
        ),
        // ── UCLO, ISNEXT, FORI..JFORL..LOOP..JMP (all jump targets) ─────────────────────────────
        0x32 | 0x48 | 0x4D..=0x58 => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::jump(jmp, target),
            OperandAnnotation::unused(),
        ),
        // ── FNEW ─────────────────────────────────────────────────────────────────────────────────
        0x33 => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::proto_idx(op_d),
            OperandAnnotation::unused(),
        ),
        // ── GSET ─────────────────────────────────────────────────────────────────────────────────
        0x37 => (
            OperandAnnotation::str_idx(op_d),
            OperandAnnotation::reg(op_a),
            OperandAnnotation::unused(),
        ),
        // ── TGETB / TSETB (table indexed by string constant) ─────────────────────────────────────
        0x39 | 0x3D => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::reg(op_b),
            OperandAnnotation::str_idx(u16::from(op_c)),
        ),
        // ── TGETI / TSETI (table indexed by immediate integer) ───────────────────────────────────
        0x3A | 0x3E => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::reg(op_b),
            OperandAnnotation::imm(i32::from(op_c)),
        ),
        // ── UGET ─────────────────────────────────────────────────────────────────────────────────
        0x2D => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::uv(op_d),
            OperandAnnotation::unused(),
        ),
        // ── USETV ────────────────────────────────────────────────────────────────────────────────
        0x2E => (
            OperandAnnotation::uv(u16::from(op_a)),
            OperandAnnotation::reg(u8::try_from(op_d & 0xFF).unwrap_or(u8::MAX)),
            OperandAnnotation::unused(),
        ),
        // ── USETS ────────────────────────────────────────────────────────────────────────────────
        0x2F => (
            OperandAnnotation::uv(u16::from(op_a)),
            OperandAnnotation::str_idx(op_d),
            OperandAnnotation::unused(),
        ),
        // ── USETN ────────────────────────────────────────────────────────────────────────────────
        0x30 => (
            OperandAnnotation::uv(u16::from(op_a)),
            OperandAnnotation::num(op_d),
            OperandAnnotation::unused(),
        ),
        // ── USETP ────────────────────────────────────────────────────────────────────────────────
        0x31 => (
            OperandAnnotation::uv(u16::from(op_a)),
            OperandAnnotation::prim(u8::try_from(op_d).unwrap_or(u8::MAX)),
            OperandAnnotation::unused(),
        ),
        // ── CALL, CALLM, ITERC, ITERN, VARG (ABC: A=reg, B=imm, C=imm) ─────────────────────────
        0x41 | 0x42 | 0x45 | 0x46 | 0x47 => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::imm(i32::from(op_b)),
            OperandAnnotation::imm(i32::from(op_c)),
        ),
        // ── RET0 ─────────────────────────────────────────────────────────────────────────────────
        0x4B => (
            OperandAnnotation::unused(),
            OperandAnnotation::unused(),
            OperandAnnotation::unused(),
        ),
        // ── RET1 ─────────────────────────────────────────────────────────────────────────────────
        0x4C => (
            OperandAnnotation::reg(op_a),
            OperandAnnotation::unused(),
            OperandAnnotation::unused(),
        ),
        // ── Function headers ─────────────────────────────────────────────────────────────────────
        0x59..=0x60 => (
            OperandAnnotation::imm(i32::from(op_a)),
            OperandAnnotation::unused(),
            OperandAnnotation::unused(),
        ),
        _ => (
            OperandAnnotation::imm(i32::from(op_a)),
            OperandAnnotation::imm(i32::from(op_d)),
            OperandAnnotation::unused(),
        ),
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// disassemble_proto â€” decode a whole prototype
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Decode all instructions in `proto` and produce a `Vec<DisasmLine>`.
///
/// Branch targets are resolved and back-annotated; each `DisasmLine::is_target`
/// is set if at least one other instruction jumps to that PC.
#[must_use]
pub fn disassemble_proto(proto: &LjProto) -> Vec<DisasmLine> {
    let n = proto.instructions.len();

    // First pass: decode all instructions
    let decoded: Vec<LjInstruction> = proto
        .instructions
        .iter()
        .enumerate()
        .map(|(pc, raw_instr)| {
            let line = proto.source_line(pc);
            decode_instruction(raw_instr.0, pc, n, line)
        })
        .collect();

    // Build a set of jump-target PCs
    let mut targets: HashMap<usize, bool> = HashMap::new();
    for instr in &decoded {
        if let Some(t) = instr.branch_target {
            targets.insert(t, true);
        }
    }

    // Second pass: format and annotate
    decoded
        .into_iter()
        .map(|instr| {
            let is_target = targets.contains_key(&instr.pc);
            let text = format_disasm_line(&instr, proto);
            DisasmLine {
                pc: instr.pc,
                text,
                instr,
                is_target,
            }
        })
        .collect()
}

/// Format one decoded instruction into a human-readable string, resolving
/// constant values from `proto`'s KGC/KN tables where possible.
#[must_use]
pub fn format_disasm_line(instr: &LjInstruction, proto: &LjProto) -> String {
    let op = instr.op;
    let op_a = instr.a;
    let op_b = instr.b;
    let op_c = instr.c;
    let op_d = instr.d;
    let jmp = instr.j;

    let kgc_str = |idx: usize| -> String {
        proto
            .kgc
            .get(idx)
            .and_then(|k| k.as_str())
            .map_or_else(|| format!("kgc[{idx}]"), |s| format!("\"{s}\""))
    };
    let kn_str = |idx: usize| -> String {
        match proto.kn.get(idx) {
            Some(KNumConst::Int(v)) => v.to_string(),
            Some(KNumConst::Float(v)) => format!("{v}"),
            None => format!("kn[{idx}]"),
        }
    };
    let uv_name = |idx: usize| -> String {
        proto
            .upvalue_names
            .get(idx)
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| format!("uv[{idx}]"))
    };

    let operand_str = match op {
        // Comparisons
        0x00 => format!("r{op_a} < r{op_d}"),
        0x01 => format!("r{op_a} >= r{op_d}"),
        0x02 => format!("r{op_a} <= r{op_d}"),
        0x03 => format!("r{op_a} > r{op_d}"),
        0x04 => format!("r{op_a} == r{op_d}"),
        0x05 => format!("r{op_a} ~= r{op_d}"),
        0x06 => format!("r{op_a} == {}", kgc_str(usize::from(op_d))),
        0x07 => format!("r{op_a} ~= {}", kgc_str(usize::from(op_d))),
        0x08 => format!("r{op_a} == {}", kn_str(usize::from(op_d))),
        0x09 => format!("r{op_a} ~= {}", kn_str(usize::from(op_d))),
        0x0A => format!("r{op_a} == {}", prim_name(u8::try_from(op_d).unwrap_or(u8::MAX))),
        0x0B => format!("r{op_a} ~= {}", prim_name(u8::try_from(op_d).unwrap_or(u8::MAX))),
        // Unary test+copy
        0x0C => format!("if r{op_a} then r{op_d}=r{op_a}"),
        0x0D => format!("if !r{op_a} then r{op_d}=r{op_a}"),
        0x0E => format!("if r{op_a}"),
        0x0F => format!("if !r{op_a}"),
        0x10 => format!("type(r{op_a})=={op_d}"),
        0x11 => format!("isnumber(r{op_a})"),
        // Unary ops
        0x12 => format!("r{op_a} = r{op_d}"),
        0x13 => format!("r{op_a} = not r{op_d}"),
        0x14 => format!("r{op_a} = -r{op_d}"),
        0x15 => format!("r{op_a} = #r{op_d}"),
        // Binary arith
        0x16 => format!("r{op_a} = r{op_b} + {}", kn_str(usize::from(op_c))),
        0x17 => format!("r{op_a} = r{op_b} - {}", kn_str(usize::from(op_c))),
        0x18 => format!("r{op_a} = r{op_b} * {}", kn_str(usize::from(op_c))),
        0x19 => format!("r{op_a} = r{op_b} / {}", kn_str(usize::from(op_c))),
        0x1A => format!("r{op_a} = r{op_b} % {}", kn_str(usize::from(op_c))),
        0x1B => format!("r{op_a} = {} + r{op_b}", kn_str(usize::from(op_c))),
        0x1C => format!("r{op_a} = {} - r{op_b}", kn_str(usize::from(op_c))),
        0x1D => format!("r{op_a} = {} * r{op_b}", kn_str(usize::from(op_c))),
        0x1E => format!("r{op_a} = {} / r{op_b}", kn_str(usize::from(op_c))),
        0x1F => format!("r{op_a} = {} % r{op_b}", kn_str(usize::from(op_c))),
        0x20 => format!("r{op_a} = r{op_b} + r{op_c}"),
        0x21 => format!("r{op_a} = r{op_b} - r{op_c}"),
        0x22 => format!("r{op_a} = r{op_b} * r{op_c}"),
        0x23 => format!("r{op_a} = r{op_b} / r{op_c}"),
        0x24 => format!("r{op_a} = r{op_b} % r{op_c}"),
        0x25 => format!("r{op_a} = r{op_b} ^ r{op_c}"),
        0x26 => format!("r{op_a} = r{op_b}..r{op_c}"),
        // Const loads
        0x27 => format!("r{op_a} = {}", kgc_str(usize::from(op_d))),
        0x28 => format!("r{op_a} = cdata[{op_d}]"),
        0x29 => format!("r{op_a} = {jmp}"),
        0x2A => format!("r{op_a} = {}", kn_str(usize::from(op_d))),
        0x2B => format!("r{op_a} = {}", prim_name(u8::try_from(op_d).unwrap_or(u8::MAX))),
        0x2C => format!("r{op_a}..r{op_d} = nil"),
        // Upvalue ops
        0x2D => format!("r{op_a} = {}", uv_name(usize::from(op_d))),
        0x2E => format!("{} = r{op_d}", uv_name(usize::from(op_a))),
        0x2F => format!("{} = {}", uv_name(usize::from(op_a)), kgc_str(usize::from(op_d))),
        0x30 => format!("{} = {}", uv_name(usize::from(op_a)), kn_str(usize::from(op_d))),
        0x31 => format!("{} = {}", uv_name(usize::from(op_a)), prim_name(u8::try_from(op_d).unwrap_or(u8::MAX))),
        0x32 => format!(
            "close_uv r{op_a}; jump {:04}",
            usize::try_from((i64::try_from(instr.pc).unwrap_or(i64::MAX) + 1 + i64::from(jmp)).max(0)).unwrap_or(usize::MAX)
        ),
        0x33 => format!("r{op_a} = proto[{op_d}]"),
        // Table ops
        0x34 => format!("r{op_a} = {{asize={}, hsize={}}}", op_d & 0x7FF, op_d >> 11),
        0x35 => format!("r{op_a} = dup_table[{op_d}]"),
        0x36 => format!("r{op_a} = _ENV[{}]", kgc_str(usize::from(op_d))),
        0x37 => format!("_ENV[{}] = r{op_a}", kgc_str(usize::from(op_d))),
        0x38 => format!("r{op_a} = r{op_b}[r{op_c}]"),
        0x39 => format!("r{op_a} = r{op_b}[{}]", kgc_str(usize::from(op_c))),
        0x3A => format!("r{op_a} = r{op_b}[{op_c}]"),
        0x3B => format!("r{op_a}..r{}= r?[M]", u32::from(op_a) + u32::from(op_d)),
        0x3C => format!("r{op_b}[r{op_c}] = r{op_a}"),
        0x3D => format!("r{op_b}[{}] = r{op_a}", kgc_str(usize::from(op_c))),
        0x3E => format!("r{op_b}[{op_c}] = r{op_a}"),
        0x3F => format!("r?[{op_d}..] = r{op_a}.."),
        0x40 => format!("r{op_b}[r{op_c}] = r{op_a}  ; raw"),
        // Calls
        0x41 => format!(
            "r{op_a}..r{}= r{op_a}(r{}..r{}+nret)",
            u32::from(op_a) + u32::from(op_b) - 1,
            u32::from(op_a) + 1,
            u32::from(op_a) + u32::from(op_c)
        ),
        0x42 => format!(
            "r{op_a}..r{}= r{op_a}(r{}..r{})",
            u32::from(op_a) + u32::from(op_b) - 1,
            u32::from(op_a) + 1,
            u32::from(op_a) + u32::from(op_c) - 1
        ),
        0x43 => format!(
            "tail r{op_a}(r{}..r{}+nret)",
            u32::from(op_a) + 1,
            u32::from(op_a) + u32::from(op_d)
        ),
        0x44 => format!("tail r{op_a}(r{}..r{})", u32::from(op_a) + 1, u32::from(op_a) + u32::from(op_d) - 1),
        0x45 => format!(
            "r{op_a},r{},r{}=r{}(r{},r{})",
            op_a + 1,
            op_a + 2,
            op_a - 3,
            op_a - 2,
            op_a - 1
        ),
        0x46 => format!("iterN r{op_a}.."),
        0x47 => format!("r{op_a}..r{}= vararg", u32::from(op_a) + u32::from(op_b) - 1),
        0x48 => {
            let t = usize::try_from((i64::try_from(instr.pc).unwrap_or(i64::MAX) + 1 + i64::from(jmp)).max(0)).unwrap_or(usize::MAX);
            format!("isnext -> {t:04}")
        }
        // Returns
        0x49 => format!("return r{op_a}..r{}+nret", u32::from(op_a) + u32::from(op_d)),
        0x4A => format!("return r{op_a}..r{}", u32::from(op_a) + u32::from(op_d) - 1),
        0x4B => "return".to_string(),
        0x4C => format!("return r{op_a}"),
        // Loops / jumps
        0x4D..=0x60 => {
            instr.branch_target.map_or_else(|| format!("j{jmp:+}"), |t| format!("-> {t:04}"))
        }
        _ => format!("A={op_a} B={op_b} C={op_c} D={op_d}"),
    };

    // Line number annotation
    let line_ann = instr
        .source_line
        .map(|ln| format!(" ; line:{ln}"))
        .unwrap_or_default();

    format!(
        "{:04}  {:<8}  {:<40}{}",
        instr.pc, instr.mnemonic, operand_str, line_ann
    )
}

/// Primitive name for KPRI operand values.
#[must_use]
const fn prim_name(v: u8) -> &'static str {
    match v {
        0 => "nil",
        1 => "false",
        2 => "true",
        _ => "?",
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Mnemonic lookup helpers (exposed for external use)
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Return the mnemonic for opcode `op`, or `"???"`.
#[must_use]
pub fn opcode_mnemonic(op: u8) -> &'static str {
    LJ_OP_TABLE
        .get(usize::from(op))
        .map_or("???", |i| i.mnemonic)
}

/// Return a `(mnemonic, mode)` pair for every opcode in table order.
#[must_use]
pub fn all_mnemonics() -> Vec<(&'static str, OpMode)> {
    LJ_OP_TABLE.iter().map(|i| (i.mnemonic, i.mode)).collect()
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KGC, KNumConst, LjConst, LjInstr, LjProtoFlags, LjUpvalue};

    fn make_proto_with_instrs(words: &[u32]) -> LjProto {
        LjProto {
            flags: LjProtoFlags::empty(),
            num_params: 0,
            frame_size: 4,
            num_upvalues: 0,
            is_vararg: false,
            instructions: words.iter().map(|&w| LjInstr(w)).collect(),
            upvalues: vec![],
            kgc: vec![KGC::String("hello".to_string())],
            kn: vec![KNumConst::Int(42)],
            constants: vec![LjConst::Str("hello".to_string())],
            instruction_count: words.len() as u32,
            debug_info: None,
            source_name: None,
            first_line: 0,
            num_lines: 0,
            line_info: vec![],
            local_vars: vec![],
            upvalue_names: vec![],
        }
    }

    #[test]
    fn test_decode_ret0() {
        let instr = decode_instruction(0x0000_004B, 0, 1, None);
        assert_eq!(instr.op, 0x4B);
        assert_eq!(instr.mnemonic, "RET0");
        assert!(instr.is_return());
        assert!(instr.is_branch());
        assert!(!instr.is_call());
    }

    #[test]
    fn test_decode_call_fields() {
        // Y086: previously 0x0201_0042 placed A in the wrong byte. Bits: op|A<<8|C<<16|B<<24.
        let word = 0x0201_0142u32; // CALL op=0x42 A=1 C=2 B=0
        let instr = decode_instruction(word, 2, 10, Some(5));
        assert_eq!(instr.op, 0x42);
        assert_eq!(instr.mnemonic, "CALL");
        assert_eq!(instr.a, 1);
        assert_eq!(instr.source_line, Some(5));
        assert!(instr.is_call());
    }

    #[test]
    fn test_decode_jmp_target() {
        // JMP at pc=3 with D=0x8001 (j=+1) â†’ target=5
        let _word = (0x8001u32 << 16) | 0x0001_0058u32 & 0x0000_FFFF | 0x5800;
        // Build manually: op=0x58, a=0x00, D=0x8001
        let raw = 0x58u32 | (0x8001u32 << 16);
        let instr = decode_instruction(raw, 3, 20, None);
        assert_eq!(instr.op, 0x58);
        assert_eq!(instr.j, 1);
        assert_eq!(instr.branch_target, Some(5));
    }

    #[test]
    fn test_decode_jmp_target_negative() {
        // JMP at pc=5 with D=0x7FFE (j=-2) â†’ target=4
        let raw = 0x58u32 | (0x7FFEu32 << 16);
        let instr = decode_instruction(raw, 5, 20, None);
        assert_eq!(instr.j, -2);
        assert_eq!(instr.branch_target, Some(4));
    }

    #[test]
    fn test_decode_jmp_out_of_range() {
        // JMP at pc=0 with j=-5 â†’ target would be -4, out of range
        let raw = 0x58u32 | (0x7FFBu32 << 16); // D=0x7FFB â†’ j=-5
        let instr = decode_instruction(raw, 0, 10, None);
        assert!(instr.branch_target.is_none());
    }

    #[test]
    fn test_decode_kshort() {
        // KSHORT A=2 D=0x8007 â†’ j=7
        let raw = 0x29u32 | (0x02u32 << 8) | (0x8007u32 << 16);
        let instr = decode_instruction(raw, 0, 5, None);
        assert_eq!(instr.mnemonic, "KSHORT");
        assert_eq!(instr.j, 7);
        assert_eq!(instr.ann_b.kind, OperandKind::Imm);
        assert_eq!(instr.ann_b.value, 7);
    }

    #[test]
    fn test_decode_kpri_true() {
        // KPRI A=0 D=2 â†’ true
        let raw = 0x2Bu32 | (0x02u32 << 16);
        let instr = decode_instruction(raw, 0, 5, None);
        assert_eq!(instr.mnemonic, "KPRI");
        assert_eq!(instr.ann_b.kind, OperandKind::Prim);
        assert_eq!(instr.ann_b.label.as_deref(), Some("true"));
    }

    #[test]
    fn test_disassemble_proto_length() {
        let proto = make_proto_with_instrs(&[0x0000_004B, 0x0000_004B]);
        let lines = disassemble_proto(&proto);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_disassemble_proto_ret0_text() {
        let proto = make_proto_with_instrs(&[0x0000_004B]);
        let lines = disassemble_proto(&proto);
        assert!(lines[0].text.contains("RET0"), "got: {}", lines[0].text);
    }

    #[test]
    fn test_disassemble_proto_pc_numbering() {
        let proto = make_proto_with_instrs(&[0x0000_004B, 0x0000_004B, 0x0000_004B]);
        let lines = disassemble_proto(&proto);
        for (i, line) in lines.iter().enumerate() {
            assert_eq!(line.pc, i);
        }
    }

    #[test]
    fn test_disassemble_branch_target_marked() {
        // pc=0: JMP +1 â†’ target=2
        // pc=1: RET0
        // pc=2: RET0  â† should be is_target=true
        let jmp = 0x58u32 | (0x8001u32 << 16); // j=+1
        let ret0 = 0x0000_004Bu32;
        let proto = make_proto_with_instrs(&[jmp, ret0, ret0]);
        let lines = disassemble_proto(&proto);
        assert!(!lines[0].is_target);
        assert!(!lines[1].is_target);
        assert!(lines[2].is_target);
    }

    #[test]
    fn test_disassemble_kstr_resolves_string() {
        // KSTR A=0 D=0 â†’ should reference kgc[0] = "hello"
        let raw = 0x27u32; // op=KSTR, a=0, d=0
        let proto = make_proto_with_instrs(&[raw]);
        let lines = disassemble_proto(&proto);
        assert!(lines[0].text.contains("hello"), "got: {}", lines[0].text);
    }

    #[test]
    fn test_operand_kind_display() {
        assert_eq!(OperandKind::Reg.to_string(), "REG");
        assert_eq!(OperandKind::Jump.to_string(), "JUMP");
        assert_eq!(OperandKind::Unused.to_string(), "_");
    }

    #[test]
    fn test_opcode_mnemonic_lookup() {
        assert_eq!(opcode_mnemonic(0x42), "CALL");
        assert_eq!(opcode_mnemonic(0x4B), "RET0");
        assert_eq!(opcode_mnemonic(0xFF), "???");
    }

    #[test]
    fn test_all_mnemonics_count() {
        let mnems = all_mnemonics();
        assert_eq!(mnems.len(), 97);
    }

    #[test]
    fn test_is_compare_flags() {
        for op in 0x00u8..=0x11 {
            let instr = decode_instruction(u32::from(op), 0, 10, None);
            assert!(instr.is_compare(), "op 0x{op:02x} should be compare");
        }
    }

    #[test]
    fn test_format_disasm_line_ret0() {
        let proto = make_proto_with_instrs(&[0x0000_004B]);
        let instr = decode_instruction(0x0000_004B, 0, 1, None);
        let line = format_disasm_line(&instr, &proto);
        assert!(line.contains("RET0"));
    }

    #[test]
    fn test_format_disasm_line_with_line_number() {
        let proto = make_proto_with_instrs(&[0x0000_004B]);
        let instr = decode_instruction(0x0000_004B, 0, 1, Some(42));
        let line = format_disasm_line(&instr, &proto);
        assert!(line.contains("line:42"), "got: {line}");
    }

    #[test]
    fn test_proto_with_upvalue_uget_resolves_name() {
        // UGET A=0 D=0 with upvalue_names = ["_ENV"]
        let raw = 0x2Du32; // UGET A=0 D=0
        let mut proto = make_proto_with_instrs(&[raw]);
        proto.upvalue_names = vec!["_ENV".to_string()];
        proto.num_upvalues = 1;
        proto.upvalues = vec![LjUpvalue {
            slot: 0,
            is_local: false,
            name: Some("_ENV".into()),
        }];
        let lines = disassemble_proto(&proto);
        assert!(lines[0].text.contains("_ENV"), "got: {}", lines[0].text);
    }
}
