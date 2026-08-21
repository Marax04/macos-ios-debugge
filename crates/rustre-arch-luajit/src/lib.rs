//! `rustre-arch-luajit`
//!
//! This crate is part of the `RustRE` Suite, a premium reverse engineering platform.
//!
//! # Architecture: `LuaJIT` 2 VM opcodes
//! Implements instruction decoding for `LuaJIT` 2 bytecode.
//! `LuaJIT` uses 32-bit fixed-width instructions.
//!
//! Instruction format (little-endian u32):
//!   bits 0..7  = opcode (8 bits)
//!   bits 8..15 = A (8 bits)
//!   bits 16..23 = C (8 bits) or low byte of D
//!   bits 24..31 = B (8 bits) or high byte of D
//!
//!   D = (B << 8) | C  (16 bits, unsigned)
//!   d = D - BIAS       (16 bits, signed, BIAS=0x8000 for branch targets)
//!
//! # Extended functionality
//! Beyond basic disassembly this module also provides:
//! - [`LuaJitBytecode`]: full bytecode dump parser (magic + header + proto chain)
//! - [`LuaJitProto`]: parsed function prototype with constants, upvalues, and sub-protos
//! - [`LjInstrDetail`]: rich per-instruction semantic info (operand roles, side effects)
//! - [`InstrCategory`]: high-level categorisation of every opcode
//! - Helper functions for encoding/decoding every instruction format

pub mod luajit21_compat;
pub mod luajit_jit_analysis;
pub mod trace_ir;

/// LuaJIT security analysis: SandboxEscape, FFIAbuse, JitBypass,
/// MemoryCorruption, LuaJitROP, LuaJitSecurity facade.
///
pub mod luajit_security;

/// LuaJIT bytecode optimizer: BytecodeOptimizer, OptRule, BCOptimizer,
/// ConstantFolding, DeadCodeElim, CopyPropagation, JumpChaining.
pub mod bc_optimizer;

/// LuaJIT bytecode assembler: LuaJitAssembler, AssemblerInstruction,
/// LabelResolver, RegisterAllocator, ConstantTable, AssemblerOutput.
pub mod luajit_assembler;

/// LuaJIT IR disassembler: LuaJitIrDisasm, IrInsn, IrOp, IrType.
pub mod luajit_ir_disasm;

/// LuaJIT machine code analyzer: McodeAnalyzer, JitTrace, TraceExit, TraceLink,
/// McodePatch, TraceStats.
pub mod luajit_mcode_analyzer;

/// LuaJIT prototype deep analyzer: LuaJitProtoAnalyzer, ProtoAnalysis,
/// ClosureGraph, UvInfo, KGCEntry, LocalVar.
pub mod luajit_proto_analyzer;

pub mod luajit_opcodes;
pub mod luajit_ir;
pub mod luajit_trace_info;

use std::fmt::Write as _;
use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::arch::{BranchCondition, BranchKind, RegisterKind};
use rustre_core::{address::Address, endian::Endian, errors::CoreError};

const BIAS: u32 = 0x8000;

/// Magic bytes at the start of every `LuaJIT` 2.x dump.
pub const LJ_MAGIC: [u8; 3] = [0x1b, 0x4c, 0x4a];
/// Version byte for `LuaJIT` 2.0.
pub const LJ_VERSION_20: u8 = 1;
/// Version byte for `LuaJIT` 2.1.
pub const LJ_VERSION_21: u8 = 2;

/// `LuaJIT` 2 opcode table.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LjOp {
    Islt = 0,
    Isge,
    Isle,
    Isgt,
    Iseqv,
    Isnev,
    Iseqs,
    Isnes,
    Iseqn,
    Isnen,
    Iseqp,
    Isnep,
    Istc,
    Isfc,
    Ist,
    Isf,
    Istype,
    Isnum,
    Mov,
    Not,
    Unm,
    Len,
    Addvn,
    Subvn,
    Mulvn,
    Divvn,
    Modvn,
    Addnv,
    Subnv,
    Mulnv,
    Divnv,
    Modnv,
    Addvv,
    Subvv,
    Mulvv,
    Divvv,
    Modvv,
    Pow,
    Cat,
    Kstr,
    Kcdata,
    Kshort,
    Knum,
    Kpri,
    Knil,
    Uget,
    Usetv,
    Usets,
    Usetn,
    Usetp,
    Uclo,
    Fnew,
    Tnew,
    Tdup,
    Gget,
    Gset,
    Tgetv,
    Tgets,
    Tgetb,
    Tgetr,
    Tsetv,
    Tsets,
    Tsetb,
    Tsetm,
    Tsetr,
    Callm,
    Call,
    Callmt,
    Callt,
    Iterc,
    Itern,
    Varg,
    Isnext,
    Retm,
    Ret,
    Ret0,
    Ret1,
    Fori,
    Jfori,
    Forl,
    Iforl,
    Jforl,
    Iterl,
    Iiterl,
    Jiterl,
    Loop,
    Iloop,
    Jloop,
    Jmp,
    Funcf,
    Ifuncf,
    Jfuncf,
    Funcv,
    Ifuncv,
    Jfuncv,
    Funcc,
    Funccw,
}

impl LjOp {
    /// Try to convert a raw `u8` into an [`LjOp`].
    #[must_use] 
    pub const fn from_u8(v: u8) -> Option<Self> {
        // Safe enumeration of all defined discriminants. Kept exhaustive so
        // any future addition to [`LjOp`] is caught at compile time.
        let op = match v {
            0 => Self::Islt,
            1 => Self::Isge,
            2 => Self::Isle,
            3 => Self::Isgt,
            4 => Self::Iseqv,
            5 => Self::Isnev,
            6 => Self::Iseqs,
            7 => Self::Isnes,
            8 => Self::Iseqn,
            9 => Self::Isnen,
            10 => Self::Iseqp,
            11 => Self::Isnep,
            12 => Self::Istc,
            13 => Self::Isfc,
            14 => Self::Ist,
            15 => Self::Isf,
            16 => Self::Istype,
            17 => Self::Isnum,
            18 => Self::Mov,
            19 => Self::Not,
            20 => Self::Unm,
            21 => Self::Len,
            22 => Self::Addvn,
            23 => Self::Subvn,
            24 => Self::Mulvn,
            25 => Self::Divvn,
            26 => Self::Modvn,
            27 => Self::Addnv,
            28 => Self::Subnv,
            29 => Self::Mulnv,
            30 => Self::Divnv,
            31 => Self::Modnv,
            32 => Self::Addvv,
            33 => Self::Subvv,
            34 => Self::Mulvv,
            35 => Self::Divvv,
            36 => Self::Modvv,
            37 => Self::Pow,
            38 => Self::Cat,
            39 => Self::Kstr,
            40 => Self::Kcdata,
            41 => Self::Kshort,
            42 => Self::Knum,
            43 => Self::Kpri,
            44 => Self::Knil,
            45 => Self::Uget,
            46 => Self::Usetv,
            47 => Self::Usets,
            48 => Self::Usetn,
            49 => Self::Usetp,
            50 => Self::Uclo,
            51 => Self::Fnew,
            52 => Self::Tnew,
            53 => Self::Tdup,
            54 => Self::Gget,
            55 => Self::Gset,
            56 => Self::Tgetv,
            57 => Self::Tgets,
            58 => Self::Tgetb,
            59 => Self::Tgetr,
            60 => Self::Tsetv,
            61 => Self::Tsets,
            62 => Self::Tsetb,
            63 => Self::Tsetm,
            64 => Self::Tsetr,
            65 => Self::Callm,
            66 => Self::Call,
            67 => Self::Callmt,
            68 => Self::Callt,
            69 => Self::Iterc,
            70 => Self::Itern,
            71 => Self::Varg,
            72 => Self::Isnext,
            73 => Self::Retm,
            74 => Self::Ret,
            75 => Self::Ret0,
            76 => Self::Ret1,
            77 => Self::Fori,
            78 => Self::Jfori,
            79 => Self::Forl,
            80 => Self::Iforl,
            81 => Self::Jforl,
            82 => Self::Iterl,
            83 => Self::Iiterl,
            84 => Self::Jiterl,
            85 => Self::Loop,
            86 => Self::Iloop,
            87 => Self::Jloop,
            88 => Self::Jmp,
            89 => Self::Funcf,   90 => Self::Ifuncf,  91 => Self::Jfuncf,
            92 => Self::Funcv,   93 => Self::Ifuncv,  94 => Self::Jfuncv,
            95 => Self::Funcc,   96 => Self::Funccw,
            _ => return None,
        };
        Some(op)
    }

    /// Return the canonical upper-case mnemonic for this opcode.
    #[must_use] 
    pub fn mnemonic(self) -> &'static str {
        LJ_NAMES[self as usize]
    }

    /// Return the [`InstrCategory`] for this opcode.
    #[must_use] 
    pub const fn category(self) -> InstrCategory {
        categorize(self as u8)
    }
}

/// Number of `LuaJIT` opcodes, as a `u8`.
///
/// The `LuaJIT` bytecode encodes the opcode in a single byte, so the table can
/// never hold more than 256 entries; the conversion is therefore exact and the
/// saturating fallback exists only to keep a future table edit from panicking.
#[must_use]
pub fn lj_names_len_u8() -> u8 {
    u8::try_from(LJ_NAMES.len()).unwrap_or(u8::MAX)
}

pub(crate) static LJ_NAMES: &[&str] = &[
    "ISLT", "ISGE", "ISLE", "ISGT", "ISEQV", "ISNEV", "ISEQS", "ISNES", "ISEQN", "ISNEN", "ISEQP",
    "ISNEP", "ISTC", "ISFC", "IST", "ISF", "ISTYPE", "ISNUM", "MOV", "NOT", "UNM", "LEN", "ADDVN",
    "SUBVN", "MULVN", "DIVVN", "MODVN", "ADDNV", "SUBNV", "MULNV", "DIVNV", "MODNV", "ADDVV",
    "SUBVV", "MULVV", "DIVVV", "MODVV", "POW", "CAT", "KSTR", "KCDATA", "KSHORT", "KNUM", "KPRI",
    "KNIL", "UGET", "USETV", "USETS", "USETN", "USETP", "UCLO", "FNEW", "TNEW", "TDUP", "GGET",
    "GSET", "TGETV", "TGETS", "TGETB", "TGETR", "TSETV", "TSETS", "TSETB", "TSETM", "TSETR",
    "CALLM", "CALL", "CALLMT", "CALLT", "ITERC", "ITERN", "VARG", "ISNEXT", "RETM", "RET", "RET0",
    "RET1", "FORI", "JFORI", "FORL", "IFORL", "JFORL", "ITERL", "IITERL", "JITERL", "LOOP",
    "ILOOP", "JLOOP", "JMP", "FUNCF", "IFUNCF", "JFUNCF", "FUNCV", "IFUNCV", "JFUNCV", "FUNCC",
    "FUNCCW",
];

/// High-level category of a `LuaJIT` instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrCategory {
    /// Comparison instructions that set the condition for the next JMP.
    Comparison,
    /// Unary or binary arithmetic/bitwise operation.
    Arithmetic,
    /// Load a constant into a register.
    LoadConst,
    /// Upvalue read/write.
    Upvalue,
    /// Table read (TGET*).
    TableGet,
    /// Table write (TSET*).
    TableSet,
    /// Function call.
    Call,
    /// Return from function.
    Return,
    /// Unconditional or conditional branch / loop.
    Branch,
    /// Function header pseudo-instruction.
    FuncHeader,
    /// Miscellaneous / other.
    Other,
}

const fn categorize(op: u8) -> InstrCategory {
    match op {
        0..=17 => InstrCategory::Comparison,
        18..=38 => InstrCategory::Arithmetic,
        39..=44 => InstrCategory::LoadConst,
        45..=51 => InstrCategory::Upvalue,
        56..=59 => InstrCategory::TableGet,
        60..=64 => InstrCategory::TableSet,
        65..=70 => InstrCategory::Call,
        73..=76 => InstrCategory::Return,
        77..=88 => InstrCategory::Branch,
        89..=96 => InstrCategory::FuncHeader,
        _ => InstrCategory::Other,
    }
}

/// Operand format for `LuaJIT` instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LjFmt {
    /// A, B, C
    Abc,
    /// A, D (16 bits unsigned)
    Ad,
    /// A, D (16 bits signed, bias-adjusted)
    AdSigned,
    /// A only
    A,
    /// No operands
    None,
}

pub(crate) const fn lj_fmt(op: u8) -> LjFmt {
    match op {
        // Ad: comparisons-with-const, loads, upvalues, tables-D, select calls, returns
        6..=21 | 39..=40 | 42..=49 | 51..=55 | 63 | 67..=68 | 72..=76 => LjFmt::Ad,
        // AdSigned: KSHORT, UCLO, branch/loop, JMP
        41 | 50 | 77..=84 | 88 => LjFmt::AdSigned,
        // A only: function headers
        89..=94 => LjFmt::A,
        // None: loops, FUNCC/FUNCCW
        85..=87 | 95..=96 => LjFmt::None,
        // Abc: everything else (comparisons reg/reg, arithmetic, table ops ABC, calls ABC)
        _ => LjFmt::Abc,
    }
}

const fn is_branch_op(op: u8) -> bool {
    matches!(
        op,
        // Comparison (followed by JMP)
        0..=17 |
        // Loop branches
        77 | 78 | 79 | 80 | 81 | 82 | 83 | 84 |
        // JMP
        88 |
        // UCLO
        50
    )
}

const fn is_call_op(op: u8) -> bool {
    matches!(op, 65..=70)
}

const fn is_return_op(op: u8) -> bool {
    matches!(op, 73..=76)
}

fn decode_luajit(word: u32) -> Result<(String, String, InstrFlags), CoreError> {
    let op = (word & 0xff) as u8;
    let a = ((word >> 8) & 0xff) as u8;
    let c = ((word >> 16) & 0xff) as u8;
    let b = ((word >> 24) & 0xff) as u8;
    let d = (u32::from(b) << 8) | u32::from(c);
    let d_signed = d.cast_signed() - BIAS.cast_signed();

    if op as usize >= LJ_NAMES.len() {
        return Err(CoreError::InvalidFormat {
            message: format!("unknown LuaJIT opcode {op}"),
        });
    }
    let mnemonic = LJ_NAMES[op as usize].to_lowercase();

    let mut flags = InstrFlags::NONE;
    if is_branch_op(op) {
        flags |= InstrFlags::BRANCH;
    }
    if is_call_op(op) {
        flags |= InstrFlags::CALL;
    }
    if is_return_op(op) {
        flags |= InstrFlags::RET;
    }
    // Comparisons are conditional
    if op <= 17 {
        flags |= InstrFlags::CONDITIONAL;
    }

    let operands = match lj_fmt(op) {
        LjFmt::Abc => format!("R{a}, R{b}, R{c}"),
        LjFmt::Ad => format!("R{a}, {d}"),
        LjFmt::AdSigned => format!("R{a}, {d_signed:+}"),
        LjFmt::A => format!("R{a}"),
        LjFmt::None => String::new(),
    };

    Ok((mnemonic, operands, flags))
}

/// Architecture support for `LuaJIT` 2.
#[derive(Debug, Clone, Default)]
pub struct LuaJitArch;

impl LuaJitArch {
    /// Create a new [`LuaJitArch`] instance.
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Classify the [`BranchKind`] of a decoded instruction from its flags.
    ///
    /// Returns `None` for instructions that do not alter control flow.
    #[must_use]
    pub const fn branch_kind(&self, instr: &Instruction) -> Option<BranchKind> {
        if instr.flags.contains(InstrFlags::RET) && !instr.flags.contains(InstrFlags::CALL) {
            return Some(BranchKind::Return);
        }
        if instr.flags.contains(InstrFlags::CALL) {
            return Some(BranchKind::Call);
        }
        if instr.flags.contains(InstrFlags::BRANCH) {
            return Some(if instr.flags.contains(InstrFlags::CONDITIONAL) {
                BranchKind::ConditionalJump
            } else {
                BranchKind::UnconditionalJump
            });
        }
        None
    }

    /// Decode the raw instruction word at position `idx` inside `words` and
    /// return an [`LjInstrDetail`] with full semantic information.
    ///
    /// # Panics
    /// Panics if `idx` does not fit in `i64`.
    #[must_use]
    pub fn detail(&self, idx: usize, words: &[u32]) -> Option<LjInstrDetail> {
        let word = *words.get(idx)?;
        let op = (word & 0xff) as u8;
        let a = ((word >> 8) & 0xff) as u8;
        let c = ((word >> 16) & 0xff) as u8;
        let b = ((word >> 24) & 0xff) as u8;
        let d = (u32::from(b) << 8) | u32::from(c);
        let d_signed = d.cast_signed() - BIAS.cast_signed();
        let fmt = lj_fmt(op);

        // Absolute branch target (in instruction units from start of words slice)
        let branch_target: Option<i64> = if is_branch_op(op) && fmt == LjFmt::AdSigned {
            Some(i64::try_from(idx).expect("instruction index fits in i64") + 1 + i64::from(d_signed))
        } else {
            None
        };

        Some(LjInstrDetail {
            index: idx,
            raw: word,
            op,
            a,
            b,
            c,
            d,
            d_signed,
            fmt,
            category: categorize(op),
            branch_target,
        })
    }

    /// Disassemble an entire slice of little-endian 32-bit words into a
    /// `Vec<Instruction>`.  `base` is the byte address of `words[0]`.
    ///
    /// # Panics
    /// Panics if the byte offset of a word does not fit in `i64`.
    #[must_use]
    pub fn disassemble_block(
        &self,
        base: Address,
        words: &[u32],
    ) -> Vec<Result<Instruction, CoreError>> {
        words
            .iter()
            .enumerate()
            .map(|(i, &w)| {
                let addr = base.offset(i64::try_from(i * 4).expect("byte offset fits in i64"));
                self.disassemble(addr, &w.to_le_bytes())
            })
            .collect()
    }
}

impl Architecture for LuaJitArch {
    fn name(&self) -> &'static str {
        "luajit"
    }

    fn pointer_size(&self) -> usize {
        8
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        if bytes.len() < 4 {
            return Err(CoreError::InvalidFormat {
                message: "need 4 bytes for LuaJIT instruction".into(),
            });
        }
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let (mnemonic, operands, flags) = decode_luajit(word)?;
        let mut instr = Instruction::new(address, 4, mnemonic, bytes[..4].to_vec());
        instr.operands = operands;
        instr.flags = flags;
        Ok(instr)
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if instr.flags.contains(InstrFlags::RET) && !instr.flags.contains(InstrFlags::CALL) {
            return vec![BranchInfo::ret()];
        }
        if instr.flags.contains(InstrFlags::BRANCH) {
            // Parse signed offset from operands (last token starting with + or -)
            for token in instr.operands.split(',').rev() {
                let t = token.trim();
                if (t.starts_with('+') || t.starts_with('-'))
                    && let Ok(off) = t.parse::<i64>() {
                        // LuaJIT branch offset: target = base + off * 4 + 4
                        let target = instr.address.offset(off * 4 + 4).as_u64();
                        if instr.flags.contains(InstrFlags::CONDITIONAL) {
                            return vec![BranchInfo::conditional_jump(
                                target,
                                BranchCondition::Custom(0),
                            )];
                        }
                        return vec![BranchInfo::unconditional_jump(target)];
                    }
            }
        }
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        (0u32..=15)
            .map(|i| RegisterInfo::new(format!("R{i}"), i, 8, RegisterKind::General))
            .collect()
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        let mut cc = CallingConvention::new("luajit")
            .with_int_args(vec![])
            .with_return_regs(vec![]);
        cc.caller_cleans_stack = false;
        vec![cc]
    }

    fn instruction_alignment(&self) -> usize {
        4
    }

    fn max_instruction_length(&self) -> usize {
        4
    }
}

// ---------------------------------------------------------------------------
// Rich per-instruction detail
// ---------------------------------------------------------------------------

/// Full semantic detail for a single decoded `LuaJIT` instruction.
///
/// Obtained via [`LuaJitArch::detail`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LjInstrDetail {
    /// Zero-based index of the instruction within the enclosing block.
    pub index: usize,
    /// Raw 32-bit instruction word.
    pub raw: u32,
    /// Opcode byte (bits 0..7).
    pub op: u8,
    /// A operand (bits 8..15).
    pub a: u8,
    /// B operand (bits 24..31).
    pub b: u8,
    /// C operand (bits 16..23).
    pub c: u8,
    /// D operand = (B << 8) | C, unsigned.
    pub d: u32,
    /// Signed interpretation: D - BIAS.
    pub d_signed: i32,
    /// Encoding format used by this instruction.
    pub fmt: LjFmt,
    /// High-level category.
    pub category: InstrCategory,
    /// Absolute target index (within the same block) for branch instructions,
    /// or `None` if this instruction does not branch.
    pub branch_target: Option<i64>,
}

impl LjInstrDetail {
    /// Return the mnemonic string (lower-case).
    #[must_use] 
    pub fn mnemonic(&self) -> String {
        if (self.op as usize) < LJ_NAMES.len() {
            LJ_NAMES[self.op as usize].to_lowercase()
        } else {
            format!("unk_{:02x}", self.op)
        }
    }

    /// Return `true` if this instruction reads from `reg`.
    #[must_use] 
    pub const fn reads_reg(&self, reg: u8) -> bool {
        match self.fmt {
            LjFmt::Abc => self.b == reg || self.c == reg,
            LjFmt::Ad | LjFmt::AdSigned => {
                // For moves / comparisons the source is in the D field as a
                // register index (upper or lower byte).  We conservatively
                // report both sub-fields.
                self.b == reg || self.c == reg
            }
            LjFmt::A | LjFmt::None => false,
        }
    }

    /// Return `true` if this instruction writes to `reg`.
    #[must_use] 
    pub const fn writes_reg(&self, reg: u8) -> bool {
        // Stores (TSET*, USET*, GSET) use A as source, not dest.
        let is_store = matches!(self.op, 46..=49 | 55 | 60..=64);
        if is_store {
            return false;
        }
        self.a == reg
    }
}

// ---------------------------------------------------------------------------
// Bytecode file parser
// ---------------------------------------------------------------------------

/// A `LuaJIT` constant value stored in a function prototype's constant table.
#[derive(Debug, Clone, PartialEq)]
pub enum LjConst {
    /// A 64-bit integer constant (`GCint` / knum that fits in i64).
    Integer(i64),
    /// A 64-bit float constant.
    Float(f64),
    /// A string constant (byte content).
    String(Vec<u8>),
    /// A `false` or `true` primitive.
    Bool(bool),
    /// The `nil` primitive.
    Nil,
}

/// An upvalue descriptor inside a [`LuaJitProto`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LjUpvalue {
    /// Whether the upvalue is in a parent register (true) or in the parent's
    /// upvalue table (false).
    pub on_stack: bool,
    /// Register or upvalue index in the parent.
    pub idx: u8,
}

/// A parsed `LuaJIT` function prototype.
///
/// This mirrors the internal `GCproto` structure at the level needed for
/// static analysis.  Fields that are not present in the compact dump format
/// are left as zero/empty.
#[derive(Debug, Clone, PartialEq)]
#[derive(Default)]
pub struct LuaJitProto {
    /// Bytecode words (each instruction is one word).
    pub instructions: Vec<u32>,
    /// Upvalue descriptors.
    pub upvalues: Vec<LjUpvalue>,
    /// Constant pool (in dump order: GC objects first, then numbers).
    pub constants: Vec<LjConst>,
    /// Nested function prototypes (children).
    pub protos: Vec<Self>,
    /// Registered number of parameters.
    pub params: u8,
    /// Frame size (number of slots).
    pub framesize: u8,
    /// Flags byte from the dump header.
    pub flags: u8,
    /// Source file name (if present).
    pub source: Option<String>,
    /// First defined line (0 if unknown).
    pub first_line: u32,
    /// Number of lines spanned.
    pub num_lines: u32,
}


impl LuaJitProto {
    /// Return the number of bytecode instructions in this prototype.
    #[must_use] 
    pub const fn instr_count(&self) -> usize {
        self.instructions.len()
    }

    /// Return `true` if the prototype is a vararg function.
    #[must_use] 
    pub const fn is_vararg(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Return `true` if the prototype has a child proto (i.e., it creates
    /// closures).
    #[must_use] 
    pub const fn has_children(&self) -> bool {
        !self.protos.is_empty()
    }

    /// Iterate over all instructions as `(index, raw_word)` pairs.
    pub fn iter_instructions(&self) -> impl Iterator<Item = (usize, u32)> + '_ {
        self.instructions.iter().copied().enumerate()
    }

    /// Compute a simple instruction-category histogram.
    ///
    /// Returns an array indexed by [`InstrCategory`] discriminant.  Each entry
    /// holds the count of instructions in that category.
    #[must_use] 
    pub fn category_histogram(&self) -> [usize; 11] {
        let mut hist = [0usize; 11];
        for &w in &self.instructions {
            let op = (w & 0xff) as u8;
            let cat = categorize(op);
            let idx = cat as usize;
            if idx < hist.len() {
                hist[idx] += 1;
            }
        }
        hist
    }

    /// Return the set of unique opcodes used by this prototype (not recursive).
    #[must_use] 
    pub fn used_opcodes(&self) -> Vec<u8> {
        let mut seen = [false; 256];
        for &w in &self.instructions {
            seen[(w & 0xff) as usize] = true;
        }
        (0u8..=255).filter(|&i| seen[i as usize]).collect()
    }

    /// Collect all instructions that are branches (unconditional or conditional).
    #[must_use] 
    pub fn branches(&self) -> Vec<LjInstrDetail> {
        let arch = LuaJitArch::new();
        self.instructions
            .iter()
            .enumerate()
            .filter_map(|(i, _)| {
                let d = arch.detail(i, &self.instructions)?;
                if d.branch_target.is_some() || is_branch_op(d.op) {
                    Some(d)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return a flat listing of all string constants in this prototype (not
    /// recursive).
    #[must_use] 
    pub fn string_constants(&self) -> Vec<&[u8]> {
        self.constants
            .iter()
            .filter_map(|c| {
                if let LjConst::String(s) = c {
                    Some(s.as_slice())
                } else {
                    None
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Parsed bytecode dump
// ---------------------------------------------------------------------------

/// Flags extracted from the `LuaJIT` dump header byte.
///
/// Stored as a packed byte:
/// - bit 0 (0x01): BE byte order
/// - bit 1 (0x02): strip debug info
/// - bit 2 (0x04): FFI used
/// - bit 3 (0x08): FR2 register convention (LJ 2.1+)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DumpFlags(u8);

impl DumpFlags {
    /// Parse from the raw flags byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self { Self(b) }

    /// Whether debug info is stripped (flag bit 0x02).
    #[must_use]
    pub const fn strip(self) -> bool { self.0 & 0x02 != 0 }

    /// Whether big-endian byte order is used (flag bit 0x01).
    #[must_use]
    pub const fn be(self) -> bool { self.0 & 0x01 != 0 }

    /// Whether FFI is used (flag bit 0x04).
    #[must_use]
    pub const fn ffi(self) -> bool { self.0 & 0x04 != 0 }

    /// Whether FR2 register convention is used (flag bit 0x08, LJ 2.1+).
    #[must_use]
    pub const fn fr2(self) -> bool { self.0 & 0x08 != 0 }
}

/// A fully-parsed `LuaJIT` bytecode dump (`.ljbc` file or in-memory dump).
#[derive(Debug, Clone, PartialEq)]
pub struct LuaJitBytecode {
    /// `LuaJIT` version: 1 = 2.0, 2 = 2.1.
    pub version: u8,
    /// Flags from the file header.
    pub flags: DumpFlags,
    /// The top-level prototype (chunk function).
    pub chunk: LuaJitProto,
}

/// Error type for bytecode parsing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Not enough input bytes.
    UnexpectedEof,
    /// The magic bytes or version byte did not match.
    BadMagic,
    /// A length-prefixed field would overflow the buffer.
    Overflow,
    /// A ULEB128-encoded value was malformed.
    BadUleb,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of bytecode"),
            Self::BadMagic => write!(f, "bad magic / unsupported LuaJIT version"),
            Self::Overflow => write!(f, "length field overflow"),
            Self::BadUleb => write!(f, "malformed ULEB128 value"),
        }
    }
}

// --------------- ULEB128 reader ------------------------------------------

/// Read an unsigned ULEB128 integer from `data[*pos..]`, advancing `*pos`.
fn read_uleb128(data: &[u8], pos: &mut usize) -> Result<u64, ParseError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= data.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let byte = data[*pos];
        *pos += 1;
        if shift >= 63 && byte > 1 {
            return Err(ParseError::BadUleb);
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(result)
}

/// Read a signed ULEB128 (bias-extended for `LuaJIT` number constants).
fn read_uleb128_33(data: &[u8], pos: &mut usize) -> Result<(bool, u32), ParseError> {
    // LuaJIT uses a 33-bit ULEB for number constants: bit 0 = sign, bits 1..32 = value.
    let raw = read_uleb128(data, pos)?;
    let sign = (raw & 1) != 0;
    let val = u32::try_from(raw >> 1).expect("33-bit ULEB value fits in u32 after shift");
    Ok((sign, val))
}

// --------------- Proto parser --------------------------------------------

/// Sane upper bound on ULEB128 field counts to prevent OOM on adversarially crafted input.
const MAX_PROTO_ITEMS: u64 = 0x10_0000; // 1 M items

/// Parse GC constants and number constants from the proto data slice.
fn parse_constants(
    proto_data: &[u8],
    p: &mut usize,
    num_kgc: usize,
    num_kn: usize,
    proto_stack: &mut Vec<LuaJitProto>,
) -> Result<(Vec<LjConst>, Vec<LuaJitProto>), ParseError> {
    let constants_cap = num_kgc.checked_add(num_kn).ok_or(ParseError::Overflow)?;
    let mut constants: Vec<LjConst> = Vec::with_capacity(constants_cap);
    let mut child_protos: Vec<LuaJitProto> = Vec::new();

    // GC constants (strings / protos / cdata)
    for _ in 0..num_kgc {
        if *p >= proto_data.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let ktype = u32::try_from(read_uleb128(proto_data, p)?).map_err(|_| ParseError::Overflow)?;
        match ktype {
            0 => {
                // KGC_CHILD: preceding proto in the stream is a child.
                if let Some(child) = proto_stack.pop() {
                    child_protos.push(child);
                }
                constants.push(LjConst::Nil);
            }
            1 | 2 => {
                constants.push(LjConst::Nil);
            }
            n if n >= 5 => {
                let slen = (n - 5) as usize;
                if *p + slen > proto_data.len() {
                    return Err(ParseError::Overflow);
                }
                let s = proto_data[*p..*p + slen].to_vec();
                *p += slen;
                constants.push(LjConst::String(s));
            }
            _ => {
                constants.push(LjConst::Nil);
            }
        }
    }

    // Number constants (ULEB128-33 encoded)
    for _ in 0..num_kn {
        let (is_float, lo) = read_uleb128_33(proto_data, p)?;
        if is_float {
            let hi = u32::try_from(read_uleb128(proto_data, p)?).map_err(|_| ParseError::Overflow)?;
            let bits: u64 = u64::from(lo) | (u64::from(hi) << 32);
            constants.push(LjConst::Float(f64::from_bits(bits)));
        } else {
            constants.push(LjConst::Integer(i64::from(lo)));
        }
    }

    Ok((constants, child_protos))
}

fn parse_proto(data: &[u8], pos: &mut usize, flags: DumpFlags, proto_stack: &mut Vec<LuaJitProto>) -> Result<LuaJitProto, ParseError> {
    // Each proto is prefixed with its size in bytes as a ULEB128.
    let proto_len = usize::try_from(read_uleb128(data, pos)?).map_err(|_| ParseError::Overflow)?;
    if proto_len == 0 {
        // Sentinel: end of proto list.
        return Ok(LuaJitProto::default());
    }
    let end = pos.checked_add(proto_len).ok_or(ParseError::Overflow)?;
    if end > data.len() {
        return Err(ParseError::Overflow);
    }
    let proto_data = &data[*pos..end];
    *pos = end;

    let mut p = 0usize;

    // Header: flags(1) params(1) framesize(1) #uv(1) #kgc(uleb) #kn(uleb) #bc(uleb)
    if p + 4 > proto_data.len() {
        return Err(ParseError::UnexpectedEof);
    }
    let proto_flags = proto_data[p];
    p += 1;
    let params = proto_data[p];
    p += 1;
    let framesize = proto_data[p];
    p += 1;
    let num_uv = proto_data[p] as usize;
    p += 1;
    // Validate field counts against proto_data length before casting to usize
    // to prevent integer-overflow / OOM on adversarially large ULEB128 values.
    let num_kgc_raw = read_uleb128(proto_data, &mut p)?;
    if num_kgc_raw > MAX_PROTO_ITEMS { return Err(ParseError::Overflow); }
    let num_kgc = usize::try_from(num_kgc_raw).expect("validated <= MAX_PROTO_ITEMS");
    let num_kn_raw = read_uleb128(proto_data, &mut p)?;
    if num_kn_raw > MAX_PROTO_ITEMS { return Err(ParseError::Overflow); }
    let num_kn = usize::try_from(num_kn_raw).expect("validated <= MAX_PROTO_ITEMS");
    let num_bc_raw = read_uleb128(proto_data, &mut p)?;
    if num_bc_raw > MAX_PROTO_ITEMS { return Err(ParseError::Overflow); }
    let num_bc = usize::try_from(num_bc_raw).expect("validated <= MAX_PROTO_ITEMS");

    // Debug info size (if not stripped)
    let _dbg_size = if flags.strip() {
        0usize
    } else {
        usize::try_from(read_uleb128(proto_data, &mut p)?).map_err(|_| ParseError::Overflow)?
    };

    let (first_line, num_lines) = if flags.strip() {
        (0u32, 0u32)
    } else {
        let fl = u32::try_from(read_uleb128(proto_data, &mut p)?).map_err(|_| ParseError::Overflow)?;
        let nl = u32::try_from(read_uleb128(proto_data, &mut p)?).map_err(|_| ParseError::Overflow)?;
        (fl, nl)
    };

    // Bytecode words
    let bc_bytes = num_bc.checked_mul(4).ok_or(ParseError::Overflow)?;
    if p + bc_bytes > proto_data.len() {
        return Err(ParseError::UnexpectedEof);
    }
    let mut instructions = Vec::with_capacity(num_bc);
    for i in 0..num_bc {
        let off = p + i * 4;
        let w = u32::from_le_bytes([
            proto_data[off],
            proto_data[off + 1],
            proto_data[off + 2],
            proto_data[off + 3],
        ]);
        instructions.push(w);
    }
    p += bc_bytes;

    // Upvalue descriptors (2 bytes each)
    let uv_bytes = num_uv.checked_mul(2).ok_or(ParseError::Overflow)?;
    if p + uv_bytes > proto_data.len() {
        return Err(ParseError::UnexpectedEof);
    }
    let mut upvalues = Vec::with_capacity(num_uv);
    for i in 0..num_uv {
        let lo = proto_data[p + i * 2];
        let hi = proto_data[p + i * 2 + 1];
        upvalues.push(LjUpvalue {
            on_stack: hi & 0x80 != 0,
            idx: lo,
        });
    }
    p += uv_bytes;

    // Constants (GC + numeric)
    let (constants, child_protos) = parse_constants(proto_data, &mut p, num_kgc, num_kn, proto_stack)?;

    // Remaining bytes are debug info — skip them.
    // (already accounted for by the proto_len boundary)

    // Build source name from the proto flags / debug section; we leave it
    // empty here since full debug-info parsing is out of scope.
    let source = None;

    Ok(LuaJitProto {
        instructions,
        upvalues,
        constants,
        protos: child_protos,
        params,
        framesize,
        flags: proto_flags,
        source,
        first_line,
        num_lines,
    })
}

impl LuaJitBytecode {
    /// Parse a `LuaJIT` bytecode dump from a byte slice.
    ///
    /// Supports both `LuaJIT` 2.0 (version byte = 1) and 2.1 (version byte = 2).
    ///
    /// # Errors
    /// Returns [`ParseError`] if the data is malformed, too short, or contains
    /// out-of-range field values.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        // Magic: 0x1b 'L' 'J'
        if data.len() < 5 {
            return Err(ParseError::UnexpectedEof);
        }
        if data[0] != LJ_MAGIC[0] || data[1] != LJ_MAGIC[1] || data[2] != LJ_MAGIC[2] {
            return Err(ParseError::BadMagic);
        }
        let version = data[3];
        if version != LJ_VERSION_20 && version != LJ_VERSION_21 {
            return Err(ParseError::BadMagic);
        }
        let flags_byte = data[4];
        let flags = DumpFlags::from_byte(flags_byte);

        let mut pos = 5usize;

        // Optional chunk name (ULEB len + bytes)
        if !flags.strip() {
            let name_len = usize::try_from(read_uleb128(data, &mut pos)?).map_err(|_| ParseError::Overflow)?;
            if pos + name_len > data.len() {
                return Err(ParseError::Overflow);
            }
            pos += name_len; // skip the chunk name
        }

        // Parse all protos in order. In the LuaJIT binary format, child protos
        // appear before their parent. We build a stack: each parsed proto is pushed,
        // and when a parent encounters a KGC_CHILD constant it pops one child from
        // the stack. The last proto in the stream is the top-level chunk.
        let mut proto_stack: Vec<LuaJitProto> = Vec::new();
        loop {
            // Peek at the next ULEB128 to detect the sentinel (length == 0).
            if pos >= data.len() {
                break;
            }
            // read_uleb128 advances pos; we need to check for sentinel without
            // consuming bytes for the sentinel case, but parse_proto handles the
            // sentinel by returning a default proto when proto_len == 0.
            // We need the sentinel detection here to know when to stop.
            // Peek at the first byte: if 0x00 this is the sentinel.
            if data[pos] == 0x00 {
                pos += 1; // consume the sentinel byte
                break;
            }
            let proto = parse_proto(data, &mut pos, flags, &mut proto_stack)?;
            proto_stack.push(proto);
        }
        let chunk = proto_stack.pop().ok_or(ParseError::UnexpectedEof)?;

        // Reject trailing bytes after the sentinel — a valid LuaJIT dump ends
        // exactly at the sentinel.  Ignoring trailing data would allow polyglot
        // files (e.g. the same byte range being parsed as two different formats).
        if pos != data.len() {
            return Err(ParseError::Overflow);
        }

        Ok(Self {
            version,
            flags,
            chunk,
        })
    }

    /// Return `true` if the dump was generated by `LuaJIT` 2.1+.
    #[must_use] 
    pub const fn is_lj21(&self) -> bool {
        self.version == LJ_VERSION_21
    }

    /// Total instruction count across the chunk (top-level proto only).
    #[must_use] 
    pub const fn total_instructions(&self) -> usize {
        self.chunk.instr_count()
    }
}

// ---------------------------------------------------------------------------
// Pretty-printer
// ---------------------------------------------------------------------------

/// Format a single raw instruction word as a human-readable string.
///
/// Example output: `"0004  ADDVV   R0, R1, R2"`
#[must_use] 
pub fn format_instruction(idx: usize, word: u32) -> String {
    let op = (word & 0xff) as u8;
    let a = ((word >> 8) & 0xff) as u8;
    let c = ((word >> 16) & 0xff) as u8;
    let b = ((word >> 24) & 0xff) as u8;
    let d: u32 = (u32::from(b) << 8) | u32::from(c);
    let d_signed: i32 = d.cast_signed() - BIAS.cast_signed();

    let name = if (op as usize) < LJ_NAMES.len() {
        LJ_NAMES[op as usize]
    } else {
        "???"
    };

    let operands = match lj_fmt(op) {
        LjFmt::Abc => format!("R{a}, R{b}, R{c}"),
        LjFmt::Ad => format!("R{a}, {d}"),
        LjFmt::AdSigned => format!("R{a}, {d_signed:+}"),
        LjFmt::A => format!("R{a}"),
        LjFmt::None => String::new(),
    };

    if operands.is_empty() {
        format!("{idx:04}  {name:<8}")
    } else {
        format!("{idx:04}  {name:<8}  {operands}")
    }
}

/// Disassemble a slice of instruction words and return a multi-line listing.
#[must_use] 
pub fn disassemble_listing(words: &[u32]) -> String {
    words
        .iter()
        .enumerate()
        .map(|(i, &w)| format_instruction(i, w))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Instruction-encoding helpers
// ---------------------------------------------------------------------------

/// Build a `LuaJIT` instruction word with ABC format.
#[must_use] 
pub fn make_lj_abc(op: u8, a: u8, b: u8, c: u8) -> u32 {
    u32::from(op) | (u32::from(a) << 8) | (u32::from(c) << 16) | (u32::from(b) << 24)
}

/// Build a `LuaJIT` instruction word with AD format.
#[must_use] 
pub fn make_lj_ad(op: u8, a: u8, d: u16) -> u32 {
    let b = (d >> 8) as u8;
    let c = (d & 0xff) as u8;
    make_lj_abc(op, a, b, c)
}

/// Build a `LuaJIT` instruction word with AD signed format.
///
/// # Panics
/// Panics if `d_signed + BIAS` does not fit in `u16` (should never occur for valid offsets).
#[must_use]
pub fn make_lj_ad_signed(op: u8, a: u8, d_signed: i16) -> u32 {
    let d = u16::try_from(i32::from(d_signed) + BIAS.cast_signed()).expect("d_signed + BIAS fits in u16");
    make_lj_ad(op, a, d)
}

/// Extract the opcode byte from a raw instruction word.
#[inline]
#[must_use] 
pub const fn instr_op(word: u32) -> u8 {
    (word & 0xff) as u8
}

/// Extract the A operand from a raw instruction word.
#[inline]
#[must_use] 
pub const fn instr_a(word: u32) -> u8 {
    ((word >> 8) & 0xff) as u8
}

/// Extract the B operand (high byte of D) from a raw instruction word.
#[inline]
#[must_use] 
pub const fn instr_b(word: u32) -> u8 {
    ((word >> 24) & 0xff) as u8
}

/// Extract the C operand (low byte of D) from a raw instruction word.
#[inline]
#[must_use] 
pub const fn instr_c(word: u32) -> u8 {
    ((word >> 16) & 0xff) as u8
}

/// Extract the unsigned D operand (= B<<8 | C) from a raw instruction word.
#[inline]
#[must_use] 
pub fn instr_d(word: u32) -> u16 {
    let b = u16::from(instr_b(word));
    let c = u16::from(instr_c(word));
    (b << 8) | c
}

/// Extract the signed D operand (D - BIAS) from a raw instruction word.
///
/// # Panics
/// Panics if `D - BIAS` does not fit in `i16` (should never occur for valid bytecode).
#[inline]
#[must_use]
pub fn instr_d_signed(word: u32) -> i16 {
    i16::try_from(i32::from(instr_d(word)) - BIAS.cast_signed()).expect("d - BIAS fits in i16")
}

// ---------------------------------------------------------------------------
// Utility: basic-block finder
// ---------------------------------------------------------------------------

/// A basic block within a `LuaJIT` prototype, identified by its start and
/// (exclusive) end instruction indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    /// Index of the first instruction in the block.
    pub start: usize,
    /// Index one past the last instruction in the block.
    pub end: usize,
}

impl BasicBlock {
    /// Return the number of instructions in this block.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// Return `true` if this block contains no instructions.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Compute a list of basic blocks for a slice of instruction words.
///
/// This performs a single linear scan and identifies block boundaries at:
/// - The start of the slice
/// - Any instruction that is a branch target
/// - Any instruction immediately following a terminator (branch/return)
///
/// # Panics
/// Panics if an instruction index does not fit in `i64`.
#[must_use]
pub fn find_basic_blocks(words: &[u32]) -> Vec<BasicBlock> {
    if words.is_empty() {
        return vec![];
    }

    let n = words.len();
    // Mark leaders (first instruction of a BB)
    let mut leaders = vec![false; n];
    leaders[0] = true;

    for (i, &w) in words.iter().enumerate() {
        let op = instr_op(w);
        let fmt = lj_fmt(op);

        // Any branch can produce a leader at the target
        if is_branch_op(op) && fmt == LjFmt::AdSigned {
            let d_s = i64::from(instr_d_signed(w));
            let target = i64::try_from(i).expect("instruction index fits in i64") + 1 + d_s;
            if target >= 0
                && let Ok(t) = usize::try_from(target)
                && t < n {
                leaders[t] = true;
            }
            // Fallthrough is a leader too (unless it's a return-like branch)
            if i + 1 < n {
                leaders[i + 1] = true;
            }
        }

        if is_return_op(op) && i + 1 < n {
            leaders[i + 1] = true;
        }
    }

    // Build blocks
    let leader_count = leaders.iter().filter(|&&l| l).count();
    let mut blocks = Vec::with_capacity(leader_count);
    let mut start = 0;
    for (i, &is_leader) in leaders.iter().enumerate().skip(1) {
        if is_leader {
            blocks.push(BasicBlock { start, end: i });
            start = i;
        }
    }
    // Push the final block
    if start < n {
        blocks.push(BasicBlock { start, end: n });
    }
    blocks
}

// ---------------------------------------------------------------------------
// Utility: def-use chain within a block
// ---------------------------------------------------------------------------

/// A single def or use of a register within a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegAccess {
    /// Instruction index.
    pub instr_idx: usize,
    /// Register number.
    pub reg: u8,
    /// `true` = definition (write), `false` = use (read).
    pub is_def: bool,
}

/// Collect all register definitions and uses for a slice of instruction words.
#[must_use] 
pub fn collect_reg_accesses(words: &[u32]) -> Vec<RegAccess> {
    let arch = LuaJitArch::new();
    let mut out = Vec::with_capacity(words.len() * 2);
    for (i, _) in words.iter().enumerate() {
        if let Some(d) = arch.detail(i, words) {
            // Defs
            if d.writes_reg(d.a) {
                out.push(RegAccess {
                    instr_idx: i,
                    reg: d.a,
                    is_def: true,
                });
            }
            // Uses
            match d.fmt {
                LjFmt::Abc => {
                    out.push(RegAccess {
                        instr_idx: i,
                        reg: d.b,
                        is_def: false,
                    });
                    out.push(RegAccess {
                        instr_idx: i,
                        reg: d.c,
                        is_def: false,
                    });
                }
                LjFmt::Ad | LjFmt::AdSigned => {
                    // Source register encoded in D for unary ops
                    if matches!(d.op, 18..=21 | 12 | 13) {
                        out.push(RegAccess {
                            instr_idx: i,
                            reg: d.c,
                            is_def: false,
                        });
                        out.push(RegAccess {
                            instr_idx: i,
                            reg: d.b,
                            is_def: false,
                        });
                    }
                }
                _ => {}
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// LjInstrFlags — semantic flag set for decoded LuaJIT instructions
// ---------------------------------------------------------------------------

/// Semantic flags that describe the control-flow and side-effect properties
/// of a decoded `LuaJIT` instruction.
///
/// These are richer than the generic [`InstrFlags`] used by the
/// [`Architecture`] trait and are exposed through [`LjInstruction`] and
/// [`decode_lj_instruction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LjInstrFlags(u16);

impl LjInstrFlags {
    /// No special properties.
    pub const NONE: Self = Self(0);
    /// Instruction may alter the program counter (unconditional or conditional
    /// jump, loop back-edge, UCLO with branch, etc.).
    pub const BRANCH: Self = Self(1 << 0);
    /// Branch is taken only when a preceding comparison is true (comparisons
    /// 0..=17 do not branch themselves — they control the *following* JMP,
    /// but we mark them CONDITIONAL here for convenience).
    pub const CONDITIONAL: Self = Self(1 << 1);
    /// Instruction performs a function call.
    pub const CALL: Self = Self(1 << 2);
    /// Instruction returns from the current function.
    pub const RETURN: Self = Self(1 << 3);
    /// Instruction reads from an upvalue slot.
    pub const UPVALUE_READ: Self = Self(1 << 4);
    /// Instruction writes to an upvalue slot.
    pub const UPVALUE_WRITE: Self = Self(1 << 5);
    /// Instruction reads from a table.
    pub const TABLE_READ: Self = Self(1 << 6);
    /// Instruction writes to a table.
    pub const TABLE_WRITE: Self = Self(1 << 7);
    /// Instruction reads from / writes to the global environment table.
    pub const GLOBAL_ACCESS: Self = Self(1 << 8);
    /// Instruction closes upvalues (UCLO / FNEW).
    pub const CLOSES_UPVALUES: Self = Self(1 << 9);
    /// Instruction is a function header pseudo-instruction (FUNCF etc.).
    pub const FUNC_HEADER: Self = Self(1 << 10);
    /// Instruction is a loop hint / iterator step.
    pub const LOOP_HINT: Self = Self(1 << 11);
    /// Instruction has a side-channel tail-call optimisation applied
    /// (CALLMT / CALLT).
    pub const TAIL_CALL: Self = Self(1 << 12);

    /// Return an instance with no flags set.
    #[inline]
    #[must_use] 
    pub const fn empty() -> Self {
        Self::NONE
    }

    /// Return `true` if all bits in `other` are set in `self`.
    #[inline]
    #[must_use] 
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Return `true` when no flag is set.
    #[inline]
    #[must_use] 
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Combine two flag sets (bitwise OR).
    #[inline]
    #[must_use] 
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl core::ops::BitOrAssign for LjInstrFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitOr for LjInstrFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::fmt::Display for LjInstrFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut parts = Vec::new();
        if self.contains(Self::BRANCH) {
            parts.push("BRANCH");
        }
        if self.contains(Self::CONDITIONAL) {
            parts.push("CONDITIONAL");
        }
        if self.contains(Self::CALL) {
            parts.push("CALL");
        }
        if self.contains(Self::RETURN) {
            parts.push("RETURN");
        }
        if self.contains(Self::UPVALUE_READ) {
            parts.push("UPVALUE_READ");
        }
        if self.contains(Self::UPVALUE_WRITE) {
            parts.push("UPVALUE_WRITE");
        }
        if self.contains(Self::TABLE_READ) {
            parts.push("TABLE_READ");
        }
        if self.contains(Self::TABLE_WRITE) {
            parts.push("TABLE_WRITE");
        }
        if self.contains(Self::GLOBAL_ACCESS) {
            parts.push("GLOBAL_ACCESS");
        }
        if self.contains(Self::CLOSES_UPVALUES) {
            parts.push("CLOSES_UPVALUES");
        }
        if self.contains(Self::FUNC_HEADER) {
            parts.push("FUNC_HEADER");
        }
        if self.contains(Self::LOOP_HINT) {
            parts.push("LOOP_HINT");
        }
        if self.contains(Self::TAIL_CALL) {
            parts.push("TAIL_CALL");
        }
        write!(f, "{}", parts.join("|"))
    }
}

// ---------------------------------------------------------------------------
// LjInstruction — decoded instruction with rich metadata
// ---------------------------------------------------------------------------

/// A fully decoded `LuaJIT` 2.x instruction with all operand fields and
/// semantic flags populated.
///
/// Obtain one via [`decode_lj_instruction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LjInstruction {
    /// Raw 32-bit instruction word (little-endian as stored in the dump).
    pub raw: u32,
    /// Opcode byte (bits 0..7).
    pub op: u8,
    /// A field (bits 8..15).  Destination register for most instructions.
    pub a: u8,
    /// B field (bits 24..31).  Second source register or high byte of D.
    pub b: u8,
    /// C field (bits 16..23).  Third source register or low byte of D.
    pub c: u8,
    /// Unsigned 16-bit D field: `(B << 8) | C`.
    pub d: u32,
    /// Signed interpretation of D: `D as i32 − BIAS` (used by branch offsets
    /// and KSHORT).
    pub d_signed: i32,
    /// Encoding format (determines which operand fields are meaningful).
    pub fmt: LjFmt,
    /// Semantic flag set for this instruction.
    pub flags: LjInstrFlags,
    /// High-level category.
    pub category: InstrCategory,
}

impl LjInstruction {
    /// Return the upper-case mnemonic string (e.g. `"ADDVV"`).
    #[must_use] 
    pub fn mnemonic(&self) -> &'static str {
        if (self.op as usize) < LJ_NAMES.len() {
            LJ_NAMES[self.op as usize]
        } else {
            "???"
        }
    }
}

// ---------------------------------------------------------------------------
// Full opcode metadata table
// ---------------------------------------------------------------------------

/// Complete metadata for a single `LuaJIT` opcode, covering the canonical
/// mnemonic, its operand encoding format, and the semantic flags that apply
/// to every instruction with this opcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LjOpMeta {
    /// Upper-case canonical mnemonic, e.g. `"ADDVV"`.
    pub mnemonic: &'static str,
    /// Operand encoding format.
    pub fmt: LjFmt,
    /// Semantic flags that are always set for this opcode.
    pub flags: LjInstrFlags,
    /// Brief English description of what the instruction does.
    pub description: &'static str,
}

/// Per-opcode metadata table indexed by opcode value (0–96).
///
/// The table is built as a `const`-compatible static array so that
/// `LjOpMeta::for_op` is a simple bounds-checked index.
static LJ_OP_META: &[LjOpMeta] = &[
    // 0: ISLT  A, D  — if (R(A) < R(D)) continue else skip next JMP
    LjOpMeta {
        mnemonic: "ISLT",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) < R(D)",
    },
    // 1: ISGE
    LjOpMeta {
        mnemonic: "ISGE",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) >= R(D)",
    },
    // 2: ISLE
    LjOpMeta {
        mnemonic: "ISLE",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) <= R(D)",
    },
    // 3: ISGT
    LjOpMeta {
        mnemonic: "ISGT",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) > R(D)",
    },
    // 4: ISEQV
    LjOpMeta {
        mnemonic: "ISEQV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) == R(D) (value)",
    },
    // 5: ISNEV
    LjOpMeta {
        mnemonic: "ISNEV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) ~= R(D) (value)",
    },
    // 6: ISEQS
    LjOpMeta {
        mnemonic: "ISEQS",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) == K(D) (string)",
    },
    // 7: ISNES
    LjOpMeta {
        mnemonic: "ISNES",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) ~= K(D) (string)",
    },
    // 8: ISEQN
    LjOpMeta {
        mnemonic: "ISEQN",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) == KN(D) (number)",
    },
    // 9: ISNEN
    LjOpMeta {
        mnemonic: "ISNEN",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) ~= KN(D) (number)",
    },
    // 10: ISEQP
    LjOpMeta {
        mnemonic: "ISEQP",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) == primitive D",
    },
    // 11: ISNEP
    LjOpMeta {
        mnemonic: "ISNEP",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) ~= primitive D",
    },
    // 12: ISTC
    LjOpMeta {
        mnemonic: "ISTC",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Copy R(D) to R(A) and skip next JMP if truthy",
    },
    // 13: ISFC
    LjOpMeta {
        mnemonic: "ISFC",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Copy R(D) to R(A) and skip next JMP if falsy",
    },
    // 14: IST
    LjOpMeta {
        mnemonic: "IST",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(D) is truthy",
    },
    // 15: ISF
    LjOpMeta {
        mnemonic: "ISF",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(D) is falsy",
    },
    // 16: ISTYPE
    LjOpMeta {
        mnemonic: "ISTYPE",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if type(R(A)) == D",
    },
    // 17: ISNUM
    LjOpMeta {
        mnemonic: "ISNUM",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Skip next JMP if R(A) is a number",
    },
    // 18: MOV
    LjOpMeta {
        mnemonic: "MOV",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(D)",
    },
    // 19: NOT
    LjOpMeta {
        mnemonic: "NOT",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags::NONE,
        description: "R(A) = not R(D)",
    },
    // 20: UNM
    LjOpMeta {
        mnemonic: "UNM",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags::NONE,
        description: "R(A) = -R(D)",
    },
    // 21: LEN
    LjOpMeta {
        mnemonic: "LEN",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags::NONE,
        description: "R(A) = #R(D)",
    },
    // 22: ADDVN
    LjOpMeta {
        mnemonic: "ADDVN",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(B) + KN(C)",
    },
    // 23: SUBVN
    LjOpMeta {
        mnemonic: "SUBVN",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(B) - KN(C)",
    },
    // 24: MULVN
    LjOpMeta {
        mnemonic: "MULVN",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(B) * KN(C)",
    },
    // 25: DIVVN
    LjOpMeta {
        mnemonic: "DIVVN",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(B) / KN(C)",
    },
    // 26: MODVN
    LjOpMeta {
        mnemonic: "MODVN",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(B) % KN(C)",
    },
    // 27: ADDNV
    LjOpMeta {
        mnemonic: "ADDNV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = KN(B) + R(C)",
    },
    // 28: SUBNV
    LjOpMeta {
        mnemonic: "SUBNV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = KN(B) - R(C)",
    },
    // 29: MULNV
    LjOpMeta {
        mnemonic: "MULNV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = KN(B) * R(C)",
    },
    // 30: DIVNV
    LjOpMeta {
        mnemonic: "DIVNV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = KN(B) / R(C)",
    },
    // 31: MODNV
    LjOpMeta {
        mnemonic: "MODNV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = KN(B) % R(C)",
    },
    // 32: ADDVV
    LjOpMeta {
        mnemonic: "ADDVV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(B) + R(C)",
    },
    // 33: SUBVV
    LjOpMeta {
        mnemonic: "SUBVV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(B) - R(C)",
    },
    // 34: MULVV
    LjOpMeta {
        mnemonic: "MULVV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(B) * R(C)",
    },
    // 35: DIVVV
    LjOpMeta {
        mnemonic: "DIVVV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(B) / R(C)",
    },
    // 36: MODVV
    LjOpMeta {
        mnemonic: "MODVV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(B) % R(C)",
    },
    // 37: POW
    LjOpMeta {
        mnemonic: "POW",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(B) ^ R(C)",
    },
    // 38: CAT
    LjOpMeta {
        mnemonic: "CAT",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A) = R(B) .. ... .. R(C)",
    },
    // 39: KSTR
    LjOpMeta {
        mnemonic: "KSTR",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags::NONE,
        description: "R(A) = K(D) (string constant)",
    },
    // 40: KCDATA
    LjOpMeta {
        mnemonic: "KCDATA",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags::NONE,
        description: "R(A) = K(D) (cdata/FFI constant)",
    },
    // 41: KSHORT
    LjOpMeta {
        mnemonic: "KSHORT",
        fmt: LjFmt::AdSigned,
        flags: LjInstrFlags::NONE,
        description: "R(A) = D_signed (integer literal)",
    },
    // 42: KNUM
    LjOpMeta {
        mnemonic: "KNUM",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags::NONE,
        description: "R(A) = KN(D) (number constant)",
    },
    // 43: KPRI
    LjOpMeta {
        mnemonic: "KPRI",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags::NONE,
        description: "R(A) = primitive D (nil/false/true)",
    },
    // 44: KNIL
    LjOpMeta {
        mnemonic: "KNIL",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags::NONE,
        description: "R(A), ..., R(D) = nil",
    },
    // 45: UGET
    LjOpMeta {
        mnemonic: "UGET",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::UPVALUE_READ.0),
        description: "R(A) = UV(D)",
    },
    // 46: USETV
    LjOpMeta {
        mnemonic: "USETV",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::UPVALUE_WRITE.0),
        description: "UV(A) = R(D)",
    },
    // 47: USETS
    LjOpMeta {
        mnemonic: "USETS",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::UPVALUE_WRITE.0),
        description: "UV(A) = K(D) (string)",
    },
    // 48: USETN
    LjOpMeta {
        mnemonic: "USETN",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::UPVALUE_WRITE.0),
        description: "UV(A) = KN(D) (number)",
    },
    // 49: USETP
    LjOpMeta {
        mnemonic: "USETP",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::UPVALUE_WRITE.0),
        description: "UV(A) = primitive D",
    },
    // 50: UCLO
    LjOpMeta {
        mnemonic: "UCLO",
        fmt: LjFmt::AdSigned,
        flags: LjInstrFlags(LjInstrFlags::CLOSES_UPVALUES.0 | LjInstrFlags::BRANCH.0),
        description: "Close upvalues for R(A) and above; branch to D_signed",
    },
    // 51: FNEW
    LjOpMeta {
        mnemonic: "FNEW",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::CLOSES_UPVALUES.0),
        description: "R(A) = new closure from proto K(D)",
    },
    // 52: TNEW
    LjOpMeta {
        mnemonic: "TNEW",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags::NONE,
        description: "R(A) = {} (new table, hint D)",
    },
    // 53: TDUP
    LjOpMeta {
        mnemonic: "TDUP",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags::NONE,
        description: "R(A) = dup(K(D)) (table template)",
    },
    // 54: GGET
    LjOpMeta {
        mnemonic: "GGET",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::GLOBAL_ACCESS.0 | LjInstrFlags::TABLE_READ.0),
        description: "R(A) = _G[K(D)]",
    },
    // 55: GSET
    LjOpMeta {
        mnemonic: "GSET",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::GLOBAL_ACCESS.0 | LjInstrFlags::TABLE_WRITE.0),
        description: "_G[K(D)] = R(A)",
    },
    // 56: TGETV
    LjOpMeta {
        mnemonic: "TGETV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::TABLE_READ.0),
        description: "R(A) = R(B)[R(C)]",
    },
    // 57: TGETS
    LjOpMeta {
        mnemonic: "TGETS",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::TABLE_READ.0),
        description: "R(A) = R(B)[K(C)] (string key)",
    },
    // 58: TGETB
    LjOpMeta {
        mnemonic: "TGETB",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::TABLE_READ.0),
        description: "R(A) = R(B)[C] (byte index)",
    },
    // 59: TGETR
    LjOpMeta {
        mnemonic: "TGETR",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::TABLE_READ.0),
        description: "R(A) = R(B)[R(C)] (raw read, LJ 2.1)",
    },
    // 60: TSETV
    LjOpMeta {
        mnemonic: "TSETV",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::TABLE_WRITE.0),
        description: "R(B)[R(C)] = R(A)",
    },
    // 61: TSETS
    LjOpMeta {
        mnemonic: "TSETS",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::TABLE_WRITE.0),
        description: "R(B)[K(C)] = R(A) (string key)",
    },
    // 62: TSETB
    LjOpMeta {
        mnemonic: "TSETB",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::TABLE_WRITE.0),
        description: "R(B)[C] = R(A) (byte index)",
    },
    // 63: TSETM
    LjOpMeta {
        mnemonic: "TSETM",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::TABLE_WRITE.0),
        description: "R(A-1)[D, D+1, ...] = R(A), R(A+1), ... (multi-assign)",
    },
    // 64: TSETR
    LjOpMeta {
        mnemonic: "TSETR",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::TABLE_WRITE.0),
        description: "R(B)[R(C)] = R(A) (raw write, LJ 2.1)",
    },
    // 65: CALLM
    LjOpMeta {
        mnemonic: "CALLM",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::CALL.0),
        description: "R(A), ..., R(A+B-2) = R(A)(R(A+1), ..., R(A+C+MULTRES))",
    },
    // 66: CALL
    LjOpMeta {
        mnemonic: "CALL",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::CALL.0),
        description: "R(A), ..., R(A+B-2) = R(A)(R(A+1), ..., R(A+C-1))",
    },
    // 67: CALLMT
    LjOpMeta {
        mnemonic: "CALLMT",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::CALL.0 | LjInstrFlags::TAIL_CALL.0),
        description: "Tailcall R(A)(R(A+1), ..., R(A+D+MULTRES))",
    },
    // 68: CALLT
    LjOpMeta {
        mnemonic: "CALLT",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::CALL.0 | LjInstrFlags::TAIL_CALL.0),
        description: "Tailcall R(A)(R(A+1), ..., R(A+D-1))",
    },
    // 69: ITERC
    LjOpMeta {
        mnemonic: "ITERC",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::CALL.0),
        description: "R(A), ..., R(A+B-2) = R(A-3)(R(A-2), R(A-1)); used with ITERL",
    },
    // 70: ITERN
    LjOpMeta {
        mnemonic: "ITERN",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags(LjInstrFlags::CALL.0),
        description: "Specialised ITERC for next()",
    },
    // 71: VARG
    LjOpMeta {
        mnemonic: "VARG",
        fmt: LjFmt::Abc,
        flags: LjInstrFlags::NONE,
        description: "R(A), ..., R(A+B-2) = vararg[1], ..., vararg[C-1]",
    },
    // 72: ISNEXT
    LjOpMeta {
        mnemonic: "ISNEXT",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::CONDITIONAL.0),
        description: "Check type of R(A-3) for ITERN; branch to D if not next()",
    },
    // 73: RETM
    LjOpMeta {
        mnemonic: "RETM",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::RETURN.0),
        description: "return R(A), ..., R(A+D-2) + MULTRES",
    },
    // 74: RET
    LjOpMeta {
        mnemonic: "RET",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::RETURN.0),
        description: "return R(A), ..., R(A+D-2)",
    },
    // 75: RET0
    LjOpMeta {
        mnemonic: "RET0",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::RETURN.0),
        description: "return (no values)",
    },
    // 76: RET1
    LjOpMeta {
        mnemonic: "RET1",
        fmt: LjFmt::Ad,
        flags: LjInstrFlags(LjInstrFlags::RETURN.0),
        description: "return R(A)",
    },
    // 77: FORI
    LjOpMeta {
        mnemonic: "FORI",
        fmt: LjFmt::AdSigned,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::LOOP_HINT.0),
        description: "Numeric for-loop initialisation; branch to D if done",
    },
    // 78: JFORI
    LjOpMeta {
        mnemonic: "JFORI",
        fmt: LjFmt::AdSigned,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::LOOP_HINT.0),
        description: "JIT-compiled FORI",
    },
    // 79: FORL
    LjOpMeta {
        mnemonic: "FORL",
        fmt: LjFmt::AdSigned,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::LOOP_HINT.0),
        description: "Numeric for-loop step; branch back if not done",
    },
    // 80: IFORL
    LjOpMeta {
        mnemonic: "IFORL",
        fmt: LjFmt::AdSigned,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::LOOP_HINT.0),
        description: "Interpreted (non-JIT) FORL",
    },
    // 81: JFORL
    LjOpMeta {
        mnemonic: "JFORL",
        fmt: LjFmt::AdSigned,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::LOOP_HINT.0),
        description: "JIT-compiled FORL",
    },
    // 82: ITERL
    LjOpMeta {
        mnemonic: "ITERL",
        fmt: LjFmt::AdSigned,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::LOOP_HINT.0),
        description: "Generic for-loop step; branch back if iterator not exhausted",
    },
    // 83: IITERL
    LjOpMeta {
        mnemonic: "IITERL",
        fmt: LjFmt::AdSigned,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::LOOP_HINT.0),
        description: "Interpreted ITERL",
    },
    // 84: JITERL
    LjOpMeta {
        mnemonic: "JITERL",
        fmt: LjFmt::AdSigned,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0 | LjInstrFlags::LOOP_HINT.0),
        description: "JIT-compiled ITERL",
    },
    // 85: LOOP
    LjOpMeta {
        mnemonic: "LOOP",
        fmt: LjFmt::None,
        flags: LjInstrFlags(LjInstrFlags::LOOP_HINT.0),
        description: "Pseudo-instruction: loop header hint for the JIT",
    },
    // 86: ILOOP
    LjOpMeta {
        mnemonic: "ILOOP",
        fmt: LjFmt::None,
        flags: LjInstrFlags(LjInstrFlags::LOOP_HINT.0),
        description: "Interpreted LOOP hint",
    },
    // 87: JLOOP
    LjOpMeta {
        mnemonic: "JLOOP",
        fmt: LjFmt::None,
        flags: LjInstrFlags(LjInstrFlags::LOOP_HINT.0),
        description: "JIT-compiled LOOP hint",
    },
    // 88: JMP
    LjOpMeta {
        mnemonic: "JMP",
        fmt: LjFmt::AdSigned,
        flags: LjInstrFlags(LjInstrFlags::BRANCH.0),
        description: "Unconditional jump by signed offset D",
    },
    // 89: FUNCF
    LjOpMeta {
        mnemonic: "FUNCF",
        fmt: LjFmt::A,
        flags: LjInstrFlags(LjInstrFlags::FUNC_HEADER.0),
        description: "Fixed-arg function header (frame size = A)",
    },
    // 90: IFUNCF
    LjOpMeta {
        mnemonic: "IFUNCF",
        fmt: LjFmt::A,
        flags: LjInstrFlags(LjInstrFlags::FUNC_HEADER.0),
        description: "Interpreted fixed-arg function header",
    },
    // 91: JFUNCF
    LjOpMeta {
        mnemonic: "JFUNCF",
        fmt: LjFmt::A,
        flags: LjInstrFlags(LjInstrFlags::FUNC_HEADER.0),
        description: "JIT-compiled fixed-arg function header",
    },
    // 92: FUNCV
    LjOpMeta {
        mnemonic: "FUNCV",
        fmt: LjFmt::A,
        flags: LjInstrFlags(LjInstrFlags::FUNC_HEADER.0),
        description: "Vararg function header",
    },
    // 93: IFUNCV
    LjOpMeta {
        mnemonic: "IFUNCV",
        fmt: LjFmt::A,
        flags: LjInstrFlags(LjInstrFlags::FUNC_HEADER.0),
        description: "Interpreted vararg function header",
    },
    // 94: JFUNCV
    LjOpMeta {
        mnemonic: "JFUNCV",
        fmt: LjFmt::A,
        flags: LjInstrFlags(LjInstrFlags::FUNC_HEADER.0),
        description: "JIT-compiled vararg function header",
    },
    // 95: FUNCC
    LjOpMeta {
        mnemonic: "FUNCC",
        fmt: LjFmt::None,
        flags: LjInstrFlags(LjInstrFlags::FUNC_HEADER.0),
        description: "C function header (called from Lua, no LuaJIT frame)",
    },
    // 96: FUNCCW
    LjOpMeta {
        mnemonic: "FUNCCW",
        fmt: LjFmt::None,
        flags: LjInstrFlags(LjInstrFlags::FUNC_HEADER.0),
        description: "Wrapped C function header",
    },
];

impl LjOpMeta {
    /// Return the metadata for a given opcode byte.
    ///
    /// # Panics
    /// Panics in debug builds if `op >= LJ_OP_META.len()`.  In release builds
    /// returns a safe default (FUNCCW entry) for out-of-range values.
    #[must_use] 
    pub fn for_op(op: u8) -> &'static Self {
        let idx = op as usize;
        if idx < LJ_OP_META.len() {
            &LJ_OP_META[idx]
        } else {
            // fallback: last valid entry (avoids panic in release builds)
            &LJ_OP_META[LJ_OP_META.len() - 1]
        }
    }
}

// ---------------------------------------------------------------------------
// decode_lj_instruction
// ---------------------------------------------------------------------------

/// Decode a raw 32-bit `LuaJIT` instruction word into an [`LjInstruction`].
///
/// All fields — opcode, A/B/C operands, the combined D field, the signed
/// interpretation of D, the encoding format, and semantic flags — are
/// populated from `word`.
///
/// If the opcode byte is out of range the function returns an [`LjInstruction`]
/// with `op` set to the raw byte, `mnemonic()` returning `"???"`, and all
/// flag bits clear.
///
/// # Examples
///
/// ```rust
/// # use rustre_arch_luajit::{decode_lj_instruction, make_lj_abc, LjOp, LjInstrFlags};
/// let word = make_lj_abc(LjOp::Addvv as u8, 0, 1, 2);
/// let instr = decode_lj_instruction(word);
/// assert_eq!(instr.mnemonic(), "ADDVV");
/// assert!(instr.flags.is_empty());
/// ```
#[must_use] 
pub fn decode_lj_instruction(word: u32) -> LjInstruction {
    let op = (word & 0xff) as u8;
    let a = ((word >> 8) & 0xff) as u8;
    let c = ((word >> 16) & 0xff) as u8;
    let b = ((word >> 24) & 0xff) as u8;
    let d = (u32::from(b) << 8) | u32::from(c);
    let d_signed = d.cast_signed() - BIAS.cast_signed();

    if (op as usize) >= LJ_OP_META.len() {
        return LjInstruction {
            raw: word,
            op,
            a,
            b,
            c,
            d,
            d_signed,
            fmt: LjFmt::Abc,
            flags: LjInstrFlags::NONE,
            category: InstrCategory::Other,
        };
    }

    let meta = LjOpMeta::for_op(op);

    LjInstruction {
        raw: word,
        op,
        a,
        b,
        c,
        d,
        d_signed,
        fmt: meta.fmt,
        flags: meta.flags,
        category: categorize(op),
    }
}

// ---------------------------------------------------------------------------
// KGC — GC constant pool companion for fmt_lj_instruction
// ---------------------------------------------------------------------------

/// A subset of the GC constant pool needed to produce annotated disassembly.
///
/// When a [`LuaJitProto`] is available you can construct a [`KGC`] from its
/// `constants` field to pass to [`fmt_lj_instruction`], enabling string
/// literals and prototype indices to be shown inline.
#[derive(Debug, Clone, Default)]
pub struct KGC {
    /// String constants in the order they appear in the proto's kgc array.
    /// Only `LjConst::String` values are collected here; other kgc entries
    /// occupy their slot as `None` or are skipped — callers must build this
    /// slice to match the string-constant indices used by KSTR/GGET/GSET.
    pub strings: Vec<Vec<u8>>,
    /// Child proto indices (unused by the formatter itself, but provided for
    /// completeness so callers can resolve FNEW operands).
    pub protos: Vec<usize>,
}

impl KGC {
    /// Build a [`KGC`] from the constant pool of a [`LuaJitProto`].
    ///
    /// Only `LjConst::String` values are extracted; numeric and other
    /// constants are ignored.  The resulting index space matches the order in
    /// which strings appear in `proto.constants`.
    #[must_use] 
    pub fn from_proto(proto: &LuaJitProto) -> Self {
        let strings = proto
            .constants
            .iter()
            .filter_map(|c| {
                if let LjConst::String(s) = c {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect();
        Self {
            strings,
            protos: Vec::new(),
        }
    }

    /// Look up a string constant by its KSTR/GGET/GSET index.
    ///
    /// Returns `None` if the index is out of range.
    #[must_use] 
    pub fn string(&self, idx: usize) -> Option<&[u8]> {
        self.strings.get(idx).map(std::vec::Vec::as_slice)
    }

    /// Attempt to interpret a string constant as valid UTF-8.
    ///
    /// Falls back to a lossy conversion if the bytes are not valid UTF-8.
    #[must_use] 
    pub fn string_lossy(&self, idx: usize) -> Option<String> {
        self.strings
            .get(idx)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }
}

// ---------------------------------------------------------------------------
// fmt_lj_instruction
// ---------------------------------------------------------------------------

/// Format a decoded [`LjInstruction`] as a human-readable disassembly line.
///
/// The output format is:
///
/// ```text
/// MNEMONIC  <operands> [; <annotation>]
/// ```
///
/// When `kgc` is `Some` and the instruction references a string constant
/// (KSTR, GGET, GSET), the string value is appended as a comment after a `;`.
///
/// # Examples
///
/// ```rust
/// # use rustre_arch_luajit::{decode_lj_instruction, fmt_lj_instruction, make_lj_abc, LjOp};
/// let word = make_lj_abc(LjOp::Addvv as u8, 0, 1, 2);
/// let instr = decode_lj_instruction(word);
/// let s = fmt_lj_instruction(&instr, None);
/// assert!(s.starts_with("ADDVV"));
/// assert!(s.contains("R0"));
/// ```
#[must_use] 
pub fn fmt_lj_instruction(instr: &LjInstruction, kgc: Option<&KGC>) -> String {
    let mnemonic = instr.mnemonic();
    let a = instr.a;
    let b = instr.b;
    let c = instr.c;
    let d = instr.d;
    let d_signed = instr.d_signed;

    // Build the operand string according to the instruction format.
    let operands: String = match instr.fmt {
        LjFmt::Abc => format!("R{a}, R{b}, R{c}"),
        LjFmt::Ad => format!("R{a}, {d}"),
        LjFmt::AdSigned => format!("R{a}, {d_signed:+}"),
        LjFmt::A => format!("R{a}"),
        LjFmt::None => String::new(),
    };

    // Build an optional annotation for instructions that reference named
    // constants in the KGC pool.
    let annotation: Option<String> = kgc.and_then(|kgc| {
        match instr.op {
            // KSTR: D is the string constant index
            39 => kgc.string_lossy(d as usize).map(|s| format!("; \"{s}\"")),
            // GGET / GSET: D is a string key in the global table
            54 | 55 => kgc
                .string_lossy(d as usize)
                .map(|s| format!("; _G[\"{s}\"]")),
            // TGETS / TSETS: C encodes a string key constant
            57 | 61 => kgc
                .string_lossy(c as usize)
                .map(|s| format!("; key=\"{s}\"")),
            // USETS: D is a string constant index
            47 => kgc.string_lossy(d as usize).map(|s| format!("; \"{s}\"")),
            // FNEW: D is a proto index — show index as a hint
            51 => Some(format!("; proto[{d}]")),
            _ => None,
        }
    });

    // Assemble the final line.
    match (operands.is_empty(), annotation) {
        (true, None) => format!("{mnemonic:<8}"),
        (true, Some(ann)) => format!("{mnemonic:<8} {ann}"),
        (false, None) => format!("{mnemonic:<8}  {operands}"),
        (false, Some(ann)) => format!("{mnemonic:<8}  {operands}  {ann}"),
    }
}

// ---------------------------------------------------------------------------
// Proto hierarchy analysis
// ---------------------------------------------------------------------------

/// Count the total number of nested function prototypes contained within
/// `proto`, including all descendants at every depth.
///
/// The root `proto` itself is **not** counted — only its children and their
/// descendants.
///
/// # Examples
///
/// ```rust
/// # use rustre_arch_luajit::{LuaJitProto, count_protos};
/// let inner = LuaJitProto::default();
/// let outer = LuaJitProto { protos: vec![inner], ..Default::default() };
/// assert_eq!(count_protos(&outer), 1);
/// ```
#[must_use] 
pub fn count_protos(proto: &LuaJitProto) -> usize {
    proto
        .protos
        .iter()
        .fold(0, |acc, child| acc + 1 + count_protos(child))
}

/// Return the maximum nesting depth of function prototypes reachable from
/// `proto`.
///
/// A `proto` with no children has a nesting depth of 0.  A `proto` with a
/// single direct child (and no grandchildren) has depth 1, and so on.
///
/// # Examples
///
/// ```rust
/// # use rustre_arch_luajit::{LuaJitProto, max_nesting_depth};
/// let leaf   = LuaJitProto::default();
/// let mid    = LuaJitProto { protos: vec![leaf],  ..Default::default() };
/// let root   = LuaJitProto { protos: vec![mid],   ..Default::default() };
/// assert_eq!(max_nesting_depth(&root), 2);
/// ```
pub fn max_nesting_depth(proto: &LuaJitProto) -> usize {
    if proto.protos.is_empty() {
        return 0;
    }
    1 + proto
        .protos
        .iter()
        .map(max_nesting_depth)
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// ProtoSummary — aggregate statistics for an entire proto tree
// ---------------------------------------------------------------------------

/// Aggregate statistics derived by walking the full prototype hierarchy of a
/// `LuaJIT` chunk.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtoSummary {
    /// Total number of nested protos (all depths; root not counted).
    pub total_protos: usize,
    /// Maximum nesting depth of any proto in the tree.
    pub max_depth: usize,
    /// Total number of bytecode instructions across all protos (root +
    /// descendants).
    pub total_instructions: usize,
    /// Total number of string constants across all protos.
    pub total_string_constants: usize,
    /// Total number of upvalue slots across all protos.
    pub total_upvalues: usize,
}

/// Walk the proto hierarchy rooted at `proto` and compute a [`ProtoSummary`].
///
/// This function does a depth-first traversal of the prototype tree and
/// accumulates the fields of [`ProtoSummary`].
#[must_use] 
pub fn proto_summary(proto: &LuaJitProto) -> ProtoSummary {
    let mut summary = ProtoSummary {
        total_protos: count_protos(proto),
        max_depth: max_nesting_depth(proto),
        total_instructions: 0,
        total_string_constants: 0,
        total_upvalues: 0,
    };
    accumulate_summary(proto, &mut summary);
    summary
}

fn accumulate_summary(proto: &LuaJitProto, out: &mut ProtoSummary) {
    out.total_instructions += proto.instructions.len();
    out.total_upvalues += proto.upvalues.len();
    out.total_string_constants += proto
        .constants
        .iter()
        .filter(|c| matches!(c, LjConst::String(_)))
        .count();
    for child in &proto.protos {
        accumulate_summary(child, out);
    }
}

// ---------------------------------------------------------------------------
// Instruction disassembly listing with KGC annotation support
// ---------------------------------------------------------------------------

/// Disassemble a slice of instruction words using the richer
/// [`fmt_lj_instruction`] formatter and return a multi-line listing.
///
/// Each line is prefixed with its zero-based instruction index in four-digit
/// hex followed by a colon, e.g.:
///
/// ```text
/// 0000:  ADDVV    R0, R1, R2
/// 0001:  RET1     R0, 2
/// ```
///
/// Pass `kgc` to get inline annotations for string constants and global
/// accesses.
#[must_use] 
pub fn disassemble_listing_annotated(words: &[u32], kgc: Option<&KGC>) -> String {
    words
        .iter()
        .enumerate()
        .map(|(i, &w)| {
            let instr = decode_lj_instruction(w);
            let formatted = fmt_lj_instruction(&instr, kgc);
            format!("{i:04x}:  {formatted}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Walk an entire proto tree (root + all descendants, depth-first) and
/// return a multi-line string with headers separating each proto.
///
/// Each proto section is preceded by a header line:
///
/// ```text
/// ===== proto [0] (params=2, framesize=4, instrs=7) =====
/// ```
///
/// followed by the annotated instruction listing for that proto.
#[must_use] 
pub fn disassemble_proto_tree(proto: &LuaJitProto) -> String {
    let mut out = String::new();
    disassemble_proto_tree_inner(proto, &mut out, &mut 0usize, 0usize);
    out
}

fn disassemble_proto_tree_inner(
    proto: &LuaJitProto,
    out: &mut String,
    counter: &mut usize,
    depth: usize,
) {
    let idx = *counter;
    *counter += 1;

    let indent = "  ".repeat(depth);
    let header = format!(
        "{indent}===== proto [{idx}] (params={params}, framesize={fs}, instrs={n}) =====\n",
        params = proto.params,
        fs = proto.framesize,
        n = proto.instructions.len(),
    );
    out.push_str(&header);

    let kgc = KGC::from_proto(proto);
    for (i, &w) in proto.instructions.iter().enumerate() {
        let instr = decode_lj_instruction(w);
        let formatted = fmt_lj_instruction(&instr, Some(&kgc));
        writeln!(out, "{indent}  {i:04x}:  {formatted}").expect("writing to String is infallible");
    }

    for child in &proto.protos {
        disassemble_proto_tree_inner(child, out, counter, depth + 1);
    }
}

// ---------------------------------------------------------------------------
// Operand role descriptors
// ---------------------------------------------------------------------------

/// Describes the semantic role of a single operand within a `LuaJIT`
/// instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperandRole {
    /// Destination register (write).
    Dst,
    /// Source register (read).
    Src,
    /// Source register that is also a table base.
    TableBase,
    /// Register range start (e.g. for KNIL, VARG, multi-return).
    RangeStart,
    /// Register range end (inclusive).
    RangeEnd,
    /// Unsigned constant-pool index.
    ConstIndex,
    /// Signed immediate (e.g. KSHORT value, branch offset).
    SignedImmediate,
    /// Unsigned immediate byte.
    ImmediateByte,
    /// Primitive type tag (0=nil, 1=false, 2=true).
    PrimitiveTag,
    /// Upvalue slot index.
    UpvalueIndex,
    /// Jump offset (signed, relative to next instruction).
    JumpOffset,
}

/// A single operand with its decoded numeric value and its semantic role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedOperand {
    /// The raw numeric value of this operand field.
    pub value: i32,
    /// How this value should be interpreted.
    pub role: OperandRole,
}

/// Build a single [`DecodedOperand`].
#[inline]
const fn op_val(value: i32, role: OperandRole) -> DecodedOperand {
    DecodedOperand { value, role }
}

/// Return a list of [`DecodedOperand`]s for an [`LjInstruction`].
///
/// The list is ordered as the operands appear in the canonical assembly
/// syntax: destination first, then sources left-to-right.
#[must_use]
pub fn instruction_operands(instr: &LjInstruction) -> Vec<DecodedOperand> {
    use OperandRole::{
        ConstIndex, Dst, ImmediateByte, JumpOffset, PrimitiveTag, RangeEnd, RangeStart,
        SignedImmediate, Src, TableBase, UpvalueIndex,
    };
    let op = instr.op;
    let a = i32::from(instr.a);
    let b = i32::from(instr.b);
    let c = i32::from(instr.c);
    let d = instr.d.cast_signed();
    let ds = instr.d_signed;

    match op {
        // ISLT/ISGE/ISLE/ISGT/ISEQV/ISNEV: A, B, C (reg/reg comparisons)
        0..=5 => vec![op_val(a, Src), op_val(b, Src), op_val(c, Src)],
        // ISEQS/ISNES/ISEQN/ISNEN / GSET: A, D (reg, const index)
        6..=9 | 55 => vec![op_val(a, Src), op_val(d, ConstIndex)],
        // ISEQP/ISNEP: A, D (reg, primitive tag)
        10 | 11 => vec![op_val(a, Src), op_val(d, PrimitiveTag)],
        // ISTC/ISFC/MOV/NOT/UNM/LEN: A = dst, D = src
        12 | 13 | 18..=21 => vec![op_val(a, Dst), op_val(d, Src)],
        // IST/ISF: D only (source)
        14 | 15 => vec![op_val(d, Src)],
        // ISTYPE/ISNUM / CALLMT/CALLT / RETM/RET/RET0/RET1: A, D (src, immediate)
        16 | 17 | 67 | 68 | 73..=76 => vec![op_val(a, Src), op_val(d, ImmediateByte)],
        // Arithmetic VN/NV/VV + POW/CAT: dst = A, src1 = B, src2 = C
        22..=38 => vec![op_val(a, Dst), op_val(b, Src), op_val(c, Src)],
        // KSTR/KCDATA/KNUM/KPRI/FNEW/TNEW/TDUP/GGET: A = dst, D = const index
        39 | 40 | 42 | 43 | 51..=54 => vec![op_val(a, Dst), op_val(d, ConstIndex)],
        // KSHORT: A = dst, D_signed = immediate
        41 => vec![op_val(a, Dst), op_val(ds, SignedImmediate)],
        // KNIL: range A..D
        44 => vec![op_val(a, RangeStart), op_val(d, RangeEnd)],
        // UGET: A = dst register, D = upvalue index
        45 => vec![op_val(a, Dst), op_val(d, UpvalueIndex)],
        // USETV: A = upvalue index, D = src register
        46 => vec![op_val(a, UpvalueIndex), op_val(d, Src)],
        // USETS/USETN/USETP: A = upvalue index, D = const
        47..=49 => vec![op_val(a, UpvalueIndex), op_val(d, ConstIndex)],
        // UCLO/ISNEXT / FORI..JITERL: A = register, D = jump offset
        50 | 72 | 77..=84 => vec![op_val(a, Src), op_val(ds, JumpOffset)],
        // TGETV/TGETS/TGETB/TGETR: A = dst, B = table, C = key
        56..=59 => vec![op_val(a, Dst), op_val(b, TableBase), op_val(c, Src)],
        // TSETV/TSETS/TSETB/TSETR: A = val, B = table, C = key
        60..=62 | 64 => vec![op_val(a, Src), op_val(b, TableBase), op_val(c, Src)],
        // TSETM: A = base reg, D = const index
        63 => vec![op_val(a, RangeStart), op_val(d, ConstIndex)],
        // CALLM/CALL: A = func, B = #results+1, C = #args+1
        65 | 66 => vec![op_val(a, Src), op_val(b, ImmediateByte), op_val(c, ImmediateByte)],
        // ITERC/ITERN/VARG: A = dst base, B = #results+1, C = arg count
        69..=71 => vec![op_val(a, Dst), op_val(b, ImmediateByte), op_val(c, ImmediateByte)],
        // JMP: D = jump offset
        88 => vec![op_val(ds, JumpOffset)],
        // FUNCF..JFUNCV: A = framesize
        89..=94 => vec![op_val(a, ImmediateByte)],
        // FUNCC/FUNCCW and unknown: no operands
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn arch() -> LuaJitArch {
        LuaJitArch::new()
    }

    fn dis(word: u32) -> Instruction {
        let bytes = word.to_le_bytes();
        arch().disassemble(Address::new(0x100), &bytes).unwrap()
    }

    // --- Original tests (preserved) ---

    #[test]
    fn test_islt() {
        let w = make_lj_abc(LjOp::Islt as u8, 0, 2, 1);
        let i = dis(w);
        assert_eq!(i.mnemonic, "islt");
        assert!(i.flags.contains(InstrFlags::BRANCH));
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_isge() {
        let w = make_lj_abc(LjOp::Isge as u8, 0, 1, 2);
        let i = dis(w);
        assert_eq!(i.mnemonic, "isge");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_isle() {
        let w = make_lj_abc(LjOp::Isle as u8, 0, 1, 2);
        let i = dis(w);
        assert_eq!(i.mnemonic, "isle");
    }

    #[test]
    fn test_isgt() {
        let w = make_lj_abc(LjOp::Isgt as u8, 0, 1, 2);
        let i = dis(w);
        assert_eq!(i.mnemonic, "isgt");
    }

    #[test]
    fn test_iseqv() {
        let w = make_lj_abc(LjOp::Iseqv as u8, 0, 1, 2);
        let i = dis(w);
        assert_eq!(i.mnemonic, "iseqv");
    }

    #[test]
    fn test_mov() {
        let w = make_lj_ad(LjOp::Mov as u8, 1, 2);
        let i = dis(w);
        assert_eq!(i.mnemonic, "mov");
        assert!(i.operands.contains("R1"));
    }

    #[test]
    fn test_not() {
        let w = make_lj_ad(LjOp::Not as u8, 0, 1);
        let i = dis(w);
        assert_eq!(i.mnemonic, "not");
    }

    #[test]
    fn test_unm() {
        let w = make_lj_ad(LjOp::Unm as u8, 0, 1);
        let i = dis(w);
        assert_eq!(i.mnemonic, "unm");
    }

    #[test]
    fn test_len() {
        let w = make_lj_ad(LjOp::Len as u8, 0, 1);
        let i = dis(w);
        assert_eq!(i.mnemonic, "len");
    }

    #[test]
    fn test_addvv() {
        let w = make_lj_abc(LjOp::Addvv as u8, 0, 1, 2);
        let i = dis(w);
        assert_eq!(i.mnemonic, "addvv");
    }

    #[test]
    fn test_subvv() {
        let w = make_lj_abc(LjOp::Subvv as u8, 0, 1, 2);
        let i = dis(w);
        assert_eq!(i.mnemonic, "subvv");
    }

    #[test]
    fn test_mulvv() {
        let w = make_lj_abc(LjOp::Mulvv as u8, 0, 1, 2);
        let i = dis(w);
        assert_eq!(i.mnemonic, "mulvv");
    }

    #[test]
    fn test_divvv() {
        let w = make_lj_abc(LjOp::Divvv as u8, 0, 1, 2);
        let i = dis(w);
        assert_eq!(i.mnemonic, "divvv");
    }

    #[test]
    fn test_kshort() {
        let w = make_lj_ad_signed(LjOp::Kshort as u8, 0, 42);
        let i = dis(w);
        assert_eq!(i.mnemonic, "kshort");
        assert!(i.operands.contains("+42"));
    }

    #[test]
    fn test_kstr() {
        let w = make_lj_ad(LjOp::Kstr as u8, 0, 5);
        let i = dis(w);
        assert_eq!(i.mnemonic, "kstr");
        assert!(i.operands.contains('5'));
    }

    #[test]
    fn test_call() {
        let w = make_lj_abc(LjOp::Call as u8, 0, 2, 1);
        let i = dis(w);
        assert_eq!(i.mnemonic, "call");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_callt() {
        let w = make_lj_ad(LjOp::Callt as u8, 0, 2);
        let i = dis(w);
        assert_eq!(i.mnemonic, "callt");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_ret() {
        let w = make_lj_ad(LjOp::Ret as u8, 0, 2);
        let i = dis(w);
        assert_eq!(i.mnemonic, "ret");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_ret0() {
        let w = make_lj_ad(LjOp::Ret0 as u8, 0, 0);
        let i = dis(w);
        assert_eq!(i.mnemonic, "ret0");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_ret1() {
        let w = make_lj_ad(LjOp::Ret1 as u8, 0, 1);
        let i = dis(w);
        assert_eq!(i.mnemonic, "ret1");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_jmp() {
        let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, 3);
        let i = dis(w);
        assert_eq!(i.mnemonic, "jmp");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_fori() {
        let w = make_lj_ad_signed(LjOp::Fori as u8, 0, 5);
        let i = dis(w);
        assert_eq!(i.mnemonic, "fori");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_forl() {
        let w = make_lj_ad_signed(LjOp::Forl as u8, 0, -3);
        let i = dis(w);
        assert_eq!(i.mnemonic, "forl");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_gget() {
        let w = make_lj_ad(LjOp::Gget as u8, 0, 1);
        let i = dis(w);
        assert_eq!(i.mnemonic, "gget");
    }

    #[test]
    fn test_gset() {
        let w = make_lj_ad(LjOp::Gset as u8, 0, 1);
        let i = dis(w);
        assert_eq!(i.mnemonic, "gset");
    }

    #[test]
    fn test_tgetv() {
        let w = make_lj_abc(LjOp::Tgetv as u8, 0, 1, 2);
        let i = dis(w);
        assert_eq!(i.mnemonic, "tgetv");
    }

    #[test]
    fn test_fnew() {
        let w = make_lj_ad(LjOp::Fnew as u8, 0, 1);
        let i = dis(w);
        assert_eq!(i.mnemonic, "fnew");
    }

    #[test]
    fn test_loop() {
        let w = make_lj_abc(LjOp::Loop as u8, 0, 0, 0);
        let i = dis(w);
        assert_eq!(i.mnemonic, "loop");
        assert_eq!(i.operands, "");
    }

    #[test]
    fn test_funcf() {
        let w = make_lj_abc(LjOp::Funcf as u8, 3, 0, 0);
        let i = dis(w);
        assert_eq!(i.mnemonic, "funcf");
        assert!(i.operands.contains("R3"));
    }

    #[test]
    fn test_registers() {
        let regs = arch().registers();
        assert_eq!(regs[0].name, "R0");
        assert!(!regs.is_empty());
    }

    #[test]
    fn test_arch_name() {
        assert_eq!(arch().name(), "luajit");
    }

    #[test]
    fn test_pointer_size() {
        assert_eq!(arch().pointer_size(), 8);
    }

    #[test]
    fn test_endian() {
        assert_eq!(arch().endian(), Endian::Little);
    }

    #[test]
    fn test_calling_convention() {
        let cc = arch().calling_conventions();
        assert!(!cc.is_empty());
        assert_eq!(cc[0].name, "luajit");
    }

    #[test]
    fn test_unknown_opcode() {
        let w: u32 = 0xff;
        let result = arch().disassemble(Address::new(0), &w.to_le_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_get_branches_unconditional_jump() {
        let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, 2);
        let i = dis(w);
        let branches = arch().get_branches(&i);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].kind, BranchKind::UnconditionalJump);
        assert!(branches[0].target.is_some());
    }

    #[test]
    fn test_get_branches_return() {
        let w = make_lj_ad(LjOp::Ret0 as u8, 0, 0);
        let i = dis(w);
        let branches = arch().get_branches(&i);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].kind, BranchKind::Return);
        assert_eq!(branches[0].target, None);
    }

    #[test]
    fn test_branch_kind_classification() {
        let jmp = dis(make_lj_ad_signed(LjOp::Jmp as u8, 0, 2));
        assert_eq!(
            arch().branch_kind(&jmp),
            Some(BranchKind::UnconditionalJump)
        );

        let ret = dis(make_lj_ad(LjOp::Ret0 as u8, 0, 0));
        assert_eq!(arch().branch_kind(&ret), Some(BranchKind::Return));
    }

    // --- New extended tests ---

    #[test]
    fn test_lj_op_from_u8_roundtrip() {
        for i in 0u8..lj_names_len_u8() {
            let op = LjOp::from_u8(i).expect("should parse");
            assert_eq!(op as u8, i);
        }
        assert!(LjOp::from_u8(0xff).is_none());
    }

    #[test]
    fn test_lj_op_mnemonic() {
        assert_eq!(LjOp::Jmp.mnemonic(), "JMP");
        assert_eq!(LjOp::Addvv.mnemonic(), "ADDVV");
        assert_eq!(LjOp::Ret0.mnemonic(), "RET0");
    }

    #[test]
    fn test_instr_category_comparison() {
        assert_eq!(LjOp::Islt.category(), InstrCategory::Comparison);
        assert_eq!(LjOp::Isnum.category(), InstrCategory::Comparison);
    }

    #[test]
    fn test_instr_category_arithmetic() {
        assert_eq!(LjOp::Addvv.category(), InstrCategory::Arithmetic);
        assert_eq!(LjOp::Mov.category(), InstrCategory::Arithmetic);
    }

    #[test]
    fn test_instr_category_load_const() {
        assert_eq!(LjOp::Kstr.category(), InstrCategory::LoadConst);
        assert_eq!(LjOp::Knil.category(), InstrCategory::LoadConst);
    }

    #[test]
    fn test_instr_category_call_return() {
        assert_eq!(LjOp::Call.category(), InstrCategory::Call);
        assert_eq!(LjOp::Ret0.category(), InstrCategory::Return);
    }

    #[test]
    fn test_instr_category_branch() {
        assert_eq!(LjOp::Jmp.category(), InstrCategory::Branch);
        assert_eq!(LjOp::Fori.category(), InstrCategory::Branch);
    }

    #[test]
    fn test_instr_field_extractors() {
        // ADDVV R2, R3, R4
        let w = make_lj_abc(LjOp::Addvv as u8, 2, 3, 4);
        assert_eq!(instr_op(w), LjOp::Addvv as u8);
        assert_eq!(instr_a(w), 2);
        assert_eq!(instr_b(w), 3);
        assert_eq!(instr_c(w), 4);
        assert_eq!(instr_d(w), (3u16 << 8) | 4);
    }

    #[test]
    fn test_instr_d_signed_roundtrip() {
        for offset in [-100i16, -1, 0, 1, 100, 32000, -32000] {
            let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, offset);
            assert_eq!(instr_d_signed(w), offset, "offset={offset}");
        }
    }

    #[test]
    fn test_format_instruction() {
        let w = make_lj_abc(LjOp::Addvv as u8, 0, 1, 2);
        let s = format_instruction(7, w);
        assert!(s.contains("ADDVV"), "got: {s}");
        assert!(s.contains("R0"), "got: {s}");
        assert!(s.starts_with("0007"), "got: {s}");
    }

    #[test]
    fn test_disassemble_listing_multi() {
        let words = vec![
            make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
            make_lj_ad(LjOp::Ret1 as u8, 0, 1),
        ];
        let listing = disassemble_listing(&words);
        assert!(listing.contains("ADDVV"));
        assert!(listing.contains("RET1"));
        
        assert_eq!(listing.lines().count(), 2);
    }

    #[test]
    fn test_disassemble_block() {
        let words = vec![
            make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
            make_lj_ad(LjOp::Ret0 as u8, 0, 0),
        ];
        let results = arch().disassemble_block(Address::new(0), &words);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert_eq!(results[0].as_ref().unwrap().mnemonic, "addvv");
        assert_eq!(results[1].as_ref().unwrap().mnemonic, "ret0");
    }

    #[test]
    fn test_detail_basic() {
        let words = vec![make_lj_abc(LjOp::Addvv as u8, 5, 6, 7)];
        let d = arch().detail(0, &words).unwrap();
        assert_eq!(d.op, LjOp::Addvv as u8);
        assert_eq!(d.a, 5);
        assert_eq!(d.b, 6);
        assert_eq!(d.c, 7);
        assert_eq!(d.category, InstrCategory::Arithmetic);
        assert_eq!(d.branch_target, None);
    }

    #[test]
    fn test_detail_branch_target() {
        // JMP +2 at index 0: target = 0 + 1 + 2 = 3
        let words = vec![make_lj_ad_signed(LjOp::Jmp as u8, 0, 2)];
        let d = arch().detail(0, &words).unwrap();
        assert_eq!(d.branch_target, Some(3));
    }

    #[test]
    fn test_detail_reads_writes() {
        // ADDVV R0, R1, R2 — writes R0, reads R1 and R2
        let words = vec![make_lj_abc(LjOp::Addvv as u8, 0, 1, 2)];
        let d = arch().detail(0, &words).unwrap();
        assert!(d.writes_reg(0));
        assert!(!d.writes_reg(1));
        assert!(d.reads_reg(1));
        assert!(d.reads_reg(2));
        assert!(!d.reads_reg(0));
    }

    #[test]
    fn test_basic_block_trivial() {
        // Single RET — one block
        let words = vec![make_lj_ad(LjOp::Ret0 as u8, 0, 0)];
        let bbs = find_basic_blocks(&words);
        assert_eq!(bbs.len(), 1);
        assert_eq!(bbs[0], BasicBlock { start: 0, end: 1 });
    }

    #[test]
    fn test_basic_block_unconditional_jmp() {
        // index 0: JMP +1 (target = 0+1+1 = 2)
        // index 1: some arith
        // index 2: ret0
        let words = vec![
            make_lj_ad_signed(LjOp::Jmp as u8, 0, 1),
            make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
            make_lj_ad(LjOp::Ret0 as u8, 0, 0),
        ];
        let bbs = find_basic_blocks(&words);
        // block 0: [0,1), block 1: [1,2), block 2: [2,3)
        assert!(bbs.len() >= 2);
        assert_eq!(bbs[0].start, 0);
    }

    #[test]
    fn test_basic_block_empty_input() {
        let bbs = find_basic_blocks(&[]);
        assert!(bbs.is_empty());
    }

    #[test]
    fn test_category_histogram() {
        let proto = LuaJitProto {
            instructions: vec![
                make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
                make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
                make_lj_ad(LjOp::Ret0 as u8, 0, 0),
            ],
            ..Default::default()
        };
        let hist = proto.category_histogram();
        assert_eq!(hist[InstrCategory::Arithmetic as usize], 2);
        assert_eq!(hist[InstrCategory::Return as usize], 1);
    }

    #[test]
    fn test_used_opcodes() {
        let proto = LuaJitProto {
            instructions: vec![
                make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
                make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
                make_lj_ad(LjOp::Ret0 as u8, 0, 0),
            ],
            ..Default::default()
        };
        let ops = proto.used_opcodes();
        assert!(ops.contains(&(LjOp::Addvv as u8)));
        assert!(ops.contains(&(LjOp::Ret0 as u8)));
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn test_proto_is_vararg() {
        let mut p = LuaJitProto {
            flags: 0x02,
            ..LuaJitProto::default()
        };
        assert!(p.is_vararg());
        p.flags = 0x00;
        assert!(!p.is_vararg());
    }

    #[test]
    fn test_proto_branches() {
        let proto = LuaJitProto {
            instructions: vec![
                make_lj_ad_signed(LjOp::Jmp as u8, 0, 1),
                make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
                make_lj_ad(LjOp::Ret0 as u8, 0, 0),
            ],
            ..Default::default()
        };
        let branches = proto.branches();
        assert!(!branches.is_empty());
        assert_eq!(branches[0].op, LjOp::Jmp as u8);
    }

    #[test]
    fn test_string_constants() {
        let proto = LuaJitProto {
            constants: vec![
                LjConst::String(b"hello".to_vec()),
                LjConst::Integer(42),
                LjConst::String(b"world".to_vec()),
            ],
            ..Default::default()
        };
        let strs = proto.string_constants();
        assert_eq!(strs.len(), 2);
        assert_eq!(strs[0], b"hello");
        assert_eq!(strs[1], b"world");
    }

    #[test]
    fn test_dump_flags_parse() {
        let f = DumpFlags::from_byte(0x03);
        assert!(f.be());
        assert!(f.strip());
        assert!(!f.ffi());
        assert!(!f.fr2());

        let g = DumpFlags::from_byte(0x0c);
        assert!(!g.be());
        assert!(!g.strip());
        assert!(g.ffi());
        assert!(g.fr2());
    }

    #[test]
    fn test_bytecode_parse_bad_magic() {
        let data = b"\x00\x00\x00\x01\x02";
        assert_eq!(LuaJitBytecode::parse(data), Err(ParseError::BadMagic));
    }

    #[test]
    fn test_bytecode_parse_too_short() {
        let data = b"\x1bLJ";
        assert_eq!(LuaJitBytecode::parse(data), Err(ParseError::UnexpectedEof));
    }

    #[test]
    fn test_bytecode_parse_bad_version() {
        let data = b"\x1bLJ\x05\x00";
        assert_eq!(LuaJitBytecode::parse(data), Err(ParseError::BadMagic));
    }

    #[test]
    fn test_uleb128_single_byte() {
        let data = [0x05u8];
        let mut pos = 0;
        let v = read_uleb128(&data, &mut pos).unwrap();
        assert_eq!(v, 5);
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_uleb128_multi_byte() {
        // 300 = 0xAC 0x02
        let data = [0xAC, 0x02u8];
        let mut pos = 0;
        let v = read_uleb128(&data, &mut pos).unwrap();
        assert_eq!(v, 300);
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_uleb128_eof() {
        let data = [0x80u8]; // continuation bit set but no more bytes
        let mut pos = 0;
        assert_eq!(
            read_uleb128(&data, &mut pos),
            Err(ParseError::UnexpectedEof)
        );
    }

    #[test]
    fn test_collect_reg_accesses_addvv() {
        // ADDVV R0, R1, R2: writes R0, reads R1 and R2
        let words = vec![make_lj_abc(LjOp::Addvv as u8, 0, 1, 2)];
        let accesses = collect_reg_accesses(&words);
        let defs: Vec<_> = accesses.iter().filter(|a| a.is_def).collect();
        let uses: Vec<_> = accesses.iter().filter(|a| !a.is_def).collect();
        assert!(defs.iter().any(|a| a.reg == 0));
        assert!(uses.iter().any(|a| a.reg == 1));
        assert!(uses.iter().any(|a| a.reg == 2));
    }

    #[test]
    fn test_branch_target_negative_offset() {
        // FORL -3 at index 5 → target = 5 + 1 + (-3) = 3
        let mut words = vec![make_lj_abc(LjOp::Addvv as u8, 0, 1, 2); 6];
        words[5] = make_lj_ad_signed(LjOp::Forl as u8, 0, -3);
        let d = arch().detail(5, &words).unwrap();
        assert_eq!(d.branch_target, Some(3));
    }

    #[test]
    fn test_proto_iter_instructions() {
        let proto = LuaJitProto {
            instructions: vec![0x1234_5678, 0xDEAD_BEEF],
            ..Default::default()
        };
        let pairs: Vec<_> = proto.iter_instructions().collect();
        assert_eq!(pairs, vec![(0, 0x1234_5678), (1, 0xDEAD_BEEF)]);
    }

    #[test]
    fn test_lj_instr_detail_mnemonic() {
        let words = vec![make_lj_abc(LjOp::Addvv as u8, 0, 1, 2)];
        let d = arch().detail(0, &words).unwrap();
        assert_eq!(d.mnemonic(), "addvv");
    }

    #[test]
    fn test_basic_block_len() {
        let bb = BasicBlock { start: 2, end: 7 };
        assert_eq!(bb.len(), 5);
        assert!(!bb.is_empty());
    }

    #[test]
    fn test_basic_block_is_empty() {
        let bb = BasicBlock { start: 3, end: 3 };
        assert!(bb.is_empty());
        assert_eq!(bb.len(), 0);
    }

    #[test]
    fn test_has_children_false() {
        let p = LuaJitProto::default();
        assert!(!p.has_children());
    }

    #[test]
    fn test_has_children_true() {
        let mut p = LuaJitProto::default();
        p.protos.push(LuaJitProto::default());
        assert!(p.has_children());
    }

    #[test]
    fn test_lj_const_variants() {
        let c_int = LjConst::Integer(42);
        let c_flt = LjConst::Float(std::f64::consts::PI);
        let c_str = LjConst::String(b"hi".to_vec());
        let c_nil = LjConst::Nil;
        let c_bool = LjConst::Bool(true);
        // Just verify they construct and compare correctly
        assert_ne!(c_int, c_flt);
        assert_ne!(c_str, c_nil);
        assert_eq!(c_bool, LjConst::Bool(true));
    }

    #[test]
    fn test_disassemble_block_addresses() {
        let words = vec![
            make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
            make_lj_ad(LjOp::Ret0 as u8, 0, 0),
        ];
        let base = Address::new(0x1000);
        let results = arch().disassemble_block(base, &words);
        assert_eq!(results[0].as_ref().unwrap().address, Address::new(0x1000));
        assert_eq!(results[1].as_ref().unwrap().address, Address::new(0x1004));
    }

    #[test]
    fn test_format_instruction_no_operands() {
        let w = make_lj_abc(LjOp::Loop as u8, 0, 0, 0);
        let s = format_instruction(0, w);
        assert!(s.contains("LOOP"));
        // Should not have trailing spaces with operands text
        assert!(s.starts_with("0000"));
    }

    #[test]
    fn test_kshort_negative() {
        let w = make_lj_ad_signed(LjOp::Kshort as u8, 0, -7);
        let i = dis(w);
        assert_eq!(i.mnemonic, "kshort");
        assert!(i.operands.contains("-7"), "operands: {}", i.operands);
    }

    #[test]
    fn test_branch_kind_conditional() {
        let w = make_lj_ad_signed(LjOp::Fori as u8, 0, 2);
        let i = dis(w);
        // fori is a branch
        assert!(arch().branch_kind(&i).is_some());
    }

    #[test]
    fn test_all_opcodes_decodable() {
        // Every valid opcode should decode without error
        for op in 0u8..lj_names_len_u8() {
            let w = make_lj_abc(op, 0, 0, 0);
            let result = arch().disassemble(Address::new(0), &w.to_le_bytes());
            assert!(result.is_ok(), "opcode {op} failed: {result:?}");
        }
    }

    // --- LjInstruction / decode_lj_instruction / fmt_lj_instruction tests ---

    #[test]
    fn test_decode_lj_instruction_addvv() {
        let w = make_lj_abc(LjOp::Addvv as u8, 3, 5, 7);
        let instr = decode_lj_instruction(w);
        assert_eq!(instr.op, LjOp::Addvv as u8);
        assert_eq!(instr.a, 3);
        assert_eq!(instr.b, 5);
        assert_eq!(instr.c, 7);
        assert_eq!(instr.fmt, LjFmt::Abc);
        assert!(instr.flags.is_empty());
    }

    #[test]
    fn test_decode_lj_instruction_jmp() {
        let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, 10);
        let instr = decode_lj_instruction(w);
        assert_eq!(instr.op, LjOp::Jmp as u8);
        assert_eq!(instr.d_signed, 10);
        assert!(instr.flags.contains(LjInstrFlags::BRANCH));
        assert!(!instr.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_decode_lj_instruction_islt() {
        let w = make_lj_abc(LjOp::Islt as u8, 1, 2, 3);
        let instr = decode_lj_instruction(w);
        assert!(instr.flags.contains(LjInstrFlags::BRANCH));
        assert!(instr.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_decode_lj_instruction_call() {
        let w = make_lj_abc(LjOp::Call as u8, 0, 2, 1);
        let instr = decode_lj_instruction(w);
        assert!(instr.flags.contains(LjInstrFlags::CALL));
    }

    #[test]
    fn test_decode_lj_instruction_ret0() {
        let w = make_lj_ad(LjOp::Ret0 as u8, 0, 0);
        let instr = decode_lj_instruction(w);
        assert!(instr.flags.contains(LjInstrFlags::RETURN));
    }

    #[test]
    fn test_fmt_lj_instruction_no_kgc() {
        let w = make_lj_abc(LjOp::Addvv as u8, 0, 1, 2);
        let instr = decode_lj_instruction(w);
        let s = fmt_lj_instruction(&instr, None);
        assert!(s.contains("ADDVV"));
        assert!(s.contains("R0"));
        assert!(s.contains("R1"));
        assert!(s.contains("R2"));
    }

    #[test]
    fn test_fmt_lj_instruction_kstr_with_kgc() {
        let kgc = KGC {
            strings: vec![b"hello".to_vec(), b"world".to_vec()],
            protos: Vec::new(),
        };
        let w = make_lj_ad(LjOp::Kstr as u8, 0, 0);
        let instr = decode_lj_instruction(w);
        let s = fmt_lj_instruction(&instr, Some(&kgc));
        assert!(s.contains("KSTR"));
        assert!(s.contains("hello"), "expected 'hello' in: {s}");
    }

    #[test]
    fn test_fmt_lj_instruction_kshort() {
        let w = make_lj_ad_signed(LjOp::Kshort as u8, 2, -5);
        let instr = decode_lj_instruction(w);
        let s = fmt_lj_instruction(&instr, None);
        assert!(s.contains("KSHORT"));
        assert!(s.contains("-5"), "got: {s}");
    }

    #[test]
    fn test_fmt_lj_instruction_jmp_offset() {
        let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, 5);
        let instr = decode_lj_instruction(w);
        let s = fmt_lj_instruction(&instr, None);
        assert!(s.contains("JMP"));
        assert!(s.contains("+5") || s.contains('5'), "got: {s}");
    }

    #[test]
    fn test_lj_instr_flags_set() {
        let mut f = LjInstrFlags::empty();
        f |= LjInstrFlags::BRANCH;
        f |= LjInstrFlags::CONDITIONAL;
        assert!(f.contains(LjInstrFlags::BRANCH));
        assert!(f.contains(LjInstrFlags::CONDITIONAL));
        assert!(!f.contains(LjInstrFlags::CALL));
    }

    #[test]
    fn test_opcode_meta_all_present() {
        for op in 0u8..lj_names_len_u8() {
            let m = LjOpMeta::for_op(op);
            assert_eq!(m.mnemonic, LJ_NAMES[op as usize]);
        }
    }

    #[test]
    fn test_opcode_meta_format() {
        assert_eq!(LjOpMeta::for_op(LjOp::Addvv as u8).fmt, LjFmt::Abc);
        assert_eq!(LjOpMeta::for_op(LjOp::Kstr as u8).fmt, LjFmt::Ad);
        assert_eq!(LjOpMeta::for_op(LjOp::Jmp as u8).fmt, LjFmt::AdSigned);
    }

    #[test]
    fn test_count_protos_no_children() {
        let p = LuaJitProto::default();
        assert_eq!(count_protos(&p), 0);
    }

    #[test]
    fn test_count_protos_nested() {
        let inner1 = LuaJitProto::default();
        let inner2 = LuaJitProto {
            protos: vec![LuaJitProto::default()],
            ..Default::default()
        };
        let outer = LuaJitProto {
            protos: vec![inner1, inner2],
            ..Default::default()
        };
        // outer has 2 direct children; inner2 has 1 child -> total 3
        assert_eq!(count_protos(&outer), 3);
    }

    #[test]
    fn test_max_nesting_depth_flat() {
        let p = LuaJitProto::default();
        assert_eq!(max_nesting_depth(&p), 0);
    }

    #[test]
    fn test_max_nesting_depth_single_child() {
        let child = LuaJitProto::default();
        let parent = LuaJitProto {
            protos: vec![child],
            ..Default::default()
        };
        assert_eq!(max_nesting_depth(&parent), 1);
    }

    #[test]
    fn test_max_nesting_depth_deep() {
        let depth3 = LuaJitProto::default();
        let depth2 = LuaJitProto {
            protos: vec![depth3],
            ..Default::default()
        };
        let depth1 = LuaJitProto {
            protos: vec![depth2],
            ..Default::default()
        };
        let root = LuaJitProto {
            protos: vec![depth1],
            ..Default::default()
        };
        assert_eq!(max_nesting_depth(&root), 3);
    }

    #[test]
    fn test_max_nesting_depth_wide_vs_deep() {
        // root has two children: one with depth 1, one with depth 3
        let leaf = LuaJitProto::default();
        let mid = LuaJitProto {
            protos: vec![leaf],
            ..Default::default()
        };
        let deep = LuaJitProto {
            protos: vec![mid],
            ..Default::default()
        };
        let shallow = LuaJitProto {
            protos: vec![LuaJitProto::default()],
            ..Default::default()
        };
        let root = LuaJitProto {
            protos: vec![shallow, deep],
            ..Default::default()
        };
        assert_eq!(max_nesting_depth(&root), 3);
    }

    #[test]
    fn test_kgc_string_lookup() {
        let kgc = KGC {
            strings: vec![b"alpha".to_vec(), b"beta".to_vec()],
            protos: Vec::new(),
        };
        assert_eq!(kgc.string(0), Some(b"alpha".as_ref()));
        assert_eq!(kgc.string(1), Some(b"beta".as_ref()));
        assert_eq!(kgc.string(2), None);
    }

    #[test]
    fn test_lj_instruction_roundtrip_fields() {
        // Verify all fields extracted correctly from a crafted word.
        let op = LjOp::Mulvv as u8;
        let w = make_lj_abc(op, 10, 11, 12);
        let instr = decode_lj_instruction(w);
        assert_eq!(instr.a, 10);
        assert_eq!(instr.b, 11);
        assert_eq!(instr.c, 12);
        assert_eq!(instr.d, (11u32 << 8) | 0x0c);
    }

    #[test]
    fn test_fmt_lj_instruction_funcf() {
        // FUNCF has LjFmt::A — only A operand
        let w = make_lj_abc(LjOp::Funcf as u8, 4, 0, 0);
        let instr = decode_lj_instruction(w);
        let s = fmt_lj_instruction(&instr, None);
        assert!(s.contains("FUNCF"));
        assert!(s.contains("R4"));
    }

    #[test]
    fn test_fmt_lj_instruction_loop_no_operands() {
        let w = make_lj_abc(LjOp::Loop as u8, 0, 0, 0);
        let instr = decode_lj_instruction(w);
        let s = fmt_lj_instruction(&instr, None);
        assert!(s.contains("LOOP"));
    }

    #[test]
    fn test_proto_summary_empty() {
        let p = LuaJitProto::default();
        let sum = proto_summary(&p);
        assert_eq!(sum.total_protos, 0);
        assert_eq!(sum.max_depth, 0);
        assert_eq!(sum.total_instructions, 0);
    }

    #[test]
    fn test_proto_summary_with_children() {
        let child_instr = LuaJitProto {
            instructions: vec![
                make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
                make_lj_ad(LjOp::Ret0 as u8, 0, 0),
            ],
            ..Default::default()
        };
        let root = LuaJitProto {
            instructions: vec![make_lj_ad(LjOp::Ret0 as u8, 0, 0)],
            protos: vec![child_instr],
            ..Default::default()
        };
        let sum = proto_summary(&root);
        assert_eq!(sum.total_protos, 1);
        assert_eq!(sum.max_depth, 1);
        assert_eq!(sum.total_instructions, 3); // 1 root + 2 child
    }

    // ── All opcodes decode without error ──────────────────────────────────────

    #[test]
    fn test_all_lj_opcodes_decode_instruction() {
        for op in 0u8..lj_names_len_u8() {
            let w = make_lj_abc(op, 0, 0, 0);
            let instr = decode_lj_instruction(w);
            assert_eq!(instr.op, op, "op {op}");
        }
    }

    #[test]
    fn test_all_lj_opcodes_format() {
        for op in 0u8..lj_names_len_u8() {
            let w = make_lj_abc(op, 1, 2, 3);
            let instr = decode_lj_instruction(w);
            let s = fmt_lj_instruction(&instr, None);
            assert!(!s.is_empty(), "op {op} produced empty string");
        }
    }

    // ── Operand role tests ────────────────────────────────────────────────────

    #[test]
    fn test_operand_roles_addvv() {
        let w = make_lj_abc(LjOp::Addvv as u8, 0, 1, 2);
        let instr = decode_lj_instruction(w);
        let ops = instruction_operands(&instr);
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0].role, OperandRole::Dst);
        assert_eq!(ops[1].role, OperandRole::Src);
        assert_eq!(ops[2].role, OperandRole::Src);
        assert_eq!(ops[0].value, 0);
        assert_eq!(ops[1].value, 1);
        assert_eq!(ops[2].value, 2);
    }

    #[test]
    fn test_operand_roles_kshort() {
        let w = make_lj_ad_signed(LjOp::Kshort as u8, 3, -10);
        let instr = decode_lj_instruction(w);
        let ops = instruction_operands(&instr);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].role, OperandRole::Dst);
        assert_eq!(ops[0].value, 3);
        assert_eq!(ops[1].role, OperandRole::SignedImmediate);
        assert_eq!(ops[1].value, -10);
    }

    #[test]
    fn test_operand_roles_knil() {
        let w = make_lj_ad(LjOp::Knil as u8, 2, 5);
        let instr = decode_lj_instruction(w);
        let ops = instruction_operands(&instr);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].role, OperandRole::RangeStart);
        assert_eq!(ops[1].role, OperandRole::RangeEnd);
    }

    #[test]
    fn test_operand_roles_uget() {
        let w = make_lj_ad(LjOp::Uget as u8, 1, 3);
        let instr = decode_lj_instruction(w);
        let ops = instruction_operands(&instr);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].role, OperandRole::Dst);
        assert_eq!(ops[1].role, OperandRole::UpvalueIndex);
        assert_eq!(ops[1].value, 3);
    }

    #[test]
    fn test_operand_roles_usetv() {
        let w = make_lj_ad(LjOp::Usetv as u8, 0, 2);
        let instr = decode_lj_instruction(w);
        let ops = instruction_operands(&instr);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].role, OperandRole::UpvalueIndex);
        assert_eq!(ops[1].role, OperandRole::Src);
    }

    #[test]
    fn test_operand_roles_tgetv() {
        let w = make_lj_abc(LjOp::Tgetv as u8, 0, 1, 2);
        let instr = decode_lj_instruction(w);
        let ops = instruction_operands(&instr);
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0].role, OperandRole::Dst);
        assert_eq!(ops[1].role, OperandRole::TableBase);
        assert_eq!(ops[2].role, OperandRole::Src);
    }

    #[test]
    fn test_operand_roles_tsetv() {
        let w = make_lj_abc(LjOp::Tsetv as u8, 0, 1, 2);
        let instr = decode_lj_instruction(w);
        let ops = instruction_operands(&instr);
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0].role, OperandRole::Src); // value
        assert_eq!(ops[1].role, OperandRole::TableBase);
        assert_eq!(ops[2].role, OperandRole::Src); // key
    }

    #[test]
    fn test_operand_roles_jmp() {
        let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, 7);
        let instr = decode_lj_instruction(w);
        let ops = instruction_operands(&instr);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].role, OperandRole::JumpOffset);
        assert_eq!(ops[0].value, 7);
    }

    #[test]
    fn test_operand_roles_call() {
        let w = make_lj_abc(LjOp::Call as u8, 0, 2, 1);
        let instr = decode_lj_instruction(w);
        let ops = instruction_operands(&instr);
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0].role, OperandRole::Src);
        assert_eq!(ops[1].role, OperandRole::ImmediateByte);
        assert_eq!(ops[2].role, OperandRole::ImmediateByte);
    }

    #[test]
    fn test_operand_roles_loop_empty() {
        let w = make_lj_abc(LjOp::Loop as u8, 0, 0, 0);
        let instr = decode_lj_instruction(w);
        let ops = instruction_operands(&instr);
        assert!(ops.is_empty());
    }

    #[test]
    fn test_operand_roles_funcf() {
        let w = make_lj_abc(LjOp::Funcf as u8, 4, 0, 0);
        let instr = decode_lj_instruction(w);
        let ops = instruction_operands(&instr);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].role, OperandRole::ImmediateByte);
        assert_eq!(ops[0].value, 4);
    }

    // ── LjInstrFlags bitwise ops ──────────────────────────────────────────────

    #[test]
    fn test_lj_instr_flags_union() {
        let a = LjInstrFlags::BRANCH;
        let b = LjInstrFlags::CALL;
        let c = a.union(b);
        assert!(c.contains(LjInstrFlags::BRANCH));
        assert!(c.contains(LjInstrFlags::CALL));
        assert!(!c.contains(LjInstrFlags::RETURN));
    }

    #[test]
    fn test_lj_instr_flags_is_empty() {
        assert!(LjInstrFlags::empty().is_empty());
        assert!(LjInstrFlags::NONE.is_empty());
        assert!(!LjInstrFlags::BRANCH.is_empty());
    }

    #[test]
    fn test_lj_instr_flags_display_branch() {
        let f = LjInstrFlags::BRANCH | LjInstrFlags::CONDITIONAL;
        let s = f.to_string();
        assert!(s.contains("BRANCH"));
        assert!(s.contains("CONDITIONAL"));
    }

    #[test]
    fn test_lj_instr_flags_display_all() {
        let f = LjInstrFlags::BRANCH
            | LjInstrFlags::CALL
            | LjInstrFlags::RETURN
            | LjInstrFlags::UPVALUE_READ
            | LjInstrFlags::UPVALUE_WRITE
            | LjInstrFlags::TABLE_READ
            | LjInstrFlags::TABLE_WRITE
            | LjInstrFlags::GLOBAL_ACCESS
            | LjInstrFlags::CLOSES_UPVALUES
            | LjInstrFlags::FUNC_HEADER
            | LjInstrFlags::LOOP_HINT
            | LjInstrFlags::TAIL_CALL;
        let s = f.to_string();
        assert!(s.contains("CALL"));
        assert!(s.contains("RETURN"));
        assert!(s.contains("TABLE_READ"));
    }

    // ── Comparison instructions ───────────────────────────────────────────────

    #[test]
    fn test_islt_flags() {
        let w = make_lj_abc(LjOp::Islt as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::BRANCH));
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_isge_flags() {
        let w = make_lj_abc(LjOp::Isge as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_iseqs_flags() {
        let w = make_lj_ad(LjOp::Iseqs as u8, 0, 5);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_iseqn_flags() {
        let w = make_lj_ad(LjOp::Iseqn as u8, 0, 3);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_iseqp_flags() {
        let w = make_lj_ad(LjOp::Iseqp as u8, 0, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_istc_flags() {
        let w = make_lj_ad(LjOp::Istc as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_isfc_flags() {
        let w = make_lj_ad(LjOp::Isfc as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_ist_flags() {
        let w = make_lj_ad(LjOp::Ist as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_isf_flags() {
        let w = make_lj_ad(LjOp::Isf as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_istype_flags() {
        let w = make_lj_ad(LjOp::Istype as u8, 0, 5);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_isnum_flags() {
        let w = make_lj_ad(LjOp::Isnum as u8, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    // ── Arithmetic instruction variants ───────────────────────────────────────

    #[test]
    fn test_addvn() {
        let w = make_lj_abc(LjOp::Addvn as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "ADDVN");
        assert!(i.flags.is_empty());
    }

    #[test]
    fn test_subvn() {
        let w = make_lj_abc(LjOp::Subvn as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "SUBVN");
    }

    #[test]
    fn test_mulvn() {
        let w = make_lj_abc(LjOp::Mulvn as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "MULVN");
    }

    #[test]
    fn test_divvn() {
        let w = make_lj_abc(LjOp::Divvn as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "DIVVN");
    }

    #[test]
    fn test_modvn() {
        let w = make_lj_abc(LjOp::Modvn as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "MODVN");
    }

    #[test]
    fn test_addnv() {
        let w = make_lj_abc(LjOp::Addnv as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "ADDNV");
    }

    #[test]
    fn test_subnv() {
        let w = make_lj_abc(LjOp::Subnv as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "SUBNV");
    }

    #[test]
    fn test_mulnv() {
        let w = make_lj_abc(LjOp::Mulnv as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "MULNV");
    }

    #[test]
    fn test_divnv() {
        let w = make_lj_abc(LjOp::Divnv as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "DIVNV");
    }

    #[test]
    fn test_modnv() {
        let w = make_lj_abc(LjOp::Modnv as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "MODNV");
    }

    #[test]
    fn test_pow() {
        let w = make_lj_abc(LjOp::Pow as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "POW");
    }

    #[test]
    fn test_cat() {
        let w = make_lj_abc(LjOp::Cat as u8, 0, 1, 3);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "CAT");
    }

    // ── Constant-load instructions ────────────────────────────────────────────

    #[test]
    fn test_kcdata() {
        let w = make_lj_ad(LjOp::Kcdata as u8, 0, 7);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "KCDATA");
    }

    #[test]
    fn test_kpri_nil() {
        // primitive 0 = nil
        let w = make_lj_ad(LjOp::Kpri as u8, 0, 0);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "KPRI");
        assert_eq!(i.d, 0);
    }

    #[test]
    fn test_kpri_false() {
        let w = make_lj_ad(LjOp::Kpri as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert_eq!(i.d, 1);
    }

    #[test]
    fn test_kpri_true() {
        let w = make_lj_ad(LjOp::Kpri as u8, 0, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.d, 2);
    }

    #[test]
    fn test_knum() {
        let w = make_lj_ad(LjOp::Knum as u8, 1, 4);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "KNUM");
        assert_eq!(i.a, 1);
        assert_eq!(i.d, 4);
    }

    // ── Upvalue instructions ──────────────────────────────────────────────────

    #[test]
    fn test_usetv_flags() {
        let w = make_lj_ad(LjOp::Usetv as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::UPVALUE_WRITE));
    }

    #[test]
    fn test_usets_flags() {
        let w = make_lj_ad(LjOp::Usets as u8, 0, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::UPVALUE_WRITE));
    }

    #[test]
    fn test_usetn_flags() {
        let w = make_lj_ad(LjOp::Usetn as u8, 0, 3);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::UPVALUE_WRITE));
    }

    #[test]
    fn test_usetp_flags() {
        let w = make_lj_ad(LjOp::Usetp as u8, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::UPVALUE_WRITE));
    }

    #[test]
    fn test_uclo_flags() {
        let w = make_lj_ad_signed(LjOp::Uclo as u8, 0, 3);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CLOSES_UPVALUES));
        assert!(i.flags.contains(LjInstrFlags::BRANCH));
    }

    #[test]
    fn test_fnew_flags() {
        let w = make_lj_ad(LjOp::Fnew as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CLOSES_UPVALUES));
    }

    #[test]
    fn test_uget_flags() {
        let w = make_lj_ad(LjOp::Uget as u8, 0, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::UPVALUE_READ));
    }

    // ── Table instructions ────────────────────────────────────────────────────

    #[test]
    fn test_tnew() {
        let w = make_lj_ad(LjOp::Tnew as u8, 0, 0x0304);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "TNEW");
    }

    #[test]
    fn test_tdup() {
        let w = make_lj_ad(LjOp::Tdup as u8, 0, 2);
        let i = decode_lj_instruction(w);
        assert_eq!(i.mnemonic(), "TDUP");
    }

    #[test]
    fn test_gget_flags() {
        let w = make_lj_ad(LjOp::Gget as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::GLOBAL_ACCESS));
        assert!(i.flags.contains(LjInstrFlags::TABLE_READ));
    }

    #[test]
    fn test_gset_flags() {
        let w = make_lj_ad(LjOp::Gset as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::GLOBAL_ACCESS));
        assert!(i.flags.contains(LjInstrFlags::TABLE_WRITE));
    }

    #[test]
    fn test_tgets_flags() {
        let w = make_lj_abc(LjOp::Tgets as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::TABLE_READ));
    }

    #[test]
    fn test_tgetb_flags() {
        let w = make_lj_abc(LjOp::Tgetb as u8, 0, 1, 3);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::TABLE_READ));
    }

    #[test]
    fn test_tgetr_flags() {
        let w = make_lj_abc(LjOp::Tgetr as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::TABLE_READ));
    }

    #[test]
    fn test_tsets_flags() {
        let w = make_lj_abc(LjOp::Tsets as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::TABLE_WRITE));
    }

    #[test]
    fn test_tsetb_flags() {
        let w = make_lj_abc(LjOp::Tsetb as u8, 0, 1, 5);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::TABLE_WRITE));
    }

    #[test]
    fn test_tsetm_flags() {
        let w = make_lj_ad(LjOp::Tsetm as u8, 0, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::TABLE_WRITE));
    }

    #[test]
    fn test_tsetr_flags() {
        let w = make_lj_abc(LjOp::Tsetr as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::TABLE_WRITE));
    }

    // ── Call instructions ─────────────────────────────────────────────────────

    #[test]
    fn test_callm_flags() {
        let w = make_lj_abc(LjOp::Callm as u8, 0, 2, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CALL));
    }

    #[test]
    fn test_callmt_flags() {
        let w = make_lj_ad(LjOp::Callmt as u8, 0, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CALL));
        assert!(i.flags.contains(LjInstrFlags::TAIL_CALL));
    }

    #[test]
    fn test_callt_flags() {
        let w = make_lj_ad(LjOp::Callt as u8, 0, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::TAIL_CALL));
    }

    #[test]
    fn test_iterc_flags() {
        let w = make_lj_abc(LjOp::Iterc as u8, 0, 3, 3);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CALL));
    }

    #[test]
    fn test_itern_flags() {
        let w = make_lj_abc(LjOp::Itern as u8, 0, 3, 3);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CALL));
    }

    #[test]
    fn test_varg_operands() {
        let w = make_lj_abc(LjOp::Varg as u8, 0, 2, 3);
        let instr = decode_lj_instruction(w);
        assert_eq!(instr.mnemonic(), "VARG");
        assert_eq!(instr.b, 2);
        assert_eq!(instr.c, 3);
    }

    #[test]
    fn test_isnext_flags() {
        let w = make_lj_ad(LjOp::Isnext as u8, 0, 5);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::BRANCH));
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    // ── Return instructions ───────────────────────────────────────────────────

    #[test]
    fn test_retm_flags() {
        let w = make_lj_ad(LjOp::Retm as u8, 0, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::RETURN));
    }

    #[test]
    fn test_ret_flags() {
        let w = make_lj_ad(LjOp::Ret as u8, 0, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::RETURN));
    }

    // ── Loop instructions ─────────────────────────────────────────────────────

    #[test]
    fn test_jfori_flags() {
        let w = make_lj_ad_signed(LjOp::Jfori as u8, 0, 4);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::BRANCH));
        assert!(i.flags.contains(LjInstrFlags::LOOP_HINT));
    }

    #[test]
    fn test_iforl_flags() {
        let w = make_lj_ad_signed(LjOp::Iforl as u8, 0, -3);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::LOOP_HINT));
    }

    #[test]
    fn test_jforl_flags() {
        let w = make_lj_ad_signed(LjOp::Jforl as u8, 0, -2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::LOOP_HINT));
    }

    #[test]
    fn test_iterl_flags() {
        let w = make_lj_ad_signed(LjOp::Iterl as u8, 0, -4);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::LOOP_HINT));
    }

    #[test]
    fn test_iiterl_flags() {
        let w = make_lj_ad_signed(LjOp::Iiterl as u8, 0, -2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::LOOP_HINT));
    }

    #[test]
    fn test_jiterl_flags() {
        let w = make_lj_ad_signed(LjOp::Jiterl as u8, 0, -1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::LOOP_HINT));
    }

    #[test]
    fn test_iloop_flags() {
        let w = make_lj_abc(LjOp::Iloop as u8, 0, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::LOOP_HINT));
    }

    #[test]
    fn test_jloop_flags() {
        let w = make_lj_abc(LjOp::Jloop as u8, 0, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::LOOP_HINT));
    }

    // ── Function header instructions ──────────────────────────────────────────

    #[test]
    fn test_ifuncf_flags() {
        let w = make_lj_abc(LjOp::Ifuncf as u8, 3, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::FUNC_HEADER));
    }

    #[test]
    fn test_jfuncf_flags() {
        let w = make_lj_abc(LjOp::Jfuncf as u8, 4, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::FUNC_HEADER));
    }

    #[test]
    fn test_funcv_flags() {
        let w = make_lj_abc(LjOp::Funcv as u8, 5, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::FUNC_HEADER));
    }

    #[test]
    fn test_ifuncv_flags() {
        let w = make_lj_abc(LjOp::Ifuncv as u8, 2, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::FUNC_HEADER));
    }

    #[test]
    fn test_jfuncv_flags() {
        let w = make_lj_abc(LjOp::Jfuncv as u8, 1, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::FUNC_HEADER));
    }

    #[test]
    fn test_funcc_flags() {
        let w = make_lj_abc(LjOp::Funcc as u8, 0, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::FUNC_HEADER));
    }

    #[test]
    fn test_funccw_flags() {
        let w = make_lj_abc(LjOp::Funccw as u8, 0, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::FUNC_HEADER));
    }

    // ── fmt_lj_instruction annotated variants ─────────────────────────────────

    #[test]
    fn test_fmt_gget_with_kgc() {
        let kgc = KGC {
            strings: vec![b"print".to_vec()],
            protos: vec![],
        };
        let w = make_lj_ad(LjOp::Gget as u8, 0, 0);
        let instr = decode_lj_instruction(w);
        let s = fmt_lj_instruction(&instr, Some(&kgc));
        assert!(s.contains("GGET"));
        assert!(s.contains("print"), "got: {s}");
    }

    #[test]
    fn test_fmt_gset_with_kgc() {
        let kgc = KGC {
            strings: vec![b"result".to_vec()],
            protos: vec![],
        };
        let w = make_lj_ad(LjOp::Gset as u8, 1, 0);
        let instr = decode_lj_instruction(w);
        let s = fmt_lj_instruction(&instr, Some(&kgc));
        assert!(s.contains("GSET"));
        assert!(s.contains("result"), "got: {s}");
    }

    #[test]
    fn test_fmt_tgets_with_kgc() {
        let kgc = KGC {
            strings: vec![b"x".to_vec(), b"y".to_vec(), b"method".to_vec()],
            protos: vec![],
        };
        let w = make_lj_abc(LjOp::Tgets as u8, 0, 1, 2);
        let instr = decode_lj_instruction(w);
        let s = fmt_lj_instruction(&instr, Some(&kgc));
        assert!(s.contains("TGETS"));
        assert!(s.contains("method"), "got: {s}");
    }

    #[test]
    fn test_fmt_usets_with_kgc() {
        let kgc = KGC {
            strings: vec![b"upname".to_vec()],
            protos: vec![],
        };
        let w = make_lj_ad(LjOp::Usets as u8, 0, 0);
        let instr = decode_lj_instruction(w);
        let s = fmt_lj_instruction(&instr, Some(&kgc));
        assert!(s.contains("USETS"));
        assert!(s.contains("upname"), "got: {s}");
    }

    #[test]
    fn test_fmt_fnew_proto_hint() {
        let w = make_lj_ad(LjOp::Fnew as u8, 0, 3);
        let instr = decode_lj_instruction(w);
        let s = fmt_lj_instruction(&instr, Some(&KGC::default()));
        assert!(s.contains("FNEW"));
        assert!(s.contains("proto[3]"), "got: {s}");
    }

    // ── disassemble_listing_annotated ─────────────────────────────────────────

    #[test]
    fn test_disassemble_listing_annotated_basic() {
        let words = vec![
            make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
            make_lj_ad(LjOp::Ret1 as u8, 0, 1),
        ];
        let s = disassemble_listing_annotated(&words, None);
        assert!(s.contains("ADDVV"));
        assert!(s.contains("RET1"));
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("0000:"));
        assert!(lines[1].starts_with("0001:"));
    }

    #[test]
    fn test_disassemble_proto_tree_single() {
        let proto = LuaJitProto {
            instructions: vec![
                make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
                make_lj_ad(LjOp::Ret0 as u8, 0, 0),
            ],
            params: 2,
            framesize: 4,
            ..Default::default()
        };
        let s = disassemble_proto_tree(&proto);
        assert!(s.contains("proto [0]"));
        assert!(s.contains("params=2"));
        assert!(s.contains("ADDVV"));
        assert!(s.contains("RET0"));
    }

    #[test]
    fn test_disassemble_proto_tree_nested() {
        let child = LuaJitProto {
            instructions: vec![make_lj_ad(LjOp::Ret0 as u8, 0, 0)],
            ..Default::default()
        };
        let root = LuaJitProto {
            instructions: vec![make_lj_abc(LjOp::Addvv as u8, 0, 1, 2)],
            protos: vec![child],
            ..Default::default()
        };
        let s = disassemble_proto_tree(&root);
        assert!(s.contains("proto [0]"));
        assert!(s.contains("proto [1]"));
    }

    // ── KGC from_proto ────────────────────────────────────────────────────────

    #[test]
    fn test_kgc_from_proto_strings_only() {
        let proto = LuaJitProto {
            constants: vec![
                LjConst::String(b"a".to_vec()),
                LjConst::Integer(42),
                LjConst::String(b"b".to_vec()),
            ],
            ..Default::default()
        };
        let kgc = KGC::from_proto(&proto);
        assert_eq!(kgc.strings.len(), 2);
        assert_eq!(kgc.strings[0], b"a");
        assert_eq!(kgc.strings[1], b"b");
    }

    #[test]
    fn test_kgc_string_lossy() {
        let kgc = KGC {
            strings: vec![b"hello".to_vec()],
            protos: vec![],
        };
        assert_eq!(kgc.string_lossy(0), Some("hello".to_string()));
        assert_eq!(kgc.string_lossy(1), None);
    }

    // ── collect_reg_accesses extended ────────────────────────────────────────

    #[test]
    fn test_collect_reg_accesses_mov() {
        // MOV R1, R0
        let words = vec![make_lj_ad(LjOp::Mov as u8, 1, 0)];
        let accesses = collect_reg_accesses(&words);
        let defs: Vec<_> = accesses.iter().filter(|a| a.is_def).collect();
        assert!(defs.iter().any(|a| a.reg == 1), "should define R1");
    }

    #[test]
    fn test_collect_reg_accesses_subvv() {
        // SUBVV R0, R2, R3
        let words = vec![make_lj_abc(LjOp::Subvv as u8, 0, 2, 3)];
        let accesses = collect_reg_accesses(&words);
        let defs: Vec<_> = accesses.iter().filter(|a| a.is_def).collect();
        let uses: Vec<_> = accesses.iter().filter(|a| !a.is_def).collect();
        assert!(defs.iter().any(|a| a.reg == 0));
        assert!(uses.iter().any(|a| a.reg == 2));
        assert!(uses.iter().any(|a| a.reg == 3));
    }

    // ── LjInstrDetail mnemonic / fmt ──────────────────────────────────────────

    #[test]
    fn test_detail_fmt_ad() {
        let words = vec![make_lj_ad(LjOp::Kstr as u8, 0, 5)];
        let d = arch().detail(0, &words).unwrap();
        assert_eq!(d.fmt, LjFmt::Ad);
    }

    #[test]
    fn test_detail_fmt_ad_signed() {
        let words = vec![make_lj_ad_signed(LjOp::Jmp as u8, 0, -3)];
        let d = arch().detail(0, &words).unwrap();
        assert_eq!(d.fmt, LjFmt::AdSigned);
        assert_eq!(d.d_signed, -3);
    }

    #[test]
    fn test_detail_fmt_a() {
        let words = vec![make_lj_abc(LjOp::Funcf as u8, 7, 0, 0)];
        let d = arch().detail(0, &words).unwrap();
        assert_eq!(d.fmt, LjFmt::A);
        assert_eq!(d.a, 7);
    }

    #[test]
    fn test_detail_fmt_none() {
        let words = vec![make_lj_abc(LjOp::Loop as u8, 0, 0, 0)];
        let d = arch().detail(0, &words).unwrap();
        assert_eq!(d.fmt, LjFmt::None);
    }

    // ── ProtoSummary totals ───────────────────────────────────────────────────

    #[test]
    fn test_proto_summary_upvalues() {
        let proto = LuaJitProto {
            upvalues: vec![
                LjUpvalue {
                    on_stack: true,
                    idx: 0,
                },
                LjUpvalue {
                    on_stack: false,
                    idx: 1,
                },
            ],
            ..Default::default()
        };
        let sum = proto_summary(&proto);
        assert_eq!(sum.total_upvalues, 2);
    }

    #[test]
    fn test_proto_summary_string_constants() {
        let proto = LuaJitProto {
            constants: vec![
                LjConst::String(b"foo".to_vec()),
                LjConst::Integer(1),
                LjConst::String(b"bar".to_vec()),
            ],
            ..Default::default()
        };
        let sum = proto_summary(&proto);
        assert_eq!(sum.total_string_constants, 2);
    }

    // ── LjUpvalue accessors ───────────────────────────────────────────────────

    #[test]
    fn test_lj_upvalue_on_stack() {
        let uv = LjUpvalue {
            on_stack: true,
            idx: 5,
        };
        assert!(uv.on_stack);
        assert_eq!(uv.idx, 5);
    }

    #[test]
    fn test_lj_upvalue_not_on_stack() {
        let uv = LjUpvalue {
            on_stack: false,
            idx: 2,
        };
        assert!(!uv.on_stack);
    }

    // ── ParseError display ────────────────────────────────────────────────────

    #[test]
    fn test_parse_error_display() {
        assert!(ParseError::UnexpectedEof.to_string().contains("unexpected"));
        assert!(ParseError::BadMagic.to_string().contains("magic"));
        assert!(ParseError::Overflow.to_string().contains("overflow"));
        assert!(ParseError::BadUleb.to_string().contains("ULEB128"));
    }

    // ── DumpFlags edge cases ──────────────────────────────────────────────────

    #[test]
    fn test_dump_flags_all_set() {
        let f = DumpFlags::from_byte(0x0f);
        assert!(f.be());
        assert!(f.strip());
        assert!(f.ffi());
        assert!(f.fr2());
    }

    #[test]
    fn test_dump_flags_none_set() {
        let f = DumpFlags::from_byte(0x00);
        assert!(!f.be());
        assert!(!f.strip());
        assert!(!f.ffi());
        assert!(!f.fr2());
    }

    // ── LuaJitBytecode version accessors ─────────────────────────────────────

    #[test]
    fn test_luajit_bytecode_is_lj21() {
        let bc = LuaJitBytecode {
            version: LJ_VERSION_21,
            flags: DumpFlags::default(),
            chunk: LuaJitProto::default(),
        };
        assert!(bc.is_lj21());
    }

    #[test]
    fn test_luajit_bytecode_is_lj20() {
        let bc = LuaJitBytecode {
            version: LJ_VERSION_20,
            flags: DumpFlags::default(),
            chunk: LuaJitProto::default(),
        };
        assert!(!bc.is_lj21());
    }

    #[test]
    fn test_luajit_bytecode_total_instructions() {
        let bc = LuaJitBytecode {
            version: LJ_VERSION_20,
            flags: DumpFlags::default(),
            chunk: LuaJitProto {
                instructions: vec![
                    make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
                    make_lj_ad(LjOp::Ret0 as u8, 0, 0),
                ],
                ..Default::default()
            },
        };
        assert_eq!(bc.total_instructions(), 2);
    }

    // ── instr encoding edge cases ─────────────────────────────────────────────

    #[test]
    fn test_make_lj_ad_max_d() {
        let w = make_lj_ad(LjOp::Kstr as u8, 0, 0xffff);
        assert_eq!(instr_d(w), 0xffff);
    }

    #[test]
    fn test_make_lj_ad_signed_max() {
        let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, 32000);
        assert_eq!(instr_d_signed(w), 32000);
    }

    #[test]
    fn test_make_lj_ad_signed_min() {
        let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, -32000);
        assert_eq!(instr_d_signed(w), -32000);
    }

    #[test]
    fn test_instr_op_extraction() {
        let w = make_lj_abc(LjOp::Mulvv as u8, 1, 2, 3);
        assert_eq!(instr_op(w), LjOp::Mulvv as u8);
    }

    #[test]
    fn test_instr_a_extraction() {
        let w = make_lj_abc(LjOp::Addvv as u8, 200, 1, 1);
        assert_eq!(instr_a(w), 200);
    }

    #[test]
    fn test_instr_b_c_extraction() {
        let w = make_lj_abc(LjOp::Addvv as u8, 0, 170, 85);
        assert_eq!(instr_b(w), 170);
        assert_eq!(instr_c(w), 85);
    }

    // ── find_basic_blocks with loop ───────────────────────────────────────────

    #[test]
    fn test_find_basic_blocks_with_loop() {
        // A simple counting loop:
        //   0: KSHORT R2, 0
        //   1: KSHORT R3, 10
        //   2: ADDVV R2, R2, R0
        //   3: KSHORT R1, 1
        //   4: ADDVV R2, R2, R1  (sub loop body)
        //   5: FORL  R0, -4      (branch back to 2)
        //   6: RET1  R2, 2
        let words = vec![
            make_lj_ad_signed(LjOp::Kshort as u8, 2, 0),
            make_lj_ad_signed(LjOp::Kshort as u8, 3, 10),
            make_lj_abc(LjOp::Addvv as u8, 2, 2, 0),
            make_lj_ad_signed(LjOp::Kshort as u8, 1, 1),
            make_lj_abc(LjOp::Addvv as u8, 2, 2, 1),
            make_lj_ad_signed(LjOp::Forl as u8, 0, -4),
            make_lj_ad(LjOp::Ret1 as u8, 2, 2),
        ];
        let bbs = find_basic_blocks(&words);
        // Back edge creates at least 2 blocks
        assert!(bbs.len() >= 2);
        // Total instructions covered
        let total: usize = bbs.iter().map(super::BasicBlock::len).sum();
        assert_eq!(total, words.len());
    }

    // ── LjOp category checks ──────────────────────────────────────────────────

    #[test]
    fn test_lj_op_category_upvalue() {
        assert_eq!(LjOp::Uget.category(), InstrCategory::Upvalue);
        assert_eq!(LjOp::Usetv.category(), InstrCategory::Upvalue);
        assert_eq!(LjOp::Uclo.category(), InstrCategory::Upvalue);
        assert_eq!(LjOp::Fnew.category(), InstrCategory::Upvalue);
    }

    #[test]
    fn test_lj_op_category_table_get() {
        assert_eq!(LjOp::Tgetv.category(), InstrCategory::TableGet);
        assert_eq!(LjOp::Tgets.category(), InstrCategory::TableGet);
        assert_eq!(LjOp::Tgetb.category(), InstrCategory::TableGet);
        assert_eq!(LjOp::Tgetr.category(), InstrCategory::TableGet);
    }

    #[test]
    fn test_lj_op_category_table_set() {
        assert_eq!(LjOp::Tsetv.category(), InstrCategory::TableSet);
        assert_eq!(LjOp::Tsets.category(), InstrCategory::TableSet);
        assert_eq!(LjOp::Tsetb.category(), InstrCategory::TableSet);
        assert_eq!(LjOp::Tsetr.category(), InstrCategory::TableSet);
    }

    #[test]
    fn test_lj_op_category_func_header() {
        assert_eq!(LjOp::Funcf.category(), InstrCategory::FuncHeader);
        assert_eq!(LjOp::Funcv.category(), InstrCategory::FuncHeader);
        assert_eq!(LjOp::Funcc.category(), InstrCategory::FuncHeader);
        assert_eq!(LjOp::Funccw.category(), InstrCategory::FuncHeader);
    }

    // ── LjOp roundtrip from u8 for all ops ───────────────────────────────────

    #[test]
    fn test_lj_op_from_u8_all_valid() {
        for i in 0u8..lj_names_len_u8() {
            let op = LjOp::from_u8(i);
            assert!(op.is_some(), "op {i} should parse");
            assert_eq!(op.unwrap() as u8, i);
        }
    }

    #[test]
    fn test_lj_op_from_u8_oob() {
        assert!(LjOp::from_u8(200).is_none());
        assert!(LjOp::from_u8(255).is_none());
    }

    // ── LjOpMeta description field ────────────────────────────────────────────

    #[test]
    fn test_op_meta_description_nonempty() {
        for op in 0u8..lj_names_len_u8() {
            let m = LjOpMeta::for_op(op);
            assert!(!m.description.is_empty(), "op {op} has empty description");
        }
    }

    #[test]
    fn test_op_meta_jmp_description() {
        let m = LjOpMeta::for_op(LjOp::Jmp as u8);
        assert!(m.description.to_lowercase().contains("jump") || m.description.contains("offset"));
    }

    // ── Proto used_opcodes dedup ──────────────────────────────────────────────

    #[test]
    fn test_used_opcodes_dedup_many() {
        let proto = LuaJitProto {
            instructions: (0..20)
                .map(|_| make_lj_abc(LjOp::Addvv as u8, 0, 1, 2))
                .collect(),
            ..Default::default()
        };
        let ops = proto.used_opcodes();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], LjOp::Addvv as u8);
    }

    #[test]
    fn test_used_opcodes_multiple() {
        let proto = LuaJitProto {
            instructions: vec![
                make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
                make_lj_abc(LjOp::Subvv as u8, 0, 1, 2),
                make_lj_ad(LjOp::Ret0 as u8, 0, 0),
            ],
            ..Default::default()
        };
        let ops = proto.used_opcodes();
        assert!(ops.contains(&(LjOp::Addvv as u8)));
        assert!(ops.contains(&(LjOp::Subvv as u8)));
        assert!(ops.contains(&(LjOp::Ret0 as u8)));
        assert_eq!(ops.len(), 3);
    }

    // ── BasicBlock len / is_empty ─────────────────────────────────────────────

    #[test]
    fn test_basic_block_large() {
        let bb = BasicBlock {
            start: 100,
            end: 200,
        };
        assert_eq!(bb.len(), 100);
        assert!(!bb.is_empty());
    }

    // ── LjConst equality and variants ────────────────────────────────────────

    #[test]
    fn test_lj_const_integer_eq() {
        assert_eq!(LjConst::Integer(7), LjConst::Integer(7));
        assert_ne!(LjConst::Integer(7), LjConst::Integer(8));
    }

    #[test]
    fn test_lj_const_float_eq() {
        assert_eq!(LjConst::Float(1.0), LjConst::Float(1.0));
    }

    #[test]
    fn test_lj_const_string_eq() {
        assert_eq!(
            LjConst::String(b"abc".to_vec()),
            LjConst::String(b"abc".to_vec())
        );
        assert_ne!(
            LjConst::String(b"abc".to_vec()),
            LjConst::String(b"xyz".to_vec())
        );
    }

    #[test]
    fn test_lj_const_bool_eq() {
        assert_eq!(LjConst::Bool(true), LjConst::Bool(true));
        assert_ne!(LjConst::Bool(true), LjConst::Bool(false));
    }

    #[test]
    fn test_lj_const_nil_eq() {
        assert_eq!(LjConst::Nil, LjConst::Nil);
    }

    // ── Proto iter_instructions ordering ─────────────────────────────────────

    #[test]
    fn test_iter_instructions_order() {
        let words: Vec<u32> = (0u8..5).map(|i| make_lj_abc(i, 0, 0, 0)).collect();
        let proto = LuaJitProto {
            instructions: words.clone(),
            ..Default::default()
        };
        for (idx, (i, w)) in proto.iter_instructions().enumerate() {
            assert_eq!(i, idx);
            assert_eq!(w, words[idx]);
        }
    }

    // ── disassemble_block address stride ─────────────────────────────────────

    #[test]
    fn test_disassemble_block_stride() {
        let words = vec![
            make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
            make_lj_abc(LjOp::Mulvv as u8, 0, 1, 2),
            make_lj_ad(LjOp::Ret0 as u8, 0, 0),
        ];
        let base = Address::new(0x2000);
        let results = arch().disassemble_block(base, &words);
        let addresses: Vec<u64> = results
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|i| i.address.as_u64())
            .collect();
        assert_eq!(addresses, vec![0x2000, 0x2004, 0x2008]);
    }

    // ── get_branches return has no target ────────────────────────────────────

    #[test]
    fn test_get_branches_ret1_no_target() {
        let w = make_lj_ad(LjOp::Ret1 as u8, 0, 1);
        let i = dis(w);
        let branches = arch().get_branches(&i);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].target, None);
    }

    #[test]
    fn test_get_branches_retm_no_target() {
        let w = make_lj_ad(LjOp::Retm as u8, 0, 2);
        let i = dis(w);
        let branches = arch().get_branches(&i);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].target, None);
    }

    // ── branch_kind for call and non-control-flow ─────────────────────────────

    #[test]
    fn test_branch_kind_call() {
        use rustre_core::arch::BranchKind;
        let w = make_lj_abc(LjOp::Call as u8, 0, 2, 1);
        let i = dis(w);
        assert_eq!(arch().branch_kind(&i), Some(BranchKind::Call));
    }

    #[test]
    fn test_branch_kind_none_for_arith() {
        let w = make_lj_abc(LjOp::Addvv as u8, 0, 1, 2);
        let i = dis(w);
        assert_eq!(arch().branch_kind(&i), None);
    }

    // ── format_instruction with all formats ───────────────────────────────────

    #[test]
    fn test_format_instruction_ad_format() {
        let w = make_lj_ad(LjOp::Kstr as u8, 2, 10);
        let s = format_instruction(5, w);
        assert!(s.contains("KSTR"));
        assert!(s.contains("R2"));
        assert!(s.contains("10"));
    }

    #[test]
    fn test_format_instruction_a_format() {
        let w = make_lj_abc(LjOp::Funcv as u8, 6, 0, 0);
        let s = format_instruction(0, w);
        assert!(s.contains("FUNCV"));
        assert!(s.contains("R6"));
    }

    #[test]
    fn test_format_instruction_signed_offset() {
        let w = make_lj_ad_signed(LjOp::Forl as u8, 0, -5);
        let s = format_instruction(9, w);
        assert!(s.contains("FORL"));
        assert!(s.contains("-5"));
    }

    // ── disassemble_listing multi-line separator ──────────────────────────────

    #[test]
    fn test_disassemble_listing_separator() {
        let words = vec![
            make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
            make_lj_abc(LjOp::Subvv as u8, 0, 1, 2),
            make_lj_ad(LjOp::Ret0 as u8, 0, 0),
        ];
        let s = disassemble_listing(&words);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("0000"));
        assert!(lines[1].starts_with("0001"));
        assert!(lines[2].starts_with("0002"));
    }

    // ── LjInstrDetail out of bounds ───────────────────────────────────────────

    #[test]
    fn test_detail_out_of_bounds() {
        let words = vec![make_lj_abc(LjOp::Addvv as u8, 0, 1, 2)];
        let d = arch().detail(1, &words); // index 1 doesn't exist
        assert!(d.is_none());
    }

    // ── proto_summary deep nesting ────────────────────────────────────────────

    #[test]
    fn test_proto_summary_deep_nesting() {
        let depth4 = LuaJitProto {
            instructions: vec![make_lj_ad(LjOp::Ret0 as u8, 0, 0)],
            ..Default::default()
        };
        let depth3 = LuaJitProto {
            protos: vec![depth4],
            instructions: vec![make_lj_ad(LjOp::Ret0 as u8, 0, 0)],
            ..Default::default()
        };
        let depth2 = LuaJitProto {
            protos: vec![depth3],
            instructions: vec![make_lj_ad(LjOp::Ret0 as u8, 0, 0)],
            ..Default::default()
        };
        let root = LuaJitProto {
            protos: vec![depth2],
            instructions: vec![make_lj_ad(LjOp::Ret0 as u8, 0, 0)],
            ..Default::default()
        };
        let sum = proto_summary(&root);
        assert_eq!(sum.max_depth, 3);
        assert_eq!(sum.total_protos, 3);
        assert_eq!(sum.total_instructions, 4);
    }

    // ── Lua version magic constants ───────────────────────────────────────────

    #[test]
    fn test_lj_magic_bytes() {
        assert_eq!(LJ_MAGIC[0], 0x1b);
        assert_eq!(LJ_MAGIC[1], b'L');
        assert_eq!(LJ_MAGIC[2], b'J');
    }

    #[test]
    fn test_lj_version_constants() {
        assert_eq!(LJ_VERSION_20, 1);
        assert_eq!(LJ_VERSION_21, 2);
    }

    // ── RegAccess fields ──────────────────────────────────────────────────────

    #[test]
    fn test_reg_access_fields() {
        let acc = RegAccess {
            instr_idx: 3,
            reg: 5,
            is_def: true,
        };
        assert_eq!(acc.instr_idx, 3);
        assert_eq!(acc.reg, 5);
        assert!(acc.is_def);
    }

    #[test]
    fn test_reg_access_use() {
        let acc = RegAccess {
            instr_idx: 0,
            reg: 2,
            is_def: false,
        };
        assert!(!acc.is_def);
    }

    // ── Instruction count edge cases ──────────────────────────────────────────

    #[test]
    fn test_proto_instr_count_zero() {
        let p = LuaJitProto::default();
        assert_eq!(p.instr_count(), 0);
    }

    #[test]
    fn test_proto_instr_count_nonzero() {
        let p = LuaJitProto {
            instructions: vec![make_lj_ad(LjOp::Ret0 as u8, 0, 0); 7],
            ..Default::default()
        };
        assert_eq!(p.instr_count(), 7);
    }

    // ── string_constants empty proto ──────────────────────────────────────────

    #[test]
    fn test_string_constants_empty() {
        let p = LuaJitProto::default();
        assert!(p.string_constants().is_empty());
    }

    // ── find_basic_blocks single instruction ──────────────────────────────────

    #[test]
    fn test_find_basic_blocks_single_non_branch() {
        let words = vec![make_lj_abc(LjOp::Addvv as u8, 0, 1, 2)];
        let bbs = find_basic_blocks(&words);
        assert_eq!(bbs.len(), 1);
        assert_eq!(bbs[0].len(), 1);
    }

    // ── category_histogram zero counts ───────────────────────────────────────

    #[test]
    fn test_category_histogram_empty() {
        let p = LuaJitProto::default();
        let h = p.category_histogram();
        for &v in &h {
            assert_eq!(v, 0);
        }
    }

    // ── Encoding/decoding D field boundary values ─────────────────────────────

    #[test]
    fn test_instr_d_zero() {
        let w = make_lj_ad(LjOp::Kstr as u8, 0, 0);
        assert_eq!(instr_d(w), 0);
    }

    #[test]
    fn test_instr_d_max() {
        let w = make_lj_ad(LjOp::Kstr as u8, 0, 0xffff);
        assert_eq!(instr_d(w), 0xffff);
    }

    // ── LjFmt equality ────────────────────────────────────────────────────────

    #[test]
    fn test_lj_fmt_eq() {
        assert_eq!(LjFmt::Abc, LjFmt::Abc);
        assert_ne!(LjFmt::Abc, LjFmt::Ad);
        assert_ne!(LjFmt::Ad, LjFmt::AdSigned);
        assert_ne!(LjFmt::A, LjFmt::None);
    }

    // ── OpMeta for every op has consistent fmt with lj_fmt ───────────────────

    #[test]
    fn test_op_meta_fmt_matches_lj_fmt() {
        for op in 0u8..lj_names_len_u8() {
            let meta_fmt = LjOpMeta::for_op(op).fmt;
            let computed_fmt = lj_fmt(op);
            assert_eq!(
                meta_fmt, computed_fmt,
                "format mismatch for op {op} ({})",
                LJ_NAMES[op as usize]
            );
        }
    }

    // ── LjInstrFlags default is NONE ─────────────────────────────────────────

    #[test]
    fn test_lj_instr_flags_default() {
        let f = LjInstrFlags::default();
        assert!(f.is_empty());
        assert_eq!(f, LjInstrFlags::NONE);
    }

    // ── BIAS constant ────────────────────────────────────────────────────────

    #[test]
    fn test_bias_constant() {
        assert_eq!(BIAS, 0x8000);
    }

    // ── Comprehensive LLIL-semantic checks ───────────────────────────────────
    // These tests verify the semantic flag assignments match LLIL lift intent.

    #[test]
    fn test_llil_semantic_mov_no_side_effects() {
        // MOV R0, R1 must have no branch/call/return flags — pure register copy.
        let w = make_lj_ad(LjOp::Mov as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(!i.flags.contains(LjInstrFlags::BRANCH));
        assert!(!i.flags.contains(LjInstrFlags::CALL));
        assert!(!i.flags.contains(LjInstrFlags::RETURN));
        assert!(i.flags.is_empty());
    }

    #[test]
    fn test_llil_semantic_not_no_side_effects() {
        let w = make_lj_ad(LjOp::Not as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.is_empty());
    }

    #[test]
    fn test_llil_semantic_len_no_side_effects() {
        let w = make_lj_ad(LjOp::Len as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.is_empty());
    }

    #[test]
    fn test_llil_semantic_unm_no_side_effects() {
        let w = make_lj_ad(LjOp::Unm as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.is_empty());
    }

    #[test]
    fn test_llil_semantic_kstr_no_side_effects() {
        let w = make_lj_ad(LjOp::Kstr as u8, 0, 5);
        let i = decode_lj_instruction(w);
        assert!(i.flags.is_empty());
    }

    #[test]
    fn test_llil_semantic_knum_no_side_effects() {
        let w = make_lj_ad(LjOp::Knum as u8, 0, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.is_empty());
    }

    #[test]
    fn test_llil_semantic_kpri_no_side_effects() {
        let w = make_lj_ad(LjOp::Kpri as u8, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.is_empty());
    }

    #[test]
    fn test_llil_semantic_kshort_no_side_effects() {
        let w = make_lj_ad_signed(LjOp::Kshort as u8, 0, 42);
        let i = decode_lj_instruction(w);
        assert!(i.flags.is_empty());
    }

    #[test]
    fn test_llil_semantic_tnew_no_side_effects() {
        let w = make_lj_ad(LjOp::Tnew as u8, 0, 0);
        let i = decode_lj_instruction(w);
        assert!(i.flags.is_empty());
    }

    #[test]
    fn test_llil_semantic_tdup_no_side_effects() {
        let w = make_lj_ad(LjOp::Tdup as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.is_empty());
    }

    // ── verify_operands for all comparison ops ────────────────────────────────

    #[test]
    fn test_cmp_op_a_b_c_fields() {
        // All ABC-format comparison ops: ISLT, ISGE, ISLE, ISGT, ISEQV, ISNEV
        for op in [
            LjOp::Islt,
            LjOp::Isge,
            LjOp::Isle,
            LjOp::Isgt,
            LjOp::Iseqv,
            LjOp::Isnev,
        ] {
            let w = make_lj_abc(op as u8, 5, 6, 7);
            let instr = decode_lj_instruction(w);
            assert_eq!(instr.a, 5, "op {op:?}");
            assert_eq!(instr.b, 6, "op {op:?}");
            assert_eq!(instr.c, 7, "op {op:?}");
        }
    }

    #[test]
    fn test_cmp_op_ad_fields() {
        // AD-format comparison ops: ISEQS, ISNES, ISEQN, ISNEN, ISEQP, ISNEP
        for op in [
            LjOp::Iseqs,
            LjOp::Isnes,
            LjOp::Iseqn,
            LjOp::Isnen,
            LjOp::Iseqp,
            LjOp::Isnep,
        ] {
            let w = make_lj_ad(op as u8, 3, 9);
            let instr = decode_lj_instruction(w);
            assert_eq!(instr.a, 3, "op {op:?}");
            assert_eq!(instr.d, 9, "op {op:?}");
        }
    }

    // ── disassemble error on short input ──────────────────────────────────────

    #[test]
    fn test_disassemble_short_input_1_byte() {
        let result = arch().disassemble(Address::new(0), &[0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_disassemble_short_input_3_bytes() {
        let result = arch().disassemble(Address::new(0), &[0x00, 0x00, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_disassemble_exact_4_bytes_valid() {
        let w = make_lj_ad(LjOp::Ret0 as u8, 0, 0);
        let result = arch().disassemble(Address::new(0), &w.to_le_bytes());
        assert!(result.is_ok());
    }

    // ── instr_count for large proto ───────────────────────────────────────────

    #[test]
    fn test_proto_instr_count_large() {
        let p = LuaJitProto {
            instructions: vec![make_lj_ad(LjOp::Ret0 as u8, 0, 0); 1000],
            ..Default::default()
        };
        assert_eq!(p.instr_count(), 1000);
    }

    // ── branches method returns correct detail ────────────────────────────────

    #[test]
    fn test_proto_branches_jmp_only() {
        let proto = LuaJitProto {
            instructions: vec![
                make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
                make_lj_ad_signed(LjOp::Jmp as u8, 0, 1),
                make_lj_ad(LjOp::Ret0 as u8, 0, 0),
            ],
            ..Default::default()
        };
        let branches = proto.branches();
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].op, LjOp::Jmp as u8);
    }

    #[test]
    fn test_proto_branches_none() {
        let proto = LuaJitProto {
            instructions: vec![
                make_lj_abc(LjOp::Addvv as u8, 0, 1, 2),
                make_lj_ad(LjOp::Ret0 as u8, 0, 0),
            ],
            ..Default::default()
        };
        // RET0 is return, not a branch with a target; JMP is what has a branch_target
        let branches = proto.branches();
        // branches() filters on branch_target.is_some() or is_branch_op
        // RET0 (op 75) is not in is_branch_op range, so 0 branches
        assert_eq!(branches.len(), 0);
    }

    // ── Encoding consistency: abc round-trip ──────────────────────────────────

    #[test]
    fn test_abc_roundtrip_all_bytes() {
        for a in [0u8, 1, 127, 255] {
            for b in [0u8, 1, 127, 255] {
                for c in [0u8, 1, 127, 255] {
                    let w = make_lj_abc(LjOp::Addvv as u8, a, b, c);
                    assert_eq!(instr_a(w), a);
                    assert_eq!(instr_b(w), b);
                    assert_eq!(instr_c(w), c);
                }
            }
        }
    }

    // ── architecture trait checks ──────────────────────────────────────────────

    #[test]
    fn test_instruction_alignment() {
        assert_eq!(arch().instruction_alignment(), 4);
    }

    #[test]
    fn test_max_instruction_length() {
        assert_eq!(arch().max_instruction_length(), 4);
    }

    #[test]
    fn test_endian_is_little() {
        assert_eq!(arch().endian(), Endian::Little);
    }

    #[test]
    fn test_pointer_size_is_8() {
        assert_eq!(arch().pointer_size(), 8);
    }

    // ── isnev / isnes / isnen / isnep negative checks ────────────────────────

    #[test]
    fn test_isnev_flags() {
        let w = make_lj_abc(LjOp::Isnev as u8, 0, 1, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_isnes_flags() {
        let w = make_lj_ad(LjOp::Isnes as u8, 0, 3);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_isnen_flags() {
        let w = make_lj_ad(LjOp::Isnen as u8, 0, 1);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_isnep_flags() {
        let w = make_lj_ad(LjOp::Isnep as u8, 0, 2);
        let i = decode_lj_instruction(w);
        assert!(i.flags.contains(LjInstrFlags::CONDITIONAL));
    }

    // ── disassemble_listing_annotated empty ────────────────────────────────────

    #[test]
    fn test_disassemble_listing_annotated_empty() {
        let s = disassemble_listing_annotated(&[], None);
        assert_eq!(s, "");
    }

    // ── proto_summary two children at same depth ──────────────────────────────

    #[test]
    fn test_proto_summary_two_siblings() {
        let c1 = LuaJitProto {
            instructions: vec![make_lj_ad(LjOp::Ret0 as u8, 0, 0)],
            ..Default::default()
        };
        let c2 = LuaJitProto {
            instructions: vec![
                make_lj_ad(LjOp::Ret0 as u8, 0, 0),
                make_lj_ad(LjOp::Ret0 as u8, 0, 0),
            ],
            ..Default::default()
        };
        let root = LuaJitProto {
            protos: vec![c1, c2],
            instructions: vec![make_lj_ad(LjOp::Ret0 as u8, 0, 0)],
            ..Default::default()
        };
        let sum = proto_summary(&root);
        assert_eq!(sum.total_protos, 2);
        assert_eq!(sum.max_depth, 1);
        assert_eq!(sum.total_instructions, 4); // 1 root + 1 + 2 children
    }

    // ── LjOp display via mnemonic ─────────────────────────────────────────────

    #[test]
    fn test_lj_op_mnemonic_all() {
        for i in 0u8..lj_names_len_u8() {
            let op = LjOp::from_u8(i).unwrap();
            assert_eq!(op.mnemonic(), LJ_NAMES[i as usize]);
        }
    }
}
