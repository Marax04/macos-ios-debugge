//! `LuaJIT` 2.x opcode table: all ~96 opcodes with operand formats, semantics,
//! branch-target computation, and a streaming instruction decoder.

use std::fmt;
use std::collections::HashMap;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Operand format
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Format of the B and C (or D) operand fields in a 4-byte `LuaJIT` instruction.
///
/// Each instruction word is laid out as: `OP(8) | A(8) | C(8) | B(8)` for ABC
/// format, or `OP(8) | A(8) | D(16)` for AD format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LjOperandFmt {
    /// `OP A B C` â€“ all three 8-bit operands used
    Abc,
    /// `OP A D` â€“ D is a 16-bit value combining C and B
    Ad,
    /// Instruction has no operands after OP (rare; e.g. FNEW stores all in A+D)
    None,
}

impl fmt::Display for LjOperandFmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Abc => write!(f, "ABC"),
            Self::Ad => write!(f, "AD"),
            Self::None => write!(f, "NONE"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Operand type annotations (for disassembly pretty-printing)
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Semantic type of an operand slot (A, B, C, or D).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandType {
    /// Destination or source slot in the register window
    Dst,
    /// Source slot
    Src,
    /// Unsigned 8-bit literal
    Lit,
    /// Numeric constant table index (kn)
    Num,
    /// GC constant table index (kgc)
    Gc,
    /// String constant (kgc sub-type)
    Str,
    /// Primitive value (nil=0, false=1, true=2)
    Pri,
    /// Upvalue index
    Uv,
    /// Signed jump displacement (relative to next PC, in instructions)
    Jump,
    /// Function prototype constant
    Func,
    /// Table constant
    Tab,
    /// Signed 16-bit literal
    Lits,
    /// Unused / reserved
    None,
}

impl fmt::Display for OperandType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Dst => "dst",
            Self::Src => "src",
            Self::Lit => "lit",
            Self::Num => "num",
            Self::Gc => "gc",
            Self::Str => "str",
            Self::Pri => "pri",
            Self::Uv => "uv",
            Self::Jump => "jmp",
            Self::Func => "func",
            Self::Tab => "tab",
            Self::Lits => "lits",
            Self::None => "-",
        };
        write!(f, "{s}")
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LjOpcode
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Every `LuaJIT` 2.x opcode as a typed enum.  Numeric values match the
/// canonical opcode byte used in `LuaJIT` 2.1 (git head as of 2024).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LjOpcode {
    // Comparison ops (all branch on false by skipping the next JMP)
    ISLT = 0x00,
    ISGE = 0x01,
    ISLE = 0x02,
    ISGT = 0x03,
    ISEQV = 0x04,
    ISNEV = 0x05,
    ISEQS = 0x06,
    ISNES = 0x07,
    ISEQN = 0x08,
    ISNEN = 0x09,
    ISEQP = 0x0A,
    ISNEP = 0x0B,
    // Unary test and copy
    ISTC = 0x0C,
    ISFC = 0x0D,
    IST  = 0x0E,
    ISF  = 0x0F,
    ISTYPE = 0x10,
    ISNUM  = 0x11,
    // Unary ops
    MOV   = 0x12,
    NOT   = 0x13,
    UNM   = 0x14,
    LEN   = 0x15,
    // Binary ops
    ADDVN = 0x16,
    SUBVN = 0x17,
    MULVN = 0x18,
    DIVVN = 0x19,
    MODVN = 0x1A,
    ADDNV = 0x1B,
    SUBNV = 0x1C,
    MULNV = 0x1D,
    DIVNV = 0x1E,
    MODNV = 0x1F,
    ADDVV = 0x20,
    SUBVV = 0x21,
    MULVV = 0x22,
    DIVVV = 0x23,
    MODVV = 0x24,
    POW   = 0x25,
    CAT   = 0x26,
    // Constant ops
    KSTR  = 0x27,
    KCDATA = 0x28,
    KSHORT = 0x29,
    KNUM  = 0x2A,
    KPRI  = 0x2B,
    KNIL  = 0x2C,
    // Upvalue and function ops
    UGET  = 0x2D,
    USETV = 0x2E,
    USETS = 0x2F,
    USETN = 0x30,
    USETP = 0x31,
    UCLO  = 0x32,
    FNEW  = 0x33,
    // Table ops
    TNEW  = 0x34,
    TDUP  = 0x35,
    GGET  = 0x36,
    GSET  = 0x37,
    TGETV = 0x38,
    TGETS = 0x39,
    TGETB = 0x3A,
    TGETR = 0x3B,
    TSETV = 0x3C,
    TSETS = 0x3D,
    TSETB = 0x3E,
    TSETM = 0x3F,
    TSETR = 0x40,
    // Calls and vararg handling
    CALLM  = 0x41,
    CALL   = 0x42,
    CALLMT = 0x43,
    CALLT  = 0x44,
    ITERC  = 0x45,
    ITERN  = 0x46,
    VARG   = 0x47,
    ISNEXT = 0x48,
    // Returns
    RETM  = 0x49,
    RET   = 0x4A,
    RET0  = 0x4B,
    RET1  = 0x4C,
    // Loops and branches
    FORI  = 0x4D,
    JFORI = 0x4E,
    FORL  = 0x4F,
    IFORL = 0x50,
    JFORL = 0x51,
    ITERL = 0x52,
    IITERL = 0x53,
    JITERL = 0x54,
    LOOP  = 0x55,
    ILOOP = 0x56,
    JLOOP = 0x57,
    JMP   = 0x58,
    // Function headers
    FUNCF = 0x59,
    IFUNCF = 0x5A,
    JFUNCF = 0x5B,
    FUNCV = 0x5C,
    IFUNCV = 0x5D,
    JFUNCV = 0x5E,
    FUNCC = 0x5F,
    FUNCCW = 0x60,
    // Unknown / out-of-range
    Unknown = 0xFF,
}

impl LjOpcode {
    /// Decode a raw opcode byte into an `LjOpcode`.  Returns `Unknown` for any
    /// byte that does not correspond to a defined opcode.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::ISLT,
            0x01 => Self::ISGE,
            0x02 => Self::ISLE,
            0x03 => Self::ISGT,
            0x04 => Self::ISEQV,
            0x05 => Self::ISNEV,
            0x06 => Self::ISEQS,
            0x07 => Self::ISNES,
            0x08 => Self::ISEQN,
            0x09 => Self::ISNEN,
            0x0A => Self::ISEQP,
            0x0B => Self::ISNEP,
            0x0C => Self::ISTC,
            0x0D => Self::ISFC,
            0x0E => Self::IST,
            0x0F => Self::ISF,
            0x10 => Self::ISTYPE,
            0x11 => Self::ISNUM,
            0x12 => Self::MOV,
            0x13 => Self::NOT,
            0x14 => Self::UNM,
            0x15 => Self::LEN,
            0x16 => Self::ADDVN,
            0x17 => Self::SUBVN,
            0x18 => Self::MULVN,
            0x19 => Self::DIVVN,
            0x1A => Self::MODVN,
            0x1B => Self::ADDNV,
            0x1C => Self::SUBNV,
            0x1D => Self::MULNV,
            0x1E => Self::DIVNV,
            0x1F => Self::MODNV,
            0x20 => Self::ADDVV,
            0x21 => Self::SUBVV,
            0x22 => Self::MULVV,
            0x23 => Self::DIVVV,
            0x24 => Self::MODVV,
            0x25 => Self::POW,
            0x26 => Self::CAT,
            0x27 => Self::KSTR,
            0x28 => Self::KCDATA,
            0x29 => Self::KSHORT,
            0x2A => Self::KNUM,
            0x2B => Self::KPRI,
            0x2C => Self::KNIL,
            0x2D => Self::UGET,
            0x2E => Self::USETV,
            0x2F => Self::USETS,
            0x30 => Self::USETN,
            0x31 => Self::USETP,
            0x32 => Self::UCLO,
            0x33 => Self::FNEW,
            0x34 => Self::TNEW,
            0x35 => Self::TDUP,
            0x36 => Self::GGET,
            0x37 => Self::GSET,
            0x38 => Self::TGETV,
            0x39 => Self::TGETS,
            0x3A => Self::TGETB,
            0x3B => Self::TGETR,
            0x3C => Self::TSETV,
            0x3D => Self::TSETS,
            0x3E => Self::TSETB,
            0x3F => Self::TSETM,
            0x40 => Self::TSETR,
            0x41 => Self::CALLM,
            0x42 => Self::CALL,
            0x43 => Self::CALLMT,
            0x44 => Self::CALLT,
            0x45 => Self::ITERC,
            0x46 => Self::ITERN,
            0x47 => Self::VARG,
            0x48 => Self::ISNEXT,
            0x49 => Self::RETM,
            0x4A => Self::RET,
            0x4B => Self::RET0,
            0x4C => Self::RET1,
            0x4D => Self::FORI,
            0x4E => Self::JFORI,
            0x4F => Self::FORL,
            0x50 => Self::IFORL,
            0x51 => Self::JFORL,
            0x52 => Self::ITERL,
            0x53 => Self::IITERL,
            0x54 => Self::JITERL,
            0x55 => Self::LOOP,
            0x56 => Self::ILOOP,
            0x57 => Self::JLOOP,
            0x58 => Self::JMP,
            0x59 => Self::FUNCF,
            0x5A => Self::IFUNCF,
            0x5B => Self::JFUNCF,
            0x5C => Self::FUNCV,
            0x5D => Self::IFUNCV,
            0x5E => Self::JFUNCV,
            0x5F => Self::FUNCC,
            0x60 => Self::FUNCCW,
            _ => Self::Unknown,
        }
    }

    /// Return the canonical mnemonic string for this opcode.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ISLT => "ISLT", Self::ISGE => "ISGE",
            Self::ISLE => "ISLE", Self::ISGT => "ISGT",
            Self::ISEQV => "ISEQV", Self::ISNEV => "ISNEV",
            Self::ISEQS => "ISEQS", Self::ISNES => "ISNES",
            Self::ISEQN => "ISEQN", Self::ISNEN => "ISNEN",
            Self::ISEQP => "ISEQP", Self::ISNEP => "ISNEP",
            Self::ISTC => "ISTC", Self::ISFC => "ISFC",
            Self::IST => "IST", Self::ISF => "ISF",
            Self::ISTYPE => "ISTYPE", Self::ISNUM => "ISNUM",
            Self::MOV => "MOV", Self::NOT => "NOT",
            Self::UNM => "UNM", Self::LEN => "LEN",
            Self::ADDVN => "ADDVN", Self::SUBVN => "SUBVN",
            Self::MULVN => "MULVN", Self::DIVVN => "DIVVN",
            Self::MODVN => "MODVN", Self::ADDNV => "ADDNV",
            Self::SUBNV => "SUBNV", Self::MULNV => "MULNV",
            Self::DIVNV => "DIVNV", Self::MODNV => "MODNV",
            Self::ADDVV => "ADDVV", Self::SUBVV => "SUBVV",
            Self::MULVV => "MULVV", Self::DIVVV => "DIVVV",
            Self::MODVV => "MODVV", Self::POW => "POW",
            Self::CAT => "CAT", Self::KSTR => "KSTR",
            Self::KCDATA => "KCDATA", Self::KSHORT => "KSHORT",
            Self::KNUM => "KNUM", Self::KPRI => "KPRI",
            Self::KNIL => "KNIL", Self::UGET => "UGET",
            Self::USETV => "USETV", Self::USETS => "USETS",
            Self::USETN => "USETN", Self::USETP => "USETP",
            Self::UCLO => "UCLO", Self::FNEW => "FNEW",
            Self::TNEW => "TNEW", Self::TDUP => "TDUP",
            Self::GGET => "GGET", Self::GSET => "GSET",
            Self::TGETV => "TGETV", Self::TGETS => "TGETS",
            Self::TGETB => "TGETB", Self::TGETR => "TGETR",
            Self::TSETV => "TSETV", Self::TSETS => "TSETS",
            Self::TSETB => "TSETB", Self::TSETM => "TSETM",
            Self::TSETR => "TSETR", Self::CALLM => "CALLM",
            Self::CALL => "CALL", Self::CALLMT => "CALLMT",
            Self::CALLT => "CALLT", Self::ITERC => "ITERC",
            Self::ITERN => "ITERN", Self::VARG => "VARG",
            Self::ISNEXT => "ISNEXT", Self::RETM => "RETM",
            Self::RET => "RET", Self::RET0 => "RET0",
            Self::RET1 => "RET1", Self::FORI => "FORI",
            Self::JFORI => "JFORI", Self::FORL => "FORL",
            Self::IFORL => "IFORL", Self::JFORL => "JFORL",
            Self::ITERL => "ITERL", Self::IITERL => "IITERL",
            Self::JITERL => "JITERL", Self::LOOP => "LOOP",
            Self::ILOOP => "ILOOP", Self::JLOOP => "JLOOP",
            Self::JMP => "JMP", Self::FUNCF => "FUNCF",
            Self::IFUNCF => "IFUNCF", Self::JFUNCF => "JFUNCF",
            Self::FUNCV => "FUNCV", Self::IFUNCV => "IFUNCV",
            Self::JFUNCV => "JFUNCV", Self::FUNCC => "FUNCC",
            Self::FUNCCW => "FUNCCW", Self::Unknown => "UNKNOWN",
        }
    }

    /// Returns true if this opcode transfers control flow (branch or jump).
    #[must_use]
    pub const fn is_branch(self) -> bool {
        matches!(self,
            Self::ISLT | Self::ISGE | Self::ISLE | Self::ISGT
            | Self::ISEQV | Self::ISNEV | Self::ISEQS | Self::ISNES
            | Self::ISEQN | Self::ISNEN | Self::ISEQP | Self::ISNEP
            | Self::ISTC | Self::ISFC | Self::IST | Self::ISF
            | Self::ISTYPE | Self::ISNUM
            | Self::JMP | Self::UCLO
            | Self::FORI | Self::JFORI
            | Self::FORL | Self::IFORL | Self::JFORL
            | Self::ITERL | Self::IITERL | Self::JITERL
            | Self::LOOP | Self::ILOOP | Self::JLOOP
            | Self::ISNEXT
        )
    }

    /// Returns true if this opcode ends a basic block unconditionally.
    #[must_use]
    pub const fn is_terminator(self) -> bool {
        matches!(self,
            Self::RET | Self::RET0 | Self::RET1 | Self::RETM
            | Self::CALLT | Self::CALLMT
        )
    }

    /// Returns true for function-header pseudo-instructions.
    #[must_use]
    pub const fn is_func_header(self) -> bool {
        matches!(self,
            Self::FUNCF | Self::IFUNCF | Self::JFUNCF
            | Self::FUNCV | Self::IFUNCV | Self::JFUNCV
            | Self::FUNCC | Self::FUNCCW
        )
    }
}

impl fmt::Display for LjOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Branch info
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Decoded branch information for instructions that carry a jump displacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LjBranch {
    /// Source PC (0-based instruction index within the proto).
    pub src_pc: u32,
    /// Signed displacement stored in the D field (bias 0x8000 removed).
    pub disp: i32,
    /// Computed absolute target PC: `src_pc + 1 + disp`.
    pub target_pc: u32,
    /// Whether the branch is unconditional (JMP/LOOP back-edges).
    pub unconditional: bool,
    /// The opcode that causes this branch.
    pub opcode: LjOpcode,
}

impl LjBranch {
    /// Compute a branch from a decoded instruction word at `pc`.
    /// `d` is the raw unsigned 16-bit D field.
    #[must_use] 
    pub fn from_raw(pc: u32, opcode: LjOpcode, d: u16) -> Self {
        // LuaJIT stores displacement with bias 0x8000: target = pc+1+(d-0x8000)
        let disp = i32::from(d) - 0x8000;
        let target_pc = u32::try_from(i64::from(pc) + 1 + i64::from(disp)).unwrap_or(u32::MAX);
        let unconditional = matches!(opcode, LjOpcode::JMP | LjOpcode::LOOP | LjOpcode::ILOOP);
        Self { src_pc: pc, disp, target_pc, unconditional, opcode }
    }
}

impl fmt::Display for LjBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{} -> PC {} (disp {}{})",
            self.opcode, self.src_pc, self.target_pc, if self.disp >= 0 { "+" } else { "" }, self.disp)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// OpcodeTable
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Per-opcode metadata stored in the static opcode table.
#[derive(Debug, Clone)]
pub struct OpcodeInfo {
    pub opcode: LjOpcode,
    pub name: &'static str,
    pub fmt: LjOperandFmt,
    pub type_a: OperandType,
    pub type_b: OperandType,
    pub type_c: OperandType,
    /// Human-readable one-line semantics description.
    pub semantics: &'static str,
}

/// Static lookup table covering all defined `LuaJIT` opcodes.  Use
/// `OpcodeTable::get(opcode)` for O(1) lookup.
pub struct OpcodeTable {
    table: HashMap<u8, OpcodeInfo>,
}

impl OpcodeTable {
    /// Build the static opcode table.
    #[must_use]
    pub fn new() -> Self {
        let entries: &[OpcodeInfo] = &[
            OpcodeInfo { opcode: LjOpcode::ISLT,   name:"ISLT",   fmt:LjOperandFmt::Abc, type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Src, semantics:"if A < D then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISGE,   name:"ISGE",   fmt:LjOperandFmt::Abc, type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Src, semantics:"if A >= D then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISLE,   name:"ISLE",   fmt:LjOperandFmt::Abc, type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Src, semantics:"if A <= D then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISGT,   name:"ISGT",   fmt:LjOperandFmt::Abc, type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Src, semantics:"if A > D then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISEQV,  name:"ISEQV",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::None, semantics:"if A == D (value) then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISNEV,  name:"ISNEV",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::None, semantics:"if A ~= D (value) then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISEQS,  name:"ISEQS",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Str,  semantics:"if A == kstr[D] then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISNES,  name:"ISNES",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Str,  semantics:"if A ~= kstr[D] then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISEQN,  name:"ISEQN",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Num,  semantics:"if A == knum[D] then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISNEN,  name:"ISNEN",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Num,  semantics:"if A ~= knum[D] then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISEQP,  name:"ISEQP",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Pri,  semantics:"if A == kpri[D] then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISNEP,  name:"ISNEP",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Pri,  semantics:"if A ~= kpri[D] then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISTC,   name:"ISTC",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Src,  semantics:"A = D; if D then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISFC,   name:"ISFC",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Src,  semantics:"A = D; if not D then skip next" },
            OpcodeInfo { opcode: LjOpcode::IST,    name:"IST",    fmt:LjOperandFmt::Ad,  type_a:OperandType::None,type_b:OperandType::None, type_c:OperandType::Src,  semantics:"if D then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISF,    name:"ISF",    fmt:LjOperandFmt::Ad,  type_a:OperandType::None,type_b:OperandType::None, type_c:OperandType::Src,  semantics:"if not D then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISTYPE, name:"ISTYPE", fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Lit,  semantics:"if type(A) == D then skip next" },
            OpcodeInfo { opcode: LjOpcode::ISNUM,  name:"ISNUM",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Lit,  semantics:"if isnumber(A) then skip next" },
            OpcodeInfo { opcode: LjOpcode::MOV,    name:"MOV",    fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Src,  semantics:"A = D" },
            OpcodeInfo { opcode: LjOpcode::NOT,    name:"NOT",    fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Src,  semantics:"A = not D" },
            OpcodeInfo { opcode: LjOpcode::UNM,    name:"UNM",    fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Src,  semantics:"A = -D" },
            OpcodeInfo { opcode: LjOpcode::LEN,    name:"LEN",    fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Src,  semantics:"A = #D" },
            OpcodeInfo { opcode: LjOpcode::ADDVN,  name:"ADDVN",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Num,  semantics:"A = B + knum[C]" },
            OpcodeInfo { opcode: LjOpcode::SUBVN,  name:"SUBVN",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Num,  semantics:"A = B - knum[C]" },
            OpcodeInfo { opcode: LjOpcode::MULVN,  name:"MULVN",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Num,  semantics:"A = B * knum[C]" },
            OpcodeInfo { opcode: LjOpcode::DIVVN,  name:"DIVVN",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Num,  semantics:"A = B / knum[C]" },
            OpcodeInfo { opcode: LjOpcode::MODVN,  name:"MODVN",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Num,  semantics:"A = B % knum[C]" },
            OpcodeInfo { opcode: LjOpcode::ADDNV,  name:"ADDNV",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Num,  semantics:"A = knum[C] + B" },
            OpcodeInfo { opcode: LjOpcode::SUBNV,  name:"SUBNV",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Num,  semantics:"A = knum[C] - B" },
            OpcodeInfo { opcode: LjOpcode::MULNV,  name:"MULNV",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Num,  semantics:"A = knum[C] * B" },
            OpcodeInfo { opcode: LjOpcode::DIVNV,  name:"DIVNV",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Num,  semantics:"A = knum[C] / B" },
            OpcodeInfo { opcode: LjOpcode::MODNV,  name:"MODNV",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Num,  semantics:"A = knum[C] % B" },
            OpcodeInfo { opcode: LjOpcode::ADDVV,  name:"ADDVV",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Src,  semantics:"A = B + C" },
            OpcodeInfo { opcode: LjOpcode::SUBVV,  name:"SUBVV",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Src,  semantics:"A = B - C" },
            OpcodeInfo { opcode: LjOpcode::MULVV,  name:"MULVV",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Src,  semantics:"A = B * C" },
            OpcodeInfo { opcode: LjOpcode::DIVVV,  name:"DIVVV",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Src,  semantics:"A = B / C" },
            OpcodeInfo { opcode: LjOpcode::MODVV,  name:"MODVV",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Src,  semantics:"A = B % C" },
            OpcodeInfo { opcode: LjOpcode::POW,    name:"POW",    fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Src,  semantics:"A = B ^ C" },
            OpcodeInfo { opcode: LjOpcode::CAT,    name:"CAT",    fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Src,  semantics:"A = B..C (concat regs B..C)" },
            OpcodeInfo { opcode: LjOpcode::KSTR,   name:"KSTR",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Str,  semantics:"A = kstr[D]" },
            OpcodeInfo { opcode: LjOpcode::KCDATA, name:"KCDATA", fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Gc,   semantics:"A = cdata[D]" },
            OpcodeInfo { opcode: LjOpcode::KSHORT, name:"KSHORT", fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Lits, semantics:"A = D (signed short literal)" },
            OpcodeInfo { opcode: LjOpcode::KNUM,   name:"KNUM",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Num,  semantics:"A = knum[D]" },
            OpcodeInfo { opcode: LjOpcode::KPRI,   name:"KPRI",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Pri,  semantics:"A = kpri[D] (nil/false/true)" },
            OpcodeInfo { opcode: LjOpcode::KNIL,   name:"KNIL",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Dst,  semantics:"A..D = nil" },
            OpcodeInfo { opcode: LjOpcode::UGET,   name:"UGET",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Uv,   semantics:"A = upvalue[D]" },
            OpcodeInfo { opcode: LjOpcode::USETV,  name:"USETV",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Uv,  type_b:OperandType::None, type_c:OperandType::Src,  semantics:"upvalue[A] = D" },
            OpcodeInfo { opcode: LjOpcode::USETS,  name:"USETS",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Uv,  type_b:OperandType::None, type_c:OperandType::Str,  semantics:"upvalue[A] = kstr[D]" },
            OpcodeInfo { opcode: LjOpcode::USETN,  name:"USETN",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Uv,  type_b:OperandType::None, type_c:OperandType::Num,  semantics:"upvalue[A] = knum[D]" },
            OpcodeInfo { opcode: LjOpcode::USETP,  name:"USETP",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Uv,  type_b:OperandType::None, type_c:OperandType::Pri,  semantics:"upvalue[A] = kpri[D]" },
            OpcodeInfo { opcode: LjOpcode::UCLO,   name:"UCLO",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"close upvalues up to A; jump D" },
            OpcodeInfo { opcode: LjOpcode::FNEW,   name:"FNEW",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Func, semantics:"A = new closure(kproto[D])" },
            OpcodeInfo { opcode: LjOpcode::TNEW,   name:"TNEW",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Lit,  semantics:"A = {} (array size B, hash size C)" },
            OpcodeInfo { opcode: LjOpcode::TDUP,   name:"TDUP",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Tab,  semantics:"A = copy of ktab[D]" },
            OpcodeInfo { opcode: LjOpcode::GGET,   name:"GGET",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Str,  semantics:"A = _G[kstr[D]]" },
            OpcodeInfo { opcode: LjOpcode::GSET,   name:"GSET",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Str,  semantics:"_G[kstr[D]] = A" },
            OpcodeInfo { opcode: LjOpcode::TGETV,  name:"TGETV",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Src,  semantics:"A = B[C]" },
            OpcodeInfo { opcode: LjOpcode::TGETS,  name:"TGETS",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Str,  semantics:"A = B[kstr[C]]" },
            OpcodeInfo { opcode: LjOpcode::TGETB,  name:"TGETB",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Lit,  semantics:"A = B[C] (byte index)" },
            OpcodeInfo { opcode: LjOpcode::TGETR,  name:"TGETR",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Src,  type_c:OperandType::Src,  semantics:"A = B[C] (raw, no metamethod)" },
            OpcodeInfo { opcode: LjOpcode::TSETV,  name:"TSETV",  fmt:LjOperandFmt::Abc, type_a:OperandType::Src, type_b:OperandType::Src,  type_c:OperandType::Src,  semantics:"B[C] = A" },
            OpcodeInfo { opcode: LjOpcode::TSETS,  name:"TSETS",  fmt:LjOperandFmt::Abc, type_a:OperandType::Src, type_b:OperandType::Src,  type_c:OperandType::Str,  semantics:"B[kstr[C]] = A" },
            OpcodeInfo { opcode: LjOpcode::TSETB,  name:"TSETB",  fmt:LjOperandFmt::Abc, type_a:OperandType::Src, type_b:OperandType::Src,  type_c:OperandType::Lit,  semantics:"B[C] = A (byte index)" },
            OpcodeInfo { opcode: LjOpcode::TSETM,  name:"TSETM",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Num,  semantics:"B[D], B[D+1], ... = A, A+1, ... (table set multi)" },
            OpcodeInfo { opcode: LjOpcode::TSETR,  name:"TSETR",  fmt:LjOperandFmt::Abc, type_a:OperandType::Src, type_b:OperandType::Src,  type_c:OperandType::Src,  semantics:"B[C] = A (raw)" },
            OpcodeInfo { opcode: LjOpcode::CALLM,  name:"CALLM",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Lit,  type_c:OperandType::Lit,  semantics:"A..A+B-1 = A(A+1..A+C+MULTRES)" },
            OpcodeInfo { opcode: LjOpcode::CALL,   name:"CALL",   fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Lit,  type_c:OperandType::Lit,  semantics:"A..A+B-1 = A(A+1..A+C-1)" },
            OpcodeInfo { opcode: LjOpcode::CALLMT, name:"CALLMT", fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Lit,  semantics:"return A(A+1..A+D+MULTRES) (tail)" },
            OpcodeInfo { opcode: LjOpcode::CALLT,  name:"CALLT",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Dst, type_b:OperandType::None, type_c:OperandType::Lit,  semantics:"return A(A+1..A+D-1) (tail)" },
            OpcodeInfo { opcode: LjOpcode::ITERC,  name:"ITERC",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Lit,  type_c:OperandType::Lit,  semantics:"A, A+1, A+2 = A-3, A-2, A-1; A..A+B-1 = A(A+1, A+2)" },
            OpcodeInfo { opcode: LjOpcode::ITERN,  name:"ITERN",  fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Lit,  type_c:OperandType::Lit,  semantics:"specialized ITERC for next()" },
            OpcodeInfo { opcode: LjOpcode::VARG,   name:"VARG",   fmt:LjOperandFmt::Abc, type_a:OperandType::Dst, type_b:OperandType::Lit,  type_c:OperandType::Lit,  semantics:"A..A+B-1 = vararg[C..]" },
            OpcodeInfo { opcode: LjOpcode::ISNEXT, name:"ISNEXT", fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"verify next() iterator; jump D if invalid" },
            OpcodeInfo { opcode: LjOpcode::RETM,   name:"RETM",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Lit,  semantics:"return A..A+D+MULTRES-1" },
            OpcodeInfo { opcode: LjOpcode::RET,    name:"RET",    fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Lit,  semantics:"return A..A+D-2" },
            OpcodeInfo { opcode: LjOpcode::RET0,   name:"RET0",   fmt:LjOperandFmt::Ad,  type_a:OperandType::None,type_b:OperandType::None, type_c:OperandType::None, semantics:"return (no values)" },
            OpcodeInfo { opcode: LjOpcode::RET1,   name:"RET1",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::None, semantics:"return A" },
            OpcodeInfo { opcode: LjOpcode::FORI,   name:"FORI",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"for init: check; jump D if done" },
            OpcodeInfo { opcode: LjOpcode::JFORI,  name:"JFORI",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"jit compiled FORI" },
            OpcodeInfo { opcode: LjOpcode::FORL,   name:"FORL",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"for step: step + check; loop D" },
            OpcodeInfo { opcode: LjOpcode::IFORL,  name:"IFORL",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"integer FORL" },
            OpcodeInfo { opcode: LjOpcode::JFORL,  name:"JFORL",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"jit compiled FORL" },
            OpcodeInfo { opcode: LjOpcode::ITERL,  name:"ITERL",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"generic for loop step" },
            OpcodeInfo { opcode: LjOpcode::IITERL, name:"IITERL", fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"integer ITERL" },
            OpcodeInfo { opcode: LjOpcode::JITERL, name:"JITERL", fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"jit compiled ITERL" },
            OpcodeInfo { opcode: LjOpcode::LOOP,   name:"LOOP",   fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"loop body header; back-edge D" },
            OpcodeInfo { opcode: LjOpcode::ILOOP,  name:"ILOOP",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"integer LOOP" },
            OpcodeInfo { opcode: LjOpcode::JLOOP,  name:"JLOOP",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"jit compiled LOOP" },
            OpcodeInfo { opcode: LjOpcode::JMP,    name:"JMP",    fmt:LjOperandFmt::Ad,  type_a:OperandType::Src, type_b:OperandType::None, type_c:OperandType::Jump, semantics:"PC += D-BIAS (unconditional jump)" },
            OpcodeInfo { opcode: LjOpcode::FUNCF,  name:"FUNCF",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Lit, type_b:OperandType::None, type_c:OperandType::None, semantics:"fixed-arg function header (framesize A)" },
            OpcodeInfo { opcode: LjOpcode::IFUNCF, name:"IFUNCF", fmt:LjOperandFmt::Ad,  type_a:OperandType::Lit, type_b:OperandType::None, type_c:OperandType::None, semantics:"integer optimized FUNCF" },
            OpcodeInfo { opcode: LjOpcode::JFUNCF, name:"JFUNCF", fmt:LjOperandFmt::Ad,  type_a:OperandType::Lit, type_b:OperandType::None, type_c:OperandType::None, semantics:"jit compiled FUNCF" },
            OpcodeInfo { opcode: LjOpcode::FUNCV,  name:"FUNCV",  fmt:LjOperandFmt::Ad,  type_a:OperandType::Lit, type_b:OperandType::None, type_c:OperandType::None, semantics:"vararg function header" },
            OpcodeInfo { opcode: LjOpcode::IFUNCV, name:"IFUNCV", fmt:LjOperandFmt::Ad,  type_a:OperandType::Lit, type_b:OperandType::None, type_c:OperandType::None, semantics:"integer optimized FUNCV" },
            OpcodeInfo { opcode: LjOpcode::JFUNCV, name:"JFUNCV", fmt:LjOperandFmt::Ad,  type_a:OperandType::Lit, type_b:OperandType::None, type_c:OperandType::None, semantics:"jit compiled FUNCV" },
            OpcodeInfo { opcode: LjOpcode::FUNCC,  name:"FUNCC",  fmt:LjOperandFmt::None,type_a:OperandType::None,type_b:OperandType::None, type_c:OperandType::None, semantics:"C function header" },
            OpcodeInfo { opcode: LjOpcode::FUNCCW, name:"FUNCCW", fmt:LjOperandFmt::None,type_a:OperandType::None,type_b:OperandType::None, type_c:OperandType::None, semantics:"wrapped C function header" },
        ];
        let mut table = HashMap::with_capacity(entries.len());
        for e in entries {
            table.insert(e.opcode as u8, e.clone());
        }
        Self { table }
    }

    /// Look up metadata for a given opcode.
    #[must_use]
    pub fn get(&self, op: LjOpcode) -> Option<&OpcodeInfo> {
        self.table.get(&(op as u8))
    }

    /// Look up metadata by raw byte.
    #[must_use]
    pub fn get_by_byte(&self, b: u8) -> Option<&OpcodeInfo> {
        self.table.get(&b)
    }

    /// Return all opcodes in opcode-byte order.
    #[must_use]
    pub fn all_sorted(&self) -> Vec<&OpcodeInfo> {
        let mut v: Vec<&OpcodeInfo> = self.table.values().collect();
        v.sort_by_key(|i| i.opcode as u8);
        v
    }
}

impl Default for OpcodeTable {
    fn default() -> Self { Self::new() }
}

impl fmt::Debug for OpcodeTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpcodeTable({} entries)", self.table.len())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LjInstrDecoder â€“ streaming decoder
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A fully decoded `LuaJIT` instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInstr {
    /// 0-based PC index within the proto's instruction array.
    pub pc: u32,
    /// Raw 32-bit instruction word (little-endian).
    pub raw: u32,
    /// Decoded opcode.
    pub opcode: LjOpcode,
    /// A field (bits 8..15).
    pub a: u8,
    /// B field (bits 24..31).
    pub b: u8,
    /// C field (bits 16..23).
    pub c: u8,
    /// D field (bits 16..31, combining C and B as a 16-bit value).
    pub d: u16,
    /// Branch info, if this instruction is a branch/jump.
    pub branch: Option<LjBranch>,
}

impl DecodedInstr {
    /// Decode one 4-byte little-endian instruction word at `pc`.
    #[must_use]
    pub fn decode(pc: u32, word: u32) -> Self {
        let op_byte = u8::try_from(word & 0xFF).unwrap_or(u8::MAX);
        let a       = u8::try_from((word >> 8) & 0xFF).unwrap_or(u8::MAX);
        let c       = u8::try_from((word >> 16) & 0xFF).unwrap_or(u8::MAX);
        let b       = u8::try_from((word >> 24) & 0xFF).unwrap_or(u8::MAX);
        let d       = u16::try_from((word >> 16) & 0xFFFF).unwrap_or(u16::MAX);
        let opcode  = LjOpcode::from_byte(op_byte);
        let branch  = if opcode.is_branch() && matches!(opcode,
            LjOpcode::JMP | LjOpcode::UCLO
            | LjOpcode::FORI | LjOpcode::JFORI
            | LjOpcode::FORL | LjOpcode::IFORL | LjOpcode::JFORL
            | LjOpcode::ITERL | LjOpcode::IITERL | LjOpcode::JITERL
            | LjOpcode::LOOP | LjOpcode::ILOOP | LjOpcode::JLOOP
            | LjOpcode::ISNEXT
        ) {
            Some(LjBranch::from_raw(pc, opcode, d))
        } else {
            None
        };
        Self { pc, raw: word, opcode, a, b, c, d, branch }
    }

    /// Signed interpretation of the D field (for KSHORT).
    #[must_use]
    pub const fn d_signed(self) -> i16 {
        self.d as i16
    }
}

impl fmt::Display for DecodedInstr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:>4}  {:>8}  A={:3} B={:3} C={:3} D={:5}",
            self.pc, self.opcode.name(), self.a, self.b, self.c, self.d)?;
        if let Some(ref br) = self.branch {
            write!(f, "  -> PC {}", br.target_pc)?;
        }
        Ok(())
    }
}

/// Streaming decoder that walks a slice of raw instruction words and emits
/// `DecodedInstr` values, optionally collecting all branch targets.
#[derive(Debug)]
pub struct LjInstrDecoder<'a> {
    words: &'a [u32],
    pc: u32,
    branches: Vec<LjBranch>,
    table: OpcodeTable,
}

impl<'a> LjInstrDecoder<'a> {
    /// Create a new decoder for the given slice of instruction words.
    #[must_use]
    pub fn new(words: &'a [u32]) -> Self {
        Self {
            words,
            pc: 0,
            branches: Vec::new(),
            table: OpcodeTable::new(),
        }
    }

    /// Decode all instructions and return them.  Also populates the branch
    /// list accessible via `branches()`.
    pub fn decode_all(&mut self) -> Vec<DecodedInstr> {
        self.pc = 0;
        self.branches.clear();
        let mut out = Vec::with_capacity(self.words.len());
        for &word in self.words {
            let instr = DecodedInstr::decode(self.pc, word);
            if let Some(ref br) = instr.branch {
                self.branches.push(br.clone());
            }
            out.push(instr);
            self.pc += 1;
        }
        out
    }

    /// All branch records collected during the last `decode_all` call.
    #[must_use]
    pub fn branches(&self) -> &[LjBranch] {
        &self.branches
    }

    /// Unique set of branch target PCs collected during the last decode.
    #[must_use]
    pub fn branch_targets(&self) -> Vec<u32> {
        let mut targets: Vec<u32> = self.branches.iter().map(|b| b.target_pc).collect();
        targets.sort_unstable();
        targets.dedup();
        targets
    }

    /// Look up opcode info for a raw byte using the embedded table.
    #[must_use]
    pub fn info_for(&self, b: u8) -> Option<&OpcodeInfo> {
        self.table.get_by_byte(b)
    }

    /// Disassemble to a multi-line string.
    #[must_use]
    pub fn disassemble(&mut self) -> String {
        use std::fmt::Write as _;
        let instrs = self.decode_all();
        let mut out = String::with_capacity(instrs.len() * 40);
        for instr in &instrs {
            writeln!(out, "{instr}").unwrap();
        }
        out
    }
}

