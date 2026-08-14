//! `bytecode_format` â€” `LuaJIT` 2.0/2.1 bytecode format types.
//!
//! This module defines the wire-level structures for `LuaJIT` `.luac` files:
//! file header layout, prototype chain parsing, instruction word layout,
//! the complete 97-opcode `OpMode` table, upvalue descriptor encoding, and
//! debug-info block layout.
//!
//! # Bytecode file layout
//! ```text
//! [magic: 3 bytes]  \x1bLJ
//! [version: 1 byte] 0x01 = LJ2.0, 0x02 = LJ2.1
//! [flags: ULEB128]  LjFlags bitset
//! [debug_name_len: ULEB128]  (omitted when STRIP flag is set)
//! [debug_name: bytes]        (omitted when STRIP flag is set)
//! [proto*]  zero-terminated chain of ULEB128-length-prefixed prototypes
//! [0x00]    end-of-chain marker
//! ```
//!
//! # Instruction encoding
//! Each instruction is a 32-bit word stored in host byte order:
//! ```text
//! bits  7-0 : OP   (opcode)
//! bits 15-8 : A    (first register operand)
//! bits 23-16: C    (low byte of combined D field; or second register in BC format)
//! bits 31-24: B    (high byte of combined D field; or third register in BC format)
//! ```
//!
//! `D = (B << 8) | C` is the 16-bit combined operand.
//! Signed jump offset: `J = D âˆ’ 0x8000`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{LjFlags, LjHeader, LjLoaderError, LjProtoFlags, LjVersion, read_uleb128};

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// OpMode â€” operand encoding mode for each opcode
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Operand encoding mode for a `LuaJIT` opcode.
///
/// Each mode describes how the A, B, C, D, and J fields are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpMode {
    /// `A`, `B`, `C` are independent 8-bit register/constant indices.
    ABC,
    /// `A` and 16-bit `D` (unsigned).
    AD,
    /// `A` and 16-bit signed jump offset `J = D âˆ’ 0x8000`.
    AJ,
    /// No operands (pseudo-instruction / internal JIT hint).
    None,
}

impl fmt::Display for OpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ABC => write!(f, "ABC"),
            Self::AD => write!(f, "AD"),
            Self::AJ => write!(f, "AJ"),
            Self::None => write!(f, "NONE"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// OpInfo â€” static descriptor for one opcode
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Static descriptor for a single `LuaJIT` opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpInfo {
    /// Opcode byte value (0x00â€“0x60).
    pub opcode: u8,
    /// ASCII mnemonic.
    pub mnemonic: &'static str,
    /// Operand encoding mode.
    pub mode: OpMode,
    /// True if the instruction can transfer control to a non-sequential PC.
    pub is_branch: bool,
    /// True if the instruction is a function-call variant.
    pub is_call: bool,
    /// True if the instruction returns from the function.
    pub is_return: bool,
    /// True if the instruction is a loop header or back-edge.
    pub is_loop: bool,
    /// True if this is a comparison/predicate that conditionally skips the
    /// following JMP instruction.
    pub is_compare: bool,
}

impl OpInfo {
    const fn new(
        opcode: u8,
        mnemonic: &'static str,
        mode: OpMode,
        is_branch: bool,
        is_call: bool,
        is_return: bool,
        is_loop: bool,
        is_compare: bool,
    ) -> Self {
        Self {
            opcode,
            mnemonic,
            mode,
            is_branch,
            is_call,
            is_return,
            is_loop,
            is_compare,
        }
    }

    /// Look up an `OpInfo` by opcode byte.  Returns `None` for unknown opcodes.
    #[must_use]
    pub fn lookup(opcode: u8) -> Option<&'static Self> {
        LJ_OP_TABLE.get(opcode as usize)
    }
}

impl fmt::Display for OpInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x} {:<8} mode={}",
            self.opcode, self.mnemonic, self.mode
        )
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LJ_OP_TABLE â€” full 97-entry static opcode table
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Complete `LuaJIT` 2.0/2.1 opcode descriptor table (97 entries, 0x00â€“0x60).
pub static LJ_OP_TABLE: &[OpInfo] = &[
    // â”€â”€ Comparisons (skip-next JMP on false) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // op   mnemonic   mode        branch  call   ret    loop   compare
    OpInfo::new(0x00, "ISLT", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x01, "ISGE", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x02, "ISLE", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x03, "ISGT", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x04, "ISEQV", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x05, "ISNEV", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x06, "ISEQS", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x07, "ISNES", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x08, "ISEQN", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x09, "ISNEN", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x0A, "ISEQP", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x0B, "ISNEP", OpMode::AD, false, false, false, false, true),
    // â”€â”€ Unary test + copy â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x0C, "ISTC", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x0D, "ISFC", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x0E, "IST", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x0F, "ISF", OpMode::AD, false, false, false, false, true),
    OpInfo::new(0x10, "ISTYPE", OpMode::AD, false, false, false, false, true), // LJ2.1+
    OpInfo::new(0x11, "ISNUM", OpMode::AD, false, false, false, false, true),  // LJ2.1+
    // â”€â”€ Unary ops â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x12, "MOV", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x13, "NOT", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x14, "UNM", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x15, "LEN", OpMode::AD, false, false, false, false, false),
    // â”€â”€ Binary arith: reg op num-const â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(
        0x16,
        "ADDVN",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x17,
        "SUBVN",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x18,
        "MULVN",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x19,
        "DIVVN",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x1A,
        "MODVN",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    // â”€â”€ Binary arith: num-const op reg â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(
        0x1B,
        "ADDNV",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x1C,
        "SUBNV",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x1D,
        "MULNV",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x1E,
        "DIVNV",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x1F,
        "MODNV",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    // â”€â”€ Binary arith: reg op reg â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(
        0x20,
        "ADDVV",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x21,
        "SUBVV",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x22,
        "MULVV",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x23,
        "DIVVV",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x24,
        "MODVV",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(0x25, "POW", OpMode::ABC, false, false, false, false, false),
    OpInfo::new(0x26, "CAT", OpMode::ABC, false, false, false, false, false),
    // â”€â”€ Constant loads â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x27, "KSTR", OpMode::AD, false, false, false, false, false),
    OpInfo::new(
        0x28,
        "KCDATA",
        OpMode::AD,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x29,
        "KSHORT",
        OpMode::AD,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(0x2A, "KNUM", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x2B, "KPRI", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x2C, "KNIL", OpMode::AD, false, false, false, false, false),
    // â”€â”€ Upvalue ops â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x2D, "UGET", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x2E, "USETV", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x2F, "USETS", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x30, "USETN", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x31, "USETP", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x32, "UCLO", OpMode::AJ, true, false, false, false, false),
    OpInfo::new(0x33, "FNEW", OpMode::AD, false, false, false, false, false),
    // â”€â”€ Table ops â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x34, "TNEW", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x35, "TDUP", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x36, "GGET", OpMode::AD, false, false, false, false, false),
    OpInfo::new(0x37, "GSET", OpMode::AD, false, false, false, false, false),
    OpInfo::new(
        0x38,
        "TGETV",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x39,
        "TGETS",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x3A,
        "TGETB",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(0x3B, "TGETM", OpMode::AD, false, false, false, false, false),
    OpInfo::new(
        0x3C,
        "TSETV",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x3D,
        "TSETS",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x3E,
        "TSETB",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(0x3F, "TSETM", OpMode::AD, false, false, false, false, false),
    OpInfo::new(
        0x40,
        "TSETR",
        OpMode::ABC,
        false,
        false,
        false,
        false,
        false,
    ), // LJ2.1
    // â”€â”€ Calls â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x41, "CALLM", OpMode::ABC, false, true, false, false, false),
    OpInfo::new(0x42, "CALL", OpMode::ABC, false, true, false, false, false),
    OpInfo::new(0x43, "CALLMT", OpMode::AD, true, true, false, false, false),
    OpInfo::new(0x44, "CALLT", OpMode::AD, true, true, false, false, false),
    // â”€â”€ Iterator calls â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x45, "ITERC", OpMode::ABC, false, true, false, false, false),
    OpInfo::new(0x46, "ITERN", OpMode::ABC, false, true, false, false, false),
    // â”€â”€ Vararg / iterator guards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x47, "VARG", OpMode::ABC, false, false, false, false, false),
    OpInfo::new(0x48, "ISNEXT", OpMode::AJ, true, false, false, false, false),
    // â”€â”€ Returns â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x49, "RETM", OpMode::AD, true, false, true, false, false),
    OpInfo::new(0x4A, "RET", OpMode::AD, true, false, true, false, false),
    OpInfo::new(0x4B, "RET0", OpMode::AD, true, false, true, false, false),
    OpInfo::new(0x4C, "RET1", OpMode::AD, true, false, true, false, false),
    // â”€â”€ Numeric for-loop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x4D, "FORI", OpMode::AJ, true, false, false, true, false),
    OpInfo::new(0x4E, "JFORI", OpMode::AJ, true, false, false, true, false),
    OpInfo::new(0x4F, "FORL", OpMode::AJ, true, false, false, true, false),
    OpInfo::new(0x50, "IFORL", OpMode::AJ, true, false, false, true, false),
    OpInfo::new(0x51, "JFORL", OpMode::AD, true, false, false, true, false),
    // â”€â”€ Iterator loop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x52, "ITERL", OpMode::AJ, true, false, false, true, false),
    OpInfo::new(0x53, "IITERL", OpMode::AJ, true, false, false, true, false),
    OpInfo::new(0x54, "JITERL", OpMode::AD, true, false, false, true, false),
    // â”€â”€ Generic loop hints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x55, "LOOP", OpMode::AJ, false, false, false, true, false),
    OpInfo::new(0x56, "ILOOP", OpMode::AJ, false, false, false, true, false),
    OpInfo::new(0x57, "JLOOP", OpMode::AD, true, false, false, true, false),
    // â”€â”€ Jump + function headers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OpInfo::new(0x58, "JMP", OpMode::AJ, true, false, false, false, false),
    OpInfo::new(0x59, "FUNCF", OpMode::AD, false, false, false, false, false),
    OpInfo::new(
        0x5A,
        "IFUNCF",
        OpMode::AD,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x5B,
        "JFUNCF",
        OpMode::AD,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(0x5C, "FUNCV", OpMode::AD, false, false, false, false, false),
    OpInfo::new(
        0x5D,
        "IFUNCV",
        OpMode::AD,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(
        0x5E,
        "JFUNCV",
        OpMode::AD,
        false,
        false,
        false,
        false,
        false,
    ),
    OpInfo::new(0x5F, "FUNCC", OpMode::AD, false, false, false, false, false),
    OpInfo::new(
        0x60,
        "FUNCCW",
        OpMode::AD,
        false,
        false,
        false,
        false,
        false,
    ),
];

/// Return the number of entries in the opcode table (should be 97).
#[must_use]
pub fn opcode_table_len() -> usize {
    LJ_OP_TABLE.len()
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// FileHeader â€” parsed file-level header
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Parsed `LuaJIT` file header (re-exported for convenience; mirrors `LjHeader`).
///
/// The on-disk encoding is:
/// ```text
/// [0x1b, b'L', b'J']   magic
/// [version byte]        0x01=LJ2.0, 0x02=LJ2.1
/// [flags: ULEB128]      see LjFlags
/// [name_len: ULEB128]   omitted if STRIP
/// [name bytes]          omitted if STRIP
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHeader {
    pub version: u8,
    pub flags_raw: u8,
    pub is_big_endian: bool,
    pub is_stripped: bool,
    pub has_ffi: bool,
    pub has_fr2: bool,
    pub debug_name: Option<String>,
}

impl FileHeader {
    /// Parse a `FileHeader` from `data`, returning `(header, bytes_consumed)`.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), LjLoaderError> {
        let (hdr, pos) = LjHeader::parse(data)?;
        let f = hdr.flags;
        Ok((
            Self {
                version: hdr.version.as_byte(),
                flags_raw: f.bits(),
                is_big_endian: f.contains(LjFlags::BE),
                is_stripped: f.contains(LjFlags::STRIP),
                has_ffi: f.contains(LjFlags::FFI),
                has_fr2: f.contains(LjFlags::FR2),
                debug_name: hdr.debug_name,
            },
            pos,
        ))
    }

    /// Decoded `LjVersion`.
    #[must_use]
    pub const fn version(&self) -> LjVersion {
        LjVersion::from_byte(self.version)
    }
}

impl fmt::Display for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FileHeader {{ version={} stripped={} be={} ffi={} fr2={} name={:?} }}",
            self.version(),
            self.is_stripped,
            self.is_big_endian,
            self.has_ffi,
            self.has_fr2,
            self.debug_name
        )
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ProtoHeaderRaw â€” raw fields from the prototype header
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Wire-level prototype header, extracted before any bytecode is decoded.
///
/// On-disk layout (after the ULEB128 proto-size prefix):
/// ```text
/// [proto_flags: u8]
/// [num_params: u8]
/// [frame_size: u8]
/// [num_upvalues: u8]
/// [num_kgc: ULEB128]
/// [num_kn:  ULEB128]
/// [bc_count: ULEB128]
/// [dbg_info_size: ULEB128]
/// [first_line: ULEB128]   (only if dbg_info_size > 0)
/// [num_lines:  ULEB128]   (only if dbg_info_size > 0)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtoHeaderRaw {
    pub flags: u8,
    pub num_params: u8,
    pub frame_size: u8,
    pub num_upvalues: u8,
    pub num_kgc: u32,
    pub num_kn: u32,
    pub bc_count: u32,
    pub dbg_info_size: u32,
    pub first_line: u32,
    pub num_lines: u32,
}

impl ProtoHeaderRaw {
    /// Parse the header fields from `pd` (the proto data slice, *after* the size prefix).
    /// Returns `(header, bytes_consumed)`.
    #[must_use]
    pub fn parse(pd: &[u8]) -> Option<(Self, usize)> {
        if pd.len() < 4 {
            return None;
        }
        let flags = pd[0];
        let num_params = pd[1];
        let frame_size = pd[2];
        let num_upvalues = pd[3];
        let mut p = 4usize;
        let (num_kgc, np) = read_uleb128(pd, p)?;
        p = np;
        let (num_kn, np) = read_uleb128(pd, p)?;
        p = np;
        let (bc_count, np) = read_uleb128(pd, p)?;
        p = np;
        let (dbg_info_size, np) = read_uleb128(pd, p)?;
        p = np;
        let (first_line, np) = if dbg_info_size > 0 {
            read_uleb128(pd, p)?
        } else {
            (0, p)
        };
        p = np;
        let (num_lines, np) = if dbg_info_size > 0 {
            read_uleb128(pd, p)?
        } else {
            (0, p)
        };
        p = np;
        Some((
            Self {
                flags,
                num_params,
                frame_size,
                num_upvalues,
                num_kgc: num_kgc as u32,
                num_kn: num_kn as u32,
                bc_count: bc_count as u32,
                dbg_info_size: dbg_info_size as u32,
                first_line: first_line as u32,
                num_lines: num_lines as u32,
            },
            p,
        ))
    }

    /// Decode the `LjProtoFlags` bitset.
    #[must_use]
    pub const fn proto_flags(&self) -> LjProtoFlags {
        LjProtoFlags::from_bits_truncate(self.flags)
    }

    /// True if the `VARARG` flag is set.
    #[must_use]
    pub const fn is_vararg(&self) -> bool {
        self.proto_flags().contains(LjProtoFlags::VARARG)
    }

    /// True if the prototype has attached debug information.
    #[must_use]
    pub const fn has_debug(&self) -> bool {
        self.dbg_info_size > 0
    }

    /// Bytes occupied by the bytecode section (`bc_count` Ã— 4).
    #[must_use]
    pub const fn bc_byte_len(&self) -> usize {
        self.bc_count as usize * 4
    }

    /// Bytes occupied by the upvalue descriptor section (`num_upvalues` Ã— 2).
    #[must_use]
    pub const fn uv_byte_len(&self) -> usize {
        self.num_upvalues as usize * 2
    }
}

impl fmt::Display for ProtoHeaderRaw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProtoHeader {{ params={} frame={} uvs={} kgc={} kn={} bc={} dbg={} lines={}..{} }}",
            self.num_params,
            self.frame_size,
            self.num_upvalues,
            self.num_kgc,
            self.num_kn,
            self.bc_count,
            self.dbg_info_size,
            self.first_line,
            self.first_line + self.num_lines
        )
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// UpvalDescriptor â€” raw upvalue descriptor encoding
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Raw 16-bit upvalue descriptor as stored in the binary.
///
/// Bit layout:
/// ```text
/// bit  15   : 1 = closed over a stack local (on-stack ref)
///             0 = closed over a parent upvalue
/// bits 14-9 : reserved / flags (immutable in bit 8 of high byte)
/// bits  7-0 : slot index
///              if bit 15 = 1: stack-slot index of the captured local
///              if bit 15 = 0: parent upvalue index
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpvalDescriptor {
    /// The raw 16-bit word.
    pub raw: u16,
}

impl UpvalDescriptor {
    /// Construct from a raw 2-byte LE value.
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        Self { raw }
    }

    /// Parse from two bytes (little-endian).
    #[must_use]
    pub const fn from_bytes(lo: u8, hi: u8) -> Self {
        Self {
            raw: u16::from_le_bytes([lo, hi]),
        }
    }

    /// Slot index (stack-slot or parent upvalue index depending on `is_stack`).
    #[must_use]
    pub const fn slot(&self) -> u8 {
        (self.raw & 0xFF) as u8
    }

    /// True if the upvalue is closed over a stack-local of the enclosing function.
    #[must_use]
    pub const fn is_stack(&self) -> bool {
        (self.raw >> 15) != 0
    }

    /// True if the upvalue is closed over a parent upvalue (not a local).
    #[must_use]
    pub const fn is_parent_uv(&self) -> bool {
        !self.is_stack()
    }

    /// True if the immutable bit (bit 8 of the high byte, i.e. bit 8 of the u16)
    /// is set.  This is set by `LuaJIT` when the upvalue is never assigned to after
    /// the initial capture.
    #[must_use]
    pub const fn is_immutable(&self) -> bool {
        (self.raw >> 8) & 0x01 != 0
    }

    /// Parse a slice of `n` upvalue descriptors from `data[offset..]`.
    /// Returns `(descriptors, new_offset)` or `None` on truncation.
    #[must_use]
    pub fn parse_n(data: &[u8], mut offset: usize, n: usize) -> Option<(Vec<Self>, usize)> {
        // `n` is caller-supplied and ultimately comes from the bytecode file;
        // each descriptor is 2 bytes, so the remaining input bounds the count.
        let mut out = Vec::with_capacity(n.min(data.len().saturating_sub(offset) / 2));
        for _ in 0..n {
            if offset + 2 > data.len() {
                return None;
            }
            let raw = u16::from_le_bytes([data[offset], data[offset + 1]]);
            out.push(Self::from_raw(raw));
            offset += 2;
        }
        Some((out, offset))
    }
}

impl fmt::Display for UpvalDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Upval {{ slot={} stack={} immutable={} raw={:#06x} }}",
            self.slot(),
            self.is_stack(),
            self.is_immutable(),
            self.raw
        )
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// InstrWord â€” 32-bit instruction word decoder
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Thin wrapper around a 32-bit `LuaJIT` instruction word providing field
/// accessors independent from `LjInstr` (which lives in `lib.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstrWord(pub u32);

impl InstrWord {
    /// Opcode byte (bits 7â€“0).
    #[must_use]
    pub const fn op(self) -> u8 {
        (self.0 & 0xFF) as u8
    }

    /// A operand (bits 15â€“8).
    #[must_use]
    pub const fn a(self) -> u8 {
        ((self.0 >> 8) & 0xFF) as u8
    }

    /// C operand â€” low byte of the D field (bits 23â€“16).
    #[must_use]
    pub const fn c(self) -> u8 {
        ((self.0 >> 16) & 0xFF) as u8
    }

    /// B operand â€” high byte of the D field (bits 31â€“24).
    #[must_use]
    pub const fn b(self) -> u8 {
        ((self.0 >> 24) & 0xFF) as u8
    }

    /// D operand â€” unsigned 16-bit (bits 31â€“16).
    #[must_use]
    pub const fn d(self) -> u16 {
        ((self.0 >> 16) & 0xFFFF) as u16
    }

    /// Signed jump offset (D âˆ’ 0x8000).
    #[must_use]
    pub const fn j(self) -> i32 {
        self.d() as i32 - 0x8000
    }

    /// Mnemonic from the static table, or `"???"`.
    #[must_use]
    pub fn mnemonic(self) -> &'static str {
        OpInfo::lookup(self.op())
            .map_or("???", |i| i.mnemonic)
    }

    /// `OpMode` from the static table, or `OpMode::None`.
    #[must_use]
    pub fn mode(self) -> OpMode {
        OpInfo::lookup(self.op())
            .map_or(OpMode::None, |i| i.mode)
    }

    /// Static `OpInfo` descriptor for this instruction's opcode.
    #[must_use]
    pub fn info(self) -> Option<&'static OpInfo> {
        OpInfo::lookup(self.op())
    }

    /// Parse a bytecode stream of `count` instructions from `data[offset..]`.
    /// Returns `(instructions, new_offset)` or `None` on truncation.
    #[must_use]
    pub fn parse_stream(
        data: &[u8],
        mut offset: usize,
        count: usize,
        big_endian: bool,
    ) -> Option<(Vec<Self>, usize)> {
        // `count * 4` would wrap for an adversarial count, letting the bounds
        // check below pass and the indexing panic afterwards.
        let byte_len = count.checked_mul(4)?;
        if offset.checked_add(byte_len).is_none_or(|end| end > data.len()) {
            return None;
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let bytes: [u8; 4] = data[offset..offset + 4].try_into().ok()?;
            let word = if big_endian {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            };
            out.push(Self(word));
            offset += 4;
        }
        Some((out, offset))
    }
}

impl fmt::Display for InstrWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<8} A={} B={} C={} D={}",
            self.mnemonic(),
            self.a(),
            self.b(),
            self.c(),
            self.d()
        )
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// DebugInfoLayout â€” byte-width calculation for debug line table
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Describes how the per-instruction line-number array is encoded.
///
/// `LuaJIT` chooses the narrowest integer width that can represent all offsets:
/// - `num_lines < 256`   â†’ 1 byte per instruction (offset from `first_line`)
/// - `num_lines < 65536` â†’ 2 bytes per instruction
/// - otherwise           â†’ 4 bytes per instruction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LineTableWidth {
    /// 1-byte offsets from `first_line`.
    Byte,
    /// 2-byte little-endian offsets.
    Short,
    /// 4-byte little-endian offsets.
    Int,
}

impl LineTableWidth {
    /// Determine width from the `num_lines` field in the prototype header.
    #[must_use]
    pub const fn from_num_lines(num_lines: u32) -> Self {
        if num_lines < 256 {
            Self::Byte
        } else if num_lines < 65536 {
            Self::Short
        } else {
            Self::Int
        }
    }

    /// Bytes per instruction.
    #[must_use]
    pub const fn bytes_per_instr(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Short => 2,
            Self::Int => 4,
        }
    }

    /// Decode the offset at `data[pos]` and return `(line_offset, new_pos)`.
    #[must_use]
    pub fn read(self, data: &[u8], pos: usize) -> Option<(u32, usize)> {
        match self {
            Self::Byte => {
                if pos >= data.len() {
                    return None;
                }
                Some((u32::from(data[pos]), pos + 1))
            }
            Self::Short => {
                if pos + 2 > data.len() {
                    return None;
                }
                let v = u32::from(u16::from_le_bytes([data[pos], data[pos + 1]]));
                Some((v, pos + 2))
            }
            Self::Int => {
                if pos + 4 > data.len() {
                    return None;
                }
                let v = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?);
                Some((v, pos + 4))
            }
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ProtoChainParser â€” iteratively parse all prototypes in a bytecode dump
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Iterating parser that walks the linear prototype chain in a `LuaJIT` dump.
///
/// `LuaJIT` dumps prototypes in reverse dependency order (innermost first) and
/// the chain terminates with a zero-length ULEB128 proto-size.
///
/// ```text
/// while pos < data.len() {
///     proto_size = ULEB128;
///     if proto_size == 0 { break; }
///     proto_data = data[pos .. pos + proto_size];
///     pos += proto_size;
/// }
/// ```
pub struct ProtoChainParser<'a> {
    data: &'a [u8],
    pos: usize,
    big_endian: bool,
    done: bool,
}

impl<'a> ProtoChainParser<'a> {
    /// Create a new parser positioned at `start_offset` (past the file header).
    #[must_use]
    pub const fn new(data: &'a [u8], start_offset: usize, big_endian: bool) -> Self {
        Self {
            data,
            pos: start_offset,
            big_endian,
            done: false,
        }
    }

    /// Current byte offset into `data`.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Returns the next raw prototype data slice and its absolute offset, or
    /// `None` at the end of the chain.
    pub fn next_raw(&mut self) -> Option<(&'a [u8], usize)> {
        if self.done || self.pos >= self.data.len() {
            self.done = true;
            return None;
        }
        let (proto_size, new_pos) = read_uleb128(self.data, self.pos)?;
        if proto_size == 0 {
            self.done = true;
            self.pos = new_pos;
            return None;
        }
        let start = new_pos;
        let proto_size_usize = usize::try_from(proto_size).unwrap_or(usize::MAX);
        let end = start.saturating_add(proto_size_usize);
        if end > self.data.len() {
            self.done = true;
            return None;
        }
        self.pos = end;
        Some((&self.data[start..end], start))
    }

    /// Whether big-endian decoding is active.
    #[must_use]
    pub const fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// Drain the chain into a `Vec` of raw slices (allocates).
    #[must_use]
    pub fn collect_raw(mut self) -> Vec<(&'a [u8], usize)> {
        let mut out = Vec::new();
        while let Some(x) = self.next_raw() {
            out.push(x);
        }
        out
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_table_length() {
        assert_eq!(LJ_OP_TABLE.len(), 97, "expected 97 entries (0x00..=0x60)");
    }

    #[test]
    fn test_opcode_islt_fields() {
        let info = OpInfo::lookup(0x00).unwrap();
        assert_eq!(info.mnemonic, "ISLT");
        assert_eq!(info.mode, OpMode::AD);
        assert!(info.is_compare);
        assert!(!info.is_call);
    }

    #[test]
    fn test_opcode_call_fields() {
        let info = OpInfo::lookup(0x42).unwrap();
        assert_eq!(info.mnemonic, "CALL");
        assert!(info.is_call);
        assert!(!info.is_return);
    }

    #[test]
    fn test_opcode_ret0_fields() {
        let info = OpInfo::lookup(0x4B).unwrap();
        assert_eq!(info.mnemonic, "RET0");
        assert!(info.is_return);
        assert!(info.is_branch);
    }

    #[test]
    fn test_opcode_jmp_mode_aj() {
        let info = OpInfo::lookup(0x58).unwrap();
        assert_eq!(info.mode, OpMode::AJ);
        assert!(info.is_branch);
    }

    #[test]
    fn test_opcode_fori_is_loop() {
        let info = OpInfo::lookup(0x4D).unwrap();
        assert!(info.is_loop);
    }

    #[test]
    fn test_opcode_unknown_none() {
        assert!(OpInfo::lookup(0xFF).is_none());
    }

    #[test]
    fn test_opmode_display() {
        assert_eq!(OpMode::ABC.to_string(), "ABC");
        assert_eq!(OpMode::AJ.to_string(), "AJ");
        assert_eq!(OpMode::None.to_string(), "NONE");
    }

    #[test]
    fn test_instr_word_fields() {
        // word = 0x0304_0142  â†’  op=0x42 a=0x01 c=0x04 b=0x03
        let w = InstrWord(0x0304_0142);
        assert_eq!(w.op(), 0x42);
        assert_eq!(w.a(), 0x01);
        assert_eq!(w.c(), 0x04);
        assert_eq!(w.b(), 0x03);
        assert_eq!(w.d(), 0x0304);
        assert_eq!(w.mnemonic(), "CALL");
    }

    #[test]
    fn test_instr_word_jump_offset() {
        // D = 0x8001 â†’ J = 1
        let w = InstrWord((0x8001u32 << 16) | 0x58);
        assert_eq!(w.j(), 1);
    }

    #[test]
    fn test_instr_word_jump_offset_negative() {
        // D = 0x7FFF â†’ J = -1
        let w = InstrWord((0x7FFF_u32 << 16) | 0x58);
        assert_eq!(w.j(), -1);
    }

    #[test]
    fn test_instr_word_parse_stream_le() {
        // Two RET0 (0x4B) instructions in LE bytes
        let data: &[u8] = &[0x4B, 0x00, 0x00, 0x00, 0x4B, 0x00, 0x00, 0x00];
        let (instrs, end) = InstrWord::parse_stream(data, 0, 2, false).unwrap();
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].op(), 0x4B);
        assert_eq!(end, 8);
    }

    #[test]
    fn test_instr_word_parse_stream_truncated() {
        let data: &[u8] = &[0x4B, 0x00]; // only 2 bytes, need 4
        assert!(InstrWord::parse_stream(data, 0, 1, false).is_none());
    }

    #[test]
    fn test_upval_descriptor_stack() {
        let d = UpvalDescriptor::from_raw(0x8005);
        assert!(d.is_stack());
        assert!(!d.is_parent_uv());
        assert_eq!(d.slot(), 5);
    }

    #[test]
    fn test_upval_descriptor_parent() {
        let d = UpvalDescriptor::from_raw(0x0003);
        assert!(!d.is_stack());
        assert!(d.is_parent_uv());
        assert_eq!(d.slot(), 3);
    }

    #[test]
    fn test_upval_descriptor_immutable() {
        // bit 8 set = immutable
        let d = UpvalDescriptor::from_raw(0x0100);
        assert!(d.is_immutable());
    }

    #[test]
    fn test_upval_descriptor_parse_n() {
        let data: &[u8] = &[0x05, 0x80, 0x03, 0x00]; // [0x8005, 0x0003]
        let (descs, end) = UpvalDescriptor::parse_n(data, 0, 2).unwrap();
        assert_eq!(descs.len(), 2);
        assert!(descs[0].is_stack());
        assert!(!descs[1].is_stack());
        assert_eq!(end, 4);
    }

    #[test]
    fn test_proto_header_raw_parse() {
        // flags=0x02 (VARARG), params=1, frame=4, uvs=1
        // num_kgc=1, num_kn=0, bc=2, dbg=0
        let pd: &[u8] = &[
            0x02, 0x01, 0x04, 0x01, // flags, params, frame, uvs
            0x01, 0x00, 0x02, 0x00, // kgc=1, kn=0, bc=2, dbg=0
        ];
        let (hdr, pos) = ProtoHeaderRaw::parse(pd).unwrap();
        assert_eq!(hdr.flags, 0x02);
        assert_eq!(hdr.num_params, 1);
        assert_eq!(hdr.frame_size, 4);
        assert_eq!(hdr.num_upvalues, 1);
        assert_eq!(hdr.num_kgc, 1);
        assert_eq!(hdr.num_kn, 0);
        assert_eq!(hdr.bc_count, 2);
        assert_eq!(hdr.dbg_info_size, 0);
        assert!(hdr.is_vararg());
        assert!(!hdr.has_debug());
        assert_eq!(hdr.bc_byte_len(), 8);
        assert_eq!(hdr.uv_byte_len(), 2);
        assert_eq!(pos, 8);
    }

    #[test]
    fn test_line_table_width_selection() {
        assert_eq!(LineTableWidth::from_num_lines(100), LineTableWidth::Byte);
        assert_eq!(LineTableWidth::from_num_lines(256), LineTableWidth::Short);
        assert_eq!(LineTableWidth::from_num_lines(65536), LineTableWidth::Int);
    }

    #[test]
    fn test_line_table_width_read_byte() {
        let data = &[42u8];
        let (v, pos) = LineTableWidth::Byte.read(data, 0).unwrap();
        assert_eq!(v, 42);
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_line_table_width_read_short() {
        let data = &[0x01u8, 0x00]; // LE 1
        let (v, pos) = LineTableWidth::Short.read(data, 0).unwrap();
        assert_eq!(v, 1);
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_file_header_parse_stripped() {
        let data: &[u8] = &[0x1B, b'L', b'J', 0x02, 0x02]; // LJ2.1 STRIP
        let (fh, _) = FileHeader::parse(data).unwrap();
        assert!(fh.is_stripped);
        assert!(!fh.is_big_endian);
        assert_eq!(fh.version().as_byte(), 2);
    }

    #[test]
    fn test_proto_chain_parser_empty_chain() {
        // Only the terminator byte
        let data: &[u8] = &[0x00];
        let mut parser = ProtoChainParser::new(data, 0, false);
        assert!(parser.next_raw().is_none());
    }

    #[test]
    fn test_proto_chain_parser_one_proto() {
        // size=4, four bytes of proto data, then terminator
        let data: &[u8] = &[0x04, 0x01, 0x02, 0x03, 0x04, 0x00];
        let mut parser = ProtoChainParser::new(data, 0, false);
        let (slice, start) = parser.next_raw().unwrap();
        assert_eq!(slice, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(start, 1);
        assert!(parser.next_raw().is_none());
    }

    #[test]
    fn test_opcode_table_all_indices_match() {
        for (i, entry) in LJ_OP_TABLE.iter().enumerate() {
            assert_eq!(entry.opcode as usize, i, "mismatch at index {i}");
        }
    }
}
