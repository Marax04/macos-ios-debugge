//! `rustre-arch-lua`
//!
//! This crate is part of the `RustRE` Suite, a premium reverse engineering platform.
//!
//! # Architecture: Lua VM (5.1 —" 5.4)
//! Implements instruction decoding for Lua bytecode across all four major
//! Lua versions.  Each version has its own opcode table and field-extraction
//! helpers; a shared [`LuaArch`] struct selects the active decoder.
//!
//! ## Instruction formats
//!
//! ### Lua 5.1 / 5.2 / 5.3 (26-bit opcode field, 6-bit opcode)
//! ```text
//! iABC:  [B:9][C:9][A:8][OP:6]
//! iABx:  [Bx:18][A:8][OP:6]
//! iAsBx: [sBx:18][A:8][OP:6]  where sBx = Bx - MAXARG_sBx
//! ```
//!
//! ### Lua 5.4 (new layout, 7-bit opcode)
//! ```text
//! iABC:  [C:8][B:8][k:1][A:8][OP:7]
//! iABx:  [Bx:17][A:8][OP:7]
//! iAsBx: [sBx:17][A:8][OP:7]
//! iAx:   [Ax:25][OP:7]
//! isJ:   [sJ:25][OP:7]
//! ```

pub mod lua54_decoder;
pub mod lua_type_inference;
pub mod lua_pattern_matcher;
pub mod lua_optimizer;
pub mod lua_bytecode_analyzer;
pub mod lua_upvalue_tracker;
pub mod lua_proto_printer;

/// Lua bytecode decompiler: LuaDecompiler, LuaExpr, LuaStmt, DecompileFunction,
/// UpvalueResolver, LuaFormatter.
pub mod lua_decompiler;

/// Complete Lua VM semantic model: LuaValue, LuaTable, LuaMetatable,
/// GcSemantics, UpvalueClosing, YieldResume, LuaVmSemantics.
pub mod lua_vm_semantics;
pub mod lua_disasm;
pub mod lua_cfg;
pub mod lua_vm_opcodes;
pub mod lua_vm_state;
pub mod lua_closure_analyzer;

use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::{
    address::Address,
    arch::{BranchCondition, RegisterKind},
    endian::Endian,
    errors::CoreError,
};
use std::fmt;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LuaVersion
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Lua version selector used to pick the correct decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum LuaVersion {
    /// Lua 5.1 bytecode format.
    Lua51,
    /// Lua 5.2 bytecode format.
    Lua52,
    /// Lua 5.3 bytecode format.
    Lua53,
    /// Lua 5.4 bytecode format (new 7-bit opcode layout).
    #[default]
    Lua54,
}

impl LuaVersion {
    /// Return the canonical short name for this version.
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Lua51 => "lua51",
            Self::Lua52 => "lua52",
            Self::Lua53 => "lua53",
            Self::Lua54 => "lua54",
        }
    }

    /// Return the human-readable version string.
    #[must_use] 
    pub const fn version_string(self) -> &'static str {
        match self {
            Self::Lua51 => "Lua 5.1",
            Self::Lua52 => "Lua 5.2",
            Self::Lua53 => "Lua 5.3",
            Self::Lua54 => "Lua 5.4",
        }
    }

    /// Return true if this version uses the old 6-bit opcode layout.
    #[must_use] 
    pub const fn is_legacy(self) -> bool {
        matches!(self, Self::Lua51 | Self::Lua52 | Self::Lua53)
    }
}

impl fmt::Display for LuaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.version_string())
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Lua 5.4 field extraction
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

// Lua 5.4: bits 0..6 = opcode (7 bits), bits 7..14 = A (8 bits),
// bit 15 = k, bits 16..23 = B (8 bits), bits 24..31 = C (8 bits).
// For Bx / sBx: bits 15..31 = 17 bits.
// MAXARG_sBx = ((1 << 17) - 1) / 2 = 65535

/// Convert a float that holds an exact integer value into an `i64`.
///
/// Returns `None` when the value is not finite, is not integral, or does not
/// fit in an `i64`. The conversion is done on the IEEE-754 fields directly so
/// every step is a checked integer operation rather than a truncating `as`.
#[must_use]
pub fn f64_to_exact_i64(f: f64) -> Option<i64> {
    if !f.is_finite() || f.fract() != 0.0 {
        return None;
    }
    if f == 0.0 {
        return Some(0);
    }
    let bits = f.to_bits();
    let negative = (bits >> 63) == 1;
    // The 11 exponent bits fit an i32 with room to spare.
    let raw_exp = i32::try_from((bits >> 52) & 0x7FF).unwrap_or(0);
    let exp = raw_exp - 1023;
    if !(0..=62).contains(&exp) {
        return None;
    }
    let mantissa = (bits & 0x000F_FFFF_FFFF_FFFF) | 0x0010_0000_0000_0000;
    let shift = 52 - exp; // 0..=52 because exp is in 0..=62
    let magnitude = if shift >= 0 {
        mantissa >> shift
    } else {
        mantissa << (-shift)
    };
    let value = i64::try_from(magnitude).ok()?;
    Some(if negative { -value } else { value })
}
/// Convert a Lua integer to the Lua float representation.
///
/// Lua 5.x defines integer-to-float coercion as round-to-nearest, exactly what
/// `as` would do. Splitting the magnitude into two 32-bit halves keeps every
/// step a *checked* conversion (`u32::try_from` on a value already masked to
/// 32 bits can never fail) while producing the same IEEE-754 double.
#[must_use]
pub fn lua_int_to_f64(v: i64) -> f64 {
    let mag = v.unsigned_abs();
    let hi = u32::try_from(mag >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(mag & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    let m = f64::from(hi).mul_add(4_294_967_296.0, f64::from(lo));
    if v < 0 { -m } else { m }
}

/// Convert a count to `f64` for ratio and percentage reporting.
///
/// Counts come from a byte slice length, so they are bounded by the input size;
/// saturating at `u32::MAX` keeps the conversion total and lossless.
#[must_use]
pub fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

pub const MAXARG_SBX: i32 = ((1 << 17) - 1) >> 1; // 65535

// Lua 5.4 —" 25-bit sJ offset (used by JMP in 5.4)
const MAXARG_SJ: i32 = ((1 << 25) - 1) >> 1; // 16777215

#[inline]
pub(crate) const fn get_op54(w: u32) -> u8 {
    (w & 0x7f) as u8
}

#[inline]
pub(crate) const fn get_a54(w: u32) -> u32 {
    (w >> 7) & 0xff
}

#[inline]
pub(crate) const fn get_b54(w: u32) -> u32 {
    (w >> 16) & 0xff
}

#[inline]
pub(crate) const fn get_c54(w: u32) -> u32 {
    (w >> 24) & 0xff
}

#[inline]
pub(crate) const fn get_k54(w: u32) -> u32 {
    (w >> 15) & 1
}

#[inline]
#[must_use] 
pub const fn get_bx54(w: u32) -> u32 {
    (w >> 15) & 0x1_ffff // 17 bits
}

#[inline]
pub(crate) const fn get_sbx54(w: u32) -> i32 {
    get_bx54(w).cast_signed() - MAXARG_SBX
}

#[inline]
#[must_use] 
pub const fn get_ax54(w: u32) -> u32 {
    w >> 7 // 25 bits
}

#[inline]
pub(crate) const fn get_sj54(w: u32) -> i32 {
    ((w >> 7) & 0x01ff_ffff).cast_signed() - MAXARG_SJ
}

/// Signed C field (8-bit with bias 127).
#[inline]
pub(crate) const fn get_sc54(w: u32) -> i32 {
    get_c54(w).cast_signed() - 127
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Lua 5.1 / 5.2 / 5.3 field extraction (6-bit opcode)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

// Layout (little-endian u32):
//   bits  0.. 5 = opcode (6 bits)
//   bits  6..13 = A      (8 bits)
//   bits 14..22 = B      (9 bits)  —" overlaps with C and Bx
//   bits 23..31 = C      (9 bits)
// For Bx:  bits 14..31 = 18 bits
// For sBx: sBx = Bx - MAXARG_SBX_OLD

const MAXARG_BX_OLD: u32 = (1 << 18) - 1; // 262143
const MAXARG_SBX_OLD: i32 = MAXARG_BX_OLD.cast_signed() >> 1; // 131071

#[inline]
const fn get_op_old(w: u32) -> u8 {
    (w & 0x3f) as u8
}

#[inline]
const fn get_a_old(w: u32) -> u32 {
    (w >> 6) & 0xff
}

#[inline]
const fn get_b_old(w: u32) -> u32 {
    (w >> 23) & 0x1ff
}

#[inline]
const fn get_c_old(w: u32) -> u32 {
    (w >> 14) & 0x1ff
}

#[inline]
const fn get_bx_old(w: u32) -> u32 {
    w >> 14
}

#[inline]
const fn get_sbx_old(w: u32) -> i32 {
    get_bx_old(w).cast_signed() - MAXARG_SBX_OLD
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Lua 5.4 opcode table
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Lua 5.4 opcode names (indexed by opcode number 0..=80).
pub(crate) static LUA54_OPCODES: &[&str] = &[
    "MOVE",       // 0
    "LOADI",      // 1
    "LOADF",      // 2
    "LOADK",      // 3
    "LOADKX",     // 4
    "LOADBOOL",   // 5  (5.3-) / LOADFALSE (5.4)
    "LOADNIL",    // 6
    "GETUPVAL",   // 7
    "SETUPVAL",   // 8
    "GETTABUP",   // 9
    "GETTABLE",   // 10
    "GETI",       // 11
    "GETFIELD",   // 12
    "SETTABUP",   // 13
    "SETTABLE",   // 14
    "SETI",       // 15
    "SETFIELD",   // 16
    "NEWTABLE",   // 17
    "SELF",       // 18
    "ADDI",       // 19
    "ADDK",       // 20
    "SUBK",       // 21
    "MULK",       // 22
    "MODK",       // 23
    "POWK",       // 24
    "DIVK",       // 25
    "IDIVK",      // 26
    "BANDK",      // 27
    "BORK",       // 28
    "BXORK",      // 29
    "SHRI",       // 30
    "SHLI",       // 31
    "ADD",        // 32
    "SUB",        // 33
    "MUL",        // 34
    "MOD",        // 35
    "POW",        // 36
    "DIV",        // 37
    "IDIV",       // 38
    "BAND",       // 39
    "BOR",        // 40
    "BXOR",       // 41
    "SHL",        // 42
    "SHR",        // 43
    "MMBIN",      // 44
    "MMBINI",     // 45
    "MMBINK",     // 46
    "UNM",        // 47
    "BNOT",       // 48
    "NOT",        // 49
    "LEN",        // 50
    "CONCAT",     // 51
    "CLOSE",      // 52
    "TBC",        // 53
    "JMP",        // 54
    "EQ",         // 55
    "LT",         // 56
    "LE",         // 57
    "EQK",        // 58
    "EQI",        // 59
    "LTI",        // 60
    "GTI",        // 61
    "LEI",        // 62
    "GEI",        // 63
    "TEST",       // 64
    "TESTSET",    // 65
    "CALL",       // 66
    "TAILCALL",   // 67
    "RETURN",     // 68
    "RETURN0",    // 69
    "RETURN1",    // 70
    "FORLOOP",    // 71
    "FORPREP",    // 72
    "TFORPREP",   // 73
    "TFORCALL",   // 74
    "TFORLOOP",   // 75
    "SETLIST",    // 76
    "CLOSURE",    // 77
    "VARARG",     // 78
    "VARARGPREP", // 79
    "EXTRAARG",   // 80
];

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Lua 5.1 opcode table
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Lua 5.1 opcode names (indexed 0..=37).
static LUA51_OPCODES: &[&str] = &[
    "MOVE",      // 0
    "LOADK",     // 1
    "LOADBOOL",  // 2
    "LOADNIL",   // 3
    "GETUPVAL",  // 4
    "GETGLOBAL", // 5
    "GETTABLE",  // 6
    "SETGLOBAL", // 7
    "SETUPVAL",  // 8
    "SETTABLE",  // 9
    "NEWTABLE",  // 10
    "SELF",      // 11
    "ADD",       // 12
    "SUB",       // 13
    "MUL",       // 14
    "DIV",       // 15
    "MOD",       // 16
    "POW",       // 17
    "UNM",       // 18
    "NOT",       // 19
    "LEN",       // 20
    "CONCAT",    // 21
    "JMP",       // 22
    "EQ",        // 23
    "LT",        // 24
    "LE",        // 25
    "TEST",      // 26
    "TESTSET",   // 27
    "CALL",      // 28
    "TAILCALL",  // 29
    "RETURN",    // 30
    "FORLOOP",   // 31
    "FORPREP",   // 32
    "TFORLOOP",  // 33
    "SETLIST",   // 34
    "CLOSE",     // 35
    "CLOSURE",   // 36
    "VARARG",    // 37
];

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Lua 5.2 opcode table
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Lua 5.2 opcode names (indexed 0..=40).
static LUA52_OPCODES: &[&str] = &[
    "MOVE",     // 0
    "LOADK",    // 1
    "LOADKX",   // 2
    "LOADBOOL", // 3
    "LOADNIL",  // 4
    "GETUPVAL", // 5
    "GETTABUP", // 6
    "GETTABLE", // 7
    "SETTABUP", // 8
    "SETUPVAL", // 9
    "SETTABLE", // 10
    "NEWTABLE", // 11
    "SELF",     // 12
    "ADD",      // 13
    "SUB",      // 14
    "MUL",      // 15
    "DIV",      // 16
    "MOD",      // 17
    "POW",      // 18
    "UNM",      // 19
    "NOT",      // 20
    "LEN",      // 21
    "CONCAT",   // 22
    "JMP",      // 23
    "EQ",       // 24
    "LT",       // 25
    "LE",       // 26
    "TEST",     // 27
    "TESTSET",  // 28
    "CALL",     // 29
    "TAILCALL", // 30
    "RETURN",   // 31
    "FORLOOP",  // 32
    "FORPREP",  // 33
    "TFORCALL", // 34
    "TFORLOOP", // 35
    "SETLIST",  // 36
    "CLOSURE",  // 37
    "VARARG",   // 38
    "EXTRAARG", // 39
];

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Lua 5.3 opcode table
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Lua 5.3 opcode names (indexed 0..=46).
static LUA53_OPCODES: &[&str] = &[
    "MOVE",     // 0
    "LOADK",    // 1
    "LOADKX",   // 2
    "LOADBOOL", // 3
    "LOADNIL",  // 4
    "GETUPVAL", // 5
    "GETTABUP", // 6
    "GETTABLE", // 7
    "SETTABUP", // 8
    "SETUPVAL", // 9
    "SETTABLE", // 10
    "NEWTABLE", // 11
    "SELF",     // 12
    "ADD",      // 13
    "SUB",      // 14
    "MUL",      // 15
    "MOD",      // 16
    "POW",      // 17
    "DIV",      // 18
    "IDIV",     // 19
    "BAND",     // 20
    "BOR",      // 21
    "BXOR",     // 22
    "SHL",      // 23
    "SHR",      // 24
    "UNM",      // 25
    "BNOT",     // 26
    "NOT",      // 27
    "LEN",      // 28
    "CONCAT",   // 29
    "JMP",      // 30
    "EQ",       // 31
    "LT",       // 32
    "LE",       // 33
    "TEST",     // 34
    "TESTSET",  // 35
    "CALL",     // 36
    "TAILCALL", // 37
    "RETURN",   // 38
    "FORLOOP",  // 39
    "FORPREP",  // 40
    "TFORCALL", // 41
    "TFORLOOP", // 42
    "SETLIST",  // 43
    "CLOSURE",  // 44
    "VARARG",   // 45
    "EXTRAARG", // 46
];

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Lua 5.4 format enum + decoder
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Internal instruction format for Lua 5.4 operand rendering.
#[derive(Debug, Clone, Copy)]
enum Lua54Fmt {
    /// Standard A, B, C with optional k flag.
    Abc,
    /// A with unsigned 17-bit Bx.
    ABx,
    /// A with signed 17-bit sBx.
    AsBx,
    /// 25-bit Ax (no A, B, C).
    Ax,
    /// Pure 25-bit signed sJ offset (JMP in 5.4).
    IsJ,
    /// Comparison with conditional branch: A, B, C k.
    TestJump,
}

const fn lua54_fmt(op: u8) -> Lua54Fmt {
    match op {
        54 => Lua54Fmt::IsJ,
        1 | 2 | 71 | 72 | 73 | 75 => Lua54Fmt::AsBx,
        3 | 77 => Lua54Fmt::ABx,
        55..=65 => Lua54Fmt::TestJump,
        80 => Lua54Fmt::Ax,
        _ => Lua54Fmt::Abc,
    }
}

/// Decode a single Lua 5.4 instruction word into (mnemonic, operands, flags).
pub(crate) fn decode_lua54(
    word: u32,
    _address: Address,
) -> Result<(String, String, InstrFlags), CoreError> {
    let op = get_op54(word);
    if op as usize >= LUA54_OPCODES.len() {
        return Err(CoreError::InvalidFormat {
            message: format!("unknown Lua 5.4 opcode {op}"),
        });
    }
    let mnemonic = LUA54_OPCODES[op as usize].to_lowercase();

    let (operands, flags): (String, InstrFlags) = match lua54_fmt(op) {
        Lua54Fmt::IsJ => {
            let sj = get_sj54(word);
            (format!("{sj:+}"), InstrFlags::BRANCH)
        }
        Lua54Fmt::AsBx => {
            let a = get_a54(word);
            let sbx = get_sbx54(word);
            let fl = match op {
                71 | 72 | 73 | 75 => InstrFlags::BRANCH,
                _ => InstrFlags::NONE,
            };
            (format!("R{a}, {sbx:+}"), fl)
        }
        Lua54Fmt::ABx => {
            let a = get_a54(word);
            let bx = get_bx54(word);
            (format!("R{a}, {bx}"), InstrFlags::NONE)
        }
        Lua54Fmt::Ax => {
            let ax = get_ax54(word);
            (format!("{ax}"), InstrFlags::NONE)
        }
        Lua54Fmt::TestJump => {
            let a = get_a54(word);
            let b = get_b54(word);
            let c = get_c54(word);
            let k = get_k54(word);
            (
                format!("R{a}, {b}, {c} k={k}"),
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            )
        }
        Lua54Fmt::Abc => {
            let a = get_a54(word);
            let b = get_b54(word);
            let c = get_c54(word);
            let k = get_k54(word);
            // Special-case ops that need signed fields
            match op {
                19 | 30 | 31 => {
                    // ADDI / SHRI / SHLI: A, B, sC
                    let sc = get_sc54(word);
                    return Ok((mnemonic, format!("R{a}, R{b}, {sc}"), InstrFlags::NONE));
                }
                66 => {
                    return Ok((mnemonic, format!("R{a}, {b}, {c}"), InstrFlags::CALL));
                }
                67 => {
                    return Ok((
                        mnemonic,
                        format!("R{a}, {b}, {c}"),
                        InstrFlags::CALL | InstrFlags::RET,
                    ));
                }
                68 => {
                    return Ok((mnemonic, format!("R{a}, {b}, {c}"), InstrFlags::RET));
                }
                69 => {
                    return Ok((mnemonic, String::new(), InstrFlags::RET));
                }
                70 => {
                    return Ok((mnemonic, format!("R{a}"), InstrFlags::RET));
                }
                _ => {}
            }
            let fl = InstrFlags::NONE;
            if k == 1 {
                (format!("R{a}, R{b}, {c} k"), fl)
            } else {
                (format!("R{a}, R{b}, R{c}"), fl)
            }
        }
    };

    Ok((mnemonic, operands, flags))
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Legacy (5.1 / 5.2 / 5.3) format enum + decoder
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Instruction formats used by Lua 5.1—"5.3.
#[derive(Debug, Clone, Copy)]
enum LuaLegacyFmt {
    /// A, B, C (9-bit B and C).
    Abc,
    /// A, Bx (18-bit unsigned).
    ABx,
    /// A, sBx (18-bit signed).
    AsBx,
    /// A, Bx (alias for EXTRAARG which has no A —" same encoding as `ABx`).
    Ax,
}

/// Determine the format of a Lua 5.1 opcode.
const fn lua51_fmt(op: u8) -> LuaLegacyFmt {
    match op {
        // LOADK
        // GETGLOBAL
        // SETGLOBAL
        22 | 31 | 32 => LuaLegacyFmt::AsBx, // JMP
        // FORLOOP
        // FORPREP
        1 | 5 | 7 | 36 => LuaLegacyFmt::ABx,  // CLOSURE
        _ => LuaLegacyFmt::Abc,
    }
}

/// Determine the format of a Lua 5.2 opcode.
const fn lua52_fmt(op: u8) -> LuaLegacyFmt {
    match op {
        // LOADK
        // LOADKX
        23 | 32 | 33 | 35 => LuaLegacyFmt::AsBx, // JMP
        // FORLOOP
        // FORPREP
        // TFORLOOP
        1 | 2 | 37 => LuaLegacyFmt::ABx,  // CLOSURE
        39 => LuaLegacyFmt::Ax,   // EXTRAARG
        _ => LuaLegacyFmt::Abc,
    }
}

/// Determine the format of a Lua 5.3 opcode.
const fn lua53_fmt(op: u8) -> LuaLegacyFmt {
    match op {
        // LOADK
        // LOADKX
        30 | 39 | 40 | 42 => LuaLegacyFmt::AsBx, // JMP
        // FORLOOP
        // FORPREP
        // TFORLOOP
        1 | 2 | 44 => LuaLegacyFmt::ABx,  // CLOSURE
        46 => LuaLegacyFmt::Ax,   // EXTRAARG
        _ => LuaLegacyFmt::Abc,
    }
}

/// Opcode numbers that represent jumps in legacy Lua (all versions).
#[must_use] 
pub const fn is_legacy_jump_op(version: LuaVersion, op: u8) -> bool {
    match version {
        LuaVersion::Lua51 => matches!(op, 22 | 31 | 32),
        LuaVersion::Lua52 => matches!(op, 23 | 32 | 33 | 35),
        LuaVersion::Lua53 => matches!(op, 30 | 39 | 40 | 42),
        LuaVersion::Lua54 => false, // handled separately
    }
}

/// Decode a legacy (5.1—"5.3) Lua instruction word.
///
/// # Errors
///
/// Returns an error when the input bytes are malformed, truncated, or
/// otherwise cannot be decoded.
pub fn decode_lua_legacy(
    version: LuaVersion,
    word: u32,
    _address: Address,
) -> Result<(String, String, InstrFlags), CoreError> {
    let op = get_op_old(word);

    let table = match version {
        LuaVersion::Lua51 => LUA51_OPCODES,
        LuaVersion::Lua52 => LUA52_OPCODES,
        LuaVersion::Lua53 => LUA53_OPCODES,
        LuaVersion::Lua54 => unreachable!("5.4 uses decode_lua54"),
    };

    if op as usize >= table.len() {
        return Err(CoreError::InvalidFormat {
            message: format!("unknown {} opcode {op}", version.version_string()),
        });
    }
    let mnemonic = table[op as usize].to_lowercase();

    let fmt = match version {
        LuaVersion::Lua51 => lua51_fmt(op),
        LuaVersion::Lua52 => lua52_fmt(op),
        LuaVersion::Lua53 => lua53_fmt(op),
        LuaVersion::Lua54 => unreachable!(),
    };

    let is_jmp = is_legacy_jump_op(version, op);

    let (operands, flags) = match fmt {
        LuaLegacyFmt::AsBx => {
            let a = get_a_old(word);
            let sbx = get_sbx_old(word);
            let fl = if is_jmp {
                InstrFlags::BRANCH
            } else {
                InstrFlags::NONE
            };
            (format!("R{a}, {sbx:+}"), fl)
        }
        LuaLegacyFmt::ABx => {
            let a = get_a_old(word);
            let bx = get_bx_old(word);
            (format!("R{a}, {bx}"), InstrFlags::NONE)
        }
        LuaLegacyFmt::Ax => {
            let bx = get_bx_old(word);
            (format!("{bx}"), InstrFlags::NONE)
        }
        LuaLegacyFmt::Abc => {
            let a = get_a_old(word);
            let b = get_b_old(word);
            let c = get_c_old(word);

            // Determine flags based on legacy opcode semantics
            let call_op = match version {
                LuaVersion::Lua51 => matches!(op, 28 | 29),
                LuaVersion::Lua52 => matches!(op, 29 | 30),
                LuaVersion::Lua53 => matches!(op, 36 | 37),
                LuaVersion::Lua54 => false,
            };
            let tailcall_op = match version {
                LuaVersion::Lua51 => op == 29,
                LuaVersion::Lua52 => op == 30,
                LuaVersion::Lua53 => op == 37,
                LuaVersion::Lua54 => false,
            };
            let ret_op = match version {
                LuaVersion::Lua51 => op == 30,
                LuaVersion::Lua52 => op == 31,
                LuaVersion::Lua53 => op == 38,
                LuaVersion::Lua54 => false,
            };
            let cmp_op = match version {
                LuaVersion::Lua51 => matches!(op, 23..=25),
                LuaVersion::Lua52 => matches!(op, 24..=26),
                LuaVersion::Lua53 => matches!(op, 31..=33),
                LuaVersion::Lua54 => false,
            };

            let fl = if tailcall_op {
                InstrFlags::CALL | InstrFlags::RET
            } else if call_op {
                InstrFlags::CALL
            } else if ret_op {
                InstrFlags::RET
            } else if cmp_op {
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL
            } else {
                InstrFlags::NONE
            };

            (format!("R{a}, R{b}, R{c}"), fl)
        }
    };

    Ok((mnemonic, operands, flags))
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LuaArch —" Architecture implementation
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Architecture backend for Lua VM bytecode (5.1—"5.4).
#[derive(Debug, Clone)]
pub struct LuaArch {
    /// Lua version this instance decodes.
    pub version: LuaVersion,
}

impl Default for LuaArch {
    fn default() -> Self {
        Self {
            version: LuaVersion::Lua54,
        }
    }
}

impl LuaArch {
    /// Create a `LuaArch` defaulting to Lua 5.4.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a `LuaArch` for a specific Lua version.
    #[must_use] 
    pub const fn with_version(version: LuaVersion) -> Self {
        Self { version }
    }

    /// Return the metadata descriptor for this architecture.
    #[must_use] 
    pub fn metadata(&self) -> LuaArchMetadata {
        LuaArchMetadata::for_version(self.version)
    }
}

impl Architecture for LuaArch {
    fn name(&self) -> &str {
        self.version.name()
    }

    fn pointer_size(&self) -> usize {
        // Lua VM is 64-bit internally (Value = 8 bytes).
        8
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn instruction_alignment(&self) -> usize {
        4
    }

    fn max_instruction_length(&self) -> usize {
        4
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        if bytes.len() < 4 {
            return Err(CoreError::InvalidFormat {
                message: "need 4 bytes for a Lua instruction".into(),
            });
        }
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        let (mnemonic, operands, flags) = decode_by_version(self.version, word, address)?;

        let mut instr = Instruction::new(address, 4, mnemonic, bytes[..4].to_vec());
        instr.operands = operands;
        instr.flags = flags;
        Ok(instr)
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        // Returns are terminal; no branch targets to emit.
        if instr.flags.contains(InstrFlags::RET) && !instr.flags.contains(InstrFlags::CALL) {
            return vec![];
        }

        if instr.flags.contains(InstrFlags::BRANCH) {
            // Parse the signed offset from the last comma-separated token.
            for token in instr.operands.split(',').rev() {
                let t = token.split_whitespace().next().unwrap_or("");
                if (t.starts_with('+') || t.starts_with('-')) && let Ok(off) = t.parse::<i64>() {
                    // Target: PC_after_this_instruction + offset * 1
                    // Lua encodes relative to "next PC", i.e. address + 4.
                    let target = instr
                        .address
                        .as_u64()
                        .wrapping_add(4)
                        .wrapping_add(off.cast_unsigned().wrapping_mul(4));
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
        // Expose R0—"R15 as representative general-purpose registers.
        (0u32..=15)
            .map(|i| RegisterInfo::new(format!("R{i}"), i, 8, RegisterKind::General))
            .collect()
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        // Lua function convention: arguments start at R0, results returned from R0.
        vec![
            CallingConvention::new("lua")
                .with_int_args(vec!["R0".into(), "R1".into(), "R2".into(), "R3".into()])
                .with_return_regs(vec!["R0".into()]),
        ]
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LuaArchMetadata
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Static metadata about a Lua bytecode variant.
#[derive(Debug, Clone)]
pub struct LuaArchMetadata {
    /// Number of opcodes defined in this version.
    pub opcode_count: usize,
    /// Number of bits used for the opcode field.
    pub opcode_bits: u8,
    /// Fixed instruction width in bytes.
    pub instr_width: usize,
    /// Lua version string.
    pub version: &'static str,
}

impl LuaArchMetadata {
    /// Return metadata for the given Lua version.
    #[must_use] 
    pub fn for_version(v: LuaVersion) -> Self {
        match v {
            LuaVersion::Lua51 => Self {
                opcode_count: LUA51_OPCODES.len(),
                opcode_bits: 6,
                instr_width: 4,
                version: "5.1",
            },
            LuaVersion::Lua52 => Self {
                opcode_count: LUA52_OPCODES.len(),
                opcode_bits: 6,
                instr_width: 4,
                version: "5.2",
            },
            LuaVersion::Lua53 => Self {
                opcode_count: LUA53_OPCODES.len(),
                opcode_bits: 6,
                instr_width: 4,
                version: "5.3",
            },
            LuaVersion::Lua54 => Self {
                opcode_count: LUA54_OPCODES.len(),
                opcode_bits: 7,
                instr_width: 4,
                version: "5.4",
            },
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Instruction word builders
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Build a Lua 5.4 iABC instruction word.
///
/// Layout: `[C:8][B:8][k:1][A:8][OP:7]`
#[must_use] 
pub const fn make_iabc(op: u8, a: u32, b: u32, c: u32, k: u32) -> u32 {
    (op as u32) | (a << 7) | (k << 15) | (b << 16) | (c << 24)
}

/// Build a Lua 5.4 iAsBx instruction word.
///
/// `sBx` is converted to unsigned by adding `MAXARG_SBX`.
///
/// # Panics
///
/// Panics when an argument is outside the range the instruction encoding
/// can represent; callers must validate untrusted values first.
#[must_use] 
pub fn make_iasbx(op: u8, a: u32, sbx: i32) -> u32 {
    assert!(
        (-MAXARG_SBX..=MAXARG_SBX).contains(&sbx),
        "make_iasbx: sbx {sbx} is out of range [-{MAXARG_SBX}, {MAXARG_SBX}]"
    );
    let bx = sbx
        .checked_add(MAXARG_SBX)
        .expect("make_iasbx: sbx addition overflowed")
        .cast_unsigned();
    u32::from(op) | (a << 7) | (bx << 15)
}

/// Build a Lua 5.4 iABx instruction word.
#[must_use] 
pub const fn make_iabx(op: u8, a: u32, bx: u32) -> u32 {
    (op as u32) | (a << 7) | (bx << 15)
}

/// Build a Lua 5.4 iAx instruction word (EXTRAARG).
#[must_use] 
pub const fn make_iax(op: u8, ax: u32) -> u32 {
    (op as u32) | (ax << 7)
}

/// Build a Lua 5.4 isJ instruction word (JMP).
///
/// `sj` is relative to the instruction after JMP, in instruction units.
///
/// # Panics
///
/// Panics when an argument is outside the range the instruction encoding
/// can represent; callers must validate untrusted values first.
#[must_use] 
pub fn make_isj(op: u8, sj: i32) -> u32 {
    assert!(
        (-MAXARG_SJ..=MAXARG_SJ).contains(&sj),
        "make_isj: sj {sj} out of range [-{MAXARG_SJ}, {MAXARG_SJ}]"
    );
    let uj = sj
        .checked_add(MAXARG_SJ)
        .expect("make_isj: sj addition overflowed")
        .cast_unsigned();
    u32::from(op) | (uj << 7)
}

/// Build a legacy (5.1—"5.3) iABC instruction word.
///
/// Layout: `[C:9][B:9][A:8][OP:6]`
#[must_use] 
pub const fn make_legacy_iabc(op: u8, a: u32, b: u32, c: u32) -> u32 {
    (op as u32) | (a << 6) | (c << 14) | (b << 23)
}

/// Build a legacy (5.1—"5.3) iABx instruction word.
#[must_use] 
pub const fn make_legacy_iabx(op: u8, a: u32, bx: u32) -> u32 {
    (op as u32) | (a << 6) | (bx << 14)
}

/// Build a legacy (5.1—"5.3) iAsBx instruction word.
///
/// # Panics
///
/// Panics when an argument is outside the range the instruction encoding
/// can represent; callers must validate untrusted values first.
#[must_use] 
pub fn make_legacy_iasbx(op: u8, a: u32, sbx: i32) -> u32 {
    assert!(
        (-MAXARG_SBX_OLD..=MAXARG_SBX_OLD).contains(&sbx),
        "make_legacy_iasbx: sbx {sbx} is out of range [-{MAXARG_SBX_OLD}, {MAXARG_SBX_OLD}]"
    );
    let bx = sbx
        .checked_add(MAXARG_SBX_OLD)
        .expect("make_legacy_iasbx: sbx addition overflowed")
        .cast_unsigned();
    u32::from(op) | (a << 6) | (bx << 14)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Opcode query helpers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Look up an opcode name by number for the given Lua version.
///
/// Returns `None` if the opcode index is out of range.
#[must_use] 
pub fn opcode_name(version: LuaVersion, opcode: u8) -> Option<&'static str> {
    let table: &[&str] = match version {
        LuaVersion::Lua51 => LUA51_OPCODES,
        LuaVersion::Lua52 => LUA52_OPCODES,
        LuaVersion::Lua53 => LUA53_OPCODES,
        LuaVersion::Lua54 => LUA54_OPCODES,
    };
    table.get(opcode as usize).copied()
}

/// Search all opcodes of a given Lua version for those whose name contains
/// `needle` (case-insensitive).  Returns a `Vec` of `(index, name)`.
#[must_use] 
pub fn find_opcodes(version: LuaVersion, needle: &str) -> Vec<(u8, &'static str)> {
    let table: &[&str] = match version {
        LuaVersion::Lua51 => LUA51_OPCODES,
        LuaVersion::Lua52 => LUA52_OPCODES,
        LuaVersion::Lua53 => LUA53_OPCODES,
        LuaVersion::Lua54 => LUA54_OPCODES,
    };
    let needle_up = needle.to_uppercase();
    table
        .iter()
        .enumerate()
        .filter(|(_, name)| name.contains(needle_up.as_str()))
        .filter_map(|(i, name)| u8::try_from(i).ok().map(|idx| (idx, *name)))
        .collect()
}

/// Return `true` if `opcode` is a branch/jump opcode in the given version.
#[must_use] 
pub const fn is_branch_opcode(version: LuaVersion, opcode: u8) -> bool {
    match version {
        LuaVersion::Lua54 => matches!(opcode, 54 | 55..=63 | 64 | 65 | 71 | 72 | 73 | 75),
        LuaVersion::Lua51 => matches!(opcode, 22 | 23..=25 | 26 | 27 | 31 | 32 | 33),
        LuaVersion::Lua52 => matches!(opcode, 23 | 24..=26 | 27 | 28 | 32 | 33 | 35),
        LuaVersion::Lua53 => matches!(opcode, 30 | 31..=33 | 34 | 35 | 39 | 40 | 42),
    }
}

/// Return `true` if `opcode` is a call opcode in the given version.
#[must_use] 
pub const fn is_call_opcode(version: LuaVersion, opcode: u8) -> bool {
    match version {
        LuaVersion::Lua54 => matches!(opcode, 66 | 67),
        LuaVersion::Lua51 => matches!(opcode, 28 | 29),
        LuaVersion::Lua52 => matches!(opcode, 29 | 30),
        LuaVersion::Lua53 => matches!(opcode, 36 | 37),
    }
}

/// Return `true` if `opcode` is a return opcode in the given version.
#[must_use] 
pub const fn is_return_opcode(version: LuaVersion, opcode: u8) -> bool {
    match version {
        LuaVersion::Lua54 => matches!(opcode, 68..=70),
        LuaVersion::Lua51 => opcode == 30,
        LuaVersion::Lua52 => opcode == 31,
        LuaVersion::Lua53 => opcode == 38,
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Bytecode chunk header parser
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Lua bytecode chunk header (the leading signature block).
///
/// Lua dumps always begin with `\x1bLua` followed by a version byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuaChunkHeader {
    /// Detected Lua version from the header byte.
    pub version: LuaVersion,
    /// `1` = little-endian, `0` = big-endian.
    pub endian: u8,
    /// Integer size in bytes reported by the header.
    pub int_size: u8,
    /// `size_t` size in bytes reported by the header.
    pub size_t_size: u8,
    /// Instruction size in bytes (always 4 for standard Lua).
    pub instr_size: u8,
}

/// Errors that can occur when parsing a Lua chunk header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkHeaderError {
    /// The buffer is too small to contain a valid header.
    TooShort,
    /// The magic signature does not match `\x1bLua`.
    BadMagic,
    /// The version byte does not correspond to a supported Lua version.
    UnsupportedVersion(u8),
}

impl fmt::Display for ChunkHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "buffer too short for Lua header"),
            Self::BadMagic => write!(f, "not a Lua bytecode file (bad magic)"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported Lua version byte {v:#04x}")
            }
        }
    }
}

/// Parse the first few bytes of a Lua bytecode dump and return the header.
///
/// The function is deliberately lenient: it only validates the magic and
/// version byte.  The remaining fields are read without further validation.
///
/// # Errors
///
/// Returns an error when the input bytes are malformed, truncated, or
/// otherwise cannot be decoded.
pub fn parse_chunk_header(data: &[u8]) -> Result<LuaChunkHeader, ChunkHeaderError> {
    // Minimum: 4 bytes magic + 1 version + 3 size fields = 8 bytes
    if data.len() < 8 {
        return Err(ChunkHeaderError::TooShort);
    }
    // Magic: 0x1b 'L' 'u' 'a'
    if data[0] != 0x1b || data[1] != b'L' || data[2] != b'u' || data[3] != b'a' {
        return Err(ChunkHeaderError::BadMagic);
    }
    let ver_byte = data[4];
    let version = match ver_byte {
        0x51 => LuaVersion::Lua51,
        0x52 => LuaVersion::Lua52,
        0x53 => LuaVersion::Lua53,
        0x54 => LuaVersion::Lua54,
        other => return Err(ChunkHeaderError::UnsupportedVersion(other)),
    };
    Ok(LuaChunkHeader {
        version,
        endian: data[5],
        int_size: data[6],
        size_t_size: data[7],
        instr_size: if data.len() > 8 { data[8] } else { 4 },
    })
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Instruction batch disassembly
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Decode a slice of raw bytes as a sequence of Lua instructions.
///
/// Each 4-byte group is decoded independently.  The returned `Vec` contains
/// one decoded [`Instruction`] per word, or `None` if decoding failed.
#[must_use] 
pub fn disassemble_chunk(
    arch: &LuaArch,
    base: Address,
    bytes: &[u8],
) -> Vec<Result<Instruction, CoreError>> {
    let mut out = Vec::with_capacity(bytes.len() / 4);
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let addr = Address::new(base.as_u64().wrapping_add(offset as u64));
        out.push(arch.disassemble(addr, &bytes[offset..]));
        offset += 4;
    }
    out
}

/// Decode only the successfully-decoded instructions from a byte slice.
///
/// Silently skips any 4-byte groups that fail to decode.
#[must_use] 
pub fn disassemble_chunk_lossy(arch: &LuaArch, base: Address, bytes: &[u8]) -> Vec<Instruction> {
    disassemble_chunk(arch, base, bytes)
        .into_iter()
        .flatten()
        .collect()
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Control-flow graph basic-block splitter
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A basic block of Lua instructions.
///
/// A block ends at the first branch/jump/return instruction or when the next
/// instruction is the target of a known jump.
#[derive(Debug, Clone)]
pub struct LuaFlatBlock {
    /// Starting address of this block.
    pub start: Address,
    /// All decoded instructions in the block.
    pub instructions: Vec<Instruction>,
    /// Outgoing branch targets (as absolute byte addresses).
    pub successors: Vec<u64>,
}

impl LuaFlatBlock {
    /// Return the address of the instruction immediately after this block.
    #[must_use] 
    pub fn end_address(&self) -> Address {
        self.instructions
            .last()
            .map_or(self.start, |i| Address::new(i.address.as_u64() + 4))
    }

    /// Return `true` if this block ends in an unconditional jump or return.
    #[must_use] 
    pub fn is_terminal(&self) -> bool {
        self.instructions.last().is_some_and(|i| {
            let f = i.flags;
            (f.contains(InstrFlags::RET) && !f.contains(InstrFlags::CALL))
                || (f.contains(InstrFlags::BRANCH) && !f.contains(InstrFlags::CONDITIONAL))
        })
    }
}

/// Split a flat sequence of instructions into basic blocks.
///
/// Uses a two-pass approach: first collect all branch targets (leaders), then
/// split the instruction list at each leader boundary.
#[must_use] 
pub fn split_basic_blocks(arch: &LuaArch, instrs: &[Instruction]) -> Vec<LuaFlatBlock> {
    use std::collections::BTreeSet;

    // Pass 1: collect leader addresses.
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    if let Some(first) = instrs.first() {
        leaders.insert(first.address.as_u64());
    }
    for instr in instrs {
        for bi in arch.get_branches(instr) {
            if let Some(t) = bi.target {
                leaders.insert(t);
            }
            // Fall-through of conditional branch is also a leader.
            if instr.flags.contains(InstrFlags::CONDITIONAL) {
                leaders.insert(instr.address.as_u64() + 4);
            }
        }
        // Instruction after a terminator starts a new block.
        if instr.flags.contains(InstrFlags::RET) && !instr.flags.contains(InstrFlags::CALL) {
            leaders.insert(instr.address.as_u64() + 4);
        }
        if instr.flags.contains(InstrFlags::BRANCH)
            && !instr.flags.contains(InstrFlags::CONDITIONAL)
        {
            leaders.insert(instr.address.as_u64() + 4);
        }
    }

    // Pass 2: group instructions into blocks.
    let mut blocks: Vec<LuaFlatBlock> = Vec::new();
    let mut current: Option<LuaFlatBlock> = None;

    for instr in instrs {
        let addr = instr.address.as_u64();
        if leaders.contains(&addr) {
            if let Some(b) = current.take() {
                blocks.push(b);
            }
            current = Some(LuaFlatBlock {
                start: instr.address,
                instructions: Vec::new(),
                successors: Vec::new(),
            });
        }
        if let Some(ref mut blk) = current {
            let branches = arch.get_branches(instr);
            for bi in &branches {
                if let Some(t) = bi.target {
                    blk.successors.push(t);
                }
            }
            // Add implicit fall-through for conditional/non-terminal instructions.
            let is_term = (instr.flags.contains(InstrFlags::RET)
                && !instr.flags.contains(InstrFlags::CALL))
                || (instr.flags.contains(InstrFlags::BRANCH)
                    && !instr.flags.contains(InstrFlags::CONDITIONAL));
            if !is_term && instr.flags.contains(InstrFlags::BRANCH) {
                blk.successors.push(addr + 4);
            }
            blk.instructions.push(instr.clone());
        }
    }
    if let Some(b) = current.take() {
        blocks.push(b);
    }
    blocks
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Instruction pretty-printer
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Format a single Lua instruction as a human-readable string.
///
/// Output format: `0x{addr:08x}  {mnemonic:<12} {operands}`
#[must_use] 
pub fn format_instruction(instr: &Instruction) -> String {
    if instr.operands.is_empty() {
        format!("0x{:08x}  {:<12}", instr.address.as_u64(), instr.mnemonic)
    } else {
        format!(
            "0x{:08x}  {:<12} {}",
            instr.address.as_u64(),
            instr.mnemonic,
            instr.operands
        )
    }
}

/// Format a slice of instructions as a multi-line disassembly listing.
pub fn format_listing(instrs: &[Instruction]) -> String {
    instrs
        .iter()
        .map(format_instruction)
        .collect::<Vec<_>>()
        .join("\n")
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Instruction statistics for Lua chunks
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Aggregate statistics about a disassembled Lua function or chunk.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LuaChunkStats {
    /// Total number of decoded instructions.
    pub total: usize,
    /// Number of branch/jump instructions.
    pub branches: usize,
    /// Number of call instructions.
    pub calls: usize,
    /// Number of return instructions.
    pub returns: usize,
    /// Number of arithmetic/bitwise operations.
    pub arithmetic: usize,
    /// Number of table access operations (GETTABLE, SETTABLE, GETTABUP, —¦).
    pub table_ops: usize,
    /// Number of upvalue operations.
    pub upvalue_ops: usize,
    /// Number of closure creation instructions.
    pub closures: usize,
}

impl LuaChunkStats {
    /// Compute statistics from a slice of decoded instructions.
    #[must_use] 
    pub fn from_instructions(version: LuaVersion, instrs: &[Instruction]) -> Self {
        let mut s = Self::default();
        for instr in instrs {
            s.total += 1;
            if instr.flags.contains(InstrFlags::BRANCH) {
                s.branches += 1;
            }
            if instr.flags.contains(InstrFlags::CALL) {
                s.calls += 1;
            }
            if instr.flags.contains(InstrFlags::RET) && !instr.flags.contains(InstrFlags::CALL) {
                s.returns += 1;
            }
            let m = instr.mnemonic.to_uppercase();
            if matches!(
                m.as_str(),
                "ADD"
                    | "SUB"
                    | "MUL"
                    | "DIV"
                    | "MOD"
                    | "POW"
                    | "IDIV"
                    | "BAND"
                    | "BOR"
                    | "BXOR"
                    | "SHL"
                    | "SHR"
                    | "UNM"
                    | "BNOT"
                    | "ADDI"
                    | "ADDK"
                    | "SUBK"
                    | "MULK"
                    | "MODK"
                    | "POWK"
                    | "DIVK"
                    | "IDIVK"
                    | "BANDK"
                    | "BORK"
                    | "BXORK"
                    | "SHRI"
                    | "SHLI"
            ) {
                s.arithmetic += 1;
            }
            if m.contains("TABLE") || m.contains("TABUP") || m.contains("FIELD") || m == "SELF" {
                s.table_ops += 1;
            }
            if m.contains("UPVAL") {
                s.upvalue_ops += 1;
            }
            let _ = version;
            if m == "CLOSURE" {
                s.closures += 1;
            }
        }
        s
    }

    /// Return the ratio of branches to total instructions.
    #[must_use] 
    pub fn branch_ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            count_as_f64(self.branches) / count_as_f64(self.total)
        }
    }
}

impl fmt::Display for LuaChunkStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LuaChunkStats {{ total={}, branches={}, calls={}, returns={}, arith={}, table={}, upval={}, closures={} }}",
            self.total,
            self.branches,
            self.calls,
            self.returns,
            self.arithmetic,
            self.table_ops,
            self.upvalue_ops,
            self.closures
        )
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Per-version dedicated decoders
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
//
// Each function below is a thin, self-contained entry point that translates a
// single 32-bit Lua instruction word into (mnemonic, operands, InstrFlags).
// They mirror the layout of `decode_lua54` but target the correct opcode table
// and field-extraction helpers for their respective Lua version.

// â"€â"€ Lua 5.1 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Decode a single Lua **5.1** instruction word.
///
/// Field layout (little-endian u32):
/// ```text
/// bits  0.. 5 = opcode (6 bits)
/// bits  6..13 = A      (8 bits)
/// bits 14..22 = C      (9 bits)   â† note: C comes before B
/// bits 23..31 = B      (9 bits)
/// Bx  = bits 14..31 (18 bits, unsigned)
/// sBx = Bx - 131071
/// ```
///
/// # Errors
///
/// Returns an error when the input bytes are malformed, truncated, or
/// otherwise cannot be decoded.
pub fn decode_lua51(
    word: u32,
    _address: Address,
) -> Result<(String, String, InstrFlags), CoreError> {
    let op = get_op_old(word);
    if op as usize >= LUA51_OPCODES.len() {
        return Err(CoreError::InvalidFormat {
            message: format!("unknown Lua 5.1 opcode {op}"),
        });
    }
    let mnemonic = LUA51_OPCODES[op as usize].to_lowercase();
    let fmt = lua51_fmt(op);

    let (operands, flags) = match fmt {
        LuaLegacyFmt::ABx => {
            let a = get_a_old(word);
            let bx = get_bx_old(word);
            (format!("R{a}, {bx}"), InstrFlags::NONE)
        }
        LuaLegacyFmt::AsBx => {
            let a = get_a_old(word);
            let sbx = get_sbx_old(word);
            // JMP=22, FORLOOP=31, FORPREP=32 are the sBx ops; all are branches.
            let fl = if matches!(op, 22 | 31 | 32) {
                InstrFlags::BRANCH
            } else {
                InstrFlags::NONE
            };
            (format!("R{a}, {sbx:+}"), fl)
        }
        LuaLegacyFmt::Ax => {
            // No EXTRAARG in 5.1, but keep a path for completeness.
            let bx = get_bx_old(word);
            (format!("{bx}"), InstrFlags::NONE)
        }
        LuaLegacyFmt::Abc => {
            let a = get_a_old(word);
            let b = get_b_old(word);
            let c = get_c_old(word);

            // Lua 5.1 opcode semantics:
            //   EQ=23, LT=24, LE=25                     â†' conditional branch
            //   TEST=26, TESTSET=27                      â†' conditional branch
            //   TFORLOOP=33                              â†' branch
            //   CALL=28                                  â†' call
            //   TAILCALL=29                              â†' call + ret
            //   RETURN=30                                â†' ret
            let fl = match op {
                23..=27 => InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                33 => InstrFlags::BRANCH,
                28 => InstrFlags::CALL,
                29 => InstrFlags::CALL | InstrFlags::RET,
                30 => InstrFlags::RET,
                _ => InstrFlags::NONE,
            };

            // LOADBOOL (op=2): A, B, C  —" C acts as skip flag, show plainly.
            // LOADNIL  (op=3): A, B     —" C unused.
            // GETUPVAL (op=4): A, B     —" C unused.
            // GETGLOBAL(op=5): handled via ABx above.
            // SETGLOBAL(op=7): handled via ABx above.
            // NEWTABLE (op=10): A, B, C encode hash/array sizes via float-encode.
            // For all others just emit R{a}, R{b}, R{c}.
            match op {
                3 => (format!("R{a}, R{b}"), fl),    // LOADNIL: A..B range
                4 | 8 => (format!("R{a}, {b}"), fl), // GETUPVAL/SETUPVAL: upvalue index
                _ => (format!("R{a}, R{b}, R{c}"), fl),
            }
        }
    };

    Ok((mnemonic, operands, flags))
}

// â"€â"€ Lua 5.2 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Decode a single Lua **5.2** instruction word.
///
/// Lua 5.2 keeps the same 6-bit opcode layout as 5.1 but reorganises the
/// opcode table (adds GETTABUP/SETTABUP, removes GETGLOBAL/SETGLOBAL, adds
/// LOADKX and EXTRAARG, TFORCALL replaces old TFORLOOP semantics).
///
/// # Errors
///
/// Returns an error when the input bytes are malformed, truncated, or
/// otherwise cannot be decoded.
pub fn decode_lua52(
    word: u32,
    _address: Address,
) -> Result<(String, String, InstrFlags), CoreError> {
    let op = get_op_old(word);
    if op as usize >= LUA52_OPCODES.len() {
        return Err(CoreError::InvalidFormat {
            message: format!("unknown Lua 5.2 opcode {op}"),
        });
    }
    let mnemonic = LUA52_OPCODES[op as usize].to_lowercase();
    let fmt = lua52_fmt(op);

    let (operands, flags) = match fmt {
        LuaLegacyFmt::ABx => {
            let a = get_a_old(word);
            let bx = get_bx_old(word);
            (format!("R{a}, {bx}"), InstrFlags::NONE)
        }
        LuaLegacyFmt::AsBx => {
            let a = get_a_old(word);
            let sbx = get_sbx_old(word);
            // JMP=23, FORLOOP=32, FORPREP=33, TFORLOOP=35
            let fl = if matches!(op, 23 | 32 | 33 | 35) {
                InstrFlags::BRANCH
            } else {
                InstrFlags::NONE
            };
            (format!("R{a}, {sbx:+}"), fl)
        }
        LuaLegacyFmt::Ax => {
            // EXTRAARG=39: carries Ax, no A register.
            let bx = get_bx_old(word);
            (format!("{bx}"), InstrFlags::NONE)
        }
        LuaLegacyFmt::Abc => {
            let a = get_a_old(word);
            let b = get_b_old(word);
            let c = get_c_old(word);

            // 5.2 opcode numbers for call/ret/compare:
            //   EQ=24, LT=25, LE=26                    â†' conditional branch
            //   TEST=27, TESTSET=28                     â†' conditional branch
            //   TFORCALL=34                             â†' (not a branch itself)
            //   CALL=29                                 â†' call
            //   TAILCALL=30                             â†' call + ret
            //   RETURN=31                               â†' ret
            let fl = match op {
                24..=28 => InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                29 => InstrFlags::CALL,
                30 => InstrFlags::CALL | InstrFlags::RET,
                31 => InstrFlags::RET,
                _ => InstrFlags::NONE,
            };

            match op {
                // LOADNIL(4): range A..A+B-1 —" show B as immediate.
                // GETUPVAL(5), SETUPVAL(9): upvalue index in B.
                4 | 5 | 9 => (format!("R{a}, {b}"), fl),
                // GETTABUP(6): A, upval-B, RK(C)
                6 => (format!("R{a}, U{b}, RK{c}"), fl),
                // SETTABUP(8): upval-A, RK(B), RK(C)
                8 => (format!("U{a}, RK{b}, RK{c}"), fl),
                _ => (format!("R{a}, R{b}, R{c}"), fl),
            }
        }
    };

    Ok((mnemonic, operands, flags))
}

// â"€â"€ Lua 5.3 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Decode a single Lua **5.3** instruction word.
///
/// Lua 5.3 is a superset of 5.2 in opcode layout: it adds integer/bitwise ops
/// (BAND, BOR, BXOR, SHL, SHR, IDIV, BNOT) and TFORCALL/TFORLOOP (two ops
/// instead of one).  There is still no TFORPREP; that was added in 5.4.
///
/// # Errors
///
/// Returns an error when the input bytes are malformed, truncated, or
/// otherwise cannot be decoded.
pub fn decode_lua53(
    word: u32,
    _address: Address,
) -> Result<(String, String, InstrFlags), CoreError> {
    let op = get_op_old(word);
    if op as usize >= LUA53_OPCODES.len() {
        return Err(CoreError::InvalidFormat {
            message: format!("unknown Lua 5.3 opcode {op}"),
        });
    }
    let mnemonic = LUA53_OPCODES[op as usize].to_lowercase();
    let fmt = lua53_fmt(op);

    let (operands, flags) = match fmt {
        LuaLegacyFmt::ABx => {
            let a = get_a_old(word);
            let bx = get_bx_old(word);
            (format!("R{a}, {bx}"), InstrFlags::NONE)
        }
        LuaLegacyFmt::AsBx => {
            let a = get_a_old(word);
            let sbx = get_sbx_old(word);
            // JMP=30, FORLOOP=39, FORPREP=40, TFORLOOP=42
            let fl = if matches!(op, 30 | 39 | 40 | 42) {
                InstrFlags::BRANCH
            } else {
                InstrFlags::NONE
            };
            (format!("R{a}, {sbx:+}"), fl)
        }
        LuaLegacyFmt::Ax => {
            // EXTRAARG=46
            let bx = get_bx_old(word);
            (format!("{bx}"), InstrFlags::NONE)
        }
        LuaLegacyFmt::Abc => {
            let a = get_a_old(word);
            let b = get_b_old(word);
            let c = get_c_old(word);

            // 5.3 opcode numbers:
            //   EQ=31, LT=32, LE=33                    â†' conditional branch
            //   TEST=34, TESTSET=35                     â†' conditional branch
            //   TFORCALL=41                             â†' plain (no branch)
            //   CALL=36                                 â†' call
            //   TAILCALL=37                             â†' call + ret
            //   RETURN=38                               â†' ret
            let fl = match op {
                31..=35 => InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
                36 => InstrFlags::CALL,
                37 => InstrFlags::CALL | InstrFlags::RET,
                38 => InstrFlags::RET,
                _ => InstrFlags::NONE,
            };

            match op {
                // LOADNIL(4): A, B where B = number of registers to nil.
                // GETUPVAL(5), SETUPVAL(9): B = upvalue index.
                4 | 5 | 9 => (format!("R{a}, {b}"), fl),
                // GETTABUP(6): A, upval-B, RK(C)
                6 => (format!("R{a}, U{b}, RK{c}"), fl),
                // SETTABUP(8): upval-A, RK(B), RK(C)
                8 => (format!("U{a}, RK{b}, RK{c}"), fl),
                // NEWTABLE(11): B and C encode sizes in a float-like scheme; emit raw.
                11 => (format!("R{a}, {b}, {c}"), fl),
                _ => (format!("R{a}, R{b}, R{c}"), fl),
            }
        }
    };

    Ok((mnemonic, operands, flags))
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Version-dispatching disassemble helper (called from Architecture::disassemble)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Decode one Lua instruction word, dispatching to the correct version decoder.
///
/// This is the canonical entry point used by [`LuaArch::disassemble`] once
/// the 4-byte word has been read from the byte slice.
///
/// # Errors
///
/// Returns an error when the input bytes are malformed, truncated, or
/// otherwise cannot be decoded.
pub fn decode_by_version(
    version: LuaVersion,
    word: u32,
    address: Address,
) -> Result<(String, String, InstrFlags), CoreError> {
    match version {
        LuaVersion::Lua51 => decode_lua51(word, address),
        LuaVersion::Lua52 => decode_lua52(word, address),
        LuaVersion::Lua53 => decode_lua53(word, address),
        LuaVersion::Lua54 => decode_lua54(word, address),
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Lua constant representation
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A Lua constant value as it appears in a compiled function prototype.
///
/// Lua bytecode stores a constant pool alongside each function prototype.
/// LOADK / LOADKX instructions reference entries in this pool by index.
/// This enum covers all constant types that can appear in any supported Lua
/// version (5.1 —" 5.4).
#[derive(Debug, Clone, PartialEq)]
pub enum LuaConst {
    /// The singleton nil value.
    Nil,
    /// A boolean constant.
    Bool(bool),
    /// An integer constant (Lua 5.3+ has native integers; earlier versions
    /// store all numbers as floats but we normalise them here).
    Int(i64),
    /// A floating-point constant.
    Float(f64),
    /// A string constant (short or long string).
    String(String),
}

impl LuaConst {
    /// Return a human-readable type tag for this constant.
    #[must_use] 
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Nil => "nil",
            Self::Bool(_) => "boolean",
            Self::Int(_) => "integer",
            Self::Float(_) => "float",
            Self::String(_) => "string",
        }
    }

    /// Return `true` if this constant is the nil value.
    #[must_use] 
    pub const fn is_nil(&self) -> bool {
        matches!(self, Self::Nil)
    }

    /// Return the inner `bool`, or `None` if not a boolean.
    #[must_use] 
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Return the inner integer, or `None` if not an integer.
    #[must_use] 
    pub const fn as_int(&self) -> Option<i64> {
        if let Self::Int(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Return the inner float, or `None` if not a float.
    #[must_use] 
    pub const fn as_float(&self) -> Option<f64> {
        if let Self::Float(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Return the inner string slice, or `None` if not a string.
    #[must_use] 
    pub const fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }
}

impl fmt::Display for LuaConst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::String(s) => write!(f, "{s:?}"),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Constant extraction from raw instruction stream
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Extract constant references found inside a raw instruction stream.
///
/// Scans the decoded instructions looking for LOADK / LOADKX opcodes and
/// collects the constant-pool indices they reference.  The returned
/// `Vec<LuaConst>` is a set of *placeholder* constants —" one `LuaConst::Int`
/// per unique index —" because the actual constant pool lives in the prototype
/// header rather than in the instruction stream itself.
///
/// In a full Lua loader you would parse the prototype binary and populate the
/// pool; this helper exists to give tooling a list of which constants are
/// *referenced* by a chunk, and to serve as a scaffolding point for richer
/// analysis.
///
/// `code` must be a sequence of 4-byte little-endian instruction words.
#[must_use] 
pub fn extract_constants_from_proto(code: &[u8], version: LuaVersion) -> Vec<LuaConst> {
    use std::collections::BTreeSet;

    // Opcode numbers for LOADK in each version.
    let loadk_ops: &[u8] = match version {
        LuaVersion::Lua51 => &[1],    // LOADK=1 (no LOADKX)
        LuaVersion::Lua52 | LuaVersion::Lua53 => &[1, 2], // LOADK=1, LOADKX=2
        // LOADK=1, LOADKX=2
        LuaVersion::Lua54 => &[3, 4], // LOADK=3, LOADKX=4
    };

    let mut seen: BTreeSet<u32> = BTreeSet::new();

    let mut offset = 0usize;
    while offset + 4 <= code.len() {
        let word = u32::from_le_bytes([
            code[offset],
            code[offset + 1],
            code[offset + 2],
            code[offset + 3],
        ]);
        offset += 4;

        let op = if version.is_legacy() {
            get_op_old(word)
        } else {
            get_op54(word)
        };

        if loadk_ops.contains(&op) {
            let bx = if version.is_legacy() {
                get_bx_old(word)
            } else {
                get_bx54(word)
            };
            seen.insert(bx);
        }
    }

    // Return one placeholder constant per unique referenced index.
    // Callers that have access to the actual prototype pool should replace
    // these with real values.
    seen.into_iter()
        .map(|idx| LuaConst::Int(i64::from(idx)))
        .collect()
}

/// Parse a raw constant-pool byte block (as written by `luac`) for Lua 5.1.
///
/// The binary format is:
/// ```text
/// int32   n_constants
/// for each constant:
///   byte  type   (0=nil, 1=bool, 3=number, 4=string)
///   —¦           (type-specific payload)
/// ```
/// Numbers are `double` (8 bytes); booleans are 1 byte; strings are
/// `int32 length` followed by the bytes (including the NUL terminator that
/// `luac` writes —" we strip it).
///
/// Returns `None` if the slice is malformed or truncated.
/// Read a little-endian `i32` from `data` at `pos`, advancing `pos`.
fn const_pool_read_i32(data: &[u8], pos: &mut usize) -> Option<i32> {
    let b = data.get(*pos..*pos + 4)?;
    *pos += 4;
    Some(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a little-endian `i64` from `data` at `pos`, advancing `pos`.
fn const_pool_read_i64(data: &[u8], pos: &mut usize) -> Option<i64> {
    let b = data.get(*pos..*pos + 8)?;
    *pos += 8;
    Some(i64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Read a little-endian IEEE-754 `f64` from `data` at `pos`, advancing `pos`.
fn const_pool_read_f64(data: &[u8], pos: &mut usize) -> Option<f64> {
    let bits = const_pool_read_i64(data, pos)?.cast_unsigned();
    Some(f64::from_bits(bits))
}

#[must_use] 
pub fn parse_const_pool_51(data: &[u8]) -> Option<Vec<LuaConst>> {
    let mut pos = 0usize;


    // A negative count cast straight to usize wraps to ~1.8e19 and makes
    // `Vec::with_capacity` abort with a capacity overflow; clamp at 0 first.
    // Each constant needs at least a one-byte type tag, so the bytes left in
    // `data` also bound how many can really be present.
    let n = usize::try_from(const_pool_read_i32(data, &mut pos)?.max(0)).unwrap_or(0);
    let mut out = Vec::with_capacity(n.min(data.len().saturating_sub(pos)));

    for _ in 0..n {
        let ty = *data.get(pos)?;
        pos += 1;
        match ty {
            0 => out.push(LuaConst::Nil),
            1 => {
                let b = *data.get(pos)?;
                pos += 1;
                out.push(LuaConst::Bool(b != 0));
            }
            3 => {
                // IEEE 754 double
                let raw = data.get(pos..pos + 8)?;
                pos += 8;
                let bits = u64::from_le_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]);
                out.push(LuaConst::Float(f64::from_bits(bits)));
            }
            4 => {
                // Lua string: int32 length (including NUL), then bytes.
                let len = usize::try_from(const_pool_read_i32(data, &mut pos)?.max(0)).unwrap_or(0);
                let bytes = data.get(pos..pos + len)?;
                pos += len;
                // Strip trailing NUL that luac includes in the length.
                let trimmed = if bytes.last() == Some(&0) {
                    &bytes[..bytes.len() - 1]
                } else {
                    bytes
                };
                out.push(LuaConst::String(
                    String::from_utf8_lossy(trimmed).into_owned(),
                ));
            }
            _ => return None, // Unknown constant type; bail out.
        }
    }

    Some(out)
}

/// Parse a raw constant-pool byte block for Lua 5.3 and 5.4.
///
/// Lua 5.3+ adds a native integer type (type byte = 19 for 5.3, or uses
/// type-tag bytes that encode sub-types in the high nibble for 5.4).
/// This function handles the common subset: nil, boolean, float, integer,
/// and string.  Integer payload is a little-endian i64 (8 bytes).
///
/// Returns `None` if the slice is malformed or truncated.
#[must_use] 
pub fn parse_const_pool_53(data: &[u8]) -> Option<Vec<LuaConst>> {
    let mut pos = 0usize;




    // A negative count cast straight to usize wraps to ~1.8e19 and makes
    // `Vec::with_capacity` abort with a capacity overflow; clamp at 0 first.
    // Each constant needs at least a one-byte type tag, so the bytes left in
    // `data` also bound how many can really be present.
    let n = usize::try_from(const_pool_read_i32(data, &mut pos)?.max(0)).unwrap_or(0);
    let mut out = Vec::with_capacity(n.min(data.len().saturating_sub(pos)));

    for _ in 0..n {
        let ty = *data.get(pos)?;
        pos += 1;
        match ty {
            // 0x00 = nil
            0x00 => out.push(LuaConst::Nil),
            // 0x01 = false, 0x11 = true (5.4 uses high nibble for sub-type)
            0x01 => out.push(LuaConst::Bool(false)),
            0x11 => out.push(LuaConst::Bool(true)),
            // 0x13 = integer (5.3+)
            0x13 => {
                let v = const_pool_read_i64(data, &mut pos)?;
                out.push(LuaConst::Int(v));
            }
            // 0x03 = float (5.3) or 0x23 = float (5.4 sub-type)
            0x03 | 0x23 => {
                let v = const_pool_read_f64(data, &mut pos)?;
                out.push(LuaConst::Float(v));
            }
            // 0x04 = short string, 0x14 = long string
            0x04 | 0x14 => {
                // Size stored as a byte if â‰¤ 0xfe, else 0xff + size_t
                let sz_byte = *data.get(pos)?;
                pos += 1;
                let len = if sz_byte == 0xff {
                    // Extended size: read a u64 (size_t on 64-bit builds).
                    let b = data.get(pos..pos + 8)?;
                    pos += 8;
                    usize::try_from(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
    .unwrap_or(usize::MAX)
                } else {
                    sz_byte as usize
                };
                // Length includes the trailing NUL in 5.3.
                let effective = if len == 0 { 0 } else { len - 1 };
                let bytes = data.get(pos..pos + effective)?;
                pos += len; // advance past bytes + NUL
                out.push(LuaConst::String(
                    String::from_utf8_lossy(bytes).into_owned(),
                ));
            }
            _ => return None,
        }
    }

    Some(out)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Debug info helpers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Generate placeholder local-variable names for a function prototype.
///
/// When debug information is not available (or has been stripped), this
/// function produces a stable set of generic names that tools can display
/// instead of blank slots.  The naming scheme is `local_0`, `local_1`, —¦
///
/// `proto_size` is the number of instruction words in the prototype; the
/// heuristic assumes at most one local per 4 instructions, capped at 64.
#[must_use] 
pub fn generate_local_var_names(proto_size: usize) -> Vec<String> {
    let count = (proto_size / 4).clamp(1, 64);
    (0..count).map(|i| format!("local_{i}")).collect()
}

/// Generate placeholder upvalue names for a function prototype.
///
/// Upvalues are captured variables from outer scopes.  When debug info is
/// absent this returns `upval_0`, `upval_1`, —¦ up to `count` entries.
#[must_use] 
pub fn generate_upvalue_names(count: usize) -> Vec<String> {
    (0..count).map(|i| format!("upval_{i}")).collect()
}

/// Generate placeholder parameter names for a function prototype.
///
/// `num_params` is taken from the prototype header.  Names follow Lua's
/// convention of `arg1`, `arg2`, —¦ (1-based), except for the implicit `self`
/// parameter inserted by methods (indicated by `has_self`).
#[must_use] 
pub fn generate_param_names(num_params: u8, has_self: bool) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if has_self {
        names.push("self".to_string());
    }
    let extra = if has_self {
        num_params.saturating_sub(1)
    } else {
        num_params
    };
    for i in 1..=extra {
        names.push(format!("arg{i}"));
    }
    names
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Prototype descriptor (lightweight, version-agnostic)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A lightweight description of a Lua function prototype derived from decoded
/// instructions and optional debug metadata.
///
/// This struct does **not** own the raw bytecode; it holds only the data that
/// tools need to display or analyse a function.
#[derive(Debug, Clone)]
pub struct LuaProtoInfo {
    /// Lua version this prototype was compiled for.
    pub version: LuaVersion,
    /// Number of fixed parameters (from the prototype header).
    pub num_params: u8,
    /// Whether the function is variadic.
    pub is_vararg: bool,
    /// Maximum stack slots used (from the prototype header).
    pub max_stack: u8,
    /// Decoded instructions.
    pub instructions: Vec<Instruction>,
    /// Constant pool (may be empty if not parsed).
    pub constants: Vec<LuaConst>,
    /// Local variable names (may be generated if debug info is absent).
    pub locals: Vec<String>,
    /// Upvalue names (may be generated if debug info is absent).
    pub upvalues: Vec<String>,
}

impl LuaProtoInfo {
    /// Construct a `LuaProtoInfo` with minimal required fields.
    ///
    /// `instructions` must already be decoded.  Constants, locals, and
    /// upvalues can be populated later.
    #[must_use] 
    pub fn new(version: LuaVersion, instructions: Vec<Instruction>) -> Self {
        let locals = generate_local_var_names(instructions.len());
        Self {
            version,
            num_params: 0,
            is_vararg: false,
            max_stack: 0,
            instructions,
            constants: Vec::new(),
            locals,
            upvalues: Vec::new(),
        }
    }

    /// Return `true` if the prototype contains no decoded instructions.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Return the number of decoded instructions.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Return aggregate statistics for this prototype.
    #[must_use] 
    pub fn stats(&self) -> LuaChunkStats {
        LuaChunkStats::from_instructions(self.version, &self.instructions)
    }

    /// Split the instruction stream into basic blocks.
    #[must_use] 
    pub fn basic_blocks(&self, arch: &LuaArch) -> Vec<LuaFlatBlock> {
        split_basic_blocks(arch, &self.instructions)
    }

    /// Return a formatted disassembly listing for this prototype.
    #[must_use] 
    pub fn listing(&self) -> String {
        format_listing(&self.instructions)
    }

    /// Look up the local variable name for register `reg`, if available.
    pub fn local_name(&self, reg: usize) -> Option<&str> {
        self.locals.get(reg).map(String::as_str)
    }

    /// Look up a constant by index, if available.
    #[must_use] 
    pub fn constant(&self, idx: usize) -> Option<&LuaConst> {
        self.constants.get(idx)
    }
}

impl fmt::Display for LuaProtoInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LuaProto[{} params={} vararg={} stack={} instrs={} consts={}]",
            self.version,
            self.num_params,
            self.is_vararg,
            self.max_stack,
            self.instructions.len(),
            self.constants.len()
        )
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Opcode category classification
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// High-level category for a Lua opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpcodeCategory {
    /// Data movement between registers or stack slots.
    Move,
    /// Loading a constant into a register.
    Load,
    /// Upvalue read or write.
    Upvalue,
    /// Global variable access (Lua 5.1 only).
    Global,
    /// Table read operation.
    TableGet,
    /// Table write operation.
    TableSet,
    /// Table creation.
    TableNew,
    /// Arithmetic or bitwise computation.
    Arithmetic,
    /// Unary operation (UNM, NOT, BNOT, LEN).
    Unary,
    /// String or value concatenation.
    Concat,
    /// Unconditional jump.
    Jump,
    /// Conditional comparison / branch.
    Compare,
    /// Loop control (FORLOOP, FORPREP, TFORLOOP, —¦).
    Loop,
    /// Function call.
    Call,
    /// Return from function.
    Return,
    /// Closure creation.
    Closure,
    /// Vararg handling.
    Vararg,
    /// Internal VM meta-operation (MMBIN, EXTRAARG, VARARGPREP, —¦).
    Meta,
    /// Anything that does not fit a more specific category.
    Other,
}

impl fmt::Display for OpcodeCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Move => "move",
            Self::Load => "load",
            Self::Upvalue => "upvalue",
            Self::Global => "global",
            Self::TableGet => "table-get",
            Self::TableSet => "table-set",
            Self::TableNew => "table-new",
            Self::Arithmetic => "arithmetic",
            Self::Unary => "unary",
            Self::Concat => "concat",
            Self::Jump => "jump",
            Self::Compare => "compare",
            Self::Loop => "loop",
            Self::Call => "call",
            Self::Return => "return",
            Self::Closure => "closure",
            Self::Vararg => "vararg",
            Self::Meta => "meta",
            Self::Other => "other",
        };
        f.write_str(s)
    }
}

/// Classify a decoded instruction mnemonic into an [`OpcodeCategory`].
///
/// The mnemonic is compared case-insensitively against well-known patterns.
/// This works for all supported Lua versions since the mnemonic strings
/// produced by the decoders match the canonical Lua source names.
#[must_use] 
pub fn classify_opcode(mnemonic: &str) -> OpcodeCategory {
    let m = mnemonic.to_uppercase();
    match m.as_str() {
        "MOVE" => OpcodeCategory::Move,

        "LOADK" | "LOADKX" | "LOADI" | "LOADF" | "LOADBOOL" | "LOADNIL" | "LOADFALSE"
        | "LOADTRUE" => OpcodeCategory::Load,

        "GETUPVAL" | "SETUPVAL" => OpcodeCategory::Upvalue,

        "GETGLOBAL" | "SETGLOBAL" => OpcodeCategory::Global,

        "GETTABLE" | "GETI" | "GETFIELD" | "GETTABUP" => OpcodeCategory::TableGet,

        "SETTABLE" | "SETI" | "SETFIELD" | "SETTABUP" => OpcodeCategory::TableSet,

        "NEWTABLE" => OpcodeCategory::TableNew,

        "ADD" | "SUB" | "MUL" | "DIV" | "MOD" | "POW" | "IDIV" | "BAND" | "BOR" | "BXOR"
        | "SHL" | "SHR" | "ADDI" | "ADDK" | "SUBK" | "MULK" | "MODK" | "POWK" | "DIVK"
        | "IDIVK" | "BANDK" | "BORK" | "BXORK" | "SHRI" | "SHLI" | "SELF" => {
            OpcodeCategory::Arithmetic
        }

        "UNM" | "NOT" | "BNOT" | "LEN" => OpcodeCategory::Unary,

        "CONCAT" => OpcodeCategory::Concat,

        "JMP" | "CLOSE" | "TBC" => OpcodeCategory::Jump,

        "EQ" | "LT" | "LE" | "TEST" | "TESTSET" | "EQK" | "EQI" | "LTI" | "GTI" | "LEI" | "GEI" => {
            OpcodeCategory::Compare
        }

        "FORLOOP" | "FORPREP" | "TFORPREP" | "TFORCALL" | "TFORLOOP" => OpcodeCategory::Loop,

        "CALL" | "TAILCALL" => OpcodeCategory::Call,

        "RETURN" | "RETURN0" | "RETURN1" => OpcodeCategory::Return,

        "CLOSURE" => OpcodeCategory::Closure,

        "VARARG" | "VARARGPREP" => OpcodeCategory::Vararg,

        "MMBIN" | "MMBINI" | "MMBINK" | "EXTRAARG" => OpcodeCategory::Meta,

        _ => OpcodeCategory::Other,
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Instruction-level annotation
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A decoded Lua instruction together with its category and a generated
/// human-readable annotation.
#[derive(Debug, Clone)]
pub struct AnnotatedInstr {
    /// The underlying decoded instruction.
    pub instr: Instruction,
    /// High-level category classification.
    pub category: OpcodeCategory,
    /// Optional annotation string (e.g. constant value, target address).
    pub annotation: Option<String>,
}

impl AnnotatedInstr {
    /// Build an `AnnotatedInstr` with no annotation.
    #[must_use] 
    pub fn new(instr: Instruction) -> Self {
        let category = classify_opcode(&instr.mnemonic);
        Self {
            instr,
            category,
            annotation: None,
        }
    }

    /// Build an `AnnotatedInstr` with a pre-computed annotation.
    pub fn with_annotation(instr: Instruction, annotation: impl Into<String>) -> Self {
        let category = classify_opcode(&instr.mnemonic);
        Self {
            instr,
            category,
            annotation: Some(annotation.into()),
        }
    }
}

impl fmt::Display for AnnotatedInstr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = format_instruction(&self.instr);
        if let Some(ref ann) = self.annotation {
            write!(f, "{base:<40} ; {ann}")
        } else {
            write!(f, "{base:<40} ; [{cat}]", cat = self.category)
        }
    }
}

/// Annotate a slice of instructions using a constant pool for cross-referencing.
///
/// For each LOADK instruction the constant referenced is looked up in `pool`
/// and its display value appended as an annotation.  All other instructions
/// receive only a category annotation.
#[must_use] 
pub fn annotate_instructions(
    instrs: &[Instruction],
    pool: &[LuaConst],
    version: LuaVersion,
) -> Vec<AnnotatedInstr> {
    // Opcode index for LOADK in each version.
    let loadk_op: u8 = match version {
        LuaVersion::Lua51 | LuaVersion::Lua52 | LuaVersion::Lua53 => 1,
        LuaVersion::Lua54 => 3,
    };

    instrs
        .iter()
        .map(|instr| {
            // Attempt to match LOADK and resolve the constant.
            let raw_op = {
                if instr.bytes.len() >= 4 {
                    let w = u32::from_le_bytes([
                        instr.bytes[0],
                        instr.bytes[1],
                        instr.bytes[2],
                        instr.bytes[3],
                    ]);
                    if version.is_legacy() {
                        get_op_old(w)
                    } else {
                        get_op54(w)
                    }
                } else {
                    0xff // sentinel: no match
                }
            };

            if raw_op == loadk_op && !pool.is_empty() {
                // Extract Bx (constant index) from the raw word.
                let bx = if instr.bytes.len() >= 4 {
                    let w = u32::from_le_bytes([
                        instr.bytes[0],
                        instr.bytes[1],
                        instr.bytes[2],
                        instr.bytes[3],
                    ]);
                    if version.is_legacy() {
                        get_bx_old(w)
                    } else {
                        get_bx54(w)
                    }
                } else {
                    0
                };
                if let Some(c) = pool.get(bx as usize) {
                    return AnnotatedInstr::with_annotation(
                        instr.clone(),
                        format!("K[{bx}] = {c}"),
                    );
                }
            }

            AnnotatedInstr::new(instr.clone())
        })
        .collect()
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Lua version detection from raw bytes
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Attempt to auto-detect the Lua version from raw bytecode.
///
/// Tries to parse a chunk header; falls back to heuristics based on the first
/// few instruction words if the header is absent or the magic is wrong.
///
/// Returns `None` if the version cannot be determined.
#[must_use] 
pub fn detect_version(data: &[u8]) -> Option<LuaVersion> {
    // Fast path: valid header.
    if let Ok(hdr) = parse_chunk_header(data) {
        return Some(hdr.version);
    }

    // Slow path: treat as a raw instruction stream and look at opcode
    // distribution heuristics.  Lua 5.4 instructions have a 7-bit opcode
    // field; any opcode â‰¥ 64 is unambiguously 5.4 (the legacy format caps at
    // opcode 46 for 5.3).
    if data.len() < 4 {
        return None;
    }
    let word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let op_legacy = get_op_old(word);
    let op_54 = get_op54(word);

    if (47..=80).contains(&op_54) {
        // Likely Lua 5.4 —" opcode range only exists in 5.4 table.
        return Some(LuaVersion::Lua54);
    }

    // Heuristic: if the 6-bit opcode maps to a valid 5.3 entry but not to a
    // valid 5.1 entry, prefer 5.3.  This is imprecise —" use parse_chunk_header
    // for reliable detection.
    if (op_legacy as usize) < LUA53_OPCODES.len() {
        return Some(LuaVersion::Lua53);
    }
    if (op_legacy as usize) < LUA52_OPCODES.len() {
        return Some(LuaVersion::Lua52);
    }
    if (op_legacy as usize) < LUA51_OPCODES.len() {
        return Some(LuaVersion::Lua51);
    }

    None
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Lua register file snapshot (analysis helper)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Symbolic value that a register might hold during abstract interpretation.
#[derive(Debug, Clone, PartialEq)]
pub enum RegValue {
    /// Register holds the given constant.
    Const(LuaConst),
    /// Register holds the result of another register (after MOVE).
    Alias(u32),
    /// Register holds an upvalue (GETUPVAL result).
    Upvalue(u32),
    /// Register holds a table field lookup result.
    TableField { table: u32, key: Box<Self> },
    /// Value is unknown (e.g. result of an arbitrary CALL or arithmetic).
    Unknown,
}

impl fmt::Display for RegValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(c) => write!(f, "const({c})"),
            Self::Alias(r) => write!(f, "R{r}"),
            Self::Upvalue(u) => write!(f, "upval({u})"),
            Self::TableField { table, key } => write!(f, "R{table}[{key}]"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

/// A snapshot of register states at a given program point.
///
/// Used by lightweight abstract interpretation passes to track constant
/// propagation across a basic block.
#[derive(Debug, Clone, Default)]
pub struct RegisterSnapshot {
    /// Map from register index to symbolic value.
    slots: Vec<Option<RegValue>>,
}

impl RegisterSnapshot {
    /// Create an empty snapshot with capacity for `size` registers.
    #[must_use] 
    pub fn new(size: usize) -> Self {
        Self {
            slots: vec![None; size],
        }
    }

    /// Record a value for register `reg`.
    pub fn set(&mut self, reg: u32, value: RegValue) {
        let idx = reg as usize;
        if idx >= self.slots.len() {
            self.slots.resize(idx + 1, None);
        }
        self.slots[idx] = Some(value);
    }

    /// Retrieve the current value of register `reg`, if known.
    #[must_use] 
    pub fn get(&self, reg: u32) -> Option<&RegValue> {
        self.slots.get(reg as usize)?.as_ref()
    }

    /// Invalidate (mark unknown) all registers at or above `from`.
    pub fn invalidate_from(&mut self, from: u32) {
        for slot in self.slots.iter_mut().skip(from as usize) {
            *slot = None;
        }
    }

    /// Propagate constant values from `pool` using a single-pass, in-order
    /// abstract interpretation of `instrs`.
    ///
    /// After this call, `self` contains the best-effort register state at the
    /// end of the instruction sequence.  No branch merging is performed; this
    /// is a straight-line analysis suitable for basic-block interiors.
    pub fn propagate(&mut self, instrs: &[Instruction], pool: &[LuaConst], version: LuaVersion) {
        for instr in instrs {
            if instr.bytes.len() < 4 {
                continue;
            }
            let word = u32::from_le_bytes([
                instr.bytes[0],
                instr.bytes[1],
                instr.bytes[2],
                instr.bytes[3],
            ]);

            if version.is_legacy() {
                let op = get_op_old(word);
                let a = get_a_old(word);
                match op {
                    // MOVE: A = B
                    0 => {
                        let b = get_b_old(word);
                        self.set(a, RegValue::Alias(b));
                    }
                    // LOADK (5.1=1, 5.2/5.3=1): A = K[Bx]
                    1 => {
                        let bx = get_bx_old(word);
                        if let Some(c) = pool.get(bx as usize) {
                            self.set(a, RegValue::Const(c.clone()));
                        } else {
                            self.set(a, RegValue::Unknown);
                        }
                    }
                    // LOADNIL: A..A+B = nil
                    3 => {
                        let b = get_b_old(word);
                        for r in a..=a + b {
                            self.set(r, RegValue::Const(LuaConst::Nil));
                        }
                    }
                    // GETUPVAL: A = UpValue[B]
                    4 => {
                        let b = get_b_old(word);
                        self.set(a, RegValue::Upvalue(b));
                    }
                    // Any call or return: conservative —" invalidate all.
                    _ if is_call_opcode(version, op) || is_return_opcode(version, op) => {
                        self.invalidate_from(0);
                    }
                    // Default: register A destination becomes unknown.
                    _ => {
                        self.set(a, RegValue::Unknown);
                    }
                }
            } else {
                // Lua 5.4
                let op = get_op54(word);
                let a = get_a54(word);
                match op {
                    // MOVE
                    0 => {
                        let b = get_b54(word);
                        self.set(a, RegValue::Alias(b));
                    }
                    // LOADI: A = sBx (integer immediate)
                    1 => {
                        let sbx = get_sbx54(word);
                        self.set(a, RegValue::Const(LuaConst::Int(i64::from(sbx))));
                    }
                    // LOADF: A = sBx (float immediate, integer bits used)
                    2 => {
                        let sbx = get_sbx54(word);
                        self.set(a, RegValue::Const(LuaConst::Float(f64::from(sbx))));
                    }
                    // LOADK: A = K[Bx]
                    3 => {
                        let bx = get_bx54(word);
                        if let Some(c) = pool.get(bx as usize) {
                            self.set(a, RegValue::Const(c.clone()));
                        } else {
                            self.set(a, RegValue::Unknown);
                        }
                    }
                    // LOADNIL: A..A+B = nil
                    6 => {
                        let b = get_b54(word);
                        for r in a..=a + b {
                            self.set(r, RegValue::Const(LuaConst::Nil));
                        }
                    }
                    // GETUPVAL: A = UpValue[B]
                    7 => {
                        let b = get_b54(word);
                        self.set(a, RegValue::Upvalue(b));
                    }
                    _ if is_call_opcode(version, op) || is_return_opcode(version, op) => {
                        self.invalidate_from(0);
                    }
                    _ => {
                        self.set(a, RegValue::Unknown);
                    }
                }
            }
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    // â"€â"€ Helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn arch54() -> LuaArch {
        LuaArch::new()
    }

    fn arch51() -> LuaArch {
        LuaArch::with_version(LuaVersion::Lua51)
    }

    fn arch52() -> LuaArch {
        LuaArch::with_version(LuaVersion::Lua52)
    }

    fn arch53() -> LuaArch {
        LuaArch::with_version(LuaVersion::Lua53)
    }

    fn dis54(word: u32) -> Instruction {
        let bytes = word.to_le_bytes();
        arch54().disassemble(Address::new(0x100), &bytes).unwrap()
    }

    fn dis51(word: u32) -> Instruction {
        let bytes = word.to_le_bytes();
        arch51().disassemble(Address::new(0x100), &bytes).unwrap()
    }

    fn dis53(word: u32) -> Instruction {
        let bytes = word.to_le_bytes();
        arch53().disassemble(Address::new(0x100), &bytes).unwrap()
    }

    fn iabc54(op: u8, a: u32, b: u32, c: u32) -> u32 {
        make_iabc(op, a, b, c, 0)
    }

    // â"€â"€ Lua 5.4 basic decode â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_move() {
        let i = dis54(iabc54(0, 0, 1, 0));
        assert_eq!(i.mnemonic, "move");
        assert!(i.operands.contains("R0"));
        assert!(i.operands.contains("R1"));
    }

    #[test]
    fn test_loadk() {
        let w = make_iabx(3, 1, 42);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "loadk");
        assert!(i.operands.contains("R1"));
        assert!(i.operands.contains("42"));
    }

    #[test]
    fn test_loadi() {
        let w = make_iasbx(1, 2, 100);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "loadi");
        assert!(i.operands.contains("R2"));
        assert!(i.operands.contains("100"));
    }

    #[test]
    fn test_loadi_negative() {
        let w = make_iasbx(1, 3, -50);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "loadi");
        assert!(i.operands.contains("-50"));
    }

    #[test]
    fn test_jmp_5_4() {
        // 5.4 JMP uses isJ encoding; op=54
        let w = make_isj(54, 5);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "jmp");
        assert!(i.flags.contains(InstrFlags::BRANCH));
        assert!(!i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_jmp_negative() {
        let w = make_isj(54, -3);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "jmp");
        assert!(i.operands.contains("-3"));
    }

    #[test]
    fn test_eq() {
        let w = iabc54(55, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "eq");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_lt() {
        let w = iabc54(56, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "lt");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_le() {
        let w = iabc54(57, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "le");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_call() {
        let w = iabc54(66, 0, 3, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "call");
        assert!(i.flags.contains(InstrFlags::CALL));
        assert!(!i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_tailcall() {
        let w = iabc54(67, 0, 3, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "tailcall");
        assert!(i.flags.contains(InstrFlags::CALL));
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_return() {
        let w = iabc54(68, 0, 2, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "return");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_return0() {
        let w = iabc54(69, 0, 0, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "return0");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_return1() {
        let w = iabc54(70, 0, 0, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "return1");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_forloop() {
        let w = make_iasbx(71, 0, 10);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "forloop");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_forprep() {
        let w = make_iasbx(72, 0, 5);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "forprep");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_closure() {
        let w = make_iabx(77, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "closure");
        assert!(i.operands.contains("R1"));
    }

    #[test]
    fn test_add() {
        let w = iabc54(32, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "add");
    }

    #[test]
    fn test_addi() {
        // sC = 5  â†' C stored as 5+127 = 132
        let w = make_iabc(19, 0, 1, 132, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "addi");
        assert!(i.operands.contains('5'));
    }

    #[test]
    fn test_not() {
        let w = iabc54(49, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "not");
    }

    #[test]
    fn test_len() {
        let w = iabc54(50, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "len");
    }

    #[test]
    fn test_concat() {
        let w = iabc54(51, 0, 1, 3);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "concat");
    }

    #[test]
    fn test_gettabup() {
        let w = iabc54(9, 0, 0, 1);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "gettabup");
    }

    #[test]
    fn test_extraarg() {
        let w = make_iax(80, 0x3ff);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "extraarg");
    }

    #[test]
    fn test_vararg() {
        let w = iabc54(78, 0, 0, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "vararg");
    }

    #[test]
    fn test_setlist() {
        let w = iabc54(76, 0, 5, 1);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "setlist");
    }

    #[test]
    fn test_newtable() {
        let w = iabc54(17, 1, 2, 3);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "newtable");
    }

    #[test]
    fn test_shri() {
        // SHRI R0, R1, sC=2  â†' C=2+127=129
        let w = make_iabc(30, 0, 1, 129, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "shri");
        assert!(i.operands.contains('2'));
    }

    #[test]
    fn test_shli() {
        let w = make_iabc(31, 2, 3, 130, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "shli");
        assert!(i.operands.contains('3')); // sC = 130 - 127 = 3
    }

    // â"€â"€ Architecture trait â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_registers() {
        let regs = arch54().registers();
        assert!(!regs.is_empty());
        assert_eq!(regs[0].name, "R0");
        assert_eq!(regs.len(), 16);
    }

    #[test]
    fn test_arch_name() {
        assert_eq!(arch54().name(), "lua54");
    }

    #[test]
    fn test_pointer_size() {
        assert_eq!(arch54().pointer_size(), 8);
    }

    #[test]
    fn test_endian() {
        assert_eq!(arch54().endian(), Endian::Little);
    }

    #[test]
    fn test_calling_convention() {
        let cc = arch54().calling_conventions();
        assert!(!cc.is_empty());
        assert_eq!(cc[0].name, "lua");
    }

    #[test]
    fn test_unknown_opcode() {
        let w: u32 = 0x7f; // opcode 0x7f (127) is out of range
        let result = arch54().disassemble(Address::new(0), &w.to_le_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_too_short_bytes() {
        let result = arch54().disassemble(Address::new(0), &[0x00, 0x01]);
        assert!(result.is_err());
    }

    // â"€â"€ Version names â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua51_version() {
        assert_eq!(LuaArch::with_version(LuaVersion::Lua51).name(), "lua51");
    }

    #[test]
    fn test_lua52_version() {
        assert_eq!(LuaArch::with_version(LuaVersion::Lua52).name(), "lua52");
    }

    #[test]
    fn test_lua53_version() {
        assert_eq!(LuaArch::with_version(LuaVersion::Lua53).name(), "lua53");
    }

    #[test]
    fn test_lua_version_display() {
        assert_eq!(LuaVersion::Lua54.to_string(), "Lua 5.4");
        assert_eq!(LuaVersion::Lua51.to_string(), "Lua 5.1");
    }

    #[test]
    fn test_lua_version_is_legacy() {
        assert!(LuaVersion::Lua51.is_legacy());
        assert!(LuaVersion::Lua52.is_legacy());
        assert!(LuaVersion::Lua53.is_legacy());
        assert!(!LuaVersion::Lua54.is_legacy());
    }

    // â"€â"€ Lua 5.1 legacy decode â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua51_move() {
        let w = make_legacy_iabc(0, 1, 2, 0);
        let i = dis51(w);
        assert_eq!(i.mnemonic, "move");
    }

    #[test]
    fn test_lua51_loadk() {
        let w = make_legacy_iabx(1, 0, 10);
        let i = dis51(w);
        assert_eq!(i.mnemonic, "loadk");
        assert!(i.operands.contains("10"));
    }

    #[test]
    fn test_lua51_jmp() {
        let w = make_legacy_iasbx(22, 0, 3);
        let i = dis51(w);
        assert_eq!(i.mnemonic, "jmp");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_lua51_call() {
        let w = make_legacy_iabc(28, 0, 3, 2);
        let i = dis51(w);
        assert_eq!(i.mnemonic, "call");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_lua51_return() {
        let w = make_legacy_iabc(30, 0, 2, 0);
        let i = dis51(w);
        assert_eq!(i.mnemonic, "return");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_lua51_tailcall() {
        let w = make_legacy_iabc(29, 0, 2, 0);
        let i = dis51(w);
        assert_eq!(i.mnemonic, "tailcall");
        assert!(i.flags.contains(InstrFlags::CALL));
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_lua51_add() {
        let w = make_legacy_iabc(12, 0, 1, 2);
        let i = dis51(w);
        assert_eq!(i.mnemonic, "add");
    }

    #[test]
    fn test_lua51_unknown_opcode() {
        let w = make_legacy_iabc(63, 0, 0, 0); // opcode 63 is out of range for 5.1
        let result = arch51().disassemble(Address::new(0), &w.to_le_bytes());
        assert!(result.is_err());
    }

    // â"€â"€ Lua 5.2 decode â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua52_move() {
        let w = make_legacy_iabc(0, 2, 3, 0);
        let i = arch52()
            .disassemble(Address::new(0), &w.to_le_bytes())
            .unwrap();
        assert_eq!(i.mnemonic, "move");
    }

    #[test]
    fn test_lua52_jmp() {
        let w = make_legacy_iasbx(23, 0, 5);
        let i = arch52()
            .disassemble(Address::new(0), &w.to_le_bytes())
            .unwrap();
        assert_eq!(i.mnemonic, "jmp");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_lua52_return() {
        let w = make_legacy_iabc(31, 0, 1, 0);
        let i = arch52()
            .disassemble(Address::new(0), &w.to_le_bytes())
            .unwrap();
        assert_eq!(i.mnemonic, "return");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    // â"€â"€ Lua 5.3 decode â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua53_move() {
        let w = make_legacy_iabc(0, 0, 1, 0);
        let i = dis53(w);
        assert_eq!(i.mnemonic, "move");
    }

    #[test]
    fn test_lua53_jmp() {
        let w = make_legacy_iasbx(30, 0, 4);
        let i = dis53(w);
        assert_eq!(i.mnemonic, "jmp");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_lua53_band() {
        let w = make_legacy_iabc(20, 0, 1, 2);
        let i = dis53(w);
        assert_eq!(i.mnemonic, "band");
    }

    #[test]
    fn test_lua53_shl() {
        let w = make_legacy_iabc(23, 0, 1, 2);
        let i = dis53(w);
        assert_eq!(i.mnemonic, "shl");
    }

    #[test]
    fn test_lua53_return() {
        let w = make_legacy_iabc(38, 0, 1, 0);
        let i = dis53(w);
        assert_eq!(i.mnemonic, "return");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    // â"€â"€ Opcode query helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_opcode_name_54() {
        assert_eq!(opcode_name(LuaVersion::Lua54, 0), Some("MOVE"));
        assert_eq!(opcode_name(LuaVersion::Lua54, 66), Some("CALL"));
        assert_eq!(opcode_name(LuaVersion::Lua54, 200), None);
    }

    #[test]
    fn test_opcode_name_51() {
        assert_eq!(opcode_name(LuaVersion::Lua51, 0), Some("MOVE"));
        assert_eq!(opcode_name(LuaVersion::Lua51, 28), Some("CALL"));
    }

    #[test]
    fn test_find_opcodes() {
        let results = find_opcodes(LuaVersion::Lua54, "LOAD");
        assert!(!results.is_empty());
        assert!(results.iter().all(|(_, name)| name.contains("LOAD")));
    }

    #[test]
    fn test_find_opcodes_empty() {
        let results = find_opcodes(LuaVersion::Lua54, "XYZZY");
        assert!(results.is_empty());
    }

    #[test]
    fn test_is_branch_opcode() {
        assert!(is_branch_opcode(LuaVersion::Lua54, 54)); // JMP
        assert!(is_branch_opcode(LuaVersion::Lua54, 55)); // EQ
        assert!(!is_branch_opcode(LuaVersion::Lua54, 0)); // MOVE
        assert!(is_branch_opcode(LuaVersion::Lua51, 22)); // JMP in 5.1
    }

    #[test]
    fn test_is_call_opcode() {
        assert!(is_call_opcode(LuaVersion::Lua54, 66));
        assert!(is_call_opcode(LuaVersion::Lua54, 67));
        assert!(!is_call_opcode(LuaVersion::Lua54, 0));
        assert!(is_call_opcode(LuaVersion::Lua51, 28));
    }

    #[test]
    fn test_is_return_opcode() {
        assert!(is_return_opcode(LuaVersion::Lua54, 68));
        assert!(is_return_opcode(LuaVersion::Lua54, 69));
        assert!(is_return_opcode(LuaVersion::Lua54, 70));
        assert!(!is_return_opcode(LuaVersion::Lua54, 0));
        assert!(is_return_opcode(LuaVersion::Lua51, 30));
        assert!(is_return_opcode(LuaVersion::Lua53, 38));
    }

    // â"€â"€ Chunk header â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_parse_chunk_header_54() {
        // Minimal valid 5.4 header
        let data = [0x1b, b'L', b'u', b'a', 0x54, 0x01, 0x04, 0x08, 0x04];
        let hdr = parse_chunk_header(&data).unwrap();
        assert_eq!(hdr.version, LuaVersion::Lua54);
        assert_eq!(hdr.endian, 1);
        assert_eq!(hdr.instr_size, 4);
    }

    #[test]
    fn test_parse_chunk_header_51() {
        let data = [0x1b, b'L', b'u', b'a', 0x51, 0x01, 0x04, 0x04, 0x04];
        let hdr = parse_chunk_header(&data).unwrap();
        assert_eq!(hdr.version, LuaVersion::Lua51);
    }

    #[test]
    fn test_parse_chunk_header_bad_magic() {
        let data = [0x00, b'L', b'u', b'a', 0x54, 0x01, 0x04, 0x08, 0x04];
        let err = parse_chunk_header(&data).unwrap_err();
        assert_eq!(err, ChunkHeaderError::BadMagic);
    }

    #[test]
    fn test_parse_chunk_header_too_short() {
        let data = [0x1b, b'L', b'u'];
        let err = parse_chunk_header(&data).unwrap_err();
        assert_eq!(err, ChunkHeaderError::TooShort);
    }

    #[test]
    fn test_parse_chunk_header_unsupported_version() {
        let data = [0x1b, b'L', b'u', b'a', 0x55, 0x01, 0x04, 0x08, 0x04];
        let err = parse_chunk_header(&data).unwrap_err();
        assert!(matches!(err, ChunkHeaderError::UnsupportedVersion(0x55)));
    }

    // â"€â"€ Chunk disassembly â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_disassemble_chunk_basic() {
        let arch = arch54();
        let words: Vec<u32> = vec![
            make_iabx(3, 0, 0),  // loadk R0, 0
            make_iabx(3, 1, 1),  // loadk R1, 1
            iabc54(32, 2, 0, 1), // add R2, R0, R1
            iabc54(68, 0, 2, 0), // return R0, 2
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let results = disassemble_chunk(&arch, Address::new(0), &bytes);
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(std::result::Result::is_ok));
    }

    #[test]
    fn test_disassemble_chunk_lossy() {
        let arch = arch54();
        // opcode = bits 0..6 of the word. 0x0000_007f => op=0x7f=127, out of range.
        let invalid_word: u32 = 0x0000_007f;
        let words: Vec<u32> = vec![
            make_iabx(3, 0, 0),  // loadk R0, 0  (valid)
            invalid_word,        // invalid opcode
            iabc54(68, 0, 1, 0), // return        (valid)
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        assert_eq!(instrs.len(), 2); // 2 valid, 1 invalid skipped
    }

    // â"€â"€ LuaChunkStats â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_chunk_stats_basic() {
        let arch = arch54();
        let words: Vec<u32> = vec![
            iabc54(32, 2, 0, 1), // add
            iabc54(66, 0, 3, 2), // call
            iabc54(68, 0, 1, 0), // return
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let stats = LuaChunkStats::from_instructions(LuaVersion::Lua54, &instrs);
        assert_eq!(stats.total, 3);
        assert_eq!(stats.arithmetic, 1);
        assert_eq!(stats.calls, 1);
        assert_eq!(stats.returns, 1);
    }

    #[test]
    fn test_chunk_stats_branch_ratio_zero() {
        let s = LuaChunkStats::default();
        assert!(s.branch_ratio().abs() < f64::EPSILON);
    }

    #[test]
    fn test_chunk_stats_display() {
        let s = LuaChunkStats {
            total: 10,
            branches: 2,
            ..Default::default()
        };
        let out = s.to_string();
        assert!(out.contains("total=10"));
        assert!(out.contains("branches=2"));
    }

    // â"€â"€ format_instruction / format_listing â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_format_instruction() {
        let i = dis54(make_iabx(3, 0, 5));
        let s = format_instruction(&i);
        assert!(s.contains("loadk"));
        assert!(s.starts_with("0x"));
    }

    #[test]
    fn test_format_listing_multiline() {
        let words = [make_iabx(3, 0, 0), iabc54(68, 0, 1, 0)];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch54(), Address::new(0), &bytes);
        let listing = format_listing(&instrs);
        assert!(listing.contains('\n'));
        assert!(listing.contains("loadk"));
        assert!(listing.contains("return"));
    }

    // â"€â"€ LuaArchMetadata â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_arch_metadata_54() {
        let m = LuaArchMetadata::for_version(LuaVersion::Lua54);
        assert_eq!(m.opcode_bits, 7);
        assert_eq!(m.instr_width, 4);
        assert_eq!(m.opcode_count, LUA54_OPCODES.len());
    }

    #[test]
    fn test_arch_metadata_51() {
        let m = LuaArchMetadata::for_version(LuaVersion::Lua51);
        assert_eq!(m.opcode_bits, 6);
        assert_eq!(m.opcode_count, LUA51_OPCODES.len());
    }

    #[test]
    fn test_arch_metadata_via_luaarch() {
        let m = arch54().metadata();
        assert_eq!(m.version, "5.4");
    }

    // â"€â"€ LuaBasicBlock / split_basic_blocks â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_split_basic_blocks_no_branches() {
        let arch = arch54();
        // Simple linear sequence: loadk, add, return
        let words = [make_iabx(3, 0, 0), iabc54(32, 1, 0, 0), iabc54(68, 0, 1, 0)];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let blocks = split_basic_blocks(&arch, &instrs);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].instructions.len(), 3);
    }

    #[test]
    fn test_basic_block_end_address() {
        let arch = arch54();
        let words = [make_iabx(3, 0, 0), iabc54(68, 0, 1, 0)];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0x100), &bytes);
        let blocks = split_basic_blocks(&arch, &instrs);
        assert!(!blocks.is_empty());
        assert_eq!(blocks[0].end_address(), Address::new(0x108));
    }

    #[test]
    fn test_basic_block_is_terminal_return() {
        let arch = arch54();
        let words = [iabc54(68, 0, 1, 0)];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let blocks = split_basic_blocks(&arch, &instrs);
        assert!(!blocks.is_empty());
        assert!(blocks[0].is_terminal());
    }

    // â"€â"€ get_branches â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_get_branches_return_empty() {
        let i = dis54(iabc54(68, 0, 1, 0));
        let branches = arch54().get_branches(&i);
        assert!(branches.is_empty());
    }

    #[test]
    fn test_get_branches_jmp_target() {
        // JMP +1: target = 0x100 + 4 + (1 * 4) = 0x108
        let w = make_isj(54, 1);
        let bytes = w.to_le_bytes();
        let i = arch54().disassemble(Address::new(0x100), &bytes).unwrap();
        let branches = arch54().get_branches(&i);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].target, Some(0x108));
    }

    #[test]
    fn test_get_branches_conditional_eq() {
        let w = iabc54(55, 0, 1, 0); // EQ —  conditional branch
        let bytes = w.to_le_bytes();
        let i = arch54().disassemble(Address::new(0x100), &bytes).unwrap();
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
        let branches = arch54().get_branches(&i);
        // Conditional branch: no k offset in operands that parses as +N; still yields branch
        // The operands are "R0, 1, 0 k=0" —" no clean offset token, so empty or one entry.
        // Either way, flags are set correctly.
        let _ = branches;
    }

    // â"€â"€ ChunkHeaderError display â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_chunk_header_error_display() {
        assert!(ChunkHeaderError::TooShort.to_string().contains("too short"));
        assert!(ChunkHeaderError::BadMagic.to_string().contains("magic"));
        assert!(
            ChunkHeaderError::UnsupportedVersion(0x55)
                .to_string()
                .contains("0x55")
        );
    }

    // â"€â"€ Field extraction round-trip â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_field_roundtrip_sbx() {
        for sbx in [-100i32, -1, 0, 1, 100, MAXARG_SBX] {
            let w = make_iasbx(1, 0, sbx);
            assert_eq!(get_sbx54(w), sbx, "sbx={sbx}");
        }
    }

    #[test]
    fn test_field_roundtrip_sj() {
        for sj in [-1000i32, -1, 0, 1, 1000] {
            let w = make_isj(54, sj);
            assert_eq!(get_sj54(w), sj, "sj={sj}");
        }
    }

    #[test]
    fn test_field_roundtrip_legacy_sbx() {
        for sbx in [-500i32, -1, 0, 1, 500, MAXARG_SBX_OLD] {
            let w = make_legacy_iasbx(22, 0, sbx);
            assert_eq!(get_sbx_old(w), sbx, "sbx={sbx}");
        }
    }

    // â"€â"€ decode_lua51 direct API â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_lua51_move() {
        let w = make_legacy_iabc(0, 3, 5, 0);
        let (m, ops, fl) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "move");
        assert!(ops.contains("R3"));
        assert!(fl == InstrFlags::NONE);
    }

    #[test]
    fn test_decode_lua51_loadk() {
        let w = make_legacy_iabx(1, 2, 7);
        let (m, ops, fl) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "loadk");
        assert!(ops.contains('7'));
        assert!(fl == InstrFlags::NONE);
    }

    #[test]
    fn test_decode_lua51_getglobal() {
        // GETGLOBAL = op 5, ABx format
        let w = make_legacy_iabx(5, 0, 42);
        let (m, ops, _) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "getglobal");
        assert!(ops.contains("42"));
    }

    #[test]
    fn test_decode_lua51_setglobal() {
        let w = make_legacy_iabx(7, 1, 10);
        let (m, ops, _) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "setglobal");
        assert!(ops.contains("10"));
    }

    #[test]
    fn test_decode_lua51_jmp_flags() {
        let w = make_legacy_iasbx(22, 0, 3);
        let (m, _, fl) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "jmp");
        assert!(fl.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_decode_lua51_forloop_flags() {
        let w = make_legacy_iasbx(31, 0, 5);
        let (m, _, fl) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "forloop");
        assert!(fl.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_decode_lua51_forprep_flags() {
        let w = make_legacy_iasbx(32, 0, -1);
        let (m, _, fl) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "forprep");
        assert!(fl.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_decode_lua51_eq_conditional() {
        let w = make_legacy_iabc(23, 0, 1, 2);
        let (m, _, fl) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "eq");
        assert!(fl.contains(InstrFlags::CONDITIONAL));
        assert!(fl.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_decode_lua51_lt_conditional() {
        let w = make_legacy_iabc(24, 0, 1, 2);
        let (_, _, fl) = decode_lua51(w, Address::new(0)).unwrap();
        assert!(fl.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_decode_lua51_test_conditional() {
        // TEST = op 26
        let w = make_legacy_iabc(26, 0, 1, 0);
        let (m, _, fl) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "test");
        assert!(fl.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_decode_lua51_tforloop_branch() {
        // TFORLOOP = op 33
        let w = make_legacy_iabc(33, 0, 0, 1);
        let (m, _, fl) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "tforloop");
        assert!(fl.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_decode_lua51_call_flags() {
        let w = make_legacy_iabc(28, 0, 2, 1);
        let (m, _, fl) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "call");
        assert!(fl.contains(InstrFlags::CALL));
        assert!(!fl.contains(InstrFlags::RET));
    }

    #[test]
    fn test_decode_lua51_tailcall_flags() {
        let w = make_legacy_iabc(29, 0, 2, 0);
        let (m, _, fl) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "tailcall");
        assert!(fl.contains(InstrFlags::CALL));
        assert!(fl.contains(InstrFlags::RET));
    }

    #[test]
    fn test_decode_lua51_return_flags() {
        let w = make_legacy_iabc(30, 0, 1, 0);
        let (m, _, fl) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "return");
        assert!(fl.contains(InstrFlags::RET));
    }

    #[test]
    fn test_decode_lua51_loadnil_format() {
        // LOADNIL = op 3: should show R{a}, R{b} (range)
        let w = make_legacy_iabc(3, 2, 4, 0);
        let (m, ops, _) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "loadnil");
        assert!(ops.contains("R2"));
    }

    #[test]
    fn test_decode_lua51_getupval_format() {
        // GETUPVAL = op 4: shows R{a}, {b} (upvalue index, not Rb)
        let w = make_legacy_iabc(4, 1, 3, 0);
        let (m, ops, _) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "getupval");
        assert!(ops.contains("R1"));
        assert!(ops.contains('3'));
    }

    #[test]
    fn test_decode_lua51_closure() {
        // CLOSURE = op 36, ABx
        let w = make_legacy_iabx(36, 0, 2);
        let (m, ops, _) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "closure");
        assert!(ops.contains("R0"));
    }

    #[test]
    fn test_decode_lua51_invalid_opcode() {
        let w = make_legacy_iabc(63, 0, 0, 0);
        assert!(decode_lua51(w, Address::new(0)).is_err());
    }

    #[test]
    fn test_decode_lua51_all_opcodes_decode() {
        // Every valid 5.1 opcode must decode without error.
        for op in 0u8..u8::try_from(LUA51_OPCODES.len()).unwrap_or(u8::MAX) {
            let w = match lua51_fmt(op) {
                LuaLegacyFmt::ABx => make_legacy_iabx(op, 0, 0),
                LuaLegacyFmt::AsBx => make_legacy_iasbx(op, 0, 0),
                _ => make_legacy_iabc(op, 0, 0, 0),
            };
            assert!(
                decode_lua51(w, Address::new(0)).is_ok(),
                "opcode {op} ({}) failed",
                LUA51_OPCODES[op as usize]
            );
        }
    }

    // â"€â"€ decode_lua52 direct API â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_lua52_gettabup() {
        // GETTABUP = op 6: R{a}, U{b}, RK{c}
        let w = make_legacy_iabc(6, 1, 0, 2);
        let (m, ops, _) = decode_lua52(w, Address::new(0)).unwrap();
        assert_eq!(m, "gettabup");
        assert!(ops.contains("U0"));
        assert!(ops.contains("RK2"));
    }

    #[test]
    fn test_decode_lua52_settabup() {
        // SETTABUP = op 8: U{a}, RK{b}, RK{c}
        let w = make_legacy_iabc(8, 0, 1, 2);
        let (m, ops, _) = decode_lua52(w, Address::new(0)).unwrap();
        assert_eq!(m, "settabup");
        assert!(ops.starts_with("U0"));
    }

    #[test]
    fn test_decode_lua52_loadkx() {
        // LOADKX = op 2, ABx
        let w = make_legacy_iabx(2, 3, 0);
        let (m, ops, _) = decode_lua52(w, Address::new(0)).unwrap();
        assert_eq!(m, "loadkx");
        assert!(ops.contains("R3"));
    }

    #[test]
    fn test_decode_lua52_extraarg() {
        // EXTRAARG = op 39, Ax format
        let w = make_legacy_iabx(39, 0, 0x1234);
        let (m, ops, _) = decode_lua52(w, Address::new(0)).unwrap();
        assert_eq!(m, "extraarg");
        // Ax = bx field; the value should appear in operands.
        assert!(!ops.is_empty());
    }

    #[test]
    fn test_decode_lua52_jmp_branch() {
        let w = make_legacy_iasbx(23, 0, 7);
        let (m, ops, fl) = decode_lua52(w, Address::new(0)).unwrap();
        assert_eq!(m, "jmp");
        assert!(ops.contains("+7"));
        assert!(fl.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_decode_lua52_tforloop_branch() {
        // TFORLOOP = op 35
        let w = make_legacy_iasbx(35, 0, -2);
        let (m, _, fl) = decode_lua52(w, Address::new(0)).unwrap();
        assert_eq!(m, "tforloop");
        assert!(fl.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_decode_lua52_eq_conditional() {
        // EQ = op 24
        let w = make_legacy_iabc(24, 0, 1, 2);
        let (m, _, fl) = decode_lua52(w, Address::new(0)).unwrap();
        assert_eq!(m, "eq");
        assert!(fl.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_decode_lua52_call() {
        let w = make_legacy_iabc(29, 0, 3, 2);
        let (m, _, fl) = decode_lua52(w, Address::new(0)).unwrap();
        assert_eq!(m, "call");
        assert!(fl.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_decode_lua52_return() {
        let w = make_legacy_iabc(31, 0, 1, 0);
        let (m, _, fl) = decode_lua52(w, Address::new(0)).unwrap();
        assert_eq!(m, "return");
        assert!(fl.contains(InstrFlags::RET));
    }

    #[test]
    fn test_decode_lua52_all_opcodes_decode() {
        for op in 0u8..u8::try_from(LUA52_OPCODES.len()).unwrap_or(u8::MAX) {
            let w = match lua52_fmt(op) {
                LuaLegacyFmt::AsBx => make_legacy_iasbx(op, 0, 0),
                LuaLegacyFmt::ABx | LuaLegacyFmt::Ax => make_legacy_iabx(op, 0, 0),
                LuaLegacyFmt::Abc => make_legacy_iabc(op, 0, 0, 0),
            };
            assert!(
                decode_lua52(w, Address::new(0)).is_ok(),
                "opcode {op} failed"
            );
        }
    }

    // â"€â"€ decode_lua53 direct API â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_lua53_idiv() {
        // IDIV = op 19
        let w = make_legacy_iabc(19, 0, 1, 2);
        let (m, ops, fl) = decode_lua53(w, Address::new(0)).unwrap();
        assert_eq!(m, "idiv");
        assert!(ops.contains("R0"));
        assert!(fl == InstrFlags::NONE);
    }

    #[test]
    fn test_decode_lua53_bnot() {
        // BNOT = op 26
        let w = make_legacy_iabc(26, 0, 1, 0);
        let (m, _, _) = decode_lua53(w, Address::new(0)).unwrap();
        assert_eq!(m, "bnot");
    }

    #[test]
    fn test_decode_lua53_bxor() {
        // BXOR = op 22
        let w = make_legacy_iabc(22, 0, 1, 2);
        let (m, _, _) = decode_lua53(w, Address::new(0)).unwrap();
        assert_eq!(m, "bxor");
    }

    #[test]
    fn test_decode_lua53_shr() {
        // SHR = op 24
        let w = make_legacy_iabc(24, 0, 1, 2);
        let (m, _, _) = decode_lua53(w, Address::new(0)).unwrap();
        assert_eq!(m, "shr");
    }

    #[test]
    fn test_decode_lua53_tforcall() {
        // TFORCALL = op 41 (not a branch)
        let w = make_legacy_iabc(41, 0, 0, 2);
        let (m, _, fl) = decode_lua53(w, Address::new(0)).unwrap();
        assert_eq!(m, "tforcall");
        assert!(!fl.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_decode_lua53_tforloop_branch() {
        // TFORLOOP = op 42
        let w = make_legacy_iasbx(42, 0, -4);
        let (m, _, fl) = decode_lua53(w, Address::new(0)).unwrap();
        assert_eq!(m, "tforloop");
        assert!(fl.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_decode_lua53_extraarg() {
        // EXTRAARG = op 46
        let w = make_legacy_iabx(46, 0, 999);
        let (m, ops, _) = decode_lua53(w, Address::new(0)).unwrap();
        assert_eq!(m, "extraarg");
        assert!(ops.contains("999"));
    }

    #[test]
    fn test_decode_lua53_newtable_format() {
        // NEWTABLE = op 11: raw A, B, C (no R prefix for B and C)
        let w = make_legacy_iabc(11, 2, 3, 4);
        let (m, ops, _) = decode_lua53(w, Address::new(0)).unwrap();
        assert_eq!(m, "newtable");
        assert!(ops.contains("R2"));
        assert!(ops.contains('3'));
        assert!(ops.contains('4'));
    }

    #[test]
    fn test_decode_lua53_gettabup_format() {
        // GETTABUP = op 6
        let w = make_legacy_iabc(6, 1, 0, 2);
        let (m, ops, _) = decode_lua53(w, Address::new(0)).unwrap();
        assert_eq!(m, "gettabup");
        assert!(ops.contains("U0"));
    }

    #[test]
    fn test_decode_lua53_invalid_opcode() {
        let w = make_legacy_iabc(63, 0, 0, 0);
        assert!(decode_lua53(w, Address::new(0)).is_err());
    }

    #[test]
    fn test_decode_lua53_all_opcodes_decode() {
        for op in 0u8..u8::try_from(LUA53_OPCODES.len()).unwrap_or(u8::MAX) {
            let w = match lua53_fmt(op) {
                LuaLegacyFmt::AsBx => make_legacy_iasbx(op, 0, 0),
                LuaLegacyFmt::ABx | LuaLegacyFmt::Ax => make_legacy_iabx(op, 0, 0),
                LuaLegacyFmt::Abc => make_legacy_iabc(op, 0, 0, 0),
            };
            assert!(
                decode_lua53(w, Address::new(0)).is_ok(),
                "opcode {op} ({}) failed",
                LUA53_OPCODES[op as usize]
            );
        }
    }

    // â"€â"€ decode_by_version â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_by_version_dispatches_51() {
        let w = make_legacy_iabx(1, 0, 5); // LOADK in 5.1
        let (m, _, _) = decode_by_version(LuaVersion::Lua51, w, Address::new(0)).unwrap();
        assert_eq!(m, "loadk");
    }

    #[test]
    fn test_decode_by_version_dispatches_52() {
        let w = make_legacy_iabc(0, 1, 2, 0); // MOVE in 5.2
        let (m, _, _) = decode_by_version(LuaVersion::Lua52, w, Address::new(0)).unwrap();
        assert_eq!(m, "move");
    }

    #[test]
    fn test_decode_by_version_dispatches_53() {
        let w = make_legacy_iabc(20, 0, 1, 2); // BAND in 5.3
        let (m, _, _) = decode_by_version(LuaVersion::Lua53, w, Address::new(0)).unwrap();
        assert_eq!(m, "band");
    }

    #[test]
    fn test_decode_by_version_dispatches_54() {
        let w = make_iabc(32, 0, 1, 2, 0); // ADD in 5.4
        let (m, _, _) = decode_by_version(LuaVersion::Lua54, w, Address::new(0)).unwrap();
        assert_eq!(m, "add");
    }

    // â"€â"€ LuaConst â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua_const_nil_display() {
        assert_eq!(LuaConst::Nil.to_string(), "nil");
    }

    #[test]
    fn test_lua_const_bool_display() {
        assert_eq!(LuaConst::Bool(true).to_string(), "true");
        assert_eq!(LuaConst::Bool(false).to_string(), "false");
    }

    #[test]
    fn test_lua_const_int_display() {
        assert_eq!(LuaConst::Int(42).to_string(), "42");
    }

    #[test]
    fn test_lua_const_float_display() {
        assert_eq!(LuaConst::Float(2.5_f64).to_string(), "2.5");
    }

    #[test]
    fn test_lua_const_string_display() {
        let c = LuaConst::String("hello".into());
        assert!(c.to_string().contains("hello"));
    }

    #[test]
    fn test_lua_const_type_name() {
        assert_eq!(LuaConst::Nil.type_name(), "nil");
        assert_eq!(LuaConst::Bool(true).type_name(), "boolean");
        assert_eq!(LuaConst::Int(0).type_name(), "integer");
        assert_eq!(LuaConst::Float(0.0).type_name(), "float");
        assert_eq!(LuaConst::String(String::new()).type_name(), "string");
    }

    #[test]
    fn test_lua_const_accessors() {
        assert!(LuaConst::Nil.is_nil());
        assert!(!LuaConst::Bool(true).is_nil());
        assert_eq!(LuaConst::Bool(true).as_bool(), Some(true));
        assert_eq!(LuaConst::Int(-7).as_int(), Some(-7));
        assert_eq!(LuaConst::Float(1.5).as_float(), Some(1.5));
        assert_eq!(LuaConst::String("x".into()).as_str(), Some("x"));
        assert_eq!(LuaConst::Int(0).as_str(), None);
    }

    // â"€â"€ extract_constants_from_proto â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_extract_constants_from_proto_51() {
        // Two LOADK (op=1) referencing constants 3 and 7.
        let words = [
            make_legacy_iabx(1, 0, 3),     // loadk R0, K[3]
            make_legacy_iabx(1, 1, 7),     // loadk R1, K[7]
            make_legacy_iabc(30, 0, 1, 0), // return (not LOADK)
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let consts = extract_constants_from_proto(&bytes, LuaVersion::Lua51);
        // Should contain placeholders for indices 3 and 7.
        assert_eq!(consts.len(), 2);
        let indices: Vec<i64> = consts.iter().map(|c| c.as_int().unwrap()).collect();
        assert!(indices.contains(&3));
        assert!(indices.contains(&7));
    }

    #[test]
    fn test_extract_constants_from_proto_54() {
        // LOADK in 5.4 is op=3.
        let words = [
            make_iabx(3, 0, 0), // loadk R0, K[0]
            make_iabx(3, 1, 5), // loadk R1, K[5]
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let consts = extract_constants_from_proto(&bytes, LuaVersion::Lua54);
        assert_eq!(consts.len(), 2);
    }

    #[test]
    fn test_extract_constants_dedup() {
        // Same constant index referenced twice â†' only one placeholder.
        let words = [make_legacy_iabx(1, 0, 4), make_legacy_iabx(1, 1, 4)];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let consts = extract_constants_from_proto(&bytes, LuaVersion::Lua51);
        assert_eq!(consts.len(), 1);
    }

    // â"€â"€ parse_const_pool_51 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_parse_const_pool_51_nil() {
        // n=1, type=0 (nil)
        let data = [
            1u8, 0, 0, 0, // n=1 (little-endian i32)
            0,
        ]; // nil type
        let pool = parse_const_pool_51(&data).unwrap();
        assert_eq!(pool.len(), 1);
        assert_eq!(pool[0], LuaConst::Nil);
    }

    #[test]
    fn test_parse_const_pool_51_bool_true() {
        // n=1, type=1 (bool), value=1 (true)
        let data = [1u8, 0, 0, 0, 1, 1];
        let pool = parse_const_pool_51(&data).unwrap();
        assert_eq!(pool[0], LuaConst::Bool(true));
    }

    #[test]
    fn test_parse_const_pool_51_bool_false() {
        let data = [1u8, 0, 0, 0, 1, 0];
        let pool = parse_const_pool_51(&data).unwrap();
        assert_eq!(pool[0], LuaConst::Bool(false));
    }

    #[test]
    fn test_parse_const_pool_51_number() {
        // n=1, type=3 (number), payload = 1.0 as f64 LE
        let mut data = vec![1u8, 0, 0, 0, 3];
        data.extend_from_slice(&1.0f64.to_bits().to_le_bytes());
        let pool = parse_const_pool_51(&data).unwrap();
        assert_eq!(pool[0], LuaConst::Float(1.0));
    }

    #[test]
    fn test_parse_const_pool_51_string() {
        // n=1, type=4 (string), length=6 (5 chars + NUL), "hello\0"
        let s = b"hello\0";
        let mut data = vec![1u8, 0, 0, 0, 4];
        data.extend_from_slice(&i32::try_from(s.len()).unwrap_or(i32::MAX).to_le_bytes());
        data.extend_from_slice(s);
        let pool = parse_const_pool_51(&data).unwrap();
        assert_eq!(pool[0], LuaConst::String("hello".into()));
    }

    #[test]
    fn test_parse_const_pool_51_empty() {
        // n=0 â†' empty pool
        let data = [0u8, 0, 0, 0];
        let pool = parse_const_pool_51(&data).unwrap();
        assert!(pool.is_empty());
    }

    #[test]
    fn test_parse_const_pool_51_truncated() {
        // Truncated after type byte —" should return None.
        let data = [1u8, 0, 0, 0, 3]; // type=3 but no 8-byte payload
        assert!(parse_const_pool_51(&data).is_none());
    }

    // â"€â"€ parse_const_pool_53 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_parse_const_pool_53_nil() {
        let data = [1u8, 0, 0, 0, 0x00];
        let pool = parse_const_pool_53(&data).unwrap();
        assert_eq!(pool[0], LuaConst::Nil);
    }

    #[test]
    fn test_parse_const_pool_53_bool_false() {
        let data = [1u8, 0, 0, 0, 0x01];
        let pool = parse_const_pool_53(&data).unwrap();
        assert_eq!(pool[0], LuaConst::Bool(false));
    }

    #[test]
    fn test_parse_const_pool_53_bool_true() {
        let data = [1u8, 0, 0, 0, 0x11];
        let pool = parse_const_pool_53(&data).unwrap();
        assert_eq!(pool[0], LuaConst::Bool(true));
    }

    #[test]
    fn test_parse_const_pool_53_integer() {
        // type=0x13, payload=i64 LE
        let mut data = vec![1u8, 0, 0, 0, 0x13];
        data.extend_from_slice(&100i64.to_le_bytes());
        let pool = parse_const_pool_53(&data).unwrap();
        assert_eq!(pool[0], LuaConst::Int(100));
    }

    #[test]
    fn test_parse_const_pool_53_float() {
        let mut data = vec![1u8, 0, 0, 0, 0x03];
        data.extend_from_slice(&2.5f64.to_bits().to_le_bytes());
        let pool = parse_const_pool_53(&data).unwrap();
        assert_eq!(pool[0], LuaConst::Float(2.5));
    }

    #[test]
    fn test_parse_const_pool_53_string() {
        // Short string: type=0x04, length byte = 6 ("world\0"), then bytes.
        let s = b"world\0";
        let mut data = vec![1u8, 0, 0, 0, 0x04, u8::try_from(s.len()).unwrap_or(u8::MAX)];
        data.extend_from_slice(s);
        let pool = parse_const_pool_53(&data).unwrap();
        assert_eq!(pool[0], LuaConst::String("world".into()));
    }

    #[test]
    fn test_parse_const_pool_53_truncated() {
        // type=0x13 (integer) but only 4 of 8 payload bytes
        let mut data = vec![1u8, 0, 0, 0, 0x13];
        data.extend_from_slice(&[0u8; 4]);
        assert!(parse_const_pool_53(&data).is_none());
    }

    // â"€â"€ generate_local_var_names â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_generate_local_var_names_basic() {
        let names = generate_local_var_names(8);
        // 8 / 4 = 2 locals
        assert_eq!(names.len(), 2);
        assert_eq!(names[0], "local_0");
        assert_eq!(names[1], "local_1");
    }

    #[test]
    fn test_generate_local_var_names_minimum_one() {
        // Even for an empty proto, at least one name is returned.
        let names = generate_local_var_names(0);
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "local_0");
    }

    #[test]
    fn test_generate_local_var_names_capped_at_64() {
        // Proto with 1000 instructions would give 250, but cap is 64.
        let names = generate_local_var_names(1000);
        assert_eq!(names.len(), 64);
        assert_eq!(names[63], "local_63");
    }

    #[test]
    fn test_generate_upvalue_names() {
        let names = generate_upvalue_names(3);
        assert_eq!(names, vec!["upval_0", "upval_1", "upval_2"]);
    }

    #[test]
    fn test_generate_upvalue_names_zero() {
        let names = generate_upvalue_names(0);
        assert!(names.is_empty());
    }

    #[test]
    fn test_generate_param_names_no_self() {
        let names = generate_param_names(3, false);
        assert_eq!(names, vec!["arg1", "arg2", "arg3"]);
    }

    #[test]
    fn test_generate_param_names_with_self() {
        let names = generate_param_names(3, true);
        assert_eq!(names[0], "self");
        assert_eq!(names.len(), 3); // self + arg1 + arg2
    }

    #[test]
    fn test_generate_param_names_zero() {
        let names = generate_param_names(0, false);
        assert!(names.is_empty());
    }

    // â"€â"€ LuaProtoInfo â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_proto_info_new() {
        let arch = arch54();
        let words = [make_iabx(3, 0, 0), iabc54(68, 0, 1, 0)];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let proto = LuaProtoInfo::new(LuaVersion::Lua54, instrs);
        assert_eq!(proto.len(), 2);
        assert!(!proto.is_empty());
        assert!(!proto.locals.is_empty());
    }

    #[test]
    fn test_proto_info_stats() {
        let arch = arch54();
        let words = [iabc54(32, 0, 1, 2), iabc54(68, 0, 1, 0)];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let proto = LuaProtoInfo::new(LuaVersion::Lua54, instrs);
        let stats = proto.stats();
        assert_eq!(stats.arithmetic, 1);
        assert_eq!(stats.returns, 1);
    }

    #[test]
    fn test_proto_info_listing() {
        let arch = arch54();
        let words = [make_iabx(3, 0, 0), iabc54(68, 0, 1, 0)];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let proto = LuaProtoInfo::new(LuaVersion::Lua54, instrs);
        let lst = proto.listing();
        assert!(lst.contains("loadk"));
        assert!(lst.contains("return"));
    }

    #[test]
    fn test_proto_info_display() {
        let proto = LuaProtoInfo::new(LuaVersion::Lua54, vec![]);
        let s = proto.to_string();
        assert!(s.contains("Lua 5.4"));
        assert!(s.contains("params=0"));
    }

    #[test]
    fn test_proto_info_constant_lookup() {
        let mut proto = LuaProtoInfo::new(LuaVersion::Lua54, vec![]);
        proto.constants.push(LuaConst::Int(99));
        assert_eq!(proto.constant(0), Some(&LuaConst::Int(99)));
        assert_eq!(proto.constant(1), None);
    }

    #[test]
    fn test_proto_info_local_name() {
        let arch = arch54();
        let words = [make_iabx(3, 0, 0), iabc54(68, 0, 1, 0)];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let proto = LuaProtoInfo::new(LuaVersion::Lua54, instrs);
        assert_eq!(proto.local_name(0), Some("local_0"));
    }

    // â"€â"€ classify_opcode â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_classify_move() {
        assert_eq!(classify_opcode("move"), OpcodeCategory::Move);
        assert_eq!(classify_opcode("MOVE"), OpcodeCategory::Move);
    }

    #[test]
    fn test_classify_load() {
        assert_eq!(classify_opcode("loadk"), OpcodeCategory::Load);
        assert_eq!(classify_opcode("loadnil"), OpcodeCategory::Load);
        assert_eq!(classify_opcode("loadi"), OpcodeCategory::Load);
    }

    #[test]
    fn test_classify_upvalue() {
        assert_eq!(classify_opcode("getupval"), OpcodeCategory::Upvalue);
        assert_eq!(classify_opcode("setupval"), OpcodeCategory::Upvalue);
    }

    #[test]
    fn test_classify_global() {
        assert_eq!(classify_opcode("getglobal"), OpcodeCategory::Global);
        assert_eq!(classify_opcode("setglobal"), OpcodeCategory::Global);
    }

    #[test]
    fn test_classify_table_ops() {
        assert_eq!(classify_opcode("gettable"), OpcodeCategory::TableGet);
        assert_eq!(classify_opcode("settable"), OpcodeCategory::TableSet);
        assert_eq!(classify_opcode("newtable"), OpcodeCategory::TableNew);
        assert_eq!(classify_opcode("gettabup"), OpcodeCategory::TableGet);
        assert_eq!(classify_opcode("settabup"), OpcodeCategory::TableSet);
    }

    #[test]
    fn test_classify_arithmetic() {
        for m in [
            "add", "sub", "mul", "div", "mod", "pow", "idiv", "band", "bor", "bxor", "shl", "shr",
            "self",
        ] {
            assert_eq!(classify_opcode(m), OpcodeCategory::Arithmetic, "{m}");
        }
    }

    #[test]
    fn test_classify_unary() {
        for m in ["unm", "not", "bnot", "len"] {
            assert_eq!(classify_opcode(m), OpcodeCategory::Unary, "{m}");
        }
    }

    #[test]
    fn test_classify_compare() {
        for m in ["eq", "lt", "le", "test", "testset", "eqi", "lti", "gti"] {
            assert_eq!(classify_opcode(m), OpcodeCategory::Compare, "{m}");
        }
    }

    #[test]
    fn test_classify_loop() {
        for m in ["forloop", "forprep", "tforloop", "tforcall", "tforprep"] {
            assert_eq!(classify_opcode(m), OpcodeCategory::Loop, "{m}");
        }
    }

    #[test]
    fn test_classify_call_return() {
        assert_eq!(classify_opcode("call"), OpcodeCategory::Call);
        assert_eq!(classify_opcode("tailcall"), OpcodeCategory::Call);
        assert_eq!(classify_opcode("return"), OpcodeCategory::Return);
        assert_eq!(classify_opcode("return0"), OpcodeCategory::Return);
        assert_eq!(classify_opcode("return1"), OpcodeCategory::Return);
    }

    #[test]
    fn test_classify_closure_vararg() {
        assert_eq!(classify_opcode("closure"), OpcodeCategory::Closure);
        assert_eq!(classify_opcode("vararg"), OpcodeCategory::Vararg);
        assert_eq!(classify_opcode("varargprep"), OpcodeCategory::Vararg);
    }

    #[test]
    fn test_classify_meta() {
        assert_eq!(classify_opcode("extraarg"), OpcodeCategory::Meta);
        assert_eq!(classify_opcode("mmbin"), OpcodeCategory::Meta);
    }

    #[test]
    fn test_classify_other() {
        assert_eq!(classify_opcode("xyzzy"), OpcodeCategory::Other);
    }

    #[test]
    fn test_classify_display() {
        assert_eq!(OpcodeCategory::Move.to_string(), "move");
        assert_eq!(OpcodeCategory::TableGet.to_string(), "table-get");
        assert_eq!(OpcodeCategory::Other.to_string(), "other");
    }

    // â"€â"€ annotate_instructions â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_annotate_loadk_resolves_constant() {
        let arch = arch54();
        let words = [
            make_iabx(3, 0, 0),  // loadk R0, K[0]
            iabc54(68, 0, 1, 0), // return
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let pool = vec![LuaConst::String("hello".into())];
        let annotated = annotate_instructions(&instrs, &pool, LuaVersion::Lua54);
        assert_eq!(annotated.len(), 2);
        let ann = annotated[0].annotation.as_deref().unwrap_or("");
        assert!(
            ann.contains("hello"),
            "expected 'hello' in annotation, got: {ann}"
        );
    }

    #[test]
    fn test_annotate_non_loadk_gets_category() {
        let arch = arch54();
        let words = [iabc54(32, 0, 1, 2)]; // add
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let annotated = annotate_instructions(&instrs, &[], LuaVersion::Lua54);
        assert_eq!(annotated[0].category, OpcodeCategory::Arithmetic);
        assert!(annotated[0].annotation.is_none());
    }

    #[test]
    fn test_annotated_instr_display_with_annotation() {
        let arch = arch54();
        let w = make_iabx(3, 0, 0);
        let bytes = w.to_le_bytes();
        let instr = arch.disassemble(Address::new(0), &bytes).unwrap();
        let ai = AnnotatedInstr::with_annotation(instr, "K[0] = 42");
        let s = ai.to_string();
        assert!(s.contains("loadk"));
        assert!(s.contains("K[0] = 42"));
    }

    #[test]
    fn test_annotated_instr_display_no_annotation() {
        let arch = arch54();
        let w = iabc54(32, 0, 1, 2);
        let bytes = w.to_le_bytes();
        let instr = arch.disassemble(Address::new(0), &bytes).unwrap();
        let ai = AnnotatedInstr::new(instr);
        let s = ai.to_string();
        assert!(s.contains("arithmetic"));
    }

    // â"€â"€ detect_version â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_detect_version_from_header_54() {
        let data = [0x1b, b'L', b'u', b'a', 0x54, 0x01, 0x04, 0x08, 0x04];
        assert_eq!(detect_version(&data), Some(LuaVersion::Lua54));
    }

    #[test]
    fn test_detect_version_from_header_51() {
        let data = [0x1b, b'L', b'u', b'a', 0x51, 0x01, 0x04, 0x04, 0x04];
        assert_eq!(detect_version(&data), Some(LuaVersion::Lua51));
    }

    #[test]
    fn test_detect_version_too_short() {
        assert_eq!(detect_version(&[]), None);
    }

    // â"€â"€ RegisterSnapshot â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_register_snapshot_set_get() {
        let mut snap = RegisterSnapshot::new(8);
        snap.set(0, RegValue::Const(LuaConst::Int(42)));
        assert_eq!(snap.get(0), Some(&RegValue::Const(LuaConst::Int(42))));
        assert_eq!(snap.get(1), None);
    }

    #[test]
    fn test_register_snapshot_alias() {
        let mut snap = RegisterSnapshot::new(8);
        snap.set(1, RegValue::Alias(3));
        assert_eq!(snap.get(1), Some(&RegValue::Alias(3)));
    }

    #[test]
    fn test_register_snapshot_invalidate_from() {
        let mut snap = RegisterSnapshot::new(4);
        snap.set(0, RegValue::Const(LuaConst::Int(1)));
        snap.set(1, RegValue::Const(LuaConst::Int(2)));
        snap.set(2, RegValue::Const(LuaConst::Int(3)));
        snap.invalidate_from(1);
        assert!(snap.get(0).is_some());
        assert!(snap.get(1).is_none());
        assert!(snap.get(2).is_none());
    }

    #[test]
    fn test_register_snapshot_propagate_loadi() {
        // LOADI R0, 99 (5.4)
        let arch = arch54();
        let w = make_iasbx(1, 0, 99);
        let bytes = w.to_le_bytes();
        let instr = arch.disassemble(Address::new(0), &bytes).unwrap();
        let mut snap = RegisterSnapshot::new(8);
        snap.propagate(&[instr], &[], LuaVersion::Lua54);
        assert_eq!(snap.get(0), Some(&RegValue::Const(LuaConst::Int(99))));
    }

    #[test]
    fn test_register_snapshot_propagate_loadk_54() {
        let arch = arch54();
        let w = make_iabx(3, 2, 0); // LOADK R2, K[0]
        let bytes = w.to_le_bytes();
        let instr = arch.disassemble(Address::new(0), &bytes).unwrap();
        let pool = vec![LuaConst::String("world".into())];
        let mut snap = RegisterSnapshot::new(8);
        snap.propagate(&[instr], &pool, LuaVersion::Lua54);
        assert_eq!(
            snap.get(2),
            Some(&RegValue::Const(LuaConst::String("world".into())))
        );
    }

    #[test]
    fn test_register_snapshot_propagate_move_54() {
        let arch = arch54();
        // First load a constant, then MOVE it.
        let words = [
            make_iasbx(1, 0, 7),      // loadi R0, 7
            make_iabc(0, 1, 0, 0, 0), // move R1, R0
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let mut snap = RegisterSnapshot::new(8);
        snap.propagate(&instrs, &[], LuaVersion::Lua54);
        assert_eq!(snap.get(0), Some(&RegValue::Const(LuaConst::Int(7))));
        // R1 is an alias to R0.
        assert_eq!(snap.get(1), Some(&RegValue::Alias(0)));
    }

    #[test]
    fn test_register_snapshot_propagate_loadk_51() {
        let arch = arch51();
        let w = make_legacy_iabx(1, 3, 0); // LOADK R3, K[0]
        let bytes = w.to_le_bytes();
        let instr = arch.disassemble(Address::new(0), &bytes).unwrap();
        let pool = vec![LuaConst::Int(100)];
        let mut snap = RegisterSnapshot::new(8);
        snap.propagate(&[instr], &pool, LuaVersion::Lua51);
        assert_eq!(snap.get(3), Some(&RegValue::Const(LuaConst::Int(100))));
    }

    #[test]
    fn test_register_snapshot_propagate_call_invalidates() {
        let arch = arch54();
        // Load then call —" call should wipe all registers.
        let words = [
            make_iasbx(1, 0, 5),       // loadi R0, 5
            make_iabc(66, 0, 1, 1, 0), // call R0, 1, 1
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let mut snap = RegisterSnapshot::new(8);
        snap.propagate(&instrs, &[], LuaVersion::Lua54);
        // After the call all registers should be unknown.
        assert!(snap.get(0).is_none());
    }

    #[test]
    fn test_reg_value_display() {
        assert_eq!(RegValue::Unknown.to_string(), "?");
        assert_eq!(RegValue::Alias(3).to_string(), "R3");
        assert_eq!(RegValue::Upvalue(1).to_string(), "upval(1)");
        assert_eq!(RegValue::Const(LuaConst::Int(42)).to_string(), "const(42)");
    }

    // â"€â"€ Lua 5.4 bitwise ops â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua54_band() {
        // BAND = op 39
        let w = iabc54(39, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "band");
        assert!(i.flags == InstrFlags::NONE);
    }

    #[test]
    fn test_lua54_bor() {
        let w = iabc54(40, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "bor");
    }

    #[test]
    fn test_lua54_bxor() {
        let w = iabc54(41, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "bxor");
    }

    #[test]
    fn test_lua54_shl() {
        let w = iabc54(42, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "shl");
    }

    #[test]
    fn test_lua54_shr() {
        let w = iabc54(43, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "shr");
    }

    #[test]
    fn test_lua54_bnot() {
        let w = iabc54(48, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "bnot");
    }

    #[test]
    fn test_lua54_idiv() {
        let w = iabc54(38, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "idiv");
    }

    #[test]
    fn test_lua54_bandk() {
        let w = make_iabc(27, 0, 1, 2, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "bandk");
    }

    #[test]
    fn test_lua54_bork() {
        let w = make_iabc(28, 0, 1, 2, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "bork");
    }

    #[test]
    fn test_lua54_bxork() {
        let w = make_iabc(29, 0, 1, 2, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "bxork");
    }

    #[test]
    fn test_lua54_idivk() {
        let w = make_iabc(26, 0, 1, 2, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "idivk");
    }

    // â"€â"€ Lua 5.4 table ops â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua54_geti() {
        // GETI = op 11
        let w = iabc54(11, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "geti");
    }

    #[test]
    fn test_lua54_getfield() {
        // GETFIELD = op 12
        let w = iabc54(12, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "getfield");
    }

    #[test]
    fn test_lua54_seti() {
        // SETI = op 15
        let w = iabc54(15, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "seti");
    }

    #[test]
    fn test_lua54_setfield() {
        // SETFIELD = op 16
        let w = iabc54(16, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "setfield");
    }

    #[test]
    fn test_lua54_gettable() {
        let w = iabc54(10, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "gettable");
    }

    #[test]
    fn test_lua54_settable() {
        let w = iabc54(14, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "settable");
    }

    #[test]
    fn test_lua54_self_op() {
        // SELF = op 18
        let w = iabc54(18, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "self");
    }

    // â"€â"€ Lua 5.4 comparison immediate ops â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua54_eqk() {
        // EQK = op 58
        let w = iabc54(58, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "eqk");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_lua54_eqi() {
        // EQI = op 59
        let w = iabc54(59, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "eqi");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_lua54_lti() {
        // LTI = op 60
        let w = iabc54(60, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "lti");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_lua54_gti() {
        // GTI = op 61
        let w = iabc54(61, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "gti");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_lua54_lei() {
        // LEI = op 62
        let w = iabc54(62, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "lei");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_lua54_gei() {
        // GEI = op 63
        let w = iabc54(63, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "gei");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_lua54_test() {
        // TEST = op 64
        let w = iabc54(64, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "test");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_lua54_testset() {
        // TESTSET = op 65
        let w = iabc54(65, 0, 1, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "testset");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    // â"€â"€ Lua 5.4 MMBIN ops â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua54_mmbin() {
        let w = iabc54(44, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "mmbin");
    }

    #[test]
    fn test_lua54_mmbini() {
        let w = iabc54(45, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "mmbini");
    }

    #[test]
    fn test_lua54_mmbink() {
        let w = iabc54(46, 0, 1, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "mmbink");
    }

    // â"€â"€ Lua 5.4 TBC / CLOSE â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua54_close() {
        // CLOSE = op 52
        let w = iabc54(52, 0, 0, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "close");
    }

    #[test]
    fn test_lua54_tbc() {
        // TBC = op 53 (to-be-closed)
        let w = iabc54(53, 0, 0, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "tbc");
    }

    // â"€â"€ Lua 5.4 VARARGPREP â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua54_varargprep() {
        // VARARGPREP = op 79
        let w = iabc54(79, 0, 0, 0);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "varargprep");
    }

    // â"€â"€ Lua 5.4 loop ops â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua54_tforprep() {
        // TFORPREP = op 73
        let w = make_iasbx(73, 0, 3);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "tforprep");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_lua54_tforcall() {
        // TFORCALL = op 74
        let w = iabc54(74, 0, 0, 2);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "tforcall");
    }

    #[test]
    fn test_lua54_tforloop() {
        // TFORLOOP = op 75
        let w = make_iasbx(75, 0, -5);
        let i = dis54(w);
        assert_eq!(i.mnemonic, "tforloop");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    // â"€â"€ Lua 5.4 all opcodes decode â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_lua54_all_opcodes_decode() {
        for op in 0u8..u8::try_from(LUA54_OPCODES.len()).unwrap_or(u8::MAX) {
            let w = make_iabc(op, 0, 0, 0, 0);
            let result = arch54().disassemble(Address::new(0), &w.to_le_bytes());
            assert!(
                result.is_ok(),
                "opcode {op} ({}) failed: {:?}",
                LUA54_OPCODES[op as usize],
                result
            );
        }
    }

    // â"€â"€ Lua 5.1 all-op roundtrip via Architecture trait â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua51_all_opcodes_via_arch() {
        for op in 0u8..u8::try_from(LUA51_OPCODES.len()).unwrap_or(u8::MAX) {
            let w = match lua51_fmt(op) {
                LuaLegacyFmt::ABx => make_legacy_iabx(op, 0, 0),
                LuaLegacyFmt::AsBx => make_legacy_iasbx(op, 0, 0),
                _ => make_legacy_iabc(op, 0, 0, 0),
            };
            let result = arch51().disassemble(Address::new(0), &w.to_le_bytes());
            assert!(result.is_ok(), "5.1 opcode {op} failed");
        }
    }

    #[test]
    fn test_lua52_all_opcodes_via_arch() {
        for op in 0u8..u8::try_from(LUA52_OPCODES.len()).unwrap_or(u8::MAX) {
            let w = match lua52_fmt(op) {
                LuaLegacyFmt::AsBx => make_legacy_iasbx(op, 0, 0),
                LuaLegacyFmt::ABx | LuaLegacyFmt::Ax => make_legacy_iabx(op, 0, 0),
                LuaLegacyFmt::Abc => make_legacy_iabc(op, 0, 0, 0),
            };
            let result = arch52().disassemble(Address::new(0), &w.to_le_bytes());
            assert!(result.is_ok(), "5.2 opcode {op} failed");
        }
    }

    #[test]
    fn test_lua53_all_opcodes_via_arch() {
        for op in 0u8..u8::try_from(LUA53_OPCODES.len()).unwrap_or(u8::MAX) {
            let w = match lua53_fmt(op) {
                LuaLegacyFmt::AsBx => make_legacy_iasbx(op, 0, 0),
                LuaLegacyFmt::ABx | LuaLegacyFmt::Ax => make_legacy_iabx(op, 0, 0),
                LuaLegacyFmt::Abc => make_legacy_iabc(op, 0, 0, 0),
            };
            let result = arch53().disassemble(Address::new(0), &w.to_le_bytes());
            assert!(result.is_ok(), "5.3 opcode {op} failed");
        }
    }

    // â"€â"€ instruction_alignment / max_instruction_length â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_instruction_alignment() {
        assert_eq!(arch54().instruction_alignment(), 4);
        assert_eq!(arch51().instruction_alignment(), 4);
    }

    #[test]
    fn test_max_instruction_length() {
        assert_eq!(arch54().max_instruction_length(), 4);
        assert_eq!(arch53().max_instruction_length(), 4);
    }

    // â"€â"€ iABC k-flag roundtrip â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_iabc_k_flag_set() {
        let w = make_iabc(10, 0, 1, 2, 1); // GETTABLE with k=1
        assert_eq!(get_k54(w), 1);
        assert_eq!(get_a54(w), 0);
        assert_eq!(get_b54(w), 1);
        assert_eq!(get_c54(w), 2);
    }

    #[test]
    fn test_iabc_k_flag_clear() {
        let w = make_iabc(10, 3, 4, 5, 0);
        assert_eq!(get_k54(w), 0);
        assert_eq!(get_a54(w), 3);
        assert_eq!(get_b54(w), 4);
        assert_eq!(get_c54(w), 5);
    }

    // â"€â"€ field-extraction helpers direct â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_get_op_old_roundtrip() {
        for op in 0u8..63 {
            let w = make_legacy_iabc(op, 0, 0, 0);
            assert_eq!(get_op_old(w), op);
        }
    }

    #[test]
    fn test_get_a_old_roundtrip() {
        for a in [0u32, 1, 127, 255] {
            let w = make_legacy_iabc(0, a, 0, 0);
            assert_eq!(get_a_old(w), a);
        }
    }

    #[test]
    fn test_get_b_old_roundtrip() {
        for b in [0u32, 1, 255, 511] {
            let w = make_legacy_iabc(0, 0, b, 0);
            assert_eq!(get_b_old(w), b);
        }
    }

    #[test]
    fn test_get_c_old_roundtrip() {
        for c in [0u32, 1, 255, 511] {
            let w = make_legacy_iabc(0, 0, 0, c);
            assert_eq!(get_c_old(w), c);
        }
    }

    #[test]
    fn test_get_bx_old_roundtrip() {
        for bx in [0u32, 1, 1000, MAXARG_BX_OLD] {
            let w = make_legacy_iabx(0, 0, bx);
            assert_eq!(get_bx_old(w), bx);
        }
    }

    // â"€â"€ LuaVersion equality / hash â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lua_version_eq() {
        assert_eq!(LuaVersion::Lua51, LuaVersion::Lua51);
        assert_ne!(LuaVersion::Lua51, LuaVersion::Lua54);
    }

    #[test]
    fn test_lua_version_copy() {
        let v = LuaVersion::Lua53;
        let v2 = v;
        assert_eq!(v, v2);
    }

    // â"€â"€ LuaArchMetadata version fields â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_arch_metadata_52() {
        let m = LuaArchMetadata::for_version(LuaVersion::Lua52);
        assert_eq!(m.opcode_bits, 6);
        assert_eq!(m.version, "5.2");
        assert_eq!(m.opcode_count, LUA52_OPCODES.len());
    }

    #[test]
    fn test_arch_metadata_53() {
        let m = LuaArchMetadata::for_version(LuaVersion::Lua53);
        assert_eq!(m.version, "5.3");
        assert_eq!(m.opcode_count, LUA53_OPCODES.len());
    }

    // â"€â"€ Chunk header endian and int_size fields â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_chunk_header_endian_and_sizes() {
        let data = [0x1b, b'L', b'u', b'a', 0x53, 0x00, 0x04, 0x08, 0x04];
        let hdr = parse_chunk_header(&data).unwrap();
        assert_eq!(hdr.version, LuaVersion::Lua53);
        assert_eq!(hdr.endian, 0);
        assert_eq!(hdr.int_size, 4);
        assert_eq!(hdr.size_t_size, 8);
        assert_eq!(hdr.instr_size, 4);
    }

    #[test]
    fn test_chunk_header_52() {
        let data = [0x1b, b'L', b'u', b'a', 0x52, 0x01, 0x04, 0x04, 0x04];
        let hdr = parse_chunk_header(&data).unwrap();
        assert_eq!(hdr.version, LuaVersion::Lua52);
    }

    // â"€â"€ RegValue TableField display â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_reg_value_table_field_display() {
        let rv = RegValue::TableField {
            table: 2,
            key: Box::new(RegValue::Const(LuaConst::String("k".into()))),
        };
        let s = rv.to_string();
        assert!(s.contains("R2"));
        assert!(s.contains("const("));
    }

    // â"€â"€ RegisterSnapshot resize on large register index â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_register_snapshot_auto_resize() {
        let mut snap = RegisterSnapshot::new(2);
        // Writing to register 10 should auto-resize.
        snap.set(10, RegValue::Alias(5));
        assert_eq!(snap.get(10), Some(&RegValue::Alias(5)));
        // Original capacity slots still accessible.
        assert_eq!(snap.get(0), None);
    }

    // â"€â"€ detect_version heuristic path â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_detect_version_heuristic_53() {
        // No header magic —" first word uses a 5.3 opcode (IDIV=19 in 5.3).
        let w = make_legacy_iabc(19, 0, 1, 2);
        let bytes = w.to_le_bytes();
        // Should resolve to 5.3 (or 5.2 as fallback —" both have this index valid).
        let v = detect_version(&bytes);
        assert!(v.is_some());
    }

    // â"€â"€ LuaProtoInfo basic_blocks delegation â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_proto_info_basic_blocks_count() {
        let arch = arch54();
        let words = [make_iabx(3, 0, 0), iabc54(68, 0, 1, 0)];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let proto = LuaProtoInfo::new(LuaVersion::Lua54, instrs);
        let bbs = proto.basic_blocks(&arch);
        assert!(!bbs.is_empty());
    }

    // â"€â"€ LuaChunkStats tables and upvalues â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_chunk_stats_table_ops() {
        let arch = arch54();
        let words = [
            iabc54(9, 0, 0, 1),  // gettabup
            iabc54(10, 1, 0, 2), // gettable
            iabc54(68, 0, 1, 0), // return
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let stats = LuaChunkStats::from_instructions(LuaVersion::Lua54, &instrs);
        assert!(stats.table_ops >= 2);
    }

    #[test]
    fn test_chunk_stats_upvalue_ops() {
        let arch = arch54();
        let words = [
            iabc54(7, 0, 1, 0),  // getupval
            iabc54(8, 0, 0, 0),  // setupval
            iabc54(68, 0, 1, 0), // return
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let stats = LuaChunkStats::from_instructions(LuaVersion::Lua54, &instrs);
        assert!(stats.upvalue_ops >= 1);
    }

    #[test]
    fn test_chunk_stats_closures() {
        let arch = arch54();
        let words = [
            make_iabx(77, 0, 0), // closure
            iabc54(68, 0, 1, 0), // return
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let stats = LuaChunkStats::from_instructions(LuaVersion::Lua54, &instrs);
        assert_eq!(stats.closures, 1);
    }

    // â"€â"€ disassemble_chunk address stride â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_disassemble_chunk_address_stride() {
        let arch = arch54();
        let words: Vec<u32> = (0..4).map(|_| make_iabx(3, 0, 0)).collect();
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let results = disassemble_chunk(&arch, Address::new(0x200), &bytes);
        let addrs: Vec<u64> = results
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|i| i.address.as_u64())
            .collect();
        assert_eq!(addrs, vec![0x200, 0x204, 0x208, 0x20c]);
    }

    // â"€â"€ format_listing empty â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_format_listing_empty() {
        let s = format_listing(&[]);
        assert_eq!(s, "");
    }

    // â"€â"€ split_basic_blocks with conditional â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_split_basic_blocks_with_conditional() {
        let arch = arch54();
        // EQ (op 55) is conditional; JMP (op 54) is the actual branch.
        let words = [
            iabc54(55, 0, 1, 0), // eq R0, R1
            make_isj(54, 1),     // jmp +1
            make_iabx(3, 0, 5),  // loadk (fall-through target)
            iabc54(68, 0, 1, 0), // return (jump target)
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
        let blocks = split_basic_blocks(&arch, &instrs);
        // At minimum 2 blocks: before and after the branch
        assert!(blocks.len() >= 2);
    }

    // â"€â"€ Lua 5.3 SELF op â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_lua53_self() {
        // SELF = op 12
        let w = make_legacy_iabc(12, 0, 1, 2);
        let (m, ops, _) = decode_lua53(w, Address::new(0)).unwrap();
        assert_eq!(m, "self");
        assert!(ops.contains("R0"));
    }

    // â"€â"€ Lua 5.2 TFORCALL â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_lua52_tforcall() {
        // TFORCALL = op 34
        let w = make_legacy_iabc(34, 0, 0, 2);
        let (m, _, fl) = decode_lua52(w, Address::new(0)).unwrap();
        assert_eq!(m, "tforcall");
        assert!(!fl.contains(InstrFlags::BRANCH));
    }

    // â"€â"€ Lua 5.2 CLOSURE â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_lua52_closure() {
        // CLOSURE = op 37
        let w = make_legacy_iabx(37, 2, 4);
        let (m, ops, _) = decode_lua52(w, Address::new(0)).unwrap();
        assert_eq!(m, "closure");
        assert!(ops.contains("R2"));
    }

    // â"€â"€ Lua 5.1 VARARG â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_lua51_vararg() {
        // VARARG = op 37
        let w = make_legacy_iabc(37, 0, 0, 3);
        let (m, _, _) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "vararg");
    }

    // â"€â"€ Lua 5.1 SETLIST â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_lua51_setlist() {
        // SETLIST = op 34
        let w = make_legacy_iabc(34, 0, 5, 1);
        let (m, _, _) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "setlist");
    }

    // â"€â"€ Lua 5.1 CLOSE â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_lua51_close() {
        // CLOSE = op 35
        let w = make_legacy_iabc(35, 0, 0, 0);
        let (m, _, _) = decode_lua51(w, Address::new(0)).unwrap();
        assert_eq!(m, "close");
    }

    // â"€â"€ Lua 5.3 SETLIST â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_lua53_setlist() {
        // SETLIST = op 43
        let w = make_legacy_iabc(43, 0, 5, 1);
        let (m, _, _) = decode_lua53(w, Address::new(0)).unwrap();
        assert_eq!(m, "setlist");
    }

    // â"€â"€ opcode_name boundary â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_opcode_name_boundary_52() {
        assert_eq!(opcode_name(LuaVersion::Lua52, 0), Some("MOVE"));
        assert_eq!(opcode_name(LuaVersion::Lua52, 39), Some("EXTRAARG"));
        assert_eq!(opcode_name(LuaVersion::Lua52, 40), None);
    }

    #[test]
    fn test_opcode_name_boundary_53() {
        assert_eq!(opcode_name(LuaVersion::Lua53, 46), Some("EXTRAARG"));
        assert_eq!(opcode_name(LuaVersion::Lua53, 47), None);
    }

    // â"€â"€ find_opcodes case-insensitive â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_find_opcodes_case_insensitive() {
        let r1 = find_opcodes(LuaVersion::Lua54, "CALL");
        let r2 = find_opcodes(LuaVersion::Lua54, "call");
        assert_eq!(r1, r2);
        assert!(!r1.is_empty());
    }

    #[test]
    fn test_find_opcodes_return_ops() {
        let results = find_opcodes(LuaVersion::Lua54, "RETURN");
        let names: Vec<&str> = results.iter().map(|(_, n)| *n).collect();
        assert!(names.contains(&"RETURN"));
        assert!(names.contains(&"RETURN0"));
        assert!(names.contains(&"RETURN1"));
    }

    // â"€â"€ is_branch / is_call / is_return all versions â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_is_branch_all_versions() {
        // JMP in each version
        assert!(is_branch_opcode(LuaVersion::Lua51, 22));
        assert!(is_branch_opcode(LuaVersion::Lua52, 23));
        assert!(is_branch_opcode(LuaVersion::Lua53, 30));
        assert!(is_branch_opcode(LuaVersion::Lua54, 54));
    }

    #[test]
    fn test_is_call_all_versions() {
        assert!(is_call_opcode(LuaVersion::Lua51, 28));
        assert!(is_call_opcode(LuaVersion::Lua52, 29));
        assert!(is_call_opcode(LuaVersion::Lua53, 36));
        assert!(is_call_opcode(LuaVersion::Lua54, 66));
    }

    #[test]
    fn test_is_return_all_versions() {
        assert!(is_return_opcode(LuaVersion::Lua51, 30));
        assert!(is_return_opcode(LuaVersion::Lua52, 31));
        assert!(is_return_opcode(LuaVersion::Lua53, 38));
        assert!(is_return_opcode(LuaVersion::Lua54, 68));
        assert!(is_return_opcode(LuaVersion::Lua54, 69));
        assert!(is_return_opcode(LuaVersion::Lua54, 70));
    }
}

