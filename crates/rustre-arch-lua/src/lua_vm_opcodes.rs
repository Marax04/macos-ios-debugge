//! `lua_vm_opcodes` — Lua opcode tables and metadata for all four VM versions.
//!
//! Provides [`LuaOpcode`], [`OpcodeInfo`], [`opcode_name`], [`opcode_format`],
//! and per-version opcode tables for Lua 5.1 through 5.4.
//!
//! # Relationship to the inline tables in `lib.rs`
//!
//! `lib.rs` maintains its own `pub(crate) static LUA54_OPCODES: &[&str]` (and
//! sibling tables for 5.1–5.3) used by the instruction decoder ([`crate::decode_lua54`],
//! [`crate::decode_lua_legacy`]).  Those are plain `&[&str]` slices — just the mnemonic
//! strings — kept inline so the hot decoder path has no extra indirection.
//!
//! The tables in *this* module ([`LUA54_OPCODES`], [`LUA51_OPCODES`]) are richer
//! `&[OpcodeInfo]` slices that also carry the encoding format, semantic effect
//! category, and a one-line description.  They are intended for tooling that needs
//! structured opcode metadata (disassembly pretty-printers, CFG builders, etc.).
//!
//! The two sets of tables are intentionally separate: merging them would require
//! the decoder to pay the cost of loading `OpcodeInfo` structs for every
//! instruction, or would strip the metadata from the public API.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// OpcodeFormat
// ─────────────────────────────────────────────────────────────────────────────

/// Instruction encoding format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpcodeFormat {
    /// A, B, C fields (iABC).
    Abc,
    /// A, Bx fields (iABx).
    ABx,
    /// A, sBx fields (iAsBx — Bx is a signed offset).
    AsBx,
    /// Ax field only (iAx — used in Lua 5.4).
    Ax,
    /// sJ jump offset only (isJ — used in Lua 5.4).
    SJ,
}

impl fmt::Display for OpcodeFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Abc => write!(f, "iABC"),
            Self::ABx => write!(f, "iABx"),
            Self::AsBx => write!(f, "iAsBx"),
            Self::Ax => write!(f, "iAx"),
            Self::SJ => write!(f, "isJ"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpcodeEffect
// ─────────────────────────────────────────────────────────────────────────────

/// High-level semantic effect category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpcodeEffect {
    Load,
    Move,
    ArithmeticBinary,
    ArithmeticUnary,
    CompareAndBranch,
    Jump,
    Call,
    Return,
    TableGet,
    TableSet,
    TableNew,
    Loop,
    Upvalue,
    Closure,
    Vararg,
    Concat,
    Misc,
}

impl fmt::Display for OpcodeEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Load => "load",
            Self::Move => "move",
            Self::ArithmeticBinary => "arith_bin",
            Self::ArithmeticUnary => "arith_unary",
            Self::CompareAndBranch => "cmp_branch",
            Self::Jump => "jump",
            Self::Call => "call",
            Self::Return => "return",
            Self::TableGet => "table_get",
            Self::TableSet => "table_set",
            Self::TableNew => "table_new",
            Self::Loop => "loop",
            Self::Upvalue => "upvalue",
            Self::Closure => "closure",
            Self::Vararg => "vararg",
            Self::Concat => "concat",
            Self::Misc => "misc",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpcodeInfo
// ─────────────────────────────────────────────────────────────────────────────

/// All static metadata for a Lua opcode.
#[derive(Debug, Clone)]
pub struct OpcodeInfo {
    /// Numeric opcode value.
    pub code: u8,
    /// Canonical mnemonic string (e.g. `"MOVE"`, `"LOADK"`).
    pub name: &'static str,
    /// Instruction encoding format.
    pub format: OpcodeFormat,
    /// High-level semantic effect.
    pub effect: OpcodeEffect,
    /// One-line description.
    pub description: &'static str,
}

impl OpcodeInfo {
    const fn new(
        code: u8,
        name: &'static str,
        format: OpcodeFormat,
        effect: OpcodeEffect,
        description: &'static str,
    ) -> Self {
        Self { code, name, format, effect, description }
    }
}

impl fmt::Display for OpcodeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X} {:12} {:8} {:14} {}",
            self.code, self.name, self.format, self.effect, self.description)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaOpcode — Lua 5.4 canonical enum
// ─────────────────────────────────────────────────────────────────────────────

/// Lua 5.4 opcode enumeration (complete).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LuaOpcode {
    Move = 0,
    LoadI,
    LoadF,
    LoadK,
    LoadKx,
    LoadFalse,
    LFalseSkip,
    LoadTrue,
    LoadNil,
    GetUpval,
    SetUpval,
    GetTabUp,
    GetTabI,
    GetField,
    GetTable,
    GetI,
    GetField2,    // alias kept for compat
    SetTabUp,
    SetTabI,
    SetField,
    SetTable,
    SetI,
    SetField2,
    NewTable,
    Self_,
    AddI,
    AddK,
    SubK,
    MulK,
    ModK,
    PowK,
    DivK,
    IDivK,
    BAndK,
    BOrK,
    BXorK,
    ShrI,
    ShlI,
    Add,
    Sub,
    Mul,
    Mod,
    Pow,
    Div,
    IDiv,
    BAnd,
    BOr,
    BXor,
    Shl,
    Shr,
    MMBin,
    MMBinI,
    MMBinK,
    Unm,
    BNot,
    Not,
    Len,
    Concat,
    Close,
    Tbc,
    Jmp,
    Eq,
    Lt,
    Le,
    EqK,
    EqI,
    LtI,
    LeI,
    GtI,
    GeI,
    Test,
    TestSet,
    Call,
    TailCall,
    Return,
    Return0,
    Return1,
    ForNum,
    ForIn,
    TForCall,
    TForLoop,
    SetList,
    Closure,
    Vararg,
    VarargPrep,
    ExtraArg,
}

impl LuaOpcode {
    /// Decode a raw 7-bit opcode (Lua 5.4).
    #[must_use]
    pub fn from_u8_54(v: u8) -> Option<Self> {
        if (v as usize) < LUA54_OPCODES.len() {
            // Use index
            Some(match v {
                0 => Self::Move,
                1 => Self::LoadI,
                2 => Self::LoadF,
                3 => Self::LoadK,
                4 => Self::LoadKx,
                5 => Self::LoadFalse,
                6 => Self::LFalseSkip,
                7 => Self::LoadTrue,
                8 => Self::LoadNil,
                9 => Self::GetUpval,
                10 => Self::SetUpval,
                11 => Self::GetTabUp,
                12 => Self::GetTabI,
                13 => Self::GetField,
                14 => Self::GetTable,
                15 => Self::GetI,
                16 => Self::GetField2,
                17 => Self::SetTabUp,
                18 => Self::SetTabI,
                19 => Self::SetField,
                20 => Self::SetTable,
                21 => Self::SetI,
                22 => Self::SetField2,
                23 => Self::NewTable,
                24 => Self::Self_,
                25 => Self::AddI,
                26 => Self::AddK,
                27 => Self::SubK,
                28 => Self::MulK,
                29 => Self::ModK,
                30 => Self::PowK,
                31 => Self::DivK,
                32 => Self::IDivK,
                33 => Self::BAndK,
                34 => Self::BOrK,
                35 => Self::BXorK,
                36 => Self::ShrI,
                37 => Self::ShlI,
                38 => Self::Add,
                39 => Self::Sub,
                40 => Self::Mul,
                41 => Self::Mod,
                42 => Self::Pow,
                43 => Self::Div,
                44 => Self::IDiv,
                45 => Self::BAnd,
                46 => Self::BOr,
                47 => Self::BXor,
                48 => Self::Shl,
                49 => Self::Shr,
                50 => Self::MMBin,
                51 => Self::MMBinI,
                52 => Self::MMBinK,
                53 => Self::Unm,
                54 => Self::BNot,
                55 => Self::Not,
                56 => Self::Len,
                57 => Self::Concat,
                58 => Self::Close,
                59 => Self::Tbc,
                60 => Self::Jmp,
                61 => Self::Eq,
                62 => Self::Lt,
                63 => Self::Le,
                64 => Self::EqK,
                65 => Self::EqI,
                66 => Self::LtI,
                67 => Self::LeI,
                68 => Self::GtI,
                69 => Self::GeI,
                70 => Self::Test,
                71 => Self::TestSet,
                72 => Self::Call,
                73 => Self::TailCall,
                74 => Self::Return,
                75 => Self::Return0,
                76 => Self::Return1,
                77 => Self::ForNum,
                78 => Self::ForIn,
                79 => Self::TForCall,
                80 => Self::TForLoop,
                81 => Self::SetList,
                82 => Self::Closure,
                83 => Self::Vararg,
                84 => Self::VarargPrep,
                85 => Self::ExtraArg,
                _ => return None,
            })
        } else {
            None
        }
    }

    /// Return the mnemonic name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        opcode_name_54(self as u8)
    }
}

impl fmt::Display for LuaOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// opcode_name / opcode_format free functions
// ─────────────────────────────────────────────────────────────────────────────

/// Return the canonical mnemonic for Lua 5.4 opcode `code`.
#[must_use]
pub const fn opcode_name_54(code: u8) -> &'static str {
    match code {
        0 => "MOVE", 1 => "LOADI", 2 => "LOADF", 3 => "LOADK", 4 => "LOADKX",
        5 => "LOADFALSE", 6 => "LFALSESKIP", 7 => "LOADTRUE", 8 => "LOADNIL",
        9 => "GETUPVAL", 10 => "SETUPVAL", 11 => "GETTABUP", 12 => "GETTABI",
        13 | 16 => "GETFIELD", 14 => "GETTABLE", 15 => "GETI", 17 => "SETTABUP", 18 => "SETTABI", 19 | 22 => "SETFIELD", 20 => "SETTABLE",
        21 => "SETI", 23 => "NEWTABLE", 24 => "SELF",
        25 => "ADDI", 26 => "ADDK", 27 => "SUBK", 28 => "MULK", 29 => "MODK",
        30 => "POWK", 31 => "DIVK", 32 => "IDIVK", 33 => "BANDK", 34 => "BORK",
        35 => "BXORK", 36 => "SHRI", 37 => "SHLI", 38 => "ADD", 39 => "SUB",
        40 => "MUL", 41 => "MOD", 42 => "POW", 43 => "DIV", 44 => "IDIV",
        45 => "BAND", 46 => "BOR", 47 => "BXOR", 48 => "SHL", 49 => "SHR",
        50 => "MMBIN", 51 => "MMBINI", 52 => "MMBINK", 53 => "UNM", 54 => "BNOT",
        55 => "NOT", 56 => "LEN", 57 => "CONCAT", 58 => "CLOSE", 59 => "TBC",
        60 => "JMP", 61 => "EQ", 62 => "LT", 63 => "LE", 64 => "EQK",
        65 => "EQI", 66 => "LTI", 67 => "LEI", 68 => "GTI", 69 => "GEI",
        70 => "TEST", 71 => "TESTSET", 72 => "CALL", 73 => "TAILCALL",
        74 => "RETURN", 75 => "RETURN0", 76 => "RETURN1",
        77 => "FORNUM", 78 => "FORIN", 79 => "TFORCALL", 80 => "TFORLOOP",
        81 => "SETLIST", 82 => "CLOSURE", 83 => "VARARG", 84 => "VARARGPREP",
        85 => "EXTRAARG",
        _ => "UNKNOWN",
    }
}

/// Return the canonical mnemonic for Lua 5.1 opcode `code`.
#[must_use]
pub const fn opcode_name_51(code: u8) -> &'static str {
    match code {
        0 => "MOVE", 1 => "LOADK", 2 => "LOADBOOL", 3 => "LOADNIL",
        4 => "GETUPVAL", 5 => "GETGLOBAL", 6 => "GETTABLE", 7 => "SETGLOBAL",
        8 => "SETUPVAL", 9 => "SETTABLE", 10 => "NEWTABLE", 11 => "SELF",
        12 => "ADD", 13 => "SUB", 14 => "MUL", 15 => "DIV", 16 => "MOD",
        17 => "POW", 18 => "UNM", 19 => "NOT", 20 => "LEN", 21 => "CONCAT",
        22 => "JMP", 23 => "EQ", 24 => "LT", 25 => "LE", 26 => "TEST",
        27 => "TESTSET", 28 => "CALL", 29 => "TAILCALL", 30 => "RETURN",
        31 => "FORLOOP", 32 => "FORPREP", 33 => "TFORLOOP", 34 => "SETLIST",
        35 => "CLOSE", 36 => "CLOSURE", 37 => "VARARG",
        _ => "UNKNOWN",
    }
}

/// Wrapper `opcode_name` that dispatches to the right version.
#[must_use]
pub const fn opcode_name(version_minor: u8, code: u8) -> &'static str {
    match version_minor {
        1..=3 => opcode_name_51(code),
        4 => opcode_name_54(code),
        _ => "UNKNOWN",
    }
}

/// Return the [`OpcodeFormat`] for a Lua 5.4 opcode.
#[must_use]
pub fn opcode_format(code: u8) -> OpcodeFormat {
    LUA54_OPCODES.get(code as usize).map_or(OpcodeFormat::Abc, |info| info.format)
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua 5.4 opcode table
// ─────────────────────────────────────────────────────────────────────────────

/// Static Lua 5.4 opcode table.
pub static LUA54_OPCODES: &[OpcodeInfo] = &[
    OpcodeInfo::new(0,  "MOVE",       OpcodeFormat::Abc,  OpcodeEffect::Move,              "R[A] := R[B]"),
    OpcodeInfo::new(1,  "LOADI",      OpcodeFormat::AsBx, OpcodeEffect::Load,              "R[A] := sBx"),
    OpcodeInfo::new(2,  "LOADF",      OpcodeFormat::AsBx, OpcodeEffect::Load,              "R[A] := (lua_Number)sBx"),
    OpcodeInfo::new(3,  "LOADK",      OpcodeFormat::ABx,  OpcodeEffect::Load,              "R[A] := K[Bx]"),
    OpcodeInfo::new(4,  "LOADKX",     OpcodeFormat::ABx,  OpcodeEffect::Load,              "R[A] := K[extra arg]"),
    OpcodeInfo::new(5,  "LOADFALSE",  OpcodeFormat::Abc,  OpcodeEffect::Load,              "R[A] := false"),
    OpcodeInfo::new(6,  "LFALSESKIP", OpcodeFormat::Abc,  OpcodeEffect::Load,              "R[A] := false; pc++"),
    OpcodeInfo::new(7,  "LOADTRUE",   OpcodeFormat::Abc,  OpcodeEffect::Load,              "R[A] := true"),
    OpcodeInfo::new(8,  "LOADNIL",    OpcodeFormat::Abc,  OpcodeEffect::Load,              "R[A..A+B] := nil"),
    OpcodeInfo::new(9,  "GETUPVAL",   OpcodeFormat::Abc,  OpcodeEffect::Upvalue,           "R[A] := UpValue[B]"),
    OpcodeInfo::new(10, "SETUPVAL",   OpcodeFormat::Abc,  OpcodeEffect::Upvalue,           "UpValue[B] := R[A]"),
    OpcodeInfo::new(11, "GETTABUP",   OpcodeFormat::Abc,  OpcodeEffect::TableGet,          "R[A] := UpValue[B][K[C]]"),
    OpcodeInfo::new(12, "GETTABI",    OpcodeFormat::Abc,  OpcodeEffect::TableGet,          "R[A] := R[B][C]"),
    OpcodeInfo::new(13, "GETFIELD",   OpcodeFormat::Abc,  OpcodeEffect::TableGet,          "R[A] := R[B][K[C]]"),
    OpcodeInfo::new(14, "GETTABLE",   OpcodeFormat::Abc,  OpcodeEffect::TableGet,          "R[A] := R[B][R[C]]"),
    OpcodeInfo::new(15, "GETI",       OpcodeFormat::Abc,  OpcodeEffect::TableGet,          "R[A] := R[B][C]"),
    OpcodeInfo::new(16, "GETFIELD",   OpcodeFormat::Abc,  OpcodeEffect::TableGet,          "R[A] := R[B][K[C]]"),
    OpcodeInfo::new(17, "SETTABUP",   OpcodeFormat::Abc,  OpcodeEffect::TableSet,          "UpValue[A][K[B]] := R[C]"),
    OpcodeInfo::new(18, "SETTABI",    OpcodeFormat::Abc,  OpcodeEffect::TableSet,          "R[A][B] := R[C]"),
    OpcodeInfo::new(19, "SETFIELD",   OpcodeFormat::Abc,  OpcodeEffect::TableSet,          "R[A][K[B]] := R[C]"),
    OpcodeInfo::new(20, "SETTABLE",   OpcodeFormat::Abc,  OpcodeEffect::TableSet,          "R[A][R[B]] := R[C]"),
    OpcodeInfo::new(21, "SETI",       OpcodeFormat::Abc,  OpcodeEffect::TableSet,          "R[A][B] := R[C]"),
    OpcodeInfo::new(22, "SETFIELD",   OpcodeFormat::Abc,  OpcodeEffect::TableSet,          "R[A][K[B]] := RK[C]"),
    OpcodeInfo::new(23, "NEWTABLE",   OpcodeFormat::Abc,  OpcodeEffect::TableNew,          "R[A] := {} (size=B,C)"),
    OpcodeInfo::new(24, "SELF",       OpcodeFormat::Abc,  OpcodeEffect::TableGet,          "R[A+1] := R[B]; R[A] := R[B][RK[C]]"),
    OpcodeInfo::new(25, "ADDI",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] + sC"),
    OpcodeInfo::new(26, "ADDK",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] + K[C]"),
    OpcodeInfo::new(27, "SUBK",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] - K[C]"),
    OpcodeInfo::new(28, "MULK",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] * K[C]"),
    OpcodeInfo::new(29, "MODK",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] % K[C]"),
    OpcodeInfo::new(30, "POWK",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] ^ K[C]"),
    OpcodeInfo::new(31, "DIVK",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] / K[C]"),
    OpcodeInfo::new(32, "IDIVK",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] // K[C]"),
    OpcodeInfo::new(33, "BANDK",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] & K[C]"),
    OpcodeInfo::new(34, "BORK",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] | K[C]"),
    OpcodeInfo::new(35, "BXORK",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] ~ K[C]"),
    OpcodeInfo::new(36, "SHRI",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] >> sC"),
    OpcodeInfo::new(37, "SHLI",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := sC << R[B]"),
    OpcodeInfo::new(38, "ADD",        OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] + R[C]"),
    OpcodeInfo::new(39, "SUB",        OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] - R[C]"),
    OpcodeInfo::new(40, "MUL",        OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] * R[C]"),
    OpcodeInfo::new(41, "MOD",        OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] % R[C]"),
    OpcodeInfo::new(42, "POW",        OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] ^ R[C]"),
    OpcodeInfo::new(43, "DIV",        OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] / R[C]"),
    OpcodeInfo::new(44, "IDIV",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] // R[C]"),
    OpcodeInfo::new(45, "BAND",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] & R[C]"),
    OpcodeInfo::new(46, "BOR",        OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] | R[C]"),
    OpcodeInfo::new(47, "BXOR",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] ~ R[C]"),
    OpcodeInfo::new(48, "SHL",        OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] << R[C]"),
    OpcodeInfo::new(49, "SHR",        OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := R[B] >> R[C]"),
    OpcodeInfo::new(50, "MMBIN",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "call C metamethod over R[A] and R[B]"),
    OpcodeInfo::new(51, "MMBINI",     OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "call C metamethod over R[A] and sB"),
    OpcodeInfo::new(52, "MMBINK",     OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "call C metamethod over R[A] and K[B]"),
    OpcodeInfo::new(53, "UNM",        OpcodeFormat::Abc,  OpcodeEffect::ArithmeticUnary,   "R[A] := -R[B]"),
    OpcodeInfo::new(54, "BNOT",       OpcodeFormat::Abc,  OpcodeEffect::ArithmeticUnary,   "R[A] := ~R[B]"),
    OpcodeInfo::new(55, "NOT",        OpcodeFormat::Abc,  OpcodeEffect::ArithmeticUnary,   "R[A] := not R[B]"),
    OpcodeInfo::new(56, "LEN",        OpcodeFormat::Abc,  OpcodeEffect::ArithmeticUnary,   "R[A] := #R[B]"),
    OpcodeInfo::new(57, "CONCAT",     OpcodeFormat::Abc,  OpcodeEffect::Concat,            "R[A] := R[A]..R[A+1]..…..R[A+B-1]"),
    OpcodeInfo::new(58, "CLOSE",      OpcodeFormat::Abc,  OpcodeEffect::Upvalue,           "close upvalues ≥ R[A]"),
    OpcodeInfo::new(59, "TBC",        OpcodeFormat::Abc,  OpcodeEffect::Misc,              "mark R[A] as to-be-closed"),
    OpcodeInfo::new(60, "JMP",        OpcodeFormat::SJ,   OpcodeEffect::Jump,              "pc += sJ"),
    OpcodeInfo::new(61, "EQ",         OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (R[A] == R[B]) ~= k then pc++"),
    OpcodeInfo::new(62, "LT",         OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (R[A] <  R[B]) ~= k then pc++"),
    OpcodeInfo::new(63, "LE",         OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (R[A] <= R[B]) ~= k then pc++"),
    OpcodeInfo::new(64, "EQK",        OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (R[A] == K[B]) ~= k then pc++"),
    OpcodeInfo::new(65, "EQI",        OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (R[A] == sB) ~= k then pc++"),
    OpcodeInfo::new(66, "LTI",        OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (R[A] <  sB) ~= k then pc++"),
    OpcodeInfo::new(67, "LEI",        OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (R[A] <= sB) ~= k then pc++"),
    OpcodeInfo::new(68, "GTI",        OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (R[A] >  sB) ~= k then pc++"),
    OpcodeInfo::new(69, "GEI",        OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (R[A] >= sB) ~= k then pc++"),
    OpcodeInfo::new(70, "TEST",       OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (bool(R[A]) ~= k) then pc++"),
    OpcodeInfo::new(71, "TESTSET",    OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (bool(R[B]) ~= k) then pc++ else R[A] := R[B]"),
    OpcodeInfo::new(72, "CALL",       OpcodeFormat::Abc,  OpcodeEffect::Call,              "R[A..(A+C-2)] := R[A](R[A+1]..(A+B-1))"),
    OpcodeInfo::new(73, "TAILCALL",   OpcodeFormat::Abc,  OpcodeEffect::Call,              "return R[A](R[A+1]..(A+B-1))"),
    OpcodeInfo::new(74, "RETURN",     OpcodeFormat::Abc,  OpcodeEffect::Return,            "return R[A..A+B-2]"),
    OpcodeInfo::new(75, "RETURN0",    OpcodeFormat::Abc,  OpcodeEffect::Return,            "return"),
    OpcodeInfo::new(76, "RETURN1",    OpcodeFormat::Abc,  OpcodeEffect::Return,            "return R[A]"),
    OpcodeInfo::new(77, "FORNUM",     OpcodeFormat::ABx,  OpcodeEffect::Loop,              "for numeric loop body"),
    OpcodeInfo::new(78, "FORIN",      OpcodeFormat::Abc,  OpcodeEffect::Loop,              "for-in loop body"),
    OpcodeInfo::new(79, "TFORCALL",   OpcodeFormat::Abc,  OpcodeEffect::Loop,              "R[A+4..A+3+C] := R[A](R[A+1],R[A+2])"),
    OpcodeInfo::new(80, "TFORLOOP",   OpcodeFormat::ABx,  OpcodeEffect::Loop,              "if R[A+2] ~= nil then pc-=Bx; R[A] = R[A+2]"),
    OpcodeInfo::new(81, "SETLIST",    OpcodeFormat::Abc,  OpcodeEffect::TableSet,          "R[A][C*FPF+i] := R[A+i]"),
    OpcodeInfo::new(82, "CLOSURE",    OpcodeFormat::ABx,  OpcodeEffect::Closure,           "R[A] := closure(Proto[Bx])"),
    OpcodeInfo::new(83, "VARARG",     OpcodeFormat::Abc,  OpcodeEffect::Vararg,            "R[A..A+C-2] := vararg"),
    OpcodeInfo::new(84, "VARARGPREP", OpcodeFormat::Abc,  OpcodeEffect::Vararg,            "adjust fixed params for vararg"),
    OpcodeInfo::new(85, "EXTRAARG",   OpcodeFormat::Ax,   OpcodeEffect::Misc,              "extra argument for previous opcode"),
];

// ─────────────────────────────────────────────────────────────────────────────
// Lua 5.1 opcode table
// ─────────────────────────────────────────────────────────────────────────────

/// Static Lua 5.1 opcode table (38 opcodes).
pub static LUA51_OPCODES: &[OpcodeInfo] = &[
    OpcodeInfo::new(0,  "MOVE",     OpcodeFormat::Abc,  OpcodeEffect::Move,              "R[A] := R[B]"),
    OpcodeInfo::new(1,  "LOADK",    OpcodeFormat::ABx,  OpcodeEffect::Load,              "R[A] := K[Bx]"),
    OpcodeInfo::new(2,  "LOADBOOL", OpcodeFormat::Abc,  OpcodeEffect::Load,              "R[A] := (Bool)B; if C then pc++"),
    OpcodeInfo::new(3,  "LOADNIL",  OpcodeFormat::Abc,  OpcodeEffect::Load,              "R[A..B] := nil"),
    OpcodeInfo::new(4,  "GETUPVAL", OpcodeFormat::Abc,  OpcodeEffect::Upvalue,           "R[A] := UpValue[B]"),
    OpcodeInfo::new(5,  "GETGLOBAL",OpcodeFormat::ABx,  OpcodeEffect::Load,              "R[A] := Gbl[K[Bx]]"),
    OpcodeInfo::new(6,  "GETTABLE", OpcodeFormat::Abc,  OpcodeEffect::TableGet,          "R[A] := R[B][RK[C]]"),
    OpcodeInfo::new(7,  "SETGLOBAL",OpcodeFormat::ABx,  OpcodeEffect::Misc,              "Gbl[K[Bx]] := R[A]"),
    OpcodeInfo::new(8,  "SETUPVAL", OpcodeFormat::Abc,  OpcodeEffect::Upvalue,           "UpValue[B] := R[A]"),
    OpcodeInfo::new(9,  "SETTABLE", OpcodeFormat::Abc,  OpcodeEffect::TableSet,          "R[A][RK[B]] := RK[C]"),
    OpcodeInfo::new(10, "NEWTABLE", OpcodeFormat::Abc,  OpcodeEffect::TableNew,          "R[A] := {} (size=B,C)"),
    OpcodeInfo::new(11, "SELF",     OpcodeFormat::Abc,  OpcodeEffect::TableGet,          "R[A+1] := R[B]; R[A] := R[B][RK[C]]"),
    OpcodeInfo::new(12, "ADD",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := RK[B]+RK[C]"),
    OpcodeInfo::new(13, "SUB",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := RK[B]-RK[C]"),
    OpcodeInfo::new(14, "MUL",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := RK[B]*RK[C]"),
    OpcodeInfo::new(15, "DIV",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := RK[B]/RK[C]"),
    OpcodeInfo::new(16, "MOD",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := RK[B]%RK[C]"),
    OpcodeInfo::new(17, "POW",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticBinary,  "R[A] := RK[B]^RK[C]"),
    OpcodeInfo::new(18, "UNM",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticUnary,   "R[A] := -R[B]"),
    OpcodeInfo::new(19, "NOT",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticUnary,   "R[A] := not R[B]"),
    OpcodeInfo::new(20, "LEN",      OpcodeFormat::Abc,  OpcodeEffect::ArithmeticUnary,   "R[A] := length of R[B]"),
    OpcodeInfo::new(21, "CONCAT",   OpcodeFormat::Abc,  OpcodeEffect::Concat,            "R[A] := R[B]..…..R[C]"),
    OpcodeInfo::new(22, "JMP",      OpcodeFormat::AsBx, OpcodeEffect::Jump,              "pc += sBx"),
    OpcodeInfo::new(23, "EQ",       OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (RK[B]==RK[C]) ~= A then pc++"),
    OpcodeInfo::new(24, "LT",       OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (RK[B]<RK[C]) ~= A then pc++"),
    OpcodeInfo::new(25, "LE",       OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (RK[B]<=RK[C]) ~= A then pc++"),
    OpcodeInfo::new(26, "TEST",     OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if not (R[A] <=> C) then pc++"),
    OpcodeInfo::new(27, "TESTSET",  OpcodeFormat::Abc,  OpcodeEffect::CompareAndBranch,  "if (R[B] <=> C) then R[A]:=R[B] else pc++"),
    OpcodeInfo::new(28, "CALL",     OpcodeFormat::Abc,  OpcodeEffect::Call,              "R[A..A+C-2] := R[A](R[A+1]..A+B-1)"),
    OpcodeInfo::new(29, "TAILCALL", OpcodeFormat::Abc,  OpcodeEffect::Call,              "return R[A](R[A+1]..A+B-1)"),
    OpcodeInfo::new(30, "RETURN",   OpcodeFormat::Abc,  OpcodeEffect::Return,            "return R[A..A+B-2]"),
    OpcodeInfo::new(31, "FORLOOP",  OpcodeFormat::AsBx, OpcodeEffect::Loop,              "R[A]+=R[A+2]; if R[A]<=R[A+1] then pc-=sBx"),
    OpcodeInfo::new(32, "FORPREP",  OpcodeFormat::AsBx, OpcodeEffect::Loop,              "R[A]-=R[A+2]; pc+=sBx"),
    OpcodeInfo::new(33, "TFORLOOP", OpcodeFormat::Abc,  OpcodeEffect::Loop,              "R[A+3]..R[A+2+C] := R[A](R[A+1],R[A+2])"),
    OpcodeInfo::new(34, "SETLIST",  OpcodeFormat::Abc,  OpcodeEffect::TableSet,          "R[A][Bx*FPF+i] := R[A+i]"),
    OpcodeInfo::new(35, "CLOSE",    OpcodeFormat::Abc,  OpcodeEffect::Upvalue,           "close upvalues from R[A]"),
    OpcodeInfo::new(36, "CLOSURE",  OpcodeFormat::ABx,  OpcodeEffect::Closure,           "R[A] := closure(Proto[Bx])"),
    OpcodeInfo::new(37, "VARARG",   OpcodeFormat::Abc,  OpcodeEffect::Vararg,            "R[A..A+B-1] := vararg"),
];

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lua54_table_length() {
        assert_eq!(LUA54_OPCODES.len(), 86);
    }

    #[test]
    fn lua51_table_length() {
        assert_eq!(LUA51_OPCODES.len(), 38);
    }

    #[test]
    fn opcode_name_move() {
        assert_eq!(opcode_name(4, 0), "MOVE");
        assert_eq!(opcode_name(1, 0), "MOVE");
    }

    #[test]
    fn opcode_name_unknown() {
        assert_eq!(opcode_name(4, 200), "UNKNOWN");
    }

    #[test]
    fn opcode_format_jmp_54() {
        // JMP (60) in Lua 5.4 uses isJ format.
        assert_eq!(opcode_format(60), OpcodeFormat::SJ);
    }

    #[test]
    fn opcode_format_loadk() {
        // LOADK (3) uses iABx.
        assert_eq!(opcode_format(3), OpcodeFormat::ABx);
    }

    #[test]
    fn lua_opcode_from_u8_54() {
        assert_eq!(LuaOpcode::from_u8_54(0), Some(LuaOpcode::Move));
        assert_eq!(LuaOpcode::from_u8_54(72), Some(LuaOpcode::Call));
        assert_eq!(LuaOpcode::from_u8_54(200), None);
    }

    #[test]
    fn lua_opcode_name() {
        assert_eq!(LuaOpcode::Call.name(), "CALL");
        assert_eq!(LuaOpcode::Return.name(), "RETURN");
    }

    #[test]
    fn lua_opcode_display() {
        assert_eq!(LuaOpcode::Move.to_string(), "MOVE");
    }

    #[test]
    fn opcode_info_display() {
        let info = &LUA54_OPCODES[0];
        let s = info.to_string();
        assert!(s.contains("MOVE"));
    }

    #[test]
    fn opcode_format_display() {
        assert_eq!(OpcodeFormat::Abc.to_string(), "iABC");
        assert_eq!(OpcodeFormat::SJ.to_string(), "isJ");
    }

    #[test]
    fn opcode_effect_display() {
        assert_eq!(OpcodeEffect::Call.to_string(), "call");
    }

    #[test]
    fn lua51_call_opcode() {
        assert_eq!(opcode_name(1, 28), "CALL");
    }

    #[test]
    fn lua54_closure_format() {
        let info = &LUA54_OPCODES[82]; // CLOSURE
        assert_eq!(info.format, OpcodeFormat::ABx);
        assert_eq!(info.effect, OpcodeEffect::Closure);
    }

    #[test]
    fn opcode_name_version_dispatch() {
        // In 5.1, opcode 22 is JMP; in 5.4, opcode 60 is JMP.
        assert_eq!(opcode_name(1, 22), "JMP");
        assert_eq!(opcode_name(4, 60), "JMP");
    }
}
