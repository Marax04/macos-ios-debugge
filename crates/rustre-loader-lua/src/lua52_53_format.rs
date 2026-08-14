//! Lua 5.2 and 5.3 bytecode format differences.
//!
//! Handles version `0x52` and `0x53` headers, new opcodes (GETTABUP, SETTABUP,
//! GETTABLE/SETTABLE differences, SELF), Lua 5.3's integer/float subtype.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, Cursor, Read};

use crate::lua51_format::{
    LUA_MAGIC, LUA52_VERSION, LUA53_VERSION, read_f64_le, read_i32_le, read_lua_string, read_u8,
    read_u32_le,
};

// We re-export the reader helpers for internal use.
// (In a real crate they'd be pub(crate) in a shared module.)

// ─────────────────────────────────────────────────────────────────────────────
// Lua 5.2 header
// ─────────────────────────────────────────────────────────────────────────────

/// The Lua 5.2 file header (12 + 6 integrity bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lua52Header {
    pub magic: [u8; 4],
    pub version: u8,
    pub format: u8,
    /// Lua 5.2 adds a 6-byte integrity marker `\x19\x93\r\n\x1a\n`.
    pub integrity: [u8; 6],
    pub endian: u8,
    pub int_size: u8,
    pub size_t_size: u8,
    pub instr_size: u8,
    pub number_size: u8,
    pub integral_flag: u8,
}

impl Lua52Header {
    pub const INTEGRITY: &'static [u8; 6] = b"\x19\x93\r\n\x1a\n";

    pub fn parse(data: &[u8]) -> Result<(Self, usize), String> {
        if data.len() < 18 {
            return Err("Lua 5.2 header too short".into());
        }
        if &data[0..4] != LUA_MAGIC {
            return Err("invalid magic".into());
        }
        if data[4] != LUA52_VERSION {
            return Err(format!("not Lua 5.2 (version=0x{:02x})", data[4]));
        }
        let integrity: [u8; 6] = data[6..12].try_into().map_err(|_| "integrity")?;
        if &integrity != Self::INTEGRITY {
            return Err("integrity check failed".into());
        }
        Ok((
            Self {
                magic: [data[0], data[1], data[2], data[3]],
                version: data[4],
                format: data[5],
                integrity,
                endian: data[12],
                int_size: data[13],
                size_t_size: data[14],
                instr_size: data[15],
                number_size: data[16],
                integral_flag: data[17],
            },
            18,
        ))
    }

    pub fn is_little_endian(&self) -> bool {
        self.endian == 1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua 5.2 opcodes (42 total)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Lua52Opcode {
    Move = 0,
    LoadK = 1,
    LoadKx = 2, // NEW in 5.2: LOADKX for large constants
    LoadBool = 3,
    LoadNil = 4,
    GetUpval = 5,
    GetTabUp = 6,   // NEW: GETTABUP (upvalue table access)
    GetTableUp = 7, // same slot, alternate name
    GetTable = 8,
    SetTabUp = 9, // NEW: SETTABUP
    SetUpval = 10,
    SetTable = 11,
    NewTable = 12,
    Self_ = 13,
    Add = 14,
    Sub = 15,
    Mul = 16,
    Div = 17,
    Mod = 18,
    Pow = 19,
    Unm = 20,
    Not = 21,
    Len = 22,
    Concat = 23,
    Jmp = 24,
    Eq = 25,
    Lt = 26,
    Le = 27,
    Test = 28,
    TestSet = 29,
    Call = 30,
    TailCall = 31,
    Return = 32,
    ForLoop = 33,
    ForPrep = 34,
    TForCall = 35, // NEW: TFORCALL
    TForLoop = 36,
    SetList = 37,
    Close = 38,
    Closure = 39,
    VarArg = 40,
    ExtraArg = 41, // NEW: EXTRAARG (for LOADKX)
}

impl Lua52Opcode {
    pub fn from_u8(n: u8) -> Option<Self> {
        Some(match n {
            0 => Self::Move,
            1 => Self::LoadK,
            2 => Self::LoadKx,
            3 => Self::LoadBool,
            4 => Self::LoadNil,
            5 => Self::GetUpval,
            6 => Self::GetTabUp,
            7 => Self::GetTableUp,
            8 => Self::GetTable,
            9 => Self::SetTabUp,
            10 => Self::SetUpval,
            11 => Self::SetTable,
            12 => Self::NewTable,
            13 => Self::Self_,
            14 => Self::Add,
            15 => Self::Sub,
            16 => Self::Mul,
            17 => Self::Div,
            18 => Self::Mod,
            19 => Self::Pow,
            20 => Self::Unm,
            21 => Self::Not,
            22 => Self::Len,
            23 => Self::Concat,
            24 => Self::Jmp,
            25 => Self::Eq,
            26 => Self::Lt,
            27 => Self::Le,
            28 => Self::Test,
            29 => Self::TestSet,
            30 => Self::Call,
            31 => Self::TailCall,
            32 => Self::Return,
            33 => Self::ForLoop,
            34 => Self::ForPrep,
            35 => Self::TForCall,
            36 => Self::TForLoop,
            37 => Self::SetList,
            38 => Self::Close,
            39 => Self::Closure,
            40 => Self::VarArg,
            41 => Self::ExtraArg,
            _ => return None,
        })
    }

    pub fn mnemonic(self) -> &'static str {
        match self {
            Self::Move => "MOVE",
            Self::LoadK => "LOADK",
            Self::LoadKx => "LOADKX",
            Self::LoadBool => "LOADBOOL",
            Self::LoadNil => "LOADNIL",
            Self::GetUpval => "GETUPVAL",
            Self::GetTabUp => "GETTABUP",
            Self::GetTableUp => "GETTABUP",
            Self::GetTable => "GETTABLE",
            Self::SetTabUp => "SETTABUP",
            Self::SetUpval => "SETUPVAL",
            Self::SetTable => "SETTABLE",
            Self::NewTable => "NEWTABLE",
            Self::Self_ => "SELF",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Div => "DIV",
            Self::Mod => "MOD",
            Self::Pow => "POW",
            Self::Unm => "UNM",
            Self::Not => "NOT",
            Self::Len => "LEN",
            Self::Concat => "CONCAT",
            Self::Jmp => "JMP",
            Self::Eq => "EQ",
            Self::Lt => "LT",
            Self::Le => "LE",
            Self::Test => "TEST",
            Self::TestSet => "TESTSET",
            Self::Call => "CALL",
            Self::TailCall => "TAILCALL",
            Self::Return => "RETURN",
            Self::ForLoop => "FORLOOP",
            Self::ForPrep => "FORPREP",
            Self::TForCall => "TFORCALL",
            Self::TForLoop => "TFORLOOP",
            Self::SetList => "SETLIST",
            Self::Close => "CLOSE",
            Self::Closure => "CLOSURE",
            Self::VarArg => "VARARG",
            Self::ExtraArg => "EXTRAARG",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua52Constant
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Lua52Constant {
    Nil,
    Boolean(bool),
    Number(f64),
    String(String),
}

impl fmt::Display for Lua52Constant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => f.write_str("nil"),
            Self::Boolean(b) => write!(f, "{}", b),
            Self::Number(n) => write!(f, "{}", n),
            Self::String(s) => write!(f, "{:?}", s),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua52Proto
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lua52UpvalDesc {
    pub in_stack: bool,
    pub idx: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lua52Proto {
    pub source_name: Option<String>,
    pub line_defined: i32,
    pub last_line_defined: i32,
    pub num_params: u8,
    pub is_vararg: u8,
    pub max_stack_size: u8,
    pub code: Vec<u32>,
    pub constants: Vec<Lua52Constant>,
    pub upvalues: Vec<Lua52UpvalDesc>,
    pub protos: Vec<Lua52Proto>,
    pub source_lines: Vec<i32>,
    pub locals: Vec<Lua52Local>,
    pub upvalue_names: Vec<Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lua52Local {
    pub name: Option<String>,
    pub start_pc: i32,
    pub end_pc: i32,
}

impl Lua52Proto {
    pub fn instr_count(&self) -> usize {
        self.code.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// decode_lua52_proto
// ─────────────────────────────────────────────────────────────────────────────

pub fn decode_lua52_proto(cur: &mut Cursor<&[u8]>) -> Result<Lua52Proto, String> {
    let source_name = read_lua_string(cur).map_err(|e| format!("52 source: {}", e))?;
    let line_defined = read_i32_le(cur).map_err(|e| format!("52 line_def: {}", e))?;
    let last_line_defined = read_i32_le(cur).map_err(|e| format!("52 last_line: {}", e))?;
    let num_params = read_u8(cur).map_err(|e| format!("52 params: {}", e))?;
    let is_vararg = read_u8(cur).map_err(|e| format!("52 vararg: {}", e))?;
    let max_stack_size = read_u8(cur).map_err(|e| format!("52 stack: {}", e))?;

    let n_code = read_u32_le(cur).map_err(|e| format!("52 n_code: {}", e))?;
    let mut code = Vec::with_capacity(n_code as usize);
    for _ in 0..n_code {
        code.push(read_u32_le(cur).map_err(|e| format!("52 instr: {}", e))?);
    }

    let n_const = read_u32_le(cur).map_err(|e| format!("52 n_const: {}", e))?;
    let mut constants = Vec::with_capacity(n_const as usize);
    for _ in 0..n_const {
        let tag = read_u8(cur).map_err(|e| format!("52 const tag: {}", e))?;
        let c = match tag {
            0 => Lua52Constant::Nil,
            1 => Lua52Constant::Boolean(read_u8(cur).map_err(|e| format!("{}", e))? != 0),
            3 => Lua52Constant::Number(read_f64_le(cur).map_err(|e| format!("{}", e))?),
            4 => Lua52Constant::String(
                read_lua_string(cur)
                    .map_err(|e| format!("{}", e))?
                    .unwrap_or_default(),
            ),
            _ => return Err(format!("52 unknown const tag {}", tag)),
        };
        constants.push(c);
    }

    let n_upvals = read_u32_le(cur).map_err(|e| format!("52 n_upvals: {}", e))?;
    let mut upvalues = Vec::with_capacity(n_upvals as usize);
    for _ in 0..n_upvals {
        let in_stack = read_u8(cur).map_err(|e| format!("{}", e))? != 0;
        let idx = read_u8(cur).map_err(|e| format!("{}", e))?;
        upvalues.push(Lua52UpvalDesc { in_stack, idx });
    }

    let n_proto = read_u32_le(cur).map_err(|e| format!("52 n_proto: {}", e))?;
    let mut protos = Vec::with_capacity(n_proto as usize);
    for _ in 0..n_proto {
        protos.push(decode_lua52_proto(cur)?);
    }

    let n_lines = read_u32_le(cur).map_err(|e| format!("52 n_lines: {}", e))?;
    let mut source_lines = Vec::with_capacity(n_lines as usize);
    for _ in 0..n_lines {
        source_lines.push(read_i32_le(cur).map_err(|e| format!("{}", e))?);
    }

    let n_locals = read_u32_le(cur).map_err(|e| format!("52 n_locals: {}", e))?;
    let mut locals = Vec::with_capacity(n_locals as usize);
    for _ in 0..n_locals {
        let name = read_lua_string(cur).map_err(|e| format!("{}", e))?;
        let start_pc = read_i32_le(cur).map_err(|e| format!("{}", e))?;
        let end_pc = read_i32_le(cur).map_err(|e| format!("{}", e))?;
        locals.push(Lua52Local {
            name,
            start_pc,
            end_pc,
        });
    }

    let n_upval_names = read_u32_le(cur).map_err(|e| format!("52 n_upval_names: {}", e))?;
    let mut upvalue_names = Vec::with_capacity(n_upval_names as usize);
    for _ in 0..n_upval_names {
        upvalue_names.push(read_lua_string(cur).map_err(|e| format!("{}", e))?);
    }

    Ok(Lua52Proto {
        source_name,
        line_defined,
        last_line_defined,
        num_params,
        is_vararg,
        max_stack_size,
        code,
        constants,
        upvalues,
        protos,
        source_lines,
        locals,
        upvalue_names,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua 5.3 header and types
// ─────────────────────────────────────────────────────────────────────────────

/// The Lua 5.3 file header.
/// Adds integer and float size fields compared to 5.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lua53Header {
    pub magic: [u8; 4],
    pub version: u8,
    pub format: u8,
    pub integrity: [u8; 6],
    pub endian: u8,
    pub int_size: u8,
    pub size_t_size: u8,
    pub instr_size: u8,
    /// Size of Lua integer (`lua_Integer`), new in 5.3.
    pub lua_int_size: u8,
    /// Size of Lua float (`lua_Number`).
    pub lua_float_size: u8,
}

impl Lua53Header {
    pub const INTEGRITY: &'static [u8; 6] = b"\x19\x93\r\n\x1a\n";
    /// Sentinel integer value embedded in Lua 5.3 headers to verify
    /// little/big-endian byte order matches the host.
    pub const EXPECTED_INT: i64 = 0x5678;
    /// Sentinel float value embedded in Lua 5.3 headers to verify the
    /// expected `lua_Number` layout (IEEE-754 double precision).
    pub const EXPECTED_FLOAT: f64 = 370.5;

    /// Returns `true` when `int_marker` and `float_marker` decoded from a Lua
    /// 5.3 header match the [`Self::EXPECTED_INT`] / [`Self::EXPECTED_FLOAT`]
    /// sentinels.
    #[must_use]
    pub fn check_sentinels(int_marker: i64, float_marker: f64) -> bool {
        int_marker == Self::EXPECTED_INT
            && (float_marker - Self::EXPECTED_FLOAT).abs() < f64::EPSILON
    }

    pub fn parse(data: &[u8]) -> Result<(Self, usize), String> {
        if data.len() < 19 {
            return Err("Lua 5.3 header too short".into());
        }
        if &data[0..4] != LUA_MAGIC {
            return Err("invalid magic".into());
        }
        if data[4] != LUA53_VERSION {
            return Err(format!("not Lua 5.3 (version=0x{:02x})", data[4]));
        }
        let integrity: [u8; 6] = data[6..12].try_into().map_err(|_| "integrity")?;
        if &integrity != Self::INTEGRITY {
            return Err("integrity check failed".into());
        }
        Ok((
            Self {
                magic: [data[0], data[1], data[2], data[3]],
                version: data[4],
                format: data[5],
                integrity,
                endian: data[12],
                int_size: data[13],
                size_t_size: data[14],
                instr_size: data[15],
                lua_int_size: data[16],
                lua_float_size: data[17],
            },
            18,
        ))
    }

    pub fn is_little_endian(&self) -> bool {
        self.endian == 1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua 5.3 opcodes (47 total)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Lua53Opcode {
    Move = 0,
    LoadK = 1,
    LoadKx = 2,
    LoadBool = 3,
    LoadNil = 4,
    GetUpval = 5,
    GetTabUp = 6,
    GetTable = 7,
    SetTabUp = 8,
    SetUpval = 9,
    SetTable = 10,
    NewTable = 11,
    Self_ = 12,
    Add = 13,
    Sub = 14,
    Mul = 15,
    Mod = 16,
    Pow = 17,
    Div = 18,
    IDiv = 19, // NEW in 5.3: integer division
    BAnd = 20, // NEW: bitwise AND
    BOr = 21,  // NEW: bitwise OR
    BXor = 22, // NEW: bitwise XOR
    Shl = 23,  // NEW: shift left
    Shr = 24,  // NEW: shift right
    Unm = 25,
    BNot = 26, // NEW: bitwise NOT
    Not = 27,
    Len = 28,
    Concat = 29,
    Jmp = 30,
    Eq = 31,
    Lt = 32,
    Le = 33,
    Test = 34,
    TestSet = 35,
    Call = 36,
    TailCall = 37,
    Return = 38,
    ForLoop = 39,
    ForPrep = 40,
    TForCall = 41,
    TForLoop = 42,
    SetList = 43,
    Closure = 44,
    VarArg = 45,
    ExtraArg = 46,
}

impl Lua53Opcode {
    pub fn from_u8(n: u8) -> Option<Self> {
        Some(match n {
            0 => Self::Move,
            1 => Self::LoadK,
            2 => Self::LoadKx,
            3 => Self::LoadBool,
            4 => Self::LoadNil,
            5 => Self::GetUpval,
            6 => Self::GetTabUp,
            7 => Self::GetTable,
            8 => Self::SetTabUp,
            9 => Self::SetUpval,
            10 => Self::SetTable,
            11 => Self::NewTable,
            12 => Self::Self_,
            13 => Self::Add,
            14 => Self::Sub,
            15 => Self::Mul,
            16 => Self::Mod,
            17 => Self::Pow,
            18 => Self::Div,
            19 => Self::IDiv,
            20 => Self::BAnd,
            21 => Self::BOr,
            22 => Self::BXor,
            23 => Self::Shl,
            24 => Self::Shr,
            25 => Self::Unm,
            26 => Self::BNot,
            27 => Self::Not,
            28 => Self::Len,
            29 => Self::Concat,
            30 => Self::Jmp,
            31 => Self::Eq,
            32 => Self::Lt,
            33 => Self::Le,
            34 => Self::Test,
            35 => Self::TestSet,
            36 => Self::Call,
            37 => Self::TailCall,
            38 => Self::Return,
            39 => Self::ForLoop,
            40 => Self::ForPrep,
            41 => Self::TForCall,
            42 => Self::TForLoop,
            43 => Self::SetList,
            44 => Self::Closure,
            45 => Self::VarArg,
            46 => Self::ExtraArg,
            _ => return None,
        })
    }

    pub fn mnemonic(self) -> &'static str {
        match self {
            Self::Move => "MOVE",
            Self::LoadK => "LOADK",
            Self::LoadKx => "LOADKX",
            Self::LoadBool => "LOADBOOL",
            Self::LoadNil => "LOADNIL",
            Self::GetUpval => "GETUPVAL",
            Self::GetTabUp => "GETTABUP",
            Self::GetTable => "GETTABLE",
            Self::SetTabUp => "SETTABUP",
            Self::SetUpval => "SETUPVAL",
            Self::SetTable => "SETTABLE",
            Self::NewTable => "NEWTABLE",
            Self::Self_ => "SELF",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Mod => "MOD",
            Self::Pow => "POW",
            Self::Div => "DIV",
            Self::IDiv => "IDIV",
            Self::BAnd => "BAND",
            Self::BOr => "BOR",
            Self::BXor => "BXOR",
            Self::Shl => "SHL",
            Self::Shr => "SHR",
            Self::Unm => "UNM",
            Self::BNot => "BNOT",
            Self::Not => "NOT",
            Self::Len => "LEN",
            Self::Concat => "CONCAT",
            Self::Jmp => "JMP",
            Self::Eq => "EQ",
            Self::Lt => "LT",
            Self::Le => "LE",
            Self::Test => "TEST",
            Self::TestSet => "TESTSET",
            Self::Call => "CALL",
            Self::TailCall => "TAILCALL",
            Self::Return => "RETURN",
            Self::ForLoop => "FORLOOP",
            Self::ForPrep => "FORPREP",
            Self::TForCall => "TFORCALL",
            Self::TForLoop => "TFORLOOP",
            Self::SetList => "SETLIST",
            Self::Closure => "CLOSURE",
            Self::VarArg => "VARARG",
            Self::ExtraArg => "EXTRAARG",
        }
    }

    /// Returns true if this opcode is new in Lua 5.3.
    pub fn is_new_in_53(self) -> bool {
        matches!(
            self,
            Self::IDiv | Self::BAnd | Self::BOr | Self::BXor | Self::Shl | Self::Shr | Self::BNot
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua53Constant — adds integer type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Lua53Constant {
    Nil,
    Boolean(bool),
    Integer(i64), // NEW in 5.3: distinct integer type
    Float(f64),
    String(String),
}

impl fmt::Display for Lua53Constant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => f.write_str("nil"),
            Self::Boolean(b) => write!(f, "{}", b),
            Self::Integer(n) => write!(f, "{}i", n),
            Self::Float(n) => write!(f, "{}f", n),
            Self::String(s) => write!(f, "{:?}", s),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua53Proto — mirrors 52 plus integer constants
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lua53Proto {
    pub source_name: Option<String>,
    pub line_defined: i32,
    pub last_line_defined: i32,
    pub num_params: u8,
    pub is_vararg: u8,
    pub max_stack_size: u8,
    pub code: Vec<u32>,
    pub constants: Vec<Lua53Constant>,
    pub upvalues: Vec<(bool, u8)>,
    pub protos: Vec<Lua53Proto>,
    pub source_lines: Vec<i32>,
    pub locals: Vec<(Option<String>, i32, i32)>,
    pub upvalue_names: Vec<Option<String>>,
}

impl Lua53Proto {
    pub fn instr_count(&self) -> usize {
        self.code.len()
    }
    pub fn integer_constants(&self) -> Vec<i64> {
        self.constants
            .iter()
            .filter_map(|c| {
                if let Lua53Constant::Integer(n) = c {
                    Some(*n)
                } else {
                    None
                }
            })
            .collect()
    }
    pub fn float_constants(&self) -> Vec<f64> {
        self.constants
            .iter()
            .filter_map(|c| {
                if let Lua53Constant::Float(n) = c {
                    Some(*n)
                } else {
                    None
                }
            })
            .collect()
    }
}

fn read_i64_le(cur: &mut Cursor<&[u8]>) -> io::Result<i64> {
    let mut buf = [0u8; 8];
    cur.read_exact(&mut buf)?;
    Ok(i64::from_le_bytes(buf))
}

// ─────────────────────────────────────────────────────────────────────────────
// decode_lua53_proto
// ─────────────────────────────────────────────────────────────────────────────

pub fn decode_lua53_proto(cur: &mut Cursor<&[u8]>) -> Result<Lua53Proto, String> {
    let source_name = read_lua_string(cur).map_err(|e| format!("53 source: {}", e))?;
    let line_defined = read_i32_le(cur).map_err(|e| format!("53 line_def: {}", e))?;
    let last_line_defined = read_i32_le(cur).map_err(|e| format!("53 last_line: {}", e))?;
    let num_params = read_u8(cur).map_err(|e| format!("53 params: {}", e))?;
    let is_vararg = read_u8(cur).map_err(|e| format!("53 vararg: {}", e))?;
    let max_stack_size = read_u8(cur).map_err(|e| format!("53 stack: {}", e))?;

    let n_code = read_u32_le(cur).map_err(|e| format!("53 n_code: {}", e))?;
    let mut code = Vec::with_capacity(n_code as usize);
    for _ in 0..n_code {
        code.push(read_u32_le(cur).map_err(|e| format!("{}", e))?);
    }

    let n_const = read_u32_le(cur).map_err(|e| format!("53 n_const: {}", e))?;
    let mut constants = Vec::with_capacity(n_const as usize);
    for _ in 0..n_const {
        let tag = read_u8(cur).map_err(|e| format!("{}", e))?;
        let c = match tag {
            0 => Lua53Constant::Nil,
            1 => Lua53Constant::Boolean(read_u8(cur).map_err(|e| format!("{}", e))? != 0),
            0x13 => Lua53Constant::Integer(read_i64_le(cur).map_err(|e| format!("{}", e))?),
            0x03 => Lua53Constant::Float(read_f64_le(cur).map_err(|e| format!("{}", e))?),
            0x14 | 0x04 => Lua53Constant::String(
                read_lua_string(cur)
                    .map_err(|e| format!("{}", e))?
                    .unwrap_or_default(),
            ),
            _ => return Err(format!("53 unknown const tag {}", tag)),
        };
        constants.push(c);
    }

    let n_upvals = read_u32_le(cur).map_err(|e| format!("53 n_upvals: {}", e))?;
    let mut upvalues = Vec::with_capacity(n_upvals as usize);
    for _ in 0..n_upvals {
        let in_stack = read_u8(cur).map_err(|e| format!("{}", e))? != 0;
        let idx = read_u8(cur).map_err(|e| format!("{}", e))?;
        upvalues.push((in_stack, idx));
    }

    let n_proto = read_u32_le(cur).map_err(|e| format!("53 n_proto: {}", e))?;
    let mut protos = Vec::with_capacity(n_proto as usize);
    for _ in 0..n_proto {
        protos.push(decode_lua53_proto(cur)?);
    }

    let n_lines = read_u32_le(cur).map_err(|e| format!("53 n_lines: {}", e))?;
    let mut source_lines = Vec::with_capacity(n_lines as usize);
    for _ in 0..n_lines {
        source_lines.push(read_i32_le(cur).map_err(|e| format!("{}", e))?);
    }

    let n_locals = read_u32_le(cur).map_err(|e| format!("53 n_locals: {}", e))?;
    let mut locals = Vec::with_capacity(n_locals as usize);
    for _ in 0..n_locals {
        let name = read_lua_string(cur).map_err(|e| format!("{}", e))?;
        let start = read_i32_le(cur).map_err(|e| format!("{}", e))?;
        let end = read_i32_le(cur).map_err(|e| format!("{}", e))?;
        locals.push((name, start, end));
    }

    let n_upval_names = read_u32_le(cur).map_err(|e| format!("53 n_upval_names: {}", e))?;
    let mut upvalue_names = Vec::with_capacity(n_upval_names as usize);
    for _ in 0..n_upval_names {
        upvalue_names.push(read_lua_string(cur).map_err(|e| format!("{}", e))?);
    }

    Ok(Lua53Proto {
        source_name,
        line_defined,
        last_line_defined,
        num_params,
        is_vararg,
        max_stack_size,
        code,
        constants,
        upvalues,
        protos,
        source_lines,
        locals,
        upvalue_names,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- Lua52Header ---

    #[test]
    fn lua52_header_wrong_magic() {
        let data = [0u8; 18];
        assert!(Lua52Header::parse(&data).is_err());
    }

    #[test]
    fn lua52_header_wrong_version() {
        let mut data = [0u8; 18];
        data[0..4].copy_from_slice(LUA_MAGIC);
        data[4] = 0x51;
        assert!(Lua52Header::parse(&data).is_err());
    }

    #[test]
    fn lua52_header_valid() {
        let mut data = [0u8; 18];
        data[0..4].copy_from_slice(LUA_MAGIC);
        data[4] = LUA52_VERSION;
        data[5] = 0;
        data[6..12].copy_from_slice(Lua52Header::INTEGRITY);
        let (hdr, n) = Lua52Header::parse(&data).unwrap();
        assert_eq!(n, 18);
        assert_eq!(hdr.version, LUA52_VERSION);
    }

    #[test]
    fn lua52_header_integrity_mismatch() {
        let mut data = [0u8; 18];
        data[0..4].copy_from_slice(LUA_MAGIC);
        data[4] = LUA52_VERSION;
        data[6..12].copy_from_slice(b"\x00\x00\x00\x00\x00\x00");
        assert!(Lua52Header::parse(&data).is_err());
    }

    // --- Lua52Opcode ---

    #[test]
    fn lua52_opcode_gettabup() {
        assert_eq!(Lua52Opcode::from_u8(6), Some(Lua52Opcode::GetTabUp));
        assert_eq!(Lua52Opcode::GetTabUp.mnemonic(), "GETTABUP");
    }

    #[test]
    fn lua52_opcode_extraarg() {
        assert_eq!(Lua52Opcode::from_u8(41), Some(Lua52Opcode::ExtraArg));
    }

    #[test]
    fn lua52_opcode_out_of_range() {
        assert_eq!(Lua52Opcode::from_u8(42), None);
    }

    #[test]
    fn lua52_opcode_tforcall() {
        assert_eq!(Lua52Opcode::TForCall.mnemonic(), "TFORCALL");
    }

    // --- Lua52Constant ---

    #[test]
    fn lua52_const_display_nil() {
        assert_eq!(format!("{}", Lua52Constant::Nil), "nil");
    }

    #[test]
    fn lua52_const_display_number() {
        let s = format!("{}", Lua52Constant::Number(2.718_f64));
        assert!(s.contains("2.718"));
    }

    // --- Lua53Header ---

    #[test]
    fn lua53_header_wrong_version() {
        let mut data = [0u8; 19];
        data[0..4].copy_from_slice(LUA_MAGIC);
        data[4] = LUA52_VERSION;
        assert!(Lua53Header::parse(&data).is_err());
    }

    #[test]
    fn lua53_header_valid() {
        let mut data = [0u8; 19];
        data[0..4].copy_from_slice(LUA_MAGIC);
        data[4] = LUA53_VERSION;
        data[6..12].copy_from_slice(Lua53Header::INTEGRITY);
        let (hdr, _) = Lua53Header::parse(&data).unwrap();
        assert_eq!(hdr.version, LUA53_VERSION);
    }

    #[test]
    fn lua53_header_too_short() {
        let data = [0u8; 10];
        assert!(Lua53Header::parse(&data).is_err());
    }

    // --- Lua53Opcode ---

    #[test]
    fn lua53_opcode_idiv_is_new() {
        assert!(Lua53Opcode::IDiv.is_new_in_53());
    }

    #[test]
    fn lua53_opcode_add_not_new() {
        assert!(!Lua53Opcode::Add.is_new_in_53());
    }

    #[test]
    fn lua53_opcode_bnot() {
        assert_eq!(Lua53Opcode::BNot.mnemonic(), "BNOT");
    }

    #[test]
    fn lua53_opcode_shl_is_new() {
        assert!(Lua53Opcode::Shl.is_new_in_53());
    }

    #[test]
    fn lua53_opcode_count_new() {
        
        assert_eq!((0u8..47)
            .filter_map(Lua53Opcode::from_u8)
            .filter(|op| op.is_new_in_53()).count(), 7); // IDiv, BAnd, BOr, BXor, Shl, Shr, BNot
    }

    // --- Lua53Constant ---

    #[test]
    fn lua53_const_display_integer() {
        assert_eq!(format!("{}", Lua53Constant::Integer(42)), "42i");
    }

    #[test]
    fn lua53_const_display_float() {
        let s = format!("{}", Lua53Constant::Float(1.5));
        assert!(s.ends_with('f'));
    }

    // --- Lua53Proto (constructed) ---

    fn make_lua53_proto() -> Lua53Proto {
        Lua53Proto {
            source_name: Some("@test.lua".into()),
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 1,
            max_stack_size: 2,
            code: vec![0u32; 4],
            constants: vec![
                Lua53Constant::Integer(100),
                Lua53Constant::Float(3.14_f64),
                Lua53Constant::String("hello".into()),
            ],
            upvalues: vec![],
            protos: vec![],
            source_lines: vec![],
            locals: vec![],
            upvalue_names: vec![],
        }
    }

    #[test]
    fn lua53_proto_instr_count() {
        assert_eq!(make_lua53_proto().instr_count(), 4);
    }

    #[test]
    fn lua53_proto_integer_constants() {
        assert_eq!(make_lua53_proto().integer_constants(), vec![100i64]);
    }

    #[test]
    fn lua53_proto_float_constants() {
        let floats = make_lua53_proto().float_constants();
        assert!((floats[0] - 3.14_f64).abs() < 1e-10);
    }

    #[test]
    fn lua52_proto_instr_count() {
        let p = Lua52Proto {
            source_name: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 0,
            max_stack_size: 2,
            code: vec![0u32; 3],
            constants: vec![],
            upvalues: vec![],
            protos: vec![],
            source_lines: vec![],
            locals: vec![],
            upvalue_names: vec![],
        };
        assert_eq!(p.instr_count(), 3);
    }
}
