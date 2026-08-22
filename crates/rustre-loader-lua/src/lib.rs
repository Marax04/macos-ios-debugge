//! `rustre-loader-lua`
//!
//! Comprehensive Lua 5.1/5.2/5.3/5.4 bytecode loader.
//!
//! prototypes, per-version instruction sets, upvalue info, constants, debug
//! symbols (line info, local variables, upvalue names), and assembles a full
//! memory-mapped binary view.

pub mod lua50_format;
pub mod lua51_format;
pub mod lua52_53_format;
pub mod lua_analysis;
pub mod lua_bytecode_parser;
pub mod lua_debug; // Parses function
pub mod lua_decompiler_full;
pub mod lua_function_graph;
pub mod lua_proto_analyzer;
pub mod lua_real_api;

pub use lua_real_api::{
    LUAJIT_MAGIC, SUPPORTED_VERSION_BYTES, all_strings_from_chunk_bytes, detect_chunk_version,
    disassemble_chunk_bytes, parse_bytecode_strict, parse_chunk_strict,
};
pub mod lua_string_extractor;
pub mod lua_version_detector;
pub mod luajit_loader;
pub mod lua_constant_pool;
pub mod lua_upvalue_analyzer;

pub use lua_decompiler_full::{
    BasicBlock, BinOp, ControlFlow, DecompError, ExpressionTree, FunctionAst, LuaAst,
    LuaConst as LuaConstDecomp, LuaDecompilerFull, Statement, StatementList, TableField, UnOp,
    render_expr,
};

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use rustre_core::address::{Address, AddressRange};
use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
    RegisterKind,
};
use rustre_core::binary_view::{BinaryView, Memory, Segment};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;
use rustre_core::ids::ViewId;
use rustre_core::permissions::Permissions;
use rustre_core::{LoadResult, Loader, LoaderInput, NestedBinary, async_trait};

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the Lua loader.
#[derive(Debug, thiserror::Error)]
pub enum LuaLoaderError {
    /// Magic bytes do not match `\x1bLua`.
    #[error("invalid magic")]
    InvalidMagic,
    /// Unsupported Lua version byte.
    #[error("unsupported version: {0:#04x}")]
    UnsupportedVersion(u8),
    /// Generic parse error with context.
    #[error("parse error: {0}")]
    ParseError(String),
    /// File is too short to parse.
    #[error("truncated data")]
    TruncatedData,
    /// Integer overflow in an offset or count.
    #[error("integer overflow")]
    Overflow,
}

// ─────────────────────────────────────────────────────────────────────────────
// Magic & detection
// ─────────────────────────────────────────────────────────────────────────────

/// Lua bytecode magic bytes (first 4 bytes).
pub const LUA_MAGIC: &[u8; 4] = b"\x1bLua";

/// Returns `true` if `data` looks like a compiled Lua 5.x bytecode file.
#[must_use]
pub fn is_lua_bytecode(data: &[u8]) -> bool {
    data.len() >= 5 && data.starts_with(LUA_MAGIC.as_ref())
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua version
// ─────────────────────────────────────────────────────────────────────────────

/// Lua version encoded in the bytecode header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuaVersion {
    /// Lua 5.1 (`0x51`).
    Lua51,
    /// Lua 5.2 (`0x52`).
    Lua52,
    /// Lua 5.3 (`0x53`).
    Lua53,
    /// Lua 5.4 (`0x54`).
    Lua54,
    /// Unrecognised version byte.
    Unknown(u8),
}

impl LuaVersion {
    /// Decode a version byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x51 => Self::Lua51,
            0x52 => Self::Lua52,
            0x53 => Self::Lua53,
            0x54 => Self::Lua54,
            other => Self::Unknown(other),
        }
    }

    /// Return `true` if this version is known.
    #[must_use]
    pub const fn is_known(self) -> bool {
        matches!(self, Self::Lua51 | Self::Lua52 | Self::Lua53 | Self::Lua54)
    }

    /// Return the raw version byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Lua51 => 0x51,
            Self::Lua52 => 0x52,
            Self::Lua53 => 0x53,
            Self::Lua54 => 0x54,
            Self::Unknown(b) => b,
        }
    }

    /// Return the minor version number.
    #[must_use]
    pub const fn minor(self) -> u8 {
        self.as_byte() & 0x0F
    }

    /// Return the major version number.
    #[must_use]
    pub const fn major(self) -> u8 {
        self.as_byte() >> 4
    }
}

impl fmt::Display for LuaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lua51 => write!(f, "Lua 5.1"),
            Self::Lua52 => write!(f, "Lua 5.2"),
            Self::Lua53 => write!(f, "Lua 5.3"),
            Self::Lua54 => write!(f, "Lua 5.4"),
            Self::Unknown(v) => write!(f, "Lua unknown(0x{v:02x})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua endian
// ─────────────────────────────────────────────────────────────────────────────

/// Endianness indicator in a Lua bytecode header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuaEndian {
    /// Big-endian (byte value `0`).
    Be,
    /// Little-endian (byte value `1`).
    Le,
}

impl LuaEndian {
    /// Decode from a raw byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        if b == 0 { Self::Be } else { Self::Le }
    }

    /// Convert to `rustre_core::endian::Endian`.
    #[must_use]
    pub const fn to_core_endian(self) -> Endian {
        match self {
            Self::Be => Endian::Big,
            Self::Le => Endian::Little,
        }
    }

    /// Return `true` if little-endian.
    #[must_use]
    pub const fn is_le(self) -> bool {
        matches!(self, Self::Le)
    }
}

impl fmt::Display for LuaEndian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Be => write!(f, "BE"),
            Self::Le => write!(f, "LE"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Integer size descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Integer size descriptor (primarily for display).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LuaIntSize {
    /// Size in bytes.
    pub size: u8,
}

impl fmt::Display for LuaIntSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "int:{}", self.size)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reader utility
// ─────────────────────────────────────────────────────────────────────────────

/// Byte-level reader with position tracking and endianness.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    is_le: bool,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8], is_le: bool) -> Self {
        Self {
            data,
            pos: 0,
            is_le,
        }
    }

    const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, LuaLoaderError> {
        if self.pos >= self.data.len() {
            return Err(LuaLoaderError::TruncatedData);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_u16(&mut self) -> Result<u16, LuaLoaderError> {
        if self.pos + 2 > self.data.len() {
            return Err(LuaLoaderError::TruncatedData);
        }
        let bytes = [self.data[self.pos], self.data[self.pos + 1]];
        self.pos += 2;
        Ok(if self.is_le {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    }

    fn read_u32(&mut self) -> Result<u32, LuaLoaderError> {
        if self.pos + 4 > self.data.len() {
            return Err(LuaLoaderError::TruncatedData);
        }
        let bytes: [u8; 4] = self.data[self.pos..self.pos + 4].try_into().unwrap();
        self.pos += 4;
        Ok(if self.is_le {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    fn read_u64(&mut self) -> Result<u64, LuaLoaderError> {
        if self.pos + 8 > self.data.len() {
            return Err(LuaLoaderError::TruncatedData);
        }
        let bytes: [u8; 8] = self.data[self.pos..self.pos + 8].try_into().unwrap();
        self.pos += 8;
        Ok(if self.is_le {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        })
    }

    fn read_f64(&mut self) -> Result<f64, LuaLoaderError> {
        let bits = self.read_u64()?;
        Ok(f64::from_bits(bits))
    }

    fn read_sized_int(&mut self, size: u8) -> Result<u64, LuaLoaderError> {
        match size {
            1 => self.read_u8().map(|b| b as u64),
            2 => self.read_u16().map(|b| b as u64),
            4 => self.read_u32().map(|b| b as u64),
            8 => self.read_u64(),
            _ => Err(LuaLoaderError::ParseError(format!(
                "unsupported int size {size}"
            ))),
        }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], LuaLoaderError> {
        if self.pos + n > self.data.len() {
            return Err(LuaLoaderError::TruncatedData);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read a Lua string: size field (`int_size` bytes) followed by bytes.
    fn read_lua_string(&mut self, int_size: u8) -> Result<Option<String>, LuaLoaderError> {
        let slen = self.read_sized_int(int_size)? as usize;
        if slen == 0 {
            return Ok(None);
        }
        // slen includes the NUL terminator in 5.1/5.2/5.3
        let raw = self.read_bytes(slen)?;
        let without_nul = if raw.ends_with(&[0]) {
            &raw[..raw.len() - 1]
        } else {
            raw
        };
        Ok(Some(String::from_utf8_lossy(without_nul).into_owned()))
    }

    /// Read a Lua 5.4-style string (`LUAI_MAXSHORTLEN` marker byte then length).
    fn read_lua54_string(&mut self) -> Result<Option<String>, LuaLoaderError> {
        if self.remaining() == 0 {
            return Err(LuaLoaderError::TruncatedData);
        }
        let size_b = self.read_u8()?;
        if size_b == 0 {
            return Ok(None);
        }
        let slen = if size_b == 0xFF {
            // Long string: size as u64
            self.read_u64()? as usize
        } else {
            size_b as usize
        };
        if slen == 0 {
            return Ok(Some(String::new()));
        }
        let raw = self.read_bytes(slen)?;
        Ok(Some(String::from_utf8_lossy(raw).into_owned()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua header
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed Lua bytecode file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuaHeader {
    /// Lua version.
    pub version: LuaVersion,
    /// Format version (0 = official).
    pub format: u8,
    /// Endianness.
    pub endian: LuaEndian,
    /// Size of `int` in bytes.
    pub int_size: u8,
    /// Size of a pointer in bytes.
    pub ptr_size: u8,
    /// Size of a VM instruction in bytes.
    pub inst_size: u8,
    /// Size of a Lua number in bytes.
    pub num_size: u8,
    /// Whether numbers are stored as integers.
    pub is_integer_num: bool,
    /// Lua 5.4: integer type width.
    pub lua_integer_size: u8,
    /// Lua 5.4: float type width.
    pub lua_float_size: u8,
}

impl LuaHeader {
    /// Minimum header size.
    pub const MIN_SIZE: usize = 12;

    /// Parse a `LuaHeader` from the beginning of `data`.
    ///
    /// # Errors
    /// Returns `LuaLoaderError::InvalidMagic` if the first 4 bytes are not `\x1bLua`.
    /// Returns `LuaLoaderError::TruncatedData` if `data` is too short.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), LuaLoaderError> {
        if data.len() < Self::MIN_SIZE {
            return Err(LuaLoaderError::TruncatedData);
        }
        if !data.starts_with(LUA_MAGIC.as_ref()) {
            return Err(LuaLoaderError::InvalidMagic);
        }
        let version = LuaVersion::from_byte(data[4]);
        let format = data[5];
        let endian = LuaEndian::from_byte(data[6]);
        let int_size = data[7];
        let ptr_size = data[8];
        let instruction_size = data[9];
        let num_size = data.get(10).copied().unwrap_or(8);
        let is_integer_num = data.get(11).is_some_and(|&b| b != 0);

        // 5.4 adds a 6-byte LUAC_DATA integrity block at data[12..18],
        // followed by integer_size at data[18] and float_size at data[19].
        // Reading data[12]/data[13] would give bytes from LUAC_DATA, not sizes.
        let (lua_integer_size, lua_float_size, end_pos) =
            if matches!(version, LuaVersion::Lua54) && data.len() >= 20 {
                // Verify LUAC_DATA integrity block
                const LUAC_DATA: [u8; 6] = [0x19, 0x93, 0x0D, 0x0A, 0x1A, 0x0A];
                if data[12..18] != LUAC_DATA {
                    return Err(LuaLoaderError::InvalidMagic);
                }
                (data[18], data[19], 20usize)
            } else {
                (8, 8, 12usize)
            };

        Ok((
            Self {
                version,
                format,
                endian,
                int_size,
                ptr_size,
                inst_size: instruction_size,
                num_size,
                is_integer_num,
                lua_integer_size,
                lua_float_size,
            },
            end_pos,
        ))
    }

    /// Returns the endianness as a `rustre_core::endian::Endian`.
    #[must_use]
    pub const fn to_endian(&self) -> Endian {
        self.endian.to_core_endian()
    }

    /// Returns `true` if the format is the official Lua reference implementation.
    #[must_use]
    pub const fn is_official_format(&self) -> bool {
        self.format == 0
    }

    /// Width in bytes of the `size_t` used for string lengths in the Lua
    /// 5.1/5.2 dump format.
    ///
    /// `luac` writes string lengths with `sizeof(size_t)`, which is the same
    /// field the header records as the pointer size — not `sizeof(int)`. A
    /// 64-bit `luac` therefore emits 8-byte lengths while `int_size` stays 4.
    /// Falls back to the pointer width recorded in the header, or 8 when the
    /// header records an implausible value.
    #[must_use]
    pub const fn size_t_size_51(&self) -> u8 {
        match self.ptr_size {
            1 | 2 | 4 | 8 => self.ptr_size,
            _ => 8,
        }
    }
}

impl fmt::Display for LuaHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} format={} endian={} int={} ptr={} inst={} num={}{}",
            self.version,
            self.format,
            self.endian,
            self.int_size,
            self.ptr_size,
            self.inst_size,
            self.num_size,
            if self.is_integer_num { " int-nums" } else { "" },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua constant types
// ─────────────────────────────────────────────────────────────────────────────

/// A constant pool entry.
#[derive(Debug, Clone, PartialEq)]
pub enum LuaConst {
    /// nil.
    Nil,
    /// Boolean.
    Bool(bool),
    /// Floating-point number.
    Number(f64),
    /// Integer (Lua 5.3+).
    Integer(i64),
    /// String constant.
    Str(String),
    /// Long string constant.
    LongStr(String),
}

impl LuaConst {
    /// Tag byte for nil in all versions.
    pub const TAG_NIL: u8 = 0;
    /// Tag byte for boolean.
    pub const TAG_BOOL: u8 = 1;
    /// Tag byte for number.
    pub const TAG_NUMBER: u8 = 3;
    /// Tag byte for string (short).
    pub const TAG_SHORT_STR: u8 = 4;
    /// Tag byte for string (long).
    pub const TAG_LONG_STR: u8 = 20;
    /// Tag for integer (Lua 5.3+ subtype 1 of number).
    pub const TAG_INT: u8 = 0x13;
    /// Tag for float (Lua 5.3+ subtype 0 of number).
    pub const TAG_FLOAT: u8 = 0x03;

    /// Return `true` if this is a string constant.
    #[must_use]
    pub const fn is_string(&self) -> bool {
        matches!(self, Self::Str(_) | Self::LongStr(_))
    }

    /// Return the string value if this is a string constant.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) | Self::LongStr(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

impl fmt::Display for LuaConst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Number(n) => write!(f, "{n}"),
            Self::Integer(i) => write!(f, "{i}"),
            Self::Str(s) | Self::LongStr(s) => write!(f, "\"{s}\""),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua instruction representation
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded Lua VM instruction (32 bits, ABC or `ABx` format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LuaInstr(pub u32);

impl LuaInstr {
    /// Decode opcode (bits 0–5).
    #[must_use]
    pub const fn opcode(self) -> u8 {
        (self.0 & 0x3F) as u8
    }

    /// Decode A operand (bits 6–13 in 5.x, but shifted differently per version).
    #[must_use]
    pub const fn a(self) -> u8 {
        ((self.0 >> 6) & 0xFF) as u8
    }

    /// Decode B operand (bits 23–31).
    #[must_use]
    pub const fn b(self) -> u16 {
        ((self.0 >> 23) & 0x1FF) as u16
    }

    /// Decode C operand (bits 14–22).
    #[must_use]
    pub const fn c(self) -> u16 {
        ((self.0 >> 14) & 0x1FF) as u16
    }

    /// Decode Bx operand (bits 14–31, 18-bit unsigned).
    #[must_use]
    pub const fn bx(self) -> u32 {
        self.0 >> 14
    }

    /// Decode sBx operand (Bx minus `MAXARG_sBx` = 131071).
    #[must_use]
    pub const fn sbx(self) -> i32 {
        self.bx() as i32 - 131_071
    }

    /// Return `true` if this instruction modifies the A register.
    #[must_use]
    pub const fn writes_a(self) -> bool {
        !matches!(self.opcode(), 0x00..=0x05 | 0x24 | 0x25 | 0x29)
    }
}

impl fmt::Display for LuaInstr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "op={:#04x} A={} B={} C={}",
            self.opcode(),
            self.a(),
            self.b(),
            self.c()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-version opcode tables
// ─────────────────────────────────────────────────────────────────────────────

/// Lua 5.1 opcode mnemonics.
pub static LUA51_OPCODES: &[&str] = &[
    "MOVE",
    "LOADK",
    "LOADBOOL",
    "LOADNIL",
    "GETUPVAL",
    "GETGLOBAL",
    "GETTABLE",
    "SETGLOBAL",
    "SETUPVAL",
    "SETTABLE",
    "NEWTABLE",
    "SELF",
    "ADD",
    "SUB",
    "MUL",
    "DIV",
    "MOD",
    "POW",
    "UNM",
    "NOT",
    "LEN",
    "CONCAT",
    "JMP",
    "EQ",
    "LT",
    "LE",
    "TEST",
    "TESTSET",
    "CALL",
    "TAILCALL",
    "RETURN",
    "FORLOOP",
    "FORPREP",
    "TFORLOOP",
    "SETLIST",
    "CLOSE",
    "CLOSURE",
    "VARARG",
];

/// Lua 5.2 opcode mnemonics.
pub static LUA52_OPCODES: &[&str] = &[
    "MOVE", "LOADK", "LOADKX", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETTABUP", "GETTABLE",
    "SETTABUP", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF", "ADD", "SUB", "MUL", "DIV", "MOD",
    "POW", "UNM", "NOT", "LEN", "CONCAT", "JMP", "EQ", "LT", "LE", "TEST", "TESTSET", "CALL",
    "TAILCALL", "RETURN", "FORLOOP", "FORPREP", "TFORCALL", "TFORLOOP", "SETLIST", "CLOSURE",
    "VARARG", "EXTRAARG",
];

/// Lua 5.3 opcode mnemonics.
pub static LUA53_OPCODES: &[&str] = &[
    "MOVE", "LOADK", "LOADKX", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETTABUP", "GETTABLE",
    "SETTABUP", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF", "ADD", "SUB", "MUL", "MOD", "POW",
    "DIV", "IDIV", "BAND", "BOR", "BXOR", "SHL", "SHR", "UNM", "BNOT", "NOT", "LEN", "CONCAT",
    "JMP", "EQ", "LT", "LE", "TEST", "TESTSET", "CALL", "TAILCALL", "RETURN", "FORLOOP", "FORPREP",
    "TFORCALL", "TFORLOOP", "SETLIST", "CLOSURE", "VARARG", "EXTRAARG",
];

/// Lua 5.4 opcode mnemonics.
pub static LUA54_OPCODES: &[&str] = &[
    "MOVE",
    "LOADI",
    "LOADF",
    "LOADK",
    "LOADKX",
    "LOADFALSE",
    "LFALSESKIP",
    "LOADTRUE",
    "LOADNIL",
    "GETUPVAL",
    "SETUPVAL",
    "GETTABUP",
    "GETTABLE",
    "GETI",
    "GETFIELD",
    "SETTABUP",
    "SETTABLE",
    "SETI",
    "SETFIELD",
    "NEWTABLE",
    "SELF",
    "ADDI",
    "ADDK",
    "SUBK",
    "MULK",
    "MODK",
    "POWK",
    "DIVK",
    "IDIVK",
    "BANDK",
    "BORK",
    "BXORK",
    "SHRI",
    "SHLI",
    "ADD",
    "SUB",
    "MUL",
    "MOD",
    "POW",
    "DIV",
    "IDIV",
    "BAND",
    "BOR",
    "BXOR",
    "SHL",
    "SHR",
    "MMBIN",
    "MMBINI",
    "MMBINK",
    "UNM",
    "BNOT",
    "NOT",
    "LEN",
    "CONCAT",
    "CLOSE",
    "TBC",
    "JMP",
    "EQ",
    "LT",
    "LE",
    "EQK",
    "EQI",
    "LTI",
    "LEI",
    "GTI",
    "GEI",
    "TEST",
    "TESTSET",
    "CALL",
    "TAILCALL",
    "RETURN",
    "RETURN0",
    "RETURN1",
    "FORLOOP",
    "FORPREP",
    "TFORPREP",
    "TFORCALL",
    "TFORLOOP",
    "SETLIST",
    "CLOSURE",
    "VARARG",
    "VARARGPREP",
    "EXTRAARG",
];

/// Return the opcode mnemonic for a given version and opcode byte.
#[must_use]
pub fn opcode_name(version: LuaVersion, opcode: u8) -> &'static str {
    let table = match version {
        LuaVersion::Lua51 => LUA51_OPCODES,
        LuaVersion::Lua52 => LUA52_OPCODES,
        LuaVersion::Lua53 => LUA53_OPCODES,
        LuaVersion::Lua54 => LUA54_OPCODES,
        LuaVersion::Unknown(_) => LUA54_OPCODES,
    };
    table.get(opcode as usize).copied().unwrap_or("UNK")
}

// ─────────────────────────────────────────────────────────────────────────────
// Local variable debug info
// ─────────────────────────────────────────────────────────────────────────────

/// A local variable debug record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuaLocalVar {
    /// Variable name.
    pub name: String,
    /// First instruction index where the variable is live.
    pub start_pc: u32,
    /// Last instruction index where the variable is live.
    pub end_pc: u32,
}

impl fmt::Display for LuaLocalVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "local {} [{}-{}]", self.name, self.start_pc, self.end_pc)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Upvalue info
// ─────────────────────────────────────────────────────────────────────────────

/// An upvalue descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuaUpvalue {
    /// Whether the upvalue is in-stack (true) or in an upvalue list (false).
    pub in_stack: bool,
    /// Index in the enclosing function's stack or upvalue list.
    pub idx: u8,
    /// Upvalue name from debug info.
    pub name: Option<String>,
}

impl fmt::Display for LuaUpvalue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "upval[{}] in_stack={} name={}",
            self.idx,
            self.in_stack,
            self.name.as_deref().unwrap_or("?"),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua function prototype
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed Lua function prototype.
#[derive(Debug, Clone)]
pub struct LuaProto {
    /// Chunk source name.
    pub name: Option<String>,
    /// First source line defined.
    pub first_line: u32,
    /// Last source line defined.
    pub last_line: u32,
    /// Number of fixed parameters.
    pub num_params: u8,
    /// Whether the function accepts vararg.
    pub is_vararg: bool,
    /// Maximum stack size.
    pub max_stack: u8,
    /// Raw instruction words.
    pub instructions: Vec<LuaInstr>,
    /// Constants.
    pub constants: Vec<LuaConst>,
    /// Upvalue descriptors.
    pub upvalues: Vec<LuaUpvalue>,
    /// Nested function prototypes.
    pub protos: Vec<Self>,
    /// Source line info: instruction index → line number.
    pub line_info: Vec<u32>,
    /// Local variable debug info.
    pub locals: Vec<LuaLocalVar>,
    /// Version this proto was parsed for.
    pub version: LuaVersion,
}

impl LuaProto {
    /// Build a mock `LuaProto` for testing.
    #[must_use]
    pub fn mock(version: LuaVersion) -> Self {
        Self {
            name: Some("@test.lua".to_string()),
            first_line: 0,
            last_line: 100,
            num_params: 0,
            is_vararg: true,
            max_stack: 8,
            instructions: vec![LuaInstr(0x0000_001E)], // RETURN
            constants: vec![
                LuaConst::Str("hello".to_string()),
                LuaConst::Number(3.14_f64),
                LuaConst::Integer(42),
                LuaConst::Bool(true),
                LuaConst::Nil,
            ],
            upvalues: vec![LuaUpvalue {
                in_stack: false,
                idx: 0,
                name: Some("_ENV".to_string()),
            }],
            protos: vec![],
            line_info: vec![1],
            locals: vec![LuaLocalVar {
                name: "x".to_string(),
                start_pc: 0,
                end_pc: 5,
            }],
            version,
        }
    }

    /// Parse a Lua 5.1/5.2 function prototype from `reader`.
    fn parse_51_52(r: &mut Reader<'_>, hdr: &LuaHeader) -> Result<Self, LuaLoaderError> {
        let name = r.read_lua_string(hdr.size_t_size_51())?;
        let first_line = r.read_sized_int(hdr.int_size)? as u32;
        let last_line = r.read_sized_int(hdr.int_size)? as u32;
        // luac 5.1/5.2 dumps `nups` immediately before `numparams`; reading
        // numparams here would shift every subsequent field by one byte.
        let num_upvalues = r.read_u8()?;
        let num_params = r.read_u8()?;
        let is_vararg = r.read_u8()? != 0;
        let max_stack = r.read_u8()?;

        // Instructions
        let inst_count = r.read_sized_int(hdr.int_size)? as usize;
        let mut instructions = Vec::with_capacity(inst_count.min(r.remaining() / 4));
        for _ in 0..inst_count {
            let w = r.read_u32()?;
            instructions.push(LuaInstr(w));
        }

        // Constants
        let kst_count = r.read_sized_int(hdr.int_size)? as usize;
        let mut constants = Vec::with_capacity(kst_count.min(r.remaining()));
        for _ in 0..kst_count {
            let tag = r.read_u8()?;
            let kst = match tag {
                LuaConst::TAG_NIL => LuaConst::Nil,
                LuaConst::TAG_BOOL => LuaConst::Bool(r.read_u8()? != 0),
                LuaConst::TAG_NUMBER => {
                    if hdr.num_size == 8 {
                        LuaConst::Number(r.read_f64()?)
                    } else {
                        let v = r.read_u32()? as f64;
                        LuaConst::Number(v)
                    }
                }
                4 | 5 => {
                    // Short or long string
                    let s = r.read_lua_string(hdr.size_t_size_51())?.unwrap_or_default();
                    if tag == 5 {
                        LuaConst::LongStr(s)
                    } else {
                        LuaConst::Str(s)
                    }
                }
                _ => LuaConst::Nil,
            };
            constants.push(kst);
        }

        // Inner protos
        let proto_count = r.read_sized_int(hdr.int_size)? as usize;
        let mut protos = Vec::with_capacity(proto_count.min(r.remaining()));
        for _ in 0..proto_count {
            protos.push(Self::parse_51_52(r, hdr)?);
        }

        // Line info
        let li_count = r.read_sized_int(hdr.int_size)? as usize;
        let mut line_info =
            Vec::with_capacity(li_count.min(r.remaining() / usize::from(hdr.int_size).max(1)));
        for _ in 0..li_count {
            line_info.push(r.read_sized_int(hdr.int_size)? as u32);
        }

        // Locals
        let loc_count = r.read_sized_int(hdr.int_size)? as usize;
        let mut locals = Vec::with_capacity(loc_count.min(r.remaining()));
        for _ in 0..loc_count {
            let lname = r.read_lua_string(hdr.size_t_size_51())?.unwrap_or_default();
            let start_pc = r.read_sized_int(hdr.int_size)? as u32;
            let end_pc = r.read_sized_int(hdr.int_size)? as u32;
            locals.push(LuaLocalVar {
                name: lname,
                start_pc,
                end_pc,
            });
        }

        // Upvalue names (5.1 style)
        let uv_count = r.read_sized_int(hdr.int_size)? as usize;
        let mut upvalues =
            Vec::with_capacity(uv_count.min(r.remaining() / usize::from(hdr.int_size).max(1)));
        for _ in 0..uv_count {
            let uv_name = r.read_lua_string(hdr.size_t_size_51())?;
            upvalues.push(LuaUpvalue {
                in_stack: false,
                idx: 0,
                name: uv_name,
            });
        }
        // Debug info may have been stripped, in which case the name list is
        // empty while `nups` still records how many upvalues exist. Record the
        // missing ones with no name rather than losing them.
        while upvalues.len() < usize::from(num_upvalues) {
            upvalues.push(LuaUpvalue {
                in_stack: false,
                idx: upvalues.len() as u8,
                name: None,
            });
        }

        Ok(Self {
            name,
            first_line,
            last_line,
            num_params,
            is_vararg,
            max_stack,
            instructions,
            constants,
            upvalues,
            protos,
            line_info,
            locals,
            version: hdr.version,
        })
    }

    /// Parse a Lua 5.3/5.4 prototype (uses separate upvalue table before protos).
    fn parse_53_54(r: &mut Reader<'_>, hdr: &LuaHeader) -> Result<Self, LuaLoaderError> {
        // Source name
        let name = if matches!(hdr.version, LuaVersion::Lua54) {
            r.read_lua54_string()?
        } else {
            r.read_lua_string(hdr.int_size)?
        };
        let first_line = r.read_u32()?;
        let last_line = r.read_u32()?;
        let num_params = r.read_u8()?;
        let is_vararg = r.read_u8()? != 0;
        let max_stack = r.read_u8()?;

        // Upvalue count (preliminary, before actual upvalue records)
        let uv_prelim = if matches!(hdr.version, LuaVersion::Lua54) {
            r.read_u8()? as usize
        } else {
            0
        };

        // Instructions
        let inst_count = r.read_u32()? as usize;
        let mut instructions = Vec::with_capacity(inst_count.min(r.remaining() / 4));
        for _ in 0..inst_count {
            instructions.push(LuaInstr(r.read_u32()?));
        }

        // Constants
        let kst_count = r.read_u32()? as usize;
        let mut constants = Vec::with_capacity(kst_count.min(r.remaining()));
        for _ in 0..kst_count {
            let tag = r.read_u8()?;
            let kst = match tag {
                LuaConst::TAG_NIL => LuaConst::Nil,
                LuaConst::TAG_BOOL => LuaConst::Bool(r.read_u8()? != 0),
                0x10 => LuaConst::Bool(false),
                0x11 => LuaConst::Bool(true),
                LuaConst::TAG_INT => {
                    // integer: 8 bytes in 5.4 or int_size in 5.3
                    let v = if matches!(hdr.version, LuaVersion::Lua54) {
                        r.read_u64()? as i64
                    } else {
                        r.read_sized_int(hdr.int_size)? as i64
                    };
                    LuaConst::Integer(v)
                }
                LuaConst::TAG_FLOAT => {
                    let v = r.read_f64()?;
                    LuaConst::Number(v)
                }
                LuaConst::TAG_SHORT_STR | LuaConst::TAG_LONG_STR => {
                    let s = if matches!(hdr.version, LuaVersion::Lua54) {
                        r.read_lua54_string()?.unwrap_or_default()
                    } else {
                        r.read_lua_string(hdr.int_size)?.unwrap_or_default()
                    };
                    if tag == 20 {
                        LuaConst::LongStr(s)
                    } else {
                        LuaConst::Str(s)
                    }
                }
                _ => LuaConst::Nil,
            };
            constants.push(kst);
        }

        // Upvalue records (5.3/5.4 format: 2 bytes per upvalue: in_stack, idx)
        let uv_count = r.read_u32()? as usize;
        // For Lua 5.4, the preliminary upvalue count read before the instruction list
        // must match the explicit uv_count; a mismatch indicates a malformed file.
        if uv_prelim != 0 && uv_count != uv_prelim {
            return Err(LuaLoaderError::ParseError(format!(
                "upvalue count mismatch: preliminary={uv_prelim} explicit={uv_count}"
            )));
        }
        let mut upvalues = Vec::with_capacity(uv_count.min(r.remaining() / 2));
        for _ in 0..uv_count {
            let in_stack = r.read_u8()? != 0;
            let idx = r.read_u8()?;
            upvalues.push(LuaUpvalue {
                in_stack,
                idx,
                name: None,
            });
        }

        // Nested protos
        let proto_count = r.read_u32()? as usize;
        let mut protos = Vec::with_capacity(proto_count.min(r.remaining()));
        for _ in 0..proto_count {
            protos.push(Self::parse_53_54(r, hdr)?);
        }

        // Debug info: line info
        let li_count = r.read_u32()? as usize;
        let mut line_info = Vec::with_capacity(li_count.min(r.remaining() / 4));
        for _ in 0..li_count {
            line_info.push(r.read_u32()?);
        }

        // Locals
        let loc_count = r.read_u32()? as usize;
        let mut locals = Vec::with_capacity(loc_count.min(r.remaining()));
        for _ in 0..loc_count {
            let lname = if matches!(hdr.version, LuaVersion::Lua54) {
                r.read_lua54_string()?.unwrap_or_default()
            } else {
                r.read_lua_string(hdr.int_size)?.unwrap_or_default()
            };
            let start_pc = r.read_u32()?;
            let end_pc = r.read_u32()?;
            locals.push(LuaLocalVar {
                name: lname,
                start_pc,
                end_pc,
            });
        }

        // Upvalue names
        let uv_name_count = r.read_u32()? as usize;
        for i in 0..uv_name_count {
            let uv_name = if matches!(hdr.version, LuaVersion::Lua54) {
                r.read_lua54_string()?
            } else {
                r.read_lua_string(hdr.int_size)?
            };
            if let Some(uv) = upvalues.get_mut(i) {
                uv.name = uv_name;
            }
        }

        Ok(Self {
            name,
            first_line,
            last_line,
            num_params,
            is_vararg,
            max_stack,
            instructions,
            constants,
            upvalues,
            protos,
            line_info,
            locals,
            version: hdr.version,
        })
    }

    /// Total number of instructions in this proto and all nested protos.
    #[must_use]
    pub fn total_instructions(&self) -> usize {
        self.instructions.len()
            + self
                .protos
                .iter()
                .map(Self::total_instructions)
                .sum::<usize>()
    }

    /// Collect all string constants (recursively through nested protos).
    #[must_use]
    pub fn all_strings(&self) -> Vec<&str> {
        let mut result: Vec<&str> = self.constants.iter().filter_map(|c| c.as_str()).collect();
        for p in &self.protos {
            result.extend(p.all_strings());
        }
        result
    }

    /// Return the source line for instruction at `pc` (0-based).
    #[must_use]
    pub fn source_line(&self, pc: usize) -> Option<u32> {
        self.line_info.get(pc).copied()
    }

    /// Count how many constants are of each type.
    #[must_use]
    pub fn constant_type_counts(&self) -> HashMap<&'static str, usize> {
        let mut map: HashMap<&'static str, usize> = HashMap::new();
        for c in &self.constants {
            let key = match c {
                LuaConst::Nil => "nil",
                LuaConst::Bool(_) => "bool",
                LuaConst::Number(_) => "number",
                LuaConst::Integer(_) => "integer",
                LuaConst::Str(_) => "string",
                LuaConst::LongStr(_) => "longstr",
            };
            *map.entry(key).or_insert(0) += 1;
        }
        map
    }
}

impl fmt::Display for LuaProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LuaProto '{}' v={} lines={}-{} params={} vararg={} instrs={} consts={} protos={}",
            self.name.as_deref().unwrap_or("?"),
            self.version,
            self.first_line,
            self.last_line,
            self.num_params,
            self.is_vararg,
            self.instructions.len(),
            self.constants.len(),
            self.protos.len(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua chunk (backward-compat wrapper)
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal descriptor for a Lua function prototype / chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuaChunk {
    /// Chunk source name.
    pub name: String,
    /// First source line defined.
    pub first_line: u32,
    /// Last source line defined.
    pub last_line: u32,
    /// Number of fixed parameters.
    pub num_params: u8,
    /// Whether the function is vararg.
    pub is_vararg: bool,
    /// Maximum stack size.
    pub max_stack: u8,
    /// Number of constants.
    pub constants_count: u32,
    /// Number of nested function prototypes.
    pub functions_count: u32,
    /// Number of bytecode instructions.
    pub instructions_count: u32,
}

impl LuaChunk {
    /// Build from a `LuaProto`.
    #[must_use]
    pub fn from_proto(p: &LuaProto) -> Self {
        Self {
            name: p.name.clone().unwrap_or_default(),
            first_line: p.first_line,
            last_line: p.last_line,
            num_params: p.num_params,
            is_vararg: p.is_vararg,
            max_stack: p.max_stack,
            constants_count: p.constants.len() as u32,
            functions_count: p.protos.len() as u32,
            instructions_count: p.instructions.len() as u32,
        }
    }

    /// Build a mock `LuaChunk` for testing.
    #[must_use]
    pub fn mock(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            first_line: 0,
            last_line: 100,
            num_params: 0,
            is_vararg: true,
            max_stack: 8,
            constants_count: 5,
            functions_count: 2,
            instructions_count: 10,
        }
    }
}

impl fmt::Display for LuaChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LuaChunk '{}' lines={}-{} params={} instrs={}",
            self.name, self.first_line, self.last_line, self.num_params, self.instructions_count,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua bytecode file
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed Lua bytecode file.
#[derive(Debug, Clone)]
pub struct LuaBytecode {
    /// File header.
    pub header: LuaHeader,
    /// Top-level function prototype.
    pub top_level: LuaProto,
}

impl LuaBytecode {
    /// Parse a `LuaBytecode` from `data`.
    ///
    /// # Errors
    /// Propagates errors from header or proto parsing.
    pub fn parse(data: &[u8]) -> Result<Self, LuaLoaderError> {
        let (header, hdr_end) = LuaHeader::parse(data)?;
        let rest = &data[hdr_end..];
        let mut reader = Reader::new(rest, header.endian.is_le());

        let top_level = match header.version {
            LuaVersion::Lua51 | LuaVersion::Lua52 => LuaProto::parse_51_52(&mut reader, &header)?,
            LuaVersion::Lua53 | LuaVersion::Lua54 | LuaVersion::Unknown(_) => {
                LuaProto::parse_53_54(&mut reader, &header)?
            }
        };

        Ok(Self { header, top_level })
    }

    /// Total instructions across all protos.
    #[must_use]
    pub fn total_instructions(&self) -> usize {
        self.top_level.total_instructions()
    }

    /// All string constants in the file.
    #[must_use]
    pub fn all_strings(&self) -> Vec<&str> {
        self.top_level.all_strings()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Architecture stub
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal Architecture stub for the Lua VM.
#[derive(Debug)]
pub struct LuaArch {
    version: LuaVersion,
}

impl LuaArch {
    /// Create for a given Lua version.
    #[must_use]
    pub const fn new(version: LuaVersion) -> Self {
        Self { version }
    }
}

impl Default for LuaArch {
    fn default() -> Self {
        Self {
            version: LuaVersion::Lua54,
        }
    }
}

impl Architecture for LuaArch {
    fn name(&self) -> &str {
        match self.version {
            LuaVersion::Lua51 => "lua51",
            LuaVersion::Lua52 => "lua52",
            LuaVersion::Lua53 => "lua53",
            LuaVersion::Lua54 => "lua54",
            LuaVersion::Unknown(_) => "lua",
        }
    }

    fn pointer_size(&self) -> usize {
        8
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        // A Lua instruction is exactly four bytes. Fewer than that is not a
        // `nop` — it is the end of the buffer, and reporting an instruction
        // there invents one. Unlike `get_branches`, this signature can say so.
        if bytes.len() < 4 {
            return Err(CoreError::Truncated {
                expected: 4,
                got: bytes.len(),
            });
        }
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        // Lua 5.4 widened the opcode to 7 bits and rearranged A/B/C, so the
        // `LuaInstr` accessors — which encode the 5.1–5.3 layout — would name
        // the wrong opcode and print operands read from the wrong bits.
        let (op, a, b, c) = if matches!(self.version, LuaVersion::Lua54) {
            let (op, a, b, c, _k) = decode_54(word);
            (op, a, b, c)
        } else {
            let instr = LuaInstr(word);
            (
                instr.opcode(),
                u32::from(instr.a()),
                u32::from(instr.b()),
                u32::from(instr.c()),
            )
        };
        let name = opcode_name(self.version, op);
        let mut decoded = Instruction::new(address, 4, name, bytes[..4].to_vec());
        decoded.operands = format!("A={a} B={b} C={c}");
        decoded.flags = InstrFlags::NONE;
        Ok(decoded)
    }

    fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        (0u32..16u32)
            .map(|i| RegisterInfo::new(format!("r{i}"), i, 8, RegisterKind::General))
            .collect()
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![
            CallingConvention::new("lua")
                .with_int_args(vec!["r0".to_string(), "r1".to_string()])
                .with_return_regs(vec!["r0".to_string()]),
        ]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loader
// ─────────────────────────────────────────────────────────────────────────────

/// Loader for Lua 5.x compiled bytecode files.
#[derive(Debug, Default)]
pub struct LuaLoader;

impl LuaLoader {
    /// Create a new `LuaLoader`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Loader for LuaLoader {
    fn name(&self) -> &str {
        "lua"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        is_lua_bytecode(&input.data)
    }

    /// # Errors
    /// Returns [`CoreError::Load`] if the Lua header is invalid or truncated.
    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let base = input.hints.base_address().map_or(0_u64, rustre_core::Address::as_u64);

        // Try to parse the header to detect version for the arch stub
        let version = LuaHeader::parse(&input.data)
            .map_or(LuaVersion::Lua54, |(h, _)| h.version);

        let mut mem = Memory::new();
        let size = input.data.len() as u64;
        if size > 0 {
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(base), Address::new(base + size)),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: input.data.clone(),
            });
        }

        let arch = Arc::new(LuaArch::new(version));
        let view = BinaryView::new(
            ViewId::from_raw(1),
            input.uri,
            arch,
            Endian::Little,
            64,
            vec![Address::new(base)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Standalone string reader (spec §3.8 public API)
// ─────────────────────────────────────────────────────────────────────────────

/// Read a length-prefixed Lua string from `data` at `*offset`.
///
/// The length field is `size_t_size` bytes (1, 2, 4, or 8) and includes the
/// trailing NUL terminator.  `*offset` is advanced past the string.
///
/// Returns `Ok(String)` (empty if length == 0).
///
/// # Errors
/// Returns an error if `data` is too short.
pub fn read_string_lua(
    data: &[u8],
    offset: &mut usize,
    size_t_size: u8,
) -> Result<String, LuaLoaderError> {
    let n_bytes = size_t_size as usize;
    if *offset + n_bytes > data.len() {
        return Err(LuaLoaderError::TruncatedData);
    }
    let slen = match size_t_size {
        1 => data[*offset] as usize,
        2 => {
            let b: [u8; 2] = data[*offset..*offset + 2].try_into().unwrap();
            u16::from_le_bytes(b) as usize
        }
        4 => {
            let b: [u8; 4] = data[*offset..*offset + 4].try_into().unwrap();
            u32::from_le_bytes(b) as usize
        }
        8 => {
            let b: [u8; 8] = data[*offset..*offset + 8].try_into().unwrap();
            u64::from_le_bytes(b) as usize
        }
        _ => {
            return Err(LuaLoaderError::ParseError(format!(
                "unsupported size_t_size {size_t_size}"
            )));
        }
    };
    *offset += n_bytes;
    if slen == 0 {
        return Ok(String::new());
    }
    if *offset + slen > data.len() {
        return Err(LuaLoaderError::TruncatedData);
    }
    let raw = &data[*offset..*offset + slen];
    *offset += slen;
    // Strip trailing NUL if present
    let without_nul = if raw.ends_with(&[0]) {
        &raw[..raw.len() - 1]
    } else {
        raw
    };
    Ok(String::from_utf8_lossy(without_nul).into_owned())
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec-compatible type aliases  (§3.8)
// ─────────────────────────────────────────────────────────────────────────────

/// Local variable debug record (spec §3.8 alias for [`LuaLocalVar`]).
pub type LocalVar = LuaLocalVar;

/// Upvalue descriptor (spec §3.8 alias).
///
/// Mirrors the field names mandated by the spec: `name`, `in_stack`, `idx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpvalueDesc {
    /// Name (from debug info; may be empty).
    pub name: String,
    /// Whether the upvalue is captured from the enclosing stack frame.
    pub in_stack: u8,
    /// Index in the enclosing frame or upvalue list.
    pub idx: u8,
}

impl UpvalueDesc {
    /// Convert from the internal [`LuaUpvalue`] type.
    #[must_use]
    pub fn from_upvalue(uv: &LuaUpvalue) -> Self {
        Self {
            name: uv.name.clone().unwrap_or_default(),
            in_stack: uv.in_stack as u8,
            idx: uv.idx,
        }
    }
}

impl fmt::Display for UpvalueDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "upval {} in_stack={} idx={}",
            self.name, self.in_stack, self.idx
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Standalone proto parsers (spec §3.8 public API)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a Lua **5.1** function prototype from `data` starting at `*offset`.
///
/// `endian` is `true` for little-endian, `false` for big-endian.
/// `int_size` is the platform `sizeof(int)` recorded in the header (usually 4).
/// `*offset` is advanced past all consumed bytes.
///
/// # Errors
/// Returns `LuaLoaderError::TruncatedData` if the slice is too short.
pub fn parse_proto_51(
    data: &[u8],
    offset: &mut usize,
    endian: bool,
    int_size: u8,
) -> Result<LuaProto, LuaLoaderError> {
    // Build a synthetic header for the shared 5.1/5.2 parser.
    let hdr = LuaHeader {
        version: LuaVersion::Lua51,
        format: 0,
        endian: if endian { LuaEndian::Le } else { LuaEndian::Be },
        int_size,
        ptr_size: 8,
        inst_size: 4,
        num_size: 8,
        is_integer_num: false,
        lua_integer_size: 8,
        lua_float_size: 8,
    };
    let mut r = Reader::new(&data[*offset..], endian);
    let proto = LuaProto::parse_51_52(&mut r, &hdr)?;
    *offset += r.pos;
    Ok(proto)
}

/// Parse a Lua **5.4** function prototype from `data` starting at `*offset`.
///
/// Always assumes little-endian (5.4 reference implementation default).
/// `*offset` is advanced past all consumed bytes.
///
/// # Errors
/// Returns `LuaLoaderError::TruncatedData` if the slice is too short.
pub fn parse_proto_54(data: &[u8], offset: &mut usize) -> Result<LuaProto, LuaLoaderError> {
    let hdr = LuaHeader {
        version: LuaVersion::Lua54,
        format: 0,
        endian: LuaEndian::Le,
        int_size: 4,
        ptr_size: 8,
        inst_size: 4,
        num_size: 8,
        is_integer_num: false,
        lua_integer_size: 8,
        lua_float_size: 8,
    };
    let mut r = Reader::new(&data[*offset..], true);
    let proto = LuaProto::parse_53_54(&mut r, &hdr)?;
    *offset += r.pos;
    Ok(proto)
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaModule  (spec §3.8 high-level type)
// ─────────────────────────────────────────────────────────────────────────────

/// A fully-parsed Lua bytecode module.
///
/// This is the top-level result produced by [`LuaBytecodeLoader`].
#[derive(Debug, Clone)]
pub struct LuaModule {
    /// File header.
    pub header: LuaHeader,
    /// Root (top-level) function prototype.
    pub root_proto: LuaProto,
}

impl LuaModule {
    /// Wrap an existing parsed [`LuaBytecode`] as a [`LuaModule`].
    #[must_use]
    pub fn from_bytecode(bc: LuaBytecode) -> Self {
        Self {
            header: bc.header,
            root_proto: bc.top_level,
        }
    }

    /// Parse a `LuaModule` from raw bytes.
    ///
    /// # Errors
    /// Propagates header or proto parse errors.
    pub fn parse(data: &[u8]) -> Result<Self, LuaLoaderError> {
        LuaBytecode::parse(data).map(Self::from_bytecode)
    }

    /// Total number of instructions across all prototypes.
    #[must_use]
    pub fn total_instructions(&self) -> usize {
        self.root_proto.total_instructions()
    }
}

impl fmt::Display for LuaModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LuaModule [{}] root={}", self.header, self.root_proto)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaBytecodeLoader  (spec §3.8)
// ─────────────────────────────────────────────────────────────────────────────

/// High-level loader that converts raw bytes into a [`LuaModule`].
///
/// Unlike the async [`LuaLoader`] (which integrates with the binary-view
/// infrastructure), this struct provides synchronous, standalone parsing
/// suitable for tools that just need the AST / constant pool.
///
/// # Example
/// ```no_run
/// # use rustre_loader_lua::LuaBytecodeLoader;
/// let data: Vec<u8> = std::fs::read("chunk.luac").unwrap();
/// let module = LuaBytecodeLoader::load(&data).unwrap();
/// println!("version: {}", module.header.version);
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct LuaBytecodeLoader;

impl LuaBytecodeLoader {
    /// Create a new loader instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse `data` as a Lua bytecode file, auto-detecting version.
    ///
    /// # Errors
    /// Fails if the magic bytes are wrong, the version is unsupported, or the
    /// data is truncated.
    pub fn load(data: &[u8]) -> Result<LuaModule, LuaLoaderError> {
        LuaModule::parse(data)
    }

    /// Parse `data` as a Lua bytecode file, overriding the version byte.
    ///
    /// This is useful when the version byte is corrupt or when loading embedded
    /// chunks stripped of their header.
    ///
    /// # Errors
    /// Same as [`load`](Self::load).
    pub fn load_version(data: &[u8], version: u8) -> Result<LuaModule, LuaLoaderError> {
        if data.len() < LuaHeader::MIN_SIZE {
            return Err(LuaLoaderError::TruncatedData);
        }
        if !data.starts_with(LUA_MAGIC.as_ref()) {
            return Err(LuaLoaderError::InvalidMagic);
        }
        // Clone header bytes and replace version.
        let mut patched = data.to_vec();
        patched[4] = version;
        LuaModule::parse(&patched)
    }

    /// Collect all prototypes in the module in depth-first order.
    ///
    /// The root prototype is always first; nested prototypes follow in
    /// declaration order.
    #[must_use]
    pub fn all_protos(module: &LuaModule) -> Vec<&LuaProto> {
        let mut out = Vec::new();
        Self::collect_protos(&module.root_proto, &mut out);
        out
    }

    /// Collect all unique string constants from the entire module.
    ///
    /// Strings are deduplicated and returned in encounter order.
    #[must_use]
    pub fn all_strings(module: &LuaModule) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for s in module.root_proto.all_strings() {
            if seen.insert(s.to_owned()) {
                out.push(s.to_owned());
            }
        }
        out
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn collect_protos<'a>(proto: &'a LuaProto, out: &mut Vec<&'a LuaProto>) {
        out.push(proto);
        for p in &proto.protos {
            Self::collect_protos(p, out);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// disassemble_proto  (spec §3.8)
// ─────────────────────────────────────────────────────────────────────────────

/// Instruction format kinds — used internally to choose the right operand layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstrFmt {
    Abc,
    ABx,
    AsBx,
    Ax,
    IsJ,
}

/// Determine the format of a Lua 5.1-5.3 instruction by opcode.
fn instr_fmt_legacy(opcode: u8, version: LuaVersion) -> InstrFmt {
    // Instructions that use sBx
    let sbx_ops: &[&str] = match version {
        LuaVersion::Lua51 => &["JMP", "FORLOOP", "FORPREP", "TFORLOOP"],
        LuaVersion::Lua52 => &["JMP", "FORLOOP", "FORPREP", "TFORLOOP"],
        LuaVersion::Lua53 => &["JMP", "FORLOOP", "FORPREP", "TFORLOOP"],
        _ => &[],
    };
    // Instructions that use Bx (unsigned)
    let bx_ops: &[&str] = match version {
        LuaVersion::Lua51 => &["LOADK", "GETGLOBAL", "SETGLOBAL", "CLOSURE"],
        LuaVersion::Lua52 | LuaVersion::Lua53 => &["LOADK", "LOADKX", "CLOSURE"],
        _ => &[],
    };
    let name = opcode_name(version, opcode);
    if sbx_ops.contains(&name) {
        InstrFmt::AsBx
    } else if bx_ops.contains(&name) {
        InstrFmt::ABx
    } else {
        InstrFmt::Abc
    }
}

/// Determine the format of a Lua 5.4 instruction by opcode.
fn instr_fmt_54(opcode: u8) -> InstrFmt {
    let name = opcode_name(LuaVersion::Lua54, opcode);
    match name {
        "LOADK" | "LOADKX" | "CLOSURE" => InstrFmt::ABx,
        "LOADI" | "LOADF" => InstrFmt::AsBx,
        "JMP" | "FORLOOP" | "FORPREP" | "TFORPREP" | "TFORLOOP" => InstrFmt::IsJ,
        "EXTRAARG" => InstrFmt::Ax,
        _ => InstrFmt::Abc,
    }
}

/// Decode a 5.4 instruction using the new 7-bit opcode layout.
///
/// ```text
/// iABC:  [C:8][B:8][k:1][A:8][OP:7]
/// iABx:  [Bx:17][A:8][OP:7]
/// iAsBx: [sBx:17][A:8][OP:7]   sBx = Bx - (2^16 - 1)
/// iAx:   [Ax:25][OP:7]
/// isJ:   [sJ:25][OP:7]          sJ  = J  - (2^24 - 1)
/// ```
const fn decode_54(word: u32) -> (u8, u32, u32, u32, bool) {
    let op = (word & 0x7F) as u8;
    let a = (word >> 7) & 0xFF;
    let k = ((word >> 15) & 1) != 0;
    let b = (word >> 16) & 0xFF;
    let c = (word >> 24) & 0xFF;
    (op, a, b, c, k)
}

/// Disassemble all instructions in `proto` into human-readable strings.
///
/// Each line has the format:
/// ```text
/// NNNN: MNEMONIC  operands          ; annotation
/// ```
/// where `NNNN` is the 0-based instruction index (zero-padded to 4 digits).
///
/// The annotation includes the source line number (if debug info is present)
/// and a contextual hint for common instructions (e.g. the string constant
/// loaded by `LOADK`).
///
/// # Arguments
/// * `proto` – the prototype to disassemble.
/// * `version` – the Lua version byte (e.g. `0x54`).
///
/// # Returns
/// A `Vec<String>`, one entry per instruction.
pub fn disassemble_proto(proto: &LuaProto, version: u8) -> Vec<String> {
    let ver = LuaVersion::from_byte(version);
    let is_54 = matches!(ver, LuaVersion::Lua54);

    let mut lines = Vec::with_capacity(proto.instructions.len());

    for (pc, &LuaInstr(word)) in proto.instructions.iter().enumerate() {
        let mnemonic;
        let operands_str;
        let mut annotation = String::new();

        // Optional source-line suffix from debug info.
        if let Some(line) = proto.line_info.get(pc) {
            annotation.push_str(&format!("line {line}"));
        }

        if is_54 {
            let (op, a, b, c, k) = decode_54(word);
            mnemonic = opcode_name(ver, op);

            // For 5.4: ABx fields: bits 7..=8 are A (8 bits), bits 15..=31 are Bx (17 bits)
            let bx_val = (word >> 15) & 0x1FFFF;
            let sbx_val = bx_val as i32 - (1 << 16) + 1;
            let ax_val = (word >> 7) & 0x01FF_FFFF;
            let sj_val = ((word >> 7) & 0x01FF_FFFF) as i32 - (1 << 24) + 1;

            let fmt = instr_fmt_54(op);
            operands_str = match fmt {
                InstrFmt::Abc => {
                    let extra = if k { " k=1" } else { "" };
                    format!("R{a}, {b}, {c}{extra}")
                }
                InstrFmt::ABx => {
                    // Try to annotate with the constant name for LOADK
                    if mnemonic == "LOADK" && let Some(kst) = proto.constants.get(bx_val as usize) {
                        let hint = const_hint(kst);
                        if !annotation.is_empty() {
                            annotation.push_str(&format!("; {hint}"));
                        } else {
                            annotation = hint;
                        }
                    }
                    format!("R{a}, K{bx_val}")
                }
                InstrFmt::AsBx => format!("R{a}, {sbx_val}"),
                InstrFmt::Ax => format!("Ax={ax_val}"),
                InstrFmt::IsJ => format!("sJ={sj_val}"),
            };
        } else {
            // 5.1 / 5.2 / 5.3: 6-bit opcode, iABC layout.
            let opcode_byte = (word & 0x3F) as u8;
            mnemonic = opcode_name(ver, opcode_byte);
            let a = (word >> 6) & 0xFF;
            let b = (word >> 23) & 0x1FF;
            let c = (word >> 14) & 0x1FF;
            let bx = word >> 14;
            let sbx = bx as i32 - 131_071;

            let fmt = instr_fmt_legacy(opcode_byte, ver);
            operands_str = match fmt {
                InstrFmt::Abc => {
                    // For 5.1 CALL-style: format as R(A), B, C
                    format!("R{a}, {b}, {c}")
                }
                InstrFmt::ABx => {
                    if (mnemonic == "LOADK" || mnemonic == "GETGLOBAL" || mnemonic == "SETGLOBAL") && let Some(kst) = proto.constants.get(bx as usize) {
                        let hint = const_hint(kst);
                        if !annotation.is_empty() {
                            annotation.push_str(&format!("; {hint}"));
                        } else {
                            annotation = hint;
                        }
                    }
                    format!("R{a}, K{bx}")
                }
                InstrFmt::AsBx => format!("R{a}, {sbx}"),
                _ => format!("R{a}, {b}, {c}"),
            };
        }

        // Pad mnemonic to 12 chars for alignment.
        let padded = format!("{mnemonic:<12}");
        let line = if annotation.is_empty() {
            format!("{pc:04}: {padded}{operands_str}")
        } else {
            format!("{pc:04}: {padded}{operands_str:<20}  ; {annotation}")
        };
        lines.push(line);
    }

    lines
}

/// Format a constant as a short display string for disassembly annotations.
fn const_hint(kst: &LuaConst) -> String {
    match kst {
        LuaConst::Nil => "nil".to_string(),
        LuaConst::Bool(b) => b.to_string(),
        LuaConst::Number(n) => format!("{n}"),
        LuaConst::Integer(i) => format!("{i}"),
        LuaConst::Str(s) | LuaConst::LongStr(s) => {
            // Truncate long strings to 40 chars for readability.
            if s.len() > 40 {
                format!("\"{}...\"", &s[..40])
            } else {
                format!("\"{s}\"")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProtoWalker — depth-first iterator over all prototypes
// ─────────────────────────────────────────────────────────────────────────────

/// Iterator that yields every [`LuaProto`] in a [`LuaModule`] depth-first.
///
/// # Example
/// ```no_run
/// # use rustre_loader_lua::{LuaBytecodeLoader, ProtoWalker};
/// # let module = LuaBytecodeLoader::load(&[]).unwrap();
/// for proto in ProtoWalker::new(&module.root_proto) {
///     println!("{}", proto.name.as_deref().unwrap_or("?"));
/// }
/// ```
pub struct ProtoWalker<'a> {
    stack: Vec<&'a LuaProto>,
}

impl<'a> ProtoWalker<'a> {
    /// Create a new walker starting from `root`.
    #[must_use]
    pub fn new(root: &'a LuaProto) -> Self {
        Self { stack: vec![root] }
    }
}

impl<'a> Iterator for ProtoWalker<'a> {
    type Item = &'a LuaProto;

    fn next(&mut self) -> Option<Self::Item> {
        let proto = self.stack.pop()?;
        // Push children in reverse so we pop them in forward order.
        for child in proto.protos.iter().rev() {
            self.stack.push(child);
        }
        Some(proto)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantIndex — typed constant pool lookup
// ─────────────────────────────────────────────────────────────────────────────

/// Typed index into a prototype's constant pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConstantIndex(pub u32);

impl ConstantIndex {
    /// Look up this index in `proto`'s constant pool.
    #[must_use]
    pub fn get<'a>(&self, proto: &'a LuaProto) -> Option<&'a LuaConst> {
        proto.constants.get(self.0 as usize)
    }
}

impl fmt::Display for ConstantIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "K{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProtoStats — aggregate statistics over a prototype tree
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics for a prototype and all its descendants.
#[derive(Debug, Clone, Default)]
pub struct ProtoStats {
    /// Total number of function prototypes.
    pub proto_count: usize,
    /// Total number of instructions across all prototypes.
    pub instruction_count: usize,
    /// Total number of constants.
    pub constant_count: usize,
    /// Number of string constants.
    pub string_count: usize,
    /// Number of numeric constants.
    pub number_count: usize,
    /// Number of integer constants.
    pub integer_count: usize,
    /// Total number of upvalues.
    pub upvalue_count: usize,
    /// Total number of local variables (debug info).
    pub local_count: usize,
}

impl ProtoStats {
    /// Compute statistics by walking the entire prototype tree from `root`.
    #[must_use]
    pub fn from_proto(root: &LuaProto) -> Self {
        let mut stats = Self::default();
        Self::collect(root, &mut stats);
        stats
    }

    fn collect(proto: &LuaProto, stats: &mut Self) {
        stats.proto_count += 1;
        stats.instruction_count += proto.instructions.len();
        stats.constant_count += proto.constants.len();
        stats.upvalue_count += proto.upvalues.len();
        stats.local_count += proto.locals.len();
        for c in &proto.constants {
            match c {
                LuaConst::Str(_) | LuaConst::LongStr(_) => stats.string_count += 1,
                LuaConst::Number(_) => stats.number_count += 1,
                LuaConst::Integer(_) => stats.integer_count += 1,
                _ => {}
            }
        }
        for child in &proto.protos {
            Self::collect(child, stats);
        }
    }
}

impl fmt::Display for ProtoStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "protos={} instrs={} consts={} strings={} nums={} ints={} upvals={} locals={}",
            self.proto_count,
            self.instruction_count,
            self.constant_count,
            self.string_count,
            self.number_count,
            self.integer_count,
            self.upvalue_count,
            self.local_count,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Disassembly summary
// ─────────────────────────────────────────────────────────────────────────────

/// A complete disassembly of a single [`LuaProto`] with metadata.
#[derive(Debug, Clone)]
pub struct ProtoDisasm {
    /// Display name of the prototype (source name or index path).
    pub name: String,
    /// First defined source line.
    pub first_line: u32,
    /// Last defined source line.
    pub last_line: u32,
    /// Version this proto was parsed with.
    pub version: LuaVersion,
    /// Disassembled instruction lines.
    pub lines: Vec<String>,
}

impl ProtoDisasm {
    /// Disassemble `proto` and wrap the result.
    #[must_use]
    pub fn from_proto(proto: &LuaProto) -> Self {
        let version_byte = proto.version.as_byte();
        Self {
            name: proto.name.clone().unwrap_or_else(|| "?".to_string()),
            first_line: proto.first_line,
            last_line: proto.last_line,
            version: proto.version,
            lines: disassemble_proto(proto, version_byte),
        }
    }
}

impl fmt::Display for ProtoDisasm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "; {} [{}] lines {}-{}",
            self.name, self.version, self.first_line, self.last_line
        )?;
        for line in &self.lines {
            writeln!(f, "  {line}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ModuleDisasm — disassemble every proto in a module
// ─────────────────────────────────────────────────────────────────────────────

/// Disassembly of an entire [`LuaModule`].
#[derive(Debug, Clone)]
pub struct ModuleDisasm {
    /// The module's version.
    pub version: LuaVersion,
    /// One entry per prototype, depth-first.
    pub protos: Vec<ProtoDisasm>,
}

impl ModuleDisasm {
    /// Build a full disassembly from a [`LuaModule`].
    #[must_use]
    pub fn from_module(module: &LuaModule) -> Self {
        let protos = LuaBytecodeLoader::all_protos(module)
            .into_iter()
            .map(ProtoDisasm::from_proto)
            .collect();
        Self {
            version: module.header.version,
            protos,
        }
    }

    /// Return a flat list of all instruction lines, interleaved with prototype
    /// header comments.
    #[must_use]
    pub fn flat_listing(&self) -> Vec<String> {
        let mut out = Vec::new();
        for pd in &self.protos {
            out.push(format!(
                "; === proto '{}' [{}-{}] ===",
                pd.name, pd.first_line, pd.last_line
            ));
            out.extend(pd.lines.iter().map(|l| format!("  {l}")));
        }
        out
    }
}

impl fmt::Display for ModuleDisasm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for pd in &self.protos {
            write!(f, "{pd}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Opcode operand format tables (spec §3.8 helpers)
// ─────────────────────────────────────────────────────────────────────────────

/// Operand layout for a single opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpcodeLayout {
    /// iABC: A, B, C fields.
    Abc,
    /// iABx: A and unsigned Bx.
    ABx,
    /// iAsBx: A and signed sBx.
    AsBx,
    /// iAx: only Ax (no A, B, C).
    Ax,
    /// isJ: signed J offset only (5.4).
    IsJ,
    /// Unknown / not classified.
    Unknown,
}

/// Return the operand layout for `opcode` under `version`.
#[must_use]
pub fn opcode_layout(version: LuaVersion, opcode: u8) -> OpcodeLayout {
    match version {
        LuaVersion::Lua54 => match instr_fmt_54(opcode) {
            InstrFmt::Abc => OpcodeLayout::Abc,
            InstrFmt::ABx => OpcodeLayout::ABx,
            InstrFmt::AsBx => OpcodeLayout::AsBx,
            InstrFmt::Ax => OpcodeLayout::Ax,
            InstrFmt::IsJ => OpcodeLayout::IsJ,
        },
        v => match instr_fmt_legacy(opcode, v) {
            InstrFmt::Abc => OpcodeLayout::Abc,
            InstrFmt::ABx => OpcodeLayout::ABx,
            InstrFmt::AsBx => OpcodeLayout::AsBx,
            _ => OpcodeLayout::Unknown,
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::LoaderHint;

    /// Minimal valid Lua header bytes (12 bytes, 5.x generic).
    fn make_lua(version_byte: u8) -> Vec<u8> {
        let mut data = vec![0u8; 32];
        data[0] = 0x1B;
        data[1] = b'L';
        data[2] = b'u';
        data[3] = b'a';
        data[4] = version_byte;
        data[5] = 0; // format = official
        data[6] = 1; // little-endian
        data[7] = 4; // int_size
        data[8] = 8; // ptr_size
        data[9] = 4; // inst_size
        data[10] = 8; // num_size
        data[11] = 0; // is_integer_num = false
        // Fixture fix: Lua 5.4 headers require a LUAC_DATA integrity block at
        // offsets 12..18 ([0x19,0x93,0x0D,0x0A,0x1A,0x0A]); without it the
        // parser correctly rejects the header as InvalidMagic.
        if version_byte == 0x54 {
            data[12] = 0x19;
            data[13] = 0x93;
            data[14] = 0x0D;
            data[15] = 0x0A;
            data[16] = 0x1A;
            data[17] = 0x0A;
            data[18] = 8; // lua_integer_size
            data[19] = 8; // lua_float_size
        }
        data
    }

    // ── magic detection ───────────────────────────────────────────────────────

    #[test]
    fn test_is_lua_bytecode_54() {
        assert!(is_lua_bytecode(&make_lua(0x54)));
    }

    #[test]
    fn test_is_lua_bytecode_53() {
        assert!(is_lua_bytecode(&make_lua(0x53)));
    }

    #[test]
    fn test_is_lua_bytecode_52() {
        assert!(is_lua_bytecode(&make_lua(0x52)));
    }

    #[test]
    fn test_is_lua_bytecode_51() {
        assert!(is_lua_bytecode(&make_lua(0x51)));
    }

    #[test]
    fn test_is_lua_bytecode_too_short() {
        assert!(!is_lua_bytecode(b"\x1bLua"));
    }

    #[test]
    fn test_is_lua_bytecode_wrong_magic() {
        assert!(!is_lua_bytecode(b"ELF\x7f0000"));
    }

    #[test]
    fn test_is_lua_empty() {
        assert!(!is_lua_bytecode(b""));
    }

    // ── LuaVersion ────────────────────────────────────────────────────────────

    #[test]
    fn test_version_from_byte_51() {
        assert_eq!(LuaVersion::from_byte(0x51), LuaVersion::Lua51);
    }

    #[test]
    fn test_version_from_byte_52() {
        assert_eq!(LuaVersion::from_byte(0x52), LuaVersion::Lua52);
    }

    #[test]
    fn test_version_from_byte_53() {
        assert_eq!(LuaVersion::from_byte(0x53), LuaVersion::Lua53);
    }

    #[test]
    fn test_version_from_byte_54() {
        assert_eq!(LuaVersion::from_byte(0x54), LuaVersion::Lua54);
    }

    #[test]
    fn test_version_unknown() {
        assert_eq!(LuaVersion::from_byte(0x55), LuaVersion::Unknown(0x55));
    }

    #[test]
    fn test_version_is_known() {
        assert!(LuaVersion::Lua51.is_known());
        assert!(LuaVersion::Lua54.is_known());
        assert!(!LuaVersion::Unknown(0x55).is_known());
    }

    #[test]
    fn test_version_as_byte() {
        assert_eq!(LuaVersion::Lua53.as_byte(), 0x53);
    }

    #[test]
    fn test_version_major_minor() {
        assert_eq!(LuaVersion::Lua54.major(), 5);
        assert_eq!(LuaVersion::Lua54.minor(), 4);
    }

    #[test]
    fn test_version_display_54() {
        assert_eq!(LuaVersion::Lua54.to_string(), "Lua 5.4");
    }

    #[test]
    fn test_version_display_unknown() {
        assert!(LuaVersion::Unknown(0x55).to_string().contains("unknown"));
    }

    // ── LuaEndian ─────────────────────────────────────────────────────────────

    #[test]
    fn test_endian_from_byte_le() {
        assert_eq!(LuaEndian::from_byte(1), LuaEndian::Le);
    }

    #[test]
    fn test_endian_from_byte_be() {
        assert_eq!(LuaEndian::from_byte(0), LuaEndian::Be);
    }

    #[test]
    fn test_endian_to_core_le() {
        assert_eq!(LuaEndian::Le.to_core_endian(), Endian::Little);
    }

    #[test]
    fn test_endian_to_core_be() {
        assert_eq!(LuaEndian::Be.to_core_endian(), Endian::Big);
    }

    #[test]
    fn test_endian_display_le() {
        assert_eq!(LuaEndian::Le.to_string(), "LE");
    }

    #[test]
    fn test_endian_display_be() {
        assert_eq!(LuaEndian::Be.to_string(), "BE");
    }

    // ── LuaIntSize ────────────────────────────────────────────────────────────

    #[test]
    fn test_int_size_display() {
        let s = LuaIntSize { size: 4 };
        assert_eq!(s.to_string(), "int:4");
    }

    // ── LuaHeader ─────────────────────────────────────────────────────────────

    #[test]
    fn test_header_parse_54() {
        let data = make_lua(0x54);
        let (hdr, _) = LuaHeader::parse(&data).unwrap();
        assert_eq!(hdr.version, LuaVersion::Lua54);
        assert_eq!(hdr.format, 0);
        assert_eq!(hdr.endian, LuaEndian::Le);
        assert_eq!(hdr.int_size, 4);
        assert_eq!(hdr.inst_size, 4);
    }

    #[test]
    fn test_header_parse_wrong_magic() {
        let err = LuaHeader::parse(&[0u8; 32]).unwrap_err();
        assert!(matches!(err, LuaLoaderError::InvalidMagic));
    }

    #[test]
    fn test_header_too_short() {
        let err = LuaHeader::parse(b"\x1bLua\x54\x00").unwrap_err();
        assert!(matches!(err, LuaLoaderError::TruncatedData));
    }

    #[test]
    fn test_header_to_endian_le() {
        let data = make_lua(0x54);
        let (hdr, _) = LuaHeader::parse(&data).unwrap();
        assert_eq!(hdr.to_endian(), Endian::Little);
    }

    #[test]
    fn test_header_to_endian_be() {
        let mut data = make_lua(0x54);
        data[6] = 0; // big-endian
        let (hdr, _) = LuaHeader::parse(&data).unwrap();
        assert_eq!(hdr.to_endian(), Endian::Big);
    }

    #[test]
    fn test_header_is_official_format() {
        let data = make_lua(0x54);
        let (hdr, _) = LuaHeader::parse(&data).unwrap();
        assert!(hdr.is_official_format());
    }

    #[test]
    fn test_header_display() {
        let data = make_lua(0x53);
        let (hdr, _) = LuaHeader::parse(&data).unwrap();
        assert!(hdr.to_string().contains("Lua 5.3"));
    }

    // ── LuaConst ──────────────────────────────────────────────────────────────

    #[test]
    fn test_const_nil() {
        assert_eq!(LuaConst::Nil.to_string(), "nil");
        assert!(!LuaConst::Nil.is_string());
    }

    #[test]
    fn test_const_bool() {
        assert_eq!(LuaConst::Bool(true).to_string(), "true");
    }

    #[test]
    fn test_const_number() {
        let c = LuaConst::Number(3.14_f64);
        assert!(!c.is_string());
        assert!(c.to_string().contains("3.14"));
    }

    #[test]
    fn test_const_integer() {
        assert_eq!(LuaConst::Integer(42).to_string(), "42");
    }

    #[test]
    fn test_const_string() {
        let c = LuaConst::Str("hello".to_string());
        assert!(c.is_string());
        assert_eq!(c.as_str(), Some("hello"));
    }

    #[test]
    fn test_const_long_str() {
        let c = LuaConst::LongStr("world".to_string());
        assert!(c.is_string());
        assert_eq!(c.as_str(), Some("world"));
    }

    // ── LuaInstr ──────────────────────────────────────────────────────────────

    #[test]
    fn test_instr_opcode() {
        let i = LuaInstr(0x0000_001E); // op = 0x1E
        assert_eq!(i.opcode(), 0x1E);
    }

    #[test]
    fn test_instr_a() {
        // A is bits 6-13; value 3 at bits 6-13 = 0b00000011_00000000 = 0x00C0
        let i = LuaInstr(0x0000_00C0);
        assert_eq!(i.a(), 3);
    }

    #[test]
    fn test_instr_bx() {
        // BX is bits 14-31; value 1 → bx=1 → 0x00004000
        let i = LuaInstr(0x0000_4000);
        assert_eq!(i.bx(), 1);
    }

    #[test]
    fn test_instr_sbx() {
        // sBx = bx - 131_071; when bx=131_071 → sbx=0
        let i = LuaInstr(131_071_u32 << 14);
        assert_eq!(i.sbx(), 0);
    }

    #[test]
    fn test_instr_display() {
        let i = LuaInstr(0x0000_001E);
        let s = i.to_string();
        assert!(s.contains("op="));
    }

    // ── LuaLocalVar ───────────────────────────────────────────────────────────

    #[test]
    fn test_local_var_display() {
        let lv = LuaLocalVar {
            name: "x".to_string(),
            start_pc: 0,
            end_pc: 5,
        };
        let s = lv.to_string();
        assert!(s.contains("local x"));
    }

    // ── LuaUpvalue ────────────────────────────────────────────────────────────

    #[test]
    fn test_upvalue_display() {
        let uv = LuaUpvalue {
            in_stack: false,
            idx: 0,
            name: Some("_ENV".to_string()),
        };
        let s = uv.to_string();
        assert!(s.contains("upval[0]"));
        assert!(s.contains("_ENV"));
    }

    // ── LuaProto mock ─────────────────────────────────────────────────────────

    #[test]
    fn test_proto_mock() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        assert!(p.is_vararg);
        assert_eq!(p.num_params, 0);
        assert!(!p.constants.is_empty());
    }

    #[test]
    fn test_proto_all_strings() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        let strings = p.all_strings();
        assert!(strings.contains(&"hello"));
    }

    #[test]
    fn test_proto_total_instructions() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        assert_eq!(p.total_instructions(), 1);
    }

    #[test]
    fn test_proto_source_line() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        assert_eq!(p.source_line(0), Some(1));
    }

    #[test]
    fn test_proto_constant_type_counts() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        let counts = p.constant_type_counts();
        assert!(counts.get("string").copied().unwrap_or(0) >= 1);
    }

    #[test]
    fn test_proto_display() {
        let p = LuaProto::mock(LuaVersion::Lua53);
        let s = p.to_string();
        assert!(s.contains("LuaProto"));
    }

    // ── LuaChunk ──────────────────────────────────────────────────────────────

    #[test]
    fn test_chunk_mock() {
        let c = LuaChunk::mock("test");
        assert_eq!(c.name, "test");
        assert_eq!(c.instructions_count, 10);
    }

    #[test]
    fn test_chunk_from_proto() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        let c = LuaChunk::from_proto(&p);
        assert_eq!(c.num_params, 0);
        assert!(c.is_vararg);
    }

    #[test]
    fn test_chunk_display() {
        let c = LuaChunk::mock("@test.lua");
        let s = c.to_string();
        assert!(s.contains("LuaChunk"));
    }

    // ── Opcode tables ─────────────────────────────────────────────────────────

    #[test]
    fn test_opcode_name_51_move() {
        assert_eq!(opcode_name(LuaVersion::Lua51, 0), "MOVE");
    }

    #[test]
    fn test_opcode_name_54_return0() {
        // RETURN0 is in the 5.4 table
        let idx = LUA54_OPCODES.iter().position(|&n| n == "RETURN0").unwrap();
        assert_eq!(opcode_name(LuaVersion::Lua54, idx as u8), "RETURN0");
    }

    #[test]
    fn test_opcode_name_unknown_opcode() {
        assert_eq!(opcode_name(LuaVersion::Lua51, 0xFF), "UNK");
    }

    #[test]
    fn test_opcode_tables_not_empty() {
        assert!(!LUA51_OPCODES.is_empty());
        assert!(!LUA52_OPCODES.is_empty());
        assert!(!LUA53_OPCODES.is_empty());
        assert!(!LUA54_OPCODES.is_empty());
    }

    // ── LuaArch ───────────────────────────────────────────────────────────────

    #[test]
    fn test_arch_name_54() {
        let arch = LuaArch::new(LuaVersion::Lua54);
        assert_eq!(arch.name(), "lua54");
    }

    #[test]
    fn test_arch_name_51() {
        let arch = LuaArch::new(LuaVersion::Lua51);
        assert_eq!(arch.name(), "lua51");
    }

    #[test]
    fn arch_disassemble_refuses_a_partial_instruction() {
        // Three bytes are not an instruction; they are the tail of a buffer.
        // This used to be reported as a one-byte "nop", which is indistinguishable
        // from a real nop at that address.
        let arch = LuaArch::new(LuaVersion::Lua51);
        for len in 0..4usize {
            let bytes = vec![0u8; len];
            assert!(
                arch.disassemble(Address::new(0), &bytes).is_err(),
                "{len} bytes must not yield an instruction"
            );
        }
        // Four bytes do decode, so the guard is not simply refusing everything.
        assert!(arch.disassemble(Address::new(0), &[0u8; 4]).is_ok());
    }

    #[test]
    fn arch_disassemble_uses_54_layout_for_54() {
        // Opcode 0x44 needs seven bits. Read as six it becomes 0x04, so the
        // instruction is named after a different opcode entirely — and A, which
        // lives at bits 7..15 in 5.4, is read from bits 6..14 in the old layout.
        let word: u32 = 0x44 | (0x1F << 7);
        let bytes = word.to_le_bytes();

        let arch54 = LuaArch::new(LuaVersion::Lua54);
        let d54 = arch54.disassemble(Address::new(0), &bytes).unwrap();
        assert_eq!(d54.operands, "A=31 B=0 C=0", "5.4 reads A from bits 7..15");
        assert_eq!(d54.mnemonic, opcode_name(LuaVersion::Lua54, 0x44));

        // The 5.1 path is untouched: it still uses the six-bit opcode.
        let arch51 = LuaArch::new(LuaVersion::Lua51);
        let d51 = arch51.disassemble(Address::new(0), &bytes).unwrap();
        assert_eq!(d51.mnemonic, opcode_name(LuaVersion::Lua51, (word & 0x3F) as u8));
    }

    #[test]
    fn test_arch_endian() {
        let arch = LuaArch::default();
        assert_eq!(arch.endian(), Endian::Little);
    }

    #[test]
    fn test_arch_ptr_size() {
        let arch = LuaArch::default();
        assert_eq!(arch.pointer_size(), 8);
    }

    #[test]
    fn test_arch_registers() {
        let arch = LuaArch::default();
        let regs = arch.registers();
        assert!(!regs.is_empty());
    }

    #[test]
    fn test_arch_calling_conventions() {
        let arch = LuaArch::default();
        let convs = arch.calling_conventions();
        assert_eq!(convs[0].name, "lua");
    }

    #[test]
    fn test_arch_disassemble() {
        let arch = LuaArch::new(LuaVersion::Lua54);
        let bytes = [0x00u8, 0x00, 0x00, 0x00]; // opcode=0 = MOVE
        let instr = arch.disassemble(Address::new(0), &bytes).unwrap();
        assert_eq!(instr.mnemonic, "MOVE");
    }

    // ── LuaLoader ─────────────────────────────────────────────────────────────

    #[test]
    fn test_loader_name() {
        assert_eq!(LuaLoader::new().name(), "lua");
    }

    #[test]
    fn test_loader_can_load_true() {
        let data = make_lua(0x54);
        let input = LoaderInput::new("test.luac", data);
        assert!(LuaLoader::new().can_load(&input));
    }

    #[test]
    fn test_loader_can_load_false() {
        let input = LoaderInput::new("test.bin", vec![0xDE, 0xAD]);
        assert!(!LuaLoader::new().can_load(&input));
    }

    #[tokio::test]
    async fn test_loader_load() {
        let data = make_lua(0x54);
        let input = LoaderInput::new("test.luac", data);
        let result = LuaLoader::new().load(input).await.unwrap();
        assert_eq!(result.view.uri, "test.luac");
    }

    #[tokio::test]
    async fn test_loader_load_with_hint() {
        let data = make_lua(0x53);
        let input = LoaderInput::new("test.luac", data)
            .with_hint(LoaderHint::BaseAddress(Address::new(0x1000)));
        let result = LuaLoader::new().load(input).await.unwrap();
        assert_eq!(result.view.entry_points[0].as_u64(), 0x1000);
    }

    #[tokio::test]
    async fn test_loader_find_nested() {
        let data = make_lua(0x54);
        let input = LoaderInput::new("test.luac", data);
        let nested = LuaLoader::new().find_nested(&input).await.unwrap();
        assert!(nested.is_empty());
    }

    // ── Reader ────────────────────────────────────────────────────────────────

    #[test]
    fn test_reader_u8() {
        let mut r = Reader::new(&[0x42, 0x00], true);
        assert_eq!(r.read_u8().unwrap(), 0x42);
    }

    #[test]
    fn test_reader_u32_le() {
        let mut r = Reader::new(&[0x01, 0x00, 0x00, 0x00], true);
        assert_eq!(r.read_u32().unwrap(), 1);
    }

    #[test]
    fn test_reader_u32_be() {
        let mut r = Reader::new(&[0x00, 0x00, 0x00, 0x01], false);
        assert_eq!(r.read_u32().unwrap(), 1);
    }

    #[test]
    fn test_reader_eof() {
        let mut r = Reader::new(&[], true);
        assert!(r.read_u8().is_err());
    }

    // ── read_string_lua ───────────────────────────────────────────────────────

    #[test]
    fn test_read_string_lua_empty() {
        // Length 0 → empty string
        let data = [0u8, 0, 0, 0]; // u32 = 0
        let mut off = 0usize;
        let s = read_string_lua(&data, &mut off, 4).unwrap();
        assert_eq!(s, "");
        assert_eq!(off, 4);
    }

    #[test]
    fn test_read_string_lua_hello() {
        // "hello\0" with 4-byte length prefix = 6
        let mut data = vec![6u8, 0, 0, 0]; // LE u32 = 6
        data.extend_from_slice(b"hello\0");
        let mut off = 0usize;
        let s = read_string_lua(&data, &mut off, 4).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(off, 10);
    }

    #[test]
    fn test_read_string_lua_1byte_size() {
        let mut data = vec![4u8]; // 1-byte length = 4
        data.extend_from_slice(b"abc\0");
        let mut off = 0usize;
        let s = read_string_lua(&data, &mut off, 1).unwrap();
        assert_eq!(s, "abc");
    }

    #[test]
    fn test_read_string_lua_truncated() {
        let data = [5u8, 0, 0, 0, b'a']; // says 5 bytes but only 1 available
        let mut off = 0usize;
        assert!(read_string_lua(&data, &mut off, 4).is_err());
    }

    // ── UpvalueDesc ───────────────────────────────────────────────────────────

    #[test]
    fn test_upvalue_desc_from_upvalue() {
        let uv = LuaUpvalue {
            in_stack: true,
            idx: 2,
            name: Some("x".to_string()),
        };
        let desc = UpvalueDesc::from_upvalue(&uv);
        assert_eq!(desc.name, "x");
        assert_eq!(desc.in_stack, 1);
        assert_eq!(desc.idx, 2);
    }

    #[test]
    fn test_upvalue_desc_no_name() {
        let uv = LuaUpvalue {
            in_stack: false,
            idx: 0,
            name: None,
        };
        let desc = UpvalueDesc::from_upvalue(&uv);
        assert_eq!(desc.name, "");
    }

    #[test]
    fn test_upvalue_desc_display() {
        let desc = UpvalueDesc {
            name: "_ENV".to_string(),
            in_stack: 1,
            idx: 0,
        };
        let s = desc.to_string();
        assert!(s.contains("_ENV"));
        assert!(s.contains("in_stack=1"));
    }

    // ── parse_proto_51 ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_proto_51_empty_fields() {
        // Build a minimal 5.1 proto blob:
        // name=0, first_line=0, last_line=0, num_params=0, is_vararg=0, max_stack=2,
        // inst_count=0, kst_count=0, proto_count=0, li_count=0, loc_count=0, uv_count=0
        let mut buf: Vec<u8> = Vec::new();
        let push_u32 = |buf: &mut Vec<u8>, v: u32| buf.extend_from_slice(&v.to_le_bytes());
        // name length is a size_t in the 5.1 dump format; parse_proto_51
        // synthesises an 8-byte pointer size, so the length is 8 bytes wide.
        buf.extend_from_slice(&0u64.to_le_bytes()); // name len = 0
        push_u32(&mut buf, 0); // first_line
        push_u32(&mut buf, 10); // last_line
        buf.push(0); // nups
        buf.push(0); // num_params
        buf.push(1); // is_vararg
        buf.push(2); // max_stack
        push_u32(&mut buf, 0); // inst_count
        push_u32(&mut buf, 0); // kst_count
        push_u32(&mut buf, 0); // proto_count
        push_u32(&mut buf, 0); // li_count
        push_u32(&mut buf, 0); // loc_count
        push_u32(&mut buf, 0); // uv_count

        let mut off = 0usize;
        let proto = parse_proto_51(&buf, &mut off, true, 4).unwrap();
        assert_eq!(proto.last_line, 10);
        assert!(proto.is_vararg);
        assert_eq!(proto.max_stack, 2);
        assert_eq!(off, buf.len());
    }

    // ── parse_proto_54 ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_proto_54_empty_fields() {
        // 5.4 proto: name=0x00 (empty 5.4 string), then fields
        let mut buf: Vec<u8> = Vec::new();
        let push_u32 = |buf: &mut Vec<u8>, v: u32| buf.extend_from_slice(&v.to_le_bytes());
        buf.push(0x00); // name: size_b=0 → None
        push_u32(&mut buf, 0); // first_line
        push_u32(&mut buf, 5); // last_line
        buf.push(1); // num_params
        buf.push(0); // is_vararg
        buf.push(4); // max_stack
        buf.push(0); // uv_prelim
        push_u32(&mut buf, 0); // inst_count
        push_u32(&mut buf, 0); // kst_count
        push_u32(&mut buf, 0); // uv_count
        push_u32(&mut buf, 0); // proto_count
        push_u32(&mut buf, 0); // li_count
        push_u32(&mut buf, 0); // loc_count
        push_u32(&mut buf, 0); // uv_name_count

        let mut off = 0usize;
        let proto = parse_proto_54(&buf, &mut off).unwrap();
        assert_eq!(proto.last_line, 5);
        assert_eq!(proto.num_params, 1);
        assert!(!proto.is_vararg);
        assert_eq!(off, buf.len());
    }

    // ── LuaModule ─────────────────────────────────────────────────────────────

    #[test]
    fn test_lua_module_from_bytecode() {
        let bc = LuaBytecode {
            header: LuaHeader {
                version: LuaVersion::Lua54,
                format: 0,
                endian: LuaEndian::Le,
                int_size: 4,
                ptr_size: 8,
                inst_size: 4,
                num_size: 8,
                is_integer_num: false,
                lua_integer_size: 8,
                lua_float_size: 8,
            },
            top_level: LuaProto::mock(LuaVersion::Lua54),
        };
        let module = LuaModule::from_bytecode(bc);
        assert_eq!(module.header.version, LuaVersion::Lua54);
        assert_eq!(module.total_instructions(), 1);
    }

    #[test]
    fn test_lua_module_display() {
        let bc = LuaBytecode {
            header: LuaHeader {
                version: LuaVersion::Lua53,
                format: 0,
                endian: LuaEndian::Le,
                int_size: 4,
                ptr_size: 8,
                inst_size: 4,
                num_size: 8,
                is_integer_num: false,
                lua_integer_size: 8,
                lua_float_size: 8,
            },
            top_level: LuaProto::mock(LuaVersion::Lua53),
        };
        let module = LuaModule::from_bytecode(bc);
        let s = module.to_string();
        assert!(s.contains("LuaModule"));
        assert!(s.contains("5.3"));
    }

    // ── LuaBytecodeLoader ─────────────────────────────────────────────────────

    #[test]
    fn test_bytecode_loader_load_invalid_magic() {
        let data = vec![0u8; 32];
        assert!(LuaBytecodeLoader::load(&data).is_err());
    }

    #[test]
    fn test_bytecode_loader_load_version_override() {
        let data = make_lua(0x54);
        // Override to 5.3 — header parse should succeed (same layout)
        let result = LuaBytecodeLoader::load_version(&data, 0x53);
        // May fail at proto parse due to minimal data, but magic must pass
        match result {
            Ok(m) => assert_eq!(m.header.version, LuaVersion::Lua53),
            Err(LuaLoaderError::TruncatedData) => { /* acceptable — no proto data */ }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_bytecode_loader_load_version_wrong_magic() {
        let data = vec![0u8; 32];
        assert!(LuaBytecodeLoader::load_version(&data, 0x54).is_err());
    }

    #[test]
    fn test_bytecode_loader_all_protos_mock() {
        let bc = LuaBytecode {
            header: LuaHeader {
                version: LuaVersion::Lua54,
                format: 0,
                endian: LuaEndian::Le,
                int_size: 4,
                ptr_size: 8,
                inst_size: 4,
                num_size: 8,
                is_integer_num: false,
                lua_integer_size: 8,
                lua_float_size: 8,
            },
            top_level: LuaProto::mock(LuaVersion::Lua54),
        };
        let module = LuaModule::from_bytecode(bc);
        let protos = LuaBytecodeLoader::all_protos(&module);
        assert_eq!(protos.len(), 1);
    }

    #[test]
    fn test_bytecode_loader_all_strings_mock() {
        let bc = LuaBytecode {
            header: LuaHeader {
                version: LuaVersion::Lua54,
                format: 0,
                endian: LuaEndian::Le,
                int_size: 4,
                ptr_size: 8,
                inst_size: 4,
                num_size: 8,
                is_integer_num: false,
                lua_integer_size: 8,
                lua_float_size: 8,
            },
            top_level: LuaProto::mock(LuaVersion::Lua54),
        };
        let module = LuaModule::from_bytecode(bc);
        let strings = LuaBytecodeLoader::all_strings(&module);
        assert!(strings.contains(&"hello".to_string()));
    }

    // ── ProtoWalker ───────────────────────────────────────────────────────────

    #[test]
    fn test_proto_walker_single() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        
        assert_eq!(ProtoWalker::new(&p).count(), 1);
    }

    #[test]
    fn test_proto_walker_nested() {
        let mut root = LuaProto::mock(LuaVersion::Lua54);
        root.protos.push(LuaProto::mock(LuaVersion::Lua54));
        root.protos.push(LuaProto::mock(LuaVersion::Lua54));
        
        assert_eq!(ProtoWalker::new(&root).count(), 3);
    }

    // ── ConstantIndex ─────────────────────────────────────────────────────────

    #[test]
    fn test_constant_index_get() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        let idx = ConstantIndex(0);
        let c = idx.get(&p);
        assert!(c.is_some());
        assert_eq!(c.unwrap().as_str(), Some("hello"));
    }

    #[test]
    fn test_constant_index_out_of_bounds() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        let idx = ConstantIndex(9999);
        assert!(idx.get(&p).is_none());
    }

    #[test]
    fn test_constant_index_display() {
        let idx = ConstantIndex(7);
        assert_eq!(idx.to_string(), "K7");
    }

    // ── ProtoStats ────────────────────────────────────────────────────────────

    #[test]
    fn test_proto_stats_from_mock() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        let stats = ProtoStats::from_proto(&p);
        assert_eq!(stats.proto_count, 1);
        assert_eq!(stats.instruction_count, 1);
        assert!(stats.string_count >= 1);
        assert!(stats.number_count >= 1);
    }

    #[test]
    fn test_proto_stats_display() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        let stats = ProtoStats::from_proto(&p);
        let s = stats.to_string();
        assert!(s.contains("protos=1"));
    }

    #[test]
    fn test_proto_stats_nested() {
        let mut root = LuaProto::mock(LuaVersion::Lua54);
        root.protos.push(LuaProto::mock(LuaVersion::Lua54));
        let stats = ProtoStats::from_proto(&root);
        assert_eq!(stats.proto_count, 2);
        assert!(stats.instruction_count >= 2);
    }

    // ── disassemble_proto ─────────────────────────────────────────────────────

    #[test]
    fn test_disassemble_proto_non_empty() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        let lines = disassemble_proto(&p, 0x54);
        assert_eq!(lines.len(), 1); // one instruction in mock
    }

    #[test]
    fn test_disassemble_proto_line_format() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        let lines = disassemble_proto(&p, 0x54);
        // Should start with "0000:"
        assert!(lines[0].starts_with("0000:"));
    }

    #[test]
    fn test_disassemble_proto_51() {
        let p = LuaProto::mock(LuaVersion::Lua51);
        let lines = disassemble_proto(&p, 0x51);
        assert!(!lines.is_empty());
        // The mock has RETURN instruction (0x1E in 5.1 = opcode 30)
        // opcode 30 in LUA51_OPCODES = "RETURN"
        assert!(lines[0].contains("RETURN"), "line was: {}", lines[0]);
    }

    #[test]
    fn test_disassemble_proto_with_loadk() {
        // Build a proto with LOADK instruction (opcode 1 in 5.1 iABx)
        // LOADK A=0 K=0  →  op=1, A=0, Bx=0
        // 5.1 iABx: op(6) A(8) Bx(18) → bits: op=1 (0..5), A=0 (6..13), Bx=0 (14..31)
        let word: u32 = 1; // opcode 1 = LOADK, A=0, Bx=0
        let mut p = LuaProto::mock(LuaVersion::Lua51);
        p.instructions = vec![LuaInstr(word)];
        let lines = disassemble_proto(&p, 0x51);
        assert!(!lines.is_empty());
        assert!(lines[0].contains("LOADK"), "line: {}", lines[0]);
    }

    #[test]
    fn test_disassemble_proto_annotation() {
        // Proto with a LOADK pointing at K0="hello", and line_info=[5]
        let word: u32 = 1; // LOADK, Bx=0
        let mut p = LuaProto::mock(LuaVersion::Lua51);
        p.instructions = vec![LuaInstr(word)];
        p.line_info = vec![5];
        let lines = disassemble_proto(&p, 0x51);
        // Should have annotation with line 5 and the constant value
        assert!(lines[0].contains(';'), "expected annotation: {}", lines[0]);
    }

    #[test]
    fn test_disassemble_proto_54_return0() {
        // RETURN0 in 5.4 — opcode 80 (0x50)
        let idx = LUA54_OPCODES.iter().position(|&n| n == "RETURN0").unwrap();
        let word: u32 = idx as u32; // op only, all other bits 0
        let mut p = LuaProto::mock(LuaVersion::Lua54);
        p.instructions = vec![LuaInstr(word)];
        let lines = disassemble_proto(&p, 0x54);
        assert!(lines[0].contains("RETURN0"), "line: {}", lines[0]);
    }

    // ── ProtoDisasm ───────────────────────────────────────────────────────────

    #[test]
    fn test_proto_disasm_from_proto() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        let pd = ProtoDisasm::from_proto(&p);
        assert_eq!(pd.name, "@test.lua");
        assert_eq!(pd.version, LuaVersion::Lua54);
        assert!(!pd.lines.is_empty());
    }

    #[test]
    fn test_proto_disasm_display() {
        let p = LuaProto::mock(LuaVersion::Lua54);
        let pd = ProtoDisasm::from_proto(&p);
        let s = pd.to_string();
        assert!(s.contains(';'));
    }

    // ── ModuleDisasm ──────────────────────────────────────────────────────────

    #[test]
    fn test_module_disasm_from_module() {
        let bc = LuaBytecode {
            header: LuaHeader {
                version: LuaVersion::Lua54,
                format: 0,
                endian: LuaEndian::Le,
                int_size: 4,
                ptr_size: 8,
                inst_size: 4,
                num_size: 8,
                is_integer_num: false,
                lua_integer_size: 8,
                lua_float_size: 8,
            },
            top_level: LuaProto::mock(LuaVersion::Lua54),
        };
        let module = LuaModule::from_bytecode(bc);
        let disasm = ModuleDisasm::from_module(&module);
        assert_eq!(disasm.protos.len(), 1);
    }

    #[test]
    fn test_module_disasm_flat_listing() {
        let bc = LuaBytecode {
            header: LuaHeader {
                version: LuaVersion::Lua54,
                format: 0,
                endian: LuaEndian::Le,
                int_size: 4,
                ptr_size: 8,
                inst_size: 4,
                num_size: 8,
                is_integer_num: false,
                lua_integer_size: 8,
                lua_float_size: 8,
            },
            top_level: LuaProto::mock(LuaVersion::Lua54),
        };
        let module = LuaModule::from_bytecode(bc);
        let disasm = ModuleDisasm::from_module(&module);
        let listing = disasm.flat_listing();
        assert!(!listing.is_empty());
        assert!(listing[0].contains("==="));
    }

    // ── opcode_layout ─────────────────────────────────────────────────────────

    #[test]
    fn test_opcode_layout_54_move() {
        // MOVE in 5.4 is ABC
        assert_eq!(opcode_layout(LuaVersion::Lua54, 0), OpcodeLayout::Abc);
    }

    #[test]
    fn test_opcode_layout_54_loadk() {
        // LOADK in 5.4 is ABx
        let idx = LUA54_OPCODES.iter().position(|&n| n == "LOADK").unwrap() as u8;
        assert_eq!(opcode_layout(LuaVersion::Lua54, idx), OpcodeLayout::ABx);
    }

    #[test]
    fn test_opcode_layout_51_jmp() {
        // JMP in 5.1 is AsBx
        let idx = LUA51_OPCODES.iter().position(|&n| n == "JMP").unwrap() as u8;
        assert_eq!(opcode_layout(LuaVersion::Lua51, idx), OpcodeLayout::AsBx);
    }

    #[test]
    fn test_opcode_layout_51_move() {
        assert_eq!(opcode_layout(LuaVersion::Lua51, 0), OpcodeLayout::Abc);
    }

    // ── const_hint (via disassemble) ──────────────────────────────────────────

    #[test]
    fn test_const_hint_long_string_truncated() {
        let long_s = "x".repeat(60);
        let kst = LuaConst::Str(long_s);
        let hint = const_hint(&kst);
        assert!(hint.contains("..."));
        assert!(hint.len() < 60); // was truncated
    }

    #[test]
    fn test_const_hint_integer() {
        let hint = const_hint(&LuaConst::Integer(-99));
        assert_eq!(hint, "-99");
    }

    #[test]
    fn test_const_hint_nil() {
        assert_eq!(const_hint(&LuaConst::Nil), "nil");
    }
}
